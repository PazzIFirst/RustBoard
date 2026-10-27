//! 安装器的 80/443 只读诊断（M5 Phase C C5）。
//!
//! 本模块只做三类**只读**探测，并在失败时给出可执行的排障命令：
//!
//! 1. 本地 bind：分别试绑 `0.0.0.0:80` / `0.0.0.0:443`。失败时用 `ss -ltnp`
//!    （存在时）找 PID / 进程名；没有 `ss` 只给通用占用提示。
//! 2. 防火墙：读取 `ufw status`、`firewall-cmd --state`、`nft list ruleset`、
//!    `iptables -S`，只生成精确放行命令文本，**绝不执行**修改防火墙的命令，
//!    `--yes` 也不会自动修改。
//! 3. 云元数据：只在「非 offline + ACME」时探测 AWS / 阿里云 / 腾讯云元数据
//!    根路径；任一返回 200 即识别厂商，只打印厂商与安全组路径建议。不读取
//!    凭证、不解析/打印响应体，也绝不使用其中的任何凭证。
//!
//! 安全约定：
//! - 所有子进程都有超时，输出上限 64 KiB；命令一律用固定参数数组，不拼 shell；
//! - 所有 HTTP 请求都有 1 秒级超时，只接受 `http://` + 字面 IP（避免 DNS / SSRF）；
//! - 报告只含公开信息（端口、PID、进程名、厂商名），不包含环境变量内容；
//! - 本模块不写任何文件、不修改任何系统状态。

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use rustboard_common::config::{AcmeChallenge, ServerTlsMode};

/// `ss` / 防火墙状态读取的超时。
const COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
/// 单条云元数据请求的超时（D9：1 秒）。
const CLOUD_TIMEOUT: Duration = Duration::from_secs(1);
/// 子进程输出上限，避免被异常命令撑爆内存 / 终端。
const OUTPUT_LIMIT: usize = 64 * 1024;
/// ACME 诊断只关心这两个入站端口。
const ACME_PORTS: [u16; 2] = [80, 443];

/// 云厂商元数据根路径（只判状态码，不取内容）。
const AWS_METADATA_URL: &str = "http://169.254.169.254/latest/meta-data/";
const ALIYUN_METADATA_URL: &str = "http://100.100.100.200/latest/meta-data/";
/// 腾讯云元数据域名 `metadata.tencentyun.com` 固定解析到 `169.254.0.23`。
/// 探测只接受字面 IP（避免 DNS 解析成为不可控阻塞点），因此直接使用固定地址，
/// 同时与 AWS 的 `169.254.169.254` 明确区分。
const TENCENT_METADATA_URL: &str = "http://169.254.0.23/latest/meta-data/";

/// 生产探测顺序；与单测共用，避免新增/修改常量时漏测。
const METADATA_ENDPOINTS: [(CloudProvider, &str); 3] = [
    (CloudProvider::Aws, AWS_METADATA_URL),
    (CloudProvider::Aliyun, ALIYUN_METADATA_URL),
    (CloudProvider::Tencent, TENCENT_METADATA_URL),
];

/// 云厂商（只用于打印安全组路径建议）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloudProvider {
    Aws,
    Aliyun,
    Tencent,
}

impl CloudProvider {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Aws => "AWS",
            Self::Aliyun => "阿里云",
            Self::Tencent => "腾讯云",
        }
    }

    /// 安全组入站放行路径；只是控制台导航建议，不会自动修改。
    pub(crate) fn security_group_hint(self) -> &'static str {
        match self {
            Self::Aws => {
                "AWS EC2：控制台 → 实例 → 安全组 → 入站规则，放行 TCP 80 与 443（ACME 验证期间）"
            }
            Self::Aliyun => {
                "阿里云 ECS：控制台 → 实例 → 安全组 → 入方向，放行 TCP 80 与 443（ACME 验证期间）"
            }
            Self::Tencent => {
                "腾讯云 CVM：控制台 → 实例 → 安全组 → 入站规则，放行 TCP 80 与 443（ACME 验证期间）"
            }
        }
    }
}

/// 云环境识别结果；只含厂商名。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CloudHint {
    pub(crate) provider: CloudProvider,
}

/// `ss -ltnp` 里解析出的端口占用者。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortHolder {
    pub(crate) pid: Option<u32>,
    pub(crate) process: Option<String>,
}

impl PortHolder {
    fn describe(&self) -> String {
        match (self.pid, self.process.as_deref()) {
            (Some(pid), Some(process)) => format!("pid={pid}, 进程={process}"),
            (Some(pid), None) => format!("pid={pid}"),
            (None, Some(process)) => format!("进程={process}"),
            (None, None) => "占用进程未知".to_string(),
        }
    }
}

/// 单个端口的 bind 检查结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PortCheck {
    pub(crate) port: u16,
    pub(crate) bindable: bool,
    pub(crate) holder: Option<PortHolder>,
    pub(crate) detail: String,
}

/// 防火墙种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FirewallKind {
    Ufw,
    Firewalld,
    Nftables,
    Iptables,
}

impl FirewallKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ufw => "ufw",
            Self::Firewalld => "firewalld",
            Self::Nftables => "nftables",
            Self::Iptables => "iptables",
        }
    }
}

/// 单个防火墙后端的只读探测结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirewallBackend {
    pub(crate) kind: FirewallKind,
    /// 是否处于启用/有规则状态。无法读取时保持 false，并在 detail 说明。
    pub(crate) active: bool,
    pub(crate) detail: String,
}

/// 本机防火墙报告；只生成命令文本，绝不执行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirewallReport {
    pub(crate) ports: Vec<u16>,
    pub(crate) backends: Vec<FirewallBackend>,
}

impl FirewallReport {
    /// 为已启用的后端生成精确放行命令（仅文本）。
    pub(crate) fn allow_commands(&self) -> Vec<String> {
        let mut commands = Vec::new();
        for backend in self.backends.iter().filter(|backend| backend.active) {
            match backend.kind {
                FirewallKind::Ufw => {
                    for port in &self.ports {
                        commands.push(format!("ufw allow {port}/tcp"));
                    }
                }
                FirewallKind::Firewalld => {
                    for port in &self.ports {
                        commands.push(format!("firewall-cmd --permanent --add-port={port}/tcp"));
                    }
                    commands.push("firewall-cmd --reload".to_string());
                }
                FirewallKind::Nftables => {
                    for port in &self.ports {
                        commands.push(format!(
                            "nft add rule inet filter input tcp dport {port} accept"
                        ));
                    }
                }
                FirewallKind::Iptables => {
                    for port in &self.ports {
                        commands.push(format!("iptables -A INPUT -p tcp --dport {port} -j ACCEPT"));
                    }
                }
            }
        }
        commands
    }

    fn active_labels(&self) -> Vec<&'static str> {
        self.backends
            .iter()
            .filter(|backend| backend.active)
            .map(|backend| backend.kind.label())
            .collect()
    }
}

/// ACME 尝试（staging / production）的结果，由安装器在诊断结论中回填。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StagingOutcome {
    /// 尚未执行（C4 `tls issue` 未合入、或 dry-run）。
    NotRun,
    /// `tls issue` 成功（其内部是否先跑 staging 由 C4 决定）。
    Succeeded,
    /// `tls issue` 失败；字符串必须已脱敏（不含 key/keyAuth/私钥）。
    Failed(String),
    /// 当前二进制没有 `tls issue` 子命令（Phase C C4 未合入）。
    Unavailable(String),
}

/// 分层结论中的单层状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerStatus {
    Ok,
    Warn,
    Fail,
    Skipped,
}

impl LayerStatus {
    fn tag(self) -> &'static str {
        match self {
            Self::Ok => "通过",
            Self::Warn => "警告",
            Self::Fail => "失败",
            Self::Skipped => "跳过",
        }
    }
}

/// 分层诊断结论的一层；`commands` 只含只读或用户手工执行的建议命令。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Layer {
    pub(crate) name: &'static str,
    pub(crate) status: LayerStatus,
    pub(crate) detail: String,
    pub(crate) commands: Vec<String>,
}

/// 一次 ACME 安装前的完整只读诊断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Diagnostics {
    pub(crate) challenge: AcmeChallenge,
    pub(crate) ports: Vec<PortCheck>,
    pub(crate) firewall: FirewallReport,
    pub(crate) cloud: Option<CloudHint>,
}

impl Diagnostics {
    /// 采集本地端口、防火墙与云环境信息。
    ///
    /// `offline = true` 时绝不访问云元数据；非 ACME 模式同样不探测云。
    pub(crate) fn collect(offline: bool, mode: ServerTlsMode, challenge: AcmeChallenge) -> Self {
        let ports = ACME_PORTS
            .iter()
            .copied()
            .map(check_port_bind)
            .collect::<Vec<_>>();
        let firewall = detect_firewall(&ACME_PORTS);
        let cloud = collect_cloud(offline, mode, CLOUD_TIMEOUT);
        Self {
            challenge,
            ports,
            firewall,
            cloud,
        }
    }

    /// 当前挑战实际需要的本地端口。
    pub(crate) fn challenge_port(&self) -> u16 {
        challenge_port(self.challenge)
    }

    /// 挑战端口是否可以在本机绑定。这是 ACME 能否继续的硬性条件。
    pub(crate) fn challenge_ready(&self) -> bool {
        self.ports
            .iter()
            .find(|check| check.port == self.challenge_port())
            .is_some_and(|check| check.bindable)
    }

    /// 分层结论：本地 bind / 防火墙 / 云安全组 / ACME 尝试。
    pub(crate) fn layers(&self, staging: StagingOutcome) -> Vec<Layer> {
        let mut layers = Vec::new();

        // 1) 本地 bind：挑战端口占用是硬失败，另一个端口只告警。
        let mut local_commands = Vec::new();
        let mut local_fail = false;
        let mut local_warn = false;
        let mut details = Vec::new();
        for check in &self.ports {
            let is_challenge = check.port == self.challenge_port();
            match (&check.holder, check.bindable) {
                (_, true) => details.push(format!("{}: 可绑定", check.port)),
                (Some(holder), false) => {
                    details.push(format!("{}: 已被占用（{}）", check.port, holder.describe()));
                    if is_challenge {
                        local_fail = true;
                        local_commands.push(format!("ss -ltnp 'sport = :{}'", check.port));
                        local_commands.push(format!(
                            "停止占用 {} 的服务后重试（如 systemctl stop <service>）",
                            check.port
                        ));
                    } else {
                        local_warn = true;
                    }
                }
                (None, false) => {
                    details.push(format!("{}: {}", check.port, check.detail));
                    if is_challenge {
                        local_fail = true;
                        local_commands.push(format!(
                            "sudo ss -ltnp 'sport = :{}'（需 root 才能看到 PID）",
                            check.port
                        ));
                    } else {
                        local_warn = true;
                    }
                }
            }
        }
        let (status, detail) = if local_fail {
            (
                LayerStatus::Fail,
                format!(
                    "{} 端口占用，ACME {} 无法完成验证：{}",
                    self.challenge_port(),
                    self.challenge.as_str(),
                    details.join("；")
                ),
            )
        } else if local_warn {
            (
                LayerStatus::Warn,
                format!(
                    "{} 挑战端口可绑定；其他端口被占用不影响本次挑战：{}",
                    self.challenge_port(),
                    details.join("；")
                ),
            )
        } else {
            (
                LayerStatus::Ok,
                format!("80/443 均可绑定：{}", details.join("；")),
            )
        };
        if local_fail {
            local_commands.push(format!(
                "或改用 --acme-challenge {}",
                alternate_challenge(self.challenge).as_str()
            ));
        }
        layers.push(Layer {
            name: "本地 bind",
            status,
            detail,
            commands: local_commands,
        });

        // 2) 防火墙：只打印放行命令，绝不执行。
        let active = self.firewall.active_labels();
        let commands = self.firewall.allow_commands();
        let (status, detail) = if active.is_empty() {
            (
                LayerStatus::Ok,
                "未检测到已启用的本机防火墙（也可能无权读取；请以实际系统为准）".to_string(),
            )
        } else {
            (
                LayerStatus::Warn,
                format!(
                    "检测到已启用的防火墙：{}；如未放行 80/443，请手工执行下列命令（安装器不会自动修改）：",
                    active.join("、")
                ),
            )
        };
        layers.push(Layer {
            name: "防火墙",
            status,
            detail,
            commands,
        });

        // 3) 云安全组：只给控制台路径。
        let cloud_layer = match &self.cloud {
            Some(hint) => Layer {
                name: "云安全组",
                status: LayerStatus::Warn,
                detail: format!(
                    "识别到 {}；请确认安全组入站已放行 TCP 80 与 443。",
                    hint.provider.label()
                ),
                commands: vec![hint.provider.security_group_hint().to_string()],
            },
            None => Layer {
                name: "云安全组",
                status: LayerStatus::Skipped,
                detail: "未识别云厂商（或为非云主机 / 离线）；如在云主机上，请手工确认安全组放行 TCP 80 与 443"
                    .to_string(),
                commands: Vec::new(),
            },
        };
        layers.push(cloud_layer);

        // 4) ACME 尝试（staging / production 由 C4 `tls issue` 负责）。
        let staging_layer = match staging {
            StagingOutcome::NotRun => Layer {
                name: "ACME 尝试",
                status: LayerStatus::Skipped,
                detail: "尚未执行（dry-run 或当前二进制没有 tls issue）".to_string(),
                commands: Vec::new(),
            },
            StagingOutcome::Succeeded => Layer {
                name: "ACME 尝试",
                status: LayerStatus::Ok,
                detail: "tls issue 已成功签发服务端证书".to_string(),
                commands: Vec::new(),
            },
            StagingOutcome::Failed(detail) => Layer {
                name: "ACME 尝试",
                status: LayerStatus::Fail,
                detail,
                commands: Vec::new(),
            },
            StagingOutcome::Unavailable(detail) => Layer {
                name: "ACME 尝试",
                status: LayerStatus::Skipped,
                detail,
                commands: Vec::new(),
            },
        };
        layers.push(staging_layer);
        layers
    }

    /// 打印分层诊断；只输出公开信息。
    pub(crate) fn print(&self, staging: StagingOutcome) {
        println!("ACME 端口 / 防火墙 / 云环境诊断（只读；安装器不会自动修改防火墙或安全组）：");
        for layer in self.layers(staging) {
            println!(
                "  [{}] {}: {}",
                layer.status.tag(),
                layer.name,
                layer.detail
            );
            for command in layer.commands {
                println!("        建议: {command}");
            }
        }
    }
}

fn challenge_port(challenge: AcmeChallenge) -> u16 {
    match challenge {
        AcmeChallenge::Http01 => 80,
        AcmeChallenge::TlsAlpn01 => 443,
    }
}

fn alternate_challenge(challenge: AcmeChallenge) -> AcmeChallenge {
    match challenge {
        AcmeChallenge::Http01 => AcmeChallenge::TlsAlpn01,
        AcmeChallenge::TlsAlpn01 => AcmeChallenge::Http01,
    }
}

/// 试绑 `0.0.0.0:<port>`；失败时尝试从 `ss -ltnp` 找占用者。
pub(crate) fn check_port_bind(port: u16) -> PortCheck {
    match TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))) {
        Ok(listener) => {
            // 只为探测；立即释放，避免影响后续安装 / 服务启动。
            drop(listener);
            PortCheck {
                port,
                bindable: true,
                holder: None,
                detail: format!("0.0.0.0:{port} 可绑定"),
            }
        }
        Err(err) => {
            let holder = ss_port_holder(port);
            let reason = match err.kind() {
                io::ErrorKind::AddrInUse => match &holder {
                    Some(holder) => format!("端口已被占用（{}）", holder.describe()),
                    None => format!("端口已被占用；{}", generic_port_holder_hint(port)),
                },
                io::ErrorKind::PermissionDenied => {
                    "权限不足（绑定 <1024 端口需要 root）".to_string()
                }
                _ => "绑定失败".to_string(),
            };
            PortCheck {
                port,
                bindable: false,
                holder,
                detail: reason,
            }
        }
    }
}

/// 从 `ss -ltnp` 输出中找指定监听端口的占用者。
fn ss_port_holder(port: u16) -> Option<PortHolder> {
    let output = run_command_capture("ss", &["-ltnp"], COMMAND_TIMEOUT)?;
    if !output.success() {
        return None;
    }
    parse_ss_output(&output.stdout, port)
}

/// 解析 `ss -ltnp` 的一行：
/// `LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=123,fd=6))`
fn parse_ss_output(text: &str, port: u16) -> Option<PortHolder> {
    let suffix = format!(":{port}");
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(local) = fields.get(3) else {
            continue;
        };
        if !local.ends_with(&suffix) {
            continue;
        }
        let mut holder = PortHolder {
            pid: None,
            process: None,
        };
        if let Some(start) = line.find("users:((") {
            // ss 的格式是 users:(("nginx",pid=123,fd=6))；先跳过进程名前引号。
            let rest = line[start + "users:((".len()..].trim_start_matches('"');
            if let Some(name_end) = rest.find('"') {
                let process = &rest[..name_end];
                if !process.is_empty() && process.chars().all(|ch| !ch.is_control()) {
                    holder.process = Some(process.to_string());
                }
            }
            if let Some(pid_start) = rest.find("pid=") {
                let digits: String = rest[pid_start + "pid=".len()..]
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect();
                if let Ok(pid) = digits.parse::<u32>() {
                    holder.pid = Some(pid);
                }
            }
        }
        if holder.pid.is_some() || holder.process.is_some() {
            return Some(holder);
        }
    }
    None
}

/// 依次读取四种防火墙后端；命令缺失/超时只是标记为无法读取。
fn detect_firewall(ports: &[u16]) -> FirewallReport {
    let mut backends = Vec::new();

    if let Some(output) = run_command_capture("ufw", &["status"], COMMAND_TIMEOUT) {
        let active = output.success()
            && output
                .stdout
                .to_ascii_lowercase()
                .contains("status: active");
        backends.push(FirewallBackend {
            kind: FirewallKind::Ufw,
            active,
            detail: if active {
                "已启用".to_string()
            } else if output.timed_out {
                "读取超时".to_string()
            } else {
                "已安装，未启用或无法读取".to_string()
            },
        });
    }

    if let Some(output) = run_command_capture("firewall-cmd", &["--state"], COMMAND_TIMEOUT) {
        let active = output.success() && output.stdout.trim() == "running";
        backends.push(FirewallBackend {
            kind: FirewallKind::Firewalld,
            active,
            detail: if active {
                "已启用".to_string()
            } else if output.timed_out {
                "读取超时".to_string()
            } else {
                "已安装，未启用或无法读取".to_string()
            },
        });
    }

    if let Some(output) = run_command_capture("nft", &["list", "ruleset"], COMMAND_TIMEOUT) {
        let active = output.success() && !output.stdout.trim().is_empty();
        backends.push(FirewallBackend {
            kind: FirewallKind::Nftables,
            active,
            detail: if active {
                "存在 nftables 规则".to_string()
            } else if output.timed_out {
                "读取超时".to_string()
            } else {
                "无规则或无法读取".to_string()
            },
        });
    }

    if let Some(output) = run_command_capture("iptables", &["-S"], COMMAND_TIMEOUT) {
        // `iptables -S` 即使没有自定义规则也会打印 `-P INPUT ACCEPT`；只有
        // 出现非策略行才算存在规则。
        let active = output.success()
            && output
                .stdout
                .lines()
                .any(|line| !line.trim_start().starts_with("-P "));
        backends.push(FirewallBackend {
            kind: FirewallKind::Iptables,
            active,
            detail: if active {
                "存在 iptables 规则".to_string()
            } else if output.timed_out {
                "读取超时".to_string()
            } else {
                "无规则或无法读取".to_string()
            },
        });
    }

    FirewallReport {
        ports: ports.to_vec(),
        backends,
    }
}

/// 云探测门控：仅非 offline + ACME 才发起请求。
fn collect_cloud(offline: bool, mode: ServerTlsMode, timeout: Duration) -> Option<CloudHint> {
    if offline || !mode.is_acme() {
        return None;
    }
    let endpoints = METADATA_ENDPOINTS
        .iter()
        .map(|(provider, url)| (*provider, (*url).to_string()))
        .collect::<Vec<_>>();
    detect_cloud_from(&endpoints, timeout)
}

/// 依次探测给定元数据端点；任一端点返回 HTTP 200 即识别为对应厂商。
///
/// 测试用本地 `127.0.0.1` mock，生产只使用固定 link-local / 内网 IP，绝不
/// 访问用户提供的 URL。
pub(crate) fn detect_cloud_from(
    endpoints: &[(CloudProvider, String)],
    timeout: Duration,
) -> Option<CloudHint> {
    for (provider, url) in endpoints {
        if fetch_http_status(url, timeout) == Some(200) {
            return Some(CloudHint {
                provider: *provider,
            });
        }
    }
    None
}

/// 已通过校验的元数据探测目标；只允许 `http://` + 字面 IP。
#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataTarget {
    addr: SocketAddr,
    path: String,
}

/// 解析并校验 `http://<字面 IP>[:port]/path`；DNS 名一律拒绝。
///
/// 这是 [`fetch_http_status`] 建立连接前的同一道 host 校验；单测直接用该函数
/// 验证生产常量，不发起任何网络请求。
fn parse_metadata_target(url: &str) -> Option<MetadataTarget> {
    let rest = url.strip_prefix("http://")?;
    if rest.is_empty() || rest.contains('@') || rest.contains('#') || rest.contains('?') {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    if authority.is_empty() || path.is_empty() {
        return None;
    }
    let (host, port) = split_host_port(authority)?;
    if host.is_empty() {
        return None;
    }
    // 只接受字面 IP：避免 DNS 解析成为不可控的阻塞点（SSRF 面也随之收敛）。
    let ip: IpAddr = host.parse().ok()?;
    Some(MetadataTarget {
        addr: SocketAddr::new(ip, port),
        path: path.to_string(),
    })
}

/// 对 `http://<字面 IP>[:port]/path` 发 GET，只返回状态码；不读取响应体。
fn fetch_http_status(url: &str, timeout: Duration) -> Option<u16> {
    let target = parse_metadata_target(url)?;

    let started = Instant::now();
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return None;
    }
    let mut stream = TcpStream::connect_timeout(&target.addr, remaining).ok()?;
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        return None;
    }
    stream.set_read_timeout(Some(remaining)).ok()?;
    stream.set_write_timeout(Some(remaining)).ok()?;

    let host = target.addr.ip().to_string();
    let host_header = if target.addr.port() == 80 {
        host
    } else {
        format!("{host}:{}", target.addr.port())
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host_header}\r\n\
         User-Agent: rustboard-install-diagnostic\r\nAccept: */*\r\n\
         Connection: close\r\n\r\n",
        path = target.path,
    );
    stream.write_all(request.as_bytes()).ok()?;

    let mut buffer = [0u8; 512];
    let read = stream.read(&mut buffer).ok()?;
    if read == 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&buffer[..read]);
    let status_line = text.lines().next()?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

/// 解析 `host[:port]`；只支持 IPv4 / 方括号外的简单主机，IPv6 元数据不使用。
fn split_host_port(authority: &str) -> Option<(&str, u16)> {
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port.parse::<u16>().ok()?;
            Some((host, port))
        }
        Some(_) => None,
        None => Some((authority, 80)),
    }
}

/// 带超时的只读命令执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CommandOutput {
    pub(crate) status: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) timed_out: bool,
}

impl CommandOutput {
    pub(crate) fn success(&self) -> bool {
        !self.timed_out && self.status == Some(0)
    }
}

/// 用固定参数数组执行命令并收集输出；命令不存在返回 `None`。
pub(crate) fn run_command_capture(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Option<CommandOutput> {
    let owned: Vec<std::ffi::OsString> = args.iter().map(std::ffi::OsString::from).collect();
    run_command_raw(OsStr::new(program), &owned, false, timeout)
}

/// `run_command_capture` 的路径版本（安装器调用当前可执行文件的 `tls issue`）。
pub(crate) fn run_program_capture(
    program: &std::path::Path,
    args: &[std::ffi::OsString],
    timeout: Duration,
) -> Option<CommandOutput> {
    run_command_raw(program.as_os_str(), args, true, timeout)
}

/// 固定参数、不拼 shell、stdin 为 null、stdout/stderr 有上限、整体有超时。
fn run_command_raw(
    program: &OsStr,
    args: &[std::ffi::OsString],
    capture_stderr: bool,
    timeout: Duration,
) -> Option<CommandOutput> {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        // 固定 locale，避免 ss / 防火墙命令输出随环境变化；不读写任何 secret。
        .env("LC_ALL", "C");

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => return None,
    };

    let stdout_reader = child.stdout.take().map(spawn_reader);
    let stderr_reader = child.stderr.take().map(spawn_reader);
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };

    let stdout = stdout_reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr_reader
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    Some(CommandOutput {
        status: status.and_then(|status| status.code()),
        stdout,
        stderr,
        timed_out,
    })
}

fn spawn_reader<R: Read + Send + 'static>(mut reader: R) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut collected = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    if collected.len() < OUTPUT_LIMIT {
                        let take = read.min(OUTPUT_LIMIT - collected.len());
                        collected.extend_from_slice(&chunk[..take]);
                    }
                    if collected.len() >= OUTPUT_LIMIT {
                        // 丢弃剩余输出，避免异常命令撑爆内存；关闭读端即可。
                        break;
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&collected).into_owned()
    })
}

/// 缺少 `ss` 时的通用提示（供安装器在端口冲突时打印）。
pub(crate) fn generic_port_holder_hint(port: u16) -> String {
    format!(
        "无法确定 {} 端口的占用进程（ss 不可用或无权限）；请用 `ss -ltnp 'sport = :{}'` \
         或 `lsof -iTCP:{} -sTCP:LISTEN` 手工排查",
        port, port, port
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn sample_firewall_report() -> FirewallReport {
        FirewallReport {
            ports: vec![80, 443],
            backends: vec![
                FirewallBackend {
                    kind: FirewallKind::Ufw,
                    active: true,
                    detail: "已启用".to_string(),
                },
                FirewallBackend {
                    kind: FirewallKind::Firewalld,
                    active: true,
                    detail: "已启用".to_string(),
                },
                FirewallBackend {
                    kind: FirewallKind::Nftables,
                    active: false,
                    detail: "无规则".to_string(),
                },
                FirewallBackend {
                    kind: FirewallKind::Iptables,
                    active: true,
                    detail: "存在规则".to_string(),
                },
            ],
        }
    }

    #[test]
    fn occupied_port_is_not_bindable() {
        let listener = TcpListener::bind("0.0.0.0:0").expect("绑定临时端口");
        let port = listener.local_addr().unwrap().port();

        let check = check_port_bind(port);
        assert!(!check.bindable, "{check:?}");
        assert_eq!(check.port, port);
        assert!(
            check.detail.contains("占用") || check.detail.contains("权限"),
            "{check:?}"
        );
        drop(listener);
    }

    #[test]
    fn released_port_is_bindable() {
        // 释放端口与探测之间可能被并行测试/进程抢占；重试几个临时端口，
        // 避免全量测试并行运行时出现与安装器逻辑无关的偶发失败。
        for _ in 0..10 {
            let listener = TcpListener::bind("0.0.0.0:0").expect("绑定临时端口");
            let port = listener.local_addr().unwrap().port();
            drop(listener);

            let check = check_port_bind(port);
            if check.bindable {
                return;
            }
        }
        panic!("连续 10 个临时端口在释放后都被抢占");
    }

    #[test]
    fn parses_ss_holder_line() {
        let text = "\
State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n\
LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=123,fd=6))\n\
LISTEN 0 511 127.0.0.1:9000 0.0.0.0:* users:((\"rustboard-hub\",pid=456,fd=7))\n";
        let holder = parse_ss_output(text, 80).expect("应解析到 80 的占用者");
        assert_eq!(holder.pid, Some(123));
        assert_eq!(holder.process.as_deref(), Some("nginx"));

        let holder = parse_ss_output(text, 9000).expect("应解析到 9000 的占用者");
        assert_eq!(holder.pid, Some(456));
        assert_eq!(holder.process.as_deref(), Some("rustboard-hub"));

        assert!(parse_ss_output(text, 443).is_none());
        // 端口必须是精确匹配：:800 不应匹配 :80。
        assert!(parse_ss_output("LISTEN 0 1 0.0.0.0:800 0.0.0.0:*", 80).is_none());
    }

    #[test]
    fn generates_exact_firewall_allow_commands() {
        let commands = sample_firewall_report().allow_commands();
        assert_eq!(
            commands,
            vec![
                "ufw allow 80/tcp",
                "ufw allow 443/tcp",
                "firewall-cmd --permanent --add-port=80/tcp",
                "firewall-cmd --permanent --add-port=443/tcp",
                "firewall-cmd --reload",
                "iptables -A INPUT -p tcp --dport 80 -j ACCEPT",
                "iptables -A INPUT -p tcp --dport 443 -j ACCEPT",
            ]
        );
    }

    #[test]
    fn inactive_firewall_generates_no_commands() {
        let report = FirewallReport {
            ports: vec![80, 443],
            backends: vec![FirewallBackend {
                kind: FirewallKind::Ufw,
                active: false,
                detail: "未启用".to_string(),
            }],
        };
        assert!(report.allow_commands().is_empty());
    }

    fn spawn_metadata_mock(status: u16) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定 mock 元数据服务");
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buffer = [0u8; 1024];
                let _ = stream.read(&mut buffer);
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        addr
    }

    #[test]
    fn detects_cloud_provider_from_local_mock() {
        let addr = spawn_metadata_mock(200);
        let endpoints = vec![(
            CloudProvider::Aliyun,
            format!("http://127.0.0.1:{}/latest/meta-data/", addr.port()),
        )];
        let hint = detect_cloud_from(&endpoints, Duration::from_secs(1)).expect("应识别阿里云");
        assert_eq!(hint.provider, CloudProvider::Aliyun);
    }

    #[test]
    fn returns_none_when_metadata_returns_non_200() {
        let addr = spawn_metadata_mock(404);
        let endpoints = vec![(
            CloudProvider::Aws,
            format!("http://127.0.0.1:{}/latest/meta-data/", addr.port()),
        )];
        assert!(detect_cloud_from(&endpoints, Duration::from_secs(1)).is_none());
    }

    #[test]
    fn production_metadata_constants_pass_literal_ip_probe_validation() {
        // 三个生产常量必须全部通过 fetch_http_status 使用的同一道 host 校验；
        // 这里只做纯字符串/地址解析，不发起任何网络请求。
        let expected = [
            (CloudProvider::Aws, AWS_METADATA_URL, "169.254.169.254"),
            (
                CloudProvider::Aliyun,
                ALIYUN_METADATA_URL,
                "100.100.100.200",
            ),
            (CloudProvider::Tencent, TENCENT_METADATA_URL, "169.254.0.23"),
        ];
        // 生产探测表必须与常量逐一对应；只改常量却漏改 collect_cloud 的表会在这里失败。
        assert_eq!(
            METADATA_ENDPOINTS,
            [
                (CloudProvider::Aws, AWS_METADATA_URL),
                (CloudProvider::Aliyun, ALIYUN_METADATA_URL),
                (CloudProvider::Tencent, TENCENT_METADATA_URL),
            ],
            "METADATA_ENDPOINTS 的 provider↔URL 映射与生产常量不一致"
        );
        for (provider, url, expected_ip) in expected {
            let target = parse_metadata_target(url).unwrap_or_else(|| {
                panic!(
                    "{} 元数据地址未通过字面 IP host 校验: {url}",
                    provider.label()
                )
            });
            assert_eq!(target.addr.ip().to_string(), expected_ip, "{url}");
            assert_eq!(target.addr.port(), 80, "{url}");
            assert_eq!(target.path, "/latest/meta-data/", "{url}");
        }

        // 腾讯云的固定地址必须与 AWS 的 169.254.169.254 区分，避免误判厂商。
        let tencent = parse_metadata_target(TENCENT_METADATA_URL).expect("腾讯云地址");
        let aws = parse_metadata_target(AWS_METADATA_URL).expect("AWS 地址");
        assert_ne!(tencent.addr.ip(), aws.addr.ip());

        // #73 的根因：域名形式会被 host 校验直接拒绝，绝不能进入网络探测。
        assert!(
            parse_metadata_target("http://metadata.tencentyun.com/latest/meta-data/").is_none(),
            "元数据域名必须被拒绝，只允许字面 IP"
        );
    }

    #[test]
    fn metadata_probe_is_bounded_by_timeout() {
        // 只 accept 不响应：探测必须在超时内返回 None，而不是挂住安装。
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let _held = listener.accept();
            thread::sleep(Duration::from_secs(2));
        });
        let endpoints = vec![(
            CloudProvider::Tencent,
            format!("http://127.0.0.1:{}/latest/meta-data/", addr.port()),
        )];
        let started = Instant::now();
        assert!(detect_cloud_from(&endpoints, Duration::from_millis(150)).is_none());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "元数据探测没有按超时返回: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn offline_and_self_signed_never_probe_cloud() {
        assert!(collect_cloud(true, ServerTlsMode::AcmeDomain, CLOUD_TIMEOUT).is_none());
        assert!(collect_cloud(false, ServerTlsMode::SelfSigned, CLOUD_TIMEOUT).is_none());
    }

    #[test]
    fn layers_mark_challenge_port_conflict_as_failure() {
        let diagnostics = Diagnostics {
            challenge: AcmeChallenge::Http01,
            ports: vec![
                PortCheck {
                    port: 80,
                    bindable: false,
                    holder: Some(PortHolder {
                        pid: Some(123),
                        process: Some("nginx".to_string()),
                    }),
                    detail: "端口已被占用".to_string(),
                },
                PortCheck {
                    port: 443,
                    bindable: true,
                    holder: None,
                    detail: "可绑定".to_string(),
                },
            ],
            firewall: FirewallReport {
                ports: vec![80, 443],
                backends: Vec::new(),
            },
            cloud: None,
        };
        let layers = diagnostics.layers(StagingOutcome::NotRun);
        assert_eq!(layers[0].status, LayerStatus::Fail);
        assert!(layers[0].detail.contains("80"), "{:?}", layers[0]);
        assert!(
            layers[0]
                .commands
                .iter()
                .any(|command| command.contains("ss -ltnp")),
            "{:?}",
            layers[0].commands
        );
        assert_eq!(layers[1].status, LayerStatus::Ok);
        assert_eq!(layers[2].status, LayerStatus::Skipped);
        assert_eq!(layers[3].status, LayerStatus::Skipped);

        let failed = diagnostics.layers(StagingOutcome::Failed("mock 失败".to_string()));
        assert_eq!(failed[3].status, LayerStatus::Fail);
        assert!(failed[3].detail.contains("mock 失败"));
    }

    #[test]
    fn challenge_port_follows_challenge_type() {
        let diagnostics = Diagnostics {
            challenge: AcmeChallenge::TlsAlpn01,
            ports: vec![
                PortCheck {
                    port: 80,
                    bindable: true,
                    holder: None,
                    detail: String::new(),
                },
                PortCheck {
                    port: 443,
                    bindable: false,
                    holder: None,
                    detail: String::new(),
                },
            ],
            firewall: FirewallReport {
                ports: vec![80, 443],
                backends: Vec::new(),
            },
            cloud: None,
        };
        assert_eq!(diagnostics.challenge_port(), 443);
        assert!(!diagnostics.challenge_ready());
    }

    #[test]
    fn generic_hint_contains_read_only_commands() {
        let hint = generic_port_holder_hint(80);
        assert!(hint.contains("ss -ltnp"), "{hint}");
        assert!(hint.contains("lsof"), "{hint}");
    }
}
