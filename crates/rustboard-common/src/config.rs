use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::{control, Error, Result};

/// hub 服务端密码套件/证书来源模式。
///
/// - `self-signed`：v0.4 行为，本地 CA 自签服务端证书 + agent 指纹钉扎；
/// - `acme-domain`：ACME 域名证书（DNS identifier）；
/// - `acme-ip`：ACME IP 证书（IPv4 identifier，通常用短期 profile）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServerTlsMode {
    /// 自签证书（默认，保持旧配置行为）。
    #[default]
    SelfSigned,
    /// ACME 域名证书。
    AcmeDomain,
    /// ACME IPv4 证书。
    AcmeIp,
}

impl ServerTlsMode {
    /// 稳定的字符串名（日志/CLI 展示用，与 serde 名称一致）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfSigned => "self-signed",
            Self::AcmeDomain => "acme-domain",
            Self::AcmeIp => "acme-ip",
        }
    }

    /// 是否由 ACME 管理服务端证书。
    pub fn is_acme(self) -> bool {
        !matches!(self, Self::SelfSigned)
    }
}

/// ACME 挑战类型。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcmeChallenge {
    /// HTTP-01（默认）：临时监听 80 端口提供 key authorization。
    #[default]
    #[serde(rename = "http-01")]
    Http01,
    /// TLS-ALPN-01：临时监听 443 端口，仅接受 `acme-tls/1`。
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

impl AcmeChallenge {
    /// 稳定的字符串名（与 serde 名称一致，可用于日志/诊断输出）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::TlsAlpn01 => "tls-alpn-01",
        }
    }
}

/// agent 的服务端信任模型。
///
/// 旧配置缺 `tls_mode` 时默认 `fingerprint`，行为与 v0.4 完全一致。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentTlsMode {
    /// 指纹钉扎（默认）：bootstrap 与已纳管都依赖 `server_fingerprint`。
    #[default]
    Fingerprint,
    /// 系统根证书 + URL 主机名校验（公共 ACME 证书）。
    SystemRoots,
    /// 指定 CA（`server_ca`）+ URL 主机名校验（私有 ACME / 自签 CA）。
    CustomCa,
}

impl AgentTlsMode {
    /// 稳定的字符串名（与 serde/CLI 名称一致）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fingerprint => "fingerprint",
            Self::SystemRoots => "system-roots",
            Self::CustomCa => "custom-ca",
        }
    }
}

/// Let's Encrypt v2 production ACME 目录（默认值）。
pub const DEFAULT_ACME_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// hub 服务端证书来源与 ACME 参数。对应 `hub.toml` 的 `[tls]`。
///
/// 全部字段有默认值：旧配置完全没有 `[tls]` 时等价于 `mode = "self-signed"`，
/// 不要求任何 ACME 字段，行为与 v0.4 一致。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    /// 服务端证书来源。
    pub mode: ServerTlsMode,
    /// ACME 账户联系邮箱；ACME 模式必填。
    pub acme_email: String,
    /// ACME directory URL；ACME 模式必须是 `https://` 且无 userinfo/fragment。
    pub acme_directory: String,
    /// ACME 挑战类型。
    pub challenge: AcmeChallenge,
    /// 证书标识：`acme-domain` 为 1–20 个 DNS 名，`acme-ip` 为恰好一个 IPv4。
    pub domains: Vec<String>,
    /// ACME profile；`acme-ip` 留空时运行时默认 `shortlived`，`acme-domain` 留空不设置。
    pub acme_profile: String,
    /// 私有/Pebble ACME 的根 CA（PEM 绝对路径）；留空使用系统根。
    pub acme_ca_file: String,
    /// 私有 ACME 签发链的稳定信任锚（PEM 绝对路径，可选）。
    ///
    /// `acme_ca_file` 是 ACME WFE 的 HTTPS 根，**不是**服务端证书链的 CA；
    /// 若私有 ACME 的链尾会轮换（中间 CA），应把稳定根写在这里。留空时
    /// 安装器从 `server.crt` 链尾派生 `agent-ca.pem`。
    pub agent_ca_file: String,
    /// 安装时先跑一次 staging 挑战（失败按 `fallback_to_self_signed` 处理）。
    pub staging_check: bool,
    /// ACME 获取证书失败时是否回退 self-signed 继续安装。
    pub fallback_to_self_signed: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: ServerTlsMode::SelfSigned,
            acme_email: String::new(),
            acme_directory: DEFAULT_ACME_DIRECTORY.to_string(),
            challenge: AcmeChallenge::Http01,
            domains: Vec::new(),
            acme_profile: String::new(),
            acme_ca_file: String::new(),
            agent_ca_file: String::new(),
            staging_check: true,
            fallback_to_self_signed: true,
        }
    }
}

impl TlsConfig {
    /// 配置级校验；不读文件、不访问网络。
    ///
    /// `self-signed` 模式不要求/不校验任何 ACME 字段（旧配置即使带着无关的
    /// ACME 字段也不影响启动）。ACME 模式的错误信息统一以 `tls.` 开头，
    /// 便于运维定位，且只包含公开配置值（邮箱、域名、路径），不涉及私钥。
    pub fn validate(&self) -> Result<()> {
        match self.mode {
            ServerTlsMode::SelfSigned => Ok(()),
            ServerTlsMode::AcmeDomain => {
                self.validate_acme_common()?;
                if !(1..=MAX_ACME_DOMAINS).contains(&self.domains.len()) {
                    return Err(Error::InvalidConfig(format!(
                        "tls.domains 在 acme-domain 模式下必须包含 1–{MAX_ACME_DOMAINS} 个域名，\
                         实际 {} 个",
                        self.domains.len()
                    )));
                }
                for domain in &self.domains {
                    validate_acme_dns_name(domain)?;
                }
                Ok(())
            }
            ServerTlsMode::AcmeIp => {
                self.validate_acme_common()?;
                if self.domains.len() != 1 {
                    return Err(Error::InvalidConfig(format!(
                        "tls.domains 在 acme-ip 模式下必须恰好包含一个 IPv4 地址，实际 {} 个",
                        self.domains.len()
                    )));
                }
                validate_acme_ipv4(&self.domains[0])
            }
        }
    }

    /// 两种 ACME 模式共用的字段校验。
    fn validate_acme_common(&self) -> Result<()> {
        validate_acme_email(&self.acme_email)?;
        validate_acme_directory(&self.acme_directory)?;
        if !self.acme_profile.trim().is_empty() {
            validate_acme_profile(&self.acme_profile)?;
        }
        if !self.acme_ca_file.trim().is_empty() {
            validate_absolute_config_path("tls.acme_ca_file", &self.acme_ca_file)?;
        }
        if !self.agent_ca_file.trim().is_empty() {
            validate_absolute_config_path("tls.agent_ca_file", &self.agent_ca_file)?;
        }
        Ok(())
    }
}

/// `acme-domain` 最多允许的域名数量。
const MAX_ACME_DOMAINS: usize = 20;

/// ACME 邮箱的基本格式校验：非空、恰好一个 `@`、无空白/控制字符。
fn validate_acme_email(email: &str) -> Result<()> {
    if email.is_empty() {
        return Err(Error::InvalidConfig(
            "tls.acme_email 在 ACME 模式下不能为空".into(),
        ));
    }
    if email
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(Error::InvalidConfig(
            "tls.acme_email 不能包含空白或控制字符".into(),
        ));
    }
    let mut parts = email.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    if local.is_empty() || domain.is_empty() || parts.next().is_some() {
        return Err(Error::InvalidConfig(
            "tls.acme_email 必须是 `name@example.com` 形式（恰好一个 @，两侧非空）".into(),
        ));
    }
    Ok(())
}

/// ACME directory 必须是 https、带主机名、无 userinfo/fragment。
fn validate_acme_directory(directory: &str) -> Result<()> {
    if directory.is_empty() {
        return Err(Error::InvalidConfig("tls.acme_directory 不能为空".into()));
    }
    if directory
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(Error::InvalidConfig(
            "tls.acme_directory 不能包含空白或控制字符".into(),
        ));
    }
    let Some(rest) = directory.strip_prefix("https://") else {
        return Err(Error::InvalidConfig(
            "tls.acme_directory 必须以 https:// 开头".into(),
        ));
    };
    // authority 截止到 path/query/fragment；userinfo 只可能出现在 authority 里。
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return Err(Error::InvalidConfig("tls.acme_directory 缺少主机名".into()));
    }
    if authority.contains('@') {
        return Err(Error::InvalidConfig(
            "tls.acme_directory 不能包含 userinfo（@）".into(),
        ));
    }
    if directory.contains('#') {
        return Err(Error::InvalidConfig(
            "tls.acme_directory 不能包含 fragment（#）".into(),
        ));
    }
    Ok(())
}

/// ACME profile 名：非空时只接受短小的 ASCII 标识符。
fn validate_acme_profile(profile: &str) -> Result<()> {
    if profile.len() > 64 {
        return Err(Error::InvalidConfig(
            "tls.acme_profile 长度不能超过 64 字节".into(),
        ));
    }
    if !profile
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(Error::InvalidConfig(
            "tls.acme_profile 只能包含字母、数字、'-'、'_'".into(),
        ));
    }
    Ok(())
}

/// `acme-domain` 的单个标识：必须是合法 DNS 名，禁止通配符与 IP。
fn validate_acme_dns_name(raw: &str) -> Result<()> {
    if raw.is_empty() {
        return Err(Error::InvalidConfig(
            "tls.domains 含空条目，无法申请 ACME 域名证书".into(),
        ));
    }
    if raw.trim() != raw {
        return Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 不能包含首尾空白"
        )));
    }
    if raw.contains('*') {
        return Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 含通配符 `*`；v1 不支持通配符证书"
        )));
    }
    if raw.parse::<IpAddr>().is_ok() {
        return Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 是 IP；acme-domain 模式只接受 DNS 域名（IP 请用 acme-ip）"
        )));
    }
    if raw.len() > 253 {
        return Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 长度超过 253 字节"
        )));
    }
    if raw.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 含空白或控制字符"
        )));
    }
    if raw.starts_with('.') || raw.ends_with('.') || raw.contains("..") {
        return Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 的 DNS 标签为空（首尾点或连续点）"
        )));
    }
    for label in raw.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(Error::InvalidConfig(format!(
                "tls.domains 条目 {raw:?} 的单个标签长度为 0 或超过 63 字节"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(Error::InvalidConfig(format!(
                "tls.domains 条目 {raw:?} 的标签不能以 '-' 开头或结尾"
            )));
        }
        if !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
        {
            return Err(Error::InvalidConfig(format!(
                "tls.domains 条目 {raw:?} 的标签只能包含字母、数字、'-'"
            )));
        }
    }
    Ok(())
}

/// `acme-ip` 的唯一标识：必须是 IPv4（明确拒绝 IPv6/空/域名）。
fn validate_acme_ipv4(raw: &str) -> Result<()> {
    if raw.trim() != raw {
        return Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 不能包含首尾空白"
        )));
    }
    match raw.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Ok(()),
        Ok(IpAddr::V6(_)) => Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 是 IPv6；acme-ip 模式只支持 IPv4"
        ))),
        Err(_) => Err(Error::InvalidConfig(format!(
            "tls.domains 条目 {raw:?} 不是合法 IPv4 地址"
        ))),
    }
}

/// 配置中的文件路径：绝对路径、无控制字符、无首尾空白。
///
/// 只做配置层校验；文件是否存在、权限、符号链接由运行时（安装器/加载器）校验。
fn validate_absolute_config_path(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidConfig(format!("{field} 不能为空")));
    }
    if value.trim() != value {
        return Err(Error::InvalidConfig(format!("{field} 不能包含首尾空白")));
    }
    if value.chars().any(|ch| ch.is_control()) {
        return Err(Error::InvalidConfig(format!(
            "{field} 不能包含控制字符（如 NUL/换行）"
        )));
    }
    if !Path::new(value).is_absolute() {
        return Err(Error::InvalidConfig(format!(
            "{field} 必须是绝对路径，实际 {value:?}"
        )));
    }
    Ok(())
}

/// agent 端配置。对应 `/etc/rustboard/agent.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// hub 的 WebSocket 入口，例如 `ws://10.0.0.1:8443/agent/ws`。
    pub hub_url: String,
    /// 纳管时由 `rustboard-hub agent add` 生成的一次性 token。
    pub token: String,
    /// hub 服务端证书的 SHA-256 指纹（hex）。`fingerprint` 模式下必须与安装命令一致。
    pub server_fingerprint: String,
    /// 服务端信任模型；旧配置缺该字段时为 `fingerprint`。
    #[serde(default)]
    pub tls_mode: AgentTlsMode,
    /// `custom-ca` 模式下服务端 CA 证书（PEM）的绝对路径。
    ///
    /// 安装器会把 `--server-ca` 复制到 `<data_dir>/server-ca.pem` 并写入该路径。
    #[serde(default)]
    pub server_ca: String,
    /// 展示名，留空则用 hostname。
    pub name: String,
    pub data_dir: PathBuf,
    /// 采样间隔，hub 可以在运行时下发覆盖值。
    pub sample_interval_ms: u64,
    /// 是否采集每核 CPU（会增加点数）。
    pub per_core: bool,
    /// 需要忽略的网卡名前缀。
    pub excluded_interfaces: Vec<String>,
    /// 本地环形缓冲的最大字节数。
    pub buffer_max_bytes: u64,
    /// 本地缓冲的最长保留小时数（与字节上限取先到者）。
    #[serde(default = "default_buffer_max_age_hours")]
    pub buffer_max_age_hours: u64,
    /// 客户端证书剩余寿命不超过该天数时自动轮换。
    #[serde(default = "default_cert_renew_before_days")]
    pub cert_renew_before_days: u32,
    /// 主动重连周期（小时），让轮换后的证书与 hub 配置有机会生效；0 表示不主动重连。
    #[serde(default = "default_session_max_hours")]
    pub session_max_hours: u64,
    /// 单次 WebSocket 写操作的超时（秒），范围 1–120。
    ///
    /// 服务端不读（半死连接）时，超过该时长仍未写完就断开当前会话并走重连退避；
    /// 默认 15 秒，与 hub 侧会话写超时保持一致。
    #[serde(default = "default_send_timeout_secs")]
    pub send_timeout_secs: u64,
    /// 会话空闲时的客户端证书检查周期（小时）。
    ///
    /// 即使 `session_max_hours = 0`（永不主动重连），也要周期检查证书剩余寿命，
    /// 否则超长会话会错过续签窗口。范围 1–168。
    #[serde(default = "default_cert_check_interval_hours")]
    pub cert_check_interval_hours: u64,
    /// 单批最多多少条采样点。
    pub max_batch_samples: usize,
    /// M3 控制面配置；默认全部关闭，旧配置无需新增任何字段。
    #[serde(default)]
    pub control: ControlConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            hub_url: format!("ws://127.0.0.1:{}/agent/ws", crate::DEFAULT_AGENT_PORT),
            token: String::new(),
            server_fingerprint: String::new(),
            tls_mode: AgentTlsMode::Fingerprint,
            server_ca: String::new(),
            name: String::new(),
            data_dir: PathBuf::from("/var/lib/rustboard/agent"),
            sample_interval_ms: 5_000,
            per_core: false,
            excluded_interfaces: default_excluded_interfaces(),
            buffer_max_bytes: 500 * 1024 * 1024,
            buffer_max_age_hours: 24,
            cert_renew_before_days: default_cert_renew_before_days(),
            session_max_hours: default_session_max_hours(),
            send_timeout_secs: default_send_timeout_secs(),
            cert_check_interval_hours: default_cert_check_interval_hours(),
            max_batch_samples: 512,
            control: ControlConfig::default(),
        }
    }
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        crate::error::load_toml(path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::error::save_toml(path, self)
    }

    pub fn validate(&self) -> Result<()> {
        // KI-21：data_dir 完全归 agent 所有。共享 / 系统目录会被启动初始化
        // chmod 成 0700，必须在读取配置时就拒绝，而不是等 prepare_data_dir 动手。
        crate::fsutil::validate_private_dir_path(&self.data_dir)
            .map_err(|err| Error::InvalidConfig(format!("data_dir 不安全: {err}")))?;
        if self.hub_url.trim().is_empty() {
            return Err(Error::InvalidConfig("hub_url 不能为空".into()));
        }
        if !self.hub_url.starts_with("ws://") && !self.hub_url.starts_with("wss://") {
            return Err(Error::InvalidConfig(
                "hub_url 必须以 ws:// 或 wss:// 开头".into(),
            ));
        }
        if self.sample_interval_ms < 1_000 {
            return Err(Error::InvalidConfig("采样间隔不能小于 1000ms".into()));
        }
        if self.hub_url.starts_with("wss://") {
            match self.tls_mode {
                // 旧行为：wss + fingerprint 必须有指纹。
                AgentTlsMode::Fingerprint => {
                    if self.server_fingerprint.trim().is_empty() {
                        return Err(Error::InvalidConfig(
                            "wss:// 连接必须配置 server_fingerprint（安装命令里会给出）".into(),
                        ));
                    }
                }
                // 系统根由 rustls-native-certs 在运行时加载，配置层不要求任何字段。
                AgentTlsMode::SystemRoots => {}
                // custom-ca 必须显式给出服务端 CA，绝不静默回退到指纹。
                AgentTlsMode::CustomCa => {
                    if self.server_ca.trim().is_empty() {
                        return Err(Error::InvalidConfig(
                            "wss:// + custom-ca 必须配置 server_ca（CA 证书的绝对路径）".into(),
                        ));
                    }
                }
            }
        } else if self.tls_mode != AgentTlsMode::Fingerprint {
            // 明文 ws:// 不构建 TLS connector：system-roots / custom-ca 的 CA
            // 与主机名校验会被完全忽略，必须拒绝，避免「配置了 CA 却明文传输」。
            return Err(Error::InvalidConfig(format!(
                "hub_url 为明文 ws:// 时只能使用 tls_mode=fingerprint；\
                 {} 必须使用 wss://（否则 CA/主机名校验会被忽略）",
                self.tls_mode.as_str()
            )));
        }
        // server_ca 只在 custom-ca 下有语义：其他模式携带非空 CA 会在运行时被
        // 静默忽略，必须在配置层拒绝（install/init 复用同一校验）。
        if !self.server_ca.trim().is_empty() {
            if self.tls_mode != AgentTlsMode::CustomCa {
                return Err(Error::InvalidConfig(format!(
                    "server_ca 只在 tls_mode=custom-ca 时允许（当前 {}）；\
                     请清空 server_ca 或改用 custom-ca",
                    self.tls_mode.as_str()
                )));
            }
            validate_absolute_config_path("server_ca", &self.server_ca)?;
        }
        // 续签阈值至少 1 天：0 会让「剩余寿命 ≤ 阈值」在刚签发后就成立。
        if self.cert_renew_before_days < 1 {
            return Err(Error::InvalidConfig(
                "cert_renew_before_days 至少为 1 天".into(),
            ));
        }
        // 主动重连周期上限 1 年：更大的值等价于不主动重连，且容易是单位写错。
        if self.session_max_hours > MAX_SESSION_MAX_HOURS {
            return Err(Error::InvalidConfig(format!(
                "session_max_hours 不能超过 {MAX_SESSION_MAX_HOURS}（0 表示不主动重连）"
            )));
        }
        // 写超时是半死连接的唯一退出手段：0 会让每次写立刻失败，过大则长期卡住会话。
        if !(MIN_SEND_TIMEOUT_SECS..=MAX_SEND_TIMEOUT_SECS).contains(&self.send_timeout_secs) {
            return Err(Error::InvalidConfig(format!(
                "send_timeout_secs 必须在 {MIN_SEND_TIMEOUT_SECS}–{MAX_SEND_TIMEOUT_SECS} 秒之间，\
                 实际 {}",
                self.send_timeout_secs
            )));
        }
        // 会话内周期检查必须有下界：0 会让定时器变成忙循环，超长周期则等于没检查。
        if !(MIN_CERT_CHECK_INTERVAL_HOURS..=MAX_CERT_CHECK_INTERVAL_HOURS)
            .contains(&self.cert_check_interval_hours)
        {
            return Err(Error::InvalidConfig(format!(
                "cert_check_interval_hours 必须在 {MIN_CERT_CHECK_INTERVAL_HOURS}–\
                 {MAX_CERT_CHECK_INTERVAL_HOURS} 小时之间，实际 {}",
                self.cert_check_interval_hours
            )));
        }
        self.control.validate()?;
        Ok(())
    }
}

/// agent 端控制面配置。对应 `agent.toml` 的 `[control]`。
///
/// 全部默认关闭：旧配置（完全没有 `[control]`）启动后能力列表为空，
/// hub 不会下发控制帧，采集链路完全不受影响。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ControlConfig {
    /// 控制面总开关。单项能力开启时必须同时为 true。
    pub enabled: bool,
    /// 是否启用 systemd 管理。
    pub systemd: bool,
    /// 是否启用 Docker 管理。
    pub docker: bool,
    /// 是否启用进程查看与结束。
    pub process: bool,
    /// 是否启用只读日志。
    pub logs: bool,
    /// systemd 白名单：精确 unit 或尾部 `*` 前缀，例如 `["nginx*"]`。
    pub systemd_units: Vec<String>,
    /// Docker 白名单：精确容器名或尾部 `*` 前缀，例如 `["web-*"]`。
    pub docker_containers: Vec<String>,
    /// 日志来源白名单；`logs` 开启时不能为空。
    pub log_sources: Vec<LogSourceConfig>,
    /// 单条外部命令的超时（秒），1–60。
    pub command_timeout_secs: u64,
    /// 单次日志 tail 允许的最大行数，1–2000。
    pub max_log_lines: u32,
    /// systemctl 绝对路径；留空则按固定候选目录探测。
    pub systemctl_path: String,
    /// docker 绝对路径；留空则按固定候选目录探测。
    pub docker_path: String,
    /// journalctl 绝对路径；留空则按固定候选目录探测。
    pub journalctl_path: String,
}

impl Default for ControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            systemd: false,
            docker: false,
            process: false,
            logs: false,
            systemd_units: Vec::new(),
            docker_containers: Vec::new(),
            log_sources: Vec::new(),
            command_timeout_secs: control::DEFAULT_COMMAND_TIMEOUT_SECS,
            max_log_lines: control::DEFAULT_MAX_LOG_LINES,
            systemctl_path: String::new(),
            docker_path: String::new(),
            journalctl_path: String::new(),
        }
    }
}

impl ControlConfig {
    /// 配置级校验（纯函数，不做文件 I/O）。
    ///
    /// 文件日志的父目录存在性 / 符号链接检查在 agent 启动时由
    /// `rustboard_agent::control::validate_io` 完成。
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            for (name, enabled) in [
                ("systemd", self.systemd),
                ("docker", self.docker),
                ("process", self.process),
                ("logs", self.logs),
            ] {
                if enabled {
                    return Err(Error::InvalidConfig(format!(
                        "control.{name} 已开启但 control.enabled=false；请先开启总开关"
                    )));
                }
            }
        }

        // 能力开启但白名单为空会让“看起来开了、实际什么都操作不了”，启动即拒绝。
        // process 是天然全量列表，不需要白名单。
        if self.systemd && self.systemd_units.is_empty() {
            return Err(Error::InvalidConfig(
                "control.systemd 已开启但 control.systemd_units 为空".into(),
            ));
        }
        if self.docker && self.docker_containers.is_empty() {
            return Err(Error::InvalidConfig(
                "control.docker 已开启但 control.docker_containers 为空".into(),
            ));
        }
        if self.logs && self.log_sources.is_empty() {
            return Err(Error::InvalidConfig(
                "control.logs 已开启但 control.log_sources 为空".into(),
            ));
        }

        for (index, pattern) in self.systemd_units.iter().enumerate() {
            control::validate_unit_pattern(pattern).map_err(|err| {
                Error::InvalidConfig(format!("control.systemd_units[{index}] 非法: {err}"))
            })?;
        }
        for (index, pattern) in self.docker_containers.iter().enumerate() {
            control::validate_container_pattern(pattern).map_err(|err| {
                Error::InvalidConfig(format!("control.docker_containers[{index}] 非法: {err}"))
            })?;
        }

        let mut seen_ids = HashSet::new();
        for (index, source) in self.log_sources.iter().enumerate() {
            control::validate_source_id(&source.id).map_err(|err| {
                Error::InvalidConfig(format!("control.log_sources[{index}].id 非法: {err}"))
            })?;
            if !seen_ids.insert(source.id.as_str()) {
                return Err(Error::InvalidConfig(format!(
                    "control.log_sources 中 id 重复: {}",
                    source.id
                )));
            }
            if !source.name.is_empty() {
                if source.name.len() > control::MAX_TARGET_LEN {
                    return Err(Error::InvalidConfig(format!(
                        "control.log_sources[{index}].name 不能超过 {} 字节",
                        control::MAX_TARGET_LEN
                    )));
                }
                if source.name.chars().any(char::is_control) {
                    return Err(Error::InvalidConfig(format!(
                        "control.log_sources[{index}].name 不能包含控制字符"
                    )));
                }
            }
            match source.kind {
                LogSourceKind::File => {
                    control::validate_log_file_target(&source.target).map_err(|err| {
                        Error::InvalidConfig(format!(
                            "control.log_sources[{index}].target 非法: {err}"
                        ))
                    })?;
                }
                LogSourceKind::Journal => {
                    control::validate_unit_name(&source.target).map_err(|err| {
                        Error::InvalidConfig(format!(
                            "control.log_sources[{index}].target 不是合法 unit: {err}"
                        ))
                    })?;
                    if control::is_forbidden_unit(&source.target) {
                        return Err(Error::InvalidConfig(format!(
                            "control.log_sources[{index}].target 是禁止操作的 unit: {}",
                            source.target
                        )));
                    }
                    if !control::unit_matches_whitelist(&source.target, &self.systemd_units) {
                        return Err(Error::InvalidConfig(format!(
                            "journal 日志来源 {} 的 target {} 必须同时出现在 control.systemd_units 白名单中",
                            source.id, source.target
                        )));
                    }
                }
            }
        }

        if !(control::MIN_COMMAND_TIMEOUT_SECS..=control::MAX_COMMAND_TIMEOUT_SECS)
            .contains(&self.command_timeout_secs)
        {
            return Err(Error::InvalidConfig(format!(
                "control.command_timeout_secs 必须在 {}–{} 之间，实际 {}",
                control::MIN_COMMAND_TIMEOUT_SECS,
                control::MAX_COMMAND_TIMEOUT_SECS,
                self.command_timeout_secs
            )));
        }
        if !(control::MIN_MAX_LOG_LINES..=control::MAX_MAX_LOG_LINES).contains(&self.max_log_lines)
        {
            return Err(Error::InvalidConfig(format!(
                "control.max_log_lines 必须在 {}–{} 之间，实际 {}",
                control::MIN_MAX_LOG_LINES,
                control::MAX_MAX_LOG_LINES,
                self.max_log_lines
            )));
        }

        for (name, path) in [
            ("systemctl_path", &self.systemctl_path),
            ("docker_path", &self.docker_path),
            ("journalctl_path", &self.journalctl_path),
        ] {
            if path.is_empty() {
                continue;
            }
            if path.contains('\0') {
                return Err(Error::InvalidConfig(format!("control.{name} 不能包含 NUL")));
            }
            if !Path::new(path).is_absolute() {
                return Err(Error::InvalidConfig(format!(
                    "control.{name} 必须是绝对路径（留空则按固定候选目录探测）"
                )));
            }
        }

        Ok(())
    }
}

/// 单个日志来源的配置。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct LogSourceConfig {
    /// 唯一 id，hub 用它在 `LogTail` 中指定来源。
    pub id: String,
    pub kind: LogSourceKind,
    /// file 为绝对路径；journal 为白名单 unit 名。
    pub target: String,
    /// 展示名；留空时使用 `id`。
    pub name: String,
}

impl Default for LogSourceConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            kind: LogSourceKind::File,
            target: String::new(),
            name: String::new(),
        }
    }
}

/// 日志来源类型。
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LogSourceKind {
    /// 白名单文件，读取时使用 `openat2` 防路径逃逸。
    #[default]
    File,
    /// journald，通过 `journalctl -u <白名单 unit>` 读取。
    Journal,
}

/// hub 端控制面配置。对应 `hub.toml` 的 `[control]`。
///
/// 由后续 hub 控制 API 使用；默认全部关闭，新增字段全部有默认值。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct HubControlConfig {
    /// 总开关；任一能力开启时必须为 true。
    pub enabled: bool,
    pub systemd: bool,
    pub docker: bool,
    pub process: bool,
    pub logs: bool,
    /// 等待 agent 控制应答的超时（毫秒），1000–60000。
    pub request_timeout_ms: u64,
    /// 每个会话最多同时挂起的控制命令数，1–128。
    pub max_pending_per_session: usize,
    /// 单条控制结果允许的最大字节数，1024–1048576。
    pub max_output_bytes: usize,
}

impl Default for HubControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            systemd: false,
            docker: false,
            process: false,
            logs: false,
            request_timeout_ms: control::DEFAULT_REQUEST_TIMEOUT_MS,
            max_pending_per_session: control::DEFAULT_MAX_PENDING_PER_SESSION,
            max_output_bytes: control::DEFAULT_MAX_CONTROL_OUTPUT_BYTES,
        }
    }
}

impl HubControlConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            for (name, enabled) in [
                ("systemd", self.systemd),
                ("docker", self.docker),
                ("process", self.process),
                ("logs", self.logs),
            ] {
                if enabled {
                    return Err(Error::InvalidConfig(format!(
                        "hub.control.{name} 已开启但 hub.control.enabled=false；请先开启总开关"
                    )));
                }
            }
        }
        if !(control::MIN_REQUEST_TIMEOUT_MS..=control::MAX_REQUEST_TIMEOUT_MS)
            .contains(&self.request_timeout_ms)
        {
            return Err(Error::InvalidConfig(format!(
                "hub.control.request_timeout_ms 必须在 {}–{} 之间，实际 {}",
                control::MIN_REQUEST_TIMEOUT_MS,
                control::MAX_REQUEST_TIMEOUT_MS,
                self.request_timeout_ms
            )));
        }
        if !(control::MIN_MAX_PENDING_PER_SESSION..=control::MAX_MAX_PENDING_PER_SESSION)
            .contains(&self.max_pending_per_session)
        {
            return Err(Error::InvalidConfig(format!(
                "hub.control.max_pending_per_session 必须在 {}–{} 之间，实际 {}",
                control::MIN_MAX_PENDING_PER_SESSION,
                control::MAX_MAX_PENDING_PER_SESSION,
                self.max_pending_per_session
            )));
        }
        if !(control::MIN_MAX_CONTROL_OUTPUT_BYTES..=control::MAX_MAX_CONTROL_OUTPUT_BYTES)
            .contains(&self.max_output_bytes)
        {
            return Err(Error::InvalidConfig(format!(
                "hub.control.max_output_bytes 必须在 {}–{} 之间，实际 {}",
                control::MIN_MAX_CONTROL_OUTPUT_BYTES,
                control::MAX_MAX_CONTROL_OUTPUT_BYTES,
                self.max_output_bytes
            )));
        }
        Ok(())
    }
}

/// 管理 API 传输模式。
///
/// - `off`：明文 HTTP；只允许绑定回环地址（127.0.0.0/8、::1），否则拒绝启动。
/// - `required`：HTTPS；复用 agent 入口同一对 `server.crt` / `server.key` 做
///   server-auth（不要求客户端证书），证书 SAN 必须覆盖管理端访问地址。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdminTlsMode {
    /// 明文 HTTP，仅回环。
    #[default]
    Off,
    /// 服务端 TLS，证书与 agent 入口相同。
    Required,
}

/// hub 端告警配置。对应 `hub.toml` 的 `[alerts]`。
///
/// 全部字段有默认值：旧配置（完全没有 `[alerts]`）可直接启动，行为与默认一致。
/// 本阶段只落地配置与校验；评估任务在 B1b 接入后读取这些值。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct HubAlertsConfig {
    /// 告警引擎总开关。关闭时规则与事件表仍可用，但不执行评估与通知。
    pub enabled: bool,
    /// 评估轮询间隔（秒），1–3600。
    pub evaluation_interval_secs: u64,
    /// 单轮评估的时间预算（毫秒），100–60000。
    ///
    /// 超预算后引擎停止评估本轮剩余规则（下一轮继续），避免超大规则集占住
    /// `spawn_blocking` 线程、拖慢 ingest 与其它后台任务。
    pub evaluation_budget_ms: u64,
    /// agent 离线判定阈值（秒），1–3600；内置离线规则默认 90 秒。
    pub offline_after_secs: u64,
    /// hub / agent 证书剩余寿命告警阈值（小时），1–720。
    pub cert_warn_hours: u32,
    /// 告警事件保留天数，1–3650。
    pub event_retention_days: u32,
    /// 告警事件表最大行数，1000–1_000_000。
    pub max_events: u64,
    /// 单次通知 HTTP 超时（秒），1–60。
    pub notify_timeout_secs: u64,
    /// 单条通知最多尝试次数（含首次），1–10。
    pub notify_max_attempts: u32,
}

impl Default for HubAlertsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            evaluation_interval_secs: 15,
            evaluation_budget_ms: 5_000,
            offline_after_secs: 90,
            cert_warn_hours: 48,
            event_retention_days: 90,
            max_events: 100_000,
            notify_timeout_secs: 10,
            notify_max_attempts: 3,
        }
    }
}

impl HubAlertsConfig {
    /// 配置自洽性校验。
    ///
    /// 即使 `enabled = false` 也校验取值范围：配置写错应在启动时暴露，
    /// 而不是等到面板打开告警开关后才失败。
    pub fn validate(&self) -> Result<()> {
        for (name, value, min, max) in [
            (
                "evaluation_interval_secs",
                self.evaluation_interval_secs,
                MIN_ALERTS_EVALUATION_INTERVAL_SECS,
                MAX_ALERTS_EVALUATION_INTERVAL_SECS,
            ),
            (
                "evaluation_budget_ms",
                self.evaluation_budget_ms,
                MIN_ALERTS_EVALUATION_BUDGET_MS,
                MAX_ALERTS_EVALUATION_BUDGET_MS,
            ),
            (
                "offline_after_secs",
                self.offline_after_secs,
                MIN_ALERTS_OFFLINE_AFTER_SECS,
                MAX_ALERTS_OFFLINE_AFTER_SECS,
            ),
            (
                "cert_warn_hours",
                u64::from(self.cert_warn_hours),
                MIN_ALERTS_CERT_WARN_HOURS,
                MAX_ALERTS_CERT_WARN_HOURS,
            ),
            (
                "event_retention_days",
                u64::from(self.event_retention_days),
                MIN_ALERTS_EVENT_RETENTION_DAYS,
                MAX_ALERTS_EVENT_RETENTION_DAYS,
            ),
            (
                "max_events",
                self.max_events,
                MIN_ALERTS_MAX_EVENTS,
                MAX_ALERTS_MAX_EVENTS,
            ),
            (
                "notify_timeout_secs",
                self.notify_timeout_secs,
                MIN_ALERTS_NOTIFY_TIMEOUT_SECS,
                MAX_ALERTS_NOTIFY_TIMEOUT_SECS,
            ),
            (
                "notify_max_attempts",
                u64::from(self.notify_max_attempts),
                MIN_ALERTS_NOTIFY_MAX_ATTEMPTS,
                MAX_ALERTS_NOTIFY_MAX_ATTEMPTS,
            ),
        ] {
            if !(min..=max).contains(&value) {
                return Err(Error::InvalidConfig(format!(
                    "alerts.{name} 必须在 {min}–{max} 之间，实际 {value}"
                )));
            }
        }
        Ok(())
    }
}

/// 归档后端类型。对应 `archive.backend`，字符串稳定为 `webdav` / `s3` / `sftp`。
///
/// 该字符串同时写入 `archive_objects.backend` 与 API 响应，不能随意改名。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveBackend {
    /// WebDAV（C1b 实现）。
    #[default]
    Webdav,
    /// S3 / MinIO（C2）。
    S3,
    /// SFTP（C3）。
    Sftp,
}

impl ArchiveBackend {
    /// 稳定字符串表示。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Webdav => "webdav",
            Self::S3 => "s3",
            Self::Sftp => "sftp",
        }
    }
}

/// hub 端冷归档配置。对应 `hub.toml` 的 `[archive]`。
///
/// 全部字段有默认值：旧配置（完全没有 `[archive]`）可直接启动，归档默认关闭。
///
/// 安全约定：
/// - 后端 secret 只存在 `hub.toml`（0600），不会进入数据库 / API / 面板；
/// - [`ArchiveConfig`] 与各后端配置的 `Debug` 均为自定义实现，secret 统一输出
///   `<redacted>`，不会随日志或错误信息泄露；
/// - 对象 key 只由配置里的 `prefix` + UTC 日期 + 分片生成，不接受外部输入。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchiveConfig {
    /// 归档总开关。关闭时不执行任何归档任务，其它字段仍做范围校验。
    pub enabled: bool,
    /// 后端类型；`enabled = true` 时必须配置对应后端段。
    pub backend: ArchiveBackend,
    /// raw 数据至少保留多少天才允许归档，1–365；不得大于 `retention_raw_days`
    ///（后者为 0 表示 raw 永不自动删除，不受该约束）。
    pub after_days: u32,
    /// 每天执行归档任务的 UTC 小时（0–23）。
    pub schedule_hour_utc: u8,
    /// 单个归档对象压缩后的字节上限，1 MiB–64 MiB。
    ///
    /// 该值决定归档 worker 的分片大小；hub 下载的硬上限固定为 64 MiB，
    /// 不会随本值缩小。配置超过 64 MiB 只会产出无法下载的对象（KI-31），
    /// 因此在配置校验阶段直接拒绝。
    pub max_object_bytes: u64,
    /// 对象 key 前缀，只允许 `[A-Za-z0-9._-]`、非空、≤64 字节且不含 `..`。
    pub prefix: String,
    /// WebDAV 后端配置；仅在 `backend = "webdav"` 且 `enabled = true` 时必填。
    pub webdav: Option<ArchiveWebdavConfig>,
    /// S3 / MinIO 后端配置；仅在 `backend = "s3"` 且 `enabled = true` 时必填。
    pub s3: Option<ArchiveS3Config>,
    /// SFTP 后端配置；仅在 `backend = "sftp"` 且 `enabled = true` 时必填。
    pub sftp: Option<ArchiveSftpConfig>,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: ArchiveBackend::Webdav,
            after_days: 7,
            schedule_hour_utc: 3,
            max_object_bytes: 33_554_432,
            prefix: "rustboard".to_string(),
            webdav: None,
            s3: None,
            sftp: None,
        }
    }
}

impl fmt::Debug for ArchiveConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveConfig")
            .field("enabled", &self.enabled)
            .field("backend", &self.backend)
            .field("after_days", &self.after_days)
            .field("schedule_hour_utc", &self.schedule_hour_utc)
            .field("max_object_bytes", &self.max_object_bytes)
            .field("prefix", &self.prefix)
            .field("webdav", &self.webdav)
            .field("s3", &self.s3)
            .field("sftp", &self.sftp)
            .finish()
    }
}

impl ArchiveConfig {
    /// 配置自洽性校验；不依赖 `HubConfig` 的其它字段。
    ///
    /// 即使 `enabled = false` 也校验取值范围与 prefix：配置写错应在启动时暴露，
    /// 而不是等管理员打开归档开关后才失败。后端连通性不在这里测试（避免启动
    /// 阻塞），由 `archive test` / 面板显式触发。
    pub fn validate(&self) -> Result<()> {
        if !(MIN_ARCHIVE_AFTER_DAYS..=MAX_ARCHIVE_AFTER_DAYS).contains(&self.after_days) {
            return Err(Error::InvalidConfig(format!(
                "archive.after_days 必须在 {MIN_ARCHIVE_AFTER_DAYS}–\
                 {MAX_ARCHIVE_AFTER_DAYS} 天之间，实际 {}",
                self.after_days
            )));
        }
        if self.schedule_hour_utc > MAX_ARCHIVE_SCHEDULE_HOUR_UTC {
            return Err(Error::InvalidConfig(format!(
                "archive.schedule_hour_utc 必须在 0–{MAX_ARCHIVE_SCHEDULE_HOUR_UTC} 之间，实际 {}",
                self.schedule_hour_utc
            )));
        }
        if !(MIN_ARCHIVE_OBJECT_BYTES..=MAX_ARCHIVE_OBJECT_BYTES).contains(&self.max_object_bytes) {
            // KI-31：上限必须与下载硬限一致，否则会产出“上传成功但下载 413”的对象。
            return Err(Error::InvalidConfig(format!(
                "archive.max_object_bytes 是单个归档对象与下载内存的硬上限，必须在 \
                 {MIN_ARCHIVE_OBJECT_BYTES}–{MAX_ARCHIVE_OBJECT_BYTES} 字节（{}–{} MiB）\
                 之间，实际 {}",
                MIN_ARCHIVE_OBJECT_BYTES / MIB,
                MAX_ARCHIVE_OBJECT_BYTES / MIB,
                self.max_object_bytes
            )));
        }
        validate_archive_prefix(&self.prefix)?;

        if !self.enabled {
            return Ok(());
        }
        match self.backend {
            ArchiveBackend::Webdav => self
                .webdav
                .as_ref()
                .ok_or_else(|| {
                    Error::InvalidConfig(
                        "archive.enabled = true 但缺少 [archive.webdav] 配置".into(),
                    )
                })?
                .validate(),
            ArchiveBackend::S3 => self
                .s3
                .as_ref()
                .ok_or_else(|| {
                    Error::InvalidConfig("archive.enabled = true 但缺少 [archive.s3] 配置".into())
                })?
                .validate(),
            ArchiveBackend::Sftp => self
                .sftp
                .as_ref()
                .ok_or_else(|| {
                    Error::InvalidConfig("archive.enabled = true 但缺少 [archive.sftp] 配置".into())
                })?
                .validate(),
        }
    }

    /// 校验 `after_days` 与 raw 保留期的关系。
    ///
    /// `retention_raw_days = 0` 表示 raw 永不自动删除，此时不存在「还没归档就被
    /// 保留期删掉」的风险，不做上限约束；非 0 时必须 `after_days <= retention_raw_days`。
    pub fn validate_against_retention(&self, retention_raw_days: u32) -> Result<()> {
        self.validate()?;
        if retention_raw_days != 0 && self.after_days > retention_raw_days {
            return Err(Error::InvalidConfig(format!(
                "archive.after_days（{}）不能大于 retention_raw_days（{}）：\
                 否则 raw 会在归档前被保留期删除；请调大 retention_raw_days 或调小 after_days",
                self.after_days, retention_raw_days
            )));
        }
        Ok(())
    }
}

/// WebDAV 后端配置。对应 `[archive.webdav]`。
///
/// `password` 只参与 Basic auth；`Debug` 输出 `<redacted>`。
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchiveWebdavConfig {
    /// 目录 URL；只允许 `http://` / `https://`。
    pub url: String,
    pub username: String,
    /// Basic auth 密码；Debug 恒为 `<redacted>`。
    pub password: String,
}

impl fmt::Debug for ArchiveWebdavConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveWebdavConfig")
            .field("url", &self.url)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl ArchiveWebdavConfig {
    pub fn validate(&self) -> Result<()> {
        validate_archive_http_url("archive.webdav.url", &self.url)?;
        validate_archive_required_text("archive.webdav.username", &self.username, 1_024)?;
        validate_archive_required_text("archive.webdav.password", &self.password, 4_096)?;
        Ok(())
    }
}

/// S3 / MinIO 后端配置。对应 `[archive.s3]`。
///
/// `access_key_id` 与 `secret_access_key` 的 `Debug` 均为 `<redacted>`。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchiveS3Config {
    pub bucket: String,
    pub region: String,
    /// 留空表示 AWS；兼容 MinIO 时填写自有 endpoint。
    pub endpoint: String,
    pub access_key_id: String,
    /// 签名密钥；Debug 恒为 `<redacted>`。
    pub secret_access_key: String,
    /// MinIO 等自建服务通常需要 path-style 寻址。
    pub path_style: bool,
}

impl Default for ArchiveS3Config {
    fn default() -> Self {
        Self {
            bucket: String::new(),
            region: String::new(),
            endpoint: String::new(),
            access_key_id: String::new(),
            secret_access_key: String::new(),
            path_style: true,
        }
    }
}

impl fmt::Debug for ArchiveS3Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveS3Config")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .field("path_style", &self.path_style)
            .finish()
    }
}

impl ArchiveS3Config {
    pub fn validate(&self) -> Result<()> {
        validate_archive_required_text("archive.s3.bucket", &self.bucket, 255)?;
        if self.bucket.contains('/') || self.bucket.contains("..") {
            return Err(Error::InvalidConfig(
                "archive.s3.bucket 不能包含 '/' 或 '..'".into(),
            ));
        }
        validate_archive_required_text("archive.s3.region", &self.region, 64)?;
        if !self.endpoint.is_empty() {
            validate_archive_http_url("archive.s3.endpoint", &self.endpoint)?;
        }
        validate_archive_required_text("archive.s3.access_key_id", &self.access_key_id, 1_024)?;
        validate_archive_required_text(
            "archive.s3.secret_access_key",
            &self.secret_access_key,
            4_096,
        )?;
        Ok(())
    }
}

/// SFTP 后端配置。对应 `[archive.sftp]`。
///
/// `password` 与 `private_key_path` 的 `Debug` 均为 `<redacted>`；
/// `host_key_fingerprint` 是公钥指纹（非 secret），用于防中间人，必须显式配置。
///
/// 密钥类型限制：vendored `russh` / `ssh-key` 已删除 optional `rsa`，因此
/// **不支持 RSA 用户私钥，也不支持仅提供 RSA 主机密钥的服务器**。用户私钥只
/// 接受 ed25519；主机密钥需为 ed25519 或 ECDSA；指纹只接受 SHA256。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchiveSftpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// 密码认证；与 `private_key_path` 至少填写一个，私钥优先。
    pub password: String,
    /// ed25519 私钥文件路径；Unix 上 group/other 不得有权限（0600）。
    /// 不支持加密私钥 / RSA / ECDSA 用户私钥；Debug 恒为 `<redacted>`。
    pub private_key_path: String,
    /// 远端目录，必须是绝对路径，且不能含反斜杠、控制字符或 `..` 段。
    pub remote_dir: String,
    /// 服务器主机公钥的 SHA256 指纹（`SHA256:<base64>`，可带一个末尾 `=`）。
    /// 不接受 MD5 / SHA1；主机密钥需为 ed25519 或 ECDSA（RSA 不支持）。
    pub host_key_fingerprint: String,
}

impl Default for ArchiveSftpConfig {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 22,
            username: String::new(),
            password: String::new(),
            private_key_path: String::new(),
            remote_dir: String::new(),
            host_key_fingerprint: String::new(),
        }
    }
}

impl fmt::Debug for ArchiveSftpConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveSftpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("private_key_path", &"<redacted>")
            .field("remote_dir", &self.remote_dir)
            .field("host_key_fingerprint", &self.host_key_fingerprint)
            .finish()
    }
}

impl ArchiveSftpConfig {
    pub fn validate(&self) -> Result<()> {
        validate_archive_required_text("archive.sftp.host", &self.host, 255)?;
        if self
            .host
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == '\\')
        {
            return Err(Error::InvalidConfig(
                "archive.sftp.host 不能包含空白或路径分隔符".into(),
            ));
        }
        if self.port == 0 {
            return Err(Error::InvalidConfig(
                "archive.sftp.port 必须在 1–65535 之间".into(),
            ));
        }
        validate_archive_required_text("archive.sftp.username", &self.username, 255)?;
        if self.password.is_empty() && self.private_key_path.is_empty() {
            return Err(Error::InvalidConfig(
                "archive.sftp 必须配置 password 或 private_key_path 之一".into(),
            ));
        }
        if !self.password.is_empty() {
            validate_archive_required_text("archive.sftp.password", &self.password, 4_096)?;
        }
        if !self.private_key_path.is_empty() {
            validate_archive_required_text(
                "archive.sftp.private_key_path",
                &self.private_key_path,
                4_096,
            )?;
        }
        validate_archive_remote_dir(&self.remote_dir)?;
        validate_archive_host_key_fingerprint(&self.host_key_fingerprint)?;
        Ok(())
    }
}

/// 归档 prefix：`[A-Za-z0-9._-]`、非空、≤64 字节、不含 `..`。
fn validate_archive_prefix(prefix: &str) -> Result<()> {
    if prefix.is_empty() {
        return Err(Error::InvalidConfig("archive.prefix 不能为空".into()));
    }
    if prefix.len() > MAX_ARCHIVE_PREFIX_BYTES {
        return Err(Error::InvalidConfig(format!(
            "archive.prefix 不能超过 {MAX_ARCHIVE_PREFIX_BYTES} 字节，实际 {}",
            prefix.len()
        )));
    }
    if prefix.contains("..") {
        return Err(Error::InvalidConfig(
            "archive.prefix 不能包含 \"..\"（防止路径穿越）".into(),
        ));
    }
    if !prefix
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(Error::InvalidConfig(
            "archive.prefix 只允许 [A-Za-z0-9._-]".into(),
        ));
    }
    Ok(())
}

/// 非空文本字段的通用校验：非空、≤`max_bytes`、不含控制字符。
fn validate_archive_required_text(field: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidConfig(format!("{field} 不能为空")));
    }
    if value.len() > max_bytes {
        return Err(Error::InvalidConfig(format!(
            "{field} 不能超过 {max_bytes} 字节，实际 {}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(format!("{field} 不能包含控制字符")));
    }
    Ok(())
}

/// WebDAV URL / S3 endpoint 只允许 `http` / `https`，且必须有主机名。
fn validate_archive_http_url(field: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::InvalidConfig(format!("{field} 不能为空")));
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::InvalidConfig(format!(
            "{field} 不能包含空白或控制字符"
        )));
    }
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "{field} 必须以 http:// 或 https:// 开头，实际 {value:?}"
            ))
        })?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(Error::InvalidConfig(format!("{field} 缺少主机名")));
    }
    Ok(())
}

/// SFTP 远端目录：绝对路径、不含反斜杠 / `..` 段、不含控制字符。
fn validate_archive_remote_dir(remote_dir: &str) -> Result<()> {
    if remote_dir.is_empty() {
        return Err(Error::InvalidConfig(
            "archive.sftp.remote_dir 不能为空".into(),
        ));
    }
    if remote_dir.len() > 1_024 {
        return Err(Error::InvalidConfig(
            "archive.sftp.remote_dir 不能超过 1024 字节".into(),
        ));
    }
    if !remote_dir.starts_with('/') {
        return Err(Error::InvalidConfig(
            "archive.sftp.remote_dir 必须是绝对路径".into(),
        ));
    }
    if remote_dir.chars().any(char::is_control) {
        return Err(Error::InvalidConfig(
            "archive.sftp.remote_dir 不能包含控制字符".into(),
        ));
    }
    // 反斜杠在 Windows SFTP 服务端是路径分隔符，可能绕过 `..` 段检查；
    // 与对象 key 的白名单保持一致，直接拒绝。
    if remote_dir.contains('\\') {
        return Err(Error::InvalidConfig(
            "archive.sftp.remote_dir 不能包含反斜杠".into(),
        ));
    }
    if remote_dir.split('/').any(|segment| segment == "..") {
        return Err(Error::InvalidConfig(
            "archive.sftp.remote_dir 不能包含 \"..\" 段（防止路径穿越）".into(),
        ));
    }
    Ok(())
}

/// SSH 主机公钥指纹：`SHA256:<43/44 base64>`，解码后必须是 32 字节。
///
/// 43 字符是去掉末尾 `=` 的标准 base64；44 字符必须恰好以一个 `=` 结尾。
fn validate_archive_host_key_fingerprint(fingerprint: &str) -> Result<()> {
    const FIELD: &str = "archive.sftp.host_key_fingerprint";
    let rest = fingerprint.strip_prefix("SHA256:").ok_or_else(|| {
        Error::InvalidConfig(format!(
            "{FIELD} 必须以 SHA256: 开头（例如 SHA256:<base64>），拒绝空值或任意主机密钥"
        ))
    })?;
    if rest.is_empty() {
        return Err(Error::InvalidConfig(format!("{FIELD} 不能为空")));
    }
    let padded = match rest.len() {
        43 => format!("{rest}="),
        44 if rest.ends_with('=') => rest.to_string(),
        _ => {
            return Err(Error::InvalidConfig(format!(
                "{FIELD} 必须是 SHA256: 加 43 或 44 个 base64 字符（44 时末尾为 '='），实际 {:?}",
                fingerprint
            )));
        }
    };
    if !rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        return Err(Error::InvalidConfig(format!("{FIELD} 含非 base64 字符")));
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(padded)
        .map_err(|_| Error::InvalidConfig(format!("{FIELD} 不是合法的 base64")))?;
    if decoded.len() != 32 {
        return Err(Error::InvalidConfig(format!(
            "{FIELD} 解码后必须是 32 字节的 SHA-256 摘要，实际 {} 字节",
            decoded.len()
        )));
    }
    Ok(())
}

/// hub 端配置。对应 `/etc/rustboard/hub.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HubConfig {
    /// agent 接入监听地址。
    pub agent_listen: String,
    /// 面板/管理 API 监听地址。默认只绑回环，公网暴露需显式修改。
    pub admin_listen: String,
    /// 管理 API 传输模式：默认 `off`（仅回环明文）。
    #[serde(default)]
    pub admin_tls: AdminTlsMode,
    pub data_dir: PathBuf,
    /// SQLite 用路径，PostgreSQL 用 `postgres://...`。
    pub database: String,
    /// 是否把 hub 所在主机也当作一台 agent 采集。
    pub self_monitor: bool,
    /// hub 自身的展示名。
    pub name: String,
    /// 服务端证书的 SAN 列表（localhost、内网 IP、公网 IP 等）。
    pub server_names: Vec<String>,
    /// agent 安装命令里使用的 hub 地址。留空则自动从 server_names 里挑一个非回环 IP。
    pub advertise_host: Option<String>,
    /// 下发给 agent 的默认采样间隔。
    pub sample_interval_ms: u64,
    /// agent 接入层允许同时处理的 TLS 连接数；超出后直接关闭 TCP。
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// 单个来源 IP 的并发连接上限（1–256）。防止单机洪水挤占全部连接槽位。
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
    /// SQLite 只读连接池大小（1–16）。写连接始终只有 1 条。
    #[serde(default = "default_read_pool_size")]
    pub read_pool_size: usize,
    /// 管理 API 每 IP 每分钟请求上限（固定窗口）；0 表示关闭。
    #[serde(default = "default_admin_rate_limit_per_min")]
    pub admin_rate_limit_per_min: u32,
    /// 管理 API 写操作（PUT/POST/PATCH/DELETE）每 IP 每分钟上限；0 表示关闭。
    #[serde(default = "default_admin_write_rate_limit_per_min")]
    pub admin_write_rate_limit_per_min: u32,
    /// 管理 API 未认证失败（缺失 / 错误 token）每来源 IP 每分钟上限（固定窗口）。
    /// 0 表示关闭；默认 60，最大 600。超限后不再 SHA-256 / 查库。
    #[serde(default = "default_admin_auth_failure_limit_per_min")]
    pub admin_auth_failure_limit_per_min: u32,
    pub per_core: bool,
    pub excluded_interfaces: Vec<String>,
    /// raw（原始点）保留天数；0 表示该层不自动删除。
    pub retention_raw_days: u32,
    /// 1m（分钟聚合）保留天数；0 表示该层不自动删除。
    ///
    /// 非 0 时不得小于 `retention_raw_days`：1m 层必须先于或同时于 raw 保留，
    /// 否则会出现「raw 还在、分钟曲线先消失」的倒挂。
    pub retention_1m_days: u32,
    /// 1h（小时聚合）保留天数；0 表示该层不自动删除。
    ///
    /// 非 0 时不得小于 `retention_1m_days`，理由同上。
    pub retention_1h_days: u32,
    /// 降采样 / 保留期后台任务的执行间隔（秒），范围 1–3600。
    ///
    /// 默认 60；e2e 可配短值以便快速观察。间隔过短只会增加空转，不会丢数据。
    #[serde(default = "default_maintenance_interval_secs")]
    pub maintenance_interval_secs: u64,
    /// 管理 API 的 Bearer token；由 `hub init` / `hub admin-token` 生成，为空时拒绝启动。
    #[serde(default)]
    pub admin_token: String,
    /// 新建 CA 的有效期（天）。已存在的 CA 不受影响。
    #[serde(default = "default_ca_validity_days")]
    pub ca_validity_days: u32,
    /// 服务端证书有效期（天）。
    #[serde(default = "default_server_cert_validity_days")]
    pub server_cert_validity_days: u32,
    /// agent 客户端证书有效期（天）。
    #[serde(default = "default_client_cert_validity_days")]
    pub client_cert_validity_days: u32,
    /// 剩余寿命不超过该天数时触发续签。
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
    /// 服务端证书续签检查周期（秒），最小 1。
    #[serde(default = "default_cert_check_interval_secs")]
    pub cert_check_interval_secs: u64,
    /// M3 控制面配置；默认全部关闭，供 hub 控制 API 使用。
    #[serde(default)]
    pub control: HubControlConfig,
    /// M4 告警配置；旧配置缺 `[alerts]` 时使用默认值。
    #[serde(default)]
    pub alerts: HubAlertsConfig,
    /// M4 冷归档配置；旧配置缺 `[archive]` 时使用默认值（归档关闭）。
    #[serde(default)]
    pub archive: ArchiveConfig,
    /// M5 Phase C：服务端证书来源与 ACME 参数。
    ///
    /// 旧配置没有 `[tls]` 时为 `mode = "self-signed"`，不需要新增任何字段。
    #[serde(default)]
    pub tls: TlsConfig,
}

/// agent 接入层默认的最大并发连接数。
fn default_max_connections() -> usize {
    1024
}

/// 单来源 IP 默认并发连接上限。
fn default_max_connections_per_ip() -> usize {
    16
}

/// SQLite 只读连接池默认大小。
fn default_read_pool_size() -> usize {
    4
}

/// 管理 API 默认每 IP 每分钟请求上限。
fn default_admin_rate_limit_per_min() -> u32 {
    60
}

/// 管理 API 写操作默认每 IP 每分钟上限。
fn default_admin_write_rate_limit_per_min() -> u32 {
    10
}

/// 管理 API 未认证失败默认每来源 IP 每分钟上限。
fn default_admin_auth_failure_limit_per_min() -> u32 {
    60
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            agent_listen: format!("0.0.0.0:{}", crate::DEFAULT_AGENT_PORT),
            admin_listen: format!("127.0.0.1:{}", crate::DEFAULT_ADMIN_PORT),
            admin_tls: AdminTlsMode::Off,
            data_dir: PathBuf::from("/var/lib/rustboard/hub"),
            database: "sqlite:///var/lib/rustboard/hub/rustboard.db".to_string(),
            self_monitor: true,
            name: String::new(),
            server_names: vec!["localhost".to_string(), "127.0.0.1".to_string()],
            advertise_host: None,
            sample_interval_ms: 5_000,
            max_connections: default_max_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
            read_pool_size: default_read_pool_size(),
            admin_rate_limit_per_min: default_admin_rate_limit_per_min(),
            admin_write_rate_limit_per_min: default_admin_write_rate_limit_per_min(),
            admin_auth_failure_limit_per_min: default_admin_auth_failure_limit_per_min(),
            per_core: false,
            excluded_interfaces: default_excluded_interfaces(),
            retention_raw_days: 7,
            retention_1m_days: 90,
            retention_1h_days: 730,
            maintenance_interval_secs: default_maintenance_interval_secs(),
            admin_token: String::new(),
            ca_validity_days: default_ca_validity_days(),
            server_cert_validity_days: default_server_cert_validity_days(),
            client_cert_validity_days: default_client_cert_validity_days(),
            renew_before_days: default_renew_before_days(),
            cert_check_interval_secs: default_cert_check_interval_secs(),
            control: HubControlConfig::default(),
            alerts: HubAlertsConfig::default(),
            archive: ArchiveConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

impl HubConfig {
    pub fn load(path: &Path) -> Result<Self> {
        crate::error::load_toml(path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::error::save_toml(path, self)
    }

    /// 当前模式实际用于证书 SAN / 对外主机的名字列表。
    ///
    /// - `self-signed`：沿用 `server_names`（v0.4 行为）；
    /// - ACME：使用 `tls.domains`（域名列表，或 `acme-ip` 的单个 IP 字符串）。
    pub fn effective_server_names(&self) -> Vec<String> {
        match self.tls.mode {
            ServerTlsMode::SelfSigned => self.server_names.clone(),
            ServerTlsMode::AcmeDomain | ServerTlsMode::AcmeIp => self.tls.domains.clone(),
        }
    }

    /// 业务校验：`run` / `init` 入口都会调用。
    ///
    /// 校验配置值是否自洽，并确认 `data_dir` 是可以交给本程序独占的私有目录
    /// （共享 / 系统目录会在启动时被 chmod，必须提前拒绝）。`data_dir` 已存在时
    /// 只读取元数据，不修改权限；不读写证书文件。`admin_token` 属于 M2 的鉴权
    /// 范围，本阶段不校验（为空仍允许启动，保持 v0.1 行为）。
    pub fn validate(&self) -> Result<()> {
        // KI-21：先拒绝 /tmp、/etc、/ 这类 data_dir，避免后续 ensure_private_dir
        // 把共享目录 chmod 成 0700（init 也会走这里，不会先留下半个 CA）。
        crate::fsutil::validate_private_dir_path(&self.data_dir)
            .map_err(|err| Error::InvalidConfig(format!("data_dir 不安全: {err}")))?;
        for (name, days) in [
            ("ca_validity_days", self.ca_validity_days),
            ("server_cert_validity_days", self.server_cert_validity_days),
            ("client_cert_validity_days", self.client_cert_validity_days),
        ] {
            if !(MIN_VALIDITY_DAYS..=MAX_VALIDITY_DAYS).contains(&days) {
                return Err(Error::InvalidConfig(format!(
                    "{name} 必须在 {MIN_VALIDITY_DAYS}–{MAX_VALIDITY_DAYS} 天之间，实际 {days}"
                )));
            }
        }
        if self.renew_before_days < 1 {
            return Err(Error::InvalidConfig("renew_before_days 至少为 1 天".into()));
        }
        if self.renew_before_days >= self.server_cert_validity_days {
            return Err(Error::InvalidConfig(format!(
                "renew_before_days（{}）必须小于 server_cert_validity_days（{}），\
                 否则续签出来的证书仍然立刻到期",
                self.renew_before_days, self.server_cert_validity_days
            )));
        }
        // 检查周期过短只会造成无意义的磁盘写入与重复签名。
        if self.cert_check_interval_secs < MIN_CERT_CHECK_INTERVAL_SECS {
            return Err(Error::InvalidConfig(format!(
                "cert_check_interval_secs 至少为 {MIN_CERT_CHECK_INTERVAL_SECS} 秒，实际 {}",
                self.cert_check_interval_secs
            )));
        }
        // 单 IP 上限必须为正且远小于总上限：否则等于没有来源维度的隔离。
        if !(MIN_CONNECTIONS_PER_IP..=MAX_CONNECTIONS_PER_IP).contains(&self.max_connections_per_ip)
        {
            return Err(Error::InvalidConfig(format!(
                "max_connections_per_ip 必须在 {MIN_CONNECTIONS_PER_IP}–\
                 {MAX_CONNECTIONS_PER_IP} 之间，实际 {}",
                self.max_connections_per_ip
            )));
        }
        // 读连接池大小有硬上限：连接数是文件句柄，配置写错不能把 fd 吃光。
        if !(MIN_READ_POOL_SIZE..=MAX_READ_POOL_SIZE).contains(&self.read_pool_size) {
            return Err(Error::InvalidConfig(format!(
                "read_pool_size 必须在 {MIN_READ_POOL_SIZE}–{MAX_READ_POOL_SIZE} 之间，实际 {}",
                self.read_pool_size
            )));
        }
        // 0 表示关闭限速；其余按每分钟请求数校验。
        if self.admin_rate_limit_per_min > MAX_ADMIN_RATE_LIMIT_PER_MIN {
            return Err(Error::InvalidConfig(format!(
                "admin_rate_limit_per_min 不能超过 {MAX_ADMIN_RATE_LIMIT_PER_MIN}（0 表示关闭），\
                 实际 {}",
                self.admin_rate_limit_per_min
            )));
        }
        if self.admin_write_rate_limit_per_min > MAX_ADMIN_RATE_LIMIT_PER_MIN {
            return Err(Error::InvalidConfig(format!(
                "admin_write_rate_limit_per_min 不能超过 {MAX_ADMIN_RATE_LIMIT_PER_MIN}\
                 （0 表示关闭），实际 {}",
                self.admin_write_rate_limit_per_min
            )));
        }
        // 未认证失败限速：0 关闭；上限 600，避免配置错误把保护变成无限额度。
        if self.admin_auth_failure_limit_per_min > MAX_ADMIN_AUTH_FAILURE_LIMIT_PER_MIN {
            return Err(Error::InvalidConfig(format!(
                "admin_auth_failure_limit_per_min 不能超过 \
                 {MAX_ADMIN_AUTH_FAILURE_LIMIT_PER_MIN}（0 表示关闭），实际 {}",
                self.admin_auth_failure_limit_per_min
            )));
        }
        // 服务端证书来源必须在启动/init 前自洽：ACME 模式的 email/directory/
        // domains/profile 非法时，不能等到签发阶段才失败。self-signed 不要求
        // 任何 ACME 字段，保持旧配置行为。
        self.tls.validate()?;
        // SAN 的唯一起点随模式变化：self-signed 用 server_names（旧行为，空仍
        // 报错）；ACME 用 tls.domains（已在 `TlsConfig::validate` 中校验，这里
        // 再做一次证书编码层的兜底）。
        match self.tls.mode {
            ServerTlsMode::SelfSigned => {
                crate::tls::parse_server_sans(&self.server_names)
                    .map_err(|err| Error::InvalidConfig(format!("server_names 非法: {err}")))?;
            }
            ServerTlsMode::AcmeDomain | ServerTlsMode::AcmeIp => {
                crate::tls::parse_server_sans(&self.tls.domains)
                    .map_err(|err| Error::InvalidConfig(format!("tls.domains 非法: {err}")))?;
            }
        }
        self.validate_retention()?;
        self.validate_maintenance_interval()?;
        self.control.validate()?;
        self.alerts.validate()?;
        self.archive
            .validate_against_retention(self.retention_raw_days)?;
        Ok(())
    }

    /// M4：三层保留期与降采样/保留期任务的配置校验。
    ///
    /// 1. 每层天数必须在硬上限内（0 表示该层永不自动删除）；
    /// 2. 非 0 的 1m 保留期不得短于 raw，非 0 的 1h 保留期不得短于 1m，
    ///    否则会先删掉聚合层、raw 反而还在，曲线出现无法解释的空洞。
    fn validate_retention(&self) -> Result<()> {
        for (name, days, max) in [
            (
                "retention_raw_days",
                self.retention_raw_days,
                MAX_RETENTION_RAW_DAYS,
            ),
            (
                "retention_1m_days",
                self.retention_1m_days,
                MAX_RETENTION_1M_DAYS,
            ),
            (
                "retention_1h_days",
                self.retention_1h_days,
                MAX_RETENTION_1H_DAYS,
            ),
        ] {
            if days > max {
                return Err(Error::InvalidConfig(format!(
                    "{name} 不能超过 {max} 天（0 表示该层不自动删除），实际 {days}；\
                     请改小到允许范围内"
                )));
            }
        }
        // 0 = 该层永不删除，不存在倒挂；只有非 0 的聚合层保留期才需要与下一层比较。
        if self.retention_1m_days != 0 && self.retention_1m_days < self.retention_raw_days {
            return Err(Error::InvalidConfig(format!(
                "retention_1m_days（{}）不能小于 retention_raw_days（{}）：\
                 1m 层必须先于或同时于 raw 保留；请调大 retention_1m_days，\
                 或把 retention_raw_days 调小到不超过它",
                self.retention_1m_days, self.retention_raw_days
            )));
        }
        if self.retention_1h_days != 0 && self.retention_1h_days < self.retention_1m_days {
            return Err(Error::InvalidConfig(format!(
                "retention_1h_days（{}）不能小于 retention_1m_days（{}）：\
                 1h 层必须先于或同时于 1m 保留；请调大 retention_1h_days，\
                 或把 retention_1m_days 调小到不超过它",
                self.retention_1h_days, self.retention_1m_days
            )));
        }
        Ok(())
    }

    /// M4：维护任务执行间隔校验（1–3600 秒）。
    fn validate_maintenance_interval(&self) -> Result<()> {
        if !(MIN_MAINTENANCE_INTERVAL_SECS..=MAX_MAINTENANCE_INTERVAL_SECS)
            .contains(&self.maintenance_interval_secs)
        {
            return Err(Error::InvalidConfig(format!(
                "maintenance_interval_secs 必须在 {MIN_MAINTENANCE_INTERVAL_SECS}–\
                 {MAX_MAINTENANCE_INTERVAL_SECS} 秒之间，实际 {}；\
                 60 适合生产，e2e 才需要 1–5 秒",
                self.maintenance_interval_secs
            )));
        }
        Ok(())
    }

    pub fn sqlite_path(&self) -> Result<PathBuf> {
        self.database
            .strip_prefix("sqlite://")
            .map(PathBuf::from)
            .ok_or_else(|| Error::InvalidConfig("v1 暂只支持 sqlite:// 形式的数据库地址".into()))
    }
}

/// 面板配置。对应 `/etc/rustboard/panel.toml`。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PanelConfig {
    pub listen: String,
    /// hub 的管理 API 地址，例如 `http://127.0.0.1:8444` 或 `https://hub.example.com:8444`。
    pub hub_url: String,
    /// hub 的私有 CA 证书路径（PEM，可包含多张证书组成的 bundle）。
    ///
    /// 只在 `hub_url` 为 `https://` 时允许非空：配了它表示只信任该 CA，
    /// 不再叠加系统根证书；留空则使用系统根证书。
    #[serde(default)]
    pub hub_ca: String,
    /// 面板访问 hub 用的 scoped token。
    pub token: String,
    /// 单管理员的 Argon2id PHC 密码哈希；`panel init` 生成。
    #[serde(default)]
    pub admin_password_hash: String,
    /// 会话有效期（小时）。
    #[serde(default = "default_session_ttl_hours")]
    pub session_ttl_hours: u64,
    /// 静态资源目录；留空则依次尝试 `web/dist` 与 `/usr/share/rustboard/web`。
    #[serde(default)]
    pub static_dir: String,
    /// 可信反代地址（精确 IP 或 CIDR）。只有直连对端命中时，才采信 `X-Forwarded-*`。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// 会话 Cookie 的 `Secure` 属性策略。
    #[serde(default)]
    pub cookie_secure: CookieSecure,
    /// 面板的对外访问源（例如 `https://panel.example.com`），用于 Origin 校验。
    #[serde(default)]
    pub public_origin: String,
    /// 面板 HTTPS 证书（PEM）绝对路径；与 `tls_key` 必须同时配置。
    ///
    /// 本阶段只落地配置字段与成对校验；私钥权限、符号链接与证书/私钥配对
    /// 由 C7 的运行时加载器校验。
    #[serde(default)]
    pub tls_cert: String,
    /// 面板 HTTPS 私钥（PEM）绝对路径；与 `tls_cert` 必须同时配置。
    #[serde(default)]
    pub tls_key: String,
}

/// 面板会话 Cookie 的 `Secure` 策略。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CookieSecure {
    /// 仅当直连对端是可信反代且声明 `X-Forwarded-Proto: https` 时加 Secure。
    #[default]
    Auto,
    /// 无条件加 Secure（面板本身走 HTTPS 或整个链路强制 HTTPS）。
    Always,
    /// 不加 Secure（仅限本地明文调试）。
    Never,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            listen: default_panel_listen(),
            hub_url: format!("http://127.0.0.1:{}", crate::DEFAULT_ADMIN_PORT),
            hub_ca: String::new(),
            token: String::new(),
            admin_password_hash: String::new(),
            session_ttl_hours: default_session_ttl_hours(),
            static_dir: String::new(),
            trusted_proxies: Vec::new(),
            cookie_secure: CookieSecure::Auto,
            public_origin: String::new(),
            tls_cert: String::new(),
            tls_key: String::new(),
        }
    }
}

/// 默认只监听回环地址，端口固定为 `DEFAULT_PANEL_PORT`。
///
/// `Default` 是纯函数、不做端口探测 I/O：缺 `listen` 的配置每次 `ports`/`run`
/// 必须得到同一个地址。随机端口只在 `rustboard-panel init` 未传 `--listen` 时选取并落盘。
/// 面板在 M2 只有明文 HTTP，绝不能默认监听 `0.0.0.0`。
fn default_panel_listen() -> String {
    format!("127.0.0.1:{}", crate::DEFAULT_PANEL_PORT)
}

impl PanelConfig {
    pub fn load(path: &Path) -> Result<Self> {
        crate::error::load_toml(path)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        crate::error::save_toml(path, self)
    }

    /// 面板配置自洽性校验：可信反代地址与 `public_origin` 的语法。
    ///
    /// 非法 CIDR / Origin 必须在启动时失败并点名字段，不能被静默忽略——
    /// 否则运维会以为反代已被信任，实际仍按直连 IP 限速与判定 Cookie。
    pub fn validate(&self) -> Result<()> {
        for proxy in &self.trusted_proxies {
            if !is_valid_trusted_proxy(proxy) {
                return Err(Error::InvalidConfig(format!(
                    "trusted_proxies 含非法条目 {proxy:?}：只接受精确 IP 或 CIDR（例如 10.0.0.0/8）"
                )));
            }
        }
        let origin = self.public_origin.trim();
        if !origin.is_empty() {
            validate_public_origin(origin)?;
        }
        self.validate_tls_pair()?;
        Ok(())
    }

    /// `tls_cert` / `tls_key` 必须同时为空（HTTP）或同时非空（HTTPS）。
    ///
    /// 本阶段只做配置层校验：路径必须绝对、无控制字符/首尾空白；文件是否
    /// 存在、私钥 0600、非符号链接、证书与私钥是否配对留到 C7 运行时。
    fn validate_tls_pair(&self) -> Result<()> {
        match (
            self.tls_cert.trim().is_empty(),
            self.tls_key.trim().is_empty(),
        ) {
            (true, true) => Ok(()),
            (false, false) => {
                validate_absolute_config_path("tls_cert", &self.tls_cert)?;
                validate_absolute_config_path("tls_key", &self.tls_key)?;
                Ok(())
            }
            _ => Err(Error::InvalidConfig(
                "tls_cert 与 tls_key 必须成对配置：都为空使用 HTTP，都非空才启用面板 HTTPS".into(),
            )),
        }
    }
}

/// 可信反代条目：精确 IP 或 `IP/前缀长度`。
fn is_valid_trusted_proxy(entry: &str) -> bool {
    let entry = entry.trim();
    if entry.is_empty() {
        return false;
    }
    match entry.split_once('/') {
        None => entry.parse::<IpAddr>().is_ok(),
        Some((ip, prefix)) => {
            let Ok(ip) = ip.parse::<IpAddr>() else {
                return false;
            };
            let Ok(prefix) = prefix.parse::<u8>() else {
                return false;
            };
            match ip {
                IpAddr::V4(_) => prefix <= 32,
                IpAddr::V6(_) => prefix <= 128,
            }
        }
    }
}

/// `public_origin` 只允许 `scheme://host[:port]`，不接受路径 / 查询串。
fn validate_public_origin(origin: &str) -> Result<()> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| {
            Error::InvalidConfig(format!(
                "public_origin 必须以 http:// 或 https:// 开头，实际 {origin:?}"
            ))
        })?;
    if rest.is_empty() {
        return Err(Error::InvalidConfig(
            "public_origin 缺少主机名（例如 https://panel.example.com）".into(),
        ));
    }
    if rest
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '?' || c == '#' || c == '@')
    {
        return Err(Error::InvalidConfig(format!(
            "public_origin 只能是 scheme://host[:port]，不能带路径 / 查询串或空白，实际 {origin:?}"
        )));
    }
    Ok(())
}

fn default_buffer_max_age_hours() -> u64 {
    24
}

/// 证书有效期允许范围（天），与 `tls` 层的签发校验保持一致。
const MIN_VALIDITY_DAYS: u32 = 1;
const MAX_VALIDITY_DAYS: u32 = 36_500;

/// 服务端证书续签检查周期下限（秒）。
const MIN_CERT_CHECK_INTERVAL_SECS: u64 = 60;

/// 单来源 IP 并发连接上限的允许范围。
const MIN_CONNECTIONS_PER_IP: usize = 1;
const MAX_CONNECTIONS_PER_IP: usize = 256;

/// SQLite 只读连接池允许范围。
const MIN_READ_POOL_SIZE: usize = 1;
const MAX_READ_POOL_SIZE: usize = 16;

/// 管理 API 每分钟请求上限的硬上限（0 表示关闭限速）。
const MAX_ADMIN_RATE_LIMIT_PER_MIN: u32 = 6_000;

/// 管理 API 未认证失败限速的硬上限（0 表示关闭限速）。
///
/// 失败限速用于压住未认证请求的查库与日志放大，阈值不宜设得过高；600/min
/// 已远超正常客户端误输 token 的频率。
const MAX_ADMIN_AUTH_FAILURE_LIMIT_PER_MIN: u32 = 600;

/// agent 会话内证书检查周期的允许范围（小时）。
const MIN_CERT_CHECK_INTERVAL_HOURS: u64 = 1;
const MAX_CERT_CHECK_INTERVAL_HOURS: u64 = 168;

/// agent 主动重连周期上限（1 年）；0 表示不主动重连。
const MAX_SESSION_MAX_HOURS: u64 = 24 * 365;

/// M4：保留期天数硬上限（raw / 1m 十年，1h 二十年）。
const MAX_RETENTION_RAW_DAYS: u32 = 3_650;
const MAX_RETENTION_1M_DAYS: u32 = 3_650;
const MAX_RETENTION_1H_DAYS: u32 = 7_300;

/// M4：维护任务执行间隔范围与默认值（秒）。
///
/// 允许 1 秒是为了 e2e 用短值；生产默认 60 秒，与降采样分钟粒度一致。
const MIN_MAINTENANCE_INTERVAL_SECS: u64 = 1;
const MAX_MAINTENANCE_INTERVAL_SECS: u64 = 3_600;
const DEFAULT_MAINTENANCE_INTERVAL_SECS: u64 = 60;

fn default_maintenance_interval_secs() -> u64 {
    DEFAULT_MAINTENANCE_INTERVAL_SECS
}

/// M4 归档配置的取值范围（与方案 §7.1 一致）。
const MIN_ARCHIVE_AFTER_DAYS: u32 = 1;
const MAX_ARCHIVE_AFTER_DAYS: u32 = 365;
const MAX_ARCHIVE_SCHEDULE_HOUR_UTC: u8 = 23;
/// 归档对象字节上限的换算单位。
const MIB: u64 = 1024 * 1024;
/// 单个归档对象的字节上限：1 MiB–64 MiB。
///
/// 上界与 hub 下载硬限（64 MiB）保持一致：下载会把整个对象读进内存，
/// 允许更大的对象只会产生无法下载的归档（KI-31）。
const MIN_ARCHIVE_OBJECT_BYTES: u64 = MIB;
const MAX_ARCHIVE_OBJECT_BYTES: u64 = 64 * MIB;
const MAX_ARCHIVE_PREFIX_BYTES: usize = 64;

/// M4 告警配置的各字段允许范围（与方案 §8.2 一致）。
const MIN_ALERTS_EVALUATION_INTERVAL_SECS: u64 = 1;
const MAX_ALERTS_EVALUATION_INTERVAL_SECS: u64 = 3_600;
const MIN_ALERTS_EVALUATION_BUDGET_MS: u64 = 100;
const MAX_ALERTS_EVALUATION_BUDGET_MS: u64 = 60_000;
const MIN_ALERTS_OFFLINE_AFTER_SECS: u64 = 1;
const MAX_ALERTS_OFFLINE_AFTER_SECS: u64 = 3_600;
const MIN_ALERTS_CERT_WARN_HOURS: u64 = 1;
const MAX_ALERTS_CERT_WARN_HOURS: u64 = 720;
const MIN_ALERTS_EVENT_RETENTION_DAYS: u64 = 1;
const MAX_ALERTS_EVENT_RETENTION_DAYS: u64 = 3_650;
const MIN_ALERTS_MAX_EVENTS: u64 = 1_000;
const MAX_ALERTS_MAX_EVENTS: u64 = 1_000_000;
const MIN_ALERTS_NOTIFY_TIMEOUT_SECS: u64 = 1;
const MAX_ALERTS_NOTIFY_TIMEOUT_SECS: u64 = 60;
const MIN_ALERTS_NOTIFY_MAX_ATTEMPTS: u64 = 1;
const MAX_ALERTS_NOTIFY_MAX_ATTEMPTS: u64 = 10;

/// agent 单次 WebSocket 写超时的允许范围与默认值（秒）。
const MIN_SEND_TIMEOUT_SECS: u64 = 1;
const MAX_SEND_TIMEOUT_SECS: u64 = 120;
const DEFAULT_SEND_TIMEOUT_SECS: u64 = 15;

fn default_cert_renew_before_days() -> u32 {
    30
}

fn default_session_max_hours() -> u64 {
    12
}

fn default_send_timeout_secs() -> u64 {
    DEFAULT_SEND_TIMEOUT_SECS
}

fn default_cert_check_interval_hours() -> u64 {
    6
}

fn default_session_ttl_hours() -> u64 {
    12
}

fn default_ca_validity_days() -> u32 {
    3650
}

fn default_server_cert_validity_days() -> u32 {
    365
}

fn default_client_cert_validity_days() -> u32 {
    90
}

fn default_renew_before_days() -> u32 {
    30
}

fn default_cert_check_interval_secs() -> u64 {
    6 * 3600
}

pub fn default_excluded_interfaces() -> Vec<String> {
    ["lo", "docker", "veth", "br-", "virbr", "cni", "flannel"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// H2：`max_connections` 缺省为 1024，老配置文件不需要显式写这一项。
    #[test]
    fn h2_hub_config_max_connections_is_backward_compatible() {
        let cfg: HubConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.max_connections, 1024);

        let cfg: HubConfig = toml::from_str("max_connections = 32\n").unwrap();
        assert_eq!(cfg.max_connections, 32);
    }

    /// v0.2.1 新增字段：缺省值必须与方案一致，旧配置不写也能启动。
    #[test]
    fn v021_hardening_defaults_are_backward_compatible() {
        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.max_connections_per_ip, 16);
        assert_eq!(hub.read_pool_size, 4);
        assert_eq!(hub.admin_rate_limit_per_min, 60);
        assert_eq!(hub.admin_write_rate_limit_per_min, 10);

        let agent: AgentConfig = toml::from_str("").unwrap();
        assert_eq!(agent.cert_check_interval_hours, 6);

        let panel: PanelConfig = toml::from_str("").unwrap();
        assert!(panel.trusted_proxies.is_empty());
        assert_eq!(panel.cookie_secure, CookieSecure::Auto);
        assert!(panel.public_origin.is_empty());

        // 显式配置必须被读取。
        let hub: HubConfig = toml::from_str(
            "max_connections_per_ip = 8\nread_pool_size = 2\n\
             admin_rate_limit_per_min = 0\nadmin_write_rate_limit_per_min = 5\n",
        )
        .unwrap();
        assert_eq!(hub.max_connections_per_ip, 8);
        assert_eq!(hub.read_pool_size, 2);
        assert_eq!(hub.admin_rate_limit_per_min, 0);
        assert_eq!(hub.admin_write_rate_limit_per_min, 5);

        let panel: PanelConfig = toml::from_str(
            "trusted_proxies = [\"127.0.0.1\", \"10.0.0.0/8\", \"::1/128\"]\n\
             cookie_secure = \"always\"\npublic_origin = \"https://panel.example.com:8443\"\n",
        )
        .unwrap();
        assert_eq!(panel.trusted_proxies.len(), 3);
        assert_eq!(panel.cookie_secure, CookieSecure::Always);
        assert_eq!(panel.public_origin, "https://panel.example.com:8443");
        panel.validate().expect("合法面板配置必须通过校验");
    }

    /// v0.3.4 KI-26：未认证失败限速缺省 60（旧配置不写即启用）、0 关闭、>600 拒绝。
    #[test]
    fn v034_admin_auth_failure_limit_default_bounds_and_toml() {
        // TOML 缺省与 Default 必须一致：旧配置不写该字段时仍为 60。
        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.admin_auth_failure_limit_per_min, 60);
        assert_eq!(HubConfig::default().admin_auth_failure_limit_per_min, 60);
        hub.validate().expect("旧配置缺省必须合法");

        // 显式值（含 0 = 关闭）必须被读取；0 / 1 / 600 是合法边界。
        for (text, expected) in [
            ("admin_auth_failure_limit_per_min = 0\n", 0),
            ("admin_auth_failure_limit_per_min = 1\n", 1),
            ("admin_auth_failure_limit_per_min = 600\n", 600),
        ] {
            let hub: HubConfig = toml::from_str(text).unwrap();
            assert_eq!(
                hub.admin_auth_failure_limit_per_min, expected,
                "text={text}"
            );
            hub.validate().expect("边界值必须合法");
        }

        // 601 必须拒绝，错误信息点名字段，方便运维定位。
        let hub: HubConfig = toml::from_str("admin_auth_failure_limit_per_min = 601\n").unwrap();
        let err = hub.validate().expect_err("601 必须被拒绝").to_string();
        assert!(
            err.contains("admin_auth_failure_limit_per_min"),
            "错误信息应包含字段名: {err}"
        );
        assert!(err.contains("600"), "错误信息应包含上限: {err}");
    }

    /// M4-A2：维护任务间隔缺省 60，1–3600 合法，0 / 3601 拒绝且错误信息可操作。
    #[test]
    fn m4a_maintenance_interval_default_bounds_and_toml() {
        // 旧配置不写该字段时必须得到默认 60，且能通过完整校验。
        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.maintenance_interval_secs, 60);
        assert_eq!(HubConfig::default().maintenance_interval_secs, 60);
        hub.validate().expect("旧配置缺省必须合法");

        for secs in [1u64, 60, 3_600] {
            let hub: HubConfig =
                toml::from_str(&format!("maintenance_interval_secs = {secs}\n")).unwrap();
            assert_eq!(hub.maintenance_interval_secs, secs);
            hub.validate().expect("1 / 60 / 3600 是合法边界");
        }

        for secs in [0u64, 3_601] {
            let hub: HubConfig =
                toml::from_str(&format!("maintenance_interval_secs = {secs}\n")).unwrap();
            let err = hub
                .validate()
                .expect_err("0 与 3601 必须被拒绝")
                .to_string();
            assert!(
                err.contains("maintenance_interval_secs"),
                "错误信息必须点名字段: {err}"
            );
            assert!(err.contains("3600"), "错误信息应包含上限: {err}");
        }
    }

    /// M4-A2：retention 三层范围与倒挂校验；默认 7/90/730、0=不删、边界值通过。
    #[test]
    fn m4a_retention_defaults_bounds_and_inversions() {
        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.retention_raw_days, 7);
        assert_eq!(hub.retention_1m_days, 90);
        assert_eq!(hub.retention_1h_days, 730);
        hub.validate().expect("默认 retention 必须合法");

        let cfg = |raw: u32, one_minute: u32, one_hour: u32| -> HubConfig {
            toml::from_str(&format!(
                "retention_raw_days = {raw}\nretention_1m_days = {one_minute}\n\
                 retention_1h_days = {one_hour}\n"
            ))
            .unwrap()
        };

        // 合法：全 0（都不删）、三层上限边界、聚合层更长的常见组合、
        // 1m/1h 为 0（永不删除）时不受倒挂约束。
        for (raw, one_minute, one_hour) in [
            (0, 0, 0),
            (3_650, 3_650, 7_300),
            (7, 90, 730),
            (0, 90, 730),
            (7, 7, 7),
            (0, 0, 730),
            (3_650, 0, 0),
        ] {
            cfg(raw, one_minute, one_hour)
                .validate()
                .unwrap_or_else(|err| {
                    panic!("raw={raw} 1m={one_minute} 1h={one_hour} 应合法: {err}")
                });
        }

        // 越界：三层各自的上限之外必须拒绝，错误信息点名字段且说明 0=不删。
        for (raw, one_minute, one_hour, field) in [
            (3_651, 3_651, 7_300, "retention_raw_days"),
            (7, 3_651, 7_300, "retention_1m_days"),
            (7, 90, 7_301, "retention_1h_days"),
        ] {
            let err = cfg(raw, one_minute, one_hour)
                .validate()
                .expect_err("越界必须被拒绝")
                .to_string();
            assert!(err.contains(field), "错误信息必须点名 {field}: {err}");
            assert!(err.contains("0 表示"), "错误信息应说明 0 语义: {err}");
        }

        // 倒挂：1m 短于 raw、1h 短于 1m 都必须拒绝，并给出可操作的调整建议。
        for (raw, one_minute, one_hour, field) in [
            (10, 5, 730, "retention_1m_days"),
            (7, 100, 50, "retention_1h_days"),
        ] {
            let err = cfg(raw, one_minute, one_hour)
                .validate()
                .expect_err("倒挂必须被拒绝")
                .to_string();
            assert!(err.contains(field), "错误信息必须点名 {field}: {err}");
            assert!(err.contains("不能小于"), "错误信息应说明倒挂: {err}");
        }
    }

    /// M4-B1：`[alerts]` 缺省与旧配置兼容；各字段默认值与方案 §8.2 一致；
    /// 边界值合法，越界必须拒绝并点名字段。
    #[test]
    fn m4b1_alerts_defaults_toml_and_validation_bounds() {
        // 旧配置完全没有 `[alerts]`：使用默认值且整体校验通过。
        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.alerts, HubAlertsConfig::default());
        let alerts = &hub.alerts;
        assert!(alerts.enabled);
        assert_eq!(alerts.evaluation_interval_secs, 15);
        assert_eq!(alerts.evaluation_budget_ms, 5_000);
        assert_eq!(alerts.offline_after_secs, 90);
        assert_eq!(alerts.cert_warn_hours, 48);
        assert_eq!(alerts.event_retention_days, 90);
        assert_eq!(alerts.max_events, 100_000);
        assert_eq!(alerts.notify_timeout_secs, 10);
        assert_eq!(alerts.notify_max_attempts, 3);
        hub.validate().expect("旧配置缺 [alerts] 必须合法");

        // 只写部分字段：其余保持默认。
        let hub: HubConfig = toml::from_str("[alerts]\nenabled = false\n").unwrap();
        assert!(!hub.alerts.enabled);
        assert_eq!(hub.alerts.evaluation_interval_secs, 15);
        assert_eq!(hub.alerts.evaluation_budget_ms, 5_000);
        hub.validate().expect("关闭告警时默认值仍合法");

        // 全部字段取合法边界。
        let hub: HubConfig = toml::from_str(
            "[alerts]\n\
             enabled = true\n\
             evaluation_interval_secs = 1\n\
             evaluation_budget_ms = 100\n\
             offline_after_secs = 3600\n\
             cert_warn_hours = 720\n\
             event_retention_days = 3650\n\
             max_events = 1000000\n\
             notify_timeout_secs = 60\n\
             notify_max_attempts = 10\n",
        )
        .unwrap();
        hub.validate().expect("所有上限边界必须合法");

        let hub: HubConfig = toml::from_str(
            "[alerts]\n\
             evaluation_interval_secs = 3600\n\
             evaluation_budget_ms = 60000\n\
             offline_after_secs = 1\n\
             cert_warn_hours = 1\n\
             event_retention_days = 1\n\
             max_events = 1000\n\
             notify_timeout_secs = 1\n\
             notify_max_attempts = 1\n",
        )
        .unwrap();
        hub.validate().expect("所有下限边界必须合法");

        // 越界：0 与上限 +1 都必须拒绝，错误信息点名 alerts.<字段>。
        for (line, field) in [
            ("evaluation_interval_secs = 0", "evaluation_interval_secs"),
            (
                "evaluation_interval_secs = 3601",
                "evaluation_interval_secs",
            ),
            ("evaluation_budget_ms = 99", "evaluation_budget_ms"),
            ("evaluation_budget_ms = 60001", "evaluation_budget_ms"),
            ("offline_after_secs = 0", "offline_after_secs"),
            ("offline_after_secs = 3601", "offline_after_secs"),
            ("cert_warn_hours = 0", "cert_warn_hours"),
            ("cert_warn_hours = 721", "cert_warn_hours"),
            ("event_retention_days = 0", "event_retention_days"),
            ("event_retention_days = 3651", "event_retention_days"),
            ("max_events = 999", "max_events"),
            ("max_events = 1000001", "max_events"),
            ("notify_timeout_secs = 0", "notify_timeout_secs"),
            ("notify_timeout_secs = 61", "notify_timeout_secs"),
            ("notify_max_attempts = 0", "notify_max_attempts"),
            ("notify_max_attempts = 11", "notify_max_attempts"),
        ] {
            let hub: HubConfig = toml::from_str(&format!("[alerts]\n{line}\n")).unwrap();
            let err = hub
                .validate()
                .expect_err("越界告警配置必须被拒绝")
                .to_string();
            assert!(
                err.contains(&format!("alerts.{field}")),
                "错误信息必须点名 alerts.{field}: {err}"
            );
        }
    }

    /// v0.3.3：`admin_tls` 默认 off（旧配置兼容），显式值必须正确解析，非法值拒绝。
    #[test]
    fn v033_admin_tls_default_serde_and_invalid_values() {
        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.admin_tls, AdminTlsMode::Off);
        assert_eq!(AdminTlsMode::default(), AdminTlsMode::Off);

        for (text, expected) in [
            ("off", AdminTlsMode::Off),
            ("required", AdminTlsMode::Required),
        ] {
            let hub: HubConfig = toml::from_str(&format!("admin_tls = \"{text}\"\n")).unwrap();
            assert_eq!(hub.admin_tls, expected);
        }

        // 大写 / 别名不能静默回退到 off：配置错误必须在解析阶段暴露。
        for invalid in ["on", "true", "REQUIRED", "tls", ""] {
            let err = toml::from_str::<HubConfig>(&format!("admin_tls = \"{invalid}\"\n"))
                .expect_err("非法 admin_tls 必须解析失败");
            assert!(
                err.to_string().contains("admin_tls"),
                "错误信息应点名 admin_tls: {err}"
            );
        }
    }

    /// v0.3.3 Panel 新增 `hub_ca`：缺省为空，旧配置不写该字段也能加载；
    /// 显式配置按原样读取，且必须能通过 serde 往返。
    #[test]
    fn v033_panel_hub_ca_is_optional_and_roundtrips() {
        let panel: PanelConfig = toml::from_str("").unwrap();
        assert!(
            panel.hub_ca.is_empty(),
            "旧配置缺 hub_ca 时必须默认为空，而不是解析失败"
        );
        assert_eq!(panel.hub_ca, PanelConfig::default().hub_ca);

        let panel: PanelConfig =
            toml::from_str("hub_ca = \"/etc/rustboard/panel/hub-ca.crt\"\n").unwrap();
        assert_eq!(panel.hub_ca, "/etc/rustboard/panel/hub-ca.crt");

        let serialized = toml::to_string(&panel).unwrap();
        let reparsed: PanelConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(reparsed.hub_ca, panel.hub_ca, "hub_ca 必须能 serde 往返");
    }

    /// 非法 `cookie_secure` 值必须在反序列化阶段失败，不能静默回退 auto。
    #[test]
    fn v021_cookie_secure_rejects_unknown_values() {
        let err = toml::from_str::<PanelConfig>("cookie_secure = \"sometimes\"\n")
            .expect_err("未知 CookieSecure 值必须解析失败");
        assert!(err.to_string().contains("cookie_secure"), "错误信息: {err}");

        for (text, expected) in [
            ("auto", CookieSecure::Auto),
            ("always", CookieSecure::Always),
            ("never", CookieSecure::Never),
        ] {
            let cfg: PanelConfig =
                toml::from_str(&format!("cookie_secure = \"{text}\"\n")).unwrap();
            assert_eq!(cfg.cookie_secure, expected);
        }
    }

    /// v0.1 的配置文件没有新增字段，必须全部走默认值而不是解析失败。
    #[test]
    fn v02_config_defaults_are_backward_compatible() {
        let agent: AgentConfig = toml::from_str("").unwrap();
        assert_eq!(agent.cert_renew_before_days, 30);
        assert_eq!(agent.session_max_hours, 12);

        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.ca_validity_days, 3650);
        assert_eq!(hub.server_cert_validity_days, 365);
        assert_eq!(hub.client_cert_validity_days, 90);
        assert_eq!(hub.renew_before_days, 30);
        assert_eq!(hub.cert_check_interval_secs, 21_600);
        assert!(hub.admin_token.is_empty());

        let panel: PanelConfig = toml::from_str("").unwrap();
        assert_eq!(panel.session_ttl_hours, 12);
        assert!(panel.admin_password_hash.is_empty());
        assert!(panel.static_dir.is_empty());
        // 面板只有明文 HTTP：默认只绑回环，且固定 8080，不能依赖随机 I/O。
        assert_eq!(
            panel.listen,
            format!("127.0.0.1:{}", crate::DEFAULT_PANEL_PORT)
        );
    }

    /// `Default` 必须幂等：缺 `listen` 的配置反复加载得到同一地址；
    /// 随机端口只属于 `panel init` 的职责。
    #[test]
    fn panel_listen_default_is_stable_and_can_be_overridden() {
        let first = PanelConfig::default();
        let second = PanelConfig::default();
        assert_eq!(first.listen, "127.0.0.1:8080");
        assert_eq!(first.listen, second.listen, "Default 不能在内部选随机端口");

        let loaded: PanelConfig = toml::from_str("").unwrap();
        assert_eq!(loaded.listen, first.listen);

        let panel: PanelConfig = toml::from_str("listen = \"0.0.0.0:18080\"\n").unwrap();
        assert_eq!(panel.listen, "0.0.0.0:18080");
    }

    /// 默认配置必须通过校验（老版本配置文件缺字段时也走默认值）。
    #[test]
    fn v02_default_configs_pass_validation() {
        let hub: HubConfig = toml::from_str("").unwrap();
        hub.validate().expect("默认 hub 配置必须合法");

        let agent: AgentConfig = toml::from_str("").unwrap();
        agent.validate().expect("默认 agent 配置必须合法");
    }

    /// KI-21：hub / agent 的 data_dir 指向共享目录、根目录或相对路径时，
    /// 配置校验必须失败，并点名 data_dir；默认 `/var/lib/rustboard/...` 仍然合法。
    #[test]
    fn ki21_config_validation_rejects_unsafe_data_dir() {
        for bad in [
            "/tmp",
            "/",
            "/etc",
            "/etc/rustboard",
            "/var/lib",
            "/var/tmp",
            "/var/log",
            "/var/log/rustboard",
            "/var/cache/rustboard",
            "/var/lib/systemd",
            "/mnt/data",
            "/media/usb",
            "/srv/www",
            "/home/alice",
            "relative/data",
        ] {
            let hub = HubConfig {
                data_dir: PathBuf::from(bad),
                ..HubConfig::default()
            };
            let err = hub
                .validate()
                .expect_err(&format!("hub data_dir={bad} 必须被拒绝"))
                .to_string();
            assert!(err.contains("data_dir"), "错误信息必须点名 data_dir: {err}");
            assert!(err.contains("不安全"), "错误信息应说明不安全: {err}");

            let agent = AgentConfig {
                data_dir: PathBuf::from(bad),
                ..AgentConfig::default()
            };
            let err = agent
                .validate()
                .expect_err(&format!("agent data_dir={bad} 必须被拒绝"))
                .to_string();
            assert!(err.contains("data_dir"), "错误信息必须点名 data_dir: {err}");
            assert!(err.contains("不安全"), "错误信息应说明不安全: {err}");
        }

        // `.` 是相对路径的一种，必须和其他相对路径一样被拒绝。
        let dot = HubConfig {
            data_dir: PathBuf::from("."),
            ..HubConfig::default()
        };
        assert!(dot.validate().is_err(), "data_dir=. 必须被拒绝");

        // 专属子目录合法：只做路径校验，不会碰真实的 /var/lib/rustboard。
        let ok = HubConfig {
            data_dir: PathBuf::from("/var/lib/rustboard/hub"),
            ..HubConfig::default()
        };
        ok.validate().expect("默认数据目录必须通过");
        let ok = AgentConfig {
            data_dir: PathBuf::from("/var/lib/rustboard/agent"),
            ..AgentConfig::default()
        };
        ok.validate().expect("默认 agent 数据目录必须通过");
    }

    /// 有效期 / 续签阈值 / 检查周期的非法组合必须被拒绝，且错误信息点名具体字段。
    #[test]
    fn v02_hub_config_validation_rejects_bad_values() {
        let cases: [(HubConfig, &str); 8] = [
            (
                HubConfig {
                    ca_validity_days: 0,
                    ..HubConfig::default()
                },
                "ca_validity_days",
            ),
            (
                HubConfig {
                    server_cert_validity_days: MAX_VALIDITY_DAYS + 1,
                    ..HubConfig::default()
                },
                "server_cert_validity_days",
            ),
            (
                HubConfig {
                    client_cert_validity_days: 0,
                    ..HubConfig::default()
                },
                "client_cert_validity_days",
            ),
            (
                HubConfig {
                    renew_before_days: 0,
                    ..HubConfig::default()
                },
                "renew_before_days",
            ),
            (
                HubConfig {
                    renew_before_days: 365,
                    ..HubConfig::default()
                },
                "必须小于",
            ),
            (
                HubConfig {
                    cert_check_interval_secs: MIN_CERT_CHECK_INTERVAL_SECS - 1,
                    ..HubConfig::default()
                },
                "cert_check_interval_secs",
            ),
            (
                HubConfig {
                    server_names: Vec::new(),
                    ..HubConfig::default()
                },
                "server_names",
            ),
            (
                HubConfig {
                    server_names: vec!["bad name".to_string()],
                    ..HubConfig::default()
                },
                "server_names",
            ),
        ];
        for (cfg, needle) in cases {
            let err = cfg.validate().expect_err("非法配置必须被拒绝").to_string();
            assert!(err.contains(needle), "错误信息应包含 {needle}: {err}");
        }

        // 边界值合法：恰好 1 天有效期 + 2 天阈值 + 60 秒周期。
        let edge = HubConfig {
            ca_validity_days: MIN_VALIDITY_DAYS,
            server_cert_validity_days: 2,
            client_cert_validity_days: MIN_VALIDITY_DAYS,
            renew_before_days: 1,
            cert_check_interval_secs: MIN_CERT_CHECK_INTERVAL_SECS,
            ..HubConfig::default()
        };
        edge.validate().expect("边界值必须合法");
    }

    /// agent 侧：续签阈值至少 1 天，主动重连周期不得超过上限，0 表示不主动重连。
    #[test]
    fn v02_agent_config_validation_checks_renew_and_session_limits() {
        let cfg: AgentConfig = toml::from_str("").unwrap();
        assert!(cfg.validate().is_ok());

        let zero_renew = AgentConfig {
            cert_renew_before_days: 0,
            ..AgentConfig::default()
        };
        assert!(zero_renew.validate().is_err());

        let too_long = AgentConfig {
            session_max_hours: MAX_SESSION_MAX_HOURS + 1,
            ..AgentConfig::default()
        };
        let err = too_long.validate().unwrap_err().to_string();
        assert!(err.contains("session_max_hours"), "错误信息: {err}");

        // 0 表示不主动重连，必须合法。
        let disabled = AgentConfig {
            session_max_hours: 0,
            ..AgentConfig::default()
        };
        assert!(disabled.validate().is_ok());
    }

    /// v0.3.1 #12：发送超时默认 15 秒，范围 1–120；旧配置缺字段必须走默认。
    #[test]
    fn v031_agent_send_timeout_defaults_and_bounds() {
        let cfg: AgentConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.send_timeout_secs, 15);
        assert_eq!(AgentConfig::default().send_timeout_secs, 15);

        // 旧配置（没有该字段）同样走默认，且能通过校验。
        let old: AgentConfig =
            toml::from_str("hub_url = \"ws://127.0.0.1:8443/agent/ws\"\n").unwrap();
        assert_eq!(old.send_timeout_secs, 15);
        old.validate()
            .expect("旧配置缺 send_timeout_secs 必须能启动");

        // 显式配置必须生效。
        let explicit: AgentConfig = toml::from_str("send_timeout_secs = 30\n").unwrap();
        assert_eq!(explicit.send_timeout_secs, 30);
        explicit.validate().expect("30 秒必须合法");

        // 闭区间边界 1 / 120 合法。
        for secs in [1, 120] {
            let cfg = AgentConfig {
                send_timeout_secs: secs,
                ..AgentConfig::default()
            };
            cfg.validate()
                .unwrap_or_else(|err| panic!("{secs} 秒必须合法: {err}"));
        }

        // 0 / 121 越界必须被拒绝，错误信息包含字段名与范围。
        for secs in [0, 121] {
            let cfg = AgentConfig {
                send_timeout_secs: secs,
                ..AgentConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err(&format!("{secs} 秒必须被拒绝"))
                .to_string();
            assert!(
                err.contains("send_timeout_secs"),
                "错误信息应包含字段名: {err}"
            );
            assert!(err.contains("1–120"), "错误信息应包含范围: {err}");
        }
    }

    /// v0.2.1 新增配置项的非法值必须在启动前被拒绝，且错误信息点名字段。
    #[test]
    fn v021_config_validation_rejects_out_of_range_values() {
        let hub_cases: [(HubConfig, &str); 6] = [
            (
                HubConfig {
                    max_connections_per_ip: 0,
                    ..HubConfig::default()
                },
                "max_connections_per_ip",
            ),
            (
                HubConfig {
                    max_connections_per_ip: 257,
                    ..HubConfig::default()
                },
                "max_connections_per_ip",
            ),
            (
                HubConfig {
                    read_pool_size: 0,
                    ..HubConfig::default()
                },
                "read_pool_size",
            ),
            (
                HubConfig {
                    read_pool_size: 17,
                    ..HubConfig::default()
                },
                "read_pool_size",
            ),
            (
                HubConfig {
                    admin_rate_limit_per_min: 6_001,
                    ..HubConfig::default()
                },
                "admin_rate_limit_per_min",
            ),
            (
                HubConfig {
                    admin_write_rate_limit_per_min: 6_001,
                    ..HubConfig::default()
                },
                "admin_write_rate_limit_per_min",
            ),
        ];
        for (cfg, needle) in hub_cases {
            let err = cfg.validate().expect_err("非法配置必须被拒绝").to_string();
            assert!(err.contains(needle), "错误信息应包含 {needle}: {err}");
        }

        // 边界值：1 / 256 / 16 与 0（关闭限速）/ 6000 全部合法。
        let edge = HubConfig {
            max_connections_per_ip: 256,
            read_pool_size: 16,
            admin_rate_limit_per_min: 6_000,
            admin_write_rate_limit_per_min: 0,
            ..HubConfig::default()
        };
        edge.validate().expect("边界值必须合法");
        let edge = HubConfig {
            max_connections_per_ip: 1,
            read_pool_size: 1,
            admin_rate_limit_per_min: 0,
            ..HubConfig::default()
        };
        edge.validate().expect("最小值必须合法");

        // agent 会话内证书检查周期：1–168 小时，0 与 169 都非法。
        for hours in [0, 169] {
            let cfg = AgentConfig {
                cert_check_interval_hours: hours,
                ..AgentConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err("非法检查周期必须被拒绝")
                .to_string();
            assert!(err.contains("cert_check_interval_hours"), "错误信息: {err}");
        }
        for hours in [1, 168] {
            let cfg = AgentConfig {
                cert_check_interval_hours: hours,
                ..AgentConfig::default()
            };
            cfg.validate().expect("边界检查周期必须合法");
        }
    }

    /// 面板可信反代 / public_origin 的语法校验。
    #[test]
    fn v021_panel_config_validation_rejects_bad_proxies_and_origin() {
        let valid = PanelConfig {
            trusted_proxies: vec![
                "127.0.0.1".to_string(),
                "10.0.0.0/8".to_string(),
                "2001:db8::/32".to_string(),
                "::1/128".to_string(),
            ],
            cookie_secure: CookieSecure::Never,
            public_origin: "http://panel.example.com".to_string(),
            ..PanelConfig::default()
        };
        valid.validate().expect("合法配置必须通过");

        for bad in [
            "10.0.0.0/33",
            "2001:db8::/129",
            "not-an-ip",
            "10.0.0.0/",
            "",
            "10.0.0.1/8/9",
        ] {
            let cfg = PanelConfig {
                trusted_proxies: vec![bad.to_string()],
                ..PanelConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err(&format!("非法 trusted_proxies 条目必须被拒绝: {bad}"))
                .to_string();
            assert!(err.contains("trusted_proxies"), "错误信息: {err}");
        }

        for bad in [
            "panel.example.com",
            "ftp://panel.example.com",
            "https://",
            "https://panel.example.com/path",
            "https://panel.example.com?x=1",
            "https://panel.example.com #frag",
        ] {
            let cfg = PanelConfig {
                public_origin: bad.to_string(),
                ..PanelConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err(&format!("非法 public_origin 必须被拒绝: {bad}"))
                .to_string();
            assert!(err.contains("public_origin"), "错误信息: {err}");
        }

        // 空字符串表示未配置，必须合法。
        PanelConfig::default().validate().expect("空配置必须合法");
    }

    /// 旧配置没有 `[control]`：必须能启动，且能力全部关闭。
    #[test]
    fn m3_control_defaults_are_off_and_old_configs_start() {
        let agent: AgentConfig = toml::from_str("").unwrap();
        assert!(!agent.control.enabled);
        assert!(!agent.control.systemd);
        assert!(!agent.control.docker);
        assert!(!agent.control.process);
        assert!(!agent.control.logs);
        assert!(agent.control.systemd_units.is_empty());
        assert!(agent.control.docker_containers.is_empty());
        assert!(agent.control.log_sources.is_empty());
        assert_eq!(agent.control.command_timeout_secs, 10);
        assert_eq!(agent.control.max_log_lines, 500);
        assert!(agent.control.systemctl_path.is_empty());
        agent.validate().expect("默认 agent 配置必须合法");

        let old: AgentConfig = toml::from_str(
            "hub_url = \"ws://127.0.0.1:8443/agent/ws\"\nsample_interval_ms = 5000\n",
        )
        .unwrap();
        assert!(!old.control.enabled);
        old.validate().expect("旧配置缺 control 段也必须能启动");

        let hub: HubConfig = toml::from_str("").unwrap();
        assert!(!hub.control.enabled);
        assert_eq!(hub.control.request_timeout_ms, 15_000);
        assert_eq!(hub.control.max_pending_per_session, 32);
        assert_eq!(hub.control.max_output_bytes, 262_144);
        hub.validate().expect("默认 hub 配置必须合法");
    }

    /// TOML 结构：`[[control.log_sources]]` 能正确解析 kind / target / name。
    #[test]
    fn m3_control_toml_parses_log_sources() {
        let toml_text = r#"
[control]
enabled = true
systemd = true
logs = true
systemd_units = ["nginx*"]
command_timeout_secs = 20
max_log_lines = 800
systemctl_path = "/usr/local/bin/systemctl"

[[control.log_sources]]
id = "nginx-error"
kind = "file"
target = "/var/log/nginx/error.log"
name = "Nginx 错误日志"

[[control.log_sources]]
id = "nginx-journal"
kind = "journal"
target = "nginx.service"
name = ""
"#;
        let agent: AgentConfig = toml::from_str(toml_text).unwrap();
        assert!(agent.control.enabled);
        assert!(agent.control.systemd);
        assert!(!agent.control.docker);
        assert_eq!(agent.control.command_timeout_secs, 20);
        assert_eq!(agent.control.max_log_lines, 800);
        assert_eq!(agent.control.systemctl_path, "/usr/local/bin/systemctl");
        assert_eq!(agent.control.log_sources.len(), 2);
        assert_eq!(agent.control.log_sources[0].kind, LogSourceKind::File);
        assert_eq!(agent.control.log_sources[1].kind, LogSourceKind::Journal);
        assert_eq!(agent.control.log_sources[1].target, "nginx.service");
        agent.validate().expect("合法控制面配置必须通过");
    }

    fn enabled_control() -> ControlConfig {
        ControlConfig {
            enabled: true,
            ..ControlConfig::default()
        }
    }

    fn file_source(id: &str, target: &str) -> LogSourceConfig {
        LogSourceConfig {
            id: id.to_string(),
            kind: LogSourceKind::File,
            target: target.to_string(),
            name: String::new(),
        }
    }

    fn journal_source(id: &str, unit: &str) -> LogSourceConfig {
        LogSourceConfig {
            id: id.to_string(),
            kind: LogSourceKind::Journal,
            target: unit.to_string(),
            name: String::new(),
        }
    }

    /// 能力开关、白名单、unit / 容器名、日志来源、超时范围都必须校验。
    #[test]
    fn m3_agent_control_validation_rejects_unsafe_config() {
        let cases: Vec<(ControlConfig, &str)> = vec![
            (
                ControlConfig {
                    systemd: true,
                    ..ControlConfig::default()
                },
                "control.enabled=false",
            ),
            (
                ControlConfig {
                    enabled: true,
                    systemd: true,
                    ..ControlConfig::default()
                },
                "systemd_units",
            ),
            (
                ControlConfig {
                    enabled: true,
                    docker: true,
                    ..ControlConfig::default()
                },
                "docker_containers",
            ),
            (
                ControlConfig {
                    enabled: true,
                    logs: true,
                    ..ControlConfig::default()
                },
                "log_sources",
            ),
            (
                ControlConfig {
                    systemd_units: vec!["sshd".into()],
                    ..enabled_control()
                },
                "禁止",
            ),
            (
                ControlConfig {
                    systemd_units: vec!["systemd-*".into()],
                    ..enabled_control()
                },
                "禁止",
            ),
            (
                ControlConfig {
                    systemd_units: vec!["rustboard-*".into()],
                    ..enabled_control()
                },
                "禁止",
            ),
            (
                ControlConfig {
                    systemd_units: vec!["-nginx".into()],
                    ..enabled_control()
                },
                "白名单",
            ),
            (
                ControlConfig {
                    systemd_units: vec!["nginx service".into()],
                    ..enabled_control()
                },
                "白名单",
            ),
            (
                ControlConfig {
                    systemd_units: vec!["*".into()],
                    ..enabled_control()
                },
                "裸 *",
            ),
            (
                ControlConfig {
                    docker_containers: vec!["web_1!".into()],
                    ..enabled_control()
                },
                "docker_containers",
            ),
            (
                ControlConfig {
                    docker_containers: vec!["*".into()],
                    ..enabled_control()
                },
                "docker_containers",
            ),
            (
                ControlConfig {
                    logs: true,
                    log_sources: vec![
                        file_source("dup", "/var/log/a.log"),
                        file_source("dup", "/var/log/b.log"),
                    ],
                    ..enabled_control()
                },
                "重复",
            ),
            (
                ControlConfig {
                    logs: true,
                    log_sources: vec![file_source("a", "var/log/a.log")],
                    ..enabled_control()
                },
                "绝对路径",
            ),
            (
                ControlConfig {
                    logs: true,
                    log_sources: vec![file_source("a", "/var/log/../etc/shadow")],
                    ..enabled_control()
                },
                "..",
            ),
            (
                ControlConfig {
                    logs: true,
                    systemd_units: vec!["nginx*".into()],
                    log_sources: vec![journal_source("j", "redis.service")],
                    ..enabled_control()
                },
                "systemd_units",
            ),
            (
                ControlConfig {
                    logs: true,
                    log_sources: vec![journal_source("j", "dbus.service")],
                    ..enabled_control()
                },
                "禁止",
            ),
            (
                ControlConfig {
                    enabled: true,
                    command_timeout_secs: 0,
                    ..ControlConfig::default()
                },
                "command_timeout_secs",
            ),
            (
                ControlConfig {
                    enabled: true,
                    command_timeout_secs: 61,
                    ..ControlConfig::default()
                },
                "command_timeout_secs",
            ),
            (
                ControlConfig {
                    enabled: true,
                    max_log_lines: 0,
                    ..ControlConfig::default()
                },
                "max_log_lines",
            ),
            (
                ControlConfig {
                    enabled: true,
                    max_log_lines: 2001,
                    ..ControlConfig::default()
                },
                "max_log_lines",
            ),
            (
                ControlConfig {
                    enabled: true,
                    systemctl_path: "systemctl".into(),
                    ..ControlConfig::default()
                },
                "systemctl_path",
            ),
            (
                ControlConfig {
                    enabled: true,
                    journalctl_path: "/usr/bin/journalctl\0".into(),
                    ..ControlConfig::default()
                },
                "journalctl_path",
            ),
        ];

        for (control, needle) in cases {
            let cfg = AgentConfig {
                control,
                ..AgentConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err("非法控制面配置必须被拒绝")
                .to_string();
            assert!(err.contains(needle), "错误信息应包含 {needle}: {err}");
        }
    }

    /// process 不需要白名单；其它能力在边界范围内必须合法。
    #[test]
    fn m3_agent_control_validation_accepts_safe_boundaries() {
        let process_only = ControlConfig {
            enabled: true,
            process: true,
            ..ControlConfig::default()
        };
        AgentConfig {
            control: process_only,
            ..AgentConfig::default()
        }
        .validate()
        .expect("process 能力不需要白名单");

        let full = ControlConfig {
            enabled: true,
            systemd: true,
            docker: true,
            process: true,
            logs: true,
            systemd_units: vec!["nginx*".into(), "redis.service".into()],
            docker_containers: vec!["web-*".into(), "db".into()],
            log_sources: vec![
                file_source("nginx-error", "/var/log/nginx/error.log"),
                journal_source("redis-journal", "redis.service"),
            ],
            command_timeout_secs: control::MIN_COMMAND_TIMEOUT_SECS,
            max_log_lines: control::MAX_MAX_LOG_LINES,
            systemctl_path: "/usr/local/bin/systemctl".into(),
            docker_path: "/usr/local/bin/docker".into(),
            journalctl_path: "/usr/local/bin/journalctl".into(),
        };
        AgentConfig {
            control: full.clone(),
            ..AgentConfig::default()
        }
        .validate()
        .expect("完整合法配置必须通过");

        // 另一个边界：60 秒超时 + 1 行。
        let other_boundary = ControlConfig {
            command_timeout_secs: control::MAX_COMMAND_TIMEOUT_SECS,
            max_log_lines: control::MIN_MAX_LOG_LINES,
            ..full
        };
        AgentConfig {
            control: other_boundary,
            ..AgentConfig::default()
        }
        .validate()
        .expect("超时上限与行数下限必须合法");
    }

    /// hub 侧控制面：能力开但总开关关、超时 / 挂起 / 输出上限越界都必须拒绝。
    #[test]
    fn m3_hub_control_validation_checks_switches_and_ranges() {
        let cases: Vec<(HubControlConfig, &str)> = vec![
            (
                HubControlConfig {
                    systemd: true,
                    ..HubControlConfig::default()
                },
                "hub.control.enabled=false",
            ),
            (
                HubControlConfig {
                    enabled: true,
                    request_timeout_ms: 999,
                    ..HubControlConfig::default()
                },
                "request_timeout_ms",
            ),
            (
                HubControlConfig {
                    enabled: true,
                    request_timeout_ms: 60_001,
                    ..HubControlConfig::default()
                },
                "request_timeout_ms",
            ),
            (
                HubControlConfig {
                    enabled: true,
                    max_pending_per_session: 0,
                    ..HubControlConfig::default()
                },
                "max_pending_per_session",
            ),
            (
                HubControlConfig {
                    enabled: true,
                    max_pending_per_session: 129,
                    ..HubControlConfig::default()
                },
                "max_pending_per_session",
            ),
            (
                HubControlConfig {
                    enabled: true,
                    max_output_bytes: 1023,
                    ..HubControlConfig::default()
                },
                "max_output_bytes",
            ),
            (
                HubControlConfig {
                    enabled: true,
                    max_output_bytes: 1_048_577,
                    ..HubControlConfig::default()
                },
                "max_output_bytes",
            ),
        ];
        for (control, needle) in cases {
            let cfg = HubConfig {
                control,
                ..HubConfig::default()
            };
            let err = cfg
                .validate()
                .expect_err("非法 hub 控制面配置必须被拒绝")
                .to_string();
            assert!(err.contains(needle), "错误信息应包含 {needle}: {err}");
        }

        let boundary = HubControlConfig {
            enabled: true,
            systemd: true,
            docker: true,
            process: true,
            logs: true,
            request_timeout_ms: control::MAX_REQUEST_TIMEOUT_MS,
            max_pending_per_session: control::MAX_MAX_PENDING_PER_SESSION,
            max_output_bytes: control::MAX_MAX_CONTROL_OUTPUT_BYTES,
        };
        HubConfig {
            control: boundary,
            ..HubConfig::default()
        }
        .validate()
        .expect("hub 控制面边界值必须合法");
    }

    /// M4-C1a：`[archive]` 缺省值、旧配置兼容、字段边界与 after_days 关系。
    #[test]
    fn m4c1_archive_defaults_legacy_toml_and_bounds() {
        // 旧配置完全没有 `[archive]`：默认关闭，行为与显式默认值一致。
        let hub: HubConfig = toml::from_str("").unwrap();
        assert_eq!(hub.archive, ArchiveConfig::default());
        assert!(!hub.archive.enabled);
        assert_eq!(hub.archive.backend, ArchiveBackend::Webdav);
        assert_eq!(hub.archive.backend.as_str(), "webdav");
        assert_eq!(ArchiveBackend::S3.as_str(), "s3");
        assert_eq!(ArchiveBackend::Sftp.as_str(), "sftp");
        assert_eq!(hub.archive.after_days, 7);
        assert_eq!(hub.archive.schedule_hour_utc, 3);
        assert_eq!(hub.archive.max_object_bytes, 33_554_432);
        assert_eq!(hub.archive.prefix, "rustboard");
        assert!(hub.archive.webdav.is_none());
        assert!(hub.archive.s3.is_none());
        assert!(hub.archive.sftp.is_none());
        hub.validate().expect("旧配置缺 [archive] 必须合法");

        // 只写部分字段：其余保持默认，后端类型字符串稳定。
        let hub: HubConfig =
            toml::from_str("[archive]\nbackend = \"s3\"\nafter_days = 3\nprefix = \"rb-01\"\n")
                .unwrap();
        assert_eq!(hub.archive.backend, ArchiveBackend::S3);
        assert_eq!(hub.archive.after_days, 3);
        assert_eq!(hub.archive.prefix, "rb-01");
        assert_eq!(hub.archive.schedule_hour_utc, 3);
        hub.validate().expect("关闭归档时只写部分字段必须合法");

        // after_days / schedule_hour_utc / max_object_bytes 的上下边界。
        for (line, ok) in [
            ("after_days = 1", true),
            ("after_days = 365", true),
            ("after_days = 0", false),
            ("after_days = 366", false),
            ("schedule_hour_utc = 0", true),
            ("schedule_hour_utc = 23", true),
            ("schedule_hour_utc = 24", false),
            ("max_object_bytes = 1048576", true),
            ("max_object_bytes = 67108864", true),
            ("max_object_bytes = 1048575", false),
            ("max_object_bytes = 67108865", false),
            // KI-31：旧上界 1 GiB 及更大的值必须被拒绝。
            ("max_object_bytes = 1073741824", false),
        ] {
            let hub: HubConfig =
                toml::from_str(&format!("[archive]\n{line}\n")).expect("TOML 必须可解析");
            // after_days 的上限与默认 raw 保留期（7 天）无关，这里只测字段范围。
            let result = hub.archive.validate();
            assert_eq!(
                result.is_ok(),
                ok,
                "{line} 的校验结果不符合预期: {result:?}"
            );
        }

        // KI-31：拒绝信息必须点名配置项，并说明这是单对象 / 下载内存上限。
        let hub: HubConfig = toml::from_str("[archive]\nmax_object_bytes = 67108865\n").unwrap();
        let err = hub
            .archive
            .validate()
            .expect_err("64 MiB + 1 必须拒绝")
            .to_string();
        assert!(
            err.contains("archive.max_object_bytes"),
            "错误必须点名字段: {err}"
        );
        assert!(err.contains("下载内存"), "错误必须说明下载内存上限: {err}");
        assert!(err.contains("67108864"), "错误必须给出上界: {err}");

        // prefix：仅 [A-Za-z0-9._-]、非空、≤64、不含 ".."。
        for (prefix, ok) in [
            ("rustboard", true),
            ("a", true),
            ("A-1_2.3", true),
            (&"a".repeat(64), true),
            (&"a".repeat(65), false),
            ("", false),
            ("bad/prefix", false),
            ("bad prefix", false),
            ("../evil", false),
            ("rustboard..", false),
            ("中文", false),
        ] {
            let hub = HubConfig {
                archive: ArchiveConfig {
                    prefix: prefix.to_string(),
                    ..ArchiveConfig::default()
                },
                ..HubConfig::default()
            };
            let result = hub.archive.validate();
            assert_eq!(result.is_ok(), ok, "prefix {prefix:?} 的校验结果不符合预期");
        }

        // after_days 必须 <= retention_raw_days；retention_raw_days=0 不受约束。
        let hub: HubConfig =
            toml::from_str("retention_raw_days = 3\n[archive]\nafter_days = 4\n").unwrap();
        let err = hub
            .validate()
            .expect_err("after_days > retention_raw_days 必须拒绝");
        let err = err.to_string();
        assert!(
            err.contains("archive.after_days"),
            "错误必须点名字段: {err}"
        );
        assert!(
            err.contains("retention_raw_days"),
            "错误必须说明与保留期的关系: {err}"
        );

        let hub: HubConfig =
            toml::from_str("retention_raw_days = 3\n[archive]\nafter_days = 3\n").unwrap();
        hub.validate()
            .expect("after_days == retention_raw_days 必须合法");

        let hub: HubConfig =
            toml::from_str("retention_raw_days = 0\n[archive]\nafter_days = 365\n").unwrap();
        hub.validate()
            .expect("retention_raw_days=0（永不删除）时 after_days 只受 365 上限约束");
    }

    /// M4-C1a：enabled 时对应后端必填，URL scheme / 端口 / 指纹格式严格校验。
    #[test]
    fn m4c1_archive_enabled_requires_valid_backend() {
        const GOOD_FP: &str = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";

        // 缺少所选后端配置。
        for (backend, needle) in [
            ("webdav", "[archive.webdav]"),
            ("s3", "[archive.s3]"),
            ("sftp", "[archive.sftp]"),
        ] {
            let hub: HubConfig = toml::from_str(&format!(
                "[archive]\nenabled = true\nbackend = \"{backend}\"\n"
            ))
            .unwrap();
            let err = hub
                .validate()
                .expect_err("缺少后端配置必须拒绝")
                .to_string();
            assert!(err.contains(needle), "错误必须点名 {needle}: {err}");
        }

        // WebDAV：合法配置通过；非 http(s) URL、空用户名/密码拒绝。
        let webdav_toml = "[archive]\nenabled = true\nbackend = \"webdav\"\n\
             [archive.webdav]\nurl = \"https://dav.example.com/rustboard\"\n\
             username = \"ops\"\npassword = \"secret\"\n";
        let hub: HubConfig = toml::from_str(webdav_toml).unwrap();
        hub.validate().expect("合法 WebDAV 配置必须通过");

        for (toml, needle) in [
            (
                "[archive]\nenabled = true\nbackend = \"webdav\"\n\
                 [archive.webdav]\nurl = \"ftp://dav.example.com\"\n\
                 username = \"ops\"\npassword = \"secret\"\n"
                    .to_string(),
                "archive.webdav.url",
            ),
            (
                "[archive]\nenabled = true\nbackend = \"webdav\"\n\
                 [archive.webdav]\nurl = \"https://\"\n\
                 username = \"ops\"\npassword = \"secret\"\n"
                    .to_string(),
                "archive.webdav.url",
            ),
            (
                "[archive]\nenabled = true\nbackend = \"webdav\"\n\
                 [archive.webdav]\nurl = \"https://dav.example.com\"\n\
                 username = \"\"\npassword = \"secret\"\n"
                    .to_string(),
                "archive.webdav.username",
            ),
            (
                "[archive]\nenabled = true\nbackend = \"webdav\"\n\
                 [archive.webdav]\nurl = \"https://dav.example.com\"\n\
                 username = \"ops\"\npassword = \"\"\n"
                    .to_string(),
                "archive.webdav.password",
            ),
        ] {
            let hub: HubConfig = toml::from_str(&toml).unwrap();
            let err = hub
                .validate()
                .expect_err("非法 WebDAV 配置必须拒绝")
                .to_string();
            assert!(err.contains(needle), "错误必须点名 {needle}: {err}");
        }

        // S3：合法配置；endpoint 必须是 http(s)。
        let hub: HubConfig = toml::from_str(
            "[archive]\nenabled = true\nbackend = \"s3\"\n\
             [archive.s3]\nbucket = \"rustboard-archive\"\nregion = \"us-east-1\"\n\
             access_key_id = \"access\"\nsecret_access_key = \"secret\"\npath_style = true\n",
        )
        .unwrap();
        hub.validate().expect("合法 S3 配置必须通过");

        let hub: HubConfig = toml::from_str(
            "[archive]\nenabled = true\nbackend = \"s3\"\n\
             [archive.s3]\nbucket = \"rustboard-archive\"\nregion = \"us-east-1\"\n\
             endpoint = \"ftp://minio.example.com\"\n\
             access_key_id = \"access\"\nsecret_access_key = \"secret\"\n",
        )
        .unwrap();
        let err = hub.validate().expect_err("非 http(s) endpoint 必须拒绝");
        assert!(err.to_string().contains("archive.s3.endpoint"));

        // SFTP：合法配置（私钥认证 + 44 字符指纹）；43 字符无填充指纹也合法。
        let sftp_prefix = "[archive]\nenabled = true\nbackend = \"sftp\"\n[archive.sftp]\n\
                            host = \"sftp.example.com\"\nusername = \"ops\"\n";
        let hub: HubConfig = toml::from_str(&format!(
            "{sftp_prefix}private_key_path = \"/etc/rustboard/id_ed25519\"\n\
             remote_dir = \"/backup/rustboard\"\nhost_key_fingerprint = \"{GOOD_FP}\"\n"
        ))
        .unwrap();
        hub.validate().expect("合法 SFTP 配置必须通过");

        let hub: HubConfig = toml::from_str(&format!(
            "{sftp_prefix}password = \"secret\"\nremote_dir = \"/backup\"\n\
             host_key_fingerprint = \"{}\"\n",
            GOOD_FP.trim_end_matches('=')
        ))
        .unwrap();
        hub.validate().expect("43 字符无填充指纹必须合法");

        for (extra, needle) in [
            (
                "password = \"secret\"\nremote_dir = \"/backup\"\nhost_key_fingerprint = \"\"\n",
                "host_key_fingerprint",
            ),
            (
                "password = \"secret\"\nremote_dir = \"/backup\"\n\
                 host_key_fingerprint = \"MD5:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n",
                "host_key_fingerprint",
            ),
            (
                "password = \"secret\"\nremote_dir = \"/backup\"\n\
                 host_key_fingerprint = \"SHA256:too-short\"\n",
                "host_key_fingerprint",
            ),
            (
                "password = \"secret\"\nremote_dir = \"backup\"\n\
                 host_key_fingerprint = \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n",
                "remote_dir",
            ),
            (
                "password = \"secret\"\nremote_dir = \"/backup/../etc\"\n\
                 host_key_fingerprint = \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n",
                "remote_dir",
            ),
            (
                "password = \"secret\"\nremote_dir = \"/backup\\\\windows\"\n\
                 host_key_fingerprint = \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n",
                "remote_dir",
            ),
            (
                "remote_dir = \"/backup\"\n\
                 host_key_fingerprint = \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n",
                "password",
            ),
            (
                "port = 0\npassword = \"secret\"\nremote_dir = \"/backup\"\n\
                 host_key_fingerprint = \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n",
                "port",
            ),
        ] {
            let hub: HubConfig = toml::from_str(&format!("{sftp_prefix}{extra}")).unwrap();
            let err = hub
                .validate()
                .expect_err("非法 SFTP 配置必须拒绝")
                .to_string();
            assert!(err.contains(needle), "错误必须点名 {needle}: {err}");
        }
    }

    /// SFTP remote_dir 必须拒绝反斜杠（Windows 服务端可能把它当分隔符）。
    #[test]
    fn archive_sftp_remote_dir_rejects_backslash() {
        let error = validate_archive_remote_dir(r"/backup\windows")
            .expect_err("含反斜杠的 remote_dir 必须拒绝")
            .to_string();
        assert!(error.contains("反斜杠"), "错误必须点名反斜杠: {error}");
        assert!(validate_archive_remote_dir("/backup/rustboard").is_ok());
    }

    /// M4-C1a：配置 Debug 不得打印 password / secret / key / 私钥路径。
    #[test]
    fn m4c1_archive_debug_redacts_secrets() {
        let hub: HubConfig = toml::from_str(
            "[archive]\nenabled = true\nbackend = \"webdav\"\nprefix = \"rb\"\n\
             [archive.webdav]\nurl = \"https://dav.example.com/rb\"\n\
             username = \"ops\"\npassword = \"webdav-password-plaintext\"\n\
             [archive.s3]\nbucket = \"bucket\"\nregion = \"us-east-1\"\n\
             access_key_id = \"AKIA-PLAINTEXT-ACCESS\"\n\
             secret_access_key = \"s3-secret-key-plaintext\"\n\
             [archive.sftp]\nhost = \"sftp.example.com\"\nusername = \"ops\"\n\
             private_key_path = \"/etc/rustboard/private-ed25519\"\n\
             remote_dir = \"/backup\"\n\
             host_key_fingerprint = \"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n",
        )
        .unwrap();
        hub.validate().expect("用于 Debug 测试的配置本身必须合法");

        let debug = format!("{hub:?}");
        for secret in [
            "webdav-password-plaintext",
            "AKIA-PLAINTEXT-ACCESS",
            "s3-secret-key-plaintext",
            "/etc/rustboard/private-ed25519",
        ] {
            assert!(
                !debug.contains(secret),
                "HubConfig Debug 不得包含 {secret}: {debug}"
            );
        }
        assert!(
            debug.matches("<redacted>").count() >= 4,
            "所有 secret 字段都必须标记 <redacted>: {debug}"
        );

        // 直接 Debug 单个后端结构也不能泄露。
        let s3_debug = format!("{:?}", hub.archive.s3.as_ref().unwrap());
        assert!(!s3_debug.contains("AKIA-PLAINTEXT-ACCESS"));
        assert!(!s3_debug.contains("s3-secret-key-plaintext"));
        let sftp_debug = format!("{:?}", hub.archive.sftp.as_ref().unwrap());
        assert!(!sftp_debug.contains("/etc/rustboard/private-ed25519"));
        let webdav_debug = format!("{:?}", hub.archive.webdav.as_ref().unwrap());
        assert!(!webdav_debug.contains("webdav-password-plaintext"));
    }
}
