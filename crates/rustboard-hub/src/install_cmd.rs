//! `rustboard-hub install / upgrade / uninstall`（M5 Phase A）。
//!
//! 本模块负责 hub 自身的一次性安装、旧手工配置的升级导入、卸载，以及同机
//! panel 的安装编排。配置/证书语义保持与 `init` 一致：自签 CA、SQLite、
//! 管理 API 默认只绑回环。
//!
//! 安全约定：
//! - systemctl 一律经 [`rustboard_install::ServiceManager`]（参数数组，不拼 shell）；
//! - `admin_token` 只写 0600 配置与 0600 临时文件，绝不打印、绝不放进 argv；
//! - 安装失败由 [`InstallTxn`] 逆序回滚，且绝不删除安装前已存在的数据目录；
//! - `--dry-run` 不写文件、不调用 systemctl。

use std::ffi::OsString;
use std::fs;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rustboard_common::config::{AcmeChallenge, AdminTlsMode, HubConfig, ServerTlsMode, TlsConfig};
use rustboard_common::fsutil;
use rustboard_common::tls;
use rustboard_common::util::{hostname, port_of};
use rustboard_install::{
    detect_system, is_systemd_unit_dir, pick_free_port, render_unit, require_root, shell_arg,
    unit_is_ours, validate_install_prefix, validate_managed_path, wait_http_ok,
    wait_https_ok_with_server_name, InstallLock, InstallState, InstallTxn, ManagedPathKind,
    PathOverrides, Paths, Prompt, Role, RoleState, ServiceManager,
};

// C5 只读诊断。用 `#[path]` 直接挂到 install_cmd 下，避免改 main.rs 与 C4 的
// `mod acme;` / `tls` 子命令冲突。
#[path = "tls_diag.rs"]
mod tls_diag;
use tls_diag::{Diagnostics, StagingOutcome};

/// 健康检查等待上限（库内部还会再截断到 30s）。
const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
/// 生产数据根目录：`--purge` 允许删除该目录下的旧手工安装数据。
const PRODUCTION_DATA_ROOT: &str = "/var/lib/rustboard";
/// systemd 系统级 unit 目录：`uninstall` 清理 enable 生成的 wants 链接时一并检查。
const SYSTEMD_SYSTEM_DIR: &str = "/etc/systemd/system";
/// ACME 最多尝试轮数（D9：失败最多 3 轮后回退）。
const ACME_MAX_ATTEMPTS: usize = 3;
/// 两轮 `tls issue` 之间的等待，避免 ACME 目录短暂故障时立刻打满重试。
const ACME_RETRY_BACKOFF: Duration = Duration::from_secs(2);
/// 单轮 `tls issue` 上限。ACME HTTP-01 / TLS-ALPN-01 通常远低于此值。
const ACME_ISSUE_TIMEOUT: Duration = Duration::from_secs(180);
/// `--domain` 上限与 `TlsConfig` 的 1–20 保持一致。
const MAX_ACME_DOMAINS: usize = 20;
/// Let's Encrypt staging directory；仅用于安装前的链路检查（证书不可信、可丢弃）。
const LE_STAGING_DIRECTORY: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
/// 私有 ACME 安装时从 `server.crt` 链尾提取的 agent 信任锚（0644）。
///
/// `tls.acme_ca_file` 是 ACME WFE 的 HTTPS 根，**不是** hub 服务端证书的 CA；
/// 同机 panel 的 `--hub-ca` 与安装器健康检查都必须用本文件。
const ACME_AGENT_CA_FILE: &str = "agent-ca.pem";
/// systemd 只读取固定目录中的 unit；写进 prefix 的 unit 不会被读取，也就不能
/// 用来 enable / restart / stop，必须在写盘和调用 systemctl 之前拒绝。
const SYSTEMD_UNIT_DIR_REQUIRED: &str =
    "systemd 不会读取 prefix 内 unit；请用 --unit-dir /etc/systemd/system 或 /run/systemd/system";

/// `rustboard-hub install` 的 ACME / 管理端 TLS 参数组。
///
/// 单独装箱再 flatten：这些字段直接内联会让 `Cmd` 枚举超过 clippy 的
/// `large_enum_variant` 阈值；clap 的 `Args for Box<T>` 支持这种写法。
#[derive(Args, Debug, Default)]
pub(crate) struct TlsCliArgs {
    /// ACME 账户联系邮箱（ACME 模式必填）。
    #[arg(long, value_name = "EMAIL")]
    pub(crate) acme_email: Option<String>,
    /// ACME directory URL；默认 Let's Encrypt production。
    #[arg(long, value_name = "URL")]
    pub(crate) acme_directory: Option<String>,
    /// ACME 挑战类型。
    #[arg(long, value_parser = ["http-01", "tls-alpn-01"])]
    pub(crate) acme_challenge: Option<String>,
    /// ACME 证书标识，可重复（acme-domain：1–20 个 DNS 名；acme-ip：恰好一个 IPv4）。
    #[arg(long = "domain", value_name = "DNS|IPv4")]
    pub(crate) domains: Vec<String>,
    /// ACME profile（例如 `shortlived`）；留空按 C4 默认。
    #[arg(long, value_name = "PROFILE")]
    pub(crate) acme_profile: Option<String>,
    /// 私有 / Pebble ACME 的根 CA PEM（绝对路径）；留空使用系统根。
    #[arg(long, value_name = "PEM")]
    pub(crate) acme_ca: Option<PathBuf>,
    /// 管理 API 传输模式：`off`（默认，仅回环明文）/ `required`（HTTPS）。
    #[arg(long, value_parser = ["off", "required"])]
    pub(crate) admin_tls: Option<String>,
}

/// `rustboard-hub install` 参数。
#[derive(Args, Debug)]
pub(crate) struct InstallArgs {
    /// 非交互执行（不读取 stdin）。
    #[arg(long)]
    pub(crate) yes: bool,
    /// 离线安装：不做任何网络探测；与 ACME（--tls acme-* / ACME 参数）互斥。
    #[arg(long)]
    pub(crate) offline: bool,
    /// 只打印计划，不写文件、不调用 systemctl。
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// 重写已有配置/unit 并重启；已有配置时保留 admin_token、data_dir 与证书。
    #[arg(long)]
    pub(crate) force: bool,
    /// 安装前缀（测试/容器用），默认 `/`。
    #[arg(long)]
    pub(crate) prefix: Option<PathBuf>,
    /// 配置文件路径，默认 `<prefix>/etc/rustboard/hub.toml`。
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    /// 数据目录，默认 `<prefix>/var/lib/rustboard/hub`。
    #[arg(long)]
    pub(crate) data_dir: Option<PathBuf>,
    /// systemd unit 目录，默认 `<prefix>/etc/systemd/system`。
    #[arg(long)]
    pub(crate) unit_dir: Option<PathBuf>,
    /// agent 接入监听地址，例如 `0.0.0.0:8443`；未指定时随机五位数端口。
    #[arg(long)]
    pub(crate) listen: Option<String>,
    /// 管理 API 监听地址；未指定时 `127.0.0.1:<随机五位数端口>`。
    #[arg(long)]
    pub(crate) admin_listen: Option<String>,
    /// 写进配置/证书的对外地址（IP 或域名）。
    #[arg(long)]
    pub(crate) advertise: Option<String>,
    /// 追加到服务端证书 SAN 的地址，可重复。
    #[arg(long = "san")]
    pub(crate) sans: Vec<String>,
    /// hub 展示名，默认 hostname。
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// 保留期，例如 `raw=7d,1m=90d,1h=2y`。
    #[arg(long)]
    pub(crate) retention: Option<String>,
    /// 数据库后端；Phase A 只支持 `sqlite`。
    #[arg(long)]
    pub(crate) db: Option<String>,
    /// 服务端证书来源：`self-signed`（默认）/ `acme-domain` / `acme-ip`。
    #[arg(long, value_parser = ["self-signed", "acme-domain", "acme-ip"])]
    pub(crate) tls: Option<String>,
    /// ACME / 管理端 TLS 参数组（装箱以控制枚举体积）。
    #[command(flatten)]
    pub(crate) tls_options: Box<TlsCliArgs>,
    /// 是否安装同机面板（`yes` / `no`）；`--yes` 时默认 `yes`。
    #[arg(long, value_parser = ["yes", "no"])]
    pub(crate) panel: Option<String>,
    /// 传给同机面板的静态资源目录。
    #[arg(long)]
    pub(crate) panel_static_dir: Option<PathBuf>,
    /// 强制通过 systemd 托管（会启动服务并做 healthz 检查）。
    #[arg(long, conflicts_with = "no_systemd")]
    pub(crate) systemd: bool,
    /// 不写 unit、不调用 systemctl。
    #[arg(long)]
    pub(crate) no_systemd: bool,
}

/// `rustboard-hub upgrade` 参数。
#[derive(Args, Debug)]
pub(crate) struct UpgradeArgs {
    /// 安装前缀，默认 `/`。
    #[arg(long)]
    pub(crate) prefix: Option<PathBuf>,
    /// 已有配置文件路径，默认 `<prefix>/etc/rustboard/hub.toml`。
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    /// unit 目录，默认 `<prefix>/etc/systemd/system`。
    #[arg(long)]
    pub(crate) unit_dir: Option<PathBuf>,
    /// 只打印计划，零写入。
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// `rustboard-hub uninstall` 参数。
#[derive(Args, Debug)]
pub(crate) struct UninstallArgs {
    /// 安装前缀，默认 `/`。
    #[arg(long)]
    pub(crate) prefix: Option<PathBuf>,
    /// 配置文件路径；缺省优先使用安装状态里的记录。
    #[arg(long)]
    pub(crate) config: Option<PathBuf>,
    /// unit 目录；缺省优先使用安装状态里的记录。
    #[arg(long)]
    pub(crate) unit_dir: Option<PathBuf>,
    /// 删除配置与数据目录（默认保留）。
    #[arg(long)]
    pub(crate) purge: bool,
    /// 非交互确认 `--purge`。
    #[arg(long)]
    pub(crate) yes: bool,
    /// 只打印计划，不写文件、不调用 systemctl。
    #[arg(long)]
    pub(crate) dry_run: bool,
}

/// `install` 的执行计划：校验/提示阶段结束后，真正落盘与启动所需的信息。
struct InstallPlan<'a> {
    args: &'a InstallArgs,
    paths: &'a Paths,
    cfg: &'a HubConfig,
    manager: ServiceManager,
    write_unit: bool,
    install_panel: bool,
    /// 需要生成自签服务端材料（ACME 成功时由 `tls issue` 负责）。
    need_certs: bool,
    /// ACME 失败回退 self-signed 时强制重签，避免沿用上一轮的 ACME 证书。
    force_self_signed: bool,
    restart: bool,
    /// 管理 API 健康检查（HTTP 或 HTTPS+SNI/CA）。
    health: HealthCheck,
}

/// 保留期覆盖值；`None` 表示沿用配置/默认值。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Retention {
    raw_days: Option<u32>,
    m_days: Option<u32>,
    h_days: Option<u32>,
}

/// 解析 `--tls`；`None` 保持旧行为（self-signed）。
fn parse_tls_mode(value: Option<&str>) -> Result<ServerTlsMode> {
    match value {
        None | Some("self-signed") => Ok(ServerTlsMode::SelfSigned),
        Some("acme-domain") => Ok(ServerTlsMode::AcmeDomain),
        Some("acme-ip") => Ok(ServerTlsMode::AcmeIp),
        Some(other) => bail!("--tls 只接受 self-signed / acme-domain / acme-ip，实际 {other:?}"),
    }
}

/// 解析 `--acme-challenge`；`None` 保持配置默认（http-01）。
fn parse_acme_challenge(value: Option<&str>) -> Result<AcmeChallenge> {
    match value {
        None | Some("http-01") => Ok(AcmeChallenge::Http01),
        Some("tls-alpn-01") => Ok(AcmeChallenge::TlsAlpn01),
        Some(other) => bail!("--acme-challenge 只接受 http-01 / tls-alpn-01，实际 {other:?}"),
    }
}

/// 读到最终配置后，`--offline` 仍必须与 ACME 模式互斥。
///
/// CLI 参数阶段的检查看不到磁盘上的既有配置：`packaging/install.sh` 会为既有
/// 安装自动注入 `--offline`，如果不在这里拒绝，后续诊断与 `tls issue` 仍会联网。
/// 必须在 Diagnostics / InstallTxn 之前调用。
fn ensure_offline_not_acme(args: &InstallArgs, cfg: &HubConfig) -> Result<()> {
    if args.offline && cfg.tls.mode.is_acme() {
        bail!(concat!(
            "--offline 与已有 ACME 配置互斥：当前配置的 tls.mode 为 ACME，",
            "安装需要诊断 80/443 链路并调用 tls issue 联网签发；",
            "请去掉 --offline，或显式使用 --tls self-signed 切回自签（会重建服务端证书）"
        ));
    }
    Ok(())
}

/// 解析 `--admin-tls`。
fn parse_admin_tls(value: Option<&str>) -> Result<AdminTlsMode> {
    match value {
        None | Some("off") => Ok(AdminTlsMode::Off),
        Some("required") => Ok(AdminTlsMode::Required),
        Some(other) => bail!("--admin-tls 只接受 off / required，实际 {other:?}"),
    }
}

/// 是否出现任何 ACME-only 参数。
fn has_acme_args(args: &InstallArgs) -> bool {
    args.tls_options.acme_email.is_some()
        || args.tls_options.acme_directory.is_some()
        || args.tls_options.acme_challenge.is_some()
        || !args.tls_options.domains.is_empty()
        || args.tls_options.acme_profile.is_some()
        || args.tls_options.acme_ca.is_some()
}

/// 写盘 / 网络之前的 TLS 参数互斥与必填校验。
///
/// 这一步必须在读取安装状态、调用 systemctl、访问网络之前执行：
/// - `--offline` 与任何 ACME 模式 / 参数同时出现 → 失败（ACME 不可能离线完成）；
/// - 显式 `--tls self-signed` 与 ACME-only 参数同时出现 → 明确拒绝，避免静默忽略；
/// - ACME 模式要求 email 与 domain；acme-ip 要求恰好一个 IPv4。
///
/// 未显式给 `--tls` 时不在这一步判定“是否为 self-signed”：已有配置可能本来
/// 就是 ACME，需要读到配置后由 [`ensure_acme_args_match_mode`] 再判定。
fn validate_tls_args(args: &InstallArgs) -> Result<ServerTlsMode> {
    let mode = parse_tls_mode(args.tls.as_deref())?;
    let acme_args = has_acme_args(args);

    if args.offline && (mode.is_acme() || acme_args) {
        bail!(concat!(
            "--offline 与 ACME 互斥：ACME 必须访问证书颁发机构并完成 80/443 挑战，",
            "离线模式不会发起任何网络请求。请去掉 --offline，或改用 --tls self-signed（默认）"
        ));
    }
    if args.tls.as_deref() == Some("self-signed") && acme_args {
        bail!(concat!(
            "--tls self-signed 不接受 ACME 参数（--acme-email / --acme-directory / ",
            "--acme-challenge / --domain / --acme-profile / --acme-ca）；",
            "如需 ACME 请显式指定 --tls acme-domain 或 --tls acme-ip"
        ));
    }
    if mode.is_acme() {
        let email = args
            .tls_options
            .acme_email
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        if email.is_empty() {
            bail!(
                "--tls {} 需要 --acme-email <邮箱>（ACME 账户联系邮箱）",
                mode.as_str()
            );
        }
        if args.tls_options.domains.is_empty() {
            bail!(
                "--tls {} 需要至少一个 --domain（acme-domain：DNS 名；acme-ip：公网 IPv4）",
                mode.as_str()
            );
        }
        if args.tls_options.domains.len() > MAX_ACME_DOMAINS {
            bail!(
                "--domain 最多 {MAX_ACME_DOMAINS} 个，实际 {} 个",
                args.tls_options.domains.len()
            );
        }
        if mode == ServerTlsMode::AcmeIp && args.tls_options.domains.len() != 1 {
            bail!(
                "--tls acme-ip 需要恰好一个 --domain <IPv4>，实际 {} 个",
                args.tls_options.domains.len()
            );
        }
        if let Some(path) = &args.tls_options.acme_ca {
            if !path.is_absolute() {
                bail!("--acme-ca 必须是绝对路径: {}", path.display());
            }
            let meta = fs::metadata(path)
                .with_context(|| format!("读取 --acme-ca {} 失败", path.display()))?;
            if !meta.is_file() {
                bail!("--acme-ca 不是普通文件: {}", path.display());
            }
        }
    }
    Ok(mode)
}

/// `--db` 只允许 SQLite；PostgreSQL 明确指向 Phase D。
fn check_db_mode(value: Option<&str>) -> Result<()> {
    match value {
        None | Some("sqlite") => Ok(()),
        Some(other) if other.starts_with("postgres://") || other.starts_with("postgresql://") => {
            bail!("PostgreSQL 后端在 Phase D 实现，当前 --db 只支持 sqlite（实际 {other:?}）")
        }
        Some(other) => bail!("--db 只支持 sqlite（Phase A），无法识别 {other:?}"),
    }
}

/// 解析 `--panel yes|no`。
fn parse_panel(value: &str) -> Result<bool> {
    match value {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => bail!("--panel 只接受 yes 或 no，实际 {other:?}"),
    }
}

/// 解析 `raw=7d,1m=90d,1h=2y`。
///
/// 键固定 `raw` / `1m` / `1h`；值支持 `d`（天）、`m`（30 天）、`y`（365 天）
/// 后缀或无后缀天数。未给出的键保持已有配置值。
fn parse_retention(input: &str) -> Result<Retention> {
    let mut retention = Retention::default();
    for part in input.split(',') {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("--retention 片段缺少 '=': {:?}", part.trim()))?;
        let key = key.trim();
        let days = parse_retention_days(value.trim())?;
        let slot = match key {
            "raw" => &mut retention.raw_days,
            "1m" => &mut retention.m_days,
            "1h" => &mut retention.h_days,
            "" => bail!("--retention 含空的键"),
            other => {
                bail!("--retention 不支持键 {other:?}（只支持 raw / 1m / 1h）")
            }
        };
        if slot.replace(days).is_some() {
            bail!("--retention 重复指定了 {key}");
        }
    }
    Ok(retention)
}

/// 把 `7d` / `90d` / `2y` 之类解析成天数（向上限 u32）。
fn parse_retention_days(value: &str) -> Result<u32> {
    if value.is_empty() {
        bail!("--retention 的值不能为空");
    }
    let (number, unit) = match value.chars().last() {
        Some(ch) if ch.is_ascii_alphabetic() => {
            let index = value.len() - ch.len_utf8();
            (&value[..index], Some(ch.to_ascii_lowercase()))
        }
        _ => (value, None),
    };
    let number: u32 = number
        .trim()
        .parse()
        .with_context(|| format!("--retention 的值 {value:?} 不是合法天数"))?;
    let multiplier = match unit {
        None | Some('d') => 1,
        Some('m') => 30,
        Some('y') => 365,
        Some(other) => {
            bail!("--retention 不支持单位 {other:?}（只支持 d / m / y）")
        }
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("--retention 的值 {value:?} 超出范围"))
}

/// 把 CLI 的 TLS / admin TLS 参数应用到配置。
///
/// 只覆盖显式给出的字段：`--force` 重装已有配置时，未给出的 ACME 字段保持原值，
/// 避免无参数重装把 ACME directory / profile 重置成默认。
fn apply_tls_flags(cfg: &mut HubConfig, args: &InstallArgs) -> Result<()> {
    if let Some(value) = args.tls.as_deref() {
        let mode = parse_tls_mode(Some(value))?;
        if mode == ServerTlsMode::SelfSigned {
            // 显式切回 self-signed：清空上一轮 ACME 参数，避免留下半份 ACME 配置。
            cfg.tls = TlsConfig::default();
        } else {
            cfg.tls.mode = mode;
        }
    }
    if let Some(email) = &args.tls_options.acme_email {
        cfg.tls.acme_email = email.trim().to_string();
    }
    if let Some(directory) = &args.tls_options.acme_directory {
        cfg.tls.acme_directory = directory.trim().to_string();
    }
    if let Some(challenge) = &args.tls_options.acme_challenge {
        cfg.tls.challenge = parse_acme_challenge(Some(challenge))?;
    }
    if let Some(profile) = &args.tls_options.acme_profile {
        cfg.tls.acme_profile = profile.trim().to_string();
    }
    if let Some(path) = &args.tls_options.acme_ca {
        let path = path
            .to_str()
            .ok_or_else(|| anyhow!("--acme-ca 不是有效 UTF-8: {}", path.display()))?;
        cfg.tls.acme_ca_file = path.to_string();
    }
    if !args.tls_options.domains.is_empty() {
        let mut domains = Vec::with_capacity(args.tls_options.domains.len());
        for domain in &args.tls_options.domains {
            push_server_name(&mut domains, domain)?;
        }
        cfg.tls.domains = domains;
    }
    if let Some(admin_tls) = &args.tls_options.admin_tls {
        cfg.admin_tls = parse_admin_tls(Some(admin_tls))?;
    }
    // 主程序的 `validate_admin_tls` 与管理端证书加载都看 `server_names`；
    // ACME 模式把证书标识同步进去，既让 `--admin-tls required` 能通过非回环
    // 绑定的校验，也让回退 self-signed 时的证书覆盖这些名字。
    if cfg.tls.mode.is_acme() {
        let domains = cfg.tls.domains.clone();
        for domain in domains {
            push_server_name(&mut cfg.server_names, &domain)?;
        }
    }
    Ok(())
}

/// 读到最终配置后，确认 ACME-only 参数没有被 self-signed 配置静默忽略。
fn ensure_acme_args_match_mode(cfg: &HubConfig, args: &InstallArgs) -> Result<()> {
    if cfg.tls.mode == ServerTlsMode::SelfSigned && has_acme_args(args) {
        bail!(concat!(
            "当前安装为 self-signed，不接受 ACME 参数（--acme-email / --acme-directory / ",
            "--acme-challenge / --domain / --acme-profile / --acme-ca）；",
            "如需 ACME 请加 --tls acme-domain 或 --tls acme-ip"
        ));
    }
    Ok(())
}

/// 应用保留期覆盖。
fn apply_retention(cfg: &mut HubConfig, retention: Retention) {
    if let Some(days) = retention.raw_days {
        cfg.retention_raw_days = days;
    }
    if let Some(days) = retention.m_days {
        cfg.retention_1m_days = days;
    }
    if let Some(days) = retention.h_days {
        cfg.retention_1h_days = days;
    }
}

/// SQLite 数据库地址（与 `hub init` 的格式一致）。
fn sqlite_database(data_dir: &Path) -> String {
    format!("sqlite://{}/rustboard.db", data_dir.display())
}

/// 解析并校验一个 `host:port` 监听地址；只解析、不 bind。
///
/// 显式端口不做 bind 预检：端口冲突应交给服务启动失败后的回滚路径。
fn parse_listen(value: &str, label: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = value
        .parse()
        .with_context(|| format!("{label} 不是合法的 host:port: {value:?}"))?;
    if addr.port() == 0 {
        bail!("{label} 的端口不能为 0: {value:?}");
    }
    Ok(addr)
}

/// 校验配置里的两个监听地址都在服务端可解析。
fn validate_listen(cfg: &HubConfig) -> Result<()> {
    parse_listen(&cfg.agent_listen, "agent 监听地址（--listen）")?;
    parse_listen(&cfg.admin_listen, "管理 API 监听地址（--admin-listen）")?;
    Ok(())
}

/// 管理 API 健康检查 URL。
///
/// 管理口绑 `0.0.0.0` / `[::]` 时改用回环地址；否则用绑定 IP（默认只绑回环）。
fn health_url(admin_listen: &str) -> Result<String> {
    let addr = parse_listen(admin_listen, "管理 API 监听地址")?;
    let host = if addr.ip().is_unspecified() {
        if addr.is_ipv6() {
            "[::1]".to_string()
        } else {
            "127.0.0.1".to_string()
        }
    } else if addr.is_ipv6() {
        format!("[{}]", addr.ip())
    } else {
        addr.ip().to_string()
    };
    Ok(format!("http://{host}:{}/healthz", addr.port()))
}

/// 追加一个 SAN，去掉首尾空白并去重（大小写不敏感）。
fn push_server_name(names: &mut Vec<String>, raw: &str) -> Result<()> {
    let name = raw.trim();
    if name.is_empty() {
        bail!("服务端证书 SAN 不能为空");
    }
    if name.chars().any(char::is_control) {
        bail!("服务端证书 SAN {name:?} 含控制字符");
    }
    if !names
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(name))
    {
        names.push(name.to_string());
    }
    Ok(())
}

/// 新装时服务端证书至少覆盖 hostname / 127.0.0.1 / localhost / advertise / --san。
fn desired_server_names(
    host: &str,
    advertise: Option<&str>,
    sans: &[String],
) -> Result<Vec<String>> {
    let mut names = Vec::new();
    push_server_name(&mut names, host)?;
    push_server_name(&mut names, "127.0.0.1")?;
    push_server_name(&mut names, "localhost")?;
    if let Some(advertise) = advertise {
        push_server_name(&mut names, advertise)?;
    }
    for san in sans {
        push_server_name(&mut names, san)?;
    }
    Ok(names)
}

/// 新装配置：默认值 + 显式 flags，端口未指定时使用五位数随机端口。
fn new_hub_config(args: &InstallArgs, paths: &Paths, retention: Retention) -> Result<HubConfig> {
    // 先解析显式地址：隐式挑 agent 端口时排除显式管理端口，避免两者撞在一起。
    let explicit_admin = match &args.admin_listen {
        Some(value) => Some(parse_listen(value, "--admin-listen")?.to_string()),
        None => None,
    };
    let agent_listen = match &args.listen {
        Some(value) => parse_listen(value, "--listen")?.to_string(),
        None => {
            let exclude: Vec<u16> = explicit_admin
                .as_deref()
                .and_then(port_of)
                .into_iter()
                .collect();
            let port = pick_free_port(&exclude).context("未找到空闲的 agent 监听端口")?;
            format!("0.0.0.0:{port}")
        }
    };
    let admin_listen = match explicit_admin {
        Some(value) => value,
        None => {
            let exclude: Vec<u16> = port_of(&agent_listen).into_iter().collect();
            let port = pick_free_port(&exclude).context("未找到空闲的管理 API 监听端口")?;
            format!("127.0.0.1:{port}")
        }
    };
    let advertise = match args.advertise.as_deref() {
        Some(value) => {
            let value = value.trim();
            if value.is_empty() {
                bail!("--advertise 不能为空");
            }
            Some(value.to_string())
        }
        None => None,
    };
    let host = hostname();
    let name = args
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| host.clone());
    let server_names = desired_server_names(&host, advertise.as_deref(), &args.sans)?;

    let mut cfg = HubConfig {
        agent_listen,
        admin_listen,
        data_dir: paths.data_dir.clone(),
        database: sqlite_database(&paths.data_dir),
        name,
        server_names,
        advertise_host: advertise,
        admin_token: crate::new_secret(),
        ..HubConfig::default()
    };
    apply_tls_flags(&mut cfg, args)?;
    apply_retention(&mut cfg, retention);
    Ok(cfg)
}

/// 已有配置（`--force` / 旧手工安装）只应用显式 flags，保留 token、data_dir 与证书。
fn apply_explicit_flags(
    cfg: &mut HubConfig,
    args: &InstallArgs,
    retention: Retention,
) -> Result<()> {
    if let Some(value) = &args.listen {
        cfg.agent_listen = parse_listen(value, "--listen")?.to_string();
    }
    if let Some(value) = &args.admin_listen {
        cfg.admin_listen = parse_listen(value, "--admin-listen")?.to_string();
    }
    if let Some(value) = &args.advertise {
        let value = value.trim();
        if value.is_empty() {
            bail!("--advertise 不能为空");
        }
        cfg.advertise_host = Some(value.to_string());
        push_server_name(&mut cfg.server_names, value)?;
    }
    for san in &args.sans {
        push_server_name(&mut cfg.server_names, san)?;
    }
    if let Some(name) = &args.name {
        cfg.name = name.clone();
    }
    // data_dir 是显式 flag 时，数据库跟随数据目录；--db 显式给出时也只支持 sqlite。
    if let Some(data_dir) = &args.data_dir {
        cfg.data_dir = data_dir.clone();
        cfg.database = sqlite_database(data_dir);
    } else if args.db.is_some() {
        cfg.database = sqlite_database(&cfg.data_dir);
    }
    apply_tls_flags(cfg, args)?;
    apply_retention(cfg, retention);
    Ok(())
}

/// 已存在配置时加载并校验；否则按 flags 生成新配置。
///
/// 返回 `need_certs`：已有配置且 CA/服务端证书齐全时为 false，安装器不会重写
/// 证书（避免 `--force` 改变服务端指纹、让已纳管 agent 失联）。
fn prepare_config(
    args: &InstallArgs,
    paths: &Paths,
    retention: Retention,
    config_present: bool,
) -> Result<(HubConfig, bool)> {
    if config_present {
        let mut cfg = load_hub_config_checked(&paths.config)?;
        apply_explicit_flags(&mut cfg, args, retention)?;
        ensure_acme_args_match_mode(&cfg, args)?;
        cfg.validate()
            .context("已有配置校验失败（检查 --san / --retention / --data-dir）")?;
        validate_listen(&cfg)?;
        crate::validate_admin_tls(&cfg).context("管理 API 监听地址不安全")?;
        let missing = missing_cert_files(&cfg.data_dir)?;
        // ACME 模式的服务端证书由 `tls issue` 负责；不能用自签的缺文件检查
        // 阻止 ACME 在已有数据目录上补签。
        let need_certs = !missing.is_empty() && !cfg.tls.mode.is_acme();
        Ok((cfg, need_certs))
    } else {
        let cfg = new_hub_config(args, paths, retention)?;
        ensure_acme_args_match_mode(&cfg, args)?;
        cfg.validate()
            .context("安装参数校验失败（检查 --san / --retention / --data-dir）")?;
        validate_listen(&cfg)?;
        crate::validate_admin_tls(&cfg).context("管理 API 监听地址不安全")?;
        let need_certs = !cfg.tls.mode.is_acme();
        Ok((cfg, need_certs))
    }
}

/// 证书材料缺失列表；符号链接 / 非普通文件直接报错，不静默沿用。
fn missing_cert_files(data_dir: &Path) -> Result<Vec<String>> {
    let dir = tls::cert_dir(data_dir);
    let mut missing = Vec::new();
    for name in [
        tls::CA_CERT_FILE,
        tls::CA_KEY_FILE,
        tls::SERVER_CERT_FILE,
        tls::SERVER_KEY_FILE,
    ] {
        let path = dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("证书材料 {} 是符号链接，拒绝使用", path.display())
            }
            Ok(meta) if meta.is_file() => {}
            Ok(_) => bail!("证书材料 {} 不是普通文件", path.display()),
            Err(err) if err.kind() == ErrorKind::NotFound => missing.push(name.to_string()),
            Err(err) => {
                return Err(err).with_context(|| format!("检查证书材料 {} 失败", path.display()))
            }
        }
    }
    Ok(missing)
}

/// 安全读取 hub 配置。
///
/// `HubConfig::load` 的底层错误会带出 TOML 行内容（例如重复 `admin_token` 的
/// 原始行），直接拼进终端或日志等于泄露管理 token。这里丢弃整条错误链，只给
/// 固定文案；人工需要细节时自行检查文件。
fn load_hub_config_checked(path: &Path) -> Result<HubConfig> {
    HubConfig::load(path).map_err(|_| {
        anyhow!(
            "读取配置失败 {}（未显示解析细节，避免泄露 admin_token）",
            path.display()
        )
    })
}

/// 只读加载 hub 配置（`upgrade --dry-run` 专用）。
///
/// 不能用 [`HubConfig::load`] / [`load_hub_config_checked`]：底层 `load_toml`
/// 会先把配置 `harden` 成 0600，dry-run 修改已有 0644 配置就违反“零写入”。
/// 这里只用 `fs::read_to_string` + `toml::from_str`；解析失败只报路径，不带
/// TOML 行内容（重复 `admin_token` 等错误会回显原始行）。
fn load_hub_config_read_only(path: &Path) -> Result<HubConfig> {
    let text =
        fs::read_to_string(path).with_context(|| format!("读取配置失败 {}", path.display()))?;
    toml::from_str(&text).map_err(|_| {
        anyhow!(
            "解析配置失败 {}（未显示解析细节，避免泄露 admin_token）",
            path.display()
        )
    })
}

/// 读配置后必须执行的校验（所有 `HubConfig::load` 调用点共用）。
fn validate_hub_config(cfg: &HubConfig) -> Result<()> {
    cfg.validate()
        .context("配置校验失败（检查 server_names / retention / data_dir）")?;
    validate_listen(cfg)?;
    crate::validate_admin_tls(cfg).context("管理 API 监听地址不安全")
}

/// 健康检查信任来源：ACME 公共证书用系统根，自签用本地 `ca.crt`，
/// 私有 ACME 用从 `server.crt` 链尾提取的 `agent-ca.pem`。
#[derive(Debug, Clone, PartialEq, Eq)]
enum HealthCa {
    SystemRoots,
    PemFile(PathBuf),
}

/// 管理 API 健康检查计划（不读文件、不联网）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum HealthCheck {
    Http {
        url: String,
    },
    Https {
        /// 实际连接地址：通配绑定改为回环；其他绑定用绑定 IP。
        addr: SocketAddr,
        /// 配置中的主机名 / IP，用于 SNI 与证书主机名校验。
        server_name: String,
        ca: HealthCa,
    },
}

impl HealthCheck {
    /// 展示用 URL（只含公开的地址 / 主机名）。
    fn display_url(&self) -> String {
        match self {
            Self::Http { url } => url.clone(),
            Self::Https {
                addr, server_name, ..
            } => format!("https://{server_name}:{}/healthz", addr.port()),
        }
    }
}

/// 规划管理 API 健康检查。
///
/// - `admin_tls=off`：沿用 v0.4 的 `http://<bind>/healthz`；
/// - `admin_tls=required`：HTTPS，SNI 取配置里的 SAN（`effective_server_names`）。
///   通配绑定时连回环；证书主机名校验仍使用配置里的名字，因此 ACME 域名证书
///   不需要包含回环 IP。`--admin-tls required` 不再被一律拒绝，但必须能推导出
///   一个配置覆盖的主机名，否则在写盘前失败。
fn health_check_for(cfg: &HubConfig) -> Result<HealthCheck> {
    let addr = parse_listen(&cfg.admin_listen, "管理 API 监听地址")?;
    if cfg.admin_tls == AdminTlsMode::Off {
        return Ok(HealthCheck::Http {
            url: health_url(&cfg.admin_listen)?,
        });
    }

    let connect_ip = if addr.ip().is_unspecified() {
        if addr.is_ipv6() {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
    } else {
        addr.ip()
    };
    let connect = SocketAddr::new(connect_ip, addr.port());
    let names: Vec<String> = cfg
        .effective_server_names()
        .into_iter()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .collect();
    if names.is_empty() {
        bail!(
            "admin_tls=required 需要管理端证书覆盖的主机名，但当前服务端 SAN 为空；\
             自签模式请用 --san 指定，ACME 模式请用 --domain 指定"
        );
    }
    // 优先用与连接 IP 精确匹配的 SAN（自签默认含 127.0.0.1）；否则用可用的
    // DNS 名（ACME 域名），最后才退回第一个名字（acme-ip 的公网 IP）。
    let server_name = names
        .iter()
        .find(|name| name.parse::<IpAddr>().is_ok_and(|ip| ip == connect_ip))
        .or_else(|| {
            names.iter().find(|name| {
                name.parse::<IpAddr>().is_err() && !name.eq_ignore_ascii_case("localhost")
            })
        })
        .or_else(|| names.first())
        .cloned()
        .ok_or_else(|| anyhow!("管理 API 健康检查无法确定 server_name"))?;

    let ca = match cfg.tls.mode {
        ServerTlsMode::SelfSigned => {
            HealthCa::PemFile(tls::cert_dir(&cfg.data_dir).join(tls::CA_CERT_FILE))
        }
        ServerTlsMode::AcmeDomain | ServerTlsMode::AcmeIp => {
            // 公共 ACME 用系统根；私有 ACME 的信任锚是服务端证书链尾（签发后由
            // `prepare_private_acme_agent_ca` 提取），绝不能把 ACME WFE 的 HTTPS
            // 根当作 hub 证书 CA。
            if cfg.tls.acme_ca_file.trim().is_empty() {
                HealthCa::SystemRoots
            } else {
                HealthCa::PemFile(tls::cert_dir(&cfg.data_dir).join(ACME_AGENT_CA_FILE))
            }
        }
    };
    Ok(HealthCheck::Https {
        addr: connect,
        server_name,
        ca,
    })
}

/// 写盘 / 启动前的健康检查可用性校验。
///
/// 不再拒绝 `admin_tls=required`：改为确认能构造 HTTPS 健康检查（SNI + CA）。
/// 真正启动后由 [`run_health_check`] 用 rustls 验证证书链与主机名。
fn ensure_admin_tls_supported(cfg: &HubConfig) -> Result<()> {
    health_check_for(cfg)
        .map(|_| ())
        .context("管理 API TLS 健康检查不可用（检查 admin_listen / server_names / tls.domains）")
}

/// 启动后执行管理 API 健康检查；HTTP 与 HTTPS 语义不同但超时一致。
fn run_health_check(health: &HealthCheck, timeout: Duration) -> Result<()> {
    match health {
        HealthCheck::Http { url } => {
            wait_http_ok(url, timeout).with_context(|| format!("等待 hub 健康检查失败: {url}"))
        }
        HealthCheck::Https {
            addr,
            server_name,
            ca,
        } => {
            let ca_pem = match ca {
                HealthCa::SystemRoots => None,
                HealthCa::PemFile(path) => Some(
                    fs::read_to_string(path)
                        .with_context(|| format!("读取健康检查 CA 失败: {}", path.display()))?,
                ),
            };
            wait_https_ok_with_server_name(*addr, server_name, ca_pem.as_deref(), timeout)
                .with_context(|| {
                    format!(
                        "等待 hub HTTPS 健康检查失败: https://{server_name}:{}/healthz",
                        addr.port()
                    )
                })
        }
    }
}

/// 受管路径允许写入 unit / 配置的字符集检查。
///
/// 库的 `validate_managed_path` 只做路径范围 allowlist；安装器另外拒绝 `$` / `%`
/// （systemd 变量与 specifier 展开）、引号与反斜杠（unit / shell 转义歧义）以及
/// 控制字符，避免 `--config '/srv/$x/hub.toml'` 这类值进入 unit 或摘要命令。
fn reject_managed_path_chars(path: &Path, label: &str) -> Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("{label}不是有效 UTF-8: {}", path.display()))?;
    if let Some(ch) = text
        .chars()
        .find(|ch| ch.is_control() || matches!(ch, '$' | '%' | '"' | '\'' | '\\'))
    {
        bail!("{label}含不允许的字符 {ch:?}（systemd / shell 转义歧义）: {text:?}");
    }
    Ok(())
}

/// 安装 / 升级写盘前的受管路径 allowlist。
///
/// 防止 `--config` / `--data-dir` / `--unit-dir` 或（损坏/伪造的）state 记录把
/// 写入引到 prefix 之外、systemd unit 目录之外；同时拒绝 `$` / 引号等会被
/// systemd 或 shell 二次解释的字符。
fn validate_install_paths(paths: &Paths) -> Result<()> {
    validate_install_prefix(&paths.prefix)?;
    for (kind, path, label) in [
        (
            ManagedPathKind::Config,
            &paths.config,
            "配置路径必须位于安装前缀的 RustBoard 管理位置",
        ),
        (
            ManagedPathKind::Data,
            &paths.data_dir,
            "数据目录必须位于安装前缀的 RustBoard 管理位置",
        ),
        (
            ManagedPathKind::Unit,
            &paths.unit,
            "unit 路径必须位于 systemd unit 目录或安装前缀内",
        ),
        (
            ManagedPathKind::Binary,
            &paths.binary,
            "二进制路径必须位于安装前缀的 RustBoard 管理位置",
        ),
    ] {
        reject_managed_path_chars(path, "受管路径")?;
        validate_managed_path(Role::Hub, &paths.prefix, path, kind).context(label)?;
    }
    Ok(())
}

/// 检查目标 unit 是否可被本安装器接管。
///
/// 不存在放行；存在则必须是普通文件、非符号链接，且内容由本安装器为当前
/// `paths` 渲染（`UNIT_MARKER` + 精确 ExecStart）。外来同名 unit 一律拒绝，
/// `--force` 也不例外：覆盖/停止别人托管的服务可能直接造成生产中断。
fn ensure_unit_owned_by_us(role: Role, paths: &Paths) -> Result<()> {
    let path = &paths.unit;
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("检查现存 unit {} 失败", path.display()))
        }
    };
    if meta.file_type().is_symlink() {
        bail!("现存 unit {} 是符号链接，拒绝覆盖/停止", path.display());
    }
    if !meta.is_file() {
        bail!("现存 unit {} 不是普通文件，拒绝覆盖/停止", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("读取现存 unit {} 失败", path.display()))?;
    let contents = String::from_utf8(bytes)
        .map_err(|_| anyhow!("现存 unit {} 不是有效 UTF-8，拒绝覆盖/停止", path.display()))?;
    if !unit_is_ours(role, paths, &contents) {
        bail!(
            "现存 unit {} 不是本安装器为当前 prefix 生成的，拒绝覆盖/停止；--force 也不会覆盖外来 unit",
            path.display()
        );
    }
    Ok(())
}

/// 判断路径是否不存在；其他元数据错误照常上报。
fn path_is_missing(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err).with_context(|| format!("检查{label} {} 失败", path.display())),
    }
}

/// 需要生成证书时，拒绝在已有数据目录上重建 CA / 服务端证书。
///
/// 旧数据目录里可能已有 agent 证书或历史证书链；重新生成 CA 会让所有已纳管
/// agent 的指纹失联，且旧证书无法再验证。证书不全只能从备份恢复或人工处理。
fn ensure_cert_rebuild_allowed(data_dir: &Path, need_certs: bool) -> Result<()> {
    if !need_certs {
        return Ok(());
    }
    match fs::symlink_metadata(data_dir) {
        Ok(_) => bail!(
            "已有数据目录 {} 但证书不完整；请从备份恢复，拒绝重建以免 agent 指纹失联",
            data_dir.display()
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("检查数据目录 {} 失败", data_dir.display())),
    }
}

/// 判断路径是否存在且是普通文件；符号链接/目录视为错误。
fn regular_file_exists(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("{label} {} 是符号链接，拒绝操作", path.display())
        }
        Ok(meta) if meta.is_file() => Ok(true),
        Ok(_) => bail!("{label} {} 不是普通文件", path.display()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("检查{label} {} 失败", path.display())),
    }
}

/// 幂等检查：列出安装状态记录中缺失的配置文件 / 二进制 / unit。
fn missing_install_files(paths: &Paths, require_unit: bool) -> Result<Vec<String>> {
    let mut missing = Vec::new();
    for (label, path, required) in [
        ("配置文件", &paths.config, true),
        ("hub 二进制", &paths.binary, true),
        ("systemd unit", &paths.unit, require_unit),
    ] {
        if !required {
            continue;
        }
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => missing.push(format!("{label} {}（不是普通文件）", path.display())),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                missing.push(format!("{label} {}", path.display()));
            }
            Err(err) => {
                return Err(err).with_context(|| format!("检查{label} {} 失败", path.display()))
            }
        }
    }
    Ok(missing)
}

/// unit 文件的父目录。
fn unit_parent(paths: &Paths) -> Result<PathBuf> {
    paths
        .unit
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("unit 路径缺少父目录: {}", paths.unit.display()))
}

/// 要求 unit 的父目录是 systemd 真正会加载的目录。
///
/// 写进 `<prefix>/etc/systemd/system` 的 unit 不会被 systemd 读取；此时再调用
/// enable / restart / stop，要么操作到同名的外来 unit，要么静默失败并让健康
/// 检查误判。装机阶段必须在写盘和 systemctl 之前硬拒绝。
fn ensure_unit_dir_read_by_systemd(unit: &Path) -> Result<()> {
    let parent = unit
        .parent()
        .ok_or_else(|| anyhow!("unit 路径缺少父目录: {}", unit.display()))?;
    if !is_systemd_unit_dir(parent) {
        bail!(
            "{SYSTEMD_UNIT_DIR_REQUIRED}（当前 unit 路径: {}）",
            unit.display()
        );
    }
    Ok(())
}

/// install 托管 systemd 时的目录校验；只写 prefix 内参考 unit 的安装不调用
/// systemctl，故不在这里拒绝（`--no-systemd` 同样跳过）。
fn ensure_install_unit_dir(manage: bool, unit: &Path) -> Result<()> {
    if manage {
        ensure_unit_dir_read_by_systemd(unit)?;
    }
    Ok(())
}

/// install 进入幂等分支前，对 systemd 实际解析结果的判定。
///
/// - `Some(path)` 且就是目标 unit：可以继续；
/// - `Some(other)`：同名外来 / 更高优先级 unit，拒绝覆盖或操作；
/// - `None` 且服务 active：transient 或外来 unit，没有可核对的 unit 文件，拒绝；
/// - `None` 且服务未 active：尚未安装或尚未加载，写完 unit + daemon-reload 后
///   由 [`ServiceManager::ensure_fragment_is`] 再次核对。
fn ensure_install_fragment_matches(
    fragment: Option<&Path>,
    active: bool,
    expected: &Path,
) -> Result<()> {
    match fragment {
        Some(path) if path == expected => Ok(()),
        Some(path) => bail!(
            "systemd 实际解析的 hub unit 是 {}，不是本安装器要写入的 {}；同名外来或更高优先级 unit，拒绝覆盖/停止",
            path.display(),
            expected.display()
        ),
        None if active => bail!(
            "systemd 中已有同名 hub unit 处于 active 但解析不到 unit 文件（transient / 外来 unit）；拒绝覆盖/停止"
        ),
        None => Ok(()),
    }
}

/// uninstall 对 systemd 解析结果的分类。
#[derive(Clone, Debug, PartialEq, Eq)]
enum UninstallUnitAction {
    /// fragment 就是 state 记录的 unit：可以 stop / disable 后删除。
    StopAndRemove,
    /// unit 文件不存在，或 systemd 未解析到该文件：绝不 stop，只删自己的文件。
    RemoveOnly,
    /// systemd 解析到别的 unit：拒绝停止 / 卸载，避免动到外来 unit。
    RefuseForeign(PathBuf),
}

/// 纯函数：只有 systemd 明确解析到本安装的 unit，才允许 stop / disable。
///
/// 失败清理、回滚恢复与卸载在真正调用 `systemctl` 前都会用
/// [`ServiceManager::ensure_fragment_is`] 实时查询并校验；这里保留同一决策的
/// 纯函数形式，供单元测试锁定“fragment 缺失或外来时绝不 stop”的语义，
/// 避免依赖 fake systemctl 的行为测试。
fn should_stop_verified(fragment: Option<&Path>, expected: &Path) -> bool {
    matches!(fragment, Some(path) if path == expected)
}

/// 根据 unit 文件是否存在与 `fragment_path` 结果决定卸载动作。
///
/// unit 文件不存在时即使同名服务 active 也绝不 stop（可能是 transient unit）；
/// 只有 systemd 明确解析到 state 记录的这个文件，才允许 stop / disable。
fn classify_uninstall_unit(
    unit_present: bool,
    fragment: Option<&Path>,
    expected: &Path,
) -> UninstallUnitAction {
    if !unit_present {
        return UninstallUnitAction::RemoveOnly;
    }
    if should_stop_verified(fragment, expected) {
        return UninstallUnitAction::StopAndRemove;
    }
    match fragment {
        Some(path) => UninstallUnitAction::RefuseForeign(path.to_path_buf()),
        None => UninstallUnitAction::RemoveOnly,
    }
}

/// 先用**原始 CLI prefix** 做校验，再交给 [`Paths::for_role`] 归一化。
///
/// `Paths::for_role` 会忽略重复分隔符与结尾 `/`（`//` → `/`、
/// `/opt/rb/` → `/opt/rb`）；如果只在归一化后调用
/// [`validate_install_prefix`]，`--prefix //` 会绕过校验直接指向生产根路径。
/// `.` / `..` 组件也会在原始校验中被拒绝。所有入口都先过这个 helper。
fn paths_for_role_validated(
    role: Role,
    raw_prefix: &Path,
    overrides: PathOverrides,
) -> Result<Paths> {
    validate_install_prefix(raw_prefix)?;
    Paths::for_role(role, raw_prefix, overrides)
}

/// 安装锁作用域：dry-run 只读不加锁；父进程已持锁时也无需（且不能）再加锁；
/// 其余流程必须持有全局锁。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InstallLockScope {
    None,
    Global,
}

/// 根据 dry-run 与锁继承标记决定锁作用域。
///
/// `inherited` 必须来自 [`InstallLock::inherited`]（`RUSTBOARD_INSTALL_LOCK_HELD`
/// 精确为 `1`），不能由 CLI 参数控制；dry-run 一律不加锁，即使环境变量被设置。
fn install_lock_scope(dry_run: bool, inherited: bool) -> InstallLockScope {
    if dry_run || inherited {
        InstallLockScope::None
    } else {
        InstallLockScope::Global
    }
}

/// 获取安装全局锁；dry-run 或已继承父进程锁时返回 `None`。
///
/// hub / panel / agent 共用同一份 `install-state.toml`，必须用全局锁串行；
/// 角色锁只串行同一角色，不能防止不同角色并发覆盖 state。锁在读取 state 之前
/// 获取，本地获取的锁由调用方持有到整个函数结束；继承来的锁由父进程持有到本
/// 进程退出。
///
/// 已继承（`RUSTBOARD_INSTALL_LOCK_HELD=1`）时**绝不能**再调用
/// [`InstallLock::acquire_global`]：对同一把锁重复 flock 会失败（自锁），而
/// 父进程的锁已经提供了串行保护。
fn acquire_install_lock(dry_run: bool) -> Result<Option<InstallLock>> {
    match install_lock_scope(dry_run, InstallLock::inherited()) {
        InstallLockScope::None => Ok(None),
        InstallLockScope::Global => InstallLock::acquire_global()
            .map(Some)
            .context("获取全局安装锁失败：另一个安装 / 升级 / 卸载进程正在运行"),
    }
}

/// `tls issue` 单轮失败原因。
#[derive(Debug, Clone, PartialEq, Eq)]
enum AcmeIssueFailure {
    /// 当前二进制没有 `tls` 子命令（Phase C C4 未合入），重试没有意义。
    Unsupported(String),
    /// 网络 / ACME / 配置错误，可重试。
    Failed(String),
}

/// 执行最多 `attempts` 轮签发；`Unsupported` 立即停止（重试也不会出现子命令）。
fn retry_issue<F>(
    attempts: usize,
    backoff: Duration,
    mut issue: F,
) -> (usize, std::result::Result<(), AcmeIssueFailure>)
where
    F: FnMut(usize) -> std::result::Result<(), AcmeIssueFailure>,
{
    debug_assert!(attempts >= 1);
    let mut last = AcmeIssueFailure::Failed("未执行任何签发尝试".to_string());
    for attempt in 1..=attempts {
        match issue(attempt) {
            Ok(()) => return (attempt, Ok(())),
            Err(AcmeIssueFailure::Unsupported(message)) => {
                return (attempt, Err(AcmeIssueFailure::Unsupported(message)))
            }
            Err(err) => {
                if attempt == attempts {
                    return (attempts, Err(err));
                }
                last = err;
                if !backoff.is_zero() {
                    eprintln!("  {backoff:?} 后重试（{attempt}/{attempts} 轮失败）...");
                    thread::sleep(backoff);
                }
            }
        }
    }
    (attempts, Err(last))
}

/// 旧二进制 / C4 未合入时 clap 的报错特征。
fn looks_like_missing_tls_cli(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    lower.contains("unrecognized subcommand")
        || lower.contains("invalid subcommand")
        || (lower.contains("unexpected argument") && lower.contains("tls"))
}

/// 过滤 `tls issue` 输出中的敏感内容：私钥块、key authorization、超长行。
///
/// 安装器不解析 ACME 账户 key / keyAuth；这里做兜底，即使子命令误打印也不会
/// 出现在终端 / 日志里。
fn sanitize_acme_output(text: &str) -> String {
    let mut rendered = String::new();
    let mut in_private_key = false;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("begin") && lower.contains("private key") {
            in_private_key = true;
            rendered.push_str("[已隐藏私钥内容]\n");
            continue;
        }
        if in_private_key {
            if lower.contains("end") && lower.contains("private key") {
                in_private_key = false;
            }
            continue;
        }
        if lower.contains("keyauth") || lower.contains("key authorization") {
            rendered.push_str("[已隐藏 ACME key authorization]\n");
            continue;
        }
        if line.len() > 512 {
            rendered.push_str("[已隐藏超长输出行]\n");
            continue;
        }
        rendered.push_str(line);
        rendered.push('\n');
    }
    if rendered.len() > 16 * 1024 {
        let mut truncated = rendered;
        while !truncated.is_char_boundary(16 * 1024) {
            truncated.pop();
        }
        truncated.push_str("\n[输出已截断]\n");
        return truncated;
    }
    rendered
}

/// 调用当前可执行文件的 `tls issue --config <path>`。
///
/// 不依赖 C4 的 Rust 函数签名：配置先由安装事务写到目标路径，再以子进程方式
/// 调用。子进程有超时，输出经脱敏后再打印。
fn run_tls_issue(config: &Path, timeout: Duration) -> std::result::Result<(), AcmeIssueFailure> {
    let exe = std::env::current_exe()
        .map_err(|err| AcmeIssueFailure::Failed(format!("读取当前可执行文件路径失败: {err}")))?;
    let args = vec![
        OsString::from("tls"),
        OsString::from("issue"),
        OsString::from("--config"),
        config.as_os_str().to_os_string(),
    ];
    let output = tls_diag::run_program_capture(&exe, &args, timeout).ok_or_else(|| {
        AcmeIssueFailure::Failed("无法执行当前 hub 二进制的 tls issue 子命令".to_string())
    })?;
    let combined = sanitize_acme_output(&format!("{}{}", output.stdout, output.stderr));
    if output.timed_out {
        return Err(AcmeIssueFailure::Failed(format!(
            "tls issue 超时（上限 {}s）{combined}",
            timeout.as_secs()
        )));
    }
    if output.success() {
        if !combined.trim().is_empty() {
            println!("{combined}");
        }
        return Ok(());
    }
    if looks_like_missing_tls_cli(&combined) {
        return Err(AcmeIssueFailure::Unsupported(combined));
    }
    Err(AcmeIssueFailure::Failed(combined))
}

/// 校验 `tls issue` 写出的服务端证书：存在、可解析、与私钥配套、未过期。
///
/// C4 未合入 `validate_public_server_cert` 时也能工作：只依赖长期存在的
/// `cert_summary` / `cert_matches_key`，不修改 `rustboard-common::tls`。
fn verify_acme_server_material(data_dir: &Path) -> Result<String> {
    let dir = tls::cert_dir(data_dir);
    let cert_path = dir.join(tls::SERVER_CERT_FILE);
    let key_path = dir.join(tls::SERVER_KEY_FILE);
    let cert_pem = fs::read_to_string(&cert_path)
        .with_context(|| format!("ACME 签发后缺少服务端证书: {}", cert_path.display()))?;
    let key_pem = fs::read_to_string(&key_path)
        .with_context(|| format!("ACME 签发后缺少服务端私钥: {}", key_path.display()))?;
    fsutil::harden(&key_path, 0o600).context("收紧 ACME 服务端私钥权限失败")?;
    if !tls::cert_matches_key(&cert_pem, &key_pem).context("校验 ACME 证书/私钥配对失败")?
    {
        bail!(
            "ACME 签发后的服务端证书与私钥不匹配（{} / {}）；拒绝继续安装",
            cert_path.display(),
            key_path.display()
        );
    }
    let summary = tls::cert_summary(&cert_pem).context("解析 ACME 服务端证书失败")?;
    let now_s = rustboard_common::util::now_ms() / 1_000;
    if summary.not_after <= now_s {
        bail!(
            "ACME 服务端证书已过期（到期 {}）；请检查系统时间后重试",
            tls::format_unix_utc(summary.not_after)
        );
    }
    if summary.not_before > now_s + 60 {
        bail!(
            "ACME 服务端证书尚未生效（notBefore {}）；请检查系统时间",
            tls::format_unix_utc(summary.not_before)
        );
    }
    Ok(format!(
        "CN={}, 到期={}",
        summary.common_name.as_deref().unwrap_or("<无 CN>"),
        tls::format_unix_utc(summary.not_after)
    ))
}

/// 私有 ACME：从 `server.crt` 链尾提取 hub 服务端证书的 CA，写 `agent-ca.pem`。
///
/// `tls.acme_ca_file` 只用于校验 ACME WFE 的 HTTPS 连接（Pebble / 私有 CA），
/// 与 hub 服务端证书链无关；把它传给同机 panel 的 `--hub-ca` 会让 panel 校验证书
/// 失败。公共 ACME（`acme_ca_file` 为空）与 self-signed 返回 `None`。
fn prepare_private_acme_agent_ca(cfg: &HubConfig) -> Result<Option<PathBuf>> {
    if !cfg.tls.mode.is_acme() || cfg.tls.acme_ca_file.trim().is_empty() {
        return Ok(None);
    }
    let dir = tls::cert_dir(&cfg.data_dir);
    let chain_path = dir.join(tls::SERVER_CERT_FILE);
    let chain = fs::read_to_string(&chain_path)
        .with_context(|| format!("读取私有 ACME 服务端证书链失败: {}", chain_path.display()))?;
    // store/启动/热加载路径已经用 validate_acme_chain 校验过；这里只提取链尾，
    // 兼容旧版安装留下的合法链，避免 `hub agent add` 依赖完整订单状态。
    let anchor = tls::last_certificate_pem(&chain)
        .with_context(|| format!("提取私有 ACME 证书链尾 CA 失败: {}", chain_path.display()))?;
    if !tls::certificate_is_ca(&anchor).context("校验私有 ACME 链尾证书失败")? {
        bail!(
            "私有 ACME 服务端证书链尾不是 CA 证书（{}）；拒绝把它作为 agent / panel 的信任锚",
            chain_path.display()
        );
    }
    let dest = dir.join(ACME_AGENT_CA_FILE);
    fsutil::atomic_write(&dest, anchor.as_bytes(), 0o644)
        .with_context(|| format!("写入私有 ACME agent CA 失败: {}", dest.display()))?;
    Ok(Some(dest))
}

/// 安装前服务端证书材料的快照；ACME 成功后若后续安装失败，回滚时恢复旧证书。
///
/// 只保存安装前**成对存在**的 `server.crt` / `server.key`。全新安装（安装前
/// `data_dir` 不存在）没有旧材料，失败时清理本次创建的 `certs` 目录，并仅在
/// `data_dir` 已空时删除它；**绝不**递归删除 `data_dir`，避免误删并发写入或
/// 用户预置的其它文件。安装前已存在 `data_dir` 但没有旧证书时不做任何删除。
struct AcmeCertGuard {
    /// 数据目录（可能由本次安装创建）。
    data_dir_path: PathBuf,
    /// 本次 ACME 写入的证书目录 `<data_dir>/certs`。
    certs_path: PathBuf,
    /// 安装前的 `server.crt` / `server.key`（只有成对存在才记录）。
    old: Option<(Vec<u8>, Vec<u8>)>,
    /// 安装前的 `agent-ca.pem`（私有 ACME 派生信任锚）；`None` 表示原先不存在。
    old_agent_ca: Option<Vec<u8>>,
    /// `issue_acme_with_fallback` 开始前 `data_dir` 是否已存在。
    data_dir_existed_before: bool,
    armed: bool,
}

impl AcmeCertGuard {
    fn capture(data_dir: &Path, data_dir_existed_before: bool) -> Self {
        let certs_path = tls::cert_dir(data_dir);
        let cert = fs::read(certs_path.join(tls::SERVER_CERT_FILE)).ok();
        let key = fs::read(certs_path.join(tls::SERVER_KEY_FILE)).ok();
        let old = match (cert, key) {
            (Some(cert), Some(key)) => Some((cert, key)),
            _ => None,
        };
        // agent-ca.pem 由新证书链尾派生；回滚旧证书时必须一起恢复/删除，
        // 否则面板会信任新链尾而 hub 已回到旧证书，导致连接校验失败。
        let old_agent_ca = fs::read(certs_path.join(ACME_AGENT_CA_FILE)).ok();
        Self {
            data_dir_path: data_dir.to_path_buf(),
            certs_path,
            old,
            old_agent_ca,
            data_dir_existed_before,
            armed: false,
        }
    }

    /// 有旧材料要恢复，或本次是全新安装（失败时需要清理新建目录）。
    fn arm(&mut self) {
        self.armed = self.old.is_some() || !self.data_dir_existed_before;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    /// 恢复安装前的证书 / 私钥；全新安装失败时清理本次创建的证书材料。
    fn restore(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        self.armed = false;
        if let Some((cert, key)) = &self.old {
            fsutil::atomic_write(&self.certs_path.join(tls::SERVER_KEY_FILE), key, 0o600)
                .context("恢复安装前的服务端私钥失败")?;
            fsutil::atomic_write(&self.certs_path.join(tls::SERVER_CERT_FILE), cert, 0o644)
                .context("恢复安装前的服务端证书失败")?;
            let agent_ca = self.certs_path.join(ACME_AGENT_CA_FILE);
            match &self.old_agent_ca {
                Some(bytes) => fsutil::atomic_write(&agent_ca, bytes, 0o644)
                    .context("恢复安装前的 agent CA 失败")?,
                None => match fs::remove_file(&agent_ca) {
                    Ok(()) => {}
                    Err(err) if err.kind() == ErrorKind::NotFound => {}
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("删除本次派生的 agent CA {} 失败", agent_ca.display())
                        })
                    }
                },
            }
            println!("已恢复安装前的服务端证书（ACME 安装未完成）。");
            return Ok(());
        }
        if self.data_dir_existed_before {
            // 安装前已有数据目录：这里没有旧证书可恢复，也绝不删除目录内容。
            return Ok(());
        }
        self.remove_created_material()
    }

    /// 全新安装失败：删除本次创建的 `certs`（CA / account / state / staging 残留），
    /// 再仅当 `data_dir` 为空时用 `remove_dir` 删除它。
    fn remove_created_material(&self) -> Result<()> {
        match fs::symlink_metadata(&self.certs_path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "证书目录 {} 在安装期间变成符号链接，拒绝递归删除（避免删除链接目标）",
                    self.certs_path.display()
                )
            }
            Ok(meta) if meta.is_dir() => {
                fs::remove_dir_all(&self.certs_path).with_context(|| {
                    format!("清理本次创建的证书目录 {} 失败", self.certs_path.display())
                })?
            }
            Ok(_) => bail!("证书路径 {} 不是目录，拒绝清理", self.certs_path.display()),
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("检查本次创建的证书目录 {} 失败", self.certs_path.display())
                })
            }
        }
        match fs::remove_dir(&self.data_dir_path) {
            Ok(()) => {}
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::NotFound | ErrorKind::DirectoryNotEmpty
                ) => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "删除本次创建的空数据目录 {} 失败",
                        self.data_dir_path.display()
                    )
                })
            }
        }
        println!("已清理本次安装创建的证书材料（ACME 安装未完成）。");
        Ok(())
    }
}

/// 恢复 guard，失败只警告（不能掩盖原始安装错误）。
fn restore_acme_guard(guard: &mut AcmeCertGuard) {
    if let Err(err) = guard.restore() {
        eprintln!("警告：恢复/清理 ACME 证书材料失败: {err:#}");
    }
}

/// ACME 签发的最终结果。
enum AcmeOutcome {
    /// 已成功签发；guard 在本次安装失败时恢复旧证书。
    Issued { guard: AcmeCertGuard },
    /// 失败后按 `fallback_to_self_signed` 回退，调用方继续 self-signed 安装。
    FellBack,
}

/// 构造修复后重试命令（只含公开参数，不含 token / key）。
fn acme_retry_command(cfg: &HubConfig) -> String {
    let mut command = format!(
        "rustboard-hub install --force --tls {} --acme-email {}",
        cfg.tls.mode.as_str(),
        shell_arg(&cfg.tls.acme_email)
    );
    command.push_str(&format!(" --acme-challenge {}", cfg.tls.challenge.as_str()));
    for domain in &cfg.tls.domains {
        command.push_str(&format!(" --domain {}", shell_arg(domain)));
    }
    if !cfg.tls.acme_profile.trim().is_empty() {
        command.push_str(&format!(
            " --acme-profile {}",
            shell_arg(&cfg.tls.acme_profile)
        ));
    }
    if !cfg.tls.acme_ca_file.trim().is_empty() {
        command.push_str(&format!(" --acme-ca {}", shell_arg(&cfg.tls.acme_ca_file)));
    }
    if !cfg.tls.acme_directory.trim().is_empty()
        && cfg.tls.acme_directory != rustboard_common::config::DEFAULT_ACME_DIRECTORY
    {
        command.push_str(&format!(
            " --acme-directory {}",
            shell_arg(&cfg.tls.acme_directory)
        ));
    }
    if cfg.admin_tls == AdminTlsMode::Required {
        command.push_str(" --admin-tls required");
    }
    command
}

/// 是否需要先跑一次 LE staging：只有默认 production directory 且
/// `staging_check = true` 时执行；`acme-ip` 默认跳过（shortlived profile 在
/// staging 的支持依 LE 策略，直接以 production 结果为准，避免误判）。
fn staging_directory_for(cfg: &HubConfig) -> Option<&'static str> {
    if !cfg.tls.staging_check {
        return None;
    }
    if cfg.tls.acme_directory != rustboard_common::config::DEFAULT_ACME_DIRECTORY {
        return None;
    }
    if cfg.tls.mode == ServerTlsMode::AcmeIp {
        return None;
    }
    Some(LE_STAGING_DIRECTORY)
}

/// staging 专用的临时 data_dir；Drop 时递归清理（覆盖 panic / 提前返回路径）。
///
/// staging 绝不能复用真实 `data_dir`：ACME `account.json` 会绑定首次使用的
/// directory（staging），写入真实数据目录后 production 的 `ensure_same_directory`
/// 必然拒绝继续，同时 staging 证书还会覆盖 live `server.crt`。
///
/// 临时目录放在真实 `data_dir` 的私有子目录下（`<data_dir>/.acme-staging-<uuid>`，
/// 0700）：不能直接用 `std::env::temp_dir()`，因为 `tls issue` 会执行
/// `HubConfig::validate()` → `validate_private_dir_path(data_dir)`，共享 / sticky
/// 顶层目录或某些 TMPDIR 布局会被拒绝，导致 staging 永远失败。
struct AcmeStagingDir {
    path: PathBuf,
    removed: bool,
}

impl AcmeStagingDir {
    fn create(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join(format!(".acme-staging-{}", uuid::Uuid::new_v4().simple()));
        fsutil::ensure_private_dir(&path, 0o700)
            .with_context(|| format!("创建 ACME staging 临时目录 {} 失败", path.display()))?;
        Ok(Self {
            path,
            removed: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// 立即清理；失败由调用方决定警告还是上报。
    fn cleanup(&mut self) -> Result<()> {
        if self.removed {
            return Ok(());
        }
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {
                self.removed = true;
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                self.removed = true;
                Ok(())
            }
            // 删除失败时保持 removed=false，Drop 还会再试一次；绝不能把
            // 「未清理」误标成已清理（会留下 staging CA/account 私钥）。
            Err(err) => Err(err).with_context(|| {
                format!("删除 ACME staging 临时目录 {} 失败", self.path.display())
            }),
        }
    }
}

impl Drop for AcmeStagingDir {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        if let Err(err) = fs::remove_dir_all(&self.path) {
            if err.kind() != ErrorKind::NotFound {
                eprintln!(
                    "警告：清理 ACME staging 临时目录 {} 失败: {err}",
                    self.path.display()
                );
            }
        }
    }
}

/// staging 配置：`data_dir` 指向独立临时目录，并关闭二次 staging。
///
/// 配置本身可以写真实 `paths.config`（由事务回滚），但 `tls issue` 写出的
/// 证书 / 账户 / 状态必须全部落在临时目录。
fn staging_config(cfg: &HubConfig, staging_dir: &Path, staging_directory: &str) -> HubConfig {
    let mut staging_cfg = cfg.clone();
    staging_cfg.data_dir = staging_dir.to_path_buf();
    staging_cfg.database = sqlite_database(staging_dir);
    staging_cfg.tls.acme_directory = staging_directory.to_string();
    staging_cfg.tls.staging_check = false;
    staging_cfg
}

/// staging 单轮失败：`Issue` 走回退/错误决策，`Fatal` 是本地配置或目录错误。
enum StagingFailure {
    Issue(AcmeIssueFailure),
    Fatal(anyhow::Error),
}

/// 在独立临时目录跑一次 staging 签发；无论成功失败都清理临时目录。
fn run_staging_issue(
    cfg: &HubConfig,
    staging_directory: &str,
    paths: &Paths,
    txn: &mut InstallTxn,
    policy: tls::CertPolicy,
) -> std::result::Result<(), StagingFailure> {
    let mut staging = AcmeStagingDir::create(&cfg.data_dir).map_err(StagingFailure::Fatal)?;
    let staging_cfg = staging_config(cfg, staging.path(), staging_directory);
    // 先准备 staging 自己的客户端 CA（mTLS 材料与 ACME 账户互相独立），再写配置。
    tls::ensure_client_ca(staging.path(), policy)
        .context("准备 ACME staging 临时客户端 CA 失败")
        .map_err(StagingFailure::Fatal)?;
    let staging_text = toml::to_string_pretty(&staging_cfg)
        .context("序列化 ACME staging 配置失败")
        .map_err(StagingFailure::Fatal)?;
    txn.write(&paths.config, staging_text.as_bytes(), 0o600)
        .map_err(StagingFailure::Fatal)?;
    let result = run_tls_issue(&paths.config, ACME_ISSUE_TIMEOUT).map_err(StagingFailure::Issue);
    if let Err(err) = staging.cleanup() {
        eprintln!("警告：{err:#}");
    }
    result
}

/// 已有数据目录的客户端 CA 完整性检查。
///
/// `ensure_client_ca` 在两个 CA 文件都不存在时会**新建** CA；对已有数据目录这是
/// 静默替换信任锚，会让所有已纳管 agent 失联。只有全新安装（`data_dir` 完全
/// 不存在）才允许自动创建；已有目录缺少任一文件都必须拒绝并提示从备份恢复。
///
/// 本函数只读、不创建任何目录；安装器在 ACME 预检（包括可能回退 self-signed
/// 的分支）之前也必须调用它，不能只在 `tls issue` 前才检查。
fn ensure_existing_acme_ca_complete(data_dir: &Path, data_dir_existed_before: bool) -> Result<()> {
    if !data_dir_existed_before {
        return Ok(());
    }
    match fs::symlink_metadata(data_dir) {
        Ok(meta) if meta.file_type().is_symlink() => bail!(
            "已有数据目录 {} 是符号链接，拒绝在其上准备 ACME 证书材料",
            data_dir.display()
        ),
        Ok(meta) if !meta.is_dir() => bail!(
            "已有数据路径 {} 不是目录，拒绝在其上准备 ACME 证书材料",
            data_dir.display()
        ),
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("检查已有数据目录 {} 失败", data_dir.display()))
        }
    }
    let dir = tls::cert_dir(data_dir);
    let ca_cert = dir.join(tls::CA_CERT_FILE);
    let ca_key = dir.join(tls::CA_KEY_FILE);
    let cert_ok = regular_file_exists(&ca_cert, "客户端 CA 证书")?;
    let key_ok = regular_file_exists(&ca_key, "客户端 CA 私钥")?;
    if !cert_ok || !key_ok {
        bail!(
            "已有数据目录缺少客户端 CA，拒绝静默重建；请从备份恢复或显式迁移\
             （{} 与 {} 必须成对存在）",
            ca_cert.display(),
            ca_key.display()
        );
    }
    Ok(())
}

/// ACME 签发前准备客户端 CA：已有数据目录只校验，全新安装才创建。
fn ensure_acme_client_ca(
    data_dir: &Path,
    data_dir_existed_before: bool,
    policy: tls::CertPolicy,
) -> Result<()> {
    ensure_existing_acme_ca_complete(data_dir, data_dir_existed_before)?;
    tls::ensure_client_ca(data_dir, policy).context("准备 ACME 模式下的客户端 CA 失败")
}

/// 把 ACME 失败转成“回退 self-signed”或硬错误，并打印分层诊断与重试命令。
fn handle_acme_failure(
    cfg: &mut HubConfig,
    diag: Option<&Diagnostics>,
    attempts: usize,
    failure: AcmeIssueFailure,
) -> Result<AcmeOutcome> {
    let (message, outcome) = match &failure {
        AcmeIssueFailure::Unsupported(message) => (
            message.clone(),
            StagingOutcome::Unavailable(
                concat!(
                    "当前 hub 二进制没有 `tls issue` 子命令（Phase C C4 尚未合入）；",
                    "安装器无法完成 ACME 签发"
                )
                .to_string(),
            ),
        ),
        AcmeIssueFailure::Failed(message) => (
            message.clone(),
            StagingOutcome::Failed(format!(
                "{attempts} 轮 tls issue 均失败；最后一次输出: {message}"
            )),
        ),
    };
    if !message.trim().is_empty() {
        eprintln!("ACME 失败输出（已脱敏）: {message}");
    }
    if let Some(diag) = diag {
        diag.print(outcome);
    }
    eprintln!("修复后重试命令: {}", acme_retry_command(cfg));

    if cfg.tls.fallback_to_self_signed {
        eprintln!(concat!(
            "警告：ACME 签发失败，按 tls.fallback_to_self_signed=true 回退为自签证书继续安装；",
            "本次不会留下 ACME 模式的配置。自签模式下已纳管 agent 继续使用证书指纹钉扎。"
        ));
        cfg.tls = TlsConfig::default();
        cfg.validate()
            .context("ACME 回退 self-signed 后的配置校验失败")?;
        ensure_admin_tls_supported(cfg)?;
        Ok(AcmeOutcome::FellBack)
    } else {
        bail!(concat!(
            "ACME 签发失败，且 tls.fallback_to_self_signed=false；",
            "安装已中止（配置/证书由事务回滚）。修复网络/端口后可用上面的重试命令重新安装。"
        ))
    }
}

/// ACME 安装：事务内先写配置，再最多 3 轮 `tls issue`；失败按配置回退。
///
/// 端口 / 防火墙 / 云诊断在调用本函数前已完成（任何写盘之前）。本函数只负责
/// 配置落盘（事务内，可回滚）、签发、校验与回退决策。
///
/// 事务边界：`InstallTxn` 只管理配置 / unit / 二进制；`certs/` 下的 CA、ACME
/// 账户/状态与服务端证书由 [`AcmeCertGuard`] 负责。全新安装失败时清理本次创建
/// 的 `certs`，已有安装则恢复旧 `server.crt/key`（账户/状态保留）。
fn issue_acme_with_fallback(
    cfg: &mut HubConfig,
    paths: &Paths,
    txn: &mut InstallTxn,
    diag: Option<&Diagnostics>,
    data_dir_existed_before: bool,
) -> Result<AcmeOutcome> {
    // 客户端 CA 与 ACME 账户是两条独立材料链：先确保 mTLS 用的客户端 CA 可用，
    // 再让 `tls issue` 只负责服务端证书。已有数据目录缺 CA 时绝不静默重建。
    let policy = tls::CertPolicy {
        ca_days: cfg.ca_validity_days,
        server_days: cfg.server_cert_validity_days,
        client_days: cfg.client_cert_validity_days,
    };
    let mut guard = AcmeCertGuard::capture(&cfg.data_dir, data_dir_existed_before);
    guard.arm();
    if let Err(err) = ensure_acme_client_ca(&cfg.data_dir, data_dir_existed_before, policy) {
        restore_acme_guard(&mut guard);
        return Err(err);
    }

    // staging 使用独立临时 data_dir：账户不属于 production directory，证书也不
    // 会写进 live server.crt。staging 失败立即走回退/错误路径，不进入 3 轮 production。
    if let Some(staging_directory) = staging_directory_for(cfg) {
        println!(
            "ACME staging 检查：先向 {staging_directory} 申请一次临时证书（仅验证域名与 80/443 链路）..."
        );
        match run_staging_issue(cfg, staging_directory, paths, txn, policy) {
            Ok(()) => println!("ACME staging 检查通过；继续向 production 申请受信任证书。"),
            Err(StagingFailure::Issue(failure)) => {
                restore_acme_guard(&mut guard);
                return handle_acme_failure(cfg, diag, 1, failure);
            }
            Err(StagingFailure::Fatal(err)) => {
                restore_acme_guard(&mut guard);
                return Err(err);
            }
        }
    }

    // 配置序列化 / 事务写入失败时，staging 已清理；仍先恢复 guard 再返回错误。
    let production = (|| -> Result<(usize, std::result::Result<(), AcmeIssueFailure>)> {
        let config_text = toml::to_string_pretty(cfg).context("序列化 ACME 配置失败")?;
        txn.write(&paths.config, config_text.as_bytes(), 0o600)?;
        let config_path = paths.config.clone();
        Ok(retry_issue(
            ACME_MAX_ATTEMPTS,
            ACME_RETRY_BACKOFF,
            |attempt| {
                println!(
                    "ACME 签发：第 {attempt}/{ACME_MAX_ATTEMPTS} 轮调用 `rustboard-hub tls issue`（production）..."
                );
                match run_tls_issue(&config_path, ACME_ISSUE_TIMEOUT) {
                    Ok(()) => Ok(()),
                    Err(failure) => {
                        if let AcmeIssueFailure::Failed(message) = &failure {
                            eprintln!("  第 {attempt}/{ACME_MAX_ATTEMPTS} 轮失败: {message}");
                        }
                        Err(failure)
                    }
                }
            },
        ))
    })();
    let (attempts, result) = match production {
        Ok(value) => value,
        Err(err) => {
            restore_acme_guard(&mut guard);
            return Err(err);
        }
    };

    match result {
        Ok(()) => match verify_acme_server_material(&cfg.data_dir) {
            Ok(summary) => {
                // 私有 ACME 的 agent/panel 信任锚来自服务端证书链尾；必须在
                // production 材料校验通过后提取，否则会缓存半套/错误证书。
                let agent_ca = match prepare_private_acme_agent_ca(cfg) {
                    Ok(agent_ca) => agent_ca,
                    Err(err) => {
                        restore_acme_guard(&mut guard);
                        return Err(err);
                    }
                };
                println!("ACME 服务端证书已签发并校验通过：{summary}");
                if let Some(path) = agent_ca {
                    println!(
                        "私有 ACME：已从服务端证书链尾提取 agent / panel 信任锚 {}",
                        path.display()
                    );
                }
                if let Some(diag) = diag {
                    diag.print(StagingOutcome::Succeeded);
                }
                Ok(AcmeOutcome::Issued { guard })
            }
            Err(err) => {
                // 校验失败同样不能留下来源不明的新证书。
                restore_acme_guard(&mut guard);
                Err(err)
            }
        },
        Err(failure) => {
            // production 失败：恢复旧服务端材料；全新安装由 guard 清理 certs。
            restore_acme_guard(&mut guard);
            handle_acme_failure(cfg, diag, attempts, failure)
        }
    }
}

/// install 子命令入口。
pub(crate) fn install(args: InstallArgs) -> Result<()> {
    // 离线/ACME 互斥与 ACME 必填参数必须在读状态、写盘、访问网络之前失败。
    let requested_tls = validate_tls_args(&args)?;
    let prefix = args.prefix.clone().unwrap_or_else(|| PathBuf::from("/"));
    check_db_mode(args.db.as_deref())?;
    let retention = match args.retention.as_deref() {
        Some(value) => parse_retention(value)?,
        None => Retention::default(),
    };

    let system = detect_system();
    if args.systemd && !system.systemd {
        bail!("显式指定了 --systemd，但未检测到 systemd（缺少 /run/systemd/system）");
    }
    let manage = if args.no_systemd {
        false
    } else if args.systemd {
        true
    } else {
        prefix == Path::new("/") && system.systemd
    };
    let write_unit = !args.no_systemd;

    let mut paths = paths_for_role_validated(
        Role::Hub,
        &prefix,
        PathOverrides {
            config: args.config.clone(),
            data_dir: args.data_dir.clone(),
            unit_dir: args.unit_dir.clone(),
            bin_dir: None,
        },
    )?;
    // prefix 与受管路径 allowlist 在 dry-run 也执行：只读检查，不产生写入。
    validate_install_paths(&paths)?;
    // P-01 的另一半：`Paths::for_role` 已归一化，dry-run 也必须用原始 prefix
    // 的校验结果；`//` / 尾斜杠 / `.` 组件在 paths_for_role_validated 里已拒绝。
    // systemd 找不到 prefix 内 unit：托管安装必须在写盘和 systemctl 之前拒绝。
    ensure_install_unit_dir(manage, &paths.unit)?;

    if args.offline {
        println!("离线模式：安装过程不做任何网络探测。");
    }

    if args.dry_run {
        // dry-run 不读已有配置；ACME 参数必须配显式 --tls，计划里的证书来源才
        // 不含歧义（否则可能把已有 ACME 配置误显示成 self-signed）。
        if args.tls.is_none() && has_acme_args(&args) {
            bail!(concat!(
                "--dry-run 下使用 ACME 参数必须显式指定 --tls acme-domain 或 --tls acme-ip；",
                "否则无法判断计划中的证书来源"
            ));
        }
        let panel_yes = match args.panel.as_deref() {
            Some(value) => parse_panel(value)?,
            None => args.yes,
        };
        print_install_plan(&args, &paths, manage, write_unit, panel_yes, requested_tls);
        return Ok(());
    }

    require_root()?;
    let prompt = Prompt::new(args.yes);
    if !args.yes {
        prompt.confirm(
            "即将安装 RustBoard Hub（写入系统配置与 systemd unit），继续吗？",
            true,
        )?;
    }
    let panel_yes = match args.panel.as_deref() {
        Some(value) => parse_panel(value)?,
        None => prompt.confirm("同时安装并启动同机面板？", true)?,
    };

    // 非 dry-run 全程持有全局锁：锁在读取 state 之前获取，避免 hub / panel /
    // agent 并发读同一份状态后互相覆盖。锁可能来自父进程：packaging/install.sh
    // 先在写 web 之前 flock `/run/rustboard-install.lock`，设置
    // RUSTBOARD_INSTALL_LOCK_HELD=1 后再启动本命令，并一直持有到本进程退出；
    // 此时 acquire_install_lock 直接复用父进程的锁，不能再 flock 同一把锁。
    // hub 调起的 panel 子进程同样继承该标记并跳过，避免自锁。
    let _lock = acquire_install_lock(false)?;

    let state = InstallState::load(&paths.state)?;
    let existing = state.role(Role::Hub).cloned();
    if let Some(record) = &existing {
        // 重复执行同一安装时允许省略当初的 --config / --data-dir / --unit-dir：
        // 以 state 记录为准，避免把已安装文件误判成“缺失”。
        if args.config.is_none() {
            paths.config = record.config.clone();
        }
        if args.data_dir.is_none() {
            paths.data_dir = record.data_dir.clone();
        }
        if args.unit_dir.is_none() {
            paths.unit = record.unit.clone();
        }
        paths.binary = record.binary.clone();
    }
    // state 记录的路径同样来自磁盘，写入前必须重新过 allowlist（拒绝 prefix 外
    // 路径或 $ / 引号等会污染 unit 的自定义值）。
    validate_install_paths(&paths)?;
    // state 记录的 unit 也可能被伪造/损坏；托管前用最终路径再校验一次。
    ensure_install_unit_dir(manage, &paths.unit)?;

    let config_present = regular_file_exists(&paths.config, "hub 配置")?;
    let manager = ServiceManager::new(unit_parent(&paths)?, manage, false);
    let active = if manage {
        manager.is_active(Role::Hub.unit_name())?
    } else {
        false
    };

    // 进入幂等分支之前，以 systemd 的实际解析结果为准：同名 /etc unit 优先级
    // 高于 /run，只看 paths.unit 是否存在会误判；没有 unit 文件的 transient
    // 服务可能 active，也不能当成“已安装”。
    if manage {
        let fragment = manager.fragment_path(Role::Hub.unit_name())?;
        ensure_install_fragment_matches(fragment.as_deref(), active, &paths.unit)?;
    }

    // 进入幂等分支之前先确认现存 unit 归属：同名外来 unit 可能已被 systemd
    // 加载且处于 active，若只看“文件齐全 + 服务在跑”会把它误判成已安装。
    if write_unit || manage {
        ensure_unit_owned_by_us(Role::Hub, &paths)?;
    }

    if existing.is_some() {
        let missing = missing_install_files(&paths, write_unit || manage)?;
        // `--force` 明确要求重写配置/unit 并（托管时）重启；不能走幂等跳过分支。
        if !args.force && missing.is_empty() && (!manage || active) {
            // 幂等返回 0 之前再确认一次 systemd 仍解析到 paths.unit：预检与
            // 返回之间 unit 可能被替换成同名更高优先级文件。
            if manage {
                manager
                    .ensure_fragment_is(Role::Hub.unit_name(), &paths.unit)
                    .context("hub 已安装但 systemd 解析的 unit 不是安装路径")?;
            }
            if panel_yes && state.role(Role::Panel).is_none() {
                let cfg = load_hub_config_checked(&paths.config)?;
                validate_hub_config(&cfg).context("已有配置校验失败，拒绝补装面板")?;
                ensure_admin_tls_supported(&cfg)?;
                // 旧版本安装的私有 ACME 可能还没有 agent-ca.pem：补装面板前从
                // 现有 server.crt 链尾派生信任锚，避免把 ACME WFE 根当作 hub CA。
                if let Some(path) = prepare_private_acme_agent_ca(&cfg)? {
                    println!("私有 ACME：已刷新 agent / panel 信任锚 {}", path.display());
                }
                install_panel(&args, &paths, &cfg, manage)?;
                println!("RustBoard Hub 已安装；本次只补装了缺失的同机面板。");
            } else {
                if manage {
                    println!(
                        "RustBoard Hub 已安装（配置 / unit / 二进制齐全，服务运行中），本次未做改动。"
                    );
                } else {
                    println!(
                        "RustBoard Hub 已安装（配置 / unit / 二进制齐全，未托管 systemd），本次未做改动。"
                    );
                }
            }
            return Ok(());
        }
        if !args.force {
            if missing.is_empty() {
                bail!("hub 安装文件齐全，但 systemd 服务未运行；请加 --force 重装并重启服务");
            }
            bail!(
                "检测到 hub 安装状态，但以下文件缺失: {}；请加 --force 修复重装",
                missing.join("、")
            );
        }
    } else if config_present && !args.force {
        bail!(
            "配置 {} 已存在但没有安装状态；请执行 `rustboard-hub upgrade --prefix {}` 导入，\
             或加 --force 覆盖",
            paths.config.display(),
            paths.prefix.display()
        );
    }

    // D：显式 `--tls self-signed` 从既有 ACME 切回自签时，旧 server.crt 仍是
    // ACME 证书；prepare_config 看到文件齐全会给 need_certs=false，后续
    // run_install 只 harden 不重签，写出的配置与证书不一致。这里读取旧模式，
    // 强制用既有客户端 CA 重签（CA 缺失则 fail-closed）。
    let previous_tls_mode = if config_present {
        HubConfig::load(&paths.config)
            .ok()
            .map(|previous| previous.tls.mode)
    } else {
        None
    };
    let (mut cfg, mut need_certs) = prepare_config(&args, &paths, retention, config_present)?;
    let switching_acme_to_self = previous_tls_mode.is_some_and(|mode| mode.is_acme())
        && cfg.tls.mode == ServerTlsMode::SelfSigned;
    if switching_acme_to_self {
        // 只有确实存在 ACME 数据目录时才要求既有 CA。ACME 新装失败后 txn 已
        // 回滚 data_dir，但配置文件可能恢复成 ACME 模式；此时重试 self-signed
        // 属于全新安装，应允许创建新 CA。
        if paths.data_dir.exists() {
            tls::load_validated_ca(&paths.data_dir)
                .context("从 ACME 切回 self-signed 需要既有客户端 CA；CA 缺失或损坏，拒绝继续")?;
        }
        need_certs = true;
    }
    // B：--offline 的 CLI 参数检查只覆盖本次显式 ACME；已有配置可能本来就是
    // ACME。必须在任何诊断 / 事务 / 联网之前拒绝，且不得改写配置。
    ensure_offline_not_acme(&args, &cfg)?;
    // 已有配置的 data_dir 是权威值：升级/重装不跟随 flag 默认值漂移。
    paths.data_dir = cfg.data_dir.clone();
    // 配置来自 state/磁盘：admin_tls=required 在 Phase C 用 HTTPS 健康检查支持，
    // 但必须在写盘前确认能推导出 SNI / CA，不能等到启动后误判并回滚。
    ensure_admin_tls_supported(&cfg)?;
    validate_install_paths(&paths)?;
    // ACME 材料（CA / 账户 / 状态 / 证书）不在 InstallTxn 的备份模型里：在诊断与
    // 任何回退路径之前记录 data_dir 是否已存在。只有全新安装才允许自动建 CA。
    let data_dir_existed_before = !path_is_missing(&paths.data_dir, "数据目录")?;
    if cfg.tls.mode.is_acme() {
        // 必须在可能回退 self-signed 的端口预检之前拒绝：否则回退路径会调用
        // ensure_hub_material，在已有数据目录里静默新建 CA，导致所有 agent 失联。
        ensure_existing_acme_ca_complete(&paths.data_dir, data_dir_existed_before)?;
    }
    // L7：需要补证书但数据目录已存在（可能有旧 CA / agent 指纹）时拒绝重建。
    // 显式 ACME→self-signed 是安全的「复用既有 CA 重签 server」，不是重建 CA。
    if !switching_acme_to_self {
        ensure_cert_rebuild_allowed(&paths.data_dir, need_certs)?;
    }
    if !need_certs && (args.advertise.is_some() || !args.sans.is_empty()) {
        println!(
            "提示：沿用已有服务端证书；新增 SAN 需再执行 `rustboard-hub rotate-cert` 才会生效。"
        );
    }

    // ACME 预检：只读端口 / 防火墙 / 云诊断必须在写配置、unit、二进制之前。
    // 挑战端口不可用时按 fallback_to_self_signed 立即回退，不产生任何 ACME 写盘。
    let mut diag: Option<Diagnostics> = None;
    let mut force_self_signed = false;
    if cfg.tls.mode.is_acme() {
        let diagnostics = Diagnostics::collect(args.offline, cfg.tls.mode, cfg.tls.challenge);
        diagnostics.print(StagingOutcome::NotRun);
        if diagnostics.challenge_ready() {
            diag = Some(diagnostics);
        } else if cfg.tls.fallback_to_self_signed {
            eprintln!(concat!(
                "警告：ACME 挑战端口在本机不可用，按 tls.fallback_to_self_signed=true ",
                "回退为自签证书继续安装（尚未写入任何文件）。"
            ));
            cfg.tls = TlsConfig::default();
            cfg.validate()
                .context("ACME 端口预检失败后回退 self-signed 的配置校验失败")?;
            ensure_admin_tls_supported(&cfg)?;
            force_self_signed = true;
        } else {
            bail!(concat!(
                "ACME 挑战端口在本机不可用，且 tls.fallback_to_self_signed=false；",
                "未写入任何文件。请释放 80/443 后重试（见上面的分层诊断）"
            ));
        }
    }

    // 只有新装、或旧面板状态丢失、或本次重新生成了 admin_token 时才重跑面板：
    // 已有配置的 --force 会保留 token，不需要动面板。
    let install_panel = panel_yes
        && (state.role(Role::Panel).is_none()
            || existing.is_none()
            || !config_present
            // 私有 ACME 的 panel 需要 hub_ca=agent-ca.pem；升级/强制安装时重跑
            // panel 安装器，把旧 acme_ca_file 迁移到新的链尾信任锚。
            || (args.force
                && cfg.tls.mode.is_acme()
                && !cfg.tls.acme_ca_file.trim().is_empty()));

    let mut txn = InstallTxn::begin(&paths, false)?;
    // 全新 ACME 安装的 data_dir 必须由事务拥有：后续 run_install 启动 hub 会
    // 写 rustboard.db，guard 只删 certs 时 data_dir 非空，失败重试会被
    // “已有 data_dir 缺 CA”/“证书不完整”卡死。提前登记 OwnedDir，txn.rollback
    // 才能递归清理。
    if cfg.tls.mode.is_acme() && !data_dir_existed_before {
        txn.create_owned_dir(&paths.data_dir, 0o700)?;
    }
    // ACME 先写配置并调用 `tls issue`：成功后继续原事务；失败回退 self-signed
    // 后继续，确保最终落盘的配置与证书来源一致。
    let mut acme_guard: Option<AcmeCertGuard> = None;
    // 端口预检回退在 issue 之前把 cfg 改成 self-signed；此时仍要保护原 ACME
    // 服务端证书，后续任何安装失败都必须能恢复回来。
    if force_self_signed && !cfg.tls.mode.is_acme() && data_dir_existed_before {
        let mut guard = AcmeCertGuard::capture(&paths.data_dir, data_dir_existed_before);
        guard.arm();
        acme_guard = Some(guard);
    }
    if cfg.tls.mode.is_acme() {
        match issue_acme_with_fallback(
            &mut cfg,
            &paths,
            &mut txn,
            diag.as_ref(),
            data_dir_existed_before,
        ) {
            Ok(AcmeOutcome::Issued { guard }) => acme_guard = Some(guard),
            Ok(AcmeOutcome::FellBack) => {
                force_self_signed = true;
                // issue 已在回退时恢复旧证书；重新捕获并保持 armed 到 commit，
                // 防止后续 run_install/健康检查/面板失败留下 self-signed 证书 +
                // 旧 ACME 配置。
                let mut guard = AcmeCertGuard::capture(&paths.data_dir, data_dir_existed_before);
                guard.arm();
                acme_guard = Some(guard);
            }
            Err(err) => {
                // 尚未触碰服务 / unit；回滚配置与本次创建的文件。
                let rollback = txn.rollback();
                return match rollback {
                    Ok(()) => Err(err),
                    Err(rollback_err) => {
                        Err(err.context(format!("ACME 安装失败后回滚失败: {rollback_err:#}")))
                    }
                };
            }
        }
    }
    // 回退后重新计算健康检查计划（self-signed 的 SNI/CA 可能不同）。
    let health = health_check_for(&cfg)?;

    let plan = InstallPlan {
        args: &args,
        paths: &paths,
        cfg: &cfg,
        manager,
        write_unit,
        install_panel,
        need_certs,
        force_self_signed,
        restart: manage && active,
        health,
    };

    let mut service_touched = false;
    match run_install(&plan, &mut txn, &mut service_touched) {
        Ok(()) => {
            txn.commit()?;
            if let Some(mut guard) = acme_guard.take() {
                guard.disarm();
            }
            print_install_success(&plan);
            if requested_tls.is_acme() && !plan.cfg.tls.mode.is_acme() {
                eprintln!(concat!(
                    "注意：本次请求的是 ACME，但签发失败后已回退为 self-signed 安装；",
                    "修复上面的诊断项后，用打印出的重试命令重新安装。"
                ));
            }
            Ok(())
        }
        Err(err) => {
            let rollback = txn.rollback();
            // 事务只恢复 config/unit/binary；ACME 写出的证书/私钥由 guard 恢复。
            if let Some(mut guard) = acme_guard.take() {
                restore_acme_guard(&mut guard);
            }
            if plan.manager.manage {
                if let Err(reload_err) = plan.manager.daemon_reload() {
                    eprintln!("警告：回滚后 systemctl daemon-reload 失败: {reload_err:#}");
                }
            }
            // 原本 active 的旧服务被本次失败安装停掉时，回滚文件后尽力恢复它；
            // 恢复失败只警告，不能掩盖原始安装错误。enable 前必须再次确认
            // systemd 解析到的仍是本安装的 unit：后置 FragmentPath 检查失败时
            // 名字可能已被同名外来 unit 顶替，此时宁可留着手工恢复也不能启用它。
            if rollback.is_ok() && service_touched && plan.restart && plan.manager.manage {
                match plan
                    .manager
                    .ensure_fragment_is(Role::Hub.unit_name(), &plan.paths.unit)
                {
                    Ok(()) => {
                        if let Err(restore_err) = plan.manager.enable_now(Role::Hub.unit_name()) {
                            eprintln!(
                                "警告：回滚后恢复原有 hub 服务失败，请手动 systemctl start {}: {restore_err:#}",
                                Role::Hub.unit_name()
                            );
                        }
                    }
                    Err(verify_err) => {
                        eprintln!("警告：跳过恢复原有 hub 服务，无法确认 unit 归属: {verify_err:#}")
                    }
                }
            }
            match rollback {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(err.context(format!("安装回滚失败: {rollback_err:#}"))),
            }
        }
    }
}

/// 事务内的安装步骤；失败时负责停掉本次实际动过的服务，事务回滚由调用方完成。
///
/// `service_touched` 只在本次安装真正调用 `enable --now`（会修改 enable 状态并
/// 启动/保持服务）后置为 true：失败时只清理自己动过的服务，绝不因为别的失败
/// 把原本未受影响的旧服务停掉。
fn run_install(
    plan: &InstallPlan<'_>,
    txn: &mut InstallTxn,
    service_touched: &mut bool,
) -> Result<()> {
    let manager = &plan.manager;
    let mut touched = false;
    let result = (|| -> Result<()> {
        // 数据目录 0700；只有本次新建时回滚才递归删除（已有数据绝不动）。
        txn.create_owned_dir(&plan.paths.data_dir, 0o700)?;
        let policy = tls::CertPolicy {
            ca_days: plan.cfg.ca_validity_days,
            server_days: plan.cfg.server_cert_validity_days,
            client_days: plan.cfg.client_cert_validity_days,
        };
        if plan.cfg.tls.mode.is_acme() {
            // 服务端证书已由 `tls issue` 写入并校验；这里只确保 mTLS 客户端 CA
            // 存在，并把证书目录/私钥权限收紧。绝不能再调用 ensure_hub_material，
            // 否则会用自签证书覆盖 ACME 证书。
            tls::ensure_client_ca(&plan.paths.data_dir, policy)
                .context("准备 ACME 模式下的客户端 CA 失败")?;
            tls::harden_hub_material(&plan.paths.data_dir).context("收紧已有证书私钥权限失败")?;
        } else if plan.need_certs || plan.force_self_signed {
            tls::ensure_hub_material(&plan.paths.data_dir, &plan.cfg.server_names, policy)
                .context("生成本地自签证书失败")?;
        } else {
            tls::harden_hub_material(&plan.paths.data_dir).context("收紧已有证书私钥权限失败")?;
        }

        let config_text = toml::to_string_pretty(plan.cfg).context("序列化 hub 配置失败")?;
        txn.write(&plan.paths.config, config_text.as_bytes(), 0o600)?;
        if plan.write_unit {
            // 事务写入前再确认一次：预检后到这里之间 unit 可能被替换。
            ensure_unit_owned_by_us(Role::Hub, plan.paths)?;
            let unit = render_unit(Role::Hub, plan.paths).context("渲染 hub systemd unit 失败")?;
            txn.write(&plan.paths.unit, unit.as_bytes(), 0o644)?;
        }
        install_binary(txn, &plan.paths.binary)?;

        if manager.manage {
            manager
                .daemon_reload()
                .context("systemctl daemon-reload 失败")?;
            // 写完 unit + daemon-reload 后必须让 systemd 自己确认 FragmentPath：
            // 同名 /etc unit 优先级更高、transient unit 没有 unit 文件，都可能在
            // 这一步被发现；失败由事务回滚，且此时尚未 enable，不能停旧服务。
            manager
                .ensure_fragment_is(Role::Hub.unit_name(), &plan.paths.unit)
                .context("systemd 未按预期解析 hub unit（疑似同名外来 / 更高优先级 unit）")?;
            touched = true;
            manager
                .enable_now(Role::Hub.unit_name())
                .context("启动 hub 服务失败（enable --now）")?;
            if plan.restart {
                manager
                    .restart(Role::Hub.unit_name())
                    .context("重启 hub 服务失败")?;
            }
            // enable / restart 期间 unit 仍可能被替换；健康检查前再核对一次。
            manager
                .ensure_fragment_is(Role::Hub.unit_name(), &plan.paths.unit)
                .context("启用后 systemd 解析的 hub unit 发生变化")?;
            run_health_check(&plan.health, HEALTH_TIMEOUT)?;
        }

        // state 必须在服务健康之后写入；失败时由事务恢复旧状态。
        let mut state = InstallState::load(&plan.paths.state)?;
        state.upsert(
            Role::Hub,
            RoleState::new(plan.paths, rustboard_common::VERSION, txn.backup_dir()),
        );
        let state_text = toml::to_string_pretty(&state).context("序列化安装状态失败")?;
        txn.write(&plan.paths.state, state_text.as_bytes(), 0o600)?;

        if plan.install_panel {
            install_panel(plan.args, plan.paths, plan.cfg, manager.manage)?;
        }
        Ok(())
    })();

    if result.is_err() && touched {
        // 后置 FragmentPath 检查或健康检查失败时，同名 unit 可能已被更高优先级
        // 文件 / transient unit 顶替；stop/disable 前必须按 FragmentPath 重新
        // 确认归属。无法确认时跳过停止并只警告，绝不按 unit 名字停别人的服务，
        // 也不能用清理警告掩盖原始安装错误。
        match manager.ensure_fragment_is(Role::Hub.unit_name(), &plan.paths.unit) {
            Ok(()) => {
                if let Err(stop_err) = manager.stop_disable(Role::Hub.unit_name()) {
                    eprintln!("警告：回滚前停止 hub 服务失败: {stop_err:#}");
                }
            }
            Err(verify_err) => {
                eprintln!("警告：跳过停止，无法确认 unit 归属: {verify_err:#}");
            }
        }
    }
    *service_touched = touched;
    result
}

/// 复制当前可执行文件到安装路径；源与目标 canonical path 相同时跳过。
fn install_binary(txn: &mut InstallTxn, dest: &Path) -> Result<()> {
    let source = std::env::current_exe()
        .context("读取当前可执行文件路径失败")?
        .canonicalize()
        .context("解析当前可执行文件真实路径失败")?;

    match fs::symlink_metadata(dest) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("目标二进制 {} 是符号链接，拒绝覆盖", dest.display())
        }
        Ok(meta) if !meta.is_file() => {
            bail!("目标二进制 {} 不是普通文件，拒绝覆盖", dest.display())
        }
        Ok(_) => {
            if source
                == dest
                    .canonicalize()
                    .with_context(|| format!("解析目标二进制 {} 真实路径失败", dest.display()))?
            {
                println!("当前可执行文件已是安装目标，跳过二进制复制。");
                return Ok(());
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("检查目标二进制 {} 失败", dest.display()))
        }
    }

    txn.copy_file(&source, dest, 0o755)
        .with_context(|| format!("安装 hub 二进制到 {} 失败", dest.display()))
}

/// 同机面板连接 hub 管理 API 的地址与信任来源。
#[derive(Debug, Clone, PartialEq, Eq)]
struct PanelEndpoint {
    hub_url: String,
    /// 自签 / 私有 ACME 时传给 `--hub-ca`；公共 ACME 用系统根，不传。
    hub_ca: Option<PathBuf>,
}

/// 根据 hub 的 admin TLS 模式选择同机 panel 的连接方式。
///
/// - `off`：保持 v0.4 行为，回环明文 `http://127.0.0.1:<port>`；
/// - `required`：`https://<SAN 覆盖的主机名>:<port>`，自签 / 私有 ACME 附
///   `--hub-ca`。公共 ACME 证书用系统根，传自签 CA 反而会校验失败，因此不传。
fn panel_endpoint(cfg: &HubConfig) -> Result<PanelEndpoint> {
    let admin_port = port_of(&cfg.admin_listen)
        .ok_or_else(|| anyhow!("无法从 admin_listen 解析端口: {}", cfg.admin_listen))?;
    if admin_port == 0 {
        bail!("管理 API 端口为 0，拒绝安装面板");
    }
    match cfg.admin_tls {
        AdminTlsMode::Off => Ok(PanelEndpoint {
            hub_url: format!("http://127.0.0.1:{admin_port}"),
            hub_ca: None,
        }),
        AdminTlsMode::Required => {
            let health = health_check_for(cfg).context("同机面板无法确定 hub 的 HTTPS 地址")?;
            let HealthCheck::Https {
                server_name, ca, ..
            } = health
            else {
                unreachable!("admin_tls=required 规划出的健康检查一定是 HTTPS")
            };
            let host = if server_name.contains(':') {
                format!("[{server_name}]")
            } else {
                server_name
            };
            let hub_ca = match ca {
                HealthCa::PemFile(path) => Some(path),
                HealthCa::SystemRoots => None,
            };
            Ok(PanelEndpoint {
                hub_url: format!("https://{host}:{admin_port}"),
                hub_ca,
            })
        }
    }
}

/// 同机面板安装：token 走 0600 临时文件，参数用数组传递，stdout 直接透传。
fn install_panel(args: &InstallArgs, paths: &Paths, cfg: &HubConfig, manage: bool) -> Result<()> {
    // 先确认能从配置推导出 HTTPS 健康检查 / panel 连接目标；不支持的组合在写盘前失败。
    ensure_admin_tls_supported(cfg).context("同机面板的 hub TLS 配置不可用")?;

    let current = std::env::current_exe()
        .context("读取当前可执行文件路径失败")?
        .canonicalize()
        .context("解析当前可执行文件真实路径失败")?;
    let dir = current
        .parent()
        .ok_or_else(|| anyhow!("当前可执行文件没有父目录"))?;
    let panel_bin = dir.join(Role::Panel.binary_name());
    let panel_meta = fs::symlink_metadata(&panel_bin).with_context(|| {
        format!(
            "找不到同机面板二进制 {}；请加 --panel no 跳过面板安装",
            panel_bin.display()
        )
    })?;
    if !panel_meta.is_file() && !panel_meta.file_type().is_symlink() {
        bail!(
            "同机面板路径 {} 不是可执行文件；请加 --panel no 跳过面板安装",
            panel_bin.display()
        );
    }

    let endpoint = panel_endpoint(cfg)?;

    let temp = TempTokenFile::create(&paths.prefix, &cfg.admin_token)?;
    let panel_config = paths
        .prefix
        .join("etc/rustboard")
        .join(Role::Panel.config_name());
    let force_panel = args.force || panel_config.is_file();

    let mut command = Command::new(&panel_bin);
    command
        .args(["install", "--yes"])
        .arg("--prefix")
        .arg(&paths.prefix)
        .arg("--hub-url")
        .arg(&endpoint.hub_url)
        .arg("--hub-token-file")
        .arg(temp.path());
    if let Some(hub_ca) = &endpoint.hub_ca {
        // C7 的 panel 安装器支持 --hub-ca；未合入时会以未知参数失败，错误里给出
        // `--panel no` 的退路，绝不静默降级成不校验证书。
        command.arg("--hub-ca").arg(hub_ca);
    }
    if let Some(static_dir) = &args.panel_static_dir {
        command.arg("--static-dir").arg(static_dir);
    }
    if force_panel {
        command.arg("--force");
    }
    if manage {
        let unit_dir = unit_parent(paths)?;
        command.arg("--systemd").arg("--unit-dir").arg(unit_dir);
    } else if args.no_systemd {
        command.arg("--no-systemd");
    }
    // hub 持有全局锁直到整个安装（含面板子进程）结束；panel 必须跳过重复加锁，
    // 否则 open + flock 同一把锁会自锁。若 hub 自身也是 packaging/install.sh 的
    // 子进程，则锁由 wrapper 持有到 hub 退出（见 install 入口注释）。该变量只是
    // 父子进程约定，不是安全边界。
    command.env("RUSTBOARD_INSTALL_LOCK_HELD", "1");
    command.stdin(Stdio::null());

    println!(
        "正在安装同机面板（hub={}，证书校验={}）...",
        endpoint.hub_url,
        if cfg.admin_tls == AdminTlsMode::Off {
            "HTTP（回环）"
        } else if endpoint.hub_ca.is_some() {
            "hub CA"
        } else {
            "系统根"
        }
    );
    let status = command
        .status()
        .with_context(|| format!("执行面板安装失败: {}", panel_bin.display()))?;
    if !status.success() {
        if cfg.admin_tls == AdminTlsMode::Required {
            bail!(concat!(
                "同机面板安装失败；hub 安装将回滚。",
                "若 panel 尚未支持 --hub-ca（Phase C C7），请加 --panel no 重试，",
                "或先升级 panel 再重新安装"
            ));
        }
        bail!("同机面板安装失败（退出状态 {status}）；hub 安装将回滚");
    }
    println!("同机面板安装完成。");
    Ok(())
}

/// panel 用的 0600 临时 token 文件；离开作用域即删除。
struct TempTokenFile {
    path: PathBuf,
}

impl TempTokenFile {
    fn create(prefix: &Path, token: &str) -> Result<Self> {
        if token.trim().is_empty() {
            bail!("admin_token 为空，拒绝安装面板");
        }
        let dir = prefix.join("var/lib/rustboard");
        fsutil::ensure_private_dir(&dir, 0o700)
            .with_context(|| format!("创建面板 token 临时目录 {} 失败", dir.display()))?;
        // 清理上次安装异常退出遗留的 token 临时文件，避免 0600 secret 长期滞留。
        cleanup_stale_token_files(&dir);
        let path = dir.join(format!(
            ".hub-admin-token.{}",
            uuid::Uuid::new_v4().simple()
        ));
        fsutil::atomic_write(&path, token.as_bytes(), 0o600)
            .with_context(|| format!("写入面板 token 临时文件 {} 失败", path.display()))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

/// 清理 `<prefix>/var/lib/rustboard/.hub-admin-token.*` 残留文件。
///
/// 只删除：普通文件（非符号链接 / 目录）、属主为当前 euid、权限正好 0600。
/// `ensure_private_dir` 已确认该目录属于当前 euid，因此用目录属主作为 euid
/// 的可靠代理；其他条目一律跳过。失败只警告，不读取、不打印 token 内容。
fn cleanup_stale_token_files(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let expected_uid = match fs::symlink_metadata(dir) {
            Ok(meta) => meta.uid(),
            Err(err) => {
                eprintln!(
                    "警告：读取面板 token 临时目录 {} 失败: {err}",
                    dir.display()
                );
                return;
            }
        };
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) => {
                eprintln!(
                    "警告：扫描面板 token 临时目录 {} 失败: {err}",
                    dir.display()
                );
                return;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    eprintln!(
                        "警告：遍历面板 token 临时目录 {} 失败: {err}",
                        dir.display()
                    );
                    continue;
                }
            };
            let file_name = entry.file_name();
            let Some(name) = file_name.to_str() else {
                continue;
            };
            if !name.starts_with(".hub-admin-token.") {
                continue;
            }
            let path = entry.path();
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(err) => {
                    eprintln!(
                        "警告：检查残留面板 token 临时文件 {} 失败: {err}",
                        path.display()
                    );
                    continue;
                }
            };
            if meta.file_type().is_symlink() || !meta.is_file() {
                continue;
            }
            if meta.uid() != expected_uid || meta.mode() & 0o777 != 0o600 {
                continue;
            }
            if let Err(err) = fs::remove_file(&path) {
                eprintln!(
                    "警告：删除残留面板 token 临时文件 {} 失败: {err}",
                    path.display()
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

impl Drop for TempTokenFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// 打印安装计划（dry-run）。
fn print_install_plan(
    args: &InstallArgs,
    paths: &Paths,
    manage: bool,
    write_unit: bool,
    panel_yes: bool,
    requested_tls: ServerTlsMode,
) {
    println!("RustBoard Hub 安装计划（--dry-run：不写文件、不调用 systemctl、不联网）");
    println!("  安装前缀: {}", paths.prefix.display());
    println!("  配置: {}", paths.config.display());
    println!("  数据目录: {}", paths.data_dir.display());
    println!("  二进制: {}", paths.binary.display());
    if write_unit {
        println!("  unit: {}", paths.unit.display());
    } else {
        println!("  unit: 不写入（--no-systemd）");
    }
    println!(
        "  systemd: {}",
        if manage {
            "daemon-reload → enable --now → 等待 /healthz"
        } else if write_unit {
            "只写 unit，不托管"
        } else {
            "不写 unit、不调用 systemctl"
        }
    );
    println!(
        "  TLS: {}（管理 API: {}）",
        requested_tls.as_str(),
        match args.tls_options.admin_tls.as_deref() {
            Some("required") => "HTTPS",
            _ => "HTTP（仅回环）",
        }
    );
    if requested_tls.is_acme() {
        println!(
            "  ACME: 写 unit 前先做 80/443/防火墙/云只读诊断，再调用 `tls issue` \
             （staging / production 由 C4 CLI 负责）；最多 {ACME_MAX_ATTEMPTS} 轮，\
             失败按 tls.fallback_to_self_signed 回退"
        );
        println!("  ACME 需要：--acme-email / --domain；不会自动修改防火墙或安全组");
    }
    if panel_yes {
        println!("  同机面板: 将调用同目录的 {}", Role::Panel.binary_name());
        if let Some(dir) = &args.panel_static_dir {
            println!("  面板静态目录: {}", dir.display());
        }
    } else {
        println!("  同机面板: 跳过（--panel no）");
    }
    if args.force {
        println!("  --force: 覆盖已有配置 / unit 并重启（保留 admin_token、data_dir、证书）");
    }
}

/// 打印安装成功摘要；不输出 token。
fn print_install_success(plan: &InstallPlan<'_>) {
    println!();
    println!("RustBoard Hub 安装完成。");
    println!("  配置: {}", plan.paths.config.display());
    println!("  数据目录: {}", plan.paths.data_dir.display());
    println!("  agent 接入: {}", plan.cfg.agent_listen);
    println!("  管理 API: {}", plan.health.display_url());
    println!("  服务端证书来源: {}", plan.cfg.tls.mode.as_str());
    if plan.cfg.tls.mode.is_acme() {
        println!("  ACME 证书标识: {}", plan.cfg.tls.domains.join(", "));
        println!("  agent 信任: --tls-mode system-roots（公共 ACME）或 custom-ca（私有 ACME）");
    } else {
        println!("  agent 信任: 证书指纹钉扎（self-signed 默认）");
    }
    if plan.manager.manage {
        println!("  systemd: 已 enable --now，/healthz 健康检查通过");
    } else if plan.write_unit {
        println!("  systemd: unit 已写入但未托管（非根 prefix 默认；如需启动请手工 enable）");
    } else {
        println!("  systemd: 未写入 unit（--no-systemd）");
    }
    println!("  管理 token: 已写入 0600 配置文件（不在此输出）");
    if plan.install_panel {
        println!("  同机面板: 已安装");
    }
    println!(
        "  纳管 agent: rustboard-hub agent add --config {} --name <name>",
        shell_arg(&plan.paths.config.display().to_string())
    );
}

/// upgrade 子命令入口：只补齐 unit / binary / state，不重写 config / cert / data。
pub(crate) fn upgrade(args: UpgradeArgs) -> Result<()> {
    let prefix = args.prefix.clone().unwrap_or_else(|| PathBuf::from("/"));
    // P-01：原始 CLI prefix 先过 allowlist，再交给 Paths::for_role 归一化。
    let mut paths = paths_for_role_validated(
        Role::Hub,
        &prefix,
        PathOverrides {
            config: args.config.clone(),
            data_dir: None,
            unit_dir: args.unit_dir.clone(),
            bin_dir: None,
        },
    )?;

    // 非 dry-run 在读取 state 之前拿全局锁，避免与并发安装/卸载交错；dry-run
    // 只读，不加锁也不写文件。
    if !args.dry_run {
        require_root()?;
    }
    let _lock = acquire_install_lock(args.dry_run)?;

    // 已有安装状态时优先沿用记录中的 config / unit / binary：否则在
    // `install --unit-dir /run/systemd/system` 之后直接跑 `upgrade --prefix P`
    // 会把新 unit 写到 prefix 下，留下旧 unit 继续运行旧二进制。
    let mut state = InstallState::load(&paths.state)?;
    let record = state.role(Role::Hub).cloned();
    if let Some(record) = &record {
        if args.config.is_none() {
            paths.config = record.config.clone();
        }
        if args.unit_dir.is_none() {
            paths.unit = record.unit.clone();
        }
        paths.binary = record.binary.clone();
    }
    validate_install_paths(&paths)?;

    if !regular_file_exists(&paths.config, "hub 配置")? {
        bail!(
            "hub 配置不存在: {}；upgrade 需要已有配置（先执行 install 或 init）",
            paths.config.display()
        );
    }
    // upgrade --dry-run 必须零写入：HubConfig::load 底层会 harden 配置为 0600，
    // 不能用它读 0644 旧配置；dry-run 改用纯只读的 read_to_string + toml。
    let cfg = if args.dry_run {
        load_hub_config_read_only(&paths.config)?
    } else {
        load_hub_config_checked(&paths.config)?
    };
    validate_hub_config(&cfg).context("升级配置校验失败")?;
    paths.data_dir = cfg.data_dir.clone();
    validate_install_paths(&paths)?;

    let missing = missing_cert_files(&paths.data_dir)?;
    if !missing.is_empty() {
        bail!(
            "证书材料不完整（缺失 {}）；请先从备份恢复再执行 upgrade",
            missing.join("、")
        );
    }

    // 原安装使用 `--no-systemd` 时 state 会记录 unit 路径但没有 unit 文件：
    // 未显式 `--unit-dir` 时不凭空写 unit（避免把 no-systemd 安装改成托管）。
    // legacy 无 state 的旧手工配置仍按默认路径补齐 unit（e2e 8.x 依赖）。
    let write_unit =
        upgrade_should_write_unit(record.as_ref(), args.unit_dir.is_some(), &paths.unit)?;
    if write_unit {
        ensure_unit_owned_by_us(Role::Hub, &paths)?;
    }

    if args.dry_run {
        println!("RustBoard Hub 升级计划（--dry-run：不写文件、不调用 systemctl）");
        println!("  配置（不改动）: {}", paths.config.display());
        println!("  数据目录（不改动）: {}", paths.data_dir.display());
        if write_unit {
            println!("  将写入 unit: {}", paths.unit.display());
        } else {
            println!(
                "  原安装未写入 systemd unit（--no-systemd），本次不写 unit: {}",
                paths.unit.display()
            );
        }
        println!("  将写入二进制: {}", paths.binary.display());
        println!("  将更新安装状态: {}", paths.state.display());
        println!("  不重写配置 / 证书 / 数据，不启动 systemd 服务");
        return Ok(());
    }

    let reload = write_unit && should_daemon_reload(&paths.unit);
    let manager = ServiceManager::new(unit_parent(&paths)?, reload, false);
    let mut txn = InstallTxn::begin(&paths, false)?;
    let result = (|| -> Result<()> {
        if write_unit {
            // 事务写入前再确认一次 unit 归属，拒绝覆盖外来 unit。
            ensure_unit_owned_by_us(Role::Hub, &paths)?;
            let unit = render_unit(Role::Hub, &paths).context("渲染 hub systemd unit 失败")?;
            txn.write(&paths.unit, unit.as_bytes(), 0o644)?;
        }
        install_binary(&mut txn, &paths.binary)?;
        state.upsert(
            Role::Hub,
            RoleState::new(&paths, rustboard_common::VERSION, txn.backup_dir()),
        );
        let state_text = toml::to_string_pretty(&state).context("序列化安装状态失败")?;
        txn.write(&paths.state, state_text.as_bytes(), 0o600)?;
        if reload {
            manager
                .daemon_reload()
                .context("systemctl daemon-reload 失败")?;
            // upgrade 不 enable / 不重启服务；但 unit 写在真实 systemd 目录时，
            // daemon-reload 后必须确认 systemd 确实解析到这个文件，避免同名
            // /etc unit 优先级更高、升级后在重启时仍加载旧 unit。
            manager
                .ensure_fragment_is(Role::Hub.unit_name(), &paths.unit)
                .context("systemd 未按预期解析 hub unit（疑似同名外来 / 更高优先级 unit）")?;
        }
        Ok(())
    })();
    if let Err(err) = result {
        let rollback = txn.rollback();
        if reload {
            if let Err(reload_err) = manager.daemon_reload() {
                eprintln!("警告：升级回滚后 systemctl daemon-reload 失败: {reload_err:#}");
            }
        }
        return match rollback {
            Ok(()) => Err(err),
            Err(rollback_err) => Err(err.context(format!("升级回滚失败: {rollback_err:#}"))),
        };
    }
    txn.commit()?;

    println!("RustBoard Hub 升级完成。");
    println!("  配置（未改动）: {}", paths.config.display());
    println!("  数据目录（未改动）: {}", paths.data_dir.display());
    if write_unit {
        println!("  已更新 unit: {}", paths.unit.display());
    } else {
        println!(
            "  未写 unit（原安装为 --no-systemd）: {}",
            paths.unit.display()
        );
    }
    println!("  已更新二进制: {}", paths.binary.display());
    println!("  已更新安装状态: {}", paths.state.display());
    println!("  未重写配置 / 证书 / 数据；本次未启动 systemd 服务。");
    if reload {
        println!("  已执行 systemctl daemon-reload；如服务在运行，请手动 restart 以加载新二进制。");
    }
    Ok(())
}

/// upgrade 是否应写入 unit。
///
/// - 有 state 记录、未显式 `--unit-dir`、且记录的 unit 文件不存在：视为原安装
///   使用了 `--no-systemd`，不凭空补 unit；
/// - legacy 无 state（旧手工 `hub init`）或显式 `--unit-dir`：按记录/flag 写入；
/// - unit 存在时无论哪种情况都返回 true，后续归属校验会拒绝外来 unit。
fn upgrade_should_write_unit(
    record: Option<&RoleState>,
    explicit_unit_dir: bool,
    unit: &Path,
) -> Result<bool> {
    if record.is_none() || explicit_unit_dir {
        return Ok(true);
    }
    Ok(!path_is_missing(unit, "已记录的 systemd unit")?)
}

/// unit 是否位于 systemd 会读取的目录（决定是否调用 systemctl）。
fn should_daemon_reload(unit: &Path) -> bool {
    unit.parent().is_some_and(is_systemd_unit_dir) && detect_system().systemd
}

/// 卸载预检结果：所有路径都在真正停服务 / 删除之前完成校验。
#[derive(Debug)]
struct UninstallTargets {
    config: PathBuf,
    data_dir: PathBuf,
    unit: PathBuf,
    binary: PathBuf,
    unit_dir: PathBuf,
    /// unit 文件存在且归属校验通过、且位于 systemd unit 目录时才允许 stop/disable。
    manage_service: bool,
    purge_config: bool,
    purge_data: bool,
}

/// 卸载整体预检：路径 allowlist、目标类型、unit 归属、数据目录安全性。
///
/// 任何一项不通过都必须在调用 systemctl 或删除任何文件之前返回错误。`--force`
/// 不参与卸载，因此外来 unit、符号链接、目录、越界路径一律硬失败。
fn preflight_uninstall(
    args: &UninstallArgs,
    prefix: &Path,
    paths: &Paths,
    record: Option<&RoleState>,
) -> Result<UninstallTargets> {
    // 优先 state 记录：e2e 安装时 unit 在 /run/systemd/system，卸载不传 --unit-dir
    // 也必须能停掉并删除。显式 flag 仍然优先于 state。
    let config = if args.config.is_some() {
        paths.config.clone()
    } else {
        record
            .map(|record| record.config.clone())
            .unwrap_or_else(|| paths.config.clone())
    };
    let unit = if args.unit_dir.is_some() {
        paths.unit.clone()
    } else {
        record
            .map(|record| record.unit.clone())
            .unwrap_or_else(|| paths.unit.clone())
    };
    let binary = record
        .map(|record| record.binary.clone())
        .unwrap_or_else(|| paths.binary.clone());
    let data_dir = record
        .map(|record| record.data_dir.clone())
        .unwrap_or_else(|| paths.data_dir.clone());
    let unit_dir = unit
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("unit 路径缺少父目录: {}", unit.display()))?;

    // unit_is_ours 的 ExecStart 必须用“state 记录里实际安装的路径”渲染，
    // 不能用可能被 CLI flag 覆盖过的默认 paths。
    let mut record_paths = paths.clone();
    record_paths.config = config.clone();
    record_paths.data_dir = data_dir.clone();
    record_paths.unit = unit.clone();
    record_paths.binary = binary.clone();

    // P-04：即使没有 --purge，state 记录的 config / data 也必须先过 allowlist
    // 与字符校验。否则伪造 state 可以把非 purge 的卸载引向任意系统路径（例如
    // 让后续 `regular_file_exists` / 提示信息接触不该接触的位置）。真正执行
    // 存在性、递归删除与 state-inside 检查仍只在 --purge 时进行。
    for (path, label) in [
        (&config, "配置路径"),
        (&data_dir, "数据目录"),
        (&unit, "unit 路径"),
        (&binary, "hub 二进制路径"),
    ] {
        reject_managed_path_chars(path, label)?;
    }
    validate_managed_path(Role::Hub, prefix, &config, ManagedPathKind::Config)
        .context("配置路径不在允许卸载的范围")?;
    validate_managed_path(Role::Hub, prefix, &data_dir, ManagedPathKind::Data)
        .context("数据目录不在允许卸载的范围")?;
    validate_managed_path(Role::Hub, prefix, &unit, ManagedPathKind::Unit)
        .context("unit 路径不在允许卸载的范围")?;
    validate_managed_path(Role::Hub, prefix, &binary, ManagedPathKind::Binary)
        .context("hub 二进制路径不在允许卸载的范围")?;

    // unit 存在时必须是我们为当前 prefix 渲染的：不是则报错，且不 stop/delete。
    ensure_unit_owned_by_us(Role::Hub, &record_paths)?;
    let unit_present = !path_is_missing(&unit, "systemd unit")?;

    // binary / config 存在时必须是普通文件（符号链接、目录直接拒绝）。
    regular_file_exists(&binary, "hub 二进制")?;
    let config_present = regular_file_exists(&config, "hub 配置")?;

    // P-04：data 存在时先校验类型（非符号链接、目录），与是否 --purge 无关；
    // 递归删除的 scope / state-inside 检查仍由 check_purge_data_dir 负责。
    ensure_data_dir_is_directory(&data_dir)?;
    let purge_config = args.purge && config_present;
    let purge_data = if args.purge {
        check_purge_data_dir(&data_dir, &paths.state)?
    } else {
        false
    };

    // 以 systemd 实际解析的 FragmentPath 为准，而不是只看 unit 文件是否存在：
    // - unit 文件存在且 fragment 指向别的文件：同名外来 / 更高优先级 unit，
    //   直接报错，不 stop、不删；
    // - fragment 为空（unit 不存在 / 未加载 / transient）：绝不 stop，只删 state
    //   记录的这个 unit 文件；
    // - 只有 fragment == unit 才允许 stop / disable。
    // dry-run 保持“不调用 systemctl”的约定：只打印计划；真正卸载在删除任何
    // 文件之前查询 FragmentPath。unit 在 prefix 内时 systemd 不会读取它，查询
    // 只会命中宿主的同名外来 unit，因此直接按“只删自己的文件”处理。
    let systemd_manage = detect_system().systemd && is_systemd_unit_dir(&unit_dir);
    let fragment = if unit_present && !args.dry_run && systemd_manage {
        let manager = ServiceManager::new(unit_dir.clone(), true, false);
        manager.fragment_path(Role::Hub.unit_name())?
    } else {
        None
    };
    let unit_action = classify_uninstall_unit(unit_present, fragment.as_deref(), &unit);
    if let UninstallUnitAction::RefuseForeign(path) = &unit_action {
        bail!(
            "systemd 实际解析的 hub unit 是 {}，不是 state 记录的 {}；同名外来或更高优先级 unit，拒绝停止/卸载",
            path.display(),
            unit.display()
        );
    }
    // 双重条件：fragment 必须是这个文件，且目录必须是 systemd 会读取的目录。
    let manage_service = unit_action == UninstallUnitAction::StopAndRemove && systemd_manage;

    Ok(UninstallTargets {
        config,
        data_dir,
        unit,
        binary,
        unit_dir,
        manage_service,
        purge_config,
        purge_data,
    })
}

/// 数据目录存在时必须是真实目录；非 --purge 卸载也要做这一步。
fn ensure_data_dir_is_directory(data_dir: &Path) -> Result<bool> {
    let meta = match fs::symlink_metadata(data_dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(err).with_context(|| format!("检查数据目录 {} 失败", data_dir.display()))
        }
    };
    if meta.file_type().is_symlink() {
        bail!("数据目录 {} 是符号链接，拒绝卸载", data_dir.display());
    }
    if !meta.is_dir() {
        bail!("数据目录 {} 不是目录，拒绝卸载", data_dir.display());
    }
    Ok(true)
}

/// 检查 `--purge` 的数据目录：存在时必须是目录、非符号链接，且不包含 install-state。
fn check_purge_data_dir(data_dir: &Path, state_path: &Path) -> Result<bool> {
    if !ensure_data_dir_is_directory(data_dir)? {
        return Ok(false);
    }
    let canonical = data_dir
        .canonicalize()
        .with_context(|| format!("解析数据目录 {} 失败", data_dir.display()))?;
    let state_inside = state_path
        .canonicalize()
        .map(|state| state.starts_with(&canonical))
        .unwrap_or(false);
    if state_inside {
        bail!(
            "数据目录 {} 包含安装状态 {}，拒绝 --purge 删除",
            data_dir.display(),
            state_path.display()
        );
    }
    Ok(true)
}

/// 删除空的安装状态文件（roles 为空时必须删文件，不能留空 state）。
fn remove_state_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("安装状态 {} 是符号链接，拒绝删除", path.display())
        }
        Ok(meta) if !meta.is_file() => {
            bail!("安装状态 {} 不是普通文件，拒绝删除", path.display())
        }
        Ok(_) => {
            fs::remove_file(path).with_context(|| format!("删除安装状态 {} 失败", path.display()))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("检查安装状态 {} 失败", path.display())),
    }
}

/// uninstall 子命令入口。
pub(crate) fn uninstall(args: UninstallArgs) -> Result<()> {
    let prefix = args.prefix.clone().unwrap_or_else(|| PathBuf::from("/"));
    // P-01：原始 CLI prefix 先过 allowlist，再交给 Paths::for_role 归一化。
    let paths = paths_for_role_validated(
        Role::Hub,
        &prefix,
        PathOverrides {
            config: args.config.clone(),
            data_dir: None,
            unit_dir: args.unit_dir.clone(),
            bin_dir: None,
        },
    )?;

    // 非 dry-run：先拿全局锁再读 state；dry-run 只读，不加锁也不产生写入。
    if !args.dry_run {
        require_root()?;
    }
    let _lock = acquire_install_lock(args.dry_run)?;

    let mut state = InstallState::load(&paths.state)?;
    let record = state.role(Role::Hub).cloned();
    let targets = preflight_uninstall(&args, &prefix, &paths, record.as_ref())?;

    if args.dry_run {
        print_uninstall_plan(&args, &paths, &targets);
        return Ok(());
    }

    if args.purge && !args.yes {
        let prompt = Prompt::new(false);
        let confirmed = prompt.confirm(
            &format!(
                "--purge 将永久删除配置 {} 与数据目录 {}，确认继续吗？",
                targets.config.display(),
                targets.data_dir.display()
            ),
            false,
        )?;
        if !confirmed {
            println!("已取消卸载。");
            return Ok(());
        }
    }

    // 预检已保证 unit 文件存在且是 ours；但预检与真正 stop 之间隔着 --purge
    // 确认（prompt），期间 unit 可能被替换。执行前必须即时重新核对 FragmentPath；
    // 确认不了就直接返回错误——此时尚未删除任何文件，绝不 stop/disable。
    if targets.manage_service {
        let manager = ServiceManager::new(targets.unit_dir.clone(), true, false);
        manager
            .ensure_fragment_is(Role::Hub.unit_name(), &targets.unit)
            .context("停止前 systemd 解析的 hub unit 已变化；未 stop/disable，也未删除任何文件")?;
        // unit 归属确认后才 disable；disable 失败只警告并继续删 unit，
        // 避免一次 systemctl 失败把卸载卡在半途。
        if let Err(err) = manager.stop_disable(Role::Hub.unit_name()) {
            eprintln!("警告：停止/禁用 hub 服务失败，继续删除 unit: {err:#}");
        }
    }

    remove_file_if_exists(&targets.unit, "systemd unit")?;
    // 只有真正 stop/disable 过（fragment == 我们的 unit）才清理 wants 链接；
    // 否则可能删掉生产环境同名外置 unit 的 enable 链接。
    if targets.manage_service && is_systemd_unit_dir(&targets.unit_dir) {
        remove_wants_symlink(&targets.unit_dir, Role::Hub.unit_name())?;
    }
    remove_file_if_exists(&targets.binary, "hub 二进制")?;

    // 先完成 --purge（config/data）再删 state 记录：purge 失败时 state 仍记录
    // hub 路径，可再次执行 uninstall --purge 重试，不会丢失待清理位置。
    if targets.purge_config {
        purge_config(&targets.config)?;
    }
    if targets.purge_data {
        purge_data_dir(&targets.data_dir, &prefix, &paths.state)?;
    }

    if record.is_some() {
        state.remove_role(Role::Hub);
        if state.roles.is_empty() {
            // roles 为空时删除整个 state 文件，而不是留下空文件。
            remove_state_file(&paths.state)?;
        } else {
            state
                .save(&paths.state)
                .with_context(|| format!("更新安装状态失败: {}", paths.state.display()))?;
        }
    }
    if targets.manage_service {
        let manager = ServiceManager::new(targets.unit_dir.clone(), true, false);
        if let Err(err) = manager.daemon_reload() {
            eprintln!("警告：systemctl daemon-reload 失败: {err:#}");
        }
    }

    print_uninstall_success(
        &args,
        &targets.config,
        &targets.data_dir,
        &targets.unit,
        &targets.binary,
    );
    Ok(())
}

/// 删除普通文件或符号链接；目录拒绝删除。目标不存在视为成功。
fn remove_file_if_exists(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            bail!("{label} {} 是目录，拒绝删除", path.display())
        }
        Ok(_) => {
            fs::remove_file(path).with_context(|| format!("删除{label} {} 失败", path.display()))?
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("检查{label} {} 失败", path.display()))
        }
    }
    Ok(())
}

/// 删除 `systemctl enable` 创建的 target.wants 符号链接。
///
/// `disable` 通常会清掉它；systemd 不可用或 disable 部分失败时兜底，避免卸载后
/// 仍残留一个指向已删除 unit 的 wants 链接。`enable` 的链接可能落在 unit 所在
/// 目录，也可能落在 `/etc/systemd/system`（systemd 的持久化 enable 目录），两处
/// 都检查。只删符号链接，不碰普通文件。
fn remove_wants_symlink(unit_dir: &Path, unit_name: &str) -> Result<()> {
    let system_dir = Path::new(SYSTEMD_SYSTEM_DIR);
    let mut dirs = vec![unit_dir];
    if unit_dir != system_dir {
        dirs.push(system_dir);
    }
    for dir in dirs {
        for target in ["multi-user.target.wants", "graphical.target.wants"] {
            let path = dir.join(target).join(unit_name);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    fs::remove_file(&path)
                        .with_context(|| format!("删除启用链接 {} 失败", path.display()))?;
                }
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("检查启用链接 {} 失败", path.display()))
                }
            }
        }
    }
    Ok(())
}

/// `--purge` 删除配置文件（拒绝符号链接与目录）。
fn purge_config(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("配置 {} 是符号链接，拒绝 --purge 删除", path.display())
        }
        Ok(meta) if meta.is_file() => {
            fs::remove_file(path).with_context(|| format!("删除配置 {} 失败", path.display()))?
        }
        Ok(_) => bail!("配置 {} 不是普通文件，拒绝 --purge 删除", path.display()),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("检查配置 {} 失败", path.display())),
    }
    Ok(())
}

/// `--purge` 删除数据目录。
///
/// 删除前用 `symlink_metadata` 拒绝符号链接，再把路径 canonicalize；只有解析后
/// 仍位于安装前缀或生产默认数据根目录下、且不是 `/`、不是前缀祖先、不包含
/// install-state 的目录才允许递归删除。
fn purge_data_dir(data_dir: &Path, prefix: &Path, state_path: &Path) -> Result<()> {
    let meta = match fs::symlink_metadata(data_dir) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("检查数据目录 {} 失败", data_dir.display()))
        }
    };
    if meta.file_type().is_symlink() {
        bail!(
            "数据目录 {} 是符号链接，拒绝 --purge 删除",
            data_dir.display()
        );
    }
    if !meta.is_dir() {
        bail!(
            "数据目录 {} 不是目录，拒绝 --purge 删除",
            data_dir.display()
        );
    }

    let canonical = data_dir
        .canonicalize()
        .with_context(|| format!("解析数据目录 {} 失败", data_dir.display()))?;
    let prefix_canonical = prefix
        .canonicalize()
        .unwrap_or_else(|_| prefix.to_path_buf());
    let production = Path::new(PRODUCTION_DATA_ROOT);

    if !path_within_scope(&canonical, &prefix_canonical, production) {
        bail!(
            "数据目录 {} 解析后不在安装前缀 {} 或生产默认路径 {} 下，拒绝 --purge 删除",
            data_dir.display(),
            prefix_canonical.display(),
            production.display()
        );
    }
    if protected_system_path(&canonical) {
        bail!(
            "数据目录 {} 解析后是系统目录，拒绝 --purge 删除",
            data_dir.display()
        );
    }
    if prefix_canonical != Path::new("/")
        && (canonical == prefix_canonical || prefix_canonical.starts_with(&canonical))
    {
        bail!(
            "数据目录 {} 是安装前缀本身或其祖先，拒绝 --purge 删除",
            data_dir.display()
        );
    }
    let state_inside = state_path
        .canonicalize()
        .map(|state| state.starts_with(&canonical))
        .unwrap_or(false);
    if state_inside {
        bail!(
            "数据目录 {} 包含安装状态 {}，拒绝 --purge 删除",
            data_dir.display(),
            state_path.display()
        );
    }

    fs::remove_dir_all(&canonical)
        .with_context(|| format!("删除数据目录 {} 失败", data_dir.display()))
}

/// canonical 路径是否位于安装前缀或生产数据根目录下；`/` 本身永远不允许。
fn path_within_scope(path: &Path, prefix: &Path, production: &Path) -> bool {
    path != Path::new("/") && (path.starts_with(prefix) || path.starts_with(production))
}

/// 额外拒绝系统目录：`--prefix /` 时前缀包含一切，不能让损坏/伪造的 state
/// 把 `--purge` 作用到 `/etc` / `/usr` 这类目录上。
fn protected_system_path(path: &Path) -> bool {
    const EXACT: [&str; 13] = [
        "/", "/etc", "/usr", "/var", "/run", "/boot", "/dev", "/proc", "/sys", "/root", "/home",
        "/tmp", "/var/tmp",
    ];
    const TREES: [&str; 6] = ["/etc", "/usr", "/boot", "/dev", "/proc", "/sys"];
    EXACT.iter().any(|candidate| path == Path::new(candidate))
        || TREES.iter().any(|candidate| path.starts_with(candidate))
}

/// 打印卸载计划（dry-run）。
fn print_uninstall_plan(args: &UninstallArgs, paths: &Paths, targets: &UninstallTargets) {
    println!("RustBoard Hub 卸载计划（--dry-run：不写文件、不调用 systemctl）");
    if targets.manage_service {
        println!("  将停止并禁用: {}", targets.unit.display());
    }
    println!("  将删除 unit: {}", targets.unit.display());
    println!("  将删除二进制: {}", targets.binary.display());
    println!("  将从安装状态删除 hub 记录: {}", paths.state.display());
    if args.purge {
        println!("  将删除配置: {}", targets.config.display());
        println!("  将删除数据目录: {}", targets.data_dir.display());
    } else {
        println!("  保留配置: {}", targets.config.display());
        println!("  保留数据目录: {}", targets.data_dir.display());
    }
}

/// 打印卸载结果（不含任何 secret）。
fn print_uninstall_success(
    args: &UninstallArgs,
    config: &Path,
    data_dir: &Path,
    unit: &Path,
    binary: &Path,
) {
    println!("RustBoard Hub 已卸载。");
    println!("  已删除 unit: {}", unit.display());
    println!("  已删除二进制: {}", binary.display());
    if args.purge {
        println!("  已删除配置: {}", config.display());
        println!("  已删除数据目录: {}", data_dir.display());
    } else {
        println!("  已保留配置: {}", config.display());
        println!("  已保留数据目录: {}", data_dir.display());
        println!("  如需删除配置与数据，请执行 `rustboard-hub uninstall --purge --yes`。");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// 测试临时目录；不引入额外 dev-dependency，Drop 时递归删除。
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "rustboard-hub-install-cmd-{tag}-{}-{}-{nanos}",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("创建测试临时目录");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn config_load_error_does_not_leak_admin_token() {
        let dir = TempDir::new("config-leak");
        let path = dir.path().join("hub.toml");
        let token = "super-secret-admin-token-4f8a";
        // 重复 admin_token 会触发 toml 解析错误；底层错误链会带原始行内容。
        fs::write(
            &path,
            format!("admin_token = \"{token}\"\nadmin_token = \"{token}\"\n"),
        )
        .unwrap();

        let err = load_hub_config_checked(&path).unwrap_err();
        let rendered = format!("{err:#}");
        assert!(rendered.contains("读取配置失败"), "{rendered}");
        assert!(
            !rendered.contains(token),
            "错误信息泄露 admin_token: {rendered}"
        );
        assert!(
            !rendered.to_ascii_lowercase().contains("duplicate"),
            "错误信息保留了 toml 解析细节: {rendered}"
        );
    }

    #[test]
    fn existing_unit_ownership_is_enforced() {
        let dir = TempDir::new("unit-own");
        let paths = Paths::for_role(Role::Hub, dir.path(), PathOverrides::default()).unwrap();
        fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();

        // 不存在：可以安装。
        assert!(ensure_unit_owned_by_us(Role::Hub, &paths).is_ok());

        // 本安装器为同一组路径渲染的 unit：允许覆盖。
        fs::write(&paths.unit, render_unit(Role::Hub, &paths).unwrap()).unwrap();
        assert!(ensure_unit_owned_by_us(Role::Hub, &paths).is_ok());

        // 外来 unit（哪怕 --force 也不能覆盖）。
        fs::write(&paths.unit, "[Service]\nExecStart=/bin/false\n").unwrap();
        let err = ensure_unit_owned_by_us(Role::Hub, &paths)
            .unwrap_err()
            .to_string();
        assert!(err.contains("不是本安装器为当前 prefix 生成的"), "{err}");
        // 拒绝时不得删除 / 改写外来 unit。
        assert!(paths.unit.exists());
    }

    #[test]
    fn upgrade_does_not_invent_unit_for_no_systemd_install() {
        let dir = TempDir::new("upgrade-unit");
        let paths = Paths::for_role(Role::Hub, dir.path(), PathOverrides::default()).unwrap();
        fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        let record = RoleState::new(&paths, "0.4.2", dir.path().join("backup"));

        // 有 state、unit 不存在、未显式 --unit-dir → 不凭空写 unit。
        assert!(!upgrade_should_write_unit(Some(&record), false, &paths.unit).unwrap());
        // 显式 --unit-dir → 写。
        assert!(upgrade_should_write_unit(Some(&record), true, &paths.unit).unwrap());
        // legacy 无 state 的旧手工配置 → 写（e2e 8.x 语义）。
        assert!(upgrade_should_write_unit(None, false, &paths.unit).unwrap());
        // unit 已存在 → 写，交由后续归属校验拒绝外来 unit。
        fs::write(&paths.unit, render_unit(Role::Hub, &paths).unwrap()).unwrap();
        assert!(upgrade_should_write_unit(Some(&record), false, &paths.unit).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_unit_is_rejected() {
        let dir = TempDir::new("unit-link");
        let paths = Paths::for_role(Role::Hub, dir.path(), PathOverrides::default()).unwrap();
        fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        let target = dir.path().join("foreign.service");
        fs::write(&target, render_unit(Role::Hub, &paths).unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &paths.unit).unwrap();

        let err = ensure_unit_owned_by_us(Role::Hub, &paths)
            .unwrap_err()
            .to_string();
        assert!(err.contains("符号链接"), "{err}");
        assert!(target.exists(), "拒绝时不能动链接目标");
    }

    #[test]
    fn admin_tls_required_uses_https_health_check() {
        // 默认回环绑定 + self-signed：required 不再被拒绝，健康检查用 127.0.0.1。
        let mut cfg = HubConfig {
            admin_tls: AdminTlsMode::Required,
            admin_listen: "127.0.0.1:9000".to_string(),
            ..HubConfig::default()
        };

        assert!(ensure_admin_tls_supported(&cfg).is_ok());
        let health = health_check_for(&cfg).expect("required 应能规划 HTTPS 健康检查");
        match health {
            HealthCheck::Https {
                addr,
                server_name,
                ca,
            } => {
                assert_eq!(addr, "127.0.0.1:9000".parse::<SocketAddr>().unwrap());
                assert_eq!(server_name, "127.0.0.1");
                assert_eq!(
                    ca,
                    HealthCa::PemFile(tls::cert_dir(&cfg.data_dir).join(tls::CA_CERT_FILE))
                );
            }
            other => panic!("expected HTTPS health check, got {other:?}"),
        }

        // 非回环绑定也支持：SNI 取 server_names 里可用的名字（默认含 localhost）。
        cfg.admin_listen = "192.0.2.10:9000".to_string();
        assert!(ensure_admin_tls_supported(&cfg).is_ok());
        match health_check_for(&cfg).unwrap() {
            HealthCheck::Https { addr, .. } => {
                assert_eq!(addr, "192.0.2.10:9000".parse::<SocketAddr>().unwrap())
            }
            other => panic!("expected HTTPS health check, got {other:?}"),
        }

        // off 仍保持 v0.4 的明文回环 healthz。
        cfg.admin_tls = AdminTlsMode::Off;
        assert_eq!(
            health_check_for(&cfg).unwrap(),
            HealthCheck::Http {
                url: "http://192.0.2.10:9000/healthz".to_string()
            }
        );
    }

    #[test]
    fn managed_paths_reject_outside_roots_and_unsafe_chars() {
        // root prefix 的默认路径全部在 allowlist 内。
        let paths = Paths::for_role(Role::Hub, Path::new("/"), PathOverrides::default()).unwrap();
        assert!(validate_install_paths(&paths).is_ok());

        for config in [
            "/srv/rustboard/hub.toml",
            "/etc/$rb/hub.toml",
            "/etc/rb\"/hub.toml",
            "/etc/rb%x/hub.toml",
            "/etc/rb\\x/hub.toml",
        ] {
            let paths = Paths::for_role(
                Role::Hub,
                Path::new("/"),
                PathOverrides {
                    config: Some(PathBuf::from(config)),
                    ..PathOverrides::default()
                },
            )
            .unwrap();
            assert!(
                validate_install_paths(&paths).is_err(),
                "config {config:?} 应被拒绝"
            );
        }

        // 非 root prefix：data_dir 必须在前缀内；unit 必须在前缀内或是 systemd 目录。
        let paths = Paths::for_role(
            Role::Hub,
            Path::new("/opt/rb"),
            PathOverrides {
                data_dir: Some(PathBuf::from("/srv/rb-data")),
                ..PathOverrides::default()
            },
        )
        .unwrap();
        assert!(validate_install_paths(&paths).is_err());
    }

    #[test]
    fn cert_rebuild_rejected_for_existing_data_dir() {
        let dir = TempDir::new("certs");
        let data_dir = dir.path().join("data");
        // 新目录 / 不需要重建证书时放行。
        assert!(ensure_cert_rebuild_allowed(&data_dir, true).is_ok());
        assert!(ensure_cert_rebuild_allowed(&data_dir, false).is_ok());

        fs::create_dir_all(&data_dir).unwrap();
        assert!(ensure_cert_rebuild_allowed(&data_dir, false).is_ok());
        let err = ensure_cert_rebuild_allowed(&data_dir, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("拒绝重建"), "{err}");
        assert!(err.contains("agent 指纹失联"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn temp_token_file_cleans_only_stale_private_regular_files() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("token");
        let paths = Paths::for_role(Role::Panel, dir.path(), PathOverrides::default()).unwrap();
        let token_dir = paths.prefix.join("var/lib/rustboard");
        fs::create_dir_all(&token_dir).unwrap();

        let stale = token_dir.join(".hub-admin-token.stale");
        fs::write(&stale, "stale-secret").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();

        // 权限不是 0600 的文件不动。
        let loose = token_dir.join(".hub-admin-token.loose");
        fs::write(&loose, "loose-secret").unwrap();
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o644)).unwrap();

        let token = TempTokenFile::create(dir.path(), "fresh-token").unwrap();
        assert!(!stale.exists(), "0600 的残留 token 文件应被清理");
        assert!(loose.exists(), "非 0600 文件不应被删除");
        assert!(token.path().exists());
        let mode = fs::metadata(token.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let contents = fs::read_to_string(token.path()).unwrap();
        assert_eq!(contents, "fresh-token");
    }

    #[test]
    fn uninstall_preflight_rejects_foreign_unit_before_touching_anything() {
        let dir = TempDir::new("uninstall");
        let prefix = dir.path();
        let paths = Paths::for_role(Role::Hub, prefix, PathOverrides::default()).unwrap();
        fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        let args = UninstallArgs {
            prefix: Some(prefix.to_path_buf()),
            config: None,
            unit_dir: None,
            purge: false,
            yes: true,
            dry_run: true,
        };

        assert!(preflight_uninstall(&args, prefix, &paths, None).is_ok());

        fs::write(&paths.unit, "[Service]\nExecStart=/bin/false\n").unwrap();
        let err = preflight_uninstall(&args, prefix, &paths, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("不是本安装器为当前 prefix 生成的"), "{err}");
        assert!(paths.unit.exists(), "预检失败不得删除 unit");
    }

    #[test]
    fn purge_data_dir_rejects_install_state_inside() {
        let dir = TempDir::new("purge-state");
        let state_path = dir.path().join("var/lib/rustboard/install-state.toml");
        fs::create_dir_all(state_path.parent().unwrap()).unwrap();
        fs::write(&state_path, "schema = 1\n").unwrap();
        let data_dir = dir.path().join("var/lib/rustboard");

        let err = check_purge_data_dir(&data_dir, &state_path)
            .unwrap_err()
            .to_string();
        assert!(err.contains("包含安装状态"), "{err}");
    }

    #[test]
    fn parses_retention_with_days_months_years() {
        let parsed = parse_retention("raw=7d,1m=90d,1h=2y").unwrap();
        assert_eq!(parsed.raw_days, Some(7));
        assert_eq!(parsed.m_days, Some(90));
        assert_eq!(parsed.h_days, Some(730));
    }

    #[test]
    fn parses_retention_partial_and_bare_days() {
        let parsed = parse_retention("raw=30").unwrap();
        assert_eq!(parsed.raw_days, Some(30));
        assert_eq!(parsed.m_days, None);
        let parsed = parse_retention("1m=6m").unwrap();
        assert_eq!(parsed.m_days, Some(180));
    }

    #[test]
    fn rejects_bad_retention() {
        for bad in [
            "",
            "raw",
            "raw=",
            "raw=7x",
            "raw=-1d",
            "raw=1d,raw=2d",
            "unknown=1d",
            "raw=99999999999d",
        ] {
            assert!(parse_retention(bad).is_err(), "{bad:?} 应被拒绝");
        }
    }

    #[test]
    fn parses_panel_yes_no() {
        assert!(parse_panel("yes").unwrap());
        assert!(!parse_panel("no").unwrap());
        assert!(parse_panel("maybe").is_err());
        assert!(parse_panel("YES").is_err());
    }

    #[test]
    fn phase_c_tls_modes_parse_and_phase_d_db_is_rejected() {
        assert_eq!(parse_tls_mode(None).unwrap(), ServerTlsMode::SelfSigned);
        assert_eq!(
            parse_tls_mode(Some("self-signed")).unwrap(),
            ServerTlsMode::SelfSigned
        );
        assert_eq!(
            parse_tls_mode(Some("acme-domain")).unwrap(),
            ServerTlsMode::AcmeDomain
        );
        assert_eq!(
            parse_tls_mode(Some("acme-ip")).unwrap(),
            ServerTlsMode::AcmeIp
        );
        let err = parse_tls_mode(Some("bogus")).unwrap_err().to_string();
        assert!(err.contains("--tls"), "{err}");

        assert!(check_db_mode(None).is_ok());
        assert!(check_db_mode(Some("sqlite")).is_ok());
        for url in ["postgres://localhost/rustboard", "postgresql://db/rb"] {
            let err = check_db_mode(Some(url)).unwrap_err().to_string();
            assert!(err.contains("Phase D"), "{url}: {err}");
        }
        assert!(check_db_mode(Some("mysql")).is_err());
    }

    #[test]
    fn rendered_unit_uses_prefixed_paths_and_hardening() {
        let paths =
            Paths::for_role(Role::Hub, Path::new("/opt/rb"), PathOverrides::default()).unwrap();
        assert_eq!(
            paths.unit,
            PathBuf::from("/opt/rb/etc/systemd/system/rustboard-hub.service")
        );
        let unit = render_unit(Role::Hub, &paths).unwrap();
        assert!(
            unit.contains(
                "ExecStart=/opt/rb/usr/local/bin/rustboard-hub run --config \
                 /opt/rb/etc/rustboard/hub.toml"
            ),
            "{unit}"
        );
        assert!(unit.contains("ReadWritePaths=/opt/rb/var/lib/rustboard/hub"));
        for directive in [
            "Type=simple",
            "Restart=on-failure",
            "RestartSec=3",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ProtectKernelTunables=true",
            "ProtectControlGroups=true",
            "LockPersonality=true",
            "WantedBy=multi-user.target",
        ] {
            assert!(unit.contains(directive), "缺少 {directive}");
        }
    }

    #[test]
    fn health_url_uses_loopback_for_wildcard_binds() {
        assert_eq!(
            health_url("0.0.0.0:8443").unwrap(),
            "http://127.0.0.1:8443/healthz"
        );
        assert_eq!(
            health_url("127.0.0.1:9000").unwrap(),
            "http://127.0.0.1:9000/healthz"
        );
        assert_eq!(
            health_url("[::]:8443").unwrap(),
            "http://[::1]:8443/healthz"
        );
        assert!(health_url("localhost:80").is_err());
        assert!(health_url("127.0.0.1:0").is_err());
    }

    #[test]
    fn server_names_cover_required_defaults() {
        let names = desired_server_names(
            "node1",
            Some("10.0.0.5"),
            &["127.0.0.1".to_string(), "board.example.com".to_string()],
        )
        .unwrap();
        assert_eq!(
            names,
            vec![
                "node1".to_string(),
                "127.0.0.1".to_string(),
                "localhost".to_string(),
                "10.0.0.5".to_string(),
                "board.example.com".to_string(),
            ]
        );
        assert!(desired_server_names("node1", None, &["".to_string()]).is_err());
        assert!(desired_server_names("", None, &[]).is_err());
    }

    #[test]
    fn purge_scope_is_limited_to_prefix_or_production() {
        let production = Path::new(PRODUCTION_DATA_ROOT);
        assert!(path_within_scope(
            Path::new("/opt/rb/var/lib/rustboard/hub"),
            Path::new("/opt/rb"),
            production
        ));
        assert!(path_within_scope(
            Path::new("/var/lib/rustboard/hub"),
            Path::new("/opt/rb"),
            production
        ));
        assert!(!path_within_scope(
            Path::new("/etc/rustboard"),
            Path::new("/opt/rb"),
            production
        ));
        assert!(!path_within_scope(
            Path::new("/"),
            Path::new("/"),
            production
        ));
    }

    #[test]
    fn purge_rejects_protected_system_directories() {
        for protected in [
            "/",
            "/etc",
            "/etc/rustboard",
            "/usr/lib/rustboard",
            "/boot",
            "/dev",
            "/proc/1",
            "/sys",
            "/run",
            "/root",
            "/home",
            "/tmp",
            "/var/tmp",
        ] {
            assert!(
                protected_system_path(Path::new(protected)),
                "{protected} 应被拒绝"
            );
        }
        for allowed in [
            "/var/lib/rustboard/hub",
            "/var/tmp/rustboard-v100.x/prefix/var/lib/rustboard/hub",
            "/root/code/serverdashboard/target/prefix/var/lib/rustboard/hub",
            "/home/user/rb/var/lib/rustboard/hub",
            "/opt/rb/var/lib/rustboard/hub",
        ] {
            assert!(
                !protected_system_path(Path::new(allowed)),
                "{allowed} 应允许"
            );
        }
    }

    #[test]
    fn raw_prefix_is_validated_before_normalization() {
        // P-01：Paths::for_role 会把 `//` 归一化成 `/`；只有先校验原始 CLI
        // prefix，才不会让 `install --prefix //` 指向生产路径。
        for bad in ["//", "/opt/rb/", "/opt/./rb"] {
            let err = paths_for_role_validated(Role::Hub, Path::new(bad), PathOverrides::default())
                .unwrap_err()
                .to_string();
            assert!(err.contains("安装前缀"), "{bad:?} 应被拒绝: {err}");
        }
        // 归一化本身确实会把 `//` 变成 `/`，证明上面的顺序检查是必要的。
        let normalized =
            Paths::for_role(Role::Hub, Path::new("//"), PathOverrides::default()).unwrap();
        assert_eq!(normalized.prefix, Path::new("/"));
    }

    #[test]
    fn systemd_managed_install_rejects_prefix_unit_dir() {
        let dir = TempDir::new("unit-dir");
        let paths = Paths::for_role(Role::Hub, dir.path(), PathOverrides::default()).unwrap();

        // manage=true（--systemd / 生产 root prefix）时，prefix 内 unit 目录
        // 不会被 systemd 读取，必须在 write / enable 之前拒绝。
        let err = ensure_install_unit_dir(true, &paths.unit)
            .unwrap_err()
            .to_string();
        assert!(err.contains("systemd 不会读取 prefix 内 unit"), "{err}");
        assert!(
            err.contains("--unit-dir /etc/systemd/system 或 /run/systemd/system"),
            "{err}"
        );
        // 不托管（非 root prefix 默认 / --no-systemd）只写参考 unit，不调用
        // systemctl，因此允许 prefix 内目录。
        assert!(ensure_install_unit_dir(false, &paths.unit).is_ok());

        for unit in [
            "/etc/systemd/system/rustboard-hub.service",
            "/run/systemd/system/rustboard-hub.service",
        ] {
            assert!(
                ensure_unit_dir_read_by_systemd(Path::new(unit)).is_ok(),
                "{unit} 应被接受"
            );
        }
    }

    #[test]
    fn install_fragment_decision_rejects_foreign_units_and_transient_active() {
        let expected = Path::new("/run/systemd/system/rustboard-hub.service");
        let foreign = Path::new("/etc/systemd/system/rustboard-hub.service");

        assert!(ensure_install_fragment_matches(Some(expected), true, expected).is_ok());
        assert!(ensure_install_fragment_matches(Some(expected), false, expected).is_ok());

        let err = ensure_install_fragment_matches(Some(foreign), false, expected)
            .unwrap_err()
            .to_string();
        assert!(err.contains("实际解析的 hub unit"), "{err}");
        assert!(err.contains(foreign.to_str().unwrap()), "{err}");
        assert!(err.contains(expected.to_str().unwrap()), "{err}");

        // unit 文件缺失但同名服务 active：transient / 外来 unit，必须拒绝。
        let err = ensure_install_fragment_matches(None, true, expected)
            .unwrap_err()
            .to_string();
        assert!(err.contains("active"), "{err}");
        assert!(err.contains("transient"), "{err}");
        assert!(ensure_install_fragment_matches(None, false, expected).is_ok());
    }

    #[test]
    fn uninstall_fragment_decision_never_stops_on_missing_or_foreign_fragment() {
        let expected = Path::new("/run/systemd/system/rustboard-hub.service");
        let foreign = Path::new("/etc/systemd/system/rustboard-hub.service");

        // unit 文件不存在：即使 systemd 解析到同名文件也不 stop。
        assert_eq!(
            classify_uninstall_unit(false, None, expected),
            UninstallUnitAction::RemoveOnly
        );
        assert_eq!(
            classify_uninstall_unit(false, Some(expected), expected),
            UninstallUnitAction::RemoveOnly
        );
        // unit 文件在，但 fragment 为空：只删自己的文件，不 stop。
        assert_eq!(
            classify_uninstall_unit(true, None, expected),
            UninstallUnitAction::RemoveOnly
        );
        // 只有 fragment 精确等于 state 记录的 unit 才允许 stop/disable。
        assert_eq!(
            classify_uninstall_unit(true, Some(expected), expected),
            UninstallUnitAction::StopAndRemove
        );
        assert_eq!(
            classify_uninstall_unit(true, Some(foreign), expected),
            UninstallUnitAction::RefuseForeign(foreign.to_path_buf())
        );
    }

    #[test]
    fn should_stop_verified_requires_exact_owned_fragment() {
        let expected = Path::new("/run/systemd/system/rustboard-hub.service");
        let foreign = Path::new("/etc/systemd/system/rustboard-hub.service");

        // 只有 fragment 精确等于本安装的 unit 才允许 stop/disable。
        assert!(should_stop_verified(Some(expected), expected));
        // 缺失 / transient、同名外来 / 更高优先级 unit：一律跳过 stop。
        assert!(!should_stop_verified(None, expected));
        assert!(!should_stop_verified(Some(foreign), expected));
    }

    #[test]
    fn install_lock_scope_skips_dry_run_and_inherited_child() {
        assert_eq!(install_lock_scope(true, false), InstallLockScope::None);
        assert_eq!(install_lock_scope(true, true), InstallLockScope::None);
        assert_eq!(install_lock_scope(false, true), InstallLockScope::None);
        assert_eq!(install_lock_scope(false, false), InstallLockScope::Global);
        // dry-run 不加锁：这个 helper 在测试环境也能安全执行，不触碰 /run。
        assert!(acquire_install_lock(true).unwrap().is_none());
    }

    /// 环境变量是进程级全局状态，测试并行时必须串行。
    static LOCK_ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 临时修改 `RUSTBOARD_INSTALL_LOCK_HELD`，Drop（含 panic）时还原。
    struct LockHeldEnvGuard {
        original: Option<std::ffi::OsString>,
    }

    impl LockHeldEnvGuard {
        fn set(value: Option<&str>) -> Self {
            let original = std::env::var_os(rustboard_install::LOCK_HELD_ENV);
            match value {
                Some(value) => std::env::set_var(rustboard_install::LOCK_HELD_ENV, value),
                None => std::env::remove_var(rustboard_install::LOCK_HELD_ENV),
            }
            Self { original }
        }
    }

    impl Drop for LockHeldEnvGuard {
        fn drop(&mut self) {
            match self.original.take() {
                Some(value) => std::env::set_var(rustboard_install::LOCK_HELD_ENV, value),
                None => std::env::remove_var(rustboard_install::LOCK_HELD_ENV),
            }
        }
    }

    #[test]
    fn inherited_lock_env_is_exactly_one_and_skips_global_flock() {
        let _serial = LOCK_ENV_MUTEX
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // 父进程（packaging/install.sh）持锁后设 =1：必须直接复用父进程的锁，
        // 不得再 flock。返回 Ok(None) 即证明没有调用 acquire_global。
        let env = LockHeldEnvGuard::set(Some("1"));
        assert!(InstallLock::inherited());
        assert!(acquire_install_lock(false).unwrap().is_none());
        drop(env);

        // 0 / 未设置 / 其他值都不算继承；只断言决策，避免测试真的去 flock /run。
        for value in [Some("0"), None, Some("true"), Some("")] {
            let _env = LockHeldEnvGuard::set(value);
            assert!(!InstallLock::inherited(), "{value:?} 不应视为已继承");
            assert_eq!(
                install_lock_scope(false, InstallLock::inherited()),
                InstallLockScope::Global,
                "{value:?} 应走全局锁"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn upgrade_dry_run_config_load_is_read_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new("upgrade-readonly");
        let path = dir.path().join("hub.toml");
        let token = "dry-run-admin-token-3c1f";
        let cfg = HubConfig {
            admin_token: token.to_string(),
            ..HubConfig::default()
        };
        fs::write(&path, toml::to_string_pretty(&cfg).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let loaded = load_hub_config_read_only(&path).unwrap();
        assert_eq!(loaded.admin_token, token);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "dry-run 读取不得把配置 harden 成 0600");

        // 正常 upgrade 仍走 HubConfig::load（会 harden 成 0600）。
        let loaded = load_hub_config_checked(&path).unwrap();
        assert_eq!(loaded.admin_token, token);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "正常 upgrade 应收紧配置权限");

        // 解析失败只报路径，不泄露重复 admin_token 的原始行。
        fs::write(
            &path,
            format!("admin_token = \"{token}\"\nadmin_token = \"{token}\"\n"),
        )
        .unwrap();
        let err = load_hub_config_read_only(&path).unwrap_err().to_string();
        assert!(!err.contains(token), "只读加载泄露 admin_token: {err}");
        assert!(err.contains(path.to_str().unwrap()), "{err}");
    }

    #[test]
    fn uninstall_preflight_validates_state_config_and_data_without_purge() {
        let dir = TempDir::new("uninstall-paths");
        let prefix = dir.path();
        let paths = Paths::for_role(Role::Hub, prefix, PathOverrides::default()).unwrap();
        fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        let args = UninstallArgs {
            prefix: Some(prefix.to_path_buf()),
            config: None,
            unit_dir: None,
            purge: false,
            yes: true,
            dry_run: true,
        };
        assert!(preflight_uninstall(&args, prefix, &paths, None).is_ok());

        // 伪造 state 的 config 指向 prefix 之外：即使没有 --purge 也必须在
        // preflight 拒绝，不能等到 purge 分支才校验。
        let mut record = RoleState::new(&paths, "0.4.2", dir.path().join("backup"));
        record.config = PathBuf::from("/etc/rustboard/hub.toml");
        let err = preflight_uninstall(&args, prefix, &paths, Some(&record))
            .unwrap_err()
            .to_string();
        assert!(err.contains("配置路径不在允许卸载的范围"), "{err}");

        // 伪造的 config / data_dir 是符号链接：非 --purge 卸载也必须拒绝。
        #[cfg(unix)]
        {
            let mut record = RoleState::new(&paths, "0.4.2", dir.path().join("backup"));
            record.config = dir.path().join("config-link.toml");
            std::os::unix::fs::symlink(dir.path().join("missing-target"), &record.config).unwrap();
            let err = preflight_uninstall(&args, prefix, &paths, Some(&record))
                .unwrap_err()
                .to_string();
            assert!(err.contains("符号链接"), "config: {err}");

            let mut record = RoleState::new(&paths, "0.4.2", dir.path().join("backup"));
            record.data_dir = dir.path().join("data-link");
            std::os::unix::fs::symlink(dir.path().join("missing-target"), &record.data_dir)
                .unwrap();
            let err = preflight_uninstall(&args, prefix, &paths, Some(&record))
                .unwrap_err()
                .to_string();
            assert!(err.contains("符号链接"), "data_dir: {err}");
        }
    }

    /// 构造测试用 InstallArgs；显式端口避免 `pick_free_port` 触碰真实端口。
    fn test_install_args() -> InstallArgs {
        InstallArgs {
            yes: true,
            offline: false,
            dry_run: true,
            force: false,
            prefix: None,
            config: None,
            data_dir: None,
            unit_dir: None,
            listen: Some("0.0.0.0:18443".to_string()),
            admin_listen: Some("127.0.0.1:19000".to_string()),
            advertise: None,
            sans: Vec::new(),
            name: None,
            retention: None,
            db: None,
            tls: None,
            tls_options: Box::default(),
            panel: None,
            panel_static_dir: None,
            systemd: false,
            no_systemd: true,
        }
    }

    fn acme_args() -> InstallArgs {
        let mut args = test_install_args();
        args.tls = Some("acme-domain".to_string());
        args.tls_options.acme_email = Some("admin@example.com".to_string());
        args.tls_options.domains = vec!["board.example.com".to_string()];
        args
    }

    #[test]
    fn offline_and_acme_are_mutually_exclusive() {
        let mut args = acme_args();
        args.offline = true;
        let err = validate_tls_args(&args).unwrap_err().to_string();
        assert!(err.contains("--offline"), "{err}");
        assert!(err.contains("ACME"), "{err}");

        // 即使没有显式 --tls，只要出现 ACME 参数也必须拒绝。
        let mut args = test_install_args();
        args.offline = true;
        args.tls_options.acme_email = Some("admin@example.com".to_string());
        let err = validate_tls_args(&args).unwrap_err().to_string();
        assert!(err.contains("--offline"), "{err}");
        assert!(err.contains("ACME"), "{err}");

        // self-signed（默认）本身仍可离线安装。
        let mut args = test_install_args();
        args.offline = true;
        assert!(validate_tls_args(&args).is_ok());
    }

    #[test]
    fn explicit_self_signed_rejects_acme_only_args() {
        let mut args = acme_args();
        args.tls = Some("self-signed".to_string());
        let err = validate_tls_args(&args).unwrap_err().to_string();
        assert!(err.contains("self-signed"), "{err}");
        assert!(err.contains("ACME"), "{err}");
        assert!(err.contains("--domain"), "{err}");
    }

    #[test]
    fn acme_mode_requires_email_domains_and_valid_ca_path() {
        let mut args = acme_args();
        args.tls_options.acme_email = None;
        let err = validate_tls_args(&args).unwrap_err().to_string();
        assert!(err.contains("--acme-email"), "{err}");

        let mut args = acme_args();
        args.tls_options.domains.clear();
        let err = validate_tls_args(&args).unwrap_err().to_string();
        assert!(err.contains("--domain"), "{err}");

        let mut args = acme_args();
        args.tls = Some("acme-ip".to_string());
        args.tls_options.domains = vec!["203.0.113.10".to_string(), "203.0.113.11".to_string()];
        let err = validate_tls_args(&args).unwrap_err().to_string();
        assert!(err.contains("acme-ip"), "{err}");

        let mut args = acme_args();
        args.tls_options.domains = (0..=MAX_ACME_DOMAINS)
            .map(|index| format!("d{index}.example.com"))
            .collect();
        let err = validate_tls_args(&args).unwrap_err().to_string();
        assert!(err.contains("最多"), "{err}");

        let mut args = acme_args();
        args.tls_options.acme_ca = Some(PathBuf::from("relative-ca.pem"));
        let err = validate_tls_args(&args).unwrap_err().to_string();
        assert!(err.contains("绝对路径"), "{err}");

        let dir = TempDir::new("acme-ca");
        let ca = dir.path().join("ca.pem");
        fs::write(&ca, "not a real ca").unwrap();
        let mut args = acme_args();
        args.tls_options.acme_ca = Some(ca);
        assert!(validate_tls_args(&args).is_ok());
    }

    #[test]
    fn new_hub_config_applies_acme_and_admin_tls() {
        let mut args = acme_args();
        args.tls_options.domains = vec![
            "board.example.com".to_string(),
            "www.board.example.com".to_string(),
        ];
        args.tls_options.acme_challenge = Some("tls-alpn-01".to_string());
        args.tls_options.acme_profile = Some("shortlived".to_string());
        args.tls_options.admin_tls = Some("required".to_string());
        args.admin_listen = Some("0.0.0.0:19000".to_string());

        let paths = Paths::for_role(
            Role::Hub,
            Path::new("/opt/rustboard-test"),
            PathOverrides::default(),
        )
        .unwrap();
        let cfg = new_hub_config(&args, &paths, Retention::default()).unwrap();
        assert_eq!(cfg.tls.mode, ServerTlsMode::AcmeDomain);
        assert_eq!(cfg.tls.acme_email, "admin@example.com");
        assert_eq!(cfg.tls.domains.len(), 2);
        assert_eq!(cfg.tls.challenge, AcmeChallenge::TlsAlpn01);
        assert_eq!(cfg.tls.acme_profile, "shortlived");
        assert_eq!(cfg.admin_tls, AdminTlsMode::Required);
        assert_eq!(cfg.effective_server_names(), cfg.tls.domains);
        // ACME 标识同步进 server_names，供主程序 validate_admin_tls 使用。
        assert!(cfg
            .server_names
            .iter()
            .any(|name| name == "board.example.com"));
        cfg.validate().expect("ACME 配置应通过校验");
        ensure_acme_args_match_mode(&cfg, &args).unwrap();

        // 新建默认 self-signed 配置 + ACME-only 参数：即使没显式 --tls 也不能静默忽略。
        let mut args = test_install_args();
        args.tls_options.acme_email = Some("admin@example.com".to_string());
        let cfg = new_hub_config(&args, &paths, Retention::default()).unwrap();
        let err = ensure_acme_args_match_mode(&cfg, &args)
            .unwrap_err()
            .to_string();
        assert!(err.contains("self-signed"), "{err}");
        assert!(err.contains("ACME"), "{err}");
    }

    #[test]
    fn explicit_self_signed_clears_previous_acme_fields() {
        let mut cfg = HubConfig::default();
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.acme_email = "old@example.com".to_string();
        cfg.tls.domains = vec!["old.example.com".to_string()];

        let mut args = test_install_args();
        args.tls = Some("self-signed".to_string());
        apply_tls_flags(&mut cfg, &args).unwrap();
        assert_eq!(cfg.tls.mode, ServerTlsMode::SelfSigned);
        assert!(cfg.tls.acme_email.is_empty());
        assert!(cfg.tls.domains.is_empty());
    }

    #[test]
    fn admin_health_plan_prefers_san_and_selects_ca() {
        // self-signed + 通配绑定：连 127.0.0.1，SNI 用 127.0.0.1，信任本地 CA。
        let mut cfg = HubConfig {
            admin_tls: AdminTlsMode::Required,
            admin_listen: "0.0.0.0:9000".to_string(),
            ..HubConfig::default()
        };
        match health_check_for(&cfg).unwrap() {
            HealthCheck::Https {
                addr,
                server_name,
                ca,
            } => {
                assert_eq!(addr, "127.0.0.1:9000".parse::<SocketAddr>().unwrap());
                assert_eq!(server_name, "127.0.0.1");
                assert_eq!(
                    ca,
                    HealthCa::PemFile(tls::cert_dir(&cfg.data_dir).join(tls::CA_CERT_FILE))
                );
            }
            other => panic!("expected HTTPS, got {other:?}"),
        }

        // ACME 公共证书：SNI 用第一个域名，信任系统根。
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.domains = vec!["board.example.com".to_string()];
        match health_check_for(&cfg).unwrap() {
            HealthCheck::Https {
                server_name, ca, ..
            } => {
                assert_eq!(server_name, "board.example.com");
                assert_eq!(ca, HealthCa::SystemRoots);
            }
            other => panic!("expected HTTPS, got {other:?}"),
        }

        // 私有 / Pebble ACME：信任从 server.crt 链尾提取的 agent-ca.pem，
        // 不是 ACME WFE 的 HTTPS 根（acme_ca_file）。
        cfg.tls.acme_ca_file = "/etc/rustboard/pebble-ca.pem".to_string();
        match health_check_for(&cfg).unwrap() {
            HealthCheck::Https { ca, .. } => assert_eq!(
                ca,
                HealthCa::PemFile(tls::cert_dir(&cfg.data_dir).join(ACME_AGENT_CA_FILE))
            ),
            other => panic!("expected HTTPS, got {other:?}"),
        }
    }

    #[test]
    fn panel_endpoint_follows_admin_tls_mode() {
        let mut cfg = HubConfig {
            admin_listen: "127.0.0.1:9000".to_string(),
            ..HubConfig::default()
        };
        assert_eq!(
            panel_endpoint(&cfg).unwrap(),
            PanelEndpoint {
                hub_url: "http://127.0.0.1:9000".to_string(),
                hub_ca: None,
            }
        );

        cfg.admin_tls = AdminTlsMode::Required;
        assert_eq!(
            panel_endpoint(&cfg).unwrap(),
            PanelEndpoint {
                hub_url: "https://127.0.0.1:9000".to_string(),
                hub_ca: Some(tls::cert_dir(&cfg.data_dir).join(tls::CA_CERT_FILE)),
            }
        );

        // 公共 ACME：系统根，不传自签 CA。
        cfg.admin_listen = "0.0.0.0:9000".to_string();
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.domains = vec!["board.example.com".to_string()];
        assert_eq!(
            panel_endpoint(&cfg).unwrap(),
            PanelEndpoint {
                hub_url: "https://board.example.com:9000".to_string(),
                hub_ca: None,
            }
        );

        // 私有 ACME：传从 server.crt 链尾提取的 agent-ca.pem，而不是 acme_ca_file。
        let dir = TempDir::new("panel-ca");
        let ca = dir.path().join("pebble-ca.pem");
        fs::write(&ca, "pem").unwrap();
        cfg.tls.acme_ca_file = ca.display().to_string();
        assert_eq!(
            panel_endpoint(&cfg).unwrap().hub_ca,
            Some(tls::cert_dir(&cfg.data_dir).join(ACME_AGENT_CA_FILE))
        );
    }

    #[test]
    fn acme_retry_command_is_reproducible_and_has_no_secret() {
        let mut cfg = HubConfig::default();
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.acme_email = "admin@example.com".to_string();
        cfg.tls.domains = vec!["board.example.com".to_string()];
        cfg.tls.challenge = AcmeChallenge::TlsAlpn01;
        cfg.admin_tls = AdminTlsMode::Required;

        let command = acme_retry_command(&cfg);
        for needle in [
            "rustboard-hub install --force",
            "--tls acme-domain",
            "--acme-email admin@example.com",
            "--domain board.example.com",
            "--acme-challenge tls-alpn-01",
            "--admin-tls required",
        ] {
            assert!(command.contains(needle), "缺少 {needle:?}: {command}");
        }
        assert!(!command.to_ascii_lowercase().contains("token"), "{command}");
    }

    #[test]
    fn retry_issue_retries_three_times_and_stops_on_unsupported() {
        let mut calls = 0;
        let (attempts, result) = retry_issue(ACME_MAX_ATTEMPTS, Duration::ZERO, |_| {
            calls += 1;
            Err(AcmeIssueFailure::Failed(format!("mock-{calls}")))
        });
        assert_eq!(attempts, ACME_MAX_ATTEMPTS);
        assert_eq!(calls, ACME_MAX_ATTEMPTS);
        assert!(matches!(result, Err(AcmeIssueFailure::Failed(_))));

        // 第二轮成功：不应继续第三轮。
        let mut calls = 0;
        let (attempts, result) = retry_issue(ACME_MAX_ATTEMPTS, Duration::ZERO, |_| {
            calls += 1;
            if calls == 2 {
                Ok(())
            } else {
                Err(AcmeIssueFailure::Failed("mock".to_string()))
            }
        });
        assert_eq!(attempts, 2);
        assert!(result.is_ok());

        // 当前二进制没有 tls 子命令：立即停止，不重试。
        let mut calls = 0;
        let (attempts, result) = retry_issue(ACME_MAX_ATTEMPTS, Duration::ZERO, |_| {
            calls += 1;
            Err(AcmeIssueFailure::Unsupported("no tls".to_string()))
        });
        assert_eq!(calls, 1);
        assert_eq!(attempts, 1);
        assert!(matches!(result, Err(AcmeIssueFailure::Unsupported(_))));
    }

    #[test]
    fn acme_output_sanitizer_hides_keys_and_key_authorization() {
        let raw = "正常输出\n\
                   -----BEGIN EC PRIVATE KEY-----\n\
                   SUPER-SECRET-KEY-BYTES\n\
                   -----END EC PRIVATE KEY-----\n\
                   keyAuthorization: super-secret-keyauth\n\
                   another normal line\n";
        let sanitized = sanitize_acme_output(raw);
        assert!(sanitized.contains("正常输出"), "{sanitized}");
        assert!(sanitized.contains("another normal line"), "{sanitized}");
        assert!(!sanitized.contains("SUPER-SECRET-KEY-BYTES"), "{sanitized}");
        assert!(!sanitized.contains("super-secret-keyauth"), "{sanitized}");
        assert!(sanitized.contains("[已隐藏私钥内容]"), "{sanitized}");
        assert!(
            sanitized.contains("[已隐藏 ACME key authorization]"),
            "{sanitized}"
        );

        let long = format!("x{}\n", "y".repeat(600));
        assert!(sanitize_acme_output(&long).contains("[已隐藏超长输出行]"));
    }

    #[test]
    fn missing_tls_cli_is_detected_from_clap_error() {
        for text in [
            "error: unrecognized subcommand 'tls'",
            "error: unexpected argument 'tls' found",
        ] {
            assert!(looks_like_missing_tls_cli(text), "{text}");
        }
        assert!(!looks_like_missing_tls_cli("network timeout"));
    }

    #[test]
    fn verifies_acme_server_material_pair_and_expiry() {
        let dir = TempDir::new("acme-material");
        let cert_dir = tls::cert_dir(dir.path());
        fs::create_dir_all(&cert_dir).unwrap();
        let certified =
            rcgen::generate_simple_self_signed(vec!["board.example.com".to_string()]).unwrap();
        let cert_path = cert_dir.join(tls::SERVER_CERT_FILE);
        let key_path = cert_dir.join(tls::SERVER_KEY_FILE);
        fs::write(&cert_path, certified.cert.pem()).unwrap();
        fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();

        let summary = verify_acme_server_material(dir.path()).expect("成对证书应通过");
        assert!(summary.contains("到期"), "{summary}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "ACME 私钥应收紧到 0600");
        }

        // 私钥换成另一把：必须拒绝。
        let other =
            rcgen::generate_simple_self_signed(vec!["board.example.com".to_string()]).unwrap();
        fs::write(&key_path, other.key_pair.serialize_pem()).unwrap();
        let err = verify_acme_server_material(dir.path())
            .unwrap_err()
            .to_string();
        assert!(err.contains("不匹配"), "{err}");
    }

    #[test]
    fn private_acme_agent_ca_extracts_chain_tail() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let dir = TempDir::new("acme-agent-ca");
        let certs = tls::cert_dir(dir.path());
        fs::create_dir_all(&certs).unwrap();

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "RustBoard Test ACME CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params =
            CertificateParams::new(vec!["board.example.com".to_string()]).unwrap();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "board.example.com");
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let chain = format!("{}{}", leaf.pem(), ca.pem());
        fs::write(certs.join(tls::SERVER_CERT_FILE), &chain).unwrap();

        let mut cfg = HubConfig {
            data_dir: dir.path().to_path_buf(),
            ..HubConfig::default()
        };
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.acme_email = "admin@example.com".to_string();
        cfg.tls.domains = vec!["board.example.com".to_string()];
        cfg.tls.acme_ca_file = "/etc/rustboard/pebble-ca.pem".to_string();

        let path = prepare_private_acme_agent_ca(&cfg)
            .unwrap()
            .expect("私有 ACME 必须生成 agent CA");
        assert_eq!(path, certs.join(ACME_AGENT_CA_FILE));
        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(written, tls::last_certificate_pem(&chain).unwrap());
        assert!(tls::certificate_is_ca(&written).unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644);
        }

        // 公共 ACME / self-signed 不生成 agent CA。
        cfg.tls.acme_ca_file.clear();
        assert!(prepare_private_acme_agent_ca(&cfg).unwrap().is_none());
        cfg.tls.mode = ServerTlsMode::SelfSigned;
        cfg.tls.acme_ca_file = "/etc/rustboard/pebble-ca.pem".to_string();
        assert!(prepare_private_acme_agent_ca(&cfg).unwrap().is_none());

        // 链尾不是 CA：拒绝把 leaf 当信任锚。
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        let only_leaf =
            rcgen::generate_simple_self_signed(vec!["board.example.com".to_string()]).unwrap();
        fs::write(certs.join(tls::SERVER_CERT_FILE), only_leaf.cert.pem()).unwrap();
        let err = prepare_private_acme_agent_ca(&cfg).unwrap_err().to_string();
        assert!(err.contains("不是 CA"), "{err}");
    }

    #[test]
    fn staging_config_uses_isolated_subdir_and_never_touches_live_material() {
        let live = TempDir::new("staging-live");
        let data_dir = live.path().join("data");
        let mut cfg = HubConfig {
            data_dir: data_dir.clone(),
            database: sqlite_database(&data_dir),
            ..HubConfig::default()
        };
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.acme_email = "admin@example.com".to_string();
        cfg.tls.domains = vec!["board.example.com".to_string()];

        // 已有 production CA / server.crt；staging 不得改写它们。
        tls::ensure_client_ca(&cfg.data_dir, tls::CertPolicy::default()).unwrap();
        let live_certs = tls::cert_dir(&cfg.data_dir);
        fs::write(live_certs.join(tls::SERVER_CERT_FILE), b"live-cert").unwrap();

        let mut staging = AcmeStagingDir::create(&cfg.data_dir).unwrap();
        assert!(
            staging.path().starts_with(&cfg.data_dir),
            "staging 临时目录必须位于真实 data_dir 内: {}",
            staging.path().display()
        );
        assert!(
            !staging.path().starts_with(&live_certs),
            "staging 不得使用 live certs 目录"
        );
        let staging_cfg = staging_config(&cfg, staging.path(), LE_STAGING_DIRECTORY);
        assert_eq!(staging_cfg.data_dir, staging.path());
        assert_eq!(staging_cfg.database, sqlite_database(staging.path()));
        assert_eq!(staging_cfg.tls.mode, cfg.tls.mode);
        assert_eq!(staging_cfg.tls.domains, cfg.tls.domains);
        assert_eq!(staging_cfg.tls.acme_directory, LE_STAGING_DIRECTORY);
        assert!(!staging_cfg.tls.staging_check);
        staging_cfg
            .validate()
            .expect("staging 配置的 data_dir 必须通过 HubConfig::validate");
        // 原始配置不被修改。
        assert_eq!(
            cfg.tls.acme_directory,
            rustboard_common::config::DEFAULT_ACME_DIRECTORY
        );
        assert!(cfg.tls.staging_check);

        // 模拟 `tls issue` 在 staging 下写入证书 / ACME 账户；live 材料保持原样。
        let staging_certs = tls::cert_dir(staging.path());
        fs::create_dir_all(staging_certs.join("acme")).unwrap();
        fs::write(staging_certs.join(tls::SERVER_CERT_FILE), b"staging-cert").unwrap();
        fs::write(staging_certs.join("acme/account.json"), b"{}").unwrap();
        staging.cleanup().unwrap();
        assert_eq!(
            fs::read(live_certs.join(tls::SERVER_CERT_FILE)).unwrap(),
            b"live-cert",
            "staging 失败/结束不得改写 live server.crt"
        );
        assert!(
            !live_certs.join("acme").exists(),
            "staging 账户状态不得写进 live certs"
        );
        assert!(!staging.path().exists(), "staging 临时目录必须清理");
    }

    #[test]
    fn acme_staging_dir_drop_cleans_up() {
        let root = TempDir::new("staging-drop");
        let data_dir = root.path().join("data");
        let staging = AcmeStagingDir::create(&data_dir).unwrap();
        let path = staging.path().to_path_buf();
        assert!(path.starts_with(&data_dir));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "staging 临时目录必须 0700");
        }
        assert!(path.exists());
        drop(staging);
        assert!(!path.exists(), "Drop 必须清理 staging 临时目录");
    }

    #[test]
    fn acme_guard_cleans_new_data_dir_and_allows_self_signed_retry() {
        let root = TempDir::new("acme-guard-new");
        let data_dir = root.path().join("data");
        let mut guard = AcmeCertGuard::capture(&data_dir, false);
        guard.arm();
        tls::ensure_client_ca(&data_dir, tls::CertPolicy::default()).unwrap();
        let cert_dir = tls::cert_dir(&data_dir);
        fs::create_dir_all(cert_dir.join("acme")).unwrap();
        fs::write(cert_dir.join("acme/account.json"), b"{}").unwrap();
        fs::write(cert_dir.join("acme/state.toml"), b"").unwrap();
        fs::write(cert_dir.join(tls::SERVER_CERT_FILE), b"leaf").unwrap();

        guard.restore().unwrap();
        assert!(!data_dir.exists(), "全新安装失败后 data_dir 必须被清理");
        assert!(!cert_dir.exists(), "certs（CA / account / state）不得残留");
        // 后续 self-signed 重试不应被“证书不完整”拦截。
        ensure_cert_rebuild_allowed(&data_dir, true).expect("清理后应允许重建自签材料");
    }

    #[test]
    fn acme_guard_restores_old_server_material() {
        let root = TempDir::new("acme-guard-old");
        let data_dir = root.path().join("data");
        let cert_dir = tls::cert_dir(&data_dir);
        fs::create_dir_all(&cert_dir).unwrap();
        fs::write(cert_dir.join(tls::SERVER_CERT_FILE), b"old-cert").unwrap();
        fs::write(cert_dir.join(tls::SERVER_KEY_FILE), b"old-key").unwrap();
        fs::write(cert_dir.join(ACME_AGENT_CA_FILE), b"old-agent-ca").unwrap();

        let mut guard = AcmeCertGuard::capture(&data_dir, true);
        guard.arm();
        fs::write(cert_dir.join(tls::SERVER_CERT_FILE), b"new-cert").unwrap();
        fs::write(cert_dir.join(tls::SERVER_KEY_FILE), b"new-key").unwrap();
        fs::write(cert_dir.join(ACME_AGENT_CA_FILE), b"new-agent-ca").unwrap();
        guard.restore().unwrap();
        assert_eq!(
            fs::read(cert_dir.join(tls::SERVER_CERT_FILE)).unwrap(),
            b"old-cert"
        );
        assert_eq!(
            fs::read(cert_dir.join(tls::SERVER_KEY_FILE)).unwrap(),
            b"old-key"
        );
        assert_eq!(
            fs::read(cert_dir.join(ACME_AGENT_CA_FILE)).unwrap(),
            b"old-agent-ca",
            "私有 ACME 的 agent 信任锚必须随旧证书一起恢复"
        );
        assert!(data_dir.exists(), "已有数据目录不得被删除");

        // 安装前没有 agent-ca.pem：回滚时必须删除本次新派生的文件。
        fs::remove_file(cert_dir.join(ACME_AGENT_CA_FILE)).unwrap();
        let mut guard = AcmeCertGuard::capture(&data_dir, true);
        guard.arm();
        fs::write(cert_dir.join(ACME_AGENT_CA_FILE), b"derived-ca").unwrap();
        guard.restore().unwrap();
        assert!(!cert_dir.join(ACME_AGENT_CA_FILE).exists());
    }

    #[test]
    fn acme_guard_never_deletes_existing_data_dir_without_old_material() {
        let root = TempDir::new("acme-guard-existing");
        let data_dir = root.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let sentinel = data_dir.join("rustboard.db");
        fs::write(&sentinel, b"db").unwrap();

        let mut guard = AcmeCertGuard::capture(&data_dir, true);
        guard.arm();
        assert!(!guard.armed, "已有 data_dir 且无旧证书时不应进入清理模式");
        guard.restore().unwrap();
        assert!(sentinel.exists());
    }

    #[test]
    fn existing_data_dir_without_ca_refuses_silent_rebuild() {
        let root = TempDir::new("acme-existing-ca");
        let data_dir = root.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let sentinel = data_dir.join("rustboard.db");
        fs::write(&sentinel, b"db").unwrap();

        let err = ensure_acme_client_ca(&data_dir, true, tls::CertPolicy::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("拒绝静默重建"), "{err}");
        assert!(!tls::cert_dir(&data_dir).exists(), "不得创建 certs/CA");
        assert!(sentinel.exists());

        // 只有一半 CA 材料：同样拒绝，且不补建另一半。
        let partial = root.path().join("partial");
        let partial_certs = tls::cert_dir(&partial);
        fs::create_dir_all(&partial_certs).unwrap();
        fs::write(partial_certs.join(tls::CA_CERT_FILE), b"pem").unwrap();
        let err = ensure_acme_client_ca(&partial, true, tls::CertPolicy::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("拒绝静默重建"), "{err}");
        assert!(!partial_certs.join(tls::CA_KEY_FILE).exists());

        // 全新安装（data_dir 不存在）才允许创建 CA。
        let fresh = root.path().join("fresh");
        ensure_acme_client_ca(&fresh, false, tls::CertPolicy::default()).unwrap();
        assert!(tls::cert_dir(&fresh).join(tls::CA_CERT_FILE).is_file());
        assert!(tls::cert_dir(&fresh).join(tls::CA_KEY_FILE).is_file());
    }

    #[test]
    fn offline_rejects_existing_acme_config() {
        let mut args = test_install_args();
        args.offline = true;
        let mut cfg = HubConfig::default();
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.acme_email = "admin@example.com".to_string();
        cfg.tls.domains = vec!["board.example.com".to_string()];
        let err = ensure_offline_not_acme(&args, &cfg)
            .unwrap_err()
            .to_string();
        assert!(err.contains("--offline"), "{err}");
        assert!(err.contains("ACME"), "{err}");

        cfg.tls = TlsConfig::default();
        ensure_offline_not_acme(&args, &cfg).expect("self-signed 离线安装仍允许");
    }

    #[test]
    fn staging_runs_only_for_default_le_production_domain_cert() {
        let mut cfg = HubConfig::default();
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.acme_directory = rustboard_common::config::DEFAULT_ACME_DIRECTORY.to_string();
        cfg.tls.staging_check = true;
        assert_eq!(staging_directory_for(&cfg), Some(LE_STAGING_DIRECTORY));

        // acme-ip / shortlived 默认跳过 staging（以 production 结果为准）。
        cfg.tls.mode = ServerTlsMode::AcmeIp;
        assert_eq!(staging_directory_for(&cfg), None);

        // 显式关闭 staging_check。
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.staging_check = false;
        assert_eq!(staging_directory_for(&cfg), None);

        // 自定义 directory（Pebble / 用户指定 staging）不再套一层 staging。
        cfg.tls.staging_check = true;
        cfg.tls.acme_directory = "https://pebble:14000/dir".to_string();
        assert_eq!(staging_directory_for(&cfg), None);
    }

    #[test]
    fn failed_acme_falls_back_or_aborts_by_config() {
        let mut cfg = HubConfig {
            admin_tls: AdminTlsMode::Off,
            ..HubConfig::default()
        };
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.acme_email = "admin@example.com".to_string();
        cfg.tls.domains = vec!["board.example.com".to_string()];
        cfg.tls.fallback_to_self_signed = true;
        let outcome = handle_acme_failure(
            &mut cfg,
            None,
            3,
            AcmeIssueFailure::Failed("mock acme error".to_string()),
        )
        .expect("默认应回退 self-signed");
        assert!(matches!(outcome, AcmeOutcome::FellBack));
        assert_eq!(cfg.tls.mode, ServerTlsMode::SelfSigned);
        assert!(cfg.tls.domains.is_empty());
        assert!(cfg.tls.acme_email.is_empty());

        // 关闭回退：必须在写盘前返回错误，调用方会回滚事务。
        cfg.tls.mode = ServerTlsMode::AcmeDomain;
        cfg.tls.acme_email = "admin@example.com".to_string();
        cfg.tls.domains = vec!["board.example.com".to_string()];
        cfg.tls.fallback_to_self_signed = false;
        let result = handle_acme_failure(
            &mut cfg,
            None,
            3,
            AcmeIssueFailure::Unsupported("no tls issue".to_string()),
        );
        assert!(result.is_err(), "fallback=false 必须中止");
        let err = result.err().expect("必须有错误");
        assert!(err.to_string().contains("fallback_to_self_signed"), "{err}");
    }

    #[test]
    fn self_signed_admin_tls_required_supports_non_loopback_bind() {
        // 非回环管理口 + 显式 SAN：安装器不再拒绝，且健康检查连绑定 IP、
        // 用该 IP 做 SNI / 主机名校验。
        let mut args = test_install_args();
        args.tls_options.admin_tls = Some("required".to_string());
        args.admin_listen = Some("192.0.2.10:9000".to_string());
        args.sans = vec!["192.0.2.10".to_string()];

        let paths = Paths::for_role(
            Role::Hub,
            Path::new("/opt/rustboard-test"),
            PathOverrides::default(),
        )
        .unwrap();
        let cfg = new_hub_config(&args, &paths, Retention::default()).unwrap();
        cfg.validate().expect("配置应自洽");
        crate::validate_admin_tls(&cfg).expect("非回环 required 应通过主程序校验");
        assert!(ensure_admin_tls_supported(&cfg).is_ok());

        match health_check_for(&cfg).unwrap() {
            HealthCheck::Https {
                addr, server_name, ..
            } => {
                assert_eq!(addr, "192.0.2.10:9000".parse::<SocketAddr>().unwrap());
                assert_eq!(server_name, "192.0.2.10");
            }
            other => panic!("expected HTTPS, got {other:?}"),
        }
    }
}
