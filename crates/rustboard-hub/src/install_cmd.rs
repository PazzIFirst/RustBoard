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

use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rustboard_common::config::{AdminTlsMode, HubConfig};
use rustboard_common::fsutil;
use rustboard_common::tls;
use rustboard_common::util::{hostname, port_of};
use rustboard_install::{
    detect_system, is_systemd_unit_dir, pick_free_port, render_unit, require_root, shell_arg,
    unit_is_ours, validate_install_prefix, validate_managed_path, wait_http_ok, InstallLock,
    InstallState, InstallTxn, ManagedPathKind, PathOverrides, Paths, Prompt, Role, RoleState,
    ServiceManager,
};

/// 健康检查等待上限（库内部还会再截断到 30s）。
const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
/// 生产数据根目录：`--purge` 允许删除该目录下的旧手工安装数据。
const PRODUCTION_DATA_ROOT: &str = "/var/lib/rustboard";
/// systemd 系统级 unit 目录：`uninstall` 清理 enable 生成的 wants 链接时一并检查。
const SYSTEMD_SYSTEM_DIR: &str = "/etc/systemd/system";
/// Phase A 安装器不做 HTTPS 健康检查，遇到 required 必须在写盘 / 停服务前拒绝。
const ADMIN_TLS_REQUIRED_UNSUPPORTED: &str =
    "Phase A 安装器不支持 admin_tls=required；请使用 upgrade 或手工部署，避免健康检查 http 误判";
/// systemd 只读取固定目录中的 unit；写进 prefix 的 unit 不会被读取，也就不能
/// 用来 enable / restart / stop，必须在写盘和调用 systemctl 之前拒绝。
const SYSTEMD_UNIT_DIR_REQUIRED: &str =
    "systemd 不会读取 prefix 内 unit；请用 --unit-dir /etc/systemd/system 或 /run/systemd/system";

/// `rustboard-hub install` 参数。
#[derive(Args, Debug)]
pub(crate) struct InstallArgs {
    /// 非交互执行（不读取 stdin）。
    #[arg(long)]
    pub(crate) yes: bool,
    /// 离线安装：不做任何网络探测（Phase A 安装器本身不联网）。
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
    /// TLS 模式；Phase A 只支持 `self-signed`。
    #[arg(long)]
    pub(crate) tls: Option<String>,
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
    need_certs: bool,
    restart: bool,
}

/// 保留期覆盖值；`None` 表示沿用配置/默认值。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Retention {
    raw_days: Option<u32>,
    m_days: Option<u32>,
    h_days: Option<u32>,
}

/// `--tls` 只允许 Phase A 的 self-signed；其余取值明确指向 Phase C。
fn check_tls_mode(value: Option<&str>) -> Result<()> {
    match value {
        None | Some("self-signed") => Ok(()),
        Some(other) => bail!(
            "--tls {other:?} 暂不支持：Phase A 只提供 self-signed；ACME（acme-domain / acme-ip）在 Phase C 实现"
        ),
    }
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
        cfg.validate()
            .context("已有配置校验失败（检查 --san / --retention / --data-dir）")?;
        validate_listen(&cfg)?;
        crate::validate_admin_tls(&cfg).context("管理 API 监听地址不安全")?;
        let missing = missing_cert_files(&cfg.data_dir)?;
        Ok((cfg, !missing.is_empty()))
    } else {
        let cfg = new_hub_config(args, paths, retention)?;
        cfg.validate()
            .context("安装参数校验失败（检查 --san / --retention / --data-dir）")?;
        validate_listen(&cfg)?;
        crate::validate_admin_tls(&cfg).context("管理 API 监听地址不安全")?;
        Ok((cfg, true))
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

/// 安装器只用 `http://` 做健康检查；已有/新配置为 `admin_tls=required` 时
/// 继续安装会把 HTTPS 监听的 `/healthz` 误判为失败并回滚，必须在写盘前拒绝。
fn ensure_admin_tls_supported(cfg: &HubConfig) -> Result<()> {
    if cfg.admin_tls == AdminTlsMode::Required {
        bail!("{ADMIN_TLS_REQUIRED_UNSUPPORTED}");
    }
    Ok(())
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

/// install 子命令入口。
pub(crate) fn install(args: InstallArgs) -> Result<()> {
    let prefix = args.prefix.clone().unwrap_or_else(|| PathBuf::from("/"));
    check_tls_mode(args.tls.as_deref())?;
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
        let panel_yes = match args.panel.as_deref() {
            Some(value) => parse_panel(value)?,
            None => args.yes,
        };
        print_install_plan(&args, &paths, manage, write_unit, panel_yes);
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

    let (cfg, need_certs) = prepare_config(&args, &paths, retention, config_present)?;
    // 已有配置的 data_dir 是权威值：升级/重装不跟随 flag 默认值漂移。
    paths.data_dir = cfg.data_dir.clone();
    // R-S5：配置来自 state/磁盘，required 的健康检查是 HTTPS，安装器必须拒绝而
    // 不是启动服务后误判失败并回滚。
    ensure_admin_tls_supported(&cfg)?;
    validate_install_paths(&paths)?;
    // L7：需要补证书但数据目录已存在（可能有旧 CA / agent 指纹）时拒绝重建。
    ensure_cert_rebuild_allowed(&paths.data_dir, need_certs)?;
    if !need_certs && (args.advertise.is_some() || !args.sans.is_empty()) {
        println!(
            "提示：沿用已有服务端证书；新增 SAN 需再执行 `rustboard-hub rotate-cert` 才会生效。"
        );
    }

    // 只有新装、或旧面板状态丢失、或本次重新生成了 admin_token 时才重跑面板：
    // 已有配置的 --force 会保留 token，不需要动面板。
    let install_panel =
        panel_yes && (state.role(Role::Panel).is_none() || existing.is_none() || !config_present);

    let plan = InstallPlan {
        args: &args,
        paths: &paths,
        cfg: &cfg,
        manager,
        write_unit,
        install_panel,
        need_certs,
        restart: manage && active,
    };

    let mut txn = InstallTxn::begin(&paths, false)?;
    let mut service_touched = false;
    match run_install(&plan, &mut txn, &mut service_touched) {
        Ok(()) => {
            txn.commit()?;
            print_install_success(&plan);
            Ok(())
        }
        Err(err) => {
            let rollback = txn.rollback();
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
        if plan.need_certs {
            let policy = tls::CertPolicy {
                ca_days: plan.cfg.ca_validity_days,
                server_days: plan.cfg.server_cert_validity_days,
                client_days: plan.cfg.client_cert_validity_days,
            };
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
            let url = health_url(&plan.cfg.admin_listen)?;
            wait_http_ok(&url, HEALTH_TIMEOUT)
                .with_context(|| format!("等待 hub 健康检查失败: {url}"))?;
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

/// 同机面板安装：token 走 0600 临时文件，参数用数组传递，stdout 直接透传。
fn install_panel(args: &InstallArgs, paths: &Paths, cfg: &HubConfig, manage: bool) -> Result<()> {
    // 面板安装器通过 http:// 回调 hub 管理 API；required 下会误把 HTTPS 健康检查
    // 当成失败。这里再兜底一次，保证任何调用路径都不会用 http 对接 required。
    ensure_admin_tls_supported(cfg).context("拒绝用 http 安装同机面板")?;

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

    let admin_port = port_of(&cfg.admin_listen)
        .ok_or_else(|| anyhow!("无法从 admin_listen 解析端口: {}", cfg.admin_listen))?;
    if admin_port == 0 {
        bail!("管理 API 端口为 0，拒绝安装面板");
    }

    let temp = TempTokenFile::create(&paths.prefix, &cfg.admin_token)?;
    let panel_config = paths
        .prefix
        .join("etc/rustboard")
        .join(Role::Panel.config_name());
    let force_panel = args.force || panel_config.is_file();

    let hub_url = format!("http://127.0.0.1:{admin_port}");
    let mut command = Command::new(&panel_bin);
    command
        .args(["install", "--yes"])
        .arg("--prefix")
        .arg(&paths.prefix)
        .arg("--hub-url")
        .arg(&hub_url)
        .arg("--hub-token-file")
        .arg(temp.path());
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

    println!("正在安装同机面板（hub={hub_url}）...");
    let status = command
        .status()
        .with_context(|| format!("执行面板安装失败: {}", panel_bin.display()))?;
    if !status.success() {
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
) {
    println!("RustBoard Hub 安装计划（--dry-run：不写文件、不调用 systemctl）");
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
    let admin_url =
        health_url(&plan.cfg.admin_listen).unwrap_or_else(|_| plan.cfg.admin_listen.clone());
    println!("  管理 API: {admin_url}");
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
    fn install_requires_admin_tls_off() {
        let mut cfg = HubConfig::default();
        assert!(ensure_admin_tls_supported(&cfg).is_ok());
        cfg.admin_tls = AdminTlsMode::Required;
        let err = ensure_admin_tls_supported(&cfg).unwrap_err().to_string();
        assert!(err.contains("admin_tls=required"), "{err}");
        assert!(err.contains("Phase A"), "{err}");
        assert!(err.contains("http"), "{err}");
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
    fn phase_c_tls_and_phase_d_db_are_rejected() {
        assert!(check_tls_mode(None).is_ok());
        assert!(check_tls_mode(Some("self-signed")).is_ok());
        for mode in ["acme-domain", "acme-ip", "bogus"] {
            let err = check_tls_mode(Some(mode)).unwrap_err().to_string();
            assert!(err.contains("Phase C"), "{mode}: {err}");
        }

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
}
