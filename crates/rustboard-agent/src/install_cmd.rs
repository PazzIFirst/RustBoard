//! `rustboard-agent install` / `uninstall` 子命令。
//!
//! 安装流程固定为：校验参数 → 用 [`InstallTxn`] 写 data/config/unit/binary →
//! `daemon-reload` → `enable --now` → 等待 enrollment 落盘 → 最后写 install-state。
//! 任何一步失败都会停服务并回滚本次写入；安装前已存在的数据目录不属于本次事务，
//! 不会被回滚删除。
//!
//! 安全约定：
//! - token 只从 `--token-file`（0600 普通文件，≤4 KiB）读取，**不接受 argv**；
//! - token 不打印、不写 unit、错误信息不包含 token 内容；
//! - 指纹在落盘前用 `tls::parse_fingerprint` 校验并归一化为 64 位小写 hex；
//! - 非 `--dry-run` 的 install/uninstall 在读取 state 之前获取**全局**安装锁
//!   [`InstallLock::acquire_global`]（hub/panel/agent 共享同一份
//!   `install-state.toml`），并持有到函数结束；`--dry-run` 不加锁；
//! - 由 systemd 管理时 unit 必须位于 systemd 真正读取的目录；`enable` /
//!   `stop` 之前用 `FragmentPath` 核对 systemd 实际解析到的 unit，同名外来 /
//!   更高优先级 / transient unit 一律拒绝操作；
//! - 安装前缀在归一化前用 [`validate_install_prefix`] 校验（拒绝 `//`、尾斜杠、
//!   `.` 等会被 `Paths::for_role` 归一化掩盖的形式），所有落盘目标经
//!   [`validate_managed_path`]；目标 unit 已存在时必须是本安装器为当前 prefix
//!   渲染的，`--force` 也不覆盖外来 unit；
//! - 卸载先在锁内完成整体 preflight（config/data/unit/binary 的 allowlist、
//!   字符集与目标类型，unit 归属），全部通过后才停止服务、删除文件；只对
//!   systemd 实际解析到的本安装器 unit 调用 systemctl；`--purge` 删除前拒绝
//!   符号链接，并拒绝包含 install-state 的目录。

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rustboard_common::config::{AgentConfig, AgentTlsMode};
use rustboard_common::tls;
use rustboard_common::util::hostname;
use rustboard_common::VERSION;
use rustboard_install::{
    detect_system, ensure_service_stopped, is_systemd_unit_dir, read_private_file,
    remove_enable_symlink, render_unit, require_root, require_systemd, shell_arg,
    stop_service_checked, unit_is_ours, validate_install_prefix, validate_managed_path,
    InstallLock, InstallState, InstallTxn, ManagedPathKind, PathOverrides, Paths, Prompt, Role,
    RoleState, ServiceControl, ServiceManager, ServiceState,
};

const AGENT_CERT: &str = "agent.crt";
const AGENT_KEY: &str = "agent.key";
const AGENT_SECRET: &str = "agent.secret";
const AGENT_CA: &str = "ca.crt";
const AGENT_ID: &str = "agent_id";
/// enrollment 完成标记；必须与 agent 主程序写入的文件名一致。
const ENROLLMENT_MARKER: &str = "enrollment.complete";
/// 五个身份文件；完成标记在它们全部落盘后最后写入。
const ENROLLMENT_FILES: [&str; 5] = [AGENT_CERT, AGENT_KEY, AGENT_SECRET, AGENT_CA, AGENT_ID];

/// `custom-ca` 模式复制到 data_dir 的服务端 CA 文件名。
const SERVER_CA_FILE: &str = "server-ca.pem";

/// `--server-ca` 源文件大小上限（PEM 证书包）。
const SERVER_CA_MAX_BYTES: usize = 1024 * 1024;

/// `--tls-mode` 的 CLI 值。
///
/// 不复用 `rustboard_common::config::AgentTlsMode` 的 `ValueEnum` derive：
/// common crate 不依赖 clap，保持配置层与 CLI 解析解耦；映射集中在
/// [`From`] 中，新增模式时编译器会强制同步。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum AgentTlsModeArg {
    /// 指纹钉扎（默认，保持 v0.4 行为）。
    #[default]
    Fingerprint,
    /// 系统根证书 + 主机名校验（公共 ACME）。
    SystemRoots,
    /// 指定 CA + 主机名校验（私有 ACME / 自签）。
    CustomCa,
}

impl From<AgentTlsModeArg> for AgentTlsMode {
    fn from(value: AgentTlsModeArg) -> Self {
        match value {
            AgentTlsModeArg::Fingerprint => AgentTlsMode::Fingerprint,
            AgentTlsModeArg::SystemRoots => AgentTlsMode::SystemRoots,
            AgentTlsModeArg::CustomCa => AgentTlsMode::CustomCa,
        }
    }
}

/// token 文件大小上限；与计划里的 4 KiB 一致。
const TOKEN_MAX_BYTES: usize = 4096;

/// enrollment 等待上限；失败时停服务并回滚。
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// enrollment 轮询间隔。
const ENROLLMENT_POLL: Duration = Duration::from_millis(200);

/// 重启 / 启动后等待 systemd 报告新 MainPID 的上限。
///
/// `enable --now` 对已经在运行的服务是 no-op；`was_active` 的升级必须 restart
/// 并确认产生了新进程，否则会把“旧二进制仍在跑”误报成安装成功。
const SERVICE_START_VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// 等待新 MainPID 的轮询间隔。
const SERVICE_START_POLL: Duration = Duration::from_millis(100);

/// 确认新进程稳定运行的间隔：重启后必须连续两次（间隔约 500ms）看到
/// ActiveState=active，避免 crash-loop 的瞬时 active 被误判为成功。
const SERVICE_STABLE_INTERVAL: Duration = Duration::from_millis(500);

/// systemd unit 文件名（固定名字，与 `render_unit` / packaging 一致）。
const AGENT_UNIT_NAME: &str = "rustboard-agent.service";

/// 读取 unit 文件的上限：unit 是纯文本配置，异常大的文件必须拒绝而不是读进内存。
const UNIT_MAX_BYTES: usize = 64 * 1024;

/// `--force --dry-run` 只读加载已有配置的大小上限。
const CONFIG_MAX_BYTES: u64 = 1024 * 1024;

/// `rustboard-agent install` 参数。
#[derive(Args, Debug)]
pub struct InstallArgs {
    /// 非交互确认；agent 安装没有交互项，保留与 hub/panel 一致的接口。
    #[arg(long)]
    pub yes: bool,
    /// 不做网络探测（Phase A 安装器本身不访问网络）。
    #[arg(long)]
    pub offline: bool,
    /// 只打印计划，不创建目录、不写文件、不调用 systemctl。
    #[arg(long)]
    pub dry_run: bool,
    /// 覆盖已有配置；已纳管的数据目录/证书不会被删除。
    #[arg(long)]
    pub force: bool,
    /// 安装前缀，默认生产根 `/`；测试/容器用非根 prefix。
    #[arg(long, default_value = "/")]
    pub prefix: PathBuf,
    /// 配置文件路径（默认由 prefix 推导）。
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// 数据目录（默认由 prefix 推导）。
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    /// systemd unit 目录（默认由 prefix 推导）。
    #[arg(long)]
    pub unit_dir: Option<PathBuf>,
    /// hub 的 WebSocket 地址，例如 `wss://127.0.0.1:8443/agent/ws`。
    #[arg(long)]
    pub hub: Option<String>,
    /// enrollment token 文件（必须 0600、普通文件、非符号链接）。
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// hub 服务端证书 SHA-256 指纹；支持 64 位 hex 或 `sha256:...`。
    ///
    /// `fingerprint` 模式新装必填；`custom-ca` 模式可选；
    /// `system-roots` 模式不使用（显式提供会被拒绝）。
    #[arg(long)]
    pub fingerprint: Option<String>,
    /// 服务端信任模型；默认 `fingerprint`（旧 CLI 不传时行为不变）。
    #[arg(long, value_enum)]
    pub tls_mode: Option<AgentTlsModeArg>,
    /// 服务端 CA 证书（PEM）；`custom-ca` 模式新装必填。
    ///
    /// 必须是 0600/0644 的普通文件、非符号链接、≤1 MiB；安装器会校验其中至少
    /// 一张证书并复制到 `<data_dir>/server-ca.pem`（0644）。
    #[arg(long)]
    pub server_ca: Option<PathBuf>,
    /// 展示名，默认取本机 hostname。
    #[arg(long)]
    pub name: Option<String>,
    /// 强制由 systemd 管理（默认：根 prefix 且系统有 systemd 时启用）。
    #[arg(long, conflicts_with = "no_systemd")]
    pub systemd: bool,
    /// 不写 unit、不调用 systemctl。
    #[arg(long)]
    pub no_systemd: bool,
}

/// `rustboard-agent uninstall` 参数。
#[derive(Args, Debug)]
pub struct UninstallArgs {
    /// 安装前缀，默认生产根 `/`。
    #[arg(long, default_value = "/")]
    pub prefix: PathBuf,
    /// 无 state 记录时使用的配置路径。
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// 无 state 记录时使用的数据目录。
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    /// 无 state 记录时使用的 unit 目录。
    #[arg(long)]
    pub unit_dir: Option<PathBuf>,
    /// 连同配置与数据目录一起删除（需要 `--yes` 或交互确认）。
    #[arg(long)]
    pub purge: bool,
    /// 非交互确认。
    #[arg(long)]
    pub yes: bool,
    /// 只打印计划，不停止服务、不删除文件。
    #[arg(long)]
    pub dry_run: bool,
}

/// 安装决策；抽成纯函数便于单测幂等/`--force` 边界。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallMode {
    /// 全新安装：必须提供 hub / token-file / fingerprint。
    Fresh,
    /// `--force` 且已有配置：复用旧配置，只应用显式参数。
    ForceReuse,
    /// 已纳管且有完整安装记录：重复执行直接返回 0。
    AlreadyInstalled,
}

/// 执行 `rustboard-agent install`。
pub fn install(args: InstallArgs) -> Result<()> {
    // `--server-ca` 只对 custom-ca 有意义；显式选了别的模式时立刻拒绝，
    // 避免把一个安全相关的参数静默忽略。--force 未传 --tls-mode 时模式来自
    // 旧配置，留到合并后再判断。
    if args.server_ca.is_some()
        && matches!(args.tls_mode, Some(mode) if mode != AgentTlsModeArg::CustomCa)
    {
        bail!("--server-ca 只能与 --tls-mode custom-ca 一起使用");
    }

    let system = detect_system();
    // P-01：必须先用**原始** prefix 做安全校验。Paths::for_role 会归一化 `//`、
    // 尾斜杠与 `.` 组件；若先归一化再校验，`--prefix //` 会被当成 `/`，dry-run
    // 就会指向生产路径。
    validate_install_prefix(&args.prefix).context("安装前缀不安全，拒绝安装")?;
    let base_paths = Paths::for_role(Role::Agent, &args.prefix, path_overrides(&args))?;
    // H1：prefix 决定全部写盘根。校验前缀（/tmp、sticky、他人拥有、
    // group/other 可写、符号链接组件、`..`/`$`/引号一律拒绝），再读 state。
    validate_install_prefix(&base_paths.prefix).context("安装前缀不安全，拒绝安装")?;
    // R-S4：非 dry-run 从 state 读取前就持有**全局**锁，直到函数结束；dry-run
    // 不加锁。使用全局锁而非角色锁：install-state.toml 由 hub/panel/agent 共享，
    // 角色锁不能阻止不同角色并发 load→save 互相覆盖。
    let _lock = if args.dry_run {
        None
    } else {
        Some(InstallLock::acquire_global().context("获取全局安装锁失败")?)
    };

    let state = InstallState::load(&base_paths.state)?;
    let record = state.role(Role::Agent).cloned();
    let record_paths = match &record {
        Some(role) => Some(paths_from_record(&base_paths, role)?),
        None => None,
    };
    let state_present = record.is_some();

    // 已有 state 时优先沿用记录中的 config/unit-dir（显式 flag 仍可覆盖），
    // 避免 `--force` 不传自定义路径时在 prefix 下写出第二套配置/unit。
    let config_override = args
        .config
        .clone()
        .or_else(|| record_paths.as_ref().map(|paths| paths.config.clone()));
    let unit_dir_override = args.unit_dir.clone().or_else(|| {
        record_paths
            .as_ref()
            .and_then(|paths| paths.unit.parent().map(Path::to_path_buf))
    });
    let config_paths = Paths::for_role(
        Role::Agent,
        &args.prefix,
        PathOverrides {
            config: config_override.clone(),
            data_dir: args.data_dir.clone(),
            unit_dir: unit_dir_override.clone(),
            bin_dir: None,
        },
    )?;
    let config_exists = path_present(&config_paths.config);

    // 只有 --force 复用旧配置时才读取配置文件（需要旧 token/hub/name）。
    // 解析失败的错误也不打印文件内容，防止 token 被 TOML 诊断回显。
    // R-S3：dry-run 必须零写入，因此走只读加载，不能触发 harden/chmod。
    let old_config = if config_exists && args.force {
        Some(load_existing_config(&config_paths.config, args.dry_run)?)
    } else {
        None
    };
    // data_dir 优先级：显式 flag > 旧配置（--force）> state 记录 > prefix 默认。
    let effective_data_dir = if args.data_dir.is_some() {
        config_paths.data_dir.clone()
    } else if let Some(cfg) = &old_config {
        cfg.data_dir.clone()
    } else if let Some(record_paths) = &record_paths {
        record_paths.data_dir.clone()
    } else {
        config_paths.data_dir.clone()
    };
    let paths = if effective_data_dir == config_paths.data_dir {
        config_paths
    } else {
        Paths::for_role(
            Role::Agent,
            &args.prefix,
            PathOverrides {
                config: config_override,
                data_dir: Some(effective_data_dir),
                unit_dir: unit_dir_override,
                bin_dir: None,
            },
        )?
    };
    // 幂等判断按 state 记录的实际路径检查，而不是当前 CLI 推导路径：
    // 旧安装可能用了 --config/--unit-dir 覆盖，重复执行同一命令时仍应判定已安装。
    let manage = if args.no_systemd {
        false
    } else if args.systemd {
        true
    } else {
        paths.is_root_prefix() && system.systemd
    };
    let write_unit = !args.no_systemd;
    // systemd 管理只对 systemd 真正读取的目录生效：prefix 内的 unit 文件不会被
    // 加载，`systemctl enable/start` 只会按名字作用到同名外来 unit（或直接失败）。
    // 这是纯路径检查，dry-run 也必须报错，且发生在任何写盘 / systemctl 之前。
    if manage {
        ensure_manageable_unit(&paths.unit)?;
    }
    let unit_dir = paths
        .unit
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.prefix.clone());
    // dry-run 时 ServiceManager 的内部调用全部跳过，不会执行任何 systemctl。
    let manager = ServiceManager::new(unit_dir, manage, args.dry_run);
    // 安装幂等判断用「五件身份齐全」而不是完成标记：旧安装可能还没有 marker，
    // 但它们已经是已安装状态，`run` 启动时会校验并补齐，不能要求 --force。
    let enrolled = has_enrollment_identity(&paths.data_dir);
    // 幂等判断要确认 state 记录的文件都在：配置、二进制必写；由 systemd 管理时
    // unit 也必须是安装出来的那个。缺文件必须报错要求 --force，不能假装已安装。
    let unit_required = manage
        || record_paths
            .as_ref()
            .is_some_and(|paths| paths.unit.parent().is_some_and(is_systemd_unit_dir));
    let idempotent_config = record_paths
        .as_ref()
        .map(|paths| paths.config.as_path())
        .unwrap_or(&paths.config);
    let idempotent_binary = record_paths
        .as_ref()
        .map(|paths| paths.binary.as_path())
        .unwrap_or(&paths.binary);
    let idempotent_unit = record_paths
        .as_ref()
        .map(|paths| paths.unit.as_path())
        .unwrap_or(&paths.unit);
    let recorded_files_present = path_present(idempotent_config)
        && path_present(idempotent_binary)
        && (!unit_required || path_present(idempotent_unit));
    let mode = decide_mode(
        state_present,
        enrolled,
        config_exists,
        recorded_files_present,
        args.force,
    )?;
    if mode == InstallMode::AlreadyInstalled {
        // 幂等返回 0 之前同样确认 unit 归属：同名外来 unit（即使服务 active）
        // 不能被误判成“已安装”，更不能在这里 stop/delete。
        if let Some(own_paths) = &record_paths {
            ensure_existing_unit_is_ours(&own_paths.unit, own_paths, "覆盖/停止")?;
        }
        // systemd 按 unit 名字操作，不能只看文件是否存在：FragmentPath 指向
        // 同名外来/更高优先级 unit，或没有 unit 文件的 transient unit 处于
        // active 时，必须拒绝“已安装”结论。dry-run 不调用 systemctl。
        if manage && !args.dry_run {
            ensure_installed_fragment(&manager, &paths.unit)
                .context("确认 systemd 实际解析的 agent unit 失败")?;
        }
        print_already_installed(&paths);
        return Ok(());
    }

    let requested_tls_mode = args.tls_mode.map(AgentTlsMode::from);
    let mut cfg = match old_config {
        Some(cfg) if mode == InstallMode::ForceReuse => cfg,
        _ => AgentConfig::default(),
    };
    if mode == InstallMode::ForceReuse {
        // --force 只应用显式 flags；未给的字段（尤其是 token / tls_mode）保持
        // 旧值，避免把已完成 enrollment 的 agent 重写成空 token 或错误的信任模式。
        if let Some(hub) = args.hub.as_deref() {
            cfg.hub_url = hub.to_string();
        }
        if let Some(name) = args.name.as_deref() {
            cfg.name = name.to_string();
        }
        if let Some(tls_mode) = requested_tls_mode {
            cfg.tls_mode = tls_mode;
        }
        // 模式可能来自旧配置或本次 --tls-mode；system-roots 下显式 --fingerprint
        // 不能静默忽略，否则用户会误以为仍启用了证书 pin。
        reject_system_roots_fingerprint(cfg.tls_mode, args.fingerprint.as_deref())?;
        if let Some(fingerprint) = args.fingerprint.as_deref() {
            cfg.server_fingerprint = normalize_fingerprint(fingerprint)?;
        }
        if let Some(token_file) = args.token_file.as_deref() {
            cfg.token = read_token(token_file)?;
        }
        cfg.data_dir = paths.data_dir.clone();
        // 模式可能来自旧配置；显式 --server-ca 与最终模式不符时必须拒绝，
        // 不能静默忽略用户传入的 CA 文件。
        if args.server_ca.is_some() && cfg.tls_mode != AgentTlsMode::CustomCa {
            bail!(
                "--server-ca 只能与 --tls-mode custom-ca 一起使用（当前配置模式为 {}）",
                cfg.tls_mode.as_str()
            );
        }
    } else {
        // 参数检查顺序与旧版一致：先 hub、再 token-file，最后指纹/CA 组合；
        // 旧 CLI（不传 --tls-mode）的错误信息因此保持不变。
        let hub = args
            .hub
            .as_deref()
            .ok_or_else(|| anyhow!("新装必须指定 --hub（例如 wss://127.0.0.1:8443/agent/ws）"))?;
        let token_file = args.token_file.as_deref().ok_or_else(|| {
            anyhow!("新装必须指定 --token-file（token 只接受 0600 文件，禁止通过 argv 传递）")
        })?;
        let tls_mode = requested_tls_mode.unwrap_or_default();
        validate_fresh_tls_args(
            tls_mode,
            args.fingerprint.as_deref(),
            args.server_ca.as_deref(),
        )?;
        cfg.hub_url = hub.to_string();
        cfg.token = read_token(token_file)?;
        cfg.tls_mode = tls_mode;
        cfg.server_fingerprint = match args.fingerprint.as_deref() {
            Some(fingerprint) => normalize_fingerprint(fingerprint)?,
            None => String::new(),
        };
        cfg.name = args.name.clone().unwrap_or_else(hostname);
        cfg.data_dir = paths.data_dir.clone();
    }

    // `--server-ca` 在任何写盘之前读取、校验并复制到 data_dir/server-ca.pem；
    // 配置里只写复制后的绝对路径，避免服务运行后源文件被移走/替换。
    let server_ca_bytes = if let Some(source) = args.server_ca.as_deref() {
        let bytes = read_server_ca(source)?;
        let dest = paths.data_dir.join(SERVER_CA_FILE);
        let dest_text = dest
            .to_str()
            .ok_or_else(|| anyhow!("data_dir 不是有效 UTF-8，无法写入 server_ca 配置"))?;
        cfg.server_ca = dest_text.to_string();
        Some(bytes)
    } else {
        None
    };

    // KI-21：必须在写任何文件之前完成校验；失败时磁盘上不能留下半个安装。
    cfg.validate()
        .context("agent 配置校验失败（检查 --hub / --data-dir / --fingerprint / --server-ca）")?;
    validate_fingerprint(&cfg)?;

    // M1/L5：任何落盘（含 dry-run 计划）之前统一校验 config/data/unit/binary
    // 的 allowlist，拒绝 prefix 外自定义路径与 $、%、引号、反斜杠等字符。
    preflight_install_paths(&paths)?;
    // M3：目标 unit 已存在时，必须是本安装器为当前 prefix 渲染的普通文件；
    // 同名外来 unit 一律拒绝覆盖（--force 也一样），且不停止任何服务。
    if write_unit {
        ensure_existing_unit_is_ours(&paths.unit, &paths, "覆盖/停止")?;
    }

    if manage && !args.dry_run {
        require_root().context("启用 systemd 管理需要 root（可加 --no-systemd 只写文件）")?;
        require_systemd()?;
    }

    let config_bytes = toml::to_string_pretty(&cfg).context("序列化 agent 配置失败")?;
    let unit_contents = if write_unit {
        Some(render_unit(Role::Agent, &paths)?)
    } else {
        None
    };
    let current_exe = std::env::current_exe().context("读取当前可执行文件路径失败")?;
    // 用安装后的二进制再次执行 install 时，源和目标可能是同一个文件，
    // 不能自己复制自己（事务会报错，重装也会失败）。
    let copy_binary = !same_file(&current_exe, &paths.binary);

    if args.dry_run {
        let mut txn = InstallTxn::begin(&paths, true)?;
        txn.create_owned_dir(&paths.data_dir, 0o700)?;
        txn.write(&paths.config, config_bytes.as_bytes(), 0o600)?;
        if let Some(bytes) = &server_ca_bytes {
            txn.write(&paths.data_dir.join(SERVER_CA_FILE), bytes, 0o644)?;
        }
        // M3：落盘前再复核一次 unit 归属，缩小“preflight 通过后 unit 被替换”
        // 的时间窗口；外来 unit 仍然拒绝覆盖。
        if write_unit {
            ensure_existing_unit_is_ours(&paths.unit, &paths, "覆盖/停止")?;
        }
        if let Some(unit) = &unit_contents {
            txn.write(&paths.unit, unit.as_bytes(), 0o644)?;
        }
        if copy_binary {
            txn.copy_file(&current_exe, &paths.binary, 0o755)?;
        }
        txn.commit()?;
        print_dry_run(&args, &paths, manage, write_unit, copy_binary, &current_exe);
        return Ok(());
    }

    let previous_state = read_optional(&paths.state)?;
    // 记录安装前服务状态：只有本次确实 enable/start 过才 stop/disable；原本
    // active 的话，回滚成功后尽力把旧服务恢复回来。
    let was_active = if manage {
        manager
            .is_active(AGENT_UNIT_NAME)
            .context("查询 agent 服务当前状态失败，拒绝在状态未知时安装")?
    } else {
        false
    };
    // 记录安装前的 MainPID：was_active 时必须确认 restart 产生了新进程，不能
    // 只凭 enable --now 成功或 enrollment 文件存在判断新二进制/配置已生效。
    let previous_pid = if manage && was_active {
        manager
            .main_pid(AGENT_UNIT_NAME)
            .context("读取当前 agent 服务 MainPID 失败，无法验证重启结果")?
    } else {
        0
    };
    ensure_active_service_pid(was_active, previous_pid)?;
    let mut started = false;
    let mut txn = InstallTxn::begin(&paths, false)?;

    let result = (|| -> Result<()> {
        // 先建数据目录再写配置：data_dir 是 agent 独占目录，安装前不存在时
        // 失败回滚会连同 enrollment 产生的证书一起删除（create_owned_dir）。
        txn.create_owned_dir(&paths.data_dir, 0o700)?;
        txn.write(&paths.config, config_bytes.as_bytes(), 0o600)?;
        if let Some(bytes) = &server_ca_bytes {
            // 与配置同事务写入；失败时 rollback 恢复旧文件/删除新建目录，
            // 不会留下半个 server-ca.pem。
            txn.write(&paths.data_dir.join(SERVER_CA_FILE), bytes, 0o644)?;
        }
        // M3：落盘前再复核一次 unit 归属，缩小“preflight 通过后 unit 被替换”
        // 的时间窗口；外来 unit 仍然拒绝覆盖。
        if write_unit {
            ensure_existing_unit_is_ours(&paths.unit, &paths, "覆盖/停止")?;
        }
        if let Some(unit) = &unit_contents {
            txn.write(&paths.unit, unit.as_bytes(), 0o644)?;
        }
        if copy_binary {
            txn.copy_file(&current_exe, &paths.binary, 0o755)?;
        }
        if manage {
            manager
                .daemon_reload()
                .context("systemctl daemon-reload 失败")?;
            // 先确认 systemd 解析到本次写入的 unit，之后才允许标记“已激活”；
            // 归属确认失败时不应 stop/disable 原本在跑的服务。真正的 enable /
            // restart 失败发生在 started=true 之后，回滚会恢复旧文件与服务。
            manager
                .ensure_fragment_is(AGENT_UNIT_NAME, &paths.unit)
                .context("systemd 未解析到本次写入的 agent unit，拒绝启动/重启")?;
            started = true;
            activate_agent_service(
                &manager,
                AGENT_UNIT_NAME,
                &paths.unit,
                was_active,
                previous_pid,
                SERVICE_START_VERIFY_TIMEOUT,
            )?;
            // enrollment 等待前后各确认一次：期间同名 unit 可能被更高优先级
            // 文件或 transient unit 顶替，不能在归属不确定时等待/记录成功。
            wait_for_enrollment(&paths.data_dir, ENROLLMENT_TIMEOUT)?;
            manager
                .ensure_fragment_is(AGENT_UNIT_NAME, &paths.unit)
                .context("enrollment 后 systemd 解析的 agent unit 已变化，拒绝写入安装状态")?;
        }
        // state 最后写：只有服务已启动且 enrollment 文件齐全才认为安装成功。
        let mut new_state = state.clone();
        new_state.upsert(
            Role::Agent,
            RoleState::new(&paths, VERSION, txn.backup_dir()),
        );
        new_state.save(&paths.state).context("写入安装状态失败")?;
        Ok(())
    })();

    if let Err(err) = result {
        return Err(rollback_agent_install(
            &manager,
            &paths,
            &mut txn,
            previous_state.as_deref(),
            started,
            was_active,
            manage,
            err,
        ));
    }

    txn.commit()?;
    print_installed(&args, &paths, manage, write_unit, copy_binary);
    Ok(())
}

/// 安装失败后的回滚：停掉本次启动的服务、恢复旧文件/state，并尽量恢复原有
/// active 服务。
///
/// 独立成函数便于用 fake [`ServiceControl`] 验证“失败后旧文件与旧服务状态
/// 都恢复”这条路径，而不必真的调用宿主机 systemd。
#[allow(clippy::too_many_arguments)]
fn rollback_agent_install(
    service: &dyn ServiceControl,
    paths: &Paths,
    txn: &mut InstallTxn,
    previous_state: Option<&[u8]>,
    started: bool,
    was_active: bool,
    manage: bool,
    error: anyhow::Error,
) -> anyhow::Error {
    let mut message = format!("安装失败: {error:#}");
    // 只有本次确实 enable/start/restart 过才 stop/disable；失败也不能阻止回滚。
    // 回滚同样只能操作 systemd 实际解析到的、本安装器写入的 unit；解析不一致
    // 时宁可留下服务，也不能停掉同名外来 unit。
    if started {
        match service.ensure_fragment_is(AGENT_UNIT_NAME, &paths.unit) {
            Ok(()) => {
                if let Err(stop_err) = service.stop(AGENT_UNIT_NAME) {
                    message.push_str(&format!("；停止本次启动的 agent 服务失败: {stop_err:#}"));
                }
                if let Err(disable_err) = service.disable(AGENT_UNIT_NAME) {
                    message.push_str(&format!(
                        "；禁用本次启动的 agent 服务失败: {disable_err:#}"
                    ));
                }
            }
            Err(guard_err) => message.push_str(&format!(
                "；回滚停止服务前确认 unit 归属失败，未 stop/disable 以避免影响外来服务: {guard_err:#}"
            )),
        }
    }
    let rollback_ok = match txn.rollback() {
        Ok(()) => true,
        Err(rollback_err) => {
            message.push_str(&format!("；回滚本次写入失败: {rollback_err:#}"));
            false
        }
    };
    // 回滚可能删除本次新建的 unit 或恢复旧 unit；reload 放在回滚之后，
    // 避免 systemd 继续持有已回滚文件的旧缓存。reload 错误并入返回错误。
    if manage {
        if let Err(reload_err) = service.daemon_reload() {
            message.push_str(&format!("；回滚后 daemon-reload 失败: {reload_err:#}"));
        }
    }
    if let Err(restore_err) = restore_state(&paths.state, previous_state) {
        message.push_str(&format!("；恢复安装状态失败: {restore_err:#}"));
    }
    // 原本 active 的旧服务在回滚成功后尽力恢复：先 enable 恢复自启，再 restart
    // 让恢复后的旧文件生效（只 enable --now 对仍在运行/半停止的服务不可靠）。
    if rollback_ok && started && was_active {
        match restore_agent_service_after_rollback(
            service,
            AGENT_UNIT_NAME,
            &paths.unit,
            SERVICE_START_VERIFY_TIMEOUT,
        ) {
            Ok(()) => {}
            Err(restart_err) => {
                message.push_str(&format!("；回滚后恢复原有 agent 服务失败: {restart_err:#}"))
            }
        }
    }
    anyhow!(message)
}

/// 执行 `rustboard-agent uninstall`。
pub fn uninstall(args: UninstallArgs) -> Result<()> {
    uninstall_impl(args, None)
}

/// 带可注入 systemd 的卸载实现（测试用 fake，生产只经 [`uninstall`] 进入）。
fn uninstall_impl(args: UninstallArgs, injected: Option<&dyn ServiceControl>) -> Result<()> {
    let system = detect_system();
    // P-01：同 install，必须用**原始** prefix 先校验；Paths::for_role 会把
    // `//`、尾斜杠与 `.` 归一化，先归一化再校验会让 `--prefix //` 指向生产路径。
    validate_install_prefix(&args.prefix).context("安装前缀不安全，拒绝卸载")?;
    let paths = Paths::for_role(Role::Agent, &args.prefix, path_overrides_uninstall(&args))?;
    // H1：顺序固定为 校验 prefix → 获取全局锁 → 读取 state。任何一步失败都不
    // 会停止服务或删除文件。
    validate_install_prefix(&paths.prefix).context("安装前缀不安全，拒绝卸载")?;
    let _lock = if args.dry_run || injected.is_some() {
        None
    } else {
        Some(InstallLock::acquire_global().context("获取全局卸载锁失败")?)
    };
    let state = InstallState::load(&paths.state)?;
    let record = state.role(Role::Agent).cloned();

    // 优先使用 state 记录：e2e 把 unit 放在 /run/systemd/system，卸载时不会
    // 再传 --unit-dir，必须仍然能停服务并删掉那个 unit。
    let own_paths = match &record {
        Some(role) => paths_from_record(&paths, role)?,
        None => paths.clone(),
    };
    let config_path = own_paths.config.clone();
    let data_dir = own_paths.data_dir.clone();
    let unit_path = own_paths.unit.clone();
    let binary_path = own_paths.binary.clone();
    let unit_name = unit_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("unit 路径缺少合法文件名: {}", unit_path.display()))?
        .to_string();

    // H1/M4：整体 preflight 必须在提示、停服、删除之前完成。`--purge` 意图来自
    // 参数；即使随后用户取消，额外校验也不会产生写入。
    preflight_uninstall_targets(&paths, &own_paths, args.purge)?;

    let unit_present = path_present(&unit_path);
    // R-S2：systemd 管理只认 is_systemd_unit_dir 的完整列表；prefix 内 unit 只删
    // 文件。注意 `check_service` 不能依赖 unit 文件是否存在：文件被删掉后同名
    // 服务仍可能 active/activating/reloading，卸载前必须查询并拒绝。
    let in_systemd_dir = injected.is_some() || unit_path.parent().is_some_and(is_systemd_unit_dir);
    let systemd_available = injected.is_some() || system.systemd;
    let check_service = systemd_available && in_systemd_dir;
    let service_candidate = unit_present && check_service;

    let binary_present = path_present(&binary_path);
    let config_present = path_present(&config_path);
    let data_present = path_present(&data_dir);

    if args.dry_run {
        print_uninstall_plan(
            &paths,
            &unit_path,
            &unit_name,
            &binary_path,
            &config_path,
            &data_dir,
            record.is_some(),
            args.purge,
            service_candidate,
        );
        return Ok(());
    }

    // 停服/删除前先问 systemd 自己：只有 FragmentPath 精确等于本安装器的 unit
    // 才允许 stop/disable。同名外来 / 更高优先级 unit 直接报错；FragmentPath
    // 为空（transient / 未加载）时只删自己的文件，不调用 systemctl。
    let unit_dir = unit_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| paths.prefix.clone());
    let fragment = if service_candidate {
        match injected {
            Some(service) => service
                .fragment_path(&unit_name)
                .with_context(|| format!("查询 systemd 实际解析的 unit {unit_name} 失败"))?,
            None => {
                let probe = ServiceManager::new(unit_dir.clone(), true, false);
                probe
                    .fragment_path(&unit_name)
                    .with_context(|| format!("查询 systemd 实际解析的 unit {unit_name} 失败"))?
            }
        }
    } else {
        None
    };
    let manage_service = match uninstall_unit_action(
        systemd_available,
        unit_present,
        in_systemd_dir,
        fragment.as_deref(),
        &unit_path,
    ) {
        UninstallUnitAction::StopDisable => true,
        UninstallUnitAction::FileOnly => {
            if service_candidate && fragment.is_none() {
                eprintln!(
                    "提示：systemd 未解析到 {unit_name} 的 unit 文件（可能为 transient/未加载）；\
                     只删除本安装器的 unit 文件，不调用 systemctl"
                );
            }
            false
        }
        UninstallUnitAction::RefuseForeign => {
            let actual = fragment
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<未解析>".to_string());
            bail!(
                "systemd 实际解析的 unit 是 {actual}，不是本安装器的 {}；拒绝 stop/disable \
                 与删除，避免操作同名外来/更高优先级 unit",
                unit_path.display()
            );
        }
    };

    // purge 必须二次确认；非 TTY 且没有 --yes 时 Prompt 直接报错，不会误删。
    let purge = if args.purge {
        if args.yes {
            true
        } else {
            Prompt::new(false).confirm(
                &format!(
                    "将删除配置 {} 与数据目录 {}，确认继续？",
                    config_path.display(),
                    data_dir.display()
                ),
                false,
            )?
        }
    } else {
        false
    };
    if args.purge && !purge {
        println!("已取消 purge；配置与数据目录保留。");
    }

    let has_work = unit_present
        || binary_present
        || record.is_some()
        || (purge && (config_present || data_present));
    if !has_work {
        println!("未发现 rustboard-agent 的 unit/二进制/安装状态，无需卸载。");
        if !purge {
            println!("配置与数据目录（若存在）保持不变；使用 --purge 可显式删除。");
        }
        return Ok(());
    }

    if manage_service && injected.is_none() {
        require_root().context("停止/禁用系统 agent 服务需要 root")?;
    }
    let manager = ServiceManager::new(unit_dir, check_service, false);
    let service: &dyn ServiceControl = injected.unwrap_or(&manager);
    execute_uninstall(
        &paths,
        &own_paths,
        state,
        record.as_ref(),
        &unit_name,
        purge,
        manage_service,
        check_service,
        service,
    )
}

/// 执行已通过 preflight / 确认的 agent 卸载动作。
///
/// 独立成函数便于测试注入 [`ServiceControl`]：stop 失败或无法确认 inactive 时
/// 必须在创建删除事务之前返回，unit、binary、config、data 与 state 全部保留。
#[allow(clippy::too_many_arguments)]
fn execute_uninstall(
    paths: &Paths,
    own_paths: &Paths,
    state: InstallState,
    record: Option<&RoleState>,
    unit_name: &str,
    purge: bool,
    manage_service: bool,
    check_service: bool,
    service: &dyn ServiceControl,
) -> Result<()> {
    let unit_path = own_paths.unit.clone();
    let binary_path = own_paths.binary.clone();
    let config_path = own_paths.config.clone();
    let data_dir = own_paths.data_dir.clone();

    // 停服前再复核一次 unit 归属与 FragmentPath；确认不了就绝不 stop/disable，
    // 也不创建删除事务。stop 失败或无法确认已停止时立即返回，保留全部文件。
    if path_present(&unit_path) {
        ensure_existing_unit_is_ours(&unit_path, own_paths, "停止/删除")?;
    }
    if manage_service {
        service
            .ensure_fragment_is(unit_name, &unit_path)
            .context("systemd 实际解析的 agent unit 已变化，拒绝 stop/disable")?;
        stop_service_checked(service, unit_name, "agent")?;
    } else if check_service {
        // unit 文件不存在 / FragmentPath 为空（transient）时不能 stop，但同名
        // 服务仍在运行就绝不能删除与 purge。
        ensure_service_stopped(service, unit_name, "agent")?;
    }

    // 在删除 unit 之前清理 wants 链接：remove_enable_symlink 需要按本安装
    // unit 的真实路径确认链接归属，unit 文件缺失时它会保留链接（不按名字删）。
    if check_service {
        if let Some(dir) = unit_path.parent() {
            remove_enable_symlink(dir, unit_name, &unit_path).context("清理 agent 启用链接失败")?;
        }
    }

    let mut txn = InstallTxn::begin(paths, false)?;
    let result = (|| -> Result<()> {
        txn.remove(&unit_path)?;
        if manage_service {
            service
                .daemon_reload()
                .context("删除 unit 后 daemon-reload 失败")?;
        }
        txn.remove(&binary_path)?;

        // 先完成 purge，再删除 state 记录：state 是回滚/重试的最后依据。
        if purge {
            txn.remove(&config_path)?;
            remove_data_dir(&data_dir)?;
        }

        if record.is_some() {
            let mut new_state = state.clone();
            new_state.remove_role(Role::Agent);
            if new_state.roles.is_empty() {
                txn.remove(&paths.state)?;
            } else {
                let text = toml::to_string_pretty(&new_state).context("序列化安装状态失败")?;
                txn.write(&paths.state, text.as_bytes(), 0o600)?;
            }
        }
        Ok(())
    })();

    if let Err(err) = result {
        let mut message = format!("卸载失败: {err:#}");
        if let Err(rollback_err) = txn.rollback() {
            message.push_str(&format!("；回滚本次删除失败: {rollback_err:#}"));
        }
        if manage_service {
            if let Err(reload_err) = service.daemon_reload() {
                message.push_str(&format!("；回滚后 daemon-reload 失败: {reload_err:#}"));
            }
        }
        return Err(anyhow!(message));
    }
    txn.commit()?;
    print_uninstalled(&config_path, &data_dir, purge);
    Ok(())
}

/// 从 CLI 参数生成 [`PathOverrides`]（安装）。
fn path_overrides(args: &InstallArgs) -> PathOverrides {
    PathOverrides {
        config: args.config.clone(),
        data_dir: args.data_dir.clone(),
        unit_dir: args.unit_dir.clone(),
        bin_dir: None,
    }
}

/// 从 CLI 参数生成 [`PathOverrides`]（卸载）。
fn path_overrides_uninstall(args: &UninstallArgs) -> PathOverrides {
    PathOverrides {
        config: args.config.clone(),
        data_dir: args.data_dir.clone(),
        unit_dir: args.unit_dir.clone(),
        bin_dir: None,
    }
}

/// 幂等/覆盖决策。
///
/// - `--force`：有旧配置就复用（token 可省），否则按新装处理；
/// - 无 `--force` 且 state+配置+二进制/unit+enrollment 齐全：已安装，直接返回 0；
/// - state 存在但记录的文件缺失：报错要求 `--force`，不静默覆盖；
/// - 只有配置没有 state：旧手工安装，报错指向 `--force`/upgrade。
fn decide_mode(
    state_present: bool,
    enrolled: bool,
    config_exists: bool,
    recorded_files_present: bool,
    force: bool,
) -> Result<InstallMode> {
    if force {
        return Ok(if config_exists {
            InstallMode::ForceReuse
        } else {
            InstallMode::Fresh
        });
    }
    if state_present {
        if enrolled && recorded_files_present {
            return Ok(InstallMode::AlreadyInstalled);
        }
        bail!(
            "安装状态已存在但记录的文件缺失（配置、二进制、unit 或 enrollment 凭据）；\
             请使用 --force 重新安装"
        );
    }
    if config_exists {
        bail!(
            "配置已存在但安装状态缺失：旧的手工安装请先执行 upgrade（Phase A 暂未提供），\
             或使用 --force 覆盖（数据目录会保留）"
        );
    }
    if enrolled {
        bail!("数据目录已纳管但安装状态缺失；请使用 --force 重新安装");
    }
    Ok(InstallMode::Fresh)
}

/// 读取 `--force` 复用的旧配置。
///
/// 不把底层 TOML 解析错误直接往上抛：toml 诊断会回显出错行的原文，而该行可能
/// 就是 `token = "..."`。安装器约定错误信息不包含 token，因此只报告路径与
/// 「配置不合法」，详细诊断由用户自行查看（或 `rustboard-agent info`）。
///
/// `dry_run` 必须零写入：`AgentConfig::load` 会先 `harden(path, 0600)`，因此
/// dry-run 改走只读分支，绝不 chmod 用户文件。
fn load_existing_config(path: &Path, dry_run: bool) -> Result<AgentConfig> {
    if dry_run {
        // 只读分支同样拒绝符号链接祖先：即使不写入，也不让 root 沿着攻击者
        // 可控的链接去读取任意文件。
        reject_symlink_components(path)
            .with_context(|| format!("检查已有配置路径 {} 失败", path.display()))?;
        let text = read_bounded_text(path, CONFIG_MAX_BYTES as usize, "已有 agent 配置")?;
        return toml::from_str(&text).map_err(|_| {
            anyhow!(
                "读取已有配置失败: {}（文件不是合法的 agent 配置；为避免泄露 token，\
                 不打印解析详情；dry-run 不修改文件权限）",
                path.display()
            )
        });
    }
    AgentConfig::load(path).map_err(|_| {
        anyhow!(
            "读取已有配置失败: {}（文件不是合法的 agent 配置；为避免泄露 token，不打印解析详情）",
            path.display()
        )
    })
}

/// 由 state 记录重建 [`Paths`]，用于 unit 归属比较与卸载目标。
///
/// state 中的路径字段可能被篡改，因此全部重新归一化并拒绝 `..`；真正的
/// 删除 allowlist 由 [`validate_managed_path`] 在 preflight 中完成。
fn paths_from_record(base: &Paths, record: &RoleState) -> Result<Paths> {
    Ok(Paths {
        prefix: base.prefix.clone(),
        config: normalize_absolute(&record.config, "安装状态记录的配置路径")?,
        data_dir: normalize_absolute(&record.data_dir, "安装状态记录的数据目录")?,
        unit: normalize_absolute(&record.unit, "安装状态记录的 unit 路径")?,
        binary: normalize_absolute(&record.binary, "安装状态记录的二进制路径")?,
        state: base.state.clone(),
        backup_root: base.backup_root.clone(),
    })
}

/// 安装落盘前校验 config/data/unit/binary：allowlist + 字符集 + 回滚安全。
fn preflight_install_paths(paths: &Paths) -> Result<()> {
    for (target, kind, label) in [
        (&paths.config, ManagedPathKind::Config, "配置路径"),
        (&paths.data_dir, ManagedPathKind::Data, "数据目录"),
        (&paths.unit, ManagedPathKind::Unit, "unit 路径"),
        (&paths.binary, ManagedPathKind::Binary, "二进制路径"),
    ] {
        validate_managed_path(Role::Agent, &paths.prefix, target, kind)
            .with_context(|| format!("{label}不允许写入: {}", target.display()))?;
        validate_install_path_chars(target, label)?;
    }
    // 数据目录不能吞掉 install-state / 事务备份：否则失败回滚的
    // create_owned_dir 会把 state 和回滚材料一起递归删除。
    if paths.state.starts_with(&paths.data_dir) || paths.backup_root.starts_with(&paths.data_dir) {
        bail!(
            "数据目录 {} 不能包含安装状态或事务备份目录，请改用更具体的数据目录",
            paths.data_dir.display()
        );
    }
    if paths.config == paths.state {
        bail!("配置路径不能与安装状态文件相同: {}", paths.config.display());
    }
    Ok(())
}

/// 卸载 preflight：路径 allowlist、目标类型、unit 归属；全部通过才允许停服/删除。
fn preflight_uninstall_targets(paths: &Paths, own_paths: &Paths, purge: bool) -> Result<()> {
    validate_managed_path(
        Role::Agent,
        &paths.prefix,
        &own_paths.unit,
        ManagedPathKind::Unit,
    )
    .context("待删除 unit 路径不在允许范围")?;
    validate_managed_path(
        Role::Agent,
        &paths.prefix,
        &own_paths.binary,
        ManagedPathKind::Binary,
    )
    .context("待删除二进制路径不在允许范围")?;
    // P-04：config/data 即使不 purge（本次不删除）也必须校验：state 文件可能
    // 被篡改，卸载摘要与重试都会继续使用这些路径。allowlist 与字符集检查始终
    // 执行；存在时的类型 / 非符号链接检查也始终执行，只有与递归删除相关的
    // “data_dir 包含 state/backup”检查才依赖 --purge。
    validate_managed_path(
        Role::Agent,
        &paths.prefix,
        &own_paths.config,
        ManagedPathKind::Config,
    )
    .context("配置路径不在允许范围")?;
    validate_install_path_chars(&own_paths.config, "配置路径")?;
    validate_managed_path(
        Role::Agent,
        &paths.prefix,
        &own_paths.data_dir,
        ManagedPathKind::Data,
    )
    .context("数据目录不在允许范围")?;
    validate_install_path_chars(&own_paths.data_dir, "数据目录")?;
    if purge {
        // 数据目录不能吞掉 state / 备份（即使目录当前不存在，也按路径关系拒绝）：
        // 递归删除会毁掉回滚材料与其余角色的安装记录。
        if paths.state.starts_with(&own_paths.data_dir)
            || paths.backup_root.starts_with(&own_paths.data_dir)
        {
            bail!(
                "拒绝 purge 数据目录 {}：该目录包含安装状态或事务备份目录，请改用更具体的数据目录",
                own_paths.data_dir.display()
            );
        }
    }

    // unit 是 systemd 的操作对象：存在时必须是普通文件、非符号链接，且内容
    // 必须由本安装器为记录中的 prefix/binary/config 渲染。外来 unit 一律报错，
    // 后续不会 stop/disable，也不会删除。
    ensure_existing_unit_is_ours(&own_paths.unit, own_paths, "停止/删除")?;
    ensure_regular_file_if_present(&own_paths.binary, "二进制")?;
    ensure_regular_file_if_present(&own_paths.config, "配置")?;
    ensure_directory_if_present(&own_paths.data_dir, "数据目录")?;
    Ok(())
}

/// 确认已存在的 unit 是本安装器为 `own_paths` 渲染的普通文件；不存在时返回 Ok。
fn ensure_existing_unit_is_ours(unit: &Path, own_paths: &Paths, action: &str) -> Result<()> {
    let meta = match std::fs::symlink_metadata(unit) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            reject_symlink_components(unit)
                .with_context(|| format!("检查 unit {} 的路径组件失败", unit.display()))?;
            return Ok(());
        }
        Err(err) => return Err(err).with_context(|| format!("检查 unit {} 失败", unit.display())),
    };
    if meta.file_type().is_symlink() {
        bail!(
            "现存 unit {} 是符号链接，不是本安装器为当前 prefix 生成的普通文件，拒绝{action}",
            unit.display()
        );
    }
    if !meta.is_file() {
        bail!("现存 unit {} 不是普通文件，拒绝{action}", unit.display());
    }
    reject_symlink_components(unit)
        .with_context(|| format!("检查 unit {} 的路径组件失败", unit.display()))?;
    let contents = read_bounded_text(unit, UNIT_MAX_BYTES, "现存 unit")?;
    if !unit_is_ours(Role::Agent, own_paths, &contents) {
        bail!(
            "现存 unit {} 不是本安装器为当前 prefix 生成的，拒绝{action}；--force 也不会覆盖外来 unit",
            unit.display()
        );
    }
    Ok(())
}

/// 启用 systemd 管理时要求 unit 位于 systemd 真正读取的目录。
///
/// prefix 内的 unit 只是普通文件：`systemctl enable/start` 会按名字解析到系统
/// unit 目录中的同名 unit（或直接失败），因此必须先拒绝，避免 enable/restart/
/// stop 作用到外来服务。
fn ensure_manageable_unit(unit: &Path) -> Result<()> {
    let parent = unit
        .parent()
        .ok_or_else(|| anyhow!("unit 路径缺少父目录: {}", unit.display()))?;
    if !is_systemd_unit_dir(parent) {
        bail!(
            "systemd 不会读取 prefix 内 unit；请用 --unit-dir /etc/systemd/system 或 \
             /run/systemd/system（当前 unit: {}）",
            unit.display()
        );
    }
    Ok(())
}

/// 幂等分支核对 systemd 实际解析结果。
///
/// `fragment` 是 `systemctl show -p FragmentPath` 的归一化结果，`active` 只在
/// `fragment` 为空时查询。匹配、同名外来、unit 缺失但 active、未解析四种情况
/// 都必须在打印“已安装”之前给出明确结论（纯函数，便于单测）。
fn verify_installed_fragment(fragment: Option<&Path>, active: bool, expected: &Path) -> Result<()> {
    match fragment {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => bail!(
            "systemd 实际解析的 {AGENT_UNIT_NAME} 是 {}，不是安装记录的 {}；同名外来/\
             更高优先级 unit 会抢走 enable/stop，拒绝按“已安装”返回；请先处理同名 unit \
             或使用 --force 重新安装",
            actual.display(),
            expected.display()
        ),
        None if active => bail!(
            "{AGENT_UNIT_NAME} 同名服务处于 active，但 systemd 的 FragmentPath 为空\
             （transient/外来 unit？）；拒绝按“已安装”返回，避免后续操作作用到来源不明的服务"
        ),
        None => bail!(
            "systemd 未解析到 {AGENT_UNIT_NAME} 的 unit 文件（FragmentPath 为空），与安装\
             记录 {} 不符；请执行 systemctl daemon-reload 或使用 --force 重新安装",
            expected.display()
        ),
    }
}

/// 查询 systemd 实际解析的 unit 并交给 [`verify_installed_fragment`] 判定。
fn ensure_installed_fragment(manager: &ServiceManager, expected: &Path) -> Result<()> {
    let fragment = manager.fragment_path(AGENT_UNIT_NAME)?;
    // FragmentPath 为空时才需要 is-active：unit 文件缺失但同名服务仍在运行时
    // 必须拒绝，不能把 transient/外来服务当成自己的安装。
    let active = if fragment.is_none() {
        manager.is_active(AGENT_UNIT_NAME)?
    } else {
        false
    };
    verify_installed_fragment(fragment.as_deref(), active, expected)
}

/// 卸载时对同名 systemd unit 的处理决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UninstallUnitAction {
    /// FragmentPath 精确等于本安装器的 unit：允许 stop/disable。
    StopDisable,
    /// 只删除本安装器的 unit 文件，不调用 systemctl。
    FileOnly,
    /// FragmentPath 指向其他文件：拒绝 stop/disable 与删除。
    RefuseForeign,
}

/// 纯函数：根据 systemd 可用性、unit 文件是否存在 / 是否在 systemd 目录，以及
/// FragmentPath 决定卸载时的 systemd 动作。
///
/// - systemd 不可用、unit 不存在或不在 systemd unit 目录：只删文件（unit 不
///   存在时绝不 stop，即使同名服务 active）；
/// - FragmentPath 等于本安装器的 unit：允许 stop/disable；
/// - FragmentPath 指向其他文件：拒绝操作；
/// - FragmentPath 为空：只删文件，不调用 systemctl。
fn uninstall_unit_action(
    systemd_available: bool,
    unit_present: bool,
    in_systemd_unit_dir: bool,
    fragment: Option<&Path>,
    unit: &Path,
) -> UninstallUnitAction {
    if !systemd_available || !unit_present || !in_systemd_unit_dir {
        return UninstallUnitAction::FileOnly;
    }
    match fragment {
        Some(actual) if actual == unit => UninstallUnitAction::StopDisable,
        Some(_) => UninstallUnitAction::RefuseForeign,
        None => UninstallUnitAction::FileOnly,
    }
}

/// 目标存在时必须是普通文件（拒绝符号链接 / 目录）。
fn ensure_regular_file_if_present(path: &Path, label: &str) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            reject_symlink_components(path)
                .with_context(|| format!("检查{label} {} 的路径组件失败", path.display()))?;
            return Ok(());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("检查{label} {} 失败", path.display()));
        }
    };
    if meta.file_type().is_symlink() {
        bail!("{label} {} 是符号链接，拒绝删除", path.display());
    }
    if !meta.is_file() {
        bail!("{label} {} 不是普通文件，拒绝删除", path.display());
    }
    reject_symlink_components(path)
        .with_context(|| format!("检查{label} {} 的路径组件失败", path.display()))?;
    Ok(())
}

/// 目标存在时必须是目录（拒绝符号链接 / 普通文件）。
fn ensure_directory_if_present(path: &Path, label: &str) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            reject_symlink_components(path)
                .with_context(|| format!("检查{label} {} 的路径组件失败", path.display()))?;
            return Ok(());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("检查{label} {} 失败", path.display()));
        }
    };
    if meta.file_type().is_symlink() {
        bail!("{label} {} 是符号链接，拒绝递归删除", path.display());
    }
    if !meta.is_dir() {
        bail!("{label} {} 不是目录，拒绝递归删除", path.display());
    }
    reject_symlink_components(path)
        .with_context(|| format!("检查{label} {} 的路径组件失败", path.display()))?;
    Ok(())
}

/// 安装目标路径字符集：control / `$` / `%` / 引号 / 反斜杠会与 systemd 或
/// shell 的转义规则冲突，必须在写盘前拒绝（prefix 已由前缀校验覆盖）。
fn validate_install_path_chars(path: &Path, label: &str) -> Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("{label}不是有效 UTF-8: {}", path.display()))?;
    if let Some(ch) = text.chars().find(|ch| ch.is_control()) {
        bail!("{label}不能包含控制字符 {ch:?}: {}", path.display());
    }
    if let Some(ch) = text
        .chars()
        .find(|ch| matches!(ch, '$' | '%' | '"' | '\'' | '\\'))
    {
        bail!(
            "{label}不能包含 `{ch}` 等 systemd / shell 特殊字符: {}",
            path.display()
        );
    }
    Ok(())
}

/// 有上限地读取 UTF-8 文本；拒绝符号链接、非普通文件与超限文件。
fn read_bounded_text(path: &Path, limit: usize, label: &str) -> Result<String> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("读取{label} {} 失败", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("{label} {} 是符号链接，拒绝读取", path.display());
    }
    if !meta.is_file() {
        bail!("{label} {} 不是普通文件，拒绝读取", path.display());
    }
    if meta.len() > limit as u64 {
        bail!("{label} {} 超过 {limit} 字节上限，拒绝读取", path.display());
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("打开{label} {} 失败", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("读取{label} {} 元数据失败", path.display()))?;
    if !opened.is_file() {
        bail!("{label} {} 不是普通文件，拒绝读取", path.display());
    }

    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("读取{label} {} 失败", path.display()))?;
    if bytes.len() > limit {
        bail!("{label} {} 超过 {limit} 字节上限，拒绝读取", path.display());
    }
    String::from_utf8(bytes).map_err(|_| anyhow!("{label} {} 不是有效 UTF-8", path.display()))
}

/// 读取 enrollment token：只接受 0600 普通文件，trim 后必须非空。
///
/// 错误信息只包含路径，不包含 token 内容。
fn read_token(path: &Path) -> Result<String> {
    let bytes = read_private_file(path, TOKEN_MAX_BYTES)
        .with_context(|| format!("读取 --token-file 失败: {}", path.display()))?;
    let token = String::from_utf8(bytes)
        .map_err(|_| anyhow!("--token-file 内容不是合法 UTF-8: {}", path.display()))?;
    let token = token.trim();
    if token.is_empty() {
        bail!("--token-file 内容为空: {}", path.display());
    }
    Ok(token.to_string())
}

/// system-roots 不使用 `--fingerprint`；显式传入必须拒绝，不能静默忽略。
fn reject_system_roots_fingerprint(mode: AgentTlsMode, fingerprint: Option<&str>) -> Result<()> {
    if mode == AgentTlsMode::SystemRoots && fingerprint.is_some() {
        bail!("system-roots 模式不使用 --fingerprint；公共 ACME 证书由系统根 + URL 主机名校验");
    }
    Ok(())
}

/// 新装时校验 `--tls-mode` 与 `--fingerprint` / `--server-ca` 的组合。
///
/// 抽成纯函数便于单测；`--force` 复用旧配置时模式可能来自旧配置，因此不能
/// 直接复用这个函数（见 `install` 内的合并后校验）。
fn validate_fresh_tls_args(
    mode: AgentTlsMode,
    fingerprint: Option<&str>,
    server_ca: Option<&Path>,
) -> Result<()> {
    match mode {
        AgentTlsMode::Fingerprint => {
            if fingerprint.is_none() {
                bail!("新装必须指定 --fingerprint（hub 服务端证书 SHA-256 指纹）");
            }
            if server_ca.is_some() {
                bail!("fingerprint 模式不使用 --server-ca；私有 CA 请改用 --tls-mode custom-ca");
            }
        }
        AgentTlsMode::SystemRoots => {
            reject_system_roots_fingerprint(mode, fingerprint)?;
            if server_ca.is_some() {
                bail!("system-roots 模式不使用 --server-ca；公共 ACME 证书由系统根校验");
            }
        }
        AgentTlsMode::CustomCa => {
            if server_ca.is_none() {
                bail!("custom-ca 模式新装必须指定 --server-ca（服务端 CA 证书的 PEM 路径）");
            }
        }
    }
    Ok(())
}

/// 读取并校验 `--server-ca`：
///
/// - 必须是绝对路径，且从 `/` 到目标不存在任何符号链接组件；
/// - 0600/0644 的普通文件、非符号链接、≤1 MiB（防止误把目录/私钥/大文件读进内存）；
/// - UTF-8 PEM，至少一张可解析证书（可包含多张，作为多根 bundle 复制）。
///
/// 错误信息只包含路径与原因，不打印证书内容。返回原始字节供事务原样复制。
fn read_server_ca(path: &Path) -> Result<Vec<u8>> {
    if !path.is_absolute() {
        bail!("--server-ca 必须是绝对路径: {}", path.display());
    }
    // 逐组件拒绝符号链接：只检查最终文件挡不住父目录被替换成链接后读取任意文件。
    // context 放在外层，底层“符号链接”根因仍保留在 `{err:#}` 错误链中。
    reject_symlink_components(path)
        .with_context(|| format!("--server-ca 路径不安全: {}", path.display()))?;
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("读取 --server-ca {} 失败", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("--server-ca {} 是符号链接，拒绝读取", path.display());
    }
    if !meta.is_file() {
        bail!("--server-ca {} 不是普通文件，拒绝读取", path.display());
    }
    if meta.len() > SERVER_CA_MAX_BYTES as u64 {
        bail!(
            "--server-ca {} 超过 {} 字节上限，拒绝读取",
            path.display(),
            SERVER_CA_MAX_BYTES
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o644 {
            bail!(
                "--server-ca {} 权限必须是 0600 或 0644，实际 {mode:04o}",
                path.display()
            );
        }
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("打开 --server-ca {} 失败", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("读取 --server-ca {} 元数据失败", path.display()))?;
    if !opened.is_file() {
        bail!("--server-ca {} 不是普通文件，拒绝读取", path.display());
    }

    let mut bytes = Vec::new();
    file.take(SERVER_CA_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("读取 --server-ca {} 失败", path.display()))?;
    if bytes.len() > SERVER_CA_MAX_BYTES {
        bail!(
            "--server-ca {} 超过 {} 字节上限，拒绝读取",
            path.display(),
            SERVER_CA_MAX_BYTES
        );
    }
    let pem = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow!("--server-ca {} 不是有效 UTF-8 PEM", path.display()))?;
    // 先按 PEM 边界拒绝私钥/公钥/CSR 混入，再解析证书。`load_certs` 只读取
    // CERTIFICATE 段，若只做它会把同一文件里的私钥原样复制到 0644 的
    // data_dir/server-ca.pem。
    tls::ensure_certificate_only_pem(pem).with_context(|| {
        format!(
            "--server-ca {} 不是仅含 CERTIFICATE 的 PEM（拒绝复制私钥/公钥/CSR）",
            path.display()
        )
    })?;
    tls::load_certs(pem)
        .with_context(|| format!("--server-ca {} 不是合法 PEM 证书", path.display()))?;
    Ok(bytes)
}

/// 校验并归一化指纹为 64 位小写 hex。
fn normalize_fingerprint(raw: &str) -> Result<String> {
    let digest = tls::parse_fingerprint(raw)
        .map_err(|err| anyhow!("--fingerprint 不是合法的 SHA-256 指纹: {err}"))?;
    let mut normalized = String::with_capacity(64);
    for byte in digest {
        normalized.push_str(&format!("{byte:02x}"));
    }
    Ok(normalized)
}

/// 指纹模式（旧行为）下 `wss://` 必须能解析出指纹；其他模式下指纹可选，
/// 但一旦提供也必须合法（避免把拼错的旧指纹静默带进新配置）。
fn validate_fingerprint(cfg: &AgentConfig) -> Result<()> {
    if cfg.hub_url.starts_with("wss://")
        && (cfg.tls_mode == AgentTlsMode::Fingerprint || !cfg.server_fingerprint.trim().is_empty())
    {
        tls::parse_fingerprint(&cfg.server_fingerprint)
            .map_err(|err| anyhow!("server_fingerprint 不是合法 SHA-256 指纹: {err}"))?;
    }
    Ok(())
}

/// 数据目录是否已有完整身份材料（五件齐全，允许旧安装暂时缺 marker）。
///
/// 不用 `exists()`：空文件或符号链接都不算，避免幂等判断把坏状态当成功。
fn has_enrollment_identity(data_dir: &Path) -> bool {
    ENROLLMENT_FILES
        .iter()
        .all(|name| file_is_nonempty(&data_dir.join(name)))
}

/// enrollment 是否真正完成：五件身份文件 + 最后写入的完成标记。
///
/// 不能用「证书/secret 已出现」判完成：agent 在写完 marker 之前崩溃时，
/// 安装器不能提前报成功。marker 也必须是普通非空文件（符号链接不算）。
fn is_enrolled_data_dir(data_dir: &Path) -> bool {
    has_enrollment_identity(data_dir) && file_is_nonempty(&data_dir.join(ENROLLMENT_MARKER))
}

/// 安装器等待 enrollment 的完成条件；与 agent 主程序 `is_enrolled` 一致。
fn enrollment_complete(data_dir: &Path) -> bool {
    is_enrolled_data_dir(data_dir)
}

/// 文件存在、是普通文件且非空（符号链接一律不算）。
fn file_is_nonempty(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => meta.file_type().is_file() && meta.len() > 0,
        Err(_) => false,
    }
}

/// 已 active 的服务必须能读到有效旧 MainPID，否则 restart 无法验证是否真的
/// 切换了进程（`enable --now` 的 no-op 会被误报成功），应 fail closed。
fn ensure_active_service_pid(was_active: bool, previous_pid: u32) -> Result<()> {
    if was_active && previous_pid == 0 {
        bail!(
            "agent 服务当前处于 active，但 MainPID 为 0；无法验证 restart 是否切换进程，拒绝安装"
        );
    }
    Ok(())
}

/// 等待 systemd 报告 agent 新进程稳定运行。
///
/// `previous_pid` 是安装前记录的主进程（0 表示安装前未运行或无法区分）。重启后
/// 必须同时满足：
/// - `ActiveState` 精确为 `active`；
/// - `MainPID` > 0，且与已知的旧 PID 不同（旧 PID 为 0 时不跳过稳定性校验）；
/// - 同一 MainPID 连续两次（间隔约 500ms）保持 active，防止 crash-loop 的
///   瞬时 active / 旧 enrollment 文件被误判为成功。
fn wait_for_agent_process(
    service: &dyn ServiceControl,
    unit: &str,
    previous_pid: Option<u32>,
    timeout: Duration,
) -> Result<u32> {
    let deadline = Instant::now() + timeout;
    let mut candidate: Option<(u32, Instant)> = None;
    loop {
        let state = service
            .active_state(unit)
            .with_context(|| format!("查询 {unit} 的 ActiveState 失败"))?;
        if state == ServiceState::Active {
            let pid = service
                .main_pid(unit)
                .with_context(|| format!("查询 {unit} 的 MainPID 失败"))?;
            let changed = previous_pid.is_none_or(|old| old == 0 || pid != old);
            if pid > 0 && changed {
                match candidate {
                    Some((same_pid, since))
                        if same_pid == pid && since.elapsed() >= SERVICE_STABLE_INTERVAL =>
                    {
                        return Ok(pid);
                    }
                    Some((same_pid, _)) if same_pid == pid => {}
                    _ => candidate = Some((pid, Instant::now())),
                }
            } else {
                candidate = None;
            }
        } else {
            // activating / reloading / deactivating / failed 都不算稳定运行。
            candidate = None;
        }
        let now = Instant::now();
        if now >= deadline {
            let expected = previous_pid
                .filter(|pid| *pid > 0)
                .map(|pid| format!("（安装前 MainPID={pid}）"))
                .unwrap_or_default();
            bail!(
                "agent 服务未在 {timeout:?} 内确认切换到新进程并稳定运行{expected}                 （要求 ActiveState=active 且同一 MainPID 连续 {}ms）；                 不能用 enable --now / enrollment 文件存在代替 restart 验证",
                SERVICE_STABLE_INTERVAL.as_millis()
            );
        }
        std::thread::sleep(SERVICE_START_POLL.min(deadline - now));
    }
}

/// 启动 / 重启 agent 服务并验证新进程。
///
/// - `was_active`：先 `enable --now` 保证开机自启，再 `restart` 强制加载新
///   二进制与配置，并等待 MainPID 变化；
/// - 原本未运行：`enable --now` 启动，等待出现新 MainPID；
/// - 调用前后都校验 FragmentPath，防止同名外来 unit 在窗口内抢占。
fn activate_agent_service(
    service: &dyn ServiceControl,
    unit: &str,
    expected_unit: &Path,
    was_active: bool,
    previous_pid: u32,
    timeout: Duration,
) -> Result<u32> {
    service
        .ensure_fragment_is(unit, expected_unit)
        .context("systemd 未解析到本次写入的 agent unit，拒绝启动/重启")?;
    service
        .enable_now(unit)
        .context("启用 agent 服务失败（systemctl enable --now）")?;
    if was_active {
        // 关键：已运行的服务仅 enable --now 不会加载新文件，必须 restart。
        service
            .restart(unit)
            .context("重启 agent 服务失败（systemctl restart）")?;
    }
    let pid = wait_for_agent_process(
        service,
        unit,
        if was_active { Some(previous_pid) } else { None },
        timeout,
    )
    .context("agent 服务未确认使用新进程，拒绝写入安装状态")?;
    service
        .ensure_fragment_is(unit, expected_unit)
        .context("启动/重启后 systemd 解析的 agent unit 已变化，拒绝写入安装状态")?;
    Ok(pid)
}

/// 回滚后恢复原本 active 的旧服务。
///
/// 回滚已恢复旧 unit/config/binary；这里先 enable 恢复开机自启，再 restart
/// 让旧文件真正生效（若失败前的 stop 未成功，仅 enable --now 不会重启）。
fn restore_agent_service_after_rollback(
    service: &dyn ServiceControl,
    unit: &str,
    expected_unit: &Path,
    timeout: Duration,
) -> Result<()> {
    service
        .ensure_fragment_is(unit, expected_unit)
        .context("回滚后 unit 归属已变化，未恢复原有 agent 服务")?;
    service
        .enable_now(unit)
        .context("回滚后重新启用 agent 服务失败")?;
    service
        .restart(unit)
        .context("回滚后重启 agent 旧服务失败")?;
    // 尽力确认服务重新运行；旧 PID 已无意义，只要求出现有效 MainPID。
    wait_for_agent_process(service, unit, None, timeout).context("回滚后 agent 服务未重新运行")?;
    Ok(())
}

/// 轮询等待 enrollment 落盘；超时错误只列出缺失文件名，不读取内容。
fn wait_for_enrollment(data_dir: &Path, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if enrollment_complete(data_dir) {
            return Ok(());
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            break;
        }
        std::thread::sleep(ENROLLMENT_POLL.min(timeout - elapsed));
    }
    let missing: Vec<&str> = ENROLLMENT_FILES
        .into_iter()
        .chain(std::iter::once(ENROLLMENT_MARKER))
        .filter(|name| !file_is_nonempty(&data_dir.join(name)))
        .collect();
    bail!(
        "等待 agent 完成 enrollment 超时（{}s），缺少或为空: {}；\
         请检查 hub 地址、指纹与 token 是否有效（enrollment.complete 由 agent 在全部身份文件写完后最后写入）",
        timeout.as_secs(),
        if missing.is_empty() {
            "未知".to_string()
        } else {
            missing.join("、")
        }
    )
}

/// 路径存在（不跟随最终符号链接）。
fn path_present(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok()
}

/// 两个路径是否指向同一个文件；目标不存在时返回 false。
fn same_file(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// 读取可选文件内容（用于安装失败时恢复旧 state）。
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

/// 恢复安装前的 state：原来有就原子写回，原来没有就删除本次可能写出的文件。
fn restore_state(path: &Path, previous: Option<&[u8]>) -> Result<()> {
    match previous {
        Some(bytes) => rustboard_common::fsutil::atomic_write(path, bytes, 0o600)
            .with_context(|| format!("恢复安装状态 {} 失败", path.display())),
        None => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("删除安装状态 {} 失败", path.display())),
        },
    }
}

/// 归一化绝对路径：拒绝空路径、相对路径、`.` / `..` 组件。
fn normalize_absolute(path: &Path, label: &str) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        bail!("{label}不能为空");
    }
    if !path.is_absolute() {
        bail!("{label}必须是绝对路径: {}", path.display());
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(part) => normalized.push(part),
            _ => bail!("{label}不能包含 . 或 .. 组件: {}", path.display()),
        }
    }
    if normalized == Path::new("/") {
        bail!("{label}不能是根目录");
    }
    Ok(normalized)
}

/// 逐组件拒绝符号链接；路径不存在时停止检查（剩余组件都还不存在）。
fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(part) => current.push(part),
            _ => bail!("路径未归一化: {}", path.display()),
        }
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!(
                    "{} 的路径组件 {} 是符号链接，拒绝操作",
                    path.display(),
                    current.display()
                );
            }
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => break,
            Err(err) => {
                return Err(err).with_context(|| format!("检查路径组件 {} 失败", current.display()))
            }
        }
    }
    Ok(())
}

/// 删除 purge 数据目录；目录本身或任一祖先为符号链接时拒绝。
fn remove_data_dir(path: &Path) -> Result<()> {
    reject_symlink_components(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("{} 是符号链接，拒绝删除数据目录", path.display())
        }
        Ok(meta) if !meta.is_dir() => {
            bail!("{} 不是目录，拒绝按数据目录删除", path.display())
        }
        Ok(_) => std::fs::remove_dir_all(path)
            .with_context(|| format!("删除数据目录 {} 失败", path.display())),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("检查数据目录 {} 失败", path.display())),
    }
}

fn print_already_installed(paths: &Paths) {
    println!("rustboard-agent 已安装且已纳管，无需重复安装（如需重写请使用 --force）。");
    println!("  配置: {}", paths.config.display());
    println!("  数据目录: {}", paths.data_dir.display());
    println!("  安装状态: {}", paths.state.display());
}

#[allow(clippy::too_many_arguments)]
fn print_dry_run(
    args: &InstallArgs,
    paths: &Paths,
    manage: bool,
    write_unit: bool,
    copy_binary: bool,
    current_exe: &Path,
) {
    println!("dry-run：以下操作不会执行（不创建目录、不写文件、不调用 systemctl）");
    println!("  数据目录: {} (0700)", paths.data_dir.display());
    println!("  配置: {} (0600)", paths.config.display());
    if write_unit {
        println!("  systemd unit: {} (0644)", paths.unit.display());
    } else {
        println!("  systemd unit: 跳过（--no-systemd）");
    }
    if copy_binary {
        println!(
            "  复制二进制: {} -> {} (0755)",
            current_exe.display(),
            paths.binary.display()
        );
    } else {
        println!(
            "  二进制: {}（已是当前可执行文件，跳过复制）",
            paths.binary.display()
        );
    }
    println!("  安装状态: {} (0600)", paths.state.display());
    if manage {
        println!("  systemctl daemon-reload && systemctl enable --now {AGENT_UNIT_NAME}");
        println!("  等待 enrollment（五个身份文件 + enrollment.complete）最长 30s");
    } else if write_unit {
        println!("  不启用 systemd（仅写 unit；如需管理请加 --systemd）");
    }
    if args.offline {
        println!("  离线模式：不发起任何网络探测");
    }
    if args.yes {
        println!("  非交互模式（--yes）");
    }
}

#[allow(clippy::too_many_arguments)]
fn print_uninstall_plan(
    paths: &Paths,
    unit_path: &Path,
    unit_name: &str,
    binary_path: &Path,
    config_path: &Path,
    data_dir: &Path,
    has_record: bool,
    purge: bool,
    service_candidate: bool,
) {
    println!("dry-run：以下操作不会执行");
    if service_candidate {
        // L6：提示命令的参数统一经 shell_arg，避免 state 中的异常 unit 名被原样
        // 粘贴到终端后产生 shell 歧义。
        let unit = shell_arg(unit_name);
        println!("  先核对 systemd 实际解析的 unit（FragmentPath）");
        println!(
            "  仅当解析到 {} 时执行 systemctl stop {unit} && systemctl disable {unit}",
            unit_path.display()
        );
    } else {
        println!("  不调用 systemctl（unit 不存在、不在 systemd unit 目录或 systemd 不可用）");
    }
    println!("  删除 unit: {}", unit_path.display());
    println!("  删除二进制: {}", binary_path.display());
    if has_record {
        println!("  删除安装状态中的 agent 记录: {}", paths.state.display());
    }
    if purge {
        println!("  删除配置: {}", config_path.display());
        println!("  删除数据目录: {}", data_dir.display());
    } else {
        println!("  保留配置: {}", config_path.display());
        println!("  保留数据目录: {}", data_dir.display());
    }
}

fn print_installed(
    args: &InstallArgs,
    paths: &Paths,
    manage: bool,
    write_unit: bool,
    copy_binary: bool,
) {
    println!("rustboard-agent 已安装。");
    println!("  配置: {} (0600)", paths.config.display());
    println!("  数据目录: {} (0700)", paths.data_dir.display());
    println!(
        "  二进制: {}{}",
        paths.binary.display(),
        if copy_binary {
            ""
        } else {
            "（当前可执行文件）"
        }
    );
    if write_unit {
        println!("  systemd unit: {} (0644)", paths.unit.display());
    }
    if manage {
        println!("  服务: {AGENT_UNIT_NAME} 已 enable --now，enrollment 已完成");
    } else if write_unit {
        println!("  服务: 未启用（仅写 unit；需要 systemd 管理时加 --systemd）");
    } else {
        println!("  服务: 未管理（--no-systemd）");
    }
    println!("  安装状态: {}", paths.state.display());
    if args.offline {
        println!("  离线模式：未发起任何网络探测");
    }
    if args.yes {
        println!("  非交互模式（--yes）");
    }
}

fn print_uninstalled(config_path: &Path, data_dir: &Path, purge: bool) {
    println!("rustboard-agent 已卸载。");
    if purge {
        println!("  已删除配置: {}", config_path.display());
        println!("  已删除数据目录: {}", data_dir.display());
    } else {
        println!("  已保留配置: {}", config_path.display());
        println!("  已保留数据目录: {}", data_dir.display());
        println!("  需要删除时请使用 --purge --yes。");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// root 测试所需的安全 prefix 根。
    ///
    /// `std::env::temp_dir()` 通常是 `/tmp`（1777 + sticky），会被
    /// [`validate_install_prefix`] 拒绝；root 下依次尝试 HOME、仓库目录与
    /// `/opt`，并在其中创建 0700 的测试根。
    fn safe_prefix_base() -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(PathBuf::from(home));
        }
        if let Ok(cwd) = std::env::current_dir() {
            candidates.push(cwd);
        }
        candidates.push(PathBuf::from("/opt"));
        for base in candidates {
            if validate_install_prefix(&base).is_err() {
                continue;
            }
            let root = base.join(format!(
                ".rustboard-agent-install-tests-{}",
                std::process::id()
            ));
            if std::fs::create_dir_all(&root).is_err() {
                continue;
            }
            if std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).is_err() {
                continue;
            }
            if validate_install_prefix(&root).is_ok() {
                return root;
            }
        }
        panic!("root 测试找不到满足 validate_install_prefix 的目录");
    }

    /// 测试临时目录。
    ///
    /// 纯函数 / preflight 用例不要求 prefix 通过安装器校验，非 root 时放在系统
    /// 临时目录即可；会走完整 install/uninstall（含前缀校验）的用例只在 root
    /// 下运行，此时改用 [`safe_prefix_base`]。
    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        use std::os::unix::fs::PermissionsExt;

        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = if running_as_root() {
            safe_prefix_base()
        } else {
            std::env::temp_dir()
        };
        let dir = base.join(format!(
            "rb-agent-install-{}-{tag}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    /// 非 dry-run install/uninstall 会取 `/run/rustboard-install.lock` 全局锁，
    /// 需要 root；CI 的非 root 测试环境跳过这类全流程用例，纯函数/preflight
    /// 用例照常运行。
    fn running_as_root() -> bool {
        #[cfg(unix)]
        {
            // SAFETY: geteuid 没有参数，也没有内存安全前提，只返回当前进程 euid。
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    /// 安装流程串行锁：默认并行测试共用。
    ///
    /// 所有会调用 [`install`] / [`uninstall`]（包括 dry-run 与直接持全局锁）
    /// 的用例开头都必须获取 guard；否则多个用例同时进入非 dry-run 流程会争抢
    /// `/run/rustboard-install.lock`，在默认并行测试下随机失败。
    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// 跨进程测试锁路径：同一主机可能并行跑多个 `cargo test` / e2e，进程内的
    /// [`TEST_SERIAL`] 管不到它们；再用一把文件锁避免两个测试进程同时进入
    /// 非 dry-run 流程抢 `/run/rustboard-install.lock`。
    #[cfg(unix)]
    const CROSS_PROCESS_TEST_LOCK: &str = "/tmp/rustboard-agent-install-tests.lock";

    /// 安装测试 guard：进程内 Mutex + 跨进程 flock，Drop 时依次释放。
    struct InstallTestGuard {
        _intra: std::sync::MutexGuard<'static, ()>,
        #[cfg(unix)]
        _cross_process: Option<std::fs::File>,
    }

    fn serialize_install_tests() -> InstallTestGuard {
        let intra = TEST_SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        #[cfg(unix)]
        let cross_process = acquire_cross_process_test_lock();
        let guard = InstallTestGuard {
            _intra: intra,
            #[cfg(unix)]
            _cross_process: cross_process,
        };
        // 宿主机上的其他 RustBoard 安装/测试（e2e、hub/panel 用例）可能短暂
        // 持有全局锁；等它释放后再进入用例，避免把跨进程并发误报成回归。
        wait_for_global_lock_free();
        guard
    }

    /// 获取跨进程测试锁（阻塞直到其他 agent 测试进程退出该用例）。
    ///
    /// 打不开锁文件时只警告并继续：非 root / 受限环境仍可跑 dry-run 用例，
    /// 此时由 [`wait_for_global_lock_free`] 与用例自身的前置检查兜底。
    #[cfg(unix)]
    fn acquire_cross_process_test_lock() -> Option<std::fs::File> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let path = Path::new(CROSS_PROCESS_TEST_LOCK);
        let file = match OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(err) => {
                eprintln!(
                    "警告：创建跨进程测试锁 {} 失败（继续，可能与其他测试进程争抢全局锁）: {err}",
                    path.display()
                );
                return None;
            }
        };
        // SAFETY: fd 来自仍存活的 File；flock 只操作该 fd，不涉及内存安全。
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            eprintln!(
                "警告：跨进程测试锁 {} flock 失败（继续）: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
        Some(file)
    }

    /// 等待宿主机全局安装锁空闲（其他 `cargo test` / e2e 可能短暂占用）。
    ///
    /// 只用于测试：生产流程拿不到锁立即失败才是正确行为。非 root 无法创建
    /// `/run/rustboard-install.lock`，此时直接返回，由用例的 `running_as_root()`
    /// 决定跳过或继续 dry-run。
    fn wait_for_global_lock_free() {
        const TIMEOUT: Duration = Duration::from_secs(120);
        let deadline = Instant::now() + TIMEOUT;
        loop {
            match InstallLock::acquire_global() {
                Ok(lock) => {
                    drop(lock);
                    return;
                }
                Err(err)
                    if format!("{err:#}").contains("另一个 RustBoard 安装/卸载/升级正在运行") =>
                {
                    if Instant::now() >= deadline {
                        eprintln!(
                            "警告：等待全局安装锁超过 {}s，仍有其他安装/测试占用；继续执行",
                            TIMEOUT.as_secs()
                        );
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                // 非 root 等无法创建锁的环境：交给用例自身处理。
                Err(_) => return,
            }
        }
    }

    #[cfg(unix)]
    fn write_private(path: &Path, contents: &[u8]) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, contents).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn base_install_args(prefix: PathBuf) -> InstallArgs {
        InstallArgs {
            yes: true,
            offline: true,
            dry_run: true,
            force: false,
            prefix,
            config: None,
            data_dir: None,
            unit_dir: None,
            hub: Some("wss://127.0.0.1:8443/agent/ws".to_string()),
            token_file: None,
            fingerprint: None,
            tls_mode: None,
            server_ca: None,
            name: None,
            systemd: false,
            no_systemd: true,
        }
    }

    /// 生成一张真实的自签 CA（只用于安装器参数/文件校验测试）。
    fn sample_ca_pem(dir: &Path) -> String {
        let hub_dir = dir.join("sample-hub");
        tls::ensure_hub_material(
            &hub_dir,
            &["localhost".to_string()],
            tls::CertPolicy::default(),
        )
        .expect("生成测试 CA 失败");
        std::fs::read_to_string(tls::cert_dir(&hub_dir).join(tls::CA_CERT_FILE)).unwrap()
    }

    #[cfg(unix)]
    fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// C2：新装的 `--tls-mode` / `--fingerprint` / `--server-ca` 组合校验
    /// （纯函数，不读写磁盘），旧 CLI 不传 --tls-mode 时仍是 fingerprint。
    #[test]
    fn c2_validate_fresh_tls_args_combinations() {
        let fingerprint = "ab".repeat(32);
        let ca = Path::new("/etc/rustboard/server-ca.pem");

        validate_fresh_tls_args(AgentTlsMode::Fingerprint, Some(&fingerprint), None)
            .expect("fingerprint + 指纹必须合法");
        validate_fresh_tls_args(AgentTlsMode::SystemRoots, None, None)
            .expect("system-roots 不需要指纹/CA");
        validate_fresh_tls_args(AgentTlsMode::CustomCa, None, Some(ca))
            .expect("custom-ca + CA 必须合法");
        validate_fresh_tls_args(AgentTlsMode::CustomCa, Some(&fingerprint), Some(ca))
            .expect("custom-ca 允许可选指纹");

        for (mode, fingerprint, server_ca, needle) in [
            (AgentTlsMode::Fingerprint, None, None, "--fingerprint"),
            (
                AgentTlsMode::Fingerprint,
                Some(fingerprint.as_str()),
                Some(ca),
                "--server-ca",
            ),
            (
                AgentTlsMode::SystemRoots,
                Some(fingerprint.as_str()),
                None,
                "--fingerprint",
            ),
            (AgentTlsMode::SystemRoots, None, Some(ca), "--server-ca"),
            (AgentTlsMode::CustomCa, None, None, "--server-ca"),
        ] {
            let err = validate_fresh_tls_args(mode, fingerprint, server_ca)
                .expect_err("非法组合必须被拒绝")
                .to_string();
            assert!(err.contains(needle), "错误必须包含 {needle}: {err}");
        }

        // clap ValueEnum：名称是 kebab-case；不传 --tls-mode 时保持 None（旧 CLI）。
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            args: InstallArgs,
        }
        use clap::Parser as _;

        let cli = Cli::try_parse_from(["test", "--tls-mode", "system-roots"]).unwrap();
        assert_eq!(cli.args.tls_mode, Some(AgentTlsModeArg::SystemRoots));
        assert_eq!(cli.args.server_ca, None);

        let cli = Cli::try_parse_from([
            "test",
            "--tls-mode",
            "custom-ca",
            "--server-ca",
            "/etc/rustboard/server-ca.pem",
        ])
        .unwrap();
        assert_eq!(cli.args.tls_mode, Some(AgentTlsModeArg::CustomCa));
        assert_eq!(
            cli.args.server_ca.as_deref(),
            Some(Path::new("/etc/rustboard/server-ca.pem"))
        );

        assert!(
            Cli::try_parse_from(["test", "--tls-mode", "bogus"]).is_err(),
            "未知 --tls-mode 必须解析失败"
        );
        assert_eq!(
            Cli::try_parse_from(["test"]).unwrap().args.tls_mode,
            None,
            "旧 CLI 不传 --tls-mode 时不能有隐式值"
        );
    }

    /// system-roots 不要求 fingerprint，但显式携带必须拒绝（不能静默忽略 pin），
    /// 且该模式不能同时使用 --server-ca（公共 ACME 由系统根校验）。
    #[test]
    fn system_roots_rejects_fingerprint_and_server_ca() {
        let fingerprint = "ab".repeat(32);
        validate_fresh_tls_args(AgentTlsMode::SystemRoots, None, None)
            .expect("system-roots 不要求指纹");
        let error = validate_fresh_tls_args(AgentTlsMode::SystemRoots, Some(&fingerprint), None)
            .expect_err("system-roots 不能使用 --fingerprint");
        assert!(error.to_string().contains("--fingerprint"), "{error}");
        assert!(
            reject_system_roots_fingerprint(AgentTlsMode::SystemRoots, Some(&fingerprint)).is_err()
        );
        assert!(
            reject_system_roots_fingerprint(AgentTlsMode::CustomCa, Some(&fingerprint)).is_ok()
        );

        let ca = Path::new("/etc/rustboard/server-ca.pem");
        let error = validate_fresh_tls_args(AgentTlsMode::SystemRoots, None, Some(ca))
            .expect_err("system-roots 不能使用 --server-ca");
        assert!(error.to_string().contains("--server-ca"), "{error}");

        // 非空但非法的 fingerprint 即使不是 system-roots 的必需项也不能静默
        // 写进配置（运行时虽不用于 pin，但配置必须自洽）。
        let cfg = AgentConfig {
            hub_url: "wss://127.0.0.1:8443/agent/ws".to_string(),
            tls_mode: AgentTlsMode::SystemRoots,
            server_fingerprint: "not-a-sha256".to_string(),
            ..AgentConfig::default()
        };
        assert!(validate_fingerprint(&cfg).is_err(), "显式非法指纹必须拒绝");
        let cfg = AgentConfig {
            server_fingerprint: String::new(),
            ..cfg
        };
        assert!(
            validate_fingerprint(&cfg).is_ok(),
            "system-roots 空指纹应允许"
        );
    }

    /// C2：`--server-ca` 只接受绝对路径、逐组件无符号链接、0600/0644 普通文件、
    /// ≤1 MiB，且 PEM 至少有一张可解析证书；错误不打印证书内容。
    #[cfg(unix)]
    #[test]
    fn c2_read_server_ca_validates_mode_size_and_pem() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("server-ca-read");
        let ca_pem = sample_ca_pem(&dir);
        let good = dir.join("ca.pem");
        write_mode(&good, ca_pem.as_bytes(), 0o600);
        assert_eq!(read_server_ca(&good).unwrap(), ca_pem.as_bytes());

        write_mode(&good, ca_pem.as_bytes(), 0o644);
        assert_eq!(read_server_ca(&good).unwrap(), ca_pem.as_bytes());

        // 多张证书的 bundle 合法。
        let bundle = format!("{ca_pem}{ca_pem}");
        let bundle_path = dir.join("bundle.pem");
        write_mode(&bundle_path, bundle.as_bytes(), 0o644);
        assert_eq!(read_server_ca(&bundle_path).unwrap(), bundle.as_bytes());

        // 0640/0664 等非 0600/0644 权限拒绝。
        for mode in [0o640, 0o664] {
            std::fs::set_permissions(&good, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = read_server_ca(&good).unwrap_err().to_string();
            assert!(
                err.contains("0600") && err.contains("0644"),
                "权限错误必须说明允许值: {err}"
            );
        }

        // 符号链接、目录、超限、空文件、非法 PEM 全部拒绝。
        let link = dir.join("ca-link.pem");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        let err = format!("{:#}", read_server_ca(&link).unwrap_err());
        assert!(
            err.contains("符号链接") || err.contains("路径不安全"),
            "符号链接必须拒绝且错误链保留根因: {err}"
        );
        // 父目录是符号链接同样拒绝，不能只检查最终文件。
        let real_dir = dir.join("real-ca-dir");
        std::fs::create_dir_all(&real_dir).unwrap();
        write_mode(&real_dir.join("ca.pem"), ca_pem.as_bytes(), 0o644);
        let ancestor = dir.join("ca-dir-link");
        std::os::unix::fs::symlink(&real_dir, &ancestor).unwrap();
        let err = format!(
            "{:#}",
            read_server_ca(&ancestor.join("ca.pem")).unwrap_err()
        );
        assert!(
            err.contains("符号链接") && err.contains("路径不安全"),
            "祖先符号链接必须拒绝且错误链保留根因: {err}"
        );
        // 相对路径没有明确的解析基准，必须拒绝。
        assert!(
            read_server_ca(Path::new("relative-ca.pem"))
                .unwrap_err()
                .to_string()
                .contains("绝对路径"),
            "相对 --server-ca 必须拒绝"
        );
        assert!(
            read_server_ca(&dir)
                .unwrap_err()
                .to_string()
                .contains("普通文件"),
            "目录必须拒绝"
        );

        let big = dir.join("big.pem");
        write_mode(&big, &vec![b'A'; SERVER_CA_MAX_BYTES + 1], 0o644);
        assert!(
            read_server_ca(&big)
                .unwrap_err()
                .to_string()
                .contains("上限"),
            "超限文件必须拒绝"
        );
        let empty = dir.join("empty.pem");
        write_mode(&empty, b"", 0o644);
        assert!(
            read_server_ca(&empty)
                .unwrap_err()
                .to_string()
                .contains("PEM"),
            "空文件必须拒绝"
        );
        let bad = dir.join("bad.pem");
        write_mode(&bad, b"not a certificate", 0o644);
        let err = read_server_ca(&bad).unwrap_err().to_string();
        // 严格状态机在 load_certs 之前就拒绝块外文本；错误只保留最外层 context。
        assert!(err.contains("不是仅含 CERTIFICATE 的 PEM"), "{err}");
        assert!(
            !err.contains("not a certificate"),
            "错误不能回显内容: {err}"
        );
        // C4：cert+key 混合 PEM 必须拒绝，不能只校验 CERTIFICATE 段后把私钥
        // 原样复制到 0644 的 server-ca.pem。
        let (_csr, key_pem) = tls::make_csr().unwrap();
        let mixed = dir.join("cert-key.pem");
        write_mode(&mixed, format!("{ca_pem}{key_pem}").as_bytes(), 0o644);
        let err = format!("{:#}", read_server_ca(&mixed).unwrap_err());
        assert!(
            err.contains("非 CERTIFICATE") && err.contains("PRIVATE KEY"),
            "混合 PEM 必须点名私钥区块: {err}"
        );
        assert!(
            !err.contains("-----BEGIN CERTIFICATE-----\n"),
            "错误只能包含路径与区块类型，不能回显 PEM 内容: {err}"
        );
        // 非 UTF-8 同样拒绝，且不回显内容。
        let binary = dir.join("binary.pem");
        write_mode(&binary, &[0xff, 0xfe, 0x00], 0o644);
        assert!(read_server_ca(&binary)
            .unwrap_err()
            .to_string()
            .contains("UTF-8"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C4：`--server-ca` 指向 cert+key 混合文件时，安装必须在任何落盘前失败，
    /// 不能把私钥写进 0644 的 server-ca.pem。
    #[cfg(unix)]
    #[test]
    fn c4_custom_ca_install_rejects_mixed_key_before_writing() {
        let _serial = serialize_install_tests();
        if !running_as_root() {
            eprintln!(
                "跳过 c4_custom_ca_install_rejects_mixed_key_before_writing：prefix 校验需要 root"
            );
            return;
        }
        let dir = temp_dir("mixed-ca-install");
        let token_file = dir.join("enroll-token");
        write_private(&token_file, b"0123456789abcdef");
        let ca_pem = sample_ca_pem(&dir);
        let (_csr, key_pem) = tls::make_csr().unwrap();
        let mixed = dir.join("mixed-ca.pem");
        write_mode(&mixed, format!("{ca_pem}{key_pem}").as_bytes(), 0o644);

        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        let mut args = base_install_args(dir.clone());
        args.token_file = Some(token_file);
        args.tls_mode = Some(AgentTlsModeArg::CustomCa);
        args.server_ca = Some(mixed);
        let err = install(args).expect_err("cert+key 混合 PEM 必须拒绝");
        assert!(
            format!("{err:#}").contains("非 CERTIFICATE"),
            "错误必须说明证书文件混入其他区块: {err:#}"
        );
        assert!(
            !paths.data_dir.join(SERVER_CA_FILE).exists(),
            "失败时不得创建 server-ca.pem"
        );
        assert!(!paths.config.exists(), "失败时不得写 agent 配置");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C2：custom-ca 新装把服务端 CA 复制到 data_dir/server-ca.pem（0644），
    /// 配置写复制后的绝对路径；旧 CLI（不传 --tls-mode）仍写 fingerprint。
    #[cfg(unix)]
    #[test]
    fn c2_custom_ca_install_copies_pem_and_writes_mode() {
        use std::os::unix::fs::PermissionsExt;

        let _serial = serialize_install_tests();
        if !running_as_root() {
            eprintln!("跳过 c2_custom_ca_install_copies_pem_and_writes_mode：prefix 校验需要 root");
            return;
        }
        let dir = temp_dir("custom-ca-install");
        let token_file = dir.join("enroll-token");
        write_private(&token_file, b"0123456789abcdef");
        let ca_pem = sample_ca_pem(&dir);
        let ca_source = dir.join("source-ca.pem");
        write_mode(&ca_source, ca_pem.as_bytes(), 0o644);

        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        let mut args = base_install_args(dir.clone());
        args.dry_run = false;
        args.token_file = Some(token_file);
        args.tls_mode = Some(AgentTlsModeArg::CustomCa);
        args.server_ca = Some(ca_source);
        install(args).expect("custom-ca 安装必须成功");

        let cfg = AgentConfig::load(&paths.config).unwrap();
        assert_eq!(cfg.tls_mode, AgentTlsMode::CustomCa);
        let expected = paths.data_dir.join(SERVER_CA_FILE);
        assert_eq!(cfg.server_ca, expected.to_string_lossy());
        assert_eq!(std::fs::read(&expected).unwrap(), ca_pem.as_bytes());
        assert_eq!(
            std::fs::metadata(&expected).unwrap().permissions().mode() & 0o777,
            0o644,
            "复制后的 CA 必须是 0644"
        );

        // 旧 CLI 不传 --tls-mode：仍是 fingerprint，不产生 server-ca.pem。
        let dir2 = temp_dir("legacy-install");
        let token2 = dir2.join("enroll-token");
        write_private(&token2, b"fedcba9876543210");
        let paths2 = Paths::for_role(Role::Agent, &dir2, PathOverrides::default()).unwrap();
        let mut args = base_install_args(dir2.clone());
        args.dry_run = false;
        args.token_file = Some(token2);
        args.fingerprint = Some("ab".repeat(32));
        install(args).expect("旧 CLI 安装必须成功");
        let cfg = AgentConfig::load(&paths2.config).unwrap();
        assert_eq!(cfg.tls_mode, AgentTlsMode::Fingerprint);
        assert!(cfg.server_ca.is_empty());
        assert!(!paths2.data_dir.join(SERVER_CA_FILE).exists());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// C2：事务中途失败不得留下半个 server-ca.pem 或配置。
    #[cfg(unix)]
    #[test]
    fn c2_custom_ca_install_failure_rolls_back_pem() {
        let _serial = serialize_install_tests();
        if !running_as_root() {
            eprintln!("跳过 c2_custom_ca_install_failure_rolls_back_pem：prefix 校验需要 root");
            return;
        }
        let dir = temp_dir("custom-ca-rollback");
        let token_file = dir.join("enroll-token");
        write_private(&token_file, b"0123456789abcdef");
        let ca_pem = sample_ca_pem(&dir);
        let ca_source = dir.join("source-ca.pem");
        write_mode(&ca_source, ca_pem.as_bytes(), 0o644);

        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        // 在二进制目标位置放一个目录，让事务在写完 config/server-ca 后的
        // copy_file 阶段失败，验证回滚不留下半个 CA。
        std::fs::create_dir_all(&paths.binary).unwrap();

        let mut args = base_install_args(dir.clone());
        args.dry_run = false;
        args.token_file = Some(token_file);
        args.tls_mode = Some(AgentTlsModeArg::CustomCa);
        args.server_ca = Some(ca_source);
        let err = install(args).expect_err("写入二进制失败时必须回滚");
        assert!(format!("{err:#}").contains("安装失败"), "{err:#}");

        assert!(
            !paths.data_dir.join(SERVER_CA_FILE).exists(),
            "失败后不得留下半个 server-ca.pem"
        );
        assert!(!paths.config.exists(), "失败后不得留下配置");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 新装必须显式给 hub / token 文件 / 指纹；缺任何一个都在写盘前失败。
    #[cfg(unix)]
    #[test]
    fn fresh_install_requires_hub_token_and_fingerprint() {
        let _serial = serialize_install_tests();
        if !running_as_root() {
            eprintln!(
                "跳过 fresh_install_requires_hub_token_and_fingerprint：prefix 校验需要 root"
            );
            return;
        }
        let dir = temp_dir("fresh-required");
        let token_file = dir.join("enroll-token");
        write_private(&token_file, b"0123456789abcdef");

        let mut args = base_install_args(dir.clone());
        args.hub = None;
        let err = install(args).unwrap_err();
        assert!(format!("{err:#}").contains("--hub"), "{err:#}");

        let mut args = base_install_args(dir.clone());
        args.token_file = None;
        let err = install(args).unwrap_err();
        assert!(format!("{err:#}").contains("--token-file"), "{err:#}");

        let mut args = base_install_args(dir.clone());
        args.token_file = Some(token_file);
        args.fingerprint = None;
        let err = install(args).unwrap_err();
        assert!(format!("{err:#}").contains("--fingerprint"), "{err:#}");

        assert!(!dir.join("etc").exists(), "参数缺失时不能写配置");
        assert!(!dir.join("var").exists(), "参数缺失时不能写安装状态");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// token 文件权限错误、指纹非法都必须在事务创建/写盘之前失败。
    #[cfg(unix)]
    #[test]
    fn install_rejects_bad_token_and_fingerprint_before_writing() {
        use std::os::unix::fs::PermissionsExt;

        let _serial = serialize_install_tests();
        if !running_as_root() {
            eprintln!("跳过 install_rejects_bad_token_and_fingerprint_before_writing：prefix 校验需要 root");
            return;
        }
        let dir = temp_dir("bad-token");
        let token_file = dir.join("enroll-token");
        std::fs::write(&token_file, b"0123456789abcdef").unwrap();
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut args = base_install_args(dir.clone());
        args.token_file = Some(token_file);
        args.fingerprint = Some("ab".repeat(32));
        let err = install(args).unwrap_err();
        assert!(format!("{err:#}").contains("0600"), "{err:#}");
        assert!(!dir.join("etc").exists(), "坏 token 文件不能触发写盘");
        assert!(!dir.join("var").exists(), "坏 token 文件不能触发写盘");

        let good_token = dir.join("good-token");
        write_private(&good_token, b"0123456789abcdef");
        let mut args = base_install_args(dir.clone());
        args.token_file = Some(good_token);
        args.fingerprint = Some("not-a-fingerprint".to_string());
        let err = install(args).unwrap_err();
        assert!(format!("{err:#}").contains("指纹"), "{err:#}");
        assert!(!dir.join("etc").exists(), "非法指纹不能触发写盘");
        assert!(!dir.join("var").exists(), "非法指纹不能触发写盘");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn decide_mode_covers_fresh_idempotent_and_force() {
        assert_eq!(
            decide_mode(false, false, false, false, false).unwrap(),
            InstallMode::Fresh
        );
        assert_eq!(
            decide_mode(false, false, false, false, true).unwrap(),
            InstallMode::Fresh,
            "force 且无配置按新装处理"
        );
        assert_eq!(
            decide_mode(true, true, true, true, false).unwrap(),
            InstallMode::AlreadyInstalled
        );
        assert_eq!(
            decide_mode(true, true, true, true, true).unwrap(),
            InstallMode::ForceReuse
        );

        for (state, enrolled, files) in [(true, false, true), (true, true, false)] {
            let err = decide_mode(state, enrolled, true, files, false).unwrap_err();
            assert!(
                format!("{err:#}").contains("--force"),
                "state 记录与文件不一致时必须提示 --force: {err:#}"
            );
        }
        // 配置在但二进制/unit 缺失：即使已纳管也必须报错，不能假装已安装。
        let err = decide_mode(true, true, true, false, false).unwrap_err();
        assert!(format!("{err:#}").contains("--force"), "{err:#}");

        let err = decide_mode(false, false, true, true, false).unwrap_err();
        assert!(format!("{err:#}").contains("--force"), "{err:#}");
        assert!(format!("{err:#}").contains("upgrade"), "{err:#}");

        let err = decide_mode(false, true, false, false, false).unwrap_err();
        assert!(format!("{err:#}").contains("--force"), "{err:#}");
    }

    /// P-01：prefix 校验必须用用户原始输入。`Paths::for_role` 会把 `//`、尾斜杠
    /// 与 `.` 归一化；先归一化再校验会让 `--prefix //` 变成 `/`（生产路径）。
    #[test]
    fn install_and_uninstall_reject_non_canonical_raw_prefix() {
        let _serial = serialize_install_tests();
        for raw in [
            "//",
            "/opt//rustboard",
            "/opt/rustboard/",
            "/opt/./rustboard",
        ] {
            let mut args = base_install_args(PathBuf::from(raw));
            args.dry_run = true;
            let err = install(args).unwrap_err();
            assert!(
                format!("{err:#}").contains("安装前缀不安全"),
                "{raw:?} 必须在归一化前被拒绝: {err:#}"
            );

            let err = uninstall(UninstallArgs {
                prefix: PathBuf::from(raw),
                config: None,
                data_dir: None,
                unit_dir: None,
                purge: false,
                yes: true,
                dry_run: true,
            })
            .unwrap_err();
            assert!(
                format!("{err:#}").contains("安装前缀不安全"),
                "{raw:?} 卸载也必须在归一化前被拒绝: {err:#}"
            );
        }
    }

    /// P-01 顺序：原始 prefix 校验必须先于全局锁。若先加锁，持锁时 `--prefix //`
    /// 会被“锁被占用”掩盖，无法证明归一化前已拒绝。
    #[cfg(unix)]
    #[test]
    fn raw_prefix_is_validated_before_global_lock() {
        if !running_as_root() {
            eprintln!("跳过 raw_prefix_is_validated_before_global_lock：全局锁需要 root");
            return;
        }
        let _serial = serialize_install_tests();
        let lock = match InstallLock::acquire_global() {
            Ok(lock) => lock,
            Err(err) => {
                eprintln!("跳过 raw_prefix_is_validated_before_global_lock：{err:#}");
                return;
            }
        };

        let mut args = base_install_args(PathBuf::from("//"));
        args.dry_run = false;
        let err = install(args).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("安装前缀不安全"), "{message}");
        assert!(
            !message.contains("已被占用"),
            "prefix 校验必须发生在全局锁之前: {message}"
        );

        let err = uninstall(UninstallArgs {
            prefix: PathBuf::from("//"),
            config: None,
            data_dir: None,
            unit_dir: None,
            purge: false,
            yes: true,
            dry_run: false,
        })
        .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("安装前缀不安全"), "{message}");
        assert!(
            !message.contains("已被占用"),
            "uninstall prefix 校验必须发生在全局锁之前: {message}"
        );
        drop(lock);
    }

    /// issue #2：`--systemd` 只接受 systemd 真正读取的 unit 目录；prefix 内的
    /// unit 会被 systemd 忽略，必须直接拒绝。
    #[test]
    fn systemd_requires_unit_in_a_real_systemd_directory() {
        for good in [
            "/etc/systemd/system/rustboard-agent.service",
            "/run/systemd/system/rustboard-agent.service",
            "/usr/lib/systemd/system/rustboard-agent.service",
        ] {
            ensure_manageable_unit(Path::new(good)).unwrap();
        }
        for bad in [
            "/opt/rustboard/etc/systemd/system/rustboard-agent.service",
            "/tmp/rb/etc/systemd/system/rustboard-agent.service",
        ] {
            let err = ensure_manageable_unit(Path::new(bad)).unwrap_err();
            let message = format!("{err:#}");
            assert!(
                message.contains("systemd 不会读取 prefix 内 unit"),
                "{bad}: {message}"
            );
            assert!(
                message.contains("--unit-dir /etc/systemd/system 或 /run/systemd/system"),
                "{message}"
            );
            assert!(message.contains("/run/systemd/system"), "{message}");
        }
    }

    /// issue #2：`--systemd` + prefix 内 unit 目录必须在任何写盘 / systemctl
    /// 之前失败。
    #[cfg(unix)]
    #[test]
    fn systemd_install_rejects_prefix_unit_dir_before_writes() {
        if !running_as_root() {
            eprintln!(
                "跳过 systemd_install_rejects_prefix_unit_dir_before_writes：prefix 校验与全局锁需要 root"
            );
            return;
        }
        let _serial = serialize_install_tests();
        let dir = temp_dir("systemd-prefix");
        let mut args = base_install_args(dir.clone());
        args.dry_run = false;
        args.no_systemd = false;
        args.systemd = true;

        let err = install(args).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("systemd 不会读取 prefix 内 unit"),
            "{message}"
        );
        assert!(!dir.join("etc").exists(), "拒绝前不能写配置/unit");
        assert!(!dir.join("var").exists(), "拒绝前不能写数据目录/state");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// issue #2：幂等分支必须区分 FragmentPath 匹配、同名外来、unit 缺失但
    /// active（transient/外来）与未解析，不能盲目打印“已安装”。
    #[test]
    fn installed_fragment_check_rejects_foreign_and_active_transient() {
        let expected = Path::new("/run/systemd/system/rustboard-agent.service");
        verify_installed_fragment(Some(expected), false, expected).unwrap();
        verify_installed_fragment(Some(expected), true, expected).unwrap();

        let foreign = Path::new("/etc/systemd/system/rustboard-agent.service");
        let err = verify_installed_fragment(Some(foreign), false, expected).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("同名外来"), "{message}");
        assert!(
            message.contains("/etc/systemd/system/rustboard-agent.service"),
            "{message}"
        );

        // fragment 为空 + 同名 active：transient / 外来 unit，必须拒绝。
        let err = verify_installed_fragment(None, true, expected).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("active"), "{message}");
        assert!(message.contains("transient"), "{message}");

        // fragment 为空且同名未运行：同样不是“已安装”，提示 daemon-reload。
        let err = verify_installed_fragment(None, false, expected).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("FragmentPath"), "{message}");
        assert!(message.contains("daemon-reload"), "{message}");
    }

    /// issue #2：卸载只有 FragmentPath == 本安装器的 unit 才 stop/disable；
    /// unit 文件不存在（即使同名服务 active）或 fragment 为空时只删文件。
    #[test]
    fn uninstall_unit_action_only_stops_own_fragment() {
        let unit = Path::new("/run/systemd/system/rustboard-agent.service");
        let foreign = Path::new("/etc/systemd/system/rustboard-agent.service");
        assert_eq!(
            uninstall_unit_action(true, true, true, Some(unit), unit),
            UninstallUnitAction::StopDisable
        );
        assert_eq!(
            uninstall_unit_action(true, true, true, Some(foreign), unit),
            UninstallUnitAction::RefuseForeign
        );
        assert_eq!(
            uninstall_unit_action(true, true, true, None, unit),
            UninstallUnitAction::FileOnly
        );
        // unit 文件不存在：绝不 stop（即使同名服务 active）。
        assert_eq!(
            uninstall_unit_action(true, false, true, Some(unit), unit),
            UninstallUnitAction::FileOnly
        );
        // prefix 内 unit / systemd 不可用：只删文件。
        assert_eq!(
            uninstall_unit_action(true, true, false, Some(unit), unit),
            UninstallUnitAction::FileOnly
        );
        assert_eq!(
            uninstall_unit_action(false, true, true, Some(unit), unit),
            UninstallUnitAction::FileOnly
        );
    }

    /// R-S4/P-01：非 dry-run install/uninstall 在读 state 前取全局锁；dry-run
    /// 不加锁。agent 不会被 hub 调起，因此不需要 `InstallLock::inherited()`。
    #[cfg(unix)]
    #[test]
    fn install_and_uninstall_hold_global_lock_but_dry_run_does_not() {
        if !running_as_root() {
            eprintln!(
                "跳过 install_and_uninstall_hold_global_lock_but_dry_run_does_not：全局锁需要 root"
            );
            return;
        }
        let _serial = serialize_install_tests();
        let dir = temp_dir("global-lock");
        let token_file = dir.join("enroll-token");
        write_private(&token_file, b"0123456789abcdef");
        let fingerprint = "ab".repeat(32);

        let lock = match InstallLock::acquire_global() {
            Ok(lock) => lock,
            Err(err) => {
                eprintln!("跳过全局锁用例（无法获取锁）: {err:#}");
                return;
            }
        };

        let mut args = base_install_args(dir.clone());
        args.dry_run = false;
        args.token_file = Some(token_file.clone());
        args.fingerprint = Some(fingerprint.clone());
        let err = install(args).unwrap_err();
        assert!(
            format!("{err:#}").contains("另一个 RustBoard 安装/卸载/升级正在运行"),
            "非 dry-run install 必须尝试获取全局锁: {err:#}"
        );

        let err = uninstall(UninstallArgs {
            prefix: dir.clone(),
            config: None,
            data_dir: None,
            unit_dir: None,
            purge: false,
            yes: true,
            dry_run: false,
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("另一个 RustBoard 安装/卸载/升级正在运行"),
            "非 dry-run uninstall 必须尝试获取全局锁: {err:#}"
        );

        // 全局锁仍被本测试持有时，dry-run 也必须能完成只读计划且零写入。
        let mut args = base_install_args(dir.clone());
        args.token_file = Some(token_file);
        args.fingerprint = Some(fingerprint);
        install(args).expect("dry-run 不应要求全局锁");
        assert!(!dir.join("etc").exists(), "dry-run 不能写配置/unit");
        assert!(!dir.join("var").exists(), "dry-run 不能写数据目录/state");
        drop(lock);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn token_reader_requires_private_nonempty_file_without_leaking() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("token");
        let missing = dir.join("missing");
        let err = read_token(&missing).unwrap_err();
        assert!(format!("{err:#}").contains("token-file"), "{err:#}");

        let loose = dir.join("loose");
        std::fs::write(&loose, b"super-secret-token").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = read_token(&loose).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("0600"), "权限错误必须说明 0600: {message}");
        assert!(
            !message.contains("super-secret-token"),
            "错误信息不能回显 token: {message}"
        );

        let good = dir.join("good");
        write_private(&good, b"  abc123\n");
        assert_eq!(read_token(&good).unwrap(), "abc123");

        let empty = dir.join("empty");
        write_private(&empty, b" \n\t");
        let err = read_token(&empty).unwrap_err();
        assert!(format!("{err:#}").contains("为空"), "{err:#}");

        let link = dir.join("link");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        let err = read_token(&link).unwrap_err();
        assert!(format!("{err:#}").contains("符号链接"), "{err:#}");

        let oversized = dir.join("oversized");
        write_private(&oversized, &[b'a'; TOKEN_MAX_BYTES + 1]);
        let err = read_token(&oversized).unwrap_err();
        assert!(format!("{err:#}").contains("超过上限"), "{err:#}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_validated_and_normalized() {
        let hex = "ab".repeat(32);
        assert_eq!(normalize_fingerprint(&hex).unwrap(), hex);
        assert_eq!(normalize_fingerprint(&format!("  {hex}  ")).unwrap(), hex);

        let uppercase: String = hex.to_ascii_uppercase();
        assert_eq!(normalize_fingerprint(&uppercase).unwrap(), hex);

        let colon = uppercase
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(
            normalize_fingerprint(&format!("sha256:{colon}")).unwrap(),
            hex
        );

        for bad in ["", "not-hex", &"ab".repeat(31), &"ab".repeat(33)] {
            let err = normalize_fingerprint(bad).unwrap_err();
            assert!(format!("{err:#}").contains("指纹"), "{bad:?}: {err:#}");
        }
    }

    #[test]
    fn enrollment_detection_requires_five_files_and_marker() {
        let dir = temp_dir("enroll");
        assert!(!has_enrollment_identity(&dir));
        assert!(!is_enrolled_data_dir(&dir));
        assert!(!enrollment_complete(&dir));

        // 只出现部分凭据（例如写完 cert/key/secret 后崩溃）：不能算完成。
        for name in [AGENT_CERT, AGENT_KEY, AGENT_SECRET] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        assert!(!has_enrollment_identity(&dir));
        assert!(!is_enrolled_data_dir(&dir));
        assert!(!enrollment_complete(&dir));

        // 五个身份文件齐全但 marker 未写：仍不算 enrollment 完成。
        std::fs::write(dir.join(AGENT_CA), b"ca").unwrap();
        std::fs::write(dir.join(AGENT_ID), b"agent-1").unwrap();
        assert!(has_enrollment_identity(&dir), "五件身份齐全供安装幂等判断");
        assert!(!is_enrolled_data_dir(&dir), "marker 未写不得判完成");
        assert!(!enrollment_complete(&dir));

        // marker 最后写入后才算完成。
        std::fs::write(dir.join(ENROLLMENT_MARKER), b"{}").unwrap();
        assert!(is_enrolled_data_dir(&dir));
        assert!(enrollment_complete(&dir));

        // 空文件不能算完成，否则安装器/幂等判断会把坏状态当成功。
        std::fs::write(dir.join(AGENT_CERT), b"").unwrap();
        assert!(!has_enrollment_identity(&dir));
        assert!(!is_enrolled_data_dir(&dir));
        assert!(!enrollment_complete(&dir));
        std::fs::write(dir.join(AGENT_CERT), b"x").unwrap();
        std::fs::write(dir.join(ENROLLMENT_MARKER), b"").unwrap();
        assert!(!is_enrolled_data_dir(&dir), "空 marker 不得判完成");
        assert!(!enrollment_complete(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_detection_rejects_symlinked_credentials() {
        let dir = temp_dir("enroll-link");
        let target = dir.join("real-cert");
        std::fs::write(&target, b"cert").unwrap();
        std::os::unix::fs::symlink(&target, dir.join(AGENT_CERT)).unwrap();
        for name in [
            AGENT_KEY,
            AGENT_SECRET,
            AGENT_CA,
            AGENT_ID,
            ENROLLMENT_MARKER,
        ] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        assert!(!has_enrollment_identity(&dir), "符号链接凭据不能算身份齐全");
        assert!(!is_enrolled_data_dir(&dir), "符号链接凭据不能算已纳管");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 卸载删除路径必须落在库 allowlist 内：prefix 外、系统目录本身都拒绝。
    #[test]
    fn managed_paths_are_confined_by_allowlist() {
        let dir = temp_dir("managed-path");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        for (path, kind) in [
            (&paths.config, ManagedPathKind::Config),
            (&paths.data_dir, ManagedPathKind::Data),
            (&paths.unit, ManagedPathKind::Unit),
            (&paths.binary, ManagedPathKind::Binary),
        ] {
            validate_managed_path(Role::Agent, &paths.prefix, path, kind).unwrap();
        }
        assert!(
            validate_managed_path(
                Role::Agent,
                &paths.prefix,
                Path::new("/etc/passwd"),
                ManagedPathKind::Config
            )
            .is_err(),
            "prefix 外路径必须拒绝"
        );
        assert!(
            validate_managed_path(
                Role::Agent,
                &paths.prefix,
                &dir.join("../etc/passwd"),
                ManagedPathKind::Config
            )
            .is_err(),
            "含 .. 的路径必须拒绝"
        );

        let root_paths =
            Paths::for_role(Role::Agent, Path::new("/"), PathOverrides::default()).unwrap();
        validate_managed_path(
            Role::Agent,
            &root_paths.prefix,
            Path::new("/etc/rustboard/agent.toml"),
            ManagedPathKind::Config,
        )
        .unwrap();
        assert!(validate_managed_path(
            Role::Agent,
            &root_paths.prefix,
            Path::new("/etc/passwd"),
            ManagedPathKind::Config
        )
        .is_err());
        assert!(
            validate_managed_path(
                Role::Agent,
                &root_paths.prefix,
                Path::new("/usr/local/bin/rustboard-hub"),
                ManagedPathKind::Binary
            )
            .is_err(),
            "root prefix 下二进制必须精确匹配角色名"
        );
        assert!(validate_managed_path(
            Role::Agent,
            &root_paths.prefix,
            Path::new("/opt/agent.service"),
            ManagedPathKind::Unit
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 安装写盘前：自定义路径必须在 prefix 内、不能含 `$` 等字符，数据目录
    /// 不能吞掉 state/backup。
    #[test]
    fn install_preflight_rejects_unsafe_targets() {
        let dir = temp_dir("install-preflight");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        assert!(preflight_install_paths(&paths).is_ok());

        let outside = dir
            .parent()
            .expect("测试 prefix 必须有父目录")
            .join("rb-agent-outside.toml");
        let paths = Paths::for_role(
            Role::Agent,
            &dir,
            PathOverrides {
                config: Some(outside),
                ..PathOverrides::default()
            },
        )
        .unwrap();
        let err = preflight_install_paths(&paths).unwrap_err();
        assert!(
            format!("{err:#}").contains("安装前缀"),
            "prefix 外配置必须拒绝: {err:#}"
        );

        let paths = Paths::for_role(
            Role::Agent,
            &dir,
            PathOverrides {
                config: Some(dir.join("etc").join("agent$toml")),
                ..PathOverrides::default()
            },
        )
        .unwrap();
        let err = preflight_install_paths(&paths).unwrap_err();
        assert!(
            format!("{err:#}").contains("特殊字符"),
            "含 $ 的路径必须拒绝: {err:#}"
        );

        let paths = Paths::for_role(
            Role::Agent,
            &dir,
            PathOverrides {
                data_dir: Some(dir.join("var/lib/rustboard")),
                ..PathOverrides::default()
            },
        )
        .unwrap();
        let err = preflight_install_paths(&paths).unwrap_err();
        assert!(
            format!("{err:#}").contains("安装状态"),
            "数据目录覆盖 state/backup 时必须拒绝: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M3：install 写 unit 前必须确认现存 unit 是本安装器渲染的；外来 unit
    /// 拒绝覆盖，`--force` 也不例外。
    #[cfg(unix)]
    #[test]
    fn install_unit_preflight_rejects_foreign_and_accepts_own() {
        let dir = temp_dir("unit-preflight");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        std::fs::write(
            &paths.unit,
            b"# user unit\n[Service]\nExecStart=/bin/true\n",
        )
        .unwrap();

        let err = ensure_existing_unit_is_ours(&paths.unit, &paths, "覆盖/停止").unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("不是本安装器为当前 prefix 生成的"),
            "必须拒绝外来 unit: {message}"
        );
        assert!(
            message.contains("--force"),
            "错误必须说明 --force 也不覆盖: {message}"
        );
        assert!(paths.unit.exists(), "拒绝时不能删除外来 unit");

        let rendered = render_unit(Role::Agent, &paths).unwrap();
        std::fs::write(&paths.unit, rendered).unwrap();
        assert!(ensure_existing_unit_is_ours(&paths.unit, &paths, "覆盖/停止").is_ok());

        std::fs::remove_file(&paths.unit).unwrap();
        std::os::unix::fs::symlink(dir.join("missing.service"), &paths.unit).unwrap();
        let err = ensure_existing_unit_is_ours(&paths.unit, &paths, "覆盖/停止").unwrap_err();
        assert!(format!("{err:#}").contains("符号链接"), "{err:#}");
        assert!(
            std::fs::symlink_metadata(&paths.unit).is_ok(),
            "符号链接不能被删除"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// H1：卸载 preflight 在停服/删除前拒绝外来 unit，目标文件原样保留。
    #[cfg(unix)]
    #[test]
    fn uninstall_preflight_rejects_foreign_unit_before_deleting() {
        let dir = temp_dir("uninstall-preflight");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        std::fs::write(&paths.unit, b"[Service]\nExecStart=/bin/true\n").unwrap();
        std::fs::create_dir_all(paths.binary.parent().unwrap()).unwrap();
        std::fs::write(&paths.binary, b"bin").unwrap();

        let err = preflight_uninstall_targets(&paths, &paths, false).unwrap_err();
        assert!(
            format!("{err:#}").contains("不是本安装器为当前 prefix 生成的"),
            "{err:#}"
        );
        assert!(paths.unit.exists(), "preflight 失败时 unit 必须保留");
        assert!(paths.binary.exists(), "preflight 失败时二进制必须保留");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// P-04：即使没有 --purge（不删除 config/data），卸载也必须校验 state 记录
    /// 的 config/data：allowlist、字符集、存在时的类型与非符号链接。只有与
    /// 递归删除相关的检查才依赖 --purge。
    #[cfg(unix)]
    #[test]
    fn uninstall_preflight_validates_config_and_data_without_purge() {
        let dir = temp_dir("preflight-config-data");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();

        // 合法路径且目标都不存在：默认卸载 preflight 必须通过。
        preflight_uninstall_targets(&paths, &paths, false).unwrap();

        // 伪造 state 把 config 指向 prefix 外：不 purge 也必须拒绝。
        let mut outside = paths.clone();
        outside.config = PathBuf::from("/etc/passwd");
        let err = preflight_uninstall_targets(&paths, &outside, false).unwrap_err();
        assert!(format!("{err:#}").contains("配置路径"), "{err:#}");

        // 伪造 state 把 data_dir 指向 prefix 外：不 purge 也必须拒绝。
        let mut outside = paths.clone();
        outside.data_dir = PathBuf::from("/var/lib/rustboard");
        let err = preflight_uninstall_targets(&paths, &outside, false).unwrap_err();
        assert!(format!("{err:#}").contains("数据目录"), "{err:#}");

        // 字符集：`$` 会被 systemd / shell 展开，即使本次不删除也要拒绝。
        let mut bad = paths.clone();
        bad.config = dir.join("etc").join("agent$toml");
        let err = preflight_uninstall_targets(&paths, &bad, false).unwrap_err();
        assert!(format!("{err:#}").contains("特殊字符"), "{err:#}");

        // 存在时的类型 / 非符号链接检查：config 是符号链接。
        std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        let real_config = dir.join("real-config");
        std::fs::write(&real_config, b"x").unwrap();
        std::os::unix::fs::symlink(&real_config, &paths.config).unwrap();
        let err = preflight_uninstall_targets(&paths, &paths, false).unwrap_err();
        assert!(format!("{err:#}").contains("符号链接"), "{err:#}");
        assert!(real_config.exists(), "preflight 失败时链接目标不能删除");

        // data_dir 是普通文件：不 purge 也要拒绝。
        std::fs::remove_file(&paths.config).unwrap();
        std::fs::create_dir_all(paths.data_dir.parent().unwrap()).unwrap();
        std::fs::write(&paths.data_dir, b"not-a-dir").unwrap();
        let err = preflight_uninstall_targets(&paths, &paths, false).unwrap_err();
        assert!(format!("{err:#}").contains("不是目录"), "{err:#}");
        assert!(paths.data_dir.exists(), "preflight 失败时不能删除目标");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 幂等分支（即使 dry-run）也不能把同名外来 unit 判成“已安装”。
    #[cfg(unix)]
    #[test]
    fn already_installed_rejects_foreign_unit() {
        let _serial = serialize_install_tests();
        if !running_as_root() {
            eprintln!("跳过 already_installed_rejects_foreign_unit：prefix 校验需要 root");
            return;
        }
        let dir = temp_dir("already-foreign");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        write_private(
            &paths.config,
            b"hub_url = \"wss://127.0.0.1:8443/agent/ws\"\n",
        );
        std::fs::create_dir_all(&paths.data_dir).unwrap();
        for name in ENROLLMENT_FILES {
            std::fs::write(paths.data_dir.join(name), b"x").unwrap();
        }
        std::fs::write(paths.data_dir.join(ENROLLMENT_MARKER), b"{}").unwrap();
        std::fs::create_dir_all(paths.binary.parent().unwrap()).unwrap();
        std::fs::write(&paths.binary, b"bin").unwrap();
        std::fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        std::fs::write(&paths.unit, b"[Service]\nExecStart=/bin/true\n").unwrap();

        let mut state = InstallState::new();
        state.upsert(
            Role::Agent,
            RoleState::new(&paths, VERSION, paths.backup_root.join("backup")),
        );
        state.save(&paths.state).unwrap();

        let args = base_install_args(dir.clone());
        let err = install(args).unwrap_err();
        assert!(
            format!("{err:#}").contains("不是本安装器为当前 prefix 生成的"),
            "同名外来 unit 不能误判已安装: {err:#}"
        );
        assert!(paths.unit.exists(), "幂等检查失败时不能删除外来 unit");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M3 全流程：`--force` 遇到同名外来 unit 必须在写盘前失败，unit 原样保留。
    #[cfg(unix)]
    #[test]
    fn install_refuses_foreign_unit_even_with_force() {
        if !running_as_root() {
            eprintln!(
                "跳过 install_refuses_foreign_unit_even_with_force：非 dry-run 需要全局安装锁"
            );
            return;
        }
        let _serial = serialize_install_tests();
        let dir = temp_dir("force-foreign");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        let foreign = b"[Service]\nExecStart=/bin/true\n";
        std::fs::write(&paths.unit, foreign).unwrap();
        let token_file = dir.join("enroll-token");
        write_private(&token_file, b"0123456789abcdef");

        let mut args = base_install_args(dir.clone());
        args.dry_run = false;
        args.force = true;
        args.no_systemd = false;
        args.token_file = Some(token_file);
        args.fingerprint = Some("ab".repeat(32));

        let err = install(args).unwrap_err();
        assert!(
            format!("{err:#}").contains("不是本安装器为当前 prefix 生成的"),
            "外来 unit 必须拒绝: {err:#}"
        );
        assert_eq!(
            std::fs::read(&paths.unit).unwrap(),
            foreign,
            "--force 也不能覆盖外来 unit"
        );
        assert!(!paths.config.exists(), "拒绝前不能写配置");
        assert!(!paths.data_dir.exists(), "拒绝前不能建数据目录");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R-S3（非 root 可跑）：dry-run 的配置加载器只读，不改权限、不回显 token。
    #[cfg(unix)]
    #[test]
    fn dry_run_config_loader_is_read_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("config-readonly");
        let good = dir.join("agent.toml");
        let cfg = AgentConfig {
            hub_url: "wss://127.0.0.1:8443/agent/ws".to_string(),
            server_fingerprint: "ab".repeat(32),
            token: "dry-run-secret-token".to_string(),
            name: "dry".to_string(),
            data_dir: dir.join("data"),
            ..AgentConfig::default()
        };
        std::fs::write(&good, toml::to_string_pretty(&cfg).unwrap()).unwrap();
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o644)).unwrap();

        let loaded = load_existing_config(&good, true).unwrap();
        assert_eq!(loaded.token, cfg.token);
        assert_eq!(
            std::fs::metadata(&good).unwrap().permissions().mode() & 0o777,
            0o644,
            "dry-run 读取不能 harden 配置"
        );

        // 坏 TOML 的诊断可能回显原文；错误只能报路径，不能包含 token。
        let bad = dir.join("bad.toml");
        std::fs::write(
            &bad,
            b"token = \"do-not-leak-this-token\"\n[not valid toml\n",
        )
        .unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_existing_config(&bad, true).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            !message.contains("do-not-leak-this-token"),
            "错误不能回显 token: {message}"
        );
        assert!(
            std::fs::metadata(&bad).unwrap().permissions().mode() & 0o777 == 0o644,
            "解析失败也不能改权限"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R-S3：`--force --dry-run` 读取已有配置不能 harden/chmod，也不能写文件。
    #[cfg(unix)]
    #[test]
    fn dry_run_force_reads_config_without_chmod() {
        use std::os::unix::fs::PermissionsExt;

        let _serial = serialize_install_tests();
        if !running_as_root() {
            eprintln!("跳过 dry_run_force_reads_config_without_chmod：prefix 校验需要 root");
            return;
        }
        let dir = temp_dir("dryrun-force");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        let cfg = AgentConfig {
            hub_url: "wss://127.0.0.1:8443/agent/ws".to_string(),
            server_fingerprint: "ab".repeat(32),
            token: "dry-run-secret-token".to_string(),
            name: "dry".to_string(),
            data_dir: paths.data_dir.clone(),
            ..AgentConfig::default()
        };
        let text = toml::to_string_pretty(&cfg).unwrap();
        std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        std::fs::write(&paths.config, text.as_bytes()).unwrap();
        std::fs::set_permissions(&paths.config, std::fs::Permissions::from_mode(0o644)).unwrap();

        let mut args = base_install_args(dir.clone());
        args.force = true;
        install(args).unwrap();

        let mode = std::fs::metadata(&paths.config)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "dry-run 只能读配置，不能 harden 成 0600（当前 {mode:04o}）"
        );
        assert!(!paths.state.exists(), "dry-run 不能写安装状态");
        assert!(!paths.binary.exists(), "dry-run 不能写二进制");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn same_file_uses_canonical_paths() {
        let dir = temp_dir("same-file");
        let file = dir.join("agent");
        std::fs::write(&file, b"bin").unwrap();
        assert!(same_file(&file, &file));
        assert!(!same_file(&file, &dir.join("missing")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// agent uninstall 只删除自己的 state 记录，hub/panel 记录必须原样保留。
    #[test]
    fn uninstall_preserves_other_role_records() {
        if !running_as_root() {
            eprintln!("跳过 uninstall_preserves_other_role_records：非 dry-run 需要全局安装锁");
            return;
        }
        let _serial = serialize_install_tests();
        let dir = temp_dir("uninstall-state-merge");
        let agent_paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        let hub_paths = Paths::for_role(Role::Hub, &dir, PathOverrides::default()).unwrap();
        let mut state = InstallState::new();
        state.upsert(
            Role::Hub,
            RoleState::new(
                &hub_paths,
                VERSION,
                hub_paths.backup_root.join("hub-backup"),
            ),
        );
        state.upsert(
            Role::Agent,
            RoleState::new(
                &agent_paths,
                VERSION,
                agent_paths.backup_root.join("agent-backup"),
            ),
        );
        state.save(&agent_paths.state).unwrap();

        uninstall(UninstallArgs {
            prefix: dir.clone(),
            config: None,
            data_dir: None,
            unit_dir: None,
            purge: false,
            yes: true,
            dry_run: false,
        })
        .unwrap();

        let after = InstallState::load(&agent_paths.state).unwrap();
        assert!(after.role(Role::Agent).is_none(), "agent 记录应被删除");
        let hub = after.role(Role::Hub).expect("hub 记录必须保留");
        assert_eq!(hub.config, hub_paths.config);
        assert_eq!(hub.data_dir, hub_paths.data_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// uninstall 默认删除 unit/binary/state，保留 config/data；第二次 purge
    /// 即使 state 已不存在，也能按 prefix 路径删除配置与数据。
    #[test]
    fn uninstall_keeps_config_and_data_until_purge() {
        if !running_as_root() {
            eprintln!(
                "跳过 uninstall_keeps_config_and_data_until_purge：非 dry-run 需要全局安装锁"
            );
            return;
        }
        let _serial = serialize_install_tests();
        let dir = temp_dir("uninstall");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        std::fs::write(&paths.config, b"hub_url = \"wss://example/agent/ws\"\n").unwrap();
        std::fs::create_dir_all(&paths.data_dir).unwrap();
        std::fs::write(paths.data_dir.join("keep"), b"data").unwrap();
        std::fs::create_dir_all(paths.binary.parent().unwrap()).unwrap();
        std::fs::write(&paths.binary, b"bin").unwrap();
        // prefix 内 unit 只删文件、不调用 systemctl（该 unit 是安装器渲染的）。
        std::fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        std::fs::write(&paths.unit, render_unit(Role::Agent, &paths).unwrap()).unwrap();

        let mut state = InstallState::new();
        state.upsert(
            Role::Agent,
            RoleState::new(&paths, VERSION, paths.backup_root.join("backup")),
        );
        state.save(&paths.state).unwrap();

        uninstall(UninstallArgs {
            prefix: dir.clone(),
            config: None,
            data_dir: None,
            unit_dir: None,
            purge: false,
            yes: true,
            dry_run: false,
        })
        .unwrap();
        assert!(!paths.binary.exists(), "默认卸载应删除二进制");
        assert!(!paths.unit.exists(), "默认卸载应删除 prefix 内 unit 文件");
        assert!(!paths.state.exists(), "默认卸载应删除 state 记录");
        assert!(paths.config.exists(), "默认卸载必须保留配置");
        assert!(paths.data_dir.exists(), "默认卸载必须保留数据目录");

        // 第二次 purge：state 已不存在，仍必须按 prefix 路径删除。
        uninstall(UninstallArgs {
            prefix: dir.clone(),
            config: None,
            data_dir: None,
            unit_dir: None,
            purge: true,
            yes: true,
            dry_run: false,
        })
        .unwrap();
        assert!(!paths.config.exists(), "--purge 应删除配置");
        assert!(!paths.data_dir.exists(), "--purge 应删除数据目录");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// purge 拒绝符号链接数据目录，且不会动链接目标。
    #[cfg(unix)]
    #[test]
    fn purge_refuses_symlinked_data_dir() {
        if !running_as_root() {
            eprintln!("跳过 purge_refuses_symlinked_data_dir：非 dry-run 需要全局安装锁");
            return;
        }
        let _serial = serialize_install_tests();
        let dir = temp_dir("purge-symlink");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        std::fs::write(&paths.config, b"config").unwrap();
        let target = dir.join("real-data");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(paths.data_dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&target, &paths.data_dir).unwrap();

        let err = uninstall(UninstallArgs {
            prefix: dir.clone(),
            config: None,
            data_dir: None,
            unit_dir: None,
            purge: true,
            yes: true,
            dry_run: false,
        })
        .unwrap_err();
        assert!(format!("{err:#}").contains("符号链接"), "{err:#}");
        assert!(target.exists(), "链接目标不能被删除");
        assert!(paths.config.exists(), "校验失败时不能先删配置");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// purge 数据目录不能包含 install-state/backup，否则递归删除会毁掉回滚材料。
    #[test]
    fn purge_refuses_data_dir_containing_state() {
        if !running_as_root() {
            eprintln!("跳过 purge_refuses_data_dir_containing_state：非 dry-run 需要全局安装锁");
            return;
        }
        let _serial = serialize_install_tests();
        let dir = temp_dir("purge-ancestor");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        std::fs::write(&paths.config, b"config").unwrap();
        // data_dir 选 prefix 下的 var/lib/rustboard：通过 allowlist 但包含 state，
        // 必须命中“包含安装状态”而不是更早的“不能是 prefix 本身”。
        let broad_data_dir = paths.data_dir.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&broad_data_dir).unwrap();

        let err = uninstall(UninstallArgs {
            prefix: dir.clone(),
            config: None,
            data_dir: Some(broad_data_dir),
            unit_dir: None,
            purge: true,
            yes: true,
            dry_run: false,
        })
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("包含安装状态"),
            "数据目录覆盖 state 时必须拒绝: {err:#}"
        );
        assert!(paths.config.exists(), "校验失败时不能删配置");
        assert!(dir.exists(), "prefix 不能被递归删除");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #72：agent 卸载流程的 fake systemd，走 preflight→execute 完整卸载路径。
    struct UninstallFakeService {
        stop_error: Option<&'static str>,
        stop_calls: std::cell::Cell<usize>,
        disable_calls: std::cell::Cell<usize>,
        fragment: Option<PathBuf>,
        state: std::cell::RefCell<ServiceState>,
        state_after_stop: ServiceState,
        state_error: Option<&'static str>,
    }

    impl UninstallFakeService {
        fn stopped(fragment: Option<PathBuf>) -> Self {
            Self {
                stop_error: None,
                stop_calls: std::cell::Cell::new(0),
                disable_calls: std::cell::Cell::new(0),
                fragment,
                state: std::cell::RefCell::new(ServiceState::Inactive),
                state_after_stop: ServiceState::Inactive,
                state_error: None,
            }
        }
    }

    impl ServiceControl for UninstallFakeService {
        fn fragment_path(&self, _unit: &str) -> Result<Option<PathBuf>> {
            Ok(self.fragment.clone())
        }

        fn ensure_fragment_is(&self, _unit: &str, _expected: &Path) -> Result<()> {
            Ok(())
        }

        fn daemon_reload(&self) -> Result<()> {
            Ok(())
        }

        fn is_managing(&self) -> bool {
            true
        }

        fn active_state(&self, _unit: &str) -> Result<ServiceState> {
            match self.state_error {
                Some(message) => bail!("{message}"),
                None => Ok(self.state.borrow().clone()),
            }
        }

        fn main_pid(&self, _unit: &str) -> Result<u32> {
            Ok(0)
        }

        fn enable_now(&self, _unit: &str) -> Result<()> {
            Ok(())
        }

        fn restart(&self, _unit: &str) -> Result<()> {
            Ok(())
        }

        fn stop(&self, _unit: &str) -> Result<()> {
            self.stop_calls.set(self.stop_calls.get() + 1);
            match self.stop_error {
                Some(message) => bail!("{message}"),
                None => {
                    *self.state.borrow_mut() = self.state_after_stop.clone();
                    Ok(())
                }
            }
        }

        fn disable(&self, _unit: &str) -> Result<()> {
            self.disable_calls.set(self.disable_calls.get() + 1);
            Ok(())
        }
    }

    /// 满足 validate_install_prefix 的测试目录（放在测试二进制所在 target 目录）。
    fn install_prefix_dir(tag: &str) -> PathBuf {
        let base = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_path_buf))
            .unwrap_or_else(std::env::temp_dir);
        let dir = base.join(format!(
            "rb-agent-install-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    struct AgentUninstallFixture {
        _dir: PathBuf,
        paths: Paths,
    }

    impl Drop for AgentUninstallFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self._dir);
        }
    }

    fn agent_uninstall_fixture(tag: &str, unit_present: bool) -> AgentUninstallFixture {
        let dir = install_prefix_dir(tag);
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        std::fs::write(&paths.config, b"hub_url = \"wss://example/agent/ws\"\n").unwrap();
        std::fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        if unit_present {
            std::fs::write(&paths.unit, render_unit(Role::Agent, &paths).unwrap()).unwrap();
        }
        std::fs::create_dir_all(paths.binary.parent().unwrap()).unwrap();
        std::fs::write(&paths.binary, b"bin").unwrap();
        std::fs::create_dir_all(&paths.data_dir).unwrap();
        std::fs::write(paths.data_dir.join("keep"), b"data").unwrap();

        let mut state = InstallState::new();
        state.upsert(
            Role::Agent,
            RoleState::new(&paths, VERSION, paths.backup_root.clone()),
        );
        state.save(&paths.state).unwrap();
        AgentUninstallFixture { _dir: dir, paths }
    }

    fn run_agent_uninstall(
        fixture: AgentUninstallFixture,
        service: &UninstallFakeService,
    ) -> (Result<()>, AgentUninstallFixture) {
        let args = UninstallArgs {
            prefix: fixture.paths.prefix.clone(),
            config: None,
            data_dir: None,
            unit_dir: None,
            purge: true,
            yes: true,
            dry_run: false,
        };
        let result = uninstall_impl(args, Some(service));
        (result, fixture)
    }

    fn assert_agent_targets_preserved(fixture: &AgentUninstallFixture, context: &str) {
        for path in [
            &fixture.paths.unit,
            &fixture.paths.binary,
            &fixture.paths.config,
            &fixture.paths.data_dir,
            &fixture.paths.state,
        ] {
            assert!(path.exists(), "{context}时必须保留 {}", path.display());
        }
    }

    fn assert_agent_targets_preserved_without_unit(fixture: &AgentUninstallFixture, context: &str) {
        for path in [
            &fixture.paths.binary,
            &fixture.paths.config,
            &fixture.paths.data_dir,
            &fixture.paths.state,
        ] {
            assert!(path.exists(), "{context}时必须保留 {}", path.display());
        }
        assert!(
            !fixture.paths.unit.exists(),
            "{context}时本就不存在 unit 文件，不应被创建"
        );
    }

    #[test]
    fn uninstall_stop_failure_preserves_files_and_state() {
        let fixture = agent_uninstall_fixture("stop-fail", true);
        let unit = fixture.paths.unit.clone();
        let mut service = UninstallFakeService::stopped(Some(unit));
        service.stop_error = Some("mock stop failure");
        service.state = std::cell::RefCell::new(ServiceState::Active);
        let (result, fixture) = run_agent_uninstall(fixture, &service);
        let message = format!("{:#}", result.expect_err("stop 失败必须返回错误"));
        assert!(message.contains("停止 agent 服务"), "{message}");
        assert!(message.contains("安装状态已保留"), "{message}");
        assert_eq!(service.stop_calls.get(), 1);
        assert_eq!(service.disable_calls.get(), 0);
        assert_agent_targets_preserved(&fixture, "stop 失败");
    }

    #[test]
    fn uninstall_active_or_unknown_state_preserves_files_and_state() {
        let fixture = agent_uninstall_fixture("active", true);
        let unit = fixture.paths.unit.clone();
        let mut active = UninstallFakeService::stopped(Some(unit));
        active.state = std::cell::RefCell::new(ServiceState::Active);
        active.state_after_stop = ServiceState::Active;
        let (result, fixture) = run_agent_uninstall(fixture, &active);
        let message = format!("{:#}", result.expect_err("仍 active 必须失败"));
        assert!(message.contains("ActiveState=active"), "{message}");
        assert_eq!(active.disable_calls.get(), 0);
        assert_agent_targets_preserved(&fixture, "仍 active");

        let fixture = agent_uninstall_fixture("unknown", true);
        let unit = fixture.paths.unit.clone();
        let mut unknown = UninstallFakeService::stopped(Some(unit));
        unknown.state_error = Some("mock ActiveState failure");
        let (result, fixture) = run_agent_uninstall(fixture, &unknown);
        let message = format!("{:#}", result.expect_err("无法确认停止必须失败"));
        assert!(message.contains("无法确认 agent 服务"), "{message}");
        assert_eq!(unknown.disable_calls.get(), 0);
        assert_agent_targets_preserved(&fixture, "状态未知");
    }

    /// unit 文件已不存在但同名服务仍 active：preflight 之后也必须拒绝删除/purge。
    #[test]
    fn uninstall_missing_unit_but_active_service_preserves_everything() {
        for (tag, state) in [
            ("activating", ServiceState::Activating),
            ("deactivating", ServiceState::Deactivating),
            ("other", ServiceState::Other("maintenance".to_string())),
        ] {
            let fixture = agent_uninstall_fixture(&format!("unit-missing-{tag}"), false);
            let mut service = UninstallFakeService::stopped(None);
            service.state = std::cell::RefCell::new(state.clone());
            let (result, fixture) = run_agent_uninstall(fixture, &service);
            let message = format!("{:#}", result.expect_err("unit 缺失但服务未停止必须失败"));
            assert!(
                message.contains(&format!("ActiveState={}", state.as_str())),
                "{message}"
            );
            assert_eq!(service.stop_calls.get(), 0, "unit 缺失时不得 stop");
            assert_eq!(service.disable_calls.get(), 0);
            assert_agent_targets_preserved_without_unit(&fixture, "unit 缺失但服务未停止");
        }
    }

    /// unit 文件缺失但同名服务已明确 stopped：允许清理，且不得 stop / 清理链接。
    #[test]
    fn uninstall_missing_unit_but_inactive_service_proceeds() {
        let fixture = agent_uninstall_fixture("unit-missing-inactive", false);
        let service = UninstallFakeService::stopped(None);
        let (result, fixture) = run_agent_uninstall(fixture, &service);
        result.expect("unit 缺失但服务 inactive 时卸载应成功");
        assert_eq!(service.stop_calls.get(), 0);
        assert_eq!(service.disable_calls.get(), 0);
        assert!(!fixture.paths.unit.exists());
        assert!(!fixture.paths.binary.exists());
        assert!(!fixture.paths.config.exists());
        assert!(!fixture.paths.data_dir.exists());
        assert!(!fixture.paths.state.exists());
    }

    #[test]
    fn uninstall_successful_stop_removes_files_and_state() {
        let fixture = agent_uninstall_fixture("stop-ok", true);
        let unit = fixture.paths.unit.clone();
        // 同名 foreign unit 的 enable 链接：指向别的 unit，卸载必须保留。
        let foreign = fixture.paths.prefix.join("foreign-agent.service");
        std::fs::write(&foreign, b"foreign unit").unwrap();
        let wants = fixture
            .paths
            .unit
            .parent()
            .unwrap()
            .join("multi-user.target.wants");
        std::fs::create_dir_all(&wants).unwrap();
        let foreign_link = wants.join(Role::Agent.unit_name());
        std::os::unix::fs::symlink(&foreign, &foreign_link).unwrap();
        let service = UninstallFakeService::stopped(Some(unit));
        let (result, fixture) = run_agent_uninstall(fixture, &service);
        result.expect("已停止时卸载应成功");
        assert!(
            std::fs::symlink_metadata(&foreign_link).is_ok(),
            "同名外来 unit 的 wants 链接必须保留"
        );
        assert!(foreign.exists(), "外来 unit 不能被删除");
        assert_eq!(service.stop_calls.get(), 1);
        assert_eq!(service.disable_calls.get(), 1);
        assert!(!fixture.paths.unit.exists());
        assert!(!fixture.paths.binary.exists());
        assert!(!fixture.paths.config.exists());
        assert!(!fixture.paths.data_dir.exists());
        assert!(!fixture.paths.state.exists());
    }

    /// #77：安装激活流程的 fake systemd，记录 restart / PID 变化。
    struct InstallFakeService {
        pid: std::cell::Cell<u32>,
        next_pid: u32,
        state: std::cell::RefCell<ServiceState>,
        restart_error: Option<&'static str>,
        flap: bool,
        flap_count: std::cell::Cell<usize>,
        restart_calls: std::cell::Cell<usize>,
        enable_calls: std::cell::Cell<usize>,
        stop_calls: std::cell::Cell<usize>,
        disable_calls: std::cell::Cell<usize>,
    }

    impl InstallFakeService {
        fn new(pid: u32, next_pid: u32) -> Self {
            Self {
                pid: std::cell::Cell::new(pid),
                next_pid,
                state: std::cell::RefCell::new(if pid > 0 {
                    ServiceState::Active
                } else {
                    ServiceState::Inactive
                }),
                restart_error: None,
                flap: false,
                flap_count: std::cell::Cell::new(0),
                restart_calls: std::cell::Cell::new(0),
                enable_calls: std::cell::Cell::new(0),
                stop_calls: std::cell::Cell::new(0),
                disable_calls: std::cell::Cell::new(0),
            }
        }

        fn crash_looping(pid: u32) -> Self {
            let mut service = Self::new(pid, pid);
            service.flap = true;
            service
        }

        fn set_state(&self, state: ServiceState) {
            *self.state.borrow_mut() = state;
        }
    }

    impl ServiceControl for InstallFakeService {
        fn fragment_path(&self, _unit: &str) -> Result<Option<PathBuf>> {
            Ok(None)
        }

        fn ensure_fragment_is(&self, _unit: &str, _expected: &Path) -> Result<()> {
            Ok(())
        }

        fn daemon_reload(&self) -> Result<()> {
            Ok(())
        }

        fn is_managing(&self) -> bool {
            true
        }

        fn active_state(&self, _unit: &str) -> Result<ServiceState> {
            if self.flap {
                let count = self.flap_count.get();
                self.flap_count.set(count + 1);
                return Ok(if count.is_multiple_of(2) {
                    ServiceState::Active
                } else {
                    ServiceState::Failed
                });
            }
            Ok(self.state.borrow().clone())
        }

        fn main_pid(&self, _unit: &str) -> Result<u32> {
            Ok(self.pid.get())
        }

        fn enable_now(&self, _unit: &str) -> Result<()> {
            self.enable_calls.set(self.enable_calls.get() + 1);
            self.set_state(ServiceState::Active);
            if self.pid.get() == 0 {
                self.pid.set(self.next_pid);
            }
            Ok(())
        }

        fn restart(&self, _unit: &str) -> Result<()> {
            self.restart_calls.set(self.restart_calls.get() + 1);
            if let Some(message) = self.restart_error {
                return Err(anyhow!(message));
            }
            self.set_state(ServiceState::Active);
            self.pid.set(self.next_pid);
            Ok(())
        }

        fn stop(&self, _unit: &str) -> Result<()> {
            self.stop_calls.set(self.stop_calls.get() + 1);
            self.set_state(ServiceState::Inactive);
            self.pid.set(0);
            Ok(())
        }

        fn disable(&self, _unit: &str) -> Result<()> {
            self.disable_calls.set(self.disable_calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn active_service_with_zero_previous_pid_fails_closed() {
        let error = ensure_active_service_pid(true, 0).expect_err("active + PID=0 必须拒绝");
        assert!(error.to_string().contains("MainPID 为 0"), "{error}");
        ensure_active_service_pid(false, 0).expect("未 active 不要求旧 PID");
        ensure_active_service_pid(true, 111).expect("active + 有效 PID 允许");
    }

    /// 从已 active（旧 PID=111）开始：必须 restart，并验证 MainPID = 222。
    #[test]
    fn active_install_restarts_and_verifies_new_pid() {
        let service = InstallFakeService::new(111, 222);
        let expected = Path::new("/var/lib/rustboard/etc/systemd/system/rustboard-agent.service");
        let pid = activate_agent_service(
            &service,
            AGENT_UNIT_NAME,
            expected,
            true,
            111,
            Duration::from_secs(2),
        )
        .expect("restart 后应确认新进程");
        assert_eq!(pid, 222, "必须返回重启后的新 MainPID");
        assert_eq!(
            service.restart_calls.get(),
            1,
            "was_active 必须调用 restart"
        );
        assert_eq!(service.enable_calls.get(), 1, "仍需 enable 保持开机自启");
        assert!(matches!(*service.state.borrow(), ServiceState::Active));
    }

    /// 原本未运行：enable --now 启动，不调用 restart，但仍要确认新进程。
    #[test]
    fn inactive_install_starts_without_restart() {
        let service = InstallFakeService::new(0, 333);
        let expected = Path::new("/var/lib/rustboard/etc/systemd/system/rustboard-agent.service");
        let pid = activate_agent_service(
            &service,
            AGENT_UNIT_NAME,
            expected,
            false,
            0,
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(pid, 333);
        assert_eq!(service.enable_calls.get(), 1);
        assert_eq!(service.restart_calls.get(), 0);
    }

    /// restart 返回成功但 PID 没变（等价于 enable --now 的 no-op）：必须失败。
    #[test]
    fn restart_without_new_pid_fails_closed() {
        let service = InstallFakeService::new(111, 111);
        let expected = Path::new("/var/lib/rustboard/etc/systemd/system/rustboard-agent.service");
        let error = activate_agent_service(
            &service,
            AGENT_UNIT_NAME,
            expected,
            true,
            111,
            Duration::from_millis(50),
        )
        .expect_err("PID 未变化不能视为成功");
        let message = format!("{error:#}");
        assert!(message.contains("稳定运行"), "{message}");
        assert!(message.contains("MainPID=111"), "{message}");
    }

    /// previous_pid=0 时不能跳过校验：PID 一直为 0 必须失败，而不是立即成功。
    #[test]
    fn previous_pid_zero_does_not_skip_process_verification() {
        let service = InstallFakeService::new(0, 0);
        let expected = Path::new("/var/lib/rustboard/etc/systemd/system/rustboard-agent.service");
        let error = activate_agent_service(
            &service,
            AGENT_UNIT_NAME,
            expected,
            true,
            0,
            Duration::from_millis(100),
        )
        .expect_err("PID=0 不能视为新进程");
        let message = format!("{error:#}");
        assert!(message.contains("稳定运行"), "{message}");
        assert!(message.contains("MainPID"), "{message}");
    }

    /// restart 后 crash-loop（active/failed 交替）不能因瞬时 active 而成功。
    #[test]
    fn crash_looping_service_is_not_treated_as_success() {
        let service = InstallFakeService::crash_looping(444);
        let expected = Path::new("/var/lib/rustboard/etc/systemd/system/rustboard-agent.service");
        let error = activate_agent_service(
            &service,
            AGENT_UNIT_NAME,
            expected,
            true,
            111,
            Duration::from_millis(700),
        )
        .expect_err("crash-loop 不能稳定 500ms，必须失败");
        let message = format!("{error:#}");
        assert!(message.contains("稳定运行"), "{message}");
    }

    /// restart 失败后回滚：旧 config / binary / unit / state 恢复，旧服务被重新
    /// restart（不是只 enable --now）。
    #[test]
    fn restart_failure_rolls_back_files_and_service() {
        let dir = temp_dir("restart-rollback");
        let paths = Paths::for_role(Role::Agent, &dir, PathOverrides::default()).unwrap();
        std::fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        std::fs::create_dir_all(paths.binary.parent().unwrap()).unwrap();
        std::fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        std::fs::create_dir_all(paths.state.parent().unwrap()).unwrap();
        std::fs::write(&paths.config, b"old-config").unwrap();
        std::fs::write(&paths.binary, b"old-binary").unwrap();
        std::fs::write(&paths.unit, b"old-unit").unwrap();
        let old_state = b"schema = 1\n".to_vec();
        std::fs::write(&paths.state, &old_state).unwrap();

        let mut txn = InstallTxn::begin(&paths, false).unwrap();
        txn.write(&paths.config, b"new-config", 0o600).unwrap();
        txn.write(&paths.binary, b"new-binary", 0o755).unwrap();
        txn.write(&paths.unit, b"new-unit", 0o644).unwrap();

        let service = InstallFakeService::new(111, 222);
        let error = rollback_agent_install(
            &service,
            &paths,
            &mut txn,
            Some(&old_state),
            true,
            true,
            true,
            anyhow!("mock install failure"),
        );
        let message = format!("{error:#}");
        assert!(
            message.contains("安装失败: mock install failure"),
            "{message}"
        );

        assert_eq!(std::fs::read(&paths.config).unwrap(), b"old-config");
        assert_eq!(std::fs::read(&paths.binary).unwrap(), b"old-binary");
        assert_eq!(std::fs::read(&paths.unit).unwrap(), b"old-unit");
        assert_eq!(std::fs::read(&paths.state).unwrap(), old_state);
        assert_eq!(service.stop_calls.get(), 1, "回滚必须 stop 本次启动的服务");
        assert_eq!(service.disable_calls.get(), 1);
        assert_eq!(
            service.restart_calls.get(),
            1,
            "回滚后必须 restart 旧服务，而不是只 enable --now"
        );
        assert_eq!(service.enable_calls.get(), 1);
        assert!(
            matches!(*service.state.borrow(), ServiceState::Active),
            "旧服务应恢复运行"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
