//! `rustboard-panel install` / `uninstall` 子命令。
//!
//! 安装器只负责面板这一个角色：生成 `panel.toml`、systemd unit、复制二进制并
//! 合并写入 `install-state.toml`。hub token 与初始密码的约束：
//!
//! - hub token 只从 `--hub-token-file`（0600、拒绝符号链接、≤4 KiB）或同 prefix
//!   的 `hub.toml` 的 `admin_token` 读取，绝不接受 argv；
//! - 密码只从 `--password-file` 读取或自动生成；自动生成的初始密码只在安装
//!   成功后打印一次；
//! - 错误信息只包含路径与字段名，不包含 token / 密码内容；
//! - `--dry-run` 不写文件、不创建目录、不调用 systemctl；读取 `hub.toml` /
//!   `panel.toml` 时走只读解析（`load_toml` 会 chmod 收紧权限，不能用于 dry-run）；
//! - 非 dry-run 的 install / uninstall 全程持有**全局**安装锁
//!   （[`InstallLock::acquire_global`]），并在读取 `install-state.toml` 之前获取；
//!   hub 调起的 panel 子进程继承父进程的锁（`RUSTBOARD_INSTALL_LOCK_HELD=1`）时
//!   跳过加锁，dry-run 也不加锁；
//! - 写盘前用 [`validate_install_prefix`] / [`validate_managed_path`] 校验前缀与
//!   受管路径；prefix 必须先校验**原始**输入，不能让 `//`、尾斜杠或 `.` 经
//!   [`Paths::for_role`] 归一化成生产路径；现存 unit 只允许是本安装器为当前
//!   prefix 渲染的（`unit_is_ours`），外来 unit 一律拒绝覆盖 / 停止 / 删除；
//! - systemd 按 unit 名字操作：`--systemd` 只接受系统 unit 目录；安装写 unit 后
//!   用 `FragmentPath` 确认 systemd 实际解析的就是本安装的 unit，卸载只对确认
//!   归属的 unit 执行 stop / disable，unit 文件不存在时绝不 stop；
//! - 同 prefix 的 `hub.toml` 为 `admin_tls=required` 时，Phase A 面板安装直接
//!   拒绝（即使显式 `--hub-url http://...`），不写出明文对接 required hub 的配置；
//! - uninstall 先完成全部只读 preflight（含 state 记录的 config / data 路径），
//!   再提示、停服、删除；只有 unit 位于系统 unit 目录时才调用 systemctl，prefix
//!   内 unit 只删文件。

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rustboard_common::config::{AdminTlsMode, CookieSecure, HubConfig, PanelConfig};
use rustboard_common::fsutil;
use rustboard_common::util::port_of;
use rustboard_common::DEFAULT_ADMIN_PORT;
use rustboard_install::{
    detect_system, is_systemd_unit_dir, pick_free_port, read_private_file, render_unit,
    require_systemd, shell_arg, unit_is_ours, validate_install_prefix, validate_managed_path,
    wait_http_ok, InstallLock, InstallState, InstallTxn, ManagedPathKind, PathOverrides, Paths,
    Prompt, Role, RoleState, ServiceManager,
};

/// token / 密码文件读取上限（方案要求 token ≤ 4 KiB）。
const SECRET_FILE_MAX_BYTES: usize = 4096;
/// 等待面板 `/healthz` 返回 200 的上限。
const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
/// 同 prefix 的 hub 配置相对路径。
const HUB_CONFIG_RELATIVE: &str = "etc/rustboard/hub.toml";
/// 生产默认配置路径：root prefix 下 `--purge` 只允许删除这些默认路径。
const PRODUCTION_CONFIG: &str = "/etc/rustboard/panel.toml";
/// 生产默认数据目录。
const PRODUCTION_DATA: &str = "/var/lib/rustboard/panel";
/// R-S5：Phase A 面板只支持明文 hub 管理 API；required 时必须在写盘 / 启动前拒绝。
const ADMIN_TLS_REQUIRED_UNSUPPORTED: &str =
    "Phase A 面板安装不支持 admin_tls=required；请等待 Phase C 或显式使用反代/HTTPS 部署";

/// `rustboard-panel install` 参数。
#[derive(Debug, Args)]
pub struct InstallArgs {
    /// 非交互模式。面板安装本身不需要确认，保留该 flag 以符合安装器统一契约。
    #[arg(long)]
    yes: bool,
    /// 离线模式；面板安装不发起任何网络请求，该 flag 只用于统一 CLI。
    #[arg(long)]
    offline: bool,
    /// 只打印计划，不写文件、不调用 systemctl。
    #[arg(long)]
    dry_run: bool,
    /// 覆盖已有安装：重写配置/unit/二进制并重启服务。
    #[arg(long)]
    force: bool,
    /// 安装前缀（测试/容器用），默认 `/`。
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// 面板配置文件路径；默认为 `<prefix>/etc/rustboard/panel.toml`。
    #[arg(long)]
    config: Option<PathBuf>,
    /// systemd unit 目录；默认为 `<prefix>/etc/systemd/system`。
    #[arg(long)]
    unit_dir: Option<PathBuf>,
    /// hub 管理 API 地址；未给时从同 prefix 的 `hub.toml` 推导。
    #[arg(long)]
    hub_url: Option<String>,
    /// hub 管理 token 的 0600 文件；未给时从同 prefix 的 `hub.toml` 读取。
    #[arg(long)]
    hub_token_file: Option<PathBuf>,
    /// 初始管理员密码的 0600 文件；未给时自动生成。
    #[arg(long)]
    password_file: Option<PathBuf>,
    /// 面板监听地址；未给时随机选择 `127.0.0.1:<五位数端口>`。
    #[arg(long)]
    listen: Option<String>,
    /// 前端静态资源目录；显式指定时必须包含 `index.html`。
    #[arg(long)]
    static_dir: Option<PathBuf>,
    /// 强制由 systemd 管理（需要 systemd 可用）。
    #[arg(long, conflicts_with = "no_systemd")]
    systemd: bool,
    /// 不写 unit、不调用 systemctl。
    #[arg(long, conflicts_with = "systemd")]
    no_systemd: bool,
}

/// `rustboard-panel uninstall` 参数。
#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// 安装前缀（测试/容器用），默认 `/`。
    #[arg(long)]
    prefix: Option<PathBuf>,
    /// 无安装记录时使用的配置文件路径。
    #[arg(long)]
    config: Option<PathBuf>,
    /// 无安装记录时使用的 unit 目录。
    #[arg(long)]
    unit_dir: Option<PathBuf>,
    /// 同时删除配置与数据目录；路径必须位于 prefix 内或是生产默认路径。
    #[arg(long)]
    purge: bool,
    /// 非交互确认（`--purge` 时不需要人工确认）。
    #[arg(long)]
    yes: bool,
    /// 只打印计划，不停止服务、不删除文件。
    #[arg(long)]
    dry_run: bool,
}

/// systemd 管理方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceMode {
    /// 写 unit 并用 systemctl 启动/重启。
    Manage,
    /// 只写 unit，不调用 systemctl（非 root prefix 的默认行为）。
    UnitOnly,
    /// 不写 unit、不调用 systemctl（`--no-systemd`）。
    None,
}

impl ServiceMode {
    /// 是否写 unit 文件。
    fn writes_unit(self) -> bool {
        !matches!(self, Self::None)
    }

    /// 是否由 systemd 管理服务。
    fn manages(self) -> bool {
        matches!(self, Self::Manage)
    }
}

/// 密码来源计划。
#[derive(Debug)]
enum PasswordPlan {
    /// 从 0600 文件读取（不打印）。
    FromFile(String),
    /// 自动生成（安装成功后打印一次）。
    Generated,
    /// `--force` 时沿用已有配置里的有效 PHC 哈希（不打印）。
    Preserve(String),
}

/// 执行安装。
pub fn install(args: InstallArgs) -> Result<()> {
    // P-01：必须先校验**原始** prefix。`Paths::for_role` 会把 `//`、尾斜杠与
    // `.` 归一化（`--prefix //` 会变成 `/`），如果只校验归一化结果，dry-run 会
    // 静默指向生产路径。这里在任何 Paths 解析之前拒绝这类输入。
    let paths = resolve_checked_paths(
        args.prefix.as_deref(),
        args.config.as_deref(),
        args.unit_dir.as_deref(),
        "",
    )?;
    let mode = resolve_service_mode(args.systemd, args.no_systemd, &paths)?;
    // 安装流程不需要交互确认；--yes 保留用于统一安装器契约。
    let _ = args.yes;

    // 非 dry-run 全程持有**全局**安装锁，且在读取 install-state 之前获取：并发
    // 安装 / 卸载（包括不同角色）会互相覆盖 config、unit 与 state。hub 调起的
    // panel 子进程继承父进程的锁，必须跳过，否则同一把 flock 会自锁失败。
    // dry-run 不写盘、不调用 systemctl，也不加锁（否则会创建锁文件）。
    let _lock = acquire_install_lock(args.dry_run, InstallLock::inherited(), "面板安装")?;
    let mut state = load_install_state(&paths.state)?;
    let unit_dir = unit_directory(&paths.unit)?;
    let service = ServiceManager::new(unit_dir, mode.manages(), args.dry_run);

    // R-S5：无论 hub_url / token 是否显式给出，只要同 prefix 的 hub.toml 存在就
    // 读取检查 admin_tls。dry-run 用只读解析，正常安装沿用会收紧权限的安全加载。
    let hub_config_path = paths.prefix.join(HUB_CONFIG_RELATIVE);
    let hub_config = load_hub_config_if_exists(&hub_config_path, args.dry_run)?;
    ensure_hub_admin_tls_supported(hub_config.as_ref())?;

    // 幂等：已有记录且文件齐全、服务 active 时直接返回；--force 才重写。
    let recorded = state.role(Role::Panel).cloned();
    match (recorded.as_ref(), args.force) {
        (Some(record), false) => {
            // 幂等捷径也必须先确认 systemd 实际解析的 unit：same-name 外来 unit
            // 或 transient unit 可能 active，不能把 `is-active` 当成自己的服务。
            ensure_install_fragment_before_idempotent(&service, &paths.unit, args.dry_run)?;
            return finish_installed(record, &paths, mode, &service, !args.dry_run);
        }
        (Some(record), true) => warn_if_paths_changed(record, &paths),
        (None, false) if path_exists(&paths.config) => bail!(
            "面板配置已存在但找不到安装记录: {}；请先运行 `rustboard-panel uninstall --prefix {} --config {}`\
             （默认保留数据），或使用 --force 覆盖配置",
            paths.config.display(),
            shell_arg(&paths.prefix.to_string_lossy()),
            shell_arg(&paths.config.to_string_lossy()),
        ),
        _ => {}
    }

    // M1/L5：写盘前按 allowlist 校验受管路径；拒绝 prefix 外的自定义配置 / 数据 /
    // 二进制，以及含 `$`、`%`、引号、反斜杠的路径（systemd / shell 转义歧义）。
    validate_install_paths(&paths, mode)?;
    // M3：目标 unit 已存在时，必须能证明它是本安装器为当前 prefix 渲染的。外来
    // unit 即使带 --force 也拒绝覆盖 / 停止，避免接管别人的服务。
    if mode.writes_unit() {
        ensure_existing_unit_is_ours(&paths, &paths.unit)?;
    }

    // --force 时以旧配置为底，保留 trusted_proxies / public_origin 等运维设置；
    // 解析失败（损坏）则按本次参数重新生成，旧文件由事务备份。dry-run 只做只读
    // 解析：`PanelConfig::load` 会 chmod 收紧权限，不能出现在 dry-run 路径上。
    let base_config = if args.force {
        load_existing_config(&paths.config, args.dry_run)
    } else {
        None
    };

    // hub 地址 / token：hub.toml 已在入口处加载（R-S5 需要无条件检查 admin_tls）。
    let hub_url = resolve_hub_url(
        args.hub_url.as_deref(),
        hub_config.as_ref(),
        &hub_config_path,
    )?;
    let token = match args.hub_token_file.as_deref() {
        Some(path) => read_secret_file(path, "hub token")?,
        None => match hub_config
            .as_ref()
            .map(|hub| hub.admin_token.trim())
            .filter(|token| !token.is_empty())
        {
            Some(token) => token.to_string(),
            None => bail!(
                "缺少 hub 管理 token：请使用 --hub-token-file 提供 0600 文件，\
                 或先安装 hub 使 {} 含非空 admin_token",
                hub_config_path.display()
            ),
        },
    };

    let listen = resolve_listen(args.listen.as_deref(), base_config.as_ref())?;
    let static_dir = resolve_static_dir(args.static_dir.as_deref(), base_config.as_ref())?;
    if static_dir.is_none() {
        warn_missing_static_dir();
    }

    let password = plan_password(args.password_file.as_deref(), base_config.as_ref())?;

    if args.dry_run {
        print_install_plan(
            &paths,
            mode,
            &listen,
            &hub_url,
            static_dir.as_deref(),
            &password,
            args.offline,
        );
        return Ok(());
    }

    let (password_hash, initial_password, password_note) = match password {
        PasswordPlan::FromFile(password) => (
            crate::auth::hash_password(&password).context("生成 Argon2id 密码哈希失败")?,
            None,
            "从 --password-file 读取（不显示）",
        ),
        PasswordPlan::Preserve(hash) => (hash, None, "沿用已有配置中的密码哈希（未改动）"),
        PasswordPlan::Generated => {
            let password = crate::generate_password();
            let hash =
                crate::auth::hash_password(&password).context("生成 Argon2id 密码哈希失败")?;
            (hash, Some(password), "自动生成（仅显示一次）")
        }
    };

    let mut cfg = base_config.unwrap_or_default();
    cfg.listen = listen;
    cfg.hub_url = hub_url;
    cfg.token = token;
    cfg.admin_password_hash = password_hash;
    cfg.static_dir = match static_dir.as_deref() {
        Some(path) => path
            .to_str()
            .ok_or_else(|| anyhow!("静态资源目录不是有效 UTF-8: {}", path.display()))?
            .to_string(),
        None => String::new(),
    };
    cfg.validate().context("面板配置校验失败")?;
    let config_bytes = render_panel_config(&cfg);
    // unit 文本在事务开始前渲染：渲染失败（路径含 systemd 特殊字符等）必须在任何
    // 落盘之前暴露，不能等到写完 config / 复制完 binary 才失败。
    let unit_text = if mode.writes_unit() {
        Some(render_unit(Role::Panel, &paths).context("渲染面板 systemd unit 失败")?)
    } else {
        None
    };

    let was_active = mode.manages() && service.is_active(Role::Panel.unit_name())?;
    let old_state = state_snapshot(&paths.state)?;
    let mut txn = InstallTxn::begin(&paths, false)?;
    let (outcome, reload_done, activation_attempted) = {
        let mut apply = ApplyInstall {
            txn: &mut txn,
            paths: &paths,
            cfg: &cfg,
            config_bytes: &config_bytes,
            unit_text: unit_text.as_deref(),
            mode,
            service: &service,
            was_active,
            reload_done: false,
            activation_attempted: false,
            state: &mut state,
        };
        let outcome = apply.run();
        (outcome, apply.reload_done, apply.activation_attempted)
    };
    if let Err(error) = outcome {
        return Err(rollback_failed_install(
            &service,
            Role::Panel.unit_name(),
            &paths.unit,
            was_active,
            reload_done,
            activation_attempted,
            &mut txn,
            &paths.state,
            old_state.as_deref(),
            error,
        ));
    }

    if let Some(password) = initial_password {
        println!("初始密码（仅显示一次，请立即保存）: {password}");
    }
    print_install_summary(&paths, mode, &cfg, password_note, args.offline);
    Ok(())
}

/// 安装失败后的回滚与状态恢复。
///
/// 只有本次真的调用过 `enable --now` / `restart` 才 stop/disable：仅仅
/// `daemon-reload` 不会启动服务，此时停服务会误杀安装前就在运行的旧实例。
/// stop/disable 与恢复旧的 active 服务前都必须用 `FragmentPath` 确认 unit
/// 仍归本安装所有，确认不了就跳过（宁可留服务，也不动同名外来 unit）。
/// 回滚、state 恢复与 daemon-reload 的错误全部并入返回错误；归属确认失败只
/// 警告，不能掩盖原始安装错误。原本 active 的旧服务在回滚成功后尽力恢复。
#[allow(clippy::too_many_arguments)]
fn rollback_failed_install(
    service: &ServiceManager,
    unit_name: &str,
    expected_unit: &Path,
    was_active: bool,
    reload_done: bool,
    activation_attempted: bool,
    txn: &mut InstallTxn,
    state_path: &Path,
    previous_state: Option<&[u8]>,
    error: anyhow::Error,
) -> anyhow::Error {
    if activation_attempted {
        // 后置 FragmentPath 检查失败时 unit 可能已被同名外来 / 更高优先级 unit
        // 顶替；停止前重新确认，无法确认就跳过 stop/disable。
        match service.ensure_fragment_is(unit_name, expected_unit) {
            Ok(()) => {
                if let Err(stop_error) = service.stop_disable(unit_name) {
                    eprintln!("警告: 安装失败后停止本次启动的 {unit_name} 失败: {stop_error:#}");
                }
            }
            Err(guard_error) => {
                eprintln!("警告: 跳过停止，无法确认 unit 归属（{unit_name}）: {guard_error:#}")
            }
        }
    }

    let mut failures: Vec<String> = Vec::new();
    let rolled_back = match txn.rollback() {
        Ok(()) => true,
        Err(rollback_error) => {
            failures.push(format!("回滚本次写入失败: {rollback_error:#}"));
            false
        }
    };
    if let Err(restore_error) = restore_state(state_path, previous_state) {
        failures.push(format!("恢复安装状态失败: {restore_error:#}"));
    }
    if reload_done {
        if let Err(reload_error) = service.daemon_reload() {
            failures.push(format!(
                "回滚后 systemctl daemon-reload 失败: {reload_error:#}"
            ));
        }
    }

    if was_active && activation_attempted && rolled_back {
        // 回滚可能恢复旧 unit 或删除本次新建的 unit；恢复服务前再确认一次
        // FragmentPath，无法确认归属时跳过，不能按名字启用外来 unit。
        match service.ensure_fragment_is(unit_name, expected_unit) {
            Ok(()) => {
                if let Err(enable_error) = service.enable_now(unit_name) {
                    eprintln!("警告: 回滚后恢复原有 {unit_name} 服务失败: {enable_error:#}");
                }
            }
            Err(guard_error) => {
                eprintln!("警告: 跳过恢复，无法确认 unit 归属（{unit_name}）: {guard_error:#}")
            }
        }
    }

    if failures.is_empty() {
        error.context("面板安装失败，已回滚本次改动")
    } else {
        error.context(format!(
            "面板安装失败，回滚/恢复未完成: {}",
            failures.join("；")
        ))
    }
}

/// 应用安装事务。
struct ApplyInstall<'a> {
    txn: &'a mut InstallTxn,
    paths: &'a Paths,
    cfg: &'a PanelConfig,
    config_bytes: &'a str,
    /// 事务开始前渲染好的 unit；`None` 表示本次不写 unit。
    unit_text: Option<&'a str>,
    mode: ServiceMode,
    service: &'a ServiceManager,
    was_active: bool,
    /// 本次是否成功执行过 daemon-reload（回滚后需要再次 reload）。
    reload_done: bool,
    /// 本次是否尝试过 enable / restart（只有此时回滚才允许 stop/disable）。
    activation_attempted: bool,
    state: &'a mut InstallState,
}

impl ApplyInstall<'_> {
    fn run(&mut self) -> Result<()> {
        self.txn.create_owned_dir(&self.paths.data_dir, 0o700)?;
        self.txn
            .write(&self.paths.config, self.config_bytes.as_bytes(), 0o600)?;
        if let Some(unit) = self.unit_text {
            self.txn.write(&self.paths.unit, unit.as_bytes(), 0o644)?;
        }
        install_binary(self.txn, &self.paths.binary)?;

        if self.mode.manages() {
            let unit_name = Role::Panel.unit_name();
            self.service.daemon_reload()?;
            self.reload_done = true;
            // 写完 unit 且 daemon-reload 后，以 systemd 实际解析的 FragmentPath
            // 为准：/etc/systemd/system 中同名 unit 优先级高于 /run，transient
            // unit 也可能先占住名字。不是本次写入的 unit 就绝不能 enable/restart。
            self.service
                .ensure_fragment_is(unit_name, &self.paths.unit)?;
            // 标记在调用之前：即使 enable/restart 失败，服务也可能已经被半启动，
            // 回滚需要 stop/disable 防止残留。
            self.activation_attempted = true;
            if self.was_active {
                self.service.restart(unit_name)?;
            } else {
                self.service.enable_now(unit_name)?;
            }
            // 启用 / 重启后再确认一次：避免操作期间被同名 unit 抢占（fail-closed，
            // 失败会走回滚并 stop/disable 本次启动的服务）。
            self.service
                .ensure_fragment_is(unit_name, &self.paths.unit)?;
            let port = port_of(&self.cfg.listen)
                .ok_or_else(|| anyhow!("面板 listen 缺少可解析端口: {}", self.cfg.listen))?;
            wait_http_ok(&format!("http://127.0.0.1:{port}/healthz"), HEALTH_TIMEOUT)
                .context("面板服务启动后 /healthz 未在时限内返回 200")?;
        }

        self.state.upsert(
            Role::Panel,
            RoleState::new(self.paths, env!("CARGO_PKG_VERSION"), self.txn.backup_dir()),
        );
        self.state.save(&self.paths.state)?;
        self.txn.commit()
    }
}

/// 执行卸载。
pub fn uninstall(args: UninstallArgs) -> Result<()> {
    // P-01：与 install 相同，先校验原始 prefix，避免 `--prefix //` 归一化成 `/`
    // 后把 dry-run / 卸载指向生产路径。
    let paths = resolve_checked_paths(
        args.prefix.as_deref(),
        args.config.as_deref(),
        args.unit_dir.as_deref(),
        "，拒绝卸载",
    )?;
    // 非 dry-run 全程持有全局锁，且在读取 install-state 之前获取，避免与安装 /
    // 另一次卸载（包括其他角色）并发。hub 子进程继承父进程锁时跳过；dry-run 不加锁。
    let _lock = acquire_install_lock(args.dry_run, InstallLock::inherited(), "面板卸载")?;
    let mut state = load_install_state(&paths.state)?;
    let record = state.role(Role::Panel).cloned();
    // 有安装记录时优先使用记录中的路径：e2e 的 unit 在 /run/systemd/system，
    // 卸载命令不带 --unit-dir 也必须能停服务并删除 unit。
    let config_path = record
        .as_ref()
        .map_or_else(|| paths.config.clone(), |record| record.config.clone());
    let data_path = record
        .as_ref()
        .map_or_else(|| paths.data_dir.clone(), |record| record.data_dir.clone());
    let unit_path = record
        .as_ref()
        .map_or_else(|| paths.unit.clone(), |record| record.unit.clone());
    let binary_path = record
        .as_ref()
        .map_or_else(|| paths.binary.clone(), |record| record.binary.clone());
    let unit_dir = unit_directory(&unit_path)?;

    // R-S2：只有 unit 位于系统 unit 目录且 systemd 可用时才允许查询 / stop /
    // disable。`--prefix /opt/test` 的 unit 在 prefix 内，只删文件，绝不触碰宿主
    // 的同名生产 `rustboard-panel.service`。
    let systemd_manage = manage_service_for(&unit_dir, detect_system().systemd);
    let service = ServiceManager::new(unit_dir, systemd_manage, args.dry_run);
    let unit_name = Role::Panel.unit_name();

    // H1/M4：在提示、停服、删除之前完成全部只读 preflight。
    let record_paths = record_paths_for(&paths, &config_path, &data_path, &unit_path, &binary_path);
    validate_managed_path(
        Role::Panel,
        &paths.prefix,
        &unit_path,
        ManagedPathKind::Unit,
    )
    .with_context(|| format!("拒绝对 unit 路径 {} 执行卸载", unit_path.display()))?;
    validate_managed_path(
        Role::Panel,
        &paths.prefix,
        &binary_path,
        ManagedPathKind::Binary,
    )
    .with_context(|| format!("拒绝对二进制路径 {} 执行卸载", binary_path.display()))?;
    // P-04：即使没有 --purge、不删除 config / data，也必须校验 state 记录中的
    // 这两个路径：受管范围、特殊字符、普通文件 / 目录且非符号链接。否则伪造
    // state 可以把卸载流程引向 prefix 外的任意路径（后续 --purge 才真正删除，
    // 但非法记录本身就必须在 preflight 失败）。
    validate_recorded_config_and_data(&paths, &config_path, &data_path)?;
    // unit / binary 总是要求“普通文件或不存在”；config 默认保留，但同样拒绝在
    // 符号链接 / 目录路径上继续卸载。data 只在 --purge 时作为删除目标校验。
    let unit_exists = check_existing_regular_file(&unit_path, "panel unit")?;
    check_existing_regular_file(&binary_path, "panel 二进制")?;
    if unit_exists {
        // 外来 unit 一律报错：不 stop / disable / 删除。
        ensure_existing_unit_is_ours(&record_paths, &unit_path)?;
    }

    // R-S3：unit 文件存在时必须核对 systemd 实际解析的 FragmentPath：
    // - Some 且不是本安装的 unit：同名外来 / 更高优先级，直接报错，不 stop / 删；
    // - None：无法证明 unit 已被 systemd 加载（transient / 未加载），只删除本安装
    //   写入的 unit 文件，不调用任何 systemctl；
    // - 只有 fragment == unit 才允许 stop / disable。
    // unit 文件不存在时绝不 stop（即使同名服务 active）。
    let service_action = if args.dry_run || !unit_exists || !systemd_manage {
        UninstallServiceAction::RemoveFileOnly
    } else {
        let actual = service.fragment_path(unit_name)?;
        let action = decide_uninstall_service(actual.as_deref(), &unit_path)?;
        if action == UninstallServiceAction::RemoveFileOnly {
            eprintln!(
                "警告: systemd 未解析到 unit 文件 {}（transient / 尚未加载）；\
                 只删除本安装写入的 unit 文件，不调用 systemctl",
                unit_path.display()
            );
        }
        action
    };

    // --purge 目标先做只读校验：符号链接、prefix 外路径、包含 install-state 的
    // 目录都在停止服务之前拒绝，避免卸到一半才发现不能删。
    let purge_targets = if args.purge {
        Some(prepare_purge_targets(&paths, &config_path, &data_path)?)
    } else {
        None
    };

    if args.dry_run {
        print_uninstall_plan(
            &paths,
            &unit_path,
            &binary_path,
            &config_path,
            &data_path,
            args.purge,
        );
        return Ok(());
    }

    // preflight 全部通过后才提示；取消时未做任何修改。
    if let Some(targets) = &purge_targets {
        if !args.yes && (targets.config.is_some() || targets.data.is_some()) {
            let question = format!(
                "确认删除面板配置 {} 与数据目录 {}？该操作不可恢复",
                config_path.display(),
                data_path.display()
            );
            let prompt = Prompt::new(false);
            if !prompt.confirm(&question, false)? {
                println!("已取消卸载（未做任何修改）");
                return Ok(());
            }
        }
    }

    let mut unit_removed = false;
    if unit_exists {
        if service_action == UninstallServiceAction::StopAndDisable {
            // preflight 与真正 stop 之间隔着 --purge 确认（prompt），期间 unit
            // 可能被替换。执行前即时复核 FragmentPath；确认不了就直接返回错误，
            // 此时尚未删除任何文件，绝不 stop/disable。
            service.ensure_fragment_is(unit_name, &unit_path).context(
                "停止前 systemd 解析的 panel unit 已变化；未 stop/disable，也未删除任何文件",
            )?;
            // disable / stop 失败只警告并继续：unit 与 state 必须清理，否则会留下
            // “无法重装 / 开机仍自启”的中间状态。这里只对 fragment 已确认归属的
            // unit 调用 systemctl，不直接删除 `/etc` 下的任何 wants 链接。
            if let Err(error) = service.stop_disable(unit_name) {
                eprintln!("警告: 停止/禁用 {unit_name} 失败（继续删除 unit）: {error:#}");
            }
            unit_removed = remove_regular_file(&unit_path, "panel unit")?;
            if let Err(error) = service.daemon_reload() {
                eprintln!("警告: 删除 {unit_name} 后 systemctl daemon-reload 失败: {error:#}");
            }
        } else {
            // unit 在 prefix 内、systemd 未解析到该 unit，或 unit 文件不存在：
            // 只删本安装写入的文件，不调用 systemctl。
            unit_removed = remove_regular_file(&unit_path, "panel unit")?;
        }
    }

    let binary_removed = remove_regular_file(&binary_path, "panel 二进制")?;

    // 先完成 --purge 删除，再删除 state 记录：purge 失败时保留记录，重试卸载仍能
    // 定位到同一组路径；state 中 roles 为空时删除整个 state 文件。
    let mut purged_config = false;
    let mut purged_data = false;
    if let Some(targets) = purge_targets {
        if let Some(config) = targets.config {
            check_existing_regular_file(&config, "panel 配置")?;
            fs::remove_file(&config)
                .with_context(|| format!("删除面板配置 {} 失败", config.display()))?;
            purged_config = true;
        }
        if let Some(data) = targets.data {
            check_removable_directory(&data, "panel 数据目录")?;
            fs::remove_dir_all(&data)
                .with_context(|| format!("删除面板数据目录 {} 失败", data.display()))?;
            purged_data = true;
        }
    }

    let removed_record = remove_state_record(&mut state, &paths.state)?;

    print_uninstall_summary(
        &paths,
        &unit_path,
        &binary_path,
        &config_path,
        &data_path,
        unit_removed,
        binary_removed,
        removed_record,
        args.purge,
        purged_config,
        purged_data,
    );
    Ok(())
}

/// 只有 systemd 可用且 unit 位于系统 unit 目录时，才允许对同名 unit 调用
/// systemctl。prefix 内的 unit 只删文件，避免测试 prefix 误停宿主生产服务。
fn manage_service_for(unit_dir: &Path, systemd_available: bool) -> bool {
    systemd_available && is_systemd_unit_dir(unit_dir)
}

/// 用安装记录（或本次参数）的路径重建 [`Paths`]，供 `unit_is_ours` 精确比较
/// ExecStart；state / backup_root 不影响 unit 归属判断。
fn record_paths_for(
    paths: &Paths,
    config: &Path,
    data_dir: &Path,
    unit: &Path,
    binary: &Path,
) -> Paths {
    Paths {
        prefix: paths.prefix.clone(),
        config: config.to_path_buf(),
        data_dir: data_dir.to_path_buf(),
        unit: unit.to_path_buf(),
        binary: binary.to_path_buf(),
        state: paths.state.clone(),
        backup_root: paths.backup_root.clone(),
    }
}

/// 安装写盘前按 allowlist 校验受管路径。
///
/// 路径中含 `$` / `%` / 引号 / 反斜杠时一律拒绝：这些字符在 systemd unit 或
/// shell 提示命令里会被展开 / 转义，容易产生注入歧义。数据目录 / 二进制 /
/// 配置必须落在 prefix 允许范围内；unit 还必须是系统 unit 目录或 prefix 内。
fn validate_install_paths(paths: &Paths, mode: ServiceMode) -> Result<()> {
    for (path, kind, label) in [
        (&paths.config, ManagedPathKind::Config, "面板配置"),
        (&paths.data_dir, ManagedPathKind::Data, "面板数据目录"),
        (&paths.binary, ManagedPathKind::Binary, "面板二进制"),
    ] {
        reject_unsafe_path_chars(path, label)?;
        validate_managed_path(Role::Panel, &paths.prefix, path, kind)
            .with_context(|| format!("{label}路径不安全: {}", path.display()))?;
    }
    if mode.writes_unit() {
        reject_unsafe_path_chars(&paths.unit, "panel unit")?;
        validate_managed_path(
            Role::Panel,
            &paths.prefix,
            &paths.unit,
            ManagedPathKind::Unit,
        )
        .with_context(|| format!("拒绝对 unit 路径 {} 执行安装", paths.unit.display()))?;
    }
    Ok(())
}

/// 卸载 preflight：校验 state 记录（或本次参数）中的 config / data 路径。
///
/// P-04：即使没有 `--purge`、本次不会删除这两个路径，也必须拒绝 prefix 外路径、
/// systemd / shell 特殊字符、符号链接与类型不符的文件。否则伪造 `install-state`
/// 可以把卸载流程引向任意路径；存在性与递归删除检查仍由 `--purge` 分支负责。
fn validate_recorded_config_and_data(
    paths: &Paths,
    config_path: &Path,
    data_path: &Path,
) -> Result<()> {
    for (path, kind, label) in [
        (config_path, ManagedPathKind::Config, "面板配置"),
        (data_path, ManagedPathKind::Data, "面板数据目录"),
    ] {
        reject_unsafe_path_chars(path, label)?;
        validate_managed_path(Role::Panel, &paths.prefix, path, kind)
            .with_context(|| format!("拒绝卸载{label}路径 {}", path.display()))?;
    }
    check_existing_regular_file(config_path, "panel 配置")?;
    check_removable_directory(data_path, "panel 数据目录")?;
    Ok(())
}

/// 拒绝写入 config / unit / 提示命令的路径里出现 systemd / shell 特殊字符。
fn reject_unsafe_path_chars(path: &Path, label: &str) -> Result<()> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow!("{label}路径不是有效 UTF-8: {}", path.display()))?;
    if let Some(ch) = text.chars().find(|ch| ch.is_control()) {
        bail!("{label}路径含控制字符（含换行）{ch:?}: {text:?}");
    }
    if let Some(ch) = text
        .chars()
        .find(|ch| matches!(ch, '$' | '%' | '"' | '\'' | '\\'))
    {
        bail!("{label}路径含 `{ch}`（systemd / shell 展开或引号歧义）: {text:?}");
    }
    Ok(())
}

/// 校验现存 unit 是“本安装器为当前路径渲染的”unit。
///
/// 路径不存在返回 `Ok(())`；存在时必须是普通文件、非符号链接，且同时带
/// [`rustboard_install::UNIT_MARKER`] 与精确的 ExecStart 行。外来 unit（同名但
/// 手工编写 / 属于另一个 prefix）一律报错，调用方不得覆盖、停止或删除它。
fn ensure_existing_unit_is_ours(paths: &Paths, unit_path: &Path) -> Result<()> {
    let Some(contents) = read_existing_unit(unit_path)? else {
        return Ok(());
    };
    let text = String::from_utf8(contents).unwrap_or_default();
    if !unit_is_ours(Role::Panel, paths, &text) {
        bail!(
            "现存 unit {} 不是本安装器为当前 prefix 生成的，拒绝覆盖/停止/删除\
             （--force 也不会覆盖外来 unit）；请先手动处理该 unit，或改用其他 --prefix/--unit-dir",
            unit_path.display()
        );
    }
    Ok(())
}

/// 读取现存 unit：不存在返回 `None`；符号链接 / 非普通文件直接拒绝。
fn read_existing_unit(unit_path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(unit_path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("读取 unit {} 元数据失败", unit_path.display()))
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!(
                "现存 unit {} 是符号链接，拒绝覆盖/停止/删除",
                unit_path.display()
            )
        }
        Ok(meta) if !meta.is_file() => {
            bail!(
                "现存 unit {} 不是普通文件，拒绝覆盖/停止/删除",
                unit_path.display()
            )
        }
        Ok(_) => fs::read(unit_path)
            .map(Some)
            .with_context(|| format!("读取现存 unit {} 失败", unit_path.display())),
    }
}

/// 存在目标必须是普通文件（或不存在）；返回是否存在。符号链接 / 目录一律拒绝。
fn check_existing_regular_file(path: &Path, label: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("读取 {label} {} 元数据失败", path.display()))
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("{label} {} 是符号链接，拒绝卸载", path.display())
        }
        Ok(meta) if !meta.is_file() => {
            bail!("{label} {} 不是普通文件，拒绝卸载", path.display())
        }
        Ok(_) => Ok(true),
    }
}

/// `--purge` 数据目录必须是普通目录（非符号链接）。
fn check_removable_directory(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("读取 {label} {} 元数据失败", path.display()))
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("{label} {} 是符号链接，拒绝 --purge 删除", path.display())
        }
        Ok(meta) if !meta.is_dir() => {
            bail!("{label} {} 不是目录，拒绝 --purge 删除", path.display())
        }
        Ok(_) => Ok(()),
    }
}

/// 从安装状态删除 panel 记录。
///
/// 删除记录前调用方必须已完成 --purge；`roles` 为空时删除整个 state 文件，
/// 避免留下只含 `schema = 1` 的空文件。
fn remove_state_record(state: &mut InstallState, state_path: &Path) -> Result<bool> {
    if state.remove_role(Role::Panel).is_none() {
        return Ok(false);
    }
    if state.roles.is_empty() {
        match fs::remove_file(state_path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
            Err(error) => Err(error)
                .with_context(|| format!("删除空的安装状态 {} 失败", state_path.display())),
        }
    } else {
        state
            .save(state_path)
            .context("从安装状态删除 panel 记录失败")?;
        Ok(true)
    }
}

/// 解析安装路径；prefix 默认 `/`。
///
/// **必须先校验原始 prefix**：`Paths::for_role` 会归一化 `//`、尾斜杠与 `.`，
/// 例如 `--prefix //` 会被归一化成 `/`，若只校验归一化结果，dry-run 与卸载会
/// 静默指向生产路径。`validate_install_prefix` 对原始输入拒绝这些写法。
fn resolve_checked_paths(
    prefix: Option<&Path>,
    config: Option<&Path>,
    unit_dir: Option<&Path>,
    context: &str,
) -> Result<Paths> {
    let raw_prefix = prefix.unwrap_or_else(|| Path::new("/"));
    validate_install_prefix(raw_prefix)
        .with_context(|| format!("安装前缀 {} 不可用{context}", raw_prefix.display()))?;
    resolve_paths(Some(raw_prefix), config, unit_dir)
}

/// 解析安装路径；prefix 默认 `/`。
fn resolve_paths(
    prefix: Option<&Path>,
    config: Option<&Path>,
    unit_dir: Option<&Path>,
) -> Result<Paths> {
    Paths::for_role(
        Role::Panel,
        prefix.unwrap_or_else(|| Path::new("/")),
        PathOverrides {
            config: config.map(Path::to_path_buf),
            unit_dir: unit_dir.map(Path::to_path_buf),
            ..PathOverrides::default()
        },
    )
}

/// 是否需要获取全局安装锁。
///
/// - dry-run 只读，既不加锁也不创建 `/run` 锁文件；
/// - hub 调起的 panel 子进程已由父进程持锁（`RUSTBOARD_INSTALL_LOCK_HELD=1`），
///   再对同一把锁 flock 会自锁失败，必须跳过。
fn should_acquire_global_lock(dry_run: bool, inherited: bool) -> bool {
    !dry_run && !inherited
}

/// 按 [`should_acquire_global_lock`] 的决策获取全局锁。
///
/// 锁在读取 `install-state.toml` 之前获取，并由调用方持有到函数结束；Drop 时
/// 内核释放 flock。
fn acquire_install_lock(
    dry_run: bool,
    inherited: bool,
    action: &str,
) -> Result<Option<InstallLock>> {
    if !should_acquire_global_lock(dry_run, inherited) {
        return Ok(None);
    }
    let lock =
        InstallLock::acquire_global().with_context(|| format!("获取{action}全局安装锁失败"))?;
    Ok(Some(lock))
}

/// R-S5：同 prefix 的 hub 配置为 `admin_tls=required` 时拒绝面板安装。
///
/// Phase A 面板只通过明文 `http://` 对接 hub 管理 API；required hub 会监听 HTTPS，
/// 继续安装既无法通过健康检查，也会写出一个 http 对接 required hub 的错误配置。
/// 必须在写盘 / 启动之前拒绝，且不因显式 `--hub-url http://...` 而放行。
fn ensure_hub_admin_tls_supported(hub: Option<&HubConfig>) -> Result<()> {
    match hub {
        Some(hub) if hub.admin_tls == AdminTlsMode::Required => {
            bail!("{ADMIN_TLS_REQUIRED_UNSUPPORTED}")
        }
        _ => Ok(()),
    }
}

/// systemd 实际解析的 `FragmentPath` 与目标 unit 的关系。
#[derive(Debug, Clone, PartialEq, Eq)]
enum FragmentResolution {
    /// systemd 解析到的就是目标 unit 文件。
    Matches,
    /// systemd 解析到其他路径（同名更高优先级 / 外来 unit）。
    Foreign(PathBuf),
    /// 未解析（unit 未加载、transient，或 systemctl 报 not found）。
    Unresolved,
}

/// 纯函数：比较 `FragmentPath` 与目标 unit。
fn resolve_fragment(actual: Option<&Path>, expected: &Path) -> FragmentResolution {
    match actual {
        Some(path) if path == expected => FragmentResolution::Matches,
        Some(path) => FragmentResolution::Foreign(path.to_path_buf()),
        None => FragmentResolution::Unresolved,
    }
}

/// 纯函数：只有 systemd 明确解析到本安装的 unit，才允许 stop / disable。
///
/// 安装失败回滚与卸载在真正调用 `systemctl` 前都会用
/// [`ServiceManager::ensure_fragment_is`] 实时查询并校验；这里保留同一决策的
/// 纯函数形式，供单元测试锁定“fragment 缺失或外来时绝不 stop”的语义，
/// 避免依赖 fake systemctl 的行为测试。
fn should_stop_verified(fragment: Option<&Path>, expected: &Path) -> bool {
    matches!(fragment, Some(path) if path == expected)
}

/// 安装幂等分支前的 fragment 判定。
///
/// `Some` 其他路径必须报错；`None` 且同名服务 active 说明存在 transient / 外来
/// unit 占用了同一个名字，也不能把 `is-active` 当作自己的服务。
fn ensure_install_fragment(actual: Option<&Path>, expected: &Path, active: bool) -> Result<()> {
    match resolve_fragment(actual, expected) {
        FragmentResolution::Matches => Ok(()),
        FragmentResolution::Foreign(path) => bail!(
            "systemd 实际解析的 unit 是 {}，不是 {}；拒绝操作同名外来/更高优先级 unit",
            path.display(),
            expected.display()
        ),
        FragmentResolution::Unresolved if active => bail!(
            "systemd 未解析到 unit 文件 {}，但同名 {} 正在运行（transient / 外来 unit）；\
             无法确认归属，拒绝 enable/restart/stop，请先手动停止该服务",
            expected.display(),
            Role::Panel.unit_name()
        ),
        FragmentResolution::Unresolved => Ok(()),
    }
}

/// 在进入幂等 `finish_installed` 前查询 systemd 实际解析的 unit。
///
/// 仅由 systemd 管理且非 dry-run 时执行；`UnitOnly` / dry-run 不调用 systemctl。
fn ensure_install_fragment_before_idempotent(
    service: &ServiceManager,
    unit: &Path,
    dry_run: bool,
) -> Result<()> {
    if dry_run || !service.manage {
        return Ok(());
    }
    let unit_name = Role::Panel.unit_name();
    let actual = service.fragment_path(unit_name)?;
    // 只有未解析时才查 active：fragment 已经指向别的 unit 时无需再发一次 systemctl。
    let active = match actual {
        None => service.is_active(unit_name)?,
        Some(_) => false,
    };
    ensure_install_fragment(actual.as_deref(), unit, active)
}

/// 卸载时对同名 unit 的处理方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UninstallServiceAction {
    /// fragment 已确认是记录中的 unit：允许 stop / disable。
    StopAndDisable,
    /// unit 在 prefix 内、systemd 未解析，或 unit 文件不存在：只删自己的文件。
    RemoveFileOnly,
}

/// 纯函数：根据卸载 preflight 查到的 fragment 决定是否调用 systemctl。
fn decide_uninstall_service(
    actual: Option<&Path>,
    expected: &Path,
) -> Result<UninstallServiceAction> {
    if should_stop_verified(actual, expected) {
        return Ok(UninstallServiceAction::StopAndDisable);
    }
    match actual {
        Some(path) => bail!(
            "systemd 实际解析的 unit 是 {}，不是记录中的 {}；\
             拒绝 stop/disable/删除同名外来/更高优先级 unit，请先手动处理",
            path.display(),
            expected.display()
        ),
        None => Ok(UninstallServiceAction::RemoveFileOnly),
    }
}

/// unit 文件所在目录。
fn unit_directory(unit: &Path) -> Result<PathBuf> {
    unit.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("unit 路径缺少父目录，无法确定 unit_dir: {}", unit.display()))
}

/// systemd 管理要求 unit 位于 systemd 会读取的系统 unit 目录。
///
/// 根 prefix 的默认管理方式与显式 `--systemd` 都走这里。prefix 内的 unit 文件
/// 不会被 systemd 解析；继续 enable / restart / stop 只会操作宿主的同名 unit
/// （或失败），故必须在任何写盘 / systemctl 之前拒绝。
fn ensure_systemd_unit_dir(paths: &Paths, reason: &str) -> Result<()> {
    let unit_dir = unit_directory(&paths.unit)?;
    if is_systemd_unit_dir(&unit_dir) {
        return Ok(());
    }
    bail!(
        "{reason}要求 unit 目录是 systemd 会读取的系统目录（/etc/systemd/system、/run/systemd/system 等），\
         当前为 {}；prefix 内的 unit 不会被 systemd 读取，拒绝 enable/restart/stop。\
         请改用 --unit-dir 指向系统 unit 目录，或用 --no-systemd 跳过 systemd",
        unit_dir.display()
    );
}

/// 解析 systemd 管理方式。
fn resolve_service_mode(
    force_systemd: bool,
    no_systemd: bool,
    paths: &Paths,
) -> Result<ServiceMode> {
    if no_systemd {
        return Ok(ServiceMode::None);
    }
    if force_systemd {
        // 先做目录判定，再做 systemd 可用性检测：即使宿主机没有 systemd，也优先
        // 报出“unit 目录不会被读取”这个根因。
        ensure_systemd_unit_dir(paths, "--systemd ")?;
        require_systemd().context("--systemd 要求 systemd 可用")?;
        return Ok(ServiceMode::Manage);
    }
    if !detect_system().systemd {
        if paths.is_root_prefix() {
            eprintln!(
                "警告: 未检测到 systemd，根 prefix 安装只写 unit 而不启动服务；\
                 可用 --systemd 强制要求或 --no-systemd 跳过 unit"
            );
        }
        return Ok(ServiceMode::UnitOnly);
    }
    if paths.is_root_prefix() {
        // 根 prefix 默认由 systemd 管理；自定义 --unit-dir 若不在系统 unit 目录，
        // systemd 根本解析不到该文件，必须在写盘前拒绝，而不是写完再回滚。
        ensure_systemd_unit_dir(paths, "root prefix 的 systemd 管理")?;
        Ok(ServiceMode::Manage)
    } else {
        // 临时 prefix 不接管宿主 systemd，避免测试/容器安装影响真实服务。
        Ok(ServiceMode::UnitOnly)
    }
}

/// 生成默认监听地址：回环 + 五位数随机空闲端口。
fn default_listen() -> Result<String> {
    let port = pick_free_port(&[]).context("选择面板监听端口失败")?;
    Ok(format!("127.0.0.1:{port}"))
}

/// 解析安装监听地址：显式 `--listen` 优先；`--force` 且未指定时沿用旧配置，
/// 避免重装把面板换到另一个随机端口。
fn resolve_listen(explicit: Option<&str>, existing: Option<&PanelConfig>) -> Result<String> {
    if let Some(raw) = explicit {
        return normalize_listen(raw);
    }
    if let Some(existing) = existing {
        if let Ok(listen) = normalize_listen(&existing.listen) {
            return Ok(listen);
        }
    }
    default_listen()
}

/// 校验并规范化 `--listen`（`host:port`，端口 1–65535）。
fn normalize_listen(raw: &str) -> Result<String> {
    let listen = raw.trim();
    if listen.is_empty() {
        bail!("--listen 不能为空");
    }
    if listen
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        bail!("--listen 不能包含空白或控制字符: {listen:?}");
    }
    let Some((host, port)) = listen.rsplit_once(':') else {
        bail!("--listen 缺少端口，应为 host:port: {listen}");
    };
    if host.is_empty() {
        bail!("--listen 缺少主机名: {listen}");
    }
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow!("--listen 端口非法（应为 1–65535）: {listen}"))?;
    if port == 0 {
        bail!("--listen 端口不能为 0: {listen}");
    }
    Ok(format!("{host}:{port}"))
}

/// 读取 hub token 或密码文件：0600 普通文件、≤4 KiB、trim 后非空。
fn read_secret_file(path: &Path, label: &str) -> Result<String> {
    let bytes = read_private_file(path, SECRET_FILE_MAX_BYTES)
        .with_context(|| format!("读取 {label} 文件失败: {}", path.display()))?;
    let text = String::from_utf8(bytes)
        .map_err(|_| anyhow!("{label} 文件不是有效 UTF-8: {}", path.display()))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        bail!("{label} 文件内容为空: {}", path.display());
    }
    Ok(trimmed.to_string())
}

/// 若 hub 配置存在则解析；错误信息不包含解析细节（可能回显 admin_token 所在行）。
///
/// `read_only` 为真时（dry-run）使用不 chmod 的只读解析：`HubConfig::load` 会
/// 通过 `load_toml` 的 harden 收紧文件权限，dry-run 必须零写入。
fn load_hub_config_if_exists(path: &Path, read_only: bool) -> Result<Option<HubConfig>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            if read_only {
                return read_toml_readonly(path, "hub 配置").map(Some);
            }
            HubConfig::load(path).map(Some).map_err(|_| {
                anyhow!(
                    "读取 hub 配置 {} 失败；为避免泄露 admin_token，未显示解析细节",
                    path.display()
                )
            })
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("读取 hub 配置 {} 元数据失败", path.display()))
        }
    }
}

/// 只读加载 TOML，不调用 `load_toml` 的 harden，保证 `--dry-run` 零写入。
///
/// 错误信息只带路径，不挂接 `toml` 解析错误：后者会回显出错行（可能是
/// `admin_token = "..."` 或密码哈希），不能进终端 / 日志。
fn read_toml_readonly<T: serde::de::DeserializeOwned>(path: &Path, label: &str) -> Result<T> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("读取 {label} {} 失败", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("{label} {} 是符号链接，拒绝读取", path.display());
    }
    if !meta.is_file() {
        bail!("{label} {} 不是普通文件，拒绝读取", path.display());
    }
    let text = fs::read_to_string(path)
        .with_context(|| format!("读取 {label} {} 失败", path.display()))?;
    toml::from_str(&text).map_err(|_| {
        anyhow!(
            "解析 {label} {} 失败；为避免泄露 token / 密码等内容，未显示解析细节",
            path.display()
        )
    })
}

/// 解析 hub 管理 API 地址。
fn resolve_hub_url(
    explicit: Option<&str>,
    hub: Option<&HubConfig>,
    hub_path: &Path,
) -> Result<String> {
    if let Some(raw) = explicit {
        return crate::normalize_hub_url(raw).context("--hub-url 非法");
    }
    if let Some(hub) = hub {
        if let Some(port) = port_of(&hub.admin_listen) {
            return Ok(format!("http://127.0.0.1:{port}"));
        }
        eprintln!(
            "警告: {} 的 admin_listen 无法解析端口，hub 地址回退到 http://127.0.0.1:{}",
            hub_path.display(),
            DEFAULT_ADMIN_PORT
        );
    } else {
        eprintln!(
            "警告: 未找到 {}，hub 地址回退到 http://127.0.0.1:{}；\
             请安装 hub 或使用 --hub-url 指定实际地址",
            hub_path.display(),
            DEFAULT_ADMIN_PORT
        );
    }
    Ok(format!("http://127.0.0.1:{DEFAULT_ADMIN_PORT}"))
}

/// 解析静态资源目录。
///
/// 显式指定时用 `web::StaticFiles::discover` 校验（无效必须失败）；`--force`
/// 且未指定时，旧配置里的目录仍有效则沿用（保持配置稳定）。全新安装依次尝试
/// 当前目录的 `web/dist` 与 `/usr/share/rustboard/web`，命中后写绝对路径。
fn resolve_static_dir(
    explicit: Option<&Path>,
    existing: Option<&PanelConfig>,
) -> Result<Option<PathBuf>> {
    if let Some(raw) = explicit {
        let text = raw
            .to_str()
            .ok_or_else(|| anyhow!("--static-dir 不是有效 UTF-8 路径: {}", raw.display()))?;
        let text = text.trim();
        if text.is_empty() {
            bail!("--static-dir 不能为空");
        }
        let discovered = crate::web::StaticFiles::discover(text)
            .with_context(|| format!("--static-dir 校验失败: {text}"))?;
        if discovered.is_none() {
            bail!("--static-dir 不可用（目录不存在或缺少 index.html）: {text}");
        }
        return fs::canonicalize(text)
            .map(Some)
            .with_context(|| format!("--static-dir 无法解析为绝对路径: {text}"));
    }

    if let Some(existing) = existing {
        let configured = existing.static_dir.trim();
        if !configured.is_empty() && crate::web::StaticFiles::from_root(configured).is_some() {
            return fs::canonicalize(configured)
                .map(Some)
                .with_context(|| format!("旧配置中的静态资源目录 {configured} 无法解析"));
        }
    }

    for candidate in [
        PathBuf::from("web/dist"),
        PathBuf::from("/usr/share/rustboard/web"),
    ] {
        if crate::web::StaticFiles::from_root(&candidate).is_none() {
            continue;
        }
        let canonical = fs::canonicalize(&candidate)
            .with_context(|| format!("静态资源目录 {} 无法解析", candidate.display()))?;
        return Ok(Some(canonical));
    }
    Ok(None)
}

/// 未找到静态资源时只警告，不阻塞安装（面板仍可启动，页面请求 503）。
fn warn_missing_static_dir() {
    eprintln!(
        "警告: 未找到面板静态资源（依次检查 ./web/dist 与 /usr/share/rustboard/web）；\
         安装继续，但页面请求将返回 503。可用 --static-dir 指定构建产物"
    );
}

/// 读取已有面板配置；损坏时按“没有旧配置”处理（--force 语义是重新生成）。
///
/// `read_only` 为真时（dry-run）用不 chmod 的只读解析，保证 dry-run 零写入；
/// 正常安装仍允许 `PanelConfig::load` 收紧旧配置权限。
fn load_existing_config(path: &Path, read_only: bool) -> Option<PanelConfig> {
    if !path_exists(path) {
        return None;
    }
    let loaded = if read_only {
        read_toml_readonly::<PanelConfig>(path, "面板配置")
    } else {
        PanelConfig::load(path).map_err(anyhow::Error::from)
    };
    match loaded {
        Ok(cfg) => Some(cfg),
        Err(_) => {
            eprintln!(
                "警告: 已有面板配置 {} 无法解析，将按本次参数重新生成{}",
                path.display(),
                if read_only {
                    "（--dry-run 不写文件）"
                } else {
                    "（旧文件会备份）"
                }
            );
            None
        }
    }
}

/// 决定密码来源。
fn plan_password(file: Option<&Path>, existing: Option<&PanelConfig>) -> Result<PasswordPlan> {
    if let Some(path) = file {
        let password = read_secret_file(path, "密码")?;
        if password.len() < crate::MIN_PASSWORD_LEN {
            eprintln!(
                "警告: 密码短于 {} 个字符，建议使用更长的密码或自动生成的随机密码",
                crate::MIN_PASSWORD_LEN
            );
        }
        return Ok(PasswordPlan::FromFile(password));
    }
    if let Some(existing) = existing {
        let hash = existing.admin_password_hash.trim();
        if crate::auth::validate_phc(hash) {
            return Ok(PasswordPlan::Preserve(hash.to_string()));
        }
        if !hash.is_empty() {
            eprintln!("警告: 已有面板配置中的 admin_password_hash 无效，将生成新的初始密码");
        }
    }
    Ok(PasswordPlan::Generated)
}

/// 把面板配置序列化为 TOML。
///
/// 这里手写序列化而不是调用 `PanelConfig::save`：安装必须通过 [`InstallTxn`]
/// 原子写入配置（0600）才能回滚，而 panel 二进制没有直接依赖 `toml`。字段逐项
/// 解构，`PanelConfig` 新增字段时编译器会强制同步。
fn render_panel_config(cfg: &PanelConfig) -> String {
    let PanelConfig {
        listen,
        hub_url,
        hub_ca,
        token,
        admin_password_hash,
        session_ttl_hours,
        static_dir,
        trusted_proxies,
        cookie_secure,
        public_origin,
    } = cfg;

    let mut out = String::new();
    push_toml_string(&mut out, "listen", listen);
    push_toml_string(&mut out, "hub_url", hub_url);
    push_toml_string(&mut out, "hub_ca", hub_ca);
    push_toml_string(&mut out, "token", token);
    push_toml_string(&mut out, "admin_password_hash", admin_password_hash);
    out.push_str(&format!("session_ttl_hours = {session_ttl_hours}\n"));
    push_toml_string(&mut out, "static_dir", static_dir);
    out.push_str("trusted_proxies = [");
    for (index, proxy) in trusted_proxies.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&toml_string(proxy));
    }
    out.push_str("]\n");
    push_toml_string(
        &mut out,
        "cookie_secure",
        cookie_secure_name(*cookie_secure),
    );
    push_toml_string(&mut out, "public_origin", public_origin);
    out
}

/// 追加 `key = "value"` 一行。
fn push_toml_string(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(&toml_string(value));
    out.push('\n');
}

/// TOML basic string 转义。
fn toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04X}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// `cookie_secure` 的 serde 小写名称。
fn cookie_secure_name(value: CookieSecure) -> &'static str {
    match value {
        CookieSecure::Auto => "auto",
        CookieSecure::Always => "always",
        CookieSecure::Never => "never",
    }
}

/// 复制当前可执行文件到安装位置；源与目标 canonical path 相同时跳过。
fn install_binary(txn: &mut InstallTxn, dest: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(dest) {
        if meta.file_type().is_symlink() {
            bail!("目标二进制 {} 是符号链接，拒绝通过安装覆盖", dest.display());
        }
    }
    let source = std::env::current_exe().context("读取当前面板可执行文件路径失败")?;
    let source = fs::canonicalize(&source)
        .with_context(|| format!("解析当前可执行文件 {} 失败", source.display()))?;
    let destination = match fs::canonicalize(dest) {
        Ok(path) => Some(path),
        Err(error) if error.kind() == ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("解析目标二进制 {} 失败", dest.display()));
        }
    };
    if destination.as_deref() == Some(source.as_path()) {
        println!(
            "  二进制已在安装位置（当前可执行文件即 {}），跳过复制",
            dest.display()
        );
        return Ok(());
    }
    txn.copy_file(&source, dest, 0o755)
        .with_context(|| format!("安装面板二进制到 {} 失败", dest.display()))
}

/// 读取安装状态；拒绝符号链接，避免以 root 读取任意文件。
fn load_install_state(path: &Path) -> Result<InstallState> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            bail!("安装状态 {} 是符号链接，拒绝使用", path.display());
        }
    }
    InstallState::load(path)
}

/// 保存当前 state 文件内容，供安装失败时恢复。
fn state_snapshot(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("读取安装状态 {} 失败", path.display())),
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("安装状态 {} 是符号链接，拒绝使用", path.display())
        }
        Ok(_) => fs::read(path)
            .map(Some)
            .with_context(|| format!("读取安装状态 {} 失败", path.display())),
    }
}

/// 安装失败时恢复旧 state（文件原先不存在则删除本次写入）。
fn restore_state(path: &Path, previous: Option<&[u8]>) -> Result<()> {
    match previous {
        Some(bytes) => fsutil::atomic_write(path, bytes, 0o600)
            .with_context(|| format!("恢复安装状态 {} 失败", path.display())),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(error) => {
                Err(error).with_context(|| format!("删除本次安装状态 {} 失败", path.display()))
            }
        },
    }
}

/// 已安装且服务 active：打印摘要并返回 0，不做任何写入。
fn finish_installed(
    record: &RoleState,
    paths: &Paths,
    mode: ServiceMode,
    service: &ServiceManager,
    check_service: bool,
) -> Result<()> {
    ensure_record_matches(record, paths)?;
    ensure_installed_files(paths, mode)?;
    // 幂等分支同样不能把“同名外来 unit 正在运行”误判成已安装：只要目标 unit
    // 存在，就先确认归属；不属于本安装器时直接报错，绝不 stop / 覆盖 / 删除。
    ensure_existing_unit_is_ours(paths, &paths.unit)?;
    if check_service && mode.manages() && !service.is_active(Role::Panel.unit_name())? {
        bail!(
            "安装记录存在且文件齐全，但 {} 未运行；请执行 `systemctl start {}`，\
             或使用 --force 重新安装并重启",
            Role::Panel.unit_name(),
            Role::Panel.unit_name()
        );
    }

    println!("面板已安装（版本 {}），未做任何修改。", record.version);
    println!("  配置: {}", paths.config.display());
    if mode.writes_unit() {
        println!("  unit: {}", paths.unit.display());
    } else {
        println!("  unit: 未写入（--no-systemd）");
    }
    println!("  二进制: {}", paths.binary.display());
    println!(
        "使用 --force 可重新生成配置/unit 并重启服务；卸载请运行 `rustboard-panel uninstall --prefix {}`。",
        shell_arg(&paths.prefix.to_string_lossy())
    );
    Ok(())
}

/// 安装记录与本次参数不一致时明确报错，避免悄悄写出第二套路径。
fn ensure_record_matches(record: &RoleState, paths: &Paths) -> Result<()> {
    if record.config != paths.config
        || record.data_dir != paths.data_dir
        || record.unit != paths.unit
        || record.binary != paths.binary
    {
        bail!(
            "安装记录与本次参数不一致：记录 config={} data={} unit={} binary={}；\
             请使用与安装时相同的 --prefix/--config/--unit-dir，或先 uninstall",
            record.config.display(),
            record.data_dir.display(),
            record.unit.display(),
            record.binary.display()
        );
    }
    Ok(())
}

/// `--force` 且路径变化时提示旧文件不会自动删除。
fn warn_if_paths_changed(record: &RoleState, paths: &Paths) {
    if record.config != paths.config
        || record.data_dir != paths.data_dir
        || record.unit != paths.unit
        || record.binary != paths.binary
    {
        eprintln!(
            "警告: 安装记录中的路径与本次参数不同；--force 会按本次路径重新安装，\
             但不会自动删除旧路径（config={} unit={} binary={}）",
            record.config.display(),
            record.unit.display(),
            record.binary.display()
        );
    }
}

/// 幂等安装条件：配置、二进制（以及要求时 unit）必须都在。
fn ensure_installed_files(paths: &Paths, mode: ServiceMode) -> Result<()> {
    let mut missing = Vec::new();
    if !path_exists(&paths.config) {
        missing.push(paths.config.display().to_string());
    }
    if !path_exists(&paths.binary) {
        missing.push(paths.binary.display().to_string());
    }
    if mode.writes_unit() && !path_exists(&paths.unit) {
        missing.push(paths.unit.display().to_string());
    }
    if !missing.is_empty() {
        bail!(
            "安装记录存在但以下文件缺失: {}；请使用 --force 重新安装（或先 uninstall）",
            missing.join(", ")
        );
    }
    Ok(())
}

/// 文件/目录是否存在（含符号链接本身）。
fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// 检查待删除的目标是普通文件（或不存在），符号链接/目录一律拒绝。
fn check_removable_file(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("读取 {label} {} 元数据失败", path.display()))
        }
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!("{label} {} 是符号链接，拒绝卸载删除", path.display())
        }
        Ok(meta) if meta.is_dir() => {
            bail!("{label} {} 是目录，拒绝卸载删除", path.display())
        }
        Ok(_) => Ok(()),
    }
}

/// 删除普通文件；不存在返回 `false`，符号链接/目录拒绝。
fn remove_regular_file(path: &Path, label: &str) -> Result<bool> {
    check_removable_file(path, label)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("删除 {label} {} 失败", path.display())),
    }
}

/// `--purge` 的目标（已解析为 canonical path）。
#[derive(Debug)]
struct PurgeTargets {
    config: Option<PathBuf>,
    data: Option<PathBuf>,
}

/// 只读校验 `--purge` 目标：受管路径 allowlist、符号链接拒绝、类型正确、
/// 路径在 prefix 内或生产默认，且绝不删除 install-state 本身。
fn prepare_purge_targets(
    paths: &Paths,
    config_path: &Path,
    data_path: &Path,
) -> Result<PurgeTargets> {
    // M1/L5：config / data 也必须是 allowlist 内的受管路径，不能靠 state 记录
    // 把任意路径带进删除流程。
    validate_managed_path(
        Role::Panel,
        &paths.prefix,
        config_path,
        ManagedPathKind::Config,
    )
    .with_context(|| format!("拒绝对配置路径 {} 执行 --purge", config_path.display()))?;
    validate_managed_path(Role::Panel, &paths.prefix, data_path, ManagedPathKind::Data)
        .with_context(|| format!("拒绝对数据路径 {} 执行 --purge", data_path.display()))?;

    let config = purge_target(config_path, paths, PRODUCTION_CONFIG, "面板配置", false)?;
    let data = purge_target(data_path, paths, PRODUCTION_DATA, "面板数据目录", true)?;
    if let Some(data) = &data {
        if paths.state.starts_with(data) {
            bail!(
                "拒绝 --purge 删除包含安装状态文件的数据目录: {}",
                data.display()
            );
        }
    }
    if let Some(config) = &config {
        let state = fs::canonicalize(&paths.state).unwrap_or_else(|_| paths.state.clone());
        if config == &state || config == &paths.state {
            bail!("拒绝 --purge 删除安装状态文件本身: {}", config.display());
        }
    }
    Ok(PurgeTargets { config, data })
}

/// 校验单个 purge 目标并返回 canonical path；不存在返回 `None`。
fn purge_target(
    path: &Path,
    paths: &Paths,
    production_default: &str,
    label: &str,
    want_dir: bool,
) -> Result<Option<PathBuf>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("读取 {label} {} 元数据失败", path.display()));
        }
    };
    if meta.file_type().is_symlink() {
        bail!("{label} {} 是符号链接，拒绝 --purge 删除", path.display());
    }
    if want_dir && !meta.is_dir() {
        bail!("{label} {} 不是目录，拒绝 --purge 删除", path.display());
    }
    if !want_dir && !meta.is_file() {
        bail!("{label} {} 不是普通文件，拒绝 --purge 删除", path.display());
    }
    let canonical =
        fs::canonicalize(path).with_context(|| format!("解析 {label} {} 失败", path.display()))?;
    validate_purge_containment(&canonical, paths, Path::new(production_default), label)?;
    Ok(Some(canonical))
}

/// purge 路径限制：非 root prefix 必须在 prefix 内；root prefix 只允许生产默认路径。
fn validate_purge_containment(
    canonical: &Path,
    paths: &Paths,
    production_default: &Path,
    label: &str,
) -> Result<()> {
    let default =
        fs::canonicalize(production_default).unwrap_or_else(|_| production_default.to_path_buf());
    // 生产默认路径在任何 prefix 下都允许（显式覆盖到默认路径的场景）。
    if canonical == default {
        return Ok(());
    }
    if paths.is_root_prefix() {
        bail!(
            "拒绝 --purge 删除 {label} 的非生产默认路径: {}（只允许 {}）",
            canonical.display(),
            production_default.display()
        );
    }
    let prefix = fs::canonicalize(&paths.prefix)
        .with_context(|| format!("解析安装前缀 {} 失败，拒绝 --purge", paths.prefix.display()))?;
    if canonical == prefix || !canonical.starts_with(&prefix) {
        bail!(
            "拒绝 --purge 删除 {label} 的 prefix 外路径: {}（prefix: {}）",
            canonical.display(),
            prefix.display()
        );
    }
    Ok(())
}

/// 打印 dry-run 安装计划；不输出 token / 密码。
fn print_install_plan(
    paths: &Paths,
    mode: ServiceMode,
    listen: &str,
    hub_url: &str,
    static_dir: Option<&Path>,
    password: &PasswordPlan,
    offline: bool,
) {
    println!("面板安装计划（--dry-run：不写文件、不调用 systemctl）:");
    println!("  配置: {}", paths.config.display());
    println!("  数据目录: {}", paths.data_dir.display());
    if mode.writes_unit() {
        println!("  unit: {}", paths.unit.display());
    } else {
        println!("  unit: 不写入（--no-systemd）");
    }
    println!("  二进制: {}", paths.binary.display());
    println!("  监听: {listen}");
    println!("  hub API: {hub_url}");
    println!("  静态目录: {}", static_dir_label(static_dir));
    println!("  密码: {}", password_plan_label(password));
    println!("  hub token: 从受保护的 0600 来源读取（不显示）");
    if offline {
        println!("  离线: 是（面板安装不发起网络请求）");
    }
}

/// 打印安装成功摘要。
fn print_install_summary(
    paths: &Paths,
    mode: ServiceMode,
    cfg: &PanelConfig,
    password_note: &str,
    offline: bool,
) {
    println!("面板安装完成。");
    println!("  配置: {}（0600）", paths.config.display());
    println!("  数据目录: {}（0700）", paths.data_dir.display());
    if mode.writes_unit() {
        println!("  unit: {}（0644）", paths.unit.display());
    } else {
        println!("  unit: 未写入（--no-systemd）");
    }
    println!("  二进制: {}（0755）", paths.binary.display());
    println!("  监听: {}", cfg.listen);
    println!("  hub API: {}", cfg.hub_url);
    println!(
        "  静态目录: {}",
        static_dir_label(if cfg.static_dir.trim().is_empty() {
            None
        } else {
            Some(Path::new(&cfg.static_dir))
        })
    );
    println!("  密码: {password_note}");
    println!("  hub token: 已写入配置（不显示）");
    if offline {
        println!("  离线: 是（面板安装不发起网络请求）");
    }
}

/// 打印 dry-run 卸载计划。
fn print_uninstall_plan(
    paths: &Paths,
    unit_path: &Path,
    binary_path: &Path,
    config_path: &Path,
    data_path: &Path,
    purge: bool,
) {
    println!("面板卸载计划（--dry-run：不停止服务、不删除文件）:");
    println!(
        "  unit: {}（{}）",
        unit_path.display(),
        existence_label(unit_path)
    );
    println!(
        "  二进制: {}（{}）",
        binary_path.display(),
        existence_label(binary_path)
    );
    if purge {
        println!("  配置: {}（--purge 将删除）", config_path.display());
        println!("  数据目录: {}（--purge 将删除）", data_path.display());
    } else {
        println!("  配置: {}（保留）", config_path.display());
        println!(
            "  数据目录: {}（保留；--purge 可删除）",
            data_path.display()
        );
    }
    println!("  安装状态: {}", paths.state.display());
}

/// 打印卸载摘要。
#[allow(clippy::too_many_arguments)]
fn print_uninstall_summary(
    paths: &Paths,
    unit_path: &Path,
    binary_path: &Path,
    config_path: &Path,
    data_path: &Path,
    unit_removed: bool,
    binary_removed: bool,
    removed_record: bool,
    purge: bool,
    purged_config: bool,
    purged_data: bool,
) {
    println!("面板已卸载。");
    if unit_removed {
        println!("  已停止并删除 unit: {}", unit_path.display());
    } else {
        println!("  unit: {}（不存在，跳过）", unit_path.display());
    }
    if binary_removed {
        println!("  已删除二进制: {}", binary_path.display());
    } else {
        println!("  二进制: {}（不存在，跳过）", binary_path.display());
    }
    if removed_record {
        println!("  已从安装状态删除 panel 记录: {}", paths.state.display());
    } else {
        println!("  安装状态: 无 panel 记录");
    }
    if purge {
        if purged_config {
            println!("  已删除配置: {}", config_path.display());
        } else {
            println!("  配置: {}（不存在）", config_path.display());
        }
        if purged_data {
            println!("  已删除数据目录: {}", data_path.display());
        } else {
            println!("  数据目录: {}（不存在）", data_path.display());
        }
    } else {
        println!("  已保留配置: {}（--purge 可删除）", config_path.display());
        println!(
            "  已保留数据目录: {}（--purge 可删除）",
            data_path.display()
        );
    }
}

/// 静态目录展示文案。
fn static_dir_label(static_dir: Option<&Path>) -> String {
    match static_dir {
        Some(path) => path.display().to_string(),
        None => "未找到（安装继续，在找到前页面请求返回 503）".to_string(),
    }
}

/// 密码计划展示文案（不含密码本身）。
fn password_plan_label(password: &PasswordPlan) -> &'static str {
    match password {
        PasswordPlan::FromFile(_) => "从 --password-file 读取（不显示）",
        PasswordPlan::Generated => "自动生成（安装成功后仅显示一次）",
        PasswordPlan::Preserve(_) => "沿用已有配置中的密码哈希（不打印）",
    }
}

/// 路径存在性文案。
fn existence_label(path: &Path) -> &'static str {
    if path_exists(path) {
        "存在"
    } else {
        "不存在"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    /// 测试用临时目录；Drop 时递归删除。
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            Self::new_in(&std::env::temp_dir(), tag)
        }

        /// 在指定父目录下创建临时目录。
        ///
        /// `validate_install_prefix` 拒绝 sticky 位，`/tmp` 不适合作为完整安装
        /// 流程测试的前缀；需要真实 prefix 的测试放在测试二进制所在的 target
        /// 目录下（属主与权限都满足要求）。
        fn new_in(base: &Path, tag: &str) -> Self {
            let unique = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                "rb-panel-install-{tag}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    /// 用于完整安装流程测试的 prefix 父目录：测试二进制所在目录（`target/...`）。
    fn install_prefix_base() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(Path::to_path_buf))
            .unwrap_or_else(std::env::temp_dir)
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[cfg(unix)]
    fn write_with_mode(path: &Path, contents: &[u8], mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn hub_token_file_missing_is_rejected() {
        let dir = TempDir::new("token-missing");
        let error = read_secret_file(&dir.join("missing-token"), "hub token").unwrap_err();
        assert!(format!("{error:#}").contains("hub token"), "{error:#}");
    }

    #[test]
    fn hub_token_file_permissions_are_rejected() {
        let dir = TempDir::new("token-mode");
        let path = dir.join("token");
        write_with_mode(&path, b"deadbeef\n", 0o644);
        let error = read_secret_file(&path, "hub token").unwrap_err();
        assert!(format!("{error:#}").contains("0600"), "{error:#}");
    }

    #[test]
    fn hub_token_file_is_trimmed() {
        let dir = TempDir::new("token-trim");
        let path = dir.join("token");
        write_with_mode(&path, b"  deadbeef  \n", 0o600);
        assert_eq!(read_secret_file(&path, "hub token").unwrap(), "deadbeef");
    }

    #[test]
    fn password_file_missing_is_rejected() {
        let dir = TempDir::new("password-missing");
        let error = read_secret_file(&dir.join("missing-password"), "密码").unwrap_err();
        assert!(format!("{error:#}").contains("密码"), "{error:#}");
    }

    #[test]
    fn password_file_permissions_are_rejected() {
        let dir = TempDir::new("password-mode");
        let path = dir.join("password");
        write_with_mode(&path, b"correct horse battery staple", 0o640);
        let error = read_secret_file(&path, "密码").unwrap_err();
        assert!(format!("{error:#}").contains("0600"), "{error:#}");
    }

    #[test]
    fn empty_password_file_is_rejected() {
        let dir = TempDir::new("password-empty");
        let path = dir.join("password");
        write_with_mode(&path, b"  \n\t", 0o600);
        let error = read_secret_file(&path, "密码").unwrap_err();
        assert!(format!("{error:#}").contains("内容为空"), "{error:#}");
    }

    #[test]
    fn explicit_static_dir_without_index_is_rejected() {
        let dir = TempDir::new("static-invalid");
        let static_dir = dir.join("web");
        fs::create_dir(&static_dir).unwrap();
        let error = resolve_static_dir(Some(static_dir.as_path()), None).unwrap_err();
        assert!(format!("{error:#}").contains("--static-dir"), "{error:#}");
    }

    #[test]
    fn explicit_static_dir_is_canonicalized() {
        let dir = TempDir::new("static-valid");
        let static_dir = dir.join("web");
        fs::create_dir(&static_dir).unwrap();
        fs::write(static_dir.join("index.html"), b"<div id=\"root\"></div>").unwrap();
        let resolved = resolve_static_dir(Some(static_dir.as_path()), None)
            .unwrap()
            .expect("显式目录应被接受");
        assert!(resolved.is_absolute(), "{}", resolved.display());
        assert_eq!(resolved, fs::canonicalize(&static_dir).unwrap());
    }

    #[test]
    fn empty_explicit_static_dir_is_rejected() {
        assert!(resolve_static_dir(Some(Path::new("")), None).is_err());
    }

    #[test]
    fn listen_parsing_accepts_host_port() {
        assert_eq!(
            normalize_listen("127.0.0.1:23456").unwrap(),
            "127.0.0.1:23456"
        );
        assert_eq!(normalize_listen(" 0.0.0.0:8444 ").unwrap(), "0.0.0.0:8444");
        assert_eq!(normalize_listen("[::1]:9000").unwrap(), "[::1]:9000");
    }

    #[test]
    fn listen_parsing_rejects_invalid_values() {
        for raw in [
            "",
            "   ",
            "127.0.0.1",
            "127.0.0.1:",
            ":8444",
            "127.0.0.1:0",
            "127.0.0.1:70000",
            "127.0.0.1:not-a-port",
            "127.0.0.1:80 80",
        ] {
            assert!(normalize_listen(raw).is_err(), "{raw:?} 应被拒绝");
        }
    }

    #[test]
    fn default_listen_is_loopback_five_digit() {
        let listen = default_listen().unwrap();
        let (host, port) = listen.rsplit_once(':').unwrap();
        assert_eq!(host, "127.0.0.1");
        let port: u16 = port.parse().unwrap();
        assert!((20_000..=64_999).contains(&port), "{port}");
    }

    #[test]
    fn force_reuses_existing_listen_when_not_specified() {
        let existing = PanelConfig {
            listen: "127.0.0.1:23456".to_string(),
            ..PanelConfig::default()
        };
        assert_eq!(
            resolve_listen(None, Some(&existing)).unwrap(),
            "127.0.0.1:23456"
        );
        // 显式参数优先，非法旧值则回退随机端口。
        assert_eq!(
            resolve_listen(Some("127.0.0.1:30000"), Some(&existing)).unwrap(),
            "127.0.0.1:30000"
        );
        let broken = PanelConfig {
            listen: "not-a-listen".to_string(),
            ..PanelConfig::default()
        };
        let listen = resolve_listen(None, Some(&broken)).unwrap();
        assert!(listen.starts_with("127.0.0.1:"), "{listen}");
    }

    #[test]
    fn force_reuses_valid_existing_static_dir() {
        let dir = TempDir::new("static-reuse");
        let static_dir = dir.join("web");
        fs::create_dir(&static_dir).unwrap();
        fs::write(static_dir.join("index.html"), b"<div id=\"root\"></div>").unwrap();
        let existing = PanelConfig {
            static_dir: static_dir.to_string_lossy().into_owned(),
            ..PanelConfig::default()
        };
        let resolved = resolve_static_dir(None, Some(&existing))
            .unwrap()
            .expect("旧配置中的有效目录应沿用");
        assert_eq!(resolved, fs::canonicalize(&static_dir).unwrap());
    }

    #[test]
    fn rendered_config_roundtrips_through_panel_loader() {
        let dir = TempDir::new("config-roundtrip");
        let path = dir.join("panel.toml");
        let cfg = PanelConfig {
            listen: "127.0.0.1:23456".to_string(),
            hub_url: "http://127.0.0.1:8444".to_string(),
            hub_ca: "/etc/rustboard/ca \"quoted\".pem".to_string(),
            token: "deadbeefdeadbeef".to_string(),
            admin_password_hash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hashvalue".to_string(),
            session_ttl_hours: 7,
            static_dir: "/srv/web \\ dist".to_string(),
            trusted_proxies: vec!["10.0.0.0/8".to_string(), "127.0.0.1".to_string()],
            cookie_secure: CookieSecure::Always,
            public_origin: "https://panel.example.com".to_string(),
        };
        fs::write(&path, render_panel_config(&cfg)).unwrap();
        let loaded = PanelConfig::load(&path).expect("渲染结果必须是合法 PanelConfig");
        assert_eq!(loaded.listen, cfg.listen);
        assert_eq!(loaded.hub_url, cfg.hub_url);
        assert_eq!(loaded.hub_ca, cfg.hub_ca);
        assert_eq!(loaded.token, cfg.token);
        assert_eq!(loaded.admin_password_hash, cfg.admin_password_hash);
        assert_eq!(loaded.session_ttl_hours, cfg.session_ttl_hours);
        assert_eq!(loaded.static_dir, cfg.static_dir);
        assert_eq!(loaded.trusted_proxies, cfg.trusted_proxies);
        assert_eq!(loaded.cookie_secure, cfg.cookie_secure);
        assert_eq!(loaded.public_origin, cfg.public_origin);
    }

    #[test]
    fn purge_containment_rejects_outside_prefix() {
        let prefix = TempDir::new("purge-prefix");
        let outside = TempDir::new("purge-outside");
        let paths = resolve_paths(Some(prefix.path.as_path()), None, None).unwrap();
        let prefix_canonical = fs::canonicalize(&prefix.path).unwrap();
        assert!(validate_purge_containment(
            &prefix_canonical,
            &paths,
            Path::new(PRODUCTION_DATA),
            "测试"
        )
        .is_err());

        let outside_dir = outside.join("data");
        fs::create_dir(&outside_dir).unwrap();
        let outside_canonical = fs::canonicalize(&outside_dir).unwrap();
        assert!(validate_purge_containment(
            &outside_canonical,
            &paths,
            Path::new(PRODUCTION_DATA),
            "测试"
        )
        .is_err());

        let inside_dir = prefix.join("var/lib/rustboard/panel");
        fs::create_dir_all(&inside_dir).unwrap();
        let inside_canonical = fs::canonicalize(&inside_dir).unwrap();
        assert!(validate_purge_containment(
            &inside_canonical,
            &paths,
            Path::new(PRODUCTION_DATA),
            "测试"
        )
        .is_ok());
    }

    // ------------------------------------------------------------------
    // M5 Phase A 安装器安全回归
    // ------------------------------------------------------------------

    /// 读取文件权限位（测试断言 dry-run 不 chmod）。
    #[cfg(unix)]
    fn file_mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn sample_state(paths: &Paths) -> RoleState {
        RoleState {
            version: "0.0.0".to_string(),
            config: paths.config.clone(),
            data_dir: paths.data_dir.clone(),
            unit: paths.unit.clone(),
            binary: paths.binary.clone(),
            installed_at_ms: 0,
            backup_dir: paths.backup_root.clone(),
        }
    }

    #[test]
    fn manage_service_requires_systemd_and_system_unit_dir() {
        // R-S2：只有系统 unit 目录 + systemd 可用才允许 stop/disable。
        assert!(manage_service_for(Path::new("/run/systemd/system"), true));
        assert!(manage_service_for(Path::new("/etc/systemd/system"), true));
        assert!(!manage_service_for(Path::new("/run/systemd/system"), false));
        assert!(!manage_service_for(
            Path::new("/opt/rustboard-test/etc/systemd/system"),
            true
        ));
    }

    #[test]
    fn existing_unit_must_be_rendered_by_installer() {
        let dir = TempDir::new("unit-ownership");
        let unit_dir = dir.join("units");
        fs::create_dir(&unit_dir).unwrap();
        let paths =
            resolve_paths(Some(dir.path.as_path()), None, Some(unit_dir.as_path())).unwrap();

        // 不存在：允许调用方按“无 unit 可删”处理。
        ensure_existing_unit_is_ours(&paths, &paths.unit).unwrap();

        // 本安装器为当前路径渲染的 unit：允许覆盖 / 删除。
        let ours = render_unit(Role::Panel, &paths).unwrap();
        fs::write(&paths.unit, &ours).unwrap();
        ensure_existing_unit_is_ours(&paths, &paths.unit).unwrap();

        // 手工 unit（没有 marker）：拒绝。
        fs::write(
            &paths.unit,
            "[Service]\nExecStart=/usr/local/bin/rustboard-panel run --config /etc/rustboard/panel.toml\n",
        )
        .unwrap();
        let error = ensure_existing_unit_is_ours(&paths, &paths.unit).unwrap_err();
        assert!(format!("{error:#}").contains("不是本安装器"), "{error:#}");

        // marker 相同但 ExecStart 指向别的 prefix：同样拒绝。
        fs::write(
            &paths.unit,
            format!(
                "{}\n[Service]\nExecStart=/usr/local/bin/rustboard-panel run --config /etc/rustboard/panel.toml\n",
                rustboard_install::UNIT_MARKER
            ),
        )
        .unwrap();
        assert!(ensure_existing_unit_is_ours(&paths, &paths.unit).is_err());

        // 目标变成目录：拒绝。
        fs::remove_file(&paths.unit).unwrap();
        fs::create_dir(&paths.unit).unwrap();
        assert!(ensure_existing_unit_is_ours(&paths, &paths.unit).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn existing_unit_symlink_is_rejected() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new("unit-symlink");
        let unit_dir = dir.join("units");
        fs::create_dir(&unit_dir).unwrap();
        let paths =
            resolve_paths(Some(dir.path.as_path()), None, Some(unit_dir.as_path())).unwrap();
        let target = dir.join("elsewhere.service");
        fs::write(&target, render_unit(Role::Panel, &paths).unwrap()).unwrap();
        symlink(&target, &paths.unit).unwrap();

        let error = ensure_existing_unit_is_ours(&paths, &paths.unit).unwrap_err();
        assert!(format!("{error:#}").contains("符号链接"), "{error:#}");
    }

    #[test]
    fn install_paths_are_validated_before_write() {
        let dir = TempDir::new("install-paths");
        let paths = resolve_paths(Some(dir.path.as_path()), None, None).unwrap();
        validate_install_paths(&paths, ServiceMode::UnitOnly).unwrap();

        // prefix 外的配置路径：拒绝。
        let mut outside = paths.clone();
        outside.config = PathBuf::from("/etc/rustboard/panel.toml");
        let error = validate_install_paths(&outside, ServiceMode::UnitOnly).unwrap_err();
        assert!(format!("{error:#}").contains("面板配置"), "{error:#}");

        // systemd / shell 特殊字符：拒绝。
        let mut special = paths.clone();
        special.config = dir.path.join("etc/rustboard/pa$nel.toml");
        let error = validate_install_paths(&special, ServiceMode::UnitOnly).unwrap_err();
        assert!(format!("{error:#}").contains("pa$nel"), "{error:#}");

        // root prefix 下自定义配置必须仍在 /etc/rustboard。
        let root_paths = resolve_paths(
            Some(Path::new("/")),
            Some(Path::new("/srv/panel.toml")),
            None,
        )
        .unwrap();
        assert!(validate_install_paths(&root_paths, ServiceMode::UnitOnly).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn dry_run_config_load_does_not_harden_permissions() {
        let dir = TempDir::new("readonly-config");
        let path = dir.join("panel.toml");
        let cfg = PanelConfig {
            listen: "127.0.0.1:23456".to_string(),
            token: "deadbeef".to_string(),
            ..PanelConfig::default()
        };
        write_with_mode(&path, render_panel_config(&cfg).as_bytes(), 0o644);

        let loaded = load_existing_config(&path, true).expect("dry-run 应能只读解析");
        assert_eq!(loaded.token, "deadbeef");
        assert_eq!(file_mode(&path), 0o644, "dry-run 不得 chmod");

        // 正常安装仍允许收紧旧配置权限。
        let loaded = load_existing_config(&path, false).expect("正常安装应能解析");
        assert_eq!(loaded.listen, "127.0.0.1:23456");
        assert_eq!(file_mode(&path), 0o600, "正常安装应 harden");
    }

    #[cfg(unix)]
    #[test]
    fn readonly_hub_config_does_not_harden_or_leak_parse_details() {
        let dir = TempDir::new("readonly-hub");
        let path = dir.join("hub.toml");
        write_with_mode(&path, b"admin_token = \"token-value\"\n", 0o644);
        let hub = load_hub_config_if_exists(&path, true)
            .unwrap()
            .expect("最小合法 hub.toml 应能解析");
        assert_eq!(hub.admin_token, "token-value");
        assert_eq!(file_mode(&path), 0o644, "dry-run 不得 chmod");

        // 解析错误只报路径，不回显 token 行。
        let bad = dir.join("bad-hub.toml");
        write_with_mode(
            &bad,
            b"admin_token = \"LEAKME-TOKEN\"\nthis is not toml\n",
            0o644,
        );
        let error = load_hub_config_if_exists(&bad, true).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("bad-hub.toml"), "{message}");
        assert!(
            !message.contains("LEAKME-TOKEN"),
            "错误信息泄露了 token: {message}"
        );
    }

    #[test]
    fn purge_targets_require_managed_paths_and_protect_state() {
        let dir = TempDir::new("purge-managed");
        let paths = resolve_paths(Some(dir.path.as_path()), None, None).unwrap();
        let config = paths.config.clone();
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(&config, b"token = \"x\"\n").unwrap();
        let data = paths.data_dir.clone();
        fs::create_dir_all(&data).unwrap();
        let targets = prepare_purge_targets(&paths, &config, &data).unwrap();
        assert!(targets.config.is_some());
        assert!(targets.data.is_some());

        // prefix 外的配置路径：拒绝。
        let outside = TempDir::new("purge-managed-outside");
        let outside_config = outside.join("panel.toml");
        fs::write(&outside_config, b"token = \"x\"\n").unwrap();
        assert!(prepare_purge_targets(&paths, &outside_config, &data).is_err());

        // 数据目录包含 install-state：拒绝。
        let broad = paths.prefix.join("var/lib/rustboard");
        fs::create_dir_all(&broad).unwrap();
        let error = prepare_purge_targets(&paths, &config, &broad).unwrap_err();
        assert!(format!("{error:#}").contains("安装状态"), "{error:#}");

        // 配置路径等于 state 文件：拒绝删除 state 本身。
        fs::write(&paths.state, b"schema = 1\n").unwrap();
        assert!(prepare_purge_targets(&paths, &paths.state, &data).is_err());
    }

    #[test]
    fn removing_last_state_record_deletes_state_file() {
        let dir = TempDir::new("state-remove");
        let paths = resolve_paths(Some(dir.path.as_path()), None, None).unwrap();
        let mut state = InstallState::new();
        state.upsert(Role::Panel, sample_state(&paths));
        state.save(&paths.state).unwrap();

        assert!(remove_state_record(&mut state, &paths.state).unwrap());
        assert!(!path_exists(&paths.state), "roles 为空时应删除 state 文件");
        // 第二次没有记录可删，不应报错。
        assert!(!remove_state_record(&mut state, &paths.state).unwrap());
    }

    #[test]
    fn removing_panel_state_keeps_other_roles() {
        let dir = TempDir::new("state-keep");
        let paths = resolve_paths(Some(dir.path.as_path()), None, None).unwrap();
        let mut state = InstallState::new();
        state.upsert(Role::Panel, sample_state(&paths));
        state.upsert(Role::Hub, sample_state(&paths));
        state.save(&paths.state).unwrap();

        assert!(remove_state_record(&mut state, &paths.state).unwrap());
        let reloaded = InstallState::load(&paths.state).unwrap();
        assert!(reloaded.role(Role::Panel).is_none());
        assert!(reloaded.role(Role::Hub).is_some());
    }

    #[test]
    fn idempotent_branch_rejects_foreign_unit() {
        let dir = TempDir::new("finish-foreign");
        let paths = resolve_paths(Some(dir.path.as_path()), None, None).unwrap();
        fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        fs::write(&paths.config, render_panel_config(&PanelConfig::default())).unwrap();
        fs::create_dir_all(paths.unit.parent().unwrap()).unwrap();
        fs::write(
            &paths.unit,
            "[Service]\nExecStart=/usr/local/bin/rustboard-panel run --config /etc/rustboard/panel.toml\n",
        )
        .unwrap();
        fs::create_dir_all(paths.binary.parent().unwrap()).unwrap();
        fs::write(&paths.binary, b"binary").unwrap();

        let service = ServiceManager::new(paths.unit.parent().unwrap().to_path_buf(), false, true);
        let error = finish_installed(
            &sample_state(&paths),
            &paths,
            ServiceMode::None,
            &service,
            false,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("不是本安装器"), "{error:#}");
    }

    #[test]
    fn install_failure_rolls_back_and_merges_errors() {
        let dir = TempDir::new("rollback");
        let paths = resolve_paths(Some(dir.path.as_path()), None, None).unwrap();
        let mut txn = InstallTxn::begin(&paths, false).unwrap();
        txn.write(&paths.config, b"token = \"x\"\n", 0o600).unwrap();
        let service = ServiceManager::new(paths.unit.parent().unwrap().to_path_buf(), false, false);

        let error = rollback_failed_install(
            &service,
            Role::Panel.unit_name(),
            &paths.unit,
            false,
            false,
            false,
            &mut txn,
            &paths.state,
            None,
            anyhow!("注入的安装失败"),
        );
        let message = format!("{error:#}");
        assert!(message.contains("已回滚"), "{message}");
        assert!(!path_exists(&paths.config), "回滚应删除本次新建的配置");

        // state 恢复失败必须并入返回错误，不能仍宣称已完成回滚。
        let blocked = dir.join("blocked");
        fs::write(&blocked, b"x").unwrap();
        let blocked_state = blocked.join("install-state.toml");
        let mut txn = InstallTxn::begin(&paths, false).unwrap();
        txn.write(&paths.config, b"token = \"x\"\n", 0o600).unwrap();
        let error = rollback_failed_install(
            &service,
            Role::Panel.unit_name(),
            &paths.unit,
            false,
            false,
            false,
            &mut txn,
            &blocked_state,
            Some(b"schema = 1\n"),
            anyhow!("注入的安装失败"),
        );
        let message = format!("{error:#}");
        assert!(message.contains("回滚/恢复未完成"), "{message}");
        assert!(!message.contains("已回滚本次改动"), "{message}");
    }

    // ------------------------------------------------------------------
    // P-01 / P-04 / R-S3 / R-S5 / 全局锁回归
    // ------------------------------------------------------------------

    /// 递归快照（相对路径、是否目录、文件长度），用于断言 dry-run 零写入。
    fn tree_snapshot(root: &Path) -> Vec<(PathBuf, bool, u64)> {
        fn visit(root: &Path, path: &Path, out: &mut Vec<(PathBuf, bool, u64)>) {
            let meta = fs::symlink_metadata(path).unwrap();
            let relative = path.strip_prefix(root).unwrap().to_path_buf();
            let len = if meta.is_file() { meta.len() } else { 0 };
            out.push((relative, meta.is_dir(), len));
            if meta.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    visit(root, &entry.unwrap().path(), out);
                }
            }
        }
        let mut entries = Vec::new();
        visit(root, root, &mut entries);
        entries.sort();
        entries
    }

    #[test]
    fn raw_prefix_with_normalization_tricks_is_rejected() {
        // P-01：`//` 经 Paths::for_role 会变成 `/`，必须在解析前拒绝。
        for raw in [
            "//",
            "///",
            "/opt/rustboard//",
            "/opt/rustboard/",
            "/opt/./rustboard",
        ] {
            let error = resolve_checked_paths(Some(Path::new(raw)), None, None, "").unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("安装前缀"), "{raw:?} 应被拒绝: {message}");
        }

        let root = resolve_checked_paths(Some(Path::new("/")), None, None, "").unwrap();
        assert!(root.is_root_prefix());

        // 前缀校验要求 / 到 prefix 的每个祖先都由当前 euid 拥有；CI runner 的
        // /home 属主是 root，无法构造“通过”用例，root-only 部分跳过。
        if detect_system().euid == 0 {
            let dir = TempDir::new_in(&install_prefix_base(), "raw-prefix-ok");
            let paths = resolve_checked_paths(Some(dir.path.as_path()), None, None, "").unwrap();
            assert_eq!(paths.prefix, dir.path);
        }
    }

    #[test]
    fn systemd_flag_requires_a_system_unit_directory() {
        let dir = TempDir::new("systemd-dir");
        let paths = resolve_paths(Some(dir.path.as_path()), None, None).unwrap();
        // prefix 内 unit（默认 `<prefix>/etc/systemd/system`）不会被 systemd 读取。
        let error = resolve_service_mode(true, false, &paths).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("--systemd"), "{message}");
        assert!(message.contains("systemd"), "{message}");
        assert!(message.contains("unit"), "{message}");

        // 没有 --systemd 时，临时 prefix 仍走 UnitOnly / None，不受影响。
        assert_eq!(
            resolve_service_mode(false, true, &paths).unwrap(),
            ServiceMode::None
        );
        assert_eq!(
            resolve_service_mode(false, false, &paths).unwrap(),
            ServiceMode::UnitOnly
        );

        // 根 prefix 默认由 systemd 管理：自定义非系统 unit 目录同样必须写盘前拒绝。
        if detect_system().systemd {
            let root_paths = resolve_paths(
                Some(Path::new("/")),
                None,
                Some(Path::new("/opt/rustboard-units")),
            )
            .unwrap();
            let error = resolve_service_mode(false, false, &root_paths).unwrap_err();
            assert!(format!("{error:#}").contains("unit 目录"), "{error:#}");
        }
    }

    #[test]
    fn install_fragment_decision_is_pure_and_fail_closed() {
        let expected = Path::new("/run/systemd/system/rustboard-panel.service");
        assert!(ensure_install_fragment(Some(expected), expected, false).is_ok());
        assert!(ensure_install_fragment(None, expected, false).is_ok());

        // unit 文件缺失但同名服务 active：transient / 外来 unit，拒绝。
        let error = ensure_install_fragment(None, expected, true).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("未解析"), "{message}");
        assert!(message.contains("正在运行"), "{message}");

        // fragment 指向其他路径：拒绝。
        let foreign = Path::new("/etc/systemd/system/rustboard-panel.service");
        let error = ensure_install_fragment(Some(foreign), expected, false).unwrap_err();
        assert!(format!("{error:#}").contains("不是"), "{error:#}");
        assert_eq!(
            resolve_fragment(Some(foreign), expected),
            FragmentResolution::Foreign(foreign.to_path_buf())
        );
        assert_eq!(
            resolve_fragment(None, expected),
            FragmentResolution::Unresolved
        );
    }

    #[test]
    fn should_stop_verified_requires_exact_owned_fragment() {
        let expected = Path::new("/etc/systemd/system/rustboard-panel.service");
        let foreign = Path::new("/usr/local/lib/systemd/system/rustboard-panel.service");

        // 只有 fragment 精确等于本安装的 unit 才允许 stop/disable。
        assert!(should_stop_verified(Some(expected), expected));
        // 缺失 / transient、同名外来 / 更高优先级 unit：一律跳过 stop。
        assert!(!should_stop_verified(None, expected));
        assert!(!should_stop_verified(Some(foreign), expected));
    }

    #[test]
    fn uninstall_fragment_decision_only_manages_confirmed_unit() {
        let expected = Path::new("/etc/systemd/system/rustboard-panel.service");
        assert_eq!(
            decide_uninstall_service(Some(expected), expected).unwrap(),
            UninstallServiceAction::StopAndDisable
        );
        // unit 文件存在但 systemd 未解析：只删文件，不调用 systemctl。
        assert_eq!(
            decide_uninstall_service(None, expected).unwrap(),
            UninstallServiceAction::RemoveFileOnly
        );
        // 同名更高优先级 / 外来 unit：拒绝且不删除。
        let foreign = Path::new("/usr/local/lib/systemd/system/rustboard-panel.service");
        let error = decide_uninstall_service(Some(foreign), expected).unwrap_err();
        assert!(format!("{error:#}").contains("拒绝"), "{error:#}");
    }

    #[test]
    fn global_lock_is_skipped_for_dry_run_and_inherited_child() {
        assert!(should_acquire_global_lock(false, false));
        assert!(!should_acquire_global_lock(true, false));
        assert!(!should_acquire_global_lock(false, true));
        assert!(!should_acquire_global_lock(true, true));

        // 无需要时不真正加锁（也不会创建 /run/rustboard-install.lock）。
        assert!(acquire_install_lock(true, false, "测试").unwrap().is_none());
        assert!(acquire_install_lock(false, true, "测试").unwrap().is_none());
    }

    #[test]
    fn admin_tls_required_is_rejected() {
        let required = HubConfig {
            admin_tls: AdminTlsMode::Required,
            ..HubConfig::default()
        };
        let error = ensure_hub_admin_tls_supported(Some(&required)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("admin_tls=required"), "{message}");
        assert!(message.contains("Phase A"), "{message}");

        let off = HubConfig {
            admin_tls: AdminTlsMode::Off,
            ..HubConfig::default()
        };
        assert!(ensure_hub_admin_tls_supported(Some(&off)).is_ok());
        assert!(ensure_hub_admin_tls_supported(None).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn required_hub_admin_tls_rejects_dry_run_without_writing() {
        if detect_system().euid != 0 {
            eprintln!("跳过 root-only panel required 测试（euid != 0）");
            return;
        }
        let dir = TempDir::new_in(&install_prefix_base(), "required-hub");
        let prefix = dir.path.clone();
        let hub_path = prefix.join(HUB_CONFIG_RELATIVE);
        fs::create_dir_all(hub_path.parent().unwrap()).unwrap();
        write_with_mode(
            &hub_path,
            b"admin_tls = \"required\"\nadmin_token = \"token-value\"\n",
            0o644,
        );
        let panel_paths = resolve_paths(Some(&prefix), None, None).unwrap();
        let before = tree_snapshot(&prefix);

        // 即使显式给出 --hub-url http://...，也必须拒绝。
        let error = install(InstallArgs {
            yes: true,
            offline: false,
            dry_run: true,
            force: false,
            prefix: Some(prefix.clone()),
            config: None,
            unit_dir: None,
            hub_url: Some("http://127.0.0.1:1234".to_string()),
            hub_token_file: None,
            password_file: None,
            listen: None,
            static_dir: None,
            systemd: false,
            no_systemd: false,
        })
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("admin_tls=required"), "{message}");
        assert!(message.contains("Phase A"), "{message}");

        // 零写入：目录树、hub.toml 权限、panel 受管路径都不变。
        assert_eq!(tree_snapshot(&prefix), before);
        assert_eq!(file_mode(&hub_path), 0o644, "dry-run 不得 chmod hub.toml");
        for path in [
            &panel_paths.config,
            &panel_paths.unit,
            &panel_paths.state,
            &panel_paths.data_dir,
        ] {
            assert!(!path_exists(path), "{} 不应存在", path.display());
        }
    }

    #[test]
    fn recorded_config_and_data_are_validated_without_purge() {
        let dir = TempDir::new("record-path");
        let paths = resolve_paths(Some(dir.path.as_path()), None, None).unwrap();
        fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        fs::write(&paths.config, b"token = \"x\"\n").unwrap();
        fs::create_dir_all(&paths.data_dir).unwrap();
        // 正常记录通过；缺失路径在未 --purge 时不算失败。
        validate_recorded_config_and_data(&paths, &paths.config, &paths.data_dir).unwrap();
        validate_recorded_config_and_data(
            &paths,
            &dir.join("missing.toml"),
            &dir.join("missing-data"),
        )
        .unwrap();

        // prefix 外路径：拒绝。
        let outside = TempDir::new("record-path-outside");
        let outside_config = outside.join("panel.toml");
        fs::write(&outside_config, b"x").unwrap();
        assert!(
            validate_recorded_config_and_data(&paths, &outside_config, &paths.data_dir).is_err()
        );

        // 特殊字符：拒绝。
        assert!(validate_recorded_config_and_data(
            &paths,
            &dir.join("etc/rustboard/pa$nel.toml"),
            &paths.data_dir
        )
        .is_err());

        // 类型错误：config 是目录、data 是普通文件，均拒绝。
        assert!(
            validate_recorded_config_and_data(&paths, &paths.data_dir, &paths.data_dir).is_err()
        );
        assert!(validate_recorded_config_and_data(&paths, &paths.config, &paths.config).is_err());
    }
}
