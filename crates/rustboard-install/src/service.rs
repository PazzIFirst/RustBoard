//! systemd 管理、unit 渲染与 HTTP 健康检查。
//!
//! 所有外部命令都用 `Command::args([...])` 调用，不拼 shell；`manage=false` 或
//! `dry_run` 时不执行 systemctl。systemd 按 unit **名字**操作，同名 unit 的优先级
//! 与 transient unit 都可能让 `systemctl stop` 作用到不是我们写的服务；因此
//! stop / restart / enable 之前必须用 [`ServiceManager::ensure_fragment_is`]
//! 核对 systemd 实际解析的 `FragmentPath`。`wait_http_ok` 只支持明文 `http://`，
//! 不引入 reqwest。

use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rustboard_common::fsutil;

use crate::path_validate::{normalize_absolute, reject_unit_unsafe_chars};
use crate::Paths;
use crate::Role;

/// 安装器写入的 unit 文件标记。
///
/// 第一行固定输出该标记，卸载 / 升级据此区分“RustBoard 管理的 unit”和用户手写
/// 的 unit；清理 unit 前必须配合 [`unit_is_ours`] 使用，不能只凭文件名删除。
pub const UNIT_MARKER: &str = "# Managed by rustboard-install; do not edit.";

/// systemd unit 模板。
///
/// 设计文档希望模板放在 `packaging/systemd` 并通过 `include_str!` 读取；但 Phase A
/// 同时要求 packaging 下的静态 unit 使用生产默认路径、能直接 `systemd-analyze
/// verify`，而带 `@...@` 占位符的 unit 无法通过 verify（ExecStart 不是绝对路径）。
/// 因此这里内嵌模板，packaging 下放渲染后的生产默认 unit；集成测试锁定
/// `render_unit(默认 Paths)` 与 packaging 文件逐字节一致，避免两处漂移。
///
/// 三个 unit 都不启用 `RestrictSUIDSGID`：systemd 257 的该 seccomp 过滤器会让
/// `openat2(2)` 返回 ENOSYS，而 `fsutil::ensure_private_dir` 依赖 openat2；已有的
/// `NoNewPrivileges=true` 已阻止 setuid/setgid 提权，去掉它不降低安全性。
const HUB_TEMPLATE: &str = r#"# RustBoard Hub systemd unit（由 rustboard-install 渲染）。
[Unit]
Description=RustBoard Hub
Documentation=https://github.com/pazzifirst/rustboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
@EXEC_LINE@
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
LockPersonality=true
ReadWritePaths=@DATA_DIR@

[Install]
WantedBy=multi-user.target
"#;

const AGENT_TEMPLATE: &str = r#"# RustBoard Agent systemd unit（由 rustboard-install 渲染）。
[Unit]
Description=RustBoard Agent
Documentation=https://github.com/pazzifirst/rustboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
@EXEC_LINE@
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
LockPersonality=true
ReadWritePaths=@DATA_DIR@

[Install]
WantedBy=multi-user.target
"#;

const PANEL_TEMPLATE: &str = r#"# RustBoard Panel systemd unit（由 rustboard-install 渲染）。
[Unit]
Description=RustBoard Panel
Documentation=https://github.com/pazzifirst/rustboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
@EXEC_LINE@
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
LockPersonality=true
ReadWritePaths=@DATA_DIR@

[Install]
WantedBy=multi-user.target
"#;

/// 渲染角色对应的 systemd unit。
///
/// 第一行固定为 [`UNIT_MARKER`]；`ExecStart` 与 `ReadWritePaths` 中的路径统一经
/// `unit_path` 校验：必须是绝对路径，且不含控制字符、`$`、`%`、引号或反斜杠
/// （systemd 会展开变量 / specifier，引号与反斜杠会产生转义歧义）。空格仍由
/// `systemd_quote` 双引号包裹。
pub fn render_unit(role: Role, paths: &Paths) -> Result<String> {
    let template = match role {
        Role::Hub => HUB_TEMPLATE,
        Role::Agent => AGENT_TEMPLATE,
        Role::Panel => PANEL_TEMPLATE,
    };
    let exec_line = exec_start_line(paths)?;
    let data_dir = unit_path(&paths.data_dir, "数据目录")?;

    let body = expand_template(
        template,
        &[
            ("@EXEC_LINE@", exec_line.as_str()),
            ("@DATA_DIR@", data_dir.as_str()),
        ],
    )?;
    Ok(format!("{UNIT_MARKER}\n{body}"))
}

/// 生成 unit 的 `ExecStart` 行。
///
/// `render_unit` 与 [`unit_is_ours`] 共用本函数，保证“判断某个 unit 是否由我们
/// 渲染”时比较的是与渲染完全一致的命令行，而不是宽松的 `contains`。
fn exec_start_line(paths: &Paths) -> Result<String> {
    let binary = unit_path(&paths.binary, "二进制路径")?;
    let config = unit_path(&paths.config, "配置路径")?;
    Ok(format!("ExecStart={binary} run --config {config}"))
}

/// 判断 `contents` 是否是安装器为 `role` / `paths` 渲染的 unit。
///
/// 条件：存在与 [`UNIT_MARKER`] 完全相同的行，且存在与 `exec_start_line`
/// 完全相同的 `ExecStart` 行。只有 marker 或只有相似的 ExecStart（例如用户手动
/// 改了配置路径）都返回 `false`，避免卸载时删掉用户正在使用的 unit。
pub fn unit_is_ours(_role: Role, paths: &Paths, contents: &str) -> bool {
    if !contents.lines().any(|line| line == UNIT_MARKER) {
        return false;
    }
    let expected = match exec_start_line(paths) {
        Ok(line) => line,
        Err(_) => return false,
    };
    contents.lines().any(|line| line == expected)
}

/// 判断路径是否是已知的 systemd unit 目录。
///
/// 识别 `/run/systemd/system`、`/etc/systemd/system`、
/// `/usr/local/lib/systemd/system`、`/usr/lib/systemd/system`、
/// `/lib/systemd/system` 以及 `/usr/local/share/systemd/system`。输入会先归一化，
/// 因此结尾 `/` 不影响判断；相对路径或含 `..` 的路径返回 `false`。
pub fn is_systemd_unit_dir(path: &Path) -> bool {
    let Ok(normalized) = normalize_absolute(path, "systemd unit 目录") else {
        return false;
    };
    matches!(
        normalized.to_str(),
        Some(
            "/run/systemd/system"
                | "/etc/systemd/system"
                | "/usr/local/lib/systemd/system"
                | "/usr/lib/systemd/system"
                | "/lib/systemd/system"
                | "/usr/local/share/systemd/system"
        )
    )
}

/// 单遍替换占位符。
///
/// 不能对模板连续做多次 `str::replace`：如果某个路径本身包含后续占位符文本
/// （例如 prefix 里出现 `@CONFIG@`），第二次替换会改坏已插入的值。这里只扫描
/// 原始模板，替换结果不再参与匹配。每个占位符必须在模板中出现至少一次。
fn expand_template(template: &str, values: &[(&str, &str)]) -> Result<String> {
    let mut rendered = String::with_capacity(template.len());
    let mut rest = template;
    let mut seen = vec![false; values.len()];

    while let Some(index) = rest.find('@') {
        rendered.push_str(&rest[..index]);
        let tail = &rest[index..];
        let mut matched = false;
        for (position, (placeholder, value)) in values.iter().enumerate() {
            if let Some(remaining) = tail.strip_prefix(placeholder) {
                rendered.push_str(value);
                rest = remaining;
                seen[position] = true;
                matched = true;
                break;
            }
        }
        if !matched {
            rendered.push('@');
            rest = &tail[1..];
        }
    }
    rendered.push_str(rest);

    for (position, (placeholder, _)) in values.iter().enumerate() {
        if !seen[position] {
            bail!("unit 模板缺少占位符 {placeholder}");
        }
    }
    Ok(rendered)
}

/// 将单个值安全地放进 POSIX shell 命令（安装摘要里打印可复制命令用）。
///
/// 安全字符集与 v0.4.1 hub 的 KI-20 实现一致；空串或含其他字符时整体单引号
/// 包裹，内部 `'` 替换为 `'\''`。
pub fn shell_arg(value: &str) -> String {
    if !value.is_empty() && value.bytes().all(shell_arg_safe_byte) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn shell_arg_safe_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'_' | b'/' | b':' | b'@' | b'%' | b'+' | b',' | b'-'
        )
}

/// 校验路径并转成 systemd 命令行里的一个参数。
///
/// `ExecStart`（binary/config）与 `ReadWritePaths`（data）都走这一个入口，避免
/// 两处字符集检查出现遗漏。
fn unit_path(path: &Path, label: &str) -> Result<String> {
    let normalized = normalize_absolute(path, label)?;
    reject_unit_unsafe_chars(&normalized, label)?;
    let text = normalized
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{label}不是有效 UTF-8: {}", path.display()))?;
    Ok(systemd_quote(text))
}

/// systemd 命令行的最小引用：安全字符原样输出，否则双引号包裹并转义。
fn systemd_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'/' | b':' | b'@' | b'+' | b'-')
        });
    if safe {
        return value.to_string();
    }
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str(r"\\"),
            '"' => escaped.push_str(r#"\""#),
            // systemd 会对 $ 做环境变量替换、对 % 做 specifier 展开；双写转义。
            '$' => escaped.push_str("$$"),
            '%' => escaped.push_str("%%"),
            _ => escaped.push(ch),
        }
    }
    escaped.push('"');
    escaped
}

/// systemd `ActiveState` 的严格分类。
///
/// 安装器不能把“systemctl 没输出 / 非零退出 / activating”当成已停止。只有
/// `inactive` 与 `failed` 被视为停止；其余状态（含未知字符串）都必须由调用方
/// 按 fail-closed 处理。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    Inactive,
    Failed,
    Active,
    Activating,
    Deactivating,
    Reloading,
    Other(String),
}

impl ServiceState {
    /// 解析 `systemctl show -p ActiveState --value` 的输出。
    pub fn parse(value: &str) -> Self {
        match value.trim() {
            "inactive" => Self::Inactive,
            "failed" => Self::Failed,
            "active" => Self::Active,
            "activating" => Self::Activating,
            "deactivating" => Self::Deactivating,
            "reloading" => Self::Reloading,
            other => Self::Other(other.to_string()),
        }
    }

    /// 是否明确停止（只有 inactive / failed）。
    pub fn is_stopped(&self) -> bool {
        matches!(self, Self::Inactive | Self::Failed)
    }

    /// 是否可视为“已启用且正在运行 / 启动中”，用于 was_active 判定。
    ///
    /// `deactivating` 与未知状态不在此列：它们不能证明服务会继续运行，也不能
    /// 证明已经停止，必须由调用方 fail-closed。
    pub fn is_active_or_starting(&self) -> bool {
        matches!(self, Self::Active | Self::Activating | Self::Reloading)
    }

    /// 用于错误信息的稳定文本。
    pub fn as_str(&self) -> &str {
        match self {
            Self::Inactive => "inactive",
            Self::Failed => "failed",
            Self::Active => "active",
            Self::Activating => "activating",
            Self::Deactivating => "deactivating",
            Self::Reloading => "reloading",
            Self::Other(value) => value,
        }
    }
}

/// 安装器依赖的 systemd 控制面。
///
/// 生产实现是 [`ServiceManager`]；测试可以注入 fake，验证停止失败 / 无法确认
/// inactive / disable 失败等分支，而不触碰宿主机 systemd。卸载流程只在
/// fragment 已确认归属后才调用这些方法。
pub trait ServiceControl {
    /// 查询 systemd 实际解析的 unit 文件。
    fn fragment_path(&self, unit: &str) -> Result<Option<PathBuf>>;
    /// 断言 systemd 实际解析的 unit 就是 `expected`。
    fn ensure_fragment_is(&self, unit: &str, expected: &Path) -> Result<()>;
    /// `systemctl daemon-reload`。
    fn daemon_reload(&self) -> Result<()>;
    /// 是否真正启用 systemd 管理（非 `--no-systemd` / 非 dry-run）。
    ///
    /// 为 false 时所有状态查询 / stop / restart 都必须拒绝，不能把 no-op 当成
    /// 成功（尤其卸载时）。
    fn is_managing(&self) -> bool;
    /// 查询严格 `ActiveState`；查询失败或输出为空必须返回 `Err`。
    fn active_state(&self, unit: &str) -> Result<ServiceState>;
    /// 便捷判定：只有 active / activating / reloading 返回 true；inactive /
    /// failed 返回 false；deactivating / 未知状态 / 查询失败返回 `Err`。
    fn is_active(&self, unit: &str) -> Result<bool> {
        if !self.is_managing() {
            bail!("systemd 管理未启用（--no-systemd / dry-run），拒绝把 no-op 当作服务状态");
        }
        match self.active_state(unit)? {
            ServiceState::Inactive | ServiceState::Failed => Ok(false),
            ServiceState::Active | ServiceState::Activating | ServiceState::Reloading => Ok(true),
            state @ (ServiceState::Deactivating | ServiceState::Other(_)) => bail!(
                "无法把 {} 的 ActiveState={} 判定为运行或停止（拒绝猜测）",
                unit,
                state.as_str()
            ),
        }
    }
    /// `systemctl show -p MainPID --value`；未运行时返回 0。
    fn main_pid(&self, unit: &str) -> Result<u32>;
    /// `systemctl enable --now`。
    fn enable_now(&self, unit: &str) -> Result<()>;
    /// `systemctl restart`。
    fn restart(&self, unit: &str) -> Result<()>;
    /// 只 `systemctl stop`，不 disable。
    fn stop(&self, unit: &str) -> Result<()>;
    /// 只 `systemctl disable`，不 stop。
    fn disable(&self, unit: &str) -> Result<()>;
}

/// systemd 服务管理器。
pub struct ServiceManager {
    pub unit_dir: PathBuf,
    pub manage: bool,
    pub dry_run: bool,
}

impl ServiceManager {
    /// 创建管理器。
    pub fn new(unit_dir: PathBuf, manage: bool, dry_run: bool) -> Self {
        Self {
            unit_dir,
            manage,
            dry_run,
        }
    }

    /// 写 unit 文件（0644，原子替换）。`dry_run` 只返回目标路径。
    ///
    /// `name` 必须是单个安全文件名，拒绝路径分隔符、`..`、控制字符与以 `-`
    /// 开头的名字，避免写出 unit_dir 或把参数伪装成 systemctl 选项。
    pub fn write_unit(&self, name: &str, contents: &str) -> Result<PathBuf> {
        let file_name = validate_unit_name(name)?;
        let unit_dir = normalize_absolute(&self.unit_dir, "unit 目录")?;
        let path = unit_dir.join(file_name);
        if contents.as_bytes().contains(&0) {
            bail!("unit {name} 内容包含 NUL，拒绝写入");
        }
        if self.dry_run {
            return Ok(path);
        }
        fsutil::ensure_dir(&unit_dir, 0o755)
            .with_context(|| format!("创建 unit 目录 {} 失败", unit_dir.display()))?;
        fsutil::atomic_write(&path, contents.as_bytes(), 0o644)
            .with_context(|| format!("写入 unit {} 失败", path.display()))?;
        Ok(path)
    }

    /// `systemctl daemon-reload`。
    pub fn daemon_reload(&self) -> Result<()> {
        self.run_systemctl(&["daemon-reload"])
    }

    /// `systemctl enable --now <unit>`。
    ///
    /// 调用前必须用 [`Self::ensure_fragment_is`] 确认 systemd 解析到的是我们的
    /// unit，避免启用同名外来 / 更高优先级 unit。
    pub fn enable_now(&self, unit: &str) -> Result<()> {
        validate_unit_arg(unit)?;
        self.run_systemctl(&["enable", "--now", unit])
    }

    /// `systemctl restart <unit>`。
    ///
    /// 调用前必须用 [`Self::ensure_fragment_is`] 确认 systemd 解析到的是我们的
    /// unit，避免重启同名外来 / 更高优先级 unit。
    pub fn restart(&self, unit: &str) -> Result<()> {
        validate_unit_arg(unit)?;
        self.run_systemctl(&["restart", unit])
    }

    /// 只执行 `systemctl stop <unit>`，不 disable。
    ///
    /// 卸载时 stop 失败必须立即中止，不能用 disable 成功掩盖；调用前先用
    /// [`Self::ensure_fragment_is`] 确认归属。
    pub fn stop(&self, unit: &str) -> Result<()> {
        validate_unit_arg(unit)?;
        self.run_systemctl(&["stop", unit])
    }

    /// 只执行 `systemctl disable <unit>`，不 stop。
    ///
    /// 卸载流程在确认服务已 inactive 之后才调用；disable 失败只影响开机自启，
    /// 不应与 stop 失败混为一谈。
    pub fn disable(&self, unit: &str) -> Result<()> {
        validate_unit_arg(unit)?;
        self.run_systemctl(&["disable", unit])
    }

    /// 先 `systemctl stop` 再 `systemctl disable`。
    ///
    /// 卸载时必须在调用前用 [`Self::ensure_fragment_is`] 确认要停的是我们的 unit；
    /// 只检查 `paths.unit` 文件挡不住同名的更高优先级 unit 或 transient unit。
    /// 新代码应改用 [`ServiceControl::stop`] / [`ServiceControl::disable`] 分别
    /// 处理失败，本方法仅供安装失败回滚等“尽力清理”路径使用。
    pub fn stop_disable(&self, unit: &str) -> Result<()> {
        validate_unit_arg(unit)?;
        let stop = self.run_systemctl(&["stop", unit]);
        // stop 失败也继续 disable：回滚时不能因为服务本来没跑就留下自启项。
        let disable = self.run_systemctl(&["disable", unit]);
        stop.and(disable)
    }

    /// `systemctl show <unit> -p MainPID --value`；未运行时返回 0。
    ///
    /// 安装器用它确认重启后确实产生了新进程，避免把 `enable --now` 对已运行
    /// 服务的 no-op 误认为“新二进制 / 新配置已生效”。
    pub fn main_pid(&self, unit: &str) -> Result<u32> {
        validate_unit_arg(unit)?;
        if !self.manage || self.dry_run {
            return Ok(0);
        }
        let output = Command::new("systemctl")
            .args(["show", unit, "-p", "MainPID", "--value"])
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("执行 systemctl show {unit} -p MainPID --value 失败"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "systemctl show {unit} -p MainPID 失败（退出状态 {}）: {}",
                output.status,
                stderr.trim()
            );
        }
        let text = String::from_utf8_lossy(&output.stdout);
        text.trim()
            .parse::<u32>()
            .with_context(|| format!("systemctl show {unit} 返回了非法 MainPID: {text:?}"))
    }

    /// 是否真正启用 systemd 管理（非 `--no-systemd` / 非 dry-run）。
    pub fn is_managing(&self) -> bool {
        self.manage && !self.dry_run
    }

    /// `systemctl show <unit> -p ActiveState --value`，严格解析。
    ///
    /// 非零退出、空输出、启动失败、未知状态一律返回错误；调用方不得把
    /// “查不到”当成 inactive。只有 [`ServiceState::Inactive`] / `Failed` 可视为
    /// 已停止。
    pub fn active_state(&self, unit: &str) -> Result<ServiceState> {
        validate_unit_arg(unit)?;
        if !self.is_managing() {
            bail!("systemd 管理未启用（--no-systemd / dry-run），拒绝把 no-op 当作服务状态");
        }
        let output = Command::new("systemctl")
            .args(["show", unit, "-p", "ActiveState", "--value"])
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("执行 systemctl show {unit} -p ActiveState --value 失败"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "systemctl show {unit} -p ActiveState 失败（退出状态 {}）: {}",
                output.status,
                stderr.trim()
            );
        }
        let text = String::from_utf8(output.stdout)
            .with_context(|| format!("systemctl show {unit} 的 ActiveState 不是 UTF-8"))?;
        let state = text.trim();
        if state.is_empty() {
            bail!("systemctl show {unit} 返回空 ActiveState，拒绝猜测服务状态");
        }
        Ok(ServiceState::parse(state))
    }

    /// `systemctl show -p ActiveState --value` 的布尔封装。
    ///
    /// 只有 `active` / `activating` / `reloading` 返回 true；`inactive` / `failed`
    /// 返回 false；`deactivating`、未知状态与查询失败返回错误。
    pub fn is_active(&self, unit: &str) -> Result<bool> {
        match self.active_state(unit)? {
            ServiceState::Inactive | ServiceState::Failed => Ok(false),
            ServiceState::Active | ServiceState::Activating | ServiceState::Reloading => Ok(true),
            state @ (ServiceState::Deactivating | ServiceState::Other(_)) => bail!(
                "无法把 {unit} 的 ActiveState={} 判定为运行或停止（拒绝猜测）",
                state.as_str()
            ),
        }
    }

    /// 查询 systemd 实际解析到的 unit 文件（`FragmentPath` + `LoadState`）。
    ///
    /// 只看 `paths.unit` 文件是否存在并不够：systemd 按 unit **名字**操作，
    /// `/etc/systemd/system` 中同名 unit 的优先级高于 `/run/systemd/system`；
    /// 文件缺失的 transient unit 也可能 active 并被 stop。这里以 systemd 自己的
    /// 解析结果为准，调用方应使用 [`Self::ensure_fragment_is`] 拒绝同名外来 unit。
    ///
    /// 行为：
    /// - `manage=false` 或 `dry_run` 时不执行 systemctl，返回 `None`；
    /// - `LoadState=not-found` 或 stderr 明确 “Unit ... could not be found” 返回
    ///   `None`（unit 确实不存在）；
    /// - **只允许明确 not-found 返回 `None`**；D-Bus、权限、systemctl 不存在、
    ///   其他非零退出或输出畸形一律 `Err`，不能因此让卸载走“只删文件”；
    /// - 成功但 `FragmentPath` 为空返回 `None`（transient / 未加载）。
    ///
    /// 返回路径已归一化，便于和 [`crate::Paths::unit`] 直接比较。安装流程应在
    /// 写完 unit 并 `daemon-reload` 后立即查询，此时 systemd 才能解析到新文件。
    pub fn fragment_path(&self, unit: &str) -> Result<Option<PathBuf>> {
        validate_unit_arg(unit)?;
        if !self.manage || self.dry_run {
            return Ok(None);
        }
        let output = Command::new("systemctl")
            .args(["show", unit, "-p", "FragmentPath", "-p", "LoadState"])
            .stdin(Stdio::null())
            .output()
            .with_context(|| {
                format!(
                    "执行 systemctl show {unit} -p FragmentPath -p LoadState 失败（systemctl 不存在或不可执行？）"
                )
            })?;
        fragment_path_from_show(
            output.status.success(),
            &output.stdout,
            &output.stderr,
            unit,
        )
    }

    /// 断言 systemd 实际解析的 unit 文件就是 `expected`。
    ///
    /// **调用方必须在 `stop` / `restart` / `enable` 之前调用本方法**：
    /// - 安装：先写 unit 并 `daemon-reload`，再检查 systemd 是否真的选中了该文件；
    /// - 卸载：在 `stop` 前检查，避免停掉 `/etc/systemd/system` 中更高优先级的
    ///   同名外来 unit，或没有 unit 文件的 transient unit。
    ///
    /// `expected` 会先归一化，再与 `FragmentPath` 比较；`FragmentPath` 为空（unit
    /// 未加载 / transient）同样拒绝，按“同名外来 / 更高优先级 unit”处理。
    /// `manage=false` 或 `dry_run` 时只校验参数并跳过实际查询。
    pub fn ensure_fragment_is(&self, unit: &str, expected: &Path) -> Result<()> {
        validate_unit_arg(unit)?;
        let expected = normalize_absolute(expected, "目标 unit 路径")?;
        if !self.manage || self.dry_run {
            return Ok(());
        }
        let actual = self.fragment_path(unit)?;
        ensure_fragment_matches(unit, &expected, actual.as_deref())
    }

    /// 统一执行 systemctl，失败时带上 stderr / stdout。
    fn run_systemctl(&self, args: &[&str]) -> Result<()> {
        if !self.manage || self.dry_run {
            return Ok(());
        }
        let output = Command::new("systemctl")
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("执行 systemctl {} 失败", args.join(" ")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = if !stderr.trim().is_empty() {
                stderr.trim()
            } else {
                stdout.trim()
            };
            bail!(
                "systemctl {} 失败（退出状态 {}）: {detail}",
                args.join(" "),
                output.status
            );
        }
        Ok(())
    }
}

impl ServiceControl for ServiceManager {
    fn fragment_path(&self, unit: &str) -> Result<Option<PathBuf>> {
        ServiceManager::fragment_path(self, unit)
    }

    fn ensure_fragment_is(&self, unit: &str, expected: &Path) -> Result<()> {
        ServiceManager::ensure_fragment_is(self, unit, expected)
    }

    fn daemon_reload(&self) -> Result<()> {
        ServiceManager::daemon_reload(self)
    }

    fn is_managing(&self) -> bool {
        ServiceManager::is_managing(self)
    }

    fn active_state(&self, unit: &str) -> Result<ServiceState> {
        ServiceManager::active_state(self, unit)
    }

    fn main_pid(&self, unit: &str) -> Result<u32> {
        ServiceManager::main_pid(self, unit)
    }

    fn enable_now(&self, unit: &str) -> Result<()> {
        ServiceManager::enable_now(self, unit)
    }

    fn restart(&self, unit: &str) -> Result<()> {
        ServiceManager::restart(self, unit)
    }

    fn stop(&self, unit: &str) -> Result<()> {
        ServiceManager::stop(self, unit)
    }

    fn disable(&self, unit: &str) -> Result<()> {
        ServiceManager::disable(self, unit)
    }
}

/// 卸载前停止服务并确认 inactive，随后尽力 disable。
///
/// 顺序固定为 **stop → ActiveState → disable → 真正删除文件**：
/// - 未启用 systemd 管理（`--no-systemd` / dry-run）：直接报错，不能把 no-op
///   当成已停止；
/// - stop 失败：直接返回错误，调用方不得删除 unit / binary / state，更不得 purge；
/// - stop 成功但 ActiveState 不是精确 `inactive` / `failed`，或查询失败：同样
///   返回错误并保留全部文件；
/// - 已确认停止后才 disable；disable 失败只警告，因为 unit 文件即将删除，
///   不应把“自启链接残留”与“服务仍在运行”混为一谈。
///
/// 错误信息由 `label` 拼成（例如“hub”），调用方负责在错误链里补充上下文。
pub fn stop_service_checked(service: &dyn ServiceControl, unit: &str, label: &str) -> Result<()> {
    if !service.is_managing() {
        bail!(
            "{label} 卸载未启用 systemd 管理（--no-systemd / dry-run），拒绝把 no-op 当作服务已停止"
        );
    }
    service.stop(unit).with_context(|| {
        format!(
            "停止 {label} 服务 {unit} 失败；未删除任何文件，安装状态已保留（可修复 systemd 后重试）"
        )
    })?;
    match service.active_state(unit) {
        Ok(state) if state.is_stopped() => {}
        Ok(state) => bail!(
            "停止 {label} 服务 {unit} 后 ActiveState={}；无法确认已停止，未删除任何文件，安装状态已保留",
            state.as_str()
        ),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "无法确认 {label} 服务 {unit} 已停止；未删除任何文件，安装状态已保留（拒绝在状态未知时删除）"
                )
            })
        }
    }
    if let Err(err) = service.disable(unit) {
        eprintln!("警告：禁用 {label} 服务 {unit} 失败（继续删除 unit）: {err:#}");
    }
    Ok(())
}

/// 卸载时对“没有可停 unit 文件”的同名服务做严格状态检查。
///
/// unit 文件不存在、或 FragmentPath 为空（transient / 未加载）时不能 stop，
/// 但仍必须确认同名服务确实已停止；active / activating / reloading /
/// deactivating / 未知状态或查询失败都必须拒绝删除与 purge。
pub fn ensure_service_stopped(service: &dyn ServiceControl, unit: &str, label: &str) -> Result<()> {
    if !service.is_managing() {
        bail!(
            "{label} 卸载未启用 systemd 管理（--no-systemd / dry-run），无法确认同名服务状态；拒绝删除"
        );
    }
    match service.active_state(unit) {
        Ok(state) if state.is_stopped() => Ok(()),
        Ok(state) => bail!(
            "{label} 的 unit 文件不存在或未解析，但同名服务 {unit} 的 ActiveState={}；\
             拒绝删除 unit / binary / config / data / state，也拒绝 --purge",
            state.as_str()
        ),
        Err(err) => Err(err).with_context(|| {
            format!("无法确认同名 {label} 服务 {unit} 已停止；拒绝删除与 --purge（安装状态已保留）")
        }),
    }
}

/// 删除 `systemctl enable` 生成的 target.wants 符号链接（只删符号链接）。
///
/// 安全边界：链接目标 canonicalize 后必须等于 `expected_target`（本安装 unit
/// 的实际路径），否则保留。这样同名外来 unit 的 enable 链接不会被误删；
/// `expected_target` 不存在（unit 文件缺失/未解析）时同样保留，不按名字猜。
///
/// `disable` 失败时 unit 文件删除前仍可能留下自启链接；调用方应先于删除 unit
/// 调用本函数。同时检查 unit_dir 与 `/etc/systemd/system`（仅当 unit_dir 是
/// systemd 会读取的目录，避免 prefix 测试触碰宿主）。
pub fn remove_enable_symlink(
    unit_dir: &Path,
    unit_name: &str,
    expected_target: &Path,
) -> Result<()> {
    validate_unit_arg(unit_name)?;
    // unit 文件已不存在 / 不是普通文件（含符号链接）/ 路径无法解析：无法证明
    // 链接归属，直接保留，不能按文件名删除。
    match fs::symlink_metadata(expected_target) {
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {}
        _ => return Ok(()),
    }
    let Ok(expected) = fs::canonicalize(expected_target) else {
        return Ok(());
    };
    let system_dir = Path::new("/etc/systemd/system");
    let mut dirs = vec![unit_dir];
    if unit_dir != system_dir && is_systemd_unit_dir(unit_dir) {
        dirs.push(system_dir);
    }
    for dir in dirs {
        for target in ["multi-user.target.wants", "graphical.target.wants"] {
            let path = dir.join(target).join(unit_name);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    // canonicalize 同时解析相对目标与多级链接；失败（悬空/权限）
                    // 时保留链接，不能按文件名删除。
                    let Ok(actual) = fs::canonicalize(&path) else {
                        continue;
                    };
                    if actual != expected {
                        continue;
                    }
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

/// 校验 unit 文件名，返回文件名本身。
fn validate_unit_name(name: &str) -> Result<&str> {
    if name.is_empty() {
        bail!("unit 文件名不能为空");
    }
    if name.starts_with('-') {
        bail!("unit 文件名不能以 - 开头: {name}");
    }
    if name.contains('\\') || name.chars().any(|ch| ch.is_control()) {
        bail!("unit 文件名含非法字符: {name:?}");
    }
    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(only)), None) => only
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("unit 文件名不是有效 UTF-8: {name:?}")),
        _ => bail!("unit 文件名必须是单个普通文件名: {name:?}"),
    }
}

/// 校验传给 systemctl 的 unit 参数，防止以 `-` 开头的选项注入。
fn validate_unit_arg(unit: &str) -> Result<()> {
    if unit.is_empty() {
        bail!("unit 名称不能为空");
    }
    if unit.starts_with('-') {
        bail!("unit 名称不能以 - 开头: {unit}");
    }
    if unit.contains('/') || unit.contains('\\') || unit.chars().any(|ch| ch.is_control()) {
        bail!("unit 名称含非法字符: {unit:?}");
    }
    Ok(())
}

/// 解析 `systemctl show -p FragmentPath --value` 的 stdout。
///
/// 空输出（unit 未加载 / transient）返回 `None`；输出必须是单行绝对路径。
/// 非 UTF-8、含控制字符或多行输出都视为畸形并返回错误（fail-closed）。
/// `systemctl show` 中安装器关心的属性。
#[derive(Debug, Default, PartialEq, Eq)]
struct UnitShowInfo {
    fragment_path: Option<String>,
    load_state: Option<String>,
}

/// 解析 `systemctl show -p FragmentPath -p LoadState` 的 `key=value` 输出。
fn parse_unit_show(stdout: &[u8], unit: &str) -> Result<UnitShowInfo> {
    let text = std::str::from_utf8(stdout)
        .with_context(|| format!("systemctl show {unit} 返回的属性不是有效 UTF-8"))?;
    let mut info = UnitShowInfo::default();
    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("systemctl show {unit} 返回了无法解析的行: {line:?}");
        };
        match key {
            "FragmentPath" => info.fragment_path = Some(value.to_string()),
            "LoadState" => info.load_state = Some(value.to_string()),
            // 只请求了两个属性；其他行说明 systemd 行为异常，但忽略不会放大权限。
            _ => {}
        }
    }
    Ok(info)
}

/// stderr 是否明确表示 unit 不存在（而不是 D-Bus / 权限 / 其他故障）。
fn stderr_looks_like_not_found(stderr: &[u8]) -> bool {
    let lower = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    lower.contains("not-found")
        || lower.contains("not found")
        || lower.contains("could not be found")
}

/// 解释 `systemctl show` 结果；只有明确 not-found 才允许返回 `Ok(None)`。
///
/// 旧实现把所有非零退出都当成“unit 未加载”，D-Bus/权限错误也会让卸载走
/// “只删文件”的危险路径；这里必须区分明确不存在与其他失败。
fn fragment_path_from_show(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    unit: &str,
) -> Result<Option<PathBuf>> {
    // 即使 systemctl 非零退出，部分旧版本仍会在 stdout 输出 LoadState=not-found；
    // 解析失败时不要用输出错误覆盖原始失败信息。
    let parsed = parse_unit_show(stdout, unit).ok();
    if parsed.as_ref().and_then(|info| info.load_state.as_deref()) == Some("not-found") {
        return Ok(None);
    }
    if !success {
        if stderr_looks_like_not_found(stderr) {
            return Ok(None);
        }
        let stderr = String::from_utf8_lossy(stderr);
        let detail = stderr.trim();
        bail!(
            "systemctl show {unit} 失败（不是明确的 not-found；拒绝当作 unit 不存在）: {}",
            if detail.is_empty() {
                "<无 stderr>"
            } else {
                detail
            }
        );
    }
    let info = parsed
        .ok_or_else(|| anyhow::anyhow!("systemctl show {unit} 输出无法解析，拒绝猜测 unit 状态"))?;
    match info.fragment_path.as_deref() {
        None | Some("") => Ok(None),
        Some(path) => parse_fragment_path(path.as_bytes(), unit),
    }
}

fn parse_fragment_path(stdout: &[u8], unit: &str) -> Result<Option<PathBuf>> {
    let text = std::str::from_utf8(stdout)
        .with_context(|| format!("systemctl show {unit} 返回的 FragmentPath 不是有效 UTF-8"))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Some(ch) = trimmed.chars().find(|ch| ch.is_control()) {
        bail!("systemctl show {unit} 返回的 FragmentPath 含控制字符 {ch:?}，拒绝使用: {trimmed:?}");
    }
    normalize_absolute(Path::new(trimmed), "systemd unit 实际路径").map(Some)
}

/// 比较 systemd 实际解析的 unit 与期望路径；不一致或未解析都必须拒绝。
fn ensure_fragment_matches(unit: &str, expected: &Path, actual: Option<&Path>) -> Result<()> {
    if actual == Some(expected) {
        return Ok(());
    }
    let actual = match actual {
        Some(path) => path.display().to_string(),
        None => format!("<未解析：{unit} 的 FragmentPath 为空>"),
    };
    bail!(
        "systemd 实际解析的 unit 是 {actual}，不是 {}；拒绝操作同名外来/更高优先级 unit",
        expected.display()
    );
}

/// 等待 URL 返回 HTTP 200。
///
/// 只接受 `http://`；最多等待 30 秒（调用方传更长也会截断），每 1 秒尝试一次。
/// 连接失败、超时、非 200 都继续重试，最后返回带最后一次错误的原因。
pub fn wait_http_ok(url: &str, timeout: Duration) -> Result<()> {
    let target = HttpTarget::parse(url)?;
    let timeout = timeout.min(Duration::from_secs(30));
    let deadline = Instant::now() + timeout;
    let last_error = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt_timeout = if remaining.is_zero() {
            Duration::from_millis(1)
        } else {
            remaining.min(Duration::from_secs(5))
        };
        match probe_http(&target, attempt_timeout) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let now = Instant::now();
                if now >= deadline {
                    break format!("{err:#}");
                }
                std::thread::sleep(Duration::from_secs(1).min(deadline - now));
            }
        }
    };
    bail!(
        "等待 {url} 返回 HTTP 200 超时（上限 {:.1}s），最后一次错误: {last_error}",
        timeout.as_secs_f64()
    )
}

#[derive(Debug)]
struct HttpTarget {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

impl HttpTarget {
    fn parse(url: &str) -> Result<Self> {
        let rest = url
            .strip_prefix("http://")
            .ok_or_else(|| anyhow::anyhow!("wait_http_ok 只支持 http:// URL: {url}"))?;
        if rest.is_empty() {
            bail!("URL 缺少主机名: {url}");
        }
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            bail!("URL 缺少主机名: {url}");
        }
        if authority.contains('@') {
            bail!("URL 不允许包含 userinfo: {url}");
        }
        if path.chars().any(|ch| ch.is_control() || ch == ' ') || !path.starts_with('/') {
            bail!("URL 路径非法: {url}");
        }
        if path.contains('#') {
            bail!("URL 不允许包含 fragment: {url}");
        }

        let (host, port) =
            parse_authority(authority).with_context(|| format!("解析 URL 主机失败: {url}"))?;
        if host.is_empty() {
            bail!("URL 缺少主机名: {url}");
        }
        if host
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, '/' | '?' | '#'))
        {
            bail!("URL 主机名非法: {url}");
        }
        Ok(Self {
            host,
            port,
            authority: authority.to_string(),
            path: path.to_string(),
        })
    }
}

fn parse_authority(authority: &str) -> Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow::anyhow!("IPv6 地址缺少 ]"))?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            80
        } else {
            let port_text = after
                .strip_prefix(':')
                .ok_or_else(|| anyhow::anyhow!("IPv6 地址后的端口格式错误"))?;
            parse_port(port_text)?
        };
        return Ok((host, port));
    }
    if authority.matches(':').count() > 1 {
        bail!("IPv6 地址必须使用方括号");
    }
    match authority.rsplit_once(':') {
        Some((host, port_text)) if !host.is_empty() => {
            Ok((host.to_string(), parse_port(port_text)?))
        }
        Some(_) => bail!("缺少主机名"),
        None => Ok((authority.to_string(), 80)),
    }
}

fn parse_port(text: &str) -> Result<u16> {
    let port = text
        .parse::<u16>()
        .with_context(|| format!("端口不是合法数字: {text:?}"))?;
    if port == 0 {
        bail!("端口不能为 0");
    }
    Ok(port)
}

fn probe_http(target: &HttpTarget, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout.max(Duration::from_millis(1));
    let addrs: Vec<SocketAddr> = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .with_context(|| format!("解析主机 {} 失败", target.host))?
        .collect();
    if addrs.is_empty() {
        bail!("主机 {} 没有可用地址", target.host);
    }

    let mut last_error: Option<anyhow::Error> = None;
    for addr in addrs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let connect_timeout = remaining.min(Duration::from_secs(2));
        match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(stream) => {
                let read_timeout = deadline
                    .saturating_duration_since(Instant::now())
                    .max(Duration::from_millis(1));
                let _ = stream.set_read_timeout(Some(read_timeout));
                let _ = stream.set_write_timeout(Some(read_timeout));
                match send_and_check_status(stream, target) {
                    Ok(()) => return Ok(()),
                    Err(err) => last_error = Some(err),
                }
            }
            Err(err) => {
                last_error = Some(anyhow::Error::new(err).context(format!("连接 {addr} 失败")));
            }
        }
    }
    match last_error {
        Some(err) => Err(err),
        None => bail!("等待 {}:{} 超时", target.host, target.port),
    }
}

fn send_and_check_status(mut stream: TcpStream, target: &HttpTarget) -> Result<()> {
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\nUser-Agent: rustboard-install/{}\r\n\r\n",
        target.path,
        target.authority,
        env!("CARGO_PKG_VERSION")
    );
    // 某些服务端会在读完请求前就返回并关闭；写失败时仍然尝试读响应。
    let _ = stream.write_all(request.as_bytes());
    let _ = stream.flush();
    let reader = BufReader::new(stream);
    let mut status_line = String::new();
    // 状态行最多 4 KiB：对端可以返回畸形超长首行，不能让安装器无限读内存。
    reader
        .take(4096)
        .read_line(&mut status_line)
        .context("读取 HTTP 状态行失败")?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok());
    if status == Some(200) {
        Ok(())
    } else {
        bail!("HTTP 状态不是 200: {:?}", status_line.trim());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_arg_quotes_only_when_needed() {
        assert_eq!(shell_arg("rustboard-hub"), "rustboard-hub");
        assert_eq!(
            shell_arg("/etc/rustboard/hub.toml"),
            "/etc/rustboard/hub.toml"
        );
        assert_eq!(shell_arg("a b"), "'a b'");
        assert_eq!(shell_arg(""), "''");
        assert_eq!(shell_arg("a'b"), r"'a'\''b'");
        assert_eq!(shell_arg("$(id)"), "'$(id)'");
    }

    #[test]
    fn systemd_quote_handles_specials() {
        assert_eq!(systemd_quote("/usr/local/bin/x"), "/usr/local/bin/x");
        assert_eq!(systemd_quote("/tmp/a b"), r#""/tmp/a b""#);
        assert_eq!(systemd_quote("/tmp/a%b"), r#""/tmp/a%%b""#);
        assert_eq!(systemd_quote("/tmp/a$b"), r#""/tmp/a$$b""#);
    }

    #[test]
    fn parses_http_urls() {
        let target = HttpTarget::parse("http://127.0.0.1:8080/healthz").unwrap();
        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 8080);
        assert_eq!(target.path, "/healthz");
        let target = HttpTarget::parse("http://example.com").unwrap();
        assert_eq!(target.port, 80);
        assert_eq!(target.path, "/");
        assert!(HttpTarget::parse("https://example.com").is_err());
        assert!(HttpTarget::parse("http://user:pass@example.com/").is_err());
    }

    #[test]
    fn unit_names_reject_traversal() {
        assert!(validate_unit_name("rustboard-hub.service").is_ok());
        for name in ["", "../x.service", "a/b.service", ".", "-x.service", "a\nb"] {
            assert!(validate_unit_name(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn parse_fragment_path_accepts_single_absolute_path() {
        assert_eq!(
            parse_fragment_path(
                b"/etc/systemd/system/rustboard-hub.service\n",
                "rustboard-hub.service"
            )
            .unwrap(),
            Some(PathBuf::from("/etc/systemd/system/rustboard-hub.service"))
        );
        assert_eq!(
            parse_fragment_path(b"  /run/systemd/system/a.service  \n", "a.service").unwrap(),
            Some(PathBuf::from("/run/systemd/system/a.service"))
        );
        // 空输出表示 unit 未加载 / transient；交给 ensure_fragment_matches 拒绝。
        assert_eq!(parse_fragment_path(b"\n", "a.service").unwrap(), None);
        assert_eq!(parse_fragment_path(b"  \t\r\n", "a.service").unwrap(), None);
    }

    #[test]
    fn parse_fragment_path_rejects_malformed_output() {
        for stdout in [
            b"/etc/a.service\n/etc/b.service\n".as_slice(),
            b"relative/a.service".as_slice(),
            b"/etc/a\0b".as_slice(),
            b"/etc/a\x1bb".as_slice(),
            &[0xff, 0xfe][..],
        ] {
            assert!(
                parse_fragment_path(stdout, "a.service").is_err(),
                "{stdout:?} 应被拒绝"
            );
        }
    }

    #[test]
    fn ensure_fragment_matches_requires_exact_expected_path() {
        let expected = Path::new("/etc/systemd/system/rustboard-hub.service");
        ensure_fragment_matches("rustboard-hub.service", expected, Some(expected)).unwrap();

        // /etc/systemd/system 的同名 unit 优先级高于 /run/systemd/system，必须拒绝。
        let foreign = Path::new("/run/systemd/system/rustboard-hub.service");
        let err =
            ensure_fragment_matches("rustboard-hub.service", expected, Some(foreign)).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains(
                "systemd 实际解析的 unit 是 /run/systemd/system/rustboard-hub.service，\
                 不是 /etc/systemd/system/rustboard-hub.service"
            ),
            "{message}"
        );
        assert!(
            message.contains("拒绝操作同名外来/更高优先级 unit"),
            "{message}"
        );

        // transient / 未加载 unit 的 FragmentPath 为空，同样 fail-closed。
        let err = ensure_fragment_matches("rustboard-hub.service", expected, None).unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("FragmentPath 为空"), "{message}");
        assert!(
            message.contains("拒绝操作同名外来/更高优先级 unit"),
            "{message}"
        );
    }

    /// 卸载停止流程的 fake：只记录调用，不接触宿主 systemd。
    struct FakeService {
        stop_error: Option<&'static str>,
        disable_error: Option<&'static str>,
        state: ServiceState,
        state_error: Option<&'static str>,
        managing: bool,
        stop_calls: std::cell::Cell<usize>,
        disable_calls: std::cell::Cell<usize>,
    }

    impl FakeService {
        fn new() -> Self {
            Self {
                stop_error: None,
                disable_error: None,
                state: ServiceState::Inactive,
                state_error: None,
                managing: true,
                stop_calls: std::cell::Cell::new(0),
                disable_calls: std::cell::Cell::new(0),
            }
        }
    }

    impl ServiceControl for FakeService {
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
            self.managing
        }

        fn active_state(&self, _unit: &str) -> Result<ServiceState> {
            match self.state_error {
                Some(message) => bail!("{message}"),
                None => Ok(self.state.clone()),
            }
        }

        fn main_pid(&self, _unit: &str) -> Result<u32> {
            Ok(if self.state.is_active_or_starting() {
                4242
            } else {
                0
            })
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
                None => Ok(()),
            }
        }

        fn disable(&self, _unit: &str) -> Result<()> {
            self.disable_calls.set(self.disable_calls.get() + 1);
            match self.disable_error {
                Some(message) => bail!("{message}"),
                None => Ok(()),
            }
        }
    }

    #[test]
    fn service_state_classification_is_strict() {
        for state in ["inactive", "failed"] {
            assert!(ServiceState::parse(state).is_stopped(), "{state}");
            assert!(
                !ServiceState::parse(state).is_active_or_starting(),
                "{state}"
            );
        }
        for state in ["active", "activating", "reloading"] {
            assert!(!ServiceState::parse(state).is_stopped(), "{state}");
            assert!(
                ServiceState::parse(state).is_active_or_starting(),
                "{state}"
            );
        }
        for state in ["deactivating", "unknown", ""] {
            assert!(!ServiceState::parse(state).is_stopped(), "{state:?}");
            assert!(
                !ServiceState::parse(state).is_active_or_starting(),
                "{state:?}"
            );
        }
    }

    #[test]
    fn fragment_path_show_distinguishes_not_found_from_systemd_errors() {
        let unit = "rustboard-hub.service";
        // 明确 not-found：可以返回 None。
        assert_eq!(
            fragment_path_from_show(
                false,
                b"",
                b"Unit rustboard-hub.service could not be found.\n",
                unit
            )
            .unwrap(),
            None
        );
        assert_eq!(
            fragment_path_from_show(false, b"LoadState=not-found\n", b"", unit).unwrap(),
            None
        );
        // 其他非零（D-Bus / 权限 / 未知）必须 Err，不能当成未加载。
        for stderr in [
            b"Failed to connect to bus: Permission denied\n".as_slice(),
            b"Failed to connect to bus: No such file or directory\n".as_slice(),
            b"Some unexpected DBus failure\n".as_slice(),
            b"".as_slice(),
        ] {
            let error = fragment_path_from_show(false, b"", stderr, unit).unwrap_err();
            assert!(
                format!("{error:#}").contains("不是明确的 not-found"),
                "{error:#}"
            );
        }
        // 成功输出正常解析；空 FragmentPath 视为未解析。
        assert_eq!(
            fragment_path_from_show(
                true,
                b"FragmentPath=/etc/systemd/system/rustboard-hub.service\nLoadState=loaded\n",
                b"",
                unit
            )
            .unwrap(),
            Some(PathBuf::from("/etc/systemd/system/rustboard-hub.service"))
        );
        assert_eq!(
            fragment_path_from_show(true, b"FragmentPath=\nLoadState=loaded\n", b"", unit).unwrap(),
            None
        );
        assert!(fragment_path_from_show(true, b"not-a-property\n", b"", unit).is_err());
    }

    #[test]
    fn stop_failure_aborts_before_disable() {
        let mut service = FakeService::new();
        service.stop_error = Some("stop failed");
        // 服务在 stop 失败后可能仍在运行；必须直接报错，不能 disable。
        service.state = ServiceState::Active;
        let error = stop_service_checked(&service, "rustboard-hub.service", "hub").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("停止 hub 服务"), "{message}");
        assert!(message.contains("安装状态已保留"), "{message}");
        assert_eq!(service.stop_calls.get(), 1);
        assert_eq!(
            service.disable_calls.get(),
            0,
            "stop 失败后不得继续 disable"
        );
    }

    #[test]
    fn still_active_or_unknown_state_aborts_before_disable() {
        let mut service = FakeService::new();
        service.state = ServiceState::Active;
        let error = stop_service_checked(&service, "rustboard-agent.service", "agent").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("ActiveState=active"), "{message}");
        assert!(message.contains("未删除任何文件"), "{message}");
        assert_eq!(service.disable_calls.get(), 0);

        // activating / deactivating / reloading 都不能当成已停止。
        for state in [
            ServiceState::Activating,
            ServiceState::Deactivating,
            ServiceState::Reloading,
        ] {
            let mut service = FakeService::new();
            service.state = state.clone();
            let error =
                stop_service_checked(&service, "rustboard-panel.service", "panel").unwrap_err();
            assert!(
                format!("{error:#}").contains(state.as_str()),
                "{}: {error:#}",
                state.as_str()
            );
            assert_eq!(service.disable_calls.get(), 0);
        }

        let mut service = FakeService::new();
        service.state_error = Some("systemctl show ActiveState 执行失败");
        let error = stop_service_checked(&service, "rustboard-panel.service", "panel").unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("无法确认 panel 服务"), "{message}");
        assert!(message.contains("拒绝在状态未知时删除"), "{message}");
        assert_eq!(service.disable_calls.get(), 0);
    }

    #[test]
    fn no_op_manager_is_rejected() {
        let mut service = FakeService::new();
        service.managing = false;
        let error = stop_service_checked(&service, "rustboard-hub.service", "hub").unwrap_err();
        assert!(
            format!("{error:#}").contains("未启用 systemd 管理"),
            "{error:#}"
        );
        assert_eq!(service.stop_calls.get(), 0);
        assert_eq!(service.disable_calls.get(), 0);

        let error = ensure_service_stopped(&service, "rustboard-hub.service", "hub").unwrap_err();
        assert!(
            format!("{error:#}").contains("未启用 systemd 管理"),
            "{error:#}"
        );
    }

    #[test]
    fn ensure_service_stopped_rejects_running_and_unknown_states() {
        for state in [
            ServiceState::Active,
            ServiceState::Activating,
            ServiceState::Deactivating,
            ServiceState::Reloading,
        ] {
            let mut service = FakeService::new();
            service.state = state.clone();
            let error =
                ensure_service_stopped(&service, "rustboard-agent.service", "agent").unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains(state.as_str()), "{message}");
            assert!(message.contains("拒绝删除"), "{message}");
        }
        for state in [ServiceState::Inactive, ServiceState::Failed] {
            let mut service = FakeService::new();
            service.state = state;
            ensure_service_stopped(&service, "rustboard-agent.service", "agent").unwrap();
        }
        let mut service = FakeService::new();
        service.state_error = Some("mock query failure");
        let error =
            ensure_service_stopped(&service, "rustboard-agent.service", "agent").unwrap_err();
        assert!(format!("{error:#}").contains("拒绝删除"), "{error:#}");
    }

    #[test]
    fn remove_enable_symlink_only_removes_symlinks() {
        let unit_dir = std::env::temp_dir().join(format!(
            "rb-install-enable-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let wants = unit_dir.join("multi-user.target.wants");
        std::fs::create_dir_all(&wants).unwrap();
        let unit_name = format!("rustboard-test-{}.service", std::process::id());
        let target = unit_dir.join("rustboard-test.service");
        std::fs::write(&target, b"unit").unwrap();
        let link = wants.join(&unit_name);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        remove_enable_symlink(&unit_dir, &unit_name, &target).unwrap();
        assert!(!link.exists(), "wants 符号链接应被删除");
        assert!(target.exists(), "链接目标不能被删除");

        // 同名普通文件必须保留（不能把用户文件当链接删除）。
        std::fs::write(&link, b"keep").unwrap();
        remove_enable_symlink(&unit_dir, &unit_name, &target).unwrap();
        assert!(link.exists(), "同名普通文件不能被删除");

        // 同名外来 unit 的 wants 链接必须保留。
        let foreign = unit_dir.join("foreign.service");
        std::fs::write(&foreign, b"foreign unit").unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&foreign, &link).unwrap();
        remove_enable_symlink(&unit_dir, &unit_name, &target).unwrap();
        assert!(link.exists(), "链接目标不是本安装 unit 时必须保留");
        assert!(foreign.exists(), "外来 unit 不能被删除");

        // 悬空链接 / 本安装 unit 缺失：无法确认归属，保留链接。
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink("missing.service", &link).unwrap();
        remove_enable_symlink(&unit_dir, &unit_name, &target).unwrap();
        assert!(
            std::fs::symlink_metadata(&link).is_ok(),
            "悬空链接不能按名字删除"
        );
        std::fs::remove_file(&target).unwrap();
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&foreign, &link).unwrap();
        remove_enable_symlink(&unit_dir, &unit_name, &target).unwrap();
        assert!(link.exists(), "unit 缺失时不能按名字删除");
        let _ = std::fs::remove_dir_all(&unit_dir);
    }

    #[test]
    fn disable_failure_is_reported_but_does_not_fail_after_inactive() {
        let mut service = FakeService::new();
        service.disable_error = Some("disable failed");
        // stop 成功、已确认 inactive 时 disable 失败只影响自启，不阻塞文件清理。
        stop_service_checked(&service, "rustboard-hub.service", "hub").unwrap();
        assert_eq!(service.stop_calls.get(), 1);
        assert_eq!(service.disable_calls.get(), 1);
    }
}
