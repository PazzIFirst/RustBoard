//! systemd 管理、unit 渲染与 HTTP 健康检查。
//!
//! 所有外部命令都用 `Command::args([...])` 调用，不拼 shell；`manage=false` 或
//! `dry_run` 时不执行 systemctl。systemd 按 unit **名字**操作，同名 unit 的优先级
//! 与 transient unit 都可能让 `systemctl stop` 作用到不是我们写的服务；因此
//! stop / restart / enable 之前必须用 [`ServiceManager::ensure_fragment_is`]
//! 核对 systemd 实际解析的 `FragmentPath`。`wait_http_ok` 只支持明文 `http://`，
//! 不引入 reqwest。

use std::io::{BufRead, BufReader, Read, Write};
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

    /// 先 `systemctl stop` 再 `systemctl disable`。
    ///
    /// 卸载时必须在调用前用 [`Self::ensure_fragment_is`] 确认要停的是我们的 unit；
    /// 只检查 `paths.unit` 文件挡不住同名的更高优先级 unit 或 transient unit。
    pub fn stop_disable(&self, unit: &str) -> Result<()> {
        validate_unit_arg(unit)?;
        let stop = self.run_systemctl(&["stop", unit]);
        // stop 失败也继续 disable：卸载时不能因为服务本来没跑就留下自启项。
        let disable = self.run_systemctl(&["disable", unit]);
        stop.and(disable)
    }

    /// `systemctl is-active --quiet <unit>`；inactive / 不存在返回 `false`。
    pub fn is_active(&self, unit: &str) -> Result<bool> {
        validate_unit_arg(unit)?;
        if !self.manage || self.dry_run {
            return Ok(false);
        }
        let output = Command::new("systemctl")
            .args(["is-active", "--quiet", unit])
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("执行 systemctl is-active {unit} 失败"))?;
        Ok(output.status.success())
    }

    /// 查询 systemd 实际解析到的 unit 文件（`FragmentPath`）。
    ///
    /// 只看 `paths.unit` 文件是否存在并不够：systemd 按 unit **名字**操作，
    /// `/etc/systemd/system` 中同名 unit 的优先级高于 `/run/systemd/system`；
    /// 文件缺失的 transient unit 也可能 active 并被 stop。这里以 systemd 自己的
    /// 解析结果为准，调用方应使用 [`Self::ensure_fragment_is`] 拒绝同名外来 unit。
    ///
    /// 行为：
    /// - `manage=false` 或 `dry_run` 时不执行 systemctl，返回 `None`；
    /// - `systemctl show` 成功但值为空白（unit 未加载 / 不存在）返回 `None`；
    /// - `systemctl show` 非零退出（旧版本对 unit not found 返回非零）返回 `None`；
    /// - 无法启动 systemctl（例如 PATH 中没有）或输出畸形返回 `Err`。
    ///
    /// 返回路径已归一化，便于和 [`crate::Paths::unit`] 直接比较。安装流程应在
    /// 写完 unit 并 `daemon-reload` 后立即查询，此时 systemd 才能解析到新文件。
    pub fn fragment_path(&self, unit: &str) -> Result<Option<PathBuf>> {
        validate_unit_arg(unit)?;
        if !self.manage || self.dry_run {
            return Ok(None);
        }
        let output = Command::new("systemctl")
            .args(["show", unit, "-p", "FragmentPath", "--value"])
            .stdin(Stdio::null())
            .output()
            .with_context(|| {
                format!(
                    "执行 systemctl show {unit} -p FragmentPath --value 失败（systemctl 不存在或不可执行？）"
                )
            })?;
        // unit 不存在 / 未加载时不同 systemd 版本可能返回非零；统一按“未解析”处理，
        // 由 ensure_fragment_is 拒绝操作。
        if !output.status.success() {
            return Ok(None);
        }
        parse_fragment_path(&output.stdout, unit)
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
}
