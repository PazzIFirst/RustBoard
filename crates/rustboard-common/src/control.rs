//! M3 控制面线协议类型与配置校验工具。
//!
//! 与 [`crate::wire::Frame::ControlRequest`] / [`crate::wire::Frame::ControlResponse`]
//! 配套使用。协议版本仍为 2：控制帧只在已认证会话、能力协商之后出现，
//! 旧 hub / 旧 agent 不会发送也不会理解这些帧。
//!
//! 序列化使用**外部标签枚举**（`{"SystemdAction": {...}}`），与 [`crate::wire::Frame`]
//! 保持一致：MessagePack 不是自描述格式，rmp-serde 不支持 internally tagged。
//!
//! 安全约定：
//! - `Debug` 只输出变体名（请求额外输出 `id`），绝不打印命令输出、日志行或错误详情；
//! - 所有来自 hub 的字符串字段在使用前都必须过本模块的长度 / 字符校验。

use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Component, Path};

use crate::config::LogSourceKind;

// ---------------------------------------------------------------------------
// 能力常量
// ---------------------------------------------------------------------------

/// systemd unit 查看 / 启动 / 停止 / 重启。
pub const CAP_SYSTEMD: &str = "systemd";
/// Docker 容器查看 / 启动 / 停止 / 重启。
pub const CAP_DOCKER: &str = "docker";
/// 进程列表与结束。
pub const CAP_PROCESS: &str = "process";
/// 只读日志（文件 / journald）。
pub const CAP_LOGS: &str = "logs";

/// 全部已知能力，顺序与 [`crate::wire::AgentHello::capabilities`] 的输出一致。
pub const ALL_CAPABILITIES: [&str; 4] = [CAP_SYSTEMD, CAP_DOCKER, CAP_PROCESS, CAP_LOGS];

/// 是否是本版本已知的控制能力。
pub fn known_capability(capability: &str) -> bool {
    ALL_CAPABILITIES.contains(&capability)
}

// ---------------------------------------------------------------------------
// 长度与范围上限
// ---------------------------------------------------------------------------

/// unit / container / 日志来源 id 的最大长度（字节）。
pub const MAX_TARGET_LEN: usize = 128;
/// 进程名的最大长度（字节）。
pub const MAX_NAME_LEN: usize = 64;
/// 单个命令行字段的最大长度（字节）。
pub const MAX_CMDLINE_BYTES: usize = 4096;
/// 配置文件日志路径的最大长度（字节）。
pub const MAX_LOG_TARGET_BYTES: usize = 4096;
/// 单条日志行的最大长度（字节）。
pub const MAX_LOG_LINE_BYTES: usize = 4096;
/// 单次日志 tail 的最大行数。
pub const MAX_LOG_LINES: u32 = 2000;
/// 任意列表结果的最大条目数。
pub const MAX_LIST_ITEMS: usize = 512;
/// 进程列表结果的最大条目数。
pub const MAX_PROCESS_ITEMS: usize = 200;
/// 单条命令 stdout / stderr 各自的输出上限（字节）。
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024;
/// agent 发送控制应答前的编码后字节预算（比 hub 的 1 MiB WS 消息上限小 4 KiB）。
///
/// `LogSources` 等由配置驱动的结果可能远超 256 KiB；超过预算时 agent 必须回
/// 固定小错误，绝不能把超限帧发出去——hub 会因 `Message too long` 关闭整个
/// 会话，命令结果反而全部丢失。留 4 KiB 给 MessagePack / 传输层开销，并保证
/// `MAX_CONTROL_RESPONSE_BYTES < hub 的 MAX_WS_MESSAGE_SIZE`。
pub const MAX_CONTROL_RESPONSE_BYTES: usize = 1024 * 1024 - 4096;
/// 命令输出被截断时附加到 ActionOutput 的标记。
pub const TRUNCATED_MARKER: &str = "\n...[truncated]...\n";

/// agent 默认命令超时（秒）。
pub const DEFAULT_COMMAND_TIMEOUT_SECS: u64 = 10;
/// agent 命令超时下限（秒）。
pub const MIN_COMMAND_TIMEOUT_SECS: u64 = 1;
/// agent 命令超时上限（秒）。
pub const MAX_COMMAND_TIMEOUT_SECS: u64 = 60;
/// agent 默认单次日志最大行数。
pub const DEFAULT_MAX_LOG_LINES: u32 = 500;
/// agent 单次日志最大行数下限。
pub const MIN_MAX_LOG_LINES: u32 = 1;
/// agent 单次日志最大行数上限（与 [`MAX_LOG_LINES`] 一致）。
pub const MAX_MAX_LOG_LINES: u32 = MAX_LOG_LINES;

/// hub 默认控制请求超时（毫秒）。
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 15_000;
/// hub 控制请求超时下限（毫秒）。
pub const MIN_REQUEST_TIMEOUT_MS: u64 = 1_000;
/// hub 控制请求超时上限（毫秒）。
pub const MAX_REQUEST_TIMEOUT_MS: u64 = 60_000;
/// hub 每个会话默认待处理控制命令上限。
pub const DEFAULT_MAX_PENDING_PER_SESSION: usize = 32;
/// hub 每个会话待处理控制命令下限。
pub const MIN_MAX_PENDING_PER_SESSION: usize = 1;
/// hub 每个会话待处理控制命令上限。
pub const MAX_MAX_PENDING_PER_SESSION: usize = 128;
/// hub 默认允许的最大控制输出字节数。
pub const DEFAULT_MAX_CONTROL_OUTPUT_BYTES: usize = 262_144;
/// hub 允许的最大控制输出字节数下限。
pub const MIN_MAX_CONTROL_OUTPUT_BYTES: usize = 1024;
/// hub 允许的最大控制输出字节数上限。
pub const MAX_MAX_CONTROL_OUTPUT_BYTES: usize = 1_048_576;

// ---------------------------------------------------------------------------
// 线协议类型
// ---------------------------------------------------------------------------

/// hub → agent：一次控制请求。
///
/// `id` 由 hub 在会话内单调递增分配，只用于匹配请求与应答，不跨会话复用。
///
/// 手写 `Debug`：只输出 `id` 与操作变体名，避免目标 / 参数进入日志。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlRequest {
    pub id: u64,
    pub op: ControlOp,
}

impl ControlRequest {
    pub fn new(id: u64, op: ControlOp) -> Self {
        Self { id, op }
    }
}

/// 支持的控制操作。动作枚举固定，agent 不接受任意命令字符串。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlOp {
    SystemdList,
    SystemdAction {
        unit: String,
        action: SystemdAction,
    },
    DockerList,
    DockerAction {
        container: String,
        action: DockerAction,
    },
    ProcessList,
    ProcessKill {
        pid: u32,
        name: String,
        signal: KillSignal,
    },
    LogList,
    LogTail {
        source: String,
        lines: u32,
    },
}

impl ControlOp {
    /// 变体名，用于日志；不包含任何字段值。
    pub fn kind(&self) -> &'static str {
        match self {
            ControlOp::SystemdList => "SystemdList",
            ControlOp::SystemdAction { .. } => "SystemdAction",
            ControlOp::DockerList => "DockerList",
            ControlOp::DockerAction { .. } => "DockerAction",
            ControlOp::ProcessList => "ProcessList",
            ControlOp::ProcessKill { .. } => "ProcessKill",
            ControlOp::LogList => "LogList",
            ControlOp::LogTail { .. } => "LogTail",
        }
    }

    /// 该操作所属的能力名，与 [`ALL_CAPABILITIES`] / Hello capabilities 一致。
    ///
    /// hub 侧鉴权与审计直接使用，避免两边各自维护字符串映射。
    pub fn capability(&self) -> &'static str {
        match self {
            ControlOp::SystemdList | ControlOp::SystemdAction { .. } => CAP_SYSTEMD,
            ControlOp::DockerList | ControlOp::DockerAction { .. } => CAP_DOCKER,
            ControlOp::ProcessList | ControlOp::ProcessKill { .. } => CAP_PROCESS,
            ControlOp::LogList | ControlOp::LogTail { .. } => CAP_LOGS,
        }
    }
}

/// systemd 允许的动作。只有这三个，`systemctl` 的其他子命令一律不可达。
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SystemdAction {
    Start,
    Stop,
    Restart,
}

impl SystemdAction {
    /// 对应 `systemctl` 子命令，也用于审计 / API 展示。
    pub fn as_str(&self) -> &'static str {
        match self {
            SystemdAction::Start => "start",
            SystemdAction::Stop => "stop",
            SystemdAction::Restart => "restart",
        }
    }
}

/// Docker 允许的动作。`exec` / `run` / `rm` 等不在枚举内。
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DockerAction {
    Start,
    Stop,
    Restart,
}

impl DockerAction {
    /// 对应 `docker` 子命令，也用于审计 / API 展示。
    pub fn as_str(&self) -> &'static str {
        match self {
            DockerAction::Start => "start",
            DockerAction::Stop => "stop",
            DockerAction::Restart => "restart",
        }
    }
}

/// 进程结束允许的信号。
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KillSignal {
    Term,
    Kill,
}

impl KillSignal {
    /// 对应信号名（不含 `SIG` 前缀），用于审计 / API 展示。
    pub fn as_str(&self) -> &'static str {
        match self {
            KillSignal::Term => "term",
            KillSignal::Kill => "kill",
        }
    }
}

/// agent → hub：控制请求的应答。`result` 与 `error` 恰好有一个非空。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlResponse {
    pub id: u64,
    pub result: Option<ControlResult>,
    pub error: Option<ControlError>,
}

impl ControlResponse {
    pub fn success(id: u64, result: ControlResult) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(id: u64, error: ControlError) -> Self {
        Self {
            id,
            result: None,
            error: Some(error),
        }
    }
}

/// 控制操作成功时的结果。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlResult {
    SystemdUnits(Vec<SystemdUnit>),
    DockerContainers(Vec<DockerContainer>),
    Processes(Vec<ProcessInfo>),
    LogSources(Vec<LogSourceInfo>),
    LogLines {
        source: String,
        lines: Vec<String>,
        truncated: bool,
        /// 文件日志为文件总字节数；journal 为 journalctl 输出字节数。
        size_bytes: u64,
    },
    ActionOutput {
        stdout: String,
        stderr: String,
        exit_code: Option<i32>,
    },
}

impl ControlResult {
    /// 变体名，用于日志；不包含命令输出或日志内容。
    pub fn kind(&self) -> &'static str {
        match self {
            ControlResult::SystemdUnits(_) => "SystemdUnits",
            ControlResult::DockerContainers(_) => "DockerContainers",
            ControlResult::Processes(_) => "Processes",
            ControlResult::LogSources(_) => "LogSources",
            ControlResult::LogLines { .. } => "LogLines",
            ControlResult::ActionOutput { .. } => "ActionOutput",
        }
    }
}

/// 控制操作失败时的错误。`code` 取 [`codes`] 中的固定值。
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

impl ControlError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    /// 总开关或单项能力未启用。
    pub fn capability_disabled() -> Self {
        Self::new(codes::CAPABILITY_DISABLED, "控制能力未启用")
    }

    /// 目标不在白名单内（含禁止项）。
    pub fn not_whitelisted(message: impl Into<String>) -> Self {
        Self::new(codes::NOT_WHITELISTED, message)
    }

    /// 参数非法（超长、空值、范围越界、路径不合法等）。
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(codes::INVALID_REQUEST, message)
    }

    /// 执行失败（工具缺失、启动失败、超时、非零退出、系统调用失败等）。
    pub fn control_failed(message: impl Into<String>) -> Self {
        Self::new(codes::CONTROL_FAILED, message)
    }

    /// 本 agent 不支持该操作。
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(codes::UNSUPPORTED, message)
    }

    /// agent 正在续签证书，暂时不能执行控制动作（固定文案，可提示稍后重试）。
    pub fn busy_renewing() -> Self {
        Self::new(codes::BUSY_RENEWING, "agent 正在续签证书，请稍后重试")
    }

    /// 控制结果超过单帧预算：动作可能已经执行，只是结果无法完整回传。
    pub fn result_too_large() -> Self {
        Self::new(
            codes::RESULT_TOO_LARGE,
            "控制结果过大，动作可能已执行，请核对状态",
        )
    }
}

/// 错误码常量，避免字符串散落在 agent / hub 两侧。
pub mod codes {
    pub const CAPABILITY_DISABLED: &str = "capability_disabled";
    pub const NOT_WHITELISTED: &str = "not_whitelisted";
    pub const INVALID_REQUEST: &str = "invalid_request";
    pub const CONTROL_FAILED: &str = "control_failed";
    pub const UNSUPPORTED: &str = "unsupported";
    /// agent 证书续签等待期间收到的控制请求：不执行动作，明确要求稍后重试。
    pub const BUSY_RENEWING: &str = "busy_renewing";
    /// 控制结果编码后超过单帧预算：动作可能已执行，结果被丢弃。
    pub const RESULT_TOO_LARGE: &str = "control_result_too_large";
}

// ---------------------------------------------------------------------------
// 列表条目
// ---------------------------------------------------------------------------

/// 一个 systemd service unit。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemdUnit {
    /// 完整 unit 名，例如 `nginx.service`。
    pub unit: String,
    /// `systemctl` 的 LOAD 列。
    pub load: String,
    /// `systemctl` 的 ACTIVE 列。
    pub active: String,
    /// `systemctl` 的 SUB 列。
    pub sub: String,
    pub description: String,
}

/// 一个 Docker 容器。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DockerContainer {
    /// 容器名（不含前导 `/`）。
    pub name: String,
    pub image: String,
    /// `docker ps` 的 State 列（running / exited / ...）。
    pub state: String,
    /// `docker ps` 的 Status 列（自然语言描述）。
    pub status: String,
    /// 完整容器 ID（`--no-trunc`）。
    pub id: String,
}

/// 一个进程。`cmdline` 已把 NUL 分隔符替换为空格并限长。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub uid: u32,
    pub rss_kb: u64,
}

/// 一个已配置的日志来源。`target` 对 file 是绝对路径，对 journal 是 unit 名。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogSourceInfo {
    pub id: String,
    pub kind: LogSourceKind,
    pub target: String,
    pub name: String,
}

// ---------------------------------------------------------------------------
// Debug 脱敏
// ---------------------------------------------------------------------------

impl fmt::Debug for ControlRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 只输出 id 与操作变体名：unit / container / pid 等参数不进入日志。
        f.debug_struct("ControlRequest")
            .field("id", &self.id)
            .field("op", &self.op)
            .finish()
    }
}

impl fmt::Debug for ControlOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind())
    }
}

impl fmt::Debug for ControlResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 结果只打变体名，错误只打错误码；命令输出与错误详情可能含敏感信息。
        f.debug_struct("ControlResponse")
            .field("id", &self.id)
            .field("result", &self.result.as_ref().map(ControlResult::kind))
            .field(
                "error_code",
                &self.error.as_ref().map(|err| err.code.as_str()),
            )
            .finish()
    }
}

impl fmt::Debug for ControlResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.kind())
    }
}

impl fmt::Debug for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 错误码是固定枚举值；message 可能包含命令 stderr，绝不进日志。
        f.debug_struct("ControlError")
            .field("code", &self.code)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// 白名单 / 参数校验（config 与 agent 执行入口共用）
// ---------------------------------------------------------------------------

/// systemd 禁止操作的服务名（精确匹配，小写比较）。
///
/// `ssh.service` / `sshd.service` 是不同发行版对 OpenSSH 的命名；
/// 另外禁止 agent / hub 自身服务，防止控制面把自己管死。
const FORBIDDEN_UNITS: [&str; 3] = ["sshd", "sshd.service", "ssh.service"];

/// systemd 禁止操作的前缀（小写比较）。
const FORBIDDEN_UNIT_PREFIXES: [&str; 4] = ["rustboard-", "sd-", "systemd-", "dbus"];

/// 是否是禁止操作的 unit（禁止项优先于白名单）。
pub fn is_forbidden_unit(unit: &str) -> bool {
    let lower = unit.to_ascii_lowercase();
    FORBIDDEN_UNITS.contains(&lower.as_str())
        || FORBIDDEN_UNIT_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

/// unit / 容器名前缀里允许出现的字符（systemd 允许 `@`、`:` 与转义用的 `\`）。
fn target_chars_are_safe(value: &str) -> bool {
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '@' | ':' | '\\'))
}

/// 校验请求里的精确 unit 名（不含通配符）。
pub fn validate_unit_name(unit: &str) -> Result<(), String> {
    if unit.is_empty() {
        return Err("unit 不能为空".into());
    }
    if unit.len() > MAX_TARGET_LEN {
        return Err(format!("unit 长度不能超过 {MAX_TARGET_LEN} 字节"));
    }
    if unit.contains('*') {
        return Err("请求的 unit 不能包含通配符".into());
    }
    if unit.starts_with('-') {
        return Err("unit 不能以 - 开头".into());
    }
    if unit.contains("..") {
        return Err("unit 不能包含 ..".into());
    }
    if !target_chars_are_safe(unit) {
        return Err("unit 含非法字符（空白、控制字符或路径分隔符）".into());
    }
    Ok(())
}

/// 校验配置里的 unit 白名单项：精确名或尾部 `*` 前缀。
///
/// 禁止项优先：`sshd`、`rustboard-*`、`sd-*`、`systemd-*`、`dbus*` 不允许出现在白名单里。
pub fn validate_unit_pattern(pattern: &str) -> Result<(), String> {
    let prefix = pattern.strip_suffix('*').unwrap_or(pattern);
    if prefix.is_empty() {
        return Err("通配白名单不能是裸 *，必须写出前缀（例如 nginx*）".into());
    }
    if pattern.len() > MAX_TARGET_LEN {
        return Err(format!("unit 白名单长度不能超过 {MAX_TARGET_LEN} 字节"));
    }
    if prefix.starts_with('-') {
        return Err("unit 白名单不能以 - 开头".into());
    }
    if prefix.contains("..") {
        return Err("unit 白名单不能包含 ..".into());
    }
    if !target_chars_are_safe(prefix) {
        return Err("unit 白名单含非法字符（空白、控制字符或路径分隔符）".into());
    }
    if is_forbidden_unit(prefix) {
        return Err(format!("禁止操作系统服务: {prefix}"));
    }
    Ok(())
}

/// 请求 unit 是否命中白名单（精确或尾部 `*` 前缀）。**不**检查禁止项。
pub fn unit_matches_whitelist(unit: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => !prefix.is_empty() && unit.starts_with(prefix),
            None => pattern == unit,
        })
}

/// 请求 unit 是否允许操作：禁止项优先，其次必须命中白名单。
pub fn unit_allowed(unit: &str, patterns: &[String]) -> bool {
    !is_forbidden_unit(unit) && unit_matches_whitelist(unit, patterns)
}

/// 校验精确容器名：`[a-zA-Z0-9][a-zA-Z0-9_.-]*`。
pub fn validate_container_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("容器名不能为空".into());
    }
    if name.len() > MAX_TARGET_LEN {
        return Err(format!("容器名长度不能超过 {MAX_TARGET_LEN} 字节"));
    }
    if name.contains('*') {
        return Err("请求的容器名不能包含通配符".into());
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err("容器名不能为空".into());
    };
    if !first.is_ascii_alphanumeric() {
        return Err("容器名必须以字母或数字开头".into());
    }
    if !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')) {
        return Err("容器名只允许 [a-zA-Z0-9_.-]".into());
    }
    Ok(())
}

/// 校验配置里的容器白名单项：精确名或尾部 `*` 前缀。
pub fn validate_container_pattern(pattern: &str) -> Result<(), String> {
    let prefix = pattern.strip_suffix('*').unwrap_or(pattern);
    if prefix.is_empty() {
        return Err("容器通配白名单不能是裸 *，必须写出前缀（例如 web-*）".into());
    }
    if pattern.len() > MAX_TARGET_LEN {
        return Err(format!("容器白名单长度不能超过 {MAX_TARGET_LEN} 字节"));
    }
    validate_container_name(prefix).map_err(|err| format!("容器白名单非法: {err}"))
}

/// 请求容器是否命中白名单（精确或尾部 `*` 前缀）。
pub fn container_matches_whitelist(name: &str, patterns: &[String]) -> bool {
    patterns
        .iter()
        .any(|pattern| match pattern.strip_suffix('*') {
            Some(prefix) => !prefix.is_empty() && name.starts_with(prefix),
            None => pattern == name,
        })
}

/// 校验日志来源 id：`[a-zA-Z0-9][a-zA-Z0-9_.-]*`，≤ 128 字节。
pub fn validate_source_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("日志来源 id 不能为空".into());
    }
    if id.len() > MAX_TARGET_LEN {
        return Err(format!("日志来源 id 不能超过 {MAX_TARGET_LEN} 字节"));
    }
    let mut chars = id.chars();
    let Some(first) = chars.next() else {
        return Err("日志来源 id 不能为空".into());
    };
    if !first.is_ascii_alphanumeric() {
        return Err("日志来源 id 必须以字母或数字开头".into());
    }
    if !chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')) {
        return Err("日志来源 id 只允许 [a-zA-Z0-9_.-]".into());
    }
    Ok(())
}

/// 校验文件日志 target：绝对路径、无 `..`、长度受限。
///
/// 父目录是否存在、是否符号链接属于启动时的 I/O 校验（见 agent `control::logs`）。
pub fn validate_log_file_target(target: &str) -> Result<(), String> {
    if target.is_empty() {
        return Err("文件日志 target 不能为空".into());
    }
    if target.len() > MAX_LOG_TARGET_BYTES {
        return Err(format!(
            "文件日志 target 不能超过 {MAX_LOG_TARGET_BYTES} 字节"
        ));
    }
    if target.contains('\0') {
        return Err("文件日志 target 不能包含 NUL".into());
    }
    let path = Path::new(target);
    if !path.is_absolute() {
        return Err("文件日志 target 必须是绝对路径".into());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("文件日志 target 不能包含 ..".into());
    }
    if path.file_name().is_none() {
        return Err("文件日志 target 必须指向一个文件".into());
    }
    if target.ends_with('/') {
        return Err("文件日志 target 不能以 / 结尾".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn capability_constants_are_known_and_stable() {
        assert_eq!(ALL_CAPABILITIES, ["systemd", "docker", "process", "logs"]);
        for capability in ALL_CAPABILITIES {
            assert!(known_capability(capability), "{capability} 应被识别");
        }
        for unknown in ["", "shell", "terminal", "SYSTEMD", "logs "] {
            assert!(!known_capability(unknown), "{unknown:?} 不应被识别");
        }
    }

    #[test]
    fn forbidden_units_win_over_whitelist() {
        for unit in [
            "sshd",
            "sshd.service",
            "ssh.service",
            "rustboard-agent.service",
            "rustboard-hub",
            "sd-agent",
            "sd-hub",
            "systemd-journald.service",
            "dbus.service",
            "dbus-broker.service",
            "SSHD",
        ] {
            assert!(is_forbidden_unit(unit), "{unit} 必须被禁止");
            let patterns = owned(&["*", "sshd*", "rustboard-*", "dbus*"]);
            assert!(
                !unit_allowed(unit, &patterns),
                "{unit} 即使命中白名单也必须被禁止"
            );
        }
        for unit in ["nginx.service", "web-1", "redis", "postgresql.service"] {
            assert!(!is_forbidden_unit(unit), "{unit} 不应被禁止");
        }
    }

    #[test]
    fn unit_whitelist_supports_exact_and_prefix() {
        let patterns = owned(&["nginx*", "redis.service"]);
        for unit in [
            "nginx.service",
            "nginx@blue.service",
            "redis.service",
            "redis",
            "nginx",
        ] {
            if unit == "redis" {
                // 精确项 `redis.service` 不匹配 `redis`，前缀项 `nginx*` 也不匹配。
                assert!(!unit_matches_whitelist(unit, &patterns));
            } else {
                assert!(
                    unit_matches_whitelist(unit, &patterns),
                    "{unit} 应命中白名单"
                );
            }
        }
        assert!(!unit_matches_whitelist("postgresql.service", &patterns));
    }

    #[test]
    fn unit_pattern_validation_rejects_unsafe_entries() {
        for valid in ["nginx*", "nginx.service", "my-app@blue.service", "redis"] {
            validate_unit_pattern(valid).unwrap_or_else(|err| panic!("{valid} 应合法: {err}"));
        }
        for invalid in [
            "",
            "*",
            "-nginx",
            "nginx service",
            "nginx\nservice",
            "nginx/../service",
            "nginx..service",
            "sshd",
            "ssh.service",
            "rustboard-*",
            "systemd-*",
            "dbus*",
            "sd-agent",
        ] {
            assert!(
                validate_unit_pattern(invalid).is_err(),
                "{invalid:?} 必须被拒绝"
            );
        }
        let too_long = format!("{}*", "a".repeat(MAX_TARGET_LEN));
        assert!(validate_unit_pattern(&too_long).is_err());
    }

    #[test]
    fn unit_request_validation_requires_exact_safe_name() {
        validate_unit_name("nginx.service").unwrap();
        for invalid in [
            "",
            "*",
            "nginx*",
            "-nginx",
            "nginx service",
            "nginx\tservice",
            "nginx/../service",
            "nginx..service",
            "nginx.service/",
        ] {
            assert!(
                validate_unit_name(invalid).is_err(),
                "{invalid:?} 必须被拒绝"
            );
        }
        assert!(validate_unit_name(&"a".repeat(MAX_TARGET_LEN + 1)).is_err());
    }

    #[test]
    fn container_names_follow_docker_charset() {
        for valid in ["web-1", "web_1", "web.1", "a", "A1"] {
            validate_container_name(valid).unwrap_or_else(|err| panic!("{valid} 应合法: {err}"));
        }
        for invalid in [
            "", "-web1", "_web1", ".web1", "web/1", "web 1", "web*", "web\n1",
        ] {
            assert!(
                validate_container_name(invalid).is_err(),
                "{invalid:?} 必须被拒绝"
            );
        }
        assert!(validate_container_name(&"a".repeat(MAX_TARGET_LEN + 1)).is_err());
    }

    #[test]
    fn container_whitelist_supports_prefix_and_rejects_bare_star() {
        let patterns = owned(&["web-*", "db"]);
        assert!(container_matches_whitelist("web-1", &patterns));
        assert!(container_matches_whitelist("db", &patterns));
        assert!(!container_matches_whitelist("db-1", &patterns));
        assert!(!container_matches_whitelist("web", &patterns));

        for valid in ["web-*", "web-1", "web_"] {
            validate_container_pattern(valid).unwrap();
        }
        for invalid in ["", "*", "-web*", "web/*", "web *"] {
            assert!(
                validate_container_pattern(invalid).is_err(),
                "{invalid:?} 必须被拒绝"
            );
        }
    }

    #[test]
    fn source_id_validation_matches_config_expectations() {
        for valid in ["nginx-error", "app.log", "a", "logs_1"] {
            validate_source_id(valid).unwrap_or_else(|err| panic!("{valid} 应合法: {err}"));
        }
        for invalid in ["", "-nginx", ".nginx", "nginx/error", "nginx error", "日志"] {
            assert!(
                validate_source_id(invalid).is_err(),
                "{invalid:?} 必须被拒绝"
            );
        }
    }

    #[test]
    fn log_file_target_must_be_absolute_and_clean() {
        for valid in ["/var/log/nginx/error.log", "/tmp/a", "/x.y"] {
            validate_log_file_target(valid).unwrap();
        }
        for invalid in [
            "",
            "var/log/nginx/error.log",
            "/var/log/../etc/shadow",
            "/var/log/",
            "/",
            "/var/log/a\0b",
        ] {
            assert!(
                validate_log_file_target(invalid).is_err(),
                "{invalid:?} 必须被拒绝"
            );
        }
        assert!(
            validate_log_file_target(&format!("/{}", "a".repeat(MAX_LOG_TARGET_BYTES))).is_err()
        );
    }

    #[test]
    fn response_constructors_keep_result_and_error_exclusive() {
        let ok = ControlResponse::success(1, ControlResult::Processes(Vec::new()));
        assert!(ok.error.is_none());
        assert!(ok.result.is_some());

        let err = ControlResponse::failure(2, ControlError::invalid_request("bad"));
        assert!(err.result.is_none());
        assert_eq!(err.error.as_ref().unwrap().code, codes::INVALID_REQUEST);
    }

    /// #16：续签期间固定错误码与文案必须稳定（hub 按码映射 503）。
    #[test]
    fn busy_renewing_has_stable_code_and_message() {
        let error = ControlError::busy_renewing();
        assert_eq!(error.code, codes::BUSY_RENEWING);
        assert_eq!(error.code, "busy_renewing");
        assert_eq!(error.message, "agent 正在续签证书，请稍后重试");
    }

    /// 控制结果过大：动作可能已执行，固定错误码 / 文案必须稳定（hub 按码映射 502）。
    #[test]
    fn result_too_large_has_stable_code_and_message() {
        let error = ControlError::result_too_large();
        assert_eq!(error.code, codes::RESULT_TOO_LARGE);
        assert_eq!(error.code, "control_result_too_large");
        assert_eq!(error.message, "控制结果过大，动作可能已执行，请核对状态");
    }
}
