//! M3 控制面：会话内待处理表、管理 API（控制 / 审计）。
//!
//! 分层：
//! - [`ControlSession`] 属于**单条 agent 会话**，持有 `id -> oneshot` 待处理表；
//!   管理 API 只把 [`ControlCommand`] 投进该会话的 mpsc，再由会话循环负责
//!   分配 id 并写 `Frame::ControlRequest`。这样同一个会话里 id 单调递增，
//!   应答匹配不需要任何全局锁。
//! - 管理 API 只做鉴权后的策略校验（总开关 / 单项能力 / agent 上报能力 /
//!   在线状态 / 参数范围），白名单由 agent 执行入口再次校验（纵深防御）。
//! - 所有 POST 都写审计；GET 不写。审计失败只记日志，不影响已经执行的动作。
//!
//! 安全约定：
//! - 不回显 agent 的错误 `message`（可能包含命令 stderr），只按错误码映射固定文案；
//! - 审计 `params` 只含 target / pid / name / signal / lines，长度受限；
//! - 控制结果（列表 / 日志 / 命令输出）在 hub 侧按 `max_output_bytes` 截断，
//!   不信任 agent 自己声明的长度。

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::extract::rejection::JsonRejection;
use axum::extract::ws::WebSocket;
use axum::extract::{Path, RawQuery, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rustboard_common::config::{HubControlConfig, LogSourceKind};
use rustboard_common::control::{
    codes as control_codes, is_forbidden_unit, known_capability, validate_container_name,
    validate_source_id, validate_unit_name, ControlError, ControlOp, ControlRequest,
    ControlResponse, ControlResult, DockerAction, KillSignal, SystemdAction, ALL_CAPABILITIES,
    CAP_DOCKER, CAP_LOGS, CAP_PROCESS, CAP_SYSTEMD, MAX_CMDLINE_BYTES, MAX_LIST_ITEMS,
    MAX_LOG_LINES, MAX_LOG_LINE_BYTES, MAX_LOG_TARGET_BYTES, MAX_NAME_LEN, MAX_OUTPUT_BYTES,
    MAX_PROCESS_ITEMS, MAX_TARGET_LEN, TRUNCATED_MARKER,
};
use rustboard_common::util::now_ms;
use rustboard_common::wire::Frame;
use rustboard_core::storage::{AuditEntry, NewAuditEntry, Storage};
use serde_json::{json, Map, Value};
use tokio::sync::{mpsc, oneshot};
use tokio::time::timeout;

use crate::{is_valid_agent_id, validate_agent_path, ApiError, AppState};

/// 每条连接的控制命令队列容量。
///
/// 管理 API 自身限速 10 次/分钟，正常情况下远不会堆满；堆满时 `try_send`
/// 立即回 `too_many_pending`，绝不阻塞会话的采集 / ACK 路径。
pub const CONTROL_COMMAND_BUFFER: usize = 16;

/// 控制请求帧的写超时。
///
/// 普通帧沿用会话级 15s 写超时；控制帧很小，且写操作发生在会话 `select!`
/// 分支里，超时越长越久阻塞 Ping / ACK 处理。这里用更短的 5s：超时即关闭会话，
/// 不会留下半帧状态。
const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// 会话内待处理命令的默认上限（配置层另有 1–128 的校验）。
const MIN_PENDING_LIMIT: usize = 1;
/// agent 上报能力的最大条数；超出部分直接忽略，避免恶意 Hello 撑爆存储。
const MAX_REPORTED_CAPABILITIES: usize = 16;
/// 审计参数 JSON 的最大字节数。
const MAX_AUDIT_PARAMS_BYTES: usize = 512;
/// 审计单列（capability / action / target）的最大字节数。
const MAX_AUDIT_LABEL_BYTES: usize = 128;
/// 审计错误信息的最大字节数。
const MAX_AUDIT_MESSAGE_BYTES: usize = 256;
/// 审计 API 单页上限。
const MAX_AUDIT_LIMIT: usize = 200;
/// 审计 API 默认单页条数。
const DEFAULT_AUDIT_LIMIT: usize = 100;
/// agent 能力过滤参数的最大长度。
const MAX_CAPABILITY_FILTER_BYTES: usize = 32;

/// hub 侧控制错误码（不在线协议错误码表里，只出现在管理 API / 审计中）。
pub mod hub_codes {
    pub const AGENT_OFFLINE: &str = "agent_offline";
    pub const CONTROL_TIMEOUT: &str = "control_timeout";
    pub const TOO_MANY_PENDING: &str = "too_many_pending";
    pub const INTERNAL: &str = "internal_error";
    pub const AGENT_NOT_FOUND: &str = "agent_not_found";
    pub const PAYLOAD_TOO_LARGE: &str = "payload_too_large";
}

/// 审计 `result` 取值，与面板 `auditResultClass` 的识别范围一致。
const AUDIT_OK: &str = "ok";
const AUDIT_DENIED: &str = "denied";
const AUDIT_ERROR: &str = "error";

/// 会话内待处理命令的应答通道。
type ControlReply = oneshot::Sender<std::result::Result<ControlResult, ControlError>>;

/// 一条待处理的控制请求：应答通道 + 本地超时 deadline。
struct PendingControl {
    reply: ControlReply,
    /// 会话内超时时间点；到点后由 [`ControlSession::expire`] 清理并回
    /// `control_timeout`，不依赖管理 API 的等待超时。
    deadline: Instant,
}

/// 管理 API → 会话任务的一条控制命令。
pub struct ControlCommand {
    pub op: ControlOp,
    pub reply: ControlReply,
}

/// 单个 agent 会话的控制状态。
pub struct ControlSession {
    /// 会话内单调递增；只用于匹配应答，不跨会话复用。
    next_id: u64,
    pending: HashMap<u64, PendingControl>,
    max_pending: usize,
    /// 每条控制请求从入表起允许等待的时长。
    request_timeout: Duration,
    /// 收到的未知 id 应答计数（陈旧 / 伪造应答），只用于排障。
    unknown_responses: u64,
}

impl ControlSession {
    pub fn new(max_pending: usize, request_timeout: Duration) -> Self {
        Self {
            next_id: 0,
            pending: HashMap::new(),
            max_pending: max_pending.max(MIN_PENDING_LIMIT),
            request_timeout,
            unknown_responses: 0,
        }
    }

    /// 分配 id 并登记待处理项，返回要发送给 agent 的请求。
    ///
    /// 超过上限时不发送任何帧，直接通过 `command.reply` 回 `too_many_pending`。
    fn enqueue(
        &mut self,
        command: ControlCommand,
    ) -> std::result::Result<ControlRequest, ControlError> {
        if self.pending.len() >= self.max_pending {
            let error = too_many_pending_error();
            let _ = command.reply.send(Err(error.clone()));
            return Err(error);
        }
        let ControlCommand { op, reply } = command;
        self.next_id = self.next_id.wrapping_add(1);
        if self.next_id == 0 {
            // 溢出回绕后跳过 0，保持 id 从 1 开始。
            self.next_id = 1;
        }
        let id = self.next_id;
        self.pending.insert(
            id,
            PendingControl {
                reply,
                deadline: Instant::now() + self.request_timeout,
            },
        );
        Ok(ControlRequest::new(id, op))
    }

    /// 清理所有已到期的 pending，向等待者回 `control_timeout`，返回清理数量。
    ///
    /// 先收集 id 再逐个移除，避免遍历 `pending` 时同时借用 `self` 发送 oneshot。
    /// 这是会话本地超时，不是 agent 的未知应答，因此**不**增加 `unknown_responses`。
    pub fn expire(&mut self, now: Instant) -> usize {
        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, pending)| pending.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            if let Some(pending) = self.pending.remove(id) {
                let _ = pending.reply.send(Err(ControlError::new(
                    hub_codes::CONTROL_TIMEOUT,
                    "控制请求超时",
                )));
            }
        }
        expired.len()
    }

    /// 登记并发送一条控制请求。
    ///
    /// 发送失败会移除刚登记的 pending 并返回错误，由会话循环统一走关闭流程；
    /// 等待中的 API 拿到 oneshot 取消信号后回 `agent_offline`。
    pub async fn dispatch(
        &mut self,
        socket: &mut WebSocket,
        command: ControlCommand,
    ) -> anyhow::Result<()> {
        let request = match self.enqueue(command) {
            Ok(request) => request,
            // 容量超限已经回复错误，会话继续正常工作。
            Err(_) => return Ok(()),
        };
        let id = request.id;
        let sent = tokio::time::timeout(
            CONTROL_WRITE_TIMEOUT,
            crate::send_frame(socket, &Frame::ControlRequest(request)),
        )
        .await;
        match sent {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                self.pending.remove(&id);
                Err(err)
            }
            Err(_) => {
                self.pending.remove(&id);
                anyhow::bail!(
                    "发送 ControlRequest 超时（{}s）",
                    CONTROL_WRITE_TIMEOUT.as_secs()
                )
            }
        }
    }

    /// 用 agent 的应答完成一个待处理请求；未知 id 丢弃并计数。
    pub fn complete(&mut self, response: ControlResponse) {
        let ControlResponse { id, result, error } = response;
        let Some(pending) = self.pending.remove(&id) else {
            self.unknown_responses = self.unknown_responses.saturating_add(1);
            tracing::debug!(id, "收到未知控制应答 id，已丢弃");
            return;
        };
        let outcome = match (result, error) {
            // 错误优先：result 与 error 同时存在时不能当成功处理。
            (_, Some(error)) => Err(error),
            (Some(result), None) => Ok(result),
            (None, None) => Err(ControlError::control_failed("agent 返回了空的控制应答")),
        };
        if pending.reply.send(outcome).is_err() {
            tracing::debug!(id, "控制应答无人等待（请求已超时或客户端断开）");
        }
    }

    /// 当前待处理命令数（测试与排障）。
    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// 未知 id 应答计数（测试与排障）。
    #[cfg(test)]
    fn unknown_responses(&self) -> u64 {
        self.unknown_responses
    }
}

impl Drop for ControlSession {
    fn drop(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        tracing::debug!(
            pending = self.pending.len(),
            "agent 会话结束，取消全部待处理控制请求"
        );
        for (_, pending) in self.pending.drain() {
            let _ = pending.reply.send(Err(agent_offline_error()));
        }
    }
}

fn agent_offline_error() -> ControlError {
    ControlError::new(hub_codes::AGENT_OFFLINE, "agent 不在线或会话已结束")
}

fn too_many_pending_error() -> ControlError {
    ControlError::new(
        hub_codes::TOO_MANY_PENDING,
        "待处理的控制命令过多，请稍后重试",
    )
}

/// 只保留本版本已知的能力，去重并限制条数；未知值只记数量，不落库也不打日志内容。
pub(crate) fn sanitize_agent_capabilities(reported: &[String]) -> Vec<String> {
    let mut accepted: Vec<String> = Vec::new();
    let mut unknown = 0usize;
    for capability in reported.iter().take(MAX_REPORTED_CAPABILITIES) {
        if !known_capability(capability) {
            unknown += 1;
            continue;
        }
        if accepted.iter().any(|item| item == capability) {
            continue;
        }
        accepted.push(capability.clone());
    }
    if unknown > 0 {
        tracing::warn!(unknown, "忽略 agent 上报的未知控制能力");
    }
    accepted
}

fn hub_capability_enabled(cfg: &HubControlConfig, capability: &str) -> bool {
    cfg.enabled
        && match capability {
            CAP_SYSTEMD => cfg.systemd,
            CAP_DOCKER => cfg.docker,
            CAP_PROCESS => cfg.process,
            CAP_LOGS => cfg.logs,
            _ => false,
        }
}

/// hub 配置中实际开启的能力，顺序固定为 systemd / docker / process / logs。
pub(crate) fn hub_enabled_capabilities(cfg: &HubControlConfig) -> Vec<String> {
    ALL_CAPABILITIES
        .iter()
        .filter(|capability| hub_capability_enabled(cfg, capability))
        .map(|capability| capability.to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// GET /api/v1/agents/{id}/control
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Serialize)]
pub(crate) struct ControlStatus {
    control_enabled: bool,
    online: bool,
    /// agent 最近一次 Hello 上报的能力。
    capabilities: Vec<String>,
    /// hub 配置中开启的能力。
    hub_capabilities: Vec<String>,
}

/// 能力状态：只读，不写审计。
///
/// 旧 agent 没有 `agent_control` 行但 `agents` 记录存在时返回 200 + 空能力
/// （面板据此显示「未启用」）；完全未知的 agent 返回 404。
pub(crate) async fn control_status(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> std::result::Result<Json<ControlStatus>, ApiError> {
    validate_agent_path(&agent_id)?;

    let record = tokio::task::spawn_blocking({
        let storage = state.storage.clone();
        let agent_id = agent_id.clone();
        move || storage.get_agent_control(&agent_id)
    })
    .await
    .map_err(ApiError::from)??;

    if record.is_none() {
        let exists = tokio::task::spawn_blocking({
            let storage = state.storage.clone();
            let agent_id = agent_id.clone();
            move || storage.get_agent(&agent_id)
        })
        .await
        .map_err(ApiError::from)??
        .is_some();
        if !exists {
            return Err(ApiError::not_found("agent 不存在"));
        }
    }

    let capabilities = record
        .map(|record| sanitize_agent_capabilities(&record.capabilities))
        .unwrap_or_default();
    Ok(Json(ControlStatus {
        control_enabled: state.cfg.control.enabled,
        online: state.sessions.has_active(&agent_id),
        capabilities,
        hub_capabilities: hub_enabled_capabilities(&state.cfg.control),
    }))
}

// ---------------------------------------------------------------------------
// POST /api/v1/agents/{id}/control
// ---------------------------------------------------------------------------

/// 控制请求体。`deny_unknown_fields`：拼错字段名直接 400，不静默忽略。
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlActionRequest {
    capability: String,
    action: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    signal: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    lines: Option<u32>,
    #[serde(default)]
    confirm: Option<bool>,
}

/// 通过本地校验、可以发给 agent 的操作。
#[derive(Debug)]
struct PreparedControl {
    capability: String,
    action: String,
    /// 审计 target 列：unit / 容器名 / 日志来源 id / 进程名。
    target: String,
    /// 审计 params（只含 target/pid/name/signal/lines）。
    params: String,
    op: ControlOp,
}

/// 本地拒绝：HTTP 状态 + 固定错误码 + 固定文案。
#[derive(Debug)]
struct Reject {
    status: StatusCode,
    code: &'static str,
    message: String,
    /// 审计 result（策略拒绝是 denied，服务端故障是 error）。
    audit_result: &'static str,
}

impl Reject {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: control_codes::INVALID_REQUEST,
            message: message.into(),
            audit_result: AUDIT_DENIED,
        }
    }

    fn disabled() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: control_codes::CAPABILITY_DISABLED,
            message: "该控制能力未启用".to_string(),
            audit_result: AUDIT_DENIED,
        }
    }

    fn not_whitelisted() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: control_codes::NOT_WHITELISTED,
            message: "目标不允许操作".to_string(),
            audit_result: AUDIT_DENIED,
        }
    }

    fn offline() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: hub_codes::AGENT_OFFLINE,
            message: "agent 不在线".to_string(),
            audit_result: AUDIT_ERROR,
        }
    }

    fn too_many_pending() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: hub_codes::TOO_MANY_PENDING,
            message: "待处理的控制命令过多，请稍后重试".to_string(),
            audit_result: AUDIT_ERROR,
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: hub_codes::INTERNAL,
            message: "内部错误，请稍后重试".to_string(),
            audit_result: AUDIT_ERROR,
        }
    }

    fn timeout() -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            code: hub_codes::CONTROL_TIMEOUT,
            message: "agent 未在限定时间内响应".to_string(),
            audit_result: AUDIT_ERROR,
        }
    }

    /// 与 `GET /control` 一致：完全未知的 agent 返回 404，而不是伪装成能力未开。
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: hub_codes::AGENT_NOT_FOUND,
            message: "agent 不存在".to_string(),
            audit_result: AUDIT_DENIED,
        }
    }

    fn payload_too_large() -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: hub_codes::PAYLOAD_TOO_LARGE,
            message: "请求体超过管理 API 的 64 KiB 上限".to_string(),
            audit_result: AUDIT_DENIED,
        }
    }
}

/// 控制请求的完整处理结果（成功或错误都带审计草稿）。
pub(crate) async fn control_action(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    body: std::result::Result<Json<ControlActionRequest>, JsonRejection>,
) -> Response {
    let started = Instant::now();
    // 非法 agent_id 不写进审计（避免污染过滤字段），但仍记录一次拒绝。
    let audit_agent = if is_valid_agent_id(&agent_id) && agent_id != "." && agent_id != ".." {
        agent_id.clone()
    } else {
        String::new()
    };
    let mut audit = AuditDraft::new(&audit_agent);

    if validate_agent_path(&agent_id).is_err() {
        return finish_error(&state, audit, started, &Reject::invalid("agent_id 非法")).await;
    }

    let payload = match body {
        Ok(Json(payload)) => payload,
        Err(rejection) => {
            // 超过 DefaultBodyLimit（64 KiB）时拒绝状态是 413；axum 0.8 没有
            // `JsonRejection::PayloadTooLarge` 变体，按 `status()` 区分即可。
            // 其余错误不回传 serde 原文：其中可能回显未知字段名。
            let reject = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                Reject::payload_too_large()
            } else {
                Reject::invalid("请求体不是合法 JSON 或包含未知字段")
            };
            return finish_error(&state, audit, started, &reject).await;
        }
    };
    audit.capability = clip_label(&payload.capability);
    audit.action = clip_label(&payload.action);
    audit.target = clip_label(
        payload
            .target
            .as_deref()
            .or(payload.source.as_deref())
            .or(payload.name.as_deref())
            .unwrap_or(""),
    );
    audit.params = build_audit_params(&payload);

    let prepared = match prepare_control(&payload, &state.cfg.control) {
        Ok(prepared) => prepared,
        Err(reject) => return finish_error(&state, audit, started, &reject).await,
    };
    audit.capability = prepared.capability.clone();
    audit.action = prepared.action.clone();
    audit.target = clip_label(&prepared.target);
    audit.params = prepared.params.clone();

    // agent 上报的能力：必须以 Hello 上报并落库的为准，hub 不替 agent 做主。
    let reported = tokio::task::spawn_blocking({
        let storage = state.storage.clone();
        let agent_id = agent_id.clone();
        move || storage.get_agent_control(&agent_id)
    })
    .await;
    let reported = match reported {
        Ok(Ok(reported)) => reported,
        Ok(Err(err)) => {
            tracing::error!(agent = %agent_id, error = %err, "读取 agent 控制能力失败");
            return finish_error(&state, audit, started, &Reject::internal()).await;
        }
        Err(err) => {
            tracing::error!(agent = %agent_id, error = %err, "读取 agent 控制能力任务失败");
            return finish_error(&state, audit, started, &Reject::internal()).await;
        }
    };
    let Some(record) = reported else {
        // 没有 agent_control 行：老 agent（agents 行存在）按能力未上报回 403；
        // 完全未知的 agent 与 GET /control 一致回 404。
        let exists = tokio::task::spawn_blocking({
            let storage = state.storage.clone();
            let agent_id = agent_id.clone();
            move || storage.get_agent(&agent_id)
        })
        .await;
        return match exists {
            Ok(Ok(Some(_))) => finish_error(&state, audit, started, &Reject::disabled()).await,
            Ok(Ok(None)) => finish_error(&state, audit, started, &Reject::not_found()).await,
            Ok(Err(err)) => {
                tracing::error!(agent = %agent_id, error = %err, "读取 agent 记录失败");
                finish_error(&state, audit, started, &Reject::internal()).await
            }
            Err(err) => {
                tracing::error!(agent = %agent_id, error = %err, "读取 agent 记录任务失败");
                finish_error(&state, audit, started, &Reject::internal()).await
            }
        };
    };
    if !record
        .capabilities
        .iter()
        .any(|capability| capability == &prepared.capability)
    {
        return finish_error(&state, audit, started, &Reject::disabled()).await;
    }

    // 在线判定以注册表为准：数据库里的 status 可能滞后于真实会话。
    let Some(sender) = state.sessions.control_sender(&agent_id) else {
        return finish_error(&state, audit, started, &Reject::offline()).await;
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    match sender.try_send(ControlCommand {
        op: prepared.op,
        reply: reply_tx,
    }) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(_)) => {
            return finish_error(&state, audit, started, &Reject::too_many_pending()).await;
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            // 注册表里还有这条连接，但接收端已经关闭：按离线处理。
            return finish_error(&state, audit, started, &Reject::offline()).await;
        }
    }

    let wait = Duration::from_millis(state.cfg.control.request_timeout_ms.max(1));
    match timeout(wait, reply_rx).await {
        Err(_) => {
            tracing::warn!(
                agent = %agent_id,
                capability = %audit.capability,
                action = %audit.action,
                timeout_ms = wait.as_millis() as u64,
                "控制请求超时"
            );
            return finish_error(&state, audit, started, &Reject::timeout()).await;
        }
        Ok(Err(_)) => {
            // oneshot 被丢弃：会话结束 / pending 被取消。
            return finish_error(&state, audit, started, &Reject::offline()).await;
        }
        Ok(Ok(Ok(result))) => {
            // 命令是否成功只看退出码：只有明确的 0 算成功；非 0 与被信号终止
            // （exit_code = None）都按失败记审计。响应仍保留 200 + 真实 exit_code
            // （前端按 exit_code 展示失败），审计只写固定文案，不回显 stderr。
            let value = control_result_json(&result, state.cfg.control.max_output_bytes);
            let duration = elapsed_ms(started);
            let entry = match command_exit(&result) {
                CommandExit::Success => audit.into_entry(AUDIT_OK, "", "", duration),
                CommandExit::NonZero(code) => {
                    tracing::warn!(
                        agent = %agent_id,
                        capability = %audit.capability,
                        action = %audit.action,
                        exit_code = code,
                        "控制命令退出码非 0"
                    );
                    audit.into_entry(
                        AUDIT_ERROR,
                        control_codes::CONTROL_FAILED,
                        "命令退出码非 0",
                        duration,
                    )
                }
                CommandExit::Signaled => {
                    tracing::warn!(
                        agent = %agent_id,
                        capability = %audit.capability,
                        action = %audit.action,
                        "控制命令被信号终止"
                    );
                    audit.into_entry(
                        AUDIT_ERROR,
                        control_codes::CONTROL_FAILED,
                        "命令被信号终止",
                        duration,
                    )
                }
            };
            record_audit(&state, entry).await;
            Json(json!({ "ok": true, "result": value })).into_response()
        }
        Ok(Ok(Err(error))) => {
            // 绝不回显 error.message：可能是命令 stderr / 路径等敏感内容。
            let reject = reject_from_agent_error(&error);
            finish_error(&state, audit, started, &reject).await
        }
    }
}

/// `ActionOutput` 的退出状态分类。
///
/// 只有明确的 `Some(0)` 算成功；非零退出码与被信号终止（`None`）都是失败。
/// 其他 `ControlResult` 变体不是命令执行结果，按成功处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandExit {
    Success,
    NonZero(i32),
    /// 进程被信号杀死：`ExitStatus::code()` 为 None。
    Signaled,
}

fn command_exit(result: &ControlResult) -> CommandExit {
    match result {
        ControlResult::ActionOutput { exit_code, .. } => match exit_code {
            Some(0) => CommandExit::Success,
            Some(code) => CommandExit::NonZero(*code),
            None => CommandExit::Signaled,
        },
        _ => CommandExit::Success,
    }
}

/// 把 agent 返回的错误码映射成 HTTP 状态与固定文案。
fn reject_from_agent_error(error: &ControlError) -> Reject {
    match error.code.as_str() {
        // 会话内 pending 表满（`ControlSession::enqueue`）与 mpsc 队列满走同一个
        // 错误码：对面板都是 429，不能落到 502。
        hub_codes::TOO_MANY_PENDING => Reject::too_many_pending(),
        // pending 期间 agent 断开 / 会话 Drop 会回这些 hub 侧错误码，
        // 必须保留原语义，不能因为不在 agent 错误表里就落 502。
        hub_codes::AGENT_OFFLINE => Reject::offline(),
        hub_codes::CONTROL_TIMEOUT => Reject::timeout(),
        hub_codes::INTERNAL => Reject::internal(),
        control_codes::CAPABILITY_DISABLED => Reject {
            status: StatusCode::FORBIDDEN,
            code: control_codes::CAPABILITY_DISABLED,
            message: "agent 未启用该控制能力".to_string(),
            audit_result: AUDIT_DENIED,
        },
        control_codes::NOT_WHITELISTED => Reject {
            status: StatusCode::FORBIDDEN,
            code: control_codes::NOT_WHITELISTED,
            message: "目标不在 agent 白名单".to_string(),
            audit_result: AUDIT_DENIED,
        },
        control_codes::INVALID_REQUEST => Reject {
            status: StatusCode::BAD_REQUEST,
            code: control_codes::INVALID_REQUEST,
            message: "agent 拒绝了该参数".to_string(),
            audit_result: AUDIT_DENIED,
        },
        control_codes::UNSUPPORTED => Reject {
            status: StatusCode::BAD_REQUEST,
            code: control_codes::UNSUPPORTED,
            message: "agent 不支持该控制操作".to_string(),
            audit_result: AUDIT_DENIED,
        },
        // #16：agent 正在续签证书，属于服务暂不可用而不是执行失败/超时。
        // 使用固定文案，不采用 agent 传来的 message。
        control_codes::BUSY_RENEWING => Reject {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: control_codes::BUSY_RENEWING,
            message: "agent 正在续签证书，请稍后重试".to_string(),
            audit_result: AUDIT_ERROR,
        },
        _ => Reject {
            status: StatusCode::BAD_GATEWAY,
            code: control_codes::CONTROL_FAILED,
            message: "agent 执行控制操作失败".to_string(),
            audit_result: AUDIT_ERROR,
        },
    }
}

/// 本地参数校验 + 能力开关检查，产出要发给 agent 的操作。
fn prepare_control(
    payload: &ControlActionRequest,
    cfg: &HubControlConfig,
) -> std::result::Result<PreparedControl, Reject> {
    let capability = payload.capability.as_str();
    if !known_capability(capability) {
        return Err(Reject::invalid(
            "capability 必须是 systemd / docker / process / logs 之一",
        ));
    }
    if !hub_capability_enabled(cfg, capability) {
        return Err(Reject::disabled());
    }

    let action = payload.action.as_str();
    match capability {
        CAP_SYSTEMD => match action {
            "list" => {
                reject_extra_fields(payload, &[])?;
                Ok(PreparedControl {
                    capability: capability.to_string(),
                    action: action.to_string(),
                    target: String::new(),
                    params: "{}".to_string(),
                    op: ControlOp::SystemdList,
                })
            }
            "start" | "stop" | "restart" => {
                reject_extra_fields(payload, &["target"])?;
                let target = required_target(payload)?.to_string();
                validate_unit_name(&target).map_err(invalid_parameter)?;
                if matches!(action, "stop" | "restart") && payload.confirm != Some(true) {
                    return Err(Reject::invalid("stop / restart 必须显式 confirm: true"));
                }
                if is_forbidden_unit(&target) {
                    return Err(Reject::not_whitelisted());
                }
                let systemd_action = match action {
                    "start" => SystemdAction::Start,
                    "stop" => SystemdAction::Stop,
                    _ => SystemdAction::Restart,
                };
                Ok(PreparedControl {
                    capability: capability.to_string(),
                    action: action.to_string(),
                    target: target.clone(),
                    params: params_json(&[("target", Value::String(target.clone()))]),
                    op: ControlOp::SystemdAction {
                        unit: target,
                        action: systemd_action,
                    },
                })
            }
            _ => Err(Reject::invalid(
                "systemd 只支持 list / start / stop / restart",
            )),
        },
        CAP_DOCKER => match action {
            "list" => {
                reject_extra_fields(payload, &[])?;
                Ok(PreparedControl {
                    capability: capability.to_string(),
                    action: action.to_string(),
                    target: String::new(),
                    params: "{}".to_string(),
                    op: ControlOp::DockerList,
                })
            }
            "start" | "stop" | "restart" => {
                reject_extra_fields(payload, &["target"])?;
                let target = required_target(payload)?.to_string();
                validate_container_name(&target).map_err(invalid_parameter)?;
                if matches!(action, "stop" | "restart") && payload.confirm != Some(true) {
                    return Err(Reject::invalid("stop / restart 必须显式 confirm: true"));
                }
                let docker_action = match action {
                    "start" => DockerAction::Start,
                    "stop" => DockerAction::Stop,
                    _ => DockerAction::Restart,
                };
                Ok(PreparedControl {
                    capability: capability.to_string(),
                    action: action.to_string(),
                    target: target.clone(),
                    params: params_json(&[("target", Value::String(target.clone()))]),
                    op: ControlOp::DockerAction {
                        container: target,
                        action: docker_action,
                    },
                })
            }
            _ => Err(Reject::invalid(
                "docker 只支持 list / start / stop / restart",
            )),
        },
        CAP_PROCESS => match action {
            "list" => {
                reject_extra_fields(payload, &[])?;
                Ok(PreparedControl {
                    capability: capability.to_string(),
                    action: action.to_string(),
                    target: String::new(),
                    params: "{}".to_string(),
                    op: ControlOp::ProcessList,
                })
            }
            "kill" => {
                reject_extra_fields(payload, &["pid", "name", "signal"])?;
                let pid = payload
                    .pid
                    .ok_or_else(|| Reject::invalid("kill 必须提供 pid"))?;
                if pid <= 1 {
                    return Err(Reject::invalid("pid 必须大于 1"));
                }
                let name = payload
                    .name
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| Reject::invalid("kill 必须提供进程名 name"))?;
                if name.len() > MAX_NAME_LEN {
                    return Err(Reject::invalid(format!(
                        "进程名长度不能超过 {MAX_NAME_LEN} 字节"
                    )));
                }
                if name.chars().any(char::is_control) {
                    return Err(Reject::invalid("进程名不能包含控制字符"));
                }
                let signal = match payload.signal.as_deref() {
                    Some("term") => KillSignal::Term,
                    Some("kill") => KillSignal::Kill,
                    Some(_) => return Err(Reject::invalid("signal 只支持 term / kill")),
                    None => return Err(Reject::invalid("kill 必须提供 signal")),
                };
                if payload.confirm != Some(true) {
                    return Err(Reject::invalid("kill 必须显式 confirm: true"));
                }
                Ok(PreparedControl {
                    capability: capability.to_string(),
                    action: action.to_string(),
                    target: name.to_string(),
                    params: params_json(&[
                        ("pid", json!(pid)),
                        ("name", Value::String(name.to_string())),
                        ("signal", Value::String(signal.as_str().to_string())),
                    ]),
                    op: ControlOp::ProcessKill {
                        pid,
                        name: name.to_string(),
                        signal,
                    },
                })
            }
            _ => Err(Reject::invalid("process 只支持 list / kill")),
        },
        CAP_LOGS => match action {
            "list" => {
                reject_extra_fields(payload, &[])?;
                Ok(PreparedControl {
                    capability: capability.to_string(),
                    action: action.to_string(),
                    target: String::new(),
                    params: "{}".to_string(),
                    op: ControlOp::LogList,
                })
            }
            "tail" => {
                reject_extra_fields(payload, &["source", "lines"])?;
                let source = payload
                    .source
                    .as_deref()
                    .filter(|source| !source.is_empty())
                    .ok_or_else(|| Reject::invalid("tail 必须提供 source"))?
                    .to_string();
                validate_source_id(&source).map_err(invalid_parameter)?;
                let lines = payload
                    .lines
                    .ok_or_else(|| Reject::invalid("tail 必须提供 lines"))?;
                if !(1..=MAX_LOG_LINES).contains(&lines) {
                    return Err(Reject::invalid(format!(
                        "lines 必须在 1–{MAX_LOG_LINES} 之间"
                    )));
                }
                Ok(PreparedControl {
                    capability: capability.to_string(),
                    action: action.to_string(),
                    target: source.clone(),
                    params: params_json(&[
                        ("target", Value::String(source.clone())),
                        ("lines", json!(lines)),
                    ]),
                    op: ControlOp::LogTail { source, lines },
                })
            }
            _ => Err(Reject::invalid("logs 只支持 list / tail")),
        },
        _ => Err(Reject::invalid("capability 非法")),
    }
}

/// 只允许当前动作声明过的字段；其余字段出现即 400，避免歧义请求。
fn reject_extra_fields(
    payload: &ControlActionRequest,
    allowed: &[&str],
) -> std::result::Result<(), Reject> {
    let fields = [
        ("target", payload.target.is_some()),
        ("pid", payload.pid.is_some()),
        ("name", payload.name.is_some()),
        ("signal", payload.signal.is_some()),
        ("source", payload.source.is_some()),
        ("lines", payload.lines.is_some()),
    ];
    for (field, present) in fields {
        if present && !allowed.contains(&field) {
            return Err(Reject::invalid(format!("当前 action 不接受字段 {field}")));
        }
    }
    Ok(())
}

fn required_target(payload: &ControlActionRequest) -> std::result::Result<&str, Reject> {
    payload
        .target
        .as_deref()
        .filter(|target| !target.is_empty())
        .ok_or_else(|| Reject::invalid("该 action 必须提供 target"))
}

fn invalid_parameter(message: String) -> Reject {
    Reject::invalid(message)
}

/// 审计 params：只放规范允许的字段，且逐个限长。
fn build_audit_params(payload: &ControlActionRequest) -> String {
    let mut fields: Vec<(&str, Value)> = Vec::new();
    if let Some(target) = payload.target.as_deref() {
        fields.push(("target", Value::String(clip_label(target))));
    }
    if let Some(source) = payload.source.as_deref() {
        if payload.target.is_none() {
            fields.push(("target", Value::String(clip_label(source))));
        }
    }
    if let Some(pid) = payload.pid {
        fields.push(("pid", json!(pid)));
    }
    if let Some(name) = payload.name.as_deref() {
        fields.push(("name", Value::String(clip_audit_value(name, MAX_NAME_LEN))));
    }
    if let Some(signal) = payload.signal.as_deref() {
        fields.push(("signal", Value::String(clip_audit_value(signal, 16))));
    }
    if let Some(lines) = payload.lines {
        fields.push(("lines", json!(lines)));
    }
    params_json(&fields)
}

fn params_json(fields: &[(&str, Value)]) -> String {
    let mut map = Map::new();
    for (key, value) in fields {
        map.insert((*key).to_string(), value.clone());
    }
    let encoded = serde_json::to_string(&Value::Object(map)).unwrap_or_else(|_| "{}".to_string());
    truncate_utf8(&encoded, MAX_AUDIT_PARAMS_BYTES)
}

// ---------------------------------------------------------------------------
// 控制结果 → 面板 JSON
// ---------------------------------------------------------------------------

/// 把线协议结果转成面板契约里的 `{"type": ..., ...}`。
///
/// 所有字段与列表都在 hub 侧重新限长：不信任 agent 自报的长度。
pub(crate) fn control_result_json(result: &ControlResult, max_bytes: usize) -> Value {
    let max_bytes = max_bytes.max(1);
    // 单行日志 / 单条输出各自再夹一次，保证极端输出下仍能保留部分内容，
    // 而不是被总预算一次性清空。
    let line_budget = MAX_LOG_LINE_BYTES.min((max_bytes / 4).max(64));
    let stream_budget = MAX_OUTPUT_BYTES.min(max_bytes);
    let value = match result {
        ControlResult::SystemdUnits(units) => json!({
            "type": "systemd_units",
            "units": units.iter().take(MAX_LIST_ITEMS).map(|unit| json!({
                "unit": clip_audit_value(&unit.unit, MAX_TARGET_LEN),
                "load": clip_audit_value(&unit.load, 32),
                "active": clip_audit_value(&unit.active, 32),
                "sub": clip_audit_value(&unit.sub, 32),
                "description": clip_audit_value(&unit.description, 256),
            })).collect::<Vec<_>>(),
        }),
        ControlResult::DockerContainers(containers) => json!({
            "type": "docker_containers",
            "containers": containers.iter().take(MAX_LIST_ITEMS).map(|container| json!({
                "name": clip_audit_value(&container.name, MAX_TARGET_LEN),
                "image": clip_audit_value(&container.image, 256),
                "state": clip_audit_value(&container.state, 32),
                "status": clip_audit_value(&container.status, 128),
                "id": clip_audit_value(&container.id, 128),
            })).collect::<Vec<_>>(),
        }),
        ControlResult::Processes(processes) => json!({
            "type": "processes",
            "processes": processes.iter().take(MAX_PROCESS_ITEMS).map(|process| json!({
                "pid": process.pid,
                "name": clip_audit_value(&process.name, MAX_NAME_LEN),
                "uid": process.uid,
                // 面板优先读 rss（字节），否则用 rss_kb * 1024；这里按线协议原字段输出。
                "rss_kb": process.rss_kb,
                "cmdline": clip_audit_value(&process.cmdline, MAX_CMDLINE_BYTES),
            })).collect::<Vec<_>>(),
        }),
        ControlResult::LogSources(sources) => json!({
            "type": "log_sources",
            "sources": sources.iter().take(MAX_LIST_ITEMS).map(|source| json!({
                "id": clip_audit_value(&source.id, MAX_TARGET_LEN),
                "kind": match source.kind {
                    LogSourceKind::File => "file",
                    LogSourceKind::Journal => "journal",
                },
                "target": clip_audit_value(&source.target, MAX_LOG_TARGET_BYTES),
                "name": clip_audit_value(&source.name, 256),
            })).collect::<Vec<_>>(),
        }),
        ControlResult::LogLines {
            source,
            lines,
            truncated,
            size_bytes,
        } => {
            let max_lines = MAX_LOG_LINES as usize;
            let dropped = lines.len() > max_lines;
            json!({
                "type": "log_lines",
                "source": clip_audit_value(source, MAX_TARGET_LEN),
                "lines": lines.iter().take(max_lines)
                    .map(|line| clip_audit_value(line, line_budget))
                    .collect::<Vec<_>>(),
                "truncated": *truncated || dropped,
                "size_bytes": size_bytes,
            })
        }
        ControlResult::ActionOutput {
            stdout,
            stderr,
            exit_code,
        } => json!({
            "type": "action_output",
            "stdout": clip_audit_value(stdout, stream_budget),
            "stderr": clip_audit_value(stderr, stream_budget),
            "exit_code": exit_code,
        }),
    };
    cap_json_size(value, max_bytes)
}

/// 把结果 JSON 压到 `max_bytes` 以内。
///
/// 列表从尾部丢弃、日志行保留最新的（从头部丢弃并置 `truncated`）、
/// 命令输出截断 stdout / stderr；最后兜底清空字符串，保证响应体不会失控。
fn cap_json_size(mut value: Value, max_bytes: usize) -> Value {
    let mut size = json_len(&value);
    let mut rounds = 0;
    while size > max_bytes && rounds < 64 {
        rounds += 1;
        if !shrink_json_once(&mut value, size, max_bytes) {
            break;
        }
        size = json_len(&value);
    }
    value
}

fn json_len(value: &Value) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

fn shrink_json_once(value: &mut Value, size: usize, max_bytes: usize) -> bool {
    let Some(map) = value.as_object_mut() else {
        return false;
    };
    // 列表：按剩余预算比例保留前面的条目。
    for key in ["units", "containers", "processes", "sources"] {
        let mut shorten = false;
        if let Some(Value::Array(items)) = map.get_mut(key) {
            if !items.is_empty() {
                let keep = ((items.len() * max_bytes) / size).clamp(0, items.len() - 1);
                items.truncate(keep);
                shorten = true;
            }
        }
        if shorten {
            return true;
        }
    }
    // 日志行：保留最新（队尾）的行，丢弃更早的行并标记 truncated。
    let mut lines_shortened = false;
    if let Some(Value::Array(lines)) = map.get_mut("lines") {
        if !lines.is_empty() {
            let keep = ((lines.len() * max_bytes) / size).clamp(0, lines.len() - 1);
            let drop_count = lines.len() - keep;
            lines.drain(0..drop_count);
            lines_shortened = true;
        }
    }
    if lines_shortened {
        map.insert("truncated".to_string(), Value::Bool(true));
        return true;
    }
    // 动作输出：按比例截断 stdout / stderr。
    let mut output_shortened = false;
    for key in ["stdout", "stderr"] {
        if let Some(Value::String(text)) = map.get_mut(key) {
            if !text.is_empty() {
                let keep = (text.len().saturating_mul(max_bytes) / size) / 2;
                *text = truncate_with_marker(text, keep);
                output_shortened = true;
            }
        }
    }
    if output_shortened {
        return true;
    }
    // 最后兜底：清空所有字符串，至少保证 JSON 结构合法且不再超限。
    let mut cleared = false;
    for item in map.values_mut() {
        if let Value::String(text) = item {
            if !text.is_empty() {
                text.clear();
                cleared = true;
            }
        }
    }
    cleared
}

fn truncate_with_marker(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let budget = max_bytes.saturating_sub(TRUNCATED_MARKER.len());
    let mut end = budget.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + TRUNCATED_MARKER.len());
    out.push_str(&text[..end]);
    out.push_str(TRUNCATED_MARKER);
    out
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// 审计列限长；控制字符替换成 `?`，避免换行伪造日志 / 表格。
fn clip_audit_value(value: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max_bytes));
    for ch in value.chars() {
        let ch = if ch.is_control() { '?' } else { ch };
        if out.len() + ch.len_utf8() > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

fn clip_label(value: &str) -> String {
    clip_audit_value(value, MAX_AUDIT_LABEL_BYTES)
}

// ---------------------------------------------------------------------------
// 审计写入 / 查询
// ---------------------------------------------------------------------------

/// 处理过程中的审计草稿；所有 POST 路径（含拒绝）都会落一条。
struct AuditDraft {
    ts: i64,
    actor: String,
    agent_id: String,
    capability: String,
    action: String,
    target: String,
    params: String,
}

impl AuditDraft {
    fn new(agent_id: &str) -> Self {
        Self {
            ts: now_ms(),
            actor: "admin".to_string(),
            agent_id: agent_id.to_string(),
            capability: String::new(),
            action: String::new(),
            target: String::new(),
            params: "{}".to_string(),
        }
    }

    fn into_entry(
        self,
        result: &str,
        error_code: &str,
        error_message: &str,
        duration_ms: i64,
    ) -> NewAuditEntry {
        NewAuditEntry {
            ts: self.ts,
            actor: self.actor,
            agent_id: self.agent_id,
            capability: self.capability,
            action: self.action,
            target: self.target,
            params: self.params,
            result: result.to_string(),
            error_code: error_code.to_string(),
            error_message: truncate_utf8(error_message, MAX_AUDIT_MESSAGE_BYTES),
            duration_ms,
        }
    }
}

fn elapsed_ms(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// 拒绝路径：先写审计，再按固定结构回错误。
async fn finish_error(
    state: &AppState,
    audit: AuditDraft,
    started: Instant,
    reject: &Reject,
) -> Response {
    let duration = elapsed_ms(started);
    let entry = audit.into_entry(reject.audit_result, reject.code, &reject.message, duration);
    record_audit(state, entry).await;
    (
        reject.status,
        Json(json!({
            "ok": false,
            "error": { "code": reject.code, "message": reject.message },
        })),
    )
        .into_response()
}

/// 审计写失败只记 ERROR，绝不改变已经执行的动作结果。
async fn record_audit(state: &AppState, entry: NewAuditEntry) {
    let storage = state.storage.clone();
    match tokio::task::spawn_blocking(move || storage.insert_audit(&entry)).await {
        Ok(Ok(_)) => {}
        Ok(Err(err)) => tracing::error!(error = %err, "写入审计失败（控制动作结果不受影响）"),
        Err(err) => tracing::error!(error = %err, "审计写入任务失败（控制动作结果不受影响）"),
    }
}

#[derive(Debug, serde::Serialize)]
pub(crate) struct AuditListResponse {
    entries: Vec<AuditEntry>,
    /// 下一页排他游标（`id < next_before_id`）；没有更多数据时为 `null`。
    next_before_id: Option<i64>,
}

/// `GET /api/v1/audit`：只读，不写审计。
pub(crate) async fn audit_list(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
) -> std::result::Result<Json<AuditListResponse>, ApiError> {
    let pairs = crate::parse_query_pairs(raw.as_deref()).map_err(ApiError::bad_request)?;
    let limit = parse_audit_limit(&pairs).map_err(ApiError::bad_request)?;
    let before_id = parse_before_id(&pairs).map_err(ApiError::bad_request)?;
    let agent_id = parse_agent_filter(&pairs).map_err(ApiError::bad_request)?;
    let capability = parse_capability_filter(&pairs).map_err(ApiError::bad_request)?;

    let entries = tokio::task::spawn_blocking({
        let storage = state.storage.clone();
        move || storage.list_audit(limit, before_id, agent_id.as_deref(), capability.as_deref())
    })
    .await
    .map_err(ApiError::from)??;

    // 排他游标：本页满时下一页从最后一条 id 继续（严格小于），不会漏也不会重。
    let next_before_id = if entries.len() == limit {
        entries.last().map(|entry| entry.id).filter(|id| *id > 1)
    } else {
        None
    };
    Ok(Json(AuditListResponse {
        entries,
        next_before_id,
    }))
}

fn single_query_value<'a>(
    pairs: &'a [(String, String)],
    key: &str,
) -> std::result::Result<Option<&'a str>, String> {
    let mut found: Option<&str> = None;
    for (name, value) in pairs {
        if name == key {
            if found.is_some() {
                return Err(format!("查询参数 {key} 重复"));
            }
            found = Some(value.as_str());
        }
    }
    Ok(found)
}

fn parse_audit_limit(pairs: &[(String, String)]) -> std::result::Result<usize, String> {
    let Some(raw) = single_query_value(pairs, "limit")? else {
        return Ok(DEFAULT_AUDIT_LIMIT);
    };
    let limit: usize = raw.parse().map_err(|_| "limit 必须是正整数".to_string())?;
    if !(1..=MAX_AUDIT_LIMIT).contains(&limit) {
        return Err(format!("limit 必须在 1–{MAX_AUDIT_LIMIT} 之间"));
    }
    Ok(limit)
}

fn parse_before_id(pairs: &[(String, String)]) -> std::result::Result<Option<i64>, String> {
    let Some(raw) = single_query_value(pairs, "before_id")? else {
        return Ok(None);
    };
    let value: i64 = raw
        .parse()
        .map_err(|_| "before_id 必须是正整数".to_string())?;
    if value <= 0 {
        return Err("before_id 必须是正整数".to_string());
    }
    Ok(Some(value))
}

fn parse_agent_filter(pairs: &[(String, String)]) -> std::result::Result<Option<String>, String> {
    let Some(raw) = single_query_value(pairs, "agent_id")? else {
        return Ok(None);
    };
    if raw.is_empty() || !is_valid_agent_id(raw) {
        return Err("agent_id 非法".to_string());
    }
    Ok(Some(raw.to_string()))
}

fn parse_capability_filter(
    pairs: &[(String, String)],
) -> std::result::Result<Option<String>, String> {
    let Some(raw) = single_query_value(pairs, "capability")? else {
        return Ok(None);
    };
    if raw.is_empty()
        || raw.len() > MAX_CAPABILITY_FILTER_BYTES
        || raw.chars().any(char::is_control)
    {
        return Err("capability 非法".to_string());
    }
    Ok(Some(raw.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustboard_common::control::{DockerContainer, LogSourceInfo, ProcessInfo, SystemdUnit};

    fn enabled_cfg() -> HubControlConfig {
        HubControlConfig {
            enabled: true,
            systemd: true,
            docker: true,
            process: true,
            logs: true,
            ..HubControlConfig::default()
        }
    }

    fn parse(body: &str) -> ControlActionRequest {
        serde_json::from_str(body).expect("测试请求体必须能反序列化")
    }

    /// 既有测试只关心 pending 上限 / 应答匹配，给一个足够长的超时避免干扰。
    const TEST_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

    fn prepare(body: &str) -> std::result::Result<PreparedControl, Reject> {
        prepare_control(&parse(body), &enabled_cfg())
    }

    #[test]
    fn request_body_rejects_unknown_fields() {
        assert!(
            serde_json::from_str::<ControlActionRequest>(
                r#"{"capability":"systemd","action":"list","extra":1}"#
            )
            .is_err(),
            "deny_unknown_fields 必须拒绝拼错的字段"
        );
        assert!(serde_json::from_str::<ControlActionRequest>(
            r#"{"capability":"systemd","action":"list"}"#
        )
        .is_ok());
    }

    #[test]
    fn read_only_actions_map_to_ops() {
        for (body, expected) in [
            (
                r#"{"capability":"systemd","action":"list"}"#,
                ControlOp::SystemdList,
            ),
            (
                r#"{"capability":"docker","action":"list"}"#,
                ControlOp::DockerList,
            ),
            (
                r#"{"capability":"process","action":"list"}"#,
                ControlOp::ProcessList,
            ),
            (
                r#"{"capability":"logs","action":"list"}"#,
                ControlOp::LogList,
            ),
        ] {
            let prepared =
                prepare(body).unwrap_or_else(|reject| panic!("{body}: {}", reject.message));
            assert_eq!(prepared.op, expected);
            assert_eq!(prepared.params, "{}");
        }
        // 只读动作携带参数会被拒绝（避免歧义请求）。
        let reject = prepare(r#"{"capability":"logs","action":"list","lines":10}"#).unwrap_err();
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);
        assert_eq!(reject.code, control_codes::INVALID_REQUEST);
    }

    #[test]
    fn dangerous_actions_require_confirm() {
        for body in [
            r#"{"capability":"systemd","action":"stop","target":"nginx.service"}"#,
            r#"{"capability":"systemd","action":"restart","target":"nginx.service"}"#,
            r#"{"capability":"docker","action":"restart","target":"web-1"}"#,
            r#"{"capability":"process","action":"kill","pid":123,"name":"sleep","signal":"term"}"#,
        ] {
            let reject = prepare(body).unwrap_err();
            assert_eq!(reject.status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(reject.code, control_codes::INVALID_REQUEST);
        }
        // confirm:false 不能绕过。
        let reject = prepare(
            r#"{"capability":"systemd","action":"restart","target":"nginx.service","confirm":false}"#,
        )
        .unwrap_err();
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);

        // start 不要求 confirm（面板会带，不强制）。
        assert_eq!(
            prepare(r#"{"capability":"systemd","action":"start","target":"nginx.service"}"#)
                .unwrap()
                .op,
            ControlOp::SystemdAction {
                unit: "nginx.service".into(),
                action: SystemdAction::Start
            }
        );
    }

    #[test]
    fn forbidden_units_are_denied_before_reaching_agent() {
        for unit in ["sshd.service", "rustboard-agent.service", "dbus.service"] {
            let body = format!(
                r#"{{"capability":"systemd","action":"restart","target":"{unit}","confirm":true}}"#
            );
            let reject = prepare(&body).unwrap_err();
            assert_eq!(reject.status, StatusCode::FORBIDDEN, "{unit}");
            assert_eq!(reject.code, control_codes::NOT_WHITELISTED);
            assert_eq!(reject.audit_result, AUDIT_DENIED);
        }
    }

    #[test]
    fn target_and_name_limits_are_enforced() {
        let too_long = "a".repeat(MAX_TARGET_LEN + 1);
        let body = format!(
            r#"{{"capability":"docker","action":"restart","target":"{too_long}","confirm":true}}"#
        );
        assert_eq!(prepare(&body).unwrap_err().status, StatusCode::BAD_REQUEST);

        for body in [
            r#"{"capability":"systemd","action":"restart","target":"nginx evil","confirm":true}"#,
            r#"{"capability":"systemd","action":"restart","target":"../nginx","confirm":true}"#,
            r#"{"capability":"docker","action":"restart","target":"-web1","confirm":true}"#,
            r#"{"capability":"logs","action":"tail","source":"../../etc/passwd","lines":10}"#,
            r#"{"capability":"logs","action":"tail","source":"nginx-error","lines":0}"#,
            r#"{"capability":"logs","action":"tail","source":"nginx-error","lines":2001}"#,
            r#"{"capability":"logs","action":"tail","source":"nginx-error"}"#,
            r#"{"capability":"process","action":"kill","pid":1,"name":"systemd","signal":"term","confirm":true}"#,
            r#"{"capability":"process","action":"kill","pid":0,"name":"sleep","signal":"term","confirm":true}"#,
            r#"{"capability":"process","action":"kill","pid":123,"name":"sleep","signal":"hup","confirm":true}"#,
            r#"{"capability":"process","action":"kill","pid":123,"name":"bad\nname","signal":"term","confirm":true}"#,
        ] {
            let reject = prepare(body).unwrap_err();
            assert_eq!(reject.status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(reject.code, control_codes::INVALID_REQUEST, "{body}");
        }
    }

    #[test]
    fn mutation_params_are_mapped_and_audited_without_output() {
        let prepared = prepare(
            r#"{"capability":"process","action":"kill","pid":123,"name":"sleep","signal":"kill","confirm":true}"#,
        )
        .unwrap();
        assert_eq!(
            prepared.op,
            ControlOp::ProcessKill {
                pid: 123,
                name: "sleep".into(),
                signal: KillSignal::Kill,
            }
        );
        assert_eq!(prepared.target, "sleep");
        let params: Value = serde_json::from_str(&prepared.params).unwrap();
        assert_eq!(params["pid"], 123);
        assert_eq!(params["name"], "sleep");
        assert_eq!(params["signal"], "kill");

        let prepared =
            prepare(r#"{"capability":"logs","action":"tail","source":"nginx-error","lines":200}"#)
                .unwrap();
        assert_eq!(
            prepared.op,
            ControlOp::LogTail {
                source: "nginx-error".into(),
                lines: 200,
            }
        );
        assert_eq!(prepared.target, "nginx-error");
        let params: Value = serde_json::from_str(&prepared.params).unwrap();
        assert_eq!(params["target"], "nginx-error");
        assert_eq!(params["lines"], 200);
    }

    #[test]
    fn hub_switch_gates_capabilities() {
        let payload = parse(r#"{"capability":"systemd","action":"list"}"#);
        let mut cfg = enabled_cfg();
        cfg.enabled = false;
        let reject = prepare_control(&payload, &cfg).unwrap_err();
        assert_eq!(reject.status, StatusCode::FORBIDDEN);
        assert_eq!(reject.code, control_codes::CAPABILITY_DISABLED);

        cfg.enabled = true;
        cfg.systemd = false;
        let reject = prepare_control(&payload, &cfg).unwrap_err();
        assert_eq!(reject.status, StatusCode::FORBIDDEN);
        assert_eq!(reject.code, control_codes::CAPABILITY_DISABLED);

        // 未知能力按参数非法处理，不是 403。
        let reject = prepare_control(
            &parse(r#"{"capability":"shell","action":"ls"}"#),
            &enabled_cfg(),
        )
        .unwrap_err();
        assert_eq!(reject.status, StatusCode::BAD_REQUEST);
        assert_eq!(reject.code, control_codes::INVALID_REQUEST);

        assert_eq!(hub_enabled_capabilities(&enabled_cfg()), ALL_CAPABILITIES);
        cfg.systemd = false;
        assert_eq!(
            hub_enabled_capabilities(&cfg),
            vec!["docker", "process", "logs"]
        );
    }

    #[test]
    fn reported_capabilities_are_filtered_and_deduped() {
        let reported = vec![
            "logs".to_string(),
            "shell".to_string(),
            "systemd".to_string(),
            "logs".to_string(),
            String::new(),
        ];
        assert_eq!(
            sanitize_agent_capabilities(&reported),
            vec!["logs", "systemd"]
        );
        // 超长上报只取前 16 条，未知值不进结果。
        let many: Vec<String> = (0..64).map(|index| format!("cap-{index}")).collect();
        assert!(sanitize_agent_capabilities(&many).is_empty());
        assert!(sanitize_agent_capabilities(&[]).is_empty());
    }

    #[test]
    fn control_session_ids_are_monotonic_and_pending_is_bounded() {
        let mut session = ControlSession::new(2, TEST_REQUEST_TIMEOUT);
        let (reply_one, _rx_one) = oneshot::channel();
        let request = session
            .enqueue(ControlCommand {
                op: ControlOp::SystemdList,
                reply: reply_one,
            })
            .expect("第一个命令应成功");
        assert_eq!(request.id, 1);
        let (reply_two, _rx_two) = oneshot::channel();
        let request = session
            .enqueue(ControlCommand {
                op: ControlOp::ProcessList,
                reply: reply_two,
            })
            .expect("第二个命令应成功");
        assert_eq!(request.id, 2);
        assert_eq!(session.pending_len(), 2);

        let (reply_three, mut rx_three) = oneshot::channel();
        let error = session
            .enqueue(ControlCommand {
                op: ControlOp::LogList,
                reply: reply_three,
            })
            .expect_err("超过上限必须拒绝");
        assert_eq!(error.code, hub_codes::TOO_MANY_PENDING);
        let received = rx_three.try_recv().expect("拒绝时应主动回复错误");
        assert_eq!(
            received.expect_err("拒绝必须是错误").code,
            hub_codes::TOO_MANY_PENDING
        );
        assert_eq!(session.pending_len(), 2, "被拒绝的命令不能占 pending 名额");
    }

    #[test]
    fn control_session_matches_responses_and_counts_unknown_ids() {
        let mut session = ControlSession::new(4, TEST_REQUEST_TIMEOUT);
        let (reply, mut rx) = oneshot::channel();
        let request = session
            .enqueue(ControlCommand {
                op: ControlOp::LogList,
                reply,
            })
            .unwrap();
        session.complete(ControlResponse::success(
            request.id,
            ControlResult::LogSources(Vec::new()),
        ));
        assert_eq!(
            rx.try_recv().unwrap().unwrap(),
            ControlResult::LogSources(Vec::new())
        );
        assert_eq!(session.pending_len(), 0);

        // 错误应答同样完成请求。
        let (reply, mut rx) = oneshot::channel();
        let request = session
            .enqueue(ControlCommand {
                op: ControlOp::DockerList,
                reply,
            })
            .unwrap();
        session.complete(ControlResponse::failure(
            request.id,
            ControlError::not_whitelisted("unit 不在白名单"),
        ));
        assert_eq!(
            rx.try_recv().unwrap().unwrap_err().code,
            control_codes::NOT_WHITELISTED
        );

        // 未知 id 丢弃并计数。
        session.complete(ControlResponse::success(
            999,
            ControlResult::SystemdUnits(Vec::new()),
        ));
        assert_eq!(session.unknown_responses(), 1);

        // 同时带 result 和 error 时按失败处理。
        let (reply, mut rx) = oneshot::channel();
        let request = session
            .enqueue(ControlCommand {
                op: ControlOp::SystemdList,
                reply,
            })
            .unwrap();
        session.complete(ControlResponse {
            id: request.id,
            result: Some(ControlResult::SystemdUnits(Vec::new())),
            error: Some(ControlError::control_failed("boom")),
        });
        assert_eq!(
            rx.try_recv().unwrap().unwrap_err().code,
            control_codes::CONTROL_FAILED
        );
    }

    /// 会话内 pending 满经 oneshot 回 `too_many_pending`；API 映射必须是 429，
    /// 不能因为错误码不在 agent 错误表里就落到 502。
    #[test]
    fn pending_limit_error_maps_to_429_not_502() {
        let mut session = ControlSession::new(1, TEST_REQUEST_TIMEOUT);
        let (reply, _rx) = oneshot::channel();
        session
            .enqueue(ControlCommand {
                op: ControlOp::SystemdList,
                reply,
            })
            .unwrap();

        let (reply, mut rx) = oneshot::channel();
        let error = session
            .enqueue(ControlCommand {
                op: ControlOp::SystemdList,
                reply,
            })
            .expect_err("pending 已满必须拒绝");
        assert_eq!(error.code, hub_codes::TOO_MANY_PENDING);

        let delivered = rx
            .try_recv()
            .expect("满时应主动回复错误")
            .expect_err("必须是错误");
        assert_eq!(delivered.code, hub_codes::TOO_MANY_PENDING);

        let reject = reject_from_agent_error(&delivered);
        assert_eq!(reject.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(reject.code, hub_codes::TOO_MANY_PENDING);
        assert_eq!(reject.audit_result, AUDIT_ERROR);
    }

    /// 会话侧回传的 hub 错误码（agent 断开 / 超时 / 内部错误 / pending 满）
    /// 必须保留各自 HTTP 语义，不能统一落 502。
    #[test]
    fn hub_side_pending_errors_keep_their_status() {
        for (code, status) in [
            (hub_codes::AGENT_OFFLINE, StatusCode::SERVICE_UNAVAILABLE),
            (hub_codes::CONTROL_TIMEOUT, StatusCode::GATEWAY_TIMEOUT),
            (hub_codes::INTERNAL, StatusCode::INTERNAL_SERVER_ERROR),
            (hub_codes::TOO_MANY_PENDING, StatusCode::TOO_MANY_REQUESTS),
        ] {
            let reject = reject_from_agent_error(&ControlError::new(code, "这里的内容不该被使用"));
            assert_eq!(reject.status, status, "{code}");
            assert_eq!(reject.code, code);
            assert_eq!(reject.audit_result, AUDIT_ERROR);
        }
    }

    #[test]
    fn dropping_session_resolves_pending_with_agent_offline() {
        let (reply, mut rx) = oneshot::channel();
        {
            let mut session = ControlSession::new(1, TEST_REQUEST_TIMEOUT);
            session
                .enqueue(ControlCommand {
                    op: ControlOp::SystemdList,
                    reply,
                })
                .unwrap();
        }
        let error = rx.try_recv().expect("Drop 必须回复等待者");
        assert_eq!(
            error.expect_err("会话结束必须是错误").code,
            hub_codes::AGENT_OFFLINE
        );
    }

    /// #18：到期的 pending 必须被清理并回 `control_timeout`；
    /// 清理后名额释放，新请求不会永久 `too_many_pending`。
    #[test]
    fn control_session_expires_timed_out_requests() {
        let mut session = ControlSession::new(1, Duration::from_millis(50));
        let (reply, mut rx) = oneshot::channel();
        session
            .enqueue(ControlCommand {
                op: ControlOp::SystemdList,
                reply,
            })
            .expect("第一个命令应成功");
        assert_eq!(session.pending_len(), 1);

        // deadline = 入队时刻 + 50ms；用 +60ms 的 now 一定过期。
        let expired = session.expire(Instant::now() + Duration::from_millis(60));
        assert_eq!(expired, 1);
        assert_eq!(session.pending_len(), 0);

        let error = rx
            .try_recv()
            .expect("过期必须回复等待者")
            .expect_err("过期必须是错误");
        assert_eq!(error.code, hub_codes::CONTROL_TIMEOUT);
        assert_eq!(error.message, "控制请求超时");

        // 名额已释放：新请求能进入 pending，而不是被历史遗留占满。
        let (reply, _rx) = oneshot::channel();
        session
            .enqueue(ControlCommand {
                op: ControlOp::ProcessList,
                reply,
            })
            .expect("过期清理后必须能再入队");
        assert_eq!(session.pending_len(), 1);
    }

    /// #18：过期后晚到的应答按未知 id 丢弃，不 panic、不改变 pending。
    #[test]
    fn late_response_after_expire_is_counted_as_unknown() {
        let mut session = ControlSession::new(2, Duration::from_millis(50));
        let (reply, mut rx) = oneshot::channel();
        let request = session
            .enqueue(ControlCommand {
                op: ControlOp::LogList,
                reply,
            })
            .unwrap();
        assert_eq!(
            session.expire(Instant::now() + Duration::from_millis(60)),
            1
        );
        assert_eq!(
            rx.try_recv()
                .expect("过期必须回复等待者")
                .expect_err("过期必须是错误")
                .code,
            hub_codes::CONTROL_TIMEOUT
        );
        assert_eq!(session.pending_len(), 0);

        // 晚到的应答：unknown_responses 计数 +1，pending 保持不变。
        session.complete(ControlResponse::success(
            request.id,
            ControlResult::SystemdUnits(Vec::new()),
        ));
        assert_eq!(session.unknown_responses(), 1);
        assert_eq!(session.pending_len(), 0);
    }

    /// #18：多个请求各自 deadline，`expire` 只清已过期的，未过期保留。
    #[test]
    fn expire_removes_only_due_requests() {
        let mut session = ControlSession::new(4, TEST_REQUEST_TIMEOUT);
        let mut ids = Vec::new();
        let mut receivers = Vec::new();
        for op in [ControlOp::SystemdList, ControlOp::ProcessList] {
            let (reply, rx) = oneshot::channel();
            let request = session.enqueue(ControlCommand { op, reply }).unwrap();
            ids.push(request.id);
            receivers.push(rx);
        }

        // 直接构造不同 deadline：第一条过期，第二条仍在等待。
        let now = Instant::now();
        session.pending.get_mut(&ids[0]).unwrap().deadline = now - Duration::from_millis(1);
        session.pending.get_mut(&ids[1]).unwrap().deadline = now + Duration::from_secs(30);

        assert_eq!(session.expire(now), 1);
        assert_eq!(session.pending_len(), 1);
        assert!(session.pending.contains_key(&ids[1]), "未过期请求必须保留");
        assert_eq!(
            receivers[0]
                .try_recv()
                .expect("过期请求必须收到错误")
                .expect_err("过期必须是错误")
                .code,
            hub_codes::CONTROL_TIMEOUT
        );
        assert!(receivers[1].try_recv().is_err(), "未过期请求不能收到错误");

        // 重复清理是幂等的：没有新的过期项时返回 0。
        assert_eq!(session.expire(now), 0);
        assert_eq!(session.pending_len(), 1);
    }

    /// #16：续签期间的固定错误码映射 503 / `busy_renewing` / 审计 error，
    /// 且 message 必须是本地固定文案，不采用 agent 传来的内容。
    #[test]
    fn busy_renewing_maps_to_503_with_fixed_message() {
        let error = ControlError::new(control_codes::BUSY_RENEWING, "agent 侧详情不应被采用");
        let reject = reject_from_agent_error(&error);
        assert_eq!(reject.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reject.code, control_codes::BUSY_RENEWING);
        assert_eq!(reject.code, "busy_renewing");
        assert_eq!(reject.message, "agent 正在续签证书，请稍后重试");
        assert!(!reject.message.contains("详情"), "不得回显 agent 错误详情");
        assert_eq!(reject.audit_result, AUDIT_ERROR);
        // 不能落到 502 / 504。
        assert_ne!(reject.status, StatusCode::BAD_GATEWAY);
        assert_ne!(reject.status, StatusCode::GATEWAY_TIMEOUT);
    }

    #[test]
    fn result_json_matches_panel_contract() {
        let units = control_result_json(
            &ControlResult::SystemdUnits(vec![SystemdUnit {
                unit: "nginx.service".into(),
                load: "loaded".into(),
                active: "active".into(),
                sub: "running".into(),
                description: "Nginx".into(),
            }]),
            MAX_OUTPUT_BYTES,
        );
        assert_eq!(units["type"], "systemd_units");
        assert_eq!(units["units"][0]["unit"], "nginx.service");

        let containers = control_result_json(
            &ControlResult::DockerContainers(vec![DockerContainer {
                name: "web-1".into(),
                image: "nginx:latest".into(),
                state: "running".into(),
                status: "Up 1 hour".into(),
                id: "abc".into(),
            }]),
            MAX_OUTPUT_BYTES,
        );
        assert_eq!(containers["type"], "docker_containers");
        assert_eq!(containers["containers"][0]["name"], "web-1");

        let processes = control_result_json(
            &ControlResult::Processes(vec![ProcessInfo {
                pid: 42,
                name: "nginx".into(),
                cmdline: "nginx -g daemon off;".into(),
                uid: 0,
                rss_kb: 1024,
            }]),
            MAX_OUTPUT_BYTES,
        );
        assert_eq!(processes["type"], "processes");
        // 面板用 rss_kb 原字段（而不是字节换算后的 rss）。
        assert_eq!(processes["processes"][0]["rss_kb"], 1024);
        assert!(processes["processes"][0].get("rss").is_none());

        let sources = control_result_json(
            &ControlResult::LogSources(vec![LogSourceInfo {
                id: "nginx-error".into(),
                kind: LogSourceKind::File,
                target: "/var/log/nginx/error.log".into(),
                name: "Nginx".into(),
            }]),
            MAX_OUTPUT_BYTES,
        );
        assert_eq!(sources["type"], "log_sources");
        assert_eq!(sources["sources"][0]["kind"], "file");
        assert_eq!(sources["sources"][0]["target"], "/var/log/nginx/error.log");
        assert!(sources["sources"][0].get("size").is_none());

        let lines = control_result_json(
            &ControlResult::LogLines {
                source: "nginx-error".into(),
                lines: vec!["a".into(), "b".into()],
                truncated: false,
                size_bytes: 12,
            },
            MAX_OUTPUT_BYTES,
        );
        assert_eq!(lines["type"], "log_lines");
        assert_eq!(lines["lines"].as_array().unwrap().len(), 2);
        assert_eq!(lines["size_bytes"], 12);

        let output = control_result_json(
            &ControlResult::ActionOutput {
                stdout: "ok".into(),
                stderr: "warn".into(),
                exit_code: Some(0),
            },
            MAX_OUTPUT_BYTES,
        );
        assert_eq!(output["type"], "action_output");
        assert_eq!(output["stdout"], "ok");
        assert_eq!(output["exit_code"], 0);
    }

    /// 只有明确的 0 算成功；非 0 与被信号终止（None）都算失败。
    #[test]
    fn command_exit_only_zero_counts_as_success() {
        let output = |exit_code| ControlResult::ActionOutput {
            stdout: String::new(),
            stderr: String::new(),
            exit_code,
        };
        assert_eq!(command_exit(&output(Some(0))), CommandExit::Success);
        assert_eq!(command_exit(&output(Some(5))), CommandExit::NonZero(5));
        assert_eq!(command_exit(&output(Some(-1))), CommandExit::NonZero(-1));
        assert_eq!(command_exit(&output(None)), CommandExit::Signaled);
        // 列表类结果没有退出码，不参与命令成败判定。
        assert_eq!(
            command_exit(&ControlResult::Processes(Vec::new())),
            CommandExit::Success
        );
    }

    #[test]
    fn oversized_results_are_capped_on_hub_side() {
        let max_bytes = 1024;

        let lines = control_result_json(
            &ControlResult::LogLines {
                source: "nginx-error".into(),
                lines: (0..MAX_LOG_LINES).map(|_| "x".repeat(4096)).collect(),
                truncated: false,
                size_bytes: u64::MAX,
            },
            max_bytes,
        );
        assert!(
            serde_json::to_vec(&lines).unwrap().len() <= max_bytes,
            "日志结果必须被 hub 截断到 max_output_bytes 以内"
        );
        assert_eq!(lines["truncated"], true);

        let output = control_result_json(
            &ControlResult::ActionOutput {
                stdout: "s".repeat(MAX_OUTPUT_BYTES),
                stderr: "e".repeat(MAX_OUTPUT_BYTES),
                exit_code: Some(1),
            },
            max_bytes,
        );
        assert!(serde_json::to_vec(&output).unwrap().len() <= max_bytes);

        let units = control_result_json(
            &ControlResult::SystemdUnits(
                (0..MAX_LIST_ITEMS)
                    .map(|index| SystemdUnit {
                        unit: format!("unit-{index}.service"),
                        load: "loaded".into(),
                        active: "active".into(),
                        sub: "running".into(),
                        description: "d".repeat(256),
                    })
                    .collect(),
            ),
            max_bytes,
        );
        let serialized = serde_json::to_vec(&units).unwrap();
        assert!(serialized.len() <= max_bytes);
        assert!(!units["units"].as_array().unwrap().is_empty());
    }
}
