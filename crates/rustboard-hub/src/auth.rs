//! 管理 API 鉴权与 scoped token 授权。
//!
//! 一次请求的完整顺序（与 v0.2 的单一 admin_token 行为兼容）：
//! 1. 解析 `Authorization: Bearer <token>`（scheme 大小写不敏感，只接受两段）；
//! 2. 缺失 / 格式错误：先查未认证失败限速，已超限直接 429；否则记一次失败后 401；
//! 3. 先常量时间比较旧 `admin_token`，命中即清空该 IP 的失败计数，按 `admin` scope
//!    的兼容主体放行，**不受失败限速影响**（保留应急入口）；
//! 4. 否则先查失败限速，已超限直接 429（不计算 SHA-256、不 spawn_blocking 查库）；
//! 5. 未超限才 SHA-256(token) 后查 `api_tokens`，只认未吊销行；成功清计数；
//!    失败记一次失败，未超限 401，达到阈值后后续请求 429；
//! 6. 认证失败固定 401 + `WWW-Authenticate: Bearer`；429 固定
//!    `{"error":"rate_limited"}` + `Retry-After`（1..=60 秒）；两者都不写审计、
//!    不回显 token；日志每 IP 每窗口只 WARN 第一条失败与首次 429，其余 debug
//!    （`limit = 0` 关闭限速时仍保留首条失败 WARN 采样，见 [`AuthFailureLimiter`]）；
//! 7. 认证成功后才进入每 IP 管理限速（未认证请求不消耗已认证额度）；
//! 8. 按「已知路由 + 方法」精确校验 scope（见 [`required_scope`]）：
//!    `read < write < admin`，权限不足 403 `forbidden_scope`，不写控制审计；
//! 9. 把 [`AuthPrincipal`] 放进 request extensions，供控制面写审计 actor。
//!
//! `/healthz` 不经过本中间件；未知 `/api/v1/*` 先认证，再由路由返回 404/405，
//! 不因为 token scope 变成 403（避免用 403 泄露路由是否存在）。

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rustboard_common::tls::sha256_hex;
use rustboard_common::util::{constant_time_eq, now_ms};

use crate::AppState;

/// 管理 API token 的权限层级：`read < write < admin`。
///
/// `write` 隐含 `read`；`admin` 通过全部检查（预留给未来的 HTTP token 管理，
/// 本阶段 token 管理只走 CLI）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScope {
    Read,
    Write,
    Admin,
}

impl TokenScope {
    /// 把数据库 / CLI 里的字符串解析成枚举；非法值返回 `None`。
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// 字符串形式，与 `api_tokens.scope` 的 CHECK 约束一致。
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Admin => 2,
        }
    }
}

/// `granted` 是否覆盖 `required`（层级比较，`admin` 通过一切）。
pub fn scope_allows(granted: TokenScope, required: TokenScope) -> bool {
    granted.rank() >= required.rank()
}

/// 通过鉴权的请求主体；控制面用它写审计 actor。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPrincipal {
    /// 旧 `admin_token` 为 `"admin"`；scoped token 为 token name。
    pub name: String,
    pub scope: TokenScope,
    /// 是否来自旧 `admin_token` 兼容路径（审计 actor 保持 `"admin"`）。
    pub legacy: bool,
}

/// 认证失败原因：只用于日志分类，绝不回显给客户端。
enum AuthFailure {
    /// 缺失 / 格式错误 / 查无此 token / 已吊销。
    Unauthorized,
    /// 数据库里的 scope 非法：按未认证处理并 warn（不猜测权限）。
    IllegalScope(String),
    /// 存储错误：安全默认拒绝（401），不能放行。
    Backend(String),
}

/// 未认证失败限速的固定窗口长度（毫秒）。
const AUTH_FAILURE_WINDOW_MS: i64 = 60_000;
/// 未认证失败限速表容量（按来源 IP 计数）。
const AUTH_FAILURE_TABLE_CAPACITY: usize = 4096;

/// 未认证失败限速的判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthFailureCheck {
    /// 未超限，可以继续认证流程。
    Allowed,
    /// 已超限：`retry_after` 秒后可重试；`first` 表示本窗口首次触发 429
    /// （只用于日志采样，避免每个被拒请求都 WARN）。
    Limited {
        retry_after: u64,
        first: bool,
        cause: AuthFailureCause,
    },
}

/// 触发 429 的原因，只用于日志分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthFailureCause {
    /// 本窗口失败次数达到阈值。
    Failures,
    /// 限速表已满且无过期项，拒绝新来源。
    TableFull,
}

/// 单个来源 IP 的固定窗口失败计数。
#[derive(Debug, Clone, Copy, Default)]
struct AuthFailureWindow {
    started_at: i64,
    failures: u32,
    /// 本窗口是否已经 WARN 过首次 429，避免超限后每个请求都刷日志。
    limited_logged: bool,
}

impl AuthFailureWindow {
    fn is_expired(&self, now: i64) -> bool {
        self.started_at == 0 || now.saturating_sub(self.started_at) >= AUTH_FAILURE_WINDOW_MS
    }

    /// 距离窗口结束的秒数，向上取整并夹在 1..=60。
    fn retry_after(&self, now: i64) -> u64 {
        let elapsed = now.saturating_sub(self.started_at).max(0);
        let remaining = (AUTH_FAILURE_WINDOW_MS - elapsed).max(0);
        (((remaining + 999) / 1_000).max(1) as u64).min(60)
    }
}

#[derive(Default)]
struct AuthFailureTable {
    windows: HashMap<IpAddr, AuthFailureWindow>,
    /// 上次「表满拒绝新来源」WARN 的时间（毫秒），按窗口全局节流。
    capacity_warned_at: i64,
}

/// 未认证请求的每来源 IP 固定窗口失败限速（KI-26）。
///
/// 独立于管理 API 的 `AdminRateLimiter`：未认证请求只消耗失败额度，认证成功后
/// 才进入每 IP 请求限速。窗口 60s、容量 4096 个来源 IP；`limit` 为 0 时关闭限速
/// （`check` 恒为 `Allowed`，不返回 429），但仍保留同一有界窗口**只用于 WARN 采样**：
/// 每 IP 每窗口首条失败返回 true，后续降为 DEBUG。时钟可注入，单测不 sleep。
pub(crate) struct AuthFailureLimiter {
    limit: u32,
    table: StdMutex<AuthFailureTable>,
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl AuthFailureLimiter {
    pub(crate) fn new(limit: u32) -> Self {
        Self::with_clock(limit, Arc::new(now_ms))
    }

    fn with_clock(limit: u32, now_ms: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            limit,
            table: StdMutex::new(AuthFailureTable::default()),
            now_ms,
        }
    }

    fn lock_table(&self) -> std::sync::MutexGuard<'_, AuthFailureTable> {
        match self.table.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// 认证前检查：已超限返回 `Limited`，调用方必须直接 429（不查库）。
    ///
    /// `limit == 0` 时恒为 `Allowed`：采样窗口只服务日志，绝不能让关闭限速变成 429。
    pub(crate) fn check(&self, ip: IpAddr) -> AuthFailureCheck {
        if self.limit == 0 {
            return AuthFailureCheck::Allowed;
        }
        let now = (self.now_ms)();
        let mut table = self.lock_table();
        if table
            .windows
            .get(&ip)
            .is_some_and(|window| window.is_expired(now))
        {
            table.windows.remove(&ip);
        }
        if let Some(window) = table.windows.get_mut(&ip) {
            if window.failures < self.limit {
                return AuthFailureCheck::Allowed;
            }
            let retry_after = window.retry_after(now);
            let first = !window.limited_logged;
            window.limited_logged = true;
            return AuthFailureCheck::Limited {
                retry_after,
                first,
                cause: AuthFailureCause::Failures,
            };
        }
        // 未跟踪来源：容量满时先清理过期项，仍满则拒绝新来源。
        if table.windows.len() >= AUTH_FAILURE_TABLE_CAPACITY {
            table.windows.retain(|_, window| !window.is_expired(now));
            if table.windows.len() >= AUTH_FAILURE_TABLE_CAPACITY {
                let first = now.saturating_sub(table.capacity_warned_at) >= AUTH_FAILURE_WINDOW_MS;
                if first {
                    table.capacity_warned_at = now;
                }
                return AuthFailureCheck::Limited {
                    retry_after: AUTH_FAILURE_WINDOW_MS as u64 / 1_000,
                    first,
                    cause: AuthFailureCause::TableFull,
                };
            }
        }
        AuthFailureCheck::Allowed
    }

    /// 记录一次认证失败；返回 true 表示这是该 IP 本窗口第一条失败（用于 WARN 采样）。
    ///
    /// `limit == 0`（关闭限速）时仍记录采样窗口：它只影响日志级别，不参与限速判定，
    /// 因此不会恢复 429。表满时新来源仍返回 false，保持 `AUTH_FAILURE_TABLE_CAPACITY`
    /// 的硬上界（此时该来源本轮无 WARN，属可接受的观测损失）。
    pub(crate) fn record_failure(&self, ip: IpAddr) -> bool {
        let now = (self.now_ms)();
        let mut table = self.lock_table();
        if table
            .windows
            .get(&ip)
            .is_some_and(|window| window.is_expired(now))
        {
            table.windows.remove(&ip);
        }
        if let Some(window) = table.windows.get_mut(&ip) {
            window.failures = window.failures.saturating_add(1);
            return false;
        }
        // 正常流程由 check 先保证容量；这里兜底，满表时丢弃新来源的计数。
        if table.windows.len() >= AUTH_FAILURE_TABLE_CAPACITY {
            table.windows.retain(|_, window| !window.is_expired(now));
            if table.windows.len() >= AUTH_FAILURE_TABLE_CAPACITY {
                return false;
            }
        }
        table.windows.insert(
            ip,
            AuthFailureWindow {
                started_at: now,
                failures: 1,
                limited_logged: false,
            },
        );
        true
    }

    /// 认证成功（含旧 admin_token 命中）时清空该来源的失败计数与采样窗口。
    ///
    /// `limit == 0` 时同样清空：否则成功登录后下一次失败仍会被当作同窗口后续失败，
    /// 失去首条 WARN 采样。
    pub(crate) fn clear(&self, ip: IpAddr) {
        self.lock_table().windows.remove(&ip);
    }

    /// 当前记录的来源数量（测试 / 排障）。
    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        self.lock_table().windows.len()
    }
}

/// 401 或失败限速 429 的拒绝结果。
enum AuthRejection {
    /// 认证失败：携带日志分类与本窗口是否首条失败。
    Unauthorized {
        failure: AuthFailure,
        first_in_window: bool,
    },
    /// 未认证失败超限，固定 429。
    RateLimited {
        retry_after: u64,
        first: bool,
        cause: AuthFailureCause,
    },
}

/// 认证失败时先记一次失败，再构造 401 拒绝。
fn reject_with_failure(state: &AppState, ip: IpAddr, failure: AuthFailure) -> AuthRejection {
    let first_in_window = state.auth_failures.record_failure(ip);
    AuthRejection::Unauthorized {
        failure,
        first_in_window,
    }
}

/// 查未认证失败限速；已超限时返回 429 拒绝。
fn check_failure_limit(state: &AppState, ip: IpAddr) -> Option<AuthRejection> {
    match state.auth_failures.check(ip) {
        AuthFailureCheck::Allowed => None,
        AuthFailureCheck::Limited {
            retry_after,
            first,
            cause,
        } => Some(AuthRejection::RateLimited {
            retry_after,
            first,
            cause,
        }),
    }
}

/// 管理 API 鉴权 + 未认证失败限速 + 已认证请求限速 + scope 授权中间件。
///
/// 401 固定 `{"error":"unauthorized"}`，403 固定 `{"error":"forbidden_scope"}`，
/// 429 固定 `{"error":"rate_limited"}`；三者都不写审计、不回显 token。
pub(crate) async fn require_auth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let ip = peer.ip();
    let principal = match resolve_principal(&state, request.headers(), ip).await {
        Ok(principal) => principal,
        Err(AuthRejection::RateLimited {
            retry_after,
            first,
            cause,
        }) => {
            log_rate_limited(ip, retry_after, first, cause);
            return rate_limited(retry_after);
        }
        Err(AuthRejection::Unauthorized {
            failure,
            first_in_window,
        }) => {
            log_auth_failure(ip, &failure, first_in_window);
            return unauthorized();
        }
    };

    // 只有认证成功的请求才消耗已认证请求额度（沿用 v0.2.1 KI-05 顺序）。
    let is_write = crate::is_admin_write_method(request.method());
    if let Err(retry_after) = state.admin_rate.check(ip, is_write) {
        return rate_limited(retry_after);
    }

    // 只对「已知路由 + 方法」做 scope 校验；未知路由留给 axum 返回 404/405。
    if let Some(required) = required_scope(request.method(), request.uri().path()) {
        if !scope_allows(principal.scope, required) {
            tracing::warn!(
                ip = %ip,
                token_name = %principal.name,
                path = %request.uri().path(),
                required = required.as_str(),
                "管理 API token scope 不足"
            );
            return forbidden_scope();
        }
    }

    request.extensions_mut().insert(principal);
    next.run(request).await
}

/// 采样后的日志级别：每 IP 每窗口首条失败 / 首次 429 用 WARN，其余 DEBUG。
///
/// 抽成纯函数便于确定性测试，不依赖 `tracing` subscriber 的线程局部状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SampledLevel {
    Warn,
    Debug,
}

impl SampledLevel {
    fn for_failure(first_in_window: bool) -> Self {
        if first_in_window {
            Self::Warn
        } else {
            Self::Debug
        }
    }

    fn for_rate_limit(first: bool) -> Self {
        if first {
            Self::Warn
        } else {
            Self::Debug
        }
    }
}

/// 认证失败日志：每 IP 每窗口只 WARN 第一条失败，其余降为 debug，避免 401 洪水刷屏。
fn log_auth_failure(ip: IpAddr, failure: &AuthFailure, first_in_window: bool) {
    match (SampledLevel::for_failure(first_in_window), failure) {
        (SampledLevel::Warn, AuthFailure::Unauthorized) => {
            tracing::warn!(ip = %ip, "管理 API 鉴权失败");
        }
        (SampledLevel::Debug, AuthFailure::Unauthorized) => {
            tracing::debug!(ip = %ip, "管理 API 鉴权失败");
        }
        (SampledLevel::Warn, AuthFailure::IllegalScope(name)) => {
            tracing::warn!(
                ip = %ip,
                token_name = %name,
                "api_tokens.scope 非法，按未认证处理"
            );
        }
        (SampledLevel::Debug, AuthFailure::IllegalScope(name)) => {
            tracing::debug!(
                ip = %ip,
                token_name = %name,
                "api_tokens.scope 非法，按未认证处理"
            );
        }
        (SampledLevel::Warn, AuthFailure::Backend(err)) => {
            tracing::warn!(
                ip = %ip,
                error = %err,
                "校验 api_token 失败，按未认证拒绝"
            );
        }
        (SampledLevel::Debug, AuthFailure::Backend(err)) => {
            tracing::debug!(
                ip = %ip,
                error = %err,
                "校验 api_token 失败，按未认证拒绝"
            );
        }
    }
}

/// 429 日志：每 IP 每窗口只在首次触发时 WARN，其余降为 debug。
fn log_rate_limited(ip: IpAddr, retry_after: u64, first: bool, cause: AuthFailureCause) {
    let cause = match cause {
        AuthFailureCause::Failures => "failures",
        AuthFailureCause::TableFull => "table_full",
    };
    match SampledLevel::for_rate_limit(first) {
        SampledLevel::Warn => tracing::warn!(
            ip = %ip,
            retry_after,
            cause,
            "管理 API 未认证请求被失败限速，返回 429"
        ),
        SampledLevel::Debug => tracing::debug!(
            ip = %ip,
            retry_after,
            cause,
            "管理 API 未认证请求继续被失败限速"
        ),
    }
}

/// 认证主体解析：旧 admin_token 优先，其次在失败限速额度内查 scoped token。
async fn resolve_principal(
    state: &AppState,
    headers: &HeaderMap,
    ip: IpAddr,
) -> Result<AuthPrincipal, AuthRejection> {
    // 1. 缺失 / 格式错误：先查限速，未超限记一次失败后 401。
    let Some(token) = bearer_token(headers) else {
        if let Some(rejection) = check_failure_limit(state, ip) {
            return Err(rejection);
        }
        return Err(reject_with_failure(state, ip, AuthFailure::Unauthorized));
    };

    // 2. 兼容路径：常量时间比较旧 admin_token；命中即清空失败计数，不受限速影响。
    //    空 token 永远不匹配。
    if bearer_matches(headers, &state.cfg.admin_token) {
        state.auth_failures.clear(ip);
        return Ok(AuthPrincipal {
            name: "admin".to_string(),
            scope: TokenScope::Admin,
            legacy: true,
        });
    }

    // 3. scoped token：先查失败限速；已超限直接 429，不计算 SHA-256、不查库。
    if let Some(rejection) = check_failure_limit(state, ip) {
        return Err(rejection);
    }

    let token_hash = sha256_hex(token);
    let now = now_ms();
    let storage = state.storage.clone();
    let lookup =
        tokio::task::spawn_blocking(move || storage.authenticate_api_token(&token_hash, now)).await;
    let record = match lookup {
        Ok(Ok(record)) => record,
        Ok(Err(err)) => {
            return Err(reject_with_failure(
                state,
                ip,
                AuthFailure::Backend(err.to_string()),
            ));
        }
        Err(err) => {
            return Err(reject_with_failure(
                state,
                ip,
                AuthFailure::Backend(err.to_string()),
            ));
        }
    };

    let Some(record) = record else {
        return Err(reject_with_failure(state, ip, AuthFailure::Unauthorized));
    };
    let Some(scope) = TokenScope::parse(&record.scope) else {
        return Err(reject_with_failure(
            state,
            ip,
            AuthFailure::IllegalScope(record.name),
        ));
    };
    state.auth_failures.clear(ip);
    Ok(AuthPrincipal {
        name: record.name,
        scope,
        legacy: false,
    })
}

/// 解析 `Authorization: Bearer <token>`，只接受「scheme + 单个 token」两段。
///
/// scheme 大小写不敏感；多余分段（token 里带空格）与空 token 直接拒绝。
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let mut parts = value.split_ascii_whitespace();
    let (Some(scheme), Some(token), None, None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }
    Some(token)
}

/// 当前请求携带的 Bearer token 是否等于 `expected`（常量时间比较）。
///
/// 旧 `admin_token` 兼容路径与既有单测都走这里；`expected` 为空永远不匹配。
pub(crate) fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    bearer_token(headers)
        .is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()))
}

/// 已知路由所需的 scope；未知路由 / 方法返回 `None`（认证后交给路由 404/405）。
///
/// 精确到「路径 + 方法」，不能按 HTTP 方法一刀切：`GET /api/v1/agents/{id}/control`
/// 是只读（Read），而 `POST` 同一路径才是 Write。
pub(crate) fn required_scope(method: &Method, path: &str) -> Option<TokenScope> {
    let is_read_route = matches!(
        path,
        "/api/v1/system"
            | "/api/v1/agents"
            | "/api/v1/series"
            | "/api/v1/overview"
            | "/api/v1/audit"
            // M4-B1：规则 / 事件 / 静默查询只读；写操作在下面单独映射为 Write。
            | "/api/v1/alerts/rules"
            | "/api/v1/alerts/events"
            | "/api/v1/alerts/silences"
            // M4-B2b：渠道列表只读；CRUD / 测试发送为 Write。
            | "/api/v1/alerts/channels"
            // M4-C1b：归档状态只读；下载 / 对象列表属于 C4。
            | "/api/v1/archive/status"
    ) || ["/latest", "/series", "/settings", "/control"]
        .iter()
        .any(|suffix| is_agent_subroute(path, suffix));

    if *method == Method::GET || *method == Method::HEAD {
        return is_read_route.then_some(TokenScope::Read);
    }
    if *method == Method::POST && path == "/api/v1/alerts/rules" {
        return Some(TokenScope::Write);
    }
    if (*method == Method::PUT || *method == Method::DELETE) && is_alert_rule_subroute(path) {
        return Some(TokenScope::Write);
    }
    // M4-B1b：创建 / 撤销静默都需要 Write；事件只读。
    if *method == Method::POST && path == "/api/v1/alerts/silences" {
        return Some(TokenScope::Write);
    }
    if *method == Method::DELETE && is_alert_silence_subroute(path) {
        return Some(TokenScope::Write);
    }
    // M4-B2b：渠道集合只接受 GET / POST；单段子路径接受 PUT / DELETE；
    // `{id}/test` 只接受 POST。未知组合保持 None，认证后交给路由 404/405。
    if *method == Method::POST && path == "/api/v1/alerts/channels" {
        return Some(TokenScope::Write);
    }
    if (*method == Method::PUT || *method == Method::DELETE) && is_alert_channel_subroute(path) {
        return Some(TokenScope::Write);
    }
    if *method == Method::POST && is_alert_channel_test_subroute(path) {
        return Some(TokenScope::Write);
    }
    if *method == Method::POST && is_agent_subroute(path, "/control") {
        return Some(TokenScope::Write);
    }
    if *method == Method::PUT && is_agent_subroute(path, "/settings") {
        return Some(TokenScope::Write);
    }
    None
}

/// 匹配 `/api/v1/alerts/rules/<id>`；`<id>` 必须是非空单段（内置 id 是
/// `builtin-*`，自定义是 UUID，都只有一段）。
fn is_alert_rule_subroute(path: &str) -> bool {
    path.strip_prefix("/api/v1/alerts/rules/")
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// 匹配 `/api/v1/alerts/silences/<id>`；`<id>` 必须是非空单段。
fn is_alert_silence_subroute(path: &str) -> bool {
    path.strip_prefix("/api/v1/alerts/silences/")
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// 匹配 `/api/v1/alerts/channels/<id>`；`<id>` 必须是非空单段。
fn is_alert_channel_subroute(path: &str) -> bool {
    path.strip_prefix("/api/v1/alerts/channels/")
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// 匹配 `/api/v1/alerts/channels/<id>/test`；`<id>` 必须是非空单段。
fn is_alert_channel_test_subroute(path: &str) -> bool {
    path.strip_prefix("/api/v1/alerts/channels/")
        .and_then(|rest| rest.strip_suffix("/test"))
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// 匹配 `/api/v1/agents/<id><suffix>`；`<id>` 必须是非空单段。
fn is_agent_subroute(path: &str, suffix: &str) -> bool {
    path.strip_prefix("/api/v1/agents/")
        .and_then(|rest| rest.strip_suffix(suffix))
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// 固定 429：`Retry-After` 夹到 1..=60 秒，不回显 token，也不写审计。
fn rate_limited(retry_after: u64) -> Response {
    let retry_after = retry_after.clamp(1, 60);
    let mut response = (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({ "error": "rate_limited" })),
    )
        .into_response();
    response.headers_mut().insert(
        header::RETRY_AFTER,
        HeaderValue::from_str(&retry_after.to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("60")),
    );
    response
}

/// 固定 401：不带 token / 内部错误信息，只告诉客户端该用 Bearer。
fn unauthorized() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// 固定 403：已认证但 scope 不足；不进入 handler，也不写控制审计。
fn forbidden_scope() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "forbidden_scope" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// scope 是全序层级：read < write < admin，低 scope 不能越级。
    #[test]
    fn scope_hierarchy_is_total_order() {
        use TokenScope::{Admin, Read, Write};

        assert!(scope_allows(Read, Read));
        assert!(!scope_allows(Read, Write));
        assert!(!scope_allows(Read, Admin));

        assert!(scope_allows(Write, Read));
        assert!(scope_allows(Write, Write));
        assert!(!scope_allows(Write, Admin));

        assert!(scope_allows(Admin, Read));
        assert!(scope_allows(Admin, Write));
        assert!(scope_allows(Admin, Admin));
    }

    #[test]
    fn scope_string_roundtrip_and_invalid_values() {
        for scope in [TokenScope::Read, TokenScope::Write, TokenScope::Admin] {
            assert_eq!(TokenScope::parse(scope.as_str()), Some(scope));
        }
        for invalid in ["", "root", "READ", "write ", "admin\n"] {
            assert_eq!(TokenScope::parse(invalid), None, "value={invalid:?}");
        }
    }

    /// 精确路由映射：GET 全部只读；control POST / settings PUT 才需要 Write。
    #[test]
    fn required_scope_maps_known_routes_only() {
        use TokenScope::{Read, Write};

        for path in [
            "/api/v1/system",
            "/api/v1/agents",
            "/api/v1/series",
            "/api/v1/overview",
            "/api/v1/audit",
            "/api/v1/agents/a1/latest",
            "/api/v1/agents/a1/series",
            "/api/v1/agents/a1/settings",
            "/api/v1/agents/a1/control",
            "/api/v1/alerts/rules",
            "/api/v1/alerts/events",
            "/api/v1/alerts/silences",
            "/api/v1/alerts/channels",
            "/api/v1/archive/status",
        ] {
            assert_eq!(
                required_scope(&Method::GET, path),
                Some(Read),
                "path={path}"
            );
            assert_eq!(
                required_scope(&Method::HEAD, path),
                Some(Read),
                "path={path}"
            );
        }
        assert_eq!(
            required_scope(&Method::POST, "/api/v1/agents/a1/control"),
            Some(Write)
        );
        assert_eq!(
            required_scope(&Method::PUT, "/api/v1/agents/a1/settings"),
            Some(Write)
        );
        // M4-B1：规则写接口必须 Write；内置 id 与 UUID 走同一路径规则。
        for (method, path) in [
            (&Method::POST, "/api/v1/alerts/rules"),
            (&Method::PUT, "/api/v1/alerts/rules/rule-1"),
            (&Method::PUT, "/api/v1/alerts/rules/builtin-agent-offline"),
            (&Method::DELETE, "/api/v1/alerts/rules/rule-1"),
            (
                &Method::DELETE,
                "/api/v1/alerts/rules/builtin-agent-offline",
            ),
            // M4-B1b：静默创建 / 撤销必须 Write。
            (&Method::POST, "/api/v1/alerts/silences"),
            (&Method::DELETE, "/api/v1/alerts/silences/12"),
            // M4-B2b：渠道 CRUD 与测试发送必须 Write。
            (&Method::POST, "/api/v1/alerts/channels"),
            (
                &Method::PUT,
                "/api/v1/alerts/channels/0b6f9a2e-6a1d-4c5e-9f3a-1d2c3b4a5e6f",
            ),
            (
                &Method::DELETE,
                "/api/v1/alerts/channels/0b6f9a2e-6a1d-4c5e-9f3a-1d2c3b4a5e6f",
            ),
            (
                &Method::POST,
                "/api/v1/alerts/channels/0b6f9a2e-6a1d-4c5e-9f3a-1d2c3b4a5e6f/test",
            ),
        ] {
            assert_eq!(
                required_scope(method, path),
                Some(Write),
                "method={method} path={path}"
            );
        }
        // 规则集合只接受 GET / POST；PUT / DELETE 集合路径不是已知路由。
        for (method, path) in [
            (&Method::PUT, "/api/v1/alerts/rules"),
            (&Method::DELETE, "/api/v1/alerts/rules"),
            // 子路径必须是单段；多段或空段交给路由 404，不提前 403。
            (&Method::PUT, "/api/v1/alerts/rules/"),
            (&Method::DELETE, "/api/v1/alerts/rules/a/b"),
            (&Method::POST, "/api/v1/alerts/rules/rule-1"),
            (&Method::GET, "/api/v1/alerts/rules/rule-1"),
            // 事件 / 静默集合只接受已声明的方法。
            (&Method::PUT, "/api/v1/alerts/events"),
            (&Method::POST, "/api/v1/alerts/events"),
            (&Method::DELETE, "/api/v1/alerts/events"),
            (&Method::PUT, "/api/v1/alerts/silences"),
            (&Method::DELETE, "/api/v1/alerts/silences"),
            // 静默子路径只允许 DELETE，且必须是单段。
            (&Method::GET, "/api/v1/alerts/silences/12"),
            (&Method::POST, "/api/v1/alerts/silences/12"),
            (&Method::DELETE, "/api/v1/alerts/silences/"),
            (&Method::DELETE, "/api/v1/alerts/silences/a/b"),
            (&Method::GET, "/api/v1/alerts/events/1"),
            // 渠道：集合不接 PUT / DELETE，子路径只接 PUT / DELETE，测试只接 POST。
            (&Method::PUT, "/api/v1/alerts/channels"),
            (&Method::DELETE, "/api/v1/alerts/channels"),
            (&Method::GET, "/api/v1/alerts/channels/abc"),
            (&Method::PUT, "/api/v1/alerts/channels/"),
            (&Method::DELETE, "/api/v1/alerts/channels/a/b"),
            (&Method::GET, "/api/v1/alerts/channels/abc/test"),
            (&Method::PUT, "/api/v1/alerts/channels/abc/test"),
            (&Method::DELETE, "/api/v1/alerts/channels/abc/test"),
            (&Method::POST, "/api/v1/alerts/channels/a/b/test"),
        ] {
            assert_eq!(
                required_scope(method, path),
                None,
                "method={method} path={path}"
            );
        }

        // 未知路径 / 已知路径的错误方法 → None：认证后交给路由 404/405，
        // read token 不能因为「路径未知」或「方法不匹配」被 403 挡住。
        for (method, path) in [
            (&Method::GET, "/api/v1/nope"),
            (&Method::POST, "/api/v1/nope"),
            (&Method::PUT, "/api/v1/nope"),
            (&Method::DELETE, "/api/v1/agents/a1/settings"),
            (&Method::POST, "/api/v1/agents"),
            (&Method::GET, "/api/v1/agents/"),
            (&Method::GET, "/api/v1/agents/a1/settings/extra"),
            (&Method::POST, "/api/v1/agents/a1/settings"),
        ] {
            assert_eq!(
                required_scope(method, path),
                None,
                "method={method} path={path}"
            );
        }
    }

    #[test]
    fn bearer_parsing_is_strict_and_case_insensitive() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        assert!(!bearer_matches(&headers, "secret"));
        assert!(!bearer_matches(&headers, ""));

        for scheme in ["Bearer", "bearer", "BEARER", "bEaReR"] {
            let value = format!("{scheme} secret");
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&value).unwrap(),
            );
            assert_eq!(bearer_token(&headers), Some("secret"), "scheme={scheme}");
            assert!(bearer_matches(&headers, "secret"), "scheme={scheme}");
            assert!(!bearer_matches(&headers, "wrong"), "scheme={scheme}");
        }

        for value in [
            "secret",
            "Bearer",
            "Bearer secret extra",
            "Basic secret",
            "Bearer ",
        ] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
            assert_eq!(bearer_token(&headers), None, "value={value}");
            assert!(!bearer_matches(&headers, "secret"), "value={value}");
        }

        // 多个 Authorization 头：只取第一个，不能因为后面有一个合法值就放行。
        let mut multiple = HeaderMap::new();
        multiple.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer first"),
        );
        multiple.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert_eq!(bearer_token(&multiple), Some("first"));
        assert!(bearer_matches(&multiple, "first"));
        assert!(!bearer_matches(&multiple, "second"));
    }

    // ------------------------------------------------------------------
    // v0.3.4 KI-26：未认证失败限速（可注入时钟，不 sleep）
    // ------------------------------------------------------------------

    /// 60 次失败允许（第 60 次仍是 401），第 61 次检查返回 Limited；
    /// 每窗口只有第一条失败与首次 429 需要 WARN 采样。
    #[test]
    fn v034_auth_failure_limiter_allows_limit_then_limits() {
        use std::sync::atomic::{AtomicI64, Ordering};

        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let limiter =
            AuthFailureLimiter::with_clock(60, Arc::new(move || clock.load(Ordering::Relaxed)));
        let ip: IpAddr = "203.0.113.10".parse().unwrap();

        for attempt in 1..=60 {
            assert_eq!(
                limiter.check(ip),
                AuthFailureCheck::Allowed,
                "第 {attempt} 次检查必须允许"
            );
            assert_eq!(
                limiter.record_failure(ip),
                attempt == 1,
                "只有每窗口第一条失败返回 true"
            );
        }
        // 第 61 次：第一次触发带 first=true，用于 WARN；之后只 debug。
        assert_eq!(
            limiter.check(ip),
            AuthFailureCheck::Limited {
                retry_after: 60,
                first: true,
                cause: AuthFailureCause::Failures,
            }
        );
        assert_eq!(
            limiter.check(ip),
            AuthFailureCheck::Limited {
                retry_after: 60,
                first: false,
                cause: AuthFailureCause::Failures,
            }
        );
    }

    /// 窗口边界：Retry-After 始终落在 1..=60 秒；恰好 60s 后恢复并重新采样 WARN。
    #[test]
    fn v034_auth_failure_limiter_window_boundary_and_retry_after() {
        use std::sync::atomic::{AtomicI64, Ordering};

        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let limiter =
            AuthFailureLimiter::with_clock(1, Arc::new(move || clock.load(Ordering::Relaxed)));
        let ip: IpAddr = "203.0.113.11".parse().unwrap();
        assert_eq!(limiter.check(ip), AuthFailureCheck::Allowed);
        assert!(limiter.record_failure(ip));

        // 同一窗口内 Retry-After 向上取整到秒，且不超过 60。
        for (elapsed_ms, expected) in [(0_i64, 60_u64), (1, 60), (30_000, 30), (59_999, 1)] {
            now.store(1_000_000 + elapsed_ms, Ordering::Relaxed);
            assert_eq!(
                limiter.check(ip),
                AuthFailureCheck::Limited {
                    retry_after: expected,
                    first: elapsed_ms == 0,
                    cause: AuthFailureCause::Failures,
                },
                "elapsed={elapsed_ms}ms"
            );
        }

        // 恰好 60s：旧窗口过期，恢复允许；再次失败开启新窗口并重新采样。
        now.store(1_000_000 + AUTH_FAILURE_WINDOW_MS, Ordering::Relaxed);
        assert_eq!(limiter.check(ip), AuthFailureCheck::Allowed);
        assert!(
            limiter.record_failure(ip),
            "新窗口第一条失败必须重新采样 WARN"
        );
        assert_eq!(
            limiter.check(ip),
            AuthFailureCheck::Limited {
                retry_after: 60,
                first: true,
                cause: AuthFailureCause::Failures,
            }
        );
    }

    /// 不同来源 IP 独立计数；limit=0 关闭限速但保留有界采样窗口。
    #[test]
    fn v034_auth_failure_limiter_is_per_ip_and_can_be_disabled() {
        use std::sync::atomic::{AtomicI64, Ordering};

        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let limiter =
            AuthFailureLimiter::with_clock(2, Arc::new(move || clock.load(Ordering::Relaxed)));
        let ip_a: IpAddr = "198.51.100.1".parse().unwrap();
        let ip_b: IpAddr = "198.51.100.2".parse().unwrap();

        for _ in 0..2 {
            assert_eq!(limiter.check(ip_a), AuthFailureCheck::Allowed);
            limiter.record_failure(ip_a);
        }
        assert!(matches!(
            limiter.check(ip_a),
            AuthFailureCheck::Limited { .. }
        ));
        assert_eq!(
            limiter.check(ip_b),
            AuthFailureCheck::Allowed,
            "不同 IP 必须独立计数"
        );

        // 认证成功（旧 admin_token 命中）清空计数。
        limiter.clear(ip_a);
        assert_eq!(limiter.check(ip_a), AuthFailureCheck::Allowed);

        // limit=0：限速关闭（check 恒 Allowed），但仍保留一条采样窗口服务 WARN。
        let disabled = AuthFailureLimiter::with_clock(0, Arc::new(|| 1_000_000));
        assert_eq!(disabled.check(ip_a), AuthFailureCheck::Allowed);
        assert!(
            disabled.record_failure(ip_a),
            "关闭限速后首条失败仍要采样 WARN"
        );
        for _ in 0..100 {
            assert_eq!(disabled.check(ip_a), AuthFailureCheck::Allowed);
            assert!(!disabled.record_failure(ip_a), "同窗口后续失败只记 DEBUG");
        }
        assert_eq!(disabled.tracked_ips(), 1, "关闭限速时只为采样保留有界窗口");
    }

    /// v0.3.5：`limit = 0` 关闭限速但保留首条 WARN 采样。
    ///
    /// 覆盖：首条失败 → WARN、同窗口第二条 → DEBUG、`check` 始终 `Allowed`（不恢复
    /// 429）、采样表有界、`clear` 后与窗口过期后可再次采样。确定性时钟，不依赖
    /// 全局 tracing subscriber。
    #[test]
    fn v035_zero_limit_keeps_first_failure_warn_sample() {
        use std::sync::atomic::{AtomicI64, Ordering};

        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let limiter =
            AuthFailureLimiter::with_clock(0, Arc::new(move || clock.load(Ordering::Relaxed)));
        let ip: IpAddr = "203.0.113.30".parse().unwrap();

        assert_eq!(limiter.check(ip), AuthFailureCheck::Allowed);
        assert_eq!(
            SampledLevel::for_failure(limiter.record_failure(ip)),
            SampledLevel::Warn,
            "关闭限速后每窗口首条失败仍必须 WARN"
        );
        assert_eq!(
            SampledLevel::for_failure(limiter.record_failure(ip)),
            SampledLevel::Debug,
            "同窗口后续失败不得刷屏"
        );
        assert_eq!(
            limiter.check(ip),
            AuthFailureCheck::Allowed,
            "limit=0 不得因为采样窗口恢复 429"
        );
        assert!(
            limiter.tracked_ips() <= 1,
            "limit=0 只保留有界采样窗口，实际 tracked={}",
            limiter.tracked_ips()
        );

        // 认证成功后清空采样窗口：下一次失败重新 WARN。
        limiter.clear(ip);
        assert_eq!(limiter.tracked_ips(), 0, "clear 必须清空采样窗口");
        assert!(
            limiter.record_failure(ip),
            "clear 后下一次失败必须重新采样 WARN"
        );
        assert!(limiter.tracked_ips() <= 1);

        // 窗口过期后重新采样，且仍不参与限速。
        now.store(1_000_000 + AUTH_FAILURE_WINDOW_MS, Ordering::Relaxed);
        assert!(
            limiter.record_failure(ip),
            "新窗口首条失败必须重新采样 WARN"
        );
        assert!(limiter.tracked_ips() <= 1);
        assert_eq!(limiter.check(ip), AuthFailureCheck::Allowed);
    }

    /// 容量 4096：满且无过期项时拒绝新来源；逐窗口只 WARN 一次容量告警；
    /// 推进一个窗口后可清理过期项并恢复。
    #[test]
    fn v034_auth_failure_limiter_table_capacity_is_bounded() {
        use std::sync::atomic::{AtomicI64, Ordering};

        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let limiter =
            AuthFailureLimiter::with_clock(600, Arc::new(move || clock.load(Ordering::Relaxed)));
        for index in 0..AUTH_FAILURE_TABLE_CAPACITY {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(index as u32));
            assert!(limiter.record_failure(ip), "容量内必须记录");
        }
        assert_eq!(limiter.tracked_ips(), AUTH_FAILURE_TABLE_CAPACITY);

        let overflow: IpAddr = "203.0.113.99".parse().unwrap();
        assert_eq!(
            limiter.check(overflow),
            AuthFailureCheck::Limited {
                retry_after: 60,
                first: true,
                cause: AuthFailureCause::TableFull,
            }
        );
        assert_eq!(
            limiter.check(overflow),
            AuthFailureCheck::Limited {
                retry_after: 60,
                first: false,
                cause: AuthFailureCause::TableFull,
            },
            "同一窗口内容量告警只 WARN 一次"
        );
        assert!(!limiter.record_failure(overflow), "满表时新来源不记录");
        assert_eq!(limiter.tracked_ips(), AUTH_FAILURE_TABLE_CAPACITY);

        // 推进一个窗口：过期项可清理，新来源恢复允许。
        now.store(1_000_000 + AUTH_FAILURE_WINDOW_MS, Ordering::Relaxed);
        assert_eq!(limiter.check(overflow), AuthFailureCheck::Allowed);
        assert!(limiter.record_failure(overflow));
        assert!(limiter.tracked_ips() <= AUTH_FAILURE_TABLE_CAPACITY);
    }

    /// 日志采样策略（确定性，不依赖全局 subscriber）：
    /// 只有每窗口首条失败与首次 429 用 WARN，其余 debug；
    /// 标志直接来自限速器返回值，串联验证不会每个请求都 WARN。
    #[test]
    fn v034_auth_failure_log_sampling_is_warn_only_once() {
        use std::sync::atomic::{AtomicI64, Ordering};

        // 纯函数决策。
        assert_eq!(SampledLevel::for_failure(true), SampledLevel::Warn);
        assert_eq!(SampledLevel::for_failure(false), SampledLevel::Debug);
        assert_eq!(SampledLevel::for_rate_limit(true), SampledLevel::Warn);
        assert_eq!(SampledLevel::for_rate_limit(false), SampledLevel::Debug);

        // 与限速器串联：limit=3，前两次失败 WARN/Debug，第 3 次失败仍是 Debug
        // （401），第 4 次请求首次 429 才是 WARN，第 5 次恢复 Debug。
        let now = Arc::new(AtomicI64::new(1_000_000));
        let clock = now.clone();
        let limiter =
            AuthFailureLimiter::with_clock(3, Arc::new(move || clock.load(Ordering::Relaxed)));
        let ip: IpAddr = "203.0.113.20".parse().unwrap();

        let mut levels = Vec::new();
        for _ in 0..3 {
            levels.push(SampledLevel::for_failure(limiter.record_failure(ip)));
        }
        assert_eq!(
            levels,
            vec![SampledLevel::Warn, SampledLevel::Debug, SampledLevel::Debug],
            "每窗口只有首条失败 WARN"
        );

        let mut limited_levels = Vec::new();
        for _ in 0..2 {
            match limiter.check(ip) {
                AuthFailureCheck::Limited { first, .. } => {
                    limited_levels.push(SampledLevel::for_rate_limit(first));
                }
                AuthFailureCheck::Allowed => panic!("达到阈值后必须 Limited"),
            }
        }
        assert_eq!(
            limited_levels,
            vec![SampledLevel::Warn, SampledLevel::Debug],
            "首次 429 只 WARN 一次"
        );
    }
}
