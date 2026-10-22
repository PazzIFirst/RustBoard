//! RustBoard 面板进程。
//!
//! 负责：单管理员登录（Argon2id + 内存会话）、把同源 `/api/*` 转发到 hub 管理 API、
//! 以及提供前端构建产物与 SPA 回退。hub 管理 token 只存在于本进程配置中，
//! 既不下发浏览器，也不写进日志。

mod auth;
mod proxy;
mod web;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path as AxumPath, RawQuery, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{any, get, post};
use axum::Router;
use clap::{Parser, Subcommand};
use rand::distributions::Alphanumeric;
use rand::Rng;
use rustboard_common::config::{HubConfig, PanelConfig};
use rustboard_common::util::{now_ms, pick_free_port, port_of};
use rustboard_common::{
    DEFAULT_ADMIN_PORT, DEFAULT_HUB_CONFIG, DEFAULT_PANEL_CONFIG, DEFAULT_PANEL_PORT,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Semaphore;

/// 登录 / 设置 / 控制面请求体上限。
const MAX_JSON_BODY: usize = 8 * 1024;
/// 同时进行的 Argon2 校验上限，避免 64 MiB × N 的内存 DoS。
const MAX_CONCURRENT_ARGON2: usize = 2;
/// 自动生成的密码长度。
const GENERATED_PASSWORD_LEN: usize = 20;
/// 密码最短长度（仅约束 init 写入的密码）。
const MIN_PASSWORD_LEN: usize = 8;
/// series 查询最大跨度（32 天）。
const MAX_SERIES_SPAN_MS: i64 = 32 * 24 * 3600 * 1000;
/// overview 的 `window_ms` 下限：与 hub 侧 overview 的 1s 下限对齐。
const MIN_OVERVIEW_WINDOW_MS: i64 = 1_000;
/// latest 的 `window_ms` 下限：与 hub 侧 latest 一致，最小 1ms。
const MIN_LATEST_WINDOW_MS: i64 = 1;
/// `window_ms` 上限 1 小时（overview / latest 相同）。
const MAX_WINDOW_MS: i64 = 3_600_000;
/// 控制面 POST 允许的字段白名单。
///
/// 面板只校验结构与长度；能力是否开启、目标是否白名单、是否需要 `confirm`
/// 等业务规则由 hub 统一裁决，避免两处规则不一致。
const CONTROL_FIELDS: [&str; 9] = [
    "capability",
    "action",
    "target",
    "pid",
    "name",
    "signal",
    "source",
    "lines",
    "confirm",
];
/// 控制请求里 target / source / name 的最大字节数。
const MAX_CONTROL_TARGET_LEN: usize = 128;
/// 控制请求里 action 的最大字节数。
const MAX_CONTROL_ACTION_LEN: usize = 32;
/// 控制请求里 capability / signal 等枚举短值的最大字节数。
const MAX_CONTROL_ENUM_LEN: usize = 32;
/// 控制请求里 pid 的上限：协议字段是 u32。
const MAX_CONTROL_PID: u64 = u32::MAX as u64;
/// 日志 tail 行数下限。
const MIN_CONTROL_LINES: u64 = 1;
/// 日志 tail 行数上限（与 agent 的 `max_log_lines` 上限一致）。
const MAX_CONTROL_LINES: u64 = 2_000;
/// 审计分页上限；与 hub 的 `MAX_AUDIT_LIMIT` 对齐（前端默认仍取 100）。
const MAX_AUDIT_LIMIT: i64 = 200;
/// 审计 capability 过滤值的最大字节数。
const MAX_AUDIT_CAPABILITY_LEN: usize = 32;
/// 面板是明文 HTTP，CSP 只允许同源资源；uPlot 运行时写入的 style 属性靠
/// `style-src 'unsafe-inline'` 放行，但禁止任何内联/外部脚本注入。
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; script-src 'self'; \
     style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; \
     frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

#[derive(Parser)]
#[command(name = "rustboard-panel", version, about = "RustBoard 面板")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 启动面板。
    Run {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        hub: Option<String>,
    },
    /// 生成面板配置、密码哈希与 hub 连接参数。
    Init {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        listen: Option<String>,
        #[arg(long)]
        hub: Option<String>,
        #[arg(long)]
        hub_token: Option<String>,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        static_dir: Option<String>,
        #[arg(long)]
        force: bool,
    },
    /// 查看当前使用的端口与访问地址。
    Ports {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 重置管理员密码（不传 --password 时自动生成 20 位随机密码）。
    ResetPassword {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        password: Option<String>,
    },
}

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rustboard_panel=info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match Cli::parse().cmd {
        Cmd::Init {
            config,
            listen,
            hub,
            hub_token,
            password,
            static_dir,
            force,
        } => init(config, listen, hub, hub_token, password, static_dir, force),
        Cmd::Ports { config } => ports(config),
        Cmd::ResetPassword { config, password } => reset_password(config, password),
        Cmd::Run {
            config,
            listen,
            hub,
        } => run(config, listen, hub),
    }
}

/// 面板运行期状态。所有内存表与 HTTP 客户端放在一起，便于测试装配。
struct AppState {
    cfg: PanelConfig,
    sessions: auth::SessionStore,
    limiter: auth::LoginLimiter,
    proxy: proxy::ProxyClient,
    static_files: Option<web::StaticFiles>,
    /// 当前生效的密码哈希；`reset-password` 后由轮询任务热更新。
    password_hash: Arc<RwLock<String>>,
    /// 配置文件路径；`None` 表示测试装配，不启用热加载。
    config_path: Option<PathBuf>,
    argon2_slots: Arc<Semaphore>,
    /// 只有这些来源的 `X-Forwarded-*` 才被采信。
    trusted_proxies: Vec<auth::IpNet>,
}

/// 轮询配置文件并热加载密码哈希的周期。
const PASSWORD_RELOAD_INTERVAL: Duration = Duration::from_secs(1);

impl AppState {
    fn new(
        cfg: PanelConfig,
        static_files: Option<web::StaticFiles>,
        config_path: Option<PathBuf>,
    ) -> Result<Self> {
        cfg.validate().context("面板配置校验失败")?;
        let trusted_proxies = auth::parse_trusted_proxies(&cfg.trusted_proxies)
            .context("解析 trusted_proxies 失败")?;
        if !auth::validate_phc(&cfg.admin_password_hash) {
            bail!(
                "admin_password_hash 为空或不是有效的 Argon2id PHC 串；请运行 `rustboard-panel init` 生成配置"
            );
        }
        if cfg.listen.trim().is_empty() {
            bail!("listen 不能为空");
        }
        let proxy =
            proxy::ProxyClient::new(&cfg.hub_url, &cfg.token).context("初始化 hub 客户端失败")?;
        let ttl_hours = cfg.session_ttl_hours.max(1);
        if cfg.session_ttl_hours == 0 {
            tracing::warn!("session_ttl_hours=0 非法，已按 1 小时处理");
        }
        let password_hash = Arc::new(RwLock::new(cfg.admin_password_hash.clone()));
        Ok(Self {
            cfg,
            sessions: auth::SessionStore::new(ttl_hours),
            limiter: auth::LoginLimiter::new(),
            proxy,
            static_files,
            password_hash,
            config_path,
            argon2_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_ARGON2)),
            trusted_proxies,
        })
    }

    /// 从磁盘重新加载配置里的密码哈希。返回 `true` 表示发生了变更。
    ///
    /// 只热加载密码哈希，不热加载监听地址 / 可信代理等需要重建监听器的字段；
    /// `reset-password` 只改哈希，因此这一范围足够且不会中断服务。
    fn reload_password_hash(&self) -> Result<bool> {
        let Some(path) = self.config_path.as_ref() else {
            return Ok(false);
        };
        let cfg = PanelConfig::load(path)
            .with_context(|| format!("热加载配置失败: {}", path.display()))?;
        if !auth::validate_phc(&cfg.admin_password_hash) {
            bail!("配置里的 admin_password_hash 不是有效 Argon2id PHC 串，保留旧密码");
        }
        let mut guard = self
            .password_hash
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if *guard == cfg.admin_password_hash {
            return Ok(false);
        }
        *guard = cfg.admin_password_hash;
        tracing::info!(path = %path.display(), "检测到面板密码变更，已热加载（无需重启）");
        Ok(true)
    }
}

/// 每秒检查配置文件内容；变化时尝试热加载密码哈希。
///
/// 比较完整文件内容而不是 mtime：`reset-password` 的原子 rename 与某些文件系统
/// 的秒级 mtime 粒度可能让 mtime 看起来不变。配置文件很小，每秒读一次成本可忽略。
fn spawn_password_reload(state: Arc<AppState>) {
    let Some(path) = state.config_path.clone() else {
        return;
    };
    // 在 spawn 之前同步读取基线：否则 reset-password 若恰好发生在任务首次被
    // 调度之前，任务会把“新内容”当成基线，永远看不到变化。
    let mut last = std::fs::read_to_string(&path).ok();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(PASSWORD_RELOAD_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let read_path = path.clone();
            let Ok(Ok(text)) =
                tokio::task::spawn_blocking(move || std::fs::read_to_string(read_path)).await
            else {
                continue;
            };
            if last.as_deref() == Some(text.as_str()) {
                continue;
            }
            last = Some(text);
            if let Err(error) = state.reload_password_hash() {
                tracing::warn!(path = %path.display(), error = %error, "密码热加载失败，保留旧密码");
            }
        }
    });
}

fn build_router(state: Arc<AppState>) -> Router {
    // 需要会话的 API 单独成树，login/logout/session/healthz 保持公开。
    let protected = Router::new()
        .route("/api/overview", get(api_overview))
        .route("/api/agents/{id}/latest", get(api_latest))
        .route("/api/agents/{id}/series", get(api_series))
        .route(
            "/api/agents/{id}/settings",
            get(api_settings_get).put(api_settings_put),
        )
        .route(
            "/api/agents/{id}/control",
            get(api_control_get).post(api_control_post),
        )
        .route("/api/audit", get(api_audit))
        .route("/api/system", get(api_system))
        .route("/api", any(api_unknown))
        // `/api/` 与 `/api/{*rest}` 必须都显式接住：否则会落到静态 SPA 回退，
        // 返回 200 text/html，违反「/api/* 不参与回退」。
        .route("/api/", any(api_unknown))
        .route("/api/{*rest}", any(api_unknown))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));

    // 所有 /api/* 响应统一强制 application/json，避免上游 HTML 在面板 origin 下执行。
    let api = Router::new()
        .route("/api/login", post(api_login))
        .route("/api/logout", post(api_logout))
        .route("/api/session", get(api_session))
        .merge(protected)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            same_origin_guard,
        ))
        .layer(middleware::from_fn(force_json_content_type));

    Router::new()
        .route("/healthz", get(healthz))
        .merge(api)
        .route("/", get(static_index))
        .route("/{*path}", get(static_path))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// 给所有响应补上基础安全头。登录页不需要被 iframe 嵌入，也不应把路径带给第三方。
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    response
}

/// `/api/*` 响应一律声明 JSON。
///
/// 上游 Content-Type 在 `proxy` 层已被丢弃；这里再兜一层，保证登录/错误/未知路由
/// 等面板自己产生的响应也不会被浏览器按 HTML 解析。
async fn force_json_content_type(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// 变更类 API 的同源校验（KI-07）。
///
/// 只拦截 `/api/*` 的 POST/PUT/PATCH/DELETE：
/// - 带 `Origin`：必须与 `Host` 同源，或与 `public_origin` 完全一致；
/// - 不带 `Origin`：要求 `Content-Type: application/json`，挡住跨站表单；
/// - 否则 403 `origin_mismatch`。
async fn same_origin_guard(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    if !matches!(
        method,
        axum::http::Method::POST
            | axum::http::Method::PUT
            | axum::http::Method::PATCH
            | axum::http::Method::DELETE
    ) {
        return next.run(request).await;
    }

    let headers = request.headers();
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string);
    let allowed = match origin.as_deref() {
        Some(origin) => auth::same_origin(origin, host.as_deref(), &state.cfg.public_origin),
        None => is_json_content_type(headers),
    };
    if allowed {
        next.run(request).await
    } else {
        tracing::warn!(
            method = %method,
            origin = origin.as_deref().unwrap_or("<none>"),
            "拒绝跨源或非 JSON 的变更请求"
        );
        proxy::json_error(StatusCode::FORBIDDEN, "origin_mismatch")
    }
}

async fn healthz() -> &'static str {
    "ok"
}

/// 会话中间件：除公开端点外，`/api/*` 必须携带有效 Cookie。
async fn require_session(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let valid = auth::token_from_headers(request.headers())
        .is_some_and(|token| state.sessions.is_authenticated(&token, now_ms()));
    if valid {
        next.run(request).await
    } else {
        proxy::json_error(StatusCode::UNAUTHORIZED, "unauthorized")
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    password: String,
}

async fn api_login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(ip) = auth::client_ip(peer.ip(), &headers, &state.trusted_proxies) else {
        tracing::warn!(peer = %peer.ip(), "可信反代传来的 X-Forwarded-For 非法或过长，拒绝登录");
        return proxy::json_error(StatusCode::BAD_REQUEST, "invalid_forwarded_for");
    };

    if !is_json_content_type(&headers) {
        tracing::warn!(ip = %ip, "面板登录缺少 application/json");
        return proxy::json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required");
    }

    let bytes = match axum::body::to_bytes(body, MAX_JSON_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => {
            tracing::warn!(ip = %ip, "面板登录请求体超过上限");
            return proxy::json_error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
        }
    };
    let Ok(request) = serde_json::from_slice::<LoginRequest>(&bytes) else {
        tracing::warn!(ip = %ip, "面板登录请求体不是合法 JSON");
        return proxy::json_error(StatusCode::BAD_REQUEST, "invalid_json");
    };

    // 限速的“检查 + 预占”必须在同一把锁内完成，且在 Argon2 之前：
    // 并发 N 个错误密码时最多 5 个进入校验，其余直接 429。
    let now = now_ms();
    let attempt_guard = match state.limiter.begin_attempt(ip, now) {
        auth::AttemptDecision::Allowed(guard) => guard,
        auth::AttemptDecision::TooMany(retry_after) => {
            tracing::warn!(ip = %ip, "面板登录被限速，并发尝试过多或仍在锁定窗口");
            return rate_limited_response(retry_after);
        }
    };

    // 最多 2 个 Argon2 并发。许可被移进阻塞任务：即使浏览器断开、handler 被丢弃，
    // 只要哈希还在算，就仍然占用配额，避免拿取消请求绕过内存上限。
    let permit = match state.argon2_slots.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            tracing::error!("Argon2 信号量已关闭");
            // attempt_guard 在此 Drop，归还预占名额。
            return proxy::json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error");
        }
    };
    let password = request.password;
    let hash = state
        .password_hash
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let verified = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        auth::verify_password(&password, &hash)
    })
    .await;

    match verified {
        Ok(true) => {
            state.limiter.record_success(ip);
            attempt_guard.disarm();
            let token = state.sessions.create(now);
            let secure = auth::secure_cookie(
                state.cfg.cookie_secure,
                peer.ip(),
                &headers,
                &state.trusted_proxies,
            );
            tracing::info!(ip = %ip, "面板登录成功");
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NO_CONTENT;
            match HeaderValue::from_str(&auth::session_cookie(&token, secure)) {
                Ok(value) => {
                    response.headers_mut().insert(header::SET_COOKIE, value);
                }
                Err(_) => {
                    return proxy::json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
                }
            }
            set_no_store(response.headers_mut());
            response
        }
        Ok(false) => {
            state.limiter.record_failure(ip, now_ms());
            attempt_guard.disarm();
            tracing::warn!(ip = %ip, "面板登录失败：密码错误");
            proxy::json_error(StatusCode::UNAUTHORIZED, "unauthorized")
        }
        Err(error) => {
            tracing::error!(error = %error, "Argon2 校验任务异常退出");
            // attempt_guard 在此 Drop，归还预占名额。
            proxy::json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
        }
    }
}

async fn api_logout(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    // 登出也是变更类请求；要求 JSON 可挡住跨站表单（配合 SameSite=Lax）。
    if !is_json_content_type(&headers) {
        return proxy::json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required");
    }
    if let Some(token) = auth::token_from_headers(&headers) {
        state.sessions.revoke(&token);
    }
    let secure = auth::secure_cookie(
        state.cfg.cookie_secure,
        peer.ip(),
        &headers,
        &state.trusted_proxies,
    );
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::NO_CONTENT;
    if let Ok(value) = HeaderValue::from_str(&auth::clear_cookie(secure)) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    set_no_store(response.headers_mut());
    response
}

async fn api_session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let authenticated = auth::token_from_headers(&headers)
        .is_some_and(|token| state.sessions.is_authenticated(&token, now_ms()));
    let mut response = Response::new(Body::from(
        json!({ "authenticated": authenticated }).to_string(),
    ));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    set_no_store(response.headers_mut());
    response
}

async fn api_overview(State(state): State<Arc<AppState>>, RawQuery(raw): RawQuery) -> Response {
    let query = match parse_allowed(raw.as_deref(), &["window_ms"]) {
        Ok(query) => query,
        Err(message) => return bad_request(&message),
    };
    if let Err(message) = validate_window(&query, MIN_OVERVIEW_WINDOW_MS) {
        return bad_request(&message);
    }
    forward_get(&state, "/api/v1/overview", &query).await
}

async fn api_latest(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if !proxy::validate_agent_id(&id) {
        return bad_request("agent_id 非法");
    }
    let query = match parse_allowed(raw.as_deref(), &["window_ms"]) {
        Ok(query) => query,
        Err(message) => return bad_request(&message),
    };
    if let Err(message) = validate_window(&query, MIN_LATEST_WINDOW_MS) {
        return bad_request(&message);
    }
    forward_get(&state, &format!("/api/v1/agents/{id}/latest"), &query).await
}

async fn api_series(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if !proxy::validate_agent_id(&id) {
        return bad_request("agent_id 非法");
    }
    let query = match parse_allowed(raw.as_deref(), &["metric", "from", "to", "bucket_ms"]) {
        Ok(query) => query,
        Err(message) => return bad_request(&message),
    };
    if let Err(message) = validate_series_query(&query) {
        return bad_request(&message);
    }
    forward_get(&state, &format!("/api/v1/agents/{id}/series"), &query).await
}

async fn api_settings_get(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if !proxy::validate_agent_id(&id) {
        return bad_request("agent_id 非法");
    }
    forward_get(&state, &format!("/api/v1/agents/{id}/settings"), &[]).await
}

#[derive(Deserialize)]
struct SettingsRequest {
    sample_interval_ms: u64,
}

async fn api_settings_put(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !proxy::validate_agent_id(&id) {
        return bad_request("agent_id 非法");
    }
    if !is_json_content_type(&headers) {
        return proxy::json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required");
    }
    let bytes = match axum::body::to_bytes(body, MAX_JSON_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return proxy::json_error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
    };
    let Ok(request) = serde_json::from_slice::<SettingsRequest>(&bytes) else {
        return bad_request("请求体必须是 {\"sample_interval_ms\": <整数>}");
    };
    if !(1_000..=300_000).contains(&request.sample_interval_ms) {
        return bad_request("sample_interval_ms 必须在 1000–300000 之间");
    }
    let path = format!("/api/v1/agents/{id}/settings");
    let payload = json!({ "sample_interval_ms": request.sample_interval_ms });
    match state.proxy.put_json(&path, &payload).await {
        Ok(reply) => proxy::hub_reply_to_response(reply),
        Err(error) => proxy::proxy_error_to_response(&error),
    }
}

/// 读取 agent 的控制能力状态；只读，不写审计。
async fn api_control_get(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if !proxy::validate_agent_id(&id) {
        return bad_request("agent_id 非法");
    }
    // 控制状态没有查询参数；显式拒绝未知参数，避免把面板变成参数透传器。
    let query = match parse_allowed(raw.as_deref(), &[]) {
        Ok(query) => query,
        Err(message) => return bad_request(&message),
    };
    forward_get(&state, &format!("/api/v1/agents/{id}/control"), &query).await
}

/// 执行控制动作；结构校验通过后原样转发给 hub。
async fn api_control_post(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if !proxy::validate_agent_id(&id) {
        return bad_request("agent_id 非法");
    }
    if !is_json_content_type(&headers) {
        return proxy::json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "json_required");
    }
    let bytes = match axum::body::to_bytes(body, MAX_JSON_BODY).await {
        Ok(bytes) => bytes,
        Err(_) => return proxy::json_error(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
    };
    let Ok(payload) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return bad_request("请求体必须是 JSON 对象");
    };
    if let Err(message) = validate_control_payload(&payload) {
        return bad_request(&message);
    }
    let path = format!("/api/v1/agents/{id}/control");
    match state.proxy.post_json(&path, &payload).await {
        Ok(reply) => proxy::hub_reply_to_response(reply),
        Err(error) => proxy::proxy_error_to_response(&error),
    }
}

/// 审计列表；只放行分页与过滤参数。
async fn api_audit(State(state): State<Arc<AppState>>, RawQuery(raw): RawQuery) -> Response {
    let query = match parse_allowed(
        raw.as_deref(),
        &["limit", "before_id", "agent_id", "capability"],
    ) {
        Ok(query) => query,
        Err(message) => return bad_request(&message),
    };
    if let Err(message) = validate_audit_query(&query) {
        return bad_request(&message);
    }
    forward_get(&state, "/api/v1/audit", &query).await
}

async fn api_system(State(state): State<Arc<AppState>>) -> Response {
    forward_get(&state, "/api/v1/system", &[]).await
}

async fn api_unknown() -> Response {
    proxy::json_error(StatusCode::NOT_FOUND, "not_found")
}

async fn static_index(State(state): State<Arc<AppState>>) -> Response {
    match &state.static_files {
        Some(files) => files.serve("").await,
        None => web::missing_site_response(),
    }
}

async fn static_path(
    State(state): State<Arc<AppState>>,
    AxumPath(path): AxumPath<String>,
) -> Response {
    match &state.static_files {
        Some(files) => files.serve(&path).await,
        None => web::missing_site_response(),
    }
}

fn parse_allowed(
    raw: Option<&str>,
    allowed: &[&str],
) -> std::result::Result<Vec<(String, String)>, String> {
    proxy::parse_query(raw, allowed).map_err(|error| error.message())
}

fn validate_window(
    query: &[(String, String)],
    min_window_ms: i64,
) -> std::result::Result<(), String> {
    let mut seen = false;
    for (key, value) in query {
        if key != "window_ms" {
            continue;
        }
        if seen {
            return Err("window_ms 不能重复".to_string());
        }
        seen = true;
        let window: i64 = value
            .parse()
            .map_err(|_| "window_ms 必须是整数".to_string())?;
        if !(min_window_ms..=MAX_WINDOW_MS).contains(&window) {
            return Err(format!(
                "window_ms 必须在 {min_window_ms}–{MAX_WINDOW_MS} 之间"
            ));
        }
    }
    Ok(())
}

fn validate_series_query(query: &[(String, String)]) -> std::result::Result<(), String> {
    let mut metrics = Vec::new();
    let mut from = None;
    let mut to = None;
    let mut bucket_seen = false;
    for (key, value) in query {
        match key.as_str() {
            "metric" => {
                if value.is_empty()
                    || value.len() > 64
                    || !value
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
                {
                    return Err(format!("metric 非法: {value}"));
                }
                metrics.push(value);
            }
            "from" => {
                if from.is_some() {
                    return Err("from 不能重复".to_string());
                }
                from = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| "from 必须是毫秒时间戳".to_string())?,
                )
            }
            "to" => {
                if to.is_some() {
                    return Err("to 不能重复".to_string());
                }
                to = Some(
                    value
                        .parse::<i64>()
                        .map_err(|_| "to 必须是毫秒时间戳".to_string())?,
                )
            }
            "bucket_ms" => {
                if bucket_seen {
                    return Err("bucket_ms 不能重复".to_string());
                }
                bucket_seen = true;
                let bucket = value
                    .parse::<i64>()
                    .map_err(|_| "bucket_ms 必须是正整数".to_string())?;
                if bucket <= 0 {
                    return Err("bucket_ms 必须大于 0".to_string());
                }
            }
            _ => return Err(format!("不支持的查询参数: {key}")),
        }
    }
    if metrics.is_empty() || metrics.len() > 20 {
        return Err("metric 数量必须在 1–20 之间".to_string());
    }
    let (Some(from), Some(to)) = (from, to) else {
        return Err("series 查询必须同时提供 from 与 to".to_string());
    };
    if from >= to {
        return Err("from 必须早于 to".to_string());
    }
    if to.saturating_sub(from) > MAX_SERIES_SPAN_MS {
        return Err("时间跨度不能超过 32 天".to_string());
    }
    Ok(())
}

/// 读取一个可选的字符串字段：类型错误或超长直接拒绝。
fn control_string_field<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    key: &str,
    max_len: usize,
) -> std::result::Result<Option<&'a str>, String> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let text = value
        .as_str()
        .ok_or_else(|| format!("{key} 必须是字符串"))?;
    if text.len() > max_len {
        return Err(format!("{key} 长度不能超过 {max_len} 字节"));
    }
    Ok(Some(text))
}

/// 控制请求体的结构校验：字段白名单、类型、长度与数值范围。
///
/// 这里**不**判断能力是否开启、目标是否在白名单、是否需要 `confirm`；
/// 这些业务规则由 hub 统一裁决。面板只拒绝明显非法的请求，避免把
/// 超长字符串、异常数字或未知字段转发给 hub。
fn validate_control_payload(payload: &serde_json::Value) -> std::result::Result<(), String> {
    let Some(object) = payload.as_object() else {
        return Err("请求体必须是 JSON 对象".to_string());
    };
    if let Some(unknown) = object
        .keys()
        .find(|key| !CONTROL_FIELDS.contains(&key.as_str()))
    {
        return Err(format!("不支持的字段: {unknown}"));
    }

    let capability = control_string_field(object, "capability", MAX_CONTROL_ENUM_LEN)?
        .ok_or_else(|| "缺少 capability".to_string())?;
    if capability.is_empty() {
        return Err("capability 不能为空".to_string());
    }
    let action = control_string_field(object, "action", MAX_CONTROL_ACTION_LEN)?
        .ok_or_else(|| "缺少 action".to_string())?;
    if action.is_empty() {
        return Err("action 不能为空".to_string());
    }
    for key in ["target", "source", "name"] {
        control_string_field(object, key, MAX_CONTROL_TARGET_LEN)?;
    }
    if control_string_field(object, "signal", MAX_CONTROL_ENUM_LEN)?.is_some_and(str::is_empty) {
        return Err("signal 不能为空".to_string());
    }

    if let Some(value) = object.get("pid") {
        let pid = value
            .as_u64()
            .ok_or_else(|| "pid 必须是正整数".to_string())?;
        if pid == 0 {
            return Err("pid 必须大于 0".to_string());
        }
        if pid > MAX_CONTROL_PID {
            return Err(format!("pid 不能超过 {MAX_CONTROL_PID}"));
        }
    }
    if let Some(value) = object.get("lines") {
        let lines = value
            .as_u64()
            .ok_or_else(|| "lines 必须是整数".to_string())?;
        if !(MIN_CONTROL_LINES..=MAX_CONTROL_LINES).contains(&lines) {
            return Err(format!(
                "lines 必须在 {MIN_CONTROL_LINES}–{MAX_CONTROL_LINES} 之间"
            ));
        }
    }
    if object
        .get("confirm")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err("confirm 必须是布尔值".to_string());
    }
    Ok(())
}

/// 审计查询参数校验：只允许 limit / before_id / agent_id / capability。
fn validate_audit_query(query: &[(String, String)]) -> std::result::Result<(), String> {
    let mut limit_seen = false;
    let mut before_seen = false;
    let mut agent_seen = false;
    let mut capability_seen = false;
    for (key, value) in query {
        match key.as_str() {
            "limit" => {
                if limit_seen {
                    return Err("limit 不能重复".to_string());
                }
                limit_seen = true;
                let limit = value
                    .parse::<i64>()
                    .map_err(|_| "limit 必须是整数".to_string())?;
                if !(1..=MAX_AUDIT_LIMIT).contains(&limit) {
                    return Err(format!("limit 必须在 1–{MAX_AUDIT_LIMIT} 之间"));
                }
            }
            "before_id" => {
                if before_seen {
                    return Err("before_id 不能重复".to_string());
                }
                before_seen = true;
                let before = value
                    .parse::<i64>()
                    .map_err(|_| "before_id 必须是非负整数".to_string())?;
                if before < 0 {
                    return Err("before_id 必须是非负整数".to_string());
                }
            }
            "agent_id" => {
                if agent_seen {
                    return Err("agent_id 不能重复".to_string());
                }
                agent_seen = true;
                if !proxy::validate_agent_id(value) {
                    return Err("agent_id 非法".to_string());
                }
            }
            "capability" => {
                if capability_seen {
                    return Err("capability 不能重复".to_string());
                }
                capability_seen = true;
                // 与 hub 的过滤规则保持一致：只拒绝空值、超长和控制字符，
                // 未知能力交给 hub 返回空列表，而不是在面板另造一套枚举。
                if value.is_empty()
                    || value.len() > MAX_AUDIT_CAPABILITY_LEN
                    || value.chars().any(char::is_control)
                {
                    return Err("capability 非法".to_string());
                }
            }
            _ => return Err(format!("不支持的查询参数: {key}")),
        }
    }
    Ok(())
}

async fn forward_get(state: &AppState, path: &str, query: &[(String, String)]) -> Response {
    match state.proxy.get(path, query).await {
        Ok(reply) => proxy::hub_reply_to_response(reply),
        Err(error) => proxy::proxy_error_to_response(&error),
    }
}

fn is_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn set_no_store(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

fn bad_request(message: &str) -> Response {
    let body = json!({ "error": "bad_request", "message": message }).to_string();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    set_no_store(response.headers_mut());
    response
}

fn rate_limited_response(retry_after: u64) -> Response {
    let mut response = proxy::json_error(StatusCode::TOO_MANY_REQUESTS, "rate_limited");
    if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn run(config: Option<PathBuf>, listen: Option<String>, hub: Option<String>) -> Result<()> {
    let explicit = config.is_some();
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_PANEL_CONFIG));
    let mut cfg = if path.exists() {
        PanelConfig::load(&path).with_context(|| format!("读取配置失败: {}", path.display()))?
    } else if explicit {
        bail!("配置文件不存在: {}", path.display());
    } else {
        eprintln!(
            "提示: 未找到 {}，使用默认配置；请先运行 `rustboard-panel init` 生成登录密码与 hub token",
            path.display()
        );
        PanelConfig::default()
    };
    if let Some(listen) = listen {
        cfg.listen = listen;
    }
    if let Some(hub) = hub {
        let override_hub = normalize_hub_url(&hub)?;
        if !cfg.token.trim().is_empty() && override_hub != cfg.hub_url {
            // 只提示风险，不打印 token 本身。
            tracing::warn!(
                config_hub = %cfg.hub_url,
                override_hub = %override_hub,
                "用 --hub 覆盖了 hub 地址，但仍沿用配置里的 hub token；请确认没有把生产 token 发到测试/第三方地址"
            );
        }
        cfg.hub_url = override_hub;
    }

    // 显式配置的 static_dir 无效时必须失败退出，不能悄悄回退到 web/dist：
    // 静默回退会让运维误以为正在提供自己指定的构建产物。
    let static_files = web::StaticFiles::discover(&cfg.static_dir).context(
        "静态资源目录配置无效，面板拒绝启动（显式配置 static_dir 时不会回退到默认目录）",
    )?;
    if static_files.is_none() {
        tracing::warn!(
            "未找到前端构建产物，页面请求将返回 503；请构建 web/ 或用 static_dir 指定目录"
        );
    }
    let state = Arc::new(AppState::new(cfg, static_files, Some(path.clone()))?);
    let listen = state.cfg.listen.clone();
    let hub = state.cfg.hub_url.clone();
    let loopback = listen_is_loopback(&listen);
    let reload_state = state.clone();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        spawn_password_reload(reload_state);
        let app = build_router(state);
        let listener = tokio::net::TcpListener::bind(&listen)
            .await
            .with_context(|| format!("监听 {listen} 失败"))?;
        if !loopback {
            tracing::warn!(
                listen = %listen,
                "面板是明文 HTTP，请使用 VPN/反代；当前监听地址不是回环地址，\
                 不要直接暴露到公网或不可信网络"
            );
        }
        tracing::info!(listen = %listen, hub = %hub, "面板已启动");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    })
}

/// `panel init` 的监听地址：显式 `--listen` 原样保留；未传时选随机回环端口并落盘。
///
/// 随机端口只在这里产生；`PanelConfig::default()` 保持幂等的 `127.0.0.1:8080`，
/// 避免缺 `listen` 的配置每次 `ports`/`run` 选到不同端口。
fn init_listen(explicit: Option<String>) -> Result<String> {
    match explicit {
        Some(listen) => Ok(listen),
        None => Ok(format!("127.0.0.1:{}", pick_free_port()?)),
    }
}

#[allow(clippy::too_many_arguments)]
fn init(
    config: Option<PathBuf>,
    listen: Option<String>,
    hub: Option<String>,
    hub_token: Option<String>,
    password: Option<String>,
    static_dir: Option<String>,
    force: bool,
) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_PANEL_CONFIG));
    if path.exists() && !force {
        bail!("{} 已存在，使用 --force 覆盖", path.display());
    }

    let mut cfg = PanelConfig {
        listen: init_listen(listen)?,
        ..PanelConfig::default()
    };

    let hub_overridden = hub.is_some();

    // hub 地址 / token 缺省时尝试复用 hub 的配置，避免用户在两份文件间抄 token。
    let hub_cfg = if hub.is_none() || hub_token.is_none() {
        load_hub_config_hint()
    } else {
        None
    };

    match hub {
        Some(hub) => cfg.hub_url = normalize_hub_url(&hub)?,
        None => {
            if let Some(hub_cfg) = &hub_cfg {
                cfg.hub_url = hub_url_from_admin_listen(&hub_cfg.admin_listen);
                println!("已从 {DEFAULT_HUB_CONFIG} 读取 hub 管理地址");
            } else {
                cfg.hub_url = format!("http://127.0.0.1:{DEFAULT_ADMIN_PORT}");
                eprintln!(
                    "提示: 未找到可读的 {DEFAULT_HUB_CONFIG}，hub 地址使用默认 {}；请用 --hub 指定实际地址",
                    cfg.hub_url
                );
            }
        }
    }

    let (token, token_source) = resolve_hub_token(hub_token, hub_cfg.as_ref());
    let Some(token) = token else {
        eprintln!(
            "提示: 没有找到 hub 管理 token。请先运行 `rustboard-hub admin-token`，\
             然后用 `--hub-token` 指定（或写入 {DEFAULT_HUB_CONFIG} 的 admin_token）"
        );
        bail!("缺少 hub 管理 token，未写入面板配置");
    };
    if let Some(source) = token_source {
        if hub_overridden {
            eprintln!(
                "警告: 用 --hub 覆盖了 hub 地址，但 hub token 仍复制自 {source}；\
                 请确认没有把生产 token 发到测试/第三方地址"
            );
        }
        println!("已从 {source} 复制 hub 管理 token（只写入面板配置，不会打印或下发浏览器）");
    }
    cfg.token = token;

    if let Some(static_dir) = static_dir {
        cfg.static_dir = static_dir;
    }

    let password = match password {
        Some(password) if password.is_empty() => bail!("密码不能为空"),
        Some(password) => {
            if password.len() < MIN_PASSWORD_LEN {
                eprintln!("警告: 密码短于 {MIN_PASSWORD_LEN} 个字符，建议使用自动生成的随机密码");
            }
            password
        }
        None => generate_password(),
    };
    cfg.admin_password_hash =
        auth::hash_password(&password).context("生成 Argon2id 密码哈希失败")?;
    cfg.save(&path)?;

    println!("已写入配置: {}", path.display());
    println!("面板监听: {}", cfg.listen);
    println!("hub API: {}", cfg.hub_url);
    println!(
        "静态目录: {}",
        if cfg.static_dir.trim().is_empty() {
            "自动查找 web/dist 或 /usr/share/rustboard/web"
        } else {
            cfg.static_dir.as_str()
        }
    );
    println!("面板密码（仅显示一次，请立即保存）: {password}");
    println!(
        "以后修改密码: rustboard-panel reset-password --config {}",
        path.display()
    );
    Ok(())
}

/// 重置管理员密码：写回新的 Argon2id PHC 哈希（配置保持 0600）。
///
/// 未传 `--password` 时生成 20 位随机密码；stdout 只展示一次。
/// 已登录会话保存在内存里，不会因改密自动失效（重启面板后清空）。
fn reset_password(config: Option<PathBuf>, password: Option<String>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_PANEL_CONFIG));
    if !path.exists() {
        bail!(
            "配置文件不存在: {}（先运行 `rustboard-panel init`）",
            path.display()
        );
    }
    let mut cfg =
        PanelConfig::load(&path).with_context(|| format!("读取配置失败: {}", path.display()))?;
    let password = match password {
        Some(password) if password.trim().is_empty() => bail!("密码不能为空"),
        Some(password) => {
            if password.len() < MIN_PASSWORD_LEN {
                eprintln!("警告: 密码短于 {MIN_PASSWORD_LEN} 个字符，建议使用自动生成的随机密码");
            }
            password
        }
        None => generate_password(),
    };
    cfg.admin_password_hash =
        auth::hash_password(&password).context("生成 Argon2id 密码哈希失败")?;
    cfg.save(&path)?;
    println!("已重置面板密码（仅显示一次，请立即保存）: {password}");
    println!("配置文件: {}（0600）", path.display());
    println!("提示: 运行中的面板会在 1 秒内自动加载新密码（无需重启）；已有登录会话仍然有效。");
    Ok(())
}

fn ports(config: Option<PathBuf>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_PANEL_CONFIG));
    let cfg = if path.exists() {
        PanelConfig::load(&path)?
    } else {
        PanelConfig::default()
    };
    let port = port_of(&cfg.listen).unwrap_or(DEFAULT_PANEL_PORT);
    let loopback = listen_is_loopback(&cfg.listen);
    println!("配置文件: {}", path.display());
    println!("面板端口: {port}");
    println!("  监听: {}", cfg.listen);
    if loopback {
        match listen_host(&cfg.listen) {
            Some(host) if host.parse::<std::net::Ipv6Addr>().is_ok() => {
                println!("  浏览器: http://[{host}]:{port}");
            }
            Some(host) => println!("  浏览器: http://{host}:{port}"),
            None => println!("  浏览器: http://127.0.0.1:{port}"),
        }
        println!("  提示: 面板只监听回环地址，请通过本机浏览器或 SSH 端口转发访问");
    } else {
        println!("  浏览器: http://<本机IP>:{port}（监听非回环地址）");
        println!(
            "  警告: 面板是明文 HTTP，请使用 VPN/反代（HTTPS）对外提供，\
             不要直接暴露到公网或不可信网络"
        );
    }
    println!("hub API: {}", cfg.hub_url);
    println!(
        "静态目录: {}",
        if cfg.static_dir.trim().is_empty() {
            "自动查找 web/dist 或 /usr/share/rustboard/web"
        } else {
            cfg.static_dir.as_str()
        }
    );
    println!(
        "登录密码: {}",
        if cfg.admin_password_hash.trim().is_empty() {
            "未设置（运行 rustboard-panel init）"
        } else {
            "已设置"
        }
    );
    Ok(())
}

/// 解析 `panel init` 使用的 hub token。
///
/// 显式 `--hub-token` 优先；否则从本机 hub 配置复制，并返回来源路径供调用方打印。
/// 来源路径只用于提示用户 token 来自哪里，不包含 token 本身。
fn resolve_hub_token(
    explicit: Option<String>,
    hub_cfg: Option<&HubConfig>,
) -> (Option<String>, Option<&'static str>) {
    if let Some(token) = explicit
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
    {
        return (Some(token), None);
    }
    let copied = hub_cfg
        .map(|hub| hub.admin_token.trim().to_string())
        .filter(|token| !token.is_empty());
    (copied, Some(DEFAULT_HUB_CONFIG))
}

fn load_hub_config_hint() -> Option<HubConfig> {
    match HubConfig::load(Path::new(DEFAULT_HUB_CONFIG)) {
        Ok(hub) => Some(hub),
        Err(error) => {
            eprintln!(
                "提示: 无法读取 {DEFAULT_HUB_CONFIG}（{error}）；hub 地址与 token 需要用 --hub/--hub-token 指定"
            );
            None
        }
    }
}

/// 把 `127.0.0.1:8444` / `0.0.0.0:8444` / `http://...` 统一成面板可用的 hub 地址。
fn normalize_hub_url(raw: &str) -> Result<String> {
    let raw = raw.trim().trim_end_matches('/');
    if raw.is_empty() {
        bail!("hub 地址不能为空");
    }
    let normalized = if raw.starts_with("http://") || raw.starts_with("https://") {
        raw.to_string()
    } else {
        format!("http://{raw}")
    };
    if normalized.starts_with("https://") {
        bail!("M2 面板只支持 http:// 的 hub 地址；https 由 M5 的反代方案承接");
    }
    Ok(normalized)
}

/// hub 的 admin_listen 常常是 `0.0.0.0:8444`，面板要连回环地址。
fn hub_url_from_admin_listen(admin_listen: &str) -> String {
    let listen = admin_listen.trim();
    if listen.starts_with("http://") || listen.starts_with("https://") {
        return listen.trim_end_matches('/').to_string();
    }
    let loopback = if let Some(rest) = listen.strip_prefix("0.0.0.0:") {
        format!("127.0.0.1:{rest}")
    } else if let Some(rest) = listen.strip_prefix("[::]:") {
        format!("[::1]:{rest}")
    } else {
        listen.to_string()
    };
    format!("http://{loopback}")
}

/// 从监听地址中取主机部分：`127.0.0.1:8080`、`[::1]:8080`、`localhost:8080`。
/// 不做 DNS 解析，也不接受空主机名。
fn listen_host(listen: &str) -> Option<&str> {
    let listen = listen.trim();
    if let Some(rest) = listen.strip_prefix('[') {
        return rest.split(']').next().filter(|host| !host.is_empty());
    }
    match listen.rsplit_once(':') {
        Some((host, port)) => {
            // 无端口或空主机（例如 `:8080`）视为无法确认。
            if host.is_empty() || port.trim().is_empty() {
                None
            } else {
                Some(host)
            }
        }
        None if !listen.is_empty() => Some(listen),
        None => None,
    }
}

/// 监听地址是否只绑回环。
///
/// 只把字面量回环 IP 与 `localhost` 视为安全；主机名无法静态确认时按“非回环”处理，
/// 宁可多打一条 WARN，也不让明文面板默认对外。
fn listen_is_loopback(listen: &str) -> bool {
    match listen_host(listen) {
        Some(host) if host.eq_ignore_ascii_case("localhost") => true,
        Some(host) => host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

fn generate_password() -> String {
    rand::rngs::OsRng
        .sample_iter(&Alphanumeric)
        .take(GENERATED_PASSWORD_LEN)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Bytes};
    use axum::http::Method;
    use axum::http::Request as HttpRequest;
    use serde_json::Value;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;
    use tower::ServiceExt;

    const TEST_PASSWORD: &str = "panel-test-password";
    /// 面板配置里的 hub token；只允许出现在面板 → hub 的请求里。
    const TEST_HUB_TOKEN: &str = "test-hub-token";
    static TEST_HASH: OnceLock<String> = OnceLock::new();
    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TempSite {
        dir: PathBuf,
    }

    impl TempSite {
        fn new() -> Self {
            let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "rustboard-panel-main-{}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(dir.join("assets")).unwrap();
            std::fs::write(
                dir.join("index.html"),
                "<!doctype html><title>RustBoard</title>",
            )
            .unwrap();
            std::fs::write(dir.join("assets/app.js"), "console.log('ok')").unwrap();
            Self { dir }
        }
    }

    impl Drop for TempSite {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn test_state() -> (Arc<AppState>, TempSite) {
        let site = TempSite::new();
        let hash = TEST_HASH
            .get_or_init(|| auth::hash_password(TEST_PASSWORD).unwrap())
            .clone();
        let cfg = PanelConfig {
            hub_url: "http://127.0.0.1:1".to_string(),
            token: TEST_HUB_TOKEN.to_string(),
            admin_password_hash: hash,
            // 该地址用于验证 Auto 策略下“可信反代 + XFP=https → Secure”。
            trusted_proxies: vec!["203.0.113.9".to_string()],
            ..PanelConfig::default()
        };
        let files = web::StaticFiles::from_root(&site.dir).unwrap();
        let state = Arc::new(AppState::new(cfg, Some(files), None).unwrap());
        (state, site)
    }

    /// 只装配一个指向 mock hub 的状态，不提供静态资源。
    fn test_state_with_hub(hub_url: &str) -> Arc<AppState> {
        let hash = TEST_HASH
            .get_or_init(|| auth::hash_password(TEST_PASSWORD).unwrap())
            .clone();
        let cfg = PanelConfig {
            hub_url: hub_url.to_string(),
            token: TEST_HUB_TOKEN.to_string(),
            admin_password_hash: hash,
            ..PanelConfig::default()
        };
        Arc::new(AppState::new(cfg, None).unwrap())
    }

    async fn call(
        state: &Arc<AppState>,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
        body: Body,
        ip: Option<&str>,
    ) -> (StatusCode, HeaderMap, Bytes) {
        let app = build_router(state.clone());
        let mut builder = HttpRequest::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut request = builder.body(body).unwrap();
        if let Some(ip) = ip {
            request
                .extensions_mut()
                .insert(ConnectInfo(ip.parse::<SocketAddr>().unwrap()));
        }
        let response = app.oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        (status, headers, bytes)
    }

    fn session_cookie(state: &AppState) -> String {
        let token = state.sessions.create(now_ms());
        format!("rb_session={token}")
    }

    /// 只服务一次请求的假 hub；返回入站 URL 与已读到的原始请求。
    fn spawn_mock_hub(status: u16, response: &'static str) -> (String, Arc<Mutex<Vec<u8>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let mut request = Vec::new();
            let mut scratch = [0u8; 4096];
            loop {
                match stream.read(&mut scratch) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&scratch[..read]),
                }
                if request_complete(&request) {
                    break;
                }
            }
            *recorded.lock().unwrap() = request;
            let reason = StatusCode::from_u16(status)
                .unwrap()
                .canonical_reason()
                .unwrap_or("OK");
            let reply = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            );
            let _ = stream.write_all(reply.as_bytes());
            let _ = stream.flush();
        });
        (format!("http://{address}"), seen)
    }

    /// 请求头完整且 `Content-Length` 指定的 body 已全部到达。
    fn request_complete(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        request.len() >= header_end + 4 + content_length
    }

    /// 拆分 mock hub 收到的请求，返回（请求头, 请求体）。
    fn seen_request(seen: &Arc<Mutex<Vec<u8>>>) -> (String, String) {
        let request = seen.lock().unwrap().clone();
        let text = String::from_utf8_lossy(&request).to_string();
        let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
        (head.to_string(), body.to_string())
    }

    /// 断言面板只把 hub token 放进面板 → hub 的 Authorization 头。
    fn assert_bearer_sent_to_hub(head: &str) {
        let expected = format!(
            "authorization: bearer {}",
            TEST_HUB_TOKEN.to_ascii_lowercase()
        );
        assert!(
            head.to_ascii_lowercase().contains(&expected),
            "面板 → hub 必须带 Bearer token: {head}"
        );
    }

    /// 带登录 Cookie 的控制 POST。
    async fn control_post(
        state: &Arc<AppState>,
        cookie: &str,
        payload: &str,
    ) -> (StatusCode, HeaderMap, Bytes) {
        call(
            state,
            Method::POST,
            "/api/agents/hub-self/control",
            &[("cookie", cookie), ("content-type", "application/json")],
            Body::from(payload.to_string()),
            None,
        )
        .await
    }

    #[tokio::test]
    async fn healthz_is_public_and_static_is_served() {
        let (state, _site) = test_state();
        let (status, headers, body) =
            call(&state, Method::GET, "/healthz", &[], Body::empty(), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], b"ok");
        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("referrer-policy").unwrap(), "same-origin");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(
            headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
            CONTENT_SECURITY_POLICY
        );

        let (status, headers, body) =
            call(&state, Method::GET, "/", &[], Body::empty(), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert!(String::from_utf8_lossy(&body).contains("<!doctype html>"));

        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/agents/hub-self",
            &[],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
        assert!(String::from_utf8_lossy(&body).contains("<!doctype html>"));

        let (status, headers, _) = call(
            &state,
            Method::GET,
            "/assets/app.js",
            &[],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "text/javascript; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn api_requires_session_and_never_falls_back_to_html() {
        let (state, _site) = test_state();
        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/overview",
            &[],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(String::from_utf8_lossy(&body).contains("unauthorized"));

        let (status, _, body) = call(
            &state,
            Method::GET,
            "/api/unknown",
            &[],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(!String::from_utf8_lossy(&body).contains("<html"));

        let cookie = session_cookie(&state);
        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/unknown",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert!(!String::from_utf8_lossy(&body).contains("<html"));
    }

    #[tokio::test]
    async fn api_responses_always_declare_json() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);

        let (status, headers, _) = call(
            &state,
            Method::GET,
            "/api/session",
            &[],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
            CONTENT_SECURITY_POLICY
        );

        let (status, headers, _) = call(
            &state,
            Method::POST,
            "/api/login",
            &[("content-type", "text/plain")],
            Body::from("{}"),
            Some("203.0.113.30:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let (status, headers, _) = call(
            &state,
            Method::POST,
            "/api/logout",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::from("{}"),
            Some("203.0.113.30:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let fresh_cookie = session_cookie(&state);
        for path in ["/api/", "/api/foo/bar"] {
            let (status, headers, _) = call(
                &state,
                Method::GET,
                path,
                &[("cookie", &fresh_cookie)],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path} 必须走 API 404");
            assert_eq!(
                headers.get(header::CONTENT_TYPE).unwrap(),
                "application/json",
                "{path} 不能回退 HTML"
            );
        }
    }

    #[tokio::test]
    async fn control_and_audit_require_session() {
        let (state, _site) = test_state();
        for (method, path) in [
            (Method::GET, "/api/agents/hub-self/control"),
            (Method::GET, "/api/audit?limit=10"),
            (Method::POST, "/api/agents/hub-self/control"),
        ] {
            let (status, headers, body) = call(
                &state,
                method,
                path,
                &[("content-type", "application/json")],
                Body::from(r#"{"capability":"systemd","action":"list"}"#),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} 必须要求登录");
            assert_eq!(
                headers.get(header::CONTENT_TYPE).unwrap(),
                "application/json",
                "{path} 的 401 必须是 JSON"
            );
            assert!(String::from_utf8_lossy(&body).contains("unauthorized"));
        }
    }

    #[tokio::test]
    async fn control_get_forwards_to_hub_and_preserves_body() {
        let hub_body = r#"{"control_enabled":true,"online":true,"capabilities":["systemd"],"hub_capabilities":["systemd"]}"#;
        let (hub_url, seen) = spawn_mock_hub(200, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/agents/hub-self/control",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], hub_body.as_bytes());
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        let (head, _) = seen_request(&seen);
        assert!(
            head.starts_with("GET /api/v1/agents/hub-self/control HTTP/1.1"),
            "{head}"
        );
        assert_bearer_sent_to_hub(&head);
    }

    #[tokio::test]
    async fn control_get_rejects_invalid_agent_and_query() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        for path in [
            "/api/agents/../control",
            "/api/agents/hub%20self/control",
            "/api/agents/hub-self/control?x=1",
        ] {
            let (status, _, _) = call(
                &state,
                Method::GET,
                path,
                &[("cookie", &cookie)],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn control_post_rejects_malformed_payloads() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        let cases = [
            r#"{"capability":"systemd","action":"list","unknown":true}"#.to_string(),
            "[]".to_string(),
            "null".to_string(),
            r#"{"action":"list"}"#.to_string(),
            r#"{"capability":"systemd"}"#.to_string(),
            r#"{"capability":"systemd","action":"list","target":123}"#.to_string(),
            r#"{"capability":"systemd","action":"list","pid":0}"#.to_string(),
            r#"{"capability":"systemd","action":"list","pid":4294967296}"#.to_string(),
            r#"{"capability":"systemd","action":"list","pid":1.5}"#.to_string(),
            r#"{"capability":"systemd","action":"list","lines":0}"#.to_string(),
            r#"{"capability":"systemd","action":"list","lines":2001}"#.to_string(),
            r#"{"capability":"systemd","action":"list","confirm":"true"}"#.to_string(),
            r#"{"capability":"systemd","action":"list","signal":1}"#.to_string(),
            format!(
                r#"{{"capability":"{}","action":"list"}}"#,
                "a".repeat(MAX_CONTROL_ENUM_LEN + 1)
            ),
            format!(
                r#"{{"capability":"systemd","action":"restart","target":"{}"}}"#,
                "a".repeat(MAX_CONTROL_TARGET_LEN + 1)
            ),
            json!({
                "capability": "systemd",
                "action": "a".repeat(MAX_CONTROL_ACTION_LEN + 1),
            })
            .to_string(),
            "{not json".to_string(),
        ];
        for payload in cases {
            let (status, _, body) = control_post(&state, &cookie, &payload).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "payload={payload}");
            assert!(
                String::from_utf8_lossy(&body).contains("bad_request"),
                "payload={payload}"
            );
        }
    }

    #[tokio::test]
    async fn control_post_requires_json_and_limits_body() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        let (status, _, body) = call(
            &state,
            Method::POST,
            "/api/agents/hub-self/control",
            &[
                ("cookie", &cookie),
                ("host", "panel.test:8080"),
                ("origin", "http://panel.test:8080"),
                ("content-type", "text/plain"),
            ],
            Body::from(r#"{"capability":"systemd","action":"list"}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(String::from_utf8_lossy(&body).contains("json_required"));

        let huge = format!(
            r#"{{"capability":"systemd","action":"list","target":"{}"}}"#,
            "a".repeat(MAX_JSON_BODY)
        );
        let (status, _, _) = control_post(&state, &cookie, &huge).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn control_post_forwards_to_hub_and_preserves_response() {
        let hub_body = r#"{"ok":true,"result":{"type":"action_output","stdout":"","stderr":"","exit_code":0}}"#;
        let (hub_url, seen) = spawn_mock_hub(200, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let payload = r#"{"capability":"systemd","action":"restart","target":"nginx.service","confirm":true}"#;
        let (status, headers, body) = control_post(&state, &cookie, payload).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], hub_body.as_bytes());
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let (head, forwarded) = seen_request(&seen);
        assert!(
            head.starts_with("POST /api/v1/agents/hub-self/control HTTP/1.1"),
            "{head}"
        );
        assert_bearer_sent_to_hub(&head);
        let forwarded: Value = serde_json::from_str(&forwarded).unwrap();
        assert_eq!(
            forwarded,
            json!({
                "capability": "systemd",
                "action": "restart",
                "target": "nginx.service",
                "confirm": true,
            })
        );
    }

    #[tokio::test]
    async fn control_post_preserves_hub_business_errors() {
        let hub_body =
            r#"{"ok":false,"error":{"code":"capability_disabled","message":"控制能力未启用"}}"#;
        let (hub_url, _seen) = spawn_mock_hub(403, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, _, body) = control_post(
            &state,
            &cookie,
            r#"{"capability":"docker","action":"list"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(&body[..], hub_body.as_bytes());
    }

    #[tokio::test]
    async fn audit_get_forwards_whitelisted_query() {
        let hub_body = r#"{"entries":[],"next_before_id":0}"#;
        let (hub_url, seen) = spawn_mock_hub(200, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, _, body) = call(
            &state,
            Method::GET,
            "/api/audit?limit=50&before_id=42&agent_id=hub-self&capability=systemd",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], hub_body.as_bytes());
        let (head, _) = seen_request(&seen);
        assert!(
            head.starts_with(
                "GET /api/v1/audit?limit=50&before_id=42&agent_id=hub-self&capability=systemd HTTP/1.1"
            ),
            "{head}"
        );
        assert_bearer_sent_to_hub(&head);
    }

    #[tokio::test]
    async fn audit_get_rejects_disallowed_or_malformed_query() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        let long_agent = format!("agent_id={}", "a".repeat(65));
        let long_capability = format!("capability={}", "a".repeat(MAX_AUDIT_CAPABILITY_LEN + 1));
        for query in [
            "foo=1".to_string(),
            "limit=0".to_string(),
            "limit=201".to_string(),
            "limit=abc".to_string(),
            "limit=1&limit=2".to_string(),
            "before_id=-1".to_string(),
            "before_id=abc".to_string(),
            "agent_id=".to_string(),
            "agent_id=../etc/passwd".to_string(),
            long_agent,
            "capability=".to_string(),
            "capability=systemd%0A".to_string(),
            long_capability,
        ] {
            let path = format!("/api/audit?{query}");
            let (status, _, _) = call(
                &state,
                Method::GET,
                &path,
                &[("cookie", &cookie)],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[test]
    fn validates_control_payload_boundaries() {
        assert!(
            validate_control_payload(&json!({"capability": "systemd", "action": "list"})).is_ok()
        );
        assert!(validate_control_payload(&json!({
            "capability": "logs",
            "action": "tail",
            "source": "s".repeat(MAX_CONTROL_TARGET_LEN),
            "lines": MAX_CONTROL_LINES,
        }))
        .is_ok());
        assert!(validate_control_payload(&json!({
            "capability": "process",
            "action": "kill",
            "pid": 1,
            "name": "n".repeat(MAX_CONTROL_TARGET_LEN),
            "signal": "term",
            "confirm": true,
        }))
        .is_ok());
        assert!(validate_control_payload(&json!({
            "capability": "process",
            "action": "kill",
            "pid": u32::MAX,
            "name": "x",
        }))
        .is_ok());

        for payload in [
            json!({"capability": "systemd", "action": "list", "target": "a".repeat(MAX_CONTROL_TARGET_LEN + 1)}),
            json!({"capability": "systemd", "action": "a".repeat(MAX_CONTROL_ACTION_LEN + 1)}),
            json!({"capability": "systemd", "action": "list", "pid": 0}),
            json!({"capability": "systemd", "action": "list", "pid": u64::from(u32::MAX) + 1}),
            json!({"capability": "systemd", "action": "list", "lines": MIN_CONTROL_LINES - 1}),
            json!({"capability": "systemd", "action": "list", "lines": MAX_CONTROL_LINES + 1}),
            json!({"capability": "", "action": "list"}),
            json!({"capability": "systemd", "action": ""}),
            json!({"capability": "systemd", "action": "list", "signal": ""}),
            json!({"capability": "systemd", "action": "list", "confirm": 1}),
            json!({"capability": "systemd", "action": "list", "extra": true}),
            json!([]),
        ] {
            assert!(
                validate_control_payload(&payload).is_err(),
                "应拒绝: {payload}"
            );
        }
    }

    fn pairs(values: &[(&str, &str)]) -> Vec<(String, String)> {
        values
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn validates_audit_query_boundaries() {
        assert!(validate_audit_query(&[]).is_ok());
        assert!(validate_audit_query(&pairs(&[
            ("limit", "100"),
            ("before_id", "0"),
            ("agent_id", "hub-self"),
            ("capability", "systemd"),
        ]))
        .is_ok());
        assert!(validate_audit_query(&pairs(&[("limit", "1")])).is_ok());
        assert!(validate_audit_query(&pairs(&[("limit", "200")])).is_ok());

        for query in [
            pairs(&[("limit", "0")]),
            pairs(&[("limit", "201")]),
            pairs(&[("before_id", "-1")]),
            pairs(&[("agent_id", "a b")]),
            pairs(&[("capability", "cap\ncontrol")]),
            pairs(&[("limit", "1"), ("limit", "2")]),
        ] {
            assert!(validate_audit_query(&query).is_err(), "应拒绝: {query:?}");
        }
    }

    #[tokio::test]
    async fn browser_never_receives_hub_token() {
        let hub_body =
            r#"{"control_enabled":false,"online":false,"capabilities":[],"hub_capabilities":[]}"#;
        let (hub_url, seen) = spawn_mock_hub(200, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/agents/hub-self/control",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!String::from_utf8_lossy(&body).contains(TEST_HUB_TOKEN));
        for (name, value) in &headers {
            assert!(
                !value.to_str().unwrap_or_default().contains(TEST_HUB_TOKEN),
                "响应头 {name} 泄露 hub token"
            );
        }
        // token 只允许出现在面板 → hub 的 Authorization 头里。
        let (head, _) = seen_request(&seen);
        assert_bearer_sent_to_hub(&head);
    }

    #[test]
    fn frontend_sources_never_contain_hub_token() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/src");
        assert!(root.is_dir(), "找不到前端源码目录: {}", root.display());
        let mut files = Vec::new();
        collect_source_files(&root, &mut files);
        assert!(!files.is_empty(), "前端源码目录为空");
        for file in files {
            let text = std::fs::read_to_string(&file).unwrap();
            assert!(
                !text.to_ascii_lowercase().contains("bearer"),
                "浏览器 bundle 不能带 Bearer 凭据: {}",
                file.display()
            );
            assert!(
                !text.contains(TEST_HUB_TOKEN),
                "浏览器 bundle 不能带 hub token: {}",
                file.display()
            );
        }
    }

    fn collect_source_files(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_source_files(&path, out);
            } else if matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("ts" | "tsx")
            ) {
                out.push(path);
            }
        }
    }

    #[test]
    fn detects_loopback_listen_addresses() {
        for listen in [
            "127.0.0.1:8080",
            "127.1.2.3:8080",
            "localhost:8080",
            "[::1]:8080",
        ] {
            assert!(listen_is_loopback(listen), "{listen} 应视为回环");
        }
        for listen in [
            "0.0.0.0:8080",
            "[::]:8080",
            "192.0.2.1:8080",
            "panel.example.com:8080",
            ":8080",
        ] {
            assert!(!listen_is_loopback(listen), "{listen} 不应视为回环");
        }
        assert_eq!(listen_host("127.0.0.1:8080"), Some("127.0.0.1"));
        assert_eq!(listen_host("[::1]:8080"), Some("::1"));
        assert_eq!(listen_host(":8080"), None);
    }

    #[tokio::test]
    async fn login_sets_cookie_and_creates_session() {
        let (state, _site) = test_state();
        let (status, headers, body) = call(
            &state,
            Method::POST,
            "/api/login",
            &[("content-type", "application/json")],
            Body::from(format!(r#"{{"password":"{TEST_PASSWORD}"}}"#)),
            Some("203.0.113.9:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
        let cookie = headers
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cookie.starts_with("rb_session="));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/"));
        assert!(!cookie.contains("Secure"));

        let token_part = cookie.split(';').next().unwrap();
        let (status, _, body) = call(
            &state,
            Method::GET,
            "/api/session",
            &[("cookie", token_part)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&body).contains("\"authenticated\":true"));
    }

    #[tokio::test]
    async fn login_over_https_proxy_sets_secure_cookie() {
        let (state, _site) = test_state();
        let (status, headers, _) = call(
            &state,
            Method::POST,
            "/api/login",
            &[
                ("content-type", "application/json"),
                ("x-forwarded-proto", "https"),
            ],
            Body::from(format!(r#"{{"password":"{TEST_PASSWORD}"}}"#)),
            Some("203.0.113.9:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cookie.contains("; Secure"));
    }

    #[tokio::test]
    async fn trusted_proxy_invalid_xff_is_rejected_without_falling_back() {
        let (state, _site) = test_state();
        let login_body = format!(r#"{{"password":"{TEST_PASSWORD}"}}"#);
        for xff in [
            "not-an-ip",
            "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8,9.9.9.9",
        ] {
            let (status, _, body) = call(
                &state,
                Method::POST,
                "/api/login",
                &[
                    ("content-type", "application/json"),
                    ("x-forwarded-for", xff),
                ],
                Body::from(login_body.clone()),
                Some("203.0.113.9:50000"),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "xff={xff}");
            assert!(String::from_utf8_lossy(&body).contains("invalid_forwarded_for"));
        }

        // 非可信来源的 XFF 完全忽略，不能被污染。
        let (status, _, _) = call(
            &state,
            Method::POST,
            "/api/login",
            &[
                ("content-type", "application/json"),
                ("x-forwarded-for", "not-an-ip"),
            ],
            Body::from(r#"{"password":"wrong-password"}"#),
            Some("198.51.100.1:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_requires_json_and_body_limit() {
        let (state, _site) = test_state();
        let (status, _, body) = call(
            &state,
            Method::POST,
            "/api/login",
            &[],
            Body::from(r#"{"password":"x"}"#),
            Some("203.0.113.10:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&body).contains("origin_mismatch"));

        let (status, _, _) = call(
            &state,
            Method::POST,
            "/api/login",
            &[("content-type", "text/plain")],
            Body::from(r#"{"password":"x"}"#),
            Some("203.0.113.10:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let huge = format!("{{\"password\":\"{}\"}}", "a".repeat(MAX_JSON_BODY + 16));
        let (status, _, _) = call(
            &state,
            Method::POST,
            "/api/login",
            &[("content-type", "application/json")],
            Body::from(huge),
            Some("203.0.113.10:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn locked_ip_gets_429_before_argon2() {
        let (state, _site) = test_state();
        let ip: std::net::IpAddr = "203.0.113.12".parse().unwrap();
        let now = now_ms();
        for _ in 0..auth::MAX_LOGIN_FAILURES {
            let guard = match state.limiter.begin_attempt(ip, now) {
                auth::AttemptDecision::Allowed(guard) => guard,
                auth::AttemptDecision::TooMany(_) => panic!("预占名额时不应提前锁定"),
            };
            state.limiter.record_failure(ip, now);
            guard.disarm();
        }
        let (status, headers, body) = call(
            &state,
            Method::POST,
            "/api/login",
            &[("content-type", "application/json")],
            Body::from(format!(r#"{{"password":"{TEST_PASSWORD}"}}"#)),
            Some("203.0.113.12:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(headers.contains_key(header::RETRY_AFTER));
        assert!(String::from_utf8_lossy(&body).contains("rate_limited"));
    }

    /// 回归：10 个并发错误密码最多 5 个进入 Argon2，其余必须 429；
    /// 不能因“先检查后计数”让所有请求都拿到 401。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_wrong_passwords_are_capped_before_argon2() {
        let (state, _site) = test_state();
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                let (status, _, _) = call(
                    &state,
                    Method::POST,
                    "/api/login",
                    &[("content-type", "application/json")],
                    Body::from(r#"{"password":"definitely-wrong-concurrent"}"#),
                    Some("203.0.113.13:50000"),
                )
                .await;
                status
            }));
        }

        let mut unauthorized = 0usize;
        let mut limited = 0usize;
        for task in tasks {
            match task.await.unwrap() {
                StatusCode::UNAUTHORIZED => unauthorized += 1,
                StatusCode::TOO_MANY_REQUESTS => limited += 1,
                other => panic!("意外状态码 {other}"),
            }
        }
        assert_eq!(unauthorized + limited, 10);
        assert!(
            limited >= auth::MAX_LOGIN_FAILURES as usize,
            "10 个并发错误尝试至少 5 个 429，实际 {limited}"
        );
        assert!(
            unauthorized <= auth::MAX_LOGIN_FAILURES as usize,
            "进入 Argon2 的错误尝试不能超过 5 次，实际 {unauthorized}"
        );
    }

    #[tokio::test]
    async fn encoded_traversal_is_rejected_by_router() {
        let (state, _site) = test_state();
        let (status, _, body) = call(
            &state,
            Method::GET,
            "/assets/%2e%2e/%2e%2e/etc/passwd",
            &[],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!String::from_utf8_lossy(&body).contains("root:"));
    }

    #[tokio::test]
    async fn wrong_password_is_401() {
        let (state, _site) = test_state();
        let (status, _, body) = call(
            &state,
            Method::POST,
            "/api/login",
            &[("content-type", "application/json")],
            Body::from(r#"{"password":"definitely-wrong"}"#),
            Some("203.0.113.11:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(String::from_utf8_lossy(&body).contains("unauthorized"));
    }

    #[tokio::test]
    async fn logout_clears_cookie_and_session() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        let (status, headers, _) = call(
            &state,
            Method::POST,
            "/api/logout",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::from("{}"),
            Some("203.0.113.30:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let cleared = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(cleared.contains("Max-Age=0"));

        let (_, _, body) = call(
            &state,
            Method::GET,
            "/api/session",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert!(String::from_utf8_lossy(&body).contains("\"authenticated\":false"));
    }

    #[tokio::test]
    async fn validates_settings_and_series_filters_before_proxying() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        let (status, _, _) = call(
            &state,
            Method::PUT,
            "/api/agents/hub-self/settings",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::from(r#"{"sample_interval_ms":999}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, _) = call(
            &state,
            Method::PUT,
            "/api/agents/hub-self/settings",
            &[
                ("cookie", &cookie),
                ("content-type", "text/plain"),
                ("host", "panel.test:8080"),
                ("origin", "http://panel.test:8080"),
            ],
            Body::from(r#"{"sample_interval_ms":1000}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);

        let (status, _, _) = call(
            &state,
            Method::GET,
            "/api/agents/../series?metric=cpu.usage&from=1&to=2",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, _) = call(
            &state,
            Method::GET,
            "/api/agents/hub-self/series?metric=cpu.usage",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, _) = call(
            &state,
            Method::GET,
            "/api/agents/hub-self/series?metric=cpu.usage&from=0&to=99999999999999",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn argon2_concurrency_is_capped_at_two() {
        let (state, _site) = test_state();
        assert_eq!(
            state.argon2_slots.available_permits(),
            MAX_CONCURRENT_ARGON2
        );
        assert_eq!(MAX_CONCURRENT_ARGON2, 2);
    }

    #[test]
    fn normalizes_hub_config_values() {
        assert_eq!(
            normalize_hub_url("127.0.0.1:8444/").unwrap(),
            "http://127.0.0.1:8444"
        );
        assert_eq!(
            normalize_hub_url("http://127.0.0.1:8444/").unwrap(),
            "http://127.0.0.1:8444"
        );
        assert!(normalize_hub_url("https://127.0.0.1:8444").is_err());
        assert!(normalize_hub_url("  ").is_err());

        assert_eq!(
            hub_url_from_admin_listen("0.0.0.0:8444"),
            "http://127.0.0.1:8444"
        );
        assert_eq!(hub_url_from_admin_listen("[::]:8444"), "http://[::1]:8444");
        assert_eq!(
            hub_url_from_admin_listen("127.0.0.1:9000"),
            "http://127.0.0.1:9000"
        );
    }

    #[test]
    fn init_listen_randomizes_only_when_omitted() {
        assert_eq!(
            init_listen(Some("0.0.0.0:18080".into())).unwrap(),
            "0.0.0.0:18080",
            "显式 --listen 必须原样落盘"
        );

        let first = init_listen(None).unwrap();
        let port = first
            .strip_prefix("127.0.0.1:")
            .expect("init 未传 --listen 时默认只绑 IPv4 回环")
            .parse::<u16>()
            .expect("init 必须带数字端口");
        assert_ne!(port, 0);

        let mut different = false;
        for _ in 0..8 {
            if init_listen(None).unwrap() != first {
                different = true;
                break;
            }
        }
        assert!(different, "init 未传 --listen 时必须随机选端口");
    }

    #[test]
    fn resolves_hub_token_and_reports_copy_source() {
        let hub = HubConfig {
            admin_token: "copied-from-hub-config".to_string(),
            ..HubConfig::default()
        };

        let (token, source) = resolve_hub_token(None, Some(&hub));
        assert_eq!(token.as_deref(), Some("copied-from-hub-config"));
        assert_eq!(source, Some(DEFAULT_HUB_CONFIG), "必须标注来源路径");

        let (token, source) = resolve_hub_token(Some(" explicit-token ".into()), Some(&hub));
        assert_eq!(token.as_deref(), Some("explicit-token"));
        assert_eq!(source, None);

        let (token, source) = resolve_hub_token(Some("   ".into()), Some(&hub));
        assert_eq!(
            token.as_deref(),
            Some("copied-from-hub-config"),
            "空白的 --hub-token 应回退到 hub 配置"
        );
        assert_eq!(source, Some(DEFAULT_HUB_CONFIG));

        let (token, _) = resolve_hub_token(None, None);
        assert!(token.is_none());
    }

    #[test]
    fn validates_query_parameter_boundaries() {
        // overview 下限与 hub overview 对齐为 1000ms。
        assert!(validate_window(
            &[("window_ms".into(), "60000".into())],
            MIN_OVERVIEW_WINDOW_MS
        )
        .is_ok());
        assert!(validate_window(
            &[("window_ms".into(), "1000".into())],
            MIN_OVERVIEW_WINDOW_MS
        )
        .is_ok());
        assert!(validate_window(
            &[("window_ms".into(), "999".into())],
            MIN_OVERVIEW_WINDOW_MS
        )
        .is_err());
        assert!(validate_window(
            &[("window_ms".into(), "3600001".into())],
            MIN_OVERVIEW_WINDOW_MS
        )
        .is_err());
        assert!(validate_window(
            &[
                ("window_ms".into(), "1000".into()),
                ("window_ms".into(), "2000".into())
            ],
            MIN_OVERVIEW_WINDOW_MS
        )
        .is_err());

        // latest 保留 hub latest 的 1ms 下限。
        assert!(validate_window(&[("window_ms".into(), "1".into())], MIN_LATEST_WINDOW_MS).is_ok());
        assert!(
            validate_window(&[("window_ms".into(), "0".into())], MIN_LATEST_WINDOW_MS).is_err()
        );

        let valid = vec![
            ("metric".to_string(), "cpu.usage".to_string()),
            ("metric".to_string(), "cpu.iowait".to_string()),
            ("from".to_string(), "1000".to_string()),
            ("to".to_string(), "2000".to_string()),
            ("bucket_ms".to_string(), "1000".to_string()),
        ];
        assert!(validate_series_query(&valid).is_ok());
        assert!(validate_series_query(&valid[..3]).is_err(), "缺少 to");
        assert!(validate_series_query(&valid[..1]).is_err(), "缺少 from/to");

        let mut duplicate = valid.clone();
        duplicate.push(("from".into(), "3000".into()));
        assert!(validate_series_query(&duplicate).is_err());

        let mut uppercase = valid.clone();
        uppercase[0].1 = "CPU.USAGE".into();
        assert!(validate_series_query(&uppercase).is_err());

        let mut too_wide = valid.clone();
        too_wide[3].1 = (1_700_000_000_000i64 + MAX_SERIES_SPAN_MS + 1).to_string();
        too_wide[2].1 = "1700000000000".into();
        assert!(validate_series_query(&too_wide).is_err());
    }

    #[test]
    fn generated_password_has_required_length() {
        let password = generate_password();
        assert_eq!(password.len(), GENERATED_PASSWORD_LEN);
        assert!(password.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(password, generate_password());
    }

    #[tokio::test]
    async fn same_origin_guard_blocks_cross_site_writes() {
        let (state, _site) = test_state();
        let (status, _, body) = call(
            &state,
            Method::POST,
            "/api/logout",
            &[
                ("content-type", "application/json"),
                ("host", "panel.test:8080"),
                ("origin", "https://evil.example"),
            ],
            Body::from("{}"),
            Some("203.0.113.30:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(String::from_utf8_lossy(&body).contains("origin_mismatch"));

        let (status, _, _) = call(
            &state,
            Method::POST,
            "/api/logout",
            &[
                ("content-type", "application/json"),
                ("host", "panel.test:8080"),
                ("origin", "http://panel.test:8080"),
            ],
            Body::from("{}"),
            Some("203.0.113.30:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);

        // 无 Origin 时必须 JSON；表单/text 一律 403。
        let (status, _, _) = call(
            &state,
            Method::POST,
            "/api/logout",
            &[("content-type", "application/x-www-form-urlencoded")],
            Body::from("{}"),
            Some("203.0.113.30:50000"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // GET 请求不受 Origin 中间件影响。
        let (status, _, _) = call(
            &state,
            Method::GET,
            "/api/session",
            &[("origin", "https://evil.example")],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[test]
    fn app_state_rejects_invalid_trusted_proxy() {
        let hash = auth::hash_password("panel-test-password").unwrap();
        let cfg = PanelConfig {
            hub_url: "http://127.0.0.1:1".to_string(),
            token: "test-hub-token".to_string(),
            admin_password_hash: hash,
            trusted_proxies: vec!["10.0.0.0/99".to_string()],
            ..PanelConfig::default()
        };
        let err = match AppState::new(cfg, None, None) {
            Ok(_) => panic!("非法 trusted_proxies 必须拒绝启动"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("trusted_proxies"));
    }

    #[test]
    fn reset_password_updates_hash_and_keeps_config_private() {
        let site = TempSite::new();
        let path = site.dir.join("panel.toml");
        let old = "old-password";
        let cfg = PanelConfig {
            hub_url: "http://127.0.0.1:1".to_string(),
            token: "test-hub-token".to_string(),
            admin_password_hash: auth::hash_password(old).unwrap(),
            trusted_proxies: vec!["127.0.0.1".to_string()],
            ..PanelConfig::default()
        };
        cfg.save(&path).unwrap();

        reset_password(Some(path.clone()), Some("new-password".to_string())).unwrap();
        let saved = PanelConfig::load(&path).unwrap();
        assert!(auth::verify_password(
            "new-password",
            &saved.admin_password_hash
        ));
        assert!(!auth::verify_password(old, &saved.admin_password_hash));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn reload_password_hash_updates_without_restart() {
        let site = TempSite::new();
        let path = site.dir.join("panel.toml");
        let old = "old-password";
        let cfg = PanelConfig {
            hub_url: "http://127.0.0.1:1".to_string(),
            token: "test-hub-token".to_string(),
            admin_password_hash: auth::hash_password(old).unwrap(),
            trusted_proxies: vec!["127.0.0.1".to_string()],
            ..PanelConfig::default()
        };
        cfg.save(&path).unwrap();
        let state = Arc::new(AppState::new(cfg, None, Some(path.clone())).unwrap());

        reset_password(Some(path), Some("new-password".to_string())).unwrap();
        assert!(state.reload_password_hash().unwrap());
        let hash = state
            .password_hash
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(auth::verify_password("new-password", &hash));
        assert!(!auth::verify_password(old, &hash));
        // 内容没再变化时不应重复报告。
        assert!(!state.reload_password_hash().unwrap());
    }

    #[tokio::test]
    async fn running_panel_picks_up_reset_password() {
        let site = TempSite::new();
        let path = site.dir.join("panel.toml");
        let old = "old-password";
        let cfg = PanelConfig {
            hub_url: "http://127.0.0.1:1".to_string(),
            token: "test-hub-token".to_string(),
            admin_password_hash: auth::hash_password(old).unwrap(),
            trusted_proxies: vec!["127.0.0.1".to_string()],
            ..PanelConfig::default()
        };
        cfg.save(&path).unwrap();
        let state = Arc::new(AppState::new(cfg, None, Some(path.clone())).unwrap());
        spawn_password_reload(state.clone());

        reset_password(Some(path.clone()), Some("new-password".to_string())).unwrap();
        let expected = PanelConfig::load(&path).unwrap().admin_password_hash;

        // 先只轮询哈希串，绝不在 timeout 里跑 Argon2（debug 下单次可能数秒）。
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let current = state
                    .password_hash
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                if current == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("热加载任务未在 5s 内应用新密码");

        let current = state
            .password_hash
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert_eq!(current, expected);

        // 密码校验放在 timeout 之外，避免 Argon2 在 current_thread 下拖垮限时。
        let old_hash = current.clone();
        let new_hash = current.clone();
        let (old_ok, new_ok) = tokio::task::spawn_blocking(move || {
            (
                auth::verify_password("old-password", &old_hash),
                auth::verify_password("new-password", &new_hash),
            )
        })
        .await
        .unwrap();
        assert!(!old_ok, "旧密码必须失效");
        assert!(new_ok, "新密码必须可用");
    }
}
