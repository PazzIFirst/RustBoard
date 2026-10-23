//! RustBoard 面板进程。
//!
//! 负责：单管理员登录（Argon2id + 内存会话）、把同源 `/api/*` 转发到 hub 管理 API、
//! 以及提供前端构建产物与 SPA 回退。hub 管理 token 只存在于本进程配置中，
//! 既不下发浏览器，也不写进日志。

mod auth;
mod proxy;
mod web;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::task::{Context as TaskContext, Poll};
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
use http_body::{Body as HttpBody, Frame as BodyFrame, SizeHint};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rustboard_common::config::{HubConfig, PanelConfig};
use rustboard_common::util::{now_ms, pick_free_port, port_of};
use rustboard_common::{
    DEFAULT_ADMIN_PORT, DEFAULT_HUB_CONFIG, DEFAULT_PANEL_CONFIG, DEFAULT_PANEL_PORT,
};
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::ServiceExt;

/// 登录 / 设置 / 控制面请求体上限。
const MAX_JSON_BODY: usize = 8 * 1024;
/// 同时进行的 Argon2 校验上限，避免 64 MiB × N 的内存 DoS。
const MAX_CONCURRENT_ARGON2: usize = 2;
/// 面板 HTTP 全局并发连接上限；超出后 accept 到的 TCP 立即关闭。
const ADMIN_MAX_CONNECTIONS: usize = 256;
/// 面板 HTTP 单来源 IP 并发连接上限；只绑回环时同样生效。
const ADMIN_MAX_CONNECTIONS_PER_IP: usize = 32;
/// HTTP/1 请求头读取超时，抵挡 slowloris 一类慢速攻击。
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// 请求体总读取超时（从 header 读完开始一次性计时，不随 frame 重置）。
///
/// header 超时只能挡住半截 header；`/api/login` 等读 body 的端点如果遇到
/// 「header 完整 + Content-Length 很大 + 不发 body」的客户端，会一直挂住并占满
/// 每 IP 连接槽位（反代后所有用户共享一个代理 IP）。10s 是正常请求的宽裕上限。
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// 单 IP 连接表容量：超过后清理空项并拒绝新来源，防止无限增长。
const MAX_IP_CONNECTION_ENTRIES: usize = 4096;
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
        let proxy = proxy::ProxyClient::new(&cfg.hub_url, &cfg.token, &cfg.hub_ca)
            .context("初始化 hub 客户端失败")?;
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
    ///
    /// 哈希真正变化时在**密码写锁内**递增认证代际，再吊销全部已有会话：登录
    /// 侧先取代际、后读哈希，因此不会读到「新哈希 + 旧代际」；而在途登录用旧
    /// 代际建会话会被拒绝，旧密码会话无法在清空之后复活。其他字段重载（哈希
    /// 未变）返回 `false`，不 bump 代际、不动会话表。为避免锁顺序问题，密码写
    /// 锁在调用 [`auth::SessionStore::revoke_all`] 之前显式释放。
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
        // 必须与哈希更新同处密码写锁内：登录读取「代际 → 哈希」两步之间若插入
        // 一次 bump，就会让旧哈希配上新代际，旧密码依然能通过代际检查。
        let generation = self.sessions.bump_generation();
        // 先释放密码写锁，再清会话表：避免持锁做无关操作，也不让两把锁嵌套。
        drop(guard);
        let revoked = self.sessions.revoke_all();
        tracing::info!(
            path = %path.display(),
            generation,
            revoked,
            "检测到面板密码变更，已热加载新哈希并吊销全部已有会话"
        );
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
    // 顺序不能反：先取代际，再读哈希。reload 在密码写锁内先更新哈希再 bump，
    // 所以这里读到「新哈希 + 旧代际」只会导致一次保守的 401；反过来则可能读到
    // 旧哈希 + 新代际，让旧密码在重置后通过代际检查。
    let generation = state.sessions.generation();
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
            // 校验期间可能发生过密码重置：只有代际未变才允许建会话。否则旧密码
            // 的校验结果会在 revoke_all 之后插入一个旧密码会话，存活整个 TTL。
            let Some(token) = state.sessions.create_if_generation(now, generation) else {
                // 凭据本身有效，只是已因改密失效：不记密码错误、不清限流状态，
                // 归还 begin_attempt 预占的名额即可。响应与密码错误完全一致，
                // 不回显“密码已变更”，避免泄露重置时序。
                drop(attempt_guard);
                tracing::warn!(ip = %ip, "面板登录失败：密码在校验期间被重置");
                return proxy::json_error(StatusCode::UNAUTHORIZED, "unauthorized");
            };
            state.limiter.record_success(ip);
            attempt_guard.disarm();
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

/// 单 IP 并发连接计数（KI-17）。
///
/// 与 hub 的 `ConnectionLimiter` 语义一致：计数归零立即删键、来源表有硬上限。
/// hub 与 panel 是两个进程，把这份逻辑放进 `rustboard-common` 会把 tokio/hyper
/// 依赖带进公共 crate，因此保留两份实现；改动时两处必须同步。
struct ConnectionLimiter {
    max_per_ip: usize,
    max_ip_entries: usize,
    per_ip: StdMutex<HashMap<IpAddr, usize>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionLimitRejection {
    /// 该来源 IP 已达并发上限。
    PerIp,
    /// 来源 IP 表已满（大量不同来源）。
    TableFull,
}

/// 一条连接持有的限额凭证；Drop 时归还 per-IP 计数。
struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    ip: IpAddr,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut per_ip = match self.limiter.per_ip.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(count) = per_ip.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                // 计数归零立即删键：长时间运行不会积累已断开的来源。
                per_ip.remove(&self.ip);
            }
        }
    }
}

impl ConnectionLimiter {
    fn new(max_per_ip: usize) -> Self {
        Self::with_ip_capacity(max_per_ip, MAX_IP_CONNECTION_ENTRIES)
    }

    fn with_ip_capacity(max_per_ip: usize, max_ip_entries: usize) -> Self {
        Self {
            max_per_ip: max_per_ip.max(1),
            max_ip_entries: max_ip_entries.max(1),
            per_ip: StdMutex::new(HashMap::new()),
        }
    }

    fn try_acquire(
        self: &Arc<Self>,
        ip: IpAddr,
    ) -> std::result::Result<ConnectionPermit, ConnectionLimitRejection> {
        let mut per_ip = match self.per_ip.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let current = per_ip.get(&ip).copied().unwrap_or(0);
        if current >= self.max_per_ip {
            return Err(ConnectionLimitRejection::PerIp);
        }
        if current == 0 {
            if per_ip.len() >= self.max_ip_entries {
                // 正常情况下计数归零即删键，这里只清理异常残留。
                per_ip.retain(|_, count| *count > 0);
                if per_ip.len() >= self.max_ip_entries {
                    return Err(ConnectionLimitRejection::TableFull);
                }
            }
            per_ip.insert(ip, 1);
        } else {
            per_ip.insert(ip, current + 1);
        }
        Ok(ConnectionPermit {
            limiter: self.clone(),
            ip,
        })
    }

    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        match self.per_ip.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

/// 尝试占用一个全局连接许可；返回 None 表示已达上限，调用方应关闭 TCP。
fn try_acquire_connection(permits: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    permits.clone().try_acquire_owned().ok()
}

/// boxed body error，axum 的 `Body::new` 也接受这个错误类型。
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// 请求体总读取超时错误。
#[derive(Debug)]
struct BodyReadTimeout;

impl std::fmt::Display for BodyReadTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("请求体读取超时")
    }
}

impl std::error::Error for BodyReadTimeout {}

/// 请求体总超时包装（KI-17 剩余缺口）。
///
/// 从请求进入（header 读完）启动**一次性** deadline，不随每个 frame 重置，
/// 因此逐字节 drip 也无法延长；超时后向 axum 返回 body 错误，连接随请求结束关闭。
/// 用 `Pin<Box<_>>` 避免引入 pin-project 依赖。
struct DeadlineBody<B> {
    inner: Pin<Box<B>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    timed_out: bool,
}

impl<B> DeadlineBody<B> {
    fn new(inner: B, timeout: Duration) -> Self {
        Self {
            inner: Box::pin(inner),
            deadline: Box::pin(tokio::time::sleep(timeout)),
            timed_out: false,
        }
    }
}

impl<B> HttpBody for DeadlineBody<B>
where
    B: HttpBody + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Data = B::Data;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<BodyFrame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.timed_out {
            return Poll::Ready(None);
        }
        // 先检查一次性 deadline：即使 inner 永远 Pending，也会在 10s 时返回错误。
        if this.deadline.as_mut().poll(cx).is_ready() {
            this.timed_out = true;
            return Poll::Ready(Some(Err(Box::new(BodyReadTimeout))));
        }
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err.into()))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        // 超时后对上层表现为流已结束，避免被误判为还有 body。
        self.timed_out || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// 面板 HTTP 的 accept 循环（KI-17）。
///
/// 不用 `axum::serve`：它没有 header 读超时，也拿不到连接数。这里手工 accept，
/// 做「全局 + 每来源 IP」并发限制、HTTP/1 header 超时与请求体总超时；半截
/// header 的慢连接最多占用 [`HEADER_READ_TIMEOUT`]，慢 body 最多占用
/// [`BODY_READ_TIMEOUT`]，洪水下 `/healthz` 仍可用。
async fn serve_panel_listener(app: Router, listener: TcpListener) -> Result<()> {
    let local = listener.local_addr().context("读取面板监听地址失败")?;
    // 与 Argon2 的 `state.argon2_slots` 完全独立，不能混用许可。
    let permits = Arc::new(Semaphore::new(ADMIN_MAX_CONNECTIONS.max(1)));
    let limits = Arc::new(ConnectionLimiter::new(ADMIN_MAX_CONNECTIONS_PER_IP));
    tracing::info!(
        listen = %local,
        max_connections = ADMIN_MAX_CONNECTIONS,
        max_connections_per_ip = ADMIN_MAX_CONNECTIONS_PER_IP,
        "面板连接限制已启用"
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // 单个 accept 失败（例如 fd 瞬时耗尽）不应让整个面板退出。
                tracing::warn!(error = %err, "面板 accept 失败，100ms 后重试");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        // 先占全局槽位，拿不到立即关 TCP（不读请求、不回响应）。
        let permit = match try_acquire_connection(&permits) {
            Some(permit) => permit,
            None => {
                tracing::warn!(
                    %peer,
                    max_connections = ADMIN_MAX_CONNECTIONS,
                    "面板连接数已达上限，直接关闭 TCP"
                );
                continue;
            }
        };

        // 再占来源 IP 槽位；计数归零时删键，表容量有上限。
        let connection = match limits.try_acquire(peer.ip()) {
            Ok(connection) => connection,
            Err(ConnectionLimitRejection::PerIp) => {
                tracing::warn!(
                    ip = %peer.ip(),
                    max_connections_per_ip = ADMIN_MAX_CONNECTIONS_PER_IP,
                    "面板来源 IP 并发连接已达上限，直接关闭 TCP"
                );
                continue;
            }
            Err(ConnectionLimitRejection::TableFull) => {
                tracing::warn!(ip = %peer.ip(), "面板连接来源表已满，拒绝新来源");
                continue;
            }
        };

        if let Err(err) = tcp.set_nodelay(true) {
            tracing::debug!(%peer, error = %err, "设置 TCP_NODELAY 失败");
        }

        let app = app.clone();
        tokio::spawn(async move {
            // 许可跟随连接生命周期；连接关闭（含超时）后自动归还。
            let _permit = permit;
            let _connection = connection;

            // 登录限速 / 可信反代取 IP 依赖 ConnectInfo<SocketAddr>，逐请求注入。
            // KI-17：请求体套一次性总 deadline，慢 body 最多占 10s，不随 frame 重置。
            let service = tower::service_fn(move |req: hyper::Request<Incoming>| {
                let (mut parts, incoming) = req.into_parts();
                parts.extensions.insert(ConnectInfo(peer));
                let body = Body::new(DeadlineBody::new(incoming, BODY_READ_TIMEOUT));
                let req = hyper::Request::from_parts(parts, body);
                let app = app.clone();
                async move { app.oneshot(req).await }
            });

            // 不用 hyper-util 的 auto builder：它的 HTTP 版本嗅探阶段没有超时。
            // http1 Builder 只对「读 header」计时；body 由 DeadlineBody 的 10s 总
            // deadline 单独约束，不会因为 header 超时被提前杀掉。
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(tcp), TowerToHyperService::new(service))
                .with_upgrades()
                .await
            {
                // 只记录来源与错误，不记录请求头。
                tracing::debug!(%peer, error = %err, "面板连接结束");
            }
        });
    }
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
        let listener = TcpListener::bind(&listen)
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
        // KI-17：手工 accept，带 header 读超时与全局 / 每 IP 连接上限。
        serve_panel_listener(app, listener).await
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

/// `reset-password` 成功后的会话失效提示。
///
/// 热加载轮询周期为 1s（最长可能因一次阻塞读取顺延），因此按 ≤2s 承诺；
/// 精确行为由 e2e 覆盖。
const RESET_PASSWORD_HINT: &str = "提示: 运行中的面板会在 2 秒内自动加载新密码（无需重启）；\
     已有面板会话将在 ≤2s 内失效，请用新密码重新登录。";

/// 重置管理员密码：写回新的 Argon2id PHC 哈希（配置保持 0600）。
///
/// 未传 `--password` 时生成 20 位随机密码；stdout 只展示一次。
/// 已登录会话保存在内存里；运行中的面板检测到新哈希后会吊销全部已有会话
/// （≤2s），未运行时重启后面板内存表自然为空。
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
    println!("{RESET_PASSWORD_HINT}");
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

/// 把 `127.0.0.1:8444` / `0.0.0.0:8444` / `http://...` / `https://...` 统一成面板可用的 hub 地址。
///
/// 无 scheme 时仍默认 `http://`（兼容旧 CLI 用法与同机回环部署）；
/// `https://` 原样保留。是否允许明文 http 由 [`proxy::ProxyClient::new`] 在启动时按
/// host 是否为回环裁决——这样 `panel init` 可以先把远程地址写进配置，
/// 由运行时给出统一的安全错误。
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
        Arc::new(AppState::new(cfg, None, None).unwrap())
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
        assert_eq!(
            normalize_hub_url("https://hub.example.com:8444/").unwrap(),
            "https://hub.example.com:8444",
            "v0.3.3 起 https:// 必须原样保留"
        );
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
        // 成功提示必须明确告知已有会话会失效，且不超过 2s。
        assert!(RESET_PASSWORD_HINT.contains("≤2s"));
        assert!(RESET_PASSWORD_HINT.contains("失效"));

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

        let now = now_ms();
        let first = state.sessions.create(now);
        let second = state.sessions.create(now);
        assert!(state.sessions.is_authenticated(&first, now));
        assert!(state.sessions.is_authenticated(&second, now));

        // 其他配置字段变化、哈希未变：reload 返回 false，已有会话不受影响。
        let mut touched = PanelConfig::load(&path).unwrap();
        touched.listen = "127.0.0.1:18081".to_string();
        touched.save(&path).unwrap();
        assert!(!state.reload_password_hash().unwrap());
        assert!(
            state.sessions.is_authenticated(&first, now),
            "哈希未变时普通重载不得清除会话"
        );
        assert!(state.sessions.is_authenticated(&second, now));

        // 密码变化：旧会话全部失效；吊销后新会话可正常创建与认证。
        reset_password(Some(path), Some("new-password".to_string())).unwrap();
        assert!(state.reload_password_hash().unwrap());
        let hash = state
            .password_hash
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(auth::verify_password("new-password", &hash));
        assert!(!auth::verify_password(old, &hash));
        assert!(!state.sessions.is_authenticated(&first, now));
        assert!(!state.sessions.is_authenticated(&second, now));

        let fresh = state.sessions.create(now);
        assert!(state.sessions.is_authenticated(&fresh, now));

        // 内容没再变化时不应重复报告，也不能再次清空会话。
        assert!(!state.reload_password_hash().unwrap());
        assert!(
            state.sessions.is_authenticated(&fresh, now),
            "相同哈希的 reload 不得清除新会话"
        );
    }

    /// KI-18 配套：只有哈希真正变化才 bump 认证代际并清会话；
    /// 普通配置重载 / 相同哈希不得影响已有会话。
    #[test]
    fn reload_password_hash_bumps_generation_only_on_real_change() {
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
        let state = AppState::new(cfg, None, Some(path.clone())).unwrap();
        let now = now_ms();
        let initial_generation = state.sessions.generation();
        assert_eq!(initial_generation, 0);
        let session = state
            .sessions
            .create_if_generation(now, initial_generation)
            .expect("初始代际应允许创建会话");

        // 其他字段变化、哈希未变：不 bump、不清会话。
        let mut touched = PanelConfig::load(&path).unwrap();
        touched.listen = "127.0.0.1:18082".to_string();
        touched.save(&path).unwrap();
        assert!(!state.reload_password_hash().unwrap());
        assert_eq!(state.sessions.generation(), initial_generation);
        assert!(
            state.sessions.is_authenticated(&session, now),
            "哈希未变时普通重载不得清除会话"
        );

        // 内容未变再次 reload：仍不 bump、不清会话。
        assert!(!state.reload_password_hash().unwrap());
        assert_eq!(state.sessions.generation(), initial_generation);
        assert!(state.sessions.is_authenticated(&session, now));

        // 密码变化：代际 +1、旧会话清空、旧代际拒绝、新代际放行。
        reset_password(Some(path), Some("new-password".to_string())).unwrap();
        assert!(state.reload_password_hash().unwrap());
        let new_generation = initial_generation + 1;
        assert_eq!(state.sessions.generation(), new_generation);
        assert!(!state.sessions.is_authenticated(&session, now));
        assert!(state
            .sessions
            .create_if_generation(now, initial_generation)
            .is_none());
        assert_eq!(state.sessions.len(), 0);
        let fresh = state
            .sessions
            .create_if_generation(now, new_generation)
            .expect("新代际应允许创建会话");
        assert!(state.sessions.is_authenticated(&fresh, now));

        // 新哈希未再变化：不得二次 bump，也不得误杀新会话。
        assert!(!state.reload_password_hash().unwrap());
        assert_eq!(state.sessions.generation(), new_generation);
        assert!(state.sessions.is_authenticated(&fresh, now));
    }

    /// 回归 KI-18：登录读取旧代际后进入 Argon2，期间 reset-password 生效；
    /// 校验完成时用旧代际建会话必须失败，清空后不能复活旧密码会话。
    /// 单线程两步复现，不依赖真实 Argon2 时长与线程调度。
    #[test]
    fn password_reset_invalidates_in_flight_login_generation() {
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
        let state = AppState::new(cfg, None, Some(path.clone())).unwrap();
        let now = now_ms();

        // 登录 handler 的第一步：先取代际，再 clone 哈希，然后进入 Argon2。
        let login_generation = state.sessions.generation();
        let login_hash = state
            .password_hash
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(
            auth::verify_password(old, &login_hash),
            "登录应能校验旧密码"
        );

        // 模拟 Argon2 期间管理员改密：热加载会 bump 代际并清空会话。
        let stale = state.sessions.create(now);
        assert!(state.sessions.is_authenticated(&stale, now));
        reset_password(Some(path), Some("new-password".to_string())).unwrap();
        assert!(state.reload_password_hash().unwrap());
        assert!(state.sessions.generation() > login_generation);
        assert!(!state.sessions.is_authenticated(&stale, now));

        // 登录侧校验完成后用旧代际建会话必须失败，且不得插入会话。
        assert!(
            state
                .sessions
                .create_if_generation(now, login_generation)
                .is_none(),
            "旧代际登录不得在 revoke_all 之后复活会话"
        );
        assert_eq!(state.sessions.len(), 0);

        // 新代际 + 新哈希是唯一能建会话的组合。
        let current_generation = state.sessions.generation();
        let current_hash = state
            .password_hash
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        assert!(auth::verify_password("new-password", &current_hash));
        assert!(!auth::verify_password(old, &current_hash));
        let fresh = state
            .sessions
            .create_if_generation(now, current_generation)
            .expect("新代际应允许创建会话");
        assert!(state.sessions.is_authenticated(&fresh, now));
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
        // 模拟改密前已登录的浏览器；轮询任务应用新哈希后它必须失效。
        let now = now_ms();
        let stale = state.sessions.create(now);
        assert!(state.sessions.is_authenticated(&stale, now));
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

        // 轮询任务应用新哈希时已经吊销了改密前的会话。
        assert!(
            !state.sessions.is_authenticated(&stale, now),
            "热加载新密码后旧会话必须失效"
        );
        let fresh = state.sessions.create(now);
        assert!(state.sessions.is_authenticated(&fresh, now));

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

    // ------------------------------------------------------------------
    // KI-17：面板慢速连接防护（A1）
    // ------------------------------------------------------------------

    /// KI-17：per-IP 上限、计数归零删键、来源表容量与陈旧项清理。
    #[test]
    fn connection_limiter_per_ip_cleanup_and_table_capacity() {
        use std::net::IpAddr;

        let limiter = Arc::new(ConnectionLimiter::with_ip_capacity(2, 2));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        let ip3: IpAddr = "10.0.0.3".parse().unwrap();

        let first = limiter.try_acquire(ip1).expect("第 1 条连接必须允许");
        let second = limiter.try_acquire(ip1).expect("第 2 条连接必须允许");
        assert!(
            matches!(
                limiter.try_acquire(ip1),
                Err(ConnectionLimitRejection::PerIp)
            ),
            "同一 IP 第 3 条连接必须被拒绝"
        );
        assert_eq!(limiter.tracked_ips(), 1);

        let other = limiter.try_acquire(ip2).expect("其他 IP 不受影响");
        assert!(
            matches!(
                limiter.try_acquire(ip3),
                Err(ConnectionLimitRejection::TableFull)
            ),
            "来源表满时必须拒绝新 IP"
        );

        // 计数归零后立即删键，新 IP 可以进入。
        drop(first);
        drop(second);
        let third = limiter.try_acquire(ip3).expect("清理归零项后应有空间");
        drop(other);
        assert_eq!(limiter.tracked_ips(), 1, "ip3 仍在线");
        drop(third);
        assert_eq!(limiter.tracked_ips(), 0, "全部断开后表必须清空");
    }

    /// KI-17：header 超时与连接上限的取值必须符合方案（30 条慢连接测试依赖它们）。
    #[test]
    fn header_read_timeout_and_connection_limits() {
        assert_eq!(HEADER_READ_TIMEOUT, Duration::from_secs(5));
        assert_eq!(BODY_READ_TIMEOUT, Duration::from_secs(10));
        assert_eq!(ADMIN_MAX_CONNECTIONS, 256);
        assert_eq!(ADMIN_MAX_CONNECTIONS_PER_IP, 32);
    }

    /// 测试路由：验证手工 accept 循环给请求注入了 `ConnectInfo<SocketAddr>`。
    async fn test_peer_ip(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
        peer.ip().to_string()
    }

    /// 测试路由：完整读取请求体（验证 body 总超时只作用于真正读 body 的请求）。
    async fn test_consume_body(_body: Bytes) -> &'static str {
        "ok"
    }

    /// 启动一个只提供 `/healthz`、`/peer`、`/consume` 的最小面板口，返回地址与 server 任务。
    async fn spawn_test_panel_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定测试端口");
        let addr = listener.local_addr().expect("读取测试端口");
        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/peer", get(test_peer_ip))
            .route("/consume", post(test_consume_body));
        let server = tokio::spawn(async move {
            let _ = serve_panel_listener(app, listener).await;
        });
        (addr, server)
    }

    /// 发一个完整的 `GET` 请求（带 `Connection: close`），返回原始响应文本。
    async fn test_http_get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let mut stream = tokio::net::TcpStream::connect(addr).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok(String::from_utf8_lossy(&response).into_owned())
    }

    /// KI-17：30 条只发半截 header 的 TCP 必须在 10s 内全部被关闭，
    /// 且慢连接存续期间与关闭之后 `/healthz` 都仍返回 200。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slow_header_connections_are_closed_and_healthz_available() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (addr, server) = spawn_test_panel_server().await;
        let response = test_http_get(addr, "/healthz")
            .await
            .expect("启动后的健康检查失败");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "启动后 /healthz 必须 200: {response}"
        );

        // 手工 accept 循环必须继续注入 ConnectInfo（登录限速/可信反代依赖它）。
        let peer = test_http_get(addr, "/peer")
            .await
            .expect("ConnectInfo 测试请求失败");
        assert!(
            peer.contains("127.0.0.1"),
            "手工 accept 必须注入 ConnectInfo<SocketAddr>: {peer}"
        );

        let partial = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Slow: ";
        let mut slow = Vec::new();
        for _ in 0..30 {
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("连接面板");
            stream.write_all(partial).await.expect("写半截 header");
            slow.push(stream);
        }
        // 让 accept 循环把这些连接登记进限额表。
        tokio::time::sleep(Duration::from_millis(100)).await;

        // 慢连接仍占用 fd 时，健康检查必须可用（30 < 全局 / 每 IP 上限）。
        let response = test_http_get(addr, "/healthz")
            .await
            .expect("慢连接存续期间健康检查失败");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "慢连接存续期间 /healthz 必须仍 200: {response}"
        );

        let started = std::time::Instant::now();
        let mut readers = Vec::new();
        for mut stream in slow {
            readers.push(tokio::spawn(async move {
                let mut buf = [0u8; 128];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            }));
        }
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            for reader in readers {
                let _ = reader.await;
            }
        })
        .await;
        assert!(closed.is_ok(), "30 条半截 header 连接必须在 10s 内被关闭");
        assert!(
            started.elapsed() <= Duration::from_secs(10),
            "连接关闭耗时 {:?} 超过 10s",
            started.elapsed()
        );

        let response = test_http_get(addr, "/healthz")
            .await
            .expect("慢连接关闭后健康检查失败");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "慢连接关闭后 /healthz 必须仍 200: {response}"
        );

        server.abort();
    }

    /// KI-17 剩余缺口：header 完整、`Content-Length` 很大但永不发送 body 的连接，
    /// 必须在请求体总超时后关闭（或收到非 2xx），且不能影响 `/healthz`。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn body_read_timeout_closes_connection_without_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (addr, server) = spawn_test_panel_server().await;
        // 先确认 server 已就绪。
        let health = test_http_get(addr, "/healthz")
            .await
            .expect("启动后健康检查失败");
        assert!(
            health.starts_with("HTTP/1.1 200"),
            "启动后 /healthz 必须 200: {health}"
        );

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("连接面板");
        // header 完整，声明 8192 字节 body，但一个 body 字节都不发。
        stream
            .write_all(
                b"POST /consume HTTP/1.1\r\nHost: localhost\r\nContent-Length: 8192\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .expect("写完整 header");

        let started = std::time::Instant::now();
        let reader = tokio::spawn(async move {
            let mut response = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        response.extend_from_slice(&buf[..n]);
                        // 400/413 响应很小；读到上限只是为了不在异常情况下无限读。
                        if response.len() >= 16 * 1024 {
                            break;
                        }
                    }
                }
            }
            response
        });

        // 慢 body 连接存续期间，/healthz 必须仍然可用。
        tokio::time::sleep(Duration::from_millis(500)).await;
        let health = test_http_get(addr, "/healthz")
            .await
            .expect("慢 body 连接存续期间健康检查失败");
        assert!(
            health.starts_with("HTTP/1.1 200"),
            "慢 body 连接存续期间 /healthz 必须仍 200: {health}"
        );

        let response = tokio::time::timeout(Duration::from_secs(12), reader)
            .await
            .expect("header 完整但没有 body 的连接必须在 12s 内关闭或返回响应")
            .expect("读取任务不得 panic");
        let elapsed = started.elapsed();
        // 必须真的等到 body deadline 才关闭：防止路由/提取器提前 404 让用例假通过。
        assert!(
            elapsed >= BODY_READ_TIMEOUT.saturating_sub(Duration::from_secs(1)),
            "连接过早关闭（{elapsed:?}），没有等到请求体 deadline"
        );
        assert!(
            elapsed <= Duration::from_secs(12),
            "连接关闭耗时 {elapsed:?} 超过 12s"
        );
        if !response.is_empty() {
            let text = String::from_utf8_lossy(&response);
            assert!(
                !text.starts_with("HTTP/1.1 2"),
                "请求体超时不得返回 2xx（实际响应: {text}）"
            );
        }
        eprintln!(
            "面板请求体超时：{elapsed:?} 后关闭，收到 {} 字节响应",
            response.len()
        );

        let health = test_http_get(addr, "/healthz")
            .await
            .expect("超时关闭后健康检查失败");
        assert!(
            health.starts_with("HTTP/1.1 200"),
            "超时关闭后 /healthz 必须仍 200: {health}"
        );

        server.abort();
    }
}
