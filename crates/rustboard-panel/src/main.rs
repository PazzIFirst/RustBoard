//! RustBoard 面板进程。
//!
//! 负责：单管理员登录（Argon2id + 内存会话）、把同源 `/api/*` 转发到 hub 管理 API、
//! 以及提供前端构建产物与 SPA 回退。hub 管理 token 只存在于本进程配置中，
//! 既不下发浏览器，也不写进日志。

mod auth;
mod install_cmd;
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

use anyhow::{anyhow, bail, Context, Result};
use axum::body::Body;
use axum::extract::{ConnectInfo, Path as AxumPath, RawQuery, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{any, delete, get, post, put};
use axum::Router;
use clap::{Parser, Subcommand};
use http_body::{Body as HttpBody, Frame as BodyFrame, SizeHint};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rand::distributions::Alphanumeric;
use rand::Rng;
use rustboard_common::config::{AdminTlsMode, CookieSecure, HubConfig, PanelConfig, ServerTlsMode};
use rustboard_common::util::{now_ms, pick_free_port, port_of};
use rustboard_common::{
    fsutil, tls, DEFAULT_ADMIN_PORT, DEFAULT_HUB_CONFIG, DEFAULT_PANEL_CONFIG, DEFAULT_PANEL_PORT,
};
use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower::ServiceExt;

/// 登录 / 设置 / 控制面请求体上限。
const MAX_JSON_BODY: usize = 8 * 1024;
/// 告警规则 / 静默 / 渠道写请求体上限（方案 §8.1：64 KiB）。
const MAX_ALERT_BODY: usize = 64 * 1024;
/// 告警事件单页上限；与 hub 的 `MAX_ALERT_EVENT_LIMIT` 对齐。
const MAX_ALERT_EVENT_LIMIT: i64 = 100;
/// 归档对象单页上限；与 hub 的 `MAX_ARCHIVE_OBJECT_LIMIT` 对齐。
const MAX_ARCHIVE_OBJECT_LIMIT: i64 = 100;
/// 同时进行的 Argon2 校验上限，避免 64 MiB × N 的内存 DoS。
const MAX_CONCURRENT_ARGON2: usize = 2;
/// 面板 HTTP/HTTPS 全局并发连接上限；超出后 accept 到的 TCP 立即关闭。
const ADMIN_MAX_CONNECTIONS: usize = 256;
/// 面板 HTTP/HTTPS 单来源 IP 并发连接上限；只绑回环时同样生效。
const ADMIN_MAX_CONNECTIONS_PER_IP: usize = 32;
/// HTTP/1 请求头读取超时，抵挡 slowloris 一类慢速攻击。
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// 请求体总读取超时（从 header 读完开始一次性计时，不随 frame 重置）。
///
/// header 超时只能挡住半截 header；`/api/login` 等读 body 的端点如果遇到
/// 「header 完整 + Content-Length 很大 + 不发 body」的客户端，会一直挂住并占满
/// 每 IP 连接槽位（反代后所有用户共享一个代理 IP）。10s 是正常请求的宽裕上限。
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// TLS 握手超时：与 header 超时同属 KI-17 的连接占用约束，避免慢握手绕过限流。
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 面板 TLS 证书 / 私钥文件大小上限（方案 D6：≤1 MiB）。
pub(crate) const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;
/// 单 IP 连接表容量：超过后清理空项并拒绝新来源，防止无限增长。
const MAX_IP_CONNECTION_ENTRIES: usize = 4096;
/// 自动生成的密码长度。
const GENERATED_PASSWORD_LEN: usize = 20;
/// 密码最短长度（仅约束 init 写入的密码）。
const MIN_PASSWORD_LEN: usize = 8;
/// series 查询最大跨度（730 天）。
///
/// 与 hub 的 `MAX_SERIES_SPAN_MS` 对齐，覆盖 1h 层默认保留期；面板只做代理，
/// 更细的选层与 bucket 提升由 hub 负责。
const MAX_SERIES_SPAN_MS: i64 = 730 * 24 * 3600 * 1000;
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
/// 面板默认明文 HTTP（C7 可直连 HTTPS），CSP 只允许同源资源；uPlot 运行时写入的 style 属性靠
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
        /// Hub 的私有 CA（PEM）；只在 https hub 时使用，复制到配置文件旁。
        #[arg(long)]
        hub_ca: Option<PathBuf>,
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
    /// 安装面板服务（生成配置、systemd unit 与初始密码）。
    Install(install_cmd::InstallArgs),
    /// 卸载面板服务（默认保留配置与数据）。
    Uninstall(install_cmd::UninstallArgs),
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
            hub_ca,
            password,
            static_dir,
            force,
        } => init(
            config, listen, hub, hub_token, hub_ca, password, static_dir, force,
        ),
        Cmd::Ports { config } => ports(config),
        Cmd::ResetPassword { config, password } => reset_password(config, password),
        Cmd::Install(args) => install_cmd::install(args),
        Cmd::Uninstall(args) => install_cmd::uninstall(args),
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
        // M4-B3 告警管理：全部要求已登录会话，路径 id / 查询参数在面板先校验，
        // 其余业务规则与 secret 脱敏由 hub 负责。
        .route(
            "/api/alerts/rules",
            get(api_alert_rules_list).post(api_alert_rule_create),
        )
        .route(
            "/api/alerts/rules/{id}",
            put(api_alert_rule_update).delete(api_alert_rule_delete),
        )
        .route("/api/alerts/events", get(api_alert_events))
        .route(
            "/api/alerts/silences",
            get(api_alert_silences_list).post(api_alert_silence_create),
        )
        .route(
            "/api/alerts/silences/{id}",
            delete(api_alert_silence_delete),
        )
        .route(
            "/api/alerts/channels",
            get(api_alert_channels_list).post(api_alert_channel_create),
        )
        .route(
            "/api/alerts/channels/{id}",
            put(api_alert_channel_update).delete(api_alert_channel_delete),
        )
        .route(
            "/api/alerts/channels/{id}/test",
            post(api_alert_channel_test),
        )
        // M4-C2b 归档数据页：列表走普通 JSON 代理；下载必须流式转发，不能进
        // 8 MiB JSON 缓冲。两者都要求已登录会话。
        .route("/api/archive/status", get(api_archive_status))
        .route("/api/archive/objects", get(api_archive_objects))
        .route(
            "/api/archive/objects/{id}/download",
            get(api_archive_object_download),
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
/// 等面板自己产生的响应也不会被浏览器按 HTML 解析。归档下载是唯一例外：它的
/// 成功响应必须是 `application/gzip` + `attachment`，错误分支已由代理层自行
/// 声明 JSON，因此下载路径不做覆盖。
async fn force_json_content_type(request: Request, next: Next) -> Response {
    let is_download = is_archive_download_path(request.uri().path());
    let mut response = next.run(request).await;
    if !is_download {
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    response
}

/// 匹配 `/api/archive/objects/<单段 id>/download`；用于 JSON Content-Type 豁免。
fn is_archive_download_path(path: &str) -> bool {
    path.strip_prefix("/api/archive/objects/")
        .and_then(|rest| rest.strip_suffix("/download"))
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
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

// ---------------------------------------------------------------------------
// M4-B3 告警管理代理
// ---------------------------------------------------------------------------

/// 告警路径 id 校验；非法时直接返回 400，不访问 hub。
fn alert_id_guard(id: &str) -> Option<Response> {
    if proxy::validate_alert_id(id) {
        None
    } else {
        Some(bad_request("id 非法"))
    }
}

/// 告警列表 / 写接口不接受任何查询参数。
fn reject_alert_query(raw: Option<&str>) -> std::result::Result<(), String> {
    parse_allowed(raw, &[])?;
    Ok(())
}

/// 读取并校验告警写请求体：JSON Content-Type、≤64 KiB、必须是 JSON 对象。
///
/// 错误响应装箱，避免 `Result` 的 Err 分支持有过大的 `Response`（clippy
/// `result_large_err`）；调用方解引用即可直接返回。
async fn read_alert_json(
    headers: &HeaderMap,
    body: Body,
) -> std::result::Result<serde_json::Value, Box<Response>> {
    if !is_json_content_type(headers) {
        return Err(Box::new(proxy::json_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "json_required",
        )));
    }
    let bytes = axum::body::to_bytes(body, MAX_ALERT_BODY)
        .await
        .map_err(|_| {
            Box::new(proxy::json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
            ))
        })?;
    let payload = serde_json::from_slice::<serde_json::Value>(&bytes)
        .map_err(|_| Box::new(bad_request("请求体必须是 JSON 对象")))?;
    if !payload.is_object() {
        return Err(Box::new(bad_request("请求体必须是 JSON 对象")));
    }
    Ok(payload)
}

/// 转发告警 GET；响应状态码（含 401）与 body 原样保留，网络错误固定 502。
async fn forward_alert_get(state: &AppState, path: &str) -> Response {
    match state.proxy.get(path, &[]).await {
        Ok(reply) => proxy::hub_reply_to_response_verbatim(reply),
        Err(error) => proxy::proxy_error_to_response(&error),
    }
}

/// 转发告警 GET，保留经过校验的查询参数。
async fn forward_alert_get_query(
    state: &AppState,
    path: &str,
    query: &[(String, String)],
) -> Response {
    match state.proxy.get(path, query).await {
        Ok(reply) => proxy::hub_reply_to_response_verbatim(reply),
        Err(error) => proxy::proxy_error_to_response(&error),
    }
}

/// 转发告警 POST；使用普通上游超时（不是控制面的 70s）。
async fn forward_alert_post(state: &AppState, path: &str, payload: &serde_json::Value) -> Response {
    match state.proxy.post_json_regular(path, payload).await {
        Ok(reply) => proxy::hub_reply_to_response_verbatim(reply),
        Err(error) => proxy::proxy_error_to_response(&error),
    }
}

async fn forward_alert_put(state: &AppState, path: &str, payload: &serde_json::Value) -> Response {
    match state.proxy.put_json(path, payload).await {
        Ok(reply) => proxy::hub_reply_to_response_verbatim(reply),
        Err(error) => proxy::proxy_error_to_response(&error),
    }
}

async fn forward_alert_delete(state: &AppState, path: &str) -> Response {
    match state.proxy.delete(path).await {
        Ok(reply) => proxy::hub_reply_to_response_verbatim(reply),
        Err(error) => proxy::proxy_error_to_response(&error),
    }
}

/// `GET /api/alerts/rules`。
async fn api_alert_rules_list(
    State(state): State<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    forward_alert_get(&state, "/api/v1/alerts/rules").await
}

/// `POST /api/alerts/rules`。
async fn api_alert_rule_create(
    State(state): State<Arc<AppState>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    let payload = match read_alert_json(&headers, body).await {
        Ok(payload) => payload,
        Err(response) => return *response,
    };
    forward_alert_post(&state, "/api/v1/alerts/rules", &payload).await
}

/// `PUT /api/alerts/rules/{id}`。
async fn api_alert_rule_update(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(response) = alert_id_guard(&id) {
        return response;
    }
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    let payload = match read_alert_json(&headers, body).await {
        Ok(payload) => payload,
        Err(response) => return *response,
    };
    forward_alert_put(&state, &format!("/api/v1/alerts/rules/{id}"), &payload).await
}

/// `DELETE /api/alerts/rules/{id}`。
async fn api_alert_rule_delete(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Some(response) = alert_id_guard(&id) {
        return response;
    }
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    forward_alert_delete(&state, &format!("/api/v1/alerts/rules/{id}")).await
}

/// `GET /api/alerts/events`；只放行数字型 `limit` / `before_id`。
async fn api_alert_events(State(state): State<Arc<AppState>>, RawQuery(raw): RawQuery) -> Response {
    let query = match parse_allowed(raw.as_deref(), &["limit", "before_id"]) {
        Ok(query) => query,
        Err(message) => return bad_request(&message),
    };
    if let Err(message) = validate_alert_event_query(&query) {
        return bad_request(&message);
    }
    forward_alert_get_query(&state, "/api/v1/alerts/events", &query).await
}

/// `GET /api/alerts/silences`。
async fn api_alert_silences_list(
    State(state): State<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    forward_alert_get(&state, "/api/v1/alerts/silences").await
}

/// `POST /api/alerts/silences`。
async fn api_alert_silence_create(
    State(state): State<Arc<AppState>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    let payload = match read_alert_json(&headers, body).await {
        Ok(payload) => payload,
        Err(response) => return *response,
    };
    forward_alert_post(&state, "/api/v1/alerts/silences", &payload).await
}

/// `DELETE /api/alerts/silences/{id}`。
async fn api_alert_silence_delete(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Some(response) = alert_id_guard(&id) {
        return response;
    }
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    forward_alert_delete(&state, &format!("/api/v1/alerts/silences/{id}")).await
}

/// `GET /api/alerts/channels`。
async fn api_alert_channels_list(
    State(state): State<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    forward_alert_get(&state, "/api/v1/alerts/channels").await
}

/// `POST /api/alerts/channels`。
async fn api_alert_channel_create(
    State(state): State<Arc<AppState>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    let payload = match read_alert_json(&headers, body).await {
        Ok(payload) => payload,
        Err(response) => return *response,
    };
    forward_alert_post(&state, "/api/v1/alerts/channels", &payload).await
}

/// `PUT /api/alerts/channels/{id}`。
async fn api_alert_channel_update(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let Some(response) = alert_id_guard(&id) {
        return response;
    }
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    let payload = match read_alert_json(&headers, body).await {
        Ok(payload) => payload,
        Err(response) => return *response,
    };
    forward_alert_put(&state, &format!("/api/v1/alerts/channels/{id}"), &payload).await
}

/// `DELETE /api/alerts/channels/{id}`。
async fn api_alert_channel_delete(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Some(response) = alert_id_guard(&id) {
        return response;
    }
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    forward_alert_delete(&state, &format!("/api/v1/alerts/channels/{id}")).await
}

/// `POST /api/alerts/channels/{id}/test`：调用 hub 发送一条固定测试消息。
///
/// 该端点没有业务请求体；仍以 `{}` 转发，保持请求是合法 JSON 且便于 hub 统一
/// 处理。上游的 502 `notify_failed` 等错误码与 body 原样交给前端。
async fn api_alert_channel_test(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Some(response) = alert_id_guard(&id) {
        return response;
    }
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    let path = format!("/api/v1/alerts/channels/{id}/test");
    forward_alert_post(&state, &path, &json!({})).await
}

/// `GET /api/archive/objects`：转发归档对象列表。
///
/// 只放行 `limit`（1..=100）与 `before_id`（正整数）；响应体由 hub 保证只含
/// 对象元数据（不含 backend 凭据）。
async fn api_archive_objects(
    State(state): State<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match parse_allowed(raw.as_deref(), &["limit", "before_id"]) {
        Ok(query) => query,
        Err(message) => return bad_request(&message),
    };
    if let Err(message) = validate_archive_objects_query(&query) {
        return bad_request(&message);
    }
    forward_alert_get_query(&state, "/api/v1/archive/objects", &query).await
}

/// `GET /api/archive/status`：转发归档开关 / 后端类型 / 水位 / 对象数。
///
/// 不接受任何查询参数；响应不含后端 URL 或凭据（hub 侧保证）。
async fn api_archive_status(
    State(state): State<Arc<AppState>>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    forward_alert_get(&state, "/api/v1/archive/status").await
}

/// `GET /api/archive/objects/{id}/download`：流式转发归档对象下载。
///
/// 路径 id 在面板先做数字校验（拒绝 `%2e%2e` / 斜杠 / `+` / 小数）；代理层
/// 注入 Bearer、保留安全响应头并限制 1 GiB，不把对象读进 8 MiB JSON 缓冲。
async fn api_archive_object_download(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    if let Err(message) = reject_alert_query(raw.as_deref()) {
        return bad_request(&message);
    }
    if !proxy::validate_archive_object_id(&id) {
        return bad_request("归档对象 id 必须是正整数");
    }
    let path = format!("/api/v1/archive/objects/{id}/download");
    match state.proxy.download(&path).await {
        Ok(response) => response,
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
        return Err("时间跨度不能超过 730 天".to_string());
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

/// 告警事件 / 归档对象分页查询校验：`limit` / `before_id` 只接受十进制数字且不得重复。
///
/// - `limit` 1–`max_limit`（缺省由 hub 使用默认值）；
/// - `before_id` 必须是正整数（1 起步的排他游标）；
/// - 数字串长度设上限，避免把超长字符串转给上游解析。
fn validate_pagination_query(
    query: &[(String, String)],
    max_limit: i64,
) -> std::result::Result<(), String> {
    let mut limit_seen = false;
    let mut before_seen = false;
    for (key, value) in query {
        match key.as_str() {
            "limit" => {
                if limit_seen {
                    return Err("limit 不能重复".to_string());
                }
                limit_seen = true;
                let limit =
                    parse_decimal_number(value).ok_or_else(|| "limit 必须是正整数".to_string())?;
                if !(1..=max_limit).contains(&limit) {
                    return Err(format!("limit 必须在 1–{max_limit} 之间"));
                }
            }
            "before_id" => {
                if before_seen {
                    return Err("before_id 不能重复".to_string());
                }
                before_seen = true;
                let before = parse_decimal_number(value)
                    .ok_or_else(|| "before_id 必须是正整数".to_string())?;
                if before <= 0 {
                    return Err("before_id 必须是正整数".to_string());
                }
            }
            _ => return Err(format!("不支持的查询参数: {key}")),
        }
    }
    Ok(())
}

/// 告警事件查询校验（limit 1–100）。
fn validate_alert_event_query(query: &[(String, String)]) -> std::result::Result<(), String> {
    validate_pagination_query(query, MAX_ALERT_EVENT_LIMIT)
}

/// 归档对象查询校验（limit 1–100）。
fn validate_archive_objects_query(query: &[(String, String)]) -> std::result::Result<(), String> {
    validate_pagination_query(query, MAX_ARCHIVE_OBJECT_LIMIT)
}

/// 只接受 1–18 位 ASCII 十进制数字；拒绝 `+`、`-`、空格、科学计数法与空串。
fn parse_decimal_number(value: &str) -> Option<i64> {
    if value.is_empty() || value.len() > 18 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
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

/// 面板 TLS 文件读取策略。
///
/// - [`Runtime`](Self::Runtime)：`panel run` 启动时读取，发现 key/cert 权限过宽会
///   收紧（key → 0600、cert → 0644），符号链接一律拒绝；
/// - [`Source`](Self::Source)：`panel install --tls-cert/--tls-key` 的源文件只读校验，
///   不修改用户文件；key 过宽直接拒绝并提示 chmod；
/// - [`ReadOnly`](Self::ReadOnly)：`--dry-run` 读取已有安装，只做内容/类型校验，
///   不做任何 chmod，保证 dry-run 零写入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsFilePolicy {
    Runtime,
    Source,
    ReadOnly,
}

/// 已校验的面板 TLS 材料。
///
/// **故意不实现 `Debug` / `Display`**：结构体内含私钥 PEM，任何调试打印都可能
/// 把私钥写进日志。日志只记录路径、SAN 与有效期等公开信息。
pub(crate) struct PanelTlsFiles {
    pub cert_pem: String,
    pub key_pem: String,
    pub dns_names: Vec<String>,
    pub ip_names: Vec<IpAddr>,
}

/// 校验面板 TLS 证书 / 私钥文件，返回已解析的 PEM。
///
/// 覆盖方案 D6 的文件层约束：普通文件、非符号链接、≤1 MiB、key 仅属主可读、
/// 证书与私钥配套、证书在有效期内、至少有一个 SAN。错误信息只包含路径、权限
/// 与公开证书信息，绝不回显私钥内容。
pub(crate) fn validate_panel_tls_files(
    cert_path: &Path,
    key_path: &Path,
    policy: TlsFilePolicy,
) -> Result<PanelTlsFiles> {
    let cert_pem = read_tls_pem(cert_path, "tls_cert", 0o644, policy)?;
    let key_pem = read_tls_pem(key_path, "tls_key", 0o600, policy)?;

    let matched = tls::cert_matches_key(&cert_pem, &key_pem)
        .context("校验证书与私钥是否配套失败（证书或私钥 PEM 无法解析）")?;
    if !matched {
        bail!("tls_cert 与 tls_key 不匹配：证书公钥与私钥不是一对");
    }

    let summary = tls::cert_summary(&cert_pem).context("解析 tls_cert 失败")?;
    let now = now_ms();
    let not_before_ms = summary.not_before.saturating_mul(1_000);
    let not_after_ms = summary.not_after.saturating_mul(1_000);
    if now >= not_after_ms {
        bail!(
            "tls_cert 已过期（notAfter={}，当前时间已超过有效期）",
            tls::format_unix_utc(summary.not_after)
        );
    }
    // 允许 60s 时钟偏差，与 hub 的现存证书校验保持一致。
    if now.saturating_add(60_000) < not_before_ms {
        bail!(
            "tls_cert 尚未生效（notBefore={}）",
            tls::format_unix_utc(summary.not_before)
        );
    }

    let (dns_names, ip_names) = cert_identities(&cert_pem)?;
    Ok(PanelTlsFiles {
        cert_pem,
        key_pem,
        dns_names,
        ip_names,
    })
}

/// 校验证书 SAN 覆盖监听 IP（非通配绑定）与 `public_origin` 主机名。
pub(crate) fn validate_panel_tls_names(
    files: &PanelTlsFiles,
    listen: &str,
    public_origin: &str,
) -> Result<()> {
    let certs = tls::load_certs(&files.cert_pem).context("解析 tls_cert 失败")?;
    let parsed = rustls::server::ParsedCertificate::try_from(&certs[0])
        .map_err(|err| anyhow!("tls_cert 不是可用的服务端证书: {err}"))?;

    // 监听地址是具体 IP 时必须覆盖它；0.0.0.0 / :: 是通配绑定，不能作为访问名。
    if let Some(host) = listen_host(listen) {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !ip.is_unspecified() {
                let name = ServerName::from(ip);
                rustls::client::verify_server_name(&parsed, &name)
                    .map_err(|_| anyhow!("tls_cert 的 SAN 未覆盖监听地址 IP {ip}"))?;
            }
        }
    }

    let origin = public_origin.trim();
    if !origin.is_empty() {
        let host = origin_host(origin)
            .ok_or_else(|| anyhow!("public_origin 无法解析出主机名: {origin:?}"))?;
        let name = ServerName::try_from(host)
            .map_err(|_| anyhow!("public_origin 主机名非法: {host:?}"))?;
        rustls::client::verify_server_name(&parsed, &name).map_err(|_| {
            anyhow!(
                "tls_cert 的 SAN 未覆盖 public_origin 主机 {host:?}\
                 （证书 DNS SAN: {:?}，IP SAN: {:?}）",
                files.dns_names,
                files.ip_names
            )
        })?;
    }
    Ok(())
}

/// 按证书 SAN 推导默认的 `public_origin`（直连 TLS 未显式指定时使用）。
pub(crate) fn derived_https_origin(files: &PanelTlsFiles) -> Result<String> {
    if let Some(dns) = files.dns_names.iter().find(|name| !name.contains('*')) {
        return Ok(format!("https://{dns}"));
    }
    if let Some(ip) = files.ip_names.first() {
        return Ok(match ip {
            IpAddr::V6(_) => format!("https://[{ip}]"),
            IpAddr::V4(_) => format!("https://{ip}"),
        });
    }
    bail!(
        "tls_cert 没有可用于推导 public_origin 的非通配 SAN；请显式传 --public-origin https://<host>"
    )
}

/// 安装器 HTTPS 健康检查使用的 SNI：优先 `public_origin` 主机名，其次证书 SAN。
pub(crate) fn preferred_tls_server_name(
    files: &PanelTlsFiles,
    public_origin: &str,
) -> Result<String> {
    if let Some(host) = origin_host(public_origin.trim()) {
        return Ok(host.to_string());
    }
    if let Some(dns) = files.dns_names.iter().find(|name| !name.contains('*')) {
        return Ok(dns.clone());
    }
    if let Some(ip) = files.ip_names.first() {
        return Ok(ip.to_string());
    }
    bail!("无法确定 HTTPS 健康检查的 SNI：public_origin 为空且证书没有可用 SAN")
}

/// 从 `scheme://host[:port]` 里取 host；只用于已经过 `PanelConfig::validate`
/// 的 `public_origin` 与安装器自己生成的值。
pub(crate) fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next()?;
    listen_host(authority)
}

/// 读取并校验一个 TLS PEM 文件（普通文件、非符号链接、≤1 MiB、权限合规）。
fn read_tls_pem(
    path: &Path,
    label: &str,
    target_mode: u32,
    policy: TlsFilePolicy,
) -> Result<String> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("读取 {label} {} 失败", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!(
            "{label} {} 是符号链接，拒绝使用；请改为指向真实文件的路径",
            path.display()
        );
    }
    if !meta.is_file() {
        bail!("{label} {} 不是普通文件", path.display());
    }
    if meta.len() > MAX_TLS_FILE_BYTES {
        bail!(
            "{label} 超过 1 MiB 上限（{} 字节）: {}",
            meta.len(),
            path.display()
        );
    }

    #[cfg(unix)]
    check_tls_file_mode(path, label, target_mode, policy)?;
    #[cfg(not(unix))]
    {
        let _ = (target_mode, policy);
    }

    let bytes =
        std::fs::read(path).with_context(|| format!("读取 {label} {} 失败", path.display()))?;
    String::from_utf8(bytes)
        .with_context(|| format!("{label} {} 不是 UTF-8 编码的 PEM 文本", path.display()))
}

/// 检查 / 收紧 TLS 文件权限；符号链接已在调用前拒绝。
#[cfg(unix)]
fn check_tls_file_mode(
    path: &Path,
    label: &str,
    target_mode: u32,
    policy: TlsFilePolicy,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if policy == TlsFilePolicy::ReadOnly {
        return Ok(());
    }
    if policy == TlsFilePolicy::Runtime {
        fsutil::harden(path, target_mode)
            .with_context(|| format!("收紧 {label} {} 权限失败", path.display()))?;
    }
    let mode = std::fs::symlink_metadata(path)
        .with_context(|| format!("读取 {label} {} 权限失败", path.display()))?
        .permissions()
        .mode()
        & 0o777;

    if target_mode == 0o600 {
        // 私钥：只允许属主读（0600；也接受 0400 这类更严格的只读权限）。
        if mode & 0o077 != 0 || mode & 0o400 == 0 {
            bail!(
                "{label} {} 权限必须是 0600（当前 {mode:04o}）；请执行 chmod 600 后重试",
                path.display()
            );
        }
    } else {
        // 证书是公开信息，但不能允许组/其他用户写入（防篡改）。
        if mode & 0o022 != 0 || mode & 0o400 == 0 {
            bail!(
                "{label} {} 权限过宽（当前 {mode:04o}）；证书不能允许组或其他用户写入，请执行 chmod 644",
                path.display()
            );
        }
    }
    Ok(())
}

/// 提取证书里的 DNS / IP SAN，并强制至少存在一个 SAN。
fn cert_identities(cert_pem: &str) -> Result<(Vec<String>, Vec<IpAddr>)> {
    let certs = tls::load_certs(cert_pem).context("解析 tls_cert 失败")?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|err| anyhow!("解析 tls_cert 失败: {err:?}"))?;

    let mut dns_names = Vec::new();
    let mut ip_names = Vec::new();
    for extension in cert.extensions() {
        let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            extension.parsed_extension()
        else {
            continue;
        };
        for name in &san.general_names {
            match name {
                x509_parser::extensions::GeneralName::DNSName(name) => {
                    dns_names.push((*name).to_string());
                }
                x509_parser::extensions::GeneralName::IPAddress(raw) => {
                    if let Some(ip) = ip_from_san(raw) {
                        ip_names.push(ip);
                    }
                }
                _ => {}
            }
        }
    }
    if dns_names.is_empty() && ip_names.is_empty() {
        bail!("tls_cert 没有任何 SAN（必须至少包含一个 DNS 或 IP SAN）");
    }
    Ok((dns_names, ip_names))
}

/// 把 X.509 SAN 里的 4/16 字节原始地址转换为 `IpAddr`。
fn ip_from_san(raw: &[u8]) -> Option<IpAddr> {
    match raw.len() {
        4 => Some(IpAddr::V4(std::net::Ipv4Addr::new(
            raw[0], raw[1], raw[2], raw[3],
        ))),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// 面板直连 TLS 的服务端配置；HTTP 模式返回 `None`。
struct PanelTlsRuntime {
    config: Arc<rustls::ServerConfig>,
}

/// 按 `PanelConfig` 的 `tls_cert` / `tls_key` 加载运行时 TLS。
///
/// 缺字段 → `Ok(None)`，HTTP 行为完全不变；只设一个、文件校验/配套/有效期/SAN
/// 任一失败 → 返回错误，启动失败。
fn load_panel_tls(cfg: &PanelConfig) -> Result<Option<PanelTlsRuntime>> {
    let cert = cfg.tls_cert.trim();
    let key = cfg.tls_key.trim();
    if cert.is_empty() && key.is_empty() {
        return Ok(None);
    }
    if cert.is_empty() || key.is_empty() {
        bail!("tls_cert 与 tls_key 必须成对配置：都为空使用 HTTP，都非空才启用面板 HTTPS");
    }

    let cert_path = Path::new(cert);
    let key_path = Path::new(key);
    if !cert_path.is_absolute() || !key_path.is_absolute() {
        bail!("tls_cert 与 tls_key 必须是绝对路径（当前 {cert:?} / {key:?}）");
    }

    let files = validate_panel_tls_files(cert_path, key_path, TlsFilePolicy::Runtime)
        .context("面板 TLS 证书/私钥校验失败")?;
    validate_panel_tls_names(&files, &cfg.listen, &cfg.public_origin)
        .context("面板 TLS 证书 SAN 校验失败")?;
    let config = tls::server_config_from_paths(&files.cert_pem, &files.key_pem)
        .context("构建面板 HTTPS 服务端配置失败（TLS 1.3 + ALPN http/1.1）")?;
    // files 在这里释放：私钥只保留在 rustls ServerConfig 内部。
    Ok(Some(PanelTlsRuntime { config }))
}

/// 面板 HTTP 的 accept 循环（KI-17）。
///
/// 不用 `axum::serve`：它没有 header 读超时，也拿不到连接数。这里手工 accept，
/// 做「全局 + 每来源 IP」并发限制、HTTP/1 header 超时与请求体总超时；半截
/// header 的慢连接最多占用 [`HEADER_READ_TIMEOUT`]，慢 body 最多占用
/// [`BODY_READ_TIMEOUT`]，洪水下 `/healthz` 仍可用。
async fn serve_panel_listener(app: Router, listener: TcpListener) -> Result<()> {
    serve_panel_connections(app, listener, None).await
}

/// 面板直连 HTTPS 的 accept 循环；TLS 握手也受连接槽位与超时约束。
async fn serve_panel_tls_listener(
    app: Router,
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
) -> Result<()> {
    serve_panel_connections(app, listener, Some(acceptor)).await
}

/// HTTP / HTTPS 共用的 accept 循环：限流、超时与 `ConnectInfo` 注入完全一致。
async fn serve_panel_connections(
    app: Router,
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
) -> Result<()> {
    let local = listener.local_addr().context("读取面板监听地址失败")?;
    // 与 Argon2 的 `state.argon2_slots` 完全独立，不能混用许可。
    let permits = Arc::new(Semaphore::new(ADMIN_MAX_CONNECTIONS.max(1)));
    let limits = Arc::new(ConnectionLimiter::new(ADMIN_MAX_CONNECTIONS_PER_IP));
    tracing::info!(
        listen = %local,
        tls = tls.is_some(),
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
        let acceptor = tls.clone();
        tokio::spawn(async move {
            // 许可跟随连接生命周期；连接关闭（含超时）后自动归还。
            let _permit = permit;
            let _connection = connection;

            match acceptor {
                Some(acceptor) => {
                    // 慢 TLS 握手同样不能无限占用连接槽位：先做握手超时，再进入
                    // 与 HTTP 完全相同的 header/body 超时处理。
                    match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                        Ok(Ok(stream)) => serve_panel_http(app, peer, stream).await,
                        Ok(Err(err)) => {
                            // 只记录来源与错误，不记录证书内容。
                            tracing::debug!(%peer, error = %err, "面板 TLS 握手失败");
                        }
                        Err(_) => {
                            tracing::warn!(%peer, "面板 TLS 握手超时，关闭连接");
                        }
                    }
                }
                None => serve_panel_http(app, peer, tcp).await,
            }
        });
    }
}

/// 在一条（已建立的 HTTP 或 TLS）连接上跑 hyper HTTP/1 服务。
async fn serve_panel_http<S>(app: Router, peer: SocketAddr, stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
        .with_upgrades()
        .await
    {
        // 只记录来源与错误，不记录请求头。
        tracing::debug!(%peer, error = %err, "面板连接结束");
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

    // C7：直连 TLS 在启动前完成文件、配套、有效期与 SAN 校验，任何失败都拒绝启动。
    let tls = load_panel_tls(&cfg).context("面板 TLS 配置无效")?;
    if tls.is_some() {
        let origin = cfg.public_origin.trim();
        if origin.is_empty() {
            tracing::warn!(
                "面板已启用 HTTPS，但 public_origin 为空；Origin 校验将退回 Host 同源比较，\
                 建议显式设置 https://<host>"
            );
        } else if !origin.starts_with("https://") {
            bail!("直连 TLS 时 public_origin 必须是 https://（当前 {origin:?}）");
        }
        // 直连 HTTPS 时 Auto 依赖可信反代 + X-Forwarded-Proto，永远不会给浏览器
        // 加 Secure；这里强制 always，避免会话 Cookie 在 HTTPS 下可被明文回放。
        if cfg.cookie_secure != CookieSecure::Always {
            tracing::warn!(
                from = ?cfg.cookie_secure,
                "面板直连 HTTPS，强制 cookie_secure=always（忽略配置里的其它策略）"
            );
            cfg.cookie_secure = CookieSecure::Always;
        }
    }
    let tls_acceptor = tls.map(|tls| tokio_rustls::TlsAcceptor::from(tls.config));

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
        match tls_acceptor {
            Some(acceptor) => {
                // 只记录 scheme；不打印证书/私钥路径，更不打印 key 内容。
                tracing::info!(
                    listen = %listen,
                    hub = %hub,
                    scheme = "https",
                    "面板已启动（HTTPS，TLS 1.3 + ALPN http/1.1）"
                );
                serve_panel_tls_listener(app, listener, acceptor).await
            }
            None => {
                if !loopback {
                    tracing::warn!(
                        listen = %listen,
                        "面板是明文 HTTP，请使用 VPN/反代；当前监听地址不是回环地址，\
                         不要直接暴露到公网或不可信网络"
                    );
                }
                tracing::info!(listen = %listen, hub = %hub, scheme = "http", "面板已启动");
                // KI-17：手工 accept，带 header 读超时与全局 / 每 IP 连接上限。
                serve_panel_listener(app, listener).await
            }
        }
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
    hub_ca: Option<PathBuf>,
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

    // hub 地址 / token / CA 缺省时尝试复用 hub 的配置，避免用户在两份文件间抄 token。
    // 只要 hub 地址不是显式给出，就必须读取 admin_tls / tls.mode 才能选对 scheme；
    // 显式 https 且未给 --hub-ca 时也读一次，用于从本机 Hub 配置推导自签 CA。
    let explicit_https = hub
        .as_deref()
        .is_some_and(|raw| raw.trim().starts_with("https://"));
    let hub_cfg = if hub.is_none() || hub_token.is_none() || (hub_ca.is_none() && explicit_https) {
        load_hub_config_hint()
    } else {
        None
    };

    // #39：没有 --hub 时以 hub.toml 的 admin_tls 决定 http/https；admin_tls=required
    // 且证书来源是 self-signed 时，CA 取 <hub data_dir>/certs/ca.crt，由
    // prepare_hub_ca 复制到面板配置目录（ACME 则使用系统根）。
    let hub_plan = match (&hub_cfg, hub.as_deref()) {
        (Some(hub_cfg), explicit) => plan_hub_connection(hub_cfg, explicit, hub_ca.as_deref())?,
        (None, Some(explicit)) => HubInitPlan {
            hub_url: normalize_hub_url(explicit)?,
            ca_source: None,
        },
        (None, None) => HubInitPlan {
            hub_url: format!("http://127.0.0.1:{DEFAULT_ADMIN_PORT}"),
            ca_source: None,
        },
    };
    cfg.hub_url = hub_plan.hub_url.clone();
    if hub_overridden {
        println!(
            "hub API: {}（来自 --hub；scheme 以显式参数为准）",
            cfg.hub_url
        );
    } else if let Some(hub_cfg) = &hub_cfg {
        println!(
            "已从 {DEFAULT_HUB_CONFIG} 读取 hub 管理地址（admin_tls={}, tls.mode={}）",
            match hub_cfg.admin_tls {
                AdminTlsMode::Off => "off",
                AdminTlsMode::Required => "required",
            },
            server_tls_mode_name(hub_cfg.tls.mode)
        );
    } else {
        eprintln!(
            "提示: 未找到可读的 {DEFAULT_HUB_CONFIG}，hub 地址使用默认 {}；请用 --hub 指定实际地址",
            cfg.hub_url
        );
    }
    if cfg.hub_url.starts_with("https://") && hub_plan.ca_source.is_none() && hub_ca.is_none() {
        eprintln!(
            "提示: hub_url 使用 https，面板将使用系统根证书；若 Hub 使用自签/私有 CA，\
             请用 --hub-ca 指定 CA（PEM）"
        );
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

    // 只读取/校验 CA，不落盘：等密码哈希与配置写入全部成功后再写 CA，
    // 避免 --force 先覆盖旧 CA、后续失败留下坏配置。
    let prepared_ca = prepare_hub_ca(&hub_plan, hub_ca.as_deref(), &path)?;
    if let Some(ca) = &prepared_ca {
        cfg.hub_ca = ca.config_path()?;
    }

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

    // 事务：CA 先落盘，配置后落盘；配置失败回滚 CA。密码打印在事务成功之后。
    write_init_artifacts(prepared_ca.as_ref(), || Ok(cfg.save(&path)?))?;

    if let Some(_ca) = &prepared_ca {
        println!("hub CA: {}", cfg.hub_ca);
    }

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
    // C7：配置了 tls_cert/tls_key 时，ports 也应显示 https 而不是 http。
    let scheme = if !cfg.tls_cert.trim().is_empty() && !cfg.tls_key.trim().is_empty() {
        "https"
    } else {
        "http"
    };
    println!("配置文件: {}", path.display());
    println!("面板端口: {port}");
    println!("  监听: {}", cfg.listen);
    println!(
        "  传输: {}",
        if scheme == "https" {
            "HTTPS（TLS 1.3 + ALPN http/1.1）"
        } else {
            "HTTP"
        }
    );
    if loopback {
        match listen_host(&cfg.listen) {
            Some(host) if host.parse::<std::net::Ipv6Addr>().is_ok() => {
                println!("  浏览器: {scheme}://[{host}]:{port}");
            }
            Some(host) => println!("  浏览器: {scheme}://{host}:{port}"),
            None => println!("  浏览器: {scheme}://127.0.0.1:{port}"),
        }
        println!("  提示: 面板只监听回环地址，请通过本机浏览器或 SSH 端口转发访问");
    } else {
        println!("  浏览器: {scheme}://<本机IP>:{port}（监听非回环地址）");
        if scheme == "http" {
            println!(
                "  警告: 面板是明文 HTTP，请使用 VPN/反代（HTTPS）对外提供，\
                 不要直接暴露到公网或不可信网络"
            );
        }
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

/// `panel init` 推导出的 hub 连接计划。
#[derive(Debug, Clone, PartialEq, Eq)]
struct HubInitPlan {
    hub_url: String,
    /// 需要复制进面板配置目录的私有 CA 源文件；`None` 表示使用系统根证书。
    ca_source: Option<PathBuf>,
}

/// 已读取并校验、待写入的 hub CA（含旧文件备份）。
///
/// #39 的失败语义：CA 必须先于配置文件落盘；CA 写失败时配置完全不动，配置
/// 写失败时恢复旧 CA / 删除新 CA。这样 `--force` 不会先覆盖旧 CA 再失败，
/// 也不会出现“配置已换、CA 还是旧的”这种半更新状态。
struct PreparedHubCa {
    dest: PathBuf,
    bytes: Vec<u8>,
    /// 旧 CA 内容；`None` 表示目标原本不存在。回滚时写回或删除。
    previous: Option<Vec<u8>>,
    /// 测试注入：模拟 CA 写失败（生产构建中不存在）。
    #[cfg(test)]
    fail_write: bool,
}

impl PreparedHubCa {
    /// 写入新 CA；任何失败都立即回滚旧 CA。
    fn install(&self) -> Result<()> {
        #[cfg(test)]
        if self.fail_write {
            self.rollback();
            bail!("注入的 hub CA 写入失败");
        }
        if let Some(parent) = self.dest.parent() {
            fsutil::ensure_dir(parent, 0o700)
                .with_context(|| format!("创建 hub CA 目录失败: {}", parent.display()))?;
        }
        if let Err(error) = fsutil::atomic_write(&self.dest, &self.bytes, 0o644) {
            // 理论上 atomic_write 失败不会改旧文件；仍显式回滚，保证“旧 CA
            // 字节不变 / 无新 CA 残留”。
            self.rollback();
            return Err(error)
                .with_context(|| format!("写入 hub CA 失败: {}", self.dest.display()));
        }
        Ok(())
    }

    /// 恢复旧 CA；原本不存在则删除新 CA。失败也不覆盖原始错误。
    fn rollback(&self) {
        match &self.previous {
            Some(bytes) => {
                let _ = fsutil::atomic_write(&self.dest, bytes, 0o644);
            }
            None => {
                let _ = std::fs::remove_file(&self.dest);
            }
        }
    }

    fn config_path(&self) -> Result<String> {
        self.dest
            .to_str()
            .map(str::to_string)
            .ok_or_else(|| anyhow!("hub CA 路径不是有效 UTF-8: {}", self.dest.display()))
    }
}

/// 事务顺序：先写 CA，再保存配置；配置保存失败时恢复旧 CA / 删除新 CA。
///
/// 密码只在本函数成功返回后打印，因此失败路径不会输出密码。
fn write_init_artifacts(
    ca: Option<&PreparedHubCa>,
    save_config: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if let Some(ca) = ca {
        ca.install()?;
    }
    if let Err(error) = save_config() {
        if let Some(ca) = ca {
            ca.rollback();
        }
        return Err(error).context("写入面板配置失败");
    }
    Ok(())
}

/// `admin_tls=off` 时的回环 authority：`0.0.0.0` / `[::]` 转成回环地址。
fn admin_listen_authority(admin_listen: &str) -> String {
    let listen = admin_listen.trim();
    if listen.is_empty() {
        return format!("127.0.0.1:{DEFAULT_ADMIN_PORT}");
    }
    let forwarded = hub_url_from_admin_listen(listen);
    forwarded
        .strip_prefix("http://")
        .or_else(|| forwarded.strip_prefix("https://"))
        .unwrap_or(&forwarded)
        .to_string()
}

/// 从 `admin_listen` 取端口；IP:port 用 `SocketAddr`，其余（hostname:port）按
/// 最后一个冒号解析，失败时回退默认管理端口。
fn admin_listen_port(admin_listen: &str) -> u16 {
    let listen = admin_listen.trim();
    let listen = listen
        .strip_prefix("http://")
        .or_else(|| listen.strip_prefix("https://"))
        .unwrap_or(listen);
    if let Ok(address) = listen.parse::<SocketAddr>() {
        return address.port();
    }
    listen
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .filter(|port| *port != 0)
        .unwrap_or(DEFAULT_ADMIN_PORT)
}

/// 证书 SAN 名称是否回环 / 通配：这些名字不能作为自动推导的 https 主机。
fn is_loopback_or_unspecified_name(name: &str) -> bool {
    let name = name.trim().trim_matches(['[', ']']);
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        return ip.is_loopback() || ip.is_unspecified();
    }
    let lower = name.to_ascii_lowercase();
    lower == "localhost" || lower.ends_with(".localhost")
}

/// 把配置里的 SAN 名称转成可放进 URL 的 host（IPv6 加方括号）。
fn san_url_host(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() {
        return None;
    }
    let san = tls::parse_server_sans(&[name.to_string()])
        .ok()?
        .into_iter()
        .next()?;
    match san {
        tls::ServerSan::Ip(ip) => Some(if ip.is_ipv6() {
            format!("[{ip}]")
        } else {
            ip.to_string()
        }),
        tls::ServerSan::Dns(dns) => Some(dns),
    }
}

/// 从证书名字（self-signed 的 `server_names` / ACME 的 `tls.domains`）里挑
/// 第一个非回环、非通配的 DNS/IP。
///
/// 不能回落到 `127.0.0.1`：ACME 证书只覆盖 `tls.domains`，self-signed 也可能
/// 只含 DNS SAN；生成 `https://127.0.0.1` 会“初始化成功但握手失败”。
fn non_loopback_san_host(names: &[String]) -> Option<String> {
    names.iter().find_map(|name| {
        if is_loopback_or_unspecified_name(name) {
            return None;
        }
        san_url_host(name)
    })
}

fn server_tls_mode_name(mode: ServerTlsMode) -> &'static str {
    match mode {
        ServerTlsMode::SelfSigned => "self-signed",
        ServerTlsMode::AcmeDomain => "acme-domain",
        ServerTlsMode::AcmeIp => "acme-ip",
    }
}

/// 由 hub.toml 的 `admin_listen` + `admin_tls` 推导出面板要连的地址。
///
/// `admin_tls=off` 只允许回环明文；`admin_tls=required` 时必须从证书名字里
/// 选一个非回环 DNS/IP，避免 ACME 证书或仅含 DNS SAN 的自签证书连不上。
fn hub_admin_url(hub: &HubConfig) -> Result<String> {
    match hub.admin_tls {
        AdminTlsMode::Off => Ok(format!(
            "http://{}",
            admin_listen_authority(&hub.admin_listen)
        )),
        AdminTlsMode::Required => {
            let names = hub.effective_server_names();
            let host = non_loopback_san_host(&names).ok_or_else(|| {
                anyhow!(
                    "本机 Hub 配置 admin_tls=\"required\"（tls.mode={}），但证书名字（{}）中\
                     没有可用的非回环 DNS/IP；回环地址无法被 ACME / 仅 DNS SAN 的证书覆盖，\
                     不能自动生成 Panel 可连接的 https URL。请用 --hub 指定 Panel 实际访问\
                     Hub 的地址，自签/私有 CA 同时用 --hub-ca 指定 CA；未写入面板配置",
                    server_tls_mode_name(hub.tls.mode),
                    if hub.tls.mode == ServerTlsMode::SelfSigned {
                        "server_names"
                    } else {
                        "tls.domains"
                    }
                )
            })?;
            Ok(format!(
                "https://{host}:{}",
                admin_listen_port(&hub.admin_listen)
            ))
        }
    }
}

/// 显式 `--hub` 的 host（IPv6 去掉方括号、统一小写）。
fn explicit_hub_host(hub_url: &str) -> Option<String> {
    let url = reqwest::Url::parse(hub_url).ok()?;
    url.host_str().map(|host| {
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase()
    })
}

/// 主机名是否回环（含 localhost / *.localhost）。
fn is_loopback_host_name(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']);
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or_else(|_| {
            let lower = host.to_ascii_lowercase();
            lower == "localhost" || lower.ends_with(".localhost")
        })
}

/// 本机管理口是否允许通过回环地址访问（回环绑定或通配绑定）。
fn local_admin_allows_loopback(hub: &HubConfig) -> bool {
    match listen_host(hub.admin_listen.trim()) {
        Some(host) => {
            let host = host.trim_matches(['[', ']']);
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback() || ip.is_unspecified())
        }
        // 无法判断时按本机回环兼容处理；真正的 CA 仍需能读到才会复制。
        None => true,
    }
}

/// 显式 `--hub` 的 host 是否指向本机 Hub。
///
/// 只用于判断能否复用本机 Hub 的自签 CA：host 与本机 `admin_listen` 或证书
/// 名字一致，或者本机绑回环/通配时显式使用 loopback 别名。远端 host 不允许
/// 自动复制本机 CA。
fn explicit_hub_matches_local(hub_url: &str, hub: &HubConfig) -> bool {
    let Some(host) = explicit_hub_host(hub_url) else {
        return false;
    };
    let mut local_hosts: Vec<String> = hub
        .effective_server_names()
        .into_iter()
        .map(|name| name.trim().to_ascii_lowercase())
        .collect();
    if let Some(listen_host) = listen_host(hub.admin_listen.trim()) {
        local_hosts.push(
            listen_host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_ascii_lowercase(),
        );
    }
    if local_hosts.contains(&host) {
        return true;
    }
    is_loopback_host_name(&host) && local_admin_allows_loopback(hub)
}

/// 规划 `panel init` 的 hub_url 与 CA 来源。
///
/// - `--hub` 显式给出时 scheme 以参数为准，不被本机 hub 配置覆盖；
/// - 本机 `admin_tls=required` 且 `tls.mode=self-signed` 时，只有显式 host
///   指向本机 Hub 才自动复制 `<hub data_dir>/certs/ca.crt`；指向远端且未给
///   `--hub-ca` 时直接失败，避免把本机 CA 用于远端 Hub（反之亦然）；
/// - ACME（`acme-domain` / `acme-ip`）使用系统根，`hub_ca` 留空。
fn plan_hub_connection(
    hub: &HubConfig,
    explicit_hub: Option<&str>,
    explicit_ca: Option<&Path>,
) -> Result<HubInitPlan> {
    let hub_url = match explicit_hub {
        Some(raw) => normalize_hub_url(raw)?,
        None => hub_admin_url(hub)?,
    };
    let local_self_signed =
        hub.admin_tls == AdminTlsMode::Required && hub.tls.mode == ServerTlsMode::SelfSigned;
    let ca_source = if hub_url.starts_with("https://") && local_self_signed {
        if explicit_hub.is_some() && !explicit_hub_matches_local(&hub_url, hub) {
            if explicit_ca.is_some() {
                None
            } else {
                bail!(
                    "显式 --hub 指向 {}，与本机 Hub 管理地址（{}）不一致；本机 Hub 使用\
                     自签证书，无法确定远端 Hub 的 CA；请用 --hub-ca 指定远端 Hub 的 CA\
                     证书；未写入面板配置",
                    hub_url,
                    hub.admin_listen
                );
            }
        } else {
            Some(tls::cert_dir(&hub.data_dir).join(tls::CA_CERT_FILE))
        }
    } else {
        None
    };
    Ok(HubInitPlan { hub_url, ca_source })
}

/// 读取并校验待复制的 hub CA，但不落盘；返回 `None` 表示使用系统根。
///
/// 显式 `--hub-ca` 优先；否则只在 [`HubInitPlan::ca_source`]（本机 Hub 自签）
/// 存在时自动复制。复制前校验 PEM 仅含 CERTIFICATE 区块，避免把私钥误当
/// 公开 CA 复制；CA 文件缺失 / 非法时明确失败并提示 `--hub-ca`。
fn prepare_hub_ca(
    plan: &HubInitPlan,
    explicit_ca: Option<&Path>,
    config_path: &Path,
) -> Result<Option<PreparedHubCa>> {
    let ca_source = explicit_ca.or(plan.ca_source.as_deref());
    let Some(ca_source) = ca_source else {
        return Ok(None);
    };
    if !plan.hub_url.starts_with("https://") {
        bail!(
            "--hub-ca 只能与 https:// 的 hub 地址一起使用（当前 {}）；\
             明文 http 配置 CA 不会加密，请先把 hub_url 改成 https://",
            plan.hub_url
        );
    }
    let bytes = read_hub_ca_pem(ca_source).map_err(|error| {
        if explicit_ca.is_some() {
            error
        } else {
            anyhow!(
                "本机 Hub 配置为 admin_tls=\"required\" + tls.mode=\"self-signed\"，\
                 但无法读取 hub CA：{error:#}；请用 --hub-ca 指定 Hub 的 CA 证书\
                 （通常为 {}），或修正 Hub 配置；未写入面板配置",
                ca_source.display()
            )
        }
    })?;
    let dest = hub_ca_destination(config_path)?;
    let previous = match std::fs::symlink_metadata(&dest) {
        Ok(meta) if meta.file_type().is_symlink() => {
            bail!(
                "hub CA 目标 {} 是符号链接，拒绝覆盖；请先人工处理",
                dest.display()
            );
        }
        Ok(meta) if !meta.is_file() => {
            bail!("hub CA 目标 {} 不是普通文件，拒绝覆盖", dest.display());
        }
        Ok(meta) => {
            if meta.len() > MAX_TLS_FILE_BYTES {
                bail!(
                    "旧 hub CA 超过 1 MiB 上限（{} 字节）: {}",
                    meta.len(),
                    dest.display()
                );
            }
            Some(
                std::fs::read(&dest)
                    .with_context(|| format!("备份旧 hub CA 失败: {}", dest.display()))?,
            )
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("检查 hub CA 目标失败: {}", dest.display()))
        }
    };
    Ok(Some(PreparedHubCa {
        dest,
        bytes,
        previous,
        #[cfg(test)]
        fail_write: false,
    }))
}

/// 读取并校验 hub 私有 CA（PEM，至少一张证书）。
fn read_hub_ca_pem(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("读取 hub CA {} 失败", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("hub CA {} 是符号链接，拒绝使用", path.display());
    }
    if !meta.is_file() {
        bail!("hub CA {} 不是普通文件", path.display());
    }
    if meta.len() > MAX_TLS_FILE_BYTES {
        bail!(
            "hub CA 超过 1 MiB 上限（{} 字节）: {}",
            meta.len(),
            path.display()
        );
    }
    let bytes =
        std::fs::read(path).with_context(|| format!("读取 hub CA {} 失败", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("hub CA {} 不是 UTF-8 PEM 文本", path.display()))?;
    tls::ensure_certificate_only_pem(text).with_context(|| {
        format!(
            "hub CA {} 只允许 CERTIFICATE 区块（发现私钥/公钥/CSR 等非证书内容）",
            path.display()
        )
    })?;
    tls::load_certs(text)
        .with_context(|| format!("hub CA {} 不是有效的 PEM 证书", path.display()))?;
    Ok(bytes)
}

/// 面板 `hub_ca` 的落盘位置：与配置文件同目录的 `hub-ca.pem`。
///
/// 配置路径可能是相对的；转成绝对路径后再写入 `hub_ca`，避免面板以不同
/// 工作目录启动时找不到 CA。
fn hub_ca_destination(config_path: &Path) -> Result<PathBuf> {
    let dir = match config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        Some(parent) if parent.is_absolute() => parent.to_path_buf(),
        Some(parent) => std::env::current_dir()
            .context("获取当前目录失败")?
            .join(parent),
        None => std::env::current_dir().context("获取当前目录失败")?,
    };
    Ok(dir.join("hub-ca.pem"))
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

    /// 只服务一次请求的假 hub：可自定义响应头与二进制 body（下载测试用）。
    ///
    /// `headers` 由调用方给出（含 Content-Length），方便模拟超限 / 缺长度等
    /// 异常响应，面板必须在不读取 body 的情况下先做上限判断。
    fn spawn_raw_mock_hub(
        status: u16,
        headers: &str,
        body: Vec<u8>,
    ) -> (String, Arc<Mutex<Vec<u8>>>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        let headers = headers.to_string();
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
            let head = format!("HTTP/1.1 {status} {reason}\r\n{headers}Connection: close\r\n\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
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

    fn json_body(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).expect("响应必须是 JSON")
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

    #[tokio::test]
    async fn alert_proxy_requires_session_for_every_endpoint() {
        let (state, _site) = test_state();
        let cases: [(Method, &str); 11] = [
            (Method::GET, "/api/alerts/rules"),
            (Method::POST, "/api/alerts/rules"),
            (Method::PUT, "/api/alerts/rules/abc"),
            (Method::DELETE, "/api/alerts/rules/abc"),
            (Method::GET, "/api/alerts/events?limit=50"),
            (Method::GET, "/api/alerts/silences"),
            (Method::POST, "/api/alerts/silences"),
            (Method::DELETE, "/api/alerts/silences/1"),
            (Method::GET, "/api/alerts/channels"),
            (Method::POST, "/api/alerts/channels"),
            (Method::DELETE, "/api/alerts/channels/abc"),
        ];
        for (method, uri) in cases {
            let (status, _, body) = call(
                &state,
                method.clone(),
                uri,
                &[("content-type", "application/json")],
                Body::from("{}"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri}");
            assert!(
                String::from_utf8_lossy(&body).contains("unauthorized"),
                "{method} {uri}"
            );
        }
        // 渠道测试端点同样是受保护路由。
        let (status, _, _) = call(
            &state,
            Method::POST,
            "/api/alerts/channels/abc/test",
            &[("content-type", "application/json")],
            Body::from("{}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn alert_proxy_rejects_path_traversal_and_bad_ids() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        let cases: [(Method, &str); 8] = [
            (Method::PUT, "/api/alerts/rules/%2e%2e"),
            (Method::DELETE, "/api/alerts/rules/%2e%2e%2fadmin"),
            (Method::DELETE, "/api/alerts/rules/..%2F..%2Fadmin"),
            (Method::DELETE, "/api/alerts/rules/a_b"),
            (Method::DELETE, "/api/alerts/channels/hub%2fself"),
            (Method::PUT, "/api/alerts/channels/hub%20self"),
            (Method::POST, "/api/alerts/channels/%2e%2e/test"),
            (Method::DELETE, "/api/alerts/silences/1.5"),
        ];
        for (method, uri) in cases {
            let (status, _, body) = call(
                &state,
                method.clone(),
                uri,
                &[("cookie", &cookie), ("content-type", "application/json")],
                Body::from("{}"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{method} {uri}");
            assert!(
                String::from_utf8_lossy(&body).contains("bad_request"),
                "{method} {uri}"
            );
        }
    }

    #[tokio::test]
    async fn alert_events_reject_unknown_or_non_numeric_query() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        for query in [
            "foo=1",
            "limit=abc",
            "limit=0",
            "limit=101",
            "limit=1&limit=2",
            "limit=%2B1",
            "limit=%20",
            "before_id=-1",
            "before_id=0",
            "before_id=abc",
            "before_id=1.2",
            "before_id=1&before_id=2",
            "before_id=999999999999999999999",
        ] {
            let uri = format!("/api/alerts/events?{query}");
            let (status, _, _) = call(
                &state,
                Method::GET,
                &uri,
                &[("cookie", &cookie)],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    #[tokio::test]
    async fn alert_lists_reject_unexpected_query_and_methods() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        for uri in [
            "/api/alerts/rules?x=1",
            "/api/alerts/silences?limit=1",
            "/api/alerts/channels?foo=bar",
            "/api/alerts/rules/abc?x=1",
        ] {
            let method = if uri.contains("/rules/abc") {
                Method::DELETE
            } else {
                Method::GET
            };
            let (status, _, _) = call(
                &state,
                method,
                uri,
                &[("cookie", &cookie), ("content-type", "application/json")],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        }

        // 已注册路径上的不支持方法必须 405，而不是被 `/api/{*rest}` 吞成 404。
        for (method, uri) in [
            (Method::GET, "/api/alerts/channels/abc/test"),
            (Method::PATCH, "/api/alerts/rules"),
            (Method::POST, "/api/alerts/events"),
        ] {
            let (status, _, _) = call(
                &state,
                method.clone(),
                uri,
                &[("cookie", &cookie), ("content-type", "application/json")],
                Body::from("{}"),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn alert_rule_create_forwards_method_path_and_body() {
        let hub_body = r#"{"id":"rule-1","name":"rule"}"#;
        let (hub_url, seen) = spawn_mock_hub(201, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let payload = r#"{"name":"rule","source":"agent_offline","threshold":90,"enabled":true}"#;
        let (status, headers, body) = call(
            &state,
            Method::POST,
            "/api/alerts/rules",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::from(payload),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(&body[..], hub_body.as_bytes());
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        let (head, forwarded) = seen_request(&seen);
        assert!(
            head.starts_with("POST /api/v1/alerts/rules HTTP/1.1"),
            "{head}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&forwarded).unwrap(),
            serde_json::from_str::<Value>(payload).unwrap()
        );
        assert_bearer_sent_to_hub(&head);
        assert!(!String::from_utf8_lossy(&body).contains(TEST_HUB_TOKEN));
    }

    #[tokio::test]
    async fn alert_rule_update_and_delete_forward_expected_methods() {
        let hub_body = r#"{"id":"builtin-agent-offline","enabled":false}"#;
        let (hub_url, seen) = spawn_mock_hub(200, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, _, body) = call(
            &state,
            Method::PUT,
            "/api/alerts/rules/builtin-agent-offline",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::from(r#"{"enabled":false}"#),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], hub_body.as_bytes());
        let (head, forwarded) = seen_request(&seen);
        assert!(
            head.starts_with("PUT /api/v1/alerts/rules/builtin-agent-offline HTTP/1.1"),
            "{head}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&forwarded).unwrap(),
            json!({"enabled": false})
        );
        assert_bearer_sent_to_hub(&head);

        let (hub_url, seen) = spawn_mock_hub(204, "");
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, _, body) = call(
            &state,
            Method::DELETE,
            "/api/alerts/rules/rule-1",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(body.is_empty());
        let (head, forwarded) = seen_request(&seen);
        assert!(
            head.starts_with("DELETE /api/v1/alerts/rules/rule-1 HTTP/1.1"),
            "{head}"
        );
        assert!(forwarded.is_empty());
        assert_bearer_sent_to_hub(&head);
    }

    #[tokio::test]
    async fn alert_events_forwards_whitelisted_query() {
        let hub_body = r#"{"events":[],"next_before_id":null}"#;
        let (hub_url, seen) = spawn_mock_hub(200, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, _, body) = call(
            &state,
            Method::GET,
            "/api/alerts/events?limit=50&before_id=42",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], hub_body.as_bytes());
        let (head, _) = seen_request(&seen);
        assert!(
            head.starts_with("GET /api/v1/alerts/events?limit=50&before_id=42 HTTP/1.1"),
            "{head}"
        );
        assert_bearer_sent_to_hub(&head);
    }

    #[tokio::test]
    async fn alert_silences_and_channels_forward_method_path_and_body() {
        // 创建静默。
        let (hub_url, seen) = spawn_mock_hub(200, r#"{"id":1}"#);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let payload = r#"{"rule_id":"builtin-disk-percent","agent_id":null,"duration_secs":3600}"#;
        let (status, _, _) = call(
            &state,
            Method::POST,
            "/api/alerts/silences",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::from(payload),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (head, forwarded) = seen_request(&seen);
        assert!(
            head.starts_with("POST /api/v1/alerts/silences HTTP/1.1"),
            "{head}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&forwarded).unwrap(),
            serde_json::from_str::<Value>(payload).unwrap()
        );

        // 撤销静默。
        let (hub_url, seen) = spawn_mock_hub(204, "");
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, _, _) = call(
            &state,
            Method::DELETE,
            "/api/alerts/silences/7",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (head, _) = seen_request(&seen);
        assert!(
            head.starts_with("DELETE /api/v1/alerts/silences/7 HTTP/1.1"),
            "{head}"
        );

        // 创建渠道：面板原样转发，不在面板层解析或记录 secret。
        let (hub_url, seen) = spawn_mock_hub(201, r#"{"id":"ch-1"}"#);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let payload = r#"{"name":"telegram","kind":"telegram","enabled":true,"config":{"chat_id":"42","bot_token":"secret-token"}}"#;
        let (status, _, body) = call(
            &state,
            Method::POST,
            "/api/alerts/channels",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::from(payload),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(!String::from_utf8_lossy(&body).contains("secret-token"));
        let (head, forwarded) = seen_request(&seen);
        assert!(
            head.starts_with("POST /api/v1/alerts/channels HTTP/1.1"),
            "{head}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&forwarded).unwrap(),
            serde_json::from_str::<Value>(payload).unwrap()
        );

        // 渠道测试：没有业务 body，固定转发 `{}`。
        let (hub_url, seen) = spawn_mock_hub(204, "");
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, _, _) = call(
            &state,
            Method::POST,
            "/api/alerts/channels/ch-1/test",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (head, forwarded) = seen_request(&seen);
        assert!(
            head.starts_with("POST /api/v1/alerts/channels/ch-1/test HTTP/1.1"),
            "{head}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(&forwarded).unwrap(),
            json!({})
        );
        assert_bearer_sent_to_hub(&head);

        // 删除渠道。
        let (hub_url, seen) = spawn_mock_hub(204, "");
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, _, _) = call(
            &state,
            Method::DELETE,
            "/api/alerts/channels/ch-1",
            &[("cookie", &cookie), ("content-type", "application/json")],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (head, _) = seen_request(&seen);
        assert!(
            head.starts_with("DELETE /api/v1/alerts/channels/ch-1 HTTP/1.1"),
            "{head}"
        );
    }

    #[tokio::test]
    async fn alert_hub_business_errors_pass_through_unchanged() {
        for (hub_status, hub_body) in [
            (400, r#"{"error":"bad_request","message":"规则名称非法"}"#),
            (
                403,
                r#"{"error":"builtin_rule","message":"内置规则不能删除"}"#,
            ),
            (404, r#"{"error":"not_found","message":"规则不存在"}"#),
            (409, r#"{"error":"conflict","message":"规则名称重复"}"#),
            (
                502,
                r#"{"error":"notify_failed","message":"测试消息发送失败"}"#,
            ),
        ] {
            let (hub_url, _seen) = spawn_mock_hub(hub_status, hub_body);
            let state = test_state_with_hub(&hub_url);
            let cookie = session_cookie(&state);
            let (status, headers, body) = call(
                &state,
                Method::DELETE,
                "/api/alerts/rules/rule-1",
                &[("cookie", &cookie), ("content-type", "application/json")],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(
                status,
                StatusCode::from_u16(hub_status).unwrap(),
                "hub status 必须原样保留"
            );
            assert_eq!(&body[..], hub_body.as_bytes(), "错误 body 必须原样保留");
            assert_eq!(
                headers.get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            assert!(
                !String::from_utf8_lossy(&body).contains(TEST_HUB_TOKEN),
                "响应不得出现 hub token"
            );
        }
    }

    /// #38：告警 / 归档透传路由的 hub 401 必须统一改写为 502 hub_auth_failed。
    ///
    /// 前端只对 401 触发全局登出；这些路由的 401 是面板 → hub 的 token 故障，
    /// 不是管理员会话失效。响应不得带上游 body（可能含 token / 认证细节），
    /// 也不能清除 Panel Cookie。
    #[tokio::test]
    async fn alert_and_archive_routes_map_hub_401_to_502_hub_auth_failed() {
        let upstream_body =
            r#"{"error":{"code":"invalid_token","message":"hub token secret must not leak"}}"#;
        let cases: [(Method, &str, bool); 16] = [
            (Method::GET, "/api/alerts/rules", false),
            (Method::POST, "/api/alerts/rules", true),
            (Method::PUT, "/api/alerts/rules/rule-1", true),
            (Method::DELETE, "/api/alerts/rules/rule-1", true),
            (Method::GET, "/api/alerts/events?limit=50", false),
            (Method::GET, "/api/alerts/silences", false),
            (Method::POST, "/api/alerts/silences", true),
            (Method::DELETE, "/api/alerts/silences/1", true),
            (Method::GET, "/api/alerts/channels", false),
            (Method::POST, "/api/alerts/channels", true),
            (Method::PUT, "/api/alerts/channels/ch-1", true),
            (Method::DELETE, "/api/alerts/channels/ch-1", true),
            (Method::POST, "/api/alerts/channels/ch-1/test", true),
            (Method::GET, "/api/archive/status", false),
            (Method::GET, "/api/archive/objects?limit=50", false),
            (Method::GET, "/api/archive/objects/42/download", false),
        ];
        for (method, uri, with_body) in cases {
            let (hub_url, seen) = spawn_mock_hub(401, upstream_body);
            let state = test_state_with_hub(&hub_url);
            let cookie = session_cookie(&state);
            let mut headers = vec![("cookie", cookie.as_str())];
            if with_body || method != Method::GET {
                headers.push(("content-type", "application/json"));
            }
            let body = if with_body {
                Body::from("{}")
            } else {
                Body::empty()
            };
            let (status, response_headers, response_body) =
                call(&state, method.clone(), uri, &headers, body, None).await;
            assert_eq!(
                status,
                StatusCode::BAD_GATEWAY,
                "{method} {uri} 必须把 hub 401 映射为 502"
            );
            assert_eq!(
                response_headers.get(header::CONTENT_TYPE).unwrap(),
                "application/json",
                "{method} {uri}"
            );
            assert_eq!(
                response_headers.get(header::CACHE_CONTROL).unwrap(),
                "no-store",
                "{method} {uri}"
            );
            assert!(
                response_headers.get(header::SET_COOKIE).is_none(),
                "{method} {uri} 不得清除仍然有效的 Panel Cookie"
            );
            assert_eq!(
                json_body(&response_body)["error"],
                "hub_auth_failed",
                "{method} {uri}"
            );
            let text = String::from_utf8_lossy(&response_body).to_string();
            assert!(
                !text.contains("invalid_token")
                    && !text.contains("hub token secret")
                    && !text.contains(TEST_HUB_TOKEN),
                "{method} {uri} 不得泄露上游 body/token: {text}"
            );
            // 路由确实转发到了 hub（而不是被本地校验 / 405 拦截）。
            assert!(
                !seen_request(&seen).0.is_empty(),
                "{method} {uri} 必须转发到 hub"
            );
        }

        // 真正失效的 Panel Cookie 仍由面板返回 401 unauthorized，前端照常登出。
        let (state, _site) = test_state();
        for uri in ["/api/alerts/rules", "/api/archive/status"] {
            let (status, _, body) = call(&state, Method::GET, uri, &[], Body::empty(), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
            assert_eq!(json_body(&body)["error"], "unauthorized", "{uri}");
        }
    }

    #[tokio::test]
    async fn alert_network_errors_are_502_without_token() {
        let state = test_state_with_hub("http://127.0.0.1:1");
        let cookie = session_cookie(&state);
        let (status, _, body) = call(
            &state,
            Method::GET,
            "/api/alerts/rules",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let text = String::from_utf8_lossy(&body).to_string();
        assert!(text.contains("hub_unreachable"), "{text}");
        assert!(!text.contains(TEST_HUB_TOKEN), "{text}");
    }

    // ------------------------------------------------------------------
    // M4-C2b：归档列表 / 流式下载代理
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn archive_proxy_requires_session_for_list_and_download() {
        let state = test_state_with_hub("http://127.0.0.1:1");
        for uri in [
            "/api/archive/status",
            "/api/archive/objects",
            "/api/archive/objects/42/download",
        ] {
            let (status, headers, body) =
                call(&state, Method::GET, uri, &[], Body::empty(), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "uri={uri}");
            assert_eq!(
                headers.get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            assert!(String::from_utf8_lossy(&body).contains("unauthorized"));
        }
    }

    #[tokio::test]
    async fn archive_objects_forwards_query_and_validates() {
        let state = test_state_with_hub("http://127.0.0.1:1");
        let cookie = session_cookie(&state);

        // 参数校验发生在代理之前：非法请求不会碰到 hub。
        for query in [
            "limit=0",
            "limit=101",
            "limit=abc",
            "before_id=0",
            "before_id=-1",
            "before_id=abc",
            "before_id=1&before_id=2",
            "limit=50&foo=bar",
            "x=1",
        ] {
            let (status, _, body) = call(
                &state,
                Method::GET,
                &format!("/api/archive/objects?{query}"),
                &[("cookie", &cookie)],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "query={query}");
            assert_eq!(json_body(&body)["error"], "bad_request", "query={query}");
        }

        // 合法查询原样转发（含 before_id），并注入 hub Bearer。
        let hub_body = r#"{"objects":[],"next_before_id":null}"#;
        let (hub_url, seen) = spawn_mock_hub(200, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/archive/objects?limit=50&before_id=42",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(&body[..], hub_body.as_bytes());
        let (head, _) = seen_request(&seen);
        assert!(
            head.starts_with("GET /api/v1/archive/objects?limit=50&before_id=42 HTTP/1.1"),
            "{head}"
        );
        assert_bearer_sent_to_hub(&head);
        assert!(!String::from_utf8_lossy(&body).contains(TEST_HUB_TOKEN));
    }

    #[tokio::test]
    async fn archive_status_forwards_and_rejects_query() {
        let hub_body = r#"{"enabled":true,"backend":"s3","last_run":null,"objects":0}"#;
        let (hub_url, seen) = spawn_mock_hub(200, hub_body);
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/archive/status",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(&body[..], hub_body.as_bytes());
        let (head, _) = seen_request(&seen);
        assert!(
            head.starts_with("GET /api/v1/archive/status HTTP/1.1"),
            "{head}"
        );
        assert_bearer_sent_to_hub(&head);

        // 状态接口不接受任何查询参数。
        let (status, _, body) = call(
            &state,
            Method::GET,
            "/api/archive/status?x=1",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json_body(&body)["error"], "bad_request");
    }

    #[tokio::test]
    async fn archive_download_streams_headers_and_body() {
        let payload = b"\x1f\x8b\x08\x00rustboard-archive-gzip".to_vec();
        let hub_headers = format!(
            "Content-Type: application/gzip\r\n\
             Content-Disposition: attachment; filename=\"rustboard-20261024-part-00001.csv.gz\"\r\n\
             Content-Length: {}\r\n",
            payload.len()
        );
        let (hub_url, seen) = spawn_raw_mock_hub(200, &hub_headers, payload.clone());
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);

        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/archive/objects/42/download",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/gzip"
        );
        assert_eq!(
            headers.get(header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"rustboard-20261024-part-00001.csv.gz\""
        );
        assert_eq!(
            headers.get(header::CONTENT_LENGTH).unwrap(),
            &payload.len().to_string()
        );
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );
        assert_eq!(body, payload, "下载流必须逐字节透传");
        assert!(!String::from_utf8_lossy(&body).contains(TEST_HUB_TOKEN));

        let (head, _) = seen_request(&seen);
        assert!(
            head.starts_with("GET /api/v1/archive/objects/42/download HTTP/1.1"),
            "{head}"
        );
        assert_bearer_sent_to_hub(&head);
        assert!(
            !head.to_ascii_lowercase().contains("x-ratelimit"),
            "不得把无关头带到 hub: {head}"
        );
    }

    #[tokio::test]
    async fn archive_download_passes_through_hub_errors() {
        for (hub_status, hub_body) in [
            (404, r#"{"error":"not_found","message":"归档对象不存在"}"#),
            (
                409,
                r#"{"error":"archive_not_ready","message":"归档对象尚未上传完成"}"#,
            ),
            (
                502,
                r#"{"error":"archive_unavailable","message":"归档对象下载失败"}"#,
            ),
            (
                429,
                r#"{"error":"archive_busy","message":"归档下载正忙，请稍后重试"}"#,
            ),
        ] {
            let (hub_url, _seen) = spawn_mock_hub(hub_status, hub_body);
            let state = test_state_with_hub(&hub_url);
            let cookie = session_cookie(&state);
            let (status, headers, body) = call(
                &state,
                Method::GET,
                "/api/archive/objects/42/download",
                &[("cookie", &cookie)],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::from_u16(hub_status).unwrap());
            assert_eq!(&body[..], hub_body.as_bytes(), "错误 body 必须原样保留");
            assert_eq!(
                headers.get(header::CONTENT_TYPE).unwrap(),
                "application/json"
            );
            assert!(!String::from_utf8_lossy(&body).contains(TEST_HUB_TOKEN));
        }
    }

    /// M4-C4：hub 429 archive_busy 的状态 / body / Retry-After 原样透传。
    #[tokio::test]
    async fn archive_download_preserves_busy_retry_after() {
        let hub_body = r#"{"error":"archive_busy","message":"归档下载正忙，请稍后重试"}"#;
        let hub_headers = format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\nRetry-After: 1\r\n",
            hub_body.len()
        );
        let (hub_url, _seen) = spawn_raw_mock_hub(429, &hub_headers, hub_body.as_bytes().to_vec());
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);

        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/archive/objects/42/download",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(&body[..], hub_body.as_bytes());
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            headers.get(header::RETRY_AFTER).unwrap(),
            "1",
            "429 的 Retry-After 必须透传"
        );
        assert!(!String::from_utf8_lossy(&body).contains(TEST_HUB_TOKEN));
    }

    #[tokio::test]
    async fn archive_download_rejects_bad_ids_and_query() {
        let state = test_state_with_hub("http://127.0.0.1:1");
        let cookie = session_cookie(&state);

        for id in [
            "abc",
            "0",
            "-1",
            "1.5",
            "%2e%2e",
            "+1",
            "9999999999999999999",
        ] {
            let (status, _, body) = call(
                &state,
                Method::GET,
                &format!("/api/archive/objects/{id}/download"),
                &[("cookie", &cookie)],
                Body::empty(),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "id={id}");
            assert_eq!(json_body(&body)["error"], "bad_request", "id={id}");
        }

        // 多段路径不匹配下载路由，落到 /api/* 兜底 404（仍是 JSON）。
        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/archive/objects/a/b/download",
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
        assert_eq!(json_body(&body)["error"], "not_found");

        // 下载不接受任何查询参数。
        let (status, _, body) = call(
            &state,
            Method::GET,
            "/api/archive/objects/42/download?x=1",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json_body(&body)["error"], "bad_request");
    }

    #[tokio::test]
    async fn archive_download_rejects_oversized_response_and_network_errors() {
        // Content-Length 已超 1 GiB：必须直接 502，不读取 body。
        let payload = b"ignored".to_vec();
        let (hub_url, _seen) = spawn_raw_mock_hub(
            200,
            "Content-Type: application/gzip\r\nContent-Length: 1073741825\r\n",
            payload,
        );
        let state = test_state_with_hub(&hub_url);
        let cookie = session_cookie(&state);
        let (status, headers, body) = call(
            &state,
            Method::GET,
            "/api/archive/objects/42/download",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(json_body(&body)["error"], "archive_too_large");
        assert!(!String::from_utf8_lossy(&body).contains(TEST_HUB_TOKEN));

        // hub 不可达同样是 502，且不回显 token。
        let state = test_state_with_hub("http://127.0.0.1:1");
        let cookie = session_cookie(&state);
        let (status, _, body) = call(
            &state,
            Method::GET,
            "/api/archive/objects/42/download",
            &[("cookie", &cookie)],
            Body::empty(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let text = String::from_utf8_lossy(&body).to_string();
        assert!(text.contains("hub_unreachable"), "{text}");
        assert!(!text.contains(TEST_HUB_TOKEN), "{text}");
    }

    #[test]
    fn archive_path_helpers_are_strict() {
        assert!(proxy::validate_archive_object_id("1"));
        assert!(proxy::validate_archive_object_id("42"));
        assert!(proxy::validate_archive_object_id("999999999999999999"));
        for invalid in [
            "",
            "0",
            "-1",
            "+1",
            "1.5",
            " 1",
            "1 ",
            "abc",
            "..",
            "1/2",
            "9999999999999999999",
        ] {
            assert!(
                !proxy::validate_archive_object_id(invalid),
                "id={invalid:?}"
            );
        }

        assert!(is_archive_download_path("/api/archive/objects/42/download"));
        for invalid in [
            "/api/archive/objects/download",
            "/api/archive/objects//download",
            "/api/archive/objects/a/b/download",
            "/api/archive/objects/42/download/extra",
            "/api/v1/archive/objects/42/download",
        ] {
            assert!(!is_archive_download_path(invalid), "path={invalid:?}");
        }
    }

    #[tokio::test]
    async fn alert_bodies_require_json_and_stay_under_64kib() {
        let (state, _site) = test_state();
        let cookie = session_cookie(&state);
        for (content_type, payload, expected) in [
            (
                "text/plain",
                "{}".to_string(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ),
            (
                "application/json",
                "[1,2,3]".to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "application/json",
                "null".to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "application/json",
                "{not json".to_string(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "application/json",
                format!(r#"{{"name":"{}"}}"#, "a".repeat(MAX_ALERT_BODY)),
                StatusCode::PAYLOAD_TOO_LARGE,
            ),
        ] {
            let (status, _, _) = call(
                &state,
                Method::POST,
                "/api/alerts/rules",
                &[
                    ("cookie", &cookie),
                    ("content-type", content_type),
                    ("host", "panel.test:8080"),
                    ("origin", "http://panel.test:8080"),
                ],
                Body::from(payload),
                None,
            )
            .await;
            assert_eq!(status, expected, "content-type={content_type}");
        }
    }

    #[test]
    fn validates_alert_event_query_boundaries() {
        let pairs = |values: &[(&str, &str)]| {
            values
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<Vec<_>>()
        };
        assert!(validate_alert_event_query(&[]).is_ok());
        assert!(validate_alert_event_query(&pairs(&[("limit", "1")])).is_ok());
        assert!(validate_alert_event_query(&pairs(&[("limit", "100")])).is_ok());
        assert!(validate_alert_event_query(&pairs(&[("before_id", "1")])).is_ok());
        assert!(
            validate_alert_event_query(&pairs(&[("limit", "50"), ("before_id", "42")])).is_ok()
        );

        for values in [
            vec![("limit", "0")],
            vec![("limit", "101")],
            vec![("limit", "1.5")],
            vec![("limit", "-1")],
            vec![("limit", "+1")],
            vec![("limit", "")],
            vec![("limit", "1"), ("limit", "2")],
            vec![("before_id", "0")],
            vec![("before_id", "-1")],
            vec![("before_id", "abc")],
            vec![("before_id", "1"), ("before_id", "2")],
        ] {
            assert!(
                validate_alert_event_query(&pairs(&values)).is_err(),
                "{values:?}"
            );
        }
    }

    #[test]
    fn validates_alert_ids() {
        for id in [
            "builtin-agent-offline",
            "builtin-disk-percent",
            "0b6c7d8e-1234-4abc-9def-0123456789ab",
            "A1",
        ] {
            assert!(proxy::validate_alert_id(id), "{id}");
        }
        let long_id = "a".repeat(65);
        for id in [
            "",
            ".",
            "..",
            "../admin",
            "a/b",
            "a b",
            "a_b",
            "a.b",
            "%2e%2e",
            long_id.as_str(),
        ] {
            assert!(!proxy::validate_alert_id(id), "{id}");
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

    fn init_hub_config(
        admin_listen: &str,
        admin_tls: AdminTlsMode,
        mode: ServerTlsMode,
        data_dir: &Path,
    ) -> HubConfig {
        HubConfig {
            admin_listen: admin_listen.to_string(),
            admin_tls,
            data_dir: data_dir.to_path_buf(),
            tls: rustboard_common::config::TlsConfig {
                mode,
                ..Default::default()
            },
            ..HubConfig::default()
        }
    }

    fn init_hub_config_with_names(
        admin_listen: &str,
        admin_tls: AdminTlsMode,
        mode: ServerTlsMode,
        data_dir: &Path,
        names: &[&str],
    ) -> HubConfig {
        let mut hub = init_hub_config(admin_listen, admin_tls, mode, data_dir);
        hub.server_names = names.iter().map(|name| (*name).to_string()).collect();
        hub.tls.domains = names.iter().map(|name| (*name).to_string()).collect();
        hub
    }

    /// #39：admin_tls=off → http，通配监听仍连回环地址。
    #[test]
    fn init_hub_url_off_uses_loopback_authority() {
        let dir = TempSite::new();
        for (listen, authority) in [
            ("127.0.0.1:8444", "127.0.0.1:8444"),
            ("0.0.0.0:8444", "127.0.0.1:8444"),
            ("[::]:8444", "[::1]:8444"),
            ("localhost:8444", "localhost:8444"),
        ] {
            let hub = init_hub_config(
                listen,
                AdminTlsMode::Off,
                ServerTlsMode::SelfSigned,
                &dir.dir,
            );
            assert_eq!(
                hub_admin_url(&hub).unwrap(),
                format!("http://{authority}"),
                "listen={listen}"
            );
        }
    }

    /// #39：required 时必须从证书 SAN 选非回环 DNS/IP，不能回落到 127.0.0.1。
    #[test]
    fn init_hub_url_requires_non_loopback_certificate_name() {
        let dir = TempSite::new();

        // self-signed：server_names 里同时有 DNS/回环 IP，必须选 DNS。
        let hub = init_hub_config_with_names(
            "0.0.0.0:8444",
            AdminTlsMode::Required,
            ServerTlsMode::SelfSigned,
            &dir.dir,
            &["127.0.0.1", "localhost", "hub.example.com"],
        );
        assert_eq!(hub_admin_url(&hub).unwrap(), "https://hub.example.com:8444");

        // ACME domain：SAN 来自 tls.domains。
        let hub = init_hub_config_with_names(
            "0.0.0.0:8444",
            AdminTlsMode::Required,
            ServerTlsMode::AcmeDomain,
            &dir.dir,
            &["panel.example.com"],
        );
        let plan = plan_hub_connection(&hub, None, None).unwrap();
        assert_eq!(plan.hub_url, "https://panel.example.com:8444");
        assert_eq!(plan.ca_source, None, "ACME 域名证书使用系统根");

        // ACME IP：选第一个非回环 IP；IPv6 必须加方括号。
        let hub = init_hub_config_with_names(
            "[::]:8444",
            AdminTlsMode::Required,
            ServerTlsMode::AcmeIp,
            &dir.dir,
            &["203.0.113.5"],
        );
        assert_eq!(hub_admin_url(&hub).unwrap(), "https://203.0.113.5:8444");
        let hub = init_hub_config_with_names(
            "[::]:8444",
            AdminTlsMode::Required,
            ServerTlsMode::SelfSigned,
            &dir.dir,
            &["2001:db8::5"],
        );
        assert_eq!(hub_admin_url(&hub).unwrap(), "https://[2001:db8::5]:8444");

        // 只有回环 SAN：无法推导可连接的 https，必须提示 --hub / --hub-ca。
        let hub = init_hub_config_with_names(
            "0.0.0.0:8444",
            AdminTlsMode::Required,
            ServerTlsMode::SelfSigned,
            &dir.dir,
            &["localhost", "127.0.0.1", "::1"],
        );
        let error = plan_hub_connection(&hub, None, None).expect_err("回环 SAN 必须失败");
        let text = format!("{error:#}");
        assert!(text.contains("--hub"), "错误必须提示 --hub: {text}");
        assert!(text.contains("--hub-ca"), "错误必须提示 --hub-ca: {text}");
        assert!(text.contains("未写入面板配置"), "{text}");
    }

    /// #39：required+self-signed 取 Hub 的 ca.crt；ACME 使用系统根；Off 用 http。
    #[test]
    fn init_plan_chooses_private_ca_only_for_self_signed() {
        let dir = TempSite::new();
        let hub = init_hub_config_with_names(
            "0.0.0.0:8444",
            AdminTlsMode::Required,
            ServerTlsMode::SelfSigned,
            &dir.dir,
            &["hub.example.com"],
        );
        let plan = plan_hub_connection(&hub, None, None).unwrap();
        assert_eq!(plan.hub_url, "https://hub.example.com:8444");
        assert_eq!(
            plan.ca_source,
            Some(tls::cert_dir(&dir.dir).join(tls::CA_CERT_FILE))
        );

        for mode in [ServerTlsMode::AcmeDomain, ServerTlsMode::AcmeIp] {
            let names = if mode == ServerTlsMode::AcmeIp {
                &["198.51.100.7"][..]
            } else {
                &["panel.example.com"][..]
            };
            let hub = init_hub_config_with_names(
                "0.0.0.0:8444",
                AdminTlsMode::Required,
                mode,
                &dir.dir,
                names,
            );
            let plan = plan_hub_connection(&hub, None, None).unwrap();
            assert_eq!(plan.ca_source, None, "ACME 必须使用系统根: {mode:?}");
        }

        let hub = init_hub_config(
            "127.0.0.1:8444",
            AdminTlsMode::Off,
            ServerTlsMode::SelfSigned,
            &dir.dir,
        );
        let plan = plan_hub_connection(&hub, None, None).unwrap();
        assert_eq!(plan.hub_url, "http://127.0.0.1:8444");
        assert_eq!(plan.ca_source, None, "admin_tls=off 不得配置 hub_ca");
    }

    /// #39：显式 --hub 的 scheme 优先；仅当 host 指向本机 Hub 时才复用自签 CA。
    #[test]
    fn init_plan_honors_explicit_hub_scheme_and_host() {
        let dir = TempSite::new();
        let hub = init_hub_config_with_names(
            "0.0.0.0:8444",
            AdminTlsMode::Required,
            ServerTlsMode::SelfSigned,
            &dir.dir,
            &["hub.example.com", "localhost", "127.0.0.1"],
        );

        let plan = plan_hub_connection(&hub, Some("http://127.0.0.1:9000"), None).unwrap();
        assert_eq!(plan.hub_url, "http://127.0.0.1:9000");
        assert_eq!(plan.ca_source, None, "http 显式覆盖时不能写 hub_ca");

        // 本机 loopback / 本机 DNS 名：允许复制本机 CA。
        for url in [
            "https://127.0.0.1:8444",
            "https://localhost:8444",
            "https://hub.example.com:8444/",
        ] {
            let plan = plan_hub_connection(&hub, Some(url), None).unwrap();
            assert_eq!(
                plan.ca_source,
                Some(tls::cert_dir(&dir.dir).join(tls::CA_CERT_FILE)),
                "本机地址必须能复用自签 CA: {url}"
            );
        }

        // 远端 host：没有 --hub-ca 时必须失败，不能把本机 CA 复制给远端。
        let error = plan_hub_connection(&hub, Some("https://remote.example.net:8444"), None)
            .expect_err("远端自签 Hub 缺少 --hub-ca 必须失败");
        let text = format!("{error:#}");
        assert!(text.contains("--hub-ca"), "错误必须提示 --hub-ca: {text}");
        assert!(text.contains("未写入面板配置"), "{text}");

        // 给了 --hub-ca 时不再推导本机 CA，交由 prepare_hub_ca 校验显式文件。
        let explicit = Path::new("/tmp/remote-ca.pem");
        let plan = plan_hub_connection(
            &hub,
            Some("https://remote.example.net:8444"),
            Some(explicit),
        )
        .unwrap();
        assert_eq!(plan.hub_url, "https://remote.example.net:8444");
        assert_eq!(plan.ca_source, None);

        let plan = plan_hub_connection(&hub, Some("127.0.0.1:9444"), None).unwrap();
        assert_eq!(
            plan.hub_url, "http://127.0.0.1:9444",
            "无 scheme 的显式 --hub 保留旧行为：默认 http"
        );
    }

    /// #39：CA 先读取校验、cfg.save 成功后才落盘；缺失/非法时失败并提示 --hub-ca。
    #[test]
    fn init_prepares_hub_ca_and_fails_closed() {
        let hub_dir = TempSite::new();
        tls::ensure_hub_material(
            &hub_dir.dir,
            &["hub.example.com".to_string()],
            tls::CertPolicy::default(),
        )
        .unwrap();
        let source = tls::cert_dir(&hub_dir.dir).join(tls::CA_CERT_FILE);
        let plan = plan_hub_connection(
            &init_hub_config_with_names(
                "0.0.0.0:8444",
                AdminTlsMode::Required,
                ServerTlsMode::SelfSigned,
                &hub_dir.dir,
                &["hub.example.com"],
            ),
            None,
            None,
        )
        .unwrap();

        let config_dir = TempSite::new();
        let config_path = config_dir.dir.join("panel.toml");
        let prepared = prepare_hub_ca(&plan, None, &config_path)
            .unwrap()
            .expect("自签 Hub 必须准备 CA");
        let copied_path = config_dir.dir.join("hub-ca.pem");
        assert_eq!(
            prepared.config_path().unwrap(),
            copied_path.to_str().unwrap()
        );
        assert!(
            !copied_path.exists(),
            "prepare 阶段只读取校验，不能在 cfg.save 前写 CA"
        );

        prepared.install().unwrap();
        assert_eq!(
            std::fs::read(&copied_path).unwrap(),
            std::fs::read(&source).unwrap(),
            "hub_ca 必须是 Hub CA 的逐字节副本"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&copied_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o644, "CA 是公开信息，使用 0644");
        }
        // 复制出的 CA 能被 ProxyClient 接受（不是空 PEM / 私钥 / 系统根回退）。
        proxy::ProxyClient::new(&plan.hub_url, "test-token", copied_path.to_str().unwrap())
            .expect("合法的 hub CA 必须能构造 ProxyClient");

        // 缺失自签 CA：必须提示 --hub-ca，不能生成指向系统根的配置。
        let missing_dir = TempSite::new();
        let missing_plan = plan_hub_connection(
            &init_hub_config_with_names(
                "0.0.0.0:8444",
                AdminTlsMode::Required,
                ServerTlsMode::SelfSigned,
                &missing_dir.dir,
                &["hub.example.com"],
            ),
            None,
            None,
        )
        .unwrap();
        let error = prepare_hub_ca(&missing_plan, None, &missing_dir.dir.join("panel.toml"))
            .err()
            .expect("缺失自签 CA 必须失败");
        let text = format!("{error:#}");
        assert!(text.contains("--hub-ca"), "错误必须提示 --hub-ca: {text}");
        assert!(
            !missing_dir.dir.join("hub-ca.pem").exists(),
            "失败时不得留下看似可用的 hub_ca"
        );

        // 显式 --hub-ca 与 http 是矛盾配置，必须拒绝。
        let http_plan = HubInitPlan {
            hub_url: "http://127.0.0.1:8444".to_string(),
            ca_source: None,
        };
        let error = prepare_hub_ca(&http_plan, Some(&source), &config_path)
            .err()
            .expect("http + --hub-ca 必须拒绝");
        assert!(format!("{error:#}").contains("https://"));
    }

    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    /// #39：注入 CA 写失败——旧 CA / 旧配置字节不变，且不保存新配置。
    #[test]
    fn init_ca_write_failure_keeps_old_ca_and_config() {
        let dir = TempSite::new();
        let dest = dir.dir.join("hub-ca.pem");
        let config_path = dir.dir.join("panel.toml");
        std::fs::write(&dest, b"old-ca-bytes").unwrap();
        std::fs::write(&config_path, b"old-config-bytes").unwrap();
        let prepared = PreparedHubCa {
            dest: dest.clone(),
            bytes: b"new-ca-bytes".to_vec(),
            previous: Some(b"old-ca-bytes".to_vec()),
            fail_write: true,
        };

        let mut saved = false;
        let error = write_init_artifacts(Some(&prepared), || {
            saved = true;
            std::fs::write(&config_path, b"new-config-bytes").unwrap();
            Ok(())
        })
        .unwrap_err();
        assert!(!saved, "CA 写失败时不得保存配置");
        assert!(format!("{error:#}").contains("注入"), "{error:#}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"old-ca-bytes");
        assert_eq!(std::fs::read(&config_path).unwrap(), b"old-config-bytes");
        assert!(
            file_names(&dir.dir)
                .iter()
                .all(|name| !name.starts_with('.')),
            "失败后不得残留临时文件"
        );
    }

    /// #39：注入 cfg.save 失败——恢复旧 CA 字节，旧配置不变。
    #[test]
    fn init_config_save_failure_restores_old_ca() {
        let dir = TempSite::new();
        let dest = dir.dir.join("hub-ca.pem");
        let config_path = dir.dir.join("panel.toml");
        std::fs::write(&dest, b"old-ca-bytes").unwrap();
        std::fs::write(&config_path, b"old-config-bytes").unwrap();
        let prepared = PreparedHubCa {
            dest: dest.clone(),
            bytes: b"new-ca-bytes".to_vec(),
            previous: Some(b"old-ca-bytes".to_vec()),
            fail_write: false,
        };

        let error = write_init_artifacts(Some(&prepared), || Err(anyhow!("注入的配置保存失败")))
            .unwrap_err();
        assert!(format!("{error:#}").contains("配置保存失败"), "{error:#}");
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"old-ca-bytes",
            "cfg.save 失败必须恢复旧 CA 字节"
        );
        assert_eq!(std::fs::read(&config_path).unwrap(), b"old-config-bytes");
        assert!(
            file_names(&dir.dir)
                .iter()
                .all(|name| !name.starts_with('.')),
            "失败后不得残留临时文件"
        );
    }

    /// #39：原本没有 CA 时 cfg.save 失败——删除新 CA，无残留。
    #[test]
    fn init_config_save_failure_removes_new_ca() {
        let dir = TempSite::new();
        let dest = dir.dir.join("hub-ca.pem");
        let prepared = PreparedHubCa {
            dest: dest.clone(),
            bytes: b"new-ca-bytes".to_vec(),
            previous: None,
            fail_write: false,
        };

        assert!(
            write_init_artifacts(Some(&prepared), || Err(anyhow!("注入的配置保存失败"))).is_err()
        );
        assert!(!dest.exists(), "cfg.save 失败必须删除新 CA");
        assert!(
            file_names(&dir.dir)
                .iter()
                .all(|name| !name.starts_with('.')),
            "失败后不得残留临时文件"
        );
    }

    /// #39：无效 CA 在写配置前失败；--force 场景下不得覆盖旧 CA。
    #[test]
    fn init_rejects_invalid_hub_ca_without_overwriting_existing() {
        let dir = TempSite::new();
        let bogus = dir.dir.join("bogus.pem");
        std::fs::write(&bogus, "not a certificate\n").unwrap();
        let plan = HubInitPlan {
            hub_url: "https://127.0.0.1:8444".to_string(),
            ca_source: None,
        };
        let config_path = dir.dir.join("panel.toml");
        let dest = dir.dir.join("hub-ca.pem");
        std::fs::write(&dest, "old-ca-bytes").unwrap();

        let error = prepare_hub_ca(&plan, Some(&bogus), &config_path)
            .err()
            .expect("非法 PEM 必须失败");
        let text = format!("{error:#}");
        assert!(text.contains("PEM"), "错误必须点名 PEM: {text}");
        assert_eq!(
            std::fs::read_to_string(&dest).unwrap(),
            "old-ca-bytes",
            "校验失败时不得覆盖旧 CA"
        );
        assert!(!config_path.exists(), "失败时不得写面板配置");
    }

    #[test]
    fn init_hub_ca_destination_is_absolute() {
        let dest = hub_ca_destination(Path::new("panel.toml")).unwrap();
        assert!(dest.is_absolute(), "相对配置路径也必须落绝对 hub_ca");
        assert_eq!(dest.file_name().unwrap(), "hub-ca.pem");
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

        // M4-A2b：与 hub 对齐，最长 730 天；边界本身通过，+1ms 拒绝。
        let from = 1_700_000_000_000i64;
        let series_at = |span_ms: i64| {
            vec![
                ("metric".to_string(), "cpu.usage".to_string()),
                ("from".to_string(), from.to_string()),
                ("to".to_string(), (from + span_ms).to_string()),
            ]
        };
        assert!(
            validate_series_query(&series_at(MAX_SERIES_SPAN_MS)).is_ok(),
            "730 天必须通过"
        );
        let err = validate_series_query(&series_at(MAX_SERIES_SPAN_MS + 1)).unwrap_err();
        assert!(err.contains("730"), "错误信息必须说明 730 天上限: {err}");
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

    // ---------- C7：面板直连 TLS 文件 / SAN 校验 ----------

    struct TlsTempDir {
        path: PathBuf,
    }

    impl TlsTempDir {
        fn new(tag: &str) -> Self {
            let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "rustboard-panel-tls-{tag}-{}-{unique}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn join(&self, name: &str) -> PathBuf {
            self.path.join(name)
        }
    }

    impl Drop for TlsTempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn test_ca() -> (rcgen::Certificate, rcgen::KeyPair) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "RustBoard Panel Test CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        let cert = params.self_signed(&key).unwrap();
        (cert, key)
    }

    /// 生成 leaf；`sans` 形如 `dns:panel.example.com` / `ip:127.0.0.1`。
    fn test_leaf(
        ca_cert: &rcgen::Certificate,
        ca_key: &rcgen::KeyPair,
        sans: &[&str],
        expired: bool,
    ) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "rustboard-panel test");
        params.subject_alt_names = sans
            .iter()
            .map(|san| {
                if let Some(ip) = san.strip_prefix("ip:") {
                    rcgen::SanType::IpAddress(ip.parse().unwrap())
                } else {
                    let dns = san.strip_prefix("dns:").unwrap_or(san);
                    rcgen::SanType::DnsName(rcgen::Ia5String::try_from(dns.to_string()).unwrap())
                }
            })
            .collect();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        if expired {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2020, 2, 1);
        }
        let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn write_tls_pair(dir: &TlsTempDir, cert_pem: &str, key_pem: &str) -> (PathBuf, PathBuf) {
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        std::fs::write(&cert, cert_pem).unwrap();
        std::fs::write(&key, key_pem).unwrap();
        set_mode(&cert, 0o644);
        set_mode(&key, 0o600);
        (cert, key)
    }

    #[test]
    fn panel_tls_http_mode_and_pair_rules() {
        assert!(
            load_panel_tls(&PanelConfig::default()).unwrap().is_none(),
            "缺 tls 字段必须保持 HTTP"
        );

        let dir = TlsTempDir::new("pair");
        let (ca_cert, ca_key) = test_ca();
        let (cert_pem, key_pem) = test_leaf(&ca_cert, &ca_key, &["dns:panel.example.com"], false);
        let (cert, _) = write_tls_pair(&dir, &cert_pem, &key_pem);

        let mut cfg = PanelConfig {
            tls_cert: cert.to_string_lossy().into_owned(),
            ..PanelConfig::default()
        };
        let error = load_panel_tls(&cfg).err().expect("必须拒绝");
        assert!(format!("{error:#}").contains("成对"), "{error:#}");

        cfg.tls_key = "relative-key.pem".to_string();
        let error = load_panel_tls(&cfg).err().expect("必须拒绝");
        assert!(format!("{error:#}").contains("绝对路径"), "{error:#}");
    }

    #[test]
    fn panel_tls_runtime_hardens_key_but_source_rejects_loose_key() {
        let dir = TlsTempDir::new("mode");
        let (ca_cert, ca_key) = test_ca();
        let (cert_pem, key_pem) = test_leaf(&ca_cert, &ca_key, &["dns:panel.example.com"], false);
        let (cert, key) = write_tls_pair(&dir, &cert_pem, &key_pem);
        set_mode(&key, 0o644);

        let error = validate_panel_tls_files(&cert, &key, TlsFilePolicy::Source)
            .err()
            .expect("必须拒绝");
        assert!(format!("{error:#}").contains("0600"), "{error:#}");
        assert_eq!(mode_of(&key), 0o644, "Source 校验不得修改用户源文件");

        validate_panel_tls_files(&cert, &key, TlsFilePolicy::Runtime)
            .expect("运行时读取应把 0644 key 收紧到 0600");
        assert_eq!(mode_of(&key), 0o600);
        assert_eq!(mode_of(&cert), 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn panel_tls_rejects_symlink_key() {
        let dir = TlsTempDir::new("symlink");
        let (ca_cert, ca_key) = test_ca();
        let (cert_pem, key_pem) = test_leaf(&ca_cert, &ca_key, &["dns:panel.example.com"], false);
        let (cert, key) = write_tls_pair(&dir, &cert_pem, &key_pem);
        let link = dir.join("key-link.pem");
        std::os::unix::fs::symlink(&key, &link).unwrap();

        let error = validate_panel_tls_files(&cert, &link, TlsFilePolicy::Source)
            .err()
            .expect("必须拒绝");
        assert!(format!("{error:#}").contains("符号链接"), "{error:#}");
    }

    #[test]
    fn panel_tls_rejects_mismatched_and_expired_certificates() {
        let dir = TlsTempDir::new("bad-mat");
        let (ca_cert, ca_key) = test_ca();
        let (cert1, _key1) = test_leaf(&ca_cert, &ca_key, &["dns:panel.example.com"], false);
        let (_cert2, key2) = test_leaf(&ca_cert, &ca_key, &["dns:panel.example.com"], false);
        let (cert, key) = write_tls_pair(&dir, &cert1, &key2);
        let error = validate_panel_tls_files(&cert, &key, TlsFilePolicy::Source)
            .err()
            .expect("必须拒绝");
        assert!(format!("{error:#}").contains("不匹配"), "{error:#}");

        let dir = TlsTempDir::new("expired");
        let (cert_pem, key_pem) = test_leaf(&ca_cert, &ca_key, &["dns:panel.example.com"], true);
        let (cert, key) = write_tls_pair(&dir, &cert_pem, &key_pem);
        let error = validate_panel_tls_files(&cert, &key, TlsFilePolicy::Source)
            .err()
            .expect("必须拒绝");
        assert!(format!("{error:#}").contains("已过期"), "{error:#}");
    }

    #[test]
    fn panel_tls_requires_san_and_checks_listen_ip_and_origin() {
        let dir = TlsTempDir::new("san");
        let (ca_cert, ca_key) = test_ca();
        let (cert_pem, key_pem) = test_leaf(
            &ca_cert,
            &ca_key,
            &["dns:panel.example.com", "ip:127.0.0.1"],
            false,
        );
        let (cert, key) = write_tls_pair(&dir, &cert_pem, &key_pem);
        let files = validate_panel_tls_files(&cert, &key, TlsFilePolicy::Source).expect("合法证书");

        validate_panel_tls_names(&files, "127.0.0.1:8443", "https://panel.example.com")
            .expect("监听 IP 与 public_origin 都被覆盖");

        let error = validate_panel_tls_names(&files, "127.0.0.2:8443", "https://panel.example.com")
            .unwrap_err();
        assert!(format!("{error:#}").contains("127.0.0.2"), "{error:#}");

        let error =
            validate_panel_tls_names(&files, "0.0.0.0:8443", "https://evil.example").unwrap_err();
        assert!(format!("{error:#}").contains("SAN"), "{error:#}");

        // 0.0.0.0 是通配绑定，不作为访问名校验。
        validate_panel_tls_names(&files, "0.0.0.0:8443", "https://panel.example.com")
            .expect("通配监听地址不应要求 IP SAN");

        assert_eq!(
            derived_https_origin(&files).unwrap(),
            "https://panel.example.com"
        );

        let dir = TlsTempDir::new("no-san");
        let (cert_pem, key_pem) = test_leaf(&ca_cert, &ca_key, &[], false);
        let (cert, key) = write_tls_pair(&dir, &cert_pem, &key_pem);
        let error = validate_panel_tls_files(&cert, &key, TlsFilePolicy::Source)
            .err()
            .expect("必须拒绝");
        assert!(format!("{error:#}").contains("没有任何 SAN"), "{error:#}");
    }

    #[test]
    fn panel_tls_load_builds_tls13_http1_config() {
        let dir = TlsTempDir::new("load");
        let (ca_cert, ca_key) = test_ca();
        let (cert_pem, key_pem) = test_leaf(
            &ca_cert,
            &ca_key,
            &["dns:panel.example.com", "ip:127.0.0.1"],
            false,
        );
        let (cert, key) = write_tls_pair(&dir, &cert_pem, &key_pem);
        let cfg = PanelConfig {
            listen: "127.0.0.1:8443".to_string(),
            public_origin: "https://panel.example.com".to_string(),
            tls_cert: cert.to_string_lossy().into_owned(),
            tls_key: key.to_string_lossy().into_owned(),
            ..PanelConfig::default()
        };
        let runtime = load_panel_tls(&cfg).expect("合法 TLS 配置").expect("HTTPS");
        assert_eq!(runtime.config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn panel_tls_origin_host_parsing() {
        assert_eq!(
            origin_host("https://panel.example.com"),
            Some("panel.example.com")
        );
        assert_eq!(
            origin_host("https://panel.example.com:8443"),
            Some("panel.example.com")
        );
        assert_eq!(origin_host("https://[::1]:8443"), Some("::1"));
        assert_eq!(origin_host("ftp://panel.example.com"), None);
        assert_eq!(origin_host("https://"), None);
    }
}
