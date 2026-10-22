//! RustBoard 汇聚端。
//!
//! 职责：接收 agent 上报、写入存储、对外提供只读 API，
//! 并在 `self_monitor` 打开时采集本机指标（hub 就是一台内置 agent）。
//!
//! 安全模型：私有 CA + 服务端证书指纹固定 + 一次性 enrollment token。
//! agent 首次连接只允许发 `Enroll`，换取客户端证书与独立 secret，之后走 mTLS。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustboard_common::config::HubConfig;
use rustboard_common::model::{AgentRecord, SampleBatch, SeriesQuery, SeriesRow};
use rustboard_common::tls;
use rustboard_common::util::{
    arch, boot_id, hostname, now_ms, os_pretty_name, pick_free_port_excluding, port_of,
};
use rustboard_common::wire::{codes, EnrollRequest, Frame, Welcome};
use rustboard_common::{DEFAULT_HUB_CONFIG, PROTOCOL_VERSION, VERSION};
use rustboard_core::collect::default_collectors;
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::{IngestOutcome, Storage};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

mod session;
use session::SessionRegistry;

/// 内置本机采集使用的 agent_id，只允许 hub 进程内部写入。
/// WebSocket 单条消息上限。agent 的正常批次只有几 KB，1 MiB 足够宽裕；
/// 不设上限时 tungstenite 默认允许 64 MiB，未认证连接可用分片消息打爆内存。
const MAX_WS_MESSAGE_SIZE: usize = 1024 * 1024;
/// 单帧上限，防止一个巨大分片占满内存。
const MAX_WS_FRAME_SIZE: usize = 256 * 1024;

const HUB_SELF_AGENT_ID: &str = "hub-self";
/// 会话身份与帧内身份不一致。
const IDENTITY_MISMATCH: &str = "identity_mismatch";
/// 正式会话缺少客户端证书。
const MTLS_REQUIRED: &str = "mtls_required";
/// 连续这么久收不到任何帧就认为连接已死（agent 每 15s 发一次 Ping）。
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// 吊销状态轮询周期，保证吊销后连接能在 2s 内被关闭。
const REVOKE_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// TLS 握手超时，避免半开连接长期占用资源。
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// HTTP/1 请求头读取超时，抵挡 slowloris 一类慢速攻击。
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// 单条 WebSocket 帧的写超时；写不出去说明对端已经不读了，直接清理会话。
const SESSION_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Parser)]
#[command(name = "rustboard-hub", version, about = "RustBoard 汇聚端")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 启动 hub。
    Run {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 生成 CA、服务端证书与默认配置。
    Init {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        agent_listen: Option<String>,
        #[arg(long)]
        admin_listen: Option<String>,
        /// 追加到服务端证书 SAN 的地址，可重复。
        #[arg(long = "san")]
        sans: Vec<String>,
        /// 写进 agent 安装命令的 hub 地址（公网 IP 或域名），留空自动探测。
        #[arg(long)]
        advertise: Option<String>,
        #[arg(long)]
        force: bool,
    },
    /// 纳管相关的运维命令。
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },
    /// 查看当前使用的端口与访问地址。
    Ports {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// 生成一次性 enrollment token 与安装命令。
    Add {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        name: String,
        #[arg(long, default_value_t = 30)]
        ttl_minutes: u32,
    },
    /// 吊销一台 agent（立即拒绝其连接）。
    Revoke {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        id: String,
    },
}

#[derive(Clone)]
struct AppState {
    storage: Arc<SqliteStorage>,
    cfg: Arc<HubConfig>,
    sessions: Arc<SessionRegistry>,
    /// 已升级的 WebSocket 会话上限。TLS 层信号量在升级完成时释放，
    /// 长连接会话必须在这里再占一个许可，才真正限制并发会话数。
    session_slots: Arc<tokio::sync::Semaphore>,
}

/// 由 TLS accept 层注入到每个请求扩展里的对端身份。
///
/// `None` 表示这条 TLS 连接没有携带客户端证书（只允许走 enrollment）。
#[derive(Clone, Debug)]
struct PeerIdentity(Option<String>);

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rustboard_hub=info,tower_http=warn".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match Cli::parse().cmd {
        Cmd::Init {
            config,
            data_dir,
            agent_listen,
            admin_listen,
            sans,
            advertise,
            force,
        } => init(
            config,
            data_dir,
            agent_listen,
            admin_listen,
            sans,
            advertise,
            force,
        ),
        Cmd::Run { config } => {
            let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
            let cfg = load_config(&path)?;
            let db_path = cfg.sqlite_path()?;
            run(cfg, db_path)
        }
        Cmd::Agent { action } => match action {
            AgentAction::Add {
                config,
                name,
                ttl_minutes,
            } => agent_add(config, name, ttl_minutes),
            AgentAction::Revoke { config, id } => agent_revoke(config, id),
        },
        Cmd::Ports { config } => print_ports(config),
    }
}

fn load_config(path: &std::path::Path) -> Result<HubConfig> {
    HubConfig::load(path).with_context(|| {
        format!(
            "读取配置失败: {}（先执行 rustboard-hub init）",
            path.display()
        )
    })
}

fn init(
    config: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    agent_listen: Option<String>,
    admin_listen: Option<String>,
    sans: Vec<String>,
    advertise: Option<String>,
    force: bool,
) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    if path.exists() && !force {
        bail!("{} 已存在，使用 --force 覆盖", path.display());
    }
    let mut cfg = HubConfig::default();
    if let Some(d) = data_dir {
        cfg.database = format!("sqlite://{}/rustboard.db", d.display());
        cfg.data_dir = d;
    }
    // 端口默认随机五位数，避免和机器上已有服务撞车；用户显式指定时以用户为准
    match agent_listen {
        Some(a) => cfg.agent_listen = a,
        None => {
            let port = pick_free_port_excluding(&[])?;
            cfg.agent_listen = format!("0.0.0.0:{port}");
        }
    }
    match admin_listen {
        Some(a) => cfg.admin_listen = a,
        None => {
            let exclude: Vec<u16> = port_of(&cfg.agent_listen).into_iter().collect();
            let port = pick_free_port_excluding(&exclude)?;
            cfg.admin_listen = format!("127.0.0.1:{port}");
        }
    }
    cfg.name = hostname();
    // 安装命令里的地址：显式指定 > 默认出口 IP
    let advertise =
        advertise.or_else(|| rustboard_common::util::primary_ipv4().map(|ip| ip.to_string()));
    if let Some(host) = &advertise {
        cfg.server_names.push(host.clone());
        cfg.advertise_host = Some(host.clone());
    }
    cfg.server_names.extend(sans);
    cfg.server_names.push(hostname());

    let fingerprint = tls::ensure_hub_material(&cfg.data_dir, &cfg.server_names)?;
    cfg.save(&path)?;

    println!("已写入配置: {}", path.display());
    println!("证书目录: {}", tls::cert_dir(&cfg.data_dir).display());
    println!("服务端证书指纹: {fingerprint}");
    println!("agent 接入监听: {}", cfg.agent_listen);
    println!("管理 API 监听: {}", cfg.admin_listen);
    println!("（端口为随机五位数，随时可用 `rustboard-hub ports` 查看）");
    println!("\n下一步:");
    println!("  1) rustboard-hub run --config {}", path.display());
    println!(
        "  2) rustboard-hub agent add --config {} --name web-01",
        path.display()
    );
    Ok(())
}

fn print_ports(config: Option<PathBuf>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    let agent_port = port_of(&cfg.agent_listen).unwrap_or(0);
    let admin_port = port_of(&cfg.admin_listen).unwrap_or(0);

    println!("配置文件: {}", path.display());
    println!("agent 接入端口: {agent_port}");
    println!("  监听: {}", cfg.agent_listen);
    println!("  对外: wss://<公网IP>:{agent_port}/agent/ws");
    println!("管理 API 端口: {admin_port}");
    println!("  本机: http://127.0.0.1:{admin_port}");
    if let Some(host) = &cfg.advertise_host {
        println!("agent 连接地址: wss://{host}:{agent_port}/agent/ws");
    }

    let cert_path = tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE);
    match std::fs::read_to_string(cert_path) {
        Ok(pem) => println!("证书指纹: {}", tls::fingerprint_of_pem(&pem)?),
        Err(_) => println!("证书: 未初始化（先执行 rustboard-hub init）"),
    }
    Ok(())
}

fn agent_add(config: Option<PathBuf>, name: String, ttl_minutes: u32) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    let db = SqliteStorage::open(&cfg.sqlite_path()?)?;

    let token = new_secret();
    let now = now_ms();
    let expires = now + (ttl_minutes as i64) * 60_000;
    db.create_enroll_token(&tls::sha256_hex(&token), &name, now, expires)?;

    let cert_pem =
        std::fs::read_to_string(tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE))
            .context("找不到服务端证书，先执行 rustboard-hub init")?;
    let fingerprint = tls::fingerprint_of_pem(&cert_pem)?;

    let host = cfg
        .advertise_host
        .clone()
        .or_else(|| {
            cfg.server_names
                .iter()
                .find(|h| {
                    h.parse::<std::net::IpAddr>()
                        .map(|ip| !ip.is_loopback())
                        .unwrap_or(false)
                })
                .cloned()
        })
        .or_else(|| cfg.server_names.first().cloned())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = cfg.agent_listen.rsplit(':').next().unwrap_or("8443");

    println!("一次性 token（{ttl_minutes} 分钟内有效，仅可使用一次）:");
    println!("  {token}");
    println!("\n在目标服务器上执行:");
    println!(
        "  rustboard-agent init --hub wss://{host}:{port}/agent/ws \\\n    --token {token} --fingerprint {fingerprint} --name {name}"
    );
    Ok(())
}

fn agent_revoke(config: Option<PathBuf>, id: String) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    let db = SqliteStorage::open(&cfg.sqlite_path()?)?;
    db.revoke_agent(&id, now_ms())?;
    println!("已吊销 agent: {id}");
    Ok(())
}

fn new_secret() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

fn run(cfg: HubConfig, db_path: PathBuf) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        let storage = Arc::new(SqliteStorage::open(&db_path)?);
        tracing::info!(db = %db_path.display(), "存储已就绪");

        // L5：监听前清掉上次异常退出遗留的 online，避免面板长期显示假在线。
        let reset = storage
            .reset_online_status()
            .context("启动时重置在线状态失败")?;
        if reset > 0 {
            tracing::info!(count = reset, "启动时已将残留的 online 状态重置为 offline");
        }

        // 升级路径：旧安装的 ca.key / server.key 可能是 0644
        tls::harden_hub_material(&cfg.data_dir)?;
        let tls_config = tls::server_config(&cfg.data_dir)?;
        let fingerprint = {
            let pem =
                std::fs::read_to_string(tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE))?;
            tls::fingerprint_of_pem(&pem)?
        };
        tracing::info!(fingerprint, "TLS 已启用");

        let sessions = SessionRegistry::new();
        let state = AppState {
            storage: storage.clone(),
            cfg: Arc::new(cfg.clone()),
            sessions: sessions.clone(),
            session_slots: Arc::new(tokio::sync::Semaphore::new(cfg.max_connections.max(1))),
        };

        spawn_revoke_watcher(storage.clone(), sessions);

        if cfg.self_monitor {
            spawn_self_monitor(storage.clone(), cfg.clone());
        }

        let agent_app = Router::new()
            .route("/agent/ws", get(agent_ws))
            .with_state(state.clone());

        let admin_app = Router::new()
            .route("/healthz", get(healthz))
            .route("/api/v1/agents", get(list_agents))
            .route("/api/v1/series", get(query_series))
            .with_state(state);

        let agent_addr = cfg.agent_listen.clone();
        let admin_addr = cfg.admin_listen.clone();
        tracing::info!(%agent_addr, "agent 接入监听（TLS）");
        tracing::info!(%admin_addr, "管理 API 监听（HTTP，请只绑内网）");

        tokio::try_join!(
            serve_tls(agent_app, agent_addr, tls_config, cfg.max_connections),
            serve(admin_app, admin_addr)
        )?;
        Ok(())
    })
}

async fn serve(app: Router, addr: String) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("监听 {addr} 失败"))?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// H2：尝试占用一个连接许可；返回 None 表示已达上限，调用方应关闭 TCP。
fn try_acquire_connection(permits: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    permits.clone().try_acquire_owned().ok()
}

async fn serve_tls(
    app: Router,
    addr: String,
    config: Arc<rustls::ServerConfig>,
    max_connections: usize,
) -> Result<()> {
    let sock: SocketAddr = addr
        .parse()
        .with_context(|| format!("监听地址非法: {addr}"))?;
    let listener = TcpListener::bind(sock)
        .await
        .with_context(|| format!("监听 {sock} 失败"))?;
    let acceptor = TlsAcceptor::from(config);
    // H2：用信号量限制同时处理的 TLS 连接数；拿不到许可就立刻关 TCP。
    let max_connections = max_connections.max(1);
    let permits = Arc::new(Semaphore::new(max_connections));
    tracing::info!(%sock, max_connections, "agent 接入监听（mTLS）");

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // 单个 accept 失败（例如 fd 瞬时耗尽）不应让整个 hub 退出。
                tracing::warn!(error = %err, "accept 失败，100ms 后重试");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        let permit = match try_acquire_connection(&permits) {
            Some(permit) => permit,
            None => {
                // 连接数已满：不握手、不读请求，直接关闭 TCP，避免慢速连接堆积。
                tracing::warn!(%peer, max_connections, "agent 连接数已达上限，直接关闭 TCP");
                continue;
            }
        };

        if let Err(err) = tcp.set_nodelay(true) {
            tracing::debug!(%peer, error = %err, "设置 TCP_NODELAY 失败");
        }

        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            // 许可跟随整条连接生命周期（TLS 握手 + WebSocket 会话）。
            let _permit = permit;
            let stream =
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(err)) => {
                        tracing::debug!(%peer, error = %err, "TLS 握手失败");
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(%peer, "TLS 握手超时");
                        return;
                    }
                };

            // 证书链已在 TLS 握手阶段由 rustls 校验；这里只取 subject CN 做身份绑定。
            let cn = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(|der| tls::peer_common_name(der.as_ref()));
            let cn_display = cn.clone();
            let service = tower::service_fn(move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(PeerIdentity(cn.clone()));
                let app = app.clone();
                async move { app.oneshot(req.map(Body::new)).await }
            });

            // H2：HTTP/1 请求头 10s 内读不完直接断开（slowloris）。
            //
            // 这里刻意不用 hyper-util 的 auto builder：它在判断 HTTP 版本前有一个
            // 最多读 24 字节、**没有超时**的嗅探阶段，什么都不发的连接会永久占住
            // 一个 max_connections 许可（实测）。http1 Builder 没有该阶段，且
            // WebSocket 升级本来只需要 HTTP/1。
            if let Err(err) = hyper::server::conn::http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
                .with_upgrades()
                .await
            {
                tracing::debug!(%peer, cn = ?cn_display, error = %err, "agent 连接结束");
            }
        });
    }
}

async fn healthz() -> &'static str {
    "ok"
}

async fn list_agents(State(state): State<AppState>) -> Result<Json<Vec<AgentRecord>>, ApiError> {
    let agents = tokio::task::spawn_blocking({
        let storage = state.storage.clone();
        move || storage.list_agents()
    })
    .await
    .map_err(ApiError::from)??;
    Ok(Json(agents))
}

#[derive(serde::Deserialize)]
struct SeriesParams {
    agent: String,
    #[serde(default)]
    metric: Option<String>,
    from: i64,
    to: i64,
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_limit() -> u32 {
    5_000
}

async fn query_series(
    State(state): State<AppState>,
    Query(params): Query<SeriesParams>,
) -> Result<Json<Vec<SeriesRow>>, ApiError> {
    let query = SeriesQuery {
        agent_id: params.agent,
        metrics: params.metric.map(|m| vec![m]).unwrap_or_default(),
        from: params.from,
        to: params.to,
        limit: params.limit.min(50_000),
    };
    let rows = tokio::task::spawn_blocking({
        let storage = state.storage.clone();
        move || storage.query_series(&query)
    })
    .await
    .map_err(ApiError::from)??;
    Ok(Json(rows))
}

struct ApiError(anyhow::Error);

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError(err)
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(err: tokio::task::JoinError) -> Self {
        ApiError(err.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        tracing::error!(error = %self.0, "API 错误");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

async fn agent_ws(
    ws: WebSocketUpgrade,
    Extension(peer): Extension<PeerIdentity>,
    State(state): State<AppState>,
) -> axum::response::Response {
    // 会话级许可：TLS 层的 permit 在 HTTP 升级完成时就释放了，
    // 这里必须再占一个，否则 max_connections 对长连接完全不生效。
    let permit = match state.session_slots.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            tracing::warn!(
                max = state.cfg.max_connections,
                "agent 会话数已达上限，拒绝新连接"
            );
            return (StatusCode::SERVICE_UNAVAILABLE, "too many sessions").into_response();
        }
    };

    ws.max_message_size(MAX_WS_MESSAGE_SIZE)
        .max_frame_size(MAX_WS_FRAME_SIZE)
        .on_upgrade(move |socket| async move {
            let _permit = permit; // 持有到会话结束
            if let Err(err) = dispatch(socket, state, peer).await {
                tracing::warn!(error = %log_safe_error(&err), "agent 会话结束");
            }
        })
        .into_response()
}

/// 第一条帧决定这条连接是 enrollment 还是正常会话。
///
/// 身份规则（#1 #2）：
/// - 无客户端证书只允许 `Enroll`，`Hello` 一律拒绝；
/// - 有客户端证书不允许再 `Enroll`（避免用已纳管证书刷新 token）；
/// - `Hello` 的 agent_id 必须等于证书 CN，且永远不能是 `hub-self`。
async fn dispatch(mut socket: WebSocket, state: AppState, peer: PeerIdentity) -> Result<()> {
    let frame = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
        Err(_) => bail!("等待首帧超时"),
        Ok(None) => bail!("连接在首帧前关闭"),
        Ok(Some(Err(err))) => bail!(err),
        Ok(Some(Ok(Message::Binary(bytes)))) => Frame::decode(bytes.as_ref())?,
        Ok(Some(Ok(_))) => bail!("首帧必须是二进制帧"),
    };

    match frame {
        Frame::Enroll(req) => {
            if let Some(cn) = peer.0 {
                reject_and_close(
                    &mut socket,
                    codes::ENROLL_DENIED,
                    "已持有客户端证书的连接不允许 enrollment",
                )
                .await;
                bail!("带客户端证书的连接尝试 enrollment: CN={cn}");
            }
            handle_enroll(socket, state, req).await
        }
        Frame::Hello(hello) => {
            let Some(cn) = peer.0 else {
                reject_and_close(&mut socket, MTLS_REQUIRED, "正式会话必须使用客户端证书").await;
                bail!("无客户端证书的连接尝试建立正式会话");
            };
            if !is_valid_agent_id(&hello.agent_id) {
                reject_and_close(&mut socket, IDENTITY_MISMATCH, "agent_id 非法").await;
                bail!("agent_id 非法（长度或字符集）");
            }
            if !is_log_safe(&hello.hostname, 255) {
                reject_and_close(&mut socket, IDENTITY_MISMATCH, "hostname 非法").await;
                bail!("hostname 含控制字符或过长");
            }
            if hello.agent_id == HUB_SELF_AGENT_ID {
                reject_and_close(&mut socket, IDENTITY_MISMATCH, "网络侧不允许声明 hub-self").await;
                bail!("网络侧声明了内置采集身份 hub-self");
            }
            if cn != hello.agent_id {
                reject_and_close(
                    &mut socket,
                    IDENTITY_MISMATCH,
                    "客户端证书 CN 与 Hello 的 agent_id 不一致",
                )
                .await;
                bail!(
                    "证书 CN 与 Hello agent_id 不一致: cn={cn} agent_id={}",
                    hello.agent_id
                );
            }
            handle_session(socket, state, hello).await
        }
        _ => bail!("首帧必须是 Enroll 或 Hello"),
    }
}

/// 发送 Problem 后关闭 WebSocket；发送失败不影响连接关闭。
///
/// M4：Problem 与 Close 的写都受 15s 超时保护，避免半开连接把会话任务挂死。
async fn reject_and_close(socket: &mut WebSocket, code: &str, message: &str) {
    let _ = send_frame(socket, &problem(code, message)).await;
    let _ = send_with_timeout(socket, Message::Close(None)).await;
}

async fn handle_enroll(mut socket: WebSocket, state: AppState, req: EnrollRequest) -> Result<()> {
    if protocol_gate(req.protocol).is_some() {
        // H1：协议不匹配不发 Welcome / Enrolled，回 Problem 后立即关闭。
        reject_and_close(&mut socket, codes::BAD_PROTOCOL, "需要 agent ≥ 2").await;
        bail!(
            "enrollment 协议版本不匹配: 收到 {}，需要 {PROTOCOL_VERSION}",
            req.protocol
        );
    }

    // requested_name 可以为空（agent init 不传 --name 时就是空），hub 实际使用的是 token 名。
    if !is_log_safe(&req.hostname, 255) || !is_log_safe_optional(&req.requested_name, 128) {
        send_frame(
            &mut socket,
            &problem(codes::ENROLL_DENIED, "hostname 或 name 非法"),
        )
        .await?;
        bail!("enrollment 字段含控制字符或过长");
    }

    let now = now_ms();
    let Some(token_name) = state
        .storage
        .consume_enroll_token(&tls::sha256_hex(&req.token), now)?
    else {
        send_frame(
            &mut socket,
            &problem(codes::ENROLL_DENIED, "token 无效、已使用或已过期"),
        )
        .await?;
        bail!("enrollment token 无效");
    };

    let dir = tls::cert_dir(&state.cfg.data_dir);
    let ca_key = std::fs::read_to_string(dir.join(tls::CA_KEY_FILE)).context("读取 CA 私钥失败")?;
    let ca_pem =
        std::fs::read_to_string(dir.join(tls::CA_CERT_FILE)).context("读取 CA 证书失败")?;

    let agent_id = uuid::Uuid::new_v4().to_string();
    let cert_pem =
        tls::sign_client_csr(&ca_key, &req.csr_pem, &agent_id).context("签发客户端证书失败")?;

    let secret = new_secret();
    state
        .storage
        .set_agent_secret(&agent_id, &tls::sha256_hex(&secret), now)?;
    state.storage.upsert_agent(&AgentRecord {
        agent_id: agent_id.clone(),
        name: if token_name.is_empty() {
            req.hostname.clone()
        } else {
            token_name
        },
        hostname: req.hostname.clone(),
        os: String::new(),
        arch: String::new(),
        version: String::new(),
        boot_id: String::new(),
        status: "pending".to_string(),
        last_seen_at: now,
        created_at: now,
    })?;

    tracing::info!(agent = %agent_id, host = %req.hostname, "agent 已纳管");
    send_frame(
        &mut socket,
        &Frame::Enrolled(rustboard_common::wire::EnrollResponse {
            agent_id: agent_id.clone(),
            agent_secret: secret,
            cert_pem,
            ca_pem,
        }),
    )
    .await?;
    // 客户端拿到证书后会主动断开并重连，这里不做等待。
    Ok(())
}

async fn handle_session(
    mut socket: WebSocket,
    state: AppState,
    hello: rustboard_common::wire::AgentHello,
) -> Result<()> {
    let agent_id = hello.agent_id.clone();

    if protocol_gate(hello.protocol).is_some() {
        // H1：协议不匹配绝不能下发 Welcome，否则 agent 会以为握手成功。
        reject_and_close(&mut socket, codes::BAD_PROTOCOL, "需要 agent ≥ 2").await;
        bail!(
            "协议版本不匹配: 收到 {}，需要 {PROTOCOL_VERSION}",
            hello.protocol
        );
    }

    if state.storage.is_revoked(&agent_id)? {
        send_frame(&mut socket, &problem(codes::REVOKED, "该 agent 已被吊销")).await?;
        bail!("已吊销的 agent 尝试连接: {agent_id}");
    }

    if !state
        .storage
        .verify_agent_secret(&agent_id, &tls::sha256_hex(&hello.secret))?
    {
        send_frame(&mut socket, &problem(codes::BAD_TOKEN, "agent secret 无效")).await?;
        bail!("agent secret 校验失败: {agent_id}");
    }

    let now = now_ms();
    let existing = state.storage.get_agent(&agent_id)?;
    let name = if !hello.name.trim().is_empty() {
        hello.name.clone()
    } else if let Some(prev) = existing.as_ref() {
        if !prev.name.trim().is_empty() {
            prev.name.clone()
        } else {
            hello.hostname.clone()
        }
    } else {
        hello.hostname.clone()
    };

    let record = AgentRecord {
        agent_id: agent_id.clone(),
        name,
        hostname: hello.hostname.clone(),
        os: hello.os.clone(),
        arch: hello.arch.clone(),
        version: hello.version.clone(),
        boot_id: hello.boot_id.clone(),
        status: "online".to_string(),
        last_seen_at: now,
        created_at: existing.map(|a| a.created_at).unwrap_or(now),
    };

    // 从这里开始，所有退出路径（正常关闭 / recv 错误 / send 错误 / 心跳超时 /
    // 入库错误 / 任务失败）都由 `_cleanup` 的 Drop 统一执行状态清理。
    let handle = state.sessions.register(&agent_id);
    let _cleanup = SessionCleanup::new(
        state.storage.clone(),
        state.sessions.clone(),
        agent_id.clone(),
        handle.conn_id,
    );

    state.storage.upsert_agent(&record)?;
    // upsert_agent 会把状态写回 online；若吊销恰好发生在握手期间，立即恢复 revoked。
    if state.storage.is_revoked(&agent_id)? {
        state.storage.set_status(&agent_id, "revoked", now_ms())?;
        send_frame(&mut socket, &problem(codes::REVOKED, "该 agent 已被吊销")).await?;
        bail!("握手期间 agent 被吊销: {agent_id}");
    }
    tracing::info!(agent = %agent_id, host = %hello.hostname, "agent 已连接");

    let welcome = Frame::Welcome(Welcome {
        agent_id: agent_id.clone(),
        server_version: VERSION.to_string(),
        protocol: PROTOCOL_VERSION,
        sample_interval_ms: state.cfg.sample_interval_ms,
        server_time: now,
    });
    send_frame(&mut socket, &welcome).await?;

    let mut shutdown = handle.shutdown;
    let mut watch_shutdown = true;

    loop {
        // 45s 内收不到任何帧就认为连接已死；agent 每 15s 发一次 Ping。
        let recv = tokio::time::timeout(SESSION_IDLE_TIMEOUT, socket.recv());
        let event = tokio::select! {
            biased;
            changed = shutdown.changed(), if watch_shutdown => {
                // 唯一的发送值是 true；Err 只会在取消信号发送端被销毁时出现。
                match changed {
                    Ok(()) => SessionEvent::Shutdown,
                    Err(_) => SessionEvent::WatchClosed,
                }
            }
            received = recv => match received {
                Err(_) => SessionEvent::IdleTimeout,
                Ok(None) => SessionEvent::Closed,
                Ok(Some(Err(err))) => SessionEvent::RecvError(err.to_string()),
                Ok(Some(Ok(message))) => SessionEvent::Message(message),
            },
        };

        match event {
            SessionEvent::Shutdown => {
                tracing::info!(agent = %agent_id, "收到吊销通知，关闭会话");
                reject_and_close(&mut socket, codes::REVOKED, "该 agent 已被吊销").await;
                break;
            }
            SessionEvent::WatchClosed => {
                // 正常流程不会走到这里：注册表在会话循环期间一直持有发送端。
                tracing::debug!(agent = %agent_id, "会话取消信号已关闭，停止监听吊销");
                watch_shutdown = false;
            }
            SessionEvent::IdleTimeout => {
                tracing::warn!(
                    agent = %agent_id,
                    timeout_secs = SESSION_IDLE_TIMEOUT.as_secs(),
                    "会话心跳超时，主动关闭"
                );
                break;
            }
            SessionEvent::Closed => break,
            SessionEvent::RecvError(err) => {
                tracing::warn!(agent = %agent_id, error = %err, "接收失败，关闭会话");
                break;
            }
            SessionEvent::Message(message) => {
                match handle_message(&mut socket, &state, &agent_id, message).await? {
                    MessageAction::Continue => {}
                    MessageAction::Close => break,
                }
            }
        }
    }

    tracing::info!(agent = %agent_id, "agent 会话结束");
    Ok(())
}

/// `select!` 每轮只产出一个事件，避免在分支里同时借用 socket 与取消信号。
enum SessionEvent {
    Message(Message),
    Closed,
    RecvError(String),
    IdleTimeout,
    Shutdown,
    WatchClosed,
}

enum MessageAction {
    Continue,
    Close,
}

async fn handle_message(
    socket: &mut WebSocket,
    state: &AppState,
    agent_id: &str,
    message: Message,
) -> Result<MessageAction> {
    match message {
        Message::Binary(bytes) => {
            let frame = match Frame::decode(bytes.as_ref()) {
                Ok(frame) => frame,
                Err(err) => {
                    tracing::warn!(
                        agent = %agent_id,
                        error = %log_safe_error(&err),
                        "帧解码失败，跳过"
                    );
                    return Ok(MessageAction::Continue);
                }
            };
            match frame {
                Frame::Batch(batch) => {
                    // 先校验格式再比较：非法值（超长/控制字符）不能原样进日志。
                    if !is_valid_agent_id(&batch.agent_id) {
                        tracing::warn!(
                            session_agent = %agent_id,
                            batch_agent_len = batch.agent_id.len(),
                            "批次 agent_id 非法，拒绝且不 ACK"
                        );
                        reject_and_close(socket, IDENTITY_MISMATCH, "批次 agent_id 非法").await;
                        return Ok(MessageAction::Close);
                    }
                    // 批次身份一律以会话身份为准，不接受报文里的 agent_id。
                    if batch.agent_id != agent_id {
                        tracing::warn!(
                            session_agent = %agent_id,
                            batch_agent = %batch.agent_id,
                            "批次身份与会话身份不一致，拒绝且不 ACK"
                        );
                        reject_and_close(socket, IDENTITY_MISMATCH, "批次身份与会话身份不一致")
                            .await;
                        return Ok(MessageAction::Close);
                    }

                    let batch_for_db = batch.clone();
                    let storage = state.storage.clone();
                    let result =
                        tokio::task::spawn_blocking(move || storage.insert_batch(&batch_for_db))
                            .await?;
                    match result {
                        Ok(IngestOutcome::Inserted { inserted }) => {
                            mark_seen(state, agent_id);
                            tracing::debug!(
                                agent = %agent_id,
                                epoch = batch.epoch,
                                seq = batch.seq,
                                inserted,
                                "批次已入库"
                            );
                            send_frame(
                                socket,
                                &Frame::Ack {
                                    epoch: batch.epoch,
                                    seq: batch.seq,
                                },
                            )
                            .await?;
                        }
                        Ok(IngestOutcome::Duplicate) => {
                            mark_seen(state, agent_id);
                            tracing::debug!(
                                agent = %agent_id,
                                epoch = batch.epoch,
                                seq = batch.seq,
                                "重复批次，已忽略"
                            );
                            send_frame(
                                socket,
                                &Frame::Ack {
                                    epoch: batch.epoch,
                                    seq: batch.seq,
                                },
                            )
                            .await?;
                        }
                        Ok(IngestOutcome::Rejected(reason)) => {
                            // 吊销检查与写入在同一个事务里，命中即整批回滚：绝不 ACK。
                            tracing::warn!(agent = %agent_id, ?reason, "批次被拒绝，关闭会话");
                            reject_and_close(socket, codes::REVOKED, "该 agent 已被吊销").await;
                            return Ok(MessageAction::Close);
                        }
                        Err(err) => {
                            tracing::error!(agent = %agent_id, error = %err, "入库失败，关闭会话");
                            reject_and_close(socket, codes::INTERNAL, "入库失败").await;
                            return Ok(MessageAction::Close);
                        }
                    }
                }
                Frame::Ping { ts } => {
                    mark_seen(state, agent_id);
                    send_frame(socket, &Frame::Pong { ts }).await?;
                }
                Frame::Pong { .. } => {
                    mark_seen(state, agent_id);
                }
                other => {
                    // L6：只打变体名，Frame 的 Debug 也已脱敏；绝不打印 Hello/Enroll 内容。
                    tracing::debug!(agent = %agent_id, frame = other.kind(), "忽略未处理帧");
                }
            }
        }
        Message::Ping(payload) => {
            mark_seen(state, agent_id);
            send_with_timeout(socket, Message::Pong(payload)).await?;
        }
        Message::Pong(_) => {
            mark_seen(state, agent_id);
        }
        Message::Close(_) => return Ok(MessageAction::Close),
        Message::Text(_) => {}
    }
    Ok(MessageAction::Continue)
}

/// 刷新在线状态与 `last_seen_at`。
///
/// 只有能走到这里的会话才是注册表里的活跃连接（会话结束后的清理不会再处理帧），
/// 所以任意活跃连接刷新状态都是正确的；状态是否置 offline 由注册表决定。
fn mark_seen(state: &AppState, agent_id: &str) {
    if let Err(err) = state.storage.mark_seen(agent_id, now_ms()) {
        tracing::warn!(agent = %agent_id, error = %err, "刷新 last_seen_at 失败");
    }
}

/// 会话退出时的统一清理。
///
/// - 只有注册表里的当前连接才有资格改状态（旧连接不覆盖新连接）；
/// - 吊销状态优先级最高：检测到吊销时恢复为 `revoked`，否则置 `offline`。
struct SessionCleanup {
    storage: Arc<SqliteStorage>,
    sessions: Arc<SessionRegistry>,
    agent_id: String,
    conn_id: u64,
    finished: bool,
}

impl SessionCleanup {
    fn new(
        storage: Arc<SqliteStorage>,
        sessions: Arc<SessionRegistry>,
        agent_id: String,
        conn_id: u64,
    ) -> Self {
        Self {
            storage,
            sessions,
            agent_id,
            conn_id,
            finished: false,
        }
    }

    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;

        if !self.sessions.unregister(&self.agent_id, self.conn_id) {
            tracing::debug!(agent = %self.agent_id, conn_id = self.conn_id, "旧会话结束，不修改在线状态");
            return;
        }

        let revoked = match self.storage.is_revoked(&self.agent_id) {
            Ok(revoked) => revoked,
            Err(err) => {
                tracing::warn!(agent = %self.agent_id, error = %err, "清理时查询吊销状态失败");
                false
            }
        };
        if revoked {
            // revoked 优先级最高，任何清理都不能把它改回 offline / online。
            if let Err(err) = self.storage.set_status(&self.agent_id, "revoked", now_ms()) {
                tracing::warn!(agent = %self.agent_id, error = %err, "恢复 revoked 状态失败");
            }
            tracing::info!(agent = %self.agent_id, status = "revoked", "agent 状态已更新");
            return;
        }

        // 注销与重连的竞态：如果刚刚有新连接注册，不要把它覆盖成 offline。
        if self.sessions.has_active(&self.agent_id) {
            tracing::debug!(agent = %self.agent_id, "已有新连接接管，跳过 offline");
            return;
        }

        if let Err(err) = self.storage.set_status(&self.agent_id, "offline", now_ms()) {
            tracing::warn!(agent = %self.agent_id, error = %err, "更新 agent 状态失败");
            return;
        }
        tracing::info!(agent = %self.agent_id, status = "offline", "agent 状态已更新");
    }
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.finish();
    }
}

/// 每 2s 检查注册表中的 agent 是否已被吊销，命中后向会话发取消信号（#5）。
///
/// 存储层没有暴露「列出全部吊销记录」的只读接口，这里对活跃连接逐个查
/// `is_revoked`；活跃连接数通常很小，语义与全表扫描一致。
fn spawn_revoke_watcher(storage: Arc<SqliteStorage>, sessions: Arc<SessionRegistry>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(REVOKE_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let active = sessions.active_agents();
            if active.is_empty() {
                continue;
            }

            let storage = storage.clone();
            let result = tokio::task::spawn_blocking(move || {
                let mut revoked = Vec::new();
                for agent_id in active {
                    if storage.is_revoked(&agent_id)? {
                        revoked.push(agent_id);
                    }
                }
                Ok::<_, anyhow::Error>(revoked)
            })
            .await;

            match result {
                Ok(Ok(revoked)) if !revoked.is_empty() => {
                    tracing::info!(agents = ?revoked, "检测到吊销，关闭活跃会话");
                    sessions.shutdown_all(&revoked);
                }
                Ok(Ok(_)) => {}
                Ok(Err(err)) => tracing::warn!(error = %err, "吊销轮询失败"),
                Err(err) => tracing::warn!(error = %err, "吊销轮询任务失败"),
            }
        }
    });
}

/// H1：协议版本门禁。返回 `Some(Problem)` 表示必须拒绝；正常版本返回 `None`。
///
/// 单独抽出来便于单测固定错误码与文案，也确保调用点在 Welcome 之前。
fn protocol_gate(protocol: u16) -> Option<Frame> {
    (protocol != PROTOCOL_VERSION).then(|| problem(codes::BAD_PROTOCOL, "需要 agent ≥ 2"))
}

/// hub 自己生成的 agent_id 是 UUID；这里只接受安全字符集，避免日志注入与超长字段。
fn is_valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// 用于打日志的字段：限长且不允许控制字符（防换行伪造日志）。
fn is_log_safe(value: &str, max_len: usize) -> bool {
    !value.is_empty() && value.len() <= max_len && !value.chars().any(|c| c.is_control())
}

/// 错误串可能包含攻击者控制的 enum 变体名（serde 报错会回显），
/// 直接写日志会造成日志注入与放大：统一转义控制字符并截断。
const MAX_LOG_ERROR_LEN: usize = 128;

fn log_safe_error(err: &impl std::fmt::Display) -> String {
    let text = err.to_string();
    let mut out = String::with_capacity(MAX_LOG_ERROR_LEN);
    for ch in text.chars() {
        let ch = if ch.is_control() { '?' } else { ch };
        // 预留 3 字节给省略号，保证最终字节长度严格不超过上限
        if out.len() + ch.len_utf8() > MAX_LOG_ERROR_LEN - 3 {
            out.push('…');
            break;
        }
        out.push(ch);
    }
    out
}

/// 可选字段：允许为空，非空时同样要满足日志安全约束。
fn is_log_safe_optional(value: &str, max_len: usize) -> bool {
    value.is_empty() || is_log_safe(value, max_len)
}

fn problem(code: &str, message: &str) -> Frame {
    Frame::Problem {
        code: code.to_string(),
        message: message.to_string(),
    }
}

/// 带超时的底层发送：对端不读时最多阻塞 `timeout`，随后返回错误走统一清理。
async fn send_with_deadline<F, E>(send: F, timeout: Duration) -> Result<()>
where
    F: std::future::Future<Output = std::result::Result<(), E>>,
    E: std::error::Error + Send + Sync + 'static,
{
    match tokio::time::timeout(timeout, send).await {
        Ok(result) => {
            result.map_err(anyhow::Error::new)?;
            Ok(())
        }
        Err(_) => bail!("发送 WebSocket 帧超时（{}s）", timeout.as_secs()),
    }
}

/// M4：所有 WebSocket 写操作统一 15s 超时。
async fn send_with_timeout(socket: &mut WebSocket, message: Message) -> Result<()> {
    send_with_deadline(socket.send(message), SESSION_WRITE_TIMEOUT).await
}

async fn send_frame(socket: &mut WebSocket, frame: &Frame) -> Result<()> {
    let bytes = frame.encode()?;
    send_with_timeout(socket, Message::Binary(bytes.into())).await
}

/// hub 自身作为一台 agent 采集，直接写库，不经过网络。
fn spawn_self_monitor(storage: Arc<SqliteStorage>, cfg: HubConfig) {
    tokio::spawn(async move {
        let collectors = default_collectors(cfg.per_core, &cfg.excluded_interfaces);
        let agent_id = HUB_SELF_AGENT_ID.to_string();
        let epoch = now_ms() as u64;
        let boot = boot_id();
        let seq = AtomicU64::new(0);

        let record = AgentRecord {
            agent_id: agent_id.clone(),
            name: if cfg.name.is_empty() {
                hostname()
            } else {
                cfg.name.clone()
            },
            hostname: hostname(),
            os: os_pretty_name(),
            arch: arch(),
            version: VERSION.to_string(),
            boot_id: boot.clone(),
            status: "online".to_string(),
            last_seen_at: now_ms(),
            created_at: now_ms(),
        };
        if let Err(err) = storage.upsert_agent(&record) {
            tracing::error!(error = %err, "注册本机 agent 失败");
        }
        tracing::info!("本机采集已启用（agent_id = {HUB_SELF_AGENT_ID}）");

        loop {
            let ts = now_ms();
            let mut samples = Vec::new();
            for collector in &collectors {
                samples.extend(collector.collect(ts));
            }
            if !samples.is_empty() {
                let batch = SampleBatch {
                    agent_id: agent_id.clone(),
                    epoch,
                    seq: seq.fetch_add(1, Ordering::Relaxed),
                    boot_id: boot.clone(),
                    sent_at: ts,
                    samples,
                };
                let storage = storage.clone();
                match tokio::task::spawn_blocking(move || storage.insert_batch(&batch)).await {
                    Ok(Ok(IngestOutcome::Inserted { .. } | IngestOutcome::Duplicate)) => {}
                    Ok(Ok(IngestOutcome::Rejected(reason))) => {
                        tracing::warn!(?reason, "本机采集批次被拒绝");
                    }
                    Ok(Err(err)) => tracing::error!(error = %err, "本机采集入库失败"),
                    Err(err) => tracing::error!(error = %err, "本机采集任务失败"),
                }
            }
            tokio::time::sleep(Duration::from_millis(cfg.sample_interval_ms)).await;
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn decode_error_is_escaped_and_truncated() {
        let evil = format!(
            "unknown variant `evil\nINFO forged`, expected one of {}",
            "x".repeat(500)
        );
        let safe = super::log_safe_error(&evil);
        assert!(!safe.contains('\n'), "不能保留换行");
        assert!(safe.len() <= super::MAX_LOG_ERROR_LEN, "必须严格截断");
        let multi = super::log_safe_error(&"中".repeat(500));
        assert!(
            multi.len() <= super::MAX_LOG_ERROR_LEN,
            "多字节字符也必须严格不超限"
        );
    }

    use super::*;

    /// H1：旧协议必须收到 `bad_protocol` + 「需要 agent ≥ 2」，当前协议放行。
    #[test]
    fn h1_protocol_gate_rejects_mismatched_version() {
        for old in [0, 1, PROTOCOL_VERSION - 1] {
            match protocol_gate(old).expect("旧协议必须被拒绝") {
                Frame::Problem { code, message } => {
                    assert_eq!(code, codes::BAD_PROTOCOL);
                    assert_eq!(message, "需要 agent ≥ 2");
                }
                other => panic!("协议门禁返回了意外帧: {other:?}"),
            }
        }
        assert!(protocol_gate(PROTOCOL_VERSION).is_none());
    }

    /// M4：写操作永不完成时必须在超时后返回错误，不能把会话任务挂死。
    #[tokio::test]
    async fn m4_send_timeout_aborts_stuck_write() {
        let pending = std::future::pending::<std::result::Result<(), std::io::Error>>();
        let err = send_with_deadline(pending, Duration::from_millis(10))
            .await
            .expect_err("永不完成的写必须超时");
        assert!(err.to_string().contains("超时"), "错误信息: {err}");
    }

    /// H2：连接数达到上限后不再发放许可，释放一条后恢复。
    #[test]
    fn h2_connection_semaphore_caps_concurrency() {
        let permits = Arc::new(Semaphore::new(2));
        let first = try_acquire_connection(&permits).expect("第 1 条连接应放行");
        let second = try_acquire_connection(&permits).expect("第 2 条连接应放行");
        assert!(
            try_acquire_connection(&permits).is_none(),
            "第 3 条连接必须被拒绝"
        );

        drop(first);
        assert!(
            try_acquire_connection(&permits).is_some(),
            "释放许可后应允许新连接"
        );
        drop(second);
    }
}
