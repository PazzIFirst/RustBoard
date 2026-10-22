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
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use clap::{Parser, Subcommand};
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
use rustboard_core::storage::Storage;

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
}

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

        let tls_config = tls::server_config(&cfg.data_dir)?;
        let fingerprint = {
            let pem =
                std::fs::read_to_string(tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE))?;
            tls::fingerprint_of_pem(&pem)?
        };
        tracing::info!(fingerprint, "TLS 已启用");

        let state = AppState {
            storage: storage.clone(),
            cfg: Arc::new(cfg.clone()),
        };

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
            serve_tls(agent_app, agent_addr, tls_config),
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

async fn serve_tls(app: Router, addr: String, config: Arc<rustls::ServerConfig>) -> Result<()> {
    let sock: SocketAddr = addr
        .parse()
        .with_context(|| format!("监听地址非法: {addr}"))?;
    let config = axum_server::tls_rustls::RustlsConfig::from_config(config);
    axum_server::bind_rustls(sock, config)
        .serve(app.into_make_service())
        .await?;
    Ok(())
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

async fn agent_ws(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| async move {
        if let Err(err) = dispatch(socket, state).await {
            tracing::warn!(error = %err, "agent 会话结束");
        }
    })
}

/// 第一条帧决定这条连接是 enrollment 还是正常会话。
async fn dispatch(mut socket: WebSocket, state: AppState) -> Result<()> {
    let frame = match tokio::time::timeout(Duration::from_secs(10), socket.recv()).await {
        Err(_) => bail!("等待首帧超时"),
        Ok(None) => bail!("连接在首帧前关闭"),
        Ok(Some(Err(err))) => bail!(err),
        Ok(Some(Ok(Message::Binary(bytes)))) => Frame::decode(bytes.as_ref())?,
        Ok(Some(Ok(_))) => bail!("首帧必须是二进制帧"),
    };

    match frame {
        Frame::Enroll(req) => handle_enroll(socket, state, req).await,
        Frame::Hello(hello) => handle_session(socket, state, hello).await,
        _ => bail!("首帧必须是 Enroll 或 Hello"),
    }
}

async fn handle_enroll(mut socket: WebSocket, state: AppState, req: EnrollRequest) -> Result<()> {
    if req.protocol != PROTOCOL_VERSION {
        send_frame(&mut socket, &problem(codes::BAD_PROTOCOL, "协议版本不匹配")).await?;
        bail!("enrollment 协议版本不匹配: {}", req.protocol);
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
    if hello.protocol != PROTOCOL_VERSION {
        send_frame(&mut socket, &problem(codes::BAD_PROTOCOL, "协议版本不匹配")).await?;
        bail!("协议版本不匹配: {}", hello.protocol);
    }

    if state.storage.is_revoked(&hello.agent_id)? {
        send_frame(&mut socket, &problem(codes::REVOKED, "该 agent 已被吊销")).await?;
        bail!("已吊销的 agent 尝试连接: {}", hello.agent_id);
    }

    if !state
        .storage
        .verify_agent_secret(&hello.agent_id, &tls::sha256_hex(&hello.secret))?
    {
        send_frame(&mut socket, &problem(codes::BAD_TOKEN, "agent secret 无效")).await?;
        bail!("agent secret 校验失败: {}", hello.agent_id);
    }

    let now = now_ms();
    let existing = state.storage.get_agent(&hello.agent_id)?;
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
        agent_id: hello.agent_id.clone(),
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
    state.storage.upsert_agent(&record)?;
    tracing::info!(agent = %hello.agent_id, host = %hello.hostname, "agent 已连接");

    let welcome = Frame::Welcome(Welcome {
        agent_id: hello.agent_id.clone(),
        server_version: VERSION.to_string(),
        protocol: PROTOCOL_VERSION,
        sample_interval_ms: state.cfg.sample_interval_ms,
        server_time: now,
    });
    send_frame(&mut socket, &welcome).await?;

    loop {
        let message = match socket.recv().await {
            Some(Ok(m)) => m,
            Some(Err(err)) => return Err(err.into()),
            None => break,
        };

        match message {
            Message::Binary(bytes) => {
                let frame = match Frame::decode(bytes.as_ref()) {
                    Ok(f) => f,
                    Err(err) => {
                        tracing::warn!(agent = %hello.agent_id, error = %err, "帧解码失败，跳过");
                        continue;
                    }
                };
                match frame {
                    Frame::Batch(batch) => {
                        let batch_for_db = batch.clone();
                        let storage = state.storage.clone();
                        let result = tokio::task::spawn_blocking(move || {
                            storage.insert_batch(&batch_for_db)
                        })
                        .await?;
                        match result {
                            Ok(outcome) => {
                                tracing::debug!(
                                    agent = %hello.agent_id,
                                    seq = batch.seq,
                                    inserted = outcome.inserted,
                                    duplicate = outcome.duplicate,
                                    "批次已入库"
                                );
                                send_frame(&mut socket, &Frame::Ack { seq: batch.seq }).await?;
                            }
                            Err(err) => {
                                tracing::error!(error = %err, "入库失败");
                                send_frame(&mut socket, &problem(codes::INTERNAL, "入库失败"))
                                    .await?;
                            }
                        }
                    }
                    Frame::Ping { ts } => {
                        send_frame(&mut socket, &Frame::Pong { ts }).await?;
                    }
                    other => {
                        tracing::debug!(?other, "忽略未处理帧");
                    }
                }
            }
            Message::Ping(payload) => {
                socket.send(Message::Pong(payload)).await?;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    tracing::info!(agent = %hello.agent_id, "agent 已断开");
    state
        .storage
        .set_status(&hello.agent_id, "offline", now_ms())
        .ok();
    Ok(())
}

fn problem(code: &str, message: &str) -> Frame {
    Frame::Problem {
        code: code.to_string(),
        message: message.to_string(),
    }
}

async fn send_frame(socket: &mut WebSocket, frame: &Frame) -> Result<()> {
    let bytes = frame.encode()?;
    socket.send(Message::Binary(bytes.into())).await?;
    Ok(())
}

/// hub 自身作为一台 agent 采集，直接写库，不经过网络。
fn spawn_self_monitor(storage: Arc<SqliteStorage>, cfg: HubConfig) {
    tokio::spawn(async move {
        let collectors = default_collectors(cfg.per_core, &cfg.excluded_interfaces);
        let agent_id = "hub-self".to_string();
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
        tracing::info!("本机采集已启用（agent_id = hub-self）");

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
                let _ = tokio::task::spawn_blocking(move || storage.insert_batch(&batch)).await;
            }
            tokio::time::sleep(Duration::from_millis(cfg.sample_interval_ms)).await;
        }
    });
}
