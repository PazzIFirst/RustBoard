//! RustBoard 采集端。
//!
//! 首次启动：用一次性 token 完成 enrollment，拿到客户端证书与独立 secret；
//! 之后：采集 -> 本地磁盘缓冲 -> 按序上报，收到 Ack 才丢弃。

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use rustboard_common::config::AgentConfig;
use rustboard_common::fsutil;
use rustboard_common::model::SampleBatch;
use rustboard_common::tls;
use rustboard_common::util::{arch, boot_id, hostname, now_ms, os_pretty_name};
use rustboard_common::wire::{codes, AgentHello, EnrollRequest, Frame};
use rustboard_common::{DEFAULT_AGENT_CONFIG, PROTOCOL_VERSION, VERSION};
use rustboard_core::buffer::DiskBuffer;
use rustboard_core::collect::default_collectors;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

const AGENT_CERT: &str = "agent.crt";
const AGENT_KEY: &str = "agent.key";
const AGENT_SECRET: &str = "agent.secret";
const AGENT_CA: &str = "ca.crt";
const AGENT_ID: &str = "agent_id";

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
type WsError = tokio_tungstenite::tungstenite::Error;

/// 等待 hub 下发 `CertRenewed` 的上限；超时只影响续签，不影响会话。
const CERT_RENEW_TIMEOUT: Duration = Duration::from_secs(20);

/// 采样间隔分片休眠的单片上限。每片之后重新读取共享间隔，
/// 保证 Welcome 下发新值后最多 1s 就会被采集循环看到。
const SAMPLE_INTERVAL_SLICE: Duration = Duration::from_secs(1);

/// Welcome 下发的采样间隔合法范围，与 hub `settings` 接口保持一致。
/// 0、过小（忙采）或过大（形同停采）的值一律不写入共享状态。
const MIN_SAMPLE_INTERVAL_MS: u64 = 1_000;
const MAX_SAMPLE_INTERVAL_MS: u64 = 300_000;

/// H1：hub 明确拒绝协议版本。重试不会自愈，必须退出让运维升级。
#[derive(Debug)]
struct BadProtocolError {
    detail: String,
}

impl fmt::Display for BadProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hub 拒绝协议版本：{}；本机 agent 协议为 {PROTOCOL_VERSION}，请升级 rustboard-agent",
            self.detail
        )
    }
}

impl std::error::Error for BadProtocolError {}

fn bad_protocol_error(message: &str) -> anyhow::Error {
    anyhow::Error::new(BadProtocolError {
        detail: message.to_string(),
    })
}

/// 判断错误是否属于「协议不兼容」这类不可重试错误。
fn is_fatal_protocol_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<BadProtocolError>().is_some()
}

/// hub 明确拒绝且重试无意义（已吊销、secret 失效）。继续重连只会刷日志。
#[derive(Debug)]
struct FatalRejection {
    detail: String,
}

impl fmt::Display for FatalRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hub 拒绝连接且不可重试：{}", self.detail)
    }
}

impl std::error::Error for FatalRejection {}

fn fatal_rejection_error(message: &str) -> anyhow::Error {
    anyhow::Error::new(FatalRejection {
        detail: message.to_string(),
    })
}

fn is_fatal_error(err: &anyhow::Error) -> bool {
    is_fatal_protocol_error(err) || err.downcast_ref::<FatalRejection>().is_some()
}

/// 这些 Problem 码重试不会自愈。
fn problem_is_fatal(code: &str) -> bool {
    matches!(
        code,
        codes::REVOKED | codes::BAD_TOKEN | codes::BAD_PROTOCOL
    )
}

#[derive(Parser)]
#[command(name = "rustboard-agent", version, about = "RustBoard 采集端")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 启动采集。
    Run {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 生成默认配置。
    /// 查看纳管状态、hub 地址与本地数据目录。
    Info {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 查看客户端证书的 CN / 有效期 / 剩余天数（缺证书或已过期时非零退出）。
    CertInfo {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 连上 hub 做一次客户端证书轮换后退出（运维手段）。
    Renew {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    Init {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        hub: Option<String>,
        #[arg(long)]
        token: Option<String>,
        /// hub 服务端证书的 SHA-256 指纹，由 `rustboard-hub init` 输出。
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rustboard_agent=info".into());
    tracing_subscriber::fmt().with_env_filter(filter).init();

    match Cli::parse().cmd {
        Cmd::Info { config } => {
            let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_CONFIG));
            let cfg = AgentConfig::load(&path).with_context(|| {
                format!(
                    "读取配置失败: {}（先执行 rustboard-agent init）",
                    path.display()
                )
            })?;
            let agent_id = std::fs::read_to_string(cfg.data_dir.join(AGENT_ID))
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "未纳管".to_string());
            let enrolled = is_enrolled(&cfg);
            println!("配置文件: {}", path.display());
            println!("hub: {}", cfg.hub_url);
            println!("agent_id: {agent_id}");
            println!("纳管状态: {}", if enrolled { "已纳管" } else { "未纳管" });
            println!("采样间隔: {}ms", cfg.sample_interval_ms);
            println!("数据目录: {}", cfg.data_dir.display());
            Ok(())
        }
        Cmd::Init {
            config,
            hub,
            token,
            fingerprint,
            name,
            data_dir,
            force,
        } => {
            let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_CONFIG));
            if path.exists() && !force {
                bail!("{} 已存在，使用 --force 覆盖", path.display());
            }
            let mut cfg = AgentConfig::default();
            if let Some(h) = hub {
                cfg.hub_url = h;
            }
            if let Some(t) = token {
                cfg.token = t;
            }
            if let Some(f) = fingerprint {
                cfg.server_fingerprint = f;
            }
            if let Some(n) = name {
                cfg.name = n;
            }
            if let Some(d) = data_dir {
                cfg.data_dir = d;
            }
            cfg.save(&path)?;
            println!("已写入配置: {}", path.display());
            println!("hub 地址: {}", cfg.hub_url);
            if cfg.hub_url.starts_with("wss://") && cfg.server_fingerprint.is_empty() {
                println!("警告: wss:// 连接缺少 --fingerprint，启动时会失败");
            }
            println!("\n下一步: rustboard-agent run --config {}", path.display());
            Ok(())
        }
        Cmd::Run { config } => {
            let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_CONFIG));
            let cfg = AgentConfig::load(&path).with_context(|| {
                format!(
                    "读取配置失败: {}（先执行 rustboard-agent init）",
                    path.display()
                )
            })?;
            cfg.validate()?;
            run(cfg)
        }
        Cmd::CertInfo { config } => cert_info(config),
        Cmd::Renew { config } => renew(config),
    }
}

fn run(cfg: AgentConfig) -> Result<()> {
    // config.rs 只校验下界；这里补上限，避免本地配置本身就忙采/形同停采。
    validate_sample_interval_config(cfg.sample_interval_ms)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move { run_async(cfg).await })
}

async fn run_async(cfg: AgentConfig) -> Result<()> {
    fsutil::ensure_dir(&cfg.data_dir, 0o700)?;

    // 没纳管过就先走 enrollment；拿到证书后再开始采集，避免用临时 agent_id 产生脏数据。
    if !is_enrolled(&cfg) {
        tracing::info!("尚未纳管，开始 enrollment");
        ensure_enrolled(&cfg).await?;
    }

    let agent_id = load_or_create_agent_id(&cfg.data_dir)?;
    let boot = boot_id();
    let epoch = now_ms() as u64;
    // 会话最长存活时间的抖动种子：启动时刻派生，进程生命周期内固定。
    let jitter_seed_ms = now_ms();
    tracing::info!(%agent_id, epoch, "采集端启动");

    let collectors = Arc::new(default_collectors(cfg.per_core, &cfg.excluded_interfaces));
    let buffer = Arc::new(Mutex::new(DiskBuffer::open(
        &cfg.data_dir,
        cfg.buffer_max_bytes,
        cfg.buffer_max_age_hours.saturating_mul(3_600_000),
    )?));
    let seq = Arc::new(AtomicU64::new(0));
    // 采集间隔由 Welcome 动态下发；采集循环每轮读取当前值。
    let sample_interval = Arc::new(AtomicU64::new(cfg.sample_interval_ms.max(1)));
    // 采集器写入后立刻唤醒上传循环，避免空缓冲时只能等心跳
    let notify = Arc::new(tokio::sync::Notify::new());

    // 采集任务
    {
        let collectors = collectors.clone();
        let buffer = buffer.clone();
        let seq = seq.clone();
        let agent_id = agent_id.clone();
        let boot = boot.clone();
        let interval = sample_interval.clone();
        let notify = notify.clone();
        tokio::spawn(async move {
            loop {
                // 首轮立即采集，之后按「当前」间隔休眠（首轮不等待）。
                let ts = now_ms();
                let mut samples = Vec::new();
                for collector in collectors.iter() {
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
                    let mut guard = buffer.lock().await;
                    match guard.push(&batch) {
                        Ok(()) => notify.notify_one(),
                        Err(err) => tracing::warn!(error = %err, "写入本地缓冲失败"),
                    }
                }

                // 若本轮采集为空也照样休眠，避免空样本时忙等。
                // 分片休眠，每片最多 `SAMPLE_INTERVAL_SLICE`；Welcome 更新间隔后
                // 下一片就会按新值重新计时，不会睡满旧的 300s 周期。
                let interval_ms = interval.load(Ordering::Relaxed).max(1);
                sleep_sample_interval(&interval, interval_ms, SAMPLE_INTERVAL_SLICE).await;
            }
        });
    }

    // 上传任务（主循环，断线指数退避重连）
    let session_ctx = SessionContext {
        cfg: &cfg,
        agent_id: &agent_id,
        epoch,
        boot: &boot,
        jitter_seed_ms,
        sample_interval: &sample_interval,
    };
    let mut backoff_secs = 1u64;
    loop {
        match connect(&cfg, true).await {
            Ok(ws) => {
                backoff_secs = 1;
                tracing::info!(url = %cfg.hub_url, "已连接 hub");
                let session_result =
                    run_session_with_deadline(ws, &session_ctx, &buffer, &notify).await;
                if let Err(err) = session_result {
                    if is_fatal_error(&err) {
                        // H1：协议不兼容 / 已吊销 / secret 失效，重连都不会自愈。
                        tracing::error!(error = %err, "hub 拒绝且不可重试，停止重连");
                        return Err(err);
                    }
                    tracing::warn!(error = %err, "会话中断");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => {
                tracing::warn!(error = %err, retry_in = backoff_secs, "连接 hub 失败");
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }
}

/// 一次运行周期内的会话上下文（身份 + 启动标识 + 抖动种子）。
///
/// 打包成一个结构体是为了让 `session` / `run_session_with_deadline` 的参数保持可读，
/// 也避免把「本进程固定的值」反复当参数传递。
struct SessionContext<'a> {
    cfg: &'a AgentConfig,
    agent_id: &'a str,
    epoch: u64,
    boot: &'a str,
    jitter_seed_ms: i64,
    /// 当前采集间隔；Welcome 下发后由会话更新，采集任务每轮读取。
    sample_interval: &'a Arc<AtomicU64>,
}

/// 会话最长存活时间（含 ±10% 抖动）；`0` 表示不主动重连（返回 `None`）。
///
/// 抖动值由启动时刻的毫秒数派生（`seed_ms`），不引入 rand 依赖、也没有额外状态；
/// 目的只是让同一批部署、同一时刻启动的 agent 不会永远在同一秒重连。
fn session_deadline(hours: u64, seed_ms: i64) -> Option<Duration> {
    if hours == 0 {
        return None;
    }
    let base_secs = hours.saturating_mul(3_600);
    // ±10% 窗口；跨度取 base/10，种子取模得到 [-span, +span] 的偏移。
    let span = (base_secs / 10).max(1) as i64;
    let range = (2 * span + 1) as u64;
    let offset = (seed_ms.unsigned_abs() % range) as i64 - span;
    Some(Duration::from_secs(base_secs.saturating_add_signed(offset)))
}

/// 会话内周期证书检查的退避：续签失败后至少隔这么久再试，避免每个 tick 重试。
const CERT_RENEW_RETRY_MS: i64 = 60 * 60 * 1000;

/// 会话内证书检查周期（秒）。配置层已限制 1–168 小时，这里再 max(1) 防御坏配置。
fn cert_check_period(hours: u64) -> Duration {
    Duration::from_secs(hours.max(1).saturating_mul(3_600))
}

/// 本轮周期检查是否应触发续签（纯函数，便于边界测试）。
///
/// - `days_left > threshold`：还没进入续签窗口，不触发；
/// - `last_attempt_ms <= 0`：本会话尚未尝试过，首次到点即触发；
/// - 距离上次尝试不足 [`CERT_RENEW_RETRY_MS`]：跳过，避免失败后忙重试。
fn cert_check_due(days_left: i64, threshold: i64, now_ms: i64, last_attempt_ms: i64) -> bool {
    if days_left > threshold {
        return false;
    }
    if last_attempt_ms <= 0 {
        return true;
    }
    now_ms.saturating_sub(last_attempt_ms) >= CERT_RENEW_RETRY_MS
}

/// 读取本地客户端证书剩余天数。
fn client_cert_days_left(cfg: &AgentConfig) -> Result<i64> {
    let cert_path = cfg.data_dir.join(AGENT_CERT);
    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("读取客户端证书失败: {}", cert_path.display()))?;
    tls::days_left(&cert_pem, now_ms())
}

/// 按 `session_max_hours` 给会话加一个最长存活时间。
///
/// 到点主动断开重连：让轮换后的客户端证书、hub 侧配置变更有机会生效。
async fn run_session_with_deadline(
    ws: WsStream,
    ctx: &SessionContext<'_>,
    buffer: &Arc<Mutex<DiskBuffer>>,
    notify: &Arc<tokio::sync::Notify>,
) -> Result<()> {
    let Some(max_lifetime) = session_deadline(ctx.cfg.session_max_hours, ctx.jitter_seed_ms) else {
        return session(ws, ctx, buffer, notify).await;
    };
    match tokio::time::timeout(max_lifetime, session(ws, ctx, buffer, notify)).await {
        Ok(result) => result,
        Err(_) => {
            tracing::info!(
                hours = ctx.cfg.session_max_hours,
                deadline_secs = max_lifetime.as_secs(),
                "会话达到最长存活时间，主动断开重连"
            );
            Ok(())
        }
    }
}

fn is_enrolled(cfg: &AgentConfig) -> bool {
    cfg.data_dir.join(AGENT_CERT).exists()
        && cfg.data_dir.join(AGENT_KEY).exists()
        && cfg.data_dir.join(AGENT_SECRET).exists()
}

async fn connect(cfg: &AgentConfig, with_client_cert: bool) -> Result<WsStream> {
    let connector = if cfg.hub_url.starts_with("wss://") {
        let config = if with_client_cert {
            // M3：老的 agent.key 可能是 0644，读取前先收紧到 0600。
            let key_path = cfg.data_dir.join(AGENT_KEY);
            fsutil::harden(&key_path, 0o600)
                .with_context(|| format!("收紧私钥权限失败: {}", key_path.display()))?;
            let cert_pem = std::fs::read_to_string(cfg.data_dir.join(AGENT_CERT))
                .context("读取客户端证书失败，可能需要重新纳管")?;
            let key_pem = std::fs::read_to_string(&key_path)
                .context("读取客户端私钥失败，可能需要重新纳管")?;

            // A4：已纳管连接改用「CA 信任 + 主机名校验」，服务端证书轮换后无需重新纳管。
            //
            // 降级策略：只有「读不到 ca.crt」才回退指纹钉扎（兼容 v0.1 安装）；
            // ca.crt 存在但内容非法时 client_config_ca 会返回错误并向上抛，
            // 不允许静默降级到钉扎——那会把一个明确的配置错误变成安全隐患。
            let ca_path = cfg.data_dir.join(AGENT_CA);
            match std::fs::read_to_string(&ca_path) {
                Ok(ca_pem) => tls::client_config_ca(&ca_pem, &cert_pem, &key_pem)?,
                Err(err) => {
                    // 兼容没有 ca.crt 的 v0.1 安装：退回指纹钉扎，但必须告警，
                    // 因为一旦 hub 轮换服务端证书，这条连接就会失效。
                    tracing::warn!(
                        path = %ca_path.display(),
                        error = %err,
                        "读取 CA 证书失败，回退服务端证书指纹钉扎（hub 轮换证书后将无法连接）"
                    );
                    tls::client_config_pinned(
                        &cfg.server_fingerprint,
                        Some(&cert_pem),
                        Some(&key_pem),
                    )?
                }
            }
        } else {
            // bootstrap：还没有客户端证书，只能用安装命令带外分发的指纹。
            tls::client_config_pinned(&cfg.server_fingerprint, None, None)?
        };
        Some(tokio_tungstenite::Connector::Rustls(config))
    } else {
        None
    };

    let (ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
        cfg.hub_url.as_str(),
        None,
        false,
        connector,
    )
    .await?;
    Ok(ws)
}

enum EnrollError {
    Fatal(anyhow::Error),
    Retry(anyhow::Error),
}

async fn ensure_enrolled(cfg: &AgentConfig) -> Result<()> {
    let mut backoff = 1u64;
    loop {
        match try_enroll(cfg).await {
            Ok(()) => return Ok(()),
            Err(EnrollError::Fatal(err)) => {
                if is_fatal_protocol_error(&err) {
                    tracing::error!(
                        error = %err,
                        "协议版本不兼容，停止 enrollment 重试；请升级 rustboard-agent"
                    );
                }
                return Err(err);
            }
            Err(EnrollError::Retry(err)) => {
                tracing::warn!(error = %err, retry_in = backoff, "纳管失败，稍后重试");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        }
    }
}

async fn try_enroll(cfg: &AgentConfig) -> std::result::Result<(), EnrollError> {
    let ws = connect(cfg, false).await.map_err(EnrollError::Retry)?;
    let (mut sink, mut stream) = ws.split();

    let (csr_pem, key_pem) = tls::make_csr().map_err(EnrollError::Fatal)?;
    let request = Frame::Enroll(EnrollRequest {
        token: cfg.token.clone(),
        csr_pem,
        requested_name: cfg.name.clone(),
        hostname: hostname(),
        protocol: PROTOCOL_VERSION,
    });
    sink.send(Message::Binary(
        request.encode().map_err(|e| EnrollError::Fatal(e.into()))?,
    ))
    .await
    .map_err(|e| EnrollError::Retry(e.into()))?;

    let frame = tokio::time::timeout(Duration::from_secs(20), recv_frame(&mut stream))
        .await
        .map_err(|_| EnrollError::Retry(anyhow!("等待纳管应答超时")))?
        .map_err(EnrollError::Retry)?;

    match frame {
        Frame::Enrolled(resp) => {
            // 证书是公开材料；私钥与 agent secret 从创建起就是 0600。
            fsutil::atomic_write(
                &cfg.data_dir.join(AGENT_CERT),
                resp.cert_pem.as_bytes(),
                0o644,
            )
            .map_err(|e| EnrollError::Fatal(e.into()))?;
            fsutil::atomic_write(&cfg.data_dir.join(AGENT_KEY), key_pem.as_bytes(), 0o600)
                .map_err(|e| EnrollError::Fatal(e.into()))?;
            fsutil::atomic_write(
                &cfg.data_dir.join(AGENT_SECRET),
                resp.agent_secret.as_bytes(),
                0o600,
            )
            .map_err(|e| EnrollError::Fatal(e.into()))?;
            fsutil::atomic_write(&cfg.data_dir.join(AGENT_CA), resp.ca_pem.as_bytes(), 0o644)
                .map_err(|e| EnrollError::Fatal(anyhow!("写入 CA 证书失败: {e}")))?;
            fsutil::atomic_write(
                &cfg.data_dir.join(AGENT_ID),
                resp.agent_id.as_bytes(),
                0o644,
            )
            .map_err(|e| EnrollError::Fatal(anyhow!("写入 agent_id 失败: {e}")))?;
            tracing::info!(agent = %resp.agent_id, "纳管成功");
            Ok(())
        }
        Frame::Problem { code, message } if code == codes::BAD_PROTOCOL => {
            Err(EnrollError::Fatal(bad_protocol_error(&message)))
        }
        Frame::Problem { code, message } => Err(EnrollError::Fatal(anyhow!(
            "纳管被拒绝: {code} {message}（token 可能已过期，请重新生成）"
        ))),
        _ => Err(EnrollError::Retry(anyhow!("意外的纳管应答"))),
    }
}

/// 发送 Hello 并等待 Welcome，返回 hub 下发的采样间隔。
///
/// 抽出来是为了让常驻会话与 `renew` 子命令走完全相同的握手与错误分类
/// （bad_protocol 立即可判死、revoked/bad_token 不可重试、其他 Problem 可重试）。
async fn handshake<Si, St>(
    sink: &mut Si,
    stream: &mut St,
    cfg: &AgentConfig,
    agent_id: &str,
    epoch: u64,
    boot: &str,
) -> Result<u64>
where
    Si: Sink<Message, Error = WsError> + Unpin,
    St: Stream<Item = std::result::Result<Message, WsError>> + Unpin,
{
    let secret_path = cfg.data_dir.join(AGENT_SECRET);
    // M3：agent.secret 是长期凭据，读取前收紧既有文件权限。
    fsutil::harden(&secret_path, 0o600)
        .with_context(|| format!("收紧 agent secret 权限失败: {}", secret_path.display()))?;
    let secret = std::fs::read_to_string(&secret_path)
        .context("读取 agent secret 失败，可能需要重新纳管")?
        .trim()
        .to_string();

    let hello = Frame::Hello(AgentHello {
        agent_id: agent_id.to_string(),
        name: cfg.name.clone(),
        hostname: hostname(),
        os: os_pretty_name(),
        arch: arch(),
        version: VERSION.to_string(),
        protocol: PROTOCOL_VERSION,
        boot_id: boot.to_string(),
        epoch,
        secret,
        capabilities: Vec::new(),
    });
    sink.send(Message::Binary(hello.encode()?)).await?;

    match tokio::time::timeout(Duration::from_secs(10), recv_frame(stream)).await {
        Err(_) => bail!("等待 Welcome 超时"),
        Ok(Err(err)) => bail!("等待 Welcome 失败: {err}"),
        Ok(Ok(Frame::Welcome(w))) => {
            if w.protocol != PROTOCOL_VERSION {
                // 服务端回了一个不同版本的 Welcome：同样不可重试。
                return Err(bad_protocol_error(&format!(
                    "Welcome 声明的协议为 {}，本机为 {PROTOCOL_VERSION}",
                    w.protocol
                )));
            }
            // 间隔合法性统一在 `apply_sample_interval` 校验：非法值只告警并沿用
            // 当前间隔，不因此丢弃一条已经建立的有效会话。
            tracing::info!(
                server = %w.server_version,
                sample_interval_ms = w.sample_interval_ms,
                "握手完成"
            );
            Ok(w.sample_interval_ms)
        }
        Ok(Ok(Frame::Problem { code, message })) if code == codes::BAD_PROTOCOL => {
            // H1：正式会话阶段被拒也必须退出，不能回主循环每秒重连。
            Err(bad_protocol_error(&message))
        }
        Ok(Ok(Frame::Problem { code, message })) if problem_is_fatal(&code) => {
            Err(fatal_rejection_error(&format!("{code}: {message}")))
        }
        Ok(Ok(Frame::Problem { code, message })) => bail!("hub 拒绝连接: {code} {message}"),
        Ok(Ok(_)) => bail!("首帧不是 Welcome"),
    }
}

/// 分片休眠：每片最多 `slice`，每片前重新读取共享间隔。
///
/// `initial_ms` 是本轮开始时的间隔；若休眠期间 Welcome 写入了新值，则按新值
/// 重新计算目标时间（从本轮开始计时）。已经等够新间隔时立即返回，因此
/// 300s → 10s 的调整最多延迟一个分片（生产环境 1s），不会睡满 300s。
///
/// 返回实际等待的时长。
async fn sleep_sample_interval(interval: &AtomicU64, initial_ms: u64, slice: Duration) -> Duration {
    let start = tokio::time::Instant::now();
    let mut target_ms = initial_ms.max(1);
    loop {
        let current_ms = interval.load(Ordering::Relaxed).max(1);
        if current_ms != target_ms {
            tracing::debug!(
                from_ms = target_ms,
                to_ms = current_ms,
                "采集间隔已变更，按新值重新计时"
            );
            target_ms = current_ms;
        }
        let elapsed = start.elapsed();
        let Some(chunk) = interval_sleep_chunk(target_ms, elapsed, slice) else {
            return elapsed;
        };
        tokio::time::sleep(chunk).await;
    }
}

/// 计算下一次分片休眠的时长；已等够目标间隔时返回 `None`。
///
/// 拆成纯函数便于直接验证「旧间隔 120s、新间隔 10s」的边界：
/// 剩余时间会被 `slice` 截断，绝不会再睡满旧的 120s。
fn interval_sleep_chunk(target_ms: u64, elapsed: Duration, slice: Duration) -> Option<Duration> {
    let target = Duration::from_millis(target_ms.max(1));
    if elapsed >= target {
        return None;
    }
    Some((target - elapsed).min(slice))
}

/// 校验本地配置的采样间隔；`config.rs` 只保留下界，上限由 agent 侧兜住。
fn validate_sample_interval_config(ms: u64) -> Result<()> {
    if !(MIN_SAMPLE_INTERVAL_MS..=MAX_SAMPLE_INTERVAL_MS).contains(&ms) {
        bail!(
            "sample_interval_ms 必须在 {MIN_SAMPLE_INTERVAL_MS}–{MAX_SAMPLE_INTERVAL_MS}ms 之间，\
             实际 {ms}ms"
        );
    }
    Ok(())
}

/// 应用 Welcome 下发的采样间隔：只接受 1s–300s，其余拒绝且不覆盖当前值。
///
/// e2e 依赖 `采样间隔已更新 ms=...` 这一行，因此日志文本保持稳定。
fn apply_sample_interval(interval: &AtomicU64, ms: u64) -> Result<()> {
    if !(MIN_SAMPLE_INTERVAL_MS..=MAX_SAMPLE_INTERVAL_MS).contains(&ms) {
        bail!(
            "hub 下发了非法的采样间隔（{ms}ms，允许 \
             {MIN_SAMPLE_INTERVAL_MS}–{MAX_SAMPLE_INTERVAL_MS}ms）"
        );
    }
    interval.store(ms, Ordering::Relaxed);
    tracing::info!("采样间隔已更新 ms={ms}");
    Ok(())
}

/// 在已认证会话内换一张新的客户端证书。
///
/// 只在剩余寿命 ≤ `cert_renew_before_days` 时发起；失败由调用方 warn，
/// 不影响本次会话（证书通常仍有 ≥ 阈值的天数可用）。
async fn maybe_renew_client_cert<Si, St>(
    sink: &mut Si,
    stream: &mut St,
    cfg: &AgentConfig,
    agent_id: &str,
) -> Result<()>
where
    Si: Sink<Message, Error = WsError> + Unpin,
    St: Stream<Item = std::result::Result<Message, WsError>> + Unpin,
{
    let cert_path = cfg.data_dir.join(AGENT_CERT);
    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("读取客户端证书失败: {}", cert_path.display()))?;
    let days_left = tls::days_left(&cert_pem, now_ms())?;
    let threshold = i64::from(cfg.cert_renew_before_days);
    if days_left > threshold {
        tracing::debug!(days_left, threshold, "客户端证书剩余寿命充足，跳过续签");
        return Ok(());
    }
    tracing::info!(days_left, threshold, "客户端证书接近到期，开始续签");
    renew_client_cert(sink, stream, cfg, agent_id).await
}

/// 校验 hub 返回的新证书，确认它可以真的用来连接。
///
/// 五项检查（任一不满足都不覆盖旧证书）：
/// 1. 可解析；
/// 2. 未过期；
/// 3. CN == 本机 agent_id；
/// 4. SPKI 与本地 agent.key 配套；
/// 5. 由本地 `ca.crt` 签发（`ca.crt` 不存在时降级为告警：兼容尚未落盘 CA 的旧安装）。
fn validate_renewed_cert(cfg: &AgentConfig, agent_id: &str, cert_pem: &str) -> Result<()> {
    let summary = tls::cert_summary(cert_pem).context("hub 返回的证书无法解析")?;
    let now = now_ms();

    if summary.not_after.saturating_mul(1_000) <= now {
        bail!(
            "hub 返回的客户端证书已过期（notAfter={}）",
            tls::format_unix_utc(summary.not_after)
        );
    }
    if summary.common_name.as_deref() != Some(agent_id) {
        bail!(
            "hub 返回的证书 CN（{}）与本机 agent_id 不一致",
            summary.common_name.as_deref().unwrap_or("(无)")
        );
    }

    let key_path = cfg.data_dir.join(AGENT_KEY);
    fsutil::harden(&key_path, 0o600)
        .with_context(|| format!("收紧私钥权限失败: {}", key_path.display()))?;
    let key_pem =
        std::fs::read_to_string(&key_path).context("读取客户端私钥失败，可能需要重新纳管")?;
    if !tls::cert_matches_key(cert_pem, &key_pem).context("校验新证书与本地私钥失败")? {
        bail!("hub 返回的证书与本机私钥不配套");
    }

    let ca_path = cfg.data_dir.join(AGENT_CA);
    match std::fs::read_to_string(&ca_path) {
        Ok(ca_pem) => {
            // CA 文件存在但内容非法/验签失败属于明确错误，绝不静默接受。
            if !tls::cert_issued_by_ca(cert_pem, &ca_pem, now).context("校验新证书签发者失败")?
            {
                bail!("hub 返回的证书不是由本地 {} 签发", ca_path.display());
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // v0.1 安装没有 ca.crt：允许续签（否则升级路径无法轮换），但必须告警。
            tracing::warn!(
                path = %ca_path.display(),
                "缺少 ca.crt，跳过「签发者校验」（建议重新纳管以启用 CA 信任）"
            );
        }
        Err(err) => {
            return Err(err).with_context(|| format!("读取 CA 证书失败: {}", ca_path.display()))
        }
    }
    Ok(())
}

/// 用当前私钥生成 CSR，向 hub 申请新证书并原子落盘。
///
/// - 复用私钥：hub 全程不接触私钥，新旧证书对应同一把 key；
/// - 20s 内必须收到 `CertRenewed`，等待期间照常回 Ping（否则会被 hub 判心跳超时）；
/// - 落盘前用 [`validate_renewed_cert`] 做五项校验，任何一项不满足都保留旧证书。
async fn renew_client_cert<Si, St>(
    sink: &mut Si,
    stream: &mut St,
    cfg: &AgentConfig,
    agent_id: &str,
) -> Result<()>
where
    Si: Sink<Message, Error = WsError> + Unpin,
    St: Stream<Item = std::result::Result<Message, WsError>> + Unpin,
{
    let key_path = cfg.data_dir.join(AGENT_KEY);
    fsutil::harden(&key_path, 0o600)
        .with_context(|| format!("收紧私钥权限失败: {}", key_path.display()))?;
    let key_pem =
        std::fs::read_to_string(&key_path).context("读取客户端私钥失败，可能需要重新纳管")?;
    let csr_pem = tls::make_csr_with_key(&key_pem)?;

    sink.send(Message::Binary(Frame::RenewCert { csr_pem }.encode()?))
        .await?;
    let cert_pem = tokio::time::timeout(CERT_RENEW_TIMEOUT, async {
        loop {
            match recv_frame(stream).await? {
                Frame::CertRenewed { cert_pem } => return Ok::<String, anyhow::Error>(cert_pem),
                // 等待期间 hub 可能发来心跳，必须回应。
                Frame::Ping { ts } => {
                    sink.send(Message::Binary(Frame::Pong { ts }.encode()?))
                        .await?;
                }
                Frame::Problem { code, message } => {
                    bail!("hub 拒绝续签: {code} {message}");
                }
                // 其他帧与续签无关（例如在途批次的 Ack），等待期间丢弃。
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| anyhow!("等待 CertRenewed 超时（{}s）", CERT_RENEW_TIMEOUT.as_secs()))??;

    // 先校验再落盘：坏证书写进去会导致下次连接失败，比不续签更糟。
    validate_renewed_cert(cfg, agent_id, &cert_pem)?;

    let not_after = tls::not_after_unix(&cert_pem)?;
    let cert_path = cfg.data_dir.join(AGENT_CERT);
    fsutil::atomic_write(&cert_path, cert_pem.as_bytes(), 0o644)
        .with_context(|| format!("写入客户端证书失败: {}", cert_path.display()))?;

    let days_left = tls::days_left(&cert_pem, now_ms())?;
    tracing::info!(
        not_after = %tls::format_unix_utc(not_after),
        days_left,
        "客户端证书已续签并落盘"
    );
    Ok(())
}

async fn session(
    ws: WsStream,
    ctx: &SessionContext<'_>,
    buffer: &Arc<Mutex<DiskBuffer>>,
    notify: &Arc<tokio::sync::Notify>,
) -> Result<()> {
    let (mut sink, mut stream) = ws.split();
    let welcome_interval_ms = handshake(
        &mut sink,
        &mut stream,
        ctx.cfg,
        ctx.agent_id,
        ctx.epoch,
        ctx.boot,
    )
    .await?;
    // 应用 hub 下发的采样间隔；0 / 越界值只告警并保留当前间隔，
    // 避免把错误状态写进采集循环，也不让一条合法会话因坏参数直接断开。
    if let Err(err) = apply_sample_interval(ctx.sample_interval, welcome_interval_ms) {
        tracing::warn!(
            error = %err,
            current_ms = ctx.sample_interval.load(Ordering::Relaxed),
            "拒绝 hub 下发的采样间隔，沿用当前值"
        );
    }

    // A5：握手后检查客户端证书，必要时在会话内续签；失败只告警，不影响采集上报。
    if let Err(err) = maybe_renew_client_cert(&mut sink, &mut stream, ctx.cfg, ctx.agent_id).await {
        tracing::warn!(
            error = %err,
            "客户端证书续签失败，本次会话继续（证书通常仍有足够寿命）"
        );
    }

    let mut ping_timer = tokio::time::interval(Duration::from_secs(15));
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // KI-12：会话空闲时也要周期检查客户端证书。`session_max_hours = 0` 只表示
    // 不主动重连，不能跳过续签窗口；定时器与 session_deadline 相互独立。
    let mut cert_timer =
        tokio::time::interval(cert_check_period(ctx.cfg.cert_check_interval_hours));
    cert_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // 第一次 tick 立即完成：握手后已经检查过一次，跳过这次立即检查。
    cert_timer.tick().await;
    let mut last_cert_attempt_ms = 0i64;

    loop {
        let batches = {
            let mut guard = buffer.lock().await;
            guard.read_next(16)?
        };

        if batches.is_empty() {
            tokio::select! {
                _ = ping_timer.tick() => {
                    sink.send(Message::Binary(Frame::Ping { ts: now_ms() }.encode()?)).await?;
                }
                _ = cert_timer.tick() => {
                    // 只在无在途批次（本分支）检查，避免与 ACK 等待争抢同一个 stream。
                    match client_cert_days_left(ctx.cfg) {
                        Ok(days_left) => {
                            let now = now_ms();
                            let threshold = i64::from(ctx.cfg.cert_renew_before_days);
                            if cert_check_due(days_left, threshold, now, last_cert_attempt_ms) {
                                last_cert_attempt_ms = now;
                                tracing::info!(days_left, threshold, "周期证书检查：进入续签窗口");
                                if let Err(err) = maybe_renew_client_cert(
                                    &mut sink,
                                    &mut stream,
                                    ctx.cfg,
                                    ctx.agent_id,
                                )
                                .await
                                {
                                    tracing::warn!(error = %err, "周期证书续签失败，本次会话继续");
                                }
                            } else {
                                tracing::debug!(days_left, threshold, "周期证书检查：尚未进入续签窗口");
                            }
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "周期证书检查读取本地证书失败");
                        }
                    }
                }
                _ = notify.notified() => {}
                incoming = stream.next() => {
                    match incoming {
                        Some(Ok(Message::Close(_))) | None => bail!("hub 关闭了连接"),
                        Some(Ok(Message::Binary(bytes))) => {
                            if let Ok(Frame::Ping { ts }) = Frame::decode(bytes.as_ref()) {
                                sink.send(Message::Binary(Frame::Pong { ts }.encode()?)).await?;
                            }
                        }
                        Some(Ok(_)) => {}
                        Some(Err(err)) => return Err(err.into()),
                    }
                }
            }
            continue;
        }

        for batch in batches {
            let (batch_epoch, batch_seq) = (batch.epoch, batch.seq);
            sink.send(Message::Binary(Frame::Batch(batch).encode()?))
                .await?;

            let acked = tokio::time::timeout(Duration::from_secs(20), async {
                loop {
                    match recv_frame(&mut stream).await? {
                        // ACK 必须对应同一 epoch，否则不能推进缓冲读指针。
                        Frame::Ack { epoch, seq } if epoch == batch_epoch && seq >= batch_seq => {
                            return Ok(())
                        }
                        Frame::Problem { code, message } => {
                            if problem_is_fatal(&code) {
                                return Err(fatal_rejection_error(&format!("{code}: {message}")));
                            }
                            bail!("hub 报错: {code} {message}")
                        }
                        Frame::Ping { ts } => {
                            sink.send(Message::Binary(Frame::Pong { ts }.encode()?))
                                .await?;
                        }
                        _ => {}
                    }
                }
            })
            .await;

            match acked {
                Ok(Ok(())) => {
                    buffer.lock().await.ack(batch_epoch, batch_seq)?;
                }
                Ok(Err(err)) => return Err(err),
                Err(_) => bail!("等待 Ack 超时 (epoch={batch_epoch}, seq={batch_seq})"),
            }
        }
    }
}

async fn recv_frame<S>(stream: &mut S) -> Result<Frame>
where
    S: futures_util::Stream<
            Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>,
        > + Unpin,
{
    loop {
        match stream.next().await {
            Some(Ok(Message::Binary(bytes))) => return Ok(Frame::decode(bytes.as_ref())?),
            Some(Ok(Message::Ping(_))) => continue,
            Some(Ok(Message::Close(_))) | None => bail!("连接已关闭"),
            Some(Ok(_)) => continue,
            Some(Err(err)) => return Err(err.into()),
        }
    }
}

fn load_or_create_agent_id(dir: &std::path::Path) -> Result<String> {
    let path = dir.join(AGENT_ID);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let id = existing.trim().to_string();
        if !id.is_empty() {
            return Ok(id);
        }
    }
    let id = uuid::Uuid::new_v4().to_string();
    fsutil::atomic_write(&path, id.as_bytes(), 0o644)?;
    Ok(id)
}

/// `cert-info`：打印客户端证书的公开信息。
///
/// 缺证书或证书已过期都以非零退出码结束（`main` 返回 Err），方便脚本与 e2e 断言。
fn cert_info(config: Option<PathBuf>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_CONFIG));
    let cfg = AgentConfig::load(&path).with_context(|| {
        format!(
            "读取配置失败: {}（先执行 rustboard-agent init）",
            path.display()
        )
    })?;
    let cert_path = cfg.data_dir.join(AGENT_CERT);
    let cert_pem = std::fs::read_to_string(&cert_path).with_context(|| {
        format!(
            "读取客户端证书失败: {}（尚未纳管？先执行 rustboard-agent run）",
            cert_path.display()
        )
    })?;

    let summary = tls::cert_summary(&cert_pem)?;
    let now = now_ms();
    let days_left = tls::days_left(&cert_pem, now)?;

    println!("配置文件: {}", path.display());
    println!("证书: {}", cert_path.display());
    println!("CN: {}", summary.common_name.as_deref().unwrap_or("(无)"));
    println!(
        "notBefore: {} ({})",
        tls::format_unix_utc(summary.not_before),
        summary.not_before
    );
    println!(
        "notAfter: {} ({})",
        tls::format_unix_utc(summary.not_after),
        summary.not_after
    );
    println!("剩余天数: {days_left}");
    println!("续签阈值: {} 天", cfg.cert_renew_before_days);

    if summary.not_after.saturating_mul(1_000) <= now {
        bail!(
            "客户端证书已过期（notAfter={}）",
            tls::format_unix_utc(summary.not_after)
        );
    }
    Ok(())
}

/// `renew`：连上 hub 完成一次客户端证书轮换后退出。
fn renew(config: Option<PathBuf>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_CONFIG));
    let cfg = AgentConfig::load(&path).with_context(|| {
        format!(
            "读取配置失败: {}（先执行 rustboard-agent init）",
            path.display()
        )
    })?;
    cfg.validate()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move { renew_once(&cfg).await })
}

async fn renew_once(cfg: &AgentConfig) -> Result<()> {
    if !is_enrolled(cfg) {
        bail!("尚未纳管（缺少 agent.crt / agent.key / agent.secret），先执行 rustboard-agent run");
    }
    // 不能在这里 create：拿一个随机 agent_id 去连，hub 会因 CN 不一致直接拒绝。
    let agent_id = std::fs::read_to_string(cfg.data_dir.join(AGENT_ID))
        .ok()
        .map(|id| id.trim().to_string())
        .filter(|id| !id.is_empty())
        .context("读取 agent_id 失败（尚未纳管？）")?;

    let ws = connect(cfg, true).await?;
    let (mut sink, mut stream) = ws.split();
    // 与常驻会话共用握手：协议不匹配 / 被吊销等错误会让命令立即失败并返回非零退出码。
    handshake(
        &mut sink,
        &mut stream,
        cfg,
        &agent_id,
        now_ms() as u64,
        &boot_id(),
    )
    .await?;
    renew_client_cert(&mut sink, &mut stream, cfg, &agent_id).await?;
    // 主动关连接：否则 hub 侧只能看到 TCP 直接断开（close_notify 缺失），日志里会出现
    // 一条误导性的接收失败。关闭失败不影响已经落盘的结果。
    if let Err(err) = sink.close().await {
        tracing::debug!(error = %err, "关闭 WebSocket 失败（证书已落盘）");
    }

    let cert_pem = std::fs::read_to_string(cfg.data_dir.join(AGENT_CERT))?;
    let not_after = tls::not_after_unix(&cert_pem)?;
    println!("证书路径: {}", cfg.data_dir.join(AGENT_CERT).display());
    println!(
        "新证书到期: {}（剩余 {} 天）",
        tls::format_unix_utc(not_after),
        tls::days_left(&cert_pem, now_ms())?
    );
    println!("续签完成；常驻进程会在下次重连时自动使用新证书。");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::atomic::AtomicU32;
    use std::task::{Context as TaskContext, Poll};

    /// H1：bad_protocol 必须被识别为不可重试错误，普通网络错误仍走退避重连。
    #[test]
    fn h1_bad_protocol_is_fatal_but_network_errors_are_retryable() {
        let fatal = bad_protocol_error("需要 agent ≥ 2");
        assert!(is_fatal_protocol_error(&fatal));
        assert!(fatal.downcast_ref::<BadProtocolError>().is_some());
        assert!(fatal.to_string().contains("请升级"));

        let retry = anyhow!("connection refused");
        assert!(!is_fatal_protocol_error(&retry));
    }

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rb-agent-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// 单测用的空 sink：吞掉写出的帧，不模拟网络错误。
    struct NullSink;

    impl Sink<Message> for NullSink {
        type Error = WsError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::result::Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, _item: Message) -> std::result::Result<(), WsError> {
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::result::Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::result::Result<(), WsError>> {
            Poll::Ready(Ok(()))
        }
    }

    /// 造一个「已纳管」的 data_dir：CA 签发的客户端证书 + 复用私钥 + agent_id。
    fn enrolled_config(dir: &Path, cert_days: u32) -> AgentConfig {
        let hub_dir = dir.join("hub");
        tls::ensure_hub_material(
            &hub_dir,
            &["localhost".to_string()],
            tls::CertPolicy::default(),
        )
        .unwrap();
        let ca_key =
            std::fs::read_to_string(tls::cert_dir(&hub_dir).join(tls::CA_KEY_FILE)).unwrap();
        let ca_pem =
            std::fs::read_to_string(tls::cert_dir(&hub_dir).join(tls::CA_CERT_FILE)).unwrap();
        let (csr, key_pem) = tls::make_csr().unwrap();
        let cert_pem = tls::sign_client_csr(&ca_key, &csr, "agent-test", cert_days).unwrap();

        fsutil::ensure_dir(dir, 0o700).unwrap();
        fsutil::atomic_write(&dir.join(AGENT_CERT), cert_pem.as_bytes(), 0o644).unwrap();
        fsutil::atomic_write(&dir.join(AGENT_KEY), key_pem.as_bytes(), 0o600).unwrap();
        fsutil::atomic_write(&dir.join(AGENT_SECRET), b"test-secret", 0o600).unwrap();
        fsutil::atomic_write(&dir.join(AGENT_ID), b"agent-test", 0o644).unwrap();
        // 纳管成功时 hub 会下发 ca.crt；续签的签发者校验依赖它。
        fsutil::atomic_write(&dir.join(AGENT_CA), ca_pem.as_bytes(), 0o644).unwrap();

        AgentConfig {
            data_dir: dir.to_path_buf(),
            cert_renew_before_days: 30,
            ..AgentConfig::default()
        }
    }

    /// 用 `enrolled_config` 里那张 CA 的私钥签新证书，模拟 hub 的 `CertRenewed`。
    fn hub_sign(dir: &Path, csr_pem: &str, days: u32) -> String {
        let ca_key =
            std::fs::read_to_string(tls::cert_dir(&dir.join("hub")).join(tls::CA_KEY_FILE))
                .unwrap();
        tls::sign_client_csr(&ca_key, csr_pem, "agent-test", days).unwrap()
    }

    /// A5：到期续签成功时新证书原子落盘，私钥保持不变。
    #[tokio::test]
    async fn a5_renewal_writes_new_certificate() {
        let dir = temp_dir("renew");
        let cfg = enrolled_config(&dir, 1);
        let key_before = std::fs::read_to_string(dir.join(AGENT_KEY)).unwrap();

        let csr = tls::make_csr_with_key(&key_before).unwrap();
        let new_cert = hub_sign(&dir, &csr, 90);
        let frame = Frame::CertRenewed {
            cert_pem: new_cert.clone(),
        }
        .encode()
        .unwrap();

        let mut sink = NullSink;
        let mut stream = futures_util::stream::iter(vec![Ok(Message::Binary(frame))]);
        renew_client_cert(&mut sink, &mut stream, &cfg, "agent-test")
            .await
            .expect("收到 CertRenewed 必须续签成功");

        let on_disk = std::fs::read_to_string(dir.join(AGENT_CERT)).unwrap();
        assert_eq!(on_disk, new_cert, "新证书必须落盘");
        assert_eq!(
            tls::days_left(&on_disk, now_ms()).unwrap(),
            90,
            "落盘证书的有效期应与 hub 签发的一致"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join(AGENT_KEY)).unwrap(),
            key_before,
            "续签必须复用原私钥"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A5：剩余寿命充足时不发续签请求（不消费 stream，直接返回）。
    #[tokio::test]
    async fn a5_skips_renewal_when_certificate_is_fresh() {
        let dir = temp_dir("fresh");
        let cfg = enrolled_config(&dir, 90);
        let before = std::fs::read_to_string(dir.join(AGENT_CERT)).unwrap();

        let mut sink = NullSink;
        let mut stream = futures_util::stream::empty::<std::result::Result<Message, WsError>>();
        maybe_renew_client_cert(&mut sink, &mut stream, &cfg, "agent-test")
            .await
            .expect("未到阈值时不应报错");

        assert_eq!(
            std::fs::read_to_string(dir.join(AGENT_CERT)).unwrap(),
            before,
            "未到阈值不得改动磁盘证书"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A5 错误路径：hub 拒绝续签时保留旧证书并返回错误（会话侧只 warn）。
    #[tokio::test]
    async fn a5_renewal_failure_keeps_old_certificate() {
        let dir = temp_dir("renew-fail");
        let cfg = enrolled_config(&dir, 1);
        let before = std::fs::read_to_string(dir.join(AGENT_CERT)).unwrap();

        let problem = Frame::Problem {
            code: codes::RATE_LIMITED.to_string(),
            message: "同一会话只能续签一次".to_string(),
        };
        let mut sink = NullSink;
        let mut stream =
            futures_util::stream::iter(vec![Ok(Message::Binary(problem.encode().unwrap()))]);

        let err = renew_client_cert(&mut sink, &mut stream, &cfg, "agent-test")
            .await
            .expect_err("hub 拒绝时续签必须失败");
        assert!(
            err.to_string().contains(codes::RATE_LIMITED),
            "错误信息: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join(AGENT_CERT)).unwrap(),
            before,
            "失败时不得覆盖旧证书"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 安全：hub 返回的证书必须通过五项校验，任何一项不符都不覆盖旧证书。
    #[tokio::test]
    async fn a5_rejects_invalid_renewed_certificates() {
        let dir = temp_dir("renew-validate");
        let cfg = enrolled_config(&dir, 1);
        let before = std::fs::read_to_string(dir.join(AGENT_CERT)).unwrap();
        let key_pem = std::fs::read_to_string(dir.join(AGENT_KEY)).unwrap();

        // 1) 无关 CA 签发的证书：CN 与私钥都正确，但签发者不对。
        //    这里用另一套 hub 材料里的 CA 私钥，避免给 agent 增加 rcgen 依赖。
        let other_hub = dir.join("other-hub");
        tls::ensure_hub_material(
            &other_hub,
            &["localhost".to_string()],
            tls::CertPolicy::default(),
        )
        .unwrap();
        let other_ca_key =
            std::fs::read_to_string(tls::cert_dir(&other_hub).join(tls::CA_KEY_FILE)).unwrap();
        let csr = tls::make_csr_with_key(&key_pem).unwrap();
        let foreign = tls::sign_client_csr(&other_ca_key, &csr, "agent-test", 90).unwrap();
        let frame = Frame::CertRenewed { cert_pem: foreign }.encode().unwrap();
        let mut sink = NullSink;
        let mut stream = futures_util::stream::iter(vec![Ok(Message::Binary(frame))]);
        let err = renew_client_cert(&mut sink, &mut stream, &cfg, "agent-test")
            .await
            .expect_err("无关 CA 签发的证书必须被拒绝");
        assert!(format!("{err:#}").contains("签发"), "错误信息: {err:#}");
        assert_eq!(
            std::fs::read_to_string(dir.join(AGENT_CERT)).unwrap(),
            before,
            "校验失败不得覆盖旧证书"
        );

        // 2) CN 与 agent_id 不一致（例如 hub 为别的身份签的证书）。
        let csr = tls::make_csr_with_key(&key_pem).unwrap();
        let ca_key =
            std::fs::read_to_string(tls::cert_dir(&dir.join("hub")).join(tls::CA_KEY_FILE))
                .unwrap();
        let wrong_cn_cert = tls::sign_client_csr(&ca_key, &csr, "other-agent", 90).unwrap();
        let err = validate_renewed_cert(&cfg, "agent-test", &wrong_cn_cert)
            .expect_err("CN 不一致必须被拒绝");
        assert!(err.to_string().contains("CN"), "错误信息: {err}");

        // 3) 与本机私钥不配套（另一把 key 签的 CSR）。
        let (other_csr, _other_key) = tls::make_csr().unwrap();
        let mismatched = tls::sign_client_csr(&ca_key, &other_csr, "agent-test", 90).unwrap();
        let err = validate_renewed_cert(&cfg, "agent-test", &mismatched)
            .expect_err("与私钥不配套必须被拒绝");
        assert!(err.to_string().contains("私钥"), "错误信息: {err}");

        // 4) 正常证书必须通过全部校验。
        let valid = hub_sign(&dir, &tls::make_csr_with_key(&key_pem).unwrap(), 90);
        validate_renewed_cert(&cfg, "agent-test", &valid).expect("正常证书必须通过校验");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A7：`cert-info` 正常输出；证书缺失时以错误结束（非零退出码）。
    #[test]
    fn a7_cert_info_reports_validity_and_fails_without_certificate() {
        let dir = temp_dir("cert-info");
        let cfg = enrolled_config(&dir, 90);
        let cfg_path = dir.join("agent.toml");
        cfg.save(&cfg_path).unwrap();

        cert_info(Some(cfg_path.clone())).expect("有证书时必须成功");

        std::fs::remove_file(dir.join(AGENT_CERT)).unwrap();
        let err = cert_info(Some(cfg_path)).expect_err("缺证书必须非零退出");
        assert!(format!("{err:#}").contains("尚未纳管"), "错误信息: {err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `session_max_hours = 0` 表示不主动重连；正数必须落在 ±10% 抖动窗口内，
    /// 且同一进程（同一 seed）结果是确定的、不会溢出。
    #[test]
    fn session_deadline_is_jittered_but_bounded() {
        assert_eq!(session_deadline(0, 1), None);

        let base = 12 * 3_600u64;
        let span = base / 10;
        for seed in [0i64, 1, 12_345_678, i64::MAX, -42] {
            let deadline = session_deadline(12, seed).expect("12 小时必须有截止时间");
            let secs = deadline.as_secs();
            assert!(
                secs >= base - span && secs <= base + span,
                "seed={seed} 的抖动超出 ±10%: {secs}"
            );
            // 确定性：同一 seed 结果相同（便于排障与测试，也说明没用 rand）。
            assert_eq!(deadline, session_deadline(12, seed).unwrap());
        }

        // 启动时刻不同 → 截止时间应当不同（抖动真的生效）。
        assert_ne!(
            session_deadline(12, 0),
            session_deadline(12, 1),
            "不同 seed 必须产生不同截止时间"
        );

        // 极大值不 panic（saturating 处理）。
        assert!(session_deadline(u64::MAX, i64::MAX).is_some());
    }

    /// 本地配置的采样间隔范围：999 / 300001 拒绝，1000 / 300000 / 5000 接受。
    #[test]
    fn agent_config_sample_interval_range_is_validated() {
        for invalid in [0, 999, MAX_SAMPLE_INTERVAL_MS + 1, u64::MAX] {
            let err = validate_sample_interval_config(invalid)
                .expect_err(&format!("{invalid}ms 必须被拒绝"));
            assert!(
                err.to_string().contains("sample_interval_ms"),
                "错误: {err}"
            );
        }
        for valid in [MIN_SAMPLE_INTERVAL_MS, 5_000, MAX_SAMPLE_INTERVAL_MS] {
            validate_sample_interval_config(valid).expect("合法配置必须通过");
        }
    }

    /// Welcome 间隔写入共享 atomic；0 / 越界值必须拒绝且不覆盖当前值。
    #[test]
    fn welcome_interval_updates_atomic_and_invalid_range_is_rejected() {
        let interval = AtomicU64::new(5_000);
        for invalid in [
            0,
            MIN_SAMPLE_INTERVAL_MS - 1,
            MAX_SAMPLE_INTERVAL_MS + 1,
            u64::MAX,
        ] {
            let err = apply_sample_interval(&interval, invalid)
                .expect_err(&format!("{invalid}ms 必须被拒绝"));
            assert!(err.to_string().contains("采样间隔"), "错误信息: {err}");
            assert_eq!(
                interval.load(Ordering::Relaxed),
                5_000,
                "拒绝 {invalid}ms 时不得覆盖原间隔"
            );
        }

        for valid in [MIN_SAMPLE_INTERVAL_MS, 10_000, MAX_SAMPLE_INTERVAL_MS] {
            apply_sample_interval(&interval, valid).expect("合法间隔必须写入");
            assert_eq!(interval.load(Ordering::Relaxed), valid);
        }
    }

    /// 握手把 Welcome 的原始值交给上层；非法值由 `apply_sample_interval` 拒绝。
    #[tokio::test]
    async fn handshake_passes_interval_and_invalid_values_do_not_override() {
        let dir = temp_dir("welcome-zero");
        let cfg = enrolled_config(&dir, 90);

        let make_welcome = |ms: u64| {
            Frame::Welcome(rustboard_common::wire::Welcome {
                agent_id: "agent-test".to_string(),
                server_version: "0.2.0".to_string(),
                protocol: PROTOCOL_VERSION,
                sample_interval_ms: ms,
                server_time: now_ms(),
            })
            .encode()
            .unwrap()
        };

        let interval = AtomicU64::new(cfg.sample_interval_ms);
        let mut sink = NullSink;
        for invalid in [0, MAX_SAMPLE_INTERVAL_MS + 1] {
            let mut stream =
                futures_util::stream::iter(vec![Ok(Message::Binary(make_welcome(invalid)))]);
            let welcome = handshake(&mut sink, &mut stream, &cfg, "agent-test", 1, "boot")
                .await
                .expect("握手本身不应因间隔非法而失败");
            assert_eq!(welcome, invalid);
            assert!(
                apply_sample_interval(&interval, welcome).is_err(),
                "{invalid}ms 必须被拒绝"
            );
            assert_eq!(
                interval.load(Ordering::Relaxed),
                cfg.sample_interval_ms,
                "非法 Welcome 不得覆盖当前间隔"
            );
        }

        // 合法值原样返回，供 session 写入 atomic。
        let mut stream =
            futures_util::stream::iter(vec![Ok(Message::Binary(make_welcome(10_000)))]);
        let welcome = handshake(&mut sink, &mut stream, &cfg, "agent-test", 1, "boot")
            .await
            .expect("合法 Welcome 必须握手成功");
        assert_eq!(welcome, 10_000);
        apply_sample_interval(&interval, welcome).unwrap();
        assert_eq!(interval.load(Ordering::Relaxed), 10_000);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M2-6 纯函数边界：120s 周期中途改成 10s 时，下一次休眠按新目标计算，
    /// 且被分片上限截断，绝不会再睡满旧的 120s。
    #[test]
    fn interval_sleep_chunk_never_waits_full_old_interval() {
        let slice = Duration::from_secs(1);

        // 旧 120s 周期进行了 2s，Welcome 改成 10s：下一次最多睡 1s 分片，
        // 而不是旧周期的剩余 118s。
        assert_eq!(
            interval_sleep_chunk(120_000, Duration::from_secs(2), slice),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            interval_sleep_chunk(10_000, Duration::from_secs(2), slice),
            Some(Duration::from_secs(1))
        );
        // 已经超过新间隔（例如 120s 周期进行到 30s 才改成 10s）立即结束。
        assert_eq!(
            interval_sleep_chunk(10_000, Duration::from_secs(30), slice),
            None
        );
        // 剩余时间小于分片时按剩余时间睡，不会越过目标。
        assert_eq!(
            interval_sleep_chunk(10_000, Duration::from_millis(9_500), slice),
            Some(Duration::from_millis(500))
        );
        // 0 / 超小目标按 1ms 处理，避免忙等死循环。
        assert_eq!(
            interval_sleep_chunk(0, Duration::ZERO, slice),
            Some(Duration::from_millis(1))
        );
    }

    /// M2-6：120s → 10s 的调整必须在一个分片内生效，不能继续睡满 120s。
    #[tokio::test]
    async fn sleep_sample_interval_switches_to_shorter_interval_quickly() {
        let interval = std::sync::Arc::new(AtomicU64::new(120_000));
        let slice = Duration::from_millis(5);

        let waiter = {
            let interval = interval.clone();
            tokio::spawn(async move { sleep_sample_interval(&interval, 120_000, slice).await })
        };
        // 等几个分片，确保旧间隔的休眠已经开始。
        tokio::time::sleep(Duration::from_millis(30)).await;
        interval.store(10, Ordering::Relaxed);

        let elapsed = tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("新间隔未在 2s 内生效（仍按 120s 休眠）")
            .unwrap();
        assert!(
            elapsed < Duration::from_secs(2),
            "120s→10ms 后耗时 {elapsed:?}，说明没有采用新间隔"
        );
    }

    /// 间隔不变时按目标时长休眠；已经超过目标时长时立即返回。
    #[tokio::test]
    async fn sleep_sample_interval_waits_for_target_when_unchanged() {
        let interval = AtomicU64::new(40);
        let started = tokio::time::Instant::now();
        let elapsed = sleep_sample_interval(&interval, 40, Duration::from_millis(5)).await;
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(elapsed >= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_secs(2));

        // 0 / 超小目标按 1ms 处理：不忙等死循环，也不 panic。
        let interval = AtomicU64::new(1);
        let elapsed = sleep_sample_interval(&interval, 0, Duration::from_millis(5)).await;
        assert!(elapsed >= Duration::from_millis(1));
        assert!(elapsed < Duration::from_secs(1));
    }

    /// KI-12：周期检查纯函数边界——阈值、首次、退避窗口与时钟回退。
    #[test]
    fn v021_cert_check_due_boundaries() {
        let threshold = 30;
        let now = 1_700_000_000_000i64;
        // 剩余寿命高于阈值：不触发。
        assert!(!cert_check_due(threshold + 1, threshold, now, 0));
        // 恰好等于阈值 / 低于阈值：触发。
        assert!(cert_check_due(threshold, threshold, now, 0));
        assert!(cert_check_due(0, threshold, now, 0));
        assert!(cert_check_due(-5, threshold, now, 0));

        // 已尝试过：退避窗口内不触发，恰好到窗口触发。
        let last = now - CERT_RENEW_RETRY_MS + 1;
        assert!(!cert_check_due(1, threshold, now, last));
        assert!(cert_check_due(1, threshold, now, last - 1));
        let last = now - CERT_RENEW_RETRY_MS;
        assert!(cert_check_due(1, threshold, now, last));

        // 时钟回退 / last 在未来：不能触发（saturating_sub 为 0）。
        assert!(!cert_check_due(1, threshold, now, now + 60_000));

        // 未进入窗口时，即使 last 很久以前也不触发。
        assert!(!cert_check_due(
            threshold + 1,
            threshold,
            now,
            now - 10 * CERT_RENEW_RETRY_MS
        ));
    }

    /// KI-12：`session_max_hours = 0` 仍必须有周期检查；周期由小时换算为秒且有护栏。
    #[test]
    fn v021_cert_check_period_has_no_session_max_hours_blind_spot() {
        // 0 表示不主动重连：会话不会按 deadline 重启，只能靠周期检查续签。
        let cfg = AgentConfig {
            session_max_hours: 0,
            cert_check_interval_hours: 6,
            ..AgentConfig::default()
        };
        cfg.validate().expect("session_max_hours=0 必须合法");
        assert_eq!(
            cert_check_period(cfg.cert_check_interval_hours),
            Duration::from_secs(6 * 3_600)
        );
        // 即使坏配置传入 0 也不允许 0 周期忙循环。
        assert_eq!(cert_check_period(0), Duration::from_secs(3_600));
        assert_eq!(cert_check_period(168), Duration::from_secs(168 * 3_600));

        // 默认值 6 小时；配置范围 1–168 已在 common 校验。
        let default_cfg: AgentConfig = toml::from_str("").unwrap();
        assert_eq!(default_cfg.cert_check_interval_hours, 6);
        assert_eq!(
            cert_check_period(default_cfg.cert_check_interval_hours),
            Duration::from_secs(6 * 3_600)
        );
    }
}
