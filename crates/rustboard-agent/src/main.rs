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
use futures_util::{SinkExt, StreamExt};
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
    }
}

fn run(cfg: AgentConfig) -> Result<()> {
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
    tracing::info!(%agent_id, epoch, "采集端启动");

    let collectors = Arc::new(default_collectors(cfg.per_core, &cfg.excluded_interfaces));
    let buffer = Arc::new(Mutex::new(DiskBuffer::open(
        &cfg.data_dir,
        cfg.buffer_max_bytes,
        cfg.buffer_max_age_hours.saturating_mul(3_600_000),
    )?));
    let seq = Arc::new(AtomicU64::new(0));
    // 采集器写入后立刻唤醒上传循环，避免空缓冲时只能等心跳
    let notify = Arc::new(tokio::sync::Notify::new());

    // 采集任务
    {
        let collectors = collectors.clone();
        let buffer = buffer.clone();
        let seq = seq.clone();
        let agent_id = agent_id.clone();
        let boot = boot.clone();
        let interval = cfg.sample_interval_ms;
        let notify = notify.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_millis(interval));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let ts = now_ms();
                let mut samples = Vec::new();
                for collector in collectors.iter() {
                    samples.extend(collector.collect(ts));
                }
                if samples.is_empty() {
                    continue;
                }
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
        });
    }

    // 上传任务（主循环，断线指数退避重连）
    let mut backoff_secs = 1u64;
    loop {
        match connect(&cfg, true).await {
            Ok(ws) => {
                backoff_secs = 1;
                tracing::info!(url = %cfg.hub_url, "已连接 hub");
                if let Err(err) = session(ws, &cfg, &agent_id, epoch, &boot, &buffer, &notify).await
                {
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

fn is_enrolled(cfg: &AgentConfig) -> bool {
    cfg.data_dir.join(AGENT_CERT).exists()
        && cfg.data_dir.join(AGENT_KEY).exists()
        && cfg.data_dir.join(AGENT_SECRET).exists()
}

async fn connect(cfg: &AgentConfig, with_client_cert: bool) -> Result<WsStream> {
    let connector = if cfg.hub_url.starts_with("wss://") {
        let (cert, key) = if with_client_cert {
            // M3：老的 agent.key 可能是 0644，读取前先收紧到 0600。
            let key_path = cfg.data_dir.join(AGENT_KEY);
            fsutil::harden(&key_path, 0o600)
                .with_context(|| format!("收紧私钥权限失败: {}", key_path.display()))?;
            (
                Some(std::fs::read_to_string(cfg.data_dir.join(AGENT_CERT))?),
                Some(std::fs::read_to_string(&key_path)?),
            )
        } else {
            (None, None)
        };
        let config = tls::client_config(&cfg.server_fingerprint, cert.as_deref(), key.as_deref())?;
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

async fn session(
    ws: WsStream,
    cfg: &AgentConfig,
    agent_id: &str,
    epoch: u64,
    boot: &str,
    buffer: &Arc<Mutex<DiskBuffer>>,
    notify: &Arc<tokio::sync::Notify>,
) -> Result<()> {
    let (mut sink, mut stream) = ws.split();
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

    match tokio::time::timeout(Duration::from_secs(10), recv_frame(&mut stream)).await {
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
            if w.sample_interval_ms == 0 {
                bail!("hub 下发了非法的采样间隔");
            }
            tracing::info!(
                server = %w.server_version,
                sample_interval_ms = w.sample_interval_ms,
                "握手完成"
            );
        }
        Ok(Ok(Frame::Problem { code, message })) if code == codes::BAD_PROTOCOL => {
            // H1：正式会话阶段被拒也必须退出，不能回主循环每秒重连。
            return Err(bad_protocol_error(&message));
        }
        Ok(Ok(Frame::Problem { code, message })) if problem_is_fatal(&code) => {
            return Err(fatal_rejection_error(&format!("{code}: {message}")));
        }
        Ok(Ok(Frame::Problem { code, message })) => bail!("hub 拒绝连接: {code} {message}"),
        Ok(Ok(_)) => bail!("首帧不是 Welcome"),
    }

    let mut ping_timer = tokio::time::interval(Duration::from_secs(15));
    ping_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
