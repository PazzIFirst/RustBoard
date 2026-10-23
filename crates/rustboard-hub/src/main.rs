//! RustBoard 汇聚端。
//!
//! 职责：接收 agent 上报、写入存储、对外提供只读 API，
//! 并在 `self_monitor` 打开时采集本机指标（hub 就是一台内置 agent）。
//!
//! 安全模型：私有 CA + 服务端证书指纹固定 + 一次性 enrollment token。
//! agent 首次连接只允许发 `Enroll`，换取客户端证书与独立 secret，之后走 mTLS。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::extract::ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, RawQuery, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use http_body::{Body as HttpBody, Frame as BodyFrame, SizeHint};
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustboard_common::config::{AdminTlsMode, HubConfig};
use rustboard_common::control::ControlError;
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};
use rustboard_common::tls;
use rustboard_common::util::{
    arch, boot_id, hostname, now_ms, os_pretty_name, pick_free_port_excluding, port_of,
};
use rustboard_common::wire::{codes, AgentHello, EnrollRequest, Frame, Welcome};
use rustboard_common::{DEFAULT_HUB_CONFIG, PROTOCOL_VERSION, VERSION};
use rustboard_core::collect::default_collectors;
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::{
    AgentSeriesRow, IngestOutcome, QueryTooLarge, Storage, AUDIT_RETENTION_MS,
};
use tokio::net::TcpListener;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

mod auth;
mod cert_rotation;
mod control;
mod session;
use auth::{AuthFailureLimiter, TokenScope};
use cert_rotation::CertStatus;
use control::{ControlCommand, ControlSession};
use session::{SessionRegistry, ShutdownReason};

/// 内置本机采集使用的 agent_id，只允许 hub 进程内部写入。
/// WebSocket 单条消息上限。agent 的正常批次只有几 KB，1 MiB 足够宽裕；
/// 不设上限时 tungstenite 默认允许 64 MiB，未认证连接可用分片消息打爆内存。
const MAX_WS_MESSAGE_SIZE: usize = 1024 * 1024;
/// 单帧上限与消息上限一致，避免合法的大控制结果被额外卡住。
///
/// agent 的 `MAX_OUTPUT_BYTES` 允许单次控制输出接近 256 KiB，MessagePack 编码后的
/// `ControlResponse` 单帧会略超 256 KiB；若单帧上限更小，tungstenite 会以
/// `Space limit exceeded` 拒绝该帧并关闭整个 agent 会话（控制动作已执行却丢结果）。
/// 内存边界不变：即使拆成多个分片，整条消息仍受 1 MiB `max_message_size` 约束。
const MAX_WS_FRAME_SIZE: usize = MAX_WS_MESSAGE_SIZE;

const HUB_SELF_AGENT_ID: &str = "hub-self";
/// 会话身份与帧内身份不一致。
const IDENTITY_MISMATCH: &str = "identity_mismatch";
/// 正式会话缺少客户端证书。
const MTLS_REQUIRED: &str = "mtls_required";
/// 连续这么久收不到任何帧就认为连接已死（agent 每 15s 发一次 Ping）。
const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// 吊销状态轮询周期，保证吊销后连接能在 2s 内被关闭。
const REVOKE_POLL_INTERVAL: Duration = Duration::from_secs(2);
/// TLS 握手超时，避免半开连接长期占用资源（5s：慢速握手不能长期占槽位）。
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// HTTP/1 请求头读取超时，抵挡 slowloris 一类慢速攻击。
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// 请求体总读取超时（从 header 读完开始一次性计时，不随 frame 重置）。
///
/// header 超时只能挡住半截 header；客户端发完 header + 超大 Content-Length 后
/// 不发 body，读取 body 的 handler 会一直挂住并占住连接槽位。10s 是正常大请求
/// 的宽裕上限，对逐字节 drip 同样只有一个总 deadline。
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// 管理 API 全局并发连接上限；超出后 accept 到的 TCP 立即关闭。
const ADMIN_MAX_CONNECTIONS: usize = 256;
/// 管理 API 单来源 IP 并发连接上限；只绑回环时同样生效。
const ADMIN_MAX_CONNECTIONS_PER_IP: usize = 32;
/// 管理 API TLS 握手超时：半开 TLS 连接最多占用 10s。
const ADMIN_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 管理端 TLS 热加载轮询周期：跟踪 mTLS 监听器已经验证并切换过的 live 证书。
const ADMIN_TLS_RELOAD_INTERVAL: Duration = Duration::from_secs(2);
/// 管理端 TLS 热加载构建失败的最小告警间隔，避免坏证书每 2s 刷日志。
const ADMIN_TLS_RELOAD_WARN_INTERVAL: Duration = Duration::from_secs(60);
/// 单条 WebSocket 帧的写超时；写不出去说明对端已经不读了，直接清理会话。
const SESSION_WRITE_TIMEOUT: Duration = Duration::from_secs(15);
/// 客户端续签请求里 CSR 的 PEM 长度上限（16 KiB）。
///
/// 正常 CSR 约 1 KiB；放大上限只会给 hub 的解析路径增加攻击面。
/// 纳管（enrollment）与续签（RenewCert）共用同一个上限。
const MAX_CSR_PEM_LEN: usize = 16 * 1024;

/// 管理 API 请求体上限（64 KiB）。管理端只有 settings 一个写接口。
const MAX_ADMIN_BODY_SIZE: usize = 64 * 1024;
/// `overview` 固定 60s 窗口：允许 1s–60s 覆盖，避免大窗口扫描拖垮 latest_samples。
const OVERVIEW_WINDOW_MS: i64 = 60_000;
const OVERVIEW_MIN_WINDOW_MS: i64 = 1_000;
const OVERVIEW_MAX_WINDOW_MS: i64 = 60_000;
/// `latest` 默认窗口 5 分钟，上限 1 小时。
const LATEST_DEFAULT_WINDOW_MS: i64 = 5 * 60 * 1000;
const LATEST_MAX_WINDOW_MS: i64 = 60 * 60 * 1000;
/// 管理 API Bearer token 的最小长度（`admin-token` 生成的是 64 位 hex）。
const MIN_ADMIN_TOKEN_LEN: usize = 32;
/// token 至少要包含多少个不同字符（挡住 `aaaa...` 这类低熵值）。
const MIN_ADMIN_TOKEN_DISTINCT: usize = 16;
/// v0.2 的 64 位随机 hex token 可能只覆盖 15 个 hex 字符（约 23% 概率），
/// 为保持升级兼容，64 位 hex 形态只要求至少 8 个不同字符。
const MIN_ADMIN_TOKEN_DISTINCT_HEX64: usize = 8;
/// token 占位符黑名单（大小写不敏感，子串匹配）。
const ADMIN_TOKEN_PLACEHOLDERS: [&str; 9] = [
    "changeme",
    "change-me",
    "secret",
    "password",
    "admin",
    "token",
    "rustboard",
    "00000000",
    "aaaaaaaa",
];
/// 单 IP 连接表容量：超过后清理空项并拒绝新来源，防止无限增长。
const MAX_IP_CONNECTION_ENTRIES: usize = 4096;
/// 管理 API 限速的固定窗口长度（毫秒）。
const ADMIN_RATE_WINDOW_MS: i64 = 60_000;
/// 管理 API 限速表容量（按 IP 计数）。
const ADMIN_RATE_TABLE_CAPACITY: usize = 4096;
/// `series` 查询最大跨度 32 天。
const MAX_SERIES_SPAN_MS: i64 = 32 * 24 * 60 * 60 * 1000;
const MAX_SERIES_METRICS: usize = 20;
const MAX_METRIC_LEN: usize = 64;
/// 自动降采样后单曲线目标点数上限。
const MAX_AUTO_BUCKET_POINTS: i64 = 1_500;
/// 单次 `series` 返回的序列（metric + labels）与点数上限。
const MAX_SERIES_COUNT: usize = 50;
const MAX_SERIES_POINTS: usize = 20_000;
/// 自动 bucket 档位（毫秒）。
const AUTO_BUCKETS_MS: [i64; 9] = [
    1_000, 5_000, 10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000, 21_600_000,
];
/// `overview.latest` 只查这些关键指标，避免全量扫描。
const OVERVIEW_METRICS: [&str; 7] = [
    "cpu.usage",
    "mem.used",
    "mem.total",
    "disk.used",
    "disk.total",
    "load.1",
    "uptime",
];
/// 采样间隔允许范围（毫秒），与 agent 侧校验保持一致。
const MIN_SAMPLE_INTERVAL_MS: u64 = 1_000;
const MAX_SAMPLE_INTERVAL_MS: u64 = 300_000;

/// CSR 长度门禁：纳管与续签共用，必须在解析/消费 token 之前调用。
fn csr_within_limit(csr_pem: &str) -> bool {
    csr_pem.len() <= MAX_CSR_PEM_LEN
}

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
        /// 管理 API 传输模式：off（仅回环明文，默认）或 required（HTTPS）。
        #[arg(long, value_parser = ["off", "required"])]
        admin_tls: Option<String>,
        /// 追加到服务端证书 SAN 的地址，可重复。
        #[arg(long = "san")]
        sans: Vec<String>,
        /// 写进 agent 安装命令的 hub 地址（公网 IP 或域名），留空自动探测。
        #[arg(long)]
        advertise: Option<String>,
        /// 新建 CA 的有效期（天，默认 3650，仅对新建 CA 生效）。
        #[arg(long)]
        ca_days: Option<u32>,
        /// 新签发服务端证书的有效期（天，默认 365）。
        #[arg(long)]
        server_cert_days: Option<u32>,
        /// 新签发 agent 客户端证书的有效期（天，默认 90）。
        #[arg(long)]
        client_cert_days: Option<u32>,
        /// 证书剩余寿命不超过该天数时自动续签（默认 30）。
        #[arg(long)]
        renew_before_days: Option<u32>,
        #[arg(long)]
        force: bool,
    },
    /// 立即用 CA 重签服务端证书（备份旧证书，运行中的 hub 会在 ≤15s 内热加载）。
    RotateCert {
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// 剩余寿命仍高于阈值时也强制重签。
        #[arg(long)]
        force: bool,
        /// 本次新证书的有效期（天），默认用配置里的值。
        #[arg(long)]
        days: Option<u32>,
    },
    /// 生成或查看管理 API 的 Bearer token（配置为空时生成并写入，0600）。
    AdminToken {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 管理 API scoped token 管理（create / list / rotate / revoke）。
    Token {
        #[command(subcommand)]
        action: TokenAction,
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

#[derive(Subcommand)]
enum TokenAction {
    /// 新建 scoped token，只输出一次明文。
    Create {
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// token 名称（1–64 字符，仅 `[A-Za-z0-9._-]`），也是审计 actor。
        #[arg(long)]
        name: String,
        /// 权限：read（只读）| write（只读 + 控制/设置）| admin（全部）。
        #[arg(long, value_parser = ["read", "write", "admin"])]
        scope: String,
    },
    /// 列出 token 元信息（TSV，不含明文 / 哈希）。
    List {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 轮换 token：生成新明文、清吊销状态，旧 token 立即失效。
    Rotate {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        name: String,
    },
    /// 吊销 token（不删行）。
    Revoke {
        #[arg(short, long)]
        config: Option<PathBuf>,
        #[arg(long)]
        name: String,
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
    /// 客户端证书续签的准入控制（按 agent 的冷却窗口 + 读盘/签名上下文）。
    renewal: Arc<RenewalContext>,
    /// 监听器当前实际使用的证书摘要（热加载成功 / 自动续签后更新）。
    live_cert: Arc<RwLock<CertStatus>>,
    /// 管理 API 的每 IP 固定窗口限速。
    admin_rate: Arc<AdminRateLimiter>,
    /// 未认证 401 的每来源 IP 固定窗口失败限速（KI-26）。
    auth_failures: Arc<AuthFailureLimiter>,
}

/// 由 TLS accept 层注入到每个请求扩展里的对端身份。
///
/// `None` 表示这条 TLS 连接没有携带客户端证书（只允许走 enrollment）。
#[derive(Clone, Debug)]
struct PeerIdentity(Option<String>);

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "rustboard_hub=info,rustboard_common=warn,tower_http=warn".into());
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        // 日志固定走 stderr：`token create/rotate` 的明文只写 stdout，
        // 避免 `RUST_LOG=info` 时脚本捕获的 token 被日志行污染。
        .with_writer(std::io::stderr)
        .init();

    match Cli::parse().cmd {
        Cmd::Init {
            config,
            data_dir,
            agent_listen,
            admin_listen,
            admin_tls,
            sans,
            advertise,
            ca_days,
            server_cert_days,
            client_cert_days,
            renew_before_days,
            force,
        } => init(
            config,
            data_dir,
            agent_listen,
            admin_listen,
            admin_tls,
            sans,
            advertise,
            ca_days,
            server_cert_days,
            client_cert_days,
            renew_before_days,
            force,
        ),
        Cmd::Run { config } => {
            let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
            let cfg = load_config(&path)?;
            let db_path = cfg.sqlite_path()?;
            run(cfg, db_path)
        }
        Cmd::RotateCert {
            config,
            force,
            days,
        } => rotate_cert(config, force, days),
        Cmd::AdminToken { config } => admin_token(config),
        Cmd::Token { action } => token_command(action),
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

/// hub 配置里的默认采样间隔范围校验。
///
/// `HubConfig::validate` 在 `rustboard-common`（panel 线同时维护），这里在
/// hub 启动前补同一范围校验，保证 Welcome 不会下发 0 / 越界间隔。
fn validate_hub_sample_interval(cfg: &HubConfig) -> Result<()> {
    let ms = cfg.sample_interval_ms;
    if !(MIN_SAMPLE_INTERVAL_MS..=MAX_SAMPLE_INTERVAL_MS).contains(&ms) {
        bail!(
            "sample_interval_ms 必须在 {MIN_SAMPLE_INTERVAL_MS}–{MAX_SAMPLE_INTERVAL_MS} 之间，\
             实际 {ms}；请修改 hub 配置后重启"
        );
    }
    Ok(())
}

/// 管理 API token 强度检查；返回 `None` 表示合格，否则给出人类可读的失败原因。
///
/// 规则（KI-04）：
/// 1. 长度 ≥ 32；
/// 2. 仅 ASCII 可见字符（0x21–0x7e，不含空格）；
/// 3. 至少 16 个不同字符；
/// 4. 不包含常见占位符（大小写不敏感）。
///
/// 失败原因**不回显 token 本身**，只说明哪条不满足。
fn admin_token_strength_error(token: &str) -> Option<String> {
    let len = token.chars().count();
    if len < MIN_ADMIN_TOKEN_LEN {
        return Some(format!(
            "长度不足（{len} 个字符，至少需要 {MIN_ADMIN_TOKEN_LEN} 个）"
        ));
    }
    if !token.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        return Some("包含空白、控制字符或非 ASCII 字符".to_string());
    }
    let distinct = token.chars().collect::<HashSet<_>>().len();
    // 兼容性豁免：v0.2 的 `hub init` / `admin-token` 生成 64 位随机 hex，
    // 其不同字符数可能是 15（只缺一个 hex 字符），仍属高熵 token。
    // 64 位 hex 至少要有 8 个不同字符：`abab...` / 全同字符会被拒绝。
    let is_hex64 = token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit());
    let min_distinct = if is_hex64 {
        MIN_ADMIN_TOKEN_DISTINCT_HEX64
    } else {
        MIN_ADMIN_TOKEN_DISTINCT
    };
    if distinct < min_distinct {
        return Some(format!(
            "不同字符只有 {distinct} 个，至少需要 {min_distinct} 个"
        ));
    }
    let lower = token.to_ascii_lowercase();
    if let Some(placeholder) = ADMIN_TOKEN_PLACEHOLDERS
        .iter()
        .find(|placeholder| lower.contains(**placeholder))
    {
        return Some(format!(
            "包含常见占位符 {placeholder:?}，不能作为管理 token"
        ));
    }
    None
}

/// 管理 API token 是否满足最低强度。
fn admin_token_is_strong(token: &str) -> bool {
    admin_token_strength_error(token).is_none()
}

/// `run` 的前置校验：管理 API 不允许空或弱 token 裸奔。
fn require_admin_token(cfg: &HubConfig) -> Result<()> {
    let token = cfg.admin_token.trim();
    if token.is_empty() {
        bail!(
            "管理 API 未配置 admin_token，拒绝启动：请先执行 `rustboard-hub admin-token` \
             生成并写入配置（或重新执行 `rustboard-hub init`）"
        );
    }
    if let Some(reason) = admin_token_strength_error(token) {
        bail!(
            "管理 API 的 admin_token 强度不足（{reason}），拒绝启动：\
             请执行 `rustboard-hub admin-token` 重新生成高强度 token"
        );
    }
    Ok(())
}

/// `admin-token` 子命令：空或过短则重新生成并保存，合法则原样打印。
///
/// 配置读写都走 `HubConfig::load/save`，文件权限固定 0600；token 只输出到 stdout。
fn admin_token(config: Option<PathBuf>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let mut cfg = load_config(&path)?;
    if !admin_token_is_strong(cfg.admin_token.trim()) {
        cfg.admin_token = new_secret();
        cfg.save(&path)?;
    }
    println!("{}", cfg.admin_token);
    Ok(())
}

/// `token` 子命令入口：只有这里负责打印，业务函数返回可测试的字符串。
///
/// `create` / `rotate` 的明文只经 stdout 输出一次，绝不写日志 / 配置 / 数据库明文。
fn token_command(action: TokenAction) -> Result<()> {
    match action {
        TokenAction::Create {
            config,
            name,
            scope,
        } => println!("{}", token_create(config, name, scope)?),
        TokenAction::List { config } => print!("{}", token_list(config)?),
        TokenAction::Rotate { config, name } => println!("{}", token_rotate(config, name)?),
        TokenAction::Revoke { config, name } => println!("{}", token_revoke(config, name)?),
    }
    Ok(())
}

/// token 名称规范：1–64 个字符，仅 `[A-Za-z0-9._-]`。
///
/// 名称会进入审计 actor 与 TSV 列表，限制字符集可避免换行 / 制表符注入。
fn validate_token_name(name: &str) -> Result<()> {
    let len = name.chars().count();
    if !(1..=64).contains(&len) {
        bail!("token 名称必须为 1–64 个字符，实际 {len} 个");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("token 名称只能包含 A-Z a-z 0-9 . _ -");
    }
    // 审计 actor 兼容性：旧 admin_token 固定写 actor="admin"，若允许同名 scoped
    // token，审计里将无法区分两者。保留名大小写不敏感（Admin/ADMIN 同样拒绝）。
    if name.eq_ignore_ascii_case("admin") {
        bail!(
            "token 名称 \"admin\" 是审计 actor 保留名（与旧 admin_token 不可区分），请换一个名称"
        );
    }
    Ok(())
}

/// 打开配置文件指向的 SQLite（CLI 与运行中的 hub 通过 WAL 并发）。
fn open_token_storage(config: Option<PathBuf>) -> Result<SqliteStorage> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    SqliteStorage::open(&cfg.sqlite_path()?)
}

/// 把 `--scope` 解析成枚举，非法值给出可读错误。
fn parse_token_scope(scope: &str) -> Result<TokenScope> {
    TokenScope::parse(scope)
        .ok_or_else(|| anyhow::anyhow!("scope 必须是 read / write / admin，实际: {scope}"))
}

/// 新建 token：返回 64 位 hex 明文（调用方负责只打印一次）。
fn token_create(config: Option<PathBuf>, name: String, scope: String) -> Result<String> {
    validate_token_name(&name)?;
    let scope = parse_token_scope(&scope)?;
    let storage = open_token_storage(config)?;
    let token = new_secret();
    storage.create_api_token(&name, &tls::sha256_hex(&token), scope.as_str(), now_ms())?;
    Ok(token)
}

/// 列出 token：TSV，表头固定；空时间显示 `-`；绝不出现哈希或明文。
fn token_list(config: Option<PathBuf>) -> Result<String> {
    let storage = open_token_storage(config)?;
    let tokens = storage.list_api_tokens()?;
    let mut output = String::from("name\tscope\tcreated_at\tlast_used_at\trevoked_at\n");
    for token in tokens {
        let last_used = token
            .last_used_at
            .map(|ts| ts.to_string())
            .unwrap_or_else(|| "-".to_string());
        let revoked = token
            .revoked_at
            .map(|ts| ts.to_string())
            .unwrap_or_else(|| "-".to_string());
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            token.name, token.scope, token.created_at, last_used, revoked
        ));
    }
    Ok(output)
}

/// 轮换 token：返回新的 64 位 hex 明文，旧 token 立即失效。
fn token_rotate(config: Option<PathBuf>, name: String) -> Result<String> {
    validate_token_name(&name)?;
    let storage = open_token_storage(config)?;
    let token = new_secret();
    storage.rotate_api_token(&name, &tls::sha256_hex(&token), now_ms())?;
    Ok(token)
}

/// 吊销 token：不删行，重复吊销 / 不存在都是明确错误。
fn token_revoke(config: Option<PathBuf>, name: String) -> Result<String> {
    validate_token_name(&name)?;
    let storage = open_token_storage(config)?;
    storage.revoke_api_token(&name, now_ms())?;
    Ok(format!("已吊销 token: {name}"))
}

// init 的参数与 `init` 子命令的 CLI 字段一一对应，拆结构体只会多一层搬运。
#[allow(clippy::too_many_arguments)]
fn init(
    config: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    agent_listen: Option<String>,
    admin_listen: Option<String>,
    admin_tls: Option<String>,
    sans: Vec<String>,
    advertise: Option<String>,
    ca_days: Option<u32>,
    server_cert_days: Option<u32>,
    client_cert_days: Option<u32>,
    renew_before_days: Option<u32>,
    force: bool,
) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    if path.exists() && !force {
        bail!("{} 已存在，使用 --force 覆盖", path.display());
    }
    let mut cfg = HubConfig::default();
    // 默认 off；`required` 复用随后签发的 server.crt / server.key。
    if admin_tls.as_deref() == Some("required") {
        cfg.admin_tls = AdminTlsMode::Required;
    }
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
    // 有效期参数：显式指定 > 配置默认值（默认值与 config.rs 保持一致）。
    if let Some(days) = ca_days {
        cfg.ca_validity_days = days;
    }
    if let Some(days) = server_cert_days {
        cfg.server_cert_validity_days = days;
    }
    if let Some(days) = client_cert_days {
        cfg.client_cert_validity_days = days;
    }
    if let Some(days) = renew_before_days {
        cfg.renew_before_days = days;
    }
    cfg.name = hostname();
    // 管理 API 必须有 Bearer token：init 一次性生成 64 位 hex，避免交付一个起不来的配置。
    cfg.admin_token = new_secret();
    // 安装命令里的地址：显式指定 > 默认出口 IP
    let advertise =
        advertise.or_else(|| rustboard_common::util::primary_ipv4().map(|ip| ip.to_string()));
    if let Some(host) = &advertise {
        cfg.server_names.push(host.clone());
        cfg.advertise_host = Some(host.clone());
    }
    cfg.server_names.extend(sans);
    cfg.server_names.push(hostname());

    // 先校验再落盘/签发：非法有效期/非法 SAN 不能留下一个起不来的安装或半个 CA。
    cfg.validate()
        .context("init 参数校验失败（检查有效期参数、--renew-before-days 与 --san）")?;
    // required 时管理端地址必须能被证书覆盖（精确 IP 或 DNS 访问），在签发/落盘前
    // 就拒绝，避免交付一个启动即失败的配置。off 非回环仍只警告、允许落盘。
    if cfg.admin_tls == AdminTlsMode::Required {
        validate_admin_tls(&cfg)
            .context("init 管理 API TLS 校验失败（检查 --admin-listen 与 --san/server_names）")?;
    }

    let policy = tls::CertPolicy {
        ca_days: cfg.ca_validity_days,
        server_days: cfg.server_cert_validity_days,
        client_days: cfg.client_cert_validity_days,
    };
    let fingerprint = tls::ensure_hub_material(&cfg.data_dir, &cfg.server_names, policy)?;
    cfg.save(&path)?;

    println!("已写入配置: {}", path.display());
    println!("证书目录: {}", tls::cert_dir(&cfg.data_dir).display());
    println!("服务端证书指纹: {fingerprint}");
    println!(
        "证书有效期: CA {} 天 / 服务端 {} 天 / 客户端 {} 天（剩余 ≤ {} 天时自动续签）",
        cfg.ca_validity_days,
        cfg.server_cert_validity_days,
        cfg.client_cert_validity_days,
        cfg.renew_before_days
    );
    println!("agent 接入监听: {}", cfg.agent_listen);
    println!(
        "管理 API 监听: {}（{}）",
        cfg.admin_listen,
        match cfg.admin_tls {
            AdminTlsMode::Off => "HTTP",
            AdminTlsMode::Required => "HTTPS",
        }
    );
    if cfg.admin_tls == AdminTlsMode::Off {
        // init 允许先落盘（便于之后改配置），但必须明确告知随后 run 会拒绝。
        if let Ok(true) = admin_listen_is_non_loopback(&cfg.admin_listen) {
            println!(
                "警告: admin_tls=\"off\" 且管理 API 监听在非回环地址 {}；\
                 启动会拒绝。请改用 --admin-tls required，或只绑回环 + TLS 反向代理。",
                cfg.admin_listen
            );
        }
    } else {
        println!("管理 API HTTPS：复用 server.crt / server.key（server-auth，不要求客户端证书）");
        println!("  证书 SAN 必须包含管理端访问地址；变更 server_names 后需执行 rotate-cert。");
    }
    println!("管理 API token: {}", cfg.admin_token);
    println!("  面板/脚本访问管理 API 时使用 Authorization: Bearer <token>；");
    println!("  可随时用 `rustboard-hub admin-token` 查看（为空时会重新生成）。");
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
    println!(
        "  本机: {}://127.0.0.1:{admin_port}",
        match cfg.admin_tls {
            AdminTlsMode::Off => "http",
            AdminTlsMode::Required => "https",
        }
    );
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

/// 立即用 CA 重签服务端证书，供运维手工触发。
///
/// 运行中的 hub 把 TLS 配置缓存在内存里（每条新连接读一次 watch），
/// 所以重签只影响磁盘：必须重启 hub 才会用新证书握手。
///
/// 走文件级签发（[`cert_rotation::renew_server_cert_files`]），不依赖当前 TLS 配置，
/// 因此 key/cert 已经不配套时也能用它修复。
fn rotate_cert(config: Option<PathBuf>, force: bool, days: Option<u32>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    let dir = tls::cert_dir(&cfg.data_dir);
    let cert_path = dir.join(tls::SERVER_CERT_FILE);

    // KI-11：整个 rotate 过程持文件锁，第二个并发进程立即失败且不写证书。
    let _lock = cert_rotation::CertLock::acquire(&dir).context("获取 rotate-cert 文件锁失败")?;

    // 证书缺失时允许用 --force 直接补签（修复场景），不带 --force 仍要求先 init。
    let old_pem = match std::fs::read_to_string(&cert_path) {
        Ok(pem) => Some(pem),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && force => {
            println!("服务端证书不存在：将直接用 CA 补签一对新的证书与私钥。");
            None
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "读取服务端证书失败: {}（先执行 rustboard-hub init，或加 --force 直接补签）",
                    cert_path.display()
                )
            })
        }
    };
    let old_not_after = old_pem.as_deref().map(tls::not_after_unix).transpose()?;
    let old_days_left = old_pem
        .as_deref()
        .map(|pem| tls::days_left(pem, now_ms()))
        .transpose()?;

    // 默认只在进入续签窗口时重签：无谓的轮换会让仍在使用指纹钉扎的旧 agent 失联。
    if !force {
        let days_left = old_days_left.context("缺少服务端证书：需要加 --force 才能直接补签")?;
        if days_left > i64::from(cfg.renew_before_days) {
            println!(
                "当前证书剩余 {days_left} 天，高于续签阈值 {} 天，未重签。",
                cfg.renew_before_days
            );
            println!("确认要立即轮换请加 --force（旧版指纹钉扎的 agent 会因此失联，需要升级）。");
            return Ok(());
        }
    }

    println!("重签只改磁盘；运行中的 hub 会在 ≤15s 内自动热加载，无需重启。");

    // 文件级签发：内部先做 CA/SAN/新证书自检，全部通过后才成对备份并写盘，
    // 失败路径不会留下无意义的备份；也不读旧 TLS 配置，key/cert 不配套时同样可用。
    let renewed =
        cert_rotation::renew_server_cert_files(&cfg, true, days)?.context("重签没有产生新证书")?;
    // 自检新文件：确保写出的 key/cert 配套且能被 rustls 接受。
    tls::server_config(&cfg.data_dir).context("重签后的证书/私钥无法被 rustls 接受")?;

    for backup in &renewed.backup_paths {
        let name = backup
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.contains(".key.") {
            println!("旧私钥已备份: {}（0600）", backup.display());
        } else {
            println!("旧证书已备份: {}", backup.display());
        }
    }
    match old_not_after {
        Some(not_after) => println!(
            "旧证书指纹: {}（到期 {}）",
            renewed.old_fingerprint,
            tls::format_unix_utc(not_after)
        ),
        None => println!("旧证书指纹: {}", renewed.old_fingerprint),
    }
    println!(
        "新证书指纹: {}（到期 {}）",
        renewed.fingerprint,
        tls::format_unix_utc(renewed.not_after)
    );
    println!(
        "运行中的 hub 将在 ≤15s 内自动加载新证书（无需重启；管理端 TLS 会跟随 mTLS 证书切换）；\
         默认（CA 未变）已纳管 agent \
         用 CA 信任会自动重连；若这次轮换同时替换了 CA，所有 agent 必须重新纳管\
         （旧 ca.crt/客户端证书属于旧 CA，会 mTLS 失败）。"
    );
    Ok(())
}

fn run(cfg: HubConfig, db_path: PathBuf) -> Result<()> {
    // 启动前先做配置自洽性校验，避免把明显错误的有效期/检查周期带到运行期。
    cfg.validate().context("hub 配置校验失败")?;
    // common 侧暂不校验采样间隔；hub 启动前本地兜住，避免 Welcome 下发非法值。
    validate_hub_sample_interval(&cfg)?;
    // M2：管理 API 全部要求 Bearer token，空 token 不允许启动。
    require_admin_token(&cfg)?;
    // v0.3.3：非回环管理监听禁止明文；required 时校验绑定 IP 在证书 SAN 内。
    // 必须发生在任何监听 / 证书加载之前。
    validate_admin_tls(&cfg)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        // KI-02：写连接 1 条 + 只读连接池，长查询不再阻塞写入与心跳。
        let storage = Arc::new(SqliteStorage::open_with_readers(
            &db_path,
            cfg.read_pool_size,
        )?);
        tracing::info!(db = %db_path.display(), read_pool_size = cfg.read_pool_size, "存储已就绪");

        // L5：监听前清掉上次异常退出遗留的 online，避免面板长期显示假在线。
        let reset = storage
            .reset_online_status()
            .context("启动时重置在线状态失败")?;
        if reset > 0 {
            tracing::info!(count = reset, "启动时已将残留的 online 状态重置为 offline");
        }

        // M3：审计保留 180 天，启动时先清一次过期记录（运行期每 1000 条再清）。
        let audit_cutoff = now_ms().saturating_sub(AUDIT_RETENTION_MS);
        match storage.prune_audit(audit_cutoff) {
            Ok(0) => {}
            Ok(removed) => tracing::info!(removed, "启动时已清理过期审计记录"),
            Err(err) => tracing::warn!(error = %err, "启动时清理过期审计记录失败"),
        }

        // 升级路径：旧安装的 ca.key / server.key 可能是 0644
        tls::harden_hub_material(&cfg.data_dir)?;
        // 启动自愈：上次续签在写盘中途被中断时，key/cert 会不配套，
        // 直接构建配置会永久失败；这里用 CA 强制重签一对再继续。
        let tls_config = cert_rotation::load_or_repair_tls_config(&cfg)?;
        // KI-10：记录初始监听器证书摘要，供 `/api/v1/system` 区分 live 与 disk。
        let initial_cert = cert_rotation::read_disk_cert_status(&cfg)
            .context("读取服务端证书摘要失败（监听器已加载但状态不可读）")?;
        let live_cert = Arc::new(RwLock::new(initial_cert));
        let fingerprint = {
            let pem =
                std::fs::read_to_string(tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE))?;
            tls::fingerprint_of_pem(&pem)?
        };
        tracing::info!(fingerprint, "TLS 已启用");
        // 管理端 watcher 以「启动时实际构建配置的证书」为基线，而不是启动后读 live：
        // 避免极端竞态下把启动后才切换的指纹误当成已加载。
        let initial_admin_fingerprint = fingerprint.clone();

        let sessions = SessionRegistry::new();
        let state = AppState {
            storage: storage.clone(),
            cfg: Arc::new(cfg.clone()),
            sessions: sessions.clone(),
            session_slots: Arc::new(tokio::sync::Semaphore::new(cfg.max_connections.max(1))),
            renewal: RenewalContext::new(
                tls::cert_dir(&cfg.data_dir),
                cfg.client_cert_validity_days,
            ),
            live_cert: live_cert.clone(),
            admin_rate: Arc::new(AdminRateLimiter::from_config(&cfg)),
            auth_failures: Arc::new(AuthFailureLimiter::new(
                cfg.admin_auth_failure_limit_per_min,
            )),
        };

        spawn_revoke_watcher(storage.clone(), sessions);

        // 服务端证书续签：每 `cert_check_interval_secs` 检查一次，需要时重签并把新的
        // rustls 配置推进 watch；accept 循环每条新连接读一次，老连接不受影响。
        let (tls_tx, tls_rx) = watch::channel(tls_config);
        cert_rotation::spawn_server_renewal(state.cfg.clone(), tls_tx.clone(), live_cert.clone());
        // KI-10：每 10s 轮询磁盘证书，运行中 rotate 后 mTLS ≤10s 热加载；
        // 管理端 watcher 每 2s 跟随 live_cert，合计最迟约 12s（对外承诺 ≤15s）。
        cert_rotation::spawn_cert_file_watcher(state.cfg.clone(), tls_tx, live_cert.clone());

        // v0.3.3：管理端可选 HTTPS。复用 agent 入口的 server.crt/server.key，
        // 但为 server-auth（不要求客户端证书）；watcher 轮询 live_cert 指纹，
        // 换证成功后新连接使用新配置，构建失败保留旧配置。
        let admin_tls = match cfg.admin_tls {
            AdminTlsMode::Off => None,
            AdminTlsMode::Required => {
                let config = tls::admin_server_config(&cfg.data_dir, &cfg.server_names)
                    .context("构建管理 API TLS 配置失败")?;
                let (admin_tx, admin_rx) = watch::channel(config);
                spawn_admin_tls_watcher(
                    state.cfg.clone(),
                    admin_tx,
                    live_cert.clone(),
                    initial_admin_fingerprint.clone(),
                );
                Some(admin_rx)
            }
        };

        if cfg.self_monitor {
            spawn_self_monitor(storage.clone(), cfg.clone());
        }

        let agent_app = Router::new()
            .route("/agent/ws", get(agent_ws))
            .with_state(state.clone());

        // `/healthz` 免鉴权；`/api/v1/*` 统一挂 Bearer 中间件。
        let admin_app = admin_router(state);

        let agent_addr = cfg.agent_listen.clone();
        let admin_addr = cfg.admin_listen.clone();
        tracing::info!(%agent_addr, "agent 接入监听（TLS）");
        match cfg.admin_tls {
            AdminTlsMode::Off => {
                tracing::info!(%admin_addr, "管理 API 监听（HTTP，仅回环）");
            }
            AdminTlsMode::Required => {
                tracing::info!(%admin_addr, "管理 API 监听（HTTPS，server-auth）");
            }
        }

        tokio::try_join!(
            serve_tls(
                agent_app,
                agent_addr,
                tls_rx,
                cfg.max_connections,
                cfg.max_connections_per_ip
            ),
            serve(admin_app, admin_addr, admin_tls)
        )?;
        Ok(())
    })
}

/// 管理监听是否绑在非回环地址；解析失败与 bind 一样视为启动错误。
///
/// 回环范围沿用 `IpAddr::is_loopback`（IPv4 127.0.0.0/8、IPv6 ::1）。
fn admin_listen_is_non_loopback(addr: &str) -> Result<bool> {
    let sock: SocketAddr = addr
        .parse()
        .with_context(|| format!("管理 API 监听地址非法: {addr}"))?;
    Ok(!sock.ip().is_loopback())
}

/// 启动前校验管理 API 的传输安全；任何失败都发生在监听之前。
///
/// - `off` 只允许回环：非回环直接拒绝（v0.3.3 有意的安全收紧）。
/// - `required`：绑定 IP 在 `server_names` 里（比较前 trim），或管理端可通过
///   `server_names` 里的 DNS 名访问；两者都不满足时提示先更新 server_names 再
///   rotate-cert。`0.0.0.0` / `::` 通配绑定跳过精确检查。
fn validate_admin_tls(cfg: &HubConfig) -> Result<()> {
    let sock: SocketAddr = cfg
        .admin_listen
        .parse()
        .with_context(|| format!("管理 API 监听地址非法: {}", cfg.admin_listen))?;
    match cfg.admin_tls {
        AdminTlsMode::Off => {
            if !sock.ip().is_loopback() {
                bail!(
                    "admin_tls=\"off\" 只允许管理 API 绑定回环地址（127.0.0.0/8、::1），\
                     当前为 {}；请改用 admin_tls=\"required\"，或只绑回环 + TLS 反向代理",
                    cfg.admin_listen
                );
            }
        }
        AdminTlsMode::Required => {
            let ip = sock.ip();
            if ip.is_unspecified() {
                // 通配绑定不知道客户端用哪个地址访问，跳过精确 SAN 检查；但如果
                // server_names 只有回环名，远端客户端必然校验证书失败，提前告警。
                if all_loopback_server_names(&cfg.server_names) {
                    tracing::warn!(
                        "管理 API 使用通配绑定，但 server_names 全部是回环名；\
                         远端客户端校验证书会失败，请补充可访问的 IP / DNS SAN 后执行 rotate-cert"
                    );
                }
                return Ok(());
            }
            let names: Vec<&str> = cfg
                .server_names
                .iter()
                .map(|name| name.trim())
                .filter(|name| !name.is_empty())
                .collect();
            let covered = names.iter().any(|name| {
                name.parse::<IpAddr>()
                    .is_ok_and(|candidate| candidate == ip)
            });
            // 也允许管理端通过 DNS 访问：bind IP 不必出现在 SAN 里，证书覆盖实际
            // 访问的 DNS 名即可。回环绑定不适用（DNS 名无法指到 127.x），仍要求
            // 精确 IP SAN，避免 init 产出无法本机访问的配置。
            let dns_covered =
                !ip.is_loopback() && names.iter().any(|name| name.parse::<IpAddr>().is_err());
            if !covered && !dns_covered {
                bail!(
                    "admin_tls=\"required\" 且管理 API 绑定 {ip}，但 server_names 中既没有该 IP SAN、\
                     也没有可用于远端访问的 DNS SAN；请先把 {ip}（或管理端 DNS 名）加入 \
                     server_names，再执行 `rustboard-hub rotate-cert --force` 重签服务端证书"
                );
            }
        }
    }
    Ok(())
}

/// server_names 是否全部是回环名（127.0.0.0/8、::1、localhost / *.localhost）。
fn all_loopback_server_names(names: &[String]) -> bool {
    !names.is_empty()
        && names.iter().all(|name| {
            let name = name.trim();
            name.parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or_else(|_| {
                    name.eq_ignore_ascii_case("localhost")
                        || name.to_ascii_lowercase().ends_with(".localhost")
                })
        })
}

async fn serve(
    app: Router,
    addr: String,
    tls: Option<watch::Receiver<Arc<rustls::ServerConfig>>>,
) -> Result<()> {
    let sock: SocketAddr = addr
        .parse()
        .with_context(|| format!("管理 API 监听地址非法: {addr}"))?;
    let listener = TcpListener::bind(sock)
        .await
        .with_context(|| format!("监听 {sock} 失败"))?;
    serve_admin_listener(app, listener, tls).await
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

/// 管理 API 的 accept 循环（KI-17）。
///
/// 不用 `axum::serve`：它没有 header 读超时，也拿不到连接数。这里手工 accept，
/// 与 agent 的 mTLS 入口同款地做「全局 + 每来源 IP」并发限制、HTTP/1 header 超时，
/// 保证半截 header 的慢连接最多占用 [`HEADER_READ_TIMEOUT`]，洪水下 `/healthz` 仍可用。
///
/// `tls` 为 `Some` 时每条新连接先做 TLS 握手（10s 超时），底层流随后交给
/// [`serve_admin_connection`]；`None` 保持原有明文 HTTP 行为。
async fn serve_admin_listener(
    app: Router,
    listener: TcpListener,
    tls: Option<watch::Receiver<Arc<rustls::ServerConfig>>>,
) -> Result<()> {
    let sock = listener.local_addr().context("读取管理 API 监听地址失败")?;
    let permits = Arc::new(Semaphore::new(ADMIN_MAX_CONNECTIONS.max(1)));
    let limits = Arc::new(ConnectionLimiter::new(ADMIN_MAX_CONNECTIONS_PER_IP));
    tracing::info!(
        %sock,
        tls = tls.is_some(),
        max_connections = ADMIN_MAX_CONNECTIONS,
        max_connections_per_ip = ADMIN_MAX_CONNECTIONS_PER_IP,
        "管理 API 连接限制已启用"
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                // 单个 accept 失败（例如 fd 瞬时耗尽）不应让整个 hub 退出。
                tracing::warn!(error = %err, "管理 API accept 失败，100ms 后重试");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };

        // KI-17：先占全局槽位，拿不到立即关 TCP（不读请求、不回响应）。
        let permit = match try_acquire_connection(&permits) {
            Some(permit) => permit,
            None => {
                tracing::warn!(
                    %peer,
                    max_connections = ADMIN_MAX_CONNECTIONS,
                    "管理 API 连接数已达上限，直接关闭 TCP"
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
                    "管理 API 来源 IP 并发连接已达上限，直接关闭 TCP"
                );
                continue;
            }
            Err(ConnectionLimitRejection::TableFull) => {
                tracing::warn!(ip = %peer.ip(), "管理 API 连接来源表已满，拒绝新来源");
                continue;
            }
        };

        if let Err(err) = tcp.set_nodelay(true) {
            tracing::debug!(%peer, error = %err, "设置 TCP_NODELAY 失败");
        }

        let app = app.clone();
        // 每条新连接取一次最新 TLS 配置：watcher 换证只影响之后的新连接。
        let tls_rx = tls.clone();
        tokio::spawn(async move {
            // 许可跟随连接生命周期；连接关闭（含超时）后自动归还。
            let _permit = permit;
            let _connection = connection;

            match tls_rx {
                None => serve_admin_connection(tcp, peer, app).await,
                Some(rx) => {
                    let config = rx.borrow().clone();
                    let acceptor = TlsAcceptor::from(config);
                    let stream = match tokio::time::timeout(
                        ADMIN_TLS_HANDSHAKE_TIMEOUT,
                        acceptor.accept(tcp),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        // 明文请求打到 HTTPS 端口、SNI/ALPN 错误等都只记 debug：
                        // 未认证连接的错误细节不应进入 info 日志。
                        Ok(Err(err)) => {
                            tracing::debug!(%peer, error = %err, "管理 API TLS 握手失败");
                            return;
                        }
                        Err(_) => {
                            tracing::debug!(%peer, "管理 API TLS 握手超时");
                            return;
                        }
                    };
                    serve_admin_connection(stream, peer, app).await;
                }
            }
        });
    }
}

/// 明文 TCP 与 TLS 流共用的管理连接服务。
///
/// 负责逐请求注入 `ConnectInfo<SocketAddr>`、套一次性 body deadline，并用 hyper
/// HTTP/1 跑 axum。TLS 握手与 TLS 配置选择由调用方在 accept 循环完成。
async fn serve_admin_connection<S>(stream: S, peer: SocketAddr, app: Router)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // KI-05：管理限速 / 鉴权依赖 ConnectInfo<SocketAddr>，逐请求注入。
    // KI-17：请求体套一次性总 deadline，慢 body 最多占 10s，不随 frame 重置。
    let service = tower::service_fn(move |req: Request<Incoming>| {
        let (mut parts, incoming) = req.into_parts();
        parts.extensions.insert(ConnectInfo(peer));
        let body = Body::new(DeadlineBody::new(incoming, BODY_READ_TIMEOUT));
        let req = Request::from_parts(parts, body);
        let app = app.clone();
        async move { app.oneshot(req).await }
    });

    // 与 agent 入口一致：不用 hyper-util 的 auto builder（它有一个无超时的
    // HTTP 版本嗅探阶段）；http1 Builder 只对「读 header」计时，header 超时
    // 不会限制 body（body 由 DeadlineBody 的 10s 总 deadline 单独约束）。
    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
        .with_upgrades()
        .await
    {
        // 只记录来源与错误，不记录请求头。
        tracing::debug!(%peer, error = %err, "管理 API 连接结束");
    }
}

/// 管理端 TLS 热加载 watcher。
///
/// 只跟随 mTLS 监听器已经校验并切换到的 live 证书指纹（2s 轮询），不重复实现磁盘
/// 轮询；指纹变化后用同一对 server.crt/server.key 重建 server-auth 配置并通过 watch
/// 推给 accept 循环。构建失败只 warn（每分钟最多一条）并保留旧配置。
fn spawn_admin_tls_watcher(
    cfg: Arc<HubConfig>,
    tx: watch::Sender<Arc<rustls::ServerConfig>>,
    live: Arc<RwLock<CertStatus>>,
    initial_fingerprint: String,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(ADMIN_TLS_RELOAD_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_fingerprint = initial_fingerprint;
        // 第一次 tick 立即完成：启动路径刚构建并校验过配置，直接跳过。
        ticker.tick().await;

        let mut last_warn: Option<Instant> = None;
        loop {
            ticker.tick().await;
            let check_cfg = cfg.clone();
            let check_tx = tx.clone();
            let check_live = live.clone();
            let last = last_fingerprint.clone();
            let result = tokio::task::spawn_blocking(move || {
                reload_admin_tls_if_changed(&check_cfg, &check_tx, &check_live, &last)
            })
            .await;

            match result {
                Ok(Ok(Some(fingerprint))) => {
                    last_fingerprint = fingerprint;
                    tracing::info!(
                        fingerprint = %last_fingerprint,
                        "管理 API TLS 证书已热加载（新连接生效）"
                    );
                }
                Ok(Ok(None)) => {}
                Ok(Err(err)) => {
                    if should_warn_admin_tls(&mut last_warn) {
                        tracing::warn!(
                            error = %format!("{err:#}"),
                            "管理 API TLS 证书热加载失败，保留旧配置（每分钟最多告警一次）"
                        );
                    }
                }
                Err(err) => {
                    if should_warn_admin_tls(&mut last_warn) {
                        tracing::warn!(error = %err, "管理 API TLS 热加载任务失败，下个周期重试");
                    }
                }
            }
        }
    });
}

fn live_fingerprint(live: &RwLock<CertStatus>) -> String {
    live.read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .fingerprint
        .clone()
}

/// 管理端 TLS 失败告警节流：返回 `true` 表示本次应告警并记录时间。
fn should_warn_admin_tls(last_warn: &mut Option<Instant>) -> bool {
    let now = Instant::now();
    match last_warn {
        Some(last) if now.duration_since(*last) < ADMIN_TLS_RELOAD_WARN_INTERVAL => false,
        _ => {
            *last_warn = Some(now);
            true
        }
    }
}

/// 一次管理端 TLS 热加载尝试（独立函数便于单测）。
///
/// `last_fingerprint` 是 accept 循环当前配置对应的证书指纹；仅在 live 指纹变化且
/// 新配置构建成功时推送，并返回新指纹。构建失败返回 `Err`，调用方保留旧配置。
fn reload_admin_tls_if_changed(
    cfg: &HubConfig,
    tx: &watch::Sender<Arc<rustls::ServerConfig>>,
    live: &RwLock<CertStatus>,
    last_fingerprint: &str,
) -> Result<Option<String>> {
    let current = live_fingerprint(live);
    if current == last_fingerprint {
        return Ok(None);
    }
    let config = tls::admin_server_config(&cfg.data_dir, &cfg.server_names)
        .context("管理 API TLS 配置构建失败")?;
    // 构建期间证书可能又被 rotate：与 mTLS 热加载一致，本周期跳过，下周期重试。
    let confirmed = cert_rotation::read_disk_cert_status(cfg)?;
    if confirmed.fingerprint != current {
        tracing::debug!("证书在管理端热加载过程中再次变化，本周期跳过");
        return Ok(None);
    }
    tx.send_replace(config);
    Ok(Some(confirmed.fingerprint))
}

/// 组装管理 API：`/healthz` 放行，`/api/v1/*` 统一 Bearer 鉴权 + 限速 + 64 KiB 请求体上限。
fn admin_router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/system", get(system_info))
        .route("/api/v1/agents", get(list_agents))
        .route("/api/v1/series", get(query_series))
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/agents/{id}/latest", get(agent_latest))
        .route("/api/v1/agents/{id}/series", get(agent_series))
        .route(
            "/api/v1/agents/{id}/settings",
            get(get_settings).put(put_settings),
        )
        // M3 控制面：GET 读能力状态（不写审计），POST 执行动作（每次写审计）。
        .route(
            "/api/v1/agents/{id}/control",
            get(control::control_status).post(control::control_action),
        )
        // 审计只读接口。
        .route("/api/v1/audit", get(control::audit_list))
        // KI-08：未知 /api/v1/* 也要先过 Bearer 再 404，不能泄露路由是否存在。
        .route("/api/v1", any(api_not_found))
        .route("/api/v1/{*rest}", any(api_not_found))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    Router::new()
        .route("/healthz", get(healthz))
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_ADMIN_BODY_SIZE))
        .layer(middleware::from_fn(no_store))
        .with_state(state)
}

/// 受保护路由树的兜底：走到这里说明认证（与限速）已经通过，只是路由不存在。
async fn api_not_found() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": "not_found" })),
    )
}

/// 管理 API 全部响应禁止缓存（含 token 的 401 与实时指标）。
async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// 固定窗口计数：`started_at` 为窗口起点（Unix 毫秒），`count` 为本窗口请求数。
#[derive(Debug, Clone, Copy, Default)]
struct RateWindow {
    started_at: i64,
    count: u32,
}

/// 管理 API 的每 IP 固定窗口限速（KI-05）。
///
/// 读写操作分开计数：普通 GET 默认 60/min，写操作（PUT/POST/PATCH/DELETE）
/// 默认 10/min。`0` 表示对应类别关闭限速。限速表有容量上限，满时先清理过期
/// 窗口；仍然满则拒绝新 IP（此时同一个 token 已在极多来源使用，属于攻击迹象）。
struct AdminRateLimiter {
    read_limit: u32,
    write_limit: u32,
    windows: StdMutex<HashMap<IpAddr, AdminWindows>>,
    /// 可注入时钟，单测覆盖窗口边界。
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

#[derive(Debug, Clone, Copy, Default)]
struct AdminWindows {
    read: RateWindow,
    write: RateWindow,
}

impl AdminWindows {
    fn is_expired(&self, now: i64) -> bool {
        let expired = |window: &RateWindow| {
            // started_at == 0 表示该类别从未使用，可随另一侧过期一起清理。
            window.started_at == 0 || now.saturating_sub(window.started_at) >= ADMIN_RATE_WINDOW_MS
        };
        expired(&self.read) && expired(&self.write)
    }
}

impl AdminRateLimiter {
    fn new(read_limit: u32, write_limit: u32) -> Self {
        Self::with_clock(
            read_limit,
            write_limit,
            Arc::new(rustboard_common::util::now_ms),
        )
    }

    fn from_config(cfg: &HubConfig) -> Self {
        Self::new(
            cfg.admin_rate_limit_per_min,
            cfg.admin_write_rate_limit_per_min,
        )
    }

    fn with_clock(
        read_limit: u32,
        write_limit: u32,
        now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self {
            read_limit,
            write_limit,
            windows: StdMutex::new(HashMap::new()),
            now_ms,
        }
    }

    /// 记录一次请求；超限返回需要等待的秒数（用于 `Retry-After`）。
    fn check(&self, ip: IpAddr, is_write: bool) -> std::result::Result<(), u64> {
        let limit = if is_write {
            self.write_limit
        } else {
            self.read_limit
        };
        if limit == 0 {
            return Ok(());
        }
        let now = (self.now_ms)();
        let mut windows = match self.windows.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !windows.contains_key(&ip) {
            if windows.len() >= ADMIN_RATE_TABLE_CAPACITY {
                windows.retain(|_, entry| !entry.is_expired(now));
                if windows.len() >= ADMIN_RATE_TABLE_CAPACITY {
                    tracing::warn!(
                        %ip,
                        capacity = ADMIN_RATE_TABLE_CAPACITY,
                        "管理 API 限速表已满且无过期项，拒绝新来源"
                    );
                    return Err(ADMIN_RATE_WINDOW_MS as u64 / 1_000);
                }
            }
            windows.insert(ip, AdminWindows::default());
        }

        let entry = windows.get_mut(&ip).expect("上一步已插入");
        let window = if is_write {
            &mut entry.write
        } else {
            &mut entry.read
        };
        if window.started_at == 0 || now.saturating_sub(window.started_at) >= ADMIN_RATE_WINDOW_MS {
            window.started_at = now;
            window.count = 0;
        }
        if window.count >= limit {
            let elapsed = now.saturating_sub(window.started_at);
            let remaining = (ADMIN_RATE_WINDOW_MS - elapsed).max(0);
            // 向上取整到秒，至少 1 秒。
            return Err(((remaining + 999) / 1_000).max(1) as u64);
        }
        window.count += 1;
        Ok(())
    }

    /// 当前记录的来源数量（测试 / 排障）。
    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        match self.windows.lock() {
            Ok(guard) => guard.len(),
            Err(poisoned) => poisoned.into_inner().len(),
        }
    }
}

fn is_admin_write_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// 单 IP 并发连接计数（KI-01）。
///
/// 设计取舍（第六轮评审）：不再设置独立的「未认证阶段预留信号量」。
/// 合法 agent 的 TLS 握手同样需要经过未认证阶段，额外的小额度信号量在
/// 空闲连接洪水下会先把合法握手挡在门外，而全局 `max_connections` 仍有空槽，
/// 净效果是更差的可用性。因此这里只做「每来源 IP 上限」，配合：
/// - 全局 `max_connections`（accept 后立即占用，已建立会话持有到结束）；
/// - TLS 握手 / HTTP header 超时收紧到 5s（慢速连接最多占用 5s）。
///
/// 单 IP 洪水最多占 `max_connections_per_ip` 个全局槽位，且在超时后释放；
/// 已建立会话不会被同 IP 的新连接直接挤掉（它们各自持有全局许可）。
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

/// H2：尝试占用一个连接许可；返回 None 表示已达上限，调用方应关闭 TCP。
fn try_acquire_connection(permits: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    permits.clone().try_acquire_owned().ok()
}

async fn serve_tls(
    app: Router,
    addr: String,
    config: watch::Receiver<Arc<rustls::ServerConfig>>,
    max_connections: usize,
    max_connections_per_ip: usize,
) -> Result<()> {
    let sock: SocketAddr = addr
        .parse()
        .with_context(|| format!("监听地址非法: {addr}"))?;
    let listener = TcpListener::bind(sock)
        .await
        .with_context(|| format!("监听 {sock} 失败"))?;
    // H2：用信号量限制同时处理的 TLS 连接数；拿不到许可就立刻关 TCP。
    let max_connections = max_connections.max(1);
    let permits = Arc::new(Semaphore::new(max_connections));
    let limits = Arc::new(ConnectionLimiter::new(max_connections_per_ip));
    tracing::info!(
        %sock,
        max_connections,
        max_connections_per_ip,
        "agent 接入监听（mTLS）"
    );

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

        // KI-01：来源 IP 维度的并发上限；计数随连接生命周期自动归还。
        let connection = match limits.try_acquire(peer.ip()) {
            Ok(connection) => connection,
            Err(ConnectionLimitRejection::PerIp) => {
                tracing::warn!(
                    ip = %peer.ip(),
                    max_connections_per_ip,
                    "来源 IP 并发连接已达上限，直接关闭 TCP"
                );
                continue;
            }
            Err(ConnectionLimitRejection::TableFull) => {
                tracing::warn!(
                    ip = %peer.ip(),
                    "连接来源表已满，拒绝新来源"
                );
                continue;
            }
        };

        if let Err(err) = tcp.set_nodelay(true) {
            tracing::debug!(%peer, error = %err, "设置 TCP_NODELAY 失败");
        }

        // 续签任务是唯一写入者；这里每条新连接取一次当前配置。
        // `borrow().clone()` 只复制 Arc，取值后立刻释放读锁，不跨 await 持有。
        let acceptor = TlsAcceptor::from(config.borrow().clone());
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
            // 握手成功；连接许可（全局 + per-IP）继续持有到会话结束。
            let _connection = connection;

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

/// `/api/v1/system` 的响应：版本、协议与**公开**的服务端证书信息。
///
/// M2 起所有 `/api/v1/*` 都在 [`admin_router`] 的 Bearer 中间件之后；
/// 字段里只有证书指纹与有效期，没有私钥。
#[derive(serde::Serialize)]
struct SystemInfo {
    version: &'static str,
    protocol: u16,
    server_time: i64,
    cert: CertInfo,
}

/// 证书状态：顶层字段保持旧版含义（= live），`live`/`disk` 供排障区分。
///
/// KI-10：运行中 rotate 后磁盘先变、监听器后热加载；旧面板只读顶层字段
/// 时也必须看到监听器实际在用的证书，而不是磁盘上尚未生效的新证书。
#[derive(serde::Serialize)]
struct CertInfo {
    fingerprint: String,
    /// Unix 秒。
    not_after: i64,
    days_left: i64,
    /// 监听器当前实际使用的证书。
    live: CertStatus,
    /// 请求时刻磁盘上的证书。
    disk: CertStatus,
}

/// 运维排障入口：`cert.live` 是监听器实际证书，`cert.disk` 是磁盘文件；
/// 顶层 `cert.fingerprint/not_after/days_left` 始终等于 live（向后兼容）。
async fn system_info(State(state): State<AppState>) -> Result<Json<SystemInfo>, ApiError> {
    let cert_dir = tls::cert_dir(&state.cfg.data_dir);
    let disk = tokio::task::spawn_blocking(move || {
        let cert_path = cert_dir.join(tls::SERVER_CERT_FILE);
        let pem = std::fs::read_to_string(&cert_path)?;
        CertStatus::from_pem(&pem)
    })
    .await
    .map_err(ApiError::from)??;

    let now = now_ms();
    let live = state
        .live_cert
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        // days_left 在请求时重算：live 只在证书变化时更新，不能冻结加载时的天数。
        .with_current_days_left(now);

    Ok(Json(SystemInfo {
        version: VERSION,
        protocol: PROTOCOL_VERSION,
        server_time: now,
        cert: CertInfo {
            fingerprint: live.fingerprint.clone(),
            not_after: live.not_after,
            days_left: live.days_left,
            live,
            disk,
        },
    }))
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

#[derive(serde::Serialize)]
struct OverviewResponse {
    server_time: i64,
    agents: Vec<AgentRecord>,
    latest: Vec<AgentSeriesRow>,
    settings: Vec<AgentSetting>,
}

/// `overview` 一次查询需要的数据：agent 列表、最新点、显式采样间隔。
type OverviewSnapshot = (Vec<AgentRecord>, Vec<AgentSeriesRow>, Vec<(String, u64)>);

#[derive(serde::Serialize)]
struct AgentSetting {
    agent_id: String,
    sample_interval_ms: u64,
}

#[derive(serde::Deserialize)]
struct UpdateSettingsRequest {
    sample_interval_ms: u64,
}

/// `GET /api/v1/overview`：agent 列表 + 关键指标最新值 + 每台 agent 的有效采样间隔。
async fn overview(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
) -> Result<Json<OverviewResponse>, ApiError> {
    let pairs = parse_query_pairs(raw.as_deref()).map_err(ApiError::bad_request)?;
    // 固定 60s 上限；允许 1s–60s 并真正用于最新点查询（前端固定带 window_ms=60000）。
    let window_ms = parse_window_ms_between(
        &pairs,
        OVERVIEW_WINDOW_MS,
        OVERVIEW_MIN_WINDOW_MS,
        OVERVIEW_MAX_WINDOW_MS,
    )
    .map_err(ApiError::bad_request)?;

    let default_interval = state.cfg.sample_interval_ms;
    let (agents, latest, intervals) = tokio::task::spawn_blocking({
        let storage = state.storage.clone();
        move || -> Result<OverviewSnapshot> {
            let metrics: Vec<String> = OVERVIEW_METRICS.iter().map(|m| m.to_string()).collect();
            let since = now_ms() - window_ms;
            Ok((
                storage.list_agents()?,
                storage.latest_samples(since, &metrics, None)?,
                storage.list_sample_intervals()?,
            ))
        }
    })
    .await
    .map_err(ApiError::from)??;

    let explicit: HashMap<&str, u64> = intervals
        .iter()
        .map(|(agent_id, ms)| (agent_id.as_str(), *ms))
        .collect();
    let settings = agents
        .iter()
        .map(|agent| AgentSetting {
            agent_id: agent.agent_id.clone(),
            sample_interval_ms: explicit
                .get(agent.agent_id.as_str())
                .copied()
                .filter(|ms| *ms > 0)
                .unwrap_or(default_interval),
        })
        .collect();

    Ok(Json(OverviewResponse {
        server_time: now_ms(),
        agents,
        latest,
        settings,
    }))
}

/// `GET /api/v1/agents/{id}/latest`：该机每个序列的最新点。
async fn agent_latest(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Json<Vec<AgentSeriesRow>>, ApiError> {
    validate_agent_path(&agent_id)?;
    let pairs = parse_query_pairs(raw.as_deref()).map_err(ApiError::bad_request)?;
    let window_ms =
        parse_window_ms(&pairs, LATEST_DEFAULT_WINDOW_MS).map_err(ApiError::bad_request)?;
    let since = now_ms() - window_ms;

    // 与 settings 一致：不存在的 agent 返回 404，避免把「没有数据」伪装成空数组。
    let rows = tokio::task::spawn_blocking(move || -> Result<Option<Vec<AgentSeriesRow>>> {
        if state.storage.get_agent(&agent_id)?.is_none() {
            return Ok(None);
        }
        Ok(Some(state.storage.latest_samples(
            since,
            &[],
            Some(&agent_id),
        )?))
    })
    .await
    .map_err(ApiError::from)??;
    let Some(rows) = rows else {
        return Err(ApiError::not_found("agent 不存在"));
    };
    Ok(Json(rows))
}

#[derive(serde::Serialize)]
struct SeriesResponse {
    bucket_ms: i64,
    series: Vec<SeriesEntry>,
}

#[derive(serde::Serialize)]
struct SeriesEntry {
    metric: String,
    labels: Labels,
    points: Vec<(i64, f64)>,
}

/// `GET /api/v1/agents/{id}/series`：多指标 + 服务端按桶聚合。
async fn agent_series(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    RawQuery(raw): RawQuery,
) -> Result<Json<SeriesResponse>, ApiError> {
    validate_agent_path(&agent_id)?;
    let parsed = parse_series_query(raw.as_deref()).map_err(ApiError::bad_request)?;
    let bucket_ms = parsed.bucket_ms;
    let query = SeriesQuery {
        agent_id,
        metrics: parsed.metrics,
        from: parsed.from,
        to: parsed.to,
        // 多取一条，交给上层判断是否超过 20000 点上限。
        limit: u32::try_from(MAX_SERIES_POINTS + 1).unwrap_or(u32::MAX),
    };

    // 与 settings 一致：不存在的 agent 返回 404；存在性检查与查询放在同一次
    // spawn_blocking 里，避免两次往返之间 agent 被删除造成不一致。
    let rows = tokio::task::spawn_blocking(move || -> Result<Option<Vec<SeriesRow>>> {
        if state.storage.get_agent(&query.agent_id)?.is_none() {
            return Ok(None);
        }
        Ok(Some(
            state.storage.query_series_bucketed(&query, bucket_ms)?,
        ))
    })
    .await
    .map_err(ApiError::from)??;
    let Some(rows) = rows else {
        return Err(ApiError::not_found("agent 不存在"));
    };
    let response = build_series_response(bucket_ms, rows).map_err(ApiError::bad_request)?;
    Ok(Json(response))
}

/// `GET /api/v1/agents/{id}/settings`：显式间隔，未配置过则回退 hub 默认值。
async fn get_settings(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentSetting>, ApiError> {
    validate_agent_path(&agent_id)?;
    let default_interval = state.cfg.sample_interval_ms;

    let effective = tokio::task::spawn_blocking({
        let storage = state.storage.clone();
        let agent_id = agent_id.clone();
        move || -> Result<Option<u64>> {
            if storage.get_agent(&agent_id)?.is_none() {
                return Ok(None);
            }
            let ms = storage
                .get_sample_interval(&agent_id)?
                .filter(|ms| *ms > 0)
                .unwrap_or(default_interval);
            Ok(Some(ms))
        }
    })
    .await
    .map_err(ApiError::from)??;

    let Some(sample_interval_ms) = effective else {
        return Err(ApiError::not_found("agent 不存在"));
    };
    Ok(Json(AgentSetting {
        agent_id,
        sample_interval_ms,
    }))
}

/// `PUT /api/v1/agents/{id}/settings`：校验 → 落库 → 踢活跃会话触发重连。
async fn put_settings(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
    body: Result<Json<UpdateSettingsRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<AgentSetting>, ApiError> {
    validate_agent_path(&agent_id)?;
    let Json(request) = body.map_err(|rejection| {
        if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
            ApiError::PayloadTooLarge
        } else {
            ApiError::bad_request("请求体必须是 {\"sample_interval_ms\": <整数>}")
        }
    })?;
    let sample_interval_ms = request.sample_interval_ms;
    if !(MIN_SAMPLE_INTERVAL_MS..=MAX_SAMPLE_INTERVAL_MS).contains(&sample_interval_ms) {
        return Err(ApiError::bad_request(format!(
            "sample_interval_ms 必须在 {MIN_SAMPLE_INTERVAL_MS}–{MAX_SAMPLE_INTERVAL_MS} 之间"
        )));
    }

    let existed = tokio::task::spawn_blocking({
        let storage = state.storage.clone();
        let agent_id = agent_id.clone();
        move || -> Result<bool> {
            if storage.get_agent(&agent_id)?.is_none() {
                return Ok(false);
            }
            storage.set_sample_interval(&agent_id, sample_interval_ms, now_ms())?;
            Ok(true)
        }
    })
    .await
    .map_err(ApiError::from)??;
    if !existed {
        return Err(ApiError::not_found("agent 不存在"));
    }

    // 间隔已落库；踢掉活跃会话让 agent 立刻重连，在 Welcome 里拿到新值。
    // 没有活跃会话时返回 false，不影响本次修改（下次连接自然生效）。
    let signaled = state.sessions.reconfigure(&agent_id);
    tracing::info!(
        agent = %agent_id,
        sample_interval_ms,
        signaled,
        "采样间隔已更新，已通知活跃会话重连"
    );

    Ok(Json(AgentSetting {
        agent_id,
        sample_interval_ms,
    }))
}

fn validate_agent_path(agent_id: &str) -> Result<(), ApiError> {
    if is_valid_agent_id(agent_id) && agent_id != "." && agent_id != ".." {
        Ok(())
    } else {
        Err(ApiError::bad_request("agent_id 非法"))
    }
}

/// 解析查询串（与 `application/x-www-form-urlencoded` 一致：`+` 表示空格，`%XX` 转义）。
///
/// 不用 `serde_urlencoded` 直接反序列化 struct：它不支持「同名键重复」映射到
/// `Vec<String>`，而 `series?metric=a&metric=b` 正是契约要求的写法。
fn parse_query_pairs(raw: Option<&str>) -> std::result::Result<Vec<(String, String)>, String> {
    let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
        return Ok(Vec::new());
    };
    let mut pairs = Vec::new();
    for part in raw.split('&') {
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = percent_decode(key).ok_or_else(|| "查询参数编码非法".to_string())?;
        let value = percent_decode(value).ok_or_else(|| "查询参数编码非法".to_string())?;
        pairs.push((key, value));
    }
    Ok(pairs)
}

fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hi = hex_nibble(*bytes.get(index + 1)?)?;
                let lo = hex_nibble(*bytes.get(index + 2)?)?;
                out.push((hi << 4) | lo);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 解析 `window_ms`；缺省用 `default`，非法或重复返回 400。
fn parse_window_ms(pairs: &[(String, String)], default: i64) -> std::result::Result<i64, String> {
    parse_window_ms_between(pairs, default, 1, LATEST_MAX_WINDOW_MS)
}

/// 带自定义下限的 `window_ms` 解析（`overview` 最小 1s，`latest` 最小 1ms）。
fn parse_window_ms_between(
    pairs: &[(String, String)],
    default: i64,
    min: i64,
    max: i64,
) -> std::result::Result<i64, String> {
    let mut window = None;
    for (key, value) in pairs {
        match key.as_str() {
            "window_ms" => {
                if window.is_some() {
                    return Err("window_ms 不能重复".to_string());
                }
                let ms: i64 = value
                    .parse()
                    .map_err(|_| "window_ms 必须是整数".to_string())?;
                if !(min..=max).contains(&ms) {
                    return Err(format!("window_ms 必须在 {min}–{max} 之间"));
                }
                window = Some(ms);
            }
            other => return Err(format!("不支持的查询参数: {other}")),
        }
    }
    Ok(window.unwrap_or(default))
}

struct ParsedSeriesQuery {
    metrics: Vec<String>,
    from: i64,
    to: i64,
    bucket_ms: i64,
}

/// `series` 参数校验与自动 bucket 选择（全部为纯函数，便于单测边界）。
fn parse_series_query(raw: Option<&str>) -> std::result::Result<ParsedSeriesQuery, String> {
    let pairs = parse_query_pairs(raw)?;
    let mut metrics = Vec::new();
    let mut from = None;
    let mut to = None;
    let mut bucket_ms = None;

    for (key, value) in pairs {
        match key.as_str() {
            "metric" => metrics.push(value),
            "from" => set_once(&mut from, parse_timestamp("from", &value)?, "from")?,
            "to" => set_once(&mut to, parse_timestamp("to", &value)?, "to")?,
            "bucket_ms" => {
                let ms: i64 = value
                    .parse()
                    .map_err(|_| "bucket_ms 必须是正整数".to_string())?;
                if ms <= 0 {
                    return Err("bucket_ms 必须大于 0".to_string());
                }
                set_once(&mut bucket_ms, ms, "bucket_ms")?;
            }
            other => return Err(format!("不支持的查询参数: {other}")),
        }
    }

    if metrics.is_empty() || metrics.len() > MAX_SERIES_METRICS {
        return Err(format!("metric 数量必须在 1–{MAX_SERIES_METRICS} 之间"));
    }
    for metric in &metrics {
        if !is_valid_metric(metric) {
            return Err(format!(
                "metric 非法（仅允许 [a-z0-9_.-]，长度 1–{MAX_METRIC_LEN}）: {metric}"
            ));
        }
    }

    let from = from.ok_or_else(|| "缺少 from".to_string())?;
    let to = to.ok_or_else(|| "缺少 to".to_string())?;
    if from >= to {
        return Err("from 必须早于 to".to_string());
    }
    let span_ms = to.saturating_sub(from);
    if span_ms > MAX_SERIES_SPAN_MS {
        return Err("时间跨度不能超过 32 天".to_string());
    }

    let bucket_ms = match bucket_ms {
        Some(bucket) => bucket,
        None => auto_bucket_ms(span_ms),
    };
    Ok(ParsedSeriesQuery {
        metrics,
        from,
        to,
        bucket_ms,
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T, name: &str) -> std::result::Result<(), String> {
    if slot.is_some() {
        return Err(format!("{name} 不能重复"));
    }
    *slot = Some(value);
    Ok(())
}

fn parse_timestamp(name: &str, value: &str) -> std::result::Result<i64, String> {
    value
        .parse()
        .map_err(|_| format!("{name} 必须是毫秒时间戳"))
}

fn is_valid_metric(metric: &str) -> bool {
    !metric.is_empty()
        && metric.len() <= MAX_METRIC_LEN
        && metric.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

/// 在方案给出的档位里选「单曲线不超过 1500 点」的最小 bucket。
fn auto_bucket_ms(span_ms: i64) -> i64 {
    AUTO_BUCKETS_MS
        .iter()
        .copied()
        .find(|bucket| span_ms / bucket < MAX_AUTO_BUCKET_POINTS)
        .unwrap_or(21_600_000)
}

/// 把聚合行按 `(metric, labels)` 组装成前端契约；同时兜住序列数与点数上限。
fn build_series_response(
    bucket_ms: i64,
    rows: Vec<SeriesRow>,
) -> std::result::Result<SeriesResponse, String> {
    if rows.len() > MAX_SERIES_POINTS {
        return Err(format!("返回点数超过 {MAX_SERIES_POINTS} 上限"));
    }

    let mut grouped: BTreeMap<(String, Labels), Vec<(i64, f64)>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry((row.metric, row.labels))
            .or_default()
            .push((row.ts, row.value));
    }
    if grouped.len() > MAX_SERIES_COUNT {
        return Err(format!("序列数量超过 {MAX_SERIES_COUNT} 上限"));
    }

    let series = grouped
        .into_iter()
        .map(|((metric, labels), mut points)| {
            points.sort_by_key(|(ts, _)| *ts);
            SeriesEntry {
                metric,
                labels,
                points,
            }
        })
        .collect();
    Ok(SeriesResponse { bucket_ms, series })
}

#[derive(Debug)]
enum ApiError {
    Internal(anyhow::Error),
    BadRequest(String),
    NotFound(String),
    PayloadTooLarge,
    /// 查询结果超过存储层硬上限：这是客户端可调整的参数问题，不是服务端错误。
    QueryTooLarge,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        // 存储层的行数上限是有业务含义的 413，不能被统一脱敏成 500。
        if err.downcast_ref::<QueryTooLarge>().is_some() {
            return ApiError::QueryTooLarge;
        }
        ApiError::Internal(err)
    }
}

impl From<tokio::task::JoinError> for ApiError {
    fn from(err: tokio::task::JoinError) -> Self {
        ApiError::Internal(err.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        match self {
            ApiError::Internal(err) => {
                // 详细错误只进日志：响应体可能被面板/浏览器/日志采集看到，
                // 不能回显数据库路径、SQL、文件系统等内部信息。
                tracing::error!(error = %err, "API 内部错误");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "internal_error" })),
                )
                    .into_response()
            }
            ApiError::BadRequest(message) => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "bad_request", "message": message })),
            )
                .into_response(),
            ApiError::NotFound(message) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "not_found", "message": message })),
            )
                .into_response(),
            ApiError::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "error": "payload_too_large" })),
            )
                .into_response(),
            ApiError::QueryTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "error": "query_too_large" })),
            )
                .into_response(),
        }
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
            // KI-19：长度 / 控制字符校验必须在比较 CN、写日志与任何 DB 写入之前。
            // 失败只记静态字段名，绝不回显原始字段值（防日志注入与放大）。
            if let Err(field) = validate_hello_metadata(&hello) {
                reject_and_close(&mut socket, codes::BAD_FRAME, "Hello 元数据非法").await;
                bail!("Hello 元数据非法: {field}");
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

/// enrollment 在消费一次性 token **之前**必须通过的全部门槛。
///
/// 顺序：协议 → 字段安全 → CSR 长度 → CA 材料配套。任何一步失败都不能消耗
/// token（否则运维刚生成的 token 会被一个注定失败的请求烧掉），也不能写 agent 记录。
/// 返回已校验的 CA，供后续签发直接复用（避免二次读盘与 TOCTOU）。
fn precheck_enroll(
    state: &AppState,
    req: &EnrollRequest,
) -> std::result::Result<tls::ValidatedCa, Box<Frame>> {
    if let Some(reject) = protocol_gate(req.protocol) {
        return Err(Box::new(reject));
    }
    // requested_name 可以为空（agent init 不传 --name 时就是空），hub 实际使用的是 token 名。
    if !is_log_safe(&req.hostname, 255) || !is_log_safe_optional(&req.requested_name, 128) {
        return Err(Box::new(problem(
            codes::ENROLL_DENIED,
            "hostname 或 name 非法",
        )));
    }
    if !csr_within_limit(&req.csr_pem) {
        return Err(Box::new(problem(codes::BAD_FRAME, "CSR 无效")));
    }
    // 先解析 CSR 再碰 CA：短小但非法的 CSR 同样不能烧掉一次性 token。
    if let Err(err) = tls::validate_client_csr(&req.csr_pem) {
        tracing::warn!(
            error = %log_safe_error(&err),
            "enrollment CSR 无法解析，拒绝且不消费 token"
        );
        return Err(Box::new(problem(codes::BAD_FRAME, "CSR 无效")));
    }
    tls::load_validated_ca(&state.cfg.data_dir).map_err(|err| {
        tracing::error!(error = %err, "enrollment 前置检查失败：CA 材料不可用");
        Box::new(problem(
            codes::INTERNAL,
            "hub CA 材料异常，暂时无法签发证书",
        ))
    })
}

async fn handle_enroll(mut socket: WebSocket, state: AppState, req: EnrollRequest) -> Result<()> {
    // 所有门槛（含 CA 配套校验）都在 consume_enroll_token 之前完成。
    let ca = match precheck_enroll(&state, &req) {
        Ok(ca) => ca,
        Err(reject) => {
            let code = match reject.as_ref() {
                Frame::Problem { code, .. } => code.clone(),
                _ => codes::INTERNAL.to_string(),
            };
            let _ = send_frame(&mut socket, &reject).await;
            let _ = send_with_timeout(&mut socket, Message::Close(None)).await;
            bail!("enrollment 前置检查未通过: {code}");
        }
    };

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

    let ca_pem = ca.cert_pem.clone();

    let agent_id = uuid::Uuid::new_v4().to_string();
    let cert_pem = ca
        .sign_client_csr(&req.csr_pem, &agent_id, state.cfg.client_cert_validity_days)
        .context("签发客户端证书失败")?;

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

async fn handle_session(mut socket: WebSocket, state: AppState, hello: AgentHello) -> Result<()> {
    // KI-19 纵深防御：dispatch 已校验一次，但任何进入会话的路径都不得把非法
    // 元数据写进 DB / 日志。失败同样只记静态字段名。
    if let Err(field) = validate_hello_metadata(&hello) {
        reject_and_close(&mut socket, codes::BAD_FRAME, "Hello 元数据非法").await;
        bail!("Hello 元数据非法: {field}");
    }

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
    // `register` 对同一 agent 会等旧连接的清理回调（写 offline/revoked）结束才插入
    // 新连接，因此下面的 `upsert_agent(online)` 一定晚于旧 offline 落库。
    let handle = state.sessions.register(&agent_id);
    let _cleanup = SessionCleanup::new(
        state.storage.clone(),
        state.sessions.clone(),
        agent_id.clone(),
        handle.conn_id,
    );
    // M3：控制命令的 pending 表属于本会话。声明顺序保证会话结束时先 Drop
    // `ControlSession`（给所有等待者回 agent_offline），再注销注册表。
    // #18：每条 pending 带上本地 deadline；会话每秒清理一次，避免管理 API 超时后
    // 残留项永久占用 max_pending 名额。
    let mut control = ControlSession::new(
        state.cfg.control.max_pending_per_session,
        Duration::from_millis(state.cfg.control.request_timeout_ms.max(1)),
    );
    let mut control_rx = handle.control_rx;
    let mut watch_control = true;
    // 首轮 tick 立即触发（此时 pending 必为空），随后每秒一次；错过的 tick 直接跳过，
    // 不让慢连接积压出连续清理。
    let mut control_expire = tokio::time::interval(Duration::from_secs(1));
    control_expire.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    state.storage.upsert_agent(&record)?;
    // M3：登记 agent 实际启用的控制能力。未知能力在入库前就被忽略，
    // 数据库里只会有本版本认识的四个字符串。
    let capabilities = control::sanitize_agent_capabilities(&hello.capabilities);
    state
        .storage
        .upsert_agent_control(&agent_id, &capabilities, now)?;
    if !capabilities.is_empty() {
        tracing::info!(
            agent = %agent_id,
            capabilities = capabilities.len(),
            "agent 控制能力已登记"
        );
    }
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
        sample_interval_ms: sample_interval_for(&state, &agent_id),
        server_time: now,
    });
    send_frame(&mut socket, &welcome).await?;

    let mut shutdown = handle.shutdown;
    let mut watch_shutdown = true;
    // 每个会话最多成功续签一次，状态跟随会话生命周期。
    let mut renew = RenewState::default();
    // 绝对空闲 deadline：每秒的控制清理 tick 不会重置它，只有入站帧才续期。
    let mut idle = SessionIdle::new(SESSION_IDLE_TIMEOUT);

    loop {
        // 45s 内收不到任何帧就认为连接已死；agent 每 15s 发一次 Ping。
        // 空闲超时是独立 select 分支：即使 recv / 控制队列 / 清理 tick 持续就绪，
        // biased 也会在 deadline 时优先关闭连接，不会被其它分支饿死。
        let recv = socket.recv();
        let idle_sleep = tokio::time::sleep_until(idle.deadline());
        tokio::pin!(idle_sleep);
        let event = tokio::select! {
            biased;
            changed = shutdown.changed(), if watch_shutdown => {
                // 关闭原因由 SessionRegistry 写入（吊销 / 配置变更）。
                match changed {
                    Ok(()) => SessionEvent::Shutdown(*shutdown.borrow_and_update()),
                    Err(_) => SessionEvent::WatchClosed,
                }
            }
            _ = &mut idle_sleep => SessionEvent::IdleTimeout,
            // 清理优先于新控制命令：持续就绪的控制队列不能把 pending 超时清理
            // 推迟到方案承诺的 ≤2s 之外。shutdown 仍保持最高优先级。
            _ = control_expire.tick() => SessionEvent::ControlExpired,
            command = control_rx.recv(), if watch_control => match command {
                Some(command) => SessionEvent::Control(command),
                None => SessionEvent::ControlClosed,
            },
            received = recv => match received {
                None => SessionEvent::Closed,
                Some(Err(err)) => SessionEvent::RecvError(err.to_string()),
                Some(Ok(message)) => SessionEvent::Message(message),
            },
        };

        match event {
            SessionEvent::Shutdown(ShutdownReason::Revoke) => {
                tracing::info!(agent = %agent_id, "收到吊销通知，关闭会话");
                reject_and_close(&mut socket, codes::REVOKED, "该 agent 已被吊销").await;
                break;
            }
            SessionEvent::Shutdown(ShutdownReason::Reconfigure) => {
                // 配置变更不是吊销：发 Close(1000) 正常关闭，agent 会立即重连并
                // 在 Welcome 里拿到新采样间隔。绝不发 revoked Problem。
                tracing::info!(agent = %agent_id, "收到配置变更通知，正常关闭会话以便重连");
                let close = Message::Close(Some(CloseFrame {
                    code: close_code::NORMAL,
                    reason: "reconfigure".into(),
                }));
                if let Err(err) = send_with_timeout(&mut socket, close).await {
                    tracing::debug!(agent = %agent_id, error = %err, "发送 Close 帧失败");
                }
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
            SessionEvent::Control(command) => {
                // #17：dispatch 前再查一次吊销。命中/查询失败都只回错误，
                // 绝不把 ControlCommand 投递给 agent；随后 continue 等 watcher 关闭。
                if let Err(error) = control_revocation_gate(&state, &agent_id).await {
                    let _ = command.reply.send(Err(error));
                    continue;
                }
                // 分配会话内 id 并发送 ControlRequest；容量超限时 dispatch 已回错误。
                control.dispatch(&mut socket, command).await?;
            }
            SessionEvent::ControlClosed => {
                tracing::debug!(agent = %agent_id, "控制命令通道已关闭，停止接收控制请求");
                watch_control = false;
            }
            SessionEvent::ControlExpired => {
                // 只遍历内存 pending 并回 oneshot，不做 I/O，不阻塞采集 / ACK。
                let expired = control.expire(Instant::now());
                if expired > 0 {
                    tracing::debug!(agent = %agent_id, expired, "清理超时的控制请求");
                }
            }
            SessionEvent::Message(message) => {
                match handle_message(
                    &mut socket,
                    &state,
                    &agent_id,
                    &mut renew,
                    &mut control,
                    message,
                )
                .await?
                {
                    MessageAction::Continue => {
                        // 只有完整处理完一帧才续期：慢批次入库 / 证书签发等
                        // 处理耗时不能被计入下一个空闲窗口，否则处理完立即被误杀。
                        // 控制命令 / 清理 tick / shutdown 都不算心跳，不续期。
                        idle.on_frame();
                    }
                    MessageAction::Close => break,
                }
            }
        }
    }

    tracing::info!(agent = %agent_id, "agent 会话结束");
    Ok(())
}

/// Welcome 下发的有效采样间隔：agent 显式配置优先，读失败/越界值回退配置默认值。
///
/// 兜底值也 clamp 到合法范围：即使配置层校验被绕过，Welcome 也绝不发非法值。
fn sample_interval_for(state: &AppState, agent_id: &str) -> u64 {
    let fallback = state
        .cfg
        .sample_interval_ms
        .clamp(MIN_SAMPLE_INTERVAL_MS, MAX_SAMPLE_INTERVAL_MS);
    match state.storage.get_sample_interval(agent_id) {
        Ok(Some(ms)) if (MIN_SAMPLE_INTERVAL_MS..=MAX_SAMPLE_INTERVAL_MS).contains(&ms) => ms,
        Ok(Some(ms)) => {
            tracing::warn!(
                agent = %agent_id,
                ms,
                min_ms = MIN_SAMPLE_INTERVAL_MS,
                max_ms = MAX_SAMPLE_INTERVAL_MS,
                "数据库中采样间隔越界，回退配置默认值"
            );
            fallback
        }
        Ok(None) => fallback,
        Err(err) => {
            tracing::warn!(
                agent = %agent_id,
                error = %err,
                "读取采样间隔失败，回退配置默认值"
            );
            fallback
        }
    }
}

/// `select!` 每轮只产出一个事件，避免在分支里同时借用 socket 与取消信号。
enum SessionEvent {
    Message(Message),
    /// 管理 API 投递过来的控制命令。
    Control(ControlCommand),
    /// 控制命令通道关闭（注册表已无发送端），后续不再轮询。
    ControlClosed,
    /// 每秒一次：清理已超过 request_timeout 的 pending。
    ControlExpired,
    Closed,
    RecvError(String),
    IdleTimeout,
    Shutdown(ShutdownReason),
    WatchClosed,
}

enum MessageAction {
    Continue,
    Close,
}

/// 会话空闲超时的绝对 deadline。
///
/// `select!` 每轮都会丢弃未完成的 recv future；如果每轮都用
/// `timeout(SESSION_IDLE_TIMEOUT, recv)` 重新计时，每秒完成一次的
/// `control_expire` tick 会把 45s 空闲窗口无限推后，静默连接（TCP 未断、
/// 不再发帧）将永远不触发空闲超时。这里保存绝对时间点，只有收到 agent
/// 入站帧才顺延；控制命令、清理 tick、shutdown 都不得调用 [`Self::on_frame`]。
struct SessionIdle {
    timeout: Duration,
    expires_at: tokio::time::Instant,
}

impl SessionIdle {
    fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            expires_at: tokio::time::Instant::now() + timeout,
        }
    }

    /// 当前这一轮 `recv` 的绝对截止时间。
    fn deadline(&self) -> tokio::time::Instant {
        self.expires_at
    }

    /// 收到 agent 入站帧后才顺延整个空闲窗口。
    fn on_frame(&mut self) {
        self.expires_at = tokio::time::Instant::now() + self.timeout;
    }
}

/// 单个会话的客户端证书续签状态。
///
/// 每个会话最多成功签发 1 次；跨会话的重复请求由 [`RenewGuard`] 的冷却窗口兜住。
#[derive(Default)]
struct RenewState {
    succeeded: bool,
}

/// 客户端续签的冷却窗口：同一 agent 10 分钟内只允许一次尝试。
///
/// 每会话 1 次可以被「断开重连」绕过，冷却表把窗口收紧到每 agent 10 分钟；
/// 正常轮换（90 天证书、30 天阈值）完全用不到第二次请求。
const RENEW_COOLDOWN_MS: i64 = 10 * 60 * 1_000;
/// 冷却表容量上限；超过后清理过期项，防止被大量 agent_id 撑爆内存。
const RENEW_GUARD_MAX_ENTRIES: usize = 4_096;

/// 续签准入表：`agent_id -> 最近一次尝试的 Unix 毫秒`。
///
/// 无效 CSR 也会占用一次机会（准入发生在解析之前），避免用坏请求刷签名。
struct RenewGuard {
    last_attempt_ms: HashMap<String, i64>,
}

impl RenewGuard {
    fn new() -> Self {
        Self {
            last_attempt_ms: HashMap::new(),
        }
    }

    /// 尝试占用一次续签机会：冷却窗口内返回 `false`，否则记录本次尝试并返回 `true`。
    fn begin_attempt(&mut self, agent_id: &str, now_ms: i64) -> bool {
        if let Some(prev) = self.last_attempt_ms.get(agent_id) {
            if now_ms.saturating_sub(*prev) < RENEW_COOLDOWN_MS {
                return false;
            }
        }
        if self.last_attempt_ms.len() >= RENEW_GUARD_MAX_ENTRIES {
            let cutoff = now_ms.saturating_sub(RENEW_COOLDOWN_MS);
            self.last_attempt_ms.retain(|_, ts| *ts > cutoff);

            // 仍在窗口内的条目占满表时，淘汰最早的一条，保证内存有硬上界。
            // 合法 agent 数远小于上限，被淘汰的只会是极久未活跃的身份。
            if self.last_attempt_ms.len() >= RENEW_GUARD_MAX_ENTRIES
                && !self.last_attempt_ms.contains_key(agent_id)
            {
                if let Some(oldest) = self
                    .last_attempt_ms
                    .iter()
                    .min_by_key(|(_, ts)| **ts)
                    .map(|(id, _)| id.clone())
                {
                    self.last_attempt_ms.remove(&oldest);
                }
            }
        }
        self.last_attempt_ms.insert(agent_id.to_string(), now_ms);
        true
    }
}

/// 续签所需的 hub 侧资源；与 `AppState` 解耦，单测可以走真实处理路径。
struct RenewalContext {
    cert_dir: PathBuf,
    client_days: u32,
    /// 用 std Mutex：临界区只有一次 HashMap 操作，不跨 await 持有。
    guard: StdMutex<RenewGuard>,
}

impl RenewalContext {
    fn new(cert_dir: PathBuf, client_days: u32) -> Arc<Self> {
        Arc::new(Self {
            cert_dir,
            client_days,
            guard: StdMutex::new(RenewGuard::new()),
        })
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, RenewGuard> {
        match self.guard.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// spawn_blocking 里的签发结果：把「CSR 有问题」和「hub 自身故障」分开，
/// 前者回 `BAD_FRAME`，后者回 `INTERNAL`。
enum SignOutcome {
    Signed(String),
    BadCsr(String),
    Internal(String),
}

/// 处理一条 `RenewCert` 请求，返回要回给 agent 的帧。
///
/// 顺序（评审要求）：
/// 1. 会话内已成功 → 限流；
/// 2. 全局冷却窗口 → 限流（记录尝试，**无效 CSR 也计入**）；
/// 3. CSR 长度上限（16 KiB，O(1)，不解析）；
/// 4. 读 CA 私钥 + 解析 CSR + 签发，全部在 `spawn_blocking` 里做。
///
/// 安全要点：证书 CN **强制**取会话身份 `agent_id`，CSR 里自带的 CN 会被丢弃，
/// 因此伪造 CN 也拿不到别人的身份。CSR 只作为公钥载体。
async fn handle_renewal(
    ctx: &RenewalContext,
    renew: &mut RenewState,
    agent_id: &str,
    csr_pem: &str,
    now_ms: i64,
) -> Frame {
    if renew.succeeded {
        tracing::warn!(agent = %agent_id, "同一会话重复请求证书续签，已拒绝");
        return problem(codes::RATE_LIMITED, "同一会话只能续签一次");
    }
    if !ctx.guard().begin_attempt(agent_id, now_ms) {
        tracing::warn!(
            agent = %agent_id,
            cooldown_secs = RENEW_COOLDOWN_MS / 1_000,
            "续签仍在冷却窗口内，已拒绝"
        );
        return problem(codes::RATE_LIMITED, "续签过于频繁，请稍后再试");
    }
    if !csr_within_limit(csr_pem) {
        tracing::warn!(
            agent = %agent_id,
            len = csr_pem.len(),
            limit = MAX_CSR_PEM_LEN,
            "续签 CSR 超过长度上限，已拒绝"
        );
        return problem(codes::BAD_FRAME, "CSR 无效");
    }

    let cert_dir = ctx.cert_dir.clone();
    let client_days = ctx.client_days;
    let agent_id_owned = agent_id.to_string();
    let csr = csr_pem.to_string();
    let outcome = tokio::task::spawn_blocking(move || {
        // 读 CA 私钥的同一次操作里校验 ca.crt 配套：不配套时绝不签发客户端证书
        // （否则会给出无效链证书，agent 下次握手失败且旧证书可能已被覆盖）。
        let ca = match tls::load_validated_ca_at(&cert_dir) {
            Ok(ca) => ca,
            Err(err) => return SignOutcome::Internal(format!("{err:#}")),
        };
        match ca.sign_client_csr(&csr, &agent_id_owned, client_days) {
            Ok(cert_pem) => SignOutcome::Signed(cert_pem),
            Err(err) => SignOutcome::BadCsr(format!("{err:#}")),
        }
    })
    .await;

    match outcome {
        Ok(SignOutcome::Signed(cert_pem)) => match tls::not_after_unix(&cert_pem) {
            Ok(not_after) => {
                renew.succeeded = true;
                // 日志只记身份与到期时间：CSR / 证书内容一律不入日志。
                tracing::info!(
                    agent = %agent_id,
                    not_after = %tls::format_unix_utc(not_after),
                    "客户端证书已续签"
                );
                Frame::CertRenewed { cert_pem }
            }
            Err(err) => {
                tracing::warn!(
                    agent = %agent_id,
                    error = %log_safe_error(&err),
                    "签发出的证书无法解析"
                );
                problem(codes::INTERNAL, "hub 无法签发证书")
            }
        },
        Ok(SignOutcome::BadCsr(reason)) => {
            // 错误串只含解析原因，已被 log_safe_error 去掉控制字符。
            tracing::warn!(
                agent = %agent_id,
                error = %log_safe_error(&reason),
                "客户端证书续签被拒绝（CSR 无效）"
            );
            problem(codes::BAD_FRAME, "CSR 无效")
        }
        Ok(SignOutcome::Internal(reason)) => {
            tracing::error!(
                agent = %agent_id,
                error = %log_safe_error(&reason),
                "客户端证书续签失败（hub 内部错误）"
            );
            problem(codes::INTERNAL, "hub 无法签发证书")
        }
        Err(join_err) => {
            tracing::error!(agent = %agent_id, error = %join_err, "证书续签任务失败");
            problem(codes::INTERNAL, "hub 无法签发证书")
        }
    }
}

async fn handle_message(
    socket: &mut WebSocket,
    state: &AppState,
    agent_id: &str,
    renew: &mut RenewState,
    control: &mut ControlSession,
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
                Frame::ControlResponse(response) => {
                    // 只按 id 匹配本会话已登记的请求；未知 id 丢弃并计数。
                    control.complete(response);
                }
                Frame::ControlRequest(_) => {
                    // hub 永远不会接受 agent 发来的控制请求，忽略而不是断开，
                    // 避免协议误用影响正常采集。
                    tracing::debug!(agent = %agent_id, "收到 agent 发来的 ControlRequest，已忽略");
                }
                Frame::RenewCert { csr_pem } => {
                    // 限流/冷却判定、长度检查、读 CA 私钥与签发都在 handle_renewal 里；
                    // 任何结果都只回 Problem / CertRenewed，不断开连接。
                    let reply =
                        handle_renewal(&state.renewal, renew, agent_id, &csr_pem, now_ms()).await;
                    if matches!(reply, Frame::CertRenewed { .. }) {
                        mark_seen(state, agent_id);
                    }
                    send_frame(socket, &reply).await?;
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
/// - 吊销状态优先级最高：命中吊销恢复为 `revoked`，否则置 `offline`；
/// - 「最后一条连接注销 + 状态写入」在注册表的 per-agent slot 锁内原子完成，
///   同一 agent 的新连接注册会被串行化，不会出现旧 offline 覆盖新 online。
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

    /// 注销本连接；只有「该 agent 的最后一条连接」才写状态。
    ///
    /// 关键点：`unregister_last_and_run` 在 per-agent slot 锁内执行回调，而同一
    /// agent 的新连接 `register` 也要拿这把锁。因此「查吊销 + 写 offline/revoked」
    /// 与「新连接注册」严格串行：回调先完成，新连接才插入，调用方随后写 online。
    /// 旧 offline 不可能落在新 online 之后，也不需要再调用 `has_active` 二次检查
    /// （slot 已空且锁仍未释放，新连接插不进来）。
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;

        let agent_id = self.agent_id.clone();
        let storage = self.storage.clone();
        // 回调内只做一次吊销查询 + 一次单行状态写入；日志与错误处理全部移到
        // slot 锁外，避免在临界区里做任何可能阻塞的操作。
        let mut revoked_error: Option<anyhow::Error> = None;
        let mut written: Option<(&'static str, anyhow::Result<()>)> = None;
        let removed = self
            .sessions
            .unregister_last_and_run(&self.agent_id, self.conn_id, || {
                // revoked 优先级最高：先查吊销，命中写 revoked，否则才写 offline。
                let revoked = match storage.is_revoked(&agent_id) {
                    Ok(revoked) => revoked,
                    Err(err) => {
                        revoked_error = Some(err);
                        false
                    }
                };
                let status = if revoked { "revoked" } else { "offline" };
                written = Some((status, storage.set_status(&agent_id, status, now_ms())));
            });

        if !removed {
            tracing::debug!(
                agent = %self.agent_id,
                conn_id = self.conn_id,
                "旧会话结束，不修改在线状态"
            );
            return;
        }
        if let Some(err) = revoked_error {
            tracing::warn!(agent = %self.agent_id, error = %err, "清理时查询吊销状态失败");
        }
        if let Some((status, result)) = written {
            match result {
                Ok(()) => {
                    tracing::info!(agent = %self.agent_id, status = status, "agent 状态已更新");
                }
                Err(err) if status == "revoked" => {
                    tracing::warn!(agent = %self.agent_id, error = %err, "恢复 revoked 状态失败");
                }
                Err(err) => {
                    tracing::warn!(agent = %self.agent_id, error = %err, "更新 agent 状态失败");
                }
            }
        }
    }
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        self.finish();
    }
}

/// #17：会话侧控制命令的吊销兜底门禁。
///
/// 管理 API 已检查两次，但 revoke 仍可能恰好插在「API 检查后、命令入队」之间；
/// 会话在 dispatch 前再查一次库，确保吊销后绝不向 agent 发送 ControlRequest。
/// 命中吊销 → `agent_revoked`；查询失败 → `internal_error`（fail closed）。
async fn control_revocation_gate(
    state: &AppState,
    agent_id: &str,
) -> std::result::Result<(), ControlError> {
    let storage = state.storage.clone();
    let agent = agent_id.to_string();
    match tokio::task::spawn_blocking(move || storage.is_revoked(&agent)).await {
        Ok(Ok(false)) => Ok(()),
        Ok(Ok(true)) => Err(ControlError::new(
            control::hub_codes::AGENT_REVOKED,
            "agent 已被吊销",
        )),
        Ok(Err(err)) => {
            tracing::warn!(agent = %agent_id, error = %err, "查询 agent 吊销状态失败，拒绝控制命令");
            Err(ControlError::new(
                control::hub_codes::INTERNAL,
                "无法确认 agent 吊销状态",
            ))
        }
        Err(err) => {
            tracing::warn!(agent = %agent_id, error = %err, "查询 agent 吊销状态任务失败，拒绝控制命令");
            Err(ControlError::new(
                control::hub_codes::INTERNAL,
                "无法确认 agent 吊销状态",
            ))
        }
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

/// KI-19：Hello 元数据长度与控制字符校验。
///
/// - 长度按 UTF-8 **字节数**计算；
/// - 所有字段拒绝控制字符（含 `\n`、`\t`、NUL），防止日志注入；
/// - `agent_id` 沿用更严格的 [`is_valid_agent_id`]（非空、≤64 字节、ASCII 安全字符集）；
/// - `name` / `os` / `arch` / `version` / `boot_id` 允许为空，`hostname` 不允许为空。
///
/// 出错时返回首个非法字段的**静态**名称，仅供内部日志使用；绝不携带字段值，
/// 避免把攻击者可控内容写进日志。
fn validate_hello_metadata(hello: &AgentHello) -> Result<(), &'static str> {
    if !is_valid_agent_id(&hello.agent_id) {
        return Err("agent_id");
    }
    if !is_log_safe_optional(&hello.name, 128) {
        return Err("name");
    }
    if !is_log_safe(&hello.hostname, 255) {
        return Err("hostname");
    }
    if !is_log_safe_optional(&hello.os, 64) {
        return Err("os");
    }
    if !is_log_safe_optional(&hello.arch, 32) {
        return Err("arch");
    }
    if !is_log_safe_optional(&hello.version, 64) {
        return Err("version");
    }
    if !is_log_safe_optional(&hello.boot_id, 128) {
        return Err("boot_id");
    }
    Ok(())
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
    use rustboard_common::fsutil;
    use rustboard_common::model::Sample;
    use std::sync::mpsc;

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

    /// KI-19：构造一份全字段合法的 Hello，供边界测试改写单个字段。
    fn valid_hello() -> AgentHello {
        AgentHello {
            agent_id: "agent-1".to_string(),
            name: "测试节点".to_string(),
            hostname: "node-1.example".to_string(),
            os: "Linux".to_string(),
            arch: "x86_64".to_string(),
            version: "0.3.4".to_string(),
            protocol: PROTOCOL_VERSION,
            boot_id: "boot-1".to_string(),
            epoch: 7,
            secret: "s".repeat(64),
            capabilities: Vec::new(),
        }
    }

    fn set_hello_field(hello: &mut AgentHello, field: &'static str, value: String) {
        match field {
            "agent_id" => hello.agent_id = value,
            "name" => hello.name = value,
            "hostname" => hello.hostname = value,
            "os" => hello.os = value,
            "arch" => hello.arch = value,
            "version" => hello.version = value,
            "boot_id" => hello.boot_id = value,
            other => panic!("未知 Hello 字段: {other}"),
        }
    }

    /// KI-19：全字段合法（name 为 UTF-8 中文）的 Hello 必须通过。
    #[test]
    fn ki19_hello_accepts_full_valid_metadata() {
        assert_eq!(validate_hello_metadata(&valid_hello()), Ok(()));
    }

    /// KI-19：每个字段按 UTF-8 字节长度卡边界，max 通过、max+1 拒绝；
    /// `agent_id` 沿用 64 字节的 ASCII 安全字符集规则（不放宽到 128）。
    #[test]
    fn ki19_hello_field_length_limits() {
        for (field, max) in [
            ("agent_id", 64),
            ("name", 128),
            ("hostname", 255),
            ("os", 64),
            ("arch", 32),
            ("version", 64),
            ("boot_id", 128),
        ] {
            let mut hello = valid_hello();
            set_hello_field(&mut hello, field, "a".repeat(max));
            assert_eq!(
                validate_hello_metadata(&hello),
                Ok(()),
                "{field} 恰好 {max} 字节必须通过"
            );

            set_hello_field(&mut hello, field, "a".repeat(max + 1));
            assert_eq!(
                validate_hello_metadata(&hello),
                Err(field),
                "{field} 超过 {max} 字节必须拒绝"
            );
        }
    }

    /// KI-19：`agent_id` / `hostname` 空值必须拒绝；`name` / `os` / `arch` /
    /// `version` / `boot_id` 允许为空。
    #[test]
    fn ki19_hello_empty_field_rules() {
        let mut hello = valid_hello();
        hello.agent_id.clear();
        assert_eq!(validate_hello_metadata(&hello), Err("agent_id"));

        let mut hello = valid_hello();
        hello.hostname.clear();
        assert_eq!(validate_hello_metadata(&hello), Err("hostname"));

        for field in ["name", "os", "arch", "version", "boot_id"] {
            let mut hello = valid_hello();
            set_hello_field(&mut hello, field, String::new());
            assert_eq!(validate_hello_metadata(&hello), Ok(()), "{field} 允许为空");
        }
    }

    /// KI-19：所有字段都拒绝控制字符；返回值只能是静态字段名，
    /// 不得包含任何攻击者提供的原始内容。
    #[test]
    fn ki19_hello_rejects_control_chars_without_echoing_values() {
        for field in [
            "agent_id", "name", "hostname", "os", "arch", "version", "boot_id",
        ] {
            for control in ['\n', '\t', '\0', '\r'] {
                let mut hello = valid_hello();
                let evil = format!("evil{control}INFO forged");
                set_hello_field(&mut hello, field, evil.clone());

                let err =
                    validate_hello_metadata(&hello).expect_err("含控制字符的元数据必须被拒绝");
                assert_eq!(err, field, "{field} 必须返回自身的静态字段名");
                assert!(
                    !err.contains(&control.to_string()),
                    "{field} 的错误串不得包含控制字符"
                );
                assert!(!err.contains("evil"), "{field} 的错误串不得回显原值");
                assert!(!err.contains("INFO forged"), "{field} 的错误串不得回显原值");
                assert!(!evil.contains(err), "错误串不得是攻击者可控内容的一部分");
            }
        }
    }

    /// KI-19：长度按 UTF-8 字节而不是字符数计算；合法中文 name 必须通过。
    #[test]
    fn ki19_hello_length_is_utf8_bytes() {
        let mut hello = valid_hello();
        // 42 个「中」= 126 字节，再补 2 个 ASCII，恰好 128 字节。
        hello.name = format!("{}ab", "中".repeat(42));
        assert_eq!(hello.name.len(), 128);
        assert_eq!(validate_hello_metadata(&hello), Ok(()));

        // 43 个「中」= 129 字节：字符数只有 43，但按字节已超限。
        hello.name = "中".repeat(43);
        assert_eq!(hello.name.len(), 129);
        assert_eq!(validate_hello_metadata(&hello), Err("name"));
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

    /// 评审回归：每秒的控制清理 tick 不得重置 45s 空闲 deadline；
    /// 只有收到入站帧（`on_frame`）才顺延。用 tokio 虚拟时间，避免 CI 抖动。
    #[tokio::test(start_paused = true)]
    async fn v032_session_idle_deadline_survives_control_ticks() {
        let start = tokio::time::Instant::now();
        let mut idle = SessionIdle::new(SESSION_IDLE_TIMEOUT);
        assert_eq!(idle.deadline(), start + SESSION_IDLE_TIMEOUT);

        // 模拟 44 次每秒 tick：tick 不续期，deadline 必须保持首次建立时的值。
        for _ in 0..44 {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        assert_eq!(
            idle.deadline(),
            start + SESSION_IDLE_TIMEOUT,
            "control_expire tick 不得重置空闲 deadline"
        );
        assert!(tokio::time::Instant::now() < idle.deadline());

        // 第 45 秒到期。
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(tokio::time::Instant::now() >= idle.deadline());

        // 收到入站帧后才顺延整个 45s 窗口。
        idle.on_frame();
        assert_eq!(
            idle.deadline(),
            tokio::time::Instant::now() + SESSION_IDLE_TIMEOUT
        );
        tokio::time::sleep(Duration::from_secs(44)).await;
        assert!(tokio::time::Instant::now() < idle.deadline());
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(tokio::time::Instant::now() >= idle.deadline());
    }

    /// 评审回归：控制命令队列持续就绪时，独立 idle 分支仍必须先触发关闭。
    /// 用暂停时钟 + 始终就绪的控制 future 复现「biased 若把 idle 排后就被饿死」。
    #[tokio::test(start_paused = true)]
    async fn v032_idle_timeout_fires_despite_control_ticks() {
        let idle = SessionIdle::new(SESSION_IDLE_TIMEOUT);
        let idle_sleep = tokio::time::sleep_until(idle.deadline());
        tokio::pin!(idle_sleep);
        let mut ticks = tokio::time::interval(Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let mut idle_fired = false;
        for _ in 0..200 {
            tokio::select! {
                biased;
                _ = &mut idle_sleep => {
                    idle_fired = true;
                    break;
                }
                _ = ticks.tick() => {}
                // 控制队列始终有命令；没有 timer 可以推进时手动拨动暂停时钟。
                command = std::future::ready(Some(())) => {
                    let _ = command;
                    tokio::time::advance(Duration::from_secs(1)).await;
                }
            }
        }
        assert!(idle_fired, "控制队列持续就绪时 idle 仍必须先触发关闭");
        // 虚拟时钟必须恰好停在 45s deadline：tick / 控制命令都没有把它推后。
        assert_eq!(
            tokio::time::Instant::now(),
            idle.deadline(),
            "空闲超时必须恰好在 deadline 触发"
        );
    }

    /// 评审回归：续期必须发生在整帧处理完成之后；处理耗时不得挤占下一个
    /// 45s 空闲窗口（helper 级断言，不必真等 45s）。
    #[tokio::test(start_paused = true)]
    async fn v032_session_idle_renews_after_slow_processing() {
        let frame_at = tokio::time::Instant::now();
        let mut idle = SessionIdle::new(SESSION_IDLE_TIMEOUT);

        // 模拟一帧处理了 50s 才完成，已超过原 deadline。
        tokio::time::sleep(Duration::from_secs(50)).await;
        assert!(tokio::time::Instant::now() >= idle.deadline());

        // 若按“帧到达时续期”，这里已经过期；必须处理完再续期，拿到完整 45s。
        idle.on_frame();
        assert_eq!(
            idle.deadline(),
            tokio::time::Instant::now() + SESSION_IDLE_TIMEOUT
        );
        assert!(
            idle.deadline() > frame_at + SESSION_IDLE_TIMEOUT,
            "处理耗时不得挤占续期后的空闲窗口"
        );
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

    /// 测试用：临时目录（进程 id + 自增序号，避免并行测试互相覆盖）。
    fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::AtomicU32;
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rb-hub-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// 测试用：构造一个 CN 由攻击者控制的 CSR。
    fn csr_with_cn(cn: &str) -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.serialize_request(&key).unwrap().pem().unwrap()
    }

    /// 准备 CA 材料并返回续签上下文。
    fn renewal_fixture(tag: &str) -> (PathBuf, Arc<RenewalContext>) {
        let dir = temp_dir(tag);
        tls::ensure_hub_material(&dir, &["localhost".to_string()], tls::CertPolicy::default())
            .unwrap();
        let ctx = RenewalContext::new(tls::cert_dir(&dir), 90);
        (dir, ctx)
    }

    fn problem_code(frame: &Frame) -> &str {
        match frame {
            Frame::Problem { code, .. } => code,
            other => panic!("期望 Problem，实际: {other:?}"),
        }
    }

    /// A5/安全：走真实 `handle_renewal` 路径——CN 强制取会话身份，
    /// 同一会话第二次、以及重连后仍在冷却窗口内的请求都被限流。
    #[tokio::test]
    async fn a5_renewal_uses_session_identity_and_rate_limits() {
        let (dir, ctx) = renewal_fixture("renew-identity");
        let now = now_ms();
        let csr = csr_with_cn("hub-self");

        // 第一次：签发成功，CN 必须是会话身份，有效期按客户端证书配置。
        let mut session = RenewState::default();
        match handle_renewal(&ctx, &mut session, "session-agent", &csr, now).await {
            Frame::CertRenewed { cert_pem } => {
                let der = tls::load_certs(&cert_pem).unwrap();
                assert_eq!(
                    tls::peer_common_name(der[0].as_ref()).as_deref(),
                    Some("session-agent"),
                    "CN 必须取会话身份，不能取 CSR 里的 CN"
                );
                let not_after = tls::not_after_unix(&cert_pem).unwrap();
                assert!(not_after * 1_000 > now, "新证书必须尚未过期");
                assert_eq!(tls::days_left(&cert_pem, now).unwrap(), 90);
                assert!(session.succeeded);
            }
            other => panic!("首次续签必须成功，实际: {other:?}"),
        }

        // 同一会话第二次：即使冷却已过也必须被会话级限流拦住。
        let reply = handle_renewal(
            &ctx,
            &mut session,
            "session-agent",
            &csr,
            now + RENEW_COOLDOWN_MS + 1,
        )
        .await;
        assert_eq!(problem_code(&reply), codes::RATE_LIMITED);

        // 换一个新会话（模拟断开重连）：仍在冷却窗口内 → 仍被限流。
        let mut reconnect = RenewState::default();
        let reply = handle_renewal(&ctx, &mut reconnect, "session-agent", &csr, now + 1_000).await;
        assert_eq!(problem_code(&reply), codes::RATE_LIMITED);
        assert!(!reconnect.succeeded);

        // 其他 agent 不受影响。
        let mut other = RenewState::default();
        assert!(matches!(
            handle_renewal(&ctx, &mut other, "other-agent", &csr, now + 1).await,
            Frame::CertRenewed { .. }
        ));

        // 冷却窗口到期后允许再次续签。
        let mut later = RenewState::default();
        assert!(matches!(
            handle_renewal(
                &ctx,
                &mut later,
                "session-agent",
                &csr,
                now + RENEW_COOLDOWN_MS + 1
            )
            .await,
            Frame::CertRenewed { .. }
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6/资源：超长 / 非 PEM / 天数非法都必须回 Problem 而不是 panic；
    /// 无效 CSR 计入冷却（防止用坏请求刷签名）。
    #[tokio::test]
    async fn a6_renewal_rejects_oversized_and_invalid_csr() {
        let (dir, ctx) = renewal_fixture("renew-bad-csr");
        let now = now_ms();

        // 超长：直接在长度检查被拒，且计入一次尝试。
        let oversized = "A".repeat(MAX_CSR_PEM_LEN + 1);
        let mut session = RenewState::default();
        let reply = handle_renewal(&ctx, &mut session, "agent-big", &oversized, now).await;
        assert_eq!(problem_code(&reply), codes::BAD_FRAME);
        // 紧接着用同一 agent 发合法 CSR：仍在冷却 → 限流（证明坏请求也计数）。
        let reply = handle_renewal(
            &ctx,
            &mut session,
            "agent-big",
            &csr_with_cn("agent-big"),
            now + 1,
        )
        .await;
        assert_eq!(problem_code(&reply), codes::RATE_LIMITED);

        // 非 PEM：BAD_FRAME，且不 panic。
        let mut session = RenewState::default();
        let reply = handle_renewal(&ctx, &mut session, "agent-garbage", "not a csr", now).await;
        assert_eq!(problem_code(&reply), codes::BAD_FRAME);
        assert!(!session.succeeded);

        // 客户端有效期非法（0 天）：即使 CSR 合法也必须被拒。
        let bad_days = RenewalContext::new(tls::cert_dir(&dir), 0);
        let mut session = RenewState::default();
        let reply = handle_renewal(
            &bad_days,
            &mut session,
            "agent-zero-days",
            &csr_with_cn("agent-zero-days"),
            now,
        )
        .await;
        assert_eq!(problem_code(&reply), codes::BAD_FRAME);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 严重项（rotate-cert 备份可回滚）：备份必须同时包含 cert 与 key，
    /// 且 key/cert 不配套时 rotate-cert 仍能修复目录。
    #[test]
    fn a7_rotate_cert_backs_up_key_and_repairs_mismatched_pair() {
        let dir = temp_dir("rotate-repair");
        let cfg = HubConfig {
            data_dir: dir.clone(),
            database: format!("sqlite://{}", dir.join("rustboard.db").display()),
            self_monitor: false,
            admin_token: "test-token".into(),
            server_names: vec!["localhost".to_string()],
            ..HubConfig::default()
        };
        tls::ensure_hub_material(&dir, &cfg.server_names, tls::CertPolicy::default()).unwrap();
        let cfg_path = dir.join("hub.toml");
        cfg.save(&cfg_path).unwrap();

        let cert_path = tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE);
        let key_path = tls::cert_dir(&dir).join(tls::SERVER_KEY_FILE);
        let old_cert = std::fs::read_to_string(&cert_path).unwrap();
        let old_key = std::fs::read_to_string(&key_path).unwrap();
        assert!(tls::cert_matches_key(&old_cert, &old_key).unwrap());

        // 模拟续签写盘中途崩溃：key 与 cert 不配套，run 的启动自检会失败。
        let bad_key = rcgen::KeyPair::generate().unwrap().serialize_pem();
        fsutil::atomic_write(&key_path, bad_key.as_bytes(), 0o600).unwrap();
        assert!(
            tls::server_config(&dir).is_err(),
            "不配套时必须能从配置构建阶段发现"
        );

        // rotate-cert 不依赖旧配置，可以直接修复。
        rotate_cert(Some(cfg_path), true, Some(30)).expect("rotate-cert 必须能修复不配套材料");

        // 修复后：配套、有效期按 --days、指纹变化。
        let new_cert = std::fs::read_to_string(&cert_path).unwrap();
        let new_key = std::fs::read_to_string(&key_path).unwrap();
        assert!(tls::cert_matches_key(&new_cert, &new_key).unwrap());
        assert!(tls::server_config(&dir).is_ok());
        assert_eq!(tls::days_left(&new_cert, now_ms()).unwrap(), 30);
        assert_ne!(
            tls::fingerprint_of_pem(&new_cert).unwrap(),
            tls::fingerprint_of_pem(&old_cert).unwrap()
        );

        // 备份：cert 0644 + key 0600，同一时间戳后缀，内容等于轮换前的磁盘内容。
        let entries: Vec<String> = std::fs::read_dir(tls::cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        let mut cert_backups: Vec<&String> = entries
            .iter()
            .filter(|name| name.starts_with("server.crt.bak-"))
            .collect();
        cert_backups.sort();
        assert_eq!(cert_backups.len(), 1, "必须恰好有一个证书备份: {entries:?}");
        let stamp = cert_backups[0]
            .trim_start_matches("server.crt.bak-")
            .to_string();
        let key_backup_name = format!("server.key.bak-{stamp}");
        assert!(
            entries.iter().any(|name| name == &key_backup_name),
            "缺少使用同一时间戳的私钥备份: {entries:?}"
        );
        assert_eq!(
            std::fs::read_to_string(tls::cert_dir(&dir).join(cert_backups[0])).unwrap(),
            old_cert,
            "证书备份必须是轮换前的证书"
        );
        assert_eq!(
            std::fs::read_to_string(tls::cert_dir(&dir).join(&key_backup_name)).unwrap(),
            bad_key,
            "私钥备份必须是轮换前磁盘上的私钥"
        );

        // 备份权限：证书 0644、私钥 0600（A8）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |name: &str| {
                std::fs::metadata(tls::cert_dir(&dir).join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(cert_backups[0].as_str()), 0o644);
            assert_eq!(mode(&key_backup_name), 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 资源保护：CSR 长度门禁的边界值（16 KiB 整合法，+1 拒绝），纳管与续签共用。
    #[test]
    fn csr_size_gate_boundary() {
        assert!(csr_within_limit(""));
        assert!(csr_within_limit(&"A".repeat(MAX_CSR_PEM_LEN)));
        assert!(!csr_within_limit(&"A".repeat(MAX_CSR_PEM_LEN + 1)));
    }

    /// 冷却表：窗口内拒绝、窗口后放行、不同 agent 互不影响，且表大小有硬上界。
    #[test]
    fn renew_guard_cooldown_and_memory_bound() {
        let mut guard = RenewGuard::new();
        let now = 1_000_000;

        assert!(guard.begin_attempt("a", now), "首次尝试必须放行");
        assert!(
            !guard.begin_attempt("a", now + RENEW_COOLDOWN_MS - 1),
            "冷却窗口内必须拒绝"
        );
        assert!(
            guard.begin_attempt("a", now + RENEW_COOLDOWN_MS),
            "冷却结束后必须放行"
        );
        assert!(guard.begin_attempt("b", now), "不同 agent 的冷却互不影响");

        // 塞入远多于上限的身份，表长度必须始终不超过上限（内存有硬上界）。
        for i in 0..(RENEW_GUARD_MAX_ENTRIES + 32) {
            assert!(guard.begin_attempt(&format!("agent-{i}"), now + i as i64));
        }
        assert!(
            guard.last_attempt_ms.len() <= RENEW_GUARD_MAX_ENTRIES,
            "冷却表不得无限增长，实际 {}",
            guard.last_attempt_ms.len()
        );
    }

    /// A2/A7：`init` 的四个有效期参数与 `rotate-cert` 参数必须出现在 --help 里。
    #[test]
    fn a2_init_and_rotate_cert_expose_cli_flags() {
        use clap::CommandFactory;

        let mut cmd = Cli::command();
        let init = cmd
            .find_subcommand_mut("init")
            .expect("init 子命令必须存在");
        for id in [
            "ca_days",
            "server_cert_days",
            "client_cert_days",
            "renew_before_days",
        ] {
            assert!(
                init.get_arguments().any(|arg| arg.get_id() == id),
                "init 缺少 --{}",
                id.replace('_', "-")
            );
        }

        let mut cmd = Cli::command();
        let rotate = cmd
            .find_subcommand_mut("rotate-cert")
            .expect("rotate-cert 子命令必须存在");
        for id in ["config", "force", "days"] {
            assert!(
                rotate.get_arguments().any(|arg| arg.get_id() == id),
                "rotate-cert 缺少参数 {id}"
            );
        }
    }

    /// 第五轮建议：短小但非法的 CSR 也在消费 token 之前被拒（不烧 token）。
    #[tokio::test]
    async fn s5_enrollment_rejects_invalid_csr_without_consuming_token() {
        let dir = temp_dir("enroll-bad-csr");
        tls::ensure_hub_material(&dir, &["localhost".to_string()], tls::CertPolicy::default())
            .unwrap();
        let cfg = HubConfig {
            data_dir: dir.clone(),
            admin_token: "token".to_string(),
            ..HubConfig::default()
        };
        let admin_rate = Arc::new(AdminRateLimiter::from_config(&cfg));
        let auth_failures = Arc::new(AuthFailureLimiter::new(
            cfg.admin_auth_failure_limit_per_min,
        ));
        let state = AppState {
            storage: Arc::new(SqliteStorage::open_in_memory().unwrap()),
            cfg: Arc::new(cfg),
            sessions: SessionRegistry::new(),
            session_slots: Arc::new(Semaphore::new(4)),
            renewal: RenewalContext::new(tls::cert_dir(&dir), 90),
            live_cert: Arc::new(RwLock::new(CertStatus::unknown())),
            admin_rate,
            auth_failures,
        };
        let token = "enroll-token-bad-csr";
        let now = now_ms();
        state
            .storage
            .create_enroll_token(&tls::sha256_hex(token), "agent", now, now + 600_000)
            .unwrap();
        let req = EnrollRequest {
            token: token.to_string(),
            csr_pem: "not a csr".to_string(),
            requested_name: "agent".to_string(),
            hostname: "host".to_string(),
            protocol: PROTOCOL_VERSION,
        };

        match precheck_enroll(&state, &req) {
            Err(reject) => match reject.as_ref() {
                Frame::Problem { code, .. } => assert_eq!(code, codes::BAD_FRAME),
                _ => panic!("非法 CSR 必须回 Problem"),
            },
            Ok(_) => panic!("非法 CSR 必须被拒绝"),
        }
        assert!(
            state
                .storage
                .consume_enroll_token(&tls::sha256_hex(token), now)
                .unwrap()
                .is_some(),
            "非法 CSR 不得消耗 token"
        );
        assert!(state.storage.list_agents().unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S1-2：CA 不配套时 enrollment 必须在消费 token 之前被拒，
    /// 一次性 token 不被烧掉，也不写 agent 记录。
    #[tokio::test]
    async fn s12_enrollment_rejects_bad_ca_without_consuming_token() {
        let dir = temp_dir("enroll-bad-ca");
        tls::ensure_hub_material(&dir, &["localhost".to_string()], tls::CertPolicy::default())
            .unwrap();
        let cfg = HubConfig {
            data_dir: dir.clone(),
            admin_token: "token".to_string(),
            ..HubConfig::default()
        };
        let admin_rate = Arc::new(AdminRateLimiter::from_config(&cfg));
        let auth_failures = Arc::new(AuthFailureLimiter::new(
            cfg.admin_auth_failure_limit_per_min,
        ));
        let state = AppState {
            storage: Arc::new(SqliteStorage::open_in_memory().unwrap()),
            cfg: Arc::new(cfg),
            sessions: SessionRegistry::new(),
            session_slots: Arc::new(Semaphore::new(4)),
            renewal: RenewalContext::new(tls::cert_dir(&dir), 90),
            live_cert: Arc::new(RwLock::new(CertStatus::unknown())),
            admin_rate,
            auth_failures,
        };

        let token = "enroll-token-value";
        let now = now_ms();
        state
            .storage
            .create_enroll_token(&tls::sha256_hex(token), "agent", now, now + 600_000)
            .unwrap();

        let (csr_pem, _key) = tls::make_csr().unwrap();
        let req = EnrollRequest {
            token: token.to_string(),
            csr_pem,
            requested_name: "agent".to_string(),
            hostname: "host".to_string(),
            protocol: PROTOCOL_VERSION,
        };

        // CA 正常时前置检查通过（不消费 token）。
        precheck_enroll(&state, &req).expect("CA 正常时前置检查应通过");
        assert!(
            state
                .storage
                .consume_enroll_token(&tls::sha256_hex(token), now)
                .unwrap()
                .is_some(),
            "前置检查本身不应消费 token"
        );

        // 用一个新的 token，然后破坏 CA 配对（已消费的 token 行会保留，不能复用）。
        let token2 = "enroll-token-value-2";
        let now = now_ms();
        state
            .storage
            .create_enroll_token(&tls::sha256_hex(token2), "agent", now, now + 600_000)
            .unwrap();
        let req_bad_ca = EnrollRequest {
            token: token2.to_string(),
            ..req.clone()
        };
        let other = temp_dir("enroll-bad-ca-other");
        tls::ensure_hub_material(
            &other,
            &["localhost".to_string()],
            tls::CertPolicy::default(),
        )
        .unwrap();
        let other_key =
            std::fs::read_to_string(tls::cert_dir(&other).join(tls::CA_KEY_FILE)).unwrap();
        fsutil::atomic_write(
            &tls::cert_dir(&dir).join(tls::CA_KEY_FILE),
            other_key.as_bytes(),
            0o600,
        )
        .unwrap();

        match precheck_enroll(&state, &req_bad_ca) {
            Err(reject) => match reject.as_ref() {
                Frame::Problem { code, .. } => assert_eq!(code, codes::INTERNAL),
                _ => panic!("CA 不配套时必须拒绝 enrollment"),
            },
            Ok(_) => panic!("CA 不配套时必须拒绝 enrollment"),
        }
        // token 必须仍然可用（未被消费），且没有写入 agent 记录。
        assert!(
            state
                .storage
                .consume_enroll_token(&tls::sha256_hex(token2), now)
                .unwrap()
                .is_some(),
            "CA 不配套时不得消耗 token"
        );
        assert!(
            state.storage.list_agents().unwrap().is_empty(),
            "被拒绝的 enrollment 不得写 agent 记录"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// `init --san` 非法时必须在创建 CA 之前失败（不留下半个 CA / 半个配置）。
    #[test]
    fn s13_init_with_bad_san_leaves_no_ca_or_config() {
        let dir = temp_dir("init-bad-san");
        let cfg_path = dir.join("hub.toml");
        let data_dir = dir.join("data");
        let err = init(
            Some(cfg_path.clone()),
            Some(data_dir.clone()),
            Some("127.0.0.1:0".to_string()),
            Some("127.0.0.1:0".to_string()),
            None,
            vec!["bad name".to_string()],
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .expect_err("非法 --san 必须让 init 失败");
        assert!(
            format!("{err:#}").contains("server_names"),
            "错误信息: {err:#}"
        );
        assert!(!cfg_path.exists(), "失败时不得写入配置文件");
        assert!(
            !tls::cert_dir(&data_dir).exists(),
            "失败时不得创建证书目录/CA"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CA 不配套时 `rotate-cert --force` 必须失败，且不新增任何备份、不改证书。
    #[test]
    fn a7_rotate_cert_failed_ca_leaves_no_backup() {
        let dir = temp_dir("rotate-bad-ca");
        let cfg = HubConfig {
            data_dir: dir.clone(),
            database: format!("sqlite://{}", dir.join("rustboard.db").display()),
            self_monitor: false,
            admin_token: "test-token".into(),
            server_names: vec!["localhost".to_string()],
            ..HubConfig::default()
        };
        tls::ensure_hub_material(&dir, &cfg.server_names, tls::CertPolicy::default()).unwrap();
        let cfg_path = dir.join("hub.toml");
        cfg.save(&cfg_path).unwrap();
        let cert_before =
            std::fs::read_to_string(tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE)).unwrap();
        let other = temp_dir("rotate-bad-ca-other");
        tls::ensure_hub_material(
            &other,
            &["localhost".to_string()],
            tls::CertPolicy::default(),
        )
        .unwrap();
        let other_key =
            std::fs::read_to_string(tls::cert_dir(&other).join(tls::CA_KEY_FILE)).unwrap();
        fsutil::atomic_write(
            &tls::cert_dir(&dir).join(tls::CA_KEY_FILE),
            other_key.as_bytes(),
            0o600,
        )
        .unwrap();

        rotate_cert(Some(cfg_path), true, Some(30)).expect_err("CA 不配套必须失败");

        assert_eq!(
            std::fs::read_to_string(tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE)).unwrap(),
            cert_before,
            "失败不得改写证书"
        );
        let backups: Vec<String> = std::fs::read_dir(tls::cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".bak-"))
            .collect();
        assert!(backups.is_empty(), "失败路径不得新增备份: {backups:?}");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// 第五轮 S1：CA 两件套被另一套覆盖后，`init --force` 必须用当前 CA 重签 server
    /// （成对备份、新链可验证），不能返回 0 却留着旧链。
    #[test]
    fn s5_init_force_reissues_when_ca_replaced() {
        let dir = temp_dir("init-replace-ca");
        let cfg_path = dir.join("hub.toml");
        let data = dir.join("data");
        let run_init = |force: bool| {
            init(
                Some(cfg_path.clone()),
                Some(data.clone()),
                Some("127.0.0.1:0".to_string()),
                Some("127.0.0.1:0".to_string()),
                None,
                Vec::new(),
                None,
                None,
                None,
                None,
                None,
                force,
            )
        };
        run_init(false).expect("首次 init 必须成功");
        let old_server =
            std::fs::read_to_string(tls::cert_dir(&data).join(tls::SERVER_CERT_FILE)).unwrap();

        // 另一套完整 CA 覆盖当前 CA 两件套。
        let other = temp_dir("init-replace-ca-other");
        tls::ensure_hub_material(
            &other,
            &["localhost".to_string()],
            tls::CertPolicy::default(),
        )
        .unwrap();
        for name in [tls::CA_CERT_FILE, tls::CA_KEY_FILE] {
            let src = std::fs::read(tls::cert_dir(&other).join(name)).unwrap();
            fsutil::atomic_write(&tls::cert_dir(&data).join(name), &src, 0o600).unwrap();
        }

        run_init(true).expect("CA 变化后 init --force 必须重签 server 并成功");

        let server =
            std::fs::read_to_string(tls::cert_dir(&data).join(tls::SERVER_CERT_FILE)).unwrap();
        let key = std::fs::read_to_string(tls::cert_dir(&data).join(tls::SERVER_KEY_FILE)).unwrap();
        let ca = std::fs::read_to_string(tls::cert_dir(&data).join(tls::CA_CERT_FILE)).unwrap();
        assert_ne!(server, old_server, "必须重签 server 证书");
        assert!(tls::cert_matches_key(&server, &key).unwrap());
        assert!(
            tls::cert_issued_by_ca(&server, &ca, now_ms()).unwrap(),
            "新 server 证书必须由当前 CA 签发"
        );
        assert!(tls::server_config(&data).is_ok());
        let backups: Vec<String> = std::fs::read_dir(tls::cert_dir(&data))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.starts_with("server.crt.bak-"))
            .collect();
        assert_eq!(backups.len(), 1, "旧 server 证书必须成对备份: {backups:?}");
        assert_eq!(
            std::fs::read_to_string(tls::cert_dir(&data).join(&backups[0])).unwrap(),
            old_server
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// 建议项：`rotate-cert --force` 在 server.crt 缺失时也能补签（不再先读旧证书失败）。
    #[test]
    fn a7_rotate_cert_force_reissues_missing_server_cert() {
        let dir = temp_dir("rotate-missing-cert");
        let cfg = HubConfig {
            data_dir: dir.clone(),
            database: format!("sqlite://{}", dir.join("rustboard.db").display()),
            self_monitor: false,
            admin_token: "test-token".into(),
            server_names: vec!["localhost".to_string()],
            ..HubConfig::default()
        };
        tls::ensure_hub_material(&dir, &cfg.server_names, tls::CertPolicy::default()).unwrap();
        let cfg_path = dir.join("hub.toml");
        cfg.save(&cfg_path).unwrap();
        std::fs::remove_file(tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE)).unwrap();

        rotate_cert(Some(cfg_path), true, Some(30)).expect("--force 应能补签缺失的服务端证书");

        let cert_pem = std::fs::read_to_string(tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE))
            .expect("应写回 server.crt");
        let key_pem = std::fs::read_to_string(tls::cert_dir(&dir).join(tls::SERVER_KEY_FILE))
            .expect("应写回 server.key");
        assert!(tls::cert_matches_key(&cert_pem, &key_pem).unwrap());
        assert_eq!(tls::days_left(&cert_pem, now_ms()).unwrap(), 30);
        assert!(tls::server_config(&dir).is_ok());
        assert!(
            std::fs::read_dir(tls::cert_dir(&dir))
                .unwrap()
                .filter_map(|entry| entry.ok())
                .any(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("server.key.bak-")),
            "补签前应备份旧私钥"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    // ------------------------------------------------------------------
    // M2：管理 API 鉴权 / overview / latest / series / settings
    // ------------------------------------------------------------------

    fn hub_state(admin_token: &str) -> AppState {
        hub_state_with(HubConfig {
            admin_token: admin_token.to_string(),
            ..HubConfig::default()
        })
    }

    fn hub_state_with(cfg: HubConfig) -> AppState {
        let admin_rate = Arc::new(AdminRateLimiter::from_config(&cfg));
        let auth_failures = Arc::new(AuthFailureLimiter::new(
            cfg.admin_auth_failure_limit_per_min,
        ));
        AppState {
            storage: Arc::new(SqliteStorage::open_in_memory().unwrap()),
            cfg: Arc::new(cfg),
            sessions: SessionRegistry::new(),
            session_slots: Arc::new(Semaphore::new(8)),
            renewal: RenewalContext::new(PathBuf::from("/tmp/rb-hub-test-unused-ca"), 90),
            live_cert: Arc::new(RwLock::new(CertStatus::unknown())),
            admin_rate,
            auth_failures,
        }
    }

    fn test_agent(agent_id: &str) -> AgentRecord {
        AgentRecord {
            agent_id: agent_id.to_string(),
            name: agent_id.to_string(),
            hostname: "test-host".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            version: "0.2.0".to_string(),
            boot_id: "boot".to_string(),
            status: "online".to_string(),
            last_seen_at: now_ms(),
            created_at: now_ms(),
        }
    }

    /// 直接调用管理 API（不绑定端口），返回状态 / 响应头 / 响应体。
    async fn admin_call(
        router: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        admin_call_from(router, "127.0.0.1", method, uri, token, body).await
    }

    /// 指定直连来源 IP 的调用（限速测试用）：必须注入 `ConnectInfo<SocketAddr>`，
    /// 否则限速中间件会因缺少扩展直接 500。
    async fn admin_call_from(
        router: &Router,
        ip: &str,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if body.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        let mut request = builder
            .body(
                body.map(|body| Body::from(body.to_string()))
                    .unwrap_or_else(Body::empty),
            )
            .unwrap();
        let peer: SocketAddr = format!("{ip}:54321").parse().expect("测试 IP 必须合法");
        request.extensions_mut().insert(ConnectInfo(peer));
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec();
        (status, headers, bytes)
    }

    /// 给原始请求注入 ConnectInfo 后直接调用 Router；非 loopback 管理调用缺这个扩展
    /// 会被 axum 直接拒绝（500），所以所有测试入口都必须走这里。
    async fn call_router(
        router: &Router,
        mut request: axum::http::Request<Body>,
    ) -> axum::response::Response {
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 12345))));
        router.clone().oneshot(request).await.unwrap()
    }

    fn json_body(bytes: &[u8]) -> serde_json::Value {
        serde_json::from_slice(bytes).expect("响应必须是 JSON")
    }

    /// M2-7：`/healthz` 免鉴权；其余 `/api/v1/*` 缺 / 错 / 无 Bearer 前缀全部 401，
    /// 正确 token 200，且所有响应带 `Cache-Control: no-store`。
    #[tokio::test]
    async fn m2_bearer_auth_healthz_public_and_api_protected() {
        let router = admin_router(hub_state("m2-admin-token"));

        let (status, headers, _) = admin_call(&router, "GET", "/healthz", None, None).await;
        assert_eq!(status, StatusCode::OK, "/healthz 必须免鉴权");
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store",
            "管理端口所有响应都要禁缓存"
        );

        let (status, headers, body) =
            admin_call(&router, "GET", "/api/v1/agents", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(json_body(&body)["error"], "unauthorized");

        let (status, _, body) =
            admin_call(&router, "GET", "/api/v1/agents", Some("wrong"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(&body)["error"], "unauthorized");

        // 只有 token、没有 Bearer 前缀同样拒绝。
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agents")
            .header(header::AUTHORIZATION, "m2-admin-token")
            .body(Body::empty())
            .unwrap();
        let response = call_router(&router, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let (status, _, body) = admin_call(
            &router,
            "GET",
            "/api/v1/agents",
            Some("m2-admin-token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json_body(&body).is_array(), "正确 token 应返回 agent 数组");

        // scheme 大小写不敏感：bearer / BEARER 都是合法 Bearer 认证。
        for scheme in ["bearer", "BEARER", "BeArEr"] {
            let request = axum::http::Request::builder()
                .method("GET")
                .uri("/api/v1/agents")
                .header(header::AUTHORIZATION, format!("{scheme} m2-admin-token"))
                .body(Body::empty())
                .unwrap();
            let response = call_router(&router, request).await;
            assert_eq!(response.status(), StatusCode::OK, "scheme={scheme}");
        }

        // token 错误时，scheme 再正确也必须 401。
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agents")
            .header(header::AUTHORIZATION, "bearer wrong-token")
            .body(Body::empty())
            .unwrap();
        let response = call_router(&router, request).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Bearer 解析：scheme 大小写不敏感、token 常量时间比较、拒绝多余分段。
    #[test]
    fn m2_bearer_scheme_is_case_insensitive() {
        use crate::auth::bearer_matches;
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        assert!(!bearer_matches(&headers, "secret"));
        assert!(!bearer_matches(&headers, ""));

        for scheme in ["Bearer", "bearer", "BEARER", "bEaReR"] {
            let value = format!("{scheme} secret");
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&value).unwrap(),
            );
            assert!(bearer_matches(&headers, "secret"), "scheme={scheme}");
            assert!(!bearer_matches(&headers, "wrong"), "scheme={scheme}");
        }

        // 没有 scheme / 多余分段 / 空 token 都不接受。
        for value in [
            "secret",
            "Bearer",
            "Bearer secret extra",
            "Basic secret",
            "Bearer ",
        ] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
            assert!(!bearer_matches(&headers, "secret"), "value={value}");
        }
    }

    /// M2：500 响应只返回固定错误码，不能回显内部路径 / SQL / 文件系统信息。
    #[tokio::test]
    async fn m2_internal_error_response_is_sanitized() {
        let err = ApiError::Internal(anyhow::anyhow!(
            "打开数据库失败: /var/lib/rustboard/secret/rustboard.db: 权限不足 \
             (SQL: SELECT * FROM agents)"
        ));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(
            json_body(&body),
            serde_json::json!({ "error": "internal_error" }),
            "500 响应体必须只有固定错误码"
        );
        let text = String::from_utf8_lossy(&body);
        for leaked in ["/var/lib", "rustboard.db", "SELECT", "权限不足"] {
            assert!(
                !text.contains(leaked),
                "500 响应泄露内部信息 {leaked}: {text}"
            );
        }
    }

    /// latest_samples 行数上限必须映射为 413 query_too_large，而不是 500 internal_error。
    #[tokio::test]
    async fn m2_query_too_large_maps_to_413() {
        let err = anyhow::Error::new(QueryTooLarge { limit: 100_000 });
        let response = ApiError::from(err).into_response();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        assert_eq!(
            json_body(&body),
            serde_json::json!({ "error": "query_too_large" })
        );
        assert!(
            !String::from_utf8_lossy(&body).contains("internal_error"),
            "查询过大不能被当成内部错误"
        );
    }

    /// M2/KI-04：空 / 弱 admin_token 必须在启动前被拒绝，错误信息提示 admin-token 修复命令。
    #[test]
    fn m2_empty_or_weak_admin_token_refuses_startup() {
        let err = require_admin_token(&HubConfig::default())
            .expect_err("空 token 必须拒绝启动")
            .to_string();
        assert!(err.contains("admin-token"), "错误信息: {err}");

        // 31 个字符：长度不足。
        let weak = HubConfig {
            admin_token: "abcdefghijklmnopqrstuvwxyz01234".to_string(),
            ..HubConfig::default()
        };
        let err = require_admin_token(&weak)
            .expect_err("31 字符 token 必须拒绝启动")
            .to_string();
        assert!(err.contains("admin-token"), "错误信息: {err}");
        assert!(err.contains("32"), "错误信息应说明最小长度: {err}");

        // 32 个相同字符：长度够但不同字符数不足。
        let same = HubConfig {
            admin_token: "a".repeat(MIN_ADMIN_TOKEN_LEN),
            ..HubConfig::default()
        };
        let err = require_admin_token(&same)
            .expect_err("全同字符 token 必须拒绝启动")
            .to_string();
        assert!(err.contains("不同字符"), "错误信息: {err}");

        // 32 个字符但含空白：字符集不合法。
        let spaced = HubConfig {
            admin_token: "0123456789abcdef 0123456789abcdef".to_string(),
            ..HubConfig::default()
        };
        let err = require_admin_token(&spaced)
            .expect_err("含空白的 token 必须拒绝启动")
            .to_string();
        assert!(err.contains("ASCII"), "错误信息: {err}");

        // 非 ASCII 字符即使长度足够也必须拒绝。
        let unicode = HubConfig {
            admin_token: "密码".repeat(16),
            ..HubConfig::default()
        };
        let err = require_admin_token(&unicode)
            .expect_err("非 ASCII token 必须拒绝启动")
            .to_string();
        assert!(err.contains("ASCII"), "错误信息: {err}");

        // 32 个字符、字符够多但包含占位符。
        let placeholder = HubConfig {
            admin_token: "changeme0123456789abcdefghijklmn".to_string(),
            ..HubConfig::default()
        };
        assert_eq!(
            placeholder.admin_token.chars().count(),
            32,
            "前提：长度合法"
        );
        let err = require_admin_token(&placeholder)
            .expect_err("占位符 token 必须拒绝启动")
            .to_string();
        assert!(err.contains("占位符"), "错误信息: {err}");

        // 边界：恰好 32 字符且恰好 16 个不同字符必须放行。
        let boundary = HubConfig {
            admin_token: "0123456789abcdef0123456789abcdef".to_string(),
            ..HubConfig::default()
        };
        require_admin_token(&boundary).expect("32 字符 / 16 个不同字符必须放行");

        // v0.2 的 64 位随机 hex token 必须继续合法（可能只有 15 个不同字符）。
        let v02_shape = HubConfig {
            admin_token: "3b18d03801b044a0b97e9e1800b860abb3ea0ba836e14ffd84ebef1150c9efa7"
                .to_string(),
            ..HubConfig::default()
        };
        require_admin_token(&v02_shape).expect("v0.2 形态的 64 位 hex token 必须放行");
        let ok = HubConfig {
            admin_token: new_secret(),
            ..HubConfig::default()
        };
        require_admin_token(&ok).expect("v0.2 生成的 64 位 hex token 必须放行");
        assert_eq!(ok.admin_token.len(), 64);

        // 但低多样性的 64 位 hex 仍然拒绝（不是所有 hex 都放行）。
        let weak_hex = HubConfig {
            admin_token: "ab".repeat(32),
            ..HubConfig::default()
        };
        let err = require_admin_token(&weak_hex)
            .expect_err("低多样性 64 位 hex 必须拒绝")
            .to_string();
        assert!(err.contains("不同字符"), "错误信息: {err}");
    }

    /// M2：`admin-token` 为空时生成 64 位 hex 并落盘（0600），非空时保持不变。
    #[test]
    fn m2_admin_token_command_generates_and_persists() {
        let dir = temp_dir("admin-token");
        let path = dir.join("hub.toml");
        HubConfig::default().save(&path).unwrap();

        admin_token(Some(path.clone())).unwrap();
        let generated = HubConfig::load(&path).unwrap().admin_token;
        assert_eq!(generated.len(), 64, "token 应为 64 位 hex");
        assert!(
            generated.bytes().all(|b| b.is_ascii_hexdigit()),
            "token 必须全部是十六进制: {generated}"
        );

        // 第二次调用必须读取已有 token，而不是重新生成。
        admin_token(Some(path.clone())).unwrap();
        assert_eq!(HubConfig::load(&path).unwrap().admin_token, generated);

        // 配置里是弱 token 时，admin-token 必须重新生成，否则启动报错给出的
        // 修复命令无法真正修复。
        let mut weak = HubConfig::load(&path).unwrap();
        weak.admin_token = "short".to_string();
        weak.save(&path).unwrap();
        admin_token(Some(path.clone())).unwrap();
        let regenerated = HubConfig::load(&path).unwrap().admin_token;
        assert_eq!(regenerated.len(), 64, "弱 token 应被重新生成为 64 位 hex");
        assert_ne!(regenerated, "short");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "配置里的 admin_token 必须 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 自动 bucket 档位：跨度越大档位越大，且每个档位能让单曲线 ≤1500 点。
    #[test]
    fn m2_auto_bucket_picks_smallest_sufficient_tier() {
        let cases = [
            (60_000_i64, 1_000_i64),
            (3_600_000, 5_000),
            (6 * 3_600_000, 30_000),
            (24 * 3_600_000, 60_000),
            (7 * 24 * 3_600_000, 900_000),
            (MAX_SERIES_SPAN_MS, 3_600_000),
        ];
        for (span, expected) in cases {
            let bucket = auto_bucket_ms(span);
            assert_eq!(bucket, expected, "span={span} 的自动 bucket 不符");
            assert!(
                span / bucket < MAX_AUTO_BUCKET_POINTS,
                "span={span} 的 bucket={bucket} 单曲线点数超限"
            );
        }
        // 档位必须单调、且来自方案固定集合。
        for bucket in [
            1_000, 5_000, 10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000, 21_600_000,
        ] {
            assert!(AUTO_BUCKETS_MS.contains(&bucket));
        }
    }

    /// series 参数边界：多 metric、from/to、32 天、metric 字符集与数量、bucket 校验。
    #[test]
    fn m2_series_query_validation_boundaries() {
        let from = 1_700_000_000_000_i64;
        let to = from + MAX_SERIES_SPAN_MS;
        let valid = format!("metric=cpu.usage&metric=mem.used&from={from}&to={to}");
        let parsed = parse_series_query(Some(&valid)).expect("合法参数必须通过");
        assert_eq!(parsed.metrics, vec!["cpu.usage", "mem.used"]);
        assert_eq!(parsed.from, from);
        assert_eq!(parsed.to, to);
        assert_eq!(parsed.bucket_ms, auto_bucket_ms(MAX_SERIES_SPAN_MS));

        let explicit = format!("metric=cpu.usage&from={from}&to={to}&bucket_ms=60000");
        assert_eq!(
            parse_series_query(Some(&explicit)).unwrap().bucket_ms,
            60_000
        );

        // 时间参数。
        assert!(parse_series_query(Some("metric=cpu.usage&from=1&to=1")).is_err());
        assert!(parse_series_query(Some("metric=cpu.usage&from=2&to=1")).is_err());
        let too_wide = format!(
            "metric=cpu.usage&from={}&to={}",
            from,
            from + MAX_SERIES_SPAN_MS + 1
        );
        assert!(parse_series_query(Some(&too_wide)).is_err());
        assert!(parse_series_query(Some("metric=cpu.usage&to=10")).is_err());
        assert!(parse_series_query(Some("metric=cpu.usage")).is_err());
        assert!(parse_series_query(Some("metric=cpu.usage&from=1&from=2&to=3")).is_err());
        assert!(parse_series_query(Some("metric=cpu.usage&from=1&to=3&bucket_ms=0")).is_err());

        // metric 数量 / 字符集 / 长度 / 空值。
        assert!(parse_series_query(Some("from=1&to=3")).is_err());
        let many: String = (0..=MAX_SERIES_METRICS)
            .map(|i| format!("metric=m{i}&"))
            .collect();
        assert!(parse_series_query(Some(&format!("{many}from=1&to=3"))).is_err());
        assert!(parse_series_query(Some("metric=CPU.usage&from=1&to=3")).is_err());
        assert!(parse_series_query(Some("metric=cpu usage&from=1&to=3")).is_err());
        assert!(parse_series_query(Some("metric=a/b&from=1&to=3")).is_err());
        let long = "a".repeat(MAX_METRIC_LEN + 1);
        assert!(parse_series_query(Some(&format!("metric={long}&from=1&to=3"))).is_err());
        assert!(parse_series_query(Some("metric=&from=1&to=3")).is_err());
        assert!(parse_series_query(Some("metric=cpu.usage&from=1&to=3&bogus=1")).is_err());
    }

    /// 单次响应的点数 / 序列数上限：超限必须返回 400（这里验证纯函数返回错误）。
    #[test]
    fn m2_series_response_limits() {
        let row = |metric: String, labels: Labels, ts: i64| SeriesRow {
            metric,
            labels,
            ts,
            value: 1.0,
        };

        let too_many_points: Vec<SeriesRow> = (0..=MAX_SERIES_POINTS)
            .map(|i| row("cpu.usage".to_string(), Labels::new(), i as i64))
            .collect();
        assert!(build_series_response(1_000, too_many_points).is_err());

        let too_many_series: Vec<SeriesRow> = (0..=MAX_SERIES_COUNT)
            .map(|i| row(format!("m{i}"), Labels::new(), 1))
            .collect();
        assert!(build_series_response(1_000, too_many_series).is_err());

        let response = build_series_response(
            1_000,
            vec![
                row("cpu.usage".to_string(), Labels::new(), 2_000),
                row("cpu.usage".to_string(), Labels::new(), 1_000),
            ],
        )
        .unwrap();
        assert_eq!(response.bucket_ms, 1_000);
        assert_eq!(response.series.len(), 1);
        assert_eq!(
            response.series[0].points,
            vec![(1_000, 1.0), (2_000, 1.0)],
            "点必须按 ts 升序"
        );
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["series"][0]["points"][0][0], 1_000);
        assert_eq!(json["series"][0]["labels"], serde_json::json!({}));
    }

    /// overview：固定指标 + 60s 窗口 + 同序列去重取最新 + 每机有效间隔。
    #[tokio::test]
    async fn m2_overview_dedupes_latest_and_reports_settings() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("a1")).unwrap();
        let now = now_ms();

        let mut seq = 0u64;
        let mut insert = |metric: &str, ts: i64, value: f64| {
            let batch = SampleBatch {
                agent_id: "a1".to_string(),
                epoch: 1,
                seq,
                boot_id: "boot".to_string(),
                sent_at: ts,
                samples: vec![Sample::new(metric, ts, value)],
            };
            seq += 1;
            state.storage.insert_batch(&batch).unwrap();
        };
        insert("cpu.usage", now - 2_000, 10.0);
        insert("cpu.usage", now - 1_000, 20.0);
        // 不在固定指标集合内，必须被过滤。
        insert("net.rx_bytes", now - 500, 999.0);
        // 超出 60s 窗口，必须被过滤。
        insert("mem.used", now - OVERVIEW_WINDOW_MS - 60_000, 123.0);

        let Json(data) = overview(State(state.clone()), RawQuery(None))
            .await
            .expect("overview 必须成功");
        assert_eq!(data.agents.len(), 1);
        assert!(data.server_time >= now);
        assert_eq!(data.latest.len(), 1, "只保留关键指标且在窗口内的最新点");
        assert_eq!(data.latest[0].agent_id, "a1");
        assert_eq!(data.latest[0].metric, "cpu.usage");
        assert_eq!(data.latest[0].ts, now - 1_000);
        assert_eq!(data.latest[0].value, 20.0);
        assert_eq!(data.settings.len(), 1);
        assert_eq!(
            data.settings[0].sample_interval_ms, state.cfg.sample_interval_ms,
            "未显式配置时必须回退 cfg 默认值"
        );

        state
            .storage
            .set_sample_interval("a1", 10_000, now)
            .unwrap();
        let Json(data) = overview(State(state.clone()), RawQuery(None))
            .await
            .expect("overview 必须成功");
        assert_eq!(data.settings[0].sample_interval_ms, 10_000);
    }

    /// overview 的 `window_ms`：默认 60s，允许 1s–1h 且必须真正用于查询；越界/非法 400。
    #[tokio::test]
    async fn m2_overview_window_ms_is_applied_and_bounded() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("a1")).unwrap();
        let now = now_ms();
        // 5s 前的点：默认 60s 能看到，window_ms=1000 必须看不到。
        state
            .storage
            .insert_batch(&SampleBatch {
                agent_id: "a1".to_string(),
                epoch: 1,
                seq: 0,
                boot_id: "boot".to_string(),
                sent_at: now - 5_000,
                samples: vec![Sample::new("cpu.usage", now - 5_000, 7.0)],
            })
            .unwrap();

        let Json(data) = overview(State(state.clone()), RawQuery(None))
            .await
            .expect("overview 默认窗口必须成功");
        assert_eq!(data.latest.len(), 1, "默认 60s 应包含 5s 前的点");

        let Json(data) = overview(
            State(state.clone()),
            RawQuery(Some("window_ms=1000".to_string())),
        )
        .await
        .expect("window_ms=1000 是合法边界");
        assert!(
            data.latest.is_empty(),
            "window_ms=1000 必须真正过滤掉 5s 前的点"
        );

        let Json(data) = overview(
            State(state.clone()),
            RawQuery(Some("window_ms=60000".to_string())),
        )
        .await
        .expect("window_ms=60000 是合法上限");
        assert_eq!(data.latest.len(), 1, "60s 窗口应包含 5s 前的点");

        // 超过 60000 必须 400，并在 message 里说明上限，前端固定 60000 不受影响。
        let err = match overview(
            State(state.clone()),
            RawQuery(Some("window_ms=60001".to_string())),
        )
        .await
        {
            Ok(_) => panic!("window_ms=60001 必须被拒绝"),
            Err(err) => err,
        };
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = json_body(&body);
        assert_eq!(body["error"], "bad_request");
        let message = body["message"].as_str().unwrap_or_default();
        assert!(
            message.contains("60000"),
            "错误信息必须说明上限 60000: {message}"
        );

        for bad in [
            "window_ms=0",
            "window_ms=999",
            "window_ms=60001",
            "window_ms=3600000",
            "window_ms=abc",
            "bogus=1",
            "window_ms=1000&window_ms=2000",
        ] {
            let err = match overview(State(state.clone()), RawQuery(Some(bad.to_string()))).await {
                Ok(_) => panic!("非法 overview 参数必须被拒绝: {bad}"),
                Err(err) => err,
            };
            assert_eq!(
                err.into_response().status(),
                StatusCode::BAD_REQUEST,
                "bad={bad}"
            );
        }
    }

    /// settings：默认值 / 1000–300000 范围 / agent 不存在 404 / 落库后踢活跃会话。
    #[tokio::test]
    async fn m2_settings_range_404_and_reconfigure() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let session = state.sessions.register("agent-1");
        let router = admin_router(state.clone());

        let (status, _, body) = admin_call(
            &router,
            "GET",
            "/api/v1/agents/agent-1/settings",
            Some("token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        assert_eq!(body["agent_id"], "agent-1");
        assert_eq!(body["sample_interval_ms"], 5_000);

        for interval in [999_u64, 300_001] {
            let payload = format!("{{\"sample_interval_ms\":{interval}}}");
            let (status, _, body) = admin_call(
                &router,
                "PUT",
                "/api/v1/agents/agent-1/settings",
                Some("token"),
                Some(&payload),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "interval={interval}");
            assert_eq!(json_body(&body)["error"], "bad_request");
        }

        // 边界值 1000 / 300000 合法；写库后必须向活跃会话发 Reconfigure。
        for interval in [1_000_u64, 300_000] {
            let payload = format!("{{\"sample_interval_ms\":{interval}}}");
            let (status, _, body) = admin_call(
                &router,
                "PUT",
                "/api/v1/agents/agent-1/settings",
                Some("token"),
                Some(&payload),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "interval={interval}");
            assert_eq!(json_body(&body)["sample_interval_ms"], interval);
            assert_eq!(
                state.storage.get_sample_interval("agent-1").unwrap(),
                Some(interval),
                "PUT 必须落库"
            );
            assert_eq!(
                *session.shutdown.borrow(),
                ShutdownReason::Reconfigure,
                "配置变更必须走 Reconfigure，不能发吊销"
            );
        }

        // 不存在的 agent：GET / PUT 都是 404。
        let (status, _, _) = admin_call(
            &router,
            "GET",
            "/api/v1/agents/missing/settings",
            Some("token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _, _) = admin_call(
            &router,
            "PUT",
            "/api/v1/agents/missing/settings",
            Some("token"),
            Some("{\"sample_interval_ms\":10000}"),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(state.storage.get_sample_interval("missing").unwrap(), None);

        // 非 JSON / 非数字 / 缺字段同样 400。
        for payload in [
            "{\"sample_interval_ms\":\"abc\"}",
            "{\"sample_interval_ms\":-1}",
            "{}",
            "not-json",
        ] {
            let (status, _, _) = admin_call(
                &router,
                "PUT",
                "/api/v1/agents/agent-1/settings",
                Some("token"),
                Some(payload),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "payload={payload}");
        }
    }

    /// latest / series 路由：window 上限与参数错误返回 400 JSON，合法请求返回契约形状。
    #[tokio::test]
    async fn m2_latest_and_series_routes_validate_windows() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("hub-self")).unwrap();
        let router = admin_router(state);
        let now = now_ms();

        for uri in [
            "/api/v1/agents/hub-self/latest?window_ms=0".to_string(),
            "/api/v1/agents/hub-self/latest?window_ms=3600001".to_string(),
            "/api/v1/agents/hub-self/latest?window_ms=abc".to_string(),
        ] {
            let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "uri={uri}");
            assert_eq!(json_body(&body)["error"], "bad_request");
        }

        let (status, _, body) = admin_call(
            &router,
            "GET",
            "/api/v1/agents/hub-self/latest?window_ms=60000",
            Some("token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json_body(&body).is_array());

        let from = now - 3_600_000;
        let uri = format!(
            "/api/v1/agents/hub-self/series?metric=cpu.usage&metric=mem.used&from={from}&to={now}"
        );
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        assert_eq!(body["bucket_ms"], 5_000);
        assert!(body["series"].is_array());

        let uri = format!(
            "/api/v1/agents/hub-self/series?metric=cpu.usage&from={from}&to={now}&bucket_ms=60000"
        );
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_body(&body)["bucket_ms"], 60_000);

        // 非法 series 参数统一 400 JSON。
        let invalid = [
            format!("metric=cpu.usage&from={now}&to={now}"),
            format!(
                "metric=cpu.usage&from={from}&to={}",
                from + MAX_SERIES_SPAN_MS + 1
            ),
            format!("metric=Bad&from={from}&to={now}"),
            format!("metric=cpu.usage&from={from}"),
        ];
        for query in invalid {
            let uri = format!("/api/v1/agents/hub-self/series?{query}");
            let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "query={query}");
            assert_eq!(json_body(&body)["error"], "bad_request");
        }
    }

    /// latest / series：不存在的 agent 返回 404（与 settings 一致），
    /// 存在但没有数据时仍是 200 + 空结果。
    #[tokio::test]
    async fn m2_latest_and_series_missing_agent_are_404() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let router = admin_router(state);
        let now = now_ms();

        for uri in [
            "/api/v1/agents/missing/latest".to_string(),
            format!(
                "/api/v1/agents/missing/series?metric=cpu.usage&from={}&to={}",
                now - 1_000,
                now
            ),
        ] {
            let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "uri={uri}");
            let body = json_body(&body);
            assert_eq!(body["error"], "not_found", "uri={uri}");
            assert_eq!(body["message"], "agent 不存在", "uri={uri}");
        }

        // 存在但没有数据：空数组，不能误报 404。
        let (status, _, body) = admin_call(
            &router,
            "GET",
            "/api/v1/agents/agent-1/latest",
            Some("token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_body(&body), serde_json::json!([]));

        let uri = format!(
            "/api/v1/agents/agent-1/series?metric=cpu.usage&from={}&to={}",
            now - 1_000,
            now
        );
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_body(&body)["series"], serde_json::json!([]));
    }

    /// 请求体上限 64 KiB：超限返回 413，不能把大请求读进内存。
    #[tokio::test]
    async fn m2_admin_body_limit_is_64kib() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let router = admin_router(state);

        let mut payload = String::from("{\"sample_interval_ms\":10000,\"pad\":\"");
        payload.push_str(&"a".repeat(MAX_ADMIN_BODY_SIZE));
        payload.push_str("\"}");
        let (status, _, _) = admin_call(
            &router,
            "PUT",
            "/api/v1/agents/agent-1/settings",
            Some("token"),
            Some(&payload),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// M2：Welcome 使用显式采样间隔；未配置 / 读取失败回退 cfg（读取失败路径用
    /// 现有真实存储验证「未配置」分支，避免为了造错去动存储抽象）。
    #[test]
    fn m2_welcome_interval_prefers_explicit_setting() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("a1")).unwrap();
        assert_eq!(
            sample_interval_for(&state, "a1"),
            state.cfg.sample_interval_ms
        );

        state
            .storage
            .set_sample_interval("a1", 10_000, now_ms())
            .unwrap();
        assert_eq!(sample_interval_for(&state, "a1"), 10_000);

        // 0/越界值（只可能来自损坏数据）不能下发给 agent，必须回退默认值。
        for invalid in [
            0,
            MIN_SAMPLE_INTERVAL_MS - 1,
            MAX_SAMPLE_INTERVAL_MS + 1,
            i64::MAX as u64,
        ] {
            state
                .storage
                .set_sample_interval("a1", invalid, now_ms())
                .unwrap();
            assert_eq!(
                sample_interval_for(&state, "a1"),
                state.cfg.sample_interval_ms,
                "interval={invalid} 必须回退默认值"
            );
        }

        // 边界值本身必须原样下发。
        for valid in [MIN_SAMPLE_INTERVAL_MS, MAX_SAMPLE_INTERVAL_MS] {
            state
                .storage
                .set_sample_interval("a1", valid, now_ms())
                .unwrap();
            assert_eq!(sample_interval_for(&state, "a1"), valid);
        }
    }

    /// hub 本地采样间隔配置校验：1000–300000；越界配置启动失败，兜底值也不会非法。
    #[test]
    fn m2_hub_sample_interval_config_range_is_validated() {
        for invalid in [0, 999, MAX_SAMPLE_INTERVAL_MS + 1, u64::MAX] {
            let cfg = HubConfig {
                sample_interval_ms: invalid,
                ..HubConfig::default()
            };
            let err = validate_hub_sample_interval(&cfg)
                .expect_err(&format!("{invalid}ms 必须被拒绝"))
                .to_string();
            assert!(err.contains("sample_interval_ms"), "错误信息: {err}");
            assert!(
                err.contains("1000") && err.contains("300000"),
                "错误信息: {err}"
            );
        }
        for valid in [MIN_SAMPLE_INTERVAL_MS, 5_000, MAX_SAMPLE_INTERVAL_MS] {
            let cfg = HubConfig {
                sample_interval_ms: valid,
                ..HubConfig::default()
            };
            validate_hub_sample_interval(&cfg).expect("合法配置必须通过");
        }

        // 即使配置层漏校验（例如只有坏配置的单元测试），Welcome 兜底也 clamp 到 1000。
        let mut state = hub_state("token");
        state.cfg = Arc::new(HubConfig {
            sample_interval_ms: 500,
            ..HubConfig::default()
        });
        assert_eq!(
            sample_interval_for(&state, "missing"),
            MIN_SAMPLE_INTERVAL_MS,
            "Welcome 绝不能下发越界配置值"
        );
    }

    /// `admin-token` 子命令必须出现在 --help 里（面板 init 会提示用户运行它）。
    #[test]
    fn m2_admin_token_subcommand_exists() {
        use clap::CommandFactory;
        let mut cmd = Cli::command();
        let admin = cmd
            .find_subcommand_mut("admin-token")
            .expect("admin-token 子命令必须存在");
        assert!(admin.get_arguments().any(|arg| arg.get_id() == "config"));
    }

    /// KI-01：per-IP 上限、计数归零删键、来源表容量与陈旧项清理。
    #[test]
    fn v021_connection_limiter_per_ip_cleanup_and_table_capacity() {
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

        // 一条连接断开、计数归零后立即从表中删除，新 IP 可进入。
        drop(first);
        drop(second);
        let third = limiter.try_acquire(ip3).expect("清理归零项后应有空间");
        drop(other);
        assert_eq!(limiter.tracked_ips(), 1, "ip3 仍在线");
        drop(third);
        assert_eq!(limiter.tracked_ips(), 0, "全部断开后表必须清空");
    }

    /// KI-01：单 IP 洪水达到上限时，已建立连接的凭证不会被回收。
    #[test]
    fn v021_connection_limiter_flood_does_not_displace_established_connection() {
        let limiter = Arc::new(ConnectionLimiter::new(2));
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let established = limiter.try_acquire(ip).expect("已建立连接");
        let flood_a = limiter.try_acquire(ip).expect("洪水第 1 条");
        assert!(matches!(
            limiter.try_acquire(ip),
            Err(ConnectionLimitRejection::PerIp)
        ));
        drop(flood_a);
        assert_eq!(limiter.tracked_ips(), 1, "已建立连接仍必须被计数");
        drop(established);
        assert_eq!(limiter.tracked_ips(), 0, "归零后必须清理");
    }

    /// KI-01：握手 / header 超时必须是 5s（慢速连接不能长期占槽位）。
    #[test]
    fn v021_connection_timeouts_are_five_seconds() {
        assert_eq!(TLS_HANDSHAKE_TIMEOUT, Duration::from_secs(5));
        assert_eq!(HEADER_READ_TIMEOUT, Duration::from_secs(5));
    }

    /// KI-05：固定窗口边界、每 IP 隔离、读写分开计数、0 关闭。
    #[test]
    fn v021_admin_rate_limiter_window_boundary_and_per_ip() {
        use std::sync::atomic::AtomicI64;

        let clock = Arc::new(AtomicI64::new(1_000_000));
        let clock_handle = clock.clone();
        let limiter = AdminRateLimiter::with_clock(
            2,
            1,
            Arc::new(move || clock_handle.load(Ordering::Relaxed)),
        );
        let ip1: IpAddr = "10.1.1.1".parse().unwrap();
        let ip2: IpAddr = "10.1.1.2".parse().unwrap();

        assert!(limiter.check(ip1, false).is_ok());
        assert!(limiter.check(ip1, false).is_ok());
        assert_eq!(limiter.check(ip1, false), Err(60), "第 3 次必须 429");
        // 不同 IP 独立计数。
        assert!(limiter.check(ip2, false).is_ok());

        // 窗口未到（59.999s）：仍拒绝，Retry-After 向上取整到 1s。
        clock.store(1_000_000 + 59_999, Ordering::Relaxed);
        assert_eq!(limiter.check(ip1, false), Err(1));
        // 30s 时剩余 30s。
        clock.store(1_000_000 + 30_000, Ordering::Relaxed);
        assert_eq!(limiter.check(ip1, false), Err(30));
        // 恰好 60s：新窗口，重新放行。
        clock.store(1_000_000 + 60_000, Ordering::Relaxed);
        assert!(limiter.check(ip1, false).is_ok());

        // 写额度独立且更低：1 次后第 2 次拒绝。
        assert!(limiter.check(ip1, true).is_ok());
        assert_eq!(limiter.check(ip1, true), Err(60));
        // 写操作不占用读窗口（读刚重置，仍有额度）。
        assert!(limiter.check(ip1, false).is_ok());

        // 0 表示关闭：不记录任何来源。
        let disabled = AdminRateLimiter::with_clock(0, 0, Arc::new(move || 0));
        for _ in 0..100 {
            disabled.check(ip1, false).unwrap();
            disabled.check(ip1, true).unwrap();
        }
        assert_eq!(disabled.tracked_ips(), 0);
    }

    /// KI-05：限速表达到容量后先清理过期窗口，仍满则拒绝新来源。
    #[test]
    fn v021_admin_rate_limiter_table_capacity_is_bounded() {
        use std::sync::atomic::AtomicI64;

        let clock = Arc::new(AtomicI64::new(1_000_000));
        let clock_handle = clock.clone();
        let limiter = AdminRateLimiter::with_clock(
            1,
            1,
            Arc::new(move || clock_handle.load(Ordering::Relaxed)),
        );
        for index in 0..ADMIN_RATE_TABLE_CAPACITY {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(index as u32));
            limiter.check(ip, false).expect("容量内必须允许");
        }
        assert_eq!(limiter.tracked_ips(), ADMIN_RATE_TABLE_CAPACITY);
        let overflow: IpAddr = "203.0.113.1".parse().unwrap();
        assert!(
            limiter.check(overflow, false).is_err(),
            "容量满且无过期窗口时必须拒绝新来源"
        );

        // 时间推进一个窗口后，旧窗口可被清理，新来源恢复。
        clock.store(1_000_000 + ADMIN_RATE_WINDOW_MS, Ordering::Relaxed);
        limiter
            .check(overflow, false)
            .expect("过期窗口清理后必须允许新来源");
        assert!(limiter.tracked_ips() <= ADMIN_RATE_TABLE_CAPACITY);
    }

    /// KI-05：管理 API 第 N+1 次请求 429 + Retry-After；不同 IP / 读写互不影响。
    #[tokio::test]
    async fn v021_admin_api_rate_limit_returns_429() {
        let state = hub_state_with(HubConfig {
            admin_token: "token".to_string(),
            admin_rate_limit_per_min: 3,
            admin_write_rate_limit_per_min: 1,
            ..HubConfig::default()
        });
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let router = admin_router(state);

        // 未认证请求不消耗额度。
        for _ in 0..5 {
            let (status, _, _) = admin_call(&router, "GET", "/api/v1/agents", None, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        for _ in 0..3 {
            let (status, _, _) =
                admin_call(&router, "GET", "/api/v1/agents", Some("token"), None).await;
            assert_eq!(status, StatusCode::OK);
        }
        let (status, headers, body) =
            admin_call(&router, "GET", "/api/v1/agents", Some("token"), None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json_body(&body)["error"], "rate_limited");
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        let retry: u64 = headers
            .get(header::RETRY_AFTER)
            .expect("429 必须带 Retry-After")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry), "Retry-After 非法: {retry}");

        // 不同 IP 完全独立。
        let (status, _, _) = admin_call_from(
            &router,
            "127.0.0.2",
            "GET",
            "/api/v1/agents",
            Some("token"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "不同 IP 不得互相影响");

        // 写额度独立（默认/此处为 1/min）：第一次 PUT 允许，第二次 429。
        let payload = "{\"sample_interval_ms\":10000}";
        let (status, _, _) = admin_call(
            &router,
            "PUT",
            "/api/v1/agents/agent-1/settings",
            Some("token"),
            Some(payload),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, body) = admin_call(
            &router,
            "PUT",
            "/api/v1/agents/agent-1/settings",
            Some("token"),
            Some(payload),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(json_body(&body)["error"], "rate_limited");
    }

    /// KI-08：未知 /api/v1/* 无 token 先 401；带 token 才 404；/healthz 保持公开。
    #[tokio::test]
    async fn v021_unknown_api_requires_bearer_before_404() {
        let router = admin_router(hub_state("token"));

        for path in [
            "/api/v1",
            "/api/v1/does-not-exist",
            "/api/v1/agents/x/extra",
        ] {
            let (status, _, body) = admin_call(&router, "GET", path, None, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "path={path}");
            assert_eq!(json_body(&body)["error"], "unauthorized", "path={path}");

            let (status, _, body) = admin_call(&router, "GET", path, Some("token"), None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "path={path}");
            assert_eq!(json_body(&body)["error"], "not_found", "path={path}");
        }

        let (status, _, _) = admin_call(&router, "GET", "/healthz", None, None).await;
        assert_eq!(status, StatusCode::OK, "/healthz 必须保持免鉴权");
        // 具体路由优先级不受兜底影响。
        let (status, _, _) =
            admin_call(&router, "GET", "/api/v1/agents", Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// v0.3.3：off 只允许回环；required 要求非通配绑定 IP 有对应 SAN；非法地址启动失败。
    #[test]
    fn v033_admin_tls_startup_validation() {
        let with = |listen: &str, mode: AdminTlsMode| HubConfig {
            admin_listen: listen.to_string(),
            admin_tls: mode,
            ..HubConfig::default()
        };

        // off + 回环：保持原有明文行为。
        for addr in ["127.0.0.1:8444", "127.1.2.3:1", "[::1]:8444"] {
            validate_admin_tls(&with(addr, AdminTlsMode::Off))
                .unwrap_or_else(|err| panic!("回环明文必须放行 {addr}: {err:#}"));
        }
        // off + 非回环：v0.3.3 起拒绝启动，错误信息给出两条迁移路径。
        for addr in [
            "0.0.0.0:8444",
            "192.168.1.10:8444",
            "8.8.8.8:8444",
            "[::]:8444",
        ] {
            let err = validate_admin_tls(&with(addr, AdminTlsMode::Off))
                .expect_err("非回环明文必须拒绝启动");
            let text = format!("{err:#}");
            assert!(text.contains("admin_tls=\"required\""), "错误信息: {text}");
            assert!(text.contains("回环"), "错误信息: {text}");
        }
        assert!(
            validate_admin_tls(&with("not-an-address", AdminTlsMode::Off)).is_err(),
            "非法监听地址必须与 bind 一样启动失败"
        );

        // required：绑定 IP 必须在 server_names 里（默认含 127.0.0.1）。
        validate_admin_tls(&with("127.0.0.1:8444", AdminTlsMode::Required))
            .expect("127.0.0.1 默认在 server_names，required 必须放行");
        let err = validate_admin_tls(&with("127.0.0.2:8444", AdminTlsMode::Required))
            .expect_err("缺失 IP SAN 必须拒绝启动");
        let text = format!("{err:#}");
        assert!(text.contains("server_names"), "错误信息: {text}");
        assert!(text.contains("rotate-cert"), "错误信息: {text}");

        // 比较前 trim：带空格的 IP 也算覆盖。
        let trimmed = HubConfig {
            admin_listen: "127.0.0.1:8444".to_string(),
            admin_tls: AdminTlsMode::Required,
            server_names: vec![" 127.0.0.1 ".to_string()],
            ..HubConfig::default()
        };
        validate_admin_tls(&trimmed).expect("trim 后的 IP 必须视为覆盖");

        // DNS 访问：非回环 bind IP 不在 SAN 里，但 server_names 有 DNS 名 → 放行。
        let dns = HubConfig {
            admin_listen: "10.0.0.5:8444".to_string(),
            admin_tls: AdminTlsMode::Required,
            server_names: vec!["hub.example.com".to_string()],
            ..HubConfig::default()
        };
        validate_admin_tls(&dns).expect("管理端通过 DNS 访问时必须放行");

        // 只有不匹配的 IP、没有任何 DNS 名 → 仍拒绝。
        let mismatched = HubConfig {
            admin_listen: "10.0.0.5:8444".to_string(),
            admin_tls: AdminTlsMode::Required,
            server_names: vec!["127.0.0.1".to_string()],
            ..HubConfig::default()
        };
        let err = validate_admin_tls(&mismatched).expect_err("只有不匹配 IP 时必须拒绝");
        assert!(format!("{err:#}").contains("DNS SAN"), "错误信息: {err:#}");

        // 回环绑定不能用 DNS 名兜底：本机只能通过该回环 IP 访问。
        let loopback_dns = HubConfig {
            admin_listen: "127.0.0.2:8444".to_string(),
            admin_tls: AdminTlsMode::Required,
            server_names: vec!["hub.example.com".to_string()],
            ..HubConfig::default()
        };
        assert!(
            validate_admin_tls(&loopback_dns).is_err(),
            "回环 bind + 仅 DNS SAN 必须拒绝（init 127.0.0.2 用例依赖此语义）"
        );

        // 通配绑定跳过 SAN 检查（由客户端 hostname/反代决定访问名）。
        for addr in ["0.0.0.0:8444", "[::]:8444"] {
            validate_admin_tls(&with(addr, AdminTlsMode::Required))
                .unwrap_or_else(|err| panic!("通配绑定必须放行 {addr}: {err:#}"));
        }
        assert!(all_loopback_server_names(&[
            "127.0.0.1".to_string(),
            " localhost ".to_string(),
            "api.localhost".to_string(),
        ]));
        assert!(!all_loopback_server_names(&[
            "127.0.0.1".to_string(),
            "hub.example.com".to_string(),
        ]));
        assert!(all_loopback_server_names(&[" ::1 ".to_string()]));
    }

    /// KI-10：`/api/v1/system` 保留旧字段并新增 live/disk，顶层等于 live。
    #[tokio::test]
    async fn v021_system_info_exposes_live_and_disk_compatibly() {
        let dir = temp_dir("system-live-disk");
        tls::ensure_hub_material(&dir, &["localhost".to_string()], tls::CertPolicy::default())
            .unwrap();
        let cfg = HubConfig {
            data_dir: dir.clone(),
            admin_token: "token".to_string(),
            server_names: vec!["localhost".to_string()],
            ..HubConfig::default()
        };
        let mut state = hub_state_with(cfg);
        // live 摘要里的 days_left 故意写错：请求时必须按 not_after 重算。
        let not_after = now_ms() / 1_000 + 2 * 86_400;
        let live = CertStatus {
            fingerprint: "live-fingerprint".to_string(),
            not_after,
            days_left: 999,
        };
        state.live_cert = Arc::new(RwLock::new(live));
        let router = admin_router(state);

        let (status, _, body) =
            admin_call(&router, "GET", "/api/v1/system", Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        assert_eq!(body["protocol"], PROTOCOL_VERSION);
        assert_eq!(body["cert"]["live"]["fingerprint"], "live-fingerprint");
        assert_eq!(body["cert"]["live"]["not_after"], not_after);
        assert_eq!(
            body["cert"]["live"]["days_left"], 2,
            "days_left 必须按请求时间重算，不能冻结加载时的值"
        );
        // 顶层旧字段必须等于 live，避免旧面板显示成磁盘上的未生效证书。
        assert_eq!(body["cert"]["fingerprint"], "live-fingerprint");
        assert_eq!(body["cert"]["not_after"], not_after);
        assert_eq!(body["cert"]["days_left"], 2);

        let disk_pem =
            std::fs::read_to_string(tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE)).unwrap();
        let disk_fp = tls::fingerprint_of_pem(&disk_pem).unwrap();
        assert_eq!(body["cert"]["disk"]["fingerprint"], disk_fp);
        assert_ne!(body["cert"]["disk"]["fingerprint"], "live-fingerprint");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KI-11：持锁时 rotate-cert 立即失败且不写证书；释放后可正常轮换。
    #[test]
    fn v021_rotate_cert_respects_lock_and_does_not_write_when_held() {
        let dir = temp_dir("rotate-lock");
        tls::ensure_hub_material(&dir, &["localhost".to_string()], tls::CertPolicy::default())
            .unwrap();
        let cfg = HubConfig {
            data_dir: dir.clone(),
            admin_token: "token".to_string(),
            server_names: vec!["localhost".to_string()],
            ..HubConfig::default()
        };
        let cfg_path = dir.join("hub.toml");
        cfg.save(&cfg_path).unwrap();
        let cert_path = tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE);
        let before = std::fs::read_to_string(&cert_path).unwrap();
        let before_fingerprint = tls::fingerprint_of_pem(&before).unwrap();

        let lock = cert_rotation::CertLock::acquire(&tls::cert_dir(&dir)).unwrap();
        let err = rotate_cert(Some(cfg_path.clone()), true, Some(30))
            .expect_err("持锁时第二个 rotate-cert 必须失败");
        assert!(
            format!("{err:#}").contains("另一个 rotate-cert 正在运行"),
            "错误信息: {err:#}"
        );
        assert_eq!(
            std::fs::read_to_string(&cert_path).unwrap(),
            before,
            "获取锁失败时绝不能写证书"
        );
        drop(lock);
        assert!(!tls::cert_dir(&dir)
            .join(cert_rotation::CERT_LOCK_FILE)
            .exists());

        rotate_cert(Some(cfg_path), true, Some(30)).expect("释放锁后必须能正常轮换");
        let after = std::fs::read_to_string(&cert_path).unwrap();
        assert_ne!(
            tls::fingerprint_of_pem(&after).unwrap(),
            before_fingerprint,
            "正常轮换必须换证书"
        );
        assert!(
            !tls::cert_dir(&dir)
                .join(cert_rotation::CERT_LOCK_FILE)
                .exists(),
            "rotate 结束后必须删除锁文件"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------------
    // M3：控制面管理 API / 审计
    // ------------------------------------------------------------------

    use rustboard_common::config::HubControlConfig;
    use rustboard_common::control::{
        ControlError, ControlResult, DockerContainer, LogSourceInfo, ProcessInfo, SystemdUnit,
    };
    use rustboard_core::storage::AuditEntry;

    const M3_TOKEN: &str = "m3-control-test-token";

    fn m3_control_cfg() -> HubControlConfig {
        HubControlConfig {
            enabled: true,
            systemd: true,
            docker: true,
            process: true,
            logs: true,
            request_timeout_ms: 1_000,
            max_pending_per_session: 8,
            max_output_bytes: 262_144,
        }
    }

    fn m3_state(control: HubControlConfig) -> AppState {
        hub_state_with(HubConfig {
            admin_token: M3_TOKEN.to_string(),
            // 限速在 v0.2.1 已有专门测试；这里关闭，避免多次 POST 触发 10/min。
            admin_rate_limit_per_min: 0,
            admin_write_rate_limit_per_min: 0,
            control,
            ..HubConfig::default()
        })
    }

    /// 建好 agents 记录 + 能力行并注册一条在线会话，返回的句柄必须活到测试结束。
    fn m3_register_agent(
        state: &AppState,
        agent_id: &str,
        capabilities: &[&str],
    ) -> crate::session::SessionHandle {
        state.storage.upsert_agent(&test_agent(agent_id)).unwrap();
        state
            .storage
            .upsert_agent_control(
                agent_id,
                &capabilities
                    .iter()
                    .map(|cap| cap.to_string())
                    .collect::<Vec<_>>(),
                now_ms(),
            )
            .unwrap();
        state.sessions.register(agent_id)
    }

    /// 在会话侧按顺序应答控制命令；返回已应答条数。
    fn m3_spawn_responder(
        mut rx: tokio::sync::mpsc::Receiver<ControlCommand>,
        responses: Vec<std::result::Result<ControlResult, ControlError>>,
    ) -> tokio::task::JoinHandle<usize> {
        tokio::spawn(async move {
            let mut served = 0;
            for response in responses {
                let Some(command) = rx.recv().await else {
                    break;
                };
                let _ = command.reply.send(response);
                served += 1;
            }
            served
        })
    }

    async fn m3_post(
        router: &Router,
        agent_id: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (status, _, bytes) = admin_call(
            router,
            "POST",
            &format!("/api/v1/agents/{agent_id}/control"),
            Some(M3_TOKEN),
            Some(body),
        )
        .await;
        (status, json_body(&bytes))
    }

    async fn m3_get(router: &Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let (status, _, bytes) = admin_call(router, "GET", uri, Some(M3_TOKEN), None).await;
        (status, json_body(&bytes))
    }

    fn m3_audit(state: &AppState) -> Vec<AuditEntry> {
        state.storage.list_audit(500, None, None, None).unwrap()
    }

    /// 能力状态：hub 开关、agent 上报、在线状态各来源正确；GET 不写审计。
    #[tokio::test]
    async fn m3_control_status_reports_capabilities_without_audit() {
        let state = m3_state(m3_control_cfg());
        let handle = m3_register_agent(&state, "a1", &["systemd", "logs"]);
        // 直接写入未知能力，GET 必须过滤掉（旧 agent / 恶意 Hello 的历史数据）。
        state
            .storage
            .upsert_agent_control(
                "a1",
                &[
                    "systemd".to_string(),
                    "shell".to_string(),
                    "logs".to_string(),
                ],
                now_ms(),
            )
            .unwrap();
        let router = admin_router(state.clone());

        let (status, body) = m3_get(&router, "/api/v1/agents/a1/control").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["control_enabled"], true);
        assert_eq!(body["online"], true);
        assert_eq!(body["capabilities"], serde_json::json!(["systemd", "logs"]));
        assert_eq!(
            body["hub_capabilities"],
            serde_json::json!(["systemd", "docker", "process", "logs"])
        );

        // 注销后在线状态立即变 false，但能力历史保留。
        assert!(state.sessions.unregister("a1", handle.conn_id));
        drop(handle);
        assert!(!state.sessions.has_active("a1"));
        let (status, body) = m3_get(&router, "/api/v1/agents/a1/control").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["online"], false);
        assert_eq!(body["capabilities"], serde_json::json!(["systemd", "logs"]));

        // 旧 agent：agents 行存在但没有能力行 → 200 + 空能力。
        state.storage.upsert_agent(&test_agent("legacy")).unwrap();
        let (status, body) = m3_get(&router, "/api/v1/agents/legacy/control").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["capabilities"], serde_json::json!([]));
        assert_eq!(body["online"], false);

        // 完全不存在的 agent → 404。
        let (status, _) = m3_get(&router, "/api/v1/agents/missing/control").await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // GET 不写审计。
        assert!(m3_audit(&state).is_empty(), "只读接口不得写审计");
    }

    /// 双端开关：hub 关闭 / agent 未上报 → 403；无会话 → 503。
    #[tokio::test]
    async fn m3_control_post_capability_gates_and_offline() {
        let mut cfg = m3_control_cfg();
        cfg.systemd = false;
        let state = m3_state(cfg);
        let _online = m3_register_agent(&state, "a1", &["systemd"]);
        let router = admin_router(state.clone());

        let (status, body) =
            m3_post(&router, "a1", r#"{"capability":"systemd","action":"list"}"#).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "capability_disabled");

        // hub 开启但 agent 未上报该能力 → 403。
        let mut cfg = m3_control_cfg();
        cfg.logs = true;
        let state2 = m3_state(cfg);
        let _online2 = m3_register_agent(&state2, "a2", &["docker"]);
        let router2 = admin_router(state2.clone());
        let (status, body) = m3_post(
            &router2,
            "a2",
            r#"{"capability":"systemd","action":"list"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "capability_disabled");

        // 能力已上报但没有活跃会话 → 503 agent_offline。
        state2.storage.upsert_agent(&test_agent("a3")).unwrap();
        state2
            .storage
            .upsert_agent_control("a3", &["docker".to_string()], now_ms())
            .unwrap();
        let (status, body) =
            m3_post(&router2, "a3", r#"{"capability":"docker","action":"list"}"#).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "agent_offline");

        // 总开关关闭：即使单项都写 true 也 403（配置层会拒绝这种组合，这里直接构造）。
        let mut cfg = m3_control_cfg();
        cfg.enabled = false;
        let state3 = m3_state(cfg);
        let _online3 = m3_register_agent(&state3, "a4", &["logs"]);
        let router3 = admin_router(state3.clone());
        let (status, body) =
            m3_post(&router3, "a4", r#"{"capability":"logs","action":"list"}"#).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "capability_disabled");

        // 所有拒绝都落审计。
        for state in [&state, &state2, &state3] {
            let entries = m3_audit(state);
            assert!(!entries.is_empty(), "拒绝也必须写审计");
            assert!(entries.iter().all(|entry| entry.actor == "admin"));
            assert!(entries.iter().all(|entry| entry.result != "ok"));
        }
    }

    /// 参数校验全部 400 invalid_request，且带审计。
    #[tokio::test]
    async fn m3_control_post_validation_failures_are_audited() {
        let state = m3_state(m3_control_cfg());
        let _online = m3_register_agent(&state, "a1", &["systemd", "process", "logs"]);
        let router = admin_router(state.clone());

        let too_long = "a".repeat(rustboard_common::control::MAX_TARGET_LEN + 1);
        let long_body = format!(
            r#"{{"capability":"systemd","action":"restart","target":"{too_long}","confirm":true}}"#
        );
        let cases = [
            r#"{"capability":"systemd","action":"restart","target":"nginx.service"}"#.to_string(),
            r#"{"capability":"process","action":"kill","pid":1,"name":"systemd","signal":"term","confirm":true}"#.to_string(),
            r#"{"capability":"logs","action":"tail","source":"nginx-error","lines":2001}"#.to_string(),
            r#"{"capability":"logs","action":"list","unknown":true}"#.to_string(),
            r#"{"capability":"systemd""#.to_string(),
            long_body,
        ];
        for body in cases {
            let (status, body) = m3_post(&router, "a1", &body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["ok"], false);
            assert_eq!(body["error"]["code"], "invalid_request");
        }

        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 6, "每次拒绝都要写一条审计");
        assert!(entries.iter().all(|entry| entry.result == "denied"));
        assert!(entries
            .iter()
            .all(|entry| entry.error_code == "invalid_request"));
    }

    /// 成功路径：6 种结果形状、审计内容与分页过滤。
    #[tokio::test]
    async fn m3_control_post_success_shapes_and_audit_pagination() {
        let state = m3_state(m3_control_cfg());
        let handle = m3_register_agent(&state, "a1", &["systemd", "docker", "process", "logs"]);
        let responder = m3_spawn_responder(
            handle.control_rx,
            vec![
                Ok(ControlResult::SystemdUnits(vec![SystemdUnit {
                    unit: "nginx.service".into(),
                    load: "loaded".into(),
                    active: "active".into(),
                    sub: "running".into(),
                    description: "Nginx".into(),
                }])),
                Ok(ControlResult::ActionOutput {
                    stdout: "restarted".into(),
                    stderr: String::new(),
                    exit_code: Some(0),
                }),
                Ok(ControlResult::DockerContainers(vec![DockerContainer {
                    name: "web-1".into(),
                    image: "nginx:latest".into(),
                    state: "running".into(),
                    status: "Up 1 hour".into(),
                    id: "abc".into(),
                }])),
                Ok(ControlResult::Processes(vec![ProcessInfo {
                    pid: 42,
                    name: "sleep".into(),
                    cmdline: "sleep 300".into(),
                    uid: 0,
                    rss_kb: 1024,
                }])),
                Ok(ControlResult::LogSources(vec![LogSourceInfo {
                    id: "nginx-error".into(),
                    kind: rustboard_common::config::LogSourceKind::File,
                    target: "/var/log/nginx/error.log".into(),
                    name: "Nginx".into(),
                }])),
                Ok(ControlResult::LogLines {
                    source: "nginx-error".into(),
                    lines: vec!["line-3".into(), "line-4".into()],
                    truncated: false,
                    size_bytes: 42,
                }),
            ],
        );
        let router = admin_router(state.clone());

        let (status, body) =
            m3_post(&router, "a1", r#"{"capability":"systemd","action":"list"}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(body["result"]["type"], "systemd_units");
        assert_eq!(body["result"]["units"][0]["unit"], "nginx.service");

        let (status, body) = m3_post(
            &router,
            "a1",
            r#"{"capability":"systemd","action":"restart","target":"nginx.service","confirm":true}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["type"], "action_output");
        assert_eq!(body["result"]["exit_code"], 0);

        let (status, body) =
            m3_post(&router, "a1", r#"{"capability":"docker","action":"list"}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["containers"][0]["name"], "web-1");

        let (status, body) =
            m3_post(&router, "a1", r#"{"capability":"process","action":"list"}"#).await;
        assert_eq!(status, StatusCode::OK);
        // 面板契约：rss_kb 是线协议原字段。
        assert_eq!(body["result"]["processes"][0]["rss_kb"], 1024);
        assert!(body["result"]["processes"][0].get("rss").is_none());

        let (status, body) =
            m3_post(&router, "a1", r#"{"capability":"logs","action":"list"}"#).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["sources"][0]["kind"], "file");
        assert_eq!(
            body["result"]["sources"][0]["target"],
            "/var/log/nginx/error.log"
        );
        assert!(body["result"]["sources"][0].get("size").is_none());

        let (status, body) = m3_post(
            &router,
            "a1",
            r#"{"capability":"logs","action":"tail","source":"nginx-error","lines":200}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["result"]["type"], "log_lines");
        assert_eq!(body["result"]["lines"][0], "line-3");
        assert_eq!(body["result"]["size_bytes"], 42);

        assert_eq!(responder.await.unwrap(), 6, "6 条命令都应送达会话");

        // 审计：actor / capability / action / target / params 全部受限且不含输出。
        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 6);
        assert!(entries.iter().all(|entry| entry.actor == "admin"));
        assert!(entries.iter().all(|entry| entry.result == "ok"));
        assert!(entries.iter().all(|entry| entry.error_code.is_empty()));
        let restart = entries
            .iter()
            .find(|entry| entry.action == "restart")
            .expect("应有 restart 审计");
        assert_eq!(restart.capability, "systemd");
        assert_eq!(restart.target, "nginx.service");
        let params: serde_json::Value = serde_json::from_str(&restart.params).unwrap();
        assert_eq!(params["target"], "nginx.service");
        assert!(params.get("stdout").is_none(), "params 绝不能包含命令输出");
        let tail = entries
            .iter()
            .find(|entry| entry.action == "tail")
            .expect("应有 tail 审计");
        let params: serde_json::Value = serde_json::from_str(&tail.params).unwrap();
        assert_eq!(params["lines"], 200);
        assert!(!restart.params.contains("restarted"));

        // 分页：limit=2 + before_id 排他游标，第二页严格小于游标且不重复。
        let (status, page) = m3_get(&router, "/api/v1/audit?limit=2").await;
        assert_eq!(status, StatusCode::OK);
        let ids: Vec<i64> = page["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids.len(), 2);
        let cursor = page["next_before_id"].as_i64().expect("满页必须有游标");
        assert_eq!(cursor, ids[1]);

        let (status, page2) = m3_get(
            &router,
            &format!("/api/v1/audit?limit=2&before_id={cursor}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let ids2: Vec<i64> = page2["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["id"].as_i64().unwrap())
            .collect();
        assert!(
            ids2.iter().all(|id| *id < cursor),
            "before_id 必须是排他游标"
        );
        assert!(ids2.iter().all(|id| !ids.contains(id)));

        // 过滤：capability / agent_id。
        let (status, page) = m3_get(&router, "/api/v1/audit?limit=50&capability=systemd").await;
        assert_eq!(status, StatusCode::OK);
        let entries = page["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry["capability"] == "systemd"));

        let (status, page) = m3_get(&router, "/api/v1/audit?limit=50&agent_id=a1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["entries"].as_array().unwrap().len(), 6);

        let (status, page) = m3_get(&router, "/api/v1/audit?limit=50&agent_id=other").await;
        assert_eq!(status, StatusCode::OK);
        assert!(page["entries"].as_array().unwrap().is_empty());
        assert!(page["next_before_id"].is_null());

        // 大量 GET 之后审计条数不变：只读接口不写审计。
        assert_eq!(m3_audit(&state).len(), 6);
    }

    /// agent 错误映射 + 超时 504；两者都不能回显 agent 输出。
    #[tokio::test]
    async fn m3_control_post_maps_agent_errors_and_timeout() {
        const SECRET: &str = "SECRET-STDERR-MUST-NOT-LEAK";
        let mut cfg = m3_control_cfg();
        cfg.request_timeout_ms = 20;
        let state = m3_state(cfg);
        let handle = m3_register_agent(&state, "a1", &["systemd", "docker"]);
        let responder = m3_spawn_responder(
            handle.control_rx,
            vec![
                Err(ControlError::not_whitelisted(SECRET)),
                Err(ControlError::control_failed(SECRET)),
            ],
        );
        // 另一台在线 agent 故意不应答：覆盖超时分支（保持句柄存活让通道不关闭）。
        let _silent = m3_register_agent(&state, "a2", &["docker"]);
        let router = admin_router(state.clone());

        let body = r#"{"capability":"systemd","action":"restart","target":"nginx.service","confirm":true}"#;
        let (status, response) = m3_post(&router, "a1", body).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(response["error"]["code"], "not_whitelisted");
        assert!(
            !response.to_string().contains(SECRET),
            "不得回显 agent 错误详情"
        );

        let (status, response) = m3_post(&router, "a1", body).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(response["error"]["code"], "control_failed");
        assert!(!response.to_string().contains(SECRET));

        assert_eq!(responder.await.unwrap(), 2);

        let (status, response) =
            m3_post(&router, "a2", r#"{"capability":"docker","action":"list"}"#).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(response["error"]["code"], "control_timeout");

        // 按 id 倒序：最近一条是超时，最早一条是 agent 拒绝。
        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].result, "error");
        assert_eq!(entries[0].error_code, "control_timeout");
        assert_eq!(entries[1].error_code, "control_failed");
        assert_eq!(entries[2].result, "denied");
        assert_eq!(entries[2].error_code, "not_whitelisted");
        assert!(
            entries.iter().all(
                |entry| !entry.error_message.contains(SECRET) && !entry.params.contains(SECRET)
            ),
            "审计不得写入 agent 错误详情"
        );
    }

    /// #19 e2e 回归：agent 允许约 256 KiB 的日志结果，MessagePack 编码后的
    /// `ControlResponse` 单帧会略超旧的 256 KiB 单帧上限；单帧上限必须与消息
    /// 上限一致，否则合法结果被 tungstenite 拒绝并连带关闭 agent 会话。
    #[test]
    fn v032_control_result_frame_fits_within_ws_frame_limit() {
        use rustboard_common::control::ControlResponse;

        // 2000 行 × 130B = 260,000B，低于 MAX_OUTPUT_BYTES(262144)；
        // 加上每行换行与编码开销后刚好越过旧的 256 KiB 单帧上限。
        let lines: Vec<String> = (0..2000).map(|_| "x".repeat(130)).collect();
        let result = ControlResult::LogLines {
            source: "journal".into(),
            lines,
            truncated: true,
            size_bytes: 260_000,
        };
        let encoded = Frame::ControlResponse(ControlResponse::success(1, result))
            .encode()
            .expect("控制结果必须可编码");

        assert!(
            encoded.len() > 256 * 1024,
            "编码后 {} 字节必须超过旧的 256 KiB 单帧上限，否则测试无法复现缺陷",
            encoded.len()
        );
        assert!(
            encoded.len() <= MAX_WS_MESSAGE_SIZE,
            "编码后 {} 字节必须落在消息上限内",
            encoded.len()
        );
        assert!(
            encoded.len() <= MAX_WS_FRAME_SIZE,
            "编码后 {} 字节必须落在单帧上限内",
            encoded.len()
        );
        assert_eq!(
            MAX_WS_FRAME_SIZE, MAX_WS_MESSAGE_SIZE,
            "单帧上限不得小于合法消息上限"
        );
    }

    /// 评审严重回归：hub 的 WS 单帧 / 单消息上限必须大于 agent 的控制应答预算，
    /// 避免未来常量漂移后合法应答在 hub 侧被拒绝并断开会话。
    #[test]
    fn v032_ws_message_limit_covers_control_response_budget() {
        let budget = rustboard_common::control::MAX_CONTROL_RESPONSE_BYTES;
        assert!(
            MAX_WS_MESSAGE_SIZE > budget,
            "WS 消息上限 {MAX_WS_MESSAGE_SIZE} 必须大于控制应答预算 {budget}"
        );
        assert!(
            MAX_WS_FRAME_SIZE > budget,
            "WS 单帧上限 {MAX_WS_FRAME_SIZE} 必须大于控制应答预算 {budget}"
        );
    }

    /// 控制结果在 hub 侧按 max_output_bytes 截断，不信任 agent 长度。
    #[tokio::test]
    async fn m3_control_result_is_capped_by_hub_max_output_bytes() {
        let mut cfg = m3_control_cfg();
        cfg.max_output_bytes = 1024;
        let state = m3_state(cfg);
        let handle = m3_register_agent(&state, "a1", &["logs"]);
        let lines: Vec<String> = (0..500).map(|_| "x".repeat(4096)).collect();
        let responder = m3_spawn_responder(
            handle.control_rx,
            vec![Ok(ControlResult::LogLines {
                source: "nginx-error".into(),
                lines,
                truncated: false,
                size_bytes: 10_000_000,
            })],
        );
        let router = admin_router(state.clone());

        let (status, body) = m3_post(
            &router,
            "a1",
            r#"{"capability":"logs","action":"tail","source":"nginx-error","lines":200}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let result_bytes = serde_json::to_vec(&body["result"]).unwrap().len();
        assert!(
            result_bytes <= 1024,
            "result 必须被截断到 max_output_bytes 以内，实际 {result_bytes}"
        );
        assert_eq!(body["result"]["type"], "log_lines");
        assert_eq!(body["result"]["truncated"], true);
        assert_eq!(responder.await.unwrap(), 1);
    }

    /// 审计查询参数校验：limit 1–200、before_id 正整数、过滤值合法。
    #[tokio::test]
    async fn m3_audit_query_validation() {
        let state = m3_state(m3_control_cfg());
        let router = admin_router(state.clone());
        for query in [
            "/api/v1/audit?limit=0",
            "/api/v1/audit?limit=201",
            "/api/v1/audit?limit=abc",
            "/api/v1/audit?before_id=0",
            "/api/v1/audit?before_id=-1",
            "/api/v1/audit?agent_id=bad%2Fid",
            "/api/v1/audit?agent_id=",
            "/api/v1/audit?capability=",
            "/api/v1/audit?limit=1&limit=2",
        ] {
            let (status, _) = m3_get(&router, query).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
        }
        let (status, body) = m3_get(&router, "/api/v1/audit").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["entries"].as_array().unwrap().is_empty());
        assert!(body["next_before_id"].is_null());
    }

    /// 命令非零退出码：响应仍 200 + 真实 exit_code，但审计必须记 error
    /// （control_failed），且不得回显 stderr。
    #[tokio::test]
    async fn m3_control_nonzero_exit_is_audited_as_error() {
        const SECRET: &str = "SECRET-STDERR-MUST-NOT-LEAK";
        let state = m3_state(m3_control_cfg());
        let handle = m3_register_agent(&state, "a1", &["docker"]);
        let responder = m3_spawn_responder(
            handle.control_rx,
            vec![Ok(ControlResult::ActionOutput {
                stdout: "restarting".into(),
                stderr: SECRET.into(),
                exit_code: Some(5),
            })],
        );
        let router = admin_router(state.clone());

        let (status, body) = m3_post(
            &router,
            "a1",
            r#"{"capability":"docker","action":"restart","target":"web-1","confirm":true}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(body["result"]["exit_code"], 5);
        assert_eq!(responder.await.unwrap(), 1);

        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].result, "error");
        assert_eq!(entries[0].error_code, "control_failed");
        assert_eq!(entries[0].error_message, "命令退出码非 0");
        assert!(
            !entries[0].error_message.contains(SECRET) && !entries[0].params.contains(SECRET),
            "审计不得回显 stderr"
        );
    }

    /// 会话 pending 满（`too_many_pending`）必须映射 429，而不是 502。
    #[tokio::test]
    async fn m3_control_pending_limit_maps_to_429() {
        let state = m3_state(m3_control_cfg());
        let handle = m3_register_agent(&state, "a1", &["logs"]);
        let responder = m3_spawn_responder(
            handle.control_rx,
            vec![Err(ControlError::new("too_many_pending", "待处理命令过多"))],
        );
        let router = admin_router(state.clone());

        let (status, body) =
            m3_post(&router, "a1", r#"{"capability":"logs","action":"list"}"#).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "too_many_pending");
        assert_eq!(responder.await.unwrap(), 1);

        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].result, "error");
        assert_eq!(entries[0].error_code, "too_many_pending");
    }

    /// POST /control 对完全不存在的 agent 返回 404（与 GET 一致）；
    /// 老 agent（agents 行存在、无能力行）仍按能力未上报回 403。
    #[tokio::test]
    async fn m3_control_post_unknown_agent_is_404() {
        let state = m3_state(m3_control_cfg());
        let router = admin_router(state.clone());

        let (status, body) = m3_post(
            &router,
            "missing",
            r#"{"capability":"systemd","action":"list"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "agent_not_found");

        // 老 agent：有 agents 行但没有 agent_control 行 → 403 capability_disabled。
        state.storage.upsert_agent(&test_agent("legacy")).unwrap();
        let (status, body) = m3_post(
            &router,
            "legacy",
            r#"{"capability":"systemd","action":"list"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "capability_disabled");

        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].error_code, "agent_not_found");
        assert_eq!(entries[1].result, "denied");
        assert_eq!(entries[0].error_code, "capability_disabled");
    }

    /// 超过 64 KiB 管理 API 请求体上限时回 413 payload_too_large（不是 400），
    /// 并且仍然写一条审计。
    #[tokio::test]
    async fn m3_control_post_oversized_body_is_413() {
        let state = m3_state(m3_control_cfg());
        let router = admin_router(state.clone());
        let body = format!(
            r#"{{"capability":"systemd","action":"list","padding":"{}"}}"#,
            "x".repeat(70_000)
        );

        let (status, response) = m3_post(&router, "a1", &body).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(response["ok"], false);
        assert_eq!(response["error"]["code"], "payload_too_large");

        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].error_code, "payload_too_large");
        assert_eq!(entries[0].result, "denied");
    }

    /// 命令被信号杀死（exit_code = None）：响应仍 200 + exit_code=null，
    /// 但审计必须记 error/control_failed，文案区分「命令被信号终止」。
    #[tokio::test]
    async fn m3_control_signaled_command_is_audited_as_error() {
        let state = m3_state(m3_control_cfg());
        let handle = m3_register_agent(&state, "a1", &["docker"]);
        let responder = m3_spawn_responder(
            handle.control_rx,
            vec![Ok(ControlResult::ActionOutput {
                stdout: "stopping".into(),
                stderr: String::new(),
                exit_code: None,
            })],
        );
        let router = admin_router(state.clone());

        let (status, body) = m3_post(
            &router,
            "a1",
            r#"{"capability":"docker","action":"restart","target":"web-1","confirm":true}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert!(
            body["result"]["exit_code"].is_null(),
            "被信号终止时响应仍返回 exit_code=null"
        );
        assert_eq!(responder.await.unwrap(), 1);

        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].result, "error");
        assert_eq!(entries[0].error_code, "control_failed");
        assert_eq!(entries[0].error_message, "命令被信号终止");
    }

    // ------------------------------------------------------------------
    // #14：会话清理与在线状态竞态（真实 SQLite 集成）
    // ------------------------------------------------------------------

    /// 真实 SQLite（临时目录文件库）+ 独立注册表，用于会话清理测试。
    fn session_cleanup_fixture(tag: &str) -> (PathBuf, Arc<SqliteStorage>, Arc<SessionRegistry>) {
        let dir = temp_dir(tag);
        let storage = Arc::new(SqliteStorage::open(&dir.join("hub.db")).expect("打开测试库失败"));
        (dir, storage, SessionRegistry::new())
    }

    fn agent_status(storage: &SqliteStorage, agent_id: &str) -> String {
        storage
            .get_agent(agent_id)
            .expect("读取 agent 失败")
            .expect("agent 记录必须存在")
            .status
    }

    /// c. 真正最后一条连接断开：回调执行一次，DB 置 offline；`finished` 保证 Drop
    /// 只清理一次，之后新连接写的 online 不会被二次清理覆盖。
    #[test]
    fn session_cleanup_marks_offline_after_last_connection() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-offline");
        storage.upsert_agent(&test_agent("a1")).unwrap();
        let handle = sessions.register("a1");
        let mut cleanup = SessionCleanup::new(
            storage.clone(),
            sessions.clone(),
            "a1".to_string(),
            handle.conn_id,
        );

        cleanup.finish();
        assert_eq!(agent_status(&storage, "a1"), "offline");
        assert!(!sessions.has_active("a1"));
        assert!(sessions.active_agents().is_empty());

        // finished 已置位：之后新连接握手写 online，再次 finish 不得覆盖。
        let _new = sessions.register("a1");
        storage.upsert_agent(&test_agent("a1")).unwrap();
        cleanup.finish();
        assert_eq!(
            agent_status(&storage, "a1"),
            "online",
            "finished 后不得再次写 offline"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// b. 新连接先完成注册并写 online，旧连接清理必须看到「仍有连接」：
    /// 返回 false、不执行回调、DB 保持 online。
    #[test]
    fn session_cleanup_keeps_online_when_new_connection_exists() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-reconnect");
        storage.upsert_agent(&test_agent("a1")).unwrap();
        let old = sessions.register("a1");
        let new = sessions.register("a1");
        // 真实 handle_session 顺序：新连接 register 之后 upsert_agent(online)。
        storage.upsert_agent(&test_agent("a1")).unwrap();

        let mut cleanup = SessionCleanup::new(
            storage.clone(),
            sessions.clone(),
            "a1".to_string(),
            old.conn_id,
        );
        cleanup.finish();

        assert_eq!(
            agent_status(&storage, "a1"),
            "online",
            "旧连接不得把新连接覆盖成 offline"
        );
        assert!(sessions.has_active("a1"));
        assert_ne!(new.conn_id, old.conn_id);
        assert!(
            !sessions.unregister("a1", old.conn_id),
            "旧连接已不在注册表"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// e. revoked 最高优先级：清理前已吊销，回调命中吊销写 revoked。
    #[test]
    fn session_cleanup_restores_revoked_status() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-revoked");
        storage.upsert_agent(&test_agent("a1")).unwrap();
        let handle = sessions.register("a1");
        storage.revoke_agent("a1", now_ms()).unwrap();
        assert_eq!(agent_status(&storage, "a1"), "revoked");

        let mut cleanup = SessionCleanup::new(
            storage.clone(),
            sessions.clone(),
            "a1".to_string(),
            handle.conn_id,
        );
        cleanup.finish();
        assert_eq!(agent_status(&storage, "a1"), "revoked");
        assert!(!sessions.has_active("a1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// e. 任意交错：吊销后并发「旧连接清理 + 新连接注册」，最终状态始终 revoked。
    #[test]
    fn revoked_status_survives_concurrent_register_and_cleanup() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-revoked-race");
        for round in 0..20 {
            let agent_id = format!("revoked-{round}");
            storage.upsert_agent(&test_agent(&agent_id)).unwrap();
            let handle = sessions.register(&agent_id);
            storage.revoke_agent(&agent_id, now_ms()).unwrap();

            let (done_tx, done_rx) = mpsc::channel::<()>();

            let cleanup_storage = storage.clone();
            let cleanup_sessions = sessions.clone();
            let cleanup_agent = agent_id.clone();
            let cleanup_conn = handle.conn_id;
            let cleanup_done = done_tx.clone();
            let cleanup = std::thread::spawn(move || {
                let mut cleanup = SessionCleanup::new(
                    cleanup_storage,
                    cleanup_sessions,
                    cleanup_agent,
                    cleanup_conn,
                );
                cleanup.finish();
                cleanup_done.send(()).expect("测试线程必须存活");
            });

            let register_storage = storage.clone();
            let register_sessions = sessions.clone();
            let register_agent = agent_id.clone();
            let register_done = done_tx.clone();
            let register = std::thread::spawn(move || {
                let _handle = register_sessions.register(&register_agent);
                // 模拟新会话握手：upsert 不得把 revoked 改回 online。
                register_storage
                    .upsert_agent(&test_agent(&register_agent))
                    .unwrap();
                register_done.send(()).expect("测试线程必须存活");
            });

            for _ in 0..2 {
                done_rx
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap_or_else(|_| {
                        panic!("第 {round} 轮吊销/清理/注册并发操作超时（疑似死锁）")
                    });
            }
            cleanup.join().expect("cleanup 线程不得 panic");
            register.join().expect("register 线程不得 panic");
            assert_eq!(
                agent_status(&storage, &agent_id),
                "revoked",
                "第 {round} 轮最终状态必须是 revoked"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// a. 确定性交错：旧清理回调停在 slot 锁内（模拟慢 DB），新 register 必须阻塞；
    /// 释放后旧 offline 先落库、新 online 后写，最终 DB 状态是 online。
    #[test]
    fn new_register_waits_for_old_cleanup_callback() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-barrier");
        storage.upsert_agent(&test_agent("a1")).unwrap();
        let old = sessions.register("a1");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let cleanup_storage = storage.clone();
        let cleanup_sessions = sessions.clone();
        let old_id = old.conn_id;
        let cleanup = std::thread::spawn(move || {
            cleanup_sessions.unregister_last_and_run("a1", old_id, || {
                // 与生产回调一致：先查吊销，再写单行状态。DB 写推迟到释放点之后，
                // 以便把「清理临界区」拉长成可观察窗口（不用 sleep 等待）。
                let revoked = cleanup_storage.is_revoked("a1").expect("查询吊销失败");
                entered_tx.send(()).expect("测试线程必须存活");
                release_rx.recv().expect("等待测试线程释放临界区");
                let status = if revoked { "revoked" } else { "offline" };
                cleanup_storage
                    .set_status("a1", status, now_ms())
                    .expect("写状态失败");
            })
        });

        entered_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("旧连接清理必须进入回调（slot 锁已持有）");

        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let register_storage = storage.clone();
        let register_sessions = sessions.clone();
        let register = std::thread::spawn(move || {
            started_tx.send(()).expect("测试线程必须存活");
            let _handle = register_sessions.register("a1");
            // 真实 handle_session 顺序：register 返回后写 online。
            register_storage
                .upsert_agent(&test_agent("a1"))
                .expect("写 online 失败");
            done_tx.send(()).expect("测试线程必须存活");
        });

        started_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("注册线程必须启动");
        assert!(
            done_rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "旧清理回调持有 slot 锁期间，新 register 不得完成写库"
        );

        release_tx.send(()).expect("cleanup 线程必须存活");
        assert!(
            cleanup.join().expect("cleanup 线程不得 panic"),
            "旧连接是最后一条，回调必须执行"
        );
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("释放临界区后注册必须完成");
        register.join().expect("register 线程不得 panic");

        assert!(sessions.has_active("a1"));
        assert_eq!(
            agent_status(&storage, "a1"),
            "online",
            "旧 offline 必须落在新 online 之前"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// d. 100 轮 register / 旧 conn_id unregister / shutdown 并发交错：
    /// 每个线程用 `recv_timeout` 做死锁检测；最终活跃集合与 DB 状态一致。
    #[test]
    fn concurrent_session_churn_has_no_deadlock() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-churn");
        storage.upsert_agent(&test_agent("hot")).unwrap();
        let mut current = sessions.register("hot");

        for round in 0..100 {
            let (done_tx, done_rx) = mpsc::channel::<()>();

            let register_sessions = sessions.clone();
            let register_storage = storage.clone();
            let register_done = done_tx.clone();
            let register = std::thread::spawn(move || {
                let handle = register_sessions.register("hot");
                // 新会话握手：register 之后写 online。
                register_storage
                    .upsert_agent(&test_agent("hot"))
                    .expect("写 online 失败");
                register_done.send(()).expect("测试线程必须存活");
                handle
            });

            let cleanup_sessions = sessions.clone();
            let cleanup_storage = storage.clone();
            let cleanup_done = done_tx.clone();
            let old_id = current.conn_id;
            let cleanup = std::thread::spawn(move || {
                cleanup_sessions.unregister_last_and_run("hot", old_id, || {
                    let status = if cleanup_storage.is_revoked("hot").expect("查询吊销失败") {
                        "revoked"
                    } else {
                        "offline"
                    };
                    cleanup_storage
                        .set_status("hot", status, now_ms())
                        .expect("写状态失败");
                });
                cleanup_done.send(()).expect("测试线程必须存活");
            });

            let shutdown_sessions = sessions.clone();
            let shutdown_done = done_tx.clone();
            let shutdown = std::thread::spawn(move || {
                shutdown_sessions.shutdown("hot");
                shutdown_done.send(()).expect("测试线程必须存活");
            });

            for _ in 0..3 {
                done_rx
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap_or_else(|_| {
                        panic!("第 {round} 轮 register/unregister/shutdown 超时（疑似死锁）")
                    });
            }
            current = register.join().expect("register 线程不得 panic");
            cleanup.join().expect("cleanup 线程不得 panic");
            shutdown.join().expect("shutdown 线程不得 panic");
            assert!(
                sessions.has_active("hot"),
                "第 {round} 轮 register 已插入新连接，agent 必须在线"
            );
        }

        // 100 轮结束后仍有一条连接：活跃集合与 DB 必须都表现为在线。
        assert!(sessions.has_active("hot"));
        assert_eq!(sessions.active_agents(), vec!["hot".to_string()]);
        assert_eq!(agent_status(&storage, "hot"), "online");

        // 最终断开：最后一条连接注销后由回调写 offline，活跃集合与 DB 一致。
        let last_conn = current.conn_id;
        let mut cleanup = SessionCleanup::new(
            storage.clone(),
            sessions.clone(),
            "hot".to_string(),
            last_conn,
        );
        cleanup.finish();

        assert!(!sessions.has_active("hot"));
        assert!(sessions.active_agents().is_empty());
        assert_eq!(agent_status(&storage, "hot"), "offline");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------------
    // KI-17：管理 API 慢速连接防护（A1）
    // ------------------------------------------------------------------

    /// 测试路由：验证手工 accept 循环给请求注入了 `ConnectInfo<SocketAddr>`。
    async fn test_peer_ip(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
        peer.ip().to_string()
    }

    /// 测试路由：完整读取请求体（验证 body 总超时只作用于真正读 body 的请求）。
    async fn test_consume_body(_body: axum::body::Bytes) -> &'static str {
        "ok"
    }

    /// 启动一个只提供 `/healthz`、`/peer`、`/consume` 的最小管理口，返回地址与 server 任务。
    async fn spawn_test_admin_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定测试端口");
        let addr = listener.local_addr().expect("读取测试端口");
        let app = Router::new()
            .route("/healthz", get(healthz))
            .route("/peer", get(test_peer_ip))
            .route("/consume", axum::routing::post(test_consume_body));
        let server = tokio::spawn(async move {
            let _ = serve_admin_listener(app, listener, None).await;
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
    async fn admin_slow_header_connections_are_closed_and_healthz_available() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // 本测试依赖 30 < 每 IP / 全局上限，锁定常量防止以后调小后测试失去意义。
        assert_eq!(ADMIN_MAX_CONNECTIONS, 256);
        assert_eq!(ADMIN_MAX_CONNECTIONS_PER_IP, 32);

        let (addr, server) = spawn_test_admin_server().await;
        let response = test_http_get(addr, "/healthz")
            .await
            .expect("启动后的健康检查失败");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "启动后 /healthz 必须 200: {response}"
        );

        // 手工 accept 循环必须继续注入 ConnectInfo（管理限速依赖它）。
        let peer = test_http_get(addr, "/peer")
            .await
            .expect("ConnectInfo 测试请求失败");
        assert!(
            peer.contains("127.0.0.1"),
            "手工 accept 必须注入 ConnectInfo<SocketAddr>: {peer}"
        );

        // 30 条连接都只发半截 header，不再发送结束的 `\r\n\r\n`。
        let partial = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Slow: ";
        let mut slow = Vec::new();
        for _ in 0..30 {
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("连接管理口");
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

        // header 读超时是 5s；从建立连接到全部被关闭必须落在 10s 内。
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

    /// KI-17：同一来源 IP 达到并发上限后，下一条连接必须被立即关闭。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_per_ip_connection_limit_closes_extra_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (addr, server) = spawn_test_admin_server().await;
        let partial = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Slow: ";

        // 占满该 IP 的额度：全部只发半截 header，保持连接不结束。
        let mut held = Vec::new();
        for _ in 0..ADMIN_MAX_CONNECTIONS_PER_IP {
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("连接管理口");
            stream.write_all(partial).await.expect("写半截 header");
            held.push(stream);
        }
        // 等 accept 循环处理完这 32 条（TCP accept 队列 FIFO，之后的新连接必然排在其后）。
        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut extra = tokio::net::TcpStream::connect(addr)
            .await
            .expect("内核仍应接受 TCP 握手");
        // 服务端拒绝时会直接关 TCP，写入可能立刻收到 RST；这本身就是证据。
        let _ = extra.write_all(partial).await;

        let closed = tokio::time::timeout(Duration::from_secs(2), async {
            let mut buf = [0u8; 128];
            loop {
                match extra.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "同 IP 第 {} 条连接必须立即被关闭",
            ADMIN_MAX_CONNECTIONS_PER_IP + 1
        );

        drop(held);
        server.abort();
    }

    /// KI-17 剩余缺口：header 完整、`Content-Length` 很大但永不发送 body 的连接，
    /// 必须在请求体总超时后关闭（或收到非 2xx），且不能影响 `/healthz`。
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn admin_body_read_timeout_closes_connection_without_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        assert_eq!(BODY_READ_TIMEOUT, Duration::from_secs(10));

        let (addr, server) = spawn_test_admin_server().await;
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
            .expect("连接管理口");
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
            "hub 请求体超时：{elapsed:?} 后关闭，收到 {} 字节响应",
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

    // ------------------------------------------------------------------
    // v0.3.3 A1：scoped token 鉴权 / 授权 / CLI / 审计 actor
    // ------------------------------------------------------------------

    const V6_LEGACY_TOKEN: &str = "v6-legacy-admin-token-0123456789";

    /// v6 鉴权测试状态：保留旧 admin_token，关闭限速（矩阵测试请求数会超过 60/min）。
    fn v6_auth_state() -> AppState {
        hub_state_with(HubConfig {
            admin_token: V6_LEGACY_TOKEN.to_string(),
            admin_rate_limit_per_min: 0,
            admin_write_rate_limit_per_min: 0,
            ..HubConfig::default()
        })
    }

    /// 直接在库里种一个 token，返回明文（只在本进程测试内使用）。
    fn v6_seed_token(state: &AppState, name: &str, scope: &str) -> String {
        let token = new_secret();
        state
            .storage
            .create_api_token(name, &tls::sha256_hex(&token), scope, now_ms())
            .unwrap();
        token
    }

    fn v6_token_cli_config(tag: &str) -> (PathBuf, PathBuf) {
        let dir = temp_dir(tag);
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("hub.toml");
        let db_path = dir.join("rustboard.db");
        HubConfig {
            database: format!("sqlite://{}", db_path.display()),
            ..HubConfig::default()
        }
        .save(&config_path)
        .unwrap();
        (config_path, db_path)
    }

    /// scope 矩阵：read/write/admin × GET/POST/PUT；旧 admin_token 仍全通过。
    /// 403 固定结构、发生在限速后 / handler 前，不写审计；未知路由认证后 404/405。
    #[tokio::test]
    async fn v6_token_scope_matrix_and_unknown_routes() {
        let state = v6_auth_state();
        let read = v6_seed_token(&state, "read-token", "read");
        let write = v6_seed_token(&state, "write-token", "write");
        let admin = v6_seed_token(&state, "admin-http-token", "admin");
        let router = admin_router(state.clone());

        // 三种 scope 都允许只读 GET（write/admin 隐含 read），旧 admin_token 也兼容。
        for token in [
            read.as_str(),
            write.as_str(),
            admin.as_str(),
            V6_LEGACY_TOKEN,
        ] {
            let (status, _, _) =
                admin_call(&router, "GET", "/api/v1/agents", Some(token), None).await;
            assert_eq!(status, StatusCode::OK, "token={token}");
        }
        // 已知只读子路由（agent 不存在时 handler 给 404，但 scope 必须先放行）。
        for token in [read.as_str(), write.as_str(), admin.as_str()] {
            let (status, _, _) = admin_call(
                &router,
                "GET",
                "/api/v1/agents/a1/settings",
                Some(token),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "token={token}");
        }

        // read token 调写接口：403 forbidden_scope，固定结构，且不写控制审计。
        for (method, uri) in [
            ("POST", "/api/v1/agents/a1/control"),
            ("PUT", "/api/v1/agents/a1/settings"),
        ] {
            let (status, _, bytes) =
                admin_call(&router, method, uri, Some(&read), Some("{}")).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {uri}");
            assert_eq!(
                json_body(&bytes),
                serde_json::json!({ "error": "forbidden_scope" })
            );
        }
        assert!(
            state
                .storage
                .list_audit(10, None, None, None)
                .unwrap()
                .is_empty(),
            "scope 不足的 403 不能进入控制 handler，也不得写审计"
        );

        // write / admin 通过 scope 检查：坏请求体由 handler 给 400（证明已进入 handler）。
        for token in [write.as_str(), admin.as_str()] {
            let (status, _, bytes) = admin_call(
                &router,
                "POST",
                "/api/v1/agents/a1/control",
                Some(token),
                Some("{}"),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "token={token}");
            assert_eq!(json_body(&bytes)["error"]["code"], "invalid_request");
        }
        let entries = state.storage.list_audit(10, None, None, None).unwrap();
        assert_eq!(entries.len(), 2, "进入 handler 的拒绝必须写审计");
        let mut actors: Vec<&str> = entries.iter().map(|entry| entry.actor.as_str()).collect();
        actors.sort_unstable();
        assert_eq!(actors, vec!["admin-http-token", "write-token"]);

        // write / admin token 通过 scope 后由 handler 校验请求体（400 而非 403）。
        for token in [write.as_str(), admin.as_str()] {
            let (status, _, _) = admin_call(
                &router,
                "PUT",
                "/api/v1/agents/a1/settings",
                Some(token),
                Some("{}"),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "token={token}");
        }

        // 未知路径：先认证再 404；未知 POST/PUT 不能被 read token 变成 403。
        for method in ["GET", "POST", "PUT", "DELETE"] {
            let (status, _, _) =
                admin_call(&router, method, "/api/v1/does-not-exist", Some(&read), None).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "method={method}");
            let (status, _, _) =
                admin_call(&router, method, "/api/v1/does-not-exist", None, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "method={method}");
        }
        // 已知路径的错误方法：认证后由路由给 405，不是 403。
        let (status, _, _) = admin_call(&router, "POST", "/api/v1/agents", Some(&read), None).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    /// 401 结构、last_used_at 更新、rotate/revoke 立即生效（每次请求查库）。
    #[tokio::test]
    async fn v6_token_auth_401_shape_last_used_rotate_revoke() {
        let state = v6_auth_state();
        let token = v6_seed_token(&state, "panel", "read");
        let router = admin_router(state.clone());

        // 缺失 / 错误 / 空 token：固定 401 + WWW-Authenticate，不回显任何 token。
        for provided in [None, Some("wrong-token"), Some("")] {
            let (status, headers, bytes) =
                admin_call(&router, "GET", "/api/v1/agents", provided, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "provided={provided:?}");
            assert_eq!(
                headers.get(header::WWW_AUTHENTICATE).unwrap(),
                "Bearer",
                "provided={provided:?}"
            );
            assert_eq!(
                json_body(&bytes),
                serde_json::json!({ "error": "unauthorized" })
            );
            assert!(!String::from_utf8_lossy(&bytes).contains("wrong-token"));
        }
        assert!(
            state
                .storage
                .list_audit(10, None, None, None)
                .unwrap()
                .is_empty(),
            "认证失败不得写审计"
        );
        assert_eq!(
            state.storage.list_api_tokens().unwrap()[0].last_used_at,
            None
        );

        // 认证成功：last_used_at 必须落库。
        let (status, _, _) = admin_call(&router, "GET", "/api/v1/agents", Some(&token), None).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            state.storage.list_api_tokens().unwrap()[0]
                .last_used_at
                .is_some(),
            "鉴权成功必须更新 last_used_at"
        );

        // rotate：旧 token 立即 401，新 token 立即 200。
        let rotated = new_secret();
        state
            .storage
            .rotate_api_token("panel", &tls::sha256_hex(&rotated), now_ms())
            .unwrap();
        let (status, _, _) = admin_call(&router, "GET", "/api/v1/agents", Some(&token), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "旧 token 必须立即失效");
        let (status, _, _) =
            admin_call(&router, "GET", "/api/v1/agents", Some(&rotated), None).await;
        assert_eq!(status, StatusCode::OK);

        // revoke：立即 401，行保留（不删行）。
        state.storage.revoke_api_token("panel", now_ms()).unwrap();
        let (status, _, _) =
            admin_call(&router, "GET", "/api/v1/agents", Some(&rotated), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let records = state.storage.list_api_tokens().unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].revoked_at.is_some());
    }

    /// CLI 端到端：临时 DB、不启 hub；TSV 不含明文 / 哈希；rotate/revoke 生效。
    #[test]
    fn v6_token_cli_create_list_rotate_revoke_end_to_end() {
        let (config_path, db_path) = v6_token_cli_config("token-cli");

        // 非法名称 / scope 在落库前拒绝。
        assert!(token_create(Some(config_path.clone()), "bad name".into(), "read".into()).is_err());
        assert!(token_create(Some(config_path.clone()), "panel".into(), "root".into()).is_err());

        // 保留名 admin（大小写不敏感）：create / rotate 都必须拒绝，
        // 否则审计 actor 与旧 admin_token 完全不可区分。
        for reserved in ["admin", "Admin", "ADMIN"] {
            let err = token_create(Some(config_path.clone()), reserved.into(), "read".into())
                .unwrap_err();
            assert!(
                format!("{err:#}").contains("保留名"),
                "create {reserved} 错误信息: {err:#}"
            );
            let err = token_rotate(Some(config_path.clone()), reserved.into()).unwrap_err();
            assert!(
                format!("{err:#}").contains("保留名"),
                "rotate {reserved} 错误信息: {err:#}"
            );
        }

        // 名称边界：1 / 64 合法；空、65、非 ASCII、tab / 换行拒绝。
        assert!(validate_token_name("a").is_ok());
        assert!(validate_token_name(&"a".repeat(64)).is_ok());
        assert!(validate_token_name("").is_err());
        assert!(validate_token_name(&"a".repeat(65)).is_err());
        assert!(validate_token_name("名字").is_err());
        assert!(validate_token_name("a\tb").is_err());
        assert!(validate_token_name("a\nb").is_err());
        assert!(validate_token_name("admin").is_err());
        assert!(validate_token_name("ADMIN").is_err());
        assert!(validate_token_name("Admin").is_err());

        let token = token_create(Some(config_path.clone()), "panel".into(), "read".into()).unwrap();
        assert_eq!(token.len(), 64, "明文必须是 64 位 hex");
        assert!(token.bytes().all(|byte| byte.is_ascii_hexdigit()));

        let db = SqliteStorage::open(&db_path).unwrap();
        let records = db.list_api_tokens().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].name, "panel");
        assert_eq!(records[0].scope, "read");
        assert_eq!(records[0].revoked_at, None);

        // 重复 name：明确失败。
        let err =
            token_create(Some(config_path.clone()), "panel".into(), "write".into()).unwrap_err();
        assert!(format!("{err:#}").contains("已存在"), "err={err:#}");

        let second =
            token_create(Some(config_path.clone()), "beta".into(), "admin".into()).unwrap();

        // list：固定表头、按 name 升序、5 列 TSV、空值 -，绝不含明文 / 哈希。
        let list = token_list(Some(config_path.clone())).unwrap();
        let mut lines = list.lines();
        assert_eq!(
            lines.next(),
            Some("name\tscope\tcreated_at\tlast_used_at\trevoked_at")
        );
        let rows: Vec<&str> = lines.collect();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].starts_with("beta\tadmin\t"), "rows={rows:?}");
        assert!(rows[1].starts_with("panel\tread\t"), "rows={rows:?}");
        assert!(
            rows[1].ends_with("\t-\t-"),
            "panel 从未使用且未吊销，时间列必须是 -: {rows:?}"
        );
        for row in &rows {
            assert_eq!(row.split('\t').count(), 5, "row={row}");
        }
        assert!(!list.contains(&token));
        assert!(!list.contains(&second));
        assert!(!list.contains(&tls::sha256_hex(&token)));
        assert!(!list.contains(&tls::sha256_hex(&second)));
        assert!(db
            .authenticate_api_token(&tls::sha256_hex(&token), now_ms())
            .unwrap()
            .is_some());

        // rotate：旧 token 立即失效，新 token 可用。
        let rotated = token_rotate(Some(config_path.clone()), "panel".into()).unwrap();
        assert_ne!(rotated, token);
        assert!(db
            .authenticate_api_token(&tls::sha256_hex(&token), now_ms())
            .unwrap()
            .is_none());
        assert!(db
            .authenticate_api_token(&tls::sha256_hex(&rotated), now_ms())
            .unwrap()
            .is_some());

        // revoke：不删行；重复吊销 / 不存在都报明确错误。
        let message = token_revoke(Some(config_path.clone()), "panel".into()).unwrap();
        assert!(message.contains("panel"));
        assert!(db
            .authenticate_api_token(&tls::sha256_hex(&rotated), now_ms())
            .unwrap()
            .is_none());
        let err = token_revoke(Some(config_path.clone()), "panel".into()).unwrap_err();
        assert!(format!("{err:#}").contains("已吊销"), "err={err:#}");
        let err = token_revoke(Some(config_path.clone()), "missing".into()).unwrap_err();
        assert!(format!("{err:#}").contains("不存在"), "err={err:#}");

        let final_list = token_list(Some(config_path)).unwrap();
        let panel = final_list
            .lines()
            .find(|line| line.starts_with("panel\t"))
            .expect("panel 行必须保留");
        assert!(
            !panel.ends_with("\t-\t-"),
            "吊销后 revoked_at 不能是 -: {panel}"
        );

        drop(db);
        let _ = std::fs::remove_dir_all(db_path.parent().unwrap());
    }

    /// CLI 参数接线：新 `token` 子命令完整可用，旧 `admin-token` 保留。
    #[test]
    fn v6_token_cli_parses_subcommands() {
        let cli = Cli::try_parse_from([
            "rustboard-hub",
            "token",
            "create",
            "--config",
            "hub.toml",
            "--name",
            "panel-prod",
            "--scope",
            "write",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Token {
                action:
                    TokenAction::Create {
                        config,
                        name,
                        scope,
                    },
            } => {
                assert_eq!(config.as_deref(), Some(std::path::Path::new("hub.toml")));
                assert_eq!(name, "panel-prod");
                assert_eq!(scope, "write");
            }
            _ => panic!("应解析为 token create"),
        }
        assert!(Cli::try_parse_from([
            "rustboard-hub",
            "token",
            "create",
            "--name",
            "panel",
            "--scope",
            "root",
        ])
        .is_err());
        assert!(matches!(
            Cli::try_parse_from(["rustboard-hub", "admin-token"])
                .unwrap()
                .cmd,
            Cmd::AdminToken { .. }
        ));
    }

    /// 控制路由缺少鉴权扩展时固定 500（接线错误），不得 panic。
    #[tokio::test]
    async fn v6_control_action_without_principal_returns_500() {
        let state = m3_state(m3_control_cfg());
        let router = Router::new()
            .route(
                "/api/v1/agents/{id}/control",
                axum::routing::post(control::control_action),
            )
            .with_state(state);

        let (status, _, bytes) = admin_call(
            &router,
            "POST",
            "/api/v1/agents/a1/control",
            None,
            Some("{}"),
        )
        .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let body = json_body(&bytes);
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "internal_error");
    }

    /// 审计 actor：旧 admin_token 写 "admin"（既有 e2e 6.10 兼容），scoped token 写 name。
    #[tokio::test]
    async fn v6_control_audit_actor_uses_token_name() {
        let state = m3_state(m3_control_cfg());
        let handle = m3_register_agent(&state, "a1", &["systemd"]);
        let responder = m3_spawn_responder(
            handle.control_rx,
            vec![
                Ok(ControlResult::ActionOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: Some(0),
                }),
                Ok(ControlResult::ActionOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: Some(0),
                }),
            ],
        );
        let router = admin_router(state.clone());
        let token = v6_seed_token(&state, "panel-prod", "write");
        let body = r#"{"capability":"systemd","action":"restart","target":"nginx.service","confirm":true}"#;

        // 旧 admin_token。
        let (status, _, _) = admin_call(
            &router,
            "POST",
            "/api/v1/agents/a1/control",
            Some(M3_TOKEN),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        // scoped token。
        let (status, _, _) = admin_call(
            &router,
            "POST",
            "/api/v1/agents/a1/control",
            Some(&token),
            Some(body),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(responder.await.unwrap(), 2);

        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 2);
        // id 倒序：最新一条是 scoped token。
        assert_eq!(entries[0].actor, "panel-prod");
        assert_eq!(entries[1].actor, "admin");
        assert!(
            !entries[0].actor.contains(&token),
            "审计 actor 不能包含 token 明文"
        );
    }

    // ------------------------------------------------------------------
    // v0.3.3 B：#17 吊销窗口内拒绝控制命令
    // ------------------------------------------------------------------

    /// 已吊销 agent：POST control 固定 403 `agent_revoked`，审计 denied，
    /// 且会话队列里绝不能出现 ControlCommand。
    #[tokio::test]
    async fn v033_revoked_agent_control_returns_403_without_dispatch() {
        let state = m3_state(m3_control_cfg());
        let mut handle = m3_register_agent(&state, "a1", &["systemd"]);
        let router = admin_router(state.clone());
        state.storage.revoke_agent("a1", now_ms()).unwrap();

        let (status, body) =
            m3_post(&router, "a1", r#"{"capability":"systemd","action":"list"}"#).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "agent_revoked");
        assert_eq!(body["error"]["message"], "agent 已被吊销");

        // API 必须在投递前拒绝：会话队列保持为空。
        assert!(
            handle.control_rx.try_recv().is_err(),
            "吊销后不得向会话投递 ControlCommand"
        );

        // 审计最后一条必须是 denied + agent_revoked，不能出现 ok。
        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 1, "拒绝路径也必须写一条审计");
        assert_eq!(entries[0].result, "denied");
        assert_eq!(entries[0].error_code, "agent_revoked");
        assert!(
            entries.iter().all(|entry| entry.result != "ok"),
            "吊销后不得出现成功审计"
        );
    }

    /// 确定性并发：命令先入队，随后 revoke，再运行会话 gate。
    /// gate 必须回 agent_revoked，且会话只回错误、不 dispatch。
    #[tokio::test]
    async fn v033_control_revocation_gate_blocks_queued_command_after_revoke() {
        let state = m3_state(m3_control_cfg());
        let mut handle = m3_register_agent(&state, "a1", &["systemd"]);

        // revoke 前 gate 放行（未吊销 agent 仍正常投递，既有测试继续覆盖完整成功路径）。
        control_revocation_gate(&state, "a1")
            .await
            .expect("未吊销 agent 的 gate 必须放行");

        // 命令先进入会话队列：模拟管理 API 已完成两次检查并成功 try_send。
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        state
            .sessions
            .control_sender("a1")
            .expect("会话必须在线")
            .try_send(ControlCommand {
                op: rustboard_common::control::ControlOp::SystemdList,
                reply: reply_tx,
            })
            .expect("队列应能接收命令");

        // revoke 在入队之后、会话 dispatch 之前生效。
        state.storage.revoke_agent("a1", now_ms()).unwrap();

        let gate_error = control_revocation_gate(&state, "a1")
            .await
            .expect_err("吊销后 gate 必须拒绝");
        assert_eq!(gate_error.code, control::hub_codes::AGENT_REVOKED);
        assert_eq!(gate_error.message, "agent 已被吊销");

        // 与生产 session loop 相同：命令出队后只回错误，绝不调用 dispatch。
        let command = handle.control_rx.try_recv().expect("命令必须已进入队列");
        command.reply.send(Err(gate_error)).expect("等待者应仍在");

        match reply_rx.await.expect("应收到拒绝回复") {
            Ok(_) => panic!("吊销后的命令绝不能返回成功"),
            Err(error) => {
                assert_eq!(error.code, control::hub_codes::AGENT_REVOKED);
                assert_eq!(error.message, "agent 已被吊销");
            }
        }
    }

    /// #17 复审回归：命令在等待回复期间会话关闭（oneshot 被丢弃）且 agent 已吊销，
    /// 必须回 403 `agent_revoked` + 审计 denied，而不是 503 `agent_offline` + error。
    #[tokio::test]
    async fn v033_dropped_reply_after_revoke_returns_agent_revoked() {
        let state = m3_state(m3_control_cfg());
        let mut handle = m3_register_agent(&state, "a1", &["systemd"]);
        let router = admin_router(state.clone());

        // 在独立任务里发起控制请求：它会通过能力/吊销检查并把命令投进会话队列，
        // 然后卡在 reply_rx 等待上。
        let post = tokio::spawn(async move {
            m3_post(&router, "a1", r#"{"capability":"systemd","action":"list"}"#).await
        });

        let command = tokio::time::timeout(Duration::from_secs(2), handle.control_rx.recv())
            .await
            .expect("控制命令必须及时入队")
            .expect("会话控制通道必须打开");

        // 先吊销，再丢弃命令且不回复：reply oneshot 被丢弃，进入 handler 的
        // `Ok(Err(_))` 分支；该分支必须重新查询吊销状态。
        state.storage.revoke_agent("a1", now_ms()).unwrap();
        drop(command);

        let (status, body) = tokio::time::timeout(Duration::from_secs(2), post)
            .await
            .expect("POST 必须及时返回")
            .expect("POST 任务不得 panic");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "agent_revoked");
        assert_eq!(body["error"]["message"], "agent 已被吊销");

        let entries = m3_audit(&state);
        assert_eq!(entries.len(), 1, "拒绝路径必须写一条审计");
        assert_eq!(entries[0].result, "denied");
        assert_eq!(entries[0].error_code, "agent_revoked");
    }

    // ------------------------------------------------------------------
    // v0.3.3 A2：管理端 TLS
    // ------------------------------------------------------------------

    /// 管理端 TLS 测试材料：同一套 server.crt/key + 指定 SAN。
    fn admin_tls_test_config(tag: &str, listen: &str, sans: &[&str]) -> HubConfig {
        let dir = temp_dir(tag);
        let server_names: Vec<String> = sans.iter().map(|san| (*san).to_string()).collect();
        tls::ensure_hub_material(&dir, &server_names, tls::CertPolicy::default()).unwrap();
        HubConfig {
            data_dir: dir,
            admin_listen: listen.to_string(),
            admin_tls: AdminTlsMode::Required,
            server_names,
            ..HubConfig::default()
        }
    }

    /// 用测试证书目录里的 CA 构建 server-auth 客户端（不携带客户端证书）。
    fn admin_tls_client_config(data_dir: &std::path::Path) -> Arc<rustls::ClientConfig> {
        let ca_pem = std::fs::read_to_string(tls::cert_dir(data_dir).join(tls::CA_CERT_FILE))
            .expect("读取测试 CA");
        let mut roots = rustls::RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates(tls::load_certs(&ca_pem).unwrap());
        assert!(added > 0, "测试 CA 必须能载入信任库");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    fn der_fingerprint(der: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(der))
    }

    /// 起一个只含 `/healthz` 的 HTTPS 管理监听，返回连接信息与热加载句柄。
    async fn spawn_test_admin_tls_server(
        sans: &[&str],
    ) -> (
        SocketAddr,
        Arc<RwLock<CertStatus>>,
        watch::Sender<Arc<rustls::ServerConfig>>,
        HubConfig,
        tokio::task::JoinHandle<()>,
    ) {
        let cfg = admin_tls_test_config("admin-tls", "127.0.0.1:0", sans);
        let config = tls::admin_server_config(&cfg.data_dir, &cfg.server_names).unwrap();
        let (tx, rx) = watch::channel(config);
        let live = Arc::new(RwLock::new(
            cert_rotation::read_disk_cert_status(&cfg).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("绑定测试端口");
        let addr = listener.local_addr().expect("读取测试端口");
        let app = Router::new().route("/healthz", get(healthz));
        let server = tokio::spawn(async move {
            let _ = serve_admin_listener(app, listener, Some(rx)).await;
        });
        (addr, live, tx, cfg, server)
    }

    /// 发起一次 HTTPS GET，返回响应文本与该连接实际看到的服务端证书。
    async fn test_https_get(
        addr: SocketAddr,
        config: Arc<rustls::ClientConfig>,
        path: &str,
    ) -> std::io::Result<(String, Vec<Vec<u8>>)> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let server_name =
            rustls::pki_types::ServerName::try_from("127.0.0.1").expect("测试 server name 合法");
        let connector = tokio_rustls::TlsConnector::from(config);
        let mut stream = connector.connect(server_name, tcp).await?;
        stream
            .write_all(
                format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let peer_certs = stream
            .get_ref()
            .1
            .peer_certificates()
            .map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
            .unwrap_or_default();
        Ok((String::from_utf8_lossy(&response).into_owned(), peer_certs))
    }

    /// required：HTTPS `/healthz` 200；明文 TCP 发同一请求拿不到 HTTP 200。
    #[tokio::test]
    async fn v033_admin_tls_required_serves_https_only() {
        // 握手超时是安全边界，锁定 10s。
        assert_eq!(ADMIN_TLS_HANDSHAKE_TIMEOUT, Duration::from_secs(10));

        let (addr, _live, _tx, cfg, server) =
            spawn_test_admin_tls_server(&["localhost", "127.0.0.1"]).await;
        let client = admin_tls_client_config(&cfg.data_dir);
        let (response, certs) = test_https_get(addr, client, "/healthz")
            .await
            .expect("HTTPS 请求失败");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "HTTPS /healthz 必须 200: {response}"
        );
        assert!(!certs.is_empty(), "客户端必须收到服务端证书");
        assert_eq!(
            der_fingerprint(&certs[0]),
            cert_rotation::read_disk_cert_status(&cfg)
                .unwrap()
                .fingerprint,
            "HTTPS 必须使用 server.crt"
        );

        // 明文请求直接打进 TLS 端口：握手失败/连接关闭，绝不能拿到 HTTP 200。
        if let Ok(text) = test_http_get(addr, "/healthz").await {
            assert!(
                !text.starts_with("HTTP/1.1 200"),
                "明文请求不得拿到 HTTP 200: {text}"
            );
        }

        server.abort();
        let _ = std::fs::remove_dir_all(&cfg.data_dir);
    }

    /// 证书轮换：watcher 重建 server-auth 配置后，新连接使用新证书。
    #[tokio::test]
    async fn v033_admin_tls_hot_reload_uses_new_certificate() {
        let (addr, live, tx, cfg, server) =
            spawn_test_admin_tls_server(&["localhost", "127.0.0.1"]).await;
        let client = admin_tls_client_config(&cfg.data_dir);
        let old_fingerprint = cert_rotation::read_disk_cert_status(&cfg)
            .unwrap()
            .fingerprint;

        let (_, certs) = test_https_get(addr, client.clone(), "/healthz")
            .await
            .expect("轮换前 HTTPS 请求失败");
        assert_eq!(der_fingerprint(&certs[0]), old_fingerprint);

        // 同一 CA / 同一 SAN 重签：客户端信任链不变，只有指纹变化。
        let renewed = cert_rotation::renew_server_cert_files(&cfg, true, None)
            .unwrap()
            .expect("--force 必须重签");
        assert_ne!(renewed.fingerprint, old_fingerprint);
        let new_fingerprint = renewed.fingerprint;

        // 模拟 mTLS watcher 已成功切换 live；管理端 watcher 只跟随这个指纹。
        *live.write().unwrap() = cert_rotation::read_disk_cert_status(&cfg).unwrap();
        let (_, certs) = test_https_get(addr, client.clone(), "/healthz")
            .await
            .expect("推送前 HTTPS 请求失败");
        assert_eq!(
            der_fingerprint(&certs[0]),
            old_fingerprint,
            "watch 未推送前 accept 循环必须继续使用旧配置"
        );

        let pushed = reload_admin_tls_if_changed(&cfg, &tx, &live, &old_fingerprint).unwrap();
        assert_eq!(pushed.as_deref(), Some(new_fingerprint.as_str()));

        let (response, certs) = test_https_get(addr, client, "/healthz")
            .await
            .expect("热加载后 HTTPS 请求失败");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert_eq!(
            der_fingerprint(&certs[0]),
            new_fingerprint,
            "新连接必须使用轮换后的证书"
        );

        server.abort();
        let _ = std::fs::remove_dir_all(&cfg.data_dir);
    }

    /// init 持久化 `--admin-tls`；非回环 + off 仍成功落盘（run 时才拒绝）。
    #[test]
    fn v033_init_persists_admin_tls_mode() {
        let dir = temp_dir("init-admin-tls");
        let cfg_path = dir.join("hub.toml");
        let data_dir = dir.join("data");
        init(
            Some(cfg_path.clone()),
            Some(data_dir.clone()),
            Some("127.0.0.1:0".to_string()),
            Some("127.0.0.1:0".to_string()),
            Some("required".to_string()),
            vec!["127.0.0.1".to_string()],
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .expect("init --admin-tls required 必须成功");
        let cfg = HubConfig::load(&cfg_path).unwrap();
        assert_eq!(cfg.admin_tls, AdminTlsMode::Required);
        assert_eq!(cfg.admin_listen, "127.0.0.1:0");
        assert!(tls::cert_dir(&data_dir)
            .join(tls::SERVER_CERT_FILE)
            .exists());
        let _ = std::fs::remove_dir_all(&dir);

        // required + 非通配且缺管理端 SAN：init 必须在签发/落盘前失败。
        let dir = temp_dir("init-admin-tls-missing-san");
        let cfg_path = dir.join("hub.toml");
        let data_dir = dir.join("data");
        let err = init(
            Some(cfg_path.clone()),
            Some(data_dir.clone()),
            Some("127.0.0.1:0".to_string()),
            Some("127.0.0.2:0".to_string()),
            Some("required".to_string()),
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .expect_err("required 且缺管理端 SAN 必须拒绝");
        assert!(
            format!("{err:#}").contains("管理 API TLS"),
            "错误信息: {err:#}"
        );
        assert!(!cfg_path.exists(), "失败时不得写入配置文件");
        assert!(
            !tls::cert_dir(&data_dir).exists(),
            "失败时不得创建证书目录/CA"
        );
        let _ = std::fs::remove_dir_all(&dir);

        // required + 通配绑定：跳过精确 SAN 检查，init 成功。
        let dir = temp_dir("init-admin-tls-wildcard");
        let cfg_path = dir.join("hub.toml");
        init(
            Some(cfg_path.clone()),
            Some(dir.join("data")),
            Some("127.0.0.1:0".to_string()),
            Some("0.0.0.0:0".to_string()),
            Some("required".to_string()),
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .expect("通配绑定 + required 必须成功");
        assert_eq!(
            HubConfig::load(&cfg_path).unwrap().admin_tls,
            AdminTlsMode::Required
        );
        let _ = std::fs::remove_dir_all(&dir);

        // 非回环 + 默认 off：init 仍成功（随后 run 会拒绝），便于先落盘再改。
        let dir = temp_dir("init-admin-tls-off");
        let cfg_path = dir.join("hub.toml");
        init(
            Some(cfg_path.clone()),
            Some(dir.join("data")),
            Some("127.0.0.1:0".to_string()),
            Some("0.0.0.0:0".to_string()),
            None,
            Vec::new(),
            None,
            None,
            None,
            None,
            None,
            false,
        )
        .expect("非回环 off 的 init 必须成功且打印警告");
        let cfg = HubConfig::load(&cfg_path).unwrap();
        assert_eq!(cfg.admin_tls, AdminTlsMode::Off);
        assert!(
            validate_admin_tls(&cfg).is_err(),
            "该配置在 run 时必须被拒绝"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------------
    // v0.3.4 KI-26：未认证 401 的每来源 IP 失败限速
    // ------------------------------------------------------------------

    /// 认证失败限速测试状态：默认失败阈值 60；关闭已认证请求限速，
    /// 避免 61 次请求触发另一套（认证成功后）的 429 干扰断言。
    fn v034_auth_state(legacy_token: &str) -> AppState {
        hub_state_with(HubConfig {
            admin_token: legacy_token.to_string(),
            admin_rate_limit_per_min: 0,
            admin_write_rate_limit_per_min: 0,
            ..HubConfig::default()
        })
    }

    /// 错误 token 前 60 次 401（不写审计），第 61 次 429 + Retry-After；
    /// 旧 admin_token 在超限后仍是应急入口（200），命中后清空失败计数。
    #[tokio::test]
    async fn v034_auth_failure_limit_429_and_legacy_bypass() {
        let legacy = "v034-legacy-admin-token-0123456789";
        let state = v034_auth_state(legacy);
        let router = admin_router(state.clone());

        for attempt in 1..=60 {
            let (status, headers, body) =
                admin_call(&router, "GET", "/api/v1/agents", Some("wrong-token"), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "第 {attempt} 次必须 401");
            assert_eq!(headers.get(header::WWW_AUTHENTICATE).unwrap(), "Bearer");
            assert_eq!(
                json_body(&body),
                serde_json::json!({ "error": "unauthorized" })
            );
            assert!(
                !String::from_utf8_lossy(&body).contains("wrong-token"),
                "401 不得回显 token"
            );
        }
        assert!(
            state
                .storage
                .list_audit(10, None, None, None)
                .unwrap()
                .is_empty(),
            "401 不得写审计"
        );

        // 第 61 次：429 固定 body + Retry-After(1..=60)，不回显 token，不写审计。
        let (status, headers, body) =
            admin_call(&router, "GET", "/api/v1/agents", Some("wrong-token"), None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            json_body(&body),
            serde_json::json!({ "error": "rate_limited" })
        );
        assert!(!String::from_utf8_lossy(&body).contains("wrong-token"));
        assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        let retry: u64 = headers
            .get(header::RETRY_AFTER)
            .expect("429 必须带 Retry-After")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry), "Retry-After 非法: {retry}");
        assert!(
            state
                .storage
                .list_audit(10, None, None, None)
                .unwrap()
                .is_empty(),
            "429 不得写审计"
        );

        // 旧 admin_token：超限后仍必须 200，不受失败限速影响。
        let (status, _, _) = admin_call(&router, "GET", "/api/v1/agents", Some(legacy), None).await;
        assert_eq!(status, StatusCode::OK, "旧 admin_token 必须绕过失败限速");

        // 命中后清空该 IP 计数：再次错误 token 重新从 401 开始。
        let (status, _, _) =
            admin_call(&router, "GET", "/api/v1/agents", Some("wrong-token"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    /// 阈值前合法 scoped token 必须 200；超限后即使 token 合法也 429，
    /// 且不查库（`last_used_at` 保持为空可证明未执行 `authenticate_api_token`）。
    #[tokio::test]
    async fn v034_scoped_token_before_limit_ok_and_after_limit_no_db() {
        let state = hub_state_with(HubConfig {
            admin_token: "v034-legacy-admin-token-0123456789".to_string(),
            admin_auth_failure_limit_per_min: 3,
            admin_rate_limit_per_min: 0,
            admin_write_rate_limit_per_min: 0,
            ..HubConfig::default()
        });
        let within = v6_seed_token(&state, "within-limit", "read");
        let blocked = v6_seed_token(&state, "above-limit", "read");
        let router = admin_router(state.clone());

        // 2 次失败 < 3：合法 scoped token 必须 200，并清空失败计数。
        for _ in 0..2 {
            let (status, _, _) =
                admin_call(&router, "GET", "/api/v1/agents", Some("wrong"), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, _, _) =
            admin_call(&router, "GET", "/api/v1/agents", Some(&within), None).await;
        assert_eq!(status, StatusCode::OK, "阈值前合法 scoped token 必须放行");

        // 成功认证清零后重新累计 3 次失败，达到阈值。
        for _ in 0..3 {
            let (status, _, _) =
                admin_call(&router, "GET", "/api/v1/agents", Some("wrong"), None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }

        let blocked_last_used = || {
            state
                .storage
                .list_api_tokens()
                .unwrap()
                .into_iter()
                .find(|record| record.name == "above-limit")
                .expect("token 必须存在")
                .last_used_at
        };
        assert_eq!(blocked_last_used(), None, "从未成功认证过");

        // 超限后合法 scoped token：429 + Retry-After，且不查库、不回显 token。
        let (status, headers, body) =
            admin_call(&router, "GET", "/api/v1/agents", Some(&blocked), None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            json_body(&body),
            serde_json::json!({ "error": "rate_limited" })
        );
        assert!(
            !String::from_utf8_lossy(&body).contains(&blocked),
            "429 不得回显 token"
        );
        let retry: u64 = headers
            .get(header::RETRY_AFTER)
            .expect("429 必须带 Retry-After")
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&retry), "Retry-After 非法: {retry}");
        assert_eq!(
            blocked_last_used(),
            None,
            "超限路径不得执行查库（last_used_at 不能更新）"
        );
    }

    /// 缺失 / 格式错误的 Bearer 也按来源 IP 计失败；达到阈值后同样 429。
    #[tokio::test]
    async fn v034_missing_and_malformed_bearer_are_rate_limited() {
        let state = hub_state_with(HubConfig {
            admin_token: "v034-legacy-admin-token-0123456789".to_string(),
            admin_auth_failure_limit_per_min: 2,
            admin_rate_limit_per_min: 0,
            admin_write_rate_limit_per_min: 0,
            ..HubConfig::default()
        });
        let router = admin_router(state);

        for _ in 0..2 {
            let (status, _, _) = admin_call(&router, "GET", "/api/v1/agents", None, None).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        for _ in 0..2 {
            let (status, headers, body) =
                admin_call(&router, "GET", "/api/v1/agents", None, None).await;
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(json_body(&body)["error"], "rate_limited");
            assert!(headers.contains_key(header::RETRY_AFTER));
        }

        // 格式错误（没有 Bearer scheme）同样会在限速检查处直接 429。
        let request = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agents")
            .header(header::AUTHORIZATION, "wrong-token")
            .body(Body::empty())
            .unwrap();
        let response = call_router(&router, request).await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
