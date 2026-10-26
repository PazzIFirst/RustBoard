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
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, RwLock};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use axum::body::{Body, Bytes};
use axum::extract::ws::{close_code, CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, Query, RawQuery, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, delete, get, post, put};
use axum::{Json, Router};
use clap::{Parser, Subcommand};
use http_body::{Body as HttpBody, Frame as BodyFrame, SizeHint};
use hyper::body::Incoming;
use hyper::Request;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use rustboard_common::config::{AdminTlsMode, DatabaseKind, HubConfig, ServerTlsMode};
use rustboard_common::control::ControlError;
use rustboard_common::fsutil;
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};
use rustboard_common::tls;
use rustboard_common::util::{
    arch, boot_id, hostname, now_ms, os_pretty_name, pick_free_port_excluding, port_of,
};
use rustboard_common::wire::{codes, AgentHello, EnrollRequest, Frame, Welcome};
use rustboard_common::{DEFAULT_HUB_CONFIG, PROTOCOL_VERSION, VERSION};
use rustboard_core::alerts::builtin_rules;
use rustboard_core::archive::{sha256_hex, ArchiveObject, ArchiveStatus, ColdStore};
use rustboard_core::collect::default_collectors;
use rustboard_core::downsample;
use rustboard_core::storage::postgres::PostgresStorage;
#[cfg(test)]
use rustboard_core::storage::sqlite::DEFAULT_READ_POOL_SIZE;
use rustboard_core::storage::StorageHandle;
use rustboard_core::storage::{
    AgentSeriesRow, IngestOutcome, QueryTooLarge, RejectReason, SampleTier, AUDIT_RETENTION_MS,
};
use tokio::net::TcpListener;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

mod acme;
mod alerts;
mod alerts_engine;
mod archive;
mod archive_s3;
mod archive_sftp;
mod archive_webdav;
mod auth;
mod backup_cmd;
mod cert_rotation;
mod channels;
mod control;
mod install_cmd;
mod migrate_cmd;
mod notify;
mod notify_worker;
mod session;
use auth::{AuthFailureLimiter, AuthPrincipal, TokenScope};
use cert_rotation::CertStatus;
use control::{ControlCommand, ControlSession};
use session::{SessionRegistry, ShutdownReason, UnregisterOutcome};

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
/// 通知渠道请求体上限（1 MiB）：渠道配置含少量 secret，远小于此；单独放宽是
/// 为了与告警规则等 64 KiB 路由解耦，同时仍给解析器一个明确硬上限。
const MAX_CHANNEL_BODY_SIZE: usize = 1024 * 1024;
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
/// 一天的毫秒数；series 跨度与保留期换算共用。
const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;
/// `series` 查询最大跨度 730 天，与 1h 层默认保留期（730 天）一致。
///
/// M4-A2b 从 32 天放宽：1h 明细保留 730 天，若仍限制 32 天，长跨度历史数据
/// 将无法查询。超出仍按参数错误（400）拒绝，避免无界扫描。
const MAX_SERIES_SPAN_MS: i64 = 730 * MS_PER_DAY;
/// 选层边界：跨度 ≤6h 用 raw，≤7d 用 1m，更长用 1h（方案 §5.2）。
const SERIES_RAW_MAX_SPAN_MS: i64 = 6 * 60 * 60 * 1000;
const SERIES_ONE_MINUTE_MAX_SPAN_MS: i64 = 7 * 24 * 60 * 60 * 1000;
const MAX_SERIES_METRICS: usize = 20;
const MAX_METRIC_LEN: usize = 64;
/// 自动降采样后单曲线目标点数上限。
const MAX_AUTO_BUCKET_POINTS: i64 = 1_500;
/// 单次 `series` 返回的序列（metric + labels）与点数上限。
const MAX_SERIES_COUNT: usize = 50;
const MAX_SERIES_POINTS: usize = 20_000;
/// 自动 bucket 档位（毫秒）。12h / 24h 两档保证 730 天查询仍不超过 1500 点/曲线。
const AUTO_BUCKETS_MS: [i64; 11] = [
    1_000, 5_000, 10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000, 21_600_000, 43_200_000,
    86_400_000,
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

/// M4：后台每轮降采样最多推进的小时块数。
///
/// 每块最多 1 小时 / 约 5,000 行；限制块数避免首次 backfill 长时间占用写锁，
/// 追平前每轮继续推进，不会丢数据。
const MAINTENANCE_MAX_BACKFILL_HOURS: u32 = 6;

/// M4：`maintenance_state.last_error` 的最大字符数，避免把超长错误写进库。
const MAX_MAINTENANCE_ERROR_CHARS: usize = 2_000;

/// #50：时间戳超界批次的审计计数（仅进程内，不写库）。
///
/// 每批拒绝都 +1；日志按固定间隔采样，避免恶意 agent 用坏批次刷爆日志。
static INGEST_TS_REJECTED_BATCHES: AtomicU64 = AtomicU64::new(0);
/// 每拒绝这么多批采样打一条 WARN；首批一定打。
const INGEST_TS_REJECT_LOG_EVERY: u64 = 100;

/// #50：批内是否有样本时间戳超出 `[ingest]` 准入范围。
///
/// 只做比较，不回显任何样本值；`now_ms` 由调用方统一传入，避免同一批
/// 各样本使用不同边界。
fn batch_timestamp_out_of_bounds(batch: &SampleBatch, cfg: &HubConfig, now: i64) -> bool {
    batch
        .samples
        .iter()
        .any(|sample| !cfg.ingest.accepts_ts(sample.ts, now))
}

/// 记录一次时间戳超界批次拒绝，返回累计拒绝批次数。
fn note_timestamp_rejected_batch(agent_id: &str, batch: &SampleBatch) -> u64 {
    let total = INGEST_TS_REJECTED_BATCHES.fetch_add(1, Ordering::Relaxed) + 1;
    if total == 1 || total.is_multiple_of(INGEST_TS_REJECT_LOG_EVERY) {
        tracing::warn!(
            agent = %agent_id,
            epoch = batch.epoch,
            seq = batch.seq,
            samples = batch.samples.len(),
            rejected_total = total,
            "批次样本时间戳超出 ingest 准入范围：整批 ACK 丢弃（不写库、不改水位）"
        );
    }
    total
}

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
    /// M5：ACME 服务端证书状态 / 强制签发 / 到期续期。
    Tls {
        #[command(subcommand)]
        action: TlsAction,
    },
    /// 查看当前使用的端口与访问地址。
    Ports {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// M4 维护任务：手动执行降采样/保留期，或查看维护状态（JSON 输出）。
    Maintenance {
        #[command(subcommand)]
        action: MaintenanceAction,
    },
    /// M4 冷归档：测试 WebDAV 后端、查看状态、手动执行一轮（JSON 输出）。
    Archive {
        #[command(subcommand)]
        action: ArchiveAction,
    },
    /// M5：安装 hub（自签证书、SQLite、systemd、可选同机面板）。
    Install(install_cmd::InstallArgs),
    /// M5：导入/刷新已有安装（旧手工配置），只补齐 unit/binary/state。
    Upgrade(install_cmd::UpgradeArgs),
    /// M5：卸载 hub（默认保留配置与数据，--purge 才删除）。
    Uninstall(install_cmd::UninstallArgs),
    /// M5：把当前 SQLite 源库离线迁移到 PostgreSQL，成功后切换配置。
    Migrate(migrate_cmd::MigrateArgs),
    /// M5：备份当前数据库、hub.toml 与证书。
    Backup(backup_cmd::BackupArgs),
    /// M5：从备份恢复数据库、hub.toml 与证书。
    Restore(backup_cmd::RestoreArgs),
}

/// `maintenance` 子命令（M4-A2）。
#[derive(Subcommand)]
enum MaintenanceAction {
    /// 执行一次维护任务。
    Run {
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// 任务类型：downsample（聚合）或 retention（按保留期删除）。
        #[arg(long, value_enum)]
        task: MaintenanceTask,
    },
    /// 输出各层行数、水位、最近错误与 retention 配置（JSON）。
    Status {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

/// 维护任务类型。默认没有默认值：必须显式 `--task`，避免误删/误跑。
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum MaintenanceTask {
    /// 1m / 1h 降采样。
    Downsample,
    /// 按 `retention_*_days` 分批删除过期数据。
    Retention,
}

/// `archive` 子命令（M4-C1b）。
#[derive(Subcommand)]
enum ArchiveAction {
    /// 写入/读取/删除一个小探针对象，验证后端连通性与凭据。
    Test {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 输出 enabled / backend / 水位 / 最近运行 / 对象数（JSON）。
    Status {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 立即执行一轮归档（忽略每日计划时间，同样只处理已到期数据）。
    Run {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// v8 归档 ledger 重建状态与手动续跑。
    Ledger {
        #[command(subcommand)]
        action: ArchiveLedgerAction,
    },
}

/// `archive ledger` 子命令（R1a-2）。
#[derive(Subcommand)]
enum ArchiveLedgerAction {
    /// 输出 archive_ledger_pending / 旧水位 / 对象数（JSON）。
    Status {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 标记 ledger 待重建并立即执行一轮归档；完整成功后清除 pending。
    Rebuild {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

/// `tls` 子命令（M5 Phase C C4）。
#[derive(Subcommand)]
enum TlsAction {
    /// 只读打印模式、域名、profile、directory 与当前证书信息（SAN/到期/指纹）。
    Status {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 强制重新签发并安装 ACME 证书（旧材料成对备份；失败保留旧证书）。
    Issue {
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// 仅在到期前续期（剩余寿命 > min(lifetime/3, 48h) 时不做任何网络请求）。
    Renew {
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
    storage: Arc<StorageHandle>,
    cfg: Arc<HubConfig>,
    sessions: Arc<SessionRegistry>,
    /// 客户端证书续签的准入控制（按 agent 的冷却窗口 + 读盘/签名上下文）。
    renewal: Arc<RenewalContext>,
    /// 监听器当前实际使用的证书摘要（热加载成功 / 自动续签后更新）。
    live_cert: Arc<RwLock<CertStatus>>,
    /// 管理 API 的每 IP 固定窗口限速。
    admin_rate: Arc<AdminRateLimiter>,
    /// 未认证 401 的每来源 IP 固定窗口失败限速（KI-26）。
    auth_failures: Arc<AuthFailureLimiter>,
    /// 通知发送器；渠道测试接口与通知 worker 共用，测试可注入 MockNotifier。
    notifier: Arc<dyn notify::Notifier>,
    /// 归档下载单并发许可（1 permit）。
    ///
    /// 下载对象必须先完整读入内存（`ColdStore::get` 返回 `Vec<u8>`），
    /// 单对象上限 64 MiB；用 1 个许可把并发峰值夹到最多一份对象内存。
    archive_download_slots: Arc<Semaphore>,
    /// 归档下载响应 body 的发送期限。
    ///
    /// 客户端拿到响应头后不读 body 时，后台定时任务在到期后释放对象内存与
    /// 下载许可，避免唯一 permit 被永久占用。测试可注入更短的值。
    archive_download_send_timeout: Duration,
    /// 每个认证主体的下载槽（1 permit）。
    ///
    /// 同一 principal 同时最多一个请求持有 / 等待全局 permit；第二个请求立即
    /// 429，避免单客户端用多条连接排队。map 容量有上限，满了先清理空闲槽。
    archive_download_principal_slots: Arc<StdMutex<HashMap<String, Arc<Semaphore>>>>,
}

/// 由 TLS accept 层注入到每个请求扩展里的对端身份。
///
/// `None` 表示这条 TLS 连接没有携带客户端证书（只允许走 enrollment）。
#[derive(Clone, Debug)]
struct PeerIdentity(Option<String>);

fn main() -> Result<()> {
    // KI-21：进程启动最早期收紧 umask 到 0o077（Unix），保证之后由 SQLite/临时文件
    // 创建的文件默认 0600。此时日志尚未初始化，返回值只用于排障，不依赖日志。
    let _ = fsutil::set_private_umask();
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
            run(cfg)
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
        Cmd::Tls { action } => match action {
            TlsAction::Status { config } => tls_status(config),
            TlsAction::Issue { config } => tls_issue(config),
            TlsAction::Renew { config } => tls_renew(config),
        },
        Cmd::Ports { config } => print_ports(config),
        Cmd::Maintenance { action } => maintenance_command(action),
        Cmd::Archive { action } => archive_command(action),
        Cmd::Install(args) => install_cmd::install(args),
        Cmd::Upgrade(args) => install_cmd::upgrade(args),
        Cmd::Uninstall(args) => install_cmd::uninstall(args),
        Cmd::Migrate(args) => migrate_cmd::migrate(args),
        Cmd::Backup(args) => backup_cmd::backup(args),
        Cmd::Restore(args) => backup_cmd::restore(args),
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

/// 只读加载配置：`tls status` 专用，绝不调用 `harden` / 写回配置文件。
///
/// `HubConfig::load` → `load_toml` 会先把 0644 的配置收紧到 0600，诊断命令不应
/// 产生这种磁盘副作用。这里直接读取并解析，权限与内容都保持不变；错误上下文与
/// [`load_config`] 保持一致。其他命令仍使用 [`load_config`] 的既有语义。
fn load_config_read_only(path: &FsPath) -> Result<HubConfig> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "读取配置失败: {}（先执行 rustboard-hub init）",
            path.display()
        )
    })?;
    toml::from_str(&text).with_context(|| {
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

/// 打开配置文件指向的存储（SQLite 或 PostgreSQL；CLI 与运行中的 hub 并发访问）。
fn open_token_storage(config: Option<PathBuf>) -> Result<StorageHandle> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    open_cli_storage_for_config(&cfg).context("打开 token 存储失败")
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

// ---------------------------------------------------------------------------
// M4-A2：maintenance CLI（降采样 / 保留期 / 状态）
// ---------------------------------------------------------------------------

/// 维护 CLI 的入口：只负责打印，业务函数返回可测试的 JSON 字符串。
fn maintenance_command(action: MaintenanceAction) -> Result<()> {
    match action {
        MaintenanceAction::Run { config, task } => {
            println!("{}", maintenance_run_json(config, task)?);
        }
        MaintenanceAction::Status { config } => {
            println!("{}", maintenance_status_json(config)?);
        }
    }
    Ok(())
}

/// 打开配置指向的存储，供维护 CLI 使用。
///
/// 只要求配置本身合法（retention 倒挂/越界必须在这里拒绝，否则删除边界不可信），
/// **不要求 admin_token / 证书材料**：排障与 e2e 可在 hub 未运行时独立执行。
/// `cfg.validate()` 不读取证书文件，也不校验 token 强度。
fn open_maintenance_storage(config: Option<PathBuf>) -> Result<(StorageHandle, HubConfig)> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    cfg.validate().context("维护任务配置校验失败")?;
    let storage = open_cli_storage_for_config(&cfg).context("打开维护数据库失败")?;
    Ok((storage, cfg))
}

/// 执行一次维护任务并返回 JSON（调用方负责打印）。
///
/// CLI 用 `max_backfill_hours = None`：手动执行要一直处理到追平。retention 的
/// 归档门禁与 hub 后台任务一致：`archive.enabled = true` 时读取
/// `archive_state.last_archived_ts`，缺失水位会阻止 raw 删除。
fn maintenance_run_json(config: Option<PathBuf>, task: MaintenanceTask) -> Result<String> {
    let (storage, cfg) = open_maintenance_storage(config)?;
    let now = now_ms();
    let report = match task {
        MaintenanceTask::Downsample => {
            let report = downsample::run_downsample(&*storage, now, None)
                .context("降采样任务失败（task=downsample）")?;
            serde_json::to_value(report)?
        }
        MaintenanceTask::Retention => {
            let gate = archive::archive_gate(&storage, &cfg);
            let report = downsample::run_retention(&*storage, &cfg, now, gate)
                .context("保留期任务失败（task=retention）")?;
            serde_json::to_value(report)?
        }
    };
    Ok(serde_json::to_string_pretty(&report)?)
}

/// `maintenance status` 的 JSON 结构：状态 + 当前生效的 retention / 间隔配置。
#[derive(serde::Serialize)]
struct MaintenanceStatusOutput {
    #[serde(flatten)]
    status: downsample::MaintenanceStatus,
    retention_raw_days: u32,
    retention_1m_days: u32,
    retention_1h_days: u32,
    maintenance_interval_secs: u64,
    ingest_max_late_days: u32,
    ingest_max_future_skew_secs: u64,
}

/// 读取维护状态并返回 JSON（调用方负责打印）。
fn maintenance_status_json(config: Option<PathBuf>) -> Result<String> {
    let (storage, cfg) = open_maintenance_storage(config)?;
    let status =
        downsample::maintenance_status(&*storage, &cfg, now_ms()).context("读取维护状态失败")?;
    let output = MaintenanceStatusOutput {
        status,
        retention_raw_days: cfg.retention_raw_days,
        retention_1m_days: cfg.retention_1m_days,
        retention_1h_days: cfg.retention_1h_days,
        maintenance_interval_secs: cfg.maintenance_interval_secs,
        ingest_max_late_days: cfg.ingest.max_late_days,
        ingest_max_future_skew_secs: cfg.ingest.max_future_skew_secs,
    };
    Ok(serde_json::to_string_pretty(&output)?)
}

// ---------------------------------------------------------------------------
// M4-C1b：archive CLI（后端测试 / 状态 / 手动执行）
// ---------------------------------------------------------------------------

/// `archive` 子命令入口：只负责打印，业务函数返回可测试的 JSON 字符串。
fn archive_command(action: ArchiveAction) -> Result<()> {
    match action {
        ArchiveAction::Test { config } => println!("{}", archive_test_json(config)?),
        ArchiveAction::Status { config } => println!("{}", archive_status_json(config)?),
        ArchiveAction::Run { config } => println!("{}", archive_run_json(config)?),
        ArchiveAction::Ledger { action } => archive_ledger_command(action)?,
    }
    Ok(())
}

/// `archive ledger` 子命令入口；只负责打印业务函数返回的 JSON。
fn archive_ledger_command(action: ArchiveLedgerAction) -> Result<()> {
    match action {
        ArchiveLedgerAction::Status { config } => {
            println!("{}", archive_ledger_status_json(config)?);
        }
        ArchiveLedgerAction::Rebuild { config } => {
            println!("{}", archive_ledger_rebuild_json(config)?);
        }
    }
    Ok(())
}

/// `archive test`：显式测试当前配置的冷存储后端（写入/读取/删除探针对象）。
///
/// 支持 WebDAV、S3 与 SFTP；成功输出 `{ok, backend}`，`backend` 是配置里的
/// 实际值。失败返回固定 [`rustboard_core::archive::ArchiveError`]，不打印
/// URL / 用户名 / 密码 / 私钥路径 / 远端路径 / 响应正文。测试不会启动 hub，
/// 也不需要证书。
fn archive_test_json(config: Option<PathBuf>) -> Result<String> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    cfg.validate().context("归档配置校验失败")?;
    let store = archive::build_store(&cfg.archive)?;
    archive_test_with_store(&cfg, store.as_ref())
}

/// `archive test` 的可测试主体：后端已由 [`archive::build_store`] 构造。
///
/// 拆出来便于测试注入 InMemory / mock store，避免单测依赖真实网络。
fn archive_test_with_store(cfg: &HubConfig, store: &dyn ColdStore) -> Result<String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("初始化归档测试运行时失败")?;
    runtime
        .block_on(store.test())
        .context("归档后端连通性测试失败")?;
    Ok(serde_json::to_string(&serde_json::json!({
        "ok": true,
        "backend": cfg.archive.backend.as_str(),
    }))?)
}

/// `archive status`：读取 `archive_state` / `archive_objects`，输出固定 JSON。
fn archive_status_json(config: Option<PathBuf>) -> Result<String> {
    let (storage, cfg) = open_maintenance_storage(config)?;
    let status = archive::status(&storage, &cfg).context("读取归档状态失败")?;
    Ok(serde_json::to_string_pretty(&status)?)
}

/// `archive run`：立即执行一轮归档（忽略每日计划时间，仍只处理已到期数据）。
fn archive_run_json(config: Option<PathBuf>) -> Result<String> {
    let (storage, cfg) = open_maintenance_storage(config)?;
    if !cfg.archive.enabled {
        bail!("归档未启用（archive.enabled = false）");
    }
    let store = archive::build_store(&cfg.archive)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("初始化归档运行时时失败")?;
    let report = runtime
        .block_on(archive::run_archive_once(
            &storage,
            &cfg,
            store.as_ref(),
            now_ms(),
        ))
        .context("归档任务失败（archive run）")?;
    Ok(serde_json::to_string_pretty(&report)?)
}

/// `archive ledger status`：只读 pending 标记 / 旧水位 / 对象数。
///
/// `archive.enabled = false` 时也可执行，用于查看迁移留下的待重建标记。
fn archive_ledger_status_json(config: Option<PathBuf>) -> Result<String> {
    let (storage, _cfg) = open_maintenance_storage(config)?;
    let status = archive::ledger_status(&storage).context("读取归档 ledger 状态失败")?;
    Ok(serde_json::to_string_pretty(&status)?)
}

/// `archive ledger rebuild`：先置 pending=1，再立即跑一轮归档。
///
/// 失败 / 中断时 pending 保持为 1（R1b 接入后 retention 会继续阻塞）；
/// 完整成功由 worker 清除 pending。输出只含固定报告与 ledger 状态，不含后端
/// URL / 凭据 / 对象内容。
fn archive_ledger_rebuild_json(config: Option<PathBuf>) -> Result<String> {
    let (storage, cfg) = open_maintenance_storage(config)?;
    if !cfg.archive.enabled {
        bail!("归档未启用（archive.enabled = false）");
    }
    let store = archive::build_store(&cfg.archive)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("初始化归档 ledger 重建运行时失败")?;
    let report = runtime
        .block_on(archive::rebuild_ledger(
            &storage,
            &cfg,
            store.as_ref(),
            now_ms(),
        ))
        .context("归档 ledger 重建失败（archive ledger rebuild）")?;
    let ledger = archive::ledger_status(&storage).context("读取归档 ledger 状态失败")?;
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "report": report,
        "ledger": ledger,
    }))?)
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
    // C3：self-signed 生成/复用 CA + 服务端证书；ACME 只准备客户端证书 CA，
    // 服务端证书必须由 `tls issue` 从 ACME 获取，绝不写自签 server 材料。
    let fingerprint = if cfg.tls.mode.is_acme() {
        tls::ensure_client_ca(&cfg.data_dir, policy)?;
        None
    } else {
        Some(tls::ensure_hub_material(
            &cfg.data_dir,
            &cfg.server_names,
            policy,
        )?)
    };
    cfg.save(&path)?;

    println!("已写入配置: {}", path.display());
    println!("证书目录: {}", tls::cert_dir(&cfg.data_dir).display());
    match &fingerprint {
        Some(fingerprint) => println!("服务端证书指纹: {fingerprint}"),
        None => {
            println!(
                "ACME 模式（{}）：只生成客户端证书 CA，未写 server.crt/server.key。",
                cfg.tls.mode.as_str()
            );
            println!(
                "  下一步获取 ACME 证书: rustboard-hub tls issue --config {}",
                path.display()
            );
        }
    }
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
    } else if cfg.tls.mode.is_acme() {
        println!("管理 API HTTPS：使用 ACME 证书（server-auth，不要求客户端证书）");
        println!("  证书 SAN 必须覆盖管理端访问地址（tls.domains）；取得证书后重启 hub 生效。");
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

/// KI-20：安装命令里不需要 shell 引用的安全字符集。
fn shell_arg_safe_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'.' | b'_' | b'/' | b':' | b'@' | b'%' | b'+' | b',' | b'-'
        )
}

/// KI-20：把单个参数安全地放进 POSIX shell 命令。
///
/// 空串或含安全字符集以外的字符时整体用单引号包裹，内部的 `'` 替换为
/// `'\''`（关闭引号 → 转义单引号 → 重新打开引号）。正常 host、token、
/// 指纹、`web-01` 等输出保持逐字节不变。
fn shell_arg(value: &str) -> String {
    if !value.is_empty() && value.bytes().all(shell_arg_safe_byte) {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// hub 的服务端证书来源 → `hub agent add` 应给 agent 的信任模型。
///
/// ACME hub 绝不输出指纹：公共 ACME 用系统根；私有/自定义 ACME
/// （`tls.acme_ca_file` 非空）由 `agent add` 从 `server.crt` 链尾提取 CA，
/// 写成 `<data_dir>/certs/agent-ca.pem` 作为 agent 信任锚。**不能**把
/// `acme_ca_file`（ACME WFE 的 HTTPS 根）当成 agent 验证 hub 的 CA。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HubAgentTrust {
    Fingerprint,
    SystemRoots,
    CustomCa,
}

fn hub_agent_trust(cfg: &HubConfig) -> HubAgentTrust {
    match cfg.tls.mode {
        ServerTlsMode::SelfSigned => HubAgentTrust::Fingerprint,
        ServerTlsMode::AcmeDomain | ServerTlsMode::AcmeIp => {
            if cfg.tls.agent_ca_file.trim().is_empty() && cfg.tls.acme_ca_file.trim().is_empty() {
                HubAgentTrust::SystemRoots
            } else {
                HubAgentTrust::CustomCa
            }
        }
    }
}

/// ACME hub 对 v0.4 指纹 agent 的升级提示（会打印在 `agent add` 输出里）。
const ACME_AGENT_UPGRADE_NOTICE: &str =
    "v0.4 指纹 agent 不兼容 ACME hub，请升级 rustboard-agent 到 v1.0+";

/// 渲染 agent 安装命令时使用的信任来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentInstallTrust<'a> {
    Fingerprint(&'a str),
    SystemRoots,
    CustomCa(&'a str),
}

/// 渲染可直接粘贴执行的 agent 安装命令。
///
/// URL、token、指纹/CA 路径、name 全部经 [`shell_arg`] 引用；fingerprint 模式的
/// 正常值输出与 v0.4 逐字节一致。
fn render_agent_install_command(
    url: &str,
    token: &str,
    name: &str,
    trust: AgentInstallTrust<'_>,
) -> String {
    let mut command = format!(
        "rustboard-agent init --hub {} \\\n    --token {}",
        shell_arg(url),
        shell_arg(token)
    );
    match trust {
        AgentInstallTrust::Fingerprint(fingerprint) => {
            command.push_str(&format!(" --fingerprint {}", shell_arg(fingerprint)));
        }
        AgentInstallTrust::SystemRoots => command.push_str(" --tls-mode system-roots"),
        AgentInstallTrust::CustomCa(ca) => {
            command.push_str(&format!(
                " --tls-mode custom-ca --server-ca {}",
                shell_arg(ca)
            ));
        }
    }
    command.push_str(&format!(" --name {}", shell_arg(name)));
    command
}

/// KI-20：渲染指纹模式的 agent 安装命令（v0.4 输出保持不变）。
///
/// URL、token、指纹、name 全部经 [`shell_arg`] 引用；正常值不改变输出。
fn render_install_command(url: &str, token: &str, fingerprint: &str, name: &str) -> String {
    render_agent_install_command(
        url,
        token,
        name,
        AgentInstallTrust::Fingerprint(fingerprint),
    )
}

/// KI-20：拒绝含 ASCII 控制字符的 agent name（NUL / 换行 / 回车 / Tab / C0 / DEL）。
///
/// 控制字符无法安全地出现在可粘贴的单行安装命令里；必须在创建 enrollment
/// token **之前**拒绝，避免留下无法使用的 token。除此之外不做白名单限制。
fn validate_agent_name(name: &str) -> Result<()> {
    if name.chars().any(|ch| ch.is_ascii_control()) {
        bail!("agent 名称不得包含 ASCII 控制字符（NUL/换行/回车/Tab/DEL）");
    }
    Ok(())
}

/// 私有 ACME：从已签发的 `server.crt` 链尾提取 CA，写成 agent 信任锚。
///
/// `tls.acme_ca_file` 是 ACME 服务端（WFE）的 HTTPS 根，与 ACME 签发的证书链
/// 不一定相同，绝不能直接给 agent 当服务端 CA。这里使用 `server.crt` 的最后
/// 一张 CERTIFICATE（通常是中间 CA / 根 CA），要求 BasicConstraints.ca=true。
///
/// 证书未签发、链尾不是 CA 或写盘失败都返回错误，调用方必须在创建 enrollment
/// token 之前失败。
fn prepare_private_acme_agent_ca(cfg: &HubConfig, config_path: &FsPath) -> Result<PathBuf> {
    let agent_ca_path = tls::cert_dir(&cfg.data_dir).join("agent-ca.pem");

    // 显式稳定根优先，避免链尾 intermediate 轮换导致已分发 agent 失联。
    let explicit = cfg.tls.agent_ca_file.trim();
    if !explicit.is_empty() {
        let source = std::path::Path::new(explicit);
        let text = std::fs::read_to_string(source)
            .with_context(|| format!("读取 tls.agent_ca_file 失败: {}", source.display()))?;
        tls::ensure_certificate_only_pem(&text).with_context(|| {
            format!(
                "tls.agent_ca_file 只允许 CERTIFICATE 区块: {}",
                source.display()
            )
        })?;
        let anchor = tls::last_certificate_pem(&text)?;
        if !tls::certificate_is_ca(&anchor)? {
            bail!(
                "tls.agent_ca_file {} 不是 CA 证书（BasicConstraints.ca=true）",
                source.display()
            );
        }
        fsutil::atomic_write(&agent_ca_path, anchor.as_bytes(), 0o644)
            .with_context(|| format!("写入显式 agent CA 失败: {}", agent_ca_path.display()))?;
        return Ok(agent_ca_path);
    }

    let cert_path = tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE);
    let chain_pem = std::fs::read_to_string(&cert_path).with_context(|| {
        format!(
            "私有 ACME 需要已签发的服务端证书 {}；先执行 `rustboard-hub tls issue --config {}`",
            cert_path.display(),
            config_path.display()
        )
    })?;
    let anchor_pem = tls::last_certificate_pem(&chain_pem)
        .with_context(|| format!("从 {} 提取链尾 CA 失败", cert_path.display()))?;
    if !tls::certificate_is_ca(&anchor_pem)
        .with_context(|| format!("判断 {} 链尾是否为 CA 失败", cert_path.display()))?
    {
        bail!(
            "{} 的证书链尾不是 CA，无法作为 agent 信任锚；请确认 ACME 返回完整证书链",
            cert_path.display()
        );
    }

    fsutil::atomic_write(&agent_ca_path, anchor_pem.as_bytes(), 0o644)
        .with_context(|| format!("写入 agent CA 失败: {}", agent_ca_path.display()))?;
    Ok(agent_ca_path)
}

/// `agent add` 只校验生成安装命令所需的 TLS 字段。
///
/// 不能调用完整 `HubConfig::validate()`：容器中 hub CLI 以 root 执行，而
/// `data_dir` 已 chown 给运行用户 10001，完整校验会因“目录属于其他用户”拒绝。
fn validate_agent_add_config(cfg: &HubConfig) -> Result<()> {
    cfg.tls
        .validate()
        .context("hub TLS 配置校验失败（检查 tls / domains 等）")?;
    tls::parse_server_sans(&cfg.effective_server_names())
        .context("hub 证书名字（server_names / tls.domains）非法")?;
    Ok(())
}

fn agent_add(config: Option<PathBuf>, name: String, ttl_minutes: u32) -> Result<()> {
    // KI-20：先校验 name，再打开数据库 / 创建 token。
    validate_agent_name(&name)?;
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    // 这里只校验生成安装命令所需的 TLS 字段，不能调用完整的
    // `HubConfig::validate()`：容器里 hub 以 root 执行 CLI，而 data_dir 已
    // chown 给 10001，完整校验会以“私有目录属于其他用户”拒绝，导致
    // `docker exec ... agent add` 永远失败。ACME 无 domains 等错误仍需在
    // 创建 token 之前暴露。
    validate_agent_add_config(&cfg)?;

    let trust = hub_agent_trust(&cfg);
    let url = hub_agent_ws_url(&cfg)?;
    let token = new_secret();
    // 所有可能失败的准备（读证书、提取/写 agent CA、渲染 URL）都必须在
    // `create_enroll_token` 之前完成；否则失败会留下无法使用的 token。
    let mut agent_ca_path = None;
    let command = match trust {
        HubAgentTrust::Fingerprint => {
            let cert_pem =
                std::fs::read_to_string(tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE))
                    .context("找不到服务端证书，先执行 rustboard-hub init")?;
            let fingerprint = tls::fingerprint_of_pem(&cert_pem)?;
            render_install_command(&url, &token, &fingerprint, &name)
        }
        HubAgentTrust::SystemRoots => {
            render_agent_install_command(&url, &token, &name, AgentInstallTrust::SystemRoots)
        }
        HubAgentTrust::CustomCa => {
            let ca_path = prepare_private_acme_agent_ca(&cfg, &path)?;
            let ca_text = ca_path.to_str().ok_or_else(|| {
                anyhow::anyhow!("agent CA 路径不是有效 UTF-8: {}", ca_path.display())
            })?;
            let command = render_agent_install_command(
                &url,
                &token,
                &name,
                AgentInstallTrust::CustomCa(ca_text),
            );
            agent_ca_path = Some(ca_path);
            command
        }
    };

    let db = open_cli_storage_for_config(&cfg).context("打开 agent 存储失败")?;
    let now = now_ms();
    let expires = now + (ttl_minutes as i64) * 60_000;
    db.create_enroll_token(&tls::sha256_hex(&token), &name, now, expires)?;

    println!("一次性 token（{ttl_minutes} 分钟内有效，仅可使用一次）:");
    println!("  {token}");
    if trust != HubAgentTrust::Fingerprint {
        println!("\n提示: {ACME_AGENT_UPGRADE_NOTICE}");
        if let Some(ca) = &agent_ca_path {
            println!("  已生成 agent 信任锚: {}", ca.display());
            println!(
                "  请将该文件复制到目标机，或在该路径可读后再执行；\
                 不要把 tls.acme_ca_file（ACME WFE 根）当作 agent CA。"
            );
        }
    }
    println!("\n在目标服务器上执行:");
    println!("  {command}");
    Ok(())
}

/// `hub agent add` 展示给 agent 的 WebSocket 入口。
///
/// self-signed 用 `server_names`（旧行为）；ACME 用 `tls.domains`。优先
/// `advertise_host`，其次第一个非回环 IP，再退回第一个名字。
///
/// ACME 模式下证书 SAN 来自 `tls.domains`：若显式 `advertise_host` 不在其中，
/// 生成的 URL 必然握手失败（主机名校验不通过），必须在创建 token 前拒绝。
fn hub_agent_ws_url(cfg: &HubConfig) -> Result<String> {
    let names = cfg.effective_server_names();
    if cfg.tls.mode.is_acme() {
        if let Some(host) = cfg.advertise_host.as_deref() {
            if !names.iter().any(|name| name.eq_ignore_ascii_case(host)) {
                bail!(
                    "advertise_host={host:?} 不在 ACME 证书名列表 tls.domains {:?} 中；\
                     生成的 wss:// 地址会因主机名校验失败，请修改 advertise_host 或 tls.domains",
                    names
                );
            }
        }
    }
    let host = cfg
        .advertise_host
        .clone()
        .or_else(|| {
            names
                .iter()
                .find(|h| {
                    h.parse::<std::net::IpAddr>()
                        .map(|ip| !ip.is_loopback())
                        .unwrap_or(false)
                })
                .cloned()
        })
        .or_else(|| names.first().cloned())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    let port = cfg.agent_listen.rsplit(':').next().unwrap_or("8443");
    Ok(format!("wss://{host}:{port}/agent/ws"))
}

fn agent_revoke(config: Option<PathBuf>, id: String) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    let db = open_cli_storage_for_config(&cfg).context("打开 agent 存储失败")?;
    db.revoke_agent(&id, now_ms())?;
    println!("已吊销 agent: {id}");
    Ok(())
}

pub(crate) fn new_secret() -> String {
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
    // C3：ACME 模式的服务端证书由 ACME 管理，绝不能走自签 rotate。
    if cfg.tls.mode.is_acme() {
        bail!(
            "当前证书来源是 {}，不能使用 rotate-cert；请用 `rustboard-hub tls issue`（强制重签）\
             或 `rustboard-hub tls renew`（到期续期）",
            cfg.tls.mode.as_str()
        );
    }
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

/// L-01：`tls status` 的 ACME 私有文件只读自检。
///
/// 只打印 `WARN` 与修复建议，**绝不**调用 `harden` / `chmod`，也不跟随符号链接；
/// 真正的权限收紧只发生在 `hub run` 启动期（`acme::store::harden_acme_material`）。
fn warn_acme_material_permissions(data_dir: &FsPath) -> Result<()> {
    for (label, path) in [
        (
            "ACME 账户文件（含私钥）",
            acme::store::account_path(data_dir),
        ),
        ("ACME 状态文件", acme::store::state_path(data_dir)),
    ] {
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                // 诊断命令不能因为单个路径 stat 失败（EACCES/ENOTDIR 等）整体退出；
                // 打印 WARN 后继续检查其余路径，保证 `tls status` 仍可用。
                println!(
                    "WARN: 无法检查 {label} 的权限或类型（{}）：{err}；\
                     tls status 只读，不会跟随或修改该路径。请检查路径与读取权限后重试。",
                    path.display()
                );
                continue;
            }
        };
        if meta.file_type().is_symlink() {
            println!(
                "WARN: {label} 是符号链接（{}）；tls status 不会跟随或修改链接目标，\
                 hub 启动会直接拒绝。请删除链接并恢复真实文件。",
                path.display()
            );
            continue;
        }
        if !meta.file_type().is_file() {
            println!(
                "WARN: {label} 不是普通文件（{}）；hub 启动会直接拒绝。\
                 请移除后恢复真实文件。",
                path.display()
            );
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                println!(
                    "WARN: {label} 权限为 {mode:04o}（含 group/other 位）：{}；\
                     修复：`chmod 600 {}`，或重启 hub（启动期会只收紧到 0600）。\
                     tls status 只读，不会自动修改文件。",
                    path.display(),
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// `rustboard-hub tls status`：只读展示证书来源、公开状态与当前证书信息。
fn tls_status(config: Option<PathBuf>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    // 诊断命令只读：不能用 load_config（load_toml 会把 0644 配置收紧到 0600）。
    let cfg = load_config_read_only(&path)?;
    cfg.validate().context("hub 配置校验失败")?;
    println!("配置文件: {}", path.display());
    println!("证书来源: {}", cfg.tls.mode.as_str());
    println!("证书名字: {}", cfg.effective_server_names().join(", "));
    println!(
        "profile: {}",
        acme::effective_profile(&cfg.tls).unwrap_or("(未设置)")
    );
    println!("挑战: {}", cfg.tls.challenge.as_str());
    println!("ACME directory: {}", cfg.tls.acme_directory);
    let ca_file = cfg.tls.acme_ca_file.trim();
    println!(
        "自定义 ACME CA: {}",
        if ca_file.is_empty() {
            "(系统根)"
        } else {
            ca_file
        }
    );
    // L-01：只读检查 ACME 私有文件权限；发现 0644 / 符号链接只告警，不写盘。
    warn_acme_material_permissions(&cfg.data_dir)?;

    let material = acme::store::read_server_material(&cfg.data_dir)
        .context("读取服务端证书材料失败（状态只读，不写盘）")?;
    let Some(material) = material else {
        println!("服务端证书: 未签发");
        if cfg.tls.mode.is_acme() {
            println!(
                "  执行 `rustboard-hub tls issue --config {}` 获取证书",
                path.display()
            );
            bail!(
                "ACME 服务端证书缺失（{}）",
                tls::cert_dir(&cfg.data_dir)
                    .join(tls::SERVER_CERT_FILE)
                    .display()
            );
        }
        println!(
            "  执行 `rustboard-hub init --config {}` 生成自签证书",
            path.display()
        );
        bail!(
            "服务端证书缺失（{}）",
            tls::cert_dir(&cfg.data_dir)
                .join(tls::SERVER_CERT_FILE)
                .display()
        );
    };
    let names = tls::public_cert_names(&material.cert_pem).context("读取证书 SAN 失败")?;
    let (not_before, not_after) = tls::validity_unix(&material.cert_pem)?;
    println!(
        "服务端证书: {}",
        tls::cert_dir(&cfg.data_dir)
            .join(tls::SERVER_CERT_FILE)
            .display()
    );
    println!("  SAN: {}", names.join(", "));
    println!("  notBefore: {}", tls::format_unix_utc(not_before));
    println!("  notAfter: {}", tls::format_unix_utc(not_after));
    println!(
        "  剩余天数: {}",
        tls::days_left(&material.cert_pem, now_ms())?
    );
    println!("  指纹: {}", tls::fingerprint_of_pem(&material.cert_pem)?);

    if cfg.tls.mode.is_acme() {
        // 只读诊断：损坏的 state.toml 不能在这里留下 `.corrupt-*` 备份文件。
        match acme::store::read_state_read_only(&cfg.data_dir)? {
            Some(state) => {
                println!(
                    "上次签发: {}",
                    state
                        .last_issue_unix
                        .map(tls::format_unix_utc)
                        .unwrap_or_else(|| "(无)".to_string())
                );
                println!(
                    "下次计划尝试: {}",
                    state
                        .next_attempt_unix
                        .map(tls::format_unix_utc)
                        .unwrap_or_else(|| "(无)".to_string())
                );
                if let Some(error) = state.last_error {
                    println!("最近错误: {error}");
                }
            }
            None => println!("ACME 状态: 尚未创建（首次 issue 后写入）"),
        }
    }
    Ok(())
}

/// `rustboard-hub tls issue`：强制重新签发 ACME 证书并原子安装。
fn tls_issue(config: Option<PathBuf>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    cfg.validate().context("hub 配置校验失败")?;
    if !cfg.tls.mode.is_acme() {
        bail!(
            "当前证书来源是 {}，不是 ACME；自签证书请使用 `rustboard-hub rotate-cert --force`",
            cfg.tls.mode.as_str()
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let issued = runtime.block_on(acme::renewal::issue_and_install(&cfg))?;
    println!("ACME 证书已签发并安装（已有旧材料时已成对备份）");
    print_issued_cert(&issued);
    println!(
        "运行中的 hub 会在 ≤10s 内热加载新证书（无需重启）；\
         若当前没有运行中的 hub，下次启动会直接使用新证书。"
    );
    Ok(())
}

/// `rustboard-hub tls renew`：仅在到期前续期；未到窗口时零网络请求、零写入。
fn tls_renew(config: Option<PathBuf>) -> Result<()> {
    let path = config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG));
    let cfg = load_config(&path)?;
    cfg.validate().context("hub 配置校验失败")?;
    if !cfg.tls.mode.is_acme() {
        bail!(
            "当前证书来源是 {}，不是 ACME；自签证书请使用 `rustboard-hub rotate-cert`",
            cfg.tls.mode.as_str()
        );
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    match runtime.block_on(acme::renewal::renew_if_due(&cfg, None))? {
        Some(issued) => {
            println!("ACME 证书已续期并安装（已有旧材料时已成对备份）");
            print_issued_cert(&issued);
            println!("运行中的 hub 会在 ≤10s 内热加载新证书（无需重启）。");
        }
        None => {
            let material = acme::store::read_server_material(&cfg.data_dir)?
                .context("未到续期窗口，但服务端证书材料缺失")?;
            println!(
                "当前证书剩余 {} 天，高于续期阈值 min(lifetime/3, 48h)，未续期。",
                tls::days_left(&material.cert_pem, now_ms())?
            );
            println!(
                "  证书到期: {}",
                tls::format_unix_utc(tls::not_after_unix(&material.cert_pem)?)
            );
            println!("  立即强制重签请执行 `rustboard-hub tls issue`。");
        }
    }
    Ok(())
}

/// 打印 ACME 签发结果的公开信息（绝不打印私钥或 token）。
fn print_issued_cert(issued: &acme::client::IssuedCert) {
    println!(
        "  服务端证书指纹: {}",
        tls::fingerprint_of_pem(&issued.cert_pem).unwrap_or_else(|_| "(无法解析)".to_string())
    );
    println!(
        "  证书到期: {}（剩余 {} 天）",
        tls::format_unix_utc(issued.not_after),
        tls::days_left(&issued.cert_pem, now_ms()).unwrap_or(0)
    );
    match tls::public_cert_names(&issued.cert_pem) {
        Ok(names) => println!("  证书 SAN: {}", names.join(", ")),
        Err(err) => println!("  证书 SAN: 无法解析（{err}）"),
    }
}

/// 数据库文件的直接父目录是否就是要声明的私有 `data_dir`。///
/// 只有「非空父目录且恰好等于 `data_dir`」才允许走
/// [`StorageHandle::sqlite_with_private_data_dir`] 收紧目录权限；相对路径（父目录为空）
/// 与外置数据库一律返回 false，调用方走普通构造，绝不 chmod 可能共享的父目录。
fn storage_uses_private_data_dir(db_path: &FsPath, data_dir: &FsPath) -> bool {
    db_path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty() && parent == data_dir)
}

/// 打开 SQLite 存储（KI-21）。
///
/// `data_dir` 是数据库文件的直接父目录时，把它声明为 hub 专用数据目录：旧版本
/// 遗留的 0755 目录会在打开前被收紧到 0700。数据库在 `data_dir` 之外（或 `database`
/// 是相对路径）时走普通构造，**绝不 chmod** 与该库无关的父目录（可能是 `/tmp`、
/// `/var/tmp` 等共享目录），并在启动时打一次 WARN 提示运维。
fn open_storage(
    db_path: &FsPath,
    data_dir: &FsPath,
    read_pool_size: usize,
) -> Result<StorageHandle> {
    let uses_private_data_dir = storage_uses_private_data_dir(db_path, data_dir);
    if !uses_private_data_dir {
        // 只告警不拒绝：外置 DB 是允许的部署形态，只是父目录不会被收紧。
        tracing::warn!(
            db = %db_path.display(),
            data_dir = %data_dir.display(),
            "数据库不在 data_dir 下：父目录不收紧（不做 0700 收紧），DB 文件仍 0600"
        );
    }
    if uses_private_data_dir {
        StorageHandle::sqlite_with_private_data_dir(db_path, read_pool_size, data_dir)
    } else {
        StorageHandle::sqlite(db_path, read_pool_size)
    }
}

/// 按 `HubConfig::database` 打开对应后端（Phase D4）。
///
/// # 运行时不变量
///
/// PostgreSQL 的同步驱动会在内部创建 current-thread runtime 并 `block_on`；
/// 在 tokio runtime 内调用会直接 panic（spike §4.1）。因此本函数**只能在
/// runtime 外调用**：`run` 在 `runtime.block_on` 之前调用，CLI 命令本身就在
/// runtime 外调用。async 任务内的存储访问必须走 [`storage_blocking`]。
///
/// PostgreSQL 路径会在返回前完成幂等 schema 迁移；SQLite 路径与旧行为一致，
/// 仍走 [`open_storage`]（数据库位于 `data_dir` 时收紧目录权限）。
/// 所有错误上下文只包含 `DatabaseKind::redacted()`，不出现 DSN 密码。
fn open_storage_for_config(cfg: &HubConfig) -> Result<StorageHandle> {
    open_storage_for_config_with(cfg, true)
}

/// CLI 版存储入口：PostgreSQL 与 hub 启动一致，SQLite 保持旧 CLI 行为。
///
/// 旧 CLI（token / agent / maintenance）直接 `StorageHandle::sqlite`，不会声明
/// `data_dir` 为私有目录。容器里 hub 以运行用户 10001 持有 `data_dir`，而
/// `docker exec` 的 CLI 是 root；若这里调用 [`open_storage`] 收紧目录权限，
/// 会因「目录属于其他用户」直接失败。因此 CLI 路径只打开数据库文件。
fn open_cli_storage_for_config(cfg: &HubConfig) -> Result<StorageHandle> {
    open_storage_for_config_with(cfg, false)
}

fn open_storage_for_config_with(
    cfg: &HubConfig,
    harden_sqlite_data_dir: bool,
) -> Result<StorageHandle> {
    let kind = cfg.database_kind().context("解析 database 配置失败")?;
    match &kind {
        DatabaseKind::Sqlite(path) => {
            if harden_sqlite_data_dir {
                open_storage(path, &cfg.data_dir, cfg.read_pool_size)
            } else {
                StorageHandle::sqlite(path, cfg.read_pool_size)
                    .with_context(|| format!("打开 SQLite 数据库失败: {}", path.display()))
            }
        }
        DatabaseKind::Postgres(_) => {
            let database = kind.redacted();
            // `open_from_config` 内部会建立连接池并做一次 SELECT 1；apply_schema
            // 复用池内连接。两者都必须在 blocking 上下文执行。
            let pg = PostgresStorage::open_from_config(cfg)
                .with_context(|| format!("打开 PostgreSQL 存储失败（database={database}）"))?;
            pg.apply_schema()
                .with_context(|| format!("初始化 PostgreSQL schema 失败（database={database}）"))?;
            Ok(StorageHandle::postgres(pg))
        }
    }
}

/// 在 blocking 线程上执行一次同步存储调用。
///
/// async 路径（会话握手、心跳、清理、启动初始化）不得直接调用
/// [`StorageHandle`]：PostgreSQL 的 connect/query/drop 在 tokio worker 上会
/// panic（`Cannot start a runtime from within a runtime`，spike §4）。闭包内
/// 完成“取连接 → 查询/事务 → 归还连接”，不把任何连接 guard 返回到 async 侧。
/// SQLite 也统一走这里，换来的是边界一致、不需要按后端分叉调用点。
async fn storage_blocking<T, F>(storage: Arc<StorageHandle>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&StorageHandle) -> Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || f(&storage)).await {
        Ok(result) => result,
        Err(err) => Err(anyhow::Error::new(err).context("执行存储后台任务失败")),
    }
}

/// 启动时收紧已存在的证书目录（KI-21）。
///
/// 只处理已经存在的目录：证书缺失是另一类需要暴露的启动错误，不能用一个新建的
/// 空目录把它掩盖成「目录存在但文件不全」。
fn harden_existing_cert_dir(data_dir: &FsPath) -> Result<()> {
    let cert_dir = tls::cert_dir(data_dir);
    if cert_dir.exists() {
        fsutil::harden_dir(&cert_dir, 0o700)
            .with_context(|| format!("收紧证书目录权限失败: {}", cert_dir.display()))?;
    }
    Ok(())
}

fn run(cfg: HubConfig) -> Result<()> {
    // 启动前先做配置自洽性校验，避免把明显错误的有效期/检查周期带到运行期。
    cfg.validate().context("hub 配置校验失败")?;
    // common 侧暂不校验采样间隔；hub 启动前本地兜住，避免 Welcome 下发非法值。
    validate_hub_sample_interval(&cfg)?;
    // M2：管理 API 全部要求 Bearer token，空 token 不允许启动。
    require_admin_token(&cfg)?;
    // v0.3.3：非回环管理监听禁止明文；required 时校验绑定 IP 在证书 SAN 内。
    // 必须发生在任何监听 / 证书加载之前。
    validate_admin_tls(&cfg)?;
    // KI-21：数据目录完全归 hub 所有。在打开数据库前创建/收紧到 0700，
    // 旧版本遗留的 0755 数据目录也会在这里被修正。
    fsutil::ensure_private_dir(&cfg.data_dir, 0o700)
        .with_context(|| format!("创建或收紧数据目录失败: {}", cfg.data_dir.display()))?;
    // L-01：启动期把既有 ACME account.json / state.toml 只收紧到 0600。必须发生在
    // 任何 TLS/ACME 读取之前，且与 tls.mode 无关（切回 self-signed 后旧文件仍在）；
    // 符号链接、非普通文件或 chmod 失败都直接阻止启动，不能静默带着过宽权限运行。
    acme::store::harden_acme_material(&cfg.data_dir)
        .context("启动前收紧 ACME 账户/状态文件权限失败")?;

    // Phase D4：存储必须在 tokio runtime 之前打开。PostgreSQL 的同步连接池
    // 不能在 async 块内创建（spike §4.1/§4.4），schema 迁移同样在 blocking
    // 上下文完成；SQLite 提前打开行为不变。
    let database = cfg
        .database_kind()
        .context("解析 database 配置失败")?
        .redacted();
    let storage = Arc::new(open_storage_for_config(&cfg)?);
    tracing::info!(database = %database, read_pool_size = cfg.read_pool_size, "存储已就绪");

    // 存储（SQLite/PG）调用统一走 spawn_blocking。默认 512 会在 200/1000 agent
    // 压测中堆到数百个 blocking 线程，每线程的 glibc allocator arena 与线程栈形成
    // RSS 高水位。64 足够覆盖 SQLite 单写 + PG pool 8 + 证书/维护任务；突发批次在
    // 队列等待，而不是无限扩线程。
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .max_blocking_threads(64)
        .enable_all()
        .build()?;

    // 保留一份 runtime 外的句柄：即使 async 侧先结束，PG 连接池的最后一个
    // Arc 也在 runtime 之外释放（D3 的 Drop 另有独立线程兜底）。
    let storage_for_run = storage.clone();
    let result: Result<()> = runtime.block_on(async move {
        let storage = storage_for_run;

        // L5：监听前清掉上次异常退出遗留的 online，避免面板长期显示假在线。
        // 所有存储调用都在 spawn_blocking 内，PG 才不会在 worker 上 panic。
        let reset = storage_blocking(storage.clone(), |storage| storage.reset_online_status())
            .await
            .context("启动时重置在线状态失败")?;
        if reset > 0 {
            tracing::info!(count = reset, "启动时已将残留的 online 状态重置为 offline");
        }

        // #50 / R1b：迁移旧库里的超界时间戳 raw 与超过 1m horizon 的未聚合行，
        // 避免 delta 为这些历史坏数据构造残缺 1m。审计失败不阻塞监听；新的
        // 超界批次仍会在 ingest 前被 ACK 丢弃。
        let audit_now = now_ms();
        let audit_cfg = cfg.clone();
        match storage_blocking(storage.clone(), move |storage| {
            downsample::audit_legacy_raw_rows(storage.as_storage(), &audit_cfg, audit_now)
        })
        .await
        {
            Ok(report) => tracing::debug!(?report, "启动时 legacy raw 时间戳审计完成"),
            Err(err) => tracing::warn!(
                error = %err,
                "启动时 legacy raw 时间戳审计失败；新批次仍受 ingest 准入校验保护"
            ),
        }

        // M3：审计保留 180 天，启动时先清一次过期记录（运行期每 1000 条再清）。
        let audit_cutoff = now_ms().saturating_sub(AUDIT_RETENTION_MS);
        match storage_blocking(storage.clone(), move |storage| {
            storage.prune_audit(audit_cutoff)
        })
        .await
        {
            Ok(0) => {}
            Ok(removed) => tracing::info!(removed, "启动时已清理过期审计记录"),
            Err(err) => tracing::warn!(error = %err, "启动时清理过期审计记录失败"),
        }

        // M4-B1：内置告警规则是面板与告警引擎的功能依赖（固定 id，创建接口只生成
        // UUID），启动后无法补种，因此种子失败直接上抛，不让 hub 以缺规则的半残
        // 状态监听。种子按固定 id 幂等、绝不覆盖用户改过的阈值 / 启停状态；名称被
        // 其它规则占用时显式失败（不再静默跳过）。初始阈值来自 `[alerts]` 配置：
        // 离线用 `offline_after_secs`（秒），证书用 `cert_warn_hours`（小时）。
        let seed_now = now_ms();
        let offline_after_secs = cfg.alerts.offline_after_secs;
        let cert_warn_hours = cfg.alerts.cert_warn_hours;
        let seeded = storage_blocking(storage.clone(), move |storage| {
            storage.seed_builtin_alert_rules(
                &builtin_rules(seed_now, offline_after_secs, cert_warn_hours),
                seed_now,
            )
        })
        .await
        .context("写入内置告警规则失败")?;
        if seeded > 0 {
            tracing::info!(seeded, "已写入内置告警规则（初始 disabled）");
        }

        // 升级路径：旧安装的 ca.key / server.key 可能是 0644
        tls::harden_hub_material(&cfg.data_dir)?;
        // KI-21：证书目录同样是 hub 专用目录，旧版本的 0755 在启动时收紧到 0700；
        // 目录不存在时保持缺失，由后续构建/自愈流程暴露真实错误。
        harden_existing_cert_dir(&cfg.data_dir)?;
        // 启动加载：self-signed 允许有限自愈（配对损坏/仅过期）；ACME 只加载/校验，
        // 证书缺失时给 `rustboard-hub tls issue` 的明确提示，绝不自签。
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
        tracing::info!(
            fingerprint,
            mode = cfg.tls.mode.as_str(),
            names = %cfg.effective_server_names().join(","),
            "TLS 已启用"
        );
        // 管理端 watcher 以「启动时实际构建配置的证书」为基线，而不是启动后读 live：
        // 避免极端竞态下把启动后才切换的指纹误当成已加载。
        let initial_admin_fingerprint = fingerprint.clone();

        let sessions = SessionRegistry::new();
        // B2：固定四家端点 + 固定超时/重试次数；`notify_max_attempts` 在构造器内
        // 夹到 1..=10。构造失败意味着系统 TLS 根证书不可用，直接启动失败更安全。
        let notifier: Arc<dyn notify::Notifier> = Arc::new(
            notify::HttpNotifier::new(
                Duration::from_secs(cfg.alerts.notify_timeout_secs),
                cfg.alerts.notify_max_attempts,
            )
            .context("初始化通知发送器失败")?,
        );
        let state = AppState {
            storage: storage.clone(),
            cfg: Arc::new(cfg.clone()),
            sessions: sessions.clone(),
            renewal: RenewalContext::new(
                tls::cert_dir(&cfg.data_dir),
                cfg.client_cert_validity_days,
            ),
            live_cert: live_cert.clone(),
            admin_rate: Arc::new(AdminRateLimiter::from_config(&cfg)),
            auth_failures: Arc::new(AuthFailureLimiter::new(
                cfg.admin_auth_failure_limit_per_min,
            )),
            notifier: notifier.clone(),
            archive_download_slots: Arc::new(Semaphore::new(1)),
            archive_download_send_timeout: ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
            archive_download_principal_slots: Arc::new(StdMutex::new(HashMap::new())),
        };

        spawn_revoke_watcher(storage.clone(), sessions);

        // 服务端证书续期：self-signed 用本地 CA 重签；ACME 用 orders/挑战续期。
        // 两者都通过 watch 推送新 rustls 配置；accept 循环每条新连接读一次。
        let (tls_tx, tls_rx) = watch::channel(tls_config);
        if cfg.tls.mode.is_acme() {
            acme::renewal::spawn_acme_renewal(state.cfg.clone(), tls_tx.clone());
        } else {
            cert_rotation::spawn_server_renewal(
                state.cfg.clone(),
                tls_tx.clone(),
                live_cert.clone(),
            );
        }
        // KI-10：每 10s 轮询磁盘证书，运行中 rotate/issue 后 mTLS ≤10s 热加载；
        // 管理端 watcher 每 2s 跟随 live_cert，合计最迟约 12s（对外承诺 ≤15s）。
        cert_rotation::spawn_cert_file_watcher(state.cfg.clone(), tls_tx, live_cert.clone());

        // v0.3.3：管理端可选 HTTPS。复用 agent 入口的 server.crt/server.key，
        // 但为 server-auth（不要求客户端证书）；watcher 轮询 live_cert 指纹，
        // 换证成功后新连接使用新配置，构建失败保留旧配置。
        let admin_tls = match cfg.admin_tls {
            AdminTlsMode::Off => None,
            AdminTlsMode::Required => {
                let config = cert_rotation::build_admin_server_config(&cfg)
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
        // M4：降采样 + 保留期后台任务。启动后先睡一个周期，不做同步 backfill，
        // 不阻塞监听；每轮在 spawn_blocking 内串行执行。
        spawn_maintenance(storage.clone(), cfg.clone());
        // M4-C1b：冷归档 worker。`archive.enabled = false` 时只记日志不启动；
        // 启动时若今天已过计划时间且水位落后，会立即补跑一轮。
        archive::spawn_archive_worker(storage.clone(), cfg.clone());
        // M4-B1b：告警评估任务。`alerts.enabled = false` 时只记日志不启动；
        // 启动后同样先睡一个周期，避免与监听 / 维护任务抢写锁。
        alerts_engine::spawn_alert_engine(storage.clone(), cfg.clone());
        // M4-B2b：通知 worker 在评估引擎之后启动。首次启动以当前最大事件 id 为
        // 水位（不补发 B1b 存量事件）；`alerts.enabled = false` 时不启动。
        notify_worker::spawn_notify_worker(storage.clone(), cfg.clone(), notifier.clone());

        let agent_app = Router::new()
            .route("/agent/ws", get(agent_ws))
            .with_state(state.clone());

        // `/healthz` 免鉴权；`/api/v1/*` 统一挂 Bearer 中间件。
        let admin_app = admin_router(state);

        let agent_addr = cfg.agent_listen.clone();
        let admin_addr = cfg.admin_listen.clone();
        tracing::info!(
            %agent_addr,
            mode = cfg.tls.mode.as_str(),
            "agent 接入监听（TLS）"
        );
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
    });
    // PG 连接池的最后一个引用必须在 runtime 外释放（spike §4.3）；D3 的
    // `PostgresStorage::Drop` 还会把池移交给独立线程，这里是双保险。
    drop(runtime);
    drop(storage);
    result
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
/// - `required`：绑定 IP 在 `server_names` / `tls.domains` 里（比较前 trim），或管理端
///   可通过 DNS 名访问；两者都不满足时拒绝启动。`0.0.0.0` / `::` 通配绑定跳过精确检查。
/// - 回环绑定要求**精确 IP SAN**，不放宽（fail-closed）；错误信息给出三种可用部署方式，
///   并明确警告不要把回环 IP 加进公共 ACME 域名证书（公共 CA 不会签发回环 IP SAN）。
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
            // self-signed 用 server_names；ACME 用 tls.domains（effective_server_names）。
            let effective_names = cfg.effective_server_names();
            if ip.is_unspecified() {
                // 通配绑定不知道客户端用哪个地址访问，跳过精确 SAN 检查；但如果
                // 证书名字只有回环名，远端客户端必然校验证书失败，提前告警。
                if all_loopback_server_names(&effective_names) {
                    tracing::warn!(
                        "管理 API 使用通配绑定，但证书名字全部是回环名；\
                         远端客户端校验证书会失败，请补充可访问的 IP / DNS SAN 后重新签发"
                    );
                }
                return Ok(());
            }
            let names: Vec<&str> = effective_names
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
                if ip.is_loopback() {
                    bail!(
                        "admin_tls=\"required\" 且管理 API 只绑定回环地址 {ip}，但证书名字\
                         （ACME tls.domains / self-signed server_names）中没有该回环 IP 的 SAN，\
                         本机无法通过 HTTPS 访问管理 API。这是刻意的 fail-closed：管理端按 IP \
                         直连时证书必须精确覆盖该 IP，不会为了启动而放宽校验。请任选一种部署方式：\n\
                         1) 管理口绑定对外地址，用防火墙 / 云安全组限制来源：\n\
                            admin_listen = \"0.0.0.0:8444\"\n\
                            admin_tls = \"required\"\n\
                            证书需覆盖管理端实际访问的 DNS 名（self-signed 用 server_names，\
                            ACME 用 tls.domains）；改完执行 `rustboard-hub tls issue`（ACME）或 \
                            `rustboard-hub rotate-cert --force`（self-signed）。\n\
                         2) 同机 panel 走回环明文 HTTP，TLS 交给反向代理：\n\
                            admin_tls = \"off\"\n\
                            admin_listen = \"127.0.0.1:8444\"\n\
                            面板访问 http://127.0.0.1:8444，由 nginx/Caddy 等反向代理终止 TLS；\
                            仍必须保留 Bearer token，且不要把 8444 直接暴露到公网。\n\
                         3) 改用包含 {ip} SAN 的 self-signed 证书（仅 self-signed）：\n\
                            把 {ip} 加入 server_names（保留现有主机名），然后执行 \
                            `rustboard-hub rotate-cert --force`。\n\
                         警告：不要把回环 IP 加入公共 ACME 域名证书（tls.domains）；\
                         Let's Encrypt 等公共 CA 不会为 127.0.0.1 / ::1 等回环地址签发 SAN。\
                         ACME 模式请使用方式 1 或 2。"
                    );
                }
                bail!(
                    "admin_tls=\"required\" 且管理 API 绑定 {ip}，但证书名字（server_names / \
                     ACME tls.domains）中既没有该 IP SAN、也没有可用于远端访问的 DNS SAN；\
                     请先把 {ip}（或管理端 DNS 名）加入 server_names / tls.domains，\
                     self-signed 执行 `rustboard-hub rotate-cert --force`，\
                     ACME 执行 `rustboard-hub tls issue` 重新签发证书"
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
    // KI-28：每来源拒绝日志采样；accept 循环单任务访问，无需加锁。
    let mut reject_sampler = RejectLogSampler::new();
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
                log_connection_reject(
                    &mut reject_sampler,
                    peer.ip(),
                    ADMIN_MAX_CONNECTIONS_PER_IP,
                    "管理 API 来源 IP 并发连接已达上限，直接关闭 TCP",
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
    let config = cert_rotation::build_admin_server_config(cfg)
        .context("管理 API TLS 配置构建失败（检查证书 SAN / 有效期 / EKU）")?;
    // 构建期间证书可能又被 rotate：与 mTLS 热加载一致，本周期跳过，下周期重试。
    let confirmed = cert_rotation::read_disk_cert_status(cfg)?;
    if confirmed.fingerprint != current {
        tracing::debug!("证书在管理端热加载过程中再次变化，本周期跳过");
        return Ok(None);
    }
    tx.send_replace(config);
    Ok(Some(confirmed.fingerprint))
}

/// 通知渠道路由：单独挂 1 MiB 请求体上限（其余管理 API 仍为 64 KiB）。
///
/// `DefaultBodyLimit` 是请求扩展：内层路由设置的值会覆盖外层全局 64 KiB。
fn channel_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/alerts/channels",
            get(channels::list_channels).post(channels::create_channel),
        )
        .route(
            "/api/v1/alerts/channels/{id}",
            put(channels::update_channel).delete(channels::delete_channel),
        )
        .route(
            "/api/v1/alerts/channels/{id}/test",
            post(channels::test_channel),
        )
        .layer(DefaultBodyLimit::max(MAX_CHANNEL_BODY_SIZE))
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
        // M4-B1：告警规则 CRUD、事件分页、静默创建 / 撤销。渠道留给 B2。
        .route(
            "/api/v1/alerts/rules",
            get(alerts::list_rules).post(alerts::create_rule),
        )
        .route(
            "/api/v1/alerts/rules/{id}",
            put(alerts::update_rule).delete(alerts::delete_rule),
        )
        .route("/api/v1/alerts/events", get(alerts::list_events))
        .route(
            "/api/v1/alerts/silences",
            get(alerts::list_silences).post(alerts::create_silence),
        )
        .route(
            "/api/v1/alerts/silences/{id}",
            delete(alerts::delete_silence),
        )
        // M4-B2b：通知渠道 CRUD 与测试发送。渠道请求体单独放宽到 1 MiB。
        .merge(channel_routes())
        // M4-C1b / C2b：归档状态、对象列表与下载。响应只含对象元数据，
        // 不返回后端 URL / 凭据；下载失败统一 502 `archive_unavailable`。
        .route("/api/v1/archive/status", get(archive_status))
        .route("/api/v1/archive/objects", get(archive_objects))
        .route(
            "/api/v1/archive/objects/{id}/download",
            get(archive_object_download),
        )
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

/// `GET /api/v1/archive/status`：归档开关 / 后端 / 水位 / 最近运行 / 对象数。
///
/// 只返回配置中的后端类型与状态，不返回 WebDAV URL 或凭据；SQLite 读取放到
/// `spawn_blocking`，避免阻塞 async worker。
async fn archive_status(
    State(state): State<AppState>,
) -> Result<Json<archive::ArchiveStatusOutput>, ApiError> {
    let storage = state.storage.clone();
    let cfg = state.cfg.clone();
    let status = tokio::task::spawn_blocking(move || archive::status(&storage, &cfg))
        .await
        .map_err(ApiError::from)?
        .map_err(ApiError::from)?;
    Ok(Json(status))
}

/// 归档对象列表默认条数（面板固定 50）。
const DEFAULT_ARCHIVE_OBJECT_LIMIT: usize = 50;
/// 归档对象列表单页上限（方案 §8.1：limit 1..=100）。
const MAX_ARCHIVE_OBJECT_LIMIT: usize = 100;
/// 单次下载的内存硬上限（64 MiB）。
///
/// `ColdStore::get` 返回完整 `Vec<u8>`，无法流式读取；1 GiB 上限在并发请求下
/// 足以打爆内存。这里把“单请求内存”夹到 64 MiB，并配合 AppState 的 1 permit
/// 信号量限制并发；超过上限直接 413，不读 body。
const MAX_ARCHIVE_DOWNLOAD_BYTES: u64 = 64 * 1024 * 1024;
/// 归档下载主体槽上限。
///
/// 认证主体数量本身有限，但仍设硬上限防止异常 token 名称撑大内存；达到上限时
/// 先清理“无人持有 / 无人等待”的空闲槽，仍满则按忙碌拒绝。
const MAX_ARCHIVE_DOWNLOAD_PRINCIPALS: usize = 1024;
/// 归档下载响应 body 的发送期限（方案 §7.4 下载防 DoS）。
///
/// 客户端拿到响应头后不读 body 时，后台任务到期释放对象内存与下载许可；
/// 固定在 120s，避免慢读客户端永久占用唯一 permit。
const ARCHIVE_DOWNLOAD_SEND_TIMEOUT: Duration = Duration::from_secs(120);
/// `archive_objects.error` 允许透传的固定错误码；其它内容（可能来自人工改库 /
/// 旧版本）一律收敛为 `archive_error`，避免把 URL 或后端正文带到 API。
const ARCHIVE_OBJECT_ERROR_CODES: [&str; 7] = [
    "invalid_key",
    "invalid_manifest",
    "invalid_status",
    "encode_failed",
    "backend_unavailable",
    "not_found",
    "rows_missing",
];

/// 归档对象列表响应：`objects` 按 id 倒序，`next_before_id` 是下一页排他游标。
#[derive(Debug, serde::Serialize)]
struct ArchiveObjectListResponse {
    objects: Vec<ArchiveObjectView>,
    next_before_id: Option<i64>,
}

/// 归档对象对外视图：只含对象元数据，不含后端 URL / 凭据 / 内部配置。
#[derive(Debug, serde::Serialize)]
struct ArchiveObjectView {
    id: i64,
    object_key: String,
    manifest_key: String,
    from_ts: i64,
    to_ts: i64,
    rows: u64,
    bytes: u64,
    sha256: String,
    status: ArchiveStatus,
    error: String,
    created_at: i64,
    uploaded_at: Option<i64>,
    deleted_at: Option<i64>,
    /// failed 重试次数（v8 claim 对象；旧 v7 对象为 0）。
    attempts: i64,
    /// 对象 claim 行集已缺失，无法再重建上传（error = `rows_missing`）。
    rows_missing: bool,
    /// 是否可下载：状态就绪且对象大小未超过固定 64 MiB 下载上限。
    downloadable: bool,
}

/// 归档对象是否可下载（KI-31）。
///
/// 只依赖固定下载硬上限，不受 `archive.max_object_bytes`（worker 分片）影响。
fn archive_object_downloadable(object: &ArchiveObject) -> bool {
    matches!(
        object.status,
        ArchiveStatus::Uploaded | ArchiveStatus::LocalDeleted
    ) && object.bytes <= MAX_ARCHIVE_DOWNLOAD_BYTES
}

impl From<ArchiveObject> for ArchiveObjectView {
    fn from(object: ArchiveObject) -> Self {
        let downloadable = archive_object_downloadable(&object);
        let rows_missing = object.error == "rows_missing";
        Self {
            id: object.id,
            object_key: object.object_key,
            manifest_key: object.manifest_key,
            from_ts: object.from_ts,
            to_ts: object.to_ts,
            rows: object.rows,
            bytes: object.bytes,
            sha256: object.sha256,
            status: object.status,
            error: archive_error_view(&object.error),
            created_at: object.created_at,
            uploaded_at: object.uploaded_at,
            deleted_at: object.deleted_at,
            attempts: object.attempts,
            rows_missing,
            downloadable,
        }
    }
}

/// `error` 只允许固定错误码；空串保持为空（成功对象）。
fn archive_error_view(error: &str) -> String {
    if error.is_empty() {
        return String::new();
    }
    if ARCHIVE_OBJECT_ERROR_CODES.contains(&error) {
        return error.to_string();
    }
    "archive_error".to_string()
}

/// `GET /api/v1/archive/objects?limit=&before_id=`：按 id 倒序分页列出归档对象。
async fn archive_objects(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
) -> Result<Json<ArchiveObjectListResponse>, ApiError> {
    let pairs = parse_query_pairs(raw.as_deref()).map_err(ApiError::bad_request)?;
    let limit = parse_archive_objects_limit(&pairs).map_err(ApiError::bad_request)?;
    let before_id = parse_archive_before_id(&pairs).map_err(ApiError::bad_request)?;

    let storage = state.storage.clone();
    let objects =
        tokio::task::spawn_blocking(move || storage.list_archive_objects(limit, before_id))
            .await
            .map_err(ApiError::from)?
            .map_err(ApiError::from)?;
    // 排他游标：本页满时下一页从最后一条 id 继续（严格小于），不会漏也不会重。
    let next_before_id = if objects.len() == limit {
        objects.last().map(|object| object.id).filter(|id| *id > 1)
    } else {
        None
    };
    Ok(Json(ArchiveObjectListResponse {
        objects: objects.into_iter().map(Into::into).collect(),
        next_before_id,
    }))
}

/// 取单值查询参数；重复出现视为参数错误（不猜客户端意图）。
fn single_archive_query_value<'a>(
    pairs: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, String> {
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

/// 解析 `limit`：缺省 50，范围 1..=100。
fn parse_archive_objects_limit(pairs: &[(String, String)]) -> Result<usize, String> {
    let Some(raw) = single_archive_query_value(pairs, "limit")? else {
        return Ok(DEFAULT_ARCHIVE_OBJECT_LIMIT);
    };
    let limit: usize = raw.parse().map_err(|_| "limit 必须是正整数".to_string())?;
    if !(1..=MAX_ARCHIVE_OBJECT_LIMIT).contains(&limit) {
        return Err(format!("limit 必须在 1–{MAX_ARCHIVE_OBJECT_LIMIT} 之间"));
    }
    Ok(limit)
}

/// 解析排他游标 `before_id`：必须是正整数。
fn parse_archive_before_id(pairs: &[(String, String)]) -> Result<Option<i64>, String> {
    let Some(raw) = single_archive_query_value(pairs, "before_id")? else {
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

/// 路径 id 只接受 1..=18 位 ASCII 十进制数字；拒绝 `+` / `-` / 空白 / 科学计数法。
fn parse_archive_object_id(raw: &str) -> Result<i64, ApiError> {
    if raw.is_empty() || raw.len() > 18 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ApiError::bad_request("归档对象 id 必须是正整数"));
    }
    let id: i64 = raw
        .parse()
        .map_err(|_| ApiError::bad_request("归档对象 id 必须是正整数"))?;
    if id <= 0 {
        return Err(ApiError::bad_request("归档对象 id 必须是正整数"));
    }
    Ok(id)
}

/// `GET /api/v1/archive/objects/{id}/download`：从冷存储读取对象并作为附件返回。
///
/// 只有 `uploaded` / `local_deleted` 可下载；不存在 404，状态未就绪 409
/// `archive_not_ready`；对象超过 64 MiB 下载上限 413 `archive_too_large`；
/// 后端失败 / 完整性校验失败统一 502 `archive_unavailable`，不回显后端 URL /
/// 凭据 / 响应正文。整个读取过程持有一个下载许可，最多并发一份对象内存。
async fn archive_object_download(
    State(state): State<AppState>,
    Extension(principal): Extension<AuthPrincipal>,
    Path(raw_id): Path<String>,
) -> Result<Response, ApiError> {
    let id = parse_archive_object_id(&raw_id)?;

    // 先占主体槽（同一主体最多一个请求持有 / 等待），再做数据库与后端工作：
    // 同一主体第二个请求立即 429，不能靠多条连接在数据库 / 全局 permit 前排队。
    let principal_slot =
        acquire_archive_principal_slot(&state.archive_download_principal_slots, &principal.name)?;

    let storage = state.storage.clone();
    let object = tokio::task::spawn_blocking(move || storage.get_archive_object(id))
        .await
        .map_err(ApiError::from)?
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::not_found("归档对象不存在"))?;
    if !matches!(
        object.status,
        ArchiveStatus::Uploaded | ArchiveStatus::LocalDeleted
    ) {
        return Err(ApiError::conflict(
            "archive_not_ready",
            "归档对象尚未上传完成，暂不可下载",
        ));
    }
    // KI-31：下载硬上限固定 64 MiB，与 `archive.max_object_bytes`（worker 分片）
    // 解耦。超限在占全局 permit / build_store / HEAD / GET 之前就拒绝，
    // 大对象完全不触碰后端、不占下载许可。
    if object.bytes > MAX_ARCHIVE_DOWNLOAD_BYTES {
        return Err(archive_too_large());
    }

    // 主体槽拿到后再按 Tokio FIFO 等待全局 permit，不同主体之间公平轮转；
    // 等待全局 permit 时请求被取消，主体槽随 future drop 释放，不会留下占位。
    let global_slot = state
        .archive_download_slots
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| archive_unavailable())?;
    let permits = ArchiveDownloadPermits {
        _principal: principal_slot,
        _global: global_slot,
    };

    let store = archive::build_store(&state.cfg.archive).map_err(|_| archive_unavailable())?;
    archive_download_response(
        &object,
        store.as_ref(),
        permits,
        state.archive_download_send_timeout,
    )
    .await
}

/// 固定 429：已有同一主体的归档下载，或主体槽已达上限；不排队，立即重试。
fn archive_busy() -> ApiError {
    ApiError::busy("archive_busy", "归档下载正忙，请稍后重试")
}

/// 取得某个认证主体的下载槽；同一主体已有请求时立即 429。
fn acquire_archive_principal_slot(
    slots: &StdMutex<HashMap<String, Arc<Semaphore>>>,
    principal: &str,
) -> Result<OwnedSemaphorePermit, ApiError> {
    let semaphore = {
        let mut slots = slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slots.len() >= MAX_ARCHIVE_DOWNLOAD_PRINCIPALS {
            // 只清理“map 外无引用且许可可用”的槽；还有请求持有 / 等待时保留。
            slots.retain(|_, semaphore| {
                semaphore.available_permits() == 0 || Arc::strong_count(semaphore) > 1
            });
            if slots.len() >= MAX_ARCHIVE_DOWNLOAD_PRINCIPALS {
                return Err(archive_busy());
            }
        }
        Arc::clone(
            slots
                .entry(principal.to_string())
                .or_insert_with(|| Arc::new(Semaphore::new(1))),
        )
    };
    // 主体槽不排队：同一主体的第二个请求立即 429。
    semaphore.try_acquire_owned().map_err(|_| archive_busy())
}

/// 固定 502：下载后端不可用；不携带后端细节。
fn archive_unavailable() -> ApiError {
    ApiError::bad_gateway("archive_unavailable", "归档对象下载失败")
}

/// 固定 413：对象超过 64 MiB 下载上限；在读取 body 之前拒绝。
fn archive_too_large() -> ApiError {
    ApiError::too_large("archive_too_large", "归档对象超过 64 MiB 下载上限")
}

/// 从冷存储读取对象并构造下载响应。
///
/// 先检查数据库记录与 `HEAD` 大小，再 `GET`；对象超过固定
/// [`MAX_ARCHIVE_DOWNLOAD_BYTES`]（64 MiB）直接 413，避免异常对象一次性占满
/// 内存。`archive.max_object_bytes` 只控制 worker 分片，不参与下载上限（KI-31）。
/// 读取后校验长度与 SHA-256 必须与数据库一致，否则固定 502。
/// 响应头只由服务端构造：
/// - `Content-Type: application/gzip`；
/// - `Content-Disposition: attachment; filename="rustboard-<yyyyMMdd>-part-NNNNN.csv.gz"`；
/// - `Content-Length` 与 `Cache-Control: private, no-store`。
async fn archive_download_response(
    object: &ArchiveObject,
    store: &dyn ColdStore,
    permits: ArchiveDownloadPermits,
    send_timeout: Duration,
) -> Result<Response, ApiError> {
    archive_download_response_with_limit(
        object,
        store,
        MAX_ARCHIVE_DOWNLOAD_BYTES,
        permits,
        send_timeout,
    )
    .await
}

/// 带可调上限 / 发送期限的下载响应实现；生产上限固定为
/// [`MAX_ARCHIVE_DOWNLOAD_BYTES`]，发送期限固定
/// [`ARCHIVE_DOWNLOAD_SEND_TIMEOUT`]，测试用小值覆盖边界。
///
/// 成功时把主体槽与全局 permit 移入 [`ArchiveDownloadBody`]，由 body 生命周期
/// 持有；任何错误返回都会在这里 drop，不会泄漏。
async fn archive_download_response_with_limit(
    object: &ArchiveObject,
    store: &dyn ColdStore,
    limit: u64,
    permits: ArchiveDownloadPermits,
    send_timeout: Duration,
) -> Result<Response, ApiError> {
    // 先看数据库记录：超限完全不触碰后端，避免把异常对象读进内存。
    if object.bytes > limit {
        return Err(archive_too_large());
    }
    let filename =
        archive::download_filename(&object.object_key).ok_or_else(archive_unavailable)?;

    let meta = store
        .head(&object.object_key)
        .await
        .map_err(|_| archive_unavailable())?
        .ok_or_else(archive_unavailable)?;
    if meta.size > limit {
        return Err(archive_too_large());
    }
    let data = store
        .get(&object.object_key)
        .await
        .map_err(|_| archive_unavailable())?;
    // 后端可能撒谎：HEAD / 数据库都小、实际 body 超大时仍拒绝（此时已分配，
    // 但不会再返回给客户端；正常情况下 S3 / WebDAV 的 get 自身有 1 GiB 防线）。
    if data.len() as u64 > limit {
        return Err(archive_too_large());
    }
    // 短读 / 对象被替换：长度或 SHA-256 必须与上传时记录一致。
    if data.len() as u64 != object.bytes || sha256_hex(&data) != object.sha256 {
        return Err(archive_unavailable());
    }

    let disposition = HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
        .map_err(|_| archive_unavailable())?;
    let length =
        HeaderValue::from_str(&data.len().to_string()).map_err(|_| archive_unavailable())?;
    let body = ArchiveDownloadBody::new(Bytes::from(data), permits, send_timeout);
    let mut response = Response::new(Body::new(body));
    *response.status_mut() = StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/gzip"),
    );
    headers.insert(header::CONTENT_DISPOSITION, disposition);
    headers.insert(header::CONTENT_LENGTH, length);
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

/// 下载 body 的分块大小；body 被 hyper 读完之前一直持有下载许可。
///
/// 读完最后一块后 body 才可能被 drop，此时最多只剩最后一块（64 KiB）在传输，
/// 不会出现多个 64 MiB 对象同时驻留内存。
const ARCHIVE_DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;

/// body 被发送期限中止后，后续 poll 返回的固定错误。
const ARCHIVE_DOWNLOAD_TIMEOUT_ERROR: &str = "归档下载发送超时";

/// 下载持有的两层许可：认证主体槽 + 全局 FIFO 槽。
///
/// 字段只用于 Drop 释放，故以下划线开头；body 同时持有两者，释放顺序由
/// [`release_archive_download_resources`] 保证 data 先于 permits。
struct ArchiveDownloadPermits {
    _principal: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

/// body 与后台定时任务共享的状态。
struct DownloadBodyState {
    /// 待发送对象；期限到期 / body drop 后置空并释放 64 MiB。
    data: Option<Bytes>,
    offset: usize,
    /// 期限到期标志；后续 poll 返回固定错误。
    expired: bool,
    /// 下载许可（主体槽 + 全局槽）；期限到期 / body drop 时释放。
    permits: Option<ArchiveDownloadPermits>,
}

/// 持有下载许可与发送期限的归档响应 body。
///
/// `ColdStore::get` 返回完整 `Vec<u8>`，转换为 `Bytes` 后由共享状态持有；
/// 后台定时任务到期会清空 data 并释放两层许可（即使客户端完全不读 body）。
/// body 被 drop 时 abort 定时任务，并立即释放 data / permits。
struct ArchiveDownloadBody {
    state: Arc<StdMutex<DownloadBodyState>>,
    deadline: Option<tokio::task::JoinHandle<()>>,
}

/// 释放下载资源：**顺序固定先 data 后 permits**。
///
/// 若先归还许可，下一请求可能在旧 64 MiB `Bytes` 真正释放前获得许可，
/// 使内存峰值变成 2×64 MiB。定时任务与 body drop 都必须走这里。
fn release_archive_download_resources(
    data: Option<Bytes>,
    permits: Option<ArchiveDownloadPermits>,
) {
    // 顺序不能交换：data 的析构必须在许可归还之前完成。
    drop(data);
    drop(permits);
}

impl ArchiveDownloadBody {
    fn new(data: Bytes, permits: ArchiveDownloadPermits, timeout: Duration) -> Self {
        let state = Arc::new(StdMutex::new(DownloadBodyState {
            data: Some(data),
            offset: 0,
            expired: false,
            permits: Some(permits),
        }));
        let timer_state = Arc::clone(&state);
        let deadline = tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let (data, permits) = {
                let mut state = timer_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if state.expired {
                    return;
                }
                state.expired = true;
                (state.data.take(), state.permits.take())
            };
            // 与 body drop 使用同一释放顺序：先 64 MiB 数据，再两层许可。
            release_archive_download_resources(data, permits);
            tracing::warn!(
                timeout_ms = timeout.as_millis() as u64,
                "归档下载发送超时，已释放对象内存与下载许可"
            );
        });
        Self {
            state,
            deadline: Some(deadline),
        }
    }

    /// 测试用：观察 data / permits / expired 状态。
    #[cfg(test)]
    fn shared_state(&self) -> Arc<StdMutex<DownloadBodyState>> {
        Arc::clone(&self.state)
    }
}

impl Drop for ArchiveDownloadBody {
    fn drop(&mut self) {
        // 先取消定时任务，避免 body 结束后定时任务仍持有 Arc 并稍后误释放。
        if let Some(deadline) = self.deadline.take() {
            deadline.abort();
        }
        let (data, permits) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (state.data.take(), state.permits.take())
        };
        // 与定时任务一致：先释放对象数据，再归还两层许可。
        release_archive_download_resources(data, permits);
    }
}

impl HttpBody for ArchiveDownloadBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<BodyFrame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let mut state = this
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.expired {
            return Poll::Ready(Some(Err(std::io::Error::other(
                ARCHIVE_DOWNLOAD_TIMEOUT_ERROR,
            ))));
        }
        let Some(data) = state.data.as_ref() else {
            return Poll::Ready(None);
        };
        if state.offset >= data.len() {
            return Poll::Ready(None);
        }
        let end = state
            .offset
            .saturating_add(ARCHIVE_DOWNLOAD_CHUNK_BYTES)
            .min(data.len());
        // 复制到独立 Bytes：hyper 若在 permit 释放后仍缓冲某些 frame，也不会
        // 通过 slice 的引用计数把整个 64 MiB 对象继续留在内存里。
        let chunk = Bytes::copy_from_slice(&data[state.offset..end]);
        state.offset = end;
        Poll::Ready(Some(Ok(BodyFrame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // 期限到期后仍返回 false：让 hyper 继续 poll，读到固定错误。
        !state.expired
            && state
                .data
                .as_ref()
                .is_some_and(|data| state.offset >= data.len())
    }

    fn size_hint(&self) -> SizeHint {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut hint = SizeHint::default();
        if let Some(data) = state.data.as_ref() {
            if !state.expired {
                hint.set_exact((data.len() - state.offset) as u64);
            }
        }
        hint
    }
}

/// 管理 API 全部响应禁止缓存（含 token 的 401 与实时指标）。
///
/// 下载接口显式声明 `private, no-store`，这里保留该值；其余响应统一强制
/// `no-store`，避免误把敏感响应放进缓存。
async fn no_store(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let explicit = response
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|value| value.to_str().ok());
    if explicit != Some("private, no-store") {
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
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

/// KI-28：连接拒绝日志采样窗口（60s）。
const REJECT_LOG_WINDOW_MS: i64 = 60_000;
/// KI-28：拒绝日志采样器最多跟踪的来源 IP 数。
const REJECT_LOG_TABLE_CAPACITY: usize = 4096;

/// 单个来源 IP 的拒绝计数窗口。
#[derive(Debug, Clone, Copy, Default)]
struct RejectWindow {
    started_at: i64,
    count: u64,
}

/// KI-28：按来源 IP 采样连接拒绝日志。
///
/// 同一来源 IP 每 60s 窗口内只有首条拒绝记 WARN，其余记 DEBUG；不同 IP
/// 独立计数。表有 4096 个 IP 的硬上限：插入新来源前先清理过期窗口，仍然
/// 满时不再插入（该来源按窗口内后续拒绝记 DEBUG），因此大量来源 IP 无法
/// 放大内存或 WARN 日志。`now_ms` 可注入，单测可精确覆盖窗口边界。
struct RejectLogSampler {
    windows: HashMap<IpAddr, RejectWindow>,
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
}

/// 一次拒绝的采样结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RejectLogSample {
    /// 本窗口内该来源的累计拒绝次数。
    rejected: u64,
    /// 是否本窗口首条拒绝（只有它记 WARN）。
    first_in_window: bool,
}

impl RejectLogSampler {
    fn new() -> Self {
        Self::with_clock(Arc::new(rustboard_common::util::now_ms))
    }

    fn with_clock(now_ms: Arc<dyn Fn() -> i64 + Send + Sync>) -> Self {
        Self {
            windows: HashMap::new(),
            now_ms,
        }
    }

    /// 记录一次拒绝并返回本窗口计数；不持有其它锁。
    fn record(&mut self, ip: IpAddr) -> RejectLogSample {
        let now = (self.now_ms)();
        if let Some(window) = self.windows.get_mut(&ip) {
            if now.saturating_sub(window.started_at) >= REJECT_LOG_WINDOW_MS {
                window.started_at = now;
                window.count = 1;
                return RejectLogSample {
                    rejected: 1,
                    first_in_window: true,
                };
            }
            window.count = window.count.saturating_add(1);
            return RejectLogSample {
                rejected: window.count,
                first_in_window: false,
            };
        }

        // 插入新来源前清理过期窗口；仍然满则不再增长采样表。
        self.windows
            .retain(|_, window| now.saturating_sub(window.started_at) < REJECT_LOG_WINDOW_MS);
        if self.windows.len() >= REJECT_LOG_TABLE_CAPACITY {
            return RejectLogSample {
                rejected: 1,
                first_in_window: false,
            };
        }
        self.windows.insert(
            ip,
            RejectWindow {
                started_at: now,
                count: 1,
            },
        );
        RejectLogSample {
            rejected: 1,
            first_in_window: true,
        }
    }

    #[cfg(test)]
    fn tracked_ips(&self) -> usize {
        self.windows.len()
    }
}

/// KI-28：按采样结果输出一条拒绝日志；窗口首条 WARN，其余 DEBUG。
///
/// 字段只含来源 IP、本窗口拒绝次数与窗口秒数，不带端口 / 证书。
fn log_connection_reject(
    sampler: &mut RejectLogSampler,
    ip: IpAddr,
    max_connections_per_ip: usize,
    message: &'static str,
) {
    let sample = sampler.record(ip);
    if sample.first_in_window {
        tracing::warn!(
            ip = %ip,
            rejected = sample.rejected,
            window_secs = REJECT_LOG_WINDOW_MS / 1_000,
            max_connections_per_ip,
            "{}",
            message
        );
    } else {
        tracing::debug!(
            ip = %ip,
            rejected = sample.rejected,
            window_secs = REJECT_LOG_WINDOW_MS / 1_000,
            max_connections_per_ip,
            "{}",
            message
        );
    }
}

/// H2：尝试占用一个连接许可；返回 None 表示已达上限，调用方应关闭 TCP。
fn try_acquire_connection(permits: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    permits.clone().try_acquire_owned().ok()
}

/// TLS accept 层取得的连接许可，随连接 / 会话生命周期持有（KI-27）。
///
/// 两个字段都用 `Arc` 包裹，使 guard 可以廉价 clone 到请求扩展；只有最后一个
/// clone 被 drop 时，底层 `OwnedSemaphorePermit` / `ConnectionPermit` 才真正
/// 归还全局槽位与 per-IP 计数。
///
/// 字段顺序决定 drop 顺序（Rust 按声明顺序释放）。这里让 `_per_ip` 先归还：
/// `serve_tls` 先取全局许可、再取 per-IP 许可，先释放 per-IP 可以避免同一 IP
/// 立即重连时出现「全局槽刚空、per-IP 计数尚未归还」的瞬时假拒绝。只是固定
/// 释放顺序，不改变许可数量与持有语义。
///
/// 生命周期：
/// - 普通 HTTP：连接层由 `service_fn` 闭包中的基础 guard 持有到
///   `serve_connection` 返回（连接结束）；请求扩展 clone 只活到响应结束，
///   不会因此提前归还连接许可；
/// - WebSocket：`agent_ws` 在升级响应前取出 clone 并移入 `on_upgrade` future；
///   `serve_connection` 提前返回后该 future 仍持有到 `dispatch` 返回（会话结束）。
#[derive(Clone)]
struct ConnectionGuards {
    _per_ip: Arc<ConnectionPermit>,
    _global: Arc<OwnedSemaphorePermit>,
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
    // KI-28：每来源拒绝日志采样；accept 循环单任务访问，无需加锁。
    let mut reject_sampler = RejectLogSampler::new();
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
                log_connection_reject(
                    &mut reject_sampler,
                    peer.ip(),
                    max_connections_per_ip,
                    "来源 IP 并发连接已达上限，直接关闭 TCP",
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
            // A1 / KI-27：全局信号量许可与 per-IP 许可都包进同一个 guard。
            // 普通 HTTP 连接由 service_fn 闭包的基础 guard 持有到
            // `serve_connection` 返回（连接结束）；请求扩展 clone 随响应释放，
            // 但不会提前归还许可。WebSocket 升级由 `agent_ws` 把 clone 移入
            // upgrade future，持有到会话结束。
            let guards = ConnectionGuards {
                _per_ip: Arc::new(connection),
                _global: Arc::new(permit),
            };
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
                // A1 / KI-27：每个请求扩展都带上连接 guard，供 `agent_ws`
                // 在升级时取走。请求扩展 clone 随响应结束释放；连接许可本身
                // 由 `service_fn` 闭包的基础 guard 持有到 `serve_connection`
                // 返回（连接结束），WS 则从 upgrade future 一直持有到会话结束。
                req.extensions_mut().insert(guards.clone());
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
    /// 实际生效的桶宽（可能被选层粒度提升，见 `tier`）。
    bucket_ms: i64,
    /// 本次查询选中的数据层：`"raw"` / `"1m"` / `"1h"`。
    ///
    /// 新增字段，旧客户端忽略即可；既有 `bucket_ms` / `series` 结构不变。
    tier: String,
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
    let now = now_ms();
    let retention = SeriesRetention::from_config(&state.cfg, now);
    let parsed = parse_series_query(raw.as_deref(), retention).map_err(ApiError::bad_request)?;
    let bucket_ms = parsed.bucket_ms;
    let tier = parsed.tier;
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
    //
    // 空结果回退：backfill 未追平 / 保留期刚删过时，所选层可能暂时为空；
    // 逐层向更粗层重试直到 1h（1h 已是最粗层，最多 2 次），每次按更粗层
    // 粒度重新夹 bucket。只有回退层查到数据才更新回显的 tier/bucket；所有层
    // 都为空时保留初始选层结果，避免把「确实无数据」误报成退了层。
    let rows = tokio::task::spawn_blocking(
        move || -> Result<Option<(Vec<SeriesRow>, SampleTier, i64)>> {
            if state.storage.get_agent(&query.agent_id)?.is_none() {
                return Ok(None);
            }
            let mut actual_tier = tier;
            let mut actual_bucket_ms = bucket_ms;
            let mut rows =
                state
                    .storage
                    .query_series_tiered(&query, actual_bucket_ms, actual_tier)?;
            let mut probe_tier = tier;
            while rows.is_empty() {
                let Some(coarser) = probe_tier.next_coarser() else {
                    break;
                };
                probe_tier = coarser;
                let probe_bucket_ms = bucket_ms.max(coarser.granularity_ms());
                rows = state
                    .storage
                    .query_series_tiered(&query, probe_bucket_ms, probe_tier)?;
                if !rows.is_empty() {
                    actual_tier = probe_tier;
                    actual_bucket_ms = probe_bucket_ms;
                }
            }
            Ok(Some((rows, actual_tier, actual_bucket_ms)))
        },
    )
    .await
    .map_err(ApiError::from)??;
    let Some((rows, actual_tier, actual_bucket_ms)) = rows else {
        return Err(ApiError::not_found("agent 不存在"));
    };
    let response = build_series_response(actual_bucket_ms, actual_tier, rows)
        .map_err(ApiError::bad_request)?;
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
    /// 实际生效的桶宽：显式值或自动档位，且不小于所选层的粒度。
    bucket_ms: i64,
    /// 按跨度与保留期选中的数据层。
    tier: SampleTier,
}

/// 各层保留期换算出的可用下界（Unix 毫秒）。
///
/// `None` 表示该层 `retention_*_days = 0`（不自动删除，永久可用）。查询起点
/// 早于某层下界时，该层数据可能已被 retention 任务删除，选层要退到更粗的层。
#[derive(Debug, Clone, Copy)]
struct SeriesRetention {
    raw_since: Option<i64>,
    one_minute_since: Option<i64>,
}

impl SeriesRetention {
    fn from_config(cfg: &HubConfig, now: i64) -> Self {
        let since = |days: u32| -> Option<i64> {
            (days != 0).then(|| now.saturating_sub(i64::from(days) * MS_PER_DAY))
        };
        Self {
            raw_since: since(cfg.retention_raw_days),
            one_minute_since: since(cfg.retention_1m_days),
        }
    }

    /// 测试用：不限制各层，只验证跨度规则。
    #[cfg(test)]
    fn unlimited() -> Self {
        Self {
            raw_since: None,
            one_minute_since: None,
        }
    }

    /// `from` 起点之后的数据是否可能仍在 `tier` 层。
    ///
    /// 1h 是最粗层，没有更粗层可退，始终按 1h 查询（超出保留期自然为空）。
    fn available(self, tier: SampleTier, from: i64) -> bool {
        let since = match tier {
            SampleTier::Raw => self.raw_since,
            SampleTier::OneMinute => self.one_minute_since,
            SampleTier::OneHour => return true,
        };
        match since {
            None => true,
            Some(since) => from >= since,
        }
    }
}

/// `series` 参数校验与自动 bucket 选择（全部为纯函数，便于单测边界）。
///
/// `retention` 由调用方按当前时间从 [`HubConfig`] 换算：跨度先给出候选层，
/// 若查询起点早于该层保留下界（数据可能已删），自动退到更粗的层。
fn parse_series_query(
    raw: Option<&str>,
    retention: SeriesRetention,
) -> std::result::Result<ParsedSeriesQuery, String> {
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
        return Err("时间跨度不能超过 730 天".to_string());
    }

    let tier = series_tier_for_query(span_ms, from, retention);
    // 显式 bucket 过小时提升到层粒度而不是返回 400：旧面板/客户端的长跨度
    // 请求仍然可用，响应 `bucket_ms` 回显实际值。自动档位同样夹到层粒度。
    let tier_granularity = tier.granularity_ms();
    let bucket_ms = match bucket_ms {
        Some(bucket) => bucket.max(tier_granularity),
        None => auto_bucket_ms(span_ms).max(tier_granularity),
    };
    Ok(ParsedSeriesQuery {
        metrics,
        from,
        to,
        bucket_ms,
        tier,
    })
}

/// 按跨度选层：≤6h raw、≤7d 1m、更长 1h（方案 §5.2）。
fn series_tier_for_span(span_ms: i64) -> SampleTier {
    if span_ms <= SERIES_RAW_MAX_SPAN_MS {
        SampleTier::Raw
    } else if span_ms <= SERIES_ONE_MINUTE_MAX_SPAN_MS {
        SampleTier::OneMinute
    } else {
        SampleTier::OneHour
    }
}

/// 在跨度候选层的基础上，根据保留期下界退到更粗的可用层。
///
/// 例：跨度 1h（候选 raw）但查询起点在 10 天前（raw 只保留 7 天）→ 1m；
/// 跨度 1d（候选 1m）但起点在 100 天前（1m 只保留 90 天）→ 1h。
fn series_tier_for_query(span_ms: i64, from: i64, retention: SeriesRetention) -> SampleTier {
    match series_tier_for_span(span_ms) {
        SampleTier::Raw if retention.available(SampleTier::Raw, from) => SampleTier::Raw,
        SampleTier::Raw | SampleTier::OneMinute
            if retention.available(SampleTier::OneMinute, from) =>
        {
            SampleTier::OneMinute
        }
        _ => SampleTier::OneHour,
    }
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
        // 730 天上限内 12h 档位必然命中；取最大档兜底，避免返回 0。
        .unwrap_or(86_400_000)
}

/// 把聚合行按 `(metric, labels)` 组装成前端契约；同时兜住序列数与点数上限。
fn build_series_response(
    bucket_ms: i64,
    tier: SampleTier,
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
    Ok(SeriesResponse {
        bucket_ms,
        tier: tier.as_str().to_string(),
        series,
    })
}

#[derive(Debug)]
enum ApiError {
    Internal(anyhow::Error),
    BadRequest(String),
    /// 请求体字段验证失败且需要稳定错误码（例如引用不存在的通知渠道）。
    BadRequestCode {
        code: &'static str,
        message: String,
    },
    NotFound(String),
    /// 已认证但操作被业务规则拒绝（例如删除内置告警规则）：403 + 固定错误码。
    Forbidden {
        code: &'static str,
        message: String,
    },
    /// 与既有数据冲突（重名 / 达到上限）：409 + 固定错误码。
    Conflict {
        code: &'static str,
        message: String,
    },
    PayloadTooLarge,
    /// 资源超过服务端可承受上限（例如归档下载 > 64 MiB）：413 + 固定错误码。
    TooLarge {
        code: &'static str,
        message: String,
    },
    /// 上游依赖失败（例如渠道测试发送失败）：502 + 固定错误码，不回显上游内容。
    BadGateway {
        code: &'static str,
        message: String,
    },
    /// 并发资源忙（例如归档下载已有请求）：429 + 固定错误码 + Retry-After。
    Busy {
        code: &'static str,
        message: String,
    },
    /// 查询结果超过存储层硬上限：这是客户端可调整的参数问题，不是服务端错误。
    QueryTooLarge,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    fn bad_request_code(code: &'static str, message: impl Into<String>) -> Self {
        Self::BadRequestCode {
            code,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::Forbidden {
            code,
            message: message.into(),
        }
    }

    fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::Conflict {
            code,
            message: message.into(),
        }
    }

    fn bad_gateway(code: &'static str, message: impl Into<String>) -> Self {
        Self::BadGateway {
            code,
            message: message.into(),
        }
    }

    fn too_large(code: &'static str, message: impl Into<String>) -> Self {
        Self::TooLarge {
            code,
            message: message.into(),
        }
    }

    fn busy(code: &'static str, message: impl Into<String>) -> Self {
        Self::Busy {
            code,
            message: message.into(),
        }
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
            ApiError::BadRequestCode { code, message } => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": code, "message": message })),
            )
                .into_response(),
            ApiError::NotFound(message) => (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({ "error": "not_found", "message": message })),
            )
                .into_response(),
            ApiError::Forbidden { code, message } => (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": code, "message": message })),
            )
                .into_response(),
            ApiError::Conflict { code, message } => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({ "error": code, "message": message })),
            )
                .into_response(),
            ApiError::PayloadTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "error": "payload_too_large" })),
            )
                .into_response(),
            ApiError::TooLarge { code, message } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "error": code, "message": message })),
            )
                .into_response(),
            ApiError::BadGateway { code, message } => (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": code, "message": message })),
            )
                .into_response(),
            ApiError::Busy { code, message } => {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({ "error": code, "message": message })),
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                response
            }
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
    Extension(guards): Extension<ConnectionGuards>,
    State(state): State<AppState>,
) -> axum::response::Response {
    // KI-27：连接许可由 TLS 层创建，经请求扩展转交到这里。请求扩展 clone 会
    // 随升级响应释放，连接层的基础 guard 也只到 `serve_connection` 返回，因此
    // 必须把取出的 guard 移入 upgrade future、持有到 `dispatch` 返回，才能覆盖
    // 整个 WebSocket 会话。缺失扩展时 axum 的 `Extension` 提取器返回 500
    //（fail-closed），绝不静默创建无许可会话。
    ws.max_message_size(MAX_WS_MESSAGE_SIZE)
        .max_frame_size(MAX_WS_FRAME_SIZE)
        .on_upgrade(move |socket| async move {
            // 全局许可与 per-IP 许可覆盖整个 WebSocket 会话。
            let _guards = guards;
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
    let token_hash = tls::sha256_hex(&req.token);
    let Some(token_name) = storage_blocking(state.storage.clone(), move |storage| {
        storage.consume_enroll_token(&token_hash, now)
    })
    .await?
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
    let secret_hash = tls::sha256_hex(&secret);
    let record = AgentRecord {
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
    };
    let agent_id_for_db = agent_id.clone();
    storage_blocking(state.storage.clone(), move |storage| {
        storage.set_agent_secret(&agent_id_for_db, &secret_hash, now)?;
        storage.upsert_agent(&record)
    })
    .await?;

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

    let revoked = storage_blocking(state.storage.clone(), {
        let agent = agent_id.clone();
        move |storage| storage.is_revoked(&agent)
    })
    .await?;
    if revoked {
        send_frame(&mut socket, &problem(codes::REVOKED, "该 agent 已被吊销")).await?;
        bail!("已吊销的 agent 尝试连接: {agent_id}");
    }

    let secret_hash = tls::sha256_hex(&hello.secret);
    let secret_ok = storage_blocking(state.storage.clone(), {
        let agent = agent_id.clone();
        move |storage| storage.verify_agent_secret(&agent, &secret_hash)
    })
    .await?;
    if !secret_ok {
        send_frame(&mut socket, &problem(codes::BAD_TOKEN, "agent secret 无效")).await?;
        bail!("agent secret 校验失败: {agent_id}");
    }

    let now = now_ms();
    let existing = storage_blocking(state.storage.clone(), {
        let agent = agent_id.clone();
        move |storage| storage.get_agent(&agent)
    })
    .await?;
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
    // 入库错误 / 任务失败）都由 `cleanup` 统一执行状态清理。
    // `register` 先 await per-agent cleanup gate：旧连接的清理（PG is_revoked +
    // set_status）在 blocking 线程上执行，worker 只 await、不抢 slot 锁；清理结束
    // 后才插入新连接，因此下面的 `upsert_agent(online)` 一定晚于旧 offline 落库。
    let handle = state.sessions.register(&agent_id).await;
    let mut cleanup = SessionCleanup::new(
        state.storage.clone(),
        state.sessions.clone(),
        agent_id.clone(),
        handle.conn_id,
    );

    // 会话主体放进 async 块：无论从哪条路径退出（含 `?`），都能在块结束后
    // 先 await 异步清理，再返回结果；Drop 只是任务被取消时的兜底。
    let outcome: Result<()> = async move {
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

        storage_blocking(state.storage.clone(), move |storage| {
            storage.upsert_agent(&record)
        })
        .await?;
        // M3 + KI-24：能力先登记到本条连接；只有它仍是该 agent 的最新连接时才写库。
        // 未知能力在入库前就被忽略，数据库里只会有本版本认识的四个字符串。
        // 旧连接晚到的 Hello 只更新自己的记录，返回 false 且不覆盖新连接的能力。
        let capabilities = control::sanitize_agent_capabilities(&hello.capabilities);
        let persisted = {
            let sessions = state.sessions.clone();
            let storage = state.storage.clone();
            let agent = agent_id.clone();
            let conn_id = handle.conn_id;
            tokio::task::spawn_blocking(move || {
                sessions.set_capabilities(&agent, conn_id, capabilities, |capabilities| {
                    storage.upsert_agent_control(&agent, capabilities, now)?;
                    if !capabilities.is_empty() {
                        tracing::info!(
                            agent = %agent,
                            capabilities = capabilities.len(),
                            "agent 控制能力已登记"
                        );
                    }
                    Ok(())
                })
            })
            .await
            .context("登记 agent 控制能力失败")??
        };
        if !persisted {
            tracing::debug!(
                agent = %agent_id,
                conn_id = handle.conn_id,
                "旧连接晚到的 Hello 能力仅登记到会话，不写库"
            );
        }
        // upsert_agent 会把状态写回 online；若吊销恰好发生在握手期间，立即恢复 revoked。
        let revoked = storage_blocking(state.storage.clone(), {
            let agent = agent_id.clone();
            move |storage| {
                let revoked = storage.is_revoked(&agent)?;
                if revoked {
                    storage.set_status(&agent, "revoked", now_ms())?;
                }
                Ok(revoked)
            }
        })
        .await?;
        if revoked {
            send_frame(&mut socket, &problem(codes::REVOKED, "该 agent 已被吊销")).await?;
            bail!("握手期间 agent 被吊销: {agent_id}");
        }
        tracing::info!(agent = %agent_id, host = %hello.hostname, "agent 已连接");

        let welcome = Frame::Welcome(Welcome {
            agent_id: agent_id.clone(),
            server_version: VERSION.to_string(),
            protocol: PROTOCOL_VERSION,
            sample_interval_ms: sample_interval_for_session(&state, &agent_id).await,
            server_time: now,
        });
        send_frame(&mut socket, &welcome).await?;

        let mut shutdown = handle.shutdown;
        let mut watch_shutdown = true;
        // 会话内只记录最近一次成功时间；能否续签由每 agent 冷却窗口决定。
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
    .await;
    cleanup.finish_async().await;
    outcome
}

/// Welcome 下发的有效采样间隔：agent 显式配置优先，读失败/越界值回退配置默认值。
///
/// 兜底值也 clamp 到合法范围：即使配置层校验被绕过，Welcome 也绝不发非法值。
/// 这是同步入口，只供单测 / 非 async 上下文使用；async 会话必须走
/// [`sample_interval_for_session`]。
#[cfg(test)]
fn sample_interval_for(state: &AppState, agent_id: &str) -> u64 {
    let fallback = state
        .cfg
        .sample_interval_ms
        .clamp(MIN_SAMPLE_INTERVAL_MS, MAX_SAMPLE_INTERVAL_MS);
    sample_interval_from_storage(&state.storage, agent_id, fallback)
}

/// async 会话入口：把 `get_sample_interval` 放到 blocking 线程，避免 PG panic。
async fn sample_interval_for_session(state: &AppState, agent_id: &str) -> u64 {
    let fallback = state
        .cfg
        .sample_interval_ms
        .clamp(MIN_SAMPLE_INTERVAL_MS, MAX_SAMPLE_INTERVAL_MS);
    let storage = state.storage.clone();
    let agent = agent_id.to_string();
    match storage_blocking(storage, move |storage| {
        Ok(sample_interval_from_storage(storage, &agent, fallback))
    })
    .await
    {
        Ok(ms) => ms,
        Err(err) => {
            tracing::warn!(
                agent = %agent_id,
                error = %err,
                "读取采样间隔任务失败，回退配置默认值"
            );
            fallback
        }
    }
}

/// 采样间隔读取的共用主体；调用方保证处于 blocking 上下文。
fn sample_interval_from_storage(storage: &StorageHandle, agent_id: &str, fallback: u64) -> u64 {
    match storage.get_sample_interval(agent_id) {
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
/// 只记录本会话最近一次成功的时间（Unix 毫秒，0 表示尚未成功），用于日志 /
/// 指标；准入门槛完全由 [`RenewGuard`] 的每 agent 冷却窗口与容量上限决定，
/// 因此同一会话在冷却结束后可以再次续签。
#[derive(Default)]
struct RenewState {
    last_success_ms: i64,
}

/// 客户端续签的冷却窗口：同一 agent 10 分钟内只允许一次尝试。
///
/// 冷却窗口同时约束「同会话高频重试」与「断开重连绕过会话状态」；正常轮换
/// （90 天证书、30 天阈值）远低于该频率，保留下来的只是防刷签名与内存上界。
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

            // 清理过期项后仍然满表：拒绝新身份，绝不淘汰仍在冷却窗口内的记录。
            // 否则攻击者可以用 ≥ 上限数量的新 agent_id 轮换，把任意身份的冷却
            // 记录挤掉，从而绕过 10 分钟限流。已在表中的身份仍可正常更新。
            if self.last_attempt_ms.len() >= RENEW_GUARD_MAX_ENTRIES
                && !self.last_attempt_ms.contains_key(agent_id)
            {
                tracing::warn!(
                    capacity = RENEW_GUARD_MAX_ENTRIES,
                    "续签冷却表已满，拒绝新身份的续签尝试"
                );
                return false;
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
/// 1. 全局冷却窗口 → 限流（记录尝试，**无效 CSR 也计入**）；
/// 2. CSR 长度上限（16 KiB，O(1)，不解析）；
/// 3. 读 CA 私钥 + 解析 CSR + 签发，全部在 `spawn_blocking` 里做。
///
/// 不再有「同会话只能成功一次」的永久拒绝：证书跨多个周期轮换时，只要冷却
/// 窗口已过就允许再次签发；成功后只更新 [`RenewState::last_success_ms`]。
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
                renew.last_success_ms = now_ms;
                // 日志只记身份、到期时间与上次成功时间：CSR / 证书内容一律不入日志。
                tracing::info!(
                    agent = %agent_id,
                    not_after = %tls::format_unix_utc(not_after),
                    last_success_ms = renew.last_success_ms,
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
                    // #50：入库前统一校验 sample.ts。超界整批 ACK 丢弃，不写
                    // samples、不改维护水位；只记审计计数与采样 WARN（不含值）。
                    if batch_timestamp_out_of_bounds(&batch, &state.cfg, now_ms()) {
                        note_timestamp_rejected_batch(agent_id, &batch);
                        send_frame(
                            socket,
                            &Frame::Ack {
                                epoch: batch.epoch,
                                seq: batch.seq,
                            },
                        )
                        .await?;
                        return Ok(MessageAction::Continue);
                    }

                    let batch_for_db = batch.clone();
                    let storage = state.storage.clone();
                    let result =
                        tokio::task::spawn_blocking(move || storage.insert_batch(&batch_for_db))
                            .await?;
                    match result {
                        Ok(IngestOutcome::Inserted { inserted }) => {
                            mark_seen(state, agent_id).await;
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
                            mark_seen(state, agent_id).await;
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
                        Ok(IngestOutcome::Rejected(reason)) => match reason {
                            RejectReason::Invalid => {
                                // NUL / NaN / Inf 等坏数据整批丢弃：ACK 让 agent 前进，
                                // 不关闭会话；否则一条坏批次会让该 agent 永久重连失败。
                                tracing::warn!(
                                    agent = %agent_id,
                                    epoch = batch.epoch,
                                    seq = batch.seq,
                                    ?reason,
                                    "批次数据非法，已丢弃"
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
                            // Revoked（以及未来新增的拒绝原因）保持吊销语义：
                            // 吊销检查与写入在同一个事务里，命中即整批回滚，绝不 ACK。
                            _ => {
                                tracing::warn!(
                                    agent = %agent_id,
                                    epoch = batch.epoch,
                                    seq = batch.seq,
                                    ?reason,
                                    "批次被拒绝，关闭会话"
                                );
                                reject_and_close(socket, codes::REVOKED, "该 agent 已被吊销").await;
                                return Ok(MessageAction::Close);
                            }
                        },
                        Err(err) => {
                            tracing::error!(agent = %agent_id, error = %err, "入库失败，关闭会话");
                            reject_and_close(socket, codes::INTERNAL, "入库失败").await;
                            return Ok(MessageAction::Close);
                        }
                    }
                }
                Frame::Ping { ts } => {
                    mark_seen(state, agent_id).await;
                    send_frame(socket, &Frame::Pong { ts }).await?;
                }
                Frame::Pong { .. } => {
                    mark_seen(state, agent_id).await;
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
                        mark_seen(state, agent_id).await;
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
            mark_seen(state, agent_id).await;
            send_with_timeout(socket, Message::Pong(payload)).await?;
        }
        Message::Pong(_) => {
            mark_seen(state, agent_id).await;
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
/// 同步存储调用必须在 blocking 线程执行（PG 在 tokio worker 上会 panic）。
async fn mark_seen(state: &AppState, agent_id: &str) {
    let storage = state.storage.clone();
    let agent = agent_id.to_string();
    match storage_blocking(storage, move |storage| storage.mark_seen(&agent, now_ms())).await {
        Ok(()) => {}
        Err(err) => tracing::warn!(agent = %agent_id, error = %err, "刷新 last_seen_at 失败"),
    }
}

/// 会话退出时的统一清理。
///
/// - 只有注册表里的当前连接才有资格改状态（旧连接不覆盖新连接）；
/// - 吊销状态优先级最高：命中吊销恢复为 `revoked`，否则置 `offline`；
/// - 「最后一条连接注销 + 状态写入」在注册表的 per-agent slot 锁内原子完成，
///   同一 agent 的新连接注册会被串行化，不会出现旧 offline 覆盖新 online。
struct SessionCleanup {
    storage: Arc<StorageHandle>,
    sessions: Arc<SessionRegistry>,
    agent_id: String,
    conn_id: u64,
    finished: bool,
}

impl SessionCleanup {
    fn new(
        storage: Arc<StorageHandle>,
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

    /// 注销本连接；最后一条连接写状态，最新连接断开时回退控制能力。
    ///
    /// 这是非 async 上下文（单测 / 普通线程）的同步入口；async 会话路径必须
    /// 用 [`Self::finish_async`]，不能让同步 PG 调用落在 tokio worker 上。
    #[cfg(test)]
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        finish_session_cleanup(
            self.storage.clone(),
            self.sessions.clone(),
            self.agent_id.clone(),
            self.conn_id,
        );
    }

    /// async 会话退出路径：把整段清理（含 slot 锁内的数据库写入）移入
    /// `spawn_blocking`，闭包返回前连接已归还。
    ///
    /// 不能只把单个查询包起来：`unregister_with_fallback` 的回调必须在 slot
    /// 锁内完成“查吊销 → 写 offline/revoked”，整段一起挪走才能保持
    /// 「旧 offline 一定早于新 online」的语义（见 `finish` 的说明）。
    async fn finish_async(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let storage = self.storage.clone();
        let sessions = self.sessions.clone();
        let agent_id = self.agent_id.clone();
        let conn_id = self.conn_id;
        match tokio::task::spawn_blocking(move || {
            finish_session_cleanup(storage, sessions, agent_id, conn_id);
        })
        .await
        {
            Ok(()) => {}
            Err(err) => tracing::warn!(
                agent = %self.agent_id,
                conn_id = self.conn_id,
                error = %err,
                "会话清理后台任务失败"
            ),
        }
    }
}

/// 会话清理主体：注销连接，并在 per-agent slot 锁内完成状态/能力写库。
///
/// 关键点：`unregister_with_fallback` 在 slot 锁内执行两个回调，而同一 agent 的
/// 新连接 `register` 也要拿这把锁。因此「查吊销 + 写 offline/revoked」以及
/// 「回退能力写库」都与「新连接注册」严格串行：回调先完成，新连接才插入，
/// 调用方随后写 online。旧 offline / 旧能力不可能落在新连接之后，也不需要再
/// 调用 `has_active` 二次检查（slot 已空且锁仍未释放，新连接插不进来）。
///
/// 两个回调都只做单行数据库写入；失败处理与日志全部移到 slot 锁外。
///
/// 进入 slot 锁前先拿 per-agent cleanup gate：`register` 在 async 侧 await 同一
/// 把 gate，因此清理的 PG 写入与「新连接注册 + 写 online」严格串行，而 tokio
/// worker 不会阻塞在 slot 的 std Mutex 上。本函数必须在 blocking 线程或非 async
/// 上下文执行（`blocking_lock`）。
fn finish_session_cleanup(
    storage: Arc<StorageHandle>,
    sessions: Arc<SessionRegistry>,
    agent_id: String,
    conn_id: u64,
) {
    // gate 的 guard 借用 slot；先保留 Arc 再取 guard，drop 顺序为 guard -> Arc。
    let cleanup_slot = sessions.cleanup_slot(&agent_id);
    let _gate = cleanup_slot
        .as_ref()
        .map(|slot| slot.acquire_cleanup_gate_blocking());
    let revoked_agent_id = agent_id.clone();
    let fallback_agent_id = agent_id.clone();
    let fallback_storage = storage.clone();
    // 回调内只记录结果，避免在临界区里打日志。
    let mut revoked_error: Option<anyhow::Error> = None;
    let mut written: Option<(&'static str, anyhow::Result<()>)> = None;
    // 能力回退写库的结果：剩余连接能力条数 + best-effort 写入结果。
    let mut fallback: Option<(usize, anyhow::Result<()>)> = None;
    let outcome = sessions.unregister_with_fallback(
        &agent_id,
        conn_id,
        || {
            // revoked 优先级最高：先查吊销，命中写 revoked，否则才写 offline。
            let revoked = match storage.is_revoked(&revoked_agent_id) {
                Ok(revoked) => revoked,
                Err(err) => {
                    revoked_error = Some(err);
                    false
                }
            };
            let status = if revoked { "revoked" } else { "offline" };
            written = Some((
                status,
                storage.set_status(&revoked_agent_id, status, now_ms()),
            ));
        },
        |capabilities| {
            // KI-24：最新连接断开且仍有剩余连接，best-effort 回退能力。
            // 失败只记录，不影响连接清理与采集。
            let result =
                fallback_storage.upsert_agent_control(&fallback_agent_id, capabilities, now_ms());
            fallback = Some((capabilities.len(), result));
        },
    );

    if matches!(
        outcome,
        UnregisterOutcome::NotRegistered | UnregisterOutcome::Removed
    ) {
        tracing::debug!(
            agent = %agent_id,
            conn_id,
            "旧会话结束，不修改在线状态与控制能力"
        );
        return;
    }
    if let Some(err) = revoked_error {
        tracing::warn!(agent = %agent_id, error = %err, "清理时查询吊销状态失败");
    }
    if let Some((status, result)) = written {
        match result {
            Ok(()) => {
                tracing::info!(agent = %agent_id, status = status, "agent 状态已更新");
            }
            Err(err) if status == "revoked" => {
                tracing::warn!(agent = %agent_id, error = %err, "恢复 revoked 状态失败");
            }
            Err(err) => {
                tracing::warn!(agent = %agent_id, error = %err, "更新 agent 状态失败");
            }
        }
    }
    match fallback {
        Some((capabilities, result)) => match result {
            Ok(()) => tracing::info!(
                agent = %agent_id,
                capabilities,
                "控制能力已回退到剩余连接"
            ),
            Err(err) => tracing::warn!(
                agent = %agent_id,
                error = %err,
                "回退控制能力失败，保留原值"
            ),
        },
        None if matches!(outcome, UnregisterOutcome::LatestRemovedWithoutFallback) => {
            // 剩余连接都还没登记能力：保留数据库里的历史能力，绝不写空。
            tracing::debug!(
                agent = %agent_id,
                "剩余连接未登记控制能力，保留历史能力"
            );
        }
        None => {}
    }
}

impl Drop for SessionCleanup {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let storage = self.storage.clone();
        let sessions = self.sessions.clone();
        let agent_id = self.agent_id.clone();
        let conn_id = self.conn_id;
        if tokio::runtime::Handle::try_current().is_ok() {
            // 正常会话路径已 await finish_async；这里只在任务被取消 / panic 时
            // 兜底。tokio worker 上不能直接跑同步 PG，也不能阻塞等待，因此
            // 交给 blocking 线程异步完成；进程退出前由下次启动的
            // reset_online_status 兜住残留状态。
            std::mem::drop(tokio::task::spawn_blocking(move || {
                finish_session_cleanup(storage, sessions, agent_id, conn_id);
            }));
        } else {
            // 单测 / 普通线程：保持旧同步语义。
            finish_session_cleanup(storage, sessions, agent_id, conn_id);
        }
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
fn spawn_revoke_watcher(storage: Arc<StorageHandle>, sessions: Arc<SessionRegistry>) {
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
fn spawn_self_monitor(storage: Arc<StorageHandle>, cfg: HubConfig) {
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
        let storage_for_register = storage.clone();
        match tokio::task::spawn_blocking(move || storage_for_register.upsert_agent(&record)).await
        {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(error = %err, "注册本机 agent 失败"),
            Err(err) => tracing::error!(error = %err, "注册本机 agent 任务失败"),
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
                // #50：self-monitor 与 agent 共用同一时间戳准入校验。
                if batch_timestamp_out_of_bounds(&batch, &cfg, ts) {
                    note_timestamp_rejected_batch(HUB_SELF_AGENT_ID, &batch);
                } else {
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
            }
            tokio::time::sleep(Duration::from_millis(cfg.sample_interval_ms)).await;
        }
    });
}

// ---------------------------------------------------------------------------
// M4-A2：后台维护任务（降采样 + 保留期）
// ---------------------------------------------------------------------------

/// 启动后台维护任务。
///
/// 语义（与方案 §5.1 / §5.3 一致）：
/// - 每 `maintenance_interval_secs` 执行一轮；启动后先睡一个周期，**不在启动时
///   同步跑大 backfill**，监听不会被占用；
/// - 每轮先 `run_downsample(..., Some(6))`，再 `run_retention(...)`；retention
///   的归档门禁由 [`archive::archive_gate`] 按配置生成（启用归档但无水位时阻止
///   删除 raw）；
/// - SQLite 读写全部在 `spawn_blocking` 里，单轮串行不重叠；
/// - 任何错误只 WARN 并写入 `maintenance_state.last_error`，任务不退出，
///   下一轮重试。
fn spawn_maintenance(storage: Arc<StorageHandle>, cfg: HubConfig) {
    tokio::spawn(async move {
        // 配置校验已保证 1–3600；这里 max(1) 只是防御非法配置造成的忙循环。
        let interval = Duration::from_secs(cfg.maintenance_interval_secs.max(1));
        loop {
            tokio::time::sleep(interval).await;
            let storage = storage.clone();
            let cfg = cfg.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                run_maintenance_round(&storage, &cfg);
            })
            .await;
            if let Err(err) = outcome {
                // worker 内部不 panic；走到这里说明任务被取消或意外 panic。
                tracing::warn!(error = %err, "维护任务轮次异常结束，下一轮继续");
            }
        }
    });
}

/// 执行一轮「降采样 → 保留期」，并维护 `last_error`。
///
/// 降采样失败时仍执行保留期：水面未推进，保留期门禁会阻止删除未聚合数据，
/// 不会因一次失败丢数据。只有整轮都成功才清空 `last_error`，否则保留本轮
/// 错误供 `maintenance status` 排障。错误字符串不含 secret。
fn run_maintenance_round(storage: &StorageHandle, cfg: &HubConfig) {
    let now = now_ms();
    let mut errors: Vec<String> = Vec::new();

    let mut downsample_ok = true;
    match downsample::run_downsample(
        storage.as_storage(),
        now,
        Some(MAINTENANCE_MAX_BACKFILL_HOURS),
    ) {
        Ok(report) => tracing::debug!(?report, "维护任务：降采样完成"),
        Err(err) => {
            downsample_ok = false;
            let message = format!("downsample: {err:#}");
            tracing::warn!(error = %message, "维护任务：降采样失败，跳过本轮保留期");
            errors.push(message);
        }
    }
    // 降采样失败时源数据状态未知；本轮不删除任何层级，避免 1m 先于迟到
    // raw 被删。保留期下一轮重试。
    if downsample_ok {
        let gate = archive::archive_gate(storage, cfg);
        match downsample::run_retention(storage.as_storage(), cfg, now, gate) {
            Ok(report) => tracing::debug!(?report, "维护任务：保留期完成"),
            Err(err) => {
                let message = format!("retention: {err:#}");
                tracing::warn!(error = %message, "维护任务：保留期失败，下一轮重试");
                errors.push(message);
            }
        }
    }

    // 成功一轮写空串（= 清空 last_error）；失败时保留错误，直到下一轮全绿。
    let last_error: String = errors
        .join("; ")
        .chars()
        .take(MAX_MAINTENANCE_ERROR_CHARS)
        .collect();
    if let Err(err) = storage.set_maintenance_state(downsample::STATE_LAST_ERROR, &last_error, now)
    {
        tracing::warn!(error = %err, "写入维护任务 last_error 失败");
    }
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

    /// 测试用：不限制各层保留期，只验证跨度选层与 bucket 规则；
    /// 保留期对选层的影响由 `m4a_series_tier_selection_respects_retention` 覆盖。
    fn parse_query(raw: Option<&str>) -> std::result::Result<ParsedSeriesQuery, String> {
        super::parse_series_query(raw, SeriesRetention::unlimited())
    }

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

    /// A5/安全：走真实 `handle_renewal` 路径——CN 强制取会话身份；
    /// #43：同会话不再永久拒绝，只受 10 分钟冷却约束（冷却内拒绝、冷却后成功），
    /// 跨两个证书周期仍能继续轮换并推进 `last_success_ms`。
    #[tokio::test]
    async fn a5_renewal_uses_session_identity_and_cooldown_only() {
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
                assert_eq!(session.last_success_ms, now);
            }
            other => panic!("首次续签必须成功，实际: {other:?}"),
        }

        // 同一会话冷却窗口内：拒绝。
        let reply = handle_renewal(
            &ctx,
            &mut session,
            "session-agent",
            &csr,
            now + RENEW_COOLDOWN_MS - 1,
        )
        .await;
        assert_eq!(problem_code(&reply), codes::RATE_LIMITED);
        assert_eq!(
            session.last_success_ms, now,
            "冷区内失败不得改写上次成功时间"
        );

        // 冷却窗口到期后，同一会话必须能再次续签（旧实现会永久拒绝）。
        let second_success_at = now + RENEW_COOLDOWN_MS;
        match handle_renewal(&ctx, &mut session, "session-agent", &csr, second_success_at).await {
            Frame::CertRenewed { .. } => {}
            other => panic!("冷却结束后同一会话必须可以续签，实际: {other:?}"),
        }
        assert_eq!(session.last_success_ms, second_success_at);

        // 换一个新会话（模拟断开重连）：仍在冷却窗口内 → 仍被限流。
        let mut reconnect = RenewState::default();
        let reply = handle_renewal(
            &ctx,
            &mut reconnect,
            "session-agent",
            &csr,
            second_success_at + 1_000,
        )
        .await;
        assert_eq!(problem_code(&reply), codes::RATE_LIMITED);
        assert_eq!(reconnect.last_success_ms, 0);

        // 其他 agent 不受影响。
        let mut other = RenewState::default();
        assert!(matches!(
            handle_renewal(&ctx, &mut other, "other-agent", &csr, second_success_at + 1).await,
            Frame::CertRenewed { .. }
        ));

        // 跨两个证书周期（90 天一轮）：每次冷却都早已过去，均应成功。
        let day_ms = 24 * 60 * 60 * 1_000i64;
        for cycle in 1..=2 {
            let at = second_success_at + cycle * 90 * day_ms;
            match handle_renewal(&ctx, &mut session, "session-agent", &csr, at).await {
                Frame::CertRenewed { .. } => {}
                other => panic!("第 {cycle} 个周期续签必须成功，实际: {other:?}"),
            }
            assert_eq!(
                session.last_success_ms, at,
                "第 {cycle} 个周期必须记录新的成功时间"
            );
        }

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
        assert_eq!(session.last_success_ms, 0, "失败不得记录成功时间");

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
    ///
    /// 满表且条目仍在冷却窗口内时必须拒绝新身份：若淘汰旧条目，攻击者可用
    /// ≥ 上限数量的新 agent_id 轮流挤掉任意身份的冷却记录，从而绕过 10 分钟限流。
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

        // 独立表精确填满容量，所有条目都处于冷却窗口内。
        let mut full = RenewGuard::new();
        for i in 0..RENEW_GUARD_MAX_ENTRIES {
            assert!(
                full.begin_attempt(&format!("agent-{i}"), now),
                "第 {i} 个身份在未满表时必须放行"
            );
        }
        assert_eq!(full.last_attempt_ms.len(), RENEW_GUARD_MAX_ENTRIES);

        // 满表且全在冷却窗口：新身份拒绝，表大小不变，旧身份的冷却不被挤掉。
        assert!(
            !full.begin_attempt("agent-overflow", now + 1),
            "满表时不得淘汰冷却中的记录来放行新身份"
        );
        assert_eq!(
            full.last_attempt_ms.len(),
            RENEW_GUARD_MAX_ENTRIES,
            "拒绝新身份后表大小必须保持上限"
        );
        assert!(
            !full.begin_attempt("agent-0", now + 1),
            "已有身份仍必须受冷却窗口约束"
        );

        // 冷却结束后：只清理过期项即可放行新身份，表仍不超过上限。
        assert!(
            full.begin_attempt("agent-overflow", now + RENEW_COOLDOWN_MS),
            "冷却结束并清理过期项后必须放行新身份"
        );
        assert!(
            full.last_attempt_ms.len() <= RENEW_GUARD_MAX_ENTRIES,
            "冷却表不得无限增长，实际 {}",
            full.last_attempt_ms.len()
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
            storage: Arc::new(StorageHandle::sqlite_memory().unwrap()),
            cfg: Arc::new(cfg),
            sessions: SessionRegistry::new(),
            renewal: RenewalContext::new(tls::cert_dir(&dir), 90),
            live_cert: Arc::new(RwLock::new(CertStatus::unknown())),
            admin_rate,
            auth_failures,
            notifier: Arc::new(crate::notify::MockNotifier::new()),
            archive_download_slots: Arc::new(Semaphore::new(1)),
            archive_download_send_timeout: ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
            archive_download_principal_slots: Arc::new(StdMutex::new(HashMap::new())),
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
            storage: Arc::new(StorageHandle::sqlite_memory().unwrap()),
            cfg: Arc::new(cfg),
            sessions: SessionRegistry::new(),
            renewal: RenewalContext::new(tls::cert_dir(&dir), 90),
            live_cert: Arc::new(RwLock::new(CertStatus::unknown())),
            admin_rate,
            auth_failures,
            notifier: Arc::new(crate::notify::MockNotifier::new()),
            archive_download_slots: Arc::new(Semaphore::new(1)),
            archive_download_send_timeout: ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
            archive_download_principal_slots: Arc::new(StdMutex::new(HashMap::new())),
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
            storage: Arc::new(StorageHandle::sqlite_memory().unwrap()),
            cfg: Arc::new(cfg),
            sessions: SessionRegistry::new(),
            renewal: RenewalContext::new(PathBuf::from("/tmp/rb-hub-test-unused-ca"), 90),
            live_cert: Arc::new(RwLock::new(CertStatus::unknown())),
            admin_rate,
            auth_failures,
            notifier: Arc::new(crate::notify::MockNotifier::new()),
            archive_download_slots: Arc::new(Semaphore::new(1)),
            archive_download_send_timeout: ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
            archive_download_principal_slots: Arc::new(StdMutex::new(HashMap::new())),
        }
    }

    /// 测试用：覆盖下载 body 发送期限（生产固定 120s）。
    fn hub_state_with_download_timeout(cfg: HubConfig, timeout: Duration) -> AppState {
        let mut state = hub_state_with(cfg);
        state.archive_download_send_timeout = timeout;
        state
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

    /// 与 [`admin_call`] 相同，但**不读取响应 body**。
    ///
    /// 用于验证下载许可是否持有到 body 生命周期结束：调用方拿到 `Response`
    /// 后可以只读一帧或直接 drop。
    async fn admin_response(router: &Router, method: &str, uri: &str, token: &str) -> Response {
        let request = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        call_router(router, request).await
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
            (30 * 24 * 3_600_000, 3_600_000),
            (365 * 24 * 3_600_000, 21_600_000),
            (MAX_SERIES_SPAN_MS, 43_200_000),
        ];
        for (span, expected) in cases {
            let bucket = auto_bucket_ms(span);
            assert_eq!(bucket, expected, "span={span} 的自动 bucket 不符");
            assert!(
                span / bucket < MAX_AUTO_BUCKET_POINTS,
                "span={span} 的 bucket={bucket} 单曲线点数超限"
            );
        }
        // 730 天（1h 默认保留期）也必须落在 1500 点目标内。
        assert!(MAX_SERIES_SPAN_MS / auto_bucket_ms(MAX_SERIES_SPAN_MS) < MAX_AUTO_BUCKET_POINTS);
        // 档位必须单调、且来自方案固定集合（M4-A2b 新增 12h / 24h）。
        for bucket in [
            1_000, 5_000, 10_000, 30_000, 60_000, 300_000, 900_000, 3_600_000, 21_600_000,
            43_200_000, 86_400_000,
        ] {
            assert!(AUTO_BUCKETS_MS.contains(&bucket));
        }
    }

    /// series 参数边界：多 metric、from/to、730 天、metric 字符集与数量、bucket 校验。
    #[test]
    fn m2_series_query_validation_boundaries() {
        let from = 1_700_000_000_000_i64;
        let to = from + MAX_SERIES_SPAN_MS;
        let valid = format!("metric=cpu.usage&metric=mem.used&from={from}&to={to}");
        let parsed = parse_query(Some(&valid)).expect("合法参数必须通过");
        assert_eq!(parsed.metrics, vec!["cpu.usage", "mem.used"]);
        assert_eq!(parsed.from, from);
        assert_eq!(parsed.to, to);
        assert_eq!(parsed.bucket_ms, auto_bucket_ms(MAX_SERIES_SPAN_MS));
        assert_eq!(parsed.tier, SampleTier::OneHour);

        // 730 天请求显式 60s：自动提升到 1h 层粒度，不返回 400。
        let explicit = format!("metric=cpu.usage&from={from}&to={to}&bucket_ms=60000");
        let parsed = parse_query(Some(&explicit)).unwrap();
        assert_eq!(parsed.bucket_ms, 3_600_000);
        assert_eq!(parsed.tier, SampleTier::OneHour);

        // 时间参数。
        assert!(parse_query(Some("metric=cpu.usage&from=1&to=1")).is_err());
        assert!(parse_query(Some("metric=cpu.usage&from=2&to=1")).is_err());
        let too_wide = format!(
            "metric=cpu.usage&from={}&to={}",
            from,
            from + MAX_SERIES_SPAN_MS + 1
        );
        assert!(parse_query(Some(&too_wide)).is_err());
        assert!(parse_query(Some("metric=cpu.usage&to=10")).is_err());
        assert!(parse_query(Some("metric=cpu.usage")).is_err());
        assert!(parse_query(Some("metric=cpu.usage&from=1&from=2&to=3")).is_err());
        assert!(parse_query(Some("metric=cpu.usage&from=1&to=3&bucket_ms=0")).is_err());

        // metric 数量 / 字符集 / 长度 / 空值。
        assert!(parse_query(Some("from=1&to=3")).is_err());
        let many: String = (0..=MAX_SERIES_METRICS)
            .map(|i| format!("metric=m{i}&"))
            .collect();
        assert!(parse_query(Some(&format!("{many}from=1&to=3"))).is_err());
        assert!(parse_query(Some("metric=CPU.usage&from=1&to=3")).is_err());
        assert!(parse_query(Some("metric=cpu usage&from=1&to=3")).is_err());
        assert!(parse_query(Some("metric=a/b&from=1&to=3")).is_err());
        let long = "a".repeat(MAX_METRIC_LEN + 1);
        assert!(parse_query(Some(&format!("metric={long}&from=1&to=3"))).is_err());
        assert!(parse_query(Some("metric=&from=1&to=3")).is_err());
        assert!(parse_query(Some("metric=cpu.usage&from=1&to=3&bogus=1")).is_err());
    }

    /// M4-A2b：跨度边界选层、显式/自动 bucket 夹到层粒度、730 天上限。
    #[test]
    fn m4a_series_tier_selection_boundaries() {
        let from = 1_700_000_000_000_i64;
        let parse = |span: i64, bucket: Option<i64>| {
            let mut raw = format!("metric=cpu.usage&from={from}&to={}", from + span);
            if let Some(bucket) = bucket {
                raw.push_str(&format!("&bucket_ms={bucket}"));
            }
            parse_query(Some(&raw))
        };

        // ≤6h → raw；显式小桶保持原值（raw 层粒度是 1ms）。
        for span in [1_i64, 60_000, 6 * 3_600_000] {
            assert_eq!(
                parse(span, None).unwrap().tier,
                SampleTier::Raw,
                "span={span}"
            );
        }
        assert_eq!(parse(6 * 3_600_000, Some(1_000)).unwrap().bucket_ms, 1_000);

        // 6h + 1ms → 1m；自动档位 30s 被提升到 1m 粒度，显式 1s 同样提升。
        let parsed = parse(6 * 3_600_000 + 1, None).unwrap();
        assert_eq!(parsed.tier, SampleTier::OneMinute);
        assert_eq!(parsed.bucket_ms, 60_000, "自动档位必须夹到 1m 粒度");
        assert_eq!(
            parse(6 * 3_600_000 + 1, Some(1_000)).unwrap().bucket_ms,
            60_000
        );
        assert_eq!(
            parse(6 * 3_600_000 + 1, Some(60_000)).unwrap().bucket_ms,
            60_000
        );

        // 7d 边界：等于 7d 仍是 1m，+1ms → 1h；自动档位 900s 夹到 1h 粒度。
        let seven_days = 7 * 24 * 3_600_000;
        assert_eq!(parse(seven_days, None).unwrap().tier, SampleTier::OneMinute);
        let parsed = parse(seven_days + 1, None).unwrap();
        assert_eq!(parsed.tier, SampleTier::OneHour);
        assert_eq!(parsed.bucket_ms, 3_600_000, "自动档位必须夹到 1h 粒度");

        // 30 天查询显式 60s：提升到 1h 层粒度，响应回显实际值；显式大桶保留。
        let parsed = parse(30 * 24 * 3_600_000, Some(60_000)).unwrap();
        assert_eq!(parsed.tier, SampleTier::OneHour);
        assert_eq!(parsed.bucket_ms, 3_600_000);
        assert_eq!(
            parse(30 * 24 * 3_600_000, Some(86_400_000))
                .unwrap()
                .bucket_ms,
            86_400_000
        );

        // 730 天边界：允许且自动落到 12h 档（< 1500 点）；+1ms 必须拒绝。
        let parsed = parse(MAX_SERIES_SPAN_MS, None).unwrap();
        assert_eq!(parsed.tier, SampleTier::OneHour);
        assert_eq!(parsed.bucket_ms, 43_200_000);
        let err = match parse(MAX_SERIES_SPAN_MS + 1, None) {
            Ok(_) => panic!("超过 730 天必须被拒绝"),
            Err(err) => err,
        };
        assert!(err.contains("730"), "错误信息必须说明 730 天上限: {err}");
    }

    /// M4-A2b：选层必须参考 retention 可用下界，而不是只看跨度。
    #[test]
    fn m4a_series_tier_selection_respects_retention() {
        let now = 1_700_000_000_000i64;
        let cfg = HubConfig {
            retention_raw_days: 7,
            retention_1m_days: 90,
            retention_1h_days: 730,
            ..HubConfig::default()
        };
        let retention = SeriesRetention::from_config(&cfg, now);
        assert_eq!(retention.raw_since, Some(now - 7 * MS_PER_DAY));
        assert_eq!(retention.one_minute_since, Some(now - 90 * MS_PER_DAY));

        let parse_at = |span: i64, from: i64| {
            let raw = format!("metric=cpu.usage&from={from}&to={}", from + span);
            super::parse_series_query(Some(&raw), retention).unwrap()
        };

        // 3 天前的 1h 窗口：raw 仍在保留期内。
        assert_eq!(
            parse_at(3_600_000, now - 3 * MS_PER_DAY).tier,
            SampleTier::Raw
        );

        // 10 天前的 1h 窗口：raw 已过 7 天保留期 → 1m，bucket 夹到 60s。
        let parsed = parse_at(3_600_000, now - 10 * MS_PER_DAY);
        assert_eq!(parsed.tier, SampleTier::OneMinute);
        assert_eq!(parsed.bucket_ms, 60_000);

        // 100 天前的 1d 窗口：1m 也已过 90 天保留期 → 1h，bucket 夹到 1h。
        let parsed = parse_at(MS_PER_DAY, now - 100 * MS_PER_DAY);
        assert_eq!(parsed.tier, SampleTier::OneHour);
        assert_eq!(parsed.bucket_ms, 3_600_000);

        // 边界：from 恰好等于保留下界仍算可用。
        assert_eq!(
            parse_at(3_600_000, now - 7 * MS_PER_DAY).tier,
            SampleTier::Raw
        );

        // retention=0 表示该层永久可用：10 天前仍选 raw。
        let unlimited = SeriesRetention::from_config(
            &HubConfig {
                retention_raw_days: 0,
                retention_1m_days: 0,
                retention_1h_days: 730,
                ..HubConfig::default()
            },
            now,
        );
        assert_eq!(unlimited.raw_since, None);
        assert_eq!(unlimited.one_minute_since, None);
        let raw = format!(
            "metric=cpu.usage&from={}&to={}",
            now - 10 * MS_PER_DAY - 3_600_000,
            now - 10 * MS_PER_DAY
        );
        assert_eq!(
            super::parse_series_query(Some(&raw), unlimited)
                .unwrap()
                .tier,
            SampleTier::Raw
        );
    }

    /// M4-A2b：30 天查询选 1h 层；响应 JSON 含 tier 且 bucket_ms 是实际值。
    #[tokio::test]
    async fn m4a_series_route_reports_tier_and_effective_bucket() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let router = admin_router(state.clone());

        // 30 天前的一个点：先写 raw，再用真实降采样生成 1m / 1h，避免依赖私有 helper。
        let to = 1_700_000_000_000_i64;
        let from = to - 30 * 24 * 3_600_000;
        let sample_ts = from + 1_000;
        state
            .storage
            .insert_batch(&SampleBatch {
                agent_id: "agent-1".to_string(),
                epoch: 1,
                seq: 0,
                boot_id: "boot".to_string(),
                sent_at: sample_ts,
                samples: vec![Sample::new("cpu.usage", sample_ts, 42.0)],
            })
            .unwrap();
        state
            .storage
            .downsample_1m_range(from, from + 3_600_000)
            .unwrap();
        state
            .storage
            .downsample_1h_range(from, from + 3_600_000)
            .unwrap();
        assert_eq!(state.storage.samples_1h_stats().unwrap().rows, 1);

        let uri = format!(
            "/api/v1/agents/agent-1/series?metric=cpu.usage&from={from}&to={to}&bucket_ms=60000"
        );
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        assert_eq!(body["tier"], "1h");
        assert_eq!(body["bucket_ms"], 3_600_000, "显式 60s 必须回显实际 1h");
        assert_eq!(body["series"][0]["metric"], "cpu.usage");
        assert_eq!(body["series"][0]["points"][0][1], 42.0);

        // 超过 730 天：400，并说明上限。
        let too_wide = format!(
            "/api/v1/agents/agent-1/series?metric=cpu.usage&from={from}&to={}",
            from + MAX_SERIES_SPAN_MS + 1
        );
        let (status, _, body) = admin_call(&router, "GET", &too_wide, Some("token"), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let body = json_body(&body);
        assert_eq!(body["error"], "bad_request");
        assert!(
            body["message"].as_str().unwrap_or_default().contains("730"),
            "错误信息必须说明 730 天上限: {body}"
        );
    }

    /// M4-A2b：8 天查询选 1h 层，且路由必须真的从 1h 表取数。
    ///
    /// 生成 1h 桶后删除 raw / 1m，只留 1h；若 `agent_series` 传错 tier（查
    /// raw 或 1m），响应会变空——只校验 `tier` 回显无法发现这种错误。
    #[tokio::test]
    async fn m4a_series_route_reads_1h_tier() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let router = admin_router(state.clone());

        let to = 1_700_000_000_000_i64;
        let from = to - 8 * 24 * 3_600_000;
        let sample_ts = from + 1_000;
        state
            .storage
            .insert_batch(&SampleBatch {
                agent_id: "agent-1".to_string(),
                epoch: 1,
                seq: 0,
                boot_id: "boot".to_string(),
                sent_at: sample_ts,
                samples: vec![Sample::new("cpu.usage", sample_ts, 42.0)],
            })
            .unwrap();
        // R1b：走真实增量聚合，同一事务内标记 raw 并生成 clean 的 1m/1h。
        downsample::run_downsample(state.storage.as_storage(), now_ms(), None).unwrap();
        state.storage.prune_samples_before(i64::MAX).unwrap();
        state.storage.prune_samples_1m_before(i64::MAX).unwrap();
        assert_eq!(state.storage.raw_stats().unwrap().rows, 0);
        assert_eq!(state.storage.samples_1m_stats().unwrap().rows, 0);
        assert_eq!(state.storage.samples_1h_stats().unwrap().rows, 1);

        let uri = format!(
            "/api/v1/agents/agent-1/series?metric=cpu.usage&from={from}&to={to}&bucket_ms=60000"
        );
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        assert_eq!(body["tier"], "1h");
        assert_eq!(body["bucket_ms"], 3_600_000, "8 天查询的 60s 必须提升到 1h");
        assert_eq!(body["series"][0]["metric"], "cpu.usage");
        assert_eq!(body["series"][0]["points"].as_array().unwrap().len(), 1);
        let expected_ts = sample_ts.div_euclid(3_600_000) * 3_600_000;
        assert_eq!(body["series"][0]["points"][0][0], expected_ts);
        assert_eq!(body["series"][0]["points"][0][1], 42.0);
    }

    /// 写一个 `cpu.usage` raw 点（单批 seq=0，测试内只调用一次）。
    fn seed_cpu_point(state: &AppState, ts: i64, value: f64) {
        state
            .storage
            .insert_batch(&SampleBatch {
                agent_id: "agent-1".to_string(),
                epoch: 1,
                seq: 0,
                boot_id: "boot".to_string(),
                sent_at: ts,
                samples: vec![Sample::new("cpu.usage", ts, value)],
            })
            .unwrap();
    }

    /// M4-A2b：跨度 >6h 选 1m 层；删除 raw 后仍必须从 1m 表取数。
    #[tokio::test]
    async fn m4a_series_route_reads_1m_tier() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let router = admin_router(state.clone());

        let now = now_ms();
        let to = now;
        let from = now - MS_PER_DAY;
        let sample_ts = now - 2 * 3_600_000;
        let minute = sample_ts.div_euclid(60_000) * 60_000;
        seed_cpu_point(&state, sample_ts, 33.0);
        // R1b：run_downsample 标记 raw 后才可被 retention 删除。
        downsample::run_downsample(state.storage.as_storage(), now, None).unwrap();
        state.storage.prune_samples_before(i64::MAX).unwrap();
        assert_eq!(state.storage.raw_stats().unwrap().rows, 0);
        assert_eq!(state.storage.samples_1m_stats().unwrap().rows, 1);

        let uri = format!("/api/v1/agents/agent-1/series?metric=cpu.usage&from={from}&to={to}");
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        assert_eq!(body["tier"], "1m");
        assert_eq!(body["bucket_ms"], 60_000);
        assert_eq!(body["series"][0]["points"][0][0], minute);
        assert_eq!(body["series"][0]["points"][0][1], 33.0);
    }

    /// M4-A2b：raw 已过保留期被删时，按 retention 下界选 1m 并返回 1m 桶。
    #[tokio::test]
    async fn m4a_series_route_uses_1m_when_raw_pruned() {
        let state = hub_state("token");
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let router = admin_router(state.clone());

        // 10 天前的 1h 窗口：跨度仍是 raw 档，但 raw 只保留 7 天，必须选 1m。
        let now = now_ms();
        let to = now - 10 * MS_PER_DAY;
        let from = to - 3_600_000;
        let sample_ts = from + 1_000;
        let minute = sample_ts.div_euclid(60_000) * 60_000;
        seed_cpu_point(&state, sample_ts, 42.0);
        downsample::run_downsample(state.storage.as_storage(), now, None).unwrap();
        state.storage.prune_samples_before(i64::MAX).unwrap();
        assert_eq!(state.storage.raw_stats().unwrap().rows, 0);
        assert_eq!(state.storage.samples_1m_stats().unwrap().rows, 1);

        let uri = format!("/api/v1/agents/agent-1/series?metric=cpu.usage&from={from}&to={to}");
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        assert_eq!(body["tier"], "1m");
        assert_eq!(body["bucket_ms"], 60_000, "1h 跨度自动 5s 必须夹到 1m");
        assert_eq!(body["series"][0]["points"][0][0], minute);
        assert_eq!(body["series"][0]["points"][0][1], 42.0);
    }

    /// M4-A2b：空结果逐层回退到 1h。
    ///
    /// retention=0 时跨度 1h 先选 raw；把 raw / 1m 都 prune、仅保留 8 天前
    /// 的 1h 桶，路由必须回退两次到 1h，并把 bucket 重新夹到 1h 粒度。
    #[tokio::test]
    async fn m4a_series_route_falls_back_to_1h_when_coarser_empty() {
        let state = hub_state_with(HubConfig {
            admin_token: "token".to_string(),
            retention_raw_days: 0,
            retention_1m_days: 0,
            retention_1h_days: 730,
            ..HubConfig::default()
        });
        state.storage.upsert_agent(&test_agent("agent-1")).unwrap();
        let router = admin_router(state.clone());

        let now = now_ms();
        let to = now - 8 * MS_PER_DAY;
        let from = to - 3_600_000;
        let sample_ts = from + 1_000;
        seed_cpu_point(&state, sample_ts, 7.0);
        downsample::run_downsample(state.storage.as_storage(), now, None).unwrap();
        state.storage.prune_samples_before(i64::MAX).unwrap();
        state.storage.prune_samples_1m_before(i64::MAX).unwrap();
        assert_eq!(state.storage.raw_stats().unwrap().rows, 0);
        assert_eq!(state.storage.samples_1m_stats().unwrap().rows, 0);
        assert_eq!(state.storage.samples_1h_stats().unwrap().rows, 1);

        let uri = format!("/api/v1/agents/agent-1/series?metric=cpu.usage&from={from}&to={to}");
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        assert_eq!(body["tier"], "1h");
        assert_eq!(body["bucket_ms"], 3_600_000);
        let expected_ts = sample_ts.div_euclid(3_600_000) * 3_600_000;
        assert_eq!(body["series"][0]["points"][0][0], expected_ts);
        assert_eq!(body["series"][0]["points"][0][1], 7.0);
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
        assert!(build_series_response(1_000, SampleTier::Raw, too_many_points).is_err());

        let too_many_series: Vec<SeriesRow> = (0..=MAX_SERIES_COUNT)
            .map(|i| row(format!("m{i}"), Labels::new(), 1))
            .collect();
        assert!(build_series_response(1_000, SampleTier::Raw, too_many_series).is_err());

        let response = build_series_response(
            1_000,
            SampleTier::Raw,
            vec![
                row("cpu.usage".to_string(), Labels::new(), 2_000),
                row("cpu.usage".to_string(), Labels::new(), 1_000),
            ],
        )
        .unwrap();
        assert_eq!(response.bucket_ms, 1_000);
        assert_eq!(response.tier, "raw");
        assert_eq!(response.series.len(), 1);
        assert_eq!(
            response.series[0].points,
            vec![(1_000, 1.0), (2_000, 1.0)],
            "点必须按 ts 升序"
        );
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["bucket_ms"], 1_000);
        assert_eq!(json["tier"], "raw");
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
        let session = state.sessions.register("agent-1").await;
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
        assert_eq!(body["tier"], "raw");
        assert!(body["series"].is_array());

        let uri = format!(
            "/api/v1/agents/hub-self/series?metric=cpu.usage&from={from}&to={now}&bucket_ms=60000"
        );
        let (status, _, body) = admin_call(&router, "GET", &uri, Some("token"), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json_body(&body)["bucket_ms"], 60_000);
        assert_eq!(json_body(&body)["tier"], "raw");

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

    /// KI-27：连接 guard 必须由最后一个 clone 释放，覆盖整个 WS 会话。
    ///
    /// 模拟 `serve_tls` 的三份 clone：请求扩展、连接本身、upgrade future。
    /// 前两者先释放时（HTTP 升级响应完成、`serve_connection` 返回），全局与
    /// per-IP 许可都必须仍被 upgrade future 持有，直到 `dispatch` 返回。
    #[test]
    fn v035_connection_guards_hold_until_last_clone_drops() {
        let permits = Arc::new(Semaphore::new(1));
        let limiter = Arc::new(ConnectionLimiter::with_ip_capacity(1, 4));
        let ip: IpAddr = "192.0.2.27".parse().unwrap();

        let guards = ConnectionGuards {
            _global: Arc::new(try_acquire_connection(&permits).expect("首个全局许可")),
            _per_ip: Arc::new(limiter.try_acquire(ip).expect("首个 per-IP 许可")),
        };
        assert!(
            try_acquire_connection(&permits).is_none(),
            "guard 存活时全局许可不得重复发放"
        );
        assert!(
            limiter.try_acquire(ip).is_err(),
            "guard 存活时 per-IP 许可不得重复发放"
        );

        // 请求扩展与连接层各持有一份 clone；升级路径再把一份移入 upgrade future。
        let request_extension = guards.clone();
        let upgrade_future = guards.clone();

        // HTTP 升级响应结束：请求扩展先释放，许可不能跟着归还。
        drop(request_extension);
        assert!(try_acquire_connection(&permits).is_none());
        assert!(limiter.try_acquire(ip).is_err());

        // `serve_connection` 返回：连接层的 guard 释放，但会话仍在进行。
        drop(guards);
        assert!(
            try_acquire_connection(&permits).is_none(),
            "WS 会话未结束前全局许可必须继续持有"
        );
        assert!(
            limiter.try_acquire(ip).is_err(),
            "WS 会话未结束前 per-IP 计数必须继续持有"
        );

        // `dispatch` 返回、upgrade future 结束：最后一份 guard 释放两个许可。
        drop(upgrade_future);
        let reacquired_global = try_acquire_connection(&permits).expect("全局许可已归还");
        let reacquired_ip = limiter.try_acquire(ip).expect("per-IP 计数已归还");
        assert_eq!(limiter.tracked_ips(), 1);
        drop(reacquired_global);
        drop(reacquired_ip);
        assert_eq!(limiter.tracked_ips(), 0, "全部释放后来源表必须清空");
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
        assert!(
            tls::cert_dir(&dir)
                .join(cert_rotation::CERT_LOCK_FILE)
                .exists(),
            "flock 锁文件是持久的，Drop 不应删除它"
        );

        rotate_cert(Some(cfg_path), true, Some(30)).expect("释放锁后必须能正常轮换");
        let after = std::fs::read_to_string(&cert_path).unwrap();
        assert_ne!(
            tls::fingerprint_of_pem(&after).unwrap(),
            before_fingerprint,
            "正常轮换必须换证书"
        );
        assert!(
            tls::cert_dir(&dir)
                .join(cert_rotation::CERT_LOCK_FILE)
                .exists(),
            "rotate 结束后锁文件仍保留（flock 已释放）"
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
    async fn m3_register_agent(
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
        state.sessions.register(agent_id).await
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
        let handle = m3_register_agent(&state, "a1", &["systemd", "logs"]).await;
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
        let _online = m3_register_agent(&state, "a1", &["systemd"]).await;
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
        let _online2 = m3_register_agent(&state2, "a2", &["docker"]).await;
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
        let _online3 = m3_register_agent(&state3, "a4", &["logs"]).await;
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
        let _online = m3_register_agent(&state, "a1", &["systemd", "process", "logs"]).await;
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
        let handle =
            m3_register_agent(&state, "a1", &["systemd", "docker", "process", "logs"]).await;
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
        let handle = m3_register_agent(&state, "a1", &["systemd", "docker"]).await;
        let responder = m3_spawn_responder(
            handle.control_rx,
            vec![
                Err(ControlError::not_whitelisted(SECRET)),
                Err(ControlError::control_failed(SECRET)),
            ],
        );
        // 另一台在线 agent 故意不应答：覆盖超时分支（保持句柄存活让通道不关闭）。
        let _silent = m3_register_agent(&state, "a2", &["docker"]).await;
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
        let handle = m3_register_agent(&state, "a1", &["logs"]).await;
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
        let handle = m3_register_agent(&state, "a1", &["docker"]).await;
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
        let handle = m3_register_agent(&state, "a1", &["logs"]).await;
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
        let handle = m3_register_agent(&state, "a1", &["docker"]).await;
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
    fn session_cleanup_fixture(tag: &str) -> (PathBuf, Arc<StorageHandle>, Arc<SessionRegistry>) {
        let dir = temp_dir(tag);
        let storage = Arc::new(
            StorageHandle::sqlite(&dir.join("hub.db"), DEFAULT_READ_POOL_SIZE)
                .expect("打开测试库失败"),
        );
        (dir, storage, SessionRegistry::new())
    }

    fn agent_status(storage: &StorageHandle, agent_id: &str) -> String {
        storage
            .get_agent(agent_id)
            .expect("读取 agent 失败")
            .expect("agent 记录必须存在")
            .status
    }

    /// KI-24：按 `handle_session` 的方式登记能力（slot 锁内写库），返回是否为最新连接。
    fn register_connection_capabilities(
        storage: &StorageHandle,
        sessions: &SessionRegistry,
        agent_id: &str,
        conn_id: u64,
        capabilities: &[&str],
    ) -> bool {
        let capabilities = capabilities
            .iter()
            .map(|capability| capability.to_string())
            .collect::<Vec<_>>();
        sessions
            .set_capabilities(agent_id, conn_id, capabilities, |capabilities| {
                storage.upsert_agent_control(agent_id, capabilities, now_ms())
            })
            .expect("写入控制能力失败")
    }

    fn stored_control_capabilities(storage: &StorageHandle, agent_id: &str) -> Vec<String> {
        storage
            .get_agent_control(agent_id)
            .expect("读取控制能力失败")
            .expect("能力记录必须存在")
            .capabilities
    }

    /// c. 真正最后一条连接断开：回调执行一次，DB 置 offline；`finished` 保证 Drop
    /// 只清理一次，之后新连接写的 online 不会被二次清理覆盖。
    #[test]
    fn session_cleanup_marks_offline_after_last_connection() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-offline");
        storage.upsert_agent(&test_agent("a1")).unwrap();
        let handle = sessions.register_blocking("a1");
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
        let _new = sessions.register_blocking("a1");
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
        let old = sessions.register_blocking("a1");
        let new = sessions.register_blocking("a1");
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

    /// KI-24：能力以最新连接为准；最新连接断开回退旧连接，全部断开保留历史并 offline。
    #[test]
    fn session_cleanup_falls_back_to_remaining_connection_capabilities() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-capabilities");
        storage.upsert_agent(&test_agent("a1")).unwrap();

        let old = sessions.register_blocking("a1");
        assert!(register_connection_capabilities(
            &storage,
            &sessions,
            "a1",
            old.conn_id,
            &["docker"],
        ));
        assert_eq!(
            stored_control_capabilities(&storage, "a1"),
            vec!["docker".to_string()]
        );

        let new = sessions.register_blocking("a1");
        assert!(register_connection_capabilities(
            &storage,
            &sessions,
            "a1",
            new.conn_id,
            &["systemd", "logs"],
        ));
        assert_eq!(
            stored_control_capabilities(&storage, "a1"),
            vec!["systemd".to_string(), "logs".to_string()]
        );

        // 最新连接断开：回退到旧连接已登记的能力，agent 仍在线上。
        let mut new_cleanup = SessionCleanup::new(
            storage.clone(),
            sessions.clone(),
            "a1".to_string(),
            new.conn_id,
        );
        new_cleanup.finish();
        assert!(sessions.has_active("a1"), "旧连接仍在线");
        assert_eq!(agent_status(&storage, "a1"), "online");
        assert_eq!(
            stored_control_capabilities(&storage, "a1"),
            vec!["docker".to_string()],
            "最新连接断开后必须回退到剩余连接的能力"
        );

        // 最后一条连接断开：offline，并保留最后能力作为历史。
        let mut old_cleanup = SessionCleanup::new(
            storage.clone(),
            sessions.clone(),
            "a1".to_string(),
            old.conn_id,
        );
        old_cleanup.finish();
        assert!(!sessions.has_active("a1"));
        assert_eq!(agent_status(&storage, "a1"), "offline");
        assert_eq!(
            stored_control_capabilities(&storage, "a1"),
            vec!["docker".to_string()],
            "无剩余连接时保留历史能力，不写空"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KI-24：旧连接晚到的 Hello 不覆盖新连接写入的能力。
    #[test]
    fn stale_connection_hello_does_not_overwrite_latest_capabilities() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-capabilities-stale");
        storage.upsert_agent(&test_agent("a1")).unwrap();

        let old = sessions.register_blocking("a1");
        assert!(register_connection_capabilities(
            &storage,
            &sessions,
            "a1",
            old.conn_id,
            &["docker"],
        ));

        let new = sessions.register_blocking("a1");
        assert!(register_connection_capabilities(
            &storage,
            &sessions,
            "a1",
            new.conn_id,
            &["systemd"],
        ));
        assert_eq!(
            stored_control_capabilities(&storage, "a1"),
            vec!["systemd".to_string()]
        );

        // 旧连接晚到的 Hello：只登记到会话，返回 false，不写库。
        assert!(!register_connection_capabilities(
            &storage,
            &sessions,
            "a1",
            old.conn_id,
            &["logs", "process"],
        ));
        assert_eq!(
            stored_control_capabilities(&storage, "a1"),
            vec!["systemd".to_string()],
            "旧连接 Hello 不得覆盖新连接的能力"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------------
    // KI-21：hub 数据目录 / 证书目录接入
    // ------------------------------------------------------------------

    /// 库在 data_dir 内：走私有构造并收紧旧 0755 数据目录；库在 data_dir 外：
    /// 走普通构造，绝不 chmod 无关的父目录。
    #[cfg(unix)]
    #[test]
    fn hub_storage_hardens_only_declared_data_dir() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir = temp_dir("hub-storage-inside");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let inside_db = data_dir.join("hub.db");
        let storage = open_storage(&inside_db, &data_dir, 2).expect("打开数据目录内的数据库失败");
        drop(storage);
        assert_eq!(
            std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "data_dir 内的数据库必须把旧 0755 数据目录收紧到 0700"
        );
        assert_eq!(
            std::fs::metadata(&inside_db).unwrap().permissions().mode() & 0o777,
            0o600,
            "数据库文件必须是 0600"
        );
        let _ = std::fs::remove_dir_all(&data_dir);

        // 数据库在 data_dir 之外：不得收紧（更不得创建）声明的数据目录。
        let db_parent = temp_dir("hub-storage-outside");
        std::fs::create_dir_all(&db_parent).unwrap();
        std::fs::set_permissions(&db_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let outside_db = db_parent.join("hub.db");
        let declared_data_dir = db_parent.join("declared-data");
        let storage =
            open_storage(&outside_db, &declared_data_dir, 2).expect("打开数据目录外的数据库失败");
        drop(storage);
        assert_eq!(
            std::fs::metadata(&db_parent).unwrap().permissions().mode() & 0o777,
            0o755,
            "未声明为数据目录的父目录不得被 chmod"
        );
        assert!(
            !declared_data_dir.exists(),
            "data_dir 外的数据库不得创建/改动声明的数据目录"
        );
        assert_eq!(
            std::fs::metadata(&outside_db).unwrap().permissions().mode() & 0o777,
            0o600,
            "数据库文件仍必须是 0600"
        );
        let _ = std::fs::remove_dir_all(&db_parent);
    }

    /// D4b 回归：`open_storage_for_config` 对 SQLite 配置仍走原有行为
    /// （数据库在 data_dir 内时收紧目录，且可直接读写）。
    #[test]
    fn d4b_open_storage_for_config_supports_sqlite() {
        let dir = temp_dir("d4b-open-storage-sqlite");
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("hub.db");
        let cfg = HubConfig {
            data_dir: dir.clone(),
            database: format!("sqlite://{}", db.display()),
            ..HubConfig::default()
        };

        let storage = open_storage_for_config(&cfg).expect("SQLite 配置必须能打开");
        storage
            .upsert_agent(&test_agent("a1"))
            .expect("写入 agent 失败");
        assert_eq!(
            storage
                .get_agent("a1")
                .expect("读取 agent 失败")
                .expect("agent 必须存在")
                .agent_id,
            "a1"
        );
        drop(storage);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D4b 安全回归：PG 打开失败的错误上下文不能回显 DSN 密码。
    ///
    /// 127.0.0.1:1 在生产环境不会监听；这里只验证错误构造，不依赖真实 PG。
    #[test]
    fn d4b_open_storage_for_config_pg_error_redacts_password() {
        let dir = temp_dir("d4b-open-storage-pg-redact");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = HubConfig {
            data_dir: dir.clone(),
            database: "postgres://rustboard:supersecret@127.0.0.1:1/rustboard?sslmode=disable"
                .to_string(),
            db_connect_timeout_ms: 200,
            ..HubConfig::default()
        };

        let err = open_storage_for_config(&cfg)
            .err()
            .expect("不可达的 PostgreSQL 必须报错");
        let text = format!("{err:#}");
        assert!(
            !text.contains("supersecret"),
            "错误信息不得包含 DSN 密码: {text}"
        );
        assert!(
            text.contains("PostgreSQL"),
            "错误信息应说明是 PostgreSQL 后端: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ------------------------------------------------------------------
    // v0.3.5：database 外置告警的构造判定（日志由 e2e 验证）
    // ------------------------------------------------------------------

    /// `database` 的**直接父目录**恰好是 `data_dir` 才允许走私有目录构造并收紧；
    /// 外置、嵌套子目录、相对路径都不能误判，避免 chmod 共享/无关目录。
    #[test]
    fn v035_storage_private_data_dir_requires_exact_parent() {
        let base = temp_dir("hub-storage-private-dir");
        let data_dir = base.join("data");

        // 同目录：直接父目录 == data_dir，允许收紧。
        assert!(storage_uses_private_data_dir(
            &data_dir.join("hub.db"),
            &data_dir
        ));

        // 外置：父目录是另一个目录，必须判 false。
        assert!(!storage_uses_private_data_dir(
            &base.join("outside.db"),
            &data_dir
        ));

        // 更深的嵌套子目录也不含在 data_dir 的直接父目录语义里。
        assert!(!storage_uses_private_data_dir(
            &data_dir.join("nested").join("hub.db"),
            &data_dir
        ));
        // 反过来（DB 在 data_dir 的父目录里）同样不能收紧 data_dir。
        assert!(!storage_uses_private_data_dir(
            &base.join("hub.db"),
            &data_dir
        ));

        // 相对路径：父目录为空，不能声明为「本程序专用目录」。
        assert!(!storage_uses_private_data_dir(
            FsPath::new("hub.db"),
            &data_dir
        ));
        assert!(!storage_uses_private_data_dir(
            FsPath::new("./hub.db"),
            &data_dir
        ));
    }

    /// KI-21：证书目录只在已存在时收紧，缺失时不得创建空目录掩盖错误。
    #[cfg(unix)]
    #[test]
    fn hub_hardens_existing_cert_dir_without_creating_it() {
        use std::os::unix::fs::PermissionsExt;

        let data_dir = temp_dir("hub-cert-dir-hardening");
        std::fs::create_dir_all(&data_dir).unwrap();
        harden_existing_cert_dir(&data_dir).expect("缺失证书目录不是错误");
        assert!(
            !tls::cert_dir(&data_dir).exists(),
            "缺失的证书目录不得被创建"
        );

        let cert_dir = tls::cert_dir(&data_dir);
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::set_permissions(&cert_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        harden_existing_cert_dir(&data_dir).expect("收紧证书目录失败");
        assert_eq!(
            std::fs::metadata(&cert_dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "已存在的 0755 证书目录必须收紧到 0700"
        );
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    /// e. revoked 最高优先级：清理前已吊销，回调命中吊销写 revoked。
    #[test]
    fn session_cleanup_restores_revoked_status() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-revoked");
        storage.upsert_agent(&test_agent("a1")).unwrap();
        let handle = sessions.register_blocking("a1");
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
            let handle = sessions.register_blocking(&agent_id);
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
                let _handle = register_sessions.register_blocking(&register_agent);
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

    /// a. 确定性交错：旧清理持 cleanup gate + slot 锁做慢 DB 写入，新 register 必须等；
    /// 释放后旧 offline 先落库、新 online 后写，最终 DB 状态是 online。
    #[test]
    fn new_register_waits_for_old_cleanup_callback() {
        let (dir, storage, sessions) = session_cleanup_fixture("cleanup-barrier");
        storage.upsert_agent(&test_agent("a1")).unwrap();
        let old = sessions.register_blocking("a1");

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let cleanup_storage = storage.clone();
        let cleanup_sessions = sessions.clone();
        let old_id = old.conn_id;
        let cleanup = std::thread::spawn(move || {
            // 与生产清理一致：先拿 per-agent cleanup gate，再进 slot 锁做 DB 写。
            let slot = cleanup_sessions
                .cleanup_slot("a1")
                .expect("清理时 slot 必须存在");
            let _gate = slot.acquire_cleanup_gate_blocking();
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
            let _handle = register_sessions.register_blocking("a1");
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
        let mut current = sessions.register_blocking("hot");

        for round in 0..100 {
            let (done_tx, done_rx) = mpsc::channel::<()>();

            let register_sessions = sessions.clone();
            let register_storage = storage.clone();
            let register_done = done_tx.clone();
            let register = std::thread::spawn(move || {
                let handle = register_sessions.register_blocking("hot");
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

        let db = StorageHandle::sqlite(&db_path, DEFAULT_READ_POOL_SIZE).unwrap();
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

    /// M4-A2：`maintenance run/status` 子命令解析；task 必填且只接受白名单值。
    #[test]
    fn m4a_maintenance_cli_parses_subcommands() {
        let cli = Cli::try_parse_from([
            "rustboard-hub",
            "maintenance",
            "run",
            "--config",
            "hub.toml",
            "--task",
            "downsample",
        ])
        .unwrap();
        match cli.cmd {
            Cmd::Maintenance {
                action: MaintenanceAction::Run { config, task },
            } => {
                assert_eq!(config.as_deref(), Some(std::path::Path::new("hub.toml")));
                assert_eq!(task, MaintenanceTask::Downsample);
            }
            _ => panic!("应解析为 maintenance run"),
        }

        assert!(matches!(
            Cli::try_parse_from(["rustboard-hub", "maintenance", "run", "--task", "retention"])
                .unwrap()
                .cmd,
            Cmd::Maintenance {
                action: MaintenanceAction::Run {
                    task: MaintenanceTask::Retention,
                    ..
                }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "rustboard-hub",
                "maintenance",
                "status",
                "--config",
                "hub.toml"
            ])
            .unwrap()
            .cmd,
            Cmd::Maintenance {
                action: MaintenanceAction::Status { .. }
            }
        ));
        // 未知 task / 缺少 task 必须拒绝（避免误跑错误任务）。
        assert!(
            Cli::try_parse_from(["rustboard-hub", "maintenance", "run", "--task", "archive"])
                .is_err()
        );
        assert!(Cli::try_parse_from(["rustboard-hub", "maintenance", "run"]).is_err());
    }

    /// M4-A2：CLI 只依赖配置里的 SQLite，不要求 admin_token / 证书；
    /// 两条命令都输出可解析 JSON。
    #[test]
    fn m4a_maintenance_cli_run_and_status_emit_json() {
        let dir = temp_dir("maintenance-json");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = HubConfig {
            data_dir: dir.clone(),
            database: format!("sqlite://{}", dir.join("rustboard.db").display()),
            // 管理 API token 与证书材料在维护 CLI 中都不需要。
            admin_token: String::new(),
            ..HubConfig::default()
        };
        let cfg_path = dir.join("hub.toml");
        cfg.save(&cfg_path).unwrap();

        let json: serde_json::Value = serde_json::from_str(
            &maintenance_run_json(Some(cfg_path.clone()), MaintenanceTask::Downsample).unwrap(),
        )
        .unwrap();
        assert_eq!(json["one_minute"]["buckets"], 0);
        assert_eq!(json["one_minute"]["watermark"], serde_json::Value::Null);

        let status: serde_json::Value =
            serde_json::from_str(&maintenance_status_json(Some(cfg_path.clone())).unwrap())
                .unwrap();
        assert_eq!(status["retention_raw_days"], 7);
        assert_eq!(status["retention_1m_days"], 90);
        assert_eq!(status["retention_1h_days"], 730);
        assert_eq!(status["maintenance_interval_secs"], 60);
        assert_eq!(status["raw"]["rows"], 0);
        assert_eq!(status["downsample_1m_watermark"], serde_json::Value::Null);

        let json: serde_json::Value = serde_json::from_str(
            &maintenance_run_json(Some(cfg_path), MaintenanceTask::Retention).unwrap(),
        )
        .unwrap();
        assert_eq!(json["raw"]["deleted"], 0);
        assert_eq!(json["raw"]["skipped_no_watermark"], false);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M4-A2：retention 倒挂配置必须在打开数据库之前被拒绝，错误点名字段。
    #[test]
    fn m4a_maintenance_cli_rejects_inverted_retention_before_touching_db() {
        let dir = temp_dir("maintenance-bad-retention");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = HubConfig {
            data_dir: dir.clone(),
            database: format!("sqlite://{}", dir.join("rustboard.db").display()),
            admin_token: String::new(),
            retention_raw_days: 30,
            retention_1m_days: 7,
            ..HubConfig::default()
        };
        let cfg_path = dir.join("hub.toml");
        cfg.save(&cfg_path).unwrap();

        let err = maintenance_run_json(Some(cfg_path), MaintenanceTask::Retention).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("retention_1m_days"),
            "错误必须点名倒挂字段: {message}"
        );
        assert!(
            !dir.join("rustboard.db").exists(),
            "配置非法时不得打开/创建数据库"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M4-C1b：`archive test/status/run` 子命令解析；不与 maintenance 冲突。
    #[test]
    fn m4c1b_archive_cli_parses_subcommands() {
        assert!(matches!(
            Cli::try_parse_from(["rustboard-hub", "archive", "test", "--config", "hub.toml"])
                .unwrap()
                .cmd,
            Cmd::Archive {
                action: ArchiveAction::Test { .. }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["rustboard-hub", "archive", "status"])
                .unwrap()
                .cmd,
            Cmd::Archive {
                action: ArchiveAction::Status { .. }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["rustboard-hub", "archive", "run", "--config", "hub.toml"])
                .unwrap()
                .cmd,
            Cmd::Archive {
                action: ArchiveAction::Run { .. }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from(["rustboard-hub", "archive", "ledger", "status"])
                .unwrap()
                .cmd,
            Cmd::Archive {
                action: ArchiveAction::Ledger {
                    action: ArchiveLedgerAction::Status { .. }
                }
            }
        ));
        assert!(matches!(
            Cli::try_parse_from([
                "rustboard-hub",
                "archive",
                "ledger",
                "rebuild",
                "--config",
                "hub.toml",
            ])
            .unwrap()
            .cmd,
            Cmd::Archive {
                action: ArchiveAction::Ledger {
                    action: ArchiveLedgerAction::Rebuild { .. }
                }
            }
        ));
        assert!(
            Cli::try_parse_from(["rustboard-hub", "archive", "ledger"]).is_err(),
            "ledger 必须指定 status / rebuild"
        );
        // maintenance 只接受 downsample / retention，archive 走独立子命令。
        assert!(
            Cli::try_parse_from(["rustboard-hub", "maintenance", "run", "--task", "archive"])
                .is_err()
        );
    }

    /// M4-C1b：`archive status` 输出固定 JSON；`archive test` 未配置 WebDAV 时
    /// 返回固定错误，不创建数据库、不打印凭据。
    #[test]
    fn m4c1b_archive_status_and_test_cli_emit_fixed_outputs() {
        let dir = temp_dir("archive-cli");
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = HubConfig {
            data_dir: dir.clone(),
            database: format!("sqlite://{}", dir.join("rustboard.db").display()),
            admin_token: String::new(),
            ..HubConfig::default()
        };
        let cfg_path = dir.join("hub.toml");
        cfg.save(&cfg_path).unwrap();

        // `archive test` 只读配置，不应创建数据库；先跑它再跑 status。
        let message = format!(
            "{:#}",
            archive_test_json(Some(cfg_path.clone())).unwrap_err()
        );
        assert!(message.contains("webdav"), "错误必须点明后端: {message}");
        assert!(!message.contains("password"), "错误不得包含凭据: {message}");
        assert!(
            !dir.join("rustboard.db").exists(),
            "archive test 不应打开数据库"
        );

        let status: serde_json::Value =
            serde_json::from_str(&archive_status_json(Some(cfg_path.clone())).unwrap()).unwrap();
        assert_eq!(status["enabled"], false);
        assert_eq!(status["backend"], "webdav");
        assert!(status["last_archived_ts"].is_null());
        assert!(status["last_run"].is_null());
        assert!(status["last_error"].is_null());
        assert_eq!(status["objects"], 0);

        let message = format!("{:#}", archive_run_json(Some(cfg_path)).unwrap_err());
        assert!(
            message.contains("archive.enabled"),
            "未启用时必须明确拒绝: {message}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M4-C1b / R1b：`maintenance run --task retention` 的归档门禁。
    ///
    /// 原始水位（`last_archived_ts`）不再单独证明 raw 可删；必须有 uploaded
    /// 的 v8 claim 对象（`archive_object_id` join）才能删除。
    #[test]
    fn m4c1b_maintenance_retention_requires_uploaded_claim() {
        use rustboard_common::config::ArchiveWebdavConfig;
        use rustboard_common::model::SampleBatch;
        use rustboard_core::archive::{ArchiveObject, ArchiveStatus, LEDGER_VERSION_V8};

        let dir = temp_dir("archive-gate-retention");
        std::fs::create_dir_all(&dir).unwrap();
        let mut cfg = HubConfig {
            data_dir: dir.clone(),
            database: format!("sqlite://{}", dir.join("rustboard.db").display()),
            admin_token: String::new(),
            retention_raw_days: 7,
            ..HubConfig::default()
        };
        cfg.archive.enabled = true;
        cfg.archive.after_days = 7;
        cfg.archive.webdav = Some(ArchiveWebdavConfig {
            // 不需要真实连通：retention 只读 ledger，不构建后端。
            url: "http://127.0.0.1:9/rustboard".to_string(),
            username: "user".to_string(),
            password: "password".to_string(),
        });
        let cfg_path = dir.join("hub.toml");
        cfg.save(&cfg_path).unwrap();

        let now = now_ms();
        let db_path = dir.join("rustboard.db");
        let storage = StorageHandle::sqlite(&db_path, DEFAULT_READ_POOL_SIZE).unwrap();
        let batch = SampleBatch {
            agent_id: "agent-1".to_string(),
            epoch: 1,
            seq: 1,
            boot_id: "boot".to_string(),
            sent_at: now - 10 * 86_400_000,
            samples: (0..3)
                .map(|index| Sample::new("cpu.usage", now - 10 * 86_400_000 + index, index as f64))
                .collect(),
        };
        assert!(matches!(
            storage.insert_batch(&batch).unwrap(),
            rustboard_core::storage::IngestOutcome::Inserted { inserted: 3 }
        ));
        // R1b：raw 必须先被增量聚合认领，retention 才会考虑删除。
        downsample::run_downsample(&*storage, now, None).unwrap();
        drop(storage);

        // 归档启用但没有任何 uploaded claim：raw 不删。
        let report: serde_json::Value = serde_json::from_str(
            &maintenance_run_json(Some(cfg_path.clone()), MaintenanceTask::Retention).unwrap(),
        )
        .unwrap();
        assert_eq!(report["raw"]["deleted"], 0);
        assert_eq!(report["raw"]["blocked_by_archive"], true);

        // 仅写旧归档水位仍然不能删；必须 uploaded join。
        let storage = StorageHandle::sqlite(&db_path, DEFAULT_READ_POOL_SIZE).unwrap();
        storage
            .set_archive_state("last_archived_ts", &now.to_string(), now)
            .unwrap();
        drop(storage);
        let report: serde_json::Value = serde_json::from_str(
            &maintenance_run_json(Some(cfg_path.clone()), MaintenanceTask::Retention).unwrap(),
        )
        .unwrap();
        assert_eq!(
            report["raw"]["deleted"], 0,
            "last_archived_ts 不能单独证明 raw 可删"
        );
        assert_eq!(report["raw"]["blocked_by_archive"], true);
        assert_eq!(
            StorageHandle::sqlite(&db_path, DEFAULT_READ_POOL_SIZE)
                .unwrap()
                .raw_stats()
                .unwrap()
                .rows,
            3,
            "无 uploaded claim 时 raw 必须保留"
        );

        // 构造 v8 claim 并置 uploaded：此时 retention 才可删除。
        let storage = StorageHandle::sqlite(&db_path, DEFAULT_READ_POOL_SIZE).unwrap();
        let rows = storage.list_unclaimed_archive_rows(0, now + 1, 10).unwrap();
        assert_eq!(rows.len(), 3);
        let from_ts = rows.iter().map(|row| row.ts).min().unwrap();
        let to_ts = rows.iter().map(|row| row.ts).max().unwrap();
        let object = ArchiveObject {
            backend: "webdav".to_string(),
            object_key: "rustboard-test/claim-v8.csv.gz".to_string(),
            manifest_key: "rustboard-test/claim-v8.csv.gz.manifest.json".to_string(),
            from_ts,
            to_ts,
            rows: rows.len() as u64,
            ledger_version: LEDGER_VERSION_V8,
            status: ArchiveStatus::Pending,
            sha256: "0".repeat(64),
            created_at: now,
            ..ArchiveObject::default()
        };
        let id = storage.claim_archive_rows(&object, &rows).unwrap();
        storage
            .update_archive_object_status(id, ArchiveStatus::Uploaded, "", Some(now), None)
            .unwrap();
        drop(storage);

        let report: serde_json::Value = serde_json::from_str(
            &maintenance_run_json(Some(cfg_path), MaintenanceTask::Retention).unwrap(),
        )
        .unwrap();
        assert_eq!(report["raw"]["deleted"], 3);
        assert_eq!(report["raw"]["blocked_by_archive"], false);
        assert_eq!(
            StorageHandle::sqlite(&db_path, DEFAULT_READ_POOL_SIZE)
                .unwrap()
                .raw_stats()
                .unwrap()
                .rows,
            0
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M4-C1b：`GET /api/v1/archive/status` 需要 read scope，响应不含凭据。
    #[tokio::test]
    async fn m4c1b_archive_status_api_requires_read_scope() {
        let state = v6_auth_state();
        let router = admin_router(state.clone());

        let (status, _, body) =
            admin_call(&router, "GET", "/api/v1/archive/status", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(&body)["error"], "unauthorized");

        let read = v6_seed_token(&state, "archive-read", "read");
        let (status, _, body) =
            admin_call(&router, "GET", "/api/v1/archive/status", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK, "read token 应可读归档状态");
        let body = json_body(&body);
        assert_eq!(body["enabled"], false);
        assert_eq!(body["backend"], "webdav");
        assert_eq!(body["objects"], 0);
        assert!(body.get("url").is_none(), "不得返回后端 URL");

        // write 隐含 read；未知方法仍交给路由 405，不提前 403。
        let write = v6_seed_token(&state, "archive-write", "write");
        let (status, _, _) =
            admin_call(&router, "GET", "/api/v1/archive/status", Some(&write), None).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// M4-C4：旧库 / 人工写入带 URL 的 last_error，status API 必须掩码。
    #[tokio::test]
    async fn m4c4_archive_status_api_masks_unsafe_last_error() {
        let state = v6_auth_state();
        state
            .storage
            .set_archive_state(
                archive::STATE_LAST_ERROR,
                "https://user:pass@minio.internal/secret-bucket?X-Amz-Credential=AKIA_LEAK",
                1,
            )
            .unwrap();
        let read = v6_seed_token(&state, "archive-status-mask", "read");
        let router = admin_router(state.clone());

        let (status, _, body) =
            admin_call(&router, "GET", "/api/v1/archive/status", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        let text = String::from_utf8_lossy(&body).to_string();
        assert!(!text.contains("minio.internal"), "不得回显 URL");
        assert!(!text.contains("AKIA"), "不得回显凭据");
        assert!(!text.contains("user:pass"), "不得回显凭据");
        assert_eq!(json_body(&body)["last_error"], "archive_error");
    }

    // ------------------------------------------------------------------
    // M4-C2b：archive objects 列表 / 下载 / S3 archive test
    // ------------------------------------------------------------------

    fn archive_object_record(
        object_key: &str,
        status: ArchiveStatus,
        error: &str,
    ) -> ArchiveObject {
        ArchiveObject {
            id: 0,
            backend: "webdav".to_string(),
            object_key: object_key.to_string(),
            manifest_key: object_key.replace(".csv.gz", ".manifest.json"),
            from_ts: 1_700_000_000_000,
            to_ts: 1_700_003_600_000,
            rows: 42,
            bytes: 128,
            sha256: "a".repeat(64),
            status,
            error: error.to_string(),
            created_at: 1_700_000_000_000,
            uploaded_at: Some(1_700_000_000_000),
            deleted_at: None,
            ledger_version: 0,
            attempts: 0,
        }
    }

    /// 直接测试下载响应构造时使用的独立许可（body 生命周期由测试控制）。
    fn download_permit() -> OwnedSemaphorePermit {
        Arc::new(Semaphore::new(1))
            .try_acquire_owned()
            .expect("新建信号量必有 1 个许可")
    }

    /// 主体槽 + 全局槽各拿一个测试许可。
    fn download_permits() -> ArchiveDownloadPermits {
        ArchiveDownloadPermits {
            _principal: download_permit(),
            _global: download_permit(),
        }
    }

    /// M4-C4：主体槽 map 有上限；达到上限时清理无人持用的空闲槽。
    #[test]
    fn principal_slot_map_is_bounded_and_prunes_idle_entries() {
        let mut slots = HashMap::new();
        for index in 0..MAX_ARCHIVE_DOWNLOAD_PRINCIPALS {
            slots.insert(format!("p{index}"), Arc::new(Semaphore::new(1)));
        }
        let slots = StdMutex::new(slots);
        let permit = acquire_archive_principal_slot(&slots, "new-principal")
            .expect("空闲槽应被清理后容纳新主体");
        {
            let slots = slots.lock().unwrap();
            assert_eq!(slots.len(), 1, "空闲槽必须被清理");
            assert_eq!(
                slots.get("new-principal").unwrap().available_permits(),
                0,
                "新主体槽必须已被占用"
            );
        }
        drop(permit);
        assert_eq!(
            slots
                .lock()
                .unwrap()
                .get("new-principal")
                .unwrap()
                .available_permits(),
            1
        );
    }

    /// M4-C2b：对象列表按 id 倒序分页；error 只透传固定错误码，不泄露 URL。
    #[tokio::test]
    async fn m4c2b_archive_objects_list_paginates_and_sanitizes() {
        let state = v6_auth_state();
        let read = v6_seed_token(&state, "archive-objs-read", "read");
        let router = admin_router(state.clone());

        let (status, _, body) =
            admin_call(&router, "GET", "/api/v1/archive/objects", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(json_body(&body)["error"], "unauthorized");

        // 三行：id 越大越新；其中一行 error 带后端 URL，必须被收敛。
        for (key, status, error) in [
            (
                "rustboard/2026/10/22/part-00001.csv.gz",
                ArchiveStatus::Uploaded,
                "",
            ),
            (
                "rustboard/2026/10/23/part-00001.csv.gz",
                ArchiveStatus::LocalDeleted,
                "",
            ),
            (
                "rustboard/2026/10/24/part-00001.csv.gz",
                ArchiveStatus::Failed,
                "https://minio.internal/secret-bucket?X-Amz-Credential=AKIA_LEAK",
            ),
        ] {
            state
                .storage
                .insert_archive_object(&archive_object_record(key, status, error))
                .unwrap();
        }

        let (status, _, body) = admin_call(
            &router,
            "GET",
            "/api/v1/archive/objects?limit=2",
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let body_text = String::from_utf8_lossy(&body).to_string();
        assert!(!body_text.contains("minio.internal"), "不得回显后端 URL");
        assert!(!body_text.contains("AKIA"), "不得回显凭据");
        let body = json_body(&body);
        let objects = body["objects"].as_array().expect("objects 必须是数组");
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0]["id"], 3);
        assert_eq!(objects[1]["id"], 2);
        assert_eq!(objects[0]["status"], "failed");
        assert_eq!(objects[0]["error"], "archive_error");
        assert_eq!(
            objects[0]["downloadable"], false,
            "failed 状态不可下载（KI-31）"
        );
        assert_eq!(
            objects[1]["downloadable"], true,
            "local_deleted 且未超 64 MiB 可下载（KI-31）"
        );
        assert_eq!(objects[0]["rows"], 42);
        assert_eq!(objects[0]["bytes"], 128);
        assert_eq!(objects[0]["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(objects[0]["attempts"], 0);
        assert_eq!(objects[0]["rows_missing"], false);
        assert!(
            objects[0].get("backend").is_none(),
            "列表不返回 backend 字段"
        );
        assert!(objects[0].get("url").is_none(), "列表不返回后端 URL");
        assert_eq!(body["next_before_id"], 2);

        // 排他游标：下一页只返回 id < 2 的记录，且游标耗尽为 null。
        let (status, _, body) = admin_call(
            &router,
            "GET",
            "/api/v1/archive/objects?limit=2&before_id=2",
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let body = json_body(&body);
        let objects = body["objects"].as_array().unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0]["id"], 1);
        assert_eq!(
            objects[0]["downloadable"], true,
            "uploaded 且未超 64 MiB 可下载（KI-31）"
        );
        assert!(body["next_before_id"].is_null());

        // 参数边界：limit 1..=100、before_id 正整数、重复参数全部 400。
        for query in [
            "limit=0",
            "limit=101",
            "limit=abc",
            "before_id=0",
            "before_id=-1",
            "before_id=abc",
            "limit=2&limit=2",
            "before_id=1&before_id=2",
        ] {
            let (status, _, body) = admin_call(
                &router,
                "GET",
                &format!("/api/v1/archive/objects?{query}"),
                Some(&read),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "query={query}");
            assert_eq!(json_body(&body)["error"], "bad_request", "query={query}");
        }
    }

    /// R1a-2：对象视图暴露 attempts 与 rows_missing，固定错误码不被掩码。
    #[test]
    fn archive_object_view_exposes_rows_missing_and_attempts() {
        let mut object = archive_object_record(
            "rustboard/2026/10/24/part-00001-v8.csv.gz",
            ArchiveStatus::Failed,
            "rows_missing",
        );
        object.attempts = 3;
        let view = ArchiveObjectView::from(object);
        assert_eq!(view.attempts, 3);
        assert!(view.rows_missing);
        assert_eq!(view.error, "rows_missing");
        assert!(!view.downloadable);

        let mut other = archive_object_record(
            "rustboard/2026/10/24/part-00002-v8.csv.gz",
            ArchiveStatus::Failed,
            "backend_unavailable",
        );
        other.attempts = 1;
        let view = ArchiveObjectView::from(other);
        assert!(!view.rows_missing);
        assert_eq!(view.error, "backend_unavailable");
    }

    /// M4-C2b：下载 200 的响应头与字节；走真实 router + mock WebDAV。
    #[tokio::test]
    async fn m4c2b_archive_download_returns_headers_and_bytes() {
        use crate::archive_webdav::test_support::MockDav;

        let mock = MockDav::spawn().await;
        let mut cfg = HubConfig::default();
        cfg.archive.backend = rustboard_common::config::ArchiveBackend::Webdav;
        cfg.archive.webdav = Some(mock.config());
        let state = hub_state_with(cfg);
        let read = v6_seed_token(&state, "archive-dl-read", "read");
        let router = admin_router(state.clone());

        let key = "rustboard/2026/10/24/part-00001.csv.gz";
        let data = b"\x1f\x8b\x08\x00rustboard-gzip".to_vec();
        mock.inner
            .lock()
            .unwrap()
            .objects
            .insert(key.to_string(), data.clone());
        let mut object = archive_object_record(key, ArchiveStatus::Uploaded, "");
        object.bytes = data.len() as u64;
        object.sha256 = sha256_hex(&data);
        let id = state.storage.insert_archive_object(&object).unwrap();

        let (status, headers, body) = admin_call(
            &router,
            "GET",
            &format!("/api/v1/archive/objects/{id}/download"),
            Some(&read),
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
            &data.len().to_string()
        );
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "private, no-store"
        );
        assert_eq!(body, data, "下载字节必须与后端对象一致");
        assert!(!String::from_utf8_lossy(&body).contains("dav-password"));
    }

    /// M4-C4：数据库记录超过下载上限时 413，且不触碰后端（无 HEAD / GET）。
    #[tokio::test]
    async fn m4c4_archive_download_oversized_is_413_without_backend_io() {
        use crate::archive_webdav::test_support::MockDav;

        let mock = MockDav::spawn().await;
        let mut cfg = HubConfig::default();
        cfg.archive.backend = rustboard_common::config::ArchiveBackend::Webdav;
        cfg.archive.webdav = Some(mock.config());
        let state = hub_state_with(cfg);
        let read = v6_seed_token(&state, "archive-dl-large", "read");
        let router = admin_router(state.clone());

        let mut object = archive_object_record(
            "rustboard/2026/10/24/part-00001.csv.gz",
            ArchiveStatus::Uploaded,
            "",
        );
        object.bytes = MAX_ARCHIVE_DOWNLOAD_BYTES + 1;
        let id = state.storage.insert_archive_object(&object).unwrap();

        let (status, _, body) = admin_call(
            &router,
            "GET",
            &format!("/api/v1/archive/objects/{id}/download"),
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        let body = json_body(&body);
        assert_eq!(body["error"], "archive_too_large");
        assert!(
            body["message"].as_str().unwrap_or("").contains("64 MiB"),
            "413 文案必须说明 64 MiB 下载上限"
        );
        assert!(
            mock.inner.lock().unwrap().requests.is_empty(),
            "超限对象不得触碰后端"
        );
        assert_eq!(
            state.archive_download_slots.available_permits(),
            1,
            "超限对象不得占用全局下载许可（KI-31）"
        );
        assert_eq!(
            state
                .archive_download_principal_slots
                .lock()
                .unwrap()
                .get("archive-dl-large")
                .expect("主体槽已在取对象前创建")
                .available_permits(),
            1,
            "413 返回时主体槽必须已归还"
        );
    }

    /// M4-C4：同一主体已有请求时立即 429；释放后恢复，错误路径不泄漏。
    #[tokio::test]
    async fn m4c4_archive_download_busy_returns_429_without_queueing() {
        let state = v6_auth_state();
        let read = v6_seed_token(&state, "archive-dl-busy", "read");
        let object = archive_object_record(
            "rustboard/2026/10/24/part-00001.csv.gz",
            ArchiveStatus::Uploaded,
            "",
        );
        let id = state.storage.insert_archive_object(&object).unwrap();
        let uri = format!("/api/v1/archive/objects/{id}/download");
        let router = admin_router(state.clone());

        // 手工占用该主体的下载槽，模拟已有请求持有 / 等待全局 permit。
        let principal_semaphore = Arc::new(Semaphore::new(1));
        let held = principal_semaphore.clone().try_acquire_owned().unwrap();
        state
            .archive_download_principal_slots
            .lock()
            .unwrap()
            .insert(
                "archive-dl-busy".to_string(),
                Arc::clone(&principal_semaphore),
            );

        // 同一主体第二个请求立即 429，不进入等待队列。
        let (status, headers, body) = admin_call(&router, "GET", &uri, Some(&read), None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            headers.get(header::RETRY_AFTER).unwrap(),
            "1",
            "429 必须带 Retry-After: 1"
        );
        assert_eq!(json_body(&body)["error"], "archive_busy");
        assert_eq!(principal_semaphore.available_permits(), 0);

        drop(held);
        assert_eq!(principal_semaphore.available_permits(), 1);

        // 该测试没有配置后端：拿到主体槽与全局槽后返回固定 502，且许可归还。
        let (status, _, body) = admin_call(&router, "GET", &uri, Some(&read), None).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(json_body(&body)["error"], "archive_unavailable");
        assert_eq!(
            principal_semaphore.available_permits(),
            1,
            "错误路径不得泄漏主体槽"
        );
        assert_eq!(
            state.archive_download_slots.available_permits(),
            1,
            "错误路径不得泄漏全局槽"
        );
    }

    /// M4-C4：许可必须持有到响应 body 结束；慢读 / 取消都不能提前归还。
    #[tokio::test]
    async fn m4c4_archive_download_permit_held_until_body_dropped() {
        use crate::archive_webdav::test_support::MockDav;

        let mock = MockDav::spawn().await;
        let mut cfg = HubConfig::default();
        cfg.archive.backend = rustboard_common::config::ArchiveBackend::Webdav;
        cfg.archive.webdav = Some(mock.config());
        let state = hub_state_with(cfg);
        let read = v6_seed_token(&state, "archive-dl-body", "read");
        let router = admin_router(state.clone());

        let key = "rustboard/2026/10/24/part-00001.csv.gz";
        // 大于 64 KiB：body 会产生多个 chunk，便于验证“部分读取仍持有许可”。
        let data = vec![0x1f_u8; 200_000];
        mock.inner
            .lock()
            .unwrap()
            .objects
            .insert(key.to_string(), data.clone());
        let mut object = archive_object_record(key, ArchiveStatus::Uploaded, "");
        object.bytes = data.len() as u64;
        object.sha256 = sha256_hex(&data);
        let id = state.storage.insert_archive_object(&object).unwrap();
        let uri = format!("/api/v1/archive/objects/{id}/download");

        // 第一个响应不读 body：许可应仍在 body 里。
        let first = admin_response(&router, "GET", &uri, &read).await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            state.archive_download_slots.available_permits(),
            0,
            "body 未读时许可不得提前释放"
        );

        // 第二个下载不排队：立即 429，不能持续占用唯一 permit。
        let (status, headers, body) = admin_call(&router, "GET", &uri, Some(&read), None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers.get(header::RETRY_AFTER).unwrap(), "1");
        assert_eq!(json_body(&body)["error"], "archive_busy");
        assert_eq!(state.archive_download_slots.available_permits(), 0);

        // 慢读：只取一帧，许可仍由第一个 body 持有。
        let mut first_body = Box::pin(first.into_body());
        let frame = std::future::poll_fn(|cx| first_body.as_mut().poll_frame(cx)).await;
        assert!(frame.is_some(), "应能读到第一帧");
        assert_eq!(
            state.archive_download_slots.available_permits(),
            0,
            "部分读取期间许可不得释放"
        );

        // drop 第一个 body → 许可归还。
        drop(first_body);
        assert_eq!(
            state.archive_download_slots.available_permits(),
            1,
            "body drop 后许可必须归还"
        );

        // 再次下载成功；其 body 存活期间同样占用许可，drop 后归还。
        let third = admin_response(&router, "GET", &uri, &read).await;
        assert_eq!(third.status(), StatusCode::OK);
        assert_eq!(state.archive_download_slots.available_permits(), 0);
        drop(third);
        assert_eq!(state.archive_download_slots.available_permits(), 1);
    }

    /// M4-C4：不同 principal 公平排队；同一 principal 32 连接只能全部 429。
    #[tokio::test]
    async fn m4c4_archive_download_per_principal_fairness() {
        use crate::archive_webdav::test_support::MockDav;

        let mock = MockDav::spawn().await;
        let mut cfg = HubConfig::default();
        cfg.archive.backend = rustboard_common::config::ArchiveBackend::Webdav;
        cfg.archive.webdav = Some(mock.config());
        // 发送期限保持默认 120s：本测试只验证排队，不依赖超时。
        let state = hub_state_with(cfg);
        let alice = v6_seed_token(&state, "alice", "read");
        let bob = v6_seed_token(&state, "bob", "read");
        let router = admin_router(state.clone());

        let key = "rustboard/2026/10/24/part-00001.csv.gz";
        let data = vec![0x1f_u8; 128 * 1024];
        mock.inner
            .lock()
            .unwrap()
            .objects
            .insert(key.to_string(), data.clone());
        let mut object = archive_object_record(key, ArchiveStatus::Uploaded, "");
        object.bytes = data.len() as u64;
        object.sha256 = sha256_hex(&data);
        let id = state.storage.insert_archive_object(&object).unwrap();
        let uri = format!("/api/v1/archive/objects/{id}/download");

        // Alice 持有一个未读完的 body（主体槽 + 全局槽都在 body 里）。
        let alice_first = admin_response(&router, "GET", &uri, &alice).await;
        assert_eq!(alice_first.status(), StatusCode::OK);
        assert_eq!(state.archive_download_slots.available_permits(), 0);

        // Bob 拿到自己的主体槽，然后按 FIFO 等待全局 permit。
        let bob_waiter = {
            let router = router.clone();
            let bob = bob.clone();
            let uri = uri.clone();
            tokio::spawn(async move { admin_call(&router, "GET", &uri, Some(&bob), None).await })
        };
        let mut bob_waiter = bob_waiter;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut bob_waiter)
                .await
                .is_err(),
            "Alice 持有时 Bob 必须等待全局 permit"
        );

        // Alice 再用 32 条连接抢：全部在主体槽处立即 429，不能插到 Bob 前面。
        let mut alice_burst = Vec::new();
        for _ in 0..32 {
            let router = router.clone();
            let alice = alice.clone();
            let uri = uri.clone();
            alice_burst.push(tokio::spawn(async move {
                admin_call(&router, "GET", &uri, Some(&alice), None).await
            }));
        }
        for task in alice_burst {
            let (status, _, body) = task.await.unwrap();
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(json_body(&body)["error"], "archive_busy");
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut bob_waiter)
                .await
                .is_err(),
            "Alice 的 32 条连接不得插队，Bob 仍在等待"
        );

        // Alice 的 body drop 后，Bob 按 FIFO 获得全局 permit 并成功。
        drop(alice_first);
        let (status, _, body) = bob_waiter.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, data);
        assert_eq!(state.archive_download_slots.available_permits(), 1);

        // 取消排队等待：Bob 的等待 future 被 abort 后主体槽立即释放，
        // 下一次 Bob 请求仍可在 Alice 结束后成功。
        let alice_second = admin_response(&router, "GET", &uri, &alice).await;
        assert_eq!(alice_second.status(), StatusCode::OK);
        let bob_cancelled = {
            let router = router.clone();
            let bob = bob.clone();
            let uri = uri.clone();
            tokio::spawn(async move { admin_call(&router, "GET", &uri, Some(&bob), None).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        bob_cancelled.abort();
        let _ = bob_cancelled.await;
        let bob_slot = state
            .archive_download_principal_slots
            .lock()
            .unwrap()
            .get("bob")
            .cloned()
            .unwrap();
        assert_eq!(
            bob_slot.available_permits(),
            1,
            "取消等待必须释放 Bob 的主体槽"
        );
        drop(alice_second);
        let (status, _, body) = admin_call(&router, "GET", &uri, Some(&bob), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, data);
    }

    /// M4-C4：不读 body 时后台定时任务必须清空数据并归还两层许可，后续 poll 报错。
    #[tokio::test]
    async fn m4c4_archive_download_body_timeout_releases_memory_and_permit() {
        let principal = Arc::new(Semaphore::new(1));
        let global = Arc::new(Semaphore::new(1));
        let permits = ArchiveDownloadPermits {
            _principal: principal.clone().try_acquire_owned().unwrap(),
            _global: global.clone().try_acquire_owned().unwrap(),
        };
        let mut body = Box::pin(ArchiveDownloadBody::new(
            Bytes::from(vec![7_u8; 1024]),
            permits,
            Duration::from_millis(50),
        ));
        let state = body.shared_state();
        {
            let state = state.lock().unwrap();
            assert!(state.data.is_some());
            assert!(state.permits.is_some());
            assert!(!state.expired);
        }
        assert_eq!(principal.available_permits(), 0);
        assert_eq!(global.available_permits(), 0);

        tokio::time::sleep(Duration::from_millis(150)).await;
        {
            let state = state.lock().unwrap();
            assert!(state.expired, "超时后 body 应标记为过期");
            assert!(state.data.is_none(), "超时必须释放对象数据");
            assert!(state.permits.is_none(), "超时必须移出两层许可");
        }
        assert_eq!(principal.available_permits(), 1, "超时必须归还主体槽");
        assert_eq!(global.available_permits(), 1, "超时必须归还全局槽");

        let frame = std::future::poll_fn(|cx| body.as_mut().poll_frame(cx)).await;
        match frame {
            Some(Err(error)) => {
                assert!(
                    error.to_string().contains(ARCHIVE_DOWNLOAD_TIMEOUT_ERROR),
                    "错误必须是固定超时文案: {error}"
                );
            }
            other => panic!("超时后 poll 必须返回错误，实际 {other:?}"),
        }
    }

    /// M4-C4：body 在期限前 drop 时必须 abort 定时任务并立即归还两层许可。
    #[tokio::test]
    async fn m4c4_archive_download_body_drop_cancels_timeout() {
        let principal = Arc::new(Semaphore::new(1));
        let global = Arc::new(Semaphore::new(1));
        let permits = ArchiveDownloadPermits {
            _principal: principal.clone().try_acquire_owned().unwrap(),
            _global: global.clone().try_acquire_owned().unwrap(),
        };
        let body = ArchiveDownloadBody::new(
            Bytes::from(vec![0_u8; 128]),
            permits,
            Duration::from_millis(200),
        );
        let state = body.shared_state();
        drop(body);
        assert_eq!(
            principal.available_permits(),
            1,
            "drop body 必须立即归还主体槽"
        );
        assert_eq!(
            global.available_permits(),
            1,
            "drop body 必须立即归还全局槽"
        );

        tokio::time::sleep(Duration::from_millis(300)).await;
        let state = state.lock().unwrap();
        assert!(!state.expired, "body drop 后定时任务不得再触发");
        assert!(state.data.is_none());
        assert!(state.permits.is_none());
    }

    /// M4-C4：已认证客户端不读 body 时，期限到期后下一次下载必须能成功。
    #[tokio::test]
    async fn m4c4_archive_download_timeout_releases_permit_for_next_download() {
        use crate::archive_webdav::test_support::MockDav;

        let mock = MockDav::spawn().await;
        let mut cfg = HubConfig::default();
        cfg.archive.backend = rustboard_common::config::ArchiveBackend::Webdav;
        cfg.archive.webdav = Some(mock.config());
        let state = hub_state_with_download_timeout(cfg, Duration::from_secs(1));
        let read = v6_seed_token(&state, "archive-dl-timeout", "read");
        let router = admin_router(state.clone());

        let key = "rustboard/2026/10/24/part-00001.csv.gz";
        let data = vec![0x1f_u8; 128 * 1024];
        mock.inner
            .lock()
            .unwrap()
            .objects
            .insert(key.to_string(), data.clone());
        let mut object = archive_object_record(key, ArchiveStatus::Uploaded, "");
        object.bytes = data.len() as u64;
        object.sha256 = sha256_hex(&data);
        let id = state.storage.insert_archive_object(&object).unwrap();
        let uri = format!("/api/v1/archive/objects/{id}/download");

        // 第一个客户端只拿响应头，不读 body。
        let first = admin_response(&router, "GET", &uri, &read).await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(state.archive_download_slots.available_permits(), 0);

        // 等待发送期限到期；不依赖客户端 poll body。
        let wait_until = std::time::Instant::now() + Duration::from_secs(3);
        while state.archive_download_slots.available_permits() == 0
            && std::time::Instant::now() < wait_until
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            state.archive_download_slots.available_permits(),
            1,
            "发送期限到期必须归还许可"
        );

        // 已超时的第一个 body 只能返回固定错误。
        let mut first_body = Box::pin(first.into_body());
        let frame = std::future::poll_fn(|cx| first_body.as_mut().poll_frame(cx)).await;
        assert!(
            matches!(frame, Some(Err(_))),
            "超时后的第一个 body 必须报错"
        );
        drop(first_body);

        // 下一个下载能重新获得许可并成功读取完整对象。
        let (status, _, body) = admin_call(&router, "GET", &uri, Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, data);
        assert_eq!(
            state.archive_download_slots.available_permits(),
            1,
            "正常读完 body 后许可应归还"
        );
    }

    /// M4-C2b：下载的状态码与路径 id 校验；后端不可用时固定 502，不泄露细节。
    #[tokio::test]
    async fn m4c2b_archive_download_maps_404_409_502_and_rejects_bad_ids() {
        let state = v6_auth_state();
        let read = v6_seed_token(&state, "archive-dl-errors", "read");
        let router = admin_router(state.clone());

        // 未认证 → 401（即便 id 非法也先鉴权）。
        let (status, _, _) = admin_call(
            &router,
            "GET",
            "/api/v1/archive/objects/abc/download",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // 路径 id 必须是 ASCII 数字正整数。
        for id in ["abc", "0", "-1", "1.5", "%2e%2e", "9999999999999999999"] {
            let (status, _, body) = admin_call(
                &router,
                "GET",
                &format!("/api/v1/archive/objects/{id}/download"),
                Some(&read),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "id={id}");
            assert_eq!(json_body(&body)["error"], "bad_request", "id={id}");
        }

        // 不存在 → 404。
        let (status, _, _) = admin_call(
            &router,
            "GET",
            "/api/v1/archive/objects/999/download",
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // pending / failed → 409 archive_not_ready。
        let pending = state
            .storage
            .insert_archive_object(&archive_object_record(
                "rustboard/2026/10/24/part-00002.csv.gz",
                ArchiveStatus::Pending,
                "",
            ))
            .unwrap();
        let (status, _, body) = admin_call(
            &router,
            "GET",
            &format!("/api/v1/archive/objects/{pending}/download"),
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(json_body(&body)["error"], "archive_not_ready");

        // uploaded 但后端未配置：502 固定码，不回显后端配置。
        let uploaded = state
            .storage
            .insert_archive_object(&archive_object_record(
                "rustboard/2026/10/24/part-00003.csv.gz",
                ArchiveStatus::Uploaded,
                "",
            ))
            .unwrap();
        let (status, _, body) = admin_call(
            &router,
            "GET",
            &format!("/api/v1/archive/objects/{uploaded}/download"),
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let body = json_body(&body);
        assert_eq!(body["error"], "archive_unavailable");
        assert!(!body.to_string().contains("webdav"));
        assert!(!body.to_string().contains("archive.webdav"));
    }

    /// M4-C4：下载 64 MiB 上限、短读 / 篡改校验；超限必须在 get 前拒绝。
    #[tokio::test]
    async fn m4c4_archive_download_response_enforces_size_and_integrity() {
        use crate::archive_s3::S3ColdStore;
        use object_store::memory::InMemory;

        let store = S3ColdStore::with_store(Arc::new(InMemory::new()));
        let key = "rustboard/2026/10/24/part-00009.csv.gz";

        // 缺失对象 → 502。
        let object = archive_object_record(key, ArchiveStatus::Uploaded, "");
        let error = archive_download_response(
            &object,
            &store,
            download_permits(),
            ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
        )
        .await
        .map(|_| ())
        .expect_err("缺失对象必须失败");
        assert!(matches!(
            error,
            ApiError::BadGateway {
                code: "archive_unavailable",
                ..
            }
        ));

        // 数据库记录超过 64 MiB → 413；对象不存在也必须是 413（证明未 get）。
        let mut oversized = archive_object_record(key, ArchiveStatus::Uploaded, "");
        oversized.bytes = MAX_ARCHIVE_DOWNLOAD_BYTES + 1;
        let error = archive_download_response(
            &oversized,
            &store,
            download_permits(),
            ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
        )
        .await
        .map(|_| ())
        .expect_err("超限对象必须失败");
        assert!(matches!(
            error,
            ApiError::TooLarge {
                code: "archive_too_large",
                ..
            }
        ));

        // HEAD 大小超限、数据库记录很小 → 413；用计数 store 证明没有调用 get。
        let get_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let head_store = HeadOnlyStore {
            size: 17,
            get_calls: get_calls.clone(),
        };
        let mut small_record = archive_object_record(key, ArchiveStatus::Uploaded, "");
        small_record.bytes = 1;
        let error = archive_download_response_with_limit(
            &small_record,
            &head_store,
            16,
            download_permits(),
            ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
        )
        .await
        .map(|_| ())
        .expect_err("HEAD 超限必须失败");
        assert!(matches!(
            error,
            ApiError::TooLarge {
                code: "archive_too_large",
                ..
            }
        ));
        assert_eq!(
            get_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "HEAD 超限不得读取对象 body"
        );

        // 短读：实际 5 字节，数据库记录 10 字节 → 502。
        let data = b"short".to_vec();
        store.put(key, &data).await.unwrap();
        let mut short_record = archive_object_record(key, ArchiveStatus::Uploaded, "");
        short_record.bytes = 10;
        short_record.sha256 = sha256_hex(&data);
        let error = archive_download_response_with_limit(
            &short_record,
            &store,
            1024,
            download_permits(),
            ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
        )
        .await
        .map(|_| ())
        .expect_err("短读必须失败");
        assert!(matches!(
            error,
            ApiError::BadGateway {
                code: "archive_unavailable",
                ..
            }
        ));

        // 篡改：长度一致但 SHA-256 不符 → 502。
        let mut tampered = archive_object_record(key, ArchiveStatus::Uploaded, "");
        tampered.bytes = data.len() as u64;
        tampered.sha256 = "0".repeat(64);
        let error = archive_download_response_with_limit(
            &tampered,
            &store,
            1024,
            download_permits(),
            ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
        )
        .await
        .map(|_| ())
        .expect_err("SHA-256 不符必须失败");
        assert!(matches!(
            error,
            ApiError::BadGateway {
                code: "archive_unavailable",
                ..
            }
        ));

        // 非标准 key（无法重新构造安全文件名）→ 502，避免 header 注入。
        let weird = archive_object_record(
            "../evil/2026/10/24/part-00001.csv.gz",
            ArchiveStatus::Uploaded,
            "",
        );
        let error = archive_download_response(
            &weird,
            &store,
            download_permits(),
            ARCHIVE_DOWNLOAD_SEND_TIMEOUT,
        )
        .await
        .map(|_| ())
        .expect_err("非标准 key 必须失败");
        assert!(matches!(
            error,
            ApiError::BadGateway {
                code: "archive_unavailable",
                ..
            }
        ));
    }

    /// 测试用 ColdStore：HEAD 返回指定大小，get 只计数不返回数据。
    struct HeadOnlyStore {
        size: u64,
        get_calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ColdStore for HeadOnlyStore {
        async fn put(
            &self,
            _key: &str,
            _data: &[u8],
        ) -> rustboard_core::archive::ArchiveResult<()> {
            unimplemented!("测试 store 不支持 put")
        }

        async fn get(&self, _key: &str) -> rustboard_core::archive::ArchiveResult<Vec<u8>> {
            self.get_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(rustboard_core::archive::ArchiveError::BackendUnavailable)
        }

        async fn delete(&self, _key: &str) -> rustboard_core::archive::ArchiveResult<()> {
            unimplemented!("测试 store 不支持 delete")
        }

        async fn head(
            &self,
            _key: &str,
        ) -> rustboard_core::archive::ArchiveResult<Option<rustboard_core::archive::ColdObjectMeta>>
        {
            Ok(Some(rustboard_core::archive::ColdObjectMeta {
                size: self.size,
            }))
        }

        async fn test(&self) -> rustboard_core::archive::ArchiveResult<()> {
            unimplemented!("测试 store 不支持 test")
        }
    }

    /// M4-C2b：`archive test` 支持 S3，backend 输出实际配置值；探针不联网。
    #[test]
    fn m4c2b_archive_test_supports_s3_with_injected_store() {
        use crate::archive_s3::S3ColdStore;
        use object_store::memory::InMemory;
        use rustboard_common::config::{ArchiveBackend, ArchiveS3Config};

        let mut cfg = HubConfig::default();
        cfg.archive.backend = ArchiveBackend::S3;
        cfg.archive.enabled = true;
        cfg.archive.s3 = Some(ArchiveS3Config {
            bucket: "rustboard-test".to_string(),
            region: "us-east-1".to_string(),
            endpoint: "http://127.0.0.1:9000".to_string(),
            access_key_id: "test-access-key".to_string(),
            secret_access_key: "test-secret-key".to_string(),
            path_style: true,
        });
        let store = S3ColdStore::with_store(Arc::new(InMemory::new()));

        let output = archive_test_with_store(&cfg, &store).unwrap();
        let output: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(output["ok"], true);
        assert_eq!(output["backend"], "s3");
        assert!(
            !output.to_string().contains("secret"),
            "archive test 输出不得包含凭据"
        );
        assert!(!output.to_string().contains("127.0.0.1"));
    }

    /// M4-A2：后台单轮串行执行，失败写 last_error、整轮成功后清空。
    #[test]
    fn m4a_maintenance_round_records_and_clears_last_error() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let cfg = HubConfig::default();

        // 先留一条旧错误：成功一轮必须清空。
        storage
            .set_maintenance_state(downsample::STATE_LAST_ERROR, "old failure", now_ms())
            .unwrap();
        run_maintenance_round(&storage, &cfg);
        assert_eq!(
            storage
                .get_maintenance_state(downsample::STATE_LAST_ERROR)
                .unwrap(),
            Some(String::new())
        );

        // 损坏 1m 水位：降采样失败并记录前缀。R1b 的保留期只依赖
        // aggregated_1m / aggregated_1h / 归档 ledger，不再读旧水位，因此
        // 保留期本轮应成功，不得把 1m 水位错误重复算到 retention 前缀下。
        storage
            .set_maintenance_state(
                downsample::STATE_DOWNSAMPLE_1M_WATERMARK,
                "not-a-number",
                now_ms(),
            )
            .unwrap();
        run_maintenance_round(&storage, &cfg);
        let recorded = storage
            .get_maintenance_state(downsample::STATE_LAST_ERROR)
            .unwrap()
            .unwrap_or_default();
        assert!(
            recorded.contains("downsample:"),
            "缺少降采样错误: {recorded}"
        );
        assert!(
            !recorded.contains("retention:"),
            "R1b retention 不再依赖旧水位，本轮不应失败: {recorded}"
        );

        // 修好水位后下一轮恢复并清空错误。
        storage
            .set_maintenance_state(downsample::STATE_DOWNSAMPLE_1M_WATERMARK, "", now_ms())
            .unwrap();
        run_maintenance_round(&storage, &cfg);
        assert_eq!(
            storage
                .get_maintenance_state(downsample::STATE_LAST_ERROR)
                .unwrap(),
            Some(String::new())
        );
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
        let handle = m3_register_agent(&state, "a1", &["systemd"]).await;
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
        let mut handle = m3_register_agent(&state, "a1", &["systemd"]).await;
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
        let mut handle = m3_register_agent(&state, "a1", &["systemd"]).await;

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
        let mut handle = m3_register_agent(&state, "a1", &["systemd"]).await;
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

    // ------------------------------------------------------------------
    // v0.4.1：KI-31 下载判定 / KI-28 拒绝日志采样 / KI-20 shell 引用
    // ------------------------------------------------------------------

    /// KI-31：downloadable 只由状态与固定 64 MiB 下载硬限决定。
    #[test]
    fn ki31_archive_object_downloadable_uses_fixed_limit() {
        let mut object = archive_object_record(
            "rustboard/2026/10/24/part-00001.csv.gz",
            ArchiveStatus::Uploaded,
            "",
        );
        object.bytes = MAX_ARCHIVE_DOWNLOAD_BYTES;
        assert!(
            archive_object_downloadable(&object),
            "恰好 64 MiB 必须可下载"
        );
        object.bytes = MAX_ARCHIVE_DOWNLOAD_BYTES + 1;
        assert!(
            !archive_object_downloadable(&object),
            "64 MiB + 1 必须不可下载"
        );

        object.bytes = 1;
        for status in [ArchiveStatus::Failed, ArchiveStatus::Pending] {
            object.status = status;
            assert!(!archive_object_downloadable(&object), "{status:?} 不可下载");
        }
        for status in [ArchiveStatus::Uploaded, ArchiveStatus::LocalDeleted] {
            object.status = status;
            assert!(archive_object_downloadable(&object), "{status:?} 可下载");
        }

        let view = serde_json::to_value(ArchiveObjectView::from(object)).unwrap();
        assert_eq!(view["downloadable"], true, "JSON 必须包含 downloadable");
    }

    /// KI-28：同 IP 每窗口首条采样、不同 IP 独立、60s 边界重置。
    #[test]
    fn ki28_reject_log_sampler_window_and_per_ip() {
        use std::sync::atomic::AtomicI64;

        let clock = Arc::new(AtomicI64::new(1_000_000));
        let clock_handle = clock.clone();
        let mut sampler =
            RejectLogSampler::with_clock(Arc::new(move || clock_handle.load(Ordering::Relaxed)));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        assert_eq!(
            sampler.record(ip1),
            RejectLogSample {
                rejected: 1,
                first_in_window: true
            }
        );
        assert_eq!(
            sampler.record(ip1),
            RejectLogSample {
                rejected: 2,
                first_in_window: false
            }
        );
        assert_eq!(
            sampler.record(ip1),
            RejectLogSample {
                rejected: 3,
                first_in_window: false
            }
        );
        // 不同 IP 不共享窗口。
        assert_eq!(
            sampler.record(ip2),
            RejectLogSample {
                rejected: 1,
                first_in_window: true
            }
        );

        // 窗口内 59.999s 仍是后续拒绝。
        clock.store(1_000_000 + 59_999, Ordering::Relaxed);
        assert_eq!(
            sampler.record(ip1),
            RejectLogSample {
                rejected: 4,
                first_in_window: false
            }
        );
        // 恰好 60s：本 IP 进入新窗口，重新 WARN。
        clock.store(1_000_000 + REJECT_LOG_WINDOW_MS, Ordering::Relaxed);
        assert_eq!(
            sampler.record(ip1),
            RejectLogSample {
                rejected: 1,
                first_in_window: true
            }
        );
    }

    /// KI-28：采样表最多 4096 个 IP；插入前清理过期，满表不再增长。
    #[test]
    fn ki28_reject_log_sampler_table_capacity_is_bounded() {
        use std::sync::atomic::AtomicI64;

        let clock = Arc::new(AtomicI64::new(1_000_000));
        let clock_handle = clock.clone();
        let mut sampler =
            RejectLogSampler::with_clock(Arc::new(move || clock_handle.load(Ordering::Relaxed)));
        for index in 0..REJECT_LOG_TABLE_CAPACITY {
            let ip = IpAddr::from(std::net::Ipv4Addr::from(index as u32 + 1));
            assert!(
                sampler.record(ip).first_in_window,
                "容量内新来源首条应 WARN"
            );
        }
        assert_eq!(sampler.tracked_ips(), REJECT_LOG_TABLE_CAPACITY);

        // 表满且无过期项：新来源不产生 WARN，也不增长采样表。
        let overflow: IpAddr = "203.0.113.9".parse().unwrap();
        let sample = sampler.record(overflow);
        assert!(!sample.first_in_window, "满表时新来源不得放大 WARN");
        assert_eq!(
            sampler.tracked_ips(),
            REJECT_LOG_TABLE_CAPACITY,
            "采样表必须保持有界"
        );
        // 已跟踪 IP 仍正常计数。
        let tracked = IpAddr::from(std::net::Ipv4Addr::from(1_u32));
        assert_eq!(sampler.record(tracked).rejected, 2);

        // 推进一个窗口后，过期项被清理，新来源恢复 WARN。
        clock.store(1_000_000 + REJECT_LOG_WINDOW_MS, Ordering::Relaxed);
        let sample = sampler.record(overflow);
        assert!(sample.first_in_window, "过期清理后新来源应重新 WARN");
        assert!(sampler.tracked_ips() <= REJECT_LOG_TABLE_CAPACITY);
    }

    /// KI-20：安全字符集不加引号，其余字符用 POSIX 单引号安全包裹。
    #[test]
    fn ki20_shell_arg_quotes_only_when_needed() {
        for safe in [
            "web-01",
            "wss://hub.example.com:8443/agent/ws",
            "0123456789abcdef",
            "/tmp/rustboard_data",
            "a.b_c/d:e@f%g+h,i",
        ] {
            assert_eq!(shell_arg(safe), safe, "安全值必须逐字节不变");
        }
        assert_eq!(shell_arg(""), "''");
        assert_eq!(shell_arg("web 01"), "'web 01'");
        assert_eq!(shell_arg("web'01"), r"'web'\''01'");
        for unsafe_value in [
            "web$(printf INJECTED)",
            "web`printf INJECTED`",
            "web;printf INJECTED",
            "web|printf INJECTED",
            "web&printf INJECTED",
            "web#printf INJECTED",
            "web\n01",
        ] {
            assert_eq!(
                shell_arg(unsafe_value),
                format!("'{unsafe_value}'"),
                "危险字符必须整体单引号包裹: {unsafe_value:?}"
            );
        }
    }

    /// 容器升级回归：`agent add` 只校验 TLS，不得因 data_dir 属于 10001 而失败。
    #[test]
    fn c2_agent_add_validation_ignores_data_dir_owner() {
        let cfg = HubConfig {
            // 容器中该目录属于 UID 10001，root CLI 不能通过完整 HubConfig::validate。
            data_dir: PathBuf::from("/data/var/lib/rustboard/hub"),
            database: "sqlite:///data/var/lib/rustboard/hub/rustboard.db".to_string(),
            ..HubConfig::default()
        };
        validate_agent_add_config(&cfg).expect("agent add 不得校验 data_dir 属主");
    }

    /// C2：`hub agent add` 的输出必须跟随 hub 的 TLS 模式；ACME hub 绝不输出指纹。
    #[test]
    fn c2_agent_install_command_follows_hub_tls_mode() {
        use rustboard_common::config::TlsConfig;

        // self-signed：保持旧行为，信任来源是指纹。
        let self_signed = HubConfig::default();
        assert_eq!(
            hub_agent_trust(&self_signed),
            HubAgentTrust::Fingerprint,
            "旧配置/自签 hub 必须继续输出 --fingerprint"
        );

        // 公共 ACME：系统根，主机名来自 tls.domains。
        let public_acme = HubConfig {
            server_names: Vec::new(),
            tls: TlsConfig {
                mode: ServerTlsMode::AcmeDomain,
                acme_email: "admin@example.com".to_string(),
                domains: vec!["board.example.com".to_string()],
                ..TlsConfig::default()
            },
            ..HubConfig::default()
        };
        assert_eq!(hub_agent_trust(&public_acme), HubAgentTrust::SystemRoots);
        assert_eq!(
            hub_agent_ws_url(&public_acme).unwrap(),
            "wss://board.example.com:8443/agent/ws",
            "ACME 模式主机名必须来自 tls.domains"
        );

        // ACME 模式显式 advertise_host 必须被证书名覆盖，否则生成的 URL
        // 必然在主机名校验阶段失败；空值仍按 effective names 选择。
        let mut bad_advertise = public_acme.clone();
        bad_advertise.advertise_host = Some("other.example.com".to_string());
        let err = hub_agent_ws_url(&bad_advertise).unwrap_err().to_string();
        assert!(
            err.contains("advertise_host") && err.contains("tls.domains"),
            "错误信息: {err}"
        );
        bad_advertise.advertise_host = Some("BOARD.EXAMPLE.COM".to_string());
        assert_eq!(
            hub_agent_ws_url(&bad_advertise).unwrap(),
            "wss://BOARD.EXAMPLE.COM:8443/agent/ws",
            "DNS 名匹配应大小写不敏感"
        );

        // 私有 ACME：custom-ca（信任锚在 agent add 时从 server.crt 链尾生成，
        // 绝不再把 acme_ca_file 当作 agent CA）。
        let mut private_tls = public_acme.tls.clone();
        private_tls.acme_ca_file = "/etc/rustboard/pebble-ca.pem".to_string();
        let private_acme = HubConfig {
            tls: private_tls,
            ..public_acme.clone()
        };
        assert_eq!(hub_agent_trust(&private_acme), HubAgentTrust::CustomCa);

        // acme-ip 的主机名是 IP 字符串。
        let ip_acme = HubConfig {
            server_names: Vec::new(),
            tls: TlsConfig {
                mode: ServerTlsMode::AcmeIp,
                acme_email: "admin@example.com".to_string(),
                domains: vec!["203.0.113.10".to_string()],
                ..TlsConfig::default()
            },
            ..HubConfig::default()
        };
        assert_eq!(hub_agent_trust(&ip_acme), HubAgentTrust::SystemRoots);
        assert_eq!(
            hub_agent_ws_url(&ip_acme).unwrap(),
            "wss://203.0.113.10:8443/agent/ws"
        );

        // 命令渲染：fingerprint 逐字节不变；ACME 只出现 --tls-mode，不出现指纹。
        let token = "0123456789abcdef".repeat(4);
        let fingerprint = "fedcba9876543210".repeat(4);
        let url = "wss://board.example.com:8443/agent/ws";
        let fingerprint_command = render_install_command(url, &token, &fingerprint, "web-01");
        assert_eq!(
            fingerprint_command,
            format!(
                "rustboard-agent init --hub {url} \\\n    \
                 --token {token} --fingerprint {fingerprint} --name web-01"
            ),
            "self-signed 输出必须与 v0.4 完全一致"
        );

        let system_roots =
            render_agent_install_command(url, &token, "web-01", AgentInstallTrust::SystemRoots);
        assert_eq!(
            system_roots,
            format!(
                "rustboard-agent init --hub {url} \\\n    \
                 --token {token} --tls-mode system-roots --name web-01"
            )
        );
        assert!(
            !system_roots.contains("fingerprint"),
            "ACME 命令不得出现指纹: {system_roots}"
        );

        let custom_ca = render_agent_install_command(
            url,
            &token,
            "web-01",
            AgentInstallTrust::CustomCa("/etc/rustboard/pebble-ca.pem"),
        );
        assert!(
            custom_ca.contains("--tls-mode custom-ca --server-ca /etc/rustboard/pebble-ca.pem"),
            "{custom_ca}"
        );
        assert!(!custom_ca.contains("fingerprint"), "{custom_ca}");

        // CA 路径含空格时仍要安全引用，不能拆成新的 shell 词。
        let quoted = render_agent_install_command(
            url,
            &token,
            "web-01",
            AgentInstallTrust::CustomCa("/etc/rust board/ca.pem"),
        );
        assert!(
            quoted.contains("--server-ca '/etc/rust board/ca.pem'"),
            "{quoted}"
        );

        assert!(
            ACME_AGENT_UPGRADE_NOTICE.contains("v0.4 指纹 agent 不兼容 ACME hub，请升级"),
            "升级提示必须点明 v0.4 agent 不兼容"
        );
    }

    /// C4：私有 ACME 的 agent CA 必须来自 `server.crt` 链尾，而不是
    /// `tls.acme_ca_file`（后者只是 ACME WFE 的 HTTPS 根）。
    #[cfg(unix)]
    #[test]
    fn c4_private_acme_agent_ca_uses_certificate_chain_tail() {
        use rustboard_common::config::TlsConfig;
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("private-acme-agent-ca");
        let data_dir = dir.join("hub");
        let cert_dir = tls::cert_dir(&data_dir);
        fsutil::ensure_dir(&cert_dir, 0o700).unwrap();

        // 构造真实链：叶子（clientAuth 不影响提取）+ 自签 CA。
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Test ACME Root");
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
        let (csr, _leaf_key) = tls::make_csr().unwrap();
        let leaf_pem = tls::sign_client_csr(&ca_key.serialize_pem(), &csr, "hub-leaf", 90).unwrap();
        let cert_path = cert_dir.join(tls::SERVER_CERT_FILE);
        fsutil::atomic_write(&cert_path, format!("{leaf_pem}{ca_pem}").as_bytes(), 0o600).unwrap();

        let cfg = HubConfig {
            data_dir: data_dir.clone(),
            tls: TlsConfig {
                mode: ServerTlsMode::AcmeDomain,
                acme_email: "admin@example.com".to_string(),
                domains: vec!["board.example.com".to_string()],
                acme_ca_file: "/etc/rustboard/pebble-wfe-ca.pem".to_string(),
                ..TlsConfig::default()
            },
            ..HubConfig::default()
        };
        let out = prepare_private_acme_agent_ca(&cfg, FsPath::new("/tmp/hub.toml")).unwrap();
        assert_eq!(out, cert_dir.join("agent-ca.pem"));
        let written = std::fs::read_to_string(&out).unwrap();
        assert_eq!(
            tls::fingerprint_of_pem(&written).unwrap(),
            tls::fingerprint_of_pem(&ca_pem).unwrap(),
            "agent CA 必须是链尾 CA，不是 ACME WFE 的 acme_ca_file"
        );
        assert!(tls::certificate_is_ca(&written).unwrap());
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o644,
            "agent CA 必须是 0644"
        );

        // 链尾是叶子：拒绝，且不能留下一个错误的 agent-ca.pem。
        std::fs::remove_file(&out).unwrap();
        fsutil::atomic_write(&cert_path, leaf_pem.as_bytes(), 0o600).unwrap();
        let err = prepare_private_acme_agent_ca(&cfg, FsPath::new("/tmp/hub.toml"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("链尾不是 CA"),
            "错误必须说明链尾不是 CA: {err}"
        );
        assert!(!out.exists(), "失败时不得留下 agent-ca.pem");

        // 证书尚未签发：提示先执行 tls issue。
        std::fs::remove_file(&cert_path).unwrap();
        let err = prepare_private_acme_agent_ca(&cfg, FsPath::new("/tmp/hub.toml"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("tls issue"), "错误信息: {err}");
        assert!(!out.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KI-20：正常 name 的安装命令逐字节不变；危险 name 只出现在安全引号里。
    #[test]
    fn ki20_render_install_command_quotes_all_fields() {
        let token = "0123456789abcdef".repeat(4);
        let fingerprint = "fedcba9876543210".repeat(4);
        let normal =
            render_install_command("wss://web-01:8443/agent/ws", &token, &fingerprint, "web-01");
        assert_eq!(
            normal,
            format!(
                "rustboard-agent init --hub wss://web-01:8443/agent/ws \\\n    \
                 --token {token} --fingerprint {fingerprint} --name web-01"
            ),
            "正常 name 命令必须保持不变"
        );

        for raw in [
            "web 01",
            "web'01",
            "web$(printf INJECTED)",
            "web`printf INJECTED`",
            "web;printf INJECTED",
            "web|printf INJECTED",
            "web&printf INJECTED",
            "web#printf INJECTED",
        ] {
            let command =
                render_install_command("wss://web-01:8443/agent/ws", &token, &fingerprint, raw);
            assert!(
                command.ends_with(&format!("--name {}", shell_arg(raw))),
                "name 必须走 shell_arg: {command}"
            );
            assert!(command.contains(&format!("--name '{}'", raw.replace('\'', r"'\''"))));
        }

        // URL 同样走 shell_arg，避免 host 注入新的 shell 词。
        let command =
            render_install_command("wss://web 01:8443/agent/ws", &token, &fingerprint, "web-01");
        assert!(
            command.starts_with("rustboard-agent init --hub 'wss://web 01:8443/agent/ws'"),
            "{command}"
        );
    }

    /// KI-20：agent name 的 ASCII 控制字符在创建 token 前拒绝；其余不设白名单。
    #[test]
    fn ki20_agent_name_rejects_ascii_control_chars() {
        for safe in ["web-01", "web 01", "web;$(id)", "web|&`#"] {
            assert!(validate_agent_name(safe).is_ok(), "不得过度限制: {safe:?}");
        }
        for bad in [
            "web\0",
            "web\n01",
            "web\r01",
            "web\t01",
            "web\u{01}",
            "web\u{1f}",
            "web\u{7f}",
        ] {
            assert!(
                validate_agent_name(bad).is_err(),
                "必须拒绝控制字符: {bad:?}"
            );
        }
    }
}
