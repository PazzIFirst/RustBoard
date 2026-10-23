//! SQLite 实现。所有写入走单连接 + 事务，读路径走只读连接池，WAL 模式。

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};
use rustboard_common::util::now_ms;

use crate::alerts::{AlertRule, AlertRuleStoreError, AlertSource, Comparator, MAX_ALERT_RULES};

use super::{
    AgentControlRecord, AgentSeriesRow, ApiTokenRecord, AuditEntry, DownsampleRangeResult,
    IngestOutcome, MaintenanceStateEntry, NewAuditEntry, PruneResult, QueryTooLarge, RejectReason,
    SampleTier, Storage, TierStats, AUDIT_RETENTION_MS, BUCKET_1H_MS, BUCKET_1M_MS,
};

/// 默认只读连接池大小（与 `HubConfig::read_pool_size` 默认值一致）。
pub const DEFAULT_READ_POOL_SIZE: usize = 4;
/// 只读连接池下限 / 上限：连接数就是文件句柄，必须有硬上限。
pub const MIN_READ_POOL_SIZE: usize = 1;
pub const MAX_READ_POOL_SIZE: usize = 16;

/// `PRAGMA user_version`：v1 = `ingest_state` 以 agent_id 为主键，
/// v2 = `(agent_id, epoch)`，v3 = 新增 `ingest_batches` 精确判重，
/// v4 = 新增 `agent_settings`（每台 agent 的采样间隔，纯新增表），
/// v5 = 新增 `agent_control` / `audit_log`（M3 控制面，纯新增表），
/// v6 = 新增 `api_tokens`（管理 API scoped token，纯新增表），
/// v7 = 新增 M4 降采样 / 告警 / 通知 / 归档 / 维护水位表（纯新增表与索引）。
const SCHEMA_VERSION: i64 = 7;

/// `last_used_at` 的写入节流窗口：同一 token 60s 内只写一次，避免每个管理
/// 请求都抢写连接；首次鉴权（`last_used_at IS NULL`）一定会写。
const API_TOKEN_LAST_USED_THROTTLE_MS: i64 = 60_000;

/// 每这么多次审计写入清理一次 180 天前的记录。
const AUDIT_CLEANUP_EVERY: u64 = 1_000;

/// 审计 `params` 的存储上限（字节）；调用方已限长，这里是最后一道防线。
const MAX_AUDIT_PARAMS_BYTES: usize = 1_024;

/// `ingest_batches` 判重记录保留 48 小时；过期后重放视为新批次。
const INGEST_BATCH_TTL_MS: i64 = 48 * 60 * 60 * 1000;

/// 每这么多次成功插入清理一次过期判重记录，避免每批都执行 DELETE。
const INGEST_CLEANUP_EVERY: u64 = 512;

/// `latest_samples` 单次查询允许扫描的行数硬上限。
///
/// 60s 窗口在大量 agent 的高频采样下仍可能超过 10 万行；SQL 侧先 `LIMIT`
/// 截断，达到上限时返回 [`QueryTooLarge`]，避免把整窗口读进内存。
const LATEST_SAMPLES_SQL_LIMIT: usize = 100_000;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS agents (
    agent_id      TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    hostname      TEXT NOT NULL,
    os            TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    boot_id       TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'offline',
    last_seen_at  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS samples (
    agent_id  TEXT NOT NULL,
    metric    TEXT NOT NULL,
    labels    TEXT NOT NULL DEFAULT '{}',
    ts        INTEGER NOT NULL,
    value     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_lookup ON samples(agent_id, metric, ts);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_hash TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE TABLE IF NOT EXISTS agent_secrets (
    agent_id    TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_agents (
    agent_id   TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_settings (
    agent_id           TEXT PRIMARY KEY,
    sample_interval_ms INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);
"#;

/// v2 的去重状态表：每个 `(agent_id, epoch)` 独立记录 `last_seq`。
/// v3 起 `last_seq` 只作统计，不再作为判重依据。
const INGEST_STATE_V2: &str = r#"
CREATE TABLE IF NOT EXISTS ingest_state (
    agent_id   TEXT NOT NULL,
    epoch      INTEGER NOT NULL,
    last_seq   INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, epoch)
);
"#;

/// v3 的精确判重表：`(agent_id, epoch, seq)` 已处理过就整批跳过。
///
/// 只靠 `ingest_state.last_seq` 判重会误杀「同一 epoch 内先到 5 后到 3」
/// 这类边界重传，造成数据丢失；逐批记录才能既去重又不丢点。
const INGEST_BATCHES: &str = r#"
CREATE TABLE IF NOT EXISTS ingest_batches (
    agent_id TEXT NOT NULL,
    epoch    INTEGER NOT NULL,
    seq      INTEGER NOT NULL,
    ts       INTEGER NOT NULL,
    PRIMARY KEY (agent_id, epoch, seq)
);
CREATE INDEX IF NOT EXISTS idx_ingest_batches_ts ON ingest_batches(ts);
"#;

/// v4 新增表：每台 agent 的显式采样间隔。纯新增，不重写旧表。
const AGENT_SETTINGS: &str = r#"
CREATE TABLE IF NOT EXISTS agent_settings (
    agent_id           TEXT PRIMARY KEY,
    sample_interval_ms INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);
"#;

/// v5 新增表：agent 控制能力与操作审计。纯新增，不重写 v1–v4 任何表。
const CONTROL_AUDIT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS agent_control (
    agent_id     TEXT PRIMARY KEY,
    capabilities TEXT NOT NULL DEFAULT '[]',
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    actor         TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    capability    TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT NOT NULL DEFAULT '',
    params        TEXT NOT NULL DEFAULT '{}',
    result        TEXT NOT NULL,
    error_code    TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    duration_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit_log(agent_id, ts);
"#;

/// v6 新增表：管理 API scoped token。纯新增，不重写 v1–v5 任何表。
///
/// 只存 SHA-256 hex：明文只在 `token create` / `token rotate` 时输出一次。
/// 吊销写 `revoked_at` 而不删行，保留审计与排障信息。
const API_TOKENS_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL CHECK (scope IN ('read','write','admin')),
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
"#;

/// v7 新增表：M4 降采样、告警、通知渠道、冷归档与维护水位。
///
/// 全部为 `CREATE TABLE / INDEX IF NOT EXISTS`，不重写 v1–v6 任何表或数据；
/// v0.3.5 等旧版本二进制会忽略这些表，可安全回滚。
///
/// `alert_rules.channel_ids` 按方案**刻意不加外键**：渠道引用完整性由 hub 在
/// 保存规则、删除渠道时校验，SQLite 侧只存 JSON 数组。
const M4_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS samples_1m (
    agent_id   TEXT NOT NULL,
    metric     TEXT NOT NULL,
    labels     TEXT NOT NULL DEFAULT '{}',
    bucket_ts  INTEGER NOT NULL,
    min_value  REAL NOT NULL,
    max_value  REAL NOT NULL,
    avg_value  REAL NOT NULL,
    last_value REAL NOT NULL,
    count      INTEGER NOT NULL,
    PRIMARY KEY (agent_id, metric, labels, bucket_ts)
);
CREATE INDEX IF NOT EXISTS idx_samples_1m_lookup ON samples_1m(agent_id, metric, bucket_ts);
CREATE INDEX IF NOT EXISTS idx_samples_1m_ts ON samples_1m(bucket_ts);

CREATE TABLE IF NOT EXISTS samples_1h (
    agent_id   TEXT NOT NULL,
    metric     TEXT NOT NULL,
    labels     TEXT NOT NULL DEFAULT '{}',
    bucket_ts  INTEGER NOT NULL,
    min_value  REAL NOT NULL,
    max_value  REAL NOT NULL,
    avg_value  REAL NOT NULL,
    last_value REAL NOT NULL,
    count      INTEGER NOT NULL,
    PRIMARY KEY (agent_id, metric, labels, bucket_ts)
);
CREATE INDEX IF NOT EXISTS idx_samples_1h_lookup ON samples_1h(agent_id, metric, bucket_ts);
CREATE INDEX IF NOT EXISTS idx_samples_1h_ts ON samples_1h(bucket_ts);

CREATE TABLE IF NOT EXISTS maintenance_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_rules (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    enabled           INTEGER NOT NULL DEFAULT 0,
    source            TEXT NOT NULL DEFAULT 'metric',
    metric            TEXT NOT NULL DEFAULT '',
    comparator        TEXT NOT NULL DEFAULT 'gt',
    threshold         REAL NOT NULL DEFAULT 0,
    duration_secs     INTEGER NOT NULL DEFAULT 0,
    cooldown_secs     INTEGER NOT NULL DEFAULT 1800,
    filter_agent_id   TEXT,
    filter_labels     TEXT NOT NULL DEFAULT '{}',
    channel_ids       TEXT NOT NULL DEFAULT '[]',
    notify_on_resolve INTEGER NOT NULL DEFAULT 1,
    is_builtin        INTEGER NOT NULL DEFAULT 0,
    updated_by        TEXT NOT NULL DEFAULT '',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS alert_states (
    rule_id          TEXT NOT NULL,
    agent_id         TEXT NOT NULL DEFAULT '',
    series_key       TEXT NOT NULL DEFAULT '',
    state            TEXT NOT NULL DEFAULT 'pending',
    since            INTEGER NOT NULL,
    last_eval_at     INTEGER NOT NULL,
    last_value       REAL,
    last_notified_at INTEGER,
    PRIMARY KEY (rule_id, agent_id, series_key)
);

CREATE TABLE IF NOT EXISTS alert_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    agent_id     TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL,
    value        REAL,
    message      TEXT NOT NULL DEFAULT '',
    notified     INTEGER NOT NULL DEFAULT 0,
    notify_error TEXT NOT NULL DEFAULT '',
    silenced     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alert_events_ts ON alert_events(ts);
CREATE INDEX IF NOT EXISTS idx_alert_events_rule_ts ON alert_events(rule_id, ts);
CREATE INDEX IF NOT EXISTS idx_alert_events_agent_ts ON alert_events(agent_id, ts);

CREATE TABLE IF NOT EXISTS alert_silences (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id    TEXT,
    agent_id   TEXT,
    until_ts   INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notification_channels (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    config_json TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    updated_by  TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS archive_objects (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    backend      TEXT NOT NULL,
    object_key   TEXT NOT NULL UNIQUE,
    manifest_key TEXT NOT NULL,
    from_ts      INTEGER NOT NULL,
    to_ts        INTEGER NOT NULL,
    rows         INTEGER NOT NULL,
    bytes        INTEGER NOT NULL,
    sha256       TEXT NOT NULL,
    status       TEXT NOT NULL,
    error        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    uploaded_at  INTEGER,
    deleted_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_archive_objects_range ON archive_objects(from_ts, to_ts);
CREATE INDEX IF NOT EXISTS idx_archive_objects_status ON archive_objects(status);

CREATE TABLE IF NOT EXISTS archive_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
"#;

/// 1m 聚合：把 `[?1, ?2)` 内 raw 行按 `(agent_id, metric, labels, 整分钟)` 聚合，
/// 按主键 upsert。`last_value` 取桶内最大 `ts`，同 ts 取最大 `rowid`。
///
/// 下标 60000 与 [`BUCKET_1M_MS`] 必须一致（单元测试会断言）。
const AGGREGATE_1M_SQL: &str = r#"
INSERT INTO samples_1m
    (agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, last_value, count)
SELECT agent_id, metric, labels, bucket_ts,
       MIN(value), MAX(value), AVG(value), last_value, COUNT(*)
FROM (
    SELECT agent_id, metric, labels,
           (ts / 60000) * 60000 AS bucket_ts,
           value,
           FIRST_VALUE(value) OVER (
               PARTITION BY agent_id, metric, labels, (ts / 60000) * 60000
               ORDER BY ts DESC, rowid DESC
           ) AS last_value
    FROM samples
    WHERE ts >= ?1 AND ts < ?2
)
GROUP BY agent_id, metric, labels, bucket_ts
ON CONFLICT(agent_id, metric, labels, bucket_ts) DO UPDATE SET
    min_value = excluded.min_value,
    max_value = excluded.max_value,
    avg_value = excluded.avg_value,
    last_value = excluded.last_value,
    count = excluded.count
"#;

/// 1h 聚合：把 `[?1, ?2)` 内 1m 桶按 `(agent_id, metric, labels, 整点小时)` 聚合。
///
/// - `avg_value` 必须按 `count` 加权（`SUM(avg*count)/SUM(count)`），不能对
///   各分钟平均值再取简单平均；
/// - `last_value` 取最新 1m 桶的 `last_value`（`bucket_ts` 最大）；
/// - 下标 3600000 与 [`BUCKET_1H_MS`] 必须一致。
const AGGREGATE_1H_SQL: &str = r#"
INSERT INTO samples_1h
    (agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, last_value, count)
SELECT agent_id, metric, labels, bucket_ts,
       MIN(min_value), MAX(max_value),
       CAST(SUM(avg_value * count) AS REAL) / SUM(count),
       last_value,
       SUM(count)
FROM (
    SELECT agent_id, metric, labels,
           (bucket_ts / 3600000) * 3600000 AS bucket_ts,
           min_value, max_value, avg_value, count,
           FIRST_VALUE(last_value) OVER (
               PARTITION BY agent_id, metric, labels, (bucket_ts / 3600000) * 3600000
               ORDER BY bucket_ts DESC
           ) AS last_value
    FROM samples_1m
    WHERE bucket_ts >= ?1 AND bucket_ts < ?2
)
GROUP BY agent_id, metric, labels, bucket_ts
ON CONFLICT(agent_id, metric, labels, bucket_ts) DO UPDATE SET
    min_value = excluded.min_value,
    max_value = excluded.max_value,
    avg_value = excluded.avg_value,
    last_value = excluded.last_value,
    count = excluded.count
"#;

/// 保留期删除 SQL：每批最多 `?2` 行，`?1` 是排他 cutoff（`< cutoff`）。
///
/// 用 `rowid IN (SELECT ... LIMIT)` 而不是全表 DELETE，保证单批事务短、批间
/// 可以释放写锁；`rowid` 对三张表都可用（均非 WITHOUT ROWID）。
const PRUNE_RAW_SQL: &str = "DELETE FROM samples WHERE rowid IN \
     (SELECT rowid FROM samples WHERE ts < ?1 ORDER BY ts LIMIT ?2)";
const PRUNE_1M_SQL: &str = "DELETE FROM samples_1m WHERE rowid IN \
     (SELECT rowid FROM samples_1m WHERE bucket_ts < ?1 ORDER BY bucket_ts LIMIT ?2)";
const PRUNE_1H_SQL: &str = "DELETE FROM samples_1h WHERE rowid IN \
     (SELECT rowid FROM samples_1h WHERE bucket_ts < ?1 ORDER BY bucket_ts LIMIT ?2)";

/// M4 降采样单事务处理的源行数上限（一个桶本身超限时按整桶处理）。
pub const DOWNSAMPLE_MAX_CHUNK_ROWS: usize = 5_000;

/// M4 保留期删除的每批行数；批间释放写锁，避免长事务阻塞 ingest。
pub const PRUNE_BATCH_ROWS: usize = 5_000;

pub struct SqliteStorage {
    /// 唯一写连接：迁移、事务、写入都走它，保证 `(agent_id, epoch, seq)` 判重原子。
    writer: Mutex<Connection>,
    /// 只读连接池：每条连接独立加锁，长查询不会阻塞写入。
    readers: Vec<Mutex<Connection>>,
    /// 轮询取读连接的下标，保证并发请求分摊到不同连接。
    next_reader: AtomicUsize,
    /// 成功插入批次的累计计数，用于低频触发 `ingest_batches` 清理。
    inserted_batches: AtomicU64,
    /// 成功写入审计的累计计数，用于低频触发 180 天保留期清理。
    audit_writes: AtomicU64,
}

/// 读路径的连接 guard：正常情况下取自只读池；池为空时回退到写连接。
///
/// 回退只发生在「只读连接一条都打不开」的启动降级路径，保证 hub 仍可对外服务；
/// 此时读会被写事务串行化，但不会数据错乱。
enum ReadGuard<'a> {
    Pool(MutexGuard<'a, Connection>),
    Writer(MutexGuard<'a, Connection>),
}

impl Deref for ReadGuard<'_> {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Pool(guard) => guard,
            Self::Writer(guard) => guard,
        }
    }
}

/// 从互斥锁取连接；锁中毒说明持有者 panic 过，但连接本身仍然可用。
fn lock_conn(conn: &Mutex<Connection>) -> MutexGuard<'_, Connection> {
    match conn.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl SqliteStorage {
    /// 打开数据库；只读连接池使用默认大小 4。
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_readers(path, DEFAULT_READ_POOL_SIZE)
    }

    /// 打开数据库并指定只读连接池大小（自动夹到 1–16）。
    ///
    /// 打开顺序：写连接建库 / 迁移 → 读连接打开同一路径并设置 `query_only=ON`。
    /// 任一读连接打开失败时停止扩容并告警，已有读连接继续服务；
    /// 一条都没有时读路径回退到写连接，**不允许启动失败**。
    ///
    /// 权限边界：本函数只保证**新建**的父目录是 0700，**不会收紧已存在的父目录**——
    /// storage 只拿到数据库路径，父目录可能是 `/tmp`、`/var/tmp` 这类共享目录，
    /// 无条件 chmod 会把系统目录改坏。数据库文件本身（含 WAL/SHM）仍会收紧到
    /// 0600。需要把旧版本遗留的 0755 专用数据目录一并收紧时，调用方应使用
    /// [`Self::open_with_private_data_dir`]。
    pub fn open_with_readers(path: &Path, read_pool_size: usize) -> Result<Self> {
        Self::open_at(path, read_pool_size, None)
    }

    /// 打开数据库，并声明 `data_dir` 是本程序**专用**的数据目录（KI-21）。
    ///
    /// 与 [`Self::open_with_readers`] 的区别：会显式调用
    /// `fsutil::ensure_private_dir(data_dir, 0o700)`，把旧版本遗留的 0755 数据目录
    /// 收紧到 0700。**调用方必须保证 `data_dir` 完全归本程序所有**；不要把
    /// `/tmp`、`/var/tmp`、`/` 等共享目录传进来。`data_dir` 必须就是数据库文件
    /// 的直接父目录，否则视为编程错误直接拒绝，避免收紧一个与数据库无关的目录。
    pub fn open_with_private_data_dir(
        path: &Path,
        read_pool_size: usize,
        data_dir: &Path,
    ) -> Result<Self> {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => anyhow::bail!(
                "数据库路径 {} 没有父目录，无法声明私有数据目录",
                path.display()
            ),
        };
        if parent != data_dir {
            anyhow::bail!(
                "私有数据目录 {} 不是数据库 {} 的父目录 {}，拒绝收紧权限",
                data_dir.display(),
                path.display(),
                parent.display()
            );
        }
        Self::open_at(path, read_pool_size, Some(data_dir))
    }

    /// `open_with_readers` / `open_with_private_data_dir` 的共同实现。
    fn open_at(
        path: &Path,
        read_pool_size: usize,
        private_data_dir: Option<&Path>,
    ) -> Result<Self> {
        let pool_size = read_pool_size.clamp(MIN_READ_POOL_SIZE, MAX_READ_POOL_SIZE);
        if pool_size != read_pool_size {
            tracing::warn!(
                requested = read_pool_size,
                actual = pool_size,
                "read_pool_size 超出允许范围，已夹到合法区间"
            );
        }
        match private_data_dir {
            Some(data_dir) => {
                // KI-21：只有调用方显式声明「目录归本程序所有」时才收紧既有权限。
                rustboard_common::fsutil::ensure_private_dir(data_dir, 0o700).with_context(
                    || format!("创建或收紧私有数据目录失败: {}", data_dir.display()),
                )?;
            }
            None => {
                if let Some(parent) = path.parent() {
                    // 保持既有语义：只给新建父目录 0700，不 chmod 已存在的共享目录。
                    rustboard_common::fsutil::ensure_dir(parent, 0o700)
                        .with_context(|| format!("创建数据目录失败: {}", parent.display()))?;
                }
            }
        }
        reject_symlink_db_path(path)?;
        let writer = Connection::open(path)
            .with_context(|| format!("打开数据库失败: {}", path.display()))?;
        let writer = init_writer(writer)?;
        // 写连接迁移完成后，主库与 WAL/SHM 都已落盘，统一收紧到 0600。
        harden_db_file(path)?;
        harden_db_sidecars(path)?;

        #[cfg(test)]
        let force_reader_failure = {
            let mut slot = FAIL_READER_OPEN_FOR
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if slot.as_deref() == Some(path) {
                slot.take();
                true
            } else {
                // 其他测试的注入路径与本库无关，不能顺手消费掉。
                false
            }
        };
        #[cfg(not(test))]
        let force_reader_failure = false;

        let mut readers = Vec::with_capacity(pool_size);
        for index in 0..pool_size {
            if force_reader_failure {
                tracing::warn!(index, "测试注入：只读连接打开失败");
                break;
            }
            match open_reader(path) {
                Ok(conn) => readers.push(Mutex::new(conn)),
                Err(err) => {
                    // 读池是吞吐优化，不是正确性前提：失败时降级而不是拒绝启动。
                    tracing::warn!(
                        index,
                        pool_size,
                        error = %err,
                        "只读连接打开失败，停止扩容并使用现有读连接"
                    );
                    break;
                }
            }
        }
        if readers.is_empty() {
            tracing::warn!(
                path = %path.display(),
                "只读连接池为空，读路径回退到写连接（读会被写事务串行化）"
            );
        }
        // KI-21：只读连接首次打开时 SQLite 可能重新创建 -wal/-shm（默认权限由
        // umask 决定），因此在读池建好后再收紧一次 sidecar。
        harden_db_sidecars(path)?;
        Ok(Self {
            writer: Mutex::new(writer),
            readers,
            next_reader: AtomicUsize::new(0),
            inserted_batches: AtomicU64::new(0),
            audit_writes: AtomicU64::new(0),
        })
    }

    /// 内存库：所有连接共享同一个 `file:...mode=memory&cache=shared` URI。
    ///
    /// 普通 `:memory:` 每条连接都是一个独立数据库，读池会看不到写入的数据；
    /// 共享缓存 URI 才能让写连接与只读池看到同一份数据。
    pub fn open_in_memory() -> Result<Self> {
        static MEMORY_DB_SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = MEMORY_DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let uri = format!(
            "file:rustboard-{}-{seq}?mode=memory&cache=shared",
            std::process::id()
        );
        let writer = Connection::open_with_flags(
            &uri,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .with_context(|| format!("打开内存数据库失败: {uri}"))?;
        let writer = init_writer(writer)?;

        let mut readers = Vec::with_capacity(DEFAULT_READ_POOL_SIZE);
        for index in 0..DEFAULT_READ_POOL_SIZE {
            match open_reader_with_flags(
                &uri,
                OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_URI,
            ) {
                Ok(conn) => readers.push(Mutex::new(conn)),
                Err(err) => {
                    tracing::warn!(index, error = %err, "内存库只读连接打开失败，停止扩容");
                    break;
                }
            }
        }
        if readers.is_empty() {
            tracing::warn!("内存库只读连接池为空，读路径回退到写连接");
        }
        Ok(Self {
            writer: Mutex::new(writer),
            readers,
            next_reader: AtomicUsize::new(0),
            inserted_batches: AtomicU64::new(0),
            audit_writes: AtomicU64::new(0),
        })
    }

    fn lock_write(&self) -> MutexGuard<'_, Connection> {
        lock_conn(&self.writer)
    }

    /// 轮询取一条只读连接；池为空时回退到写连接。
    fn lock_read(&self) -> ReadGuard<'_> {
        if self.readers.is_empty() {
            return ReadGuard::Writer(lock_conn(&self.writer));
        }
        let index = self.next_reader.fetch_add(1, Ordering::Relaxed) % self.readers.len();
        ReadGuard::Pool(lock_conn(&self.readers[index]))
    }

    /// 实际打开的只读连接数（测试与排障用）。
    #[cfg(test)]
    fn read_pool_len(&self) -> usize {
        self.readers.len()
    }

    /// `latest_samples` 的 raw 路径：SQL 侧最多取 `limit` 行。
    ///
    /// 只查 raw 表；1m/1h 回退由 [`Storage::latest_samples`] 负责。
    /// 达到上限（行数 == limit）时返回错误而不是静默截断：截断后的「最新点」
    /// 可能缺序列，面板会显示错误的监控数据；宁可让调用方缩小窗口。
    fn latest_samples_limited(
        &self,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AgentSeriesRow>> {
        debug_assert!(limit > 0, "latest_samples 的行数上限必须大于 0");
        let conn = self.lock_read();

        let mut sql =
            String::from("SELECT agent_id, metric, labels, ts, value FROM samples WHERE ts >= ?");
        let mut params: Vec<rusqlite::types::Value> = vec![rusqlite::types::Value::Integer(since)];
        if let Some(agent_id) = agent {
            sql.push_str(" AND agent_id = ?");
            params.push(rusqlite::types::Value::Text(agent_id.to_string()));
        }
        if !metrics.is_empty() {
            let holders = vec!["?"; metrics.len()].join(",");
            sql.push_str(&format!(" AND metric IN ({holders})"));
            for metric in metrics {
                params.push(rusqlite::types::Value::Text(metric.clone()));
            }
        }
        sql.push_str(" ORDER BY agent_id, metric, labels, ts ASC LIMIT ?");
        params.push(rusqlite::types::Value::Integer(
            i64::try_from(limit).unwrap_or(i64::MAX),
        ));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
            let labels_json: String = r.get(2)?;
            let labels: Labels = serde_json::from_str(&labels_json).unwrap_or_default();
            Ok(AgentSeriesRow {
                agent_id: r.get(0)?,
                metric: r.get(1)?,
                labels,
                ts: r.get(3)?,
                value: r.get(4)?,
            })
        })?;
        let rows: Vec<AgentSeriesRow> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        dedupe_latest_samples(rows, limit, since, metrics, agent, SampleTier::Raw)
    }

    /// 聚合表回退：取 `since` 之后某层每个序列的最新桶。
    ///
    /// 谓词写成 `bucket_ts > since - 层粒度 AND bucket_ts <= now`：
    /// - 前一项等价于「桶与窗口重叠」（严格大于，桶结束恰好等于 since 的旧桶
    ///   不算），且不再对列做表达式运算，可走 `idx_samples_1m_lookup` /
    ///   `idx_samples_1m_ts` 的范围扫描；
    /// - 后一项排除未来桶，避免时钟异常/脏数据把扫描拖到全表尾部。
    ///
    /// 返回 `bucket_ts` 作为 `ts`、`last_value` 作为 `value`。行数上限、agent /
    /// metrics 过滤与按序列去重的语义都与 raw 路径一致。
    fn latest_tier_samples(
        &self,
        tier: SampleTier,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
    ) -> Result<Vec<AgentSeriesRow>> {
        let (table, granularity) = match tier {
            SampleTier::Raw => {
                return self.latest_samples_limited(since, metrics, agent, LATEST_SAMPLES_SQL_LIMIT)
            }
            SampleTier::OneMinute => ("samples_1m", BUCKET_1M_MS),
            SampleTier::OneHour => ("samples_1h", BUCKET_1H_MS),
        };
        let conn = self.lock_read();

        // 表名来自上面的固定分支，不接受外部输入；其余值全部参数绑定。
        let sql = latest_tier_sql(table, agent.is_some(), metrics.len());
        let mut params: Vec<rusqlite::types::Value> = vec![
            rusqlite::types::Value::Integer(since.saturating_sub(granularity)),
            rusqlite::types::Value::Integer(now_ms()),
        ];
        if let Some(agent_id) = agent {
            params.push(rusqlite::types::Value::Text(agent_id.to_string()));
        }
        for metric in metrics {
            params.push(rusqlite::types::Value::Text(metric.clone()));
        }
        params.push(rusqlite::types::Value::Integer(
            i64::try_from(LATEST_SAMPLES_SQL_LIMIT).unwrap_or(i64::MAX),
        ));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
            let labels_json: String = r.get(2)?;
            let labels: Labels = serde_json::from_str(&labels_json).unwrap_or_default();
            Ok(AgentSeriesRow {
                agent_id: r.get(0)?,
                metric: r.get(1)?,
                labels,
                ts: r.get(3)?,
                value: r.get(4)?,
            })
        })?;
        let rows: Vec<AgentSeriesRow> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        dedupe_latest_samples(rows, LATEST_SAMPLES_SQL_LIMIT, since, metrics, agent, tier)
    }
}

/// 构造 1m/1h 时间桶聚合 SQL。
///
/// `table` 只能来自 [`SampleTier`] 的固定分支，不接收外部输入；metric 过滤器
/// 只改变占位符数量，值全部由调用方绑定。`bucket_ts > ?2` 是
/// `bucket_ts + 层粒度 > from` 的等价改写（`?2 = from - 层粒度`），让 SQLite
/// 能对 `bucket_ts` 做索引范围扫描，而不是逐行计算表达式。
///
/// 用 `INDEXED BY` 固定走 `(agent_id, metric, bucket_ts)` 复合索引：没有
/// ANALYZE 统计时优化器可能选 PRIMARY KEY 自动索引或全表扫描，这里显式锁定
/// 与查询形状匹配的索引（索引名与表名一一对应，均来自固定分支）。
fn tiered_query_sql(table: &'static str, metric_count: usize) -> String {
    let mut sql = format!(
        "SELECT metric, labels, (bucket_ts / ?4) * ?4 AS query_ts,
                CAST(SUM(avg_value * count) AS REAL) / SUM(count)
         FROM {table} INDEXED BY idx_{table}_lookup
         WHERE agent_id = ?1 AND bucket_ts > ?2 AND bucket_ts <= ?3"
    );
    if metric_count > 0 {
        let holders: Vec<String> = (0..metric_count).map(|i| format!("?{}", 5 + i)).collect();
        sql.push_str(&format!(" AND metric IN ({})", holders.join(",")));
    }
    let limit_idx = 5 + metric_count;
    sql.push_str(&format!(
        " GROUP BY metric, labels, query_ts
          ORDER BY metric, labels, query_ts
          LIMIT ?{limit_idx}"
    ));
    sql
}

/// 构造 latest_samples 的 1m/1h 回退 SQL。
///
/// 条件同样保持列上无表达式：`bucket_ts > since - 层粒度 AND bucket_ts <= now`。
/// 前一项与「桶结束晚于 since」（`bucket_ts + 层粒度 > since`）等价，且保持
/// 严格不包含「桶结束恰好等于 since」的旧桶。
/// 带 agent 过滤时走复合索引（先按 agent 收窄），跨 agent 查询走 `bucket_ts`
/// 单列索引；两条路径都用 `INDEXED BY` 固定，避免无统计信息时全表扫描。
fn latest_tier_sql(table: &'static str, has_agent: bool, metric_count: usize) -> String {
    let index = if has_agent {
        format!("idx_{table}_lookup")
    } else {
        format!("idx_{table}_ts")
    };
    let mut sql = format!(
        "SELECT agent_id, metric, labels, bucket_ts, last_value FROM {table} INDEXED BY {index}
         WHERE bucket_ts > ? AND bucket_ts <= ?"
    );
    if has_agent {
        sql.push_str(" AND agent_id = ?");
    }
    if metric_count > 0 {
        let holders = vec!["?"; metric_count].join(",");
        sql.push_str(&format!(" AND metric IN ({holders})"));
    }
    sql.push_str(" ORDER BY agent_id, metric, labels, bucket_ts ASC LIMIT ?");
    sql
}

/// `latest_samples` 各条路径共用的上限检查与按序列去重。
///
/// `rows` 必须已按 `(agent_id, metric, labels, ts)` 升序（SQL 保证）；同键后到
/// 的（更新的 ts）覆盖先到的。用 BTreeMap 保证最终输出顺序稳定，便于面板与
/// 测试断言。达到行数硬上限时返回 [`QueryTooLarge`] 而不是静默截断。
fn dedupe_latest_samples(
    rows: Vec<AgentSeriesRow>,
    limit: usize,
    since: i64,
    metrics: &[String],
    agent: Option<&str>,
    tier: SampleTier,
) -> Result<Vec<AgentSeriesRow>> {
    if rows.len() >= limit {
        tracing::error!(
            limit,
            since,
            metrics = metrics.len(),
            agent = agent.unwrap_or("<all>"),
            tier = tier.as_str(),
            "latest_samples 达到 SQL 行数硬上限，拒绝返回可能不完整的快照"
        );
        return Err(anyhow::Error::new(QueryTooLarge { limit }));
    }

    let mut latest: std::collections::BTreeMap<(String, String, Labels), AgentSeriesRow> =
        std::collections::BTreeMap::new();
    for row in rows {
        let key = (row.agent_id.clone(), row.metric.clone(), row.labels.clone());
        match latest.get(&key) {
            Some(existing) if existing.ts > row.ts => {}
            _ => {
                latest.insert(key, row);
            }
        }
    }
    Ok(latest.into_values().collect())
}

/// 测试注入：让指定路径的只读连接全部打开失败，覆盖「读池降级到写连接」分支。
#[cfg(test)]
static FAIL_READER_OPEN_FOR: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

/// KI-21：数据库路径本身是符号链接时拒绝打开。
///
/// 必须在 `Connection::open` 之前调用：SQLite 默认跟随符号链接，先打开再 chmod
/// 已经作用在链接目标上，无法保证「只收紧本进程拥有的数据文件」。
fn reject_symlink_db_path(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!(
                "数据库路径 {} 是符号链接，拒绝打开（请改为真实文件路径）",
                path.display()
            )
        }
        Ok(_) => Ok(()),
        // 新库：路径尚不存在，由后续 `Connection::open` 创建。
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("检查数据库路径失败: {}", path.display())),
    }
}

/// 收紧 SQLite 主库文件权限（KI-21）；主库此时必然存在，任何错误都要上抛。
fn harden_db_file(path: &Path) -> Result<()> {
    rustboard_common::fsutil::harden(path, 0o600)
        .with_context(|| format!("收紧数据库文件权限失败: {}", path.display()))
}

/// 收紧 WAL/SHM sidecar 权限（KI-21）。
///
/// sidecar 按需创建、WAL 重置时可能被删除，`NotFound` 属于正常竞态；除此之外
/// 的错误（PermissionDenied、I/O 错误）必须上抛，不能当成“没有文件”吞掉。
fn harden_db_sidecars(path: &Path) -> Result<()> {
    for suffix in ["-wal", "-shm"] {
        let sidecar = db_sidecar_path(path, suffix);
        match rustboard_common::fsutil::harden(&sidecar, 0o600) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("收紧数据库 sidecar 权限失败: {}", sidecar.display()))
            }
        }
    }
    Ok(())
}

/// 拼接 SQLite sidecar 路径（保留非 UTF-8 路径原名）。
fn db_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

/// 初始化写连接：设置 PRAGMA、建表并迁移。
fn init_writer(mut conn: Connection) -> Result<Connection> {
    // busy_timeout 必须最先设置：两个进程并发首次打开旧库时，
    // 切 WAL 会拿写锁，没有超时就会直接报 database is locked。
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    // journal_mode 会返回一行，必须用 query_row 消费掉
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    tracing::debug!(mode, "sqlite journal mode");
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(SCHEMA)?;
    migrate(&mut conn)?;
    Ok(conn)
}

/// 打开一条文件库只读连接。
fn open_reader(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("打开只读数据库连接失败: {}", path.display()))?;
    prepare_reader(conn)
}

/// 打开一条指定 flags 的只读连接（内存共享缓存 URI 用）。
fn open_reader_with_flags(uri: &str, flags: OpenFlags) -> Result<Connection> {
    let conn = Connection::open_with_flags(uri, flags)
        .with_context(|| format!("打开只读数据库连接失败: {uri}"))?;
    prepare_reader(conn)
}

/// 只读连接的统一设置：busy_timeout + `query_only=ON`。
///
/// `query_only` 是 SQLite 层的写保护，防止读路径误写；真正的隔离靠「独立连接 +
/// 独立锁」，而不是这把 PRAGMA。
fn prepare_reader(conn: Connection) -> Result<Connection> {
    conn.pragma_update(None, "busy_timeout", 5_000)?;
    conn.pragma_update(None, "query_only", "ON")?;
    Ok(conn)
}

/// 把 `ingest_state` 从 v1（agent_id 主键）迁移到 v2（agent_id + epoch 主键），
/// 为 v3 建好 `ingest_batches` 精确判重表，为 v4 建好 `agent_settings` 表，
/// 为 v5–v7 建好 M3/M4 的纯新增表。旧行原样保留。
///
/// v1 代码从未写过 `user_version`，所以只靠版本号无法区分「空库」和「v1 库」：
/// 版本号不足 2 时再看表是否存在。整个迁移在一个 `BEGIN IMMEDIATE` 事务里完成，
/// 避免多个 hub 进程同时启动时重复迁移；旧行原样保留。
fn migrate(conn: &mut Connection) -> Result<()> {
    // L3：先拿写锁再读版本，两个进程同时启动时只有一个能迁移。
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    if version < 2 {
        // 半途失败的残留表先清掉，避免 ALTER RENAME 撞名；即使本次没有
        // ingest_state 需要迁移，也顺手清理历史遗留。
        tx.execute_batch("DROP TABLE IF EXISTS ingest_state_v2;")?;

        let has_ingest_state: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ingest_state')",
            [],
            |r| r.get(0),
        )?;

        if has_ingest_state != 0 {
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS ingest_state_v2 (
                     agent_id   TEXT NOT NULL,
                     epoch      INTEGER NOT NULL,
                     last_seq   INTEGER NOT NULL DEFAULT 0,
                     updated_at INTEGER NOT NULL DEFAULT 0,
                     PRIMARY KEY (agent_id, epoch)
                 );
                 INSERT INTO ingest_state_v2 (agent_id, epoch, last_seq, updated_at)
                     SELECT agent_id, epoch, last_seq, updated_at FROM ingest_state;
                 DROP TABLE ingest_state;
                 ALTER TABLE ingest_state_v2 RENAME TO ingest_state;",
            )?;
            tracing::info!("ingest_state 已迁移到 v2：按 (agent_id, epoch) 去重");
        }
    }

    // 无论版本如何都执行 IF NOT EXISTS：兼容 v1/v2 以及迁移中断后缺表的库。
    tx.execute_batch(INGEST_STATE_V2)?;
    tx.execute_batch(INGEST_BATCHES)?;
    tx.execute_batch(AGENT_SETTINGS)?;
    // v5：控制面能力与审计表。纯新增，旧版本二进制忽略这两张表。
    tx.execute_batch(CONTROL_AUDIT_SCHEMA)?;
    // v6：管理 API scoped token 表。纯新增，旧版本二进制忽略这张表。
    tx.execute_batch(API_TOKENS_SCHEMA)?;
    // v7：M4 降采样 / 告警 / 归档 / 维护水位表。纯新增，旧版本二进制忽略这些表；
    // 带 IF NOT EXISTS，迁移中断或重复打开都不会重复建表。
    tx.execute_batch(M4_SCHEMA)?;

    if version < SCHEMA_VERSION {
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tracing::info!(
            from = version,
            to = SCHEMA_VERSION,
            "数据库已迁移：新增 M4 schema v7（降采样、告警、通知、归档、维护水位表）"
        );
    }
    tx.commit()?;
    Ok(())
}

/// 删除 48 小时前的判重记录；由 `insert_batch` 每 512 次成功插入调用一次。
fn prune_ingest_batches(tx: &Transaction<'_>, now: i64) -> Result<()> {
    let cutoff = now.saturating_sub(INGEST_BATCH_TTL_MS);
    let removed = tx.execute("DELETE FROM ingest_batches WHERE ts < ?1", params![cutoff])?;
    if removed > 0 {
        tracing::debug!(removed, cutoff, "已清理过期 ingest_batches 判重记录");
    }
    Ok(())
}

impl Storage for SqliteStorage {
    fn upsert_agent(&self, agent: &AgentRecord) -> Result<()> {
        self.lock_write().execute(
            "INSERT INTO agents
                (agent_id, name, hostname, os, arch, version, boot_id, status, last_seen_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(agent_id) DO UPDATE SET
                name = excluded.name,
                hostname = excluded.hostname,
                os = excluded.os,
                arch = excluded.arch,
                version = excluded.version,
                boot_id = excluded.boot_id,
                -- M1：revoked 是终态，任何 upsert 都不能把它改回 online/pending。
                status = CASE
                    WHEN agents.status = 'revoked' THEN agents.status
                    ELSE excluded.status
                END,
                last_seen_at = excluded.last_seen_at",
            params![
                agent.agent_id,
                agent.name,
                agent.hostname,
                agent.os,
                agent.arch,
                agent.version,
                agent.boot_id,
                agent.status,
                agent.last_seen_at,
                agent.created_at
            ],
        )?;
        Ok(())
    }

    fn mark_seen(&self, agent_id: &str, ts: i64) -> Result<()> {
        self.lock_write().execute(
            // M1：活跃会话的 mark_seen 不能覆盖 revoked。
            "UPDATE agents
             SET last_seen_at = ?2,
                 status = CASE WHEN status = 'revoked' THEN status ELSE 'online' END
             WHERE agent_id = ?1",
            params![agent_id, ts],
        )?;
        Ok(())
    }

    fn set_status(&self, agent_id: &str, status: &str, ts: i64) -> Result<()> {
        self.lock_write().execute(
            "UPDATE agents
             SET status = CASE WHEN status = 'revoked' THEN status ELSE ?2 END,
                 last_seen_at = ?3
             WHERE agent_id = ?1",
            params![agent_id, status, ts],
        )?;
        Ok(())
    }

    fn reset_online_status(&self) -> Result<usize> {
        // L5：只清理 online，revoked 是终态必须保留。
        let updated = self.lock_write().execute(
            "UPDATE agents SET status = 'offline' WHERE status = 'online'",
            [],
        )?;
        Ok(updated)
    }

    fn insert_batch(&self, batch: &SampleBatch) -> Result<IngestOutcome> {
        let mut conn = self.lock_write();
        let tx = conn.transaction()?;

        // 吊销检查与写入必须在同一事务内：命中后不写任何数据。
        let revoked: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_agents WHERE agent_id = ?1)",
            params![batch.agent_id],
            |r| r.get(0),
        )?;
        if revoked != 0 {
            tx.rollback()?;
            return Ok(IngestOutcome::Rejected(RejectReason::Revoked));
        }

        // M2：精确到 seq 判重。水位 last_seq 只用于统计，不能再作为唯一依据，
        // 否则同一 epoch 内「先到 5 后到 3」会误判为 Duplicate 而丢数据。
        let already_processed: i64 = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM ingest_batches
                 WHERE agent_id = ?1 AND epoch = ?2 AND seq = ?3
             )",
            params![batch.agent_id, batch.epoch, batch.seq],
            |r| r.get(0),
        )?;
        if already_processed != 0 {
            tx.commit()?;
            return Ok(IngestOutcome::Duplicate);
        }

        let mut inserted = 0usize;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO samples (agent_id, metric, labels, ts, value) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for s in &batch.samples {
                let labels = serde_json::to_string(&s.labels)?;
                stmt.execute(params![batch.agent_id, s.metric, labels, s.ts, s.value])?;
                inserted += 1;
            }
        }

        // TTL 以 hub 的接收时间为准，避免 agent 时钟偏差导致过早/永不清理
        let received_at = rustboard_common::util::now_ms();
        tx.execute(
            "INSERT INTO ingest_batches (agent_id, epoch, seq, ts) VALUES (?1, ?2, ?3, ?4)",
            params![batch.agent_id, batch.epoch, batch.seq, received_at],
        )?;
        tx.execute(
            "INSERT INTO ingest_state (agent_id, epoch, last_seq, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(agent_id, epoch) DO UPDATE SET
                last_seq = MAX(ingest_state.last_seq, excluded.last_seq),
                updated_at = excluded.updated_at",
            params![batch.agent_id, batch.epoch, batch.seq, batch.sent_at],
        )?;

        // 每 512 次成功插入清理一次 48h 前的判重记录，避免每批都 DELETE。
        let completed = self.inserted_batches.fetch_add(1, Ordering::Relaxed) + 1;
        if completed % INGEST_CLEANUP_EVERY == 0 {
            prune_ingest_batches(&tx, rustboard_common::util::now_ms())?;
        }

        tx.commit()?;
        Ok(IngestOutcome::Inserted { inserted })
    }

    fn list_agents(&self) -> Result<Vec<AgentRecord>> {
        let conn = self.lock_read();
        let mut stmt = conn.prepare(
            "SELECT agent_id, name, hostname, os, arch, version, boot_id, status, last_seen_at, created_at
             FROM agents ORDER BY name",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AgentRecord {
                agent_id: r.get(0)?,
                name: r.get(1)?,
                hostname: r.get(2)?,
                os: r.get(3)?,
                arch: r.get(4)?,
                version: r.get(5)?,
                boot_id: r.get(6)?,
                status: r.get(7)?,
                last_seen_at: r.get(8)?,
                created_at: r.get(9)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn get_agent(&self, agent_id: &str) -> Result<Option<AgentRecord>> {
        let conn = self.lock_read();
        let row = conn
            .query_row(
                "SELECT agent_id, name, hostname, os, arch, version, boot_id, status, last_seen_at, created_at
                 FROM agents WHERE agent_id = ?1",
                params![agent_id],
                |r| {
                    Ok(AgentRecord {
                        agent_id: r.get(0)?,
                        name: r.get(1)?,
                        hostname: r.get(2)?,
                        os: r.get(3)?,
                        arch: r.get(4)?,
                        version: r.get(5)?,
                        boot_id: r.get(6)?,
                        status: r.get(7)?,
                        last_seen_at: r.get(8)?,
                        created_at: r.get(9)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    fn query_series(&self, query: &SeriesQuery) -> Result<Vec<SeriesRow>> {
        let conn = self.lock_read();
        let mut sql = String::from(
            "SELECT metric, labels, ts, value FROM samples
             WHERE agent_id = ?1 AND ts >= ?2 AND ts <= ?3",
        );
        let mut params: Vec<rusqlite::types::Value> = vec![
            rusqlite::types::Value::Text(query.agent_id.clone()),
            rusqlite::types::Value::Integer(query.from),
            rusqlite::types::Value::Integer(query.to),
        ];

        if !query.metrics.is_empty() {
            let holders = vec!["?"; query.metrics.len()].join(",");
            sql.push_str(&format!(" AND metric IN ({holders})"));
            for m in &query.metrics {
                params.push(rusqlite::types::Value::Text(m.clone()));
            }
        }
        sql.push_str(" ORDER BY ts ASC LIMIT ?");
        params.push(rusqlite::types::Value::Integer(query.limit as i64));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
            let labels_json: String = r.get(1)?;
            let labels: Labels = serde_json::from_str(&labels_json).unwrap_or_default();
            Ok(SeriesRow {
                metric: r.get(0)?,
                labels,
                ts: r.get(2)?,
                value: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn sample_count(&self, agent_id: &str) -> Result<i64> {
        let conn = self.lock_read();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM samples WHERE agent_id = ?1",
            params![agent_id],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    fn query_series_bucketed(&self, query: &SeriesQuery, bucket_ms: i64) -> Result<Vec<SeriesRow>> {
        if bucket_ms <= 0 {
            anyhow::bail!("bucket_ms 必须大于 0");
        }
        let conn = self.lock_read();

        // 参数全部绑定：只有占位符数量由 metrics 决定，值本身不进 SQL 文本。
        // 桶起点 = floor(ts / bucket_ms) * bucket_ms（Unix 毫秒均为正数）。
        let mut sql = String::from(
            "SELECT metric, labels, (ts / ?4) * ?4 AS bucket_ts, AVG(value)
             FROM samples
             WHERE agent_id = ?1 AND ts >= ?2 AND ts <= ?3",
        );
        let mut params: Vec<rusqlite::types::Value> = vec![
            rusqlite::types::Value::Text(query.agent_id.clone()),
            rusqlite::types::Value::Integer(query.from),
            rusqlite::types::Value::Integer(query.to),
            rusqlite::types::Value::Integer(bucket_ms),
        ];
        if !query.metrics.is_empty() {
            let holders: Vec<String> = (0..query.metrics.len())
                .map(|i| format!("?{}", 5 + i))
                .collect();
            sql.push_str(&format!(" AND metric IN ({})", holders.join(",")));
            for metric in &query.metrics {
                params.push(rusqlite::types::Value::Text(metric.clone()));
            }
        }
        let limit_idx = params.len() + 1;
        sql.push_str(&format!(
            " GROUP BY metric, labels, bucket_ts
              ORDER BY metric, labels, bucket_ts
              LIMIT ?{limit_idx}"
        ));
        params.push(rusqlite::types::Value::Integer(i64::from(query.limit)));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
            let labels_json: String = r.get(1)?;
            let labels: Labels = serde_json::from_str(&labels_json).unwrap_or_default();
            Ok(SeriesRow {
                metric: r.get(0)?,
                labels,
                ts: r.get(2)?,
                value: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn query_series_tiered(
        &self,
        query: &SeriesQuery,
        bucket_ms: i64,
        tier: SampleTier,
    ) -> Result<Vec<SeriesRow>> {
        if bucket_ms <= 0 {
            anyhow::bail!("bucket_ms 必须大于 0");
        }
        if tier == SampleTier::Raw {
            // raw 路径保持旧行为不变（包含 AVG(value) 与原有时间过滤）。
            return self.query_series_bucketed(query, bucket_ms);
        }
        let (table, tier_granularity) = match tier {
            SampleTier::Raw => unreachable!("raw 已在上面委托"),
            SampleTier::OneMinute => ("samples_1m", BUCKET_1M_MS),
            SampleTier::OneHour => ("samples_1h", BUCKET_1H_MS),
        };
        let conn = self.lock_read();

        // 表名来自固定分支，不接受外部输入；值全部参数绑定。
        // - 请求桶起点 = floor(bucket_ts / bucket_ms) * bucket_ms；别名不能叫
        //   bucket_ts（会与源列同名，GROUP BY 解析到源列而拆散聚合）；
        // - 与 [from, to] 有重叠即纳入；`bucket_ts > from - 层粒度` 是
        //   `bucket_ts + 层粒度 > from` 的等价改写，避免列上表达式导致全表扫描；
        // - value 必须按 count 加权平均，不能对各层均值再取简单平均。
        let sql = tiered_query_sql(table, query.metrics.len());
        let mut params: Vec<rusqlite::types::Value> = vec![
            rusqlite::types::Value::Text(query.agent_id.clone()),
            rusqlite::types::Value::Integer(query.from.saturating_sub(tier_granularity)),
            rusqlite::types::Value::Integer(query.to),
            rusqlite::types::Value::Integer(bucket_ms),
        ];
        for metric in &query.metrics {
            params.push(rusqlite::types::Value::Text(metric.clone()));
        }
        params.push(rusqlite::types::Value::Integer(i64::from(query.limit)));

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), |r| {
            let labels_json: String = r.get(1)?;
            let labels: Labels = serde_json::from_str(&labels_json).unwrap_or_default();
            Ok(SeriesRow {
                metric: r.get(0)?,
                labels,
                ts: r.get(2)?,
                value: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn latest_samples(
        &self,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
    ) -> Result<Vec<AgentSeriesRow>> {
        // 先走 raw；只有 raw 完全没有数据时才依次回退 1m、1h，避免保留期删除
        // raw 后面板「最新点」整片空白。任一层有数据就不再继续回落。
        let rows = self.latest_samples_limited(since, metrics, agent, LATEST_SAMPLES_SQL_LIMIT)?;
        if !rows.is_empty() {
            return Ok(rows);
        }
        for tier in [SampleTier::OneMinute, SampleTier::OneHour] {
            let rows = self.latest_tier_samples(tier, since, metrics, agent)?;
            if !rows.is_empty() {
                return Ok(rows);
            }
        }
        Ok(Vec::new())
    }

    fn get_sample_interval(&self, agent_id: &str) -> Result<Option<u64>> {
        let stored: Option<i64> = self
            .lock_read()
            .query_row(
                "SELECT sample_interval_ms FROM agent_settings WHERE agent_id = ?1",
                params![agent_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(stored.and_then(|ms| u64::try_from(ms).ok()))
    }

    fn set_sample_interval(&self, agent_id: &str, ms: u64, now: i64) -> Result<()> {
        let ms = i64::try_from(ms).context("sample_interval_ms 超出可存储范围")?;
        self.lock_write().execute(
            "INSERT INTO agent_settings (agent_id, sample_interval_ms, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_id) DO UPDATE SET
                sample_interval_ms = excluded.sample_interval_ms,
                updated_at = excluded.updated_at",
            params![agent_id, ms, now],
        )?;
        Ok(())
    }

    fn list_sample_intervals(&self) -> Result<Vec<(String, u64)>> {
        let conn = self.lock_read();
        let mut stmt = conn
            .prepare("SELECT agent_id, sample_interval_ms FROM agent_settings ORDER BY agent_id")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (agent_id, ms) = row?;
            if let Ok(ms) = u64::try_from(ms) {
                out.push((agent_id, ms));
            }
        }
        Ok(out)
    }

    fn create_enroll_token(
        &self,
        token_hash: &str,
        name: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        self.lock_write().execute(
            "INSERT INTO enroll_tokens (token_hash, name, created_at, expires_at, used_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![token_hash, name, created_at, expires_at],
        )?;
        Ok(())
    }

    fn consume_enroll_token(&self, token_hash: &str, now: i64) -> Result<Option<String>> {
        let mut conn = self.lock_write();
        let tx = conn.transaction()?;
        let name: Option<String> = tx
            .query_row(
                "SELECT name FROM enroll_tokens
                 WHERE token_hash = ?1 AND used_at IS NULL AND expires_at > ?2",
                params![token_hash, now],
                |r| r.get(0),
            )
            .optional()?;
        if name.is_some() {
            tx.execute(
                "UPDATE enroll_tokens SET used_at = ?2 WHERE token_hash = ?1",
                params![token_hash, now],
            )?;
        }
        tx.commit()?;
        Ok(name)
    }

    fn set_agent_secret(&self, agent_id: &str, secret_hash: &str, created_at: i64) -> Result<()> {
        self.lock_write().execute(
            "INSERT INTO agent_secrets (agent_id, secret_hash, created_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_id) DO UPDATE SET
                secret_hash = excluded.secret_hash,
                created_at = excluded.created_at",
            params![agent_id, secret_hash, created_at],
        )?;
        Ok(())
    }

    fn verify_agent_secret(&self, agent_id: &str, secret_hash: &str) -> Result<bool> {
        let stored: Option<String> = self
            .lock_read()
            .query_row(
                "SELECT secret_hash FROM agent_secrets WHERE agent_id = ?1",
                params![agent_id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(stored
            .map(|s| rustboard_common::util::constant_time_eq(s.as_bytes(), secret_hash.as_bytes()))
            .unwrap_or(false))
    }

    fn revoke_agent(&self, agent_id: &str, ts: i64) -> Result<()> {
        // L2：吊销涉及三张表，必须同一事务提交，避免只写了一半。
        let mut conn = self.lock_write();
        let tx = conn.transaction()?;
        tx.execute(
            "INSERT INTO revoked_agents (agent_id, revoked_at) VALUES (?1, ?2)
             ON CONFLICT(agent_id) DO UPDATE SET revoked_at = excluded.revoked_at",
            params![agent_id, ts],
        )?;
        tx.execute(
            "UPDATE agents SET status = 'revoked' WHERE agent_id = ?1",
            params![agent_id],
        )?;
        tx.execute(
            "DELETE FROM agent_secrets WHERE agent_id = ?1",
            params![agent_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn is_revoked(&self, agent_id: &str) -> Result<bool> {
        let exists: i64 = self.lock_read().query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_agents WHERE agent_id = ?1)",
            params![agent_id],
            |r| r.get(0),
        )?;
        Ok(exists != 0)
    }

    // ---- M3：控制面能力与审计 ----

    fn upsert_agent_control(
        &self,
        agent_id: &str,
        capabilities: &[String],
        updated_at: i64,
    ) -> Result<()> {
        let json = serde_json::to_string(capabilities).context("序列化控制能力失败")?;
        self.lock_write().execute(
            "INSERT INTO agent_control (agent_id, capabilities, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_id) DO UPDATE SET
                capabilities = excluded.capabilities,
                updated_at = excluded.updated_at",
            params![agent_id, json, updated_at],
        )?;
        Ok(())
    }

    fn get_agent_control(&self, agent_id: &str) -> Result<Option<AgentControlRecord>> {
        let row: Option<(String, i64)> = self
            .lock_read()
            .query_row(
                "SELECT capabilities, updated_at FROM agent_control WHERE agent_id = ?1",
                params![agent_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((json, updated_at)) = row else {
            return Ok(None);
        };
        // 数据库内容可能来自旧版本或被损坏：解析失败降级为空能力而不是报错，
        // 控制 API 会因此返回 403，面板仍能正常打开。
        let capabilities: Vec<String> = match serde_json::from_str(&json) {
            Ok(capabilities) => capabilities,
            Err(err) => {
                tracing::warn!(
                    agent = %agent_id,
                    error = %err,
                    "agent_control.capabilities 不是合法 JSON，按空能力处理"
                );
                Vec::new()
            }
        };
        Ok(Some(AgentControlRecord {
            capabilities,
            updated_at,
        }))
    }

    fn insert_audit(&self, entry: &NewAuditEntry) -> Result<i64> {
        // 最后防线：调用方已限长，这里再夹一次，避免异常调用撑大数据库。
        let params = truncate_utf8(&entry.params, MAX_AUDIT_PARAMS_BYTES);
        let conn = self.lock_write();
        conn.execute(
            "INSERT INTO audit_log
                (ts, actor, agent_id, capability, action, target, params, result,
                 error_code, error_message, duration_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                entry.ts,
                entry.actor,
                entry.agent_id,
                entry.capability,
                entry.action,
                entry.target,
                params,
                entry.result,
                entry.error_code,
                entry.error_message,
                entry.duration_ms
            ],
        )?;
        let id = conn.last_insert_rowid();

        // 每 1000 条成功写入清理一次 180 天前的记录，避免每条都 DELETE。
        let written = self.audit_writes.fetch_add(1, Ordering::Relaxed) + 1;
        if written % AUDIT_CLEANUP_EVERY == 0 {
            let cutoff = rustboard_common::util::now_ms().saturating_sub(AUDIT_RETENTION_MS);
            match conn.execute("DELETE FROM audit_log WHERE ts < ?1", params![cutoff]) {
                Ok(removed) if removed > 0 => {
                    tracing::info!(removed, cutoff, "已清理过期审计记录");
                }
                Ok(_) => {}
                Err(err) => tracing::warn!(error = %err, "清理过期审计记录失败"),
            }
        }
        Ok(id)
    }

    fn list_audit(
        &self,
        limit: usize,
        before_id: Option<i64>,
        agent_id: Option<&str>,
        capability: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut sql = String::from(
            "SELECT id, ts, actor, agent_id, capability, action, target, params, result,
                    error_code, error_message, duration_ms
             FROM audit_log WHERE 1 = 1",
        );
        let mut values: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(before_id) = before_id {
            sql.push_str(" AND id < ?");
            values.push(rusqlite::types::Value::Integer(before_id));
        }
        if let Some(agent_id) = agent_id {
            sql.push_str(" AND agent_id = ?");
            values.push(rusqlite::types::Value::Text(agent_id.to_string()));
        }
        if let Some(capability) = capability {
            sql.push_str(" AND capability = ?");
            values.push(rusqlite::types::Value::Text(capability.to_string()));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        values.push(rusqlite::types::Value::Integer(
            i64::try_from(limit).unwrap_or(i64::MAX),
        ));

        let conn = self.lock_read();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(values), |r| {
            Ok(AuditEntry {
                id: r.get(0)?,
                ts: r.get(1)?,
                actor: r.get(2)?,
                agent_id: r.get(3)?,
                capability: r.get(4)?,
                action: r.get(5)?,
                target: r.get(6)?,
                params: r.get(7)?,
                result: r.get(8)?,
                error_code: r.get(9)?,
                error_message: r.get(10)?,
                duration_ms: r.get(11)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn prune_audit(&self, before_ts: i64) -> Result<usize> {
        let removed = self
            .lock_write()
            .execute("DELETE FROM audit_log WHERE ts < ?1", params![before_ts])?;
        Ok(removed)
    }

    fn get_maintenance_state(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock_read();
        Ok(conn
            .query_row(
                "SELECT value FROM maintenance_state WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn set_maintenance_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()> {
        self.lock_write().execute(
            "INSERT INTO maintenance_state (key, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET
                 value = excluded.value,
                 updated_at = excluded.updated_at",
            params![key, value, updated_at],
        )?;
        Ok(())
    }

    fn list_maintenance_state(&self) -> Result<Vec<MaintenanceStateEntry>> {
        let conn = self.lock_read();
        let mut stmt =
            conn.prepare("SELECT key, value, updated_at FROM maintenance_state ORDER BY key ASC")?;
        let rows = stmt.query_map([], |row| {
            Ok(MaintenanceStateEntry {
                key: row.get(0)?,
                value: row.get(1)?,
                updated_at: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

// ---------------------------------------------------------------------------
// M4-B1：告警规则（schema v7 `alert_rules` 表）
// ---------------------------------------------------------------------------

/// `alert_rules` 的 SELECT 列表；与 [`alert_rule_from_row`] 的列下标一一对应。
const ALERT_RULE_COLUMNS: &str = "id, name, enabled, source, metric, comparator, threshold, \
     duration_secs, cooldown_secs, filter_agent_id, filter_labels, channel_ids, \
     notify_on_resolve, is_builtin, updated_by, created_at, updated_at";

/// 新建 / 种子共用的列清单。
const ALERT_RULE_INSERT_COLUMNS: &str = "(id, name, enabled, source, metric, comparator, \
     threshold, duration_secs, cooldown_secs, filter_agent_id, filter_labels, channel_ids, \
     notify_on_resolve, is_builtin, updated_by, created_at, updated_at)";

/// 更新语句只覆盖可写字段：id 不变，`is_builtin` / `created_at` 由存储层保持原值。
const ALERT_RULE_UPDATE_SQL: &str =
    "UPDATE alert_rules SET name = ?2, enabled = ?3, source = ?4, metric = ?5, \
     comparator = ?6, threshold = ?7, duration_secs = ?8, cooldown_secs = ?9, \
     filter_agent_id = ?10, filter_labels = ?11, channel_ids = ?12, \
     notify_on_resolve = ?13, updated_by = ?14, updated_at = ?15 WHERE id = ?1";

/// 数据库里出现未知枚举值时产生的错误（不静默降级成默认值）。
#[derive(Debug)]
struct AlertRuleColumnError(&'static str);

impl std::fmt::Display for AlertRuleColumnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "alert_rules.{} 字段值非法", self.0)
    }
}

impl std::error::Error for AlertRuleColumnError {}

/// 把列值损坏翻译成 rusqlite 错误，让上层拿到明确失败而不是被默认值掩盖。
fn alert_rule_column_error(column: usize, field: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        Box::new(AlertRuleColumnError(field)),
    )
}

fn parse_alert_source(raw: &str, column: usize) -> rusqlite::Result<AlertSource> {
    AlertSource::parse(raw).ok_or_else(|| alert_rule_column_error(column, "source"))
}

fn parse_alert_comparator(raw: &str, column: usize) -> rusqlite::Result<Comparator> {
    Comparator::parse(raw).ok_or_else(|| alert_rule_column_error(column, "comparator"))
}

fn parse_alert_rule_json<T: serde::de::DeserializeOwned>(
    raw: &str,
    column: usize,
    field: &'static str,
) -> rusqlite::Result<T> {
    serde_json::from_str(raw).map_err(|_| alert_rule_column_error(column, field))
}

/// 一行 `alert_rules` 映射成 [`AlertRule`]；SELECT 列顺序必须与 [`ALERT_RULE_COLUMNS`] 一致。
fn alert_rule_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRule> {
    let enabled: i64 = row.get(2)?;
    let source: String = row.get(3)?;
    let comparator: String = row.get(5)?;
    let filter_labels: String = row.get(10)?;
    let channel_ids: String = row.get(11)?;
    let notify_on_resolve: i64 = row.get(12)?;
    let is_builtin: i64 = row.get(13)?;
    Ok(AlertRule {
        id: row.get(0)?,
        name: row.get(1)?,
        enabled: enabled != 0,
        source: parse_alert_source(&source, 3)?,
        metric: row.get(4)?,
        comparator: parse_alert_comparator(&comparator, 5)?,
        threshold: row.get(6)?,
        duration_secs: row.get(7)?,
        cooldown_secs: row.get(8)?,
        filter_agent_id: row.get(9)?,
        filter_labels: parse_alert_rule_json(&filter_labels, 10, "filter_labels")?,
        channel_ids: parse_alert_rule_json(&channel_ids, 11, "channel_ids")?,
        notify_on_resolve: notify_on_resolve != 0,
        is_builtin: is_builtin != 0,
        updated_by: row.get(14)?,
        created_at: row.get(15)?,
        updated_at: row.get(16)?,
    })
}

/// 把 `alert_rules.name` 的唯一约束冲突翻译成领域错误，不透传 SQL。
fn map_alert_rule_unique_error(err: rusqlite::Error) -> anyhow::Error {
    if let rusqlite::Error::SqliteFailure(inner, Some(message)) = &err {
        if inner.code == rusqlite::ErrorCode::ConstraintViolation
            && message.contains("alert_rules.name")
        {
            return AlertRuleStoreError::NameExists.into();
        }
    }
    tracing::debug!(error = %err, "写入告警规则失败（非名称唯一约束错误）");
    anyhow::anyhow!("写入告警规则失败（数据库错误，详见日志）")
}

impl SqliteStorage {
    /// 写入内置规则种子：`INSERT OR IGNORE`，已存在的规则（含用户改过的阈值 /
    /// 启停状态）**绝不覆盖**；重复调用幂等，返回本次新插入的条数。
    ///
    /// `now` 作为新插入行的 `created_at` / `updated_at`；调用方通常传 `now_ms()`。
    pub fn seed_builtin_alert_rules(&self, rules: &[AlertRule], now: i64) -> Result<usize> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sql = format!(
            "INSERT OR IGNORE INTO alert_rules {ALERT_RULE_INSERT_COLUMNS} \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
        );
        let mut inserted = 0usize;
        for rule in rules {
            let filter_labels = serde_json::to_string(&rule.filter_labels)?;
            let channel_ids = serde_json::to_string(&rule.channel_ids)?;
            inserted += tx.execute(
                &sql,
                params![
                    rule.id,
                    rule.name,
                    rule.enabled as i64,
                    rule.source.as_str(),
                    rule.metric,
                    rule.comparator.as_str(),
                    rule.threshold,
                    i64::from(rule.duration_secs),
                    i64::from(rule.cooldown_secs),
                    rule.filter_agent_id.as_deref(),
                    filter_labels,
                    channel_ids,
                    rule.notify_on_resolve as i64,
                    rule.is_builtin as i64,
                    rule.updated_by,
                    now,
                    now,
                ],
            )?;
        }
        tx.commit()?;
        Ok(inserted)
    }

    /// 按 id 读取一条规则；不存在返回 `None`。
    pub fn get_alert_rule(&self, id: &str) -> Result<Option<AlertRule>> {
        let conn = self.lock_read();
        let sql = format!("SELECT {ALERT_RULE_COLUMNS} FROM alert_rules WHERE id = ?1");
        Ok(conn
            .query_row(&sql, params![id], alert_rule_from_row)
            .optional()?)
    }

    /// 列出全部规则：内置规则在前，同组按名称升序。
    pub fn list_alert_rules(&self) -> Result<Vec<AlertRule>> {
        let conn = self.lock_read();
        let sql = format!(
            "SELECT {ALERT_RULE_COLUMNS} FROM alert_rules ORDER BY is_builtin DESC, name ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], alert_rule_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 规则总数（含内置规则）。
    pub fn alert_rule_count(&self) -> Result<usize> {
        let conn = self.lock_read();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM alert_rules", [], |row| row.get(0))?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// 新建一条规则。
    ///
    /// 事务内先查重再写入，把两种失败翻译成领域错误：
    /// - 总数（含内置）达到 [`MAX_ALERT_RULES`] → [`AlertRuleStoreError::LimitReached`]；
    /// - 名称重复 → [`AlertRuleStoreError::NameExists`]（并发下仍由 UNIQUE 兜底）。
    pub fn create_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM alert_rules", [], |row| row.get(0))?;
        if count >= MAX_ALERT_RULES as i64 {
            return Err(AlertRuleStoreError::LimitReached.into());
        }
        let name_exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM alert_rules WHERE name = ?1",
                params![rule.name],
                |row| row.get(0),
            )
            .optional()?;
        if name_exists.is_some() {
            return Err(AlertRuleStoreError::NameExists.into());
        }
        let filter_labels = serde_json::to_string(&rule.filter_labels)?;
        let channel_ids = serde_json::to_string(&rule.channel_ids)?;
        let sql = format!(
            "INSERT INTO alert_rules {ALERT_RULE_INSERT_COLUMNS} VALUES \
             (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
        );
        tx.execute(
            &sql,
            params![
                rule.id,
                rule.name,
                rule.enabled as i64,
                rule.source.as_str(),
                rule.metric,
                rule.comparator.as_str(),
                rule.threshold,
                i64::from(rule.duration_secs),
                i64::from(rule.cooldown_secs),
                rule.filter_agent_id.as_deref(),
                filter_labels,
                channel_ids,
                rule.notify_on_resolve as i64,
                rule.is_builtin as i64,
                rule.updated_by,
                rule.created_at,
                rule.updated_at,
            ],
        )
        .map_err(map_alert_rule_unique_error)?;
        tx.commit()?;
        Ok(())
    }

    /// 更新一条规则的可写字段。
    ///
    /// - `id` 是定位键，`is_builtin` / `created_at` 保持数据库中的原值（上层改不了）；
    /// - 不存在 → [`AlertRuleStoreError::NotFound`]；
    /// - 改成与其它规则重名 → [`AlertRuleStoreError::NameExists`]。
    pub fn update_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM alert_rules WHERE id = ?1",
                params![rule.id],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(AlertRuleStoreError::NotFound.into());
        }
        let name_exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM alert_rules WHERE name = ?1 AND id != ?2",
                params![rule.name, rule.id],
                |row| row.get(0),
            )
            .optional()?;
        if name_exists.is_some() {
            return Err(AlertRuleStoreError::NameExists.into());
        }
        let filter_labels = serde_json::to_string(&rule.filter_labels)?;
        let channel_ids = serde_json::to_string(&rule.channel_ids)?;
        tx.execute(
            ALERT_RULE_UPDATE_SQL,
            params![
                rule.id,
                rule.name,
                rule.enabled as i64,
                rule.source.as_str(),
                rule.metric,
                rule.comparator.as_str(),
                rule.threshold,
                i64::from(rule.duration_secs),
                i64::from(rule.cooldown_secs),
                rule.filter_agent_id.as_deref(),
                filter_labels,
                channel_ids,
                rule.notify_on_resolve as i64,
                rule.updated_by,
                rule.updated_at,
            ],
        )
        .map_err(map_alert_rule_unique_error)?;
        tx.commit()?;
        Ok(())
    }

    /// 删除自定义规则；内置规则返回 [`AlertRuleStoreError::BuiltinRule`]。
    ///
    /// 不存在与内置是两种不同的错误，调用方分别映射 404 / 403。
    pub fn delete_alert_rule(&self, id: &str) -> Result<()> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let is_builtin: Option<i64> = tx
            .query_row(
                "SELECT is_builtin FROM alert_rules WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        match is_builtin {
            None => return Err(AlertRuleStoreError::NotFound.into()),
            Some(flag) if flag != 0 => return Err(AlertRuleStoreError::BuiltinRule.into()),
            Some(_) => {}
        }
        tx.execute("DELETE FROM alert_rules WHERE id = ?1", params![id])?;
        tx.commit()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// v6：管理 API scoped token
// ---------------------------------------------------------------------------

/// 允许的 scope 字符串；与 `api_tokens.scope` 的 CHECK 约束保持一致。
const API_TOKEN_SCOPES: [&str; 3] = ["read", "write", "admin"];

/// 把 `api_tokens` 的一行映射成记录。SELECT 的列顺序必须与这里一致。
fn row_to_api_token(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApiTokenRecord> {
    Ok(ApiTokenRecord {
        id: row.get(0)?,
        name: row.get(1)?,
        scope: row.get(2)?,
        created_at: row.get(3)?,
        last_used_at: row.get(4)?,
        revoked_at: row.get(5)?,
    })
}

/// `api_tokens` 的 SELECT 列表；与 [`row_to_api_token`] 一一对应。
const API_TOKEN_COLUMNS: &str = "id, name, scope, created_at, last_used_at, revoked_at";

/// 把唯一约束冲突翻译成可读错误，不把 SQL / 表结构泄露给 CLI 用户。
fn map_api_token_unique_error(err: rusqlite::Error, name: &str) -> anyhow::Error {
    if let rusqlite::Error::SqliteFailure(inner, Some(message)) = &err {
        if inner.code == rusqlite::ErrorCode::ConstraintViolation {
            if message.contains("api_tokens.name") {
                return anyhow::anyhow!("token 名称已存在: {name}");
            }
            if message.contains("api_tokens.token_hash") {
                return anyhow::anyhow!("token 哈希冲突，请重新生成 token");
            }
        }
    }
    // 兜底不透传原始 SQLite 错误（可能含 SQL / 文件路径），只记 debug。
    tracing::debug!(error = %err, "创建/轮换 token 失败（非唯一约束错误）");
    anyhow::anyhow!("创建/轮换 token 失败: {name}（数据库错误，详见日志）")
}

impl SqliteStorage {
    /// 新建一条 scoped token；`token_hash` 是明文的 SHA-256 hex。
    ///
    /// 重复 name 返回可读错误；非法 scope 在落库前就被拒绝（数据库 CHECK 是
    /// 最后防线）。
    pub fn create_api_token(
        &self,
        name: &str,
        token_hash: &str,
        scope: &str,
        created_at: i64,
    ) -> Result<ApiTokenRecord> {
        if !API_TOKEN_SCOPES.contains(&scope) {
            anyhow::bail!("非法 token scope: {scope}（只允许 read / write / admin）");
        }
        let conn = self.lock_write();
        conn.execute(
            "INSERT INTO api_tokens (name, token_hash, scope, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![name, token_hash, scope, created_at],
        )
        .map_err(|err| map_api_token_unique_error(err, name))?;
        Ok(ApiTokenRecord {
            id: conn.last_insert_rowid(),
            name: name.to_string(),
            scope: scope.to_string(),
            created_at,
            last_used_at: None,
            revoked_at: None,
        })
    }

    /// 按 name 升序列出全部 token（含已吊销）；不返回哈希或明文。
    pub fn list_api_tokens(&self) -> Result<Vec<ApiTokenRecord>> {
        let conn = self.lock_read();
        let sql = format!("SELECT {API_TOKEN_COLUMNS} FROM api_tokens ORDER BY name ASC");
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_api_token)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 轮换 token：同一行写入新哈希、清 `revoked_at`，旧哈希立即失效。
    ///
    /// 新凭据的 `created_at` 记为本次轮换时间，`last_used_at` 清空（新凭据尚未
    /// 使用）；name / scope / id 不变，因此审计 actor 保持稳定。
    pub fn rotate_api_token(
        &self,
        name: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<ApiTokenRecord> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = tx.execute(
            "UPDATE api_tokens
             SET token_hash = ?2, created_at = ?3, last_used_at = NULL, revoked_at = NULL
             WHERE name = ?1",
            params![name, token_hash, now],
        );
        let updated = match updated {
            Ok(updated) => updated,
            Err(err) => return Err(map_api_token_unique_error(err, name)),
        };
        if updated == 0 {
            anyhow::bail!("token 不存在: {name}");
        }
        let sql = format!("SELECT {API_TOKEN_COLUMNS} FROM api_tokens WHERE name = ?1");
        let record = tx.query_row(&sql, params![name], row_to_api_token)?;
        tx.commit()?;
        Ok(record)
    }

    /// 吊销 token：只写 `revoked_at`，不删行。
    ///
    /// 不存在与已吊销是两种不同的可读错误；重复吊销不会刷新时间戳。
    pub fn revoke_api_token(&self, name: &str, now: i64) -> Result<()> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let updated = tx.execute(
            "UPDATE api_tokens SET revoked_at = ?2 WHERE name = ?1 AND revoked_at IS NULL",
            params![name, now],
        )?;
        if updated == 0 {
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM api_tokens WHERE name = ?1",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            anyhow::bail!(match exists {
                Some(_) => format!("token 已吊销: {name}"),
                None => format!("token 不存在: {name}"),
            });
        }
        tx.commit()?;
        Ok(())
    }

    /// 鉴权：只返回未吊销行，并 best-effort 更新 `last_used_at`。
    ///
    /// - 60s 节流：同一 token 的 `last_used_at` 每 60s 最多写一次；首次必写。
    /// - 更新失败只记 debug，不影响本次鉴权结果（读路径已完成）。
    /// - 若更新时发现行已被并发吊销（影响 0 行），按未认证处理（安全默认拒绝）。
    ///
    /// 并发下两个请求可能同时通过节流判断、各写一次 `last_used_at`；两次写入
    /// 都是幂等的统计更新，最多多一条 UPDATE，不影响鉴权与吊销语义。
    pub fn authenticate_api_token(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<ApiTokenRecord>> {
        let sql = format!(
            "SELECT {API_TOKEN_COLUMNS} FROM api_tokens
             WHERE token_hash = ?1 AND revoked_at IS NULL"
        );
        // 显式作用域释放读连接：读池为空时会回退到写连接，提前 drop 才能避免
        // 后续 UPDATE 等待自己持有的写锁。
        let record: Option<ApiTokenRecord> = {
            let conn = self.lock_read();
            conn.query_row(&sql, params![token_hash], row_to_api_token)
                .optional()?
        };
        let Some(mut record) = record else {
            return Ok(None);
        };

        let should_touch = record
            .last_used_at
            .map(|last| now.saturating_sub(last) >= API_TOKEN_LAST_USED_THROTTLE_MS)
            .unwrap_or(true);
        if should_touch {
            match self.lock_write().execute(
                "UPDATE api_tokens SET last_used_at = ?2
                 WHERE id = ?1 AND revoked_at IS NULL",
                params![record.id, now],
            ) {
                Ok(0) => return Ok(None),
                Ok(_) => record.last_used_at = Some(now),
                Err(err) => {
                    // 鉴权已成功，last_used_at 只是统计信息，绝不能因此拒绝请求。
                    tracing::debug!(token = %record.name, error = %err, "更新 token last_used_at 失败");
                }
            }
        }
        Ok(Some(record))
    }
}

// ---------------------------------------------------------------------------
// M4：降采样与保留期（schema v7 的 samples_1m / samples_1h / maintenance_state）
// ---------------------------------------------------------------------------

/// 把时间戳向下取整到 `bucket_ms` 边界（UTC 毫秒，非负）。
fn bucket_floor(ts: i64, bucket_ms: i64) -> i64 {
    ts.div_euclid(bucket_ms) * bucket_ms
}

impl SqliteStorage {
    /// 把 `[from_ts, to_ts)` 内已完成的分钟 raw 聚合成 `samples_1m`。
    ///
    /// - 调用方负责只传「已关闭」的分钟；这里会把两端向下取整到整分钟，
    ///   保证不会把半分钟数据算进一个不完整的桶；
    /// - 按主键 upsert，重复执行幂等（值被重算覆盖，行数不增）；
    /// - `last_value` 取桶内最大 `ts`，同 ts 取最大 `rowid`；
    /// - labels 按原始文本分组，不做 JSON 归一化。
    ///
    /// 返回本次 upsert 的桶数与参与聚合的 raw 行数。
    pub fn downsample_1m_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult> {
        let from = bucket_floor(from_ts, BUCKET_1M_MS);
        let to = bucket_floor(to_ts, BUCKET_1M_MS);
        if to <= from {
            return Ok(DownsampleRangeResult::default());
        }
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows: i64 = tx.query_row(
            "SELECT COUNT(*) FROM samples WHERE ts >= ?1 AND ts < ?2",
            params![from, to],
            |row| row.get(0),
        )?;
        let buckets = tx.execute(AGGREGATE_1M_SQL, params![from, to])?;
        tx.commit()?;
        Ok(DownsampleRangeResult {
            buckets,
            rows: rows as usize,
        })
    }

    /// 把 `[from_ts, to_ts)` 内已完成整点的 1m 桶聚合成 `samples_1h`。
    ///
    /// `avg_value` 使用按 `count` 加权的平均值；`last_value` 取最新 1m 桶；
    /// 两端向下取整到整点，保证不聚合半个小时的残缺数据；upsert 幂等。
    pub fn downsample_1h_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult> {
        let from = bucket_floor(from_ts, BUCKET_1H_MS);
        let to = bucket_floor(to_ts, BUCKET_1H_MS);
        if to <= from {
            return Ok(DownsampleRangeResult::default());
        }
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows: i64 = tx.query_row(
            "SELECT COUNT(*) FROM samples_1m WHERE bucket_ts >= ?1 AND bucket_ts < ?2",
            params![from, to],
            |row| row.get(0),
        )?;
        let buckets = tx.execute(AGGREGATE_1H_SQL, params![from, to])?;
        tx.commit()?;
        Ok(DownsampleRangeResult {
            buckets,
            rows: rows as usize,
        })
    }

    /// raw 层的行数与最旧/最新时间戳。
    pub fn raw_stats(&self) -> Result<TierStats> {
        self.tier_stats("SELECT COUNT(*), MIN(ts), MAX(ts) FROM samples")
    }

    /// 1m 层的行数与最旧/最新时间戳。
    pub fn samples_1m_stats(&self) -> Result<TierStats> {
        self.tier_stats("SELECT COUNT(*), MIN(bucket_ts), MAX(bucket_ts) FROM samples_1m")
    }

    /// 1h 层的行数与最旧/最新时间戳。
    pub fn samples_1h_stats(&self) -> Result<TierStats> {
        self.tier_stats("SELECT COUNT(*), MIN(bucket_ts), MAX(bucket_ts) FROM samples_1h")
    }

    /// 三张表的统计查询只差表名/列名；SQL 是编译期常量，不接受外部输入。
    fn tier_stats(&self, sql: &'static str) -> Result<TierStats> {
        let conn = self.lock_read();
        Ok(conn.query_row(sql, [], |row| {
            Ok(TierStats {
                rows: row.get(0)?,
                oldest_ts: row.get(1)?,
                newest_ts: row.get(2)?,
            })
        })?)
    }

    /// 取 raw `[from_ts, to_ts)` 内按 `(ts, rowid)` 升序的第 `offset` 条（0-based）时间戳。
    ///
    /// 降采样分块用：找到第 N 条数据所在桶，就能把单事务控制在 N 行左右。
    /// 不足 `offset + 1` 条时返回 `None`。
    pub fn raw_ts_at_offset(&self, from_ts: i64, to_ts: i64, offset: usize) -> Result<Option<i64>> {
        self.ts_at_offset(
            "SELECT ts FROM samples WHERE ts >= ?1 AND ts < ?2 \
             ORDER BY ts ASC, rowid ASC LIMIT 1 OFFSET ?3",
            from_ts,
            to_ts,
            offset,
        )
    }

    /// 取 1m `[from_ts, to_ts)` 内按 `(bucket_ts, rowid)` 升序的第 `offset` 条时间戳。
    pub fn samples_1m_ts_at_offset(
        &self,
        from_ts: i64,
        to_ts: i64,
        offset: usize,
    ) -> Result<Option<i64>> {
        self.ts_at_offset(
            "SELECT bucket_ts FROM samples_1m WHERE bucket_ts >= ?1 AND bucket_ts < ?2 \
             ORDER BY bucket_ts ASC, rowid ASC LIMIT 1 OFFSET ?3",
            from_ts,
            to_ts,
            offset,
        )
    }

    fn ts_at_offset(
        &self,
        sql: &'static str,
        from_ts: i64,
        to_ts: i64,
        offset: usize,
    ) -> Result<Option<i64>> {
        let conn = self.lock_read();
        Ok(conn
            .query_row(sql, params![from_ts, to_ts, offset as i64], |row| {
                row.get(0)
            })
            .optional()?)
    }

    /// 读取 raw 当前最大 `rowid`，以及 `(after_rowid, max_rowid]` 区间内最旧 `ts`。
    ///
    /// 降采样用 `rowid` 水位发现迟到 / 重放批次：新写入的 raw 行 `rowid` 一定
    /// 更大，即使 `ts` 很旧也能被发现。
    ///
    /// **先读 `MAX(rowid)` 再读 `MIN(ts)`**：并发插入的行 `rowid > max`，不会
    /// 被本轮认领；即使它们 `ts` 很旧，下一轮也会被再次发现，不会漏。
    ///
    /// 返回 `(None, None)` 表示 raw 为空。`rowid` 空间可能因整表删除后重新插入
    /// 而回退（SQLite 未用 AUTOINCREMENT 时会复用 rowid）：此时忽略旧水位，
    /// 把所有现存行当作新行重新扫描，保守但不漏数据。
    pub fn raw_new_rows(&self, after_rowid: Option<i64>) -> Result<(Option<i64>, Option<i64>)> {
        let conn = self.lock_read();
        let max_rowid: Option<i64> =
            conn.query_row("SELECT MAX(rowid) FROM samples", [], |row| row.get(0))?;
        let Some(max_rowid) = max_rowid else {
            return Ok((None, None));
        };
        let after = match after_rowid {
            // last == max：没有新行，MIN 返回 NULL；
            // last > max：rowid 回退，按「全部是新行」重新扫描。
            Some(last) if last <= max_rowid => last,
            Some(_) | None => 0,
        };
        let min_ts: Option<i64> = conn.query_row(
            "SELECT MIN(ts) FROM samples WHERE rowid > ?1 AND rowid <= ?2",
            params![after, max_rowid],
            |row| row.get(0),
        )?;
        Ok((Some(max_rowid), min_ts))
    }

    /// 1m 层最旧桶时间；`None` 表示该层没有数据（用 `MIN` 走索引，不 `COUNT(*)`）。
    pub fn samples_1m_oldest_ts(&self) -> Result<Option<i64>> {
        let conn = self.lock_read();
        Ok(
            conn.query_row("SELECT MIN(bucket_ts) FROM samples_1m", [], |row| {
                row.get(0)
            })?,
        )
    }

    /// 分批删除 raw 中 `ts < cutoff` 的行；`cutoff` 是排他边界（等于不删）。
    pub fn prune_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_batched(PRUNE_RAW_SQL, cutoff)
    }

    /// 分批删除 1m 中 `bucket_ts < cutoff` 的行。
    pub fn prune_samples_1m_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_batched(PRUNE_1M_SQL, cutoff)
    }

    /// 分批删除 1h 中 `bucket_ts < cutoff` 的行。
    pub fn prune_samples_1h_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_batched(PRUNE_1H_SQL, cutoff)
    }

    /// 每批 [`PRUNE_BATCH_ROWS`] 行、每批独立隐式事务。
    ///
    /// 每轮循环内的写锁 guard 在批次结束后立即释放，等待中的 ingest 线程可以
    /// 插进来；批次之间再 `yield_now`，避免长时间占用 CPU 让写线程饿死。
    fn prune_batched(&self, sql: &'static str, cutoff: i64) -> Result<PruneResult> {
        let mut result = PruneResult::default();
        loop {
            let deleted = {
                let conn = self.lock_write();
                conn.execute(sql, params![cutoff, PRUNE_BATCH_ROWS as i64])?
            };
            if deleted == 0 {
                break;
            }
            result.deleted += deleted;
            result.batches += 1;
            if deleted < PRUNE_BATCH_ROWS {
                break;
            }
            std::thread::yield_now();
        }
        Ok(result)
    }

    /// 测试专用：读取 1m / 1h 聚合行，供 worker 单测断言聚合值。
    ///
    /// 生产代码不通过这里读数据（查询选层由 A2b 提供独立 API）；仅在同 crate
    /// 的 `#[cfg(test)]` 构建里可见。
    #[cfg(test)]
    pub(crate) fn aggregate_rows_for_test(&self, tier: &str) -> Vec<AggregateRowForTest> {
        let sql = match tier {
            "1m" => {
                "SELECT agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, \
                 last_value, count FROM samples_1m ORDER BY bucket_ts, labels"
            }
            "1h" => {
                "SELECT agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, \
                 last_value, count FROM samples_1h ORDER BY bucket_ts, labels"
            }
            other => panic!("未知聚合层: {other}"),
        };
        let conn = self.lock_read();
        let mut stmt = conn.prepare(sql).unwrap();
        stmt.query_map([], |row| {
            Ok(AggregateRowForTest {
                agent_id: row.get(0)?,
                metric: row.get(1)?,
                labels: row.get(2)?,
                bucket_ts: row.get(3)?,
                min_value: row.get(4)?,
                max_value: row.get(5)?,
                avg_value: row.get(6)?,
                last_value: row.get(7)?,
                count: row.get(8)?,
            })
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }
}

/// 测试专用：一行 1m / 1h 聚合结果。
#[cfg(test)]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct AggregateRowForTest {
    pub agent_id: String,
    pub metric: String,
    pub labels: String,
    pub bucket_ts: i64,
    pub min_value: f64,
    pub max_value: f64,
    pub avg_value: f64,
    pub last_value: f64,
    pub count: i64,
}

/// 按字节截断 UTF-8 字符串，保证不会切出半个字符。
fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::{IngestOutcome, RejectReason};
    use rustboard_common::model::Sample;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn batch_with(agent_id: &str, epoch: u64, seq: u64) -> SampleBatch {
        SampleBatch {
            agent_id: agent_id.into(),
            epoch,
            seq,
            boot_id: "boot".into(),
            sent_at: 1_700_000_000_000,
            samples: vec![
                Sample::new("cpu.usage", 1_700_000_000_000, 12.5),
                Sample::new("mem.used", 1_700_000_000_000, 1024.0),
            ],
        }
    }

    fn batch(seq: u64) -> SampleBatch {
        batch_with("a1", 1, seq)
    }

    fn agent_record(agent_id: &str, status: &str) -> AgentRecord {
        AgentRecord {
            agent_id: agent_id.into(),
            name: agent_id.into(),
            hostname: "host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "0.1.0".into(),
            boot_id: "boot".into(),
            status: status.into(),
            last_seen_at: 1,
            created_at: 1,
        }
    }

    fn ingest_states(s: &SqliteStorage) -> Vec<(u64, u64)> {
        let conn = s.lock_read();
        let mut stmt = conn
            .prepare("SELECT epoch, last_seq FROM ingest_state WHERE agent_id = ?1 ORDER BY epoch")
            .unwrap();
        stmt.query_map(params!["a1"], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    }

    #[test]
    fn insert_is_idempotent() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let first = s.insert_batch(&batch(1)).unwrap();
        assert_eq!(first, IngestOutcome::Inserted { inserted: 2 });

        let again = s.insert_batch(&batch(1)).unwrap();
        assert_eq!(again, IngestOutcome::Duplicate);
        assert_eq!(s.sample_count("a1").unwrap(), 2);
    }

    /// issue #4：A -> B -> A 重放已确认批次，不增加样本。
    #[test]
    fn ingest_ttl_covers_buffer_window() {
        // agent 缓冲最长保留 24h，判重记录必须至少覆盖它（当前 48h）。
        // 常量化校验：任何调小都会让这条测试失败
        assert_eq!(INGEST_BATCH_TTL_MS, 48 * 60 * 60 * 1_000);
    }

    #[test]
    fn replayed_batch_within_window_is_duplicate() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let mut b = batch(1);
        b.sent_at = rustboard_common::util::now_ms() - 60_000;
        assert!(matches!(
            s.insert_batch(&b).unwrap(),
            IngestOutcome::Inserted { .. }
        ));
        assert_eq!(s.insert_batch(&b).unwrap(), IngestOutcome::Duplicate);
        assert_eq!(s.sample_count("a1").unwrap(), 2);
    }

    #[test]
    fn issue_4_epoch_replay_a_b_a_stays_idempotent() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 1)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(
            s.insert_batch(&batch_with("a1", 2, 0)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        // 重放旧 epoch 的批次：v1 时代这里会重新插入
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 1)).unwrap(),
            IngestOutcome::Duplicate
        );
        assert_eq!(
            s.insert_batch(&batch_with("a1", 2, 0)).unwrap(),
            IngestOutcome::Duplicate
        );
        assert_eq!(s.sample_count("a1").unwrap(), 4);
    }

    /// issue #4：每个 epoch 的 last_seq 独立，旧 epoch 不会覆盖新 epoch 的状态。
    #[test]
    fn issue_4_old_epoch_does_not_overwrite_new_epoch() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(
            s.insert_batch(&batch_with("a1", 2, 0)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        // 旧 epoch 的高 seq 仍按自己的状态判断
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 9)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        // epoch 2 的状态不能被 epoch 1 覆盖，重放仍是重复
        assert_eq!(
            s.insert_batch(&batch_with("a1", 2, 0)).unwrap(),
            IngestOutcome::Duplicate
        );
        assert_eq!(ingest_states(&s), vec![(1, 9), (2, 0)]);
        assert_eq!(s.sample_count("a1").unwrap(), 4);
    }

    /// M2：同一 epoch 内乱序到达的 seq 不能被水位误判成重复。
    ///
    /// 旧实现用 `seq <= last_seq` 判重，「先 5 后 3」会把 seq 3 丢掉；
    /// 现在按 `(agent_id, epoch, seq)` 精确记录，两批都必须入库。
    #[test]
    fn m2_out_of_order_seq_within_epoch_is_inserted() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 5)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 3)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(s.sample_count("a1").unwrap(), 4);
        // 水位只做统计，取最大值
        assert_eq!(ingest_states(&s), vec![(1, 5)]);

        // 重放两批都仍是 Duplicate，不会重复增加样本。
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 5)).unwrap(),
            IngestOutcome::Duplicate
        );
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 3)).unwrap(),
            IngestOutcome::Duplicate
        );
        assert_eq!(s.sample_count("a1").unwrap(), 4);
    }

    /// M2：判重键精确到 seq，水位以下的未处理 seq 仍可以写入。
    #[test]
    fn m2_watermark_below_seq_does_not_block_new_sequences() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 5)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 4)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 6)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(s.sample_count("a1").unwrap(), 6);
        assert_eq!(ingest_states(&s), vec![(1, 6)]);
    }

    /// M2：每 512 次插入清理 48h 前的判重记录，之后旧批次重放会被视为新批次。
    #[test]
    fn m2_ingest_batches_are_pruned_after_ttl() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let now = rustboard_common::util::now_ms();
        let mut conn = s.lock_write();
        let tx = conn.transaction().unwrap();
        // 直接写入一条超期记录（insert_batch 用的是接收时间，构造不出旧值）
        tx.execute(
            "INSERT INTO ingest_batches (agent_id, epoch, seq, ts) VALUES ('a1', 9, 0, ?1)",
            params![now - INGEST_BATCH_TTL_MS - 60_000],
        )
        .unwrap();
        prune_ingest_batches(&tx, now).unwrap();
        tx.commit().unwrap();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM ingest_batches", [], |r| r.get(0))
            .unwrap();
        assert_eq!(remaining, 0, "超过 TTL 的判重记录应被清理");
    }

    /// issue #4：已吊销 agent 的批次直接被拒绝，且不写入样本与状态。
    #[test]
    fn issue_4_revoked_agent_batch_is_rejected_without_samples() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.revoke_agent("a1", 1).unwrap();

        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 0)).unwrap(),
            IngestOutcome::Rejected(RejectReason::Revoked)
        );
        assert_eq!(s.sample_count("a1").unwrap(), 0);
        let states: i64 = s
            .lock_read()
            .query_row("SELECT COUNT(*) FROM ingest_state", [], |r| r.get(0))
            .unwrap();
        assert_eq!(states, 0);
    }

    /// issue #4 / M2：v1 库按 user_version 迁移到 v3，已有 ingest_state 行必须保留，
    /// 并补齐 `ingest_batches` 表；迁移后按 seq 精确判重。
    #[test]
    fn issue_4_v1_schema_migrates_and_preserves_state() {
        let dir = std::env::temp_dir().join(format!("rb-sqlite-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("rustboard.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE ingest_state (
                     agent_id   TEXT PRIMARY KEY,
                     epoch      INTEGER NOT NULL DEFAULT 0,
                     last_seq   INTEGER NOT NULL DEFAULT 0,
                     updated_at INTEGER NOT NULL DEFAULT 0
                 );
                 INSERT INTO ingest_state (agent_id, epoch, last_seq, updated_at)
                     VALUES ('a1', 7, 5, 42);",
            )
            .unwrap();
        }

        let s = SqliteStorage::open(&db_path).unwrap();
        let version: i64 = s
            .lock_read()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let batches_table: i64 = s
            .lock_read()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'ingest_batches')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(batches_table, 1);
        // 迁移保留了旧状态行（v1 主键含 agent_id，若未迁移这里会丢）。
        assert_eq!(ingest_states(&s), vec![(7, 5)]);

        // 旧库里没有逐批记录，因此 (7,5) 第一次按新数据写入，重放才判重。
        assert_eq!(
            s.insert_batch(&batch_with("a1", 7, 5)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(
            s.insert_batch(&batch_with("a1", 7, 5)).unwrap(),
            IngestOutcome::Duplicate
        );
        assert_eq!(
            s.insert_batch(&batch_with("a1", 7, 6)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        // 新 epoch 有独立状态（若仍以 agent_id 为主键这里会冲突）
        assert_eq!(
            s.insert_batch(&batch_with("a1", 8, 0)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(s.sample_count("a1").unwrap(), 6);
        assert_eq!(ingest_states(&s), vec![(7, 6), (8, 0)]);

        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L3：v2 库（user_version=2）启动时补建 ingest_batches / agent_settings /
    /// v5 控制面表，user_version 升级到当前版本。
    #[test]
    fn l3_v2_schema_upgrades_to_v3_with_ingest_batches() {
        let dir = std::env::temp_dir().join(format!("rb-sqlite-v2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("rustboard.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE ingest_state (
                     agent_id   TEXT NOT NULL,
                     epoch      INTEGER NOT NULL,
                     last_seq   INTEGER NOT NULL DEFAULT 0,
                     updated_at INTEGER NOT NULL DEFAULT 0,
                     PRIMARY KEY (agent_id, epoch)
                 );
                 INSERT INTO ingest_state (agent_id, epoch, last_seq, updated_at)
                     VALUES ('a1', 1, 9, 42);
                 PRAGMA user_version = 2;",
            )
            .unwrap();
        }

        let s = SqliteStorage::open(&db_path).unwrap();
        let version: i64 = s
            .lock_read()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        // 水位 9 只作统计：seq 3 未处理过，必须正常写入（M2）。
        assert_eq!(
            s.insert_batch(&batch_with("a1", 1, 3)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(s.sample_count("a1").unwrap(), 2);
        assert_eq!(ingest_states(&s), vec![(1, 9)]);

        drop(s);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn enroll_token_is_single_use() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.create_enroll_token("hash-a", "web-01", 1_000, 5_000)
            .unwrap();
        assert_eq!(
            s.consume_enroll_token("hash-a", 2_000).unwrap().as_deref(),
            Some("web-01")
        );
        // 第二次使用必须失败
        assert_eq!(s.consume_enroll_token("hash-a", 2_100).unwrap(), None);
        // 未知 token 同样失败
        assert_eq!(s.consume_enroll_token("hash-b", 2_100).unwrap(), None);
    }

    #[test]
    fn expired_enroll_token_rejected() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.create_enroll_token("hash-c", "web-02", 1_000, 2_000)
            .unwrap();
        assert_eq!(s.consume_enroll_token("hash-c", 2_001).unwrap(), None);
    }

    #[test]
    fn revoked_agent_secret_cleared() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.set_agent_secret("a1", "secret-hash", 1).unwrap();
        assert!(s.verify_agent_secret("a1", "secret-hash").unwrap());
        s.revoke_agent("a1", 2).unwrap();
        assert!(!s.verify_agent_secret("a1", "secret-hash").unwrap());
        assert!(s.is_revoked("a1").unwrap());
    }

    /// L2：吊销的三张表写入在同一事务里，提交后三个效果同时可见。
    #[test]
    fn l2_revoke_agent_updates_all_three_tables_together() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.upsert_agent(&agent_record("a1", "online")).unwrap();
        s.set_agent_secret("a1", "secret-hash", 1).unwrap();

        s.revoke_agent("a1", 2).unwrap();

        assert!(s.is_revoked("a1").unwrap());
        assert_eq!(s.get_agent("a1").unwrap().unwrap().status, "revoked");
        assert!(!s.verify_agent_secret("a1", "secret-hash").unwrap());
    }

    /// M1：吊销后 `mark_seen` / `upsert_agent` 都不能把状态改回 online。
    #[test]
    fn m1_revoked_status_is_never_overwritten() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.upsert_agent(&agent_record("a1", "online")).unwrap();
        s.revoke_agent("a1", 10).unwrap();

        s.mark_seen("a1", 20).unwrap();
        assert_eq!(s.get_agent("a1").unwrap().unwrap().status, "revoked");
        assert_eq!(s.get_agent("a1").unwrap().unwrap().last_seen_at, 20);

        // 已吊销的 agent 即使带着 online 记录重新 upsert，也保持 revoked。
        s.upsert_agent(&agent_record("a1", "online")).unwrap();
        assert_eq!(s.get_agent("a1").unwrap().unwrap().status, "revoked");
        assert!(s.is_revoked("a1").unwrap());

        // 未吊销的 agent 正常更新为 online。
        s.upsert_agent(&agent_record("a2", "offline")).unwrap();
        s.mark_seen("a2", 30).unwrap();
        assert_eq!(s.get_agent("a2").unwrap().unwrap().status, "online");
    }

    /// L5：hub 启动时把残留的 online 清成 offline，revoked 保持不变。
    #[test]
    fn l5_reset_online_status_preserves_revoked() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.upsert_agent(&agent_record("online-1", "online")).unwrap();
        s.upsert_agent(&agent_record("offline-1", "offline"))
            .unwrap();
        s.upsert_agent(&agent_record("pending-1", "pending"))
            .unwrap();
        s.upsert_agent(&agent_record("revoked-1", "online"))
            .unwrap();
        s.revoke_agent("revoked-1", 5).unwrap();

        assert_eq!(s.reset_online_status().unwrap(), 1);
        assert_eq!(s.get_agent("online-1").unwrap().unwrap().status, "offline");
        assert_eq!(s.get_agent("offline-1").unwrap().unwrap().status, "offline");
        assert_eq!(s.get_agent("pending-1").unwrap().unwrap().status, "pending");
        assert_eq!(s.get_agent("revoked-1").unwrap().unwrap().status, "revoked");
        // 再执行一次没有 online 可清。
        assert_eq!(s.reset_online_status().unwrap(), 0);
    }

    #[test]
    fn query_returns_rows_in_order() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.insert_batch(&batch(1)).unwrap();
        let rows = s
            .query_series(&SeriesQuery {
                agent_id: "a1".into(),
                metrics: vec!["cpu.usage".into()],
                from: 0,
                to: i64::MAX,
                limit: 10,
            })
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, 12.5);
    }

    /// 直接写 samples 表，绕开批次判重（聚合 / 最新点测试只关心数据本身）。
    fn insert_samples(s: &SqliteStorage, agent_id: &str, rows: &[(&str, &str, i64, f64)]) {
        let conn = s.lock_write();
        let mut stmt = conn
            .prepare("INSERT INTO samples (agent_id, metric, labels, ts, value) VALUES (?1, ?2, ?3, ?4, ?5)")
            .unwrap();
        for (metric, labels, ts, value) in rows {
            stmt.execute(params![agent_id, metric, labels, ts, value])
                .unwrap();
        }
    }

    /// v4：`agent_settings` 按 agent 覆盖写入，列表按 agent_id 稳定排序。
    #[test]
    fn v4_agent_settings_roundtrip() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(s.get_sample_interval("a1").unwrap(), None);
        assert!(s.list_sample_intervals().unwrap().is_empty());

        s.set_sample_interval("a1", 10_000, 100).unwrap();
        s.set_sample_interval("a2", 5_000, 101).unwrap();
        s.set_sample_interval("a1", 30_000, 102).unwrap();

        assert_eq!(s.get_sample_interval("a1").unwrap(), Some(30_000));
        assert_eq!(s.get_sample_interval("a2").unwrap(), Some(5_000));
        assert_eq!(s.get_sample_interval("missing").unwrap(), None);
        assert_eq!(
            s.list_sample_intervals().unwrap(),
            vec![("a1".to_string(), 30_000), ("a2".to_string(), 5_000)]
        );

        let updated_at: i64 = s
            .lock_read()
            .query_row(
                "SELECT updated_at FROM agent_settings WHERE agent_id = 'a1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(updated_at, 102, "覆盖写入必须刷新 updated_at");
    }

    /// v3 → 当前版本：只建新表、升级 user_version，旧数据原样保留；重复打开幂等。
    #[test]
    fn v4_migration_from_v3_is_idempotent_and_preserves_data() {
        let dir = std::env::temp_dir().join(format!("rb-sqlite-v3-v4-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("rustboard.db");
        {
            // 模拟 v3 库：真实旧表结构 + 一行样本，user_version = 3。
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE samples (
                     agent_id TEXT NOT NULL,
                     metric   TEXT NOT NULL,
                     labels   TEXT NOT NULL DEFAULT '{}',
                     ts       INTEGER NOT NULL,
                     value    REAL NOT NULL
                 );
                 CREATE TABLE ingest_state (
                     agent_id   TEXT NOT NULL,
                     epoch      INTEGER NOT NULL,
                     last_seq   INTEGER NOT NULL DEFAULT 0,
                     updated_at INTEGER NOT NULL DEFAULT 0,
                     PRIMARY KEY (agent_id, epoch)
                 );
                 INSERT INTO samples (agent_id, metric, labels, ts, value)
                     VALUES ('a1', 'cpu.usage', '{}', 1700000000000, 12.5);
                 PRAGMA user_version = 3;",
            )
            .unwrap();
        }

        for _ in 0..2 {
            let s = SqliteStorage::open(&db_path).unwrap();
            let version: i64 = s
                .lock_read()
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION);
            let settings_table: i64 = s
                .lock_read()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'agent_settings')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(settings_table, 1, "v4 必须创建 agent_settings");
            assert_eq!(s.sample_count("a1").unwrap(), 1, "旧样本不得被重写或删除");

            let rows = s
                .query_series(&SeriesQuery {
                    agent_id: "a1".into(),
                    metrics: Vec::new(),
                    from: 0,
                    to: i64::MAX,
                    limit: 10,
                })
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].value, 12.5);
            assert_eq!(rows[0].ts, 1_700_000_000_000);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 同桶多点取平均、ts 返回桶起点、空桶不补点；多指标分别聚合。
    #[test]
    fn v4_bucketed_query_averages_and_skips_empty_buckets() {
        let s = SqliteStorage::open_in_memory().unwrap();
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", 1_000, 10.0),
                ("cpu.usage", "{}", 1_900, 20.0),
                ("cpu.usage", "{}", 2_100, 30.0),
                ("cpu.usage", "{}", 4_000, 40.0),
                ("mem.used", "{}", 1_500, 100.0),
            ],
        );

        let query = SeriesQuery {
            agent_id: "a1".into(),
            metrics: Vec::new(),
            from: 0,
            to: 10_000,
            limit: 100,
        };
        let rows = s.query_series_bucketed(&query, 2_000).unwrap();
        let summary: Vec<(&str, i64, f64)> = rows
            .iter()
            .map(|r| (r.metric.as_str(), r.ts, r.value))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("cpu.usage", 0, 15.0),
                ("cpu.usage", 2_000, 30.0),
                ("cpu.usage", 4_000, 40.0),
                ("mem.used", 0, 100.0),
            ],
            "同桶平均、桶起点、空桶（6s/8s）不补点"
        );

        // 指标过滤仍走参数绑定，且不影响聚合结果。
        let filtered = s
            .query_series_bucketed(
                &SeriesQuery {
                    metrics: vec!["cpu.usage".into()],
                    ..query.clone()
                },
                2_000,
            )
            .unwrap();
        assert_eq!(filtered.len(), 3);
        assert!(filtered.iter().all(|r| r.metric == "cpu.usage"));

        // 非法桶宽直接拒绝，避免除法/乘法产生无意义结果。
        assert!(s.query_series_bucketed(&query, 0).is_err());
        assert!(s.query_series_bucketed(&query, -1).is_err());
    }

    /// 多桶同时存在时 `LIMIT` 作用在聚合之后（上层靠多取一条判定超限）。
    #[test]
    fn v4_bucketed_query_honours_limit_after_grouping() {
        let s = SqliteStorage::open_in_memory().unwrap();
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", 1_000, 1.0),
                ("cpu.usage", "{}", 1_500, 3.0),
                ("cpu.usage", "{}", 2_000, 2.0),
            ],
        );
        let rows = s
            .query_series_bucketed(
                &SeriesQuery {
                    agent_id: "a1".into(),
                    metrics: Vec::new(),
                    from: 0,
                    to: 10_000,
                    limit: 1,
                },
                2_000,
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, 2.0, "桶内平均后再截断");
    }

    /// 最新点：按 (agent_id, metric, labels) 去重取最大 ts；指标 / agent 过滤生效。
    #[test]
    fn v4_latest_samples_dedupes_by_series_and_keeps_newest() {
        let s = SqliteStorage::open_in_memory().unwrap();
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", 1_000, 1.0),
                ("cpu.usage", "{}", 3_000, 3.0),
                ("mem.used", "{}", 2_000, 20.0),
                ("cpu.usage", "{\"core\":\"0\"}", 2_500, 25.0),
            ],
        );
        insert_samples(&s, "a2", &[("cpu.usage", "{}", 4_000, 40.0)]);

        let all = s.latest_samples(0, &[], None).unwrap();
        assert_eq!(all.len(), 4, "同序列只保留最新一点，不同 label 是不同序列");
        let a1_cpu = all
            .iter()
            .find(|r| r.agent_id == "a1" && r.metric == "cpu.usage" && r.labels.is_empty())
            .expect("a1 的 cpu.usage 必须存在");
        assert_eq!(a1_cpu.ts, 3_000);
        assert_eq!(a1_cpu.value, 3.0);
        assert!(
            all.windows(2)
                .all(|w| (&w[0].agent_id, &w[0].metric) <= (&w[1].agent_id, &w[1].metric)),
            "返回顺序必须稳定"
        );

        let cpu_only = s
            .latest_samples(0, &["cpu.usage".to_string()], None)
            .unwrap();
        assert_eq!(cpu_only.len(), 3);

        let a1_only = s.latest_samples(0, &[], Some("a1")).unwrap();
        assert_eq!(a1_only.len(), 3);
        assert!(a1_only.iter().all(|r| r.agent_id == "a1"));

        let recent = s.latest_samples(2_600, &[], None).unwrap();
        assert_eq!(
            recent.len(),
            2,
            "since 之后只剩 a1 cpu(3000) 与 a2 cpu(4000)"
        );
    }

    /// M2-6：`latest_samples` 的 SQL 行数硬上限。
    ///
    /// 达到上限必须返回错误（不能静默截断后把不完整快照当成最新点），
    /// 未达到时正常返回；同时确认常量确实限制在 10 万行。
    #[test]
    fn m2_latest_samples_hard_row_limit_is_enforced() {
        assert_eq!(LATEST_SAMPLES_SQL_LIMIT, 100_000);

        let s = SqliteStorage::open_in_memory().unwrap();
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", 1_000, 1.0),
                ("mem.used", "{}", 2_000, 2.0),
            ],
        );

        let err = s.latest_samples_limited(0, &[], None, 1).unwrap_err();
        let typed = err
            .downcast_ref::<QueryTooLarge>()
            .expect("达到上限必须是可识别的 QueryTooLarge，供 HTTP 层映射为 413");
        assert_eq!(typed.limit, 1);
        assert!(err.to_string().contains("1 行上限"), "错误信息: {err}");
        // 恰好等于上限也算「达到」，因为无法区分后面还有没有更多行。
        assert!(s.latest_samples_limited(0, &[], None, 2).is_err());
        // 未达到上限时正常去重返回。
        let rows = s.latest_samples_limited(0, &[], None, 3).unwrap();
        assert_eq!(rows.len(), 2);
    }

    fn temp_db(tag: &str) -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rb-sqlite-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("rustboard.db")
    }

    /// v7 的 10 张新表（与方案 §4 一一对应）。
    const V7_TABLES: [&str; 10] = [
        "samples_1m",
        "samples_1h",
        "maintenance_state",
        "alert_rules",
        "alert_states",
        "alert_events",
        "alert_silences",
        "notification_channels",
        "archive_objects",
        "archive_state",
    ];

    /// v7 的 9 个显式索引。
    const V7_INDEXES: [&str; 9] = [
        "idx_samples_1m_lookup",
        "idx_samples_1m_ts",
        "idx_samples_1h_lookup",
        "idx_samples_1h_ts",
        "idx_alert_events_ts",
        "idx_alert_events_rule_ts",
        "idx_alert_events_agent_ts",
        "idx_archive_objects_range",
        "idx_archive_objects_status",
    ];

    /// 查询 sqlite_master 中指定类型（table / index）的对象是否存在。
    fn sqlite_object_exists(s: &SqliteStorage, kind: &str, name: &str) -> bool {
        let exists: i64 = s
            .lock_read()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2)",
                params![kind, name],
                |r| r.get(0),
            )
            .unwrap();
        exists == 1
    }

    /// sqlite_master 中表 + 索引的对象总数，用于断言重复打开不重复建表。
    fn sqlite_object_count(s: &SqliteStorage) -> i64 {
        s.lock_read()
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('table', 'index')",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// 断言 WAL 模式下两个 sidecar 都存在且为 0600。
    #[cfg(unix)]
    fn assert_sidecars_private(db: &Path) {
        for suffix in ["-wal", "-shm"] {
            let sidecar = db_sidecar_path(db, suffix);
            assert!(
                sidecar.exists(),
                "WAL 模式下 {suffix} 应该已经存在（open 已执行建表写入）"
            );
            assert_eq!(mode_of(&sidecar), 0o600, "{suffix} 必须是 0600");
        }
    }

    /// KI-21：新建数据库的父目录 0700，主库/WAL/SHM 0600，且可正常读写。
    #[cfg(unix)]
    #[test]
    fn ki21_new_db_gets_private_dir_and_files() {
        let path = temp_db("perms-new");
        let parent = path.parent().unwrap().to_path_buf();
        // temp_db 为其他用例预建了目录；这里删掉，覆盖“父目录尚不存在”的新建路径。
        std::fs::remove_dir_all(&parent).unwrap();

        let storage = SqliteStorage::open(&path).unwrap();
        assert_eq!(mode_of(&parent), 0o700, "新建数据目录必须是 0700");
        assert_eq!(mode_of(&path), 0o600, "数据库主文件必须是 0600");
        assert_sidecars_private(&path);
        assert_eq!(
            storage.insert_batch(&batch(1)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(storage.sample_count("a1").unwrap(), 2);
        drop(storage);
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// KI-21 安全边界：默认 `open` 只拿到 DB 路径，不能收紧已存在的共享父目录。
    ///
    /// `/tmp`、`/var/tmp`、`/` 都可能是 DB 的父目录，无条件 chmod 会把系统目录
    /// 改坏；默认路径只保证新建目录 0700，旧目录由调用方显式声明后收紧。
    #[cfg(unix)]
    #[test]
    fn ki21_default_open_does_not_tighten_existing_parent() {
        let path = temp_db("perms-shared");
        let parent = path.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let storage = SqliteStorage::open(&path).unwrap();
        assert_eq!(
            mode_of(&parent),
            0o755,
            "默认 open 不得 chmod 已存在的共享父目录（如 /tmp）"
        );
        assert_eq!(mode_of(&path), 0o600, "数据库文件本身仍必须收紧到 0600");
        assert_sidecars_private(&path);
        assert_eq!(storage.sample_count("a1").unwrap(), 0);
        drop(storage);
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// KI-21：显式声明私有数据目录后，已存在的 0755 目录与 0644 主库被收紧，
    /// 且读写正常；再次打开幂等。
    #[cfg(unix)]
    #[test]
    fn ki21_private_data_dir_tightens_existing_permissions() {
        let path = temp_db("perms-tighten");
        let parent = path.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let storage = SqliteStorage::open_with_private_data_dir(&path, 2, &parent).unwrap();
        assert_eq!(mode_of(&parent), 0o700, "私有数据目录必须收紧到 0700");
        assert_eq!(mode_of(&path), 0o600, "预置 0644 主库必须收紧到 0600");
        assert_sidecars_private(&path);
        assert_eq!(
            storage.insert_batch(&batch(1)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(storage.sample_count("a1").unwrap(), 2);
        drop(storage);

        // 重复打开幂等：权限已合规时不再报错，数据仍在。
        let storage = SqliteStorage::open_with_private_data_dir(&path, 2, &parent).unwrap();
        assert_eq!(mode_of(&parent), 0o700);
        assert_eq!(mode_of(&path), 0o600);
        assert_sidecars_private(&path);
        assert_eq!(storage.sample_count("a1").unwrap(), 2);
        drop(storage);
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// KI-21：私有目录参数必须就是数据库父目录，防止误收紧无关目录。
    #[cfg(unix)]
    #[test]
    fn ki21_private_data_dir_must_match_db_parent() {
        let path = temp_db("perms-mismatch");
        let root = path.parent().unwrap().to_path_buf();
        let other = root.join("other");
        std::fs::create_dir(&other).unwrap();

        let err = SqliteStorage::open_with_private_data_dir(&path, 1, &other)
            .err()
            .expect("目录与 DB 父目录不一致必须拒绝");
        assert!(format!("{err:#}").contains("不是数据库"), "err={err:#}");
        assert!(!path.exists(), "拒绝时不能创建数据库文件");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// KI-21：数据库路径本身是符号链接时，必须在打开/收紧权限之前拒绝。
    #[cfg(unix)]
    #[test]
    fn ki21_rejects_symlink_db_path_before_chmod() {
        let path = temp_db("perms-symlink");
        let parent = path.parent().unwrap().to_path_buf();
        let victim = parent.join("victim.db");
        std::fs::write(&victim, b"").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&victim, &path).unwrap();

        let err = SqliteStorage::open(&path)
            .err()
            .expect("数据库路径是符号链接必须拒绝");
        assert!(format!("{err:#}").contains("符号链接"), "err={err:#}");
        assert_eq!(
            mode_of(&victim),
            0o644,
            "拒绝必须发生在打开之前，链接目标不能被 chmod"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// KI-21：in-memory 路径不触碰文件系统，权限收紧逻辑不能影响它。
    #[test]
    fn ki21_in_memory_storage_still_works() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(
            s.insert_batch(&batch(1)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        assert_eq!(s.sample_count("a1").unwrap(), 2);
    }

    /// KI-02：读连接池大小可配置并在 1–16 内夹取；读连接必须是 `query_only=ON`。
    #[test]
    fn v021_read_pool_size_is_clamped_and_query_only() {
        let path = temp_db("pool-size");

        let s = SqliteStorage::open_with_readers(&path, 0).unwrap();
        assert_eq!(
            s.read_pool_len(),
            MIN_READ_POOL_SIZE,
            "0 条读连接必须夹到 1"
        );
        {
            let conn = s.lock_read();
            let query_only: i64 = conn
                .query_row("PRAGMA query_only", [], |r| r.get(0))
                .unwrap();
            assert_eq!(query_only, 1, "读连接必须开启 query_only");
        }
        drop(s);

        let s = SqliteStorage::open_with_readers(&path, 99).unwrap();
        assert_eq!(
            s.read_pool_len(),
            MAX_READ_POOL_SIZE,
            "超过 16 条的配置必须夹到上限"
        );
        drop(s);

        let s = SqliteStorage::open_with_readers(&path, 2).unwrap();
        assert_eq!(s.read_pool_len(), 2);
        drop(s);

        // `open` 使用默认池大小 4。
        let s = SqliteStorage::open(&path).unwrap();
        assert_eq!(s.read_pool_len(), DEFAULT_READ_POOL_SIZE);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// KI-02：只读连接必须能看到写连接写入的数据（文件库 + 内存库两条路径）。
    #[test]
    fn v021_read_pool_sees_writes_in_file_and_memory_databases() {
        let path = temp_db("visibility");
        let file = SqliteStorage::open_with_readers(&path, 2).unwrap();
        assert_eq!(
            file.insert_batch(&batch(1)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        // 连续读多次会轮询到不同读连接，每条都必须看到同一份数据。
        for _ in 0..4 {
            assert_eq!(file.sample_count("a1").unwrap(), 2);
            assert_eq!(
                file.query_series(&SeriesQuery {
                    agent_id: "a1".into(),
                    metrics: vec!["cpu.usage".into()],
                    from: 0,
                    to: i64::MAX,
                    limit: 10,
                })
                .unwrap()
                .len(),
                1
            );
        }
        drop(file);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());

        // 内存库必须用共享缓存 URI，否则读连接会各自看到一个空库。
        let memory = SqliteStorage::open_in_memory().unwrap();
        assert!(memory.read_pool_len() > 0);
        memory.insert_batch(&batch(1)).unwrap();
        for _ in 0..4 {
            assert_eq!(
                memory.sample_count("a1").unwrap(),
                2,
                "内存库读连接必须与写连接共享同一份数据"
            );
        }
    }

    /// KI-02 关键回归：一条读连接持有长事务时，写入与心跳刷新必须立即完成，
    /// 不能因为读路径占着全局锁而排队。
    #[test]
    fn v021_long_read_transaction_does_not_block_writes() {
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        let path = temp_db("read-does-not-block-write");
        let storage = std::sync::Arc::new(SqliteStorage::open_with_readers(&path, 1).unwrap());
        storage.insert_batch(&batch(1)).unwrap();

        let (ready_tx, ready_rx) = mpsc::channel();
        let reader = {
            let storage = storage.clone();
            std::thread::spawn(move || {
                let conn = storage.lock_read();
                conn.execute_batch("BEGIN").unwrap();
                // 真实执行一次查询后再挂起事务，模拟面板的大范围分桶查询。
                let count: i64 = conn
                    .query_row("SELECT COUNT(*) FROM samples", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, 2);
                ready_tx.send(()).unwrap();
                // 长查询仍在进行：读者继续持锁 300ms。
                std::thread::sleep(Duration::from_millis(300));
                conn.execute_batch("COMMIT").unwrap();
            })
        };
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("读线程必须在 2s 内取得读连接并开始查询");

        let started = Instant::now();
        assert_eq!(
            storage.insert_batch(&batch(2)).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        );
        storage.mark_seen("a1", 123).unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(200),
            "长读事务期间写入被阻塞了 {elapsed:?}（必须 <200ms）"
        );
        reader.join().unwrap();
        assert_eq!(storage.sample_count("a1").unwrap(), 4);

        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// KI-02：至少两条读连接能同时被占用（真正并发，而不是一把全局锁）。
    #[test]
    fn v021_read_pool_serves_two_concurrent_readers() {
        use std::sync::mpsc;
        use std::time::Duration;

        let path = temp_db("read-concurrency");
        let storage = std::sync::Arc::new(SqliteStorage::open_with_readers(&path, 2).unwrap());
        storage.insert_batch(&batch(1)).unwrap();

        let (first_ready_tx, first_ready_rx) = mpsc::channel();
        let first = {
            let storage = storage.clone();
            std::thread::spawn(move || {
                let conn = storage.lock_read();
                let value: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
                assert_eq!(value, 1);
                first_ready_tx.send(()).unwrap();
                // 持锁 500ms：单连接池时第二个线程要等到这里结束。
                std::thread::sleep(Duration::from_millis(500));
            })
        };
        first_ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("第一个读线程必须取得连接");

        let (second_ready_tx, second_ready_rx) = mpsc::channel();
        let second = {
            let storage = storage.clone();
            std::thread::spawn(move || {
                let conn = storage.lock_read();
                let value: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
                assert_eq!(value, 1);
                second_ready_tx.send(()).unwrap();
            })
        };
        second_ready_rx
            .recv_timeout(Duration::from_millis(200))
            .expect("第二个读连接必须能并发取得（读池不能退化成一把全局锁）");

        first.join().unwrap();
        second.join().unwrap();
        drop(storage);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// KI-02 降级路径：只读连接全部打不开时必须告警并回退到写连接，不能拒绝启动。
    #[test]
    fn v021_read_pool_falls_back_to_writer_when_open_fails() {
        let path = temp_db("read-fallback");
        {
            let mut slot = FAIL_READER_OPEN_FOR
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            *slot = Some(path.clone());
        }

        let s = SqliteStorage::open_with_readers(&path, 4).unwrap();
        assert_eq!(s.read_pool_len(), 0, "测试注入下读池应为空");
        // 读路径仍然可用（走写连接），且能看到写入的数据。
        s.insert_batch(&batch(1)).unwrap();
        assert_eq!(s.sample_count("a1").unwrap(), 2);
        assert_eq!(s.list_agents().unwrap().len(), 0);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    // ------------------------------------------------------------------
    // M3：schema v5 / agent_control / audit_log
    // ------------------------------------------------------------------

    fn audit_entry(agent_id: &str, capability: &str, action: &str, ts: i64) -> NewAuditEntry {
        NewAuditEntry {
            ts,
            actor: "admin".into(),
            agent_id: agent_id.into(),
            capability: capability.into(),
            action: action.into(),
            target: "nginx.service".into(),
            params: "{\"target\":\"nginx.service\"}".into(),
            result: "ok".into(),
            error_code: String::new(),
            error_message: String::new(),
            duration_ms: 12,
        }
    }

    /// v4 库（已有 agent_settings 行）启动时幂等升级到 v5：只新增表，旧数据保留。
    #[test]
    fn m3_v4_schema_upgrades_to_v5_without_touching_old_tables() {
        let dir = std::env::temp_dir().join(format!("rb-sqlite-v5-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("rustboard.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE agent_settings (
                     agent_id           TEXT PRIMARY KEY,
                     sample_interval_ms INTEGER NOT NULL,
                     updated_at         INTEGER NOT NULL
                 );
                 INSERT INTO agent_settings VALUES ('a1', 2500, 42);
                 PRAGMA user_version = 4;",
            )
            .unwrap();
        }

        for round in 0..2 {
            let s = SqliteStorage::open(&db_path)
                .unwrap_or_else(|err| panic!("第 {round} 次打开 v4 库失败（迁移必须幂等）: {err}"));
            let version: i64 = s
                .lock_read()
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION);
            assert_eq!(s.get_sample_interval("a1").unwrap(), Some(2500));
            for table in ["agent_control", "audit_log"] {
                let exists: i64 = s
                    .lock_read()
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                        params![table],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(exists, 1, "v5 必须建好 {table} 表");
            }
            assert_eq!(s.list_audit(10, None, None, None).unwrap(), Vec::new());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn m3_agent_control_upsert_replaces_capabilities() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert!(s.get_agent_control("a1").unwrap().is_none());

        s.upsert_agent_control("a1", &["systemd".to_string(), "logs".to_string()], 111)
            .unwrap();
        let record = s.get_agent_control("a1").unwrap().expect("应能读回能力");
        assert_eq!(record.capabilities, vec!["systemd", "logs"]);
        assert_eq!(record.updated_at, 111);

        // 再次 Hello 只覆盖一行，不产生重复记录。
        s.upsert_agent_control("a1", &["process".to_string()], 222)
            .unwrap();
        let record = s.get_agent_control("a1").unwrap().unwrap();
        assert_eq!(record.capabilities, vec!["process"]);
        assert_eq!(record.updated_at, 222);
        let rows: i64 = s
            .lock_read()
            .query_row("SELECT COUNT(*) FROM agent_control", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1);
    }

    #[test]
    fn m3_audit_pagination_and_filters() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let first = s
            .insert_audit(&audit_entry("a1", "systemd", "list", 100))
            .unwrap();
        let second = s
            .insert_audit(&audit_entry("a1", "systemd", "restart", 200))
            .unwrap();
        let third = s
            .insert_audit(&audit_entry("b2", "docker", "list", 300))
            .unwrap();
        let fourth = s
            .insert_audit(&audit_entry("b2", "docker", "restart", 400))
            .unwrap();
        assert!(first < second && second < third && third < fourth);

        // 按 id 倒序 + limit。
        let page = s.list_audit(2, None, None, None).unwrap();
        assert_eq!(
            page.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![fourth, third]
        );

        // before_id 为排他游标。
        let page = s.list_audit(2, Some(third), None, None).unwrap();
        assert_eq!(
            page.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![second, first]
        );
        assert!(s
            .list_audit(10, Some(first), None, None)
            .unwrap()
            .is_empty());

        // agent / capability 过滤可以叠加。
        let only_a1 = s.list_audit(10, None, Some("a1"), None).unwrap();
        assert_eq!(
            only_a1.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![second, first]
        );
        let only_docker = s.list_audit(10, None, None, Some("docker")).unwrap();
        assert_eq!(
            only_docker.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![fourth, third]
        );
        let combined = s
            .list_audit(10, Some(fourth), Some("a1"), Some("systemd"))
            .unwrap();
        assert_eq!(
            combined.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![second, first]
        );
        assert!(s.list_audit(0, None, None, None).unwrap().is_empty());

        // 字段完整落库。
        let entry = &s.list_audit(1, None, None, None).unwrap()[0];
        assert_eq!(entry.actor, "admin");
        assert_eq!(entry.target, "nginx.service");
        assert_eq!(entry.params, "{\"target\":\"nginx.service\"}");
        assert_eq!(entry.duration_ms, 12);
    }

    #[test]
    fn m3_audit_prune_removes_only_expired_rows() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let now = rustboard_common::util::now_ms();
        let old = now - AUDIT_RETENTION_MS - 1;
        let old_id = s
            .insert_audit(&audit_entry("a1", "systemd", "list", old))
            .unwrap();
        let fresh_id = s
            .insert_audit(&audit_entry("a1", "systemd", "list", now))
            .unwrap();

        let cutoff = now - AUDIT_RETENTION_MS;
        assert_eq!(s.prune_audit(cutoff).unwrap(), 1);
        let left = s.list_audit(10, None, None, None).unwrap();
        assert_eq!(
            left.iter().map(|e| e.id).collect::<Vec<_>>(),
            vec![fresh_id]
        );
        assert_ne!(old_id, fresh_id);
        // 再清理一次不会重复计数。
        assert_eq!(s.prune_audit(cutoff).unwrap(), 0);
    }

    /// 每 1000 条成功写入触发一次保留期清理：第 1000 条写入后过期记录被删。
    #[test]
    fn m3_audit_auto_prunes_every_thousand_writes() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let now = rustboard_common::util::now_ms();
        let stale_ts = now - AUDIT_RETENTION_MS - 1;
        s.insert_audit(&audit_entry("a1", "systemd", "list", stale_ts))
            .unwrap();

        // 再写 999 条：累计 1000 条，触发清理。
        for _ in 0..AUDIT_CLEANUP_EVERY {
            s.insert_audit(&audit_entry("a1", "systemd", "list", now))
                .unwrap();
        }
        let stale_left = s
            .list_audit(10, None, Some("a1"), None)
            .unwrap()
            .into_iter()
            .filter(|entry| entry.ts == stale_ts)
            .count();
        assert_eq!(stale_left, 0, "第 1000 条写入后应清理 180 天前的审计");
        assert_eq!(
            s.list_audit(10, None, None, None).unwrap().len(),
            10,
            "新写入的审计必须保留"
        );
    }

    // ------------------------------------------------------------------
    // v6：管理 API scoped token
    // ------------------------------------------------------------------

    /// v5 库（已有审计与控制数据）升级到 v6：只新增 api_tokens，旧数据保留，重复打开幂等。
    #[test]
    fn v6_v5_schema_upgrades_and_preserves_old_data() {
        let path = temp_db("v6-migration");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE agent_settings (
                     agent_id           TEXT PRIMARY KEY,
                     sample_interval_ms INTEGER NOT NULL,
                     updated_at         INTEGER NOT NULL
                 );
                 INSERT INTO agent_settings VALUES ('a1', 2500, 42);
                 CREATE TABLE audit_log (
                     id            INTEGER PRIMARY KEY AUTOINCREMENT,
                     ts            INTEGER NOT NULL,
                     actor         TEXT NOT NULL,
                     agent_id      TEXT NOT NULL,
                     capability    TEXT NOT NULL,
                     action        TEXT NOT NULL,
                     target        TEXT NOT NULL DEFAULT '',
                     params        TEXT NOT NULL DEFAULT '{}',
                     result        TEXT NOT NULL,
                     error_code    TEXT NOT NULL DEFAULT '',
                     error_message TEXT NOT NULL DEFAULT '',
                     duration_ms   INTEGER NOT NULL
                 );
                 INSERT INTO audit_log
                     (ts, actor, agent_id, capability, action, target, params, result,
                      error_code, error_message, duration_ms)
                 VALUES (111, 'admin', 'a1', 'systemd', 'list', '', '{}', 'ok', '', '', 5);
                 PRAGMA user_version = 5;",
            )
            .unwrap();
        }

        for round in 0..2 {
            let s = SqliteStorage::open(&path).unwrap_or_else(|err| {
                panic!("第 {round} 次打开 v5 库失败（v5→v6 迁移必须幂等）: {err}")
            });
            let version: i64 = s
                .lock_read()
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION, "必须升级到 v6");
            assert_eq!(s.get_sample_interval("a1").unwrap(), Some(2500));
            let audits = s.list_audit(10, None, None, None).unwrap();
            assert_eq!(audits.len(), 1, "旧审计必须保留");
            assert_eq!(audits[0].actor, "admin");
            assert!(s.list_api_tokens().unwrap().is_empty());

            let table_exists: i64 = s
                .lock_read()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'api_tokens')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(table_exists, 1, "v6 必须建好 api_tokens 表");
            let index_exists: i64 = s
                .lock_read()
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'idx_api_tokens_hash')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(index_exists, 1, "v6 必须建好 idx_api_tokens_hash");
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// 创建 / 列表排序 / 重复 name / 非法 scope；数据库只存哈希。
    #[test]
    fn v6_create_list_tokens_never_store_plaintext() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let plain_a = "plain-token-a";
        let plain_b = "plain-token-b";
        let hash_a = rustboard_common::tls::sha256_hex(plain_a);
        let hash_b = rustboard_common::tls::sha256_hex(plain_b);

        let record = s
            .create_api_token("web-b", &hash_a, "read", 1_700_000_000_000)
            .unwrap();
        assert_eq!(record.name, "web-b");
        assert_eq!(record.scope, "read");
        assert_eq!(record.created_at, 1_700_000_000_000);
        assert_eq!(record.last_used_at, None);
        assert_eq!(record.revoked_at, None);
        assert!(record.id > 0);

        s.create_api_token("app-a", &hash_b, "admin", 1_700_000_000_001)
            .unwrap();
        let listed = s.list_api_tokens().unwrap();
        assert_eq!(
            listed.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
            vec!["app-a", "web-b"],
            "列表必须按 name 升序"
        );

        // 重复 name 是可读错误，不能是 SQL 约束原文。
        let err = s
            .create_api_token(
                "web-b",
                &rustboard_common::tls::sha256_hex("other"),
                "read",
                1,
            )
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("token 名称已存在"),
            "err={err:#}"
        );

        // 非法 scope 在落库前被拒绝。
        let err = s
            .create_api_token("bad-scope", &hash_a, "root", 1)
            .unwrap_err();
        assert!(format!("{err:#}").contains("scope"), "err={err:#}");

        // 数据库只有 SHA-256 hex，没有明文；对外记录里也没有哈希字段。
        let stored: String = s
            .lock_read()
            .query_row(
                "SELECT token_hash FROM api_tokens WHERE name = 'web-b'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stored, hash_a);
        assert!(!stored.contains(plain_a));
        let debug = format!("{listed:?}");
        assert!(!debug.contains(plain_a) && !debug.contains(plain_b));
        assert!(!debug.contains(&hash_a) && !debug.contains(&hash_b));
    }

    /// 鉴权：只返回未吊销行；首次写 last_used_at，60s 内节流，60s 后刷新。
    #[test]
    fn v6_authenticate_updates_last_used_and_rejects_revoked() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let hash = rustboard_common::tls::sha256_hex("active-token");
        s.create_api_token("panel", &hash, "write", 100).unwrap();

        assert!(s
            .authenticate_api_token("not-a-hash", 200)
            .unwrap()
            .is_none());
        let record = s
            .authenticate_api_token(&hash, 200)
            .unwrap()
            .expect("未吊销 token 必须认证通过");
        assert_eq!(record.name, "panel");
        assert_eq!(record.scope, "write");
        assert_eq!(
            record.last_used_at,
            Some(200),
            "首次鉴权必须写 last_used_at"
        );

        // 60s 内节流：数据库保持首次时间，但鉴权仍成功。
        let throttled = s.authenticate_api_token(&hash, 201).unwrap().unwrap();
        assert_eq!(throttled.last_used_at, Some(200), "节流窗口内不重复写");
        assert_eq!(s.list_api_tokens().unwrap()[0].last_used_at, Some(200));

        // 超过 60s 刷新。
        let refreshed = s
            .authenticate_api_token(&hash, 200 + API_TOKEN_LAST_USED_THROTTLE_MS)
            .unwrap()
            .unwrap();
        assert_eq!(
            refreshed.last_used_at,
            Some(200 + API_TOKEN_LAST_USED_THROTTLE_MS)
        );
        assert_eq!(
            s.list_api_tokens().unwrap()[0].last_used_at,
            Some(200 + API_TOKEN_LAST_USED_THROTTLE_MS)
        );

        s.revoke_api_token("panel", 300).unwrap();
        assert!(
            s.authenticate_api_token(&hash, 301).unwrap().is_none(),
            "已吊销 token 必须认证失败"
        );
        let listed = s.list_api_tokens().unwrap();
        assert_eq!(listed.len(), 1, "吊销不删行");
        assert_eq!(listed[0].revoked_at, Some(300));

        let err = s.revoke_api_token("panel", 400).unwrap_err();
        assert!(format!("{err:#}").contains("已吊销"), "err={err:#}");
        let err = s.revoke_api_token("missing", 400).unwrap_err();
        assert!(format!("{err:#}").contains("不存在"), "err={err:#}");
    }

    /// 轮换：旧哈希立即失效、新哈希可用、清 revoked_at、created_at 更新。
    #[test]
    fn v6_rotate_invalidates_old_hash_and_clears_revocation() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let old_hash = rustboard_common::tls::sha256_hex("old-token");
        let new_hash = rustboard_common::tls::sha256_hex("new-token");
        s.create_api_token("panel", &old_hash, "read", 100).unwrap();
        s.revoke_api_token("panel", 150).unwrap();

        let rotated = s.rotate_api_token("panel", &new_hash, 200).unwrap();
        assert_eq!(rotated.name, "panel");
        assert_eq!(rotated.scope, "read", "rotate 不改变 scope");
        assert_eq!(rotated.created_at, 200);
        assert_eq!(rotated.last_used_at, None);
        assert_eq!(rotated.revoked_at, None, "rotate 必须清 revoked_at");

        assert!(
            s.authenticate_api_token(&old_hash, 210).unwrap().is_none(),
            "旧哈希必须立即失效"
        );
        let active = s
            .authenticate_api_token(&new_hash, 210)
            .unwrap()
            .expect("新哈希必须可用");
        assert_eq!(active.name, "panel");

        let err = s.rotate_api_token("missing", &new_hash, 300).unwrap_err();
        assert!(format!("{err:#}").contains("不存在"), "err={err:#}");

        // 轮换后只有一行，不新建记录。
        assert_eq!(s.list_api_tokens().unwrap().len(), 1);
    }

    // ------------------------------------------------------------------
    // v7：M4 schema（降采样 / 告警 / 归档 / 维护水位）
    // ------------------------------------------------------------------

    /// fresh 库：方案 §4 的 10 张新表与 9 个索引全部存在，版本号为 7。
    #[test]
    fn v7_schema_creates_all_tables_and_indexes() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let version: i64 = s
            .lock_read()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        for table in V7_TABLES {
            assert!(
                sqlite_object_exists(&s, "table", table),
                "缺少 v7 表: {table}"
            );
        }
        for index in V7_INDEXES {
            assert!(
                sqlite_object_exists(&s, "index", index),
                "缺少 v7 索引: {index}"
            );
        }
    }

    /// v6 库升级到 v7：只建新表，旧 agents / samples / api_tokens 数据不变，
    /// 连续打开两次不报错、不重复建表，`user_version=7`。
    #[test]
    fn v7_v6_schema_upgrades_preserves_old_data_and_is_idempotent() {
        let path = temp_db("v7-migration");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE agents (
                     agent_id      TEXT PRIMARY KEY,
                     name          TEXT NOT NULL,
                     hostname      TEXT NOT NULL,
                     os            TEXT NOT NULL DEFAULT '',
                     arch          TEXT NOT NULL DEFAULT '',
                     version       TEXT NOT NULL DEFAULT '',
                     boot_id       TEXT NOT NULL DEFAULT '',
                     status        TEXT NOT NULL DEFAULT 'offline',
                     last_seen_at  INTEGER NOT NULL DEFAULT 0,
                     created_at    INTEGER NOT NULL DEFAULT 0
                 );
                 INSERT INTO agents VALUES
                     ('a1', '老 agent', 'old-host', 'linux', 'x86_64', '0.3.5', 'boot',
                      'online', 123, 100);
                 CREATE TABLE samples (
                     agent_id TEXT NOT NULL,
                     metric   TEXT NOT NULL,
                     labels   TEXT NOT NULL DEFAULT '{}',
                     ts       INTEGER NOT NULL,
                     value    REAL NOT NULL
                 );
                 INSERT INTO samples VALUES ('a1', 'cpu.usage', '{}', 1000, 12.5);
                 INSERT INTO samples VALUES ('a1', 'mem.used', '{}', 1000, 1024.0);
                 CREATE TABLE api_tokens (
                     id           INTEGER PRIMARY KEY AUTOINCREMENT,
                     name         TEXT NOT NULL UNIQUE,
                     token_hash   TEXT NOT NULL UNIQUE,
                     scope        TEXT NOT NULL CHECK (scope IN ('read','write','admin')),
                     created_at   INTEGER NOT NULL,
                     last_used_at INTEGER,
                     revoked_at   INTEGER
                 );
                 INSERT INTO api_tokens (name, token_hash, scope, created_at)
                     VALUES ('legacy', 'hash-legacy', 'read', 50);
                 PRAGMA user_version = 6;",
            )
            .unwrap();
        }

        let mut first_object_count = None;
        for round in 0..2 {
            let s = SqliteStorage::open(&path).unwrap_or_else(|err| {
                panic!("第 {round} 次打开 v6 库失败（v6→v7 迁移必须幂等）: {err}")
            });
            let version: i64 = s
                .lock_read()
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION, "必须升级到 v7");

            // 旧数据逐字段保留。
            let agent = s.get_agent("a1").unwrap().expect("旧 agent 必须保留");
            assert_eq!(agent.hostname, "old-host");
            assert_eq!(agent.version, "0.3.5");
            assert_eq!(agent.status, "online");
            assert_eq!(s.sample_count("a1").unwrap(), 2);
            let value: f64 = s
                .lock_read()
                .query_row(
                    "SELECT value FROM samples WHERE metric = 'cpu.usage'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(value, 12.5);
            let tokens = s.list_api_tokens().unwrap();
            assert_eq!(tokens.len(), 1);
            assert_eq!(tokens[0].name, "legacy");
            assert_eq!(tokens[0].scope, "read");

            // 新表全部建好。
            for table in V7_TABLES {
                assert!(
                    sqlite_object_exists(&s, "table", table),
                    "第 {round} 次打开缺少表 {table}"
                );
            }

            let count = sqlite_object_count(&s);
            match first_object_count {
                None => first_object_count = Some(count),
                Some(first) => assert_eq!(count, first, "重复打开不得重复建表/索引"),
            }
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// maintenance_state：缺失返回 None；set 覆盖刷新 value/updated_at；
    /// list 按 key 升序；含引号的键值走参数化 SQL。
    #[test]
    fn v7_maintenance_state_upsert_list_and_none() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(s.get_maintenance_state("last_archived_ts").unwrap(), None);

        s.set_maintenance_state("last_archived_ts", "100", 1_000)
            .unwrap();
        s.set_maintenance_state("last_downsample_ts", "50", 900)
            .unwrap();
        assert_eq!(
            s.get_maintenance_state("last_archived_ts").unwrap(),
            Some("100".to_string())
        );

        // 覆盖写：同一 key 不新增行，value 与 updated_at 刷新。
        s.set_maintenance_state("last_archived_ts", "200", 2_000)
            .unwrap();
        assert_eq!(
            s.list_maintenance_state().unwrap(),
            vec![
                MaintenanceStateEntry {
                    key: "last_archived_ts".into(),
                    value: "200".into(),
                    updated_at: 2_000,
                },
                MaintenanceStateEntry {
                    key: "last_downsample_ts".into(),
                    value: "50".into(),
                    updated_at: 900,
                },
            ],
            "必须按 key 升序且覆盖写不产生重复行"
        );

        // 参数化：引号 / SQL 片段按字面量存取，不会被当作 SQL 执行。
        let key = "k'quote";
        let value = "v'; DROP TABLE maintenance_state; --";
        s.set_maintenance_state(key, value, 3_000).unwrap();
        assert_eq!(
            s.get_maintenance_state(key).unwrap(),
            Some(value.to_string())
        );
        assert_eq!(s.list_maintenance_state().unwrap().len(), 3);
        assert!(sqlite_object_exists(&s, "table", "maintenance_state"));
    }

    // ---- M4-A2：降采样聚合 / 统计 / 分批删除 ----

    /// 一行聚合结果，便于整行断言（避免长元组）。
    #[derive(Debug, Clone, PartialEq)]
    struct AggRow {
        labels: String,
        bucket_ts: i64,
        min_value: f64,
        max_value: f64,
        avg_value: f64,
        last_value: f64,
        count: i64,
    }

    /// 读取某张聚合表并按 `(bucket_ts, labels)` 排序。
    fn agg_rows(s: &SqliteStorage, table: &str) -> Vec<AggRow> {
        assert!(matches!(table, "samples_1m" | "samples_1h"));
        let sql = format!(
            "SELECT labels, bucket_ts, min_value, max_value, avg_value, last_value, count
             FROM {table} ORDER BY bucket_ts, labels"
        );
        let conn = s.lock_read();
        let mut stmt = conn.prepare(&sql).unwrap();
        stmt.query_map([], |row| {
            Ok(AggRow {
                labels: row.get(0)?,
                bucket_ts: row.get(1)?,
                min_value: row.get(2)?,
                max_value: row.get(3)?,
                avg_value: row.get(4)?,
                last_value: row.get(5)?,
                count: row.get(6)?,
            })
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
    }

    fn find_agg<'a>(rows: &'a [AggRow], labels: &str) -> &'a AggRow {
        rows.iter()
            .find(|row| row.labels == labels)
            .unwrap_or_else(|| panic!("缺少 labels={labels} 的聚合行: {rows:?}"))
    }

    /// M4-A2：1m 的 min/max/avg/last/count 与手算一致；labels 不同不合并；
    /// 空桶不建行；区间外的数据不参与聚合。
    #[test]
    fn m4a_downsample_1m_matches_manual_aggregation() {
        // SQL 里的 60000 / 3600000 必须与公共常量一致。
        assert_eq!(BUCKET_1M_MS, 60_000);
        assert_eq!(BUCKET_1H_MS, 3_600_000);

        let s = SqliteStorage::open_in_memory().unwrap();
        let base = 1_700_000_040_000; // 刚好落在整分钟
        assert_eq!(base % BUCKET_1M_MS, 0);
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", base + 1_000, 1.0),
                ("cpu.usage", "{}", base + 20_000, 5.0),
                ("cpu.usage", "{}", base + 40_000, 3.0),
                ("cpu.usage", r#"{"disk":"sda"}"#, base + 5_000, 42.0),
                // 下一分钟的迟到数据：不在本次 [base, base+60000) 内。
                ("cpu.usage", "{}", base + 61_000, 9.0),
            ],
        );

        let res = s.downsample_1m_range(base, base + BUCKET_1M_MS).unwrap();
        assert_eq!(
            res,
            DownsampleRangeResult {
                buckets: 2,
                rows: 4
            },
            "同一标签 3 行 + 另一标签 1 行 → 2 个桶、4 行源数据"
        );

        let rows = agg_rows(&s, "samples_1m");
        assert_eq!(rows.len(), 2, "空桶 / 区间外数据都不得建行");
        let plain = find_agg(&rows, "{}");
        assert_eq!(plain.bucket_ts, base);
        assert_eq!(plain.min_value, 1.0);
        assert_eq!(plain.max_value, 5.0);
        assert!((plain.avg_value - 3.0).abs() < 1e-9);
        assert_eq!(plain.last_value, 3.0, "last 取最大 ts 的 3.0");
        assert_eq!(plain.count, 3);

        let disk = find_agg(&rows, r#"{"disk":"sda"}"#);
        assert_eq!(disk.bucket_ts, base);
        assert_eq!(disk.min_value, 42.0);
        assert_eq!(disk.max_value, 42.0);
        assert_eq!(disk.avg_value, 42.0);
        assert_eq!(disk.last_value, 42.0);
        assert_eq!(disk.count, 1);

        // 没有任何 raw 的空区间：零结果，不写行、不建空桶。
        let empty = s
            .downsample_1m_range(base + 120_000, base + 180_000)
            .unwrap();
        assert_eq!(empty, DownsampleRangeResult::default());
        assert_eq!(s.samples_1m_stats().unwrap().rows, 2);
    }

    /// M4-A2：重复聚合不增行、不改值；迟到数据（同 ts 更高 rowid）重算后
    /// last_value / max / count 都更新。
    #[test]
    fn m4a_downsample_1m_rerun_is_idempotent_and_recomputes_late_data() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let base = 1_700_000_040_000;
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", base + 1_000, 1.0),
                ("cpu.usage", "{}", base + 2_000, 2.0),
            ],
        );

        let first = s.downsample_1m_range(base, base + 60_000).unwrap();
        assert_eq!(
            first,
            DownsampleRangeResult {
                buckets: 1,
                rows: 2
            }
        );
        let before = agg_rows(&s, "samples_1m");
        assert_eq!(before.len(), 1);

        // 重复执行：upsert 覆盖，行数与值都不变。
        let again = s.downsample_1m_range(base, base + 60_000).unwrap();
        assert_eq!(again, first);
        assert_eq!(agg_rows(&s, "samples_1m"), before, "重复执行必须幂等");

        // 迟到重传：同 ts、更高 rowid → last_value 取 8.0。
        insert_samples(&s, "a1", &[("cpu.usage", "{}", base + 2_000, 8.0)]);
        let third = s.downsample_1m_range(base, base + 60_000).unwrap();
        assert_eq!(
            third,
            DownsampleRangeResult {
                buckets: 1,
                rows: 3
            }
        );
        let rows = agg_rows(&s, "samples_1m");
        assert_eq!(rows.len(), 1, "重算不得新增桶");
        let row = &rows[0];
        assert_eq!(row.count, 3);
        assert_eq!(row.max_value, 8.0);
        assert_eq!(row.last_value, 8.0, "同 ts 取最大 rowid");
        assert!(
            (row.avg_value - 11.0 / 3.0).abs() < 1e-9,
            "avg 必须重算: {}",
            row.avg_value
        );
    }

    /// M4-A2：1h 的 avg 必须按 count 加权，min/max/count/last 正确；
    /// 重复执行幂等；不足整点的范围不聚合。
    #[test]
    fn m4a_downsample_1h_weighted_average_idempotent() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let hour = 1_699_999_200_000; // 整点
        assert_eq!(hour % BUCKET_1H_MS, 0);
        insert_samples(
            &s,
            "a1",
            &[
                // 分钟 0：avg=5, count=2
                ("cpu.usage", "{}", hour + 1_000, 0.0),
                ("cpu.usage", "{}", hour + 2_000, 10.0),
                // 分钟 1：avg=20, count=1
                ("cpu.usage", "{}", hour + 61_000, 20.0),
                // 分钟 2：avg=1000, count=1
                ("cpu.usage", "{}", hour + 121_000, 1_000.0),
            ],
        );
        s.downsample_1m_range(hour, hour + 180_000).unwrap();
        assert_eq!(s.samples_1m_stats().unwrap().rows, 3);

        let res = s.downsample_1h_range(hour, hour + BUCKET_1H_MS).unwrap();
        assert_eq!(
            res,
            DownsampleRangeResult {
                buckets: 1,
                rows: 3
            }
        );
        let rows = agg_rows(&s, "samples_1h");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.bucket_ts, hour);
        assert_eq!(row.min_value, 0.0);
        assert_eq!(row.max_value, 1_000.0);
        assert_eq!(row.count, 4);
        assert_eq!(row.last_value, 1_000.0, "last 取最新 1m 桶的 last_value");
        // (5*2 + 20*1 + 1000*1) / 4 = 257.5；简单平均会得到 341.67，必须区分。
        assert!(
            (row.avg_value - 257.5).abs() < 1e-9,
            "1h avg 必须按 count 加权: {}",
            row.avg_value
        );

        // 幂等：再跑一次不增行、不改值。
        let before = agg_rows(&s, "samples_1h");
        let again = s.downsample_1h_range(hour, hour + BUCKET_1H_MS).unwrap();
        assert_eq!(again, res);
        assert_eq!(agg_rows(&s, "samples_1h"), before);

        // 同一个整点内、未跨到下一个整点的范围：向下取整后为空，绝不聚合未满整点的数据。
        assert_eq!(
            s.downsample_1h_range(hour + 1_800_000, hour + 3_000_000)
                .unwrap(),
            DownsampleRangeResult::default()
        );
    }

    /// M4-A2：三层统计与分块探测用的 offset 时间戳。
    #[test]
    fn m4a_tier_stats_and_offset_probe() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(s.raw_stats().unwrap(), TierStats::default());
        assert_eq!(s.samples_1m_stats().unwrap(), TierStats::default());
        assert_eq!(s.samples_1h_stats().unwrap(), TierStats::default());

        let base = 1_700_000_040_000;
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", base + 1_000, 1.0),
                ("cpu.usage", "{}", base + 2_000, 2.0),
                ("cpu.usage", "{}", base + 61_000, 3.0),
            ],
        );
        let raw = s.raw_stats().unwrap();
        assert_eq!(raw.rows, 3);
        assert_eq!(raw.oldest_ts, Some(base + 1_000));
        assert_eq!(raw.newest_ts, Some(base + 61_000));

        assert_eq!(
            s.raw_ts_at_offset(base, base + 120_000, 0).unwrap(),
            Some(base + 1_000)
        );
        assert_eq!(
            s.raw_ts_at_offset(base, base + 120_000, 2).unwrap(),
            Some(base + 61_000)
        );
        assert_eq!(s.raw_ts_at_offset(base, base + 120_000, 3).unwrap(), None);
        // 范围外的数据不会被探测到。
        assert_eq!(s.raw_ts_at_offset(base, base + 60_000, 2).unwrap(), None);

        s.downsample_1m_range(base, base + 120_000).unwrap();
        let minute = s.samples_1m_stats().unwrap();
        assert_eq!(minute.rows, 2);
        assert_eq!(minute.oldest_ts, Some(base));
        assert_eq!(minute.newest_ts, Some(base + 60_000));
        assert_eq!(
            s.samples_1m_ts_at_offset(base, base + 120_000, 1).unwrap(),
            Some(base + 60_000)
        );

        s.downsample_1h_range(base, base + 3_600_000).unwrap();
        let hour = s.samples_1h_stats().unwrap();
        assert_eq!(hour.rows, 1, "两个分钟桶属于同一个整点");
        assert_eq!(hour.oldest_ts, Some(1_699_999_200_000));
        assert_eq!(hour.newest_ts, Some(1_699_999_200_000));
    }

    /// M4-A2：rowid 扫描能发现增量行、无新行不误报、整表删除后 rowid 回退可恢复。
    #[test]
    fn m4a_raw_new_rows_detects_incremental_and_rowid_reset() {
        let s = SqliteStorage::open_in_memory().unwrap();
        assert_eq!(s.raw_new_rows(None).unwrap(), (None, None));

        let base = 1_700_000_040_000;
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", base + 1_000, 1.0),
                ("cpu.usage", "{}", base + 2_000, 2.0),
            ],
        );
        let (max, min_ts) = s.raw_new_rows(None).unwrap();
        let max = max.expect("非空表必须有最大 rowid");
        assert_eq!(min_ts, Some(base + 1_000));
        // 没有新行：不得把历史行误报成新行。
        assert_eq!(s.raw_new_rows(Some(max)).unwrap(), (Some(max), None));

        // 新写入一行更旧 ts 的迟到行：rowid 增长、MIN(ts) 变旧。
        insert_samples(&s, "a1", &[("cpu.usage", "{}", base - 5_000, 9.0)]);
        let (max2, min_ts2) = s.raw_new_rows(Some(max)).unwrap();
        let max2 = max2.expect("迟到的行也有 rowid");
        assert!(max2 > max);
        assert_eq!(min_ts2, Some(base - 5_000));

        // 整表删除后重新插入：rowid 回退，旧 rowid 水位必须失效并重新扫描。
        assert_eq!(s.prune_samples_before(i64::MAX).unwrap().deleted, 3);
        insert_samples(&s, "a1", &[("cpu.usage", "{}", base + 10_000, 3.0)]);
        let (max3, min_ts3) = s.raw_new_rows(Some(max2)).unwrap();
        assert_eq!(
            min_ts3,
            Some(base + 10_000),
            "rowid 回退后必须把全部现存行当作新行"
        );
        assert!(max3.unwrap() < max2);
    }

    /// M4-A2：删除严格 `< cutoff`（等于不删）、按 5000 行分批、三层都生效。
    #[test]
    fn m4a_prune_is_batched_and_strictly_before_cutoff() {
        assert_eq!(PRUNE_BATCH_ROWS, 5_000);
        assert_eq!(DOWNSAMPLE_MAX_CHUNK_ROWS, 5_000);

        let s = SqliteStorage::open_in_memory().unwrap();
        let cutoff = 1_700_000_040_000; // 整分钟
        let mut rows = Vec::with_capacity(12_002);
        for index in 0..12_000i64 {
            rows.push(("cpu.usage", "{}", cutoff - 12_000 + index, index as f64));
        }
        // 恰好等于 cutoff 的行必须保留；最新一行同样保留。
        rows.push(("cpu.usage", "{}", cutoff, 1.0));
        rows.push(("cpu.usage", "{}", cutoff + 1_000, 2.0));
        insert_samples(&s, "a1", &rows);

        let pruned = s.prune_samples_before(cutoff).unwrap();
        assert_eq!(pruned.deleted, 12_000);
        assert_eq!(pruned.batches, 3, "12,000 行 = 5000 + 5000 + 2000");
        let raw = s.raw_stats().unwrap();
        assert_eq!(raw.rows, 2, "等于 cutoff 的行必须保留");
        assert_eq!(raw.oldest_ts, Some(cutoff));

        // 重复删除：已无过期行，零批次零删除。
        assert_eq!(
            s.prune_samples_before(cutoff).unwrap(),
            PruneResult::default()
        );

        // 1m：bucket_ts 严格小于 cutoff 才删除。
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", cutoff - 60_000 + 1_000, 1.0),
                ("cpu.usage", "{}", cutoff + 1_000, 2.0),
            ],
        );
        s.downsample_1m_range(cutoff - 60_000, cutoff + 60_000)
            .unwrap();
        assert_eq!(s.samples_1m_stats().unwrap().rows, 2);
        assert_eq!(s.prune_samples_1m_before(cutoff).unwrap().deleted, 1);
        let minute = s.samples_1m_stats().unwrap();
        assert_eq!(minute.rows, 1);
        assert_eq!(minute.oldest_ts, Some(cutoff));

        // 1h：整点边界同样是严格小于。
        let hour = 1_699_999_200_000;
        insert_samples(&s, "a1", &[("cpu.usage", "{}", hour - 1_800_000, 5.0)]);
        s.downsample_1m_range(hour - BUCKET_1H_MS, hour + BUCKET_1H_MS)
            .unwrap();
        s.downsample_1h_range(hour - BUCKET_1H_MS, hour + BUCKET_1H_MS)
            .unwrap();
        assert_eq!(s.samples_1h_stats().unwrap().rows, 2);
        assert_eq!(s.prune_samples_1h_before(hour).unwrap().deleted, 1);
        assert_eq!(s.samples_1h_stats().unwrap().oldest_ts, Some(hour));
    }

    // ---- M4-A2b：查询选层（1m/1h 加权聚合、latest_samples 回退） ----

    /// 直接写 1m/1h 聚合表，`min/max` 取 `avg`（查询测试只关心 avg/last/count）。
    ///
    /// 参数顺序：metric、labels、bucket_ts、avg_value、last_value、count。
    fn insert_tier_rows(
        s: &SqliteStorage,
        table: &str,
        agent_id: &str,
        rows: &[(&str, &str, i64, f64, f64, i64)],
    ) {
        assert!(matches!(table, "samples_1m" | "samples_1h"));
        let conn = s.lock_write();
        let sql = format!(
            "INSERT INTO {table}
                 (agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, last_value, count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?5, ?6, ?7)"
        );
        let mut stmt = conn.prepare(&sql).unwrap();
        for (metric, labels, bucket_ts, avg_value, last_value, count) in rows {
            stmt.execute(params![
                agent_id, metric, labels, bucket_ts, avg_value, last_value, count
            ])
            .unwrap();
        }
    }

    /// 1m 层：`value` 按 count 加权平均；labels 不同不合并；空范围返回空。
    #[test]
    fn m4b_tiered_query_1m_weights_by_count_and_groups_labels() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let base = 1_700_000_700_000; // 整 5 分钟
        assert_eq!(base % BUCKET_1M_MS, 0);
        assert_eq!(base % 300_000, 0);

        // 三分钟桶合成一个 5 分钟查询桶：简单平均 37.33，按 count 加权 = 36。
        insert_tier_rows(
            &s,
            "samples_1m",
            "a1",
            &[
                ("cpu.usage", "{}", base, 2.0, 2.0, 3),
                ("cpu.usage", "{}", base + 60_000, 10.0, 10.0, 1),
                ("cpu.usage", "{}", base + 120_000, 100.0, 100.0, 2),
                ("cpu.usage", r#"{"disk":"sda"}"#, base, 8.0, 9.0, 2),
            ],
        );

        let query = SeriesQuery {
            agent_id: "a1".into(),
            metrics: Vec::new(),
            from: base,
            to: base + 299_999,
            limit: 100,
        };
        let rows = s
            .query_series_tiered(&query, 300_000, SampleTier::OneMinute)
            .unwrap();
        assert_eq!(rows.len(), 2, "labels 不同不能合并: {rows:?}");

        let cpu = rows.iter().find(|r| r.labels.is_empty()).unwrap();
        assert_eq!(cpu.ts, base);
        assert!(
            (cpu.value - 36.0).abs() < 1e-9,
            "必须按 count 加权平均，实际 {}",
            cpu.value
        );
        let disk = rows
            .iter()
            .find(|r| r.labels.get("disk").map(String::as_str) == Some("sda"))
            .unwrap();
        assert_eq!(disk.ts, base);
        assert!((disk.value - 8.0).abs() < 1e-9);

        // 空范围 / 非法桶宽。
        let empty = SeriesQuery {
            from: base + 10_000_000,
            to: base + 10_100_000,
            ..query.clone()
        };
        assert!(s
            .query_series_tiered(&empty, 300_000, SampleTier::OneMinute)
            .unwrap()
            .is_empty());
        assert!(s
            .query_series_tiered(&query, 0, SampleTier::OneMinute)
            .is_err());
        assert!(s
            .query_series_tiered(&query, -1, SampleTier::OneMinute)
            .is_err());
    }

    /// 1h 层：请求桶大于层粒度时仍按 `SUM(avg*count)/SUM(count)` 加权。
    #[test]
    fn m4b_tiered_query_1h_bucket_larger_than_granularity() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let hour = 1_699_999_200_000; // 整点且 2 小时对齐
        assert_eq!(hour % BUCKET_1H_MS, 0);
        assert_eq!(hour % 7_200_000, 0);

        insert_tier_rows(
            &s,
            "samples_1h",
            "a1",
            &[
                ("cpu.usage", "{}", hour, 12.5, 12.5, 4),
                ("cpu.usage", "{}", hour + BUCKET_1H_MS, 100.0, 100.0, 2),
            ],
        );

        let query = SeriesQuery {
            agent_id: "a1".into(),
            metrics: vec!["cpu.usage".into()],
            from: hour,
            to: hour + 7_199_999,
            limit: 10,
        };
        let rows = s
            .query_series_tiered(&query, 7_200_000, SampleTier::OneHour)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ts, hour, "返回 2 小时桶起点");
        let expected = (12.5 * 4.0 + 100.0 * 2.0) / 6.0;
        assert!(
            (rows[0].value - expected).abs() < 1e-9,
            "2h 桶必须按 count 加权: {} != {expected}",
            rows[0].value
        );
        assert!(
            (rows[0].value - 56.25).abs() > 1.0,
            "不能对各小时均值简单平均"
        );

        // 上界恰好等于桶起点：纳入；上界早于桶：排除。
        let at_start = SeriesQuery {
            from: hour - 10_000,
            to: hour,
            ..query.clone()
        };
        assert_eq!(
            s.query_series_tiered(&at_start, 7_200_000, SampleTier::OneHour)
                .unwrap()
                .len(),
            1
        );
        let before_start = SeriesQuery {
            from: hour - 10_000,
            to: hour - 1,
            ..query
        };
        assert!(s
            .query_series_tiered(&before_start, 7_200_000, SampleTier::OneHour)
            .unwrap()
            .is_empty());
    }

    /// 1m 时间重叠：`bucket_ts + 60s > from` 且 `bucket_ts <= to`；raw 路径不变。
    #[test]
    fn m4b_tiered_query_time_overlap_and_raw_path_unchanged() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let base = 1_700_000_700_000;
        insert_tier_rows(
            &s,
            "samples_1m",
            "a1",
            &[("cpu.usage", "{}", base, 4.0, 4.0, 1)],
        );
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", base + 1_000, 10.0),
                ("cpu.usage", "{}", base + 1_900, 20.0),
                ("cpu.usage", "{}", base + 2_100, 30.0),
            ],
        );

        let range = |from: i64, to: i64| SeriesQuery {
            agent_id: "a1".into(),
            metrics: vec!["cpu.usage".into()],
            from,
            to,
            limit: 100,
        };

        // 窗口落在桶中间：仍有重叠，返回桶起点。
        let rows = s
            .query_series_tiered(
                &range(base + 30_000, base + 30_000),
                60_000,
                SampleTier::OneMinute,
            )
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ts, base);
        // 窗口起点等于桶尾（bucket_ts + 60s）：不再重叠。
        assert!(s
            .query_series_tiered(
                &range(base + 60_000, base + 120_000),
                60_000,
                SampleTier::OneMinute
            )
            .unwrap()
            .is_empty());
        // 窗口终点早于桶起点：排除。
        assert!(s
            .query_series_tiered(
                &range(base - 10_000, base - 1),
                60_000,
                SampleTier::OneMinute
            )
            .unwrap()
            .is_empty());

        // raw 层必须与旧的 query_series_bucketed 完全一致。
        let query = range(0, base + 10_000);
        let tiered = s
            .query_series_tiered(&query, 2_000, SampleTier::Raw)
            .unwrap();
        let legacy = s.query_series_bucketed(&query, 2_000).unwrap();
        let summary = |rows: &[SeriesRow]| {
            rows.iter()
                .map(|r| (r.metric.clone(), r.labels.clone(), r.ts, r.value))
                .collect::<Vec<_>>()
        };
        assert_eq!(summary(&tiered), summary(&legacy), "raw 路径必须保持旧行为");
        assert_eq!(tiered.len(), 2, "只有 raw 表参与，1m 行不得混入");
        assert!(s.query_series_tiered(&query, 0, SampleTier::Raw).is_err());
    }

    /// `latest_samples`：raw 为空才回退 1m，1m 也为空再回退 1h；
    /// 保留 since 放宽一个层粒度、metrics/agent 过滤与 last_value 语义。
    #[test]
    fn m4b_latest_samples_falls_back_to_1m_then_1h() {
        assert_eq!(LATEST_SAMPLES_SQL_LIMIT, 100_000);

        let s = SqliteStorage::open_in_memory().unwrap();
        let base = 1_700_000_700_000; // 整分钟
        assert_eq!(base % BUCKET_1M_MS, 0);
        let hour = base.div_euclid(BUCKET_1H_MS) * BUCKET_1H_MS;

        // raw：同序列两点，last_value 必须是 ts 更新的 9。
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", base + 1_000, 1.0),
                ("cpu.usage", "{}", base + 2_000, 9.0),
            ],
        );
        s.downsample_1m_range(base, base + BUCKET_1M_MS).unwrap();
        // 额外的 1m / 1h 序列：raw 存在时不得出现在 latest 结果里。
        insert_tier_rows(
            &s,
            "samples_1m",
            "a1",
            &[("disk.used", "{}", base, 10.0, 77.0, 3)],
        );
        insert_tier_rows(
            &s,
            "samples_1h",
            "a1",
            &[("net.rx", "{}", hour, 20.0, 88.0, 5)],
        );
        insert_tier_rows(
            &s,
            "samples_1m",
            "a2",
            &[("disk.used", "{}", base, 30.0, 99.0, 1)],
        );

        // raw 有数据：只返回 raw，不混入 1m/1h。
        let rows = s.latest_samples(0, &[], None).unwrap();
        assert_eq!(rows.len(), 1, "只能是 raw 序列: {rows:?}");
        assert_eq!(rows[0].metric, "cpu.usage");
        assert_eq!(rows[0].ts, base + 2_000);
        assert!((rows[0].value - 9.0).abs() < 1e-9);

        // 删除 raw：回退 1m，ts 用 bucket_ts、value 用 last_value。
        s.prune_samples_before(i64::MAX).unwrap();
        assert_eq!(s.raw_stats().unwrap().rows, 0);
        let rows = s.latest_samples(0, &[], Some("a1")).unwrap();
        let summary: Vec<(&str, i64, f64)> = rows
            .iter()
            .map(|r| (r.metric.as_str(), r.ts, r.value))
            .collect();
        assert_eq!(
            summary,
            vec![("cpu.usage", base, 9.0), ("disk.used", base, 77.0)],
            "1m 回退：按 (agent,metric,labels) 去重且用 last_value"
        );

        // since 放宽一个层粒度：跨窗口边界的桶仍可见；桶结束恰好等于 since
        // （base + 60s）时必须不可见。
        let rows = s
            .latest_samples(base + 30_000, &["cpu.usage".into()], Some("a1"))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ts, base);
        assert!(s
            .latest_samples(base + BUCKET_1M_MS, &["cpu.usage".into()], None)
            .unwrap()
            .is_empty());
        // metrics / agent 过滤同样作用于回退查询。
        let rows = s
            .latest_samples(0, &["disk.used".into()], Some("a2"))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].agent_id, "a2");
        assert!((rows[0].value - 99.0).abs() < 1e-9);

        // 1m 也为空：再回退 1h。
        s.prune_samples_1m_before(i64::MAX).unwrap();
        assert_eq!(s.samples_1m_stats().unwrap().rows, 0);
        let rows = s.latest_samples(0, &[], None).unwrap();
        assert_eq!(rows.len(), 1, "只能回退到 1h: {rows:?}");
        assert_eq!(rows[0].metric, "net.rx");
        assert_eq!(rows[0].ts, hour);
        assert!((rows[0].value - 88.0).abs() < 1e-9);

        // 1h 的 since 同样放宽一个层粒度；桶结束恰好等于 since 时不可见。
        assert_eq!(
            s.latest_samples(hour + 1_800_000, &[], None).unwrap().len(),
            1
        );
        assert!(s
            .latest_samples(hour + BUCKET_1H_MS, &[], None)
            .unwrap()
            .is_empty());
    }

    /// EXPLAIN QUERY PLAN：tiered / latest 回退都必须走聚合表索引（范围受限），
    /// 不能因为列上表达式退化成全表扫描。
    #[test]
    fn m4b_tiered_queries_use_tier_indexes() {
        let s = SqliteStorage::open_in_memory().unwrap();
        // EXPLAIN 不执行查询，但 rusqlite 仍要求占位符数量匹配；绑定 NULL 即可。
        let plan = |sql: &str, params_len: usize| -> Vec<String> {
            let conn = s.lock_read();
            let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let nulls = vec![rusqlite::types::Value::Null; params_len];
            stmt.query_map(rusqlite::params_from_iter(nulls), |r| r.get::<_, String>(3))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        let assert_indexed = |sql: &str, params_len: usize, index: &str| {
            let plan = plan(sql, params_len);
            assert!(
                plan.iter().any(|detail| detail.contains(index)),
                "{index} 未被使用: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|detail| detail == "SCAN samples_1m" || detail == "SCAN samples_1h"),
                "不得全表扫描: {plan:?}"
            );
        };

        // 路由主查询总是带 metric，走 (agent_id, metric, bucket_ts) 复合索引。
        // 占位符：4 个基础参数 + metric + limit。
        for table in ["samples_1m", "samples_1h"] {
            assert_indexed(
                &tiered_query_sql(table, 1),
                6,
                &format!("idx_{table}_lookup"),
            );
        }
        // latest 回退：带 agent 时可用 lookup，不带 agent 时用 bucket_ts 单列索引。
        assert_indexed(
            &latest_tier_sql("samples_1m", true, 0),
            4,
            "idx_samples_1m_lookup",
        );
        assert_indexed(
            &latest_tier_sql("samples_1h", false, 1),
            4,
            "idx_samples_1h_ts",
        );
    }

    /// latest 回退必须有 `bucket_ts <= now` 上界，未来桶不能顶掉正常最新点。
    #[test]
    fn m4b_latest_tier_ignores_future_buckets() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let now = now_ms();
        let base = (now - 10 * BUCKET_1M_MS).div_euclid(BUCKET_1M_MS) * BUCKET_1M_MS;
        insert_tier_rows(
            &s,
            "samples_1m",
            "a1",
            &[
                ("cpu.usage", "{}", base, 1.0, 1.0, 1),
                // 未来桶：没有上界时 ts 更大，会在去重时顶掉正常点。
                ("cpu.usage", "{}", now + 86_400_000, 9.0, 9.0, 1),
            ],
        );

        let rows = s.latest_samples(0, &[], None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ts, base, "未来桶必须被 bucket_ts <= now 排除");
        assert!((rows[0].value - 1.0).abs() < 1e-9);
    // ------------------------------------------------------------------
    // M4-B1：告警规则存储
    // ------------------------------------------------------------------

    use crate::alerts::builtin_rules;

    fn alert_rule(name: &str) -> AlertRule {
        AlertRule {
            id: format!("custom-{name}"),
            name: name.to_string(),
            enabled: false,
            source: AlertSource::Metric,
            metric: "disk.used_percent".to_string(),
            comparator: Comparator::Gt,
            threshold: 90.0,
            duration_secs: 300,
            cooldown_secs: 1_800,
            filter_agent_id: None,
            filter_labels: Labels::new(),
            channel_ids: Vec::new(),
            notify_on_resolve: true,
            is_builtin: false,
            updated_by: "admin".to_string(),
            created_at: 1_000,
            updated_at: 1_000,
        }
    }

    fn store_error(err: anyhow::Error) -> AlertRuleStoreError {
        *err.downcast_ref::<AlertRuleStoreError>()
            .expect("必须是可映射的告警规则领域错误")
    }

    /// CRUD 往返：labels / channel_ids / filter_agent_id 原样读回，删除后计数归零。
    #[test]
    fn m4_b1_alert_rule_crud_roundtrip() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let mut rule = alert_rule("磁盘告警");
        rule.filter_agent_id = Some("agent-1".into());
        rule.filter_labels.insert("mount".into(), "/".into());
        rule.channel_ids = vec!["channel-1".into(), "channel-2".into()];

        s.create_alert_rule(&rule).unwrap();
        assert_eq!(s.alert_rule_count().unwrap(), 1);
        assert_eq!(s.get_alert_rule(&rule.id).unwrap(), Some(rule.clone()));
        assert_eq!(s.get_alert_rule("missing").unwrap(), None);

        let mut updated = rule.clone();
        updated.name = "磁盘告警-2".into();
        updated.enabled = true;
        updated.threshold = 95.5;
        updated.duration_secs = 0;
        updated.cooldown_secs = 0;
        updated.filter_agent_id = None;
        updated.filter_labels = Labels::new();
        updated.channel_ids = vec!["channel-2".into()];
        updated.notify_on_resolve = false;
        updated.updated_by = "ops".into();
        updated.updated_at = 2_000;
        s.update_alert_rule(&updated).unwrap();

        assert_eq!(s.get_alert_rule(&rule.id).unwrap(), Some(updated.clone()));
        assert_eq!(s.list_alert_rules().unwrap(), vec![updated.clone()]);

        s.delete_alert_rule(&rule.id).unwrap();
        assert_eq!(s.get_alert_rule(&rule.id).unwrap(), None);
        assert_eq!(s.alert_rule_count().unwrap(), 0);
        assert!(s.list_alert_rules().unwrap().is_empty());
    }

    /// 名称唯一：创建与更新都返回 NameExists，失败时原值不变；缺失返回 NotFound。
    #[test]
    fn m4_b1_alert_rule_name_unique_and_missing_errors() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.create_alert_rule(&alert_rule("同名")).unwrap();

        let err = s.create_alert_rule(&alert_rule("同名")).unwrap_err();
        assert_eq!(store_error(err), AlertRuleStoreError::NameExists);

        let mut second = alert_rule("第二条");
        second.id = "rule-2".into();
        s.create_alert_rule(&second).unwrap();
        let mut conflict = second.clone();
        conflict.name = "同名".into();
        let err = s.update_alert_rule(&conflict).unwrap_err();
        assert_eq!(store_error(err), AlertRuleStoreError::NameExists);
        assert_eq!(
            s.get_alert_rule("rule-2").unwrap().unwrap().name,
            "第二条",
            "重名更新失败不能改动原行"
        );

        let mut missing = alert_rule("不存在");
        missing.id = "missing".into();
        assert_eq!(
            store_error(s.update_alert_rule(&missing).unwrap_err()),
            AlertRuleStoreError::NotFound
        );
        assert_eq!(
            store_error(s.delete_alert_rule("missing").unwrap_err()),
            AlertRuleStoreError::NotFound
        );

        // 主键冲突不是「名称重复」，不能被误映射成 409 rule_name_exists。
        let mut duplicate_id = alert_rule("另一个");
        duplicate_id.id = "custom-同名".into();
        let err = s.create_alert_rule(&duplicate_id).unwrap_err();
        assert!(
            err.downcast_ref::<AlertRuleStoreError>().is_none(),
            "主键冲突必须是内部错误: {err}"
        );
    }

    /// 种子幂等：重复调用不新增；用户改过的阈值 / 启停 / 名称绝不被覆盖。
    #[test]
    fn m4_b1_alert_rule_seed_is_idempotent_and_preserves_user_edits() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let now = 1_700_000_000_000;
        let rules = builtin_rules(now);
        assert_eq!(s.seed_builtin_alert_rules(&rules, now).unwrap(), 5);
        assert_eq!(s.alert_rule_count().unwrap(), 5);

        // 重复种子（哪怕时间戳不同）不新增、不刷新任何字段。
        let same: Vec<AlertRule> = s.list_alert_rules().unwrap();
        assert_eq!(
            s.seed_builtin_alert_rules(&builtin_rules(now + 1), now + 1)
                .unwrap(),
            0
        );
        assert_eq!(s.list_alert_rules().unwrap(), same);

        let mut edited = s
            .get_alert_rule("builtin-disk-percent")
            .unwrap()
            .expect("内置规则必须已种入");
        let seeded_created_at = edited.created_at;
        edited.enabled = true;
        edited.threshold = 95.0;
        edited.name = "磁盘（自定义）".into();
        edited.updated_by = "ops".into();
        edited.updated_at = now + 60_000;
        s.update_alert_rule(&edited).unwrap();

        assert_eq!(
            s.seed_builtin_alert_rules(&builtin_rules(now + 120_000), now + 120_000)
                .unwrap(),
            0
        );
        let after = s.get_alert_rule("builtin-disk-percent").unwrap().unwrap();
        assert_eq!(after, edited, "种子绝不能覆盖用户改动");
        assert_eq!(after.created_at, seeded_created_at);
        assert_eq!(s.alert_rule_count().unwrap(), 5);
    }

    /// 内置规则禁删；更新时 `is_builtin` / `created_at` 由存储层保持原值。
    #[test]
    fn m4_b1_alert_rule_builtin_delete_rejected_and_update_keeps_flag() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let now = 42;
        s.seed_builtin_alert_rules(&builtin_rules(now), now)
            .unwrap();

        let err = s.delete_alert_rule("builtin-agent-offline").unwrap_err();
        assert_eq!(store_error(err), AlertRuleStoreError::BuiltinRule);
        assert!(s.get_alert_rule("builtin-agent-offline").unwrap().is_some());

        // 模拟上层把服务端字段改坏：存储层忽略 is_builtin / created_at 的改动。
        let mut rule = s.get_alert_rule("builtin-agent-offline").unwrap().unwrap();
        rule.is_builtin = false;
        rule.created_at = 999;
        rule.enabled = true;
        rule.name = "离线（自定义）".into();
        rule.updated_at = 100;
        s.update_alert_rule(&rule).unwrap();

        let stored = s.get_alert_rule("builtin-agent-offline").unwrap().unwrap();
        assert!(stored.is_builtin, "is_builtin 不能通过更新接口改掉");
        assert_eq!(stored.created_at, now, "created_at 不能被更新覆盖");
        assert!(stored.enabled);
        assert_eq!(stored.name, "离线（自定义）");
        assert_eq!(stored.updated_at, 100);

        // 自定义规则仍然可以删除。
        s.create_alert_rule(&alert_rule("可删除")).unwrap();
        s.delete_alert_rule("custom-可删除").unwrap();
        assert_eq!(s.alert_rule_count().unwrap(), 5);
    }

    /// JSON 列稳定序列化：labels 按 BTreeMap 键序、channel_ids 保留顺序；
    /// NULL `filter_agent_id` 与空 labels / 空数组往返一致。
    #[test]
    fn m4_b1_alert_rule_json_columns_are_stable() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let mut rule = alert_rule("json");
        // 插入顺序与字典序相反，落库必须按字典序稳定输出。
        rule.filter_labels.insert("mount".into(), "/data".into());
        rule.filter_labels.insert("fs".into(), "ext4".into());
        rule.channel_ids = vec!["channel-b".into(), "channel-a".into()];
        s.create_alert_rule(&rule).unwrap();

        {
            let conn = s.lock_write();
            let (labels, channels): (String, String) = conn
                .query_row(
                    "SELECT filter_labels, channel_ids FROM alert_rules WHERE id = ?1",
                    params![rule.id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(labels, r#"{"fs":"ext4","mount":"/data"}"#);
            assert_eq!(channels, r#"["channel-b","channel-a"]"#);
        }
        let stored = s.get_alert_rule(&rule.id).unwrap().unwrap();
        assert_eq!(stored.filter_labels, rule.filter_labels);
        assert_eq!(stored.channel_ids, rule.channel_ids);
        assert_eq!(stored.filter_agent_id, None);

        // 空 labels / 空数组 / NULL 过滤 agent 的稳定形态。
        let empty = alert_rule("empty");
        s.create_alert_rule(&empty).unwrap();
        let conn = s.lock_write();
        let (labels, channels): (String, String) = conn
            .query_row(
                "SELECT filter_labels, channel_ids FROM alert_rules WHERE id = ?1",
                params![empty.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(labels, "{}");
        assert_eq!(channels, "[]");
    }

    /// 上限：总数（含内置）达到 200 后创建返回 LimitReached。
    #[test]
    fn m4_b1_alert_rule_limit_is_enforced() {
        let s = SqliteStorage::open_in_memory().unwrap();
        for index in 0..MAX_ALERT_RULES {
            let mut rule = alert_rule("批量");
            rule.id = format!("rule-{index}");
            rule.name = format!("规则-{index}");
            s.create_alert_rule(&rule).unwrap();
        }
        assert_eq!(s.alert_rule_count().unwrap(), MAX_ALERT_RULES);

        let err = s.create_alert_rule(&alert_rule("超额")).unwrap_err();
        assert_eq!(store_error(err), AlertRuleStoreError::LimitReached);
        assert_eq!(s.alert_rule_count().unwrap(), MAX_ALERT_RULES);
    }
}
