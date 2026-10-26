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

use crate::alerts::{
    AlertEvent, AlertRule, AlertRuleStoreError, AlertSilence, AlertSilenceStoreError, AlertSource,
    AlertState, AlertStateKind, Comparator, MAX_ALERT_RULES, MAX_ALERT_SILENCES,
};
use crate::archive::{ArchiveObject, ArchiveStatus, ArchiveStoreError, LEDGER_VERSION_V8};
use crate::channels::{ChannelConfig, ChannelKind, NotificationChannel};

use super::{
    invalid_batch, AgentControlRecord, AgentSeriesRow, ApiTokenRecord, AuditEntry,
    DownsampleRangeResult, IngestOutcome, MaintenanceStateEntry, NewAuditEntry, PruneResult,
    QueryTooLarge, RejectReason, SampleTier, Storage, TierStats, AUDIT_RETENTION_MS, BUCKET_1H_MS,
    BUCKET_1M_MS,
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
/// v8 = raw 归档归属 / 聚合认领列、1m 水位列、归档 ledger 版本与对应 partial index。
const SCHEMA_VERSION: i64 = 8;

/// `last_used_at` 的写入节流窗口：同一 token 60s 内只写一次，避免每个管理
/// 请求都抢写连接；首次鉴权（`last_used_at IS NULL`）一定会写。
const API_TOKEN_LAST_USED_THROTTLE_MS: i64 = 60_000;

/// 每这么多次审计写入清理一次 180 天前的记录。
const AUDIT_CLEANUP_EVERY: u64 = 1_000;

/// 审计 `params` 的存储上限（字节）；调用方已限长，这里是最后一道防线。
const MAX_AUDIT_PARAMS_BYTES: usize = 1_024;

/// 通知渠道总数硬上限（方案 §8.1 / B2 验收标准）。
pub const MAX_NOTIFICATION_CHANNELS: usize = 50;

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
    value     REAL NOT NULL,
    archive_object_id INTEGER,
    aggregated_1m INTEGER NOT NULL DEFAULT 0
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
    last_ts    INTEGER NOT NULL DEFAULT 0,
    aggregated_1h INTEGER NOT NULL DEFAULT 0,
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

-- 告警 raw-only 查询按 metric + 时间范围扫描；没有它只能走 ts 索引后逐行过滤 metric。
CREATE INDEX IF NOT EXISTS idx_samples_metric_ts ON samples(metric, ts);

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
-- 保留期 / 陈旧状态清理按 (state, last_eval_at) 扫描，避免全表。
CREATE INDEX IF NOT EXISTS idx_alert_states_state_eval ON alert_states(state, last_eval_at);

CREATE TABLE IF NOT EXISTS alert_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    agent_id     TEXT NOT NULL DEFAULT '',
    series_key   TEXT NOT NULL DEFAULT '',
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
-- B2 通知队列：只取未通知且未静默的事件，按 id 升序；silenced 事件永不投递。
CREATE INDEX IF NOT EXISTS idx_alert_events_pending ON alert_events(notified, silenced, id);

CREATE TABLE IF NOT EXISTS alert_silences (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id    TEXT,
    agent_id   TEXT,
    until_ts   INTEGER NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
-- 查询生效静默 / 过期清理都按 until_ts 过滤。
CREATE INDEX IF NOT EXISTS idx_alert_silences_until ON alert_silences(until_ts);

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
    deleted_at   INTEGER,
    ledger_version INTEGER NOT NULL DEFAULT 0,
    attempts     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_archive_objects_range ON archive_objects(from_ts, to_ts);
CREATE INDEX IF NOT EXISTS idx_archive_objects_status ON archive_objects(status);

CREATE TABLE IF NOT EXISTS archive_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
"#;

/// v8 的 partial index。
///
/// 必须在 [`ensure_v8_columns`] 之后执行：旧 v7 库建索引时新列还不存在。
/// 扫描条件与索引谓词完全一致，SQLite 才会走 partial index 而不是全表。
const V8_INDEXES: &str = r#"
CREATE INDEX IF NOT EXISTS idx_samples_unarchived ON samples(ts)
    WHERE archive_object_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_samples_unaggregated ON samples(ts)
    WHERE aggregated_1m = 0;
CREATE INDEX IF NOT EXISTS idx_samples_1m_unaggregated ON samples_1m(bucket_ts)
    WHERE aggregated_1h = 0;
"#;

/// v8 新增列（旧 v7 库逐列检查后 ALTER）。
///
/// `(表, 列, ALTER 语句)` 全部是编译期常量，不接受外部输入。
const V8_COLUMNS: [(&str, &str, &str); 6] = [
    (
        "samples",
        "archive_object_id",
        "ALTER TABLE samples ADD COLUMN archive_object_id INTEGER",
    ),
    (
        "samples",
        "aggregated_1m",
        "ALTER TABLE samples ADD COLUMN aggregated_1m INTEGER NOT NULL DEFAULT 0",
    ),
    (
        "samples_1m",
        "last_ts",
        "ALTER TABLE samples_1m ADD COLUMN last_ts INTEGER NOT NULL DEFAULT 0",
    ),
    (
        "samples_1m",
        "aggregated_1h",
        "ALTER TABLE samples_1m ADD COLUMN aggregated_1h INTEGER NOT NULL DEFAULT 0",
    ),
    (
        "archive_objects",
        "ledger_version",
        "ALTER TABLE archive_objects ADD COLUMN ledger_version INTEGER NOT NULL DEFAULT 0",
    ),
    (
        "archive_objects",
        "attempts",
        "ALTER TABLE archive_objects ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0",
    ),
];

/// `archive_state` 中的最后成功归档水位。
const STATE_LAST_ARCHIVED_TS: &str = "last_archived_ts";
/// `archive_state` 中的 v8 ledger 重建待办标记。
const STATE_ARCHIVE_LEDGER_PENDING: &str = "archive_ledger_pending";

/// 可归档 raw 的最小时间戳（Unix 毫秒）：小于 0 的旧行不进入 v8 claim。
///
/// R1b 会把这些超界行计数并隔离；本切片只保证它们不会被
/// [`SqliteStorage::list_unclaimed_archive_rows`] 选中，避免 `archive_day_for`
/// 在 i64::MIN 上整轮报错。
pub const MIN_ARCHIVE_TS_MS: i64 = 0;

/// 可归档 raw 的绝对上界：9999-12-31T23:59:59.999Z（与 `ArchiveDay` 上限一致）。
pub const MAX_ARCHIVE_TS_MS: i64 = 253_402_300_799_999;

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
/// v8 归档启用时的 raw 保留期：只删「已聚合且所属对象已 uploaded」的行。
///
/// 未认领行（`archive_object_id IS NULL`）与 pending / failed 对象必须保留；
/// 本常量只在 [`SqliteStorage::prune_archived_samples_before`] 中使用，
/// R1a-1 不改动现有 [`PRUNE_RAW_SQL`] 的行为。
const PRUNE_ARCHIVED_RAW_SQL: &str = "DELETE FROM samples WHERE rowid IN \
     (SELECT s.rowid FROM samples s \
        JOIN archive_objects o ON o.id = s.archive_object_id \
      WHERE s.ts < ?1 AND s.aggregated_1m = 1 AND o.status = 'uploaded' \
      ORDER BY s.ts LIMIT ?2)";
const PRUNE_1M_SQL: &str = "DELETE FROM samples_1m WHERE rowid IN \
     (SELECT rowid FROM samples_1m WHERE bucket_ts < ?1 ORDER BY bucket_ts LIMIT ?2)";
const PRUNE_1H_SQL: &str = "DELETE FROM samples_1h WHERE rowid IN \
     (SELECT rowid FROM samples_1h WHERE bucket_ts < ?1 ORDER BY bucket_ts LIMIT ?2)";

/// `maintenance_state` 中记录降采样已认领 raw rowid 的键。
///
/// 必须与 [`crate::downsample::STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID`] 一致；
/// 这里用同字符串常量，避免存储层反向依赖降采样层。单测
/// `ki29_rowid_watermark_key_matches_downsample_module` 校验两者相等。
const DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY: &str = "downsample_1m_last_raw_rowid";

/// `maintenance_state` 中记录 raw prune 代际的键。
///
/// raw 删除批次只要删掉「最大 rowid 行」就把值 +1（缺失/非法按 1 写）。
/// downsample 认领 rowid 水位时用它做 CAS 的第二比较项：即使 rowid key 恰好
/// 缺失，也能发现期间发生过 prune。仅写 `maintenance_state` 行，无 schema 变更。
pub const STATE_RAW_PRUNE_GENERATION: &str = "raw_prune_generation";

/// raw 删除批次收敛 rowid 水位的结果；`new == None` 表示水位键被删除/失效。
///
/// 只在事务提交后用于日志，不参与返回结构。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RowidWatermarkChange {
    old: i64,
    new: Option<i64>,
}

/// 在调用方已开启的写事务内把 `raw_prune_generation` 读-改-写为 +1。
///
/// 缺失或非法旧值按 1 写；`saturating_add` 防止极端脏数据下溢出。
/// 调用方必须已持有写事务，否则 generation 与 raw 删除不在同一原子边界。
fn bump_raw_prune_generation(tx: &Transaction<'_>, now: i64) -> Result<()> {
    let current: Option<String> = tx
        .query_row(
            "SELECT value FROM maintenance_state WHERE key = ?1",
            params![STATE_RAW_PRUNE_GENERATION],
            |row| row.get(0),
        )
        .optional()?;
    let next = current
        .and_then(|raw| raw.trim().parse::<i64>().ok())
        .map_or(1, |value| value.saturating_add(1));
    tx.execute(
        "INSERT INTO maintenance_state (key, value, updated_at)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(key) DO UPDATE SET
             value = excluded.value,
             updated_at = excluded.updated_at",
        params![STATE_RAW_PRUNE_GENERATION, next.to_string(), now],
    )?;
    Ok(())
}

/// 在调用方已开启的写事务内收敛 `downsample_1m_last_raw_rowid`，并在最大
/// rowid 行被删时推进 `raw_prune_generation`。
///
/// `max_before` / `max_after` 由调用方在本批 DELETE 前后读取；函数不再自己
/// 查 MAX，保证判断依据与删除同属一个事务。
///
/// rowid 水位规则：
/// - raw 表为空：删除水位键（残留键会让复用 rowid 的行永远扫描不到）；
/// - 最大 rowid 行被删（`max_after < max_before`）且旧水位不高于 `max_after`：
///   删除键。此时不能保留原值：downsample 可能已用旧值作 CAS 期望，保留会
///   让并发 downsample 把删除前的旧 MAX 写回；
/// - 其余情况只降不升：旧水位高于 `max_after` 才更新，否则不动；
/// - 旧值缺失/非法时不新增 key。
///
/// 只要 `max_after < max_before`，无论 rowid 水位是否存在都先把 generation +1，
/// 让 rowid key 缺失时 CAS 也能发现 prune。
///
/// **必须在 `tx` 上直接执行 SQL**：`set_maintenance_state` /
/// `get_maintenance_state` 会再次抢写/读连接，在同一线程里自锁。
fn lower_raw_rowid_watermark(
    tx: &Transaction<'_>,
    max_before: Option<i64>,
    max_after: Option<i64>,
    now: i64,
) -> Result<Option<RowidWatermarkChange>> {
    let max_row_deleted = match (max_before, max_after) {
        (Some(before), Some(after)) => before > after,
        (Some(_), None) => true,
        _ => false,
    };
    if max_row_deleted {
        bump_raw_prune_generation(tx, now)?;
    }

    let old_value: Option<String> = tx
        .query_row(
            "SELECT value FROM maintenance_state WHERE key = ?1",
            params![DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY],
            |row| row.get(0),
        )
        .optional()?;

    let Some(max_after) = max_after else {
        // raw 已空：残留水位会让复用 rowid 的行永远扫描不到，必须删除。
        let Some(old_value) = old_value else {
            return Ok(None);
        };
        tx.execute(
            "DELETE FROM maintenance_state WHERE key = ?1",
            params![DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY],
        )?;
        // 历史脏值无法给出数值日志；清理本身仍然执行。
        return Ok(old_value
            .trim()
            .parse::<i64>()
            .ok()
            .map(|old| RowidWatermarkChange { old, new: None }));
    };

    // 缺失或非法旧值不新增 key，也不据此改写任何状态。
    let Some(old) = old_value.and_then(|raw| raw.trim().parse::<i64>().ok()) else {
        return Ok(None);
    };

    // 最大 rowid 行被删：即使旧水位 <= 新 MAX 也必须让键失效，否则并发
    // downsample 的 CAS 期望仍成立，会把删除前的旧 MAX 写回。
    if max_row_deleted && old <= max_after {
        tx.execute(
            "DELETE FROM maintenance_state WHERE key = ?1",
            params![DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY],
        )?;
        return Ok(Some(RowidWatermarkChange { old, new: None }));
    }

    // 只降不升。
    if old <= max_after {
        return Ok(None);
    }
    tx.execute(
        "UPDATE maintenance_state SET value = ?2, updated_at = ?3 WHERE key = ?1",
        params![DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY, max_after.to_string(), now],
    )?;
    Ok(Some(RowidWatermarkChange {
        old,
        new: Some(max_after),
    }))
}

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
    // v8 门禁：更高版本库必须在 WAL/DDL/迁移之前拒绝，避免旧二进制写坏新库。
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    reject_newer_schema_version(version)?;
    // journal_mode 会返回一行，必须用 query_row 消费掉
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
    tracing::debug!(mode, "sqlite journal mode");
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.execute_batch(SCHEMA)?;
    migrate(&mut conn)?;
    Ok(conn)
}

/// 拒绝比本程序更新的 SQLite schema，避免旧二进制写坏新库。
fn reject_newer_schema_version(version: i64) -> Result<()> {
    if version > SCHEMA_VERSION {
        anyhow::bail!(
            "SQLite schema 版本 {version} 高于本程序支持的 v{SCHEMA_VERSION}；\
             请升级 rustboard-hub 后再启动，避免旧二进制写坏新库"
        );
    }
    Ok(())
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
/// 为 v5–v7 建好 M3/M4 的纯新增表，并把 v7 库补列/回填到 v8。旧行原样保留。
///
/// v1 代码从未写过 `user_version`，所以只靠版本号无法区分「空库」和「v1 库」：
/// 版本号不足 2 时再看表是否存在。整个迁移在一个 `BEGIN IMMEDIATE` 事务里完成，
/// 避免多个 hub 进程同时启动时重复迁移；旧行原样保留。
///
/// **v8 是单向升级**：已发布的 v7 二进制不会识别新列，升级后不得回退旧二进制，
/// 回滚只能恢复升级前备份。
fn migrate(conn: &mut Connection) -> Result<()> {
    // L3：先拿写锁再读版本，两个进程同时启动时只有一个能迁移。
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    // v8 门禁放在任何 DDL/数据迁移之前；init_writer 的预检只是提前拒绝，
    // 这里在持有写锁后再判一次，避免与另一个迁移进程竞态。
    reject_newer_schema_version(version)?;

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
    // 旧 v7 库（B2b 首次落地）的 alert_events 没有 series_key；纯新增列，
    // 历史事件自动补空串，通知 worker 按空序列处理。
    ensure_alert_events_series_key(&tx)?;

    // v8：先补列（旧 v7 的 CREATE TABLE IF NOT EXISTS 不会改已存在的表），
    // 再建依赖新列的 partial index，最后回填旧数据。
    ensure_v8_columns(&tx)?;
    tx.execute_batch(V8_INDEXES)?;
    apply_v8_data_migration(&tx, version)?;

    if version < SCHEMA_VERSION {
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tracing::info!(
            from = version,
            to = SCHEMA_VERSION,
            "数据库已迁移：schema v8（归档 claim / 聚合认领列与 v7 旧数据回填）"
        );
    }
    tx.commit()?;
    Ok(())
}

/// 为旧 v7 库逐列补 v8 新增列；列已存在时零写入。
fn ensure_v8_columns(tx: &Transaction<'_>) -> Result<()> {
    for (table, column, alter_sql) in V8_COLUMNS {
        let exists: i64 = tx.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2
             )",
            params![table, column],
            |row| row.get(0),
        )?;
        if exists != 0 {
            continue;
        }
        tx.execute_batch(alter_sql)?;
        tracing::info!(table, column, "已补充 v8 列");
    }
    Ok(())
}

/// v7→v8 数据回填；`version >= 8` 时整体跳过，保证重复打开不重写数据。
///
/// **按桶对账，不按维护水位**：v7 的 downsample 先写 1m 行再推进水位，崩溃
/// 窗口里会有「1m 已写、水位未推进」的桶。若按水位标记 `aggregated_1m`，
/// 这些桶的 raw 会被再次聚合（双计）；反过来水位先行也会漏计。因此：
///
/// 1. `samples.aggregated_1m`：同一分钟桶的 raw 按 `rowid` 升序编号，
///    编号 `<= 1m.count` 的置 1；raw 少于 count 全置 1，无 1m 行保持 0。
///    仅凭「桶已有 1m 行」会把崩溃窗口后到达的 late raw 误标，造成永久漏计；
/// 2. `samples_1m.last_ts`：按 `rowid` 升序取最早 `1m.count` 条 raw 的
///    `MAX(ts)`；raw 已删（无现存 raw）才回填 `bucket_ts + 59999`，避免迟到行
///    被错误当成已聚合的 last；
/// 3. `samples_1m.aggregated_1h`：同小时 1m 行按 `(bucket_ts, rowid)` 累计
///    `count`，累计值 `<= 1h.count` 的置 1，其余保持 0；不读 1h 水位（v7 水位
///    可能落在非整点）；
/// 4. `archive_objects.ledger_version` / `attempts`：DB 默认 0，不需要额外更新；
/// 5. 归档水位存在时写 `archive_state.archive_ledger_pending=1`，交给 R1a-2
///    worker 重新导出仍存在的 unclaimed raw；这里只写状态，不做上传。
///
/// 迁移层拿不到 `archive.enabled`；`last_archived_ts` 是 v7 归档 worker 唯一
/// 的持久化证据，因此以「水位存在」作为归档曾启用的 DB 侧代理。禁用归档的库
/// 不会写入 pending，重复打开也不会重写。
///
/// TODO(R1b): 超界旧 `ts` 的隔离/计数（`invalid_timestamp_rows`）与聚合查询
/// 过滤不在本切片；这里不修改任何 raw 的 `ts`，避免写坏数据。
fn apply_v8_data_migration(tx: &Transaction<'_>, version: i64) -> Result<()> {
    if version >= SCHEMA_VERSION {
        return Ok(());
    }

    // 按桶对账，而不是按非原子水位：避免 v7 崩溃窗口造成双计/漏计。
    // 先清掉非 0 残留（半迁移/异常数据），保证「无 1m 桶」严格为 0。
    // 超界时间戳（i64::MIN / 未来）不参与认领，留给 R1b 计数/隔离。
    let now = now_ms().min(MAX_ARCHIVE_TS_MS);
    tx.execute(
        "UPDATE samples SET aggregated_1m = 0 WHERE aggregated_1m != 0",
        [],
    )?;
    // 只认领每个 1m 桶「最早 1m.count 条 raw」（按 rowid 排序）；raw 少于
    // count 时全部认领。不能仅凭桶存在就把所有 raw 标 1，否则崩溃窗口后
    // 才到的 late raw 会被永久漏聚合。
    let aggregated = tx.execute(
        "UPDATE samples SET aggregated_1m = 1
         WHERE rowid IN (
             SELECT s.rowid FROM (
                 SELECT rowid, agent_id, metric, labels, ts,
                        ROW_NUMBER() OVER (
                            PARTITION BY agent_id, metric, labels, (ts / 60000) * 60000
                            ORDER BY rowid ASC
                        ) AS rn
                 FROM samples
                 WHERE ts >= ?1 AND ts <= ?2
             ) s
             JOIN samples_1m m
               ON m.agent_id = s.agent_id
              AND m.metric = s.metric
              AND m.labels = s.labels
              AND m.bucket_ts = (s.ts / 60000) * 60000
             WHERE s.rn <= m.count
         )",
        params![MIN_ARCHIVE_TS_MS, now],
    )?;
    tracing::info!(aggregated, "v8 迁移：按已存在的 1m 桶标记已聚合 raw");

    // last_ts 取「该桶最早 count 条 raw」的 MAX(ts)；raw 已删的桶才回填
    // bucket_ts+59999。这样 late raw 不会被错误当成已聚合的 last。
    tx.execute("UPDATE samples_1m SET last_ts = 0 WHERE last_ts != 0", [])?;
    let backfilled = tx.execute(
        "UPDATE samples_1m SET last_ts = COALESCE(
             (SELECT MAX(s.ts) FROM samples s
              WHERE s.agent_id = samples_1m.agent_id
                AND s.metric = samples_1m.metric
                AND s.labels = samples_1m.labels
                AND s.ts >= samples_1m.bucket_ts
                AND s.ts < samples_1m.bucket_ts + 60000
                AND (SELECT COUNT(*) FROM samples s2
                     WHERE s2.agent_id = samples_1m.agent_id
                       AND s2.metric = samples_1m.metric
                       AND s2.labels = samples_1m.labels
                       AND s2.ts >= samples_1m.bucket_ts
                       AND s2.ts < samples_1m.bucket_ts + 60000
                       AND s2.rowid <= s.rowid) <= samples_1m.count),
             samples_1m.bucket_ts + 59999)
         WHERE bucket_ts >= ?1 AND bucket_ts <= ?2",
        params![MIN_ARCHIVE_TS_MS, now],
    )?;
    tracing::info!(backfilled, "v8 迁移：回填 legacy 1m last_ts");

    // 1h 按 (bucket_ts, rowid) 累计 count 对账：累计值 <= 1h.count 的 1m
    // 行才算已并入；崩溃窗口后的 late 1m 行保持 0，交给 R1b 重算。
    tx.execute(
        "UPDATE samples_1m SET aggregated_1h = 0 WHERE aggregated_1h != 0",
        [],
    )?;
    let aggregated_hour = tx.execute(
        "UPDATE samples_1m SET aggregated_1h = 1
         WHERE rowid IN (
             SELECT m.rowid FROM (
                 SELECT rowid, agent_id, metric, labels, bucket_ts, count,
                        SUM(count) OVER (
                            PARTITION BY agent_id, metric, labels,
                                         (bucket_ts / 3600000) * 3600000
                            ORDER BY bucket_ts ASC, rowid ASC
                            ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW
                        ) AS cumulative_count
                 FROM samples_1m
                 WHERE bucket_ts >= ?1 AND bucket_ts <= ?2
             ) m
             JOIN samples_1h h
               ON h.agent_id = m.agent_id
              AND h.metric = m.metric
              AND h.labels = m.labels
              AND h.bucket_ts = (m.bucket_ts / 3600000) * 3600000
             WHERE m.cumulative_count <= h.count
         )",
        params![MIN_ARCHIVE_TS_MS, now],
    )?;
    tracing::info!(aggregated_hour, "v8 迁移：按已存在的 1h 桶标记已聚合 1m");

    let archived_watermark: Option<String> = tx
        .query_row(
            "SELECT value FROM archive_state WHERE key = ?1",
            params![STATE_LAST_ARCHIVED_TS],
            |row| row.get(0),
        )
        .optional()?;
    if archived_watermark.is_some_and(|value| !value.trim().is_empty()) {
        tx.execute(
            "INSERT INTO archive_state (key, value, updated_at)
             VALUES (?1, '1', ?2)
             ON CONFLICT(key) DO UPDATE SET
                 value = excluded.value,
                 updated_at = excluded.updated_at",
            params![STATE_ARCHIVE_LEDGER_PENDING, now_ms()],
        )?;
        tracing::info!("v8 迁移：archive_ledger_pending=1（等待 R1a-2 重建 ledger）");
    }
    Ok(())
}

/// 为旧 v7 库补 `alert_events.series_key`（`CREATE TABLE IF NOT EXISTS` 不会
/// 修改已存在的表）。每次打开都检查 `PRAGMA table_info`，列已存在时零写入。
fn ensure_alert_events_series_key(tx: &Transaction<'_>) -> Result<()> {
    let columns = {
        let mut stmt = tx.prepare("PRAGMA table_info(alert_events)")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    if columns.iter().any(|column| column == "series_key") {
        return Ok(());
    }
    tx.execute_batch("ALTER TABLE alert_events ADD COLUMN series_key TEXT NOT NULL DEFAULT ''")?;
    tracing::info!("alert_events 已补充 series_key 列（历史事件补空串）");
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
        // NUL / NaN / Inf 必须在开启事务前拒绝：不占位、不写任何行。
        if let Some(reason) = invalid_batch(batch) {
            return Ok(IngestOutcome::Rejected(reason));
        }

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
        if completed.is_multiple_of(INGEST_CLEANUP_EVERY) {
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
        if written.is_multiple_of(AUDIT_CLEANUP_EVERY) {
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

    // ---- Phase D D1a：`Storage` trait 剩余方法的 UFCS 转发 ----
    //
    // 上面已有 29 个方法直接实现；这里把 `impl SqliteStorage` 其余 68 个固有
    // 方法转发进 trait，使 `dyn Storage` 覆盖完整存储 API。**必须走
    // `SqliteStorage::method(self, ...)`**：写成 `self.method(...)` 会命中
    // trait 方法自身，造成无限递归或歧义。
    //
    // Rust 不允许同一 trait 对同一类型拆成多个 `impl` 块（E0119），所以这些
    // 转发方法与上面的实现共处一个 impl 块，但方法体互不重复。

    fn seed_builtin_alert_rules(&self, rules: &[AlertRule], now: i64) -> Result<usize> {
        SqliteStorage::seed_builtin_alert_rules(self, rules, now)
    }

    fn get_alert_rule(&self, id: &str) -> Result<Option<AlertRule>> {
        SqliteStorage::get_alert_rule(self, id)
    }

    fn list_alert_rules(&self) -> Result<Vec<AlertRule>> {
        SqliteStorage::list_alert_rules(self)
    }

    fn alert_rule_count(&self) -> Result<usize> {
        SqliteStorage::alert_rule_count(self)
    }

    fn create_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        SqliteStorage::create_alert_rule(self, rule)
    }

    fn update_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        SqliteStorage::update_alert_rule(self, rule)
    }

    fn update_alert_rule_and_clear_states(&self, rule: &AlertRule) -> Result<()> {
        SqliteStorage::update_alert_rule_and_clear_states(self, rule)
    }

    fn delete_alert_rule(&self, id: &str) -> Result<()> {
        SqliteStorage::delete_alert_rule(self, id)
    }

    fn delete_alert_rule_and_clear_states(&self, id: &str) -> Result<()> {
        SqliteStorage::delete_alert_rule_and_clear_states(self, id)
    }

    fn list_alert_states(&self) -> Result<Vec<AlertState>> {
        SqliteStorage::list_alert_states(self)
    }

    fn get_alert_state(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
    ) -> Result<Option<AlertState>> {
        SqliteStorage::get_alert_state(self, rule_id, agent_id, series_key)
    }

    fn upsert_alert_state(&self, state: &AlertState) -> Result<()> {
        SqliteStorage::upsert_alert_state(self, state)
    }

    fn delete_alert_state(&self, rule_id: &str, agent_id: &str, series_key: &str) -> Result<usize> {
        SqliteStorage::delete_alert_state(self, rule_id, agent_id, series_key)
    }

    fn prune_alert_states(&self, resolved_before: i64) -> Result<usize> {
        SqliteStorage::prune_alert_states(self, resolved_before)
    }

    fn prune_stale_alert_states(&self, stale_before: i64, max_rows: usize) -> Result<usize> {
        SqliteStorage::prune_stale_alert_states(self, stale_before, max_rows)
    }

    fn insert_alert_event(&self, event: &AlertEvent) -> Result<i64> {
        SqliteStorage::insert_alert_event(self, event)
    }

    fn list_alert_events(&self, limit: usize, before_id: Option<i64>) -> Result<Vec<AlertEvent>> {
        SqliteStorage::list_alert_events(self, limit, before_id)
    }

    fn prune_alert_events(&self, before_ts: i64, max_rows: usize) -> Result<usize> {
        SqliteStorage::prune_alert_events(self, before_ts, max_rows)
    }

    fn create_alert_silence(&self, silence: &AlertSilence) -> Result<i64> {
        SqliteStorage::create_alert_silence(self, silence)
    }

    fn list_active_silences(&self, now: i64) -> Result<Vec<AlertSilence>> {
        SqliteStorage::list_active_silences(self, now)
    }

    fn delete_alert_silence(&self, id: i64) -> Result<bool> {
        SqliteStorage::delete_alert_silence(self, id)
    }

    fn prune_alert_silences(&self, before_ts: i64) -> Result<usize> {
        SqliteStorage::prune_alert_silences(self, before_ts)
    }

    fn list_enabled_alert_rules(&self) -> Result<Vec<AlertRule>> {
        SqliteStorage::list_enabled_alert_rules(self)
    }

    fn list_alert_states_for_rule(&self, rule_id: &str, limit: usize) -> Result<Vec<AlertState>> {
        SqliteStorage::list_alert_states_for_rule(self, rule_id, limit)
    }

    fn prune_alert_states_for_rule(&self, rule_id: &str, keep: usize) -> Result<usize> {
        SqliteStorage::prune_alert_states_for_rule(self, rule_id, keep)
    }

    fn latest_alert_series(
        &self,
        metric: &str,
        since: i64,
        agent: Option<&str>,
        limit: usize,
    ) -> Result<AlertSeriesSnapshot> {
        SqliteStorage::latest_alert_series(self, metric, since, agent, limit)
    }

    fn apply_alert_transitions(&self, events: &[AlertEvent], states: &[AlertState]) -> Result<()> {
        SqliteStorage::apply_alert_transitions(self, events, states)
    }

    fn apply_alert_evaluation(
        &self,
        rule_id: &str,
        events: &[AlertEvent],
        states: &[AlertState],
        keep_states: usize,
    ) -> Result<usize> {
        SqliteStorage::apply_alert_evaluation(self, rule_id, events, states, keep_states)
    }

    fn max_alert_event_id(&self) -> Result<i64> {
        SqliteStorage::max_alert_event_id(self)
    }

    fn list_pending_notification_events_after(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<AlertEvent>> {
        SqliteStorage::list_pending_notification_events_after(self, after_id, limit)
    }

    fn mark_notification_processed(&self, id: i64, notify_error: &str) -> Result<bool> {
        SqliteStorage::mark_notification_processed(self, id, notify_error)
    }

    fn list_pending_notification_events(&self, limit: usize) -> Result<Vec<AlertEvent>> {
        SqliteStorage::list_pending_notification_events(self, limit)
    }

    fn mark_notification_result(
        &self,
        id: i64,
        notified: bool,
        notify_error: &str,
    ) -> Result<bool> {
        SqliteStorage::mark_notification_result(self, id, notified, notify_error)
    }

    fn update_alert_state_notified(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
        last_notified_at: i64,
    ) -> Result<bool> {
        SqliteStorage::update_alert_state_notified(
            self,
            rule_id,
            agent_id,
            series_key,
            last_notified_at,
        )
    }

    fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>> {
        SqliteStorage::list_notification_channels(self)
    }

    fn get_notification_channel(&self, id: &str) -> Result<Option<NotificationChannel>> {
        SqliteStorage::get_notification_channel(self, id)
    }

    fn notification_channel_count(&self) -> Result<usize> {
        SqliteStorage::notification_channel_count(self)
    }

    fn create_notification_channel(&self, channel: &NotificationChannel) -> Result<()> {
        SqliteStorage::create_notification_channel(self, channel)
    }

    fn update_notification_channel(&self, channel: &NotificationChannel) -> Result<()> {
        SqliteStorage::update_notification_channel(self, channel)
    }

    fn delete_notification_channel(&self, id: &str) -> Result<()> {
        SqliteStorage::delete_notification_channel(self, id)
    }

    fn create_api_token(
        &self,
        name: &str,
        token_hash: &str,
        scope: &str,
        created_at: i64,
    ) -> Result<ApiTokenRecord> {
        SqliteStorage::create_api_token(self, name, token_hash, scope, created_at)
    }

    fn list_api_tokens(&self) -> Result<Vec<ApiTokenRecord>> {
        SqliteStorage::list_api_tokens(self)
    }

    fn rotate_api_token(&self, name: &str, token_hash: &str, now: i64) -> Result<ApiTokenRecord> {
        SqliteStorage::rotate_api_token(self, name, token_hash, now)
    }

    fn revoke_api_token(&self, name: &str, now: i64) -> Result<()> {
        SqliteStorage::revoke_api_token(self, name, now)
    }

    fn authenticate_api_token(&self, token_hash: &str, now: i64) -> Result<Option<ApiTokenRecord>> {
        SqliteStorage::authenticate_api_token(self, token_hash, now)
    }

    fn downsample_1m_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult> {
        SqliteStorage::downsample_1m_range(self, from_ts, to_ts)
    }

    fn downsample_1h_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult> {
        SqliteStorage::downsample_1h_range(self, from_ts, to_ts)
    }

    fn raw_stats(&self) -> Result<TierStats> {
        SqliteStorage::raw_stats(self)
    }

    fn samples_1m_stats(&self) -> Result<TierStats> {
        SqliteStorage::samples_1m_stats(self)
    }

    fn samples_1h_stats(&self) -> Result<TierStats> {
        SqliteStorage::samples_1h_stats(self)
    }

    fn raw_ts_at_offset(&self, from_ts: i64, to_ts: i64, offset: usize) -> Result<Option<i64>> {
        SqliteStorage::raw_ts_at_offset(self, from_ts, to_ts, offset)
    }

    fn samples_1m_ts_at_offset(
        &self,
        from_ts: i64,
        to_ts: i64,
        offset: usize,
    ) -> Result<Option<i64>> {
        SqliteStorage::samples_1m_ts_at_offset(self, from_ts, to_ts, offset)
    }

    fn raw_new_rows(&self, after_rowid: Option<i64>) -> Result<(Option<i64>, Option<i64>)> {
        SqliteStorage::raw_new_rows(self, after_rowid)
    }

    fn samples_1m_oldest_ts(&self) -> Result<Option<i64>> {
        SqliteStorage::samples_1m_oldest_ts(self)
    }

    fn prune_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        SqliteStorage::prune_samples_before(self, cutoff)
    }

    fn prune_archived_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        SqliteStorage::prune_archived_samples_before(self, cutoff)
    }

    fn prune_samples_1m_before(&self, cutoff: i64) -> Result<PruneResult> {
        SqliteStorage::prune_samples_1m_before(self, cutoff)
    }

    fn prune_samples_1h_before(&self, cutoff: i64) -> Result<PruneResult> {
        SqliteStorage::prune_samples_1h_before(self, cutoff)
    }

    fn claim_raw_rowid_if_unchanged(
        &self,
        expected_rowid: Option<i64>,
        expected_generation: i64,
        new_max: i64,
    ) -> Result<bool> {
        SqliteStorage::claim_raw_rowid_if_unchanged(
            self,
            expected_rowid,
            expected_generation,
            new_max,
        )
    }

    fn insert_archive_object(&self, object: &ArchiveObject) -> Result<i64> {
        SqliteStorage::insert_archive_object(self, object)
    }

    fn get_archive_object(&self, id: i64) -> Result<Option<ArchiveObject>> {
        SqliteStorage::get_archive_object(self, id)
    }

    fn find_archive_object_by_key(&self, object_key: &str) -> Result<Option<ArchiveObject>> {
        SqliteStorage::find_archive_object_by_key(self, object_key)
    }

    fn list_archive_objects(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>> {
        SqliteStorage::list_archive_objects(self, limit, before_id)
    }

    fn list_retryable_archive_objects(
        &self,
        limit: usize,
        after_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>> {
        SqliteStorage::list_retryable_archive_objects(self, limit, after_id)
    }

    fn update_archive_object_status(
        &self,
        id: i64,
        status: ArchiveStatus,
        error: &str,
        uploaded_at: Option<i64>,
        deleted_at: Option<i64>,
    ) -> Result<()> {
        SqliteStorage::update_archive_object_status(
            self,
            id,
            status,
            error,
            uploaded_at,
            deleted_at,
        )
    }

    fn get_archive_state(&self, key: &str) -> Result<Option<String>> {
        SqliteStorage::get_archive_state(self, key)
    }

    fn set_archive_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()> {
        SqliteStorage::set_archive_state(self, key, value, updated_at)
    }

    fn list_archive_objects_in_range(
        &self,
        from_ts: i64,
        to_ts: i64,
    ) -> Result<Vec<ArchiveObject>> {
        SqliteStorage::list_archive_objects_in_range(self, from_ts, to_ts)
    }

    fn scan_archive_rows(
        &self,
        from_ts: i64,
        to_ts: i64,
        after_rowid: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ArchiveRawRow>> {
        SqliteStorage::scan_archive_rows(self, from_ts, to_ts, after_rowid, limit)
    }

    fn list_unclaimed_archive_rows(
        &self,
        from_ts: i64,
        to_ts: i64,
        limit: usize,
    ) -> Result<Vec<ArchiveRawRow>> {
        SqliteStorage::list_unclaimed_archive_rows(self, from_ts, to_ts, limit)
    }

    fn claim_archive_rows(&self, object: &ArchiveObject, rows: &[ArchiveRawRow]) -> Result<i64> {
        SqliteStorage::claim_archive_rows(self, object, rows)
    }

    fn archive_rows_for_object(&self, object_id: i64) -> Result<Vec<ArchiveRawRow>> {
        SqliteStorage::archive_rows_for_object(self, object_id)
    }

    fn record_archive_object_failure(&self, id: i64, error: &str) -> Result<()> {
        SqliteStorage::record_archive_object_failure(self, id, error)
    }

    fn update_archive_object_metadata(&self, id: i64, bytes: u64, sha256: &str) -> Result<()> {
        SqliteStorage::update_archive_object_metadata(self, id, bytes, sha256)
    }

    fn count_invalid_archive_raw_rows(&self) -> Result<i64> {
        SqliteStorage::count_invalid_archive_raw_rows(self)
    }

    fn record_archive_attempt(&self, id: i64) -> Result<i64> {
        SqliteStorage::record_archive_attempt(self, id)
    }

    fn count_archive_objects(&self) -> Result<i64> {
        SqliteStorage::count_archive_objects(self)
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

/// 内置规则种子写入失败：名称被其它规则占用必须显式报错，不能静默跳过。
///
/// 只用于种子路径；自定义规则走 `create_alert_rule` 的 409 映射。`rule_id` 是
/// 代码里的固定内置 id，可以安全写进错误信息。
fn map_seed_alert_rule_error(err: rusqlite::Error, rule_id: &str) -> anyhow::Error {
    if let rusqlite::Error::SqliteFailure(inner, Some(message)) = &err {
        if inner.code == rusqlite::ErrorCode::ConstraintViolation
            && message.contains("alert_rules.name")
        {
            return anyhow::anyhow!(
                "内置告警规则 {rule_id} 的名称已被其它规则占用；\
                 请先重命名冲突规则再启动 hub"
            );
        }
    }
    tracing::debug!(error = %err, rule_id = %rule_id, "写入内置告警规则种子失败（非名称唯一冲突）");
    anyhow::anyhow!("写入内置告警规则 {rule_id} 失败（数据库错误详见日志）")
}

impl SqliteStorage {
    /// 写入内置规则种子：按固定 id 已存在的规则（含用户改过的阈值 / 启停状态）
    /// **绝不覆盖**；重复调用幂等，返回本次新插入的条数。
    ///
    /// 与 `INSERT OR IGNORE` 不同：先按 id 查重、再显式 INSERT。这样 `name`
    /// 唯一冲突（例如升级前用户已建同名自定义规则）会直接失败并回滚整批种子，
    /// 而不是被 `OR IGNORE` 静默吞掉、留下「缺内置规则」的半残状态。
    ///
    /// 注意：id 已存在时整行跳过（可能已被用户改过），因此**不会**把修复前种入
    /// 的旧内置规则（如 `cert.days_left` + 48）自动迁移成新单位；这类安装需要
    /// 用户在面板里更新对应规则，或删除后由种子重建。v0.4.0 尚未发布，不存在
    /// 已发布的旧数据升级路径。
    ///
    /// `now` 作为新插入行的 `created_at` / `updated_at`；调用方通常传 `now_ms()`。
    pub fn seed_builtin_alert_rules(&self, rules: &[AlertRule], now: i64) -> Result<usize> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let sql = format!(
            "INSERT INTO alert_rules {ALERT_RULE_INSERT_COLUMNS} \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)"
        );
        let mut inserted = 0usize;
        for rule in rules {
            let exists: Option<i64> = tx
                .query_row(
                    "SELECT 1 FROM alert_rules WHERE id = ?1",
                    params![rule.id],
                    |row| row.get(0),
                )
                .optional()?;
            if exists.is_some() {
                // 可能已被用户改过阈值 / 启停 / 名称：种子绝不覆盖。
                continue;
            }
            let filter_labels = serde_json::to_string(&rule.filter_labels)?;
            let channel_ids = serde_json::to_string(&rule.channel_ids)?;
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
                    now,
                    now,
                ],
            )
            .map_err(|err| map_seed_alert_rule_error(err, &rule.id))?;
            inserted += 1;
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
    ///
    /// **不清理 alert_states**；API 禁用规则时用
    /// [`Self::update_alert_rule_and_clear_states`]。
    pub fn update_alert_rule(&self, rule: &AlertRule) -> Result<()> {
        self.update_alert_rule_inner(rule, false)
    }

    /// 与 [`Self::update_alert_rule`] 相同，但同一事务内清空该规则的 alert_states。
    ///
    /// 供 hub 在「启用 → 禁用」时调用：规则停用后旧状态会一直冻结（引擎不再评估
    /// 它），既占空间又可能让面板显示过期 firing；重新启用时应从干净状态开始。
    pub fn update_alert_rule_and_clear_states(&self, rule: &AlertRule) -> Result<()> {
        self.update_alert_rule_inner(rule, true)
    }

    fn update_alert_rule_inner(&self, rule: &AlertRule, clear_states: bool) -> Result<()> {
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
        if clear_states {
            tx.execute(
                "DELETE FROM alert_states WHERE rule_id = ?1",
                params![rule.id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// 删除自定义规则；内置规则返回 [`AlertRuleStoreError::BuiltinRule`]。
    ///
    /// 不存在与内置是两种不同的错误，调用方分别映射 404 / 403。
    ///
    /// **不清理 alert_states**；API 删除规则时用
    /// [`Self::delete_alert_rule_and_clear_states`]。
    pub fn delete_alert_rule(&self, id: &str) -> Result<()> {
        self.delete_alert_rule_inner(id, false)
    }

    /// 与 [`Self::delete_alert_rule`] 相同，但同一事务内清空该规则的 alert_states。
    pub fn delete_alert_rule_and_clear_states(&self, id: &str) -> Result<()> {
        self.delete_alert_rule_inner(id, true)
    }

    fn delete_alert_rule_inner(&self, id: &str, clear_states: bool) -> Result<()> {
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
        if clear_states {
            tx.execute("DELETE FROM alert_states WHERE rule_id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// M4-B1b：告警状态 / 事件 / 静默（schema v7 `alert_states` / `alert_events` /
// `alert_silences`）
// ---------------------------------------------------------------------------

/// `alert_states` 的 SELECT 列表；列顺序与 [`alert_state_from_row`] 一一对应。
const ALERT_STATE_COLUMNS: &str =
    "rule_id, agent_id, series_key, state, since, last_eval_at, last_value, last_notified_at";

/// `alert_events` 的 SELECT 列表；列顺序与 [`alert_event_from_row`] 一一对应。
const ALERT_EVENT_COLUMNS: &str = "id, ts, rule_id, rule_name, agent_id, series_key, state, \
     value, message, notified, notify_error, silenced";

/// `alert_silences` 的 SELECT 列表；列顺序与 [`alert_silence_from_row`] 一一对应。
const ALERT_SILENCE_COLUMNS: &str = "id, rule_id, agent_id, until_ts, created_by, created_at";

/// 插入一条事件；单条插入与批量事务共用。
const ALERT_EVENT_INSERT_SQL: &str = "INSERT INTO alert_events
        (ts, rule_id, rule_name, agent_id, series_key, state, value, message, notified,
         notify_error, silenced)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";

/// 插入或整行更新一条状态；单条 upsert 与批量事务共用。
const ALERT_STATE_UPSERT_SQL: &str = "INSERT INTO alert_states
        (rule_id, agent_id, series_key, state, since, last_eval_at, last_value,
         last_notified_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
     ON CONFLICT(rule_id, agent_id, series_key) DO UPDATE SET
        state = excluded.state,
        since = excluded.since,
        last_eval_at = excluded.last_eval_at,
        last_value = excluded.last_value,
        last_notified_at = excluded.last_notified_at";

/// B2 `notify_error` 的存储上限（字节）；B2 的错误信息也只能是脱敏后的摘要。
const MAX_ALERT_NOTIFY_ERROR_BYTES: usize = 512;

/// 告警评估用的 raw-only 最新序列快照。
///
/// 只包含 `samples` 原始表：**绝不回退** 1m / 1h 聚合桶。旧桶里的 `last_value`
/// 可能是几分钟甚至几小时前的值，把它当成“当前值”会导致告警误触发 / 误恢复。
#[derive(Debug, Clone, PartialEq)]
pub struct AlertSeriesSnapshot {
    /// 每个 `(agent_id, labels)` 的最新 raw 样本；按 `(agent_id, labels)` 排序。
    pub rows: Vec<AgentSeriesRow>,
    /// 是否因为达到上限而截断了序列；`true` 时 `rows` 只包含前 limit 条。
    pub truncated: bool,
}

/// 每规则状态硬上限的 SQL：保留最近 `keep` 条（非 resolved 优先，其次更新）。
const ALERT_STATE_PRUNE_FOR_RULE_SQL: &str = "DELETE FROM alert_states
     WHERE rule_id = ?1 AND rowid NOT IN (
         SELECT rowid FROM alert_states WHERE rule_id = ?1
         ORDER BY (state = 'resolved') ASC, last_eval_at DESC, rowid DESC LIMIT ?2
     )";

/// 构造 `latest_alert_series` 的 SQL；`has_agent` 只影响占位符数量。
///
/// 单独抽出来是为了 EXPLAIN QUERY PLAN 测试能断言走 `(metric, ts)` 索引。
fn latest_alert_series_sql(has_agent: bool) -> String {
    // 索引名来自固定分支；`INDEXED BY` 保证无统计信息时也走预期索引，避免
    // 优化器误选 `idx_samples_ts` 后逐行过滤 metric（全窗口扫描）。
    let index = if has_agent {
        "idx_samples_lookup"
    } else {
        "idx_samples_metric_ts"
    };
    let mut sql = format!(
        "SELECT agent_id, metric, labels, ts, value FROM (
             SELECT agent_id, metric, labels, ts, value,
                    ROW_NUMBER() OVER (
                        PARTITION BY agent_id, labels ORDER BY ts DESC, rowid DESC
                    ) AS rn
             FROM samples INDEXED BY {index}
             WHERE metric = ?1 AND ts >= ?2"
    );
    if has_agent {
        sql.push_str(" AND agent_id = ?");
    }
    sql.push_str(") WHERE rn = 1 ORDER BY agent_id ASC, labels ASC LIMIT ?");
    sql
}

/// 在既有事务内插入事件、upsert 状态；事件先于状态。
fn insert_alert_transitions(
    tx: &Transaction<'_>,
    events: &[AlertEvent],
    states: &[AlertState],
) -> Result<()> {
    {
        let mut insert = tx.prepare(ALERT_EVENT_INSERT_SQL)?;
        for event in events {
            insert.execute(params![
                event.ts,
                event.rule_id,
                event.rule_name,
                event.agent_id,
                event.series_key,
                event.state.as_str(),
                event.value,
                event.message,
                event.notified as i64,
                event.notify_error,
                event.silenced as i64,
            ])?;
        }
    }
    {
        let mut upsert = tx.prepare(ALERT_STATE_UPSERT_SQL)?;
        for state in states {
            upsert.execute(params![
                state.rule_id,
                state.agent_id,
                state.series_key,
                state.state.as_str(),
                state.since,
                state.last_eval_at,
                state.last_value,
                state.last_notified_at,
            ])?;
        }
    }
    Ok(())
}

/// 在既有事务内做每规则状态裁剪，返回删除行数。
fn prune_alert_states_for_rule_in_tx(
    tx: &Transaction<'_>,
    rule_id: &str,
    keep: usize,
) -> rusqlite::Result<usize> {
    tx.execute(
        ALERT_STATE_PRUNE_FOR_RULE_SQL,
        params![rule_id, i64::try_from(keep).unwrap_or(i64::MAX)],
    )
}

/// 数据库里出现未知枚举值时产生的错误（不静默降级成默认值）。
#[derive(Debug)]
struct AlertTableColumnError {
    table: &'static str,
    field: &'static str,
}

impl std::fmt::Display for AlertTableColumnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{} 字段值非法", self.table, self.field)
    }
}

impl std::error::Error for AlertTableColumnError {}

/// 把告警表的列值损坏翻译成 rusqlite 错误，让上层拿到明确失败。
fn alert_table_column_error(
    table: &'static str,
    field: &'static str,
    column: usize,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        Box::new(AlertTableColumnError { table, field }),
    )
}

/// 一行 `alert_states` 映射成 [`AlertState`]。
fn alert_state_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertState> {
    let state: String = row.get(3)?;
    Ok(AlertState {
        rule_id: row.get(0)?,
        agent_id: row.get(1)?,
        series_key: row.get(2)?,
        state: AlertStateKind::parse(&state)
            .ok_or_else(|| alert_table_column_error("alert_states", "state", 3))?,
        since: row.get(4)?,
        last_eval_at: row.get(5)?,
        last_value: row.get(6)?,
        last_notified_at: row.get(7)?,
    })
}

/// 一行 `alert_events` 映射成 [`AlertEvent`]；`state` 只允许 firing / resolved。
fn alert_event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertEvent> {
    let state: String = row.get(6)?;
    let state = AlertStateKind::parse(&state)
        .filter(|state| state.is_event())
        .ok_or_else(|| alert_table_column_error("alert_events", "state", 6))?;
    let notified: i64 = row.get(9)?;
    let silenced: i64 = row.get(11)?;
    Ok(AlertEvent {
        id: row.get(0)?,
        ts: row.get(1)?,
        rule_id: row.get(2)?,
        rule_name: row.get(3)?,
        agent_id: row.get(4)?,
        series_key: row.get(5)?,
        state,
        value: row.get(7)?,
        message: row.get(8)?,
        notified: notified != 0,
        notify_error: row.get(10)?,
        silenced: silenced != 0,
    })
}

/// 一行 `alert_silences` 映射成 [`AlertSilence`]。
fn alert_silence_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertSilence> {
    Ok(AlertSilence {
        id: row.get(0)?,
        rule_id: row.get(1)?,
        agent_id: row.get(2)?,
        until_ts: row.get(3)?,
        created_by: row.get(4)?,
        created_at: row.get(5)?,
    })
}

impl SqliteStorage {
    /// 列出全部告警状态，按 `(rule_id, agent_id, series_key)` 稳定排序。
    pub fn list_alert_states(&self) -> Result<Vec<AlertState>> {
        let conn = self.lock_read();
        let sql = format!(
            "SELECT {ALERT_STATE_COLUMNS} FROM alert_states \
             ORDER BY rule_id ASC, agent_id ASC, series_key ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], alert_state_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 按主键读取一条告警状态；不存在返回 `None`。
    pub fn get_alert_state(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
    ) -> Result<Option<AlertState>> {
        let sql = format!(
            "SELECT {ALERT_STATE_COLUMNS} FROM alert_states \
             WHERE rule_id = ?1 AND agent_id = ?2 AND series_key = ?3"
        );
        Ok(self
            .lock_read()
            .query_row(
                &sql,
                params![rule_id, agent_id, series_key],
                alert_state_from_row,
            )
            .optional()?)
    }

    /// 插入或整行更新一条告警状态（主键冲突时覆盖状态、时间与值）。
    pub fn upsert_alert_state(&self, state: &AlertState) -> Result<()> {
        self.lock_write().execute(
            ALERT_STATE_UPSERT_SQL,
            params![
                state.rule_id,
                state.agent_id,
                state.series_key,
                state.state.as_str(),
                state.since,
                state.last_eval_at,
                state.last_value,
                state.last_notified_at,
            ],
        )?;
        Ok(())
    }

    /// 删除一条告警状态，返回受影响行数（0 = 本来不存在）。
    pub fn delete_alert_state(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
    ) -> Result<usize> {
        Ok(self.lock_write().execute(
            "DELETE FROM alert_states WHERE rule_id = ?1 AND agent_id = ?2 AND series_key = ?3",
            params![rule_id, agent_id, series_key],
        )?)
    }

    /// 清理 `resolved` 状态：只删 `state = 'resolved'` 且 `last_eval_at < resolved_before`
    /// 的行，返回删除行数。
    ///
    /// pending / firing 无论多旧都不删：它们代表仍然存在的告警，删除会导致下一次
    /// 评估重复产生 firing 事件。
    pub fn prune_alert_states(&self, resolved_before: i64) -> Result<usize> {
        Ok(self.lock_write().execute(
            "DELETE FROM alert_states WHERE state = 'resolved' AND last_eval_at < ?1",
            params![resolved_before],
        )?)
    }

    /// 清理**陈旧**的 pending / firing 状态，返回删除行数。
    ///
    /// series 消失、agent 被删除、规则被禁用但未走 API 清理时，状态不会再被
    /// 评估推进；`last_eval_at` 会一直停在旧值。保留期（引擎当前用 30 天）之后
    /// 删除，防止 `alert_states` 无界增长。`max_rows` 限制单次删除量，避免一次
    /// 清理长时间占住写锁；未删完的部分下一轮继续。
    ///
    /// resolved 状态由 [`Self::prune_alert_states`] 负责，不在这里重复处理。
    pub fn prune_stale_alert_states(&self, stale_before: i64, max_rows: usize) -> Result<usize> {
        if max_rows == 0 {
            return Ok(0);
        }
        Ok(self.lock_write().execute(
            "DELETE FROM alert_states WHERE rowid IN \
             (SELECT rowid FROM alert_states \
              WHERE state IN ('pending','firing') AND last_eval_at < ?1 \
              ORDER BY state ASC, last_eval_at ASC LIMIT ?2)",
            params![stale_before, i64::try_from(max_rows).unwrap_or(i64::MAX)],
        )?)
    }

    /// 插入一条告警事件，返回自增 id。
    ///
    /// `event.id` 被忽略：主键始终由 SQLite 生成。
    pub fn insert_alert_event(&self, event: &AlertEvent) -> Result<i64> {
        let conn = self.lock_write();
        conn.execute(
            ALERT_EVENT_INSERT_SQL,
            params![
                event.ts,
                event.rule_id,
                event.rule_name,
                event.agent_id,
                event.series_key,
                event.state.as_str(),
                event.value,
                event.message,
                event.notified as i64,
                event.notify_error,
                event.silenced as i64,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// 按 id 倒序（最新在前）分页列出事件；`before_id` 是排他游标。
    ///
    /// `limit == 0` 返回空列表，避免上层把 0 当成「无限制」。
    pub fn list_alert_events(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<AlertEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut sql = format!("SELECT {ALERT_EVENT_COLUMNS} FROM alert_events");
        let mut values: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(before_id) = before_id {
            sql.push_str(" WHERE id < ?");
            values.push(rusqlite::types::Value::Integer(before_id));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        values.push(rusqlite::types::Value::Integer(
            i64::try_from(limit).unwrap_or(i64::MAX),
        ));

        let conn = self.lock_read();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(values), alert_event_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 清理告警事件：先按时间删 `ts < before_ts`，再按 id 从旧到新删到只剩 `max_rows` 行。
    ///
    /// `max_rows == 0` 表示清空全部事件。两步在同一个写事务内完成，返回删除总数。
    pub fn prune_alert_events(&self, before_ts: i64, max_rows: usize) -> Result<usize> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut removed =
            tx.execute("DELETE FROM alert_events WHERE ts < ?1", params![before_ts])?;
        let remaining: i64 =
            tx.query_row("SELECT COUNT(*) FROM alert_events", [], |row| row.get(0))?;
        let max_rows = i64::try_from(max_rows).unwrap_or(i64::MAX);
        if remaining > max_rows {
            let excess = remaining - max_rows;
            removed += tx.execute(
                "DELETE FROM alert_events WHERE id IN \
                 (SELECT id FROM alert_events ORDER BY id ASC LIMIT ?1)",
                params![excess],
            )?;
        }
        tx.commit()?;
        Ok(removed)
    }

    /// 创建一条静默，返回自增 id；`silence.id` 被忽略。
    ///
    /// 同一事务内检查生效中数量：达到 [`MAX_ALERT_SILENCES`] 返回
    /// [`AlertSilenceStoreError::LimitReached`]（API 映射 409 `silence_limit`）。
    /// 生效判定以 `silence.created_at` 为 now：`until_ts > created_at`。
    pub fn create_alert_silence(&self, silence: &AlertSilence) -> Result<i64> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: i64 = tx.query_row(
            "SELECT COUNT(*) FROM alert_silences WHERE until_ts > ?1",
            params![silence.created_at],
            |row| row.get(0),
        )?;
        if active >= MAX_ALERT_SILENCES as i64 {
            return Err(AlertSilenceStoreError::LimitReached.into());
        }
        tx.execute(
            "INSERT INTO alert_silences (rule_id, agent_id, until_ts, created_by, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                silence.rule_id,
                silence.agent_id,
                silence.until_ts,
                silence.created_by,
                silence.created_at,
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// 列出 `now` 时刻仍生效的静默（`until_ts > now`），最新创建的在前。
    pub fn list_active_silences(&self, now: i64) -> Result<Vec<AlertSilence>> {
        let sql = format!(
            "SELECT {ALERT_SILENCE_COLUMNS} FROM alert_silences \
             WHERE until_ts > ?1 ORDER BY id DESC"
        );
        let conn = self.lock_read();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![now], alert_silence_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 删除一条静默，返回 `false` 表示 id 不存在（API 映射 404）。
    pub fn delete_alert_silence(&self, id: i64) -> Result<bool> {
        let removed = self
            .lock_write()
            .execute("DELETE FROM alert_silences WHERE id = ?1", params![id])?;
        Ok(removed > 0)
    }

    /// 清理到期静默（`until_ts <= before_ts`），返回删除行数。
    pub fn prune_alert_silences(&self, before_ts: i64) -> Result<usize> {
        Ok(self.lock_write().execute(
            "DELETE FROM alert_silences WHERE until_ts <= ?1",
            params![before_ts],
        )?)
    }

    /// 列出启用的规则（评估引擎使用）；排序与 [`Self::list_alert_rules`] 一致。
    pub fn list_enabled_alert_rules(&self) -> Result<Vec<AlertRule>> {
        let conn = self.lock_read();
        let sql = format!(
            "SELECT {ALERT_RULE_COLUMNS} FROM alert_rules WHERE enabled != 0 \
             ORDER BY is_builtin DESC, name ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], alert_rule_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 列出指定规则最近更新的 `limit` 条状态（引擎每轮只读一次）。
    ///
    /// 按 `last_eval_at DESC, rowid DESC` 排序并强制 `LIMIT`：即使规则积累了大量
    /// 历史状态（label churn / series 消失），单轮加载内存也不会无界增长。调用方
    /// 应在返回条数达到上限时配合 [`Self::prune_alert_states_for_rule`] 淘汰旧行。
    /// `limit == 0` 返回空列表。
    pub fn list_alert_states_for_rule(
        &self,
        rule_id: &str,
        limit: usize,
    ) -> Result<Vec<AlertState>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {ALERT_STATE_COLUMNS} FROM alert_states WHERE rule_id = ?1 \
             ORDER BY last_eval_at DESC, rowid DESC LIMIT ?2"
        );
        let conn = self.lock_read();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![rule_id, i64::try_from(limit).unwrap_or(i64::MAX)],
            alert_state_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 每规则状态硬上限清理：只保留最近 `keep` 条，返回删除行数。
    ///
    /// 保留优先级：非 resolved 优先于 resolved（避免把仍在告警的 Pending/Firing
    /// 先删掉），同类按 `last_eval_at` 新→旧；相同时间按 rowid 新→旧。`keep == 0`
    /// 清空该规则全部状态。
    pub fn prune_alert_states_for_rule(&self, rule_id: &str, keep: usize) -> Result<usize> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let removed = prune_alert_states_for_rule_in_tx(&tx, rule_id, keep)?;
        tx.commit()?;
        Ok(removed)
    }

    /// 告警评估专用的 **raw-only** 最新序列查询。
    ///
    /// 语义：
    /// - 只查 `samples` 原始表，**不回退** 1m / 1h（旧桶不能当当前值）；
    /// - 只取 `ts >= since` 的样本；
    /// - 每个 `(agent_id, labels)` 取 `ts` 最大的一行，同 `ts` 取 `rowid` 最大；
    /// - `agent` 为 `Some` 时只查该 agent；
    /// - SQL 侧向数据库要 `limit + 1` 行：拿到 `limit + 1` 条就说明还有更多序列，
    ///   返回前 `limit` 条并置 `truncated = true`，**不返回 QueryTooLarge**。
    ///
    /// 注意：labels 过滤由引擎在返回后完成，因此截断发生在过滤之前。某一 metric
    /// 的序列基数远超上限时，即使规则带较窄的 `filter_labels` 也可能漏评估；
    /// 应优先用 `filter_agent_id` 收窄，或拆分 metric。
    ///
    /// `limit == 0` 返回空快照且 `truncated = true`（有数据也不返回）。
    pub fn latest_alert_series(
        &self,
        metric: &str,
        since: i64,
        agent: Option<&str>,
        limit: usize,
    ) -> Result<AlertSeriesSnapshot> {
        if limit == 0 {
            return Ok(AlertSeriesSnapshot {
                rows: Vec::new(),
                truncated: true,
            });
        }
        let conn = self.lock_read();
        let sql = latest_alert_series_sql(agent.is_some());
        let mut params: Vec<rusqlite::types::Value> = vec![
            rusqlite::types::Value::Text(metric.to_string()),
            rusqlite::types::Value::Integer(since),
        ];
        if let Some(agent_id) = agent {
            params.push(rusqlite::types::Value::Text(agent_id.to_string()));
        }
        // 多取一条用于判断是否被截断；溢出时退回 usize::MAX 会被 SQLite 当成
        // 极大值处理，实际不可能有那么多序列。
        let sql_limit = limit.saturating_add(1);
        params.push(rusqlite::types::Value::Integer(
            i64::try_from(sql_limit).unwrap_or(i64::MAX),
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
        let mut rows: Vec<AgentSeriesRow> = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        let truncated = rows.len() > limit;
        if truncated {
            rows.truncate(limit);
        }
        Ok(AlertSeriesSnapshot { rows, truncated })
    }

    /// 单事务批量落库一条规则产生的全部事件与状态。
    ///
    /// - **事件先插入、状态后 upsert**：状态写失败时整事务回滚，下一轮重试；
    ///   不会出现「状态已推进、事件却没落库」的永久丢告警（at-least-once）；
    /// - 一条规则只抢一次写锁，避免上千序列逐条 `insert + upsert` 阻塞 ingest。
    pub fn apply_alert_transitions(
        &self,
        events: &[AlertEvent],
        states: &[AlertState],
    ) -> Result<()> {
        if events.is_empty() && states.is_empty() {
            return Ok(());
        }
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_alert_transitions(&tx, events, states)?;
        tx.commit()?;
        Ok(())
    }

    /// 引擎单规则落库：事件 + 状态 + **规则状态硬上限**在同一事务内完成。
    ///
    /// `keep_states` 是写完后该规则最多保留的状态数；超出部分（优先 resolved，
    /// 其次更旧）当场删除。这样即使每轮大量新 series 持续 churn，状态表也不会
    /// 无限增长，下一次加载仍 ≤ `MAX_ALERT_STATES_PER_RULE`。
    /// 返回本事务淘汰的状态行数。
    pub fn apply_alert_evaluation(
        &self,
        rule_id: &str,
        events: &[AlertEvent],
        states: &[AlertState],
        keep_states: usize,
    ) -> Result<usize> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        insert_alert_transitions(&tx, events, states)?;
        let removed = prune_alert_states_for_rule_in_tx(&tx, rule_id, keep_states)?;
        tx.commit()?;
        Ok(removed)
    }

    /// 当前最大告警事件 id；没有事件时返回 0。
    ///
    /// B2 通知 worker 首次启动用它建立「上线水位」，避免把 B1b 阶段积压的历史
    /// 事件全部补发出去。
    pub fn max_alert_event_id(&self) -> Result<i64> {
        Ok(self.lock_read().query_row(
            "SELECT COALESCE(MAX(id), 0) FROM alert_events",
            [],
            |row| row.get(0),
        )?)
    }

    /// B2 通知队列：只取 `id > after_id` 且未通知、未静默的事件。
    ///
    /// 与 [`Self::list_pending_notification_events`] 的区别是带**持久化游标**：
    /// worker 只处理首次上线之后的新事件，崩溃重启后从 `maintenance_state` 的
    /// 水位继续，不会重放历史事件。`after_id` 由调用方保证非负。
    pub fn list_pending_notification_events_after(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<AlertEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {ALERT_EVENT_COLUMNS} FROM alert_events \
             WHERE id > ?1 AND notified = 0 AND silenced = 0 ORDER BY id ASC LIMIT ?2"
        );
        let conn = self.lock_read();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![after_id, i64::try_from(limit).unwrap_or(i64::MAX)],
            alert_event_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// B2：把事件标记为「已处理」并保留固定原因（`no_channel` / `cooldown` 等）。
    ///
    /// [`Self::mark_notification_result`] 在 `notified = true` 时会清空错误（那是
    /// 「发送成功」的语义），但通知 worker 需要对**跳过或全部失败**的事件同时写入
    /// `notified = 1`（不再重试）与固定原因。原因由调用方保证已脱敏，存储层再做
    /// 一次 UTF-8 字节截断。返回 `false` 表示事件 id 不存在。
    pub fn mark_notification_processed(&self, id: i64, notify_error: &str) -> Result<bool> {
        let stored_error = truncate_utf8(notify_error, MAX_ALERT_NOTIFY_ERROR_BYTES);
        let updated = self.lock_write().execute(
            "UPDATE alert_events SET notified = 1, notify_error = ?2 WHERE id = ?1",
            params![id, stored_error],
        )?;
        Ok(updated > 0)
    }

    /// B2 通知队列：取未通知且未静默的事件，按 id 升序（先发生先发）。
    ///
    /// **silenced 事件永不返回**：静默只影响通知，事件本身仍保留给面板。
    ///
    /// 重要（B2 首次上线）：B1b 阶段所有事件都是 `notified = 0`，历史事件也在
    /// 其中。B2 的通知 worker 第一次启动时必须自己带一个「上线时间」水位（只取
    /// `ts >= worker_started_at` 的事件），或先把历史事件批量标记为已处理；
    /// 直接调用本方法会把积压的历史事件全部投递出去。
    pub fn list_pending_notification_events(&self, limit: usize) -> Result<Vec<AlertEvent>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {ALERT_EVENT_COLUMNS} FROM alert_events \
             WHERE notified = 0 AND silenced = 0 ORDER BY id ASC LIMIT ?1"
        );
        let conn = self.lock_read();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![i64::try_from(limit).unwrap_or(i64::MAX)],
            alert_event_from_row,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 记录一次通知结果（B2 使用）。
    ///
    /// 成功时 `notified = true` 且清空 `notify_error`；失败保留错误摘要（最多
    /// [`MAX_ALERT_NOTIFY_ERROR_BYTES`] 字节，B2 负责脱敏）。返回 `false` 表示
    /// 事件 id 不存在。
    pub fn mark_notification_result(
        &self,
        id: i64,
        notified: bool,
        notify_error: &str,
    ) -> Result<bool> {
        let stored_error = if notified {
            String::new()
        } else {
            truncate_utf8(notify_error, MAX_ALERT_NOTIFY_ERROR_BYTES)
        };
        let updated = self.lock_write().execute(
            "UPDATE alert_events SET notified = ?2, notify_error = ?3 WHERE id = ?1",
            params![id, notified as i64, stored_error],
        )?;
        Ok(updated > 0)
    }

    /// 只更新状态的 `last_notified_at`（B2 使用），不整行覆盖。
    ///
    /// 引擎可能正在并发推进同一行；独立 UPDATE 只改通知时间，避免把状态机刚写入
    /// 的 `state` / `since` / `last_value` 用旧快照盖回去。返回 `false` 表示状态
    /// 已被清理（规则禁用 / 删除或保留期清理）。
    pub fn update_alert_state_notified(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
        last_notified_at: i64,
    ) -> Result<bool> {
        let updated = self.lock_write().execute(
            "UPDATE alert_states SET last_notified_at = ?4 \
             WHERE rule_id = ?1 AND agent_id = ?2 AND series_key = ?3",
            params![rule_id, agent_id, series_key, last_notified_at],
        )?;
        Ok(updated > 0)
    }
}

// ---------------------------------------------------------------------------
// M4-B2b：通知渠道（schema v7 `notification_channels` 表）
// ---------------------------------------------------------------------------

/// `notification_channels` 的 SELECT 列表；列顺序与 [`notification_channel_from_row`]
/// 一一对应。
const NOTIFICATION_CHANNEL_COLUMNS: &str =
    "id, name, kind, config_json, enabled, updated_by, created_at, updated_at";

/// 通知渠道存储的领域错误；hub 映射成固定 HTTP 错误码。
///
/// 不携带名称 / id / 配置等用户输入，避免错误信息回显到响应或日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStoreError {
    /// 渠道不存在（404）。
    NotFound,
    /// 渠道名称重复（409 `channel_name_exists`）。
    NameExists,
    /// 渠道总数达到 [`MAX_NOTIFICATION_CHANNELS`]（409 `channel_limit`）。
    LimitReached,
    /// 渠道仍被 `alert_rules.channel_ids` 引用（409 `channel_in_use`）。
    InUse,
    /// 渠道配置 / 类型不合法（400）；消息是固定的中文原因。
    Invalid(&'static str),
}

impl std::fmt::Display for ChannelStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "通知渠道不存在"),
            Self::NameExists => write!(f, "通知渠道名称已存在"),
            Self::LimitReached => write!(f, "通知渠道数量已达上限 {MAX_NOTIFICATION_CHANNELS} 条"),
            Self::InUse => write!(f, "通知渠道仍被告警规则引用"),
            Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for ChannelStoreError {}

/// 数据库里出现未知渠道类型 / 配置 JSON 损坏时产生的错误（不静默降级）。
#[derive(Debug)]
struct NotificationChannelColumnError(&'static str);

impl std::fmt::Display for NotificationChannelColumnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "notification_channels.{} 字段值非法", self.0)
    }
}

impl std::error::Error for NotificationChannelColumnError {}

fn notification_channel_column_error(column: usize, field: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        Box::new(NotificationChannelColumnError(field)),
    )
}

/// 一行 `notification_channels` 映射成 [`NotificationChannel`]。
///
/// `kind` 列与 `config_json.kind` 必须一致；任何一侧非法都返回明确错误，
/// 不把损坏的行静默降级成默认渠道。
fn notification_channel_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationChannel> {
    let kind_raw: String = row.get(2)?;
    let kind = ChannelKind::parse(&kind_raw)
        .ok_or_else(|| notification_channel_column_error(2, "kind"))?;
    let config_json: String = row.get(3)?;
    let config: ChannelConfig = serde_json::from_str(&config_json)
        .map_err(|_| notification_channel_column_error(3, "config_json"))?;
    if config.kind() != kind {
        return Err(notification_channel_column_error(2, "kind"));
    }
    let enabled: i64 = row.get(4)?;
    Ok(NotificationChannel {
        id: row.get(0)?,
        name: row.get(1)?,
        kind,
        config,
        enabled: enabled != 0,
        updated_by: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

/// 把 `notification_channels.name` 的唯一约束冲突翻译成领域错误，不透传 SQL。
fn map_notification_channel_unique_error(err: rusqlite::Error) -> anyhow::Error {
    if let rusqlite::Error::SqliteFailure(inner, Some(message)) = &err {
        if inner.code == rusqlite::ErrorCode::ConstraintViolation
            && message.contains("notification_channels.name")
        {
            return ChannelStoreError::NameExists.into();
        }
    }
    tracing::debug!(error = %err, "写入通知渠道失败（非名称唯一约束错误）");
    anyhow::anyhow!("写入通知渠道失败（数据库错误，详见日志）")
}

/// 校验渠道可在存储层落库；错误固定为中文，不回显配置原文。
fn validate_channel_for_store(channel: &NotificationChannel) -> Result<()> {
    channel
        .validate()
        .map_err(|_| ChannelStoreError::Invalid("通知渠道配置不合法"))?;
    Ok(())
}

impl SqliteStorage {
    /// 列出全部通知渠道，按名称升序（名称 UNIQUE，顺序稳定）。
    ///
    /// 返回完整 [`NotificationChannel`]（含 secret），只允许 hub 内部使用；
    /// API 响应必须走 `ChannelView`。
    pub fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>> {
        let conn = self.lock_read();
        let sql = format!(
            "SELECT {NOTIFICATION_CHANNEL_COLUMNS} FROM notification_channels ORDER BY name ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], notification_channel_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 按 id 读取一条渠道；不存在返回 `None`。
    pub fn get_notification_channel(&self, id: &str) -> Result<Option<NotificationChannel>> {
        let sql = format!(
            "SELECT {NOTIFICATION_CHANNEL_COLUMNS} FROM notification_channels WHERE id = ?1"
        );
        let conn = self.lock_read();
        Ok(conn
            .query_row(&sql, params![id], notification_channel_from_row)
            .optional()?)
    }

    /// 渠道总数（供上限检查与面板统计）。
    pub fn notification_channel_count(&self) -> Result<usize> {
        let count: i64 = self.lock_read().query_row(
            "SELECT COUNT(*) FROM notification_channels",
            [],
            |row| row.get(0),
        )?;
        Ok(usize::try_from(count).unwrap_or(0))
    }

    /// 新建一条渠道。
    ///
    /// 事务内先查总数与名称，再写入；并发下仍由 `name UNIQUE` 兜底：
    /// - 达到 [`MAX_NOTIFICATION_CHANNELS`] → [`ChannelStoreError::LimitReached`]；
    /// - 名称重复 → [`ChannelStoreError::NameExists`]；
    /// - `kind` 与 `config.kind` 不一致或字段非法 → [`ChannelStoreError::Invalid`]。
    pub fn create_notification_channel(&self, channel: &NotificationChannel) -> Result<()> {
        validate_channel_for_store(channel)?;
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT COUNT(*) FROM notification_channels", [], |row| {
            row.get(0)
        })?;
        if count >= MAX_NOTIFICATION_CHANNELS as i64 {
            return Err(ChannelStoreError::LimitReached.into());
        }
        let name_exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM notification_channels WHERE name = ?1",
                params![channel.name],
                |row| row.get(0),
            )
            .optional()?;
        if name_exists.is_some() {
            return Err(ChannelStoreError::NameExists.into());
        }
        let config_json = serde_json::to_string(&channel.config)?;
        tx.execute(
            "INSERT INTO notification_channels \
             (id, name, kind, config_json, enabled, updated_by, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                channel.id,
                channel.name,
                channel.kind.as_str(),
                config_json,
                channel.enabled as i64,
                channel.updated_by,
                channel.created_at,
                channel.updated_at,
            ],
        )
        .map_err(map_notification_channel_unique_error)?;
        tx.commit()?;
        Ok(())
    }

    /// 更新一条渠道的可写字段。
    ///
    /// - `id` 是定位键，`created_at` 保持数据库原值；
    /// - 不存在 → [`ChannelStoreError::NotFound`]；
    /// - 改成与其它渠道重名 → [`ChannelStoreError::NameExists`]；
    /// - `kind` / `config.kind` 不一致或配置非法 → [`ChannelStoreError::Invalid`]。
    ///
    /// secret 保留语义由调用方用 `ChannelConfigInput::resolve` 完成，存储层只
    /// 接收合并后的完整配置。
    pub fn update_notification_channel(&self, channel: &NotificationChannel) -> Result<()> {
        validate_channel_for_store(channel)?;
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM notification_channels WHERE id = ?1",
                params![channel.id],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ChannelStoreError::NotFound.into());
        }
        let name_exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM notification_channels WHERE name = ?1 AND id != ?2",
                params![channel.name, channel.id],
                |row| row.get(0),
            )
            .optional()?;
        if name_exists.is_some() {
            return Err(ChannelStoreError::NameExists.into());
        }
        let config_json = serde_json::to_string(&channel.config)?;
        tx.execute(
            "UPDATE notification_channels SET name = ?2, kind = ?3, config_json = ?4, \
             enabled = ?5, updated_by = ?6, updated_at = ?7 WHERE id = ?1",
            params![
                channel.id,
                channel.name,
                channel.kind.as_str(),
                config_json,
                channel.enabled as i64,
                channel.updated_by,
                channel.updated_at,
            ],
        )
        .map_err(map_notification_channel_unique_error)?;
        tx.commit()?;
        Ok(())
    }

    /// 删除一条渠道；仍被 `alert_rules.channel_ids` 引用时返回
    /// [`ChannelStoreError::InUse`]，绝不留下悬空引用。
    ///
    /// 引用检查与 DELETE 在同一个 `IMMEDIATE` 事务内完成，避免检查通过后另一
    /// 条规则写入引用造成竞态。`channel_ids` 是 JSON 数组，损坏时返回错误而不
    /// 是放行删除。
    pub fn delete_notification_channel(&self, id: &str) -> Result<()> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: Option<i64> = tx
            .query_row(
                "SELECT 1 FROM notification_channels WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        if exists.is_none() {
            return Err(ChannelStoreError::NotFound.into());
        }
        let references: Vec<(String, String)> = {
            let mut stmt = tx.prepare("SELECT id, channel_ids FROM alert_rules")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for (rule_id, channel_ids) in references {
            let ids: Vec<String> = serde_json::from_str(&channel_ids)
                .with_context(|| format!("告警规则 {rule_id} 的 channel_ids 损坏，拒绝删除渠道"))?;
            if ids.iter().any(|channel_id| channel_id == id) {
                return Err(ChannelStoreError::InUse.into());
            }
        }
        tx.execute(
            "DELETE FROM notification_channels WHERE id = ?1",
            params![id],
        )?;
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
    ///
    /// 每批删除都在同一 `BEGIN IMMEDIATE` 事务内收敛
    /// `downsample_1m_last_raw_rowid`，见 [`Self::prune_raw_batched`]。
    pub fn prune_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_raw_batched(PRUNE_RAW_SQL, cutoff)
    }

    /// v8 归档启用时的 raw 保留期：只删「已聚合且对象已 uploaded」的行。
    ///
    /// R1a-1 只提供原语，不改变现有 [`Self::prune_samples_before`] 的行为；
    /// R1b 在 `archive.enabled` 分支接入，并在 `archive_ledger_pending=1`
    /// 时直接跳过。未认领行、pending / failed 对象、未聚合行都不删。
    pub fn prune_archived_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_raw_batched(PRUNE_ARCHIVED_RAW_SQL, cutoff)
    }

    /// 分批删除 1m 中 `bucket_ts < cutoff` 的行。
    pub fn prune_samples_1m_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_batched(PRUNE_1M_SQL, cutoff)
    }

    /// 分批删除 1h 中 `bucket_ts < cutoff` 的行。
    pub fn prune_samples_1h_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_batched(PRUNE_1H_SQL, cutoff)
    }

    /// raw 专属分批删除：每批在一个显式 `BEGIN IMMEDIATE` 事务内完成
    /// 「读 `MAX(rowid)` → 删除 → 再读 `MAX(rowid)` → 收敛 rowid 水位 → commit」。
    ///
    /// 不复用 [`Self::prune_batched`]：后者无状态，做不到删除与降水位的原子性。
    /// 一旦删除的正是最大 rowid 行，下一批之前（或下一次 prune 调用之前）插入
    /// 的迟到行会复用该 rowid；若水位仍停在高位，这些行会被当成已认领而漏算。
    /// 因此不能等所有批次结束再更新水位。
    ///
    /// 批大小、提前退出条件与返回结构都和 1m / 1h 的 [`Self::prune_batched`]
    /// 保持一致；1m / 1h 的行为不受影响。
    fn prune_raw_batched(&self, sql: &'static str, cutoff: i64) -> Result<PruneResult> {
        let mut result = PruneResult::default();
        loop {
            let (deleted, change) = {
                let mut conn = self.lock_write();
                let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
                // DELETE 前后各读一次 MAX：只有删除前 = 删除后的批次才允许
                // 「只降不升」；最大 rowid 行被删时水位键必须失效并推进
                // generation（见 helper）。
                let max_before: Option<i64> =
                    tx.query_row("SELECT MAX(rowid) FROM samples", [], |row| row.get(0))?;
                let deleted = tx.execute(sql, params![cutoff, PRUNE_BATCH_ROWS as i64])?;
                let max_after: Option<i64> =
                    tx.query_row("SELECT MAX(rowid) FROM samples", [], |row| row.get(0))?;
                // 即使本批删除 0 行也收敛一次：可修复 v0.4.0 遗留的高水位，
                // 包括 raw 已空但 maintenance_state 仍残留水位键的情况。
                let change = lower_raw_rowid_watermark(&tx, max_before, max_after, now_ms())?;
                tx.commit()?;
                (deleted, change)
            };

            // 提交后再记日志：回滚时不会出现与实际状态不符的日志。
            if let Some(change) = change {
                match change.new {
                    Some(new) => tracing::info!(
                        old = change.old,
                        new,
                        "raw 保留期删除后下调 downsample_1m_last_raw_rowid"
                    ),
                    None => tracing::info!(
                        old = change.old,
                        "raw 保留期删除后清除 downsample_1m_last_raw_rowid"
                    ),
                }
            }

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

    /// CAS 认领 raw rowid 水位：rowid 与 generation 都等于期望时才写 `new_max`。
    ///
    /// downsample 先读 `MAX(rowid)`、稍后才写水位；两步之间 retention 可能
    /// 删除最大 rowid 行并降低/删除 rowid key。这里在同一个 `BEGIN IMMEDIATE`
    /// 事务内做「读当前 rowid + generation + 条件写」，任一不匹配都返回
    /// `false`，调用方本轮不认领，下一轮从更低位重扫。
    ///
    /// generation 缺失视为 0；当前 generation 非法时视为不匹配（不覆盖）。
    /// 即使 rowid key 恰好缺失，generation 变化也能让 CAS 失败。rowid
    /// `expected == None` 表示调用方读到 key 缺失，只有当前仍缺失才算匹配。
    pub fn claim_raw_rowid_if_unchanged(
        &self,
        expected_rowid: Option<i64>,
        expected_generation: i64,
        new_max: i64,
    ) -> Result<bool> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current_rowid: Option<String> = tx
            .query_row(
                "SELECT value FROM maintenance_state WHERE key = ?1",
                params![DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY],
                |row| row.get(0),
            )
            .optional()?;
        let current_generation: Option<String> = tx
            .query_row(
                "SELECT value FROM maintenance_state WHERE key = ?1",
                params![STATE_RAW_PRUNE_GENERATION],
                |row| row.get(0),
            )
            .optional()?;

        let rowid_matches = match expected_rowid {
            None => current_rowid.is_none(),
            Some(expected) => {
                current_rowid
                    .as_deref()
                    .and_then(|raw| raw.trim().parse::<i64>().ok())
                    == Some(expected)
            }
        };
        // 缺失 generation 视为 0；非法值解析失败，不匹配任何期望。
        let generation_matches = match current_generation.as_deref() {
            None => expected_generation == 0,
            Some(raw) => raw.trim().parse::<i64>().ok() == Some(expected_generation),
        };

        if !rowid_matches || !generation_matches {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO maintenance_state (key, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET
                 value = excluded.value,
                 updated_at = excluded.updated_at",
            params![
                DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY,
                new_max.to_string(),
                now_ms()
            ],
        )?;
        tx.commit()?;
        Ok(true)
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

// ---------------------------------------------------------------------------
// M4-C1：归档对象与归档水位（schema v7 的 archive_objects / archive_state）
// ---------------------------------------------------------------------------

/// `archive_objects` 的 SELECT 列表；列下标与 [`row_to_archive_object`] 一一对应。
const ARCHIVE_OBJECT_COLUMNS: &str = "id, backend, object_key, manifest_key, from_ts, to_ts, \
     rows, bytes, sha256, status, error, created_at, uploaded_at, deleted_at, ledger_version, \
     attempts";

/// 数据库里出现非法状态 / 负数行数时产生的错误（不静默降级成默认值）。
#[derive(Debug)]
struct ArchiveObjectColumnError(&'static str);

impl std::fmt::Display for ArchiveObjectColumnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "archive_objects.{} 字段值非法", self.0)
    }
}

impl std::error::Error for ArchiveObjectColumnError {}

/// 把损坏的列值翻译成 rusqlite 错误，让上层拿到明确失败而不是被默认值掩盖。
fn archive_object_column_error(column: usize, field: &'static str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Text,
        Box::new(ArchiveObjectColumnError(field)),
    )
}

/// 非负计数列必须能放进 `u64`；负数说明数据损坏，读取即失败。
fn archive_count_from_row(value: i64, column: usize, field: &'static str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| archive_object_column_error(column, field))
}

/// 一行待归档的 raw 采样；`rowid` 用于按升序分批扫描（见
/// [`SqliteStorage::scan_archive_rows`]）。
#[derive(Debug, Clone, PartialEq)]
pub struct ArchiveRawRow {
    /// `samples` 表的隐式 `rowid`，升序扫描的游标。
    pub rowid: i64,
    pub agent_id: String,
    pub metric: String,
    /// labels 的原始 JSON 文本（不做归一化，保持与 CSV 输出一致）。
    pub labels: String,
    pub ts: i64,
    pub value: f64,
}

/// 一行 `archive_objects` 映射成 [`ArchiveObject`]。
fn row_to_archive_object(row: &rusqlite::Row<'_>) -> rusqlite::Result<ArchiveObject> {
    let status: String = row.get(9)?;
    let rows: i64 = row.get(6)?;
    let bytes: i64 = row.get(7)?;
    Ok(ArchiveObject {
        id: row.get(0)?,
        backend: row.get(1)?,
        object_key: row.get(2)?,
        manifest_key: row.get(3)?,
        from_ts: row.get(4)?,
        to_ts: row.get(5)?,
        rows: archive_count_from_row(rows, 6, "rows")?,
        bytes: archive_count_from_row(bytes, 7, "bytes")?,
        sha256: row.get(8)?,
        status: ArchiveStatus::parse(&status)
            .ok_or_else(|| archive_object_column_error(9, "status"))?,
        error: row.get(10)?,
        created_at: row.get(11)?,
        uploaded_at: row.get(12)?,
        deleted_at: row.get(13)?,
        ledger_version: row.get(14)?,
        attempts: row.get(15)?,
    })
}

/// 把 `archive_objects.object_key` 的唯一约束冲突翻译成领域错误，不透传 SQL。
fn map_archive_object_unique_error(err: rusqlite::Error) -> anyhow::Error {
    if let rusqlite::Error::SqliteFailure(inner, Some(message)) = &err {
        if inner.code == rusqlite::ErrorCode::ConstraintViolation
            && message.contains("archive_objects.object_key")
        {
            return ArchiveStoreError::ObjectExists.into();
        }
    }
    tracing::debug!(error = %err, "写入归档对象失败（非 object_key 唯一约束错误）");
    anyhow::anyhow!("写入归档对象失败（数据库错误，详见日志）")
}

/// 在给定连接（或调用方已开启的事务）上插入一条归档对象，返回自增 id。
///
/// 单独抽成自由函数：claim 必须与对象插入处于同一事务，不能被
/// [`SqliteStorage::insert_archive_object`] 的隐式提交边界拆开。
fn insert_archive_object_on(conn: &Connection, object: &ArchiveObject) -> Result<i64> {
    let rows = i64::try_from(object.rows).context("归档对象行数超出 SQLite INTEGER 范围")?;
    let bytes = i64::try_from(object.bytes).context("归档对象字节数超出 SQLite INTEGER 范围")?;
    let result = conn.execute(
        "INSERT INTO archive_objects
            (backend, object_key, manifest_key, from_ts, to_ts, rows, bytes, sha256,
             status, error, created_at, uploaded_at, deleted_at, ledger_version, attempts)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            object.backend,
            object.object_key,
            object.manifest_key,
            object.from_ts,
            object.to_ts,
            rows,
            bytes,
            object.sha256,
            object.status.as_str(),
            object.error,
            object.created_at,
            object.uploaded_at,
            object.deleted_at,
            object.ledger_version,
            object.attempts,
        ],
    );
    match result {
        Ok(_) => Ok(conn.last_insert_rowid()),
        Err(err) => Err(map_archive_object_unique_error(err)),
    }
}

/// 校验元数据 SHA-256：64 位小写十六进制。
///
/// claim 事务允许 sha256 为空占位；只有 CSV 生成完成后的
/// `update_archive_object_metadata` 才要求真实摘要。
pub(crate) fn validate_archive_sha256(sha256: &str) -> Result<()> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        anyhow::bail!("归档对象 sha256 必须是 64 位小写十六进制");
    }
    Ok(())
}

/// 校验 claim 输入与行集完全一致；不合法直接拒绝，绝不部分认领。
///
/// 关键不变量：
/// - 空行集没有可下载对象，拒绝；
/// - 只接受 v8 claim 对象（`ledger_version=1`）且状态必须是 `pending`；
/// - `rows/from_ts/to_ts` 必须与行集逐项一致；
/// - 行键不得重复（否则 affected 行数永远小于选中数）；
/// - 行时间戳必须落在可归档范围（`0 ..= 9999-12-31`），超界行留给 R1b；
/// - `bytes` / `sha256` 允许是占位值：claim 只做短事务，CSV.GZ 在事务外生成，
///   之后用 `update_archive_object_metadata` 补真实摘要。
///
/// SQLite 用 `samples.rowid`、PG 用 `samples.id`，调用方不得自行拼接。
pub(crate) fn validate_archive_claim(object: &ArchiveObject, rows: &[ArchiveRawRow]) -> Result<()> {
    if rows.is_empty() {
        anyhow::bail!("归档 claim 行集不能为空");
    }
    if object.ledger_version != LEDGER_VERSION_V8 {
        anyhow::bail!(
            "归档 claim 对象的 ledger_version 必须为 {LEDGER_VERSION_V8}，实际为 {}",
            object.ledger_version
        );
    }
    if object.status != ArchiveStatus::Pending {
        anyhow::bail!(
            "归档 claim 对象状态必须为 pending，实际为 {}",
            object.status.as_str()
        );
    }
    let expected_rows = u64::try_from(rows.len()).context("归档 claim 行数超出 u64 范围")?;
    if object.rows != expected_rows {
        anyhow::bail!(
            "归档 claim 对象的 rows={} 与行集大小 {expected_rows} 不一致",
            object.rows
        );
    }

    let mut seen = std::collections::HashSet::with_capacity(rows.len());
    let mut min_ts = i64::MAX;
    let mut max_ts = i64::MIN;
    for row in rows {
        if !seen.insert(row.rowid) {
            anyhow::bail!("归档 claim 行集包含重复行键 {}", row.rowid);
        }
        if !(MIN_ARCHIVE_TS_MS..=MAX_ARCHIVE_TS_MS).contains(&row.ts) {
            anyhow::bail!(
                "归档 claim 行时间戳超出可归档范围 {}..={}",
                MIN_ARCHIVE_TS_MS,
                MAX_ARCHIVE_TS_MS
            );
        }
        min_ts = min_ts.min(row.ts);
        max_ts = max_ts.max(row.ts);
    }
    if object.from_ts != min_ts || object.to_ts != max_ts {
        anyhow::bail!(
            "归档 claim 对象的 from_ts/to_ts={}..={} 与行集 {}..={} 不一致",
            object.from_ts,
            object.to_ts,
            min_ts,
            max_ts
        );
    }
    Ok(())
}

impl SqliteStorage {
    /// 插入一条归档对象记录，返回数据库生成的自增 id。
    ///
    /// `object.id` 被忽略；`object_key` 有 UNIQUE 约束，重复插入返回
    /// [`ArchiveStoreError::ObjectExists`]，不会覆盖已有记录。
    pub fn insert_archive_object(&self, object: &ArchiveObject) -> Result<i64> {
        let conn = self.lock_write();
        insert_archive_object_on(&conn, object)
    }

    /// 按 id 读取归档对象；不存在返回 `None`。
    pub fn get_archive_object(&self, id: i64) -> Result<Option<ArchiveObject>> {
        let conn = self.lock_read();
        let sql = format!("SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects WHERE id = ?1");
        Ok(conn
            .query_row(&sql, params![id], row_to_archive_object)
            .optional()?)
    }

    /// 按 `object_key` 读取归档对象；不存在返回 `None`。
    ///
    /// 上传前先查这个 key 可以避免重复 PUT 同一对象（方案 §7.2）。
    pub fn find_archive_object_by_key(&self, object_key: &str) -> Result<Option<ArchiveObject>> {
        let conn = self.lock_read();
        let sql =
            format!("SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects WHERE object_key = ?1");
        Ok(conn
            .query_row(&sql, params![object_key], row_to_archive_object)
            .optional()?)
    }

    /// 按 id 倒序分页列出归档对象，最多 `limit` 条；`before_id` 用于翻页。
    ///
    /// `limit == 0` 返回空列表；`before_id` 是上一页最后一条的 id（排他）。
    pub fn list_archive_objects(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.lock_read();
        let sql = format!(
            "SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects \
             WHERE (?1 IS NULL OR id < ?1) ORDER BY id DESC LIMIT ?2"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![before_id, limit], row_to_archive_object)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 按 id 升序分页列出待重试的 v8 归档对象（`pending` / `failed`）。
    ///
    /// 只包含 `ledger_version = LEDGER_VERSION_V8` 的对象：v7 旧对象没有 claim
    /// 行集，不能按 `archive_rows_for_object` 重建。`after_id` 为上一页最后
    /// 一条的 id（排他）；`limit == 0` 返回空列表。
    pub fn list_retryable_archive_objects(
        &self,
        limit: usize,
        after_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.lock_read();
        let sql = format!(
            "SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects \
             WHERE ledger_version = ?1 AND status IN ('pending', 'failed') \
               AND (?2 IS NULL OR id > ?2) ORDER BY id ASC LIMIT ?3"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(
            params![LEDGER_VERSION_V8, after_id, limit],
            row_to_archive_object,
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 更新归档对象状态，并校验合法迁移。
    ///
    /// - 允许 `pending -> uploaded -> local_deleted`，以及 `pending` / `uploaded`
    ///   -> `failed`；`failed` 可重试回 `pending` 或直接 `uploaded`；
    /// - `local_deleted` 是终态，任何回退都返回
    ///   [`ArchiveStoreError::InvalidTransition`]；
    /// - `error` 按传入值覆盖（成功时调用方传空串）；
    /// - `uploaded_at` / `deleted_at` 为 `None` 时保留原值，局部更新不会清空
    ///   已有时间戳；
    /// - id 不存在返回 [`ArchiveStoreError::NotFound`]。
    pub fn update_archive_object_status(
        &self,
        id: i64,
        status: ArchiveStatus,
        error: &str,
        uploaded_at: Option<i64>,
        deleted_at: Option<i64>,
    ) -> Result<()> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<String> = tx
            .query_row(
                "SELECT status FROM archive_objects WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        let current = match current {
            Some(value) => ArchiveStatus::parse(&value)
                .ok_or_else(|| anyhow::anyhow!("archive_objects.status 字段值非法"))?,
            None => return Err(ArchiveStoreError::NotFound.into()),
        };
        if !current.can_transition_to(status) {
            return Err(ArchiveStoreError::InvalidTransition.into());
        }
        tx.execute(
            "UPDATE archive_objects SET status = ?2, error = ?3, \
             uploaded_at = COALESCE(?4, uploaded_at), \
             deleted_at = COALESCE(?5, deleted_at) WHERE id = ?1",
            params![id, status.as_str(), error, uploaded_at, deleted_at],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 记录一次上传失败：状态置 `failed`、覆盖 `error`，`attempts` 加一。
    ///
    /// 只允许 `pending` / `failed` 迁移到 `failed`；已 `uploaded` /
    /// `local_deleted` 的状态回退返回 [`ArchiveStoreError::InvalidTransition`]。
    /// id 不存在返回 [`ArchiveStoreError::NotFound`]。
    pub fn record_archive_object_failure(&self, id: i64, error: &str) -> Result<()> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<String> = tx
            .query_row(
                "SELECT status FROM archive_objects WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        let current = match current {
            Some(value) => ArchiveStatus::parse(&value)
                .ok_or_else(|| anyhow::anyhow!("archive_objects.status 字段值非法"))?,
            None => return Err(ArchiveStoreError::NotFound.into()),
        };
        if !matches!(current, ArchiveStatus::Pending | ArchiveStatus::Failed) {
            return Err(ArchiveStoreError::InvalidTransition.into());
        }
        tx.execute(
            "UPDATE archive_objects SET status = 'failed', error = ?2, \
             attempts = attempts + 1 WHERE id = ?1",
            params![id, error],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 读取归档水位；键不存在返回 `None`。
    pub fn get_archive_state(&self, key: &str) -> Result<Option<String>> {
        let conn = self.lock_read();
        Ok(conn
            .query_row(
                "SELECT value FROM archive_state WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// 写入 / 更新归档水位（UPSERT）；`updated_at` 由调用方提供。
    pub fn set_archive_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()> {
        self.lock_write().execute(
            "INSERT INTO archive_state (key, value, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET
                 value = excluded.value,
                 updated_at = excluded.updated_at",
            params![key, value, updated_at],
        )?;
        Ok(())
    }

    /// 列出时间范围与 `[from_ts, to_ts]` 有交集的归档对象。
    ///
    /// 交集判定为 `from_ts <= to_ts（查询上界）` 且 `to_ts >= from_ts（查询下界）`，
    /// 两端都包含；结果按 `from_ts, id` 升序，供下载 / 清理按对象顺序处理。
    pub fn list_archive_objects_in_range(
        &self,
        from_ts: i64,
        to_ts: i64,
    ) -> Result<Vec<ArchiveObject>> {
        let conn = self.lock_read();
        let sql = format!(
            "SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects \
             WHERE from_ts <= ?2 AND to_ts >= ?1 ORDER BY from_ts ASC, id ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params![from_ts, to_ts], row_to_archive_object)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 按 `rowid` 升序分批扫描 raw 采样，供归档 worker 生成 CSV.GZ。
    ///
    /// - 时间范围是左闭右开 `[from_ts, to_ts)`；
    /// - `after_rowid` 是上一批最后一条的 `rowid`（排他），`None` 表示从该
    ///   时间范围的第一条开始；
    /// - `limit == 0` 返回空列表；SQL 全部参数化，不接受外部拼接；
    /// - 返回顺序严格按 `rowid ASC`，调用方据此把连续行切成归档分片，并在
    ///   中断后从最后一条继续。
    pub fn scan_archive_rows(
        &self,
        from_ts: i64,
        to_ts: i64,
        after_rowid: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ArchiveRawRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.lock_read();
        let mut stmt = conn.prepare(
            "SELECT rowid, agent_id, metric, labels, ts, value FROM samples \
             WHERE ts >= ?1 AND ts < ?2 AND (?3 IS NULL OR rowid > ?3) \
             ORDER BY rowid ASC LIMIT ?4",
        )?;
        let rows = stmt.query_map(params![from_ts, to_ts, after_rowid, limit], |row| {
            Ok(ArchiveRawRow {
                rowid: row.get(0)?,
                agent_id: row.get(1)?,
                metric: row.get(2)?,
                labels: row.get(3)?,
                ts: row.get(4)?,
                value: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 按 `ts, rowid` 升序扫描尚未被任何归档对象认领的 raw 行。
    ///
    /// 归档 worker 的 claim 入口：只扫 `archive_object_id IS NULL`，时间范围
    /// 左闭右开 `[from_ts, to_ts)`；SQL 谓词与 `idx_samples_unarchived` 的
    /// partial index 一致，避免全表扫描。`limit == 0` 返回空列表。
    pub fn list_unclaimed_archive_rows(
        &self,
        from_ts: i64,
        to_ts: i64,
        limit: usize,
    ) -> Result<Vec<ArchiveRawRow>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let conn = self.lock_read();
        let mut stmt = conn.prepare(
            "SELECT rowid, agent_id, metric, labels, ts, value FROM samples \
             WHERE archive_object_id IS NULL AND ts >= ?1 AND ts < ?2 \
               AND ts >= ?4 AND ts <= ?5 \
             ORDER BY ts ASC, rowid ASC LIMIT ?3",
        )?;
        let now = now_ms().min(MAX_ARCHIVE_TS_MS);
        let rows = stmt.query_map(
            params![from_ts, to_ts, limit, MIN_ARCHIVE_TS_MS, now],
            |row| {
                Ok(ArchiveRawRow {
                    rowid: row.get(0)?,
                    agent_id: row.get(1)?,
                    metric: row.get(2)?,
                    labels: row.get(3)?,
                    ts: row.get(4)?,
                    value: row.get(5)?,
                })
            },
        )?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// 统计不可归档的 raw 行数（`ts < 0` 或 `ts > now`）。
    ///
    /// R1a-1 只提供计数原语，供 R1b 的 `maintenance status
    /// invalid_timestamp_rows` 与运维清理使用；不修改、不删除这些行。
    pub fn count_invalid_archive_raw_rows(&self) -> Result<i64> {
        let conn = self.lock_read();
        Ok(conn.query_row(
            "SELECT COUNT(*) FROM samples WHERE ts < ?1 OR ts > ?2",
            params![MIN_ARCHIVE_TS_MS, now_ms().min(MAX_ARCHIVE_TS_MS)],
            |row| row.get(0),
        )?)
    }

    /// 插入归档对象并原子认领 `rows` 的行集，返回新对象 id。
    ///
    /// 对象插入和 `archive_object_id` 更新在同一 `BEGIN IMMEDIATE` 事务内；
    /// `UPDATE ... AND archive_object_id IS NULL` 的 affected 行数必须等于
    /// 选中行数，否则整事务回滚并返回可重试的
    /// [`ArchiveStoreError::ClaimConflict`]。两个 worker 并发 claim 同一批行
    /// 时只有一个能提交。
    pub fn claim_archive_rows(
        &self,
        object: &ArchiveObject,
        rows: &[ArchiveRawRow],
    ) -> Result<i64> {
        validate_archive_claim(object, rows)?;
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let object_id = insert_archive_object_on(&tx, object)?;
        let mut claimed = 0usize;
        {
            // rowid 在 scan→claim 之间可能因删除最大行而被复用；必须同时比对
            // 行身份（agent/metric/labels/ts/value），否则会把新行误认领。
            let mut stmt = tx.prepare(
                "UPDATE samples SET archive_object_id = ?1 \
                 WHERE rowid = ?2 AND archive_object_id IS NULL \
                   AND agent_id = ?3 AND metric = ?4 AND labels = ?5 \
                   AND ts = ?6 AND value = ?7",
            )?;
            for row in rows {
                claimed += stmt.execute(params![
                    object_id,
                    row.rowid,
                    row.agent_id,
                    row.metric,
                    row.labels,
                    row.ts,
                    row.value,
                ])?;
            }
        }
        if claimed != rows.len() {
            tx.rollback()?;
            tracing::warn!(
                object_id,
                selected = rows.len(),
                claimed,
                "归档 claim 行集与扫描结果不一致，整事务回滚"
            );
            return Err(ArchiveStoreError::ClaimConflict.into());
        }
        tx.commit()?;
        Ok(object_id)
    }

    /// 更新归档对象的压缩后字节数与 SHA-256。
    ///
    /// 配合短事务 claim：claim 只插入对象（bytes/sha256 可为占位空值）并
    /// 认领行集，CSV.GZ 在事务外生成后调用本方法补元数据，避免大对象编码
    /// 阻塞 ingest 写锁。`sha256` 必须是 64 位小写十六进制；对象不存在返回
    /// [`ArchiveStoreError::NotFound`]。
    pub fn update_archive_object_metadata(&self, id: i64, bytes: u64, sha256: &str) -> Result<()> {
        validate_archive_sha256(sha256)?;
        let bytes = i64::try_from(bytes).context("归档对象字节数超出 SQLite INTEGER 范围")?;
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let object: Option<(i64, String)> = tx
            .query_row(
                "SELECT ledger_version, status FROM archive_objects WHERE id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((ledger_version, status)) = object else {
            return Err(ArchiveStoreError::NotFound.into());
        };
        let status = ArchiveStatus::parse(&status)
            .ok_or_else(|| anyhow::anyhow!("archive_objects.status 字段值非法"))?;
        if ledger_version != LEDGER_VERSION_V8
            || !matches!(status, ArchiveStatus::Pending | ArchiveStatus::Failed)
        {
            return Err(ArchiveStoreError::InvalidTransition.into());
        }
        tx.execute(
            "UPDATE archive_objects SET bytes = ?2, sha256 = ?3 WHERE id = ?1",
            params![id, bytes, sha256],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 记录一次上传尝试：仅 pending / failed 对象允许，`attempts += 1`。
    ///
    /// 返回递增后的 attempts。对象不存在返回 `NotFound`，uploaded /
    /// local_deleted 返回 `InvalidTransition`。
    pub fn record_archive_attempt(&self, id: i64) -> Result<i64> {
        let mut conn = self.lock_write();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status: Option<String> = tx
            .query_row(
                "SELECT status FROM archive_objects WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(status) = status else {
            return Err(ArchiveStoreError::NotFound.into());
        };
        let status = ArchiveStatus::parse(&status)
            .ok_or_else(|| anyhow::anyhow!("archive_objects.status 字段值非法"))?;
        if !matches!(status, ArchiveStatus::Pending | ArchiveStatus::Failed) {
            return Err(ArchiveStoreError::InvalidTransition.into());
        }
        tx.execute(
            "UPDATE archive_objects SET attempts = attempts + 1 WHERE id = ?1",
            params![id],
        )?;
        let attempts: i64 = tx.query_row(
            "SELECT attempts FROM archive_objects WHERE id = ?1",
            params![id],
            |row| row.get(0),
        )?;
        tx.commit()?;
        Ok(attempts)
    }

    /// 按 `archive_object_id` 读回 claim 行集，按 `ts, rowid` 升序。
    ///
    /// 排序必须与 claim/scan 的 `(ts, rowid)` 一致，重试才能重建字节级相同的
    /// CSV；上传失败 / 崩溃后不得重扫 raw。对象不存在或行已删除返回空列表。
    pub fn archive_rows_for_object(&self, object_id: i64) -> Result<Vec<ArchiveRawRow>> {
        let conn = self.lock_read();
        let mut stmt = conn.prepare(
            "SELECT rowid, agent_id, metric, labels, ts, value FROM samples \
             WHERE archive_object_id = ?1 ORDER BY ts ASC, rowid ASC",
        )?;
        let rows = stmt.query_map(params![object_id], |row| {
            Ok(ArchiveRawRow {
                rowid: row.get(0)?,
                agent_id: row.get(1)?,
                metric: row.get(2)?,
                labels: row.get(3)?,
                ts: row.get(4)?,
                value: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// `archive_objects` 的总行数（`archive status` / 面板状态用）。
    pub fn count_archive_objects(&self) -> Result<i64> {
        let conn = self.lock_read();
        Ok(conn.query_row("SELECT COUNT(*) FROM archive_objects", [], |row| row.get(0))?)
    }
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

    /// NUL / NaN / Inf 必须在开启事务前整批拒绝：三张表都不能留下任何行。
    #[test]
    fn insert_rejects_nul_and_non_finite_without_rows() {
        let s = SqliteStorage::open_in_memory().unwrap();

        let mut nul_agent = batch(1);
        nul_agent.agent_id = "a\0b".into();
        let mut nul_metric = batch(2);
        nul_metric.samples[0].metric = "cpu\0usage".into();
        let mut nul_label_key = batch(3);
        nul_label_key.samples[0]
            .labels
            .insert("co\0re".into(), "0".into());
        let mut nul_label_value = batch(4);
        nul_label_value.samples[0]
            .labels
            .insert("core".into(), "0\0".into());
        let mut nan = batch(5);
        nan.samples[0].value = f64::NAN;
        let mut inf = batch(6);
        inf.samples[0].value = f64::INFINITY;
        let mut neg_inf = batch(7);
        neg_inf.samples[0].value = f64::NEG_INFINITY;

        for (what, invalid) in [
            ("agent_id 含 NUL", nul_agent),
            ("metric 含 NUL", nul_metric),
            ("labels key 含 NUL", nul_label_key),
            ("labels value 含 NUL", nul_label_value),
            ("NaN", nan),
            ("+Inf", inf),
            ("-Inf", neg_inf),
        ] {
            assert_eq!(
                s.insert_batch(&invalid).unwrap(),
                IngestOutcome::Rejected(RejectReason::Invalid),
                "{what} 必须返回 Invalid"
            );
        }

        let conn = s.lock_read();
        for table in ["samples", "ingest_batches", "ingest_state"] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "非法批次不得写入 {table}");
        }
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

    /// v7 的 13 个显式索引 + v8 的 3 个 partial index，共 16 个。
    const V7_INDEXES: [&str; 16] = [
        "idx_samples_1m_lookup",
        "idx_samples_1m_ts",
        "idx_samples_1h_lookup",
        "idx_samples_1h_ts",
        "idx_samples_metric_ts",
        "idx_alert_events_ts",
        "idx_alert_events_rule_ts",
        "idx_alert_events_agent_ts",
        "idx_alert_events_pending",
        "idx_alert_states_state_eval",
        "idx_alert_silences_until",
        "idx_archive_objects_range",
        "idx_archive_objects_status",
        "idx_samples_unarchived",
        "idx_samples_unaggregated",
        "idx_samples_1m_unaggregated",
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

    /// fresh 库：方案 §4 的 10 张新表与 v8 的 16 个索引全部存在，版本号为 8。
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

    /// 已存在的 v7 库缺少 B1b 新增索引时，重新打开必须补建（IF NOT EXISTS 每次都执行）。
    #[test]
    fn m4_b1b_v7_reopen_creates_new_indexes() {
        let path = temp_db("b1b-index-upgrade");
        {
            let s = SqliteStorage::open(&path).unwrap();
            s.lock_write()
                .execute_batch(
                    "DROP INDEX idx_alert_events_pending;
                     DROP INDEX idx_alert_states_state_eval;
                     DROP INDEX idx_alert_silences_until;
                     DROP INDEX idx_samples_metric_ts;",
                )
                .unwrap();
            assert!(!sqlite_object_exists(
                &s,
                "index",
                "idx_alert_events_pending"
            ));
        }
        {
            let s = SqliteStorage::open(&path).unwrap();
            for index in [
                "idx_alert_events_pending",
                "idx_alert_states_state_eval",
                "idx_alert_silences_until",
                "idx_samples_metric_ts",
            ] {
                assert!(
                    sqlite_object_exists(&s, "index", index),
                    "重新打开后必须补建索引 {index}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// v6 库升级到 v8：建新表并给 samples 补 v8 列，旧 agents / samples /
    /// api_tokens 数据不变，连续打开两次不报错、不重复建表，`user_version=8`。
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
                panic!("第 {round} 次打开 v6 库失败（v6→v8 迁移必须幂等）: {err}")
            });
            let version: i64 = s
                .lock_read()
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(version, SCHEMA_VERSION, "必须升级到 v8");

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

    /// KI-29：raw 删除最大 rowid 行后，水位必须在同一批事务里降到新 MAX。
    #[test]
    fn ki29_prune_lowers_rowid_watermark_to_new_max() {
        let s = SqliteStorage::open_in_memory().unwrap();
        // rowid 1 = 旧行（删）、rowid 2 = 最新行（留）、rowid 3 = 旧行（删）。
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", 1_000, 1.0),
                ("cpu.usage", "{}", 9_000, 2.0),
                ("cpu.usage", "{}", 2_000, 3.0),
            ],
        );
        s.set_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY, "3", 1)
            .unwrap();

        let pruned = s.prune_samples_before(5_000).unwrap();
        assert_eq!(pruned.deleted, 2);
        assert_eq!(pruned.batches, 1);
        assert_eq!(s.raw_new_rows(None).unwrap().0, Some(2));
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap()
                .as_deref(),
            Some("2"),
            "旧水位 3 高于新 MAX=2，只能降到 2"
        );
    }

    /// KI-29：水位只降不升；raw 清空时删键；缺失/非法旧值不得被凭空创建。
    #[test]
    fn ki29_prune_only_lowers_and_clears_or_keeps_missing_watermark() {
        let s = SqliteStorage::open_in_memory().unwrap();
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", 1_000, 1.0),
                ("cpu.usage", "{}", 2_000, 2.0),
                ("cpu.usage", "{}", 9_000, 3.0),
            ],
        );
        s.set_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY, "1", 1)
            .unwrap();

        // 删掉 rowid 1/2，MAX 仍是 3：旧水位更低，不得抬高。
        assert_eq!(s.prune_samples_before(5_000).unwrap().deleted, 2);
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap()
                .as_deref(),
            Some("1"),
            "水位只能降低，不得升高"
        );

        // 清空 raw：必须删除水位键。
        assert_eq!(s.prune_samples_before(i64::MAX).unwrap().deleted, 1);
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap(),
            None,
            "raw 表为空时必须删除水位键"
        );

        // 旧键缺失时，普通删除不得凭空创建水位。
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", 1_000, 1.0),
                ("cpu.usage", "{}", 9_000, 2.0),
            ],
        );
        assert_eq!(s.prune_samples_before(5_000).unwrap().deleted, 1);
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap(),
            None,
            "旧水位缺失时不得新增 key"
        );

        // 非法旧值不参与比较，也不被改写成推算出的数值。
        s.set_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY, "bogus", 1)
            .unwrap();
        insert_samples(&s, "a1", &[("cpu.usage", "{}", 2_000, 4.0)]);
        assert_eq!(s.prune_samples_before(5_000).unwrap().deleted, 1);
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap()
                .as_deref(),
            Some("bogus"),
            "非法旧值不是有效水位，不得据此更新或新建"
        );
    }

    /// KI-29：raw 已空但残留高水位时，no-op prune（deleted=0）也必须清键。
    #[test]
    fn ki29_noop_prune_clears_stale_watermark_on_empty_raw() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.set_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY, "7", 1)
            .unwrap();

        let pruned = s.prune_samples_before(i64::MAX).unwrap();
        assert_eq!(
            pruned,
            PruneResult::default(),
            "空表 prune 不得产生删除或批次"
        );
        assert_eq!(s.raw_new_rows(None).unwrap().0, None, "raw 表应为空");
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap(),
            None,
            "raw 表为空时即使 deleted=0 也必须清除残留水位"
        );
    }

    /// KI-29 竞态：删掉最大 rowid 行且旧水位 <= 新 MAX 时必须删键（让 CAS 失效）。
    #[test]
    fn ki29_prune_clears_watermark_when_max_rowid_row_deleted() {
        let s = SqliteStorage::open_in_memory().unwrap();
        // rowid 1..9 保留（ts=9_000），rowid 10 是最旧行（ts=1_000，会被删）。
        let mut rows = vec![("cpu.usage", "{}", 9_000i64, 1.0f64); 9];
        rows.push(("cpu.usage", "{}", 1_000, 2.0));
        insert_samples(&s, "a1", &rows);
        assert_eq!(s.raw_new_rows(None).unwrap().0, Some(10));
        // old=5 <= max_after=9：若保留 5，并发 downsample 的 CAS(expected=5)
        // 仍会成功并把 max_before=10 写回，因此必须删键。
        s.set_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY, "5", 1)
            .unwrap();

        let pruned = s.prune_samples_before(5_000).unwrap();
        assert_eq!(pruned.deleted, 1);
        assert_eq!(pruned.batches, 1);
        assert_eq!(s.raw_new_rows(None).unwrap().0, Some(9));
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap(),
            None,
            "最大 rowid 行被删且旧水位 <= 新 MAX 时必须删键，避免 CAS 误判"
        );
    }

    /// KI-29：只有删除最大 rowid 行才推进 `raw_prune_generation`。
    #[test]
    fn ki29_prune_generation_increments_only_when_max_rowid_row_deleted() {
        let s = SqliteStorage::open_in_memory().unwrap();
        // rowid 1=旧、rowid 2=保留、rowid 3=旧（当前最大 rowid）。
        insert_samples(
            &s,
            "a1",
            &[
                ("cpu.usage", "{}", 1_000, 1.0),
                ("cpu.usage", "{}", 9_000, 2.0),
                ("cpu.usage", "{}", 2_000, 3.0),
            ],
        );

        // 删 rowid 1：MAX 保持 3，不推进 generation（缺失保持缺失）。
        assert_eq!(s.prune_samples_before(1_500).unwrap().deleted, 1);
        assert_eq!(
            s.get_maintenance_state(STATE_RAW_PRUNE_GENERATION).unwrap(),
            None,
            "删非最大 rowid 行不得推进 generation"
        );

        // 删 rowid 3（最大）：缺失按 1 写。
        assert_eq!(s.prune_samples_before(5_000).unwrap().deleted, 1);
        assert_eq!(
            s.get_maintenance_state(STATE_RAW_PRUNE_GENERATION)
                .unwrap()
                .as_deref(),
            Some("1"),
            "删最大 rowid 行时 generation 缺失按 1 写"
        );

        // 新迟到行复用 rowid 3，再删一次最大行：1 -> 2。
        insert_samples(&s, "a1", &[("cpu.usage", "{}", 3_000, 4.0)]);
        assert_eq!(s.raw_new_rows(None).unwrap().0, Some(3));
        assert_eq!(s.prune_samples_before(5_000).unwrap().deleted, 1);
        assert_eq!(
            s.get_maintenance_state(STATE_RAW_PRUNE_GENERATION)
                .unwrap()
                .as_deref(),
            Some("2"),
            "每次删最大 rowid 行都应 +1"
        );

        // 非法旧值按 1 写。
        s.set_maintenance_state(STATE_RAW_PRUNE_GENERATION, "bogus", 1)
            .unwrap();
        insert_samples(&s, "a1", &[("cpu.usage", "{}", 3_000, 5.0)]);
        assert_eq!(s.prune_samples_before(5_000).unwrap().deleted, 1);
        assert_eq!(
            s.get_maintenance_state(STATE_RAW_PRUNE_GENERATION)
                .unwrap()
                .as_deref(),
            Some("1"),
            "非法 generation 按 1 写"
        );
    }

    /// KI-29 竞态：rowid 水位 CAS 只在当前值仍等于调用方读到的值时才写入。
    #[test]
    fn ki29_claim_raw_rowid_if_unchanged_compares_and_swaps() {
        let s = SqliteStorage::open_in_memory().unwrap();

        // key 缺失 + expected=None（generation 也缺失=0）：可写。
        assert!(s.claim_raw_rowid_if_unchanged(None, 0, 10).unwrap());
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap()
                .as_deref(),
            Some("10")
        );

        // 当前 5、expected=5：写入 new_max。
        s.set_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY, "5", 1)
            .unwrap();
        assert!(s.claim_raw_rowid_if_unchanged(Some(5), 0, 12).unwrap());
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap()
                .as_deref(),
            Some("12")
        );

        // expected 不匹配：失败且不覆盖。
        assert!(!s.claim_raw_rowid_if_unchanged(Some(4), 0, 99).unwrap());
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap()
                .as_deref(),
            Some("12"),
            "CAS 失败不得改写水位"
        );

        // key 已存在时 expected=None 不匹配。
        assert!(!s.claim_raw_rowid_if_unchanged(None, 0, 99).unwrap());
        assert!(
            !s.claim_raw_rowid_if_unchanged(Some(12), 1, 99).unwrap(),
            "generation 单独不匹配也必须失败"
        );
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap()
                .as_deref(),
            Some("12")
        );

        // key 缺失时 expected=Some 不匹配，也不得凭空创建。
        let empty = SqliteStorage::open_in_memory().unwrap();
        assert!(!empty.claim_raw_rowid_if_unchanged(Some(5), 0, 10).unwrap());
        assert_eq!(
            empty
                .get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap(),
            None
        );
    }

    /// KI-29 竞态：rowid key 缺失时代际变化仍必须让 CAS 失败。
    #[test]
    fn ki29_claim_fails_when_generation_changes_without_rowid_key() {
        let s = SqliteStorage::open_in_memory().unwrap();
        // 模拟 prune 删除最大 rowid 行：rowid key 缺失，generation 0 -> 1。
        s.set_maintenance_state(STATE_RAW_PRUNE_GENERATION, "1", 1)
            .unwrap();
        assert!(
            !s.claim_raw_rowid_if_unchanged(None, 0, 10).unwrap(),
            "generation 从 0 变 1 时，即使 rowid key 缺失也不得认领"
        );
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap(),
            None,
            "CAS 失败不得创建 rowid key"
        );

        // generation 对齐后才可写。
        assert!(s.claim_raw_rowid_if_unchanged(None, 1, 10).unwrap());
        assert_eq!(
            s.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap()
                .as_deref(),
            Some("10")
        );

        // 当前 generation 非法：任何期望都不匹配。
        let bad = SqliteStorage::open_in_memory().unwrap();
        bad.set_maintenance_state(STATE_RAW_PRUNE_GENERATION, "bogus", 1)
            .unwrap();
        assert!(!bad.claim_raw_rowid_if_unchanged(None, 0, 10).unwrap());
        assert_eq!(
            bad.get_maintenance_state(DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY)
                .unwrap(),
            None
        );
    }

    /// KI-29：本地键常量必须与 downsample 模块的公开常量一致。
    #[test]
    fn ki29_rowid_watermark_key_matches_downsample_module() {
        assert_eq!(
            DOWNSAMPLE_1M_LAST_RAW_ROWID_KEY,
            crate::downsample::STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID
        );
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
    }

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
        let rules = builtin_rules(now, 90, 48);
        assert_eq!(s.seed_builtin_alert_rules(&rules, now).unwrap(), 5);
        assert_eq!(s.alert_rule_count().unwrap(), 5);

        // 重复种子（哪怕时间戳不同）不新增、不刷新任何字段。
        let same: Vec<AlertRule> = s.list_alert_rules().unwrap();
        assert_eq!(
            s.seed_builtin_alert_rules(&builtin_rules(now + 1, 90, 48), now + 1)
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
            s.seed_builtin_alert_rules(&builtin_rules(now + 120_000, 90, 48), now + 120_000)
                .unwrap(),
            0
        );
        let after = s.get_alert_rule("builtin-disk-percent").unwrap().unwrap();
        assert_eq!(after, edited, "种子绝不能覆盖用户改动");
        assert_eq!(after.created_at, seeded_created_at);
        assert_eq!(s.alert_rule_count().unwrap(), 5);
    }

    /// M4-B1 修复：种子不能被 name UNIQUE 冲突静默吞掉。
    ///
    /// 用户先建了与内置规则同名的自定义规则时，种子必须显式失败并回滚整批，
    /// 而不是 `INSERT OR IGNORE` 静默跳过、留下缺内置规则的半残状态。
    #[test]
    fn m4_b1fix_seed_fails_loudly_on_name_conflict_and_rolls_back() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let now = 1_700_000_000_000;

        // 自定义规则抢占内置规则名（不同 id）。
        let mut squatter = alert_rule("磁盘使用率过高");
        squatter.id = "custom-squatter".into();
        s.create_alert_rule(&squatter).unwrap();

        let err = s
            .seed_builtin_alert_rules(&builtin_rules(now, 90, 48), now)
            .expect_err("名称冲突必须显式失败");
        let text = err.to_string();
        assert!(
            text.contains("名称已被其它规则占用") || text.contains("内置告警规则"),
            "错误信息必须说明种子失败原因: {text}"
        );

        // 整批回滚：抢占者保留，内置规则一条都不能落库。
        assert_eq!(s.alert_rule_count().unwrap(), 1);
        assert_eq!(
            s.get_alert_rule("custom-squatter").unwrap(),
            Some(squatter.clone())
        );
        assert!(s.get_alert_rule("builtin-agent-offline").unwrap().is_none());
        assert!(s.get_alert_rule("builtin-disk-percent").unwrap().is_none());

        // 解决冲突后重新种子成功；抢占者不被覆盖。
        let mut renamed = squatter.clone();
        renamed.name = "用户自己的磁盘规则".into();
        s.update_alert_rule(&renamed).unwrap();
        assert_eq!(
            s.seed_builtin_alert_rules(&builtin_rules(now, 90, 48), now)
                .unwrap(),
            5
        );
        assert_eq!(s.alert_rule_count().unwrap(), 6);
        assert_eq!(
            s.get_alert_rule("custom-squatter").unwrap().unwrap().name,
            "用户自己的磁盘规则"
        );
    }

    /// 内置规则禁删；更新时 `is_builtin` / `created_at` 由存储层保持原值。
    #[test]
    fn m4_b1_alert_rule_builtin_delete_rejected_and_update_keeps_flag() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let now = 42;
        s.seed_builtin_alert_rules(&builtin_rules(now, 90, 48), now)
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

    // ------------------------------------------------------------------
    // M4-B1b：告警状态 / 事件 / 静默存储
    // ------------------------------------------------------------------

    use crate::alerts::{
        AlertEvent, AlertSilence, AlertSilenceStoreError, AlertState, AlertStateKind,
        MAX_ALERT_SILENCES,
    };

    fn alert_state(rule: &str, agent: &str, key: &str) -> AlertState {
        AlertState {
            rule_id: rule.to_string(),
            agent_id: agent.to_string(),
            series_key: key.to_string(),
            state: AlertStateKind::Pending,
            since: 1_000,
            last_eval_at: 1_000,
            last_value: Some(1.5),
            last_notified_at: None,
        }
    }

    fn alert_event(ts: i64, state: AlertStateKind, silenced: bool) -> AlertEvent {
        AlertEvent {
            id: 0,
            ts,
            rule_id: "rule-1".into(),
            rule_name: "磁盘告警".into(),
            agent_id: "agent-1".into(),
            series_key: "series-1".into(),
            state,
            value: Some(95.0),
            message:
                "规则「磁盘告警」触发：agent agent-1 指标「disk.used_percent」当前值 95，阈值 > 90"
                    .into(),
            notified: false,
            notify_error: String::new(),
            silenced,
        }
    }

    /// 状态往返 / upsert / 删除 / 只清理旧 resolved。
    #[test]
    fn m4_b1b_alert_state_roundtrip_upsert_and_prune() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let mut state = alert_state("rule-1", "agent-1", "series-1");
        assert_eq!(
            s.get_alert_state("rule-1", "agent-1", "series-1").unwrap(),
            None
        );
        s.upsert_alert_state(&state).unwrap();
        assert_eq!(
            s.get_alert_state("rule-1", "agent-1", "series-1").unwrap(),
            Some(state.clone())
        );

        state.state = AlertStateKind::Firing;
        state.since = 2_000;
        state.last_eval_at = 2_100;
        state.last_value = None;
        state.last_notified_at = Some(2_050);
        s.upsert_alert_state(&state).unwrap();
        assert_eq!(
            s.get_alert_state("rule-1", "agent-1", "series-1").unwrap(),
            Some(state.clone()),
            "upsert 必须覆盖状态、时间与值"
        );

        let mut second = alert_state("rule-1", "agent-2", "");
        second.state = AlertStateKind::Resolved;
        second.since = 500;
        second.last_eval_at = 500;
        s.upsert_alert_state(&second).unwrap();
        let states = s.list_alert_states().unwrap();
        assert_eq!(states.len(), 2);
        assert_eq!(states[0], state, "按 (rule, agent, series) 稳定排序");
        assert_eq!(states[1], second);

        // 只删 resolved 且 last_eval_at 早于 cutoff 的状态。
        assert_eq!(s.prune_alert_states(1_000).unwrap(), 1);
        assert_eq!(s.get_alert_state("rule-1", "agent-2", "").unwrap(), None);
        assert!(s
            .get_alert_state("rule-1", "agent-1", "series-1")
            .unwrap()
            .is_some());
        assert_eq!(s.prune_alert_states(i64::MAX).unwrap(), 0);

        assert_eq!(
            s.delete_alert_state("rule-1", "agent-1", "series-1")
                .unwrap(),
            1
        );
        assert_eq!(
            s.delete_alert_state("rule-1", "agent-1", "series-1")
                .unwrap(),
            0
        );
        assert!(s.list_alert_states().unwrap().is_empty());
    }

    /// 事件往返 / 分页（before_id 排他）/ 按时间与行数上限清理。
    #[test]
    fn m4_b1b_alert_event_pagination_and_prune() {
        let s = SqliteStorage::open_in_memory().unwrap();
        for (index, ts) in [1_000, 2_000, 3_000, 4_000, 5_000].into_iter().enumerate() {
            let event = alert_event(
                ts,
                if index % 2 == 0 {
                    AlertStateKind::Firing
                } else {
                    AlertStateKind::Resolved
                },
                index == 4,
            );
            assert_eq!(s.insert_alert_event(&event).unwrap(), index as i64 + 1);
        }

        let first = s.list_alert_events(2, None).unwrap();
        assert_eq!(
            first.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![5, 4]
        );
        assert_eq!(first[0].ts, 5_000);
        assert!(first[0].silenced);
        assert!(!first[0].notified);
        assert!(first[0].notify_error.is_empty());
        assert_eq!(
            first[0].message,
            alert_event(5_000, AlertStateKind::Firing, true).message
        );

        let second = s.list_alert_events(2, Some(4)).unwrap();
        assert_eq!(
            second.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![3, 2]
        );
        let last = s.list_alert_events(2, Some(2)).unwrap();
        assert_eq!(
            last.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![1]
        );
        assert!(s.list_alert_events(0, None).unwrap().is_empty());

        // 先按时间删：ts < 3000 的 2 条。
        assert_eq!(s.prune_alert_events(3_000, 100).unwrap(), 2);
        assert_eq!(s.list_alert_events(10, None).unwrap().len(), 3);
        // 再按行数上限从旧删到 max_rows：剩 3 条只保留最新 1 条。
        assert_eq!(s.prune_alert_events(0, 1).unwrap(), 2);
        let remaining = s.list_alert_events(10, None).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, 5);
        // max_rows = 0 表示清空。
        assert_eq!(s.prune_alert_events(0, 0).unwrap(), 1);
        assert!(s.list_alert_events(10, None).unwrap().is_empty());
    }

    /// 静默往返 / 生效窗口 / 删除 / 过期清理。
    #[test]
    fn m4_b1b_alert_silence_crud_active_window_and_prune() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let global = AlertSilence {
            id: 0,
            rule_id: None,
            agent_id: None,
            until_ts: 2_000,
            created_by: "admin".into(),
            created_at: 1_000,
        };
        assert_eq!(s.create_alert_silence(&global).unwrap(), 1);

        let mut rule_only = global.clone();
        rule_only.rule_id = Some("rule-1".into());
        rule_only.until_ts = 5_000;
        assert_eq!(s.create_alert_silence(&rule_only).unwrap(), 2);

        let mut both = global.clone();
        both.rule_id = Some("rule-1".into());
        both.agent_id = Some("agent-1".into());
        both.until_ts = 10_000;
        assert_eq!(s.create_alert_silence(&both).unwrap(), 3);

        // now=3000：until=2000 已过期；最新创建的在前。
        let active = s.list_active_silences(3_000).unwrap();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].id, 3);
        assert_eq!(active[1].id, 2);
        assert_eq!(active[0].rule_id.as_deref(), Some("rule-1"));
        assert_eq!(active[0].agent_id.as_deref(), Some("agent-1"));
        assert_eq!(active[1].rule_id.as_deref(), Some("rule-1"));
        assert_eq!(active[1].agent_id, None);

        // 到期时刻（until_ts == now）不再生效。
        let boundary = s.list_active_silences(2_000).unwrap();
        assert_eq!(boundary.len(), 2);
        assert!(boundary.iter().all(|silence| silence.until_ts > 2_000));

        assert!(s.delete_alert_silence(2).unwrap());
        assert!(
            !s.delete_alert_silence(2).unwrap(),
            "重复删除必须返回 false"
        );
        assert_eq!(s.list_active_silences(3_000).unwrap().len(), 1);

        // until_ts <= before_ts 的静默全部清理（含边界）。
        assert_eq!(s.prune_alert_silences(10_000).unwrap(), 2);
        assert!(s.list_active_silences(0).unwrap().is_empty());
        assert_eq!(s.prune_alert_silences(10_000).unwrap(), 0);
    }

    /// 评估引擎只应看到 enabled 规则。
    #[test]
    fn m4_b1b_list_enabled_alert_rules_filters_disabled() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let mut enabled = alert_rule("启用规则");
        enabled.id = "rule-enabled".into();
        enabled.metric = "disk.used_percent".into();
        enabled.enabled = true;
        s.create_alert_rule(&enabled).unwrap();

        let mut disabled = alert_rule("禁用规则");
        disabled.id = "rule-disabled".into();
        disabled.metric = "disk.used_percent".into();
        s.create_alert_rule(&disabled).unwrap();

        let rules = s.list_enabled_alert_rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "rule-enabled");

        enabled.enabled = false;
        s.update_alert_rule(&enabled).unwrap();
        assert!(s.list_enabled_alert_rules().unwrap().is_empty());
    }

    fn seed_metric_sample(
        s: &SqliteStorage,
        agent: &str,
        seq: u64,
        labels: Labels,
        ts: i64,
        value: f64,
    ) {
        s.insert_batch(&SampleBatch {
            agent_id: agent.into(),
            epoch: 1,
            seq,
            boot_id: "boot".into(),
            sent_at: ts,
            samples: vec![Sample {
                metric: "disk.used_percent".into(),
                labels,
                ts,
                value,
            }],
        })
        .unwrap();
    }

    /// raw-only 有界查询：每序列最新、同 ts 取最大 rowid、since 过滤、limit+1 截断。
    #[test]
    fn m4_b1b_latest_alert_series_is_raw_only_bounded_and_rowid_latest() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let mut root = Labels::new();
        root.insert("mount".into(), "/".into());
        let mut data = Labels::new();
        data.insert("mount".into(), "/data".into());

        seed_metric_sample(&s, "a1", 1, root.clone(), 1_000, 10.0);
        seed_metric_sample(&s, "a1", 2, root.clone(), 2_000, 20.0);
        seed_metric_sample(&s, "a1", 3, root.clone(), 3_000, 30.0);
        // 同一 ts 的第二行：必须取 rowid 更大的 31。
        seed_metric_sample(&s, "a1", 4, root.clone(), 3_000, 31.0);
        seed_metric_sample(&s, "a1", 5, data, 1_500, 15.0);
        seed_metric_sample(&s, "a2", 6, root, 2_500, 25.0);
        // since 之前的旧样本必须排除。
        seed_metric_sample(&s, "a3", 7, Labels::new(), 500, 99.0);

        let snapshot = s
            .latest_alert_series("disk.used_percent", 1_000, None, 10)
            .unwrap();
        assert!(!snapshot.truncated);
        assert_eq!(snapshot.rows.len(), 3);
        let find = |agent: &str, mount: &str| {
            snapshot
                .rows
                .iter()
                .find(|row| {
                    row.agent_id == agent
                        && row.labels.get("mount").map(String::as_str) == Some(mount)
                })
                .unwrap_or_else(|| panic!("缺少序列 {agent}/{mount}"))
        };
        assert_eq!(find("a1", "/").ts, 3_000);
        assert!((find("a1", "/").value - 31.0).abs() < 1e-9);
        assert_eq!(find("a1", "/data").value, 15.0);
        assert_eq!(find("a2", "/").value, 25.0);

        // limit+1 探测：3 条序列、limit=2 → 只回 2 条且 truncated。
        let bounded = s
            .latest_alert_series("disk.used_percent", 1_000, None, 2)
            .unwrap();
        assert!(bounded.truncated);
        assert_eq!(bounded.rows.len(), 2);
        // limit=0 不返回数据。
        let empty = s
            .latest_alert_series("disk.used_percent", 1_000, None, 0)
            .unwrap();
        assert!(empty.truncated);
        assert!(empty.rows.is_empty());

        // agent 过滤与 since 过滤。
        let a2 = s
            .latest_alert_series("disk.used_percent", 1_000, Some("a2"), 10)
            .unwrap();
        assert_eq!(a2.rows.len(), 1);
        assert_eq!(a2.rows[0].agent_id, "a2");
        let recent = s
            .latest_alert_series("disk.used_percent", 2_600, None, 10)
            .unwrap();
        assert_eq!(recent.rows.len(), 1);
        assert_eq!(recent.rows[0].ts, 3_000);

        // 只有 1m 聚合桶、raw 已删除：raw-only 查询必须为空。
        seed_metric_sample(&s, "a4", 8, Labels::new(), 100_000, 88.0);
        s.downsample_1m_range(100_000, 200_000).unwrap();
        s.prune_samples_before(200_000).unwrap();
        let raw_only = s
            .latest_alert_series("disk.used_percent", 0, None, 10)
            .unwrap();
        assert!(
            raw_only.rows.is_empty(),
            "raw-only 查询不得回退到 1m: {raw_only:?}"
        );
    }

    /// 单事务批量写：事件与状态一起落库，空批次是 no-op。
    #[test]
    fn m4_b1b_apply_alert_transitions_batches_events_then_states() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let events = vec![
            alert_event(1_000, AlertStateKind::Firing, false),
            alert_event(1_001, AlertStateKind::Resolved, true),
        ];
        let states = vec![
            alert_state("rule-1", "agent-1", "series-1"),
            alert_state("rule-1", "agent-2", "series-1"),
        ];
        s.apply_alert_transitions(&events, &states).unwrap();
        assert_eq!(s.list_alert_events(10, None).unwrap().len(), 2);
        assert_eq!(s.list_alert_states().unwrap(), {
            let mut sorted = states.clone();
            sorted.sort_by(|a, b| {
                (&a.rule_id, &a.agent_id, &a.series_key).cmp(&(
                    &b.rule_id,
                    &b.agent_id,
                    &b.series_key,
                ))
            });
            sorted
        });

        // 空批次不抢写锁、不报错。
        s.apply_alert_transitions(&[], &[]).unwrap();
        assert_eq!(s.list_alert_events(10, None).unwrap().len(), 2);
    }

    /// B2 预留：待通知队列排除 silenced / 已通知；通知结果与状态通知时间独立更新。
    #[test]
    fn m4_b1b_b2_notification_helpers() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let first = s
            .insert_alert_event(&alert_event(1_000, AlertStateKind::Firing, false))
            .unwrap();
        let silenced = s
            .insert_alert_event(&alert_event(1_001, AlertStateKind::Firing, true))
            .unwrap();
        let mut already = alert_event(1_002, AlertStateKind::Firing, false);
        already.notified = true;
        let already_id = s.insert_alert_event(&already).unwrap();

        let pending = s.list_pending_notification_events(10).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].id, first);
        assert!(!pending.iter().any(|event| event.id == silenced));
        assert!(!pending.iter().any(|event| event.id == already_id));
        assert!(s.list_pending_notification_events(0).unwrap().is_empty());

        // 成功：notified=1 且清空错误。
        assert!(s.mark_notification_result(first, true, "不应写入").unwrap());
        let stored = s.list_alert_events(10, None).unwrap();
        let first_event = stored.iter().find(|event| event.id == first).unwrap();
        assert!(first_event.notified);
        assert!(first_event.notify_error.is_empty());
        assert!(s.list_pending_notification_events(10).unwrap().is_empty());

        // 失败：保留截断后的错误摘要，仍留在待通知队列。
        let failing = s
            .insert_alert_event(&alert_event(1_003, AlertStateKind::Firing, false))
            .unwrap();
        assert!(s
            .mark_notification_result(failing, false, &"x".repeat(1_024))
            .unwrap());
        let stored = s.list_alert_events(10, None).unwrap();
        let failing_event = stored.iter().find(|event| event.id == failing).unwrap();
        assert!(!failing_event.notified);
        assert_eq!(
            failing_event.notify_error.len(),
            MAX_ALERT_NOTIFY_ERROR_BYTES
        );
        assert_eq!(
            s.list_pending_notification_events(10)
                .unwrap()
                .iter()
                .map(|event| event.id)
                .collect::<Vec<_>>(),
            vec![failing]
        );
        assert!(!s.mark_notification_result(999_999, true, "").unwrap());

        // 状态通知时间：只改 last_notified_at，不动状态机字段。
        let mut state = alert_state("rule-1", "agent-1", "series-1");
        state.state = AlertStateKind::Firing;
        state.since = 111;
        state.last_eval_at = 222;
        state.last_value = Some(1.5);
        s.upsert_alert_state(&state).unwrap();
        assert!(s
            .update_alert_state_notified("rule-1", "agent-1", "series-1", 333)
            .unwrap());
        let stored = s
            .get_alert_state("rule-1", "agent-1", "series-1")
            .unwrap()
            .unwrap();
        assert_eq!(stored.last_notified_at, Some(333));
        assert_eq!(stored.state, AlertStateKind::Firing);
        assert_eq!(stored.since, 111);
        assert_eq!(stored.last_eval_at, 222);
        assert_eq!(stored.last_value, Some(1.5));
        assert!(!s
            .update_alert_state_notified("rule-missing", "agent-1", "series-1", 333)
            .unwrap());
    }

    /// 规则更新 / 删除的「清状态」变体在一个事务内完成；普通变体保持状态不变。
    #[test]
    fn m4_b1b_rule_state_cleanup_variants() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let mut rule = alert_rule("清理测试");
        rule.enabled = true;
        rule.metric = "disk.used_percent".into();
        s.create_alert_rule(&rule).unwrap();
        s.upsert_alert_state(&alert_state(&rule.id, "agent-1", "series-1"))
            .unwrap();

        // 普通更新不动状态。
        let mut updated = rule.clone();
        updated.threshold = 95.0;
        s.update_alert_rule(&updated).unwrap();
        assert!(s
            .get_alert_state(&rule.id, "agent-1", "series-1")
            .unwrap()
            .is_some());

        // 禁用 + 清状态。
        let mut disabled = updated.clone();
        disabled.enabled = false;
        s.update_alert_rule_and_clear_states(&disabled).unwrap();
        assert!(s
            .get_alert_state(&rule.id, "agent-1", "series-1")
            .unwrap()
            .is_none());
        assert!(!s.get_alert_rule(&rule.id).unwrap().unwrap().enabled);

        // 重新写状态后删除：clear 变体同时删规则与状态。
        s.upsert_alert_state(&alert_state(&rule.id, "agent-1", "series-1"))
            .unwrap();
        s.delete_alert_rule_and_clear_states(&rule.id).unwrap();
        assert!(s.get_alert_rule(&rule.id).unwrap().is_none());
        assert!(s.list_alert_states().unwrap().is_empty());

        // 普通删除保留状态（供 B1a 既有语义 / 测试使用）。
        let mut keep = alert_rule("保留状态");
        keep.metric = "disk.used_percent".into();
        keep.id = "keep-rule".into();
        s.create_alert_rule(&keep).unwrap();
        s.upsert_alert_state(&alert_state(&keep.id, "agent-1", "s"))
            .unwrap();
        s.delete_alert_rule(&keep.id).unwrap();
        assert_eq!(s.list_alert_states().unwrap().len(), 1);
    }

    /// 生效静默数量上限：第 1001 条返回领域错误，不写库。
    #[test]
    fn m4_b1b_active_silence_limit_is_enforced() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let silence = AlertSilence {
            id: 0,
            rule_id: None,
            agent_id: None,
            until_ts: 1_000_000,
            created_by: "admin".into(),
            created_at: 1_000,
        };
        for _ in 0..MAX_ALERT_SILENCES {
            s.create_alert_silence(&silence).unwrap();
        }
        let err = s.create_alert_silence(&silence).unwrap_err();
        assert_eq!(
            *err.downcast_ref::<AlertSilenceStoreError>()
                .expect("必须是静默领域错误"),
            AlertSilenceStoreError::LimitReached
        );
        assert_eq!(
            s.list_active_silences(1_000).unwrap().len(),
            MAX_ALERT_SILENCES,
            "超限请求不能写库"
        );
    }

    /// 陈旧 pending/firing 清理：批量上限、边界与 resolved 不受影响。
    #[test]
    fn m4_b1b_prune_stale_alert_states_is_bounded() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let cutoff = 10_000;
        let mut stale_pending = alert_state("rule-1", "agent-1", "stale-pending");
        stale_pending.state = AlertStateKind::Pending;
        stale_pending.last_eval_at = 8_000;
        let mut stale_firing = alert_state("rule-1", "agent-1", "stale-firing");
        stale_firing.state = AlertStateKind::Firing;
        stale_firing.last_eval_at = 9_000;
        let mut boundary = alert_state("rule-1", "agent-1", "boundary");
        boundary.state = AlertStateKind::Firing;
        boundary.last_eval_at = cutoff;
        let mut resolved = alert_state("rule-1", "agent-1", "resolved");
        resolved.state = AlertStateKind::Resolved;
        resolved.last_eval_at = 1_000;
        let mut fresh = alert_state("rule-1", "agent-1", "fresh");
        fresh.state = AlertStateKind::Firing;
        fresh.last_eval_at = 20_000;
        for state in [&stale_pending, &stale_firing, &boundary, &resolved, &fresh] {
            s.upsert_alert_state(state).unwrap();
        }

        // 单次只删 max_rows 条；索引顺序是 (state, last_eval_at)，firing 先于 pending。
        assert_eq!(s.prune_stale_alert_states(cutoff, 1).unwrap(), 1);
        assert!(s
            .get_alert_state("rule-1", "agent-1", "stale-firing")
            .unwrap()
            .is_none());
        assert_eq!(s.prune_stale_alert_states(cutoff, 1).unwrap(), 1);
        assert!(s
            .get_alert_state("rule-1", "agent-1", "stale-pending")
            .unwrap()
            .is_none());
        assert_eq!(s.prune_stale_alert_states(cutoff, 10).unwrap(), 0);
        assert_eq!(s.prune_stale_alert_states(cutoff, 0).unwrap(), 0);

        let remaining: Vec<String> = s
            .list_alert_states()
            .unwrap()
            .into_iter()
            .map(|state| state.series_key)
            .collect();
        assert_eq!(
            remaining,
            vec![
                "boundary".to_string(),
                "fresh".to_string(),
                "resolved".to_string()
            ],
            "resolved / 边界 / 新状态不能被陈旧清理删除"
        );
    }

    /// 每规则状态加载上限、淘汰优先级（非 resolved 优先）与写事务内硬上限。
    #[test]
    fn m4_b1b_rule_state_load_limit_and_prune_priority() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let rule_id = "rule-cap";
        let seed = |key: &str, kind: AlertStateKind, last_eval_at: i64| {
            let mut state = alert_state(rule_id, "agent-1", key);
            state.state = kind;
            state.last_eval_at = last_eval_at;
            s.upsert_alert_state(&state).unwrap();
        };
        seed("firing-100", AlertStateKind::Firing, 100);
        seed("firing-200", AlertStateKind::Firing, 200);
        seed("pending-300", AlertStateKind::Pending, 300);
        seed("firing-400", AlertStateKind::Firing, 400);
        seed("resolved-500", AlertStateKind::Resolved, 500);
        seed("resolved-600", AlertStateKind::Resolved, 600);

        // 加载按 last_eval_at 新→旧，且硬 LIMIT。
        let loaded = s.list_alert_states_for_rule(rule_id, 3).unwrap();
        assert_eq!(loaded.len(), 3);
        assert_eq!(
            loaded
                .iter()
                .map(|state| state.series_key.as_str())
                .collect::<Vec<_>>(),
            vec!["resolved-600", "resolved-500", "firing-400"]
        );
        assert_eq!(s.list_alert_states_for_rule(rule_id, 0).unwrap(), vec![]);

        // 保留 3 条：非 resolved 优先保留，即使 resolved 更新。
        assert_eq!(s.prune_alert_states_for_rule(rule_id, 3).unwrap(), 3);
        let kept = s.list_alert_states_for_rule(rule_id, 10).unwrap();
        assert_eq!(kept.len(), 3);
        assert!(kept
            .iter()
            .all(|state| state.state != AlertStateKind::Resolved));
        assert_eq!(
            kept.iter()
                .map(|state| state.last_eval_at)
                .collect::<Vec<_>>(),
            vec![400, 300, 200],
            "keep 3 应保留最新的非 resolved 状态"
        );

        // 批量评估写入 + 同事务硬上限：新状态最新，淘汰最旧一条。
        let mut new_state = alert_state(rule_id, "agent-1", "firing-700");
        new_state.state = AlertStateKind::Firing;
        new_state.last_eval_at = 700;
        assert_eq!(
            s.apply_alert_evaluation(rule_id, &[], &[new_state], 3)
                .unwrap(),
            1
        );
        let after = s.list_alert_states_for_rule(rule_id, 10).unwrap();
        assert_eq!(
            after
                .iter()
                .map(|state| state.last_eval_at)
                .collect::<Vec<_>>(),
            vec![700, 400, 300]
        );

        assert_eq!(s.prune_alert_states_for_rule(rule_id, 0).unwrap(), 3);
        assert!(s
            .list_alert_states_for_rule(rule_id, 10)
            .unwrap()
            .is_empty());
    }

    /// 告警 raw 查询必须走 `(metric, ts)` / `(agent, metric, ts)` 索引，不能全表扫描。
    #[test]
    fn m4_b1b_latest_alert_series_uses_index_without_full_scan() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let conn = s.lock_read();
        let plan_for = |has_agent: bool| -> Vec<String> {
            let sql = format!("EXPLAIN QUERY PLAN {}", latest_alert_series_sql(has_agent));
            let mut stmt = conn.prepare(&sql).unwrap();
            let values: Vec<rusqlite::types::Value> = if has_agent {
                vec![
                    rusqlite::types::Value::Text("disk.used_percent".into()),
                    rusqlite::types::Value::Integer(0),
                    rusqlite::types::Value::Text("a1".into()),
                    rusqlite::types::Value::Integer(10),
                ]
            } else {
                vec![
                    rusqlite::types::Value::Text("disk.used_percent".into()),
                    rusqlite::types::Value::Integer(0),
                    rusqlite::types::Value::Integer(10),
                ]
            };
            stmt.query_map(rusqlite::params_from_iter(values), |row| {
                row.get::<_, String>(3)
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
        };

        let all_agents = plan_for(false).join("\n");
        assert!(
            all_agents.contains("idx_samples_metric_ts"),
            "跨 agent 查询必须使用 idx_samples_metric_ts: {all_agents}"
        );
        assert!(
            !all_agents.lines().any(|line| line.trim() == "SCAN samples"),
            "不得出现全表扫描: {all_agents}"
        );

        let single_agent = plan_for(true).join("\n");
        assert!(
            single_agent.contains("idx_samples_lookup"),
            "单 agent 查询必须使用 idx_samples_lookup: {single_agent}"
        );
        assert!(
            !single_agent
                .lines()
                .any(|line| line.trim() == "SCAN samples"),
            "不得出现全表扫描: {single_agent}"
        );
    }
    // ------------------------------------------------------------------
    // M4-B2b：通知渠道存储
    // ------------------------------------------------------------------

    use crate::channels::{ChannelConfig, NotificationChannel, Secret};

    fn notification_channel(name: &str) -> NotificationChannel {
        static CHANNEL_SEQ: AtomicU64 = AtomicU64::new(1);
        let seq = CHANNEL_SEQ.fetch_add(1, Ordering::Relaxed);
        NotificationChannel {
            id: format!("00000000-0000-4000-8000-{seq:012}"),
            name: name.to_string(),
            kind: ChannelKind::Telegram,
            config: ChannelConfig::Telegram {
                bot_token: Secret::new("123456789:AAH_test-token_0123456789"),
                chat_id: "-1001234567890".to_string(),
            },
            enabled: true,
            updated_by: "admin".to_string(),
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_001_000,
        }
    }

    fn channel_store_error(err: anyhow::Error) -> ChannelStoreError {
        *err.downcast_ref::<ChannelStoreError>()
            .expect("必须是可映射的通知渠道领域错误")
    }

    /// CRUD 往返：配置原样读回、created_at 不被更新覆盖、删除后计数归零。
    #[test]
    fn m4_b2b_notification_channel_crud_roundtrip() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let channel = notification_channel("运维通知");
        s.create_notification_channel(&channel).unwrap();
        assert_eq!(s.notification_channel_count().unwrap(), 1);
        assert_eq!(
            s.get_notification_channel(&channel.id).unwrap(),
            Some(channel.clone())
        );
        assert_eq!(s.get_notification_channel("missing").unwrap(), None);
        assert_eq!(
            s.list_notification_channels().unwrap(),
            vec![channel.clone()]
        );

        let mut updated = channel.clone();
        updated.name = "运维通知-2".to_string();
        updated.enabled = false;
        updated.updated_by = "write-token".to_string();
        updated.updated_at = 1_700_000_999_000;
        updated.config = ChannelConfig::Telegram {
            bot_token: Secret::new("123456789:AAH_new-token_0123456789"),
            chat_id: "-1009999999999".to_string(),
        };
        s.update_notification_channel(&updated).unwrap();
        let stored = s.get_notification_channel(&channel.id).unwrap().unwrap();
        assert_eq!(stored, updated);
        assert_eq!(
            stored.created_at, channel.created_at,
            "created_at 不能被更新覆盖"
        );

        s.delete_notification_channel(&channel.id).unwrap();
        assert_eq!(s.notification_channel_count().unwrap(), 0);
        assert_eq!(s.get_notification_channel(&channel.id).unwrap(), None);

        // 重复名称（含更新时改成别人的名字）→ NameExists。
        let first = notification_channel("渠道-A");
        s.create_notification_channel(&first).unwrap();
        let mut duplicate = notification_channel("渠道-B");
        duplicate.name = first.name.clone();
        assert_eq!(
            channel_store_error(s.create_notification_channel(&duplicate).unwrap_err()),
            ChannelStoreError::NameExists
        );
        let mut rename = notification_channel("渠道-B");
        s.create_notification_channel(&rename).unwrap();
        rename.name = first.name.clone();
        assert_eq!(
            channel_store_error(s.update_notification_channel(&rename).unwrap_err()),
            ChannelStoreError::NameExists
        );
        assert_eq!(s.notification_channel_count().unwrap(), 2);

        // 不存在 / 类型不匹配 → 明确领域错误。
        assert_eq!(
            channel_store_error(s.update_notification_channel(&channel).unwrap_err()),
            ChannelStoreError::NotFound
        );
        let mut wrong_kind = notification_channel("类型错误");
        wrong_kind.kind = ChannelKind::Wecom;
        assert_eq!(
            channel_store_error(s.create_notification_channel(&wrong_kind).unwrap_err()),
            ChannelStoreError::Invalid("通知渠道配置不合法")
        );
    }

    /// 渠道上限 50：第 51 条拒绝写入，已有数据不受影响。
    #[test]
    fn m4_b2b_notification_channel_limit_is_enforced() {
        let s = SqliteStorage::open_in_memory().unwrap();
        for index in 0..MAX_NOTIFICATION_CHANNELS {
            s.create_notification_channel(&notification_channel(&format!("渠道-{index}")))
                .unwrap();
        }
        assert_eq!(
            s.notification_channel_count().unwrap(),
            MAX_NOTIFICATION_CHANNELS
        );
        let over = notification_channel("渠道-50");
        assert_eq!(
            channel_store_error(s.create_notification_channel(&over).unwrap_err()),
            ChannelStoreError::LimitReached
        );
        assert_eq!(
            s.notification_channel_count().unwrap(),
            MAX_NOTIFICATION_CHANNELS,
            "超限请求不能写库"
        );
    }

    /// 删除前在同一事务内检查 `alert_rules.channel_ids`；引用存在时必须 409，
    /// 解除引用后才能删除。
    #[test]
    fn m4_b2b_notification_channel_delete_rejects_in_use() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let channel = notification_channel("被引用渠道");
        s.create_notification_channel(&channel).unwrap();
        let mut rule = alert_rule("引用渠道规则");
        rule.channel_ids = vec![channel.id.clone()];
        s.create_alert_rule(&rule).unwrap();

        assert_eq!(
            channel_store_error(s.delete_notification_channel(&channel.id).unwrap_err()),
            ChannelStoreError::InUse
        );
        assert!(
            s.get_notification_channel(&channel.id).unwrap().is_some(),
            "被引用渠道不能删除"
        );

        rule.channel_ids.clear();
        s.update_alert_rule(&rule).unwrap();
        s.delete_notification_channel(&channel.id).unwrap();
        assert_eq!(s.get_notification_channel(&channel.id).unwrap(), None);
        assert_eq!(
            channel_store_error(s.delete_notification_channel(&channel.id).unwrap_err()),
            ChannelStoreError::NotFound
        );
    }

    /// B2 游标查询：只返回 `id > cursor` 且未通知、未静默的事件。
    #[test]
    fn m4_b2b_pending_notification_events_respect_cursor_and_silence() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let event = |ts: i64, silenced: bool| AlertEvent {
            id: 0,
            ts,
            rule_id: "rule-1".into(),
            rule_name: "规则".into(),
            agent_id: "agent-1".into(),
            series_key: "series-1".into(),
            state: AlertStateKind::Firing,
            value: Some(91.0),
            message: "触发".into(),
            notified: false,
            notify_error: String::new(),
            silenced,
        };
        let first = s.insert_alert_event(&event(1_000, false)).unwrap();
        let silenced = s.insert_alert_event(&event(2_000, true)).unwrap();
        let last = s.insert_alert_event(&event(3_000, false)).unwrap();
        assert_eq!(s.max_alert_event_id().unwrap(), last);

        let pending = s.list_pending_notification_events_after(0, 10).unwrap();
        assert_eq!(
            pending.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![first, last]
        );
        assert_eq!(
            s.list_pending_notification_events_after(first, 1)
                .unwrap()
                .iter()
                .map(|event| event.id)
                .collect::<Vec<_>>(),
            vec![last],
            "静默事件必须被排除，且 cursor 排他"
        );
        assert!(s
            .list_pending_notification_events_after(last, 10)
            .unwrap()
            .is_empty());
        assert!(s
            .list_pending_notification_events_after(0, 0)
            .unwrap()
            .is_empty());
        assert!(silenced > first);
        assert_eq!(s.max_alert_event_id().unwrap(), last);

        // 空表最大 id 为 0。
        assert_eq!(
            SqliteStorage::open_in_memory()
                .unwrap()
                .max_alert_event_id()
                .unwrap(),
            0
        );
    }

    /// 已处理但未发送的事件：`notified = 1` 且保留固定原因（不会被清空）。
    #[test]
    fn m4_b2b_mark_notification_processed_keeps_reason() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let event = AlertEvent {
            id: 0,
            ts: 1_000,
            rule_id: "rule-1".into(),
            rule_name: "规则".into(),
            agent_id: "agent-1".into(),
            series_key: "series-1".into(),
            state: AlertStateKind::Firing,
            value: Some(91.0),
            message: "触发".into(),
            notified: false,
            notify_error: String::new(),
            silenced: false,
        };
        let id = s.insert_alert_event(&event).unwrap();
        assert!(s.mark_notification_processed(id, "no_channel").unwrap());
        let stored = s.list_alert_events(10, None).unwrap().remove(0);
        assert!(stored.notified);
        assert_eq!(stored.notify_error, "no_channel");
        assert!(!s
            .mark_notification_processed(999_999, "no_channel")
            .unwrap());
        assert!(s
            .list_pending_notification_events_after(0, 10)
            .unwrap()
            .is_empty());
    }
}
