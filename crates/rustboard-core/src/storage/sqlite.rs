//! SQLite 实现。所有写入走单连接 + 事务，读路径走只读连接池，WAL 模式。

use std::ops::Deref;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};

use super::{
    AgentControlRecord, AgentSeriesRow, AuditEntry, IngestOutcome, NewAuditEntry, QueryTooLarge,
    RejectReason, Storage, AUDIT_RETENTION_MS,
};

/// 默认只读连接池大小（与 `HubConfig::read_pool_size` 默认值一致）。
pub const DEFAULT_READ_POOL_SIZE: usize = 4;
/// 只读连接池下限 / 上限：连接数就是文件句柄，必须有硬上限。
pub const MIN_READ_POOL_SIZE: usize = 1;
pub const MAX_READ_POOL_SIZE: usize = 16;

/// `PRAGMA user_version`：v1 = `ingest_state` 以 agent_id 为主键，
/// v2 = `(agent_id, epoch)`，v3 = 新增 `ingest_batches` 精确判重，
/// v4 = 新增 `agent_settings`（每台 agent 的采样间隔，纯新增表），
/// v5 = 新增 `agent_control` / `audit_log`（M3 控制面，纯新增表）。
const SCHEMA_VERSION: i64 = 5;

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
    pub fn open_with_readers(path: &Path, read_pool_size: usize) -> Result<Self> {
        let pool_size = read_pool_size.clamp(MIN_READ_POOL_SIZE, MAX_READ_POOL_SIZE);
        if pool_size != read_pool_size {
            tracing::warn!(
                requested = read_pool_size,
                actual = pool_size,
                "read_pool_size 超出允许范围，已夹到合法区间"
            );
        }
        if let Some(parent) = path.parent() {
            rustboard_common::fsutil::ensure_dir(parent, 0o700)
                .with_context(|| format!("创建数据目录失败: {}", parent.display()))?;
        }
        let writer = Connection::open(path)
            .with_context(|| format!("打开数据库失败: {}", path.display()))?;
        let writer = init_writer(writer)?;

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

    /// `latest_samples` 的实现：SQL 侧最多取 `limit` 行。
    ///
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

        if rows.len() >= limit {
            tracing::error!(
                limit,
                since,
                metrics = metrics.len(),
                agent = agent.unwrap_or("<all>"),
                "latest_samples 达到 SQL 行数硬上限，拒绝返回可能不完整的快照"
            );
            return Err(anyhow::Error::new(QueryTooLarge { limit }));
        }

        // SQL 已按 ts 升序；同键后到的（更新的 ts）覆盖先到的。
        // 用 BTreeMap 保证最终输出顺序稳定，便于面板与测试断言。
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
}

/// 测试注入：让指定路径的只读连接全部打开失败，覆盖「读池降级到写连接」分支。
#[cfg(test)]
static FAIL_READER_OPEN_FOR: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

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
/// 为 v3 建好 `ingest_batches` 精确判重表，为 v4 建好 `agent_settings` 表。
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

    if version < SCHEMA_VERSION {
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tracing::info!(
            from = version,
            to = SCHEMA_VERSION,
            "数据库已迁移：新增 agent_control / audit_log（M3 控制面）"
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

    fn latest_samples(
        &self,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
    ) -> Result<Vec<AgentSeriesRow>> {
        self.latest_samples_limited(since, metrics, agent, LATEST_SAMPLES_SQL_LIMIT)
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
}
