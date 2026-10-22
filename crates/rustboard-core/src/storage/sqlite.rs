//! SQLite 实现。所有写入走单连接 + 事务，WAL 模式。

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};

use super::{IngestOutcome, RejectReason, Storage};

/// `PRAGMA user_version`：v1 = `ingest_state` 以 agent_id 为主键，
/// v2 = `(agent_id, epoch)`，v3 = 新增 `ingest_batches` 精确判重。
const SCHEMA_VERSION: i64 = 3;

/// `ingest_batches` 判重记录保留 48 小时；过期后重放视为新批次。
const INGEST_BATCH_TTL_MS: i64 = 48 * 60 * 60 * 1000;

/// 每这么多次成功插入清理一次过期判重记录，避免每批都执行 DELETE。
const INGEST_CLEANUP_EVERY: u64 = 512;

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

pub struct SqliteStorage {
    conn: Mutex<Connection>,
    /// 成功插入批次的累计计数，用于低频触发 `ingest_batches` 清理。
    inserted_batches: AtomicU64,
}

impl SqliteStorage {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            rustboard_common::fsutil::ensure_dir(parent, 0o700)
                .with_context(|| format!("创建数据目录失败: {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("打开数据库失败: {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
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
        Ok(Self {
            conn: Mutex::new(conn),
            inserted_batches: AtomicU64::new(0),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// 把 `ingest_state` 从 v1（agent_id 主键）迁移到 v2（agent_id + epoch 主键），
/// 并为 v3 建好 `ingest_batches` 精确判重表。
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

    if version < SCHEMA_VERSION {
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tracing::info!(
            from = version,
            to = SCHEMA_VERSION,
            "数据库已迁移：新增 ingest_batches 精确判重"
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
        self.lock().execute(
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
        self.lock().execute(
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
        self.lock().execute(
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
        let updated = self.lock().execute(
            "UPDATE agents SET status = 'offline' WHERE status = 'online'",
            [],
        )?;
        Ok(updated)
    }

    fn insert_batch(&self, batch: &SampleBatch) -> Result<IngestOutcome> {
        let mut conn = self.lock();
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
        let conn = self.lock();
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
        let conn = self.lock();
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
        let conn = self.lock();
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
        let conn = self.lock();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM samples WHERE agent_id = ?1",
            params![agent_id],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    fn create_enroll_token(
        &self,
        token_hash: &str,
        name: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        self.lock().execute(
            "INSERT INTO enroll_tokens (token_hash, name, created_at, expires_at, used_at)
             VALUES (?1, ?2, ?3, ?4, NULL)",
            params![token_hash, name, created_at, expires_at],
        )?;
        Ok(())
    }

    fn consume_enroll_token(&self, token_hash: &str, now: i64) -> Result<Option<String>> {
        let mut conn = self.lock();
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
        self.lock().execute(
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
            .lock()
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
        let mut conn = self.lock();
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
        let exists: i64 = self.lock().query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_agents WHERE agent_id = ?1)",
            params![agent_id],
            |r| r.get(0),
        )?;
        Ok(exists != 0)
    }
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
        let conn = s.lock();
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
        let mut conn = s.lock();
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
            .lock()
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
            .lock()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let batches_table: i64 = s
            .lock()
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

    /// L3：v2 库（user_version=2）启动时补建 ingest_batches，并升级到 v3。
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
            .lock()
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, 3);
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
}
