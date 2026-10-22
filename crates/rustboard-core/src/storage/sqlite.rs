//! SQLite 实现。所有写入走单连接 + 事务，WAL 模式。

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};

use super::{InsertOutcome, Storage};

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

CREATE TABLE IF NOT EXISTS ingest_state (
    agent_id   TEXT PRIMARY KEY,
    epoch      INTEGER NOT NULL DEFAULT 0,
    last_seq   INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0
);
"#;

pub struct SqliteStorage {
    conn: Mutex<Connection>,
}

impl SqliteStorage {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("创建数据目录失败: {}", parent.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("打开数据库失败: {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        // journal_mode 会返回一行，必须用 query_row 消费掉
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        tracing::debug!(mode, "sqlite journal mode");
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "busy_timeout", 5_000)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
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
                status = excluded.status,
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
            "UPDATE agents SET last_seen_at = ?2, status = 'online' WHERE agent_id = ?1",
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

    fn insert_batch(&self, batch: &SampleBatch) -> Result<InsertOutcome> {
        let mut conn = self.lock();
        let tx = conn.transaction()?;

        let state: Option<(u64, u64)> = tx
            .query_row(
                "SELECT epoch, last_seq FROM ingest_state WHERE agent_id = ?1",
                params![batch.agent_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        if let Some((epoch, last_seq)) = state {
            if epoch == batch.epoch && batch.seq <= last_seq {
                tx.commit()?;
                return Ok(InsertOutcome { inserted: 0, duplicate: true });
            }
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

        tx.execute(
            "INSERT INTO ingest_state (agent_id, epoch, last_seq, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(agent_id) DO UPDATE SET
                epoch = excluded.epoch,
                last_seq = excluded.last_seq,
                updated_at = excluded.updated_at",
            params![batch.agent_id, batch.epoch, batch.seq, batch.sent_at],
        )?;
        tx.commit()?;
        Ok(InsertOutcome { inserted, duplicate: false })
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
        self.lock().execute(
            "INSERT INTO revoked_agents (agent_id, revoked_at) VALUES (?1, ?2)
             ON CONFLICT(agent_id) DO UPDATE SET revoked_at = excluded.revoked_at",
            params![agent_id, ts],
        )?;
        self.lock().execute(
            "UPDATE agents SET status = 'revoked' WHERE agent_id = ?1",
            params![agent_id],
        )?;
        self.lock().execute(
            "DELETE FROM agent_secrets WHERE agent_id = ?1",
            params![agent_id],
        )?;
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
    use rustboard_common::model::Sample;

    fn batch(seq: u64) -> SampleBatch {
        SampleBatch {
            agent_id: "a1".into(),
            epoch: 1,
            seq,
            boot_id: "boot".into(),
            sent_at: 1_700_000_000_000,
            samples: vec![
                Sample::new("cpu.usage", 1_700_000_000_000, 12.5),
                Sample::new("mem.used", 1_700_000_000_000, 1024.0),
            ],
        }
    }

    #[test]
    fn insert_is_idempotent() {
        let s = SqliteStorage::open_in_memory().unwrap();
        let first = s.insert_batch(&batch(1)).unwrap();
        assert_eq!(first.inserted, 2);
        assert!(!first.duplicate);

        let again = s.insert_batch(&batch(1)).unwrap();
        assert!(again.duplicate);
        assert_eq!(s.sample_count("a1").unwrap(), 2);
    }

    #[test]
    fn enroll_token_is_single_use() {
        let s = SqliteStorage::open_in_memory().unwrap();
        s.create_enroll_token("hash-a", "web-01", 1_000, 5_000).unwrap();
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
        s.create_enroll_token("hash-c", "web-02", 1_000, 2_000).unwrap();
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
