//! PostgreSQL Core 域：agent / 采样 / ingest / 设置 / 纳管 / 控制能力。
//!
//! 本文件只写 [`PostgresStorage`] 的**固有方法**，签名与
//! [`Storage`](crate::storage::Storage) trait 中对应方法逐字一致；统一
//! `impl Storage for PostgresStorage` 由最后的转发层一次性补齐。
//!
//! 行为对照 `sqlite.rs`：
//!
//! - `revoked` 是终态：`upsert_agent` / `mark_seen` / `set_status` 都不覆盖；
//! - `insert_batch` 单事务完成吊销检查、`(agent_id, epoch, seq)` 原子占位判重、
//!   逐点插入与 `ingest_state` 写入；重复批次整批跳过，NUL/NaN/Inf 整批拒绝；
//! - 查询值全部用 `$N` 绑定，只有占位符数量由 metrics 数量决定；
//! - 文本排序显式 `COLLATE "C"`，与 SQLite 默认 BINARY 的字节序一致；
//! - `latest_samples` 与 SQLite 一样先 raw，raw 为空才依次回退 1m、1h；
//!   达到 10 万行硬上限返回 [`QueryTooLarge`]，不静默截断。
//!
//! 所有方法都通过 [`PostgresStorage::with_client`] 取连接；调用方必须位于
//! blocking 线程（spike §4：tokio worker 内直接调用同步 PG 会 panic）。

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use anyhow::{bail, Context, Result};
use postgres::types::ToSql;
use postgres::Row;
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};
use rustboard_common::util::{constant_time_eq, now_ms};

use super::PostgresStorage;
use crate::storage::{
    invalid_batch, AgentControlRecord, AgentSeriesRow, IngestOutcome, QueryTooLarge, RejectReason,
    SampleTier, BUCKET_1H_MS, BUCKET_1M_MS,
};

/// 与 SQLite 一致：`ingest_batches` 判重记录保留 48 小时。
const INGEST_BATCH_TTL_MS: i64 = 48 * 60 * 60 * 1000;

/// 与 SQLite 一致：每 512 次成功写入清理一次过期判重记录。
const INGEST_CLEANUP_EVERY: u64 = 512;

/// 与 SQLite 一致：`latest_samples` 单次 SQL 允许扫描的行数硬上限。
const LATEST_SAMPLES_SQL_LIMIT: usize = 100_000;

impl PostgresStorage {
    /// 插入或更新 agent 元信息；`revoked` 状态是终态，不会被覆盖。
    pub fn upsert_agent(&self, agent: &AgentRecord) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    "INSERT INTO agents
                    (agent_id, name, hostname, os, arch, version, boot_id, status,
                     last_seen_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                 ON CONFLICT (agent_id) DO UPDATE SET
                    name = EXCLUDED.name,
                    hostname = EXCLUDED.hostname,
                    os = EXCLUDED.os,
                    arch = EXCLUDED.arch,
                    version = EXCLUDED.version,
                    boot_id = EXCLUDED.boot_id,
                    -- revoked 是终态：任何 upsert 都不能把它改回 online/pending。
                    status = CASE
                        WHEN agents.status = 'revoked' THEN agents.status
                        ELSE EXCLUDED.status
                    END,
                    last_seen_at = EXCLUDED.last_seen_at",
                    &[
                        &agent.agent_id,
                        &agent.name,
                        &agent.hostname,
                        &agent.os,
                        &agent.arch,
                        &agent.version,
                        &agent.boot_id,
                        &agent.status,
                        &agent.last_seen_at,
                        &agent.created_at,
                    ],
                )
                .context("执行 upsert_agent SQL 失败")?;
            Ok(())
        })
        .context("upsert_agent")
    }

    /// 刷新在线状态与最后活跃时间；不覆盖 `revoked`。
    pub fn mark_seen(&self, agent_id: &str, ts: i64) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    "UPDATE agents
                     SET last_seen_at = $2,
                         status = CASE
                             WHEN status = 'revoked' THEN status
                             ELSE 'online'
                         END
                     WHERE agent_id = $1",
                    &[&agent_id, &ts],
                )
                .context("执行 mark_seen SQL 失败")?;
            Ok(())
        })
        .context("mark_seen")
    }

    /// 修改状态（online / offline / revoked / pending）；`revoked` 不被覆盖。
    pub fn set_status(&self, agent_id: &str, status: &str, ts: i64) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    "UPDATE agents
                     SET status = CASE
                             WHEN status = 'revoked' THEN status
                             ELSE $2
                         END,
                         last_seen_at = $3
                     WHERE agent_id = $1",
                    &[&agent_id, &status, &ts],
                )
                .context("执行 set_status SQL 失败")?;
            Ok(())
        })
        .context("set_status")
    }

    /// hub 启动时把遗留 `online` 清成 `offline`，返回受影响行数。
    pub fn reset_online_status(&self) -> Result<usize> {
        let updated = self
            .with_client(|client| {
                client
                    .execute(
                        "UPDATE agents SET status = 'offline' WHERE status = 'online'",
                        &[],
                    )
                    .context("执行 reset_online_status SQL 失败")
            })
            .context("reset_online_status")?;
        usize::try_from(updated).context("reset_online_status 返回了超出 usize 的行数")
    }

    /// 写入一批采样点，按 `(agent_id, epoch, seq)` 幂等；吊销检查同事务。
    ///
    /// 非法数据（NUL / NaN / Inf）在建立连接前直接拒绝；判重用
    /// `INSERT ... ON CONFLICT DO NOTHING RETURNING` 原子占位，两个并发同键
    /// 批次只会有一个真正插入 samples，另一个返回 [`IngestOutcome::Duplicate`]。
    pub fn insert_batch(&self, batch: &SampleBatch) -> Result<IngestOutcome> {
        // NUL / NaN / Inf 必须在任何数据库操作之前拒绝：不占位、不写任何行。
        if let Some(reason) = invalid_batch(batch) {
            return Ok(IngestOutcome::Rejected(reason));
        }
        let epoch = i64::try_from(batch.epoch).context("insert_batch: epoch 超出 BIGINT 范围")?;
        let seq = i64::try_from(batch.seq).context("insert_batch: seq 超出 BIGINT 范围")?;

        self.with_client(|client| {
            let mut tx = client.transaction().context("开启 insert_batch 事务失败")?;

            // 吊销检查与写入必须在同一事务内：命中后不写任何数据。
            let revoked: bool = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM revoked_agents WHERE agent_id = $1)",
                    &[&batch.agent_id],
                )
                .context("检查 agent 是否已吊销失败")?
                .get(0);
            if revoked {
                tx.rollback().context("回滚 insert_batch 事务失败")?;
                return Ok(IngestOutcome::Rejected(RejectReason::Revoked));
            }

            // 原子占位：并发同键事务由主键唯一约束串行化，只有一个能拿到行；
            // 拿不到说明另一个事务已（或正在）写入同一批次，整批按 Duplicate
            // 处理。占位与 samples/ingest_state 同事务，后续失败会整体回滚。
            // TTL 以 hub 接收时间为准，避免 agent 时钟偏差导致过早/永不清理。
            let received_at = now_ms();
            let claimed = tx
                .query_opt(
                    "INSERT INTO ingest_batches (agent_id, epoch, seq, ts)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT (agent_id, epoch, seq) DO NOTHING
                     RETURNING agent_id",
                    &[&batch.agent_id, &epoch, &seq, &received_at],
                )
                .context("原子占位 ingest_batches 失败")?;
            if claimed.is_none() {
                tx.commit().context("提交重复批次事务失败")?;
                return Ok(IngestOutcome::Duplicate);
            }

            let mut inserted = 0usize;
            let statement = tx
                .prepare(
                    "INSERT INTO samples (agent_id, metric, labels, ts, value)
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .context("准备 samples 插入语句失败")?;
            for sample in &batch.samples {
                let labels =
                    serde_json::to_string(&sample.labels).context("序列化采样 labels 失败")?;
                tx.execute(
                    &statement,
                    &[
                        &batch.agent_id,
                        &sample.metric,
                        &labels,
                        &sample.ts,
                        &sample.value,
                    ],
                )
                .context("插入采样点失败")?;
                inserted += 1;
            }

            tx.execute(
                "INSERT INTO ingest_state (agent_id, epoch, last_seq, updated_at)
                 VALUES ($1, $2, $3, $4)
                 ON CONFLICT (agent_id, epoch) DO UPDATE SET
                    last_seq = GREATEST(ingest_state.last_seq, EXCLUDED.last_seq),
                    updated_at = EXCLUDED.updated_at",
                &[&batch.agent_id, &epoch, &seq, &batch.sent_at],
            )
            .context("写入 ingest_state 失败")?;

            // 每 512 次成功插入清理一次 48h 前的判重记录，避免每批都 DELETE。
            let completed = self.inserted_batches.fetch_add(1, Ordering::Relaxed) + 1;
            if completed.is_multiple_of(INGEST_CLEANUP_EVERY) {
                prune_ingest_batches(&mut tx, now_ms())?;
            }

            tx.commit().context("提交 insert_batch 事务失败")?;
            Ok(IngestOutcome::Inserted { inserted })
        })
        .context("insert_batch")
    }

    /// 列出全部 agent，按 name 升序（与 SQLite 的 `ORDER BY name` 一致）。
    pub fn list_agents(&self) -> Result<Vec<AgentRecord>> {
        self.with_client(|client| {
            let rows = client
                .query(
                    "SELECT agent_id, name, hostname, os, arch, version, boot_id, status,
                            last_seen_at, created_at
                     FROM agents
                     ORDER BY name COLLATE \"C\", agent_id COLLATE \"C\"",
                    &[],
                )
                .context("执行 list_agents SQL 失败")?;
            Ok(rows.iter().map(agent_from_row).collect())
        })
        .context("list_agents")
    }

    /// 按 agent_id 读取元信息；不存在返回 `None`。
    pub fn get_agent(&self, agent_id: &str) -> Result<Option<AgentRecord>> {
        self.with_client(|client| {
            let row = client
                .query_opt(
                    "SELECT agent_id, name, hostname, os, arch, version, boot_id, status,
                            last_seen_at, created_at
                     FROM agents WHERE agent_id = $1",
                    &[&agent_id],
                )
                .context("执行 get_agent SQL 失败")?;
            Ok(row.as_ref().map(agent_from_row))
        })
        .context("get_agent")
    }

    /// 原始采样查询：按 `ts`、`id` 升序，`limit` 在 SQL 层生效。
    pub fn query_series(&self, query: &SeriesQuery) -> Result<Vec<SeriesRow>> {
        let limit = i64::from(query.limit);
        self.with_client(|client| {
            let mut sql = String::from(
                "SELECT metric, labels, ts, value FROM samples
                 WHERE agent_id = $1 AND ts >= $2 AND ts <= $3",
            );
            let mut params: Vec<&(dyn ToSql + Sync)> =
                vec![&query.agent_id, &query.from, &query.to];
            sql.push_str(&metric_in_clause(&query.metrics, params.len() + 1));
            for metric in &query.metrics {
                params.push(metric);
            }
            // PG 额外用 id 稳定同一 ts 内的顺序；与 SQLite 的 rowid 顺序等价。
            sql.push_str(&format!(
                " ORDER BY ts ASC, id ASC LIMIT ${}",
                params.len() + 1
            ));
            params.push(&limit);

            let rows = client
                .query(&sql, &params)
                .context("执行 query_series SQL 失败")?;
            Ok(rows.iter().map(series_row_from_row).collect())
        })
        .context("query_series")
    }

    /// 按时间桶聚合：`GROUP BY metric, labels, floor(ts/bucket_ms)*bucket_ms`。
    pub fn query_series_bucketed(
        &self,
        query: &SeriesQuery,
        bucket_ms: i64,
    ) -> Result<Vec<SeriesRow>> {
        if bucket_ms <= 0 {
            bail!("bucket_ms 必须大于 0");
        }
        let limit = i64::from(query.limit);
        self.with_client(|client| {
            let mut sql = String::from(
                "SELECT metric, labels, (ts / $4) * $4 AS bucket_ts, AVG(value)
                 FROM samples
                 WHERE agent_id = $1 AND ts >= $2 AND ts <= $3",
            );
            let mut params: Vec<&(dyn ToSql + Sync)> =
                vec![&query.agent_id, &query.from, &query.to, &bucket_ms];
            sql.push_str(&metric_in_clause(&query.metrics, params.len() + 1));
            for metric in &query.metrics {
                params.push(metric);
            }
            sql.push_str(&format!(
                " GROUP BY metric, labels, bucket_ts
                  ORDER BY metric COLLATE \"C\", labels COLLATE \"C\", bucket_ts
                  LIMIT ${}",
                params.len() + 1
            ));
            params.push(&limit);

            let rows = client
                .query(&sql, &params)
                .context("执行 query_series_bucketed SQL 失败")?;
            Ok(rows.iter().map(series_row_from_row).collect())
        })
        .context("query_series_bucketed")
    }

    /// 按数据层做时间桶聚合：raw 委托 bucketed；1m/1h 按 count 加权平均。
    pub fn query_series_tiered(
        &self,
        query: &SeriesQuery,
        bucket_ms: i64,
        tier: SampleTier,
    ) -> Result<Vec<SeriesRow>> {
        if bucket_ms <= 0 {
            bail!("bucket_ms 必须大于 0");
        }
        if tier == SampleTier::Raw {
            return self.query_series_bucketed(query, bucket_ms);
        }
        let (table, tier_granularity) = match tier {
            SampleTier::Raw => unreachable!("raw 已在上面委托 bucketed"),
            SampleTier::OneMinute => ("samples_1m", BUCKET_1M_MS),
            SampleTier::OneHour => ("samples_1h", BUCKET_1H_MS),
        };
        // 与 SQLite 相同的桶重叠规则：bucket_ts + 层粒度 > from（改写为
        // bucket_ts > from - 层粒度，避免列上表达式），且 bucket_ts <= to。
        let from = query.from.saturating_sub(tier_granularity);
        let limit = i64::from(query.limit);

        self.with_client(|client| {
            let mut sql = format!(
                "SELECT metric, labels, (bucket_ts / $4) * $4 AS query_ts,
                        CAST(SUM(avg_value * count) AS DOUBLE PRECISION) / SUM(count)
                 FROM {table}
                 WHERE agent_id = $1 AND bucket_ts > $2 AND bucket_ts <= $3"
            );
            let mut params: Vec<&(dyn ToSql + Sync)> =
                vec![&query.agent_id, &from, &query.to, &bucket_ms];
            sql.push_str(&metric_in_clause(&query.metrics, params.len() + 1));
            for metric in &query.metrics {
                params.push(metric);
            }
            sql.push_str(&format!(
                " GROUP BY metric, labels, query_ts
                  ORDER BY metric COLLATE \"C\", labels COLLATE \"C\", query_ts
                  LIMIT ${}",
                params.len() + 1
            ));
            params.push(&limit);

            let rows = client
                .query(&sql, &params)
                .context("执行 query_series_tiered SQL 失败")?;
            Ok(rows.iter().map(series_row_from_row).collect())
        })
        .context("query_series_tiered")
    }

    /// 取 `since` 之后、指定指标（空表示全部）的最新点。
    ///
    /// 与 SQLite 相同：先 raw；raw 完全没有数据才依次回退 1m、1h，任一层有
    /// 数据就不再继续。每层 SQL 先按固定上限截断，达到上限时返回
    /// [`QueryTooLarge`]，避免返回可能缺序列的快照。
    pub fn latest_samples(
        &self,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
    ) -> Result<Vec<AgentSeriesRow>> {
        let rows = self.latest_raw_samples(since, metrics, agent)?;
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

    /// raw 层最新点：SQL 侧最多取 `LATEST_SAMPLES_SQL_LIMIT` 行。
    fn latest_raw_samples(
        &self,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
    ) -> Result<Vec<AgentSeriesRow>> {
        let limit = i64::try_from(LATEST_SAMPLES_SQL_LIMIT).unwrap_or(i64::MAX);
        let rows = self
            .with_client(|client| {
                let mut sql = String::from(
                    "SELECT agent_id, metric, labels, ts, value FROM samples WHERE ts >= $1",
                );
                let mut params: Vec<&(dyn ToSql + Sync)> = vec![&since];
                if let Some(agent_id) = agent.as_ref() {
                    sql.push_str(&format!(" AND agent_id = ${}", params.len() + 1));
                    // `agent` 参数活得比 params 久；这里借用 Option 里的
                    // `&str`，避免借用 if-let 的临时绑定。
                    params.push(agent_id);
                }
                sql.push_str(&metric_in_clause(metrics, params.len() + 1));
                for metric in metrics {
                    params.push(metric);
                }
                // 同 ts 用 id 升序，与 SQLite 的 rowid 升序一致（后到者覆盖）。
                sql.push_str(&format!(
                    " ORDER BY agent_id COLLATE \"C\", metric COLLATE \"C\", \
                     labels COLLATE \"C\", ts ASC, id ASC LIMIT ${}",
                    params.len() + 1
                ));
                params.push(&limit);

                let rows = client
                    .query(&sql, &params)
                    .context("执行 latest_samples raw SQL 失败")?;
                Ok(rows.iter().map(agent_series_row_from_row).collect())
            })
            .context("latest_samples")?;
        dedupe_latest_samples(
            rows,
            LATEST_SAMPLES_SQL_LIMIT,
            since,
            metrics,
            agent,
            SampleTier::Raw,
        )
    }

    /// 1m/1h 回退：取 `since` 之后某层每个序列的最新桶。
    fn latest_tier_samples(
        &self,
        tier: SampleTier,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
    ) -> Result<Vec<AgentSeriesRow>> {
        let (table, tier_granularity) = match tier {
            SampleTier::Raw => unreachable!("raw 不应走 latest_tier_samples"),
            SampleTier::OneMinute => ("samples_1m", BUCKET_1M_MS),
            SampleTier::OneHour => ("samples_1h", BUCKET_1H_MS),
        };
        let from = since.saturating_sub(tier_granularity);
        let until = now_ms();
        let limit = i64::try_from(LATEST_SAMPLES_SQL_LIMIT).unwrap_or(i64::MAX);

        let rows = self
            .with_client(|client| {
                let mut sql = format!(
                    "SELECT agent_id, metric, labels, bucket_ts, last_value
                     FROM {table}
                     WHERE bucket_ts > $1 AND bucket_ts <= $2"
                );
                let mut params: Vec<&(dyn ToSql + Sync)> = vec![&from, &until];
                if let Some(agent_id) = agent.as_ref() {
                    sql.push_str(&format!(" AND agent_id = ${}", params.len() + 1));
                    // `agent` 参数活得比 params 久；这里借用 Option 里的
                    // `&str`，避免借用 if-let 的临时绑定。
                    params.push(agent_id);
                }
                sql.push_str(&metric_in_clause(metrics, params.len() + 1));
                for metric in metrics {
                    params.push(metric);
                }
                sql.push_str(&format!(
                    " ORDER BY agent_id COLLATE \"C\", metric COLLATE \"C\", \
                     labels COLLATE \"C\", bucket_ts ASC, id ASC LIMIT ${}",
                    params.len() + 1
                ));
                params.push(&limit);

                let rows = client
                    .query(&sql, &params)
                    .context("执行 latest_samples 聚合层 SQL 失败")?;
                Ok(rows.iter().map(agent_series_row_from_row).collect())
            })
            .context("latest_samples")?;
        dedupe_latest_samples(rows, LATEST_SAMPLES_SQL_LIMIT, since, metrics, agent, tier)
    }

    /// 读取 agent 的显式采样间隔；没有配置过返回 `None`。
    pub fn get_sample_interval(&self, agent_id: &str) -> Result<Option<u64>> {
        self.with_client(|client| {
            let stored: Option<i64> = client
                .query_opt(
                    "SELECT sample_interval_ms FROM agent_settings WHERE agent_id = $1",
                    &[&agent_id],
                )
                .context("执行 get_sample_interval SQL 失败")?
                .map(|row| row.get(0));
            Ok(stored.and_then(|ms| u64::try_from(ms).ok()))
        })
        .context("get_sample_interval")
    }

    /// 写入/更新 agent 的采样间隔。
    pub fn set_sample_interval(&self, agent_id: &str, ms: u64, now: i64) -> Result<()> {
        let ms = i64::try_from(ms).context("set_sample_interval: sample_interval_ms 超出范围")?;
        self.with_client(|client| {
            client
                .execute(
                    "INSERT INTO agent_settings (agent_id, sample_interval_ms, updated_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (agent_id) DO UPDATE SET
                        sample_interval_ms = EXCLUDED.sample_interval_ms,
                        updated_at = EXCLUDED.updated_at",
                    &[&agent_id, &ms, &now],
                )
                .context("执行 set_sample_interval SQL 失败")?;
            Ok(())
        })
        .context("set_sample_interval")
    }

    /// 列出所有显式配置过采样间隔的 agent（按 agent_id 升序）。
    pub fn list_sample_intervals(&self) -> Result<Vec<(String, u64)>> {
        self.with_client(|client| {
            let rows = client
                .query(
                    "SELECT agent_id, sample_interval_ms FROM agent_settings
                     ORDER BY agent_id COLLATE \"C\"",
                    &[],
                )
                .context("执行 list_sample_intervals SQL 失败")?;
            let mut out = Vec::with_capacity(rows.len());
            for row in &rows {
                let agent_id: String = row.get(0);
                let ms: i64 = row.get(1);
                if let Ok(ms) = u64::try_from(ms) {
                    out.push((agent_id, ms));
                }
            }
            Ok(out)
        })
        .context("list_sample_intervals")
    }

    /// 某台 agent 的 raw 采样点数。
    pub fn sample_count(&self, agent_id: &str) -> Result<i64> {
        self.with_client(|client| {
            let count: i64 = client
                .query_one(
                    "SELECT COUNT(*)::BIGINT FROM samples WHERE agent_id = $1",
                    &[&agent_id],
                )
                .context("执行 sample_count SQL 失败")?
                .get(0);
            Ok(count)
        })
        .context("sample_count")
    }

    // ---- 纳管与吊销 ----

    /// 写入一条一次性 enrollment token（只存哈希）。
    pub fn create_enroll_token(
        &self,
        token_hash: &str,
        name: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    "INSERT INTO enroll_tokens (token_hash, name, created_at, expires_at, used_at)
                     VALUES ($1, $2, $3, $4, NULL)",
                    &[&token_hash, &name, &created_at, &expires_at],
                )
                .context("执行 create_enroll_token SQL 失败")?;
            Ok(())
        })
        .context("create_enroll_token")
    }

    /// 原子消费 token：未使用且未过期时标记 used_at 并返回绑定名字。
    ///
    /// 单条 `UPDATE ... RETURNING` 与 SQLite 的「事务内 SELECT + UPDATE」等价，
    /// 且在 PG 多连接并发下不会让同一 token 被消费两次。
    pub fn consume_enroll_token(&self, token_hash: &str, now: i64) -> Result<Option<String>> {
        self.with_client(|client| {
            let row = client
                .query_opt(
                    "UPDATE enroll_tokens SET used_at = $2
                     WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
                     RETURNING name",
                    &[&token_hash, &now],
                )
                .context("执行 consume_enroll_token SQL 失败")?;
            Ok(row.map(|row| row.get(0)))
        })
        .context("consume_enroll_token")
    }

    /// 保存 agent 的长期密钥哈希（UPSERT）。
    pub fn set_agent_secret(
        &self,
        agent_id: &str,
        secret_hash: &str,
        created_at: i64,
    ) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    "INSERT INTO agent_secrets (agent_id, secret_hash, created_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (agent_id) DO UPDATE SET
                        secret_hash = EXCLUDED.secret_hash,
                        created_at = EXCLUDED.created_at",
                    &[&agent_id, &secret_hash, &created_at],
                )
                .context("执行 set_agent_secret SQL 失败")?;
            Ok(())
        })
        .context("set_agent_secret")
    }

    /// 常数时间比较 agent 密钥哈希；没有记录返回 `false`。
    pub fn verify_agent_secret(&self, agent_id: &str, secret_hash: &str) -> Result<bool> {
        self.with_client(|client| {
            let stored: Option<String> = client
                .query_opt(
                    "SELECT secret_hash FROM agent_secrets WHERE agent_id = $1",
                    &[&agent_id],
                )
                .context("执行 verify_agent_secret SQL 失败")?
                .map(|row| row.get(0));
            Ok(stored
                .map(|stored| constant_time_eq(stored.as_bytes(), secret_hash.as_bytes()))
                .unwrap_or(false))
        })
        .context("verify_agent_secret")
    }

    /// 吊销 agent：写 revoked_agents、状态置 revoked、删除长期密钥，同一事务。
    pub fn revoke_agent(&self, agent_id: &str, ts: i64) -> Result<()> {
        self.with_client(|client| {
            let mut tx = client.transaction().context("开启 revoke_agent 事务失败")?;
            tx.execute(
                "INSERT INTO revoked_agents (agent_id, revoked_at)
                 VALUES ($1, $2)
                 ON CONFLICT (agent_id) DO UPDATE SET revoked_at = EXCLUDED.revoked_at",
                &[&agent_id, &ts],
            )
            .context("写入 revoked_agents 失败")?;
            tx.execute(
                "UPDATE agents SET status = 'revoked' WHERE agent_id = $1",
                &[&agent_id],
            )
            .context("更新 agents.status 为 revoked 失败")?;
            tx.execute(
                "DELETE FROM agent_secrets WHERE agent_id = $1",
                &[&agent_id],
            )
            .context("删除 agent_secrets 失败")?;
            tx.commit().context("提交 revoke_agent 事务失败")?;
            Ok(())
        })
        .context("revoke_agent")
    }

    /// agent 是否已吊销。
    pub fn is_revoked(&self, agent_id: &str) -> Result<bool> {
        self.with_client(|client| {
            let revoked: bool = client
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM revoked_agents WHERE agent_id = $1)",
                    &[&agent_id],
                )
                .context("执行 is_revoked SQL 失败")?
                .get(0);
            Ok(revoked)
        })
        .context("is_revoked")
    }

    // ---- 控制面能力 ----

    /// 覆盖写入 agent 上报的控制能力（Hello 后调用）。
    pub fn upsert_agent_control(
        &self,
        agent_id: &str,
        capabilities: &[String],
        updated_at: i64,
    ) -> Result<()> {
        let json = serde_json::to_string(capabilities).context("序列化控制能力失败")?;
        self.with_client(|client| {
            client
                .execute(
                    "INSERT INTO agent_control (agent_id, capabilities, updated_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (agent_id) DO UPDATE SET
                        capabilities = EXCLUDED.capabilities,
                        updated_at = EXCLUDED.updated_at",
                    &[&agent_id, &json, &updated_at],
                )
                .context("执行 upsert_agent_control SQL 失败")?;
            Ok(())
        })
        .context("upsert_agent_control")
    }

    /// 读取 agent 最近一次上报的控制能力；从未上报返回 `None`。
    pub fn get_agent_control(&self, agent_id: &str) -> Result<Option<AgentControlRecord>> {
        self.with_client(|client| {
            let row = client
                .query_opt(
                    "SELECT capabilities, updated_at FROM agent_control WHERE agent_id = $1",
                    &[&agent_id],
                )
                .context("执行 get_agent_control SQL 失败")?;
            let Some(row) = row else {
                return Ok(None);
            };
            let json: String = row.get(0);
            let updated_at: i64 = row.get(1);
            // 数据库内容可能来自旧版本或被损坏：解析失败降级为空能力，而不是
            // 让控制 API 500；读取结果仍返回记录，调用方按 403 处理。
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
        })
        .context("get_agent_control")
    }
}

/// 生成 ` AND metric IN ($N, ...)`；metrics 为空时返回空串。
///
/// 只由调用方传入的下标决定占位符编号，metric 值本身始终参数绑定。
fn metric_in_clause(metrics: &[String], first_placeholder: usize) -> String {
    if metrics.is_empty() {
        return String::new();
    }
    let holders: Vec<String> = (0..metrics.len())
        .map(|index| format!("${}", first_placeholder + index))
        .collect();
    format!(" AND metric IN ({})", holders.join(","))
}

/// agent 行映射：列顺序与各 SQL 的 SELECT 列表一致。
fn agent_from_row(row: &Row) -> AgentRecord {
    AgentRecord {
        agent_id: row.get(0),
        name: row.get(1),
        hostname: row.get(2),
        os: row.get(3),
        arch: row.get(4),
        version: row.get(5),
        boot_id: row.get(6),
        status: row.get(7),
        last_seen_at: row.get(8),
        created_at: row.get(9),
    }
}

/// `(metric, labels, ts, value)` 行映射；labels 解析失败回退空标签。
fn series_row_from_row(row: &Row) -> SeriesRow {
    let labels_json: String = row.get(1);
    SeriesRow {
        metric: row.get(0),
        labels: parse_labels(&labels_json),
        ts: row.get(2),
        value: row.get(3),
    }
}

/// `(agent_id, metric, labels, ts, value)` 行映射。
fn agent_series_row_from_row(row: &Row) -> AgentSeriesRow {
    let labels_json: String = row.get(2);
    AgentSeriesRow {
        agent_id: row.get(0),
        metric: row.get(1),
        labels: parse_labels(&labels_json),
        ts: row.get(3),
        value: row.get(4),
    }
}

fn parse_labels(json: &str) -> Labels {
    serde_json::from_str(json).unwrap_or_default()
}

/// 与 SQLite 相同的上限检查与按序列去重。
///
/// `rows` 必须已按 `(agent_id, metric, labels, ts)` 升序；同键后到的（更新的
/// ts）覆盖先到的。用 BTreeMap 保证输出顺序稳定。达到硬上限时返回
/// [`QueryTooLarge`] 而不是静默截断。
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

    let mut latest: BTreeMap<(String, String, Labels), AgentSeriesRow> = BTreeMap::new();
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

/// 清理 48h 前的 ingest_batches 判重记录（在 insert_batch 事务内执行）。
fn prune_ingest_batches(tx: &mut postgres::Transaction<'_>, now: i64) -> Result<()> {
    let cutoff = now.saturating_sub(INGEST_BATCH_TTL_MS);
    let removed = tx
        .execute("DELETE FROM ingest_batches WHERE ts < $1", &[&cutoff])
        .context("清理过期 ingest_batches 失败")?;
    if removed > 0 {
        tracing::debug!(removed, cutoff, "已清理过期 ingest_batches 判重记录");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_series(agent_id: &str, ts: i64, value: f64) -> AgentSeriesRow {
        AgentSeriesRow {
            agent_id: agent_id.to_string(),
            metric: "cpu.usage".to_string(),
            labels: Labels::new(),
            ts,
            value,
        }
    }

    #[test]
    fn query_too_large_survives_method_context() {
        // hub 用 `err.downcast_ref::<QueryTooLarge>()` 映射 413；这里锁住
        // anyhow 在追加方法名上下文后仍能向下转型的行为。
        let err = anyhow::Error::new(QueryTooLarge { limit: 100_000 }).context("latest_samples");
        assert!(
            err.downcast_ref::<QueryTooLarge>().is_some(),
            "QueryTooLarge 不能被上下文包装吞掉"
        );
    }

    #[test]
    fn dedupe_keeps_newest_ts_per_series_and_is_stable() {
        let rows = vec![
            agent_series("a2", 1, 1.0),
            agent_series("a1", 1, 10.0),
            agent_series("a1", 3, 30.0),
            agent_series("a1", 2, 20.0),
        ];
        let latest = dedupe_latest_samples(rows, 100, 0, &[], None, SampleTier::Raw).unwrap();
        assert_eq!(latest.len(), 2);
        assert_eq!(latest[0].agent_id, "a1", "输出必须按 agent_id 升序");
        assert_eq!(latest[0].ts, 3);
        assert_eq!(latest[0].value, 30.0);
        assert_eq!(latest[1].agent_id, "a2");
        assert_eq!(latest[1].ts, 1);
    }

    #[test]
    fn dedupe_hits_limit_and_returns_query_too_large() {
        let rows = vec![agent_series("a1", 1, 1.0), agent_series("a2", 2, 2.0)];
        let err = dedupe_latest_samples(rows, 2, 0, &[], None, SampleTier::Raw)
            .expect_err("达到上限必须返回 QueryTooLarge");
        assert_eq!(
            err.downcast_ref::<QueryTooLarge>(),
            Some(&QueryTooLarge { limit: 2 })
        );
    }

    #[test]
    fn metric_clause_only_varies_placeholder_count() {
        let metrics = vec!["a".to_string(), "b".to_string()];
        assert_eq!(metric_in_clause(&metrics, 4), " AND metric IN ($4,$5)");
        assert_eq!(metric_in_clause(&[], 4), "");
    }
}
