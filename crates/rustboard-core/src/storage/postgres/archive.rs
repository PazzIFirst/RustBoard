//! PostgreSQL 降采样 / 保留期 / 归档域。
//!
//! 本文件只写 [`PostgresStorage`] 的**固有方法**，签名与
//! [`Storage`](crate::storage::Storage) trait 中对应方法逐字一致；统一
//! `impl Storage for PostgresStorage` 由最后的转发层一次性补齐。
//!
//! # 与 SQLite 基线的对应关系
//!
//! SQLite 借助隐式 `rowid` 完成「同一 `ts` 的稳定次序」和 raw 删除游标。
//! PostgreSQL 在 schema v7 里为 `samples` / `samples_1m` / `samples_1h` 增加了
//! `id BIGSERIAL PRIMARY KEY`，本文件把 SQLite 的 `rowid` 一律映射为 `id`：
//!
//! - [`PostgresStorage::raw_new_rows`] 返回 `MAX(samples.id)`，语义仍是
//!   `(max_rowid, oldest_ts)`；
//! - [`PostgresStorage::claim_raw_rowid_if_unchanged`] 的参数/返回值仍是
//!   `Option<i64>` / `bool`，内部读写 `maintenance_state` 的同一个键；
//! - [`PostgresStorage::scan_archive_rows`] 的 [`ArchiveRawRow::rowid`] 取
//!   `samples.id`；
//! - 删除按 `DELETE ... WHERE id IN (SELECT id ... LIMIT $2)` 分批。
//!
//! 1m 聚合用窗口函数 `FIRST_VALUE(value) OVER (PARTITION ... ORDER BY
//! ts DESC, id DESC)` 取桶内最后一个值；1h 的 `avg_value` 用
//! `SUM(avg_value * count) / SUM(count)` 按 `count` 加权，绝不把各分钟均值
//! 再取简单平均。upsert 目标与 schema 的 UNIQUE 约束一致：
//! `(agent_id, metric, labels, bucket_ts)`。
//!
//! 所有 SQL 值参数都用 `$N` 绑定；只有表名/列名来自本文件的编译期常量，
//! 不接受外部输入。所有方法通过 [`PostgresStorage::with_client`] 取连接，
//! 调用方必须位于 blocking 线程（同步 PG 驱动不能在 tokio worker 内直接调用）。

use anyhow::{anyhow, Context, Result};
use postgres::error::SqlState;
use postgres::Row;
use rustboard_common::util::now_ms;

use super::PostgresStorage;
use crate::archive::{ArchiveObject, ArchiveStatus, ArchiveStoreError};
use crate::downsample::STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID;
use crate::storage::sqlite::{
    validate_archive_claim, validate_archive_sha256, ArchiveRawRow, MAX_ARCHIVE_TS_MS,
    MIN_ARCHIVE_TS_MS, PRUNE_BATCH_ROWS, STATE_RAW_PRUNE_GENERATION,
};
use crate::storage::{DownsampleRangeResult, PruneResult, TierStats, BUCKET_1H_MS, BUCKET_1M_MS};

/// `archive_objects` 的 SELECT 列表；列下标与 [`row_to_archive_object`] 一一对应。
const ARCHIVE_OBJECT_COLUMNS: &str = "id, backend, object_key, manifest_key, from_ts, to_ts, \
     rows, bytes, sha256, status, error, created_at, uploaded_at, deleted_at, ledger_version, \
     attempts";

/// 1m 聚合：`[from, to)` 内 raw 行按「整分钟」聚合后 upsert。
///
/// - `bucket_ts` 的 `60000` 必须等于 [`BUCKET_1M_MS`]（单测断言）；
/// - `last_value` 取桶内最大 `ts`，同一 `ts` 取最大 `id`（等价 SQLite 的
///   最大 `rowid`）；窗口值在组内唯一，外层用 `MAX(last_value)` 取出；
/// - 按 `(agent_id, metric, labels, bucket_ts)` upsert，重复执行幂等。
const AGGREGATE_1M_SQL: &str = r#"
INSERT INTO samples_1m
    (agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, last_value, count)
SELECT agent_id, metric, labels, bucket_ts,
       MIN(value), MAX(value), AVG(value), MAX(last_value), COUNT(*)
FROM (
    SELECT agent_id, metric, labels,
           (ts / 60000) * 60000 AS bucket_ts,
           value,
           FIRST_VALUE(value) OVER (
               PARTITION BY agent_id, metric, labels, (ts / 60000) * 60000
               ORDER BY ts DESC, id DESC
           ) AS last_value
    FROM samples
    WHERE ts >= $1 AND ts < $2
) AS aggregated
GROUP BY agent_id, metric, labels, bucket_ts
ON CONFLICT (agent_id, metric, labels, bucket_ts) DO UPDATE SET
    min_value = EXCLUDED.min_value,
    max_value = EXCLUDED.max_value,
    avg_value = EXCLUDED.avg_value,
    last_value = EXCLUDED.last_value,
    count = EXCLUDED.count
"#;

/// 1h 聚合：`[from, to)` 内 1m 桶按「整点小时」聚合后 upsert。
///
/// - `avg_value` 用 `SUM(avg_value * count) / SUM(count)` 加权；
/// - `last_value` 取最新 1m 桶（`bucket_ts` 最大）的 `last_value`；唯一约束
///   保证同一桶只有一行，窗口排序不需要再加 `id`；
/// - `3600000` 必须等于 [`BUCKET_1H_MS`]（单测断言）。
const AGGREGATE_1H_SQL: &str = r#"
INSERT INTO samples_1h
    (agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, last_value, count)
SELECT agent_id, metric, labels, bucket_ts,
       MIN(min_value), MAX(max_value),
       CAST(SUM(avg_value * count) AS DOUBLE PRECISION)
           / CAST(SUM(count) AS DOUBLE PRECISION),
       MAX(last_value),
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
    WHERE bucket_ts >= $1 AND bucket_ts < $2
) AS aggregated
GROUP BY agent_id, metric, labels, bucket_ts
ON CONFLICT (agent_id, metric, labels, bucket_ts) DO UPDATE SET
    min_value = EXCLUDED.min_value,
    max_value = EXCLUDED.max_value,
    avg_value = EXCLUDED.avg_value,
    last_value = EXCLUDED.last_value,
    count = EXCLUDED.count
"#;

/// 保留期删除：每批最多 `$2` 行，`$1` 是排他 cutoff（`< cutoff`）。
///
/// PG 没有 `rowid`，用 `id IN (SELECT id ... LIMIT)` 把单批事务控制在
/// [`PRUNE_BATCH_ROWS`] 行以内；`ORDER BY` 与 SQLite 基线保持一致。
const PRUNE_RAW_SQL: &str = "DELETE FROM samples WHERE id IN \
     (SELECT id FROM samples WHERE ts < $1 ORDER BY ts LIMIT $2)";
/// v8 归档启用时的 raw 保留期：只删「已聚合且所属对象已 uploaded」的行。
///
/// 与 SQLite 的 `PRUNE_ARCHIVED_RAW_SQL` 语义一致；R1a-1 只提供原语，
/// 现有 [`PRUNE_RAW_SQL`] 的行为不变。
const PRUNE_ARCHIVED_RAW_SQL: &str = "DELETE FROM samples WHERE id IN \
     (SELECT s.id FROM samples s \
        JOIN archive_objects o ON o.id = s.archive_object_id \
      WHERE s.ts < $1 AND s.aggregated_1m = 1 AND o.status = 'uploaded' \
      ORDER BY s.ts LIMIT $2)";
const PRUNE_1M_SQL: &str = "DELETE FROM samples_1m WHERE id IN \
     (SELECT id FROM samples_1m WHERE bucket_ts < $1 ORDER BY bucket_ts LIMIT $2)";
const PRUNE_1H_SQL: &str = "DELETE FROM samples_1h WHERE id IN \
     (SELECT id FROM samples_1h WHERE bucket_ts < $1 ORDER BY bucket_ts LIMIT $2)";

/// raw 保留期删除与 rowid 水位 CAS 共用的固定事务级 advisory lock key。
///
/// 两处操作都会读改写 `maintenance_state` 的 raw 水位/代际；取同一把固定锁
/// 后，claim 的「读 rowid + generation → 条件写」与 prune 的「删行 → 收敛
/// 水位/推进代际」在数据库侧严格串行，避免 claim 把 prune 删除前的旧 MAX
/// 在删除提交后写回。必须与 [`SCHEMA_ADVISORY_LOCK_KEY`] 使用不同 key：schema
/// 锁只串行化启动迁移，不能与高频维护事务互相阻塞。
///
/// [`SCHEMA_ADVISORY_LOCK_KEY`]: super::schema::SCHEMA_ADVISORY_LOCK_KEY
const RAW_MAINTENANCE_ADVISORY_LOCK_KEY: i64 = 0x5242_5047_0000_0012;

/// raw 删除后收敛 `downsample_1m_last_raw_rowid` 的结果；`new == None`
/// 表示水位键被删除/失效，只在事务提交后用于日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RowidWatermarkChange {
    old: i64,
    new: Option<i64>,
}

/// 把时间戳向下取整到 `bucket_ms` 边界（UTC 毫秒，非负）。
///
/// 与 SQLite 的 `bucket_floor` 完全一致：使用欧几里得除法，负时间戳也向
/// 更小的边界取整。
fn bucket_floor(ts: i64, bucket_ms: i64) -> i64 {
    ts.div_euclid(bucket_ms) * bucket_ms
}

/// 把 `archive_objects.object_key` 的唯一约束冲突翻译成领域错误。
///
/// 只认 `object_key` 约束；其它数据库错误按 SQLite 基线统一成不带 SQL 细节
/// 的通用错误，避免把驱动信息透传到 API。
fn map_archive_object_insert_error(err: postgres::Error) -> anyhow::Error {
    if let Some(db_error) = err.as_db_error() {
        if db_error.code() == &SqlState::UNIQUE_VIOLATION
            && db_error
                .constraint()
                .is_some_and(|name| name.contains("object_key"))
        {
            return ArchiveStoreError::ObjectExists.into();
        }
    }
    tracing::debug!(error = %err, "写入归档对象失败（非 object_key 唯一约束错误）");
    anyhow!("写入归档对象失败（数据库错误，详见日志）")
}

/// 在调用方事务内插入归档对象并返回 `id`。
///
/// claim 必须与对象插入同事务，不能复用会自动提交的
/// [`PostgresStorage::insert_archive_object`]。
fn insert_archive_object_tx(
    tx: &mut postgres::Transaction<'_>,
    object: &ArchiveObject,
) -> Result<i64> {
    let rows = i64::try_from(object.rows).context("归档对象行数超出 BIGINT 范围")?;
    let bytes = i64::try_from(object.bytes).context("归档对象字节数超出 BIGINT 范围")?;
    let row = tx
        .query_one(
            "INSERT INTO archive_objects
                (backend, object_key, manifest_key, from_ts, to_ts, rows, bytes,
                 sha256, status, error, created_at, uploaded_at, deleted_at,
                 ledger_version, attempts)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
             RETURNING id",
            &[
                &object.backend,
                &object.object_key,
                &object.manifest_key,
                &object.from_ts,
                &object.to_ts,
                &rows,
                &bytes,
                &object.sha256,
                &object.status.as_str(),
                &object.error,
                &object.created_at,
                &object.uploaded_at,
                &object.deleted_at,
                &object.ledger_version,
                &object.attempts,
            ],
        )
        .map_err(map_archive_object_insert_error)?;
    Ok(row.get::<_, i64>(0))
}

/// 一行 `archive_objects` 映射成 [`ArchiveObject`]。
///
/// 非法状态/负数计数不静默降级，读取直接失败（与 SQLite 基线一致）。
fn row_to_archive_object(row: &Row) -> Result<ArchiveObject> {
    let status: String = row.get(9);
    let rows: i64 = row.get(6);
    let bytes: i64 = row.get(7);
    Ok(ArchiveObject {
        id: row.get(0),
        backend: row.get(1),
        object_key: row.get(2),
        manifest_key: row.get(3),
        from_ts: row.get(4),
        to_ts: row.get(5),
        rows: u64::try_from(rows).context("archive_objects.rows 字段值非法")?,
        bytes: u64::try_from(bytes).context("archive_objects.bytes 字段值非法")?,
        sha256: row.get(8),
        status: ArchiveStatus::parse(&status)
            .ok_or_else(|| anyhow!("archive_objects.status 字段值非法"))?,
        error: row.get(10),
        created_at: row.get(11),
        uploaded_at: row.get(12),
        deleted_at: row.get(13),
        ledger_version: row.get(14),
        attempts: row.get(15),
    })
}

/// 在调用方事务内把 `raw_prune_generation` 读-改-写为 +1。
///
/// 缺失或非法旧值按 1 写；`saturating_add` 防止极端脏数据下溢出。必须与
/// raw 删除处于同一事务，否则代际与删除不构成原子边界。
fn bump_raw_prune_generation(tx: &mut postgres::Transaction<'_>, now: i64) -> Result<()> {
    let current: Option<String> = tx
        .query_opt(
            "SELECT value FROM maintenance_state WHERE key = $1",
            &[&STATE_RAW_PRUNE_GENERATION],
        )
        .context("读取 raw_prune_generation 失败")?
        .map(|row| row.get(0));
    let next = current
        .and_then(|raw| raw.trim().parse::<i64>().ok())
        .map_or(1, |value| value.saturating_add(1));
    tx.execute(
        "INSERT INTO maintenance_state (key, value, updated_at)
         VALUES ($1, $2, $3)
         ON CONFLICT (key) DO UPDATE SET
             value = EXCLUDED.value,
             updated_at = EXCLUDED.updated_at",
        &[&STATE_RAW_PRUNE_GENERATION, &next.to_string(), &now],
    )
    .context("写入 raw_prune_generation 失败")?;
    Ok(())
}

/// 在调用方事务内收敛 `downsample_1m_last_raw_rowid`，并在最大 id 行被删时
/// 推进 `raw_prune_generation`。
///
/// 规则逐条对齐 SQLite 基线：
///
/// - raw 表为空：删除 rowid 水位键；
/// - 最大 id 行被删（`max_after < max_before`）且旧水位不高于 `max_after`：
///   删除键，避免并发 downsample 把删除前的旧 MAX 写回；
/// - 其余情况只降不升；
/// - 旧值缺失/非法时不新增 key；
/// - 只要最大 id 行被删，无论 rowid 水位是否存在都先把 generation +1。
///
/// **必须在 `tx` 上直接执行 SQL**：不能再调用走连接池的水位读写方法，否则
/// 会与当前事务互相等待。
fn lower_raw_rowid_watermark(
    tx: &mut postgres::Transaction<'_>,
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
        .query_opt(
            "SELECT value FROM maintenance_state WHERE key = $1",
            &[&STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID],
        )
        .context("读取 downsample_1m_last_raw_rowid 失败")?
        .map(|row| row.get(0));

    let Some(max_after) = max_after else {
        // raw 已空：残留水位会让新插入的 id（序列更大）被误判为已认领。
        let Some(old_value) = old_value else {
            return Ok(None);
        };
        tx.execute(
            "DELETE FROM maintenance_state WHERE key = $1",
            &[&STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID],
        )
        .context("删除 downsample_1m_last_raw_rowid 失败")?;
        // 历史脏值无法给出数值日志；清理本身仍然执行。
        return Ok(old_value
            .trim()
            .parse::<i64>()
            .ok()
            .map(|old| RowidWatermarkChange { old, new: None }));
    };

    let Some(old) = old_value.and_then(|raw| raw.trim().parse::<i64>().ok()) else {
        return Ok(None);
    };

    // 最大 id 行被删：即使旧水位 <= 新 MAX 也必须让键失效，否则并发
    // downsample 的 CAS 期望仍成立，会把删除前的旧 MAX 写回。
    if max_row_deleted && old <= max_after {
        tx.execute(
            "DELETE FROM maintenance_state WHERE key = $1",
            &[&STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID],
        )
        .context("失效 downsample_1m_last_raw_rowid 失败")?;
        return Ok(Some(RowidWatermarkChange { old, new: None }));
    }

    // 只降不升。
    if old <= max_after {
        return Ok(None);
    }
    tx.execute(
        "UPDATE maintenance_state SET value = $2, updated_at = $3 WHERE key = $1",
        &[
            &STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID,
            &max_after.to_string(),
            &now,
        ],
    )
    .context("下调 downsample_1m_last_raw_rowid 失败")?;
    Ok(Some(RowidWatermarkChange {
        old,
        new: Some(max_after),
    }))
}

impl PostgresStorage {
    // ---- 降采样 ----

    /// 把 `[from_ts, to_ts)` 内已关闭分钟的 raw 聚合进 `samples_1m`。
    ///
    /// 两端先按整分钟向下取整（不足一分钟的窗口返回空结果），整个区间在
    /// 单个事务内完成「统计源行数 + upsert」；重复执行幂等。
    pub fn downsample_1m_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult> {
        let from = bucket_floor(from_ts, BUCKET_1M_MS);
        let to = bucket_floor(to_ts, BUCKET_1M_MS);
        if to <= from {
            return Ok(DownsampleRangeResult::default());
        }
        self.with_client(|client| {
            let mut tx = client.transaction().context("开启 1m 降采样事务失败")?;
            let rows: i64 = tx
                .query_one(
                    "SELECT COUNT(*)::BIGINT FROM samples WHERE ts >= $1 AND ts < $2",
                    &[&from, &to],
                )
                .context("统计 1m 降采样源行数失败")?
                .get(0);
            let buckets = tx
                .execute(AGGREGATE_1M_SQL, &[&from, &to])
                .context("执行 1m 聚合 SQL 失败")?;
            tx.commit().context("提交 1m 降采样事务失败")?;
            Ok(DownsampleRangeResult {
                buckets: usize::try_from(buckets).context("1m 聚合返回了超出 usize 的桶数")?,
                rows: usize::try_from(rows).context("1m 降采样源行数溢出")?,
            })
        })
        .context("downsample_1m_range")
    }

    /// 把 `[from_ts, to_ts)` 内已完成整点的 1m 桶聚合进 `samples_1h`。
    ///
    /// 两端先按整点向下取整；`avg_value` 按 `count` 加权。重复执行幂等。
    pub fn downsample_1h_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult> {
        let from = bucket_floor(from_ts, BUCKET_1H_MS);
        let to = bucket_floor(to_ts, BUCKET_1H_MS);
        if to <= from {
            return Ok(DownsampleRangeResult::default());
        }
        self.with_client(|client| {
            let mut tx = client.transaction().context("开启 1h 降采样事务失败")?;
            let rows: i64 = tx
                .query_one(
                    "SELECT COUNT(*)::BIGINT FROM samples_1m
                     WHERE bucket_ts >= $1 AND bucket_ts < $2",
                    &[&from, &to],
                )
                .context("统计 1h 降采样源行数失败")?
                .get(0);
            let buckets = tx
                .execute(AGGREGATE_1H_SQL, &[&from, &to])
                .context("执行 1h 聚合 SQL 失败")?;
            tx.commit().context("提交 1h 降采样事务失败")?;
            Ok(DownsampleRangeResult {
                buckets: usize::try_from(buckets).context("1h 聚合返回了超出 usize 的桶数")?,
                rows: usize::try_from(rows).context("1h 降采样源行数溢出")?,
            })
        })
        .context("downsample_1h_range")
    }

    // ---- 数据层统计与分块 ----

    /// raw 层的行数与最旧 / 最新时间戳。
    pub fn raw_stats(&self) -> Result<TierStats> {
        self.tier_stats("SELECT COUNT(*)::BIGINT, MIN(ts), MAX(ts) FROM samples")
            .context("raw_stats")
    }

    /// 1m 层的行数与最旧 / 最新时间戳。
    pub fn samples_1m_stats(&self) -> Result<TierStats> {
        self.tier_stats("SELECT COUNT(*)::BIGINT, MIN(bucket_ts), MAX(bucket_ts) FROM samples_1m")
            .context("samples_1m_stats")
    }

    /// 1h 层的行数与最旧 / 最新时间戳。
    pub fn samples_1h_stats(&self) -> Result<TierStats> {
        self.tier_stats("SELECT COUNT(*)::BIGINT, MIN(bucket_ts), MAX(bucket_ts) FROM samples_1h")
            .context("samples_1h_stats")
    }

    /// 三张表的统计查询只差表名/列名；SQL 是本文件的编译期常量。
    fn tier_stats(&self, sql: &'static str) -> Result<TierStats> {
        self.with_client(|client| {
            let row = client
                .query_one(sql, &[])
                .context("执行数据层统计 SQL 失败")?;
            Ok(TierStats {
                rows: row.get(0),
                oldest_ts: row.get(1),
                newest_ts: row.get(2),
            })
        })
    }

    /// 取 raw `[from_ts, to_ts)` 内按 `(ts, id)` 升序的第 `offset` 条时间戳。
    pub fn raw_ts_at_offset(&self, from_ts: i64, to_ts: i64, offset: usize) -> Result<Option<i64>> {
        self.ts_at_offset(
            "SELECT ts FROM samples WHERE ts >= $1 AND ts < $2 \
             ORDER BY ts ASC, id ASC LIMIT 1 OFFSET $3",
            from_ts,
            to_ts,
            offset,
        )
        .context("raw_ts_at_offset")
    }

    /// 取 1m `[from_ts, to_ts)` 内按 `(bucket_ts, id)` 升序的第 `offset` 条时间戳。
    pub fn samples_1m_ts_at_offset(
        &self,
        from_ts: i64,
        to_ts: i64,
        offset: usize,
    ) -> Result<Option<i64>> {
        self.ts_at_offset(
            "SELECT bucket_ts FROM samples_1m WHERE bucket_ts >= $1 AND bucket_ts < $2 \
             ORDER BY bucket_ts ASC, id ASC LIMIT 1 OFFSET $3",
            from_ts,
            to_ts,
            offset,
        )
        .context("samples_1m_ts_at_offset")
    }

    fn ts_at_offset(
        &self,
        sql: &'static str,
        from_ts: i64,
        to_ts: i64,
        offset: usize,
    ) -> Result<Option<i64>> {
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        self.with_client(|client| {
            Ok(client
                .query_opt(sql, &[&from_ts, &to_ts, &offset])
                .context("执行时间戳偏移查询失败")?
                .map(|row| row.get::<_, i64>(0)))
        })
    }

    /// 读取 raw 当前最大 `id`，以及 `(after_rowid, max_id]` 区间内最旧 `ts`。
    ///
    /// 返回 `(None, None)` 表示 raw 为空。**先读 `MAX(id)` 再读 `MIN(ts)`**：
    /// 并发插入的行 id 更大，不会被本轮认领；即使它们的 `ts` 很旧，下一轮也
    /// 会被再次发现。`after_rowid > max_id` 说明水位来自重建前的旧库，按
    /// 「全部是新行」重新扫描（与 SQLite 基线一致，保守但不漏数据）。
    pub fn raw_new_rows(&self, after_rowid: Option<i64>) -> Result<(Option<i64>, Option<i64>)> {
        self.with_client(|client| {
            let max_id: Option<i64> = client
                .query_one("SELECT MAX(id) FROM samples", &[])
                .context("读取 samples.MAX(id) 失败")?
                .get(0);
            let Some(max_id) = max_id else {
                return Ok((None, None));
            };
            let after = match after_rowid {
                // last == max：没有新行，MIN 返回 NULL；
                // last > max：id 水位回退，按「全部是新行」重新扫描。
                Some(last) if last <= max_id => last,
                Some(_) | None => 0,
            };
            let min_ts: Option<i64> = client
                .query_one(
                    "SELECT MIN(ts) FROM samples WHERE id > $1 AND id <= $2",
                    &[&after, &max_id],
                )
                .context("读取 raw 新区间最旧 ts 失败")?
                .get(0);
            Ok((Some(max_id), min_ts))
        })
        .context("raw_new_rows")
    }

    /// 1m 层最旧桶时间；`None` 表示该层没有数据。
    pub fn samples_1m_oldest_ts(&self) -> Result<Option<i64>> {
        self.with_client(|client| {
            Ok(client
                .query_one("SELECT MIN(bucket_ts) FROM samples_1m", &[])
                .context("读取 samples_1m 最旧桶失败")?
                .get(0))
        })
        .context("samples_1m_oldest_ts")
    }

    // ---- 保留期删除 ----

    /// 分批删除 raw 中 `ts < cutoff` 的行。
    ///
    /// raw 专属：每批在一个显式事务内完成「读删除前 MAX(id) → 删除 → 读删除
    /// 后 MAX(id) → 收敛 rowid 水位 / generation → 提交」，语义与 SQLite 的
    /// `prune_raw_batched` 一致。即使本批删除 0 行也收敛一次水位，可修复残留
    /// 的高水位。
    pub fn prune_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_raw_batched(PRUNE_RAW_SQL, cutoff)
            .context("prune_samples_before")
    }

    /// v8 归档启用时的 raw 保留期：只删「已聚合且对象已 uploaded」的行。
    ///
    /// R1a-1 只提供原语，不改变 [`Self::prune_samples_before`] 的行为；
    /// R1b 在 `archive.enabled` 分支接入，并在 ledger pending 时跳过。
    pub fn prune_archived_samples_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_raw_batched(PRUNE_ARCHIVED_RAW_SQL, cutoff)
            .context("prune_archived_samples_before")
    }

    /// 分批删除 1m 中 `bucket_ts < cutoff` 的行。
    pub fn prune_samples_1m_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_batched(PRUNE_1M_SQL, cutoff)
            .context("prune_samples_1m_before")
    }

    /// 分批删除 1h 中 `bucket_ts < cutoff` 的行。
    pub fn prune_samples_1h_before(&self, cutoff: i64) -> Result<PruneResult> {
        self.prune_batched(PRUNE_1H_SQL, cutoff)
            .context("prune_samples_1h_before")
    }

    /// 每批 [`PRUNE_BATCH_ROWS`] 行；每条 `DELETE` 自动提交，批间让出 CPU。
    fn prune_batched(&self, sql: &'static str, cutoff: i64) -> Result<PruneResult> {
        let batch = PRUNE_BATCH_ROWS as i64;
        let mut result = PruneResult::default();
        loop {
            let deleted = self.with_client(|client| {
                client
                    .execute(sql, &[&cutoff, &batch])
                    .context("执行保留期删除 SQL 失败")
            })?;
            if deleted == 0 {
                break;
            }
            let deleted = usize::try_from(deleted).context("保留期删除返回了超出 usize 的行数")?;
            result.deleted += deleted;
            result.batches += 1;
            if deleted < PRUNE_BATCH_ROWS {
                break;
            }
            std::thread::yield_now();
        }
        Ok(result)
    }

    /// raw 专属分批删除，见 [`Self::prune_samples_before`]。
    ///
    /// `sql` 只来自本文件的编译期常量（普通 raw 删除 / 归档 uploaded join）。
    fn prune_raw_batched(&self, sql: &'static str, cutoff: i64) -> Result<PruneResult> {
        let batch = PRUNE_BATCH_ROWS as i64;
        let mut result = PruneResult::default();
        loop {
            let (deleted, change) = self.with_client(|client| {
                let mut tx = client
                    .transaction()
                    .context("开启 raw 保留期删除事务失败")?;
                // 与 claim 共用固定事务级锁：删除+收敛水位必须是一个原子边界。
                tx.query_one(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&RAW_MAINTENANCE_ADVISORY_LOCK_KEY],
                )
                .context("获取 raw 维护 advisory lock 失败")?;
                let max_before: Option<i64> = tx
                    .query_one("SELECT MAX(id) FROM samples", &[])
                    .context("读取删除前 samples.MAX(id) 失败")?
                    .get(0);
                let deleted = tx
                    .execute(sql, &[&cutoff, &batch])
                    .context("执行 raw 保留期删除 SQL 失败")?;
                let max_after: Option<i64> = tx
                    .query_one("SELECT MAX(id) FROM samples", &[])
                    .context("读取删除后 samples.MAX(id) 失败")?
                    .get(0);
                // 即使本批删除 0 行也收敛一次：可修复历史遗留的高水位，
                // 包括 raw 已空但 maintenance_state 仍残留水位键的情况。
                let change = lower_raw_rowid_watermark(&mut tx, max_before, max_after, now_ms())?;
                tx.commit().context("提交 raw 保留期删除事务失败")?;
                Ok((deleted, change))
            })?;

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
            let deleted =
                usize::try_from(deleted).context("raw 保留期删除返回了超出 usize 的行数")?;
            result.deleted += deleted;
            result.batches += 1;
            if deleted < PRUNE_BATCH_ROWS {
                break;
            }
            std::thread::yield_now();
        }
        Ok(result)
    }

    /// CAS 认领 raw `id` 水位：rowid 与 generation 都等于期望时才写 `new_max`。
    ///
    /// 在同一个事务内做「读当前 rowid + generation + 条件写」，任一不匹配都
    /// 返回 `false`，调用方本轮不认领，下一轮从更低位重扫。generation 缺失
    /// 视为 0；当前 generation 非法时视为不匹配（不覆盖）。`expected_rowid`
    /// 为 `None` 表示调用方读到键缺失，只有当前仍缺失才算匹配。
    pub fn claim_raw_rowid_if_unchanged(
        &self,
        expected_rowid: Option<i64>,
        expected_generation: i64,
        new_max: i64,
    ) -> Result<bool> {
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 rowid 水位 CAS 事务失败")?;
            // 与 raw 保留期删除共用同一把事务级锁：读水位/代际与条件写不能被
            // prune 的「删行 + 推进代际」穿插，否则可能写回删除前的旧 MAX。
            tx.query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&RAW_MAINTENANCE_ADVISORY_LOCK_KEY],
            )
            .context("获取 raw 维护 advisory lock 失败")?;
            let current_rowid: Option<String> = tx
                .query_opt(
                    "SELECT value FROM maintenance_state WHERE key = $1",
                    &[&STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID],
                )
                .context("读取当前 downsample_1m_last_raw_rowid 失败")?
                .map(|row| row.get(0));
            let current_generation: Option<String> = tx
                .query_opt(
                    "SELECT value FROM maintenance_state WHERE key = $1",
                    &[&STATE_RAW_PRUNE_GENERATION],
                )
                .context("读取当前 raw_prune_generation 失败")?
                .map(|row| row.get(0));

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
                tx.commit().context("提交未命中的 CAS 事务失败")?;
                return Ok(false);
            }
            tx.execute(
                "INSERT INTO maintenance_state (key, value, updated_at)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (key) DO UPDATE SET
                     value = EXCLUDED.value,
                     updated_at = EXCLUDED.updated_at",
                &[
                    &STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID,
                    &new_max.to_string(),
                    &now_ms(),
                ],
            )
            .context("写入 raw id 水位失败")?;
            tx.commit().context("提交 rowid 水位 CAS 事务失败")?;
            Ok(true)
        })
        .context("claim_raw_rowid_if_unchanged")
    }

    // ---- 归档对象 ----

    /// 插入一条归档对象记录，返回数据库生成的 `id`。
    ///
    /// `object.id` 被忽略；`object_key` 重复返回
    /// [`ArchiveStoreError::ObjectExists`]，不会覆盖已有记录。
    pub fn insert_archive_object(&self, object: &ArchiveObject) -> Result<i64> {
        self.with_client(|client| {
            let mut tx = client.transaction().context("开启归档对象插入事务失败")?;
            let id = insert_archive_object_tx(&mut tx, object)?;
            tx.commit().context("提交归档对象插入事务失败")?;
            Ok(id)
        })
        .context("insert_archive_object")
    }

    /// 按 id 读取归档对象；不存在返回 `None`。
    pub fn get_archive_object(&self, id: i64) -> Result<Option<ArchiveObject>> {
        let sql = format!("SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects WHERE id = $1");
        self.with_client(|client| {
            let row = client
                .query_opt(&sql, &[&id])
                .context("执行 get_archive_object SQL 失败")?;
            match row {
                Some(row) => Ok(Some(row_to_archive_object(&row)?)),
                None => Ok(None),
            }
        })
        .context("get_archive_object")
    }

    /// 按 `object_key` 读取归档对象；不存在返回 `None`。
    pub fn find_archive_object_by_key(&self, object_key: &str) -> Result<Option<ArchiveObject>> {
        let sql =
            format!("SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects WHERE object_key = $1");
        self.with_client(|client| {
            let row = client
                .query_opt(&sql, &[&object_key])
                .context("执行 find_archive_object_by_key SQL 失败")?;
            match row {
                Some(row) => Ok(Some(row_to_archive_object(&row)?)),
                None => Ok(None),
            }
        })
        .context("find_archive_object_by_key")
    }

    /// 按 id 倒序分页列出归档对象；`before_id` 是排他游标。
    ///
    /// `limit == 0` 返回空列表。
    pub fn list_archive_objects(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let sql = format!(
            "SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects \
             WHERE ($1::BIGINT IS NULL OR id < $1) ORDER BY id DESC LIMIT $2"
        );
        self.with_client(|client| {
            let rows = client
                .query(&sql, &[&before_id, &limit])
                .context("执行 list_archive_objects SQL 失败")?;
            rows.iter()
                .map(row_to_archive_object)
                .collect::<Result<Vec<_>>>()
        })
        .context("list_archive_objects")
    }

    /// 更新归档对象状态，并校验合法迁移。
    ///
    /// 允许 `pending -> uploaded -> local_deleted` 与
    /// `pending`/`uploaded` -> `failed`；`failed` 可重试回 `pending` 或
    /// `uploaded`；`local_deleted` 是终态（同状态幂等）。`uploaded_at` /
    /// `deleted_at` 为 `None` 时保留原值。id 不存在返回
    /// [`ArchiveStoreError::NotFound`]，非法迁移返回
    /// [`ArchiveStoreError::InvalidTransition`]。
    pub fn update_archive_object_status(
        &self,
        id: i64,
        status: ArchiveStatus,
        error: &str,
        uploaded_at: Option<i64>,
        deleted_at: Option<i64>,
    ) -> Result<()> {
        self.with_client(|client| {
            let mut tx = client.transaction().context("开启归档状态更新事务失败")?;
            // `FOR UPDATE` 让「读当前状态 + 校验 + 更新」在 PG 下也保持原子，
            // 等价 SQLite 的 BEGIN IMMEDIATE（读后不会被并发删改）。
            let current: Option<String> = tx
                .query_opt(
                    "SELECT status FROM archive_objects WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .context("读取归档对象当前状态失败")?
                .map(|row| row.get(0));
            let Some(current) = current else {
                return Err(ArchiveStoreError::NotFound.into());
            };
            let current = ArchiveStatus::parse(&current)
                .ok_or_else(|| anyhow!("archive_objects.status 字段值非法"))?;
            if !current.can_transition_to(status) {
                return Err(ArchiveStoreError::InvalidTransition.into());
            }
            tx.execute(
                "UPDATE archive_objects
                 SET status = $2,
                     error = $3,
                     uploaded_at = COALESCE($4, uploaded_at),
                     deleted_at = COALESCE($5, deleted_at)
                 WHERE id = $1",
                &[&id, &status.as_str(), &error, &uploaded_at, &deleted_at],
            )
            .context("执行归档状态更新 SQL 失败")?;
            tx.commit().context("提交归档状态更新事务失败")?;
            Ok(())
        })
        .context("update_archive_object_status")
    }

    /// 读取归档水位；键不存在返回 `None`。
    pub fn get_archive_state(&self, key: &str) -> Result<Option<String>> {
        self.with_client(|client| {
            Ok(client
                .query_opt("SELECT value FROM archive_state WHERE key = $1", &[&key])
                .context("执行 get_archive_state SQL 失败")?
                .map(|row| row.get(0)))
        })
        .context("get_archive_state")
    }

    /// 写入 / 更新归档水位（UPSERT）；`updated_at` 由调用方提供。
    pub fn set_archive_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    "INSERT INTO archive_state (key, value, updated_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (key) DO UPDATE SET
                         value = EXCLUDED.value,
                         updated_at = EXCLUDED.updated_at",
                    &[&key, &value, &updated_at],
                )
                .context("执行 set_archive_state SQL 失败")?;
            Ok(())
        })
        .context("set_archive_state")
    }

    /// 列出与 `[from_ts, to_ts]` 有交集的归档对象。
    ///
    /// 交集两端都包含：`archive.from_ts <= 查询上界` 且
    /// `archive.to_ts >= 查询下界`；结果按 `from_ts, id` 升序。
    pub fn list_archive_objects_in_range(
        &self,
        from_ts: i64,
        to_ts: i64,
    ) -> Result<Vec<ArchiveObject>> {
        let sql = format!(
            "SELECT {ARCHIVE_OBJECT_COLUMNS} FROM archive_objects \
             WHERE from_ts <= $2 AND to_ts >= $1 ORDER BY from_ts ASC, id ASC"
        );
        self.with_client(|client| {
            let rows = client
                .query(&sql, &[&from_ts, &to_ts])
                .context("执行 list_archive_objects_in_range SQL 失败")?;
            rows.iter()
                .map(row_to_archive_object)
                .collect::<Result<Vec<_>>>()
        })
        .context("list_archive_objects_in_range")
    }

    /// 按 `samples.id` 升序分批扫描 raw 采样，供归档 worker 生成 CSV.GZ。
    ///
    /// - 时间范围左闭右开 `[from_ts, to_ts)`；
    /// - `after_rowid` 是上一批最后一条的 `samples.id`（排他）；
    /// - `limit == 0` 返回空列表；返回顺序严格按 `id ASC`。
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
        self.with_client(|client| {
            let rows = client
                .query(
                    "SELECT id, agent_id, metric, labels, ts, value FROM samples \
                     WHERE ts >= $1 AND ts < $2 AND ($3::BIGINT IS NULL OR id > $3) \
                     ORDER BY id ASC LIMIT $4",
                    &[&from_ts, &to_ts, &after_rowid, &limit],
                )
                .context("执行 scan_archive_rows SQL 失败")?;
            Ok(rows
                .iter()
                .map(|row| ArchiveRawRow {
                    rowid: row.get(0),
                    agent_id: row.get(1),
                    metric: row.get(2),
                    labels: row.get(3),
                    ts: row.get(4),
                    value: row.get(5),
                })
                .collect())
        })
        .context("scan_archive_rows")
    }

    /// 按 `ts, samples.id` 升序扫描尚未被任何归档对象认领的 raw 行。
    ///
    /// 时间范围左闭右开 `[from_ts, to_ts)`；谓词与
    /// `idx_samples_unarchived` partial index 一致。`limit == 0` 返回空列表。
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
        self.with_client(|client| {
            let rows = client
                .query(
                    "SELECT id, agent_id, metric, labels, ts, value FROM samples \
                     WHERE archive_object_id IS NULL AND ts >= $1 AND ts < $2 \
                       AND ts >= $4 AND ts <= $5 \
                     ORDER BY ts ASC, id ASC LIMIT $3",
                    &[
                        &from_ts,
                        &to_ts,
                        &limit,
                        &MIN_ARCHIVE_TS_MS,
                        &now_ms().min(MAX_ARCHIVE_TS_MS),
                    ],
                )
                .context("执行 list_unclaimed_archive_rows SQL 失败")?;
            Ok(rows
                .iter()
                .map(|row| ArchiveRawRow {
                    rowid: row.get(0),
                    agent_id: row.get(1),
                    metric: row.get(2),
                    labels: row.get(3),
                    ts: row.get(4),
                    value: row.get(5),
                })
                .collect())
        })
        .context("list_unclaimed_archive_rows")
    }

    /// 插入归档对象并原子认领 `rows`，返回新对象 id。
    ///
    /// `UPDATE ... WHERE id = ANY(...) AND archive_object_id IS NULL` 的
    /// affected 行数必须等于选中数；否则整事务回滚并返回可重试的
    /// [`ArchiveStoreError::ClaimConflict`]。并发 claim 由行级锁串行化，
    /// 后提交者会看到已认领行并失败。
    pub fn claim_archive_rows(
        &self,
        object: &ArchiveObject,
        rows: &[ArchiveRawRow],
    ) -> Result<i64> {
        validate_archive_claim(object, rows)?;
        self.with_client(|client| {
            let mut tx = client.transaction().context("开启归档 claim 事务失败")?;
            let object_id = insert_archive_object_tx(&mut tx, object)?;
            // 与 SQLite 一样做行身份比对：即使 id 理论上不复用，也不把
            // 「同 id 但内容已变」的行算作同一 claim 目标。
            let mut updated = 0usize;
            for row in rows {
                let affected = tx
                    .execute(
                        "UPDATE samples SET archive_object_id = $1 \
                         WHERE id = $2 AND archive_object_id IS NULL \
                           AND agent_id = $3 AND metric = $4 AND labels = $5 \
                           AND ts = $6 AND value = $7",
                        &[
                            &object_id,
                            &row.rowid,
                            &row.agent_id,
                            &row.metric,
                            &row.labels,
                            &row.ts,
                            &row.value,
                        ],
                    )
                    .context("执行归档 claim 更新失败")?;
                updated += usize::try_from(affected).context("归档 claim 返回行数溢出")?;
            }
            if updated != rows.len() {
                tx.rollback().context("回滚归档 claim 事务失败")?;
                tracing::warn!(
                    object_id,
                    selected = rows.len(),
                    claimed = updated,
                    "归档 claim 行集与扫描结果不一致，整事务回滚"
                );
                return Err(ArchiveStoreError::ClaimConflict.into());
            }
            tx.commit().context("提交归档 claim 事务失败")?;
            Ok(object_id)
        })
        .context("claim_archive_rows")
    }

    /// 更新归档对象的压缩后字节数与 SHA-256。
    ///
    /// 短事务 claim 只插入对象并把 bytes/sha256 留作占位；CSV.GZ 在事务外
    /// 生成后调用本方法补元数据。`sha256` 必须是 64 位小写十六进制；对象
    /// 不存在返回 [`ArchiveStoreError::NotFound`]。
    pub fn update_archive_object_metadata(&self, id: i64, bytes: u64, sha256: &str) -> Result<()> {
        validate_archive_sha256(sha256)?;
        let bytes = i64::try_from(bytes).context("归档对象字节数超出 BIGINT 范围")?;
        self.with_client(|client| {
            let mut tx = client.transaction().context("开启归档元数据更新事务失败")?;
            let status: Option<String> = tx
                .query_opt(
                    "SELECT status FROM archive_objects WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .context("读取归档对象状态失败")?
                .map(|row| row.get(0));
            let Some(status) = status else {
                return Err(ArchiveStoreError::NotFound.into());
            };
            let status = ArchiveStatus::parse(&status)
                .ok_or_else(|| anyhow!("archive_objects.status 字段值非法"))?;
            if !matches!(status, ArchiveStatus::Pending | ArchiveStatus::Failed) {
                return Err(ArchiveStoreError::InvalidTransition.into());
            }
            tx.execute(
                "UPDATE archive_objects SET bytes = $2, sha256 = $3 WHERE id = $1",
                &[&id, &bytes, &sha256],
            )
            .context("执行 update_archive_object_metadata SQL 失败")?;
            tx.commit().context("提交归档元数据更新事务失败")?;
            Ok(())
        })
        .context("update_archive_object_metadata")
    }

    /// 记录一次上传尝试：仅 pending / failed 对象允许，`attempts += 1`。
    ///
    /// 返回递增后的 attempts。对象不存在返回 `NotFound`，uploaded /
    /// local_deleted 返回 `InvalidTransition`。
    pub fn record_archive_attempt(&self, id: i64) -> Result<i64> {
        self.with_client(|client| {
            let mut tx = client.transaction().context("开启归档尝试计数事务失败")?;
            let status: Option<String> = tx
                .query_opt(
                    "SELECT status FROM archive_objects WHERE id = $1 FOR UPDATE",
                    &[&id],
                )
                .context("读取归档对象状态失败")?
                .map(|row| row.get(0));
            let Some(status) = status else {
                return Err(ArchiveStoreError::NotFound.into());
            };
            let status = ArchiveStatus::parse(&status)
                .ok_or_else(|| anyhow!("archive_objects.status 字段值非法"))?;
            if !matches!(status, ArchiveStatus::Pending | ArchiveStatus::Failed) {
                return Err(ArchiveStoreError::InvalidTransition.into());
            }
            let attempts: i64 = tx
                .query_one(
                    "UPDATE archive_objects SET attempts = attempts + 1 \
                     WHERE id = $1 RETURNING attempts",
                    &[&id],
                )
                .context("执行归档尝试计数 SQL 失败")?
                .get(0);
            tx.commit().context("提交归档尝试计数事务失败")?;
            Ok(attempts)
        })
        .context("record_archive_attempt")
    }

    /// 统计不可归档 raw 行数（`ts < 0` 或 `ts > now`）；只计数不修改。
    ///
    /// 与 SQLite 语义一致，供 R1b 的 `invalid_timestamp_rows` 使用。
    pub fn count_invalid_archive_raw_rows(&self) -> Result<i64> {
        self.with_client(|client| {
            Ok(client
                .query_one(
                    "SELECT COUNT(*)::BIGINT FROM samples WHERE ts < $1 OR ts > $2",
                    &[&MIN_ARCHIVE_TS_MS, &now_ms().min(MAX_ARCHIVE_TS_MS)],
                )
                .context("统计不可归档 raw 行数失败")?
                .get(0))
        })
        .context("count_invalid_archive_raw_rows")
    }

    /// 按 `archive_object_id` 读回 claim 行集，按 `ts, samples.id` 升序。
    ///
    /// 排序与 claim/scan 的 `(ts, id)` 一致，重试才能重建字节级相同的 CSV；
    /// 对象不存在或行已删除返回空列表。
    pub fn archive_rows_for_object(&self, object_id: i64) -> Result<Vec<ArchiveRawRow>> {
        self.with_client(|client| {
            let rows = client
                .query(
                    "SELECT id, agent_id, metric, labels, ts, value FROM samples \
                     WHERE archive_object_id = $1 ORDER BY ts ASC, id ASC",
                    &[&object_id],
                )
                .context("执行 archive_rows_for_object SQL 失败")?;
            Ok(rows
                .iter()
                .map(|row| ArchiveRawRow {
                    rowid: row.get(0),
                    agent_id: row.get(1),
                    metric: row.get(2),
                    labels: row.get(3),
                    ts: row.get(4),
                    value: row.get(5),
                })
                .collect())
        })
        .context("archive_rows_for_object")
    }

    /// `archive_objects` 的总行数。
    pub fn count_archive_objects(&self) -> Result<i64> {
        self.with_client(|client| {
            Ok(client
                .query_one("SELECT COUNT(*)::BIGINT FROM archive_objects", &[])
                .context("统计 archive_objects 行数失败")?
                .get(0))
        })
        .context("count_archive_objects")
    }
}

#[cfg(test)]
mod tests {
    //! 实库测试：未设置 `RUSTBOARD_TEST_PG` 时整体 skip（cargo 记为 passed）。
    //!
    //! 每个用例创建独立数据库并在 `Drop` 时 `DROP DATABASE ... WITH (FORCE)`，
    //! 因此可以并行执行；`RUSTBOARD_TEST_PG` 对应角色需要 `CREATEDB` 权限。
    //! DSN 必须显式 `sslmode=disable`（与 `PostgresStorage::open` 的明文路径一致）。

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use postgres::config::SslMode;
    use postgres::types::ToSql;
    use postgres::{NoTls, Row};

    use crate::storage::postgres::PostgresOptions;

    use super::*;

    const PG_ENV: &str = "RUSTBOARD_TEST_PG";

    static DB_SEQ: AtomicU64 = AtomicU64::new(0);

    fn skip(test_name: &str) {
        eprintln!("SKIP {test_name}: 未设置 {PG_ENV}（归档/降采样实库测试需要 PostgreSQL）");
    }

    /// 读取并校验测试 DSN；未设置/空串返回 `None`。
    fn base_dsn(test_name: &str) -> Option<String> {
        let dsn = std::env::var(PG_ENV)
            .ok()
            .filter(|dsn| !dsn.trim().is_empty())?;
        let config: postgres::Config = dsn
            .parse()
            .unwrap_or_else(|err| panic!("{PG_ENV} 解析失败：{err}"));
        assert_eq!(
            config.get_ssl_mode(),
            SslMode::Disable,
            "{PG_ENV} 必须显式 sslmode=disable"
        );
        // 变量存在时不要静默跳过：断言失败比“看似通过”更安全。
        let _ = test_name;
        Some(dsn)
    }

    /// 把测试 DSN 的数据库名替换为 `name`，保留 query（含 sslmode）。
    fn dsn_with_database(base: &str, name: &str) -> String {
        let (head, query) = match base.split_once('?') {
            Some((head, query)) => (head, Some(query)),
            None => (base, None),
        };
        let (prefix, _database) = head.rsplit_once('/').expect("测试 DSN 必须包含数据库名");
        match query {
            Some(query) => format!("{prefix}/{name}?{query}"),
            None => format!("{prefix}/{name}?sslmode=disable"),
        }
    }

    fn unique_database_name(tag: &str) -> String {
        let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let name = format!("rb_ar_{tag}_{}_{nanos}_{seq}", std::process::id());
        assert!(
            name.len() <= 63,
            "测试库名超过 PostgreSQL 标识符上限：{name}"
        );
        assert!(
            name.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
            "测试库名只允许小写字母/数字/下划线：{name}"
        );
        name
    }

    /// 一次性测试库 + `PostgresStorage`；drop 时顺带删库。
    struct TestPg {
        name: String,
        admin: postgres::Config,
        storage: Option<PostgresStorage>,
    }

    impl TestPg {
        fn create(test_name: &str, tag: &str) -> Option<Self> {
            Self::create_with_pool(test_name, tag, 1)
        }

        fn create_with_pool(test_name: &str, tag: &str, pool_size: usize) -> Option<Self> {
            let base = match base_dsn(test_name) {
                Some(base) => base,
                None => {
                    skip(test_name);
                    return None;
                }
            };
            let config: postgres::Config = base.parse().expect("测试 DSN 必须可解析");
            let mut admin = config;
            admin.dbname("postgres");
            let name = unique_database_name(tag);

            let mut admin_client = admin.connect(NoTls).unwrap_or_else(|err| {
                panic!("连接 postgres 维护库失败（检查 {PG_ENV} 与容器）：{err}")
            });
            admin_client
                .batch_execute(&format!("CREATE DATABASE {name}"))
                .unwrap_or_else(|err| {
                    panic!("CREATE DATABASE {name} 失败（角色需要 CREATEDB 权限）：{err}")
                });
            drop(admin_client);

            let dsn = dsn_with_database(&base, &name);
            let storage = PostgresStorage::open(PostgresOptions {
                dsn,
                pool_size,
                connect_timeout: Duration::from_secs(10),
                statement_timeout: Duration::from_secs(60),
                sslrootcert: None,
            })
            .unwrap_or_else(|err| panic!("打开测试库 {name} 失败：{err:#}"));
            storage
                .apply_schema()
                .unwrap_or_else(|err| panic!("应用测试库 schema 失败：{err:#}"));

            Some(Self {
                name,
                admin,
                storage: Some(storage),
            })
        }

        fn storage(&self) -> &PostgresStorage {
            self.storage.as_ref().expect("测试存储已释放")
        }

        /// 取出存储用于并发测试；`TestPg` 仍负责最终删库。
        fn take_storage(&mut self) -> PostgresStorage {
            self.storage.take().expect("测试存储已释放")
        }
    }

    impl Drop for TestPg {
        fn drop(&mut self) {
            // 池释放会移交独立线程；WITH (FORCE) 负责终止仍存活的测试连接。
            self.storage.take();
            let mut client = match self.admin.connect(NoTls) {
                Ok(client) => client,
                Err(err) => {
                    eprintln!(
                        "[archive-test] 清理失败：无法连接维护库删除 {}：{err}",
                        self.name
                    );
                    return;
                }
            };
            if let Err(err) = client.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            )) {
                eprintln!(
                    "[archive-test] 清理失败：DROP DATABASE {} 出错：{err}",
                    self.name
                );
            }
        }
    }

    fn execute(storage: &PostgresStorage, sql: &str, params: &[&(dyn ToSql + Sync)]) -> u64 {
        storage
            .with_client(|client| Ok(client.execute(sql, params)?))
            .expect("测试 SQL 执行失败")
    }

    fn fetch(storage: &PostgresStorage, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Vec<Row> {
        storage
            .with_client(|client| Ok(client.query(sql, params)?))
            .expect("测试 SQL 查询失败")
    }

    fn set_state(storage: &PostgresStorage, key: &str, value: &str) {
        execute(
            storage,
            "INSERT INTO maintenance_state (key, value, updated_at) VALUES ($1, $2, 1)
             ON CONFLICT (key) DO UPDATE SET
                 value = EXCLUDED.value,
                 updated_at = EXCLUDED.updated_at",
            &[&key, &value],
        );
    }

    fn get_state(storage: &PostgresStorage, key: &str) -> Option<String> {
        fetch(
            storage,
            "SELECT value FROM maintenance_state WHERE key = $1",
            &[&key],
        )
        .into_iter()
        .next()
        .map(|row| row.get(0))
    }

    fn archive_object(key: &str, from_ts: i64, to_ts: i64, status: ArchiveStatus) -> ArchiveObject {
        ArchiveObject {
            id: 0,
            backend: "webdav".to_string(),
            object_key: key.to_string(),
            manifest_key: format!("{key}.manifest.json"),
            from_ts,
            to_ts,
            rows: 10,
            bytes: 100,
            sha256: "a".repeat(64),
            status,
            error: String::new(),
            created_at: 1_000,
            uploaded_at: None,
            deleted_at: None,
            ledger_version: 0,
            attempts: 0,
        }
    }

    /// 无需数据库的静态自检：SQL 常量必须使用 PG 占位符与 `id`，且宽度的
    /// 字面量与常量保持一致。
    #[test]
    fn archive_sql_constants_are_postgres_specific() {
        assert_eq!(PRUNE_BATCH_ROWS, 5_000);
        assert!(AGGREGATE_1M_SQL.contains(&format!("/ {BUCKET_1M_MS}")));
        assert!(AGGREGATE_1H_SQL.contains(&format!("/ {BUCKET_1H_MS}")));
        for sql in [
            AGGREGATE_1M_SQL,
            AGGREGATE_1H_SQL,
            PRUNE_RAW_SQL,
            PRUNE_1M_SQL,
            PRUNE_1H_SQL,
        ] {
            assert!(!sql.contains("rowid"), "SQL 不得再使用 SQLite rowid：{sql}");
            assert!(!sql.contains('?'), "SQL 不得使用 SQLite ?N 占位符：{sql}");
            assert!(sql.contains('$'), "SQL 必须使用 $N 占位符：{sql}");
        }
        assert!(PRUNE_RAW_SQL.contains("samples WHERE id IN"));
    }

    #[test]
    fn pg_downsample_1m_window_last_value_and_idempotent() {
        const NAME: &str = "pg_downsample_1m_window_last_value_and_idempotent";
        let Some(pg) = TestPg::create(NAME, "ds1m") else {
            return;
        };
        let storage = pg.storage();
        let base = 1_700_000_000_000_i64 / BUCKET_1M_MS * BUCKET_1M_MS;

        for (ts, value) in [
            (base + 10, 1.0_f64),
            (base + 20, 3.0),
            (base + 30, 5.0),
            // 同一 ts 的后到值必须靠更大的 id 成为 last_value。
            (base + 30, 7.0),
            (base + BUCKET_1M_MS + 5, 9.0),
            // to 向下取整后之外的行：必须被排除。
            (base + 2 * BUCKET_1M_MS, 100.0),
        ] {
            execute(
                storage,
                "INSERT INTO samples (agent_id, metric, labels, ts, value)
                 VALUES ('a', 'cpu.usage', '{}', $1, $2)",
                &[&ts, &value],
            );
        }

        let first = storage
            .downsample_1m_range(base + 999, base + 2 * BUCKET_1M_MS + 500)
            .expect("1m 降采样失败");
        assert_eq!(
            first,
            DownsampleRangeResult {
                buckets: 2,
                rows: 5
            }
        );

        let rows = fetch(
            storage,
            "SELECT bucket_ts, min_value, max_value, avg_value, last_value, count, id
             FROM samples_1m ORDER BY bucket_ts",
            &[],
        );
        assert_eq!(rows.len(), 2);
        let first_bucket: i64 = rows[0].get(0);
        assert_eq!(first_bucket, base);
        let min: f64 = rows[0].get(1);
        let max: f64 = rows[0].get(2);
        let avg: f64 = rows[0].get(3);
        let last: f64 = rows[0].get(4);
        let count: i64 = rows[0].get(5);
        assert_eq!((min, max, avg, last, count), (1.0, 7.0, 4.0, 7.0, 4));
        let second_bucket: i64 = rows[1].get(0);
        assert_eq!(second_bucket, base + BUCKET_1M_MS);
        let second_count: i64 = rows[1].get(5);
        assert_eq!(second_count, 1);

        let ids_before: Vec<i64> = rows.iter().map(|row| row.get(6)).collect();
        let again = storage
            .downsample_1m_range(base + 999, base + 2 * BUCKET_1M_MS + 500)
            .expect("重复 1m 降采样失败");
        assert_eq!(again, first, "重复执行必须返回同样的桶数/源行数");
        let rows_after = fetch(storage, "SELECT id FROM samples_1m ORDER BY bucket_ts", &[]);
        assert_eq!(rows_after.len(), 2, "upsert 不得新增桶");
        let ids_after: Vec<i64> = rows_after.iter().map(|row| row.get(0)).collect();
        assert_eq!(ids_after, ids_before, "upsert 必须原地更新，不重建行");

        assert_eq!(
            storage
                .downsample_1m_range(base + 10, base + 10)
                .expect("空窗口 1m 降采样失败"),
            DownsampleRangeResult::default(),
            "两端取整后相同的窗口必须返回空结果"
        );
    }

    #[test]
    fn pg_downsample_1h_weighted_average_and_idempotent() {
        const NAME: &str = "pg_downsample_1h_weighted_average_and_idempotent";
        let Some(pg) = TestPg::create(NAME, "ds1h") else {
            return;
        };
        let storage = pg.storage();
        let hour = 1_700_000_000_000_i64 / BUCKET_1H_MS * BUCKET_1H_MS;

        // 故意乱序插入，验证 last_value 取的是最新桶而不是最后插入的行。
        for (bucket_ts, min, max, avg, last, count) in [
            (
                hour + BUCKET_1M_MS,
                1.0_f64,
                8.0_f64,
                8.0_f64,
                8.0_f64,
                6_i64,
            ),
            (hour, 2.0, 10.0, 4.0, 10.0, 2),
            // 范围之外：不得参与聚合。
            (hour + BUCKET_1H_MS, 100.0, 100.0, 100.0, 100.0, 100),
        ] {
            execute(
                storage,
                "INSERT INTO samples_1m
                     (agent_id, metric, labels, bucket_ts, min_value, max_value,
                      avg_value, last_value, count)
                 VALUES ('a', 'cpu.usage', '{}', $1, $2, $3, $4, $5, $6)",
                &[&bucket_ts, &min, &max, &avg, &last, &count],
            );
        }

        let result = storage
            .downsample_1h_range(hour + 1, hour + BUCKET_1H_MS)
            .expect("1h 降采样失败");
        assert_eq!(
            result,
            DownsampleRangeResult {
                // 两个 1m 桶落在同一个整点小时里，只产生 1 个 1h 桶。
                buckets: 1,
                rows: 2
            }
        );

        let rows = fetch(
            storage,
            "SELECT bucket_ts, min_value, max_value, avg_value, last_value, count, id
             FROM samples_1h",
            &[],
        );
        assert_eq!(rows.len(), 1);
        let bucket_ts: i64 = rows[0].get(0);
        let min: f64 = rows[0].get(1);
        let max: f64 = rows[0].get(2);
        let avg: f64 = rows[0].get(3);
        let last: f64 = rows[0].get(4);
        let count: i64 = rows[0].get(5);
        assert_eq!(bucket_ts, hour);
        assert_eq!((min, max, last, count), (1.0, 10.0, 8.0, 8));
        assert_eq!(avg, 7.0, "必须按 count 加权：(4*2 + 8*6) / 8 = 7");
        assert_ne!(avg, 6.0, "不得把各分钟均值再取简单平均");

        let id_before: i64 = rows[0].get(6);
        let again = storage
            .downsample_1h_range(hour + 1, hour + BUCKET_1H_MS)
            .expect("重复 1h 降采样失败");
        assert_eq!(again, result);
        let rows_after = fetch(storage, "SELECT id, count FROM samples_1h", &[]);
        assert_eq!(rows_after.len(), 1, "upsert 不得新增小时桶");
        let id_after: i64 = rows_after[0].get(0);
        let count_after: i64 = rows_after[0].get(1);
        assert_eq!(id_after, id_before, "upsert 必须原地更新");
        assert_eq!(count_after, 8, "重复聚合不得把 count 累加");
    }

    #[test]
    fn pg_stats_offsets_and_raw_new_rows_match_sqlite_semantics() {
        const NAME: &str = "pg_stats_offsets_and_raw_new_rows_match_sqlite_semantics";
        let Some(pg) = TestPg::create(NAME, "stats") else {
            return;
        };
        let storage = pg.storage();
        let base = 1_700_000_000_000_i64;

        assert_eq!(
            storage.raw_stats().expect("空 raw 统计失败"),
            TierStats::default()
        );
        assert_eq!(storage.raw_stats().expect("空 raw 统计失败").rows, 0);
        assert_eq!(
            storage.raw_new_rows(None).expect("空 raw new_rows 失败"),
            (None, None)
        );
        assert_eq!(
            storage.samples_1m_oldest_ts().expect("空 1m 最旧桶失败"),
            None
        );

        for (ts, value) in [(base + 30, 3.0_f64), (base + 10, 1.0), (base + 20, 2.0)] {
            execute(
                storage,
                "INSERT INTO samples (agent_id, metric, labels, ts, value)
                 VALUES ('a', 'cpu.usage', '{}', $1, $2)",
                &[&ts, &value],
            );
        }

        let stats = storage.raw_stats().expect("raw 统计失败");
        assert_eq!(
            stats,
            TierStats {
                rows: 3,
                oldest_ts: Some(base + 10),
                newest_ts: Some(base + 30),
            }
        );
        assert_eq!(
            storage
                .raw_ts_at_offset(base, base + 100, 1)
                .expect("raw 偏移查询失败"),
            Some(base + 20)
        );
        assert_eq!(
            storage
                .raw_ts_at_offset(base, base + 100, 3)
                .expect("raw 偏移越界查询失败"),
            None
        );
        // 左闭右开：上界是 base + 20 时第 1 条（0-based）不存在第二条。
        assert_eq!(
            storage
                .raw_ts_at_offset(base, base + 20, 1)
                .expect("raw 右开边界查询失败"),
            None
        );

        let (max_id, min_ts) = storage.raw_new_rows(None).expect("raw_new_rows 失败");
        assert_eq!(max_id, Some(3), "id 从 1 递增，MAX(id) 应为 3");
        assert_eq!(min_ts, Some(base + 10), "新区间最旧 ts 应为 base+10");
        assert_eq!(
            storage
                .raw_new_rows(max_id)
                .expect("水位后 raw_new_rows 失败"),
            (Some(3), None),
            "水位等于 MAX 时没有新行"
        );
        // 水位超前（重建库/回退场景）必须按「全部是新行」重扫。
        let (max_after_rewind, oldest) = storage
            .raw_new_rows(Some(99))
            .expect("水位回退 raw_new_rows 失败");
        assert_eq!(max_after_rewind, Some(3));
        assert_eq!(oldest, Some(base + 10));

        execute(
            storage,
            "INSERT INTO samples_1m
                 (agent_id, metric, labels, bucket_ts, min_value, max_value,
                  avg_value, last_value, count)
             VALUES ('a', 'cpu.usage', '{}', $1, 1, 2, 1.5, 2, 2),
                    ('b', 'cpu.usage', '{}', $1, 1, 2, 1.5, 2, 2)",
            &[&(base - base % BUCKET_1M_MS)],
        );
        let bucket = base - base % BUCKET_1M_MS;
        assert_eq!(
            storage
                .samples_1m_ts_at_offset(bucket, bucket + BUCKET_1M_MS, 1)
                .expect("1m 偏移查询失败"),
            Some(bucket)
        );
        assert_eq!(
            storage.samples_1m_oldest_ts().expect("1m 最旧桶查询失败"),
            Some(bucket)
        );
        let stats_1m = storage.samples_1m_stats().expect("1m 统计失败");
        assert_eq!(
            stats_1m,
            TierStats {
                rows: 2,
                oldest_ts: Some(bucket),
                newest_ts: Some(bucket),
            }
        );
    }

    #[test]
    fn pg_prune_respects_boundaries_and_batch_size() {
        const NAME: &str = "pg_prune_respects_boundaries_and_batch_size";
        let Some(pg) = TestPg::create(NAME, "prune") else {
            return;
        };
        let storage = pg.storage();
        let cutoff = 1_700_000_000_000_i64;
        let expired_rows = PRUNE_BATCH_ROWS + 3;

        // 5003 条 `ts < cutoff` 的过期 raw + 1 条恰好等于 cutoff 的边界行。
        execute(
            storage,
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             SELECT 'a', 'cpu.usage', '{}', $1::BIGINT - 1 - g, 0.5
             FROM generate_series(0, $2::BIGINT) AS g",
            &[&cutoff, &(expired_rows as i64 - 1)],
        );
        execute(
            storage,
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('a', 'cpu.usage', '{}', $1, 1.0)",
            &[&cutoff],
        );

        let result = storage
            .prune_samples_before(cutoff)
            .expect("raw 保留期删除失败");
        assert_eq!(
            result,
            PruneResult {
                deleted: expired_rows,
                batches: 2
            },
            "5003 行必须分两批（5000 + 3）删除"
        );
        let remaining = fetch(storage, "SELECT ts FROM samples", &[]);
        assert_eq!(remaining.len(), 1, "等于 cutoff 的行不得删除");
        let ts: i64 = remaining[0].get(0);
        assert_eq!(ts, cutoff);

        // 1m / 1h：cutoff 是排他边界，等于 cutoff 的行保留。
        for table in ["samples_1m", "samples_1h"] {
            execute(
                storage,
                &format!(
                    "INSERT INTO {table}
                         (agent_id, metric, labels, bucket_ts, min_value, max_value,
                          avg_value, last_value, count)
                     VALUES ('a', 'cpu.usage', '{{}}', $1::BIGINT - 1, 1, 1, 1, 1, 1),
                            ('a', 'cpu.usage', '{{}}', $1::BIGINT, 2, 2, 2, 2, 2)"
                ),
                &[&cutoff],
            );
        }
        let pruned_1m = storage
            .prune_samples_1m_before(cutoff)
            .expect("1m 保留期删除失败");
        assert_eq!(
            pruned_1m,
            PruneResult {
                deleted: 1,
                batches: 1
            }
        );
        let pruned_1h = storage
            .prune_samples_1h_before(cutoff)
            .expect("1h 保留期删除失败");
        assert_eq!(
            pruned_1h,
            PruneResult {
                deleted: 1,
                batches: 1
            }
        );
        for table in ["samples_1m", "samples_1h"] {
            let rows = fetch(storage, &format!("SELECT bucket_ts FROM {table}"), &[]);
            assert_eq!(rows.len(), 1, "{table} 等于 cutoff 的桶不得删除");
            let bucket_ts: i64 = rows[0].get(0);
            assert_eq!(bucket_ts, cutoff);
        }
    }

    #[test]
    fn pg_prune_converges_raw_watermark_and_generation() {
        const NAME: &str = "pg_prune_converges_raw_watermark_and_generation";
        let Some(pg) = TestPg::create(NAME, "prunewm") else {
            return;
        };
        let storage = pg.storage();

        for ts in [1_000_i64, 2_000, 3_000] {
            execute(
                storage,
                "INSERT INTO samples (agent_id, metric, labels, ts, value)
                 VALUES ('a', 'cpu.usage', '{}', $1, 1.0)",
                &[&ts],
            );
        }
        let max_id: i64 = fetch(storage, "SELECT MAX(id) FROM samples", &[])[0].get(0);
        set_state(storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID, "99");
        set_state(storage, STATE_RAW_PRUNE_GENERATION, "5");

        // 删除 0 行也要收敛一次：高水位必须降到当前 MAX(id)，代际不变。
        let noop = storage.prune_samples_before(0).expect("空批 raw 删除失败");
        assert_eq!(noop, PruneResult::default());
        assert_eq!(
            get_state(storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            Some(max_id.to_string())
        );
        assert_eq!(
            get_state(storage, STATE_RAW_PRUNE_GENERATION),
            Some("5".to_string())
        );

        // 删除最大 id 行：代际 +1；raw 清空后 rowid 水位键必须删除。
        let result = storage
            .prune_samples_before(10_000)
            .expect("raw 全量删除失败");
        assert_eq!(
            result,
            PruneResult {
                deleted: 3,
                batches: 1
            }
        );
        assert_eq!(
            get_state(storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            None,
            "raw 为空时必须清除 rowid 水位"
        );
        assert_eq!(
            get_state(storage, STATE_RAW_PRUNE_GENERATION),
            Some("6".to_string()),
            "删除最大 id 行必须推进 prune 代际"
        );
    }

    #[test]
    fn pg_claim_raw_rowid_cas_matches_sqlite_expectations() {
        const NAME: &str = "pg_claim_raw_rowid_cas_matches_sqlite_expectations";
        let Some(pg) = TestPg::create(NAME, "cas") else {
            return;
        };
        let storage = pg.storage();

        // 键全缺失 + generation 0：匹配并写入。
        assert!(storage
            .claim_raw_rowid_if_unchanged(None, 0, 1)
            .expect("首次 CAS 失败"));
        assert_eq!(
            get_state(storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            Some("1".to_string())
        );

        // 正常命中。
        assert!(storage
            .claim_raw_rowid_if_unchanged(Some(1), 0, 2)
            .expect("命中 CAS 失败"));
        assert_eq!(
            get_state(storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            Some("2".to_string())
        );

        // 期望 rowid 过期：不写。
        assert!(!storage
            .claim_raw_rowid_if_unchanged(Some(1), 0, 3)
            .expect("过期 rowid CAS 失败"));
        assert_eq!(
            get_state(storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            Some("2".to_string())
        );

        // generation 不匹配：不写。
        set_state(storage, STATE_RAW_PRUNE_GENERATION, "2");
        assert!(!storage
            .claim_raw_rowid_if_unchanged(Some(2), 1, 4)
            .expect("generation 不匹配 CAS 失败"));
        assert!(storage
            .claim_raw_rowid_if_unchanged(Some(2), 2, 4)
            .expect("generation 命中 CAS 失败"));

        // 非法 generation 视为不匹配，即使 rowid 期望正确也不覆盖。
        set_state(storage, STATE_RAW_PRUNE_GENERATION, "bogus");
        assert!(!storage
            .claim_raw_rowid_if_unchanged(Some(4), 2, 5)
            .expect("非法 generation CAS 失败"));
        assert_eq!(
            get_state(storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            Some("4".to_string())
        );

        // rowid 键缺失：expected None 且 generation 匹配时才成功。
        execute(
            storage,
            "DELETE FROM maintenance_state WHERE key = $1",
            &[&STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID],
        );
        set_state(storage, STATE_RAW_PRUNE_GENERATION, "3");
        assert!(storage
            .claim_raw_rowid_if_unchanged(None, 3, 6)
            .expect("缺失 rowid 命中 CAS 失败"));

        // 缺失 generation 视为 0；键存在时 expected None 不匹配。
        execute(
            storage,
            "DELETE FROM maintenance_state WHERE key = $1",
            &[&STATE_RAW_PRUNE_GENERATION],
        );
        assert!(storage
            .claim_raw_rowid_if_unchanged(Some(6), 0, 7)
            .expect("缺失 generation 视为 0 的 CAS 失败"));
        assert!(!storage
            .claim_raw_rowid_if_unchanged(None, 0, 8)
            .expect("rowid 存在时 None 期望应失败"));
        assert_eq!(
            get_state(storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            Some("7".to_string())
        );
    }

    #[test]
    fn pg_archive_object_insert_unique_pagination_and_range() {
        const NAME: &str = "pg_archive_object_insert_unique_pagination_and_range";
        let Some(pg) = TestPg::create(NAME, "obj") else {
            return;
        };
        let storage = pg.storage();

        let first = archive_object(
            "rustboard/2026/10/24/part-00001.csv.gz",
            100,
            200,
            ArchiveStatus::Pending,
        );
        let first_id = storage
            .insert_archive_object(&first)
            .expect("插入归档对象失败");
        assert!(
            first_id > 0,
            "archive_objects.id 必须是 BIGSERIAL 生成的正数"
        );
        let mut expected = first.clone();
        expected.id = first_id;
        assert_eq!(
            storage
                .get_archive_object(first_id)
                .expect("读取归档对象失败"),
            Some(expected.clone())
        );
        assert_eq!(
            storage
                .get_archive_object(first_id + 999)
                .expect("读取不存在归档对象失败"),
            None
        );
        assert_eq!(
            storage
                .find_archive_object_by_key(&first.object_key)
                .expect("按 key 读取归档对象失败")
                .map(|object| object.id),
            Some(first_id)
        );
        assert!(storage
            .find_archive_object_by_key("rustboard/missing.csv.gz")
            .expect("读取不存在 key 失败")
            .is_none());

        // object_key UNIQUE：字段不同也不能覆盖已有记录。
        let mut duplicate = first.clone();
        duplicate.backend = "s3".to_string();
        duplicate.from_ts = 300;
        duplicate.to_ts = 400;
        let err = storage
            .insert_archive_object(&duplicate)
            .expect_err("重复 object_key 必须失败");
        assert_eq!(
            err.downcast_ref::<ArchiveStoreError>(),
            Some(&ArchiveStoreError::ObjectExists)
        );
        assert!(
            format!("{err:#}").contains("归档对象已存在"),
            "错误链应保留领域错误：{err:#}"
        );
        assert_eq!(
            storage
                .get_archive_object(first_id)
                .expect("读取归档对象失败"),
            Some(expected),
            "唯一冲突不得修改原记录"
        );

        let second_id = storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00002.csv.gz",
                300,
                400,
                ArchiveStatus::Uploaded,
            ))
            .expect("插入第二个归档对象失败");
        let third_id = storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00003.csv.gz",
                300,
                350,
                ArchiveStatus::Failed,
            ))
            .expect("插入第三个归档对象失败");
        let fourth_id = storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00004.csv.gz",
                500,
                600,
                ArchiveStatus::LocalDeleted,
            ))
            .expect("插入第四个归档对象失败");

        // 分页：id 倒序，before_id 排他。
        let page = storage
            .list_archive_objects(2, None)
            .expect("第一页查询失败");
        assert_eq!(
            page.iter().map(|object| object.id).collect::<Vec<_>>(),
            vec![fourth_id, third_id]
        );
        let page = storage
            .list_archive_objects(2, Some(third_id))
            .expect("第二页查询失败");
        assert_eq!(
            page.iter().map(|object| object.id).collect::<Vec<_>>(),
            vec![second_id, first_id]
        );
        assert!(storage
            .list_archive_objects(0, None)
            .expect("limit=0 查询失败")
            .is_empty());
        assert_eq!(
            storage
                .list_archive_objects(100, None)
                .expect("全量查询失败")
                .len(),
            4
        );

        // 范围查询：两端包含，按 from_ts,id 升序，不按 status 过滤。
        let ranged = storage
            .list_archive_objects_in_range(200, 300)
            .expect("范围查询失败");
        assert_eq!(
            ranged.iter().map(|object| object.id).collect::<Vec<_>>(),
            vec![first_id, second_id, third_id],
            "边界包含且同 from_ts 按 id 升序"
        );
        assert!(storage
            .list_archive_objects_in_range(201, 299)
            .expect("空范围查询失败")
            .is_empty());
        assert_eq!(
            storage
                .list_archive_objects_in_range(600, 600)
                .expect("单点范围查询失败")
                .iter()
                .map(|object| object.id)
                .collect::<Vec<_>>(),
            vec![fourth_id],
            "单点范围也要包含跨过该点的对象"
        );
        assert_eq!(storage.count_archive_objects().expect("对象计数失败"), 4);
    }

    #[test]
    fn pg_claim_rows_readback_and_metadata_update_use_sample_ids() {
        const NAME: &str = "pg_claim_rows_readback_and_metadata_update_use_sample_ids";
        let Some(pg) = TestPg::create(NAME, "claim") else {
            return;
        };
        let storage = pg.storage();
        // 插入顺序与 ts 顺序相反，验证 scan/readback 都按 (ts, id) 排序。
        for ts in [2_000_i64, 1_000] {
            execute(
                storage,
                "INSERT INTO samples (agent_id, metric, labels, ts, value)
                 VALUES ('a', 'cpu.usage', '{}', $1, 1.0)",
                &[&ts],
            );
        }
        let rows = storage
            .list_unclaimed_archive_rows(0, 10_000, 100)
            .expect("读取未认领行失败");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows.iter().map(|row| row.ts).collect::<Vec<_>>(),
            vec![1_000, 2_000],
            "scan 必须按 (ts, id) 排序"
        );
        let mut row_ids: Vec<i64> = rows.iter().map(|row| row.rowid).collect();
        row_ids.sort_unstable();
        let sample_ids: Vec<i64> = fetch(storage, "SELECT id FROM samples ORDER BY id", &[])
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(
            row_ids, sample_ids,
            "ArchiveRawRow.rowid 必须来自 samples.id"
        );

        let mut object = archive_object(
            "v8/part-00001-v8.csv.gz",
            1_000,
            2_000,
            ArchiveStatus::Pending,
        );
        object.rows = 2;
        object.ledger_version = crate::archive::LEDGER_VERSION_V8;
        object.bytes = 0;
        object.sha256.clear();
        let object_id = storage
            .claim_archive_rows(&object, &rows)
            .expect("PG claim 失败");
        let readback = storage
            .archive_rows_for_object(object_id)
            .expect("PG 读回 claim 行集失败");
        assert_eq!(readback, rows);

        let digest = "e".repeat(64);
        storage
            .update_archive_object_metadata(object_id, 321, &digest)
            .expect("PG 元数据更新失败");
        let stored = storage.get_archive_object(object_id).unwrap().unwrap();
        assert_eq!(stored.bytes, 321);
        assert_eq!(stored.sha256, digest);
        assert_eq!(stored.attempts, 0);
        assert_eq!(storage.record_archive_attempt(object_id).unwrap(), 1);
        assert_eq!(storage.record_archive_attempt(object_id).unwrap(), 2);
        storage
            .update_archive_object_status(object_id, ArchiveStatus::Uploaded, "", Some(2_000), None)
            .expect("pending→uploaded 合法");
        let err = storage
            .update_archive_object_metadata(object_id, 1, &"f".repeat(64))
            .expect_err("uploaded 后不得再改元数据");
        assert_eq!(
            err.downcast_ref::<ArchiveStoreError>(),
            Some(&ArchiveStoreError::InvalidTransition)
        );
        let err = storage
            .record_archive_attempt(object_id)
            .expect_err("uploaded 后不得再记录尝试");
        assert_eq!(
            err.downcast_ref::<ArchiveStoreError>(),
            Some(&ArchiveStoreError::InvalidTransition)
        );

        // 同一批行再次 claim 必须整事务回滚并返回可重试冲突。
        let mut again = archive_object(
            "v8/part-00002-v8.csv.gz",
            1_000,
            2_000,
            ArchiveStatus::Pending,
        );
        again.rows = 2;
        again.ledger_version = crate::archive::LEDGER_VERSION_V8;
        let err = storage
            .claim_archive_rows(&again, &rows)
            .expect_err("重复 claim 必须失败");
        assert_eq!(
            err.downcast_ref::<ArchiveStoreError>(),
            Some(&ArchiveStoreError::ClaimConflict)
        );
        assert!(
            storage
                .find_archive_object_by_key("v8/part-00002-v8.csv.gz")
                .unwrap()
                .is_none(),
            "冲突 claim 的对象插入必须回滚"
        );
    }

    #[test]
    fn pg_archive_status_transitions_and_errors() {
        const NAME: &str = "pg_archive_status_transitions_and_errors";
        let Some(pg) = TestPg::create(NAME, "status") else {
            return;
        };
        let storage = pg.storage();
        let id = storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00001.csv.gz",
                100,
                200,
                ArchiveStatus::Pending,
            ))
            .expect("插入归档对象失败");

        // pending -> uploaded：记录上传时间与 error（成功时应传空串）。
        storage
            .update_archive_object_status(id, ArchiveStatus::Uploaded, "", Some(1_100), None)
            .expect("pending -> uploaded 必须允许");
        let object = storage
            .get_archive_object(id)
            .expect("读取归档对象失败")
            .expect("归档对象必须存在");
        assert_eq!(object.status, ArchiveStatus::Uploaded);
        assert_eq!(object.uploaded_at, Some(1_100));
        assert_eq!(object.deleted_at, None);
        assert_eq!(object.error, "");

        // uploaded -> local_deleted：None 不得清空历史时间戳。
        storage
            .update_archive_object_status(id, ArchiveStatus::LocalDeleted, "", None, Some(1_200))
            .expect("uploaded -> local_deleted 必须允许");
        let object = storage
            .get_archive_object(id)
            .expect("读取归档对象失败")
            .expect("归档对象必须存在");
        assert_eq!(object.status, ArchiveStatus::LocalDeleted);
        assert_eq!(object.uploaded_at, Some(1_100));
        assert_eq!(object.deleted_at, Some(1_200));

        // local_deleted 是终态：任何不同状态都非法，同状态幂等。
        for next in [
            ArchiveStatus::Pending,
            ArchiveStatus::Uploaded,
            ArchiveStatus::Failed,
        ] {
            let err = storage
                .update_archive_object_status(id, next, "", None, None)
                .expect_err("local_deleted 迁移必须被拒绝");
            assert_eq!(
                err.downcast_ref::<ArchiveStoreError>(),
                Some(&ArchiveStoreError::InvalidTransition),
                "local_deleted -> {next:?} 必须拒绝"
            );
            assert!(
                format!("{err:#}").contains("归档对象状态迁移非法"),
                "错误链应保留领域错误：{err:#}"
            );
        }
        storage
            .update_archive_object_status(id, ArchiveStatus::LocalDeleted, "", None, None)
            .expect("同状态更新必须幂等");

        // 失败路径：pending -> failed 记录 error；failed 可重试回 pending。
        let failed_id = storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00002.csv.gz",
                100,
                200,
                ArchiveStatus::Pending,
            ))
            .expect("插入第二个归档对象失败");
        let err = storage
            .update_archive_object_status(failed_id, ArchiveStatus::LocalDeleted, "", None, None)
            .expect_err("pending -> local_deleted 必须拒绝");
        assert_eq!(
            err.downcast_ref::<ArchiveStoreError>(),
            Some(&ArchiveStoreError::InvalidTransition)
        );
        storage
            .update_archive_object_status(failed_id, ArchiveStatus::Failed, "后端 500", None, None)
            .expect("pending -> failed 必须允许");
        let object = storage
            .get_archive_object(failed_id)
            .expect("读取归档对象失败")
            .expect("归档对象必须存在");
        assert_eq!(object.status, ArchiveStatus::Failed);
        assert_eq!(object.error, "后端 500");
        storage
            .update_archive_object_status(failed_id, ArchiveStatus::Pending, "", None, None)
            .expect("failed -> pending 重试必须允许");
        assert_eq!(
            storage
                .get_archive_object(failed_id)
                .expect("读取归档对象失败")
                .expect("归档对象必须存在")
                .error,
            "",
            "重试时应由调用方清空旧错误"
        );

        // 不存在的 id。
        let err = storage
            .update_archive_object_status(9_999, ArchiveStatus::Uploaded, "", None, None)
            .expect_err("不存在的 id 必须失败");
        assert_eq!(
            err.downcast_ref::<ArchiveStoreError>(),
            Some(&ArchiveStoreError::NotFound)
        );

        // 数据库里的非法状态不能被静默降级。
        let poisoned_id = storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00003.csv.gz",
                100,
                200,
                ArchiveStatus::Pending,
            ))
            .expect("插入第三个归档对象失败");
        execute(
            storage,
            "UPDATE archive_objects SET status = 'bogus' WHERE id = $1",
            &[&poisoned_id],
        );
        let err = storage
            .update_archive_object_status(poisoned_id, ArchiveStatus::Uploaded, "", None, None)
            .expect_err("非法状态必须读取失败");
        assert!(
            format!("{err:#}").contains("archive_objects.status 字段值非法"),
            "非法状态必须显式报错：{err:#}"
        );
    }

    #[test]
    fn pg_archive_state_upsert_and_scan_rows_use_samples_id() {
        const NAME: &str = "pg_archive_state_upsert_and_scan_rows_use_samples_id";
        let Some(pg) = TestPg::create(NAME, "scan") else {
            return;
        };
        let storage = pg.storage();

        // archive_state：UPSERT、参数化、注入字符串按字面量保存。
        assert_eq!(
            storage
                .get_archive_state("last_archived_ts")
                .expect("读取缺失水位失败"),
            None
        );
        storage
            .set_archive_state("last_archived_ts", "100", 1_000)
            .expect("写入归档水位失败");
        storage
            .set_archive_state("last_archived_ts", "200", 2_000)
            .expect("更新归档水位失败");
        assert_eq!(
            storage
                .get_archive_state("last_archived_ts")
                .expect("读取归档水位失败"),
            Some("200".to_string())
        );
        let key = "k'quote";
        let value = "v'; DROP TABLE archive_state; --";
        storage
            .set_archive_state(key, value, 3_000)
            .expect("写入含引号水位失败");
        assert_eq!(
            storage.get_archive_state(key).expect("读取含引号水位失败"),
            Some(value.to_string())
        );
        assert_eq!(
            storage
                .get_archive_state("last_archived_ts")
                .expect("读取归档水位失败"),
            Some("200".to_string()),
            "注入字符串不得破坏已有水位"
        );

        let base = 1_700_000_000_000_i64;
        execute(
            storage,
            "INSERT INTO samples (agent_id, metric, labels, ts, value) VALUES
                 ('agent-1', 'cpu.usage', '{\"host\":\"h0\"}', $1, 1.0),
                 ('agent-1', 'cpu.usage', '{\"host\":\"h1\"}', $2, 2.0),
                 ('agent-1', 'cpu.usage', '{\"host\":\"h2\"}', $3, 3.0),
                 ('agent-1', 'cpu.usage', '{\"host\":\"h3\"}', $4, 10.0)",
            &[&(base + 1), &(base + 2), &(base + 3), &(base + 10)],
        );

        // 左闭右开：base + 10 必须被排除；limit 生效。
        let first = storage
            .scan_archive_rows(base, base + 10, None, 2)
            .expect("扫描归档 raw 失败");
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].ts, base + 1);
        assert_eq!(first[1].ts, base + 2);
        assert!(first[0].rowid < first[1].rowid, "必须按 samples.id 升序");
        assert_eq!(first[0].agent_id, "agent-1");
        assert_eq!(first[0].metric, "cpu.usage");
        assert_eq!(first[0].labels, r#"{"host":"h0"}"#);
        assert_eq!(first[0].value, 1.0);
        let ids = fetch(
            storage,
            "SELECT id FROM samples WHERE ts < $1 ORDER BY id",
            &[&(base + 10)],
        );
        let first_page_ids: Vec<i64> = ids.iter().take(first.len()).map(|row| row.get(0)).collect();
        assert_eq!(
            first.iter().map(|row| row.rowid).collect::<Vec<_>>(),
            first_page_ids,
            "ArchiveRawRow.rowid 必须来自 samples.id"
        );

        // after_rowid 排他。
        let second = storage
            .scan_archive_rows(base, base + 10, Some(first[1].rowid), 2)
            .expect("扫描第二页失败");
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].ts, base + 3);
        assert!(second[0].rowid > first[1].rowid);
        assert!(storage
            .scan_archive_rows(base, base + 10, Some(second[0].rowid), 2)
            .expect("扫描末页失败")
            .is_empty());

        // limit = 0、空范围、时间范围外都返回空，不 panic。
        assert!(storage
            .scan_archive_rows(base, base + 10, None, 0)
            .expect("limit=0 扫描失败")
            .is_empty());
        assert!(storage
            .scan_archive_rows(base + 100, base + 200, None, 10)
            .expect("空范围扫描失败")
            .is_empty());
        assert!(storage
            .scan_archive_rows(base + 10, base + 20, None, 10)
            .expect("单点范围扫描失败")
            .iter()
            .all(|row| row.ts == base + 10));
        assert_eq!(storage.count_archive_objects().expect("对象计数失败"), 0);
    }

    /// raw 维护锁必须固定，且不能与 schema 迁移锁同 key。
    #[test]
    fn raw_maintenance_lock_key_is_fixed_and_distinct_from_schema_lock() {
        assert_eq!(RAW_MAINTENANCE_ADVISORY_LOCK_KEY, 0x5242_5047_0000_0012);
        assert_ne!(
            RAW_MAINTENANCE_ADVISORY_LOCK_KEY,
            crate::storage::postgres::schema::SCHEMA_ADVISORY_LOCK_KEY,
            "raw 维护锁不能复用 schema 迁移锁"
        );
    }

    /// 在 raw 维护 advisory lock 内读取「水位 / 代际 / MAX(id)」，得到一致的
    /// 快照；同时验证测试侧取同一把锁不会与生产事务死锁。
    fn locked_raw_state(
        storage: &PostgresStorage,
    ) -> (Option<String>, Option<String>, Option<i64>) {
        storage
            .with_client(|client| {
                let mut tx = client.transaction()?;
                tx.query_one(
                    "SELECT pg_advisory_xact_lock($1)",
                    &[&RAW_MAINTENANCE_ADVISORY_LOCK_KEY],
                )?;
                let watermark: Option<String> = tx
                    .query_opt(
                        "SELECT value FROM maintenance_state WHERE key = $1",
                        &[&STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID],
                    )?
                    .map(|row| row.get(0));
                let generation: Option<String> = tx
                    .query_opt(
                        "SELECT value FROM maintenance_state WHERE key = $1",
                        &[&STATE_RAW_PRUNE_GENERATION],
                    )?
                    .map(|row| row.get(0));
                let max_id: Option<i64> = tx.query_one("SELECT MAX(id) FROM samples", &[])?.get(0);
                tx.commit()?;
                Ok((watermark, generation, max_id))
            })
            .expect("读取 raw 维护状态失败")
    }

    /// claim 与 prune 两线程并发循环：同一把事务级 advisory lock 串行化
    /// 「读水位/代际 + 条件写」与「删行 + 收敛水位/推进代际」。
    ///
    /// 断言：
    /// - 每轮 prune 删光本轮所有行，水位不得残留、代际恰好 +1；
    /// - 并发期间 claim 只要求无错、不 panic（可能一直输给 prune 返回 false），
    ///   且不能在 raw 已空时留下高水位；
    /// - 空闲后 claim 返回 true 时水位等于写入值；再 prune 清空后不保留已删行、
    ///   水位删除、代际 +1。
    #[test]
    fn pg_claim_and_prune_are_serialized_by_advisory_lock() {
        const NAME: &str = "pg_claim_and_prune_are_serialized_by_advisory_lock";
        let Some(mut pg) = TestPg::create_with_pool(NAME, "lockrace", 2) else {
            return;
        };
        let storage = Arc::new(pg.take_storage());
        let base = 1_700_000_000_000_i64;

        for cycle in 0..12i64 {
            let start = base + cycle * 100;
            execute(
                &storage,
                "INSERT INTO samples (agent_id, metric, labels, ts, value)
                 SELECT 'a', 'cpu.usage', '{}', $1::BIGINT + g, 1.0
                 FROM generate_series(0, 7) AS g",
                &[&start],
            );
            let cutoff = start + 8;
            let barrier = Arc::new(Barrier::new(2));

            let claim_storage = Arc::clone(&storage);
            let claim_barrier = Arc::clone(&barrier);
            let claim_handle = std::thread::spawn(move || -> Result<()> {
                claim_barrier.wait();
                for _ in 0..40 {
                    // 与 downsample 调用方相同的快照顺序：先水位、再代际、
                    // 最后 MAX(id)。否则可能在 prune 提交后拿新代际配旧 MAX。
                    let expected_rowid = claim_storage
                        .get_maintenance_state(STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID)?
                        .and_then(|raw| raw.trim().parse::<i64>().ok());
                    let generation = claim_storage
                        .get_maintenance_state(STATE_RAW_PRUNE_GENERATION)?
                        .and_then(|raw| raw.trim().parse::<i64>().ok())
                        .unwrap_or(0);
                    let Some(max_id) = claim_storage.raw_new_rows(None)?.0 else {
                        continue;
                    };
                    // 竞态下 claim 可能一直输给 prune（返回 false）而得不到
                    // 成功；这里只要求无错、不 panic，成功路径由下面的空闲期
                    // 断言覆盖。
                    let _ = claim_storage.claim_raw_rowid_if_unchanged(
                        expected_rowid,
                        generation,
                        max_id,
                    )?;
                }
                Ok(())
            });

            let prune_storage = Arc::clone(&storage);
            let prune_barrier = Arc::clone(&barrier);
            let prune_handle = std::thread::spawn(move || -> Result<()> {
                prune_barrier.wait();
                for _ in 0..8 {
                    prune_storage.prune_samples_before(cutoff)?;
                }
                Ok(())
            });

            claim_handle
                .join()
                .expect("claim 线程 panic")
                .expect("claim 线程返回错误");
            prune_handle
                .join()
                .expect("prune 线程 panic")
                .expect("prune 线程返回错误");

            let (watermark, generation, max_id) = locked_raw_state(&storage);
            assert_eq!(max_id, None, "第 {cycle} 轮 prune 必须删光本轮的行");
            assert_eq!(
                watermark, None,
                "第 {cycle} 轮 raw 为空时不得残留 rowid 水位"
            );
            assert_eq!(
                generation,
                Some((cycle + 1).to_string()),
                "第 {cycle} 轮删除最大 id 行必须恰好推进一代"
            );
        }

        // 空闲期：claim 返回 true 后水位必须等于写入值。
        let start = base + 10_000;
        execute(
            &storage,
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             SELECT 'a', 'cpu.usage', '{}', $1::BIGINT + g, 1.0
             FROM generate_series(0, 2) AS g",
            &[&start],
        );
        let max_id = storage
            .raw_new_rows(None)
            .expect("读取 MAX(id) 失败")
            .0
            .expect("应有 raw 行");
        let expected_rowid = get_state(&storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID)
            .and_then(|raw| raw.trim().parse::<i64>().ok());
        let generation = get_state(&storage, STATE_RAW_PRUNE_GENERATION)
            .and_then(|raw| raw.trim().parse::<i64>().ok())
            .unwrap_or(0);
        assert!(
            storage
                .claim_raw_rowid_if_unchanged(expected_rowid, generation, max_id)
                .expect("空闲期 CAS 失败"),
            "空闲期 CAS 必须命中"
        );
        assert_eq!(
            get_state(&storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            Some(max_id.to_string()),
            "claim 返回 true 后水位必须等于写入值"
        );

        // 再 prune 全部：已删行不保留，水位清空，代际 +1。
        storage
            .prune_samples_before(start + 3)
            .expect("最终 raw 删除失败");
        let rows: i64 = fetch(&storage, "SELECT COUNT(*)::BIGINT FROM samples", &[])[0].get(0);
        assert_eq!(rows, 0, "prune 后不得保留已删行");
        assert_eq!(
            get_state(&storage, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID),
            None,
            "raw 清空后必须删除 rowid 水位"
        );
        assert_eq!(
            get_state(&storage, STATE_RAW_PRUNE_GENERATION),
            Some((generation + 1).to_string()),
            "最终 prune 删除最大 id 行必须再推进一代"
        );
    }
}
