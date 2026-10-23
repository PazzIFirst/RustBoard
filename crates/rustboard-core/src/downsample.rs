//! M4：降采样与保留期 worker。
//!
//! - 1m：把已关闭分钟的 raw 聚合进 `samples_1m`；
//! - 1h：把已关闭整点的 1m 聚合进 `samples_1h`（按 `count` 加权平均）；
//! - retention：按层分批删除过期数据；raw 同时受 1m 水位与可选归档水位门禁，
//!   1m 受 1h 水位门禁，水位缺失时该层不删；
//! - 所有进度写入 `maintenance_state`；**先提交数据再写水位**，崩溃后最多重做
//!   最后一块，不会出现「水位已过但数据没写」。
//!
//! 时间统一使用 UTC 毫秒。worker 不读真实时钟：`now` 由调用方（hub / CLI）传入，
//! 便于测试与同一轮内保持一致。

use anyhow::Result;
use rustboard_common::config::HubConfig;
use serde::Serialize;

use crate::storage::sqlite::{SqliteStorage, DOWNSAMPLE_MAX_CHUNK_ROWS};
use crate::storage::{Storage, TierStats, BUCKET_1H_MS, BUCKET_1M_MS};

/// `maintenance_state` 键：1m 层已完整聚合到（不含）该时间戳。
pub const STATE_DOWNSAMPLE_1M_WATERMARK: &str = "downsample_1m_watermark";
/// `maintenance_state` 键：1h 层已完整聚合到（不含）该时间戳。
pub const STATE_DOWNSAMPLE_1H_WATERMARK: &str = "downsample_1h_watermark";
/// `maintenance_state` 键：最近一次成功执行保留期任务的时间戳。
pub const STATE_RETENTION_LAST_RUN: &str = "retention_last_run";
/// `maintenance_state` 键：最近一次维护任务失败信息（成功一轮后清空）。
pub const STATE_LAST_ERROR: &str = "last_error";

/// 一天对应的毫秒数。
const DAY_MS: i64 = 86_400_000;

/// 单层降采样结果。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DownsampleTierReport {
    /// 本次写入/更新的聚合桶数（含最近 2 个桶的重算）。
    pub buckets: usize,
    /// 参与聚合的源行数（含最近 2 个桶的重算）。
    pub rows: usize,
    /// 本次处理的后填块数（`max_backfill_hours` 限制的单位）。
    pub chunks: usize,
    /// 任务结束时该层持久化的水位（无数据且从未写过时为 `None`）。
    pub watermark: Option<i64>,
}

/// 一次降采样任务的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DownsampleReport {
    /// 1m 层（raw → samples_1m）。
    pub one_minute: DownsampleTierReport,
    /// 1h 层（samples_1m → samples_1h）。
    pub one_hour: DownsampleTierReport,
    /// 失败信息；成功时为 `None`（失败路径整体返回 `Err`，此字段供将来
    /// 非致命错误一并序列化）。
    pub error: Option<String>,
}

/// 单层保留期结果。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RetentionLayerReport {
    /// 配置的保留天数（0 表示该层不自动删除）。
    pub retention_days: u32,
    /// 由配置与 `now` 算出的排他边界；该层禁用时为 `None`。
    pub cutoff: Option<i64>,
    /// 叠加降采样/归档门禁后实际使用的删除边界。
    pub effective_cutoff: Option<i64>,
    /// 实际删除行数。
    pub deleted: usize,
    /// 实际执行了删除的批次数。
    pub batches: usize,
    /// 该层配置为 0（不删除）。
    pub disabled: bool,
    /// 缺少前置水位，本轮没有删除该层。
    pub skipped_no_watermark: bool,
    /// 删除边界被更早的降采样水位截断（可能还有未聚合数据）。
    pub blocked_by_downsample: bool,
    /// 删除边界被更早的归档水位截断（raw 层）。
    pub blocked_by_archive: bool,
}

/// 一次保留期任务的结果。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RetentionReport {
    pub raw: RetentionLayerReport,
    pub one_minute: RetentionLayerReport,
    pub one_hour: RetentionLayerReport,
    /// 失败信息；成功时为 `None`。
    pub error: Option<String>,
}

/// 维护状态快照（`maintenance status` 的输出主体）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MaintenanceStatus {
    /// raw 层行数与时间范围。
    pub raw: TierStats,
    /// 1m 层行数与时间范围。
    pub one_minute: TierStats,
    /// 1h 层行数与时间范围。
    pub one_hour: TierStats,
    /// 1m 聚合水位。
    pub downsample_1m_watermark: Option<i64>,
    /// 1h 聚合水位。
    pub downsample_1h_watermark: Option<i64>,
    /// 最近一次成功保留期任务时间。
    pub retention_last_run: Option<i64>,
    /// 最近一次维护任务失败信息（成功后清空）。
    pub last_error: Option<String>,
}

/// 把时间戳向下取整到 `bucket_ms` 边界（UTC 毫秒）。
fn bucket_floor(ts: i64, bucket_ms: i64) -> i64 {
    ts.div_euclid(bucket_ms) * bucket_ms
}

/// 读取整数型 `maintenance_state`。
///
/// - key 不存在或值为空串 → `None`（空串供 hub 清除 `last_error` 使用，也把
///   被清空的水位当作「缺失」处理，宁可重做也不误删）；
/// - 非法值 → `Err`，明确点名字段，不静默跳过损坏的进度。
fn read_state_i64(db: &SqliteStorage, key: &str) -> Result<Option<i64>> {
    let Some(raw) = db.get_maintenance_state(key)? else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let value = trimmed
        .parse::<i64>()
        .map_err(|_| anyhow::anyhow!("maintenance_state.{key} 不是合法的十进制整数: {raw:?}"))?;
    Ok(Some(value))
}

/// 持久化水位（十进制字符串）。
fn write_watermark(db: &SqliteStorage, key: &str, watermark: i64, now: i64) -> Result<()> {
    db.set_maintenance_state(key, &watermark.to_string(), now)
}

/// 计一段 raw 的分块结束点：单事务最多约 [`DOWNSAMPLE_MAX_CHUNK_ROWS`] 行。
///
/// 桶不可拆分（拆开会让 avg/count 只统计到一部分行），所以若第一个桶本身
/// 就超过行数上限，则整桶处理。返回值为分钟桶边界。
fn raw_chunk_end(db: &SqliteStorage, from_ts: i64, max_end: i64) -> Result<i64> {
    let Some(ts) = db.raw_ts_at_offset(from_ts, max_end, DOWNSAMPLE_MAX_CHUNK_ROWS)? else {
        return Ok(max_end);
    };
    let bucket = bucket_floor(ts, BUCKET_1M_MS);
    if bucket > from_ts {
        return Ok(bucket.min(max_end));
    }
    Ok((bucket + BUCKET_1M_MS).min(max_end))
}

/// 计算一段 1m 的分块结束点：单事务最多约 [`DOWNSAMPLE_MAX_CHUNK_ROWS`] 行。
fn minute_chunk_end(db: &SqliteStorage, from_ts: i64, max_end: i64) -> Result<i64> {
    let Some(ts) = db.samples_1m_ts_at_offset(from_ts, max_end, DOWNSAMPLE_MAX_CHUNK_ROWS)? else {
        return Ok(max_end);
    };
    let bucket = bucket_floor(ts, BUCKET_1H_MS);
    if bucket > from_ts {
        return Ok(bucket.min(max_end));
    }
    Ok((bucket + BUCKET_1H_MS).min(max_end))
}

/// 按小时块后填 1m 聚合，并重算最近 2 个已关闭分钟桶。
fn run_one_minute_tier(
    db: &SqliteStorage,
    now: i64,
    max_backfill_chunks: Option<u32>,
) -> Result<DownsampleTierReport> {
    let closed_end = bucket_floor(now, BUCKET_1M_MS);
    let mut report = DownsampleTierReport::default();
    let stored = read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?;
    let raw = db.raw_stats()?;

    let start = match stored {
        // 水位可能因回拨时钟而超前：不越过已关闭分钟。
        Some(watermark) => Some(watermark.min(closed_end)),
        // 首次运行从最旧 raw 所在分钟开始。
        None => raw.oldest_ts.map(|ts| bucket_floor(ts, BUCKET_1M_MS)),
    };
    // 追平目标就是最后一个已关闭分钟：没有 raw 行的空分钟也算「已完整聚合」，
    // 否则 1h 永远等不到一个被 1m 水位完整覆盖的整点（稀疏数据是常态）。
    // 完全没有 raw 行时不推进水位（不写假水位）。
    let target_end = if raw.rows > 0 {
        closed_end
    } else {
        start.unwrap_or(closed_end)
    };

    if let Some(mut cursor) = start {
        let mut chunks: u32 = 0;
        while cursor < target_end {
            if max_backfill_chunks.is_some_and(|limit| chunks >= limit) {
                break;
            }
            let candidate_end = (cursor + BUCKET_1H_MS).min(target_end);
            let chunk_end = raw_chunk_end(db, cursor, candidate_end)?;
            // 防御：分块不前进就退出，避免任何边界错误造成死循环。
            if chunk_end <= cursor {
                break;
            }
            let result = db.downsample_1m_range(cursor, chunk_end)?;
            // 数据已在 downsample_1m_range 内提交；这里再写水位。崩溃只会重做
            // 本块，不会丢数据。
            write_watermark(db, STATE_DOWNSAMPLE_1M_WATERMARK, chunk_end, now)?;
            report.buckets += result.buckets;
            report.rows += result.rows;
            report.chunks += 1;
            cursor = chunk_end;
            chunks += 1;
        }
    }

    // 每轮重算最近 2 个已关闭分钟桶，覆盖迟到 / 重传批次；upsert 幂等，
    // 不推进水位（它们本就在水位之内或之后由 tail 兜底）。
    if closed_end >= 2 * BUCKET_1M_MS {
        let tail_start = closed_end - 2 * BUCKET_1M_MS;
        let result = db.downsample_1m_range(tail_start, closed_end)?;
        report.buckets += result.buckets;
        report.rows += result.rows;
    }

    report.watermark = read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?;
    Ok(report)
}

/// 按小时块后填 1h 聚合，并重算最近 2 个已关闭整点小时。
///
/// 1h 只聚合「1m 已完整生成」的整点小时：上限同时受 `closed_end_1h` 与
/// 1m 水位约束，且必须落在整点边界上，绝不聚合半个小时的残缺数据。
fn run_one_hour_tier(
    db: &SqliteStorage,
    now: i64,
    max_backfill_chunks: Option<u32>,
) -> Result<DownsampleTierReport> {
    let closed_end = bucket_floor(now, BUCKET_1H_MS);
    let mut report = DownsampleTierReport::default();
    let minute_watermark = read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?;
    let hour_limit = match minute_watermark {
        Some(watermark) => bucket_floor(watermark.min(closed_end), BUCKET_1H_MS),
        None => 0,
    };
    let minute = db.samples_1m_stats()?;
    let stored = read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)?;

    let start = match stored {
        Some(watermark) => Some(watermark.min(hour_limit)),
        None if minute.rows > 0 => minute.oldest_ts.map(|ts| bucket_floor(ts, BUCKET_1H_MS)),
        None => None,
    };
    // 追平目标就是最后一个 1m 已完整覆盖的整点；空小时不产生 1h 行，但水位
    // 可以越过它（其 1m 数据确实已经聚合完毕）。
    let target_end = if minute.rows > 0 {
        hour_limit
    } else {
        start.unwrap_or(0)
    };

    if let Some(mut cursor) = start {
        let mut chunks: u32 = 0;
        while cursor < target_end {
            if max_backfill_chunks.is_some_and(|limit| chunks >= limit) {
                break;
            }
            let candidate_end = (cursor + BUCKET_1H_MS).min(target_end);
            let chunk_end = minute_chunk_end(db, cursor, candidate_end)?;
            if chunk_end <= cursor {
                break;
            }
            let result = db.downsample_1h_range(cursor, chunk_end)?;
            write_watermark(db, STATE_DOWNSAMPLE_1H_WATERMARK, chunk_end, now)?;
            report.buckets += result.buckets;
            report.rows += result.rows;
            report.chunks += 1;
            cursor = chunk_end;
            chunks += 1;
        }
    }

    // 最近 2 个「1m 已完整生成」的整点小时重算（受 hour_limit 约束）。
    if hour_limit > 0 {
        let tail_start = hour_limit.saturating_sub(2 * BUCKET_1H_MS).max(0);
        let result = db.downsample_1h_range(tail_start, hour_limit)?;
        report.buckets += result.buckets;
        report.rows += result.rows;
    }

    report.watermark = read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)?;
    Ok(report)
}

/// 执行一轮降采样。
///
/// - `max_backfill_hours = None`：手动 / CLI 模式，持续分块直到追平；
/// - `Some(n)`：后台模式，每轮最多处理 n 个「小时块」，避免长时间占用写锁。
///
/// 无 raw 数据时不写水位；失败返回 `Err`（不 panic），由调用方记录 WARN 与
/// `maintenance_state.last_error`，下一轮重试。
pub fn run_downsample(
    db: &SqliteStorage,
    now: i64,
    max_backfill_hours: Option<u32>,
) -> Result<DownsampleReport> {
    let one_minute = run_one_minute_tier(db, now, max_backfill_hours)?;
    let one_hour = run_one_hour_tier(db, now, max_backfill_hours)?;
    Ok(DownsampleReport {
        one_minute,
        one_hour,
        error: None,
    })
}

/// 计算某层的排他删除边界；`days = 0` 表示该层禁用。
fn layer_cutoff(days: u32, now: i64) -> Option<i64> {
    if days == 0 {
        None
    } else {
        Some(now.saturating_sub(i64::from(days) * DAY_MS))
    }
}

/// raw 层保留：同时受 1m 降采样水位与可选归档水位门禁。
fn retention_raw(
    db: &SqliteStorage,
    days: u32,
    now: i64,
    watermark_1m: Option<i64>,
    archive_watermark: Option<i64>,
) -> Result<RetentionLayerReport> {
    let mut report = RetentionLayerReport {
        retention_days: days,
        ..RetentionLayerReport::default()
    };
    let Some(cutoff) = layer_cutoff(days, now) else {
        report.disabled = true;
        return Ok(report);
    };
    report.cutoff = Some(cutoff);
    let Some(watermark) = watermark_1m else {
        // 没有 1m 水位 = raw 还没被聚合过，删除会永久丢数据。
        report.skipped_no_watermark = true;
        return Ok(report);
    };
    report.blocked_by_downsample = watermark < cutoff;
    let mut effective = cutoff.min(watermark);
    if let Some(archive) = archive_watermark {
        report.blocked_by_archive = archive < cutoff;
        effective = effective.min(archive);
    }
    report.effective_cutoff = Some(effective);
    let pruned = db.prune_samples_before(effective)?;
    report.deleted = pruned.deleted;
    report.batches = pruned.batches;
    Ok(report)
}

/// 1m 层保留：受 1h 降采样水位门禁。
fn retention_minute(
    db: &SqliteStorage,
    days: u32,
    now: i64,
    watermark_1h: Option<i64>,
) -> Result<RetentionLayerReport> {
    let mut report = RetentionLayerReport {
        retention_days: days,
        ..RetentionLayerReport::default()
    };
    let Some(cutoff) = layer_cutoff(days, now) else {
        report.disabled = true;
        return Ok(report);
    };
    report.cutoff = Some(cutoff);
    let Some(watermark) = watermark_1h else {
        report.skipped_no_watermark = true;
        return Ok(report);
    };
    report.blocked_by_downsample = watermark < cutoff;
    let effective = cutoff.min(watermark);
    report.effective_cutoff = Some(effective);
    let pruned = db.prune_samples_1m_before(effective)?;
    report.deleted = pruned.deleted;
    report.batches = pruned.batches;
    Ok(report)
}

/// 1h 层保留：最老的一层，没有更上层水位门禁。
fn retention_hour(db: &SqliteStorage, days: u32, now: i64) -> Result<RetentionLayerReport> {
    let mut report = RetentionLayerReport {
        retention_days: days,
        ..RetentionLayerReport::default()
    };
    let Some(cutoff) = layer_cutoff(days, now) else {
        report.disabled = true;
        return Ok(report);
    };
    report.cutoff = Some(cutoff);
    report.effective_cutoff = Some(cutoff);
    let pruned = db.prune_samples_1h_before(cutoff)?;
    report.deleted = pruned.deleted;
    report.batches = pruned.batches;
    Ok(report)
}

/// 执行一轮保留期删除。
///
/// `archive_watermark = None` 表示未启用归档（M4-A 的 CLI / hub 都传 None；
/// M4-C 接入后传 `archive_state.last_archived_ts`）。任何一层删除失败都返回
/// `Err`，已提交的批次保持幂等，下一轮继续。
pub fn run_retention(
    db: &SqliteStorage,
    cfg: &HubConfig,
    now: i64,
    archive_watermark: Option<i64>,
) -> Result<RetentionReport> {
    let watermark_1m = read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?;
    let watermark_1h = read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)?;

    let raw = retention_raw(
        db,
        cfg.retention_raw_days,
        now,
        watermark_1m,
        archive_watermark,
    )?;
    let one_minute = retention_minute(db, cfg.retention_1m_days, now, watermark_1h)?;
    let one_hour = retention_hour(db, cfg.retention_1h_days, now)?;

    // 三层都成功后才记录本轮时间；失败时保留旧值，便于判断上次完整成功的时间。
    db.set_maintenance_state(STATE_RETENTION_LAST_RUN, &now.to_string(), now)?;

    Ok(RetentionReport {
        raw,
        one_minute,
        one_hour,
        error: None,
    })
}

/// 读取当前维护状态（各层行数 / 时间范围 / 水位 / 最近错误）。
pub fn maintenance_status(db: &SqliteStorage) -> Result<MaintenanceStatus> {
    let last_error = db
        .get_maintenance_state(STATE_LAST_ERROR)?
        .filter(|value| !value.trim().is_empty());
    Ok(MaintenanceStatus {
        raw: db.raw_stats()?,
        one_minute: db.samples_1m_stats()?,
        one_hour: db.samples_1h_stats()?,
        downsample_1m_watermark: read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?,
        downsample_1h_watermark: read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)?,
        retention_last_run: read_state_i64(db, STATE_RETENTION_LAST_RUN)?,
        last_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sqlite::AggregateRowForTest;
    use crate::storage::Storage;
    use rustboard_common::model::{Sample, SampleBatch};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 固定测试时间：1_700_000_100_000 恰好是整分钟（15 分钟偏移的整点内）。
    const NOW: i64 = 1_700_000_100_000;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn seed(db: &SqliteStorage, agent: &str, samples: Vec<Sample>) {
        let batch = SampleBatch {
            agent_id: agent.to_string(),
            epoch: 1,
            seq: SEQ.fetch_add(1, Ordering::Relaxed),
            boot_id: "boot".to_string(),
            sent_at: 0,
            samples,
        };
        db.insert_batch(&batch).unwrap();
    }

    fn cfg_with_retention(raw: u32, one_minute: u32, one_hour: u32) -> HubConfig {
        HubConfig {
            retention_raw_days: raw,
            retention_1m_days: one_minute,
            retention_1h_days: one_hour,
            ..HubConfig::default()
        }
    }

    fn find_agg<'a>(rows: &'a [AggregateRowForTest], labels: &str) -> &'a AggregateRowForTest {
        rows.iter()
            .find(|row| row.labels == labels)
            .unwrap_or_else(|| panic!("缺少 labels={labels} 的聚合行: {rows:?}"))
    }

    /// 无任何数据：返回全零、不写假水位，状态也保持空。
    #[test]
    fn m4a_run_downsample_without_raw_writes_no_watermark() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let report = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(report.one_minute, DownsampleTierReport::default());
        assert_eq!(report.one_hour, DownsampleTierReport::default());
        assert_eq!(report.error, None);

        assert_eq!(
            db.get_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK)
                .unwrap(),
            None
        );
        assert_eq!(
            db.get_maintenance_state(STATE_DOWNSAMPLE_1H_WATERMARK)
                .unwrap(),
            None
        );
        let status = maintenance_status(&db).unwrap();
        assert_eq!(status, MaintenanceStatus::default());
    }

    /// 1m：只聚合已关闭分钟；最近 2 个桶会被重算（同一批数据重复计数），
    /// 当前分钟与空桶都不建行。
    #[test]
    fn m4a_run_downsample_one_minute_backfill_and_open_minute() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS);
        let base = closed - 2 * BUCKET_1M_MS; // closed 是否整分钟取决于 NOW；见断言
        assert_eq!(NOW % BUCKET_1M_MS, 0, "固定测试时间必须是整分钟");

        seed(
            &db,
            "a1",
            vec![
                Sample::new("cpu.usage", base + 1_000, 1.0),
                Sample::new("cpu.usage", base + 20_000, 5.0),
                Sample::new("cpu.usage", base + 40_000, 3.0),
                Sample::new("cpu.usage", base + 5_000, 42.0).with_label("disk", "sda"),
                Sample::new("cpu.usage", base + 61_000, 7.0),
                // 当前未关闭分钟：不得进入 1m。
                Sample::new("cpu.usage", closed + 1_000, 99.0),
            ],
        );

        let report = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(report.one_minute.watermark, Some(closed));
        assert_eq!(report.one_minute.chunks, 1, "两分钟数据在一个小时块内");
        // 后填 2 个桶 / 5 行 + 最近 2 桶重算 3 桶 / 5 行。
        assert_eq!(report.one_minute.buckets, 6);
        assert_eq!(report.one_minute.rows, 10);

        let rows = db.aggregate_rows_for_test("1m");
        assert_eq!(rows.len(), 3, "两个分钟 × 两种标签 = 3 个非空桶");
        let plain = find_agg(&rows, "{}");
        assert_eq!(plain.bucket_ts, base);
        assert_eq!(plain.min_value, 1.0);
        assert_eq!(plain.max_value, 5.0);
        assert!((plain.avg_value - 3.0).abs() < 1e-9);
        assert_eq!(plain.last_value, 3.0);
        assert_eq!(plain.count, 3);
        let disk = find_agg(&rows, r#"{"disk":"sda"}"#);
        assert_eq!(disk.bucket_ts, base);
        assert_eq!(disk.count, 1);
        assert_eq!(disk.last_value, 42.0);
        // 第二个分钟桶只有 7.0。
        let second = rows
            .iter()
            .find(|row| row.bucket_ts == base + BUCKET_1M_MS)
            .expect("第二个分钟桶必须存在");
        assert_eq!(second.count, 1);
        assert_eq!(second.last_value, 7.0);
        // 未关闭分钟不得建行。
        assert!(
            rows.iter().all(|row| row.bucket_ts != closed),
            "未关闭分钟不得聚合: {rows:?}"
        );

        // 当前小时尚未结束：1h 不能聚合半个小时的残缺数据，也不写 1h 水位。
        assert_eq!(report.one_hour.watermark, None);
        assert!(db.aggregate_rows_for_test("1h").is_empty());
    }

    /// 重跑幂等；最近桶的迟到数据（更大 ts）会被重算修正。
    #[test]
    fn m4a_run_downsample_rerun_is_idempotent_and_recomputes_late_data() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS);
        let last_bucket = closed - BUCKET_1M_MS;
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", last_bucket + 1_000, 1.0)],
        );

        let first = run_downsample(&db, NOW, None).unwrap();
        let before_1m = db.aggregate_rows_for_test("1m");
        assert_eq!(before_1m.len(), 1);
        assert_eq!(first.one_minute.watermark, Some(closed));

        let again = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(again.one_minute.watermark, Some(closed));
        assert_eq!(
            db.aggregate_rows_for_test("1m"),
            before_1m,
            "重复执行不得增行 / 改值"
        );

        // 迟到重传：最近已关闭桶来了更晚的样本，下一次 tail 重算必须修正。
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", last_bucket + 30_000, 9.0)],
        );
        let third = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(third.one_minute.watermark, Some(closed));
        let rows = db.aggregate_rows_for_test("1m");
        assert_eq!(rows.len(), 1, "重算不得新增桶");
        assert_eq!(rows[0].count, 2);
        assert_eq!(rows[0].max_value, 9.0);
        assert_eq!(rows[0].last_value, 9.0);
        assert!((rows[0].avg_value - 5.0).abs() < 1e-9);
    }

    /// 1h：只聚合完整小时，按 count 加权平均；重复执行幂等。
    #[test]
    fn m4a_run_downsample_one_hour_weighted_and_complete_hours_only() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let current_hour = bucket_floor(NOW, BUCKET_1H_MS);
        let hour = current_hour - 2 * BUCKET_1H_MS;
        seed(
            &db,
            "a1",
            vec![
                // 第一个完整小时：3 个分钟桶，count 分别为 2 / 1 / 1。
                Sample::new("cpu.usage", hour + 1_000, 0.0),
                Sample::new("cpu.usage", hour + 2_000, 10.0),
                Sample::new("cpu.usage", hour + 61_000, 20.0),
                Sample::new("cpu.usage", hour + 121_000, 1_000.0),
                // 第二个完整小时：1 个分钟桶。
                Sample::new("cpu.usage", hour + BUCKET_1H_MS + 1_000, 7.0),
            ],
        );

        let report = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(report.one_hour.watermark, Some(current_hour));
        let rows = db.aggregate_rows_for_test("1h");
        assert_eq!(rows.len(), 2, "只聚合两个完整小时");

        let first = rows
            .iter()
            .find(|row| row.bucket_ts == hour)
            .expect("第一个完整小时必须存在");
        assert_eq!(first.min_value, 0.0);
        assert_eq!(first.max_value, 1_000.0);
        assert_eq!(first.count, 4);
        assert_eq!(first.last_value, 1_000.0);
        // (5*2 + 20*1 + 1000*1)/4 = 257.5；简单平均会是 341.67。
        assert!(
            (first.avg_value - 257.5).abs() < 1e-9,
            "1h 必须按 count 加权: {}",
            first.avg_value
        );
        let second = rows
            .iter()
            .find(|row| row.bucket_ts == hour + BUCKET_1H_MS)
            .expect("第二个完整小时必须存在");
        assert_eq!(second.count, 1);
        assert_eq!(second.last_value, 7.0);

        // 当前小时只有 15 分钟的数据：绝不能提前聚合。
        assert!(rows.iter().all(|row| row.bucket_ts != current_hour));

        // 幂等：重跑后 1m / 1h 内容都不变。
        let before_1m = db.aggregate_rows_for_test("1m");
        let before_1h = rows.clone();
        let again = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(again.one_hour.watermark, Some(current_hour));
        assert_eq!(db.aggregate_rows_for_test("1m"), before_1m);
        assert_eq!(db.aggregate_rows_for_test("1h"), before_1h);
    }

    /// 后台模式 `Some(n)`：每轮最多 n 个小时块，水位逐轮推进，最终追平。
    #[test]
    fn m4a_run_downsample_max_backfill_limits_chunks_and_catches_up() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS);
        let oldest = closed - 10 * BUCKET_1H_MS;
        seed(
            &db,
            "a1",
            vec![
                Sample::new("cpu.usage", oldest + 1_000, 1.0),
                Sample::new("cpu.usage", oldest + 2 * BUCKET_1H_MS, 2.0),
                Sample::new("cpu.usage", closed - 1_000, 3.0),
            ],
        );

        let first = run_downsample(&db, NOW, Some(1)).unwrap();
        assert_eq!(first.one_minute.chunks, 1);
        assert_eq!(
            first.one_minute.watermark,
            Some(oldest + BUCKET_1H_MS),
            "第一轮只处理第一个小时块"
        );

        let second = run_downsample(&db, NOW, Some(1)).unwrap();
        assert_eq!(second.one_minute.chunks, 1);
        assert_eq!(second.one_minute.watermark, Some(oldest + 2 * BUCKET_1H_MS));

        // None = 手动模式，持续处理直到追平最新 raw。
        let final_report = run_downsample(&db, NOW, None).unwrap();
        assert!(final_report.one_minute.chunks >= 7);
        assert_eq!(final_report.one_minute.watermark, Some(closed));
    }

    /// 损坏的水位必须报错（不 panic、不静默重置），错误点名字段。
    #[test]
    fn m4a_run_downsample_corrupt_watermark_returns_error() {
        let db = SqliteStorage::open_in_memory().unwrap();
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, "not-a-number", NOW)
            .unwrap();
        let err = run_downsample(&db, NOW, None).unwrap_err();
        assert!(
            err.to_string().contains(STATE_DOWNSAMPLE_1M_WATERMARK),
            "错误信息必须点名损坏的键: {err}"
        );
    }

    /// raw 保留：严格 `< cutoff`（等于不删）、0 = 不删、记录 retention_last_run。
    #[test]
    fn m4a_run_retention_raw_cutoff_boundary_and_zero() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let cutoff = NOW - 7 * DAY_MS;
        seed(
            &db,
            "a1",
            vec![
                Sample::new("cpu.usage", cutoff - 1_000, 1.0),
                Sample::new("cpu.usage", cutoff, 2.0),
                Sample::new("cpu.usage", cutoff + 1_000, 3.0),
                Sample::new("cpu.usage", NOW - 1_000, 4.0),
            ],
        );
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &NOW.to_string(), NOW)
            .unwrap();

        let cfg = cfg_with_retention(7, 90, 730);
        let report = run_retention(&db, &cfg, NOW, None).unwrap();
        assert_eq!(report.raw.retention_days, 7);
        assert_eq!(report.raw.cutoff, Some(cutoff));
        assert_eq!(report.raw.effective_cutoff, Some(cutoff));
        assert_eq!(report.raw.deleted, 1);
        assert_eq!(report.raw.batches, 1);
        assert!(!report.raw.disabled);
        assert!(!report.raw.skipped_no_watermark);
        assert!(!report.raw.blocked_by_downsample);

        let raw = db.raw_stats().unwrap();
        assert_eq!(raw.rows, 3, "等于 cutoff 的行必须保留");
        assert_eq!(raw.oldest_ts, Some(cutoff));
        assert_eq!(
            db.get_maintenance_state(STATE_RETENTION_LAST_RUN).unwrap(),
            Some(NOW.to_string())
        );

        // 0 = 该层不删：即使数据远早于默认保留期也不动。
        let cfg_disabled = cfg_with_retention(0, 0, 0);
        let report = run_retention(&db, &cfg_disabled, NOW, None).unwrap();
        assert!(report.raw.disabled);
        assert_eq!(report.raw.cutoff, None);
        assert_eq!(report.raw.deleted, 0);
        assert_eq!(db.raw_stats().unwrap().rows, 3);
    }

    /// raw 水位缺失 / 归档水位阻塞 / 1m 水位缺失三种门禁。
    #[test]
    fn m4a_run_retention_watermark_and_archive_gates() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let old_raw = NOW - 100 * DAY_MS;
        seed(&db, "a1", vec![Sample::new("cpu.usage", old_raw, 1.0)]);
        let cfg = cfg_with_retention(7, 90, 730);

        // 没有 1m 水位：raw 不得删除。
        let report = run_retention(&db, &cfg, NOW, None).unwrap();
        assert!(report.raw.skipped_no_watermark);
        assert_eq!(report.raw.deleted, 0);
        assert_eq!(db.raw_stats().unwrap().rows, 1);

        // 1m 水位已到 now，但归档水位更早：raw 仍不得删除，并标记归档阻塞。
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &NOW.to_string(), NOW)
            .unwrap();
        let archive_cutoff = NOW - 200 * DAY_MS;
        let report = run_retention(&db, &cfg, NOW, Some(archive_cutoff)).unwrap();
        assert_eq!(report.raw.deleted, 0);
        assert!(report.raw.blocked_by_archive);
        assert!(!report.raw.blocked_by_downsample);
        assert_eq!(report.raw.effective_cutoff, Some(archive_cutoff));
        assert_eq!(db.raw_stats().unwrap().rows, 1);

        // 归档水位推进到 now 后 raw 才可删。
        let report = run_retention(&db, &cfg, NOW, Some(NOW)).unwrap();
        assert_eq!(report.raw.deleted, 1);
        assert!(!report.raw.blocked_by_archive);
        assert_eq!(db.raw_stats().unwrap().rows, 0);

        // 1m 层：没有 1h 水位时不得删除。
        let old_bucket = bucket_floor(old_raw, BUCKET_1M_MS);
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", old_bucket + 1_000, 1.0)],
        );
        db.downsample_1m_range(old_bucket, old_bucket + BUCKET_1M_MS)
            .unwrap();
        assert_eq!(db.samples_1m_stats().unwrap().rows, 1);
        let report = run_retention(&db, &cfg, NOW, None).unwrap();
        assert!(report.one_minute.skipped_no_watermark);
        assert_eq!(report.one_minute.deleted, 0);
        assert_eq!(db.samples_1m_stats().unwrap().rows, 1);

        // 1h 水位到位后才允许删除 1m。
        db.set_maintenance_state(STATE_DOWNSAMPLE_1H_WATERMARK, &NOW.to_string(), NOW)
            .unwrap();
        let report = run_retention(&db, &cfg, NOW, None).unwrap();
        assert_eq!(report.one_minute.deleted, 1);
        assert_eq!(db.samples_1m_stats().unwrap().rows, 0);
    }

    /// 1h 保留边界：`bucket_ts == cutoff` 不删，严格更早才删。
    #[test]
    fn m4a_run_retention_hour_cutoff_boundary() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let now = 1_699_999_200_000; // 整点
        let cutoff = now - 730 * DAY_MS;
        let old_bucket = cutoff - BUCKET_1H_MS;
        let equal_bucket = cutoff;
        seed(
            &db,
            "a1",
            vec![
                Sample::new("cpu.usage", old_bucket + 1_000, 1.0),
                Sample::new("cpu.usage", equal_bucket + 1_000, 2.0),
            ],
        );
        db.downsample_1m_range(old_bucket, equal_bucket + BUCKET_1H_MS)
            .unwrap();
        db.downsample_1h_range(old_bucket, equal_bucket + BUCKET_1H_MS)
            .unwrap();
        assert_eq!(db.samples_1h_stats().unwrap().rows, 2);

        // 只启用 1h 保留，避免 raw / 1m 层干扰断言。
        let cfg = cfg_with_retention(0, 0, 730);
        let report = run_retention(&db, &cfg, now, None).unwrap();
        assert_eq!(report.one_hour.cutoff, Some(cutoff));
        assert_eq!(report.one_hour.deleted, 1);
        assert_eq!(db.samples_1h_stats().unwrap().rows, 1);
        assert_eq!(db.samples_1h_stats().unwrap().oldest_ts, Some(equal_bucket));
    }

    /// 保留期按 5,000 行/批删除，批次数正确。
    #[test]
    fn m4a_run_retention_deletes_in_batches() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let cutoff = NOW - 7 * DAY_MS;
        let samples = (0..12_000i64)
            .map(|index| Sample::new("cpu.usage", cutoff - 12_000 + index, index as f64))
            .collect();
        seed(&db, "a1", samples);
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &NOW.to_string(), NOW)
            .unwrap();

        let cfg = cfg_with_retention(7, 0, 0);
        let report = run_retention(&db, &cfg, NOW, None).unwrap();
        assert_eq!(report.raw.deleted, 12_000);
        assert_eq!(report.raw.batches, 3, "12,000 = 5000 + 5000 + 2000");
        assert_eq!(db.raw_stats().unwrap().rows, 0);
    }

    /// 维护状态：各层行数、时间范围、水位、last_error 的读取与清空语义。
    #[test]
    fn m4a_maintenance_status_rows_watermarks_and_error() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS);
        let bucket = closed - BUCKET_1M_MS;
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", bucket + 1_000, 1.0)],
        );
        db.downsample_1m_range(bucket, bucket + BUCKET_1M_MS)
            .unwrap();
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &closed.to_string(), NOW)
            .unwrap();
        db.set_maintenance_state(STATE_RETENTION_LAST_RUN, &NOW.to_string(), NOW)
            .unwrap();

        let status = maintenance_status(&db).unwrap();
        assert_eq!(status.raw.rows, 1);
        assert_eq!(status.raw.oldest_ts, Some(bucket + 1_000));
        assert_eq!(status.one_minute.rows, 1);
        assert_eq!(status.one_minute.oldest_ts, Some(bucket));
        assert_eq!(status.one_hour.rows, 0);
        assert_eq!(status.downsample_1m_watermark, Some(closed));
        assert_eq!(status.downsample_1h_watermark, None);
        assert_eq!(status.retention_last_run, Some(NOW));
        assert_eq!(status.last_error, None);

        db.set_maintenance_state(STATE_LAST_ERROR, "downsample: boom", NOW)
            .unwrap();
        assert_eq!(
            maintenance_status(&db).unwrap().last_error,
            Some("downsample: boom".to_string())
        );
        // 成功一轮后 hub 写空串清空错误。
        db.set_maintenance_state(STATE_LAST_ERROR, "", NOW).unwrap();
        assert_eq!(maintenance_status(&db).unwrap().last_error, None);
    }

    /// CLI / hub 输出依赖：三份报告都能直接序列化为 JSON。
    #[test]
    fn m4a_reports_serialize_to_json() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let cfg = cfg_with_retention(7, 90, 730);

        let downsample = run_downsample(&db, NOW, None).unwrap();
        let json = serde_json::to_value(&downsample).unwrap();
        assert_eq!(json["one_minute"]["buckets"], 0);
        assert_eq!(json["one_minute"]["watermark"], serde_json::Value::Null);
        assert!(json["one_hour"].is_object());
        assert!(json.get("error").is_some());

        let retention = run_retention(&db, &cfg, NOW, None).unwrap();
        let json = serde_json::to_value(&retention).unwrap();
        assert_eq!(json["raw"]["retention_days"], 7);
        assert_eq!(json["raw"]["deleted"], 0);
        assert_eq!(json["one_minute"]["retention_days"], 90);
        assert_eq!(json["one_hour"]["retention_days"], 730);
        assert_eq!(json["raw"]["skipped_no_watermark"], true);

        let status = maintenance_status(&db).unwrap();
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["raw"]["rows"], 0);
        assert_eq!(json["one_minute"]["rows"], 0);
        assert!(json.get("downsample_1m_watermark").is_some());
        assert!(json.get("last_error").is_some());
    }

    /// 1h 水位不得超过 1m 水位：1m 只推进了部分小时时，1h 只能停在完整整点。
    #[test]
    fn m4a_one_hour_never_outruns_one_minute_watermark() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS);
        let oldest = closed - 10 * BUCKET_1H_MS;
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", oldest + 1_000, 1.0)],
        );

        // 两轮各推进有限个小时块：1m 水位落在整点中间（NOW 有 15 分钟偏移），
        // 1h 只能聚合到被 1m 完整覆盖的整点（即该水位向下取整）。
        let first = run_downsample(&db, NOW, Some(1)).unwrap();
        assert!(
            first.one_minute.watermark.unwrap() < bucket_floor(NOW, BUCKET_1H_MS),
            "第一轮 1m 不应追平到当前整点"
        );
        let second = run_downsample(&db, NOW, Some(2)).unwrap();
        let one_minute = second.one_minute.watermark.expect("1m 水位必须存在");
        let one_hour = second.one_hour.watermark.expect("1h 水位必须存在");
        assert_eq!(one_hour % BUCKET_1H_MS, 0, "1h 水位必须是整点");
        assert_eq!(
            one_hour,
            bucket_floor(one_minute, BUCKET_1H_MS),
            "1h 只能聚合 1m 已完整覆盖的整点小时"
        );
        assert!(one_hour <= one_minute);

        // 手动模式追平后，1h 仍停在最后一个完整整点，不聚合当前小时。
        let final_report = run_downsample(&db, NOW, None).unwrap();
        let one_minute = final_report.one_minute.watermark.unwrap();
        let one_hour = final_report.one_hour.watermark.unwrap();
        assert_eq!(one_hour, bucket_floor(one_minute, BUCKET_1H_MS));
        assert_eq!(one_hour, bucket_floor(NOW, BUCKET_1H_MS));
    }

    /// 1m 保留边界：`bucket_ts == cutoff` 不删，严格更早才删。
    #[test]
    fn m4a_run_retention_minute_cutoff_boundary() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let cutoff = NOW - 90 * DAY_MS; // NOW 为整分钟，cutoff 同样对齐
        seed(
            &db,
            "a1",
            vec![
                Sample::new("cpu.usage", cutoff - BUCKET_1M_MS + 1_000, 1.0),
                Sample::new("cpu.usage", cutoff + 1_000, 2.0),
            ],
        );
        db.downsample_1m_range(cutoff - BUCKET_1M_MS, cutoff + BUCKET_1M_MS)
            .unwrap();
        assert_eq!(db.samples_1m_stats().unwrap().rows, 2);
        db.set_maintenance_state(
            STATE_DOWNSAMPLE_1H_WATERMARK,
            &(cutoff + BUCKET_1M_MS).to_string(),
            NOW,
        )
        .unwrap();

        // 只启用 1m 保留，避免 raw 层干扰断言。
        let cfg = cfg_with_retention(0, 90, 0);
        let report = run_retention(&db, &cfg, NOW, None).unwrap();
        assert_eq!(report.one_minute.cutoff, Some(cutoff));
        assert_eq!(report.one_minute.deleted, 1);
        assert_eq!(db.samples_1m_stats().unwrap().rows, 1);
        assert_eq!(db.samples_1m_stats().unwrap().oldest_ts, Some(cutoff));
    }
}
