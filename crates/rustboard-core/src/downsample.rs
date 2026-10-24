//! M4：降采样与保留期 worker。
//!
//! - 1m：把已关闭分钟的 raw 聚合进 `samples_1m`；
//! - 1h：把已关闭整点的 1m 聚合进 `samples_1h`（按 `count` 加权平均）；
//! - 迟到 / 重放：用 raw `rowid` 水位发现「新写入但 ts 很旧」的行，回拨 1m
//!   与 1h 水位后重算；回拨水位同时是 retention 的删除门禁，重算前不删数据；
//! - retention：按层分批删除过期数据；raw 同时受 1m 水位与归档门禁，
//!   1m 受 1h 水位门禁，水位缺失时该层不删；
//! - 所有进度写入 `maintenance_state`；**先提交数据再写水位**，崩溃后最多重做
//!   最后一块，不会出现「水位已过但数据没写」。
//!
//! 时间统一使用 UTC 毫秒。worker 不读真实时钟：`now` 由调用方（hub / CLI）传入，
//! 便于测试与同一轮内保持一致。

use anyhow::Result;
use rustboard_common::config::HubConfig;
use serde::Serialize;

use crate::storage::sqlite::{
    SqliteStorage, DOWNSAMPLE_MAX_CHUNK_ROWS, STATE_RAW_PRUNE_GENERATION,
};
use crate::storage::{Storage, TierStats, BUCKET_1H_MS, BUCKET_1M_MS};

/// `maintenance_state` 键：1m 层已完整聚合到（不含）该时间戳。
pub const STATE_DOWNSAMPLE_1M_WATERMARK: &str = "downsample_1m_watermark";
/// `maintenance_state` 键：1h 层已完整聚合到（不含）该时间戳。
pub const STATE_DOWNSAMPLE_1H_WATERMARK: &str = "downsample_1h_watermark";
/// `maintenance_state` 键：已认领（见下面的说明）的最大 raw `rowid`。
///
/// 用于发现**迟到 / 重放**写入：新 raw 行的 `rowid` 一定更大，即使 `ts` 很旧
/// 也能被下一轮发现；发现 `ts` 早于水位时回拨水位重算。
pub const STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID: &str = "downsample_1m_last_raw_rowid";
/// `maintenance_state` 键：最近一次成功执行保留期任务的时间戳。
pub const STATE_RETENTION_LAST_RUN: &str = "retention_last_run";
/// `maintenance_state` 键：最近一次维护任务失败信息（成功一轮后清空）。
pub const STATE_LAST_ERROR: &str = "last_error";

/// 一天对应的毫秒数。
const DAY_MS: i64 = 86_400_000;

/// 冷归档门禁。
///
/// 必须显式区分「归档未启用」与「归档已启用但还没有任何成功归档」：
/// 后者若按「无水位 = 不设限」处理，会在 M4-C 接入后立即删掉未归档的 raw。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum ArchiveGate {
    /// 归档未启用（当前 M4-A 的 CLI / hub 都传这个）：raw 不受归档限制。
    #[default]
    Disabled,
    /// 归档已启用。`watermark` 是**排他**边界：只有 `ts < watermark` 的 raw
    /// 才算已成功归档；`None` 表示尚无成功归档，此时 raw 一律不删。
    Enabled { watermark: Option<i64> },
}

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
    /// 已认领的最大 raw `rowid`（迟到检测进度）。
    pub downsample_1m_last_raw_rowid: Option<i64>,
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

/// 迟到重放会把 1m 水位回拨到 `rewind_1m` 所在分钟，1h 水位必须同步回拨到
/// 该分钟所在整点，才能：
/// 1. 让 1m 保留期在重算完成前不删对应 1m 行（1m retention 受 1h 水位门禁）；
/// 2. 让 1h 重新聚合受影响的整点小时。
///
/// 必须先于 1m 水位回拨落库：即使随后崩溃，下一轮仍能从回拨后的 1h 水位重算。
fn rewind_hour_watermark(db: &SqliteStorage, rewind_1m: i64, now: i64) -> Result<()> {
    let Some(current) = read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)? else {
        // 1h 还没有水位：它本来就会从最旧 1m 桶重新聚合，无需额外回拨。
        return Ok(());
    };
    let rewind_hour = bucket_floor(rewind_1m, BUCKET_1H_MS);
    if current > rewind_hour {
        write_watermark(db, STATE_DOWNSAMPLE_1H_WATERMARK, rewind_hour, now)?;
    }
    Ok(())
}

/// 重算一段 1m 区间，按桶/行数分块，避免高基数下把整段塞进一个长事务。
fn recompute_1m_range(db: &SqliteStorage, from_ts: i64, to_ts: i64) -> Result<(usize, usize)> {
    let mut buckets = 0usize;
    let mut rows = 0usize;
    let mut cursor = from_ts;
    while cursor < to_ts {
        let chunk_end = raw_chunk_end(db, cursor, to_ts)?;
        if chunk_end <= cursor {
            break;
        }
        let result = db.downsample_1m_range(cursor, chunk_end)?;
        buckets += result.buckets;
        rows += result.rows;
        cursor = chunk_end;
    }
    Ok((buckets, rows))
}

/// 重算一段 1h 区间，按桶/行数分块。
fn recompute_1h_range(db: &SqliteStorage, from_ts: i64, to_ts: i64) -> Result<(usize, usize)> {
    let mut buckets = 0usize;
    let mut rows = 0usize;
    let mut cursor = from_ts;
    while cursor < to_ts {
        let chunk_end = minute_chunk_end(db, cursor, to_ts)?;
        if chunk_end <= cursor {
            break;
        }
        let result = db.downsample_1h_range(cursor, chunk_end)?;
        buckets += result.buckets;
        rows += result.rows;
        cursor = chunk_end;
    }
    Ok((buckets, rows))
}

/// 按小时块后填 1m 聚合，并重算最近 2 个已关闭分钟桶。
///
/// 迟到 / 重放保护：用 `downsample_1m_last_raw_rowid` 扫描新 raw 行；若新行
/// 的最旧 `ts` 早于当前 1m 水位，就把 1m 水位（以及 1h 水位）**回拨**到对应
/// 桶，重新聚合到 `closed_end`。回拨后的水位同时是 raw 保留期的删除门禁，
/// 因此重算完成前不会删掉迟到数据。
fn run_one_minute_tier(
    db: &SqliteStorage,
    now: i64,
    max_backfill_chunks: Option<u32>,
) -> Result<DownsampleTierReport> {
    let closed_end = bucket_floor(now, BUCKET_1M_MS);
    let mut report = DownsampleTierReport::default();
    let stored = read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?;
    let last_rowid = read_state_i64(db, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID)?;

    // 没有 1m 水位时忽略 rowid 进度，从最旧 raw 重新覆盖（安全降级）。
    let scan_after = if stored.is_some() { last_rowid } else { None };
    // 必须在读 MAX(rowid) 之前拍 generation 快照：prune 若在此后删除最大
    // rowid 行会把 generation +1，CAS 因代际不一致而失败，即使 rowid key
    // 恰好缺失也不会把删除前的旧 MAX 写回。缺失按 0；非法值在 CAS 侧视为不匹配。
    let prune_generation = db
        .get_maintenance_state(STATE_RAW_PRUNE_GENERATION)?
        .and_then(|raw| raw.trim().parse::<i64>().ok())
        .unwrap_or(0);
    let (max_rowid, min_new_ts) = db.raw_new_rows(scan_after)?;

    let mut start = match stored {
        // 水位可能因回拨时钟而超前：不越过已关闭分钟。
        Some(watermark) => Some(watermark.min(closed_end)),
        // 首次运行从最旧 raw 所在分钟开始。`min_new_ts` 是在 `MAX(rowid)` 之后
        // 读取的 `(0, max]` 区间最旧 ts，能覆盖本轮会认领的全部行。
        None => min_new_ts.map(|ts| bucket_floor(ts, BUCKET_1M_MS)),
    };

    // 迟到 / 重放检测：本轮新 raw 的最旧 ts 落在已聚合水位之前 → 回拨重算。
    if let (Some(current), Some(min_ts)) = (stored, min_new_ts) {
        let watermark = current.min(closed_end);
        if min_ts < watermark {
            let rewind = bucket_floor(min_ts, BUCKET_1M_MS);
            // 顺序：先回拨 1h 水位（保护 1m 保留期 + 让 1h 重算受影响小时），
            // 再回拨 1m 水位（保护 raw 保留期）。两者都先于 rowid 认领落库。
            rewind_hour_watermark(db, rewind, now)?;
            write_watermark(db, STATE_DOWNSAMPLE_1M_WATERMARK, rewind, now)?;
            start = Some(start.map_or(rewind, |cursor| cursor.min(rewind)));
        }
    }

    // 认领本轮已扫描到的 rowid。必须在回拨水位落库之后：被认领行的 ts 都
    // 不早于已落库的 1m 水位（迟到行已把水位回拨到其桶起点），崩溃后重做不丢；
    // 之后写入的并发行 rowid 更大，下一轮仍会被发现。
    //
    // 用 CAS 而不是直接写：若从上面读 MAX 到现在，retention 删除了最大 rowid
    // 行，prune 会降低或删除本 key；CAS 失败时本轮不认领，下一轮从更低位重扫，
    // 避免把删除前的旧 MAX 写回、永久吞掉复用该 rowid 的迟到行。
    if let Some(max) = max_rowid {
        if last_rowid != Some(max)
            && !db.claim_raw_rowid_if_unchanged(last_rowid, prune_generation, max)?
        {
            tracing::debug!(
                expected = ?last_rowid,
                generation = prune_generation,
                new = max,
                "raw rowid 水位或 prune 代际已变化，本轮不认领"
            );
        }
    }

    // 追平目标就是最后一个已关闭分钟：没有 raw 行的空分钟也算「已完整聚合」，
    // 否则 1h 永远等不到一个被 1m 水位完整覆盖的整点（稀疏数据是常态）。
    // 完全没有 raw 行时不推进水位（不写假水位）。
    let target_end = match max_rowid {
        Some(_) => closed_end,
        None => start.unwrap_or(closed_end),
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
    // 不推进水位。按桶/行数分块，避免高基数下长事务。
    if closed_end >= 2 * BUCKET_1M_MS {
        let tail_start = closed_end - 2 * BUCKET_1M_MS;
        let (buckets, rows) = recompute_1m_range(db, tail_start, closed_end)?;
        report.buckets += buckets;
        report.rows += rows;
    }

    report.watermark = read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?;
    Ok(report)
}

/// 按小时块后填 1h 聚合，并重算最近 2 个已关闭整点小时。
///
/// 1h 只聚合「1m 已完整生成」的整点小时：上限同时受 `closed_end_1h` 与
/// 1m 水位约束，且必须落在整点边界上，绝不聚合半个小时的残缺数据。
/// 1m 因迟到重放回拨时，`rewind_hour_watermark` 会同步回拨 1h 水位，本函数
/// 从回拨处重新聚合受影响的整点小时。
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
    let minute_oldest = db.samples_1m_oldest_ts()?;
    let mut stored = read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)?;

    // 防御：1h 水位不得高于「1m 已完整覆盖的整点」；只回拨、不前进。
    if hour_limit > 0 {
        if let Some(current) = stored {
            if current > hour_limit {
                write_watermark(db, STATE_DOWNSAMPLE_1H_WATERMARK, hour_limit, now)?;
                stored = Some(hour_limit);
            }
        }
    }

    let start = match stored {
        Some(watermark) => Some(watermark.min(hour_limit)),
        None => minute_oldest.map(|ts| bucket_floor(ts, BUCKET_1H_MS)),
    };
    // 追平目标就是最后一个 1m 已完整覆盖的整点；空小时不产生 1h 行，但水位
    // 可以越过它（其 1m 数据确实已经聚合完毕）。
    let target_end = if minute_oldest.is_some() {
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
        let (buckets, rows) = recompute_1h_range(db, tail_start, hour_limit)?;
        report.buckets += buckets;
        report.rows += rows;
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

/// raw 层保留：同时受 1m 降采样水位与归档门禁。
fn retention_raw(
    db: &SqliteStorage,
    days: u32,
    now: i64,
    watermark_1m: Option<i64>,
    archive_gate: ArchiveGate,
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
    match archive_gate {
        ArchiveGate::Disabled => {}
        ArchiveGate::Enabled {
            watermark: Some(archive),
        } => {
            // watermark 是排他边界：只删除严格早于它的 raw。
            report.blocked_by_archive = archive < cutoff;
            effective = effective.min(archive);
        }
        ArchiveGate::Enabled { watermark: None } => {
            // 归档已启用但尚无任何成功归档：此时删除任何 raw 都可能丢掉唯一副本。
            report.blocked_by_archive = true;
            report.effective_cutoff = None;
            return Ok(report);
        }
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
/// `archive_gate` 必须显式区分「未启用归档」与「已启用但尚无成功归档」；
/// 后者会阻止 raw 删除并标记 `blocked_by_archive`。任何一层删除失败都返回
/// `Err`，已提交的批次保持幂等，下一轮继续。
pub fn run_retention(
    db: &SqliteStorage,
    cfg: &HubConfig,
    now: i64,
    archive_gate: ArchiveGate,
) -> Result<RetentionReport> {
    let watermark_1m = read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?;
    let watermark_1h = read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)?;

    let raw = retention_raw(db, cfg.retention_raw_days, now, watermark_1m, archive_gate)?;
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
        downsample_1m_last_raw_rowid: read_state_i64(db, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID)?,
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
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
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
        let report = run_retention(&db, &cfg_disabled, NOW, ArchiveGate::Disabled).unwrap();
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
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
        assert!(report.raw.skipped_no_watermark);
        assert_eq!(report.raw.deleted, 0);
        assert_eq!(db.raw_stats().unwrap().rows, 1);

        // 1m 水位已到 now，但归档水位更早：raw 仍不得删除，并标记归档阻塞。
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &NOW.to_string(), NOW)
            .unwrap();
        let archive_cutoff = NOW - 200 * DAY_MS;
        let report = run_retention(
            &db,
            &cfg,
            NOW,
            ArchiveGate::Enabled {
                watermark: Some(archive_cutoff),
            },
        )
        .unwrap();
        assert_eq!(report.raw.deleted, 0);
        assert!(report.raw.blocked_by_archive);
        assert!(!report.raw.blocked_by_downsample);
        assert_eq!(report.raw.effective_cutoff, Some(archive_cutoff));
        assert_eq!(db.raw_stats().unwrap().rows, 1);

        // 归档水位推进到 now 后 raw 才可删。
        let report = run_retention(
            &db,
            &cfg,
            NOW,
            ArchiveGate::Enabled {
                watermark: Some(NOW),
            },
        )
        .unwrap();
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
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
        assert!(report.one_minute.skipped_no_watermark);
        assert_eq!(report.one_minute.deleted, 0);
        assert_eq!(db.samples_1m_stats().unwrap().rows, 1);

        // 1h 水位到位后才允许删除 1m。
        db.set_maintenance_state(STATE_DOWNSAMPLE_1H_WATERMARK, &NOW.to_string(), NOW)
            .unwrap();
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
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
        let report = run_retention(&db, &cfg, now, ArchiveGate::Disabled).unwrap();
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
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
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

        let retention = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
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
        assert!(json.get("downsample_1m_last_raw_rowid").is_some());
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
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
        assert_eq!(report.one_minute.cutoff, Some(cutoff));
        assert_eq!(report.one_minute.deleted, 1);
        assert_eq!(db.samples_1m_stats().unwrap().rows, 1);
        assert_eq!(db.samples_1m_stats().unwrap().oldest_ts, Some(cutoff));
    }

    /// 评审回归：agent 缓冲 10h 后重放的旧 ts 数据必须被 rowid 扫描发现，
    /// 回拨 1m/1h 水位并同时修正两层聚合，而不是只重算最近 2 分钟。
    #[test]
    fn m4a_late_replay_rewinds_and_fixes_one_minute_and_hour() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let hour = bucket_floor(NOW, BUCKET_1H_MS);
        let replay_bucket = hour - 10 * BUCKET_1H_MS;
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", replay_bucket + 1_000, 1.0)],
        );

        let first = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(first.one_minute.watermark, Some(NOW));
        assert_eq!(first.one_hour.watermark, Some(hour));
        assert_eq!(db.aggregate_rows_for_test("1m")[0].count, 1);

        // 10 小时前的重放：ts 落在旧桶，rowid 是新的。
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", replay_bucket + 30_000, 10.0)],
        );
        let replay = run_downsample(&db, NOW, None).unwrap();
        assert!(
            replay.one_minute.chunks >= 10,
            "必须从回拨点重新聚合到 closed_end: {}",
            replay.one_minute.chunks
        );
        assert_eq!(replay.one_minute.watermark, Some(NOW));
        assert_eq!(replay.one_hour.watermark, Some(hour));

        let rows_1m = db.aggregate_rows_for_test("1m");
        let minute = rows_1m
            .iter()
            .find(|row| row.bucket_ts == replay_bucket)
            .expect("回拨后的 1m 桶必须存在");
        assert_eq!(minute.count, 2, "迟到行必须进入 1m");
        assert_eq!(minute.last_value, 10.0);
        assert!((minute.avg_value - 5.5).abs() < 1e-9);

        let rows_1h = db.aggregate_rows_for_test("1h");
        let hourly = rows_1h
            .iter()
            .find(|row| row.bucket_ts == replay_bucket)
            .expect("受影响的整点小时必须被重算");
        assert_eq!(hourly.count, 2, "迟到行必须进入 1h");
        assert_eq!(hourly.last_value, 10.0);
        assert!((hourly.avg_value - 5.5).abs() < 1e-9);
    }

    /// 评审回归：迟到回拨期间 retention 必须同时保护尚未重算的 raw 与 1m。
    ///
    /// 场景：100 天前的迟到重放；`max_backfill_hours = Some(1)` 只重算第一小时：
    /// - raw 水位回拨到 t0+1h，7 天 cutoff 只能删到该水位，第二小时的迟到 raw 保留；
    /// - 1h 水位同步回拨到 t0+1h，90 天 cutoff 不能越过该水位删掉未重算的 1m。
    #[test]
    fn m4a_late_replay_watermark_protects_retention() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let now = NOW;
        let t0 = bucket_floor(now - 100 * DAY_MS, BUCKET_1H_MS);
        // 手动构造“100 天前已有数据且 1m/1h/rowid 水位都追平”的状态，
        // 避免测试真的回填 100 天（worker 用固定 now 时同样会这样追平）。
        seed(&db, "a1", vec![Sample::new("cpu.usage", t0 + 1_000, 1.0)]);
        db.downsample_1m_range(t0, t0 + BUCKET_1H_MS).unwrap();
        db.downsample_1h_range(t0, t0 + BUCKET_1H_MS).unwrap();
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &now.to_string(), now)
            .unwrap();
        db.set_maintenance_state(
            STATE_DOWNSAMPLE_1H_WATERMARK,
            &bucket_floor(now, BUCKET_1H_MS).to_string(),
            now,
        )
        .unwrap();
        let (max_rowid, _) = db.raw_new_rows(None).unwrap();
        db.set_maintenance_state(
            STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID,
            &max_rowid.expect("已有 raw 行").to_string(),
            now,
        )
        .unwrap();

        // 两个迟到重放：A 在第一小时，B 在第二小时（本轮只重算到第一小时）。
        let replay_a = t0 + 30_000;
        let replay_b = t0 + 90 * BUCKET_1M_MS;
        seed(
            &db,
            "a1",
            vec![
                Sample::new("cpu.usage", replay_a, 10.0),
                Sample::new("cpu.usage", replay_b, 20.0),
            ],
        );

        let partial = run_downsample(&db, now, Some(1)).unwrap();
        assert_eq!(partial.one_minute.watermark, Some(t0 + BUCKET_1H_MS));
        assert_eq!(partial.one_hour.watermark, Some(t0 + BUCKET_1H_MS));
        let rows_1m = db.aggregate_rows_for_test("1m");
        assert_eq!(find_agg(&rows_1m, "{}").count, 2, "A 已进入 1m");
        let rows_1h = db.aggregate_rows_for_test("1h");
        assert_eq!(find_agg(&rows_1h, "{}").count, 2, "A 已进入 1h");

        let cfg = cfg_with_retention(7, 90, 730);
        let retention = run_retention(&db, &cfg, now, ArchiveGate::Disabled).unwrap();
        assert!(retention.raw.blocked_by_downsample);
        assert_eq!(
            retention.raw.effective_cutoff,
            Some(t0 + BUCKET_1H_MS),
            "raw 只能删到回拨后的 1m 水位"
        );
        assert_eq!(retention.raw.deleted, 2, "初始行 + 已重算的迟到 A");
        let raw = db.raw_stats().unwrap();
        assert_eq!(raw.rows, 1, "B 尚未重算，raw 必须保留");
        assert_eq!(raw.oldest_ts, Some(replay_b));

        assert!(retention.one_minute.blocked_by_downsample);
        assert_eq!(
            retention.one_minute.effective_cutoff,
            Some(t0 + BUCKET_1H_MS),
            "1m 只能删到回拨后的 1h 水位"
        );
        assert_eq!(retention.one_minute.deleted, 1, "只删已聚合的 t0 桶");
        assert_eq!(db.samples_1m_stats().unwrap().rows, 0);
        // 已聚合的 1h 行不会被删，且已经包含迟到数据。
        let rows_1h = db.aggregate_rows_for_test("1h");
        assert_eq!(find_agg(&rows_1h, "{}").count, 2);

        // 追平后 B 的分钟/小时桶都被补上。
        let caught_up = run_downsample(&db, t0 + 3 * BUCKET_1H_MS, None).unwrap();
        assert_eq!(caught_up.one_minute.watermark, Some(t0 + 3 * BUCKET_1H_MS));
        assert_eq!(caught_up.one_hour.watermark, Some(t0 + 3 * BUCKET_1H_MS));
        let rows_1m = db.aggregate_rows_for_test("1m");
        let b_minute = rows_1m
            .iter()
            .find(|row| row.bucket_ts == replay_b)
            .expect("B 的分钟桶必须补上");
        assert_eq!(b_minute.count, 1);
        assert_eq!(b_minute.avg_value, 20.0);
        let rows_1h = db.aggregate_rows_for_test("1h");
        let b_hour = rows_1h
            .iter()
            .find(|row| row.bucket_ts == t0 + BUCKET_1H_MS)
            .expect("B 所在小时必须补上");
        assert_eq!(b_hour.count, 1);
        assert_eq!(b_hour.avg_value, 20.0);
    }

    /// 评审回归：归档已启用但尚无成功归档时，raw 一律不删并标记 blocked。
    #[test]
    fn m4a_archive_gate_enabled_without_watermark_blocks_raw() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let old = NOW - 100 * DAY_MS;
        seed(&db, "a1", vec![Sample::new("cpu.usage", old, 1.0)]);
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &NOW.to_string(), NOW)
            .unwrap();
        let cfg = cfg_with_retention(7, 0, 0);

        let report =
            run_retention(&db, &cfg, NOW, ArchiveGate::Enabled { watermark: None }).unwrap();
        assert!(report.raw.blocked_by_archive);
        assert_eq!(report.raw.effective_cutoff, None);
        assert_eq!(report.raw.deleted, 0);
        assert_eq!(db.raw_stats().unwrap().rows, 1);

        // 归档水位早于 raw 行：仍不能删。
        let report = run_retention(
            &db,
            &cfg,
            NOW,
            ArchiveGate::Enabled {
                watermark: Some(old - DAY_MS),
            },
        )
        .unwrap();
        assert!(report.raw.blocked_by_archive);
        assert_eq!(report.raw.deleted, 0);

        // 归档水位推进到 now：才能按 7 天保留期删除。
        let report = run_retention(
            &db,
            &cfg,
            NOW,
            ArchiveGate::Enabled {
                watermark: Some(NOW),
            },
        )
        .unwrap();
        assert!(!report.raw.blocked_by_archive);
        assert_eq!(report.raw.deleted, 1);
        assert_eq!(db.raw_stats().unwrap().rows, 0);
    }

    /// 评审建议：1m 水位早于 cutoff 时，raw 只能删到水位，不能越过。
    #[test]
    fn m4a_run_retention_deletes_only_below_downsample_watermark() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let cutoff = NOW - 7 * DAY_MS;
        let watermark = cutoff - BUCKET_1H_MS;
        seed(
            &db,
            "a1",
            vec![
                Sample::new("cpu.usage", cutoff - 2 * BUCKET_1H_MS, 1.0),
                Sample::new("cpu.usage", cutoff - 30 * BUCKET_1M_MS, 2.0),
                Sample::new("cpu.usage", cutoff, 3.0),
                Sample::new("cpu.usage", NOW - BUCKET_1H_MS, 4.0),
            ],
        );
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &watermark.to_string(), NOW)
            .unwrap();

        let cfg = cfg_with_retention(7, 0, 0);
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
        assert!(report.raw.blocked_by_downsample);
        assert_eq!(report.raw.effective_cutoff, Some(watermark));
        assert_eq!(report.raw.deleted, 1, "只能删水位之前的 1 行");
        let raw = db.raw_stats().unwrap();
        assert_eq!(raw.rows, 3);
        assert_eq!(raw.oldest_ts, Some(cutoff - 30 * BUCKET_1M_MS));
    }

    /// 评审建议：单分钟桶超过 5,000 行时整桶聚合，绝不拆桶产生错误 avg/count。
    #[test]
    fn m4a_backfill_does_not_split_oversized_minute_bucket() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS);
        let from = closed - 2 * BUCKET_1M_MS;
        let mut samples = Vec::with_capacity(5_002);
        for index in 0..5_001i64 {
            samples.push(Sample::new("cpu.usage", from + index, index as f64));
        }
        samples.push(Sample::new("cpu.usage", from + BUCKET_1M_MS + 1_000, 42.0));
        seed(&db, "a1", samples);

        let report = run_downsample(&db, NOW, Some(1)).unwrap();
        assert_eq!(report.one_minute.chunks, 1);
        assert_eq!(
            report.one_minute.watermark,
            Some(from + BUCKET_1M_MS),
            "第一块是整桶（5,001 行），不是被 5,000 行切开的半个桶"
        );
        let rows = db.aggregate_rows_for_test("1m");
        let first = rows
            .iter()
            .find(|row| row.bucket_ts == from)
            .expect("超限分钟桶必须存在");
        assert_eq!(first.count, 5_001);
        assert_eq!(first.min_value, 0.0);
        assert_eq!(first.max_value, 5_000.0);
        // tail 重算同样按桶分块处理第二个分钟桶。
        let second = rows
            .iter()
            .find(|row| row.bucket_ts == from + BUCKET_1M_MS)
            .expect("tail 必须重算第二个分钟桶");
        assert_eq!(second.count, 1);
        assert_eq!(second.last_value, 42.0);

        // 追平后超限桶仍保持整桶聚合结果。
        run_downsample(&db, NOW, None).unwrap();
        let rows = db.aggregate_rows_for_test("1m");
        let first = rows
            .iter()
            .find(|row| row.bucket_ts == from)
            .expect("超限分钟桶必须存在");
        assert_eq!(first.count, 5_001);
        assert!((first.avg_value - 2_500.0).abs() < 1e-9);
    }

    /// 评审建议：单个整点小时超过 5,000 行 1m 数据时整小时聚合，不拆小时。
    #[test]
    fn m4a_backfill_does_not_split_oversized_hour_bucket() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let now = NOW;
        let closed_hour = bucket_floor(now, BUCKET_1H_MS);
        let hour = closed_hour - 2 * BUCKET_1H_MS;
        let mut samples = Vec::with_capacity(6_000);
        for series in 0..100i64 {
            for minute in 0..60i64 {
                samples.push(
                    Sample::new(
                        "cpu.usage",
                        hour + minute * BUCKET_1M_MS + 1_000,
                        (series * 100 + minute) as f64,
                    )
                    .with_label("series", series.to_string()),
                );
            }
        }
        seed(&db, "a1", samples);
        db.downsample_1m_range(hour, hour + BUCKET_1H_MS).unwrap();
        assert_eq!(db.samples_1m_stats().unwrap().rows, 6_000);
        // 1m 已完整覆盖该小时；rowid 已认领，本轮只做 1h。
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &now.to_string(), now)
            .unwrap();
        let (max_rowid, _) = db.raw_new_rows(None).unwrap();
        db.set_maintenance_state(
            STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID,
            &max_rowid.expect("已有 raw 行").to_string(),
            now,
        )
        .unwrap();

        let report = run_downsample(&db, now, None).unwrap();
        assert_eq!(report.one_hour.watermark, Some(closed_hour));
        let rows = db.aggregate_rows_for_test("1h");
        assert_eq!(rows.len(), 100, "100 个序列各一行 1h");
        assert_eq!(
            rows.iter().map(|row| row.count).sum::<i64>(),
            6_000,
            "整小时 6,000 行 1m 必须完整聚合，不能被 5,000 行切成两段"
        );
        assert!(
            rows.iter().all(|row| row.count == 60),
            "每个序列每小时 60 个分钟桶必须完整"
        );
        assert!(rows.iter().all(|row| row.bucket_ts == hour));
    }
}
