//! M4 / R1b：降采样与保留期 worker。
//!
//! - 1m：按 **增量 delta** 认领 `samples.aggregated_1m=0` 的 raw，合并进
//!   `samples_1m`；同一事务内标记 raw，并把所在**整小时**的 1m 行置
//!   `aggregated_1h=0`；
//! - 1h：锁定 `samples_1m.aggregated_1h=0` 的整点小时，按整小时全部 1m 行
//!   重算；写 1h 后把该小时所有 1m 行置 `aggregated_1h=1`；
//! - 全局水位只前进，不再因迟到回拨；迟到数据由 `aggregated_1m=0` 的增量
//!   认领直接覆盖，不依赖「最近 2 桶/小时」重算；
//! - retention：raw 只删 `aggregated_1m=1`（归档启用时还要 uploaded join），
//!   1m 只删整小时 `aggregated_1h=1` 的行；旧水位不再单独证明可删；
//! - 所有进度写入 `maintenance_state`；**先提交数据再写水位**，崩溃后最多重做
//!   最后一块，不会出现「水位已过但数据没写」。
//!
//! 时间统一使用 UTC 毫秒。worker 不读真实时钟：`now` 由调用方（hub / CLI）传入，
//! 便于测试与同一轮内保持一致。

use anyhow::Result;
use rustboard_common::config::HubConfig;
use serde::Serialize;

use crate::archive::STATE_ARCHIVE_LEDGER_PENDING;
use crate::storage::sqlite::DOWNSAMPLE_MAX_CHUNK_ROWS;
use crate::storage::{Storage, TierStats, BUCKET_1H_MS, BUCKET_1M_MS};

/// `maintenance_state` 键：1m 层已处理到（不含）该时间戳；**只前进**。
pub const STATE_DOWNSAMPLE_1M_WATERMARK: &str = "downsample_1m_watermark";
/// `maintenance_state` 键：1h 层已重算到（不含）该时间戳；**只前进**。
pub const STATE_DOWNSAMPLE_1H_WATERMARK: &str = "downsample_1h_watermark";
/// 已废弃的 raw `rowid` 水位键（v0.4.x KI-29）。
///
/// R1b 改用 `samples.aggregated_1m=0` 增量认领，迟到行不再依赖 rowid 扫描。
/// 该键仅为 `maintenance status` 兼容与历史清理保留，不再读写于降采样路径。
pub const STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID: &str = "downsample_1m_last_raw_rowid";
/// `maintenance_state` 键：最近一次成功执行保留期任务的时间戳。
pub const STATE_RETENTION_LAST_RUN: &str = "retention_last_run";
/// `maintenance_state` 键：最近一次维护任务失败信息（成功一轮后清空）。
pub const STATE_LAST_ERROR: &str = "last_error";

/// 一天对应的毫秒数。
const DAY_MS: i64 = 86_400_000;

/// 冷归档门禁。
///
/// R1b 起 raw 是否可删只由「`aggregated_1m=1` + 归档对象 uploaded + ledger
/// 不 pending」决定，`watermark` 不再单独证明可删；字段保留用于兼容旧
/// CLI/测试构造与 `archive status` 展示。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum ArchiveGate {
    /// 归档未启用：raw 只受保留期与 `aggregated_1m=1` 约束。
    #[default]
    Disabled,
    /// 归档已启用：必须走 uploaded join；`watermark` 仅作历史信息。
    Enabled { watermark: Option<i64> },
}

/// 单层降采样结果。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DownsampleTierReport {
    /// 本次写入/更新的聚合桶数。
    pub buckets: usize,
    /// 参与聚合的源行数。
    pub rows: usize,
    /// 本次处理的块数（后台模式受 `max_backfill_hours` 限制）。
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
    /// 实际使用的删除边界（1m 层会向下取整到整点）。
    pub effective_cutoff: Option<i64>,
    /// 实际删除行数。
    pub deleted: usize,
    /// 实际执行了删除的批次数。
    pub batches: usize,
    /// 该层配置为 0（不删除）。
    pub disabled: bool,
    /// 兼容字段：R1b 起不再以「缺少水位」跳过删除，恒为 `false`。
    pub skipped_no_watermark: bool,
    /// 删除边界内仍有未聚合数据 / dirty hour，因此只删了其中一部分。
    pub blocked_by_downsample: bool,
    /// 归档门禁阻止或部分阻止了 raw 删除。
    pub blocked_by_archive: bool,
    /// 归档 ledger 重建未完成（`archive_ledger_pending=1`），本轮完全跳过。
    pub skipped_archive_ledger_pending: bool,
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
    /// 1m 聚合水位（只前进；仅作进度展示）。
    pub downsample_1m_watermark: Option<i64>,
    /// 1h 聚合水位（只前进；仅作进度展示）。
    pub downsample_1h_watermark: Option<i64>,
    /// 已废弃的 raw rowid 水位（兼容字段，R1b 不再写入）。
    pub downsample_1m_last_raw_rowid: Option<i64>,
    /// 最近一次成功保留期任务时间。
    pub retention_last_run: Option<i64>,
    /// 最近一次维护任务失败信息（成功后清空）。
    pub last_error: Option<String>,
    /// 尚未聚合的 raw 行数（`aggregated_1m=0`）。
    pub unaggregated_rows: i64,
    /// 超出 `[ingest]` 时间戳准入范围的 raw 行数（含已隔离行）。
    pub invalid_timestamp_rows: i64,
    /// 早于 1m 保留期 horizon 且仍未聚合的 raw 行数（启动审计后应为 0）。
    pub legacy_unaggregated_rows: i64,
    /// 归档 ledger 重建待办标记。
    pub archive_ledger_pending: bool,
}

/// 启动时 legacy raw 时间戳审计结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LegacyAuditReport {
    /// 超出 `[ingest]` 准入范围的 raw 行数。
    pub invalid_timestamp_rows: i64,
    /// 其中仍未聚合（会被 delta 选中）的行数。
    pub unaggregated_invalid_rows: i64,
    /// 早于 1m 保留期 horizon 且未聚合的行数。
    pub legacy_unaggregated_rows: i64,
    /// 本次实际标记为 `aggregated_1m=1` 隔离的行数。
    pub isolated_rows: usize,
}

/// 把时间戳向下取整到 `bucket_ms` 边界（UTC 毫秒）。
///
/// #50：除法与乘法都走 checked；`i64::MIN` 等极端值返回显式错误，
/// 不 panic、不回绕。
fn bucket_floor(ts: i64, bucket_ms: i64) -> Result<i64> {
    ts.checked_div_euclid(bucket_ms)
        .and_then(|quotient| quotient.checked_mul(bucket_ms))
        .ok_or_else(|| anyhow::anyhow!("时间戳无法对齐到 {bucket_ms}ms 桶：超出 i64 可表示范围"))
}

/// 读取整数型 `maintenance_state`。
///
/// - key 不存在或值为空串 → `None`（空串供 hub 清除 `last_error` 使用，也把
///   被清空的水位当作「缺失」处理，宁可重做也不误删）；
/// - 非法值 → `Err`，明确点名字段，不静默跳过损坏的进度。
fn read_state_i64(db: &dyn Storage, key: &str) -> Result<Option<i64>> {
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
fn write_watermark(db: &dyn Storage, key: &str, watermark: i64, now: i64) -> Result<()> {
    db.set_maintenance_state(key, &watermark.to_string(), now)
}

/// 只前进地推进水位：当前值更大时保持不变，绝不回拨。
fn advance_watermark(db: &dyn Storage, key: &str, watermark: i64, now: i64) -> Result<()> {
    let current = read_state_i64(db, key)?;
    if current.is_none_or(|value| watermark > value) {
        write_watermark(db, key, watermark, now)?;
    }
    Ok(())
}

/// 增量推进 1m：每轮反复认领一批 raw，直到没有更多可聚合行或达到块上限。
fn run_one_minute_tier(
    db: &dyn Storage,
    now: i64,
    max_backfill_chunks: Option<u32>,
) -> Result<DownsampleTierReport> {
    let closed_end = bucket_floor(now, BUCKET_1M_MS)?;
    let mut report = DownsampleTierReport::default();
    let mut chunks: u32 = 0;
    loop {
        if max_backfill_chunks.is_some_and(|limit| chunks >= limit) {
            break;
        }
        let result = db.downsample_1m_delta(closed_end, DOWNSAMPLE_MAX_CHUNK_ROWS)?;
        if result.rows == 0 {
            break;
        }
        report.buckets += result.buckets;
        report.rows += result.rows;
        report.chunks += 1;
        chunks += 1;
        // 数据已在本批事务内提交；这里只前进水位。崩溃只会重做本批（幂等）。
        advance_watermark(db, STATE_DOWNSAMPLE_1M_WATERMARK, result.processed_to, now)?;
    }
    report.watermark = read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?;
    Ok(report)
}

/// 1h：逐个重算可重算的 dirty 整点小时。
fn run_one_hour_tier(
    db: &dyn Storage,
    now: i64,
    max_backfill_chunks: Option<u32>,
) -> Result<DownsampleTierReport> {
    let closed_hour = bucket_floor(now, BUCKET_1H_MS)?;
    let mut report = DownsampleTierReport::default();
    let mut chunks: u32 = 0;
    loop {
        if max_backfill_chunks.is_some_and(|limit| chunks >= limit) {
            break;
        }
        let Some(result) = db.downsample_1h_hour(closed_hour)? else {
            break;
        };
        report.buckets += result.buckets;
        report.rows += result.rows;
        report.chunks += 1;
        chunks += 1;
        let hour_end = result
            .hour_ts
            .checked_add(BUCKET_1H_MS)
            .ok_or_else(|| anyhow::anyhow!("整点小时上界溢出"))?;
        advance_watermark(db, STATE_DOWNSAMPLE_1H_WATERMARK, hour_end, now)?;
    }
    report.watermark = read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)?;
    Ok(report)
}

/// 执行一轮降采样。
///
/// - `max_backfill_hours = None`：手动 / CLI 模式，持续分块直到追平；
/// - `Some(n)`：后台模式，每轮 1m / 1h 各最多处理 n 块，避免长时间占用写锁。
///
/// 无 raw 数据时不写水位；失败返回 `Err`（不 panic），由调用方记录 WARN 与
/// `maintenance_state.last_error`，下一轮重试。
pub fn run_downsample(
    db: &dyn Storage,
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
        Some(now.saturating_sub(i64::from(days).saturating_mul(DAY_MS)))
    }
}

/// 读取归档 ledger 是否仍处于重建待办。
fn archive_ledger_pending(db: &dyn Storage) -> Result<bool> {
    Ok(db
        .get_archive_state(STATE_ARCHIVE_LEDGER_PENDING)?
        .is_some_and(|value| value.trim() == "1"))
}

/// raw 层保留：只删已聚合 raw；归档启用时再加 uploaded join 与 ledger 门禁。
fn retention_raw(
    db: &dyn Storage,
    days: u32,
    now: i64,
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
    report.effective_cutoff = Some(cutoff);

    let pruned = match archive_gate {
        ArchiveGate::Disabled => db.prune_samples_before(cutoff)?,
        ArchiveGate::Enabled { .. } => {
            if archive_ledger_pending(db)? {
                report.blocked_by_archive = true;
                report.skipped_archive_ledger_pending = true;
                return Ok(report);
            }
            let pruned = db.prune_archived_samples_before(cutoff)?;
            // 归档启用时，未上传/未认领行一律保留；本轮 0 删除视为归档门禁
            // 仍在阻塞（便于排障），不代表没有可删数据。
            report.blocked_by_archive = pruned.deleted == 0;
            pruned
        }
    };
    report.deleted = pruned.deleted;
    report.batches = pruned.batches;
    // 边界内仍有未聚合 raw：只删掉了其中已聚合部分，不能声称已删干净。
    report.blocked_by_downsample = db.count_unaggregated_raw_rows_before(cutoff)? > 0;
    Ok(report)
}

/// 1m 层保留：只删整小时 `aggregated_1h=1` 的行；dirty hour 整小时跳过。
fn retention_minute(db: &dyn Storage, days: u32, now: i64) -> Result<RetentionLayerReport> {
    let mut report = RetentionLayerReport {
        retention_days: days,
        ..RetentionLayerReport::default()
    };
    let Some(cutoff) = layer_cutoff(days, now) else {
        report.disabled = true;
        return Ok(report);
    };
    report.cutoff = Some(cutoff);
    let hour_cutoff = bucket_floor(cutoff, BUCKET_1H_MS)?;
    report.effective_cutoff = Some(hour_cutoff);
    let pruned = db.prune_samples_1m_before(cutoff)?;
    report.deleted = pruned.deleted;
    report.batches = pruned.batches;
    // 取删除后的状态：hour_cutoff 之前仍有 1m 行 = 存在 dirty hour（或不足
    // 整小时的部分被刻意保留）。
    report.blocked_by_downsample = db
        .samples_1m_stats()?
        .oldest_ts
        .is_some_and(|oldest| oldest < hour_cutoff);
    Ok(report)
}

/// 1h 层保留：最老的一层，没有更上层水位门禁。
fn retention_hour(db: &dyn Storage, days: u32, now: i64) -> Result<RetentionLayerReport> {
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
/// raw 只删 `aggregated_1m=1`（归档启用时还要 uploaded join 且 ledger 不
/// pending）；1m 只删整小时 `aggregated_1h=1` 的行。旧维护水位不参与删除
/// 证明。任何一层删除失败都返回 `Err`，已提交的批次保持幂等，下一轮继续。
pub fn run_retention(
    db: &dyn Storage,
    cfg: &HubConfig,
    now: i64,
    archive_gate: ArchiveGate,
) -> Result<RetentionReport> {
    let raw = retention_raw(db, cfg.retention_raw_days, now, archive_gate)?;
    let one_minute = retention_minute(db, cfg.retention_1m_days, now)?;
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

/// 启动时审计 legacy raw 时间戳。
///
/// 1. 超出 `[ingest]` 准入范围的 raw 计数（`invalid_timestamp_rows`）；
/// 2. 其中仍未聚合的行单独计数（这些行本来会被 delta 选中）；
/// 3. 早于 1m 保留期 horizon 的未聚合行计数（配置校验保证它是第 1 类的
///    子集；单独记录便于排障）；
/// 4. 把超界且未聚合的行分批标记为 `aggregated_1m=1` 隔离：delta 不会再为
///    这些旧数据构造残缺 1m，保留期/归档可以按正常路径处理它们。
///
/// 不打印任何样本值；只输出行数。
pub fn audit_legacy_raw_rows(
    db: &dyn Storage,
    cfg: &HubConfig,
    now: i64,
) -> Result<LegacyAuditReport> {
    // 只隔离真正不可表示的时间戳（负值/未来超界）；早于 max_late 的历史
    // backlog 仍交给 delta 聚合，不能因为升级/长时间离线被静默丢弃。
    let invalid_min_ts = 0;
    let max_ts = cfg.ingest.max_sample_ts(now);
    let invalid_timestamp_rows = db.count_raw_rows_outside(invalid_min_ts, max_ts)?;
    let unaggregated_invalid_rows =
        db.count_unaggregated_raw_rows_outside(invalid_min_ts, max_ts)?;
    let legacy_unaggregated_rows = if cfg.retention_1m_days == 0 {
        0
    } else {
        let horizon = now.saturating_sub(i64::from(cfg.retention_1m_days).saturating_mul(DAY_MS));
        db.count_unaggregated_raw_rows_before(horizon)?
    };
    let isolated_rows = if unaggregated_invalid_rows > 0 {
        db.isolate_raw_rows_outside(invalid_min_ts, max_ts)?
    } else {
        0
    };
    if invalid_timestamp_rows > 0 || legacy_unaggregated_rows > 0 {
        tracing::warn!(
            invalid_timestamp_rows,
            unaggregated_invalid_rows,
            legacy_unaggregated_rows,
            isolated_rows,
            "legacy raw 时间戳审计：负值/未来超界样本已隔离；早于 1m horizon 的未聚合行保留给 delta"
        );
    }
    Ok(LegacyAuditReport {
        invalid_timestamp_rows,
        unaggregated_invalid_rows,
        legacy_unaggregated_rows,
        isolated_rows,
    })
}

/// 读取当前维护状态（各层行数 / 时间范围 / 水位 / 最近错误 / 未聚合计数）。
pub fn maintenance_status(
    db: &dyn Storage,
    cfg: &HubConfig,
    now: i64,
) -> Result<MaintenanceStatus> {
    let last_error = db
        .get_maintenance_state(STATE_LAST_ERROR)?
        .filter(|value| !value.trim().is_empty());
    // 与 audit 一致：只有负值/未来真正非法；old backlog 不是 invalid。
    let invalid_min_ts = 0;
    let max_ts = cfg.ingest.max_sample_ts(now);
    let legacy_unaggregated_rows = if cfg.retention_1m_days == 0 {
        0
    } else {
        let horizon = now.saturating_sub(i64::from(cfg.retention_1m_days).saturating_mul(DAY_MS));
        db.count_unaggregated_raw_rows_before(horizon)?
    };
    Ok(MaintenanceStatus {
        raw: db.raw_stats()?,
        one_minute: db.samples_1m_stats()?,
        one_hour: db.samples_1h_stats()?,
        downsample_1m_watermark: read_state_i64(db, STATE_DOWNSAMPLE_1M_WATERMARK)?,
        downsample_1h_watermark: read_state_i64(db, STATE_DOWNSAMPLE_1H_WATERMARK)?,
        downsample_1m_last_raw_rowid: read_state_i64(db, STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID)?,
        retention_last_run: read_state_i64(db, STATE_RETENTION_LAST_RUN)?,
        last_error,
        unaggregated_rows: db.count_unaggregated_raw_rows()?,
        invalid_timestamp_rows: db.count_raw_rows_outside(invalid_min_ts, max_ts)?,
        legacy_unaggregated_rows,
        archive_ledger_pending: archive_ledger_pending(db)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::sqlite::{AggregateRowForTest, SqliteStorage};
    use rustboard_common::config::HubIngestConfig;
    use rustboard_common::model::{Sample, SampleBatch};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// 固定测试时间：整分钟（UTC 毫秒）。
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
            ingest: HubIngestConfig {
                max_late_days: 3_650,
                max_future_skew_secs: 3_600,
            },
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
    fn r1b_run_downsample_without_raw_writes_no_watermark() {
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
        let status = maintenance_status(&db, &HubConfig::default(), NOW).unwrap();
        assert_eq!(status, MaintenanceStatus::default());
    }

    /// 1m：只聚合已关闭分钟；桶内 min/max/avg/last 与 count 正确。
    #[test]
    fn r1b_one_minute_delta_aggregates_closed_buckets_only() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS).unwrap();
        let base = closed - 2 * BUCKET_1M_MS;
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
        assert_eq!(report.one_minute.rows, 5);
        // 两个分钟 × 两种标签 = 3 个非空桶。
        assert_eq!(report.one_minute.buckets, 3);

        let rows = db.aggregate_rows_for_test("1m");
        let plain = find_agg(&rows, "{}");
        assert_eq!(plain.bucket_ts, base);
        assert_eq!(plain.min_value, 1.0);
        assert_eq!(plain.max_value, 5.0);
        assert!((plain.avg_value - 3.0).abs() < 1e-9);
        assert_eq!(plain.last_value, 3.0);
        assert_eq!(plain.count, 3);
        let disk = find_agg(&rows, r#"{"disk":"sda"}"#);
        assert_eq!(disk.count, 1);
        assert_eq!(disk.last_value, 42.0);
        let second = rows
            .iter()
            .find(|row| row.bucket_ts == base + BUCKET_1M_MS)
            .expect("第二个分钟桶必须存在");
        assert_eq!(second.count, 1);
        assert_eq!(second.last_value, 7.0);
        assert!(
            rows.iter().all(|row| row.bucket_ts != closed),
            "未关闭分钟不得聚合: {rows:?}"
        );

        // 当前小时尚未结束：1h 不能聚合半个小时的残缺数据，也不写 1h 水位。
        assert_eq!(report.one_hour.watermark, None);
        assert!(db.aggregate_rows_for_test("1h").is_empty());
    }

    /// 重跑幂等；迟到（同桶更大 ts）按 delta 合并，水位不回拨。
    #[test]
    fn r1b_rerun_is_idempotent_and_late_merges_delta() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS).unwrap();
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
        assert_eq!(again.one_minute.rows, 0, "没有新 raw 时不得重复合并");
        assert_eq!(again.one_minute.watermark, Some(closed));
        assert_eq!(
            db.aggregate_rows_for_test("1m"),
            before_1m,
            "重复执行不得增行 / 改值"
        );

        // 迟到重传：同一已关闭桶来了更晚的样本，下一轮 delta 合并。
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", last_bucket + 30_000, 9.0)],
        );
        let third = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(
            third.one_minute.watermark,
            Some(closed),
            "迟到不得回拨 1m 水位"
        );
        let rows = db.aggregate_rows_for_test("1m");
        assert_eq!(rows.len(), 1, "delta 不得新增桶");
        assert_eq!(rows[0].count, 2);
        assert_eq!(rows[0].max_value, 9.0);
        assert_eq!(rows[0].last_value, 9.0);
        assert!((rows[0].avg_value - 5.0).abs() < 1e-9);
    }

    /// 1h：只聚合完整小时，按 count 加权平均；重复执行幂等。
    #[test]
    fn r1b_one_hour_weighted_and_complete_hours_only() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let now = 1_699_999_200_000; // 整点
        let current_hour = bucket_floor(now, BUCKET_1H_MS).unwrap();
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

        let report = run_downsample(&db, now, None).unwrap();
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
        assert!(
            rows.iter().all(|row| row.bucket_ts != current_hour),
            "当前小时不得提前聚合"
        );

        let before_1m = db.aggregate_rows_for_test("1m");
        let before_1h = rows.clone();
        let again = run_downsample(&db, now, None).unwrap();
        assert_eq!(again.one_hour.rows, 0);
        assert_eq!(again.one_hour.watermark, Some(current_hour));
        assert_eq!(db.aggregate_rows_for_test("1m"), before_1m);
        assert_eq!(db.aggregate_rows_for_test("1h"), before_1h);
    }

    /// 后台模式：1m 单块最多约 5,000 行；一个桶超限时整桶处理。
    #[test]
    fn r1b_one_minute_chunks_by_rows_and_keeps_whole_bucket() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS).unwrap();
        let first_bucket = closed - 3 * BUCKET_1M_MS;
        let last_bucket = closed - BUCKET_1M_MS;
        let mut samples: Vec<Sample> = (0..5_001i64)
            .map(|index| Sample::new("cpu.usage", first_bucket + index % 59_000, index as f64))
            .collect();
        samples.push(Sample::new("cpu.usage", last_bucket + 1_000, 1.0));
        seed(&db, "a1", samples);

        let first = run_downsample(&db, NOW, Some(1)).unwrap();
        assert_eq!(first.one_minute.chunks, 1);
        assert_eq!(
            first.one_minute.watermark,
            Some(first_bucket + BUCKET_1M_MS),
            "第一块必须整桶收在第一分钟桶结束"
        );
        assert_eq!(db.aggregate_rows_for_test("1m").len(), 1);

        let rest = run_downsample(&db, NOW, None).unwrap();
        assert_eq!(rest.one_minute.watermark, Some(closed));
        assert_eq!(db.aggregate_rows_for_test("1m").len(), 2);
    }

    /// 1h 不得在 1m 源残缺时聚合：1m 只处理了前一分钟桶时必须跳过该小时。
    #[test]
    fn r1b_one_hour_waits_for_complete_one_minute_source() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let now = 1_699_999_200_000; // 整点
        let hour = now - BUCKET_1H_MS;
        let first_bucket = hour + BUCKET_1M_MS;
        let second_bucket = hour + 2 * BUCKET_1M_MS;
        let mut samples: Vec<Sample> = (0..5_001i64)
            .map(|index| Sample::new("cpu.usage", first_bucket + index % 59_000, index as f64))
            .collect();
        samples.push(Sample::new("cpu.usage", second_bucket + 1_000, 1.0));
        seed(&db, "a1", samples);

        let first = run_downsample(&db, now, Some(1)).unwrap();
        assert_eq!(first.one_minute.chunks, 1);
        assert_eq!(
            first.one_hour.watermark, None,
            "1m 源不完整时不得写 1h 水位"
        );
        assert!(
            db.aggregate_rows_for_test("1h").is_empty(),
            "1m 源不完整时不得生成 1h"
        );

        let rest = run_downsample(&db, now, None).unwrap();
        assert_eq!(rest.one_minute.chunks, 1);
        assert_eq!(rest.one_hour.watermark, Some(now));
        assert_eq!(db.aggregate_rows_for_test("1h").len(), 1);
    }

    /// 损坏的水位必须报错（不 panic、不静默重置），错误点名字段。
    #[test]
    fn r1b_run_downsample_corrupt_watermark_returns_error() {
        let db = SqliteStorage::open_in_memory().unwrap();
        db.set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, "not-a-number", NOW)
            .unwrap();
        let err = run_downsample(&db, NOW, None).unwrap_err();
        assert!(
            err.to_string().contains(STATE_DOWNSAMPLE_1M_WATERMARK),
            "错误信息必须点名损坏的键: {err}"
        );
    }

    /// #50：`bucket_floor` 对 i64 极端值只返回错误，不 panic / 回绕。
    #[test]
    fn issue50_bucket_floor_is_checked_for_i64_extremes() {
        assert!(bucket_floor(i64::MIN, BUCKET_1M_MS).is_err());
        assert!(bucket_floor(i64::MIN, BUCKET_1H_MS).is_err());
        // 最大正数取整不会溢出（向下取整结果 <= i64::MAX）。
        assert!(bucket_floor(i64::MAX, BUCKET_1M_MS).is_ok());
        assert_eq!(bucket_floor(0, BUCKET_1M_MS).unwrap(), 0);
        assert_eq!(bucket_floor(BUCKET_1M_MS - 1, BUCKET_1M_MS).unwrap(), 0);
    }

    /// raw 保留：严格 `< cutoff`（等于不删）、0 = 不删、只删已聚合行。
    #[test]
    fn r1b_run_retention_raw_only_deletes_aggregated_rows() {
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
        run_downsample(&db, NOW, None).unwrap();

        let cfg = cfg_with_retention(7, 90, 730);
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
        assert_eq!(report.raw.cutoff, Some(cutoff));
        assert_eq!(report.raw.effective_cutoff, Some(cutoff));
        assert_eq!(report.raw.deleted, 1, "只删 cutoff 之前且已聚合的行");
        assert!(!report.raw.disabled);
        assert!(!report.raw.blocked_by_downsample);

        let raw = db.raw_stats().unwrap();
        assert_eq!(raw.rows, 3, "等于 cutoff 的行必须保留");
        assert_eq!(raw.oldest_ts, Some(cutoff));
        assert_eq!(
            db.get_maintenance_state(STATE_RETENTION_LAST_RUN).unwrap(),
            Some(NOW.to_string())
        );

        // 0 = 该层不删。
        let cfg_disabled = cfg_with_retention(0, 0, 0);
        let report = run_retention(&db, &cfg_disabled, NOW, ArchiveGate::Disabled).unwrap();
        assert!(report.raw.disabled);
        assert_eq!(report.raw.cutoff, None);
        assert_eq!(report.raw.deleted, 0);
        assert_eq!(db.raw_stats().unwrap().rows, 3);
    }

    /// 未聚合 raw 即使早于 cutoff 也不得删除，并标记 blocked_by_downsample。
    #[test]
    fn r1b_run_retention_never_deletes_unaggregated_raw() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let old = NOW - 100 * DAY_MS;
        seed(&db, "a1", vec![Sample::new("cpu.usage", old, 1.0)]);
        let cfg = cfg_with_retention(7, 90, 730);

        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
        assert_eq!(report.raw.deleted, 0);
        assert!(!report.raw.skipped_no_watermark, "R1b 不再依赖水位");
        assert!(report.raw.blocked_by_downsample);
        assert_eq!(db.raw_stats().unwrap().rows, 1);

        run_downsample(&db, NOW, None).unwrap();
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
        assert_eq!(report.raw.deleted, 1, "聚合后下一轮才可删");
        assert_eq!(db.raw_stats().unwrap().rows, 0);
    }

    /// 归档门禁：仅旧水位不足以删除；ledger pending 时完全跳过。
    #[test]
    fn r1b_run_retention_archive_requires_uploaded_claim() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let old = NOW - 100 * DAY_MS;
        seed(&db, "a1", vec![Sample::new("cpu.usage", old, 1.0)]);
        run_downsample(&db, NOW, None).unwrap();
        let cfg = cfg_with_retention(7, 90, 730);

        let report = run_retention(
            &db,
            &cfg,
            NOW,
            ArchiveGate::Enabled {
                watermark: Some(NOW),
            },
        )
        .unwrap();
        assert_eq!(report.raw.deleted, 0, "未 uploaded 的 raw 不得删除");
        assert!(report.raw.blocked_by_archive);
        assert_eq!(db.raw_stats().unwrap().rows, 1);

        db.set_archive_state(STATE_ARCHIVE_LEDGER_PENDING, "1", NOW)
            .unwrap();
        let report = run_retention(
            &db,
            &cfg,
            NOW,
            ArchiveGate::Enabled {
                watermark: Some(NOW),
            },
        )
        .unwrap();
        assert_eq!(report.raw.deleted, 0);
        assert!(report.raw.skipped_archive_ledger_pending);
        assert_eq!(db.raw_stats().unwrap().rows, 1);
    }

    /// 1h 保留边界：`bucket_ts == cutoff` 不删，严格更早才删。
    #[test]
    fn r1b_run_retention_hour_cutoff_boundary() {
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
        run_downsample(&db, now, None).unwrap();
        assert_eq!(db.samples_1h_stats().unwrap().rows, 2);

        let cfg = cfg_with_retention(0, 0, 730);
        let report = run_retention(&db, &cfg, now, ArchiveGate::Disabled).unwrap();
        assert_eq!(report.one_hour.cutoff, Some(cutoff));
        assert_eq!(report.one_hour.deleted, 1);
        assert_eq!(db.samples_1h_stats().unwrap().rows, 1);
        assert_eq!(db.samples_1h_stats().unwrap().oldest_ts, Some(equal_bucket));
    }

    /// 保留期按 5,000 行/批删除，批次数正确。
    #[test]
    fn r1b_run_retention_deletes_in_batches() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let cutoff = NOW - 7 * DAY_MS;
        let samples = (0..12_000i64)
            .map(|index| Sample::new("cpu.usage", cutoff - 12_000 + index, index as f64))
            .collect();
        seed(&db, "a1", samples);
        run_downsample(&db, NOW, None).unwrap();

        let cfg = cfg_with_retention(7, 0, 0);
        let report = run_retention(&db, &cfg, NOW, ArchiveGate::Disabled).unwrap();
        assert_eq!(report.raw.deleted, 12_000);
        assert_eq!(report.raw.batches, 3, "12,000 = 5000 + 5000 + 2000");
        assert_eq!(db.raw_stats().unwrap().rows, 0);
    }

    /// 维护状态：新增未聚合 / 超界 / legacy horizon 字段与 JSON 序列化。
    #[test]
    fn r1b_maintenance_status_fields_and_reports_serialize() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let cfg = cfg_with_retention(7, 90, 730);
        let status = maintenance_status(&db, &cfg, NOW).unwrap();
        assert_eq!(status.unaggregated_rows, 0);
        assert_eq!(status.invalid_timestamp_rows, 0);
        assert_eq!(status.legacy_unaggregated_rows, 0);
        assert!(!status.archive_ledger_pending);

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
        assert_eq!(json["raw"]["skipped_no_watermark"], false);
        assert_eq!(json["one_minute"]["retention_days"], 90);
        assert_eq!(json["one_hour"]["retention_days"], 730);

        let status = maintenance_status(&db, &cfg, NOW).unwrap();
        let json = serde_json::to_value(&status).unwrap();
        assert_eq!(json["raw"]["rows"], 0);
        assert_eq!(json["unaggregated_rows"], 0);
        assert_eq!(json["invalid_timestamp_rows"], 0);
        assert_eq!(json["legacy_unaggregated_rows"], 0);
        assert_eq!(json["archive_ledger_pending"], false);
        assert!(json.get("downsample_1m_watermark").is_some());
        assert!(json.get("last_error").is_some());
    }

    /// #33：升级/长期离线 backlog 不得在启动审计被隔离后静默丢弃。
    #[test]
    fn r1b_audit_does_not_isolate_old_backlog() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let old = NOW - 100 * DAY_MS;
        seed(&db, "a1", vec![Sample::new("cpu.usage", old, 1.0)]);
        let cfg = cfg_with_retention(7, 90, 730);
        let report = audit_legacy_raw_rows(&db, &cfg, NOW).unwrap();
        assert_eq!(
            report.invalid_timestamp_rows, 0,
            "旧 backlog 不是非法时间戳"
        );
        assert_eq!(report.isolated_rows, 0, "旧 backlog 不得被隔离");
        assert_eq!(report.legacy_unaggregated_rows, 1);
        assert_eq!(db.count_unaggregated_raw_rows_before(NOW).unwrap(), 1);

        run_downsample(&db, NOW, None).unwrap();
        let buckets = db.aggregate_rows_for_test("1m");
        assert_eq!(buckets.len(), 1, "旧 backlog 必须真正进入 1m");
        assert_eq!(buckets[0].count, 1);
    }

    /// 干净 1m 小时里只要还有未聚合 raw，就不能先删 1m；补聚合后才可删。
    #[test]
    fn r1b_retention_keeps_1m_hour_with_unaggregated_raw() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let hour = bucket_floor(NOW - 2 * BUCKET_1H_MS, BUCKET_1H_MS).unwrap();
        seed(&db, "a1", vec![Sample::new("cpu.usage", hour + 1_000, 1.0)]);
        run_downsample(&db, NOW, None).unwrap();
        assert_eq!(db.aggregate_rows_for_test("1m").len(), 1);

        // 同一小时再来一条迟到 raw，尚未并入 1m。
        seed(&db, "a1", vec![Sample::new("cpu.usage", hour + 2_000, 2.0)]);
        let cutoff = hour + BUCKET_1H_MS;
        assert_eq!(
            db.prune_samples_1m_before(cutoff).unwrap().deleted,
            0,
            "同小时还有未聚合 raw 时不得删 1m"
        );

        // 真实 delta 补入迟到行；再用真实 1h 聚合把整小时标 clean。
        run_downsample(&db, NOW, None).unwrap();
        db.downsample_1h_range(hour, cutoff).unwrap();
        assert_eq!(
            db.prune_samples_1m_before(cutoff).unwrap().deleted,
            1,
            "raw 补聚合且 1h 完成后才允许删 1m"
        );
    }

    /// 水位只前进：用更早的 now 重跑不得回拨。
    #[test]
    fn r1b_watermarks_only_advance() {
        let db = SqliteStorage::open_in_memory().unwrap();
        let closed = bucket_floor(NOW, BUCKET_1M_MS).unwrap();
        seed(
            &db,
            "a1",
            vec![Sample::new("cpu.usage", closed - 1_000, 1.0)],
        );
        run_downsample(&db, NOW, None).unwrap();
        let report = run_downsample(&db, NOW - BUCKET_1H_MS, None).unwrap();
        assert_eq!(report.one_minute.watermark, Some(closed), "1m 水位只前进");
    }
}
