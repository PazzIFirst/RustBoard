//! M4-C1b：冷归档 worker、水位与保留期门禁。
//!
//! 实现范围（方案 §7.1–7.4 / §10 C1，仅 WebDAV）：
//!
//! - [`spawn_archive_worker`]：仅 `archive.enabled = true` 时启动；每天 UTC
//!   `schedule_hour_utc` 执行一次，启动时若今天已过计划时间且
//!   `archive_state.last_archived_ts` 落后则立即补跑。任何错误只 WARN，
//!   任务不退出；
//! - [`run_archive_once`]：可测试的单轮归档。按 UTC 天 + 分片处理 raw，
//!   只归档「已完成且早于 `now - after_days` 天」的数据；
//! - 每片用 [`CsvArchiveWriter`] 生成 `csv.gz`，上传对象与同名
//!   `.manifest.json`，`HEAD` 校验大小；失败标记 `failed`、保留 raw、
//!   不推进水位；
//! - `archive_objects` 先按 key 查重，已 `uploaded` / `local_deleted` 直接跳过
//!   （重跑幂等）；`failed` 记录可重试；
//! - 只有一整天所有分片成功后才把 `archive_state.last_archived_ts` 推进到
//!   **该天结束（排他）**，供 [`archive_gate`] 与 retention 使用；
//! - 本模块不删除 raw：保留期由 `downsample::run_retention` 在归档门禁下执行。
//!
//! 安全约定：错误与日志不包含 WebDAV URL、用户名、密码或响应正文；对象 key
//! 只由配置 prefix + UTC 日期 + 分片生成。

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustboard_common::config::{ArchiveBackend, ArchiveConfig, HubConfig};
use rustboard_common::util::now_ms;
use rustboard_core::archive::{
    build_object_keys, manifest_json, ArchiveDay, ArchiveError, ArchiveManifest, ArchiveObject,
    ArchiveStatus, ArchiveStoreError, ColdStore, CsvArchiveOutput, CsvArchiveWriter,
};
use rustboard_core::downsample::ArchiveGate;
use rustboard_core::storage::sqlite::{ArchiveRawRow, SqliteStorage};
use serde::Serialize;

use crate::archive_webdav::WebdavColdStore;

/// `archive_state` 键：已成功归档到的排他时间边界（Unix 毫秒）。
pub(crate) const STATE_LAST_ARCHIVED_TS: &str = "last_archived_ts";
/// `archive_state` 键：最近一次归档尝试时间（Unix 毫秒）。
pub(crate) const STATE_LAST_RUN: &str = "last_run";
/// `archive_state` 键：最近一次归档失败原因（成功后清空）。
pub(crate) const STATE_LAST_ERROR: &str = "last_error";

/// 一天 / 一小时的毫秒数（UTC，无夏令时）。
const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

/// 单片最大行数。方案允许 100,000 行，这里按 50,000 行保守分片，降低
/// 单对象内存峰值与压缩后超过 `max_object_bytes` 的概率。
const MAX_SHARD_ROWS: usize = 50_000;

/// 单次 SQL 扫描行数；worker 分批读取，避免一次把整天 raw 读进内存。
const SCAN_BATCH_ROWS: usize = 10_000;

/// 写入 `archive_state.last_error` 的最大字符数，避免超长错误撑大状态表。
const MAX_LAST_ERROR_CHARS: usize = 512;

/// 一次归档任务的结果（`archive run` 输出 / worker 日志 / 测试断言）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ArchiveRunReport {
    /// 归档是否启用；未启用时任务直接失败，不返回报告。
    pub enabled: bool,
    /// 本次成功处理（含空天）的天数。
    pub days: usize,
    /// 本次新上传的对象数。
    pub objects: usize,
    /// 已存在且成功而跳过的对象数（重跑幂等）。
    pub skipped_objects: usize,
    /// 本次处理 / 跳过的 raw 行数。
    pub rows: u64,
    /// 本次新上传对象的压缩后字节数。
    pub bytes: u64,
    /// 任务结束时的归档水位（排他边界）。
    pub watermark: Option<i64>,
}

/// `archive status` / `GET /api/v1/archive/status` 的固定结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ArchiveStatusOutput {
    pub enabled: bool,
    pub backend: String,
    pub last_archived_ts: Option<i64>,
    pub last_run: Option<i64>,
    pub last_error: Option<String>,
    /// `archive_objects` 总行数（不区分状态）。
    pub objects: i64,
}

/// 构建 WebDAV 冷存储；S3 / SFTP 属于 C2 / C3，当前显式失败。
pub(crate) fn build_store(cfg: &ArchiveConfig) -> Result<Arc<dyn ColdStore>> {
    match cfg.backend {
        ArchiveBackend::Webdav => {
            let webdav = cfg.webdav.as_ref().context("缺少 [archive.webdav] 配置")?;
            let store = WebdavColdStore::new(webdav)?;
            Ok(Arc::new(store))
        }
        ArchiveBackend::S3 | ArchiveBackend::Sftp => bail!(
            "归档后端 {} 尚未实现（当前仅支持 webdav，S3 / SFTP 在 C2 / C3 提供）",
            cfg.backend.as_str()
        ),
    }
}

/// 读取归档水位；key 不存在 / 空串视为 `None`，非法整数返回错误。
fn read_archive_i64(storage: &SqliteStorage, key: &str) -> Result<Option<i64>> {
    let Some(raw) = storage.get_archive_state(key)? else {
        return Ok(None);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<i64>()
        .map(Some)
        .map_err(|_| anyhow::anyhow!("archive_state.{key} 不是合法的十进制整数"))
}

/// 保留期使用的归档门禁。
///
/// 归档启用时读 `archive_state.last_archived_ts`：
/// - 有合法水位 → `Enabled { watermark: Some(..) }`；
/// - 水位缺失 / 为空 / 损坏 → `Enabled { watermark: None }`，**阻止 raw 删除**，
///   避免「还没成功归档就被保留期删掉唯一副本」。
pub(crate) fn archive_gate(storage: &SqliteStorage, cfg: &HubConfig) -> ArchiveGate {
    if !cfg.archive.enabled {
        return ArchiveGate::Disabled;
    }
    match read_archive_i64(storage, STATE_LAST_ARCHIVED_TS) {
        Ok(watermark) => ArchiveGate::Enabled { watermark },
        Err(err) => {
            tracing::warn!(
                error = %err,
                "读取归档水位失败：按无水位处理，阻止 raw 保留期删除"
            );
            ArchiveGate::Enabled { watermark: None }
        }
    }
}

/// 读取 `archive status` 的结构化状态。
pub(crate) fn status(storage: &SqliteStorage, cfg: &HubConfig) -> Result<ArchiveStatusOutput> {
    let last_error = storage
        .get_archive_state(STATE_LAST_ERROR)?
        .filter(|value| !value.trim().is_empty());
    Ok(ArchiveStatusOutput {
        enabled: cfg.archive.enabled,
        backend: cfg.archive.backend.as_str().to_string(),
        last_archived_ts: read_archive_i64(storage, STATE_LAST_ARCHIVED_TS)?,
        last_run: read_archive_i64(storage, STATE_LAST_RUN)?,
        last_error,
        objects: storage.count_archive_objects()?,
    })
}

/// 启动归档 worker。
///
/// - `archive.enabled = false`：只记 INFO，不启动；
/// - 非 WebDAV 后端：C2 / C3 未实现，WARN 后不启动（不能让 hub 启动失败）；
/// - 启动补跑：今天已过 `schedule_hour_utc` 且水位落后于「最新可归档天结束」
///   时立即执行一轮，之后按每天计划时间运行；
/// - 每轮错误只 WARN，任务不退出；不修改 raw，保留期仍受 [`archive_gate`] 门禁。
pub(crate) fn spawn_archive_worker(storage: Arc<SqliteStorage>, cfg: HubConfig) {
    if !cfg.archive.enabled {
        tracing::info!("归档 worker 未启用（archive.enabled = false）");
        return;
    }
    let store = match build_store(&cfg.archive) {
        Ok(store) => store,
        Err(err) => {
            tracing::warn!(error = %err, "归档 worker 初始化失败，不启动");
            return;
        }
    };

    tokio::spawn(async move {
        let startup_now = now_ms();
        match should_catch_up(&storage, &cfg, startup_now) {
            Ok(true) => {
                tracing::info!("归档 worker：今天已过计划时间且水位落后，立即补跑");
                if let Err(err) =
                    run_archive_once(&storage, &cfg, store.as_ref(), startup_now).await
                {
                    tracing::warn!(error = %err, "归档补跑失败，保留水位等待下一轮重试");
                }
            }
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(error = %err, "判断归档补跑条件失败，等待计划时间");
            }
        }

        loop {
            let delay = next_run_delay(now_ms(), cfg.archive.schedule_hour_utc);
            tracing::debug!(
                delay_secs = delay.as_secs(),
                hour_utc = cfg.archive.schedule_hour_utc,
                "归档 worker：等待下一次计划时间"
            );
            tokio::time::sleep(delay).await;
            if let Err(err) = run_archive_once(&storage, &cfg, store.as_ref(), now_ms()).await {
                tracing::warn!(error = %err, "归档任务失败，保留水位等待下一轮重试");
            }
        }
    });
}

/// 启动补跑判定：今天已过计划时间，且水位早于最新可归档天的结束边界。
fn should_catch_up(storage: &SqliteStorage, cfg: &HubConfig, now: i64) -> Result<bool> {
    let scheduled = day_start(now) + i64::from(cfg.archive.schedule_hour_utc) * HOUR_MS;
    if now < scheduled {
        return Ok(false);
    }
    let eligible_end = eligible_day_end(cfg.archive.after_days, now);
    let watermark = read_archive_i64(storage, STATE_LAST_ARCHIVED_TS)?;
    Ok(match watermark {
        Some(watermark) => watermark < eligible_end,
        None => true,
    })
}

/// 距离下一次计划执行的时长；刚好处在计划时刻时排到第二天，避免忙循环。
fn next_run_delay(now: i64, schedule_hour_utc: u8) -> Duration {
    let scheduled = day_start(now) + i64::from(schedule_hour_utc) * HOUR_MS;
    let target = if now < scheduled {
        scheduled
    } else {
        scheduled + DAY_MS
    };
    let millis = u64::try_from(target - now).unwrap_or(0).max(1_000);
    Duration::from_millis(millis)
}

/// 执行一轮归档（后台 worker 与 `archive run` 共用）。
///
/// 无论成功失败都会写 `last_run`；失败时把固定错误摘要写入 `last_error`。
/// 返回的 [`ArchiveRunReport`] 只用于日志 / CLI，不包含 secret。
pub(crate) async fn run_archive_once(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    now: i64,
) -> Result<ArchiveRunReport> {
    run_archive_once_with_limits(storage, cfg, store, now, MAX_SHARD_ROWS, SCAN_BATCH_ROWS).await
}

/// 带可调分片 / 扫描行数的实现；测试用小分片覆盖多分片路径。
async fn run_archive_once_with_limits(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    now: i64,
    max_shard_rows: usize,
    scan_batch_rows: usize,
) -> Result<ArchiveRunReport> {
    let result = run_archive_cycle(
        storage,
        cfg,
        store,
        now,
        max_shard_rows.max(1),
        scan_batch_rows.max(1),
    )
    .await;
    record_run_state(storage, now, &result);
    result
}

/// 访问数据库失败时只 WARN，不覆盖调用方真正关心的归档错误。
fn record_run_state(storage: &SqliteStorage, now: i64, result: &Result<ArchiveRunReport>) {
    let last_error = match result {
        Ok(_) => String::new(),
        Err(err) => format!("{err:#}")
            .chars()
            .take(MAX_LAST_ERROR_CHARS)
            .collect::<String>(),
    };
    if let Err(err) = storage.set_archive_state(STATE_LAST_RUN, &now.to_string(), now) {
        tracing::warn!(error = %err, "写入归档任务 last_run 失败");
    }
    if let Err(err) = storage.set_archive_state(STATE_LAST_ERROR, &last_error, now) {
        tracing::warn!(error = %err, "写入归档任务 last_error 失败");
    }
}

/// 一轮归档的主体：按 UTC 天推进，逐日切分片并上传。
async fn run_archive_cycle(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    now: i64,
    max_shard_rows: usize,
    scan_batch_rows: usize,
) -> Result<ArchiveRunReport> {
    if !cfg.archive.enabled {
        bail!("归档未启用（archive.enabled = false）");
    }

    let watermark = read_archive_i64(storage, STATE_LAST_ARCHIVED_TS)?;
    let mut report = ArchiveRunReport {
        enabled: true,
        watermark,
        ..ArchiveRunReport::default()
    };

    // 只处理「整天都早于 now - after_days」的原始数据：eligible_end 是最后
    // 一个完整可归档 UTC 天的排他结束边界。
    let eligible_end = eligible_day_end(cfg.archive.after_days, now);
    let mut cursor = match watermark {
        Some(value) if value % DAY_MS == 0 => value,
        // 非整天值（旧版本 / 人工修库）从下一天开始，避免把半天重复归档。
        Some(value) => day_start(value) + DAY_MS,
        None => match storage.raw_stats()?.oldest_ts {
            Some(oldest) => day_start(oldest),
            // 没有任何 raw：本轮无事可做，也不凭空写水位。
            None => return Ok(report),
        },
    };

    while cursor.saturating_add(DAY_MS) <= eligible_end {
        let day = archive_day_for(cursor)?;
        let day_end = cursor + DAY_MS;
        let mut after_rowid: Option<i64> = None;
        let mut shard_rows: Vec<ArchiveRawRow> = Vec::new();
        let mut next_shard: u32 = 1;

        loop {
            while shard_rows.len() < max_shard_rows {
                let remaining = max_shard_rows - shard_rows.len();
                let batch = storage.scan_archive_rows(
                    cursor,
                    day_end,
                    after_rowid,
                    scan_batch_rows.min(remaining),
                )?;
                if batch.is_empty() {
                    break;
                }
                after_rowid = batch.last().map(|row| row.rowid);
                shard_rows.extend(batch);
            }
            if shard_rows.is_empty() {
                break;
            }
            let outcome =
                upload_shard(storage, cfg, store, day, &mut next_shard, &shard_rows, now).await?;
            report.objects += outcome.uploaded;
            report.skipped_objects += outcome.skipped;
            report.rows += outcome.rows;
            report.bytes += outcome.bytes;
            shard_rows.clear();
        }

        // 整天所有分片成功后才推进水位；中途失败会直接返回，水位保持旧值。
        storage.set_archive_state(STATE_LAST_ARCHIVED_TS, &day_end.to_string(), now)?;
        report.days += 1;
        report.watermark = Some(day_end);
        cursor = day_end;
    }

    Ok(report)
}

/// 一片的上传结果（`upload_shard` 内部分裂时会累加多片）。
#[derive(Debug, Default, Clone, Copy)]
struct ShardOutcome {
    uploaded: usize,
    skipped: usize,
    rows: u64,
    bytes: u64,
}

/// 生成并上传一个分片；若压缩后超过 `max_object_bytes`，把行对半拆开重试。
///
/// 用显式 `VecDeque` 代替递归，避免 async 递归的 boxed future 与额外分配；
/// 拆分保持行顺序，分片编号连续。
async fn upload_shard(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    day: ArchiveDay,
    next_shard: &mut u32,
    rows: &[ArchiveRawRow],
    now: i64,
) -> Result<ShardOutcome> {
    let mut pending: VecDeque<&[ArchiveRawRow]> = VecDeque::new();
    pending.push_back(rows);
    let mut outcome = ShardOutcome::default();

    while let Some(chunk) = pending.pop_front() {
        let output = build_csv(chunk)?;
        if output.bytes > cfg.archive.max_object_bytes && chunk.len() > 1 {
            let mid = chunk.len() / 2;
            pending.push_front(&chunk[mid..]);
            pending.push_front(&chunk[..mid]);
            continue;
        }

        let shard = format!("part-{:05}", *next_shard);
        *next_shard = (*next_shard).checked_add(1).context("归档分片编号溢出")?;
        let keys = build_object_keys(&cfg.archive.prefix, day, &shard)?;
        let from_ts = chunk.iter().map(|row| row.ts).min().unwrap_or(now);
        let to_ts = chunk.iter().map(|row| row.ts).max().unwrap_or(now);
        let manifest = ArchiveManifest::new(
            keys.object_key.clone(),
            from_ts,
            to_ts,
            output.rows,
            output.bytes,
            output.sha256.clone(),
            now,
        );
        let manifest_bytes = manifest_json(&manifest)?.into_bytes();

        let existing = storage.find_archive_object_by_key(&keys.object_key)?;
        let id = match existing {
            Some(object) => match object.status {
                ArchiveStatus::Uploaded | ArchiveStatus::LocalDeleted => {
                    outcome.skipped += 1;
                    outcome.rows += output.rows;
                    continue;
                }
                ArchiveStatus::Failed => {
                    storage.update_archive_object_status(
                        object.id,
                        ArchiveStatus::Pending,
                        "",
                        None,
                        None,
                    )?;
                    object.id
                }
                ArchiveStatus::Pending => object.id,
            },
            None => {
                let object = ArchiveObject {
                    id: 0,
                    backend: cfg.archive.backend.as_str().to_string(),
                    object_key: keys.object_key.clone(),
                    manifest_key: keys.manifest_key.clone(),
                    from_ts,
                    to_ts,
                    rows: output.rows,
                    bytes: output.bytes,
                    sha256: output.sha256.clone(),
                    status: ArchiveStatus::Pending,
                    error: String::new(),
                    created_at: now,
                    uploaded_at: None,
                    deleted_at: None,
                };
                match storage.insert_archive_object(&object) {
                    Ok(id) => id,
                    Err(err)
                        if matches!(
                            err.downcast_ref::<ArchiveStoreError>(),
                            Some(ArchiveStoreError::ObjectExists)
                        ) =>
                    {
                        // 并发 / 上一轮中断造成插入冲突：重新读一次，已上传则跳过。
                        let Some(existing) =
                            storage.find_archive_object_by_key(&keys.object_key)?
                        else {
                            return Err(err);
                        };
                        match existing.status {
                            ArchiveStatus::Uploaded | ArchiveStatus::LocalDeleted => {
                                outcome.skipped += 1;
                                outcome.rows += output.rows;
                                continue;
                            }
                            ArchiveStatus::Failed => {
                                storage.update_archive_object_status(
                                    existing.id,
                                    ArchiveStatus::Pending,
                                    "",
                                    None,
                                    None,
                                )?;
                                existing.id
                            }
                            ArchiveStatus::Pending => existing.id,
                        }
                    }
                    Err(err) => return Err(err),
                }
            }
        };

        if let Err(err) =
            upload_object_and_manifest(store, &keys, &output.data, &manifest_bytes).await
        {
            if let Err(db_err) = storage.update_archive_object_status(
                id,
                ArchiveStatus::Failed,
                archive_error_code(err),
                None,
                None,
            ) {
                tracing::warn!(error = %db_err, "标记归档对象失败状态时数据库错误");
            }
            return Err(err.into());
        }
        storage.update_archive_object_status(id, ArchiveStatus::Uploaded, "", Some(now), None)?;
        outcome.uploaded += 1;
        outcome.rows += output.rows;
        outcome.bytes += output.bytes;
    }

    Ok(outcome)
}

/// 生成 CSV.GZ 并返回压缩内容、行数、字节数与 SHA-256。
fn build_csv(rows: &[ArchiveRawRow]) -> Result<CsvArchiveOutput> {
    let mut writer = CsvArchiveWriter::new();
    for row in rows {
        writer.write_row(&row.agent_id, &row.metric, &row.labels, row.ts, row.value)?;
    }
    writer.finish().map_err(Into::into)
}

/// 上传对象与 manifest，并用 HEAD 校验两者大小。
async fn upload_object_and_manifest(
    store: &dyn ColdStore,
    keys: &rustboard_core::archive::ArchiveObjectKeys,
    data: &[u8],
    manifest_bytes: &[u8],
) -> Result<(), ArchiveError> {
    store.put(&keys.object_key, data).await?;
    let meta = store
        .head(&keys.object_key)
        .await?
        .ok_or(ArchiveError::BackendUnavailable)?;
    if meta.size != data.len() as u64 {
        return Err(ArchiveError::BackendUnavailable);
    }

    store.put(&keys.manifest_key, manifest_bytes).await?;
    let manifest_meta = store
        .head(&keys.manifest_key)
        .await?
        .ok_or(ArchiveError::BackendUnavailable)?;
    if manifest_meta.size != manifest_bytes.len() as u64 {
        return Err(ArchiveError::BackendUnavailable);
    }
    Ok(())
}

/// 归档失败时写入 `archive_objects.error` 的固定错误码（不含后端细节）。
fn archive_error_code(err: ArchiveError) -> &'static str {
    match err {
        ArchiveError::InvalidKey => "invalid_key",
        ArchiveError::InvalidManifest => "invalid_manifest",
        ArchiveError::InvalidStatus => "invalid_status",
        ArchiveError::Encode => "encode_failed",
        ArchiveError::BackendUnavailable => "backend_unavailable",
        ArchiveError::NotFound => "not_found",
    }
}

/// 「最后一个完整可归档 UTC 天」的排他结束边界。
///
/// `after_days = 7`、`now = D 12:00` 时，cutoff = `D-7 12:00`，最后可归档的是
/// `D-8` 这一天，返回 `D-7 00:00`。
fn eligible_day_end(after_days: u32, now: i64) -> i64 {
    day_start(now.saturating_sub(i64::from(after_days).saturating_mul(DAY_MS)))
}

/// 向下取整到 UTC 天边界（毫秒）。
fn day_start(ts: i64) -> i64 {
    ts.div_euclid(DAY_MS) * DAY_MS
}

/// 把 UTC 天边界转成 [`ArchiveDay`]（`1970-01-01` 起算）。
fn archive_day_for(day_start_ts: i64) -> Result<ArchiveDay> {
    let days = day_start_ts.div_euclid(DAY_MS);
    let (year, month, day) = civil_from_days(days);
    let year = u32::try_from(year).context("归档日期年份超出范围")?;
    let month = u32::try_from(month).context("归档日期月份超出范围")?;
    let day = u32::try_from(day).context("归档日期日超出范围")?;
    ArchiveDay::new(year, month, day).map_err(Into::into)
}

/// Howard Hinnant 的 civil_from_days：Unix 天数 → 公历年月日。
///
/// 不引入时间库；只处理 UTC，闰年规则包含在算法内。有效范围覆盖
/// [`ArchiveDay`] 的 `1970..=9999`。
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive_webdav::test_support::MockDav;
    use crate::archive_webdav::WebdavColdStore;
    use rustboard_common::model::{Sample, SampleBatch};
    use rustboard_core::downsample::{run_retention, STATE_DOWNSAMPLE_1M_WATERMARK};
    use rustboard_core::storage::{IngestOutcome, Storage};

    /// 固定测试时间：第 20,000 天 12:00 UTC（与真实日期无关，便于算边界）。
    const TEST_DAY_MS: i64 = 86_400_000;
    const TEST_NOW: i64 = 20_000 * TEST_DAY_MS + 12 * 3_600_000;
    /// `after_days = 1` 时最后一个完整可归档 UTC 天的起点（第 19,998 天）。
    const ARCHIVE_DAY_START: i64 = 19_998 * TEST_DAY_MS;

    fn test_cfg() -> HubConfig {
        let mut cfg = HubConfig::default();
        cfg.archive.enabled = true;
        cfg.archive.after_days = 1;
        cfg.archive.prefix = "rustboard-test".to_string();
        cfg
    }

    fn insert_raw_rows(storage: &SqliteStorage, at: i64, values: &[f64]) {
        let samples = values
            .iter()
            .map(|value| Sample::new("cpu.usage", at, *value).with_label("host", "a"))
            .collect::<Vec<_>>();
        let batch = SampleBatch {
            agent_id: "agent-1".to_string(),
            epoch: 1,
            seq: 1,
            boot_id: "boot".to_string(),
            sent_at: at,
            samples,
        };
        match storage.insert_batch(&batch).unwrap() {
            IngestOutcome::Inserted { inserted } => assert_eq!(inserted, values.len()),
            other => panic!("测试数据必须插入成功: {other:?}"),
        }
    }

    fn archive_object_for_test(key: &str) -> ArchiveObject {
        ArchiveObject {
            id: 0,
            backend: "webdav".to_string(),
            object_key: key.to_string(),
            manifest_key: format!("{key}.manifest.json"),
            from_ts: 1,
            to_ts: 2,
            rows: 1,
            bytes: 2,
            sha256: "sha".to_string(),
            status: ArchiveStatus::Pending,
            error: String::new(),
            created_at: 1,
            uploaded_at: None,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn worker_uploads_two_shards_and_advances_watermark() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + 3_600_000, &[1.0, 2.0, 3.0]);

        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2, 2)
            .await
            .unwrap();
        assert!(report.enabled);
        assert_eq!(report.days, 1);
        assert_eq!(report.objects, 2, "3 行按 2 行分片必须产生 2 个对象");
        assert_eq!(report.skipped_objects, 0);
        assert_eq!(report.rows, 3);
        assert!(report.bytes > 0);
        let expected_watermark = ARCHIVE_DAY_START + TEST_DAY_MS;
        assert_eq!(report.watermark, Some(expected_watermark));
        assert_eq!(
            storage.get_archive_state(STATE_LAST_ARCHIVED_TS).unwrap(),
            Some(expected_watermark.to_string())
        );

        let mut objects = storage.list_archive_objects(10, None).unwrap();
        objects.sort_by_key(|object| object.id);
        assert_eq!(objects.len(), 2);
        assert_eq!(
            objects.iter().map(|object| object.rows).collect::<Vec<_>>(),
            vec![2, 1]
        );
        for object in &objects {
            assert_eq!(object.backend, "webdav");
            assert_eq!(object.status, ArchiveStatus::Uploaded);
            assert!(object.uploaded_at.is_some());
            assert!(object.error.is_empty());
            assert!(
                object.object_key.starts_with("rustboard-test/"),
                "key 必须带配置 prefix: {}",
                object.object_key
            );
        }
        assert!(objects[0].object_key.ends_with("part-00001.csv.gz"));
        assert!(objects[1].object_key.ends_with("part-00002.csv.gz"));
        // 归档不删 raw：保留期受 watermark 门禁。
        assert_eq!(storage.raw_stats().unwrap().rows, 3);

        let uploaded = mock.inner.lock().unwrap().objects.clone();
        assert_eq!(uploaded.len(), 4, "2 个对象 + 2 个 manifest");

        let rows = storage
            .scan_archive_rows(ARCHIVE_DAY_START, ARCHIVE_DAY_START + TEST_DAY_MS, None, 10)
            .unwrap();
        assert_eq!(rows.len(), 3);
        let mut cursor = 0usize;
        for object in &objects {
            let end = cursor + object.rows as usize;
            let mut writer = CsvArchiveWriter::new();
            for row in &rows[cursor..end] {
                writer
                    .write_row(&row.agent_id, &row.metric, &row.labels, row.ts, row.value)
                    .unwrap();
            }
            let expected = writer.finish().unwrap();
            let actual = uploaded
                .get(&object.object_key)
                .unwrap_or_else(|| panic!("对象未上传: {}", object.object_key));
            assert_eq!(&actual[..2], &[0x1f, 0x8b], "对象必须是 gzip");
            assert_eq!(actual, &expected.data);
            assert_eq!(object.sha256, expected.sha256);
            assert_eq!(object.bytes, expected.bytes);

            let manifest_text = std::str::from_utf8(
                uploaded
                    .get(&object.manifest_key)
                    .expect("manifest 必须上传"),
            )
            .unwrap();
            let manifest = ArchiveManifest::from_json(manifest_text).unwrap();
            assert_eq!(manifest.object_key, object.object_key);
            assert_eq!(manifest.rows, object.rows);
            assert_eq!(manifest.bytes, object.bytes);
            assert_eq!(manifest.sha256, object.sha256);
            assert_eq!(manifest.from_ts, ARCHIVE_DAY_START + 3_600_000);
            assert_eq!(manifest.to_ts, ARCHIVE_DAY_START + 3_600_000);
            cursor = end;
        }
        assert_eq!(cursor, 3);

        let inner = mock.inner.lock().unwrap();
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "PUT")
                .count(),
            4
        );
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "HEAD")
                .count(),
            4
        );
    }

    #[tokio::test]
    async fn worker_failure_keeps_raw_and_does_not_advance_watermark() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + 3_600_000, &[1.0, 2.0, 3.0]);
        mock.inner.lock().unwrap().fail_put = Some(500);

        let error = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2, 2)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("冷存储后端不可用"),
            "错误必须是固定分类: {error:#}"
        );
        assert_eq!(
            storage.get_archive_state(STATE_LAST_ARCHIVED_TS).unwrap(),
            None,
            "失败不得推进水位"
        );
        assert_eq!(storage.raw_stats().unwrap().rows, 3, "失败必须保留 raw");
        let objects = storage.list_archive_objects(10, None).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].status, ArchiveStatus::Failed);
        assert_eq!(objects[0].error, "backend_unavailable");
        let last_error = storage
            .get_archive_state(STATE_LAST_ERROR)
            .unwrap()
            .unwrap_or_default();
        assert!(!last_error.is_empty(), "失败必须记录 last_error");
        assert!(mock.inner.lock().unwrap().objects.is_empty());
    }

    #[tokio::test]
    async fn worker_rerun_is_idempotent_and_skips_uploaded_objects() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + 3_600_000, &[1.0, 2.0, 3.0]);
        run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2, 2)
            .await
            .unwrap();
        let requests_after_first = mock.inner.lock().unwrap().requests.len();

        // 人工把水位回拨到当天起点，模拟重跑 / 崩溃恢复。
        storage
            .set_archive_state(
                STATE_LAST_ARCHIVED_TS,
                &ARCHIVE_DAY_START.to_string(),
                TEST_NOW,
            )
            .unwrap();
        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2, 2)
            .await
            .unwrap();
        assert_eq!(report.objects, 0, "已上传 key 不得重复上传");
        assert_eq!(report.skipped_objects, 2);
        assert_eq!(report.rows, 3);
        assert_eq!(report.bytes, 0);
        assert_eq!(
            mock.inner.lock().unwrap().requests.len(),
            requests_after_first,
            "幂等重跑不得产生新的 HTTP 请求"
        );
        assert_eq!(storage.list_archive_objects(10, None).unwrap().len(), 2);
        assert_eq!(
            storage.get_archive_state(STATE_LAST_ARCHIVED_TS).unwrap(),
            Some((ARCHIVE_DAY_START + TEST_DAY_MS).to_string())
        );
    }

    #[tokio::test]
    async fn empty_day_advances_watermark_without_objects() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        storage
            .set_archive_state(
                STATE_LAST_ARCHIVED_TS,
                &ARCHIVE_DAY_START.to_string(),
                TEST_NOW,
            )
            .unwrap();

        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2, 2)
            .await
            .unwrap();
        assert_eq!(report.days, 1);
        assert_eq!(report.objects, 0);
        assert_eq!(report.rows, 0);
        let expected_watermark = ARCHIVE_DAY_START + TEST_DAY_MS;
        assert_eq!(report.watermark, Some(expected_watermark));
        assert_eq!(
            storage.get_archive_state(STATE_LAST_ARCHIVED_TS).unwrap(),
            Some(expected_watermark.to_string())
        );
        assert!(mock.inner.lock().unwrap().requests.is_empty());
        assert!(storage.list_archive_objects(10, None).unwrap().is_empty());
    }

    #[test]
    fn retention_gate_blocks_raw_until_watermark_covers_cutoff() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = TEST_NOW;
        insert_raw_rows(&storage, now - 10 * TEST_DAY_MS, &[1.0, 2.0, 3.0]);
        storage
            .set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &now.to_string(), now)
            .unwrap();

        // 归档启用但没有水位：raw 一律不删。
        let gate = archive_gate(&storage, &cfg);
        assert_eq!(gate, ArchiveGate::Enabled { watermark: None });
        let report = run_retention(&storage, &cfg, now, gate).unwrap();
        assert_eq!(report.raw.deleted, 0);
        assert!(report.raw.blocked_by_archive);
        assert_eq!(storage.raw_stats().unwrap().rows, 3);

        // 水位覆盖 cutoff 后才允许删除。
        storage
            .set_archive_state(STATE_LAST_ARCHIVED_TS, &now.to_string(), now)
            .unwrap();
        let gate = archive_gate(&storage, &cfg);
        assert_eq!(
            gate,
            ArchiveGate::Enabled {
                watermark: Some(now)
            }
        );
        let report = run_retention(&storage, &cfg, now, gate).unwrap();
        assert_eq!(report.raw.deleted, 3);
        assert!(!report.raw.blocked_by_archive);
        assert_eq!(storage.raw_stats().unwrap().rows, 0);
    }

    #[test]
    fn retention_gate_disabled_keeps_legacy_raw_deletion() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = HubConfig::default();
        let now = TEST_NOW;
        insert_raw_rows(&storage, now - 10 * TEST_DAY_MS, &[1.0, 2.0]);
        storage
            .set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &now.to_string(), now)
            .unwrap();

        assert_eq!(archive_gate(&storage, &cfg), ArchiveGate::Disabled);
        let report = run_retention(&storage, &cfg, now, archive_gate(&storage, &cfg)).unwrap();
        assert_eq!(report.raw.deleted, 2);
        assert!(!report.raw.blocked_by_archive);
    }

    #[test]
    fn status_reports_archive_state_and_object_count() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        storage
            .set_archive_state(STATE_LAST_ARCHIVED_TS, "123", 1)
            .unwrap();
        storage.set_archive_state(STATE_LAST_RUN, "456", 1).unwrap();
        storage
            .set_archive_state(STATE_LAST_ERROR, "backend down", 1)
            .unwrap();
        storage
            .insert_archive_object(&archive_object_for_test(
                "rustboard-test/2026/10/18/part-00001.csv.gz",
            ))
            .unwrap();

        let status = status(&storage, &cfg).unwrap();
        assert!(status.enabled);
        assert_eq!(status.backend, "webdav");
        assert_eq!(status.last_archived_ts, Some(123));
        assert_eq!(status.last_run, Some(456));
        assert_eq!(status.last_error.as_deref(), Some("backend down"));
        assert_eq!(status.objects, 1);
    }

    #[test]
    fn schedule_helpers_use_utc_and_only_catch_up_after_scheduled_hour() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        let day = archive_day_for(19_723 * TEST_DAY_MS).unwrap();
        assert_eq!((day.year(), day.month(), day.day()), (2024, 1, 1));

        let base = 20_000 * TEST_DAY_MS;
        assert_eq!(
            next_run_delay(base + 2 * 3_600_000, 3),
            Duration::from_millis(3_600_000)
        );
        assert_eq!(
            next_run_delay(base + 4 * 3_600_000, 3),
            Duration::from_millis(23 * 3_600_000)
        );
        assert_eq!(
            next_run_delay(base + 3 * 3_600_000, 3),
            Duration::from_millis(TEST_DAY_MS as u64)
        );

        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        assert!(!should_catch_up(&storage, &cfg, base + 2 * 3_600_000).unwrap());
        assert!(should_catch_up(&storage, &cfg, base + 3 * 3_600_000).unwrap());
        let eligible = eligible_day_end(cfg.archive.after_days, base + 3 * 3_600_000);
        storage
            .set_archive_state(STATE_LAST_ARCHIVED_TS, &eligible.to_string(), 0)
            .unwrap();
        assert!(!should_catch_up(&storage, &cfg, base + 3 * 3_600_000).unwrap());
    }
}
