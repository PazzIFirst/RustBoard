//! M4-C1b/C2b + R1a-2：冷归档 worker、v8 ledger 与保留期门禁。
//!
//! 实现范围（方案 §4.1）：
//!
//! - [`build_store`]：按配置构造 WebDAV / S3 / SFTP 冷存储；
//! - [`spawn_archive_worker`]：仅 `archive.enabled = true` 时启动；每天 UTC
//!   `schedule_hour_utc` 执行一次，启动时若今天已过计划时间且
//!   `archive_state.last_archived_ts` 落后则立即补跑。任何错误只 WARN，
//!   任务不退出；
//! - [`run_archive_once`]：可测试的单轮归档。先重试 `pending` / `failed` 的
//!   v8 对象，再扫描 `archive_object_id IS NULL` 且早于 `eligible_end` 的 raw；
//!   **不从旧水位向后扫**，late 行自然进入下一轮；
//! - 每个逻辑对象按 `archive.max_object_bytes` 切分，key 带 `-v8` 后缀；
//!   CSV.GZ 与 manifest 在 claim 事务外生成，[`claim_archive_rows`] 只做
//!   「插入对象 + 认领行集」短事务；
//! - 失败标记 `failed` 并累计 `attempts`，保留 raw；重试按
//!   `archive_object_id` 读回同一行集，用对象 `created_at` 重建确定性 CSV /
//!   manifest，不重新扫描 raw、不纳入新 late 行；
//! - 旧 v7 对象（`ledger_version=0`）保留且不重试；`archive_ledger_pending`
//!   在完整重建成功后清除，CLI 入口见 `archive ledger status|rebuild`；
//! - 本模块不删除 raw：保留期由 `downsample::run_retention` 在归档门禁下执行
//!   （R1b 会改用 `prune_archived_samples_before` 的 uploaded join）。
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
    build_v8_object_keys, is_v8_object_key, manifest_json, parse_object_key_shard, ArchiveDay,
    ArchiveError, ArchiveManifest, ArchiveObject, ArchiveObjectKeys, ArchiveStatus,
    ArchiveStoreError, ColdStore, CsvArchiveOutput, CsvArchiveWriter, LEDGER_VERSION_V8,
    MAX_ARCHIVE_SHARD,
};
use rustboard_core::downsample::ArchiveGate;
use rustboard_core::storage::sqlite::ArchiveRawRow;
use rustboard_core::storage::StorageHandle;
use serde::Serialize;

use crate::archive_sftp::SftpColdStore;
use crate::archive_webdav::WebdavColdStore;

/// `archive_state` 键：已成功归档到的排他时间边界（Unix 毫秒）。
pub(crate) const STATE_LAST_ARCHIVED_TS: &str = "last_archived_ts";
/// `archive_state` 键：最近一次归档尝试时间（Unix 毫秒）。
pub(crate) const STATE_LAST_RUN: &str = "last_run";
/// `archive_state` 键：最近一次归档失败原因（成功后清空）。
pub(crate) const STATE_LAST_ERROR: &str = "last_error";
/// `archive_state` 键：v7→v8 归档 ledger 重建待办标记。
pub(crate) const STATE_ARCHIVE_LEDGER_PENDING: &str = "archive_ledger_pending";

/// ledger pending 写入值：`1` 表示仍需重建，`0` 表示已完成。
const LEDGER_PENDING_ON: &str = "1";
const LEDGER_PENDING_OFF: &str = "0";

/// 一天 / 一小时的毫秒数（UTC，无夏令时）。
const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

/// 单片最大行数。方案允许 100,000 行，这里按 50,000 行保守分片，降低
/// 单对象内存峰值与压缩后超过 `max_object_bytes` 的概率。
const MAX_SHARD_ROWS: usize = 50_000;

/// 每次列出待重试 v8 对象的条数。
const RETRY_BATCH_SIZE: usize = 100;

/// claim / key 冲突的最大重试次数；超过后本轮失败，由下一轮继续。
const MAX_CLAIM_RETRIES: usize = 5;

/// 归档存储调用的来源：`Arc` 直接复用，`&StorageHandle` 克隆底层句柄。
///
/// 目的只是让 async 函数能拿到 `'static` 的存储句柄交给 `spawn_blocking`，
/// 同时保持既有测试 / CLI 传 `&StorageHandle` 的调用方式不变。
pub(crate) trait StorageSource {
    fn into_storage_handle(self) -> Arc<StorageHandle>;
}

impl StorageSource for Arc<StorageHandle> {
    fn into_storage_handle(self) -> Arc<StorageHandle> {
        self
    }
}

impl StorageSource for &Arc<StorageHandle> {
    fn into_storage_handle(self) -> Arc<StorageHandle> {
        self.clone()
    }
}

impl StorageSource for &StorageHandle {
    fn into_storage_handle(self) -> Arc<StorageHandle> {
        Arc::new(self.clone())
    }
}

/// 在 blocking 线程执行同步存储调用（PG 同步驱动在 tokio worker 上会 panic）。
///
/// 闭包内完成取连接 / 查询 / 事务；不把任何连接 guard 带回 async 侧。
async fn storage_blocking<T, F>(storage: Arc<StorageHandle>, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&StorageHandle) -> Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(move || f(&storage)).await {
        Ok(result) => result,
        Err(err) => Err(anyhow::Error::new(err).context("执行归档存储后台任务失败")),
    }
}

/// `archive_state.last_error` 允许透传的固定中文文案（历史版本可能直接存过
/// `ArchiveError::Display`）。未知内容一律掩码为 `archive_error`。
const SAFE_LAST_ERROR_TEXTS: [&str; 7] = [
    "归档未启用（archive.enabled = false）",
    "归档对象 key 非法",
    "归档 manifest 非法",
    "归档对象状态非法",
    "归档数据编码失败",
    "冷存储后端不可用",
    "归档对象不存在",
];

/// `last_error` 允许透传的固定错误码（精确集合，不接受任意 `*_failed`）。
const SAFE_LAST_ERROR_CODES: [&str; 1] = [LAST_ERROR_RUN_FAILED];

/// 新失败写入的固定码：不含后端 URL / 凭据 / 响应正文。
const LAST_ERROR_RUN_FAILED: &str = "archive_run_failed";

/// 未知 / 不安全状态的统一掩码。
const LAST_ERROR_MASKED: &str = "archive_error";

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
    /// 固定错误码 / 固定中文，或掩码后的 `archive_error`；不含 URL / 凭据。
    pub last_error: Option<String>,
    /// `archive_objects` 总行数（不区分状态）。
    pub objects: i64,
}

/// `archive ledger status` 的固定结构。
///
/// 只暴露重建待办与水位 / 对象数，不包含后端 URL、凭据或对象 key。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct ArchiveLedgerStatusOutput {
    /// `archive_ledger_pending=1`：v8 ledger 重建尚未完成，retention 必须阻塞。
    pub pending: bool,
    /// 旧 v7 归档水位；仅用于展示，不再单独证明可删。
    pub last_archived_ts: Option<i64>,
    /// `archive_objects` 总行数（含 v7 旧对象）。
    pub objects: i64,
}

/// 构建冷存储后端。
///
/// - WebDAV / S3 / SFTP 都只校验配置并构造客户端，**不发起网络请求**；
/// - SFTP 构造时会校验主机密钥指纹格式与私钥文件权限，但连通性 / 认证由
///   [`ColdStore::test`] 或 `archive test` 显式触发；
/// - 任何构造错误都不包含后端 URL / 凭据 / 远端路径（由各后端自身保证）。
pub(crate) fn build_store(cfg: &ArchiveConfig) -> Result<Arc<dyn ColdStore>> {
    match cfg.backend {
        ArchiveBackend::Webdav => {
            let webdav = cfg.webdav.as_ref().context("缺少 [archive.webdav] 配置")?;
            let store = WebdavColdStore::new(webdav)?;
            Ok(Arc::new(store))
        }
        ArchiveBackend::S3 => {
            let s3 = cfg.s3.as_ref().context("缺少 [archive.s3] 配置")?;
            let store = crate::archive_s3::build_s3_store(s3)?;
            Ok(Arc::new(store))
        }
        ArchiveBackend::Sftp => {
            let sftp = cfg.sftp.as_ref().context("缺少 [archive.sftp] 配置")?;
            let store = SftpColdStore::new(sftp)?;
            Ok(Arc::new(store))
        }
    }
}

/// 从对象 key 重新构造下载文件名：`rustboard-<yyyyMMdd>-part-NNNNN.csv.gz`。
///
/// 只接受标准 key 形状（`<prefix>/<yyyy>/<mm>/<dd>/part-NNNNN[-v8].csv.gz`）；
/// 文件名完全由重新校验过的数字段拼接，**绝不**直接截取或回显数据库里的原始
/// key，因此不存在 header / 路径注入。无法识别时返回 `None`，由 API 层映射为
/// 固定的 502。
pub(crate) fn download_filename(object_key: &str) -> Option<String> {
    let base = object_key.strip_suffix(".csv.gz")?;
    let mut segments = base.rsplit('/');
    let shard = segments.next()?;
    let day = segments.next()?;
    let month = segments.next()?;
    let year = segments.next()?;
    let prefix = segments.next()?;
    // prefix 是单个路径段（配置校验禁止 `/`）；多段说明不是标准 key。
    // 同时复用配置 prefix 的字符白名单，拒绝 `..` / 绝对路径伪装。
    if prefix.is_empty()
        || prefix.len() > rustboard_core::archive::MAX_ARCHIVE_PREFIX_BYTES
        || prefix.contains("..")
        || !prefix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || segments.next().is_some()
    {
        return None;
    }
    if year.len() != 4
        || month.len() != 2
        || day.len() != 2
        || !year
            .bytes()
            .chain(month.bytes())
            .chain(day.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let (shard, v8_suffix) = match shard.strip_suffix(rustboard_core::archive::V8_OBJECT_KEY_SUFFIX)
    {
        Some(shard) => (shard, rustboard_core::archive::V8_OBJECT_KEY_SUFFIX),
        None => (shard, ""),
    };
    let shard_digits = shard.strip_prefix("part-")?;
    if shard_digits.len() != 5 || !shard_digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let shard_number: u32 = shard_digits.parse().ok()?;
    if shard_number == 0 {
        return None;
    }
    let (year_value, month_value, day_value) = (
        year.parse::<u32>().ok()?,
        month.parse::<u32>().ok()?,
        day.parse::<u32>().ok()?,
    );
    if !(1970..=9999).contains(&year_value)
        || !(1..=12).contains(&month_value)
        || !(1..=31).contains(&day_value)
    {
        return None;
    }
    Some(format!(
        "rustboard-{year}{month}{day}-part-{shard_digits}{v8_suffix}.csv.gz"
    ))
}

/// 读取归档水位；key 不存在 / 空串视为 `None`，非法整数返回错误。
fn read_archive_i64(storage: &StorageHandle, key: &str) -> Result<Option<i64>> {
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
pub(crate) fn archive_gate(storage: &StorageHandle, cfg: &HubConfig) -> ArchiveGate {
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
///
/// `last_error` 可能是旧版本写入的原始 `{err:#}`，读取时再做一次白名单 / 掩码，
/// 防止历史库里的 URL、凭据或路径经由 API / 面板回显。
pub(crate) fn status(storage: &StorageHandle, cfg: &HubConfig) -> Result<ArchiveStatusOutput> {
    let last_error = storage
        .get_archive_state(STATE_LAST_ERROR)?
        .map(|value| sanitize_last_error(&value))
        .filter(|value| !value.is_empty());
    Ok(ArchiveStatusOutput {
        enabled: cfg.archive.enabled,
        backend: cfg.archive.backend.as_str().to_string(),
        last_archived_ts: read_archive_i64(storage, STATE_LAST_ARCHIVED_TS)?,
        last_run: read_archive_i64(storage, STATE_LAST_RUN)?,
        last_error,
        objects: storage.count_archive_objects()?,
    })
}

/// 读取 `archive ledger status`：pending 标记、旧水位与对象总数。
///
/// 只读数据库；`archive.enabled = false` 时也可用于查看迁移留下的待办标记。
pub(crate) fn ledger_status(storage: &StorageHandle) -> Result<ArchiveLedgerStatusOutput> {
    let pending = storage
        .get_archive_state(STATE_ARCHIVE_LEDGER_PENDING)?
        .is_some_and(|value| is_ledger_pending_value(&value));
    Ok(ArchiveLedgerStatusOutput {
        pending,
        last_archived_ts: read_archive_i64(storage, STATE_LAST_ARCHIVED_TS)?,
        objects: storage.count_archive_objects()?,
    })
}

/// `1` / `true` / `yes` 都视为待重建；其它值（含 `0`、空串）视为已完成。
fn is_ledger_pending_value(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "yes")
}

/// 异步读取 ledger pending 标记（worker 在 blocking 线程访问数据库）。
async fn read_ledger_pending(storage: &Arc<StorageHandle>) -> Result<bool> {
    let read_storage = storage.clone();
    let raw = storage_blocking(read_storage, |storage| {
        storage.get_archive_state(STATE_ARCHIVE_LEDGER_PENDING)
    })
    .await?;
    Ok(raw.is_some_and(|value| is_ledger_pending_value(&value)))
}

/// 异步写入 ledger pending 标记；`false` 写 `0` 而不是删行，便于运维看到已清理。
async fn set_ledger_pending(storage: &Arc<StorageHandle>, pending: bool, now: i64) -> Result<()> {
    let value = if pending {
        LEDGER_PENDING_ON
    } else {
        LEDGER_PENDING_OFF
    }
    .to_string();
    let write_storage = storage.clone();
    storage_blocking(write_storage, move |storage| {
        storage.set_archive_state(STATE_ARCHIVE_LEDGER_PENDING, &value, now)
    })
    .await
}

/// `archive_state.last_error` 的展示脱敏。
///
/// 只允许固定中文文案或 [`SAFE_LAST_ERROR_CODES`] 中的精确固定码；其余内容
/// （URL、凭据、路径、超长错误或任意旧版本 `{err:#}`）一律返回
/// `archive_error`，不做截断展示。不接受任意 `*_failed` 形式。
fn sanitize_last_error(raw: &str) -> String {
    let value = raw.trim();
    if value.is_empty() {
        return String::new();
    }
    if SAFE_LAST_ERROR_TEXTS.contains(&value) || SAFE_LAST_ERROR_CODES.contains(&value) {
        value.to_string()
    } else {
        LAST_ERROR_MASKED.to_string()
    }
}

/// 启动归档 worker。
///
/// - `archive.enabled = false`：只记 INFO，不启动；
/// - 后端配置 / 构造失败：WARN 后不启动（不能让 hub 启动失败）；
/// - 启动补跑：今天已过 `schedule_hour_utc` 且水位落后于「最新可归档天结束」
///   时立即执行一轮，之后按每天计划时间运行；
/// - 每轮错误只 WARN，任务不退出；不修改 raw，保留期仍受 [`archive_gate`] 门禁。
pub(crate) fn spawn_archive_worker(storage: Arc<StorageHandle>, cfg: HubConfig) {
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
        let check_storage = storage.clone();
        let check_cfg = cfg.clone();
        match storage_blocking(check_storage, move |storage| {
            should_catch_up(storage, &check_cfg, startup_now)
        })
        .await
        {
            Ok(true) => {
                tracing::info!("归档 worker：今天已过计划时间且水位落后，立即补跑");
                if let Err(err) =
                    run_archive_once(storage.clone(), &cfg, store.as_ref(), startup_now).await
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
            if let Err(err) =
                run_archive_once(storage.clone(), &cfg, store.as_ref(), now_ms()).await
            {
                tracing::warn!(error = %err, "归档任务失败，保留水位等待下一轮重试");
            }
        }
    });
}

/// 启动补跑判定：今天已过计划时间，且水位早于最新可归档天的结束边界。
fn should_catch_up(storage: &StorageHandle, cfg: &HubConfig, now: i64) -> Result<bool> {
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
/// 无论成功失败都会写 `last_run`；失败时只把固定码 `archive_run_failed`
/// 写入 `last_error`（成功清空），不存后端错误原文。
/// 返回的 [`ArchiveRunReport`] 只用于日志 / CLI，不包含 secret。
///
/// 所有存储访问在 [`storage_blocking`] 内执行；PG 的同步驱动不能直接跑在
/// tokio worker 上。
pub(crate) async fn run_archive_once(
    storage: impl StorageSource,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    now: i64,
) -> Result<ArchiveRunReport> {
    run_archive_once_with_limits(storage, cfg, store, now, MAX_SHARD_ROWS).await
}

/// `archive ledger rebuild`：先标记 pending，再立即跑一轮 worker。
///
/// 先置 `archive_ledger_pending=1` 再执行：手动重建中途崩溃 / 失败时标记仍
/// 保留，R1b 接入后的 retention 会继续 fail-closed；全部成功由 worker 清除。
pub(crate) async fn rebuild_ledger(
    storage: impl StorageSource,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    now: i64,
) -> Result<ArchiveRunReport> {
    if !cfg.archive.enabled {
        bail!("归档未启用（archive.enabled = false）");
    }
    let storage = storage.into_storage_handle();
    set_ledger_pending(&storage, true, now).await?;
    run_archive_once(storage, cfg, store, now).await
}

/// 带可调分片行数的实现；测试用小分片覆盖多分片路径。
async fn run_archive_once_with_limits(
    storage: impl StorageSource,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    now: i64,
    max_shard_rows: usize,
) -> Result<ArchiveRunReport> {
    let storage = storage.into_storage_handle();
    let result = run_archive_cycle(storage.clone(), cfg, store, now, max_shard_rows.max(1)).await;
    record_run_state(storage, now, &result).await;
    result
}

/// 访问数据库失败时只 WARN，不覆盖调用方真正关心的归档错误。
async fn record_run_state(
    storage: Arc<StorageHandle>,
    now: i64,
    result: &Result<ArchiveRunReport>,
) {
    // 只写固定码：后端错误即使意外带出 URL / 凭据，也不会进入状态表。
    let last_error = match result {
        Ok(_) => String::new(),
        Err(_) => LAST_ERROR_RUN_FAILED.to_string(),
    };
    let run_storage = storage.clone();
    if let Err(err) = storage_blocking(run_storage, move |storage| {
        storage.set_archive_state(STATE_LAST_RUN, &now.to_string(), now)
    })
    .await
    {
        tracing::warn!(error = %err, "写入归档任务 last_run 失败");
    }
    if let Err(err) = storage_blocking(storage, move |storage| {
        storage.set_archive_state(STATE_LAST_ERROR, &last_error, now)
    })
    .await
    {
        tracing::warn!(error = %err, "写入归档任务 last_error 失败");
    }
}

/// 一轮归档的主体。
///
/// 顺序固定为：
/// 1. 先重试所有 `pending` / `failed` 的 **v8** 对象：按 `archive_object_id`
///    读回同一行集、用对象 `created_at` 重建确定性 CSV/manifest，不重新扫描
///    raw（崩溃恢复与失败重试）；
/// 2. 再扫描 `archive_object_id IS NULL` 且 `ts < eligible_end` 的 raw。**不**
///    从旧水位向后扫：v7 水位可能早于真实未归档行，late 行也会落在水位之前；
/// 3. 全部成功后才推进 `last_archived_ts`（仅 status/UI，不再单独证明可删），
///    并在 ledger pending 时清除标记。
async fn run_archive_cycle(
    storage: Arc<StorageHandle>,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    now: i64,
    max_shard_rows: usize,
) -> Result<ArchiveRunReport> {
    if !cfg.archive.enabled {
        bail!("归档未启用（archive.enabled = false）");
    }

    let watermark_storage = storage.clone();
    let watermark = storage_blocking(watermark_storage, |storage| {
        read_archive_i64(storage, STATE_LAST_ARCHIVED_TS)
    })
    .await?;
    let mut report = ArchiveRunReport {
        enabled: true,
        watermark,
        ..ArchiveRunReport::default()
    };
    let eligible_end = eligible_day_end(cfg.archive.after_days, now);
    let ledger_pending = read_ledger_pending(&storage).await?;
    if ledger_pending {
        tracing::info!("归档 worker：archive_ledger_pending=1，优先重建仍存在的 v8 ledger");
    }

    // 1. 崩溃恢复 / 上次失败：对象已 claim，行集固定；绝不重新扫描 raw。
    retry_pending_objects(&storage, store, now, &mut report).await?;

    // 2. 扫描未认领行：每轮重新找最旧的未认领行，late 行自然进入下一轮。
    loop {
        let oldest_storage = storage.clone();
        let oldest = storage_blocking(oldest_storage, move |storage| {
            storage.list_unclaimed_archive_rows(0, eligible_end, 1)
        })
        .await?;
        let Some(first) = oldest.into_iter().next() else {
            break;
        };
        let day_start_ts = day_start(first.ts);
        let day_end = day_start_ts
            .checked_add(DAY_MS)
            .context("归档日期范围溢出")?;
        archive_day(
            &storage,
            cfg,
            store,
            day_start_ts,
            day_end,
            now,
            max_shard_rows,
            &mut report,
        )
        .await?;
        report.days += 1;
    }

    // 3. 全部成功：推进 status/UI 水位（取 max，绝不回拨）。
    let new_watermark = watermark.map_or(eligible_end, |current| current.max(eligible_end));
    let watermark_storage = storage.clone();
    let watermark_value = new_watermark.to_string();
    storage_blocking(watermark_storage, move |storage| {
        storage.set_archive_state(STATE_LAST_ARCHIVED_TS, &watermark_value, now)
    })
    .await?;
    report.watermark = Some(new_watermark);

    // ledger 重建只有在本轮完整成功（没有 unclaimed 残留、没有重试失败）后
    // 才清除；失败路径在 return 前不会走到这里。
    if ledger_pending {
        set_ledger_pending(&storage, false, now).await?;
        tracing::info!("归档 worker：v8 ledger 重建完成，已清除 archive_ledger_pending");
    }

    Ok(report)
}

/// 处理一个 UTC 天内所有未认领 raw；每批最多 `max_shard_rows` 行。
#[allow(clippy::too_many_arguments)]
async fn archive_day(
    storage: &Arc<StorageHandle>,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    day_start_ts: i64,
    day_end: i64,
    now: i64,
    max_shard_rows: usize,
    report: &mut ArchiveRunReport,
) -> Result<()> {
    let day = archive_day_for(day_start_ts)?;
    let mut next_shard = next_shard_for_day(storage, day_start_ts, day_end).await?;
    let mut conflicts = 0usize;

    loop {
        let scan_storage = storage.clone();
        let rows = storage_blocking(scan_storage, move |storage| {
            storage.list_unclaimed_archive_rows(day_start_ts, day_end, max_shard_rows)
        })
        .await?;
        if rows.is_empty() {
            return Ok(());
        }

        match archive_row_chunks(
            storage,
            cfg,
            store,
            day,
            &mut next_shard,
            &rows,
            now,
            report,
        )
        .await?
        {
            ClaimResult::Done => {}
            ClaimResult::Conflict => {
                conflicts += 1;
                if conflicts > MAX_CLAIM_RETRIES {
                    bail!("归档 claim 连续冲突，超过最大重试次数");
                }
                // 行集被并发 worker 抢走：重新找下一个可用分片号再扫一遍。
                next_shard = next_shard_for_day(storage, day_start_ts, day_end).await?;
            }
        }
    }
}

/// 计算该 UTC 天已用过的最大分片号 + 1（同时覆盖 v7 与 v8 对象）。
///
/// 旧 v7 对象保留自己的 key；v8 对象带 `-v8` 后缀。这里把两种 key 的分片号
/// 都算进去，只影响编号连续性，不会复用旧 key。
async fn next_shard_for_day(
    storage: &Arc<StorageHandle>,
    day_start_ts: i64,
    day_end: i64,
) -> Result<u32> {
    let list_storage = storage.clone();
    let objects = storage_blocking(list_storage, move |storage| {
        storage.list_archive_objects_in_range(day_start_ts, day_end.saturating_sub(1))
    })
    .await?;
    let max_used = objects
        .iter()
        .filter_map(|object| parse_object_key_shard(&object.object_key))
        .max()
        .unwrap_or(0);
    let next = max_used.checked_add(1).context("归档分片编号溢出")?;
    if next > MAX_ARCHIVE_SHARD {
        bail!("归档分片编号超过上限 {MAX_ARCHIVE_SHARD}");
    }
    Ok(next)
}

/// 一次 claim 的结果：`Conflict` 表示行集已被并发 worker 抢走，需要重扫。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimResult {
    Done,
    Conflict,
}

/// 把一批未认领行按 `max_object_bytes` 切成逻辑对象，逐个 claim + 上传。
///
/// CSV.GZ 与 manifest 都在 claim 事务外生成；claim 只插入对象（bytes/sha 先
/// 占位）并原子认领行集，随后用 `update_archive_object_metadata` 补真实摘要。
/// 若任一 chunk claim 时发现行集已被并发 worker 抢走，返回 [`ClaimResult::Conflict`]
/// 由上层重新扫描，不会部分认领。
#[allow(clippy::too_many_arguments)]
async fn archive_row_chunks(
    storage: &Arc<StorageHandle>,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    day: ArchiveDay,
    next_shard: &mut u32,
    rows: &[ArchiveRawRow],
    now: i64,
    report: &mut ArchiveRunReport,
) -> Result<ClaimResult> {
    let mut pending: VecDeque<&[ArchiveRawRow]> = VecDeque::new();
    pending.push_back(rows);

    while let Some(chunk) = pending.pop_front() {
        let output = build_csv(chunk)?;
        if output.bytes > cfg.archive.max_object_bytes && chunk.len() > 1 {
            let mid = chunk.len() / 2;
            pending.push_front(&chunk[mid..]);
            pending.push_front(&chunk[..mid]);
            continue;
        }
        match claim_and_upload_chunk(
            storage, cfg, store, day, next_shard, chunk, &output, now, report,
        )
        .await?
        {
            ClaimResult::Done => {}
            ClaimResult::Conflict => return Ok(ClaimResult::Conflict),
        }
    }
    Ok(ClaimResult::Done)
}

/// 认领并上传一个逻辑对象。
///
/// key 固定带 `-v8` 后缀；若 key 已被并发 worker 占用则换下一个分片号重试。
/// 对象 `rows/from_ts/to_ts` 来自行集，`created_at=now` 固定，保证失败重试
/// 能重建字节级一致的 CSV 与 manifest。
#[allow(clippy::too_many_arguments)]
async fn claim_and_upload_chunk(
    storage: &Arc<StorageHandle>,
    cfg: &HubConfig,
    store: &dyn ColdStore,
    day: ArchiveDay,
    next_shard: &mut u32,
    chunk: &[ArchiveRawRow],
    output: &CsvArchiveOutput,
    now: i64,
    report: &mut ArchiveRunReport,
) -> Result<ClaimResult> {
    let from_ts = chunk.iter().map(|row| row.ts).min().unwrap_or(now);
    let to_ts = chunk.iter().map(|row| row.ts).max().unwrap_or(now);

    for _ in 0..MAX_CLAIM_RETRIES {
        let shard = format!("part-{:05}", *next_shard);
        *next_shard = next_shard.checked_add(1).context("归档分片编号溢出")?;
        let keys = build_v8_object_keys(&cfg.archive.prefix, day, &shard)?;

        let object = ArchiveObject {
            id: 0,
            backend: cfg.archive.backend.as_str().to_string(),
            object_key: keys.object_key.clone(),
            manifest_key: keys.manifest_key.clone(),
            from_ts,
            to_ts,
            rows: output.rows,
            // claim 是短事务：真实 bytes/sha 在事务外生成后单独补写。
            bytes: 0,
            sha256: String::new(),
            status: ArchiveStatus::Pending,
            error: String::new(),
            created_at: now,
            uploaded_at: None,
            deleted_at: None,
            ledger_version: LEDGER_VERSION_V8,
            attempts: 0,
        };

        let claim_storage = storage.clone();
        let claim_object = object.clone();
        let claim_rows = chunk.to_vec();
        let claim_result = storage_blocking(claim_storage, move |storage| {
            storage.claim_archive_rows(&claim_object, &claim_rows)
        })
        .await;

        let id = match claim_result {
            Ok(id) => id,
            // 并发 worker 已占用同一 key：换下一个分片号重试。
            Err(err) if is_store_error(&err, ArchiveStoreError::ObjectExists) => continue,
            // 行集被抢走：整批回到上层重新扫描，绝不部分认领。
            Err(err) if is_store_error(&err, ArchiveStoreError::ClaimConflict) => {
                return Ok(ClaimResult::Conflict);
            }
            Err(err) => return Err(err),
        };

        // claim 成功后补真实 bytes/sha；失败时对象保留 pending，下一轮按行集重建。
        let metadata_storage = storage.clone();
        let metadata_bytes = output.bytes;
        let metadata_sha = output.sha256.clone();
        storage_blocking(metadata_storage, move |storage| {
            storage.update_archive_object_metadata(id, metadata_bytes, &metadata_sha)
        })
        .await?;

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
        if let Err(err) =
            upload_object_and_manifest(store, &keys, &output.data, &manifest_bytes).await
        {
            record_failure(storage, id, archive_error_code(err)).await;
            return Err(err.into());
        }

        let update_storage = storage.clone();
        storage_blocking(update_storage, move |storage| {
            storage.update_archive_object_status(id, ArchiveStatus::Uploaded, "", Some(now), None)
        })
        .await?;
        report.objects += 1;
        report.rows += output.rows;
        report.bytes += output.bytes;
        return Ok(ClaimResult::Done);
    }

    bail!("归档对象 key 连续冲突，超过最大重试次数")
}

/// 先重试所有 `pending` / `failed` 的 v8 对象（按 id 升序分页）。
///
/// 重试只按 `archive_object_id` 读回原行集，不重新扫描 raw、不纳入新 late 行；
/// manifest 使用对象 `created_at`，保证与首次生成完全一致。
async fn retry_pending_objects(
    storage: &Arc<StorageHandle>,
    store: &dyn ColdStore,
    now: i64,
    report: &mut ArchiveRunReport,
) -> Result<()> {
    let mut after_id: Option<i64> = None;
    loop {
        let page_storage = storage.clone();
        let page = storage_blocking(page_storage, move |storage| {
            storage.list_retryable_archive_objects(RETRY_BATCH_SIZE, after_id)
        })
        .await?;
        if page.is_empty() {
            return Ok(());
        }

        for object in page {
            after_id = Some(object.id);
            // 旧 v7 对象没有 claim 行集，绝不能按行重建，也不改它的记录。
            if object.ledger_version != LEDGER_VERSION_V8 {
                tracing::warn!(
                    object_id = object.id,
                    ledger_version = object.ledger_version,
                    "归档重试列表出现非 v8 对象，跳过且保持原记录"
                );
                continue;
            }
            // retry 前校验 key 形状：只允许标准 `part-NNNNN-v8` 对象 / manifest。
            if !is_v8_object_key(&object.object_key) || !is_v8_object_key(&object.manifest_key) {
                record_failure(storage, object.id, "invalid_key").await;
                tracing::warn!(
                    object_id = object.id,
                    "归档重试对象 key 不是合法 v8 形状，标记 failed 后跳过"
                );
                continue;
            }
            let rows_storage = storage.clone();
            let object_id = object.id;
            let rows = storage_blocking(rows_storage, move |storage| {
                storage.archive_rows_for_object(object_id)
            })
            .await?;
            if rows.is_empty() || rows.len() as u64 != object.rows {
                record_failure(storage, object.id, "rows_missing").await;
                tracing::warn!(
                    object_id = object.id,
                    expected_rows = object.rows,
                    actual_rows = rows.len(),
                    "归档对象 claim 行集缺失，标记 failed 后跳过，避免阻塞其它对象"
                );
                continue;
            }

            let output = build_csv(&rows)?;
            let metadata_storage = storage.clone();
            let metadata_bytes = output.bytes;
            let metadata_sha = output.sha256.clone();
            let metadata_object_id = object.id;
            storage_blocking(metadata_storage, move |storage| {
                storage.update_archive_object_metadata(
                    metadata_object_id,
                    metadata_bytes,
                    &metadata_sha,
                )
            })
            .await?;

            let keys = ArchiveObjectKeys {
                object_key: object.object_key.clone(),
                manifest_key: object.manifest_key.clone(),
            };
            let manifest = ArchiveManifest::new(
                keys.object_key.clone(),
                object.from_ts,
                object.to_ts,
                output.rows,
                output.bytes,
                output.sha256.clone(),
                object.created_at,
            );
            let manifest_bytes = manifest_json(&manifest)?.into_bytes();
            if let Err(err) =
                upload_object_and_manifest(store, &keys, &output.data, &manifest_bytes).await
            {
                record_failure(storage, object.id, archive_error_code(err)).await;
                return Err(err.into());
            }

            let update_storage = storage.clone();
            let uploaded_id = object.id;
            storage_blocking(update_storage, move |storage| {
                storage.update_archive_object_status(
                    uploaded_id,
                    ArchiveStatus::Uploaded,
                    "",
                    Some(now),
                    None,
                )
            })
            .await?;
            report.objects += 1;
            report.rows += output.rows;
            report.bytes += output.bytes;
        }
    }
}

/// 记录失败状态与 `attempts+1`；数据库错误只 WARN，不掩盖上传错误。
async fn record_failure(storage: &Arc<StorageHandle>, id: i64, error_code: &'static str) {
    let fail_storage = storage.clone();
    if let Err(db_err) = storage_blocking(fail_storage, move |storage| {
        storage.record_archive_object_failure(id, error_code)
    })
    .await
    {
        tracing::warn!(error = %db_err, "标记归档对象失败状态时数据库错误");
    }
}

/// 判断 anyhow 错误链中是否包含指定领域错误（PG 实现会给错误加 context）。
fn is_store_error(err: &anyhow::Error, expected: ArchiveStoreError) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<ArchiveStoreError>()
            .is_some_and(|actual| *actual == expected)
    })
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
    use rustboard_core::storage::IngestOutcome;

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

    fn insert_raw_rows(storage: &StorageHandle, at: i64, values: &[f64]) {
        insert_raw_rows_with_seq(storage, at, values, 1);
    }

    fn insert_raw_rows_with_seq(storage: &StorageHandle, at: i64, values: &[f64], seq: u64) {
        let samples = values
            .iter()
            .map(|value| Sample::new("cpu.usage", at, *value).with_label("host", "a"))
            .collect::<Vec<_>>();
        let batch = SampleBatch {
            agent_id: "agent-1".to_string(),
            epoch: 1,
            seq,
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
            ledger_version: 0,
            attempts: 0,
        }
    }

    fn insert_unique_rows(storage: &StorageHandle, at: i64, count: usize, seq: u64) {
        let samples = (0..count)
            .map(|index| {
                Sample::new("cpu.usage", at + index as i64, index as f64)
                    .with_label("host", format!("host-{index:04}-unique-label-padding"))
            })
            .collect::<Vec<_>>();
        let batch = SampleBatch {
            agent_id: "agent-1".to_string(),
            epoch: 1,
            seq,
            boot_id: "boot".to_string(),
            sent_at: at,
            samples,
        };
        match storage.insert_batch(&batch).unwrap() {
            IngestOutcome::Inserted { inserted } => assert_eq!(inserted, count),
            other => panic!("测试数据必须插入成功: {other:?}"),
        }
    }

    fn day_start_ts() -> i64 {
        ARCHIVE_DAY_START
    }

    fn day_end_ts() -> i64 {
        ARCHIVE_DAY_START + TEST_DAY_MS
    }

    fn unclaimed_rows(storage: &StorageHandle, limit: usize) -> Vec<ArchiveRawRow> {
        storage
            .list_unclaimed_archive_rows(day_start_ts(), day_end_ts(), limit)
            .unwrap()
    }

    /// 模拟「claim 事务已提交、上传尚未开始」的崩溃现场。
    fn claim_pending_for_test(
        storage: &StorageHandle,
        rows: &[ArchiveRawRow],
        shard: &str,
        created_at: i64,
    ) -> i64 {
        let day = archive_day_for(day_start_ts()).unwrap();
        let keys = build_v8_object_keys("rustboard-test", day, shard).unwrap();
        let object = ArchiveObject {
            id: 0,
            backend: "webdav".to_string(),
            object_key: keys.object_key,
            manifest_key: keys.manifest_key,
            from_ts: rows.iter().map(|row| row.ts).min().unwrap(),
            to_ts: rows.iter().map(|row| row.ts).max().unwrap(),
            rows: rows.len() as u64,
            bytes: 0,
            sha256: String::new(),
            status: ArchiveStatus::Pending,
            error: String::new(),
            created_at,
            uploaded_at: None,
            deleted_at: None,
            ledger_version: LEDGER_VERSION_V8,
            attempts: 0,
        };
        storage.claim_archive_rows(&object, rows).unwrap()
    }

    fn csv_for(rows: &[ArchiveRawRow]) -> CsvArchiveOutput {
        build_csv(rows).unwrap()
    }

    #[tokio::test]
    async fn worker_uploads_two_shards_and_advances_watermark() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + 3_600_000, &[1.0, 2.0, 3.0]);

        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2)
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
        assert!(objects[0].object_key.ends_with("part-00001-v8.csv.gz"));
        assert!(objects[1].object_key.ends_with("part-00002-v8.csv.gz"));
        assert!(objects[0]
            .manifest_key
            .ends_with("part-00001-v8.manifest.json"));
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
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + 3_600_000, &[1.0, 2.0, 3.0]);
        mock.inner.lock().unwrap().fail_put = Some(500);

        let error = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2)
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
        assert_eq!(
            last_error, LAST_ERROR_RUN_FAILED,
            "失败只记录固定码，不写后端错误原文"
        );
        assert!(mock.inner.lock().unwrap().objects.is_empty());
    }

    #[tokio::test]
    async fn attempts_accumulate_on_repeated_failures_and_retry_keeps_rows() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + 3_600_000, &[1.0, 2.0]);
        mock.inner.lock().unwrap().fail_put = Some(500);

        for expected_attempts in 1..=2 {
            run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
                .await
                .unwrap_err();
            let objects = storage.list_archive_objects(10, None).unwrap();
            assert_eq!(objects.len(), 1);
            assert_eq!(objects[0].status, ArchiveStatus::Failed);
            assert_eq!(objects[0].attempts, expected_attempts);
            assert_eq!(objects[0].error, "backend_unavailable");
            assert_eq!(objects[0].rows, 2);
            assert_eq!(storage.raw_stats().unwrap().rows, 2, "失败不得删除 raw");
        }

        mock.inner.lock().unwrap().fail_put = None;
        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap();
        assert_eq!(report.objects, 1);
        let objects = storage.list_archive_objects(10, None).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].status, ArchiveStatus::Uploaded);
        assert_eq!(objects[0].attempts, 2, "成功后保留失败次数作为历史");
        assert_eq!(objects[0].rows, 2);
    }

    #[tokio::test]
    async fn late_row_after_upload_creates_new_v8_object_without_touching_a() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows_with_seq(&storage, ARCHIVE_DAY_START + HOUR_MS, &[1.0, 2.0, 3.0], 1);

        let first = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap();
        assert_eq!(first.objects, 1);
        let first_object = storage
            .list_archive_objects(10, None)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(first_object.rows, 3);
        let first_key = first_object.object_key.clone();
        let first_sha = first_object.sha256.clone();
        let first_bytes = first_object.bytes;
        let first_upload = mock.inner.lock().unwrap().objects.clone();

        // 迟到行：ts 仍早于新水位，但 archive_object_id 为 NULL，必须进入下一轮。
        insert_raw_rows_with_seq(&storage, ARCHIVE_DAY_START + 2 * HOUR_MS, &[4.0, 5.0], 2);
        let second = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap();
        assert_eq!(second.objects, 1, "迟到行必须生成一个新对象");

        let mut objects = storage.list_archive_objects(10, None).unwrap();
        objects.sort_by_key(|object| object.id);
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].object_key, first_key);
        assert_eq!(objects[0].sha256, first_sha);
        assert_eq!(objects[0].bytes, first_bytes);
        assert_eq!(objects[0].rows, 3);
        assert!(objects[1].object_key.ends_with("part-00002-v8.csv.gz"));
        assert_eq!(objects[1].rows, 2);
        assert_eq!(objects[1].status, ArchiveStatus::Uploaded);

        let uploaded = mock.inner.lock().unwrap().objects.clone();
        assert_eq!(
            uploaded.get(&first_key),
            first_upload.get(&first_key),
            "A 对象内容不得被迟到行改写"
        );
        let late_rows = storage.archive_rows_for_object(objects[1].id).unwrap();
        let late_expected = csv_for(&late_rows);
        let late_actual = uploaded.get(&objects[1].object_key).unwrap();
        assert_eq!(late_actual, &late_expected.data);
        assert_eq!(objects[1].sha256, late_expected.sha256);
        assert_eq!(objects[1].bytes, late_expected.bytes);
        assert_eq!(
            storage.raw_stats().unwrap().rows,
            5,
            "本切片不删除 raw，retention 由 R1b 接线"
        );
    }

    #[tokio::test]
    async fn failed_object_retry_contains_only_original_rows_then_late_row_gets_new_object() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows_with_seq(&storage, ARCHIVE_DAY_START + HOUR_MS, &[1.0, 2.0], 1);
        mock.inner.lock().unwrap().fail_put = Some(500);

        run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap_err();
        let failed = storage
            .list_archive_objects(10, None)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(failed.status, ArchiveStatus::Failed);
        assert_eq!(failed.rows, 2);
        assert!(failed.object_key.ends_with("part-00001-v8.csv.gz"));

        // 失败后才补 B；重试必须只重建 A 的行集，B 另起对象。
        insert_raw_rows_with_seq(&storage, ARCHIVE_DAY_START + 2 * HOUR_MS, &[9.0], 2);
        mock.inner.lock().unwrap().fail_put = None;
        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap();
        assert_eq!(report.objects, 2, "1 个重试对象 + 1 个迟到行新对象");

        let mut objects = storage.list_archive_objects(10, None).unwrap();
        objects.sort_by_key(|object| object.id);
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].id, failed.id);
        assert_eq!(objects[0].status, ArchiveStatus::Uploaded);
        assert_eq!(objects[0].rows, 2);
        assert_eq!(objects[0].attempts, 1);
        assert!(objects[1].object_key.ends_with("part-00002-v8.csv.gz"));
        assert_eq!(objects[1].rows, 1);

        let uploaded = mock.inner.lock().unwrap().objects.clone();
        let original_rows = storage.archive_rows_for_object(objects[0].id).unwrap();
        assert_eq!(
            original_rows
                .iter()
                .map(|row| row.value)
                .collect::<Vec<_>>(),
            vec![1.0, 2.0],
            "重试不得纳入迟到行"
        );
        let original_expected = csv_for(&original_rows);
        assert_eq!(
            uploaded.get(&objects[0].object_key),
            Some(&original_expected.data)
        );
        assert_eq!(objects[0].sha256, original_expected.sha256);

        let late_rows = storage.archive_rows_for_object(objects[1].id).unwrap();
        assert_eq!(
            late_rows.iter().map(|row| row.value).collect::<Vec<_>>(),
            vec![9.0]
        );
        let late_expected = csv_for(&late_rows);
        assert_eq!(
            uploaded.get(&objects[1].object_key),
            Some(&late_expected.data)
        );
    }

    #[tokio::test]
    async fn rows_missing_is_recorded_and_skipped_without_blocking_other_objects() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();

        // A 的行集随后会被误删；B 的行集保留；C 是之后到达的未认领行。
        insert_raw_rows_with_seq(&storage, ARCHIVE_DAY_START + HOUR_MS, &[1.0, 2.0], 1);
        insert_raw_rows_with_seq(&storage, ARCHIVE_DAY_START + 3 * HOUR_MS, &[3.0, 4.0], 2);
        let rows = unclaimed_rows(&storage, 10);
        assert_eq!(rows.len(), 4);
        let a_id = claim_pending_for_test(&storage, &rows[..2], "part-00001", TEST_NOW - 20);
        let b_id = claim_pending_for_test(&storage, &rows[2..], "part-00002", TEST_NOW - 10);

        // 模拟已 claim 的 A 行被误删；旧 retention 直接按 ts 删除。
        let pruned = storage
            .prune_samples_before(ARCHIVE_DAY_START + 3 * HOUR_MS)
            .unwrap();
        assert_eq!(pruned.deleted, 2, "只删除 A 的两行");
        insert_raw_rows_with_seq(&storage, ARCHIVE_DAY_START + 5 * HOUR_MS, &[5.0], 3);

        // 不能因为 A 行集缺失而整轮失败：A 记 rows_missing 后继续 B 与 C。
        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .expect("rows_missing 不得阻塞其它对象");
        assert_eq!(report.objects, 2, "B 重试上传 + C 新对象");

        let mut objects = storage.list_archive_objects(10, None).unwrap();
        objects.sort_by_key(|object| object.id);
        assert_eq!(objects.len(), 3);
        let a = objects.iter().find(|object| object.id == a_id).unwrap();
        assert_eq!(a.status, ArchiveStatus::Failed);
        assert_eq!(a.error, "rows_missing");
        assert_eq!(a.attempts, 1);
        let b = objects.iter().find(|object| object.id == b_id).unwrap();
        assert_eq!(b.status, ArchiveStatus::Uploaded);
        assert_eq!(b.attempts, 0);
        let c = objects
            .iter()
            .find(|object| object.id != a_id && object.id != b_id)
            .unwrap();
        assert!(c.object_key.ends_with("part-00003-v8.csv.gz"));
        assert_eq!(c.status, ArchiveStatus::Uploaded);
        assert_eq!(c.rows, 1);
        assert_eq!(storage.raw_stats().unwrap().rows, 3, "B 行 + C 行仍保留");

        // 失败对象下一轮仍会记录一次失败并跳过，但不会卡死 B/C。
        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .expect("下一轮仍不得因 rows_missing 失败");
        assert_eq!(report.objects, 0);
        let a = storage.get_archive_object(a_id).unwrap().unwrap();
        assert_eq!(a.error, "rows_missing");
        assert_eq!(a.attempts, 2);
    }

    #[tokio::test]
    async fn pending_object_after_claim_is_recovered_from_archived_rows() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + HOUR_MS, &[1.0, 2.0, 3.0]);
        let rows = unclaimed_rows(&storage, 10);
        let created_at = TEST_NOW - 123_456;
        let object_id = claim_pending_for_test(&storage, &rows, "part-00001", created_at);
        let expected = csv_for(&rows);

        // 模拟 claim 已提交、上传 / 状态更新前 kill -9。
        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap();
        assert_eq!(report.objects, 1);
        let object = storage.get_archive_object(object_id).unwrap().unwrap();
        assert_eq!(object.status, ArchiveStatus::Uploaded);
        assert_eq!(object.created_at, created_at, "重试必须使用对象 created_at");
        assert_eq!(object.rows, 3);
        assert_eq!(object.bytes, expected.bytes);
        assert_eq!(object.sha256, expected.sha256);

        let uploaded = mock.inner.lock().unwrap().objects.clone();
        assert_eq!(uploaded.get(&object.object_key), Some(&expected.data));
        let manifest_text = std::str::from_utf8(
            uploaded
                .get(&object.manifest_key)
                .expect("manifest 必须上传"),
        )
        .unwrap();
        let manifest = ArchiveManifest::from_json(manifest_text).unwrap();
        assert_eq!(manifest.created_at, created_at);
        assert_eq!(manifest.rows, object.rows);
        assert_eq!(manifest.bytes, object.bytes);
        assert_eq!(manifest.sha256, object.sha256);
        assert_eq!(manifest.from_ts, object.from_ts);
        assert_eq!(manifest.to_ts, object.to_ts);
        assert_eq!(storage.list_archive_objects(10, None).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn uploaded_before_status_update_is_recovered_without_new_object() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + HOUR_MS, &[4.0, 5.0]);
        let rows = unclaimed_rows(&storage, 10);
        let created_at = TEST_NOW - 999;
        let object_id = claim_pending_for_test(&storage, &rows, "part-00001", created_at);
        let expected = csv_for(&rows);

        // 模拟「对象与 manifest 已上传、状态仍是 pending」的崩溃现场。
        {
            let object = storage.get_archive_object(object_id).unwrap().unwrap();
            let manifest = ArchiveManifest::new(
                object.object_key.clone(),
                object.from_ts,
                object.to_ts,
                expected.rows,
                expected.bytes,
                expected.sha256.clone(),
                created_at,
            );
            let mut inner = mock.inner.lock().unwrap();
            inner
                .objects
                .insert(object.object_key.clone(), expected.data.clone());
            inner.objects.insert(
                object.manifest_key.clone(),
                manifest_json(&manifest).unwrap().into_bytes(),
            );
        }

        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap();
        assert_eq!(report.objects, 1);
        let object = storage.get_archive_object(object_id).unwrap().unwrap();
        assert_eq!(object.status, ArchiveStatus::Uploaded);
        let uploaded = mock.inner.lock().unwrap().objects.clone();
        assert_eq!(uploaded.get(&object.object_key), Some(&expected.data));
        assert_eq!(storage.list_archive_objects(10, None).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn max_object_bytes_splits_unclaimed_rows_into_multiple_v8_objects() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let mut cfg = test_cfg();
        insert_unique_rows(&storage, ARCHIVE_DAY_START + HOUR_MS, 20, 1);
        let rows = unclaimed_rows(&storage, 100);
        assert_eq!(rows.len(), 20);
        let single_row = csv_for(&rows[..1]);
        // 取「单行压缩后大小」的 2 倍作为上限：至少能放下 1 行，20 行必须拆多个对象。
        cfg.archive.max_object_bytes = single_row.bytes.saturating_mul(2).max(1);

        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 100)
            .await
            .unwrap();
        let mut objects = storage.list_archive_objects(100, None).unwrap();
        objects.sort_by_key(|object| object.id);
        assert!(objects.len() > 1, "20 行必须拆成多个逻辑对象");
        assert_eq!(report.objects, objects.len());
        assert_eq!(
            objects.iter().map(|object| object.rows).sum::<u64>(),
            20,
            "所有对象行数之和必须等于原始行数"
        );
        let mut keys = std::collections::HashSet::new();
        for object in &objects {
            assert_eq!(object.status, ArchiveStatus::Uploaded);
            assert!(object.object_key.ends_with("-v8.csv.gz"));
            assert!(
                object.bytes <= cfg.archive.max_object_bytes,
                "对象 {} 超过 max_object_bytes: {} > {}",
                object.object_key,
                object.bytes,
                cfg.archive.max_object_bytes
            );
            assert!(keys.insert(object.object_key.clone()), "对象 key 不得重复");
            let data = mock
                .inner
                .lock()
                .unwrap()
                .objects
                .get(&object.object_key)
                .cloned()
                .expect("对象必须上传");
            assert_eq!(data.len() as u64, object.bytes);
            assert_eq!(rustboard_core::archive::sha256_hex(&data), object.sha256);
        }
    }

    #[tokio::test]
    async fn legacy_v7_object_and_watermark_are_not_treated_as_archived() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        let day = archive_day_for(day_start_ts()).unwrap();
        let legacy_keys =
            rustboard_core::archive::build_object_keys("rustboard-test", day, "part-00001")
                .unwrap();
        let mut legacy = archive_object_for_test(&legacy_keys.object_key);
        legacy.manifest_key = legacy_keys.manifest_key.clone();
        legacy.from_ts = ARCHIVE_DAY_START + HOUR_MS;
        legacy.to_ts = ARCHIVE_DAY_START + HOUR_MS;
        legacy.rows = 1;
        legacy.status = ArchiveStatus::Failed;
        legacy.ledger_version = rustboard_core::archive::LEDGER_VERSION_V7;
        let legacy_id = storage.insert_archive_object(&legacy).unwrap();

        // v7 水位声称该天已归档：不能据此跳过仍存在且 unclaimed 的 raw。
        storage
            .set_archive_state(
                STATE_LAST_ARCHIVED_TS,
                &(ARCHIVE_DAY_START + TEST_DAY_MS).to_string(),
                TEST_NOW,
            )
            .unwrap();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + HOUR_MS, &[1.0, 2.0]);

        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap();
        assert_eq!(report.objects, 1, "旧水位不得掩盖未认领 raw");
        let mut objects = storage.list_archive_objects(10, None).unwrap();
        objects.sort_by_key(|object| object.id);
        assert_eq!(objects.len(), 2);
        let v8 = objects
            .iter()
            .find(|object| object.id != legacy_id)
            .expect("必须生成新的 v8 对象");
        assert!(v8.object_key.ends_with("part-00002-v8.csv.gz"));
        assert_eq!(v8.ledger_version, LEDGER_VERSION_V8);
        assert_eq!(v8.status, ArchiveStatus::Uploaded);

        let legacy_after = storage.get_archive_object(legacy_id).unwrap().unwrap();
        assert_eq!(legacy_after.status, ArchiveStatus::Failed);
        assert_eq!(legacy_after.attempts, 0, "v7 对象不得被 worker 重试");
        assert!(!mock
            .inner
            .lock()
            .unwrap()
            .objects
            .contains_key(&legacy_keys.object_key));
    }

    #[tokio::test]
    async fn ledger_pending_blocks_until_rebuild_succeeds_then_clears() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + HOUR_MS, &[1.0, 2.0]);
        storage
            .set_archive_state(STATE_ARCHIVE_LEDGER_PENDING, "1", TEST_NOW)
            .unwrap();
        assert!(ledger_status(&storage).unwrap().pending);

        mock.inner.lock().unwrap().fail_put = Some(500);
        run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap_err();
        assert!(
            ledger_status(&storage).unwrap().pending,
            "失败时 pending 必须保留"
        );

        mock.inner.lock().unwrap().fail_put = None;
        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 10)
            .await
            .unwrap();
        assert_eq!(report.objects, 1);
        assert!(!ledger_status(&storage).unwrap().pending);
        assert_eq!(
            storage
                .get_archive_state(STATE_ARCHIVE_LEDGER_PENDING)
                .unwrap()
                .as_deref(),
            Some("0")
        );
        let objects = storage.list_archive_objects(10, None).unwrap();
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].status, ArchiveStatus::Uploaded);
    }

    #[tokio::test]
    async fn ledger_rebuild_marks_pending_before_running_and_keeps_it_on_failure() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + HOUR_MS, &[1.0]);
        mock.inner.lock().unwrap().fail_put = Some(500);

        rebuild_ledger(&storage, &cfg, &store, TEST_NOW)
            .await
            .unwrap_err();
        assert!(
            ledger_status(&storage).unwrap().pending,
            "手动 rebuild 失败后必须保持 pending"
        );

        mock.inner.lock().unwrap().fail_put = None;
        let report = rebuild_ledger(&storage, &cfg, &store, TEST_NOW)
            .await
            .unwrap();
        assert_eq!(report.objects, 1);
        assert!(!ledger_status(&storage).unwrap().pending);
    }

    #[tokio::test]
    async fn worker_rerun_is_idempotent_without_rescanning_uploaded_rows() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let mock = MockDav::spawn().await;
        let store = WebdavColdStore::new(&mock.config()).unwrap();
        let cfg = test_cfg();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + 3_600_000, &[1.0, 2.0, 3.0]);
        run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2)
            .await
            .unwrap();
        let requests_after_first = mock.inner.lock().unwrap().requests.len();

        // 人工把水位回拨到当天起点，模拟重跑；已 claim 的行不应再次归档。
        storage
            .set_archive_state(
                STATE_LAST_ARCHIVED_TS,
                &ARCHIVE_DAY_START.to_string(),
                TEST_NOW,
            )
            .unwrap();
        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2)
            .await
            .unwrap();
        assert_eq!(report.objects, 0, "已 claim 行不得重复生成对象");
        assert_eq!(report.skipped_objects, 0);
        assert_eq!(report.rows, 0);
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
    async fn empty_round_advances_watermark_without_objects() {
        let storage = StorageHandle::sqlite_memory().unwrap();
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

        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2)
            .await
            .unwrap();
        assert_eq!(report.days, 0, "没有 unclaimed raw 时不算处理新的一天");
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
        let storage = StorageHandle::sqlite_memory().unwrap();
        let cfg = test_cfg();
        let now = TEST_NOW;
        insert_raw_rows(&storage, now - 10 * TEST_DAY_MS, &[1.0, 2.0, 3.0]);
        storage
            .set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &now.to_string(), now)
            .unwrap();

        // 归档启用但没有水位：raw 一律不删。
        let gate = archive_gate(&storage, &cfg);
        assert_eq!(gate, ArchiveGate::Enabled { watermark: None });
        let report = run_retention(&*storage, &cfg, now, gate).unwrap();
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
        let report = run_retention(&*storage, &cfg, now, gate).unwrap();
        assert_eq!(report.raw.deleted, 3);
        assert!(!report.raw.blocked_by_archive);
        assert_eq!(storage.raw_stats().unwrap().rows, 0);
    }

    #[test]
    fn retention_gate_disabled_keeps_legacy_raw_deletion() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let cfg = HubConfig::default();
        let now = TEST_NOW;
        insert_raw_rows(&storage, now - 10 * TEST_DAY_MS, &[1.0, 2.0]);
        storage
            .set_maintenance_state(STATE_DOWNSAMPLE_1M_WATERMARK, &now.to_string(), now)
            .unwrap();

        assert_eq!(archive_gate(&storage, &cfg), ArchiveGate::Disabled);
        let report = run_retention(&*storage, &cfg, now, archive_gate(&storage, &cfg)).unwrap();
        assert_eq!(report.raw.deleted, 2);
        assert!(!report.raw.blocked_by_archive);
    }

    #[test]
    fn status_reports_archive_state_and_object_count() {
        let storage = StorageHandle::sqlite_memory().unwrap();
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
        assert_eq!(status.last_error.as_deref(), Some("archive_error"));
        assert_eq!(status.objects, 1);
    }

    /// M4-C4：旧库 / 人工写入的 last_error 可能带 URL / 凭据 / 路径，
    /// status 必须掩码；固定中文与固定码仍可展示。
    #[test]
    fn status_masks_unsafe_last_error_values() {
        let storage = StorageHandle::sqlite_memory().unwrap();
        let cfg = test_cfg();

        let long = "a".repeat(512);
        for unsafe_value in [
            "https://minio.internal/secret-bucket?X-Amz-Credential=AKIA_LEAK",
            "user:password@dav.example.com/rustboard",
            "/var/lib/rustboard/hub.toml",
            "C:\\rustboard\\hub.toml",
            "backend down",
            long.as_str(),
        ] {
            storage
                .set_archive_state(STATE_LAST_ERROR, unsafe_value, 1)
                .unwrap();
            assert_eq!(
                status(&storage, &cfg).unwrap().last_error.as_deref(),
                Some(LAST_ERROR_MASKED),
                "value={unsafe_value:?}"
            );
        }

        for safe_value in [
            "archive_run_failed",
            "冷存储后端不可用",
            "归档对象 key 非法",
            "归档未启用（archive.enabled = false）",
        ] {
            storage
                .set_archive_state(STATE_LAST_ERROR, safe_value, 1)
                .unwrap();
            assert_eq!(
                status(&storage, &cfg).unwrap().last_error.as_deref(),
                Some(safe_value),
                "value={safe_value:?}"
            );
        }

        // 空串视为无错误。
        storage
            .set_archive_state(STATE_LAST_ERROR, "   ", 1)
            .unwrap();
        assert!(status(&storage, &cfg).unwrap().last_error.is_none());
    }

    /// 固定码白名单必须精确匹配，不能把任意 `*_failed` 形式放行。
    #[test]
    fn last_error_code_whitelist_is_exact() {
        for value in [
            "archive_upload_failed",
            "Archive_failed",
            "archive_failed!",
            "../../etc/passwd_failed",
            "x@_failed",
            "archive_ failed",
        ] {
            assert_eq!(
                sanitize_last_error(value),
                LAST_ERROR_MASKED,
                "value={value:?}"
            );
        }
        assert_eq!(
            sanitize_last_error("archive_run_failed"),
            LAST_ERROR_RUN_FAILED
        );
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

        let storage = StorageHandle::sqlite_memory().unwrap();
        let cfg = test_cfg();
        assert!(!should_catch_up(&storage, &cfg, base + 2 * 3_600_000).unwrap());
        assert!(should_catch_up(&storage, &cfg, base + 3 * 3_600_000).unwrap());
        let eligible = eligible_day_end(cfg.archive.after_days, base + 3 * 3_600_000);
        storage
            .set_archive_state(STATE_LAST_ARCHIVED_TS, &eligible.to_string(), 0)
            .unwrap();
        assert!(!should_catch_up(&storage, &cfg, base + 3 * 3_600_000).unwrap());
    }

    // ------------------------------------------------------------------
    // M4-C2b：S3 接线与下载文件名
    // ------------------------------------------------------------------

    fn valid_s3_config() -> rustboard_common::config::ArchiveS3Config {
        rustboard_common::config::ArchiveS3Config {
            bucket: "rustboard-test".to_string(),
            region: "us-east-1".to_string(),
            endpoint: "http://127.0.0.1:9000".to_string(),
            access_key_id: "test-access-key".to_string(),
            secret_access_key: "test-secret-key".to_string(),
            path_style: true,
        }
    }

    fn test_cfg_s3() -> HubConfig {
        let mut cfg = test_cfg();
        cfg.archive.backend = ArchiveBackend::S3;
        cfg.archive.s3 = Some(valid_s3_config());
        cfg
    }

    /// S3 / SFTP builder 只校验配置 / 构造客户端，不联网；`build_store` 应接受它。
    #[test]
    fn build_store_wires_webdav_s3_and_sftp_without_network() {
        let mut cfg = ArchiveConfig {
            enabled: true,
            webdav: Some(rustboard_common::config::ArchiveWebdavConfig {
                url: "http://127.0.0.1:9/dav".to_string(),
                username: "dav-user".to_string(),
                password: "dav-password".to_string(),
            }),
            ..ArchiveConfig::default()
        };
        let webdav = build_store(&cfg).unwrap();
        drop(webdav);

        cfg.backend = ArchiveBackend::S3;
        cfg.s3 = Some(valid_s3_config());
        let s3 = build_store(&cfg).unwrap();
        drop(s3);

        // 缺少 [archive.s3] 时给出明确错误，且不包含凭据。
        cfg.s3 = None;
        let error = build_store(&cfg).err().expect("缺少 S3 配置必须失败");
        assert!(
            format!("{error:#}").contains("archive.s3"),
            "缺少 S3 配置必须明确报错: {error:#}"
        );

        // SFTP 构造只校验本地配置与指纹格式，不联网。
        cfg.backend = ArchiveBackend::Sftp;
        cfg.sftp = Some(crate::archive_sftp::test_config());
        let sftp = build_store(&cfg).unwrap();
        drop(sftp);

        // 缺少 [archive.sftp] 时给出明确错误，且不包含凭据 / 远端路径。
        cfg.sftp = None;
        let error = build_store(&cfg).err().expect("缺少 SFTP 配置必须失败");
        assert!(
            format!("{error:#}").contains("archive.sftp"),
            "缺少 SFTP 配置必须明确报错: {error:#}"
        );
    }

    /// 用 InMemory 注入的 `S3ColdStore` 跑完整 worker：验证 S3 后端不止能构造，
    /// 上传 / HEAD 校验 / 状态落库都走同一条真实 S3 代码路径（不联网）。
    #[tokio::test]
    async fn s3_worker_uploads_objects_through_injected_store() {
        use crate::archive_s3::S3ColdStore;
        use object_store::memory::InMemory;

        let storage = StorageHandle::sqlite_memory().unwrap();
        let store = S3ColdStore::with_store(Arc::new(InMemory::new()));
        let cfg = test_cfg_s3();
        insert_raw_rows(&storage, ARCHIVE_DAY_START + 3_600_000, &[1.0, 2.0, 3.0]);

        let report = run_archive_once_with_limits(&storage, &cfg, &store, TEST_NOW, 2)
            .await
            .unwrap();
        assert_eq!(report.days, 1);
        assert_eq!(report.objects, 2);
        assert_eq!(report.rows, 3);
        assert_eq!(report.watermark, Some(ARCHIVE_DAY_START + TEST_DAY_MS));

        let mut objects = storage.list_archive_objects(10, None).unwrap();
        objects.sort_by_key(|object| object.id);
        assert_eq!(objects.len(), 2);
        for object in &objects {
            assert_eq!(object.backend, "s3");
            assert_eq!(object.status, ArchiveStatus::Uploaded);
            assert!(object.object_key.ends_with(".csv.gz"));
            assert!(object.manifest_key.ends_with(".manifest.json"));
            assert_eq!(
                store
                    .head(&object.object_key)
                    .await
                    .unwrap()
                    .map(|meta| meta.size),
                Some(object.bytes),
                "S3 对象大小必须与数据库记录一致"
            );
            assert!(
                store.head(&object.manifest_key).await.unwrap().is_some(),
                "manifest 必须上传"
            );
        }
    }

    #[test]
    fn download_filename_is_rebuilt_from_validated_key_segments() {
        assert_eq!(
            download_filename("rustboard/2026/10/24/part-00001.csv.gz").as_deref(),
            Some("rustboard-20261024-part-00001.csv.gz")
        );
        assert_eq!(
            download_filename("rb-test/1970/01/01/part-99999.csv.gz").as_deref(),
            Some("rustboard-19700101-part-99999.csv.gz")
        );
        // v8 claim 对象保留 `-v8` 后缀，文件名仍只由校验过的数字段拼接。
        assert_eq!(
            download_filename("rustboard/2026/10/24/part-00001-v8.csv.gz").as_deref(),
            Some("rustboard-20261024-part-00001-v8.csv.gz")
        );
        assert_eq!(
            download_filename("rb-test/1970/01/01/part-99999-v8.csv.gz").as_deref(),
            Some("rustboard-19700101-part-99999-v8.csv.gz")
        );

        // 只有标准 key 才能生成文件名；其余一律拒绝，绝不回显原始 key。
        for key in [
            "",
            "rustboard/2026/10/24/part-00001.csv",
            "rustboard/2026/10/24/part-00001.csv.gz.extra",
            "rustboard/2026/10/24/part-00001.csv.gz/",
            "/2026/10/24/part-00001.csv.gz",
            "rustboard/2026/10/24/part-00000.csv.gz",
            "rustboard/2026/10/24/part-1.csv.gz",
            "rustboard/2026/10/24/part-000001.csv.gz",
            "rustboard/2026/10/24/part-0000a.csv.gz",
            "rustboard/2026/10/24/part-00001-v9.csv.gz",
            "rustboard/2026/10/24/part-00001-v8-v8.csv.gz",
            "rustboard/2026/10/24/part-00000-v8.csv.gz",
            "rustboard/2026/13/24/part-00001.csv.gz",
            "rustboard/2026/00/24/part-00001.csv.gz",
            "rustboard/2026/10/32/part-00001.csv.gz",
            "rustboard/2026/10/24/part-00001-v8.csv.gz/../../evil.csv.gz",
            "rustboard/2026/10/24/part-00001.csv.gz/../../evil.csv.gz",
            "../2026/10/24/part-00001.csv.gz",
            "rustboard-../../etc/2026/10/24/part-00001.csv.gz",
            "rustboard\\2026\\10\\24\\part-00001.csv.gz",
            "rustboard/2026/10/24/part-00001.csv.gz\r\nX-Injected: 1",
        ] {
            assert_eq!(download_filename(key), None, "key={key:?}");
        }

        let name = download_filename("rustboard/2026/10/24/part-00001-v8.csv.gz").unwrap();
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')),
            "文件名只允许安全字符: {name}"
        );
    }
}
