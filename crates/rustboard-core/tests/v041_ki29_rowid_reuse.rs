//! v0.4.1 KI-29：raw 删除后 rowid 水位复用边界的独立回归测试。
//!
//! 只依据 `docs/plans/2026-10-24-known-issues-fix.md` §3.1 的验收标准编写：
//!
//! - retention 删除“最大 rowid 的迟到 raw 行”后，`maintenance_state` 里的
//!   `downsample_1m_last_raw_rowid` 不得高于新的 `MAX(rowid)`；表空时应清除；
//! - 新迟到行复用被删除的 rowid 后，下一轮 `run_downsample` 必须通过 rowid
//!   水位发现它，并重算对应的 1m / 1h 桶。
//!
//! 数据全部通过公开接口构造：`SqliteStorage::open_in_memory`、
//! `Storage::insert_batch`、`run_downsample`、`run_retention`、
//! `prune_samples_before`、`maintenance_status`。读取聚合结果也只走
//! `Storage::query_series_tiered`，不直接碰内部表结构。
//!
//! 这些用例在 v0.4.0 基线上应当失败；修复 KI-29 后应当通过。

use rustboard_common::config::HubConfig;
use rustboard_common::model::{AgentRecord, Labels, Sample, SampleBatch, SeriesQuery};
use rustboard_core::downsample::{
    maintenance_status, run_downsample, run_retention, ArchiveGate,
    STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID,
};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::{IngestOutcome, SampleTier, Storage, BUCKET_1H_MS, BUCKET_1M_MS};

/// 整小时对齐的测试基准时间（UTC 毫秒）。
const BASE: i64 = 1_699_999_200_000;
/// 固定的“当前时间”：对齐到整点，避免测试依赖真实时钟。
const NOW: i64 = BASE + 13 * BUCKET_1H_MS;
const DAY_MS: i64 = 86_400_000;
const AGENT: &str = "agent-v041-ki29";

fn setup() -> SqliteStorage {
    let storage = SqliteStorage::open_in_memory().expect("open_in_memory 失败");
    storage
        .upsert_agent(&AgentRecord {
            agent_id: AGENT.to_string(),
            name: AGENT.to_string(),
            hostname: "host-v041".to_string(),
            status: "online".to_string(),
            ..AgentRecord::default()
        })
        .expect("upsert_agent 失败");
    storage
}

fn sample(ts: i64, value: f64) -> Sample {
    Sample {
        metric: "cpu.usage".to_string(),
        labels: Labels::new(),
        ts,
        value,
    }
}

fn insert(storage: &SqliteStorage, seq: u64, samples: Vec<Sample>) {
    let batch = SampleBatch {
        agent_id: AGENT.to_string(),
        epoch: 1,
        seq,
        boot_id: "boot-v041-ki29".to_string(),
        sent_at: NOW,
        samples,
    };
    match storage.insert_batch(&batch).expect("insert_batch 失败") {
        IngestOutcome::Inserted { inserted } => {
            assert_eq!(inserted, batch.samples.len(), "插入条数与批次不一致");
        }
        other => panic!("测试批次应正常写入，实际为 {other:?}"),
    }
}

/// 造数并跑第一轮降采样：最近行 rowid=1，迟到旧行 rowid=2（最大）。
/// 返回 (old_ts, old_bucket, old_hour)。
fn seed_and_downsample(storage: &SqliteStorage) -> (i64, i64, i64) {
    // 旧行 1 天 2 分钟前：配置 retention_raw_days=1 时会被 retention 删除，
    // 同时只产生约 1440 个分钟桶，测试不会因跨 7 天而变慢。
    let old_ts = NOW - DAY_MS - 2 * BUCKET_1M_MS;
    let recent_ts = NOW - 90_000;
    insert(
        storage,
        1,
        vec![sample(recent_ts, 1.0), sample(old_ts, 100.0)],
    );

    let report = run_downsample(storage, NOW, None).expect("首次 run_downsample 失败");
    assert_eq!(
        report.one_minute.watermark,
        Some(NOW),
        "首次降采样后 1m 水位应推进到 now"
    );
    assert_eq!(
        report.one_hour.watermark,
        Some(NOW),
        "首次降采样后 1h 水位应推进到整点 NOW"
    );

    let old_bucket = old_ts.div_euclid(BUCKET_1M_MS) * BUCKET_1M_MS;
    let old_hour = old_ts.div_euclid(BUCKET_1H_MS) * BUCKET_1H_MS;
    (old_ts, old_bucket, old_hour)
}

fn retention_config() -> HubConfig {
    HubConfig {
        retention_raw_days: 1,
        retention_1m_days: 90,
        retention_1h_days: 730,
        ..HubConfig::default()
    }
}

fn bucket_value(storage: &SqliteStorage, tier: SampleTier, bucket_ms: i64, bucket_ts: i64) -> f64 {
    let rows = storage
        .query_series_tiered(
            &SeriesQuery {
                agent_id: AGENT.to_string(),
                metrics: vec!["cpu.usage".to_string()],
                from: bucket_ts,
                to: bucket_ts + bucket_ms - 1,
                limit: 10,
            },
            bucket_ms,
            tier,
        )
        .expect("query_series_tiered 失败");
    assert_eq!(
        rows.len(),
        1,
        "{tier:?} 层应恰好有一个 bucket_ts={bucket_ts} 的聚合行，实际 {}",
        rows.len()
    );
    assert_eq!(rows[0].ts, bucket_ts, "{tier:?} 层返回的桶起点不符");
    rows[0].value
}

fn assert_close(actual: f64, expected: f64, context: &str) {
    assert!(
        (actual - expected).abs() < 1e-9,
        "{context}：期望 {expected}，实际 {actual}"
    );
}

// ---------------------------------------------------------------------------
// 用例 1：prune 后水位不得高于新的 MAX(rowid)。
// ---------------------------------------------------------------------------

#[test]
fn v041_ki29_retention_lowers_rowid_watermark_below_new_max() {
    let storage = setup();
    let _ = seed_and_downsample(&storage);

    let conn_max_before = storage.raw_new_rows(None).expect("raw_new_rows 失败").0;
    assert_eq!(
        conn_max_before,
        Some(2),
        "造数后最大 rowid 应为 2（旧行最后插入）"
    );

    let before = maintenance_status(&storage).expect("maintenance_status 失败");
    assert_eq!(
        before.downsample_1m_last_raw_rowid,
        Some(2),
        "首次降采样应认领到最大 rowid=2"
    );

    let retention = run_retention(&storage, &retention_config(), NOW, ArchiveGate::Disabled)
        .expect("run_retention 失败");
    assert_eq!(retention.raw.deleted, 1, "retention 应删除 1 条过期 raw");

    let max_after = storage.raw_new_rows(None).expect("raw_new_rows 失败").0;
    assert_eq!(max_after, Some(1), "删除后 raw 仅剩 rowid=1");

    let status = maintenance_status(&storage).expect("maintenance_status 失败");
    let watermark = status.downsample_1m_last_raw_rowid.expect(
        "retention 后 raw 表仍非空（MAX(rowid)=1），downsample_1m_last_raw_rowid \
         不得被清除，必须保留有效整数水位",
    );
    let max_rowid = max_after.expect("已断言删除后 raw 仅剩 rowid=1");
    assert!(
        watermark <= max_rowid,
        "retention 删除最大 rowid 行后，downsample_1m_last_raw_rowid={watermark} \
         不得高于新的 MAX(rowid)={max_rowid}；否则复用 rowid 的迟到行会被误判为已认领"
    );
}

// ---------------------------------------------------------------------------
// 用例 2：新迟到行复用被删除的 rowid，必须触发 1m / 1h 重算。
// ---------------------------------------------------------------------------

#[test]
fn v041_ki29_late_row_reusing_deleted_rowid_recomputes_one_minute_and_one_hour() {
    let storage = setup();
    let (old_ts, old_bucket, old_hour) = seed_and_downsample(&storage);

    // 首次降采样已把旧桶聚合为 100.0；修复前该值会在下面被错误地保留。
    assert_close(
        bucket_value(&storage, SampleTier::OneMinute, BUCKET_1M_MS, old_bucket),
        100.0,
        "首次降采样后的 1m 旧桶",
    );
    assert_close(
        bucket_value(&storage, SampleTier::OneHour, BUCKET_1H_MS, old_hour),
        100.0,
        "首次降采样后的 1h 旧桶",
    );

    let retention = run_retention(&storage, &retention_config(), NOW, ArchiveGate::Disabled)
        .expect("run_retention 失败");
    assert_eq!(retention.raw.deleted, 1, "retention 应删除旧 raw 行");
    assert_eq!(
        storage.raw_new_rows(None).expect("raw_new_rows 失败").0,
        Some(1),
        "删除旧行后 MAX(rowid) 应回退到 1"
    );

    // 新迟到行：ts 落在同一分钟桶内；因为 rowid=2 刚被删除，SQLite 会复用它。
    insert(&storage, 2, vec![sample(old_ts + 40_000, 5.0)]);
    assert_eq!(
        storage.raw_new_rows(None).expect("raw_new_rows 失败").0,
        Some(2),
        "测试前提：新迟到行应复用被删除的 rowid=2"
    );

    let second = run_downsample(&storage, NOW, None).expect("迟到行后的 run_downsample 失败");
    assert_eq!(
        second.one_minute.watermark,
        Some(NOW),
        "迟到重算后 1m 水位应恢复到 now"
    );
    assert_eq!(
        second.one_hour.watermark,
        Some(NOW),
        "迟到重算后 1h 水位应恢复到整点 NOW"
    );

    // 修复前：rowid 水位仍是 2，扫描区间为空，旧桶停留在 100.0。
    // 修复后：水位被降到 1，rowid=2 被视为新行，按 raw 重算为 5.0。
    assert_close(
        bucket_value(&storage, SampleTier::OneMinute, BUCKET_1M_MS, old_bucket),
        5.0,
        "复用 rowid 的迟到行必须触发 1m 旧桶重算",
    );
    assert_close(
        bucket_value(&storage, SampleTier::OneHour, BUCKET_1H_MS, old_hour),
        5.0,
        "1h 旧桶必须随 1m 重算（不能停留在旧值 100.0）",
    );
}

// ---------------------------------------------------------------------------
// 用例 3：raw 表被清空时必须清除 rowid 水位。
// ---------------------------------------------------------------------------

#[test]
fn v041_ki29_pruning_last_raw_row_clears_rowid_watermark() {
    let storage = setup();
    let old_ts = NOW - 2 * DAY_MS;
    insert(&storage, 1, vec![sample(old_ts, 1.0)]);

    // 模拟上一轮降采样已认领 rowid=1（这里故意写一个高于实际 MAX 的值，
    // 同时覆盖“水位高于新 MAX 时只降低/清除”的方向）。
    storage
        .set_maintenance_state(STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID, "7", NOW)
        .expect("set_maintenance_state 失败");

    let pruned = storage
        .prune_samples_before(i64::MAX)
        .expect("prune_samples_before 失败");
    assert_eq!(pruned.deleted, 1, "应删除唯一一条 raw");
    assert_eq!(
        storage.raw_new_rows(None).expect("raw_new_rows 失败").0,
        None,
        "raw 表应为空"
    );

    let status = maintenance_status(&storage).expect("maintenance_status 失败");
    assert_eq!(
        status.downsample_1m_last_raw_rowid, None,
        "raw 表为空时必须清除 downsample_1m_last_raw_rowid；\
         残留旧水位会让复用的 rowid 永远无法被扫描"
    );
}
