//! R1b：raw 删除后 rowid 复用边界的独立回归测试。
//!
//! v0.4.1 KI-29 依赖 `downsample_1m_last_raw_rowid` 发现迟到行；R1b 改为
//! `samples.aggregated_1m=0` 增量认领后，迟到行不再依赖 rowid 水位。本文件
//! 继续覆盖两个仍然重要的事实：
//!
//! - retention 只删 `aggregated_1m=1` 的 raw，删除后新迟到行仍会被 delta
//!   发现并修正 1m / 1h（即使它复用了刚被删除的 rowid）；
//! - raw 表清空后，历史遗留的 `downsample_1m_last_raw_rowid` 由保留期路径
//!   收敛/清除（兼容旧库，不再由降采样写入）。
//!
//! 数据全部通过公开接口构造；聚合结果只走 `Storage::query_series_tiered`。

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
/// 固定的「当前时间」：对齐到整点，避免测试依赖真实时钟。
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

/// 造数并跑第一轮降采样：返回 (old_ts, old_bucket, old_hour)。
fn seed_and_downsample(storage: &SqliteStorage) -> (i64, i64, i64) {
    // 旧行 1 天 2 分钟前：retention_raw_days=1 时会被 retention 删除。
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
// 用例 1：R1b 不再写 rowid 水位；retention 只删已聚合 raw。
// ---------------------------------------------------------------------------

#[test]
fn v041_ki29_retention_deletes_only_aggregated_raw_and_does_not_claim_rowid() {
    let storage = setup();
    let _ = seed_and_downsample(&storage);

    let status =
        maintenance_status(&storage, &HubConfig::default(), NOW).expect("maintenance_status 失败");
    assert_eq!(
        status.downsample_1m_last_raw_rowid, None,
        "R1b 增量认领不再写 downsample_1m_last_raw_rowid；旧字段只作兼容展示"
    );
    assert_eq!(status.unaggregated_rows, 0, "首轮降采样后 raw 应全部已聚合");

    let retention = run_retention(&storage, &retention_config(), NOW, ArchiveGate::Disabled)
        .expect("run_retention 失败");
    assert_eq!(retention.raw.deleted, 1, "retention 应删除已聚合的旧 raw");
    assert_eq!(storage.raw_stats().unwrap().rows, 1, "未过期 raw 保留");
}

// ---------------------------------------------------------------------------
// 用例 2：迟到行复用被删除的 rowid，仍必须被 delta 发现并修正 1m / 1h。
// ---------------------------------------------------------------------------

#[test]
fn v041_ki29_late_row_reusing_deleted_rowid_recomputes_one_minute_and_one_hour() {
    let storage = setup();
    let (old_ts, old_bucket, old_hour) = seed_and_downsample(&storage);

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
        "迟到行不得回拨 1m 水位"
    );
    assert_eq!(
        second.one_hour.watermark,
        Some(NOW),
        "迟到行不得回拨 1h 水位"
    );

    // 1m 旧桶由 100.0 增量合并 5.0：count=2、avg=(100+5)/2=52.5。
    assert_close(
        bucket_value(&storage, SampleTier::OneMinute, BUCKET_1M_MS, old_bucket),
        52.5,
        "复用 rowid 的迟到行必须被 delta 合并进 1m 旧桶",
    );
    assert_close(
        bucket_value(&storage, SampleTier::OneHour, BUCKET_1H_MS, old_hour),
        52.5,
        "1h 旧桶必须随 1m 重算（不能停留在旧值 100.0）",
    );
}

// ---------------------------------------------------------------------------
// 用例 3：raw 表被清空时，历史遗留的 rowid 水位应被收敛/清除。
// ---------------------------------------------------------------------------

#[test]
fn v041_ki29_pruning_last_raw_row_clears_legacy_rowid_watermark() {
    let storage = setup();
    let old_ts = NOW - 2 * DAY_MS;
    insert(&storage, 1, vec![sample(old_ts, 1.0)]);
    run_downsample(&storage, NOW, None).expect("run_downsample 失败");

    // 模拟旧版本遗留的 rowid 水位（故意写一个高于实际 MAX 的值，覆盖
    // 「水位高于新 MAX 时只降低/清除」的方向）。
    storage
        .set_maintenance_state(STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID, "7", NOW)
        .expect("set_maintenance_state 失败");

    let pruned = storage
        .prune_samples_before(i64::MAX)
        .expect("prune_samples_before 失败");
    assert_eq!(pruned.deleted, 1, "应删除唯一一条已聚合 raw");
    assert_eq!(
        storage.raw_new_rows(None).expect("raw_new_rows 失败").0,
        None,
        "raw 表应为空"
    );

    let status =
        maintenance_status(&storage, &HubConfig::default(), NOW).expect("maintenance_status 失败");
    assert_eq!(
        status.downsample_1m_last_raw_rowid, None,
        "raw 表为空时必须清除历史 rowid 水位"
    );
}
