//! M4-A2 迟到重放、归档门禁与保留期水位夹紧的独立集成测试。
//!
//! 只依据 `docs/plans/2026-10-24-m4-alerting-archive.md` §5.1 / §5.3 与
//! `crates/rustboard-core/src/downsample.rs` 的公开类型 / 函数文档 / 签名编写；
//! 不参考 `downsample.rs` 的内部算法，也不修改生产代码。
//!
//! 数据全部通过公开接口构造：`SqliteStorage::open`、`Storage::insert_batch`、
//! `run_downsample`、`run_retention`。`rusqlite::Connection` 只以只读方式打开
//! 做核对（只用 SELECT），不参与造数、修改水位或删除。

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use rustboard_common::config::HubConfig;
use rustboard_common::model::{AgentRecord, Labels, Sample, SampleBatch};
use rustboard_core::downsample::{
    maintenance_status, run_downsample, run_retention, ArchiveGate, STATE_DOWNSAMPLE_1H_WATERMARK,
};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::{IngestOutcome, Storage, BUCKET_1H_MS, BUCKET_1M_MS};

const MINUTE_MS: i64 = BUCKET_1M_MS;
const HOUR_MS: i64 = BUCKET_1H_MS;
const DAY_MS: i64 = 86_400_000;

/// 整点对齐的测试基准时间：UTC 毫秒。
const BASE: i64 = 1_699_999_200_000;

const SAMPLES_1M: &str = "samples_1m";
const SAMPLES_1H: &str = "samples_1h";

/// 每个用例自建唯一临时目录，`Drop` 时递归清理。
struct TempDbDir {
    root: PathBuf,
}

impl TempDbDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系统时间早于 UNIX_EPOCH")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rb-m4-a2-late-{}-{tag}-{nanos}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("创建临时目录失败");
        Self { root }
    }

    fn db_path(&self) -> PathBuf {
        self.root.join("rustboard.db")
    }
}

impl Drop for TempDbDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn open_storage(dir: &TempDbDir) -> SqliteStorage {
    SqliteStorage::open(&dir.db_path()).expect("SqliteStorage::open 失败")
}

/// 只读连接：整份测试里只做 SELECT 核对，不用它改库。
fn readonly_conn(dir: &TempDbDir) -> Connection {
    Connection::open_with_flags(dir.db_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("以只读方式打开测试库失败")
}

fn ensure_agent(storage: &SqliteStorage, agent_id: &str) {
    let record = AgentRecord {
        agent_id: agent_id.to_string(),
        name: agent_id.to_string(),
        hostname: "host-test".to_string(),
        status: "online".to_string(),
        ..AgentRecord::default()
    };
    storage.upsert_agent(&record).expect("upsert_agent 失败");
}

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn sample(metric: &str, labels: Labels, ts: i64, value: f64) -> Sample {
    Sample {
        metric: metric.to_string(),
        labels,
        ts,
        value,
    }
}

fn batch(agent_id: &str, seq: u64, sent_at: i64, samples: Vec<Sample>) -> SampleBatch {
    SampleBatch {
        agent_id: agent_id.to_string(),
        epoch: 1,
        seq,
        boot_id: "boot-m4-a2-late".to_string(),
        sent_at,
        samples,
    }
}

fn insert(storage: &SqliteStorage, batch: &SampleBatch) {
    match storage.insert_batch(batch).expect("insert_batch 失败") {
        IngestOutcome::Inserted { inserted } => {
            assert_eq!(
                inserted,
                batch.samples.len(),
                "insert_batch 返回的插入条数与批次不一致"
            );
        }
        other => panic!("测试批次应正常写入，实际为 {other:?}"),
    }
}

/// `samples_1m` / `samples_1h` 单桶的只读快照。
#[derive(Debug)]
struct Aggregate {
    count: i64,
    avg_value: f64,
    last_value: f64,
}

/// 只读查询某一聚合桶；桶不存在返回 `None`。
fn tier_row(
    conn: &Connection,
    table: &'static str,
    agent_id: &str,
    metric: &str,
    bucket_ts: i64,
) -> Option<Aggregate> {
    // table 只可能是下面两个常量，不拼接外部输入。
    let table = match table {
        SAMPLES_1M => SAMPLES_1M,
        SAMPLES_1H => SAMPLES_1H,
        other => panic!("未知聚合表 {other}"),
    };
    let sql = format!(
        "SELECT \"count\", avg_value, last_value FROM {table} \
         WHERE agent_id = ?1 AND metric = ?2 AND bucket_ts = ?3"
    );
    conn.query_row(&sql, params![agent_id, metric, bucket_ts], |row| {
        Ok(Aggregate {
            count: row.get(0)?,
            avg_value: row.get(1)?,
            last_value: row.get(2)?,
        })
    })
    .optional()
    .unwrap_or_else(|err| panic!("只读查询 {table} 桶失败：{err}"))
}

fn assert_close(actual: f64, expected: f64, context: &str) {
    let tolerance = 1e-9 * expected.abs().max(1.0);
    assert!(
        (actual - expected).abs() <= tolerance,
        "{context}：期望 {expected}，实际 {actual}"
    );
}

fn assert_aggregate(
    conn: &Connection,
    table: &'static str,
    agent_id: &str,
    metric: &str,
    bucket_ts: i64,
    expected: (i64, f64, f64),
    context: &str,
) {
    let (count, avg_value, last_value) = expected;
    let row = tier_row(conn, table, agent_id, metric, bucket_ts)
        .unwrap_or_else(|| panic!("{context}：缺少 bucket_ts={bucket_ts} 的 {table} 行"));
    assert_eq!(row.count, count, "{context}：count");
    assert_close(row.avg_value, avg_value, &format!("{context}：avg_value"));
    assert_close(
        row.last_value,
        last_value,
        &format!("{context}：last_value"),
    );
}

fn raw_count(conn: &Connection, agent_id: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM samples WHERE agent_id = ?1",
        params![agent_id],
        |row| row.get(0),
    )
    .unwrap_or_else(|err| panic!("统计 raw 行数失败：{err}"))
}

fn raw_has_ts(conn: &Connection, agent_id: &str, ts: i64) -> bool {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples WHERE agent_id = ?1 AND ts = ?2",
            params![agent_id, ts],
            |row| row.get(0),
        )
        .unwrap_or_else(|err| panic!("只读核对 raw ts={ts} 失败：{err}"));
    count == 1
}

// ---------------------------------------------------------------------------
// 用例 1：10h 迟到重放。
//
// 旧实现只重算最近 2 个已关闭桶，10h 前桶里的迟到 raw 会被永久漏掉；
// 修复后必须通过 raw rowid 水位发现「新行但旧 ts」，回拨水位并重算 1m/1h，
// 最后把水位恢复到 now（1m / 1h 均不得停留在被回拨的旧桶）。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2_late_raw_ten_hours_replay_recomputes_one_minute_and_one_hour() {
    let dir = TempDbDir::new("replay");
    let storage = open_storage(&dir);
    let agent = "agent-late";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 13 * HOUR_MS;
    let old_hour = NOW - 10 * HOUR_MS;
    let old_bucket = old_hour + 2 * MINUTE_MS;
    // 该桶远早于「最近 2 个桶」的重算窗口，只有回拨水位才能覆盖。
    assert!(
        old_bucket < NOW - 2 * HOUR_MS,
        "测试前提：迟到桶必须早于最近 2 小时"
    );

    let label = [("host", "late")];
    insert(
        &storage,
        &batch(
            agent,
            1,
            NOW,
            vec![
                sample("cpu.usage", labels(&label), old_bucket, 10.0),
                sample("cpu.usage", labels(&label), old_bucket + 20_000, 20.0),
                // 一小时前的 raw，保证首次运行后 1h 水位推进到 NOW。
                sample(
                    "cpu.usage",
                    labels(&label),
                    NOW - HOUR_MS + 5 * MINUTE_MS,
                    5.0,
                ),
                // 最后一个已关闭分钟（桶 [NOW-120s, NOW-60s)）。
                sample("cpu.usage", labels(&label), NOW - 90_000, 7.0),
            ],
        ),
    );

    let first = run_downsample(&storage, NOW, None).expect("首次 run_downsample 失败");
    assert_eq!(
        first.one_minute.watermark,
        Some(NOW),
        "首次运行后 1m 水位应推进到 now"
    );
    assert_eq!(
        first.one_hour.watermark,
        Some(NOW),
        "首次运行后 1h 水位应推进到整点 NOW"
    );

    let conn = readonly_conn(&dir);
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "cpu.usage",
        old_bucket,
        (2, 15.0, 20.0),
        "迟到前 1m 旧桶",
    );
    assert_aggregate(
        &conn,
        SAMPLES_1H,
        agent,
        "cpu.usage",
        old_hour,
        (2, 15.0, 20.0),
        "迟到前 1h 旧桶",
    );

    // 新批次 seq：同一旧桶、ts 早于 now 10h 的迟到 raw。
    insert(
        &storage,
        &batch(
            agent,
            2,
            NOW,
            vec![sample(
                "cpu.usage",
                labels(&label),
                old_bucket + 40_000,
                30.0,
            )],
        ),
    );

    let second = run_downsample(&storage, NOW, None).expect("迟到重放后的 run_downsample 失败");
    assert_eq!(
        second.one_minute.watermark, first.one_minute.watermark,
        "迟到重放后 1m 水位必须回到重放前的 now 边界"
    );
    assert_eq!(
        second.one_hour.watermark, first.one_hour.watermark,
        "迟到重放后 1h 水位必须回到重放前的 now 边界"
    );
    assert_eq!(
        second.one_minute.watermark,
        Some(NOW),
        "迟到重放后 1m 水位不得停留在被回拨的旧桶"
    );
    assert_eq!(
        second.one_hour.watermark,
        Some(NOW),
        "迟到重放后 1h 水位不得停留在被回拨的旧桶"
    );

    // 1m 必须按 raw 重算：count 2 -> 3，avg 15 -> 20，last 20 -> 30。
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "cpu.usage",
        old_bucket,
        (3, 20.0, 30.0),
        "迟到重放后的 1m 旧桶",
    );
    // 1h 依赖 1m 重算：同样被修正，而不是停留在旧值。
    assert_aggregate(
        &conn,
        SAMPLES_1H,
        agent,
        "cpu.usage",
        old_hour,
        (3, 20.0, 30.0),
        "迟到重放后的 1h 旧桶",
    );

    let status = maintenance_status(&storage).expect("maintenance_status 失败");
    assert_eq!(
        status.downsample_1m_watermark,
        Some(NOW),
        "持久化的 1m 水位必须恢复"
    );
    assert_eq!(
        status.downsample_1h_watermark,
        Some(NOW),
        "持久化的 1h 水位必须恢复"
    );
}

// ---------------------------------------------------------------------------
// 用例 2：归档门禁。
//
// 归档未启用与「已启用但还没有任何成功归档」必须区分：
// - Enabled { watermark: None }：raw 一行不删，blocked_by_archive=true；
// - Enabled { watermark: Some(w) }：raw 只删 ts < w 的部分；
// - Disabled：才按 retention_raw_days 删除。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2_archive_gate_blocks_raw_until_watermark() {
    let dir = TempDbDir::new("archive");
    let storage = open_storage(&dir);
    let agent = "agent-archive";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 20 * HOUR_MS;
    let oldest = NOW - 10 * DAY_MS;
    let middle = NOW - 9 * DAY_MS + HOUR_MS;
    let newest_expired = NOW - 8 * DAY_MS;
    // 未过期的新数据。
    let fresh = NOW - 90_000;

    insert(
        &storage,
        &batch(
            agent,
            1,
            NOW,
            vec![
                sample("mem.used", Labels::new(), oldest, 1.0),
                sample("mem.used", Labels::new(), middle, 2.0),
                sample("mem.used", Labels::new(), newest_expired, 3.0),
                sample("mem.used", Labels::new(), fresh, 4.0),
            ],
        ),
    );

    let downsample = run_downsample(&storage, NOW, None).expect("run_downsample 失败");
    assert_eq!(
        downsample.one_minute.watermark,
        Some(NOW),
        "构造的 1m 水位应推进到 now"
    );

    let cfg = HubConfig {
        retention_raw_days: 7,
        retention_1m_days: 90,
        retention_1h_days: 730,
        ..HubConfig::default()
    };
    let conn = readonly_conn(&dir);
    assert_eq!(raw_count(&conn, agent), 4, "造数后 raw 行数");

    // 已启用但还没有成功归档：raw 一律不删。
    let enabled_none = run_retention(
        &storage,
        &cfg,
        NOW,
        ArchiveGate::Enabled { watermark: None },
    )
    .expect("Enabled{None} 的 run_retention 失败");
    assert_eq!(
        enabled_none.raw.deleted, 0,
        "归档已启用但无水位时 raw 必须一行不删"
    );
    assert!(
        enabled_none.raw.blocked_by_archive,
        "归档已启用但无水位时必须标记 blocked_by_archive"
    );
    assert_eq!(
        raw_count(&conn, agent),
        4,
        "归档门禁阻止后 raw 行数必须不变"
    );
    for ts in [oldest, middle, newest_expired, fresh] {
        assert!(raw_has_ts(&conn, agent, ts), "raw ts={ts} 不应被删除");
    }

    // 已启用且有旧水位：只删 ts < watermark 的部分。
    let archive_watermark = NOW - 9 * DAY_MS;
    let enabled_some = run_retention(
        &storage,
        &cfg,
        NOW,
        ArchiveGate::Enabled {
            watermark: Some(archive_watermark),
        },
    )
    .expect("Enabled{Some} 的 run_retention 失败");
    assert_eq!(
        enabled_some.raw.deleted, 1,
        "只应删除归档水位之前的 1 行 raw"
    );
    assert!(
        enabled_some.raw.blocked_by_archive,
        "归档水位早于保留期 cutoff 时仍应标记 blocked_by_archive"
    );
    assert_eq!(
        enabled_some.raw.effective_cutoff,
        Some(archive_watermark),
        "raw 的实际删除边界必须夹紧到归档水位"
    );
    assert_eq!(raw_count(&conn, agent), 3, "删除后 raw 行数");
    assert!(
        !raw_has_ts(&conn, agent, oldest),
        "归档水位前的 raw 应被删除"
    );
    for ts in [middle, newest_expired, fresh] {
        assert!(
            raw_has_ts(&conn, agent, ts),
            "归档水位之后（含未过期）的 raw ts={ts} 必须保留"
        );
    }

    // 只有归档未启用时，才完全按 retention_raw_days 删除。
    let disabled = run_retention(&storage, &cfg, NOW, ArchiveGate::Disabled)
        .expect("Disabled 的 run_retention 失败");
    assert_eq!(
        disabled.raw.deleted, 2,
        "归档未启用时应按保留期删除剩余 2 行过期 raw"
    );
    assert!(
        !disabled.raw.blocked_by_archive,
        "归档未启用时不得标记 blocked_by_archive"
    );
    assert_eq!(
        disabled.raw.effective_cutoff,
        Some(NOW - 7 * DAY_MS),
        "无归档门禁时 raw 的实际删除边界应为保留期 cutoff"
    );
    assert_eq!(raw_count(&conn, agent), 1, "只剩未过期的 fresh raw");
    assert!(
        raw_has_ts(&conn, agent, fresh),
        "未过期 raw 必须保留，实际被删"
    );
}

// ---------------------------------------------------------------------------
// 用例 3：保留期水位夹紧。
//
// - raw 的水位（1m 水位）早于 cutoff 时，raw 只能删到水位；
// - 1m 层受 1h 水位夹紧，且没有 1h 水位时该层一行不删。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2_retention_clamps_to_tier_watermarks() {
    let dir = TempDbDir::new("clamp");
    let storage = open_storage(&dir);
    let agent = "agent-clamp";
    ensure_agent(&storage, agent);

    // first_now：产生一个远早于保留期 cutoff 的 1m 水位。
    const NOW_BASE: i64 = BASE + 8 * HOUR_MS;
    let t0 = NOW_BASE - 10 * DAY_MS;
    let first_now = t0 + 2 * HOUR_MS;
    let now = first_now + 10 * DAY_MS;

    let raw_before_watermark = t0 + 10 * MINUTE_MS;
    // 水位之前最后一个 1m 桶内的 raw，用于让 1m 层出现一个可被夹紧删除的旧桶。
    let raw_pin_watermark = first_now - 90_000;
    // 水位之后（相对首次 downsample 的 now）、但远早于保留期 cutoff 的 raw，必须保留。
    let raw_after_watermark = first_now + 30_000;
    // 1m 层中晚于 1h 水位、但早于 1m cutoff 的桶，必须保留。
    let raw_after_tier = first_now + DAY_MS + 10 * MINUTE_MS;

    let watermark_1m = first_now;
    let cutoff = now - 7 * DAY_MS;
    assert!(
        watermark_1m < cutoff,
        "测试前提：1m 水位必须早于保留期 cutoff"
    );
    assert!(
        raw_after_watermark < cutoff && raw_after_tier < cutoff,
        "测试前提：水位之后的 raw 必须仍早于保留期 cutoff"
    );

    let label = [("host", "clamp")];
    insert(
        &storage,
        &batch(
            agent,
            1,
            first_now,
            vec![
                sample("disk.used", labels(&label), raw_before_watermark, 1.0),
                sample("disk.used", labels(&label), raw_pin_watermark, 2.0),
            ],
        ),
    );

    let first = run_downsample(&storage, first_now, None).expect("首次 run_downsample 失败");
    assert_eq!(
        first.one_minute.watermark,
        Some(watermark_1m),
        "1m 水位应推进到 first_now"
    );
    assert_eq!(
        first.one_hour.watermark,
        Some(first_now),
        "1h 水位应推进到 first_now 整点"
    );

    // 首次 downsample 之后才写入、且 ts 晚于水位的 raw。
    insert(
        &storage,
        &batch(
            agent,
            2,
            first_now,
            vec![sample(
                "disk.used",
                labels(&label),
                raw_after_watermark,
                3.0,
            )],
        ),
    );
    // 用公开的单层聚合接口造一个晚于 1h 水位、早于 1m cutoff 的 1m 桶；
    // 这里不运行完整 downsample，避免把水位继续推进。
    insert(
        &storage,
        &batch(
            agent,
            3,
            first_now,
            vec![sample("disk.used", labels(&label), raw_after_tier, 4.0)],
        ),
    );
    let direct = storage
        .downsample_1m_range(raw_after_tier, raw_after_tier + HOUR_MS)
        .expect("downsample_1m_range 失败");
    assert_eq!(direct.buckets, 1, "应生成 1 个用于夹紧测试的 1m 桶");

    let conn = readonly_conn(&dir);

    // raw 层：1m 水位早于 cutoff，只能删到水位。
    let cfg_raw = HubConfig {
        retention_raw_days: 7,
        retention_1m_days: 90,
        retention_1h_days: 730,
        ..HubConfig::default()
    };
    let raw_run = run_retention(&storage, &cfg_raw, now, ArchiveGate::Disabled)
        .expect("raw 夹紧的 run_retention 失败");
    assert_eq!(
        raw_run.raw.deleted, 2,
        "raw 只应删除水位之前的 2 行（含旧 1m 桶对应的 raw）"
    );
    assert!(
        raw_run.raw.blocked_by_downsample,
        "1m 水位早于 cutoff 时必须标记 blocked_by_downsample"
    );
    assert_eq!(
        raw_run.raw.effective_cutoff,
        Some(watermark_1m),
        "raw 的实际删除边界必须夹紧到 1m 水位"
    );
    assert_eq!(
        raw_run.one_minute.deleted, 0,
        "1m 保留期 90 天时这批 1m 桶不应被删除"
    );
    assert_eq!(raw_count(&conn, agent), 2, "raw 只能删到水位，之后保留");
    assert!(
        !raw_has_ts(&conn, agent, raw_before_watermark),
        "水位之前的 raw 应被删除"
    );
    assert!(
        !raw_has_ts(&conn, agent, raw_pin_watermark),
        "水位之前旧 1m 桶对应的 raw 应被删除"
    );
    assert!(
        raw_has_ts(&conn, agent, raw_after_watermark),
        "水位之后的 raw 必须保留"
    );
    assert!(
        raw_has_ts(&conn, agent, raw_after_tier),
        "水位之后的 raw（即使早于 cutoff）必须保留"
    );
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "disk.used",
        raw_before_watermark,
        (1, 1.0, 1.0),
        "1m 90 天保留期内的旧桶",
    );

    // 1m 层：受 1h 水位（first_now）夹紧，只删 first_now 之前的桶。
    let cfg_1m = HubConfig {
        retention_raw_days: 7,
        retention_1m_days: 7,
        retention_1h_days: 730,
        ..HubConfig::default()
    };
    let tier_run = run_retention(&storage, &cfg_1m, now, ArchiveGate::Disabled)
        .expect("1m 夹紧的 run_retention 失败");
    assert_eq!(
        tier_run.one_minute.deleted, 2,
        "1m 只应删除 1h 水位之前的 2 个桶"
    );
    assert!(
        tier_run.one_minute.blocked_by_downsample,
        "1h 水位早于 1m cutoff 时必须标记 blocked_by_downsample"
    );
    assert_eq!(
        tier_run.one_minute.effective_cutoff,
        Some(first_now),
        "1m 的实际删除边界必须夹紧到 1h 水位"
    );
    assert_eq!(tier_run.raw.deleted, 0, "该轮不应再删除 raw");
    assert!(
        tier_row(&conn, SAMPLES_1M, agent, "disk.used", raw_before_watermark).is_none(),
        "1h 水位之前的 1m 桶应被删除"
    );
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "disk.used",
        raw_after_tier,
        (1, 4.0, 4.0),
        "1h 水位之后的 1m 桶即使早于 1m cutoff 也必须保留",
    );

    // 没有 1h 水位：1m 层一行不删（即使 cutoff 已越过这些桶）。
    storage
        .set_maintenance_state(STATE_DOWNSAMPLE_1H_WATERMARK, "", now)
        .expect("清空 1h 水位失败");
    let skipped = run_retention(&storage, &cfg_1m, now, ArchiveGate::Disabled)
        .expect("无 1h 水位的 run_retention 失败");
    assert_eq!(
        skipped.one_minute.deleted, 0,
        "缺少 1h 水位时 1m 层必须跳过删除"
    );
    assert!(
        skipped.one_minute.skipped_no_watermark,
        "缺少 1h 水位时必须标记 skipped_no_watermark"
    );
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "disk.used",
        raw_after_tier,
        (1, 4.0, 4.0),
        "无 1h 水位时 1m 桶不得被删除",
    );
    assert_eq!(skipped.raw.deleted, 0, "该轮不应再删除 raw");
}
