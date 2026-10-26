//! M4-A2b 查询选层独立集成测试。
//!
//! 只依据 `docs/plans/2026-10-24-m4-alerting-archive.md` §5.2 / §11.1 与
//! `crates/rustboard-core/src/storage/mod.rs` 的公开文档与签名编写；
//! 不参考 `storage/sqlite.rs` 里的 SQL / 算法实现，也不修改生产代码。
//!
//! 数据全部通过公开接口构造：`SqliteStorage::open`、`Storage::insert_batch`、
//! `downsample_1m_range` / `downsample_1h_range`。
//! `rusqlite::Connection` 只以只读方式打开做核对（只用 SELECT），不参与造数或删除。

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OpenFlags};
use rustboard_common::model::{AgentRecord, Labels, Sample, SampleBatch, SeriesQuery, SeriesRow};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::{SampleTier, Storage, BUCKET_1H_MS, BUCKET_1M_MS};

/// 整点对齐的测试基准时间：同时是 2h / 1h / 30min / 5min / 1min 边界。
const HOUR: i64 = 1_699_999_200_000;

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
            "rb-m4-a2b-query-{}-{tag}-{nanos}-{seq}",
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

/// R1b：retention 只删 `aggregated_1m=1` 的 raw；本用例只验证查询选层，
/// 直接补上真实聚合后应有的标记（不改变任何行内容/计数）。
fn mark_raw_aggregated_for_test(dir: &TempDbDir) {
    let conn = Connection::open(dir.db_path()).expect("打开可写测试库失败");
    conn.execute("UPDATE samples SET aggregated_1m = 1", [])
        .expect("标记 raw 已聚合失败");
}

/// R1b：1m retention 只删整小时 clean 行；补上 1h 认领标记。
fn mark_one_minute_clean_for_test(dir: &TempDbDir) {
    let conn = Connection::open(dir.db_path()).expect("打开可写测试库失败");
    conn.execute("UPDATE samples_1m SET aggregated_1h = 1", [])
        .expect("标记 1m 已聚合失败");
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
        boot_id: "boot-m4-a2b".to_string(),
        sent_at,
        samples,
    }
}

fn insert(storage: &SqliteStorage, batch: &SampleBatch) {
    match storage.insert_batch(batch).expect("insert_batch 失败") {
        rustboard_core::storage::IngestOutcome::Inserted { inserted } => {
            assert_eq!(
                inserted,
                batch.samples.len(),
                "insert_batch 返回的插入条数与批次不一致"
            );
        }
        other => panic!("测试批次应正常写入，实际为 {other:?}"),
    }
}

fn query(agent: &str, metrics: &[&str], from: i64, to: i64) -> SeriesQuery {
    SeriesQuery {
        agent_id: agent.to_string(),
        metrics: metrics.iter().map(|metric| (*metric).to_string()).collect(),
        from,
        to,
        limit: 1_000,
    }
}

fn metric_names(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

fn labels_key(labels: &Labels) -> String {
    serde_json::to_string(labels).expect("序列化 labels 失败")
}

type Point = (String, String, i64, f64);

fn sort_points(mut points: Vec<Point>) -> Vec<Point> {
    points.sort_by(|a, b| (&a.0, &a.1, a.2).cmp(&(&b.0, &b.1, b.2)));
    points
}

fn series_points(rows: &[SeriesRow]) -> Vec<Point> {
    sort_points(
        rows.iter()
            .map(|row| {
                (
                    row.metric.clone(),
                    labels_key(&row.labels),
                    row.ts,
                    row.value,
                )
            })
            .collect(),
    )
}

fn point(metric: &str, label_pairs: &[(&str, &str)], ts: i64, value: f64) -> Point {
    (
        metric.to_string(),
        labels_key(&labels(label_pairs)),
        ts,
        value,
    )
}

fn assert_close(actual: f64, expected: f64, context: &str) {
    let tolerance = 1e-9 * expected.abs().max(1.0);
    assert!(
        (actual - expected).abs() <= tolerance,
        "{context}：期望 {expected}，实际 {actual}"
    );
}

fn assert_points_eq(actual: Vec<Point>, expected: Vec<Point>, context: &str) {
    let actual = sort_points(actual);
    let expected = sort_points(expected);
    assert_eq!(
        actual.len(),
        expected.len(),
        "{context}：点数不一致，实际 {actual:?}，期望 {expected:?}"
    );
    for (index, (actual, expected)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            (&actual.0, &actual.1, actual.2),
            (&expected.0, &expected.1, expected.2),
            "{context}：第 {index} 个点的序列或桶起点不一致"
        );
        assert_close(
            actual.3,
            expected.3,
            &format!("{context}：第 {index} 个点（ts={}）的值", actual.2),
        );
    }
}

/// `samples_1m` / `samples_1h` 的只读行快照。
#[derive(Debug)]
struct TierAggregate {
    labels: Labels,
    bucket_ts: i64,
    min_value: f64,
    max_value: f64,
    avg_value: f64,
    last_value: f64,
    count: i64,
}

fn read_tier_rows(
    conn: &Connection,
    table: &'static str,
    agent: &str,
    metric: &str,
) -> Vec<TierAggregate> {
    // table 只可能是下面两个常量，不拼接外部输入。
    let table = match table {
        SAMPLES_1M => SAMPLES_1M,
        SAMPLES_1H => SAMPLES_1H,
        other => panic!("未知聚合表 {other}"),
    };
    let sql = format!(
        "SELECT labels, bucket_ts, min_value, max_value, avg_value, last_value, \"count\" \
         FROM {table} WHERE agent_id = ?1 AND metric = ?2 ORDER BY bucket_ts"
    );
    let mut stmt = conn.prepare(&sql).expect("准备只读聚合行查询失败");
    let rows = stmt
        .query_map(params![agent, metric], |row| {
            let raw_labels: String = row.get(0)?;
            let labels: Labels = serde_json::from_str(&raw_labels).expect("解析 labels JSON 失败");
            Ok(TierAggregate {
                labels,
                bucket_ts: row.get(1)?,
                min_value: row.get(2)?,
                max_value: row.get(3)?,
                avg_value: row.get(4)?,
                last_value: row.get(5)?,
                count: row.get(6)?,
            })
        })
        .expect("只读查询聚合行失败");
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .expect("收集聚合行失败")
}

fn tier_map(rows: Vec<TierAggregate>) -> BTreeMap<(String, i64), TierAggregate> {
    rows.into_iter()
        .map(|row| ((labels_key(&row.labels), row.bucket_ts), row))
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn assert_tier_row(
    map: &BTreeMap<(String, i64), TierAggregate>,
    label_pairs: &[(&str, &str)],
    bucket_ts: i64,
    min_value: f64,
    max_value: f64,
    avg_value: f64,
    last_value: f64,
    count: i64,
    context: &str,
) {
    let key = (labels_key(&labels(label_pairs)), bucket_ts);
    let row = map.get(&key).unwrap_or_else(|| {
        panic!(
            "{context}：缺少 bucket_ts={bucket_ts} 的聚合行，实际 keys {:?}",
            map.keys().collect::<Vec<_>>()
        )
    });
    assert_close(row.min_value, min_value, &format!("{context}：min_value"));
    assert_close(row.max_value, max_value, &format!("{context}：max_value"));
    assert_close(row.avg_value, avg_value, &format!("{context}：avg_value"));
    assert_close(
        row.last_value,
        last_value,
        &format!("{context}：last_value"),
    );
    assert_eq!(row.count, count, "{context}：count");
}

fn table_count(conn: &Connection, table: &'static str) -> i64 {
    let table = match table {
        SAMPLES_1M => SAMPLES_1M,
        SAMPLES_1H => SAMPLES_1H,
        "samples" => "samples",
        other => panic!("未知表 {other}"),
    };
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap_or_else(|err| panic!("统计 {table} 行数失败：{err}"))
}

// ---------------------------------------------------------------------------
// 用例 1：1m 层按 count 加权、labels 不合并、范围外为空。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2b_one_minute_tier_weighted_by_count_per_label() {
    let dir = TempDbDir::new("1m");
    let storage = open_storage(&dir);
    ensure_agent(&storage, "agent-1m");

    let a = [("host", "a")];
    let b = [("host", "b")];
    let samples = vec![
        // host=a：5 个分钟桶，其中 base+120s 桶有 3 条、base+300s 桶有 2 条。
        sample("cpu.usage", labels(&a), HOUR, 10.0),
        sample("cpu.usage", labels(&a), HOUR + 10_000, 20.0),
        sample("cpu.usage", labels(&a), HOUR + 60_000, 30.0),
        sample("cpu.usage", labels(&a), HOUR + 120_000, 40.0),
        sample("cpu.usage", labels(&a), HOUR + 130_000, 60.0),
        sample("cpu.usage", labels(&a), HOUR + 140_000, 50.0),
        sample("cpu.usage", labels(&a), HOUR + 240_000, 90.0),
        sample("cpu.usage", labels(&a), HOUR + 300_000, 100.0),
        sample("cpu.usage", labels(&a), HOUR + 310_000, 110.0),
        // host=b：同 metric、不同 labels，必须单独成序列。
        sample("cpu.usage", labels(&b), HOUR, 5.0),
        sample("cpu.usage", labels(&b), HOUR + 60_000, 8.0),
        sample("cpu.usage", labels(&b), HOUR + 70_000, 10.0),
        sample("cpu.usage", labels(&b), HOUR + 80_000, 12.0),
        sample("cpu.usage", labels(&b), HOUR + 360_000, 50.0),
        sample("cpu.usage", labels(&b), HOUR + 370_000, 60.0),
        sample("cpu.usage", labels(&b), HOUR + 380_000, 70.0),
    ];
    let expected_samples = samples.len();
    insert(&storage, &batch("agent-1m", 1, HOUR, samples));

    let downsample = storage
        .downsample_1m_range(HOUR, HOUR + 600_000)
        .expect("downsample_1m_range 失败");
    assert_eq!(downsample.buckets, 8, "1m 桶数（两个 labels 分开计）");
    assert_eq!(downsample.rows, expected_samples, "参与聚合的 raw 行数");

    // 只读核对 1m 表：每桶 min/max/avg/last/count 与手算一致。
    let conn = readonly_conn(&dir);
    let aggregates = read_tier_rows(&conn, SAMPLES_1M, "agent-1m", "cpu.usage");
    let aggregates = tier_map(aggregates);
    assert_eq!(aggregates.len(), 8, "1m 表行数");
    assert_tier_row(
        &aggregates,
        &a,
        HOUR,
        10.0,
        20.0,
        15.0,
        20.0,
        2,
        "1m/a/base",
    );
    assert_tier_row(
        &aggregates,
        &a,
        HOUR + 60_000,
        30.0,
        30.0,
        30.0,
        30.0,
        1,
        "1m/a/base+60s",
    );
    assert_tier_row(
        &aggregates,
        &a,
        HOUR + 120_000,
        40.0,
        60.0,
        50.0,
        50.0,
        3,
        "1m/a/base+120s",
    );
    assert_tier_row(
        &aggregates,
        &a,
        HOUR + 240_000,
        90.0,
        90.0,
        90.0,
        90.0,
        1,
        "1m/a/base+240s",
    );
    assert_tier_row(
        &aggregates,
        &a,
        HOUR + 300_000,
        100.0,
        110.0,
        105.0,
        110.0,
        2,
        "1m/a/base+300s",
    );
    assert_tier_row(&aggregates, &b, HOUR, 5.0, 5.0, 5.0, 5.0, 1, "1m/b/base");
    assert_tier_row(
        &aggregates,
        &b,
        HOUR + 60_000,
        8.0,
        12.0,
        10.0,
        12.0,
        3,
        "1m/b/base+60s",
    );
    assert_tier_row(
        &aggregates,
        &b,
        HOUR + 360_000,
        50.0,
        70.0,
        60.0,
        70.0,
        3,
        "1m/b/base+360s",
    );

    // 300s 查询桶：值必须按 count 加权，而不是 1m 桶均值的简单平均。
    let rows = storage
        .query_series_tiered(
            &query("agent-1m", &["cpu.usage"], HOUR, HOUR + 600_000),
            300_000,
            SampleTier::OneMinute,
        )
        .expect("query_series_tiered(1m) 失败");
    // host=a base 桶：15*2 + 30*1 + 50*3 + 90*1 = 300，count=7。
    // 简单平均是 (15+30+50+90)/4 = 46.25，必须不同。
    // host=b base 桶：5*1 + 10*3 = 35，count=4，加权值 8.75（简单平均 7.5）。
    assert_points_eq(
        series_points(&rows),
        vec![
            point("cpu.usage", &a, HOUR, 300.0 / 7.0),
            point("cpu.usage", &a, HOUR + 300_000, 105.0),
            point("cpu.usage", &b, HOUR, 35.0 / 4.0),
            point("cpu.usage", &b, HOUR + 300_000, 60.0),
        ],
        "1m 层 300s 加权查询",
    );
    let weighted_a = rows
        .iter()
        .find(|row| row.labels == labels(&a) && row.ts == HOUR)
        .expect("缺少 host=a 的 300s 桶");
    assert!(
        (weighted_a.value - 46.25).abs() > 1e-9,
        "加权平均不得退化成简单平均"
    );

    // 范围外与无数据范围必须为空。
    let outside = storage
        .query_series_tiered(
            &query("agent-1m", &["cpu.usage"], HOUR - 3_600_000, HOUR - 1),
            300_000,
            SampleTier::OneMinute,
        )
        .expect("范围外 1m 查询失败");
    assert!(outside.is_empty(), "范围外查询必须为空，实际 {outside:?}");

    let empty_range = storage
        .query_series_tiered(
            &query("agent-1m", &["cpu.usage"], HOUR + 900_000, HOUR + 1_200_000),
            300_000,
            SampleTier::OneMinute,
        )
        .expect("无数据范围 1m 查询失败");
    assert!(empty_range.is_empty(), "空范围查询必须为空");
}

// ---------------------------------------------------------------------------
// 用例 2：1h 层把两个 1m 桶合成 2h 请求桶，按 count 加权。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2b_one_hour_tier_weighted_across_hours() {
    let dir = TempDbDir::new("1h");
    let storage = open_storage(&dir);
    ensure_agent(&storage, "agent-1h");

    let label = [("host", "h1")];
    let samples = vec![
        sample("cpu.usage", labels(&label), HOUR, 10.0),
        sample("cpu.usage", labels(&label), HOUR + 10_000, 20.0),
        sample("cpu.usage", labels(&label), HOUR + 3_600_000, 30.0),
        sample("cpu.usage", labels(&label), HOUR + 3_610_000, 30.0),
        sample("cpu.usage", labels(&label), HOUR + 3_620_000, 30.0),
        sample("cpu.usage", labels(&label), HOUR + 3_630_000, 30.0),
    ];
    insert(&storage, &batch("agent-1h", 1, HOUR, samples));

    let downsample_1m = storage
        .downsample_1m_range(HOUR, HOUR + 7_200_000)
        .expect("downsample_1m_range 失败");
    assert_eq!(downsample_1m.buckets, 2, "跨两个小时的 1m 桶数");
    assert_eq!(downsample_1m.rows, 6, "参与 1m 聚合的 raw 行数");

    let downsample_1h = storage
        .downsample_1h_range(HOUR, HOUR + 7_200_000)
        .expect("downsample_1h_range 失败");
    assert_eq!(downsample_1h.buckets, 2, "两个 1h 桶");
    assert_eq!(downsample_1h.rows, 2, "参与 1h 聚合的 1m 行数");

    // 只读核对 1h 表：last/min/max 不参与 API 选值，但存储值必须正确。
    let conn = readonly_conn(&dir);
    let aggregates = tier_map(read_tier_rows(&conn, SAMPLES_1H, "agent-1h", "cpu.usage"));
    assert_eq!(aggregates.len(), 2, "1h 表行数");
    assert_tier_row(
        &aggregates,
        &label,
        HOUR,
        10.0,
        20.0,
        15.0,
        20.0,
        2,
        "1h/第一个小时",
    );
    assert_tier_row(
        &aggregates,
        &label,
        HOUR + 3_600_000,
        30.0,
        30.0,
        30.0,
        30.0,
        4,
        "1h/第二个小时",
    );

    // 2h 请求桶：两个 1h 桶合并，值 = (15*2 + 30*4) / (2+4) = 25。
    // 简单平均是 (15+30)/2 = 22.5；last=30、min=10、max=30，均不是 25。
    let rows = storage
        .query_series_tiered(
            &query("agent-1h", &["cpu.usage"], HOUR, HOUR + 7_200_000),
            7_200_000,
            SampleTier::OneHour,
        )
        .expect("query_series_tiered(1h) 失败");
    assert_points_eq(
        series_points(&rows),
        vec![point("cpu.usage", &label, HOUR, 25.0)],
        "1h 层 2h 加权查询",
    );
    let value = rows[0].value;
    for forbidden in [22.5_f64, 10.0, 30.0] {
        assert!(
            (value - forbidden).abs() > 1e-9,
            "2h 桶值必须是 count 加权平均 25，不能取到 {forbidden}"
        );
    }
}

// ---------------------------------------------------------------------------
// 用例 3：Raw 层与旧 query_series_bucketed 逐点一致；非法 bucket 返回 Err。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2b_raw_tier_matches_legacy_bucketed_and_rejects_bad_bucket() {
    let dir = TempDbDir::new("raw");
    let storage = open_storage(&dir);
    ensure_agent(&storage, "agent-raw");

    let label = [("host", "r1")];
    let samples = vec![
        sample("cpu.usage", labels(&label), HOUR, 5.0),
        sample("cpu.usage", labels(&label), HOUR + 10_000, 7.0),
        sample("cpu.usage", labels(&label), HOUR + 60_000, 11.0),
        sample("cpu.usage", labels(&label), HOUR + 130_000, 13.0),
        sample("cpu.usage", labels(&label), HOUR + 250_000, 17.0),
        sample("mem.used", labels(&[]), HOUR + 5_000, 1.0),
        sample("mem.used", labels(&[]), HOUR + 65_000, 2.0),
        sample("mem.used", labels(&[]), HOUR + 250_000, 3.0),
    ];
    insert(&storage, &batch("agent-raw", 1, HOUR, samples));

    let query = query(
        "agent-raw",
        &["cpu.usage", "mem.used"],
        HOUR,
        HOUR + 300_000,
    );
    for bucket_ms in [1_000_i64, 60_000, 300_000] {
        let tiered = storage
            .query_series_tiered(&query, bucket_ms, SampleTier::Raw)
            .unwrap_or_else(|err| panic!("Raw tier bucket_ms={bucket_ms} 查询失败：{err}"));
        let legacy = storage
            .query_series_bucketed(&query, bucket_ms)
            .unwrap_or_else(|err| panic!("旧 bucketed bucket_ms={bucket_ms} 查询失败：{err}"));
        assert!(
            !tiered.is_empty() && !legacy.is_empty(),
            "bucket_ms={bucket_ms} 的比较不能是空集对空集"
        );
        assert_points_eq(
            series_points(&tiered),
            series_points(&legacy),
            &format!("Raw 层与旧 bucketed 在 bucket_ms={bucket_ms} 时必须逐点一致"),
        );
    }

    // 明确文档化的错误路径：bucket 0 / -1 必须返回 Err，而不是 panic 或静默。
    for bucket_ms in [0_i64, -1_i64] {
        let result = storage.query_series_tiered(&query, bucket_ms, SampleTier::Raw);
        assert!(
            result.is_err(),
            "非法 bucket_ms={bucket_ms} 必须返回 Err，实际 {result:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 用例 4：latest_samples 的 raw -> 1m -> 1h 回退、过滤与 since 边界。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2b_latest_samples_falls_back_from_raw_to_1m_to_1h() {
    let dir = TempDbDir::new("latest");
    let storage = open_storage(&dir);
    ensure_agent(&storage, "agent-a");
    ensure_agent(&storage, "agent-b");

    let label = [("host", "a")];
    insert(
        &storage,
        &batch(
            "agent-a",
            1,
            HOUR,
            vec![
                sample("cpu.usage", labels(&label), HOUR, 10.0),
                sample("cpu.usage", labels(&label), HOUR + 30_000, 30.0),
            ],
        ),
    );
    insert(
        &storage,
        &batch(
            "agent-b",
            1,
            HOUR,
            vec![sample("mem.used", labels(&[]), HOUR + 120_000, 7.0)],
        ),
    );

    // 先生成 1m 数据，保证 raw 存在时也能验证「不会误用 1m」。
    let downsample = storage
        .downsample_1m_range(HOUR, HOUR + 60_000)
        .expect("downsample_1m_range 失败");
    assert_eq!(downsample.buckets, 1);
    assert_eq!(downsample.rows, 2);

    // ---- raw 有数据：只返回 raw 点 ----
    let raw_rows = storage
        .latest_samples(HOUR - 1, &[], None)
        .expect("raw 阶段 latest_samples 失败");
    assert_eq!(raw_rows.len(), 2, "raw 阶段应返回两条序列的最新点");
    // 顺序按文档：agent_id、metric、labels 升序。
    assert_eq!(raw_rows[0].agent_id, "agent-a");
    assert_eq!(raw_rows[0].metric, "cpu.usage");
    assert_eq!(raw_rows[0].labels, labels(&label));
    assert_eq!(raw_rows[0].ts, HOUR + 30_000, "必须返回 raw 的最大 ts");
    assert_eq!(raw_rows[0].value, 30.0);
    assert_eq!(raw_rows[1].agent_id, "agent-b");
    assert_eq!(raw_rows[1].metric, "mem.used");
    assert_eq!(raw_rows[1].ts, HOUR + 120_000);
    assert_eq!(raw_rows[1].value, 7.0);

    // metrics 过滤。
    let cpu_only = storage
        .latest_samples(HOUR - 1, &metric_names(&["cpu.usage"]), None)
        .expect("metrics 过滤失败");
    assert_eq!(cpu_only.len(), 1);
    assert_eq!(cpu_only[0].metric, "cpu.usage");
    let mem_only = storage
        .latest_samples(HOUR - 1, &metric_names(&["mem.used"]), None)
        .expect("metrics 过滤失败");
    assert_eq!(mem_only.len(), 1);
    assert_eq!(mem_only[0].agent_id, "agent-b");
    assert!(
        storage
            .latest_samples(HOUR - 1, &metric_names(&["disk.used"]), None)
            .expect("不存在的 metric 查询失败")
            .is_empty(),
        "不存在的 metric 必须返回空"
    );

    // agent 过滤。
    let a_only = storage
        .latest_samples(HOUR - 1, &[], Some("agent-a"))
        .expect("agent 过滤失败");
    assert_eq!(a_only.len(), 1);
    assert_eq!(a_only[0].agent_id, "agent-a");
    let b_only = storage
        .latest_samples(HOUR - 1, &[], Some("agent-b"))
        .expect("agent 过滤失败");
    assert_eq!(b_only.len(), 1);
    assert_eq!(b_only[0].agent_id, "agent-b");

    // ---- 删除 raw：回退 1m，ts=bucket_ts，value=last_value ----
    mark_raw_aggregated_for_test(&dir);
    let pruned = storage
        .prune_samples_before(HOUR + 10_000_000)
        .expect("删除 raw 失败");
    assert_eq!(pruned.deleted, 3, "应删除 3 条 raw");
    assert_eq!(table_count(&readonly_conn(&dir), "samples"), 0);

    let minute_rows = storage
        .latest_samples(HOUR - 1, &[], None)
        .expect("1m 回退失败");
    assert_eq!(minute_rows.len(), 1, "raw 删除后应回退到 1m");
    assert_eq!(minute_rows[0].agent_id, "agent-a");
    assert_eq!(minute_rows[0].metric, "cpu.usage");
    assert_eq!(minute_rows[0].labels, labels(&label));
    assert_eq!(minute_rows[0].ts, HOUR, "1m 回退必须用 bucket_ts 作为 ts");
    assert_eq!(
        minute_rows[0].value, 30.0,
        "1m 回退必须用 last_value（30），不是 avg（20）"
    );
    assert!(
        (minute_rows[0].value - 20.0).abs() > 1e-9,
        "1m 回退不得误用 avg_value"
    );

    // since 落在桶中间仍可见；到达/超过桶尾为空。
    let inside = storage
        .latest_samples(HOUR + 30_000, &[], None)
        .expect("since 在桶内查询失败");
    assert_eq!(inside.len(), 1, "since 在桶中间时 1m 桶仍应可见");
    assert_eq!(inside[0].ts, HOUR);
    let edge_inside = storage
        .latest_samples(HOUR + BUCKET_1M_MS - 1, &[], None)
        .expect("since 在桶尾前查询失败");
    assert_eq!(edge_inside.len(), 1, "since 在桶尾前 1ms 仍应可见");
    let at_tail = storage
        .latest_samples(HOUR + BUCKET_1M_MS, &[], None)
        .expect("since 在桶尾查询失败");
    assert!(
        at_tail.is_empty(),
        "since 到达桶尾（bucket_ts + 1m）必须为空，实际 {at_tail:?}"
    );
    let beyond_tail = storage
        .latest_samples(HOUR + BUCKET_1M_MS + 1, &[], None)
        .expect("since 超过桶尾查询失败");
    assert!(beyond_tail.is_empty(), "since 超过桶尾必须为空");

    // 回退后的过滤仍然生效。
    assert!(
        storage
            .latest_samples(HOUR - 1, &metric_names(&["mem.used"]), None)
            .expect("1m 回退 metrics 过滤失败")
            .is_empty(),
        "1m 表中没有 mem.used，不得凭空返回 raw 或其它层数据"
    );
    assert!(
        storage
            .latest_samples(HOUR - 1, &[], Some("agent-b"))
            .expect("1m 回退 agent 过滤失败")
            .is_empty(),
        "1m 表中没有 agent-b 数据"
    );

    // ---- 生成 1h 后删除 1m：回退 1h ----
    let downsample_1h = storage
        .downsample_1h_range(HOUR, HOUR + 3_600_000)
        .expect("downsample_1h_range 失败");
    assert_eq!(downsample_1h.buckets, 1);
    assert_eq!(downsample_1h.rows, 1);

    let conn = readonly_conn(&dir);
    let hour_aggregates = tier_map(read_tier_rows(&conn, SAMPLES_1H, "agent-a", "cpu.usage"));
    assert_eq!(hour_aggregates.len(), 1);
    assert_tier_row(
        &hour_aggregates,
        &label,
        HOUR,
        10.0,
        30.0,
        20.0,
        30.0,
        2,
        "latest/1h",
    );

    mark_one_minute_clean_for_test(&dir);
    let pruned_1m = storage
        .prune_samples_1m_before(HOUR + BUCKET_1H_MS)
        .expect("删除 1m 失败");
    assert_eq!(pruned_1m.deleted, 1, "应删除 1 条 1m");
    assert_eq!(table_count(&conn, SAMPLES_1M), 0);

    let hour_rows = storage
        .latest_samples(HOUR - 1, &[], None)
        .expect("1h 回退失败");
    assert_eq!(hour_rows.len(), 1, "1m 删除后应回退到 1h");
    assert_eq!(hour_rows[0].agent_id, "agent-a");
    assert_eq!(hour_rows[0].metric, "cpu.usage");
    assert_eq!(hour_rows[0].ts, HOUR, "1h 回退必须用 bucket_ts 作为 ts");
    assert_eq!(
        hour_rows[0].value, 30.0,
        "1h 回退必须用 last_value（30），不是 avg（20）"
    );

    let hour_inside = storage
        .latest_samples(HOUR + 1_800_000, &[], None)
        .expect("since 在 1h 桶内查询失败");
    assert_eq!(hour_inside.len(), 1, "since 在 1h 桶中间时仍应可见");
    assert_eq!(hour_inside[0].ts, HOUR);
    let hour_edge = storage
        .latest_samples(HOUR + BUCKET_1H_MS - 1, &[], None)
        .expect("since 在 1h 桶尾前查询失败");
    assert_eq!(hour_edge.len(), 1, "since 在 1h 桶尾前仍应可见");
    let hour_at_tail = storage
        .latest_samples(HOUR + BUCKET_1H_MS, &[], None)
        .expect("since 在 1h 桶尾查询失败");
    assert!(
        hour_at_tail.is_empty(),
        "since 到达 1h 桶尾必须为空，实际 {hour_at_tail:?}"
    );
    let hour_beyond = storage
        .latest_samples(HOUR + BUCKET_1H_MS + 1, &[], None)
        .expect("since 超过 1h 桶尾查询失败");
    assert!(hour_beyond.is_empty(), "since 超过 1h 桶尾必须为空");

    // 1h 回退后的过滤。
    let cpu_1h = storage
        .latest_samples(HOUR - 1, &metric_names(&["cpu.usage"]), None)
        .expect("1h 回退 metrics 过滤失败");
    assert_eq!(cpu_1h.len(), 1);
    assert!(storage
        .latest_samples(HOUR - 1, &metric_names(&["mem.used"]), None)
        .expect("1h 回退 mem 查询失败")
        .is_empty());
    assert!(storage
        .latest_samples(HOUR - 1, &[], Some("agent-b"))
        .expect("1h 回退 agent 过滤失败")
        .is_empty());
}

// ---------------------------------------------------------------------------
// 用例 5：空库上三层查询与 latest_samples 都必须返回空，不得凭空造点。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2b_empty_database_returns_empty_for_all_tiers() {
    let dir = TempDbDir::new("empty");
    let storage = open_storage(&dir);
    ensure_agent(&storage, "agent-empty");

    let query = query("agent-empty", &["cpu.usage"], HOUR, HOUR + 300_000);
    for (tier, bucket_ms) in [
        (SampleTier::Raw, 60_000),
        (SampleTier::OneMinute, BUCKET_1M_MS),
        (SampleTier::OneHour, BUCKET_1H_MS),
    ] {
        let rows = storage
            .query_series_tiered(&query, bucket_ms, tier)
            .unwrap_or_else(|err| panic!("空库 {tier:?} 查询失败：{err}"));
        assert!(rows.is_empty(), "空库 {tier:?} 查询必须为空，实际 {rows:?}");
    }

    let latest = storage
        .latest_samples(HOUR, &[], Some("agent-empty"))
        .expect("空库 latest_samples 失败");
    assert!(latest.is_empty(), "空库 latest_samples 必须为空");
}

// ---------------------------------------------------------------------------
// 用例 6：bucket_ms 小于层粒度时按文档返回更细桶（每层行各自成组）。
//
// `storage/mod.rs` 的公开文档：调用方应保证 `bucket_ms >= tier.granularity_ms()`，
// 否则“桶会比该层粒度还细”。本用例只断言这一文档化结果：1m/1h 行本来就在
// 层边界上，所以更细的 bucket 不会把相邻层行合并；不假设错误或自动提升行为
// （自动提升是方案 §5.2 里 HTTP 层的职责）。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2b_bucket_below_tier_granularity_keeps_layer_rows_separate() {
    assert_eq!(BUCKET_1M_MS, 60_000);
    assert_eq!(BUCKET_1H_MS, 3_600_000);
    assert_eq!(SampleTier::Raw.granularity_ms(), 1);
    assert_eq!(SampleTier::OneMinute.granularity_ms(), BUCKET_1M_MS);
    assert_eq!(SampleTier::OneHour.granularity_ms(), BUCKET_1H_MS);

    let dir = TempDbDir::new("below-granularity");
    let storage = open_storage(&dir);
    ensure_agent(&storage, "agent-boundary");

    let label = [("host", "b1")];
    let samples = vec![
        sample("cpu.usage", labels(&label), HOUR, 10.0),
        sample("cpu.usage", labels(&label), HOUR + 60_000, 20.0),
        sample("cpu.usage", labels(&label), HOUR + 3_600_000, 30.0),
        sample("cpu.usage", labels(&label), HOUR + 3_660_000, 50.0),
    ];
    insert(&storage, &batch("agent-boundary", 1, HOUR, samples));

    let downsample_1m = storage
        .downsample_1m_range(HOUR, HOUR + 7_200_000)
        .expect("downsample_1m_range 失败");
    assert_eq!(downsample_1m.buckets, 4);
    assert_eq!(downsample_1m.rows, 4);
    let downsample_1h = storage
        .downsample_1h_range(HOUR, HOUR + 7_200_000)
        .expect("downsample_1h_range 失败");
    assert_eq!(downsample_1h.buckets, 2);
    assert_eq!(downsample_1h.rows, 4);

    // 只读核对两层存储值，确保下面的查询预期有据可依。
    let conn = readonly_conn(&dir);
    let minute_rows = tier_map(read_tier_rows(
        &conn,
        SAMPLES_1M,
        "agent-boundary",
        "cpu.usage",
    ));
    assert_eq!(minute_rows.len(), 4);
    assert_tier_row(
        &minute_rows,
        &label,
        HOUR,
        10.0,
        10.0,
        10.0,
        10.0,
        1,
        "below/1m/0",
    );
    assert_tier_row(
        &minute_rows,
        &label,
        HOUR + 60_000,
        20.0,
        20.0,
        20.0,
        20.0,
        1,
        "below/1m/1",
    );
    assert_tier_row(
        &minute_rows,
        &label,
        HOUR + 3_600_000,
        30.0,
        30.0,
        30.0,
        30.0,
        1,
        "below/1m/2",
    );
    assert_tier_row(
        &minute_rows,
        &label,
        HOUR + 3_660_000,
        50.0,
        50.0,
        50.0,
        50.0,
        1,
        "below/1m/3",
    );
    let hour_rows = tier_map(read_tier_rows(
        &conn,
        SAMPLES_1H,
        "agent-boundary",
        "cpu.usage",
    ));
    assert_eq!(hour_rows.len(), 2);
    assert_tier_row(
        &hour_rows,
        &label,
        HOUR,
        10.0,
        20.0,
        15.0,
        20.0,
        2,
        "below/1h/0",
    );
    assert_tier_row(
        &hour_rows,
        &label,
        HOUR + 3_600_000,
        30.0,
        50.0,
        40.0,
        50.0,
        2,
        "below/1h/1",
    );

    // 1m：bucket_ms=30s < 60s。文档说明桶会更细；层行都在整分钟，故每行各成一组。
    let minute_query = query("agent-boundary", &["cpu.usage"], HOUR, HOUR + 7_200_000);
    let minute_at_granularity = storage
        .query_series_tiered(&minute_query, BUCKET_1M_MS, SampleTier::OneMinute)
        .expect("1m 层按粒度查询失败");
    let minute_below = storage
        .query_series_tiered(&minute_query, 30_000, SampleTier::OneMinute)
        .expect("1m 层小于粒度查询失败");
    let expected_minute = vec![
        point("cpu.usage", &label, HOUR, 10.0),
        point("cpu.usage", &label, HOUR + 60_000, 20.0),
        point("cpu.usage", &label, HOUR + 3_600_000, 30.0),
        point("cpu.usage", &label, HOUR + 3_660_000, 50.0),
    ];
    assert_points_eq(
        series_points(&minute_at_granularity),
        expected_minute.clone(),
        "1m 层 bucket_ms=粒度",
    );
    assert_points_eq(
        series_points(&minute_below),
        expected_minute,
        "1m 层 bucket_ms=30s（小于粒度，桶更细但不能合并层行）",
    );

    // 1h：bucket_ms=30min < 60min，行为同文档描述。
    let hour_query = query("agent-boundary", &["cpu.usage"], HOUR, HOUR + 7_200_000);
    let hour_at_granularity = storage
        .query_series_tiered(&hour_query, BUCKET_1H_MS, SampleTier::OneHour)
        .expect("1h 层按粒度查询失败");
    let hour_below = storage
        .query_series_tiered(&hour_query, 1_800_000, SampleTier::OneHour)
        .expect("1h 层小于粒度查询失败");
    let expected_hour = vec![
        point("cpu.usage", &label, HOUR, 15.0),
        point("cpu.usage", &label, HOUR + 3_600_000, 40.0),
    ];
    assert_points_eq(
        series_points(&hour_at_granularity),
        expected_hour.clone(),
        "1h 层 bucket_ms=粒度",
    );
    assert_points_eq(
        series_points(&hour_below),
        expected_hour,
        "1h 层 bucket_ms=30min（小于粒度，桶更细但不能合并层行）",
    );
}
