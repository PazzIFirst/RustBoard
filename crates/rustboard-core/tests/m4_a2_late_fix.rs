//! R1b：迟到增量合并、归档保留门禁与 dirty hour 的独立集成测试。
//!
//! 只依据 `docs/plans/2026-10-27-open-issues-remediation.md` §4.2 的验收标准
//! 与 `crates/rustboard-core/src/downsample.rs` 的公开类型 / 函数文档 / 签名
//! 编写；不参考内部算法，也不修改生产代码。
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
    audit_legacy_raw_rows, maintenance_status, run_downsample, run_retention, ArchiveGate,
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

fn tier_count(conn: &Connection, table: &'static str, hour_start: i64) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE bucket_ts >= ?1 AND bucket_ts < ?2");
    conn.query_row(&sql, params![hour_start, hour_start + HOUR_MS], |row| {
        row.get(0)
    })
    .unwrap_or_else(|err| panic!("统计 {table} 小时行数失败：{err}"))
}

// ---------------------------------------------------------------------------
// 用例 1：10h 迟到增量合并。
//
// R1b 取消回拨：迟到行由 `aggregated_1m=0` 直接认领，水位只前进；1m 从
// count=2/avg=15 合并到 3/20，1h 随整小时重算。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2_late_raw_ten_hours_replay_uses_incremental_delta() {
    let dir = TempDbDir::new("replay");
    let storage = open_storage(&dir);
    let agent = "agent-late";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 13 * HOUR_MS;
    let old_hour = NOW - 10 * HOUR_MS;
    let old_bucket = old_hour + 2 * MINUTE_MS;
    assert!(
        old_bucket < NOW - 2 * HOUR_MS,
        "测试前提：迟到桶必须早于旧实现「最近 2 小时」窗口"
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
    assert_eq!(first.one_minute.watermark, Some(NOW));
    assert_eq!(first.one_hour.watermark, Some(NOW));

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

    // 同一旧桶的迟到 raw（ts 早于 now 10h，seq 更新）。
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
        "R1b 不得因迟到回拨 1m 水位"
    );
    assert_eq!(
        second.one_hour.watermark, first.one_hour.watermark,
        "R1b 不得因迟到回拨 1h 水位"
    );
    assert_eq!(second.one_minute.watermark, Some(NOW));
    assert_eq!(second.one_hour.watermark, Some(NOW));

    // 1m：10/20/30 → count=3、avg=20、min=10、max=30、last=30。
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "cpu.usage",
        old_bucket,
        (3, 20.0, 30.0),
        "迟到重放后的 1m 旧桶",
    );
    // 1h 由整小时 1m 重算：同一旧桶，val 同样 3/20/30。
    assert_aggregate(
        &conn,
        SAMPLES_1H,
        agent,
        "cpu.usage",
        old_hour,
        (3, 20.0, 30.0),
        "迟到重放后的 1h 旧桶",
    );

    // 重放幂等：再跑一轮不得重复计数。
    let third = run_downsample(&storage, NOW, None).expect("重放幂等 run_downsample 失败");
    assert_eq!(
        third.one_minute.rows, 0,
        "没有新的未聚合 raw 时不得再次合并"
    );
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "cpu.usage",
        old_bucket,
        (3, 20.0, 30.0),
        "幂等重跑后的 1m 旧桶",
    );
    assert_aggregate(
        &conn,
        SAMPLES_1H,
        agent,
        "cpu.usage",
        old_hour,
        (3, 20.0, 30.0),
        "幂等重跑后的 1h 旧桶",
    );

    let status =
        maintenance_status(&storage, &HubConfig::default(), NOW).expect("maintenance_status 失败");
    assert_eq!(status.unaggregated_rows, 0);
    assert_eq!(status.invalid_timestamp_rows, 0);
}

// ---------------------------------------------------------------------------
// 用例 2：归档门禁。
//
// 归档启用时 raw 只能通过 `archive_object_id` → `uploaded` 的 join 删除；
// 仅有一个 last_archived_ts 水位不能证明可删。ledger pending 时完全跳过。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2_archive_gate_requires_uploaded_claim_not_watermark() {
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
    assert_eq!(downsample.one_minute.watermark, Some(NOW));

    let cfg = HubConfig {
        retention_raw_days: 7,
        retention_1m_days: 90,
        retention_1h_days: 730,
        ..HubConfig::default()
    };
    let conn = readonly_conn(&dir);
    assert_eq!(raw_count(&conn, agent), 4, "造数后 raw 行数");

    // 归档已启用但还没有成功归档：raw 一律不删。
    let enabled_none = run_retention(
        &storage,
        &cfg,
        NOW,
        ArchiveGate::Enabled { watermark: None },
    )
    .expect("Enabled{None} 的 run_retention 失败");
    assert_eq!(
        enabled_none.raw.deleted, 0,
        "归档已启用但无 uploaded 对象时 raw 必须一行不删"
    );
    assert!(
        enabled_none.raw.blocked_by_archive,
        "归档已启用但无可删对象时必须标记 blocked_by_archive"
    );
    assert_eq!(raw_count(&conn, agent), 4);

    // 只有旧水位（没有任何 uploaded claim）：仍然一行不删。
    let enabled_some = run_retention(
        &storage,
        &cfg,
        NOW,
        ArchiveGate::Enabled {
            watermark: Some(NOW),
        },
    )
    .expect("Enabled{Some} 的 run_retention 失败");
    assert_eq!(
        enabled_some.raw.deleted, 0,
        "last_archived_ts 水位不能单独证明 raw 可删；必须 uploaded join"
    );
    assert_eq!(
        enabled_some.raw.effective_cutoff,
        Some(NOW - 7 * DAY_MS),
        "effective_cutoff 是保留期边界，不再夹紧到旧归档水位"
    );
    assert_eq!(raw_count(&conn, agent), 4, "raw 必须保持不变");

    // ledger pending：即使有旧归档水位也必须完全跳过 raw 删除。
    storage
        .set_archive_state("archive_ledger_pending", "1", NOW)
        .unwrap();
    let pending = run_retention(
        &storage,
        &cfg,
        NOW,
        ArchiveGate::Enabled {
            watermark: Some(NOW),
        },
    )
    .expect("ledger pending 的 run_retention 失败");
    assert_eq!(pending.raw.deleted, 0);
    assert!(pending.raw.skipped_archive_ledger_pending);
    assert_eq!(raw_count(&conn, agent), 4);

    // 清掉 pending、关闭归档后，只删已聚合且过期的 3 行。
    storage
        .set_archive_state("archive_ledger_pending", "0", NOW)
        .unwrap();
    let disabled = run_retention(&storage, &cfg, NOW, ArchiveGate::Disabled)
        .expect("Disabled 的 run_retention 失败");
    assert_eq!(
        disabled.raw.deleted, 3,
        "归档未启用时应按保留期删除 3 行已聚合过期 raw"
    );
    assert!(!disabled.raw.blocked_by_archive);
    assert_eq!(
        disabled.raw.effective_cutoff,
        Some(NOW - 7 * DAY_MS),
        "无归档门禁时 raw 的删除边界应为保留期 cutoff"
    );
    assert_eq!(raw_count(&conn, agent), 1, "只剩未过期的 fresh raw");
    assert!(raw_has_ts(&conn, agent, fresh), "未过期 raw 必须保留");
}

// ---------------------------------------------------------------------------
// 用例 3：1m 保留只删整小时 clean 行；dirty hour 整小时跳过。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2_retention_skips_dirty_hour_and_only_deletes_whole_clean_hours() {
    let dir = TempDbDir::new("dirty-hour");
    let storage = open_storage(&dir);
    let agent = "agent-dirty";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 8 * HOUR_MS;
    // 1m 保留 10 天；max_late_days=8 与该配置自洽（10 >= 8 + 2）。
    let cutoff = NOW - 10 * DAY_MS;
    let hour_a = cutoff - 3 * HOUR_MS;
    let hour_b = cutoff - 2 * HOUR_MS;
    let label = [("host", "dirty")];

    insert(
        &storage,
        &batch(
            agent,
            1,
            NOW,
            vec![
                sample("cpu.usage", labels(&label), hour_a + MINUTE_MS, 1.0),
                sample("cpu.usage", labels(&label), hour_a + 2 * MINUTE_MS, 2.0),
                sample("cpu.usage", labels(&label), hour_b + MINUTE_MS, 3.0),
            ],
        ),
    );
    run_downsample(&storage, NOW, None).expect("首次 run_downsample 失败");
    let conn = readonly_conn(&dir);
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_a), 2);
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_b), 1);

    // 两个旧小时各来一条迟到 raw；后台块上限 1 令 1h 只重算其中一小时。
    insert(
        &storage,
        &batch(
            agent,
            2,
            NOW,
            vec![
                sample(
                    "cpu.usage",
                    labels(&label),
                    hour_a + 3 * MINUTE_MS + 30_000,
                    10.0,
                ),
                sample(
                    "cpu.usage",
                    labels(&label),
                    hour_b + 3 * MINUTE_MS + 30_000,
                    20.0,
                ),
            ],
        ),
    );
    let downsample =
        run_downsample(&storage, NOW, Some(1)).expect("块上限 1 的 run_downsample 失败");
    assert_eq!(downsample.one_minute.chunks, 1, "1m 块上限 1");
    assert_eq!(downsample.one_hour.chunks, 1, "1h 块上限 1，只清理一小时");

    // hour_a 已被 1h 认领（clean），hour_b 仍 dirty。
    let conn = readonly_conn(&dir);
    let dirty_hours: Vec<i64> = conn
        .prepare("SELECT DISTINCT (bucket_ts / 3600000) * 3600000 FROM samples_1m WHERE aggregated_1h = 0 ORDER BY 1")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(dirty_hours, vec![hour_b], "只应剩 hour_b 为 dirty");

    let cfg = HubConfig {
        retention_raw_days: 0,
        retention_1m_days: 10,
        retention_1h_days: 0,
        ingest: rustboard_common::config::HubIngestConfig {
            max_late_days: 8,
            max_future_skew_secs: 300,
        },
        ..HubConfig::default()
    };
    let retention = run_retention(&storage, &cfg, NOW, ArchiveGate::Disabled)
        .expect("dirty hour retention 失败");
    assert_eq!(retention.one_minute.cutoff, Some(cutoff));
    assert_eq!(retention.one_minute.effective_cutoff, Some(cutoff));
    assert_eq!(
        retention.one_minute.deleted, 3,
        "只应删除 hour_a 的 3 个 clean 1m 行，dirty hour_b 整小时保留"
    );
    assert!(
        retention.one_minute.blocked_by_downsample,
        "dirty hour 未删必须标记 blocked_by_downsample"
    );
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_a), 0);
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_b), 2);

    // 下一轮降采样清理 hour_b 后，保留期才能删除整小时。
    run_downsample(&storage, NOW, None).expect("追平 dirty hour 失败");
    let retention =
        run_retention(&storage, &cfg, NOW, ArchiveGate::Disabled).expect("清理后的 retention 失败");
    assert_eq!(retention.one_minute.deleted, 2);
    assert!(!retention.one_minute.blocked_by_downsample);
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_b), 0);
}

// ---------------------------------------------------------------------------
// 用例 4：1m 保留边界按整点向下取整（半个小时的 cutoff 不删该小时）。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2_retention_minute_cutoff_rounds_down_to_hour_boundary() {
    let dir = TempDbDir::new("minute-cutoff");
    let storage = open_storage(&dir);
    let agent = "agent-cutoff";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 8 * HOUR_MS + 30 * MINUTE_MS;
    let cutoff = NOW - 10 * DAY_MS; // 落在半小时点，不是整点
    let hour_before = (cutoff / HOUR_MS) * HOUR_MS - HOUR_MS;
    let hour_at_cutoff = (cutoff / HOUR_MS) * HOUR_MS;
    let label = [("host", "cutoff")];

    insert(
        &storage,
        &batch(
            agent,
            1,
            NOW,
            vec![
                sample("cpu.usage", labels(&label), hour_before + MINUTE_MS, 1.0),
                sample("cpu.usage", labels(&label), hour_at_cutoff + MINUTE_MS, 2.0),
            ],
        ),
    );
    run_downsample(&storage, NOW, None).expect("run_downsample 失败");
    let conn = readonly_conn(&dir);
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_before), 1);
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_at_cutoff), 1);

    let cfg = HubConfig {
        retention_raw_days: 0,
        retention_1m_days: 10,
        retention_1h_days: 0,
        ingest: rustboard_common::config::HubIngestConfig {
            max_late_days: 8,
            max_future_skew_secs: 300,
        },
        ..HubConfig::default()
    };
    let retention =
        run_retention(&storage, &cfg, NOW, ArchiveGate::Disabled).expect("run_retention 失败");
    assert_eq!(retention.one_minute.cutoff, Some(cutoff));
    assert_eq!(
        retention.one_minute.effective_cutoff,
        Some(hour_at_cutoff),
        "1m cutoff 必须向下取整到整点"
    );
    assert_eq!(
        retention.one_minute.deleted, 1,
        "只删 cutoff 之前的完整小时，cutoff 所在小时整小时保留"
    );
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_before), 0);
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour_at_cutoff), 1);
}

// ---------------------------------------------------------------------------
// 用例 5：#50 旧库超界时间戳审计与 i64 边界。
// ---------------------------------------------------------------------------

#[test]
fn issue50_legacy_audit_isolates_only_invalid_timestamps_and_handles_i64() {
    let dir = TempDbDir::new("audit");
    let storage = open_storage(&dir);
    let agent = "agent-audit";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 8 * HOUR_MS;
    let valid = NOW - 2 * DAY_MS;
    let too_old = NOW - 31 * DAY_MS;
    let too_new = NOW + 301_000;
    insert(
        &storage,
        &batch(
            agent,
            1,
            NOW,
            vec![
                sample("cpu.usage", Labels::new(), valid, 1.0),
                sample("cpu.usage", Labels::new(), too_old, 2.0),
                sample("cpu.usage", Labels::new(), too_new, 3.0),
                sample("cpu.usage", Labels::new(), i64::MIN, 4.0),
                sample("cpu.usage", Labels::new(), i64::MAX, 5.0),
            ],
        ),
    );

    let cfg = HubConfig::default(); // max_late_days=30, max_future_skew_secs=300
    let audit = audit_legacy_raw_rows(&storage, &cfg, NOW).expect("legacy 审计失败");
    // too_old 仍是合法历史数据，留给 delta；只有 too_new / i64 极值被隔离。
    assert_eq!(
        audit.invalid_timestamp_rows, 3,
        "too_new / i64::MIN / i64::MAX 是非法时间戳"
    );
    assert_eq!(
        audit.unaggregated_invalid_rows, 3,
        "审计前 3 条非法行都未聚合"
    );
    assert_eq!(audit.isolated_rows, 3);
    assert_eq!(
        audit.legacy_unaggregated_rows, 1,
        "31 天前的 too_old 超过默认 30 天 1m horizon"
    );

    let status = maintenance_status(&storage, &cfg, NOW).expect("maintenance_status 失败");
    assert_eq!(status.raw.rows, 5);
    assert_eq!(status.unaggregated_rows, 2, "valid 与 too_old 都仍待聚合");
    assert_eq!(status.invalid_timestamp_rows, 3);
    assert_eq!(
        status.legacy_unaggregated_rows, 0,
        "i64::MIN 已隔离；too_old 未到 90 天 1m horizon"
    );

    // 审计已把 3 条非法行隔离为 aggregated_1m=1，但仍保留在 raw。
    let conn = readonly_conn(&dir);
    let isolated: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples WHERE aggregated_1m = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(isolated, 3, "审计必须只隔离 3 条非法时间戳");
    // delta 聚合 valid 与 too_old；i64 极值不得 panic / 回绕。
    let report = run_downsample(&storage, NOW, None).expect("审计后的 run_downsample 失败");
    assert_eq!(report.one_minute.rows, 2);
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "cpu.usage",
        (valid / MINUTE_MS) * MINUTE_MS,
        (1, 1.0, 1.0),
        "只有 valid 行进入 1m",
    );
    assert_eq!(raw_count(&conn, agent), 5);
    let aggregated: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples WHERE aggregated_1m = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(aggregated, 5, "审计隔离 3 行 + valid/too_old 聚合 2 行");
}

// ---------------------------------------------------------------------------
// 用例 6：late 行在 downsample 之后、retention 之前到达时不得被删除；
// 下一轮增量聚合完成后才允许按保留期删除。
// ---------------------------------------------------------------------------

#[test]
fn m4_a2_late_raw_arriving_between_downsample_and_retention_is_not_deleted_first() {
    let dir = TempDbDir::new("late-retention");
    let storage = open_storage(&dir);
    let agent = "agent-late-retention";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 12 * HOUR_MS;
    let late_bucket = NOW - 40 * DAY_MS;
    let cfg = HubConfig {
        retention_raw_days: 30,
        retention_1m_days: 90,
        retention_1h_days: 730,
        ingest: rustboard_common::config::HubIngestConfig {
            max_late_days: 60,
            max_future_skew_secs: 300,
        },
        ..HubConfig::default()
    };
    let label = [("host", "late-retention")];

    // 首次聚合：桶内 10/20。
    insert(
        &storage,
        &batch(
            agent,
            1,
            NOW,
            vec![
                sample("cpu.usage", labels(&label), late_bucket, 10.0),
                sample("cpu.usage", labels(&label), late_bucket + 20_000, 20.0),
            ],
        ),
    );
    run_downsample(&storage, NOW, None).expect("首次 run_downsample 失败");

    // 迟到 30 在 downsample 之后到达；此时 raw 仍是 aggregated_1m=0。
    insert(
        &storage,
        &batch(
            agent,
            2,
            NOW,
            vec![sample(
                "cpu.usage",
                labels(&label),
                late_bucket + 40_000,
                30.0,
            )],
        ),
    );
    let retention = run_retention(&storage, &cfg, NOW, ArchiveGate::Disabled)
        .expect("downsample 后 retention 失败");
    assert_eq!(
        retention.raw.deleted, 2,
        "只应删除已聚合的 2 行；新迟到行未聚合，不能删"
    );
    assert!(
        retention.raw.blocked_by_downsample,
        "存在未聚合 raw 时必须标记 blocked_by_downsample"
    );
    let conn = readonly_conn(&dir);
    assert!(raw_has_ts(&conn, agent, late_bucket + 40_000));

    let report = run_downsample(&storage, NOW, None).expect("迟到行合并失败");
    assert_eq!(report.one_minute.rows, 1);
    assert_aggregate(
        &conn,
        SAMPLES_1M,
        agent,
        "cpu.usage",
        late_bucket,
        (3, 20.0, 30.0),
        "迟到行合并后的 1m 桶",
    );
    let retention = run_retention(&storage, &cfg, NOW, ArchiveGate::Disabled)
        .expect("增量聚合后的 retention 失败");
    assert_eq!(retention.raw.deleted, 1, "迟到 raw 聚合后才可删除");
    assert_eq!(raw_count(&conn, agent), 0);
}

// ---------------------------------------------------------------------------
// 用例 7：#33 legacy backlog 不得用残缺 1m 覆盖完整 1h。
//
// 旧 1h 由 10/20 生成 count=2/avg=15；1m 已按保留期整组删除；之后补传的
// legacy raw 30/40/50 只能被隔离，不能重算成 count=3/avg=40 覆盖旧桶。
// ---------------------------------------------------------------------------

/// 只构造「旧 1h + 已删 1m」的公共前置，返回小时起点。
fn seed_complete_1h_then_prune_1m(
    storage: &SqliteStorage,
    dir: &TempDbDir,
    agent: &str,
    label: &Labels,
) -> i64 {
    let hour = BASE;
    let build_now = BASE + 5 * DAY_MS;
    insert(
        storage,
        &batch(
            agent,
            1,
            build_now,
            vec![
                sample("cpu.usage", label.clone(), hour + 1_000, 10.0),
                sample("cpu.usage", label.clone(), hour + 2_000, 20.0),
            ],
        ),
    );
    run_downsample(storage, build_now, None).expect("首次 run_downsample 失败");
    let conn = readonly_conn(dir);
    assert_aggregate(
        &conn,
        SAMPLES_1H,
        agent,
        "cpu.usage",
        hour,
        (2, 15.0, 20.0),
        "前置：完整旧 1h",
    );
    // 真实 retention：整组删 1m，并删已聚合旧 raw，只剩旧 1h。
    assert_eq!(
        storage
            .prune_samples_1m_before(hour + HOUR_MS)
            .unwrap()
            .deleted,
        1,
        "前置：1m 必须整组删除"
    );
    assert_eq!(
        storage
            .prune_samples_before(hour + HOUR_MS)
            .unwrap()
            .deleted,
        2,
        "前置：已聚合旧 raw 删除"
    );
    hour
}

fn issue33_cfg() -> HubConfig {
    HubConfig {
        retention_raw_days: 7,
        retention_1m_days: 90,
        retention_1h_days: 730,
        ..HubConfig::default()
    }
}

/// 启动审计路径：真实 prune 后，审计必须在 delta 之前隔离 legacy raw。
#[test]
fn issue33_audit_quarantines_legacy_backlog_instead_of_overwriting_1h() {
    let dir = TempDbDir::new("issue33-audit");
    let storage = open_storage(&dir);
    let agent = "agent-issue33-audit";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 100 * DAY_MS + 5 * HOUR_MS;
    let label = labels(&[("host", "legacy")]);
    let hour = seed_complete_1h_then_prune_1m(&storage, &dir, agent, &label);

    insert(
        &storage,
        &batch(
            agent,
            2,
            NOW,
            vec![
                sample("cpu.usage", label.clone(), hour + 3_000, 30.0),
                sample("cpu.usage", label.clone(), hour + 4_000, 40.0),
                sample("cpu.usage", label.clone(), hour + 5_000, 50.0),
            ],
        ),
    );

    let cfg = issue33_cfg();
    let audit = audit_legacy_raw_rows(&storage, &cfg, NOW).expect("legacy 审计失败");
    assert_eq!(audit.invalid_timestamp_rows, 0);
    assert_eq!(audit.legacy_unaggregated_rows, 3);
    assert_eq!(
        audit.quarantined_legacy_rows, 3,
        "旧于 1m horizon 且已有 1h 的 legacy raw 必须隔离"
    );

    let report = run_downsample(&storage, NOW, None).expect("审计后的 run_downsample 失败");
    assert_eq!(report.one_minute.quarantined, 0, "审计已完成隔离");

    let conn = readonly_conn(&dir);
    assert_aggregate(
        &conn,
        SAMPLES_1H,
        agent,
        "cpu.usage",
        hour,
        (2, 15.0, 20.0),
        "legacy raw 不得覆盖完整 1h",
    );
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour), 0, "不得生成残缺 1m");
    assert_eq!(raw_count(&conn, agent), 3, "隔离只标记、不删 raw");
    let unaggregated: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples WHERE agent_id = ?1 AND aggregated_1m = 0",
            params![agent],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unaggregated, 0, "legacy raw 必须被隔离为 aggregated_1m=1");

    let status = maintenance_status(&storage, &cfg, NOW).expect("maintenance_status 失败");
    assert_eq!(status.legacy_unaggregated_rows, 0);
    assert_eq!(status.quarantined_legacy_raw_rows, 3);
    assert_eq!(status.quarantined_1h_groups, 0);
    assert_eq!(status.last_pruned_1m_hour, Some(hour));
    assert_eq!(status.pruned_1m_hours, 1);
}

/// worker 路径：没有启动审计时，真实 prune 标记也必须阻止残缺源覆盖。
#[test]
fn issue33_delta_quarantines_after_1m_prune_without_audit() {
    let dir = TempDbDir::new("issue33-delta");
    let storage = open_storage(&dir);
    let agent = "agent-issue33-delta";
    ensure_agent(&storage, agent);

    const NOW: i64 = BASE + 100 * DAY_MS + 5 * HOUR_MS;
    let label = labels(&[("host", "legacy-delta")]);
    let hour = seed_complete_1h_then_prune_1m(&storage, &dir, agent, &label);

    insert(
        &storage,
        &batch(
            agent,
            2,
            NOW,
            vec![
                sample("cpu.usage", label.clone(), hour + 3_000, 30.0),
                sample("cpu.usage", label.clone(), hour + 4_000, 40.0),
                sample("cpu.usage", label.clone(), hour + 5_000, 50.0),
            ],
        ),
    );

    // 不调用 audit：delta 直接读 prune 标记并隔离。
    let report = run_downsample(&storage, NOW, None).expect("run_downsample 失败");
    assert_eq!(report.one_minute.quarantined, 3);
    assert_eq!(report.one_minute.rows, 0);

    let conn = readonly_conn(&dir);
    assert_aggregate(
        &conn,
        SAMPLES_1H,
        agent,
        "cpu.usage",
        hour,
        (2, 15.0, 20.0),
        "prune 后的旧 1h 必须保留",
    );
    assert_eq!(tier_count(&conn, SAMPLES_1M, hour), 0);
    assert_eq!(raw_count(&conn, agent), 3);
    let unaggregated: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples WHERE agent_id = ?1 AND aggregated_1m = 0",
            params![agent],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(unaggregated, 0);

    let status =
        maintenance_status(&storage, &issue33_cfg(), NOW).expect("maintenance_status 失败");
    assert_eq!(status.quarantined_legacy_raw_rows, 3);
    assert_eq!(status.last_pruned_1m_hour, Some(hour));
    assert_eq!(status.pruned_1m_hours, 1);

    // 再来一轮：隔离计数不重复增长，旧 1h 不变。
    let again = run_downsample(&storage, NOW, None).expect("幂等重跑失败");
    assert_eq!(again.one_minute.quarantined, 0);
    let status =
        maintenance_status(&storage, &issue33_cfg(), NOW).expect("maintenance_status 失败");
    assert_eq!(status.quarantined_legacy_raw_rows, 3);
    assert_aggregate(
        &conn,
        SAMPLES_1H,
        agent,
        "cpu.usage",
        hour,
        (2, 15.0, 20.0),
        "幂等重跑后旧 1h 仍保留",
    );
}
