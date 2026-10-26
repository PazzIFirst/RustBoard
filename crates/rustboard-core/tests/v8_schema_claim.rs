//! R1a-1：schema v8 迁移门禁与归档 claim 存储原语。
//!
//! 只依赖公开接口与真实 SQLite 文件，覆盖：
//! - v7→v8 列/数据回填（聚合水位、last_ts、ledger_version、ledger pending）；
//! - 更高 `user_version` 拒绝且不建/改业务表；
//! - 两个并发 claim 只有一个成功，冲突返回可重试领域错误；
//! - 按 `archive_object_id` 读回同一行集；
//! - 归档保留期只删除「已聚合 + 对象 uploaded」的行（pending 不删）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use rustboard_common::model::{Sample, SampleBatch};
use rustboard_core::archive::{
    ArchiveObject, ArchiveStatus, ArchiveStoreError, LEDGER_VERSION_V7, LEDGER_VERSION_V8,
};
use rustboard_core::storage::sqlite::{ArchiveRawRow, SqliteStorage};
use rustboard_core::storage::Storage;

struct TempDb {
    root: PathBuf,
}

impl TempDb {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系统时间早于 UNIX_EPOCH")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rb-v8-claim-{}-{tag}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("创建临时目录失败");
        Self { root }
    }

    fn db_path(&self) -> PathBuf {
        self.root.join("rustboard.db")
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn user_version(conn: &Connection) -> i64 {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("读取 user_version 失败")
}

fn insert_batch(storage: &SqliteStorage, seq: u64, samples: Vec<Sample>) {
    let batch = SampleBatch {
        agent_id: "agent-claim".into(),
        epoch: 1,
        seq,
        boot_id: "boot".into(),
        sent_at: 1_000,
        samples,
    };
    storage.insert_batch(&batch).expect("写入 raw 采样失败");
}

/// 构造 v7 旧表 fixture：只建本用例需要的表，其余由 v8 迁移补齐。
fn build_v7_fixture(path: &PathBuf, with_1h_row: bool, archived_watermark: bool) {
    let conn = Connection::open(path).expect("创建 v7 fixture 失败");
    let mut sql = String::from(
        r#"
        CREATE TABLE samples (
            agent_id TEXT NOT NULL,
            metric   TEXT NOT NULL,
            labels   TEXT NOT NULL DEFAULT '{}',
            ts       INTEGER NOT NULL,
            value    REAL NOT NULL
        );
        INSERT INTO samples VALUES ('a', 'm', '{}', 30000, 1.0);
        INSERT INTO samples VALUES ('a', 'm', '{}', 90000, 2.0);
        INSERT INTO samples VALUES ('a', 'm', '{}', 180000, 3.0);

        CREATE TABLE samples_1m (
            agent_id   TEXT NOT NULL,
            metric     TEXT NOT NULL,
            labels     TEXT NOT NULL DEFAULT '{}',
            bucket_ts  INTEGER NOT NULL,
            min_value  REAL NOT NULL,
            max_value  REAL NOT NULL,
            avg_value  REAL NOT NULL,
            last_value REAL NOT NULL,
            count      INTEGER NOT NULL,
            PRIMARY KEY (agent_id, metric, labels, bucket_ts)
        );
        INSERT INTO samples_1m VALUES
            ('a', 'm', '{}', 0, 1.0, 1.0, 1.0, 1.0, 1);
        INSERT INTO samples_1m VALUES
            ('a', 'm', '{}', 60000, 1.0, 2.0, 1.5, 2.0, 2);
        INSERT INTO samples_1m VALUES
            ('a', 'm', '{}', 120000, 3.0, 3.0, 3.0, 3.0, 3);
        -- hour=0 的末尾 1m 行（180000）与 1h.count 对账后应保持 0。
        INSERT INTO samples_1m VALUES
            ('a', 'm', '{}', 180000, 3.0, 3.0, 3.0, 3.0, 1);
        -- hour=3600000 没有 1h 行，1m 行必须保持 aggregated_1h=0。
        INSERT INTO samples_1m VALUES
            ('a', 'm', '{}', 3660000, 4.0, 4.0, 4.0, 4.0, 1);

        -- 迟到 raw：rowid 比原 1m 行更晚，但仍在 bucket 0；1m.count=1
        -- 只应认领最早一条 raw（30000），不能把 59000 误标为已聚合。
        INSERT INTO samples VALUES ('a', 'm', '{}', 59000, 4.0);

        CREATE TABLE archive_objects (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            backend      TEXT NOT NULL,
            object_key   TEXT NOT NULL UNIQUE,
            manifest_key TEXT NOT NULL,
            from_ts      INTEGER NOT NULL,
            to_ts        INTEGER NOT NULL,
            rows         INTEGER NOT NULL,
            bytes        INTEGER NOT NULL,
            sha256       TEXT NOT NULL,
            status       TEXT NOT NULL,
            error        TEXT NOT NULL DEFAULT '',
            created_at   INTEGER NOT NULL,
            uploaded_at  INTEGER,
            deleted_at   INTEGER
        );
        INSERT INTO archive_objects
            (backend, object_key, manifest_key, from_ts, to_ts, rows, bytes, sha256,
             status, error, created_at, uploaded_at)
        VALUES
            ('webdav', 'v7/old.csv.gz', 'v7/old.manifest.json', 0, 60000, 2, 10,
             'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
             'uploaded', '', 1000, 2000);

        CREATE TABLE maintenance_state (
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE archive_state (
            key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
        );
        "#,
    );
    if with_1h_row {
        sql.push_str(
            "CREATE TABLE samples_1h (
                 agent_id   TEXT NOT NULL,
                 metric     TEXT NOT NULL,
                 labels     TEXT NOT NULL DEFAULT '{}',
                 bucket_ts  INTEGER NOT NULL,
                 min_value  REAL NOT NULL,
                 max_value  REAL NOT NULL,
                 avg_value  REAL NOT NULL,
                 last_value REAL NOT NULL,
                 count      INTEGER NOT NULL,
                 PRIMARY KEY (agent_id, metric, labels, bucket_ts)
             );
             INSERT INTO samples_1h VALUES
                 ('a', 'm', '{}', 0, 1.0, 4.0, 2.5, 4.0, 6);",
        );
    }
    if archived_watermark {
        sql.push_str("INSERT INTO archive_state VALUES ('last_archived_ts', '1700000000000', 1);");
    }
    sql.push_str("PRAGMA user_version = 7;");
    conn.execute_batch(&sql).expect("写入 v7 fixture 失败");
}

fn table_columns(conn: &Connection, table: &str) -> Vec<(String, bool, Option<String>)> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .expect("准备 table_info 失败");
    stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(1)?,
            row.get::<_, i64>(3)? != 0,
            row.get::<_, Option<String>>(4)?,
        ))
    })
    .expect("查询 table_info 失败")
    .collect::<rusqlite::Result<Vec<_>>>()
    .expect("收集 table_info 失败")
}

fn assert_column(
    conn: &Connection,
    table: &str,
    name: &str,
    not_null: bool,
    default: Option<&str>,
) {
    let columns = table_columns(conn, table);
    let column = columns
        .iter()
        .find(|(column, _, _)| column == name)
        .unwrap_or_else(|| panic!("{table}.{name} 不存在"));
    assert_eq!(column.1, not_null, "{table}.{name} NOT NULL 不符");
    let raw_default = column.2.as_deref().map(str::trim);
    assert_eq!(
        raw_default, default,
        "{table}.{name} 默认值不符（实际 {raw_default:?}）"
    );
}

fn index_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?1)",
        params![name],
        |row| row.get::<_, i64>(0),
    )
    .expect("查询索引失败")
        == 1
}

#[test]
fn v7_to_v8_migration_reconciles_count_order_and_keeps_old_data() {
    let dir = TempDb::new("migrate");
    build_v7_fixture(&dir.db_path(), true, true);

    {
        let storage = SqliteStorage::open(&dir.db_path()).expect("v7→v8 迁移失败");
        assert_eq!(
            storage
                .get_archive_state("archive_ledger_pending")
                .expect("读取 ledger pending 失败")
                .as_deref(),
            Some("1"),
            "v7 归档水位存在时必须写 ledger pending"
        );
        let object = storage
            .get_archive_object(1)
            .expect("读取旧归档对象失败")
            .expect("旧归档对象必须保留");
        assert_eq!(object.ledger_version, LEDGER_VERSION_V7);
        assert_eq!(object.object_key, "v7/old.csv.gz");
        assert_eq!(storage.count_archive_objects().unwrap(), 1);
        assert_eq!(storage.sample_count("a").unwrap(), 4, "旧 raw 行不得丢失");
    }

    let conn = Connection::open(dir.db_path()).expect("重新打开迁移后库失败");
    assert_eq!(user_version(&conn), 8);
    assert_column(&conn, "samples", "archive_object_id", false, None);
    assert_column(&conn, "samples", "aggregated_1m", true, Some("0"));
    assert_column(&conn, "samples_1m", "last_ts", true, Some("0"));
    assert_column(&conn, "samples_1m", "aggregated_1h", true, Some("0"));
    assert_column(&conn, "archive_objects", "ledger_version", true, Some("0"));
    assert_column(&conn, "archive_objects", "attempts", true, Some("0"));
    for index in [
        "idx_samples_unarchived",
        "idx_samples_unaggregated",
        "idx_samples_1m_unaggregated",
    ] {
        assert!(index_exists(&conn, index), "缺少 v8 partial index {index}");
    }

    let raw: Vec<(i64, i64)> = conn
        .prepare("SELECT ts, aggregated_1m FROM samples ORDER BY ts")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    // 迟到/崩溃窗口：59000 的 rowid 晚于原 1m 行，bucket 0 的 1m.count=1，
    // 只能认领最早一条 raw（30000）；59000 必须保持 0，否则永久漏聚合。
    assert_eq!(
        raw,
        vec![(30_000, 1), (59_000, 0), (90_000, 1), (180_000, 1)],
        "raw 按 1m count/rowid 对账：只标最早 count 条，late raw 保持 0"
    );

    let buckets: Vec<(i64, i64, i64)> = conn
        .prepare("SELECT bucket_ts, last_ts, aggregated_1h FROM samples_1m ORDER BY bucket_ts")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(
        buckets,
        vec![
            (0, 30_000, 1),
            (60_000, 90_000, 1),
            (120_000, 179_999, 1),
            (180_000, 180_000, 0),
            (3_660_000, 3_719_999, 0),
        ],
        "last_ts 取最早 count 条 raw 的 MAX(ts)，无 raw 才用桶尾；\
         1h 按累计 count 对账，180000 的累计 7 > 1h.count 6 必须为 0"
    );
}

#[test]
fn v7_migration_without_1h_rows_does_not_mark_1h_or_pending() {
    let dir = TempDb::new("no-watermark");
    build_v7_fixture(&dir.db_path(), false, false);
    {
        let storage = SqliteStorage::open(&dir.db_path()).expect("v7→v8 迁移失败");
        assert_eq!(
            storage.get_archive_state("archive_ledger_pending").unwrap(),
            None,
            "没有归档水位时不得写 ledger pending"
        );
    }
    let conn = Connection::open(dir.db_path()).unwrap();
    assert_eq!(user_version(&conn), 8);
    let raw_flagged: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples WHERE aggregated_1m = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let m_flagged: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples_1m WHERE aggregated_1h != 0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        raw_flagged, 3,
        "raw 按 1m count/rowid 对账（与维护水位无关）"
    );
    assert_eq!(m_flagged, 0, "没有 1h 行时 1m 必须全部保持 0");
}

#[test]
fn v7_migration_does_not_mark_extreme_or_future_timestamps() {
    let dir = TempDb::new("future-ts");
    build_v7_fixture(&dir.db_path(), true, false);
    {
        let conn = Connection::open(dir.db_path()).unwrap();
        // 2033 年（未来但未超 ArchiveDay 上限）与超过 9999 年的极端值。
        for (agent, ts) in [
            ("future", 2_000_000_000_000_i64),
            ("beyond", 253_402_300_800_000),
        ] {
            let bucket = (ts / 60_000) * 60_000;
            let hour = (bucket / 3_600_000) * 3_600_000;
            conn.execute(
                "INSERT INTO samples VALUES (?1, 'm', '{}', ?2, 1.0)",
                params![agent, ts],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO samples_1m VALUES (?1, 'm', '{}', ?2, 1.0, 1.0, 1.0, 1.0, 1)",
                params![agent, bucket],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO samples_1h VALUES (?1, 'm', '{}', ?2, 1.0, 1.0, 1.0, 1.0, 1)",
                params![agent, hour],
            )
            .unwrap();
        }
    }
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    let conn = Connection::open(dir.db_path()).unwrap();
    let flagged: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples WHERE agent_id IN ('future','beyond') AND aggregated_1m != 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let m_flagged: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM samples_1m
             WHERE agent_id IN ('future','beyond')
               AND (last_ts != 0 OR aggregated_1h != 0)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(flagged, 0, "超界/未来 raw 不得被标成已聚合");
    assert_eq!(m_flagged, 0, "超界/未来 1m 不得回填 last_ts 或标 1h");
    assert_eq!(
        storage.count_invalid_archive_raw_rows().unwrap(),
        2,
        "超界 raw 必须可计数，供 R1b 隔离/告警"
    );
}

#[test]
fn newer_sqlite_schema_version_is_rejected_before_ddl() {
    let dir = TempDb::new("future-version");
    {
        let conn = Connection::open(dir.db_path()).unwrap();
        conn.pragma_update(None, "user_version", 9)
            .expect("设置 user_version=9 失败");
    }
    let err = match SqliteStorage::open(&dir.db_path()) {
        Ok(_) => panic!("v9 库必须拒绝打开"),
        Err(err) => err,
    };
    let message = format!("{err:#}");
    assert!(
        message.contains('9') && message.contains('8') && message.contains("高于"),
        "拒绝信息应点名实际/支持版本并说明原因：{message}"
    );

    // 门禁先于建表：未来版本库不得被塞入任何业务表。
    let conn = Connection::open(dir.db_path()).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 0, "拒绝路径不得创建表");
    assert_eq!(user_version(&conn), 9, "拒绝路径不得改写 user_version");
}

fn claim_object(key: &str, rows: &[ArchiveRawRow]) -> ArchiveObject {
    ArchiveObject {
        id: 0,
        backend: "webdav".into(),
        object_key: key.into(),
        manifest_key: format!("{key}.manifest.json"),
        from_ts: rows.iter().map(|row| row.ts).min().unwrap(),
        to_ts: rows.iter().map(|row| row.ts).max().unwrap(),
        rows: u64::try_from(rows.len()).unwrap(),
        bytes: 123,
        sha256: "b".repeat(64),
        status: ArchiveStatus::Pending,
        error: String::new(),
        created_at: 1_000,
        uploaded_at: None,
        deleted_at: None,
        ledger_version: LEDGER_VERSION_V8,
        attempts: 0,
    }
}

#[test]
fn concurrent_claims_only_one_succeeds_and_rows_are_readable() {
    let dir = TempDb::new("claim-race");
    {
        let storage = SqliteStorage::open(&dir.db_path()).unwrap();
        insert_batch(
            &storage,
            0,
            vec![Sample::new("m", 1_000, 1.0), Sample::new("m", 2_000, 2.0)],
        );
    }

    let first = SqliteStorage::open(&dir.db_path()).unwrap();
    let second = SqliteStorage::open(&dir.db_path()).unwrap();
    let rows_a = first
        .list_unclaimed_archive_rows(0, 10_000, 100)
        .expect("读取未认领行失败");
    let rows_b = second
        .list_unclaimed_archive_rows(0, 10_000, 100)
        .expect("读取未认领行失败");
    assert_eq!(rows_a.len(), 2);
    assert_eq!(rows_a, rows_b, "两个 worker 必须看到同一候选行集");

    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [
        (first, rows_a, "v8/part-00001-v8.csv.gz"),
        (second, rows_b, "v8/part-00002-v8.csv.gz"),
    ]
    .into_iter()
    .map(|(storage, rows, key)| {
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            let object = claim_object(key, &rows);
            barrier.wait();
            storage.claim_archive_rows(&object, &rows)
        })
    })
    .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let successes: Vec<i64> = results
        .iter()
        .filter_map(|result| result.as_ref().ok().copied())
        .collect();
    assert_eq!(successes.len(), 1, "两个并发 claim 只能有一个成功");
    let conflict = results
        .iter()
        .find_map(|result| result.as_ref().err())
        .expect("另一个 claim 必须失败");
    assert_eq!(
        conflict.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::ClaimConflict),
        "冲突必须返回可重试的 ClaimConflict，实际：{conflict:#}"
    );

    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    assert_eq!(
        storage.count_archive_objects().unwrap(),
        1,
        "失败的 claim 必须回滚对象插入"
    );
    let object = storage.get_archive_object(successes[0]).unwrap().unwrap();
    assert_eq!(object.ledger_version, LEDGER_VERSION_V8);
    assert_eq!(object.rows, 2);
    let claimed = storage
        .archive_rows_for_object(successes[0])
        .expect("读回 claim 行集失败");
    assert_eq!(
        claimed.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![1_000, 2_000],
        "必须按 archive_object_id 原样读回 claim 行集"
    );
    assert_eq!(claimed.len(), 2);
}

#[test]
fn archived_retention_only_deletes_aggregated_uploaded_rows() {
    let dir = TempDb::new("retention");
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    insert_batch(
        &storage,
        0,
        vec![
            Sample::new("m", 1_000, 1.0),
            Sample::new("m", 2_000, 2.0),
            Sample::new("m", 3_000, 3.0),
        ],
    );
    let rows = storage
        .list_unclaimed_archive_rows(0, 3_000, 2)
        .expect("读取未认领行失败");
    assert_eq!(rows.len(), 2);
    let object = claim_object("v8/part-00001-v8.csv.gz", &rows);
    let object_id = storage
        .claim_archive_rows(&object, &rows)
        .expect("claim 失败");

    // 模拟 R1b 已把 raw 标记为已聚合；本切片不实现聚合行为。
    {
        let conn = Connection::open(dir.db_path()).unwrap();
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        conn.execute("UPDATE samples SET aggregated_1m = 1", [])
            .expect("标记 aggregated_1m 失败");
    }

    // pending 对象不能作为删除依据。
    let pending = storage
        .prune_archived_samples_before(2_500)
        .expect("pending 归档保留期失败");
    assert_eq!(pending.deleted, 0, "pending 对象的 raw 不得删除");

    storage
        .update_archive_object_status(object_id, ArchiveStatus::Uploaded, "", Some(2_000), None)
        .expect("更新对象状态失败");
    let pruned = storage
        .prune_archived_samples_before(2_500)
        .expect("uploaded 归档保留期失败");
    assert_eq!(pruned.deleted, 2, "只删除已聚合且对象 uploaded 的行");
    assert_eq!(
        storage.sample_count("agent-claim").unwrap(),
        1,
        "未认领 raw 即使已聚合也不得删除"
    );
}

#[test]
fn claim_can_defer_csv_metadata_and_update_it_outside_transaction() {
    let dir = TempDb::new("claim-metadata");
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    insert_batch(
        &storage,
        0,
        vec![Sample::new("m", 5_000, 1.5), Sample::new("m", 6_000, 2.5)],
    );
    let rows = storage
        .list_unclaimed_archive_rows(0, 10_000, 100)
        .expect("读取未认领行失败");
    let mut object = claim_object("v8/part-00001-v8.csv.gz", &rows);
    // 短事务：claim 时只插入 rows/from/to，CSV.GZ 尚未生成，元数据留占位。
    object.bytes = 0;
    object.sha256.clear();

    let object_id = storage
        .claim_archive_rows(&object, &rows)
        .expect("短事务 claim 失败");
    let stored = storage.get_archive_object(object_id).unwrap().unwrap();
    assert_eq!(stored.bytes, 0);
    assert_eq!(stored.sha256, "");
    assert_eq!(stored.attempts, 0);

    let digest = "c".repeat(64);
    storage
        .update_archive_object_metadata(object_id, 456, &digest)
        .expect("事务外更新元数据失败");
    let stored = storage.get_archive_object(object_id).unwrap().unwrap();
    assert_eq!(stored.bytes, 456);
    assert_eq!(stored.sha256, digest);
    assert_eq!(stored.rows, 2);

    // attempts 写入路径：pending / failed 可累加，uploaded 后拒绝。
    assert_eq!(storage.record_archive_attempt(object_id).unwrap(), 1);
    assert_eq!(storage.record_archive_attempt(object_id).unwrap(), 2);
    storage
        .update_archive_object_status(object_id, ArchiveStatus::Failed, "boom", None, None)
        .expect("pending→failed 合法");
    assert_eq!(storage.record_archive_attempt(object_id).unwrap(), 3);
    // 上传完成后既不能再重试，也不能改元数据。
    storage
        .update_archive_object_status(object_id, ArchiveStatus::Uploaded, "", Some(9_000), None)
        .expect("failed→uploaded 合法");
    let err = storage
        .record_archive_attempt(object_id)
        .expect_err("uploaded 后不得再记录尝试");
    assert_eq!(
        err.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::InvalidTransition)
    );
    let err = storage
        .update_archive_object_metadata(object_id, 999, &"e".repeat(64))
        .expect_err("uploaded 后不得改元数据");
    assert_eq!(
        err.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::InvalidTransition)
    );

    let err = storage
        .update_archive_object_metadata(object_id, 1, "not-a-sha")
        .expect_err("非法 sha256 必须拒绝");
    assert!(format!("{err:#}").contains("sha256"), "err={err:#}");
    let err = storage
        .update_archive_object_metadata(i64::MAX, 1, &"d".repeat(64))
        .expect_err("不存在的对象必须报错");
    assert_eq!(
        err.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::NotFound)
    );
}

#[test]
fn archive_claim_excludes_extreme_timestamps_and_counts_them() {
    let dir = TempDb::new("invalid-ts");
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    insert_batch(
        &storage,
        0,
        vec![
            Sample::new("m", i64::MIN, 1.0),
            Sample::new("m", i64::MAX, 2.0),
            Sample::new("m", 1_000, 3.0),
        ],
    );
    assert_eq!(
        storage.count_invalid_archive_raw_rows().unwrap(),
        2,
        "i64::MIN 与未来时间戳必须被计数"
    );
    let rows = storage
        .list_unclaimed_archive_rows(i64::MIN, i64::MAX, 100)
        .expect("读取未认领行失败");
    assert_eq!(
        rows.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![1_000],
        "超界时间戳不得进入 archive claim"
    );
    storage
        .claim_archive_rows(&claim_object("v8/part-00001-v8.csv.gz", &rows), &rows)
        .expect("正常行必须可 claim");

    // 即使调用方手工构造超界行集，claim 也必须拒绝而不是写库。
    let bad = ArchiveRawRow {
        rowid: 999,
        agent_id: "a".into(),
        metric: "m".into(),
        labels: "{}".into(),
        ts: i64::MIN,
        value: 1.0,
    };
    let bad_rows = std::slice::from_ref(&bad);
    let bad_object = claim_object("v8/part-00002-v8.csv.gz", bad_rows);
    let err = storage
        .claim_archive_rows(&bad_object, bad_rows)
        .expect_err("超界时间戳必须拒绝 claim");
    assert!(format!("{err:#}").contains("可归档范围"), "err={err:#}");
}

#[test]
fn claims_can_split_candidate_rows_into_multiple_objects() {
    let dir = TempDb::new("claim-split");
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    insert_batch(
        &storage,
        0,
        vec![
            Sample::new("m", 1_000, 1.0),
            Sample::new("m", 2_000, 2.0),
            Sample::new("m", 3_000, 3.0),
        ],
    );

    let first_rows = storage
        .list_unclaimed_archive_rows(0, 10_000, 2)
        .expect("读取第一批未认领行失败");
    assert_eq!(first_rows.len(), 2);
    let first_id = storage
        .claim_archive_rows(
            &claim_object("v8/part-00001-v8.csv.gz", &first_rows),
            &first_rows,
        )
        .expect("claim 第一个对象失败");

    let second_rows = storage
        .list_unclaimed_archive_rows(0, 10_000, 2)
        .expect("读取第二批未认领行失败");
    assert_eq!(second_rows.len(), 1, "已认领行不得再次被扫描");
    let second_id = storage
        .claim_archive_rows(
            &claim_object("v8/part-00002-v8.csv.gz", &second_rows),
            &second_rows,
        )
        .expect("claim 第二个对象失败");
    assert_ne!(first_id, second_id);
    assert_eq!(storage.count_archive_objects().unwrap(), 2);
    assert_eq!(storage.archive_rows_for_object(first_id).unwrap().len(), 2);
    assert_eq!(storage.archive_rows_for_object(second_id).unwrap().len(), 1);
}

#[test]
fn claim_rejects_reused_rowid_after_max_row_deleted() {
    let dir = TempDb::new("rowid-reuse");
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    insert_batch(&storage, 0, vec![Sample::new("metric-old", 1_000, 1.0)]);
    let stale = storage
        .list_unclaimed_archive_rows(0, 10_000, 100)
        .expect("读取未认领行失败");
    assert_eq!(stale.len(), 1);
    let stale_rowid = stale[0].rowid;

    // 删除最大 rowid 行后再插入，SQLite 会复用同一个 rowid。
    assert_eq!(storage.prune_samples_before(2_000).unwrap().deleted, 1);
    insert_batch(&storage, 1, vec![Sample::new("metric-new", 1_500, 9.0)]);
    let reused = storage
        .list_unclaimed_archive_rows(0, 10_000, 100)
        .expect("读取复用的未认领行失败");
    assert_eq!(reused.len(), 1);
    assert_eq!(
        reused[0].rowid, stale_rowid,
        "本用例必须真的触发 rowid 复用，否则覆盖不到身份校验"
    );
    assert_ne!(reused[0].metric, stale[0].metric);

    let err = storage
        .claim_archive_rows(&claim_object("v8/part-00001-v8.csv.gz", &stale), &stale)
        .expect_err("rowid 复用后旧行集 claim 必须失败");
    assert_eq!(
        err.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::ClaimConflict),
        "身份不匹配必须回滚并返回 ClaimConflict：{err:#}"
    );
    assert_eq!(
        storage.count_archive_objects().unwrap(),
        0,
        "冲突 claim 的对象插入必须回滚"
    );
    // 新行不得被旧 claim 占走。
    assert_eq!(
        storage.list_unclaimed_archive_rows(0, 10_000, 100).unwrap(),
        reused
    );
}

#[test]
fn claim_and_readback_preserve_ts_rowid_order() {
    let dir = TempDb::new("claim-order");
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    // 插入顺序与 ts 顺序相反：scan 按 ts,rowid 排序，readback 必须一致。
    insert_batch(
        &storage,
        0,
        vec![Sample::new("m", 3_000, 3.0), Sample::new("m", 1_000, 1.0)],
    );
    let rows = storage
        .list_unclaimed_archive_rows(0, 10_000, 100)
        .expect("读取未认领行失败");
    assert_eq!(
        rows.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![1_000, 3_000]
    );
    let object_id = storage
        .claim_archive_rows(&claim_object("v8/part-00001-v8.csv.gz", &rows), &rows)
        .expect("claim 失败");
    assert_eq!(
        storage.archive_rows_for_object(object_id).unwrap(),
        rows,
        "readback 必须与 claim/scan 使用相同的 ts,rowid 排序"
    );
}
