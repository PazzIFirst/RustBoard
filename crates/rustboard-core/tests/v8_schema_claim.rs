//! R1a-1：schema v9 门禁与归档 claim 存储原语。
//!
//! 只依赖公开接口与真实 SQLite 文件，覆盖：
//! - v1.0.0 旧 schema（v7 等）fail closed，不执行 v7→v8 补列/回填；
//! - 更高 `user_version` 拒绝且不建/改业务表；
//! - 两个并发 claim 只有一个成功，冲突返回可重试领域错误；
//! - 按 `archive_object_id` 读回同一行集；
//! - 归档保留期只删除「已聚合 + 对象 uploaded」的行（pending 不删）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};
use rustboard_common::model::{Sample, SampleBatch};
use rustboard_core::archive::{
    ArchiveObject, ArchiveStatus, ArchiveStoreError, LEDGER_VERSION_V7, LEDGER_VERSION_V8,
};
use rustboard_core::downsample::run_downsample;
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
fn newer_sqlite_schema_version_is_rejected_before_ddl() {
    let dir = TempDb::new("future-version");
    {
        let conn = Connection::open(dir.db_path()).unwrap();
        conn.pragma_update(None, "user_version", 10)
            .expect("设置 user_version=10 失败");
    }
    let err = match SqliteStorage::open(&dir.db_path()) {
        Ok(_) => panic!("v10 库必须拒绝打开"),
        Err(err) => err,
    };
    let message = format!("{err:#}");
    assert!(
        message.contains("10") && message.contains('9') && message.contains("高于"),
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
    assert_eq!(user_version(&conn), 10, "拒绝路径不得改写 user_version");
}

/// v1.0.0 只支持全新安装：真实 v7 库必须被拒绝，旧表/数据/水位零改写，
/// 不执行 v7→v8 的补列、partial index 或 ledger pending 回填。
#[test]
fn v7_database_is_rejected_without_running_v8_backfill() {
    let dir = TempDb::new("reject-v7");
    build_v7_fixture(&dir.db_path(), true, true);

    let before_samples = table_columns(&Connection::open(dir.db_path()).unwrap(), "samples");
    let before_1m = table_columns(&Connection::open(dir.db_path()).unwrap(), "samples_1m");
    let before_archive =
        table_columns(&Connection::open(dir.db_path()).unwrap(), "archive_objects");
    let before_object_count: i64 = Connection::open(dir.db_path())
        .unwrap()
        .query_row("SELECT COUNT(*) FROM archive_objects", [], |row| row.get(0))
        .unwrap();

    let err = match SqliteStorage::open(&dir.db_path()) {
        Ok(_) => panic!("v7 旧库必须被拒绝"),
        Err(err) => err,
    };
    let message = format!("{err:#}");
    assert!(message.contains("schema v7"), "{message}");
    assert!(message.contains("只支持全新安装"), "{message}");
    assert!(
        message.contains("旧数据兼容将在首个正式版本之后提供"),
        "{message}"
    );

    let conn = Connection::open(dir.db_path()).unwrap();
    assert_eq!(user_version(&conn), 7, "拒绝路径不得改写 user_version");
    // v8 补列/回填都没有发生。
    assert_eq!(
        table_columns(&conn, "samples"),
        before_samples,
        "拒绝路径不得给 samples 补 v8 列"
    );
    assert_eq!(
        table_columns(&conn, "samples_1m"),
        before_1m,
        "拒绝路径不得给 samples_1m 补 v8 列"
    );
    assert_eq!(
        table_columns(&conn, "archive_objects"),
        before_archive,
        "拒绝路径不得给 archive_objects 补 v8 列"
    );
    for (table, column) in [
        ("samples", "archive_object_id"),
        ("samples", "aggregated_1m"),
        ("samples_1m", "last_ts"),
        ("samples_1m", "aggregated_1h"),
        ("archive_objects", "ledger_version"),
        ("archive_objects", "attempts"),
    ] {
        assert!(
            !table_columns(&conn, table)
                .iter()
                .any(|(name, _, _)| name == column),
            "拒绝路径不得补列 {table}.{column}"
        );
    }
    for index in [
        "idx_samples_unarchived",
        "idx_samples_unaggregated",
        "idx_samples_1m_unaggregated",
    ] {
        assert!(
            !index_exists(&conn, index),
            "拒绝路径不得创建 v8 partial index {index}"
        );
    }
    // 旧数据原样保留，且没有写 archive_ledger_pending。
    let sample_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM samples", [], |row| row.get(0))
        .unwrap();
    assert_eq!(sample_count, 4, "拒绝路径不得删除旧 raw");
    let object_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM archive_objects", [], |row| row.get(0))
        .unwrap();
    assert_eq!(object_count, before_object_count);
    let pending: Option<String> = conn
        .query_row(
            "SELECT value FROM archive_state WHERE key = 'archive_ledger_pending'",
            [],
            |row| row.get(0),
        )
        .optional()
        .unwrap();
    assert_eq!(pending, None, "拒绝路径不得写 archive_ledger_pending");
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
fn archive_rows_for_object_is_ordered_by_ts_for_deterministic_retry() {
    let dir = TempDb::new("readback-order");
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    // 先写 ts=2000、再写 ts=1000：rowid 顺序与 ts 顺序相反。
    insert_batch(
        &storage,
        0,
        vec![Sample::new("m", 2_000, 2.0), Sample::new("m", 1_000, 1.0)],
    );
    let rows = storage
        .list_unclaimed_archive_rows(0, 10_000, 100)
        .expect("读取未认领行失败");
    assert_eq!(
        rows.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![1_000, 2_000],
        "claim 扫描必须按 ts, rowid 排序"
    );
    assert_eq!(
        rows.iter().map(|row| row.rowid).collect::<Vec<_>>(),
        vec![2, 1]
    );

    let object = claim_object("v8/part-00001-v8.csv.gz", &rows);
    let object_id = storage
        .claim_archive_rows(&object, &rows)
        .expect("claim 失败");
    let readback = storage
        .archive_rows_for_object(object_id)
        .expect("读回 claim 行集失败");
    assert_eq!(
        readback, rows,
        "重试重建必须与 claim 扫描顺序一致，否则 CSV/SHA 不一致"
    );
}

#[test]
fn archive_retryable_objects_are_v8_only_and_failures_increment_attempts() {
    let dir = TempDb::new("retryable");
    let storage = SqliteStorage::open(&dir.db_path()).unwrap();
    insert_batch(
        &storage,
        0,
        vec![Sample::new("m", 1_000, 1.0), Sample::new("m", 2_000, 2.0)],
    );
    let rows = storage
        .list_unclaimed_archive_rows(0, 10_000, 100)
        .expect("读取未认领行失败");
    let object = claim_object("v8/part-00001-v8.csv.gz", &rows);
    let object_id = storage
        .claim_archive_rows(&object, &rows)
        .expect("claim 失败");

    // v7 旧对象即使 pending 也不得进入 v8 重试列表，也不能补写 bytes/sha。
    let mut legacy = claim_object("v7/part-00001.csv.gz", &rows);
    legacy.ledger_version = LEDGER_VERSION_V7;
    let legacy_id = storage.insert_archive_object(&legacy).unwrap();
    let error = storage
        .update_archive_object_metadata(legacy_id, 1, &"f".repeat(64))
        .expect_err("v7 对象不得补写 v8 元数据");
    assert_eq!(
        error.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::InvalidTransition)
    );

    let retryable = storage
        .list_retryable_archive_objects(10, None)
        .expect("列出重试对象失败");
    assert_eq!(retryable.len(), 1);
    assert_eq!(retryable[0].id, object_id);

    storage
        .record_archive_object_failure(object_id, "backend_unavailable")
        .expect("记录失败状态失败");
    let failed = storage.get_archive_object(object_id).unwrap().unwrap();
    assert_eq!(failed.status, ArchiveStatus::Failed);
    assert_eq!(failed.error, "backend_unavailable");
    assert_eq!(failed.attempts, 1);

    storage
        .record_archive_object_failure(object_id, "backend_unavailable")
        .expect("第二次记录失败状态失败");
    let failed = storage.get_archive_object(object_id).unwrap().unwrap();
    assert_eq!(failed.attempts, 2, "每次失败必须累计 attempts");

    // 已上传对象不再进入重试列表；记录 failure 的合法迁移不是本用例职责。
    storage
        .update_archive_object_status(object_id, ArchiveStatus::Uploaded, "", Some(3_000), None)
        .unwrap();
    let uploaded = storage.get_archive_object(object_id).unwrap().unwrap();
    assert_eq!(uploaded.status, ArchiveStatus::Uploaded);
    assert_eq!(uploaded.attempts, 2);

    let retryable = storage.list_retryable_archive_objects(10, None).unwrap();
    assert!(
        retryable.iter().all(|object| object.id != object_id),
        "uploaded 对象不得继续重试"
    );
    // v7 对象原样保留，worker 不会重试。
    let legacy_after = storage.get_archive_object(legacy_id).unwrap().unwrap();
    assert_eq!(legacy_after.ledger_version, LEDGER_VERSION_V7);
    assert_eq!(legacy_after.attempts, 0);
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

    // R1b：retention 只删已聚合 raw；先跑一轮真实降采样把 raw 认领。
    run_downsample(&storage, 60_000, None).expect("claim 用例的降采样失败");
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
