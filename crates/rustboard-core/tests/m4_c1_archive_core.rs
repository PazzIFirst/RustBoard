//! M4-C1a 验收测试：归档配置之外的冷存储核心、CSV.GZ / manifest 与 SQLite 存储。
//!
//! 覆盖方案 §7.2 / §7.3 与任务书：状态字符串稳定、CSV 转义与 gzip 可读回、
//! SHA-256 固定向量、对象 key 校验、manifest 往返、ColdStore 错误脱敏、归档
//! 对象往返 / 唯一 / 分页 / 状态迁移 / 水位 UPSERT / 范围查询。

use std::collections::BTreeMap;
use std::future::Future;
use std::io::Read;
use std::str::FromStr;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};

use flate2::read::GzDecoder;
use rustboard_core::archive::{
    build_object_keys, format_csv_value, manifest_json, sha256_hex, ArchiveDay, ArchiveError,
    ArchiveManifest, ArchiveObject, ArchiveStatus, ArchiveStoreError, ColdObjectMeta, ColdStore,
    CsvArchiveWriter, CSV_HEADER, MANIFEST_FORMAT_VERSION, MAX_ARCHIVE_SHARD,
};
use rustboard_core::storage::sqlite::SqliteStorage;

/// 单线程 block_on：测试里的 async mock 全部立即就绪，不需要 tokio 运行时。
fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    let mut future = std::pin::pin!(future);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("测试 future 必须立即就绪"),
    }
}

fn gunzip(data: &[u8]) -> String {
    let mut decoder = GzDecoder::new(data);
    let mut text = String::new();
    decoder.read_to_string(&mut text).expect("gzip 解压失败");
    text
}

/// 测试侧独立实现 RFC 4180 的加引号规则，用于逐字校验 writer 输出。
fn quoted(field: &str) -> String {
    format!("\"{}\"", field.replace('"', "\"\""))
}

// ---------------------------------------------------------------------------
// ColdStore mock
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MemoryColdStore {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

#[async_trait::async_trait]
impl ColdStore for MemoryColdStore {
    async fn put(&self, key: &str, data: &[u8]) -> Result<(), ArchiveError> {
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_string(), data.to_vec());
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>, ArchiveError> {
        self.objects
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or(ArchiveError::NotFound)
    }

    async fn delete(&self, key: &str) -> Result<(), ArchiveError> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }

    async fn head(&self, key: &str) -> Result<Option<ColdObjectMeta>, ArchiveError> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .map(|data| ColdObjectMeta {
                size: data.len() as u64,
            }))
    }

    async fn test(&self) -> Result<(), ArchiveError> {
        Ok(())
    }
}

/// 一个会失败的 mock：故意持有敏感 endpoint，验证错误信息不会把它带出去。
struct FailingColdStore {
    endpoint: String,
}

#[async_trait::async_trait]
impl ColdStore for FailingColdStore {
    async fn put(&self, _key: &str, _data: &[u8]) -> Result<(), ArchiveError> {
        Err(ArchiveError::BackendUnavailable)
    }

    async fn get(&self, _key: &str) -> Result<Vec<u8>, ArchiveError> {
        Err(ArchiveError::BackendUnavailable)
    }

    async fn delete(&self, _key: &str) -> Result<(), ArchiveError> {
        Err(ArchiveError::BackendUnavailable)
    }

    async fn head(&self, _key: &str) -> Result<Option<ColdObjectMeta>, ArchiveError> {
        Err(ArchiveError::BackendUnavailable)
    }

    async fn test(&self) -> Result<(), ArchiveError> {
        Err(ArchiveError::BackendUnavailable)
    }
}

// ---------------------------------------------------------------------------
// 状态机
// ---------------------------------------------------------------------------

#[test]
fn archive_status_strings_and_transitions_are_stable() {
    for status in [
        ArchiveStatus::Pending,
        ArchiveStatus::Uploaded,
        ArchiveStatus::LocalDeleted,
        ArchiveStatus::Failed,
    ] {
        assert_eq!(ArchiveStatus::parse(status.as_str()), Some(status));
        assert_eq!(ArchiveStatus::from_str(status.as_str()).unwrap(), status);
        assert!(status.can_transition_to(status), "同状态更新必须幂等");
    }
    assert_eq!(ArchiveStatus::Pending.as_str(), "pending");
    assert_eq!(ArchiveStatus::Uploaded.as_str(), "uploaded");
    assert_eq!(ArchiveStatus::LocalDeleted.as_str(), "local_deleted");
    assert_eq!(ArchiveStatus::Failed.as_str(), "failed");
    assert_eq!(ArchiveStatus::parse("uploading"), None);
    assert_eq!(
        ArchiveStatus::from_str("localDeleted"),
        Err(ArchiveError::InvalidStatus)
    );

    // 正常路径与失败路径。
    assert!(ArchiveStatus::Pending.can_transition_to(ArchiveStatus::Uploaded));
    assert!(ArchiveStatus::Uploaded.can_transition_to(ArchiveStatus::LocalDeleted));
    assert!(ArchiveStatus::Pending.can_transition_to(ArchiveStatus::Failed));
    assert!(ArchiveStatus::Uploaded.can_transition_to(ArchiveStatus::Failed));
    assert!(ArchiveStatus::Failed.can_transition_to(ArchiveStatus::Pending));
    assert!(ArchiveStatus::Failed.can_transition_to(ArchiveStatus::Uploaded));

    // 不能跳过上传直接标记本地已删；local_deleted 不得回退。
    assert!(!ArchiveStatus::Pending.can_transition_to(ArchiveStatus::LocalDeleted));
    assert!(!ArchiveStatus::Failed.can_transition_to(ArchiveStatus::LocalDeleted));
    for next in [
        ArchiveStatus::Pending,
        ArchiveStatus::Uploaded,
        ArchiveStatus::Failed,
    ] {
        assert!(
            !ArchiveStatus::LocalDeleted.can_transition_to(next),
            "local_deleted 不得回退到 {next:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// CSV.GZ / SHA-256 / manifest / key
// ---------------------------------------------------------------------------

#[test]
fn csv_gzip_roundtrip_escapes_rfc4180_and_reports_digest() {
    let mut writer = CsvArchiveWriter::new();
    assert_eq!(writer.rows(), 0);

    let labels = "{\"host\":\"web-1\"}";
    writer
        .write_row("agent-1", "cpu.usage", labels, 1_700_000_000_000, 12.5)
        .unwrap();
    assert_eq!(writer.rows(), 1);

    // 逗号 / 双引号 / 实际换行 / UTF-8 都必须按 CSV 规则转义。
    let tricky_labels = "{\"l\":\"x\ny\",\"备注\":\"a,b\"}";
    writer
        .write_row(
            "agent,2",
            "mem\"used",
            tricky_labels,
            1_700_000_000_001,
            1.0,
        )
        .unwrap();

    let output = writer.finish().unwrap();
    assert_eq!(output.rows, 2);
    assert_eq!(output.bytes, output.data.len() as u64);
    assert_eq!(output.sha256, sha256_hex(&output.data));
    assert_eq!(output.sha256.len(), 64);
    assert!(output.data.starts_with(&[0x1f, 0x8b]), "必须是 gzip 数据");

    let text = gunzip(&output.data);
    let expected_first = format!("agent-1,cpu.usage,{},1700000000000,12.5", quoted(labels));
    let expected_second = format!(
        "{},{},{},1700000000001,1",
        quoted("agent,2"),
        quoted("mem\"used"),
        quoted(tricky_labels)
    );
    assert_eq!(
        text,
        format!("{CSV_HEADER}\n{expected_first}\n{expected_second}\n")
    );

    // 空对象也必须有表头，避免生成 0 字节 gz。
    let empty = CsvArchiveWriter::new().finish().unwrap();
    assert_eq!(empty.rows, 0);
    assert_eq!(empty.bytes, empty.data.len() as u64);
    assert_eq!(gunzip(&empty.data), format!("{CSV_HEADER}\n"));
}

#[test]
fn csv_value_format_is_stable_roundtrip() {
    for (value, expected) in [
        (1.0, "1"),
        (-0.0, "-0"),
        (12.5, "12.5"),
        (0.1, "0.1"),
        (-1234.5678, "-1234.5678"),
        (f64::NAN, "NaN"),
        (f64::INFINITY, "inf"),
        (f64::NEG_INFINITY, "-inf"),
    ] {
        assert_eq!(format_csv_value(value), expected);
    }
    // CSV 里的十进制值必须能无损往返到同一个 f64。
    for value in [0.1, -0.0, 1.234_567_890_123_45, f64::MIN_POSITIVE] {
        let text = format_csv_value(value);
        assert_eq!(text.parse::<f64>().unwrap(), value, "{text} 不能往返");
    }
}

#[test]
fn sha256_known_vectors() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_ne!(sha256_hex(b"rustboard"), sha256_hex(b"RustBoard"));
}

#[test]
fn manifest_json_is_stable_and_roundtrips() {
    let manifest = ArchiveManifest::new(
        "rustboard/2026/10/24/part-00001.csv.gz",
        1_700_000_000_000,
        1_700_086_400_000,
        42,
        128,
        "abc123",
        1_700_090_000_000,
    );
    assert_eq!(manifest.format_version, MANIFEST_FORMAT_VERSION);

    let expected = format!(
        "{{\n  \"format_version\": {MANIFEST_FORMAT_VERSION},\n  \
         \"object_key\": \"rustboard/2026/10/24/part-00001.csv.gz\",\n  \
         \"from_ts\": 1700000000000,\n  \"to_ts\": 1700086400000,\n  \
         \"rows\": 42,\n  \"bytes\": 128,\n  \"sha256\": \"abc123\",\n  \
         \"created_at\": 1700090000000\n}}\n"
    );
    let json = manifest.to_json().unwrap();
    assert_eq!(json, expected, "manifest JSON 必须字段有序且末尾换行");
    assert_eq!(manifest_json(&manifest).unwrap(), json);
    assert_eq!(ArchiveManifest::from_json(&json).unwrap(), manifest);

    assert_eq!(
        ArchiveManifest::from_json("{}"),
        Err(ArchiveError::InvalidManifest)
    );
    assert_eq!(
        ArchiveManifest::from_json("not json"),
        Err(ArchiveError::InvalidManifest)
    );
}

#[test]
fn object_keys_only_accept_valid_utc_day_and_shard() {
    let day = ArchiveDay::new(2026, 10, 24).unwrap();
    assert_eq!((day.year(), day.month(), day.day()), (2026, 10, 24));

    let keys = build_object_keys("rustboard", day, "part-00001").unwrap();
    assert_eq!(keys.object_key, "rustboard/2026/10/24/part-00001.csv.gz");
    assert_eq!(
        keys.manifest_key,
        "rustboard/2026/10/24/part-00001.manifest.json"
    );

    // 闰日与最大分片编号。
    let leap = ArchiveDay::new(2024, 2, 29).unwrap();
    assert_eq!(
        build_object_keys("rb-01", leap, "part-99999")
            .unwrap()
            .object_key,
        "rb-01/2024/02/29/part-99999.csv.gz"
    );
    assert_eq!(MAX_ARCHIVE_SHARD, 99_999);

    for prefix in ["", "a/b", "../evil", "a..b", "a b", "中文"] {
        assert_eq!(
            build_object_keys(prefix, day, "part-00001"),
            Err(ArchiveError::InvalidKey),
            "prefix {prefix:?} 必须拒绝"
        );
    }
    assert_eq!(
        build_object_keys(&"a".repeat(65), day, "part-00001"),
        Err(ArchiveError::InvalidKey)
    );

    for shard in [
        "part-00000",
        "part-1",
        "part-000001",
        "part-100000",
        "part-00a01",
        "../part-00001",
        "/part-00001",
        "part-00001/../x",
        "part-00001.csv.gz",
        "",
    ] {
        assert_eq!(
            build_object_keys("rustboard", day, shard),
            Err(ArchiveError::InvalidKey),
            "shard {shard:?} 必须拒绝"
        );
    }

    for (year, month, date) in [
        (1969, 12, 31),
        (10000, 1, 1),
        (2025, 2, 29),
        (2024, 2, 30),
        (2026, 0, 1),
        (2026, 13, 1),
        (2026, 1, 0),
        (2026, 4, 31),
    ] {
        assert_eq!(
            ArchiveDay::new(year, month, date),
            Err(ArchiveError::InvalidKey),
            "{year}-{month}-{date} 必须拒绝"
        );
    }
}

// ---------------------------------------------------------------------------
// ColdStore
// ---------------------------------------------------------------------------

#[test]
fn cold_store_contract_supports_dyn_and_redacts_errors() {
    let store = MemoryColdStore::default();
    let store_ref: &dyn ColdStore = &store;
    assert_eq!(block_on(store_ref.head("object-1")).unwrap(), None);
    block_on(store_ref.put("object-1", b"hello")).unwrap();
    assert_eq!(
        block_on(store_ref.head("object-1")).unwrap(),
        Some(ColdObjectMeta { size: 5 })
    );
    assert_eq!(block_on(store_ref.get("object-1")).unwrap(), b"hello");
    block_on(store_ref.test()).unwrap();

    block_on(store_ref.delete("object-1")).unwrap();
    assert_eq!(block_on(store_ref.head("object-1")).unwrap(), None);
    // delete 幂等；get 不存在时返回固定 NotFound。
    block_on(store_ref.delete("object-1")).unwrap();
    assert_eq!(
        block_on(store_ref.get("object-1")),
        Err(ArchiveError::NotFound)
    );

    let failing = FailingColdStore {
        endpoint: "https://ops:password@dav.internal.example/rustboard".to_string(),
    };
    // mock 确实持有敏感值，但错误分类不携带它。
    assert!(!failing.endpoint.is_empty());
    for error in [
        block_on(failing.put("k", b"v")).unwrap_err(),
        block_on(failing.get("k")).unwrap_err(),
        block_on(failing.delete("k")).unwrap_err(),
        block_on(failing.head("k")).unwrap_err(),
        block_on(failing.test()).unwrap_err(),
    ] {
        assert_eq!(error, ArchiveError::BackendUnavailable);
        let text = error.to_string();
        assert_eq!(text, "冷存储后端不可用");
        let debug = format!("{error:?}");
        for secret in ["password", "dav.internal.example", "ops"] {
            assert!(!text.contains(secret), "错误 Display 泄露 {secret}: {text}");
            assert!(!debug.contains(secret), "错误 Debug 泄露 {secret}: {debug}");
        }
    }
}

// ---------------------------------------------------------------------------
// SQLite 存储
// ---------------------------------------------------------------------------

fn archive_object(key: &str, from_ts: i64, to_ts: i64, status: ArchiveStatus) -> ArchiveObject {
    ArchiveObject {
        id: 0,
        backend: "webdav".to_string(),
        object_key: key.to_string(),
        manifest_key: format!("{}.manifest.json", key.trim_end_matches(".csv.gz")),
        from_ts,
        to_ts,
        rows: 10,
        bytes: 100,
        sha256: "a".repeat(64),
        status,
        error: String::new(),
        created_at: 1_000,
        uploaded_at: None,
        deleted_at: None,
        ledger_version: 0,
        attempts: 0,
    }
}

#[test]
fn archive_object_insert_get_unique_and_pagination() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    let first = archive_object(
        "rustboard/2026/10/24/part-00001.csv.gz",
        100,
        200,
        ArchiveStatus::Pending,
    );
    let first_id = storage.insert_archive_object(&first).unwrap();
    assert!(first_id > 0);

    let mut expected = first.clone();
    expected.id = first_id;
    assert_eq!(
        storage.get_archive_object(first_id).unwrap(),
        Some(expected.clone())
    );
    assert_eq!(storage.get_archive_object(first_id + 999).unwrap(), None);
    assert_eq!(
        storage
            .find_archive_object_by_key(&first.object_key)
            .unwrap()
            .unwrap()
            .id,
        first_id
    );
    assert!(storage
        .find_archive_object_by_key("rustboard/missing.csv.gz")
        .unwrap()
        .is_none());

    // object_key UNIQUE：字段不同也不能覆盖已有记录。
    let mut duplicate = archive_object(
        "rustboard/2026/10/24/part-00001.csv.gz",
        300,
        400,
        ArchiveStatus::Failed,
    );
    duplicate.backend = "s3".to_string();
    let err = storage.insert_archive_object(&duplicate).unwrap_err();
    assert_eq!(
        err.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::ObjectExists)
    );
    assert_eq!(err.to_string(), "归档对象已存在");
    assert_eq!(
        storage.get_archive_object(first_id).unwrap().unwrap(),
        expected,
        "唯一冲突不得修改原记录"
    );

    // 分页：id 倒序，before_id 排他。
    let second_id = storage
        .insert_archive_object(&archive_object(
            "rustboard/2026/10/25/part-00001.csv.gz",
            300,
            400,
            ArchiveStatus::Pending,
        ))
        .unwrap();
    let third_id = storage
        .insert_archive_object(&archive_object(
            "rustboard/2026/10/26/part-00001.csv.gz",
            500,
            600,
            ArchiveStatus::Pending,
        ))
        .unwrap();

    let page = storage.list_archive_objects(2, None).unwrap();
    assert_eq!(
        page.iter().map(|object| object.id).collect::<Vec<_>>(),
        vec![third_id, second_id]
    );
    let page = storage.list_archive_objects(2, Some(second_id)).unwrap();
    assert_eq!(
        page.iter().map(|object| object.id).collect::<Vec<_>>(),
        vec![first_id]
    );
    assert!(storage.list_archive_objects(0, None).unwrap().is_empty());
    assert_eq!(storage.list_archive_objects(100, None).unwrap().len(), 3);
}

#[test]
fn archive_status_transitions_are_enforced_and_timestamps_preserved() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    let id = storage
        .insert_archive_object(&archive_object(
            "rustboard/2026/10/24/part-00001.csv.gz",
            100,
            200,
            ArchiveStatus::Pending,
        ))
        .unwrap();

    // pending -> uploaded：记录上传时间与 error（成功时应传空串）。
    storage
        .update_archive_object_status(id, ArchiveStatus::Uploaded, "", Some(1_100), None)
        .unwrap();
    let object = storage.get_archive_object(id).unwrap().unwrap();
    assert_eq!(object.status, ArchiveStatus::Uploaded);
    assert_eq!(object.uploaded_at, Some(1_100));
    assert_eq!(object.deleted_at, None);
    assert_eq!(object.error, "");

    // uploaded -> local_deleted：uploaded_at=None 不得清空历史时间戳。
    storage
        .update_archive_object_status(id, ArchiveStatus::LocalDeleted, "", None, Some(1_200))
        .unwrap();
    let object = storage.get_archive_object(id).unwrap().unwrap();
    assert_eq!(object.status, ArchiveStatus::LocalDeleted);
    assert_eq!(object.uploaded_at, Some(1_100));
    assert_eq!(object.deleted_at, Some(1_200));

    // local_deleted 是终态：任何不同状态都非法，同状态幂等。
    for next in [
        ArchiveStatus::Pending,
        ArchiveStatus::Uploaded,
        ArchiveStatus::Failed,
    ] {
        let err = storage
            .update_archive_object_status(id, next, "", None, None)
            .unwrap_err();
        assert_eq!(
            err.downcast_ref::<ArchiveStoreError>(),
            Some(&ArchiveStoreError::InvalidTransition),
            "local_deleted -> {next:?} 必须拒绝"
        );
        assert_eq!(err.to_string(), "归档对象状态迁移非法");
    }
    storage
        .update_archive_object_status(id, ArchiveStatus::LocalDeleted, "", None, None)
        .unwrap();

    // 失败路径：pending -> failed 记录 error；failed 可重试回 pending。
    let failed_id = storage
        .insert_archive_object(&archive_object(
            "rustboard/2026/10/24/part-00002.csv.gz",
            100,
            200,
            ArchiveStatus::Pending,
        ))
        .unwrap();
    let err = storage
        .update_archive_object_status(failed_id, ArchiveStatus::LocalDeleted, "", None, None)
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::InvalidTransition)
    );
    storage
        .update_archive_object_status(failed_id, ArchiveStatus::Failed, "后端 500", None, None)
        .unwrap();
    let object = storage.get_archive_object(failed_id).unwrap().unwrap();
    assert_eq!(object.status, ArchiveStatus::Failed);
    assert_eq!(object.error, "后端 500");
    storage
        .update_archive_object_status(failed_id, ArchiveStatus::Pending, "", None, None)
        .unwrap();
    assert_eq!(
        storage
            .get_archive_object(failed_id)
            .unwrap()
            .unwrap()
            .error,
        "",
        "重试时应由调用方清空旧错误"
    );

    // 不存在的 id。
    let err = storage
        .update_archive_object_status(9_999, ArchiveStatus::Uploaded, "", None, None)
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<ArchiveStoreError>(),
        Some(&ArchiveStoreError::NotFound)
    );
}

#[test]
fn archive_state_upsert_and_range_query() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    assert_eq!(storage.get_archive_state("last_archived_ts").unwrap(), None);
    storage
        .set_archive_state("last_archived_ts", "100", 1_000)
        .unwrap();
    storage
        .set_archive_state("last_downsample_ts", "50", 900)
        .unwrap();
    assert_eq!(
        storage.get_archive_state("last_archived_ts").unwrap(),
        Some("100".to_string())
    );

    // UPSERT：同一 key 不新增行，value 刷新。
    storage
        .set_archive_state("last_archived_ts", "200", 2_000)
        .unwrap();
    assert_eq!(
        storage.get_archive_state("last_archived_ts").unwrap(),
        Some("200".to_string())
    );

    // 参数化：引号 / SQL 片段按字面量存取。
    let key = "k'quote";
    let value = "v'; DROP TABLE archive_state; --";
    storage.set_archive_state(key, value, 3_000).unwrap();
    assert_eq!(
        storage.get_archive_state(key).unwrap(),
        Some(value.to_string())
    );
    assert_eq!(
        storage.get_archive_state("last_archived_ts").unwrap(),
        Some("200".to_string()),
        "注入字符串不得破坏已有水位"
    );

    // 范围查询：两端包含、按 from_ts,id 升序，不按 status 过滤。
    let ids = [
        storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00001.csv.gz",
                100,
                200,
                ArchiveStatus::Uploaded,
            ))
            .unwrap(),
        storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00002.csv.gz",
                300,
                400,
                ArchiveStatus::Uploaded,
            ))
            .unwrap(),
        storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00003.csv.gz",
                300,
                350,
                ArchiveStatus::Failed,
            ))
            .unwrap(),
        storage
            .insert_archive_object(&archive_object(
                "rustboard/2026/10/24/part-00004.csv.gz",
                500,
                600,
                ArchiveStatus::LocalDeleted,
            ))
            .unwrap(),
    ];

    let ranged = storage.list_archive_objects_in_range(200, 300).unwrap();
    assert_eq!(
        ranged.iter().map(|object| object.id).collect::<Vec<_>>(),
        vec![ids[0], ids[1], ids[2]],
        "边界包含且同 from_ts 按 id 升序"
    );
    assert!(storage
        .list_archive_objects_in_range(201, 299)
        .unwrap()
        .is_empty());
    let all = storage.list_archive_objects_in_range(0, 1_000).unwrap();
    assert_eq!(
        all.iter().map(|object| object.id).collect::<Vec<_>>(),
        ids.to_vec()
    );
    assert_eq!(
        storage
            .list_archive_objects_in_range(600, 600)
            .unwrap()
            .iter()
            .map(|object| object.id)
            .collect::<Vec<_>>(),
        vec![ids[3]],
        "单点范围也要包含跨过该点的对象"
    );
}
