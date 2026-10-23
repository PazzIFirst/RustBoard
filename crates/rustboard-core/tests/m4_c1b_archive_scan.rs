//! M4-C1b 验收测试：归档 worker 的 raw 扫描辅助。
//!
//! 覆盖方案 §7.2：按 `rowid` 升序、左闭右开时间范围、`after_rowid` 排他游标、
//! `limit` 分批，以及 `archive_objects` 计数。

use rustboard_common::model::{Sample, SampleBatch};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::{IngestOutcome, Storage};

const BASE: i64 = 1_700_000_000_000;

fn insert_rows(storage: &SqliteStorage, values: &[(i64, f64)]) {
    let batch = SampleBatch {
        agent_id: "agent-1".to_string(),
        epoch: 1,
        seq: 1,
        boot_id: "boot".to_string(),
        sent_at: BASE,
        samples: values
            .iter()
            .enumerate()
            .map(|(index, (ts, value))| {
                Sample::new("cpu.usage", *ts, *value).with_label("host", format!("host-{index}"))
            })
            .collect(),
    };
    assert!(matches!(
        storage.insert_batch(&batch).unwrap(),
        IngestOutcome::Inserted { inserted } if inserted == values.len()
    ));
}

#[test]
fn scan_archive_rows_is_rowid_ordered_and_batched() {
    let storage = SqliteStorage::open_in_memory().unwrap();
    insert_rows(
        &storage,
        &[
            (BASE + 1, 1.0),
            (BASE + 2, 2.0),
            (BASE + 3, 3.0),
            (BASE + 10, 10.0),
        ],
    );

    // 左闭右开：BASE + 10 必须被排除。
    let first = storage.scan_archive_rows(BASE, BASE + 10, None, 2).unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].ts, BASE + 1);
    assert_eq!(first[1].ts, BASE + 2);
    assert!(first[0].rowid < first[1].rowid, "必须按 rowid 升序");
    assert_eq!(first[0].agent_id, "agent-1");
    assert_eq!(first[0].metric, "cpu.usage");
    assert_eq!(first[0].labels, r#"{"host":"host-0"}"#);
    assert_eq!(first[0].value, 1.0);

    // after_rowid 排他：从第一页最后一条继续。
    let second = storage
        .scan_archive_rows(BASE, BASE + 10, Some(first[1].rowid), 2)
        .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].ts, BASE + 3);
    assert!(second[0].rowid > first[1].rowid);

    let end = storage
        .scan_archive_rows(BASE, BASE + 10, Some(second[0].rowid), 2)
        .unwrap();
    assert!(end.is_empty());

    // limit = 0、空范围、时间范围外都返回空，不 panic。
    assert!(storage
        .scan_archive_rows(BASE, BASE + 10, None, 0)
        .unwrap()
        .is_empty());
    assert!(storage
        .scan_archive_rows(BASE + 100, BASE + 200, None, 10)
        .unwrap()
        .is_empty());
    assert!(storage
        .scan_archive_rows(BASE + 10, BASE + 20, None, 10)
        .unwrap()
        .iter()
        .all(|row| row.ts == BASE + 10));
    assert_eq!(storage.count_archive_objects().unwrap(), 0);
}
