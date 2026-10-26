//! #34 的 DiskBuffer 恢复验收测试。
//!
//! 覆盖：双 meta 回退与 fail-closed、meta 非记录边界、中间损坏向前重同步、
//! 尾部半写截断、已 ACK 前缀不复活、重复打开幂等、显式 repair 入口。
//! 只通过公开 API 与磁盘文件观察行为。

use super::*;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const MIB: u64 = 1024 * 1024;

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rb-v100-{}-{tag}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn batch_with(epoch: u64, seq: u64, padding: usize) -> SampleBatch {
    let suffix = "x".repeat(padding);
    SampleBatch {
        agent_id: "agent-v100".to_string(),
        epoch,
        seq,
        boot_id: "boot-v100".to_string(),
        sent_at: rustboard_common::util::now_ms(),
        samples: vec![rustboard_common::model::Sample::new(
            format!("v100.metric.{seq}.{suffix}"),
            rustboard_common::util::now_ms(),
            seq as f64,
        )],
    }
}

fn read_meta(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

fn pending_seqs(buf: &mut DiskBuffer) -> Vec<u64> {
    buf.read_next(100_000)
        .expect("read_next 失败")
        .iter()
        .map(|b| b.seq)
        .collect()
}

/// 日志中的 `(起始偏移, 记录长度)` 列表；只用于测试，要求文件是完整记录序列。
fn record_layout(dir: &Path) -> Vec<(u64, u64)> {
    let bytes = std::fs::read(dir.join(LOG_FILE)).expect("读取 buffer.log 失败");
    let mut out = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= bytes.len() {
        let payload_len =
            u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let record_len = 4 + payload_len;
        assert!(
            offset + record_len <= bytes.len(),
            "测试前置条件：日志必须由完整记录组成，offset={offset}"
        );
        out.push((offset as u64, record_len as u64));
        offset += record_len;
    }
    assert_eq!(offset, bytes.len(), "日志尾部有残缺字节");
    out
}

/// 把第 `index` 条记录的 payload 首字节改成 0xc1（msgpack 中永不使用的字节），
/// 长度头保持合法，因此后续记录边界仍然可被重新同步找到。
fn corrupt_payload_byte(dir: &Path, index: usize) {
    let layout = record_layout(dir);
    let (offset, len) = layout[index];
    assert!(len > 4, "记录太短，无法篡改 payload");
    let log_path = dir.join(LOG_FILE);
    let mut bytes = std::fs::read(&log_path).unwrap();
    bytes[offset as usize + 4] = 0xc1;
    std::fs::write(&log_path, bytes).unwrap();
}

fn corrupt_copies(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(CORRUPT_LOG_PREFIX)
        {
            out.push(entry.path());
        }
    }
    out.sort();
    out
}

#[cfg(unix)]
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn meta_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join(META_FILE), dir.join(META_BACKUP_FILE))
}

/// meta=1（有 backup）：回退到 backup 从日志开头恢复全部记录，并修复 primary。
#[test]
fn meta_offset_one_with_backup_restores_all_records() {
    let dir = TempDir::new("meta-one-backup");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        // 制造 backup=0、primary=已确认 seq0 后的偏移。
        buf.ack(1, 0).unwrap();
    }
    let (primary, backup) = meta_paths(dir.path());
    assert_eq!(read_meta(&backup), Some(0), "首次落盘 backup 应是旧值 0");
    let good = read_meta(&primary).expect("primary 应存在");
    assert!(good > 1);
    std::fs::write(&primary, "1").unwrap();

    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("有 backup 时必须恢复而不是失败");
    assert_eq!(
        pending_seqs(&mut buf),
        vec![0, 1, 2],
        "backup=0 应恢复日志开头的全部记录"
    );
    assert_eq!(buf.read_offset, 0);
    assert_eq!(
        read_meta(&primary),
        Some(buf.read_offset),
        "回退 backup 后必须把 primary 修复为同一偏移"
    );
}

/// meta=1 且没有 backup：fail-closed，保留文件并给出显式修复指引。
#[test]
fn meta_offset_one_without_backup_fails_closed() {
    let dir = TempDir::new("meta-one-fail-closed");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        buf.ack(1, 0).unwrap();
    }
    let (primary, backup) = meta_paths(dir.path());
    std::fs::remove_file(&backup).unwrap();
    std::fs::write(&primary, "1").unwrap();
    let log_before = std::fs::read(dir.path().join(LOG_FILE)).unwrap();

    let err = match DiskBuffer::open(dir.path(), MIB, 0) {
        Ok(_) => panic!("两条 meta 都非法时必须 fail-closed"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    let message = err.to_string();
    assert!(
        message.contains("buffer repair --from-start"),
        "错误信息必须给出显式修复入口: {message}"
    );
    assert!(
        message.contains(META_FILE) && message.contains(META_BACKUP_FILE),
        "错误信息必须点名两条 meta: {message}"
    );
    assert_eq!(
        std::fs::read(dir.path().join(LOG_FILE)).unwrap(),
        log_before,
        "fail-closed 不得修改 buffer.log"
    );
    assert_eq!(
        std::fs::read_to_string(&primary).unwrap(),
        "1",
        "fail-closed 不得改写损坏的 primary"
    );
    assert!(!backup.exists(), "fail-closed 不得凭空空建 backup");

    // 显式 repair 后可以恢复（会重发已 ACK 的 seq=0，依赖 hub 判重）。
    repair_from_start(dir.path()).expect("repair 失败");
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("repair 后应能打开");
    assert_eq!(pending_seqs(&mut buf), vec![0, 1, 2]);
}

/// 第二条 payload 改成 0xc1：第 3 条必须保留，坏区间由压实移除，并留 0600 副本。
#[test]
fn middle_corruption_keeps_later_records_and_preserves_copy() {
    let dir = TempDir::new("middle-corruption");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
    }
    corrupt_payload_byte(dir.path(), 1);
    let damaged = std::fs::read(dir.path().join(LOG_FILE)).unwrap();
    let layout_before = record_layout(dir.path());
    let expected_after_compact = layout_before[0].1 + layout_before[2].1;

    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("中间损坏必须自愈");
    assert_eq!(
        pending_seqs(&mut buf),
        vec![0, 2],
        "第 2 条损坏，第 1/3 条必须保留"
    );
    assert_eq!(
        file_len(&dir.path().join(LOG_FILE)),
        expected_after_compact,
        "read_offset=0 的中间损坏应立即压实，物理移除坏区间"
    );
    let copies = corrupt_copies(dir.path());
    assert_eq!(copies.len(), 1, "修复前应保留一份损坏日志副本");
    assert_eq!(
        std::fs::read(&copies[0]).unwrap(),
        damaged,
        "损坏副本必须是修复前的原始字节"
    );
    #[cfg(unix)]
    assert_eq!(mode_of(&copies[0]), 0o600, "损坏副本必须是 0600");

    // 重复打开幂等：pending 与文件长度不变，也不会重复制造损坏副本。
    drop(buf);
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(pending_seqs(&mut buf), vec![0, 2]);
    assert_eq!(corrupt_copies(dir.path()).len(), 1);
    assert_eq!(file_len(&dir.path().join(LOG_FILE)), expected_after_compact);

    buf.ack(1, 2).unwrap();
    assert_eq!(buf.pending_len(), 0);
}

/// 长度头本身损坏（不只是 payload）：走逐字节向前重同步，同样保留后续记录。
#[test]
fn corrupt_length_header_resyncs_to_later_records() {
    let dir = TempDir::new("corrupt-header");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..4 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
    }
    let layout = record_layout(dir.path());
    let log_path = dir.path().join(LOG_FILE);
    let mut bytes = std::fs::read(&log_path).unwrap();
    let (offset, _) = layout[1];
    // 把第 2 条的长度头改成越界值：既不能解码，也算不出记录结尾。
    bytes[offset as usize..offset as usize + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&log_path, &bytes).unwrap();

    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("长度头损坏也必须自愈");
    assert_eq!(
        pending_seqs(&mut buf),
        vec![0, 2, 3],
        "长度头损坏后应重同步到第 3/4 条有效记录"
    );
    assert_eq!(corrupt_copies(dir.path()).len(), 1);
    // 落盘 meta 即便在 ACK 后也必须仍是记录边界：重开验证。
    buf.ack(1, 0).unwrap();
    drop(buf);
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(pending_seqs(&mut buf), vec![2, 3]);
}

/// 尾部半写：只截断撕裂的最后一条，前面的记录全部保留。
#[test]
fn tail_half_write_truncates_only_torn_record() {
    let dir = TempDir::new("tail-half-write");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
    }
    let layout = record_layout(dir.path());
    let last_len = layout[2].1;
    assert!(last_len > 2);
    let torn_len = layout[2].0 + last_len / 2;
    let log_path = dir.path().join(LOG_FILE);
    let mut bytes = std::fs::read(&log_path).unwrap();
    bytes.truncate(torn_len as usize);
    std::fs::write(&log_path, &bytes).unwrap();

    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("尾部半写必须自愈");
    assert_eq!(pending_seqs(&mut buf), vec![0, 1], "只允许丢掉被撕裂的末条");
    assert_eq!(
        file_len(&log_path),
        layout[2].0,
        "应截断到最后一条有效记录末尾"
    );
    let copies = corrupt_copies(dir.path());
    assert_eq!(copies.len(), 1);
    assert_eq!(
        std::fs::read(&copies[0]).unwrap(),
        bytes,
        "副本是截断前内容"
    );
    #[cfg(unix)]
    assert_eq!(mode_of(&copies[0]), 0o600);

    // 第二次打开：已是干净文件，不得再次复制或截断。
    drop(buf);
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(pending_seqs(&mut buf), vec![0, 1]);
    assert_eq!(corrupt_copies(dir.path()).len(), 1);
    assert_eq!(file_len(&log_path), layout[2].0);
}

/// 中间损坏（read_offset 已推进）不得复活已 ACK 前缀，后续有效记录要保留。
#[test]
fn middle_corruption_keeps_later_records_without_resurrecting_acked_prefix() {
    let dir = TempDir::new("middle-acked");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..5 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        buf.ack(1, 0).unwrap();
        buf.ack(1, 1).unwrap();
        assert_eq!(pending_seqs(&mut buf), vec![2, 3, 4]);
    }
    // 损坏第 4 条（seq=3），它前后都有有效记录。
    corrupt_payload_byte(dir.path(), 3);

    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("中间损坏必须自愈");
    assert_eq!(
        pending_seqs(&mut buf),
        vec![2, 4],
        "seq=2/4 必须保留，seq=3 丢掉；已 ACK 的 0/1 不得复活"
    );
    assert!(!pending_seqs(&mut buf).contains(&0));
    assert!(!pending_seqs(&mut buf).contains(&1));
    assert_eq!(corrupt_copies(dir.path()).len(), 1, "损坏修复应留下副本");
    assert_eq!(
        read_meta(&dir.path().join(META_FILE)),
        Some(buf.read_offset)
    );

    // 再打开一次：pending 不变；如果坏区间尚未压实，也不重复复制。
    drop(buf);
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(pending_seqs(&mut buf), vec![2, 4]);
    assert_eq!(corrupt_copies(dir.path()).len(), 1);

    // ACK seq=2 时读指针跨过中间坏区间，落盘的 meta 必须是合法记录边界，
    // 重启后只保留 seq=4，已 ACK 的 0/1/2 不复活。
    buf.ack(1, 2).unwrap();
    assert_eq!(pending_seqs(&mut buf), vec![4]);
    let primary = dir.path().join(META_FILE);
    assert_eq!(read_meta(&primary), Some(buf.read_offset));
    drop(buf);
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(
        pending_seqs(&mut buf),
        vec![4],
        "ACK 后的 meta 必须仍是记录边界"
    );
}

/// 只有 primary、没有 backup（旧版本 agent 或人工删除 backup）仍能正常恢复。
#[test]
fn primary_meta_alone_remains_downgrade_compatible() {
    let dir = TempDir::new("primary-only");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        buf.ack(1, 0).unwrap();
    }
    let (primary, backup) = meta_paths(dir.path());
    std::fs::remove_file(&backup).unwrap();
    let expected = read_meta(&primary).expect("primary 应存在");

    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("只有 primary 时不得 fail-closed");
    assert_eq!(pending_seqs(&mut buf), vec![1, 2]);
    assert_eq!(buf.read_offset, expected);
    assert_eq!(
        read_meta(&primary),
        Some(expected),
        "正常路径不应改写 primary"
    );
}

/// 正常缓冲重复打开：pending、meta、文件长度完全稳定，不产生损坏副本。
#[test]
fn healthy_reopen_is_idempotent() {
    let dir = TempDir::new("healthy-idempotent");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        buf.ack(1, 1).unwrap();
    }
    let (primary, backup) = meta_paths(dir.path());
    let meta_before = (read_meta(&primary), read_meta(&backup));
    let log_len_before = file_len(&dir.path().join(LOG_FILE));

    let mut first = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(pending_seqs(&mut first), vec![2]);
    drop(first);
    let mut second = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(pending_seqs(&mut second), vec![2]);
    assert_eq!(
        (read_meta(&primary), read_meta(&backup)),
        meta_before,
        "重复打开不得改写 meta"
    );
    assert_eq!(file_len(&dir.path().join(LOG_FILE)), log_len_before);
    assert!(corrupt_copies(dir.path()).is_empty());
    assert_eq!(read_meta(&backup), Some(0), "backup 保存旧值");

    #[cfg(unix)]
    {
        assert_eq!(mode_of(&primary), 0o600, "primary meta 必须是 0600");
        assert_eq!(mode_of(&backup), 0o600, "backup meta 必须是 0600");
    }
}

/// 显式 repair：只重置两条 meta 到 0，不动日志；重开后重发全部记录（含已 ACK）。
#[test]
fn repair_from_start_resets_metas_and_replays_all_records() {
    let dir = TempDir::new("repair");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        buf.ack(1, 1).unwrap();
    }
    let log_before = std::fs::read(dir.path().join(LOG_FILE)).unwrap();
    let (primary, backup) = meta_paths(dir.path());
    assert_ne!(read_meta(&primary), Some(0));

    let report = repair_from_start(dir.path()).expect("repair 失败");
    assert_eq!(report.log_bytes, log_before.len() as u64);
    assert!(report.had_primary && report.had_backup);
    assert_eq!(read_meta(&primary), Some(0));
    assert_eq!(read_meta(&backup), Some(0));
    assert_eq!(
        std::fs::read(dir.path().join(LOG_FILE)).unwrap(),
        log_before,
        "repair 不得修改日志"
    );

    // 重复执行幂等。
    let again = repair_from_start(dir.path()).unwrap();
    assert_eq!(again.log_bytes, report.log_bytes);

    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(
        pending_seqs(&mut buf),
        vec![0, 1, 2],
        "显式从日志开头恢复会重发已 ACK 前缀，依赖 hub 判重"
    );
}

/// 两条 meta 都是非法内容：fail-closed，不修改任何文件。
#[test]
fn both_metas_invalid_fail_closed_preserves_files() {
    let dir = TempDir::new("both-invalid");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..2 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        buf.ack(1, 0).unwrap();
    }
    let (primary, backup) = meta_paths(dir.path());
    std::fs::write(&primary, "not-a-number").unwrap();
    std::fs::write(&backup, "999999999").unwrap();
    let log_before = std::fs::read(dir.path().join(LOG_FILE)).unwrap();

    let err = match DiskBuffer::open(dir.path(), MIB, 0) {
        Ok(_) => panic!("两条 meta 非法必须拒绝启动"),
        Err(err) => err,
    };
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    assert!(err.to_string().contains("buffer repair --from-start"));
    assert_eq!(
        std::fs::read(dir.path().join(LOG_FILE)).unwrap(),
        log_before
    );
    assert_eq!(std::fs::read_to_string(&primary).unwrap(), "not-a-number");
    assert_eq!(std::fs::read_to_string(&backup).unwrap(), "999999999");
}

/// repair --from-start 写入 0/0 后，即使首条记录损坏也必须能进入 recover 重同步。
#[test]
fn repair_from_start_accepts_zero_offset_even_with_corrupt_first_record() {
    let dir = TempDir::new("repair-zero-corrupt-first");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
    }
    corrupt_payload_byte(dir.path(), 0);
    repair_from_start(dir.path()).expect("repair 失败");
    let (primary, backup) = meta_paths(dir.path());
    assert_eq!(read_meta(&primary), Some(0));
    assert_eq!(read_meta(&backup), Some(0));

    let mut buf = DiskBuffer::open(dir.path(), MIB, 0)
        .expect("offset=0 必须无条件视为合法边界，首条损坏交给 recover 重同步");
    assert_eq!(pending_seqs(&mut buf), vec![1, 2]);
    assert_eq!(corrupt_copies(dir.path()).len(), 1, "首条损坏也要留副本");
    drop(buf);
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("二次打开仍应成功");
    assert_eq!(pending_seqs(&mut buf), vec![1, 2]);
}

/// 大记录长度头损坏后，重同步预算不得被“可算长度但未解码”的垃圾候选耗尽。
#[test]
fn corrupt_header_of_large_record_still_resyncs_to_later_records() {
    let dir = TempDir::new("large-header-corrupt");
    let max_bytes = 8 * MIB;
    {
        let mut buf = DiskBuffer::open(dir.path(), max_bytes, 0).unwrap();
        buf.push(&batch_with(1, 0, 0)).unwrap();
        buf.push(&batch_with(1, 1, MIB as usize)).unwrap();
        buf.push(&batch_with(1, 2, 0)).unwrap();
        buf.push(&batch_with(1, 3, 0)).unwrap();
    }
    let layout = record_layout(dir.path());
    assert!(layout[1].1 > 900_000, "测试前置条件：第 2 条必须是大记录");
    let log_path = dir.path().join(LOG_FILE);
    let mut bytes = std::fs::read(&log_path).unwrap();
    let (offset, record_len) = layout[1];
    // 用 [00 20 00 00] 重复填充 payload：大量字节位置都能算出 ≤8 MiB 的
    // “记录长度”，但 payload 首字节是 0x00/0x20，不会通过 msgpack 类型过滤。
    // 旧实现会为这些未解码候选扣预算并把真实记录当尾部截断。
    for (i, byte) in bytes[offset as usize + 4..(offset + record_len) as usize]
        .iter_mut()
        .enumerate()
    {
        *byte = [0x00u8, 0x20, 0x00, 0x00][i % 4];
    }
    bytes[offset as usize..offset as usize + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    std::fs::write(&log_path, &bytes).unwrap();

    let mut buf = DiskBuffer::open(dir.path(), max_bytes, 0).expect("大记录头损坏必须自愈");
    assert_eq!(
        pending_seqs(&mut buf),
        vec![0, 2, 3],
        "后续有效记录不得因重同步预算记账错误被误截断"
    );
    assert_eq!(corrupt_copies(dir.path()).len(), 1);
}

/// pending 清空（全部 ACK）后必须压实物理删除 ACK 前缀；双 meta 丢失也不得重放。
#[test]
fn acked_all_is_compacted_and_meta_loss_does_not_replay() {
    let dir = TempDir::new("acked-all-compact");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        buf.ack(1, 2).unwrap();
        assert_eq!(buf.pending_len(), 0);
    }
    assert_eq!(
        file_len(&dir.path().join(LOG_FILE)),
        0,
        "全部 ACK 后应压实为 0 字节，不能把 ACK 前缀留在文件里"
    );
    let (primary, backup) = meta_paths(dir.path());
    // 模拟两条 meta 都丢失（磁盘损坏 / 人为删除）。
    let _ = std::fs::remove_file(&primary);
    let _ = std::fs::remove_file(&backup);
    let buf = DiskBuffer::open(dir.path(), MIB, 0).expect("日志已清空时 meta 丢失不得重放 ACK");
    assert_eq!(buf.pending_len(), 0);
    assert_eq!(buf.pending_bytes(), 0);
}

/// 陈旧/非法 backup 不得覆盖有效 primary（旧版本只维护 primary 的降级场景）。
#[test]
fn stale_backup_never_overrides_valid_primary() {
    let dir = TempDir::new("stale-backup");
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
        for seq in 0..3 {
            buf.push(&batch_with(1, seq, 0)).unwrap();
        }
        buf.ack(1, 0).unwrap();
    }
    let (primary, backup) = meta_paths(dir.path());
    let primary_value = read_meta(&primary).expect("primary 应存在");
    // 1) 陈旧但仍是合法边界的 backup（0）：primary 优先，不得重放 seq=0。
    std::fs::write(&backup, "0").unwrap();
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(pending_seqs(&mut buf), vec![1, 2]);
    assert_eq!(read_meta(&primary), Some(primary_value));
    drop(buf);
    // 2) 非法/越界 backup：仍以 primary 为准。
    std::fs::write(&backup, "999999999").unwrap();
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    assert_eq!(pending_seqs(&mut buf), vec![1, 2]);
    assert_eq!(read_meta(&primary), Some(primary_value));
}

/// push 与 recover 共用 8 MiB 单条上限：超限批次直接拒绝，不写进日志。
#[test]
fn push_rejects_payload_above_recover_cap() {
    let dir = TempDir::new("push-cap");
    let mut buf = DiskBuffer::open(dir.path(), MIB, 0).unwrap();
    let oversized = batch_with(1, 0, MAX_RECORD_PAYLOAD_BYTES as usize);
    let err = buf
        .push(&oversized)
        .expect_err("超过 8 MiB 的 payload 必须拒绝");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("上限"), "错误信息: {err}");
    assert_eq!(
        file_len(&dir.path().join(LOG_FILE)),
        0,
        "拒绝后不得写入任何字节"
    );
    assert_eq!(buf.pending_len(), 0);
    // 正常批次不受影响。
    buf.push(&batch_with(1, 1, 0)).unwrap();
    assert_eq!(pending_seqs(&mut buf), vec![1]);
}
