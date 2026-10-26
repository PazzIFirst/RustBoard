//! v0.3.1 Issue #10 / 方案 A2 的 DiskBuffer 独立验收测试。
//!
//! 只依据 `docs/plans/2026-10-23-v0.3.1-hardening.md` §3.2 / §5 的接口与验收契约编写，
//! 不参考 `buffer.rs` 的实现细节；所有断言都直接观察磁盘文件、meta 文件与公开计数。

use super::*;

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const MIB: u64 = 1024 * 1024;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// 方案里的压实水位公式：`max(2 * max_bytes, max_bytes + 1 MiB)`。
fn compact_watermark(max_bytes: u64) -> u64 {
    (max_bytes * 2).max(max_bytes + MIB)
}

fn now_ms() -> i64 {
    rustboard_common::util::now_ms()
}

/// 测试专用临时目录：名称含 PID + 标签 + 原子计数，Drop 时清理。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("rb-v031-{}-{}-{}", std::process::id(), tag, n));
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

fn batch_with(
    epoch: u64,
    seq: u64,
    sent_at: i64,
    sample_count: usize,
    padding: usize,
) -> SampleBatch {
    let metric_padding = "x".repeat(padding);
    SampleBatch {
        agent_id: "agent-v031".to_string(),
        epoch,
        seq,
        boot_id: "boot-v031".to_string(),
        sent_at,
        samples: (0..sample_count)
            .map(|i| {
                rustboard_common::model::Sample::new(
                    format!("v031.metric.{i}.{metric_padding}"),
                    sent_at,
                    i as f64,
                )
            })
            .collect(),
    }
}

fn small_batch(seq: u64) -> SampleBatch {
    batch_with(1, seq, now_ms(), 1, 0)
}

fn read_meta(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("无法读取 {} 的元信息: {e}", path.display()))
        .len()
}

/// 读取当前全部未确认批次（`read_next` 不推进 ACK）。
fn pending_seqs(buf: &mut DiskBuffer) -> Vec<u64> {
    buf.read_next(100_000)
        .expect("read_next 失败")
        .iter()
        .map(|b| b.seq)
        .collect()
}

/// 断言 meta 与内存偏移一致：meta == read_offset == write_offset - pending_bytes。
fn assert_meta(buf: &DiskBuffer, ctx: &str) {
    let meta = read_meta(&buf.meta_path)
        .unwrap_or_else(|| panic!("{ctx}: buffer.meta 不存在或无法解析为 u64"));
    assert_eq!(
        meta, buf.read_offset,
        "{ctx}: buffer.meta={meta} 与 read_offset={} 不一致",
        buf.read_offset
    );
    assert_eq!(
        meta,
        buf.write_offset - buf.pending_bytes(),
        "{ctx}: buffer.meta={meta} != write_offset({}) - pending_bytes({})",
        buf.write_offset,
        buf.pending_bytes()
    );
}

/// 断言写偏移与真实文件长度一致，且 pending 恰好是 [read_offset, write_offset) 区间。
fn assert_offsets_consistent(buf: &DiskBuffer, ctx: &str) {
    let len = file_len(&buf.path);
    assert_eq!(
        buf.write_offset, len,
        "{ctx}: write_offset={} 与 buffer.log 实际长度 {len} 不一致",
        buf.write_offset
    );
    assert_eq!(
        buf.read_offset + buf.pending_bytes(),
        buf.write_offset,
        "{ctx}: read_offset({}) + pending_bytes({}) != write_offset({})",
        buf.read_offset,
        buf.pending_bytes(),
        buf.write_offset
    );
}

/// 1. 物理文件硬上界：持续 push 远超 max_bytes 后，buffer.log 仍被压实水位压住。
#[test]
fn physical_file_has_hard_upper_bound() {
    let dir = TempDir::new("physical-bound");
    let max_bytes = MIB;
    let mut buf = DiskBuffer::open(dir.path(), max_bytes, 0).unwrap();

    let total = 4_000u64;
    let mut max_seen_len = 0u64;
    let mut max_seen_pending = 0usize;
    let mut max_dropped = 0u64;
    let mut total_sample_bytes = 0u64;

    for seq in 0..total {
        // 每批 2..=5 个 sample，每个 metric 约 1.4 KiB，单批约 3–7 KiB。
        let sample_count = 2 + (seq % 4) as usize;
        let padding = 1_400;
        total_sample_bytes += (sample_count * padding) as u64;
        let batch = batch_with(1, seq, now_ms(), sample_count, padding);
        buf.push(&batch)
            .unwrap_or_else(|e| panic!("push seq={seq} 失败: {e}"));

        let len = file_len(&buf.path);
        max_seen_len = max_seen_len.max(len);
        max_seen_pending = max_seen_pending.max(buf.pending_len());
        // compaction 会把 dropped 清零，必须记录过程最大值来判断“曾经发生过淘汰”。
        max_dropped = max_dropped.max(buf.dropped());
        assert!(
            buf.pending_bytes() <= max_bytes,
            "push seq={seq} 后 pending_bytes={} 超过 max_bytes={max_bytes}",
            buf.pending_bytes()
        );
    }

    // 累计样本字符串本身已明显超过 10 MiB，保证确实经历了多轮压实。
    assert!(
        total_sample_bytes > 10 * MIB,
        "累计样本字节 {total_sample_bytes} 未明显超过 10 MiB，测试强度不足"
    );

    let final_len = file_len(&buf.path);
    assert!(
        final_len <= max_bytes * 3,
        "最终 buffer.log 长度 {final_len} 超过 max_bytes*3={}",
        max_bytes * 3
    );
    assert!(
        max_seen_len <= max_bytes * 3,
        "观测到 buffer.log 最大长度 {max_seen_len} 超过 max_bytes*3={}",
        max_bytes * 3
    );
    assert!(
        buf.pending_len() <= 1_000,
        "pending_len={} 无界增长",
        buf.pending_len()
    );
    assert!(
        max_seen_pending <= 1_000,
        "观测到 pending_len 最大 {max_seen_pending}，疑似无界"
    );
    assert!(
        max_dropped > 0,
        "持续超限 push 后 dropped 始终为 0（从未发生淘汰）"
    );
    assert_offsets_consistent(&buf, "physical-bound");
    assert_meta(&buf, "physical-bound");

    eprintln!(
        "physical-bound: final_len={final_len} max_seen_len={max_seen_len} \
         pending_bytes={} pending_len={} dropped={} max_dropped={max_dropped}",
        buf.pending_bytes(),
        buf.pending_len(),
        buf.dropped()
    );
}

/// 2. meta 原子持久化 + 淘汰后重启不复活。
#[test]
fn meta_is_atomic_and_evictions_do_not_resurrect() {
    let dir = TempDir::new("meta-atomic");
    let max_bytes = 4 * 1024u64;
    let total = 30u64;

    let mut buf = DiskBuffer::open(dir.path(), max_bytes, 0).unwrap();
    for seq in 0..total {
        buf.push(&batch_with(1, seq, now_ms(), 2, 400))
            .unwrap_or_else(|e| panic!("push seq={seq} 失败: {e}"));
    }

    assert!(buf.dropped() > 0, "push 超过上限后没有发生淘汰");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );

    // 成功路径：meta 必须已经落盘，且等于当前读偏移。
    let meta =
        read_meta(&buf.meta_path).unwrap_or_else(|| panic!("淘汰后 buffer.meta 不存在或不可解析"));
    assert_eq!(
        meta, buf.read_offset,
        "buffer.meta={meta} 与 read_offset={} 不一致",
        buf.read_offset
    );
    assert_eq!(
        meta,
        buf.write_offset - buf.pending_bytes(),
        "buffer.meta={meta} != write_offset({}) - pending_bytes({})",
        buf.write_offset,
        buf.pending_bytes()
    );

    // 没有遗留的临时 meta 文件。#34 起 backup meta 是正常状态的一部分。
    let leftovers: Vec<String> = std::fs::read_dir(dir.path())
        .expect("read_dir 失败")
        .map(|entry| {
            entry
                .expect("read_dir entry 失败")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name != "buffer.log" && name != "buffer.meta" && name != "buffer.meta.bak")
        .collect();
    assert!(
        leftovers.is_empty(),
        "成功路径遗留未知/临时文件: {leftovers:?}"
    );

    let seqs_before = pending_seqs(&mut buf);
    assert!(!seqs_before.is_empty(), "淘汰后 pending 不应为空");
    let first_alive = *seqs_before.first().expect("pending 非空");
    assert!(
        first_alive > 0,
        "最早的 seq=0 已被淘汰，重启前却仍在 pending"
    );
    assert_eq!(
        seqs_before,
        (first_alive..total).collect::<Vec<_>>(),
        "pending 不是连续后缀（淘汰不是从最旧开始）"
    );

    let bytes_before = buf.pending_bytes();
    let read_offset_before = buf.read_offset;
    drop(buf);

    // 重启：已淘汰记录不得复活，pending 与 meta 保持一致。
    let mut buf = DiskBuffer::open(dir.path(), max_bytes, 0).unwrap();
    assert!(
        buf.pending_bytes() <= max_bytes,
        "重启后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    assert_eq!(
        buf.pending_bytes(),
        bytes_before,
        "重启后 pending_bytes 变化：memory/disk 分裂"
    );
    assert_eq!(
        buf.read_offset, read_offset_before,
        "重启后 read_offset 变化：meta 未持久化"
    );
    let seqs_after = pending_seqs(&mut buf);
    assert_eq!(
        seqs_after, seqs_before,
        "重启后已淘汰记录复活或未确认序列变化"
    );
    assert_meta(&buf, "meta-atomic reopen");

    // 后续 push / ack 正常。
    buf.push(&batch_with(1, total, now_ms(), 2, 400))
        .expect("重启后 push 失败");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "重启后 push 使 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    let seqs_after_push = pending_seqs(&mut buf);
    assert_eq!(
        *seqs_after_push.last().expect("push 后 pending 不应为空"),
        total,
        "重启后新 push 的 seq={total} 未出现在 pending"
    );
    assert_eq!(
        seqs_after_push,
        (total + 1 - seqs_after_push.len() as u64..=total).collect::<Vec<_>>(),
        "重启后 push 的 pending 不是连续后缀"
    );

    let head = *seqs_after_push.first().expect("pending 非空");
    buf.ack(1, head).expect("ack 失败");
    assert_eq!(
        pending_seqs(&mut buf),
        seqs_after_push[1..].to_vec(),
        "重启后 ack 边界不正确"
    );
    assert_meta(&buf, "meta-atomic after ack");
}

/// 3. meta 保存失败不推进内存偏移，恢复后可继续工作。
#[test]
fn meta_save_failure_does_not_advance_offsets() {
    let dir = TempDir::new("meta-fail");
    let max_bytes = 4 * 1024u64;

    let mut buf = DiskBuffer::open(dir.path(), max_bytes, 0).unwrap();
    for seq in 0..10u64 {
        buf.push(&batch_with(1, seq, now_ms(), 2, 400))
            .unwrap_or_else(|e| panic!("准备阶段 push seq={seq} 失败: {e}"));
    }
    assert!(buf.dropped() > 0, "准备阶段未触发淘汰");
    let read_offset_before = buf.read_offset;
    let pending_before = pending_seqs(&mut buf);
    assert!(!pending_before.is_empty(), "准备阶段 pending 不应为空");

    // 把 meta 路径换成目录：后续原子 rename 必然失败。
    let _ = std::fs::remove_file(&buf.meta_path);
    std::fs::create_dir(&buf.meta_path).expect("创建 meta 目录失败");

    let mut failure = None;
    for seq in 10..40u64 {
        match buf.push(&batch_with(1, seq, now_ms(), 2, 400)) {
            Ok(()) => {}
            Err(err) => {
                failure = Some((seq, err));
                break;
            }
        }
    }
    let (failed_seq, err) = failure.unwrap_or_else(|| {
        panic!("meta 路径被目录占用时 push 仍返回成功（应返回 Err 且不推进 read_offset）")
    });
    eprintln!("meta-fail: push seq={failed_seq} 按预期失败: {err}");

    // 关键不变式：淘汰没有执行，内存读偏移不得推进。
    assert_eq!(
        buf.read_offset, read_offset_before,
        "meta 保存失败后 read_offset 从 {read_offset_before} 推进到 {}",
        buf.read_offset
    );
    let pending_after_failure = pending_seqs(&mut buf);
    for seq in &pending_before {
        assert!(
            pending_after_failure.contains(seq),
            "meta 保存失败后旧 pending 的 seq={seq} 被弹出（淘汰不应执行）"
        );
    }
    // 允许失败批次已经 append 到 pending（实现先 append 再淘汰），但偏移必须自洽。
    assert_offsets_consistent(&buf, "meta-fail after failed push");

    // 恢复 meta 路径后重试：限额重新生效。
    std::fs::remove_dir(&buf.meta_path).expect("移除 meta 目录失败");
    buf.push(&batch_with(1, 40, now_ms(), 2, 400))
        .expect("恢复 meta 路径后 push 仍失败");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "恢复后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    assert!(
        buf.read_offset > read_offset_before,
        "恢复后淘汰未推进 read_offset（仍为 {read_offset_before}）"
    );
    assert_meta(&buf, "meta-fail recovered");
    assert_offsets_consistent(&buf, "meta-fail recovered");

    let seqs = pending_seqs(&mut buf);
    assert_eq!(
        *seqs.last().expect("恢复后 pending 不应为空"),
        40,
        "恢复后的新批次 seq=40 未进入 pending"
    );
    let head = *seqs.first().expect("pending 非空");
    buf.ack(1, head).expect("恢复后 ack 失败");
    assert_eq!(
        pending_seqs(&mut buf),
        seqs[1..].to_vec(),
        "恢复后 ack 边界不正确"
    );
}

// ---------------------------------------------------------------------------
// 崩溃注入测试：父进程启动自身测试二进制作为子进程，子进程在指定窗口 abort。
// ---------------------------------------------------------------------------

#[cfg(unix)]
const CHILD_ENV: &str = "RB_V031_CRASH_CHILD";
#[cfg(unix)]
const DIR_ENV: &str = "RB_V031_DIR";
#[cfg(unix)]
const MARKER_ENV: &str = "RB_V031_MARKER";
#[cfg(unix)]
const SIDECAR_ENV: &str = "RB_V031_SIDECAR";

#[cfg(unix)]
struct ChildOutput {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

#[cfg(unix)]
fn run_child(
    test_name: &str,
    mode: &str,
    dir: &Path,
    marker: &Path,
    sidecar: &Path,
) -> ChildOutput {
    let exe = std::env::current_exe().expect("无法获取当前测试二进制路径");
    let output = Command::new(exe)
        .arg("--exact")
        .arg(format!("buffer::v031_tests::{test_name}"))
        .arg("--nocapture")
        .env(CHILD_ENV, mode)
        .env(DIR_ENV, dir)
        .env(MARKER_ENV, marker)
        .env(SIDECAR_ENV, sidecar)
        .output()
        .expect("启动崩溃子进程失败");
    ChildOutput {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[cfg(unix)]
fn assert_aborted(output: &ChildOutput, ctx: &str) {
    use std::os::unix::process::ExitStatusExt;

    assert_eq!(
        output.status.signal(),
        Some(6),
        "{ctx}: 子进程未因 abort(SIGABRT) 退出，status={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        output.stdout,
        output.stderr
    );
    assert!(!output.status.success(), "{ctx}: 子进程状态不应为成功");
    assert!(
        !output.stderr.contains("未命中崩溃点"),
        "{ctx}: 子进程没有命中注入的崩溃窗口\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
}

#[cfg(unix)]
fn child_env_path(key: &str) -> PathBuf {
    PathBuf::from(std::env::var(key).unwrap_or_else(|_| panic!("子进程缺少环境变量 {key}")))
}

/// 4. 崩溃窗口 A：淘汰后、meta 落盘前 abort；重启后超量记录不复活。
#[test]
#[cfg(unix)]
fn crash_after_eviction_before_meta_save() {
    if std::env::var(CHILD_ENV).ok().as_deref() == Some("eviction") {
        run_eviction_crash_child();
    }

    let root = TempDir::new("crash-eviction");
    let buf_dir = root.path().join("buf");
    let marker = root.path().join("marker");
    let sidecar = root.path().join("sidecar");
    let max_bytes = 4 * 1024u64;

    let output = run_child(
        "crash_after_eviction_before_meta_save",
        "eviction",
        &buf_dir,
        &marker,
        &sidecar,
    );
    assert_aborted(&output, "eviction");

    let crashed_seq: u64 = std::fs::read_to_string(&marker)
        .expect("崩溃子进程未留下 marker 文件")
        .trim()
        .parse()
        .expect("marker 内容不是 u64");
    eprintln!("crash-eviction: 子进程在 push seq={crashed_seq} 的淘汰窗口 abort");

    let mut buf = DiskBuffer::open(&buf_dir, max_bytes, 0).expect("崩溃后重新 open 失败");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "重启后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    let seqs = pending_seqs(&mut buf);
    assert!(!seqs.is_empty(), "重启后 pending 为空，已落盘记录丢失");
    assert_eq!(
        *seqs.last().expect("pending 非空"),
        crashed_seq,
        "崩溃时已 append 的 seq={crashed_seq} 在重启后丢失"
    );
    assert!(
        *seqs.first().expect("pending 非空") > 0,
        "seq=0 已被淘汰，重启后却复活"
    );
    assert_eq!(
        seqs,
        (*seqs.first().expect("pending 非空")..=crashed_seq).collect::<Vec<_>>(),
        "重启后 pending 不是连续后缀"
    );
    assert_offsets_consistent(&buf, "crash-eviction reopen");
    assert_meta(&buf, "crash-eviction reopen");

    let log_len = file_len(&buf.path);
    let bound = max_bytes * 3 + 8192;
    assert!(
        log_len <= bound,
        "崩溃重启后 buffer.log 长度 {log_len} 超过上界 {bound}"
    );

    // 继续追加并 ack 已读批次。
    buf.push(&batch_with(1, crashed_seq + 1, now_ms(), 2, 400))
        .expect("崩溃重启后继续 push 失败");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "继续 push 后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    let seqs_after = pending_seqs(&mut buf);
    assert_eq!(
        *seqs_after.last().expect("pending 非空"),
        crashed_seq + 1,
        "继续 push 的新批次未进入 pending"
    );
    let head = *seqs_after.first().expect("pending 非空");
    buf.ack(1, head).expect("崩溃重启后 ack 失败");
    assert_eq!(
        pending_seqs(&mut buf),
        seqs_after[1..].to_vec(),
        "崩溃重启后 ack 边界不正确"
    );
    assert_meta(&buf, "crash-eviction after ack");

    eprintln!(
        "crash-eviction: reopen pending_bytes={} pending_len={} log_len={log_len}",
        buf.pending_bytes(),
        buf.pending_len()
    );
}

#[cfg(unix)]
fn run_eviction_crash_child() -> ! {
    let dir = child_env_path(DIR_ENV);
    let marker = child_env_path(MARKER_ENV);
    let max_bytes = 4 * 1024u64;

    let mut buf = DiskBuffer::open(&dir, max_bytes, 0).expect("崩溃子进程 open 失败");
    set_crash_point(Some(CrashPoint::AfterEvictionBeforeMetaSave));

    for seq in 0..50u64 {
        std::fs::write(&marker, seq.to_string()).expect("子进程写 marker 失败");
        match buf.push(&batch_with(1, seq, now_ms(), 2, 400)) {
            Ok(()) => {}
            Err(err) => {
                eprintln!("eviction child: push seq={seq} 在崩溃前意外失败: {err}");
                std::process::exit(3);
            }
        }
    }

    eprintln!("eviction child: 50 次 push 未命中淘汰崩溃点（淘汰未发生）");
    std::process::exit(4);
}

/// 5. 崩溃窗口 B：compact rename 后、meta 落盘前 abort；重启后未确认记录不丢。
#[test]
#[cfg(unix)]
fn crash_after_compaction_rename_before_meta_save() {
    if std::env::var(CHILD_ENV).ok().as_deref() == Some("compaction") {
        run_compaction_crash_child();
    }

    let root = TempDir::new("crash-compaction");
    let buf_dir = root.path().join("buf");
    let marker = root.path().join("marker");
    let sidecar = root.path().join("sidecar");
    let max_bytes = MIB;

    let output = run_child(
        "crash_after_compaction_rename_before_meta_save",
        "compaction",
        &buf_dir,
        &marker,
        &sidecar,
    );
    assert_aborted(&output, "compaction");

    let crashed_seq: u64 = std::fs::read_to_string(&marker)
        .expect("崩溃子进程未留下 marker 文件")
        .trim()
        .parse()
        .expect("marker 内容不是 u64");
    let sidecar_seqs: Vec<u64> = std::fs::read_to_string(&sidecar)
        .expect("崩溃子进程未留下 pending sidecar")
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().parse().expect("sidecar 内容不是 u64"))
        .collect();
    assert!(!sidecar_seqs.is_empty(), "崩溃前 pending 快照为空");
    eprintln!(
        "crash-compaction: 子进程在 push seq={crashed_seq} 的压实 rename 窗口 abort，\
         崩溃前 pending={sidecar_seqs:?}"
    );

    let mut buf = DiskBuffer::open(&buf_dir, max_bytes, DAY_MS).expect("崩溃后重新 open 失败");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "重启后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    let seqs = pending_seqs(&mut buf);
    assert!(
        !seqs.is_empty(),
        "压实崩溃重启后 pending 为空，未确认记录丢失"
    );

    // 崩溃时正在 push 的批次已经 append，必须保留。
    assert!(
        seqs.contains(&crashed_seq),
        "崩溃时正在 push 的 seq={crashed_seq} 在压实崩溃后丢失；pending={seqs:?}"
    );
    // 快照中最旧的一条可能在崩溃 push 的限额淘汰中被正常淘汰，其余必须保留。
    for seq in &sidecar_seqs[1..] {
        assert!(
            seqs.contains(seq),
            "未确认记录 seq={seq} 在压实崩溃后丢失；pending={seqs:?}"
        );
    }
    // 已 ack 的前缀不得复活。
    for acked in 0..=9u64 {
        assert!(
            !seqs.contains(&acked),
            "已 ack 的 seq={acked} 在压实崩溃重启后复活；pending={seqs:?}"
        );
    }

    assert_offsets_consistent(&buf, "crash-compaction reopen");
    assert_meta(&buf, "crash-compaction reopen");
    let log_len = file_len(&buf.path);
    assert!(
        log_len <= 2 * max_bytes,
        "压实崩溃重启后 buffer.log 长度 {log_len} 超过 2*max_bytes={}",
        2 * max_bytes
    );
    assert!(
        buf.read_offset <= log_len,
        "meta 修正后 read_offset={} 仍超过新文件长度 {log_len}",
        buf.read_offset
    );

    // 日志可继续追加，ACK 语义不变。
    buf.push(&batch_with(1, crashed_seq + 1, now_ms(), 1, 62_000))
        .expect("压实崩溃重启后继续 push 失败");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "继续 push 后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    let seqs_after = pending_seqs(&mut buf);
    assert_eq!(
        *seqs_after.last().expect("pending 非空"),
        crashed_seq + 1,
        "继续 push 的新批次未进入 pending"
    );
    assert_offsets_consistent(&buf, "crash-compaction after push");
    let head = *seqs_after.first().expect("pending 非空");
    buf.ack(1, head).expect("压实崩溃重启后 ack 失败");
    assert_eq!(
        pending_seqs(&mut buf),
        seqs_after[1..].to_vec(),
        "压实崩溃重启后 ack 边界不正确"
    );

    eprintln!(
        "crash-compaction: reopen pending_bytes={} pending_len={} log_len={log_len} meta={:?}",
        buf.pending_bytes(),
        buf.pending_len(),
        read_meta(&buf.meta_path)
    );
}

#[cfg(unix)]
fn run_compaction_crash_child() -> ! {
    let dir = child_env_path(DIR_ENV);
    let marker = child_env_path(MARKER_ENV);
    let sidecar = child_env_path(SIDECAR_ENV);
    let max_bytes = MIB;

    let mut buf = DiskBuffer::open(&dir, max_bytes, DAY_MS).expect("崩溃子进程 open 失败");
    // 先写 10 条并全部 ack，制造“已确认前缀”；单条约 62 KiB。
    for seq in 0..10u64 {
        buf.push(&batch_with(1, seq, now_ms(), 1, 62_000))
            .unwrap_or_else(|e| panic!("崩溃子进程预置 push seq={seq} 失败: {e}"));
    }
    buf.ack(1, 9).expect("崩溃子进程预置 ack 失败");

    // 从这里开始启用压实崩溃注入。
    set_crash_point(Some(CrashPoint::AfterCompactionRenameBeforeMetaSave));

    for seq in 10..200u64 {
        std::fs::write(&marker, seq.to_string()).expect("子进程写 marker 失败");
        match buf.push(&batch_with(1, seq, now_ms(), 1, 62_000)) {
            Ok(()) => {
                // push 成功后记录当前 pending 快照；下一次 push 崩溃时父进程以此为准。
                let snapshot: Vec<String> = pending_seqs(&mut buf)
                    .iter()
                    .map(|s| s.to_string())
                    .collect();
                std::fs::write(&sidecar, snapshot.join(",")).expect("子进程写 sidecar 失败");
            }
            Err(err) => {
                eprintln!("compaction child: push seq={seq} 在崩溃前意外失败: {err}");
                std::process::exit(3);
            }
        }
    }

    eprintln!("compaction child: 200 次 push 未命中压实崩溃点（未触发压实）");
    std::process::exit(4);
}

/// 6. max_age 语义：0 不按时间淘汰；重启时按新配置淘汰超龄记录。
#[test]
fn max_age_zero_disables_age_eviction_and_reopen_enforces_it() {
    let dir = TempDir::new("max-age");

    let old_sent_at = now_ms() - 120_000;
    {
        let mut buf = DiskBuffer::open(dir.path(), MIB, 0).expect("open 失败");
        buf.push(&batch_with(1, 0, old_sent_at, 1, 0))
            .expect("push 超龄批次 seq=0 失败");
        buf.push(&batch_with(1, 1, old_sent_at, 1, 0))
            .expect("push 超龄批次 seq=1 失败");
        buf.push(&batch_with(1, 2, now_ms(), 1, 0))
            .expect("push 新鲜批次 seq=2 失败");
        assert_eq!(
            buf.pending_len(),
            3,
            "max_age_ms=0 时不应按时间淘汰，pending_len={}",
            buf.pending_len()
        );
        assert_eq!(buf.dropped(), 0, "max_age_ms=0 时不应计入 dropped");
        assert_eq!(pending_seqs(&mut buf), vec![0, 1, 2]);
    }

    // 重开时启用 60s 时限：两条 120s 前的记录必须在 recover 阶段淘汰，
    // 但新鲜记录必须保留，且 read_offset 要前进到新鲜记录起点并落盘。
    let mut buf = DiskBuffer::open(dir.path(), MIB, 60_000).expect("重启 open 失败");
    assert_eq!(
        buf.pending_len(),
        1,
        "重启后 pending_len={}，超龄记录未被淘汰或新鲜记录被误删",
        buf.pending_len()
    );
    assert_eq!(
        pending_seqs(&mut buf),
        vec![2],
        "重启后超龄记录复活或新鲜记录丢失"
    );
    assert!(
        buf.pending_bytes() > 0,
        "重启后新鲜记录 seq=2 的 pending_bytes 为 0"
    );
    assert!(
        buf.read_offset > 0,
        "重启后 read_offset 未推进，已淘汰的超龄记录前缀可能复活"
    );
    assert!(
        buf.read_offset < buf.write_offset,
        "重启后 read_offset={} 未停留在新鲜记录起点（write_offset={}）",
        buf.read_offset,
        buf.write_offset
    );
    eprintln!(
        "max-age: reopen read_offset={} write_offset={} meta={:?} log_len={}",
        buf.read_offset,
        buf.write_offset,
        read_meta(&buf.meta_path),
        file_len(&buf.path)
    );
    assert_meta(&buf, "max-age reopen");
    assert_offsets_consistent(&buf, "max-age reopen");

    let log_len = file_len(&buf.path);
    assert!(
        log_len <= compact_watermark(MIB) + 8192,
        "重启后 buffer.log 长度 {log_len} 超过水位上界"
    );

    // 新批次（新鲜 sent_at）应正常保留，ACK 边界正确。
    buf.push(&small_batch(3)).expect("重启后 push 失败");
    assert_eq!(
        pending_seqs(&mut buf),
        vec![2, 3],
        "重启后新批次 seq=3 未正常进入 pending"
    );
    buf.ack(1, 2).expect("重启后 ack seq=2 失败");
    assert_eq!(pending_seqs(&mut buf), vec![3], "重启后 ack 边界不正确");
    buf.ack(1, 3).expect("重启后 ack seq=3 失败");
    assert_eq!(buf.pending_len(), 0, "ack 后 pending 未清空");
}

/// 7. 单条超大记录：保留该条、后续 push 被丢弃、文件不无界增长、ack 后恢复。
#[test]
fn single_oversized_record_is_kept_without_unbounded_growth() {
    let dir = TempDir::new("oversized");
    let max_bytes = 4 * 1024u64;
    let mut buf = DiskBuffer::open(dir.path(), max_bytes, 0).expect("open 失败");

    buf.push(&batch_with(1, 0, now_ms(), 1, 8_000))
        .expect("push 超大记录失败");
    assert_eq!(
        buf.pending_len(),
        1,
        "单条超大记录应被保留，实际 pending_len={}",
        buf.pending_len()
    );
    let oversized_bytes = buf.pending_bytes();
    assert!(
        oversized_bytes > max_bytes,
        "超大记录 pending_bytes={oversized_bytes} 未超过 max_bytes={max_bytes}"
    );
    assert_eq!(buf.dropped(), 0, "保留超大记录不应计入 dropped");
    let len_after_first = file_len(&buf.path);
    assert!(
        len_after_first >= 8_000,
        "超大记录 push 后 buffer.log 长度 {len_after_first} 异常偏小"
    );

    for seq in 1..=300u64 {
        buf.push(&small_batch(seq))
            .unwrap_or_else(|e| panic!("超大记录后 push seq={seq} 失败: {e}"));
    }
    assert_eq!(
        buf.pending_len(),
        1,
        "超大记录后新 push 未按策略被淘汰，pending_len={}",
        buf.pending_len()
    );
    assert_eq!(
        buf.pending_bytes(),
        oversized_bytes,
        "超大记录后 pending_bytes 从 {oversized_bytes} 变为 {}",
        buf.pending_bytes()
    );
    assert_eq!(
        buf.dropped(),
        300,
        "超大记录后的 300 次 push 应全部计入 dropped，实际 {}",
        buf.dropped()
    );
    assert_eq!(
        pending_seqs(&mut buf),
        vec![0],
        "pending 中保留的应是超大记录 seq=0"
    );

    let log_len = file_len(&buf.path);
    let bound = compact_watermark(max_bytes) + 8192;
    assert!(
        log_len <= bound,
        "300 次被丢弃的 push 后 buffer.log 长度 {log_len} 超过水位上界 {bound}"
    );

    // ack 掉超大记录后 pending 清空，并可继续正常 push。
    buf.ack(1, 0).expect("ack 超大记录失败");
    assert_eq!(buf.pending_len(), 0, "ack 超大记录后 pending 未清空");
    assert_eq!(buf.pending_bytes(), 0, "ack 超大记录后 pending_bytes 非零");

    buf.push(&small_batch(301)).expect("ack 后 push 失败");
    assert_eq!(
        pending_seqs(&mut buf),
        vec![301],
        "ack 后新批次 seq=301 未正常进入 pending"
    );
    assert!(
        buf.pending_bytes() <= max_bytes,
        "ack 后新批次 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
}

fn vm_rss_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
    })
}

/// 8. 内存上界：8 KiB 上限下连续 100_000 次 push，pending 不随总数增长。
#[test]
fn pending_and_memory_stay_bounded_under_100k_pushes() {
    let dir = TempDir::new("memory-bound");
    let max_bytes = 8 * 1024u64;
    let mut buf = DiskBuffer::open(dir.path(), max_bytes, 0).expect("open 失败");

    let rss_before = vm_rss_kb();
    let total = 100_000u64;
    let mut max_pending_len = 0usize;
    let mut max_pending_bytes = 0u64;
    let mut max_dropped = 0u64;

    for seq in 0..total {
        buf.push(&small_batch(seq))
            .unwrap_or_else(|e| panic!("第 {seq} 次 push 失败: {e}"));
        // compaction 会清零 dropped；逐次记录过程最大值，避免最后一次 push 恰好压实导致误判。
        max_dropped = max_dropped.max(buf.dropped());
        if seq % 1_000 == 0 {
            max_pending_len = max_pending_len.max(buf.pending_len());
            max_pending_bytes = max_pending_bytes.max(buf.pending_bytes());
            assert!(
                buf.pending_bytes() <= max_bytes,
                "push {seq} 后 pending_bytes={} 超过 max_bytes={max_bytes}",
                buf.pending_bytes()
            );
        }
    }
    let rss_after = vm_rss_kb();

    max_pending_len = max_pending_len.max(buf.pending_len());
    max_pending_bytes = max_pending_bytes.max(buf.pending_bytes());
    assert!(
        buf.pending_bytes() <= max_bytes,
        "10 万次 push 后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    assert!(
        max_pending_bytes <= max_bytes,
        "观测到 pending_bytes 最大 {max_pending_bytes} 超过 max_bytes={max_bytes}"
    );
    assert!(
        buf.pending_len() <= 500,
        "10 万次 push 后 pending_len={} 无界增长",
        buf.pending_len()
    );
    assert!(
        max_pending_len <= 500,
        "观测到 pending_len 最大 {max_pending_len} 无界增长"
    );
    // 注意：压实会把 dropped 计数清零（实现行为），因此用过程最大值验证淘汰确实
    // 发生过，不用 dropped 与总 push 数做等式约束。
    assert!(
        max_dropped > 0,
        "10 万次 push 过程中 dropped 始终为 0，淘汰疑似未执行"
    );
    assert!(
        max_dropped <= total,
        "观测到 dropped 最大 {max_dropped} 超过总 push 数 {total}"
    );
    assert!(buf.read_offset > 0, "淘汰持续发生后 read_offset 仍为 0");
    assert_offsets_consistent(&buf, "100k pushes");
    assert_meta(&buf, "100k pushes");

    let log_len = file_len(&buf.path);
    let bound = compact_watermark(max_bytes) + 8192;
    assert!(
        log_len <= bound,
        "10 万次 push 后 buffer.log 长度 {log_len} 超过水位上界 {bound}"
    );

    match (rss_before, rss_after) {
        (Some(before), Some(after)) => eprintln!(
            "memory-bound: pending_len={} pending_bytes={} dropped={} max_dropped={max_dropped} \
             log_len={log_len} VmRSS: {before} KiB -> {} KiB (diff {} KiB，仅参考，非硬断言)",
            buf.pending_len(),
            buf.pending_bytes(),
            buf.dropped(),
            after,
            after as i64 - before as i64
        ),
        _ => eprintln!(
            "memory-bound: pending_len={} pending_bytes={} dropped={} max_dropped={max_dropped} \
             log_len={log_len} VmRSS 不可用（非 Linux）",
            buf.pending_len(),
            buf.pending_bytes(),
            buf.dropped()
        ),
    }
}

/// 9. 压实后偏移/读取/ACK 一致性，重启后序列不变。
#[test]
fn compaction_keeps_offsets_and_read_order_consistent() {
    let dir = TempDir::new("compaction-consistency");
    let max_bytes = MIB;
    let total = 40u64;
    // 每条约 62 KiB：17 条即超过 1 MiB，35 条左右超过 2 MiB 压实水位。
    let padding = 62_000usize;

    let mut buf = DiskBuffer::open(dir.path(), max_bytes, DAY_MS).expect("open 失败");
    let mut previous_len = 0u64;
    let mut compaction_observed = false;

    for seq in 0..total {
        buf.push(&batch_with(1, seq, now_ms(), 1, padding))
            .unwrap_or_else(|e| panic!("push seq={seq} 失败: {e}"));
        let len = file_len(&buf.path);
        if len < previous_len && !compaction_observed {
            // 文件长度回退说明本 push 触发了压实：此时应已 reset 偏移并落盘 meta=0。
            compaction_observed = true;
            let meta = read_meta(&buf.meta_path)
                .unwrap_or_else(|| panic!("压实后 buffer.meta 不存在或不可解析"));
            assert_eq!(meta, 0, "压实后 meta 应重置为 0，实际 {meta}（seq={seq}）");
            assert_eq!(
                buf.read_offset, 0,
                "压实后 read_offset 应重置为 0，实际 {}",
                buf.read_offset
            );
            assert_eq!(
                len,
                buf.pending_bytes(),
                "压实后 buffer.log 长度 {len} 应等于 pending_bytes={}",
                buf.pending_bytes()
            );
            assert_eq!(
                buf.write_offset, len,
                "压实后 write_offset={} 应等于文件长度 {len}",
                buf.write_offset
            );
            eprintln!(
                "compaction-consistency: seq={seq} 触发压实，len={len} pending_bytes={}",
                buf.pending_bytes()
            );
        }
        previous_len = len;
    }

    assert!(
        compaction_observed,
        "push {total} 条 ~62 KiB 记录后未观测到压实（文件长度未回退）"
    );
    assert!(
        buf.pending_bytes() <= max_bytes,
        "压实场景中 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    assert_offsets_consistent(&buf, "compaction-consistency");
    assert_meta(&buf, "compaction-consistency");

    let seqs = pending_seqs(&mut buf);
    assert!(!seqs.is_empty(), "压实场景中 pending 为空");
    let expected_start = total - seqs.len() as u64;
    assert_eq!(
        seqs,
        (expected_start..total).collect::<Vec<_>>(),
        "压实后 read_next 序列不是连续后缀"
    );
    assert!(!seqs.contains(&0), "已淘汰的 seq=0 在压实后仍可读到");

    // ack 边界：确认队首后只能前进一条。
    let head = seqs[0];
    buf.ack(1, head).expect("压实后 ack 失败");
    let seqs_after_ack = pending_seqs(&mut buf);
    assert_eq!(seqs_after_ack, seqs[1..].to_vec(), "压实后 ack 边界不正确");

    // 重启后序列一致。
    let bytes_after_ack = buf.pending_bytes();
    drop(buf);
    let mut buf = DiskBuffer::open(dir.path(), max_bytes, DAY_MS).expect("重启 open 失败");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "重启后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    assert_eq!(
        buf.pending_bytes(),
        bytes_after_ack,
        "重启后 pending_bytes 与压实+ack 后不一致"
    );
    assert_eq!(
        pending_seqs(&mut buf),
        seqs_after_ack,
        "重启后 read_next 序列与压实+ack 后不一致"
    );
    assert_offsets_consistent(&buf, "compaction-consistency reopen");
    assert_meta(&buf, "compaction-consistency reopen");

    // 继续追加，仍保持连续、无复活。
    buf.push(&batch_with(1, total, now_ms(), 1, padding))
        .expect("压实重启后继续 push 失败");
    assert!(
        buf.pending_bytes() <= max_bytes,
        "继续 push 后 pending_bytes={} 超过 max_bytes={max_bytes}",
        buf.pending_bytes()
    );
    let seqs_final = pending_seqs(&mut buf);
    assert_eq!(
        *seqs_final.last().expect("pending 非空"),
        total,
        "压实重启后新批次 seq={total} 未进入 pending"
    );
    assert!(!seqs_final.contains(&head), "已 ack 的 seq={head} 复活");
    let final_start = total + 1 - seqs_final.len() as u64;
    assert_eq!(
        seqs_final,
        (final_start..=total).collect::<Vec<_>>(),
        "压实重启后继续 push 的序列不连续"
    );
    assert_meta(&buf, "compaction-consistency final");
}
