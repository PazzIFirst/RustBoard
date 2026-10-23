//! 本地磁盘缓冲。
//!
//! hub 断连时采样点不能丢，所以写入一个只追加的分段日志；
//! 收到 Ack、超过时效或超过字节上限时推进读指针，物理文件超过水位时做一次
//! 压实（重写文件，只保留未确认记录）。
//!
//! 记录格式：`[len: u32 LE][msgpack payload]`，没有 CRC——尾部截断或
//! 解码失败时直接丢弃损坏的尾部记录，前面的数据仍然可用。
//!
//! # 持久化与崩溃安全
//!
//! - `buffer.meta` 只存一个十进制 `read_offset`，通过
//!   `rustboard_common::fsutil::atomic_write` 原子替换。任何推进读指针的操作
//!   都必须先把目标偏移成功落盘，再修改内存中的 `pending` / `read_offset`；
//!   落盘失败时保持旧状态并返回错误，避免“内存已淘汰、磁盘偏移未变”的分裂。
//! - 压实先写同目录临时文件、`sync_all`、`rename`，最后写 `buffer.meta = 0`。
//!   只有 `read_offset > write_offset - read_offset`（已确认前缀严格大于剩余
//!   未确认字节）时才允许压实。这样如果在 rename 之后、meta 落盘之前崩溃，
//!   旧 meta 的 start 一定大于新文件长度，`recover()` 的 `start > len -> 0`
//!   兜底分支会从新文件开头恢复，不会把未确认记录当成已确认前缀跳过。

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rustboard_common::model::SampleBatch;

/// `buffer.meta` 的权限：只允许 agent 自己读写。
const META_MODE: u32 = 0o600;

/// 压实水位至少比 `max_bytes` 高 1 MiB，避免小上限时过于频繁地重写文件。
const COMPACT_SLACK_BYTES: u64 = 1024 * 1024;

struct Pending {
    epoch: u64,
    /// 批次产生时间（agent 墙钟），用于按时间淘汰。
    ts: i64,
    seq: u64,
    offset: u64,
    len: u64,
}

pub struct DiskBuffer {
    path: PathBuf,
    /// 记录已确认前缀的字节偏移，重启后据此跳过已上传部分。
    meta_path: PathBuf,
    file: File,
    /// 第一条未确认记录的起始偏移。
    read_offset: u64,
    /// 文件末尾偏移。
    write_offset: u64,
    pending: VecDeque<Pending>,
    max_bytes: u64,
    /// 最长保留时间，超时记录在 push 时丢弃（与 max_bytes 取先到者）。
    max_age_ms: u64,
    dropped: u64,
    /// 压实已经 `rename`、但 `save_meta(0)` 失败时为 true。
    ///
    /// 此时磁盘上的旧 meta 仍指向“旧文件里的读偏移”，它严格大于新文件长度；
    /// 一旦继续追加，旧偏移可能落进新文件范围。后续写操作必须先补写 meta。
    meta_dirty: bool,
    /// 缓冲文件已不可信（写失败后截断回滚也失败，或文件长度与写偏移不一致）。
    ///
    /// 一旦置位，所有追加与压实都直接返回错误，避免在撕裂记录之后继续写、
    /// 把损坏范围扩大。只能通过重新 `open()`（recover 自愈）恢复。
    broken: bool,
}

impl DiskBuffer {
    pub fn open(dir: impl AsRef<Path>, max_bytes: u64, max_age_ms: u64) -> std::io::Result<Self> {
        // KI-21：缓冲目录归 agent 独占，旧版本留下的 0755 也要在启动时收紧到 0700。
        rustboard_common::fsutil::ensure_private_dir(dir.as_ref(), 0o700)?;
        let path = dir.as_ref().join("buffer.log");
        let meta_path = dir.as_ref().join("buffer.meta");
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;

        let mut buf = Self {
            path,
            meta_path,
            file,
            read_offset: 0,
            write_offset: 0,
            pending: VecDeque::new(),
            max_bytes,
            max_age_ms,
            dropped: 0,
            meta_dirty: false,
            broken: false,
        };
        let start = buf.load_meta();
        buf.recover(start)?;
        // 重启后重新执行一次统一限额：旧版本可能没持久化淘汰偏移，离线期间
        // 也可能积累超龄/超量记录；单条超大记录由 enforce_limit 保留。
        buf.enforce_limit(rustboard_common::util::now_ms())?;
        Ok(buf)
    }

    fn load_meta(&self) -> u64 {
        std::fs::read_to_string(&self.meta_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// 把目标读偏移原子写入 `buffer.meta`。
    ///
    /// 先落盘成功、再允许调用方修改内存：失败时保持旧状态并返回错误，
    /// 不会出现“内存已淘汰、磁盘偏移未变”的分裂。
    fn persist_offset(&mut self, offset: u64) -> std::io::Result<()> {
        let bytes = offset.to_string();
        rustboard_common::fsutil::atomic_write(&self.meta_path, bytes.as_bytes(), META_MODE)?;
        self.meta_dirty = false;
        Ok(())
    }

    fn save_meta(&mut self) -> std::io::Result<()> {
        self.persist_offset(self.read_offset)
    }

    /// 追加/压实前的物理文件完整性检查。
    ///
    /// `write_offset` 是内存认为的文件长度。若文件实际长度与之不一致（外部
    /// 截断/追加，或上次写失败且回滚也失败），继续 append 会写进撕裂记录
    /// 之后；此时标记 `broken` 并拒绝写入/压实，交给重新 `open()` 的 recover 自愈。
    fn ensure_intact(&mut self) -> std::io::Result<()> {
        if self.broken {
            return Err(std::io::Error::other("缓冲已标记为 broken，拒绝写入/压实"));
        }
        let len = self.file.metadata()?.len();
        if len != self.write_offset {
            self.broken = true;
            tracing::error!(
                file_len = len,
                write_offset = self.write_offset,
                "缓冲文件长度与写偏移不一致，标记为 broken"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "缓冲文件长度 {len} 与写偏移 {} 不一致，拒绝继续写入",
                    self.write_offset
                ),
            ));
        }
        Ok(())
    }

    /// 从 `start` 开始扫描已有日志，重建待发送队列；损坏的尾部会被截断。
    fn recover(&mut self, start: u64) -> std::io::Result<()> {
        let len = self.file.metadata()?.len();
        // meta 越界（典型：压实 rename 后 meta 未落盘就崩溃）时从 0 重扫：
        // 新文件长度小于旧 read_offset，说明已确认前缀已经不在文件里了。
        let start_out_of_bounds = start > len;
        let mut offset = if start_out_of_bounds { 0 } else { start };
        self.read_offset = offset;
        let mut good_end = offset;

        while offset + 4 <= len {
            self.file.seek(SeekFrom::Start(offset))?;
            let mut len_buf = [0u8; 4];
            if self.file.read_exact(&mut len_buf).is_err() {
                break;
            }
            let payload_len = u32::from_le_bytes(len_buf) as u64;
            if payload_len == 0 || offset + 4 + payload_len > len {
                break;
            }

            let mut payload = vec![0u8; payload_len as usize];
            if self.file.read_exact(&mut payload).is_err() {
                break;
            }
            match BatchCodec::decode(&payload) {
                Some(batch) => {
                    self.pending.push_back(Pending {
                        epoch: batch.epoch,
                        seq: batch.seq,
                        ts: batch.sent_at,
                        offset,
                        len: 4 + payload_len,
                    });
                    offset += 4 + payload_len;
                    good_end = offset;
                }
                None => break,
            }
        }

        if good_end < len {
            tracing::warn!(dropped_bytes = len - good_end, "缓冲尾部损坏，已截断");
            self.file.set_len(good_end)?;
        }
        self.write_offset = good_end;
        if start_out_of_bounds {
            // 修正后的偏移必须落盘，否则下次启动仍会读到越界旧值。
            self.save_meta()?;
        }
        Ok(())
    }

    /// 追加一条记录；测试构建可注入“只写前 N 字节后返回错误”。
    #[cfg(test)]
    fn write_record(&mut self, record: &[u8]) -> std::io::Result<()> {
        if let Some(limit) = partial_write_limit() {
            let n = limit.min(record.len());
            // 模拟真实的 ENOSPC/EFBIG 部分写：先写进一部分，再返回错误。
            let written = self.file.write(&record[..n]);
            tracing::debug!(?written, "测试注入：记录只写入一部分后失败");
            return Err(std::io::Error::other("测试注入的部分写失败"));
        }
        self.file.write_all(record)
    }

    #[cfg(not(test))]
    fn write_record(&mut self, record: &[u8]) -> std::io::Result<()> {
        self.file.write_all(record)
    }

    /// 写入失败后把文件截回旧 EOF。
    ///
    /// `write_all` 在 ENOSPC/EFBIG 等错误下可能已经写入部分字节，而错误本身
    /// 不告诉调用方实际写入多少；因此必须显式 `set_len(offset)` 回滚到写前
    /// 长度。截断也失败说明文件状态不可信，标记 `broken`，禁止后续追加。
    fn rollback_write(&mut self, offset: u64, write_err: std::io::Error) -> std::io::Result<()> {
        match self.file.set_len(offset) {
            Ok(()) => {
                tracing::warn!(
                    error = %write_err,
                    offset,
                    "缓冲写入失败，已截断回滚到旧 EOF"
                );
                Err(write_err)
            }
            Err(rollback_err) => {
                self.broken = true;
                tracing::error!(
                    write_error = %write_err,
                    rollback_error = %rollback_err,
                    offset,
                    "缓冲写入失败且回滚失败，标记为 broken 并拒绝后续写入"
                );
                Err(std::io::Error::new(
                    write_err.kind(),
                    format!(
                        "缓冲写入失败且回滚失败：写入错误 {write_err}；截断错误 {rollback_err}"
                    ),
                ))
            }
        }
    }

    pub fn push(&mut self, batch: &SampleBatch) -> std::io::Result<()> {
        let now = rustboard_common::util::now_ms();

        // 文件长度必须与内存写偏移一致，否则后续 append 会写进撕裂记录之后。
        self.ensure_intact()?;

        // 上次压实换了新文件但 meta 没写成功：先补写，避免旧偏移落进新文件范围。
        if self.meta_dirty {
            self.save_meta()?;
        }

        // 上次淘汰在 save_meta 失败后可能留下超限状态；写新记录前先重试一次，
        // 成功后会回到“最多只保留一条超大记录”的正常状态。
        if self.pending_bytes() > self.max_bytes {
            self.enforce_limit(now)?;
        }
        // 单条超大记录本身超过 max_bytes 时，再写新记录只会让文件无界增长：
        // 丢弃新批次（保留超大记录等待 ack），计入 dropped 并告警，不 panic。
        if self.pending_bytes() > self.max_bytes {
            self.dropped += 1;
            tracing::warn!(
                pending_bytes = self.pending_bytes(),
                max_bytes = self.max_bytes,
                "缓冲中保留了单条超大记录，丢弃新批次"
            );
            return Ok(());
        }

        let payload = rmp_serde::to_vec(batch).map_err(std::io::Error::other)?;
        let mut record = Vec::with_capacity(4 + payload.len());
        record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        record.extend_from_slice(&payload);

        let offset = self.write_offset;
        // write_all 失败时可能已写入部分字节；必须先截断回滚，再返回错误，
        // 不能在这条撕裂记录之后继续追加。
        if let Err(err) = self.write_record(&record) {
            return self.rollback_write(offset, err);
        }
        self.write_offset += record.len() as u64;
        self.pending.push_back(Pending {
            epoch: batch.epoch,
            seq: batch.seq,
            ts: batch.sent_at,
            offset,
            len: record.len() as u64,
        });

        self.enforce_limit(now)?;
        Ok(())
    }

    /// 统一限额：先按 `max_age_ms` 淘汰队首超时记录，再按 `max_bytes` 淘汰最旧记录。
    ///
    /// 两个阶段都先算出目标偏移、原子落盘成功后才弹出 `pending`；落盘失败时
    /// 直接返回错误，内存状态保持不变。
    fn enforce_limit(&mut self, now: i64) -> std::io::Result<()> {
        self.evict_aged(now)?;
        self.evict_oldest()?;
        self.maybe_compact()?;
        Ok(())
    }

    /// 丢弃超过 `max_age_ms` 的旧记录（agent 长时间离线且缓冲未涨满时，
    /// 过旧的数据对 hub 已无意义，也避免判重窗口被撑爆）。
    ///
    /// `max_age_ms == 0` 表示不按时间淘汰。先扫描算出目标偏移并落盘，
    /// 成功后才真正弹出记录。
    fn evict_aged(&mut self, now: i64) -> std::io::Result<()> {
        if self.max_age_ms == 0 || self.pending.is_empty() {
            return Ok(());
        }
        let cutoff = now.saturating_sub(self.max_age_ms.min(i64::MAX as u64) as i64);
        let mut target = self.read_offset;
        let mut evict_count = 0usize;
        for front in &self.pending {
            if front.ts >= cutoff {
                break;
            }
            target = front.offset + front.len;
            evict_count += 1;
        }
        if evict_count == 0 {
            return Ok(());
        }
        self.persist_offset(target)?;
        for _ in 0..evict_count {
            self.pending.pop_front();
        }
        self.read_offset = target;
        self.dropped += evict_count as u64;
        Ok(())
    }

    /// 超过 `max_bytes` 时丢弃最旧的记录（宁可丢历史也不能撑爆磁盘）。
    ///
    /// 循环条件保留最后一条记录：单条记录本身大于 `max_bytes` 时不能为了
    /// 满足上限把它也弹掉，否则会丢失唯一未确认数据；该记录保留到 ack。
    fn evict_oldest(&mut self) -> std::io::Result<()> {
        let mut target = self.read_offset;
        let mut evict_count = 0usize;
        while self.pending.len() > evict_count + 1
            && self.write_offset.saturating_sub(target) > self.max_bytes
        {
            let front = &self.pending[evict_count];
            target = front.offset + front.len;
            evict_count += 1;
        }
        if evict_count == 0 {
            return Ok(());
        }
        #[cfg(test)]
        crash_if(CrashPoint::AfterEvictionBeforeMetaSave);
        self.persist_offset(target)?;
        for _ in 0..evict_count {
            self.pending.pop_front();
        }
        self.read_offset = target;
        self.dropped += evict_count as u64;
        Ok(())
    }

    /// 按物理文件长度触发压实。
    ///
    /// 水位为 `max(2 * max_bytes, max_bytes + 1 MiB)`：即使 pending 非空，
    /// 文件超过水位也要压实，否则持续写入会让 `buffer.log` 无界增长。
    /// pending 清空但仍残留已确认前缀时也压实，让文件尽快归零。
    fn maybe_compact(&mut self) -> std::io::Result<()> {
        let len = match self.file.metadata() {
            Ok(meta) => meta.len(),
            Err(err) => {
                tracing::warn!(error = %err, "读取缓冲文件大小失败，改用写偏移判断压实");
                self.write_offset
            }
        };
        let threshold = self
            .max_bytes
            .saturating_mul(2)
            .max(self.max_bytes.saturating_add(COMPACT_SLACK_BYTES));
        if len > threshold || (self.pending.is_empty() && self.read_offset > 0) {
            self.compact()?;
        }
        Ok(())
    }

    /// 读出最多 `max` 批尚未确认的数据。
    pub fn read_next(&mut self, max: usize) -> std::io::Result<Vec<SampleBatch>> {
        let mut out = Vec::new();
        for p in self.pending.iter().take(max) {
            self.file.seek(SeekFrom::Start(p.offset + 4))?;
            let mut payload = vec![0u8; (p.len - 4) as usize];
            self.file.read_exact(&mut payload)?;
            if let Some(batch) = BatchCodec::decode(&payload) {
                out.push(batch);
            }
        }
        Ok(out)
    }

    /// 确认 `epoch` 下 `seq`（含）之前的批次，可安全丢弃。
    ///
    /// 只推进队首同 epoch 的连续前缀；遇到第一个 epoch 不同的记录立即停止，
    /// 避免旧 epoch 的高 seq ACK 误删新 epoch 的低 seq 未确认批次。
    ///
    /// 先只计算可确认前缀的结束偏移，`save_meta` 成功后才弹出 `pending`；
    /// 落盘失败时内存状态保持不变，返回错误交给调用方重试/断开。
    pub fn ack(&mut self, epoch: u64, seq: u64) -> std::io::Result<()> {
        let mut advance = self.read_offset;
        let mut count = 0usize;
        for front in &self.pending {
            if front.epoch != epoch || front.seq > seq {
                break;
            }
            advance = front.offset + front.len;
            count += 1;
        }
        if count > 0 {
            self.persist_offset(advance)?;
            for _ in 0..count {
                self.pending.pop_front();
            }
            self.read_offset = advance;
        }
        // pending 清空或物理文件超过水位时压实（compact 内部有崩溃安全判断）。
        self.maybe_compact()?;
        Ok(())
    }

    /// 把未确认部分搬到新文件，丢弃已确认前缀。
    ///
    /// 顺序：同目录临时文件 → 写入 → `sync_all` → 先打开新句柄 → `rename` →
    /// 修正 pending 偏移与读写偏移 → 原子写 `buffer.meta = 0`。
    fn compact(&mut self) -> std::io::Result<()> {
        // 压实前同样确认文件长度与内存写偏移一致，避免基于撕裂文件重写。
        self.ensure_intact()?;
        if self.read_offset == 0 {
            // 上次压实 rename 后 meta 写失败：这里补写一次，避免旧 meta 长期悬空。
            if self.meta_dirty {
                self.save_meta()?;
            }
            return Ok(());
        }
        let remaining = self.write_offset.saturating_sub(self.read_offset);

        // 崩溃安全不变式（必须严格遵守）：
        // 只有 read_offset > remaining 时才压实。若在 rename 之后、meta 落盘
        // 之前崩溃，旧 meta 里的 start 仍严格大于新文件长度 remaining，
        // recover() 会命中 `start > len -> 0` 分支，从新文件开头扫描，
        // 不会把尚未确认的记录当成已确认前缀跳过。
        // 单条超大记录通常使 remaining >= read_offset，此时宁可跳过本次压实。
        if self.read_offset <= remaining {
            tracing::debug!(
                read_offset = self.read_offset,
                remaining,
                "不满足压实崩溃安全不变式，跳过压实"
            );
            return Ok(());
        }

        let mut buf = vec![0u8; remaining as usize];
        self.file.seek(SeekFrom::Start(self.read_offset))?;
        self.file.read_exact(&mut buf)?;

        let tmp = self.path.with_extension("log.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        // 先打开新文件句柄、再 rename：rename 成功后 self.file 已指向新 inode，
        // 不会出现“rename 成功但重新 open 失败”时继续写已 unlink 旧文件的窗口。
        // 若这里 open 失败，rename 尚未发生，旧文件/旧句柄/meta 全部保持不变，
        // 直接返回 Err 即可安全重试。
        let new_file = OpenOptions::new().read(true).append(true).open(&tmp)?;
        std::fs::rename(&tmp, &self.path)?;
        // rename 后句柄仍指向同一 inode，直接接管，无需再次 open(path)。
        self.file = new_file;

        let shift = self.read_offset;
        for p in self.pending.iter_mut() {
            p.offset -= shift;
        }
        self.write_offset = remaining;
        self.read_offset = 0;
        self.dropped = 0;

        #[cfg(test)]
        crash_if(CrashPoint::AfterCompactionRenameBeforeMetaSave);

        if let Err(err) = self.save_meta() {
            // rename 已经成功，新文件里只剩未确认记录，但磁盘旧 meta 现在
            // 指向新文件尾部之后。标记待补写，后续写操作会先重试，
            // 防止旧偏移落进追加后的文件范围而跳过未确认记录。
            self.meta_dirty = true;
            return Err(err);
        }
        Ok(())
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn pending_bytes(&self) -> u64 {
        self.write_offset.saturating_sub(self.read_offset)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// 测试子 Agent 用来制造确定性崩溃窗口的注入点；生产构建完全不存在。
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CrashPoint {
    /// 按字节淘汰已算出目标偏移、即将写 `buffer.meta`。
    AfterEvictionBeforeMetaSave,
    /// 压实已 rename 并重新打开/修正偏移、即将写 `buffer.meta = 0`。
    AfterCompactionRenameBeforeMetaSave,
}

#[cfg(test)]
static CRASH_POINT: std::sync::Mutex<Option<CrashPoint>> = std::sync::Mutex::new(None);

/// 设置崩溃注入点；`None` 表示关闭。
#[cfg(test)]
#[allow(dead_code)] // 独立测试模块按需使用；未引用时不报 dead_code。
pub(crate) fn set_crash_point(point: Option<CrashPoint>) {
    let mut guard = match CRASH_POINT.lock() {
        Ok(guard) => guard,
        // 只读测试钩子：锁中毒时仍按最后一次设置的值继续。
        Err(poisoned) => poisoned.into_inner(),
    };
    *guard = point;
}

/// 命中当前注入点时直接终止进程，模拟 `kill -9` 的崩溃窗口。
#[cfg(test)]
fn crash_if(point: CrashPoint) {
    let hit = match CRASH_POINT.lock() {
        Ok(guard) => *guard == Some(point),
        Err(poisoned) => *poisoned.into_inner() == Some(point),
    };
    if hit {
        std::process::abort();
    }
}

// 测试注入：当前线程下一次记录写入只写前 N 字节后返回错误。
// 用线程局部而不是进程级静态：`cargo test` 默认并行跑测试，进程级钩子会
// 误伤其它测试线程；线程局部保证注入只作用于发起注入的测试。
#[cfg(test)]
thread_local! {
    static FAIL_PARTIAL_WRITE: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn partial_write_limit() -> Option<usize> {
    FAIL_PARTIAL_WRITE.with(|limit| limit.get())
}

#[cfg(test)]
fn set_partial_write_limit(limit: Option<usize>) {
    FAIL_PARTIAL_WRITE.with(|slot| slot.set(limit));
}

/// 只用来解出 batch 的小工具，避免把 Frame 依赖带进来。
struct BatchCodec;

impl BatchCodec {
    fn decode(payload: &[u8]) -> Option<SampleBatch> {
        rmp_serde::from_slice::<SampleBatch>(payload).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(seq: u64) -> SampleBatch {
        SampleBatch {
            agent_id: "a".into(),
            epoch: 1,
            seq,
            boot_id: "b".into(),
            sent_at: rustboard_common::util::now_ms(),
            samples: vec![rustboard_common::model::Sample::new("cpu.usage", 1, 1.0)],
        }
    }

    fn batch_epoch(epoch: u64, seq: u64) -> SampleBatch {
        let mut batch = batch(seq);
        batch.epoch = epoch;
        batch
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rb-buf-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// KI-21：缓冲目录新建即 0700，旧版本遗留的 0755 在 open 时收紧。
    #[cfg(unix)]
    #[test]
    fn ki21_buffer_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;

        fn mode_of(path: &Path) -> u32 {
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777
        }

        let dir = temp_dir("perms-new");
        {
            let _b = DiskBuffer::open(&dir, 1024 * 1024, 60_000).unwrap();
            assert_eq!(mode_of(&dir), 0o700, "新建缓冲目录必须是 0700");
        }
        let _ = std::fs::remove_dir_all(&dir);

        let dir = temp_dir("perms-old");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        {
            let _b = DiskBuffer::open(&dir, 1024 * 1024, 60_000).unwrap();
            assert_eq!(mode_of(&dir), 0o700, "旧 0755 缓冲目录必须在 open 时收紧");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn epochs_and_seqs(batches: &[SampleBatch]) -> Vec<(u64, u64)> {
        batches.iter().map(|b| (b.epoch, b.seq)).collect()
    }

    #[test]
    fn old_records_are_dropped_by_age_limit() {
        let dir = std::env::temp_dir().join(format!("rb-buf-age-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 60_000).unwrap();
        let mut old = batch(0);
        old.sent_at = rustboard_common::util::now_ms() - 120_000;
        b.push(&old).unwrap();
        assert_eq!(b.pending_len(), 0, "超过 1 分钟的记录应被淘汰");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn push_and_ack() {
        let dir = std::env::temp_dir().join(format!("rb-buf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
            b.push(&batch(0)).unwrap();
            b.push(&batch(1)).unwrap();
            let got = b.read_next(10).unwrap();
            assert_eq!(got.len(), 2);
            b.ack(1, 0).unwrap();
            assert_eq!(b.pending_len(), 1);
            b.ack(1, 1).unwrap();
            assert_eq!(b.pending_len(), 0);
        }
        // 重开后应能恢复未确认部分
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        assert_eq!(b.read_next(10).unwrap().len(), 0);
        b.push(&batch(2)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovers_pending_after_reopen() {
        let dir = std::env::temp_dir().join(format!("rb-buf2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
            b.push(&batch(7)).unwrap();
        }
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        let got = b.read_next(10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// issue #3：旧 epoch 的高 seq ACK 只能删到 epoch 边界，不能碰新 epoch 的低 seq。
    #[test]
    fn issue_3_epoch_a_high_seq_ack_keeps_epoch_b_batches() {
        let dir = temp_dir("epoch-boundary");
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        b.push(&batch_epoch(1, 100)).unwrap();
        b.push(&batch_epoch(1, 101)).unwrap();
        // 模拟 agent 重启：新 epoch 的 seq 从 0 重新开始
        b.push(&batch_epoch(2, 0)).unwrap();
        b.push(&batch_epoch(2, 1)).unwrap();

        b.ack(1, 101).unwrap();

        assert_eq!(b.pending_len(), 2);
        assert_eq!(
            epochs_and_seqs(&b.read_next(10).unwrap()),
            vec![(2, 0), (2, 1)]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// issue #3：交错 epoch 重传并重启后，未确认批次仍能完整恢复。
    #[test]
    fn issue_3_interleaved_epochs_survive_reopen() {
        let dir = temp_dir("interleaved-reopen");
        {
            let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
            b.push(&batch_epoch(1, 10)).unwrap();
            b.push(&batch_epoch(2, 0)).unwrap();
            b.push(&batch_epoch(1, 11)).unwrap();

            b.ack(1, 10).unwrap();
            assert_eq!(b.pending_len(), 2);
        }

        // 重开后读指针位于 B0，B0 与 A11 都必须保留
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        assert_eq!(
            epochs_and_seqs(&b.read_next(10).unwrap()),
            vec![(2, 0), (1, 11)]
        );
        // 确认 B0 只推进 epoch 2 的队首，不能越界删除后面的 A11
        b.ack(2, 0).unwrap();
        assert_eq!(b.pending_len(), 1);
        drop(b);

        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        assert_eq!(epochs_and_seqs(&b.read_next(10).unwrap()), vec![(1, 11)]);
        b.ack(1, 11).unwrap();
        assert_eq!(b.pending_len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// issue #3：未知 epoch 的 ACK 不能推进读指针，更不能误删任何批次。
    #[test]
    fn issue_3_ack_for_unknown_epoch_does_not_advance() {
        let dir = temp_dir("unknown-epoch");
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        b.push(&batch_epoch(1, 0)).unwrap();
        b.push(&batch_epoch(2, 0)).unwrap();

        b.ack(99, u64::MAX).unwrap();

        assert_eq!(b.pending_len(), 2);
        assert_eq!(
            epochs_and_seqs(&b.read_next(10).unwrap()),
            vec![(1, 0), (2, 0)]
        );
        // 队首仍能按自己的 epoch 正常确认
        b.ack(1, 0).unwrap();
        assert_eq!(b.pending_len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// issue #3：重复 ACK 幂等，不重复推进、不报错、不影响后续确认。
    #[test]
    fn issue_3_duplicate_ack_is_idempotent() {
        let dir = temp_dir("duplicate-ack");
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        b.push(&batch_epoch(1, 0)).unwrap();
        b.push(&batch_epoch(1, 1)).unwrap();

        b.ack(1, 0).unwrap();
        let bytes_after_first = b.pending_bytes();
        b.ack(1, 0).unwrap();
        b.ack(1, 0).unwrap();

        assert_eq!(b.pending_bytes(), bytes_after_first);
        assert_eq!(b.pending_len(), 1);
        assert_eq!(epochs_and_seqs(&b.read_next(10).unwrap()), vec![(1, 1)]);

        b.ack(1, 1).unwrap();
        b.ack(1, 1).unwrap();
        assert_eq!(b.pending_len(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 回归：write_all 部分写失败后必须截断回滚，不能留下撕裂记录。
    ///
    /// 注入一次“只写前 N 字节再失败”，断言文件长度、write_offset、pending
    /// 都不变；清除注入后再 push，读取、ack、重启都必须正常。
    #[test]
    fn partial_write_failure_is_rolled_back() {
        const PARTIAL_LEN: usize = 9;

        let dir = temp_dir("partial-write");
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        b.push(&batch(0)).unwrap();
        let log_path = dir.join("buffer.log");
        let before_len = std::fs::metadata(&log_path).unwrap().len();
        let before_offset = b.write_offset;
        let before_pending = b.pending_len();
        assert!(
            before_len > PARTIAL_LEN as u64,
            "前置条件：已有记录应长于注入的字节数"
        );

        set_partial_write_limit(Some(PARTIAL_LEN));
        let err = b.push(&batch(1)).unwrap_err();
        set_partial_write_limit(None);

        assert_eq!(
            err.kind(),
            std::io::ErrorKind::Other,
            "应返回注入的原始错误"
        );
        assert_eq!(
            std::fs::metadata(&log_path).unwrap().len(),
            before_len,
            "部分写后必须把文件截回旧 EOF"
        );
        assert_eq!(b.write_offset, before_offset, "write_offset 不得前进");
        assert_eq!(
            b.pending_len(),
            before_pending,
            "失败的记录不得进入 pending"
        );
        assert!(!b.broken, "回滚成功后不应标记 broken");

        // 清除注入后同一实例应继续可用，且不能读到撕裂字节。
        b.push(&batch(1)).unwrap();
        assert_eq!(b.pending_len(), before_pending + 1);
        let got = b.read_next(10).unwrap();
        assert_eq!(got.last().map(|item| item.seq), Some(1));
        b.ack(1, 1).unwrap();
        assert_eq!(b.pending_len(), 0);
        drop(b);

        // 重启后不得复活失败写入的撕裂记录。
        let mut b = DiskBuffer::open(&dir, 1024 * 1024, 24 * 3600 * 1000).unwrap();
        assert_eq!(b.pending_len(), 0, "ack 后重启不应复活任何记录");
        b.push(&batch(2)).unwrap();
        assert_eq!(b.read_next(10).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// 独立测试子 Agent 的 v0.3.1 测试模块；当前为占位，避免与实现 Agent 冲突。
#[cfg(test)]
#[path = "buffer_v031_tests.rs"]
mod v031_tests;
