//! 本地磁盘缓冲。
//!
//! hub 断连时采样点不能丢，所以写入一个只追加的分段日志；
//! 收到 Ack 后推进读指针，占用超过一半时做一次压实（重写文件）。
//!
//! 记录格式：`[len: u32 LE][msgpack payload]`，没有 CRC——尾部截断或
//! 解码失败时直接丢弃损坏的尾部记录，前面的数据仍然可用。

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rustboard_common::model::SampleBatch;

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
}

impl DiskBuffer {
    pub fn open(dir: impl AsRef<Path>, max_bytes: u64, max_age_ms: u64) -> std::io::Result<Self> {
        rustboard_common::fsutil::ensure_dir(dir.as_ref(), 0o700)?;
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
        };
        let start = buf.load_meta();
        buf.recover(start)?;
        Ok(buf)
    }

    fn load_meta(&self) -> u64 {
        std::fs::read_to_string(&self.meta_path)
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    }

    fn save_meta(&self) -> std::io::Result<()> {
        std::fs::write(&self.meta_path, self.read_offset.to_string())
    }

    /// 从 `start` 开始扫描已有日志，重建待发送队列；损坏的尾部会被截断。
    fn recover(&mut self, start: u64) -> std::io::Result<()> {
        let len = self.file.metadata()?.len();
        let mut offset = if start <= len { start } else { 0 };
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
        self.prune_aged(rustboard_common::util::now_ms())?;
        Ok(())
    }

    pub fn push(&mut self, batch: &SampleBatch) -> std::io::Result<()> {
        let payload = rmp_serde::to_vec(batch).map_err(std::io::Error::other)?;
        let mut record = Vec::with_capacity(4 + payload.len());
        record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        record.extend_from_slice(&payload);

        let offset = self.write_offset;
        self.file.write_all(&record)?;
        self.write_offset += record.len() as u64;
        self.pending.push_back(Pending {
            epoch: batch.epoch,
            seq: batch.seq,
            ts: batch.sent_at,
            offset,
            len: record.len() as u64,
        });

        self.prune_aged(rustboard_common::util::now_ms())?;
        self.enforce_limit()?;
        Ok(())
    }

    /// 丢弃超过 `max_age_ms` 的旧记录（agent 长时间离线且缓冲未涨满时，
    /// 过旧的数据对 hub 已无意义，也避免判重窗口被撑爆）。
    fn prune_aged(&mut self, now: i64) -> std::io::Result<()> {
        if self.max_age_ms == 0 || self.pending.is_empty() {
            return Ok(());
        }
        let cutoff = now.saturating_sub(self.max_age_ms.min(i64::MAX as u64) as i64);
        let mut advanced = false;
        while let Some(front) = self.pending.front() {
            if front.ts >= cutoff {
                break;
            }
            let end = front.offset + front.len;
            self.pending.pop_front();
            self.read_offset = end;
            self.dropped += 1;
            advanced = true;
        }
        if advanced {
            self.save_meta()?;
        }
        Ok(())
    }

    /// 超过上限时丢弃最旧的记录（宁可丢历史也不能撑爆磁盘）。
    fn enforce_limit(&mut self) -> std::io::Result<()> {
        while self.write_offset.saturating_sub(self.read_offset) > self.max_bytes {
            let Some(front) = self.pending.pop_front() else {
                break;
            };
            self.read_offset = front.offset + front.len;
            self.dropped += 1;
        }
        if self.dropped > 0 && self.pending.is_empty() {
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
    pub fn ack(&mut self, epoch: u64, seq: u64) -> std::io::Result<()> {
        let mut advance = 0u64;
        while let Some(front) = self.pending.front() {
            if front.epoch != epoch || front.seq > seq {
                break;
            }
            advance = front.offset + front.len;
            self.pending.pop_front();
        }
        if advance > self.read_offset {
            self.read_offset = advance;
            self.save_meta()?;
        }
        // 已消费部分超过 1MB 且占文件一半以上时压实
        if self.read_offset > 1024 * 1024 && self.read_offset * 2 > self.write_offset {
            self.compact()?;
        }
        Ok(())
    }

    /// 把未确认部分搬到新文件，丢弃已确认前缀。
    fn compact(&mut self) -> std::io::Result<()> {
        if self.read_offset == 0 {
            return Ok(());
        }
        let remaining = self.write_offset - self.read_offset;
        let mut buf = vec![0u8; remaining as usize];
        self.file.seek(SeekFrom::Start(self.read_offset))?;
        self.file.read_exact(&mut buf)?;

        let tmp = self.path.with_extension("log.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;

        self.file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&self.path)?;

        let shift = self.read_offset;
        for p in self.pending.iter_mut() {
            p.offset -= shift;
        }
        self.write_offset = remaining;
        self.read_offset = 0;
        self.dropped = 0;
        self.save_meta()?;
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
}
