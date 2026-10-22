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
    dropped: u64,
}

impl DiskBuffer {
    pub fn open(dir: impl AsRef<Path>, max_bytes: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir.as_ref())?;
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
                        seq: batch.seq,
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
            seq: batch.seq,
            offset,
            len: record.len() as u64,
        });

        self.enforce_limit()?;
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

    /// 确认到 `seq`（含）为止的批次，可安全丢弃。
    pub fn ack(&mut self, seq: u64) -> std::io::Result<()> {
        let mut advance = 0u64;
        while let Some(front) = self.pending.front() {
            if front.seq > seq {
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
            sent_at: 0,
            samples: vec![rustboard_common::model::Sample::new("cpu.usage", 1, 1.0)],
        }
    }

    #[test]
    fn push_and_ack() {
        let dir = std::env::temp_dir().join(format!("rb-buf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let mut b = DiskBuffer::open(&dir, 1024 * 1024).unwrap();
            b.push(&batch(0)).unwrap();
            b.push(&batch(1)).unwrap();
            let got = b.read_next(10).unwrap();
            assert_eq!(got.len(), 2);
            b.ack(0).unwrap();
            assert_eq!(b.pending_len(), 1);
            b.ack(1).unwrap();
            assert_eq!(b.pending_len(), 0);
        }
        // 重开后应能恢复未确认部分
        let mut b = DiskBuffer::open(&dir, 1024 * 1024).unwrap();
        assert_eq!(b.read_next(10).unwrap().len(), 0);
        b.push(&batch(2)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn recovers_pending_after_reopen() {
        let dir = std::env::temp_dir().join(format!("rb-buf2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        {
            let mut b = DiskBuffer::open(&dir, 1024 * 1024).unwrap();
            b.push(&batch(7)).unwrap();
        }
        let mut b = DiskBuffer::open(&dir, 1024 * 1024).unwrap();
        let got = b.read_next(10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
