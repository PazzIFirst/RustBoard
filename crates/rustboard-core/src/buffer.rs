//! 本地磁盘缓冲。
//!
//! hub 断连时采样点不能丢，所以写入一个只追加的分段日志；
//! 收到 Ack、超过时效或超过字节上限时推进读指针，物理文件超过水位时做一次
//! 压实（重写文件，只保留未确认记录）。
//!
//! 记录格式仍是 `[len: u32 LE][msgpack payload]`，没有 CRC；不改变格式是为了
//! 保持与旧 agent 的降级兼容。损坏记录不能简单当成“尾部截断”：中间字节损坏
//! 时后面的有效记录必须保留，只有真正的尾部撕裂才截断。
//!
//! # 持久化与崩溃安全（#34）
//!
//! - 双 meta：`buffer.meta`（primary）与 `buffer.meta.bak`（backup）都只存十进制
//!   `read_offset`，通过 `rustboard_common::fsutil::atomic_write` 原子替换，
//!   权限 0600。推进读指针时先写 backup（上一次 primary 的旧值），再写 primary；
//!   启动时优先 primary，primary 非法/不在记录边界时才回退 backup。两者都非法
//!   （且不是全新缓冲）则 fail-closed：保留文件并返回明确错误，绝不静默从 0
//!   重放已 ACK 前缀。确需从日志开头恢复时由运维显式执行
//!   `rustboard-agent buffer repair --from-start`，依赖 hub 的
//!   `(agent_id, epoch, seq)` 判重。
//! - 记录边界：`offset == 文件长度`，或该偏移处 `[len][msgpack]` 能完整解码，
//!   才算合法 meta。meta 指向记录中间时视为损坏，回退 backup。
//! - 中间损坏向前重同步：顺序扫描遇到非法长度/解码失败时，从下一个字节起寻找
//!   可解码记录；找到则保留其后有效记录并只记录坏区间，找不到才按尾部撕裂
//!   截断到最后一条有效记录。修复前先把原 `buffer.log` 复制为
//!   `buffer.log.corrupt-<ts>`（0600），同一份损坏内容不会重复复制。
//! - 压实只重写 `pending` 中仍然有效的记录，因此会把中间坏区间物理删掉；
//!   已确认前缀与坏字节都不会进入新文件。
//! - 压实先写同目录临时文件、`sync_all`，再把 backup 写 0、`rename`、写
//!   `buffer.meta = 0`。只有 `read_offset == 0 || read_offset > 剩余未确认字节`
//!   时才允许压实：若在 rename 后、primary 落盘前崩溃，旧 primary 会因越界/
//!   非边界被拒绝，启动时回退到 backup=0，从新文件开头恢复，不会把未确认
//!   记录当成已确认前缀跳过。

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rustboard_common::model::SampleBatch;

/// `buffer.meta` / `buffer.meta.bak` 的权限：只允许 agent 自己读写。
const META_MODE: u32 = 0o600;

/// 压实水位至少比 `max_bytes` 高 1 MiB，避免小上限时过于频繁地重写文件。
const COMPACT_SLACK_BYTES: u64 = 1024 * 1024;

/// 单条记录 payload 的合理上限（8 MiB）。
///
/// hub 的 WebSocket 消息上限是 1 MiB，正常批次远小于 8 MiB。恢复时用它挡住
/// 损坏 header 声明出的超大长度，避免为一条伪造记录分配整个文件的缓冲区；
/// 超过该值的记录本来也无法上报成功。
const MAX_RECORD_PAYLOAD_BYTES: u64 = 8 * 1024 * 1024;

/// header 本身损坏时，向后逐字节寻找有效记录的最大扫描距离。
///
/// 单条合法记录的 payload 上限与 `push` 一致（`MAX_RECORD_PAYLOAD_BYTES`），
/// 因此下一条记录起点至多在该距离处（再留 4 字节给它的长度头）；超过后按
/// 尾部损坏处理，避免极端损坏文件让启动扫描无上界。
const RESYNC_SCAN_LIMIT_BYTES: u64 = MAX_RECORD_PAYLOAD_BYTES + 8;

/// 主 meta 文件名（十进制 `read_offset`）。
const META_FILE: &str = "buffer.meta";
/// 备份 meta 文件名；正常推进时保存上一次 primary 的值，压实期间临时写 0。
const META_BACKUP_FILE: &str = "buffer.meta.bak";
/// 缓冲日志文件名。
const LOG_FILE: &str = "buffer.log";
/// 损坏日志副本的文件名前缀。
const CORRUPT_LOG_PREFIX: &str = "buffer.log.corrupt-";

/// 读取到的 meta 文件状态。缺文件与“内容非法”必须区分：全新缓冲没有 meta
/// 是正常状态，而存在但无法解析/不在记录边界则可能是损坏。
enum MetaState {
    Missing,
    Value(u64),
    Invalid(String),
}

impl MetaState {
    fn describe(&self) -> String {
        match self {
            Self::Missing => "文件不存在".to_string(),
            Self::Value(value) => format!("值 {value}"),
            Self::Invalid(reason) => format!("内容非法（{reason}）"),
        }
    }
}

/// 读取并粗略解析 meta 文件；是否落在记录边界由调用方结合日志长度判断。
fn read_meta_state(path: &Path) -> MetaState {
    match std::fs::read_to_string(path) {
        Ok(text) => match text.trim().parse::<u64>() {
            Ok(value) => MetaState::Value(value),
            Err(err) => MetaState::Invalid(format!("无法解析为十进制 u64: {err}")),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => MetaState::Missing,
        Err(err) => MetaState::Invalid(format!("读取失败: {err}")),
    }
}

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
    /// `buffer.meta` 的备份，保存上一次成功落盘的 primary 旧值。
    meta_backup_path: PathBuf,
    /// 主 meta 的逻辑值：下一次写 backup 时用它作为“旧值”。
    meta_primary: u64,
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
        let path = dir.as_ref().join(LOG_FILE);
        let meta_path = dir.as_ref().join(META_FILE);
        let meta_backup_path = dir.as_ref().join(META_BACKUP_FILE);
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&path)?;

        let mut buf = Self {
            path,
            meta_path,
            meta_backup_path,
            meta_primary: 0,
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
        let start = buf.load_start()?;
        buf.recover(start)?;
        // 重启后重新执行一次统一限额：旧版本可能没持久化淘汰偏移，离线期间
        // 也可能积累超龄/超量记录；单条超大记录由 enforce_limit 保留。
        buf.enforce_limit(rustboard_common::util::now_ms())?;
        Ok(buf)
    }

    /// 读取启动偏移：primary 优先，primary 非法/非记录边界时回退 backup。
    ///
    /// 只有“两个文件都不存在”（全新缓冲 / 旧版本从未 ACK）才默认从 0 开始；
    /// 只要有一个 meta 文件存在但两者都不可用，就 fail-closed，保留全部文件，
    /// 避免静默重放已 ACK 数据或跳过未确认记录。恢复入口是显式的
    /// `rustboard-agent buffer repair --from-start`。
    fn load_start(&mut self) -> std::io::Result<u64> {
        let len = self.file.metadata()?.len();
        let primary = read_meta_state(&self.meta_path);
        let backup = read_meta_state(&self.meta_backup_path);
        let primary_start = self.valid_boundary(&primary, len);
        let backup_start = self.valid_boundary(&backup, len);

        if let Some(start) = primary_start {
            self.meta_primary = start;
            return Ok(start);
        }
        if let Some(start) = backup_start {
            tracing::warn!(
                primary = %primary.describe(),
                backup_offset = start,
                log_len = len,
                "buffer.meta 不可用，已回退 buffer.meta.bak 并修复主 meta"
            );
            // 修复 primary，避免每次启动都走回退路径。
            let bytes = start.to_string();
            rustboard_common::fsutil::atomic_write(&self.meta_path, bytes.as_bytes(), META_MODE)?;
            self.meta_primary = start;
            return Ok(start);
        }
        if matches!(primary, MetaState::Missing) && matches!(backup, MetaState::Missing) {
            // 全新缓冲，或旧版本从未推进过读指针：从日志开头恢复。
            self.meta_primary = 0;
            return Ok(0);
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "缓冲元数据损坏：{} {}；{} {}；{LOG_FILE} 长度 {len}。两条 meta 都不是\
                 日志中的合法记录边界。为避免重放已 ACK 前缀或跳过未确认记录，启动已\
                 中止且所有文件保持不变。确认 hub 会按 (agent_id, epoch, seq) 判重后，\
                 可显式执行 `rustboard-agent buffer repair --from-start` 从日志开头恢复。",
                self.meta_path.display(),
                primary.describe(),
                self.meta_backup_path.display(),
                backup.describe()
            ),
        ))
    }

    /// 校验 meta 值是否是当前日志的合法记录边界：
    /// `offset == 0`、`offset == len`，或该偏移处能完整读出 `[len][msgpack]`
    /// 并解码。
    ///
    /// 0 必须无条件接受：它不可能跳过任何未确认记录；即使首条记录损坏，
    /// recover 也会从 0 开始向前重同步。若要求首条可解码，两 meta 都是 0 的
    /// 现场（压实后 / repair --from-start 后）遇到首条损坏就会误 fail-closed。
    fn valid_boundary(&mut self, state: &MetaState, len: u64) -> Option<u64> {
        let MetaState::Value(offset) = state else {
            return None;
        };
        let offset = *offset;
        if offset > len {
            return None;
        }
        if offset == 0 || offset == len {
            return Some(offset);
        }
        record_at(&mut self.file, offset, len).map(|_| offset)
    }

    /// 把目标读偏移落盘：先 backup（旧 primary 值）再 primary。
    ///
    /// 先落盘成功、再允许调用方修改内存：失败时保持旧状态并返回错误，
    /// 不会出现“内存已淘汰、磁盘偏移未变”的分裂。
    fn persist_offset(&mut self, offset: u64) -> std::io::Result<()> {
        let backup = self.meta_primary;
        self.persist_meta(offset, backup)
    }

    fn save_meta(&mut self) -> std::io::Result<()> {
        self.persist_offset(self.read_offset)
    }

    /// 先原子写 backup、再原子写 primary；任何一步失败都返回错误。
    ///
    /// `meta_primary` 只在 primary 成功后更新：写 backup 成功但 primary 失败时，
    /// 下次重试仍以旧 primary 作为 backup 值。
    fn persist_meta(&mut self, offset: u64, backup: u64) -> std::io::Result<()> {
        let backup_bytes = backup.to_string();
        rustboard_common::fsutil::atomic_write(
            &self.meta_backup_path,
            backup_bytes.as_bytes(),
            META_MODE,
        )?;
        let bytes = offset.to_string();
        rustboard_common::fsutil::atomic_write(&self.meta_path, bytes.as_bytes(), META_MODE)?;
        self.meta_primary = offset;
        self.meta_dirty = false;
        Ok(())
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

    /// 从 `start` 开始扫描已有日志，重建待发送队列。
    ///
    /// - 记录完整可解码：进入 pending；
    /// - 记录损坏但后面还能找到可解码记录：中间损坏，跳到下一条有效记录，
    ///   坏区间只记 WARN，不删后续 pending；
    /// - 记录损坏且后面没有有效记录：尾部撕裂，截断到最后一条有效记录结尾。
    ///
    /// 修改日志前先把原文件复制为 `buffer.log.corrupt-<ts>`（0600）。
    fn recover(&mut self, start: u64) -> std::io::Result<()> {
        let len = self.file.metadata()?.len();
        if start > len {
            // load_start 已做过边界校验；保留防御，不能让越界偏移进入扫描。
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("缓冲读偏移 {start} 超过日志长度 {len}"),
            ));
        }
        let mut offset = start;
        let mut good_end = offset;
        let mut gap_bytes = 0u64;
        let mut gap_count = 0u64;

        while offset < len {
            let Some((record_len, batch)) = record_at(&mut self.file, offset, len) else {
                // 先看后面是否还有可解码记录：有则是中间损坏，向前重同步；
                // 没有才按尾部撕裂处理，避免把后续有效记录一起截掉。
                let Some(next) = resync_after_bad_record(&mut self.file, &self.path, offset, len)
                else {
                    break;
                };
                tracing::warn!(
                    bad_offset = offset,
                    next_valid_offset = next,
                    bad_bytes = next - offset,
                    "缓冲中段记录损坏，向前重同步并保留后续有效记录"
                );
                gap_bytes += next - offset;
                gap_count += 1;
                offset = next;
                continue;
            };
            self.pending.push_back(Pending {
                epoch: batch.epoch,
                seq: batch.seq,
                ts: batch.sent_at,
                offset,
                len: record_len,
            });
            offset += record_len;
            good_end = offset;
        }

        let tail_damaged = good_end < len;
        if gap_bytes > 0 || tail_damaged {
            // 先留证据再动文件：复制失败就不做修复，原文件保持原样。
            self.preserve_corrupt_log(len)?;
        }
        if tail_damaged {
            tracing::warn!(
                dropped_bytes = len - good_end,
                last_good_offset = good_end,
                "缓冲尾部损坏，已截断到最后一条有效记录"
            );
            self.file.set_len(good_end)?;
        }
        self.read_offset = start;
        self.write_offset = good_end;

        if gap_bytes > 0 {
            // 中间损坏：满足崩溃安全不变式时立即压实，把坏区间物理删掉；
            // 不满足时保留坏区间，后续正常压实时会只重写 pending 自然清掉。
            let remaining = self.write_offset.saturating_sub(self.read_offset);
            if self.read_offset == 0 || self.read_offset > remaining {
                tracing::warn!(
                    gap_bytes,
                    gap_count,
                    read_offset = self.read_offset,
                    write_offset = self.write_offset,
                    "中间损坏修复：重写未确认记录并移除坏区间"
                );
                self.compact()?;
            } else {
                tracing::warn!(
                    gap_bytes,
                    gap_count,
                    read_offset = self.read_offset,
                    remaining,
                    "坏区间暂未压实（不满足崩溃安全不变式），将在后续正常压实时移除"
                );
            }
        }
        Ok(())
    }

    /// 修改日志前保存一份损坏日志副本：`buffer.log.corrupt-<ts>`，0600。
    ///
    /// 已存在内容完全相同（长度与字节均一致）的副本时直接跳过，保证反复
    /// 打开同一份未修复日志不会每次启动都复制一遍。
    fn preserve_corrupt_log(&self, len: u64) -> std::io::Result<()> {
        if self.has_identical_corrupt_copy(len)? {
            return Ok(());
        }
        let mut ts = rustboard_common::util::now_ms();
        for _ in 0..100 {
            let path = self
                .path
                .with_file_name(format!("{CORRUPT_LOG_PREFIX}{ts}"));
            match open_private_copy(&path) {
                Ok(mut dest) => {
                    let mut src = File::open(&self.path)?;
                    std::io::copy(&mut src, &mut dest)?;
                    dest.sync_all()?;
                    tracing::warn!(
                        path = %path.display(),
                        bytes = len,
                        "已保存损坏缓冲日志副本（0600）"
                    );
                    return Ok(());
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => ts += 1,
                Err(err) => return Err(err),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "无法创建 buffer.log.corrupt-<ts>：连续 100 个时间戳都被占用",
        ))
    }

    /// 是否已存在与当前日志内容完全相同的损坏副本。
    fn has_identical_corrupt_copy(&self, len: u64) -> std::io::Result<bool> {
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with(CORRUPT_LOG_PREFIX) {
                continue;
            }
            let meta = entry.metadata()?;
            if !meta.is_file() || meta.len() != len {
                continue;
            }
            if files_equal(&self.path, &entry.path())? {
                return Ok(true);
            }
        }
        Ok(false)
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
        // 与 recover 的 MAX_RECORD_PAYLOAD_BYTES 保持一致：超限批次直接拒绝，
        // 不能先写进日志、下次启动再被当成损坏记录截掉。
        if payload.len() as u64 > MAX_RECORD_PAYLOAD_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "批次 payload {} 字节超过缓冲单条记录上限 {} 字节，拒绝写入",
                    payload.len(),
                    MAX_RECORD_PAYLOAD_BYTES
                ),
            ));
        }
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

    /// 淘汰前 `evict_count` 条记录后应落盘的读偏移。
    ///
    /// 正常连续日志下等于最后一条被淘汰记录的结尾；存在中间损坏留下的空洞时，
    /// 直接跳到下一条 pending 记录的起点（坏字节和已淘汰记录一起丢弃），
    /// 保证落盘的 meta 始终是合法记录边界，而不是坏区间起点。
    fn eviction_target(&self, evict_count: usize) -> u64 {
        match self.pending.get(evict_count) {
            Some(next) => next.offset,
            None => self.write_offset,
        }
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
        let mut evict_count = 0usize;
        for front in &self.pending {
            if front.ts >= cutoff {
                break;
            }
            evict_count += 1;
        }
        if evict_count == 0 {
            return Ok(());
        }
        let target = self.eviction_target(evict_count);
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
        let mut evict_count = 0usize;
        while self.pending.len() > evict_count + 1 {
            let target = self.eviction_target(evict_count);
            if self.write_offset.saturating_sub(target) <= self.max_bytes {
                break;
            }
            evict_count += 1;
        }
        if evict_count == 0 {
            return Ok(());
        }
        #[cfg(test)]
        crash_if(CrashPoint::AfterEvictionBeforeMetaSave);
        let target = self.eviction_target(evict_count);
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
        let remaining = self.write_offset.saturating_sub(self.read_offset);
        let pending_total: u64 = self.pending.iter().map(|p| p.len).sum();
        // 文件超过水位，或 [read_offset, write_offset) 里还有已确认前缀/中间
        // 损坏空洞（区间长度大于 pending 有效字节）时都值得压实。
        // pending 清空但仍残留已确认前缀时也必须压实：否则文件里留着 ACK 数据，
        // 一旦两条 meta 都丢失，就会从 0 重放全部 ACK 前缀（hub 判重窗口有限）。
        let acked_prefix_only = self.pending.is_empty() && self.read_offset > 0;
        if len > threshold || remaining > pending_total || acked_prefix_only {
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
        let mut count = 0usize;
        for front in &self.pending {
            if front.epoch != epoch || front.seq > seq {
                break;
            }
            count += 1;
        }
        if count > 0 {
            // 目标取“下一条 pending 的起点”而不是最后一条被确认记录的结尾：
            // 中间损坏留下的空洞不是合法记录边界，直接随已确认前缀一起跳过，
            // 保证落盘的 meta 永远是 boundary。
            let target = self.eviction_target(count);
            self.persist_offset(target)?;
            for _ in 0..count {
                self.pending.pop_front();
            }
            self.read_offset = target;
        }
        // pending 清空或物理文件超过水位时压实（compact 内部有崩溃安全判断）。
        self.maybe_compact()?;
        Ok(())
    }

    /// 把未确认记录搬到新文件，丢弃已确认前缀与中间损坏区间。
    ///
    /// 新文件只由 `pending` 中仍然有效的记录顺序拼接而成，因此中间损坏留下的
    /// 坏字节不会进入新文件。顺序：同目录临时文件 → 写入 → `sync_all` →
    /// 先把 backup 写 0 → 打开新句柄 → `rename` → 修正偏移 →
    /// 原子写 primary=0（backup 也是 0）。
    fn compact(&mut self) -> std::io::Result<()> {
        // 压实前同样确认文件长度与内存写偏移一致，避免基于撕裂文件重写。
        self.ensure_intact()?;
        let remaining = self.write_offset.saturating_sub(self.read_offset);
        let pending_total: u64 = self.pending.iter().map(|p| p.len).sum();
        let has_hole = remaining > pending_total;
        if !has_hole && self.read_offset == 0 {
            // 上次压实 rename 后 meta 写失败：这里补写一次，避免旧 meta 长期悬空。
            if self.meta_dirty {
                self.save_meta()?;
            }
            return Ok(());
        }

        // 崩溃安全不变式（必须严格遵守）：
        // 只有 read_offset == 0（旧 meta 本来就是 0）或 read_offset > remaining
        // 时才允许 rename。若在 rename 后、primary 落盘前崩溃，旧 primary 会
        // 因越界/非边界被拒绝，启动时回退到 rename 前预写的 backup=0，从新文件
        // 开头恢复，不会把尚未确认的记录当成已确认前缀跳过。
        // 单条超大记录通常使 remaining >= read_offset，此时宁可跳过本次压实。
        if self.read_offset != 0 && self.read_offset <= remaining {
            tracing::debug!(
                read_offset = self.read_offset,
                remaining,
                "不满足压实崩溃安全不变式，跳过压实"
            );
            return Ok(());
        }

        // 只重写 pending 中的有效记录：已确认前缀与中间损坏字节都被丢弃。
        let mut buf = Vec::with_capacity(pending_total as usize);
        for p in &self.pending {
            let start = buf.len();
            buf.resize(start + p.len as usize, 0);
            self.file.seek(SeekFrom::Start(p.offset))?;
            self.file.read_exact(&mut buf[start..])?;
        }

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
        // rename 之前先把 backup 写成 0：这是“新文件只含 pending”的崩溃标记。
        // 若 rename 后 primary 未落盘就崩溃，旧 primary 会越界，启动时用 backup=0
        // 从新文件开头恢复；若 rename 前崩溃，primary 仍有效且优先于 backup。
        rustboard_common::fsutil::atomic_write(&self.meta_backup_path, b"0", META_MODE)?;
        std::fs::rename(&tmp, &self.path)?;
        // rename 后句柄仍指向同一 inode，直接接管，无需再次 open(path)。
        self.file = new_file;

        let mut new_offset = 0u64;
        for p in self.pending.iter_mut() {
            p.offset = new_offset;
            new_offset += p.len;
        }
        self.write_offset = new_offset;
        self.read_offset = 0;
        self.dropped = 0;
        // primary 的旧值已不属于新文件，逻辑值同步为 0（供失败重试时写 backup）。
        self.meta_primary = 0;

        #[cfg(test)]
        crash_if(CrashPoint::AfterCompactionRenameBeforeMetaSave);

        if let Err(err) = self.persist_meta(0, 0) {
            // rename 已经成功，新文件里只剩未确认记录，但 primary 尚未落盘。
            // backup 已是 0，标记待补写，后续写操作会先重试。
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

/// 从 `offset` 读取一条完整记录并解码。
///
/// `offset == len` 或越界、长度为 0、超过 `MAX_RECORD_PAYLOAD_BYTES`、payload
/// 越过文件尾、解码失败都返回 None。调用方据“后面是否还有有效记录”区分
/// 中间损坏与尾部撕裂。
fn record_at(file: &mut File, offset: u64, len: u64) -> Option<(u64, SampleBatch)> {
    if offset.checked_add(4)? > len {
        return None;
    }
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut header = [0u8; 4];
    file.read_exact(&mut header).ok()?;
    let payload_len = u64::from(u32::from_le_bytes(header));
    if payload_len == 0 || payload_len > MAX_RECORD_PAYLOAD_BYTES {
        return None;
    }
    let record_len = 4 + payload_len;
    if offset.checked_add(record_len)? > len {
        return None;
    }
    let mut payload = vec![0u8; payload_len as usize];
    file.read_exact(&mut payload).ok()?;
    let batch = BatchCodec::decode(&payload)?;
    Some((record_len, batch))
}

/// 读取长度头，算出记录结尾（不校验 payload 能否解码）。
///
/// payload 被篡改但长度头完好时，下一条记录的起点是确定的；这是中间损坏
/// 最常见的形式，用它避免逐字节扫描。
fn record_extent(file: &mut File, offset: u64, len: u64) -> Option<u64> {
    if offset.checked_add(4)? > len {
        return None;
    }
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut header = [0u8; 4];
    file.read_exact(&mut header).ok()?;
    let payload_len = u64::from(u32::from_le_bytes(header));
    if payload_len == 0 || payload_len > MAX_RECORD_PAYLOAD_BYTES {
        return None;
    }
    let end = offset.checked_add(4 + payload_len)?;
    (end <= len).then_some(end)
}

/// 坏记录之后的下一条有效记录起点。
///
/// 快路径：长度头完好 → 校验其后是否是一条有效记录（或正好到 EOF）；
/// 慢路径：长度头也损坏 → 向后逐字节搜索，最多扫 `RESYNC_SCAN_LIMIT_BYTES`。
fn resync_after_bad_record(file: &mut File, path: &Path, offset: u64, len: u64) -> Option<u64> {
    if let Some(end) = record_extent(file, offset, len) {
        if end == len || record_at(file, end, len).is_some() {
            return Some(end);
        }
    }
    find_next_valid_record(file, path, offset + 1, len)
}

/// 从 `from` 起逐字节寻找下一条可解码记录（最多扫 `RESYNC_SCAN_LIMIT_BYTES`）。
///
/// 用完整 `SampleBatch` 解码作为最终判据；先用长度头与 payload 前两字节的
/// msgpack 结构（array/map + 字符串头）做廉价过滤，避免损坏区域里每个字节
/// 都尝试分配/解码。这里刻意不设“解码字节预算”：只要预算按未成功解码的
/// 候选累计，损坏区里的假候选就可能把它耗光，让后面的真实记录被误当尾部
/// 截断。工作量改由扫描窗口上限 + 两级廉价过滤控制。
///
/// 头部扫描用独立句柄 + `BufReader` 顺序读取，避免每个字节一次 seek+read；
/// 候选校验仍用原句柄与完整解码。不额外要求“后面还必须有一条有效记录”，
/// 否则中间损坏后只剩最后一条有效记录时会被误判成尾部撕裂而删掉。
fn find_next_valid_record(file: &mut File, path: &Path, from: u64, len: u64) -> Option<u64> {
    let scan_end = len.min(from.saturating_add(RESYNC_SCAN_LIMIT_BYTES));
    if from.checked_add(4)? > scan_end {
        return None;
    }
    // 独立打开扫描句柄：dup 的 fd 会共享文件偏移，不能与 file 混用顺序读。
    let mut reader = BufReader::new(File::open(path).ok()?);
    reader.seek(SeekFrom::Start(from)).ok()?;
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).ok()?;
    let mut candidate = from;

    loop {
        let payload_len = u64::from(u32::from_le_bytes(header));
        if payload_len > 0 && payload_len <= MAX_RECORD_PAYLOAD_BYTES {
            if let Some(end) = candidate.checked_add(4 + payload_len) {
                if end <= len
                    && plausible_sample_batch_prefix(file, candidate + 4).unwrap_or(false)
                    && record_at(file, candidate, len).is_some()
                {
                    return Some(candidate);
                }
            }
        }
        if candidate + 4 >= scan_end {
            break;
        }
        let mut next = [0u8; 1];
        if reader.read_exact(&mut next).is_err() {
            break;
        }
        header.rotate_left(1);
        header[3] = next[0];
        candidate += 1;
    }
    None
}

/// payload 前两字节是否可能是 `SampleBatch` 的 msgpack 结构。
///
/// `SampleBatch` 按结构体编码：首字节是 array/map 头，第二个字段是字符串
/// （agent_id；map 编码时则是第一个 key）。两级检查都是 O(1) 读字节，不做
/// 分配；仅是廉价预过滤，最终仍由 `BatchCodec::decode` 判定。若编码形式
/// 未来变化，最坏退化为该损坏场景下找不到有效记录并按尾部截断。
fn plausible_sample_batch_prefix(file: &mut File, payload_offset: u64) -> std::io::Result<bool> {
    file.seek(SeekFrom::Start(payload_offset))?;
    let mut prefix = [0u8; 2];
    file.read_exact(&mut prefix)?;
    let container = matches!(
        prefix[0],
        0x80..=0x8f | 0x90..=0x9f | 0xdc..=0xdd | 0xde..=0xdf
    );
    let first_field_is_string = matches!(prefix[1], 0xa0..=0xbf | 0xd9..=0xdb);
    Ok(container && first_field_is_string)
}

/// 以 0600 新建文件（Unix 下禁止跟随符号链接），用于损坏日志副本。
fn open_private_copy(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(META_MODE).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(META_MODE))?;
    }
    Ok(file)
}

/// 按块比较两个文件内容（调用方已确认长度相同）。
fn files_equal(a: &Path, b: &Path) -> std::io::Result<bool> {
    let mut left = File::open(a)?;
    let mut right = File::open(b)?;
    let mut left_buf = [0u8; 64 * 1024];
    let mut right_buf = [0u8; 64 * 1024];
    loop {
        let left_len = read_full(&mut left, &mut left_buf)?;
        let right_len = read_full(&mut right, &mut right_buf)?;
        if left_len != right_len || left_buf[..left_len] != right_buf[..right_len] {
            return Ok(false);
        }
        if left_len == 0 {
            return Ok(true);
        }
    }
}

/// 尽量填满缓冲区；只有读到 EOF 才返回不足长度。
fn read_full(file: &mut File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let read = file.read(&mut buf[filled..])?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

/// `buffer repair --from-start` 的结果，供 CLI 输出。
pub struct BufferRepairReport {
    /// 当前 `buffer.log` 字节数（不会被 repair 修改）。
    pub log_bytes: u64,
    /// repair 之前 primary meta 是否存在。
    pub had_primary: bool,
    /// repair 之前 backup meta 是否存在。
    pub had_backup: bool,
}

/// 显式把读偏移重置到日志开头，供 `rustboard-agent buffer repair --from-start`
/// 使用；必须在 agent 停止时执行。
///
/// 不修改 `buffer.log`，只把 primary / backup 都原子写成 0（先 backup 后
/// primary）。下次启动会从日志开头恢复并重发已 ACK 前缀，依赖 hub 的
/// `(agent_id, epoch, seq)` 判重。启动流程不会自动调用本函数。
pub fn repair_from_start(dir: impl AsRef<Path>) -> std::io::Result<BufferRepairReport> {
    rustboard_common::fsutil::ensure_private_dir(dir.as_ref(), 0o700)?;
    let dir = dir.as_ref();
    let log_path = dir.join(LOG_FILE);
    let log_bytes = match std::fs::metadata(&log_path) {
        Ok(meta) => meta.len(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => return Err(err),
    };
    let meta_path = dir.join(META_FILE);
    let backup_path = dir.join(META_BACKUP_FILE);
    let had_primary = meta_path.exists();
    let had_backup = backup_path.exists();
    // 先 backup 后 primary，与运行时持久化顺序一致；两步都写 0。
    rustboard_common::fsutil::atomic_write(&backup_path, b"0", META_MODE)?;
    rustboard_common::fsutil::atomic_write(&meta_path, b"0", META_MODE)?;
    Ok(BufferRepairReport {
        log_bytes,
        had_primary,
        had_backup,
    })
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

/// #34（双 meta / 中间损坏向前重同步 / repair）验收测试。
#[cfg(test)]
#[path = "buffer_v100_tests.rs"]
mod v100_tests;
