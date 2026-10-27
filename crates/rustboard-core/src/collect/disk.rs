//! 磁盘采集：容量走 `/proc/mounts` + `statvfs`，IO 走 `/proc/diskstats`。

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::sync::Mutex;

use rustboard_common::model::Sample;

use super::{labelled, Collector};

/// 这些文件系统不计入容量统计：要么是虚拟的，要么和别的挂载点重复。
const SKIP_FS: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "cgroup",
    "cgroup2",
    "overlay",
    "squashfs",
    "nsfs",
    "rpc_pipefs",
    "autofs",
    "securityfs",
    "debugfs",
    "tracefs",
    "pstore",
    "bpf",
    "configfs",
    "fusectl",
    "mqueue",
    "hugetlbfs",
    "efivarfs",
    "binfmt_misc",
    "ramfs",
];

/// `/proc/mounts` 里的字段带八进制转义（空格是 `\040`，反斜杠是 `\134`）。
///
/// 按字节解码并返回字节：内核转义的是原始路径字节，逐字节 `as char`
/// 会把 0x80..=0xFF 重新编码成多字节 UTF-8，破坏非 ASCII 路径。
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if field[i] == b'\\' && i + 3 < field.len() {
            let digits = &field[i + 1..i + 4];
            if digits.iter().all(|b| (b'0'..=b'7').contains(b)) {
                let value = digits
                    .iter()
                    .fold(0u16, |acc, b| acc * 8 + u16::from(b - b'0'));
                // 三位八进制最大 0o777，超出 u8 的不是内核生成的转义；
                // 保守地按普通文本原样保留，不做有损截断。
                if let Ok(byte) = u8::try_from(value) {
                    out.push(byte);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(field[i]);
        i += 1;
    }
    out
}

/// `/proc/mounts` 的一行。路径保留原始字节，可能不是合法 UTF-8。
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    dev: OsString,
    mount: OsString,
    fs: String,
}

/// 解析 `/proc/mounts` 内容。抽成纯函数，便于用已知样例做单测。
fn parse_mounts(data: &[u8]) -> Vec<MountEntry> {
    data.split(|b| *b == b'\n')
        .filter_map(|line| {
            let mut fields = line
                .split(|b| b.is_ascii_whitespace())
                .filter(|f| !f.is_empty());
            let dev = unescape(fields.next()?);
            let mount = unescape(fields.next()?);
            let fs = String::from_utf8_lossy(fields.next()?).into_owned();
            Some(MountEntry {
                dev: OsString::from_vec(dev),
                mount: OsString::from_vec(mount),
                fs,
            })
        })
        .collect()
}

fn read_mounts() -> Vec<MountEntry> {
    // 按字节读：挂载路径本身可以包含非法 UTF-8，`read_to_string` 会整份失败。
    match std::fs::read("/proc/mounts") {
        Ok(data) => parse_mounts(&data),
        Err(_) => Vec::new(),
    }
}

fn statvfs(path: &OsStr) -> Option<libc::statvfs> {
    let c = CString::new(path.as_bytes()).ok()?;
    // SAFETY: statvfs 是纯输出结构，先零初始化再交给 libc 填写。
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c 以 NUL 结尾，且在本调用期间一直存活。
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc == 0 {
        Some(st)
    } else {
        None
    }
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

fn push_hex_escape(out: &mut String, byte: u8) {
    out.push('\\');
    out.push('x');
    out.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
    out.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
}

fn push_valid_text(out: &mut String, text: &str) {
    for ch in text.chars() {
        if ch == '\\' {
            // 反斜杠也转义，否则合法路径里的字面量 `\xFF` 会和非法字节混淆。
            out.push_str("\\\\");
        } else {
            out.push(ch);
        }
    }
}

/// 把原始路径字节编码为唯一、可逆的 label。
///
/// 合法 UTF-8 原样保留（`\` 写成 `\\`），非法字节写成 `\xNN`。
/// 不能直接用 `to_string_lossy`：不同非法路径都会变成 U+FFFD，导致多个挂载点
/// 合并成同一条指标序列。
fn path_label(path: &OsStr) -> String {
    let bytes = path.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                push_valid_text(&mut out, valid);
                break;
            }
            Err(err) => {
                let valid_len = err.valid_up_to();
                let valid = std::str::from_utf8(&rest[..valid_len])
                    .expect("valid_up_to 保证前缀是合法 UTF-8");
                push_valid_text(&mut out, valid);
                let bad_len = err.error_len().unwrap_or(rest.len() - valid_len);
                for &byte in &rest[valid_len..valid_len + bad_len] {
                    push_hex_escape(&mut out, byte);
                }
                rest = &rest[valid_len + bad_len..];
                if rest.is_empty() {
                    break;
                }
            }
        }
    }
    out
}

/// 磁盘已用百分比：`(total - free) / total * 100`，夹在 0..=100。
///
/// 与 `disk.used` 使用同一个 `(total - free)`，保证两个指标口径一致；
/// `total` 非正或非有限值时返回 `None`，不产生除零 / NaN 样本。
fn used_percent(total: f64, free: f64) -> Option<f64> {
    if !total.is_finite() || !free.is_finite() || total <= 0.0 {
        return None;
    }
    Some(((total - free) / total * 100.0).clamp(0.0, 100.0))
}

/// 挂载点容量与 inode 使用率。
pub struct DiskUsageCollector;

impl Collector for DiskUsageCollector {
    fn name(&self) -> &'static str {
        "disk"
    }

    fn collect(&self, ts: i64) -> Vec<Sample> {
        let mut out = Vec::new();
        for MountEntry { dev, mount, fs } in read_mounts() {
            if SKIP_FS.contains(&fs.as_str()) {
                continue;
            }
            let Some(st) = statvfs(&mount) else {
                continue;
            };
            let frsize = if st.f_frsize > 0 {
                st.f_frsize
            } else {
                st.f_bsize
            };
            let total = st.f_blocks.saturating_mul(frsize) as f64;
            let free = st.f_bfree.saturating_mul(frsize) as f64;
            let avail = st.f_bavail.saturating_mul(frsize) as f64;
            if total == 0.0 {
                continue;
            }

            // label 必须是 UTF-8：非法字节写成唯一的 `\xNN`，避免不同路径因
            // U+FFFD 合并；合法路径（含中文）保持原样。
            let mount_label = path_label(&mount);
            let dev_label = path_label(&dev);
            let mount_label = mount_label.as_str();
            let dev_label = dev_label.as_str();
            let fs_label = fs.as_str();
            out.push(
                labelled("disk.total", "mount", mount_label, ts, total)
                    .with_label("fs", fs_label)
                    .with_label("dev", dev_label),
            );
            out.push(
                labelled(
                    "disk.used",
                    "mount",
                    mount_label,
                    ts,
                    (total - free).max(0.0),
                )
                .with_label("fs", fs_label),
            );
            // M4-B1：每个 mount 的已用百分比，labels 与 disk.used 一致。
            if let Some(percent) = used_percent(total, free) {
                out.push(
                    labelled("disk.used_percent", "mount", mount_label, ts, percent)
                        .with_label("fs", fs_label),
                );
            }
            out.push(
                labelled("disk.avail", "mount", mount_label, ts, avail.max(0.0))
                    .with_label("fs", fs_label),
            );

            let inodes_total = st.f_files as f64;
            if inodes_total > 0.0 {
                out.push(labelled(
                    "disk.inode.used",
                    "mount",
                    mount_label,
                    ts,
                    (st.f_files - st.f_ffree) as f64,
                ));
                out.push(labelled(
                    "disk.inode.total",
                    "mount",
                    mount_label,
                    ts,
                    inodes_total,
                ));
            }
        }
        out
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct IoCounters {
    read_ops: u64,
    write_ops: u64,
    read_sectors: u64,
    write_sectors: u64,
    /// 读请求累计耗时（/proc/diskstats 第 7 个字段，f[6]）。
    read_ticks: u64,
    /// 写请求累计耗时（/proc/diskstats 第 11 个字段，f[10]）。
    write_ticks: u64,
    /// 设备有 IO 在进行的累计时间（f[12]），只用于 util。
    io_ms: u64,
}

/// 每个设备的 IO 累计计数器，附带由差分得到的 await / util。
pub struct DiskIoCollector {
    prev: Mutex<(HashMap<String, IoCounters>, Option<i64>)>,
}

impl Default for DiskIoCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DiskIoCollector {
    pub fn new() -> Self {
        Self {
            prev: Mutex::new((HashMap::new(), None)),
        }
    }
}

/// 这些设备名不是真实磁盘，统计进去只会重复计数。
fn skip_device(name: &str) -> bool {
    ["loop", "ram", "zram", "sr", "fd", "dm-", "md"]
        .iter()
        .any(|p| name.starts_with(p))
}

/// 解析 `/proc/diskstats` 文本。抽成纯函数，便于用已知样例做单测。
fn parse_diskstats(text: &str) -> HashMap<String, IoCounters> {
    let mut map = HashMap::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 14 {
            continue;
        }
        let name = f[2].to_string();
        if skip_device(&name) {
            continue;
        }
        let n = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        map.insert(
            name,
            IoCounters {
                read_ops: n(3),
                read_sectors: n(5),
                read_ticks: n(6),
                write_ops: n(7),
                write_sectors: n(9),
                write_ticks: n(10),
                io_ms: n(12),
            },
        );
    }
    map
}

fn read_diskstats() -> HashMap<String, IoCounters> {
    match std::fs::read_to_string("/proc/diskstats") {
        Ok(text) => parse_diskstats(&text),
        Err(_) => HashMap::new(),
    }
}

/// 平均请求耗时 = (Δread_ticks + Δwrite_ticks) / (Δread_ops + Δwrite_ops)。
///
/// `io_ms` 是设备忙碌时间，不能用来算单请求耗时；它只参与 `diskio.util`。
/// 任一计数器回退（驱动重置 / 设备消失后重现 / 计数器回绕）都放弃本帧，
/// 不能像旧实现那样只比较读数之和——那会把「只有 read_ticks 回退」漏过去。
fn await_ms(old: &IoCounters, cur: &IoCounters) -> Option<f64> {
    if cur.read_ops < old.read_ops
        || cur.read_ticks < old.read_ticks
        || cur.write_ops < old.write_ops
        || cur.write_ticks < old.write_ticks
    {
        return None;
    }

    let d_ops = (cur.read_ops - old.read_ops) + (cur.write_ops - old.write_ops);
    if d_ops == 0 {
        return None;
    }
    let d_ticks = (cur.read_ticks - old.read_ticks) + (cur.write_ticks - old.write_ticks);
    Some(d_ticks as f64 / d_ops as f64)
}

impl Collector for DiskIoCollector {
    fn name(&self) -> &'static str {
        "diskio"
    }

    fn collect(&self, ts: i64) -> Vec<Sample> {
        let current = read_diskstats();
        if current.is_empty() {
            return Vec::new();
        }

        let mut guard = match self.prev.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let (prev, prev_ts) = &mut *guard;
        let elapsed_ms = prev_ts.map(|p| (ts - p).max(1) as f64);

        let mut out = Vec::new();
        for (name, cur) in &current {
            let key = name.as_str();
            // 原始计数器：原样上报，重启归零由 hub 侧结转
            out.push(labelled(
                "diskio.read_bytes",
                "dev",
                key,
                ts,
                (cur.read_sectors * 512) as f64,
            ));
            out.push(labelled(
                "diskio.write_bytes",
                "dev",
                key,
                ts,
                (cur.write_sectors * 512) as f64,
            ));
            out.push(labelled(
                "diskio.read_ops",
                "dev",
                key,
                ts,
                cur.read_ops as f64,
            ));
            out.push(labelled(
                "diskio.write_ops",
                "dev",
                key,
                ts,
                cur.write_ops as f64,
            ));

            if let (Some(old), Some(elapsed)) = (prev.get(name), elapsed_ms) {
                if let Some(avg_await) = await_ms(old, cur) {
                    out.push(labelled("diskio.await_ms", "dev", key, ts, avg_await));
                }
                // util 语义不变：设备忙碌时间 / 采样间隔。
                let d_io_ms = cur.io_ms.saturating_sub(old.io_ms) as f64;
                out.push(labelled(
                    "diskio.util",
                    "dev",
                    key,
                    ts,
                    (d_io_ms / elapsed * 100.0).min(100.0),
                ));
            }
        }

        *prev = current;
        *prev_ts = Some(ts);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// issue #8 的已知两帧计数器样例。
    const PREV: &str = "8 0 sda 100 0 0 1000 50 0 0 500 0 1200 0";
    const CURR: &str = "8 0 sda 110 0 0 1500 60 0 0 1000 0 1600 0";

    #[test]
    fn issue_8_parse_diskstats_reads_ticks() {
        let prev = parse_diskstats(PREV);
        let cur = parse_diskstats(CURR);
        let p = prev.get("sda").unwrap();
        assert_eq!((p.read_ops, p.write_ops), (100, 50));
        assert_eq!((p.read_ticks, p.write_ticks), (1000, 500));
        assert_eq!(p.io_ms, 1200);

        let c = cur.get("sda").unwrap();
        assert_eq!((c.read_ops, c.write_ops), (110, 60));
        assert_eq!((c.read_ticks, c.write_ticks), (1500, 1000));
        assert_eq!(c.io_ms, 1600);
    }

    #[test]
    fn issue_8_await_ms_matches_known_sample() {
        let prev = parse_diskstats(PREV);
        let cur = parse_diskstats(CURR);
        // (500 + 500) / (10 + 10) = 50ms；旧公式 io_ticks 差分只能得到 20ms
        assert_eq!(await_ms(&prev["sda"], &cur["sda"]), Some(50.0));
        // util 仍基于 io_ticks 差分，行为不变
        assert_eq!(cur["sda"].io_ms - prev["sda"].io_ms, 400);
    }

    #[test]
    fn issue_8_await_ms_skips_zero_request_delta() {
        let prev = parse_diskstats(PREV);
        let cur = parse_diskstats(PREV);
        assert_eq!(await_ms(&prev["sda"], &cur["sda"]), None);
    }

    #[test]
    fn issue_8_await_ms_high_and_low_concurrency() {
        // 高并发：请求数翻倍但 ticks 增长 3 倍，平均耗时 20ms；io_ticks 差分不参与
        let high_prev = IoCounters {
            read_ops: 1_000,
            write_ops: 1_000,
            read_ticks: 10_000,
            write_ticks: 10_000,
            ..IoCounters::default()
        };
        let high_cur = IoCounters {
            read_ops: 2_000,
            write_ops: 2_000,
            read_ticks: 30_000,
            write_ticks: 30_000,
            ..IoCounters::default()
        };
        assert_eq!(await_ms(&high_prev, &high_cur), Some(20.0));

        // 低并发：单个请求耗时 7ms
        let low_prev = IoCounters::default();
        let low_cur = IoCounters {
            read_ops: 1,
            read_ticks: 7,
            ..IoCounters::default()
        };
        assert_eq!(await_ms(&low_prev, &low_cur), Some(7.0));
    }

    #[test]
    fn issue_8_await_ms_handles_counter_reset() {
        let prev = parse_diskstats(CURR);
        let cur = parse_diskstats(PREV);
        assert_eq!(await_ms(&prev["sda"], &cur["sda"]), None);
    }

    /// L4：只有 read_ticks 回退、其它计数器都在增长时，也不能输出负差分样本。
    #[test]
    fn l4_await_ms_rejects_any_single_counter_regression() {
        let prev = IoCounters {
            read_ops: 1_000,
            write_ops: 1_000,
            read_ticks: 10_000,
            write_ticks: 10_000,
            ..IoCounters::default()
        };
        let only_read_ticks_regressed = IoCounters {
            read_ops: 1_100,
            write_ops: 1_100,
            read_ticks: 9_000,
            write_ticks: 12_000,
            ..IoCounters::default()
        };
        // 旧实现把 read_ticks/write_ticks 加总后做 saturating_sub，
        // 会得到 1000 ticks 的“正常”结果；逐项检查必须返回 None。
        assert_eq!(await_ms(&prev, &only_read_ticks_regressed), None);

        // 其余三个计数器各自单独回退时同样拒绝。
        let all_forward = IoCounters {
            read_ops: 1_100,
            write_ops: 1_100,
            read_ticks: 12_000,
            write_ticks: 12_000,
            ..IoCounters::default()
        };
        let read_ops_regressed = IoCounters {
            read_ops: 900,
            ..all_forward
        };
        assert_eq!(await_ms(&prev, &read_ops_regressed), None);
        let write_ops_regressed = IoCounters {
            write_ops: 900,
            ..all_forward
        };
        assert_eq!(await_ms(&prev, &write_ops_regressed), None);
        let write_ticks_regressed = IoCounters {
            write_ticks: 9_000,
            ..all_forward
        };
        assert_eq!(await_ms(&prev, &write_ticks_regressed), None);
    }

    #[test]
    fn issue_8_parse_diskstats_skips_virtual_devices() {
        let text = "7 0 loop0 1 0 0 1 1 0 0 1 0 2 0\n8 0 sda 100 0 0 1000 50 0 0 500 0 1200 0";
        let map = parse_diskstats(text);
        assert!(!map.contains_key("loop0"));
        assert!(map.contains_key("sda"));
    }

    /// M4-B1：`disk.used_percent` 与 `disk.used` 同口径（total-free），并有界。
    #[test]
    fn m4_b1_used_percent_matches_disk_used_and_is_bounded() {
        // 100 GiB 总量，用掉 40 GiB → 40%。
        assert_eq!(used_percent(100.0, 60.0), Some(40.0));
        assert_eq!(used_percent(100.0, 0.0), Some(100.0));
        assert_eq!(used_percent(100.0, 100.0), Some(0.0));
        // 与 disk.used 的分子一致：used = total - free = 25。
        let (total, free) = (100.0, 75.0);
        assert_eq!(total - free, 25.0);
        assert_eq!(used_percent(total, free), Some(25.0));

        // 坏输入不产生 NaN / 除零 / 越界样本。
        assert_eq!(used_percent(0.0, 0.0), None);
        assert_eq!(used_percent(-1.0, 0.0), None);
        assert_eq!(used_percent(f64::NAN, 0.0), None);
        assert_eq!(used_percent(100.0, f64::INFINITY), None);
        // free > total（异常文件系统）夹到 0，而不是负数。
        assert_eq!(used_percent(100.0, 120.0), Some(0.0));
        // free 为负（异常）夹到 100。
        assert_eq!(used_percent(100.0, -20.0), Some(100.0));
    }

    /// #35：八进制转义必须还原成原始字节，不能逐字节 `as char`。
    #[test]
    fn issue_35_unescape_decodes_octal_as_bytes() {
        assert_eq!(unescape(b"/mnt/data"), b"/mnt/data");
        assert_eq!(unescape("中文路径".as_bytes()), "中文路径".as_bytes());
        assert_eq!(unescape(b"/mnt/my\\040disk"), b"/mnt/my disk");
        assert_eq!(unescape(b"/mnt/back\\134slash"), b"/mnt/back\\slash");
        // 内核把非 ASCII 字节转义成 \ooo；必须还原成同一串 UTF-8 字节。
        assert_eq!(
            unescape(b"/mnt/\\344\\270\\255\\346\\226\\207"),
            "/mnt/中文".as_bytes()
        );
        // 混合：原样 UTF-8、八进制中文、空格、反斜杠。
        assert_eq!(
            unescape(b"/mnt/\\344\\270\\255\\346\\226\\207\\040a\\134b\\040raw"),
            "/mnt/中文 a\\b raw".as_bytes()
        );
        // 无效 / 不完整转义保持原样，不越界也不做有损截断。
        assert_eq!(unescape(b"/mnt/\\777"), b"/mnt/\\777");
        assert_eq!(unescape(b"/mnt/\\04"), b"/mnt/\\04");
        assert_eq!(unescape(b"/mnt/\\"), b"/mnt/\\");
    }

    /// #35：解析保留原始字节，label 用唯一、可逆的 `\xNN` 编码。
    #[test]
    fn issue_35_parse_mounts_preserves_bytes() {
        let data = b"/dev/sda1 /mnt/\\040data\\134x ext4 rw 0 0\n\
                     proc /proc proc rw 0 0\n\
                     none /mnt/\xff\xfe xfs rw 0 0\n";
        let entries = parse_mounts(data);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].dev, OsString::from("/dev/sda1"));
        assert_eq!(entries[0].mount, OsString::from("/mnt/ data\\x"));
        assert_eq!(entries[0].fs, "ext4");
        assert_eq!(entries[1].mount, OsString::from("/proc"));
        // 反斜杠按可逆规则写成 `\\`。
        assert_eq!(path_label(&entries[0].mount), r"/mnt/ data\\x");
        // 无效 UTF-8 路径按原始字节保留，label 逐字节转义，不塌缩成 U+FFFD。
        assert_eq!(entries[2].mount.as_bytes(), b"/mnt/\xff\xfe");
        let label = path_label(&entries[2].mount);
        assert_eq!(label, r"/mnt/\xFF\xFE");
        assert!(!label.contains('\u{fffd}'));
    }

    /// #35：非法字节 label 必须唯一且可逆，两个不同路径不能合并。
    #[test]
    fn issue_35_path_label_is_reversible_and_unique() {
        fn decode(label: &str) -> Vec<u8> {
            let bytes = label.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] != b'\\' {
                    let text = std::str::from_utf8(&bytes[i..]).expect("普通部分是合法 UTF-8");
                    let ch = text.chars().next().expect("非空");
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    i += ch.len_utf8();
                } else if bytes.get(i + 1) == Some(&b'\\') {
                    out.push(b'\\');
                    i += 2;
                } else {
                    assert_eq!(bytes.get(i + 1), Some(&b'x'), "未知 label 转义");
                    assert!(i + 4 <= bytes.len(), "label 转义不完整");
                    let hex = std::str::from_utf8(&bytes[i + 2..i + 4]).expect("十六进制是 ASCII");
                    out.push(u8::from_str_radix(hex, 16).expect("合法十六进制"));
                    i += 4;
                }
            }
            out
        }

        let invalid = OsString::from_vec(b"/mnt/\xff\xfe".to_vec());
        assert_eq!(path_label(&invalid), r"/mnt/\xFF\xFE");
        assert!(!path_label(&invalid).contains('\u{fffd}'));

        // 合法文本里的字面量 "\xFF" 不能被误认成非法字节。
        let literal = OsString::from("/mnt/\\xFF");
        assert_eq!(path_label(&literal), r"/mnt/\\xFF");
        assert_ne!(path_label(&invalid), path_label(&literal));
        assert_eq!(decode(&path_label(&literal)), literal.as_bytes());

        // 中文、反斜杠、非法字节混合时仍可逆。
        let mut raw = "目录/".as_bytes().to_vec();
        raw.push(b'\\');
        raw.push(0xff);
        raw.push(0x01);
        let mixed = OsString::from_vec(raw.clone());
        assert_eq!(decode(&path_label(&mixed)), raw);
        assert!(path_label(&mixed).starts_with("目录/\\\\"));

        // 不同的非法字节不能合并成同一序列。
        let a = OsString::from_vec(b"/mnt/\xff".to_vec());
        let b = OsString::from_vec(b"/mnt/\xfe".to_vec());
        assert_ne!(path_label(&a), path_label(&b));

        // 截断的多字节 UTF-8 也是非法字节，逐字节转义。
        let truncated = OsString::from_vec(b"/mnt/\xe4\xb8".to_vec());
        assert_eq!(path_label(&truncated), r"/mnt/\xE4\xB8");
        assert_eq!(decode(&path_label(&truncated)), b"/mnt/\xe4\xb8");
    }

    /// #35：真实 UTF-8 / 无效 UTF-8 目录都能 statvfs，不 panic。
    #[test]
    fn issue_35_statvfs_accepts_utf8_and_invalid_utf8_paths() {
        fn temp_dir(name: OsString) -> std::path::PathBuf {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("时钟早于 UNIX_EPOCH")
                .as_nanos();
            let mut name = name;
            name.push(format!("-{}-{nanos}", std::process::id()));
            let dir = std::env::temp_dir().join(name);
            std::fs::create_dir(&dir).expect("创建临时目录");
            dir
        }

        let utf8 = temp_dir(OsString::from("rustboard-磁盘-采集"));
        let st = statvfs(utf8.as_os_str());
        let _ = std::fs::remove_dir(&utf8);
        assert!(
            st.expect("真实 UTF-8 目录应能 statvfs").f_blocks > 0,
            "临时目录所在文件系统应报告容量"
        );

        let mut invalid_name = OsString::from("rustboard-invalid-");
        invalid_name.push(OsString::from_vec(vec![0xff, 0xfe]));
        let invalid = temp_dir(invalid_name);
        let st = statvfs(invalid.as_os_str());
        let label = path_label(invalid.as_os_str());
        let _ = std::fs::remove_dir(&invalid);
        assert!(
            st.expect("无效 UTF-8 目录应能 statvfs").f_blocks > 0,
            "原始字节路径应直接传给 libc"
        );
        assert!(label.contains(r"\xFF\xFE"));
        assert!(!label.contains('\u{fffd}'));
    }
}
