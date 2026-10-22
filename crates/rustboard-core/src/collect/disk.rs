//! 磁盘采集：容量走 `/proc/mounts` + `statvfs`，IO 走 `/proc/diskstats`。

use std::collections::HashMap;
use std::ffi::CString;
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

/// `/proc/mounts` 里的字段带八进制转义（空格是 `\040`）。
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = String::with_capacity(field.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let oct = &field[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(oct, 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn read_mounts() -> Vec<(String, String, String)> {
    let Ok(text) = std::fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut it = line.split_whitespace();
            let dev = it.next()?;
            let mount = it.next()?;
            let fs = it.next()?;
            Some((unescape(dev), unescape(mount), fs.to_string()))
        })
        .collect()
}

fn statvfs(path: &str) -> Option<libc::statvfs> {
    let c = CString::new(path).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc == 0 {
        Some(st)
    } else {
        None
    }
}

/// 挂载点容量与 inode 使用率。
pub struct DiskUsageCollector;

impl Collector for DiskUsageCollector {
    fn name(&self) -> &'static str {
        "disk"
    }

    fn collect(&self, ts: i64) -> Vec<Sample> {
        let mut out = Vec::new();
        for (dev, mount, fs) in read_mounts() {
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

            let mount_label = mount.as_str();
            let fs_label = fs.as_str();
            out.push(
                labelled("disk.total", "mount", mount_label, ts, total)
                    .with_label("fs", fs_label)
                    .with_label("dev", dev.as_str()),
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
}
