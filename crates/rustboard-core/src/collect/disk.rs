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

fn read_diskstats() -> HashMap<String, IoCounters> {
    let mut map = HashMap::new();
    let Ok(text) = std::fs::read_to_string("/proc/diskstats") else {
        return map;
    };
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
                write_ops: n(7),
                write_sectors: n(9),
                io_ms: n(12),
            },
        );
    }
    map
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
                let d_ops = (cur.read_ops + cur.write_ops)
                    .saturating_sub(old.read_ops + old.write_ops)
                    as f64;
                let d_ms = cur.io_ms.saturating_sub(old.io_ms) as f64;
                if d_ops > 0.0 {
                    out.push(labelled("diskio.await_ms", "dev", key, ts, d_ms / d_ops));
                }
                out.push(labelled(
                    "diskio.util",
                    "dev",
                    key,
                    ts,
                    (d_ms / elapsed * 100.0).min(100.0),
                ));
            }
        }

        *prev = current;
        *prev_ts = Some(ts);
        out
    }
}
