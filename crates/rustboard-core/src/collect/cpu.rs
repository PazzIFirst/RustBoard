//! CPU 与负载采集：解析 `/proc/stat` 与 `/proc/loadavg`。
//!
//! `/proc/stat` 给的是开机以来的累计值，必须做两次差分才有意义。

use std::io;
use std::sync::Mutex;

use rustboard_common::model::Sample;

use super::{labelled, point, Collector};

#[derive(Debug, Clone, Copy, Default)]
struct CpuTimes {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
}

impl CpuTimes {
    fn total(self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
    }

    fn busy(self) -> u64 {
        self.total().saturating_sub(self.idle + self.iowait)
    }

    fn delta(self, prev: CpuTimes) -> CpuTimes {
        CpuTimes {
            user: self.user.saturating_sub(prev.user),
            nice: self.nice.saturating_sub(prev.nice),
            system: self.system.saturating_sub(prev.system),
            idle: self.idle.saturating_sub(prev.idle),
            iowait: self.iowait.saturating_sub(prev.iowait),
            irq: self.irq.saturating_sub(prev.irq),
            softirq: self.softirq.saturating_sub(prev.softirq),
            steal: self.steal.saturating_sub(prev.steal),
        }
    }

    fn pct(self, part: u64) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            part as f64 * 100.0 / total as f64
        }
    }
}

/// 解析一行 `cpu ...`，返回累计时间片。
fn parse_times(line: &str) -> Option<CpuTimes> {
    let mut it = line.split_whitespace();
    let _name = it.next()?;
    // 老内核字段更少，缺的按 0 处理
    let mut vals = [0u64; 8];
    for slot in vals.iter_mut() {
        *slot = it.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
    }
    Some(CpuTimes {
        user: vals[0],
        nice: vals[1],
        system: vals[2],
        idle: vals[3],
        iowait: vals[4],
        irq: vals[5],
        softirq: vals[6],
        steal: vals[7],
    })
}

fn read_stat() -> io::Result<(CpuTimes, Vec<CpuTimes>)> {
    let text = std::fs::read_to_string("/proc/stat")?;
    let mut total = CpuTimes::default();
    let mut cores = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("cpu ") {
            if let Some(t) = parse_times(&format!("cpu {rest}")) {
                total = t;
            }
        } else if let Some(rest) = line.strip_prefix("cpu") {
            // cpu0, cpu1 ...
            if rest.starts_with(|c: char| c.is_ascii_digit()) {
                if let Some(t) = parse_times(line) {
                    cores.push(t);
                }
            }
        }
    }
    Ok((total, cores))
}

pub struct CpuCollector {
    per_core: bool,
    prev: Mutex<Option<(CpuTimes, Vec<CpuTimes>)>>,
}

impl CpuCollector {
    pub fn new(per_core: bool) -> Self {
        Self {
            per_core,
            prev: Mutex::new(None),
        }
    }
}

impl Collector for CpuCollector {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn collect(&self, ts: i64) -> Vec<Sample> {
        let (total, cores) = match read_stat() {
            Ok(v) => v,
            Err(err) => {
                tracing::debug!(error = %err, "读取 /proc/stat 失败");
                return Vec::new();
            }
        };

        let mut guard = match self.prev.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        let result = match guard.as_ref() {
            None => Vec::new(),
            Some((prev_total, prev_cores)) => {
                let d = total.delta(*prev_total);
                let mut samples = vec![
                    point("cpu.usage", ts, d.pct(d.busy())),
                    point("cpu.user", ts, d.pct(d.user + d.nice)),
                    point("cpu.system", ts, d.pct(d.system + d.irq + d.softirq)),
                    point("cpu.iowait", ts, d.pct(d.iowait)),
                    point("cpu.steal", ts, d.pct(d.steal)),
                    point("cpu.idle", ts, d.pct(d.idle)),
                ];
                if self.per_core {
                    for (idx, core) in cores.iter().enumerate() {
                        let prev = prev_cores.get(idx).copied().unwrap_or_default();
                        let cd = core.delta(prev);
                        samples.push(labelled(
                            "cpu.cores.usage",
                            "core",
                            &idx.to_string(),
                            ts,
                            cd.pct(cd.busy()),
                        ));
                    }
                }
                samples.extend(load_samples(ts));
                samples
            }
        };

        *guard = Some((total, cores));
        result
    }
}

fn load_samples(ts: i64) -> Vec<Sample> {
    let Ok(text) = std::fs::read_to_string("/proc/loadavg") else {
        return Vec::new();
    };
    let mut it = text.split_whitespace();
    let mut out = Vec::new();
    for metric in ["load.1", "load.5", "load.15"] {
        if let Some(v) = it.next().and_then(|v| v.parse::<f64>().ok()) {
            out.push(point(metric, ts, v));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_line() {
        let t = parse_times("cpu  100 2 30 400 5 0 0 0").unwrap();
        assert_eq!(t.user, 100);
        assert_eq!(t.system, 30);
        assert_eq!(t.idle, 400);
        assert_eq!(t.total(), 537);
    }

    #[test]
    fn delta_saturates_on_reset() {
        let a = CpuTimes {
            user: 50,
            ..Default::default()
        };
        let b = CpuTimes {
            user: 10,
            ..Default::default()
        };
        assert_eq!(b.delta(a).user, 0);
    }
}
