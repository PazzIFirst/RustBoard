//! 系统级辅助指标：开机时长、进程数。

use rustboard_common::model::Sample;

use super::{point, Collector};

pub struct SysCollector;

impl Collector for SysCollector {
    fn name(&self) -> &'static str {
        "sys"
    }

    fn collect(&self, ts: i64) -> Vec<Sample> {
        let mut out = Vec::new();

        if let Ok(text) = std::fs::read_to_string("/proc/uptime") {
            if let Some(secs) = text
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
            {
                out.push(point("sys.uptime", ts, secs));
                out.push(point("sys.boot_time", ts, ts as f64 - secs * 1000.0));
            }
        }

        // /proc/loadavg 最后一个字段是 "running/total"
        if let Ok(text) = std::fs::read_to_string("/proc/loadavg") {
            if let Some(tail) = text.split_whitespace().nth(3) {
                if let Some(total) = tail.split('/').nth(1).and_then(|v| v.parse::<f64>().ok()) {
                    out.push(point("sys.procs", ts, total));
                }
            }
        }

        out
    }
}
