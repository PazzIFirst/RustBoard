//! 内存与 Swap 采集：解析 `/proc/meminfo`。

use rustboard_common::model::Sample;

use super::{point, Collector};

/// 从 `/proc/meminfo` 读一个以 kB 为单位的字段，转成字节。
fn kb_field(text: &str, key: &str) -> Option<f64> {
    let prefix = format!("{key}:");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&prefix) {
            let value = rest.split_whitespace().next()?.parse::<f64>().ok()?;
            return Some(value * 1024.0);
        }
    }
    None
}

pub struct MemCollector;

impl Collector for MemCollector {
    fn name(&self) -> &'static str {
        "mem"
    }

    fn collect(&self, ts: i64) -> Vec<Sample> {
        let Ok(text) = std::fs::read_to_string("/proc/meminfo") else {
            return Vec::new();
        };

        let total = kb_field(&text, "MemTotal").unwrap_or(0.0);
        let available = kb_field(&text, "MemAvailable")
            .or_else(|| kb_field(&text, "MemFree"))
            .unwrap_or(0.0);
        let cached = kb_field(&text, "Cached").unwrap_or(0.0);
        let buffers = kb_field(&text, "Buffers").unwrap_or(0.0);
        let swap_total = kb_field(&text, "SwapTotal").unwrap_or(0.0);
        let swap_free = kb_field(&text, "SwapFree").unwrap_or(0.0);

        let used = (total - available).max(0.0);

        vec![
            point("mem.total", ts, total),
            point("mem.used", ts, used),
            point("mem.available", ts, available),
            point("mem.cached", ts, cached),
            point("mem.buffers", ts, buffers),
            point("swap.total", ts, swap_total),
            point("swap.used", ts, (swap_total - swap_free).max(0.0)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_meminfo() {
        let text = "MemTotal:       16384000 kB\nMemFree:         1000000 kB\nMemAvailable:    8000000 kB\nCached:          2000000 kB\nBuffers:          100000 kB\nSwapTotal:       2000000 kB\nSwapFree:        1500000 kB\n";
        assert_eq!(kb_field(text, "MemTotal"), Some(16384000.0 * 1024.0));
        assert_eq!(kb_field(text, "Nope"), None);
    }
}
