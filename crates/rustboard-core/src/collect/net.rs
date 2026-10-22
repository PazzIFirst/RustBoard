//! 网卡采集：解析 `/proc/net/dev`。
//!
//! 上报的都是自开机以来的累计计数器，速率由 hub 侧按差值计算。

use rustboard_common::model::Sample;

use super::{labelled, Collector};

pub struct NetCollector {
    excluded: Vec<String>,
}

impl NetCollector {
    pub fn new(excluded: Vec<String>) -> Self {
        Self { excluded }
    }

    fn is_excluded(&self, iface: &str) -> bool {
        self.excluded.iter().any(|p| iface.starts_with(p.as_str()))
    }
}

impl Collector for NetCollector {
    fn name(&self) -> &'static str {
        "net"
    }

    fn collect(&self, ts: i64) -> Vec<Sample> {
        let Ok(text) = std::fs::read_to_string("/proc/net/dev") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for line in text.lines() {
            let Some((iface, rest)) = line.split_once(':') else {
                continue;
            };
            let iface = iface.trim();
            if iface.is_empty() || self.is_excluded(iface) {
                continue;
            }
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() < 16 {
                continue;
            }
            let n = |i: usize| f.get(i).and_then(|v| v.parse::<f64>().ok()).unwrap_or(0.0);

            out.push(labelled("net.rx_bytes", "if", iface, ts, n(0)));
            out.push(labelled("net.rx_packets", "if", iface, ts, n(1)));
            out.push(labelled("net.rx_errors", "if", iface, ts, n(2)));
            out.push(labelled("net.rx_drops", "if", iface, ts, n(3)));
            out.push(labelled("net.tx_bytes", "if", iface, ts, n(8)));
            out.push(labelled("net.tx_packets", "if", iface, ts, n(9)));
            out.push(labelled("net.tx_errors", "if", iface, ts, n(10)));
            out.push(labelled("net.tx_drops", "if", iface, ts, n(11)));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excludes_loopback_and_docker() {
        let c = NetCollector::new(vec!["lo".into(), "docker".into()]);
        assert!(c.is_excluded("lo"));
        assert!(c.is_excluded("docker0"));
        assert!(!c.is_excluded("eth0"));
    }
}
