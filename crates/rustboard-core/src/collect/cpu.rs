//! CPU 与负载采集：解析 `/proc/stat` 与 `/proc/loadavg`。
//!
//! `/proc/stat` 给的是开机以来的累计值，必须做两次差分才有意义。

use std::collections::BTreeMap;
use std::io;
use std::sync::Mutex;

use rustboard_common::model::Sample;

use super::{labelled, point, Collector};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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

    /// 任一字段小于上一帧即视为计数回退。
    ///
    /// CPU 热插拔会让 `/proc/stat` 的汇总累计值下降；此时饱和差分会把整段
    /// 回退量丢掉，算出一个虚假的高占用，必须重建基线而不是上报。
    fn regressed(self, prev: CpuTimes) -> bool {
        self.user < prev.user
            || self.nice < prev.nice
            || self.system < prev.system
            || self.idle < prev.idle
            || self.iowait < prev.iowait
            || self.irq < prev.irq
            || self.softirq < prev.softirq
            || self.steal < prev.steal
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

/// 解析 `/proc/stat` 内容，保留每个 `cpuN` 的实际 N。
///
/// 核心编号在 CPU 热插拔后可能稀疏，绝不能拿 Vec 下标当核心 ID。
fn parse_stat(text: &str) -> (CpuTimes, Vec<(u32, CpuTimes)>) {
    let mut total = CpuTimes::default();
    let mut cores = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("cpu ") {
            if let Some(t) = parse_times(&format!("cpu {rest}")) {
                total = t;
            }
        } else if let Some(rest) = line.strip_prefix("cpu") {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 {
                // cpufreq 之类不是核心行。
                continue;
            }
            // 数字后必须是空白或行尾，避免把 cpufoo 当成核心。
            if rest
                .as_bytes()
                .get(digits)
                .is_some_and(|b| !b.is_ascii_whitespace())
            {
                continue;
            }
            let Ok(id) = rest[..digits].parse::<u32>() else {
                continue;
            };
            if let Some(t) = parse_times(line) {
                cores.push((id, t));
            }
        }
    }
    (total, cores)
}

fn read_stat() -> io::Result<(CpuTimes, Vec<(u32, CpuTimes)>)> {
    let text = std::fs::read_to_string("/proc/stat")?;
    Ok(parse_stat(&text))
}

pub struct CpuCollector {
    per_core: bool,
    prev: Mutex<Option<(CpuTimes, BTreeMap<u32, CpuTimes>)>>,
}

impl CpuCollector {
    pub fn new(per_core: bool) -> Self {
        Self {
            per_core,
            prev: Mutex::new(None),
        }
    }
}

/// 推进基线并生成样本；返回 `None` 表示本帧只重建基线、不下发样本。
///
/// 首帧只建基线；汇总计数出现回退（CPU 热插拔）时整帧跳过并重建基线，
/// 避免饱和差分产生虚假的高占用。新上线的核心本帧同样只建基线；
/// 单核计数回退只跳过该核心，已下线的核心在新基线中被整体移除。
fn advance(
    state: &mut Option<(CpuTimes, BTreeMap<u32, CpuTimes>)>,
    total: CpuTimes,
    cores: &[(u32, CpuTimes)],
    ts: i64,
    per_core: bool,
) -> Option<Vec<Sample>> {
    let Some((prev_total, prev_cores)) = state.as_mut() else {
        *state = Some((total, cores.iter().copied().collect()));
        return None;
    };

    if total.regressed(*prev_total) {
        // 汇总计数回退：整帧基数已变，重建全部基线并跳过本帧。
        *prev_total = total;
        *prev_cores = cores.iter().copied().collect();
        return None;
    }

    let d = total.delta(*prev_total);
    let mut samples = vec![
        point("cpu.usage", ts, d.pct(d.busy())),
        point("cpu.user", ts, d.pct(d.user + d.nice)),
        point("cpu.system", ts, d.pct(d.system + d.irq + d.softirq)),
        point("cpu.iowait", ts, d.pct(d.iowait)),
        point("cpu.steal", ts, d.pct(d.steal)),
        point("cpu.idle", ts, d.pct(d.idle)),
    ];
    if per_core {
        for &(id, cur) in cores {
            let Some(old) = prev_cores.get(&id) else {
                // 新上线的核心：首帧只建基线，本帧不下发 0 / 假值。
                continue;
            };
            if cur.regressed(*old) {
                // 单核计数回退：本帧跳过该核心，帧末会把它写成新基线。
                continue;
            }
            let cd = cur.delta(*old);
            samples.push(labelled(
                "cpu.cores.usage",
                "core",
                &id.to_string(),
                ts,
                cd.pct(cd.busy()),
            ));
        }
    }

    *prev_total = total;
    // 整体替换：新增核心写入基线，下线核心自然移除。
    *prev_cores = cores.iter().copied().collect();
    Some(samples)
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

        let mut samples = {
            let mut guard = match self.prev.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let Some(samples) = advance(&mut guard, total, &cores, ts, self.per_core) else {
                // 首帧或汇总计数回退：只重建基线，本帧无 CPU/load 样本。
                return Vec::new();
            };
            samples
        };
        samples.extend(load_samples(ts));
        samples
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

    /// 生成 `idle` + `busy` 两个字段的累计时间片（busy 记在 user）。
    fn times(idle: u64, busy: u64) -> CpuTimes {
        CpuTimes {
            user: busy,
            idle,
            ..CpuTimes::default()
        }
    }

    fn core_sample(samples: &[Sample], id: u32) -> Option<&Sample> {
        samples.iter().find(|s| {
            s.metric == "cpu.cores.usage"
                && s.labels.get("core").and_then(|v| v.parse::<u32>().ok()) == Some(id)
        })
    }

    fn core_ids(samples: &[Sample]) -> Vec<u32> {
        let mut ids: Vec<u32> = samples
            .iter()
            .filter(|s| s.metric == "cpu.cores.usage")
            .filter_map(|s| s.labels.get("core")?.parse::<u32>().ok())
            .collect();
        ids.sort_unstable();
        ids
    }

    fn total_metric_count(samples: &[Sample]) -> usize {
        samples
            .iter()
            .filter(|s| s.metric.starts_with("cpu.") && !s.metric.starts_with("cpu.cores."))
            .count()
    }

    /// #36：稀疏的 cpu0/2/4 必须保留实际编号，不能按下标重排。
    #[test]
    fn issue_36_parse_stat_keeps_sparse_core_ids() {
        let text = "\
cpu  1000 0 1000 8000 0 0 0 0
cpu0 100 0 100 800 0 0 0 0
cpu2 200 0 200 600 0 0 0 0
cpu4 300 0 300 400 0 0 0 0
cpufreq 1 2 3
intr 0 0 0
";
        let (total, cores) = parse_stat(text);
        assert_eq!(total.user, 1000);
        assert_eq!(total.idle, 8000);
        assert_eq!(
            cores.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            vec![0, 2, 4]
        );
        assert_eq!(cores[1].1.user, 200);
        assert_eq!(cores[2].1.idle, 400);
    }

    /// #36：cpu1 下线后 cpu2 仍按自己的基线算 10%，而不是错配成 100%。
    #[test]
    fn issue_36_cpu_hotplug_does_not_shift_core_ids() {
        let mut state = None;
        // 第一帧只建基线：cpu1 的 idle 远大于 cpu2，旧按下标差分正是这样错配的。
        let frame1 = vec![
            (0, times(100, 100)),
            (1, times(10_000, 0)),
            (2, times(0, 1_000)),
        ];
        assert!(advance(&mut state, times(20_000, 1_000), &frame1, 1_000, true).is_none());

        // 第二帧 cpu1 下线；cpu2 自身 idle +900 / busy +100 → 10%。
        let frame2 = vec![(0, times(200, 200)), (2, times(900, 1_100))];
        let samples = advance(&mut state, times(21_000, 2_000), &frame2, 2_000, true)
            .expect("非首帧必须有样本");
        assert_eq!(
            core_sample(&samples, 2).map(|s| s.value),
            Some(10.0),
            "cpu2 必须按自己的上一帧差分"
        );
        assert!(
            core_sample(&samples, 1).is_none(),
            "离线的 cpu1 不应再有样本"
        );
        assert_eq!(core_ids(&samples), vec![0, 2]);
        assert_eq!(total_metric_count(&samples), 6, "总数指标条数不受插拔影响");
        // 基线中已移除 cpu1。
        let (_, prev_cores) = state.as_ref().expect("基线存在");
        assert_eq!(prev_cores.keys().copied().collect::<Vec<_>>(), vec![0, 2]);

        // 第三帧 cpu1 恢复：首帧只建基线，cpu0/2 继续正常输出。
        let frame3 = vec![
            (0, times(300, 300)),
            (1, times(10_100, 100)),
            (2, times(1_800, 1_200)),
        ];
        let samples = advance(&mut state, times(22_000, 3_000), &frame3, 3_000, true)
            .expect("非首帧必须有样本");
        assert!(
            core_sample(&samples, 1).is_none(),
            "恢复的核心首帧只建基线，不下发假值"
        );
        assert_eq!(core_ids(&samples), vec![0, 2]);
        assert_eq!(total_metric_count(&samples), 6);

        // 第四帧 cpu1 用恢复后的基线差分，标签仍是实际 ID。
        let frame4 = vec![
            (0, times(400, 400)),
            (1, times(10_200, 200)),
            (2, times(2_700, 1_300)),
        ];
        let samples = advance(&mut state, times(23_000, 4_000), &frame4, 4_000, true)
            .expect("非首帧必须有样本");
        let cpu1 = core_sample(&samples, 1).expect("cpu1 恢复后应重新上报");
        assert_eq!(cpu1.labels.get("core").map(String::as_str), Some("1"));
        assert_eq!(cpu1.value, 50.0);
        assert_eq!(core_ids(&samples), vec![0, 1, 2]);
        assert_eq!(total_metric_count(&samples), 6);
        // 总数指标口径不变：本帧总差分 idle +1000 / busy +1000。
        let usage = samples
            .iter()
            .find(|s| s.metric == "cpu.usage")
            .expect("必须有总数 cpu.usage");
        assert_eq!(usage.value, 50.0);
    }

    /// #36：汇总计数任一字段回退都必须重建基线并跳过整帧。
    #[test]
    fn issue_36_total_regression_rebuilds_baseline() {
        let prev = CpuTimes {
            user: 100,
            nice: 100,
            system: 100,
            idle: 100,
            iowait: 100,
            irq: 100,
            softirq: 100,
            steal: 100,
        };
        assert!(!prev.regressed(prev), "相同读数不算回退");

        macro_rules! assert_field_regresses {
            ($field:ident) => {{
                let mut current = prev;
                current.$field = 99;
                assert!(
                    current.regressed(prev),
                    concat!(stringify!($field), " 回退必须被检测")
                );
            }};
        }
        assert_field_regresses!(user);
        assert_field_regresses!(nice);
        assert_field_regresses!(system);
        assert_field_regresses!(idle);
        assert_field_regresses!(iowait);
        assert_field_regresses!(irq);
        assert_field_regresses!(softirq);
        assert_field_regresses!(steal);

        let mut state = None;
        let frame1 = vec![(0, times(100, 100))];
        assert!(advance(&mut state, times(20_000, 1_000), &frame1, 1, true).is_none());

        // 模拟核心下线：汇总 idle 回退、busy 上升；旧饱和差分会算出虚高占用。
        let frame2 = vec![(0, times(200, 200))];
        let skipped = advance(&mut state, times(19_000, 2_000), &frame2, 2, true);
        assert!(skipped.is_none(), "汇总计数回退必须跳过整帧");
        // 基线已重建为回退后的读数。
        let (prev_total, prev_cores) = state.as_ref().expect("基线存在");
        assert_eq!(prev_total.idle, 19_000);
        assert_eq!(prev_cores.get(&0).copied(), Some(times(200, 200)));

        // 下一帧从新基线差分：idle +1000 / busy +1000 → 50%，不是假 100%。
        let frame3 = vec![(0, times(300, 300))];
        let samples = advance(&mut state, times(20_000, 3_000), &frame3, 3, true)
            .expect("回退后的下一帧应恢复上报");
        let usage = samples
            .iter()
            .find(|s| s.metric == "cpu.usage")
            .expect("必须有总数 cpu.usage");
        assert_eq!(usage.value, 50.0);
        assert_eq!(core_sample(&samples, 0).map(|s| s.value), Some(50.0));
    }

    /// #36：单核计数回退只跳过该核，其他核与下一帧不受影响。
    #[test]
    fn issue_36_core_regression_skips_only_that_core() {
        let mut state = None;
        let frame1 = vec![(0, times(100, 100)), (1, times(100, 100))];
        assert!(advance(&mut state, times(10_000, 0), &frame1, 1, true).is_none());

        // cpu1 idle 回退（busy 仍增长），旧饱和差分会造出假高占用。
        let frame2 = vec![(0, times(200, 200)), (1, times(50, 150))];
        let samples = advance(&mut state, times(20_000, 100), &frame2, 2, true)
            .expect("汇总正常时不应整帧跳过");
        assert_eq!(core_sample(&samples, 0).map(|s| s.value), Some(50.0));
        assert!(core_sample(&samples, 1).is_none(), "回退核心本帧不下发");
        assert_eq!(core_ids(&samples), vec![0]);
        assert_eq!(total_metric_count(&samples), 6);

        // 下一帧 cpu1 从回退后的新基线差分，而不是旧值。
        let frame3 = vec![(0, times(300, 300)), (1, times(150, 250))];
        let samples =
            advance(&mut state, times(30_000, 200), &frame3, 3, true).expect("非首帧必须有样本");
        assert_eq!(core_sample(&samples, 1).map(|s| s.value), Some(50.0));
        assert_eq!(core_ids(&samples), vec![0, 1]);
    }

    /// #36：关闭 per-core 采集时不应产生核心样本，总数指标仍完整。
    #[test]
    fn issue_36_per_core_disabled_emits_no_core_samples() {
        let mut state = None;
        assert!(advance(&mut state, times(10, 10), &[(0, times(1, 1))], 1, false).is_none());
        let samples = advance(&mut state, times(20, 20), &[(0, times(2, 2))], 2, false)
            .expect("非首帧必须有样本");
        assert!(core_ids(&samples).is_empty());
        assert_eq!(total_metric_count(&samples), 6);
    }
}
