//! 指标采集器。全部走 `/proc` 与 `statvfs`，不依赖外部命令。

pub mod cpu;
pub mod disk;
pub mod mem;
pub mod net;
pub mod sys;

use rustboard_common::model::{Labels, Sample};

/// 一个采集器负责一类指标。
pub trait Collector: Send + Sync {
    fn name(&self) -> &'static str;
    /// 采集一次。返回空表示本次无有效数据（例如首次调用缺少基线）。
    fn collect(&self, ts: i64) -> Vec<Sample>;
}

/// 组装默认采集器集合。
pub fn default_collectors(per_core: bool, excluded_interfaces: &[String]) -> Vec<Box<dyn Collector>> {
    vec![
        Box::new(cpu::CpuCollector::new(per_core)),
        Box::new(mem::MemCollector),
        Box::new(disk::DiskUsageCollector),
        Box::new(disk::DiskIoCollector::new()),
        Box::new(net::NetCollector::new(excluded_interfaces.to_vec())),
        Box::new(sys::SysCollector),
    ]
}

/// 构造一个无标签采样点。
pub(crate) fn point(metric: &str, ts: i64, value: f64) -> Sample {
    Sample::new(metric, ts, value)
}

/// 构造一个单标签采样点。
pub(crate) fn labelled(
    metric: &str,
    key: &str,
    value: &str,
    ts: i64,
    sample_value: f64,
) -> Sample {
    let mut sample = Sample::new(metric, ts, sample_value);
    let mut labels = Labels::new();
    labels.insert(key.to_string(), value.to_string());
    sample.labels = labels;
    sample
}
