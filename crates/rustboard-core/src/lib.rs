//! 采集器与本地缓冲、存储实现。

pub mod buffer;
pub mod collect;
pub mod downsample;
pub mod storage;

pub use collect::Collector;
