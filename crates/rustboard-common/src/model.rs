use serde::{Deserialize, Serialize};

/// 指标标签集合。序列化顺序稳定，便于计算 label_hash。
pub type Labels = std::collections::BTreeMap<String, String>;

/// 单个采样点。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Sample {
    pub metric: String,
    pub labels: Labels,
    /// agent 侧墙钟时间，Unix 毫秒。
    pub ts: i64,
    pub value: f64,
}

impl Sample {
    pub fn new(metric: impl Into<String>, ts: i64, value: f64) -> Self {
        Self {
            metric: metric.into(),
            labels: Labels::new(),
            ts,
            value,
        }
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.insert(key.into(), value.into());
        self
    }

    /// 标签的稳定指纹，用于建索引与去重。
    pub fn label_hash(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        for (k, v) in &self.labels {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }
        hasher.finish()
    }
}

/// 一批采样点。seq 在同一个 epoch 内单调递增，hub 据此去重。
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SampleBatch {
    pub agent_id: String,
    /// agent 进程每次启动 +1（或用一个新时间戳），用于区分追加日志的断点。
    pub epoch: u64,
    /// epoch 内的批次序号，从 0 开始。
    pub seq: u64,
    pub boot_id: String,
    pub sent_at: i64,
    pub samples: Vec<Sample>,
}

impl SampleBatch {
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

/// hub 侧保存的 agent 元信息。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct AgentRecord {
    pub agent_id: String,
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub boot_id: String,
    pub status: String,
    pub last_seen_at: i64,
    pub created_at: i64,
}

impl Default for AgentRecord {
    fn default() -> Self {
        Self {
            agent_id: String::new(),
            name: String::new(),
            hostname: String::new(),
            os: String::new(),
            arch: String::new(),
            version: String::new(),
            boot_id: String::new(),
            status: "offline".to_string(),
            last_seen_at: 0,
            created_at: 0,
        }
    }
}

/// 一次时间序列查询。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeriesQuery {
    pub agent_id: String,
    pub metrics: Vec<String>,
    pub from: i64,
    pub to: i64,
    pub limit: u32,
}

/// 查询结果中的一行。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SeriesRow {
    pub metric: String,
    pub labels: Labels,
    pub ts: i64,
    pub value: f64,
}
