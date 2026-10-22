//! 存储抽象。v1 先实现 SQLite，PostgreSQL 走同一套 SQL 子集。

pub mod sqlite;

use anyhow::Result;
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};

/// 一批数据的写入结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestOutcome {
    /// 正常写入，`inserted` 为本次新增的采样点数。
    Inserted { inserted: usize },
    /// 同一 `(agent_id, epoch, seq)` 已处理过，整批跳过。
    Duplicate,
    /// 批次被拒绝，不写入任何数据。
    Rejected(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// agent 已被吊销。
    Revoked,
}

/// 查询结果达到存储层的行数硬上限。
///
/// 单独定义成类型而不是普通 `anyhow!` 字符串，是为了让 HTTP 层能把它映射成
/// `413 query_too_large`，而不是被统一当成 500 内部错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryTooLarge {
    /// 触发的行数上限。
    pub limit: usize,
}

impl std::fmt::Display for QueryTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "查询结果达到 {} 行上限，请缩小时间窗口或指标范围",
            self.limit
        )
    }
}

impl std::error::Error for QueryTooLarge {}

/// 一台 agent 的一组序列（metric + labels）的最新采样点。
///
/// 与 [`SeriesRow`] 的区别是带上 `agent_id`：`latest_samples` 一次可以跨多台
/// agent 查询（`overview` 用），Rust 侧按 `(agent_id, metric, labels)` 去重。
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AgentSeriesRow {
    pub agent_id: String,
    pub metric: String,
    pub labels: Labels,
    pub ts: i64,
    pub value: f64,
}

pub trait Storage: Send + Sync {
    /// 插入或更新 agent 元信息。
    fn upsert_agent(&self, agent: &AgentRecord) -> Result<()>;

    /// 刷新在线状态与最后活跃时间。
    fn mark_seen(&self, agent_id: &str, ts: i64) -> Result<()>;

    /// 修改状态（online / offline / revoked / pending）。
    fn set_status(&self, agent_id: &str, status: &str, ts: i64) -> Result<()>;

    /// hub 启动时把上次遗留的 `online` 状态清成 `offline`，返回受影响行数。
    ///
    /// 进程异常退出时来不及走会话清理，数据库里会残留 online；监听前重置，
    /// 避免面板长期显示假在线。`revoked` 不受影响。
    fn reset_online_status(&self) -> Result<usize>;

    /// 写入一批采样点，按 `(agent_id, epoch, seq)` 幂等。
    ///
    /// 已吊销 agent 的批次始终返回 `Rejected(Revoked)`，且不写入任何数据。
    fn insert_batch(&self, batch: &SampleBatch) -> Result<IngestOutcome>;

    fn list_agents(&self) -> Result<Vec<AgentRecord>>;

    fn get_agent(&self, agent_id: &str) -> Result<Option<AgentRecord>>;

    fn query_series(&self, query: &SeriesQuery) -> Result<Vec<SeriesRow>>;

    /// 按时间桶聚合查询：`GROUP BY metric, labels, ts / bucket_ms`，取 `AVG(value)`。
    ///
    /// 返回点的 `ts` 是桶起点；空桶不补点。`query.limit` 在聚合后生效，
    /// 供上层用「多取一条」的方式判断点数是否超限。
    fn query_series_bucketed(&self, query: &SeriesQuery, bucket_ms: i64) -> Result<Vec<SeriesRow>>;

    /// 取 `since` 之后、指定指标（空表示全部）的最新点。
    ///
    /// 按 `(agent_id, metric, labels)` 去重并保留最大 `ts`；`agent` 为 `None`
    /// 时跨全部 agent 查询。返回顺序稳定（agent_id、metric、labels 升序）。
    fn latest_samples(
        &self,
        since: i64,
        metrics: &[String],
        agent: Option<&str>,
    ) -> Result<Vec<AgentSeriesRow>>;

    /// 读取 agent 的显式采样间隔；没有配置过返回 `None`（上层回退配置默认值）。
    fn get_sample_interval(&self, agent_id: &str) -> Result<Option<u64>>;

    /// 写入/更新 agent 的采样间隔。
    fn set_sample_interval(&self, agent_id: &str, ms: u64, now: i64) -> Result<()>;

    /// 列出所有显式配置过采样间隔的 agent（按 agent_id 升序）。
    fn list_sample_intervals(&self) -> Result<Vec<(String, u64)>>;

    fn sample_count(&self, agent_id: &str) -> Result<i64>;

    // ---- 纳管与吊销 ----

    /// 写入一条一次性 enrollment token（只存哈希）。
    fn create_enroll_token(
        &self,
        token_hash: &str,
        name: &str,
        created_at: i64,
        expires_at: i64,
    ) -> Result<()>;

    /// 消费 token，返回它绑定的名字。已用过或过期返回 None。
    fn consume_enroll_token(&self, token_hash: &str, now: i64) -> Result<Option<String>>;

    /// 保存 agent 的长期密钥哈希。
    fn set_agent_secret(&self, agent_id: &str, secret_hash: &str, created_at: i64) -> Result<()>;

    fn verify_agent_secret(&self, agent_id: &str, secret_hash: &str) -> Result<bool>;

    fn revoke_agent(&self, agent_id: &str, ts: i64) -> Result<()>;

    fn is_revoked(&self, agent_id: &str) -> Result<bool>;
}
