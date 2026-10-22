//! 存储抽象。v1 先实现 SQLite，PostgreSQL 走同一套 SQL 子集。

pub mod sqlite;

use anyhow::Result;
use rustboard_common::model::{AgentRecord, SampleBatch, SeriesQuery, SeriesRow};

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
