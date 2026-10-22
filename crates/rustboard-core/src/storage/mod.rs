//! 存储抽象。v1 先实现 SQLite，PostgreSQL 走同一套 SQL 子集。

pub mod sqlite;

use anyhow::Result;
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};

/// 审计记录保留时长：180 天（毫秒）。启动时与每 1000 条写入后按此清理。
pub const AUDIT_RETENTION_MS: i64 = 180 * 24 * 60 * 60 * 1000;

/// agent 上报的控制能力（schema v5 `agent_control` 表）。
///
/// 每次 Hello 后整行覆盖；断线不清空，面板仍可看到历史能力。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentControlRecord {
    /// 已知能力字符串（`systemd` / `docker` / `process` / `logs`），顺序与上报一致。
    pub capabilities: Vec<String>,
    /// 最后一次 Hello 的 hub 时间（毫秒）。
    pub updated_at: i64,
}

/// 一条待写入的审计记录（没有自增 `id`）。
///
/// `params` 只放 `target` / `pid` / `name` / `signal` / `lines`，
/// **绝不**写命令输出、日志内容或 agent 错误详情。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewAuditEntry {
    /// hub 时间（毫秒）。
    pub ts: i64,
    pub actor: String,
    pub agent_id: String,
    pub capability: String,
    pub action: String,
    /// systemd unit / 容器名 / 日志来源 id / 进程名。
    pub target: String,
    /// 参数 JSON，调用方负责限长。
    pub params: String,
    /// `ok` / `denied` / `error`。
    pub result: String,
    pub error_code: String,
    pub error_message: String,
    pub duration_ms: i64,
}

/// 一条审计记录。直接序列化给管理 API（面板页面只依赖其中的展示字段）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AuditEntry {
    /// 自增主键，同时是分页游标。
    pub id: i64,
    pub ts: i64,
    pub actor: String,
    pub agent_id: String,
    pub capability: String,
    pub action: String,
    pub target: String,
    pub params: String,
    pub result: String,
    pub error_code: String,
    pub error_message: String,
    pub duration_ms: i64,
}

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

    // ---- M3 控制面能力与审计 ----

    /// 覆盖写入 agent 上报的控制能力（Hello 后调用）。
    fn upsert_agent_control(
        &self,
        agent_id: &str,
        capabilities: &[String],
        updated_at: i64,
    ) -> Result<()>;

    /// 读取 agent 最近一次上报的控制能力；从未上报返回 `None`。
    fn get_agent_control(&self, agent_id: &str) -> Result<Option<AgentControlRecord>>;

    /// 写入一条审计记录，返回自增 id。
    ///
    /// 每 1000 条成功后按 [`AUDIT_RETENTION_MS`] 清理一次过期记录。
    fn insert_audit(&self, entry: &NewAuditEntry) -> Result<i64>;

    /// 按 id 倒序分页查询审计；`before_id` 为**排他**游标（`id < before_id`）。
    fn list_audit(
        &self,
        limit: usize,
        before_id: Option<i64>,
        agent_id: Option<&str>,
        capability: Option<&str>,
    ) -> Result<Vec<AuditEntry>>;

    /// 删除 `ts < before_ts` 的审计记录，返回删除行数。
    fn prune_audit(&self, before_ts: i64) -> Result<usize>;
}
