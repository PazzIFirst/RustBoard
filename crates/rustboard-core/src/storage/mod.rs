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

/// 一条管理 API scoped token 记录（schema v6 `api_tokens` 表）。
///
/// **不含明文、不含 token 哈希**：哈希只用于数据库内比对，不进入任何对外
/// 结构或日志。`scope` 以字符串保存，由 hub 侧映射成枚举；读取到非法值
/// 时按未认证处理。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiTokenRecord {
    /// 自增主键。
    pub id: i64,
    /// token 名称（运维可读，也是审计 actor）。
    pub name: String,
    /// `read` / `write` / `admin`。
    pub scope: String,
    /// 当前凭据创建时间（Unix 毫秒）；rotate 后更新为新凭据的创建时间。
    pub created_at: i64,
    /// 最近一次鉴权成功时间（Unix 毫秒）；从未使用为 `None`。
    pub last_used_at: Option<i64>,
    /// 吊销时间（Unix 毫秒）；未吊销为 `None`。吊销不删行。
    pub revoked_at: Option<i64>,
}

/// 一条维护水位记录（schema v7 `maintenance_state` 表）。
///
/// 用于保存降采样、保留期与归档任务的进度水位（例如 `last_archived_ts`）。
/// `value` 是字符串，编码由调用方约定；存储层只做原样读写。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceStateEntry {
    /// 水位键，例如 `last_archived_ts`。
    pub key: String,
    /// 水位值（字符串编码，便于后续扩展）。
    pub value: String,
    /// 最近一次写入时间（Unix 毫秒）。
    pub updated_at: i64,
}

/// 1m 聚合桶宽度（毫秒）：按 UTC 对齐的整分钟。
pub const BUCKET_1M_MS: i64 = 60_000;

/// 1h 聚合桶宽度（毫秒）：按 UTC 对齐的整点小时。
pub const BUCKET_1H_MS: i64 = 3_600_000;

/// 查询选中的数据层（M4-A2b）。
///
/// 上层的选层规则见方案 §5.2：短跨度查 raw，中跨度查 1m，长跨度查 1h。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleTier {
    /// 原始采样表 `samples`。
    Raw,
    /// 分钟聚合表 `samples_1m`。
    OneMinute,
    /// 小时聚合表 `samples_1h`。
    OneHour,
}

impl SampleTier {
    /// 对外 API 与日志里的层标识：`"raw"` / `"1m"` / `"1h"`。
    pub fn as_str(self) -> &'static str {
        match self {
            SampleTier::Raw => "raw",
            SampleTier::OneMinute => "1m",
            SampleTier::OneHour => "1h",
        }
    }

    /// 该层聚合桶的宽度（毫秒）：raw 为 1，1m 为 60_000，1h 为 3_600_000。
    pub fn granularity_ms(self) -> i64 {
        match self {
            SampleTier::Raw => 1,
            SampleTier::OneMinute => BUCKET_1M_MS,
            SampleTier::OneHour => BUCKET_1H_MS,
        }
    }

    /// 更粗的一层（Raw→1m→1h）；1h 已是最粗层，返回 `None`。
    ///
    /// 查询在所选层没有数据时可回退一层，但最多到 1h。
    pub fn next_coarser(self) -> Option<SampleTier> {
        match self {
            SampleTier::Raw => Some(SampleTier::OneMinute),
            SampleTier::OneMinute => Some(SampleTier::OneHour),
            SampleTier::OneHour => None,
        }
    }
}

/// 单次降采样聚合的结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct DownsampleRangeResult {
    /// 写入/更新的聚合桶数（按主键 upsert，重复执行同样计数）。
    pub buckets: usize,
    /// 参与本次聚合的源行数（raw 或 1m）。
    pub rows: usize,
}

/// 某一数据层（raw / 1m / 1h）的时间范围与总行数。
///
/// `oldest_ts` / `newest_ts` 为 `None` 表示该层没有数据；供维护状态与
/// 保留期/降采样的起点判断使用。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct TierStats {
    /// 总行数。
    pub rows: i64,
    /// 最旧时间戳（毫秒）。
    pub oldest_ts: Option<i64>,
    /// 最新时间戳（毫秒）。
    pub newest_ts: Option<i64>,
}

/// 按批删除过期行的结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct PruneResult {
    /// 删除的总行数。
    pub deleted: usize,
    /// 实际执行了删除的批次数（空批不计）。
    pub batches: usize,
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

    /// 按指定数据层做时间桶聚合查询（M4-A2b 查询选层）。
    ///
    /// - [`SampleTier::Raw`]：与 [`Storage::query_series_bucketed`] 行为一致；
    /// - [`SampleTier::OneMinute`] / [`SampleTier::OneHour`]：从降采样表读取，
    ///   `value` 按桶内原始样本数加权平均（`SUM(avg_value*count)/SUM(count)`），
    ///   不是各层均值的简单平均；
    /// - 只要聚合桶与 `[from, to]` 有重叠就纳入（`bucket_ts + 层粒度 > from`
    ///   且 `bucket_ts <= to`），返回桶起点；
    /// - 调用方应保证 `bucket_ms >= tier.granularity_ms()`，否则桶会比该层
    ///   粒度还细；`limit` 在聚合后生效。
    fn query_series_tiered(
        &self,
        query: &SeriesQuery,
        bucket_ms: i64,
        tier: SampleTier,
    ) -> Result<Vec<SeriesRow>>;

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

    // ---- M4 维护水位（schema v7） ----

    /// 读取维护水位；key 不存在返回 `None`。
    fn get_maintenance_state(&self, key: &str) -> Result<Option<String>>;

    /// 覆盖写入维护水位：不存在则插入，已存在则刷新 value 与 updated_at。
    fn set_maintenance_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()>;

    /// 列出全部维护水位，按 key 升序。
    fn list_maintenance_state(&self) -> Result<Vec<MaintenanceStateEntry>>;
}
