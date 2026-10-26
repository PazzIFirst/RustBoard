//! 存储抽象。
//!
//! [`Storage`] 是同步 trait，SQLite 与 PostgreSQL 共用同一接口。PG 驱动是
//! 同步网络 I/O，**本层不做运行时适配，也不自动把调用搬离 tokio worker**。
//! 唯一受支持的调用路径是调用方在 hub 的 `spawn_blocking` 中执行，或走独立的
//! blocking CLI 线程/进程；在 tokio worker 内直接调用 PG 方法会 panic
//! （`Cannot start a runtime from within a runtime`）。
//!
//! [`StorageHandle`] 是 Phase D 引入的多后端边界：内部是 `Arc<dyn Storage>`，
//! 可构造 SQLite 或 PostgreSQL；调用点只依赖 [`Deref`] 后的 trait 方法。

pub mod migrate;
pub mod postgres;
pub mod sqlite;

use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use rustboard_common::model::{AgentRecord, Labels, SampleBatch, SeriesQuery, SeriesRow};

use self::postgres::PostgresStorage;
use self::sqlite::{AlertSeriesSnapshot, ArchiveRawRow, SqliteStorage};
use crate::alerts::{AlertEvent, AlertRule, AlertSilence, AlertState};
use crate::archive::{ArchiveObject, ArchiveStatus};
use crate::channels::NotificationChannel;

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

/// R1b：一批 1m 增量聚合（raw → samples_1m）的结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct DownsampleDeltaResult {
    /// 本次写入/合并的 1m 聚合桶数。
    pub buckets: usize,
    /// 本次认领并标记 `aggregated_1m=1` 的 raw 行数。
    pub rows: usize,
    /// 本批处理的排他上界（整分钟，且不晚于调用方传入的 `closed_end`）。
    pub processed_to: i64,
}

/// R1b：一个整点小时的 1h 重算结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct DownsampleHourResult {
    /// 被重算的整点小时起点。
    pub hour_ts: i64,
    /// 写入/更新的 1h 聚合桶数。
    pub buckets: usize,
    /// 锁定并参与重算的 1m 源行数。
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
    /// 批次数据非法（字符串含 NUL，或采样值不是有限浮点数）。
    Invalid,
}

/// 批次是否含有不能落库的数据；非法时返回 [`RejectReason::Invalid`]。
///
/// 检查项：`agent_id`、`metric`、labels 的 key/value 是否含 NUL 字符，以及
/// 采样值是否为有限浮点数（拒绝 NaN / ±Inf）。SQLite 与 PostgreSQL 的
/// `insert_batch` 都在开启事务之前调用本函数，命中后整批拒绝、不写任何行。
pub(crate) fn invalid_batch(batch: &SampleBatch) -> Option<RejectReason> {
    if batch.agent_id.contains('\0') {
        return Some(RejectReason::Invalid);
    }
    for sample in &batch.samples {
        if sample.metric.contains('\0') || !sample.value.is_finite() {
            return Some(RejectReason::Invalid);
        }
        for (key, value) in &sample.labels {
            if key.contains('\0') || value.contains('\0') {
                return Some(RejectReason::Invalid);
            }
        }
    }
    None
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

/// 同步存储接口：SQLite 实现见 [`sqlite::SqliteStorage`]。
///
/// 所有方法都是同步阻塞调用。PostgreSQL 的同步网络 I/O **不会**被本层自动
/// 搬到 blocking 线程：调用方必须在 hub 的 `spawn_blocking` 或 blocking CLI
/// 路径中调用（在 tokio worker 内直接调用会 panic）。因此这里不加 `async`，
/// 保持 `dyn Storage` 可用。
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
    /// 已吊销 agent 的批次始终返回 `Rejected(Revoked)`；含 NUL 字符或非有限
    /// 数值（NaN / ±Inf）的批次返回 `Rejected(Invalid)`。两种拒绝都不写入任何
    /// 数据。
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

    // ---- M4-B1 告警规则（schema v7 `alert_rules`） ----

    /// 写入内置规则种子；按 id 已存在则跳过，重复调用幂等，返回新增条数。
    fn seed_builtin_alert_rules(&self, rules: &[AlertRule], now: i64) -> Result<usize>;

    /// 按 id 读取规则；不存在返回 `None`。
    fn get_alert_rule(&self, id: &str) -> Result<Option<AlertRule>>;

    /// 列出全部规则：内置在前，同组按名称升序。
    fn list_alert_rules(&self) -> Result<Vec<AlertRule>>;

    /// 规则总数（含内置规则）。
    fn alert_rule_count(&self) -> Result<usize>;

    /// 新建规则；达到上限或名称重复返回领域错误。
    fn create_alert_rule(&self, rule: &AlertRule) -> Result<()>;

    /// 更新规则的可写字段；不清理 `alert_states`。
    fn update_alert_rule(&self, rule: &AlertRule) -> Result<()>;

    /// 与 `update_alert_rule` 相同，并在同一事务内清空该规则的状态。
    fn update_alert_rule_and_clear_states(&self, rule: &AlertRule) -> Result<()>;

    /// 删除自定义规则；内置规则拒绝删除。
    fn delete_alert_rule(&self, id: &str) -> Result<()>;

    /// 与 `delete_alert_rule` 相同，并在同一事务内清空该规则的状态。
    fn delete_alert_rule_and_clear_states(&self, id: &str) -> Result<()>;

    // ---- M4-B1b 告警状态 / 事件 / 静默（schema v7） ----

    /// 列出全部告警状态，按主键稳定排序。
    fn list_alert_states(&self) -> Result<Vec<AlertState>>;

    /// 按主键读取告警状态；不存在返回 `None`。
    fn get_alert_state(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
    ) -> Result<Option<AlertState>>;

    /// 插入或整行更新告警状态。
    fn upsert_alert_state(&self, state: &AlertState) -> Result<()>;

    /// 删除告警状态，返回受影响行数（0 = 本来不存在）。
    fn delete_alert_state(&self, rule_id: &str, agent_id: &str, series_key: &str) -> Result<usize>;

    /// 只清理 `resolved` 且 `last_eval_at < resolved_before` 的状态。
    fn prune_alert_states(&self, resolved_before: i64) -> Result<usize>;

    /// 分页清理陈旧的 pending / firing 状态，`max_rows` 限制单次删除量。
    fn prune_stale_alert_states(&self, stale_before: i64, max_rows: usize) -> Result<usize>;

    /// 插入告警事件，返回自增 id。
    fn insert_alert_event(&self, event: &AlertEvent) -> Result<i64>;

    /// 按 id 倒序分页列出事件；`before_id` 为排他游标。
    fn list_alert_events(&self, limit: usize, before_id: Option<i64>) -> Result<Vec<AlertEvent>>;

    /// 按时间清理事件，并只保留最近 `max_rows` 行。
    fn prune_alert_events(&self, before_ts: i64, max_rows: usize) -> Result<usize>;

    /// 创建静默，返回自增 id；生效中数量有上限。
    fn create_alert_silence(&self, silence: &AlertSilence) -> Result<i64>;

    /// 列出 `now` 时刻仍生效的静默。
    fn list_active_silences(&self, now: i64) -> Result<Vec<AlertSilence>>;

    /// 删除静默；`false` 表示 id 不存在。
    fn delete_alert_silence(&self, id: i64) -> Result<bool>;

    /// 清理到期静默。
    fn prune_alert_silences(&self, before_ts: i64) -> Result<usize>;

    /// 列出启用的规则（评估引擎使用）。
    fn list_enabled_alert_rules(&self) -> Result<Vec<AlertRule>>;

    /// 按最近更新时间读取指定规则至多 `limit` 条状态。
    fn list_alert_states_for_rule(&self, rule_id: &str, limit: usize) -> Result<Vec<AlertState>>;

    /// 每规则只保留最近 `keep` 条状态，返回删除行数。
    fn prune_alert_states_for_rule(&self, rule_id: &str, keep: usize) -> Result<usize>;

    /// 告警评估专用的 raw-only 最新序列快照；达到 `limit` 时截断并标记。
    ///
    /// `filter_labels` 是精确子集：序列的 labels 必须包含其中每一对。过滤在
    /// `ROW_NUMBER` / 排序 / `LIMIT` **之前**完成，因此截断只作用于匹配的序列，
    /// 不会因为大量不相关序列先占满上限而漏掉目标序列。
    fn latest_alert_series(
        &self,
        metric: &str,
        since: i64,
        agent: Option<&str>,
        filter_labels: &Labels,
        limit: usize,
    ) -> Result<AlertSeriesSnapshot>;

    /// 单事务批量落库事件与状态（先事件后状态，at-least-once）。
    fn apply_alert_transitions(&self, events: &[AlertEvent], states: &[AlertState]) -> Result<()>;

    /// 单事务落库事件、状态与每规则状态上限清理，返回淘汰行数。
    fn apply_alert_evaluation(
        &self,
        rule_id: &str,
        events: &[AlertEvent],
        states: &[AlertState],
        keep_states: usize,
    ) -> Result<usize>;

    /// 当前最大告警事件 id；没有事件返回 0。
    fn max_alert_event_id(&self) -> Result<i64>;

    /// 通知队列：取 `id > after_id` 且未通知、未静默的事件。
    fn list_pending_notification_events_after(
        &self,
        after_id: i64,
        limit: usize,
    ) -> Result<Vec<AlertEvent>>;

    /// 标记事件已处理并保留固定原因（如 `no_channel`）。
    fn mark_notification_processed(&self, id: i64, notify_error: &str) -> Result<bool>;

    /// 通知队列：未通知且未静默的事件，按 id 升序。
    fn list_pending_notification_events(&self, limit: usize) -> Result<Vec<AlertEvent>>;

    /// 记录通知结果；成功时清空错误信息。
    fn mark_notification_result(&self, id: i64, notified: bool, notify_error: &str)
        -> Result<bool>;

    /// 只更新状态的 `last_notified_at`，不整行覆盖。
    fn update_alert_state_notified(
        &self,
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
        last_notified_at: i64,
    ) -> Result<bool>;

    // ---- M4-B2 通知渠道（schema v7 `notification_channels`） ----

    /// 列出全部渠道（含 secret，仅限 hub 内部使用），按名称升序。
    fn list_notification_channels(&self) -> Result<Vec<NotificationChannel>>;

    /// 按 id 读取渠道；不存在返回 `None`。
    fn get_notification_channel(&self, id: &str) -> Result<Option<NotificationChannel>>;

    /// 渠道总数。
    fn notification_channel_count(&self) -> Result<usize>;

    /// 新建渠道；达到上限、重名或配置非法返回领域错误。
    fn create_notification_channel(&self, channel: &NotificationChannel) -> Result<()>;

    /// 更新渠道的可写字段；`created_at` 保持原值。
    fn update_notification_channel(&self, channel: &NotificationChannel) -> Result<()>;

    /// 删除渠道；仍被规则引用时返回 `InUse`。
    fn delete_notification_channel(&self, id: &str) -> Result<()>;

    // ---- M6 管理 API scoped token（schema v6 `api_tokens`） ----

    /// 新建 scoped token（只存哈希）；重名或非法 scope 在落库前拒绝。
    fn create_api_token(
        &self,
        name: &str,
        token_hash: &str,
        scope: &str,
        created_at: i64,
    ) -> Result<ApiTokenRecord>;

    /// 按 name 升序列出全部 token（含已吊销），不返回哈希或明文。
    fn list_api_tokens(&self) -> Result<Vec<ApiTokenRecord>>;

    /// 轮换 token：写入新哈希、清除吊销并重置使用时间。
    fn rotate_api_token(&self, name: &str, token_hash: &str, now: i64) -> Result<ApiTokenRecord>;

    /// 吊销 token，只写 `revoked_at`，不删行。
    fn revoke_api_token(&self, name: &str, now: i64) -> Result<()>;

    /// 鉴权：只返回未吊销 token，并节流更新 `last_used_at`。
    fn authenticate_api_token(&self, token_hash: &str, now: i64) -> Result<Option<ApiTokenRecord>>;

    // ---- M4 降采样 / 保留期 / 维护水位（schema v7） ----

    /// 把 `[from_ts, to_ts)` 内已关闭分钟的 raw 聚合进 1m，按主键 upsert 幂等。
    ///
    /// **R1b 起只供既有测试/工具构造聚合行使用**；维护 worker 使用增量认领的
    /// [`Storage::downsample_1m_delta`]，不会走这里，避免与 delta 重复计数。
    fn downsample_1m_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult>;

    /// 把完整整点的 1m 聚合进 1h（按 `count` 加权平均），幂等。
    ///
    /// **R1b 起只供既有测试/工具构造聚合行使用**；维护 worker 使用带锁的
    /// [`Storage::downsample_1h_hour`]。
    fn downsample_1h_range(&self, from_ts: i64, to_ts: i64) -> Result<DownsampleRangeResult>;

    /// R1b：认领并增量合并一批未聚合 raw 到 1m。
    ///
    /// 选 `aggregated_1m=0 AND ts >= 0 AND ts < closed_end` 的 raw，按
    /// `(ts, rowid/id)` 升序取至多 `max_rows` 行；若第 `max_rows` 行落在某个
    /// 分钟桶内，则该桶整桶纳入（桶不可拆分），因此实际行数可能略超上限。
    ///
    /// 单写事务内完成：delta 合并进已有 1m 桶、把源 raw 所在**整小时**的
    /// 所有 1m 行置 `aggregated_1h=0`、再以
    /// `UPDATE ... WHERE 行键 IN (...) AND aggregated_1m=0` 标记 raw；affected
    /// 必须等于选中行数，否则回滚。返回 `processed_to` 是本批的分钟对齐上界。
    fn downsample_1m_delta(
        &self,
        closed_end: i64,
        max_rows: usize,
    ) -> Result<DownsampleDeltaResult>;

    /// R1b：锁定并重算最早一个可重算整点小时的 1h。
    ///
    /// 只选 `aggregated_1h=0`、`bucket_ts < closed_hour`、且该小时之前没有
    /// 未聚合 raw（`aggregated_1m=0`）的整点。单写事务内锁定该小时全部 1m
    /// 行（PG 用 `SELECT ... FOR UPDATE`），按 `count` 加权重算整小时，再把
    /// 该小时所有 1m 行置 `aggregated_1h=1`；affected 必须等于锁定行数，否则
    /// 回滚。没有可重算小时返回 `None`。
    fn downsample_1h_hour(&self, closed_hour: i64) -> Result<Option<DownsampleHourResult>>;

    /// 未聚合 raw 行数（`aggregated_1m=0`），供 `maintenance status` 使用。
    fn count_unaggregated_raw_rows(&self) -> Result<i64>;

    /// `ts < min_ts OR ts > max_ts` 的 raw 行数（旧超界时间戳审计）。
    fn count_raw_rows_outside(&self, min_ts: i64, max_ts: i64) -> Result<i64>;

    /// `ts < min_ts OR ts > max_ts` 且仍未聚合的 raw 行数。
    fn count_unaggregated_raw_rows_outside(&self, min_ts: i64, max_ts: i64) -> Result<i64>;

    /// `ts < before_ts` 且仍未聚合的 raw 行数（legacy 1m horizon 审计）。
    fn count_unaggregated_raw_rows_before(&self, before_ts: i64) -> Result<i64>;

    /// 把超界时间戳的未聚合 raw 标记为 `aggregated_1m=1` 隔离，返回标记行数。
    ///
    /// 分批执行，不删除任何行；隔离后 delta 不会再为这些行构造残缺 1m。
    fn isolate_raw_rows_outside(&self, min_ts: i64, max_ts: i64) -> Result<usize>;

    /// raw 层行数与最旧 / 最新时间戳。
    fn raw_stats(&self) -> Result<TierStats>;

    /// 1m 层行数与最旧 / 最新时间戳。
    fn samples_1m_stats(&self) -> Result<TierStats>;

    /// 1h 层行数与最旧 / 最新时间戳。
    fn samples_1h_stats(&self) -> Result<TierStats>;

    /// 取 raw 区间内按 `(ts, rowid)` 升序的第 `offset` 条时间戳（分块用）。
    fn raw_ts_at_offset(&self, from_ts: i64, to_ts: i64, offset: usize) -> Result<Option<i64>>;

    /// 取 1m 区间内按 `(bucket_ts, rowid)` 升序的第 `offset` 条时间戳。
    fn samples_1m_ts_at_offset(
        &self,
        from_ts: i64,
        to_ts: i64,
        offset: usize,
    ) -> Result<Option<i64>>;

    /// 读取 raw 最大 `rowid` 与新区间内最旧 `ts`（迟到检测）。
    fn raw_new_rows(&self, after_rowid: Option<i64>) -> Result<(Option<i64>, Option<i64>)>;

    /// 1m 层最旧桶时间；`None` 表示该层没有数据。
    fn samples_1m_oldest_ts(&self) -> Result<Option<i64>>;

    /// 分批删除 raw 中 `ts < cutoff` 且 `aggregated_1m=1` 的行。
    ///
    /// R1b 起未聚合 raw 一律不删；维护水位不再单独作为可删证明。
    fn prune_samples_before(&self, cutoff: i64) -> Result<PruneResult>;

    /// v8 归档启用时的 raw 保留期：只删已聚合且所属对象 `uploaded` 的行。
    ///
    /// R1a-1 只提供原语，不改现有 [`Storage::prune_samples_before`] 的行为；
    /// R1b 在 `archive.enabled` 分支接入，并在 ledger pending 时跳过删除。
    /// 未认领行、pending / failed 对象、未聚合行一律保留。
    fn prune_archived_samples_before(&self, cutoff: i64) -> Result<PruneResult>;

    /// 分批删除 1m 中 `bucket_ts < cutoff` 且整小时 `aggregated_1h=1` 的行。
    ///
    /// `cutoff` 会先向下取整到整点；只要该小时有一行 `aggregated_1h=0`，
    /// 整小时都跳过（dirty hour）。维护水位不再单独作为可删证明。
    fn prune_samples_1m_before(&self, cutoff: i64) -> Result<PruneResult>;

    /// 分批删除 1h 中 `bucket_ts < cutoff` 的行。
    fn prune_samples_1h_before(&self, cutoff: i64) -> Result<PruneResult>;

    /// CAS 认领 raw `rowid` 水位；rowid 与代际都匹配才写入。
    fn claim_raw_rowid_if_unchanged(
        &self,
        expected_rowid: Option<i64>,
        expected_generation: i64,
        new_max: i64,
    ) -> Result<bool>;

    // ---- M4-C 归档对象与归档水位（schema v7） ----

    /// 插入归档对象，返回自增 id；`object_key` 重复返回 `ObjectExists`。
    fn insert_archive_object(&self, object: &ArchiveObject) -> Result<i64>;

    /// 按 id 读取归档对象；不存在返回 `None`。
    fn get_archive_object(&self, id: i64) -> Result<Option<ArchiveObject>>;

    /// 按 `object_key` 读取归档对象；不存在返回 `None`。
    fn find_archive_object_by_key(&self, object_key: &str) -> Result<Option<ArchiveObject>>;

    /// 按 id 倒序分页列出归档对象；`before_id` 为排他游标。
    fn list_archive_objects(
        &self,
        limit: usize,
        before_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>>;

    /// 按 id 升序分页列出**待重试**的 v8 归档对象（`pending` / `failed`）。
    ///
    /// 只返回 `ledger_version = LEDGER_VERSION_V8` 的对象：旧 v7 对象没有
    /// claim 行集，不能按行重建，也不得复用其 key。`after_id` 是上一页最后
    /// 一条的 id（排他）。worker 用它做崩溃恢复与失败重试。
    fn list_retryable_archive_objects(
        &self,
        limit: usize,
        after_id: Option<i64>,
    ) -> Result<Vec<ArchiveObject>>;

    /// 更新归档对象状态，并校验合法的状态迁移。
    fn update_archive_object_status(
        &self,
        id: i64,
        status: ArchiveStatus,
        error: &str,
        uploaded_at: Option<i64>,
        deleted_at: Option<i64>,
    ) -> Result<()>;

    /// 读取归档水位；键不存在返回 `None`。
    fn get_archive_state(&self, key: &str) -> Result<Option<String>>;

    /// 写入 / 更新归档水位（UPSERT）。
    fn set_archive_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()>;

    /// 列出与 `[from_ts, to_ts]` 有交集的归档对象，按 `from_ts, id` 升序。
    fn list_archive_objects_in_range(&self, from_ts: i64, to_ts: i64)
        -> Result<Vec<ArchiveObject>>;

    /// 按 `rowid` 升序分批扫描 raw；`after_rowid` 为排他游标。
    fn scan_archive_rows(
        &self,
        from_ts: i64,
        to_ts: i64,
        after_rowid: Option<i64>,
        limit: usize,
    ) -> Result<Vec<ArchiveRawRow>>;

    /// 按 `ts, rowid`（PG 为 `ts, id`）升序扫描 `archive_object_id IS NULL`
    /// 的 raw，供归档 claim。
    ///
    /// 时间范围左闭右开 `[from_ts, to_ts)`，`limit == 0` 返回空列表。
    fn list_unclaimed_archive_rows(
        &self,
        from_ts: i64,
        to_ts: i64,
        limit: usize,
    ) -> Result<Vec<ArchiveRawRow>>;

    /// 插入归档对象并在同一事务内原子认领 `rows`。
    ///
    /// claim 是**短事务**：只插入对象（`bytes`/`sha256` 可先留占位）并
    /// `UPDATE` 行集，CSV.GZ 生成与上传必须在事务外完成，避免阻塞 ingest。
    /// 调用方可按 `max_object_bytes` 把候选行切成多个对象、多次调用本方法。
    ///
    /// 返回新对象 id。`object.rows/from_ts/to_ts` 必须与行集一致，
    /// `ledger_version` 必须为 [`crate::archive::LEDGER_VERSION_V8`]，
    /// 状态必须为 `pending`；affected 行数不等于选中数时整事务回滚并返回
    /// [`crate::archive::ArchiveStoreError::ClaimConflict`]（可重试）。
    fn claim_archive_rows(&self, object: &ArchiveObject, rows: &[ArchiveRawRow]) -> Result<i64>;

    /// 按 `archive_object_id` 读回 claim 行集（重试重建 CSV/manifest 用）。
    ///
    /// 按 `ts, rowid`（PG 为 `ts, id`）升序返回，与 claim 扫描顺序一致；
    /// 只有同一顺序才能在第 3 步重试时重建字节级一致的 CSV。对象不存在或行
    /// 已删除返回空列表。
    fn archive_rows_for_object(&self, object_id: i64) -> Result<Vec<ArchiveRawRow>>;

    /// 记录一次上传失败：状态置 `failed`、覆盖 `error`，`attempts` 加一。
    ///
    /// 只允许 `pending` / `failed` 迁移到 `failed`；已 `uploaded` /
    /// `local_deleted` 的对象返回 [`crate::archive::ArchiveStoreError::InvalidTransition`]，
    /// 不得回退。id 不存在返回
    /// [`crate::archive::ArchiveStoreError::NotFound`]。
    fn record_archive_object_failure(&self, id: i64, error: &str) -> Result<()>;

    /// CSV.GZ 在 claim 事务外生成后，补对象的 `bytes` / `sha256` 元数据。
    ///
    /// claim 只做「插入对象 + UPDATE 行集」，`bytes`/`sha256` 可先留占位；
    /// 大对象编码与上传不得占用 claim 事务，避免阻塞 ingest。`sha256` 必须
    /// 是 64 位小写十六进制；仅 v8（`ledger_version=1`）且 `pending` /
    /// `failed` 的对象允许更新，对象不存在返回
    /// [`crate::archive::ArchiveStoreError::NotFound`]，
    /// 其它 ledger 版本 / 状态返回 `InvalidTransition`。
    fn update_archive_object_metadata(&self, id: i64, bytes: u64, sha256: &str) -> Result<()>;

    /// 记录一次上传尝试：仅 `pending` / `failed` 对象允许，`attempts += 1`。
    ///
    /// 返回递增后的 attempts；对象不存在返回
    /// [`crate::archive::ArchiveStoreError::NotFound`]，uploaded /
    /// local_deleted 返回 `InvalidTransition`。
    fn record_archive_attempt(&self, id: i64) -> Result<i64>;

    /// 统计不可归档的 raw 行数：`ts < 0` 或 `ts > now`。
    ///
    /// 只计数，不修改/删除；R1b 会在 `maintenance status invalid_timestamp_rows`
    /// 暴露给运维。归档 claim 扫描已排除这些行，避免 `archive_day_for` 在
    /// `i64::MIN` / 未来时间戳上整轮报错。
    fn count_invalid_archive_raw_rows(&self) -> Result<i64>;

    /// 归档对象总数。
    fn count_archive_objects(&self) -> Result<i64>;
}

/// 存储句柄：Phase D 的多后端边界。
///
/// 内部是 `Arc<dyn Storage>`，`Clone` 只增加引用计数，不复制底层连接。
/// SQLite 与 PostgreSQL 都能从这里构造；调用点通过 [`Deref`] 直接使用
/// trait 方法，不需要知道具体后端。
#[derive(Clone)]
pub struct StorageHandle {
    inner: Arc<dyn Storage>,
}

impl StorageHandle {
    /// 打开 SQLite 文件库；只读连接池大小会自动夹到 1–16。
    pub fn sqlite(path: &Path, read_pool_size: usize) -> Result<Self> {
        Ok(Self::from_sqlite(SqliteStorage::open_with_readers(
            path,
            read_pool_size,
        )?))
    }

    /// 打开 SQLite 文件库，并声明 `data_dir` 为本程序专用数据目录（KI-21）。
    ///
    /// 与 [`StorageHandle::sqlite`] 的区别见
    /// [`SqliteStorage::open_with_private_data_dir`]：会额外收紧数据目录权限。
    pub fn sqlite_with_private_data_dir(
        path: &Path,
        read_pool_size: usize,
        data_dir: &Path,
    ) -> Result<Self> {
        Ok(Self::from_sqlite(
            SqliteStorage::open_with_private_data_dir(path, read_pool_size, data_dir)?,
        ))
    }

    /// 打开内存 SQLite（共享缓存），供测试与只读 CLI 使用。
    pub fn sqlite_memory() -> Result<Self> {
        Ok(Self::from_sqlite(SqliteStorage::open_in_memory()?))
    }

    /// 用已打开的 PostgreSQL 存储构造句柄（Phase D3）。
    ///
    /// 只做 `Arc<dyn Storage>` 装箱，不建立连接、不跑 schema 迁移；连接与
    /// 迁移由调用方在 blocking 线程通过 [`PostgresStorage::open`] /
    /// [`PostgresStorage::apply_schema`] 完成。
    pub fn postgres(storage: PostgresStorage) -> Self {
        Self {
            inner: Arc::new(storage),
        }
    }

    /// 以 `&dyn Storage` 借用底层存储。
    pub fn as_storage(&self) -> &dyn Storage {
        self.inner.as_ref()
    }

    fn from_sqlite(storage: SqliteStorage) -> Self {
        Self {
            inner: Arc::new(storage),
        }
    }
}

impl Deref for StorageHandle {
    type Target = dyn Storage;

    fn deref(&self) -> &Self::Target {
        // 直接借用 Arc 里的 trait object：`Target` 默认 `'static`，
        // 不能走 `as_storage()`（其返回的 object lifetime 绑定在 `&self` 上）。
        &*self.inner
    }
}

// 编译期证明句柄可跨线程共享：`Storage: Send + Sync` 保证 `Arc<dyn Storage>`
// 同时满足 `Send + Sync`，hub 不需要任何 `unsafe impl`。
#[allow(dead_code)]
fn _assert_storage_handle_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<StorageHandle>();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `StorageHandle` 通过 `Deref` 直接暴露 trait object；`Clone` 只共享
    /// 同一个 `Arc`，不会复制底层连接。
    #[test]
    fn storage_handle_exposes_dyn_storage_and_clones_the_arc() {
        let handle = StorageHandle::sqlite_memory().expect("打开内存库失败");
        assert!(handle.list_agents().unwrap().is_empty());

        let cloned = handle.clone();
        assert_eq!(
            Arc::strong_count(&handle.inner),
            2,
            "Clone 应共享同一个 Arc，而不是复制底层存储"
        );
        let via_trait: &dyn Storage = cloned.as_storage();
        assert_eq!(via_trait.sample_count("missing").unwrap(), 0);
    }
}
