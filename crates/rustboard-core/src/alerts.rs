//! M4-B1：告警规则模型与内置规则。
//!
//! 本模块只负责**规则本身**：类型、输入校验、内置规则常量，以及存储层可以
//! 直接映射成 409 / 403 的领域错误。告警评估状态机、事件、静默与通知渠道
//! 属于 B1b / B2，不在这里实现。
//!
//! 字段与 schema v7 的 `alert_rules` 表一一对应；序列化后的 JSON 就是管理 API
//! 的规则结构，`source` / `comparator` 用稳定的字符串（不是数字枚举），
//! 避免将来加枚举值时改变已有值。
//!
//! 安全约定：
//! - 规则名等用户输入只做格式校验，**错误信息不回显原始输入**（防止把超长 /
//!   控制字符带进响应与日志）；
//! - `channel_ids` 在本层只校验格式与数量；渠道是否存在、是否启用由存储层在
//!   写规则事务内复核（并发删除 / 禁用时返回
//!   [`AlertRuleStoreError::ChannelNotFound`] / [`AlertRuleStoreError::ChannelDisabled`]）；
//! - 内置规则固定 id、初始 disabled：升级后没有渠道时不会产生意外通知。

use std::collections::BTreeSet;
use std::fmt;

use rustboard_common::model::Labels;
use serde::{Deserialize, Deserializer, Serialize};

/// 规则总数硬上限（含 5 条内置规则）。
///
/// 与方案 §6.2 的每轮 `max_rules` 上限一致：再多规则评估一轮也处理不完。
pub const MAX_ALERT_RULES: usize = 200;

/// 规则名称最大字节数（与方案 §8.1 的「1..64 字节」一致）。
pub const MAX_RULE_NAME_BYTES: usize = 64;
/// 规则名称最大字符数：字节与字符双上限，避免多字节字符绕过长度检查。
pub const MAX_RULE_NAME_CHARS: usize = 64;

/// metric 名最大字节数。
pub const MAX_METRIC_BYTES: usize = 64;

/// `duration_secs` 上限：1 天。
pub const MAX_DURATION_SECS: u32 = 86_400;
/// `cooldown_secs` 上限：7 天。
pub const MAX_COOLDOWN_SECS: u32 = 604_800;

/// 过滤 labels 最多多少对。
pub const MAX_FILTER_LABELS: usize = 16;
/// 过滤 labels 的键最大字节数。
pub const MAX_LABEL_KEY_BYTES: usize = 64;
/// 过滤 labels 的值最大字节数。
pub const MAX_LABEL_VALUE_BYTES: usize = 256;

/// 单条规则的 `channel_ids` 上限。
pub const MAX_CHANNEL_IDS: usize = 16;
/// 渠道 id 最大字节数（B2 使用 UUID）。
pub const MAX_CHANNEL_ID_BYTES: usize = 64;

/// `filter_agent_id` 最大字节数（与 `agents.agent_id` 的既有上限一致）。
pub const MAX_FILTER_AGENT_ID_BYTES: usize = 64;

/// 规则来源。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSource {
    /// 指标规则：比较最新采样值。
    #[default]
    Metric,
    /// agent 离线：比较 `now - last_seen_at` 与阈值（秒）。
    AgentOffline,
    /// hub 服务端证书剩余小时数（与 `cert_warn_hours` 同单位）。
    HubCert,
}

impl AlertSource {
    /// 数据库 / API 使用的稳定字符串。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Metric => "metric",
            Self::AgentOffline => "agent_offline",
            Self::HubCert => "hub_cert",
        }
    }

    /// 解析稳定字符串；未知值返回 `None`（不静默降级）。
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "metric" => Some(Self::Metric),
            "agent_offline" => Some(Self::AgentOffline),
            "hub_cert" => Some(Self::HubCert),
            _ => None,
        }
    }

    /// 该来源是否必须带 metric。
    pub fn requires_metric(self) -> bool {
        matches!(self, Self::Metric)
    }
}

/// 阈值比较符。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Comparator {
    /// `>`
    #[default]
    Gt,
    /// `>=`
    Gte,
    /// `<`
    Lt,
    /// `<=`
    Lte,
    /// `==`
    Eq,
    /// `!=`
    Ne,
}

impl Comparator {
    /// 数据库 / API 使用的稳定字符串。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gt => "gt",
            Self::Gte => "gte",
            Self::Lt => "lt",
            Self::Lte => "lte",
            Self::Eq => "eq",
            Self::Ne => "ne",
        }
    }

    /// 解析稳定字符串；未知值返回 `None`。
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "gt" => Some(Self::Gt),
            "gte" => Some(Self::Gte),
            "lt" => Some(Self::Lt),
            "lte" => Some(Self::Lte),
            "eq" => Some(Self::Eq),
            "ne" => Some(Self::Ne),
            _ => None,
        }
    }
}

/// 一条告警规则（schema v9 `alert_rules` 的一行，JSON 即管理 API 结构）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertRule {
    /// 主键：自定义规则为 UUID，内置规则为固定的 `builtin-*`。
    pub id: String,
    /// 规则名；全库唯一。
    pub name: String,
    /// 是否启用；内置规则初始为 `false`。
    pub enabled: bool,
    /// 规则来源。
    pub source: AlertSource,
    /// 指标名；非 metric 来源必须为空字符串。
    pub metric: String,
    /// 阈值比较符。
    pub comparator: Comparator,
    /// 阈值；必须是有限数。
    pub threshold: f64,
    /// 条件需连续满足的秒数；0 表示立即触发。
    pub duration_secs: u32,
    /// 两次通知之间的最小间隔（秒）。
    pub cooldown_secs: u32,
    /// 只匹配指定 agent；`None` 表示全部 agent。
    pub filter_agent_id: Option<String>,
    /// 精确子集匹配的 labels。
    pub filter_labels: Labels,
    /// 绑定的通知渠道 id；管理 API 兼容字段。
    ///
    /// 存储层在规则写事务内同时维护 JSON 与 `alert_rule_channels` 关系行，
    /// 并校验渠道存在且启用；读取时两处不一致会 fail closed。
    pub channel_ids: Vec<String>,
    /// 恢复时是否发送通知。
    pub notify_on_resolve: bool,
    /// 是否内置规则；内置规则不允许删除。
    pub is_builtin: bool,
    /// 最近一次修改者（旧 admin token 为 `"admin"`）。
    pub updated_by: String,
    /// 创建时间（Unix 毫秒）。
    pub created_at: i64,
    /// 最近修改时间（Unix 毫秒）。
    pub updated_at: i64,
    /// 规则内容版本；每次更新由存储层执行 `revision = revision + 1`。
    ///
    /// 仅用于评估事务的 CAS（旧评估结果必须能识别规则已被改过），
    /// 不属于管理 API JSON：序列化时跳过，反序列化默认 0。
    #[serde(skip)]
    pub revision: i64,
}

impl AlertRule {
    /// 校验一条**合并完成**的规则是否语义自洽。
    ///
    /// `AlertRuleInput::validate` 只能校验请求里出现的字段；切换 source 时
    /// metric 是否该清空、metric 规则是否缺 metric，只有合并到既有规则后才
    /// 能判断，因此这里再校验一次最终状态。Hub 在落库前必须调用。
    pub fn validate_semantics(&self) -> Result<(), String> {
        validate_rule_name(&self.name)?;
        if self.source.requires_metric() {
            validate_metric(&self.metric)?;
        } else if !self.metric.is_empty() {
            return Err("非 metric 规则不能指定 metric".to_string());
        }
        if !self.threshold.is_finite() {
            return Err("threshold 必须是有限数值".to_string());
        }
        validate_duration(self.duration_secs)?;
        validate_cooldown(self.cooldown_secs)?;
        validate_filter_labels(&self.filter_labels)?;
        if let Some(agent_id) = &self.filter_agent_id {
            validate_filter_agent_id(agent_id)?;
        }
        validate_channel_ids(&self.channel_ids)?;
        Ok(())
    }
}

/// POST / PUT 的请求体：只包含可写字段。
///
/// 全部字段可选，语义是「出现即覆盖」：
/// - POST 时从与表默认值一致的初始规则开始合并；
/// - PUT 时在既有规则上合并，因此只传 `{"enabled": true}` 就能启停；
/// - `filter_agent_id` 支持三种状态：字段缺省 = 保留原值，`null` / `""` =
///   清空为全部 agent，字符串 = 设置过滤。
///
/// `deny_unknown_fields`：字段名拼错直接 400，不静默忽略。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertRuleInput {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub source: Option<AlertSource>,
    #[serde(default)]
    pub metric: Option<String>,
    #[serde(default)]
    pub comparator: Option<Comparator>,
    #[serde(default)]
    pub threshold: Option<f64>,
    #[serde(default)]
    pub duration_secs: Option<u32>,
    #[serde(default)]
    pub cooldown_secs: Option<u32>,
    /// `None` = 未提供；`Some(None)` = 显式 null；`Some(Some(x))` = 设置。
    #[serde(default, deserialize_with = "deserialize_some")]
    pub filter_agent_id: Option<Option<String>>,
    #[serde(default)]
    pub filter_labels: Option<Labels>,
    #[serde(default)]
    pub channel_ids: Option<Vec<String>>,
    #[serde(default)]
    pub notify_on_resolve: Option<bool>,
}

/// 区分「字段缺省」与「显式 null」：缺省由 `#[serde(default)]` 得到 `None`，
/// 显式 null 会进入这里并包成 `Some(None)`。
fn deserialize_some<'de, T, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl AlertRuleInput {
    /// 校验请求里出现的字段。
    ///
    /// 错误信息为中文且只描述规则，不回显用户输入原文。
    pub fn validate(&self) -> Result<(), String> {
        if let Some(name) = &self.name {
            validate_rule_name(name)?;
        }
        if let Some(source) = self.source {
            if source.requires_metric() {
                if let Some(metric) = &self.metric {
                    if metric.is_empty() {
                        return Err("metric 规则必须指定 metric".to_string());
                    }
                }
            } else if let Some(metric) = &self.metric {
                if !metric.is_empty() {
                    return Err("非 metric 规则不能指定 metric".to_string());
                }
            }
        }
        if let Some(metric) = &self.metric {
            if !metric.is_empty() {
                validate_metric(metric)?;
            }
        }
        if let Some(threshold) = self.threshold {
            if !threshold.is_finite() {
                return Err("threshold 必须是有限数值".to_string());
            }
        }
        if let Some(duration) = self.duration_secs {
            validate_duration(duration)?;
        }
        if let Some(cooldown) = self.cooldown_secs {
            validate_cooldown(cooldown)?;
        }
        if let Some(labels) = &self.filter_labels {
            validate_filter_labels(labels)?;
        }
        // 空串等价于「清空过滤」，是合法输入；只校验非空值。
        if let Some(agent_id) = self
            .filter_agent_id
            .as_ref()
            .and_then(|filter| filter.as_deref())
            .filter(|agent_id| !agent_id.is_empty())
        {
            validate_filter_agent_id(agent_id)?;
        }
        if let Some(channel_ids) = &self.channel_ids {
            validate_channel_ids(channel_ids)?;
        }
        Ok(())
    }

    /// 把请求里出现的字段合并到 `rule` 上。
    ///
    /// 调用方必须先调用 [`Self::validate`]，并在合并后调用
    /// [`AlertRule::validate_semantics`] 校验最终状态。
    ///
    /// 切到非 metric 来源时自动清空 metric：PUT 只改 `source` 时不要求客户端
    /// 同时显式传 `"metric": ""`，避免旧 metric 残留成非法规则。
    pub fn apply_to(&self, rule: &mut AlertRule) {
        if let Some(name) = &self.name {
            rule.name = name.clone();
        }
        if let Some(enabled) = self.enabled {
            rule.enabled = enabled;
        }
        if let Some(source) = self.source {
            rule.source = source;
        }
        if let Some(metric) = &self.metric {
            rule.metric = metric.clone();
        }
        if let Some(comparator) = self.comparator {
            rule.comparator = comparator;
        }
        if let Some(threshold) = self.threshold {
            rule.threshold = threshold;
        }
        if let Some(duration) = self.duration_secs {
            rule.duration_secs = duration;
        }
        if let Some(cooldown) = self.cooldown_secs {
            rule.cooldown_secs = cooldown;
        }
        if let Some(filter) = &self.filter_agent_id {
            rule.filter_agent_id = filter
                .as_ref()
                .filter(|agent_id| !agent_id.is_empty())
                .cloned();
        }
        if let Some(labels) = &self.filter_labels {
            rule.filter_labels = labels.clone();
        }
        if let Some(channel_ids) = &self.channel_ids {
            rule.channel_ids = dedupe_channel_ids(channel_ids);
        }
        if let Some(notify_on_resolve) = self.notify_on_resolve {
            rule.notify_on_resolve = notify_on_resolve;
        }
        if !rule.source.requires_metric() {
            rule.metric.clear();
        }
    }
}

/// 规则名校验：1–64 字节且不超过 64 字符，首尾无空白，不含控制字符。
///
/// 允许中文（内置规则就是中文名）；错误信息不回显名称。
pub fn validate_rule_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("规则名称不能为空".to_string());
    }
    if name.len() > MAX_RULE_NAME_BYTES || name.chars().count() > MAX_RULE_NAME_CHARS {
        return Err(format!("规则名称必须在 1–{MAX_RULE_NAME_BYTES} 字节以内"));
    }
    if name.trim() != name {
        return Err("规则名称首尾不能有空白".to_string());
    }
    if name.chars().any(char::is_control) {
        return Err("规则名称不能包含控制字符".to_string());
    }
    Ok(())
}

/// metric 名校验：1–64 字节，只允许 `[a-z0-9_.-]`。
pub fn validate_metric(metric: &str) -> Result<(), String> {
    if metric.is_empty()
        || metric.len() > MAX_METRIC_BYTES
        || !metric.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        })
    {
        return Err(format!(
            "metric 必须是 1–{MAX_METRIC_BYTES} 个 [a-z0-9_.-] 字符"
        ));
    }
    Ok(())
}

/// `duration_secs` 范围校验：0..=86400。
pub fn validate_duration(duration_secs: u32) -> Result<(), String> {
    if duration_secs > MAX_DURATION_SECS {
        return Err(format!("duration_secs 不能超过 {MAX_DURATION_SECS} 秒"));
    }
    Ok(())
}

/// `cooldown_secs` 范围校验：0..=604800。
pub fn validate_cooldown(cooldown_secs: u32) -> Result<(), String> {
    if cooldown_secs > MAX_COOLDOWN_SECS {
        return Err(format!("cooldown_secs 不能超过 {MAX_COOLDOWN_SECS} 秒"));
    }
    Ok(())
}

/// 过滤 labels 校验：最多 16 对；键 1–64 字节、无空白/控制字符；值 ≤256 字节。
pub fn validate_filter_labels(labels: &Labels) -> Result<(), String> {
    if labels.len() > MAX_FILTER_LABELS {
        return Err(format!("filter_labels 最多 {MAX_FILTER_LABELS} 对"));
    }
    for (key, value) in labels {
        if key.is_empty()
            || key.len() > MAX_LABEL_KEY_BYTES
            || key.chars().any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(format!(
                "filter_labels 的键必须是 1–{MAX_LABEL_KEY_BYTES} 字节且不含空白"
            ));
        }
        if value.len() > MAX_LABEL_VALUE_BYTES || value.chars().any(char::is_control) {
            return Err(format!(
                "filter_labels 的值不能超过 {MAX_LABEL_VALUE_BYTES} 字节或包含控制字符"
            ));
        }
    }
    Ok(())
}

/// `filter_agent_id` 校验：1–64 字节的 `[A-Za-z0-9_.-]`。
pub fn validate_filter_agent_id(agent_id: &str) -> Result<(), String> {
    let valid = !agent_id.is_empty()
        && agent_id.len() <= MAX_FILTER_AGENT_ID_BYTES
        && agent_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err("filter_agent_id 格式非法".to_string());
    }
    Ok(())
}

/// 渠道 id 校验：1–64 字节的 `[A-Za-z0-9_.-]`（B2 使用 UUID）。
pub fn validate_channel_id(channel_id: &str) -> Result<(), String> {
    let valid = !channel_id.is_empty()
        && channel_id.len() <= MAX_CHANNEL_ID_BYTES
        && channel_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err("channel_ids 含非法渠道 id".to_string());
    }
    Ok(())
}

/// `channel_ids` 校验：逐个校验格式，去重后不超过 16 个。
pub fn validate_channel_ids(channel_ids: &[String]) -> Result<(), String> {
    for channel_id in channel_ids {
        validate_channel_id(channel_id)?;
    }
    if dedupe_channel_ids(channel_ids).len() > MAX_CHANNEL_IDS {
        return Err(format!("channel_ids 最多 {MAX_CHANNEL_IDS} 个"));
    }
    Ok(())
}

/// 保留首次出现顺序去重（落库与判断上限都用这个结果）。
pub fn dedupe_channel_ids(channel_ids: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(channel_ids.len().min(MAX_CHANNEL_IDS));
    for channel_id in channel_ids {
        if seen.insert(channel_id.as_str()) {
            out.push(channel_id.clone());
        }
    }
    out
}

/// 存储层可以交给 hub 映射成固定 HTTP 错误码的领域错误。
///
/// 不携带规则名等用户输入，避免错误信息出现在响应 / 日志时回显原文。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertRuleStoreError {
    /// 规则不存在（404）。
    NotFound,
    /// 规则名重复（409 `rule_name_exists`）。
    NameExists,
    /// 规则总数达到上限（409 `rule_limit`）。
    LimitReached,
    /// 内置规则不允许删除（403 `builtin_rule`）。
    BuiltinRule,
    /// 规则引用的通知渠道不存在（400 `channel_not_found`）。
    ///
    /// Hub 在写入前会先校验渠道存在 / 启用，但该校验与落库不在同一事务；
    /// 并发删除渠道时仍可能在这里失败。存储层在写规则的同一事务内复核，
    /// 映射成与前置校验一致的 400，而不是 500。
    ChannelNotFound,
    /// 规则引用的通知渠道存在但已禁用（400 `channel_disabled`）。
    ///
    /// 与 Hub 的前置校验一致：启用中的规则不能绑定禁用渠道；存储层在写事务内
    /// 复核，避免并发禁用造成“规则可用但永远发不出去”的静默配置。
    ChannelDisabled,
}

impl fmt::Display for AlertRuleStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "告警规则不存在"),
            Self::NameExists => write!(f, "告警规则名称已存在"),
            Self::LimitReached => write!(f, "告警规则数量已达上限 {MAX_ALERT_RULES} 条"),
            Self::BuiltinRule => write!(f, "内置告警规则不允许删除"),
            Self::ChannelNotFound => write!(f, "告警规则引用的通知渠道不存在"),
            Self::ChannelDisabled => write!(f, "告警规则引用的通知渠道已禁用"),
        }
    }
}

impl std::error::Error for AlertRuleStoreError {}

/// [`Storage::apply_alert_evaluation`] 的事务结果。
///
/// CAS 的判定标准是事务内重新读取的 `alert_rules.enabled` 与 `revision`：
/// 规则不存在、已禁用或 revision 与评估开始时读到的不一致，都意味着本轮
/// 评估结果已经过期，**不得**写入任何状态 / 事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertEvaluationOutcome {
    /// 规则仍启用且 revision 匹配；事件 / 状态已在同一事务内落库。
    Applied {
        /// 本事务按每规则状态上限淘汰的行数。
        removed: usize,
    },
    /// 规则不存在、已禁用或 revision 已变化；未写入 / 未清理任何数据。
    Stale,
}

/// 静默存储的领域错误；hub 映射成固定 409 `silence_limit`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertSilenceStoreError {
    /// 生效中的静默数量达到 [`MAX_ALERT_SILENCES`]。
    LimitReached,
}

impl fmt::Display for AlertSilenceStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitReached => {
                write!(f, "生效中的静默数量已达上限 {MAX_ALERT_SILENCES} 条")
            }
        }
    }
}

impl std::error::Error for AlertSilenceStoreError {}

/// 内置规则固定 id（升级 / 重启后不变，面板与文档依赖它们）。
pub const BUILTIN_AGENT_OFFLINE: &str = "builtin-agent-offline";
pub const BUILTIN_DISK_PERCENT: &str = "builtin-disk-percent";
pub const BUILTIN_AGENT_CERT: &str = "builtin-agent-cert";
pub const BUILTIN_HUB_CERT: &str = "builtin-hub-cert";
pub const BUILTIN_BUFFER_BACKLOG: &str = "builtin-buffer-backlog";

/// 内置规则种子：固定 id、`is_builtin = true`、初始 **disabled**、不绑定渠道。
///
/// 初始禁用是方案 §6.1 的明确要求：升级后若默认启用，没有渠道时会静默丢通知，
/// 有渠道时可能产生用户没预期的告警。面板启用并绑定渠道后才真正生效。
///
/// `now` 只用于 `created_at` / `updated_at`；种子已存在时存储层绝不覆盖用户改动。
///
/// `offline_after_secs` / `cert_warn_hours` 来自 `HubAlertsConfig`：内置规则只在
/// **首次种入**时使用当时的配置值，之后规则自身的 `threshold` 才是权威——用户
/// 改过阈值后，改配置不会覆盖它（与方案「规则阈值优先」一致）。
///
/// 单位必须与评估口径一致：
/// - 离线：秒；
/// - agent / hub 证书：小时（agent 上传的 `cert.hours_left` 也是小时）。
pub fn builtin_rules(now: i64, offline_after_secs: u64, cert_warn_hours: u32) -> Vec<AlertRule> {
    let offline_threshold = offline_after_secs as f64;
    let cert_threshold = f64::from(cert_warn_hours);
    vec![
        builtin_rule(
            BUILTIN_AGENT_OFFLINE,
            "Agent 离线",
            AlertSource::AgentOffline,
            "",
            Comparator::Gt,
            offline_threshold,
            0,
            1_800,
            now,
        ),
        builtin_rule(
            BUILTIN_DISK_PERCENT,
            "磁盘使用率过高",
            AlertSource::Metric,
            "disk.used_percent",
            Comparator::Gt,
            90.0,
            300,
            1_800,
            now,
        ),
        builtin_rule(
            BUILTIN_AGENT_CERT,
            "Agent 证书即将过期",
            AlertSource::Metric,
            "cert.hours_left",
            Comparator::Lt,
            cert_threshold,
            0,
            1_800,
            now,
        ),
        builtin_rule(
            BUILTIN_HUB_CERT,
            "Hub 证书即将过期",
            AlertSource::HubCert,
            "",
            Comparator::Lt,
            cert_threshold,
            0,
            1_800,
            now,
        ),
        builtin_rule(
            BUILTIN_BUFFER_BACKLOG,
            "缓冲积压",
            AlertSource::Metric,
            "buffer.pending_ratio",
            Comparator::Gt,
            0.8,
            60,
            1_800,
            now,
        ),
    ]
}

/// 构造一条内置规则；`channel_ids` 恒为空，`notify_on_resolve` 恒为 true。
#[allow(clippy::too_many_arguments)]
fn builtin_rule(
    id: &str,
    name: &str,
    source: AlertSource,
    metric: &str,
    comparator: Comparator,
    threshold: f64,
    duration_secs: u32,
    cooldown_secs: u32,
    now: i64,
) -> AlertRule {
    AlertRule {
        id: id.to_string(),
        name: name.to_string(),
        enabled: false,
        source,
        metric: metric.to_string(),
        comparator,
        threshold,
        duration_secs,
        cooldown_secs,
        filter_agent_id: None,
        filter_labels: Labels::new(),
        channel_ids: Vec::new(),
        notify_on_resolve: true,
        is_builtin: true,
        updated_by: "builtin".to_string(),
        created_at: now,
        updated_at: now,
        revision: 0,
    }
}

// ---------------------------------------------------------------------------
// M4-B1b：评估状态、事件与静默
// ---------------------------------------------------------------------------

/// `alert_states.series_key` 的最大字节数。
///
/// labels 是 agent 上报的任意键值对，长度没有强约束；状态表主键必须有上限，
/// 超长序列键会退化成 SHA-256 摘要（见 [`series_key`]）。
pub const MAX_SERIES_KEY_BYTES: usize = 512;

/// 事件 `message` 的最大字节数（与方案 §6.2 一致）。
pub const MAX_ALERT_MESSAGE_BYTES: usize = 512;

/// 静默最短时长（秒）。
pub const MIN_SILENCE_DURATION_SECS: u64 = 1;
/// 静默最长时长（秒）：7 天。
pub const MAX_SILENCE_DURATION_SECS: u64 = 604_800;

/// 静默中的规则 id 最大字节数（内置 id 与 UUID 都远小于此值）。
pub const MAX_SILENCE_RULE_ID_BYTES: usize = 64;

/// 同时生效的静默数量上限。
///
/// 静默是低频运维操作；1000 条已经远超正常使用量。限制上限防止误用 / 恶意
/// 请求把 `alert_silences` 撑成无界表，也保证事件产生时的静默匹配保持廉价。
pub const MAX_ALERT_SILENCES: usize = 1_000;

/// 告警状态机的三个状态，与 `alert_states.state` 的取值一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertStateKind {
    /// 条件已满足，但尚未达到 `duration_secs`。
    Pending,
    /// 条件持续满足，已触发。
    Firing,
    /// 条件不再满足；保留状态用于重新计时。
    Resolved,
}

impl AlertStateKind {
    /// 数据库 / API 使用的稳定字符串。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Firing => "firing",
            Self::Resolved => "resolved",
        }
    }

    /// 解析稳定字符串；未知值返回 `None`（不静默降级）。
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "firing" => Some(Self::Firing),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }

    /// 是否能作为事件状态（`alert_events.state` 只允许 firing / resolved）。
    pub fn is_event(self) -> bool {
        matches!(self, Self::Firing | Self::Resolved)
    }
}

/// 一条告警状态（`alert_states` 的一行）。
///
/// 主键是 `(rule_id, agent_id, series_key)`：metric 规则每个序列独立一行，
/// agent_offline 规则每个 agent 一行（`series_key` 为空），hub_cert 规则全局一行
/// （`agent_id` / `series_key` 都为空）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertState {
    /// 规则 id。
    pub rule_id: String,
    /// agent id；全局规则为空字符串。
    pub agent_id: String,
    /// 序列键；合成规则为空字符串。
    pub series_key: String,
    /// 当前状态。
    pub state: AlertStateKind,
    /// 进入当前状态的时间（Unix 毫秒）。
    pub since: i64,
    /// 最近一次评估时间（Unix 毫秒）。
    pub last_eval_at: i64,
    /// 最近一次观测值；非有限值（NaN / Infinity）存 `None`。
    pub last_value: Option<f64>,
    /// 最近一次通知时间；B1b 不发送通知，恒为 `None`，留给 B2。
    pub last_notified_at: Option<i64>,
}

/// 一条告警事件（`alert_events` 的一行，JSON 即管理 API 结构）。
///
/// B1b 只落库、不发送通知：新事件的 `notified` 恒为 `false`、
/// `notify_error` 恒为空串；`silenced` 表示命中静默。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertEvent {
    /// 自增主键；新事件插入前为 0。
    pub id: i64,
    /// 事件时间（Unix 毫秒）。
    pub ts: i64,
    /// 规则 id。
    pub rule_id: String,
    /// 事件产生时的规则名快照（规则改名不改变历史事件）。
    pub rule_name: String,
    /// agent id；全局事件为空字符串。
    pub agent_id: String,
    /// 产生事件的状态序列键；合成规则（agent_offline / hub_cert）为空字符串。
    ///
    /// 通知 worker 用 `(rule_id, agent_id, series_key)` 精确定位
    /// `alert_states.last_notified_at`，避免同一 agent 的多序列互相触发冷却。
    pub series_key: String,
    /// 事件状态：firing / resolved。
    pub state: AlertStateKind,
    /// 触发 / 恢复时的观测值。
    pub value: Option<f64>,
    /// 中文可读描述；≤512 字节，不含 labels 全量与任何 secret。
    pub message: String,
    /// 是否已通知；B1b 恒为 false（B2 才可能为 true）。
    pub notified: bool,
    /// 通知失败原因；B1b 恒为空串。
    pub notify_error: String,
    /// 事件产生时是否命中静默。
    pub silenced: bool,
}

/// 一条静默（`alert_silences` 的一行）。
///
/// `rule_id` / `agent_id` 为 `None` 表示匹配全部规则 / 全部 agent。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AlertSilence {
    /// 自增主键；新建时为 0，落库后由存储层填入。
    pub id: i64,
    /// 规则 id；`None` = 全部规则。
    pub rule_id: Option<String>,
    /// agent id；`None` = 全部 agent。
    pub agent_id: Option<String>,
    /// 静默截止时间（Unix 毫秒，排他：`until_ts > now` 才生效）。
    pub until_ts: i64,
    /// 创建者（旧 admin token 为 `"admin"`）。
    pub created_by: String,
    /// 创建时间（Unix 毫秒）。
    pub created_at: i64,
}

impl AlertSilence {
    /// 在 `now` 时刻是否仍生效。
    pub fn is_active_at(&self, now: i64) -> bool {
        self.until_ts > now
    }

    /// 是否命中给定规则 / agent（尚未检查时间窗口）。
    pub fn matches_target(&self, rule_id: &str, agent_id: &str) -> bool {
        let rule_matches = match &self.rule_id {
            None => true,
            Some(candidate) => candidate == rule_id,
        };
        let agent_matches = match &self.agent_id {
            None => true,
            Some(candidate) => candidate == agent_id,
        };
        rule_matches && agent_matches
    }

    /// 在 `now` 时刻是否命中给定规则 / agent。
    pub fn matches(&self, rule_id: &str, agent_id: &str, now: i64) -> bool {
        self.is_active_at(now) && self.matches_target(rule_id, agent_id)
    }
}

/// 创建静默的请求体；字段缺省即 `None`（= 全部）。
///
/// `deny_unknown_fields`：字段名拼错直接 400，不静默忽略。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertSilenceInput {
    /// 规则 id；缺省 / `null` = 全部规则。
    #[serde(default)]
    pub rule_id: Option<String>,
    /// agent id；缺省 / `null` = 全部 agent。
    #[serde(default)]
    pub agent_id: Option<String>,
    /// 静默时长（秒），1–604800。
    pub duration_secs: u64,
}

impl AlertSilenceInput {
    /// 校验请求字段；错误信息为中文，不回显用户输入原文。
    pub fn validate(&self) -> Result<(), String> {
        if let Some(rule_id) = &self.rule_id {
            validate_silence_rule_id(rule_id)?;
        }
        if let Some(agent_id) = &self.agent_id {
            validate_filter_agent_id(agent_id)?;
        }
        if !(MIN_SILENCE_DURATION_SECS..=MAX_SILENCE_DURATION_SECS).contains(&self.duration_secs) {
            return Err(format!(
                "duration_secs 必须在 {MIN_SILENCE_DURATION_SECS}–{MAX_SILENCE_DURATION_SECS} 之间"
            ));
        }
        Ok(())
    }

    /// 转成待落库的静默；`id` 由存储层回填。
    ///
    /// 调用方必须先执行 [`Self::validate`]，并校验 `rule_id` 对应的规则存在。
    pub fn into_silence(&self, now: i64, created_by: String) -> AlertSilence {
        let duration_ms = self
            .duration_secs
            .saturating_mul(1_000)
            .min(i64::MAX as u64) as i64;
        AlertSilence {
            id: 0,
            rule_id: self.rule_id.clone(),
            agent_id: self.agent_id.clone(),
            until_ts: now.saturating_add(duration_ms),
            created_by,
            created_at: now,
        }
    }
}

/// 静默规则 id 校验：1–64 字节的 `[A-Za-z0-9_.-]`。
pub fn validate_silence_rule_id(rule_id: &str) -> Result<(), String> {
    let valid = !rule_id.is_empty()
        && rule_id.len() <= MAX_SILENCE_RULE_ID_BYTES
        && rule_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err("rule_id 格式非法".to_string());
    }
    Ok(())
}

/// 比较符对 `f64` 求值。
///
/// 安全边界：
/// - 任何一侧是 NaN 一律返回 `false`（包括 `ne`：NaN 不代表“不相等”）；
/// - 阈值不是有限数一律返回 `false`（配置坏掉时宁可不告警，不能误告警）；
/// - `eq` / `ne` 使用 `f64` 精确比较，由规则作者自行承担浮点误差。
pub fn evaluate_condition(comparator: Comparator, threshold: f64, value: f64) -> bool {
    if !threshold.is_finite() || value.is_nan() {
        return false;
    }
    match comparator {
        Comparator::Gt => value > threshold,
        Comparator::Gte => value >= threshold,
        Comparator::Lt => value < threshold,
        Comparator::Lte => value <= threshold,
        Comparator::Eq => value == threshold,
        Comparator::Ne => value != threshold,
    }
}

/// labels 过滤：`filter` 必须是 `labels` 的精确子集（键与值都相等）。
pub fn labels_match_filter(filter: &Labels, labels: &Labels) -> bool {
    filter
        .iter()
        .all(|(key, value)| labels.get(key).is_some_and(|actual| actual == value))
}

/// 生成稳定的序列键：`metric` + 按字典序排列的 labels 的 JSON。
///
/// `Labels` 是 `BTreeMap`，序列化顺序天然稳定；超过 [`MAX_SERIES_KEY_BYTES`]
/// 时退化为「metric 前 64 字节 + SHA-256」，避免超长 labels 撑大状态表主键。
/// 同一条序列在任何进程、任何重启后都得到相同键。
pub fn series_key(metric: &str, labels: &Labels) -> String {
    #[derive(Serialize)]
    struct Canonical<'a> {
        metric: &'a str,
        labels: &'a Labels,
    }

    let encoded =
        serde_json::to_string(&Canonical { metric, labels }).unwrap_or_else(|_| metric.to_string());
    if encoded.len() <= MAX_SERIES_KEY_BYTES {
        return encoded;
    }
    let digest = rustboard_common::tls::sha256_hex(&encoded);
    let metric_prefix = {
        let mut end = metric.len().min(64);
        while end > 0 && !metric.is_char_boundary(end) {
            end -= 1;
        }
        &metric[..end]
    };
    format!("{metric_prefix}#sha256:{digest}")
}

/// 一次状态机推进的结果。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AlertTransition {
    /// 需要写入的状态；`None` 表示「无状态 + 条件不满足」，不创建行。
    pub state: Option<AlertState>,
    /// 本轮产生的状态转换事件；`None` 表示没有状态转换。
    pub event: Option<AlertStateKind>,
}

/// 状态机纯函数：根据既有状态与本次观测推进一轮。
///
/// 规则（与方案 §6.2 一致）：
/// - 无状态 + 条件满足 → pending；`duration_secs == 0` 时同一轮直接 firing 并产生事件；
/// - pending + 条件满足且 `now - since >= duration_secs * 1000` → firing + 事件；
///   未到时长只刷新 `last_eval_at` / `last_value`，`since` 保持不变；
/// - pending / firing + 条件不满足 → resolved；只有 firing 产生 resolved 事件；
/// - firing + 条件满足 → 状态不变，**不重复**产生 firing 事件；
/// - resolved + 条件满足 → pending 重新计时；`duration_secs == 0` 时同一轮 firing；
/// - resolved + 条件不满足 → 保持 resolved。
///
/// 调用方负责「无样本 / 评估失败不进状态机」，因此这里永远拿到一个真实观测值。
/// `last_notified_at` 原样保留：B1b 不发通知，留给 B2 维护。
pub fn next_alert_state(
    existing: Option<&AlertState>,
    rule: &AlertRule,
    agent_id: &str,
    series_key: &str,
    value: f64,
    now: i64,
) -> AlertTransition {
    let condition_met = evaluate_condition(rule.comparator, rule.threshold, value);
    if existing.is_none() && !condition_met {
        return AlertTransition::default();
    }

    let previous = existing.map(|state| (state.state, state.since));
    let duration_ms = i64::from(rule.duration_secs).saturating_mul(1_000);
    let mut next = AlertState {
        rule_id: rule.id.clone(),
        agent_id: agent_id.to_string(),
        series_key: series_key.to_string(),
        state: AlertStateKind::Pending,
        since: now,
        last_eval_at: now,
        last_value: value.is_finite().then_some(value),
        // 仅为状态机 / 测试保留旧快照；持久化 upsert 的冲突分支不覆盖该列，
        // 通知时间由 notify_worker 的专用 UPDATE 独占。新序列为 None。
        last_notified_at: existing.and_then(|state| state.last_notified_at),
    };

    match previous {
        // 首次满足：duration 为 0 立即触发，否则进入 pending 计时。
        None => {
            if duration_ms == 0 {
                next.state = AlertStateKind::Firing;
                AlertTransition {
                    state: Some(next),
                    event: Some(AlertStateKind::Firing),
                }
            } else {
                next.state = AlertStateKind::Pending;
                AlertTransition {
                    state: Some(next),
                    event: None,
                }
            }
        }
        Some((AlertStateKind::Pending, since)) if condition_met => {
            if now.saturating_sub(since) >= duration_ms {
                next.state = AlertStateKind::Firing;
                AlertTransition {
                    state: Some(next),
                    event: Some(AlertStateKind::Firing),
                }
            } else {
                next.state = AlertStateKind::Pending;
                next.since = since;
                AlertTransition {
                    state: Some(next),
                    event: None,
                }
            }
        }
        Some((AlertStateKind::Pending, _)) => {
            // pending → resolved 不产生事件：从未触发过的抖动不值得打扰用户。
            next.state = AlertStateKind::Resolved;
            AlertTransition {
                state: Some(next),
                event: None,
            }
        }
        Some((AlertStateKind::Firing, since)) if condition_met => {
            next.state = AlertStateKind::Firing;
            next.since = since;
            AlertTransition {
                state: Some(next),
                event: None,
            }
        }
        Some((AlertStateKind::Firing, _)) => {
            next.state = AlertStateKind::Resolved;
            AlertTransition {
                state: Some(next),
                event: Some(AlertStateKind::Resolved),
            }
        }
        Some((AlertStateKind::Resolved, _)) if condition_met => {
            next.state = if duration_ms == 0 {
                AlertStateKind::Firing
            } else {
                AlertStateKind::Pending
            };
            let event = (duration_ms == 0).then_some(AlertStateKind::Firing);
            AlertTransition {
                state: Some(next),
                event,
            }
        }
        Some((AlertStateKind::Resolved, since)) => {
            next.state = AlertStateKind::Resolved;
            next.since = since;
            AlertTransition {
                state: Some(next),
                event: None,
            }
        }
    }
}

/// 构造一条待落库的告警事件（`id = 0`，由存储层回填）。
///
/// `notified` 恒为 `false`：B1b 不发送任何通知，B2 才更新；`silenced` 由调用方
/// 按本轮静默快照判定。`state` 只接受 firing / resolved（debug 构建断言）。
pub fn new_alert_event(
    rule: &AlertRule,
    agent_id: &str,
    series_key: &str,
    state: AlertStateKind,
    value: f64,
    now: i64,
    silenced: bool,
) -> AlertEvent {
    debug_assert!(
        state.is_event(),
        "告警事件状态只能是 firing / resolved，实际 {state:?}"
    );
    AlertEvent {
        id: 0,
        ts: now,
        rule_id: rule.id.clone(),
        rule_name: rule.name.clone(),
        agent_id: agent_id.to_string(),
        series_key: series_key.to_string(),
        state,
        value: value.is_finite().then_some(value),
        message: alert_event_message(rule, agent_id, state, value),
        notified: false,
        notify_error: String::new(),
        silenced,
    }
}

/// 生成中文事件描述。
///
/// 只包含规则名、agent、metric、观测值与阈值；**不写 labels 全量**，也不包含
/// 任何 secret。总长度严格 ≤ [`MAX_ALERT_MESSAGE_BYTES`]，超长按字符边界截断并
/// 追加省略号（不会切坏 UTF-8）。
pub fn alert_event_message(
    rule: &AlertRule,
    agent_id: &str,
    state: AlertStateKind,
    value: f64,
) -> String {
    let subject = if agent_id.is_empty() {
        "全局".to_string()
    } else {
        format!("agent {agent_id}")
    };
    let value_text = format_number(value);
    let threshold = format_number(rule.threshold);
    let comparator = rule.comparator.symbol();
    let detail = match rule.source {
        AlertSource::Metric => format!(
            "{subject} 指标「{}」当前值 {value_text}，阈值 {comparator} {threshold}",
            rule.metric
        ),
        AlertSource::AgentOffline => {
            format!("{subject} 离线时长 {value_text} 秒，阈值 {comparator} {threshold} 秒")
        }
        AlertSource::HubCert => format!(
            "{subject} Hub 服务端证书剩余 {value_text} 小时，阈值 {comparator} {threshold} 小时"
        ),
    };
    let verb = match state {
        AlertStateKind::Pending => "状态更新",
        AlertStateKind::Firing => "触发",
        AlertStateKind::Resolved => "恢复",
    };
    truncate_alert_message(format!("规则「{}」{verb}：{detail}", rule.name))
}

/// 阈值展示用的比较符符号。
impl Comparator {
    /// API / 事件描述里的符号形式。
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Gt => ">",
            Self::Gte => ">=",
            Self::Lt => "<",
            Self::Lte => "<=",
            Self::Eq => "==",
            Self::Ne => "!=",
        }
    }
}

/// 数值展示：最多两位小数，去掉多余的 `.0`；非有限值给出中文占位。
fn format_number(value: f64) -> String {
    if !value.is_finite() {
        return "非数值".to_string();
    }
    let rounded = (value * 100.0).round() / 100.0;
    format!("{rounded}")
}

/// 按 UTF-8 字符边界截断到 `max` 字节以内（不加省略号）。
fn alert_message_truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// 把事件描述夹到 [`MAX_ALERT_MESSAGE_BYTES`] 以内；截断时保留省略号。
fn truncate_alert_message(text: String) -> String {
    if text.len() <= MAX_ALERT_MESSAGE_BYTES {
        return text;
    }
    let ellipsis = '…';
    let budget = MAX_ALERT_MESSAGE_BYTES - ellipsis.len_utf8();
    let mut truncated = alert_message_truncate(&text, budget);
    truncated.push(ellipsis);
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_rule() -> AlertRule {
        AlertRule {
            id: "rule-1".into(),
            name: "磁盘告警".into(),
            enabled: false,
            source: AlertSource::Metric,
            metric: "disk.used_percent".into(),
            comparator: Comparator::Gt,
            threshold: 90.0,
            duration_secs: 300,
            cooldown_secs: 1_800,
            filter_agent_id: None,
            filter_labels: Labels::new(),
            channel_ids: Vec::new(),
            notify_on_resolve: true,
            is_builtin: false,
            updated_by: "admin".into(),
            created_at: 1,
            updated_at: 1,
            revision: 0,
        }
    }

    /// revision 是存储层内部字段：API JSON 不输出，反序列化默认 0。
    #[test]
    fn alert_rule_revision_is_not_part_of_api_json() {
        let rule = base_rule();
        let json = serde_json::to_value(&rule).expect("AlertRule 必须可序列化");
        assert!(
            json.get("revision").is_none(),
            "API JSON 不得输出内部 revision 字段：{json}"
        );

        let parsed: AlertRule = serde_json::from_value(json).expect("AlertRule 必须可反序列化");
        assert_eq!(parsed.revision, 0, "反序列化时 revision 必须默认 0");
        assert_eq!(parsed, rule, "跳过 revision 不得改变其它字段");
    }

    /// 内置规则：固定 id、5 条、全部 disabled、is_builtin、无渠道、阈值语义正确。
    #[test]
    fn m4_b1_builtin_rules_are_fixed_disabled_and_channel_free() {
        let rules = builtin_rules(1_700_000_000_000, 90, 48);
        assert_eq!(rules.len(), 5);
        let ids: Vec<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                BUILTIN_AGENT_OFFLINE,
                BUILTIN_DISK_PERCENT,
                BUILTIN_AGENT_CERT,
                BUILTIN_HUB_CERT,
                BUILTIN_BUFFER_BACKLOG,
            ]
        );
        for rule in &rules {
            assert!(rule.is_builtin, "内置规则 is_builtin 必须为 true: {rule:?}");
            assert!(!rule.enabled, "内置规则初始必须 disabled: {rule:?}");
            assert!(rule.channel_ids.is_empty(), "内置规则不得绑定渠道");
            assert!(rule.filter_agent_id.is_none());
            assert!(rule.filter_labels.is_empty());
            assert!(rule.notify_on_resolve);
            assert_eq!(rule.created_at, 1_700_000_000_000);
            assert_eq!(rule.updated_at, 1_700_000_000_000);
            rule.validate_semantics()
                .unwrap_or_else(|err| panic!("内置规则必须通过校验: {err}"));
        }

        let by_id = |id: &str| rules.iter().find(|rule| rule.id == id).unwrap();
        let offline = by_id(BUILTIN_AGENT_OFFLINE);
        assert_eq!(offline.source, AlertSource::AgentOffline);
        assert_eq!(offline.metric, "");
        assert_eq!(offline.comparator, Comparator::Gt);
        assert_eq!(offline.threshold, 90.0);
        assert_eq!(offline.duration_secs, 0);
        assert_eq!(offline.cooldown_secs, 1_800);

        let disk = by_id(BUILTIN_DISK_PERCENT);
        assert_eq!(disk.metric, "disk.used_percent");
        assert_eq!(disk.threshold, 90.0);
        assert_eq!(disk.duration_secs, 300);

        let cert = by_id(BUILTIN_AGENT_CERT);
        assert_eq!(cert.metric, "cert.hours_left", "证书阈值单位是小时");
        assert_eq!(cert.comparator, Comparator::Lt);
        assert_eq!(cert.threshold, 48.0);

        let hub_cert = by_id(BUILTIN_HUB_CERT);
        assert_eq!(hub_cert.source, AlertSource::HubCert);
        assert_eq!(hub_cert.metric, "");
        assert_eq!(hub_cert.threshold, 48.0);

        let buffer = by_id(BUILTIN_BUFFER_BACKLOG);
        assert_eq!(buffer.metric, "buffer.pending_ratio");
        assert_eq!(buffer.threshold, 0.8);
        assert_eq!(buffer.duration_secs, 60);
    }

    /// M4-B1 修复：内置离线 / 证书阈值必须来自 `HubAlertsConfig`，不是写死的 90/48。
    ///
    /// 证书阈值单位是**小时**：如果仍用 `cert.days_left` + 48，语义会变成「48 天
    /// 就告警」；这里同时锁定 metric 名与数值来源。
    #[test]
    fn m4_b1fix_builtin_thresholds_come_from_config() {
        let now = 1_700_000_000_000;
        let rules = builtin_rules(now, 120, 72);
        let by_id = |id: &str| rules.iter().find(|rule| rule.id == id).unwrap();

        let offline = by_id(BUILTIN_AGENT_OFFLINE);
        assert_eq!(
            offline.threshold, 120.0,
            "离线阈值必须取 alerts.offline_after_secs"
        );
        assert_eq!(offline.comparator, Comparator::Gt);

        let agent_cert = by_id(BUILTIN_AGENT_CERT);
        assert_eq!(
            agent_cert.metric, "cert.hours_left",
            "agent 证书规则必须使用小时指标"
        );
        assert_eq!(
            agent_cert.threshold, 72.0,
            "agent 证书阈值必须取 alerts.cert_warn_hours"
        );
        assert_eq!(agent_cert.comparator, Comparator::Lt);

        let hub_cert = by_id(BUILTIN_HUB_CERT);
        assert_eq!(
            hub_cert.threshold, 72.0,
            "hub 证书阈值必须取 alerts.cert_warn_hours"
        );
        assert_eq!(hub_cert.source, AlertSource::HubCert);
        assert_eq!(hub_cert.comparator, Comparator::Lt);

        // 非证书规则不受这两个配置影响。
        assert_eq!(by_id(BUILTIN_DISK_PERCENT).threshold, 90.0);
        assert_eq!(by_id(BUILTIN_BUFFER_BACKLOG).threshold, 0.8);
    }

    /// source / comparator 的字符串编码必须与 v7 表约定一致，且拒绝未知值。
    #[test]
    fn m4_b1_source_and_comparator_string_roundtrip() {
        for source in [
            AlertSource::Metric,
            AlertSource::AgentOffline,
            AlertSource::HubCert,
        ] {
            assert_eq!(AlertSource::parse(source.as_str()), Some(source));
            let json = serde_json::to_string(&source).unwrap();
            assert_eq!(json, format!("\"{}\"", source.as_str()));
            assert_eq!(serde_json::from_str::<AlertSource>(&json).unwrap(), source);
        }
        for invalid in ["", "Metric", "agent-offline", "hubcert", "system"] {
            assert_eq!(AlertSource::parse(invalid), None, "value={invalid:?}");
        }

        for comparator in [
            Comparator::Gt,
            Comparator::Gte,
            Comparator::Lt,
            Comparator::Lte,
            Comparator::Eq,
            Comparator::Ne,
        ] {
            assert_eq!(Comparator::parse(comparator.as_str()), Some(comparator));
            let json = serde_json::to_string(&comparator).unwrap();
            assert_eq!(json, format!("\"{}\"", comparator.as_str()));
            assert_eq!(
                serde_json::from_str::<Comparator>(&json).unwrap(),
                comparator
            );
        }
        for invalid in ["", "GT", "ge", "==", "not"] {
            assert_eq!(Comparator::parse(invalid), None, "value={invalid:?}");
        }
    }

    /// 规则名：中文可用；空 / 超长 / 首尾空白 / 控制字符必须拒绝。
    #[test]
    fn m4_b1_rule_name_validation() {
        validate_rule_name("Agent 离线").expect("中文规则名必须允许");
        validate_rule_name("disk high").expect("ASCII 空格必须允许");

        assert!(validate_rule_name("").is_err());
        assert!(validate_rule_name(" rule").is_err());
        assert!(validate_rule_name("rule ").is_err());
        assert!(validate_rule_name("bad\nname").is_err());
        let too_long = "名".repeat(22); // 66 字节，超过 64
        assert!(validate_rule_name(&too_long).is_err());

        // 错误信息不回显用户输入原文。
        let err = validate_rule_name(" bad\tname ").unwrap_err();
        assert!(!err.contains("bad"), "错误信息不能回显规则名: {err}");
    }

    /// metric / 时长 / 冷却 / labels / agent_id / channel_ids 的边界。
    #[test]
    fn m4_b1_field_validation_boundaries() {
        validate_metric("disk.used_percent").unwrap();
        validate_metric("a").unwrap();
        for invalid in ["", "Disk.Used", "disk used", "磁盘", "a/b"] {
            assert!(validate_metric(invalid).is_err(), "value={invalid:?}");
        }
        assert!(validate_metric(&"a".repeat(65)).is_err());

        validate_duration(0).unwrap();
        validate_duration(MAX_DURATION_SECS).unwrap();
        assert!(validate_duration(MAX_DURATION_SECS + 1).is_err());

        validate_cooldown(0).unwrap();
        validate_cooldown(MAX_COOLDOWN_SECS).unwrap();
        assert!(validate_cooldown(MAX_COOLDOWN_SECS + 1).is_err());

        let mut labels = Labels::new();
        labels.insert("mount".into(), "/".into());
        labels.insert("fs".into(), "ext4".into());
        validate_filter_labels(&labels).unwrap();

        let mut too_many = Labels::new();
        for index in 0..=MAX_FILTER_LABELS {
            too_many.insert(format!("k{index}"), "v".into());
        }
        assert!(validate_filter_labels(&too_many).is_err());
        let mut bad_key = Labels::new();
        bad_key.insert("bad key".into(), "v".into());
        assert!(validate_filter_labels(&bad_key).is_err());
        let mut bad_value = Labels::new();
        bad_value.insert("k".into(), "v".repeat(MAX_LABEL_VALUE_BYTES + 1));
        assert!(validate_filter_labels(&bad_value).is_err());

        validate_filter_agent_id("agent-1").unwrap();
        for invalid in ["", "agent 1", "agent/1", "a".repeat(65).as_str()] {
            assert!(
                validate_filter_agent_id(invalid).is_err(),
                "value={invalid:?}"
            );
        }

        validate_channel_ids(&[]).unwrap();
        let many: Vec<String> = (0..MAX_CHANNEL_IDS)
            .map(|index| format!("channel-{index}"))
            .collect();
        validate_channel_ids(&many).unwrap();
        // 重复项去重后不超过 16 个：允许。
        let with_dupes = vec!["channel-a".to_string(); 20];
        validate_channel_ids(&with_dupes).unwrap();
        assert_eq!(
            dedupe_channel_ids(&with_dupes),
            vec!["channel-a".to_string()]
        );
        let seventeen_unique: Vec<String> = (0..=MAX_CHANNEL_IDS)
            .map(|index| format!("channel-{index}"))
            .collect();
        assert!(validate_channel_ids(&seventeen_unique).is_err());
        assert!(validate_channel_ids(&["bad id".to_string()]).is_err());
    }

    /// `AlertRuleInput::validate`：未知字段由 serde 拒绝；组合校验拒绝非法 source/metric。
    #[test]
    fn m4_b1_input_validation_and_unknown_fields() {
        let input: AlertRuleInput = serde_json::from_str(
            r#"{"name":"磁盘告警","source":"metric","metric":"disk.used_percent","threshold":90}"#,
        )
        .unwrap();
        input.validate().unwrap();

        assert!(
            serde_json::from_str::<AlertRuleInput>(r#"{"name":"x","unknown":1}"#).is_err(),
            "未知字段必须被 deny_unknown_fields 拒绝"
        );

        // 非 metric 来源不能带 metric；metric 来源不能显式清空 metric。
        let input: AlertRuleInput =
            serde_json::from_str(r#"{"source":"hub_cert","metric":"disk.used_percent"}"#).unwrap();
        assert!(input.validate().is_err());
        let input: AlertRuleInput =
            serde_json::from_str(r#"{"source":"metric","metric":""}"#).unwrap();
        assert!(input.validate().is_err());

        // 阈值必须有限：serde_json 不能表示 NaN / Infinity，这里直接构造。
        let input = AlertRuleInput {
            threshold: Some(f64::NAN),
            ..AlertRuleInput::default()
        };
        assert!(input.validate().is_err());
        let input = AlertRuleInput {
            threshold: Some(f64::INFINITY),
            ..AlertRuleInput::default()
        };
        assert!(input.validate().is_err());

        // filter_agent_id：缺省 / null / 空串 / 合法值；非法值拒绝。
        let input: AlertRuleInput = serde_json::from_str("{}").unwrap();
        assert_eq!(input.filter_agent_id, None);
        let input: AlertRuleInput = serde_json::from_str(r#"{"filter_agent_id":null}"#).unwrap();
        assert_eq!(input.filter_agent_id, Some(None));
        let input: AlertRuleInput = serde_json::from_str(r#"{"filter_agent_id":""}"#).unwrap();
        assert_eq!(input.filter_agent_id, Some(Some(String::new())));
        input.validate().unwrap();
        let input: AlertRuleInput = serde_json::from_str(r#"{"filter_agent_id":"a b"}"#).unwrap();
        assert!(input.validate().is_err());
    }

    /// 部分更新语义：只传 enabled 只改启用状态；PUT 切换 source 自动清空 metric；
    /// 显式 null / 空串清空 filter_agent_id；channel_ids 去重。
    #[test]
    fn m4_b1_input_apply_to_merges_and_normalizes() {
        let mut rule = base_rule();
        rule.filter_agent_id = Some("agent-1".into());

        let input: AlertRuleInput = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        input.validate().unwrap();
        input.apply_to(&mut rule);
        assert!(rule.enabled);
        assert_eq!(rule.name, "磁盘告警", "未提供的字段必须保持原值");
        assert_eq!(rule.metric, "disk.used_percent");
        assert_eq!(rule.filter_agent_id, Some("agent-1".into()));

        let input: AlertRuleInput = serde_json::from_str(r#"{"filter_agent_id":null}"#).unwrap();
        input.validate().unwrap();
        input.apply_to(&mut rule);
        assert_eq!(rule.filter_agent_id, None);

        rule.filter_agent_id = Some("agent-2".into());
        let input: AlertRuleInput = serde_json::from_str(r#"{"filter_agent_id":""}"#).unwrap();
        input.apply_to(&mut rule);
        assert_eq!(rule.filter_agent_id, None);

        let input: AlertRuleInput =
            serde_json::from_str(r#"{"source":"agent_offline","threshold":90}"#).unwrap();
        input.validate().unwrap();
        input.apply_to(&mut rule);
        assert_eq!(rule.source, AlertSource::AgentOffline);
        assert_eq!(rule.metric, "", "切换 source 必须清空旧 metric");
        rule.validate_semantics().unwrap();

        let input: AlertRuleInput = serde_json::from_str(
            r#"{"name":"新名字","channel_ids":["c1","c1","c2"],"notify_on_resolve":false}"#,
        )
        .unwrap();
        input.validate().unwrap();
        input.apply_to(&mut rule);
        assert_eq!(rule.name, "新名字");
        assert_eq!(rule.channel_ids, vec!["c1".to_string(), "c2".to_string()]);
        assert!(!rule.notify_on_resolve);
    }

    /// 合并后的语义校验：metric 规则缺 metric、非 metric 留 metric 都必须拒绝。
    #[test]
    fn m4_b1_validate_semantics_rejects_inconsistent_rule() {
        let mut rule = base_rule();
        rule.metric.clear();
        assert!(rule.validate_semantics().is_err(), "metric 规则缺 metric");

        let mut rule = base_rule();
        rule.source = AlertSource::HubCert;
        assert!(
            rule.validate_semantics().is_err(),
            "非 metric 规则带 metric"
        );

        let mut rule = base_rule();
        rule.name.clear();
        assert!(rule.validate_semantics().is_err());

        let mut rule = base_rule();
        rule.threshold = f64::NAN;
        assert!(rule.validate_semantics().is_err());

        let mut rule = base_rule();
        rule.duration_secs = MAX_DURATION_SECS + 1;
        assert!(rule.validate_semantics().is_err());

        let mut rule = base_rule();
        rule.cooldown_secs = MAX_COOLDOWN_SECS + 1;
        assert!(rule.validate_semantics().is_err());

        let mut rule = base_rule();
        rule.channel_ids = (0..=MAX_CHANNEL_IDS)
            .map(|index| format!("c{index}"))
            .collect();
        assert!(rule.validate_semantics().is_err());

        let mut rule = base_rule();
        rule.filter_agent_id = Some("bad agent".into());
        assert!(rule.validate_semantics().is_err());
    }

    /// 领域错误的 Display 是可读中文，且不含用户输入。
    #[test]
    fn m4_b1_store_errors_are_readable_and_safe() {
        assert_eq!(AlertRuleStoreError::NotFound.to_string(), "告警规则不存在");
        assert!(AlertRuleStoreError::LimitReached
            .to_string()
            .contains(&MAX_ALERT_RULES.to_string()));
        for error in [
            AlertRuleStoreError::NameExists,
            AlertRuleStoreError::BuiltinRule,
            AlertRuleStoreError::ChannelNotFound,
            AlertRuleStoreError::ChannelDisabled,
        ] {
            let text = error.to_string();
            assert!(!text.is_empty());
            assert!(!text.contains('\n'));
        }
    }

    // ------------------------------------------------------------------
    // M4-B1b：比较符 / 状态机 / 事件 / 静默
    // ------------------------------------------------------------------

    fn state_at(kind: AlertStateKind, since: i64) -> AlertState {
        AlertState {
            rule_id: "rule-1".into(),
            agent_id: "agent-1".into(),
            series_key: "series-1".into(),
            state: kind,
            since,
            last_eval_at: since,
            last_value: Some(1.0),
            last_notified_at: Some(since - 5),
        }
    }

    /// 六种比较符的边界；NaN / 非有限阈值一律 false（包括 ne）。
    #[test]
    fn m4_b1b_evaluate_condition_boundaries() {
        assert!(evaluate_condition(Comparator::Gt, 90.0, 90.01));
        assert!(!evaluate_condition(Comparator::Gt, 90.0, 90.0));
        assert!(evaluate_condition(Comparator::Gte, 90.0, 90.0));
        assert!(!evaluate_condition(Comparator::Gte, 90.0, 89.99));
        assert!(evaluate_condition(Comparator::Lt, 48.0, 47.99));
        assert!(!evaluate_condition(Comparator::Lt, 48.0, 48.0));
        assert!(evaluate_condition(Comparator::Lte, 48.0, 48.0));
        assert!(!evaluate_condition(Comparator::Lte, 48.0, 48.01));
        assert!(evaluate_condition(Comparator::Eq, 1.5, 1.5));
        assert!(!evaluate_condition(Comparator::Eq, 1.5, 1.500_001));
        assert!(evaluate_condition(Comparator::Ne, 1.5, 1.500_001));
        assert!(!evaluate_condition(Comparator::Ne, 1.5, 1.5));

        for comparator in [
            Comparator::Gt,
            Comparator::Gte,
            Comparator::Lt,
            Comparator::Lte,
            Comparator::Eq,
            Comparator::Ne,
        ] {
            assert!(
                !evaluate_condition(comparator, 1.0, f64::NAN),
                "NaN value 必须 false: {comparator:?}"
            );
            assert!(
                !evaluate_condition(comparator, f64::NAN, 1.0),
                "NaN threshold 必须 false: {comparator:?}"
            );
            assert!(
                !evaluate_condition(comparator, f64::INFINITY, 1.0),
                "非有限阈值必须 false: {comparator:?}"
            );
            assert!(
                !evaluate_condition(comparator, f64::NEG_INFINITY, 1.0),
                "非有限阈值必须 false: {comparator:?}"
            );
        }
    }

    /// labels 精确子集：多出的 label 不影响，值不同不匹配。
    #[test]
    fn m4_b1b_labels_match_filter_is_exact_subset() {
        let mut filter = Labels::new();
        filter.insert("mount".into(), "/".into());
        let mut labels = Labels::new();
        labels.insert("mount".into(), "/".into());
        labels.insert("fs".into(), "ext4".into());
        assert!(labels_match_filter(&filter, &labels));
        assert!(
            labels_match_filter(&Labels::new(), &labels),
            "空过滤匹配全部"
        );

        let mut wrong = labels.clone();
        wrong.insert("mount".into(), "/data".into());
        assert!(!labels_match_filter(&filter, &wrong));
        assert!(
            !labels_match_filter(&filter, &Labels::new()),
            "缺少键不匹配"
        );
    }

    /// 序列键稳定（labels 顺序无关）、可区分、超长时有上限。
    #[test]
    fn m4_b1b_series_key_is_stable_and_bounded() {
        let mut first = Labels::new();
        first.insert("mount".into(), "/".into());
        first.insert("fs".into(), "ext4".into());
        let mut second = Labels::new();
        second.insert("fs".into(), "ext4".into());
        second.insert("mount".into(), "/".into());
        let key = series_key("disk.used_percent", &first);
        assert_eq!(key, series_key("disk.used_percent", &second));
        assert!(key.contains("disk.used_percent"));
        assert!(
            key.find("\"fs\"").unwrap() < key.find("\"mount\"").unwrap(),
            "labels 必须按字典序编码: {key}"
        );
        assert_ne!(key, series_key("disk.used_percent", &Labels::new()));

        let mut huge = Labels::new();
        huge.insert("blob".into(), "x".repeat(4_096));
        let huge_key = series_key("disk.used_percent", &huge);
        assert!(huge_key.len() <= MAX_SERIES_KEY_BYTES);
        assert_eq!(huge_key, series_key("disk.used_percent", &huge));
        assert!(huge_key.contains("sha256:"));

        let mut other = Labels::new();
        other.insert("blob".into(), "y".repeat(4_096));
        assert_ne!(huge_key, series_key("disk.used_percent", &other));
    }

    /// 无状态 + 条件满足：duration=0 立即 firing 并产生事件；否则先 pending。
    #[test]
    fn m4_b1b_first_observation_enters_pending_or_firing() {
        let mut rule = base_rule();
        rule.duration_secs = 300;
        let transition = next_alert_state(None, &rule, "agent-1", "series-1", 95.0, 1_000);
        let state = transition.state.expect("必须创建 pending 状态");
        assert_eq!(state.state, AlertStateKind::Pending);
        assert_eq!(state.since, 1_000);
        assert_eq!(state.last_eval_at, 1_000);
        assert_eq!(state.last_value, Some(95.0));
        assert_eq!(state.rule_id, "rule-1");
        assert_eq!(state.agent_id, "agent-1");
        assert_eq!(state.series_key, "series-1");
        assert_eq!(transition.event, None);

        rule.duration_secs = 0;
        let transition = next_alert_state(None, &rule, "agent-1", "series-1", 95.0, 1_000);
        let state = transition.state.expect("必须创建 firing 状态");
        assert_eq!(state.state, AlertStateKind::Firing);
        assert_eq!(state.since, 1_000);
        assert_eq!(transition.event, Some(AlertStateKind::Firing));

        // 无状态 + 条件不满足：不创建状态，也不产生事件。
        let rule = base_rule();
        let transition = next_alert_state(None, &rule, "agent-1", "series-1", 10.0, 1_000);
        assert_eq!(transition, AlertTransition::default());
    }

    /// pending 持续满足：未到 duration 不触发，到 duration 触发一次且不重复。
    #[test]
    fn m4_b1b_pending_waits_for_duration_then_fires_once() {
        let mut rule = base_rule();
        rule.duration_secs = 300;
        let start = 1_700_000_000_000;
        let pending = next_alert_state(None, &rule, "agent-1", "series-1", 95.0, start)
            .state
            .unwrap();

        let before = next_alert_state(
            Some(&pending),
            &rule,
            "agent-1",
            "series-1",
            95.0,
            start + 299_999,
        );
        let before_state = before.state.unwrap();
        assert_eq!(before_state.state, AlertStateKind::Pending);
        assert_eq!(before_state.since, start, "未到时长必须保持首次满足时间");
        assert_eq!(before_state.last_eval_at, start + 299_999);
        assert_eq!(before.event, None);

        let firing = next_alert_state(
            Some(&before_state),
            &rule,
            "agent-1",
            "series-1",
            97.0,
            start + 300_000,
        );
        let firing_state = firing.state.unwrap();
        assert_eq!(firing_state.state, AlertStateKind::Firing);
        assert_eq!(firing_state.since, start + 300_000);
        assert_eq!(firing.event, Some(AlertStateKind::Firing));
        assert_eq!(
            firing_state.last_notified_at, None,
            "由无状态创建的 pending 从未通知过"
        );

        // 已有状态里的 last_notified_at（B2 写入）在推进时必须原样保留。
        let notified_pending = state_at(AlertStateKind::Pending, start);
        assert_eq!(notified_pending.last_notified_at, Some(start - 5));
        let fired = next_alert_state(
            Some(&notified_pending),
            &rule,
            "agent-1",
            "series-1",
            95.0,
            start + 300_000,
        );
        assert_eq!(
            fired.state.unwrap().last_notified_at,
            Some(start - 5),
            "last_notified_at 必须保留"
        );

        let again = next_alert_state(
            Some(&firing_state),
            &rule,
            "agent-1",
            "series-1",
            98.0,
            start + 315_000,
        );
        let again_state = again.state.unwrap();
        assert_eq!(again_state.state, AlertStateKind::Firing);
        assert_eq!(again_state.since, start + 300_000, "firing 不重置 since");
        assert_eq!(again.event, None, "firing 不能重复产生事件");
    }

    /// 恢复：firing → resolved 产生事件；pending → resolved 不产生事件。
    #[test]
    fn m4_b1b_recovery_events_only_after_firing() {
        let rule = base_rule();

        let pending = state_at(AlertStateKind::Pending, 1_000);
        let resolved = next_alert_state(Some(&pending), &rule, "agent-1", "series-1", 10.0, 2_000);
        let resolved_state = resolved.state.unwrap();
        assert_eq!(resolved_state.state, AlertStateKind::Resolved);
        assert_eq!(resolved_state.since, 2_000);
        assert_eq!(resolved.event, None, "pending 恢复不产生事件");

        let firing = state_at(AlertStateKind::Firing, 1_000);
        let resolved = next_alert_state(Some(&firing), &rule, "agent-1", "series-1", 10.0, 2_000);
        let resolved_state = resolved.state.unwrap();
        assert_eq!(resolved_state.state, AlertStateKind::Resolved);
        assert_eq!(resolved.event, Some(AlertStateKind::Resolved));

        // resolved + 条件仍不满足：状态不变、since 不变，只刷新评估时间。
        let again = next_alert_state(
            Some(&resolved_state),
            &rule,
            "agent-1",
            "series-1",
            9.0,
            3_000,
        );
        let again_state = again.state.unwrap();
        assert_eq!(again_state.state, AlertStateKind::Resolved);
        assert_eq!(again_state.since, 2_000);
        assert_eq!(again_state.last_eval_at, 3_000);
        assert_eq!(again.event, None);
    }

    /// 重触发：resolved + 条件满足 → pending 重新计时；duration=0 时同轮 firing。
    #[test]
    fn m4_b1b_resolved_retriggers_with_fresh_duration() {
        let mut rule = base_rule();
        rule.duration_secs = 60;
        let resolved = state_at(AlertStateKind::Resolved, 1_000);

        let retrigger =
            next_alert_state(Some(&resolved), &rule, "agent-1", "series-1", 95.0, 5_000);
        let retrigger_state = retrigger.state.unwrap();
        assert_eq!(retrigger_state.state, AlertStateKind::Pending);
        assert_eq!(retrigger_state.since, 5_000, "必须重新计时");
        assert_eq!(retrigger.event, None);

        let firing = next_alert_state(
            Some(&retrigger_state),
            &rule,
            "agent-1",
            "series-1",
            95.0,
            65_000,
        );
        assert_eq!(firing.state.unwrap().state, AlertStateKind::Firing);
        assert_eq!(firing.event, Some(AlertStateKind::Firing));

        rule.duration_secs = 0;
        let immediate =
            next_alert_state(Some(&resolved), &rule, "agent-1", "series-1", 95.0, 5_000);
        let immediate_state = immediate.state.unwrap();
        assert_eq!(immediate_state.state, AlertStateKind::Firing);
        assert_eq!(immediate.event, Some(AlertStateKind::Firing));
    }

    /// 事件描述：中文、含规则名 / agent / 值 / 阈值、不含 labels 与换行，≤512 字节。
    #[test]
    fn m4_b1b_event_message_is_safe_and_bounded() {
        let mut rule = base_rule();
        rule.filter_labels
            .insert("mount".into(), "/secret-mount".into());
        let message = alert_event_message(&rule, "agent-1", AlertStateKind::Firing, 95.5);
        assert!(message.contains("磁盘告警"), "必须包含规则名: {message}");
        assert!(message.contains("agent-1"), "必须包含 agent: {message}");
        assert!(message.contains("95.5"), "必须包含观测值: {message}");
        assert!(message.contains("90"), "必须包含阈值: {message}");
        assert!(message.contains('>'), "必须包含比较符: {message}");
        assert!(
            !message.contains("secret-mount"),
            "不能写完整 labels: {message}"
        );
        assert!(!message.contains('\n'));

        let resolved = alert_event_message(&rule, "agent-1", AlertStateKind::Resolved, 12.0);
        assert!(resolved.contains("恢复"));
        assert!(resolved.contains("12"));

        rule.source = AlertSource::AgentOffline;
        rule.metric.clear();
        let offline = alert_event_message(&rule, "agent-1", AlertStateKind::Firing, 120.0);
        assert!(offline.contains("离线") && offline.contains("120"));

        rule.source = AlertSource::HubCert;
        let cert = alert_event_message(&rule, "", AlertStateKind::Firing, 20.0);
        assert!(cert.contains("证书") && cert.contains("全局"), "{cert}");
        assert!(
            cert.contains("小时"),
            "hub_cert 事件必须以小时为单位: {cert}"
        );
        assert!(!cert.contains("天"), "hub_cert 事件不能再用天: {cert}");

        // 超长消息：严格按 UTF-8 边界截断到 512 字节以内。
        let mut long = base_rule();
        long.name = "超长规则名称".repeat(9);
        let long_message =
            alert_event_message(&long, "agent-1", AlertStateKind::Firing, 1.234_567_89e300);
        assert!(long_message.len() <= MAX_ALERT_MESSAGE_BYTES);
        assert!(long_message.ends_with('…'));
    }

    /// 事件构造：notified 恒 false、notify_error 空、silenced 透传、值非有限存 None。
    #[test]
    fn m4_b1b_new_event_defaults_to_not_notified() {
        let rule = base_rule();
        let event = new_alert_event(
            &rule,
            "agent-1",
            "series-1",
            AlertStateKind::Firing,
            95.0,
            7_000,
            true,
        );
        assert_eq!(event.id, 0);
        assert_eq!(event.ts, 7_000);
        assert_eq!(event.rule_id, "rule-1");
        assert_eq!(event.rule_name, "磁盘告警");
        assert_eq!(event.agent_id, "agent-1");
        assert_eq!(event.series_key, "series-1");
        assert_eq!(event.state, AlertStateKind::Firing);
        assert_eq!(event.value, Some(95.0));
        assert!(!event.notified);
        assert!(event.notify_error.is_empty());
        assert!(event.silenced);

        let nan = new_alert_event(
            &rule,
            "agent-1",
            "series-1",
            AlertStateKind::Resolved,
            f64::NAN,
            7_000,
            false,
        );
        assert_eq!(nan.value, None);
        assert!(!nan.silenced);
    }

    /// 静默匹配：NULL 通配、规则 / agent 精确、until_ts 排他边界。
    #[test]
    fn m4_b1b_silence_matching_window_and_wildcards() {
        let silence = AlertSilence {
            id: 1,
            rule_id: None,
            agent_id: None,
            until_ts: 10_000,
            created_by: "admin".into(),
            created_at: 1_000,
        };
        assert!(silence.matches("rule-1", "agent-1", 9_999));
        assert!(
            !silence.matches("rule-1", "agent-1", 10_000),
            "到期时刻不生效"
        );
        assert!(!silence.matches("rule-1", "agent-1", 10_001));

        let rule_only = AlertSilence {
            rule_id: Some("rule-1".into()),
            agent_id: None,
            ..silence.clone()
        };
        assert!(rule_only.matches("rule-1", "any-agent", 1_000));
        assert!(!rule_only.matches("rule-2", "any-agent", 1_000));

        let agent_only = AlertSilence {
            rule_id: None,
            agent_id: Some("agent-1".into()),
            ..silence.clone()
        };
        assert!(agent_only.matches("any-rule", "agent-1", 1_000));
        assert!(!agent_only.matches("any-rule", "agent-2", 1_000));

        let both = AlertSilence {
            rule_id: Some("rule-1".into()),
            agent_id: Some("agent-1".into()),
            ..silence.clone()
        };
        assert!(both.matches("rule-1", "agent-1", 1_000));
        assert!(!both.matches("rule-1", "agent-2", 1_000));
    }

    /// 静默请求校验：时长边界、rule / agent 格式、未知字段、into_silence 时间计算。
    #[test]
    fn m4_b1b_silence_input_validation_and_build() {
        let input: AlertSilenceInput =
            serde_json::from_str(r#"{"rule_id":"builtin-disk-percent","duration_secs":60}"#)
                .unwrap();
        input.validate().unwrap();
        let silence = input.into_silence(1_000, "admin".into());
        assert_eq!(silence.id, 0);
        assert_eq!(silence.rule_id.as_deref(), Some("builtin-disk-percent"));
        assert_eq!(silence.agent_id, None);
        assert_eq!(silence.until_ts, 61_000);
        assert_eq!(silence.created_at, 1_000);
        assert_eq!(silence.created_by, "admin");

        for body in [
            // 缺少 duration_secs（必填）。
            r#"{"rule_id":"rule-1"}"#,
            // 未知字段。
            r#"{"duration_secs":60,"created_by":"attacker"}"#,
            // 时长边界。
            r#"{"duration_secs":0}"#,
            r#"{"duration_secs":604801}"#,
            // 非法 rule / agent。
            r#"{"duration_secs":60,"rule_id":""}"#,
            r#"{"duration_secs":60,"rule_id":"bad id"}"#,
            r#"{"duration_secs":60,"agent_id":"bad agent"}"#,
            r#"{"duration_secs":60,"agent_id":""}"#,
        ] {
            let result = serde_json::from_str::<AlertSilenceInput>(body)
                .map_err(|err| err.to_string())
                .and_then(|input| input.validate());
            assert!(result.is_err(), "body 必须被拒绝: {body}");
        }

        let max: AlertSilenceInput =
            serde_json::from_str(r#"{"duration_secs":604800,"rule_id":null,"agent_id":null}"#)
                .unwrap();
        max.validate().unwrap();
        let silence = max.into_silence(0, "admin".into());
        assert_eq!(silence.until_ts, 604_800_000);

        let min: AlertSilenceInput = serde_json::from_str(r#"{"duration_secs":1}"#).unwrap();
        min.validate().unwrap();
        assert_eq!(min.into_silence(0, "admin".into()).until_ts, 1_000);
    }
}
