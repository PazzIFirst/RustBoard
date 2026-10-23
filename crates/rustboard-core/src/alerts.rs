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
//! - `channel_ids` 只校验格式与数量，不查渠道是否存在（渠道 CRUD 在 B2）；
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
    /// hub 服务端证书剩余天数。
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

/// 一条告警规则（schema v7 `alert_rules` 的一行，JSON 即管理 API 结构）。
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
    /// 绑定的通知渠道 id；B1a 只存不校验渠道是否存在。
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
}

impl fmt::Display for AlertRuleStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "告警规则不存在"),
            Self::NameExists => write!(f, "告警规则名称已存在"),
            Self::LimitReached => write!(f, "告警规则数量已达上限 {MAX_ALERT_RULES} 条"),
            Self::BuiltinRule => write!(f, "内置告警规则不允许删除"),
        }
    }
}

impl std::error::Error for AlertRuleStoreError {}

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
pub fn builtin_rules(now: i64) -> Vec<AlertRule> {
    vec![
        builtin_rule(
            BUILTIN_AGENT_OFFLINE,
            "Agent 离线",
            AlertSource::AgentOffline,
            "",
            Comparator::Gt,
            90.0,
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
            "cert.days_left",
            Comparator::Lt,
            48.0,
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
            48.0,
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
    }
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
        }
    }

    /// 内置规则：固定 id、5 条、全部 disabled、is_builtin、无渠道、阈值语义正确。
    #[test]
    fn m4_b1_builtin_rules_are_fixed_disabled_and_channel_free() {
        let rules = builtin_rules(1_700_000_000_000);
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
        assert_eq!(cert.metric, "cert.days_left");
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
        ] {
            let text = error.to_string();
            assert!(!text.is_empty());
            assert!(!text.contains('\n'));
        }
    }
}
