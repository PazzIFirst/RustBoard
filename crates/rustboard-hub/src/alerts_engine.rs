//! M4-B1b：告警评估引擎。
//!
//! 一轮评估（[`evaluate_once`]）是**同步纯函数式**的：调用方给出 `now`，引擎只
//! 读取存储、推进状态机、写状态与事件，最后按小时做一次保留期清理。后台任务
//! （[`spawn_alert_engine`]）只是按 `alerts.evaluation_interval_secs` 循环调用它。
//!
//! 规则语义（与方案 §6.1–6.3 一致）：
//! - `metric`：查 `now - max(evaluation_interval * 3, 60s)` 窗口内的最新 **raw**
//!   样本，按 `filter_agent_id` / `filter_labels`（精确子集）过滤，每个序列独立
//!   状态。**只读 raw、不回退 1m/1h**：旧聚合桶的 `last_value` 不能当当前值，
//!   否则会产生误触发 / 误恢复；每规则最多 [`MAX_ALERT_SERIES_PER_RULE`] 条序列，
//!   超出时截断并 WARN，绝不因为行数过多跳过整条规则；
//! - `agent_offline`：`now - agents.last_seen_at` 与阈值（秒）比较；每个 agent
//!   一条状态（`series_key` 为空），已吊销 agent 跳过；
//! - `hub_cert`：读取 `cfg.data_dir/certs/server.crt` 的剩余**小时数**
//!   （与 `cert_warn_hours` 同单位），全局一条状态；读盘 / 解析失败只 WARN 并
//!   跳过本轮，**绝不 resolve**。
//!
//! 资源边界：
//! - 每轮最多 [`MAX_ALERT_RULES`] 条规则；
//! - 每规则最多 [`MAX_ALERT_SERIES_PER_RULE`] 条序列；
//! - 单轮时间预算 `alerts.evaluation_budget_ms`，超时停止后续规则并在报告 /
//!   WARN 中记录；
//! - 一条规则的状态与事件合并为**单事务批量写入**，避免逐序列抢写锁阻塞 ingest；
//! - 事件保留 / 状态清理 / 静默过期最多每小时执行一次（`maintenance_state` 记水位），
//!   避免每 15 秒全表 COUNT / DELETE。
//!
//! 配置说明：`HubAlertsConfig::offline_after_secs` / `cert_warn_hours` 只用于
//! 生成内置规则的默认阈值。评估时**规则自身的 threshold 才是权威**——用户改过
//! 阈值后，引擎不会被配置项覆盖。`notify_*` 留给 B2。
//!
//! 安全约定：日志只输出规则 id、计数与上限，不输出样本值之外的 secret；事件
//! message 由 [`rustboard_core::alerts::alert_event_message`] 生成，不含 labels
//! 全量。所有 SQL 参数化。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rustboard_common::config::HubConfig;
use rustboard_common::model::AgentRecord;
use rustboard_common::tls;
use rustboard_common::util::now_ms;
use rustboard_core::alerts::{
    self, AlertEvent, AlertRule, AlertSilence, AlertSource, AlertState, AlertStateKind,
    MAX_ALERT_RULES,
};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::Storage;

/// metric 规则回看窗口下限：60 秒。
///
/// 采样间隔通常 5–60 秒；窗口只要覆盖最近 3 个评估周期即可发现新样本。低于
/// 60 秒会让 15 秒评估周期在 agent 偶发延迟时误判「无样本」。
const METRIC_LOOKBACK_MIN_SECS: u64 = 60;

/// metric 回看窗口 = `evaluation_interval_secs * 3`。
const METRIC_LOOKBACK_INTERVALS: u64 = 3;

/// 单条规则每轮最多评估的序列数（raw-only 查询上限）。
///
/// 5000 条已经远超正常单 metric 的序列数；达到上限说明 labels 基数异常或规则
/// 过滤过宽。引擎截断并 WARN，而不是让查询失败或把整轮评估拖死。
pub(crate) const MAX_ALERT_SERIES_PER_RULE: usize = 5_000;

/// resolved 状态保留 30 天（方案 §6.2）。
pub(crate) const RESOLVED_STATE_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// 陈旧 pending / firing 状态保留 30 天。
///
/// 序列消失、agent 被删除、规则被直接停用但没走 API 时，状态不再被评估推进；
/// 超过保留期后清理，避免 `alert_states` 无界增长。规则禁用 / 删除走 API 时
/// 会立即清理，不依赖这里。
pub(crate) const STALE_STATE_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// 单次清理陈旧状态的最大行数，避免一次 DELETE 长时间占用写锁。
const MAX_STALE_STATE_PRUNE_ROWS: usize = 5_000;

/// 历史数据清理频率：1 小时。
///
/// 之前每轮（默认 15s）都执行事件 COUNT / resolved 删除 / 静默删除，规则多或
/// 事件表大时会在每轮评估后制造一次全表扫描。改为按小时清理，错误下一小时重试。
pub(crate) const PRUNE_INTERVAL_MS: i64 = 60 * 60 * 1_000;

/// `maintenance_state` 里记录最近一次告警清理的时间。
const PRUNE_STATE_KEY: &str = "alert_engine_last_prune_ts";

/// 一轮评估的统计结果；只含计数，可安全写入日志。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct EvaluationReport {
    /// 本轮实际完成评估的规则数（受 [`MAX_ALERT_RULES`] 与时间预算截断）。
    pub rules_evaluated: usize,
    /// 实际进入状态机的序列数（metric 每个序列、离线每个 agent、证书全局 1 条）。
    pub series_evaluated: usize,
    /// 写入 / 更新的状态行数。
    pub state_writes: usize,
    /// 新产生的 firing 事件数。
    pub firing_events: usize,
    /// 新产生的 resolved 事件数。
    pub resolved_events: usize,
    /// 命中静默的事件数（包含在 firing / resolved 计数内）。
    pub silenced_events: usize,
    /// 单条规则查询失败而跳过的次数（不会推进状态）。
    pub evaluation_errors: usize,
    /// hub 证书读取 / 解析失败次数（该轮跳过 hub_cert 规则）。
    pub cert_read_errors: usize,
    /// 因达到 [`MAX_ALERT_SERIES_PER_RULE`] 而截断的规则数。
    pub truncated_rules: usize,
    /// 因时间预算耗尽而跳过的规则数。
    pub rules_skipped_budget: usize,
    /// 清理的事件数。
    pub pruned_events: usize,
    /// 清理的 resolved 状态数。
    pub pruned_states: usize,
    /// 清理的陈旧 pending / firing 状态数（有单次行数上限）。
    pub pruned_stale_states: usize,
    /// 清理的过期静默数。
    pub pruned_silences: usize,
}

/// 执行一轮告警评估（固定 `now`，可直接单测）。
///
/// 流程：读取启用规则与生效静默 → 逐条规则查询观测值并推进状态机 → 单事务批量
/// 落库该规则的状态 / 事件 → 预算允许时按小时清理过期数据。
///
/// 任何单条规则的查询失败只记 WARN 与计数，**不会**把状态误判成 resolved；
/// 存储写入失败则整轮返回错误，下一轮重试。
pub(crate) fn evaluate_once(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    now: i64,
) -> Result<EvaluationReport> {
    evaluate_once_with_cert_hours(storage, cfg, now, |cfg| hub_cert_hours_left(cfg, now))
}

/// 带证书剩余小时数注入的评估入口，供单测替换真实证书读取。
///
/// 生产路径使用 [`evaluate_once`]；测试传 `|_| Ok(20)` 之类的闭包即可覆盖
/// hub_cert 规则，无需真实证书文件。单位与规则阈值一致：**小时**。
pub(crate) fn evaluate_once_with_cert_hours<F>(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    now: i64,
    cert_hours: F,
) -> Result<EvaluationReport>
where
    F: Fn(&HubConfig) -> Result<i64>,
{
    evaluate_with_options(
        storage,
        cfg,
        now,
        cert_hours,
        MAX_ALERT_SERIES_PER_RULE,
        round_budget(cfg),
    )
}

/// 单轮时间预算；配置下限是 100ms，`max(1)` 只防御未校验的外部构造。
fn round_budget(cfg: &HubConfig) -> Duration {
    Duration::from_millis(cfg.alerts.evaluation_budget_ms.max(1))
}

/// 评估入口的完整参数版本：测试可注入更小的序列上限 / 预算，避免构造 5001
/// 条序列或等待真实时间。
fn evaluate_with_options<F>(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    now: i64,
    cert_hours: F,
    max_series_per_rule: usize,
    budget: Duration,
) -> Result<EvaluationReport>
where
    F: Fn(&HubConfig) -> Result<i64>,
{
    let started = Instant::now();
    let rules = storage.list_enabled_alert_rules()?;
    let rule_count = rules.len().min(MAX_ALERT_RULES);
    if rules.len() > MAX_ALERT_RULES {
        tracing::warn!(
            rules = rules.len(),
            max_rules = MAX_ALERT_RULES,
            "启用规则数超过单轮上限，本轮只评估前 {MAX_ALERT_RULES} 条"
        );
    }
    let silences = storage.list_active_silences(now)?;
    let mut report = EvaluationReport::default();

    // 离线规则共用一份 agent 列表；hub_cert 规则共用一次证书读取。
    let mut agents: Option<Vec<AgentRecord>> = None;
    let mut cert_hours_cache: Option<Option<i64>> = None;

    for (index, rule) in rules.iter().take(MAX_ALERT_RULES).enumerate() {
        if started.elapsed() >= budget {
            report.rules_skipped_budget = rule_count.saturating_sub(index);
            tracing::warn!(
                budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
                skipped = report.rules_skipped_budget,
                "告警评估时间预算耗尽，跳过本轮剩余规则"
            );
            break;
        }

        // 每条规则只读一次状态；后续全部状态推进在内存里完成。
        let existing_states = storage.list_alert_states_for_rule(&rule.id)?;
        let mut evaluator = RuleEvaluator::new(rule, now, &silences, existing_states);

        let truncated = match rule.source {
            AlertSource::Metric => {
                let since = now.saturating_sub(metric_lookback_ms(cfg));
                // raw-only + 有界查询：绝不回退 1m/1h，也绝不因行数过多返回
                // QueryTooLarge 而跳过整条规则。
                let snapshot = match storage.latest_alert_series(
                    &rule.metric,
                    since,
                    rule.filter_agent_id.as_deref(),
                    max_series_per_rule,
                ) {
                    Ok(snapshot) => snapshot,
                    Err(err) => {
                        report.evaluation_errors += 1;
                        tracing::warn!(
                            rule_id = %rule.id,
                            error = %err,
                            "查询告警指标失败，本轮跳过该规则（不改状态）"
                        );
                        continue;
                    }
                };
                for row in &snapshot.rows {
                    if !alerts::labels_match_filter(&rule.filter_labels, &row.labels) {
                        continue;
                    }
                    let key = alerts::series_key(&row.metric, &row.labels);
                    evaluator.observe(&row.agent_id, &key, row.value);
                }
                snapshot.truncated
            }
            AlertSource::AgentOffline => {
                if agents.is_none() {
                    agents = Some(storage.list_agents()?);
                }
                for agent in agents.as_deref().unwrap_or(&[]) {
                    // 吊销是终态：不再产生 / 恢复告警，避免误报。
                    if agent.status == "revoked" {
                        continue;
                    }
                    // last_seen_at = 0 表示从未成功握手（刚入库 / 种子数据）：
                    // 状态未知，不能当成“已经离线很久”而立刻告警。
                    if agent.last_seen_at <= 0 {
                        continue;
                    }
                    if let Some(filter) = &rule.filter_agent_id {
                        if filter != &agent.agent_id {
                            continue;
                        }
                    }
                    let elapsed_ms = now.saturating_sub(agent.last_seen_at).max(0);
                    let elapsed_secs = elapsed_ms as f64 / 1_000.0;
                    evaluator.observe(&agent.agent_id, "", elapsed_secs);
                }
                false
            }
            AlertSource::HubCert => {
                let cached = match cert_hours_cache {
                    Some(value) => value,
                    None => {
                        let loaded = match cert_hours(cfg) {
                            Ok(hours) => Some(hours),
                            Err(err) => {
                                report.cert_read_errors += 1;
                                tracing::warn!(
                                    rule_id = %rule.id,
                                    error = %err,
                                    "读取 Hub 服务端证书失败，本轮跳过 hub_cert 规则（不改状态）"
                                );
                                None
                            }
                        };
                        cert_hours_cache = Some(loaded);
                        loaded
                    }
                };
                if let Some(hours) = cached {
                    evaluator.observe("", "", hours as f64);
                }
                false
            }
        };

        if truncated {
            report.truncated_rules += 1;
            tracing::warn!(
                rule_id = %rule.id,
                limit = max_series_per_rule,
                "告警规则序列数达到单轮上限，已截断；请收窄 agent 范围或拆分规则"
            );
        }

        let batch = evaluator.finish();
        // 单事务批量写入：事件先、状态后；一条规则只抢一次写锁。
        storage.apply_alert_transitions(&batch.events, &batch.states)?;
        report.rules_evaluated += 1;
        report.series_evaluated += batch.series_evaluated;
        report.state_writes += batch.states.len();
        report.firing_events += batch.firing_events;
        report.resolved_events += batch.resolved_events;
        report.silenced_events += batch.silenced_events;
    }

    prune_history_if_due(storage, cfg, now, &mut report);
    Ok(report)
}

/// 一条规则本轮要写入的状态与事件；先在内存里攒齐，再一次性落库。
#[derive(Debug, Default)]
struct RuleEvaluation {
    states: Vec<AlertState>,
    events: Vec<AlertEvent>,
    series_evaluated: usize,
    firing_events: usize,
    resolved_events: usize,
    silenced_events: usize,
}

/// 单条规则的状态机执行器：持有该规则既有状态、本轮观测与输出批次。
struct RuleEvaluator<'a> {
    rule: &'a AlertRule,
    now: i64,
    silences: &'a [AlertSilence],
    existing: HashMap<String, AlertState>,
    batch: RuleEvaluation,
}

impl<'a> RuleEvaluator<'a> {
    fn new(
        rule: &'a AlertRule,
        now: i64,
        silences: &'a [AlertSilence],
        states: Vec<AlertState>,
    ) -> Self {
        let existing = states
            .into_iter()
            .map(|state| (state_key(&state.agent_id, &state.series_key), state))
            .collect();
        Self {
            rule,
            now,
            silences,
            existing,
            batch: RuleEvaluation::default(),
        }
    }

    /// 推进一个序列并在内存里累计状态 / 事件。
    fn observe(&mut self, agent_id: &str, series_key: &str, value: f64) {
        let key = state_key(agent_id, series_key);
        let existing = self.existing.get(&key);
        let transition =
            alerts::next_alert_state(existing, self.rule, agent_id, series_key, value, self.now);
        self.batch.series_evaluated += 1;

        if let Some(kind) = transition.event {
            // 静默只影响通知（B2），事件仍必须落库，面板才能看到「静默中」。
            let silenced = self
                .silences
                .iter()
                .any(|silence| silence.matches(&self.rule.id, agent_id, self.now));
            self.batch.events.push(alerts::new_alert_event(
                self.rule, agent_id, kind, value, self.now, silenced,
            ));
            match kind {
                AlertStateKind::Firing => self.batch.firing_events += 1,
                AlertStateKind::Resolved => self.batch.resolved_events += 1,
                AlertStateKind::Pending => {}
            }
            if silenced {
                self.batch.silenced_events += 1;
            }
        }

        if let Some(state) = transition.state {
            self.batch.states.push(state);
        }
    }

    fn finish(self) -> RuleEvaluation {
        self.batch
    }
}

/// `(agent_id, series_key)` 的复合键。
///
/// 用长度前缀而不是分隔符，避免 agent_id / series_key 里出现分隔符时键冲突。
fn state_key(agent_id: &str, series_key: &str) -> String {
    let mut key = String::with_capacity(agent_id.len() + series_key.len() + 8);
    key.push_str(&agent_id.len().to_string());
    key.push(':');
    key.push_str(agent_id);
    key.push_str(series_key);
    key
}

/// 按小时执行一次清理；水位存 `maintenance_state`，重启后继续遵守。
///
/// 读取水位失败时照常清理（避免坏键让清理永久停摆）；清理失败只 WARN，水位仍
/// 推进到本轮，最多一小时后重试，避免每轮反复 COUNT / DELETE。
fn prune_history_if_due(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    now: i64,
    report: &mut EvaluationReport,
) {
    let due = match storage.get_maintenance_state(PRUNE_STATE_KEY) {
        Ok(Some(value)) => value
            .parse::<i64>()
            .map(|last| now.saturating_sub(last) >= PRUNE_INTERVAL_MS)
            .unwrap_or(true),
        Ok(None) => true,
        Err(err) => {
            tracing::warn!(error = %err, "读取告警清理水位失败，本轮仍执行清理");
            true
        }
    };
    if !due {
        return;
    }
    prune_history(storage, cfg, now, report);
    if let Err(err) = storage.set_maintenance_state(PRUNE_STATE_KEY, &now.to_string(), now) {
        tracing::warn!(error = %err, "写入告警清理水位失败，下一小时可能重复清理");
    }
}

/// 清理过期事件 / resolved 状态 / 静默。失败只 WARN，不影响本轮评估结果。
fn prune_history(
    storage: &SqliteStorage,
    cfg: &HubConfig,
    now: i64,
    report: &mut EvaluationReport,
) {
    let retention_ms =
        i64::from(cfg.alerts.event_retention_days).saturating_mul(24 * 60 * 60 * 1_000);
    let max_rows = usize::try_from(cfg.alerts.max_events).unwrap_or(usize::MAX);
    match storage.prune_alert_events(now.saturating_sub(retention_ms), max_rows) {
        Ok(removed) => report.pruned_events = removed,
        Err(err) => tracing::warn!(error = %err, "清理告警事件失败，下一小时重试"),
    }
    match storage.prune_alert_states(now.saturating_sub(RESOLVED_STATE_RETENTION_MS)) {
        Ok(removed) => report.pruned_states = removed,
        Err(err) => tracing::warn!(error = %err, "清理 resolved 告警状态失败，下一小时重试"),
    }
    match storage.prune_stale_alert_states(
        now.saturating_sub(STALE_STATE_RETENTION_MS),
        MAX_STALE_STATE_PRUNE_ROWS,
    ) {
        Ok(removed) => report.pruned_stale_states = removed,
        Err(err) => tracing::warn!(error = %err, "清理陈旧告警状态失败，下一小时重试"),
    }
    match storage.prune_alert_silences(now) {
        Ok(removed) => report.pruned_silences = removed,
        Err(err) => tracing::warn!(error = %err, "清理过期静默失败，下一小时重试"),
    }
}

/// metric 规则的回看窗口（毫秒）：`max(evaluation_interval * 3, 60s)`。
fn metric_lookback_ms(cfg: &HubConfig) -> i64 {
    let secs = cfg
        .alerts
        .evaluation_interval_secs
        .saturating_mul(METRIC_LOOKBACK_INTERVALS)
        .max(METRIC_LOOKBACK_MIN_SECS);
    i64::try_from(secs)
        .unwrap_or(i64::MAX)
        .saturating_mul(1_000)
}

/// 读取 hub 服务端证书剩余小时数（`data_dir/certs/server.crt`）。
///
/// **单位是小时**：规则阈值来自 `alerts.cert_warn_hours`（如 48 小时）。旧实现
/// 用 `days_left` 与「48」比较，等于把阈值放大成 48 天，证书快到期也不会告警。
/// 只读磁盘上的当前证书：证书轮换 / 续签后下一轮自动使用新值。读取或解析失败
/// 由调用方 WARN 并跳过，不会 resolve。
fn hub_cert_hours_left(cfg: &HubConfig, now: i64) -> Result<i64> {
    let path = tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE);
    let pem = std::fs::read_to_string(&path)
        .with_context(|| format!("读取服务端证书失败: {}", path.display()))?;
    tls::hours_left(&pem, now).context("解析服务端证书失败")
}

/// 启动后台告警评估任务。
///
/// - `alerts.enabled = false`：只记一条 INFO，不启动循环；
/// - 启动后先睡一个周期，避免与监听启动抢 SQLite 写锁；
/// - 每轮在 `spawn_blocking` 内串行执行，错误只 WARN，任务不退出；
/// - 日志只输出计数，不输出 secret。
pub(crate) fn spawn_alert_engine(storage: Arc<SqliteStorage>, cfg: HubConfig) {
    if !cfg.alerts.enabled {
        tracing::info!("告警引擎未启用（alerts.enabled = false）");
        return;
    }
    tokio::spawn(async move {
        // 配置校验保证 1–3600；`max(1)` 只防御非法配置造成的忙循环。
        let interval = Duration::from_secs(cfg.alerts.evaluation_interval_secs.max(1));
        tracing::info!(
            interval_secs = interval.as_secs(),
            budget_ms = cfg.alerts.evaluation_budget_ms,
            "告警评估任务已启动（先等待一个周期）"
        );
        loop {
            tokio::time::sleep(interval).await;
            let storage = storage.clone();
            let cfg = cfg.clone();
            let outcome =
                tokio::task::spawn_blocking(move || evaluate_once(&storage, &cfg, now_ms())).await;
            match outcome {
                Ok(Ok(report)) => {
                    if report.firing_events > 0
                        || report.resolved_events > 0
                        || report.rules_skipped_budget > 0
                    {
                        tracing::info!(?report, "告警评估完成");
                    } else {
                        tracing::debug!(?report, "告警评估完成");
                    }
                }
                Ok(Err(err)) => tracing::warn!(error = %err, "告警评估失败，下一轮重试"),
                Err(err) => tracing::warn!(error = %err, "告警评估任务异常结束，下一轮继续"),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use rustboard_common::model::{Labels, Sample, SampleBatch};
    use rustboard_core::alerts::{AlertState, Comparator};

    use super::*;

    fn test_cfg() -> HubConfig {
        HubConfig {
            data_dir: PathBuf::from("/tmp/rb-alert-engine-unused-data-dir"),
            ..HubConfig::default()
        }
    }

    fn seed_agent(storage: &SqliteStorage, id: &str, last_seen_at: i64) {
        storage
            .upsert_agent(&AgentRecord {
                agent_id: id.to_string(),
                name: id.to_string(),
                hostname: "host".into(),
                os: "linux".into(),
                arch: "x86_64".into(),
                version: "test".into(),
                boot_id: "boot".into(),
                status: "online".into(),
                last_seen_at,
                created_at: last_seen_at,
            })
            .unwrap();
    }

    fn seed_sample(
        storage: &SqliteStorage,
        seq: u64,
        agent: &str,
        metric: &str,
        labels: Labels,
        ts: i64,
        value: f64,
    ) {
        storage
            .insert_batch(&SampleBatch {
                agent_id: agent.to_string(),
                epoch: 1,
                seq,
                boot_id: "boot".into(),
                sent_at: ts,
                samples: vec![Sample {
                    metric: metric.to_string(),
                    labels,
                    ts,
                    value,
                }],
            })
            .unwrap();
    }

    fn rule(
        id: &str,
        source: AlertSource,
        metric: &str,
        comparator: Comparator,
        threshold: f64,
        duration_secs: u32,
    ) -> AlertRule {
        AlertRule {
            id: id.to_string(),
            name: format!("规则-{id}"),
            enabled: true,
            source,
            metric: metric.to_string(),
            comparator,
            threshold,
            duration_secs,
            cooldown_secs: 1_800,
            filter_agent_id: None,
            filter_labels: Labels::new(),
            channel_ids: Vec::new(),
            notify_on_resolve: true,
            is_builtin: false,
            updated_by: "test".into(),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn store(storage: &SqliteStorage, rule: &AlertRule) {
        storage.create_alert_rule(rule).unwrap();
    }

    fn metric_rule(id: &str, threshold: f64, duration_secs: u32) -> AlertRule {
        rule(
            id,
            AlertSource::Metric,
            "disk.used_percent",
            Comparator::Gt,
            threshold,
            duration_secs,
        )
    }

    /// metric：多 agent 每个序列独立、labels 精确子集、窗口外样本不评估、不重复触发。
    #[test]
    fn m4_b1b_metric_rule_multi_agent_labels_and_no_duplicate_event() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;

        let mut root = Labels::new();
        root.insert("mount".into(), "/".into());
        let mut data = Labels::new();
        data.insert("mount".into(), "/data".into());

        seed_sample(
            &storage,
            1,
            "a1",
            "disk.used_percent",
            root.clone(),
            now - 1_000,
            95.5,
        );
        seed_sample(
            &storage,
            2,
            "a1",
            "disk.used_percent",
            data,
            now - 1_000,
            99.9,
        );
        seed_sample(
            &storage,
            3,
            "a2",
            "disk.used_percent",
            root,
            now - 2_000,
            92.0,
        );
        // 窗口外（>60s）的样本不能被当作当前观测值。
        seed_sample(
            &storage,
            4,
            "a3",
            "disk.used_percent",
            Labels::new(),
            now - 120_000,
            100.0,
        );

        let mut disk = metric_rule("disk", 90.0, 0);
        disk.filter_labels.insert("mount".into(), "/".into());
        store(&storage, &disk);

        let report = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(report.rules_evaluated, 1);
        assert_eq!(report.series_evaluated, 2, "只评估 mount=/ 的两个序列");
        assert_eq!(report.firing_events, 2);
        assert_eq!(report.resolved_events, 0);
        assert_eq!(report.state_writes, 2);

        let a1_key = alerts::series_key("disk.used_percent", &{
            let mut labels = Labels::new();
            labels.insert("mount".into(), "/".into());
            labels
        });
        let a1_state = storage
            .get_alert_state("disk", "a1", &a1_key)
            .unwrap()
            .expect("a1 必须有状态");
        assert_eq!(a1_state.state, AlertStateKind::Firing);
        assert!(storage.get_alert_state("disk", "a3", "").unwrap().is_none());
        assert!(
            storage
                .get_alert_state(
                    "disk",
                    "a1",
                    &alerts::series_key("disk.used_percent", &{
                        let mut labels = Labels::new();
                        labels.insert("mount".into(), "/data".into());
                        labels
                    })
                )
                .unwrap()
                .is_none(),
            "labels 不匹配的序列不能有状态"
        );

        let events = storage.list_alert_events(10, None).unwrap();
        assert_eq!(events.len(), 2);
        for event in &events {
            assert_eq!(event.state, AlertStateKind::Firing);
            assert!(!event.notified);
            assert!(!event.silenced);
            assert!(event.message.contains("规则-disk"));
            assert!(!event.message.contains("mount"), "message 不能写 labels");
        }

        // 下一轮仍然超阈值：不重复产生 firing 事件。
        let report = evaluate_once(&storage, &cfg, now + 15_000).unwrap();
        assert_eq!(report.firing_events, 0);
        assert_eq!(report.series_evaluated, 2);
        assert_eq!(storage.list_alert_events(10, None).unwrap().len(), 2);
    }

    /// metric：duration 未满只更新 pending，满后触发一次。
    #[test]
    fn m4_b1b_metric_rule_waits_for_duration() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;
        store(&storage, &metric_rule("slow-disk", 90.0, 60));

        seed_sample(
            &storage,
            1,
            "a1",
            "disk.used_percent",
            Labels::new(),
            now - 1_000,
            95.0,
        );
        let report = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(report.firing_events, 0);
        let state = storage
            .get_alert_state(
                "slow-disk",
                "a1",
                &alerts::series_key("disk.used_percent", &Labels::new()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(state.state, AlertStateKind::Pending);

        // 60 秒后再来一个新鲜样本：达到 duration，触发。
        let later = now + 60_000;
        seed_sample(
            &storage,
            2,
            "a1",
            "disk.used_percent",
            Labels::new(),
            later - 1_000,
            96.0,
        );
        let report = evaluate_once(&storage, &cfg, later).unwrap();
        assert_eq!(report.firing_events, 1);
        let state = storage
            .get_alert_state(
                "slow-disk",
                "a1",
                &alerts::series_key("disk.used_percent", &Labels::new()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(state.state, AlertStateKind::Firing);
        assert_eq!(state.since, later);

        // 再过一轮仍超阈值：不重复触发。
        let even_later = later + 15_000;
        seed_sample(
            &storage,
            3,
            "a1",
            "disk.used_percent",
            Labels::new(),
            even_later - 1_000,
            97.0,
        );
        let report = evaluate_once(&storage, &cfg, even_later).unwrap();
        assert_eq!(report.firing_events, 0);
    }

    /// 恢复与重触发：firing → resolved → firing，事件依次落库。
    #[test]
    fn m4_b1b_metric_rule_resolves_and_retriggers() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;
        store(&storage, &metric_rule("flap", 90.0, 0));

        seed_sample(
            &storage,
            1,
            "a1",
            "disk.used_percent",
            Labels::new(),
            now - 1_000,
            95.0,
        );
        assert_eq!(evaluate_once(&storage, &cfg, now).unwrap().firing_events, 1);

        let resolved_at = now + 15_000;
        seed_sample(
            &storage,
            2,
            "a1",
            "disk.used_percent",
            Labels::new(),
            resolved_at - 1_000,
            10.0,
        );
        let report = evaluate_once(&storage, &cfg, resolved_at).unwrap();
        assert_eq!(report.firing_events, 0);
        assert_eq!(report.resolved_events, 1);
        let state = storage
            .get_alert_state(
                "flap",
                "a1",
                &alerts::series_key("disk.used_percent", &Labels::new()),
            )
            .unwrap()
            .unwrap();
        assert_eq!(state.state, AlertStateKind::Resolved);

        let retrigger_at = resolved_at + 15_000;
        seed_sample(
            &storage,
            3,
            "a1",
            "disk.used_percent",
            Labels::new(),
            retrigger_at - 1_000,
            99.0,
        );
        let report = evaluate_once(&storage, &cfg, retrigger_at).unwrap();
        assert_eq!(report.firing_events, 1);

        let events = storage.list_alert_events(10, None).unwrap();
        assert_eq!(events.len(), 3);
        // list 按 id 倒序：最新的是第二次 firing。
        assert_eq!(events[0].state, AlertStateKind::Firing);
        assert_eq!(events[1].state, AlertStateKind::Resolved);
        assert_eq!(events[2].state, AlertStateKind::Firing);
    }

    /// 无样本 / 证书读取失败不得把 firing 误判成 resolved。
    #[test]
    fn m4_b1b_missing_samples_and_cert_errors_never_resolve() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;

        let metric = metric_rule("no-data", 90.0, 0);
        store(&storage, &metric);
        let series = alerts::series_key("disk.used_percent", &Labels::new());
        storage
            .upsert_alert_state(&AlertState {
                rule_id: metric.id.clone(),
                agent_id: "a1".into(),
                series_key: series.clone(),
                state: AlertStateKind::Firing,
                since: now - 600_000,
                last_eval_at: now - 600_000,
                last_value: Some(95.0),
                last_notified_at: None,
            })
            .unwrap();

        // 没有样本：规则被跳过，状态与事件都不变。
        let report = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(report.series_evaluated, 0);
        assert_eq!(report.firing_events, 0);
        assert_eq!(report.resolved_events, 0);
        let state = storage
            .get_alert_state(&metric.id, "a1", &series)
            .unwrap()
            .unwrap();
        assert_eq!(state.state, AlertStateKind::Firing);
        assert!(storage.list_alert_events(10, None).unwrap().is_empty());

        // hub_cert 读取失败：同样跳过，不 resolve。
        let cert_rule = rule("cert", AlertSource::HubCert, "", Comparator::Lt, 48.0, 0);
        store(&storage, &cert_rule);
        storage
            .upsert_alert_state(&AlertState {
                rule_id: cert_rule.id.clone(),
                agent_id: String::new(),
                series_key: String::new(),
                state: AlertStateKind::Firing,
                since: now - 600_000,
                last_eval_at: now - 600_000,
                last_value: Some(20.0),
                last_notified_at: None,
            })
            .unwrap();
        let report = evaluate_once_with_cert_hours(&storage, &cfg, now, |_| {
            anyhow::bail!("模拟证书读取失败")
        })
        .unwrap();
        assert_eq!(report.cert_read_errors, 1);
        assert_eq!(report.resolved_events, 0);
        let state = storage
            .get_alert_state(&cert_rule.id, "", "")
            .unwrap()
            .unwrap();
        assert_eq!(state.state, AlertStateKind::Firing);
    }

    /// agent_offline：阈值比较、吊销跳过、恢复后 resolved。
    #[test]
    fn m4_b1b_offline_rule_fires_skips_revoked_and_resolves() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;

        seed_agent(&storage, "a1", now - 120_000);
        seed_agent(&storage, "a2", now - 10_000);
        // 从未成功握手：last_seen_at = 0，不能被当成“离线很久”。
        seed_agent(&storage, "never", 0);
        seed_agent(&storage, "revoked", now - 1_000_000);
        storage.revoke_agent("revoked", now - 1_000_000).unwrap();

        let offline = rule(
            "offline",
            AlertSource::AgentOffline,
            "",
            Comparator::Gt,
            90.0,
            0,
        );
        store(&storage, &offline);

        let report = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(report.firing_events, 1, "只有 a1 离线超过阈值");
        assert!(storage
            .get_alert_state("offline", "a1", "")
            .unwrap()
            .is_some());
        assert!(storage
            .get_alert_state("offline", "a2", "")
            .unwrap()
            .is_none());
        assert!(storage
            .get_alert_state("offline", "revoked", "")
            .unwrap()
            .is_none());
        assert!(
            storage
                .get_alert_state("offline", "never", "")
                .unwrap()
                .is_none(),
            "last_seen_at=0 的 agent 不能立即离线"
        );
        let events = storage.list_alert_events(10, None).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].agent_id, "a1");
        assert!(events[0].message.contains("离线"));
        assert!(events[0].message.contains("120"));

        // a1 重新上报 → 离线时长归零 → resolved。
        storage.mark_seen("a1", now).unwrap();
        let report = evaluate_once(&storage, &cfg, now + 1_000).unwrap();
        assert_eq!(report.resolved_events, 1);
        let state = storage
            .get_alert_state("offline", "a1", "")
            .unwrap()
            .unwrap();
        assert_eq!(state.state, AlertStateKind::Resolved);
        assert_eq!(storage.list_alert_events(10, None).unwrap().len(), 2);
    }

    /// hub_cert：注入**小时数**，阈值 48 小时，低于 / 高于阈值分别 firing / resolved。
    ///
    /// 回归：旧实现用 `days_left` 与 48 比较（等于阈值 48 天）。证书剩 720 小时
    /// （30 天）在旧语义下 30 < 48 → 误报；新语义 720 > 48 → 不得触发。
    #[test]
    fn m4_b1fix_hub_cert_rule_uses_injected_hours_not_days() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;
        store(
            &storage,
            &rule(
                "hub-cert",
                AlertSource::HubCert,
                "",
                Comparator::Lt,
                48.0,
                0,
            ),
        );

        // 30 天 = 720 小时，远高于 48 小时：不能触发。
        let report = evaluate_once_with_cert_hours(&storage, &cfg, now, |_| Ok(720)).unwrap();
        assert_eq!(report.firing_events, 0, "30 天远高于 48 小时，不能触发");
        assert!(storage.list_alert_events(10, None).unwrap().is_empty());

        // 47 小时 < 48 小时：触发；事件 message 必须用「小时」而不是「天」。
        let report =
            evaluate_once_with_cert_hours(&storage, &cfg, now + 15_000, |_| Ok(47)).unwrap();
        assert_eq!(report.firing_events, 1);
        let state = storage
            .get_alert_state("hub-cert", "", "")
            .unwrap()
            .unwrap();
        assert_eq!(state.state, AlertStateKind::Firing);
        assert_eq!(state.last_value, Some(47.0));
        let event = storage.list_alert_events(1, None).unwrap().pop().unwrap();
        assert!(event.message.contains("证书"), "{event:?}");
        assert!(event.message.contains("47 小时"), "{event:?}");
        assert!(!event.message.contains('天'), "{event:?}");

        // 60 小时 > 48：恢复。
        let report =
            evaluate_once_with_cert_hours(&storage, &cfg, now + 30_000, |_| Ok(60)).unwrap();
        assert_eq!(report.resolved_events, 1);
        let state = storage
            .get_alert_state("hub-cert", "", "")
            .unwrap()
            .unwrap();
        assert_eq!(state.state, AlertStateKind::Resolved);
    }

    /// 静默：事件仍落库，silenced=true、notified=false；静默过期后不再标记。
    #[test]
    fn m4_b1b_silence_marks_events_but_keeps_them() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;
        store(&storage, &metric_rule("silenced", 90.0, 0));
        storage
            .create_alert_silence(&AlertSilence {
                id: 0,
                rule_id: Some("silenced".into()),
                agent_id: None,
                until_ts: now + 60_000,
                created_by: "admin".into(),
                created_at: now,
            })
            .unwrap();

        seed_sample(
            &storage,
            1,
            "a1",
            "disk.used_percent",
            Labels::new(),
            now - 1_000,
            95.0,
        );
        let report = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(report.firing_events, 1);
        assert_eq!(report.silenced_events, 1);
        let event = storage.list_alert_events(1, None).unwrap().pop().unwrap();
        assert!(event.silenced);
        assert!(!event.notified, "B1b 永不发送通知");
        assert!(event.notify_error.is_empty());

        // 恢复事件同样在静默期内，仍落库并标记 silenced。
        let resolved_at = now + 15_000;
        seed_sample(
            &storage,
            2,
            "a1",
            "disk.used_percent",
            Labels::new(),
            resolved_at - 1_000,
            10.0,
        );
        let report = evaluate_once(&storage, &cfg, resolved_at).unwrap();
        assert_eq!(report.resolved_events, 1);
        assert_eq!(report.silenced_events, 1);

        // 静默过期后重新触发：事件不再标记 silenced。
        let expired_at = now + 120_000;
        storage.prune_alert_silences(expired_at).unwrap();
        seed_sample(
            &storage,
            3,
            "a1",
            "disk.used_percent",
            Labels::new(),
            expired_at - 1_000,
            99.0,
        );
        let report = evaluate_once(&storage, &cfg, expired_at).unwrap();
        assert_eq!(report.firing_events, 1);
        assert_eq!(report.silenced_events, 0);
        let event = storage.list_alert_events(1, None).unwrap().pop().unwrap();
        assert!(!event.silenced);
    }

    /// 状态持久化：重启（重新打开数据库）后 firing 状态仍在，不重复产生事件。
    #[test]
    fn m4_b1b_state_survives_reopen_without_duplicate_events() {
        let dir =
            std::env::temp_dir().join(format!("rb-alert-engine-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("rustboard.db");
        let cfg = test_cfg();
        let now = 1_700_000_000_000;

        {
            let storage = SqliteStorage::open(&db).unwrap();
            store(&storage, &metric_rule("persist", 90.0, 0));
            seed_sample(
                &storage,
                1,
                "a1",
                "disk.used_percent",
                Labels::new(),
                now - 1_000,
                95.0,
            );
            let report = evaluate_once(&storage, &cfg, now).unwrap();
            assert_eq!(report.firing_events, 1);
        }

        {
            let storage = SqliteStorage::open(&db).unwrap();
            let state = storage
                .get_alert_state(
                    "persist",
                    "a1",
                    &alerts::series_key("disk.used_percent", &Labels::new()),
                )
                .unwrap()
                .expect("重启后状态必须仍在");
            assert_eq!(state.state, AlertStateKind::Firing);
            seed_sample(
                &storage,
                2,
                "a1",
                "disk.used_percent",
                Labels::new(),
                now + 14_000,
                96.0,
            );
            let report = evaluate_once(&storage, &cfg, now + 15_000).unwrap();
            assert_eq!(report.firing_events, 0, "重启不能重复产生 firing 事件");
            assert_eq!(storage.list_alert_events(10, None).unwrap().len(), 1);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 保留期：事件按天数 / 行数清理，resolved 状态 30 天清理，静默到期清理；
    /// pending / firing 状态不清理。
    #[test]
    fn m4_b1b_round_prunes_expired_history() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let mut cfg = test_cfg();
        cfg.alerts.event_retention_days = 1;
        let now = 1_700_000_000_000;

        storage
            .insert_alert_event(&rustboard_core::alerts::AlertEvent {
                id: 0,
                ts: now - 2 * 24 * 60 * 60 * 1_000,
                rule_id: "gone".into(),
                rule_name: "旧规则".into(),
                agent_id: "a1".into(),
                state: AlertStateKind::Resolved,
                value: Some(1.0),
                message: "旧事件".into(),
                notified: false,
                notify_error: String::new(),
                silenced: false,
            })
            .unwrap();
        let old_state =
            |rule_id: &str, key: &str, state: AlertStateKind, eval_at: i64| AlertState {
                rule_id: rule_id.into(),
                agent_id: "a1".into(),
                series_key: key.into(),
                state,
                since: eval_at,
                last_eval_at: eval_at,
                last_value: Some(1.0),
                last_notified_at: None,
            };
        let old_at = now - 40 * 24 * 60 * 60 * 1_000;
        storage
            .upsert_alert_state(&old_state("gone", "", AlertStateKind::Resolved, old_at))
            .unwrap();
        // 陈旧 firing / pending 超过 30 天保留期也要清理，否则 alert_states 无界。
        storage
            .upsert_alert_state(&old_state("gone", "firing", AlertStateKind::Firing, old_at))
            .unwrap();
        storage
            .upsert_alert_state(&old_state(
                "gone",
                "pending",
                AlertStateKind::Pending,
                old_at,
            ))
            .unwrap();
        // 近期仍在评估的 firing 不能被清理。
        storage
            .upsert_alert_state(&old_state(
                "gone",
                "fresh-firing",
                AlertStateKind::Firing,
                now - 24 * 60 * 60 * 1_000,
            ))
            .unwrap();
        storage
            .create_alert_silence(&AlertSilence {
                id: 0,
                rule_id: None,
                agent_id: None,
                until_ts: now - 1_000,
                created_by: "admin".into(),
                created_at: now - 2_000,
            })
            .unwrap();

        let report = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(report.pruned_events, 1);
        assert_eq!(report.pruned_states, 1, "只清陈旧的 resolved");
        assert_eq!(
            report.pruned_stale_states, 2,
            "陈旧的 firing / pending 也必须清理"
        );
        assert_eq!(report.pruned_silences, 1);
        assert!(storage.list_alert_events(10, None).unwrap().is_empty());
        assert!(storage.list_active_silences(now).unwrap().is_empty());
        let states = storage.list_alert_states().unwrap();
        assert_eq!(states.len(), 1, "近期 firing 不能被保留期删除");
        assert_eq!(states[0].series_key, "fresh-firing");
    }

    /// metric 只读 raw：downsample + 删除 raw 后，旧 1m 桶既不能触发也不能恢复。
    ///
    /// 旧实现 `latest_samples` 会回退到 1m/1h，把旧桶的 `last_value` 当当前值。
    #[test]
    fn m4_b1b_metric_rule_never_uses_downsampled_buckets() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let mut cfg = test_cfg();
        // 窗口 3 小时，确保 1m 桶落在回看范围内。
        cfg.alerts.evaluation_interval_secs = 3_600;
        let now = 1_700_000_000_000;
        store(&storage, &metric_rule("raw-only", 90.0, 0));

        let sample_ts = now - 120_000;
        seed_sample(
            &storage,
            1,
            "a1",
            "disk.used_percent",
            Labels::new(),
            sample_ts,
            95.0,
        );
        // 第一阶段：raw 存在 → firing。
        let first = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(first.firing_events, 1);
        let key = alerts::series_key("disk.used_percent", &Labels::new());
        let firing = storage
            .get_alert_state("raw-only", "a1", &key)
            .unwrap()
            .expect("raw 样本必须触发 firing");
        assert_eq!(firing.state, AlertStateKind::Firing);

        // 生成 1m 桶后删除全部 raw：只剩旧桶。
        storage.downsample_1m_range(sample_ts, now).unwrap();
        assert!(
            storage.samples_1m_stats().unwrap().rows > 0,
            "必须先生成 1m 桶"
        );
        storage.prune_samples_before(now + 1_000).unwrap();
        assert_eq!(storage.sample_count("a1").unwrap(), 0, "raw 已删除");

        // 第二阶段：不得用旧桶再次 firing，也不得用旧桶 resolve。
        let second = evaluate_once(&storage, &cfg, now + 15_000).unwrap();
        assert_eq!(second.series_evaluated, 0, "1m 桶不能当作当前值");
        assert_eq!(second.firing_events, 0);
        assert_eq!(second.resolved_events, 0, "无 raw 样本不得 resolve");
        let after = storage
            .get_alert_state("raw-only", "a1", &key)
            .unwrap()
            .expect("状态应保持不变");
        assert_eq!(after.state, AlertStateKind::Firing);
        assert_eq!(storage.list_alert_events(10, None).unwrap().len(), 1);
    }

    /// 每规则序列数上限：超出时截断并计数，不产生错误。
    #[test]
    fn m4_b1b_metric_series_are_bounded_and_marked_truncated() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;
        store(&storage, &metric_rule("bounded", 90.0, 0));

        for index in 0..3 {
            let mut labels = Labels::new();
            labels.insert("mount".into(), format!("/data{index}"));
            seed_sample(
                &storage,
                index as u64 + 1,
                "a1",
                "disk.used_percent",
                labels,
                now - 1_000,
                95.0,
            );
        }

        let report =
            evaluate_with_options(&storage, &cfg, now, |_| Ok(0), 2, Duration::from_secs(60))
                .unwrap();
        assert_eq!(report.rules_evaluated, 1);
        assert_eq!(report.series_evaluated, 2, "只评估前 2 条序列");
        assert_eq!(report.firing_events, 2);
        assert_eq!(report.truncated_rules, 1);
        // 截断不是失败：允许后续轮次继续评估（这里 3 条都会在下一轮出现）。
        assert_eq!(report.evaluation_errors, 0);
    }

    /// 时间预算耗尽：跳过剩余规则并记录，不产生事件。
    #[test]
    fn m4_b1b_budget_skips_remaining_rules_and_reports() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;
        store(&storage, &metric_rule("first", 90.0, 0));
        store(&storage, &metric_rule("second", 90.0, 0));

        let report = evaluate_with_options(
            &storage,
            &cfg,
            now,
            |_| Ok(0),
            MAX_ALERT_SERIES_PER_RULE,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(report.rules_evaluated, 0);
        assert_eq!(report.rules_skipped_budget, 2);
        assert_eq!(report.series_evaluated, 0);
        assert_eq!(report.firing_events, 0);
    }

    /// 清理按小时节流：一轮内不重复 COUNT / DELETE，一小时后恢复。
    #[test]
    fn m4_b1b_prune_runs_at_most_hourly() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let mut cfg = test_cfg();
        cfg.alerts.event_retention_days = 1;
        let now = 1_700_000_000_000;

        let old_event = || rustboard_core::alerts::AlertEvent {
            id: 0,
            ts: now - 2 * 24 * 60 * 60 * 1_000,
            rule_id: "gone".into(),
            rule_name: "旧规则".into(),
            agent_id: "a1".into(),
            state: AlertStateKind::Resolved,
            value: Some(1.0),
            message: "旧事件".into(),
            notified: false,
            notify_error: String::new(),
            silenced: false,
        };

        storage.insert_alert_event(&old_event()).unwrap();
        let first = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(first.pruned_events, 1);
        assert!(storage.list_alert_events(10, None).unwrap().is_empty());

        // 15 秒后：未到清理周期，不再执行 DELETE。
        storage.insert_alert_event(&old_event()).unwrap();
        let second = evaluate_once(&storage, &cfg, now + 15_000).unwrap();
        assert_eq!(second.pruned_events, 0);
        assert_eq!(storage.list_alert_events(10, None).unwrap().len(), 1);

        // 一小时后：恢复清理。
        let third = evaluate_once(&storage, &cfg, now + PRUNE_INTERVAL_MS).unwrap();
        assert_eq!(third.pruned_events, 1);
        assert!(storage.list_alert_events(10, None).unwrap().is_empty());
    }

    /// 禁用的规则不评估（引擎只看 `list_enabled_alert_rules`）。
    #[test]
    fn m4_b1b_disabled_rules_are_not_evaluated() {
        let storage = SqliteStorage::open_in_memory().unwrap();
        let cfg = test_cfg();
        let now = 1_700_000_000_000;
        let mut disabled = metric_rule("disabled", 90.0, 0);
        disabled.enabled = false;
        store(&storage, &disabled);
        seed_sample(
            &storage,
            1,
            "a1",
            "disk.used_percent",
            Labels::new(),
            now - 1_000,
            95.0,
        );

        let report = evaluate_once(&storage, &cfg, now).unwrap();
        assert_eq!(report.rules_evaluated, 0);
        assert_eq!(report.firing_events, 0);
        assert!(storage.list_alert_events(10, None).unwrap().is_empty());
    }
}
