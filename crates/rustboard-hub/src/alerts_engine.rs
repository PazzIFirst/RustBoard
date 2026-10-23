//! M4-B1b：告警评估引擎。
//!
//! 一轮评估（[`evaluate_once`]）是**同步纯函数式**的：调用方给出 `now`，引擎只
//! 读取存储、推进状态机、写状态与事件，最后做一次保留期清理。后台任务
//! （[`spawn_alert_engine`]）只是按 `alerts.evaluation_interval_secs` 循环调用它。
//!
//! 规则语义（与方案 §6.1–6.3 一致）：
//! - `metric`：查 `now - max(evaluation_interval * 3, 60s)` 窗口内的最新样本，
//!   按 `filter_agent_id` / `filter_labels`（精确子集）过滤，每个序列独立状态；
//! - `agent_offline`：`now - agents.last_seen_at` 与阈值（秒）比较；每个 agent
//!   一条状态（`series_key` 为空），已吊销 agent 跳过；
//! - `hub_cert`：读取 `cfg.data_dir/certs/server.crt` 的剩余**小时数**
//!   （与 `cert_warn_hours` 同单位），全局一条状态；读盘 / 解析失败只 WARN 并
//!   跳过本轮，**绝不 resolve**。
//!
//! 配置说明：`HubAlertsConfig::offline_after_secs` / `cert_warn_hours` 只用于
//! 生成内置规则的默认阈值。评估时**规则自身的 threshold 才是权威**——用户改过
//! 阈值后，引擎不会被配置项覆盖。事件保留 / 上限与静默过期分别使用
//! `event_retention_days` / `max_events`；`notify_*` 留给 B2。
//!
//! 安全约定：日志只输出规则 id、agent id 与计数，不输出样本值之外的 secret；
//! 事件 message 由 [`rustboard_core::alerts::alert_event_message`] 生成，不含
//! labels 全量。所有 SQL 参数化。

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustboard_common::config::HubConfig;
use rustboard_common::model::AgentRecord;
use rustboard_common::tls;
use rustboard_common::util::now_ms;
use rustboard_core::alerts::{
    self, AlertRule, AlertSilence, AlertSource, AlertStateKind, MAX_ALERT_RULES,
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

/// resolved 状态保留 30 天（方案 §6.2）。
pub(crate) const RESOLVED_STATE_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// 一轮评估的统计结果；只含计数，可安全写入日志。
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub(crate) struct EvaluationReport {
    /// 本轮评估的规则数（受 [`MAX_ALERT_RULES`] 截断）。
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
    /// 清理的事件数。
    pub pruned_events: usize,
    /// 清理的 resolved 状态数。
    pub pruned_states: usize,
    /// 清理的过期静默数。
    pub pruned_silences: usize,
}

/// 执行一轮告警评估（固定 `now`，可直接单测）。
///
/// 流程：读取启用规则与生效静默 → 逐条规则查询观测值并推进状态机 → 落库状态 /
/// 事件 → 清理过期数据。任何单条规则的查询失败只记 WARN 与计数，**不会**把
/// 状态误判成 resolved；存储写入失败则整轮返回错误，下一轮重试。
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
    let rules = storage.list_enabled_alert_rules()?;
    if rules.len() > MAX_ALERT_RULES {
        tracing::warn!(
            rules = rules.len(),
            max_rules = MAX_ALERT_RULES,
            "启用规则数超过单轮上限，本轮只评估前 {MAX_ALERT_RULES} 条"
        );
    }
    let silences = storage.list_active_silences(now)?;
    let mut report = EvaluationReport {
        rules_evaluated: rules.len().min(MAX_ALERT_RULES),
        ..EvaluationReport::default()
    };

    // 离线规则共用一份 agent 列表；hub_cert 规则共用一次证书读取。
    let mut agents: Option<Vec<AgentRecord>> = None;
    let mut cert_hours_cache: Option<Option<i64>> = None;

    for rule in rules.iter().take(MAX_ALERT_RULES) {
        let mut context = RuleContext {
            storage,
            rule,
            now,
            silences: &silences,
            report: &mut report,
        };
        match rule.source {
            AlertSource::Metric => {
                let since = now.saturating_sub(metric_lookback_ms(cfg));
                let metrics = std::slice::from_ref(&rule.metric);
                let rows =
                    match storage.latest_samples(since, metrics, rule.filter_agent_id.as_deref()) {
                        Ok(rows) => rows,
                        Err(err) => {
                            context.report.evaluation_errors += 1;
                            tracing::warn!(
                                rule_id = %rule.id,
                                error = %err,
                                "查询告警指标失败，本轮跳过该规则（不改状态）"
                            );
                            continue;
                        }
                    };
                for row in rows {
                    if !alerts::labels_match_filter(&rule.filter_labels, &row.labels) {
                        continue;
                    }
                    let key = alerts::series_key(&row.metric, &row.labels);
                    context.apply(&row.agent_id, &key, row.value)?;
                }
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
                    if let Some(filter) = &rule.filter_agent_id {
                        if filter != &agent.agent_id {
                            continue;
                        }
                    }
                    let elapsed_ms = now.saturating_sub(agent.last_seen_at).max(0);
                    let elapsed_secs = elapsed_ms as f64 / 1_000.0;
                    context.apply(&agent.agent_id, "", elapsed_secs)?;
                }
            }
            AlertSource::HubCert => {
                let cached = match cert_hours_cache {
                    Some(value) => value,
                    None => {
                        let loaded = match cert_hours(cfg) {
                            Ok(hours) => Some(hours),
                            Err(err) => {
                                context.report.cert_read_errors += 1;
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
                let Some(hours) = cached else { continue };
                context.apply("", "", hours as f64)?;
            }
        }
    }

    prune_history(storage, cfg, now, &mut report);
    Ok(report)
}

/// 单条规则的评估上下文：聚合存储、规则、本轮静默快照与计数。
struct RuleContext<'a> {
    storage: &'a SqliteStorage,
    rule: &'a AlertRule,
    now: i64,
    silences: &'a [AlertSilence],
    report: &'a mut EvaluationReport,
}

impl RuleContext<'_> {
    /// 推进一个序列的状态机并落库。
    ///
    /// 事件先于状态写入：极端情况下（状态写失败）下一轮可能重复产生事件，属于
    /// 方案 §11.3 允许的 at-least-once；反之先写状态再写事件则可能永久丢告警。
    fn apply(&mut self, agent_id: &str, series_key: &str, value: f64) -> Result<()> {
        let existing = self
            .storage
            .get_alert_state(&self.rule.id, agent_id, series_key)?;
        let transition = alerts::next_alert_state(
            existing.as_ref(),
            self.rule,
            agent_id,
            series_key,
            value,
            self.now,
        );
        self.report.series_evaluated += 1;

        if let Some(kind) = transition.event {
            // 静默只影响通知（B2），事件仍必须落库，面板才能看到「静默中」。
            let silenced = self
                .silences
                .iter()
                .any(|silence| silence.matches(&self.rule.id, agent_id, self.now));
            let event =
                alerts::new_alert_event(self.rule, agent_id, kind, value, self.now, silenced);
            self.storage.insert_alert_event(&event)?;
            match kind {
                AlertStateKind::Firing => self.report.firing_events += 1,
                AlertStateKind::Resolved => self.report.resolved_events += 1,
                AlertStateKind::Pending => {}
            }
            if silenced {
                self.report.silenced_events += 1;
            }
        }

        if let Some(state) = transition.state {
            self.storage.upsert_alert_state(&state)?;
            self.report.state_writes += 1;
        }
        Ok(())
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
        Err(err) => tracing::warn!(error = %err, "清理告警事件失败，下一轮重试"),
    }
    match storage.prune_alert_states(now.saturating_sub(RESOLVED_STATE_RETENTION_MS)) {
        Ok(removed) => report.pruned_states = removed,
        Err(err) => tracing::warn!(error = %err, "清理 resolved 告警状态失败，下一轮重试"),
    }
    match storage.prune_alert_silences(now) {
        Ok(removed) => report.pruned_silences = removed,
        Err(err) => tracing::warn!(error = %err, "清理过期静默失败，下一轮重试"),
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
                    if report.firing_events > 0 || report.resolved_events > 0 {
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
        let old_resolved = AlertState {
            rule_id: "gone".into(),
            agent_id: "a1".into(),
            series_key: String::new(),
            state: AlertStateKind::Resolved,
            since: now - 40 * 24 * 60 * 60 * 1_000,
            last_eval_at: now - 40 * 24 * 60 * 60 * 1_000,
            last_value: Some(1.0),
            last_notified_at: None,
        };
        storage.upsert_alert_state(&old_resolved).unwrap();
        let mut old_firing = old_resolved.clone();
        old_firing.series_key = "firing".into();
        old_firing.state = AlertStateKind::Firing;
        storage.upsert_alert_state(&old_firing).unwrap();
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
        assert_eq!(report.pruned_states, 1);
        assert_eq!(report.pruned_silences, 1);
        assert!(storage.list_alert_events(10, None).unwrap().is_empty());
        assert!(storage.list_active_silences(now).unwrap().is_empty());
        let states = storage.list_alert_states().unwrap();
        assert_eq!(states.len(), 1, "firing 状态不能被保留期删除");
        assert_eq!(states[0].series_key, "firing");
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
