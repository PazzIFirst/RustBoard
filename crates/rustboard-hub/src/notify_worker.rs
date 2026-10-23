//! M4-B2b：告警通知 worker。
//!
//! 设计要点（方案 §6.2–6.4 + B2b 验收标准）：
//! - **不补发存量**：首次启动把 `maintenance_state.notify_started_event_id` 设为
//!   当前 `MAX(alert_events.id)`，之后只处理 `id > cursor AND notified = 0 AND
//!   silenced = 0` 的新事件；
//! - 游标在处理完整批后推进并持久化；崩溃可能造成 at-least-once 重复发送，
//!   日志会记录，不追求严格 exactly-once；
//! - 每 tick 最多 [`NOTIFY_BATCH_LIMIT`] 条；tick 固定 5s，独立于评估间隔，
//!   避免评估周期变大时通知延迟被同步放大；
//! - 无规则 / 无渠道 / 渠道全禁用 / 冷却中 / 静默 / 恢复通知关闭都不会阻塞后续
//!   事件：事件标记 `notified = 1` 并写入固定原因，不再永久重试；事件落库后新建
//!   的静默在发送前重新检查，命中写 `silenced_late`；
//! - 每个启用渠道独立发送；至少一个成功即视为已通知并更新
//!   `alert_states.last_notified_at`；全部失败也标记，错误摘要只含渠道名与固定
//!   错误码（≤512 字节），不含 secret / URL；
//! - 静默事件由 SQL 直接排除，worker 仍有防御性检查，永不发送。
//!
//! 安全约定：日志只输出事件 id、渠道 id/kind 与固定错误码，不输出配置、token、
//! 请求 URL 或上游响应正文。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustboard_common::config::HubConfig;
use rustboard_common::util::now_ms;
use rustboard_core::alerts::{AlertEvent, AlertRule, AlertStateKind};
use rustboard_core::channels::{build_text, NotificationChannel};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::Storage;

use crate::notify::{Notifier, NotifyError};

/// `maintenance_state` 中保存通知事件游标的键。
pub(crate) const NOTIFY_CURSOR_KEY: &str = "notify_started_event_id";

/// 单 tick 最多处理的事件数（方案 §6.2 的有界队列容量同量级）。
const NOTIFY_BATCH_LIMIT: usize = 50;

/// 通知 worker 的轮询间隔。
///
/// 不跟 `alerts.evaluation_interval_secs` 绑定：评估间隔可配置到 3600s，若共用会
/// 让通知延迟一小时。固定 5s 在「及时性」与「空轮询 SQL 开销」之间取平衡。
const NOTIFY_TICK: Duration = Duration::from_secs(5);

/// 一轮通知处理的统计（只用于日志与测试）。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotifyCycleReport {
    /// 处理后的游标（未处理任何事件时保持输入游标）。
    pub cursor: i64,
    /// 本轮检查的事件数。
    pub processed: usize,
    /// 至少一个渠道发送成功的事件数。
    pub sent: usize,
    /// 未发送但已标记原因的事件数（静默 / 冷却 / 无渠道等）。
    pub skipped: usize,
    /// 尝试发送但全部渠道失败的事件数。
    pub failed: usize,
}

/// 单个事件的处置结果。
enum EventOutcome {
    Sent,
    Skipped,
    Failed,
}

/// 首次启动（或游标损坏）时建立通知水位。
///
/// - 已有合法游标：直接返回（重启不补发）；
/// - 不存在 / 非法：取当前 `MAX(alert_events.id)` 写入，返回该值。B1b 阶段所有
///   历史事件都是 `notified = 0`，绝不能直接投递。
pub(crate) fn initialize_notify_cursor(storage: &SqliteStorage, now: i64) -> Result<i64> {
    if let Some(raw) = storage.get_maintenance_state(NOTIFY_CURSOR_KEY)? {
        match raw.trim().parse::<i64>() {
            Ok(cursor) if cursor >= 0 => return Ok(cursor),
            _ => tracing::warn!(
                key = NOTIFY_CURSOR_KEY,
                "通知游标不是非负整数，按首次上线重新建立水位"
            ),
        }
    }
    let cursor = storage.max_alert_event_id()?;
    storage.set_maintenance_state(NOTIFY_CURSOR_KEY, &cursor.to_string(), now)?;
    tracing::info!(
        cursor,
        key = NOTIFY_CURSOR_KEY,
        "通知 worker 首次上线：跳过存量告警事件"
    );
    Ok(cursor)
}

/// 启动后台通知 worker。
///
/// - `alerts.enabled = false`：只记 INFO，不启动；
/// - 启动阶段若游标初始化失败（例如数据库暂时忙），每 5s 重试，绝不带着
///   「未知游标」开始发送；
/// - 每轮在 `spawn_blocking` 内读库，发送阶段走 async `Notifier`；任务本身
///   不退出，错误只 WARN。
pub(crate) fn spawn_notify_worker(
    storage: Arc<SqliteStorage>,
    cfg: HubConfig,
    notifier: Arc<dyn Notifier>,
) {
    if !cfg.alerts.enabled {
        tracing::info!("通知 worker 未启用（alerts.enabled = false）");
        return;
    }
    tokio::spawn(async move {
        let cursor = loop {
            let storage = storage.clone();
            let outcome =
                tokio::task::spawn_blocking(move || initialize_notify_cursor(&storage, now_ms()))
                    .await;
            match outcome {
                Ok(Ok(cursor)) => break cursor,
                Ok(Err(err)) => {
                    tracing::warn!(error = %err, "初始化通知游标失败，5s 后重试");
                }
                Err(err) => {
                    tracing::warn!(error = %err, "初始化通知游标任务异常，5s 后重试");
                }
            }
            tokio::time::sleep(NOTIFY_TICK).await;
        };
        tracing::info!(
            cursor,
            tick_secs = NOTIFY_TICK.as_secs(),
            batch_limit = NOTIFY_BATCH_LIMIT,
            "通知 worker 已启动"
        );

        let mut cursor = cursor;
        loop {
            tokio::time::sleep(NOTIFY_TICK).await;
            let now = now_ms();
            match notify_once(storage.clone(), notifier.clone(), cursor, now).await {
                Ok(report) => {
                    cursor = report.cursor;
                    if report.processed > 0 {
                        tracing::info!(?report, "通知批次完成");
                    } else {
                        tracing::debug!(?report, "通知批次完成（无新事件）");
                    }
                }
                Err(err) => {
                    tracing::warn!(error = %err, cursor, "通知批次失败，下一轮从已持久化游标重试");
                }
            }
        }
    });
}

/// 处理一轮通知：读取新事件、逐个发送并推进游标。
///
/// 供后台任务与单元测试共用；调用方保证 `cursor` 已持久化。每个事件的发送结果
/// 都落库后才推进内存游标，批末再持久化一次。
pub(crate) async fn notify_once(
    storage: Arc<SqliteStorage>,
    notifier: Arc<dyn Notifier>,
    cursor: i64,
    now: i64,
) -> Result<NotifyCycleReport> {
    let events = {
        let storage = storage.clone();
        blocking(storage, move |storage| {
            storage.list_pending_notification_events_after(cursor, NOTIFY_BATCH_LIMIT)
        })
        .await?
    };
    let mut report = NotifyCycleReport {
        cursor,
        ..NotifyCycleReport::default()
    };
    if events.is_empty() {
        return Ok(report);
    }

    // 规则 / 渠道数量都有硬上限（200 / 50），每批只读一次，避免逐事件查库。
    let rules = {
        let storage = storage.clone();
        blocking(storage, move |storage| storage.list_alert_rules()).await?
    };
    let channels = {
        let storage = storage.clone();
        blocking(storage, move |storage| storage.list_notification_channels()).await?
    };
    let rules: HashMap<String, AlertRule> = rules
        .into_iter()
        .map(|rule| (rule.id.clone(), rule))
        .collect();
    let channels: HashMap<String, NotificationChannel> = channels
        .into_iter()
        .map(|channel| (channel.id.clone(), channel))
        .collect();

    for event in events {
        match process_event(&storage, &notifier, &event, &rules, &channels, now).await {
            Ok(outcome) => {
                report.processed += 1;
                match outcome {
                    EventOutcome::Sent => report.sent += 1,
                    EventOutcome::Skipped => report.skipped += 1,
                    EventOutcome::Failed => report.failed += 1,
                }
                report.cursor = event.id;
            }
            Err(err) => {
                // 已处理的事件都已落库；未完成的事件保持 notified = 0，下一轮
                // 从已持久化游标重试（可能重复发送，at-least-once）。
                tracing::warn!(
                    event_id = event.id,
                    rule_id = %event.rule_id,
                    error = %err,
                    "处理通知事件失败，保留游标稍后重试"
                );
                break;
            }
        }
    }

    if report.cursor != cursor {
        let next_cursor = report.cursor;
        let storage = storage.clone();
        blocking(storage, move |storage| {
            storage.set_maintenance_state(NOTIFY_CURSOR_KEY, &next_cursor.to_string(), now)
        })
        .await?;
    }
    Ok(report)
}

/// 处理单个事件；所有「不发送」路径都会写 `notified = 1` + 固定原因。
async fn process_event(
    storage: &Arc<SqliteStorage>,
    notifier: &Arc<dyn Notifier>,
    event: &AlertEvent,
    rules: &HashMap<String, AlertRule>,
    channels: &HashMap<String, NotificationChannel>,
    now: i64,
) -> Result<EventOutcome> {
    // B1b 的 SQL 已排除 silenced；这里仍防御，静默事件永不发送。
    if event.silenced {
        tracing::debug!(
            event_id = event.id,
            "跳过静默告警事件（不应出现在待发队列）"
        );
        return Ok(EventOutcome::Skipped);
    }

    let Some(rule) = rules.get(&event.rule_id) else {
        mark_skipped(storage, event.id, "rule_missing").await?;
        return Ok(EventOutcome::Skipped);
    };

    // 发送前重新检查当前生效静默：事件落库时还没静默、之后才创建的静默也必须
    // 阻止发送。命中后标记 processed，避免下一轮重复检查。
    let silences = {
        let storage = storage.clone();
        blocking(storage, move |storage| storage.list_active_silences(now)).await?
    };
    if silences
        .iter()
        .any(|silence| silence.matches(&event.rule_id, &event.agent_id, now))
    {
        mark_skipped(storage, event.id, "silenced_late").await?;
        return Ok(EventOutcome::Skipped);
    }

    // 恢复通知关闭：事件仍保留给面板，但不发送、不重试。
    if event.state == AlertStateKind::Resolved && !rule.notify_on_resolve {
        mark_skipped(storage, event.id, "resolve_disabled").await?;
        return Ok(EventOutcome::Skipped);
    }

    // 冷却只限制 firing：恢复通知按方案 §6.3 不受 cooldown 限制。
    // 精确按 (rule_id, agent_id, series_key) 读取状态：同一 agent 的其它序列
    // 刚发送过通知，不能阻断本序列的首次 firing。
    if event.state == AlertStateKind::Firing && rule.cooldown_secs > 0 {
        let rule_id = event.rule_id.clone();
        let agent_id = event.agent_id.clone();
        let series_key = event.series_key.clone();
        let state = {
            let storage = storage.clone();
            blocking(storage, move |storage| {
                storage.get_alert_state(&rule_id, &agent_id, &series_key)
            })
            .await?
        };
        if let Some(last_notified_at) = state.and_then(|state| state.last_notified_at) {
            let cooldown_ms = i64::from(rule.cooldown_secs).saturating_mul(1_000);
            if now.saturating_sub(last_notified_at) < cooldown_ms {
                mark_skipped(storage, event.id, "cooldown").await?;
                return Ok(EventOutcome::Skipped);
            }
        }
    }

    if rule.channel_ids.is_empty() {
        mark_skipped(storage, event.id, "no_channel").await?;
        return Ok(EventOutcome::Skipped);
    }

    // 按规则中的顺序去重；未知 / 禁用渠道不算启用。
    let mut seen = HashSet::new();
    let mut enabled: Vec<&NotificationChannel> = Vec::new();
    let mut missing = 0usize;
    let mut disabled = 0usize;
    for channel_id in &rule.channel_ids {
        if !seen.insert(channel_id.as_str()) {
            continue;
        }
        match channels.get(channel_id) {
            Some(channel) if channel.enabled => enabled.push(channel),
            Some(_) => disabled += 1,
            None => missing += 1,
        }
    }
    if enabled.is_empty() {
        let code = if missing == seen.len() {
            "channel_missing"
        } else {
            "no_channel"
        };
        mark_skipped(storage, event.id, code).await?;
        return Ok(EventOutcome::Skipped);
    }
    if missing > 0 || disabled > 0 {
        tracing::warn!(
            event_id = event.id,
            rule_id = %rule.id,
            missing,
            disabled,
            "告警规则的渠道部分缺失或禁用，继续向启用渠道发送"
        );
    }

    let mut successes = 0usize;
    let mut failures: Vec<(&str, NotifyError)> = Vec::new();
    for channel in enabled {
        let text = build_text(&channel.name, event);
        match notifier.send(channel, &text).await {
            Ok(()) => successes += 1,
            Err(error) => {
                tracing::warn!(
                    event_id = event.id,
                    channel_id = %channel.id,
                    kind = channel.kind.as_str(),
                    error = error.code(),
                    "通知渠道发送失败"
                );
                failures.push((channel.name.as_str(), error));
            }
        }
    }

    if successes > 0 {
        // 只有 firing 的通知时间参与冷却；恢复通知不刷新 cooldown 锚点。
        // 只更新事件自身的序列，绝不扩散到同一 agent 的其它 series。
        if event.state == AlertStateKind::Firing {
            let rule_id = event.rule_id.clone();
            let agent_id = event.agent_id.clone();
            let series_key = event.series_key.clone();
            let storage = storage.clone();
            blocking(storage, move |storage| {
                storage.update_alert_state_notified(&rule_id, &agent_id, &series_key, now)
            })
            .await?;
        }
        let storage = storage.clone();
        let event_id = event.id;
        blocking(storage, move |storage| {
            storage.mark_notification_result(event_id, true, "")
        })
        .await?;
        return Ok(EventOutcome::Sent);
    }

    let summary = failure_summary(&failures);
    let storage = storage.clone();
    let event_id = event.id;
    blocking(storage, move |storage| {
        storage.mark_notification_processed(event_id, &summary)
    })
    .await?;
    Ok(EventOutcome::Failed)
}

/// 标记事件已处理但未发送；原因固定且已脱敏。
async fn mark_skipped(storage: &Arc<SqliteStorage>, event_id: i64, reason: &str) -> Result<()> {
    let storage = storage.clone();
    let reason = reason.to_string();
    blocking(storage, move |storage| {
        let updated = storage.mark_notification_processed(event_id, &reason)?;
        if !updated {
            tracing::debug!(event_id, "通知事件已被清理，跳过标记");
        }
        Ok(())
    })
    .await
}

/// 汇总全部渠道失败：只含渠道名 + 固定 code，按 512 字节截断由存储层兜底。
fn failure_summary(failures: &[(&str, NotifyError)]) -> String {
    let details = failures
        .iter()
        .map(|(name, error)| format!("{name}={}", error.code()))
        .collect::<Vec<_>>()
        .join(",");
    format!("notify_failed: {details}")
}

/// 在 `spawn_blocking` 中执行一次存储读取 / 写入，避免阻塞 async worker。
async fn blocking<T, F>(storage: Arc<SqliteStorage>, task: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&SqliteStorage) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || task(&storage))
        .await
        .context("通知 worker 存储任务异常结束")?
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use rustboard_core::alerts::{AlertRule, AlertSilence, AlertSource, AlertState, Comparator};
    use rustboard_core::channels::{ChannelConfig, ChannelKind, Secret};
    use rustboard_core::storage::sqlite::SqliteStorage;
    use rustboard_core::storage::Storage;

    use super::*;
    use crate::notify::MockNotifier;

    const NOW: i64 = 1_700_000_000_000;

    fn rule(id: &str, cooldown_secs: u32) -> AlertRule {
        AlertRule {
            id: id.to_string(),
            name: format!("规则-{id}"),
            enabled: true,
            source: AlertSource::Metric,
            metric: "disk.used_percent".to_string(),
            comparator: Comparator::Gt,
            threshold: 90.0,
            duration_secs: 0,
            cooldown_secs,
            filter_agent_id: None,
            filter_labels: Default::default(),
            channel_ids: Vec::new(),
            notify_on_resolve: true,
            is_builtin: false,
            updated_by: "admin".to_string(),
            created_at: NOW,
            updated_at: NOW,
        }
    }

    fn channel(name: &str, enabled: bool) -> NotificationChannel {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        NotificationChannel {
            id: format!("00000000-0000-4000-8000-{seq:012}"),
            name: name.to_string(),
            kind: ChannelKind::Telegram,
            config: ChannelConfig::Telegram {
                bot_token: Secret::new("123456789:AAH_worker-test-token_01"),
                chat_id: "-1001234567890".to_string(),
            },
            enabled,
            updated_by: "admin".to_string(),
            created_at: NOW,
            updated_at: NOW,
        }
    }

    fn event(
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
        state: AlertStateKind,
        silenced: bool,
    ) -> AlertEvent {
        AlertEvent {
            id: 0,
            ts: NOW,
            rule_id: rule_id.to_string(),
            rule_name: format!("规则-{rule_id}"),
            agent_id: agent_id.to_string(),
            series_key: series_key.to_string(),
            state,
            value: Some(95.0),
            message: "测试事件".to_string(),
            notified: false,
            notify_error: String::new(),
            silenced,
        }
    }

    fn insert_event(storage: &SqliteStorage, event: AlertEvent) -> i64 {
        storage.insert_alert_event(&event).unwrap()
    }

    fn stored_event(storage: &SqliteStorage, id: i64) -> AlertEvent {
        storage
            .list_alert_events(100, None)
            .unwrap()
            .into_iter()
            .find(|event| event.id == id)
            .expect("事件必须存在")
    }

    fn seed_rule(storage: &SqliteStorage, rule: &AlertRule) {
        storage.create_alert_rule(rule).unwrap();
    }

    fn seed_channel(storage: &SqliteStorage, channel: &NotificationChannel) {
        storage.create_notification_channel(channel).unwrap();
    }

    fn firing_state(
        rule_id: &str,
        agent_id: &str,
        series_key: &str,
        last_notified_at: Option<i64>,
    ) -> AlertState {
        AlertState {
            rule_id: rule_id.to_string(),
            agent_id: agent_id.to_string(),
            series_key: series_key.to_string(),
            state: AlertStateKind::Firing,
            since: NOW - 10_000,
            last_eval_at: NOW,
            last_value: Some(95.0),
            last_notified_at,
        }
    }

    /// 首次启动跳过 B1b 存量事件；处理新事件后游标持久化，重启继续。
    #[tokio::test]
    async fn m4_b2b_worker_first_start_skips_backlog_and_persists_cursor() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());
        let mut backlog_rule = rule("rule-old", 0);
        let backlog_channel = channel("存量渠道", true);
        backlog_rule.channel_ids = vec![backlog_channel.id.clone()];
        seed_rule(&storage, &backlog_rule);
        seed_channel(&storage, &backlog_channel);

        let first = insert_event(
            &storage,
            event(
                "rule-old",
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                false,
            ),
        );
        let second = insert_event(
            &storage,
            event(
                "rule-old",
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                false,
            ),
        );
        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        assert_eq!(cursor, second);
        assert!(second > first);

        // 存量事件不发送（mock 也没有任何调用）。
        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW)
            .await
            .unwrap();
        assert_eq!(report.processed, 0);
        assert_eq!(mock.send_count(), 0);
        assert!(!stored_event(&storage, first).notified);
        assert!(!stored_event(&storage, second).notified);

        // 新事件正常发送并推进游标。
        let third = insert_event(
            &storage,
            event(
                "rule-old",
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                false,
            ),
        );
        let report = notify_once(storage.clone(), mock.clone(), report.cursor, NOW + 1)
            .await
            .unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(report.cursor, third);
        assert_eq!(mock.send_count(), 1);
        assert!(stored_event(&storage, third).notified);

        // 「重启」：游标从 maintenance_state 读回，不重复处理。
        assert_eq!(initialize_notify_cursor(&storage, NOW + 2).unwrap(), third);
        let report = notify_once(storage.clone(), mock.clone(), third, NOW + 3)
            .await
            .unwrap();
        assert_eq!(report.processed, 0);
        assert_eq!(mock.send_count(), 1);

        // 游标损坏：重置为当前最大 id，不回退成 0（避免重放全部历史）。
        storage
            .set_maintenance_state(NOTIFY_CURSOR_KEY, "corrupt", NOW + 4)
            .unwrap();
        assert_eq!(
            initialize_notify_cursor(&storage, NOW + 5).unwrap(),
            storage.max_alert_event_id().unwrap()
        );
    }

    /// 新事件发送成功：事件 notified、状态 last_notified_at 更新、文本含事件快照。
    #[tokio::test]
    async fn m4_b2b_worker_sends_new_event_and_updates_state() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());
        let mut rule = rule("rule-send", 1_800);
        let channel = channel("运维群", true);
        rule.channel_ids = vec![channel.id.clone()];
        seed_rule(&storage, &rule);
        seed_channel(&storage, &channel);
        storage
            .upsert_alert_state(&firing_state(&rule.id, "agent-1", "series-1", None))
            .unwrap();

        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        let event_id = insert_event(
            &storage,
            event(
                &rule.id,
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                false,
            ),
        );
        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW + 1)
            .await
            .unwrap();
        assert_eq!(report.sent, 1);
        assert_eq!(report.cursor, event_id);

        let stored = stored_event(&storage, event_id);
        assert!(stored.notified);
        assert!(stored.notify_error.is_empty());
        let sent = mock.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].channel_id, channel.id);
        assert!(sent[0].text.contains("状态：触发"));
        assert!(sent[0].text.contains("规则-rule-send"));

        let state = storage
            .get_alert_state(&rule.id, "agent-1", "series-1")
            .unwrap()
            .expect("状态必须存在");
        assert_eq!(state.last_notified_at, Some(NOW + 1));
    }

    /// 冷却抑制 firing、但不抑制 resolved；resolved 不刷新冷却锚点。
    #[tokio::test]
    async fn m4_b2b_worker_cooldown_and_resolve_exemption() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());
        let mut rule = rule("rule-cooldown", 1_800);
        let channel = channel("冷却群", true);
        rule.channel_ids = vec![channel.id.clone()];
        seed_rule(&storage, &rule);
        seed_channel(&storage, &channel);
        storage
            .upsert_alert_state(&firing_state(
                &rule.id,
                "agent-1",
                "series-1",
                Some(NOW - 1_000),
            ))
            .unwrap();

        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        let firing = insert_event(
            &storage,
            event(
                &rule.id,
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                false,
            ),
        );
        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW + 1)
            .await
            .unwrap();
        assert_eq!(report.skipped, 1);
        assert_eq!(mock.send_count(), 0, "冷却中不能发送");
        let stored = stored_event(&storage, firing);
        assert!(stored.notified);
        assert_eq!(stored.notify_error, "cooldown");

        // 恢复通知不受 cooldown 限制；发送成功后也不更新 last_notified_at。
        let mut resolved_state = firing_state(&rule.id, "agent-1", "series-1", Some(NOW - 1_000));
        resolved_state.state = AlertStateKind::Resolved;
        storage.upsert_alert_state(&resolved_state).unwrap();
        let resolved = insert_event(
            &storage,
            event(
                &rule.id,
                "agent-1",
                "series-1",
                AlertStateKind::Resolved,
                false,
            ),
        );
        let report = notify_once(storage.clone(), mock.clone(), report.cursor, NOW + 2)
            .await
            .unwrap();
        assert_eq!(report.sent, 1);
        assert_eq!(mock.send_count(), 1);
        let state = storage
            .get_alert_state(&rule.id, "agent-1", "series-1")
            .unwrap()
            .unwrap();
        assert_eq!(
            state.last_notified_at,
            Some(NOW - 1_000),
            "恢复通知不能重置冷却锚点"
        );
        assert!(stored_event(&storage, resolved).notified);
    }

    /// 无渠道 / 渠道不存在 / 渠道全禁用 / 规则不存在都标记固定原因且不阻塞。
    #[tokio::test]
    async fn m4_b2b_worker_marks_no_channel_missing_rule_and_disabled() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());

        let no_channel = rule("rule-no-channel", 0);
        seed_rule(&storage, &no_channel);

        let mut missing_channel = rule("rule-missing-channel", 0);
        missing_channel.channel_ids = vec!["00000000-0000-4000-8000-999999999999".into()];
        seed_rule(&storage, &missing_channel);

        let disabled_channel = channel("禁用渠道", false);
        seed_channel(&storage, &disabled_channel);
        let mut disabled = rule("rule-disabled-channel", 0);
        disabled.channel_ids = vec![disabled_channel.id.clone()];
        seed_rule(&storage, &disabled);

        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        let ids = [
            insert_event(
                &storage,
                event(
                    &no_channel.id,
                    "agent-1",
                    "series-1",
                    AlertStateKind::Firing,
                    false,
                ),
            ),
            insert_event(
                &storage,
                event(
                    &missing_channel.id,
                    "agent-1",
                    "series-1",
                    AlertStateKind::Firing,
                    false,
                ),
            ),
            insert_event(
                &storage,
                event(
                    &disabled.id,
                    "agent-1",
                    "series-1",
                    AlertStateKind::Firing,
                    false,
                ),
            ),
            insert_event(
                &storage,
                event(
                    "rule-does-not-exist",
                    "agent-1",
                    "series-1",
                    AlertStateKind::Firing,
                    false,
                ),
            ),
        ];
        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW + 1)
            .await
            .unwrap();
        assert_eq!(report.processed, 4);
        assert_eq!(report.skipped, 4);
        assert_eq!(mock.send_count(), 0);

        for (id, reason) in [
            (ids[0], "no_channel"),
            (ids[1], "channel_missing"),
            (ids[2], "no_channel"),
            (ids[3], "rule_missing"),
        ] {
            let stored = stored_event(&storage, id);
            assert!(stored.notified, "event {id} 必须标记避免重试");
            assert_eq!(stored.notify_error, reason, "event {id}");
        }
    }

    /// 部分失败：至少一个成功 → 事件成功且错误为空；全部失败 → 固定摘要。
    #[tokio::test]
    async fn m4_b2b_worker_partial_and_total_failure() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());

        let first = channel("渠道-1", true);
        let second = channel("渠道-2", true);
        seed_channel(&storage, &first);
        seed_channel(&storage, &second);
        let mut partial = rule("rule-partial", 0);
        partial.channel_ids = vec![first.id.clone(), second.id.clone()];
        seed_rule(&storage, &partial);
        storage
            .upsert_alert_state(&firing_state(&partial.id, "agent-1", "series-1", None))
            .unwrap();

        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        mock.push_result(Ok(()));
        mock.push_result(Err(NotifyError::Timeout));
        let event_id = insert_event(
            &storage,
            event(
                &partial.id,
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                false,
            ),
        );
        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW + 1)
            .await
            .unwrap();
        assert_eq!(report.sent, 1);
        assert_eq!(mock.send_count(), 2);
        let stored = stored_event(&storage, event_id);
        assert!(stored.notified);
        assert!(stored.notify_error.is_empty(), "至少一个成功不写失败摘要");
        assert_eq!(
            storage
                .get_alert_state(&partial.id, "agent-1", "series-1")
                .unwrap()
                .unwrap()
                .last_notified_at,
            Some(NOW + 1)
        );

        // 全部失败：notified = 1、摘要含两个渠道名与固定 code、不含 URL/secret。
        let failing = Arc::new(MockNotifier::failing(NotifyError::Transport));
        let mut all_fail = rule("rule-all-fail", 0);
        all_fail.channel_ids = vec![first.id.clone(), second.id.clone()];
        seed_rule(&storage, &all_fail);
        storage
            .upsert_alert_state(&firing_state(&all_fail.id, "agent-1", "series-1", None))
            .unwrap();
        let failed_id = insert_event(
            &storage,
            event(
                &all_fail.id,
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                false,
            ),
        );
        let report = notify_once(storage.clone(), failing.clone(), report.cursor, NOW + 2)
            .await
            .unwrap();
        assert_eq!(report.failed, 1);
        let stored = stored_event(&storage, failed_id);
        assert!(stored.notified);
        let error = stored.notify_error;
        assert!(error.contains("渠道-1"), "error={error}");
        assert!(error.contains("渠道-2"), "error={error}");
        assert!(error.contains("transport"), "error={error}");
        assert!(error.len() <= 512);
        assert!(!error.contains("https://"));
        assert!(!error.contains("123456789:AAH"));
        assert_eq!(
            storage
                .list_pending_notification_events_after(0, 100)
                .unwrap()
                .len(),
            0,
            "全部失败也必须标记，不能永久重试"
        );
    }

    /// 静默事件永不发送；单 tick 严格限制 50 条，游标在批末推进。
    #[tokio::test]
    async fn m4_b2b_worker_silence_defense_and_batch_limit() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());
        let mut rule = rule("rule-batch", 0);
        let channel = channel("批量渠道", true);
        rule.channel_ids = vec![channel.id.clone()];
        seed_rule(&storage, &rule);
        seed_channel(&storage, &channel);

        // 先建立游标（空库 = 0），再写入事件；否则首次上线会把它们当存量跳过。
        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        assert_eq!(cursor, 0);

        let silenced = insert_event(
            &storage,
            event(
                &rule.id,
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                true,
            ),
        );
        for _ in 0..(NOTIFY_BATCH_LIMIT + 1) {
            insert_event(
                &storage,
                event(
                    &rule.id,
                    "agent-1",
                    "series-1",
                    AlertStateKind::Firing,
                    false,
                ),
            );
        }

        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW + 1)
            .await
            .unwrap();
        assert_eq!(report.processed, NOTIFY_BATCH_LIMIT);
        assert_eq!(mock.send_count(), NOTIFY_BATCH_LIMIT);
        assert!(
            !stored_event(&storage, silenced).notified,
            "静默事件保持 B1b 状态，不发送也不标记"
        );

        let report = notify_once(storage.clone(), mock.clone(), report.cursor, NOW + 2)
            .await
            .unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(mock.send_count(), NOTIFY_BATCH_LIMIT + 1);
    }

    /// 冷却按 (rule, agent, series) 精确比较：同 agent 的 A 序列发送后，B 序列
    /// 首次 firing 不能被 A 的通知时间误判成冷却中。
    #[tokio::test]
    async fn m4_b2b_worker_cooldown_is_per_series() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());
        let mut rule = rule("rule-two-series", 1_800);
        let channel = channel("双序列渠道", true);
        rule.channel_ids = vec![channel.id.clone()];
        seed_rule(&storage, &rule);
        seed_channel(&storage, &channel);
        storage
            .upsert_alert_state(&firing_state(&rule.id, "agent-1", "series-a", None))
            .unwrap();
        storage
            .upsert_alert_state(&firing_state(&rule.id, "agent-1", "series-b", None))
            .unwrap();

        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        let a = insert_event(
            &storage,
            event(
                &rule.id,
                "agent-1",
                "series-a",
                AlertStateKind::Firing,
                false,
            ),
        );
        let b = insert_event(
            &storage,
            event(
                &rule.id,
                "agent-1",
                "series-b",
                AlertStateKind::Firing,
                false,
            ),
        );
        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW + 1)
            .await
            .unwrap();
        assert_eq!(report.sent, 2, "两个序列都必须发送");
        assert_eq!(mock.send_count(), 2);
        assert!(stored_event(&storage, a).notified);
        assert!(stored_event(&storage, b).notified);
        for series in ["series-a", "series-b"] {
            let state = storage
                .get_alert_state(&rule.id, "agent-1", series)
                .unwrap()
                .expect("状态必须存在");
            assert_eq!(
                state.last_notified_at,
                Some(NOW + 1),
                "{series} 必须在自己的序列上记录通知时间"
            );
        }
    }

    /// 事件落库后新建的静默：发送前重新检查当前生效静默，命中不发送。
    #[tokio::test]
    async fn m4_b2b_worker_rechecks_late_silence_before_send() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());
        let mut rule = rule("rule-late-silence", 0);
        let channel = channel("晚到静默渠道", true);
        rule.channel_ids = vec![channel.id.clone()];
        seed_rule(&storage, &rule);
        seed_channel(&storage, &channel);

        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        let event_id = insert_event(
            &storage,
            event(
                &rule.id,
                "agent-1",
                "series-1",
                AlertStateKind::Firing,
                false,
            ),
        );
        // 先事件、后静默：事件落库时还未命中静默。
        storage
            .create_alert_silence(&AlertSilence {
                id: 0,
                rule_id: Some(rule.id.clone()),
                agent_id: Some("agent-1".to_string()),
                until_ts: NOW + 60_000,
                created_by: "admin".to_string(),
                created_at: NOW + 1,
            })
            .unwrap();

        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW + 2)
            .await
            .unwrap();
        assert_eq!(report.skipped, 1);
        assert_eq!(mock.send_count(), 0, "晚到静默必须阻止发送");
        let stored = stored_event(&storage, event_id);
        assert!(stored.notified);
        assert_eq!(stored.notify_error, "silenced_late");
    }

    /// 恢复通知关闭：标记 resolve_disabled，不发送。
    #[tokio::test]
    async fn m4_b2b_worker_resolve_disabled_is_marked() {
        let storage = Arc::new(SqliteStorage::open_in_memory().unwrap());
        let mock = Arc::new(MockNotifier::new());
        let mut rule = rule("rule-no-resolve", 0);
        rule.notify_on_resolve = false;
        let channel = channel("不恢复通知", true);
        rule.channel_ids = vec![channel.id.clone()];
        seed_rule(&storage, &rule);
        seed_channel(&storage, &channel);
        storage
            .upsert_alert_state(&AlertState {
                state: AlertStateKind::Resolved,
                ..firing_state(&rule.id, "agent-1", "series-1", None)
            })
            .unwrap();

        let cursor = initialize_notify_cursor(&storage, NOW).unwrap();
        let id = insert_event(
            &storage,
            event(
                &rule.id,
                "agent-1",
                "series-1",
                AlertStateKind::Resolved,
                false,
            ),
        );
        let report = notify_once(storage.clone(), mock.clone(), cursor, NOW + 1)
            .await
            .unwrap();
        assert_eq!(report.skipped, 1);
        assert_eq!(mock.send_count(), 0);
        let stored = stored_event(&storage, id);
        assert!(stored.notified);
        assert_eq!(stored.notify_error, "resolve_disabled");
    }
}
