//! M4-B1b 告警状态机 / 状态 / 事件 / 静默独立集成测试。
//!
//! 依据：`docs/plans/2026-10-24-m4-alerting-archive.md` §6.1 / §8.1 / §11.1，
//! `crates/rustboard-core/src/alerts.rs` 的公开类型、`next_alert_state` /
//! `new_alert_event` 文档，以及 `crates/rustboard-core/src/storage/sqlite.rs`
//! 的公开 state / event / silence 方法签名与文档。
//! 不参考内部实现；不修改生产代码；不弱化断言。
//!
//! 数据库一律使用文件库（`std::env::temp_dir()` 下每个用例自建唯一目录），
//! 通过 `SqliteStorage::open` 打开，不借助内存库掩盖持久化问题。

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustboard_common::model::Labels;
use rustboard_core::alerts::{
    evaluate_condition, new_alert_event, next_alert_state, AlertEvent, AlertRule, AlertSilence,
    AlertSilenceInput, AlertSource, AlertState, AlertStateKind, AlertTransition, Comparator,
    MAX_ALERT_MESSAGE_BYTES, MAX_SILENCE_DURATION_SECS, MIN_SILENCE_DURATION_SECS,
};
use rustboard_core::storage::sqlite::SqliteStorage;

// ---------------------------------------------------------------------------
// 测试基础设施
// ---------------------------------------------------------------------------

/// 每个用例自建唯一临时目录，`Drop` 时递归清理。
struct TempDbDir {
    root: PathBuf,
}

impl TempDbDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系统时间早于 UNIX_EPOCH")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rb-m4-b1b-state-{}-{tag}-{nanos}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("创建临时目录失败");
        Self { root }
    }

    fn db_path(&self) -> PathBuf {
        self.root.join("rustboard.db")
    }
}

impl Drop for TempDbDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn open_storage(dir: &TempDbDir) -> SqliteStorage {
    SqliteStorage::open(&dir.db_path()).expect("SqliteStorage::open 失败")
}

/// 一条语义合法的 metric 规则；用例只按需覆盖 `duration_secs`。
fn rule_with_duration(duration_secs: u32) -> AlertRule {
    AlertRule {
        id: "rule-cpu".to_string(),
        name: "CPU 使用率过高".to_string(),
        enabled: true,
        source: AlertSource::Metric,
        metric: "cpu.usage".to_string(),
        comparator: Comparator::Gte,
        threshold: 80.0,
        duration_secs,
        cooldown_secs: 300,
        filter_agent_id: None,
        filter_labels: Labels::new(),
        channel_ids: Vec::new(),
        notify_on_resolve: true,
        is_builtin: false,
        updated_by: "admin".to_string(),
        created_at: 1_700_000_000_000,
        updated_at: 1_700_000_000_000,
    }
}

/// 构造一条状态；`last_value` / `last_notified_at` 由用例按需补齐。
fn alert_state(
    rule_id: &str,
    agent_id: &str,
    series_key: &str,
    state: AlertStateKind,
    since: i64,
    last_eval_at: i64,
) -> AlertState {
    AlertState {
        rule_id: rule_id.to_string(),
        agent_id: agent_id.to_string(),
        series_key: series_key.to_string(),
        state,
        since,
        last_eval_at,
        last_value: None,
        last_notified_at: None,
    }
}

/// 构造一条待落库的静默；`id` 由用例在插入后回填。
fn alert_silence(
    rule_id: Option<&str>,
    agent_id: Option<&str>,
    until_ts: i64,
    created_by: &str,
    created_at: i64,
) -> AlertSilence {
    AlertSilence {
        id: 0,
        rule_id: rule_id.map(str::to_string),
        agent_id: agent_id.map(str::to_string),
        until_ts,
        created_by: created_by.to_string(),
        created_at,
    }
}

/// 构造一条手工事件；默认字段齐全，用例按需覆盖。
fn manual_event(ts: i64, rule_name: &str) -> AlertEvent {
    AlertEvent {
        id: 0,
        ts,
        rule_id: "rule-cpu".to_string(),
        rule_name: rule_name.to_string(),
        agent_id: "agent-01".to_string(),
        state: AlertStateKind::Firing,
        value: Some(95.0),
        message: format!("规则「{rule_name}」触发：CPU 使用率过高"),
        notified: false,
        notify_error: String::new(),
        silenced: false,
    }
}

// ---------------------------------------------------------------------------
// 1. next_alert_state：方案 §6.2 状态机
// ---------------------------------------------------------------------------

#[test]
fn next_alert_state_follows_documented_state_machine() {
    let base = 1_700_000_000_000_i64;
    let immediate_rule = rule_with_duration(0);
    let delayed_rule = rule_with_duration(60);
    let agent = "agent-01";
    let series = "series-a";

    // 无状态 + 条件不满足：不创建状态、不产生事件。
    let idle = next_alert_state(None, &immediate_rule, agent, series, 10.0, base);
    assert_eq!(
        idle,
        AlertTransition::default(),
        "无状态且条件不满足时必须是空转换"
    );
    assert_eq!(idle.state, None);
    assert_eq!(idle.event, None);

    // 无状态 + 条件满足 + duration=0：同一轮直接 firing，并产生 firing 事件。
    let first = next_alert_state(None, &immediate_rule, agent, series, 95.0, base);
    assert_eq!(
        first.event,
        Some(AlertStateKind::Firing),
        "duration=0 首次满足必须产生 firing 事件"
    );
    let firing = first
        .state
        .clone()
        .expect("duration=0 首次满足必须写入 firing 状态");
    assert_eq!(firing.state, AlertStateKind::Firing);
    assert_eq!(firing.rule_id, immediate_rule.id);
    assert_eq!(firing.agent_id, agent);
    assert_eq!(firing.series_key, series);
    assert_eq!(
        firing.since, base,
        "首次进入 firing 的 since 必须是本轮时间"
    );
    assert_eq!(firing.last_eval_at, base);
    assert_eq!(firing.last_value, Some(95.0));
    assert_eq!(firing.last_notified_at, None, "B1b 不写通知时间");

    // 无状态 + 条件满足 + duration>0：进入 pending 计时，不产生事件。
    let pending_transition = next_alert_state(None, &delayed_rule, agent, series, 95.0, base);
    assert_eq!(
        pending_transition.event, None,
        "首次进入 pending 不得产生事件"
    );
    let pending = pending_transition
        .state
        .clone()
        .expect("duration>0 首次满足必须写入 pending 状态");
    assert_eq!(pending.state, AlertStateKind::Pending);
    assert_eq!(pending.since, base);
    assert_eq!(pending.last_eval_at, base);
    assert_eq!(pending.last_value, Some(95.0));

    // 距时长还差 1 毫秒：仍 pending；since 保持不变，评估时间与观测值刷新。
    let before_duration = next_alert_state(
        Some(&pending),
        &delayed_rule,
        agent,
        series,
        96.0,
        base + 59_999,
    );
    assert_eq!(
        before_duration.event, None,
        "未到 duration 不得产生 firing 事件"
    );
    let still_pending = before_duration
        .state
        .clone()
        .expect("未到 duration 必须继续保持 pending");
    assert_eq!(still_pending.state, AlertStateKind::Pending);
    assert_eq!(still_pending.since, base, "pending 计时起点不得被刷新");
    assert_eq!(still_pending.last_eval_at, base + 59_999);
    assert_eq!(still_pending.last_value, Some(96.0));

    // 恰好达到 duration：pending → firing，且只产生一条 firing 事件。
    let reached = next_alert_state(
        Some(&still_pending),
        &delayed_rule,
        agent,
        series,
        97.0,
        base + 60_000,
    );
    assert_eq!(
        reached.event,
        Some(AlertStateKind::Firing),
        "达到 duration 必须产生 firing 事件"
    );
    let firing_from_pending = reached
        .state
        .clone()
        .expect("达到 duration 必须写入 firing 状态");
    assert_eq!(firing_from_pending.state, AlertStateKind::Firing);
    assert_eq!(
        firing_from_pending.since,
        base + 60_000,
        "进入 firing 的 since 必须是本轮时间"
    );
    assert_eq!(firing_from_pending.last_eval_at, base + 60_000);

    // firing + 条件继续满足：状态不变、since 保持、不重复产生 firing 事件；
    // last_notified_at 原样保留（B1b 不发通知，留给 B2）。
    let mut notified = firing_from_pending.clone();
    notified.last_notified_at = Some(base + 61_000);
    let repeat = next_alert_state(
        Some(&notified),
        &delayed_rule,
        agent,
        series,
        98.0,
        base + 75_000,
    );
    assert_eq!(
        repeat.event, None,
        "firing 条件继续满足不得重复产生 firing 事件"
    );
    let still_firing = repeat
        .state
        .clone()
        .expect("firing 条件继续满足必须保持 firing 状态");
    assert_eq!(still_firing.state, AlertStateKind::Firing);
    assert_eq!(
        still_firing.since,
        base + 60_000,
        "firing 期间 since 不得变化"
    );
    assert_eq!(still_firing.last_eval_at, base + 75_000);
    assert_eq!(still_firing.last_value, Some(98.0));
    assert_eq!(
        still_firing.last_notified_at,
        Some(base + 61_000),
        "last_notified_at 必须原样保留"
    );

    // firing + 条件不满足：resolved 且产生恢复事件。
    let recovered = next_alert_state(
        Some(&still_firing),
        &delayed_rule,
        agent,
        series,
        10.0,
        base + 90_000,
    );
    assert_eq!(
        recovered.event,
        Some(AlertStateKind::Resolved),
        "firing 条件不满足必须产生 resolved 事件"
    );
    let resolved = recovered
        .state
        .clone()
        .expect("firing 条件不满足必须写入 resolved 状态");
    assert_eq!(resolved.state, AlertStateKind::Resolved);
    assert_eq!(resolved.since, base + 90_000);

    // pending + 条件不满足：resolved 但不产生事件（抖动不打扰用户）。
    let pending_recovered = next_alert_state(
        Some(&pending),
        &delayed_rule,
        agent,
        series,
        10.0,
        base + 1_000,
    );
    assert_eq!(
        pending_recovered.event, None,
        "pending 直接恢复不得产生 resolved 事件"
    );
    let pending_resolved = pending_recovered
        .state
        .clone()
        .expect("pending 条件不满足必须写入 resolved 状态");
    assert_eq!(pending_resolved.state, AlertStateKind::Resolved);
    assert_eq!(pending_resolved.since, base + 1_000);

    // resolved + 条件再次满足 + duration>0：回到 pending 重新计时，不产生事件。
    let retime = next_alert_state(
        Some(&resolved),
        &delayed_rule,
        agent,
        series,
        95.0,
        base + 120_000,
    );
    assert_eq!(
        retime.event, None,
        "resolved 重新计时进入 pending 不得产生事件"
    );
    let retimed = retime
        .state
        .clone()
        .expect("resolved 条件满足必须写入 pending 状态");
    assert_eq!(retimed.state, AlertStateKind::Pending);
    assert_eq!(
        retimed.since,
        base + 120_000,
        "resolved 后必须从本轮重新计时"
    );

    // resolved + 条件再次满足 + duration=0：同一轮直接 firing 并产生事件。
    let relight = next_alert_state(
        Some(&resolved),
        &immediate_rule,
        agent,
        series,
        95.0,
        base + 120_000,
    );
    assert_eq!(
        relight.event,
        Some(AlertStateKind::Firing),
        "duration=0 的 resolved 再次满足必须产生 firing 事件"
    );
    let relit = relight
        .state
        .clone()
        .expect("duration=0 的 resolved 再次满足必须写入 firing 状态");
    assert_eq!(relit.state, AlertStateKind::Firing);
    assert_eq!(relit.since, base + 120_000);

    // resolved + 条件仍不满足：保持 resolved，since 不变，不产生事件。
    let stay = next_alert_state(
        Some(&resolved),
        &delayed_rule,
        agent,
        series,
        10.0,
        base + 150_000,
    );
    assert_eq!(stay.event, None);
    let stayed = stay
        .state
        .clone()
        .expect("resolved 条件不满足必须保持 resolved 状态");
    assert_eq!(stayed.state, AlertStateKind::Resolved);
    assert_eq!(stayed.since, resolved.since, "resolved 期间 since 不得变化");
    assert_eq!(stayed.last_eval_at, base + 150_000);

    // NaN / 非有限阈值：任何比较符一律 false（包括 ne），不得误告警。
    for comparator in [
        Comparator::Gt,
        Comparator::Gte,
        Comparator::Lt,
        Comparator::Lte,
        Comparator::Eq,
        Comparator::Ne,
    ] {
        assert!(
            !evaluate_condition(comparator, 80.0, f64::NAN),
            "{comparator:?} 对 NaN 观测值必须为 false"
        );
        assert!(
            !evaluate_condition(comparator, f64::NAN, 95.0),
            "{comparator:?} 对 NaN 阈值必须为 false"
        );
        assert!(
            !evaluate_condition(comparator, f64::INFINITY, 95.0),
            "{comparator:?} 对 +Inf 阈值必须为 false"
        );
        assert!(
            !evaluate_condition(comparator, f64::NEG_INFINITY, 95.0),
            "{comparator:?} 对 -Inf 阈值必须为 false"
        );
    }
    // 状态机把 NaN 观测值按“条件不满足”处理：无状态不建行；firing → resolved 事件；
    // 非有限观测值落库必须是 None（公开文档：非有限值存 None）。
    let nan_idle = next_alert_state(None, &immediate_rule, agent, series, f64::NAN, base);
    assert_eq!(nan_idle, AlertTransition::default());
    let nan_recovered = next_alert_state(
        Some(&firing),
        &immediate_rule,
        agent,
        series,
        f64::NAN,
        base + 1_000,
    );
    assert_eq!(
        nan_recovered.event,
        Some(AlertStateKind::Resolved),
        "NaN 观测值必须被视为条件不满足"
    );
    let nan_state = nan_recovered.state.clone().expect("NaN 观测值必须推进状态");
    assert_eq!(nan_state.state, AlertStateKind::Resolved);
    assert_eq!(
        nan_state.last_value, None,
        "非有限观测值必须存为 None 而不是 NaN"
    );
}

// ---------------------------------------------------------------------------
// 2. 文件库状态往返与 30 天 resolved 清理
// ---------------------------------------------------------------------------

#[test]
fn alert_state_storage_roundtrip_and_30_day_resolved_prune() {
    let dir = TempDbDir::new("states");
    let storage = open_storage(&dir);
    let now = 1_700_000_000_000_i64;

    assert!(
        storage.list_alert_states().expect("列表失败").is_empty(),
        "新库不得有告警状态"
    );

    // 四行覆盖 metric 每序列独立、agent_offline 每 agent 独立、hub_cert 全局形态，
    // 以及 last_value / last_notified_at 的 Some / None 两种取值。
    let mut firing = alert_state(
        "rule-a",
        "agent-01",
        "series-1",
        AlertStateKind::Firing,
        now - 1_000,
        now,
    );
    firing.last_value = Some(95.5);
    firing.last_notified_at = Some(now - 500);
    let pending = alert_state(
        "rule-a",
        "agent-01",
        "series-2",
        AlertStateKind::Pending,
        now - 2_000,
        now - 1_000,
    );
    let mut other_agent = alert_state(
        "rule-a",
        "agent-02",
        "",
        AlertStateKind::Firing,
        now - 3_000,
        now - 2_000,
    );
    other_agent.last_value = Some(1.0);
    let mut global = alert_state(
        "rule-b",
        "",
        "",
        AlertStateKind::Resolved,
        now - 4_000,
        now - 3_000,
    );
    global.last_value = Some(2.5);

    // 乱序写入，验证读取与排序不依赖插入顺序。
    for state in [&other_agent, &pending, &global, &firing] {
        storage.upsert_alert_state(state).expect("写入状态失败");
    }

    for expected in [&firing, &pending, &other_agent, &global] {
        let fetched = storage
            .get_alert_state(&expected.rule_id, &expected.agent_id, &expected.series_key)
            .expect("读取状态失败");
        assert_eq!(
            fetched.as_ref(),
            Some(expected),
            "状态必须逐字段往返: {}/{}/{}",
            expected.rule_id,
            expected.agent_id,
            expected.series_key
        );
    }
    assert_eq!(
        storage.list_alert_states().expect("列表失败"),
        vec![
            firing.clone(),
            pending.clone(),
            other_agent.clone(),
            global.clone()
        ],
        "状态必须按 (rule_id, agent_id, series_key) 稳定排序"
    );

    // 同主键 upsert 覆盖全部字段，不新增行。
    let mut updated = firing.clone();
    updated.state = AlertStateKind::Resolved;
    updated.since = now + 1;
    updated.last_eval_at = now + 2;
    updated.last_value = None;
    updated.last_notified_at = Some(now + 3);
    storage.upsert_alert_state(&updated).expect("更新状态失败");
    assert_eq!(
        storage.list_alert_states().expect("列表失败").len(),
        4,
        "upsert 同一主键不得新增行"
    );
    assert_eq!(
        storage
            .get_alert_state("rule-a", "agent-01", "series-1")
            .expect("读取失败"),
        Some(updated.clone()),
        "upsert 必须覆盖 state / since / last_eval_at / last_value / last_notified_at"
    );

    // delete 返回受影响行数：存在 1、再次 0。
    assert_eq!(
        storage
            .delete_alert_state("rule-a", "agent-02", "")
            .expect("删除失败"),
        1,
        "删除已存在状态必须返回 1"
    );
    assert_eq!(
        storage
            .get_alert_state("rule-a", "agent-02", "")
            .expect("读取失败"),
        None
    );
    assert_eq!(
        storage
            .delete_alert_state("rule-a", "agent-02", "")
            .expect("删除失败"),
        0,
        "重复删除必须返回 0"
    );
    assert_eq!(storage.list_alert_states().expect("列表失败").len(), 3);

    // 文件库持久化：关闭后重新打开，状态与更新结果仍在。
    drop(storage);
    let storage = open_storage(&dir);
    assert_eq!(
        storage
            .get_alert_state("rule-a", "agent-01", "series-1")
            .expect("读取失败"),
        Some(updated.clone()),
        "重启后状态必须持久化"
    );
    assert_eq!(storage.list_alert_states().expect("列表失败").len(), 3);

    // 30 天 resolved 清理：只删 state=resolved 且 last_eval_at < cutoff 的行。
    let prune_dir = TempDbDir::new("states-prune");
    let storage = open_storage(&prune_dir);
    let day_ms = 86_400_000_i64;
    let cutoff = now - 30 * day_ms;

    let mut old_firing = alert_state(
        "prune-firing",
        "agent-01",
        "s",
        AlertStateKind::Firing,
        now - 40 * day_ms,
        now - 40 * day_ms,
    );
    old_firing.last_value = Some(99.0);
    let old_pending = alert_state(
        "prune-pending",
        "agent-01",
        "s",
        AlertStateKind::Pending,
        now - 40 * day_ms,
        now - 40 * day_ms,
    );
    let stale_resolved = alert_state(
        "prune-stale-resolved",
        "agent-01",
        "s",
        AlertStateKind::Resolved,
        now - 40 * day_ms,
        cutoff - 1,
    );
    let boundary_resolved = alert_state(
        "prune-boundary-resolved",
        "agent-01",
        "s",
        AlertStateKind::Resolved,
        now - 30 * day_ms,
        cutoff,
    );
    let fresh_resolved = alert_state(
        "prune-fresh-resolved",
        "agent-01",
        "s",
        AlertStateKind::Resolved,
        now - day_ms,
        now - day_ms,
    );

    for state in [
        &old_firing,
        &old_pending,
        &stale_resolved,
        &boundary_resolved,
        &fresh_resolved,
    ] {
        storage.upsert_alert_state(state).expect("写入状态失败");
    }

    assert_eq!(
        storage
            .prune_alert_states(cutoff)
            .expect("清理 resolved 状态失败"),
        1,
        "只允许删除 last_eval_at 严格早于 cutoff 的 resolved 状态"
    );
    assert_eq!(
        storage
            .get_alert_state("prune-stale-resolved", "agent-01", "s")
            .expect("读取失败"),
        None,
        "超过 30 天的 resolved 状态必须被清理"
    );
    for kept in [
        &old_firing,
        &old_pending,
        &boundary_resolved,
        &fresh_resolved,
    ] {
        assert_eq!(
            storage
                .get_alert_state(&kept.rule_id, &kept.agent_id, &kept.series_key)
                .expect("读取失败")
                .as_ref(),
            Some(kept),
            "firing / pending 无论多旧、resolved 在 cutoff 边界都不得被清理: {}",
            kept.rule_id
        );
    }

    // 幂等：同一 cutoff 再清理返回 0；cutoff 用 i64::MAX 时清掉全部 resolved。
    assert_eq!(storage.prune_alert_states(cutoff).expect("重复清理失败"), 0);
    assert_eq!(
        storage
            .prune_alert_states(i64::MAX)
            .expect("清理全部 resolved 失败"),
        2,
        "只剩 boundary 与 fresh 两条 resolved 可删"
    );
    assert_eq!(
        storage
            .get_alert_state("prune-firing", "agent-01", "s")
            .expect("读取失败")
            .as_ref(),
        Some(&old_firing),
        "resolved 清理不得误删 firing 状态"
    );
    assert_eq!(
        storage
            .get_alert_state("prune-pending", "agent-01", "s")
            .expect("读取失败")
            .as_ref(),
        Some(&old_pending),
        "resolved 清理不得误删 pending 状态"
    );
}

// ---------------------------------------------------------------------------
// 3. 事件落库、字段往返、before_id 排他分页、prune 顺序
// ---------------------------------------------------------------------------

#[test]
fn alert_events_roundtrip_pagination_and_prune_order() {
    let dir = TempDbDir::new("events");
    let storage = open_storage(&dir);
    let now = 1_700_000_000_000_i64;
    let rule = rule_with_duration(0);

    assert!(
        storage
            .list_alert_events(100, None)
            .expect("列表失败")
            .is_empty(),
        "新库不得有告警事件"
    );

    // new_alert_event：字段完整性、silenced 往返、B1b 默认 notified=false / 空错误。
    let generated = new_alert_event(&rule, "agent-01", AlertStateKind::Firing, 95.5, now, true);
    assert_eq!(generated.id, 0, "新事件 id 必须为 0，由存储层回填");
    assert!(!generated.notified, "B1b 新事件 notified 必须为 false");
    assert_eq!(
        generated.notify_error, "",
        "B1b 新事件 notify_error 必须为空"
    );
    assert!(generated.silenced, "命中静默的事件必须保留 silenced=true");
    assert!(
        generated.message.len() <= MAX_ALERT_MESSAGE_BYTES,
        "事件描述不得超过 {MAX_ALERT_MESSAGE_BYTES} 字节"
    );
    let generated_id = storage
        .insert_alert_event(&generated)
        .expect("插入新事件失败");
    assert!(generated_id > 0, "插入必须返回正的自增 id");
    let stored = storage.list_alert_events(10, None).expect("列表失败");
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0],
        AlertEvent {
            id: generated_id,
            ..generated.clone()
        },
        "new_alert_event 的事件必须逐字段往返"
    );

    // 手工事件覆盖 notified=true / notify_error 非空 / value=None 的全部列往返；
    // 同时验证 insert 忽略调用方提供的 event.id。
    let mut manual = manual_event(now + 1, "CPU 使用率过高");
    manual.id = 999_999;
    manual.agent_id = "agent-02".to_string();
    manual.state = AlertStateKind::Resolved;
    manual.value = None;
    manual.message =
        "规则「CPU 使用率过高」恢复：agent agent-02 指标「cpu.usage」当前值 非数值".to_string();
    manual.notified = true;
    manual.notify_error = "queue_full".to_string();
    manual.silenced = true;
    let manual_id = storage
        .insert_alert_event(&manual)
        .expect("插入手工事件失败");
    assert_ne!(manual_id, 999_999, "insert 必须忽略 event.id");
    let listed = storage.list_alert_events(10, None).expect("列表失败");
    assert_eq!(
        listed[0],
        AlertEvent {
            id: manual_id,
            ..manual.clone()
        },
        "notified / notify_error / value=None 必须完整往返"
    );
    assert!(
        listed.iter().all(|event| event.id != 999_999),
        "库中不得出现调用方伪造的 id"
    );

    // 再插入 5 条用于分页；ts 故意递减，证明排序按 id 而不是 ts。
    let mut inserted_ids = Vec::new();
    for index in 0..5 {
        let mut event = manual_event(now - index, "分页事件");
        event.value = Some(index as f64);
        event.message = format!("分页事件 {index}");
        inserted_ids.push(
            storage
                .insert_alert_event(&event)
                .expect("插入分页事件失败"),
        );
    }
    assert!(
        inserted_ids.windows(2).all(|pair| pair[0] < pair[1]),
        "事件 id 必须严格递增"
    );

    let all_ids: Vec<i64> = storage
        .list_alert_events(100, None)
        .expect("列表失败")
        .iter()
        .map(|event| event.id)
        .collect();
    let mut expected_ids: Vec<i64> = inserted_ids.clone();
    expected_ids.reverse();
    expected_ids.push(manual_id);
    expected_ids.push(generated_id);
    assert_eq!(
        all_ids, expected_ids,
        "事件必须按 id 倒序（最新在前），不得按 ts 排序"
    );

    // before_id 是排他游标：只返回 id 严格小于游标的事件。
    let page_1 = storage.list_alert_events(2, None).expect("分页失败");
    assert_eq!(
        page_1.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![inserted_ids[4], inserted_ids[3]]
    );
    let page_2 = storage
        .list_alert_events(2, Some(inserted_ids[4]))
        .expect("分页失败");
    assert_eq!(
        page_2.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![inserted_ids[3], inserted_ids[2]],
        "before_id 必须排他，不得重复返回游标本身"
    );
    let tail = storage
        .list_alert_events(10, Some(inserted_ids[1]))
        .expect("分页失败");
    assert_eq!(
        tail.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![inserted_ids[0], manual_id, generated_id],
        "before_id 之后必须按 id 倒序返回全部更旧事件"
    );
    assert!(
        storage
            .list_alert_events(10, Some(generated_id))
            .expect("分页失败")
            .is_empty(),
        "游标之后没有更旧事件时必须返回空列表"
    );
    assert!(
        storage
            .list_alert_events(0, None)
            .expect("分页失败")
            .is_empty(),
        "limit=0 必须返回空列表，不能当成无限制"
    );
    assert!(
        storage
            .list_alert_events(100, Some(0))
            .expect("分页失败")
            .is_empty(),
        "before_id=0 不得返回任何正 id 事件"
    );

    // prune：先按时间删 ts < before_ts，再按 id 从旧到新删到只剩 max_rows 行。
    let prune_dir = TempDbDir::new("events-prune");
    let storage = open_storage(&prune_dir);
    let mut cleanup_ids = Vec::new();
    for (index, ts) in [1_000_i64, 1_000, 1_000, 2_000, 2_000, 2_000]
        .iter()
        .enumerate()
    {
        let mut event = manual_event(*ts, "清理事件");
        event.message = format!("清理事件 {index}");
        cleanup_ids.push(
            storage
                .insert_alert_event(&event)
                .expect("插入清理事件失败"),
        );
    }
    // 时间删除 3 条（ts=1000）后剩 3 条 > max_rows=2，再按 id 从旧到新删 1 条。
    assert_eq!(
        storage.prune_alert_events(1_500, 2).expect("清理事件失败"),
        4,
        "先按时间删 3 条，再按 max_rows 删最旧 1 条"
    );
    let remaining: Vec<i64> = storage
        .list_alert_events(100, None)
        .expect("列表失败")
        .iter()
        .map(|event| event.id)
        .collect();
    assert_eq!(
        remaining,
        vec![cleanup_ids[5], cleanup_ids[4]],
        "按时间清理后必须再按 max_rows 从旧到新裁掉最旧行"
    );
    assert_eq!(
        storage.prune_alert_events(1_500, 2).expect("重复清理失败"),
        0,
        "重复清理必须幂等"
    );

    // max_rows 足够大时只按时间删。
    assert_eq!(
        storage
            .prune_alert_events(2_500, 10)
            .expect("按时间清理失败"),
        2,
        "ts 在删除线之前的事件必须全部删除"
    );
    assert!(storage
        .list_alert_events(100, None)
        .expect("列表失败")
        .is_empty());

    // max_rows=0 表示清空全部事件（两步仍按时间起点开始）。
    let mut zero_ids = Vec::new();
    for index in 0..3 {
        let mut event = manual_event(10_000 + index, "清空事件");
        event.message = format!("清空事件 {index}");
        zero_ids.push(
            storage
                .insert_alert_event(&event)
                .expect("插入清空事件失败"),
        );
    }
    assert_eq!(
        storage.prune_alert_events(0, 0).expect("清空事件失败"),
        3,
        "max_rows=0 必须清空全部事件"
    );
    assert!(storage
        .list_alert_events(100, None)
        .expect("列表失败")
        .is_empty());

    // 仅按 max_rows 保留最新 N 条。
    let mut keep_ids = Vec::new();
    for index in 0..4 {
        let mut event = manual_event(20_000 + index, "保留事件");
        event.message = format!("保留事件 {index}");
        keep_ids.push(
            storage
                .insert_alert_event(&event)
                .expect("插入保留事件失败"),
        );
    }
    assert_eq!(
        storage.prune_alert_events(0, 2).expect("按行数清理失败"),
        2,
        "max_rows=2 时只允许保留最新 2 条"
    );
    let kept: Vec<i64> = storage
        .list_alert_events(100, None)
        .expect("列表失败")
        .iter()
        .map(|event| event.id)
        .collect();
    assert_eq!(
        kept,
        vec![keep_ids[3], keep_ids[2]],
        "按 max_rows 清理必须从最旧 id 开始删"
    );
}

// ---------------------------------------------------------------------------
// 4. 静默窗口 / 通配 / 删除 / 到期清理 / 输入边界
// ---------------------------------------------------------------------------

#[test]
fn alert_silences_window_wildcards_delete_prune_and_input_bounds() {
    let dir = TempDbDir::new("silences");
    let storage = open_storage(&dir);
    let now = 1_700_000_000_000_i64;

    assert!(
        storage
            .list_active_silences(now)
            .expect("列表失败")
            .is_empty(),
        "新库不得有静默"
    );

    // 覆盖：双通配、只通配 rule、只通配 agent、精确匹配、已过期、until==now 边界。
    let wildcard = alert_silence(None, None, now + 600_000, "admin", now);
    let rule_only = alert_silence(Some("rule-a"), None, now + 300_000, "ops", now + 1);
    let agent_only = alert_silence(None, Some("agent-01"), now + 200_000, "ops", now + 2);
    let specific = alert_silence(
        Some("rule-b"),
        Some("agent-02"),
        now + 100_000,
        "ops",
        now + 3,
    );
    let expired = alert_silence(Some("rule-c"), Some("agent-03"), now - 1, "ops", now - 10);
    let boundary = alert_silence(Some("rule-d"), None, now, "ops", now - 10);

    let wildcard_id = storage
        .create_alert_silence(&wildcard)
        .expect("创建静默失败");
    let rule_only_id = storage
        .create_alert_silence(&rule_only)
        .expect("创建静默失败");
    let agent_only_id = storage
        .create_alert_silence(&agent_only)
        .expect("创建静默失败");
    let specific_id = storage
        .create_alert_silence(&specific)
        .expect("创建静默失败");
    let expired_id = storage
        .create_alert_silence(&expired)
        .expect("创建静默失败");
    let boundary_id = storage
        .create_alert_silence(&boundary)
        .expect("创建静默失败");
    for id in [
        wildcard_id,
        rule_only_id,
        agent_only_id,
        specific_id,
        expired_id,
        boundary_id,
    ] {
        assert!(id > 0, "创建静默必须返回正的自增 id");
    }
    assert!(
        [wildcard_id, rule_only_id, agent_only_id, specific_id]
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "静默 id 必须严格递增"
    );

    // 文件库持久化：重启后静默仍在。
    drop(storage);
    let storage = open_storage(&dir);
    let active = storage.list_active_silences(now).expect("列表失败");
    assert_eq!(
        active.iter().map(|silence| silence.id).collect::<Vec<_>>(),
        vec![specific_id, agent_only_id, rule_only_id, wildcard_id],
        "只列出 until_ts > now 的静默，最新创建的在前"
    );
    assert_eq!(
        active[0],
        AlertSilence {
            id: specific_id,
            ..specific.clone()
        },
        "精确静默必须逐字段往返"
    );
    assert_eq!(
        active[3],
        AlertSilence {
            id: wildcard_id,
            ..wildcard.clone()
        },
        "通配静默必须逐字段往返（rule_id/agent_id 为 None）"
    );

    // 通配与精确匹配语义。
    let wildcard_stored = active
        .iter()
        .find(|silence| silence.id == wildcard_id)
        .expect("通配静默必须存在");
    let rule_only_stored = active
        .iter()
        .find(|silence| silence.id == rule_only_id)
        .expect("rule 通配静默必须存在");
    let agent_only_stored = active
        .iter()
        .find(|silence| silence.id == agent_only_id)
        .expect("agent 通配静默必须存在");
    let specific_stored = active
        .iter()
        .find(|silence| silence.id == specific_id)
        .expect("精确静默必须存在");

    assert!(
        wildcard_stored.matches("any-rule", "any-agent", now),
        "双通配必须匹配任意规则/agent"
    );
    assert!(
        wildcard_stored.matches("", "", now),
        "双通配必须匹配空规则/空 agent（全局规则）"
    );
    assert!(
        rule_only_stored.matches("rule-a", "whatever", now),
        "rule 通配必须匹配同规则任意 agent"
    );
    assert!(
        !rule_only_stored.matches("rule-b", "whatever", now),
        "rule 通配不得跨规则匹配"
    );
    assert!(
        agent_only_stored.matches("whatever", "agent-01", now),
        "agent 通配必须匹配同 agent 任意规则"
    );
    assert!(
        !agent_only_stored.matches("whatever", "agent-02", now),
        "agent 通配不得跨 agent 匹配"
    );
    assert!(
        specific_stored.matches("rule-b", "agent-02", now),
        "精确静默必须匹配同 rule/agent"
    );
    assert!(
        !specific_stored.matches("rule-b", "agent-01", now),
        "精确静默 rule 对但 agent 错不得匹配"
    );
    assert!(
        !specific_stored.matches("rule-a", "agent-02", now),
        "精确静默 agent 对但 rule 错不得匹配"
    );

    // 时间窗口排他：until_ts > now 才生效。
    let until = specific_stored.until_ts;
    assert!(
        specific_stored.is_active_at(until - 1),
        "until_ts 前 1ms 必须仍生效"
    );
    assert!(
        !specific_stored.is_active_at(until),
        "until_ts 当刻必须失效（排他窗口）"
    );
    assert!(
        !specific_stored.is_active_at(until + 1),
        "until_ts 之后必须失效"
    );
    assert!(
        !specific_stored.matches("rule-b", "agent-02", until),
        "matches 必须同时检查时间窗口"
    );

    // delete 返回 bool：存在 true、再次 false、不存在 false。
    assert!(
        storage
            .delete_alert_silence(agent_only_id)
            .expect("删除静默失败"),
        "删除已存在静默必须返回 true"
    );
    assert!(
        !storage
            .delete_alert_silence(agent_only_id)
            .expect("删除静默失败"),
        "重复删除必须返回 false"
    );
    assert!(
        !storage.delete_alert_silence(999_999).expect("删除静默失败"),
        "删除不存在的静默必须返回 false"
    );
    assert!(
        storage
            .list_active_silences(now)
            .expect("列表失败")
            .iter()
            .all(|silence| silence.id != agent_only_id),
        "删除后的静默不得再出现在列表中"
    );

    // 到期清理：until_ts <= before_ts 删除（包含边界）。
    assert_eq!(
        storage.prune_alert_silences(now).expect("清理静默失败"),
        2,
        "已过期与 until_ts == now 的静默必须被清理"
    );
    assert_eq!(
        storage
            .prune_alert_silences(now + 100_000)
            .expect("清理静默失败"),
        1,
        "until_ts 恰等于清理线的静默必须被删除"
    );
    assert_eq!(
        storage.prune_alert_silences(now - 1).expect("清理静默失败"),
        0,
        "清理线之前没有到期静默时必须返回 0"
    );
    assert_eq!(
        storage
            .list_active_silences(now)
            .expect("列表失败")
            .iter()
            .map(|silence| silence.id)
            .collect::<Vec<_>>(),
        vec![rule_only_id, wildcard_id],
        "未到期的静默不得被清理"
    );

    // AlertSilenceInput：duration 边界 1..=7d、缺省/显式 null 通配、未知字段拒绝。
    let parsed: AlertSilenceInput =
        serde_json::from_str(r#"{"duration_secs":60}"#).expect("缺省字段必须可解析");
    assert_eq!(parsed.rule_id, None, "缺省 rule_id 表示全部规则");
    assert_eq!(parsed.agent_id, None, "缺省 agent_id 表示全部 agent");
    assert_eq!(parsed.duration_secs, 60);
    parsed.validate().expect("缺省通配的合法静默必须通过");

    let explicit_null: AlertSilenceInput =
        serde_json::from_str(r#"{"rule_id":null,"agent_id":null,"duration_secs":1}"#)
            .expect("显式 null 必须可解析");
    assert_eq!(explicit_null.rule_id, None);
    assert_eq!(explicit_null.agent_id, None);
    explicit_null.validate().expect("显式 null 通配必须合法");

    for duration in [MIN_SILENCE_DURATION_SECS, MAX_SILENCE_DURATION_SECS] {
        let input = AlertSilenceInput {
            rule_id: None,
            agent_id: None,
            duration_secs: duration,
        };
        input
            .validate()
            .unwrap_or_else(|err| panic!("duration_secs={duration} 必须是合法边界: {err}"));
        let converted = input.into_silence(now, "admin".to_string());
        assert_eq!(converted.id, 0, "落库前 id 必须为 0");
        assert_eq!(
            converted.until_ts,
            now + i64::try_from(duration).expect("duration 转 i64 失败") * 1_000,
            "until_ts 必须是 now + duration_secs*1000"
        );
        assert_eq!(converted.created_at, now);
        assert_eq!(converted.created_by, "admin");
        assert_eq!(converted.rule_id, None);
        assert_eq!(converted.agent_id, None);
    }

    for duration in [0, MAX_SILENCE_DURATION_SECS + 1] {
        let input = AlertSilenceInput {
            rule_id: None,
            agent_id: None,
            duration_secs: duration,
        };
        let err = input.validate().expect_err("duration 越界必须被拒绝");
        assert!(
            err.contains("duration_secs"),
            "错误信息必须点名 duration_secs，实际: {err}"
        );
    }

    let valid = AlertSilenceInput {
        rule_id: Some("builtin-disk-percent".to_string()),
        agent_id: Some("agent-01.prod_1".to_string()),
        duration_secs: 60,
    };
    valid.validate().expect("合法 rule_id/agent_id 必须通过");
    let max_rule = "r".repeat(64);
    let max_agent = "a".repeat(64);
    for (rule_id, agent_id) in [
        (max_rule.as_str(), max_agent.as_str()),
        ("a-b_c.1", "a-b_c.1"),
    ] {
        AlertSilenceInput {
            rule_id: Some(rule_id.to_string()),
            agent_id: Some(agent_id.to_string()),
            duration_secs: 1,
        }
        .validate()
        .unwrap_or_else(|err| panic!("合法静默目标 {rule_id}/{agent_id} 被拒绝: {err}"));
    }

    let long_rule = "r".repeat(65);
    for bad_rule in ["", "bad rule", "bad/rule", "规则", long_rule.as_str()] {
        let input = AlertSilenceInput {
            rule_id: Some(bad_rule.to_string()),
            agent_id: None,
            duration_secs: 60,
        };
        assert!(
            input.validate().is_err(),
            "非法 rule_id {bad_rule:?} 必须被拒绝"
        );
    }
    let long_agent = "a".repeat(65);
    for bad_agent in ["", "agent 01", "agent/01", "agent#01", long_agent.as_str()] {
        let input = AlertSilenceInput {
            rule_id: None,
            agent_id: Some(bad_agent.to_string()),
            duration_secs: 60,
        };
        assert!(
            input.validate().is_err(),
            "非法 agent_id {bad_agent:?} 必须被拒绝"
        );
    }

    // deny_unknown_fields 与字段类型：拼错 / 多传 / 缺必填一律解析失败。
    for body in [
        r#"{"duration_secs":60,"until_ts":1}"#,
        r#"{"duration_secs":60,"nope":true}"#,
        r#"{"rule_id":"rule-a"}"#,
        r#"{"duration_secs":-1}"#,
        r#"{"duration_secs":1.5}"#,
        r#"{"duration_secs":"60"}"#,
        r#"{"duration_secs":60,"rule_id":123}"#,
    ] {
        assert!(
            serde_json::from_str::<AlertSilenceInput>(body).is_err(),
            "非法静默请求体必须解析失败: {body}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. 事件先写、状态后写失败/重试：事件内容不被改变（at-least-once）
// ---------------------------------------------------------------------------

#[test]
fn alert_event_state_retry_is_at_least_once_and_events_stay_immutable() {
    let dir = TempDbDir::new("event-state-combo");
    let storage = open_storage(&dir);
    let now = 1_700_000_000_000_i64;
    let rule = rule_with_duration(0);
    let agent = "agent-01";
    let series = "series-key-combo";

    // 第一轮评估：状态机给出 firing，先把事件落库。
    let transition = next_alert_state(None, &rule, agent, series, 95.0, now);
    let firing_state = transition
        .state
        .clone()
        .expect("首次满足必须写入 firing 状态");
    assert_eq!(transition.event, Some(AlertStateKind::Firing));
    let event = new_alert_event(&rule, agent, AlertStateKind::Firing, 95.0, now, false);
    let first_event_id = storage
        .insert_alert_event(&event)
        .expect("插入第一轮事件失败");

    // 模拟“事件已落库、状态写失败 / 进程在状态写入前崩溃”：库里没有状态。
    assert_eq!(
        storage
            .get_alert_state(&rule.id, agent, series)
            .expect("读取状态失败"),
        None,
        "模拟状态写失败后不得出现状态行"
    );

    // 重试同一轮：再次产生 firing 事件并落库。公开语义允许 at-least-once 重复，
    // 但重复事件必须内容一致、id 不同，且不得改写第一条事件。
    let retry = next_alert_state(None, &rule, agent, series, 95.0, now);
    assert_eq!(
        retry.state.as_ref(),
        Some(&firing_state),
        "同一输入重试必须得到相同状态"
    );
    assert_eq!(retry.event, Some(AlertStateKind::Firing));
    let retry_event = new_alert_event(&rule, agent, AlertStateKind::Firing, 95.0, now, false);
    let second_event_id = storage
        .insert_alert_event(&retry_event)
        .expect("插入重试事件失败");
    assert_ne!(first_event_id, second_event_id, "重复事件必须是不同行");

    let duplicates = storage.list_alert_events(10, None).expect("列表失败");
    assert_eq!(duplicates.len(), 2, "at-least-once 允许两条重复事件");
    assert_eq!(duplicates[0].id, second_event_id, "列表最新在前");
    assert_eq!(duplicates[1].id, first_event_id);
    let mut newest = duplicates[0].clone();
    newest.id = 0;
    let mut oldest = duplicates[1].clone();
    oldest.id = 0;
    assert_eq!(
        newest, oldest,
        "重复事件除 id 外的内容必须完全一致，第一条事件不得被改写"
    );

    // 状态写入成功后重复 upsert（模拟重试）：事件列表必须逐字节保持不变。
    let mut changed_state = firing_state.clone();
    changed_state.last_eval_at = now + 15_000;
    changed_state.last_value = Some(96.0);
    storage
        .upsert_alert_state(&firing_state)
        .expect("写入状态失败");
    let events_before_state_retry = storage.list_alert_events(100, None).expect("列表失败");
    storage
        .upsert_alert_state(&firing_state)
        .expect("重复写入状态失败");
    storage
        .upsert_alert_state(&changed_state)
        .expect("更新状态失败");
    assert_eq!(
        storage.list_alert_events(100, None).expect("列表失败"),
        events_before_state_retry,
        "状态写入 / 重试 / 更新不得改变任何历史事件"
    );

    // 状态已存在且条件继续满足：状态机不得重复产生 firing 事件。
    let current_state = storage
        .get_alert_state(&rule.id, agent, series)
        .expect("读取状态失败")
        .expect("状态写入后必须存在");
    let steady = next_alert_state(
        Some(&current_state),
        &rule,
        agent,
        series,
        97.0,
        now + 15_000,
    );
    assert_eq!(steady.event, None, "firing 重复评估不得新增事件");
    let steady_state = steady.state.clone().expect("firing 必须保持状态");
    assert_eq!(steady_state.state, AlertStateKind::Firing);
    assert_eq!(steady_state.since, now, "firing 期间 since 必须保持");
    storage
        .upsert_alert_state(&steady_state)
        .expect("写入状态失败");
    assert_eq!(
        storage.list_alert_events(100, None).expect("列表失败"),
        events_before_state_retry,
        "firing 重复评估与状态写入不得新增或改写事件"
    );

    // 规则改名只影响后续新事件：历史事件保留产生时的 rule_name 快照。
    let mut renamed = rule.clone();
    renamed.name = "CPU 使用率过高（改名）".to_string();
    let recovered = next_alert_state(
        Some(&steady_state),
        &renamed,
        agent,
        series,
        10.0,
        now + 30_000,
    );
    assert_eq!(recovered.event, Some(AlertStateKind::Resolved));
    let resolved_event = new_alert_event(
        &renamed,
        agent,
        AlertStateKind::Resolved,
        10.0,
        now + 30_000,
        false,
    );
    let resolved_event_id = storage
        .insert_alert_event(&resolved_event)
        .expect("插入 resolved 事件失败");

    let all = storage.list_alert_events(100, None).expect("列表失败");
    assert_eq!(all.len(), 3, "resolved 事件必须新增一行");
    assert_eq!(all[0].id, resolved_event_id);
    assert_eq!(all[0].state, AlertStateKind::Resolved);
    assert_eq!(
        all[0].rule_name, "CPU 使用率过高（改名）",
        "新事件必须使用当前规则名"
    );
    assert_eq!(
        all[1], events_before_state_retry[0],
        "历史事件内容不得被改写"
    );
    assert_eq!(
        all[2], events_before_state_retry[1],
        "历史事件内容不得被改写"
    );
    assert_eq!(
        all[1].rule_name, rule.name,
        "历史事件必须保留产生时的 rule_name 快照"
    );
}
