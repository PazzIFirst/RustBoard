//! M4-B1a 告警规则独立集成测试。
//!
//! 依据：`docs/plans/2026-10-24-m4-alerting-archive.md` §6.1 / §8.1 / §8.2，
//! `crates/rustboard-core/src/alerts.rs` 的公开类型与函数文档，
//! `crates/rustboard-core/src/storage/sqlite.rs` 的公开 alert 方法文档。
//! 不参考内部实现；不修改生产代码。
//!
//! 数据库一律使用文件库（`std::env::temp_dir()` 下每个用例自建唯一目录），
//! 通过 `SqliteStorage::open` 打开；不借助内存库掩盖持久化问题。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rustboard_common::config::{HubAlertsConfig, HubConfig};
use rustboard_common::model::Labels;
use rustboard_core::alerts::{
    builtin_rules, dedupe_channel_ids, validate_channel_ids, validate_filter_labels,
    validate_metric, validate_rule_name, AlertRule, AlertRuleInput, AlertRuleStoreError,
    AlertSource, Comparator, BUILTIN_AGENT_CERT, BUILTIN_AGENT_OFFLINE, BUILTIN_BUFFER_BACKLOG,
    BUILTIN_DISK_PERCENT, BUILTIN_HUB_CERT, MAX_ALERT_RULES, MAX_CHANNEL_IDS, MAX_CHANNEL_ID_BYTES,
    MAX_COOLDOWN_SECS, MAX_DURATION_SECS, MAX_FILTER_LABELS, MAX_LABEL_KEY_BYTES,
    MAX_LABEL_VALUE_BYTES, MAX_METRIC_BYTES, MAX_RULE_NAME_BYTES,
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
            "rb-m4-b1a-alerts-{}-{tag}-{nanos}-{seq}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("创建临时目录失败");
        Self { root }
    }

    fn db_path(&self) -> PathBuf {
        self.root.join("rustboard.db")
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("hub.toml")
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

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

fn many_labels(count: usize) -> Labels {
    (0..count)
        .map(|index| (format!("key{index:02}"), format!("value{index:02}")))
        .collect()
}

/// 一条字段齐全、语义合法的自定义 metric 规则。
fn custom_rule(id: &str, name: &str) -> AlertRule {
    AlertRule {
        id: id.to_string(),
        name: name.to_string(),
        enabled: true,
        source: AlertSource::Metric,
        metric: "cpu.usage".to_string(),
        comparator: Comparator::Gte,
        threshold: 80.0,
        duration_secs: 60,
        cooldown_secs: 300,
        filter_agent_id: Some("agent-01".to_string()),
        filter_labels: labels(&[("env", "prod")]),
        channel_ids: vec!["chan-a".to_string(), "chan-b".to_string()],
        notify_on_resolve: true,
        is_builtin: false,
        updated_by: "admin".to_string(),
        created_at: 1_700_000_000_000,
        updated_at: 1_700_000_000_000,
    }
}

/// 从 `anyhow::Error` 中取出公开的领域错误；类型不符直接失败。
fn store_error(err: anyhow::Error) -> AlertRuleStoreError {
    match err.downcast_ref::<AlertRuleStoreError>() {
        Some(err) => *err,
        None => panic!("期望 AlertRuleStoreError，实际错误: {err:#}"),
    }
}

/// 写一份 hub.toml 并加载；`alerts` 为 `None` 表示完全缺 `[alerts]`。
fn load_hub_config(dir: &TempDbDir, alerts: Option<&str>) -> HubConfig {
    let data_dir = dir.root.join("data");
    let mut text = format!("data_dir = \"{}\"\n", data_dir.display());
    if let Some(fields) = alerts {
        text.push_str("\n[alerts]\n");
        text.push_str(fields);
        if !fields.ends_with('\n') {
            text.push('\n');
        }
    }
    let path = dir.config_path();
    fs::write(&path, text).expect("写入 hub.toml 失败");
    HubConfig::load(&path).expect("加载 hub.toml 失败")
}

// ---------------------------------------------------------------------------
// 1. AlertRuleInput 校验：名称、source/metric、枚举、threshold
// ---------------------------------------------------------------------------

#[test]
fn alert_rule_input_rejects_bad_name_source_metric_and_threshold() {
    // 合法边界：64 字节 ASCII 名称。
    let max_ascii_name = "a".repeat(MAX_RULE_NAME_BYTES);
    assert_eq!(max_ascii_name.len(), 64);
    let input = AlertRuleInput {
        name: Some(max_ascii_name.clone()),
        ..AlertRuleInput::default()
    };
    input.validate().expect("64 字节名称必须合法");

    // 合法边界：中文名称（内置规则本身就是中文名；按字节与字符双上限判断）。
    let chinese_name = "磁盘告警".repeat(5);
    assert_eq!(chinese_name.chars().count(), 20);
    assert_eq!(chinese_name.len(), 60);
    AlertRuleInput {
        name: Some(chinese_name.clone()),
        ..AlertRuleInput::default()
    }
    .validate()
    .expect("60 字节 / 20 字符的中文名称必须合法");

    // 非法：空、65 字节、65 字符（多字节）、首尾空白、控制字符。
    for bad_name in [
        String::new(),
        "a".repeat(MAX_RULE_NAME_BYTES + 1),
        "磁".repeat(65), // 195 字节且 65 字符
        " 前后有空格".to_string(),
        "前后有空格 ".to_string(),
        "含\u{7}控制符".to_string(),
        "含\n换行".to_string(),
        "含\t制表符".to_string(),
    ] {
        let result = AlertRuleInput {
            name: Some(bad_name.clone()),
            ..AlertRuleInput::default()
        }
        .validate();
        assert!(result.is_err(), "非法名称 {bad_name:?} 必须被拒绝");
    }

    // 安全：错误信息不回显用户输入原文。
    let long_name = "超长规则名称".repeat(20);
    let err = validate_rule_name(&long_name).expect_err("超长名称必须被拒绝");
    assert!(!err.contains(&long_name), "错误信息不得回显用户输入: {err}");

    // metric 规则缺 metric：输入层只校验出现的字段；合并后的最终规则必须被拒绝。
    let missing_metric_input = AlertRuleInput {
        source: Some(AlertSource::Metric),
        ..AlertRuleInput::default()
    };
    missing_metric_input
        .validate()
        .expect("AlertRuleInput::validate 只校验请求里出现的字段");
    let mut merged = custom_rule("semantic-missing-metric", "待校验规则");
    merged.metric = String::new();
    missing_metric_input.apply_to(&mut merged);
    assert!(
        merged.validate_semantics().is_err(),
        "metric 规则合并后仍缺 metric，必须被 validate_semantics 拒绝"
    );

    // metric 规则显式传空 metric：输入层直接拒绝。
    let empty_metric_input = AlertRuleInput {
        source: Some(AlertSource::Metric),
        metric: Some(String::new()),
        ..AlertRuleInput::default()
    };
    assert!(
        empty_metric_input.validate().is_err(),
        "metric 规则显式空 metric 必须被拒绝"
    );

    // 非 metric 规则不得携带 metric。
    for source in [AlertSource::AgentOffline, AlertSource::HubCert] {
        let input = AlertRuleInput {
            source: Some(source),
            metric: Some("cpu.usage".to_string()),
            ..AlertRuleInput::default()
        };
        assert!(
            input.validate().is_err(),
            "{source:?} 规则携带 metric 必须被拒绝"
        );
    }

    // 非 metric 规则清空 metric 合法，且 apply_to 会把旧 metric 清掉。
    let mut switched = custom_rule("switch-source", "切换来源");
    switched.metric = "cpu.usage".to_string();
    AlertRuleInput {
        source: Some(AlertSource::AgentOffline),
        ..AlertRuleInput::default()
    }
    .apply_to(&mut switched);
    assert_eq!(switched.metric, "", "切到非 metric 来源必须自动清空 metric");
    assert_eq!(switched.source, AlertSource::AgentOffline);

    // metric 名只允许 [a-z0-9_.-] 且 1–64 字节。
    for good in [
        "cpu.usage",
        "disk.used_percent",
        "buffer.pending_ratio",
        "a-b_c.1",
    ] {
        validate_metric(good).unwrap_or_else(|err| panic!("合法 metric {good} 被拒绝: {err}"));
    }
    let max_metric = "a".repeat(MAX_METRIC_BYTES);
    validate_metric(&max_metric).expect("64 字节 metric 必须是合法边界");
    for bad in [
        String::new(),
        "CPU.usage".to_string(),
        "cpu usage".to_string(),
        "cpu/usage".to_string(),
        "磁盘.使用率".to_string(),
        "a".repeat(MAX_METRIC_BYTES + 1),
    ] {
        assert!(
            validate_metric(&bad).is_err(),
            "非法 metric {bad:?} 必须被拒绝"
        );
    }

    // threshold 必须是有限数：NaN / ±Inf 拒绝；普通负数是合法阈值。
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let input = AlertRuleInput {
            threshold: Some(bad),
            ..AlertRuleInput::default()
        };
        assert!(input.validate().is_err(), "threshold {bad} 必须被拒绝");

        let mut rule = custom_rule("threshold", "阈值规则");
        rule.threshold = bad;
        assert!(
            rule.validate_semantics().is_err(),
            "最终规则 threshold {bad} 必须被拒绝"
        );
    }
    AlertRuleInput {
        threshold: Some(-1.5),
        ..AlertRuleInput::default()
    }
    .validate()
    .expect("负的有限阈值按契约是合法输入");

    // duration / cooldown 边界：0 与上限合法，上限 +1 拒绝。
    AlertRuleInput {
        duration_secs: Some(0),
        cooldown_secs: Some(0),
        ..AlertRuleInput::default()
    }
    .validate()
    .expect("duration/cooldown 为 0 必须合法");
    AlertRuleInput {
        duration_secs: Some(MAX_DURATION_SECS),
        cooldown_secs: Some(MAX_COOLDOWN_SECS),
        ..AlertRuleInput::default()
    }
    .validate()
    .expect("duration/cooldown 上限必须合法");
    assert!(AlertRuleInput {
        duration_secs: Some(MAX_DURATION_SECS + 1),
        ..AlertRuleInput::default()
    }
    .validate()
    .is_err());
    assert!(AlertRuleInput {
        cooldown_secs: Some(MAX_COOLDOWN_SECS + 1),
        ..AlertRuleInput::default()
    }
    .validate()
    .is_err());

    // 枚举稳定字符串：合法值双向一致，未知值不静默降级。
    for (source, raw) in [
        (AlertSource::Metric, "metric"),
        (AlertSource::AgentOffline, "agent_offline"),
        (AlertSource::HubCert, "hub_cert"),
    ] {
        assert_eq!(source.as_str(), raw);
        assert_eq!(AlertSource::parse(raw), Some(source));
    }
    for (comparator, raw) in [
        (Comparator::Gt, "gt"),
        (Comparator::Gte, "gte"),
        (Comparator::Lt, "lt"),
        (Comparator::Lte, "lte"),
        (Comparator::Eq, "eq"),
        (Comparator::Ne, "ne"),
    ] {
        assert_eq!(comparator.as_str(), raw);
        assert_eq!(Comparator::parse(raw), Some(comparator));
    }
    assert_eq!(AlertSource::parse("Metric"), None);
    assert_eq!(AlertSource::parse("unknown"), None);
    assert_eq!(Comparator::parse("GT"), None);
    assert_eq!(Comparator::parse("unknown"), None);

    // JSON 枚举字符串非法必须解析失败，未知字段也必须失败（deny_unknown_fields）。
    for body in [
        r#"{"source":"unknown"}"#,
        r#"{"source":"Metric"}"#,
        r#"{"comparator":"GT"}"#,
        r#"{"comparator":"unknown"}"#,
        r#"{"nope":1}"#,
    ] {
        assert!(
            serde_json::from_str::<AlertRuleInput>(body).is_err(),
            "非法请求体 {body} 必须解析失败"
        );
    }
    let parsed: AlertRuleInput =
        serde_json::from_str(r#"{"source":"agent_offline","comparator":"ne"}"#)
            .expect("合法枚举字符串必须可解析");
    assert_eq!(parsed.source, Some(AlertSource::AgentOffline));
    assert_eq!(parsed.comparator, Some(Comparator::Ne));
}

// ---------------------------------------------------------------------------
// 2. AlertRuleInput 校验：labels、channel_ids、filter_agent_id
// ---------------------------------------------------------------------------

#[test]
fn alert_rule_input_enforces_label_channel_and_filter_limits() {
    // labels：16 对合法；17 对拒绝。
    let labels_16 = many_labels(MAX_FILTER_LABELS);
    assert_eq!(labels_16.len(), 16);
    validate_filter_labels(&labels_16).expect("16 对 labels 必须合法");
    AlertRuleInput {
        filter_labels: Some(labels_16.clone()),
        ..AlertRuleInput::default()
    }
    .validate()
    .expect("16 对 labels 的输入必须合法");

    let labels_17 = many_labels(MAX_FILTER_LABELS + 1);
    assert!(
        validate_filter_labels(&labels_17).is_err(),
        "17 对 labels 必须被拒绝"
    );
    assert!(AlertRuleInput {
        filter_labels: Some(labels_17),
        ..AlertRuleInput::default()
    }
    .validate()
    .is_err());

    // labels 键：1–64 字节且不含空白/控制字符；值 ≤256 字节且无控制字符。
    assert!(
        validate_filter_labels(&Labels::new()).is_ok(),
        "空 labels 合法"
    );
    assert!(validate_filter_labels(&labels(&[("", "v")])).is_err());
    assert!(validate_filter_labels(&labels(&[("bad key", "v")])).is_err());
    let max_key = "k".repeat(MAX_LABEL_KEY_BYTES);
    assert!(
        validate_filter_labels(&labels(&[(&max_key, "v")])).is_ok(),
        "64 字节 label 键必须是合法边界"
    );
    assert!(validate_filter_labels(&labels(&[("含\n键", "v")])).is_err());

    let long_key = "k".repeat(MAX_LABEL_KEY_BYTES + 1);
    assert!(validate_filter_labels(&labels(&[(&long_key, "v")])).is_err());
    let max_value = "v".repeat(MAX_LABEL_VALUE_BYTES);
    assert!(
        validate_filter_labels(&labels(&[("k", &max_value)])).is_ok(),
        "256 字节 label 值必须是合法边界"
    );
    let long_value = "v".repeat(MAX_LABEL_VALUE_BYTES + 1);
    assert!(validate_filter_labels(&labels(&[("k", &long_value)])).is_err());
    assert!(validate_filter_labels(&labels(&[("k", "含\n值")])).is_err());

    // filter_agent_id：1–64 字节 [A-Za-z0-9_.-]；空串表示清空，是合法输入。
    assert!(AlertRuleInput {
        filter_agent_id: Some(Some("agent-01.prod_1".to_string())),
        ..AlertRuleInput::default()
    }
    .validate()
    .is_ok());
    let max_agent_id = "a".repeat(64);
    assert!(AlertRuleInput {
        filter_agent_id: Some(Some(max_agent_id.clone())),
        ..AlertRuleInput::default()
    }
    .validate()
    .is_ok());
    for bad in [
        "a".repeat(65),
        "agent 01".to_string(),
        "agent/01".to_string(),
        "agent#01".to_string(),
    ] {
        assert!(AlertRuleInput {
            filter_agent_id: Some(Some(bad.clone())),
            ..AlertRuleInput::default()
        }
        .validate()
        .is_err());
    }
    AlertRuleInput {
        filter_agent_id: Some(Some(String::new())),
        ..AlertRuleInput::default()
    }
    .validate()
    .expect("空串 filter_agent_id 表示清空，必须合法");
    AlertRuleInput {
        filter_agent_id: Some(None),
        ..AlertRuleInput::default()
    }
    .validate()
    .expect("显式 null filter_agent_id 表示清空，必须合法");

    // 三态：缺省保留、null/空串清空。
    let mut rule = custom_rule("filter-agent", "过滤 agent");
    let clear: AlertRuleInput =
        serde_json::from_str(r#"{"filter_agent_id":null}"#).expect("null 必须可解析");
    assert_eq!(clear.filter_agent_id, Some(None));
    clear.apply_to(&mut rule);
    assert_eq!(rule.filter_agent_id, None, "显式 null 必须清空过滤");
    rule.filter_agent_id = Some("agent-02".to_string());
    AlertRuleInput {
        filter_agent_id: Some(Some(String::new())),
        ..AlertRuleInput::default()
    }
    .apply_to(&mut rule);
    assert_eq!(rule.filter_agent_id, None, "空串必须清空过滤");

    // channel_ids：16 个唯一 id 合法；17 个唯一 id 拒绝。
    let unique_16: Vec<String> = (0..MAX_CHANNEL_IDS)
        .map(|index| format!("chan-{index:02}"))
        .collect();
    validate_channel_ids(&unique_16).expect("16 个渠道 id 必须合法");
    AlertRuleInput {
        channel_ids: Some(unique_16),
        ..AlertRuleInput::default()
    }
    .validate()
    .expect("16 个渠道 id 的输入必须合法");

    let unique_17: Vec<String> = (0..=MAX_CHANNEL_IDS)
        .map(|index| format!("chan-{index:02}"))
        .collect();
    assert!(
        validate_channel_ids(&unique_17).is_err(),
        "17 个唯一渠道 id 必须被拒绝"
    );
    assert!(AlertRuleInput {
        channel_ids: Some(unique_17),
        ..AlertRuleInput::default()
    }
    .validate()
    .is_err());

    // 公开文档：重复 id 保留首次出现顺序去重；去重后不超限即合法。
    let repeated = vec!["chan-1".to_string(); MAX_CHANNEL_IDS + 1];
    assert_eq!(
        dedupe_channel_ids(&repeated),
        vec!["chan-1".to_string()],
        "重复渠道 id 必须去重"
    );
    validate_channel_ids(&repeated).expect("重复 id 去重后只有 1 个，必须合法");
    let mut deduped_rule = custom_rule("dedupe", "渠道去重");
    AlertRuleInput {
        channel_ids: Some(vec![
            "chan-b".to_string(),
            "chan-a".to_string(),
            "chan-b".to_string(),
            "chan-c".to_string(),
        ]),
        ..AlertRuleInput::default()
    }
    .apply_to(&mut deduped_rule);
    assert_eq!(
        deduped_rule.channel_ids,
        vec![
            "chan-b".to_string(),
            "chan-a".to_string(),
            "chan-c".to_string()
        ],
        "去重必须保留首次出现顺序"
    );

    // 渠道 id 格式：1–64 字节 [A-Za-z0-9_.-]。
    let max_channel_id = "c".repeat(MAX_CHANNEL_ID_BYTES);
    validate_channel_ids(&[max_channel_id]).expect("64 字节渠道 id 必须是合法边界");
    for bad in [
        String::new(),
        "has space".to_string(),
        "a/b".to_string(),
        "含中文".to_string(),
        "c".repeat(MAX_CHANNEL_ID_BYTES + 1),
    ] {
        assert!(
            validate_channel_ids(std::slice::from_ref(&bad)).is_err(),
            "非法渠道 id {bad:?} 必须被拒绝"
        );
    }

    // 合法完整输入（含中文名/labels）整体通过。
    let valid = AlertRuleInput {
        name: Some("生产磁盘告警".to_string()),
        enabled: Some(true),
        source: Some(AlertSource::Metric),
        metric: Some("disk.used_percent".to_string()),
        comparator: Some(Comparator::Gt),
        threshold: Some(90.0),
        duration_secs: Some(300),
        cooldown_secs: Some(1_800),
        filter_agent_id: Some(Some(max_agent_id)),
        filter_labels: Some(labels(&[("env", "生产"), ("role", "db")])),
        channel_ids: Some(vec!["chan-a".to_string(), "chan-b".to_string()]),
        notify_on_resolve: Some(true),
    };
    valid.validate().expect("合法完整输入必须通过");
    let mut rule = custom_rule("valid", "生产磁盘告警");
    valid.apply_to(&mut rule);
    rule.validate_semantics()
        .expect("合法输入合并后的规则必须语义自洽");
}

// ---------------------------------------------------------------------------
// 3. 内置规则
// ---------------------------------------------------------------------------

#[test]
fn builtin_rules_are_five_fixed_disabled_and_channel_free() {
    let now = 1_700_000_000_123_i64;
    let alerts = HubAlertsConfig::default();
    let rules = builtin_rules(now, alerts.offline_after_secs, alerts.cert_warn_hours);
    assert_eq!(rules.len(), 5, "内置规则必须固定 5 条");

    let expected_ids: BTreeSet<&str> = BTreeSet::from([
        BUILTIN_AGENT_OFFLINE,
        BUILTIN_DISK_PERCENT,
        BUILTIN_AGENT_CERT,
        BUILTIN_HUB_CERT,
        BUILTIN_BUFFER_BACKLOG,
    ]);
    let actual_ids: BTreeSet<&str> = rules.iter().map(|rule| rule.id.as_str()).collect();
    assert_eq!(actual_ids, expected_ids, "内置规则 id 必须固定且唯一");

    let names: BTreeSet<&str> = rules.iter().map(|rule| rule.name.as_str()).collect();
    assert_eq!(names.len(), 5, "内置规则名称必须唯一");
    assert!(names.iter().all(|name| !name.is_empty()));

    for rule in &rules {
        assert!(!rule.enabled, "内置规则初始必须 disabled: {}", rule.id);
        assert!(rule.is_builtin, "内置规则必须标记 is_builtin: {}", rule.id);
        assert!(
            rule.channel_ids.is_empty(),
            "内置规则初始不得绑定渠道: {}",
            rule.id
        );
        assert!(
            rule.filter_agent_id.is_none(),
            "内置规则不得默认过滤 agent: {}",
            rule.id
        );
        assert!(
            rule.filter_labels.is_empty(),
            "内置规则不得默认过滤 labels: {}",
            rule.id
        );
        assert!(rule.notify_on_resolve, "内置规则默认发送恢复通知");
        assert_eq!(rule.created_at, now, "created_at 必须使用传入时间");
        assert_eq!(rule.updated_at, now, "updated_at 必须使用传入时间");
        rule.validate_semantics()
            .unwrap_or_else(|err| panic!("内置规则 {} 语义非法: {err}", rule.id));
    }

    let by_id: BTreeMap<&str, &AlertRule> =
        rules.iter().map(|rule| (rule.id.as_str(), rule)).collect();

    // 来源与 metric 必须与方案 §6.1 的新指标/内置规则一一对应。
    let offline = by_id[BUILTIN_AGENT_OFFLINE];
    assert_eq!(offline.source, AlertSource::AgentOffline);
    assert_eq!(offline.metric, "");
    assert_eq!(
        offline.threshold, 90.0,
        "离线阈值默认取 alerts.offline_after_secs = 90 秒"
    );

    let disk = by_id[BUILTIN_DISK_PERCENT];
    assert_eq!(disk.source, AlertSource::Metric);
    assert_eq!(disk.metric, "disk.used_percent");

    let agent_cert = by_id[BUILTIN_AGENT_CERT];
    assert_eq!(agent_cert.source, AlertSource::Metric);
    assert_eq!(
        agent_cert.metric, "cert.hours_left",
        "证书阈值单位是小时，不能再使用 days_left"
    );
    assert_eq!(
        agent_cert.threshold, 48.0,
        "证书阈值默认取 alerts.cert_warn_hours = 48 小时"
    );

    let hub_cert = by_id[BUILTIN_HUB_CERT];
    assert_eq!(hub_cert.source, AlertSource::HubCert);
    assert_eq!(hub_cert.metric, "");
    assert_eq!(hub_cert.threshold, 48.0, "hub 证书阈值同样是 48 小时");

    let buffer = by_id[BUILTIN_BUFFER_BACKLOG];
    assert_eq!(buffer.source, AlertSource::Metric);
    assert_eq!(buffer.metric, "buffer.pending_ratio");
}

/// 内置离线 / 证书阈值必须来自 `HubAlertsConfig`，且证书规则用小时指标。
///
/// 回归：旧实现把 48 小时当成 48 天（`cert.days_left` + 阈值 48）。
#[test]
fn builtin_rules_thresholds_track_config() {
    let now = 1_700_000_000_456_i64;
    let alerts = HubAlertsConfig {
        offline_after_secs: 30,
        cert_warn_hours: 72,
        ..HubAlertsConfig::default()
    };
    let rules = builtin_rules(now, alerts.offline_after_secs, alerts.cert_warn_hours);
    let by_id: BTreeMap<&str, &AlertRule> =
        rules.iter().map(|rule| (rule.id.as_str(), rule)).collect();

    assert_eq!(
        by_id[BUILTIN_AGENT_OFFLINE].threshold,
        f64::from(30_u32),
        "离线阈值必须取 offline_after_secs"
    );
    assert_eq!(
        by_id[BUILTIN_AGENT_CERT].metric, "cert.hours_left",
        "agent 证书规则必须使用小时指标"
    );
    assert_eq!(
        by_id[BUILTIN_AGENT_CERT].threshold,
        f64::from(72_u32),
        "agent 证书阈值必须取 cert_warn_hours（小时）"
    );
    assert_eq!(
        by_id[BUILTIN_HUB_CERT].threshold,
        f64::from(72_u32),
        "hub 证书阈值必须取 cert_warn_hours（小时）"
    );
    // 非证书规则不受影响。
    assert_eq!(by_id[BUILTIN_DISK_PERCENT].threshold, 90.0);
    assert_eq!(by_id[BUILTIN_BUFFER_BACKLOG].threshold, 0.8);
}

#[test]
fn seed_builtin_alert_rules_is_idempotent_and_preserves_user_edits() {
    let dir = TempDbDir::new("seed");
    let storage = open_storage(&dir);
    let now = 1_700_000_000_000_i64;

    assert_eq!(
        storage
            .seed_builtin_alert_rules(&builtin_rules(now, 90, 48), now)
            .expect("首次种子失败"),
        5,
        "首次种子必须插入 5 条"
    );
    assert_eq!(storage.alert_rule_count().expect("统计失败"), 5);
    let first: Vec<AlertRule> = storage.list_alert_rules().expect("列表失败");
    assert_eq!(first.len(), 5);

    assert_eq!(
        storage
            .seed_builtin_alert_rules(&builtin_rules(now + 60_000, 90, 48), now + 60_000)
            .expect("重复种子失败"),
        0,
        "再次种子必须插入 0 条"
    );
    assert_eq!(storage.alert_rule_count().expect("统计失败"), 5);
    assert_eq!(
        storage.list_alert_rules().expect("列表失败"),
        first,
        "重复种子不得刷新任何字段（含时间戳）"
    );

    // 用户修改 enabled / threshold 后再次种子，改动必须保留。
    let mut edited = storage
        .get_alert_rule(BUILTIN_DISK_PERCENT)
        .expect("读取失败")
        .expect("内置规则必须存在");
    let seeded_created_at = edited.created_at;
    edited.enabled = true;
    edited.threshold = 97.5;
    edited.duration_secs = 42;
    edited.updated_by = "ops".to_string();
    edited.updated_at = now + 120_000;
    storage
        .update_alert_rule(&edited)
        .expect("更新内置规则失败");

    assert_eq!(
        storage
            .seed_builtin_alert_rules(&builtin_rules(now + 240_000, 90, 48), now + 240_000)
            .expect("用户改动后再种子失败"),
        0,
        "已存在时种子必须插入 0 条"
    );
    let after = storage
        .get_alert_rule(BUILTIN_DISK_PERCENT)
        .expect("读取失败")
        .expect("内置规则必须存在");
    assert_eq!(after, edited, "种子绝不能覆盖用户改过的 enabled/threshold");
    assert_eq!(
        after.created_at, seeded_created_at,
        "created_at 不得被种子重置"
    );
    assert_eq!(after.updated_at, now + 120_000, "updated_at 不得被种子重置");
    assert_eq!(storage.alert_rule_count().expect("统计失败"), 5);
}

// ---------------------------------------------------------------------------
// 4. CRUD 与领域错误
// ---------------------------------------------------------------------------

#[test]
fn alert_rule_crud_roundtrip_and_domain_errors() {
    let dir = TempDbDir::new("crud");
    let storage = open_storage(&dir);

    // 不存在的规则：get 返回 None；update / delete 返回 NotFound。
    assert_eq!(
        storage.get_alert_rule("missing").expect("读取失败"),
        None,
        "不存在的规则读取必须返回 None"
    );
    let missing = custom_rule("missing", "不存在的规则");
    assert_eq!(
        store_error(
            storage
                .update_alert_rule(&missing)
                .expect_err("更新不存在规则必须失败")
        ),
        AlertRuleStoreError::NotFound
    );
    assert_eq!(
        store_error(
            storage
                .delete_alert_rule("missing")
                .expect_err("删除不存在规则必须失败")
        ),
        AlertRuleStoreError::NotFound
    );

    // 创建 + 读取：labels / channel_ids / filter_agent_id 完整往返。
    let rule = custom_rule("custom-1", "生产 CPU 告警");
    storage.create_alert_rule(&rule).expect("创建规则失败");
    assert_eq!(
        storage.get_alert_rule("custom-1").expect("读取失败"),
        Some(rule.clone()),
        "读取结果必须与创建时逐字段一致（含 labels/channel_ids/filter_agent_id）"
    );
    assert_eq!(storage.alert_rule_count().expect("统计失败"), 1);
    assert_eq!(
        storage.list_alert_rules().expect("列表失败"),
        vec![rule.clone()]
    );

    // 重名：不同 id 使用已有 name → NameExists，且不写入。
    let duplicate = custom_rule("custom-2", &rule.name);
    assert_eq!(
        store_error(
            storage
                .create_alert_rule(&duplicate)
                .expect_err("重名创建必须失败")
        ),
        AlertRuleStoreError::NameExists
    );
    assert_eq!(
        storage.get_alert_rule("custom-2").expect("读取失败"),
        None,
        "失败的重名创建不得写入"
    );
    assert_eq!(storage.alert_rule_count().expect("统计失败"), 1);

    // 更新：改名、关闭、改阈值/过滤/渠道；存储层必须忽略 is_builtin/created_at 改动。
    let mut updated = rule.clone();
    updated.name = "生产 CPU 告警（更新）".to_string();
    updated.enabled = false;
    updated.threshold = 95.5;
    updated.duration_secs = 120;
    updated.filter_agent_id = None;
    updated.filter_labels = labels(&[("env", "staging"), ("role", "db")]);
    updated.channel_ids = vec!["chan-z".to_string()];
    updated.notify_on_resolve = false;
    updated.updated_by = "ops".to_string();
    updated.updated_at = 1_700_000_100_000;
    updated.is_builtin = true; // 上层伪造，存储层应保留数据库原值 false
    updated.created_at = 999; // 上层伪造，存储层应保留数据库原值
    storage.update_alert_rule(&updated).expect("更新规则失败");

    let fetched = storage
        .get_alert_rule("custom-1")
        .expect("读取失败")
        .expect("更新后规则必须存在");
    assert_eq!(fetched.name, "生产 CPU 告警（更新）");
    assert!(!fetched.enabled);
    assert_eq!(fetched.threshold, 95.5);
    assert_eq!(fetched.duration_secs, 120);
    assert_eq!(fetched.filter_agent_id, None, "filter_agent_id 必须可清空");
    assert_eq!(
        fetched.filter_labels,
        labels(&[("env", "staging"), ("role", "db")]),
        "labels 必须往返"
    );
    assert_eq!(fetched.channel_ids, vec!["chan-z".to_string()]);
    assert!(!fetched.notify_on_resolve);
    assert_eq!(fetched.updated_by, "ops");
    assert_eq!(fetched.updated_at, 1_700_000_100_000);
    assert!(!fetched.is_builtin, "存储层必须保留数据库中的 is_builtin");
    assert_eq!(
        fetched.created_at, rule.created_at,
        "存储层必须保留数据库中的 created_at"
    );

    // 更新到与其它规则重名 → NameExists。
    let other = custom_rule("custom-3", "另一条规则");
    storage
        .create_alert_rule(&other)
        .expect("创建另一条规则失败");
    let mut conflicting = other.clone();
    conflicting.name = fetched.name.clone();
    assert_eq!(
        store_error(
            storage
                .update_alert_rule(&conflicting)
                .expect_err("更新为重名必须失败")
        ),
        AlertRuleStoreError::NameExists
    );

    // 内置规则：可更新（启停/阈值），但禁止删除。
    storage
        .seed_builtin_alert_rules(&builtin_rules(1_700_000_200_000, 90, 48), 1_700_000_200_000)
        .expect("种子内置规则失败");
    assert_eq!(
        store_error(
            storage
                .delete_alert_rule(BUILTIN_AGENT_OFFLINE)
                .expect_err("删除内置规则必须失败")
        ),
        AlertRuleStoreError::BuiltinRule
    );
    let still_there = storage
        .get_alert_rule(BUILTIN_AGENT_OFFLINE)
        .expect("读取失败")
        .expect("内置规则不得被删除");
    assert!(still_there.is_builtin);

    let mut enable_builtin = still_there.clone();
    enable_builtin.enabled = true;
    storage
        .update_alert_rule(&enable_builtin)
        .expect("内置规则必须允许启停/改阈值");
    assert!(
        storage
            .get_alert_rule(BUILTIN_AGENT_OFFLINE)
            .expect("读取失败")
            .expect("内置规则必须存在")
            .enabled
    );

    // 删除自定义规则：成功且之后读不到。
    storage
        .delete_alert_rule("custom-1")
        .expect("删除自定义规则失败");
    assert_eq!(storage.get_alert_rule("custom-1").expect("读取失败"), None);
    // 剩余：5 条内置 + custom-3。
    assert_eq!(storage.alert_rule_count().expect("统计失败"), 6);
}

// ---------------------------------------------------------------------------
// 5. 规则数量上限
// ---------------------------------------------------------------------------

#[test]
fn alert_rule_limit_is_enforced_without_writing() {
    assert_eq!(MAX_ALERT_RULES, 200, "方案 §6.2 规定规则总数上限为 200");

    let dir = TempDbDir::new("limit");
    let storage = open_storage(&dir);
    let now = 1_700_000_000_000_i64;

    assert_eq!(
        storage
            .seed_builtin_alert_rules(&builtin_rules(now, 90, 48), now)
            .expect("种子内置规则失败"),
        5
    );

    // 预置到 200 条（含 5 条内置）。
    let custom_total = MAX_ALERT_RULES - 5;
    for index in 0..custom_total {
        let rule = custom_rule(
            &format!("limit-{index:03}"),
            &format!("上限规则 {index:03}"),
        );
        storage
            .create_alert_rule(&rule)
            .unwrap_or_else(|err| panic!("创建第 {} 条规则失败: {err:#}", index + 6));
    }
    assert_eq!(
        storage.alert_rule_count().expect("统计失败"),
        MAX_ALERT_RULES,
        "含内置规则总数必须恰好为 200"
    );

    // 第 201 条必须返回 LimitReached。
    let overflow = custom_rule("limit-200", "第 201 条规则");
    assert_eq!(
        store_error(
            storage
                .create_alert_rule(&overflow)
                .expect_err("第 201 条规则必须失败")
        ),
        AlertRuleStoreError::LimitReached
    );

    // 失败不得写入：总数、单条读取、列表都不含这条规则。
    assert_eq!(
        storage.alert_rule_count().expect("统计失败"),
        MAX_ALERT_RULES,
        "超限失败后总数不得变化"
    );
    assert_eq!(
        storage.get_alert_rule("limit-200").expect("读取失败"),
        None,
        "超限失败不得写入规则"
    );
    let listed = storage.list_alert_rules().expect("列表失败");
    assert_eq!(listed.len(), MAX_ALERT_RULES);
    assert!(
        listed.iter().all(|rule| rule.id != "limit-200"),
        "超限失败后列表中不得出现该规则"
    );
}

// ---------------------------------------------------------------------------
// 6. HubConfig [alerts] 默认值与边界
// ---------------------------------------------------------------------------

#[test]
fn hub_alerts_config_defaults_and_bounds() {
    let dir = TempDbDir::new("config");

    // 旧配置完全没有 `[alerts]`：使用默认值且整体校验通过。
    let hub = load_hub_config(&dir, None);
    assert_eq!(
        hub.alerts,
        HubAlertsConfig::default(),
        "缺 [alerts] 必须使用默认值"
    );
    assert!(hub.alerts.enabled);
    assert_eq!(hub.alerts.evaluation_interval_secs, 15);
    assert_eq!(hub.alerts.offline_after_secs, 90);
    assert_eq!(hub.alerts.cert_warn_hours, 48);
    assert_eq!(hub.alerts.event_retention_days, 90);
    assert_eq!(hub.alerts.max_events, 100_000);
    assert_eq!(hub.alerts.notify_timeout_secs, 10);
    assert_eq!(hub.alerts.notify_max_attempts, 3);
    hub.validate().expect("旧配置缺 [alerts] 必须整体合法");

    // 只写部分字段：未写字段保持默认。
    let hub = load_hub_config(&dir, Some("enabled = false\n"));
    assert!(!hub.alerts.enabled);
    assert_eq!(hub.alerts.evaluation_interval_secs, 15);
    hub.validate().expect("关闭告警时默认值仍必须合法");

    // 全部字段取下限边界。
    let lower = "evaluation_interval_secs = 1\n\
                 offline_after_secs = 1\n\
                 cert_warn_hours = 1\n\
                 event_retention_days = 1\n\
                 max_events = 1000\n\
                 notify_timeout_secs = 1\n\
                 notify_max_attempts = 1\n";
    let hub = load_hub_config(&dir, Some(lower));
    assert_eq!(hub.alerts.evaluation_interval_secs, 1);
    assert_eq!(hub.alerts.offline_after_secs, 1);
    assert_eq!(hub.alerts.cert_warn_hours, 1);
    assert_eq!(hub.alerts.event_retention_days, 1);
    assert_eq!(hub.alerts.max_events, 1_000);
    assert_eq!(hub.alerts.notify_timeout_secs, 1);
    assert_eq!(hub.alerts.notify_max_attempts, 1);
    hub.validate().expect("所有下限边界必须合法");

    // 全部字段取上限边界。
    let upper = "evaluation_interval_secs = 3600\n\
                 offline_after_secs = 3600\n\
                 cert_warn_hours = 720\n\
                 event_retention_days = 3650\n\
                 max_events = 1000000\n\
                 notify_timeout_secs = 60\n\
                 notify_max_attempts = 10\n";
    let hub = load_hub_config(&dir, Some(upper));
    assert_eq!(hub.alerts.evaluation_interval_secs, 3_600);
    assert_eq!(hub.alerts.offline_after_secs, 3_600);
    assert_eq!(hub.alerts.cert_warn_hours, 720);
    assert_eq!(hub.alerts.event_retention_days, 3_650);
    assert_eq!(hub.alerts.max_events, 1_000_000);
    assert_eq!(hub.alerts.notify_timeout_secs, 60);
    assert_eq!(hub.alerts.notify_max_attempts, 10);
    hub.validate().expect("所有上限边界必须合法");

    // 每个字段 0 / 上限 +1 都必须拒绝，且错误信息点名 alerts.<字段>。
    for (line, field) in [
        ("evaluation_interval_secs = 0", "evaluation_interval_secs"),
        (
            "evaluation_interval_secs = 3601",
            "evaluation_interval_secs",
        ),
        ("offline_after_secs = 0", "offline_after_secs"),
        ("offline_after_secs = 3601", "offline_after_secs"),
        ("cert_warn_hours = 0", "cert_warn_hours"),
        ("cert_warn_hours = 721", "cert_warn_hours"),
        ("event_retention_days = 0", "event_retention_days"),
        ("event_retention_days = 3651", "event_retention_days"),
        ("max_events = 0", "max_events"),
        ("max_events = 1000001", "max_events"),
        ("notify_timeout_secs = 0", "notify_timeout_secs"),
        ("notify_timeout_secs = 61", "notify_timeout_secs"),
        ("notify_max_attempts = 0", "notify_max_attempts"),
        ("notify_max_attempts = 11", "notify_max_attempts"),
    ] {
        let hub = load_hub_config(&dir, Some(line));
        let err = hub
            .validate()
            .expect_err("越界告警配置必须被拒绝")
            .to_string();
        assert!(
            err.contains(&format!("alerts.{field}")),
            "错误信息必须点名 alerts.{field}，实际: {err}"
        );
    }

    // 即使 enabled=false，取值范围错误也必须在启动时暴露，不能静默推迟。
    let hub = load_hub_config(
        &dir,
        Some("enabled = false\nevaluation_interval_secs = 0\n"),
    );
    let err = hub
        .validate()
        .expect_err("关闭告警时非法配置仍必须被拒绝")
        .to_string();
    assert!(err.contains("alerts.evaluation_interval_secs"));
}
