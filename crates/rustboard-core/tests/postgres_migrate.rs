//! M5 Phase D5 核心：SQLite v9 → PostgreSQL 实库迁移/校验测试。
//!
//! 依据 `docs/plans/2026-10-26-m5-phase-d-postgres-backup-l01-l03.md`
//! §3.4/§5 D5/§6.3 编写。测试只覆盖 `storage::migrate` 的核心 API：
//!
//! - 22 张表全量迁移、每表行数、samples/1m/1h 范围、token/alert/archive 数量；
//! - samples/1m/1h/alert_states 的 SQLite rowid 与 PG `id` 一一对应；
//! - 5 张 SQLite `AUTOINCREMENT` 表的 id 保留；
//! - 9 个 `BIGSERIAL` 序列 setval 后不会撞主键；清理事件/raw 后仍按
//!   `sqlite_sequence` 与持久化游标推进，新 id 越过旧游标；
//! - 目标非空拒绝、失败注入后事务回滚、SQLite 文件/WAL 哈希不变、再次迁移成功；
//! - 空库、schema 已 apply 但全空、5000 行 samples 批量迁移；
//! - `samples_1m.last_ts` 总和超过 `i64::MAX` 时仍用分块 i128 校验完成迁移。
//!
//! # 运行方式
//!
//! ```bash
//! set -a; . /tmp/rb-d3-pg.env; set +a
//! cargo test -p rustboard-core --test postgres_migrate --locked -- --nocapture
//! ```
//!
//! 未设置 `RUSTBOARD_TEST_PG` 时每个用例打印 `SKIP` 并返回（cargo 记为 passed）。
//! DSN 必须显式 `sslmode=disable`。每个用例创建独立数据库
//! `rb_d5_<tag>_<pid>_<nanos>_<seq>`，结束时 `DROP DATABASE ... WITH (FORCE)`；
//! 角色需要 `CREATEDB` 权限。测试只创建/删除临时库，不触碰容器本体。
//!
//! 测试 DSN 只存在于运行环境；本文件不含真实密码。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres::config::SslMode;
use postgres::NoTls;
use rusqlite::{Connection, OpenFlags};
use rustboard_common::model::{AgentRecord, Labels, Sample, SampleBatch};
use rustboard_core::alerts::{
    AlertEvent, AlertRule, AlertSilence, AlertSource, AlertState, AlertStateKind, Comparator,
};
use rustboard_core::archive::{ArchiveObject, ArchiveStatus};
use rustboard_core::channels::{ChannelConfig, ChannelKind, NotificationChannel, Secret};
use rustboard_core::storage::migrate::{
    migrate_sqlite_to_postgres, validate_target_empty, MigrateReport,
};
use rustboard_core::storage::postgres::schema::{apply_schema, connect_for_schema};
use rustboard_core::storage::postgres::{PostgresOptions, PostgresStorage};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::{IngestOutcome, NewAuditEntry, Storage};
use sha2::{Digest, Sha256};

/// 实库测试 DSN 的环境变量；未设置时全部用例 skip。
const PG_ENV: &str = "RUSTBOARD_TEST_PG";

/// 与 schema.rs 一致的 22 张业务表；用于不依赖报告的全表计数。
const TABLES: [&str; 22] = [
    "agents",
    "samples",
    "enroll_tokens",
    "agent_secrets",
    "revoked_agents",
    "agent_settings",
    "ingest_state",
    "ingest_batches",
    "agent_control",
    "audit_log",
    "api_tokens",
    "samples_1m",
    "samples_1h",
    "maintenance_state",
    "alert_rules",
    "alert_states",
    "alert_events",
    "alert_silences",
    "notification_channels",
    "alert_rule_channels",
    "archive_objects",
    "archive_state",
];

/// 与 migrate.rs 一致的 9 张 `BIGSERIAL` 表；序列状态必须逐张核对。
const SERIAL_TABLES: [&str; 9] = [
    "samples",
    "audit_log",
    "api_tokens",
    "samples_1m",
    "samples_1h",
    "alert_states",
    "alert_events",
    "alert_silences",
    "archive_objects",
];

/// 与 fixture 一致的时间基点（整分钟对齐）。
const BASE_TS: i64 = 1_700_000_040_000;
const NOW: i64 = 1_700_000_100_000;

/// 每次调用返回递增序号，避免同一纳秒内两个用例撞库名。
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

fn skip(test_name: &str) {
    eprintln!("SKIP {test_name}: 未设置 {PG_ENV}（D5 迁移实库测试需要 PostgreSQL）");
}

/// 解析 `RUSTBOARD_TEST_PG`；未设置或空串时返回 `None`。
fn test_dsn() -> Option<String> {
    let dsn = std::env::var(PG_ENV).ok()?;
    if dsn.trim().is_empty() {
        return None;
    }
    let config: postgres::Config = dsn
        .parse()
        .unwrap_or_else(|e| panic!("{PG_ENV} 解析失败：{e}"));
    assert_eq!(
        config.get_ssl_mode(),
        SslMode::Disable,
        "{PG_ENV} 必须显式 sslmode=disable（D5 实库测试只覆盖明文路径）"
    );
    Some(dsn)
}

/// 把 URL DSN 的数据库路径替换成 `db`，保留 authority/query。
fn dsn_with_database(dsn: &str, db: &str) -> String {
    let (base, query) = match dsn.split_once('?') {
        Some((base, query)) => (base, Some(query)),
        None => (dsn, None),
    };
    let scheme_end = base.find("://").expect("DSN 必须包含 scheme") + 3;
    let path_start = base[scheme_end..].find('/').map(|index| scheme_end + index);
    let prefix = match path_start {
        Some(index) => &base[..index],
        None => base,
    };
    let mut out = format!("{prefix}/{db}");
    if let Some(query) = query {
        out.push('?');
        out.push_str(query);
    }
    out
}

/// 从 URL DSN 的 userinfo 提取明文密码（只用于断言错误信息不泄露）。
fn dsn_password(dsn: &str) -> Option<String> {
    let rest = dsn
        .strip_prefix("postgres://")
        .or_else(|| dsn.strip_prefix("postgresql://"))?;
    let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, _) = authority.rsplit_once('@')?;
    let (_, password) = userinfo.split_once(':')?;
    Some(password.to_string())
}

/// 一个临时 PostgreSQL 测试库；Drop 时用维护库连接强制删除。
struct TestDatabase {
    name: String,
    admin: postgres::Config,
    app: postgres::Config,
    app_dsn: String,
}

impl TestDatabase {
    fn create(tag: &str) -> Option<Self> {
        let dsn = test_dsn()?;
        let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let name = format!("rb_d5_{tag}_{}_{nanos}_{seq}", std::process::id());
        assert!(
            name.len() <= 63,
            "测试库名超过 PostgreSQL 标识符上限：{name}"
        );
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "测试库名只允许小写字母/数字/下划线：{name}"
        );

        let base: postgres::Config = dsn
            .parse()
            .unwrap_or_else(|e| panic!("{PG_ENV} 解析失败：{e}"));
        let mut admin = base.clone();
        admin.dbname("postgres");
        let mut admin_client = admin
            .connect(NoTls)
            .unwrap_or_else(|e| panic!("连接 postgres 维护库失败（检查 {PG_ENV} 与容器）：{e}"));
        admin_client
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .unwrap_or_else(|e| {
                panic!("CREATE DATABASE {name} 失败（角色需要 CREATEDB 权限）：{e}")
            });
        drop(admin_client);

        let app_dsn = dsn_with_database(&dsn, &name);
        let mut app = base;
        app.dbname(&name);
        eprintln!("[d5] 创建测试数据库 {name}（tag={tag}）");
        Some(Self {
            name,
            admin,
            app,
            app_dsn,
        })
    }

    /// 打开 `PostgresStorage`；不应用 schema，用于测试「裸空目标」。
    fn open_raw_storage(&self) -> PostgresStorage {
        PostgresStorage::open(PostgresOptions {
            dsn: self.app_dsn.clone(),
            pool_size: 2,
            connect_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(30),
            sslrootcert: None,
        })
        .unwrap_or_else(|e| panic!("打开 PostgresStorage 失败：{e:#}"))
    }

    /// 应用 schema v9 后打开 storage，用于「schema 已 apply 但全空」场景。
    fn open_storage(&self) -> PostgresStorage {
        let mut client = connect_for_schema(&self.app_dsn)
            .unwrap_or_else(|e| panic!("schema 连接失败（{}）：{e:#}", self.name));
        apply_schema(&mut client).unwrap_or_else(|e| panic!("apply_schema 失败：{e:#}"));
        drop(client);
        self.open_raw_storage()
    }

    /// 直连测试库（造数/校验）。
    fn client(&self) -> postgres::Client {
        self.app
            .connect(NoTls)
            .unwrap_or_else(|e| panic!("连接测试库 {} 失败：{e}", self.name))
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let mut client = match self.admin.connect(NoTls) {
            Ok(client) => client,
            Err(e) => {
                eprintln!(
                    "[d5] 清理失败：无法连接维护库删除 {}（请手工 DROP）：{e}",
                    self.name
                );
                return;
            }
        };
        if let Err(e) = client.batch_execute(&format!(
            "DROP DATABASE IF EXISTS {} WITH (FORCE)",
            self.name
        )) {
            eprintln!(
                "[d5] 清理失败：DROP DATABASE {} 出错（请手工清理）：{e}",
                self.name
            );
        }
    }
}

/// 临时目录，Drop 时递归删除。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("rb-d5-{tag}-{}-{nanos}-{seq}", std::process::id()));
        std::fs::create_dir_all(&path).expect("创建临时目录失败");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    _temp: TempDir,
    path: PathBuf,
    watermark: i64,
}

fn agent_record(id: &str, name: &str, status: &str) -> AgentRecord {
    AgentRecord {
        agent_id: id.to_string(),
        name: name.to_string(),
        hostname: format!("host-{id}"),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        version: "1.0.0".to_string(),
        boot_id: "boot-1".to_string(),
        status: status.to_string(),
        last_seen_at: NOW,
        created_at: NOW - 1_000,
    }
}

fn sample_batch(agent_id: &str, epoch: u64, seq: u64, samples: Vec<Sample>) -> SampleBatch {
    SampleBatch {
        agent_id: agent_id.to_string(),
        epoch,
        seq,
        boot_id: "boot-1".to_string(),
        sent_at: NOW,
        samples,
    }
}

fn labeled_sample(metric: &str, label: &str, ts: i64, value: f64) -> Sample {
    Sample::new(metric, ts, value).with_label("host", label)
}

fn alert_rule(id: &str, name: &str, enabled: bool) -> AlertRule {
    AlertRule {
        id: id.to_string(),
        name: name.to_string(),
        enabled,
        source: AlertSource::Metric,
        metric: "cpu.usage".to_string(),
        comparator: Comparator::Gt,
        threshold: 80.0,
        duration_secs: 60,
        cooldown_secs: 1_800,
        filter_agent_id: Some("agent-1".to_string()),
        filter_labels: Labels::new(),
        channel_ids: vec!["chan-1".to_string()],
        notify_on_resolve: true,
        is_builtin: false,
        updated_by: "admin".to_string(),
        created_at: NOW - 2_000,
        updated_at: NOW - 2_000,
        revision: 0,
    }
}

fn offline_rule(id: &str, name: &str) -> AlertRule {
    AlertRule {
        id: id.to_string(),
        name: name.to_string(),
        enabled: false,
        source: AlertSource::AgentOffline,
        metric: String::new(),
        comparator: Comparator::Gt,
        threshold: 300.0,
        duration_secs: 0,
        cooldown_secs: 1_800,
        filter_agent_id: None,
        filter_labels: Labels::new(),
        channel_ids: Vec::new(),
        notify_on_resolve: false,
        is_builtin: false,
        updated_by: "admin".to_string(),
        created_at: NOW - 1_000,
        updated_at: NOW - 1_000,
        revision: 0,
    }
}

fn alert_state(
    rule_id: &str,
    agent_id: &str,
    state: AlertStateKind,
    last_value: Option<f64>,
    last_notified_at: Option<i64>,
) -> AlertState {
    AlertState {
        rule_id: rule_id.to_string(),
        agent_id: agent_id.to_string(),
        series_key: "cpu.usage".to_string(),
        state,
        since: NOW - 3_000,
        last_eval_at: NOW,
        last_value,
        last_notified_at,
    }
}

fn alert_event(
    ts: i64,
    state: AlertStateKind,
    value: Option<f64>,
    notified: bool,
    silenced: bool,
) -> AlertEvent {
    AlertEvent {
        id: 0,
        ts,
        rule_id: "rule-1".to_string(),
        rule_name: "High CPU".to_string(),
        agent_id: "agent-1".to_string(),
        series_key: "cpu.usage".to_string(),
        state,
        value,
        message: "测试告警事件".to_string(),
        notified,
        notify_error: if notified {
            String::new()
        } else {
            "no_channel".to_string()
        },
        silenced,
    }
}

/// 审计写入的最小合法记录；id 由 SQLite/PG 自增分配。
fn audit_entry(ts: i64) -> NewAuditEntry {
    NewAuditEntry {
        ts,
        actor: "admin".to_string(),
        agent_id: String::new(),
        capability: "systemd".to_string(),
        action: "restart".to_string(),
        target: "rb-hub".to_string(),
        params: "{}".to_string(),
        result: "ok".to_string(),
        error_code: String::new(),
        error_message: String::new(),
        duration_ms: 1,
    }
}

fn notification_channel() -> NotificationChannel {
    NotificationChannel {
        id: "chan-1".to_string(),
        name: "ops".to_string(),
        kind: ChannelKind::Telegram,
        config: ChannelConfig::Telegram {
            bot_token: Secret::new("123456789:fake-token-for-test-12345"),
            chat_id: "-1001234567890".to_string(),
        },
        enabled: true,
        updated_by: "admin".to_string(),
        created_at: NOW - 5_000,
        updated_at: NOW - 5_000,
    }
}

fn archive_object(index: i64, uploaded: bool) -> ArchiveObject {
    ArchiveObject {
        id: 0,
        backend: "webdav".to_string(),
        object_key: format!("rustboard/2026/10/26/part-{index:05}.csv.gz"),
        manifest_key: format!("rustboard/2026/10/26/part-{index:05}.csv.gz.manifest.json"),
        from_ts: BASE_TS,
        to_ts: BASE_TS + 120_000,
        rows: 11,
        bytes: 1_234,
        sha256: format!("{index:064x}"),
        status: if uploaded {
            ArchiveStatus::Uploaded
        } else {
            ArchiveStatus::Pending
        },
        error: String::new(),
        created_at: NOW - 6_000,
        uploaded_at: if uploaded { Some(NOW - 1_000) } else { None },
        deleted_at: None,
        ledger_version: 0,
        attempts: 0,
    }
}

/// 构建一个包含全部 22 张表、覆盖 NULL/布尔/rowid/AUTOINCREMENT 的 SQLite v9。
fn build_fixture(tag: &str) -> Fixture {
    let temp = TempDir::new(tag);
    let path = temp.0.join("source.db");
    let watermark;

    {
        let storage = SqliteStorage::open(&path).expect("创建 SQLite v9 源库失败");

        // agents：3 行，其中 agent-3 走吊销终态。
        storage
            .upsert_agent(&agent_record("agent-1", "Node 1", "online"))
            .unwrap();
        storage
            .upsert_agent(&agent_record("agent-2", "Node 2", "offline"))
            .unwrap();
        storage
            .upsert_agent(&agent_record("agent-3", "Node 3", "pending"))
            .unwrap();
        storage.revoke_agent("agent-3", NOW + 1).unwrap();

        // agent_settings / agent_secrets / enroll_tokens / agent_control。
        storage.set_sample_interval("agent-1", 5_000, NOW).unwrap();
        storage
            .set_agent_secret("agent-1", "secret-hash-1", NOW)
            .unwrap();
        storage
            .create_enroll_token("enroll-hash-1", "enroll-1", NOW, NOW + 3_600_000)
            .unwrap();
        storage
            .create_enroll_token("enroll-hash-2", "enroll-2", NOW, NOW + 3_600_000)
            .unwrap();
        assert_eq!(
            storage
                .consume_enroll_token("enroll-hash-2", NOW + 1)
                .unwrap()
                .as_deref(),
            Some("enroll-2")
        );
        storage
            .upsert_agent_control("agent-1", &["systemd".to_string(), "logs".to_string()], NOW)
            .unwrap();

        // samples / ingest_state / ingest_batches：3 个批次、11 个样本点、3 个序列。
        let batch1 = sample_batch(
            "agent-1",
            1,
            0,
            vec![
                labeled_sample("cpu.usage", "a", BASE_TS, 10.5),
                labeled_sample("cpu.usage", "a", BASE_TS + 1_000, 11.5),
                labeled_sample("cpu.usage", "a", BASE_TS + 2_000, 12.5),
                labeled_sample("cpu.usage", "a", BASE_TS + 60_000, 20.0),
                labeled_sample("cpu.usage", "a", BASE_TS + 61_000, 21.0),
                labeled_sample("cpu.usage", "a", BASE_TS + 120_000, 30.0),
            ],
        );
        assert!(matches!(
            storage.insert_batch(&batch1).unwrap(),
            IngestOutcome::Inserted { inserted: 6 }
        ));
        let batch2 = sample_batch(
            "agent-1",
            1,
            1,
            vec![
                Sample::new("mem.used", BASE_TS, 100.0),
                Sample::new("mem.used", BASE_TS + 60_000, 110.0),
            ],
        );
        assert!(matches!(
            storage.insert_batch(&batch2).unwrap(),
            IngestOutcome::Inserted { inserted: 2 }
        ));
        let batch3 = sample_batch(
            "agent-2",
            7,
            0,
            vec![
                labeled_sample("cpu.usage", "b", BASE_TS, 5.0),
                labeled_sample("cpu.usage", "b", BASE_TS + 60_000, 6.0),
                labeled_sample("cpu.usage", "b", BASE_TS + 120_000, 7.0),
            ],
        );
        assert!(matches!(
            storage.insert_batch(&batch3).unwrap(),
            IngestOutcome::Inserted { inserted: 3 }
        ));

        // audit_log：2 行，覆盖空/非空错误字段。
        storage
            .insert_audit(&NewAuditEntry {
                ts: NOW - 100,
                actor: "admin".to_string(),
                agent_id: "agent-1".to_string(),
                capability: "systemd".to_string(),
                action: "restart".to_string(),
                target: "demo.service".to_string(),
                params: "{\"pid\":1}".to_string(),
                result: "ok".to_string(),
                error_code: String::new(),
                error_message: String::new(),
                duration_ms: 12,
            })
            .unwrap();
        storage
            .insert_audit(&NewAuditEntry {
                ts: NOW - 200,
                actor: "admin".to_string(),
                agent_id: "agent-2".to_string(),
                capability: "logs".to_string(),
                action: "tail".to_string(),
                target: "syslog".to_string(),
                params: "{}".to_string(),
                result: "error".to_string(),
                error_code: "denied".to_string(),
                error_message: "not allowed".to_string(),
                duration_ms: 0,
            })
            .unwrap();

        // api_tokens：2 行；一行 last_used_at 非空，一行 revoked_at 非空。
        storage
            .create_api_token("ops", &"a".repeat(64), "admin", NOW)
            .unwrap();
        storage
            .authenticate_api_token(&"a".repeat(64), NOW + 120_000)
            .unwrap();
        storage
            .create_api_token("readonly", &"b".repeat(64), "read", NOW + 1)
            .unwrap();
        storage.revoke_api_token("readonly", NOW + 2).unwrap();

        // 1m / 1h 降采样：制造真实 rowid 与聚合值。
        assert!(
            storage
                .downsample_1m_range(BASE_TS, BASE_TS + 180_000)
                .unwrap()
                .buckets
                > 0
        );
        assert!(
            storage
                .downsample_1h_range(BASE_TS, BASE_TS + 3_600_000)
                .unwrap()
                .buckets
                > 0
        );

        // maintenance_state：rowid 水位指向真实 raw 行；另有 prune 代际。
        let (max_rowid, _) = storage.raw_new_rows(None).unwrap();
        watermark = max_rowid.expect("samples 非空，必须存在最大 rowid");
        storage
            .set_maintenance_state("downsample_1m_last_raw_rowid", &watermark.to_string(), NOW)
            .unwrap();
        storage
            .set_maintenance_state("raw_prune_generation", "2", NOW)
            .unwrap();
        storage
            .set_archive_state("last_archived_ts", &(BASE_TS - 1).to_string(), NOW)
            .unwrap();

        // alert_rules / alert_states / alert_events / alert_silences / channels。
        // v9 起规则写入会在同一事务内校验渠道并写关系行，先创建 chan-1。
        storage
            .create_notification_channel(&notification_channel())
            .unwrap();
        storage
            .create_alert_rule(&alert_rule("rule-1", "High CPU", true))
            .unwrap();
        let mut offline = offline_rule("rule-2", "Agent Offline");
        offline.channel_ids = vec!["chan-1".to_string()];
        storage.create_alert_rule(&offline).unwrap();
        // 更新一次 rule-1，让 revision 离开默认值 0，验证迁移原样复制。
        let mut updated_rule = storage
            .get_alert_rule("rule-1")
            .unwrap()
            .expect("rule-1 必须存在");
        updated_rule.threshold = 81.0;
        updated_rule.updated_at = NOW;
        storage.update_alert_rule(&updated_rule).unwrap();
        assert_eq!(
            storage.get_alert_rule("rule-1").unwrap().unwrap().revision,
            1,
            "更新规则后 revision 必须为 1"
        );
        storage
            .upsert_alert_state(&alert_state(
                "rule-1",
                "agent-1",
                AlertStateKind::Firing,
                Some(91.5),
                None,
            ))
            .unwrap();
        storage
            .upsert_alert_state(&alert_state(
                "rule-2",
                "agent-2",
                AlertStateKind::Pending,
                None,
                Some(NOW - 500),
            ))
            .unwrap();
        storage
            .insert_alert_event(&alert_event(
                NOW - 100,
                AlertStateKind::Firing,
                Some(91.5),
                true,
                false,
            ))
            .unwrap();
        storage
            .insert_alert_event(&alert_event(
                NOW - 50,
                AlertStateKind::Resolved,
                None,
                false,
                true,
            ))
            .unwrap();
        storage
            .create_alert_silence(&AlertSilence {
                id: 0,
                rule_id: None,
                agent_id: None,
                until_ts: NOW + 3_600_000,
                created_by: "admin".to_string(),
                created_at: NOW - 10,
            })
            .unwrap();
        storage
            .create_alert_silence(&AlertSilence {
                id: 0,
                rule_id: Some("rule-1".to_string()),
                agent_id: Some("agent-2".to_string()),
                until_ts: NOW + 7_200_000,
                created_by: "admin".to_string(),
                created_at: NOW - 20,
            })
            .unwrap();
        // archive_objects：pending / uploaded 各一行，覆盖可空时间戳。
        storage
            .insert_archive_object(&archive_object(1, false))
            .unwrap();
        storage
            .insert_archive_object(&archive_object(2, true))
            .unwrap();
    }

    Fixture {
        _temp: temp,
        path,
        watermark,
    }
}

fn read_source_count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap_or_else(|e| panic!("统计 SQLite {table} 失败：{e}"))
}

fn pg_count(client: &mut postgres::Client, table: &str) -> i64 {
    client
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .unwrap_or_else(|e| panic!("统计 PostgreSQL {table} 失败：{e}"))
        .get(0)
}

/// 读取 `table.id` 关联序列的 `(last_value, is_called)`。
fn pg_sequence_state(client: &mut postgres::Client, table: &str) -> (i64, bool) {
    let sequence: String = client
        .query_one("SELECT pg_get_serial_sequence($1, 'id')", &[&table])
        .unwrap_or_else(|e| panic!("读取 {table} 序列名失败：{e}"))
        .get(0);
    let row = client
        .query_one(
            &format!("SELECT last_value, is_called FROM {sequence}"),
            &[],
        )
        .unwrap_or_else(|e| panic!("读取序列 {sequence} 状态失败：{e}"));
    (row.get(0), row.get(1))
}

/// 构建只有 agent + `count` 条 samples 的源库，用于批量/并发测试。
fn build_bulk_fixture(tag: &str, count: usize) -> (TempDir, PathBuf) {
    let temp = TempDir::new(tag);
    let path = temp.0.join("bulk.db");
    {
        let storage = SqliteStorage::open(&path).expect("创建 bulk SQLite 失败");
        storage
            .upsert_agent(&agent_record("agent-bulk", "Bulk", "online"))
            .unwrap();
        let samples = (0..count)
            .map(|index| {
                Sample::new(
                    "cpu.usage",
                    BASE_TS + i64::try_from(index).unwrap(),
                    index as f64 * 0.25,
                )
            })
            .collect();
        assert!(matches!(
            storage
                .insert_batch(&sample_batch("agent-bulk", 1, 0, samples))
                .unwrap(),
            IngestOutcome::Inserted { inserted } if inserted == count
        ));
    }
    (temp, path)
}

/// 构造只有 `alert_events` 历史高水位与 notify 游标的 SQLite v9 源库：
/// 写入 `event_count` 条已通知事件 → 保存任意字符串游标 → prune 清空。
///
/// 这样 `sqlite_sequence.seq = event_count`，而 `maintenance_state` 里的游标
/// 可以是更大值（验证游标分支）、0、负数或非法值（验证忽略语义）。
fn build_pruned_event_fixture(tag: &str, event_count: i64, cursor: &str) -> (TempDir, PathBuf) {
    let temp = TempDir::new(tag);
    let path = temp.0.join("events.db");
    {
        let storage = SqliteStorage::open(&path).expect("创建事件 SQLite 源库失败");
        for index in 0..event_count {
            let event = alert_event(
                BASE_TS + index,
                AlertStateKind::Firing,
                Some(90.0),
                true,
                false,
            );
            let id = storage
                .insert_alert_event(&event)
                .expect("写入告警事件失败");
            assert_eq!(id, index + 1, "alert_events 自增 id 应从 1 开始");
        }
        storage
            .set_maintenance_state("notify_started_event_id", cursor, NOW)
            .expect("保存通知游标失败");
        assert_eq!(
            storage
                .prune_alert_events(i64::MAX, 0)
                .expect("清空告警事件失败"),
            usize::try_from(event_count).expect("事件数必须能放进 usize")
        );
    }
    (temp, path)
}

/// archive_objects 的（id, object_key, status, uploaded_at, deleted_at）。
type ArchiveRow = (i64, String, String, Option<i64>, Option<i64>);

fn hash_file(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("读取 {} 失败：{e}", path.display()));
    hex::encode(Sha256::digest(bytes))
}

fn wal_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push("-wal");
    PathBuf::from(os)
}

/// 源库主文件 + WAL 的哈希；WAL 不存在时第二项为 None。
fn hash_source(path: &Path) -> (String, Option<String>) {
    let wal = wal_path(path);
    let wal_hash = if wal.is_file() {
        Some(hash_file(&wal))
    } else {
        None
    };
    (hash_file(path), wal_hash)
}

fn open_readonly(path: &Path) -> Connection {
    // 与 migrate::open_source 相同：没有 -wal 时用 immutable=1，避免测试自己
    // 的只读查询创建空 WAL，从而污染“源库/WAL 哈希不变”的断言。
    let wal = wal_path(path);
    let open = |target: &Path, flags| {
        Connection::open_with_flags(target, flags)
            .unwrap_or_else(|e| panic!("只读打开 {} 失败：{e}", target.display()))
    };
    if wal.is_file() {
        open(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
    } else {
        let absolute = std::path::absolute(path).expect("解析源库绝对路径失败");
        let text = absolute.to_str().expect("源库路径必须是 UTF-8");
        let mut uri = String::from("file:");
        for byte in text.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                    uri.push(char::from(byte));
                }
                _ => uri.push_str(&format!("%{byte:02X}")),
            }
        }
        uri.push_str("?immutable=1");
        open(
            Path::new(&uri),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
    }
}

fn source_samples(path: &Path) -> Vec<(i64, String, String, String, i64, f64)> {
    let conn = open_readonly(path);
    let mut stmt = conn
        .prepare(
            "SELECT rowid, agent_id, metric, labels, ts, value
             FROM samples ORDER BY rowid",
        )
        .expect("准备 samples 查询失败");
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        })
        .expect("查询 samples 失败");
    rows.map(|row| row.expect("读取 samples 行失败")).collect()
}

fn pg_samples(client: &mut postgres::Client) -> Vec<(i64, String, String, String, i64, f64)> {
    client
        .query(
            "SELECT id, agent_id, metric, labels, ts, value
             FROM samples ORDER BY id",
            &[],
        )
        .expect("查询 PostgreSQL samples 失败")
        .into_iter()
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
            )
        })
        .collect()
}

struct BucketRow {
    id: i64,
    agent_id: String,
    metric: String,
    labels: String,
    bucket_ts: i64,
    min_value: f64,
    max_value: f64,
    avg_value: f64,
    last_value: f64,
    count: i64,
}

fn source_buckets(path: &Path, table: &str) -> Vec<BucketRow> {
    let conn = open_readonly(path);
    let mut stmt = conn
        .prepare(&format!(
            "SELECT rowid, agent_id, metric, labels, bucket_ts,
                    min_value, max_value, avg_value, last_value, count
             FROM {table} ORDER BY rowid"
        ))
        .unwrap_or_else(|e| panic!("准备 {table} 查询失败：{e}"));
    let rows = stmt
        .query_map([], |row| {
            Ok(BucketRow {
                id: row.get(0)?,
                agent_id: row.get(1)?,
                metric: row.get(2)?,
                labels: row.get(3)?,
                bucket_ts: row.get(4)?,
                min_value: row.get(5)?,
                max_value: row.get(6)?,
                avg_value: row.get(7)?,
                last_value: row.get(8)?,
                count: row.get(9)?,
            })
        })
        .unwrap_or_else(|e| panic!("查询 {table} 失败：{e}"));
    rows.map(|row| row.expect("读取桶行失败")).collect()
}

fn pg_buckets(client: &mut postgres::Client, table: &str) -> Vec<BucketRow> {
    client
        .query(
            &format!(
                "SELECT id, agent_id, metric, labels, bucket_ts,
                        min_value, max_value, avg_value, last_value, count
                 FROM {table} ORDER BY id"
            ),
            &[],
        )
        .unwrap_or_else(|e| panic!("查询 PostgreSQL {table} 失败：{e}"))
        .into_iter()
        .map(|row| BucketRow {
            id: row.get(0),
            agent_id: row.get(1),
            metric: row.get(2),
            labels: row.get(3),
            bucket_ts: row.get(4),
            min_value: row.get(5),
            max_value: row.get(6),
            avg_value: row.get(7),
            last_value: row.get(8),
            count: row.get(9),
        })
        .collect()
}

fn assert_f64_eq(actual: f64, expected: f64, context: &str) {
    let tolerance = 1e-9 * expected.abs().max(1.0);
    assert!(
        (actual - expected).abs() <= tolerance,
        "{context}：actual={actual} expected={expected}"
    );
}

fn assert_samples_match(
    source: &[(i64, String, String, String, i64, f64)],
    target: &[(i64, String, String, String, i64, f64)],
) {
    assert_eq!(source.len(), target.len(), "samples 行数不一致");
    for (index, (source, target)) in source.iter().zip(target).enumerate() {
        assert_eq!(source.0, target.0, "第 {index} 行 samples.id 不一致");
        assert_eq!(source.1, target.1, "第 {index} 行 agent_id 不一致");
        assert_eq!(source.2, target.2, "第 {index} 行 metric 不一致");
        assert_eq!(source.3, target.3, "第 {index} 行 labels 不一致");
        assert_eq!(source.4, target.4, "第 {index} 行 ts 不一致");
        assert_f64_eq(target.5, source.5, &format!("第 {index} 行 value"));
    }
}

fn assert_buckets_match(source: &[BucketRow], target: &[BucketRow], table: &str) {
    assert_eq!(source.len(), target.len(), "{table} 行数不一致");
    for (index, (source, target)) in source.iter().zip(target).enumerate() {
        assert_eq!(source.id, target.id, "{table} 第 {index} 行 id 不一致");
        assert_eq!(source.agent_id, target.agent_id);
        assert_eq!(source.metric, target.metric);
        assert_eq!(source.labels, target.labels);
        assert_eq!(source.bucket_ts, target.bucket_ts);
        assert_f64_eq(
            target.min_value,
            source.min_value,
            &format!("{table} 第 {index} 行 min"),
        );
        assert_f64_eq(
            target.max_value,
            source.max_value,
            &format!("{table} 第 {index} 行 max"),
        );
        assert_f64_eq(
            target.avg_value,
            source.avg_value,
            &format!("{table} 第 {index} 行 avg"),
        );
        assert_f64_eq(
            target.last_value,
            source.last_value,
            &format!("{table} 第 {index} 行 last"),
        );
        assert_eq!(source.count, target.count);
    }
}

// ---------------------------------------------------------------------------
// 1. 全表迁移 + ID/范围/字段校验 + 目标非空之外的所有验收
// ---------------------------------------------------------------------------

#[test]
fn migrates_all_tables_and_preserves_ids() {
    const NAME: &str = "migrates_all_tables_and_preserves_ids";
    let Some(db) = TestDatabase::create("parity") else {
        skip(NAME);
        return;
    };
    let fixture = build_fixture("parity");
    let source_hash_before = hash_source(&fixture.path);

    let storage = db.open_raw_storage();
    // 裸空目标（schema 未 apply）也必须通过空库校验。
    validate_target_empty(&storage).expect("裸空目标必须允许迁移");
    let report = migrate_sqlite_to_postgres(&fixture.path, &storage)
        .unwrap_or_else(|e| panic!("迁移失败：{e:#}"));
    // 迁移本身（不含测试后续的只读查询）不得改动主库/WAL。
    assert_eq!(
        hash_source(&fixture.path),
        source_hash_before,
        "迁移修改了 SQLite 源库或 WAL"
    );

    assert_eq!(report.sqlite_schema_version, 9);
    assert_eq!(report.postgres_schema_version, 9);
    assert_eq!(report.tables.len(), TABLES.len());
    assert_eq!(
        report
            .tables
            .iter()
            .map(|table| table.table.as_str())
            .collect::<Vec<_>>(),
        TABLES.to_vec(),
        "报告表顺序必须与 PG schema/导入顺序一致"
    );

    let source = open_readonly(&fixture.path);
    let mut source_counts = Vec::new();
    for table in TABLES {
        source_counts.push((table, read_source_count(&source, table)));
    }
    for (table, count) in &source_counts {
        let reported = report
            .tables
            .iter()
            .find(|entry| entry.table == *table)
            .unwrap_or_else(|| panic!("报告缺少表 {table}"));
        assert_eq!(
            reported.rows,
            u64::try_from(*count).unwrap(),
            "报告行数与 SQLite {table} 不一致"
        );
    }
    assert_eq!(
        report.total_rows,
        source_counts
            .iter()
            .map(|(_, count)| *count as u64)
            .sum::<u64>()
    );
    assert_eq!(report.alert_states, 2);
    assert_eq!(report.alert_events, 2);
    assert_eq!(report.api_tokens, 2);
    assert_eq!(report.api_token_hashes, 2);
    assert_eq!(report.archive_objects, 2);

    // samples / 1m / 1h 的 rowid 与 PG id、时间范围、字段逐一对照。
    let source_samples = source_samples(&fixture.path);
    let mut client = db.client();
    let target_samples = pg_samples(&mut client);
    assert_samples_match(&source_samples, &target_samples);
    assert_eq!(report.samples_range.id_min, Some(source_samples[0].0));
    assert_eq!(
        report.samples_range.id_max,
        Some(source_samples.last().expect("samples 非空").0)
    );
    assert_eq!(
        report.samples_range.ts_min,
        source_samples.iter().map(|row| row.4).min()
    );
    assert_eq!(
        report.samples_range.ts_max,
        source_samples.iter().map(|row| row.4).max()
    );

    for (table, range) in [
        ("samples_1m", report.samples_1m_range),
        ("samples_1h", report.samples_1h_range),
    ] {
        let source_buckets = source_buckets(&fixture.path, table);
        let target_buckets = pg_buckets(&mut client, table);
        assert_buckets_match(&source_buckets, &target_buckets, table);
        assert_eq!(range.id_min, source_buckets.first().map(|row| row.id));
        assert_eq!(range.id_max, source_buckets.last().map(|row| row.id));
        assert_eq!(
            range.ts_min,
            source_buckets.iter().map(|row| row.bucket_ts).min()
        );
        assert_eq!(
            range.ts_max,
            source_buckets.iter().map(|row| row.bucket_ts).max()
        );
    }

    // 5 张 SQLite AUTOINCREMENT 表：id 必须原样保留（含中间被 revoke 的行）。
    for table in [
        "audit_log",
        "api_tokens",
        "alert_events",
        "alert_silences",
        "archive_objects",
    ] {
        let source_ids: Vec<i64> = {
            let conn = open_readonly(&fixture.path);
            let mut stmt = conn
                .prepare(&format!("SELECT id FROM {table} ORDER BY id"))
                .unwrap();
            let rows = stmt.query_map([], |row| row.get(0)).unwrap();
            rows.map(|row| row.unwrap()).collect()
        };
        let target_ids: Vec<i64> = client
            .query(&format!("SELECT id FROM {table} ORDER BY id"), &[])
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(source_ids, target_ids, "{table} 的 AUTOINCREMENT id 未保留");
    }

    // alert_states 的 rowid → id 也必须一致。
    let source_state_ids: Vec<i64> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare("SELECT rowid FROM alert_states ORDER BY rowid")
            .unwrap();
        let rows = stmt.query_map([], |row| row.get(0)).unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_state_ids: Vec<i64> = client
        .query("SELECT id FROM alert_states ORDER BY id", &[])
        .unwrap()
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(
        source_state_ids, target_state_ids,
        "alert_states rowid 未保留"
    );

    // 布尔列：SQLite INTEGER 0/1 必须变成 PG true/false（不是 i64）。
    let source_rules: Vec<(String, bool, bool)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare(
                "SELECT id, enabled, notify_on_resolve
                 FROM alert_rules ORDER BY id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, i64>(2)? != 0,
                ))
            })
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_rules: Vec<(String, bool, bool)> = client
        .query(
            "SELECT id, enabled, notify_on_resolve
             FROM alert_rules ORDER BY id",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert_eq!(source_rules, target_rules, "alert_rules 布尔列映射不一致");

    let source_events: Vec<(i64, bool, bool, Option<f64>)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare(
                "SELECT id, notified, silenced, value
                 FROM alert_events ORDER BY id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)? != 0,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, Option<f64>>(3)?,
                ))
            })
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    // TEXT JSON 列原样复制：notification_channels.config_json 与
    // alert_rules.filter_labels/channel_ids 不能改序列化格式。
    let source_channels: Vec<(String, String, bool)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare(
                "SELECT id, config_json, enabled
                 FROM notification_channels ORDER BY id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)? != 0,
                ))
            })
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_channels: Vec<(String, String, bool)> = client
        .query(
            "SELECT id, config_json, enabled
             FROM notification_channels ORDER BY id",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    assert_eq!(
        source_channels, target_channels,
        "notification_channels.config_json 未原样复制"
    );

    let source_rule_text: Vec<(String, Option<String>, String, String)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare(
                "SELECT id, filter_agent_id, filter_labels, channel_ids
                 FROM alert_rules ORDER BY id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_rule_text: Vec<(String, Option<String>, String, String)> = client
        .query(
            "SELECT id, filter_agent_id, filter_labels, channel_ids
             FROM alert_rules ORDER BY id",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    assert_eq!(
        source_rule_text, target_rule_text,
        "alert_rules 的 NULL/TEXT JSON 列映射不一致"
    );

    // v9 关系表必须逐行迁移；alert_rules.revision 原样复制（不能重置成 0）。
    let source_relations: Vec<(String, String)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare(
                "SELECT rule_id, channel_id FROM alert_rule_channels ORDER BY rule_id, channel_id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_relations: Vec<(String, String)> = client
        .query(
            "SELECT rule_id, channel_id FROM alert_rule_channels ORDER BY rule_id, channel_id",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        source_relations, target_relations,
        "alert_rule_channels 关系行未逐行迁移"
    );
    assert_eq!(target_relations.len(), 2, "关系表夹具应有 2 行");

    let source_revisions: Vec<(String, i64)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare("SELECT id, revision FROM alert_rules ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_revisions: Vec<(String, i64)> = client
        .query("SELECT id, revision FROM alert_rules ORDER BY id", &[])
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        source_revisions, target_revisions,
        "alert_rules.revision 未原样迁移"
    );

    // 两张水位表的 key/value 文本必须逐行原样保留。
    let source_maintenance: Vec<(String, String)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare("SELECT key, value FROM maintenance_state ORDER BY key")
            .unwrap();
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_maintenance: Vec<(String, String)> = client
        .query("SELECT key, value FROM maintenance_state ORDER BY key", &[])
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        source_maintenance, target_maintenance,
        "maintenance_state 文本值未原样复制"
    );

    let source_archive_state: Vec<(String, String)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare("SELECT key, value FROM archive_state ORDER BY key")
            .unwrap();
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_archive_state: Vec<(String, String)> = client
        .query("SELECT key, value FROM archive_state ORDER BY key", &[])
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect();
    assert_eq!(
        source_archive_state, target_archive_state,
        "archive_state 文本值未原样复制"
    );

    let target_events: Vec<(i64, bool, bool, Option<f64>)> = client
        .query(
            "SELECT id, notified, silenced, value
             FROM alert_events ORDER BY id",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    assert_eq!(
        source_events, target_events,
        "alert_events 布尔/NULL 映射不一致"
    );

    // api_tokens：哈希、last_used_at、revoked_at 的 NULL/值必须一致。
    let source_tokens: Vec<(i64, String, Option<i64>, Option<i64>)> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare(
                "SELECT id, token_hash, last_used_at, revoked_at
                 FROM api_tokens ORDER BY id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_tokens: Vec<(i64, String, Option<i64>, Option<i64>)> = client
        .query(
            "SELECT id, token_hash, last_used_at, revoked_at
             FROM api_tokens ORDER BY id",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3)))
        .collect();
    assert_eq!(source_tokens, target_tokens, "api_tokens 字段映射不一致");

    // archive_objects：pending/uploaded 与可空时间戳必须一致。
    let source_archives: Vec<ArchiveRow> = {
        let conn = open_readonly(&fixture.path);
        let mut stmt = conn
            .prepare(
                "SELECT id, object_key, status, uploaded_at, deleted_at
                 FROM archive_objects ORDER BY id",
            )
            .unwrap();
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .unwrap();
        rows.map(|row| row.unwrap()).collect()
    };
    let target_archives: Vec<ArchiveRow> = client
        .query(
            "SELECT id, object_key, status, uploaded_at, deleted_at
             FROM archive_objects ORDER BY id",
            &[],
        )
        .unwrap()
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2), row.get(3), row.get(4)))
        .collect();
    assert_eq!(
        source_archives, target_archives,
        "archive_objects 字段映射不一致"
    );

    // maintenance_state：rowid 水位原样保留，且目标 raw 行 id 与源 rowid 对应。
    let source_watermark: String = {
        let conn = open_readonly(&fixture.path);
        conn.query_row(
            "SELECT value FROM maintenance_state
             WHERE key = 'downsample_1m_last_raw_rowid'",
            [],
            |row| row.get(0),
        )
        .expect("读取 SQLite rowid 水位失败")
    };
    assert_eq!(source_watermark, fixture.watermark.to_string());
    let target_watermark: String = client
        .query_one(
            "SELECT value FROM maintenance_state
             WHERE key = 'downsample_1m_last_raw_rowid'",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(target_watermark, source_watermark);
    let watermark_row: bool = client
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM samples WHERE id = $1)",
            &[&fixture.watermark],
        )
        .unwrap()
        .get(0);
    assert!(watermark_row, "rowid 水位指向的 raw 行未按 id 迁移");

    // 9 个序列都已 setval：直接插一行 samples 必须拿到 MAX(id)+1。
    let max_sample_id: i64 = client
        .query_one("SELECT MAX(id) FROM samples", &[])
        .unwrap()
        .get(0);
    let next_sample_id: i64 = client
        .query_one(
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('sequence-probe', 'probe', '{}', $1, 1.0)
             RETURNING id",
            &[&(BASE_TS + 999_999)],
        )
        .unwrap()
        .get(0);
    assert_eq!(
        next_sample_id,
        max_sample_id + 1,
        "samples_id_seq 未推进到 MAX(id)"
    );

    // 9 张 SERIAL 表逐张核对：序列 last_value 必须等于迁移后 MAX(id) 且已
    // is_called，保证每张表的下一个 id 都是 MAX(id)+1，没有漏设任何一张。
    // 该 fixture 的 9 张表都非空，因此可以用 MAX(id) 作为精确期望。
    for table in SERIAL_TABLES {
        let (last_value, is_called) = pg_sequence_state(&mut client, table);
        let max_id: i64 = client
            .query_one(&format!("SELECT MAX(id) FROM {table}"), &[])
            .unwrap_or_else(|e| panic!("读取 {table} 最大 id 失败：{e}"))
            .get(0);
        assert_eq!(
            last_value, max_id,
            "{table} 序列 last_value 必须等于迁移后的 MAX(id)"
        );
        assert!(is_called, "{table} 序列必须 setval(is_called=true)");
    }

    // 报告 JSON 必须可序列化，且带每表行数/范围/耗时。
    let json = serde_json::to_value(&report).expect("MigrateReport 必须可序列化");
    assert_eq!(json["tables"].as_array().map(Vec::len), Some(TABLES.len()));
    assert!(json["samples_range"]["id_max"].is_number());
    assert!(json["tables"][0]["duration_ms"].is_number());
    assert!(json["total_rows"].is_number());
    assert!(json["duration_ms"].is_number());

    // 源库主文件/WAL 不得被修改。
    assert_eq!(
        hash_source(&fixture.path),
        source_hash_before,
        "迁移修改了 SQLite 源库或 WAL"
    );
}

// ---------------------------------------------------------------------------
// 2. 目标非空：拒绝、错误信息不含密码、目标数据不被覆盖
// ---------------------------------------------------------------------------

#[test]
fn rejects_non_empty_target_without_touching_source_or_target() {
    const NAME: &str = "rejects_non_empty_target_without_touching_source_or_target";
    let Some(db) = TestDatabase::create("nonempty") else {
        skip(NAME);
        return;
    };
    let fixture = build_fixture("nonempty");
    let source_hash_before = hash_source(&fixture.path);
    let storage = db.open_storage();
    storage
        .upsert_agent(&agent_record("existing", "Existing", "online"))
        .unwrap();

    let error = validate_target_empty(&storage).expect_err("目标有 agents 行时必须拒绝");
    assert!(format!("{error:#}").contains("非空"), "{error:#}");

    let error =
        migrate_sqlite_to_postgres(&fixture.path, &storage).expect_err("目标非空时迁移必须拒绝");
    let message = format!("{error:#}");
    assert!(message.contains("非空"), "{message}");
    assert!(message.contains("agents"), "{message}");
    if let Some(password) = dsn_password(&db.app_dsn) {
        assert!(
            !message.contains(&format!(":{password}@")),
            "迁移错误泄露了数据库密码"
        );
    }

    let mut client = db.client();
    assert_eq!(pg_count(&mut client, "agents"), 1, "目标已有行不能丢失");
    assert_eq!(
        pg_count(&mut client, "samples"),
        0,
        "拒绝时不能写入任何 samples"
    );
    assert_eq!(
        hash_source(&fixture.path),
        source_hash_before,
        "拒绝迁移修改了 SQLite 源库"
    );
}

// ---------------------------------------------------------------------------
// 3. 失败注入：非法布尔值 → 目标整体回滚；修复后再次迁移成功
// ---------------------------------------------------------------------------

#[test]
fn bool_failure_rolls_back_target_and_second_migration_succeeds() {
    const NAME: &str = "bool_failure_rolls_back_target_and_second_migration_succeeds";
    let Some(db) = TestDatabase::create("rollback") else {
        skip(NAME);
        return;
    };
    let fixture = build_fixture("rollback");

    // SQLite 不强制布尔，手工写入 2 模拟源库脏数据；迁移到 alert_rules
    // 时应在 samples 等前序表已写入后失败，从而验证整事务回滚。
    {
        let conn = Connection::open(&fixture.path).expect("打开 SQLite 写连接失败");
        conn.execute("UPDATE alert_rules SET enabled = 2 WHERE id = 'rule-1'", [])
            .expect("写入非法布尔值失败");
    }
    let source_hash_before = hash_source(&fixture.path);

    let storage = db.open_raw_storage();
    let error =
        migrate_sqlite_to_postgres(&fixture.path, &storage).expect_err("非法布尔值必须让迁移失败");
    let message = format!("{error:#}");
    assert!(message.contains("alert_rules"), "{message}");
    assert!(message.contains("布尔值"), "{message}");

    let mut client = db.client();
    for table in TABLES {
        assert_eq!(
            pg_count(&mut client, table),
            0,
            "失败注入后 {table} 仍有部分数据（事务未回滚）"
        );
    }
    let version: Option<i64> = client
        .query_one("SELECT MAX(version) FROM schema_migrations", &[])
        .unwrap()
        .get(0);
    assert_eq!(
        version,
        Some(9),
        "v9 DDL 已提交；数据导入失败只回滚业务数据，schema 版本保持 9"
    );
    assert_eq!(
        hash_source(&fixture.path),
        source_hash_before,
        "失败迁移修改了 SQLite 源库或 WAL"
    );

    // 修复源数据后再次迁移：目标此时仍是空的（仅 schema），必须成功。
    {
        let conn = Connection::open(&fixture.path).expect("打开 SQLite 写连接失败");
        conn.execute("UPDATE alert_rules SET enabled = 1 WHERE id = 'rule-1'", [])
            .expect("修复布尔值失败");
    }
    let report = migrate_sqlite_to_postgres(&fixture.path, &storage)
        .unwrap_or_else(|e| panic!("修复后第二次迁移失败：{e:#}"));
    assert_eq!(report.alert_states, 2);
    assert_eq!(report.alert_events, 2);
    assert_eq!(report.api_tokens, 2);
    assert_eq!(report.archive_objects, 2);

    let enabled: bool = client
        .query_one("SELECT enabled FROM alert_rules WHERE id = 'rule-1'", &[])
        .unwrap()
        .get(0);
    assert!(enabled, "修复后布尔值应为 true");
}

// ---------------------------------------------------------------------------
// 4. 空库：schema 已 apply 但全空允许；空表序列从 1 开始
// ---------------------------------------------------------------------------

#[test]
fn empty_source_migrates_and_sequences_start_at_one() {
    const NAME: &str = "empty_source_migrates_and_sequences_start_at_one";
    let Some(db) = TestDatabase::create("empty") else {
        skip(NAME);
        return;
    };
    let temp = TempDir::new("empty");
    let path = temp.0.join("empty.db");
    {
        let storage = SqliteStorage::open(&path).expect("创建空 SQLite v9 失败");
        drop(storage);
    }

    // schema 已 apply、22 张业务表全空：按验收必须允许。
    let storage = db.open_storage();
    validate_target_empty(&storage).expect("schema 已 apply 但全空的目标必须允许迁移");
    let report = migrate_sqlite_to_postgres(&path, &storage)
        .unwrap_or_else(|e| panic!("空库迁移失败：{e:#}"));
    assert_eq!(report.total_rows, 0);
    assert_eq!(report.tables.len(), TABLES.len());
    assert!(report.tables.iter().all(|table| table.rows == 0));
    assert_eq!(report.samples_range, Default::default());
    assert_eq!(report.alert_states, 0);
    assert_eq!(report.api_token_hashes, 0);

    let mut client = db.client();
    for table in TABLES {
        assert_eq!(pg_count(&mut client, table), 0, "空库迁移后 {table} 应为空");
    }

    let sample_id: i64 = client
        .query_one(
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('empty-probe', 'probe', '{}', 1, 1.0)
             RETURNING id",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(sample_id, 1, "空表 samples_id_seq 应从 1 开始");
    let audit_id: i64 = client
        .query_one(
            "INSERT INTO audit_log
                (ts, actor, agent_id, capability, action, result, duration_ms)
             VALUES (1, 'admin', '', 'systemd', 'restart', 'ok', 0)
             RETURNING id",
            &[],
        )
        .unwrap()
        .get(0);
    assert_eq!(audit_id, 1, "空表 audit_log 序列应从 1 开始");
}

// ---------------------------------------------------------------------------
// 4b. 清理后的历史高水位：sqlite_sequence + 持久化游标必须一起迁移
// ---------------------------------------------------------------------------

#[test]
fn pruned_tables_keep_high_water_and_event_cursor() {
    const NAME: &str = "pruned_tables_keep_high_water_and_event_cursor";
    let Some(db) = TestDatabase::create("highwater") else {
        skip(NAME);
        return;
    };
    let temp = TempDir::new("highwater");
    let path = temp.0.join("highwater.db");

    const EVENT_COUNT: i64 = 100;
    const AUDIT_COUNT: i64 = 7;
    const SAMPLE_COUNT: i64 = 5;

    {
        let storage = SqliteStorage::open(&path).expect("创建高水位 SQLite 源库失败");
        storage
            .upsert_agent(&agent_record("agent-highwater", "High Water", "online"))
            .unwrap();

        // alert_events：100 条已通知事件 + 游标 100，随后 prune 清空。
        for index in 0..EVENT_COUNT {
            let event = alert_event(
                BASE_TS + index,
                AlertStateKind::Firing,
                Some(90.0),
                true,
                false,
            );
            let id = storage
                .insert_alert_event(&event)
                .expect("写入告警事件失败");
            assert_eq!(id, index + 1, "alert_events 自增 id 应从 1 开始");
        }
        storage
            .set_maintenance_state("notify_started_event_id", &EVENT_COUNT.to_string(), NOW)
            .unwrap();
        assert_eq!(
            storage
                .prune_alert_events(i64::MAX, 0)
                .expect("清空告警事件失败"),
            usize::try_from(EVENT_COUNT).expect("事件数必须能放进 usize")
        );

        // audit_log：7 条后清空，验证 sqlite_sequence 高水位（AUTOINCREMENT）。
        for index in 0..AUDIT_COUNT {
            let id = storage
                .insert_audit(&audit_entry(BASE_TS + index))
                .expect("写入审计失败");
            assert_eq!(id, index + 1, "audit_log 自增 id 应从 1 开始");
        }
        assert_eq!(
            storage.prune_audit(i64::MAX).expect("清空审计失败"),
            usize::try_from(AUDIT_COUNT).expect("审计数必须能放进 usize")
        );

        // samples：5 条 raw + rowid 游标 5，随后清空 raw（rowid 表没有
        // sqlite_sequence，历史高水位只能来自持久化游标）。
        let samples = (0..SAMPLE_COUNT)
            .map(|index| {
                Sample::new("cpu.usage", BASE_TS + index, index as f64)
                    .with_label("host", "highwater")
            })
            .collect();
        assert!(matches!(
            storage
                .insert_batch(&sample_batch("agent-highwater", 1, 0, samples))
                .expect("写入 raw samples 失败"),
            IngestOutcome::Inserted { inserted }
                if inserted == usize::try_from(SAMPLE_COUNT).expect("样本数必须能放进 usize")
        ));
        storage
            .set_maintenance_state(
                "downsample_1m_last_raw_rowid",
                &SAMPLE_COUNT.to_string(),
                NOW,
            )
            .unwrap();
    }

    // 直接清空 samples，保留 rowid 游标 = 5（模拟旧版本遗留 / 崩溃残留的高水位）。
    {
        let conn = Connection::open(&path).expect("打开高水位 SQLite 写连接失败");
        conn.execute("DELETE FROM samples", [])
            .expect("清空 raw samples 失败");
    }

    // 源库侧确认：表已空，但 sqlite_sequence 与游标都还在。
    {
        let conn = open_readonly(&path);
        let event_seq: i64 = conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'alert_events'",
                [],
                |row| row.get(0),
            )
            .expect("读取 alert_events sqlite_sequence 失败");
        assert_eq!(event_seq, EVENT_COUNT);
        let cursor: String = conn
            .query_row(
                "SELECT value FROM maintenance_state WHERE key = 'notify_started_event_id'",
                [],
                |row| row.get(0),
            )
            .expect("读取通知游标失败");
        assert_eq!(cursor, EVENT_COUNT.to_string());
        for table in ["alert_events", "audit_log", "samples"] {
            assert_eq!(read_source_count(&conn, table), 0, "{table} 应已清空");
        }
    }

    let storage = db.open_raw_storage();
    let report = migrate_sqlite_to_postgres(&path, &storage)
        .unwrap_or_else(|e| panic!("清理后的高水位迁移失败：{e:#}"));
    assert_eq!(report.alert_events, 0);
    assert_eq!(report.samples_range, Default::default());
    // agents + ingest_state + ingest_batches + 2 条 maintenance_state 游标；
    // 三张被清空的表不得复活。
    assert_eq!(report.total_rows, 5);

    let mut client = db.client();
    assert_eq!(
        pg_sequence_state(&mut client, "alert_events"),
        (EVENT_COUNT, true),
        "alert_events 序列必须推进到 sqlite_sequence/通知游标高水位"
    );
    assert_eq!(
        pg_sequence_state(&mut client, "audit_log"),
        (AUDIT_COUNT, true),
        "audit_log 序列必须推进到 sqlite_sequence 高水位"
    );
    assert_eq!(
        pg_sequence_state(&mut client, "samples"),
        (SAMPLE_COUNT, true),
        "samples 序列必须推进到 rowid 游标高水位"
    );

    // 通知 worker 的游标原样迁移；新事件 id 必须越过它，pending 查询可读。
    let cursor: i64 = storage
        .get_maintenance_state("notify_started_event_id")
        .expect("读取目标通知游标失败")
        .expect("目标通知游标丢失")
        .trim()
        .parse()
        .expect("目标通知游标不是整数");
    assert_eq!(cursor, EVENT_COUNT);

    let mut new_event = alert_event(NOW, AlertStateKind::Firing, Some(99.0), false, false);
    new_event.notify_error = String::new();
    let new_event_id = storage
        .insert_alert_event(&new_event)
        .expect("迁移后写入新告警事件失败");
    assert!(
        new_event_id > EVENT_COUNT,
        "迁移后新事件 id（{new_event_id}）必须大于通知游标（{EVENT_COUNT}）"
    );
    let pending = storage
        .list_pending_notification_events_after(cursor, 10)
        .expect("读取 pending 事件失败");
    assert_eq!(pending.len(), 1, "新事件必须能被通知 worker 读到");
    assert_eq!(pending[0].id, new_event_id);

    // audit_log / samples 的新 id 也必须越过各自的历史高水位。
    let audit_id = storage
        .insert_audit(&audit_entry(NOW))
        .expect("迁移后写入审计失败");
    assert_eq!(audit_id, AUDIT_COUNT + 1);

    let sample_id: i64 = client
        .query_one(
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('agent-highwater', 'cpu.usage', '{}', $1, 1.0)
             RETURNING id",
            &[&(BASE_TS + 10)],
        )
        .expect("迁移后写入 raw sample 失败")
        .get(0);
    assert_eq!(sample_id, SAMPLE_COUNT + 1);
    assert_eq!(pg_count(&mut client, "samples"), 1);
}

// ---------------------------------------------------------------------------
// 4c. 通知游标单独决定高水位：cursor > sqlite_sequence.seq
// ---------------------------------------------------------------------------

#[test]
fn notify_cursor_ahead_of_sqlite_sequence_wins() {
    const NAME: &str = "notify_cursor_ahead_of_sqlite_sequence_wins";
    const EVENT_COUNT: i64 = 100;
    const CURSOR: i64 = 150;
    let Some(db) = TestDatabase::create("cursor_ahead") else {
        skip(NAME);
        return;
    };
    let (_temp, path) =
        build_pruned_event_fixture("cursor_ahead", EVENT_COUNT, &CURSOR.to_string());

    // 源库历史高水位是 100，但游标已被推进到 150；忽略游标就会错误地回到 101。
    {
        let conn = open_readonly(&path);
        let seq: i64 = conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'alert_events'",
                [],
                |row| row.get(0),
            )
            .expect("读取 alert_events sqlite_sequence 失败");
        assert_eq!(seq, EVENT_COUNT, "sqlite_sequence 历史高水位应为 100");
        assert_eq!(read_source_count(&conn, "alert_events"), 0, "事件应已清空");
    }

    let storage = db.open_raw_storage();
    migrate_sqlite_to_postgres(&path, &storage)
        .unwrap_or_else(|e| panic!("cursor > sqlite_sequence 的迁移失败：{e:#}"));

    let migrated_cursor = storage
        .get_maintenance_state("notify_started_event_id")
        .expect("读取目标通知游标失败")
        .expect("目标通知游标丢失");
    assert_eq!(migrated_cursor, CURSOR.to_string(), "游标必须原样迁移");

    let mut client = db.client();
    assert_eq!(
        pg_sequence_state(&mut client, "alert_events"),
        (CURSOR, true),
        "序列必须越过游标 150，而不是 sqlite_sequence 的 100"
    );

    let mut new_event = alert_event(NOW, AlertStateKind::Firing, Some(99.0), false, false);
    new_event.notify_error = String::new();
    let new_event_id = storage
        .insert_alert_event(&new_event)
        .expect("迁移后写入新告警事件失败");
    assert_eq!(
        new_event_id,
        CURSOR + 1,
        "新事件 id 必须是 151（越过游标），而不是 101（只按 sqlite_sequence）"
    );
    let pending = storage
        .list_pending_notification_events_after(CURSOR, 10)
        .expect("读取 pending 事件失败");
    assert_eq!(pending.len(), 1, "新事件必须能被通知 worker 读到");
    assert_eq!(pending[0].id, new_event_id);
}

// ---------------------------------------------------------------------------
// 4d. 通知游标 0 / 负数 / 非法值：不参与高水位，由 sqlite_sequence 兜底
// ---------------------------------------------------------------------------

#[test]
fn non_positive_or_invalid_notify_cursor_falls_back_to_sequence() {
    const NAME: &str = "non_positive_or_invalid_notify_cursor_falls_back_to_sequence";
    const EVENT_COUNT: i64 = 100;
    for (tag, raw_cursor) in [
        ("cursor_zero", "0"),
        ("cursor_negative", "-3"),
        ("cursor_invalid", "not-a-number"),
    ] {
        let Some(db) = TestDatabase::create(tag) else {
            skip(NAME);
            return;
        };
        let (_temp, path) = build_pruned_event_fixture(tag, EVENT_COUNT, raw_cursor);

        let storage = db.open_raw_storage();
        migrate_sqlite_to_postgres(&path, &storage).unwrap_or_else(|e| {
            panic!("游标 {raw_cursor:?} 的迁移失败（0/负数/非法值不得阻断迁移）：{e:#}")
        });

        // verify_maintenance_state 要求游标原样迁移，即使值是 0/负数/非法串。
        let migrated_cursor = storage
            .get_maintenance_state("notify_started_event_id")
            .expect("读取目标通知游标失败")
            .expect("目标通知游标丢失");
        assert_eq!(
            migrated_cursor, raw_cursor,
            "游标 {raw_cursor:?} 必须原样迁移"
        );

        let mut client = db.client();
        assert_eq!(
            pg_sequence_state(&mut client, "alert_events"),
            (EVENT_COUNT, true),
            "游标 {raw_cursor:?} 不得抬高序列；必须由 sqlite_sequence={EVENT_COUNT} 兜底"
        );

        let mut new_event = alert_event(NOW, AlertStateKind::Firing, Some(99.0), false, false);
        new_event.notify_error = String::new();
        let new_event_id = storage
            .insert_alert_event(&new_event)
            .expect("迁移后写入新告警事件失败");
        assert_eq!(
            new_event_id,
            EVENT_COUNT + 1,
            "游标 {raw_cursor:?} 时新事件 id 应由 sqlite_sequence 决定"
        );

        // 通知 worker 对游标 0 直接使用，对负数/非法值会在启动时重建为
        // MAX(alert_events.id)=0；两种情况下 after_id=0 都能读到新事件。
        let pending = storage
            .list_pending_notification_events_after(0, 10)
            .expect("读取 pending 事件失败");
        assert_eq!(
            pending.iter().map(|event| event.id).collect::<Vec<_>>(),
            vec![new_event_id],
            "游标 {raw_cursor:?} 时 after_id=0 必须能读到新事件"
        );
    }
}

// ---------------------------------------------------------------------------
// 4e. samples_1m.last_ts 总和超过 i64::MAX：分块 i128 校验必须通过
// ---------------------------------------------------------------------------

#[test]
fn samples_1m_sum_above_i64_max_migrates_across_chunks() {
    const NAME: &str = "samples_1m_sum_above_i64_max_migrates_across_chunks";
    let Some(db) = TestDatabase::create("sum_overflow") else {
        skip(NAME);
        return;
    };
    // 10 个完整分块 + 1 行：覆盖 10k 分块边界；总和 ≈ 1.0e19 > i64::MAX。
    const ROWS: usize = 100_001;
    const LAST_TS: i64 = 100_000_000_000_000; // < MAX_ARCHIVE_TS_MS，合法毫秒时间戳

    let temp = TempDir::new("sum_overflow");
    let path = temp.0.join("sum.db");
    {
        let storage = SqliteStorage::open(&path).expect("创建求和 SQLite 源库失败");
        drop(storage);
    }
    {
        let mut conn = Connection::open(&path).expect("打开 SQLite 写连接失败");
        let tx = conn.transaction().expect("开启 SQLite 事务失败");
        {
            let mut statement = tx
                .prepare(
                    "INSERT INTO samples_1m
                        (agent_id, metric, labels, bucket_ts, min_value, max_value,
                         avg_value, last_value, count, last_ts, aggregated_1h)
                     VALUES ('agent-sum', 'cpu.usage', '{}', ?1,
                             1.0, 1.0, 1.0, 1.0, 1, ?2, 0)",
                )
                .expect("准备 samples_1m 插入失败");
            for index in 0..ROWS {
                let bucket_ts =
                    BASE_TS + i64::try_from(index).expect("行号必须能放进 i64") * 60_000;
                statement
                    .execute(rusqlite::params![bucket_ts, LAST_TS])
                    .expect("插入 samples_1m 失败");
            }
        }
        tx.commit().expect("提交 samples_1m 写事务失败");
    }

    let expected = i128::from(LAST_TS) * i128::try_from(ROWS).expect("行数必须能放进 i128");
    assert!(
        expected > i128::from(i64::MAX),
        "反例总和必须超过 i64::MAX，才能覆盖旧 SUM 的溢出"
    );

    // 旧实现会在这一步 integer overflow；新检查必须不依赖 SQL SUM。
    {
        let conn = open_readonly(&path);
        assert_eq!(read_source_count(&conn, "samples_1m"), ROWS as i64);
        let legacy = conn.query_row("SELECT SUM(last_ts) FROM samples_1m", [], |row| {
            row.get::<_, i64>(0)
        });
        assert!(legacy.is_err(), "旧 SQL SUM(last_ts) 必须溢出失败");
    }

    let storage = db.open_raw_storage();
    let report = migrate_sqlite_to_postgres(&path, &storage)
        .unwrap_or_else(|e| panic!("总和超过 i64::MAX 的合法 samples_1m 迁移失败：{e:#}"));
    assert_eq!(report.samples_1m_range.id_min, Some(1));
    assert_eq!(report.samples_1m_range.id_max, Some(ROWS as i64));
    assert_eq!(
        report.samples_1m_range.ts_max,
        Some(BASE_TS + (ROWS as i64 - 1) * 60_000)
    );

    let mut client = db.client();
    assert_eq!(pg_count(&mut client, "samples_1m"), ROWS as i64);
    let target_sum: String = client
        .query_one("SELECT SUM(last_ts::NUMERIC)::TEXT FROM samples_1m", &[])
        .expect("读取目标 1m 精确总和失败")
        .get(0);
    assert_eq!(
        target_sum
            .parse::<i128>()
            .expect("目标总和必须是十进制整数"),
        expected,
        "目标 samples_1m.last_ts 精确总和与原值不一致"
    );
}

// ---------------------------------------------------------------------------
// 5. 大批量 samples：5000 行分批迁移与 rowid/setval
// ---------------------------------------------------------------------------

#[test]
fn bulk_samples_5000_rows_migrate() {
    const NAME: &str = "bulk_samples_5000_rows_migrate";
    let Some(db) = TestDatabase::create("bulk") else {
        skip(NAME);
        return;
    };
    const COUNT: usize = 5_000;
    let (_temp, path) = build_bulk_fixture("bulk", COUNT);

    let storage = db.open_raw_storage();
    let report = migrate_sqlite_to_postgres(&path, &storage)
        .unwrap_or_else(|e| panic!("5000 行迁移失败：{e:#}"));
    eprintln!(
        "[d5] 5000 行 samples 迁移耗时 {} ms，报告总行数 {}",
        report.duration_ms, report.total_rows
    );
    // 22 表总行数 = 5000 samples + 1 agents + 1 ingest_state + 1 ingest_batches。
    assert_eq!(report.total_rows, COUNT as u64 + 3);
    let samples_table = report
        .tables
        .iter()
        .find(|table| table.table == "samples")
        .expect("报告缺少 samples 表");
    assert_eq!(samples_table.rows, COUNT as u64);
    assert_eq!(report.samples_range.id_min, Some(1));
    assert_eq!(report.samples_range.id_max, Some(COUNT as i64));
    assert_eq!(report.samples_range.ts_min, Some(BASE_TS));
    assert_eq!(
        report.samples_range.ts_max,
        Some(BASE_TS + i64::try_from(COUNT).unwrap() - 1)
    );

    let mut client = db.client();
    assert_eq!(pg_count(&mut client, "samples"), COUNT as i64);
    let range_row = client
        .query_one(
            "SELECT MIN(id), MAX(id), MIN(ts), MAX(ts) FROM samples",
            &[],
        )
        .unwrap();
    let (min_id, max_id, min_ts, max_ts): (i64, i64, i64, i64) = (
        range_row.get(0),
        range_row.get(1),
        range_row.get(2),
        range_row.get(3),
    );
    assert_eq!((min_id, max_id), (1, COUNT as i64));
    assert_eq!((min_ts, max_ts), (BASE_TS, BASE_TS + COUNT as i64 - 1));

    let value: f64 = client
        .query_one("SELECT value FROM samples WHERE id = $1", &[&2_500_i64])
        .unwrap()
        .get(0);
    assert_f64_eq(value, 2_499.0 * 0.25, "中间样本值");

    let next_id: i64 = client
        .query_one(
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('bulk-probe', 'probe', '{}', $1, 1.0)
             RETURNING id",
            &[&(BASE_TS + 1_000_000)],
        )
        .unwrap()
        .get(0);
    assert_eq!(next_id, COUNT as i64 + 1);
}

// ---------------------------------------------------------------------------
// 6. 并发：两个迁移同时启动，只有一个能导入；另一个必须看到非空目标并回滚
// ---------------------------------------------------------------------------

#[test]
fn concurrent_migrations_allow_only_one_import() {
    const NAME: &str = "concurrent_migrations_allow_only_one_import";
    let Some(db) = TestDatabase::create("concurrent") else {
        skip(NAME);
        return;
    };
    const COUNT: usize = 5_000;
    let (_temp, path) = build_bulk_fixture("concurrent", COUNT);
    let source_hash_before = hash_source(&path);
    let storage = db.open_raw_storage();

    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| migrate_sqlite_to_postgres(&path, &storage));
        let second = scope.spawn(|| migrate_sqlite_to_postgres(&path, &storage));
        (first.join().unwrap(), second.join().unwrap())
    });

    let mut successes = Vec::new();
    let mut failures = Vec::new();
    for result in [first, second] {
        match result {
            Ok(report) => successes.push(report),
            Err(error) => failures.push(format!("{error:#}")),
        }
    }
    assert_eq!(
        successes.len(),
        1,
        "两个并发迁移必须恰好一个成功；failures={failures:?}"
    );
    assert_eq!(failures.len(), 1, "另一个并发迁移必须失败");
    assert!(
        failures[0].contains("非空"),
        "后到的迁移必须因目标非空被拒绝：{}",
        failures[0]
    );
    let report = &successes[0];
    assert_eq!(report.total_rows, COUNT as u64 + 3);

    let mut client = db.client();
    assert_eq!(
        pg_count(&mut client, "samples"),
        COUNT as i64,
        "并发迁移不能重复导入 samples"
    );
    assert_eq!(pg_count(&mut client, "ingest_batches"), 1);
    assert_eq!(pg_count(&mut client, "agents"), 1);
    assert_eq!(
        hash_source(&path),
        source_hash_before,
        "并发迁移修改了 SQLite 源库"
    );
}

// 让 `MigrateReport` 在测试里被使用，避免只作为返回值类型出现时误判 dead_code。
#[allow(dead_code)]
fn _assert_report_is_send_sync(report: MigrateReport) {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MigrateReport>();
    drop(report);
}
