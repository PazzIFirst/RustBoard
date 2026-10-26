//! Phase D6：PostgreSQL 告警/归档/维护域独立黑盒 parity 测试。
//!
//! 依据 `docs/plans/2026-10-26-m5-phase-d-postgres-backup-l01-l03.md`
//! §1.3 D-G2/D-G3/D-G4、§6.2 与 `Storage` trait 的公开签名编写。
//!
//! # 测试方式
//!
//! - 每个用例创建独立临时 PostgreSQL 数据库，应用 schema v7 后通过
//!   [`StorageHandle::postgres`] 装箱成 `dyn Storage`；
//! - 同一段操作再用 [`StorageHandle::sqlite_memory`] 跑一遍，逐字段比较；
//! - 所有业务调用都经过 `Storage` trait，不直接访问 PostgreSQL 业务表；
//!   只有两类例外，且都服务于“验证存储契约”：
//!   1. `information_schema` 断言 PG 的 BOOLEAN / DOUBLE PRECISION 类型；
//!   2. 故障注入用例在临时库里加 trigger 强制事务失败，验证回滚原子性。
//! - PG 同步驱动，测试是普通 `#[test]`，不创建 tokio runtime。
//!
//! # 运行
//!
//! ```bash
//! docker run -d --name rb-d3-pg -p 127.0.0.1:55435:5432 \
//!   -e POSTGRES_USER=rustboard -e POSTGRES_PASSWORD='<TEST_PASSWORD>' \
//!   -e POSTGRES_DB=rustboard postgres:16
//! export RUSTBOARD_TEST_PG='postgres://rustboard:<TEST_PASSWORD>@127.0.0.1:55435/rustboard?sslmode=disable'
//! cargo test -p rustboard-core --test postgres_parity --locked -- --nocapture
//! ```
//!
//! 未设置 `RUSTBOARD_TEST_PG`（或为空串）时，每个用例打印 `SKIP` 并返回。
//! 每个用例结束时用 `DROP DATABASE ... WITH (FORCE)` 清理临时库。因此
//! `RUSTBOARD_TEST_PG` 对应的角色需要 `CREATEDB` 权限。
//!
//! 测试 DSN 只存在于运行环境；本文件不含任何真实密码或 secret。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres::config::SslMode;
use postgres::NoTls;
use rustboard_common::model::{AgentRecord, Labels, Sample, SampleBatch, SeriesQuery, SeriesRow};
use rustboard_core::alerts::{
    builtin_rules, AlertEvent, AlertRule, AlertRuleStoreError, AlertSilence,
    AlertSilenceStoreError, AlertSource, AlertState, AlertStateKind, Comparator,
    BUILTIN_AGENT_OFFLINE, BUILTIN_DISK_PERCENT, MAX_ALERT_RULES, MAX_ALERT_SILENCES,
};
use rustboard_core::archive::{ArchiveObject, ArchiveStatus, ArchiveStoreError};
use rustboard_core::channels::{ChannelConfig, ChannelKind, NotificationChannel, Secret};
use rustboard_core::downsample::STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID;
use rustboard_core::storage::postgres::{PostgresOptions, PostgresStorage};
use rustboard_core::storage::sqlite::{
    ChannelStoreError, MAX_NOTIFICATION_CHANNELS, STATE_RAW_PRUNE_GENERATION,
};
use rustboard_core::storage::{
    ApiTokenRecord, AuditEntry, DownsampleRangeResult, IngestOutcome, MaintenanceStateEntry,
    NewAuditEntry, PruneResult, RejectReason, SampleTier, Storage, StorageHandle, TierStats,
    BUCKET_1H_MS, BUCKET_1M_MS,
};

/// 实库测试 DSN 的环境变量；未设置时全部用例 skip。
const PG_ENV: &str = "RUSTBOARD_TEST_PG";

/// 固定的逻辑“当前时间”（Unix 毫秒），避免依赖真实时钟。
const NOW: i64 = 1_700_000_000_000;

/// 每次调用返回递增序号，避免同一纳秒内两个用例撞库名。
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

fn skip(test_name: &str) {
    eprintln!("SKIP {test_name}: 未设置 {PG_ENV}（PG parity 实库测试需要 PostgreSQL）");
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
        "{PG_ENV} 必须显式 sslmode=disable（本测试只覆盖明文路径）"
    );
    Some(dsn)
}

/// 把 URL DSN 的数据库路径替换成 `db`，保留 authority/query（含密码与 sslmode）。
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

/// 一个临时测试数据库；`Drop` 时用维护库连接强制删除。
struct TestDatabase {
    name: String,
    /// 指向 `postgres` 维护库，用于 CREATE/DROP DATABASE。
    admin: postgres::Config,
    /// 指向测试库。
    app: postgres::Config,
    /// 测试库的 URL DSN（保留原密码与 sslmode=disable）。
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
        let name = format!("rb_parity_{tag}_{}_{nanos}_{seq}", std::process::id());
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
        eprintln!("[parity] 创建测试数据库 {name}（tag={tag}）");
        Some(Self {
            name,
            admin,
            app,
            app_dsn,
        })
    }

    /// 打开 `PostgresStorage` 并应用 schema v7。
    fn open_storage(&self) -> PostgresStorage {
        let storage = PostgresStorage::open(PostgresOptions {
            dsn: self.app_dsn.clone(),
            pool_size: 2,
            connect_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(30),
            sslrootcert: None,
        })
        .unwrap_or_else(|e| panic!("打开 PostgresStorage 失败：{e:#}"));
        storage
            .apply_schema()
            .unwrap_or_else(|e| panic!("apply_schema 失败（{}）：{e:#}", self.name));
        storage
    }

    /// 直连测试库（只用于类型断言与故障注入 trigger）。
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
                    "[parity] 清理失败：无法连接维护库删除 {}（请手工 DROP）：{e}",
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
                "[parity] 清理失败：DROP DATABASE {} 出错（请手工清理）：{e}",
                self.name
            );
        }
    }
}

/// 临时目录，`Drop` 时递归删除；仅故障注入用例需要文件型 SQLite。
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "rb-parity-{tag}-{}-{nanos}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("创建临时目录失败");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 一个 PG + SQLite 的 parity 固定装置。
///
/// 字段顺序就是析构顺序：存储句柄先于临时库释放，SQLite 连接先于临时目录释放。
struct ParityFixture {
    pg: StorageHandle,
    sq: StorageHandle,
    _temp: Option<TempDir>,
    sqlite_path: Option<PathBuf>,
    db: TestDatabase,
}

impl ParityFixture {
    /// 内存 SQLite + 临时 PG 数据库。
    fn new(tag: &str) -> Option<Self> {
        let db = TestDatabase::create(tag)?;
        let pg = StorageHandle::postgres(db.open_storage());
        let sq = StorageHandle::sqlite_memory().expect("打开内存 SQLite 失败");
        Some(Self {
            pg,
            sq,
            _temp: None,
            sqlite_path: None,
            db,
        })
    }

    /// 文件型 SQLite + 临时 PG 数据库；故障注入用例需要第二个 SQLite 连接加 trigger。
    fn new_file_sqlite(tag: &str) -> Option<Self> {
        let db = TestDatabase::create(tag)?;
        let pg = StorageHandle::postgres(db.open_storage());
        let temp = TempDir::new(tag);
        let path = temp.0.join("parity.db");
        let sq = StorageHandle::sqlite(&path, 2).expect("打开文件型 SQLite 失败");
        Some(Self {
            pg,
            sq,
            _temp: Some(temp),
            sqlite_path: Some(path),
            db,
        })
    }
}

/// 同一闭包跑在 PG 与 SQLite 的 `dyn Storage` 上。
fn both<T>(fixture: &ParityFixture, f: impl Fn(&dyn Storage) -> T) -> (T, T) {
    let pg = f(fixture.pg.as_storage());
    let sq = f(fixture.sq.as_storage());
    (pg, sq)
}

// ---------------------------------------------------------------------------
// 领域错误提取：类型不符直接失败，避免“任何错误都算通过”。
// ---------------------------------------------------------------------------

fn rule_store_error(err: anyhow::Error) -> AlertRuleStoreError {
    *err.downcast_ref::<AlertRuleStoreError>()
        .unwrap_or_else(|| panic!("期望 AlertRuleStoreError，实际错误：{err:#}"))
}

fn silence_store_error(err: anyhow::Error) -> AlertSilenceStoreError {
    *err.downcast_ref::<AlertSilenceStoreError>()
        .unwrap_or_else(|| panic!("期望 AlertSilenceStoreError，实际错误：{err:#}"))
}

fn channel_store_error(err: anyhow::Error) -> ChannelStoreError {
    *err.downcast_ref::<ChannelStoreError>()
        .unwrap_or_else(|| panic!("期望 ChannelStoreError，实际错误：{err:#}"))
}

fn archive_store_error(err: anyhow::Error) -> ArchiveStoreError {
    *err.downcast_ref::<ArchiveStoreError>()
        .unwrap_or_else(|| panic!("期望 ArchiveStoreError，实际错误：{err:#}"))
}

// ---------------------------------------------------------------------------
// 数据构造器
// ---------------------------------------------------------------------------

fn labels(pairs: &[(&str, &str)]) -> Labels {
    pairs
        .iter()
        .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
        .collect()
}

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
        channel_ids: vec!["chan-a".to_string()],
        notify_on_resolve: true,
        is_builtin: false,
        updated_by: "admin".to_string(),
        created_at: NOW,
        updated_at: NOW,
    }
}

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
        last_value: Some(1.5),
        last_notified_at: None,
    }
}

fn alert_event(ts: i64, rule_id: &str, rule_name: &str, state: AlertStateKind) -> AlertEvent {
    AlertEvent {
        id: 0,
        ts,
        rule_id: rule_id.to_string(),
        rule_name: rule_name.to_string(),
        agent_id: "agent-01".to_string(),
        series_key: "series-1".to_string(),
        state,
        value: Some(95.5),
        message: format!("事件 {ts}"),
        notified: false,
        notify_error: String::new(),
        silenced: false,
    }
}

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

const TELEGRAM_BOT_TOKEN: &str = "123456789:abcdefghijklmnopqrstuvwxyz";
const WECOM_WEBHOOK_KEY: &str = "wecom-webhook-key-0123456789";
const DINGTALK_ACCESS_TOKEN: &str = "dingtalk-access-token-0123456789";
const DINGTALK_SECRET: &str = "dingtalk-secret-01234567890123456789";

fn telegram_channel(id: &str, name: &str, enabled: bool) -> NotificationChannel {
    NotificationChannel {
        id: id.to_string(),
        name: name.to_string(),
        kind: ChannelKind::Telegram,
        config: ChannelConfig::Telegram {
            bot_token: Secret::new(TELEGRAM_BOT_TOKEN),
            chat_id: "-1001234567890".to_string(),
        },
        enabled,
        updated_by: "admin".to_string(),
        created_at: NOW,
        updated_at: NOW,
    }
}

fn wecom_channel(id: &str, name: &str, enabled: bool) -> NotificationChannel {
    NotificationChannel {
        id: id.to_string(),
        name: name.to_string(),
        kind: ChannelKind::Wecom,
        config: ChannelConfig::Wecom {
            webhook_key: Secret::new(WECOM_WEBHOOK_KEY),
        },
        enabled,
        updated_by: "admin".to_string(),
        created_at: NOW,
        updated_at: NOW,
    }
}

fn dingtalk_channel(id: &str, name: &str, enabled: bool) -> NotificationChannel {
    NotificationChannel {
        id: id.to_string(),
        name: name.to_string(),
        kind: ChannelKind::Dingtalk,
        config: ChannelConfig::Dingtalk {
            access_token: Secret::new(DINGTALK_ACCESS_TOKEN),
            secret: Secret::new(DINGTALK_SECRET),
        },
        enabled,
        updated_by: "admin".to_string(),
        created_at: NOW,
        updated_at: NOW,
    }
}

fn archive_object(key: &str, from_ts: i64, to_ts: i64, status: ArchiveStatus) -> ArchiveObject {
    ArchiveObject {
        id: 0,
        backend: "webdav".to_string(),
        object_key: key.to_string(),
        manifest_key: format!("{}.manifest.json", key.trim_end_matches(".csv.gz")),
        from_ts,
        to_ts,
        rows: 5_000_000_000,
        bytes: 6_000_000_000,
        sha256: "a".repeat(64),
        status,
        error: String::new(),
        created_at: 1_000,
        uploaded_at: None,
        deleted_at: None,
        ledger_version: 0,
        attempts: 0,
    }
}

fn new_audit(ts: i64, agent_id: &str, capability: &str) -> NewAuditEntry {
    NewAuditEntry {
        ts,
        actor: "admin".to_string(),
        agent_id: agent_id.to_string(),
        capability: capability.to_string(),
        action: "restart".to_string(),
        target: "nginx.service".to_string(),
        params: r#"{"name":"nginx","signal":"TERM"}"#.to_string(),
        result: "ok".to_string(),
        error_code: String::new(),
        error_message: String::new(),
        duration_ms: 12,
    }
}

fn sample_batch(agent_id: &str, epoch: u64, seq: u64, samples: Vec<Sample>) -> SampleBatch {
    SampleBatch {
        agent_id: agent_id.to_string(),
        epoch,
        seq,
        boot_id: "boot-parity".to_string(),
        sent_at: NOW,
        samples,
    }
}

fn series_query(agent_id: &str, metrics: &[&str], from: i64, to: i64, limit: u32) -> SeriesQuery {
    SeriesQuery {
        agent_id: agent_id.to_string(),
        metrics: metrics.iter().map(|metric| (*metric).to_string()).collect(),
        from,
        to,
        limit,
    }
}

fn agent_record(agent_id: &str, status: &str, ts: i64) -> AgentRecord {
    AgentRecord {
        agent_id: agent_id.to_string(),
        name: format!("Node {agent_id}"),
        hostname: format!("host-{agent_id}"),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        version: "1.0.0".to_string(),
        boot_id: "boot-1".to_string(),
        status: status.to_string(),
        last_seen_at: ts,
        created_at: 50,
    }
}

// ---------------------------------------------------------------------------
// 浮点 / 行比较
// ---------------------------------------------------------------------------

fn assert_f64_close(pg: f64, sq: f64, context: &str) {
    let tolerance = 1e-9 * pg.abs().max(sq.abs()).max(1.0);
    assert!(
        (pg - sq).abs() <= tolerance,
        "{context}: PG={pg} SQLite={sq}（容差 {tolerance}）"
    );
}

fn assert_series_eq(context: &str, pg: &[SeriesRow], sq: &[SeriesRow]) {
    assert_eq!(pg.len(), sq.len(), "{context}: 行数不一致");
    for (index, (pg_row, sq_row)) in pg.iter().zip(sq).enumerate() {
        assert_eq!(
            pg_row.metric, sq_row.metric,
            "{context}: 第 {index} 行 metric"
        );
        assert_eq!(
            pg_row.labels, sq_row.labels,
            "{context}: 第 {index} 行 labels"
        );
        assert_eq!(pg_row.ts, sq_row.ts, "{context}: 第 {index} 行 ts");
        assert_f64_close(
            pg_row.value,
            sq_row.value,
            &format!("{context}: 第 {index} 行 value"),
        );
    }
}

fn assert_agent_series_eq(
    context: &str,
    pg: &[rustboard_core::storage::AgentSeriesRow],
    sq: &[rustboard_core::storage::AgentSeriesRow],
) {
    assert_eq!(pg.len(), sq.len(), "{context}: 行数不一致");
    for (index, (pg_row, sq_row)) in pg.iter().zip(sq).enumerate() {
        assert_eq!(
            pg_row.agent_id, sq_row.agent_id,
            "{context}: 第 {index} 行 agent_id"
        );
        assert_eq!(
            pg_row.metric, sq_row.metric,
            "{context}: 第 {index} 行 metric"
        );
        assert_eq!(
            pg_row.labels, sq_row.labels,
            "{context}: 第 {index} 行 labels"
        );
        assert_eq!(pg_row.ts, sq_row.ts, "{context}: 第 {index} 行 ts");
        assert_f64_close(
            pg_row.value,
            sq_row.value,
            &format!("{context}: 第 {index} 行 value"),
        );
    }
}

fn assert_stats_eq(context: &str, pg: &TierStats, sq: &TierStats) {
    assert_eq!(pg, sq, "{context}: TierStats 不一致");
}

fn event_by_message<'a>(events: &'a [AlertEvent], message: &str) -> &'a AlertEvent {
    events
        .iter()
        .find(|event| event.message == message)
        .unwrap_or_else(|| panic!("找不到事件 {message}"))
}

fn strip_event_ids(events: &[AlertEvent]) -> Vec<AlertEvent> {
    events
        .iter()
        .cloned()
        .map(|mut event| {
            event.id = 0;
            event
        })
        .collect()
}

fn strip_archive_ids(objects: &[ArchiveObject]) -> Vec<ArchiveObject> {
    objects
        .iter()
        .cloned()
        .map(|mut object| {
            object.id = 0;
            object
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 1. 空库：所有列表 / 统计 / 计数必须返回稳定默认值
// ---------------------------------------------------------------------------

#[test]
fn empty_database_defaults_match() {
    const NAME: &str = "empty_database_defaults_match";
    let Some(fx) = ParityFixture::new("empty") else {
        skip(NAME);
        return;
    };

    let (pg_basic, sq_basic) = both(&fx, |s| {
        (
            s.list_agents().unwrap(),
            s.list_sample_intervals().unwrap(),
            s.sample_count("missing").unwrap(),
            s.list_audit(10, None, None, None).unwrap(),
            s.list_maintenance_state().unwrap(),
            s.reset_online_status().unwrap(),
        )
    });
    assert_eq!(pg_basic, sq_basic, "空库基础查询必须一致");
    assert!(pg_basic.0.is_empty(), "空库不得有 agent");
    assert!(pg_basic.1.is_empty(), "空库不得有采样间隔");
    assert_eq!(pg_basic.2, 0, "空库 sample_count 必须为 0");
    let empty_audit: Vec<AuditEntry> = pg_basic.3;
    let empty_maintenance: Vec<MaintenanceStateEntry> = pg_basic.4;
    assert!(empty_audit.is_empty(), "空库不得有审计记录");
    assert!(empty_maintenance.is_empty(), "空库不得有维护水位");
    assert_eq!(pg_basic.5, 0, "空库 reset_online_status 必须为 0");

    let (pg_rules, sq_rules) = both(&fx, |s| {
        (
            s.alert_rule_count().unwrap(),
            s.list_alert_rules().unwrap(),
            s.list_enabled_alert_rules().unwrap(),
            s.list_alert_states().unwrap(),
            s.list_alert_states_for_rule("missing", 10).unwrap(),
        )
    });
    assert_eq!(pg_rules, sq_rules, "空库规则/状态查询必须一致");
    assert_eq!(pg_rules.0, 0);
    assert!(pg_rules.1.is_empty());
    assert!(pg_rules.2.is_empty());
    assert!(pg_rules.3.is_empty());
    assert!(pg_rules.4.is_empty());

    let (pg_events, sq_events) = both(&fx, |s| {
        (
            s.list_alert_events(10, None).unwrap(),
            s.list_alert_events(10, Some(0)).unwrap(),
            s.max_alert_event_id().unwrap(),
            s.list_pending_notification_events(10).unwrap(),
            s.list_pending_notification_events_after(0, 10).unwrap(),
        )
    });
    assert_eq!(pg_events, sq_events, "空库事件查询必须一致");
    assert!(pg_events.0.is_empty());
    assert!(pg_events.1.is_empty());
    assert_eq!(pg_events.2, 0, "空库 max_alert_event_id 必须为 0");
    assert!(pg_events.3.is_empty());
    assert!(pg_events.4.is_empty());

    let (pg_channels, sq_channels) = both(&fx, |s| {
        (
            s.list_notification_channels().unwrap(),
            s.notification_channel_count().unwrap(),
            s.get_notification_channel("missing").unwrap(),
            s.list_api_tokens().unwrap(),
        )
    });
    assert_eq!(pg_channels, sq_channels, "空库渠道/token 查询必须一致");
    assert!(pg_channels.0.is_empty());
    assert_eq!(pg_channels.1, 0);
    assert_eq!(pg_channels.2, None);
    let empty_tokens: Vec<ApiTokenRecord> = pg_channels.3;
    assert!(empty_tokens.is_empty());

    let (pg_tiers, sq_tiers) = both(&fx, |s| {
        (
            s.raw_stats().unwrap(),
            s.samples_1m_stats().unwrap(),
            s.samples_1h_stats().unwrap(),
            s.raw_new_rows(None).unwrap(),
            s.samples_1m_oldest_ts().unwrap(),
            s.raw_ts_at_offset(0, i64::MAX, 0).unwrap(),
            s.samples_1m_ts_at_offset(0, i64::MAX, 0).unwrap(),
        )
    });
    assert_eq!(pg_tiers, sq_tiers, "空库分层统计必须一致");
    for (index, stats) in [pg_tiers.0, pg_tiers.1, pg_tiers.2].iter().enumerate() {
        assert_eq!(stats.rows, 0, "第 {index} 层空库行数必须为 0");
        assert_eq!(stats.oldest_ts, None);
        assert_eq!(stats.newest_ts, None);
    }
    assert_eq!(pg_tiers.3, (None, None));
    assert_eq!(pg_tiers.4, None);
    assert_eq!(pg_tiers.5, None);
    assert_eq!(pg_tiers.6, None);

    let (pg_archive, sq_archive) = both(&fx, |s| {
        (
            s.count_archive_objects().unwrap(),
            s.list_archive_objects(10, None).unwrap(),
            s.list_archive_objects_in_range(0, i64::MAX).unwrap(),
            s.get_archive_state("missing").unwrap(),
            s.scan_archive_rows(0, i64::MAX, None, 10).unwrap(),
        )
    });
    assert_eq!(pg_archive, sq_archive, "空库归档查询必须一致");
    assert_eq!(pg_archive.0, 0);
    assert!(pg_archive.1.is_empty());
    assert!(pg_archive.2.is_empty());
    assert_eq!(pg_archive.3, None);
    assert!(pg_archive.4.is_empty());

    let (pg_series, sq_series) = both(&fx, |s| {
        s.query_series(&series_query("missing", &[], 0, i64::MAX, 10))
            .unwrap()
    });
    assert_series_eq("空库 query_series", &pg_series, &sq_series);
    assert!(pg_series.is_empty(), "空库 query_series 必须为空");
}

// ---------------------------------------------------------------------------
// 2. 告警规则：种子幂等 / CRUD / 内置保护 / 启用列表
// ---------------------------------------------------------------------------

#[test]
fn alert_rules_seed_crud_and_enabled_parity() {
    const NAME: &str = "alert_rules_seed_crud_and_enabled_parity";
    let Some(fx) = ParityFixture::new("rules") else {
        skip(NAME);
        return;
    };

    // 空库初始态与不存在规则的读取 / 删除。
    let (pg_empty, sq_empty) = both(&fx, |s| {
        (
            s.alert_rule_count().unwrap(),
            s.list_alert_rules().unwrap(),
            s.list_enabled_alert_rules().unwrap(),
            s.get_alert_rule("missing").unwrap(),
            rule_store_error(s.delete_alert_rule("missing").unwrap_err()),
        )
    });
    assert_eq!(pg_empty, sq_empty, "空库规则查询必须一致");
    assert_eq!(pg_empty.0, 0);
    assert!(pg_empty.1.is_empty());
    assert!(pg_empty.2.is_empty());
    assert_eq!(pg_empty.3, None);
    assert_eq!(pg_empty.4, AlertRuleStoreError::NotFound);

    // 首次种子插入 5 条；重复种子插入 0 条且逐字段不变。
    let (pg_seed, sq_seed) = both(&fx, |s| {
        let first = s
            .seed_builtin_alert_rules(&builtin_rules(NOW, 90, 48), NOW)
            .unwrap();
        let first_list = s.list_alert_rules().unwrap();
        let second = s
            .seed_builtin_alert_rules(&builtin_rules(NOW + 60_000, 90, 48), NOW + 60_000)
            .unwrap();
        let second_list = s.list_alert_rules().unwrap();
        (first, first_list, second, second_list)
    });
    assert_eq!(pg_seed, sq_seed, "内置规则种子结果必须一致");
    assert_eq!(pg_seed.0, 5, "首次种子必须插入 5 条");
    assert_eq!(pg_seed.2, 0, "重复种子必须插入 0 条");
    assert_eq!(pg_seed.1, pg_seed.3, "重复种子不得刷新任何字段");
    assert_eq!(pg_seed.1.len(), 5);
    assert!(pg_seed.1.iter().all(|rule| rule.is_builtin));
    assert!(
        pg_seed.1.iter().all(|rule| !rule.enabled),
        "内置规则初始必须全部禁用"
    );

    // 用户修改内置规则后再次种子：改动必须保留。
    let (pg_edited, sq_edited) = both(&fx, |s| {
        let mut rule = s.get_alert_rule(BUILTIN_DISK_PERCENT).unwrap().unwrap();
        rule.enabled = true;
        rule.threshold = 97.5;
        rule.duration_secs = 42;
        rule.updated_by = "ops".to_string();
        rule.updated_at = NOW + 120_000;
        s.update_alert_rule(&rule).unwrap();
        s.seed_builtin_alert_rules(&builtin_rules(NOW + 240_000, 90, 48), NOW + 240_000)
            .unwrap();
        s.get_alert_rule(BUILTIN_DISK_PERCENT).unwrap().unwrap()
    });
    assert_eq!(pg_edited, sq_edited, "内置规则用户改动后的读取必须一致");
    assert!(pg_edited.enabled);
    assert_eq!(pg_edited.threshold, 97.5);
    assert_eq!(pg_edited.duration_secs, 42);
    assert_eq!(pg_edited.updated_at, NOW + 120_000);
    assert_eq!(pg_edited.created_at, NOW, "种子不得重置 created_at");

    // 创建自定义规则：逐字段往返，包含 labels / channel_ids / filter。
    let rule = custom_rule("custom-1", "生产 CPU 告警");
    let (pg_created, sq_created) = both(&fx, |s| {
        s.create_alert_rule(&rule).unwrap();
        (
            s.get_alert_rule("custom-1").unwrap(),
            s.alert_rule_count().unwrap(),
            s.list_alert_rules().unwrap(),
        )
    });
    assert_eq!(pg_created, sq_created, "创建自定义规则后查询必须一致");
    assert_eq!(pg_created.0, Some(rule.clone()));
    assert_eq!(pg_created.1, 6);
    assert_eq!(pg_created.2.len(), 6);
    assert!(pg_created.2[0].is_builtin, "列表必须内置在前");

    // 重名创建：NameExists 且不写入。
    let (pg_conflict, sq_conflict) = both(&fx, |s| {
        let err = rule_store_error(
            s.create_alert_rule(&custom_rule("custom-2", "生产 CPU 告警"))
                .unwrap_err(),
        );
        (
            err,
            s.get_alert_rule("custom-2").unwrap(),
            s.alert_rule_count().unwrap(),
        )
    });
    assert_eq!(pg_conflict, sq_conflict, "重名创建结果必须一致");
    assert_eq!(pg_conflict.0, AlertRuleStoreError::NameExists);
    assert_eq!(pg_conflict.1, None, "失败的重名创建不得写入");
    assert_eq!(pg_conflict.2, 6);

    // 更新不存在的规则：NotFound。
    let (pg_missing, sq_missing) = both(&fx, |s| {
        rule_store_error(
            s.update_alert_rule(&custom_rule("missing", "不存在"))
                .unwrap_err(),
        )
    });
    assert_eq!(pg_missing, sq_missing);
    assert_eq!(pg_missing, AlertRuleStoreError::NotFound);

    // 更新：可写字段生效，is_builtin / created_at 不得被上层伪造。
    let (pg_updated, sq_updated) = both(&fx, |s| {
        let mut updated = s.get_alert_rule("custom-1").unwrap().unwrap();
        updated.name = "生产 CPU 告警（更新）".to_string();
        updated.enabled = false;
        updated.threshold = 95.5;
        updated.duration_secs = 120;
        updated.filter_agent_id = None;
        updated.filter_labels = labels(&[("env", "staging"), ("role", "db")]);
        updated.channel_ids = vec!["chan-z".to_string()];
        updated.notify_on_resolve = false;
        updated.updated_by = "ops".to_string();
        updated.updated_at = NOW + 100_000;
        updated.is_builtin = true; // 上层伪造，必须被忽略
        updated.created_at = 999; // 上层伪造，必须被忽略
        s.update_alert_rule(&updated).unwrap();
        s.get_alert_rule("custom-1").unwrap().unwrap()
    });
    assert_eq!(pg_updated, sq_updated, "更新后规则必须逐字段一致");
    assert_eq!(pg_updated.name, "生产 CPU 告警（更新）");
    assert!(!pg_updated.enabled);
    assert_eq!(pg_updated.threshold, 95.5);
    assert_eq!(pg_updated.duration_secs, 120);
    assert_eq!(pg_updated.filter_agent_id, None);
    assert_eq!(
        pg_updated.filter_labels,
        labels(&[("env", "staging"), ("role", "db")])
    );
    assert_eq!(pg_updated.channel_ids, vec!["chan-z".to_string()]);
    assert!(!pg_updated.notify_on_resolve);
    assert!(!pg_updated.is_builtin, "存储层必须忽略伪造的 is_builtin");
    assert_eq!(pg_updated.created_at, rule.created_at);

    // 更新到与其它规则重名：NameExists，原规则不变。
    let (pg_rename, sq_rename) = both(&fx, |s| {
        s.create_alert_rule(&custom_rule("custom-3", "另一条规则"))
            .unwrap();
        let mut conflicting = s.get_alert_rule("custom-1").unwrap().unwrap();
        conflicting.name = "另一条规则".to_string();
        let err = rule_store_error(s.update_alert_rule(&conflicting).unwrap_err());
        (err, s.get_alert_rule("custom-1").unwrap().unwrap().name)
    });
    assert_eq!(pg_rename, sq_rename, "改名冲突结果必须一致");
    assert_eq!(pg_rename.0, AlertRuleStoreError::NameExists);
    assert_eq!(pg_rename.1, "生产 CPU 告警（更新）");

    // 启用列表：内置磁盘规则 enabled + 两条自定义 enabled。
    let (pg_enabled, sq_enabled) = both(&fx, |s| s.list_enabled_alert_rules().unwrap());
    assert_eq!(pg_enabled, sq_enabled, "启用列表必须一致");
    let enabled_ids: Vec<&str> = pg_enabled.iter().map(|rule| rule.id.as_str()).collect();
    assert_eq!(
        enabled_ids.len(),
        2,
        "custom-1 已关闭，应只剩磁盘内置规则与 custom-3"
    );
    assert!(enabled_ids.contains(&BUILTIN_DISK_PERCENT));
    assert!(enabled_ids.contains(&"custom-3"));
    assert!(
        !enabled_ids.contains(&"custom-1"),
        "关闭后的自定义规则不得出现在启用列表"
    );
    assert!(pg_enabled[0].is_builtin, "启用列表同样必须内置在前");

    // 内置规则禁止删除；自定义规则可删除。
    let (pg_delete, sq_delete) = both(&fx, |s| {
        let builtin_err = rule_store_error(s.delete_alert_rule(BUILTIN_AGENT_OFFLINE).unwrap_err());
        let builtin_still_there = s.get_alert_rule(BUILTIN_AGENT_OFFLINE).unwrap().is_some();
        s.delete_alert_rule("custom-1").unwrap();
        let after = s.get_alert_rule("custom-1").unwrap();
        let missing_err = rule_store_error(s.delete_alert_rule("custom-1").unwrap_err());
        (
            builtin_err,
            builtin_still_there,
            after,
            missing_err,
            s.alert_rule_count().unwrap(),
        )
    });
    assert_eq!(pg_delete, sq_delete, "删除规则结果必须一致");
    assert_eq!(pg_delete.0, AlertRuleStoreError::BuiltinRule);
    assert!(pg_delete.1, "内置规则不得被删除");
    assert_eq!(pg_delete.2, None, "删除后不得再读到自定义规则");
    assert_eq!(pg_delete.3, AlertRuleStoreError::NotFound);
    assert_eq!(pg_delete.4, 6, "5 条内置 + custom-3");
}

// ---------------------------------------------------------------------------
// 3. 规则状态清理：update/delete 的 clear_states 变体
// ---------------------------------------------------------------------------

#[test]
fn alert_rule_state_cleanup_parity() {
    const NAME: &str = "alert_rule_state_cleanup_parity";
    let Some(fx) = ParityFixture::new("rule_clean") else {
        skip(NAME);
        return;
    };

    let rule_a = custom_rule("rule-a", "规则 A");
    let rule_b = custom_rule("rule-b", "规则 B");
    let state_a1 = alert_state(
        "rule-a",
        "agent-1",
        "s1",
        AlertStateKind::Firing,
        NOW - 20,
        NOW,
    );
    let state_a2 = alert_state(
        "rule-a",
        "agent-1",
        "s2",
        AlertStateKind::Pending,
        NOW - 10,
        NOW,
    );
    let state_b1 = alert_state(
        "rule-b",
        "agent-2",
        "",
        AlertStateKind::Resolved,
        NOW - 30,
        NOW,
    );

    // update_and_clear_states：更新规则 A 并清空 A 的状态，B 的状态保留。
    let (pg_update, sq_update) = both(&fx, |s| {
        s.create_alert_rule(&rule_a).unwrap();
        s.create_alert_rule(&rule_b).unwrap();
        s.upsert_alert_state(&state_a1).unwrap();
        s.upsert_alert_state(&state_a2).unwrap();
        s.upsert_alert_state(&state_b1).unwrap();
        let mut updated = s.get_alert_rule("rule-a").unwrap().unwrap();
        updated.name = "规则 A（更新）".to_string();
        updated.updated_at = NOW + 10;
        s.update_alert_rule_and_clear_states(&updated).unwrap();
        (
            s.list_alert_states().unwrap(),
            s.get_alert_state("rule-a", "agent-1", "s1").unwrap(),
            s.get_alert_state("rule-b", "agent-2", "").unwrap(),
            s.get_alert_rule("rule-a").unwrap().unwrap().name,
        )
    });
    assert_eq!(pg_update, sq_update, "update_and_clear_states 结果必须一致");
    assert_eq!(pg_update.0, vec![state_b1.clone()], "只应保留规则 B 的状态");
    assert_eq!(pg_update.1, None);
    assert_eq!(pg_update.2, Some(state_b1.clone()));
    assert_eq!(pg_update.3, "规则 A（更新）");

    // delete_alert_rule 不清状态；delete_alert_rule_and_clear_states 才清。
    let (pg_delete, sq_delete) = both(&fx, |s| {
        s.upsert_alert_state(&state_a1).unwrap();
        s.delete_alert_rule("rule-b").unwrap();
        let after_plain_delete = s.get_alert_state("rule-b", "agent-2", "").unwrap();
        s.delete_alert_rule_and_clear_states("rule-a").unwrap();
        (
            after_plain_delete,
            s.get_alert_state("rule-a", "agent-1", "s1").unwrap(),
            s.get_alert_state("rule-b", "agent-2", "").unwrap(),
            s.alert_rule_count().unwrap(),
        )
    });
    assert_eq!(pg_delete, sq_delete, "delete 变体结果必须一致");
    assert_eq!(
        pg_delete.0,
        Some(state_b1.clone()),
        "delete_alert_rule 不得隐式清理状态"
    );
    assert_eq!(pg_delete.1, None, "clear 变体必须清掉规则 A 的状态");
    assert_eq!(pg_delete.2, Some(state_b1), "其它规则状态不得被误删");
    assert_eq!(pg_delete.3, 0);

    // 内置规则：clear 变体同样返回 BuiltinRule，且不得清状态。
    let (pg_builtin, sq_builtin) = both(&fx, |s| {
        s.seed_builtin_alert_rules(&builtin_rules(NOW, 90, 48), NOW)
            .unwrap();
        let builtin_state = alert_state(
            BUILTIN_AGENT_OFFLINE,
            "agent-1",
            "",
            AlertStateKind::Firing,
            NOW - 5,
            NOW,
        );
        s.upsert_alert_state(&builtin_state).unwrap();
        let err = rule_store_error(
            s.delete_alert_rule_and_clear_states(BUILTIN_AGENT_OFFLINE)
                .unwrap_err(),
        );
        (
            err,
            s.get_alert_state(BUILTIN_AGENT_OFFLINE, "agent-1", "")
                .unwrap(),
            s.get_alert_rule(BUILTIN_AGENT_OFFLINE).unwrap().is_some(),
        )
    });
    assert_eq!(pg_builtin, sq_builtin, "内置规则 clear 变体结果必须一致");
    assert_eq!(pg_builtin.0, AlertRuleStoreError::BuiltinRule);
    assert!(pg_builtin.1.is_some(), "删除内置规则失败后状态不得被清空");
    assert!(pg_builtin.2);

    // 不存在的规则：两个 clear 变体都返回 NotFound。
    let (pg_missing, sq_missing) = both(&fx, |s| {
        let update_err = rule_store_error(
            s.update_alert_rule_and_clear_states(&custom_rule("missing", "不存在"))
                .unwrap_err(),
        );
        let delete_err =
            rule_store_error(s.delete_alert_rule_and_clear_states("missing").unwrap_err());
        (update_err, delete_err)
    });
    assert_eq!(pg_missing, sq_missing);
    assert_eq!(pg_missing.0, AlertRuleStoreError::NotFound);
    assert_eq!(pg_missing.1, AlertRuleStoreError::NotFound);
}

// ---------------------------------------------------------------------------
// 4. 规则数量上限：第 201 条返回 LimitReached 且不写入
// ---------------------------------------------------------------------------

#[test]
fn alert_rule_limit_parity() {
    const NAME: &str = "alert_rule_limit_parity";
    let Some(fx) = ParityFixture::new("rule_limit") else {
        skip(NAME);
        return;
    };
    assert_eq!(MAX_ALERT_RULES, 200, "规则总数上限必须是 200");

    let (pg, sq) = both(&fx, |s| {
        s.seed_builtin_alert_rules(&builtin_rules(NOW, 90, 48), NOW)
            .unwrap();
        for index in 0..(MAX_ALERT_RULES - 5) {
            let rule = custom_rule(
                &format!("limit-{index:03}"),
                &format!("上限规则 {index:03}"),
            );
            s.create_alert_rule(&rule).unwrap();
        }
        let count = s.alert_rule_count().unwrap();
        let err = rule_store_error(
            s.create_alert_rule(&custom_rule("limit-overflow", "第 201 条规则"))
                .unwrap_err(),
        );
        (
            count,
            err,
            s.get_alert_rule("limit-overflow").unwrap(),
            s.alert_rule_count().unwrap(),
            s.list_alert_rules().unwrap().len(),
        )
    });
    assert_eq!(pg, sq, "规则上限行为必须一致");
    assert_eq!(pg.0, MAX_ALERT_RULES);
    assert_eq!(pg.1, AlertRuleStoreError::LimitReached);
    assert_eq!(pg.2, None, "超限失败不得写入");
    assert_eq!(pg.3, MAX_ALERT_RULES, "超限失败后总数不得变化");
    assert_eq!(pg.4, MAX_ALERT_RULES);
}

// ---------------------------------------------------------------------------
// 5. 告警状态：upsert / 排序 / get/delete / resolved & stale 清理 / 每规则上限
// ---------------------------------------------------------------------------

#[test]
fn alert_states_roundtrip_prune_and_cap_parity() {
    const NAME: &str = "alert_states_roundtrip_prune_and_cap_parity";
    let Some(fx) = ParityFixture::new("states") else {
        skip(NAME);
        return;
    };

    let mut global = alert_state(
        "rule-global",
        "",
        "",
        AlertStateKind::Resolved,
        NOW - 500,
        NOW - 400,
    );
    global.last_value = None;
    global.last_notified_at = Some(NOW - 300);
    let mut a1 = alert_state(
        "rule-a",
        "agent-1",
        "series-1",
        AlertStateKind::Firing,
        NOW - 200,
        NOW,
    );
    a1.last_value = Some(95.5);
    a1.last_notified_at = Some(NOW - 100);
    let mut a2 = alert_state(
        "rule-a",
        "agent-1",
        "series-2",
        AlertStateKind::Pending,
        NOW - 300,
        NOW - 100,
    );
    a2.last_value = None;
    let a3 = alert_state(
        "rule-a",
        "agent-2",
        "",
        AlertStateKind::Firing,
        NOW - 150,
        NOW - 50,
    );
    let b1 = alert_state(
        "rule-b",
        "agent-1",
        "series-Z",
        AlertStateKind::Resolved,
        NOW - 250,
        NOW - 150,
    );

    // 乱序写入；列表按 (rule_id, agent_id, series_key) 稳定排序。
    let (pg_list, sq_list) = both(&fx, |s| {
        for state in [&global, &b1, &a2, &a1, &a3] {
            s.upsert_alert_state(state).unwrap();
        }
        (
            s.list_alert_states().unwrap(),
            s.get_alert_state("rule-a", "agent-1", "series-1").unwrap(),
            s.list_alert_states_for_rule("rule-a", 10).unwrap(),
            s.list_alert_states_for_rule("rule-a", 0).unwrap(),
            s.get_alert_state("missing", "", "").unwrap(),
        )
    });
    assert_eq!(pg_list, sq_list, "告警状态查询必须一致");
    assert_eq!(
        pg_list.0,
        vec![
            a1.clone(),
            a2.clone(),
            a3.clone(),
            b1.clone(),
            global.clone()
        ],
        "状态必须按主键稳定排序"
    );
    assert_eq!(pg_list.1, Some(a1.clone()));
    assert_eq!(
        pg_list
            .2
            .iter()
            .map(|state| state.series_key.as_str())
            .collect::<Vec<_>>(),
        vec!["series-1", "", "series-2"],
        "按规则读取必须按 last_eval_at 倒序"
    );
    assert!(pg_list.3.is_empty(), "limit=0 必须返回空列表");
    assert_eq!(pg_list.4, None);

    // 同主键 upsert：整行覆盖，不新增行。
    let mut updated = a1.clone();
    updated.state = AlertStateKind::Resolved;
    updated.since = NOW + 1;
    updated.last_eval_at = NOW + 2;
    updated.last_value = None;
    updated.last_notified_at = Some(NOW + 3);
    let (pg_upsert, sq_upsert) = both(&fx, |s| {
        s.upsert_alert_state(&updated).unwrap();
        (
            s.list_alert_states().unwrap().len(),
            s.get_alert_state("rule-a", "agent-1", "series-1").unwrap(),
        )
    });
    assert_eq!(pg_upsert, sq_upsert);
    assert_eq!(pg_upsert.0, 5, "同主键 upsert 不得新增行");
    assert_eq!(pg_upsert.1, Some(updated.clone()));

    // delete 返回受影响行数。
    let (pg_delete, sq_delete) = both(&fx, |s| {
        let first = s.delete_alert_state("rule-a", "agent-2", "").unwrap();
        let second = s.delete_alert_state("rule-a", "agent-2", "").unwrap();
        (first, second, s.list_alert_states().unwrap().len())
    });
    assert_eq!(pg_delete, sq_delete);
    assert_eq!(pg_delete, (1, 0, 4));

    // 特殊 series_key（引号 / 反斜杠 / 换行 / 中文）与空 agent_id 必须原样往返。
    let special = alert_state(
        "rule-special",
        "",
        "series-'quote'-\\-\n-中文",
        AlertStateKind::Pending,
        NOW - 1,
        NOW,
    );
    let (pg_special, sq_special) = both(&fx, |s| {
        s.upsert_alert_state(&special).unwrap();
        let fetched = s
            .get_alert_state("rule-special", "", &special.series_key)
            .unwrap();
        s.delete_alert_state("rule-special", "", &special.series_key)
            .unwrap();
        (
            fetched,
            s.get_alert_state("rule-special", "", &special.series_key)
                .unwrap(),
        )
    });
    assert_eq!(pg_special, sq_special);
    assert_eq!(pg_special.0, Some(special.clone()));
    assert_eq!(pg_special.1, None);

    // 清空状态，进入 resolved 清理场景。
    let (pg_clear, sq_clear) = both(&fx, |s| {
        for state in s.list_alert_states().unwrap() {
            s.delete_alert_state(&state.rule_id, &state.agent_id, &state.series_key)
                .unwrap();
        }
        s.list_alert_states().unwrap()
    });
    assert_eq!(pg_clear, sq_clear);
    assert!(pg_clear.is_empty());

    // resolved 清理：只删 state=resolved 且 last_eval_at 严格早于 cutoff 的行。
    let cutoff = NOW - 1_000;
    let old_resolved = alert_state(
        "prune-old-resolved",
        "agent-1",
        "s",
        AlertStateKind::Resolved,
        cutoff - 500,
        cutoff - 1,
    );
    let boundary_resolved = alert_state(
        "prune-boundary-resolved",
        "agent-1",
        "s",
        AlertStateKind::Resolved,
        cutoff - 500,
        cutoff,
    );
    let fresh_resolved = alert_state(
        "prune-fresh-resolved",
        "agent-1",
        "s",
        AlertStateKind::Resolved,
        cutoff + 1,
        cutoff + 1,
    );
    let old_firing = alert_state(
        "prune-old-firing",
        "agent-1",
        "s",
        AlertStateKind::Firing,
        cutoff - 10_000,
        cutoff - 10_000,
    );
    let (pg_prune, sq_prune) = both(&fx, |s| {
        for state in [
            &old_resolved,
            &boundary_resolved,
            &fresh_resolved,
            &old_firing,
        ] {
            s.upsert_alert_state(state).unwrap();
        }
        let first = s.prune_alert_states(cutoff).unwrap();
        let second = s.prune_alert_states(cutoff).unwrap();
        let all_resolved = s.prune_alert_states(i64::MAX).unwrap();
        (first, second, all_resolved, s.list_alert_states().unwrap())
    });
    assert_eq!(pg_prune, sq_prune, "resolved 清理必须一致");
    assert_eq!(pg_prune.0, 1, "只应删除 last_eval_at < cutoff 的 resolved");
    assert_eq!(pg_prune.1, 0, "重复清理必须幂等");
    assert_eq!(pg_prune.2, 2, "i64::MAX 应清掉剩余 2 条 resolved");
    assert_eq!(pg_prune.3, vec![old_firing], "firing 状态不得被清理");

    // 清空状态，进入 stale 清理场景。
    let (pg_clear, sq_clear) = both(&fx, |s| {
        for state in s.list_alert_states().unwrap() {
            s.delete_alert_state(&state.rule_id, &state.agent_id, &state.series_key)
                .unwrap();
        }
        s.list_alert_states().unwrap()
    });
    assert_eq!(pg_clear, sq_clear);
    assert!(pg_clear.is_empty());

    // stale 清理：只删 pending/firing 且 last_eval_at < stale_before，按 max_rows 分批。
    let stale_firing_old = alert_state("stale", "a", "s1", AlertStateKind::Firing, NOW - 10, 1_000);
    let stale_pending_old =
        alert_state("stale", "a", "s2", AlertStateKind::Pending, NOW - 10, 2_000);
    let stale_pending_new =
        alert_state("stale", "a", "s3", AlertStateKind::Pending, NOW - 10, 3_600);
    let stale_resolved_old = alert_state(
        "stale",
        "a",
        "s4",
        AlertStateKind::Resolved,
        NOW - 10,
        1_000,
    );
    let stale_firing_new = alert_state("stale", "a", "s5", AlertStateKind::Firing, NOW - 10, 4_000);
    let (pg_stale, sq_stale) = both(&fx, |s| {
        for state in [
            &stale_firing_old,
            &stale_pending_old,
            &stale_pending_new,
            &stale_resolved_old,
            &stale_firing_new,
        ] {
            s.upsert_alert_state(state).unwrap();
        }
        let zero = s.prune_stale_alert_states(3_500, 0).unwrap();
        let first = s.prune_stale_alert_states(3_500, 1).unwrap();
        let second = s.prune_stale_alert_states(3_500, 1).unwrap();
        let third = s.prune_stale_alert_states(3_500, 1).unwrap();
        let fourth = s.prune_stale_alert_states(3_500, 1).unwrap();
        (
            zero,
            first,
            second,
            third,
            fourth,
            s.list_alert_states().unwrap(),
        )
    });
    assert_eq!(pg_stale, sq_stale, "stale 清理必须一致");
    assert_eq!(
        (pg_stale.0, pg_stale.1, pg_stale.2, pg_stale.3, pg_stale.4),
        (0, 1, 1, 0, 0),
        "max_rows=0 不得删除；之后每次最多删 1 条陈旧状态"
    );
    assert_eq!(
        pg_stale
            .5
            .iter()
            .map(|state| state.series_key.as_str())
            .collect::<Vec<_>>(),
        vec!["s3", "s4", "s5"],
        "resolved 与未陈旧状态必须保留"
    );

    // 清空状态，进入每规则状态上限场景。
    let (pg_clear, sq_clear) = both(&fx, |s| {
        for state in s.list_alert_states().unwrap() {
            s.delete_alert_state(&state.rule_id, &state.agent_id, &state.series_key)
                .unwrap();
        }
        s.list_alert_states().unwrap()
    });
    assert_eq!(pg_clear, sq_clear);
    assert!(pg_clear.is_empty());

    // 每规则上限：非 resolved 优先，其次按 last_eval_at 新→旧。
    let mut cap_states = vec![
        alert_state("cap", "a", "r100", AlertStateKind::Resolved, 0, 100),
        alert_state("cap", "a", "r200", AlertStateKind::Resolved, 0, 200),
        alert_state("cap", "a", "r300", AlertStateKind::Resolved, 0, 300),
        alert_state("cap", "a", "r400", AlertStateKind::Resolved, 0, 400),
        alert_state("cap", "a", "fire50", AlertStateKind::Firing, 0, 50),
        alert_state("cap", "a", "pend60", AlertStateKind::Pending, 0, 60),
    ];
    cap_states.reverse();
    let (pg_cap, sq_cap) = both(&fx, |s| {
        for state in &cap_states {
            s.upsert_alert_state(state).unwrap();
        }
        let before = s.list_alert_states_for_rule("cap", 10).unwrap();
        let removed = s.prune_alert_states_for_rule("cap", 3).unwrap();
        let first_two = s.list_alert_states_for_rule("cap", 2).unwrap();
        let after = s.list_alert_states_for_rule("cap", 10).unwrap();
        let removed_all = s.prune_alert_states_for_rule("cap", 0).unwrap();
        (
            before,
            removed,
            first_two,
            after,
            removed_all,
            s.list_alert_states_for_rule("cap", 10).unwrap(),
        )
    });
    assert_eq!(pg_cap, sq_cap, "每规则状态上限行为必须一致");
    assert_eq!(
        pg_cap
            .0
            .iter()
            .map(|state| state.series_key.as_str())
            .collect::<Vec<_>>(),
        vec!["r400", "r300", "r200", "r100", "pend60", "fire50"],
        "读取顺序必须是 last_eval_at 倒序"
    );
    assert_eq!(pg_cap.1, 3, "keep=3 时应淘汰 3 条");
    assert_eq!(
        pg_cap
            .2
            .iter()
            .map(|state| state.series_key.as_str())
            .collect::<Vec<_>>(),
        vec!["r400", "pend60"]
    );
    assert_eq!(
        pg_cap
            .3
            .iter()
            .map(|state| state.series_key.as_str())
            .collect::<Vec<_>>(),
        vec!["r400", "pend60", "fire50"],
        "非 resolved 必须优先于更旧的 resolved 保留"
    );
    assert_eq!(pg_cap.4, 3, "keep=0 必须清空该规则全部状态");
    assert!(pg_cap.5.is_empty());

    // 同 last_eval_at 的序列排序：按插入顺序（rowid/id）新→旧稳定排序。
    let tie_a = alert_state("tie-rule", "a", "tie-a", AlertStateKind::Pending, 0, 5_000);
    let tie_b = alert_state("tie-rule", "a", "tie-b", AlertStateKind::Pending, 0, 5_000);
    let (pg_tie, sq_tie) = both(&fx, |s| {
        s.upsert_alert_state(&tie_a).unwrap();
        s.upsert_alert_state(&tie_b).unwrap();
        (
            s.list_alert_states_for_rule("tie-rule", 10)
                .unwrap()
                .iter()
                .map(|state| state.series_key.clone())
                .collect::<Vec<_>>(),
            s.list_alert_states().unwrap().len(),
        )
    });
    assert_eq!(pg_tie, sq_tie, "同时间戳状态排序必须一致");
    assert_eq!(
        pg_tie.0,
        vec!["tie-b".to_string(), "tie-a".to_string()],
        "同 last_eval_at 必须按插入顺序新→旧"
    );
    assert_eq!(pg_tie.1, 2);
}

// ---------------------------------------------------------------------------
// 6. 告警事件：id 单调 / before_id 分页 / 通知队列 / prune / 批量事务
// ---------------------------------------------------------------------------

#[test]
fn alert_events_queue_prune_and_apply_parity() {
    const NAME: &str = "alert_events_queue_prune_and_apply_parity";
    let Some(fx) = ParityFixture::new("events") else {
        skip(NAME);
        return;
    };

    let e0 = alert_event(100, "rule-a", "规则 A", AlertStateKind::Firing);
    let mut e1 = alert_event(200, "rule-a", "规则 A", AlertStateKind::Firing);
    e1.silenced = true;
    let e2 = alert_event(300, "rule-a", "规则 A", AlertStateKind::Resolved);
    let mut e3 = alert_event(400, "rule-b", "规则 B", AlertStateKind::Firing);
    e3.notified = true;
    e3.notify_error = "earlier".to_string();
    let mut e4 = alert_event(500, "rule-b", "规则 B", AlertStateKind::Resolved);
    e4.value = None;
    e4.message = "事件 500（value=None）".to_string();
    let e5 = alert_event(600, "rule-c", "规则 C", AlertStateKind::Firing);
    let events = [
        e0.clone(),
        e1.clone(),
        e2.clone(),
        e3.clone(),
        e4.clone(),
        e5.clone(),
    ];

    // 插入 6 条：id 严格递增，列表按 id 倒序，before_id 排他。
    let (pg_insert, sq_insert) = both(&fx, |s| {
        let mut ids = Vec::new();
        for event in &events {
            ids.push(s.insert_alert_event(event).unwrap());
        }
        let all = s.list_alert_events(100, None).unwrap();
        let first_page = s.list_alert_events(2, None).unwrap();
        let second_page = s.list_alert_events(2, Some(first_page[1].id)).unwrap();
        let zero = s.list_alert_events(0, None).unwrap();
        let before_zero = s.list_alert_events(10, Some(0)).unwrap();
        (
            ids,
            strip_event_ids(&all),
            all.iter()
                .map(|event| event.message.clone())
                .collect::<Vec<_>>(),
            first_page.iter().map(|event| event.id).collect::<Vec<_>>(),
            second_page.iter().map(|event| event.id).collect::<Vec<_>>(),
            zero,
            before_zero,
            s.max_alert_event_id().unwrap(),
        )
    });
    assert_eq!(pg_insert, sq_insert, "事件插入 / 分页结果必须一致");
    assert!(
        pg_insert.0.windows(2).all(|pair| pair[0] < pair[1]),
        "事件 id 必须严格递增"
    );
    assert_eq!(
        pg_insert.2,
        vec![
            "事件 600",
            "事件 500（value=None）",
            "事件 400",
            "事件 300",
            "事件 200",
            "事件 100"
        ],
        "事件必须按 id 倒序"
    );
    assert_eq!(pg_insert.3, vec![pg_insert.0[5], pg_insert.0[4]]);
    assert_eq!(pg_insert.4, vec![pg_insert.0[3], pg_insert.0[2]]);
    assert!(pg_insert.5.is_empty(), "limit=0 必须返回空");
    assert!(pg_insert.6.is_empty(), "before_id=0 不得返回任何事件");
    assert_eq!(pg_insert.7, pg_insert.0[5], "max id 必须是最后插入的 id");
    assert_eq!(pg_insert.5.len(), 0);

    // 通知队列：只取未通知且未静默，id 升序；after_id 为持久化游标。
    let (pg_pending, sq_pending) = both(&fx, |s| {
        let all = s.list_alert_events(100, None).unwrap();
        let e2_id = all
            .iter()
            .find(|event| event.message == "事件 300")
            .unwrap()
            .id;
        let e5_id = all
            .iter()
            .find(|event| event.message == "事件 600")
            .unwrap()
            .id;
        (
            s.list_pending_notification_events(100)
                .unwrap()
                .iter()
                .map(|event| event.message.clone())
                .collect::<Vec<_>>(),
            s.list_pending_notification_events_after(0, 100)
                .unwrap()
                .len(),
            s.list_pending_notification_events_after(e2_id, 100)
                .unwrap()
                .iter()
                .map(|event| event.message.clone())
                .collect::<Vec<_>>(),
            s.list_pending_notification_events_after(e5_id, 100)
                .unwrap()
                .len(),
            s.list_pending_notification_events(0).unwrap().len(),
        )
    });
    assert_eq!(pg_pending, sq_pending, "通知队列必须一致");
    assert_eq!(
        pg_pending.0,
        vec!["事件 100", "事件 300", "事件 500（value=None）", "事件 600"],
        "silenced / notified 事件不得进入队列"
    );
    assert_eq!(pg_pending.1, 4);
    assert_eq!(
        pg_pending.2,
        vec!["事件 500（value=None）", "事件 600"],
        "after_id 必须排他"
    );
    assert_eq!(pg_pending.3, 0);
    assert_eq!(pg_pending.4, 0);

    // 标记已处理 / 通知结果 / 只更新状态通知时间。
    let (pg_mark, sq_mark) = both(&fx, |s| {
        let all = s.list_alert_events(100, None).unwrap();
        let id_of = |message: &str| {
            all.iter()
                .find(|event| event.message == message)
                .unwrap()
                .id
        };
        let processed = s
            .mark_notification_processed(id_of("事件 100"), "no_channel")
            .unwrap();
        let processed_again = s
            .mark_notification_processed(id_of("事件 100"), "no_channel")
            .unwrap();
        let processed_missing = s.mark_notification_processed(9_999_999, "x").unwrap();
        let success = s
            .mark_notification_result(id_of("事件 300"), true, "会被清空")
            .unwrap();
        let failed = s
            .mark_notification_result(id_of("事件 500（value=None）"), false, "send_failed")
            .unwrap();
        let failed_missing = s.mark_notification_result(9_999_999, false, "x").unwrap();
        let after = s.list_alert_events(100, None).unwrap();
        (
            processed,
            processed_again,
            processed_missing,
            success,
            failed,
            failed_missing,
            strip_event_ids(&after),
        )
    });
    assert_eq!(pg_mark, sq_mark, "通知标记结果必须一致");
    assert_eq!(
        (pg_mark.0, pg_mark.1, pg_mark.2, pg_mark.3, pg_mark.4, pg_mark.5),
        (true, true, false, true, true, false)
    );
    assert!(event_by_message(&pg_mark.6, "事件 100").notified);
    assert_eq!(
        event_by_message(&pg_mark.6, "事件 100").notify_error,
        "no_channel"
    );
    assert!(event_by_message(&pg_mark.6, "事件 300").notified);
    assert_eq!(
        event_by_message(&pg_mark.6, "事件 300").notify_error,
        "",
        "notified=true 必须清空错误"
    );
    assert!(!event_by_message(&pg_mark.6, "事件 500（value=None）").notified);
    assert_eq!(
        event_by_message(&pg_mark.6, "事件 500（value=None）").notify_error,
        "send_failed"
    );

    let notify_state = alert_state(
        "notify-rule",
        "agent-n",
        "notify-series",
        AlertStateKind::Firing,
        NOW - 10,
        NOW,
    );
    let (pg_notified, sq_notified) = both(&fx, |s| {
        s.upsert_alert_state(&notify_state).unwrap();
        let updated = s
            .update_alert_state_notified("notify-rule", "agent-n", "notify-series", NOW + 5)
            .unwrap();
        let missing = s
            .update_alert_state_notified("notify-rule", "agent-n", "missing", NOW + 5)
            .unwrap();
        (
            updated,
            missing,
            s.get_alert_state("notify-rule", "agent-n", "notify-series")
                .unwrap(),
        )
    });
    assert_eq!(pg_notified, sq_notified);
    assert_eq!((pg_notified.0, pg_notified.1), (true, false));
    assert_eq!(
        pg_notified.2,
        Some(AlertState {
            last_notified_at: Some(NOW + 5),
            ..notify_state.clone()
        }),
        "只允许改 last_notified_at"
    );

    // prune：先按 ts 删，再按 max_rows 从旧到新删；空库后重新插入 id 继续增长。
    let (pg_prune, sq_prune) = both(&fx, |s| {
        let deleted = s.prune_alert_events(350, 2).unwrap();
        let after = s.list_alert_events(100, None).unwrap();
        let repeat = s.prune_alert_events(350, 2).unwrap();
        let max_after_prune = s.max_alert_event_id().unwrap();
        let cleared = s.prune_alert_events(0, 0).unwrap();
        let empty = s.list_alert_events(100, None).unwrap();
        let max_empty = s.max_alert_event_id().unwrap();
        let new_id = s
            .insert_alert_event(&alert_event(
                700,
                "rule-d",
                "规则 D",
                AlertStateKind::Firing,
            ))
            .unwrap();
        (
            deleted,
            strip_event_ids(&after),
            after
                .iter()
                .map(|event| event.message.clone())
                .collect::<Vec<_>>(),
            repeat,
            max_after_prune,
            cleared,
            empty,
            max_empty,
            new_id,
        )
    });
    assert_eq!(
        (
            pg_prune.0,
            pg_prune.2.clone(),
            pg_prune.3,
            pg_prune.5,
            pg_prune.6.len(),
            pg_prune.7
        ),
        (
            4,
            vec!["事件 600".to_string(), "事件 500（value=None）".to_string()],
            0,
            2,
            0,
            0
        ),
        "事件 prune 顺序必须是先时间、后最旧行"
    );
    assert_eq!(pg_prune, sq_prune, "事件 prune 结果必须一致");
    assert!(pg_prune.8 > 1, "清空后新事件 id 必须继续增长");

    // apply_alert_transitions：事件 + 状态单事务批量落库。
    let batch_events = vec![
        alert_event(800, "batch-rule", "批量规则", AlertStateKind::Firing),
        alert_event(801, "batch-rule", "批量规则", AlertStateKind::Resolved),
    ];
    let batch_states = vec![
        alert_state("batch-rule", "a1", "s1", AlertStateKind::Firing, NOW, NOW),
        alert_state("batch-rule", "a1", "s2", AlertStateKind::Resolved, NOW, NOW),
    ];
    let (pg_apply, sq_apply) = both(&fx, |s| {
        s.apply_alert_transitions(&batch_events, &batch_states)
            .unwrap();
        let before_empty_apply = (
            s.list_alert_events(100, None).unwrap().len(),
            s.list_alert_states().unwrap().len(),
        );
        s.apply_alert_transitions(&[], &[]).unwrap();
        (
            before_empty_apply,
            s.list_alert_events(100, None)
                .unwrap()
                .iter()
                .map(|event| event.message.clone())
                .collect::<Vec<_>>(),
            s.list_alert_states().unwrap(),
        )
    });
    assert_eq!(pg_apply, sq_apply, "批量事务结果必须一致");
    assert_eq!(
        pg_apply.0,
        (3, 3),
        "1 条新事件 + 2 条批量事件；notify-rule 1 条 + batch 2 条状态"
    );
    assert_eq!(
        pg_apply.1,
        vec!["事件 801", "事件 800", "事件 700"],
        "批量事件同样按 id 倒序"
    );
    let batch_keys: Vec<(&str, &str, &str)> = pg_apply
        .2
        .iter()
        .map(|state| {
            (
                state.rule_id.as_str(),
                state.agent_id.as_str(),
                state.series_key.as_str(),
            )
        })
        .collect();
    assert!(batch_keys.contains(&("batch-rule", "a1", "s1")));
    assert!(batch_keys.contains(&("batch-rule", "a1", "s2")));

    // apply_alert_evaluation：事务内落库并执行每规则上限清理。
    let eval_events = vec![alert_event(
        900,
        "eval-rule",
        "评估规则",
        AlertStateKind::Firing,
    )];
    let eval_states = vec![
        alert_state("eval-rule", "a1", "new-1", AlertStateKind::Firing, NOW, NOW),
        alert_state(
            "eval-rule",
            "a1",
            "new-2",
            AlertStateKind::Pending,
            NOW,
            NOW,
        ),
    ];
    let old_eval_states = vec![
        alert_state("eval-rule", "a1", "old-1", AlertStateKind::Resolved, 0, 10),
        alert_state("eval-rule", "a1", "old-2", AlertStateKind::Resolved, 0, 20),
        alert_state("eval-rule", "a1", "old-3", AlertStateKind::Resolved, 0, 30),
    ];
    let (pg_eval, sq_eval) = both(&fx, |s| {
        for state in &old_eval_states {
            s.upsert_alert_state(state).unwrap();
        }
        let removed = s
            .apply_alert_evaluation("eval-rule", &eval_events, &eval_states, 2)
            .unwrap();
        (
            removed,
            s.list_alert_states_for_rule("eval-rule", 10)
                .unwrap()
                .iter()
                .map(|state| state.series_key.clone())
                .collect::<Vec<_>>(),
            s.list_alert_events(100, None)
                .unwrap()
                .iter()
                .filter(|event| event.rule_id == "eval-rule")
                .count(),
        )
    });
    assert_eq!(pg_eval, sq_eval, "评估事务结果必须一致");
    assert_eq!(pg_eval.0, 3, "5 条状态保留 2 条应淘汰 3 条");
    assert_eq!(
        pg_eval.1,
        vec!["new-2".to_string(), "new-1".to_string()],
        "非 resolved 新状态必须优先保留"
    );
    assert_eq!(pg_eval.2, 1);
}

// ---------------------------------------------------------------------------
// 7. 批量事务原子性：注入 trigger 让状态插入失败，事件与状态都必须回滚
// ---------------------------------------------------------------------------

#[test]
fn alert_transaction_rollback_is_atomic_on_failure() {
    const NAME: &str = "alert_transaction_rollback_is_atomic_on_failure";
    let Some(fx) = ParityFixture::new_file_sqlite("atomic") else {
        skip(NAME);
        return;
    };
    let sqlite_path = fx.sqlite_path.as_ref().expect("文件型 SQLite 路径缺失");

    let existing_state = alert_state(
        "poison-eval",
        "agent-1",
        "existing",
        AlertStateKind::Firing,
        NOW - 100,
        NOW,
    );
    let (pg_pre, sq_pre) = both(&fx, |s| {
        s.upsert_alert_state(&existing_state).unwrap();
        s.list_alert_states().unwrap()
    });
    assert_eq!(pg_pre, sq_pre);
    assert_eq!(pg_pre, vec![existing_state.clone()]);

    // PG：BEFORE INSERT trigger 在 rule_id='poison' 时 RAISE EXCEPTION。
    {
        let mut client = fx.db.client();
        client
            .batch_execute(
                "CREATE OR REPLACE FUNCTION parity_fail_poison_state()
                 RETURNS trigger AS $$
                 BEGIN
                     RAISE EXCEPTION 'parity injected state failure';
                 END;
                 $$ LANGUAGE plpgsql;
                 CREATE TRIGGER parity_fail_poison_state
                 BEFORE INSERT ON alert_states
                 FOR EACH ROW WHEN (NEW.rule_id = 'poison')
                 EXECUTE FUNCTION parity_fail_poison_state();",
            )
            .expect("安装 PG 故障注入 trigger 失败");
    }
    // SQLite：等价 trigger。
    {
        let connection =
            rusqlite::Connection::open(sqlite_path).expect("打开 SQLite trigger 连接失败");
        connection
            .execute_batch(
                "CREATE TRIGGER parity_fail_poison_state
                 BEFORE INSERT ON alert_states
                 WHEN NEW.rule_id = 'poison'
                 BEGIN
                     SELECT RAISE(ABORT, 'parity injected state failure');
                 END;",
            )
            .expect("安装 SQLite 故障注入 trigger 失败");
    }

    let poison_transitions_events = vec![alert_event(
        950,
        "ok-rule",
        "正常规则",
        AlertStateKind::Firing,
    )];
    let poison_transitions_states = vec![
        alert_state("ok-rule", "a1", "s1", AlertStateKind::Firing, NOW, NOW),
        alert_state("poison", "a1", "s1", AlertStateKind::Firing, NOW, NOW),
    ];
    let (pg_fail, sq_fail) = both(&fx, |s| {
        s.apply_alert_transitions(&poison_transitions_events, &poison_transitions_states)
            .is_err()
    });
    assert!(
        pg_fail,
        "PG apply_alert_transitions 必须因注入 failure 报错"
    );
    assert!(
        sq_fail,
        "SQLite apply_alert_transitions 必须因注入 failure 报错"
    );

    let (pg_after, sq_after) = both(&fx, |s| {
        (
            s.list_alert_events(100, None).unwrap(),
            s.list_alert_states().unwrap(),
            s.max_alert_event_id().unwrap(),
        )
    });
    assert_eq!(pg_after, sq_after, "回滚后两侧状态必须一致");
    assert!(
        pg_after.0.is_empty(),
        "事务失败后事件必须全部回滚，不得留下半写事件"
    );
    assert_eq!(
        pg_after.1,
        vec![existing_state.clone()],
        "事务失败后不得留下注入测试的状态"
    );
    assert_eq!(pg_after.2, 0);

    // apply_alert_evaluation：事件写入 + upsert + 每规则裁剪同一事务，失败全部回滚。
    let eval_event = alert_event(960, "poison-eval", "评估规则", AlertStateKind::Firing);
    let eval_states = vec![
        alert_state("ok-rule", "a1", "s1", AlertStateKind::Firing, NOW, NOW),
        alert_state("poison", "a1", "s1", AlertStateKind::Firing, NOW, NOW),
    ];
    let (pg_eval_fail, sq_eval_fail) = both(&fx, |s| {
        s.apply_alert_evaluation(
            "poison-eval",
            std::slice::from_ref(&eval_event),
            &eval_states,
            0,
        )
        .is_err()
    });
    assert!(pg_eval_fail, "PG apply_alert_evaluation 必须报错");
    assert!(sq_eval_fail, "SQLite apply_alert_evaluation 必须报错");
    let (pg_after_eval, sq_after_eval) = both(&fx, |s| {
        (
            s.list_alert_events(100, None).unwrap(),
            s.list_alert_states().unwrap(),
        )
    });
    assert_eq!(pg_after_eval, sq_after_eval);
    assert!(pg_after_eval.0.is_empty(), "评估失败不得留下事件");
    assert_eq!(
        pg_after_eval.1,
        vec![existing_state.clone()],
        "评估失败不得提交裁剪（原 poison-eval 状态必须还在）"
    );

    // 移除 trigger 后同样的调用必须成功，证明前面失败确由注入导致。
    {
        let mut client = fx.db.client();
        client
            .batch_execute(
                "DROP TRIGGER parity_fail_poison_state ON alert_states;
                 DROP FUNCTION parity_fail_poison_state();",
            )
            .expect("卸载 PG trigger 失败");
    }
    {
        let connection =
            rusqlite::Connection::open(sqlite_path).expect("打开 SQLite trigger 连接失败");
        connection
            .execute_batch("DROP TRIGGER parity_fail_poison_state;")
            .expect("卸载 SQLite trigger 失败");
    }
    let (pg_ok, sq_ok) = both(&fx, |s| {
        s.apply_alert_transitions(&poison_transitions_events, &poison_transitions_states)
            .unwrap();
        (
            s.list_alert_events(100, None).unwrap().len(),
            s.list_alert_states().unwrap().len(),
        )
    });
    assert_eq!(pg_ok, sq_ok);
    assert_eq!(pg_ok, (1, 3), "移除 trigger 后事件 1 条、状态 3 条");
}

// ---------------------------------------------------------------------------
// 8. 告警静默：生效窗口 / 删除 / 到期清理 / 上限
// ---------------------------------------------------------------------------

#[test]
fn alert_silences_window_delete_prune_and_limit_parity() {
    const NAME: &str = "alert_silences_window_delete_prune_and_limit_parity";
    let Some(fx) = ParityFixture::new("silences") else {
        skip(NAME);
        return;
    };

    let wildcard = alert_silence(None, None, NOW + 600_000, "admin", NOW);
    let rule_only = alert_silence(Some("rule-a"), None, NOW + 300_000, "ops", NOW + 1);
    let agent_only = alert_silence(None, Some("agent-01"), NOW + 200_000, "ops", NOW + 2);
    let specific = alert_silence(
        Some("rule-b"),
        Some("agent-02"),
        NOW + 100_000,
        "ops",
        NOW + 3,
    );
    let expired = alert_silence(Some("rule-c"), Some("agent-03"), NOW - 1, "ops", NOW - 10);
    let boundary = alert_silence(Some("rule-d"), None, NOW, "ops", NOW - 10);

    let (pg, sq) = both(&fx, |s| {
        assert!(
            s.list_active_silences(NOW).unwrap().is_empty(),
            "新库不得有静默"
        );
        let ids = [
            s.create_alert_silence(&wildcard).unwrap(),
            s.create_alert_silence(&rule_only).unwrap(),
            s.create_alert_silence(&agent_only).unwrap(),
            s.create_alert_silence(&specific).unwrap(),
            s.create_alert_silence(&expired).unwrap(),
            s.create_alert_silence(&boundary).unwrap(),
        ];
        let active = s.list_active_silences(NOW).unwrap();
        let deleted = s.delete_alert_silence(ids[2]).unwrap();
        let deleted_again = s.delete_alert_silence(ids[2]).unwrap();
        let deleted_missing = s.delete_alert_silence(999_999).unwrap();
        let pruned_now = s.prune_alert_silences(NOW).unwrap();
        let pruned_until_specific = s.prune_alert_silences(NOW + 100_000).unwrap();
        let pruned_before = s.prune_alert_silences(NOW - 1).unwrap();
        let remaining = s.list_active_silences(NOW).unwrap();
        (
            ids,
            active,
            deleted,
            deleted_again,
            deleted_missing,
            pruned_now,
            pruned_until_specific,
            pruned_before,
            remaining,
        )
    });
    assert_eq!(pg, sq, "静默创建 / 删除 / 清理结果必须一致");
    assert!(pg.0.iter().all(|id| *id > 0));
    assert!(
        pg.0.windows(2).all(|pair| pair[0] < pair[1]),
        "静默 id 必须严格递增"
    );
    assert_eq!(
        pg.1.iter().map(|silence| silence.id).collect::<Vec<_>>(),
        vec![pg.0[3], pg.0[2], pg.0[1], pg.0[0]],
        "生效静默必须按最新创建在前"
    );
    assert_eq!(pg.1[0].rule_id, Some("rule-b".to_string()));
    assert_eq!(pg.1[0].agent_id, Some("agent-02".to_string()));
    assert_eq!(pg.1[3].rule_id, None);
    assert_eq!(pg.1[3].agent_id, None);
    assert_eq!((pg.2, pg.3, pg.4), (true, false, false));
    assert_eq!(pg.5, 2, "应清理已过期与 until_ts==NOW 的静默");
    assert_eq!(pg.6, 1, "until_ts 恰等于清理线必须删除");
    assert_eq!(pg.7, 0, "清理线之前不得误删");
    assert_eq!(
        pg.8.iter().map(|silence| silence.id).collect::<Vec<_>>(),
        vec![pg.0[1], pg.0[0]],
        "只剩 rule_only 与 wildcard"
    );

    // 纯函数窗口语义：until_ts > now 才生效。
    let stored_specific = &pg.1[0];
    assert!(stored_specific.is_active_at(stored_specific.until_ts - 1));
    assert!(!stored_specific.is_active_at(stored_specific.until_ts));
    assert!(stored_specific.matches("rule-b", "agent-02", NOW));
    assert!(!stored_specific.matches("rule-b", "agent-01", NOW));
    assert!(!stored_specific.matches("rule-a", "agent-02", NOW));
    assert!(pg.1[3].matches("any-rule", "any-agent", NOW));

    // 上限：1000 条生效静默之后，第 1001 条必须 LimitReached。
    assert_eq!(MAX_ALERT_SILENCES, 1_000);
    let (pg_limit, sq_limit) = both(&fx, |s| {
        for silence in s.list_active_silences(NOW).unwrap() {
            s.delete_alert_silence(silence.id).unwrap();
        }
        for index in 0..MAX_ALERT_SILENCES {
            let silence = alert_silence(
                None,
                None,
                NOW + 1_000_000 + index as i64,
                "bulk",
                NOW + index as i64,
            );
            s.create_alert_silence(&silence).unwrap();
        }
        let count = s.list_active_silences(NOW).unwrap().len();
        let overflow = alert_silence(None, None, NOW + 2_000_000, "bulk", NOW);
        let err = silence_store_error(s.create_alert_silence(&overflow).unwrap_err());
        let count_after = s.list_active_silences(NOW).unwrap().len();
        let pruned = s.prune_alert_silences(NOW + 2_000_000).unwrap();
        (
            count,
            err,
            count_after,
            pruned,
            s.list_active_silences(NOW).unwrap().len(),
        )
    });
    assert_eq!(pg_limit, sq_limit, "静默上限行为必须一致");
    assert_eq!(pg_limit.0, MAX_ALERT_SILENCES);
    assert_eq!(pg_limit.1, AlertSilenceStoreError::LimitReached);
    assert_eq!(pg_limit.2, MAX_ALERT_SILENCES, "超限失败不得写入");
    assert_eq!(pg_limit.3, MAX_ALERT_SILENCES, "清理应删除全部到期静默");
    assert_eq!(pg_limit.4, 0);
}

// ---------------------------------------------------------------------------
// 9. 通知渠道：CRUD / 重名 / 上限 / 被引用保护 / BOOLEAN / secret JSON
// ---------------------------------------------------------------------------

fn pg_data_type(fx: &ParityFixture, table: &str, column: &str) -> String {
    let mut client = fx.db.client();
    let row = client
        .query_one(
            "SELECT data_type FROM information_schema.columns \
             WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
            &[&table, &column],
        )
        .unwrap_or_else(|e| panic!("查询 {table}.{column} 类型失败：{e}"));
    row.get::<_, String>(0)
}

#[test]
fn notification_channels_crud_reference_and_limit_parity() {
    const NAME: &str = "notification_channels_crud_reference_and_limit_parity";
    let Some(fx) = ParityFixture::new("channels") else {
        skip(NAME);
        return;
    };

    let telegram = telegram_channel("chan-telegram", "Alpha telegram", true);
    let wecom = wecom_channel("chan-wecom", "Beta wecom", false);
    let dingtalk = dingtalk_channel("chan-dingtalk", "Gamma dingtalk", true);

    let (pg_empty, sq_empty) = both(&fx, |s| {
        (
            s.list_notification_channels().unwrap(),
            s.notification_channel_count().unwrap(),
            s.get_notification_channel("missing").unwrap(),
        )
    });
    assert_eq!(pg_empty, sq_empty);
    assert!(pg_empty.0.is_empty());
    assert_eq!(pg_empty.1, 0);
    assert_eq!(pg_empty.2, None);

    let (pg_created, sq_created) = both(&fx, |s| {
        s.create_notification_channel(&telegram).unwrap();
        s.create_notification_channel(&wecom).unwrap();
        s.create_notification_channel(&dingtalk).unwrap();
        (
            s.list_notification_channels().unwrap(),
            s.notification_channel_count().unwrap(),
            s.get_notification_channel("chan-telegram").unwrap(),
            s.get_notification_channel("chan-wecom").unwrap(),
            s.get_notification_channel("chan-dingtalk").unwrap(),
        )
    });
    assert_eq!(pg_created, sq_created, "创建渠道后查询必须一致");
    assert_eq!(
        pg_created
            .0
            .iter()
            .map(|channel| channel.name.as_str())
            .collect::<Vec<_>>(),
        vec!["Alpha telegram", "Beta wecom", "Gamma dingtalk"],
        "渠道必须按名称升序"
    );
    assert_eq!(pg_created.1, 3);
    assert_eq!(pg_created.2, Some(telegram.clone()));
    assert_eq!(pg_created.3, Some(wecom.clone()));
    assert_eq!(pg_created.4, Some(dingtalk.clone()));
    assert_eq!(
        pg_created.3.as_ref().unwrap().config.kind(),
        ChannelKind::Wecom
    );
    assert_eq!(pg_created.4.as_ref().unwrap().kind, ChannelKind::Dingtalk);

    // secret 的 Debug 必须脱敏，不能出现在日志/断言输出中。
    let debug = format!("{telegram:?}");
    assert!(
        !debug.contains(TELEGRAM_BOT_TOKEN),
        "NotificationChannel Debug 不得包含 secret"
    );
    assert!(
        debug.contains("<redacted>"),
        "Secret Debug 必须显示 <redacted>"
    );
    let view_debug = format!("{:?}", telegram.to_view());
    assert!(
        !view_debug.contains(TELEGRAM_BOT_TOKEN),
        "ChannelView Debug 不得包含 secret"
    );
    assert_eq!(
        telegram.to_view().secret_fields,
        vec!["bot_token"],
        "API 视图只允许暴露 secret 字段名"
    );

    // PG 类型显式断言：BOOL 与 DOUBLE PRECISION（不是 INTEGER / REAL）。
    assert_eq!(
        pg_data_type(&fx, "notification_channels", "enabled"),
        "boolean"
    );
    assert_eq!(pg_data_type(&fx, "alert_events", "notified"), "boolean");
    assert_eq!(pg_data_type(&fx, "alert_events", "silenced"), "boolean");
    assert_eq!(
        pg_data_type(&fx, "samples_1m", "avg_value"),
        "double precision"
    );
    assert_eq!(
        pg_data_type(&fx, "alert_states", "last_value"),
        "double precision"
    );
    assert_eq!(pg_data_type(&fx, "samples", "value"), "double precision");
    assert_eq!(pg_data_type(&fx, "api_tokens", "created_at"), "bigint");

    // config_json 原样存储：与 serde 序列化结果逐字节一致；只断言相等，不打印内容。
    {
        let mut client = fx.db.client();
        let row = client
            .query_one(
                "SELECT config_json, enabled FROM notification_channels WHERE id = $1",
                &[&telegram.id],
            )
            .expect("读取 PG 渠道配置失败");
        let stored_json: String = row.get(0);
        let stored_enabled: bool = row.get(1);
        let expected_json = serde_json::to_string(&telegram.config).unwrap();
        assert!(
            stored_json == expected_json,
            "PG config_json 必须与序列化结果完全一致（内容已隐藏）"
        );
        assert!(stored_enabled, "PG BOOLEAN enabled 必须读成 true");
    }

    // 重名 / 类型冲突 / 更新 / 被规则引用时禁止删除。
    let (pg_conflict, sq_conflict) = both(&fx, |s| {
        let duplicate = channel_store_error(
            s.create_notification_channel(&telegram_channel("dup", "Alpha telegram", true))
                .unwrap_err(),
        );
        let mut mismatched = telegram_channel("bad-kind", "Bad kind", true);
        mismatched.kind = ChannelKind::Wecom;
        let invalid = channel_store_error(s.create_notification_channel(&mismatched).unwrap_err());
        (duplicate, invalid)
    });
    assert_eq!(pg_conflict, sq_conflict);
    assert_eq!(pg_conflict.0, ChannelStoreError::NameExists);
    assert!(
        matches!(pg_conflict.1, ChannelStoreError::Invalid(_)),
        "kind 与 config 不一致必须被拒绝"
    );

    let (pg_update, sq_update) = both(&fx, |s| {
        let mut updated = s
            .get_notification_channel("chan-telegram")
            .unwrap()
            .unwrap();
        updated.name = "Alpha telegram v2".to_string();
        updated.enabled = false;
        updated.config = ChannelConfig::Telegram {
            bot_token: Secret::new("987654321:zyxwvutsrqponmlkjihgfedcba"),
            chat_id: "42".to_string(),
        };
        updated.updated_by = "ops".to_string();
        updated.updated_at = NOW + 500;
        s.update_notification_channel(&updated).unwrap();
        let fetched = s
            .get_notification_channel("chan-telegram")
            .unwrap()
            .unwrap();
        let mut conflicting = fetched.clone();
        conflicting.name = "Beta wecom".to_string();
        let conflict =
            channel_store_error(s.update_notification_channel(&conflicting).unwrap_err());
        let mut missing = telegram_channel("missing", "不存在", true);
        missing.updated_at = NOW + 600;
        let not_found = channel_store_error(s.update_notification_channel(&missing).unwrap_err());
        (fetched, conflict, not_found)
    });
    assert_eq!(pg_update, sq_update, "渠道更新结果必须一致");
    assert_eq!(pg_update.0.name, "Alpha telegram v2");
    assert!(!pg_update.0.enabled, "BOOL enabled 必须能写回 false");
    assert_eq!(pg_update.0.updated_by, "ops");
    assert_eq!(pg_update.0.created_at, NOW, "update 不得改 created_at");
    assert_eq!(pg_update.0.updated_at, NOW + 500);
    assert_eq!(pg_update.1, ChannelStoreError::NameExists);
    assert_eq!(pg_update.2, ChannelStoreError::NotFound);

    let (pg_reference, sq_reference) = both(&fx, |s| {
        let mut rule = custom_rule("channel-ref", "引用渠道规则");
        rule.channel_ids = vec!["chan-telegram".to_string()];
        s.create_alert_rule(&rule).unwrap();
        let in_use =
            channel_store_error(s.delete_notification_channel("chan-telegram").unwrap_err());
        let still_there = s
            .get_notification_channel("chan-telegram")
            .unwrap()
            .is_some();
        let mut unreferenced = s.get_alert_rule("channel-ref").unwrap().unwrap();
        unreferenced.channel_ids = Vec::new();
        s.update_alert_rule(&unreferenced).unwrap();
        s.delete_notification_channel("chan-telegram").unwrap();
        let missing =
            channel_store_error(s.delete_notification_channel("chan-telegram").unwrap_err());
        (
            in_use,
            still_there,
            s.get_notification_channel("chan-telegram").unwrap(),
            missing,
        )
    });
    assert_eq!(pg_reference, sq_reference, "渠道引用保护结果必须一致");
    assert_eq!(pg_reference.0, ChannelStoreError::InUse);
    assert!(pg_reference.1, "被引用时不得删除");
    assert_eq!(pg_reference.2, None);
    assert_eq!(pg_reference.3, ChannelStoreError::NotFound);

    // 上限：50 条之后第 51 条 LimitReached。
    assert_eq!(MAX_NOTIFICATION_CHANNELS, 50);
    let (pg_limit, sq_limit) = both(&fx, |s| {
        s.delete_notification_channel("chan-wecom").unwrap();
        s.delete_notification_channel("chan-dingtalk").unwrap();
        for index in 0..MAX_NOTIFICATION_CHANNELS {
            let channel = telegram_channel(
                &format!("limit-{index:03}"),
                &format!("渠道 {index:03}"),
                index % 2 == 0,
            );
            s.create_notification_channel(&channel).unwrap();
        }
        let count = s.notification_channel_count().unwrap();
        let overflow = telegram_channel("limit-overflow", "第 51 条渠道", true);
        let err = channel_store_error(s.create_notification_channel(&overflow).unwrap_err());
        (
            count,
            err,
            s.notification_channel_count().unwrap(),
            s.get_notification_channel("limit-overflow").unwrap(),
            s.list_notification_channels().unwrap().len(),
        )
    });
    assert_eq!(pg_limit, sq_limit, "渠道上限行为必须一致");
    assert_eq!(pg_limit.0, MAX_NOTIFICATION_CHANNELS);
    assert_eq!(pg_limit.1, ChannelStoreError::LimitReached);
    assert_eq!(pg_limit.2, MAX_NOTIFICATION_CHANNELS);
    assert_eq!(pg_limit.3, None, "超限失败不得写入");
    assert_eq!(pg_limit.4, MAX_NOTIFICATION_CHANNELS);
}

// ---------------------------------------------------------------------------
// 10. API token：create / list / rotate / revoke / authenticate 节流
// ---------------------------------------------------------------------------

#[test]
fn api_tokens_lifecycle_and_auth_throttle_parity() {
    const NAME: &str = "api_tokens_lifecycle_and_auth_throttle_parity";
    let Some(fx) = ParityFixture::new("tokens") else {
        skip(NAME);
        return;
    };

    let (pg_create, sq_create) = both(&fx, |s| {
        let empty = s.list_api_tokens().unwrap();
        let alpha = s
            .create_api_token("alpha", "hash-alpha", "read", NOW)
            .unwrap();
        let beta = s
            .create_api_token("beta", "hash-beta", "write", NOW + 1)
            .unwrap();
        let gamma = s
            .create_api_token("gamma", "hash-gamma", "admin", NOW + 2)
            .unwrap();
        (empty, alpha, beta, gamma, s.list_api_tokens().unwrap())
    });
    assert_eq!(pg_create, sq_create, "创建 token 结果必须一致");
    assert!(pg_create.0.is_empty());
    assert!(pg_create.1.id > 0);
    assert_eq!(pg_create.1.name, "alpha");
    assert_eq!(pg_create.1.scope, "read");
    assert_eq!(pg_create.1.created_at, NOW);
    assert_eq!(pg_create.1.last_used_at, None);
    assert_eq!(pg_create.1.revoked_at, None);
    assert!(pg_create.1.id < pg_create.2.id && pg_create.2.id < pg_create.3.id);
    assert_eq!(
        pg_create
            .4
            .iter()
            .map(|token| token.name.as_str())
            .collect::<Vec<_>>(),
        vec!["alpha", "beta", "gamma"],
        "token 必须按 name 升序"
    );
    assert!(
        !format!("{:?}", pg_create.1).contains("hash-alpha"),
        "ApiTokenRecord Debug 不得包含 token 哈希"
    );

    // 重名 / 非法 scope / 重复哈希都必须在落库前拒绝。
    let (pg_reject, sq_reject) = both(&fx, |s| {
        let duplicate = s
            .create_api_token("alpha", "other-hash", "read", NOW + 10)
            .is_err();
        let bad_scope = s
            .create_api_token("delta", "hash-delta", "root", NOW + 10)
            .is_err();
        let duplicate_hash = s
            .create_api_token("delta", "hash-alpha", "read", NOW + 10)
            .is_err();
        (
            duplicate,
            bad_scope,
            duplicate_hash,
            s.list_api_tokens().unwrap().len(),
        )
    });
    assert_eq!(pg_reject, sq_reject, "非法 token 请求结果必须一致");
    assert_eq!(pg_reject, (true, true, true, 3));

    // 鉴权：未知哈希 None；首次写 last_used_at；60s 节流窗口内不写。
    let (pg_auth, sq_auth) = both(&fx, |s| {
        let unknown = s.authenticate_api_token("missing", NOW + 20).unwrap();
        let first = s
            .authenticate_api_token("hash-alpha", NOW + 20)
            .unwrap()
            .unwrap();
        let within = s
            .authenticate_api_token("hash-alpha", NOW + 20 + 59_999)
            .unwrap()
            .unwrap();
        let boundary = s
            .authenticate_api_token("hash-alpha", NOW + 20 + 60_000)
            .unwrap()
            .unwrap();
        let after = s
            .authenticate_api_token("hash-alpha", NOW + 20 + 60_001)
            .unwrap()
            .unwrap();
        (
            unknown,
            first.last_used_at,
            within.last_used_at,
            boundary.last_used_at,
            after.last_used_at,
        )
    });
    assert_eq!(pg_auth, sq_auth, "鉴权节流结果必须一致");
    assert_eq!(pg_auth.0, None);
    assert_eq!(pg_auth.1, Some(NOW + 20), "首次鉴权必须写 last_used_at");
    assert_eq!(pg_auth.2, Some(NOW + 20), "60s 窗口内不得更新");
    assert_eq!(pg_auth.3, Some(NOW + 60_020), "满 60s 必须更新");
    assert_eq!(pg_auth.4, Some(NOW + 60_020), "更新后再次进入节流窗口");

    // 吊销：只写 revoked_at，不删行；鉴权立即失败；重复吊销报错。
    let (pg_revoke, sq_revoke) = both(&fx, |s| {
        s.revoke_api_token("beta", NOW + 200).unwrap();
        let beta = s
            .list_api_tokens()
            .unwrap()
            .into_iter()
            .find(|token| token.name == "beta")
            .unwrap();
        let auth = s.authenticate_api_token("hash-beta", NOW + 201).unwrap();
        let repeat = s.revoke_api_token("beta", NOW + 202).is_err();
        let missing = s.revoke_api_token("missing", NOW + 202).is_err();
        (
            beta,
            auth,
            repeat,
            missing,
            s.list_api_tokens().unwrap().len(),
        )
    });
    assert_eq!(pg_revoke, sq_revoke, "吊销 token 结果必须一致");
    assert_eq!(pg_revoke.0.revoked_at, Some(NOW + 200));
    assert_eq!(pg_revoke.0.last_used_at, None);
    assert_eq!(pg_revoke.1, None, "已吊销 token 不得再通过鉴权");
    assert!(pg_revoke.2, "重复吊销必须报错");
    assert!(pg_revoke.3, "吊销不存在的 token 必须报错");
    assert_eq!(pg_revoke.4, 3, "吊销不得删行");

    // 轮换：同一行换哈希、清吊销、重置使用时间与 created_at；旧哈希立即失效。
    let (pg_rotate, sq_rotate) = both(&fx, |s| {
        let beta_id = s
            .list_api_tokens()
            .unwrap()
            .into_iter()
            .find(|token| token.name == "beta")
            .unwrap()
            .id;
        let rotated = s
            .rotate_api_token("beta", "hash-beta-v2", NOW + 300)
            .unwrap();
        let old_auth = s.authenticate_api_token("hash-beta", NOW + 301).unwrap();
        let new_auth = s.authenticate_api_token("hash-beta-v2", NOW + 302).unwrap();
        let missing = s
            .rotate_api_token("missing", "hash-missing", NOW + 303)
            .is_err();
        (beta_id, rotated, old_auth, new_auth, missing)
    });
    assert_eq!(pg_rotate, sq_rotate, "轮换 token 结果必须一致");
    assert_eq!(pg_rotate.1.id, pg_rotate.0, "轮换必须复用同一行");
    assert_eq!(pg_rotate.1.name, "beta");
    assert_eq!(pg_rotate.1.scope, "write");
    assert_eq!(pg_rotate.1.created_at, NOW + 300);
    assert_eq!(pg_rotate.1.last_used_at, None);
    assert_eq!(pg_rotate.1.revoked_at, None);
    assert_eq!(pg_rotate.2, None, "轮换后旧哈希必须立即失效");
    assert_eq!(
        pg_rotate.3.as_ref().map(|token| token.last_used_at),
        Some(Some(NOW + 302)),
        "轮换后新哈希首次鉴权必须写 last_used_at"
    );

    // PG 原始哈希列必须与传入值一致；列表/错误信息不得含明文哈希。
    {
        let mut client = fx.db.client();
        let row = client
            .query_one(
                "SELECT token_hash FROM api_tokens WHERE name = $1",
                &[&"alpha"],
            )
            .expect("读取 PG token_hash 失败");
        assert_eq!(row.get::<_, String>(0), "hash-alpha");
    }
    let (pg_final, sq_final) = both(&fx, |s| s.list_api_tokens().unwrap());
    assert_eq!(pg_final, sq_final, "最终 token 列表必须一致");
    assert_eq!(pg_final.len(), 3);
    let beta = pg_final.iter().find(|token| token.name == "beta").unwrap();
    assert_eq!(beta.created_at, NOW + 300);
    assert_eq!(beta.revoked_at, None);
    assert_eq!(
        beta.last_used_at,
        Some(NOW + 302),
        "轮换后的新哈希鉴权应写入 last_used_at"
    );
}

// ---------------------------------------------------------------------------
// 11. 审计与维护水位：分页 / 过滤 / prune / upsert / 排序
// ---------------------------------------------------------------------------

#[test]
fn audit_and_maintenance_parity() {
    const NAME: &str = "audit_and_maintenance_parity";
    let Some(fx) = ParityFixture::new("audit") else {
        skip(NAME);
        return;
    };

    let (pg_empty, sq_empty) = both(&fx, |s| {
        (
            s.list_audit(10, None, None, None).unwrap(),
            s.list_maintenance_state().unwrap(),
            s.get_maintenance_state("missing").unwrap(),
        )
    });
    assert_eq!(pg_empty, sq_empty);
    assert!(pg_empty.0.is_empty());
    assert!(pg_empty.1.is_empty());
    assert_eq!(pg_empty.2, None);

    let mut entries = Vec::new();
    let mut entry = new_audit(1_000, "agent-a", "systemd");
    entries.push(entry.clone());
    entry = new_audit(2_000, "agent-a", "docker");
    entry.result = "denied".to_string();
    entry.error_code = "policy".to_string();
    entries.push(entry.clone());
    entry = new_audit(3_000, "agent-b", "systemd");
    entry.result = "error".to_string();
    entry.error_message = "unit not found".to_string();
    entries.push(entry.clone());
    entry = new_audit(4_000, "agent-b", "docker");
    entry.params = r#"{"name":"nginx'); DROP TABLE audit_log; --"}"#.to_string();
    entries.push(entry.clone());
    let mut long_params = new_audit(5_000, "agent-c", "logs");
    long_params.params = "x".repeat(1_500);
    entries.push(long_params.clone());
    let mut injected = new_audit(6_000, "agent-a' OR '1'='1", "systemd");
    injected.params = "v'); DROP TABLE audit_log; --".to_string();
    injected.target = "x'); DELETE FROM audit_log; --".to_string();
    entries.push(injected.clone());

    let (pg_insert, sq_insert) = both(&fx, |s| {
        let ids: Vec<i64> = entries
            .iter()
            .map(|entry| s.insert_audit(entry).unwrap())
            .collect();
        let all = s.list_audit(100, None, None, None).unwrap();
        let page_1 = s.list_audit(2, None, None, None).unwrap();
        let page_2 = s.list_audit(2, Some(page_1[1].id), None, None).unwrap();
        let agent_a = s.list_audit(100, None, Some("agent-a"), None).unwrap();
        let docker = s.list_audit(100, None, None, Some("docker")).unwrap();
        let both_filters = s
            .list_audit(100, None, Some("agent-b"), Some("systemd"))
            .unwrap();
        let zero = s.list_audit(0, None, None, None).unwrap();
        let before_zero = s.list_audit(100, Some(0), None, None).unwrap();
        let injected_filter = s
            .list_audit(100, None, Some("agent-a' OR '1'='1"), None)
            .unwrap();
        (
            ids,
            all,
            page_1,
            page_2,
            agent_a,
            docker,
            both_filters,
            zero,
            before_zero,
            injected_filter,
        )
    });
    assert_eq!(pg_insert, sq_insert, "审计写入 / 查询结果必须一致");
    assert!(
        pg_insert.0.windows(2).all(|pair| pair[0] < pair[1]),
        "审计 id 必须严格递增"
    );
    assert_eq!(
        pg_insert.1.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        pg_insert.0.iter().rev().copied().collect::<Vec<_>>(),
        "审计必须按 id 倒序"
    );
    let truncated = pg_insert
        .1
        .iter()
        .find(|entry| entry.agent_id == "agent-c")
        .expect("必须存在长 params 审计");
    assert_eq!(
        truncated.params.len(),
        1_024,
        "params 必须在存储层截断到 1024 字节"
    );
    assert_eq!(truncated.params, "x".repeat(1_024));
    assert_eq!(
        pg_insert.2.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![pg_insert.0[5], pg_insert.0[4]]
    );
    assert_eq!(
        pg_insert.3.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![pg_insert.0[3], pg_insert.0[2]],
        "before_id 必须排他"
    );
    assert_eq!(
        pg_insert.4.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![pg_insert.0[1], pg_insert.0[0]],
        "agent_id 过滤必须精确匹配"
    );
    assert_eq!(
        pg_insert.5.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![pg_insert.0[3], pg_insert.0[1]]
    );
    assert_eq!(
        pg_insert.6.iter().map(|entry| entry.id).collect::<Vec<_>>(),
        vec![pg_insert.0[2]]
    );
    assert!(pg_insert.7.is_empty(), "limit=0 必须返回空");
    assert!(pg_insert.8.is_empty(), "before_id=0 不得返回记录");
    assert_eq!(pg_insert.9.len(), 1, "SQL 注入字符串必须按字面量匹配");
    assert_eq!(
        pg_insert.9[0].agent_id, "agent-a' OR '1'='1",
        "注入字符串必须原样存储"
    );

    // prune：严格早于边界删除；重复清理幂等。
    let (pg_prune, sq_prune) = both(&fx, |s| {
        let first = s.prune_audit(3_000).unwrap();
        let second = s.prune_audit(3_000).unwrap();
        (
            first,
            second,
            s.list_audit(100, None, None, None).unwrap().len(),
        )
    });
    assert_eq!(pg_prune, sq_prune, "审计清理结果必须一致");
    assert_eq!(pg_prune, (2, 0, 4), "ts=3000 的记录不得被删除");

    // 注入字符串不能破坏表结构：继续写入 / 查询仍然正常。
    let (pg_after_injection, sq_after_injection) = both(&fx, |s| {
        let id = s
            .insert_audit(&new_audit(7_000, "agent-d", "logs"))
            .unwrap();
        let found = s.list_audit(100, None, Some("agent-d"), None).unwrap();
        (
            id,
            found.len(),
            s.list_audit(100, None, None, None).unwrap().len(),
        )
    });
    assert_eq!(pg_after_injection, sq_after_injection);
    assert!(pg_after_injection.0 > 0);
    assert_eq!(pg_after_injection.1, 1);
    assert_eq!(pg_after_injection.2, 5);

    // 维护水位：空 → set → upsert → list 排序；注入字符串按值处理。
    let (pg_maint, sq_maint) = both(&fx, |s| {
        s.set_maintenance_state("a-key", "1", 10).unwrap();
        s.set_maintenance_state("b-key", "", 20).unwrap();
        s.set_maintenance_state("中文键", "v'); DROP TABLE maintenance_state; --", 30)
            .unwrap();
        let a = s.get_maintenance_state("a-key").unwrap();
        let b_empty = s.get_maintenance_state("b-key").unwrap();
        let injection = s.get_maintenance_state("中文键").unwrap();
        s.set_maintenance_state("b-key", "2", 40).unwrap();
        let b = s.get_maintenance_state("b-key").unwrap();
        (
            a,
            b_empty,
            injection,
            b,
            s.list_maintenance_state().unwrap(),
        )
    });
    assert_eq!(pg_maint, sq_maint, "维护水位结果必须一致");
    assert_eq!(pg_maint.0, Some("1".to_string()));
    assert_eq!(pg_maint.1, Some(String::new()));
    assert_eq!(
        pg_maint.2,
        Some("v'); DROP TABLE maintenance_state; --".to_string()),
        "注入字符串必须原样存储"
    );
    assert_eq!(pg_maint.3, Some("2".to_string()));
    assert_eq!(
        pg_maint
            .4
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>(),
        vec!["a-key", "b-key", "中文键"],
        "维护水位必须按 key 升序"
    );
    assert_eq!(pg_maint.4[1].value, "2");
    assert_eq!(pg_maint.4[1].updated_at, 40);

    // 注入后继续 upsert，证明结构未受损。
    let (pg_still_works, sq_still_works) = both(&fx, |s| {
        s.set_maintenance_state("after-injection", "ok", 50)
            .unwrap();
        s.get_maintenance_state("after-injection").unwrap()
    });
    assert_eq!(pg_still_works, sq_still_works);
    assert_eq!(pg_still_works, Some("ok".to_string()));
}

// ---------------------------------------------------------------------------
// 12. 降采样：1m / 1h 聚合、count 加权、桶边界、幂等、分层统计
// ---------------------------------------------------------------------------

#[test]
fn downsample_1m_and_1h_parity() {
    const NAME: &str = "downsample_1m_and_1h_parity";
    let Some(fx) = ParityFixture::new("downsample") else {
        skip(NAME);
        return;
    };

    let samples = vec![
        Sample::new("cpu.usage", 1_000, 10.0).with_label("host", "ds"),
        Sample::new("cpu.usage", 20_000, 20.0).with_label("host", "ds"),
        Sample::new("cpu.usage", 59_000, 30.0).with_label("host", "ds"),
        Sample::new("cpu.usage", 61_000, 40.0).with_label("host", "ds"),
        Sample::new("cpu.usage", 119_000, 50.0).with_label("host", "ds"),
        Sample::new("cpu.usage", 125_000, 60.0).with_label("host", "ds"),
    ];
    let batch = sample_batch("ds-agent", 1, 0, samples);

    let (pg, sq) = both(&fx, |s| {
        let outcome = s.insert_batch(&batch).unwrap();
        let first = s.downsample_1m_range(0, 180_000).unwrap();
        let second = s.downsample_1m_range(0, 180_000).unwrap();
        let empty_range = s.downsample_1m_range(0, 30_000).unwrap();
        let floored_range = s.downsample_1m_range(30_000, 90_000).unwrap();
        let stats = s.samples_1m_stats().unwrap();
        let oldest = s.samples_1m_oldest_ts().unwrap();
        let offsets = [
            s.samples_1m_ts_at_offset(0, 180_000, 0).unwrap(),
            s.samples_1m_ts_at_offset(0, 180_000, 1).unwrap(),
            s.samples_1m_ts_at_offset(0, 180_000, 2).unwrap(),
            s.samples_1m_ts_at_offset(0, 180_000, 3).unwrap(),
        ];
        let ranged_offset = s.samples_1m_ts_at_offset(60_000, 180_000, 0).unwrap();
        (
            outcome,
            first,
            second,
            empty_range,
            floored_range,
            stats,
            oldest,
            offsets,
            ranged_offset,
        )
    });
    assert_eq!(pg, sq, "1m 降采样结果必须一致");
    assert_eq!(
        pg.0,
        IngestOutcome::Inserted { inserted: 6 },
        "应写入 6 条原始样本"
    );
    assert_eq!(
        pg.1,
        DownsampleRangeResult {
            buckets: 3,
            rows: 6
        }
    );
    assert_eq!(pg.2, pg.1, "重复降采样必须幂等且计数一致");
    assert_eq!(
        pg.3,
        DownsampleRangeResult::default(),
        "to 向下取整后不大于 from 时必须空操作"
    );
    assert_eq!(
        pg.4,
        DownsampleRangeResult {
            buckets: 1,
            rows: 3
        },
        "非对齐区间必须向下取整到整分钟"
    );
    assert_stats_eq("1m stats", &pg.5, &sq.5);
    assert_eq!(
        pg.5,
        TierStats {
            rows: 3,
            oldest_ts: Some(0),
            newest_ts: Some(120_000)
        }
    );
    assert_eq!(pg.6, Some(0));
    assert_eq!(
        pg.7,
        [Some(0), Some(60_000), Some(120_000), None],
        "1m offset 必须按桶时间升序"
    );
    assert_eq!(pg.8, Some(60_000));

    // 1m 查询：count 加权平均 + 桶重叠边界 + limit。
    let cases: Vec<(i64, SeriesQuery, Vec<i64>, Vec<f64>)> = vec![
        (
            BUCKET_1M_MS,
            series_query("ds-agent", &[], 0, 180_000, 100),
            vec![0, 60_000, 120_000],
            vec![20.0, 45.0, 60.0],
        ),
        (
            120_000,
            series_query("ds-agent", &[], 0, 180_000, 100),
            vec![0, 120_000],
            vec![30.0, 60.0],
        ),
        (
            BUCKET_1M_MS,
            series_query("ds-agent", &[], 60_000, 180_000, 100),
            vec![60_000, 120_000],
            vec![45.0, 60.0],
        ),
        (
            BUCKET_1M_MS,
            series_query("ds-agent", &[], 59_999, 180_000, 100),
            vec![0, 60_000, 120_000],
            vec![20.0, 45.0, 60.0],
        ),
        (
            BUCKET_1M_MS,
            series_query("ds-agent", &[], 0, 0, 100),
            vec![0],
            vec![20.0],
        ),
        (
            BUCKET_1M_MS,
            series_query("ds-agent", &[], 0, -1, 100),
            vec![],
            vec![],
        ),
        (
            BUCKET_1M_MS,
            series_query("ds-agent", &[], 0, 180_000, 1),
            vec![0],
            vec![20.0],
        ),
        (
            BUCKET_1M_MS,
            series_query("ds-agent", &["missing"], 0, 180_000, 100),
            vec![],
            vec![],
        ),
    ];
    for (bucket_ms, query, expected_ts, expected_values) in cases {
        let (pg_rows, sq_rows) = both(&fx, |s| {
            s.query_series_tiered(&query, bucket_ms, SampleTier::OneMinute)
                .unwrap()
        });
        assert_series_eq("1m tiered query", &pg_rows, &sq_rows);
        assert_eq!(
            pg_rows.iter().map(|row| row.ts).collect::<Vec<_>>(),
            expected_ts,
            "1m 桶起点不符（bucket_ms={bucket_ms}）"
        );
        assert_eq!(pg_rows.len(), expected_values.len());
        for (index, expected) in expected_values.into_iter().enumerate() {
            assert_f64_close(pg_rows[index].value, expected, "1m count 加权平均");
        }
    }

    // raw tier 与 bucketed 必须一致。
    let raw_query = series_query("ds-agent", &[], 0, 180_000, 100);
    let (pg_raw, sq_raw) = both(&fx, |s| {
        s.query_series_tiered(&raw_query, 120_000, SampleTier::Raw)
            .unwrap()
    });
    assert_series_eq("raw tiered query", &pg_raw, &sq_raw);
    assert_eq!(pg_raw.len(), 2);
    assert_f64_close(pg_raw[0].value, 30.0, "raw 桶 0 AVG（5 个点）");
    assert_f64_close(pg_raw[1].value, 60.0, "raw 桶 1 AVG（1 个点）");

    // 1h 聚合与 count 加权。
    let (pg_1h, sq_1h) = both(&fx, |s| {
        let first = s.downsample_1h_range(0, 7_200_000).unwrap();
        let second = s.downsample_1h_range(0, 7_200_000).unwrap();
        let empty = s.downsample_1h_range(3_600_000, 7_200_000).unwrap();
        let stats = s.samples_1h_stats().unwrap();
        (first, second, empty, stats)
    });
    assert_eq!(pg_1h, sq_1h, "1h 降采样结果必须一致");
    assert_eq!(
        pg_1h.0,
        DownsampleRangeResult {
            buckets: 1,
            rows: 3
        }
    );
    assert_eq!(pg_1h.1, pg_1h.0, "1h 重复降采样必须幂等");
    assert_eq!(pg_1h.2, DownsampleRangeResult::default());
    assert_eq!(
        pg_1h.3,
        TierStats {
            rows: 1,
            oldest_ts: Some(0),
            newest_ts: Some(0)
        }
    );

    let (pg_hour_rows, sq_hour_rows) = both(&fx, |s| {
        s.query_series_tiered(
            &series_query("ds-agent", &[], 0, 3_600_000, 100),
            BUCKET_1H_MS,
            SampleTier::OneHour,
        )
        .unwrap()
    });
    assert_series_eq("1h tiered query", &pg_hour_rows, &sq_hour_rows);
    assert_eq!(pg_hour_rows.len(), 1);
    assert_eq!(pg_hour_rows[0].ts, 0);
    assert_f64_close(pg_hour_rows[0].value, 35.0, "1h count 加权平均");

    // 告警评估快照必须 raw-only：有 1m/1h 数据也不能回退。
    let (pg_alert_snapshot, sq_alert_snapshot) = both(&fx, |s| {
        s.latest_alert_series("cpu.usage", 1_000_000, None, 10)
            .unwrap()
    });
    assert_eq!(
        pg_alert_snapshot.truncated, sq_alert_snapshot.truncated,
        "latest_alert_series truncated 必须一致"
    );
    assert!(
        pg_alert_snapshot.rows.is_empty(),
        "latest_alert_series 只读 raw，不得回退到 1m/1h"
    );
    assert_agent_series_eq(
        "latest_alert_series raw-only",
        &pg_alert_snapshot.rows,
        &sq_alert_snapshot.rows,
    );

    let (pg_hour_empty, sq_hour_empty) = both(&fx, |s| {
        s.query_series_tiered(
            &series_query("ds-agent", &[], 3_600_000, 7_200_000, 100),
            BUCKET_1H_MS,
            SampleTier::OneHour,
        )
        .unwrap()
    });
    assert_series_eq("1h 边界 query", &pg_hour_empty, &sq_hour_empty);
    assert!(
        pg_hour_empty.is_empty(),
        "桶结束时间 == from 时必须排除该桶"
    );

    let (pg_stats, sq_stats) = both(&fx, |s| {
        (
            s.raw_stats().unwrap(),
            s.samples_1m_stats().unwrap(),
            s.samples_1h_stats().unwrap(),
        )
    });
    assert_eq!(pg_stats, sq_stats);
    assert_eq!(
        pg_stats.0,
        TierStats {
            rows: 6,
            oldest_ts: Some(1_000),
            newest_ts: Some(125_000)
        }
    );
    assert_eq!(
        pg_stats.1,
        TierStats {
            rows: 3,
            oldest_ts: Some(0),
            newest_ts: Some(120_000)
        }
    );
    assert_eq!(
        pg_stats.2,
        TierStats {
            rows: 1,
            oldest_ts: Some(0),
            newest_ts: Some(0)
        }
    );

    // 非法 bucket 必须在两层查询上都报错。
    let query = series_query("ds-agent", &[], 0, 180_000, 100);
    let (pg_zero, sq_zero) = both(&fx, |s| {
        s.query_series_tiered(&query, 0, SampleTier::OneMinute)
            .is_err()
    });
    assert!(pg_zero && sq_zero, "bucket_ms=0 必须被两层实现拒绝");
}

// ---------------------------------------------------------------------------
// 13. 保留期 prune 边界 / rowid 扫描 / claim CAS
// ---------------------------------------------------------------------------

#[test]
fn retention_prune_boundary_and_claim_cas_parity() {
    const NAME: &str = "retention_prune_boundary_and_claim_cas_parity";
    let Some(fx) = ParityFixture::new("retention") else {
        skip(NAME);
        return;
    };

    let batch = sample_batch(
        "ret-agent",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 1_000, 1.0),
            Sample::new("cpu.usage", 2_000, 2.0),
            Sample::new("cpu.usage", 3_000, 3.0),
            Sample::new("cpu.usage", 4_000, 4.0),
            Sample::new("cpu.usage", 5_000, 5.0),
        ],
    );

    let (pg_scan, sq_scan) = both(&fx, |s| {
        let outcome = s.insert_batch(&batch).unwrap();
        let raw_stats = s.raw_stats().unwrap();
        let new_none = s.raw_new_rows(None).unwrap();
        let new_last = s.raw_new_rows(Some(5)).unwrap();
        let new_mid = s.raw_new_rows(Some(3)).unwrap();
        let new_high = s.raw_new_rows(Some(99)).unwrap();
        let offsets = [
            s.raw_ts_at_offset(0, 6_000, 0).unwrap(),
            s.raw_ts_at_offset(0, 6_000, 3).unwrap(),
            s.raw_ts_at_offset(0, 6_000, 5).unwrap(),
            s.raw_ts_at_offset(2_000, 5_000, 2).unwrap(),
        ];
        let ds_1m = s.downsample_1m_range(0, 60_000).unwrap();
        let stats_1m = s.samples_1m_stats().unwrap();
        let ds_1h = s.downsample_1h_range(0, 7_200_000).unwrap();
        let stats_1h = s.samples_1h_stats().unwrap();
        (
            outcome, raw_stats, new_none, new_last, new_mid, new_high, offsets, ds_1m, stats_1m,
            ds_1h, stats_1h,
        )
    });
    assert_eq!(pg_scan, sq_scan, "保留期前的扫描结果必须一致");
    assert_eq!(pg_scan.0, IngestOutcome::Inserted { inserted: 5 });
    assert_eq!(
        pg_scan.1,
        TierStats {
            rows: 5,
            oldest_ts: Some(1_000),
            newest_ts: Some(5_000)
        }
    );
    assert_eq!(
        pg_scan.2,
        (Some(5), Some(1_000)),
        "raw_new_rows(None) 必须返回最大 rowid 与最旧 ts"
    );
    assert_eq!(
        pg_scan.3,
        (Some(5), None),
        "rowid 已认领到最大时必须返回 None 的 min ts"
    );
    assert_eq!(pg_scan.4, (Some(5), Some(4_000)), "after_rowid 必须排他");
    assert_eq!(
        pg_scan.5,
        (Some(5), Some(1_000)),
        "after_rowid 超过当前最大 rowid 时必须保守重扫全部"
    );
    assert_eq!(
        pg_scan.6,
        [Some(1_000), Some(4_000), None, Some(4_000)],
        "raw offset 必须按 (ts,rowid) 升序"
    );
    assert_eq!(
        pg_scan.7,
        DownsampleRangeResult {
            buckets: 1,
            rows: 5
        }
    );
    assert_eq!(
        pg_scan.8,
        TierStats {
            rows: 1,
            oldest_ts: Some(0),
            newest_ts: Some(0)
        }
    );
    assert_eq!(
        pg_scan.9,
        DownsampleRangeResult {
            buckets: 1,
            rows: 1
        }
    );
    assert_eq!(
        pg_scan.10,
        TierStats {
            rows: 1,
            oldest_ts: Some(0),
            newest_ts: Some(0)
        }
    );

    // prune：cutoff 排他、分批计数、重复清理幂等。
    let (pg_prune, sq_prune) = both(&fx, |s| {
        let raw = s.prune_samples_before(3_000).unwrap();
        let raw_repeat = s.prune_samples_before(3_000).unwrap();
        let one_minute = s.prune_samples_1m_before(3_000).unwrap();
        let one_minute_repeat = s.prune_samples_1m_before(3_000).unwrap();
        let one_hour = s.prune_samples_1h_before(3_600_000).unwrap();
        let one_hour_repeat = s.prune_samples_1h_before(3_600_000).unwrap();
        (
            raw,
            raw_repeat,
            one_minute,
            one_minute_repeat,
            one_hour,
            one_hour_repeat,
            s.raw_stats().unwrap(),
            s.samples_1m_stats().unwrap(),
            s.samples_1h_stats().unwrap(),
        )
    });
    assert_eq!(pg_prune, sq_prune, "prune 结果必须一致");
    assert_eq!(
        pg_prune.0,
        PruneResult {
            deleted: 2,
            batches: 1
        },
        "raw 只删除 ts < cutoff 的 2 行"
    );
    assert_eq!(pg_prune.1, PruneResult::default(), "重复 prune 必须幂等");
    assert_eq!(
        pg_prune.2,
        PruneResult {
            deleted: 1,
            batches: 1
        },
        "1m 只删除 bucket_ts < cutoff 的 1 个桶"
    );
    assert_eq!(pg_prune.3, PruneResult::default());
    assert_eq!(
        pg_prune.4,
        PruneResult {
            deleted: 1,
            batches: 1
        }
    );
    assert_eq!(pg_prune.5, PruneResult::default());
    assert_eq!(
        pg_prune.6,
        TierStats {
            rows: 3,
            oldest_ts: Some(3_000),
            newest_ts: Some(5_000)
        }
    );
    assert_eq!(pg_prune.7, TierStats::default());
    assert_eq!(
        pg_prune.8,
        TierStats {
            rows: 0,
            oldest_ts: None,
            newest_ts: None
        }
    );

    // prune 后 rowid 游标仍基于剩余最大 rowid。
    let (pg_after, sq_after) = both(&fx, |s| {
        (
            s.raw_new_rows(Some(5)).unwrap(),
            s.raw_new_rows(Some(3)).unwrap(),
            s.raw_ts_at_offset(0, 6_000, 0).unwrap(),
        )
    });
    assert_eq!(pg_after, sq_after);
    assert_eq!(pg_after.0, (Some(5), None));
    assert_eq!(pg_after.1, (Some(5), Some(4_000)));
    assert_eq!(pg_after.2, Some(3_000));

    // claim CAS：rowid 与 generation 都匹配才写入新水位。
    let claim_key = STATE_DOWNSAMPLE_1M_LAST_RAW_ROWID;
    let (pg_claim, sq_claim) = both(&fx, |s| {
        let initial = s.get_maintenance_state(claim_key).unwrap();
        let one = s.claim_raw_rowid_if_unchanged(None, 0, 5).unwrap();
        let key_after_one = s.get_maintenance_state(claim_key).unwrap();
        let two = s.claim_raw_rowid_if_unchanged(Some(5), 0, 6).unwrap();
        let key_after_two = s.get_maintenance_state(claim_key).unwrap();
        let stale_rowid = s.claim_raw_rowid_if_unchanged(Some(5), 0, 7).unwrap();
        let stale_generation = s.claim_raw_rowid_if_unchanged(Some(6), 1, 7).unwrap();
        let key_after_stale = s.get_maintenance_state(claim_key).unwrap();
        s.set_maintenance_state(STATE_RAW_PRUNE_GENERATION, "1", NOW)
            .unwrap();
        let three = s.claim_raw_rowid_if_unchanged(Some(6), 1, 7).unwrap();
        let key_after_three = s.get_maintenance_state(claim_key).unwrap();
        let absent_rowid = s.claim_raw_rowid_if_unchanged(None, 0, 8).unwrap();
        let generation = s.get_maintenance_state(STATE_RAW_PRUNE_GENERATION).unwrap();
        (
            initial,
            one,
            key_after_one,
            two,
            key_after_two,
            stale_rowid,
            stale_generation,
            key_after_stale,
            three,
            key_after_three,
            absent_rowid,
            generation,
        )
    });
    assert_eq!(pg_claim, sq_claim, "claim CAS 结果必须一致");
    assert_eq!(pg_claim.0, None);
    assert!(pg_claim.1);
    assert_eq!(pg_claim.2, Some("5".to_string()));
    assert!(pg_claim.3);
    assert_eq!(pg_claim.4, Some("6".to_string()));
    assert!(!pg_claim.5, "rowid 不匹配必须失败");
    assert!(!pg_claim.6, "generation 不匹配必须失败");
    assert_eq!(pg_claim.7, Some("6".to_string()), "失败不得写水位");
    assert!(pg_claim.8);
    assert_eq!(pg_claim.9, Some("7".to_string()));
    assert!(!pg_claim.10, "key 已存在时 expected=None 必须失败");
    assert_eq!(pg_claim.11, Some("1".to_string()));
}

// ---------------------------------------------------------------------------
// 14. 归档：objects CRUD / 状态机 / 分页 / 范围 / 水位 / raw scan
// ---------------------------------------------------------------------------

#[test]
fn archive_objects_status_range_scan_and_state_parity() {
    const NAME: &str = "archive_objects_status_range_scan_and_state_parity";
    let Some(fx) = ParityFixture::new("archive") else {
        skip(NAME);
        return;
    };

    let o1 = archive_object(
        "rustboard/2026/10/24/part-00001.csv.gz",
        100,
        200,
        ArchiveStatus::Uploaded,
    );
    let o2 = archive_object(
        "rustboard/2026/10/24/part-00002.csv.gz",
        300,
        400,
        ArchiveStatus::Uploaded,
    );
    let o3 = archive_object(
        "rustboard/2026/10/24/part-00003.csv.gz",
        300,
        350,
        ArchiveStatus::Failed,
    );
    let o4 = archive_object(
        "rustboard/2026/10/24/part-00004.csv.gz",
        500,
        600,
        ArchiveStatus::LocalDeleted,
    );

    let (pg_insert, sq_insert) = both(&fx, |s| {
        let ids = [
            s.insert_archive_object(&o1).unwrap(),
            s.insert_archive_object(&o2).unwrap(),
            s.insert_archive_object(&o3).unwrap(),
            s.insert_archive_object(&o4).unwrap(),
        ];
        (
            ids,
            strip_archive_ids(&s.list_archive_objects(100, None).unwrap()),
            s.count_archive_objects().unwrap(),
            s.find_archive_object_by_key(&o1.object_key).unwrap(),
            s.get_archive_object(9_999).unwrap(),
            s.find_archive_object_by_key("missing").unwrap(),
        )
    });
    assert_eq!(pg_insert, sq_insert, "归档对象插入 / 查询必须一致");
    assert!(pg_insert.0.iter().all(|id| *id > 0));
    assert!(
        pg_insert.0.windows(2).all(|pair| pair[0] < pair[1]),
        "归档对象 id 必须严格递增"
    );
    assert_eq!(pg_insert.1.len(), 4);
    assert_eq!(pg_insert.2, 4);
    assert_eq!(
        pg_insert.3.as_ref().map(|object| object.id),
        Some(pg_insert.0[0]),
        "find_archive_object_by_key 必须返回原记录 id"
    );
    assert_eq!(pg_insert.4, None);
    assert_eq!(pg_insert.5, None);
    assert_eq!(pg_insert.1[0].rows, 5_000_000_000);
    assert_eq!(pg_insert.1[0].bytes, 6_000_000_000);

    // object_key UNIQUE：冲突返回 ObjectExists，且不得改写原记录。
    let (pg_duplicate, sq_duplicate) = both(&fx, |s| {
        let mut duplicate = archive_object(
            "rustboard/2026/10/24/part-00001.csv.gz",
            999,
            1000,
            ArchiveStatus::Pending,
        );
        duplicate.backend = "s3".to_string();
        let err = archive_store_error(s.insert_archive_object(&duplicate).unwrap_err());
        (err, s.get_archive_object(1).unwrap())
    });
    assert_eq!(pg_duplicate, sq_duplicate);
    assert_eq!(pg_duplicate.0, ArchiveStoreError::ObjectExists);
    assert_eq!(
        pg_duplicate
            .1
            .as_ref()
            .map(|object| object.object_key.as_str()),
        Some(o1.object_key.as_str()),
        "唯一冲突不得修改原记录"
    );

    // 分页：id 倒序 + before_id 排他 + limit=0。
    let (pg_pages, sq_pages) = both(&fx, |s| {
        let page_1 = s.list_archive_objects(2, None).unwrap();
        let page_2 = s.list_archive_objects(2, Some(page_1[1].id)).unwrap();
        let zero = s.list_archive_objects(0, None).unwrap();
        let before_zero = s.list_archive_objects(10, Some(0)).unwrap();
        (
            page_1.iter().map(|object| object.id).collect::<Vec<_>>(),
            page_2.iter().map(|object| object.id).collect::<Vec<_>>(),
            zero,
            before_zero,
        )
    });
    assert_eq!(pg_pages, sq_pages);
    assert_eq!(pg_pages.0, vec![pg_insert.0[3], pg_insert.0[2]]);
    assert_eq!(pg_pages.1, vec![pg_insert.0[1], pg_insert.0[0]]);
    assert!(pg_pages.2.is_empty());
    assert!(pg_pages.3.is_empty());

    // 状态机：合法迁移、时间戳保留、终态保护、失败重试、NotFound。
    let (pg_status, sq_status) = both(&fx, |s| {
        let first_id = pg_insert.0[0];
        let second_id = pg_insert.0[1];
        s.update_archive_object_status(first_id, ArchiveStatus::Uploaded, "", Some(1_100), None)
            .unwrap();
        let uploaded = s.get_archive_object(first_id).unwrap().unwrap();
        s.update_archive_object_status(
            first_id,
            ArchiveStatus::LocalDeleted,
            "",
            None,
            Some(1_200),
        )
        .unwrap();
        let deleted = s.get_archive_object(first_id).unwrap().unwrap();
        let mut invalid = Vec::new();
        for next in [
            ArchiveStatus::Pending,
            ArchiveStatus::Uploaded,
            ArchiveStatus::Failed,
        ] {
            invalid.push(archive_store_error(
                s.update_archive_object_status(first_id, next, "", None, None)
                    .unwrap_err(),
            ));
        }
        s.update_archive_object_status(first_id, ArchiveStatus::LocalDeleted, "", None, None)
            .unwrap();
        let idempotent = s.get_archive_object(first_id).unwrap().unwrap();
        s.update_archive_object_status(second_id, ArchiveStatus::Failed, "backend 500", None, None)
            .unwrap();
        let failed = s.get_archive_object(second_id).unwrap().unwrap();
        s.update_archive_object_status(second_id, ArchiveStatus::Pending, "", None, None)
            .unwrap();
        let retried = s.get_archive_object(second_id).unwrap().unwrap();
        let not_found = archive_store_error(
            s.update_archive_object_status(9_999, ArchiveStatus::Uploaded, "", None, None)
                .unwrap_err(),
        );
        (
            uploaded, deleted, invalid, idempotent, failed, retried, not_found,
        )
    });
    assert_eq!(pg_status, sq_status, "归档状态机结果必须一致");
    assert_eq!(pg_status.0.status, ArchiveStatus::Uploaded);
    assert_eq!(pg_status.0.uploaded_at, Some(1_100));
    assert_eq!(pg_status.0.deleted_at, None);
    assert_eq!(pg_status.0.error, "");
    assert_eq!(pg_status.1.status, ArchiveStatus::LocalDeleted);
    assert_eq!(
        pg_status.1.uploaded_at,
        Some(1_100),
        "local_deleted 迁移不得清空 uploaded_at"
    );
    assert_eq!(pg_status.1.deleted_at, Some(1_200));
    assert_eq!(
        pg_status.2,
        vec![
            ArchiveStoreError::InvalidTransition,
            ArchiveStoreError::InvalidTransition,
            ArchiveStoreError::InvalidTransition
        ],
        "local_deleted 是终态，不能回到任何其它状态"
    );
    assert_eq!(pg_status.3.status, ArchiveStatus::LocalDeleted);
    assert_eq!(
        pg_status.3.uploaded_at,
        Some(1_100),
        "同状态幂等更新不得清空历史时间戳"
    );
    assert_eq!(pg_status.4.status, ArchiveStatus::Failed);
    assert_eq!(pg_status.4.error, "backend 500");
    assert_eq!(pg_status.5.status, ArchiveStatus::Pending);
    assert_eq!(pg_status.5.error, "", "重试时应清空旧错误");
    assert_eq!(pg_status.6, ArchiveStoreError::NotFound);

    // 范围查询：两端包含、按 from_ts,id 升序、不按状态过滤。
    let (pg_range, sq_range) = both(&fx, |s| {
        (
            s.list_archive_objects_in_range(200, 300)
                .unwrap()
                .iter()
                .map(|object| object.id)
                .collect::<Vec<_>>(),
            s.list_archive_objects_in_range(201, 299).unwrap(),
            s.list_archive_objects_in_range(600, 600)
                .unwrap()
                .iter()
                .map(|object| object.id)
                .collect::<Vec<_>>(),
            s.list_archive_objects_in_range(0, 1_000).unwrap().len(),
        )
    });
    assert_eq!(pg_range, sq_range, "归档范围查询必须一致");
    assert_eq!(
        pg_range.0,
        vec![pg_insert.0[0], pg_insert.0[1], pg_insert.0[2]],
        "边界包含且同 from_ts 按 id 升序"
    );
    assert!(pg_range.1.is_empty());
    assert_eq!(pg_range.2, vec![pg_insert.0[3]]);
    assert_eq!(pg_range.3, 4);

    // 归档水位：UPSERT + 注入字符串按值处理。
    let (pg_state, sq_state) = both(&fx, |s| {
        s.set_archive_state("last_archived_ts", "100", 1_000)
            .unwrap();
        s.set_archive_state("last_downsample_ts", "50", 900)
            .unwrap();
        s.set_archive_state("last_archived_ts", "200", 2_000)
            .unwrap();
        let key = "k'quote";
        let value = "v'; DROP TABLE archive_state; --";
        s.set_archive_state(key, value, 3_000).unwrap();
        (
            s.get_archive_state("last_archived_ts").unwrap(),
            s.get_archive_state("last_downsample_ts").unwrap(),
            s.get_archive_state("missing").unwrap(),
            s.get_archive_state(key).unwrap(),
            s.get_archive_state("last_archived_ts").unwrap(),
        )
    });
    assert_eq!(pg_state, sq_state, "归档水位结果必须一致");
    assert_eq!(pg_state.0, Some("200".to_string()));
    assert_eq!(pg_state.1, Some("50".to_string()));
    assert_eq!(pg_state.2, None);
    assert_eq!(
        pg_state.3,
        Some("v'; DROP TABLE archive_state; --".to_string()),
        "注入字符串必须原样存储"
    );
    assert_eq!(pg_state.4, Some("200".to_string()), "注入不得破坏已有水位");

    // scan_archive_rows：rowid 升序、[from,to) 左闭右开、after_rowid 排他、labels 原样。
    let scan_batch = sample_batch(
        "arch-agent",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 1_000, 1.0).with_label("host", "h0"),
            Sample::new("cpu.usage", 2_000, 2.0).with_label("host", "h1"),
            Sample::new("cpu.usage", 3_000, 3.0).with_label("host", "h2"),
            Sample::new("cpu.usage", 10_000, 10.0).with_label("host", "h3"),
        ],
    );
    let (pg_scan, sq_scan) = both(&fx, |s| {
        let outcome = s.insert_batch(&scan_batch).unwrap();
        let first = s.scan_archive_rows(1_000, 10_000, None, 2).unwrap();
        let second = s
            .scan_archive_rows(1_000, 10_000, Some(first[1].rowid), 2)
            .unwrap();
        let end = s
            .scan_archive_rows(1_000, 10_000, Some(second[0].rowid), 2)
            .unwrap();
        let zero_limit = s.scan_archive_rows(1_000, 10_000, None, 0).unwrap();
        let boundary_only = s.scan_archive_rows(10_000, 11_000, None, 10).unwrap();
        let empty_range = s.scan_archive_rows(20_000, 30_000, None, 10).unwrap();
        (
            outcome,
            first,
            second,
            end,
            zero_limit,
            boundary_only,
            empty_range,
        )
    });
    assert_eq!(pg_scan, sq_scan, "归档 raw scan 结果必须一致");
    assert_eq!(pg_scan.0, IngestOutcome::Inserted { inserted: 4 });
    assert_eq!(
        pg_scan.1.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![1_000, 2_000],
        "scan 必须按 rowid 升序"
    );
    assert!(pg_scan.1[0].rowid < pg_scan.1[1].rowid);
    assert_eq!(pg_scan.1[0].agent_id, "arch-agent");
    assert_eq!(pg_scan.1[0].metric, "cpu.usage");
    assert_eq!(pg_scan.1[0].labels, r#"{"host":"h0"}"#);
    assert_f64_close(pg_scan.1[0].value, 1.0, "scan value");
    assert_eq!(
        pg_scan.2.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![3_000],
        "after_rowid 必须排他"
    );
    assert!(pg_scan.2[0].rowid > pg_scan.1[1].rowid);
    assert!(pg_scan.3.is_empty());
    assert!(pg_scan.4.is_empty(), "limit=0 必须返回空");
    assert_eq!(
        pg_scan.5.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![10_000],
        "左闭右开范围必须包含 from"
    );
    assert!(pg_scan.6.is_empty());
    assert_eq!(pg_insert.2, 4, "archived objects count 不得被 scan 影响");
}

// ---------------------------------------------------------------------------
// 15. Core 冒烟：agent / settings / enroll / secret / control / ingest 幂等
// ---------------------------------------------------------------------------

#[test]
fn core_storage_smoke_parity() {
    const NAME: &str = "core_storage_smoke_parity";
    let Some(fx) = ParityFixture::new("core") else {
        skip(NAME);
        return;
    };

    let (pg_agents, sq_agents) = both(&fx, |s| {
        s.upsert_agent(&agent_record("a1", "pending", 100)).unwrap();
        s.upsert_agent(&agent_record("a2", "pending", 200)).unwrap();
        s.upsert_agent(&agent_record("a3", "online", 300)).unwrap();
        s.revoke_agent("a3", 350).unwrap();
        s.upsert_agent(&agent_record("a3", "online", 400)).unwrap();
        s.mark_seen("a3", 999).unwrap();
        s.set_status("a3", "online", 1000).unwrap();
        s.mark_seen("a1", 150).unwrap();
        s.set_status("a2", "offline", 250).unwrap();
        let reset = s.reset_online_status().unwrap();
        (
            reset,
            s.list_agents().unwrap(),
            s.get_agent("a1").unwrap(),
            s.get_agent("a3").unwrap(),
            s.is_revoked("a1").unwrap(),
            s.is_revoked("a3").unwrap(),
        )
    });
    assert_eq!(pg_agents, sq_agents, "agent 生命周期必须一致");
    assert_eq!(pg_agents.0, 1, "只应重置 a1 的 online 状态");
    let a1 = pg_agents.2.as_ref().expect("a1 必须存在");
    assert_eq!(a1.status, "offline");
    assert_eq!(a1.last_seen_at, 150);
    let a3 = pg_agents.3.as_ref().expect("a3 必须存在");
    assert_eq!(a3.status, "revoked", "revoked 是终态");
    assert_eq!(a3.name, "Node a3");
    assert_eq!(a3.last_seen_at, 1000);
    assert_eq!((pg_agents.4, pg_agents.5), (false, true));

    let (pg_settings, sq_settings) = both(&fx, |s| {
        let absent = s.get_sample_interval("a1").unwrap();
        s.set_sample_interval("a1", 5_000, 1_000).unwrap();
        s.set_sample_interval("a2", 7_000, 2_000).unwrap();
        s.set_sample_interval("a1", 6_000, 3_000).unwrap();
        let overflow = s.set_sample_interval("a1", u64::MAX, 4_000).is_err();
        (
            absent,
            s.list_sample_intervals().unwrap(),
            s.get_sample_interval("a1").unwrap(),
            overflow,
            s.get_sample_interval("a1").unwrap(),
        )
    });
    assert_eq!(pg_settings, sq_settings);
    assert_eq!(pg_settings.0, None);
    assert_eq!(
        pg_settings.1,
        vec![("a1".to_string(), 6_000), ("a2".to_string(), 7_000)]
    );
    assert_eq!(pg_settings.2, Some(6_000));
    assert!(pg_settings.3, "u64 超出 BIGINT 必须报错");
    assert_eq!(pg_settings.4, Some(6_000), "溢出失败不得破坏已有值");

    let (pg_secret, sq_secret) = both(&fx, |s| {
        let before_verify = s.verify_agent_secret("a4", "secret-hash").unwrap();
        s.set_agent_secret("a4", "secret-hash", 1_000).unwrap();
        let correct = s.verify_agent_secret("a4", "secret-hash").unwrap();
        let wrong = s.verify_agent_secret("a4", "other").unwrap();
        s.set_agent_secret("a4", "secret-hash-2", 1_100).unwrap();
        let old = s.verify_agent_secret("a4", "secret-hash").unwrap();
        let new = s.verify_agent_secret("a4", "secret-hash-2").unwrap();
        s.revoke_agent("a4", 1_200).unwrap();
        let after_revoke = s.verify_agent_secret("a4", "secret-hash-2").unwrap();

        s.create_enroll_token("hash-1", "enrolled-agent", 100, 1_000)
            .unwrap();
        let consumed = s.consume_enroll_token("hash-1", 500).unwrap();
        let consumed_again = s.consume_enroll_token("hash-1", 600).unwrap();
        s.create_enroll_token("hash-2", "expired-agent", 100, 1_000)
            .unwrap();
        let expired_boundary = s.consume_enroll_token("hash-2", 1_000).unwrap();
        let unknown = s.consume_enroll_token("missing", 500).unwrap();
        (
            before_verify,
            correct,
            wrong,
            old,
            new,
            after_revoke,
            consumed,
            consumed_again,
            expired_boundary,
            unknown,
        )
    });
    assert_eq!(pg_secret, sq_secret, "enroll / secret 结果必须一致");
    assert_eq!(
        (
            pg_secret.0,
            pg_secret.1,
            pg_secret.2,
            pg_secret.3,
            pg_secret.4,
            pg_secret.5
        ),
        (false, true, false, false, true, false)
    );
    assert_eq!(pg_secret.6.as_deref(), Some("enrolled-agent"));
    assert_eq!(pg_secret.7, None, "enroll token 必须一次性");
    assert_eq!(pg_secret.8, None, "expires_at == now 必须视为过期");
    assert_eq!(pg_secret.9, None);

    let (pg_control, sq_control) = both(&fx, |s| {
        let absent = s.get_agent_control("a5").unwrap();
        let capabilities = vec!["systemd".to_string(), "docker".to_string()];
        s.upsert_agent_control("a5", &capabilities, 1_500).unwrap();
        let control = s.get_agent_control("a5").unwrap();
        s.upsert_agent_control("a5", &[], 1_600).unwrap();
        (absent, control, s.get_agent_control("a5").unwrap())
    });
    assert_eq!(pg_control, sq_control, "控制能力结果必须一致");
    assert_eq!(pg_control.0, None);
    assert_eq!(
        pg_control
            .1
            .as_ref()
            .map(|record| record.capabilities.clone()),
        Some(vec!["systemd".to_string(), "docker".to_string()])
    );
    assert_eq!(
        pg_control
            .2
            .as_ref()
            .map(|record| record.capabilities.clone()),
        Some(Vec::new()),
        "空能力也必须覆盖持久化"
    );

    let batch = sample_batch(
        "a1",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 1_000, 10.0),
            Sample::new("cpu.usage", 1_000, 15.0).with_label("core", "0"),
            Sample::new("mem.used", 1_000, 1024.0),
        ],
    );
    let altered = sample_batch("a1", 1, 0, vec![Sample::new("cpu.usage", 2_000, 999.0)]);
    let later = sample_batch("a1", 1, 5, vec![Sample::new("cpu.usage", 3_000, 5.0)]);
    let out_of_order = sample_batch("a1", 1, 3, vec![Sample::new("cpu.usage", 2_500, 3.0)]);
    let revoked_batch = sample_batch("a2", 1, 0, vec![Sample::new("cpu.usage", 1_000, 1.0)]);
    let (pg_ingest, sq_ingest) = both(&fx, |s| {
        s.revoke_agent("a2", 300).unwrap();
        (
            s.insert_batch(&batch).unwrap(),
            s.insert_batch(&batch).unwrap(),
            s.insert_batch(&altered).unwrap(),
            s.insert_batch(&later).unwrap(),
            s.insert_batch(&out_of_order).unwrap(),
            s.insert_batch(&revoked_batch).unwrap(),
            s.sample_count("a1").unwrap(),
            s.sample_count("a2").unwrap(),
        )
    });
    assert_eq!(
        pg_ingest, sq_ingest,
        "ingest 幂等 / 乱序 / 吊销结果必须一致"
    );
    assert_eq!(pg_ingest.0, IngestOutcome::Inserted { inserted: 3 });
    assert_eq!(pg_ingest.1, IngestOutcome::Duplicate);
    assert_eq!(pg_ingest.2, IngestOutcome::Duplicate);
    assert_eq!(pg_ingest.3, IngestOutcome::Inserted { inserted: 1 });
    assert_eq!(pg_ingest.4, IngestOutcome::Inserted { inserted: 1 });
    assert_eq!(pg_ingest.5, IngestOutcome::Rejected(RejectReason::Revoked));
    assert_eq!(pg_ingest.6, 5);
    assert_eq!(pg_ingest.7, 0);

    let query = series_query("a1", &[], 0, i64::MAX, 100);
    let (pg_rows, sq_rows) = both(&fx, |s| s.query_series(&query).unwrap());
    assert_series_eq("core query_series", &pg_rows, &sq_rows);
    assert_eq!(
        pg_rows.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![1_000, 1_000, 1_000, 2_500, 3_000]
    );
    let (pg_latest, sq_latest) = both(&fx, |s| s.latest_samples(0, &[], Some("a1")).unwrap());
    assert_agent_series_eq("core latest_samples", &pg_latest, &sq_latest);
    assert_eq!(pg_latest.len(), 3);
}

// ---------------------------------------------------------------------------
// 16. 查询 / 边界：时间边界、排序、limit、特殊 labels、SQL 注入字符串
// ---------------------------------------------------------------------------

#[test]
fn query_boundaries_and_special_values_parity() {
    const NAME: &str = "query_boundaries_and_special_values_parity";
    let Some(fx) = ParityFixture::new("query") else {
        skip(NAME);
        return;
    };

    let special_labels = labels(&[("path", "/"), ("tag", "a\"b\\c\n中文"), ("空", "")]);
    let mut special = Sample::new("mem.used", 2_000, 512.0);
    special.labels = special_labels.clone();

    let batch = sample_batch(
        "q1",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 1_000, 1.0),
            Sample::new("cpu.usage", 2_000, 2.0),
            Sample::new("cpu.usage", 3_000, 3.0),
            Sample::new("cpu.usage", 1_000, 10.0).with_label("core", "0"),
            special,
            Sample::new("disk.io", 1_000, 7.0),
            Sample::new("cpu.usage'; DROP TABLE samples; --", 4_000, 42.0),
        ],
    );
    let injected_agent = "agent-1'; DROP TABLE samples; --";
    let injected_batch = sample_batch(
        injected_agent,
        1,
        0,
        vec![Sample::new("cpu.usage", 5_000, 99.0)],
    );

    let (pg_insert, sq_insert) = both(&fx, |s| {
        let first = s.insert_batch(&batch).unwrap();
        let second = s.insert_batch(&injected_batch).unwrap();
        (
            first,
            second,
            s.sample_count("q1").unwrap(),
            s.sample_count(injected_agent).unwrap(),
        )
    });
    assert_eq!(pg_insert, sq_insert);
    assert_eq!(pg_insert.0, IngestOutcome::Inserted { inserted: 7 });
    assert_eq!(pg_insert.1, IngestOutcome::Inserted { inserted: 1 });
    assert_eq!(pg_insert.2, 7);
    assert_eq!(pg_insert.3, 1);

    // 时间边界：[from, to] 双闭；limit 在排序后生效。
    let cases = [
        (series_query("q1", &[], 0, 10_000, 100), 7usize),
        (series_query("q1", &[], 1_000, 2_000, 100), 5),
        (series_query("q1", &[], 2_000, 10_000, 100), 4),
        (series_query("q1", &[], 0, 999, 100), 0),
        (series_query("q1", &[], 2_000, 2_000, 100), 2),
        (series_query("q1", &[], 0, 10_000, 2), 2),
        (series_query("q1", &[], 0, 10_000, 0), 0),
        (series_query("q1", &["mem.used"], 0, 10_000, 100), 1),
        (series_query("q1", &["missing"], 0, 10_000, 100), 0),
    ];
    for (query, expected_len) in cases {
        let (pg_rows, sq_rows) = both(&fx, |s| s.query_series(&query).unwrap());
        assert_series_eq("query_series 边界", &pg_rows, &sq_rows);
        assert_eq!(
            pg_rows.len(),
            expected_len,
            "query_series 行数不符（from={} to={} limit={}）",
            query.from,
            query.to,
            query.limit
        );
    }

    let (pg_all, sq_all) = both(&fx, |s| {
        s.query_series(&series_query("q1", &[], 0, 10_000, 100))
            .unwrap()
    });
    assert_series_eq("全量查询", &pg_all, &sq_all);
    assert_eq!(
        pg_all.iter().map(|row| row.ts).collect::<Vec<_>>(),
        vec![1_000, 1_000, 1_000, 2_000, 2_000, 3_000, 4_000],
        "query_series 必须按 ts 升序"
    );
    let special_row = pg_all
        .iter()
        .find(|row| row.metric == "mem.used")
        .expect("特殊 labels 行必须存在");
    assert_eq!(
        special_row.labels, special_labels,
        "特殊 labels 必须逐字段往返（引号/反斜杠/换行/中文/空值）"
    );
    let injected_row = pg_all
        .iter()
        .find(|row| row.metric == "cpu.usage'; DROP TABLE samples; --")
        .expect("注入字符串 metric 必须按字面量存储");
    assert_f64_close(injected_row.value, 42.0, "注入 metric 行 value");

    // bucketed / tiered：bucket_ms 非法必须报错，Raw 层与 bucketed 一致。
    let query = series_query("q1", &[], 0, 10_000, 100);
    let (pg_bucket, sq_bucket) = both(&fx, |s| s.query_series_bucketed(&query, 1_000).unwrap());
    assert_series_eq("bucketed 查询", &pg_bucket, &sq_bucket);
    assert_eq!(
        pg_bucket.len(),
        7,
        "分组后应保留 7 个 (metric,labels,bucket)"
    );
    let (pg_tier, sq_tier) = both(&fx, |s| {
        s.query_series_tiered(&query, 1_000, SampleTier::Raw)
            .unwrap()
    });
    assert_series_eq("Raw tiered 查询", &pg_tier, &sq_tier);
    assert_eq!(pg_tier.len(), pg_bucket.len());
    let (pg_bad_bucket, sq_bad_bucket) = both(&fx, |s| s.query_series_bucketed(&query, 0).is_err());
    assert!(pg_bad_bucket && sq_bad_bucket, "bucket_ms=0 必须报错");

    // latest_samples：since 边界、去重、agent 过滤、特殊 labels。
    let (pg_latest, sq_latest) = both(&fx, |s| s.latest_samples(0, &[], None).unwrap());
    assert_agent_series_eq("latest_samples 全量", &pg_latest, &sq_latest);
    assert_eq!(pg_latest.len(), 6, "两个 agent 共 6 条序列");
    let (pg_latest_q1, sq_latest_q1) = both(&fx, |s| s.latest_samples(0, &[], Some("q1")).unwrap());
    assert_agent_series_eq("latest_samples q1", &pg_latest_q1, &sq_latest_q1);
    assert_eq!(pg_latest_q1.len(), 5);
    let latest_cpu = pg_latest_q1
        .iter()
        .find(|row| row.metric == "cpu.usage" && row.labels.is_empty())
        .expect("cpu.usage 无 labels 序列必须存在");
    assert_eq!(latest_cpu.ts, 3_000);
    assert_f64_close(latest_cpu.value, 3.0, "latest_samples 最新值");
    let latest_special = pg_latest_q1
        .iter()
        .find(|row| row.metric == "mem.used")
        .expect("special series 必须存在");
    assert_eq!(latest_special.labels, special_labels);
    let (pg_since, sq_since) = both(&fx, |s| s.latest_samples(3_001, &[], Some("q1")).unwrap());
    assert_agent_series_eq("latest_samples since", &pg_since, &sq_since);
    assert_eq!(pg_since.len(), 1, "since 排他，只应留下 ts=4000 的序列");
    assert_eq!(pg_since[0].ts, 4_000);
    let (pg_metric, sq_metric) = both(&fx, |s| {
        s.latest_samples(0, &["mem.used".to_string()], None)
            .unwrap()
    });
    assert_agent_series_eq("latest_samples metric 过滤", &pg_metric, &sq_metric);
    assert_eq!(pg_metric.len(), 1);
    let (pg_missing, sq_missing) = both(&fx, |s| {
        s.latest_samples(0, &["missing".to_string()], None).unwrap()
    });
    assert!(pg_missing.is_empty() && sq_missing.is_empty());

    // latest_alert_series：raw-only 快照，按 (agent_id, labels) 排序，limit 截断。
    let (pg_snapshot, sq_snapshot) = both(&fx, |s| {
        s.latest_alert_series("cpu.usage", 0, None, 100).unwrap()
    });
    assert_eq!(
        pg_snapshot.truncated, sq_snapshot.truncated,
        "latest_alert_series truncated 必须一致"
    );
    assert_agent_series_eq(
        "latest_alert_series 全量",
        &pg_snapshot.rows,
        &sq_snapshot.rows,
    );
    assert_eq!(pg_snapshot.rows.len(), 3);
    assert!(!pg_snapshot.truncated);
    let (pg_snapshot_agent, sq_snapshot_agent) = both(&fx, |s| {
        s.latest_alert_series("cpu.usage", 1_000, Some("q1"), 100)
            .unwrap()
    });
    assert_agent_series_eq(
        "latest_alert_series agent 过滤",
        &pg_snapshot_agent.rows,
        &sq_snapshot_agent.rows,
    );
    assert_eq!(pg_snapshot_agent.rows.len(), 2);
    assert!(!pg_snapshot_agent.truncated);
    let (pg_snapshot_limit, sq_snapshot_limit) = both(&fx, |s| {
        s.latest_alert_series("cpu.usage", 1_000, Some("q1"), 1)
            .unwrap()
    });
    assert_eq!(pg_snapshot_limit.rows.len(), 1);
    assert!(pg_snapshot_limit.truncated);
    assert_eq!(
        pg_snapshot_limit.truncated, sq_snapshot_limit.truncated,
        "latest_alert_series limit 截断标记必须一致"
    );
    assert_agent_series_eq(
        "latest_alert_series limit",
        &pg_snapshot_limit.rows,
        &sq_snapshot_limit.rows,
    );

    // SQL 注入字符串只作为值：表结构完好，后续写入 / 查询仍然正常。
    let (pg_intact, sq_intact) = both(&fx, |s| {
        let extra = sample_batch("q1", 2, 0, vec![Sample::new("cpu.usage", 6_000, 6.0)]);
        let inserted = s.insert_batch(&extra).unwrap();
        (
            inserted,
            s.sample_count("q1").unwrap(),
            s.sample_count(injected_agent).unwrap(),
            s.query_series(&series_query(
                "q1",
                &["cpu.usage'; DROP TABLE samples; --"],
                0,
                10_000,
                10,
            ))
            .unwrap()
            .len(),
        )
    });
    assert_eq!(pg_intact, sq_intact);
    assert_eq!(pg_intact.0, IngestOutcome::Inserted { inserted: 1 });
    assert_eq!(pg_intact.1, 8, "注入字符串不得改变表结构或丢数据");
    assert_eq!(pg_intact.2, 1);
    assert_eq!(pg_intact.3, 1);
}

// __PARITY_TEST_APPEND__
