//! SQLite v9 → PostgreSQL 离线迁移与校验（M5 Phase D5 核心）。
//!
//! 本模块只实现「读 SQLite、写 PostgreSQL、校验、回滚」的核心逻辑；CLI
//! （`hub migrate --to ... --dry-run/--force/--yes`）、迁移前 `VACUUM INTO`
//! 备份、配置切换与目标非空时的 `--force` 清空/备份属于 D5b，不在本文件。
//!
//! # 目标库必须为空
//!
//! [`validate_target_empty`] 的判定：
//!
//! - 22 张业务表**全部不存在或没有行**；
//! - `schema_migrations` 不存在 / 没有版本行且没有任何业务表（真正的空库），
//!   或版本为 v9 且 22 张表/23 个命名索引完整（允许「schema 已 apply 但业务表
//!   全空」）；
//! - 版本高于本程序支持的版本时明确拒绝，避免旧二进制写坏新库；
//! - `0 < version < 9`、版本 0 但已有业务表、自称 v9 但对象不完整时**一律拒绝**：
//!   CLI 的 `--force` 会在本校验通过后才 `pg_dump`/`TRUNCATE`，旧库绝不能被清空。
//!
//! 非空目标返回可读错误，**不覆盖任何数据**。`--force` 的备份 + 清空由 CLI
//! 先完成，再调用本模块；核心函数没有隐式 force 参数，避免误覆盖。
//!
//! # 源库只读
//!
//! 源 SQLite 用 [`OpenFlags::SQLITE_OPEN_READ_ONLY`] 打开，并在一个
//! `BEGIN DEFERRED` 只读快照内完成全部读取；不会执行 `VACUUM`、
//! checkpoint、`PRAGMA journal_mode` 或任何写语句，不改源库与 WAL。
//!
//! # 单事务导入
//!
//! 1. 先调用 [`PostgresStorage::apply_schema`] 幂等补齐 schema v9；
//! 2. 在一个 PostgreSQL 事务内取固定 key 的**事务级 advisory lock**，再对 22
//!    张业务表取 `SHARE` 表锁，阻止其他实例在导入期间写入；
//! 3. 再次校验目标为空（防止 `apply_schema` 与导入之间的竞态）；
//! 4. 按 [`TABLE_SPECS`] 的固定顺序逐表导入，每张表先读源库行数/范围；
//! 5. 恢复 9 个 `BIGSERIAL` 序列到 `MAX(id)`；
//! 6. 在**同一事务**内校验行数、samples/1m/1h 的 id 与时间范围、
//!    alert_states/alert_events 数量、api_tokens 哈希数量、archive_objects
//!    数量以及 `maintenance_state` 的 rowid 水位；
//! 7. 全部通过才 `COMMIT`。任何一步失败都回滚整个事务，目标库不会留下部分行。
//!
//! 目标写入期间其他实例不能写这 22 张表；离线迁移完成后才恢复写入。
//!
//! # 行序与 ID
//!
//! 表之间只有 `alert_rule_channels` 的三条外键，按 PostgreSQL schema 的声明
//! 顺序导入即可（被引用的 `alert_rules` / `notification_channels` 都排在它前面）。SQLite 的
//! `samples` / `samples_1m` / `samples_1h` / `alert_states` 没有显式 `id`，
//! 用 `rowid AS id` 导出并显式写入 PG 的 `id`；`audit_log` / `api_tokens` /
//! `alert_events` / `alert_silences` / `archive_objects` 的
//! `INTEGER PRIMARY KEY AUTOINCREMENT` 也按原值写入。最后对 9 个
//! `BIGSERIAL` 序列执行 `setval(MAX(id))`，保证后续插入不会撞主键。
//!
//! 这样 `maintenance_state.downsample_1m_last_raw_rowid` 里的 rowid 水位仍指向
//! 同一行（D4b/D3 的 `ORDER BY ts DESC, id DESC` 与删除游标语义不变）。
//!
//! # 类型映射
//!
//! - SQLite 布尔列（`INTEGER 0/1`）→ PG `BOOLEAN`；非 0/1 直接报错；
//! - SQLite `REAL` → PG `DOUBLE PRECISION`，`INTEGER` 计数/时间 → `BIGINT`；
//! - `labels` / `filter_labels` / `channel_ids` / `config_json` 等 `TEXT`
//!   原样复制（JSON 序列化格式不变）；`NULL` 原样保留；
//! - 所有值只通过 `$N` 绑定，表名/列名只来自本文件的常量，绝不拼用户值。
//!
//! # 批量与错误
//!
//! 每批最多 [`BATCH_ROWS`] 行，使用多行 `INSERT ... VALUES ($1, ...)`；
//! 5000 行 samples 只需 10 次网络往返。错误只带表名/列名/行号，不输出行内容；
//! `PostgresStorage::with_client` 只追加脱敏后的 DSN，不泄露密码。

use std::fmt::Write as _;
use std::path::Path;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use postgres::types::ToSql;
use postgres::Transaction;
use rusqlite::types::ValueRef;
use rusqlite::{Connection as SqliteConnection, OpenFlags, OptionalExtension};
use serde::Serialize;

use super::postgres::schema::{
    any_business_table_exists, bail_old_schema, ensure_schema_objects, POSTGRES_SCHEMA_VERSION,
    SCHEMA_ADVISORY_LOCK_KEY,
};
use super::postgres::PostgresStorage;

/// 本模块支持的 SQLite schema 版本；必须与 `sqlite.rs` 的 `SCHEMA_VERSION` 对齐。
pub const SQLITE_SCHEMA_VERSION: i64 = 9;

/// 单批最多导出的行数。
///
/// 最宽的表有 18 列（`alert_rules`），500 行 × 18 = 9000 个绑定参数，低于
/// PostgreSQL 的 65535 上限；5000 行 samples 只有 10 批。
const BATCH_ROWS: usize = 500;

/// `maintenance_state` 中记录降采样已认领 raw rowid 的键。
const DOWNSAMPLE_ROWID_KEY: &str = "downsample_1m_last_raw_rowid";

/// `maintenance_state` 中记录 raw prune 代际的键。
const RAW_PRUNE_GENERATION_KEY: &str = "raw_prune_generation";

/// PostgreSQL 列类型（只覆盖迁移需要的四种）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    Int,
    Real,
    Bool,
}

impl Kind {
    const fn name(self) -> &'static str {
        match self {
            Self::Text => "TEXT",
            Self::Int => "BIGINT",
            Self::Real => "DOUBLE PRECISION",
            Self::Bool => "BOOLEAN",
        }
    }
}

/// 目标表的一列：列名、PG 类型、是否允许 NULL。
#[derive(Debug, Clone, Copy)]
struct Column {
    name: &'static str,
    kind: Kind,
    nullable: bool,
}

const fn text(name: &'static str) -> Column {
    Column {
        name,
        kind: Kind::Text,
        nullable: false,
    }
}

const fn text_null(name: &'static str) -> Column {
    Column {
        name,
        kind: Kind::Text,
        nullable: true,
    }
}

const fn int(name: &'static str) -> Column {
    Column {
        name,
        kind: Kind::Int,
        nullable: false,
    }
}

const fn int_null(name: &'static str) -> Column {
    Column {
        name,
        kind: Kind::Int,
        nullable: true,
    }
}

const fn real(name: &'static str) -> Column {
    Column {
        name,
        kind: Kind::Real,
        nullable: false,
    }
}

const fn real_null(name: &'static str) -> Column {
    Column {
        name,
        kind: Kind::Real,
        nullable: true,
    }
}

const fn boolean(name: &'static str) -> Column {
    Column {
        name,
        kind: Kind::Bool,
        nullable: false,
    }
}

/// SQLite 侧 id 的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdSource {
    /// 没有显式 id（文本主键表）。
    None,
    /// SQLite 隐式 `rowid`，映射到 PG 新增的 `id BIGSERIAL`。
    Rowid,
    /// SQLite 已有显式 `id INTEGER PRIMARY KEY AUTOINCREMENT`。
    Column,
}

/// 一张表的迁移规则。列顺序必须与 PG schema 的列顺序一致。
#[derive(Debug, Clone, Copy)]
struct TableSpec {
    name: &'static str,
    columns: &'static [Column],
    id_source: IdSource,
    /// 可选的「时间范围」列，用于报告与校验。
    time_column: Option<&'static str>,
}

impl TableSpec {
    const fn has_id(self) -> bool {
        !matches!(self.id_source, IdSource::None)
    }

    const fn source_id_expr(self) -> Option<&'static str> {
        match self.id_source {
            IdSource::None => None,
            IdSource::Rowid => Some("rowid"),
            IdSource::Column => Some("id"),
        }
    }
}

const AGENTS_COLUMNS: &[Column] = &[
    text("agent_id"),
    text("name"),
    text("hostname"),
    text("os"),
    text("arch"),
    text("version"),
    text("boot_id"),
    text("status"),
    int("last_seen_at"),
    int("created_at"),
];

const SAMPLES_COLUMNS: &[Column] = &[
    int("id"),
    text("agent_id"),
    text("metric"),
    text("labels"),
    int("ts"),
    real("value"),
    int_null("archive_object_id"),
    int("aggregated_1m"),
];

const ENROLL_TOKENS_COLUMNS: &[Column] = &[
    text("token_hash"),
    text("name"),
    int("created_at"),
    int("expires_at"),
    int_null("used_at"),
];

const AGENT_SECRETS_COLUMNS: &[Column] =
    &[text("agent_id"), text("secret_hash"), int("created_at")];

const REVOKED_AGENTS_COLUMNS: &[Column] = &[text("agent_id"), int("revoked_at")];

const AGENT_SETTINGS_COLUMNS: &[Column] = &[
    text("agent_id"),
    int("sample_interval_ms"),
    int("updated_at"),
];

const INGEST_STATE_COLUMNS: &[Column] = &[
    text("agent_id"),
    int("epoch"),
    int("last_seq"),
    int("updated_at"),
];

const INGEST_BATCHES_COLUMNS: &[Column] = &[text("agent_id"), int("epoch"), int("seq"), int("ts")];

const AGENT_CONTROL_COLUMNS: &[Column] =
    &[text("agent_id"), text("capabilities"), int("updated_at")];

const AUDIT_LOG_COLUMNS: &[Column] = &[
    int("id"),
    int("ts"),
    text("actor"),
    text("agent_id"),
    text("capability"),
    text("action"),
    text("target"),
    text("params"),
    text("result"),
    text("error_code"),
    text("error_message"),
    int("duration_ms"),
];

const API_TOKENS_COLUMNS: &[Column] = &[
    int("id"),
    text("name"),
    text("token_hash"),
    text("scope"),
    int("created_at"),
    int_null("last_used_at"),
    int_null("revoked_at"),
];

const SAMPLES_1M_COLUMNS: &[Column] = &[
    int("id"),
    text("agent_id"),
    text("metric"),
    text("labels"),
    int("bucket_ts"),
    real("min_value"),
    real("max_value"),
    real("avg_value"),
    real("last_value"),
    int("count"),
    int("last_ts"),
    int("aggregated_1h"),
];

const SAMPLES_1H_COLUMNS: &[Column] = &[
    int("id"),
    text("agent_id"),
    text("metric"),
    text("labels"),
    int("bucket_ts"),
    real("min_value"),
    real("max_value"),
    real("avg_value"),
    real("last_value"),
    int("count"),
];

const MAINTENANCE_STATE_COLUMNS: &[Column] = &[text("key"), text("value"), int("updated_at")];

const ALERT_RULES_COLUMNS: &[Column] = &[
    text("id"),
    text("name"),
    boolean("enabled"),
    text("source"),
    text("metric"),
    text("comparator"),
    real("threshold"),
    int("duration_secs"),
    int("cooldown_secs"),
    text_null("filter_agent_id"),
    text("filter_labels"),
    text("channel_ids"),
    boolean("notify_on_resolve"),
    boolean("is_builtin"),
    text("updated_by"),
    int("created_at"),
    int("updated_at"),
    int("revision"),
];

const ALERT_STATES_COLUMNS: &[Column] = &[
    int("id"),
    text("rule_id"),
    text("agent_id"),
    text("series_key"),
    text("state"),
    int("since"),
    int("last_eval_at"),
    real_null("last_value"),
    int_null("last_notified_at"),
];

const ALERT_EVENTS_COLUMNS: &[Column] = &[
    int("id"),
    int("ts"),
    text("rule_id"),
    text("rule_name"),
    text("agent_id"),
    text("series_key"),
    text("state"),
    real_null("value"),
    text("message"),
    boolean("notified"),
    text("notify_error"),
    boolean("silenced"),
];

const ALERT_SILENCES_COLUMNS: &[Column] = &[
    int("id"),
    text_null("rule_id"),
    text_null("agent_id"),
    int("until_ts"),
    text("created_by"),
    int("created_at"),
];

const NOTIFICATION_CHANNELS_COLUMNS: &[Column] = &[
    text("id"),
    text("name"),
    text("kind"),
    text("config_json"),
    boolean("enabled"),
    text("updated_by"),
    int("created_at"),
    int("updated_at"),
];

/// v9 规则→渠道关系表；复合主键两列都是 TEXT。
const ALERT_RULE_CHANNELS_COLUMNS: &[Column] = &[text("rule_id"), text("channel_id")];

const ARCHIVE_OBJECTS_COLUMNS: &[Column] = &[
    int("id"),
    text("backend"),
    text("object_key"),
    text("manifest_key"),
    int("from_ts"),
    int("to_ts"),
    int("rows"),
    int("bytes"),
    text("sha256"),
    text("status"),
    text("error"),
    int("created_at"),
    int_null("uploaded_at"),
    int_null("deleted_at"),
    int("ledger_version"),
    int("attempts"),
];

const ARCHIVE_STATE_COLUMNS: &[Column] = &[text("key"), text("value"), int("updated_at")];

/// 22 张业务表的固定导入顺序；与 `postgres/schema.rs` 的 `TABLES` 完全一致。
///
/// `alert_rule_channels` 依赖 `alert_rules` / `notification_channels` 的外键，
/// 因此必须排在两者之后；其余表之间没有外键，顺序只影响可复现性与失败注入时
/// 已写表的覆盖范围。这里保持 PG schema 的声明顺序，便于对照。
const TABLE_SPECS: [TableSpec; 22] = [
    TableSpec {
        name: "agents",
        columns: AGENTS_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "samples",
        columns: SAMPLES_COLUMNS,
        id_source: IdSource::Rowid,
        time_column: Some("ts"),
    },
    TableSpec {
        name: "enroll_tokens",
        columns: ENROLL_TOKENS_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "agent_secrets",
        columns: AGENT_SECRETS_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "revoked_agents",
        columns: REVOKED_AGENTS_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "agent_settings",
        columns: AGENT_SETTINGS_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "ingest_state",
        columns: INGEST_STATE_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "ingest_batches",
        columns: INGEST_BATCHES_COLUMNS,
        id_source: IdSource::None,
        time_column: Some("ts"),
    },
    TableSpec {
        name: "agent_control",
        columns: AGENT_CONTROL_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "audit_log",
        columns: AUDIT_LOG_COLUMNS,
        id_source: IdSource::Column,
        time_column: Some("ts"),
    },
    TableSpec {
        name: "api_tokens",
        columns: API_TOKENS_COLUMNS,
        id_source: IdSource::Column,
        time_column: None,
    },
    TableSpec {
        name: "samples_1m",
        columns: SAMPLES_1M_COLUMNS,
        id_source: IdSource::Rowid,
        time_column: Some("bucket_ts"),
    },
    TableSpec {
        name: "samples_1h",
        columns: SAMPLES_1H_COLUMNS,
        id_source: IdSource::Rowid,
        time_column: Some("bucket_ts"),
    },
    TableSpec {
        name: "maintenance_state",
        columns: MAINTENANCE_STATE_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "alert_rules",
        columns: ALERT_RULES_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "alert_states",
        columns: ALERT_STATES_COLUMNS,
        id_source: IdSource::Rowid,
        time_column: None,
    },
    TableSpec {
        name: "alert_events",
        columns: ALERT_EVENTS_COLUMNS,
        id_source: IdSource::Column,
        time_column: Some("ts"),
    },
    TableSpec {
        name: "alert_silences",
        columns: ALERT_SILENCES_COLUMNS,
        id_source: IdSource::Column,
        time_column: None,
    },
    TableSpec {
        name: "notification_channels",
        columns: NOTIFICATION_CHANNELS_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "alert_rule_channels",
        columns: ALERT_RULE_CHANNELS_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
    TableSpec {
        name: "archive_objects",
        columns: ARCHIVE_OBJECTS_COLUMNS,
        id_source: IdSource::Column,
        time_column: Some("from_ts"),
    },
    TableSpec {
        name: "archive_state",
        columns: ARCHIVE_STATE_COLUMNS,
        id_source: IdSource::None,
        time_column: None,
    },
];

/// 9 个 `BIGSERIAL` 主键所在的表；迁移后必须把序列推进到 `MAX(id)`。
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

/// 单张表的迁移报告。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TableMigration {
    /// 表名。
    pub table: String,
    /// 导出行数（与源/目标校验后的结果一致）。
    pub rows: u64,
    /// 自增/rowid 最小值；无 id 的表为 `None`。
    pub id_min: Option<i64>,
    /// 自增/rowid 最大值；无 id 的表为 `None`。
    pub id_max: Option<i64>,
    /// 时间/桶最小值；无时间列的表为 `None`。
    pub ts_min: Option<i64>,
    /// 时间/桶最大值；无时间列的表为 `None`。
    pub ts_max: Option<i64>,
    /// 本表导入耗时（毫秒，只含扫描源表 + 写入目标）。
    pub duration_ms: u64,
}

/// id 与时间范围；无对应列时为 `None`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct MigrateRange {
    pub id_min: Option<i64>,
    pub id_max: Option<i64>,
    pub ts_min: Option<i64>,
    pub ts_max: Option<i64>,
}

/// 迁移报告；可直接 `serde_json` 序列化给 CLI 输出。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MigrateReport {
    /// 源 SQLite `PRAGMA user_version`。
    pub sqlite_schema_version: i64,
    /// 目标 PostgreSQL schema 版本。
    pub postgres_schema_version: i64,
    /// 22 张表的行数/范围/耗时，顺序与 [`TABLE_SPECS`] 一致。
    pub tables: Vec<TableMigration>,
    /// raw 采样的 rowid 与 ts 范围。
    pub samples_range: MigrateRange,
    /// 1m 聚合的 rowid 与 bucket_ts 范围。
    pub samples_1m_range: MigrateRange,
    /// 1h 聚合的 rowid 与 bucket_ts 范围。
    pub samples_1h_range: MigrateRange,
    /// `alert_states` 行数。
    pub alert_states: u64,
    /// `alert_events` 行数。
    pub alert_events: u64,
    /// `api_tokens` 行数。
    pub api_tokens: u64,
    /// `api_tokens.token_hash` 的去重数量（必须等于行数）。
    pub api_token_hashes: u64,
    /// `archive_objects` 行数。
    pub archive_objects: u64,
    /// 22 张表的总行数。
    pub total_rows: u64,
    /// 整个迁移耗时（毫秒，含源库打开、schema 校验与提交）。
    pub duration_ms: u64,
}

/// 校验目标 PostgreSQL 是否为空。
///
/// 允许 `apply_schema` 已经执行、`schema_migrations` 已有 v9、但 22 张业务表
/// 全空的目标；任何一张业务表有行都返回明确错误。判定细节见模块文档。
///
/// 只读：在短事务内查询目录与行数，不取 advisory lock；真正导入时会在同一
/// 导入事务内重新校验，避免 check-then-act 竞态。
pub fn validate_target_empty(storage: &PostgresStorage) -> Result<()> {
    storage
        .with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启目标 PostgreSQL 空库校验事务失败")?;
            validate_target_empty_tx(&mut tx)?;
            tx.commit()
                .context("提交目标 PostgreSQL 空库校验事务失败")?;
            Ok(())
        })
        .context("校验目标 PostgreSQL 是否为空失败")
}

/// SQLite v9 → PostgreSQL 离线迁移。
///
/// 调用方必须保证 hub 已停止（离线迁移）且目标库为空；本函数会在导入事务内
/// 再次校验空库并加表锁，防止导入期间其他实例写入。非空目标直接报错，
/// `--force` 的备份/清空由 D5b CLI 先完成。
///
/// 失败时 PostgreSQL 事务整体回滚；源 SQLite 始终只读。成功返回可序列化的
/// [`MigrateReport`]，只有全部校验通过才会提交。
pub fn migrate_sqlite_to_postgres(
    source: &Path,
    target: &PostgresStorage,
) -> Result<MigrateReport> {
    let started = Instant::now();

    // 1. 只读打开源库并建立快照；先验证版本/表齐全，避免改目标后才失败。
    let source_conn = open_source(source)?;
    let sqlite_schema_version = source_schema_version(&source_conn)?;
    if sqlite_schema_version != SQLITE_SCHEMA_VERSION {
        bail!(
            "SQLite 源库 schema 版本为 {sqlite_schema_version}，本迁移只支持 v{SQLITE_SCHEMA_VERSION}；\
             请先用能升级到 v{SQLITE_SCHEMA_VERSION} 的 rustboard-hub 打开一次源库"
        );
    }
    ensure_source_tables(&source_conn)?;

    // 2. 目标非空时在 apply_schema 之前就失败，避免对非空目标做任何 DDL。
    validate_target_empty(target).context("迁移前校验目标 PostgreSQL 是否为空失败")?;

    // 3. 幂等补齐目标 schema；失败不会写入任何业务行。
    target
        .apply_schema()
        .context("迁移前应用 PostgreSQL schema 失败")?;

    // 4. 单事务导入 + 校验；with_client 只追加脱敏 DSN。
    let mut report = target
        .with_client(|client| import_all(client, &source_conn, sqlite_schema_version))
        .context("SQLite → PostgreSQL 导入失败")?;

    report.duration_ms = elapsed_ms(started);
    Ok(report)
}

/// 以只读方式打开源 SQLite，并在一个只读快照内读取全部表。
fn open_source(path: &Path) -> Result<SqliteConnection> {
    if !path.is_file() {
        bail!(
            "SQLite 源库不存在或不是普通文件：{}（迁移不会创建空库）",
            path.display()
        );
    }

    // 没有 -wal 时用 immutable=1 打开：数据已全部 checkpoint 到主库，这样
    // SQLite 不会为只读连接新建空的 -wal/-shm 文件。存在 -wal 时必须正常
    // 只读打开，否则会漏掉尚未 checkpoint 的数据。
    let wal = wal_sidecar_path(path);
    let wal_was_present = wal.is_file();
    let conn = if wal_was_present {
        open_readonly_sqlite(path)?
    } else {
        let uri = immutable_sqlite_uri(path)?;
        SqliteConnection::open_with_flags(
            uri.as_str(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .with_context(|| {
            format!(
                "以只读 immutable 方式打开 SQLite 源库失败：{}",
                path.display()
            )
        })?
    };
    // 检查与打开之间若出现 WAL，immutable 连接会看不到它；关闭后按正常
    // 只读方式重开。离线迁移下这是极窄的竞态，仍做一次防御。
    if !wal_was_present && wal.is_file() {
        drop(conn);
        return prepare_source_snapshot(open_readonly_sqlite(path)?);
    }

    prepare_source_snapshot(conn)
}

fn open_readonly_sqlite(path: &Path) -> Result<SqliteConnection> {
    SqliteConnection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("以只读方式打开 SQLite 源库失败：{}", path.display()))
}

fn prepare_source_snapshot(conn: SqliteConnection) -> Result<SqliteConnection> {
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .context("设置 SQLite 源库 busy_timeout 失败")?;
    conn.execute_batch("PRAGMA query_only = ON; BEGIN DEFERRED;")
        .context("开启 SQLite 源库只读快照失败")?;
    Ok(conn)
}

/// 生成 `file:<percent-encoded-absolute-path>?immutable=1`。
fn immutable_sqlite_uri(path: &Path) -> Result<String> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("解析 SQLite 源库绝对路径失败：{}", path.display()))?;
    let text = absolute.to_str().ok_or_else(|| {
        anyhow!(
            "SQLite 源库路径不是合法 UTF-8，无法以 immutable URI 打开：{}",
            path.display()
        )
    })?;
    let mut uri = String::with_capacity(text.len() + 16);
    uri.push_str("file:");
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                uri.push(char::from(byte));
            }
            _ => write!(uri, "%{byte:02X}").expect("写入 String 不会失败"),
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

fn wal_sidecar_path(path: &Path) -> std::path::PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push("-wal");
    std::path::PathBuf::from(os)
}

fn source_schema_version(conn: &SqliteConnection) -> Result<i64> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .context("读取 SQLite 源库 PRAGMA user_version 失败")
}

/// 迁移前确认源库 22 张表都存在；缺表时给出明确列表，不进入导入阶段。
fn ensure_source_tables(conn: &SqliteConnection) -> Result<()> {
    let mut missing = Vec::new();
    for spec in TABLE_SPECS {
        let exists: i64 = conn
            .query_row(
                "SELECT EXISTS(
                     SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1
                 )",
                [spec.name],
                |row| row.get(0),
            )
            .with_context(|| format!("检查 SQLite 源表 {} 是否存在失败", spec.name))?;
        if exists == 0 {
            missing.push(spec.name);
        }
    }
    if !missing.is_empty() {
        bail!(
            "SQLite 源库缺少 v{SQLITE_SCHEMA_VERSION} 表：{}；\
             请先用同版本 rustboard-hub 打开源库完成升级，再执行迁移",
            missing.join(", ")
        );
    }
    Ok(())
}

fn import_all(
    client: &mut postgres::Client,
    source: &SqliteConnection,
    sqlite_schema_version: i64,
) -> Result<MigrateReport> {
    let mut tx = client
        .transaction()
        .context("开启 PostgreSQL 迁移事务失败")?;

    let result = import_all_inner(&mut tx, source, sqlite_schema_version);
    match result {
        Ok(report) => {
            tx.commit()
                .context("提交 PostgreSQL 迁移事务失败（数据未提交）")?;
            Ok(report)
        }
        Err(err) => {
            // Transaction 的 Drop 也会回滚；这里显式回滚并把回滚失败降级为日志，
            // 保证返回给调用方的是原始迁移错误。
            if let Err(rollback_err) = tx.rollback() {
                tracing::warn!(
                    error = %rollback_err,
                    "回滚 PostgreSQL 迁移事务失败；请立即用 pg_stat_activity/pg_locks 检查"
                );
            }
            Err(err)
        }
    }
}

fn import_all_inner(
    tx: &mut Transaction<'_>,
    source: &SqliteConnection,
    sqlite_schema_version: i64,
) -> Result<MigrateReport> {
    // schema apply 与导入使用同一把固定 advisory lock：两个 migrate 实例不会
    // 同时进入导入阶段。表锁进一步阻止运行中的 hub 在导入期间写入目标表。
    tx.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&SCHEMA_ADVISORY_LOCK_KEY],
    )
    .context("获取 PostgreSQL 迁移 advisory lock 失败")?;
    lock_target_tables(tx)?;

    // apply_schema 与取表锁之间可能有其他实例写入；在锁内重新校验一次。
    validate_target_empty_tx(tx)?;

    let mut tables = Vec::with_capacity(TABLE_SPECS.len());
    for spec in TABLE_SPECS {
        let stats = source_stats(source, &spec)?;
        let table_started = Instant::now();
        let imported = import_table(tx, source, &spec)?;
        let imported_i64 = i64::try_from(imported)
            .with_context(|| format!("表 {} 行数超出 i64 范围", spec.name))?;
        if imported_i64 != stats.rows {
            bail!(
                "迁移过程中表 {} 行数发生变化（读取前 {}，实际导出 {}）；\
                 请确认 hub 已停止后重试",
                spec.name,
                stats.rows,
                imported
            );
        }
        tables.push(TableMigration {
            table: spec.name.to_string(),
            rows: u64::try_from(stats.rows)
                .with_context(|| format!("表 {} 行数不能为负", spec.name))?,
            id_min: stats.id_min,
            id_max: stats.id_max,
            ts_min: stats.ts_min,
            ts_max: stats.ts_max,
            duration_ms: elapsed_ms(table_started),
        });
    }

    // 先做数据校验，再推进序列：setval 不属于事务（PostgreSQL 序列不随
    // ROLLBACK 回退），放在校验失败路径之前会留下无意义的序列副作用。
    let api_token_hashes = verify_migration(tx, source)?;

    // 显式 id 不会推进序列；数据确认无误后统一 setval，避免后续写入撞主键。
    reset_sequences(tx)?;

    Ok(build_report(
        sqlite_schema_version,
        tables,
        api_token_hashes,
    ))
}

/// 对 22 张业务表取 `SHARE` 锁：允许读，阻止 INSERT/UPDATE/DELETE。
///
/// 事务提交/回滚后自动释放；只持有一张连接，不额外占用池。
fn lock_target_tables(tx: &mut Transaction<'_>) -> Result<()> {
    let names = TABLE_SPECS
        .iter()
        .map(|spec| spec.name)
        .collect::<Vec<_>>()
        .join(", ");
    tx.batch_execute(&format!("LOCK TABLE {names} IN SHARE MODE"))
        .context("锁定目标 PostgreSQL 业务表失败（可能有其他实例正在写入）")?;
    Ok(())
}

fn validate_target_empty_tx(tx: &mut Transaction<'_>) -> Result<()> {
    // 先判定版本与对象完整性，**再**统计行数。`--force` 迁移会先 pg_dump 再
    // TRUNCATE 全部业务表；若旧 schema（0<v<9）或声明 v9 但对象不全的目标被
    // 归入 Empty/NonEmpty，旧库会在 apply_schema 拒绝之前就被清空。
    let mut version: Option<i64> = None;
    if pg_table_exists(tx, "schema_migrations")? {
        version = tx
            .query_one("SELECT MAX(version) FROM schema_migrations", &[])
            .context("读取目标 PostgreSQL schema_migrations 版本失败")?
            .get(0);
    }
    let version = version.unwrap_or(0);
    if version > POSTGRES_SCHEMA_VERSION {
        bail!(
            "目标 PostgreSQL schema 版本 {version} 高于本程序支持的 \
             {POSTGRES_SCHEMA_VERSION}；拒绝迁移，请升级 rustboard-hub 后再试"
        );
    }
    if version > 0 {
        if version != POSTGRES_SCHEMA_VERSION {
            // v1.0.0 只支持全新安装：旧版本目标即使业务表全空也不得被清空。
            return bail_old_schema(version);
        }
        // 版本号自称 v9 仍不够：TRUNCATE 的是表，若 22 张表/23 个索引不完整，
        // 必须在这里拒绝，不能等 apply_schema 在清空之后才发现。
        ensure_schema_objects(tx).context(
            "目标 PostgreSQL 声明 schema v9，但 22 张业务表/23 个命名索引不完整；\
             拒绝迁移/清空",
        )?;
    } else if any_business_table_exists(tx)? {
        // 版本 0 但已有业务表：半迁移/旧库；与 apply_schema 的 v9 门禁保持一致。
        return bail_old_schema(0);
    }

    let mut non_empty = Vec::new();
    for spec in TABLE_SPECS {
        if !pg_table_exists(tx, spec.name)? {
            continue;
        }
        let count = pg_table_count(tx, spec.name)?;
        if count > 0 {
            non_empty.push(format!("{}（{count} 行）", spec.name));
        }
    }
    if !non_empty.is_empty() {
        bail!(
            "目标 PostgreSQL 非空：{}；核心迁移拒绝覆盖。\
             请先备份并清空目标（CLI 的 --force 流程），或改用空库",
            non_empty.join("、")
        );
    }
    Ok(())
}

fn pg_table_exists(tx: &mut Transaction<'_>, table: &str) -> Result<bool> {
    let exists: bool = tx
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM information_schema.tables
                 WHERE table_schema = current_schema() AND table_name = $1
             )",
            &[&table],
        )
        .with_context(|| format!("检查目标 PostgreSQL 表 {table} 是否存在失败"))?
        .get(0);
    Ok(exists)
}

fn pg_table_count(tx: &mut Transaction<'_>, table: &str) -> Result<i64> {
    // `table` 只来自 TABLE_SPECS 常量，不包含用户输入。
    let sql = format!("SELECT COUNT(*) FROM {table}");
    let count: i64 = tx
        .query_one(sql.as_str(), &[])
        .with_context(|| format!("统计目标 PostgreSQL 表 {table} 行数失败"))?
        .get(0);
    Ok(count)
}

/// 把每张表的行按 [`BATCH_ROWS`] 分批写入 PG；返回实际读取/写入的行数。
fn import_table(
    tx: &mut Transaction<'_>,
    source: &SqliteConnection,
    spec: &TableSpec,
) -> Result<usize> {
    let select_sql = source_select_sql(spec);
    let mut statement = source
        .prepare(&select_sql)
        .with_context(|| format!("准备 SQLite 表 {} 的导出查询失败", spec.name))?;
    let mut rows = statement
        .query([])
        .with_context(|| format!("执行 SQLite 表 {} 的导出查询失败", spec.name))?;

    let mut batch: Vec<Vec<PgValue>> = Vec::with_capacity(BATCH_ROWS);
    let mut imported = 0usize;
    while let Some(row) = rows
        .next()
        .with_context(|| format!("读取 SQLite 表 {} 的行失败", spec.name))?
    {
        let mut values = Vec::with_capacity(spec.columns.len());
        for (index, column) in spec.columns.iter().enumerate() {
            let raw = row
                .get_ref(index)
                .with_context(|| format!("读取 SQLite 表 {} 的第 {index} 列失败", spec.name))?;
            values.push(convert_value(spec.name, column, imported, raw)?);
        }
        batch.push(values);
        imported += 1;

        if batch.len() >= BATCH_ROWS {
            insert_rows(
                tx,
                spec,
                std::mem::replace(&mut batch, Vec::with_capacity(BATCH_ROWS)),
            )?;
        }
    }
    insert_rows(tx, spec, batch)?;
    Ok(imported)
}

/// 生成 `SELECT ... FROM table`；rowid 表显式导出 `rowid AS id`。
fn source_select_sql(spec: &TableSpec) -> String {
    let mut selected: Vec<&'static str> = Vec::with_capacity(spec.columns.len());
    match spec.id_source {
        IdSource::None => {}
        IdSource::Rowid => selected.push("rowid AS id"),
        IdSource::Column => selected.push("id"),
    }
    for column in spec.columns {
        if spec.id_source != IdSource::None && column.name == "id" {
            continue;
        }
        selected.push(column.name);
    }
    format!("SELECT {} FROM {}", selected.join(", "), spec.name)
}

/// 把一批行拼成多行 `INSERT`；表名/列名来自常量，值全部走 `$N` 参数。
fn build_insert_sql(table: &str, columns: &[Column], rows: usize) -> String {
    debug_assert!(rows > 0, "空批次不应生成 INSERT");
    debug_assert!(!columns.is_empty(), "INSERT 至少需要一列");

    let mut sql = String::with_capacity(64 + rows * columns.len() * 6);
    write!(sql, "INSERT INTO {table} (").expect("写入 String 不会失败");
    for (index, column) in columns.iter().enumerate() {
        if index > 0 {
            sql.push_str(", ");
        }
        sql.push_str(column.name);
    }
    sql.push_str(") VALUES ");

    let width = columns.len();
    for row_index in 0..rows {
        if row_index > 0 {
            sql.push(',');
        }
        sql.push('(');
        for column_index in 0..width {
            if column_index > 0 {
                sql.push(',');
            }
            write!(sql, "${}", row_index * width + column_index + 1).expect("写入 String 不会失败");
        }
        sql.push(')');
    }
    sql
}

fn insert_rows(tx: &mut Transaction<'_>, spec: &TableSpec, rows: Vec<Vec<PgValue>>) -> Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let sql = build_insert_sql(spec.name, spec.columns, rows.len());
    let params: Vec<Box<dyn ToSql + Sync>> =
        rows.into_iter().flatten().map(PgValue::into_sql).collect();
    let refs: Vec<&(dyn ToSql + Sync)> = params.iter().map(|value| value.as_ref()).collect();
    if let Err(err) = tx.execute(sql.as_str(), &refs) {
        return match err.code() {
            Some(code) => Err(anyhow!(
                "批量写入 PostgreSQL 表 {} 失败（SQLSTATE {}）；目标事务将回滚；为避免错误详情回显源库内容，未输出数据库原始错误",
                spec.name,
                code.code()
            )),
            // 连接级错误不含源行内容，保留原始错误便于排障。
            None => Err(err)
                .with_context(|| format!("批量写入 PostgreSQL 表 {} 失败", spec.name)),
        };
    }
    Ok(())
}

/// SQLite 值 → PG 绑定值；NULL 需要带上目标列类型，避免 TEXT/BIGINT 推断冲突。
#[derive(Debug)]
enum PgValue {
    NullText,
    NullInt,
    NullReal,
    Int(i64),
    Real(f64),
    Text(String),
    Bool(bool),
}

impl PgValue {
    fn into_sql(self) -> Box<dyn ToSql + Sync> {
        match self {
            Self::NullText => Box::new(Option::<String>::None),
            Self::NullInt => Box::new(Option::<i64>::None),
            Self::NullReal => Box::new(Option::<f64>::None),
            Self::Int(value) => Box::new(value),
            Self::Real(value) => Box::new(value),
            Self::Text(value) => Box::new(value),
            Self::Bool(value) => Box::new(value),
        }
    }
}

fn convert_value(
    table: &str,
    column: &Column,
    row_index: usize,
    raw: ValueRef<'_>,
) -> Result<PgValue> {
    match raw {
        ValueRef::Null => {
            if !column.nullable {
                bail!(
                    "表 {table} 的列 {} 第 {row_index} 行为 NULL，但目标列是 NOT NULL",
                    column.name
                );
            }
            match column.kind {
                Kind::Text => Ok(PgValue::NullText),
                Kind::Int => Ok(PgValue::NullInt),
                Kind::Real => Ok(PgValue::NullReal),
                Kind::Bool => bail!(
                    "表 {table} 的列 {} 第 {row_index} 行为 NULL，但布尔列不允许 NULL",
                    column.name
                ),
            }
        }
        ValueRef::Integer(value) => match column.kind {
            Kind::Int => Ok(PgValue::Int(value)),
            Kind::Real => Ok(PgValue::Real(value as f64)),
            Kind::Bool => match value {
                0 => Ok(PgValue::Bool(false)),
                1 => Ok(PgValue::Bool(true)),
                _ => bail!(
                    "表 {table} 的列 {} 第 {row_index} 行不是合法布尔值（只接受 INTEGER 0/1）",
                    column.name
                ),
            },
            Kind::Text => bail!(
                "表 {table} 的列 {} 第 {row_index} 行是 INTEGER，但目标列是 TEXT",
                column.name
            ),
        },
        ValueRef::Real(value) => match column.kind {
            Kind::Real => Ok(PgValue::Real(value)),
            // SQLite INTEGER 亲和列在极端情况下可能存成 REAL；整数才接受。
            Kind::Int => {
                if value.is_finite()
                    && value.fract() == 0.0
                    && value >= i64::MIN as f64
                    && value <= i64::MAX as f64
                {
                    Ok(PgValue::Int(value as i64))
                } else {
                    bail!(
                        "表 {table} 的列 {} 第 {row_index} 行是 REAL，但目标列是 BIGINT",
                        column.name
                    )
                }
            }
            Kind::Bool | Kind::Text => bail!(
                "表 {table} 的列 {} 第 {row_index} 行是 REAL，但目标列是 {}",
                column.name,
                column.kind.name()
            ),
        },
        ValueRef::Text(bytes) => match column.kind {
            Kind::Text => {
                let value = std::str::from_utf8(bytes).with_context(|| {
                    format!(
                        "表 {table} 的列 {} 第 {row_index} 行不是合法 UTF-8 文本",
                        column.name
                    )
                })?;
                Ok(PgValue::Text(value.to_string()))
            }
            _ => bail!(
                "表 {table} 的列 {} 第 {row_index} 行是 TEXT，但目标列是 {}",
                column.name,
                column.kind.name()
            ),
        },
        ValueRef::Blob(_) => bail!(
            "表 {table} 的列 {} 第 {row_index} 行是 BLOB，目标 schema 不支持 BLOB",
            column.name
        ),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RangeStats {
    rows: i64,
    id_min: Option<i64>,
    id_max: Option<i64>,
    ts_min: Option<i64>,
    ts_max: Option<i64>,
}

fn source_stats(conn: &SqliteConnection, spec: &TableSpec) -> Result<RangeStats> {
    let rows: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {}", spec.name), [], |row| {
            row.get(0)
        })
        .with_context(|| format!("统计 SQLite 表 {} 行数失败", spec.name))?;

    let (id_min, id_max) = match spec.source_id_expr() {
        Some(expr) => conn
            .query_row(
                &format!("SELECT MIN({expr}), MAX({expr}) FROM {}", spec.name),
                [],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .with_context(|| format!("统计 SQLite 表 {} id 范围失败", spec.name))?,
        None => (None, None),
    };

    let (ts_min, ts_max) = match spec.time_column {
        Some(column) => conn
            .query_row(
                &format!("SELECT MIN({column}), MAX({column}) FROM {}", spec.name),
                [],
                |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
            )
            .with_context(|| format!("统计 SQLite 表 {} 时间范围失败", spec.name))?,
        None => (None, None),
    };

    Ok(RangeStats {
        rows,
        id_min,
        id_max,
        ts_min,
        ts_max,
    })
}

fn target_stats(tx: &mut Transaction<'_>, spec: &TableSpec) -> Result<RangeStats> {
    let rows = pg_table_count(tx, spec.name)?;

    let (id_min, id_max) = if spec.has_id() {
        let sql = format!("SELECT MIN(id), MAX(id) FROM {}", spec.name);
        let row = tx
            .query_one(sql.as_str(), &[])
            .with_context(|| format!("统计目标 PostgreSQL 表 {} id 范围失败", spec.name))?;
        (row.get::<_, Option<i64>>(0), row.get::<_, Option<i64>>(1))
    } else {
        (None, None)
    };

    let (ts_min, ts_max) = match spec.time_column {
        Some(column) => {
            let sql = format!("SELECT MIN({column}), MAX({column}) FROM {}", spec.name);
            let row = tx
                .query_one(sql.as_str(), &[])
                .with_context(|| format!("统计目标 PostgreSQL 表 {} 时间范围失败", spec.name))?;
            (row.get::<_, Option<i64>>(0), row.get::<_, Option<i64>>(1))
        }
        None => (None, None),
    };

    Ok(RangeStats {
        rows,
        id_min,
        id_max,
        ts_min,
        ts_max,
    })
}

/// 把 9 个 `BIGSERIAL` 序列推进到 `MAX(id)`（空表设为 1，`is_called=false`）。
fn reset_sequences(tx: &mut Transaction<'_>) -> Result<()> {
    for table in SERIAL_TABLES {
        let sequence: Option<String> = tx
            .query_one("SELECT pg_get_serial_sequence($1, 'id')", &[&table])
            .with_context(|| format!("读取表 {table}.id 的序列名失败"))?
            .get(0);
        let sequence = sequence.ok_or_else(|| {
            anyhow!("表 {table}.id 没有关联的 BIGSERIAL 序列；目标 schema 可能不完整")
        })?;

        let max_id: Option<i64> = tx
            .query_one(&format!("SELECT MAX(id) FROM {table}"), &[])
            .with_context(|| format!("读取表 {table} 的最大 id 失败"))?
            .get(0);

        match max_id {
            Some(max_id) => {
                tx.query_one(
                    "SELECT setval($1::text::regclass, $2, true)",
                    &[&sequence, &max_id],
                )
                .with_context(|| format!("把序列 {sequence} 推进到 {max_id} 失败（表 {table}）"))?;
            }
            None => {
                tx.query_one("SELECT setval($1::text::regclass, 1, false)", &[&sequence])
                    .with_context(|| format!("把空表 {table} 的序列设为 1 失败"))?;
            }
        }
    }
    Ok(())
}

/// 在提交前完成全部校验；返回 `api_tokens.token_hash` 去重数量。
fn verify_migration(tx: &mut Transaction<'_>, source: &SqliteConnection) -> Result<i64> {
    // 目标版本必须是 v9（apply_schema 刚跑过；这里防止调用方绕过）。
    let version: Option<i64> = tx
        .query_one("SELECT MAX(version) FROM schema_migrations", &[])
        .context("校验目标 PostgreSQL schema 版本失败")?
        .get(0);
    if version != Some(POSTGRES_SCHEMA_VERSION) {
        bail!("目标 PostgreSQL schema 版本应为 {POSTGRES_SCHEMA_VERSION}，实际为 {version:?}");
    }

    // 每张表：行数 + id 范围 + 时间范围必须与源库逐项一致。
    for spec in TABLE_SPECS {
        let expected = source_stats(source, &spec)?;
        let actual = target_stats(tx, &spec)?;
        if expected != actual {
            bail!(
                "迁移校验失败：表 {} 不一致（源 rows={} id={:?}..{:?} ts={:?}..{:?}；\
                 目标 rows={} id={:?}..{:?} ts={:?}..{:?}）",
                spec.name,
                expected.rows,
                expected.id_min,
                expected.id_max,
                expected.ts_min,
                expected.ts_max,
                actual.rows,
                actual.id_min,
                actual.id_max,
                actual.ts_min,
                actual.ts_max
            );
        }
    }

    // v8/v9 列必须真的搬过去：只校验行数/id/ts 会漏掉 claim、聚合标记与
    // revision。
    verify_extra_columns(tx, source)?;

    // api_tokens 只存哈希：去重数量必须等于行数（UNIQUE 约束之外的二次检查）。
    let source_hashes: i64 = source
        .query_row(
            "SELECT COUNT(DISTINCT token_hash) FROM api_tokens",
            [],
            |row| row.get(0),
        )
        .context("统计 SQLite api_tokens 哈希数量失败")?;
    let target_hashes: i64 = tx
        .query_one("SELECT COUNT(DISTINCT token_hash) FROM api_tokens", &[])
        .context("统计目标 PostgreSQL api_tokens 哈希数量失败")?
        .get(0);
    let target_tokens = pg_table_count(tx, "api_tokens")?;
    if source_hashes != target_hashes || target_hashes != target_tokens {
        bail!(
            "迁移校验失败：api_tokens 哈希数量不一致（源去重 {}，目标去重 {}，目标行数 {}）",
            source_hashes,
            target_hashes,
            target_tokens
        );
    }

    // maintenance_state 的 rowid 水位必须原样保留；源库中仍存在的 raw 行，
    // 目标库必须能用同一个 id 找到，证明 rowid → id 映射没有错位。
    verify_maintenance_state(tx, source)?;

    Ok(target_hashes)
}

/// 校验 v8/v9 新增列在源/目标的一致性（计数/求和，不回显行内容）。
fn verify_extra_columns(tx: &mut Transaction<'_>, source: &SqliteConnection) -> Result<()> {
    let checks = [
        (
            "samples.aggregated_1m=1 行数",
            "SELECT COUNT(*) FROM samples WHERE aggregated_1m = 1",
            "SELECT COUNT(*)::BIGINT FROM samples WHERE aggregated_1m = 1",
        ),
        (
            "samples.archive_object_id 非空行数",
            "SELECT COUNT(*) FROM samples WHERE archive_object_id IS NOT NULL",
            "SELECT COUNT(*)::BIGINT FROM samples WHERE archive_object_id IS NOT NULL",
        ),
        (
            "samples_1m.aggregated_1h=1 行数",
            "SELECT COUNT(*) FROM samples_1m WHERE aggregated_1h = 1",
            "SELECT COUNT(*)::BIGINT FROM samples_1m WHERE aggregated_1h = 1",
        ),
        (
            "samples_1m.last_ts 求和",
            "SELECT COALESCE(SUM(last_ts), 0) FROM samples_1m",
            "SELECT COALESCE(SUM(last_ts), 0)::BIGINT FROM samples_1m",
        ),
        (
            "archive_objects.ledger_version 求和",
            "SELECT COALESCE(SUM(ledger_version), 0) FROM archive_objects",
            "SELECT COALESCE(SUM(ledger_version), 0)::BIGINT FROM archive_objects",
        ),
        (
            "archive_objects.attempts 求和",
            "SELECT COALESCE(SUM(attempts), 0) FROM archive_objects",
            "SELECT COALESCE(SUM(attempts), 0)::BIGINT FROM archive_objects",
        ),
        (
            "alert_rules.revision 求和",
            "SELECT COALESCE(SUM(revision), 0) FROM alert_rules",
            "SELECT COALESCE(SUM(revision), 0)::BIGINT FROM alert_rules",
        ),
    ];
    for (label, source_sql, target_sql) in checks {
        let source_value: i64 = source
            .query_row(source_sql, [], |row| row.get(0))
            .with_context(|| format!("读取 SQLite 扩展列校验值失败：{label}"))?;
        let target_value: i64 = tx
            .query_one(target_sql, &[])
            .with_context(|| format!("读取目标 PostgreSQL 扩展列校验值失败：{label}"))?
            .get(0);
        if source_value != target_value {
            bail!(
                "迁移校验失败：{label} 不一致（源 {source_value}，目标 {target_value}）；                 具体行值未输出，避免泄露源库内容"
            );
        }
    }
    Ok(())
}

fn verify_maintenance_state(tx: &mut Transaction<'_>, source: &SqliteConnection) -> Result<()> {
    for key in [DOWNSAMPLE_ROWID_KEY, RAW_PRUNE_GENERATION_KEY] {
        let source_value: Option<String> = source
            .query_row(
                "SELECT value FROM maintenance_state WHERE key = ?1",
                [key],
                |row| row.get(0),
            )
            .optional()
            .with_context(|| format!("读取 SQLite maintenance_state.{key} 失败"))?;
        let target_value: Option<String> = tx
            .query_opt(
                "SELECT value FROM maintenance_state WHERE key = $1",
                &[&key],
            )
            .with_context(|| format!("读取目标 PostgreSQL maintenance_state.{key} 失败"))?
            .map(|row| row.get(0));
        if source_value != target_value {
            bail!(
                "迁移校验失败：maintenance_state.{key} 值不一致；为避免回显源库内容，错误中不输出具体值"
            );
        }
    }

    let watermark: Option<String> = source
        .query_row(
            "SELECT value FROM maintenance_state WHERE key = ?1",
            [DOWNSAMPLE_ROWID_KEY],
            |row| row.get(0),
        )
        .optional()
        .context("读取 SQLite 降采样 rowid 水位失败")?;
    let Some(watermark) = watermark else {
        return Ok(());
    };
    let Ok(rowid) = watermark.trim().parse::<i64>() else {
        // 历史脏值原样迁移即可，不因为无法解析而拒绝整个迁移。
        return Ok(());
    };

    let source_has_row: i64 = source
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM samples WHERE rowid = ?1)",
            [rowid],
            |row| row.get(0),
        )
        .context("检查 SQLite rowid 水位对应的 raw 行失败")?;
    let target_has_row: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM samples WHERE id = $1)",
            &[&rowid],
        )
        .context("检查目标 PostgreSQL id 水位对应的 raw 行失败")?
        .get(0);
    if (source_has_row != 0) != target_has_row {
        bail!(
            "迁移校验失败：maintenance_state.{DOWNSAMPLE_ROWID_KEY}={rowid} \
             对应的 raw 行没有按原 rowid 映射到目标 id"
        );
    }

    Ok(())
}

fn build_report(
    sqlite_schema_version: i64,
    tables: Vec<TableMigration>,
    api_token_hashes: i64,
) -> MigrateReport {
    let total_rows = tables.iter().map(|table| table.rows).sum();
    let api_token_hashes = u64::try_from(api_token_hashes).unwrap_or_default();
    MigrateReport {
        sqlite_schema_version,
        postgres_schema_version: POSTGRES_SCHEMA_VERSION,
        samples_range: table_range(&tables, "samples"),
        samples_1m_range: table_range(&tables, "samples_1m"),
        samples_1h_range: table_range(&tables, "samples_1h"),
        alert_states: table_rows(&tables, "alert_states"),
        alert_events: table_rows(&tables, "alert_events"),
        api_tokens: table_rows(&tables, "api_tokens"),
        api_token_hashes,
        archive_objects: table_rows(&tables, "archive_objects"),
        tables,
        total_rows,
        // 由 migrate_sqlite_to_postgres 在 commit 后填入总耗时。
        duration_ms: 0,
    }
}

fn table_rows(tables: &[TableMigration], name: &str) -> u64 {
    tables
        .iter()
        .find(|table| table.table == name)
        .map(|table| table.rows)
        .unwrap_or(0)
}

fn table_range(tables: &[TableMigration], name: &str) -> MigrateRange {
    tables
        .iter()
        .find(|table| table.table == name)
        .map(|table| MigrateRange {
            id_min: table.id_min,
            id_max: table.id_max,
            ts_min: table.ts_min,
            ts_max: table.ts_max,
        })
        .unwrap_or_default()
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(name: &str) -> &'static TableSpec {
        TABLE_SPECS
            .iter()
            .find(|spec| spec.name == name)
            .unwrap_or_else(|| panic!("缺少表规格 {name}"))
    }

    #[test]
    fn table_specs_match_postgres_schema_order() {
        let expected = [
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
        assert_eq!(TABLE_SPECS.len(), expected.len());
        for (actual, expected) in TABLE_SPECS.iter().zip(expected) {
            assert_eq!(actual.name, expected);
            assert!(!actual.columns.is_empty());
        }
        assert_eq!(SQLITE_SCHEMA_VERSION, 9);
        assert_eq!(POSTGRES_SCHEMA_VERSION, 9);
        assert_eq!(BATCH_ROWS, 500);
    }

    #[test]
    fn id_tables_have_id_as_first_column() {
        for spec in TABLE_SPECS {
            if spec.has_id() {
                assert_eq!(
                    spec.columns.first().map(|column| column.name),
                    Some("id"),
                    "表 {} 的 id 必须是第一列",
                    spec.name
                );
                assert_eq!(spec.columns[0].kind, Kind::Int);
            } else if let Some(column) = spec.columns.iter().find(|column| column.name == "id") {
                // alert_rules / notification_channels 的 id 是 TEXT 业务主键，
                // 不是 BIGSERIAL，因此没有 rowid/serial 映射。
                assert_eq!(
                    column.kind,
                    Kind::Text,
                    "表 {} 的非自增 id 必须是 TEXT",
                    spec.name
                );
            }
        }

        for table in SERIAL_TABLES {
            let spec = spec(table);
            assert!(spec.has_id(), "序列表 {table} 必须有 id");
        }
    }

    #[test]
    fn rowid_tables_export_rowid_as_id() {
        let sql = source_select_sql(spec("samples"));
        assert!(
            sql.starts_with("SELECT rowid AS id, agent_id, metric"),
            "{sql}"
        );
        assert!(!sql.contains("SELECT id,"), "samples 源表没有 id 列：{sql}");

        let sql = source_select_sql(spec("alert_states"));
        assert!(sql.starts_with("SELECT rowid AS id, rule_id"), "{sql}");

        let sql = source_select_sql(spec("audit_log"));
        assert!(sql.starts_with("SELECT id, ts"), "{sql}");
    }

    #[test]
    fn insert_sql_is_fully_parameterized() {
        let samples = spec("samples");
        let sql = build_insert_sql(samples.name, samples.columns, 2);
        assert_eq!(sql.matches('$').count(), 16, "{sql}");
        assert!(sql.contains("$1"), "{sql}");
        assert!(sql.contains("$16"), "{sql}");
        assert!(!sql.contains('\''), "SQL 不应包含字面值：{sql}");
        assert!(!sql.contains("cpu"), "SQL 不应包含用户值：{sql}");
    }

    #[test]
    fn boolean_conversion_only_accepts_0_and_1() {
        let column = Column {
            name: "enabled",
            kind: Kind::Bool,
            nullable: false,
        };
        assert!(matches!(
            convert_value("alert_rules", &column, 0, ValueRef::Integer(0)).unwrap(),
            PgValue::Bool(false)
        ));
        assert!(matches!(
            convert_value("alert_rules", &column, 1, ValueRef::Integer(1)).unwrap(),
            PgValue::Bool(true)
        ));
        let error = convert_value("alert_rules", &column, 0, ValueRef::Integer(2))
            .expect_err("非 0/1 必须拒绝");
        let message = format!("{error:#}");
        assert!(message.contains("布尔值"), "{message}");
        assert!(!message.contains('2'), "错误不应回显值：{message}");
    }

    #[test]
    fn null_requires_nullable_column() {
        let not_null = Column {
            name: "name",
            kind: Kind::Text,
            nullable: false,
        };
        let error = convert_value("agents", &not_null, 0, ValueRef::Null)
            .expect_err("NOT NULL 列遇到 NULL 必须报错");
        assert!(format!("{error:#}").contains("NOT NULL"), "{error:#}");

        let nullable = Column {
            name: "used_at",
            kind: Kind::Int,
            nullable: true,
        };
        assert!(matches!(
            convert_value("enroll_tokens", &nullable, 0, ValueRef::Null).unwrap(),
            PgValue::NullInt
        ));
    }

    #[test]
    fn real_accepts_integer_storage() {
        let column = Column {
            name: "value",
            kind: Kind::Real,
            nullable: false,
        };
        assert!(matches!(
            convert_value("samples", &column, 0, ValueRef::Integer(3)).unwrap(),
            PgValue::Real(value) if value == 3.0
        ));
    }

    #[test]
    fn immutable_uri_percent_encodes_special_characters() {
        let path = Path::new("/tmp/rb d5/source?#%.db");
        let uri = immutable_sqlite_uri(path).expect("生成 immutable URI 失败");
        assert_eq!(uri, "file:/tmp/rb%20d5/source%3F%23%25.db?immutable=1");
    }

    #[test]
    fn report_is_json_serializable() {
        let report = MigrateReport {
            sqlite_schema_version: 7,
            postgres_schema_version: 7,
            tables: vec![TableMigration {
                table: "samples".to_string(),
                rows: 2,
                id_min: Some(1),
                id_max: Some(3),
                ts_min: Some(10),
                ts_max: Some(20),
                duration_ms: 5,
            }],
            samples_range: MigrateRange {
                id_min: Some(1),
                id_max: Some(3),
                ts_min: Some(10),
                ts_max: Some(20),
            },
            samples_1m_range: MigrateRange::default(),
            samples_1h_range: MigrateRange::default(),
            alert_states: 1,
            alert_events: 2,
            api_tokens: 3,
            api_token_hashes: 3,
            archive_objects: 4,
            total_rows: 2,
            duration_ms: 9,
        };
        let value = serde_json::to_value(&report).expect("报告必须可序列化");
        assert_eq!(value["tables"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["samples_range"]["id_max"], 3);
        assert_eq!(value["duration_ms"], 9);
        assert_eq!(value["api_token_hashes"], 3);
    }
}
