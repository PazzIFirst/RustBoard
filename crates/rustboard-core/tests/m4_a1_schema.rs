//! M4-A1 schema v7 独立集成测试。
//!
//! 只依据 `docs/plans/2026-10-24-m4-alerting-archive.md` §4、§5、§10 A1、
//! §11.1 与 `crates/rustboard-core/src/storage/mod.rs` 的公开接口编写；
//! 不参考 `sqlite.rs` 中 v7 的实现细节，也不修改生产代码。
//!
//! 每个用例使用 `std::env::temp_dir()` 下自建的唯一目录，结束时清理；
//! schema 断言直接使用 `rusqlite::Connection` 读取 `sqlite_master` / `PRAGMA`。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::Storage;

/// 方案 §4 规定的 10 张 v7 新表。
const V7_TABLES: [&str; 10] = [
    "samples_1m",
    "samples_1h",
    "maintenance_state",
    "alert_rules",
    "alert_states",
    "alert_events",
    "alert_silences",
    "notification_channels",
    "archive_objects",
    "archive_state",
];

/// 方案 §4 规定的 9 个索引 + B1b 新增的通知 / 状态清理 / 静默索引，共 12 个。
const V7_INDEXES: [(&str, &str); 12] = [
    ("idx_samples_1m_lookup", "samples_1m"),
    ("idx_samples_1m_ts", "samples_1m"),
    ("idx_samples_1h_lookup", "samples_1h"),
    ("idx_samples_1h_ts", "samples_1h"),
    ("idx_alert_events_ts", "alert_events"),
    ("idx_alert_events_rule_ts", "alert_events"),
    ("idx_alert_events_agent_ts", "alert_events"),
    ("idx_alert_events_pending", "alert_events"),
    ("idx_alert_states_state_eval", "alert_states"),
    ("idx_alert_silences_until", "alert_silences"),
    ("idx_archive_objects_range", "archive_objects"),
    ("idx_archive_objects_status", "archive_objects"),
];

/// v6 的全部真实表；迁移测试以它们为基线检查「旧表不被改写」。
const V6_TABLES: [&str; 11] = [
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
];

/// v6 真实 schema（与 v0.3.5 基线一致）。
///
/// 测试里手工建库，保证迁移输入是一个真正停在 v6 的数据库，
/// 而不是用当前代码「先建 v7 再降级」造出来的假象。
const V6_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS agents (
    agent_id      TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    hostname      TEXT NOT NULL,
    os            TEXT NOT NULL DEFAULT '',
    arch          TEXT NOT NULL DEFAULT '',
    version       TEXT NOT NULL DEFAULT '',
    boot_id       TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'offline',
    last_seen_at  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS samples (
    agent_id  TEXT NOT NULL,
    metric    TEXT NOT NULL,
    labels    TEXT NOT NULL DEFAULT '{}',
    ts        INTEGER NOT NULL,
    value     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_lookup ON samples(agent_id, metric, ts);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_hash TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
);

CREATE TABLE IF NOT EXISTS agent_secrets (
    agent_id    TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_agents (
    agent_id   TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_settings (
    agent_id           TEXT PRIMARY KEY,
    sample_interval_ms INTEGER NOT NULL,
    updated_at         INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ingest_state (
    agent_id   TEXT NOT NULL,
    epoch      INTEGER NOT NULL,
    last_seq   INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, epoch)
);

CREATE TABLE IF NOT EXISTS ingest_batches (
    agent_id TEXT NOT NULL,
    epoch    INTEGER NOT NULL,
    seq      INTEGER NOT NULL,
    ts       INTEGER NOT NULL,
    PRIMARY KEY (agent_id, epoch, seq)
);
CREATE INDEX IF NOT EXISTS idx_ingest_batches_ts ON ingest_batches(ts);

CREATE TABLE IF NOT EXISTS agent_control (
    agent_id     TEXT PRIMARY KEY,
    capabilities TEXT NOT NULL DEFAULT '[]',
    updated_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    actor         TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    capability    TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT NOT NULL DEFAULT '',
    params        TEXT NOT NULL DEFAULT '{}',
    result        TEXT NOT NULL,
    error_code    TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    duration_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit_log(agent_id, ts);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL CHECK (scope IN ('read','write','admin')),
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
"#;

/// 唯一临时目录；`Drop` 时递归清理（栈上通常先声明目录、后声明 storage，
/// 因此 storage 的连接会先关闭，再删除目录）。
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
            "rb-m4-a1-schema-{}-{tag}-{nanos}-{seq}",
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

fn user_version(conn: &Connection) -> i64 {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("读取 PRAGMA user_version 失败")
}

fn object_exists(conn: &Connection, kind: &str, name: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = ?1 AND name = ?2)",
        params![kind, name],
        |row| row.get::<_, i64>(0),
    )
    .expect("查询 sqlite_master 失败")
        == 1
}

fn object_count(conn: &Connection, kind: &str, name: &str) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = ?1 AND name = ?2",
        params![kind, name],
        |row| row.get(0),
    )
    .unwrap_or_else(|err| panic!("统计 sqlite_master 中 {kind} {name} 失败：{err}"))
}

fn object_owner(conn: &Connection, index: &str) -> String {
    conn.query_row(
        "SELECT tbl_name FROM sqlite_master WHERE type = 'index' AND name = ?1",
        params![index],
        |row| row.get(0),
    )
    .unwrap_or_else(|err| panic!("读取索引 {index} 的所属表失败：{err}"))
}

/// `PRAGMA table_info` 的一行。
#[derive(Debug)]
struct ColumnInfo {
    name: String,
    decl_type: String,
    not_null: bool,
    default: Option<String>,
    pk: i64,
}

fn columns(conn: &Connection, table: &str) -> Vec<ColumnInfo> {
    // table 只来自本文件里的常量，不拼接外部输入。
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .unwrap_or_else(|err| panic!("读取 {table} 列信息失败：{err}"));
    let rows = stmt
        .query_map([], |row| {
            Ok(ColumnInfo {
                name: row.get(1)?,
                decl_type: row.get(2)?,
                not_null: row.get::<_, i64>(3)? != 0,
                default: row.get(4)?,
                pk: row.get(5)?,
            })
        })
        .unwrap_or_else(|err| panic!("查询 {table} 列信息失败：{err}"));
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .unwrap_or_else(|err| panic!("收集 {table} 列信息失败：{err}"))
}

fn assert_columns(conn: &Connection, table: &str, expected: &[(&str, &str, bool)]) {
    let actual = columns(conn, table);
    let actual_names: Vec<&str> = actual.iter().map(|column| column.name.as_str()).collect();
    let expected_names: Vec<&str> = expected.iter().map(|(name, _, _)| *name).collect();
    assert_eq!(actual_names, expected_names, "{table} 列名或顺序不符");
    for (column, &(name, decl_type, not_null)) in actual.iter().zip(expected.iter()) {
        assert_eq!(
            column.decl_type.as_str(),
            decl_type,
            "{table}.{name} 声明类型不符"
        );
        assert_eq!(
            column.not_null, not_null,
            "{table}.{name} 的 NOT NULL 属性不符"
        );
    }
}

fn assert_primary_key(conn: &Connection, table: &str, expected: &[&str]) {
    let mut pk: Vec<(i64, String)> = columns(conn, table)
        .into_iter()
        .filter(|column| column.pk > 0)
        .map(|column| (column.pk, column.name))
        .collect();
    pk.sort_by_key(|(position, _)| *position);
    let names: Vec<&str> = pk.iter().map(|(_, name)| name.as_str()).collect();
    assert_eq!(names.as_slice(), expected, "{table} 主键列或顺序不符");
}

fn column_default<'a>(columns: &'a [ColumnInfo], name: &str) -> Option<&'a str> {
    columns
        .iter()
        .find(|column| column.name.as_str() == name)
        .unwrap_or_else(|| panic!("缺少列 {name}"))
        .default
        .as_deref()
}

/// 去掉 SQLite 默认值外层单/双引号，按语义比较文本默认值。
fn normalize_default(raw: Option<&str>) -> Option<&str> {
    raw.map(|value| {
        let trimmed = value.trim();
        if trimmed.len() >= 2 {
            let first = trimmed.as_bytes()[0];
            let last = trimmed.as_bytes()[trimmed.len() - 1];
            if (first == b'\'' && last == b'\'') || (first == b'"' && last == b'"') {
                return &trimmed[1..trimmed.len() - 1];
            }
        }
        trimmed
    })
}

fn assert_default(columns: &[ColumnInfo], name: &str, expected: &str) {
    assert_eq!(
        normalize_default(column_default(columns, name)),
        Some(expected),
        "{name} 的默认值不符"
    );
}

/// 断言方案 §4 的 10 张表与 12 个索引全部存在，且索引挂在正确的表上。
fn assert_v7_objects(conn: &Connection) {
    for table in V7_TABLES {
        assert!(object_exists(conn, "table", table), "缺少 v7 表 {table}");
    }
    for (index, owner) in V7_INDEXES {
        assert!(object_exists(conn, "index", index), "缺少 v7 索引 {index}");
        assert_eq!(
            object_owner(conn, index),
            owner,
            "索引 {index} 应建在 {owner} 上"
        );
    }
}

fn assert_unique_violation<T>(result: rusqlite::Result<T>, context: &str) {
    match result {
        Ok(_) => panic!("{context}：重复值必须触发 UNIQUE 约束错误"),
        Err(err) => {
            let message = err.to_string();
            assert!(
                message.contains("UNIQUE"),
                "{context}：期望 UNIQUE 约束错误，实际却是：{message}"
            );
        }
    }
}

fn table_sql(conn: &Connection, tables: &[&str]) -> Vec<(String, String)> {
    tables
        .iter()
        .map(|table| {
            let sql: String = conn
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    params![*table],
                    |row| row.get(0),
                )
                .unwrap_or_else(|err| panic!("读取 {table} 建表 SQL 失败：{err}"));
            ((*table).to_string(), sql)
        })
        .collect()
}

fn table_counts(conn: &Connection, tables: &[&str]) -> Vec<(String, i64)> {
    tables
        .iter()
        .map(|table| {
            // table 只来自本文件里的常量；用双引号包裹以兼容关键字列/表名。
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
                    row.get(0)
                })
                .unwrap_or_else(|err| panic!("统计 {table} 行数失败：{err}"));
            ((*table).to_string(), count)
        })
        .collect()
}

/// 旧 agents 表一行的逐字段快照。
type OldAgentRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
);

/// 旧 samples 表一行的逐字段快照。
type OldSampleRow = (String, String, String, i64, f64);

/// 旧 api_tokens 表一行的逐字段快照。
type OldApiTokenRow = (i64, String, String, String, i64, Option<i64>, Option<i64>);

/// 旧表建表 SQL 快照。
type TableSqlSnapshot = Vec<(String, String)>;

/// 旧表行数快照。
type TableCountSnapshot = Vec<(String, i64)>;

/// v6 固定数据：一台在线 agent。
fn expected_agent() -> OldAgentRow {
    (
        "agent-old".to_string(),
        "旧节点".to_string(),
        "host-old".to_string(),
        "linux".to_string(),
        "x86_64".to_string(),
        "0.3.5".to_string(),
        "boot-old".to_string(),
        "online".to_string(),
        1_712_345_678_901,
        1_700_000_000_000,
    )
}

/// v6 固定数据：三条 raw 采样（labels 含 JSON 与空对象两种形态）。
fn expected_samples() -> Vec<OldSampleRow> {
    vec![
        (
            "agent-old".to_string(),
            "cpu.usage".to_string(),
            r#"{"core":"0"}"#.to_string(),
            1_700_000_000_000,
            12.5,
        ),
        (
            "agent-old".to_string(),
            "cpu.usage".to_string(),
            r#"{"core":"0"}"#.to_string(),
            1_700_000_060_000,
            13.75,
        ),
        (
            "agent-old".to_string(),
            "mem.used".to_string(),
            "{}".to_string(),
            1_700_000_060_000,
            2048.0,
        ),
    ]
}

/// v6 固定数据：两个 scoped token（一个活跃、一个已吊销）。
fn expected_api_tokens() -> Vec<OldApiTokenRow> {
    vec![
        (
            1,
            "token-alpha".to_string(),
            "hash-alpha".to_string(),
            "read".to_string(),
            1_700_000_000_000,
            Some(1_700_000_100_000),
            None,
        ),
        (
            2,
            "token-beta".to_string(),
            "hash-beta".to_string(),
            "admin".to_string(),
            1_700_000_001_000,
            None,
            Some(1_700_000_200_000),
        ),
    ]
}

fn read_old_agent(conn: &Connection) -> OldAgentRow {
    conn.query_row(
        "SELECT agent_id, name, hostname, os, arch, version, boot_id, status, last_seen_at, created_at \
         FROM agents WHERE agent_id = ?1",
        params!["agent-old"],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
                row.get(8)?,
                row.get(9)?,
            ))
        },
    )
    .expect("读取旧 agents 行失败")
}

fn read_old_samples(conn: &Connection) -> Vec<OldSampleRow> {
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, metric, labels, ts, value FROM samples \
             ORDER BY ts, metric, labels",
        )
        .expect("准备旧 samples 查询失败");
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
        .expect("查询旧 samples 失败");
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .expect("收集旧 samples 失败")
}

fn read_old_api_tokens(conn: &Connection) -> Vec<OldApiTokenRow> {
    let mut stmt = conn
        .prepare(
            "SELECT id, name, token_hash, scope, created_at, last_used_at, revoked_at \
             FROM api_tokens ORDER BY id",
        )
        .expect("准备旧 api_tokens 查询失败");
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
            ))
        })
        .expect("查询旧 api_tokens 失败");
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .expect("收集旧 api_tokens 失败")
}

/// 手工建一个 v6 数据库并写入旧数据，返回迁移前的旧表 SQL 与行数快照。
fn create_v6_database(path: &Path) -> (TableSqlSnapshot, TableCountSnapshot) {
    let conn = Connection::open(path).expect("创建 v6 测试库失败");
    conn.execute_batch(V6_SCHEMA).expect("建 v6 schema 失败");

    let agent = expected_agent();
    conn.execute(
        "INSERT INTO agents \
         (agent_id, name, hostname, os, arch, version, boot_id, status, last_seen_at, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            agent.0, agent.1, agent.2, agent.3, agent.4, agent.5, agent.6, agent.7, agent.8,
            agent.9
        ],
    )
    .expect("写入旧 agents 行失败");

    for sample in expected_samples() {
        conn.execute(
            "INSERT INTO samples (agent_id, metric, labels, ts, value) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sample.0, sample.1, sample.2, sample.3, sample.4],
        )
        .expect("写入旧 samples 行失败");
    }

    for token in expected_api_tokens() {
        conn.execute(
            "INSERT INTO api_tokens \
             (name, token_hash, scope, created_at, last_used_at, revoked_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![token.1, token.2, token.3, token.4, token.5, token.6],
        )
        .expect("写入旧 api_tokens 行失败");
    }

    conn.pragma_update(None, "user_version", 6)
        .expect("设置 user_version=6 失败");

    let sql = table_sql(&conn, &V6_TABLES);
    let counts = table_counts(&conn, &V6_TABLES);
    (sql, counts)
}

// ---------------------------------------------------------------------------
// 用例 1：fresh 库的版本、10 张表、12 个索引；重复打开不重复建表。
// ---------------------------------------------------------------------------

#[test]
fn v7_fresh_database_has_version_tables_and_indexes() {
    let dir = TempDbDir::new("fresh");
    {
        let _storage = open_storage(&dir);
    }

    let conn = Connection::open(dir.db_path()).expect("打开 fresh 库失败");
    assert_eq!(user_version(&conn), 7, "fresh 库的 user_version 必须是 7");
    assert_v7_objects(&conn);
    drop(conn);

    // 关闭再打开一次：建表必须幂等，不能报错或产生同名重复对象。
    let storage = open_storage(&dir);
    let conn = Connection::open(dir.db_path()).expect("第二次打开 fresh 库失败");
    assert_eq!(user_version(&conn), 7, "重复打开后 user_version 仍应为 7");
    assert_v7_objects(&conn);
    for table in V7_TABLES {
        assert_eq!(
            object_count(&conn, "table", table),
            1,
            "重复打开后表 {table} 不应出现多次"
        );
    }
    drop(conn);
    drop(storage);
}

// ---------------------------------------------------------------------------
// 用例 2：关键列、主键、UNIQUE 约束（重复插入必须报错）。
// ---------------------------------------------------------------------------

#[test]
fn v7_key_columns_primary_keys_and_unique_constraints() {
    let dir = TempDbDir::new("columns");
    {
        let _storage = open_storage(&dir);
    }
    let conn = Connection::open(dir.db_path()).expect("打开测试库失败");

    // 降采样表：9 列、4 列复合主键、全部 NOT NULL。
    for table in ["samples_1m", "samples_1h"] {
        assert_columns(
            &conn,
            table,
            &[
                ("agent_id", "TEXT", true),
                ("metric", "TEXT", true),
                ("labels", "TEXT", true),
                ("bucket_ts", "INTEGER", true),
                ("min_value", "REAL", true),
                ("max_value", "REAL", true),
                ("avg_value", "REAL", true),
                ("last_value", "REAL", true),
                ("count", "INTEGER", true),
            ],
        );
        assert_primary_key(&conn, table, &["agent_id", "metric", "labels", "bucket_ts"]);
        let cols = columns(&conn, table);
        assert_default(&cols, "labels", "{}");
    }

    // 告警规则表：方案 §4.2 的全部 17 列。
    //
    // 注意：方案 DDL 里 `id TEXT PRIMARY KEY` 没有显式 NOT NULL，SQLite 对
    // 非 STRICT 表的 PRIMARY KEY 不会补 notnull 标记（PRAGMA 报 0）；主键约束
    // 由下面的 assert_primary_key 断言，这里只按方案原文校验列属性。
    assert_columns(
        &conn,
        "alert_rules",
        &[
            ("id", "TEXT", false),
            ("name", "TEXT", true),
            ("enabled", "INTEGER", true),
            ("source", "TEXT", true),
            ("metric", "TEXT", true),
            ("comparator", "TEXT", true),
            ("threshold", "REAL", true),
            ("duration_secs", "INTEGER", true),
            ("cooldown_secs", "INTEGER", true),
            ("filter_agent_id", "TEXT", false),
            ("filter_labels", "TEXT", true),
            ("channel_ids", "TEXT", true),
            ("notify_on_resolve", "INTEGER", true),
            ("is_builtin", "INTEGER", true),
            ("updated_by", "TEXT", true),
            ("created_at", "INTEGER", true),
            ("updated_at", "INTEGER", true),
        ],
    );
    assert_primary_key(&conn, "alert_rules", &["id"]);
    let rule_cols = columns(&conn, "alert_rules");
    assert_default(&rule_cols, "enabled", "0");
    assert_default(&rule_cols, "source", "metric");
    assert_default(&rule_cols, "comparator", "gt");
    assert_default(&rule_cols, "threshold", "0");
    assert_default(&rule_cols, "duration_secs", "0");
    assert_default(&rule_cols, "cooldown_secs", "1800");
    assert_default(&rule_cols, "filter_labels", "{}");
    assert_default(&rule_cols, "channel_ids", "[]");
    assert_default(&rule_cols, "notify_on_resolve", "1");
    assert_default(&rule_cols, "is_builtin", "0");
    assert_default(&rule_cols, "updated_by", "");

    // 告警事件表：方案 §4.2 的全部 11 列（id 同样是未显式 NOT NULL 的主键）。
    assert_columns(
        &conn,
        "alert_events",
        &[
            ("id", "INTEGER", false),
            ("ts", "INTEGER", true),
            ("rule_id", "TEXT", true),
            ("rule_name", "TEXT", true),
            ("agent_id", "TEXT", true),
            ("state", "TEXT", true),
            ("value", "REAL", false),
            ("message", "TEXT", true),
            ("notified", "INTEGER", true),
            ("notify_error", "TEXT", true),
            ("silenced", "INTEGER", true),
        ],
    );
    assert_primary_key(&conn, "alert_events", &["id"]);

    // 归档对象表：方案 §4.3 的全部 14 列（id 同样是未显式 NOT NULL 的主键）。
    assert_columns(
        &conn,
        "archive_objects",
        &[
            ("id", "INTEGER", false),
            ("backend", "TEXT", true),
            ("object_key", "TEXT", true),
            ("manifest_key", "TEXT", true),
            ("from_ts", "INTEGER", true),
            ("to_ts", "INTEGER", true),
            ("rows", "INTEGER", true),
            ("bytes", "INTEGER", true),
            ("sha256", "TEXT", true),
            ("status", "TEXT", true),
            ("error", "TEXT", true),
            ("created_at", "INTEGER", true),
            ("uploaded_at", "INTEGER", false),
            ("deleted_at", "INTEGER", false),
        ],
    );
    assert_primary_key(&conn, "archive_objects", &["id"]);

    // 维护水位表主键为 key。
    assert_primary_key(&conn, "maintenance_state", &["key"]);

    // ---- UNIQUE 约束：重复插入必须报错 ----
    conn.execute(
        "INSERT INTO alert_rules (id, name, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params!["rule-1", "磁盘空间不足", 1_000, 1_000],
    )
    .expect("插入第一条 alert_rules 失败");
    assert_unique_violation(
        conn.execute(
            "INSERT INTO alert_rules (id, name, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params!["rule-2", "磁盘空间不足", 2_000, 2_000],
        ),
        "alert_rules.name 重复",
    );
    conn.execute(
        "INSERT INTO alert_rules (id, name, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4)",
        params!["rule-2", "内存不足", 2_000, 2_000],
    )
    .expect("不同 name 的 alert_rules 应允许插入");

    conn.execute(
        "INSERT INTO notification_channels \
         (id, name, kind, config_json, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "channel-1",
            "值班群",
            "telegram",
            r#"{"chat_id":"1"}"#,
            1_000,
            1_000
        ],
    )
    .expect("插入第一条 notification_channels 失败");
    assert_unique_violation(
        conn.execute(
            "INSERT INTO notification_channels \
             (id, name, kind, config_json, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "channel-2",
                "值班群",
                "wecom",
                r#"{"webhook":"x"}"#,
                2_000,
                2_000
            ],
        ),
        "notification_channels.name 重复",
    );

    let archive_insert = "INSERT INTO archive_objects \
         (backend, object_key, manifest_key, from_ts, to_ts, \"rows\", bytes, sha256, status, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
    conn.execute(
        archive_insert,
        params![
            "s3",
            "raw/2026/10/24/0000.csv.gz",
            "raw/2026/10/24/0000.manifest.json",
            0,
            60_000,
            10,
            100,
            "sha256-alpha",
            "uploaded",
            1_000
        ],
    )
    .expect("插入第一条 archive_objects 失败");
    assert_unique_violation(
        conn.execute(
            archive_insert,
            params![
                "s3",
                "raw/2026/10/24/0000.csv.gz",
                "raw/2026/10/24/0000-other.manifest.json",
                60_000,
                120_000,
                20,
                200,
                "sha256-beta",
                "failed",
                2_000
            ],
        ),
        "archive_objects.object_key 重复",
    );
}

// ---------------------------------------------------------------------------
// 用例 3：v6→v7 迁移守恒旧数据、新表落地、重复打开幂等。
// ---------------------------------------------------------------------------

#[test]
fn v7_migrates_real_v6_database_and_reopen_is_idempotent() {
    let dir = TempDbDir::new("v6-migration");
    let (old_sql, old_counts) = create_v6_database(&dir.db_path());

    // 迁移前先确认 fixture 确实是 v6，且没有任何 v7 表。
    {
        let conn = Connection::open(dir.db_path()).expect("打开 v6 fixture 失败");
        assert_eq!(user_version(&conn), 6, "fixture 的 user_version 必须是 6");
        assert!(
            !object_exists(&conn, "table", "samples_1m"),
            "v6 fixture 不应预先包含 v7 表"
        );
        assert_eq!(read_old_agent(&conn), expected_agent());
        assert_eq!(read_old_samples(&conn), expected_samples());
        assert_eq!(read_old_api_tokens(&conn), expected_api_tokens());
    }

    // 第一次由 v6 打开：迁移到 v7。
    let storage = open_storage(&dir);
    let conn = Connection::open(dir.db_path()).expect("迁移后打开数据库失败");
    assert_eq!(user_version(&conn), 7, "v6→v7 迁移后 user_version 必须是 7");
    assert_v7_objects(&conn);
    assert_eq!(
        read_old_agent(&conn),
        expected_agent(),
        "迁移后旧 agents 行必须逐字段不变"
    );
    assert_eq!(
        read_old_samples(&conn),
        expected_samples(),
        "迁移后旧 samples 行必须逐字段不变"
    );
    assert_eq!(
        read_old_api_tokens(&conn),
        expected_api_tokens(),
        "迁移后旧 api_tokens 行必须逐字段不变"
    );
    assert_eq!(
        table_sql(&conn, &V6_TABLES),
        old_sql,
        "迁移不得改写任何旧表 SQL"
    );
    assert_eq!(
        table_counts(&conn, &V6_TABLES),
        old_counts,
        "迁移不得增删任何旧表行"
    );

    // 公开读接口仍可读取旧数据。
    let agents = storage.list_agents().expect("迁移后 list_agents 失败");
    assert_eq!(agents.len(), 1, "迁移后应仍只有一台旧 agent");
    assert_eq!(agents[0].agent_id, "agent-old");
    assert_eq!(agents[0].status, "online");
    assert_eq!(agents[0].last_seen_at, 1_712_345_678_901);
    assert_eq!(
        storage
            .sample_count("agent-old")
            .expect("迁移后 sample_count 失败"),
        3
    );
    drop(conn);
    drop(storage);

    // 第二次打开：幂等，旧表 SQL 与行数仍与 v6 基线完全一致。
    let storage = open_storage(&dir);
    let conn = Connection::open(dir.db_path()).expect("第二次打开迁移后数据库失败");
    assert_eq!(user_version(&conn), 7, "重复打开后 user_version 必须仍是 7");
    assert_v7_objects(&conn);
    assert_eq!(
        table_sql(&conn, &V6_TABLES),
        old_sql,
        "重复打开不得改写旧表 SQL"
    );
    assert_eq!(
        table_counts(&conn, &V6_TABLES),
        old_counts,
        "重复打开不得改变旧表行数"
    );
    assert_eq!(read_old_agent(&conn), expected_agent());
    assert_eq!(read_old_samples(&conn), expected_samples());
    assert_eq!(read_old_api_tokens(&conn), expected_api_tokens());
    drop(conn);
    drop(storage);
}

// ---------------------------------------------------------------------------
// 用例 4：maintenance_state 的缺失、覆盖写、排序与 updated_at。
// ---------------------------------------------------------------------------

#[test]
fn m4_a1_maintenance_state_get_set_list_and_overwrite() {
    let dir = TempDbDir::new("maintenance-state");
    let storage = open_storage(&dir);

    // 缺失键返回 None，而不是空串。
    assert_eq!(
        storage
            .get_maintenance_state("last_archived_ts")
            .expect("读取缺失水位失败"),
        None,
        "缺失的 maintenance_state 键必须返回 None"
    );

    storage
        .set_maintenance_state("last_archived_ts", "1700000000000", 1_000)
        .expect("首次写入水位失败");
    assert_eq!(
        storage
            .get_maintenance_state("last_archived_ts")
            .expect("读取首次写入水位失败"),
        Some("1700000000000".to_string())
    );

    // 覆盖写：刷新 value/updated_at，且不新增行。
    storage
        .set_maintenance_state("last_archived_ts", "1700000060000", 2_000)
        .expect("覆盖写水位失败");
    assert_eq!(
        storage
            .get_maintenance_state("last_archived_ts")
            .expect("读取覆盖写后的水位失败"),
        Some("1700000060000".to_string())
    );
    let entries = storage
        .list_maintenance_state()
        .expect("覆盖写后 list_maintenance_state 失败");
    assert_eq!(entries.len(), 1, "覆盖写不得新增 maintenance_state 行");
    assert_eq!(entries[0].key, "last_archived_ts");
    assert_eq!(entries[0].value, "1700000060000");
    assert_eq!(entries[0].updated_at, 2_000, "覆盖写必须刷新 updated_at");

    // 乱序写入多个 key，list 必须按 key 升序返回。
    storage
        .set_maintenance_state("b_watermark", "b", 30)
        .expect("写入 b_watermark 失败");
    storage
        .set_maintenance_state("a_watermark", "a", 10)
        .expect("写入 a_watermark 失败");
    storage
        .set_maintenance_state("c_watermark", "c", 20)
        .expect("写入 c_watermark 失败");
    let entries = storage
        .list_maintenance_state()
        .expect("多键 list_maintenance_state 失败");
    let keys: Vec<&str> = entries.iter().map(|entry| entry.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "a_watermark",
            "b_watermark",
            "c_watermark",
            "last_archived_ts"
        ],
        "list_maintenance_state 必须按 key 升序"
    );

    // 直接数行，确认覆盖写没有留下旧行。
    drop(storage);
    let conn = Connection::open(dir.db_path()).expect("打开数据库统计水位行数失败");
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM maintenance_state", [], |row| {
            row.get(0)
        })
        .expect("统计 maintenance_state 行数失败");
    assert_eq!(rows, 4, "覆盖写后应只有 4 行水位");
}

// ---------------------------------------------------------------------------
// 用例 5：边界——空表、重复打开、带引号/SQL 片段的键值按字面量存取。
// ---------------------------------------------------------------------------

#[test]
fn m4_a1_maintenance_state_empty_list_and_literal_roundtrip() {
    let dir = TempDbDir::new("maintenance-literal");
    {
        let storage = open_storage(&dir);
        assert!(
            storage
                .list_maintenance_state()
                .expect("新库 list_maintenance_state 失败")
                .is_empty(),
            "新库的 maintenance_state 列表必须为空"
        );
    }

    // 第二次打开（重复建表路径）不应报错，空列表保持不变。
    let storage = open_storage(&dir);
    assert!(
        storage
            .list_maintenance_state()
            .expect("重复打开后 list_maintenance_state 失败")
            .is_empty(),
        "重复打开后空表仍应为空"
    );

    // 键值故意包含单/双引号、分号、SQL 片段、换行、制表符与中文。
    let key = "水位'\" ; DROP TABLE maintenance_state; -- 中文\n\tend";
    let value = "值'\" ; DELETE FROM maintenance_state; -- '{}'\n第二行";
    storage
        .set_maintenance_state(key, value, 42)
        .expect("写入特殊字符水位失败");
    assert_eq!(
        storage
            .get_maintenance_state(key)
            .expect("读取特殊字符水位失败"),
        Some(value.to_string()),
        "特殊字符必须按字面量原样读回"
    );
    assert_eq!(
        storage
            .get_maintenance_state("水位")
            .expect("读取另一个缺失键失败"),
        None
    );
    let entries = storage
        .list_maintenance_state()
        .expect("特殊字符场景 list_maintenance_state 失败");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, key);
    assert_eq!(entries[0].value, value);
    assert_eq!(entries[0].updated_at, 42);
    drop(storage);

    // 表仍然存在、行仍在：特殊字符没有被当成 SQL 执行。
    let conn = Connection::open(dir.db_path()).expect("打开数据库验证字面量存储失败");
    assert!(
        object_exists(&conn, "table", "maintenance_state"),
        "字面量键值不得破坏 maintenance_state 表"
    );
    let rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM maintenance_state", [], |row| {
            row.get(0)
        })
        .expect("统计 maintenance_state 行数失败");
    assert_eq!(rows, 1);
    let stored: String = conn
        .query_row(
            "SELECT \"value\" FROM maintenance_state WHERE \"key\" = ?1",
            params![key],
            |row| row.get(0),
        )
        .expect("按原样键读取水位失败");
    assert_eq!(stored, value);
}

// ---------------------------------------------------------------------------
// 用例 6：错误路径——samples_1m 的 4 列复合主键拒绝完全重复的桶行。
// ---------------------------------------------------------------------------

#[test]
fn m4_a1_samples_1m_primary_key_rejects_duplicate() {
    let dir = TempDbDir::new("samples-1m-pk");
    {
        let _storage = open_storage(&dir);
    }
    let conn = Connection::open(dir.db_path()).expect("打开测试库失败");

    let insert = "INSERT INTO samples_1m \
         (agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, last_value, \"count\") \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)";

    conn.execute(
        insert,
        params![
            "agent-1",
            "cpu.usage",
            r#"{"core":"0"}"#,
            60_000,
            1.0,
            2.0,
            1.5,
            2.0,
            2
        ],
    )
    .expect("插入第一条 samples_1m 失败");

    // 完全相同的 (agent_id, metric, labels, bucket_ts) 必须冲突。
    assert_unique_violation(
        conn.execute(
            insert,
            params![
                "agent-1",
                "cpu.usage",
                r#"{"core":"0"}"#,
                60_000,
                9.0,
                10.0,
                9.5,
                10.0,
                7
            ],
        ),
        "samples_1m 复合主键重复",
    );

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM samples_1m", [], |row| row.get(0))
        .expect("统计 samples_1m 行数失败");
    assert_eq!(count, 1, "主键冲突后不得留下重复行");

    // 同 labels、不同 bucket_ts 是不同主键，允许插入。
    conn.execute(
        insert,
        params![
            "agent-1",
            "cpu.usage",
            r#"{"core":"0"}"#,
            120_000,
            2.0,
            3.0,
            2.5,
            3.0,
            2
        ],
    )
    .expect("不同 bucket_ts 的 samples_1m 应允许插入");

    // 同 bucket_ts、不同 labels 也是不同主键，允许插入。
    conn.execute(
        insert,
        params!["agent-1", "cpu.usage", "{}", 60_000, 4.0, 5.0, 4.5, 5.0, 2],
    )
    .expect("不同 labels 的 samples_1m 应允许插入");

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM samples_1m", [], |row| row.get(0))
        .expect("统计 samples_1m 行数失败");
    assert_eq!(count, 3);
}
