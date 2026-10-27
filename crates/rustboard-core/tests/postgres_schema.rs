//! Phase D2：PostgreSQL schema / migration 实库集成测试。
//!
//! 只依据 `docs/plans/2026-10-26-m5-phase-d-postgres-backup-l01-l03.md` §3.3、
//! §5 D2 与 `docs/plans/2026-10-26-m5-phase-d-pg-spike.md` §3/§8 编写；不实现
//! `Storage` 方法（D3），也不改 SQLite schema。
//!
//! # 运行方式
//!
//! ```bash
//! docker run -d --name rustboard-pg-d2 -p 127.0.0.1:55434:5432 \
//!   -e POSTGRES_USER=rustboard -e POSTGRES_PASSWORD='<TEST_PASSWORD>' \
//!   -e POSTGRES_DB=rustboard postgres:17
//! RUSTBOARD_TEST_PG='postgres://rustboard:<TEST_PASSWORD>@127.0.0.1:55434/rustboard?sslmode=disable' \
//!   cargo test -p rustboard-core --test postgres_schema --locked -- --nocapture
//! ```
//!
//! 未设置 `RUSTBOARD_TEST_PG` 时用例打印 `SKIP` 并返回（cargo 会记为 passed，
//! 但日志明确标注未执行）；只有设置该变量并连上真实 PG 才算通过。DSN 必须
//! 显式 `sslmode=disable`：D2 的 schema 连接只支持明文回环，TLS/pool 是 D3 的范围。
//!
//! 每个用例创建一个独立数据库（`rb_d2_<tag>_<pid>_<nanos>_<seq>`），结束时
//! `DROP DATABASE ... WITH (FORCE)`；用例可并行且互不污染。因此
//! `RUSTBOARD_TEST_PG` 对应的角色需要 `CREATEDB` 权限（本地容器默认 superuser 即可）。
//!
//! 注意：这里**故意**不提交任何密码/真实 IP；测试 DSN 只存在于运行环境。

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use postgres::config::SslMode;
use postgres::error::SqlState;
use postgres::{Client, NoTls};
use rustboard_core::storage::postgres::schema::{
    apply_schema, connect_for_schema, POSTGRES_SCHEMA_VERSION, SCHEMA_ADVISORY_LOCK_KEY,
};
use rustboard_core::storage::sqlite::SqliteStorage;

/// 实库测试 DSN 的环境变量；未设置时全部 JSON schema 用例 skip。
const PG_ENV: &str = "RUSTBOARD_TEST_PG";

/// 21 张业务表（与 SQLite v8 一致），本清单独立于实现硬编码。
const TABLES: [&str; 21] = [
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
    "archive_objects",
    "archive_state",
];

/// SQLite v8 的显式命名索引（22 个）。
///
/// v8 在 v7 的 19 个命名索引上新增 3 个 partial index；其余是
/// `sqlite_autoindex_*` 主键/唯一约束的隐式索引。本文件以真实 SQLite 建库
/// 结果为准（见 `table_and_index_sets_match_sqlite_baseline`）。
const INDEXES: [&str; 22] = [
    "idx_samples_lookup",
    "idx_samples_ts",
    "idx_ingest_batches_ts",
    "idx_audit_ts",
    "idx_audit_agent_ts",
    "idx_api_tokens_hash",
    "idx_samples_1m_lookup",
    "idx_samples_1m_ts",
    "idx_samples_1h_lookup",
    "idx_samples_1h_ts",
    "idx_samples_metric_ts",
    "idx_alert_states_state_eval",
    "idx_alert_events_ts",
    "idx_alert_events_rule_ts",
    "idx_alert_events_agent_ts",
    "idx_alert_events_pending",
    "idx_alert_silences_until",
    "idx_archive_objects_range",
    "idx_archive_objects_status",
    "idx_samples_unarchived",
    "idx_samples_unaggregated",
    "idx_samples_1m_unaggregated",
];

/// 每次调用返回递增序号，避免同一纳秒内两个用例撞库名。
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

fn skip(test_name: &str) {
    eprintln!("SKIP {test_name}: 未设置 {PG_ENV}（D2 实库测试需要 PostgreSQL）");
}

/// 解析 `RUSTBOARD_TEST_PG`；未设置或空串时返回 `None`。
fn base_config() -> Option<postgres::Config> {
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
        "{PG_ENV} 必须显式 sslmode=disable（D2 的 schema 连接不做 TLS）"
    );
    Some(config)
}

/// D2 的 schema 连接入口必须真的能用 `sslmode=disable` 连上测试库。
#[test]
fn connect_for_schema_works_with_sslmode_disable() {
    const NAME: &str = "connect_for_schema_works_with_sslmode_disable";
    let Some(dsn) = std::env::var(PG_ENV)
        .ok()
        .filter(|dsn| !dsn.trim().is_empty())
    else {
        skip(NAME);
        return;
    };
    let mut client = connect_for_schema(&dsn).expect("connect_for_schema 必须能连上测试库");
    let one: i32 = client
        .query_one("SELECT 1", &[])
        .expect("schema 连接必须能执行查询")
        .get(0);
    assert_eq!(one, 1);
}

/// 一个临时测试数据库；`Drop` 时用维护库连接强制删除。
struct TestDatabase {
    name: String,
    /// 指向 `postgres` 维护库，用于 CREATE/DROP DATABASE。
    admin: postgres::Config,
    /// 指向测试库。
    app: postgres::Config,
}

impl TestDatabase {
    fn create(tag: &str) -> Option<Self> {
        let mut base = base_config()?;
        let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!("rb_d2_{tag}_{}_{nanos}_{seq}", std::process::id());
        assert!(
            name.len() <= 63,
            "测试库名超过 PostgreSQL 标识符上限：{name}"
        );
        assert!(
            name.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "测试库名只允许小写字母/数字/下划线：{name}"
        );

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

        base.dbname(&name);
        eprintln!("[d2] 创建测试数据库 {name}（tag={tag}）");
        Some(Self {
            name,
            admin,
            app: base,
        })
    }

    fn connect(&self) -> Client {
        self.app
            .connect(NoTls)
            .unwrap_or_else(|e| panic!("连接测试库 {} 失败：{e}", self.name))
    }

    fn app_config(&self) -> postgres::Config {
        self.app.clone()
    }
}

impl Drop for TestDatabase {
    fn drop(&mut self) {
        let mut client = match self.admin.connect(NoTls) {
            Ok(client) => client,
            Err(e) => {
                eprintln!(
                    "[d2] 清理失败：无法连接维护库删除 {}（请手工 DROP）：{e}",
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
                "[d2] 清理失败：DROP DATABASE {} 出错（请手工清理）：{e}",
                self.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 断言辅助
// ---------------------------------------------------------------------------

/// 当前测试库 public schema 下的基础表名（按名称排序）。
fn table_names(client: &mut Client) -> Vec<String> {
    client
        .query(
            "SELECT table_name::text FROM information_schema.tables
             WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
             ORDER BY table_name",
            &[],
        )
        .expect("查询 information_schema.tables 失败")
        .iter()
        .map(|row| row.get(0))
        .collect()
}

/// 当前测试库 public schema 下的全部索引名（按名称排序）。
fn index_names(client: &mut Client) -> Vec<String> {
    client
        .query(
            "SELECT indexname::text FROM pg_indexes
             WHERE schemaname = 'public' ORDER BY indexname",
            &[],
        )
        .expect("查询 pg_indexes 失败")
        .iter()
        .map(|row| row.get(0))
        .collect()
}

fn named_index_names(client: &mut Client) -> BTreeSet<String> {
    index_names(client)
        .into_iter()
        .filter(|name| name.starts_with("idx_"))
        .collect()
}

fn schema_version(client: &mut Client) -> i64 {
    client
        .query_one(
            "SELECT COALESCE(MAX(version), 0)::bigint FROM schema_migrations",
            &[],
        )
        .expect("读取 schema_migrations 版本失败")
        .get(0)
}

fn migration_row_count(client: &mut Client) -> i64 {
    client
        .query_one("SELECT COUNT(*)::bigint FROM schema_migrations", &[])
        .expect("统计 schema_migrations 行数失败")
        .get(0)
}

/// `(data_type, is_nullable, column_default)`。
fn column_meta(client: &mut Client, table: &str, column: &str) -> (String, String, Option<String>) {
    let row = client
        .query_one(
            "SELECT data_type::text, is_nullable::text, column_default::text
             FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2",
            &[&table, &column],
        )
        .unwrap_or_else(|e| panic!("读取列 {table}.{column} 元数据失败：{e}"));
    (row.get(0), row.get(1), row.get(2))
}

fn assert_all_21_tables(client: &mut Client) {
    let mut expected: Vec<String> = TABLES.iter().map(|table| table.to_string()).collect();
    expected.push("schema_migrations".to_string());
    expected.sort_unstable();
    assert_eq!(
        table_names(client),
        expected,
        "public schema 必须恰好是 21 张业务表 + schema_migrations"
    );
}

fn assert_all_named_indexes(client: &mut Client) {
    let actual = named_index_names(client);
    for index in INDEXES {
        assert!(
            actual.contains(index),
            "缺少 SQLite 基线索引 {index}；实际命名索引：{actual:?}"
        );
    }
    assert_eq!(
        actual.len(),
        INDEXES.len(),
        "PG 命名索引数量必须与 SQLite 基线一致（不允许多余的 idx_*）"
    );
}

/// 用真实 SQLite v8 建库，返回 `(业务表集合, 显式命名索引集合)`。
///
/// 不依赖 schema 常量，直接读 `sqlite_master`，作为 PG 表/索引的对照基线。
fn sqlite_baseline_objects() -> (BTreeSet<String>, BTreeSet<String>) {
    let seq = DB_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("rb-d2-sqlite-{}-{nanos}-{seq}", std::process::id()));
    fs::create_dir_all(&dir).expect("创建 SQLite 测试目录失败");
    let db_path = dir.join("baseline.db");

    // SqliteStorage::open 会建全量 v8 schema；drop 后再用独立连接读目录表。
    let storage = SqliteStorage::open(&db_path).expect("创建 SQLite v8 基线失败");
    drop(storage);

    let connection = rusqlite::Connection::open(&db_path).expect("打开 SQLite 基线失败");
    let tables = sqlite_object_names(&connection, "table");
    let indexes = sqlite_object_names(&connection, "index");
    drop(connection);
    fs::remove_dir_all(&dir).ok();
    (tables, indexes)
}

/// 读 `sqlite_master` 中某一类对象名，过滤掉 `sqlite_*` 内部对象
/// （如 `sqlite_sequence` 与 `sqlite_autoindex_*`）。
fn sqlite_object_names(connection: &rusqlite::Connection, kind: &str) -> BTreeSet<String> {
    let mut stmt = connection
        .prepare(
            "SELECT name FROM sqlite_master
             WHERE type = ?1 AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .expect("准备 sqlite_master 查询失败");
    let rows = stmt
        .query_map([kind], |row| row.get::<_, String>(0))
        .expect("查询 sqlite_master 失败");
    rows.map(|row| row.expect("读取 sqlite_master 行失败"))
        .collect()
}

// ---------------------------------------------------------------------------
// 1. 空库：21 张表 + 22 个索引 + 版本 8
// ---------------------------------------------------------------------------

#[test]
fn empty_database_apply_creates_21_tables_and_22_indexes() {
    const NAME: &str = "empty_database_apply_creates_21_tables_and_22_indexes";
    let Some(db) = TestDatabase::create("empty") else {
        skip(NAME);
        return;
    };
    let mut client = db.connect();

    apply_schema(&mut client).expect("空库 apply_schema 必须成功");

    assert_eq!(schema_version(&mut client), POSTGRES_SCHEMA_VERSION);
    assert_eq!(migration_row_count(&mut client), 1, "版本表应只有一行 v8");
    assert_all_21_tables(&mut client);
    assert_all_named_indexes(&mut client);

    // SQLite 基线的 22 个命名索引必须全部存在；PG 另有主键/唯一约束的隐式索引。
    let all_indexes = index_names(&mut client);
    eprintln!(
        "[d2] 空库结果：tables={} named_indexes={} all_indexes={}",
        table_names(&mut client).len(),
        named_index_names(&mut client).len(),
        all_indexes.len()
    );
    assert!(
        all_indexes.len() > INDEXES.len(),
        "PG 应额外存在主键/唯一约束的隐式索引"
    );
}

// ---------------------------------------------------------------------------
// 2. 表/索引集合与真实 SQLite 基线对照
// ---------------------------------------------------------------------------

#[test]
fn table_and_index_sets_match_sqlite_baseline() {
    const NAME: &str = "table_and_index_sets_match_sqlite_baseline";
    let Some(db) = TestDatabase::create("parity") else {
        skip(NAME);
        return;
    };
    let mut client = db.connect();
    apply_schema(&mut client).expect("apply_schema 必须成功");

    let pg_tables: BTreeSet<String> = table_names(&mut client)
        .into_iter()
        // schema_migrations 是 PG 独立的版本表，SQLite 用 PRAGMA，不参与对照。
        .filter(|table| table != "schema_migrations")
        .collect();
    let pg_indexes = named_index_names(&mut client);
    let (sqlite_tables, sqlite_indexes) = sqlite_baseline_objects();

    assert_eq!(sqlite_tables.len(), 21, "SQLite v8 应有 21 张业务表");
    assert_eq!(
        pg_tables, sqlite_tables,
        "PG 21 张业务表必须与真实 SQLite v8 的 sqlite_master 完全一致"
    );
    assert_eq!(
        pg_indexes, sqlite_indexes,
        "PG 命名索引集合必须与真实 SQLite v8 的 sqlite_master 完全一致"
    );
    eprintln!(
        "[d2] 对照：SQLite tables={} indexes={}，PG tables={} named_indexes={}",
        sqlite_tables.len(),
        sqlite_indexes.len(),
        pg_tables.len(),
        pg_indexes.len()
    );
}

// ---------------------------------------------------------------------------
// 3. 类型映射、布尔列、可空性与 upsert/CHECK 约束
// ---------------------------------------------------------------------------

#[test]
fn type_mapping_booleans_constraints_and_upsert_targets() {
    const NAME: &str = "type_mapping_booleans_constraints_and_upsert_targets";
    let Some(db) = TestDatabase::create("types") else {
        skip(NAME);
        return;
    };
    let mut client = db.connect();
    apply_schema(&mut client).expect("apply_schema 必须成功");

    // 时间/计数 BIGINT、REAL DOUBLE PRECISION、TEXT 保持。
    for (table, column, expected) in [
        ("agents", "last_seen_at", "bigint"),
        ("agents", "created_at", "bigint"),
        ("samples", "ts", "bigint"),
        ("samples", "value", "double precision"),
        ("samples", "labels", "text"),
        ("samples_1m", "count", "bigint"),
        ("samples_1m", "avg_value", "double precision"),
        ("alert_rules", "threshold", "double precision"),
        ("audit_log", "duration_ms", "bigint"),
        ("archive_objects", "rows", "bigint"),
        ("archive_objects", "bytes", "bigint"),
        ("archive_objects", "ledger_version", "bigint"),
        ("archive_objects", "attempts", "bigint"),
        ("samples", "archive_object_id", "bigint"),
        ("samples", "aggregated_1m", "bigint"),
        ("samples_1m", "last_ts", "bigint"),
        ("samples_1m", "aggregated_1h", "bigint"),
    ] {
        let (data_type, _, _) = column_meta(&mut client, table, column);
        assert_eq!(
            data_type, expected,
            "{table}.{column} 类型应为 {expected}，实际 {data_type}"
        );
    }

    // 布尔列：不能沿用 SQLite 的 INTEGER。
    for (table, column) in [
        ("alert_rules", "enabled"),
        ("alert_rules", "notify_on_resolve"),
        ("alert_rules", "is_builtin"),
        ("alert_events", "notified"),
        ("alert_events", "silenced"),
        ("notification_channels", "enabled"),
    ] {
        let (data_type, nullable, _) = column_meta(&mut client, table, column);
        assert_eq!(data_type, "boolean", "{table}.{column} 必须是 BOOLEAN");
        assert_eq!(nullable, "NO", "{table}.{column} 必须 NOT NULL");
    }

    // 4 张需要稳定行序/删除游标的表：id BIGSERIAL PRIMARY KEY（D3 替代 rowid）。
    for table in ["samples", "samples_1m", "samples_1h", "alert_states"] {
        let (data_type, nullable, default) = column_meta(&mut client, table, "id");
        assert_eq!(data_type, "bigint", "{table}.id 必须是 BIGSERIAL(bigint)");
        assert_eq!(nullable, "NO", "{table}.id 必须 NOT NULL");
        assert!(
            default.as_deref().unwrap_or("").contains("nextval"),
            "{table}.id 必须有序列默认值，实际 {default:?}"
        );
    }

    // 可空列必须与 SQLite 原样一致。
    for (table, column) in [
        ("enroll_tokens", "used_at"),
        ("api_tokens", "last_used_at"),
        ("api_tokens", "revoked_at"),
        ("alert_rules", "filter_agent_id"),
        ("alert_states", "last_value"),
        ("alert_states", "last_notified_at"),
        ("alert_events", "value"),
        ("alert_silences", "rule_id"),
        ("alert_silences", "agent_id"),
        ("archive_objects", "uploaded_at"),
        ("archive_objects", "deleted_at"),
    ] {
        let (_, nullable, _) = column_meta(&mut client, table, column);
        assert_eq!(nullable, "YES", "{table}.{column} 应可空（与 SQLite 对齐）");
    }

    // v8 列的默认值/可空性必须与 SQLite 语义一致。
    for (table, column) in [
        ("samples", "aggregated_1m"),
        ("samples_1m", "last_ts"),
        ("samples_1m", "aggregated_1h"),
        ("archive_objects", "ledger_version"),
        ("archive_objects", "attempts"),
    ] {
        let (_, nullable, default) = column_meta(&mut client, table, column);
        assert_eq!(nullable, "NO", "{table}.{column} 必须 NOT NULL");
        assert_eq!(
            default.as_deref().map(str::trim),
            Some("0"),
            "{table}.{column} 默认值应为 0，实际 {default:?}"
        );
    }
    let (_, nullable, _) = column_meta(&mut client, "samples", "archive_object_id");
    assert_eq!(nullable, "YES", "samples.archive_object_id 必须可空");

    // v8 partial index 的谓词必须随 DDL 落地（不能只建普通索引）。
    for (index, predicate) in [
        ("idx_samples_unarchived", "archive_object_id IS NULL"),
        ("idx_samples_unaggregated", "aggregated_1m = 0"),
        ("idx_samples_1m_unaggregated", "aggregated_1h = 0"),
    ] {
        let definition: String = client
            .query_one(
                "SELECT indexdef FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1",
                &[&index],
            )
            .unwrap_or_else(|e| panic!("读取索引 {index} 定义失败：{e}"))
            .get(0);
        assert!(
            definition.contains("WHERE") && definition.contains(predicate),
            "索引 {index} 必须是 partial index（{predicate}），实际：{definition}"
        );
    }

    // NOT NULL 的 error 字段不能被放宽。
    for (table, column) in [
        ("audit_log", "error_code"),
        ("audit_log", "error_message"),
        ("archive_objects", "error"),
    ] {
        let (_, nullable, _) = column_meta(&mut client, table, column);
        assert_eq!(nullable, "NO", "{table}.{column} 必须 NOT NULL");
    }

    // upsert 目标 1：samples_1m 的复合 UNIQUE（SQLite 原复合主键）。
    for _ in 0..2 {
        client
            .batch_execute(
                "INSERT INTO samples_1m
                     (agent_id, metric, labels, bucket_ts, min_value, max_value, avg_value, last_value, count)
                 VALUES ('a1', 'cpu.usage', '{}', 60000, 1.0, 2.0, 1.5, 2.0, 10)
                 ON CONFLICT (agent_id, metric, labels, bucket_ts) DO UPDATE SET
                     count = samples_1m.count + excluded.count,
                     avg_value = excluded.avg_value",
            )
            .expect("samples_1m upsert 必须命中 UNIQUE 约束");
    }
    let (rows, count): (i64, i64) = {
        let row = client
            .query_one(
                "SELECT COUNT(*)::bigint, MAX(count)::bigint FROM samples_1m",
                &[],
            )
            .expect("统计 samples_1m 失败");
        (row.get(0), row.get(1))
    };
    assert_eq!(rows, 1, "复合 UNIQUE 必须阻止重复桶");
    assert_eq!(count, 20, "upsert 必须累加 count");

    // upsert 目标 2：alert_states 的复合 UNIQUE（SQLite 原复合主键）。
    for state in ["pending", "firing"] {
        client
            .execute(
                "INSERT INTO alert_states
                     (rule_id, agent_id, series_key, state, since, last_eval_at)
                 VALUES ('rule-1', '', '', $1, 1000, 2000)
                 ON CONFLICT (rule_id, agent_id, series_key) DO UPDATE SET
                     state = excluded.state,
                     last_eval_at = excluded.last_eval_at",
                &[&state],
            )
            .expect("alert_states upsert 必须命中 UNIQUE 约束");
    }
    let (rows, state): (i64, String) = {
        let row = client
            .query_one(
                "SELECT COUNT(*)::bigint, MAX(state) FROM alert_states
                 WHERE rule_id = 'rule-1'",
                &[],
            )
            .expect("统计 alert_states 失败");
        (row.get(0), row.get(1))
    };
    assert_eq!(rows, 1, "复合 UNIQUE 必须阻止重复状态行");
    assert_eq!(state, "firing");

    // CHECK(scope)：非法 scope 必须被数据库拒绝。
    let err = client
        .execute(
            "INSERT INTO api_tokens (name, token_hash, scope, created_at)
             VALUES ('bad', 'hash-bad', 'root', 1)",
            &[],
        )
        .expect_err("非法 scope 必须违反 CHECK");
    assert_eq!(
        err.as_db_error().map(|e| e.code()),
        Some(&SqlState::CHECK_VIOLATION),
        "scope CHECK 错误码不对：{err}"
    );

    // UNIQUE(name)：重名规则必须被拒绝。
    client
        .batch_execute(
            "INSERT INTO alert_rules (id, name, created_at, updated_at)
             VALUES ('r1', 'same-name', 1, 1)",
        )
        .expect("插入第一条规则失败");
    let err = client
        .execute(
            "INSERT INTO alert_rules (id, name, created_at, updated_at)
             VALUES ('r2', 'same-name', 2, 2)",
            &[],
        )
        .expect_err("重复规则名必须违反 UNIQUE");
    assert_eq!(
        err.as_db_error().map(|e| e.code()),
        Some(&SqlState::UNIQUE_VIOLATION),
        "name UNIQUE 错误码不对：{err}"
    );

    // 序列默认值：不传 id 也能插入，且 id 由数据库生成（D3 依赖它排序）。
    client
        .execute(
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('a-id', 'cpu.usage', '{}', 1000, 1.0)",
            &[],
        )
        .expect("samples.id 必须有序列默认值");
    let sample_id: i64 = client
        .query_one(
            "SELECT id FROM samples WHERE agent_id = 'a-id' AND ts = 1000",
            &[],
        )
        .expect("读取 samples.id 失败")
        .get(0);
    assert!(sample_id > 0, "BIGSERIAL 必须生成正数 id，实际 {sample_id}");

    // NOT NULL：省略无默认值的 value 必须失败。
    let err = client
        .execute(
            "INSERT INTO samples (agent_id, metric, labels, ts)
             VALUES ('a-id', 'cpu.usage', '{}', 2000)",
            &[],
        )
        .expect_err("samples 必填列缺失必须失败");
    assert_eq!(
        err.as_db_error().map(|e| e.code()),
        Some(&SqlState::NOT_NULL_VIOLATION)
    );
}

// ---------------------------------------------------------------------------
// 4. 重复 apply 幂等
// ---------------------------------------------------------------------------

#[test]
fn repeated_apply_is_idempotent_and_preserves_data() {
    const NAME: &str = "repeated_apply_is_idempotent_and_preserves_data";
    let Some(db) = TestDatabase::create("idempotent") else {
        skip(NAME);
        return;
    };
    let mut client = db.connect();

    apply_schema(&mut client).expect("首次 apply_schema 必须成功");
    let applied_at: i64 = client
        .query_one(
            "SELECT applied_at FROM schema_migrations WHERE version = $1",
            &[&POSTGRES_SCHEMA_VERSION],
        )
        .expect("读取 applied_at 失败")
        .get(0);
    let tables_before = table_names(&mut client);
    let indexes_before = index_names(&mut client);

    client
        .batch_execute(
            "INSERT INTO agents (agent_id, name, hostname, status, last_seen_at, created_at)
             VALUES ('a-idem', '保数据', 'h1', 'online', 111, 222);
             INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('a-idem', 'cpu.usage', '{\"core\":\"0\"}', 333, 12.5);",
        )
        .expect("写入幂等测试数据失败");

    apply_schema(&mut client).expect("第二次 apply_schema 必须成功（幂等）");
    apply_schema(&mut client).expect("第三次 apply_schema 必须成功（幂等）");

    assert_eq!(schema_version(&mut client), POSTGRES_SCHEMA_VERSION);
    assert_eq!(migration_row_count(&mut client), 1, "版本行不得重复");
    let applied_at_after: i64 = client
        .query_one(
            "SELECT applied_at FROM schema_migrations WHERE version = $1",
            &[&POSTGRES_SCHEMA_VERSION],
        )
        .expect("读取 applied_at 失败")
        .get(0);
    assert_eq!(applied_at, applied_at_after, "幂等路径不得改写 applied_at");
    assert_eq!(tables_before, table_names(&mut client), "表集合不得变化");
    assert_eq!(indexes_before, index_names(&mut client), "索引集合不得变化");

    let (agent_name, sample_count): (String, i64) = {
        let row = client
            .query_one(
                "SELECT a.name, (SELECT COUNT(*) FROM samples WHERE agent_id = 'a-idem')::bigint
                 FROM agents a WHERE a.agent_id = 'a-idem'",
                &[],
            )
            .expect("读取幂等测试数据失败");
        (row.get(0), row.get(1))
    };
    assert_eq!(agent_name, "保数据", "重复 apply 不得改数据");
    assert_eq!(sample_count, 1, "重复 apply 不得删数据");
}

// ---------------------------------------------------------------------------
// 5. 半迁移：表在、无版本行、已有数据
// ---------------------------------------------------------------------------

#[test]
fn half_migration_keeps_existing_rows_and_completes_schema() {
    const NAME: &str = "half_migration_keeps_existing_rows_and_completes_schema";
    let Some(db) = TestDatabase::create("half") else {
        skip(NAME);
        return;
    };
    let mut client = db.connect();

    // 模拟 DDL 执行到一半（agents/samples 已建、无 schema_migrations）后中断。
    client
        .batch_execute(
            "CREATE TABLE agents (
                 agent_id     TEXT PRIMARY KEY,
                 name         TEXT NOT NULL,
                 hostname     TEXT NOT NULL,
                 os           TEXT NOT NULL DEFAULT '',
                 arch         TEXT NOT NULL DEFAULT '',
                 version      TEXT NOT NULL DEFAULT '',
                 boot_id      TEXT NOT NULL DEFAULT '',
                 status       TEXT NOT NULL DEFAULT 'offline',
                 last_seen_at BIGINT NOT NULL DEFAULT 0,
                 created_at   BIGINT NOT NULL DEFAULT 0
             );
             CREATE TABLE samples (
                 id       BIGSERIAL PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 metric   TEXT NOT NULL,
                 labels   TEXT NOT NULL DEFAULT '{}',
                 ts       BIGINT NOT NULL,
                 value    DOUBLE PRECISION NOT NULL
             );
             INSERT INTO agents (agent_id, name, hostname, status, last_seen_at, created_at)
             VALUES ('half-agent', '半迁移数据', 'host-half', 'online', 123, 456);
             INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('half-agent', 'cpu.usage', '{}', 999, 42.5);",
        )
        .expect("构造半迁移库失败");

    assert_eq!(
        table_names(&mut client),
        vec!["agents".to_string(), "samples".to_string()],
        "半迁移前置状态应为两张表"
    );

    apply_schema(&mut client).expect("半迁移库必须能用 IF NOT EXISTS 补齐");

    assert_eq!(schema_version(&mut client), POSTGRES_SCHEMA_VERSION);
    assert_all_21_tables(&mut client);
    assert_all_named_indexes(&mut client);

    let name: String = client
        .query_one("SELECT name FROM agents WHERE agent_id = 'half-agent'", &[])
        .expect("读取保留的 agent 失败")
        .get(0);
    assert_eq!(name, "半迁移数据", "补齐 schema 不得丢已有行");

    let value: f64 = client
        .query_one(
            "SELECT value FROM samples WHERE agent_id = 'half-agent' AND ts = 999",
            &[],
        )
        .expect("读取保留的 sample 失败")
        .get(0);
    assert_eq!(value, 42.5, "补齐 schema 不得改已有样本");

    // 补出来的表必须真的可用（不是仅存在于名字层面）。
    client
        .execute(
            "INSERT INTO archive_state (key, value, updated_at) VALUES ('half', 'ok', 1)",
            &[],
        )
        .expect("补齐后的 archive_state 必须可写");
}

// ---------------------------------------------------------------------------
// 5b. v7 旧库：显式 ALTER 补 v8 列 + partial index，旧数据保留
// ---------------------------------------------------------------------------

#[test]
fn v7_database_is_altered_to_v8_without_losing_rows() {
    const NAME: &str = "v7_database_is_altered_to_v8_without_losing_rows";
    let Some(db) = TestDatabase::create("v7_alter") else {
        skip(NAME);
        return;
    };
    let mut client = db.connect();
    client
        .batch_execute(
            "CREATE TABLE schema_migrations (
                 version BIGINT PRIMARY KEY,
                 applied_at BIGINT NOT NULL
             );
             INSERT INTO schema_migrations VALUES (7, 1);
             CREATE TABLE samples (
                 id       BIGSERIAL PRIMARY KEY,
                 agent_id TEXT NOT NULL,
                 metric   TEXT NOT NULL,
                 labels   TEXT NOT NULL DEFAULT '{}',
                 ts       BIGINT NOT NULL,
                 value    DOUBLE PRECISION NOT NULL
             );
             INSERT INTO samples (agent_id, metric, labels, ts, value)
             VALUES ('a7', 'cpu.usage', '{}', 30000, 1.0);
             CREATE TABLE samples_1m (
                 id         BIGSERIAL PRIMARY KEY,
                 agent_id   TEXT NOT NULL,
                 metric     TEXT NOT NULL,
                 labels     TEXT NOT NULL DEFAULT '{}',
                 bucket_ts  BIGINT NOT NULL,
                 min_value  DOUBLE PRECISION NOT NULL,
                 max_value  DOUBLE PRECISION NOT NULL,
                 avg_value  DOUBLE PRECISION NOT NULL,
                 last_value DOUBLE PRECISION NOT NULL,
                 count      BIGINT NOT NULL,
                 CONSTRAINT samples_1m_unique UNIQUE (agent_id, metric, labels, bucket_ts)
             );
             INSERT INTO samples_1m
                 (agent_id, metric, labels, bucket_ts, min_value, max_value,
                  avg_value, last_value, count)
             VALUES ('a7', 'cpu.usage', '{}', 60000, 1, 1, 1, 1, 1);
             CREATE TABLE archive_objects (
                 id           BIGSERIAL PRIMARY KEY,
                 backend      TEXT NOT NULL,
                 object_key   TEXT NOT NULL UNIQUE,
                 manifest_key TEXT NOT NULL,
                 from_ts      BIGINT NOT NULL,
                 to_ts        BIGINT NOT NULL,
                 rows         BIGINT NOT NULL,
                 bytes        BIGINT NOT NULL,
                 sha256       TEXT NOT NULL,
                 status       TEXT NOT NULL,
                 error        TEXT NOT NULL DEFAULT '',
                 created_at   BIGINT NOT NULL,
                 uploaded_at  BIGINT,
                 deleted_at   BIGINT
             );
             INSERT INTO archive_objects
                 (backend, object_key, manifest_key, from_ts, to_ts, rows, bytes,
                  sha256, status, created_at)
             VALUES ('webdav', 'v7/old.csv.gz', 'v7/old.manifest.json', 0, 60000, 1,
                     10, repeat('a', 64), 'uploaded', 1);",
        )
        .expect("构造 v7 PG 库失败");

    apply_schema(&mut client).expect("v7→v8 迁移必须成功");

    assert_eq!(schema_version(&mut client), POSTGRES_SCHEMA_VERSION);
    for (table, column, expected_default) in [
        ("samples", "aggregated_1m", Some("0")),
        ("samples_1m", "last_ts", Some("0")),
        ("samples_1m", "aggregated_1h", Some("0")),
        ("archive_objects", "ledger_version", Some("0")),
        ("archive_objects", "attempts", Some("0")),
    ] {
        let (data_type, nullable, default) = column_meta(&mut client, table, column);
        assert_eq!(data_type, "bigint", "{table}.{column} 必须是 BIGINT");
        assert_eq!(nullable, "NO", "{table}.{column} 必须 NOT NULL");
        assert_eq!(
            default.as_deref().map(str::trim),
            expected_default,
            "{table}.{column} 默认值不符"
        );
    }
    let (_, nullable, _) = column_meta(&mut client, "samples", "archive_object_id");
    assert_eq!(nullable, "YES");

    // ALTER 不得丢数据；v7 旧桶 last_ts 按统一保守值回填。
    let (raw_rows, last_ts): (i64, i64) = {
        let row = client
            .query_one(
                "SELECT (SELECT COUNT(*) FROM samples WHERE agent_id = 'a7')::bigint,
                        (SELECT last_ts FROM samples_1m WHERE agent_id = 'a7')",
                &[],
            )
            .expect("读取迁移后 v7 数据失败");
        (row.get(0), row.get(1))
    };
    assert_eq!(raw_rows, 1, "v7 raw 行不得丢失");
    assert_eq!(last_ts, 119_999, "legacy 1m 桶必须回填 bucket_ts+59999");
    assert_eq!(
        migration_row_count(&mut client),
        2,
        "保留 v7 版本行并追加 v8 版本行"
    );
    assert_all_named_indexes(&mut client);
}

// ---------------------------------------------------------------------------
// 6. 并发 apply：两线程竞争 + advisory lock 串行化
// ---------------------------------------------------------------------------

#[test]
fn concurrent_apply_on_empty_database_ends_at_version_8() {
    const NAME: &str = "concurrent_apply_on_empty_database_ends_at_version_8";
    let Some(db) = TestDatabase::create("race") else {
        skip(NAME);
        return;
    };
    let app = db.app_config();
    let barrier = Arc::new(Barrier::new(2));

    let handles: Vec<_> = (0..2)
        .map(|worker| {
            let app = app.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut client = app
                    .connect(NoTls)
                    .unwrap_or_else(|e| panic!("并发 worker {worker} 连接失败：{e}"));
                barrier.wait();
                apply_schema(&mut client)
                    .map_err(|e| format!("并发 worker {worker} apply_schema 失败：{e:#}"))
            })
        })
        .collect();

    for handle in handles {
        handle
            .join()
            .expect("并发 apply 线程 panic")
            .expect("并发 apply 必须都成功（后到者走幂等校验路径）");
    }

    let mut client = db.connect();
    assert_eq!(schema_version(&mut client), POSTGRES_SCHEMA_VERSION);
    assert_eq!(
        migration_row_count(&mut client),
        1,
        "并发迁移只允许一行 v8 版本记录"
    );
    assert_all_21_tables(&mut client);
    assert_all_named_indexes(&mut client);
}

#[test]
fn advisory_lock_blocks_second_migration_until_release() {
    const NAME: &str = "advisory_lock_blocks_second_migration_until_release";
    let Some(db) = TestDatabase::create("lock") else {
        skip(NAME);
        return;
    };

    // 先在独立连接上持有同一把事务级 advisory lock。
    let mut holder = db.connect();
    holder.batch_execute("BEGIN").expect("开始持锁事务失败");
    holder
        .query_one(
            "SELECT pg_advisory_xact_lock($1)",
            &[&SCHEMA_ADVISORY_LOCK_KEY],
        )
        .expect("持有 advisory lock 失败");

    let app = db.app_config();
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut client = app.connect(NoTls).expect("advisory lock 测试连接失败");
        let started = Instant::now();
        let result = apply_schema(&mut client);
        let elapsed = started.elapsed();
        let _ = tx.send(result.is_ok());
        (result, elapsed)
    });

    // 锁被占用时 apply_schema 必须停在 advisory lock 上，不能先做 DDL。
    thread::sleep(Duration::from_millis(600));
    match rx.try_recv() {
        Err(TryRecvError::Empty) => {}
        other => panic!("apply_schema 在 advisory lock 被占用时不应完成：{other:?}"),
    }

    holder
        .batch_execute("COMMIT")
        .expect("释放 advisory lock 失败");

    let ok = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("释放锁后 apply_schema 应在 30s 内完成");
    assert!(ok, "释放锁后 apply_schema 必须成功");
    let (result, elapsed) = handle.join().expect("持锁测试线程 panic");
    result.expect("apply_schema 必须成功");
    assert!(
        elapsed >= Duration::from_millis(500),
        "apply_schema 必须等待锁释放（实际仅 {elapsed:?}）"
    );

    let mut client = db.connect();
    assert_eq!(schema_version(&mut client), POSTGRES_SCHEMA_VERSION);
    assert_all_21_tables(&mut client);
}

// ---------------------------------------------------------------------------
// 7. 版本 9 必须拒绝
// ---------------------------------------------------------------------------

#[test]
fn future_schema_version_is_rejected_without_ddl() {
    const NAME: &str = "future_schema_version_is_rejected_without_ddl";
    let Some(db) = TestDatabase::create("future") else {
        skip(NAME);
        return;
    };
    let mut client = db.connect();

    client
        .batch_execute(
            "CREATE TABLE schema_migrations (
                 version BIGINT PRIMARY KEY,
                 applied_at BIGINT NOT NULL
             );
             INSERT INTO schema_migrations (version, applied_at) VALUES (9, 123456);",
        )
        .expect("构造 v9 库失败");

    let err = apply_schema(&mut client).expect_err("schema 版本 9 必须被拒绝");
    let message = format!("{err:#}");
    assert!(
        message.contains('9') && message.contains('8'),
        "拒绝信息应包含实际/支持版本：{message}"
    );
    assert!(
        message.contains("升级"),
        "拒绝信息应提示升级 hub：{message}"
    );

    // 拒绝路径不得执行任何业务 DDL。
    assert_eq!(
        table_names(&mut client),
        vec!["schema_migrations".to_string()],
        "版本过高时不得建业务表"
    );
    assert_eq!(schema_version(&mut client), 9, "版本行不得被改写");
}

// ---------------------------------------------------------------------------
// 8. 失败回滚：DDL 中途出错不留半套
// ---------------------------------------------------------------------------

#[test]
fn failed_ddl_rolls_back_entire_transaction() {
    const NAME: &str = "failed_ddl_rolls_back_entire_transaction";
    let Some(db) = TestDatabase::create("rollback") else {
        skip(NAME);
        return;
    };
    let mut client = db.connect();

    // 预先放一张结构不兼容的 samples：DDL 建到 idx_samples_lookup 时会失败。
    // 这是对 apply_schema 真实失败路径的注入，而不是另写一个假事务。
    client
        .batch_execute(
            "CREATE TABLE samples (poisoned INTEGER NOT NULL);
             INSERT INTO samples (poisoned) VALUES (7);",
        )
        .expect("构造失败注入表失败");

    let err = apply_schema(&mut client).expect_err("不兼容的 samples 必须让迁移失败");
    let message = format!("{err:#}");
    assert!(
        message.contains("agent_id") || message.contains("idx_samples_lookup"),
        "失败信息应指向不兼容的列/索引：{message}"
    );

    // 事务回滚：本次创建的表与版本表都不能残留。
    let agents: Option<String> = client
        .query_one("SELECT to_regclass('public.agents')::text", &[])
        .expect("查询 agents 是否存在失败")
        .get(0);
    assert!(agents.is_none(), "失败事务不得残留 agents 表");
    let migrations: Option<String> = client
        .query_one("SELECT to_regclass('public.schema_migrations')::text", &[])
        .expect("查询 schema_migrations 是否存在失败")
        .get(0);
    assert!(
        migrations.is_none(),
        "失败事务不得残留 schema_migrations 表"
    );

    // 预先存在的数据原样保留（回滚不能误删）。
    let count: i64 = client
        .query_one("SELECT COUNT(*)::bigint FROM samples", &[])
        .expect("读取注入表失败")
        .get(0);
    assert_eq!(count, 1, "回滚不得影响迁移前已存在的数据");

    // 修复注入后再次 apply 必须成功（证明失败没有留下不可恢复状态）。
    client
        .batch_execute("DROP TABLE samples")
        .expect("清理注入表失败");
    apply_schema(&mut client).expect("清理注入后 apply_schema 必须成功");
    assert_eq!(schema_version(&mut client), POSTGRES_SCHEMA_VERSION);
    assert_all_21_tables(&mut client);
}
