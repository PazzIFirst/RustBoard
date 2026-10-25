//! Phase D3：PostgreSQL Core 23 个固有方法的实库 parity 测试。
//!
//! 依据 `docs/plans/2026-10-26-m5-phase-d-postgres-backup-l01-l03.md` §3.2/§3.3/
//! §5 D3、`docs/plans/2026-10-26-m5-phase-d-pg-spike.md` §3/§4/§6/§7/§11 编写。
//!
//! # 运行方式
//!
//! ```bash
//! docker run -d --name rustboard-pg-d3 -p 127.0.0.1:55435:5432 \
//!   -e POSTGRES_USER=rustboard -e POSTGRES_PASSWORD='<TEST_PASSWORD>' \
//!   -e POSTGRES_DB=rustboard postgres:16
//! RUSTBOARD_TEST_PG='postgres://rustboard:<TEST_PASSWORD>@127.0.0.1:55435/rustboard?sslmode=disable' \
//!   cargo test -p rustboard-core --test postgres_core --locked -- --nocapture
//! ```
//!
//! 未设置 `RUSTBOARD_TEST_PG` 时每个用例打印 `SKIP` 并返回（cargo 记为 passed，
//! 但日志明确标注未执行）。DSN 必须显式 `sslmode=disable`：D3 的实库测试只覆盖
//! 明文路径，TLS `verify-full` 的配置解析由 `postgres::tests` 单测覆盖。
//!
//! 每个用例创建一个独立数据库（`rb_d3_<tag>_<pid>_<nanos>_<seq>`），结束时用
//! `DROP DATABASE ... WITH (FORCE)` 删除；用例可并行且互不污染。因此
//! `RUSTBOARD_TEST_PG` 对应的角色需要 `CREATEDB` 权限。
//!
//! 同一组操作分别跑在 PostgreSQL 与内存 SQLite 上，再逐字段比较（浮点用相对
//! 容差）。测试不读实现私有状态，只通过 Core 方法与必要的直接 SQL 造数
//! （1m/1h 表目前还没有 PG 降采样方法，属于后续维护域）。
//!
//! 测试 DSN 只存在于运行环境；本文件不含任何真实密码。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use postgres::config::SslMode;
use postgres::NoTls;
use rustboard_common::config::HubConfig;
use rustboard_common::model::{AgentRecord, Sample, SampleBatch, SeriesQuery, SeriesRow};
use rustboard_core::storage::postgres::schema::{apply_schema, connect_for_schema};
use rustboard_core::storage::postgres::{PostgresOptions, PostgresStorage};
use rustboard_core::storage::sqlite::SqliteStorage;
use rustboard_core::storage::{
    AgentSeriesRow, IngestOutcome, QueryTooLarge, RejectReason, SampleTier, Storage,
};

/// 实库测试 DSN 的环境变量；未设置时全部用例 skip。
const PG_ENV: &str = "RUSTBOARD_TEST_PG";

/// 每次调用返回递增序号，避免同一纳秒内两个用例撞库名。
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

fn skip(test_name: &str) {
    eprintln!("SKIP {test_name}: 未设置 {PG_ENV}（D3 Core 实库测试需要 PostgreSQL）");
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
        "{PG_ENV} 必须显式 sslmode=disable（D3 实库测试只覆盖明文路径）"
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
        let name = format!("rb_d3_{tag}_{}_{nanos}_{seq}", std::process::id());
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
        eprintln!("[d3] 创建测试数据库 {name}（tag={tag}）");
        Some(Self {
            name,
            admin,
            app,
            app_dsn,
        })
    }

    /// 应用 schema v7 并打开 `PostgresStorage`（在 tokio runtime 外的测试线程）。
    fn open_storage(&self) -> PostgresStorage {
        let mut client = connect_for_schema(&self.app_dsn)
            .unwrap_or_else(|e| panic!("schema 连接失败（{}）：{e:#}", self.name));
        apply_schema(&mut client).unwrap_or_else(|e| panic!("apply_schema 失败：{e:#}"));
        drop(client);

        PostgresStorage::open(PostgresOptions {
            dsn: self.app_dsn.clone(),
            pool_size: 2,
            connect_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(10),
            sslrootcert: None,
        })
        .unwrap_or_else(|e| panic!("打开 PostgresStorage 失败：{e:#}"))
    }

    /// 直连测试库（造 1m/1h 数据、批量灌 10 万行等）。
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
                    "[d3] 清理失败：无法连接维护库删除 {}（请手工 DROP）：{e}",
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
                "[d3] 清理失败：DROP DATABASE {} 出错（请手工清理）：{e}",
                self.name
            );
        }
    }
}

/// 同一段 Core 调用跑在 PG 与 SQLite 上，返回两边结果。
///
/// 两边方法签名逐字一致；SQLite 通过 `Storage` trait 解析，PG 是固有方法。
macro_rules! both {
    ($pg:expr, $sq:expr, |$store:ident| $body:expr) => {{
        let pg_result = {
            let $store = &$pg;
            $body
        };
        let sqlite_result = {
            let $store = &$sq;
            $body
        };
        (pg_result, sqlite_result)
    }};
}

fn agent_record(id: &str, name: &str, status: &str, ts: i64) -> AgentRecord {
    AgentRecord {
        agent_id: id.to_string(),
        name: name.to_string(),
        hostname: format!("host-{id}"),
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        version: "1.0.0".to_string(),
        boot_id: "boot-1".to_string(),
        status: status.to_string(),
        last_seen_at: ts,
        created_at: 50,
    }
}

fn sample_batch(agent_id: &str, epoch: u64, seq: u64, samples: Vec<Sample>) -> SampleBatch {
    SampleBatch {
        agent_id: agent_id.to_string(),
        epoch,
        seq,
        boot_id: "boot-1".to_string(),
        sent_at: 1_700_000_000_000,
        samples,
    }
}

fn labeled_sample(metric: &str, labels: &[(&str, &str)], ts: i64, value: f64) -> Sample {
    let mut sample = Sample::new(metric, ts, value);
    for (key, value) in labels {
        sample
            .labels
            .insert((*key).to_string(), (*value).to_string());
    }
    sample
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

fn assert_series_eq(pg: &[SeriesRow], sqlite: &[SeriesRow]) {
    assert_eq!(pg.len(), sqlite.len(), "PG/SQLite 返回行数不一致");
    for (index, (pg_row, sqlite_row)) in pg.iter().zip(sqlite).enumerate() {
        assert_eq!(
            pg_row.metric, sqlite_row.metric,
            "第 {index} 行 metric 不一致"
        );
        assert_eq!(
            pg_row.labels, sqlite_row.labels,
            "第 {index} 行 labels 不一致"
        );
        assert_eq!(pg_row.ts, sqlite_row.ts, "第 {index} 行 ts 不一致");
        let tolerance = 1e-9 * pg_row.value.abs().max(1.0);
        assert!(
            (pg_row.value - sqlite_row.value).abs() <= tolerance,
            "第 {index} 行 value 不一致：pg={} sqlite={}",
            pg_row.value,
            sqlite_row.value
        );
    }
}

fn assert_agent_series_eq(pg: &[AgentSeriesRow], sqlite: &[AgentSeriesRow]) {
    assert_eq!(pg.len(), sqlite.len(), "PG/SQLite 最新点行数不一致");
    for (index, (pg_row, sqlite_row)) in pg.iter().zip(sqlite).enumerate() {
        assert_eq!(
            pg_row.agent_id, sqlite_row.agent_id,
            "第 {index} 行 agent_id 不一致"
        );
        assert_eq!(
            pg_row.metric, sqlite_row.metric,
            "第 {index} 行 metric 不一致"
        );
        assert_eq!(
            pg_row.labels, sqlite_row.labels,
            "第 {index} 行 labels 不一致"
        );
        assert_eq!(pg_row.ts, sqlite_row.ts, "第 {index} 行 ts 不一致");
        let tolerance = 1e-9 * pg_row.value.abs().max(1.0);
        assert!(
            (pg_row.value - sqlite_row.value).abs() <= tolerance,
            "第 {index} 行 value 不一致：pg={} sqlite={}",
            pg_row.value,
            sqlite_row.value
        );
    }
}

// ---------------------------------------------------------------------------
// 1. agent 生命周期：upsert / mark_seen / set_status / revoked 终态 / reset
// ---------------------------------------------------------------------------

#[test]
fn agent_lifecycle_matches_sqlite() {
    const NAME: &str = "agent_lifecycle_matches_sqlite";
    let Some(db) = TestDatabase::create("lifecycle") else {
        skip(NAME);
        return;
    };
    let pg = db.open_storage();
    let sqlite = SqliteStorage::open_in_memory().expect("打开内存 SQLite 失败");

    let (pg_reset, sqlite_reset) = both!(pg, sqlite, |s| {
        s.upsert_agent(&agent_record("a1", "Node 1", "pending", 100))
            .unwrap();
        s.upsert_agent(&agent_record("a2", "Node 2", "pending", 200))
            .unwrap();
        s.upsert_agent(&agent_record("a3", "Node 3", "online", 300))
            .unwrap();
        // 吊销后：upsert 可更新元信息，但 status 必须保持 revoked。
        s.revoke_agent("a3", 350).unwrap();
        s.upsert_agent(&agent_record("a3", "Node 3 renamed", "online", 400))
            .unwrap();
        s.mark_seen("a3", 999).unwrap();
        s.set_status("a3", "online", 1000).unwrap();

        // 非吊销 agent 的正常状态机。
        s.mark_seen("a1", 150).unwrap();
        s.set_status("a2", "offline", 250).unwrap();

        // 只剩 a1 是 online，reset 后应恰好影响 1 行。
        s.reset_online_status().unwrap()
    });
    assert_eq!(pg_reset, sqlite_reset);
    assert_eq!(pg_reset, 1, "reset_online_status 应只影响 a1");

    let (pg_agents, sqlite_agents) = both!(pg, sqlite, |s| s.list_agents().unwrap());
    assert_eq!(pg_agents, sqlite_agents, "list_agents 顺序/内容必须一致");

    let (pg_a1, sqlite_a1) = both!(pg, sqlite, |s| s.get_agent("a1").unwrap());
    assert_eq!(pg_a1, sqlite_a1);
    assert_eq!(pg_a1.unwrap().status, "offline");

    let (pg_a3, sqlite_a3) = both!(pg, sqlite, |s| s.get_agent("a3").unwrap());
    assert_eq!(pg_a3, sqlite_a3);
    let a3 = pg_a3.expect("a3 必须存在");
    assert_eq!(a3.status, "revoked", "revoked 是终态，不能被覆盖");
    assert_eq!(a3.name, "Node 3 renamed", "非状态字段应随 upsert 更新");
    assert_eq!(
        a3.last_seen_at, 1000,
        "revoked 后 mark_seen/set_status 仍刷新时间"
    );

    let (pg_revoked, sqlite_revoked) = both!(pg, sqlite, |s| {
        (s.is_revoked("a1").unwrap(), s.is_revoked("a3").unwrap())
    });
    assert_eq!(pg_revoked, sqlite_revoked);
    assert_eq!(pg_revoked, (false, true));

    // 第二次 reset 没有 online，返回 0。
    let (pg_reset_again, sqlite_reset_again) =
        both!(pg, sqlite, |s| s.reset_online_status().unwrap());
    assert_eq!(pg_reset_again, sqlite_reset_again);
    assert_eq!(pg_reset_again, 0);
}

// ---------------------------------------------------------------------------
// 2. ingest：幂等 / 重复 seq / 乱序 / 吊销 / 查询
// ---------------------------------------------------------------------------

#[test]
fn ingest_batches_match_sqlite() {
    const NAME: &str = "ingest_batches_match_sqlite";
    let Some(db) = TestDatabase::create("ingest") else {
        skip(NAME);
        return;
    };
    let pg = db.open_storage();
    let sqlite = SqliteStorage::open_in_memory().expect("打开内存 SQLite 失败");

    let first_batch = sample_batch(
        "a1",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 1_000, 10.0),
            labeled_sample("cpu.usage", &[("core", "0")], 1_000, 15.0),
            Sample::new("mem.used", 1_000, 1024.0),
        ],
    );
    let (pg_first, sqlite_first) = both!(pg, sqlite, |s| s.insert_batch(&first_batch).unwrap());
    assert_eq!(pg_first, sqlite_first);
    assert_eq!(pg_first, IngestOutcome::Inserted { inserted: 3 });

    // 完全相同的批次：整批 Duplicate，不重复写点。
    let (pg_dup, sqlite_dup) = both!(pg, sqlite, |s| s.insert_batch(&first_batch).unwrap());
    assert_eq!(pg_dup, sqlite_dup);
    assert_eq!(pg_dup, IngestOutcome::Duplicate);

    // 同 (epoch, seq) 但内容不同：仍必须判重，不能覆盖已写入的数据。
    let altered = sample_batch("a1", 1, 0, vec![Sample::new("cpu.usage", 2_000, 999.0)]);
    let (pg_altered, sqlite_altered) = both!(pg, sqlite, |s| s.insert_batch(&altered).unwrap());
    assert_eq!(pg_altered, sqlite_altered);
    assert_eq!(pg_altered, IngestOutcome::Duplicate);

    // 同一 epoch 乱序：先到 seq=5 再到 seq=3，都必须写入（不能只看 last_seq）。
    let seq_five = sample_batch("a1", 1, 5, vec![Sample::new("cpu.usage", 3_000, 5.0)]);
    let seq_three = sample_batch("a1", 1, 3, vec![Sample::new("cpu.usage", 2_500, 3.0)]);
    let (pg_five, sqlite_five) = both!(pg, sqlite, |s| s.insert_batch(&seq_five).unwrap());
    assert_eq!(pg_five, sqlite_five);
    assert_eq!(pg_five, IngestOutcome::Inserted { inserted: 1 });
    let (pg_three, sqlite_three) = both!(pg, sqlite, |s| s.insert_batch(&seq_three).unwrap());
    assert_eq!(pg_three, sqlite_three);
    assert_eq!(pg_three, IngestOutcome::Inserted { inserted: 1 });

    // 已吊销 agent 的批次：Rejected(Revoked)，且不写入任何点。
    let revoked_batch = sample_batch("a2", 1, 0, vec![Sample::new("cpu.usage", 1_000, 1.0)]);
    let (pg_rejected, sqlite_rejected) = both!(pg, sqlite, |s| {
        s.revoke_agent("a2", 777).unwrap();
        s.insert_batch(&revoked_batch).unwrap()
    });
    assert_eq!(pg_rejected, sqlite_rejected);
    assert_eq!(pg_rejected, IngestOutcome::Rejected(RejectReason::Revoked));

    let (pg_count, sqlite_count) = both!(pg, sqlite, |s| {
        (s.sample_count("a1").unwrap(), s.sample_count("a2").unwrap())
    });
    assert_eq!(pg_count, sqlite_count);
    assert_eq!(pg_count, (5, 0), "a1 应有 5 个点，吊销的 a2 应为 0");

    // 查询与 SQLite 一致（含同一 ts 的插入顺序与 limit）。
    for query in [
        series_query("a1", &[], 0, i64::MAX, 100),
        series_query("a1", &["cpu.usage"], 0, i64::MAX, 100),
        series_query("a1", &["cpu.usage"], 1_000, 2_500, 2),
        series_query("a1", &["mem.used"], 0, i64::MAX, 100),
    ] {
        let (pg_rows, sqlite_rows) = both!(pg, sqlite, |s| s.query_series(&query).unwrap());
        assert_series_eq(&pg_rows, &sqlite_rows);
    }
}

// ---------------------------------------------------------------------------
// 3a. raw / bucketed 查询：排序、边界、limit
// ---------------------------------------------------------------------------

#[test]
fn raw_and_bucketed_queries_match_sqlite() {
    const NAME: &str = "raw_and_bucketed_queries_match_sqlite";
    let Some(db) = TestDatabase::create("series") else {
        skip(NAME);
        return;
    };
    let pg = db.open_storage();
    let sqlite = SqliteStorage::open_in_memory().expect("打开内存 SQLite 失败");

    let batch = sample_batch(
        "a1",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 60_000, 10.0),
            Sample::new("cpu.usage", 60_000, 20.0), // 同 ts，后插入者应排在后面
            labeled_sample("cpu.usage", &[("core", "0")], 120_000, 30.0),
            Sample::new("mem.used", 120_000, 100.0),
            Sample::new("cpu.usage", 180_000, 40.0),
        ],
    );
    let (pg_outcome, sqlite_outcome) = both!(pg, sqlite, |s| s.insert_batch(&batch).unwrap());
    assert_eq!(pg_outcome, sqlite_outcome);

    for query in [
        series_query("a1", &[], 0, i64::MAX, 100),
        series_query("a1", &["cpu.usage"], 0, i64::MAX, 100),
        series_query("a1", &["cpu.usage"], 60_000, 120_000, 100),
        series_query("a1", &[], 0, i64::MAX, 2),
        series_query("a1", &["missing.metric"], 0, i64::MAX, 100),
    ] {
        let (pg_rows, sqlite_rows) = both!(pg, sqlite, |s| s.query_series(&query).unwrap());
        assert_series_eq(&pg_rows, &sqlite_rows);
    }

    for (bucket_ms, query) in [
        (60_000, series_query("a1", &[], 0, i64::MAX, 100)),
        (60_000, series_query("a1", &["cpu.usage"], 0, i64::MAX, 2)),
        (120_000, series_query("a1", &[], 0, i64::MAX, 100)),
        (120_000, series_query("a1", &["mem.used"], 0, i64::MAX, 100)),
    ] {
        let (pg_rows, sqlite_rows) = both!(pg, sqlite, |s| s
            .query_series_bucketed(&query, bucket_ms)
            .unwrap());
        assert_series_eq(&pg_rows, &sqlite_rows);
    }

    // bucket_ms <= 0 两边都必须拒绝。
    let query = series_query("a1", &[], 0, i64::MAX, 100);
    assert!(pg.query_series_bucketed(&query, 0).is_err());
    assert!(sqlite.query_series_bucketed(&query, 0).is_err());

    // tier=Raw 必须与 bucketed 行为一致。
    let (pg_rows, sqlite_rows) = both!(pg, sqlite, |s| {
        s.query_series_tiered(&query, 60_000, SampleTier::Raw)
            .unwrap()
    });
    assert_series_eq(&pg_rows, &sqlite_rows);
    assert!(pg.query_series_tiered(&query, 0, SampleTier::Raw).is_err());
}

// ---------------------------------------------------------------------------
// 3b. 1m/1h 聚合查询：count 加权、桶重叠边界、limit
// ---------------------------------------------------------------------------

#[test]
fn tiered_queries_match_sqlite() {
    const NAME: &str = "tiered_queries_match_sqlite";
    let Some(db) = TestDatabase::create("tiered") else {
        skip(NAME);
        return;
    };
    let pg = db.open_storage();
    let sqlite = SqliteStorage::open_in_memory().expect("打开内存 SQLite 失败");

    // 原始点：minute 0 两个点（10/20），minute 1 一个点（30）。
    let batch = sample_batch(
        "tier",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 10_000, 10.0),
            Sample::new("cpu.usage", 20_000, 20.0),
            Sample::new("cpu.usage", 70_000, 30.0),
        ],
    );
    let (pg_outcome, sqlite_outcome) = both!(pg, sqlite, |s| s.insert_batch(&batch).unwrap());
    assert_eq!(pg_outcome, sqlite_outcome);

    // SQLite 用真实降采样生成 1m/1h；PG 侧还没有维护域方法，直接写入同样的行。
    sqlite
        .downsample_1m_range(0, 120_000)
        .expect("SQLite 1m 降采样失败");
    sqlite
        .downsample_1h_range(0, 3_600_000)
        .expect("SQLite 1h 降采样失败");
    let mut client = db.client();
    client
        .batch_execute(
            "INSERT INTO samples_1m
                 (agent_id, metric, labels, bucket_ts, min_value, max_value,
                  avg_value, last_value, count)
             VALUES
                 ('tier', 'cpu.usage', '{}', 0, 10.0, 20.0, 15.0, 20.0, 2),
                 ('tier', 'cpu.usage', '{}', 60000, 30.0, 30.0, 30.0, 30.0, 1);
             INSERT INTO samples_1h
                 (agent_id, metric, labels, bucket_ts, min_value, max_value,
                  avg_value, last_value, count)
             VALUES
                 ('tier', 'cpu.usage', '{}', 0, 10.0, 30.0, 20.0, 30.0, 3);",
        )
        .expect("写入 PG 1m/1h 测试数据失败");
    drop(client);

    for (bucket_ms, tier, query) in [
        (
            60_000,
            SampleTier::OneMinute,
            series_query("tier", &[], 0, 120_000, 100),
        ),
        (
            120_000,
            SampleTier::OneMinute,
            series_query("tier", &[], 0, 120_000, 100),
        ),
        (
            60_000,
            SampleTier::OneMinute,
            series_query("tier", &[], 0, 120_000, 1),
        ),
        (
            60_000,
            SampleTier::OneMinute,
            series_query("tier", &["cpu.usage"], 0, 120_000, 100),
        ),
        // 桶重叠：from=60000 时 bucket 0 的结束正好等于 from，必须排除。
        (
            60_000,
            SampleTier::OneMinute,
            series_query("tier", &[], 60_000, 120_000, 100),
        ),
        (
            60_000,
            SampleTier::OneMinute,
            series_query("tier", &[], 0, 59_999, 100),
        ),
        (
            3_600_000,
            SampleTier::OneHour,
            series_query("tier", &[], 0, 3_600_000, 100),
        ),
        // 1h 桶 0 的结束正好等于 from，必须排除。
        (
            3_600_000,
            SampleTier::OneHour,
            series_query("tier", &[], 3_600_000, 3_600_000, 100),
        ),
    ] {
        let (pg_rows, sqlite_rows) = both!(pg, sqlite, |s| {
            s.query_series_tiered(&query, bucket_ms, tier).unwrap()
        });
        assert_series_eq(&pg_rows, &sqlite_rows);
    }

    // raw 层仍是普通 AVG，与 SQLite 的 raw tier 查询一致。
    let query = series_query("tier", &[], 0, 120_000, 100);
    let (pg_raw, sqlite_raw) = both!(pg, sqlite, |s| {
        s.query_series_tiered(&query, 120_000, SampleTier::Raw)
            .unwrap()
    });
    assert_series_eq(&pg_raw, &sqlite_raw);
    assert_eq!(pg_raw.len(), 1);
    assert!((pg_raw[0].value - 20.0).abs() < 1e-9, "raw AVG 应为 20");
}

// ---------------------------------------------------------------------------
// 4. 设置 / enroll token / secret / 控制能力
// ---------------------------------------------------------------------------

#[test]
fn settings_enroll_secret_control_match_sqlite() {
    const NAME: &str = "settings_enroll_secret_control_match_sqlite";
    let Some(db) = TestDatabase::create("meta") else {
        skip(NAME);
        return;
    };
    let pg = db.open_storage();
    let sqlite = SqliteStorage::open_in_memory().expect("打开内存 SQLite 失败");

    // ---- agent_settings ----
    let (pg_absent, sqlite_absent) = both!(pg, sqlite, |s| s.get_sample_interval("a1").unwrap());
    assert_eq!(pg_absent, sqlite_absent);
    assert_eq!(pg_absent, None);

    let (pg_intervals, sqlite_intervals) = both!(pg, sqlite, |s| {
        s.set_sample_interval("a1", 5_000, 1_000).unwrap();
        s.set_sample_interval("a2", 7_000, 2_000).unwrap();
        s.set_sample_interval("a1", 6_000, 3_000).unwrap();
        s.list_sample_intervals().unwrap()
    });
    assert_eq!(pg_intervals, sqlite_intervals);
    assert_eq!(
        pg_intervals,
        vec![("a1".to_string(), 6_000), ("a2".to_string(), 7_000)]
    );

    let (pg_get, sqlite_get) = both!(pg, sqlite, |s| s.get_sample_interval("a1").unwrap());
    assert_eq!(pg_get, sqlite_get);
    assert_eq!(pg_get, Some(6_000));

    // u64 超出 BIGINT：两边都必须报错，且已有值不被破坏。
    assert!(pg.set_sample_interval("a1", u64::MAX, 4_000).is_err());
    assert!(sqlite.set_sample_interval("a1", u64::MAX, 4_000).is_err());
    let (pg_after_overflow, sqlite_after_overflow) =
        both!(pg, sqlite, |s| s.get_sample_interval("a1").unwrap());
    assert_eq!(pg_after_overflow, sqlite_after_overflow);
    assert_eq!(pg_after_overflow, Some(6_000));

    // ---- enroll token ----
    let (pg_consumed, sqlite_consumed) = both!(pg, sqlite, |s| {
        s.create_enroll_token("hash-1", "enrolled-agent", 100, 1_000)
            .unwrap();
        s.consume_enroll_token("hash-1", 500).unwrap()
    });
    assert_eq!(pg_consumed, sqlite_consumed);
    assert_eq!(pg_consumed.as_deref(), Some("enrolled-agent"));

    // 一次性：第二次消费失败。
    let (pg_second, sqlite_second) = both!(pg, sqlite, |s| s
        .consume_enroll_token("hash-1", 600)
        .unwrap());
    assert_eq!(pg_second, sqlite_second);
    assert_eq!(pg_second, None);

    // 过期边界：expires_at > now 才有效，等于 now 即过期。
    let (pg_expired, sqlite_expired) = both!(pg, sqlite, |s| {
        s.create_enroll_token("hash-2", "expired-agent", 100, 1_000)
            .unwrap();
        s.consume_enroll_token("hash-2", 1_000).unwrap()
    });
    assert_eq!(pg_expired, sqlite_expired);
    assert_eq!(pg_expired, None);

    let (pg_unknown, sqlite_unknown) = both!(pg, sqlite, |s| s
        .consume_enroll_token("missing", 500)
        .unwrap());
    assert_eq!(pg_unknown, sqlite_unknown);
    assert_eq!(pg_unknown, None);

    // ---- agent secret ----
    let (pg_verify, sqlite_verify) = both!(pg, sqlite, |s| {
        let before = s.verify_agent_secret("a1", "secret-hash").unwrap();
        s.set_agent_secret("a1", "secret-hash", 1_000).unwrap();
        let correct = s.verify_agent_secret("a1", "secret-hash").unwrap();
        let wrong = s.verify_agent_secret("a1", "other-hash").unwrap();
        s.set_agent_secret("a1", "secret-hash-2", 1_100).unwrap();
        let old = s.verify_agent_secret("a1", "secret-hash").unwrap();
        let new = s.verify_agent_secret("a1", "secret-hash-2").unwrap();
        (before, correct, wrong, old, new)
    });
    assert_eq!(pg_verify, sqlite_verify);
    assert_eq!(pg_verify, (false, true, false, false, true));

    // 吊销删除长期密钥：verify 必须回到 false。
    let (pg_after_revoke, sqlite_after_revoke) = both!(pg, sqlite, |s| {
        s.revoke_agent("a1", 2_000).unwrap();
        (
            s.is_revoked("a1").unwrap(),
            s.verify_agent_secret("a1", "secret-hash-2").unwrap(),
        )
    });
    assert_eq!(pg_after_revoke, sqlite_after_revoke);
    assert_eq!(pg_after_revoke, (true, false));

    // ---- agent_control ----
    let (pg_control_absent, sqlite_control_absent) =
        both!(pg, sqlite, |s| s.get_agent_control("a9").unwrap());
    assert_eq!(pg_control_absent, sqlite_control_absent);
    assert_eq!(pg_control_absent, None);

    let capabilities = vec!["systemd".to_string(), "docker".to_string()];
    let (pg_control, sqlite_control) = both!(pg, sqlite, |s| {
        s.upsert_agent_control("a9", &capabilities, 1_000).unwrap();
        s.get_agent_control("a9").unwrap()
    });
    assert_eq!(pg_control, sqlite_control);
    let control = pg_control.expect("控制能力记录必须存在");
    assert_eq!(control.capabilities, capabilities);
    assert_eq!(control.updated_at, 1_000);

    // 覆盖写：空能力也必须能持久化。
    let (pg_empty, sqlite_empty) = both!(pg, sqlite, |s| {
        s.upsert_agent_control("a9", &[], 1_500).unwrap();
        s.get_agent_control("a9").unwrap()
    });
    assert_eq!(pg_empty, sqlite_empty);
    assert_eq!(pg_empty.map(|record| record.capabilities), Some(Vec::new()));
}

// ---------------------------------------------------------------------------
// 5. latest_samples：raw / 同 ts tie / 过滤 / 1m、1h 回退
// ---------------------------------------------------------------------------

#[test]
fn latest_samples_matches_sqlite() {
    const NAME: &str = "latest_samples_matches_sqlite";
    let Some(db) = TestDatabase::create("latest") else {
        skip(NAME);
        return;
    };
    let pg = db.open_storage();
    let sqlite = SqliteStorage::open_in_memory().expect("打开内存 SQLite 失败");

    let batch = sample_batch(
        "a1",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 1_000, 10.0),
            Sample::new("cpu.usage", 2_000, 20.0),
            Sample::new("cpu.usage", 3_000, 30.0),
            // 同序列同 ts：id 更大者（后插入）必须胜出。
            Sample::new("cpu.usage", 3_000, 31.0),
            labeled_sample("cpu.usage", &[("core", "1")], 2_500, 25.0),
            Sample::new("mem.used", 2_000, 1_024.0),
        ],
    );
    let second = sample_batch("a2", 1, 0, vec![Sample::new("cpu.usage", 1_500, 99.0)]);
    let (pg_first, sqlite_first) = both!(pg, sqlite, |s| {
        (
            s.insert_batch(&batch).unwrap(),
            s.insert_batch(&second).unwrap(),
        )
    });
    assert_eq!(pg_first, sqlite_first);
    assert_eq!(
        pg_first,
        (
            IngestOutcome::Inserted { inserted: 6 },
            IngestOutcome::Inserted { inserted: 1 }
        )
    );

    for (since, metrics, agent) in [
        (0, Vec::new(), None),
        (1_800, Vec::new(), None),
        (1_800, vec!["cpu.usage".to_string()], Some("a1")),
        (0, vec!["missing".to_string()], None),
        (0, Vec::new(), Some("a2")),
    ] {
        let (pg_rows, sqlite_rows) = both!(pg, sqlite, |s| {
            s.latest_samples(since, &metrics, agent).unwrap()
        });
        assert_agent_series_eq(&pg_rows, &sqlite_rows);
    }

    let (pg_tie, sqlite_tie) = both!(pg, sqlite, |s| s
        .latest_samples(0, &[], Some("a1"))
        .unwrap());
    assert_agent_series_eq(&pg_tie, &sqlite_tie);
    let cpu = pg_tie
        .iter()
        .find(|row| row.metric == "cpu.usage" && row.labels.is_empty())
        .expect("cpu.usage 序列必须存在");
    assert_eq!(cpu.ts, 3_000);
    assert_eq!(cpu.value, 31.0, "同 ts 必须取 id 更大的后插入点");

    // ---- 1m / 1h 回退：raw 在 since 窗口内为空时才回退 ----
    let tier_raw = sample_batch(
        "tier",
        1,
        0,
        vec![
            Sample::new("cpu.usage", 130_000, 10.0),
            Sample::new("cpu.usage", 140_000, 20.0),
            Sample::new("cpu.usage", 190_000, 30.0),
        ],
    );
    let (pg_tier, sqlite_tier) = both!(pg, sqlite, |s| s.insert_batch(&tier_raw).unwrap());
    assert_eq!(pg_tier, sqlite_tier);
    // 只降采样 tier 的窗口，避免把上面 a1/a2 的点也聚合进来（它们是另一个场景）。
    sqlite.downsample_1m_range(120_000, 240_000).unwrap();
    sqlite.downsample_1h_range(0, 3_600_000).unwrap();
    let mut client = db.client();
    client
        .batch_execute(
            "INSERT INTO samples_1m
                 (agent_id, metric, labels, bucket_ts, min_value, max_value,
                  avg_value, last_value, count)
             VALUES
                 ('tier', 'cpu.usage', '{}', 120000, 10.0, 20.0, 15.0, 20.0, 2),
                 ('tier', 'cpu.usage', '{}', 180000, 30.0, 30.0, 30.0, 30.0, 1);
             INSERT INTO samples_1h
                 (agent_id, metric, labels, bucket_ts, min_value, max_value,
                  avg_value, last_value, count)
             VALUES
                 ('tier', 'cpu.usage', '{}', 0, 10.0, 30.0, 20.0, 30.0, 3);",
        )
        .unwrap();
    drop(client);

    // raw 为空，1m 桶 180000 与窗口重叠 → 必须返回 1m 的 last_value=30。
    let (pg_1m, sqlite_1m) = both!(pg, sqlite, |s| s
        .latest_samples(195_000, &[], None)
        .unwrap());
    assert_agent_series_eq(&pg_1m, &sqlite_1m);
    assert_eq!(pg_1m.len(), 1);
    assert_eq!(pg_1m[0].ts, 180_000);
    assert_eq!(pg_1m[0].value, 30.0);

    // 1m 也为空，1h 桶 0 与窗口重叠 → 回退到 1h。
    let (pg_1h, sqlite_1h) = both!(pg, sqlite, |s| s
        .latest_samples(1_000_000, &[], None)
        .unwrap());
    assert_agent_series_eq(&pg_1h, &sqlite_1h);
    assert_eq!(pg_1h.len(), 1);
    assert_eq!(pg_1h[0].ts, 0);
    assert_eq!(pg_1h[0].value, 30.0);
}

// ---------------------------------------------------------------------------
// 6. latest_samples 行数硬上限：QueryTooLarge
// ---------------------------------------------------------------------------

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
            std::env::temp_dir().join(format!("rb-d3-{tag}-{}-{nanos}-{seq}", std::process::id()));
        std::fs::create_dir_all(&path).expect("创建临时目录失败");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn latest_samples_limit_is_query_too_large() {
    const NAME: &str = "latest_samples_limit_is_query_too_large";
    let Some(db) = TestDatabase::create("limit") else {
        skip(NAME);
        return;
    };
    let pg = db.open_storage();

    // PG：generate_series 一次灌 10 万行（避免 10 万次 round-trip）。
    let mut client = db.client();
    client
        .batch_execute(
            "INSERT INTO samples (agent_id, metric, labels, ts, value)
             SELECT 'bulk', 'cpu.usage', '{}', g, 1.0
             FROM generate_series(1, 100000) AS g",
        )
        .expect("写入 PG 10 万行失败");
    drop(client);

    // SQLite：临时文件库 + 独立连接一次灌 10 万行。
    let temp = TempDir::new("limit");
    let sqlite_path = temp.0.join("limit.db");
    let sqlite = SqliteStorage::open(&sqlite_path).expect("打开临时 SQLite 失败");
    {
        let connection =
            rusqlite::Connection::open(&sqlite_path).expect("打开 SQLite 写入连接失败");
        connection
            .execute_batch(
                "WITH RECURSIVE seq(n) AS (
                     SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < 100000
                 )
                 INSERT INTO samples (agent_id, metric, labels, ts, value)
                 SELECT 'bulk', 'cpu.usage', '{}', n, 1.0 FROM seq",
            )
            .expect("写入 SQLite 10 万行失败");
    }

    let pg_err = pg
        .latest_samples(0, &[], None)
        .expect_err("PG 达到 10 万行上限必须返回错误");
    assert_eq!(
        pg_err.downcast_ref::<QueryTooLarge>().map(|err| err.limit),
        Some(100_000),
        "PG 错误必须可向下转型为 QueryTooLarge（供 HTTP 映射 413）"
    );
    let sqlite_err = sqlite
        .latest_samples(0, &[], None)
        .expect_err("SQLite 达到 10 万行上限必须返回错误");
    assert_eq!(
        sqlite_err
            .downcast_ref::<QueryTooLarge>()
            .map(|err| err.limit),
        Some(100_000)
    );
}

// ---------------------------------------------------------------------------
// 7. 连接层：open_from_config、schema 幂等、sslmode 拒绝且不泄露密码
// ---------------------------------------------------------------------------

#[test]
fn connection_layer_and_ssl_policy_are_safe() {
    const NAME: &str = "connection_layer_and_ssl_policy_are_safe";
    let Some(db) = TestDatabase::create("conn") else {
        skip(NAME);
        return;
    };

    // open_from_config 必须能直接用 temp DB 的 DSN（schema 已在 open_storage
    // 之外单独应用，这里通过 storage.apply_schema 验证幂等入口）。
    let cfg = HubConfig {
        database: db.app_dsn.clone(),
        db_pool_size: 2,
        db_connect_timeout_ms: 5_000,
        db_statement_timeout_ms: 10_000,
        db_sslrootcert: None,
        ..HubConfig::default()
    };
    let storage = PostgresStorage::open_from_config(&cfg)
        .unwrap_or_else(|e| panic!("open_from_config 失败：{e:#}"));
    storage.ping().expect("ping 必须成功");
    storage
        .apply_schema()
        .expect("在池内连接上 apply_schema 必须幂等成功");
    assert_eq!(storage.sample_count("missing").unwrap(), 0);
    drop(storage);

    // 非法 sslmode 必须在建连前拒绝，错误信息不含密码。
    let password = dsn_password(&db.app_dsn).expect("测试 DSN 必须带密码");
    let bad_dsn = db.app_dsn.replacen("sslmode=disable", "sslmode=require", 1);
    let err = PostgresStorage::open(PostgresOptions {
        dsn: bad_dsn,
        pool_size: 1,
        connect_timeout: Duration::from_secs(5),
        statement_timeout: Duration::from_secs(10),
        sslrootcert: None,
    })
    .expect_err("sslmode=require 必须被拒绝");
    let message = format!("{err:#}");
    assert!(!message.contains(&password), "错误信息泄露密码：{message}");
    assert!(
        message.contains("verify-full") && message.contains("disable"),
        "错误信息应列出允许的 sslmode：{message}"
    );
}
