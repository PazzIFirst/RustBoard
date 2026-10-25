//! Phase D3 Gate：PostgreSQL 200 agent 并发写入/查询与断连重连的实库负载测试。
//!
//! 依据 `docs/plans/2026-10-26-m5-phase-d-postgres-backup-l01-l03.md` §5 D3 的
//! Gate（“PG 200 agent 写入/查询达标；断连重连不丢已提交数据”）与
//! `docs/plans/2026-10-26-m5-phase-d-pg-spike.md` §11 编写。
//!
//! # 覆盖点
//!
//! 1. 200 个 OS 线程（`Barrier` 同时起跑）各写 5 批 × 3 点，全部经
//!    `Storage::insert_batch`；断言 0 失败、3000 samples、1000 ingest_batches、
//!    每 agent 15 行；串行 + 8 线程并发抽样校验 `sample_count` /
//!    `query_series` / `latest_samples`；记录总耗时与单批 p50/p95。
//!    `pool_size=8`：200 个 agent 复用 8 条 PG 连接，不建立 200 条长期连接。
//! 2. 先写入 50 行已提交数据，再用维护连接 `pg_terminate_backend` 杀掉测试库
//!    内其他连接（即池内空闲连接）；同一个 `PostgresStorage` 重试写入新批次
//!    （最多 10 次、间隔 100ms），断言最终成功，旧 50 + 新 3 = 53 行逐点无
//!    丢失。池的 `test_on_check_out=true` + `PgManager::is_valid`
//!    （`simple_query("")`）会在 checkout 时发现被杀连接、丢弃并由 r2d2 补建
//!    新连接，因此自动恢复；这是“按需/惰性”恢复，不是一次性重置整个池。
//! 3. 两个线程并发写同一 `(agent, epoch, seq)`：只允许一个 `Inserted`，另一个
//!    `Duplicate`，无 `Err`（D3 用 `INSERT ... ON CONFLICT DO NOTHING RETURNING`
//!    原子占位）。
//!
//! # 运行
//!
//! ```bash
//! export PATH="$HOME/.cargo/bin:$PATH"
//! set -a; . /tmp/rb-d3-pg.env; set +a
//! cargo test -p rustboard-core --test postgres_load --locked -- --nocapture
//! ```
//!
//! 未设置 `RUSTBOARD_TEST_PG`（或为空串）时每个用例打印 `SKIP` 并返回。
//! 测试不创建容器，只使用 `RUSTBOARD_TEST_PG` 指向的现有实例；每个用例创建
//! 独立临时库（角色需要 `CREATEDB`），结束时 `DROP DATABASE ... WITH (FORCE)`。
//! 断连用例还会对本库执行 `pg_terminate_backend`，角色需要超级用户或
//! `pg_signal_backend` 权限（CI 的 `POSTGRES_USER` 即超级用户）。
//! DSN 只存在于运行环境，本文件不含任何真实密码。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use postgres::config::SslMode;
use postgres::NoTls;
use rustboard_common::model::{Sample, SampleBatch, SeriesQuery};
use rustboard_core::storage::postgres::schema::{apply_schema, connect_for_schema};
use rustboard_core::storage::postgres::{PostgresOptions, PostgresStorage};
use rustboard_core::storage::{IngestOutcome, Storage};

/// 实库测试 DSN 的环境变量；未设置时全部用例 skip。
const PG_ENV: &str = "RUSTBOARD_TEST_PG";

const AGENTS: usize = 200;
const BATCHES_PER_AGENT: usize = 5;
const SAMPLES_PER_BATCH: usize = 3;

/// Gate 要求：连接池固定 8 条，与 200 个 agent 解耦。
const LOAD_POOL_SIZE: usize = 8;

/// 固定的基准时间，避免测试依赖真实时钟（查询用 `from=0`）。
const BASE_TS: i64 = 1_700_000_000_000;

/// 每批 3 个点，分别落在不同 metric 上，便于验证 `latest_samples` 去重。
const METRICS: [&str; SAMPLES_PER_BATCH] = ["cpu.usage", "mem.used", "disk.used"];

const RECONNECT_AGENT: &str = "reconnect-agent";
const DUPLICATE_AGENT: &str = "dup-agent";

/// 每次调用返回递增序号，避免同一纳秒内两个用例撞库名。
static DB_SEQ: AtomicU64 = AtomicU64::new(0);

fn skip(test_name: &str) {
    eprintln!("SKIP {test_name}: 未设置 {PG_ENV}（D3 PG 负载测试需要 PostgreSQL）");
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
        eprintln!("[d3-load] 创建测试数据库 {name}（tag={tag}）");
        Some(Self {
            name,
            admin,
            app,
            app_dsn,
        })
    }

    /// 应用 schema v7 并打开指定池大小的 `PostgresStorage`（tokio runtime 外）。
    fn open_storage(&self, pool_size: usize) -> PostgresStorage {
        let mut client = connect_for_schema(&self.app_dsn)
            .unwrap_or_else(|e| panic!("schema 连接失败（{}）：{e:#}", self.name));
        apply_schema(&mut client).unwrap_or_else(|e| panic!("apply_schema 失败：{e:#}"));
        drop(client);

        PostgresStorage::open(PostgresOptions {
            dsn: self.app_dsn.clone(),
            pool_size,
            connect_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(10),
            sslrootcert: None,
        })
        .unwrap_or_else(|e| panic!("打开 PostgresStorage 失败：{e:#}"))
    }

    /// 直连测试库（统计行数、杀掉池内连接等）。
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
                    "[d3-load] 清理失败：无法连接维护库删除 {}（请手工 DROP）：{e}",
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
                "[d3-load] 清理失败：DROP DATABASE {} 出错（请手工清理）：{e}",
                self.name
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 数据构造与校验辅助
// ---------------------------------------------------------------------------

fn agent_id(index: usize) -> String {
    format!("agent-{index:03}")
}

fn load_sample_ts(agent_index: usize, batch_index: usize, sample_index: usize) -> i64 {
    BASE_TS + (agent_index as i64) * 10_000 + (batch_index as i64) * 1_000 + sample_index as i64
}

fn load_sample_value(agent_index: usize, batch_index: usize, sample_index: usize) -> f64 {
    (agent_index * 1_000 + batch_index * 10 + sample_index) as f64
}

/// 200-agent 用例的单批数据：epoch 每 agent 不同，seq 每批不同。
fn load_batch(agent_index: usize, batch_index: usize) -> SampleBatch {
    let samples = (0..SAMPLES_PER_BATCH)
        .map(|sample_index| {
            Sample::new(
                METRICS[sample_index],
                load_sample_ts(agent_index, batch_index, sample_index),
                load_sample_value(agent_index, batch_index, sample_index),
            )
        })
        .collect();
    SampleBatch {
        agent_id: agent_id(agent_index),
        epoch: 1_000 + agent_index as u64,
        seq: batch_index as u64,
        boot_id: "boot-load".to_string(),
        sent_at: BASE_TS,
        samples,
    }
}

fn all_metrics_query(agent_id: &str, from: i64, to: i64, limit: u32) -> SeriesQuery {
    SeriesQuery {
        agent_id: agent_id.to_string(),
        metrics: METRICS.iter().map(|metric| (*metric).to_string()).collect(),
        from,
        to,
        limit,
    }
}

fn reconnect_sample_ts(seq: u64, sample_index: usize) -> i64 {
    BASE_TS + (seq as i64) * 1_000 + sample_index as i64
}

fn reconnect_sample_value(seq: u64, sample_index: usize) -> f64 {
    (seq * 10 + sample_index as u64) as f64
}

/// 断连重连用例的单批数据（单一 metric，ts 由 seq 唯一决定）。
fn reconnect_batch(seq: u64, sample_count: usize) -> SampleBatch {
    let samples = (0..sample_count)
        .map(|sample_index| {
            Sample::new(
                METRICS[0],
                reconnect_sample_ts(seq, sample_index),
                reconnect_sample_value(seq, sample_index),
            )
        })
        .collect();
    SampleBatch {
        agent_id: RECONNECT_AGENT.to_string(),
        epoch: 7,
        seq,
        boot_id: "boot-reconnect".to_string(),
        sent_at: BASE_TS,
        samples,
    }
}

fn duplicate_batch(round: u64) -> SampleBatch {
    let samples = (0..SAMPLES_PER_BATCH)
        .map(|sample_index| {
            Sample::new(
                METRICS[sample_index],
                BASE_TS + (round as i64) * 1_000 + sample_index as i64,
                (round * 10 + sample_index as u64) as f64,
            )
        })
        .collect();
    SampleBatch {
        agent_id: DUPLICATE_AGENT.to_string(),
        epoch: 9,
        seq: round,
        boot_id: "boot-duplicate".to_string(),
        sent_at: BASE_TS,
        samples,
    }
}

/// 串行校验一个 agent 的 `sample_count` / `query_series` / `latest_samples`。
fn verify_agent_load(storage: &dyn Storage, agent_index: usize) {
    let id = agent_id(agent_index);
    let expected_count = (BATCHES_PER_AGENT * SAMPLES_PER_BATCH) as i64;
    let count = storage
        .sample_count(&id)
        .unwrap_or_else(|e| panic!("sample_count({id}) 失败：{e:#}"));
    assert_eq!(count, expected_count, "agent {id} sample_count 不正确");

    let rows = storage
        .query_series(&all_metrics_query(&id, 0, i64::MAX, 100))
        .unwrap_or_else(|e| panic!("query_series({id}) 失败：{e:#}"));
    assert_eq!(
        rows.len(),
        BATCHES_PER_AGENT * SAMPLES_PER_BATCH,
        "agent {id} query_series 行数不正确"
    );
    for (batch_index, batch_rows) in rows.chunks(SAMPLES_PER_BATCH).enumerate() {
        for (sample_index, row) in batch_rows.iter().enumerate() {
            assert_eq!(
                row.metric, METRICS[sample_index],
                "agent {id} batch {batch_index} 的 metric 顺序不正确"
            );
            assert_eq!(
                row.ts,
                load_sample_ts(agent_index, batch_index, sample_index),
                "agent {id} batch {batch_index} sample {sample_index} 的 ts 不正确"
            );
            let expected = load_sample_value(agent_index, batch_index, sample_index);
            assert!(
                (row.value - expected).abs() <= 1e-9,
                "agent {id} batch {batch_index} sample {sample_index} 的 value 不正确：{} != {expected}",
                row.value
            );
            assert!(
                row.labels.is_empty(),
                "agent {id} 的测试点不应带 labels：{:?}",
                row.labels
            );
        }
    }

    // 每 agent 每 metric 一条最新点；cpu 应落在第 5 批（序号 4）的第 0 个点。
    let cpu_metrics = vec![METRICS[0].to_string()];
    let latest = storage
        .latest_samples(0, &cpu_metrics, Some(id.as_str()))
        .unwrap_or_else(|e| panic!("latest_samples({id}) 失败：{e:#}"));
    assert_eq!(
        latest.len(),
        1,
        "agent {id} latest_samples 应只有 1 条 cpu 序列"
    );
    assert_eq!(
        latest[0].ts,
        load_sample_ts(agent_index, BATCHES_PER_AGENT - 1, 0),
        "agent {id} latest_samples 的 ts 不正确"
    );
    let expected_latest = load_sample_value(agent_index, BATCHES_PER_AGENT - 1, 0);
    assert!(
        (latest[0].value - expected_latest).abs() <= 1e-9,
        "agent {id} latest_samples 的 value 不正确：{} != {expected_latest}",
        latest[0].value
    );
    assert!(
        latest[0].labels.is_empty(),
        "agent {id} latest_samples 不应带 labels：{:?}",
        latest[0].labels
    );
}

/// 最近秩（nearest-rank）百分位；输入必须已排序。
fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    assert!(!sorted.is_empty(), "百分位输入不能为空");
    assert!((1..=100).contains(&pct), "百分位必须在 1–100 之间");
    let rank = (sorted.len() * pct).div_ceil(100).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)]
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

// ---------------------------------------------------------------------------
// 1. 200 agent 并发写入 + 串行/并发查询
// ---------------------------------------------------------------------------

#[test]
fn two_hundred_agents_concurrent_ingest_and_query() {
    const NAME: &str = "two_hundred_agents_concurrent_ingest_and_query";
    let Some(db) = TestDatabase::create("load200") else {
        skip(NAME);
        return;
    };
    let storage = Arc::new(db.open_storage(LOAD_POOL_SIZE));

    let failures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let inserted_batches = Arc::new(AtomicUsize::new(0));
    let inserted_samples = Arc::new(AtomicUsize::new(0));
    let latencies: Arc<Mutex<Vec<Duration>>> =
        Arc::new(Mutex::new(Vec::with_capacity(AGENTS * BATCHES_PER_AGENT)));
    let barrier = Arc::new(Barrier::new(AGENTS));

    let write_started = Instant::now();
    let mut handles = Vec::with_capacity(AGENTS);
    for agent_index in 0..AGENTS {
        let storage = Arc::clone(&storage);
        let failures = Arc::clone(&failures);
        let inserted_batches = Arc::clone(&inserted_batches);
        let inserted_samples = Arc::clone(&inserted_samples);
        let latencies = Arc::clone(&latencies);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            // 200 个 agent 同时开始，全部经 Storage trait 写入。
            barrier.wait();
            for batch_index in 0..BATCHES_PER_AGENT {
                let batch = load_batch(agent_index, batch_index);
                let started = Instant::now();
                let result = Storage::insert_batch(storage.as_ref(), &batch);
                let elapsed = started.elapsed();
                latencies
                    .lock()
                    .expect("latencies mutex poisoned")
                    .push(elapsed);
                match result {
                    Ok(IngestOutcome::Inserted {
                        inserted: SAMPLES_PER_BATCH,
                    }) => {
                        inserted_batches.fetch_add(1, Ordering::Relaxed);
                        inserted_samples.fetch_add(SAMPLES_PER_BATCH, Ordering::Relaxed);
                    }
                    Ok(other) => failures
                        .lock()
                        .expect("failures mutex poisoned")
                        .push(format!(
                            "agent {agent_index} batch {batch_index} 返回非预期结果：{other:?}"
                        )),
                    Err(err) => failures
                        .lock()
                        .expect("failures mutex poisoned")
                        .push(format!(
                            "agent {agent_index} batch {batch_index} 写入失败：{err:#}"
                        )),
                }
            }
        }));
    }
    for handle in handles {
        handle.join().expect("200 agent 写入线程 panic");
    }
    let write_elapsed = write_started.elapsed();

    {
        let failures = failures.lock().expect("failures mutex poisoned");
        assert!(
            failures.is_empty(),
            "200 agent 并发写入出现 {} 个失败：{:?}",
            failures.len(),
            failures.iter().take(3).collect::<Vec<_>>()
        );
    }

    let expected_batches = AGENTS * BATCHES_PER_AGENT;
    let expected_samples = expected_batches * SAMPLES_PER_BATCH;
    assert_eq!(
        inserted_batches.load(Ordering::Relaxed),
        expected_batches,
        "成功批次数不正确"
    );
    assert_eq!(
        inserted_samples.load(Ordering::Relaxed),
        expected_samples,
        "成功点位数不正确"
    );

    // 直接 SQL 核对落库行数、批次数与每 agent 行数（不经过实现方法）。
    let mut client = db.client();
    let total_samples: i64 = client
        .query_one("SELECT COUNT(*)::BIGINT FROM samples", &[])
        .expect("统计 samples 失败")
        .get(0);
    assert_eq!(
        total_samples, expected_samples as i64,
        "samples 总行数应等于 {expected_samples}"
    );
    let total_batches: i64 = client
        .query_one("SELECT COUNT(*)::BIGINT FROM ingest_batches", &[])
        .expect("统计 ingest_batches 失败")
        .get(0);
    assert_eq!(
        total_batches, expected_batches as i64,
        "ingest_batches 行数应等于 {expected_batches}"
    );

    let sample_rows = client
        .query(
            "SELECT agent_id, COUNT(*)::BIGINT FROM samples
             GROUP BY agent_id ORDER BY agent_id",
            &[],
        )
        .expect("按 agent 统计 samples 失败");
    assert_eq!(
        sample_rows.len(),
        AGENTS,
        "samples 中应有 {AGENTS} 个 agent"
    );
    for (index, row) in sample_rows.iter().enumerate() {
        let id: String = row.get(0);
        let count: i64 = row.get(1);
        assert_eq!(id, agent_id(index), "第 {index} 个 agent_id 不正确");
        assert_eq!(
            count,
            (BATCHES_PER_AGENT * SAMPLES_PER_BATCH) as i64,
            "agent {id} 的行数不是 15"
        );
    }

    let batch_rows = client
        .query(
            "SELECT agent_id, COUNT(*)::BIGINT FROM ingest_batches
             GROUP BY agent_id ORDER BY agent_id",
            &[],
        )
        .expect("按 agent 统计 ingest_batches 失败");
    assert_eq!(
        batch_rows.len(),
        AGENTS,
        "ingest_batches 中应有 {AGENTS} 个 agent"
    );
    for (index, row) in batch_rows.iter().enumerate() {
        let id: String = row.get(0);
        let count: i64 = row.get(1);
        assert_eq!(
            id,
            agent_id(index),
            "ingest_batches 第 {index} 个 agent_id 不正确"
        );
        assert_eq!(count, BATCHES_PER_AGENT as i64, "agent {id} 的批次数不是 5");
    }

    // 200 个 agent 复用 8 条连接，而不是 200 条长期连接。
    let pool_conns: i64 = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM pg_stat_activity
             WHERE datname = current_database() AND application_name = 'rustboard-hub'",
            &[],
        )
        .expect("统计连接池连接数失败")
        .get(0);
    assert!(
        (1..=LOAD_POOL_SIZE as i64).contains(&pool_conns),
        "连接池应只持有 1–{LOAD_POOL_SIZE} 条连接，实际 {pool_conns}"
    );
    drop(client);

    // 串行抽样查询。
    let serial_started = Instant::now();
    for agent_index in [0usize, 17, 99, 199] {
        verify_agent_load(storage.as_ref(), agent_index);
    }
    let serial_elapsed = serial_started.elapsed();

    // 跨全部 agent 的 latest_samples：200 × 3 条序列，互不覆盖。
    let all_latest = storage
        .latest_samples(0, &[], None)
        .expect("跨 agent latest_samples 失败");
    assert_eq!(
        all_latest.len(),
        AGENTS * SAMPLES_PER_BATCH,
        "latest_samples 应返回 {AGENTS}×{SAMPLES_PER_BATCH} 条序列"
    );
    let mut latest_per_agent: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &all_latest {
        *latest_per_agent.entry(row.agent_id.as_str()).or_insert(0) += 1;
    }
    assert_eq!(
        latest_per_agent.len(),
        AGENTS,
        "latest_samples 应覆盖全部 {AGENTS} 个 agent"
    );
    assert!(
        latest_per_agent
            .values()
            .all(|&count| count == SAMPLES_PER_BATCH),
        "每个 agent 的 latest_samples 应恰好 {SAMPLES_PER_BATCH} 条"
    );
    let first_cpu = all_latest
        .iter()
        .find(|row| row.agent_id == "agent-000" && row.metric == METRICS[0])
        .expect("latest_samples 缺少 agent-000 的 cpu.usage");
    assert_eq!(
        first_cpu.ts,
        load_sample_ts(0, BATCHES_PER_AGENT - 1, 0),
        "agent-000 的 cpu.usage 最新点 ts 不正确"
    );

    // 8 线程并发抽样查询，覆盖全部 200 个 agent。
    const QUERY_WORKERS: usize = 8;
    let query_barrier = Arc::new(Barrier::new(QUERY_WORKERS));
    let query_started = Instant::now();
    let mut query_handles = Vec::with_capacity(QUERY_WORKERS);
    for worker in 0..QUERY_WORKERS {
        let storage = Arc::clone(&storage);
        let barrier = Arc::clone(&query_barrier);
        query_handles.push(std::thread::spawn(move || {
            barrier.wait();
            for offset in 0..(AGENTS / QUERY_WORKERS) {
                verify_agent_load(storage.as_ref(), worker + offset * QUERY_WORKERS);
            }
        }));
    }
    for handle in query_handles {
        handle.join().expect("并发查询线程 panic");
    }
    let query_elapsed = query_started.elapsed();

    // 单线程基线：重复写已存在的批次（返回 Duplicate，不新增行），用于区分
    // “200 线程同时起跑的连接池排队时间”和“单批事务本身的开销”。
    let mut baseline_latencies = Vec::with_capacity(50);
    for _ in 0..50 {
        let started = Instant::now();
        let outcome =
            Storage::insert_batch(storage.as_ref(), &load_batch(0, 0)).expect("单线程基线写入失败");
        assert!(
            matches!(outcome, IngestOutcome::Duplicate),
            "同一批次重复写入应为 Duplicate，实际 {outcome:?}"
        );
        baseline_latencies.push(started.elapsed());
    }
    baseline_latencies.sort_unstable();
    assert_eq!(
        storage
            .sample_count(&agent_id(0))
            .expect("基线后 sample_count 失败"),
        (BATCHES_PER_AGENT * SAMPLES_PER_BATCH) as i64,
        "重复批次不应增加 samples 行数"
    );

    let mut sorted_latencies = latencies.lock().expect("latencies mutex poisoned").clone();
    sorted_latencies.sort_unstable();
    let p50 = percentile(&sorted_latencies, 50);
    let p95 = percentile(&sorted_latencies, 95);
    let max = *sorted_latencies.last().expect("至少有一个批次延迟");
    let baseline_p50 = percentile(&baseline_latencies, 50);
    let baseline_p95 = percentile(&baseline_latencies, 95);
    eprintln!(
        "[d3-load] agents={AGENTS} 线程={AGENTS} pool_size={LOAD_POOL_SIZE} 实际池连接={pool_conns}；\
         写入总耗时={:.3}s 吞吐={:.1} batch/s 单批端到端延迟（含池排队）p50={:.3}ms p95={:.3}ms max={:.3}ms；\
         单线程重复批基线 p50={:.3}ms p95={:.3}ms；\
         串行查询 4 agent={:.3}ms，并发查询 {QUERY_WORKERS} 线程×{} agent={:.3}ms；\
         samples={total_samples} ingest_batches={total_batches}，每 agent 15 行，0 失败",
        write_elapsed.as_secs_f64(),
        expected_batches as f64 / write_elapsed.as_secs_f64(),
        millis(p50),
        millis(p95),
        millis(max),
        millis(baseline_p50),
        millis(baseline_p95),
        millis(serial_elapsed),
        AGENTS / QUERY_WORKERS,
        millis(query_elapsed),
    );
}

// ---------------------------------------------------------------------------
// 2. 断连重连：已提交数据不丢，池自动补建连接
// ---------------------------------------------------------------------------

#[test]
fn disconnect_and_reconnect_preserves_committed_rows() {
    const NAME: &str = "disconnect_and_reconnect_preserves_committed_rows";
    let Some(db) = TestDatabase::create("reconnect") else {
        skip(NAME);
        return;
    };
    const POOL_SIZE: usize = 4;
    let storage = Arc::new(db.open_storage(POOL_SIZE));

    // 4 条连接并发写 8 批 + 串行 2 批，共 10 批 × 5 点 = 50 行已提交数据。
    let barrier = Arc::new(Barrier::new(POOL_SIZE));
    let mut handles = Vec::with_capacity(POOL_SIZE);
    for worker in 0..POOL_SIZE {
        let storage = Arc::clone(&storage);
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            for offset in 0..2u64 {
                let seq = worker as u64 * 2 + offset;
                match Storage::insert_batch(storage.as_ref(), &reconnect_batch(seq, 5)) {
                    Ok(IngestOutcome::Inserted { inserted: 5 }) => {}
                    Ok(other) => panic!("预热 seq={seq} 返回非预期结果：{other:?}"),
                    Err(err) => panic!("预热 seq={seq} 写入失败：{err:#}"),
                }
            }
        }));
    }
    for handle in handles {
        handle.join().expect("预热写入线程 panic");
    }
    for seq in [8u64, 9] {
        match Storage::insert_batch(storage.as_ref(), &reconnect_batch(seq, 5)) {
            Ok(IngestOutcome::Inserted { inserted: 5 }) => {}
            Ok(other) => panic!("预热 seq={seq} 返回非预期结果：{other:?}"),
            Err(err) => panic!("预热 seq={seq} 写入失败：{err:#}"),
        }
    }
    let before_count = storage
        .sample_count(RECONNECT_AGENT)
        .expect("断连前 sample_count 失败");
    assert_eq!(before_count, 50, "断连前应已提交 50 行");

    // 维护连接杀掉测试库内除自己以外的全部连接（即池内空闲连接）。
    let mut maintenance = db.client();
    let pool_before: i64 = maintenance
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM pg_stat_activity
             WHERE datname = current_database() AND application_name = 'rustboard-hub'",
            &[],
        )
        .expect("统计断连前池连接失败")
        .get(0);
    assert!(
        (1..=POOL_SIZE as i64).contains(&pool_before),
        "断连前应存在 1–{POOL_SIZE} 条池连接，实际 {pool_before}"
    );
    let terminated: Vec<bool> = maintenance
        .query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
             WHERE datname = current_database() AND pid <> pg_backend_pid()",
            &[],
        )
        .expect("pg_terminate_backend 失败")
        .iter()
        .map(|row| row.get(0))
        .collect();
    drop(maintenance);
    let killed = terminated.into_iter().filter(|&flag| flag).count();
    assert!(killed >= 1, "没有杀掉任何测试库连接，故障注入未生效");
    eprintln!(
        "[d3-reconnect] pool_size={POOL_SIZE} 断连前池连接={pool_before}，已终止 {killed} 条测试库连接"
    );
    // 给服务端一点时间完成 FIN/RST，避免重连与杀连接竞争。
    std::thread::sleep(Duration::from_millis(100));

    // 同一个 PostgresStorage：最多重试 10 次，间隔 100ms，最终必须成功。
    let reconnect_started = Instant::now();
    let mut attempts = 0usize;
    loop {
        attempts += 1;
        let attempt_started = Instant::now();
        match Storage::insert_batch(storage.as_ref(), &reconnect_batch(10, 3)) {
            Ok(IngestOutcome::Inserted { inserted: 3 }) => {
                eprintln!(
                    "[d3-reconnect] 断连后第 {attempts} 次写入成功（{:.3}ms）",
                    millis(attempt_started.elapsed())
                );
                break;
            }
            Ok(other) => panic!("断连重连写入返回非预期结果（第 {attempts} 次）：{other:?}"),
            Err(err) => {
                eprintln!(
                    "[d3-reconnect] 断连后第 {attempts} 次写入失败（{:.3}ms）：{err:#}",
                    millis(attempt_started.elapsed())
                );
                assert!(attempts < 10, "断连重连重试 10 次仍失败：{err:#}");
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    let reconnect_elapsed = reconnect_started.elapsed();

    // 旧 50 行 + 新 3 行逐点核对，确认已提交数据没有丢失。
    let after_count = storage
        .sample_count(RECONNECT_AGENT)
        .expect("断连后 sample_count 失败");
    assert_eq!(after_count, 53, "断连重连后应恰好 53 行");
    let rows = storage
        .query_series(&all_metrics_query(RECONNECT_AGENT, 0, i64::MAX, 100))
        .expect("断连后 query_series 失败");
    assert_eq!(rows.len(), 53, "断连后 query_series 应返回 53 行");
    let actual: BTreeMap<i64, f64> = rows.iter().map(|row| (row.ts, row.value)).collect();
    assert_eq!(actual.len(), 53, "断连后不应出现重复/丢失的时间戳");
    for seq in 0..10u64 {
        for sample_index in 0..5 {
            let ts = reconnect_sample_ts(seq, sample_index);
            let value = reconnect_sample_value(seq, sample_index);
            assert_eq!(
                actual.get(&ts).copied(),
                Some(value),
                "已提交的旧数据点丢失：seq={seq} sample={sample_index} ts={ts}"
            );
        }
    }
    for sample_index in 0..3 {
        let ts = reconnect_sample_ts(10, sample_index);
        let value = reconnect_sample_value(10, sample_index);
        assert_eq!(
            actual.get(&ts).copied(),
            Some(value),
            "断连后的新数据点缺失：sample={sample_index} ts={ts}"
        );
    }

    let mut client = db.client();
    let total_batches: i64 = client
        .query_one("SELECT COUNT(*)::BIGINT FROM ingest_batches", &[])
        .expect("统计断连后 ingest_batches 失败")
        .get(0);
    assert_eq!(
        total_batches, 11,
        "断连后 ingest_batches 应为 11（10 旧 + 1 新）"
    );
    let pool_conns: i64 = client
        .query_one(
            "SELECT COUNT(*)::BIGINT FROM pg_stat_activity
             WHERE datname = current_database() AND application_name = 'rustboard-hub'",
            &[],
        )
        .expect("统计断连后池连接失败")
        .get(0);
    assert!(
        (1..=POOL_SIZE as i64).contains(&pool_conns),
        "断连后池应自动补建 1–{POOL_SIZE} 条连接，实际 {pool_conns}"
    );
    eprintln!(
        "[d3-reconnect] 断连恢复：重试 {attempts} 次、耗时 {:.3}ms；旧 50 行 + 新 3 行 = 53 行逐点核对无丢失；\
         ingest_batches=11；池当前活连接={pool_conns}（test_on_check_out + is_valid 惰性自动恢复，无需重建 Pool）",
        millis(reconnect_elapsed)
    );
}

// ---------------------------------------------------------------------------
// 3. 并发重复批次：同一 (agent, epoch, seq) 只插入一次
// ---------------------------------------------------------------------------

#[test]
fn concurrent_duplicate_batch_is_inserted_once() {
    const NAME: &str = "concurrent_duplicate_batch_is_inserted_once";
    let Some(db) = TestDatabase::create("duplicate") else {
        skip(NAME);
        return;
    };
    const ROUNDS: u64 = 5;
    let storage = Arc::new(db.open_storage(4));

    for round in 0..ROUNDS {
        let barrier = Arc::new(Barrier::new(2));
        let mut handles = Vec::with_capacity(2);
        for _ in 0..2 {
            let storage = Arc::clone(&storage);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                Storage::insert_batch(storage.as_ref(), &duplicate_batch(round))
                    .unwrap_or_else(|e| panic!("第 {round} 轮重复批次写入失败：{e:#}"))
            }));
        }
        let outcomes: Vec<IngestOutcome> = handles
            .into_iter()
            .map(|handle| handle.join().expect("重复批次线程 panic"))
            .collect();

        let mut inserted = 0usize;
        let mut duplicate = 0usize;
        for outcome in &outcomes {
            match outcome {
                IngestOutcome::Inserted { inserted: count } if *count == SAMPLES_PER_BATCH => {
                    inserted += 1;
                }
                IngestOutcome::Duplicate => duplicate += 1,
                other => panic!("第 {round} 轮返回非预期结果：{other:?}"),
            }
        }
        assert_eq!(inserted, 1, "第 {round} 轮应恰好一个线程 Inserted");
        assert_eq!(duplicate, 1, "第 {round} 轮应恰好一个线程 Duplicate");
    }

    let count = storage
        .sample_count(DUPLICATE_AGENT)
        .expect("重复批次 sample_count 失败");
    assert_eq!(
        count,
        (ROUNDS * SAMPLES_PER_BATCH as u64) as i64,
        "重复批次不应增加点数"
    );
    let mut client = db.client();
    let total_batches: i64 = client
        .query_one("SELECT COUNT(*)::BIGINT FROM ingest_batches", &[])
        .expect("统计重复批次 ingest_batches 失败")
        .get(0);
    assert_eq!(total_batches, ROUNDS as i64, "重复批次只应占一次判重记录");
    eprintln!(
        "[d3-dup] {ROUNDS} 轮 × 2 线程同键并发：每轮 1 Inserted + 1 Duplicate、0 Err；\
         samples={count} ingest_batches={total_batches}（SQL 幂等占位由 D3 修复）"
    );
}
