//! PostgreSQL schema v7：21 张业务表、索引与迁移入口。
//!
//! 这是 Phase D2 的落地：只负责「建表/索引 + 版本记录」，不实现任何
//! [`Storage`](crate::storage::Storage) 方法（D3 才做 `PostgresStorage`）。
//! 本模块也不处理 TLS 与连接池：D2 的迁移入口
//! [`connect_for_schema`] 只支持 `sslmode=disable`，供 `hub migrate` 前的
//! schema 初始化与测试使用；生产连接（verify-full + r2d2）在 D3/D4 接线。
//!
//! # 与 SQLite v7 的对应关系
//!
//! 基线是 `crates/rustboard-core/src/storage/sqlite.rs` 的 `SCHEMA_VERSION = 7`
//! （21 张表、19 个显式命名索引）。PG 使用独立的版本表，不复用
//! `PRAGMA user_version`：
//!
//! - `INTEGER`（时间戳/计数）→ `BIGINT`；
//! - `REAL` → `DOUBLE PRECISION`；
//! - JSON 列继续用 `TEXT`（序列化格式不变）；
//! - 布尔列 `alert_rules.enabled/notify_on_resolve/is_builtin`、
//!   `alert_events.notified/silenced`、`notification_channels.enabled`
//!   → `BOOLEAN`，读取层必须显式转换，不能沿用 SQLite 的 `i64` 假设；
//! - 自增主键 → `BIGSERIAL`。
//!
//! ## 为什么 `samples` / `samples_1m` / `samples_1h` / `alert_states` 要加 `id`
//!
//! SQLite 有隐式 `rowid`：`samples` 本身没有主键，D3 的聚合 SQL 与告警状态
//! 清理都靠 `rowid` 做「同一 ts 的稳定次序」和删除游标。PG 没有 `rowid`，
//! 因此这四张表额外加 `id BIGSERIAL PRIMARY KEY`：
//!
//! - `samples_1m` / `samples_1h` 原有的复合主键
//!   `(agent_id, metric, labels, bucket_ts)` 改成 `UNIQUE` 约束，保留
//!   `ON CONFLICT (...) DO UPDATE` 的 upsert 目标；
//! - `alert_states` 原有的 `(rule_id, agent_id, series_key)` 同样改成 `UNIQUE`；
//! - 由此 D3 可把 `ORDER BY ts DESC, rowid DESC` 直接映射为
//!   `ORDER BY ts DESC, id DESC`，分页/删除游标不再依赖物理顺序。
//!
//! 这些 `id` 列只增加主键默认索引，不额外改变 SQLite 既有查询计划：19 个
//! 命名索引与 SQLite 一一对应（SQLite 基线实际是 19 个显式索引，不是 20 个）。
//!
//! # 迁移策略
//!
//! [`apply_schema`] 在**单个事务**内完成：
//!
//! 1. 先取固定 key 的事务级 advisory lock，多实例同时启动时只有一个能迁移；
//! 2. 读 `schema_migrations` 最大版本：`> 7` 明确拒绝（防止旧二进制写坏新库）；
//! 3. 已是 7：只校验 21 张表与 19 个索引存在，然后提交（幂等、零 DDL）；
//! 4. 空库 / 半迁移（表存在但没有版本行）/ 旧版本：执行全部
//!    `CREATE TABLE/INDEX IF NOT EXISTS` 补齐，校验后写入 version 7；
//! 5. 任何一步失败都回滚整个事务，不留半套表。
//!
//! 半迁移场景刻意依赖 `IF NOT EXISTS`：已有表的**列**不会被改写（PG 的
//! `CREATE TABLE IF NOT EXISTS` 不会补列），但缺的表/索引会补齐且不触碰数据。
//! 若已有表结构与本 schema 不兼容，DDL 会失败并整体回滚，而不是静默留坏库。

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use postgres::config::SslMode;
use postgres::NoTls;

/// PostgreSQL schema 版本；与 SQLite 的 `PRAGMA user_version = 7` 对齐。
pub const POSTGRES_SCHEMA_VERSION: i64 = 7;

/// schema 迁移的固定 advisory lock key（hex 语义：`RB` + `PG` + 版本 7）。
///
/// 事务级锁（`pg_advisory_xact_lock`）随事务提交/回滚自动释放，不需要
/// 显式 unlock；固定成常量以保证所有 hub 实例争用同一把锁。
pub const SCHEMA_ADVISORY_LOCK_KEY: i64 = 0x5242_5047_0000_0007;

/// 21 张业务表；用于迁移后与「已是 v7」路径的存在性校验。
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

/// SQLite v7 的 19 个显式命名索引；PG 侧名字与列顺序完全一致。
///
/// 主键/唯一约束产生的隐式索引（`*_pkey`、`*_key`、`*_unique`）不计入这里。
const INDEXES: [&str; 19] = [
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
];

/// 版本表。SQLite 用 `PRAGMA user_version`，PG 独立维护，避免两套后端语义混淆。
const SCHEMA_MIGRATIONS_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    BIGINT PRIMARY KEY,
    applied_at BIGINT NOT NULL
);
"#;

/// v7 全量 DDL。
///
/// 全部 `IF NOT EXISTS`：空库、半迁移（只建了部分表、没有版本行）与旧版本
/// 都能安全补齐；已存在表的数据不会被 DDL 触碰。
const POSTGRES_SCHEMA_DDL: &str = r#"
-- v1：agent 元数据与原始采样。samples 在 SQLite 没有主键，PG 用 BIGSERIAL
-- id 提供稳定行序/删除游标（D3 映射 rowid）。
CREATE TABLE IF NOT EXISTS agents (
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

CREATE TABLE IF NOT EXISTS samples (
    id       BIGSERIAL PRIMARY KEY,
    agent_id TEXT NOT NULL,
    metric   TEXT NOT NULL,
    labels   TEXT NOT NULL DEFAULT '{}',
    ts       BIGINT NOT NULL,
    value    DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_lookup ON samples(agent_id, metric, ts);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);

CREATE TABLE IF NOT EXISTS enroll_tokens (
    token_hash TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    used_at    BIGINT
);

CREATE TABLE IF NOT EXISTS agent_secrets (
    agent_id    TEXT PRIMARY KEY,
    secret_hash TEXT NOT NULL,
    created_at  BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_agents (
    agent_id   TEXT PRIMARY KEY,
    revoked_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_settings (
    agent_id           TEXT PRIMARY KEY,
    sample_interval_ms BIGINT NOT NULL,
    updated_at         BIGINT NOT NULL
);

-- v2：每 (agent_id, epoch) 的判重状态。
CREATE TABLE IF NOT EXISTS ingest_state (
    agent_id   TEXT NOT NULL,
    epoch      BIGINT NOT NULL,
    last_seq   BIGINT NOT NULL DEFAULT 0,
    updated_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, epoch)
);

-- v3：逐批精确判重。
CREATE TABLE IF NOT EXISTS ingest_batches (
    agent_id TEXT NOT NULL,
    epoch    BIGINT NOT NULL,
    seq      BIGINT NOT NULL,
    ts       BIGINT NOT NULL,
    PRIMARY KEY (agent_id, epoch, seq)
);
CREATE INDEX IF NOT EXISTS idx_ingest_batches_ts ON ingest_batches(ts);

-- v5：控制面能力与操作审计。
CREATE TABLE IF NOT EXISTS agent_control (
    agent_id     TEXT PRIMARY KEY,
    capabilities TEXT NOT NULL DEFAULT '[]',
    updated_at   BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            BIGSERIAL PRIMARY KEY,
    ts            BIGINT NOT NULL,
    actor         TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    capability    TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT NOT NULL DEFAULT '',
    params        TEXT NOT NULL DEFAULT '{}',
    result        TEXT NOT NULL,
    error_code    TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    duration_ms   BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit_log(agent_id, ts);

-- v6：管理 API scoped token；只存 SHA-256 hex，吊销写 revoked_at 不删行。
CREATE TABLE IF NOT EXISTS api_tokens (
    id           BIGSERIAL PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    token_hash   TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL CHECK (scope IN ('read','write','admin')),
    created_at   BIGINT NOT NULL,
    last_used_at BIGINT,
    revoked_at   BIGINT
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);

-- v7：降采样。原复合主键改成 UNIQUE，保留 upsert 目标；id 供稳定行序。
CREATE TABLE IF NOT EXISTS samples_1m (
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
CREATE INDEX IF NOT EXISTS idx_samples_1m_lookup ON samples_1m(agent_id, metric, bucket_ts);
CREATE INDEX IF NOT EXISTS idx_samples_1m_ts ON samples_1m(bucket_ts);

CREATE TABLE IF NOT EXISTS samples_1h (
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
    CONSTRAINT samples_1h_unique UNIQUE (agent_id, metric, labels, bucket_ts)
);
CREATE INDEX IF NOT EXISTS idx_samples_1h_lookup ON samples_1h(agent_id, metric, bucket_ts);
CREATE INDEX IF NOT EXISTS idx_samples_1h_ts ON samples_1h(bucket_ts);

CREATE TABLE IF NOT EXISTS maintenance_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- 告警 raw-only 查询按 metric + 时间范围扫描（M4-B1b）。
CREATE INDEX IF NOT EXISTS idx_samples_metric_ts ON samples(metric, ts);

CREATE TABLE IF NOT EXISTS alert_rules (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    enabled           BOOLEAN NOT NULL DEFAULT FALSE,
    source            TEXT NOT NULL DEFAULT 'metric',
    metric            TEXT NOT NULL DEFAULT '',
    comparator        TEXT NOT NULL DEFAULT 'gt',
    threshold         DOUBLE PRECISION NOT NULL DEFAULT 0,
    duration_secs     BIGINT NOT NULL DEFAULT 0,
    cooldown_secs     BIGINT NOT NULL DEFAULT 1800,
    filter_agent_id   TEXT,
    filter_labels     TEXT NOT NULL DEFAULT '{}',
    channel_ids       TEXT NOT NULL DEFAULT '[]',
    notify_on_resolve BOOLEAN NOT NULL DEFAULT TRUE,
    is_builtin        BOOLEAN NOT NULL DEFAULT FALSE,
    updated_by        TEXT NOT NULL DEFAULT '',
    created_at        BIGINT NOT NULL,
    updated_at        BIGINT NOT NULL
);

-- 原复合主键改成 UNIQUE（保留 ON CONFLICT 目标）；id 供删除游标。
CREATE TABLE IF NOT EXISTS alert_states (
    id               BIGSERIAL PRIMARY KEY,
    rule_id          TEXT NOT NULL,
    agent_id         TEXT NOT NULL DEFAULT '',
    series_key       TEXT NOT NULL DEFAULT '',
    state            TEXT NOT NULL DEFAULT 'pending',
    since            BIGINT NOT NULL,
    last_eval_at     BIGINT NOT NULL,
    last_value       DOUBLE PRECISION,
    last_notified_at BIGINT,
    CONSTRAINT alert_states_unique UNIQUE (rule_id, agent_id, series_key)
);
CREATE INDEX IF NOT EXISTS idx_alert_states_state_eval ON alert_states(state, last_eval_at);

CREATE TABLE IF NOT EXISTS alert_events (
    id           BIGSERIAL PRIMARY KEY,
    ts           BIGINT NOT NULL,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    agent_id     TEXT NOT NULL DEFAULT '',
    series_key   TEXT NOT NULL DEFAULT '',
    state        TEXT NOT NULL,
    value        DOUBLE PRECISION,
    message      TEXT NOT NULL DEFAULT '',
    notified     BOOLEAN NOT NULL DEFAULT FALSE,
    notify_error TEXT NOT NULL DEFAULT '',
    silenced     BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_alert_events_ts ON alert_events(ts);
CREATE INDEX IF NOT EXISTS idx_alert_events_rule_ts ON alert_events(rule_id, ts);
CREATE INDEX IF NOT EXISTS idx_alert_events_agent_ts ON alert_events(agent_id, ts);
-- B2 通知队列：只取未通知且未静默的事件，按 id 升序。
CREATE INDEX IF NOT EXISTS idx_alert_events_pending ON alert_events(notified, silenced, id);

CREATE TABLE IF NOT EXISTS alert_silences (
    id         BIGSERIAL PRIMARY KEY,
    rule_id    TEXT,
    agent_id   TEXT,
    until_ts   BIGINT NOT NULL,
    created_by TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_silences_until ON alert_silences(until_ts);

CREATE TABLE IF NOT EXISTS notification_channels (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    config_json TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by  TEXT NOT NULL DEFAULT '',
    created_at  BIGINT NOT NULL,
    updated_at  BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS archive_objects (
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
CREATE INDEX IF NOT EXISTS idx_archive_objects_range ON archive_objects(from_ts, to_ts);
CREATE INDEX IF NOT EXISTS idx_archive_objects_status ON archive_objects(status);

CREATE TABLE IF NOT EXISTS archive_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);
"#;

/// 解析 DSN、叠加环境变量密码，返回 schema 初始化用的连接配置。
///
/// 密码优先级与 [`PostgresStorage::open`](super::PostgresStorage::open) 一致：
/// `RUSTBOARD_DATABASE_PASSWORD` 非空时覆盖 DSN query/authority 里的密码；
/// 未设置或空串则沿用 DSN 内密码。非 UTF-8 的 env 直接报错（fail-closed），
/// 错误信息只含变量名，不回显密码或 DSN。
fn schema_config(dsn: &str) -> Result<postgres::Config> {
    let mut config: postgres::Config = dsn
        .parse()
        .context("PostgreSQL DSN 解析失败（D2 schema 连接只支持 sslmode=disable）")?;
    if config.get_ssl_mode() != SslMode::Disable {
        bail!(
            "schema 初始化连接只支持 sslmode=disable；生产 TLS/pool 由 D3 的 PostgresStorage 负责"
        );
    }
    if let Some(password) = super::database_password_from_env()? {
        config.password(password);
    }
    Ok(config)
}

/// 解析 DSN 并建立一条**仅供 schema 初始化使用**的连接。
///
/// D2 不做 TLS、不做连接池：只接受显式 `sslmode=disable`（本地/受信内网），
/// 其他模式直接拒绝，避免误以为这里已经具备生产 TLS 语义。D3 的
/// `PostgresStorage` 会用 `tokio-postgres-rustls` + `r2d2` 单独建连。
///
/// env `RUSTBOARD_DATABASE_PASSWORD` 非空时覆盖 DSN 内密码，与
/// `PostgresStorage` 保持一致；错误信息不回显 DSN 或密码。
pub fn connect_for_schema(dsn: &str) -> Result<postgres::Client> {
    schema_config(dsn)?
        .connect(NoTls)
        .context("连接 PostgreSQL 失败（D2 schema 连接只支持 sslmode=disable）")
}

/// 在给定连接上应用/校验 PostgreSQL schema v7。
///
/// 幂等：可重复调用。整个迁移在单事务内完成，失败自动回滚。调用方负责
/// 串行化以外的生命周期（D2 测试直接调用；D3 启动时在 blocking 线程调用）。
pub fn apply_schema(client: &mut postgres::Client) -> Result<()> {
    if let Err(err) = apply_schema_inner(client) {
        // 不打印 DSN 或连接串；错误本身来自 DDL/版本校验，可安全记录。
        tracing::error!(error = %err, "PostgreSQL schema 应用失败，事务已回滚");
        return Err(err);
    }
    Ok(())
}

fn apply_schema_inner(client: &mut postgres::Client) -> Result<()> {
    let mut tx = client
        .transaction()
        .context("开启 PostgreSQL schema 迁移事务失败")?;

    // schema DDL/校验可能在大库上超过连接级 statement_timeout；只在迁移事务内
    // 取消超时（SET LOCAL 随提交/回滚自动失效），不改变连接池里其它语句。
    tx.batch_execute("SET LOCAL statement_timeout = 0")
        .context("关闭 schema 迁移事务的 statement_timeout 失败")?;

    // 锁必须在读版本之前：两个实例同时启动时，后到者阻塞到前者提交，
    // 再看到 version=7 走纯校验路径，不会重复执行 DDL。
    tx.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&SCHEMA_ADVISORY_LOCK_KEY],
    )
    .context("获取 PostgreSQL schema advisory lock 失败")?;

    // 版本表本身也放进同一事务：回滚后不会残留。
    tx.batch_execute(SCHEMA_MIGRATIONS_DDL)
        .context("创建 PostgreSQL schema_migrations 表失败")?;

    let current: Option<i64> = tx
        .query_one("SELECT MAX(version) FROM schema_migrations", &[])
        .context("读取 PostgreSQL schema 版本失败")?
        .get(0);
    let current = current.unwrap_or(0);

    if current > POSTGRES_SCHEMA_VERSION {
        bail!(
            "PostgreSQL schema 版本 {current} 高于本程序支持的 {POSTGRES_SCHEMA_VERSION}；\
             请升级 rustboard-hub 后再启动，避免旧二进制写坏新库"
        );
    }

    if current == POSTGRES_SCHEMA_VERSION {
        // 已是 v7：只校验对象存在，不执行 DDL（幂等路径）。
        ensure_schema_objects(&mut tx)?;
        tx.commit().context("提交 PostgreSQL schema 校验事务失败")?;
        tracing::debug!(version = current, "PostgreSQL schema 已是最新，跳过迁移");
        return Ok(());
    }

    // 空库 / 半迁移 / 旧版本：全部 IF NOT EXISTS，已有数据原样保留。
    tx.batch_execute(POSTGRES_SCHEMA_DDL)
        .context("执行 PostgreSQL schema v7 DDL 失败")?;
    ensure_schema_objects(&mut tx)?;

    tx.execute(
        "INSERT INTO schema_migrations (version, applied_at) VALUES ($1, $2) \
         ON CONFLICT (version) DO NOTHING",
        &[&POSTGRES_SCHEMA_VERSION, &now_ms()],
    )
    .context("写入 PostgreSQL schema 版本失败")?;

    tx.commit().context("提交 PostgreSQL schema 迁移事务失败")?;
    tracing::info!(
        from = current,
        to = POSTGRES_SCHEMA_VERSION,
        "PostgreSQL schema v7 已创建/补齐"
    );
    Ok(())
}

/// 校验 21 张业务表与 19 个命名索引都已存在。
///
/// 只查目录表，不锁表、不触碰数据；在迁移事务内调用，失败会连同 DDL 一起回滚。
fn ensure_schema_objects(tx: &mut postgres::Transaction<'_>) -> Result<()> {
    for table in TABLES {
        let exists: bool = tx
            .query_one(
                "SELECT EXISTS (
                     SELECT 1 FROM information_schema.tables
                     WHERE table_schema = current_schema() AND table_name = $1
                 )",
                &[&table],
            )
            .with_context(|| format!("校验 PostgreSQL 表 {table} 是否存在失败"))?
            .get(0);
        if !exists {
            bail!(
                "PostgreSQL schema 缺少表 {table}；迁移可能异常中断或数据库被手工修改，\
                 请重试；仍失败则从备份恢复"
            );
        }
    }

    for index in INDEXES {
        let exists: bool = tx
            .query_one(
                "SELECT EXISTS (
                     SELECT 1 FROM pg_indexes
                     WHERE schemaname = current_schema() AND indexname = $1
                 )",
                &[&index],
            )
            .with_context(|| format!("校验 PostgreSQL 索引 {index} 是否存在失败"))?
            .get(0);
        if !exists {
            bail!(
                "PostgreSQL schema 缺少索引 {index}；迁移可能异常中断或数据库被手工修改，\
                 请重试；仍失败则从备份恢复"
            );
        }
    }
    Ok(())
}

/// Unix 毫秒时间戳；系统时钟异常时退化为 0（仅用于版本表审计字段）。
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::sync::{Mutex, MutexGuard};

    use super::*;

    /// 表/索引清单必须与 SQLite v7 基线一一对应，防止后续改 DDL 时漏项。
    #[test]
    fn table_and_index_lists_are_distinct_and_match_baseline() {
        assert_eq!(TABLES.len(), 21);
        assert_eq!(INDEXES.len(), 19);

        let mut tables = TABLES.to_vec();
        tables.sort_unstable();
        tables.dedup();
        assert_eq!(tables.len(), 21, "TABLES 有重复项");

        let mut indexes = INDEXES.to_vec();
        indexes.sort_unstable();
        indexes.dedup();
        assert_eq!(indexes.len(), 19, "INDEXES 有重复项");
    }

    /// 版本号固定 7，advisory lock 固定且不与版本号混淆。
    #[test]
    fn version_and_lock_key_are_stable() {
        assert_eq!(POSTGRES_SCHEMA_VERSION, 7);
        assert_eq!(SCHEMA_ADVISORY_LOCK_KEY, 0x5242_5047_0000_0007);
    }

    /// DDL 必须覆盖清单里的每张表与每个索引（字符串级自检，不需要数据库）。
    #[test]
    fn ddl_contains_every_declared_object() {
        for table in TABLES {
            assert!(
                POSTGRES_SCHEMA_DDL.contains(&format!("CREATE TABLE IF NOT EXISTS {table} (")),
                "DDL 缺少表 {table}"
            );
        }
        for index in INDEXES {
            assert!(
                POSTGRES_SCHEMA_DDL.contains(&format!("CREATE INDEX IF NOT EXISTS {index} ON ")),
                "DDL 缺少索引 {index}"
            );
        }
    }

    /// D2 的 schema 连接必须拒绝任何非 `disable` 的 TLS 模式。
    #[test]
    fn schema_connection_rejects_tls_modes() {
        for dsn in [
            "postgres://rustboard@127.0.0.1:1/rustboard?sslmode=require",
            // 缺省 sslmode 在驱动里是 prefer；生产默认 verify-full 由 D3 负责。
            "postgres://rustboard@127.0.0.1:1/rustboard",
        ] {
            let err = connect_for_schema(dsn)
                .err()
                .expect("非 sslmode=disable 必须在建连前被拒绝");
            assert!(
                format!("{err:#}").contains("sslmode=disable"),
                "错误信息应指明只支持 sslmode=disable：{err:#}"
            );
        }
    }

    /// 布尔列必须映射成 BOOLEAN；id 主键必须是 BIGSERIAL。
    #[test]
    fn ddl_type_mapping_is_explicit() {
        // 去掉对齐空格后再断言，避免 DDL 缩进调整导致测试假失败。
        let normalized = POSTGRES_SCHEMA_DDL
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for column in [
            "enabled BOOLEAN NOT NULL DEFAULT FALSE",
            "notify_on_resolve BOOLEAN NOT NULL DEFAULT TRUE",
            "is_builtin BOOLEAN NOT NULL DEFAULT FALSE",
            "notified BOOLEAN NOT NULL DEFAULT FALSE",
            "silenced BOOLEAN NOT NULL DEFAULT FALSE",
            "enabled BOOLEAN NOT NULL DEFAULT TRUE",
        ] {
            assert!(normalized.contains(column), "布尔列映射缺失：{column}");
        }
        assert_eq!(
            POSTGRES_SCHEMA_DDL.matches("BIGSERIAL PRIMARY KEY").count(),
            9,
            "9 张表应有 BIGSERIAL 主键（5 张 SQLite AUTOINCREMENT + 4 张新增 id）"
        );
    }

    // ---- env 密码覆盖 ----------------------------------------------------
    //
    // 串行化所有会改动进程环境变量的测试，并在 guard drop 时还原原值。

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    struct PasswordEnvGuard {
        _lock: MutexGuard<'static, ()>,
        previous: Option<OsString>,
    }

    impl PasswordEnvGuard {
        fn set(value: Option<&OsStr>) -> Self {
            let lock = ENV_MUTEX
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let previous = std::env::var_os(super::super::PASSWORD_ENV);
            match value {
                Some(value) => std::env::set_var(super::super::PASSWORD_ENV, value),
                None => std::env::remove_var(super::super::PASSWORD_ENV),
            }
            Self {
                _lock: lock,
                previous,
            }
        }
    }

    impl Drop for PasswordEnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(super::super::PASSWORD_ENV, value),
                None => std::env::remove_var(super::super::PASSWORD_ENV),
            }
        }
    }

    /// env 覆盖优先级必须与 `PostgresStorage` 一致：非空 env > DSN 内密码。
    #[test]
    fn schema_config_env_password_matches_postgres_storage_priority() {
        const DSN_WITH_PW: &str =
            "postgres://rustboard:url-secret@127.0.0.1:1/rustboard?sslmode=disable";
        const DSN_WITHOUT_PW: &str = "postgres://rustboard@127.0.0.1:1/rustboard?sslmode=disable";

        {
            let _env = PasswordEnvGuard::set(None);
            assert_eq!(
                schema_config(DSN_WITH_PW).unwrap().get_password(),
                Some(b"url-secret".as_slice()),
                "无 env 时应保留 DSN 内密码"
            );
            assert_eq!(
                schema_config(DSN_WITHOUT_PW).unwrap().get_password(),
                None,
                "无 env 且 DSN 无密码时应保持无密码"
            );
        }

        {
            let _env = PasswordEnvGuard::set(Some(OsStr::new("")));
            assert_eq!(
                schema_config(DSN_WITH_PW).unwrap().get_password(),
                Some(b"url-secret".as_slice()),
                "空 env 视为未设置，不得覆盖 DSN 密码"
            );
        }

        {
            let _env = PasswordEnvGuard::set(Some(OsStr::new("env-secret")));
            assert_eq!(
                schema_config(DSN_WITH_PW).unwrap().get_password(),
                Some(b"env-secret".as_slice()),
                "非空 env 必须覆盖 DSN 内密码"
            );
            assert_eq!(
                schema_config(DSN_WITHOUT_PW).unwrap().get_password(),
                Some(b"env-secret".as_slice()),
                "DSN 无密码时 env 密码必须生效"
            );
        }
    }

    /// 非 UTF-8 env 必须 fail-closed，且错误信息不能带出密码内容。
    #[cfg(unix)]
    #[test]
    fn non_utf8_env_password_is_rejected_without_leaking() {
        use std::os::unix::ffi::OsStrExt;

        let _env = PasswordEnvGuard::set(Some(OsStr::from_bytes(b"topsecret\xff")));
        let err = schema_config("postgres://rustboard@127.0.0.1:1/rustboard?sslmode=disable")
            .expect_err("非 UTF-8 env 必须返回错误");
        let message = format!("{err:#}");
        assert!(
            message.contains(super::super::PASSWORD_ENV),
            "错误应指出环境变量名：{message}"
        );
        assert!(
            !message.contains("topsecret"),
            "错误信息泄露密码：{message}"
        );
    }
}
