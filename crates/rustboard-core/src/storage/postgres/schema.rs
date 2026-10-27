//! PostgreSQL schema v9：22 张业务表、索引与迁移入口。
//!
//! 这是 Phase D2 的落地：只负责「建表/索引 + 版本记录」，不实现任何
//! [`Storage`](crate::storage::Storage) 方法（D3 才做 `PostgresStorage`）。
//! 本模块也不处理 TLS 与连接池：D2 的迁移入口
//! [`connect_for_schema`] 只支持 `sslmode=disable`，供 `hub migrate` 前的
//! schema 初始化与测试使用；生产连接（verify-full + r2d2）在 D3/D4 接线。
//!
//! # 与 SQLite v9 的对应关系
//!
//! 基线是 `crates/rustboard-core/src/storage/sqlite.rs` 的 `SCHEMA_VERSION = 9`
//! （22 张表、23 个显式命名索引）。PG 使用独立的版本表，不复用
//! `PRAGMA user_version`：
//!
//! - `INTEGER`（时间戳/计数）→ `BIGINT`；
//! - `REAL` → `DOUBLE PRECISION`；
//! - JSON 列继续用 `TEXT`（序列化格式不变）；
//! - 布尔列 `alert_rules.enabled/notify_on_resolve/is_builtin`、
//!   `alert_events.notified/silenced`、`notification_channels.enabled`
//!   → `BOOLEAN`，读取层必须显式转换，不能沿用 SQLite 的 `i64` 假设；
//! - 自增主键 → `BIGSERIAL`；
//! - `alert_rules.revision` → `BIGINT NOT NULL DEFAULT 0`。
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
//! 这些 `id` 列只增加主键默认索引，不额外改变 SQLite 既有查询计划：23 个
//! 命名索引与 SQLite 一一对应。
//!
//! # 迁移策略
//!
//! [`apply_schema`] 在**单个事务**内完成：
//!
//! 1. 先取固定 key 的事务级 advisory lock，多实例同时启动时只有一个能迁移；
//! 2. 读 `schema_migrations` 最大版本：`> 9` 明确拒绝（防止旧二进制写坏新库）；
//! 3. 已是 9：只校验 22 张表与 23 个索引存在，然后提交（幂等、零 DDL）；
//! 4. 空库（没有任何已知业务表）：执行全部 `CREATE TABLE/INDEX IF NOT EXISTS`
//!    并写入 version 9；
//! 5. 版本 0 但已有业务表（半迁移/旧库），或版本 1..8：**fail closed**，
//!    不执行任何 DDL，提示 v1.0.0 只支持全新安装。
//! 6. 任何一步失败都回滚整个事务，不留半套表。
//!
//! `schema_migrations` 自身不算业务表：只有版本表、没有业务表的库仍按空库处理。

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use postgres::config::SslMode;
use postgres::NoTls;

/// PostgreSQL schema 版本；与 SQLite 的 `PRAGMA user_version = 9` 对齐。
pub const POSTGRES_SCHEMA_VERSION: i64 = 9;

/// schema 迁移的固定 advisory lock key（hex 语义：`RB` + `PG`）。
///
/// **固定不随 schema 版本变化**：所有历史版本与新二进制必须争用同一把锁，
/// 避免升级窗口内两个进程各自迁移；值中的 `0007` 是历史编码。
///
/// 事务级锁（`pg_advisory_xact_lock`）随事务提交/回滚自动释放，不需要
/// 显式 unlock；固定成常量以保证所有 hub 实例争用同一把锁。
pub const SCHEMA_ADVISORY_LOCK_KEY: i64 = 0x5242_5047_0000_0007;

/// 22 张业务表；用于迁移后、「已是 v9」与旧库判定的存在性校验。
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

/// SQLite v9 的 23 个显式命名索引；PG 侧名字与列顺序完全一致。
///
/// 主键/唯一约束产生的隐式索引（`*_pkey`、`*_key`、`*_unique`）不计入这里。
const INDEXES: [&str; 23] = [
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
    "idx_alert_rule_channels_channel",
    "idx_archive_objects_range",
    "idx_archive_objects_status",
    "idx_samples_unarchived",
    "idx_samples_unaggregated",
    "idx_samples_1m_unaggregated",
];

/// 版本表。SQLite 用 `PRAGMA user_version`，PG 独立维护，避免两套后端语义混淆。
const SCHEMA_MIGRATIONS_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    BIGINT PRIMARY KEY,
    applied_at BIGINT NOT NULL
);
"#;

/// v9 全量 DDL。
///
/// 全部 `IF NOT EXISTS`：空库与建表中途崩溃（事务回滚后）都能安全补齐；
/// 已存在表的数据不会被 DDL 触碰。v1.0.0 不再接受旧 schema，因此这里没有
/// 任何 `ALTER TABLE` 迁移分支。
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
    value    DOUBLE PRECISION NOT NULL,
    archive_object_id BIGINT,
    aggregated_1m BIGINT NOT NULL DEFAULT 0
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
    last_ts    BIGINT NOT NULL DEFAULT 0,
    aggregated_1h BIGINT NOT NULL DEFAULT 0,
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
    updated_at        BIGINT NOT NULL,
    revision          BIGINT NOT NULL DEFAULT 0
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

-- v9：规则→渠道关系表。JSON `channel_ids` 仅为 API 兼容保留；关系表以
-- 复合主键去重，规则删除级联清理，渠道仍被引用时由 RESTRICT 阻止删除。
CREATE TABLE IF NOT EXISTS alert_rule_channels (
    rule_id    TEXT NOT NULL,
    channel_id TEXT NOT NULL,
    PRIMARY KEY (rule_id, channel_id),
    -- 显式命名外键：P3/审计与运维脚本按稳定约束名映射，不依赖 PG 自动命名。
    CONSTRAINT alert_rule_channels_rule_id_fkey
        FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,
    CONSTRAINT alert_rule_channels_channel_id_fkey
        FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE RESTRICT
);
-- FK RESTRICT 检查按 channel_id 反查，没有索引会全表扫描。
CREATE INDEX IF NOT EXISTS idx_alert_rule_channels_channel
    ON alert_rule_channels(channel_id);

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
    deleted_at   BIGINT,
    ledger_version BIGINT NOT NULL DEFAULT 0,
    attempts     BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_archive_objects_range ON archive_objects(from_ts, to_ts);
CREATE INDEX IF NOT EXISTS idx_archive_objects_status ON archive_objects(status);

CREATE TABLE IF NOT EXISTS archive_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at BIGINT NOT NULL
);

-- v8 的 partial index：v9 全新库建表时列已存在，直接与建表同批创建。
CREATE INDEX IF NOT EXISTS idx_samples_unarchived ON samples(ts)
    WHERE archive_object_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_samples_unaggregated ON samples(ts)
    WHERE aggregated_1m = 0;
CREATE INDEX IF NOT EXISTS idx_samples_1m_unaggregated ON samples_1m(bucket_ts)
    WHERE aggregated_1h = 0;
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

/// 在给定连接上应用/校验 PostgreSQL schema v9。
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
    // 再看到 version=9 走纯校验路径，不会重复执行 DDL。
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
        // 已是 v9：只校验对象存在，不执行 DDL（幂等路径）。
        ensure_schema_objects(&mut tx)?;
        tx.commit().context("提交 PostgreSQL schema 校验事务失败")?;
        tracing::debug!(version = current, "PostgreSQL schema 已是最新，跳过迁移");
        return Ok(());
    }

    // v1.0.0 只支持全新安装：版本 0 且已有任何业务表（半迁移/旧库），
    // 或版本 1..8，一律 fail closed，不执行任何 DDL。`schema_migrations`
    // 自身不算业务表，因此「只有版本表、没有业务表」仍按空库处理。
    if current > 0 {
        bail_old_schema(current)?;
    }
    if any_business_table_exists(&mut tx)? {
        bail_old_schema(0)?;
    }

    // 真正的空库：全部 IF NOT EXISTS，校验后写入 version 9。
    tx.batch_execute(POSTGRES_SCHEMA_DDL)
        .context("执行 PostgreSQL schema v9 DDL 失败")?;
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
        "PostgreSQL schema v9 已创建"
    );
    Ok(())
}

/// 旧 schema 的 fail-closed 错误；文案与 SQLite 保持一致，便于测试与排障。
///
/// `pub(crate)`：迁移目标预检也要在 `--force` 清空/导入前复用同一文案与判定。
pub(crate) fn bail_old_schema(version: i64) -> Result<()> {
    bail!(
        "检测到已有数据库 schema v{version}：v1.0.0 只支持全新安装，\
         不执行任何旧 schema 升级或数据回填；旧数据兼容将在首个正式版本之后提供。\
         请先备份该数据库，再按全新安装部署（本程序不会修改旧库）"
    )
}

/// 当前 schema 中是否存在任一已知业务表（`schema_migrations` 不算）。
pub(crate) fn any_business_table_exists(tx: &mut postgres::Transaction<'_>) -> Result<bool> {
    let business_tables: Vec<String> = TABLES.iter().map(|table| (*table).to_string()).collect();
    let exists: bool = tx
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM information_schema.tables
                 WHERE table_schema = current_schema()
                   AND table_name = ANY($1)
             )",
            &[&business_tables],
        )
        .context("检查 PostgreSQL 是否已有业务表失败")?
        .get(0);
    Ok(exists)
}

/// 校验 22 张业务表与 23 个命名索引都已存在。
///
/// 只查目录表，不锁表、不触碰数据；在迁移事务内调用，失败会连同 DDL 一起回滚。
/// `pub(crate)`：迁移目标预检在清空/导入前校验目标确实具完整的 v9 对象。
pub(crate) fn ensure_schema_objects(tx: &mut postgres::Transaction<'_>) -> Result<()> {
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

    /// 表/索引清单必须与 SQLite v9 基线一一对应，防止后续改 DDL 时漏项。
    #[test]
    fn table_and_index_lists_are_distinct_and_match_baseline() {
        assert_eq!(TABLES.len(), 22);
        assert_eq!(INDEXES.len(), 23);

        let mut tables = TABLES.to_vec();
        tables.sort_unstable();
        tables.dedup();
        assert_eq!(tables.len(), 22, "TABLES 有重复项");

        let mut indexes = INDEXES.to_vec();
        indexes.sort_unstable();
        indexes.dedup();
        assert_eq!(indexes.len(), 23, "INDEXES 有重复项");
    }

    /// 版本号固定 9；advisory lock 固定且不随版本变化。
    #[test]
    fn version_and_lock_key_are_stable() {
        assert_eq!(POSTGRES_SCHEMA_VERSION, 9);
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
        // 索引声明可能换行（如 idx_alert_rule_channels_channel），比较前折叠空白。
        let normalized_ddl = POSTGRES_SCHEMA_DDL
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for index in INDEXES {
            assert!(
                normalized_ddl.contains(&format!("CREATE INDEX IF NOT EXISTS {index} ON ")),
                "DDL 缺少索引 {index}"
            );
        }
        for column in [
            "archive_object_id BIGINT",
            "aggregated_1m BIGINT NOT NULL DEFAULT 0",
            "last_ts BIGINT NOT NULL DEFAULT 0",
            "aggregated_1h BIGINT NOT NULL DEFAULT 0",
            "ledger_version BIGINT NOT NULL DEFAULT 0",
            "attempts BIGINT NOT NULL DEFAULT 0",
            "revision BIGINT NOT NULL DEFAULT 0",
        ] {
            assert!(normalized_ddl.contains(column), "DDL 缺少列定义：{column}");
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

    /// P3 映射依赖稳定的外键约束名，不能依赖 PostgreSQL 自动命名。
    #[test]
    fn alert_rule_channels_foreign_keys_are_explicitly_named() {
        for name in [
            "alert_rule_channels_rule_id_fkey",
            "alert_rule_channels_channel_id_fkey",
        ] {
            assert!(
                POSTGRES_SCHEMA_DDL.contains(name),
                "DDL 缺少显式外键名 {name}"
            );
        }
    }
}
