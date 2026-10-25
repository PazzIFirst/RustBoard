//! PostgreSQL Admin 域：审计、维护水位与管理 API scoped token。
//!
//! 本文件只写 [`PostgresStorage`] 的**固有方法**，签名与
//! [`Storage`](crate::storage::Storage) trait 中对应方法逐字一致；统一
//! `impl Storage for PostgresStorage` 由最后的转发层一次性补齐。
//!
//! 行为对照 `sqlite.rs`：
//!
//! - `audit_log.id` 用 `BIGSERIAL` 自增，`list_audit` 按 `id DESC` 分页，
//!   `before_id` 是排他游标（`id < before_id`）；agent / capability 过滤可叠加；
//!   `params` 与错误字段原样存取，写入前按 [`MAX_AUDIT_PARAMS_BYTES`] 截断；
//! - 审计保留期与 SQLite 相同：每 1000 条成功写入清理一次 180 天前的记录，
//!   绝不对每一行执行全表 `DELETE`；
//! - `maintenance_state` 用 `ON CONFLICT (key) DO UPDATE` 覆盖写，按 key 升序
//!   （显式 `COLLATE "C"`，与 SQLite 的 BINARY 顺序一致）；
//! - `api_tokens` 只存调用方给的 SHA-256 hex，绝不存明文；唯一约束冲突映射为
//!   与 SQLite 一致的领域错误，错误/日志不输出 hash、明文或 DSN；
//! - `authenticate_api_token` 只返回未吊销行；`last_used_at` 60 秒节流与
//!   SQLite 的 `now - last >= 60000` 等价，并通过条件 `UPDATE` 在并发下仍只
//!   做统计性写入。
//!
//! 所有值参数都用 `$N` 绑定；时间/计数为 `BIGINT`（Rust `i64`），唯一布尔
//! 语义由 SQL 条件表达，不沿用 SQLite 的整数约定。
//!
//! 所有方法都通过 [`PostgresStorage::with_client`] 取连接；调用方必须位于
//! blocking 线程（spike §4：tokio worker 内直接调用同步 PG 会 panic）。

use std::sync::atomic::Ordering;

use anyhow::{anyhow, bail, Context, Result};
use postgres::error::SqlState;
use postgres::types::ToSql;
use postgres::Row;
use rustboard_common::util::now_ms;

use super::PostgresStorage;
use crate::storage::{
    ApiTokenRecord, AuditEntry, MaintenanceStateEntry, NewAuditEntry, AUDIT_RETENTION_MS,
};

/// 与 SQLite 一致：每这么多次成功写入清理一次 180 天前的审计记录。
const AUDIT_CLEANUP_EVERY: u64 = 1_000;

/// 与 SQLite 一致：审计 `params` 的存储上限（字节）。
const MAX_AUDIT_PARAMS_BYTES: usize = 1_024;

/// 与 SQLite 一致：`last_used_at` 的写入节流窗口（60 秒）。
const API_TOKEN_LAST_USED_THROTTLE_MS: i64 = 60_000;

/// 允许的 scope 字符串；与 `api_tokens.scope` 的 CHECK 约束保持一致。
const API_TOKEN_SCOPES: [&str; 3] = ["read", "write", "admin"];

/// `api_tokens` 的 SELECT 列表；列顺序必须与 [`api_token_from_row`] 一致。
const API_TOKEN_COLUMNS: &str = "id, name, scope, created_at, last_used_at, revoked_at";

impl PostgresStorage {
    // ---- M3 审计 ----

    /// 写入一条审计记录，返回自增 id。
    ///
    /// `params` 在落库前按字节截断到 [`MAX_AUDIT_PARAMS_BYTES`]（不切坏
    /// UTF-8）；每 1000 条成功写入后按 [`AUDIT_RETENTION_MS`] 清理一次过期
    /// 记录，清理失败只记日志，不影响本次写入结果（与 SQLite 一致）。
    pub fn insert_audit(&self, entry: &NewAuditEntry) -> Result<i64> {
        // 最后防线：调用方已限长，这里再夹一次，避免异常调用撑大数据库。
        let params = truncate_utf8(&entry.params, MAX_AUDIT_PARAMS_BYTES);
        self.with_client(|client| {
            let id: i64 = client
                .query_one(
                    "INSERT INTO audit_log
                        (ts, actor, agent_id, capability, action, target, params, result,
                         error_code, error_message, duration_ms)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                     RETURNING id",
                    &[
                        &entry.ts,
                        &entry.actor,
                        &entry.agent_id,
                        &entry.capability,
                        &entry.action,
                        &entry.target,
                        &params,
                        &entry.result,
                        &entry.error_code,
                        &entry.error_message,
                        &entry.duration_ms,
                    ],
                )
                .context("执行 insert_audit SQL 失败")?
                .get(0);

            // 每 1000 条成功写入清理一次 180 天前的记录，避免每条都 DELETE。
            // 计数器属于当前 storage 实例，多实例互不叠加。
            let written = self.audit_writes.fetch_add(1, Ordering::Relaxed) + 1;
            if written.is_multiple_of(AUDIT_CLEANUP_EVERY) {
                prune_expired_audit(client);
            }
            Ok(id)
        })
        .context("insert_audit")
    }

    /// 按 id 倒序分页查询审计；`before_id` 为**排他**游标（`id < before_id`）。
    ///
    /// `agent_id` / `capability` 可叠加过滤；`limit == 0` 直接返回空列表，
    /// 不访问数据库（与 SQLite 一致）。
    pub fn list_audit(
        &self,
        limit: usize,
        before_id: Option<i64>,
        agent_id: Option<&str>,
        capability: Option<&str>,
    ) -> Result<Vec<AuditEntry>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        self.with_client(|client| {
            let mut sql = String::from(
                "SELECT id, ts, actor, agent_id, capability, action, target, params, result,
                        error_code, error_message, duration_ms
                 FROM audit_log WHERE 1 = 1",
            );
            let mut params: Vec<&(dyn ToSql + Sync)> = Vec::new();
            if let Some(before_id) = before_id.as_ref() {
                sql.push_str(&format!(" AND id < ${}", params.len() + 1));
                params.push(before_id);
            }
            if let Some(agent_id) = agent_id.as_ref() {
                sql.push_str(&format!(" AND agent_id = ${}", params.len() + 1));
                params.push(agent_id);
            }
            if let Some(capability) = capability.as_ref() {
                sql.push_str(&format!(" AND capability = ${}", params.len() + 1));
                params.push(capability);
            }
            sql.push_str(&format!(" ORDER BY id DESC LIMIT ${}", params.len() + 1));
            params.push(&limit);

            let rows = client
                .query(&sql, &params)
                .context("执行 list_audit SQL 失败")?;
            Ok(rows.iter().map(audit_entry_from_row).collect())
        })
        .context("list_audit")
    }

    /// 删除 `ts < before_ts` 的审计记录，返回删除行数。
    pub fn prune_audit(&self, before_ts: i64) -> Result<usize> {
        let removed = self
            .with_client(|client| {
                client
                    .execute("DELETE FROM audit_log WHERE ts < $1", &[&before_ts])
                    .context("执行 prune_audit SQL 失败")
            })
            .context("prune_audit")?;
        usize::try_from(removed).context("prune_audit 返回了超出 usize 的行数")
    }

    // ---- M4 维护水位 ----

    /// 读取维护水位；key 不存在返回 `None`。
    pub fn get_maintenance_state(&self, key: &str) -> Result<Option<String>> {
        self.with_client(|client| {
            let value: Option<String> = client
                .query_opt(
                    "SELECT value FROM maintenance_state WHERE key = $1",
                    &[&key],
                )
                .context("执行 get_maintenance_state SQL 失败")?
                .map(|row| row.get(0));
            Ok(value)
        })
        .context("get_maintenance_state")
    }

    /// 覆盖写入维护水位：不存在则插入，已存在则刷新 value 与 updated_at。
    pub fn set_maintenance_state(&self, key: &str, value: &str, updated_at: i64) -> Result<()> {
        self.with_client(|client| {
            client
                .execute(
                    "INSERT INTO maintenance_state (key, value, updated_at)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (key) DO UPDATE SET
                         value = EXCLUDED.value,
                         updated_at = EXCLUDED.updated_at",
                    &[&key, &value, &updated_at],
                )
                .context("执行 set_maintenance_state SQL 失败")?;
            Ok(())
        })
        .context("set_maintenance_state")
    }

    /// 列出全部维护水位，按 key 升序（`COLLATE "C"` 对齐 SQLite BINARY）。
    pub fn list_maintenance_state(&self) -> Result<Vec<MaintenanceStateEntry>> {
        self.with_client(|client| {
            let rows = client
                .query(
                    "SELECT key, value, updated_at FROM maintenance_state
                     ORDER BY key COLLATE \"C\" ASC",
                    &[],
                )
                .context("执行 list_maintenance_state SQL 失败")?;
            Ok(rows
                .iter()
                .map(|row| MaintenanceStateEntry {
                    key: row.get(0),
                    value: row.get(1),
                    updated_at: row.get(2),
                })
                .collect())
        })
        .context("list_maintenance_state")
    }

    // ---- M6 管理 API scoped token ----

    /// 新建 scoped token（只存哈希）；重名或非法 scope 在落库前拒绝。
    ///
    /// `token_hash` 应是明文的 SHA-256 hex；存储层不接触明文。返回的
    /// [`ApiTokenRecord`] 不含哈希或明文。
    pub fn create_api_token(
        &self,
        name: &str,
        token_hash: &str,
        scope: &str,
        created_at: i64,
    ) -> Result<ApiTokenRecord> {
        if !API_TOKEN_SCOPES.contains(&scope) {
            bail!("非法 token scope: {scope}（只允许 read / write / admin）");
        }
        self.with_client(|client| {
            let id: i64 = client
                .query_one(
                    "INSERT INTO api_tokens (name, token_hash, scope, created_at)
                     VALUES ($1, $2, $3, $4)
                     RETURNING id",
                    &[&name, &token_hash, &scope, &created_at],
                )
                .map_err(|err| map_api_token_db_error(err, name, Some(scope)))?
                .get(0);
            Ok(ApiTokenRecord {
                id,
                name: name.to_string(),
                scope: scope.to_string(),
                created_at,
                last_used_at: None,
                revoked_at: None,
            })
        })
        .context("create_api_token")
    }

    /// 按 name 升序列出全部 token（含已吊销），不返回哈希或明文。
    pub fn list_api_tokens(&self) -> Result<Vec<ApiTokenRecord>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {API_TOKEN_COLUMNS} FROM api_tokens ORDER BY name COLLATE \"C\" ASC"
            );
            let rows = client
                .query(&sql, &[])
                .context("执行 list_api_tokens SQL 失败")?;
            Ok(rows.iter().map(api_token_from_row).collect())
        })
        .context("list_api_tokens")
    }

    /// 轮换 token：同一行写入新哈希、清 `revoked_at`，旧哈希立即失效。
    ///
    /// 新凭据的 `created_at` 记为本次轮换时间，`last_used_at` 清空（新凭据尚未
    /// 使用）；name / scope / id 不变，因此审计 actor 保持稳定。单条
    /// `UPDATE ... RETURNING` 保证失败（如哈希冲突）时原记录不变。
    pub fn rotate_api_token(
        &self,
        name: &str,
        token_hash: &str,
        now: i64,
    ) -> Result<ApiTokenRecord> {
        self.with_client(|client| {
            let sql = format!(
                "UPDATE api_tokens
                 SET token_hash = $2, created_at = $3, last_used_at = NULL, revoked_at = NULL
                 WHERE name = $1
                 RETURNING {API_TOKEN_COLUMNS}"
            );
            let row = client
                .query_opt(&sql, &[&name, &token_hash, &now])
                .map_err(|err| map_api_token_db_error(err, name, None))?;
            let Some(row) = row else {
                bail!("token 不存在: {name}");
            };
            Ok(api_token_from_row(&row))
        })
        .context("rotate_api_token")
    }

    /// 吊销 token：只写 `revoked_at`，不删行。
    ///
    /// 不存在与已吊销是两种不同的可读错误；重复吊销不会刷新时间戳。
    pub fn revoke_api_token(&self, name: &str, now: i64) -> Result<()> {
        self.with_client(|client| {
            let mut tx = client
                .transaction()
                .context("开启 revoke_api_token 事务失败")?;
            let updated = tx
                .execute(
                    "UPDATE api_tokens SET revoked_at = $2
                     WHERE name = $1 AND revoked_at IS NULL",
                    &[&name, &now],
                )
                .context("执行 revoke_api_token SQL 失败")?;
            if updated == 0 {
                let exists: bool = tx
                    .query_one(
                        "SELECT EXISTS(SELECT 1 FROM api_tokens WHERE name = $1)",
                        &[&name],
                    )
                    .context("检查 token 是否存在失败")?
                    .get(0);
                // 返回 Err 时事务随 Drop 回滚，不会留下半写状态。
                return Err(if exists {
                    anyhow!("token 已吊销: {name}")
                } else {
                    anyhow!("token 不存在: {name}")
                });
            }
            tx.commit().context("提交 revoke_api_token 事务失败")?;
            Ok(())
        })
        .context("revoke_api_token")
    }

    /// 鉴权：只返回未吊销行，并 best-effort 更新 `last_used_at`。
    ///
    /// - 60s 节流与 SQLite 等价：`now - last >= 60000` 时才写；首次必写。
    /// - 条件 `UPDATE ... (last_used_at IS NULL OR last_used_at <= $cutoff)`
    ///   让并发请求最多多写一次统计值，不会重复写。
    /// - 更新失败只记 debug，不影响本次鉴权结果（读路径已完成）。
    /// - 若更新影响 0 行，可能是并发吊销，也可能是另一个请求刚刷新了
    ///   `last_used_at`：重读一次；已吊销则按未认证处理（安全默认拒绝）。
    pub fn authenticate_api_token(
        &self,
        token_hash: &str,
        now: i64,
    ) -> Result<Option<ApiTokenRecord>> {
        self.with_client(|client| {
            let sql = format!(
                "SELECT {API_TOKEN_COLUMNS} FROM api_tokens
                 WHERE token_hash = $1 AND revoked_at IS NULL"
            );
            let record: Option<ApiTokenRecord> = client
                .query_opt(&sql, &[&token_hash])
                .context("执行 authenticate_api_token 查询失败")?
                .map(|row| api_token_from_row(&row));
            let Some(mut record) = record else {
                return Ok(None);
            };

            let should_touch = record
                .last_used_at
                .map(|last| now.saturating_sub(last) >= API_TOKEN_LAST_USED_THROTTLE_MS)
                .unwrap_or(true);
            if should_touch {
                // `now - 60000` 用 i64 减法；极端时用 saturating 防止溢出。
                let cutoff = now.saturating_sub(API_TOKEN_LAST_USED_THROTTLE_MS);
                let updated = client.execute(
                    "UPDATE api_tokens SET last_used_at = $2
                     WHERE token_hash = $1 AND revoked_at IS NULL
                       AND (last_used_at IS NULL OR last_used_at <= $3)",
                    &[&token_hash, &now, &cutoff],
                );
                match updated {
                    Ok(0) => {
                        // 并发吊销或并发刷新：重读一次再决定；绝不因统计写入
                        // 失败而误放行已吊销 token。
                        let current: Option<ApiTokenRecord> = client
                            .query_opt(&sql, &[&token_hash])
                            .context("并发更新后重读 token 失败")?
                            .map(|row| api_token_from_row(&row));
                        return Ok(current);
                    }
                    Ok(_) => record.last_used_at = Some(now),
                    Err(err) => {
                        // 鉴权已成功，last_used_at 只是统计信息，绝不能因此拒绝请求。
                        // 日志只带 SQLSTATE，不输出哈希/明文。
                        let sqlstate = err.as_db_error().map(|db_error| db_error.code().code());
                        tracing::debug!(
                            token = %record.name,
                            sqlstate = sqlstate.unwrap_or("-"),
                            "更新 token last_used_at 失败"
                        );
                    }
                }
            }
            Ok(Some(record))
        })
        .context("authenticate_api_token")
    }
}

/// 每 1000 条审计写入触发的保留期清理。
///
/// 清理失败只记 warning，不影响已经提交的审计写入（与 SQLite 一致）。
fn prune_expired_audit(client: &mut postgres::Client) {
    let cutoff = now_ms().saturating_sub(AUDIT_RETENTION_MS);
    match client.execute("DELETE FROM audit_log WHERE ts < $1", &[&cutoff]) {
        Ok(removed) if removed > 0 => {
            tracing::info!(removed, cutoff, "已清理过期审计记录");
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(error = %err, "清理过期审计记录失败"),
    }
}

/// 把 `api_tokens` 的一行映射成记录；列顺序与 [`API_TOKEN_COLUMNS`] 一致。
fn api_token_from_row(row: &Row) -> ApiTokenRecord {
    ApiTokenRecord {
        id: row.get(0),
        name: row.get(1),
        scope: row.get(2),
        created_at: row.get(3),
        last_used_at: row.get(4),
        revoked_at: row.get(5),
    }
}

/// 把 `audit_log` 的一行映射成记录；列顺序与 `list_audit` 的 SELECT 一致。
fn audit_entry_from_row(row: &Row) -> AuditEntry {
    AuditEntry {
        id: row.get(0),
        ts: row.get(1),
        actor: row.get(2),
        agent_id: row.get(3),
        capability: row.get(4),
        action: row.get(5),
        target: row.get(6),
        params: row.get(7),
        result: row.get(8),
        error_code: row.get(9),
        error_message: row.get(10),
        duration_ms: row.get(11),
    }
}

/// 把 token 写入的数据库错误翻译成与 SQLite 一致的领域错误。
///
/// 只检查约束名 / SQLSTATE，**不**透传 `detail()`（PG 的 detail 会包含重复
/// 键值，其中 hash 冲突时正是 token_hash），也不把原始 SQL 或 DSN 放进错误。
fn map_api_token_db_error(err: postgres::Error, name: &str, scope: Option<&str>) -> anyhow::Error {
    if let Some(db_error) = err.as_db_error() {
        let constraint = db_error.constraint().unwrap_or("");
        // 约束名由 schema DDL 的 UNIQUE 自动生成；同时用 message 兜底，避免
        // 手工改过约束名的库把错误落到不透明的兜底分支。
        let message = db_error.message();
        if db_error.code() == &SqlState::UNIQUE_VIOLATION {
            if constraint.contains("token_hash") || message.contains("api_tokens_token_hash_key") {
                return anyhow!("token 哈希冲突，请重新生成 token");
            }
            if constraint.contains("name") || message.contains("api_tokens_name_key") {
                return anyhow!("token 名称已存在: {name}");
            }
        }
        if db_error.code() == &SqlState::CHECK_VIOLATION {
            let scope = scope.unwrap_or("<unknown>");
            return anyhow!("非法 token scope: {scope}（只允许 read / write / admin）");
        }
        // 只记录 SQLSTATE 与约束名：不记录 detail / 参数值，避免 hash 落日志。
        tracing::debug!(
            sqlstate = db_error.code().code(),
            constraint,
            "创建/轮换 token 失败（非领域错误）"
        );
    } else {
        tracing::debug!("创建/轮换 token 失败（非数据库错误）");
    }
    // 兜底不透传原始 PG 错误（可能含重复键 detail / SQL / 连接信息）。
    anyhow!("创建/轮换 token 失败: {name}（数据库错误，详见日志）")
}

/// 按字节截断 UTF-8 字符串，保证不会切出半个字符（与 SQLite 同语义）。
fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::Context;
    use postgres::config::SslMode;
    use postgres::NoTls;
    use rustboard_common::tls::sha256_hex;
    use rustboard_common::util::now_ms;

    use super::super::schema::{apply_schema, connect_for_schema};
    use super::super::{PostgresOptions, PostgresStorage};
    use super::{API_TOKEN_LAST_USED_THROTTLE_MS, AUDIT_CLEANUP_EVERY, MAX_AUDIT_PARAMS_BYTES};
    use crate::storage::{MaintenanceStateEntry, NewAuditEntry, AUDIT_RETENTION_MS};

    /// 实库测试 DSN 的环境变量；未设置时全部 Admin 用例 skip。
    const PG_ENV: &str = "RUSTBOARD_TEST_PG";

    /// 每次调用返回递增序号，避免同一纳秒内两个用例撞库名。
    static DB_SEQ: AtomicU64 = AtomicU64::new(0);

    fn skip(test_name: &str) {
        eprintln!("SKIP {test_name}: 未设置 {PG_ENV}（D3 Admin 实库测试需要 PostgreSQL）");
    }

    /// 解析 `RUSTBOARD_TEST_PG`；未设置或空串时返回 `None`。
    fn test_dsn() -> Option<String> {
        let dsn = std::env::var(PG_ENV).ok()?;
        if dsn.trim().is_empty() {
            return None;
        }
        let config: postgres::Config = dsn
            .parse()
            .unwrap_or_else(|err| panic!("{PG_ENV} 解析失败：{err}"));
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
        /// 指向测试库的 URL DSN。
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
            let name = format!("rb_d3_admin_{tag}_{}_{nanos}_{seq}", std::process::id());
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
                .unwrap_or_else(|err| panic!("{PG_ENV} 解析失败：{err}"));
            let mut admin = base.clone();
            admin.dbname("postgres");
            let mut admin_client = admin.connect(NoTls).unwrap_or_else(|err| {
                panic!("连接 postgres 维护库失败（检查 {PG_ENV} 与容器）：{err}")
            });
            admin_client
                .batch_execute(&format!("CREATE DATABASE {name}"))
                .unwrap_or_else(|err| {
                    panic!("CREATE DATABASE {name} 失败（角色需要 CREATEDB 权限）：{err}")
                });
            drop(admin_client);

            let app_dsn = dsn_with_database(&dsn, &name);
            eprintln!("[d3-admin] 创建测试数据库 {name}（tag={tag}）");
            Some(Self {
                name,
                admin,
                app_dsn,
            })
        }

        /// 应用 schema v7 并打开 `PostgresStorage`（在 tokio runtime 外的测试线程）。
        fn open_storage(&self) -> PostgresStorage {
            let mut client = connect_for_schema(&self.app_dsn)
                .unwrap_or_else(|err| panic!("schema 连接失败（{}）：{err:#}", self.name));
            apply_schema(&mut client).unwrap_or_else(|err| panic!("apply_schema 失败：{err:#}"));
            drop(client);

            PostgresStorage::open(PostgresOptions {
                dsn: self.app_dsn.clone(),
                pool_size: 2,
                connect_timeout: Duration::from_secs(5),
                statement_timeout: Duration::from_secs(10),
                sslrootcert: None,
            })
            .unwrap_or_else(|err| panic!("打开 PostgresStorage 失败：{err:#}"))
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            let mut client = match self.admin.connect(NoTls) {
                Ok(client) => client,
                Err(err) => {
                    eprintln!(
                        "[d3-admin] 清理失败：无法连接维护库删除 {}（请手工 DROP）：{err}",
                        self.name
                    );
                    return;
                }
            };
            if let Err(err) = client.batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            )) {
                eprintln!(
                    "[d3-admin] 清理失败：DROP DATABASE {} 出错（请手工清理）：{err}",
                    self.name
                );
            }
        }
    }

    fn audit_entry(agent_id: &str, capability: &str, action: &str, ts: i64) -> NewAuditEntry {
        NewAuditEntry {
            ts,
            actor: "admin".into(),
            agent_id: agent_id.into(),
            capability: capability.into(),
            action: action.into(),
            target: "nginx.service".into(),
            params: "{\"target\":\"nginx.service\"}".into(),
            result: "ok".into(),
            error_code: String::new(),
            error_message: String::new(),
            duration_ms: 12,
        }
    }

    /// 审计分页（id 倒序 + 排他游标）、过滤叠加、字段原样与显式清理。
    #[test]
    fn audit_pagination_filters_and_prune() {
        const NAME: &str = "audit_pagination_filters_and_prune";
        let Some(db) = TestDatabase::create("audit") else {
            skip(NAME);
            return;
        };
        let storage = db.open_storage();

        // ts 用「当前时间 + 偏移」：即使并发测试触发保留期清理，也不会被当成
        // 180 天前的旧记录删掉（id 才是分页游标）。
        let now = now_ms();
        let first = storage
            .insert_audit(&audit_entry("a1", "systemd", "list", now))
            .unwrap();
        let second = storage
            .insert_audit(&audit_entry("a1", "systemd", "restart", now + 1))
            .unwrap();
        let third = storage
            .insert_audit(&audit_entry("b2", "docker", "list", now + 2))
            .unwrap();
        let fourth = storage
            .insert_audit(&audit_entry("b2", "docker", "restart", now + 3))
            .unwrap();
        assert!(
            first < second && second < third && third < fourth,
            "audit id 必须自增：{first} {second} {third} {fourth}"
        );

        // 按 id 倒序 + limit。
        let page = storage.list_audit(2, None, None, None).unwrap();
        assert_eq!(
            page.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![fourth, third]
        );

        // before_id 为排他游标。
        let page = storage.list_audit(2, Some(third), None, None).unwrap();
        assert_eq!(
            page.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![second, first]
        );
        assert!(storage
            .list_audit(10, Some(first), None, None)
            .unwrap()
            .is_empty());

        // agent / capability 过滤可以叠加。
        let only_a1 = storage.list_audit(10, None, Some("a1"), None).unwrap();
        assert_eq!(
            only_a1.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![second, first]
        );
        let only_docker = storage.list_audit(10, None, None, Some("docker")).unwrap();
        assert_eq!(
            only_docker.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![fourth, third]
        );
        let combined = storage
            .list_audit(10, Some(fourth), Some("a1"), Some("systemd"))
            .unwrap();
        assert_eq!(
            combined.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![second, first]
        );
        assert!(storage.list_audit(0, None, None, None).unwrap().is_empty());

        // 字段完整落库。
        let entry = &storage.list_audit(1, None, None, None).unwrap()[0];
        assert_eq!(entry.actor, "admin");
        assert_eq!(entry.agent_id, "b2");
        assert_eq!(entry.capability, "docker");
        assert_eq!(entry.action, "restart");
        assert_eq!(entry.target, "nginx.service");
        assert_eq!(entry.params, "{\"target\":\"nginx.service\"}");
        assert_eq!(entry.result, "ok");
        assert_eq!(entry.duration_ms, 12);
        assert_eq!(entry.ts, now + 3);

        // 显式清理：只删除 ts < cutoff 的行。
        let cutoff = now + 2;
        assert_eq!(storage.prune_audit(cutoff).unwrap(), 2);
        let left = storage.list_audit(10, None, None, None).unwrap();
        assert_eq!(
            left.iter().map(|entry| entry.id).collect::<Vec<_>>(),
            vec![fourth, third]
        );
        assert_eq!(storage.prune_audit(cutoff).unwrap(), 0);
    }

    /// `params` 按 1024 字节截断且不切坏 UTF-8；错误字段原样往返。
    #[test]
    fn audit_truncates_params_and_preserves_error_fields() {
        const NAME: &str = "audit_truncates_params_and_preserves_error_fields";
        let Some(db) = TestDatabase::create("audit_trunc") else {
            skip(NAME);
            return;
        };
        let storage = db.open_storage();

        let now = now_ms();
        let long_params = "目".repeat(400); // 1200 字节，超过 1024 上限
        let mut entry = audit_entry("a1", "logs", "tail", now);
        entry.params = long_params;
        entry.result = "error".into();
        entry.error_code = "E_TIMEOUT".into();
        entry.error_message = "读取日志超时".into();
        entry.duration_ms = 1_234;
        storage.insert_audit(&entry).unwrap();

        let stored = &storage.list_audit(1, None, None, None).unwrap()[0];
        assert!(
            stored.params.len() <= MAX_AUDIT_PARAMS_BYTES,
            "params 必须截断到 {MAX_AUDIT_PARAMS_BYTES} 字节以内，实际 {}",
            stored.params.len()
        );
        assert_eq!(
            stored.params,
            "目".repeat(341),
            "截断必须按 UTF-8 字符边界回退，不能切出半个字符"
        );
        assert_eq!(stored.result, "error");
        assert_eq!(stored.error_code, "E_TIMEOUT");
        assert_eq!(stored.error_message, "读取日志超时");
        assert_eq!(stored.duration_ms, 1_234);

        // 未超限的 params 原样保存（不做无关规范化）。
        let short = "{\"target\":\"nginx.service\"}";
        let mut entry = audit_entry("a1", "systemd", "status", now + 1);
        entry.params = short.into();
        storage.insert_audit(&entry).unwrap();
        let stored = &storage.list_audit(1, None, None, None).unwrap()[0];
        assert_eq!(stored.params, short);
    }

    /// 每 1000 条成功写入触发一次 180 天保留期清理，且不是每条都 DELETE。
    #[test]
    fn audit_auto_prunes_every_thousand_writes() {
        const NAME: &str = "audit_auto_prunes_every_thousand_writes";
        let Some(db) = TestDatabase::create("audit_prune") else {
            skip(NAME);
            return;
        };
        let storage = db.open_storage();

        let now = now_ms();
        let stale_ts = now - AUDIT_RETENTION_MS - 1;
        storage
            .insert_audit(&audit_entry("a1", "systemd", "list", stale_ts))
            .unwrap();

        // 再写 1000 条：计数器从本实例的 0 开始，第 1000 次写入恰好触发
        // 本库的保留期清理。
        for _ in 0..AUDIT_CLEANUP_EVERY {
            storage
                .insert_audit(&audit_entry("a1", "systemd", "list", now))
                .unwrap();
        }

        let rows = storage.list_audit(2_000, None, None, None).unwrap();
        assert!(
            rows.iter().all(|entry| entry.ts > stale_ts),
            "180 天前的审计必须被自动清理"
        );
        assert_eq!(rows.len(), 1_000, "新写入的审计必须全部保留");
    }

    /// 审计计数器是 per-storage：两个实例各自计数，合计到 1000 不会触发
    /// 清理；只有某个实例自己写满 1000 条才触发。
    #[test]
    fn audit_cleanup_counter_is_per_storage_instance() {
        const NAME: &str = "audit_cleanup_counter_is_per_storage_instance";
        let Some(db) = TestDatabase::create("audit_per_storage") else {
            skip(NAME);
            return;
        };
        let first = db.open_storage();
        let second = db.open_storage();

        let now = now_ms();
        let stale_ts = now - AUDIT_RETENTION_MS - 1;
        first
            .insert_audit(&audit_entry("a1", "systemd", "list", stale_ts))
            .unwrap();
        // 合计写满 1000 条，但两个实例各自都未到 1000。
        for _ in 1..600 {
            first
                .insert_audit(&audit_entry("a1", "systemd", "list", now))
                .unwrap();
        }
        for _ in 0..400 {
            second
                .insert_audit(&audit_entry("a1", "systemd", "list", now))
                .unwrap();
        }
        assert!(
            second
                .list_audit(2_000, None, None, None)
                .unwrap()
                .iter()
                .any(|entry| entry.ts == stale_ts),
            "合计 1000 条但单实例未到阈值时，不得触发保留期清理"
        );

        // first 自己写满 1000 条：只清理 first 触发的这一轮。
        for _ in 0..400 {
            first
                .insert_audit(&audit_entry("a1", "systemd", "list", now))
                .unwrap();
        }
        assert!(
            second
                .list_audit(2_000, None, None, None)
                .unwrap()
                .iter()
                .all(|entry| entry.ts > stale_ts),
            "单实例达到 1000 条后必须清理 180 天前的审计"
        );
    }

    /// maintenance_state：缺失返回 None；UPSERT 覆盖；list 按 key 升序；
    /// 引号 / SQL 片段按字面量存取（参数化）。
    #[test]
    fn maintenance_state_upsert_list_and_none() {
        const NAME: &str = "maintenance_state_upsert_list_and_none";
        let Some(db) = TestDatabase::create("maint") else {
            skip(NAME);
            return;
        };
        let storage = db.open_storage();
        assert_eq!(
            storage.get_maintenance_state("last_archived_ts").unwrap(),
            None
        );

        storage
            .set_maintenance_state("last_archived_ts", "100", 1_000)
            .unwrap();
        storage
            .set_maintenance_state("last_downsample_ts", "50", 900)
            .unwrap();
        assert_eq!(
            storage.get_maintenance_state("last_archived_ts").unwrap(),
            Some("100".to_string())
        );

        // 覆盖写：同一 key 不新增行，value 与 updated_at 刷新。
        storage
            .set_maintenance_state("last_archived_ts", "200", 2_000)
            .unwrap();
        assert_eq!(
            storage.list_maintenance_state().unwrap(),
            vec![
                MaintenanceStateEntry {
                    key: "last_archived_ts".into(),
                    value: "200".into(),
                    updated_at: 2_000,
                },
                MaintenanceStateEntry {
                    key: "last_downsample_ts".into(),
                    value: "50".into(),
                    updated_at: 900,
                },
            ],
            "必须按 key 升序且覆盖写不产生重复行"
        );

        // 参数化：引号 / SQL 片段按字面量存取，不会被当作 SQL 执行。
        let key = "k'quote";
        let value = "v'; DROP TABLE maintenance_state; --";
        storage.set_maintenance_state(key, value, 3_000).unwrap();
        assert_eq!(
            storage.get_maintenance_state(key).unwrap(),
            Some(value.to_string())
        );
        assert_eq!(storage.list_maintenance_state().unwrap().len(), 3);
    }

    /// create / list：按 name 升序（C 字节序）、重复 name/hash、非法 scope、
    /// 只存 SHA-256，对外记录与错误都不含 hash/明文。
    #[test]
    fn api_tokens_create_list_and_constraints() {
        const NAME: &str = "api_tokens_create_list_and_constraints";
        let Some(db) = TestDatabase::create("token_create") else {
            skip(NAME);
            return;
        };
        let storage = db.open_storage();

        let plain_a = "plain-token-a";
        let plain_b = "plain-token-b";
        let hash_a = sha256_hex(plain_a);
        let hash_b = sha256_hex(plain_b);

        let record = storage
            .create_api_token("web-b", &hash_a, "read", 1_700_000_000_000)
            .unwrap();
        assert_eq!(record.name, "web-b");
        assert_eq!(record.scope, "read");
        assert_eq!(record.created_at, 1_700_000_000_000);
        assert_eq!(record.last_used_at, None);
        assert_eq!(record.revoked_at, None);
        assert!(record.id > 0, "RETURNING id 必须返回正数 id");

        storage
            .create_api_token("app-a", &hash_b, "admin", 1_700_000_000_001)
            .unwrap();
        // 大写名验证 `COLLATE "C"`：Z(0x5A) 排在 a(0x61) 前，与 SQLite BINARY 一致。
        storage
            .create_api_token("Zulu", &sha256_hex("plain-token-z"), "write", 1)
            .unwrap();

        let listed = storage.list_api_tokens().unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|token| token.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Zulu", "app-a", "web-b"],
            "列表必须按 name 的字节序升序"
        );

        // 重复 name 是可读错误，不能是 SQL 约束原文，也不能带 hash。
        let err = storage
            .create_api_token("web-b", &sha256_hex("other"), "read", 1)
            .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("token 名称已存在"), "err={message}");
        assert!(!message.contains(&hash_a), "错误信息泄露 hash：{message}");

        // 重复 token_hash 必须映射成哈希冲突，且不泄露 hash。
        let err = storage
            .create_api_token("dup-hash", &hash_a, "read", 1)
            .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("token 哈希冲突"), "err={message}");
        assert!(!message.contains(&hash_a), "错误信息泄露 hash：{message}");
        assert!(!message.contains(plain_a), "错误信息泄露明文：{message}");

        // 非法 scope 在落库前被拒绝。
        let err = storage
            .create_api_token("bad-scope", &sha256_hex("x"), "root", 1)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("scope"),
            "非法 scope 必须被拒绝：{err:#}"
        );
        assert_eq!(storage.list_api_tokens().unwrap().len(), 3, "失败不得落行");

        // 数据库只有 SHA-256 hex，没有明文；对外记录里也没有哈希字段。
        let stored: String = storage
            .with_client(|client| {
                let row = client
                    .query_one(
                        "SELECT token_hash FROM api_tokens WHERE name = 'web-b'",
                        &[],
                    )
                    .context("查询 token_hash 失败")?;
                Ok(row.get(0))
            })
            .expect("读取 token_hash 失败");
        assert_eq!(stored, hash_a);
        assert!(!stored.contains(plain_a));

        let debug = format!("{listed:?}");
        assert!(!debug.contains(plain_a) && !debug.contains(plain_b));
        assert!(!debug.contains(&hash_a) && !debug.contains(&hash_b));
    }

    /// rotate / revoke / authenticate：旧哈希失效、吊销不删行、60s 节流、
    /// 轮换失败不改原记录、重复吊销与不存在是可读错误。
    #[test]
    fn api_tokens_rotate_revoke_and_authenticate_throttle() {
        const NAME: &str = "api_tokens_rotate_revoke_and_authenticate_throttle";
        let Some(db) = TestDatabase::create("token_lifecycle") else {
            skip(NAME);
            return;
        };
        let storage = db.open_storage();

        let old_hash = sha256_hex("old-token");
        let new_hash = sha256_hex("new-token");
        let other_hash = sha256_hex("other-token");
        let created = storage
            .create_api_token("panel", &old_hash, "write", 100)
            .unwrap();

        // 吊销：只写 revoked_at，不删行；重复吊销与不存在是不同错误。
        storage.revoke_api_token("panel", 150).unwrap();
        let listed = storage.list_api_tokens().unwrap();
        assert_eq!(listed.len(), 1, "吊销不删行");
        assert_eq!(listed[0].revoked_at, Some(150));

        // 轮换：id/name/scope 不变，created_at 更新，清空 last_used/revoked。
        let rotated = storage.rotate_api_token("panel", &new_hash, 200).unwrap();
        assert_eq!(rotated.id, created.id);
        assert_eq!(rotated.name, "panel");
        assert_eq!(rotated.scope, "write", "rotate 不改变 scope");
        assert_eq!(rotated.created_at, 200);
        assert_eq!(rotated.last_used_at, None);
        assert_eq!(rotated.revoked_at, None, "rotate 必须清 revoked_at");

        // 旧哈希立即失效，新哈希可用；首次鉴权写 last_used_at。
        assert!(storage
            .authenticate_api_token(&old_hash, 210)
            .unwrap()
            .is_none());
        let active = storage
            .authenticate_api_token(&new_hash, 210)
            .unwrap()
            .expect("新哈希必须可用");
        assert_eq!(active.name, "panel");
        assert_eq!(
            active.last_used_at,
            Some(210),
            "首次鉴权必须写 last_used_at"
        );
        assert_eq!(
            storage.list_api_tokens().unwrap()[0].last_used_at,
            Some(210)
        );

        // 60s 内节流：数据库保持首次时间，但鉴权仍成功。
        let throttled = storage
            .authenticate_api_token(&new_hash, 211)
            .unwrap()
            .unwrap();
        assert_eq!(throttled.last_used_at, Some(210), "节流窗口内不重复写");
        assert_eq!(
            storage.list_api_tokens().unwrap()[0].last_used_at,
            Some(210)
        );

        // 60s 整点刷新（与 SQLite `now - last >= 60000` 等价）。
        let refreshed = storage
            .authenticate_api_token(&new_hash, 210 + API_TOKEN_LAST_USED_THROTTLE_MS)
            .unwrap()
            .unwrap();
        assert_eq!(
            refreshed.last_used_at,
            Some(210 + API_TOKEN_LAST_USED_THROTTLE_MS)
        );
        assert_eq!(
            storage.list_api_tokens().unwrap()[0].last_used_at,
            Some(210 + API_TOKEN_LAST_USED_THROTTLE_MS)
        );

        // 轮换到已被占用的 hash：失败且原记录（新哈希）仍然可用。
        storage
            .create_api_token("other", &other_hash, "read", 300)
            .unwrap();
        let err = storage
            .rotate_api_token("panel", &other_hash, 400)
            .unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("token 哈希冲突"), "err={message}");
        assert!(
            !message.contains(&other_hash),
            "错误信息泄露 hash：{message}"
        );
        assert!(
            storage
                .authenticate_api_token(&new_hash, 401)
                .unwrap()
                .is_some(),
            "失败的轮换不得破坏原记录"
        );

        // 不存在的轮换 / 吊销 / 重复吊销。
        let err = storage
            .rotate_api_token("missing", &new_hash, 500)
            .unwrap_err();
        assert!(format!("{err:#}").contains("不存在"), "err={err:#}");

        // 最终吊销 + 鉴权拒绝。
        storage.revoke_api_token("panel", 70_000).unwrap();
        assert!(
            storage
                .authenticate_api_token(&new_hash, 70_001)
                .unwrap()
                .is_none(),
            "已吊销 token 必须认证失败"
        );
        let listed = storage.list_api_tokens().unwrap();
        assert_eq!(listed.len(), 2, "吊销不删行");
        let panel = listed.iter().find(|token| token.name == "panel").unwrap();
        assert_eq!(panel.revoked_at, Some(70_000));

        let err = storage.revoke_api_token("panel", 70_002).unwrap_err();
        assert!(format!("{err:#}").contains("已吊销"), "err={err:#}");
        let err = storage.revoke_api_token("missing", 70_002).unwrap_err();
        assert!(format!("{err:#}").contains("不存在"), "err={err:#}");
    }
}
