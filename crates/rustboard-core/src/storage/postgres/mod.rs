//! PostgreSQL 后端（M5 Phase D）。
//!
//! D2 落地 schema/migration：[`schema::apply_schema`] 建 22 张表与 23 个命名
//! 索引、维护 PG 独立的 `schema_migrations`，并用事务级 advisory lock 串行化
//! 多实例启动。
//!
//! D3 在 D2 之上补齐「连接层 + 97 个 Storage 方法」：
//!
//! - [`PostgresStorage::open`] 解析 DSN、建立 rustls/NoTls 连接器与 r2d2 连接池；
//! - [`PostgresStorage::with_client`] 是所有 PG SQL 的唯一取连接入口，统一做
//!   连接池超时、错误上下文与 DSN/密码脱敏；
//! - `core` / `admin` / `alerts` / `archive` 按域实现 97 个固有方法（agent /
//!   sample / ingest / 纳管 / 审计 / 告警 / 通知 / token / 降采样 / 归档），
//!   签名与 [`Storage`] 逐字一致；
//! - `storage_impl` 是最后的薄转发层：`impl Storage for PostgresStorage` 用
//!   UFCS 逐个转发到上述固有方法，`PostgresStorage` 因此可以直接作为
//!   `Arc<dyn Storage>` 交给 [`StorageHandle`](crate::storage::StorageHandle)。
//!
//! # 运行时不变量（spike §4/§11）
//!
//! `postgres` 是同步驱动，内部为每条连接创建 current-thread runtime 并
//! `block_on`。在 tokio worker 上直接 connect/query **会 panic**
//! （`Cannot start a runtime from within a runtime`），不是单纯变慢。因此：
//!
//! 1. [`PostgresStorage::open`] 和所有固有方法都必须在 tokio runtime **之外**
//!    或 `spawn_blocking` 闭包内调用；D4 负责逐个调用点接线。
//! 2. 连接池在 [`PostgresStorage::drop`] 中移交给独立 OS 线程释放；池内
//!    `postgres::Client` 的 `Drop` 不能在 tokio runtime 内执行。
//! 3. 本模块不使用 `async`、不调用 `block_on`、不启动任何 runtime。
//!
//! # TLS
//!
//! `sslmode` 只接受 `verify-full`（缺省）与 `disable`。`verify-full` 在配置层
//! 从 DSN 剥离后映射为 [`SslMode::Require`] + 校验型 rustls
//! （[`tokio_postgres_rustls::MakeRustlsConnect`]），等价 libpq 的
//! verify-full；`require`/`prefer`/`verify-ca`/`allow` 明确拒绝。`disable`
//! 会在启动时打一次 WARN（不包含 DSN）。
//!
//! [`Storage`]: crate::storage::Storage

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use postgres::config::SslMode;
use postgres::NoTls;
use r2d2::{ManageConnection, Pool};
use rustboard_common::config::{redact_database_url, DatabaseKind, HubConfig};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use rustls::{ClientConfig, RootCertStore};
use tokio_postgres_rustls::MakeRustlsConnect;

mod admin;
mod alerts;
mod archive;
mod core;
pub mod schema;
mod storage_impl;

pub use schema::{
    apply_schema, connect_for_schema, POSTGRES_SCHEMA_VERSION, SCHEMA_ADVISORY_LOCK_KEY,
};

/// 数据库密码覆盖来源；非空时优先于 URL 内密码。
const PASSWORD_ENV: &str = "RUSTBOARD_DATABASE_PASSWORD";

/// 连接池上限与 `HubConfig::db_pool_size` 的校验区间保持一致。
const MIN_POOL_SIZE: usize = 1;
const MAX_POOL_SIZE: usize = 64;

/// 连接最长存活时间：防止服务端长期连接积累状态（spike §6.3）。
const POOL_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// 空闲连接回收时间（spike §6.3）。
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// 建立 PostgreSQL 连接所需的参数。
///
/// 不 `derive(Debug)`：`dsn` 字段在 `Debug` 中固定输出 `"<redacted>"`，不输出
/// URL 的任何部分（scheme/user/host/db/query）。
pub struct PostgresOptions {
    /// `postgres://` / `postgresql://` 连接串；后续 D4 由 `HubConfig::database`
    /// 提供。query 中的 `sslmode` 与 `sslrootcert` 在 [`PostgresStorage::open`]
    /// 内解析并剥离。
    pub dsn: String,
    /// 连接池上限（1–64）。
    pub pool_size: usize,
    /// 建立连接 / 从池中取连接的超时。
    pub connect_timeout: Duration,
    /// 每条新连接的 `statement_timeout`。
    pub statement_timeout: Duration,
    /// 自定义根 CA（PEM）。与 DSN query 里的 `sslrootcert` 同时出现时必须
    /// 指向同一文件；配置字段优先。
    pub sslrootcert: Option<PathBuf>,
}

impl fmt::Debug for PostgresOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresOptions")
            // 固定占位符：不输出 URL 的任何部分（scheme/user/host/db/query）。
            .field("dsn", &"<redacted>")
            .field("pool_size", &self.pool_size)
            .field("connect_timeout", &self.connect_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field("sslrootcert", &self.sslrootcert)
            .finish()
    }
}

/// TLS 模式：只支持显式 `disable` 与等价 verify-full 的校验型 TLS。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PgTlsMode {
    VerifyFull,
    Disable,
}

/// 从 DSN 解析出的可连接配置。
struct ResolvedDsn {
    /// 已剥离 `sslmode` / `sslrootcert` 的 DSN 解析结果。
    config: postgres::Config,
    tls_mode: PgTlsMode,
    root: Option<PathBuf>,
    /// 供日志/错误使用的脱敏 DSN。
    redacted: String,
    /// 已知密码集合；任何格式化进错误的信息都先经过它。
    redactor: Redactor,
}

/// PostgreSQL 连接池与 Core 方法入口。
///
/// 只在 `open` / `open_from_config` 构造；构造与析构都必须在 tokio runtime
/// 之外（或 `spawn_blocking` 内），理由见模块文档。
pub struct PostgresStorage {
    /// `Option` 是为了在 `Drop` 中 `take` 后移交给独立线程释放。
    pool: Option<Pool<PgManager>>,
    /// 从池中取连接的超时（与建连超时一致）。
    timeout: Duration,
    /// 脱敏 DSN，仅用于错误上下文。
    redacted_dsn: String,
    /// 密码脱敏器；`Debug` 不输出。
    redactor: Redactor,
    /// 成功写入的批次数，用于每 512 批清理一次过期判重记录。
    inserted_batches: AtomicU64,
    /// 成功写入的审计条数，用于每 1000 条清理一次 180 天前的记录。
    ///
    /// 每个 `PostgresStorage` 实例独立计数，多实例不会互相叠加。
    audit_writes: AtomicU64,
}

impl fmt::Debug for PostgresStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresStorage")
            .field("dsn", &self.redacted_dsn)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl PostgresStorage {
    /// 打开 PostgreSQL 连接池并做一次 `SELECT 1` 探活。
    ///
    /// # 必须在 tokio runtime 外调用
    ///
    /// `postgres::Config::connect` 内部会创建 current-thread runtime 并
    /// `block_on`；在 tokio worker 内调用会 panic（spike §4.1）。D4 的启动
    /// 路径必须在 `runtime.block_on` 之前调用本函数，或放进
    /// `spawn_blocking`。
    ///
    /// schema 不会在这里自动迁移：调用方先通过 [`schema::apply_schema`]
    /// 完成幂等迁移（同样在 blocking 线程），或使用 [`Self::apply_schema`]。
    pub fn open(options: PostgresOptions) -> Result<Self> {
        if !(MIN_POOL_SIZE..=MAX_POOL_SIZE).contains(&options.pool_size) {
            bail!(
                "db_pool_size 必须在 {MIN_POOL_SIZE}–{MAX_POOL_SIZE} 之间，实际 {}",
                options.pool_size
            );
        }
        if options.connect_timeout.is_zero() {
            bail!("db_connect_timeout 必须大于 0");
        }
        let statement_timeout_ms = u64::try_from(options.statement_timeout.as_millis())
            .unwrap_or(u64::MAX)
            .min(i64::MAX as u64);
        if statement_timeout_ms == 0 {
            bail!("db_statement_timeout 至少为 1ms");
        }

        let env_password = database_password_from_env()?;
        let resolved = resolve_dsn(
            &options.dsn,
            options.sslrootcert.as_deref(),
            env_password.as_deref(),
        )?;
        let ResolvedDsn {
            mut config,
            tls_mode,
            root,
            redacted,
            redactor,
        } = resolved;

        if tls_mode == PgTlsMode::Disable {
            tracing::warn!(
                "PostgreSQL 已配置 sslmode=disable：数据库流量为明文传输，请只用于本机回环或受信内网"
            );
            if root.is_some() {
                tracing::warn!("sslmode=disable 下 sslrootcert 不会被使用，已忽略");
            }
        }

        config.connect_timeout(options.connect_timeout);
        let connector = match tls_mode {
            PgTlsMode::VerifyFull => PgTls::Rustls(build_rustls_connector(root.as_deref())?),
            PgTlsMode::Disable => PgTls::NoTls,
        };
        let manager = PgManager {
            config,
            connector,
            statement_timeout_ms,
        };

        let pool = Pool::builder()
            .max_size(options.pool_size as u32)
            .min_idle(Some(1))
            .connection_timeout(options.connect_timeout)
            .test_on_check_out(true)
            .max_lifetime(Some(POOL_MAX_LIFETIME))
            .idle_timeout(Some(POOL_IDLE_TIMEOUT))
            .build(manager)
            .map_err(|err| {
                anyhow!(
                    "创建 PostgreSQL 连接池失败（dsn={redacted}）：{}",
                    redactor.scrub(&err.to_string())
                )
            })?;

        let storage = Self {
            pool: Some(pool),
            timeout: options.connect_timeout,
            redacted_dsn: redacted,
            redactor,
            inserted_batches: AtomicU64::new(0),
            audit_writes: AtomicU64::new(0),
        };
        // 失败时 `storage` 的 Drop 会把池交给独立线程，避免在 runtime 内
        // drop 同步 Client（见 `impl Drop`）。
        storage.ping().context("PostgreSQL 初始连接探活失败")?;
        Ok(storage)
    }

    /// 从 hub 配置打开；`database` 必须是 `postgres://` / `postgresql://`。
    ///
    /// SQLite 配置走 [`StorageHandle`](crate::storage::StorageHandle)，不应
    /// 调用本函数。配置层的 `db_sslrootcert` 优先于 DSN query 中的
    /// `sslrootcert`；两者不一致时拒绝启动。
    pub fn open_from_config(cfg: &HubConfig) -> Result<Self> {
        let kind = cfg.database_kind().context("解析 database 配置失败")?;
        let DatabaseKind::Postgres(dsn) = kind else {
            bail!("当前 database 不是 PostgreSQL；SQLite 后端请继续走 StorageHandle::sqlite");
        };
        Self::open(PostgresOptions {
            dsn,
            pool_size: cfg.db_pool_size,
            connect_timeout: Duration::from_millis(cfg.db_connect_timeout_ms),
            statement_timeout: Duration::from_millis(cfg.db_statement_timeout_ms),
            sslrootcert: cfg.db_sslrootcert.clone(),
        })
    }

    /// 在池内连接上幂等应用 schema v9。
    ///
    /// 与 [`schema::apply_schema`] 相同，只是复用连接池；必须在 tokio runtime
    /// 外的 blocking 线程调用（启动路径）。
    pub fn apply_schema(&self) -> Result<()> {
        self.with_client(apply_schema)
            .context("PostgreSQL schema 初始化失败")
    }

    /// 所有 PG SQL 的唯一取连接入口。
    ///
    /// - `get_timeout(connect_timeout)` 限制排队等待；
    /// - 取连接失败的错误统一脱敏后包成 `anyhow`；
    /// - 闭包内的 `postgres::Error` 会保留在 `anyhow` 错误链里（后续域可按
    ///   SQLSTATE 分类重试），只追加不带 DSN userinfo 的上下文。
    ///
    /// **调用方必须位于 blocking 线程**；本函数自身不创建 runtime，也不会
    /// 把 `PooledConnection` 返回到 async 侧。
    pub(crate) fn with_client<T>(
        &self,
        f: impl FnOnce(&mut postgres::Client) -> Result<T>,
    ) -> Result<T> {
        let pool = self
            .pool
            .as_ref()
            .ok_or_else(|| anyhow!("PostgreSQL 连接池已关闭"))?;
        // `PooledConnection` 的 Drop 只是把连接放回池，在 tokio 任务内也安全；
        // 真正危险的是 `Client`/`Pool` 自身的 Drop（spike §4.2/§4.3）。
        let mut client = pool.get_timeout(self.timeout).map_err(|err| {
            anyhow!(
                "从 PostgreSQL 连接池获取连接失败（dsn={}）：{}",
                self.redacted_dsn,
                self.redactor.scrub(&err.to_string())
            )
        })?;
        f(&mut client).with_context(|| format!("PostgreSQL 操作失败（dsn={}）", self.redacted_dsn))
    }

    /// 探活：`SELECT 1`。启动时由 [`Self::open`] 调用一次。
    pub fn ping(&self) -> Result<()> {
        self.with_client(|client| {
            let row = client
                .query_one("SELECT 1", &[])
                .context("执行 SELECT 1 失败")?;
            let one: i32 = row.get(0);
            if one != 1 {
                bail!("SELECT 1 返回了非预期值");
            }
            Ok(())
        })
        .context("PostgreSQL ping 失败")
    }
}

impl Drop for PostgresStorage {
    fn drop(&mut self) {
        let Some(pool) = self.pool.take() else {
            return;
        };
        // spike §4.2：池内 `postgres::Client` 的 Drop 会在内部 runtime 上
        // `block_on`；若当前线程处于 tokio runtime，直接 drop 会 panic。
        // 移到独立 OS 线程后就没有 runtime 上下文，且不阻塞调用方。
        std::thread::spawn(move || drop(pool));
    }
}

// 编译期证明连接池可跨线程共享：hub 会在 Arc/多个 spawn_blocking 间共享。
#[allow(dead_code)]
fn _assert_postgres_storage_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PostgresStorage>();
}

/// 连接器：verify-full 用 rustls，disable 用 NoTls。
#[derive(Clone)]
enum PgTls {
    Rustls(MakeRustlsConnect),
    NoTls,
}

/// r2d2 自定义 Manager：新连接统一设置 statement_timeout 与 application_name。
#[derive(Clone)]
struct PgManager {
    config: postgres::Config,
    connector: PgTls,
    statement_timeout_ms: u64,
}

impl ManageConnection for PgManager {
    type Connection = postgres::Client;
    type Error = postgres::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let mut client = match &self.connector {
            PgTls::Rustls(connector) => self.config.connect(connector.clone())?,
            PgTls::NoTls => self.config.connect(NoTls)?,
        };
        // 两个值都来自 u64/常量，不拼接任何用户输入；SET 只执行一次。
        client.batch_execute(&format!(
            "SET statement_timeout = {}; SET application_name = 'rustboard-hub'",
            self.statement_timeout_ms
        ))?;
        Ok(client)
    }

    fn is_valid(&self, client: &mut Self::Connection) -> Result<(), Self::Error> {
        // 与 r2d2_postgres 相同的空查询探活；实测约 160µs（spike §6.3）。
        client.simple_query("").map(|_| ())
    }

    fn has_broken(&self, client: &mut Self::Connection) -> bool {
        client.is_closed()
    }
}

/// 密码脱敏器：把已知密码替换成 `***`。
///
/// 正常情况下 `postgres::Error` 不回显 DSN/密码；这里是纵深防御，保证我们
/// 自己拼接的错误文本（连接池、配置解析）即使意外带出密码也不会进日志。
struct Redactor {
    /// 按长度倒序，避免短密码先替换破坏长密码片段。
    secrets: Vec<String>,
}

impl Redactor {
    fn new(secrets: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let mut secrets: Vec<String> = secrets
            .into_iter()
            .filter(|secret| !secret.is_empty())
            .map(|secret| String::from_utf8_lossy(&secret).into_owned())
            .collect();
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        Self { secrets }
    }

    fn scrub(&self, text: &str) -> String {
        let mut out = text.to_string();
        for secret in &self.secrets {
            if !secret.is_empty() {
                out = out.replace(secret.as_str(), "***");
            }
        }
        out
    }
}

/// 读取 `RUSTBOARD_DATABASE_PASSWORD`；未设置/空串返回 `None`。
///
/// 非 UTF-8 时 fail-closed：静默回退 URL 密码会把用户以为已生效的覆盖配置
/// 悄悄丢掉。
fn database_password_from_env() -> Result<Option<String>> {
    match std::env::var(PASSWORD_ENV) {
        Ok(password) if !password.is_empty() => Ok(Some(password)),
        Ok(_) => Ok(None),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("环境变量 {PASSWORD_ENV} 不是合法 UTF-8；请使用 UTF-8 密码或改回 URL 内密码")
        }
    }
}

/// 解析 DSN 的 TLS 参数，并返回剥离 `sslmode` / `sslrootcert` 后的连接串。
fn extract_ssl_options(dsn: &str) -> Result<(String, PgTlsMode, Option<PathBuf>)> {
    let Some(query_start) = dsn.find('?') else {
        return Ok((dsn.to_string(), PgTlsMode::VerifyFull, None));
    };
    let base = &dsn[..query_start];
    let query = &dsn[query_start + 1..];

    let mut mode = None;
    let mut root: Option<PathBuf> = None;
    let mut remaining: Vec<&str> = Vec::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        let key = percent_decode(raw_key, "query 参数名")?;
        match key.as_str() {
            "sslmode" => {
                if mode.is_some() {
                    bail!("PostgreSQL DSN 重复指定 sslmode；请只保留一个");
                }
                let value = percent_decode(raw_value, "sslmode")?;
                mode = Some(match value.as_str() {
                    "verify-full" => PgTlsMode::VerifyFull,
                    "disable" => PgTlsMode::Disable,
                    _ => bail!(
                        "database 的 sslmode 只支持 \"verify-full\" 或 \"disable\"；\
                         \"require\"/\"prefer\" 无法保证主机名校验或会静默降级，已拒绝。\
                         请改成 sslmode=verify-full（推荐）或显式 sslmode=disable。"
                    ),
                });
            }
            "sslrootcert" => {
                if root.is_some() {
                    bail!("PostgreSQL DSN 重复指定 sslrootcert；请只保留一个");
                }
                let value = percent_decode(raw_value, "sslrootcert")?;
                if value.is_empty() {
                    bail!("PostgreSQL DSN 的 sslrootcert 不能为空；请填写 PEM 根 CA 文件路径");
                }
                root = Some(PathBuf::from(value));
            }
            _ => remaining.push(pair),
        }
    }

    let cleaned = if remaining.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", remaining.join("&"))
    };
    Ok((cleaned, mode.unwrap_or(PgTlsMode::VerifyFull), root))
}

/// 严格解析 DSN query 中的百分号编码（只用于 TLS 参数与参数名）。
///
/// 不用 `+` 代表空格：libpq URI 使用 percent-encoding，不采用 form 编码。
fn percent_decode(raw: &str, what: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                bail!("PostgreSQL DSN 的 {what} 含不完整的百分号编码，已拒绝");
            }
            let high = hex_value(bytes[index + 1]);
            let low = hex_value(bytes[index + 2]);
            let (Some(high), Some(low)) = (high, low) else {
                bail!("PostgreSQL DSN 的 {what} 含非法百分号编码，已拒绝");
            };
            out.push(high << 4 | low);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).with_context(|| format!("PostgreSQL DSN 的 {what} 不是合法 UTF-8"))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 解析 DSN、应用密码覆盖与 TLS 模式。
///
/// - 只接受 `postgres://` / `postgresql://` URL 形式；keyword 形式无法可靠
///   剥离 `sslmode`，直接拒绝；
/// - `sslmode` 缺省为 `verify-full`；
/// - `env_password` 非空时覆盖 URL 密码；
/// - `config_root` 与 DSN `sslrootcert` 同时出现时必须指向同一文件。
fn resolve_dsn(
    dsn: &str,
    config_root: Option<&Path>,
    env_password: Option<&str>,
) -> Result<ResolvedDsn> {
    let redacted = redact_database_url(dsn);
    if !(dsn.starts_with("postgres://") || dsn.starts_with("postgresql://")) {
        bail!(
            "PostgreSQL DSN 必须以 postgres:// 或 postgresql:// 开头；\
             不支持 keyword 形式，也无法安全解析 sslmode"
        );
    }

    let (cleaned, tls_mode, query_root) = extract_ssl_options(dsn)?;
    let root = resolve_root(config_root, query_root)?;

    let mut config: postgres::Config = cleaned
        .parse()
        .map_err(|err| anyhow!("PostgreSQL DSN 解析失败（dsn={redacted}）：{err}"))?;
    let url_password = config.get_password().map(<[u8]>::to_vec);
    if let Some(password) = env_password.filter(|password| !password.is_empty()) {
        config.password(password);
    }
    let effective_password = config.get_password().map(<[u8]>::to_vec);
    let redactor = Redactor::new(url_password.into_iter().chain(effective_password));

    // 驱动只接受 disable/prefer/require；verify-full 由配置层剥离后映射为
    // require + 校验型 rustls。disable 显式映射，绝不保留驱动默认的 prefer。
    config.ssl_mode(match tls_mode {
        PgTlsMode::VerifyFull => SslMode::Require,
        PgTlsMode::Disable => SslMode::Disable,
    });

    Ok(ResolvedDsn {
        config,
        tls_mode,
        root,
        redacted,
        redactor,
    })
}

/// 合并配置层根 CA 与 DSN `sslrootcert`。
///
/// 两处同时出现时必须指向同一文件：运行连接、备份/恢复/迁移的外部工具
/// 以及错误提示都复用这一条规则，避免某条路径静默选用另一份信任根。
fn resolve_root(
    config_root: Option<&Path>,
    query_root: Option<PathBuf>,
) -> Result<Option<PathBuf>> {
    match (config_root, query_root) {
        (Some(config_path), Some(query_path)) if config_path != query_path => bail!(
            "db_sslrootcert 与 DSN 中的 sslrootcert 指向不同文件；\
             请只保留一处配置，或让两处指向同一 PEM 文件"
        ),
        (Some(config_path), _) => Ok(Some(config_path.to_path_buf())),
        (None, query_root) => Ok(query_root),
    }
}

/// 外部 PostgreSQL 工具（`pg_dump` / `pg_restore` / 迁移目标连接）所需的
/// DSN 与 TLS 策略。
///
/// 与运行连接复用同一套解析：
/// - `sslmode` 缺省 `verify-full`，只接受显式 `disable`；
/// - `db_sslrootcert` / DSN `sslrootcert` 的冲突校验一致；
/// - URL 内密码优先级完全交给 `postgres::Config`（query 覆盖 authority、
///   重复 query 后者生效、参数名先百分号解码），非空
///   `RUSTBOARD_DATABASE_PASSWORD` 再覆盖。
///
/// 结构体包含密码，故意不实现 `Debug`，防止被日志/panic 意外打印。
pub struct PgExternalToolDsn {
    /// 已剥离 authority/query 密码、`sslpassword`、`sslmode`、`sslrootcert`
    /// 的 DSN，可以安全放进 argv。
    pub sanitized: String,
    /// URL 自身的有效密码（未应用环境变量覆盖），仅用于错误脱敏。
    pub url_password: Option<String>,
    /// 实际应通过 `PGPASSWORD` 传递的密码（环境变量覆盖后）。
    pub effective_password: Option<String>,
    /// `sslpassword`（已从 DSN 剥离），通过 `PGSSLPASSWORD` 传递。
    pub sslpassword: Option<String>,
    /// `verify-full` 或 `disable`（外部工具通过 `PGSSLMODE` 显式传递）。
    pub sslmode: &'static str,
    /// 私有 CA（如有），外部工具通过 `PGSSLROOTCERT` 传递。
    pub sslrootcert: Option<PathBuf>,
}

/// 解析外部 PostgreSQL 工具所需的 DSN 与 TLS 策略。
///
/// 读取一次 `RUSTBOARD_DATABASE_PASSWORD`（与运行连接同一个环境变量）；
/// 非 UTF-8 时 fail-closed。
pub fn resolve_external_tool_dsn(
    dsn: &str,
    config_root: Option<&Path>,
) -> Result<PgExternalToolDsn> {
    let env_password = database_password_from_env()?;
    resolve_external_tool_dsn_with_env(dsn, config_root, env_password.as_deref())
}

/// [`resolve_external_tool_dsn`] 的可注入环境变量版本（供测试对比驱动优先级）。
fn resolve_external_tool_dsn_with_env(
    dsn: &str,
    config_root: Option<&Path>,
    env_password: Option<&str>,
) -> Result<PgExternalToolDsn> {
    let redacted = redact_database_url(dsn);
    if !(dsn.starts_with("postgres://") || dsn.starts_with("postgresql://")) {
        bail!(
            "PostgreSQL DSN 必须以 postgres:// 或 postgresql:// 开头；\
             不支持 keyword 形式，也无法安全解析 sslmode（当前值已脱敏：{redacted}）"
        );
    }
    // fragment 不是合法连接参数，且可能被用来把密码后缀藏进错误信息；直接拒绝。
    if dsn.contains('#') {
        bail!("PostgreSQL DSN 不能包含 fragment（#）；当前值已脱敏：{redacted}");
    }

    // sslmode/sslrootcert 的解析、重复检测与冲突校验与运行连接完全一致。
    let (cleaned, tls_mode, query_root) = extract_ssl_options(dsn)?;
    let root = resolve_root(config_root, query_root)?;
    // sslpassword 是 libpq 参数，`postgres` 驱动不认识；先提取并从 DSN 剥离，
    // 再把剩余部分交给驱动解析密码优先级。
    let (cleaned, sslpassword) = extract_sslpassword(&cleaned)?;
    let mut config: postgres::Config = cleaned
        .parse()
        .map_err(|_| anyhow!("PostgreSQL DSN 解析失败（当前值已脱敏：{redacted}），已拒绝"))?;
    let url_password = config.get_password().map(password_to_string).transpose()?;
    if let Some(password) = env_password.filter(|password| !password.is_empty()) {
        config.password(password);
    }
    let effective_password = config.get_password().map(password_to_string).transpose()?;
    let sanitized = strip_url_passwords(&cleaned)
        .map_err(|err| anyhow!("无法生成脱敏 PostgreSQL DSN（当前值已脱敏：{redacted}）：{err}"))?;
    // 纵深防御：即使畸形 authority 未被上面的解析覆盖，argv 里也不能出现密码。
    // 对合法 DSN（已无密码）该函数原样返回。
    let sanitized = redact_database_url(&sanitized);
    // spawn 前断言：驱动不能再解析出 password，且已知长密码不以明文残留。
    ensure_sanitized_has_no_password(
        &sanitized,
        url_password.as_deref(),
        effective_password.as_deref(),
    )?;

    Ok(PgExternalToolDsn {
        sanitized,
        url_password,
        effective_password,
        sslpassword,
        sslmode: match tls_mode {
            PgTlsMode::VerifyFull => "verify-full",
            PgTlsMode::Disable => "disable",
        },
        // disable 下根证书不会被使用；运行连接同样忽略它，但冲突校验仍然执行。
        sslrootcert: match tls_mode {
            PgTlsMode::VerifyFull => root,
            PgTlsMode::Disable => None,
        },
    })
}

/// 把驱动返回的密码字节转成可放进环境变量的 UTF-8 字符串。
fn password_to_string(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| anyhow!("PostgreSQL DSN 密码不是合法 UTF-8；无法安全传给外部工具"))
}

/// 从已剥离 TLS 参数的 DSN 中提取 `sslpassword` 并移除该参数。
///
/// 参数名与值都按驱动/libpq 规则做百分号解码；重复参数取最后一个（与
/// libpq/驱动一致）。非法编码直接拒绝，避免把无法可靠识别的值写进 argv。
fn extract_sslpassword(dsn: &str) -> Result<(String, Option<String>)> {
    let Some(query_start) = dsn.find('?') else {
        return Ok((dsn.to_string(), None));
    };
    let base = &dsn[..query_start];
    let query = &dsn[query_start + 1..];
    let mut remaining: Vec<&str> = Vec::new();
    let mut sslpassword = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = pair
            .split_once('=')
            .ok_or_else(|| anyhow!("PostgreSQL DSN query 参数缺少 =（保留参数名，不输出原值）"))?;
        let key = percent_decode(raw_key, "query 参数名")?;
        if key.eq_ignore_ascii_case("sslpassword") {
            sslpassword = Some(percent_decode(raw_value, "sslpassword")?);
        } else {
            remaining.push(pair);
        }
    }
    let cleaned = if remaining.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", remaining.join("&"))
    };
    Ok((cleaned, sslpassword))
}

/// 从 DSN 中剥离 authority 与 query 两处密码，生成可放进 argv 的 DSN。
///
/// userinfo 到第一个 `@` 结束，**绝不**先按 `/` 截断 authority：密码里的裸
/// `/`（如 `user:2024/secret@host`）会让旧逻辑把数字前缀当端口、把密码后半段
/// 留在 path 里。多个裸 `@` 无法判断密码边界，直接 fail closed；query 中所有
/// 解码后为 `password` / `sslpassword` 的参数整体删除。
fn strip_url_passwords(dsn: &str) -> Result<String> {
    let (scheme, rest) = dsn
        .split_once("://")
        .ok_or_else(|| anyhow!("DSN 缺少 scheme"))?;
    let boundary = rest.find(['?', '#']).unwrap_or(rest.len());
    let head = &rest[..boundary];
    let tail = &rest[boundary..];

    let sanitized_head = match head.find('@') {
        Some(first_at) => {
            if head[first_at + 1..].contains('@') {
                // 驱动按第一个 `@` 结束 userinfo；多个裸 `@` 时无法判断
                // `pa@ss` 哪一段是密码，拒绝生成 argv。
                bail!(
                    "PostgreSQL DSN userinfo 含多个裸 @，无法安全剥离密码；\
                     请对密码中的 @ 做百分号编码"
                );
            }
            let userinfo = &head[..first_at];
            let host_and_path = &head[first_at + 1..];
            match userinfo.split_once(':') {
                Some((user, _password)) => format!("{user}@{host_and_path}"),
                None => format!("{userinfo}@{host_and_path}"),
            }
        }
        None => {
            // 查询/片段里出现裸 `@`：驱动同样会把它当作 userinfo 分隔符，
            // 无法安全判断哪段是密码，fail closed。
            if tail.contains('@') {
                bail!("PostgreSQL DSN 的 @ 出现在 query/fragment 中，无法安全剥离密码");
            }
            // 没有 `@` 但形如 `user:非数字密码`（漏写 @host）：无法定位 host。
            let authority_end = head.find('/').unwrap_or(head.len());
            if let Some((_, password)) = head[..authority_end].split_once(':') {
                if !password.is_empty() && !password.bytes().all(|b| b.is_ascii_digit()) {
                    bail!("PostgreSQL DSN userinfo 缺少 @，无法安全剥离密码");
                }
            }
            head.to_string()
        }
    };

    let mut kept: Vec<&str> = Vec::new();
    if let Some(query) = tail.strip_prefix('?') {
        // `#` 在调用方已拒绝；这里再取一次防止绕过。
        let query = query.split('#').next().unwrap_or(query);
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_key, _) = pair
                .split_once('=')
                .ok_or_else(|| anyhow!("PostgreSQL DSN query 参数缺少 =，无法安全剥离密码"))?;
            let key = percent_decode(raw_key, "query 参数名")?;
            if key.eq_ignore_ascii_case("password") || key.eq_ignore_ascii_case("sslpassword") {
                continue;
            }
            kept.push(pair);
        }
    }
    let mut sanitized = format!("{scheme}://{sanitized_head}");
    if !kept.is_empty() {
        sanitized.push('?');
        sanitized.push_str(&kept.join("&"));
    }
    Ok(sanitized)
}

/// 生成 argv DSN 后的最后一道断言：驱动不能再从中解析出密码，且已知密码
/// 不应以明文片段残留。失败时拒绝 spawn 外部工具。
fn ensure_sanitized_has_no_password(
    sanitized: &str,
    url_password: Option<&str>,
    effective_password: Option<&str>,
) -> Result<()> {
    let reparsed: postgres::Config = sanitized
        .parse()
        .map_err(|_| anyhow!("内部错误：脱敏后的 PostgreSQL DSN 无法被驱动解析，已拒绝"))?;
    if reparsed.get_password().is_some() {
        bail!("内部错误：脱敏后的 PostgreSQL DSN 仍含密码，拒绝传给外部工具");
    }
    for secret in [url_password, effective_password].into_iter().flatten() {
        // 极短密码可能天然出现在用户名/主机名中；驱动级“无 password 字段”
        // 已覆盖语义，这里只对可判定的长密码做明文包含检查。
        if secret.len() >= 6 && sanitized.contains(secret) {
            bail!("内部错误：脱敏后的 PostgreSQL DSN 仍包含密码，拒绝传给外部工具");
        }
    }
    Ok(())
}

/// 按 Hub 配置建立一条 PostgreSQL 应用连接（与连接池同一 DSN/TLS/密码解析）。
///
/// 供 CLI 子命令在不需要连接池时使用（迁移串行化锁、清理目标、schema 探针）。
/// 与 **必须在 tokio runtime 外调用** 的约束一致：`postgres` 是同步驱动。
pub fn connect_with_config(cfg: &HubConfig, dsn: &str) -> Result<postgres::Client> {
    let env_password = database_password_from_env()?;
    let resolved = resolve_dsn(dsn, cfg.db_sslrootcert.as_deref(), env_password.as_deref())?;
    let ResolvedDsn {
        mut config,
        tls_mode,
        root,
        redacted,
        redactor,
    } = resolved;
    config.connect_timeout(Duration::from_millis(cfg.db_connect_timeout_ms));
    let connector = match tls_mode {
        PgTlsMode::VerifyFull => PgTls::Rustls(build_rustls_connector(root.as_deref())?),
        PgTlsMode::Disable => PgTls::NoTls,
    };
    let client = match &connector {
        PgTls::Rustls(connector) => config.connect(connector.clone()),
        PgTls::NoTls => config.connect(NoTls),
    };
    client.map_err(|err| {
        anyhow!(
            "连接 PostgreSQL 失败（dsn={redacted}）：{}",
            redactor.scrub(&err.to_string())
        )
    })
}

/// 校验目标 PostgreSQL 确实是完整 v9 schema（只读事务）。
///
/// 用于 `pg_restore` 之后、切换配置/证书之前：`schema_migrations` 缺失或
/// `MAX(version)` 为 NULL 视为 0；版本必须等于 [`POSTGRES_SCHEMA_VERSION`]，
/// 且 22 张业务表与 23 个命名索引齐全。任何失败都返回错误，调用方必须中止。
pub fn validate_postgres_schema_v9(cfg: &HubConfig, dsn: &str) -> Result<()> {
    let redacted = redact_database_url(dsn);
    let mut client = connect_with_config(cfg, dsn)
        .with_context(|| format!("连接 PostgreSQL 校验 schema 失败（{redacted}）"))?;
    let mut tx = client
        .transaction()
        .context("开启 PostgreSQL schema 校验事务失败")?;
    let has_version_table: bool = tx
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM information_schema.tables
                 WHERE table_schema = current_schema() AND table_name = 'schema_migrations'
             )",
            &[],
        )
        .context("检查 PostgreSQL schema_migrations 是否存在失败")?
        .get(0);
    let version: Option<i64> = if has_version_table {
        tx.query_one("SELECT MAX(version) FROM schema_migrations", &[])
            .context("读取恢复后的 PostgreSQL schema 版本失败")?
            .get(0)
    } else {
        None
    };
    let version = version.unwrap_or(0);
    if version > POSTGRES_SCHEMA_VERSION {
        bail!(
            "恢复后的 PostgreSQL schema 版本 {version} 高于本程序支持的 \
             {POSTGRES_SCHEMA_VERSION}；拒绝切换配置，请升级 rustboard-hub"
        );
    }
    if version < POSTGRES_SCHEMA_VERSION {
        return schema::bail_old_schema(version);
    }
    schema::ensure_schema_objects(&mut tx)
        .context("恢复后的 PostgreSQL 声明 schema v9，但 22 张业务表/23 个命名索引不完整")?;
    tx.rollback()
        .context("结束 PostgreSQL schema 校验事务失败")?;
    Ok(())
}

/// 构建校验型 rustls 连接器：证书链与主机名都由 rustls 校验。
fn build_rustls_connector(root: Option<&Path>) -> Result<MakeRustlsConnect> {
    let mut roots = RootCertStore::empty();
    match root {
        Some(path) => {
            // 只接受普通文件：拒绝符号链接和目录/设备。错误只带路径，绝不回显
            // 文件内容。注意这是打开前的检查（不解决 TOCTOU），但足以阻止把
            // 可被替换的符号链接当作信任根。
            let metadata = std::fs::symlink_metadata(path).with_context(|| {
                format!(
                    "读取 PostgreSQL 根证书文件失败：{}（需要 PEM 编码的 CA 证书）",
                    path.display()
                )
            })?;
            if metadata.file_type().is_symlink() {
                bail!("PostgreSQL 根证书不能是符号链接：{}", path.display());
            }
            if !metadata.file_type().is_file() {
                bail!("PostgreSQL 根证书必须是普通文件：{}", path.display());
            }
            let certificates = CertificateDer::pem_file_iter(path).with_context(|| {
                format!(
                    "读取 PostgreSQL 根证书文件失败：{}（需要 PEM 编码的 CA 证书）",
                    path.display()
                )
            })?;
            let mut parsed = Vec::new();
            for certificate in certificates {
                parsed.push(certificate.with_context(|| {
                    format!(
                        "解析 PostgreSQL 根证书失败：{}（需要 PEM 编码的 CA 证书）",
                        path.display()
                    )
                })?);
            }
            let (valid, invalid) = roots.add_parsable_certificates(parsed);
            if valid == 0 {
                bail!(
                    "PostgreSQL 根证书文件没有可用 CA：{}（有效 0，无效 {invalid}）",
                    path.display()
                );
            }
            if invalid > 0 {
                tracing::warn!(
                    path = %path.display(),
                    invalid,
                    "PostgreSQL 根证书文件部分证书无法解析，已跳过"
                );
            }
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            let loaded = native.certs.len();
            let error_count = native.errors.len();
            let (valid, invalid) = roots.add_parsable_certificates(native.certs);
            if error_count > 0 {
                tracing::warn!(
                    errors = error_count,
                    "加载系统根证书时出现错误，继续使用已成功加载的部分"
                );
            }
            if valid == 0 {
                bail!(
                    "系统根证书为空或无法解析（加载 {loaded}，有效 0，无效 {invalid}，\
                     读取错误 {error_count}）；请安装 CA 证书，或通过 db_sslrootcert 指定私有 CA"
                );
            }
        }
    }

    // 显式固定 ring provider，不依赖进程全局默认，避免被 aws-lc feature 接管。
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("配置 rustls 协议版本失败")?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(dsn: &str, root: Option<&Path>, password: Option<&str>) -> Result<ResolvedDsn> {
        resolve_dsn(dsn, root, password)
    }

    /// `ResolvedDsn` / `MakeRustlsConnect` 都没有 Debug（含密码/连接配置），
    /// 不能用 `expect_err`，这里统一取出错误。
    fn expect_resolve_err(
        dsn: &str,
        root: Option<&Path>,
        password: Option<&str>,
        message: &str,
    ) -> anyhow::Error {
        match resolve_dsn(dsn, root, password) {
            Ok(_) => panic!("{message}"),
            Err(err) => err,
        }
    }

    #[test]
    fn defaults_to_verify_full_and_strips_sslmode() {
        let dsn = "postgres://rustboard:s3cret@127.0.0.1:5432/rustboard?sslmode=verify-full&application_name=hub";
        let resolved = resolve(dsn, None, None).expect("合法 DSN 必须解析成功");
        assert_eq!(resolved.tls_mode, PgTlsMode::VerifyFull);
        assert_eq!(resolved.config.get_ssl_mode(), SslMode::Require);
        assert_eq!(
            resolved.config.get_application_name(),
            Some("hub"),
            "剥离 sslmode 时必须保留其它 query 参数"
        );
        assert!(resolved.redacted.contains("***"));
        assert!(!resolved.redactor.scrub("s3cret").contains("s3cret"));
    }

    #[test]
    fn missing_sslmode_defaults_to_verify_full() {
        let resolved = resolve("postgres://rustboard@127.0.0.1/rustboard", None, None).unwrap();
        assert_eq!(resolved.tls_mode, PgTlsMode::VerifyFull);
        assert_eq!(resolved.config.get_ssl_mode(), SslMode::Require);
    }

    #[test]
    fn explicit_disable_is_accepted_and_reads_percent_encoded_root() {
        let dsn = "postgres://rustboard:pw@127.0.0.1:5432/db?sslmode=disable&sslrootcert=%2Ftmp%2Frb-ca.pem";
        let resolved = resolve(dsn, None, None).unwrap();
        assert_eq!(resolved.tls_mode, PgTlsMode::Disable);
        assert_eq!(resolved.config.get_ssl_mode(), SslMode::Disable);
        assert_eq!(resolved.root.as_deref(), Some(Path::new("/tmp/rb-ca.pem")));
    }

    #[test]
    fn unsupported_ssl_modes_are_rejected_without_leaking_password() {
        for mode in ["require", "prefer", "verify-ca", "allow", "no-verify"] {
            let dsn = format!("postgres://rustboard:topsecret@127.0.0.1:5432/db?sslmode={mode}");
            let err = expect_resolve_err(&dsn, None, None, "非法 sslmode 必须被拒绝");
            let message = format!("{err:#}");
            assert!(
                !message.contains("topsecret"),
                "错误信息泄露密码：{message}"
            );
            assert!(
                message.contains("verify-full") && message.contains("disable"),
                "错误信息应列出允许值：{message}"
            );
        }
    }

    #[test]
    fn duplicate_sslmode_is_rejected() {
        let dsn = "postgres://rustboard:pw@127.0.0.1/db?sslmode=disable&sslmode=verify-full";
        let err = expect_resolve_err(dsn, None, None, "重复 sslmode 必须拒绝");
        assert!(format!("{err:#}").contains("重复"));
    }

    #[test]
    fn invalid_percent_encoding_is_rejected_without_echoing_value() {
        let dsn = "postgres://rustboard:topsecret@127.0.0.1/db?sslmode=%zz";
        let err = expect_resolve_err(dsn, None, None, "非法百分号编码必须拒绝");
        let message = format!("{err:#}");
        assert!(
            !message.contains("topsecret"),
            "错误信息泄露密码：{message}"
        );
    }

    #[test]
    fn config_root_takes_precedence_and_must_match_dsn_root() {
        let dsn = "postgres://rustboard@127.0.0.1/db?sslmode=verify-full&sslrootcert=/tmp/a.pem";
        let resolved = resolve(dsn, Some(Path::new("/tmp/a.pem")), None).unwrap();
        assert_eq!(resolved.root.as_deref(), Some(Path::new("/tmp/a.pem")));

        let err = expect_resolve_err(
            dsn,
            Some(Path::new("/tmp/b.pem")),
            None,
            "两个根证书路径不一致必须拒绝",
        );
        assert!(format!("{err:#}").contains("不同文件"));
    }

    #[test]
    fn env_password_overrides_url_password_and_both_are_redacted() {
        let dsn = "postgres://rustboard:url-secret@127.0.0.1/db?sslmode=disable";
        let resolved = resolve(dsn, None, Some("env-secret")).unwrap();
        assert_eq!(
            resolved.config.get_password(),
            Some(b"env-secret".as_slice()),
            "环境变量必须覆盖 URL 密码"
        );
        let scrubbed = resolved.redactor.scrub("url-secret env-secret");
        assert!(!scrubbed.contains("url-secret"));
        assert!(!scrubbed.contains("env-secret"));
    }

    #[test]
    fn empty_env_password_does_not_override_url_password() {
        let dsn = "postgres://rustboard:url-secret@127.0.0.1/db?sslmode=disable";
        let resolved = resolve(dsn, None, Some("")).unwrap();
        assert_eq!(
            resolved.config.get_password(),
            Some(b"url-secret".as_slice())
        );
    }

    #[test]
    fn keyword_dsn_form_is_rejected() {
        let err = expect_resolve_err(
            "host=127.0.0.1 user=rustboard password=topsecret dbname=db",
            None,
            None,
            "keyword 形式必须拒绝",
        );
        assert!(!format!("{err:#}").contains("topsecret"));
    }

    #[test]
    fn options_debug_redacts_password() {
        let options = PostgresOptions {
            dsn: "postgres://rustboard:topsecret@127.0.0.1/db?sslmode=disable".to_string(),
            pool_size: 8,
            connect_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(30),
            sslrootcert: None,
        };
        let debug = format!("{options:?}");
        assert!(!debug.contains("topsecret"), "Debug 泄露密码：{debug}");
        assert!(
            debug.contains("dsn: \"<redacted>\""),
            "dsn 必须固定输出占位符：{debug}"
        );
        // 不输出 URL 的任何部分：scheme/user/host/port/db/query 都不能出现。
        for fragment in [
            "postgres://",
            "postgresql://",
            "rustboard",
            "127.0.0.1",
            "sslmode",
        ] {
            assert!(
                !debug.contains(fragment),
                "Debug 泄露 URL 片段 {fragment}：{debug}"
            );
        }
    }

    #[test]
    fn root_cert_symlink_and_non_regular_file_are_rejected() {
        let unique = format!(
            "rb-postgres-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).expect("创建临时目录失败");
        let regular = dir.join("ca.pem");
        std::fs::write(&regular, b"-----BEGIN CERTIFICATE-----\nnot-a-cert\n")
            .expect("写入临时证书文件失败");

        // 普通文件（即使内容非法）应进入 PEM 解析，而不是被文件类型检查拒绝。
        let err = match build_rustls_connector(Some(&regular)) {
            Ok(_) => panic!("非法 PEM 内容必须解析失败"),
            Err(err) => err,
        };
        let message = format!("{err:#}");
        assert!(
            !message.contains("普通文件") && !message.contains("符号链接"),
            "普通文件不应被文件类型检查拒绝：{message}"
        );
        assert!(message.contains("根证书"), "错误应指出根证书：{message}");

        // 目录不是普通文件。
        let err = match build_rustls_connector(Some(&dir)) {
            Ok(_) => panic!("目录不能作为根证书"),
            Err(err) => err,
        };
        let message = format!("{err:#}");
        assert!(message.contains("普通文件"), "目录必须被拒绝：{message}");
        assert!(message.contains(&dir.display().to_string()));

        #[cfg(unix)]
        {
            let link = dir.join("ca-link.pem");
            std::os::unix::fs::symlink(&regular, &link).expect("创建符号链接失败");
            let err = match build_rustls_connector(Some(&link)) {
                Ok(_) => panic!("符号链接不能作为根证书"),
                Err(err) => err,
            };
            let message = format!("{err:#}");
            assert!(
                message.contains("符号链接"),
                "符号链接必须被拒绝：{message}"
            );
            assert!(message.contains(&link.display().to_string()));
        }

        std::fs::remove_dir_all(&dir).expect("清理临时目录失败");
    }

    #[test]
    fn open_from_config_rejects_sqlite_database() {
        let cfg = HubConfig::default();
        let err = PostgresStorage::open_from_config(&cfg)
            .expect_err("SQLite 配置不能打开 PostgresStorage");
        assert!(format!("{err:#}").contains("不是 PostgreSQL"));
    }

    #[test]
    fn invalid_root_file_is_reported_without_touching_database() {
        let err =
            match build_rustls_connector(Some(Path::new("/nonexistent/rustboard-test-ca.pem"))) {
                Ok(_) => panic!("不存在的根证书必须失败"),
                Err(err) => err,
            };
        let message = format!("{err:#}");
        assert!(
            message.contains("根证书"),
            "错误信息应指出根证书：{message}"
        );
    }

    #[test]
    fn invalid_pool_size_is_rejected() {
        let options = PostgresOptions {
            dsn: "postgres://rustboard@127.0.0.1/db?sslmode=disable".to_string(),
            pool_size: 0,
            connect_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(30),
            sslrootcert: None,
        };
        let err = PostgresStorage::open(options).expect_err("pool_size=0 必须拒绝");
        assert!(format!("{err:#}").contains("db_pool_size"));
    }

    fn driver_password(dsn: &str) -> Option<String> {
        let config: postgres::Config = dsn.parse().expect("测试 DSN 必须能被驱动解析");
        config
            .get_password()
            .map(|password| String::from_utf8(password.to_vec()).expect("测试密码是 UTF-8"))
    }

    /// #64：外部工具的有效密码必须与真实 `postgres::Config` 完全一致。
    #[test]
    fn external_tool_password_matches_driver_priority() {
        for (dsn, expected) in [
            // authority-only
            (
                "postgres://u:auth-secret@h/db?sslmode=disable",
                "auth-secret",
            ),
            // query-only
            (
                "postgres://u@h/db?password=query-secret&sslmode=disable",
                "query-secret",
            ),
            // 两处都有：query 覆盖 authority
            (
                "postgres://u:auth-secret@h/db?password=query-secret&sslmode=disable",
                "query-secret",
            ),
            // 重复 query：后者覆盖
            (
                "postgres://u@h/db?password=first&password=second&sslmode=disable",
                "second",
            ),
            // 参数名百分号编码
            (
                "postgres://u:auth-secret@h/db?pass%77ord=encoded-key&sslmode=disable",
                "encoded-key",
            ),
            (
                "postgres://u@h/db?%70assword=encoded-query&sslmode=disable",
                "encoded-query",
            ),
        ] {
            assert_eq!(
                driver_password(dsn).as_deref(),
                Some(expected),
                "前提：驱动对 {dsn} 的有效密码"
            );
            let resolved =
                resolve_external_tool_dsn_with_env(dsn, None, None).expect("合法 DSN 必须解析成功");
            assert_eq!(
                resolved.url_password.as_deref(),
                Some(expected),
                "外部工具 URL 密码必须与驱动一致: {dsn}"
            );
            assert_eq!(
                resolved.effective_password.as_deref(),
                Some(expected),
                "无 env 时有效密码必须与驱动一致: {dsn}"
            );
            for secret in [
                "auth-secret",
                "query-secret",
                "first",
                "second",
                "encoded-key",
                "encoded-query",
            ] {
                assert!(
                    !resolved.sanitized.contains(secret),
                    "sanitized DSN 泄露密码 {secret}: {}",
                    resolved.sanitized
                );
            }
            assert!(
                !resolved.sanitized.contains("password="),
                "{}",
                resolved.sanitized
            );
        }
    }

    /// #64：非空环境变量覆盖后的有效密码与驱动一致；空串不覆盖。
    #[test]
    fn external_tool_env_password_matches_driver_override() {
        let dsn = "postgres://u:url-secret@h/db?password=query-secret&sslmode=disable";
        let mut driver: postgres::Config = dsn.parse().unwrap();
        driver.password("env-secret");
        assert_eq!(
            driver
                .get_password()
                .map(|password| String::from_utf8(password.to_vec()).unwrap()),
            Some("env-secret".to_string())
        );
        let resolved = resolve_external_tool_dsn_with_env(dsn, None, Some("env-secret")).unwrap();
        assert_eq!(resolved.effective_password.as_deref(), Some("env-secret"));
        assert_eq!(resolved.url_password.as_deref(), Some("query-secret"));

        let empty = resolve_external_tool_dsn_with_env(dsn, None, Some("")).unwrap();
        assert_eq!(empty.effective_password.as_deref(), Some("query-secret"));
        for secret in ["url-secret", "query-secret", "env-secret"] {
            assert!(!resolved.sanitized.contains(secret));
        }
    }

    /// #64：`sslpassword` 从 DSN 剥离（单独通过 PGSSLPASSWORD 传递）。
    #[test]
    fn external_tool_strips_sslpassword_from_dsn() {
        let dsn = "postgres://u:p@h/db?sslpassword=ssl-secret&application_name=hub&sslmode=disable";
        let resolved = resolve_external_tool_dsn_with_env(dsn, None, None).unwrap();
        assert_eq!(resolved.sslpassword.as_deref(), Some("ssl-secret"));
        assert!(!resolved.sanitized.contains("sslpassword"));
        assert!(!resolved.sanitized.contains("ssl-secret"));
        assert!(resolved.sanitized.contains("application_name=hub"));
    }

    /// P1 复审：密码含裸 `/` 且数字前缀像端口时，argv DSN 必须仍能剥离密码。
    #[test]
    fn external_tool_strips_raw_slash_password_from_argv_dsn() {
        for (dsn, password, expected) in [
            (
                "postgres://rb_user:2024/secret@127.0.0.1:1/db?sslmode=disable",
                "2024/secret",
                "postgres://rb_user@127.0.0.1:1/db",
            ),
            (
                "postgres://rb_user:99999/secret@127.0.0.1:1/db?sslmode=disable",
                "99999/secret",
                "postgres://rb_user@127.0.0.1:1/db",
            ),
            (
                "postgres://us/er:s3cret@host/db",
                "s3cret",
                "postgres://us/er@host/db",
            ),
        ] {
            let resolved = resolve_external_tool_dsn_with_env(dsn, None, None)
                .expect("裸 / 密码 DSN 必须可安全剥离");
            assert_eq!(
                resolved.sanitized, expected,
                "argv DSN 不符合预期: dsn={dsn}"
            );
            for secret in [password, "secret", "s3cret"] {
                assert!(
                    !resolved.sanitized.contains(secret),
                    "argv DSN 泄露 {secret}: {}",
                    resolved.sanitized
                );
            }
            let reparsed: postgres::Config =
                resolved.sanitized.parse().expect("sanitized 必须可解析");
            assert!(reparsed.get_password().is_none());
        }

        // 多个裸 @：无法判断 userinfo 边界，必须在 spawn 前拒绝。
        let err = match resolve_external_tool_dsn_with_env(
            "postgres://u:pa@ss@host/db?sslmode=disable",
            None,
            None,
        ) {
            Ok(_) => panic!("多个裸 @ 必须拒绝"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("多个裸 @"));
        assert!(!format!("{err:#}").contains("pa"));
    }

    /// #67：外部工具 TLS 策略与运行连接一致：缺省 verify-full、显式 disable、
    /// DSN/配置根 CA 冲突校验。
    #[test]
    fn external_tool_tls_matches_runtime_policy() {
        let dsn = "postgres://u:p@h/db?sslrootcert=%2Ftmp%2Frb-ca.pem";
        let resolved = resolve_external_tool_dsn_with_env(dsn, None, None).unwrap();
        assert_eq!(resolved.sslmode, "verify-full");
        assert_eq!(
            resolved.sslrootcert.as_deref(),
            Some(Path::new("/tmp/rb-ca.pem"))
        );
        assert!(!resolved.sanitized.contains("sslrootcert"));
        assert!(!resolved.sanitized.contains("sslmode"));

        // 配置根与 DSN 根不一致：与运行连接相同的错误。
        let err = match resolve_external_tool_dsn_with_env(
            dsn,
            Some(Path::new("/tmp/other-ca.pem")),
            None,
        ) {
            Ok(_) => panic!("根证书冲突必须拒绝"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("不同文件"));

        // 显式 disable 才 disable，且根证书不再传给外部工具。
        let disabled = resolve_external_tool_dsn_with_env(
            "postgres://u:p@h/db?sslmode=disable&sslrootcert=%2Ftmp%2Frb-ca.pem",
            None,
            None,
        )
        .unwrap();
        assert_eq!(disabled.sslmode, "disable");
        assert!(disabled.sslrootcert.is_none());

        // require/prefer 会静默降级，必须与运行连接一样拒绝。
        for mode in ["require", "prefer", "verify-ca"] {
            let dsn = format!("postgres://u:topsecret@h/db?sslmode={mode}");
            let err = match resolve_external_tool_dsn_with_env(&dsn, None, None) {
                Ok(_) => panic!("{mode} 必须拒绝"),
                Err(err) => err,
            };
            let message = format!("{err:#}");
            assert!(message.contains("verify-full") && message.contains("disable"));
            assert!(!message.contains("topsecret"), "错误泄露密码: {message}");
        }
    }
}
