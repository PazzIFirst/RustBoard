//! PostgreSQL 后端（M5 Phase D）。
//!
//! D2 落地 schema/migration：[`schema::apply_schema`] 建 21 张表与 19 个命名
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

    /// 在池内连接上幂等应用 schema v8。
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
    let root = match (config_root, query_root) {
        (Some(config_path), Some(query_path)) if config_path != query_path => bail!(
            "db_sslrootcert 与 DSN 中的 sslrootcert 指向不同文件；\
             请只保留一处配置，或让两处指向同一 PEM 文件"
        ),
        (Some(config_path), _) => Some(config_path.to_path_buf()),
        (None, query_root) => query_root,
    };

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
}
