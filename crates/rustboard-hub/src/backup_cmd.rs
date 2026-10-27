//! `rustboard-hub backup / restore`（M5 Phase D5b）。
//!
//! 设计约束：
//!
//! - SQLite 用 `VACUUM INTO` 生成一致快照；PG 用 `pg_dump --format=custom` /
//!   `pg_restore`。外部命令一律用参数数组，绝不拼 shell；
//! - `pg_dump` / `pg_restore` 的 `--dbname` 参数**不含密码**：密码从 DSN 中
//!   提取后只通过 `PGPASSWORD` / `PGSSLPASSWORD` 环境变量传递；
//! - 外部工具继承 Hub 的 PostgreSQL TLS 策略：`PGSSLMODE` 缺省 `verify-full`，
//!   只有显式 `sslmode=disable` 才关闭；根 CA 通过 `PGSSLROOTCERT` 传递，
//!   并清理会改变策略的继承环境（`PGSERVICE`/`PGREQUIRESSL` 等）；
//! - 备份目录 `<out>/<UTC timestamp>/`，内部 `manifest.json` 记录版本、schema、
//!   后端、创建时间与每个文件的 SHA256/大小；配置与证书 0600、目录 0700；
//! - 复制证书与 `rotate-cert`/ACME 使用同一把 `CertLock`；复制后校验
//!   server 证书/私钥与 CA 证书/私钥配套，失败不生成 manifest；
//! - 恢复前校验 manifest 里每个文件的 SHA256 与大小，只接受相对、无 `..`、
//!   无符号链接的路径；恢复证书前再次校验配套，失败不覆盖现有材料；
//!   恢复前尽可能备份当前目标；恢复配置/证书是显式行为；
//! - v1.0.0 只支持全新安装：manifest schema 不是 v9 的备份一律在写目标前拒绝；
//! - 错误信息不输出 DSN 密码；日志只出现 `user:***@host`。

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rusqlite::{Connection as SqliteConnection, OpenFlags};
use rustboard_common::config::{redact_database_url, DatabaseKind, HubConfig};
use rustboard_common::fsutil;
use rustboard_common::tls;
use rustboard_common::util::now_ms;
use rustboard_common::DEFAULT_HUB_CONFIG;
use rustboard_core::storage::postgres::{
    connect_with_config, resolve_external_tool_dsn, validate_postgres_schema_v9, PostgresStorage,
    POSTGRES_SCHEMA_VERSION,
};
use rustboard_install::Prompt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::cert_rotation::{CertLock, CERT_LOCK_FILE};

/// manifest 格式版本；恢复只接受完全匹配的版本，避免未来格式被旧二进制误读。
const MANIFEST_VERSION: u32 = 1;
/// 本程序支持的 SQLite schema 版本（与 core 的 `SQLITE_SCHEMA_VERSION` 对齐）。
pub(crate) const SQLITE_SCHEMA_VERSION: i64 = 9;
/// 备份/恢复时单个外部命令输出的最大收集长度，避免故障时把巨量日志读入内存。
const MAX_TOOL_OUTPUT: usize = 8 * 1024;
/// 等待证书轮换锁的间隔：与 rotate/ACME 的 flock 冲突时最多等待 5s。
const CERT_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);
/// 等待证书轮换锁的总时长；超时 fail closed，绝不绕过锁复制证书。
const CERT_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
/// 外部工具继承环境里会改变 PostgreSQL 连接/降级 TLS 的变量。
///
/// - `PGSSLMODE` / `PGSSLROOTCERT`：每处调用都由本模块显式设置；
/// - `PGPASSWORD` / `PGSSLPASSWORD`：无密码时必须清除宿主的旧值；
/// - `PGREQUIRESSL`：旧版 libpq 的隐式 SSL 要求，会与显式 `sslmode` 混淆；
/// - `PGSERVICE` / `PGSERVICEFILE`：service 文件可注入另一套 sslmode/rootcert；
/// - `PGSSLNEGOTIATION`：PG17 direct TLS 协商方式，避免继承意外配置；
/// - `PGUSER/PGHOST/PGPORT/PGDATABASE`：连接目标只由 DSN 决定；
/// - `PGPASSFILE/PGSSLCERT/PGSSLKEY/PGOPTIONS`：避免宿主密码文件或客户端证书
///   参与本次连接（会改变认证/信任行为）。
const PG_TOOL_ENV_CLEAR: [&str; 16] = [
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGPASSWORD",
    "PGSSLPASSWORD",
    "PGREQUIRESSL",
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGSSLNEGOTIATION",
    "PGUSER",
    "PGHOST",
    "PGPORT",
    "PGDATABASE",
    "PGPASSFILE",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGOPTIONS",
];

/// hub schema v9 的 22 张业务表。
///
/// 与 `rustboard-core/src/storage/postgres/schema.rs` 的 `TABLES` 保持一致；
/// 只用于 `--force` 前确认目标库没有未知表，以及在迁移 CLIs 中展示。若核心
/// 新增表而这里没更新，`--force` 会因「未知表」拒绝清空，属于 fail-closed。
pub(crate) const HUB_TABLES: [&str; 22] = [
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

/// `rustboard-hub backup` 参数。
#[derive(Args, Debug)]
pub struct BackupArgs {
    /// 备份根目录；实际生成 `<out>/<timestamp>/`。
    #[arg(long, value_name = "DIR")]
    pub out: PathBuf,
    /// hub 配置文件；默认 `/etc/rustboard/hub.toml`。
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// 非交互执行（不读取 stdin）。
    #[arg(long)]
    pub yes: bool,
}

/// `rustboard-hub restore` 参数。
#[derive(Args, Debug)]
pub struct RestoreArgs {
    /// 备份目录（包含 `manifest.json` 的 timestamp 目录）。
    #[arg(long, value_name = "DIR")]
    pub from: PathBuf,
    /// hub 配置文件；默认 `/etc/rustboard/hub.toml`。
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// 配置文件不存在时的目标 data_dir（必须绝对路径；SQLite 的 DB 固定为该目录下 rustboard.db）。
    #[arg(long, value_name = "DIR")]
    pub data_dir: Option<PathBuf>,
    /// 配置文件不存在且恢复 PostgreSQL 备份时的目标 DSN。
    #[arg(long, value_name = "DSN")]
    pub db: Option<String>,
    /// 目标非空时仍恢复（必须先成功备份当前目标）。
    #[arg(long)]
    pub force: bool,
    /// 显式跳过恢复前目标备份（不推荐；仅在目标非空时相关）。
    #[arg(long)]
    pub no_pre_restore_backup: bool,
    /// 显式声明 hub 已停止（无 systemd / unit 不存在时必须提供）。
    #[arg(long)]
    pub hub_stopped: bool,
    /// 非交互执行（不读取 stdin）。
    #[arg(long)]
    pub yes: bool,
}

/// manifest 中的一个文件。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManifestFile {
    /// 相对备份目录的路径，例如 `rustboard.db` / `certs/server.key`。
    path: String,
    /// 小写 hex SHA256。
    sha256: String,
    /// 字节数。
    size: u64,
    /// Unix 权限（四位八进制字符串，例如 `0600`）。
    mode: String,
}

/// `manifest.json`。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Manifest {
    /// manifest 格式版本。
    manifest_version: u32,
    /// 生成备份的 RustBoard 版本。
    version: String,
    /// 备份时数据库 schema 版本。
    schema: i64,
    /// `sqlite` 或 `postgres`。
    backend: String,
    /// RFC3339 UTC 时间。
    created_at: String,
    /// Unix 毫秒时间戳。
    created_at_ms: i64,
    /// 备份文件清单（按路径排序）。
    files: Vec<ManifestFile>,
}

/// 解析配置 TOML，错误信息固定为「路径 + TOML 解析失败」。
///
/// `toml::de::Error` 的 `Display` 会带出源码行/片段，而 `hub.toml` 可能含
/// `admin_token`、数据库密码等敏感值；这里丢弃底层错误，只保留可排障的路径，
/// 与安装器 `load_hub_config_checked` 的脱敏策略一致。
pub(crate) fn parse_toml_sanitized<T>(text: &str, path: &Path) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    toml::from_str(text).map_err(|_| {
        anyhow!(
            "TOML 解析失败: {}（已隐藏原始配置内容与解析位置，避免泄露 token/密码）",
            path.display()
        )
    })
}

/// 读取配置文件，返回原始字节与解析结果。
///
/// 与 `HubConfig::load` 的区别：**不 chmod** 配置文件，也不在读取阶段产生任何
/// 磁盘副作用。备份需要保留原始字节（TOML 注释/顺序），迁移失败时也要求配置
/// 字节完全不变。
pub(crate) fn load_config_snapshot(path: &Path) -> Result<(Vec<u8>, HubConfig)> {
    let meta = fs::symlink_metadata(path).with_context(|| {
        format!(
            "读取配置失败: {}（先执行 rustboard-hub init）",
            path.display()
        )
    })?;
    if meta.file_type().is_symlink() {
        bail!("配置文件是符号链接，拒绝读取: {}", path.display());
    }
    if !meta.is_file() {
        bail!("配置文件不是普通文件: {}", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("读取配置失败: {}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("配置文件不是合法 UTF-8: {}", path.display()))?;
    let cfg: HubConfig = parse_toml_sanitized(text, path)?;
    Ok((bytes, cfg))
}

/// 解析 `--config`：默认 `/etc/rustboard/hub.toml`。
pub(crate) fn config_path(config: Option<PathBuf>) -> PathBuf {
    config.unwrap_or_else(|| PathBuf::from(DEFAULT_HUB_CONFIG))
}

/// 确认问题；`--yes` 直接视为同意。非 TTY 且没有 `--yes` 时返回错误。
pub(crate) fn confirm(yes: bool, question: &str) -> Result<()> {
    if yes {
        return Ok(());
    }
    let prompt = Prompt::new(false);
    if !prompt.confirm(question, true)? {
        bail!("已取消");
    }
    Ok(())
}

/// `backup` 子命令。
pub fn backup(args: BackupArgs) -> Result<()> {
    let config_path = config_path(args.config);
    validate_user_path(&args.out, "备份输出目录")?;
    let (config_bytes, cfg) = load_config_snapshot(&config_path)?;
    let kind = cfg.database_kind().context("解析 database 配置失败")?;
    // 防止 --out 落在证书目录内：复制 certs 时会把自己的输出目录再递归复制。
    let out_abs = std::path::absolute(&args.out)
        .with_context(|| format!("解析备份输出目录失败: {}", args.out.display()))?;
    let certs_abs = std::path::absolute(tls::cert_dir(&cfg.data_dir))
        .with_context(|| format!("解析证书目录失败: {}", cfg.data_dir.display()))?;
    if out_abs.starts_with(&certs_abs) {
        bail!(
            "备份输出目录不能位于证书目录内（{}）；请改用 data_dir 之外的目录",
            certs_abs.display()
        );
    }
    // 外部工具在创建目录前检查：缺 pg_dump 时不留下半成品目录。
    if matches!(kind, DatabaseKind::Postgres(_)) {
        ensure_tool("pg_dump")?;
    }
    confirm(
        args.yes,
        &format!(
            "将在 {} 下创建 {} 备份，继续？",
            args.out.display(),
            backend_name(&kind)
        ),
    )?;
    let dir = snapshot_to(&args.out, &cfg, &config_bytes, false)?;
    let manifest = read_manifest(&dir)?;
    println!("备份完成: {}", dir.display());
    println!(
        "后端: {}；schema: {}；文件: {} 个",
        backend_name(&kind),
        manifest.schema,
        manifest.files.len()
    );
    Ok(())
}

/// `restore` 子命令。
pub fn restore(args: RestoreArgs) -> Result<()> {
    let config_path = std::path::absolute(config_path(args.config.clone()))
        .context("解析 --config 绝对路径失败")?;
    validate_user_path(&args.from, "备份源目录")?;
    let from_meta = fs::symlink_metadata(&args.from)
        .with_context(|| format!("备份目录不存在: {}", args.from.display()))?;
    if from_meta.file_type().is_symlink() || !from_meta.is_dir() {
        bail!("备份源必须是普通目录: {}", args.from.display());
    }

    // 1. 先完整校验 manifest 与所有文件哈希，任何失败都在写目标前返回。
    let manifest = read_manifest(&args.from)?;
    if manifest.manifest_version != MANIFEST_VERSION {
        bail!(
            "备份 manifest 版本 {} 不受支持（当前支持 {}）",
            manifest.manifest_version,
            MANIFEST_VERSION
        );
    }
    let backend = parse_backend(&manifest.backend)?;
    validate_manifest_schema(backend, manifest.schema)?;
    let verified = verify_manifest_files(&args.from, &manifest)?;
    let config_rel = verified
        .get("hub.toml")
        .ok_or_else(|| anyhow!("备份缺少 hub.toml（不完整的备份不能恢复）"))?;
    let db_name = database_file_name(backend);
    if !verified.contains_key(db_name) {
        bail!("备份缺少数据库文件 {db_name}（不完整的备份不能恢复）");
    }
    // 证书配套校验必须在任何目标写入（包括 pre-restore 备份/配置 .bak）之前。
    validate_backup_cert_material(&args.from, &manifest)?;
    // 不能只信 manifest 的 schema 字段：直接校验备份数据库本身是 v9 且
    // 22 张业务表齐全，失败时不写目标、不做 pre-restore 覆盖。
    if backend == Backend::Sqlite {
        sqlite_assert_v9(&verified[db_name], "备份中的 SQLite ")?;
    }
    let backup_config_bytes = fs::read(config_rel)?;
    let backup_config_text =
        std::str::from_utf8(&backup_config_bytes).context("备份中的 hub.toml 不是合法 UTF-8")?;
    let backup_cfg: HubConfig = parse_toml_sanitized(backup_config_text, config_rel)?;
    let backup_kind = backup_cfg
        .database_kind()
        .context("备份中的 database 配置非法")?;
    if backend != backend_of(&backup_kind) {
        bail!(
            "备份 backend={} 与备份配置中的 database 不一致（{}）",
            manifest.backend,
            backup_kind.redacted()
        );
    }

    // 2. 目标路径只信任本机当前配置 / 显式 CLI 参数，**绝不**用备份内
    //    hub.toml 的 data_dir/database 作为写入目标。恶意备份即使 manifest
    //    哈希自洽，也只能恢复到当前安装的目标路径。
    let current = load_optional_config_snapshot(&config_path)?;
    let (target_cfg, target_config_bytes) = resolve_restore_target(
        &args,
        &config_path,
        config_rel,
        &backup_cfg,
        &backup_config_bytes,
        backend,
        current.as_ref(),
    )?;
    let target_kind = target_cfg
        .database_kind()
        .context("解析恢复目标 database 失败")?;
    if backend_of(&target_kind) != backend {
        bail!(
            "备份 backend={} 与恢复目标 backend={} 不一致；不支持跨后端恢复，请恢复同一后端的备份",
            manifest.backend,
            backend_name(&target_kind)
        );
    }
    if !target_cfg.data_dir.is_absolute() {
        bail!(
            "恢复目标 data_dir 必须是绝对路径: {}；请修正当前配置或 --data-dir",
            target_cfg.data_dir.display()
        );
    }
    validate_user_path(&target_cfg.data_dir, "目标 data_dir")?;
    if let DatabaseKind::Sqlite(path) = &target_kind {
        if !path.is_absolute() {
            bail!(
                "恢复目标 SQLite 路径必须是绝对路径: {}；拒绝恢复",
                path.display()
            );
        }
        validate_user_path(path, "目标 SQLite 数据库")?;
        // 不能带着旧 WAL/SHM/journal 覆盖主库：SQLite 下次打开会重放旧 WAL，
        // 可能把新库覆盖成旧数据。必须先干净停机并人工确认/清理。
        ensure_no_sqlite_sidecars(path)?;
    }
    let certs_dst = tls::cert_dir(&target_cfg.data_dir);
    println!("恢复目标配置: {}", config_path.display());
    println!("恢复目标证书目录: {}", certs_dst.display());
    match &target_kind {
        DatabaseKind::Sqlite(path) => println!("恢复目标数据库: {}", path.display()),
        DatabaseKind::Postgres(dsn) => {
            println!("恢复目标数据库: {}", dsn_redacted(dsn));
        }
    }

    // 3. 外部工具预检（PG 恢复必须在写入任何文件前失败）。
    if backend == Backend::Postgres {
        ensure_tool("pg_restore")?;
    }

    // 4. 检查目标是否可覆盖。
    let target_non_empty = target_has_data(&target_cfg, &target_kind)
        .with_context(|| format!("检查恢复目标是否为空失败（{}）", target_kind.redacted()))?;
    if target_non_empty && !args.force {
        bail!(
            "恢复目标非空（{}）；请先备份并使用 --force，或恢复到一个空数据库",
            target_kind.redacted()
        );
    }

    // 5. 运行中的 hub 会持续写数据库，恢复会与写入竞争；与 migrate 同样拒绝。
    super::migrate_cmd::ensure_hub_stopped("restore", args.hub_stopped)?;

    // 6. 目标路径安全检查必须在任何破坏性写入之前完成。
    reject_existing_symlinks(&certs_dst)?;
    reject_existing_symlinks(&config_path)?;
    if let DatabaseKind::Sqlite(path) = &target_kind {
        reject_existing_symlinks(path)?;
    }

    // 7. 确认。
    let action = if target_non_empty {
        "恢复目标非空：将先备份当前目标，再覆盖数据库/配置/证书"
    } else {
        "将恢复数据库/配置/证书到目标位置"
    };
    confirm(
        args.yes,
        &format!(
            "从 {} 恢复 {} 备份？{action}。",
            args.from.display(),
            backend_name(&target_kind)
        ),
    )?;

    // 8. 配置 .bak 在数据恢复前写好：它失败时目标库/证书尚未被改动。
    let config_bak = match &current {
        Some((current_bytes, _)) => Some(backup_file_next_to(&config_path, current_bytes, "bak")?),
        None => None,
    };

    // 9. 非空目标必须先成功备份当前目标；失败立即中止，不做 best-effort 继续。
    //    只有显式 --no-pre-restore-backup 才允许在无备份的情况下覆盖。
    if target_non_empty && args.no_pre_restore_backup {
        eprintln!(
            "WARN: 已显式指定 --no-pre-restore-backup，跳过恢复前目标备份；\
             目标非空，覆盖后无法用本工具回滚"
        );
    } else if target_non_empty {
        let pre_bytes = current
            .as_ref()
            .map(|(bytes, _)| bytes.clone())
            .unwrap_or_else(|| target_config_bytes.clone());
        let path = pre_restore_snapshot(&target_cfg, &pre_bytes)
            .context("恢复前备份当前目标失败；已中止（未修改目标数据库/证书/配置）")?;
        println!("恢复前目标备份: {}", path.display());
    }

    // 10. 预检/预备份可能由只读连接创建空 sidecar；rename 前清掉。
    if let DatabaseKind::Sqlite(path) = &target_kind {
        remove_restore_sidecars(path)
            .context("清理恢复前只读检查产生的 SQLite sidecar 失败；已中止")?;
    }

    // 10.4 目标写入前重验 manifest：缩小“入口校验后被替换备份文件”的 TOCTOU
    //      窗口；失败时尚未替换目标数据库/证书/配置。
    verify_manifest_files(&args.from, &manifest)?;

    // 10.5 证书锁提前到数据库替换之前：DB 恢复成功、证书写入前不允许
    //      rotate-cert/ACME 换掉目标证书材料。必须在 pre-restore 快照之后取锁，
    //      否则快照自身的 CertLock 会与之冲突。
    let cert_lock = if manifest_cert_paths(&manifest)?.is_empty() {
        None
    } else {
        reject_existing_symlinks(&certs_dst)?;
        fsutil::ensure_dir(&certs_dst, 0o700)
            .with_context(|| format!("创建目标证书目录失败: {}", certs_dst.display()))?;
        Some(acquire_cert_lock_bounded(&certs_dst)?)
    };

    // 11. 先恢复数据，再恢复证书，最后写配置（配置决定下次启动读哪里）。
    match &target_kind {
        DatabaseKind::Sqlite(path) => {
            restore_sqlite_file(&verified[db_name], path)
                .with_context(|| format!("恢复 SQLite 数据库失败: {}", path.display()))?;
            println!("SQLite 数据库已恢复: {}", path.display());
        }
        DatabaseKind::Postgres(dsn) => {
            pg_restore_from(&target_cfg, dsn, &verified[db_name])?;
            // 不能只信 manifest：pg_restore 后直接校验目标真实 schema
            // （MAX(version)==9、22 表、23 索引），失败时不写证书/配置。
            validate_postgres_schema_v9(&target_cfg, dsn).with_context(|| {
                "PostgreSQL 恢复后 schema 校验失败；未恢复证书、未切换配置文件，请检查备份"
            })?;
            println!("PostgreSQL 数据库已恢复: {}", dsn_redacted(dsn));
        }
    }

    restore_certs(
        &args.from,
        &manifest,
        &target_cfg.data_dir,
        cert_lock.as_ref(),
    )?;
    drop(cert_lock);
    println!("证书目录已恢复: {}", certs_dst.display());

    // 配置写最后：数据/证书失败时旧配置仍指向旧路径，避免启动到半恢复状态。
    write_private_file(&config_path, &target_config_bytes)?;
    if let Some(path) = config_bak {
        println!("旧配置备份: {}", path.display());
    }
    println!("配置文件已恢复: {}", config_path.display());

    Ok(())
}

/// 解析恢复目标：只使用本机当前 `hub.toml` 或显式 CLI 参数，忽略备份内的路径。
fn resolve_restore_target(
    args: &RestoreArgs,
    config_path: &Path,
    backup_config_path: &Path,
    backup_cfg: &HubConfig,
    backup_config_bytes: &[u8],
    backend: Backend,
    current: Option<&(Vec<u8>, HubConfig)>,
) -> Result<(HubConfig, Vec<u8>)> {
    let (target_data_dir, target_database, mut target_cfg) = match current {
        Some((_, cfg)) => {
            if args.data_dir.is_some() || args.db.is_some() {
                bail!(
                    "配置文件已存在（{}），恢复目标以该配置为准；不要同时指定 --data-dir/--db",
                    config_path.display()
                );
            }
            (cfg.data_dir.clone(), cfg.database.clone(), cfg.clone())
        }
        None => {
            let data_dir = args.data_dir.clone().ok_or_else(|| {
                anyhow!(
                    "配置文件不存在（{}），必须指定 --data-dir <绝对路径> 作为恢复目标",
                    config_path.display()
                )
            })?;
            if !data_dir.is_absolute() {
                bail!("--data-dir 必须是绝对路径: {}", data_dir.display());
            }
            let database = match backend {
                Backend::Sqlite => {
                    if args.db.is_some() {
                        bail!(
                            "恢复 SQLite 备份时 DB 路径固定为 <data-dir>/rustboard.db，不接受 --db"
                        );
                    }
                    format!("sqlite://{}", data_dir.join("rustboard.db").display())
                }
                Backend::Postgres => args.db.clone().ok_or_else(|| {
                    anyhow!(
                        "配置文件不存在且恢复 PostgreSQL 备份时必须指定 --db <DSN> 作为恢复目标"
                    )
                })?,
            };
            let mut cfg = backup_cfg.clone();
            cfg.data_dir = data_dir.clone();
            cfg.database = database.clone();
            (data_dir, database, cfg)
        }
    };
    let kind = target_cfg
        .database_kind()
        .context("解析恢复目标 database 失败")?;
    if backend_of(&kind) != backend {
        bail!(
            "恢复目标 database 是 {}，与备份 backend={} 不一致",
            kind.redacted(),
            backend_name_of(backend)
        );
    }
    let bytes = rewrite_config_paths(
        backup_cfg,
        backup_config_path,
        backup_config_bytes,
        &target_data_dir,
        &target_database,
    )?;
    target_cfg.data_dir = target_data_dir;
    target_cfg.database = target_database;
    Ok((target_cfg, bytes))
}

/// 只把备份配置里的 `data_dir` / `database` 重写为目标值，其余字段（含未知字段）
/// 保留；两个值本来就相等时直接复用备份原始字节，保留注释与排版。
fn rewrite_config_paths(
    backup_cfg: &HubConfig,
    backup_config_path: &Path,
    backup_bytes: &[u8],
    data_dir: &Path,
    database: &str,
) -> Result<Vec<u8>> {
    if backup_cfg.data_dir == data_dir && backup_cfg.database == database {
        return Ok(backup_bytes.to_vec());
    }
    let data_dir_text = data_dir
        .to_str()
        .ok_or_else(|| anyhow!("目标 data_dir 不是合法 UTF-8: {}", data_dir.display()))?;
    let text = std::str::from_utf8(backup_bytes).context("备份中的 hub.toml 不是合法 UTF-8")?;
    let mut value: toml::Value = parse_toml_sanitized(text, backup_config_path)?;
    let table = value
        .as_table_mut()
        .ok_or_else(|| anyhow!("备份中的 hub.toml 顶层不是 TOML table"))?;
    table.insert(
        "data_dir".to_string(),
        toml::Value::String(data_dir_text.to_string()),
    );
    table.insert(
        "database".to_string(),
        toml::Value::String(database.to_string()),
    );
    Ok(toml::to_string_pretty(&value)
        .context("序列化恢复后的 hub.toml 失败")?
        .into_bytes())
}

/// 把 manifest、DB、配置和证书写入 `<out_root>/<timestamp>/`，返回目录。
///
/// 仅供 `backup`、`migrate` 与 restore 的 best-effort 预备份使用；调用方负责
/// 确认与参数校验。`assume_stopped` 为 true 且源库没有 `-wal` 时以 immutable
/// 只读方式打开 SQLite，避免为迁移前备份创建 sidecar。失败时会删除本次新建的
/// 时间戳目录，不留下半成品 manifest。
pub(crate) fn snapshot_to(
    out_root: &Path,
    cfg: &HubConfig,
    config_bytes: &[u8],
    assume_stopped: bool,
) -> Result<PathBuf> {
    validate_user_path(out_root, "备份根目录")?;
    fsutil::ensure_dir(out_root, 0o700)
        .with_context(|| format!("创建备份根目录失败: {}", out_root.display()))?;
    let dir = create_timestamp_dir(out_root)?;
    let mut guard = BackupDirGuard::new(dir.clone());

    let kind = cfg.database_kind().context("解析 database 配置失败")?;
    let schema = match &kind {
        DatabaseKind::Sqlite(path) => {
            if !path.is_file() {
                bail!("SQLite 数据库不存在: {}", path.display());
            }
            if assume_stopped {
                sqlite_schema_version_immutable(path)?
            } else {
                sqlite_schema_version(path)?
            }
        }
        DatabaseKind::Postgres(dsn) => postgres_schema_version(cfg, dsn)?,
    };
    // v1.0.0 只支持全新安装：旧 schema 源库即使还能被读取，也不能产出
    // restore 会拒绝的 manifest（必须先判版本，而不是等缺表/导入阶段报错）。
    ensure_schema_supported(backend_of(&kind), schema)
        .with_context(|| format!("源数据库 {} 的 schema 不受支持", kind.redacted()))?;

    match &kind {
        DatabaseKind::Sqlite(path) => {
            let dump = dir.join("rustboard.db");
            sqlite_backup_to(path, &dump, assume_stopped)?;
        }
        DatabaseKind::Postgres(dsn) => {
            let dump = dir.join("rustboard.dump");
            pg_dump_to(cfg, dsn, &dump)?;
        }
    }
    write_private_file(&dir.join("hub.toml"), config_bytes)?;
    copy_certs_snapshot(&cfg.data_dir, &dir).with_context(|| {
        format!(
            "复制证书目录失败: {}",
            tls::cert_dir(&cfg.data_dir).display()
        )
    })?;

    let mut files = Vec::new();
    record_file(
        &dir,
        Path::new(database_file_name_from_kind(&kind)),
        &mut files,
    )?;
    record_file(&dir, Path::new("hub.toml"), &mut files)?;
    collect_files(&dir.join("certs"), Path::new("certs"), &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest = Manifest {
        manifest_version: MANIFEST_VERSION,
        version: env!("CARGO_PKG_VERSION").to_string(),
        schema,
        backend: backend_name(&kind).to_string(),
        created_at: format_rfc3339(now_ms()),
        created_at_ms: now_ms(),
        files,
    };
    let json = serde_json::to_vec_pretty(&manifest).context("序列化备份 manifest 失败")?;
    write_private_file(&dir.join("manifest.json"), &json)?;
    sync_dir(&dir)?;
    // 时间戳目录是新 entry，父目录也要 fsync；否则断电后可能出现
    // manifest 已落盘但目录项丢失（或反之）的“半成品备份”。
    sync_dir(out_root)?;
    guard.commit();
    Ok(dir)
}

/// 删除失败/中断时本次新建的时间戳目录，避免留下看似完整但缺 manifest 的备份。
struct BackupDirGuard {
    dir: PathBuf,
    committed: bool,
}

impl BackupDirGuard {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for BackupDirGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
}

fn create_timestamp_dir(root: &Path) -> Result<PathBuf> {
    let base = format_timestamp(now_ms());
    for attempt in 0..100 {
        let name = if attempt == 0 {
            base.clone()
        } else {
            format!("{base}-{attempt}")
        };
        let dir = root.join(&name);
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("创建备份目录失败: {}", dir.display()))
            }
        }
    }
    bail!(
        "备份目录 {} 下同一时间戳已存在 100 个目录，拒绝覆盖",
        root.display()
    )
}

/// 读取并校验 manifest；文件哈希由 [`verify_manifest_files`] 单独完成。
fn read_manifest(dir: &Path) -> Result<Manifest> {
    let path = dir.join("manifest.json");
    reject_existing_symlinks(&path)?;
    let bytes =
        fs::read(&path).with_context(|| format!("读取备份 manifest 失败: {}", path.display()))?;
    let manifest: Manifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("解析备份 manifest 失败: {}", path.display()))?;
    Ok(manifest)
}

/// 校验 manifest 中的每个文件，返回 `相对路径 -> 绝对路径`。
fn verify_manifest_files(
    dir: &Path,
    manifest: &Manifest,
) -> Result<std::collections::BTreeMap<String, PathBuf>> {
    let mut verified = std::collections::BTreeMap::new();
    if manifest.files.is_empty() {
        bail!("备份 manifest 的文件列表为空");
    }
    for file in &manifest.files {
        let rel = safe_relative_path(&file.path)?;
        let key = rel.to_string_lossy().replace('\\', "/");
        if verified.contains_key(&key) {
            bail!("备份 manifest 包含重复文件: {key}");
        }
        let path = safe_join(dir, &rel)?;
        let meta = fs::symlink_metadata(&path).with_context(|| format!("备份文件缺失: {key}"))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            bail!("备份文件不是普通文件（拒绝符号链接/目录）: {key}");
        }
        if meta.len() != file.size {
            bail!(
                "备份文件大小不匹配: {key}，manifest={}，实际={}",
                file.size,
                meta.len()
            );
        }
        let actual = sha256_file(&path)?;
        if actual != file.sha256.to_ascii_lowercase() {
            bail!("备份文件 SHA256 不匹配: {key}（备份可能损坏或被篡改）");
        }
        verified.insert(key, path);
    }
    Ok(verified)
}

/// 把 `dir/rel` 解析为安全路径：拒绝绝对路径、`..`、`curdir`、符号链接组件。
fn safe_join(dir: &Path, rel: &Path) -> Result<PathBuf> {
    let joined = dir.join(rel);
    if !joined.starts_with(dir) {
        bail!("备份路径越界: {}", rel.display());
    }
    // 逐组件检查已存在的父目录，避免 `certs` 被替换成指向目录外的符号链接。
    let mut current = dir.to_path_buf();
    let components: Vec<&std::ffi::OsStr> = rel
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    for (index, name) in components.iter().enumerate() {
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("备份路径包含符号链接，拒绝访问: {}", current.display());
            }
            Ok(meta) if index + 1 < components.len() && !meta.is_dir() => {
                bail!("备份路径的父级不是目录: {}", current.display());
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(err).with_context(|| format!("检查备份路径失败: {}", current.display()))
            }
        }
    }
    Ok(joined)
}

/// 把 manifest 里的相对路径解析为安全相对路径。
fn safe_relative_path(raw: &str) -> Result<PathBuf> {
    if raw.is_empty() {
        bail!("备份 manifest 包含空路径");
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        bail!("备份 manifest 包含绝对路径: {raw}");
    }
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::CurDir => bail!("备份 manifest 包含 . 路径: {raw}"),
            Component::ParentDir => bail!("备份 manifest 包含 .. 路径: {raw}"),
            Component::RootDir | Component::Prefix(_) => {
                bail!("备份 manifest 包含绝对路径: {raw}")
            }
        }
    }
    if out.as_os_str().is_empty() {
        bail!("备份 manifest 包含空路径");
    }
    Ok(out)
}

/// 用户提供的 `--out` / `--from`：拒绝 `..` 与已存在的符号链接组件。
fn validate_user_path(path: &Path, what: &str) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("{what}不能为空");
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("{what}不允许包含 ..: {}", path.display());
    }
    let absolute = std::path::absolute(path)
        .with_context(|| format!("解析{what}绝对路径失败: {}", path.display()))?;
    reject_existing_symlinks(&absolute)
}

/// 逐组件拒绝已存在的符号链接（不要求路径存在）。
fn reject_existing_symlinks(path: &Path) -> Result<()> {
    let absolute =
        std::path::absolute(path).with_context(|| format!("解析路径失败: {}", path.display()))?;
    let mut current = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::RootDir => continue,
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            Component::ParentDir | Component::Prefix(_) => {
                bail!("路径包含非法组件: {}", path.display())
            }
        }
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                bail!("路径包含符号链接，拒绝访问: {}", current.display())
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => {
                return Err(err).with_context(|| format!("检查路径失败: {}", current.display()))
            }
        }
    }
    Ok(())
}

/// 写入 0600 文件（原子替换）。
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fsutil::ensure_dir(parent, 0o700)
                .with_context(|| format!("创建目录失败: {}", parent.display()))?;
        }
    }
    fsutil::atomic_write(path, bytes, 0o600)
        .with_context(|| format!("写入文件失败: {}", path.display()))
}

/// 在配置文件旁边保留 `<name>.bak-<timestamp>`（0600）。
fn backup_file_next_to(path: &Path, bytes: &[u8], suffix: &str) -> Result<PathBuf> {
    let candidate = path.with_file_name(format!(
        "{}.{}-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("hub.toml"),
        suffix,
        format_timestamp(now_ms())
    ));
    write_private_file(&candidate, bytes)?;
    Ok(candidate)
}

/// 读取 SQLite `PRAGMA user_version`（只读）。
pub(crate) fn sqlite_schema_version(path: &Path) -> Result<i64> {
    let conn = open_sqlite_readonly(path)?;
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .with_context(|| format!("读取 SQLite schema 版本失败: {}", path.display()))
}

/// SQLite 源库预检结果。
pub(crate) struct SqliteSourceInfo {
    pub schema_version: i64,
    pub sample_count: i64,
}

/// 迁移 dry-run / 源预检的只读连接。
///
/// - 无 `-wal` / `-journal`：直接 immutable 打开，源目录零写入；
/// - 有未 checkpoint 的 `-wal` / 热 `-journal`：immutable 会忽略它们（会把 v7
///   库读成 v0 / 漏数据），因此把主库与 sidecar 复制到 0700 临时目录，在副本上
///   用普通只读连接读取。副本里 SQLite 可以自由建 `-shm`，源目录不受影响。
struct SqlitePreflight {
    conn: Option<SqliteConnection>,
    _temp: Option<TempDirGuard>,
}

impl SqlitePreflight {
    fn open(path: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(path)
            .with_context(|| format!("打开 SQLite 数据库失败: {}", path.display()))?;
        if meta.file_type().is_symlink() {
            bail!("SQLite 数据库是符号链接，拒绝打开: {}", path.display());
        }
        if !meta.is_file() {
            bail!("SQLite 数据库不是普通文件: {}", path.display());
        }
        let wal = sidecar_path(path, "-wal");
        let journal = sidecar_path(path, "-journal");
        if !wal.exists() && !journal.exists() {
            let conn = open_sqlite_readonly_immutable(path)?;
            return Ok(Self {
                conn: Some(conn),
                _temp: None,
            });
        }

        // 有 WAL/热 journal：复制到临时目录再读。临时文件全部 0600，目录 0700。
        let temp = TempDirGuard::new(create_private_temp_dir("sqlite-preflight")?);
        let copy = temp.path().join("source.db");
        copy_private_database(path, &copy)?;
        if wal.exists() {
            copy_private_database(&wal, &sidecar_path(&copy, "-wal"))?;
        }
        if journal.exists() {
            copy_private_database(&journal, &sidecar_path(&copy, "-journal"))?;
        }
        let conn = SqliteConnection::open_with_flags(&copy, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| {
                format!(
                    "在临时副本上只读打开 SQLite 失败: {}（源 {}）",
                    copy.display(),
                    path.display()
                )
            })?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .context("设置 SQLite busy_timeout 失败")?;
        Ok(Self {
            conn: Some(conn),
            _temp: Some(temp),
        })
    }

    fn conn(&self) -> &SqliteConnection {
        self.conn.as_ref().expect("SqlitePreflight conn 已关闭")
    }

    fn schema_version(&self) -> Result<i64> {
        self.conn()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .context("读取 SQLite schema 版本失败")
    }

    fn validate_tables(&self) -> Result<()> {
        for table in HUB_TABLES {
            let exists: i64 = self
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                    [table],
                    |row| row.get(0),
                )
                .with_context(|| format!("检查 SQLite 源库表 {table} 失败"))?;
            if exists == 0 {
                bail!(
                    "SQLite 源库缺少表 {table}（schema 不是完整的 v{}）；拒绝迁移",
                    SQLITE_SCHEMA_VERSION
                );
            }
        }
        Ok(())
    }

    fn sample_count(&self) -> Result<i64> {
        self.conn()
            .query_row("SELECT COUNT(*) FROM samples", [], |row| row.get(0))
            .context("统计 SQLite 源库 samples 行数失败")
    }
}

impl Drop for SqlitePreflight {
    fn drop(&mut self) {
        // 先关连接，再让 TempDirGuard 删目录（字段顺序也保证，但这里显式关闭）。
        drop(self.conn.take());
    }
}

/// 迁移预检：版本 + 22 张表 + samples 行数，一次打开（WAL 库只复制一次）。
pub(crate) fn sqlite_source_info(path: &Path) -> Result<SqliteSourceInfo> {
    let preflight = SqlitePreflight::open(path)?;
    let schema_version = preflight.schema_version()?;
    // 先判版本再判表：v8 源库即使缺 v9 新表，也必须先得到「只支持全新安装」
    // 的统一文案，不能只报缺表。
    ensure_schema_supported(Backend::Sqlite, schema_version)
        .with_context(|| format!("SQLite 源库 {}", path.display()))?;
    preflight.validate_tables()?;
    let sample_count = preflight.sample_count()?;
    Ok(SqliteSourceInfo {
        schema_version,
        sample_count,
    })
}

/// 以 immutable/临时副本方式读取 schema 版本（无源目录写入）。
pub(crate) fn sqlite_schema_version_immutable(path: &Path) -> Result<i64> {
    SqlitePreflight::open(path)?.schema_version()
}

/// SQLite 目标是否已有业务数据。
///
/// 文件不存在、没有用户表、或所有用户表都为空时视为空目标；任何一行数据都
/// 视为非空。空库但已经 apply schema 的 SQLite 文件仍可恢复。
fn target_sqlite_has_data(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        bail!("SQLite 目标是符号链接，拒绝操作: {}", path.display());
    }
    let conn = open_sqlite_readonly_immutable(path)?;
    let mut statement = conn
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .context("读取 SQLite 表列表失败")?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .context("读取 SQLite 表列表失败")?
        .collect::<rusqlite::Result<Vec<_>>>()
        .context("读取 SQLite 表列表失败")?;
    for name in names {
        let quoted = name.replace('"', "\"\"");
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{quoted}\""), [], |row| {
                row.get(0)
            })
            .with_context(|| format!("统计 SQLite 表 {name} 行数失败"))?;
        if count > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// 检查恢复目标（PG 或 SQLite）是否已有数据。
fn target_has_data(cfg: &HubConfig, kind: &DatabaseKind) -> Result<bool> {
    match kind {
        DatabaseKind::Sqlite(path) => target_sqlite_has_data(path),
        DatabaseKind::Postgres(dsn) => {
            let mut target_cfg = cfg.clone();
            target_cfg.database = dsn.clone();
            let storage = PostgresStorage::open_from_config(&target_cfg)
                .with_context(|| format!("连接 PostgreSQL 目标失败（{}）", dsn_redacted(dsn)))?;
            match rustboard_core::storage::migrate::validate_target_empty(&storage) {
                Ok(()) => Ok(false),
                Err(err) => {
                    if is_non_empty_target_error(&err) {
                        Ok(true)
                    } else {
                        Err(err)
                    }
                }
            }
        }
    }
}

/// 判断 core 的空库校验错误是否只是「目标非空」。
pub(crate) fn is_non_empty_target_error(err: &anyhow::Error) -> bool {
    format!("{err:#}").contains("目标 PostgreSQL 非空")
}

/// 目标 schema 版本是否高于当前二进制支持版本。
pub(crate) fn is_too_new_target_error(err: &anyhow::Error) -> bool {
    format!("{err:#}").contains("高于本程序支持")
}

/// 目标是否被判定为旧 schema（v1.0.0 只支持全新安装）。
///
/// 这类错误必须在 `--force` 的 pg_dump/TRUNCATE 之前返回；调用方不能把它
/// 归类成 Empty/NonEmpty，否则旧目标会在被拒绝前清空。
pub(crate) fn is_old_schema_target_error(err: &anyhow::Error) -> bool {
    format!("{err:#}").contains("只支持全新安装")
}

/// 打开只读 SQLite 连接；拒绝符号链接与不存在的文件。
fn open_sqlite_readonly(path: &Path) -> Result<SqliteConnection> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("打开 SQLite 数据库失败: {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("SQLite 数据库是符号链接，拒绝打开: {}", path.display());
    }
    if !meta.is_file() {
        bail!("SQLite 数据库不是普通文件: {}", path.display());
    }
    let conn = SqliteConnection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("以只读方式打开 SQLite 数据库失败: {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .context("设置 SQLite busy_timeout 失败")?;
    Ok(conn)
}

/// 以 `immutable=1` 只读打开 SQLite；不创建 `-shm/-wal`。
fn open_sqlite_readonly_immutable(path: &Path) -> Result<SqliteConnection> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("打开 SQLite 数据库失败: {}", path.display()))?;
    if meta.file_type().is_symlink() {
        bail!("SQLite 数据库是符号链接，拒绝打开: {}", path.display());
    }
    if !meta.is_file() {
        bail!("SQLite 数据库不是普通文件: {}", path.display());
    }
    let uri = immutable_sqlite_uri(path)?;
    let conn = SqliteConnection::open_with_flags(
        uri.as_str(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .with_context(|| {
        format!(
            "以 immutable 方式打开 SQLite 数据库失败: {}",
            path.display()
        )
    })?;
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .context("设置 SQLite busy_timeout 失败")?;
    Ok(conn)
}

/// 用 `VACUUM INTO` 生成 SQLite 一致快照。
///
/// `assume_stopped` 为 true 且源库没有 `-wal` 时用 immutable URI 打开，避免为
/// 只读连接创建 `-shm/-wal`；备份命令可能在线执行，因此传 false 走正常只读。
pub(crate) fn sqlite_backup_to(
    source: &Path,
    destination: &Path,
    assume_stopped: bool,
) -> Result<()> {
    if destination.exists() {
        bail!("SQLite 备份目标已存在，拒绝覆盖: {}", destination.display());
    }
    let wal = sidecar_path(source, "-wal");
    let conn = if assume_stopped && !wal.exists() {
        let uri = immutable_sqlite_uri(source)?;
        SqliteConnection::open_with_flags(
            uri.as_str(),
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
        )
        .with_context(|| {
            format!(
                "以只读 immutable 方式打开 SQLite 数据库失败: {}",
                source.display()
            )
        })?
    } else {
        open_sqlite_readonly(source)?
    };
    let target = destination
        .to_str()
        .ok_or_else(|| anyhow!("SQLite 备份路径不是合法 UTF-8: {}", destination.display()))?;
    conn.execute("VACUUM INTO ?1", [target])
        .with_context(|| format!("VACUUM INTO 备份 SQLite 失败: {}", source.display()))?;
    drop(conn);

    fsutil::harden(destination, 0o600)
        .with_context(|| format!("收紧 SQLite 备份权限失败: {}", destination.display()))?;
    sync_file(destination)?;
    // 立即验证备份可打开且页结构完整，避免把损坏文件当成功备份。
    let check = open_sqlite_readonly(destination)?
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .context("校验 SQLite 备份完整性失败")?;
    if check != "ok" {
        bail!("SQLite 备份完整性校验失败: {check}");
    }
    Ok(())
}

/// 生成 immutable SQLite URI。
fn immutable_sqlite_uri(path: &Path) -> Result<String> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("解析 SQLite 路径失败: {}", path.display()))?;
    let text = absolute
        .to_str()
        .ok_or_else(|| anyhow!("SQLite 路径不是合法 UTF-8: {}", path.display()))?;
    let mut uri = String::with_capacity(text.len() + 16);
    uri.push_str("file:");
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                uri.push(char::from(byte));
            }
            _ => uri.push_str(&format!("%{byte:02X}")),
        }
    }
    uri.push_str("?immutable=1");
    Ok(uri)
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

/// 把已验证的 SQLite 备份原子替换到目标路径。
/// 目标 SQLite 旁路文件后缀；存在任何一个都拒绝恢复。
const SQLITE_SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];

/// 拒绝带 sidecar 的 SQLite 目标。
///
/// 旧 WAL 里的页面会在下一次打开时重放；如果先替换主库再删 WAL，中间崩溃或
/// 删除失败就会把新库覆盖回旧数据。因此恢复前必须先干净停止 hub 并确认这些
/// 文件不存在，而不是由工具在 rename 后“顺手”删除。
fn ensure_no_sqlite_sidecars(path: &Path) -> Result<()> {
    for suffix in SQLITE_SIDECARS {
        let sidecar = sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(meta) => {
                let kind = if meta.file_type().is_symlink() {
                    "符号链接"
                } else {
                    "残留文件"
                };
                bail!(
                    "目标 SQLite 存在 {kind} {}；恢复前必须先干净停止 hub 并确认/删除该 sidecar，\
                     不能让 SQLite 重放旧 WAL 覆盖新库",
                    sidecar.display()
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("检查 SQLite sidecar 失败: {}", sidecar.display()))
            }
        }
    }
    Ok(())
}

/// 私有临时目录 guard；Drop 递归删除。
struct TempDirGuard {
    path: PathBuf,
}

impl TempDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// 在系统临时目录下创建随机 0700 目录（不跟随预先放好的名字/链接）。
fn create_private_temp_dir(tag: &str) -> Result<PathBuf> {
    let base = std::env::temp_dir();
    for _ in 0..32 {
        let path = base.join(format!(
            ".rustboard-{tag}-{}-{:016x}",
            std::process::id(),
            rand_suffix()
        ));
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("创建临时目录失败: {}", path.display()))
            }
        }
    }
    bail!("无法创建 SQLite 预检临时目录（随机名连续冲突）")
}

/// 删除本次恢复的只读检查可能产生的 sidecar，并 fsync 父目录。
///
/// 调用前提：进入 restore 时已确认目标没有 sidecar（外部残留会提前拒绝），且
/// hub 已停止/由 `--hub-stopped` 声明。只读连接可能在目标目录创建空 `-shm` /
/// `-wal`；这些不是用户数据，必须在 rename 前清掉，否则 SQLite 会重放它们。
/// 删除失败（含 sidecar 是目录/权限不足）仍然 fail-closed。
fn remove_restore_sidecars(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("SQLite 目标没有父目录: {}", path.display()))?;
    match fs::symlink_metadata(parent) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => bail!("SQLite 目标父路径不是目录，拒绝恢复: {}", parent.display()),
        // 新目标目录尚不存在：没有任何 sidecar/目录需要清理或 fsync。
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("检查 SQLite 目标父目录失败: {}", parent.display()))
        }
    }
    for suffix in SQLITE_SIDECARS {
        let sidecar = sidecar_path(path, suffix);
        match fs::symlink_metadata(&sidecar) {
            Ok(meta) => {
                if meta.is_dir() {
                    bail!(
                        "目标 SQLite sidecar 是目录，拒绝删除/恢复: {}",
                        sidecar.display()
                    );
                }
                fs::remove_file(&sidecar).with_context(|| {
                    format!(
                        "清理只读检查产生的 SQLite sidecar 失败: {}；已中止恢复",
                        sidecar.display()
                    )
                })?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("检查 SQLite sidecar 失败: {}", sidecar.display()))
            }
        }
    }
    sync_dir(parent)?;
    ensure_no_sqlite_sidecars(path)
}

/// 临时文件 guard：未 `disarm` 时 Drop 删除，避免失败后留下半成品/回滚副本。
struct TempPathGuard {
    path: PathBuf,
    armed: bool,
}

impl TempPathGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(mut self) -> PathBuf {
        self.armed = false;
        self.path.clone()
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// 复制数据库文件到新路径（create_new，0600，fsync）。
fn copy_private_database(source: &Path, destination: &Path) -> Result<()> {
    let mut src =
        File::open(source).with_context(|| format!("打开数据库失败: {}", source.display()))?;
    let mut dst = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)
        .with_context(|| format!("创建数据库临时文件失败: {}", destination.display()))?;
    std::io::copy(&mut src, &mut dst).context("复制数据库失败")?;
    dst.sync_all().context("fsync 数据库临时文件失败")?;
    drop(dst);
    fsutil::harden(destination, 0o600)
        .with_context(|| format!("收紧数据库文件权限失败: {}", destination.display()))?;
    Ok(())
}

fn temp_database_path(destination: &Path, tag: &str) -> PathBuf {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    parent.join(format!(
        ".{}.{tag}.{}.{:016x}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("rustboard.db"),
        std::process::id(),
        rand_suffix()
    ))
}

fn sqlite_quick_check(path: &Path) -> Result<()> {
    let check = open_sqlite_readonly_immutable(path)?
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .with_context(|| format!("SQLite quick_check 失败: {}", path.display()))?;
    if check != "ok" {
        bail!("SQLite 完整性校验失败（{}）: {check}", path.display());
    }
    Ok(())
}

/// 校验 SQLite 文件确实是 v9 且 22 张业务表齐全。
///
/// 恢复不能只信 manifest 的 `schema` 字段：备份文件可能是旧库，或被伪造
/// manifest 包装。这里在 rename 到目标前直接读 `PRAGMA user_version` 与
/// `sqlite_master`，不满足就拒绝，绝不把不可启动的库换到目标路径。
fn sqlite_assert_v9(path: &Path, what: &str) -> Result<()> {
    let conn = open_sqlite_readonly_immutable(path)?;
    let version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .with_context(|| format!("读取{what} schema 版本失败: {}", path.display()))?;
    if let Err(err) = ensure_schema_supported(Backend::Sqlite, version) {
        return Err(err)
            .with_context(|| format!("{what} schema 版本为 v{version}（{}）", path.display()));
    }
    for table in HUB_TABLES {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .with_context(|| format!("检查{what}表 {table} 失败: {}", path.display()))?;
        if exists == 0 {
            bail!(
                "{what}缺少表 {table}（schema 不完整），拒绝恢复: {}",
                path.display()
            );
        }
    }
    Ok(())
}

/// 关键表行数：只统计存在的业务表，源/目标必须完全一致。
fn sqlite_key_table_counts(path: &Path) -> Result<Vec<(&'static str, i64)>> {
    let conn = open_sqlite_readonly_immutable(path)?;
    let mut counts = Vec::new();
    for table in HUB_TABLES {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .with_context(|| format!("检查 SQLite 表 {table} 失败: {}", path.display()))?;
        if exists == 0 {
            continue;
        }
        // `table` 只来自 HUB_TABLES 常量。
        let count: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{table}\""), [], |row| {
                row.get(0)
            })
            .with_context(|| format!("统计 SQLite 表 {table} 失败: {}", path.display()))?;
        counts.push((table, count));
    }
    Ok(counts)
}

/// 恢复后校验失败时回滚：有旧库副本则原子替换回去，否则删除新库。
fn rollback_sqlite_target(destination: &Path, rollback: Option<&Path>) -> Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("SQLite 目标没有父目录: {}", destination.display()))?;
    remove_restore_sidecars(destination)?;
    match rollback {
        Some(source) => {
            let tmp = TempPathGuard::new(temp_database_path(destination, "rollback"));
            copy_private_database(source, tmp.path())?;
            let tmp = tmp.disarm();
            fs::rename(&tmp, destination)
                .with_context(|| format!("回滚 SQLite 数据库失败: {}", destination.display()))?;
        }
        None => match fs::remove_file(destination) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("回滚时删除新 SQLite 数据库失败: {}", destination.display())
                })
            }
        },
    }
    fsutil::harden(destination, 0o600)?;
    ensure_no_sqlite_sidecars(destination)?;
    sync_dir(parent)?;
    Ok(())
}

/// 用已验证的 SQLite 快照替换目标。
///
/// 安全顺序：
/// 1. 目标存在任何 `-wal/-shm/-journal` 直接拒绝（不把旧 WAL 留在 rename 之后）；
/// 2. 目标旧库先复制一份本地回滚副本（即使目标为空/只有空 schema）；
/// 3. 新库写入同目录临时文件，校验 SHA256、`quick_check` 与 22 张表行数；
/// 4. 再检查一次无 sidecar 后 rename；
/// 5. rename 后再次校验；失败则用回滚副本原子替换回去（没有旧库则删除新库），
///    并返回明确错误，绝不静默留下半恢复状态。
fn restore_sqlite_file(source: &Path, destination: &Path) -> Result<()> {
    ensure_no_sqlite_sidecars(destination)?;
    sqlite_assert_v9(source, "备份中的 SQLite ")?;
    let source_hash = sha256_file(source)?;
    let source_counts = sqlite_key_table_counts(source)?;
    sqlite_quick_check(source)?;

    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("SQLite 目标没有父目录: {}", destination.display()))?;
    fsutil::ensure_dir(parent, 0o700)
        .with_context(|| format!("创建 SQLite 目标目录失败: {}", parent.display()))?;
    reject_existing_symlinks(destination)?;
    if fs::symlink_metadata(destination).is_ok_and(|meta| meta.is_dir()) {
        bail!("SQLite 目标是目录，拒绝覆盖: {}", destination.display());
    }

    // 本地回滚副本：不依赖 restore 的 pre-restore 快照，空目标/只有空 schema
    // 的旧库也能在 post-rename 校验失败时恢复原文件。
    let rollback = if fs::symlink_metadata(destination).is_ok() {
        let path = temp_database_path(destination, "pre-restore");
        let guard = TempPathGuard::new(path.clone());
        copy_private_database(destination, &path)
            .with_context(|| format!("备份当前 SQLite 数据库失败: {}", destination.display()))?;
        Some(guard)
    } else {
        None
    };

    let tmp = TempPathGuard::new(temp_database_path(destination, "restore"));
    copy_private_database(source, tmp.path())
        .with_context(|| format!("复制 SQLite 备份失败: {}", source.display()))?;
    let tmp_hash = sha256_file(tmp.path())?;
    if tmp_hash != source_hash {
        bail!(
            "SQLite 临时副本 SHA256 与备份不一致: {}",
            tmp.path().display()
        );
    }
    sqlite_quick_check(tmp.path())?;
    // rename 前直接校验恢复出的库：manifest 可被伪造，必须看真实
    // `user_version` 与 22 张业务表。
    sqlite_assert_v9(tmp.path(), "SQLite 恢复临时副本 ")?;
    let tmp_counts = sqlite_key_table_counts(tmp.path())?;
    if tmp_counts != source_counts {
        bail!(
            "SQLite 临时副本行数与备份不一致（期望 {:?}，实际 {:?}）",
            source_counts,
            tmp_counts
        );
    }
    // 只读校验/临时副本准备期间可能在目标目录留下空 sidecar；rename 前删除
    // 并 fsync。删除失败仍 fail-closed。
    remove_restore_sidecars(destination)?;
    let tmp = tmp.disarm();
    fs::rename(&tmp, destination)
        .with_context(|| format!("替换 SQLite 数据库失败: {}", destination.display()))?;

    let post_check = (|| -> Result<()> {
        ensure_no_sqlite_sidecars(destination)?;
        if sha256_file(destination)? != source_hash {
            bail!("恢复后的 SQLite 文件 SHA256 与备份不一致");
        }
        sqlite_quick_check(destination)?;
        sqlite_assert_v9(destination, "恢复后的 SQLite ")?;
        let counts = sqlite_key_table_counts(destination)?;
        if counts != source_counts {
            bail!(
                "恢复后的 SQLite 关键表行数与备份不一致（期望 {:?}，实际 {:?}）",
                source_counts,
                counts
            );
        }
        Ok(())
    })();
    if let Err(err) = post_check {
        let rollback_ref = rollback.as_ref().map(|guard| guard.path());
        return match rollback_sqlite_target(destination, rollback_ref) {
            Ok(()) => Err(err).context("恢复后校验失败；已回滚到恢复前 SQLite 数据库"),
            Err(rb) => Err(err).context(format!(
                "恢复后校验失败；回滚也失败（需要人工处理）: {rb:#}"
            )),
        };
    }

    fsutil::harden(destination, 0o600)?;
    sync_dir(parent)?;
    Ok(())
}

/// 外部 `pg_dump` 备份。
///
/// TLS/密码策略来自 `cfg` 与 DSN，经 [`PgDsnSecrets`] 统一解析；`pg_dump` 与
/// Hub 运行连接使用同一套 `sslmode` / 根 CA / 密码优先级，绝不允许工具侧降级。
pub(crate) fn pg_dump_to(cfg: &HubConfig, dsn: &str, destination: &Path) -> Result<()> {
    ensure_tool("pg_dump")?;
    if destination.exists() {
        bail!(
            "PostgreSQL 备份目标已存在，拒绝覆盖: {}",
            destination.display()
        );
    }
    let secrets = PgDsnSecrets::parse(dsn, cfg)?;
    let mut command = Command::new("pg_dump");
    command
        .arg("--format=custom")
        .arg("--no-owner")
        .arg("--no-privileges")
        .arg("--file")
        .arg(destination)
        .arg("--dbname")
        .arg(&secrets.sanitized);
    apply_pg_env(&mut command, &secrets);
    run_pg_tool(command, "pg_dump", dsn, &secrets)?;
    fsutil::harden(destination, 0o600)
        .with_context(|| format!("收紧 PostgreSQL 备份权限失败: {}", destination.display()))?;
    sync_file(destination)?;
    let size = fs::metadata(destination)
        .with_context(|| format!("读取 PostgreSQL 备份大小失败: {}", destination.display()))?
        .len();
    if size == 0 {
        bail!("pg_dump 成功但备份文件为空: {}", destination.display());
    }
    Ok(())
}

/// 外部 `pg_restore` 恢复；`--single-transaction` 保证失败时目标不被半恢复。
///
/// TLS/密码策略与运行连接一致，见 [`pg_dump_to`]。
fn pg_restore_from(cfg: &HubConfig, dsn: &str, dump: &Path) -> Result<()> {
    ensure_tool("pg_restore")?;
    let secrets = PgDsnSecrets::parse(dsn, cfg)?;
    let mut command = Command::new("pg_restore");
    command
        .arg("--clean")
        .arg("--if-exists")
        .arg("--no-owner")
        .arg("--no-privileges")
        .arg("--single-transaction")
        .arg("--dbname")
        .arg(&secrets.sanitized)
        .arg(dump);
    apply_pg_env(&mut command, &secrets);
    run_pg_tool(command, "pg_restore", dsn, &secrets)?;
    Ok(())
}

/// 检查外部工具存在；错误里给出安装文档路径。
pub(crate) fn ensure_tool(tool: &str) -> Result<()> {
    let output = Command::new(tool)
        .arg("--version")
        .stdin(Stdio::null())
        .output();
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "{tool} 不可用（--version 退出码 {:?}）：{}；请安装 postgresql-client，见 docs/install/postgres.md §6",
                output.status.code(),
                truncate(stderr.trim(), 512)
            )
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
            "{tool} 不存在或不在 PATH；PostgreSQL 备份/恢复需要 postgresql-client。安装说明见 docs/install/postgres.md §6"
        ),
        Err(err) => Err(err).with_context(|| format!("执行 {tool} --version 失败")),
    }
}

fn run_pg_tool(command: Command, tool: &str, dsn: &str, secrets: &PgDsnSecrets) -> Result<()> {
    let mut command = command;
    command.stdin(Stdio::null());
    let output: Output = command
        .output()
        .with_context(|| format!("执行 {tool} 失败（工具不存在或无法启动）"))?;
    if output.status.success() {
        return Ok(());
    }
    let mut detail = String::new();
    if !output.stderr.is_empty() {
        detail.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    if !output.stdout.is_empty() {
        if !detail.is_empty() {
            detail.push('\n');
        }
        detail.push_str(&String::from_utf8_lossy(&output.stdout));
    }
    let detail = secrets.scrub(&detail, dsn);
    bail!(
        "{tool} 失败（退出码 {:?}）：{}",
        output.status.code(),
        truncate(detail.trim(), MAX_TOOL_OUTPUT)
    )
}

/// 把统一的 TLS/密码策略传给外部 libpq 工具。
///
/// 先清理继承环境（见 [`PG_TOOL_ENV_CLEAR`]），再显式设置 `PGSSLMODE`、有 CA 时
/// 设置 `PGSSLROOTCERT`、有密码时设置 `PGPASSWORD`/`PGSSLPASSWORD`。这样
/// `pg_dump`/`pg_restore` 既不会用宿主遗留的 `PGSSLMODE=disable` 降级，也不会
/// 让旧的 `PGPASSWORD` 覆盖本次目标密码。
fn apply_pg_env(command: &mut Command, secrets: &PgDsnSecrets) {
    for key in PG_TOOL_ENV_CLEAR {
        command.env_remove(key);
    }
    command.env("PGSSLMODE", secrets.sslmode);
    if let Some(root) = &secrets.sslrootcert {
        command.env("PGSSLROOTCERT", root);
    }
    if let Some(password) = secrets.password.as_deref() {
        command.env("PGPASSWORD", password);
    }
    if let Some(sslpassword) = secrets.sslpassword.as_deref() {
        command.env("PGSSLPASSWORD", sslpassword);
    }
}

/// PostgreSQL DSN 的密码与 TLS 策略，供外部 `pg_dump`/`pg_restore` 使用。
///
/// 解析统一交给 core 的 [`resolve_external_tool_dsn`]：URL 密码优先级与运行连接
/// 使用同一个 `postgres::Config`，根 CA 冲突校验也完全一致。
///
/// 结构体包含密码，故意不实现 `Debug`。
struct PgDsnSecrets {
    /// 已剥离两处密码、sslpassword、sslmode、sslrootcert 的 DSN（argv 安全）。
    sanitized: String,
    /// URL 自身密码（用于脱敏工具输出）。
    url_password: Option<String>,
    /// 实际传给 `PGPASSWORD` 的密码（环境变量覆盖后）。
    password: Option<String>,
    sslpassword: Option<String>,
    sslmode: &'static str,
    sslrootcert: Option<PathBuf>,
}

impl PgDsnSecrets {
    fn parse(dsn: &str, cfg: &HubConfig) -> Result<Self> {
        let resolved =
            resolve_external_tool_dsn(dsn, cfg.db_sslrootcert.as_deref()).with_context(|| {
                format!(
                    "解析 PostgreSQL DSN / TLS 策略失败（{}）",
                    dsn_redacted(dsn)
                )
            })?;
        Ok(Self {
            sanitized: resolved.sanitized,
            url_password: resolved.url_password,
            password: resolved.effective_password,
            sslpassword: resolved.sslpassword,
            sslmode: resolved.sslmode,
            sslrootcert: resolved.sslrootcert,
        })
    }

    fn scrub(&self, text: &str, dsn: &str) -> String {
        let mut value = text.replace(dsn, &dsn_redacted(dsn));
        for secret in [
            self.url_password.as_deref(),
            self.password.as_deref(),
            self.sslpassword.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !secret.is_empty() {
                value = value.replace(secret, "***");
            }
        }
        value
    }
}

/// 预检 PostgreSQL 目标 DSN 的密码/TLS 策略，供 `migrate` 在交互确认前调用。
///
/// 与运行连接/外部工具共用 [`PgDsnSecrets`]，非法 `sslmode`、根证书冲突、
/// 重复参数等都会在任何破坏性操作前 fail closed。
pub(crate) fn validate_pg_connection_policy(cfg: &HubConfig, dsn: &str) -> Result<()> {
    let _ = PgDsnSecrets::parse(dsn, cfg)?;
    Ok(())
}

/// 获取与 `rotate-cert` / ACME 续期相同的证书锁，锁冲突时有界等待。
///
/// `CertLock` 用 `flock(LOCK_EX | LOCK_NB)`，持锁进程崩溃时内核自动释放。这里
/// 只对「另一个 rotate-cert 正在运行」做 100ms × 50 次重试；其它错误（权限、
/// 符号链接等）立即返回，不把真实故障伪装成锁竞争。等待超时 fail closed，
/// 绝不无锁复制证书。
fn acquire_cert_lock_bounded(cert_dir: &Path) -> Result<CertLock> {
    let deadline = Instant::now() + CERT_LOCK_TIMEOUT;
    loop {
        match CertLock::acquire(cert_dir) {
            Ok(lock) => return Ok(lock),
            Err(err) => {
                let contended = format!("{err:#}").contains("另一个 rotate-cert 正在运行");
                let now = Instant::now();
                if !contended || now >= deadline {
                    return Err(err).with_context(|| {
                        format!(
                            "获取证书轮换锁失败（{}）：证书操作必须与 rotate-cert/ACME 串行，\
                             已安全中止",
                            cert_dir.display()
                        )
                    });
                }
                std::thread::sleep(CERT_LOCK_RETRY_INTERVAL.min(deadline - now));
            }
        }
    }
}

/// 校验一对证书/私钥是否配套；都不存在时跳过，只存在一个时 fail closed。
fn validate_cert_file_pair(cert: &Path, key: &Path, label: &str) -> Result<()> {
    let cert_meta = match fs::symlink_metadata(cert) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("检查{label}失败: {}", cert.display()))
        }
    };
    let key_meta = match fs::symlink_metadata(key) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(err).with_context(|| format!("检查{label}失败: {}", key.display())),
    };
    match (cert_meta, key_meta) {
        (None, None) => return Ok(()),
        (Some(_), None) => bail!(
            "{label}材料不完整：证书 {} 存在但私钥 {} 缺失；已安全中止",
            cert.display(),
            key.display()
        ),
        (None, Some(_)) => bail!(
            "{label}材料不完整：私钥 {} 存在但证书 {} 缺失；已安全中止",
            key.display(),
            cert.display()
        ),
        (Some(cert_meta), Some(key_meta)) => {
            if cert_meta.file_type().is_symlink() || key_meta.file_type().is_symlink() {
                bail!(
                    "{label}不能是符号链接：{} / {}",
                    cert.display(),
                    key.display()
                );
            }
            if !cert_meta.is_file() || !key_meta.is_file() {
                bail!(
                    "{label}必须是普通文件：{} / {}",
                    cert.display(),
                    key.display()
                );
            }
        }
    }
    let cert_pem =
        fs::read_to_string(cert).with_context(|| format!("读取{label}失败: {}", cert.display()))?;
    let key_pem =
        fs::read_to_string(key).with_context(|| format!("读取{label}失败: {}", key.display()))?;
    let matches = tls::cert_matches_key(&cert_pem, &key_pem)
        .with_context(|| format!("解析{label}失败：{} / {}", cert.display(), key.display()))?;
    if !matches {
        bail!(
            "{label}不配套：{} 与 {} 不是一对（可能是轮换写盘中途被中断）；\
             已安全中止，不生成备份/不覆盖目标",
            cert.display(),
            key.display()
        );
    }
    Ok(())
}

/// 只按「manifest 实际会写入的证书集合」校验一对材料是否齐全/配套。
///
/// 备份目录里可能残留未列入 manifest 的旧文件（例如旧版备份的 `.rotate.lock`
/// 或半套证书）。如果按目录实际内容校验，会误以为 server.crt/key 配套，而
/// restore 只写 manifest 里的 crt，最终恢复出坏材料。
fn validate_cert_file_pair_in_set(
    dir: &Path,
    cert_name: &str,
    key_name: &str,
    label: &str,
    present: &std::collections::BTreeSet<PathBuf>,
) -> Result<()> {
    let cert_rel = Path::new(cert_name);
    let key_rel = Path::new(key_name);
    match (present.contains(cert_rel), present.contains(key_rel)) {
        (false, false) => Ok(()),
        (true, false) => {
            bail!("{label}材料不完整：manifest 含 {cert_name} 但缺少 {key_name}；拒绝恢复")
        }
        (false, true) => {
            bail!("{label}材料不完整：manifest 含 {key_name} 但缺少 {cert_name}；拒绝恢复")
        }
        (true, true) => validate_cert_file_pair(&dir.join(cert_name), &dir.join(key_name), label),
    }
}

/// 按给定证书集合校验 server/CA 材料配套。
fn validate_cert_material_set(
    dir: &Path,
    present: &std::collections::BTreeSet<PathBuf>,
) -> Result<()> {
    validate_cert_file_pair_in_set(
        dir,
        tls::SERVER_CERT_FILE,
        tls::SERVER_KEY_FILE,
        "服务端证书与私钥",
        present,
    )?;
    validate_cert_file_pair_in_set(
        dir,
        tls::CA_CERT_FILE,
        tls::CA_KEY_FILE,
        "CA 证书与私钥",
        present,
    )
}

/// 校验目录实际存在的 server 与 CA 材料配套（用于备份临时副本）。
fn validate_cert_material(dir: &Path) -> Result<()> {
    let mut present = std::collections::BTreeSet::new();
    for name in [
        tls::SERVER_CERT_FILE,
        tls::SERVER_KEY_FILE,
        tls::CA_CERT_FILE,
        tls::CA_KEY_FILE,
    ] {
        if fs::symlink_metadata(dir.join(name)).is_ok() {
            present.insert(PathBuf::from(name));
        }
    }
    validate_cert_material_set(dir, &present)
}

/// 在 `CertLock` 保护下把证书目录复制到备份临时目录，校验配套后再落到 `certs/`。
///
/// 证书目录不存在（HTTP/无 TLS 的 hub）时直接跳过，不因缺目录失败；目录存在
/// 但只有非证书文件时按原样复制。任何配套校验失败都会删除临时目录并中止本次
/// 备份（`BackupDirGuard` 随后删除整个时间戳目录），不会写出 manifest。
fn copy_certs_snapshot(data_dir: &Path, backup_dir: &Path) -> Result<()> {
    let source = tls::cert_dir(data_dir);
    match fs::symlink_metadata(&source) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                bail!("证书路径是符号链接，拒绝备份: {}", source.display());
            }
            if !meta.is_dir() {
                bail!("证书路径不是目录: {}", source.display());
            }
        }
        // HTTP hub 没有证书目录：保持可备份，manifest 不包含 certs。
        // 明确告警而不是静默省略，便于发现「TLS hub 证书目录被误删」。
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %source.display(),
                "证书目录不存在，本次备份不包含证书材料"
            );
            return Ok(());
        }
        Err(err) => {
            return Err(err).with_context(|| format!("读取证书路径失败: {}", source.display()))
        }
    }

    let _lock = acquire_cert_lock_bounded(&source)?;
    // 持锁后目录可能已被清理（安装器删除/手工操作）；重新确认，避免为了
    // 复制不存在的目录而失败，也避免在目录缺失时生成空 certs。
    match fs::symlink_metadata(&source) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
        Ok(_) => bail!("证书路径不是普通目录: {}", source.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(err).with_context(|| format!("读取证书路径失败: {}", source.display()))
        }
    }

    let temp = backup_dir.join("certs.partial");
    copy_tree(&source, &temp, "certs")?;
    if let Err(err) = validate_cert_material(&temp) {
        let _ = fs::remove_dir_all(&temp);
        return Err(err).context("证书材料一致性校验失败，本次备份已中止");
    }
    let destination = backup_dir.join("certs");
    if let Err(err) = fs::rename(&temp, &destination) {
        let _ = fs::remove_dir_all(&temp);
        return Err(err).with_context(|| {
            format!(
                "提交证书备份目录失败: {} -> {}",
                temp.display(),
                destination.display()
            )
        });
    }
    Ok(())
}

/// manifest 中 `certs/` 下实际会写入的相对路径集合。
fn manifest_cert_paths(manifest: &Manifest) -> Result<std::collections::BTreeSet<PathBuf>> {
    let mut paths = std::collections::BTreeSet::new();
    for file in &manifest.files {
        let rel = safe_relative_path(&file.path)?;
        let Ok(within) = rel.strip_prefix("certs") else {
            continue;
        };
        if !within.as_os_str().is_empty() {
            paths.insert(within.to_path_buf());
        }
    }
    Ok(paths)
}

/// 校验备份内 **manifest 实际会写入的** 证书材料配套；不配套时在写目标前拒绝。
fn validate_backup_cert_material(backup_dir: &Path, manifest: &Manifest) -> Result<()> {
    let present = manifest_cert_paths(manifest)?;
    if present.is_empty() {
        return Ok(());
    }
    let certs_dir = backup_dir.join("certs");
    let meta = fs::symlink_metadata(&certs_dir)
        .with_context(|| format!("读取备份证书目录失败: {}", certs_dir.display()))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!("备份证书路径不是普通目录: {}", certs_dir.display());
    }
    validate_cert_material_set(&certs_dir, &present)
        .context("备份中的证书材料不配套，拒绝恢复（未覆盖现有材料）")
}

/// 把证书目录复制到备份目录（目录 0700、文件 0600，拒绝符号链接）。
///
/// 持久化的 `.rotate.lock` 不属于证书材料，排除在备份之外；否则 restore 会
/// 用备份里的旧锁文件覆盖目标目录中正在使用的锁 inode。
fn copy_tree(source: &Path, destination: &Path, rel: &str) -> Result<()> {
    let meta = fs::symlink_metadata(source)
        .with_context(|| format!("读取证书路径失败: {}", source.display()))?;
    if meta.file_type().is_symlink() {
        bail!("证书路径是符号链接，拒绝备份: {}", source.display());
    }
    if !meta.is_dir() {
        bail!("证书路径不是目录: {}", source.display());
    }
    fsutil::ensure_dir(destination, 0o700)
        .with_context(|| format!("创建证书备份目录失败: {}", destination.display()))?;
    let mut entries = fs::read_dir(source)
        .with_context(|| format!("读取证书目录失败: {}", source.display()))?
        .collect::<std::io::Result<Vec<_>>>()
        .context("读取证书目录项失败")?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        if name.to_string_lossy() == CERT_LOCK_FILE {
            // 锁文件是运行态资源，不是证书材料；复制它会在 restore 时覆盖
            // 目标目录当前正在使用的锁 inode。
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(&name);
        let child_rel = format!("{rel}/{}", name.to_string_lossy());
        let meta = fs::symlink_metadata(&source_path)
            .with_context(|| format!("读取证书文件失败: {}", source_path.display()))?;
        if meta.file_type().is_symlink() {
            bail!("证书目录包含符号链接，拒绝备份: {}", source_path.display());
        }
        if meta.is_dir() {
            copy_tree(&source_path, &destination_path, &child_rel)?;
        } else if meta.is_file() {
            let bytes = fs::read(&source_path)
                .with_context(|| format!("读取证书文件失败: {}", source_path.display()))?;
            write_private_file(&destination_path, &bytes)?;
        } else {
            bail!("证书目录包含特殊文件，拒绝备份: {}", source_path.display());
        }
    }
    Ok(())
}

/// 收集备份目录中某棵树下的所有普通文件，写入 manifest 清单。
fn collect_files(root: &Path, rel: &Path, files: &mut Vec<ManifestFile>) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    let meta = fs::symlink_metadata(root)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        bail!("备份目录中的 {} 不是普通目录", root.display());
    }
    let mut entries = fs::read_dir(root)?
        .collect::<std::io::Result<Vec<_>>>()
        .context("读取备份目录项失败")?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let child_rel = rel.join(entry.file_name());
        let meta = fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            bail!(
                "备份目录出现符号链接，拒绝生成 manifest: {}",
                path.display()
            );
        }
        if meta.is_dir() {
            collect_files(&path, &child_rel, files)?;
        } else if meta.is_file() {
            record_file_entry(&path, &child_rel, files)?;
        } else {
            bail!("备份目录出现特殊文件: {}", path.display());
        }
    }
    Ok(())
}

/// 记录单个已知文件（路径相对于备份目录）。
fn record_file(base: &Path, rel: &Path, files: &mut Vec<ManifestFile>) -> Result<()> {
    let path = base.join(rel);
    record_file_entry(&path, rel, files)
}

fn record_file_entry(path: &Path, rel: &Path, files: &mut Vec<ManifestFile>) -> Result<()> {
    let meta = fs::symlink_metadata(path)
        .with_context(|| format!("读取备份文件失败: {}", path.display()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        bail!("备份文件不是普通文件: {}", path.display());
    }
    let mode = if cfg!(unix) {
        use std::os::unix::fs::PermissionsExt;
        format!("{:04o}", meta.permissions().mode() & 0o777)
    } else {
        "0600".to_string()
    };
    files.push(ManifestFile {
        path: rel.to_string_lossy().replace('\\', "/"),
        sha256: sha256_file(path)?,
        size: meta.len(),
        mode,
    });
    Ok(())
}

/// 恢复证书目录：先校验备份内证书/私钥配套，再在 `CertLock` 下写目标。
///
/// 校验失败直接返回，不创建/覆盖目标证书目录；manifest 里没有证书文件时
/// 不创建空目录（HTTP hub 备份）。`cert_lock` 由 `restore` 在数据库替换前
/// 获取并持有；单元测试传 `None` 时自行取锁。
fn restore_certs(
    backup_dir: &Path,
    manifest: &Manifest,
    data_dir: &Path,
    cert_lock: Option<&CertLock>,
) -> Result<()> {
    let mut cert_files = Vec::new();
    for file in &manifest.files {
        let rel = safe_relative_path(&file.path)?;
        if !rel.starts_with("certs") || rel.as_os_str() == "certs" {
            continue;
        }
        let within = rel.strip_prefix("certs").expect("前面已确认 certs 前缀");
        if within
            .file_name()
            .is_some_and(|name| name.to_string_lossy() == CERT_LOCK_FILE)
        {
            continue;
        }
        cert_files.push((safe_join(backup_dir, &rel)?, within.to_path_buf()));
    }
    if cert_files.is_empty() {
        return Ok(());
    }
    validate_backup_cert_material(backup_dir, manifest)?;

    let certs_dst = tls::cert_dir(data_dir);
    reject_existing_symlinks(&certs_dst)?;
    fsutil::ensure_dir(&certs_dst, 0o700)
        .with_context(|| format!("创建证书目录失败: {}", certs_dst.display()))?;
    // 写目标证书与 rotate-cert/ACME 串行；调用方已持锁时不重复获取（同进程
    // 两个 fd 的 flock 会互相冲突）。
    let _owned_lock = match cert_lock {
        Some(_) => None,
        None => Some(acquire_cert_lock_bounded(&certs_dst)?),
    };
    for (source, within) in cert_files {
        let destination = certs_dst.join(within);
        reject_existing_symlinks(&destination)?;
        let bytes =
            fs::read(&source).with_context(|| format!("读取备份证书失败: {}", source.display()))?;
        write_private_file(&destination, &bytes)?;
    }
    Ok(())
}

/// restore 前对当前目标做快照；失败时调用方必须中止恢复。
fn pre_restore_snapshot(target_cfg: &HubConfig, target_config_bytes: &[u8]) -> Result<PathBuf> {
    let out_root = target_cfg.data_dir.join("backups");
    snapshot_to(&out_root, target_cfg, target_config_bytes, true).context("创建恢复前目标备份失败")
}

fn load_optional_config_snapshot(path: &Path) -> Result<Option<(Vec<u8>, HubConfig)>> {
    match fs::symlink_metadata(path) {
        Ok(_) => load_config_snapshot(path).map(Some),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("检查配置文件失败: {}", path.display())),
    }
}

/// PostgreSQL schema 版本；连接/查询失败必须 fail closed，不能回退成“最新”。
///
/// 连接使用与 Hub 运行连接相同的 DSN/TLS/密码策略；`schema_migrations` 不存在
/// 或 `MAX(version)` 为 NULL 都返回 0（随后由 schema 门禁拒绝旧库），绝不静默
/// 把不可达/旧库标成当前支持版本。
fn postgres_schema_version(cfg: &HubConfig, dsn: &str) -> Result<i64> {
    let redacted = dsn_redacted(dsn);
    let mut client = connect_with_config(cfg, dsn)
        .with_context(|| format!("连接 PostgreSQL 读取 schema 版本失败（{redacted}）"))?;
    let exists: bool = client
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = 'schema_migrations')",
            &[],
        )
        .with_context(|| format!("检查 PostgreSQL schema_migrations 失败（{redacted}）"))?
        .get(0);
    if !exists {
        return Ok(0);
    }
    let version: Option<i64> = client
        .query_one("SELECT MAX(version) FROM schema_migrations", &[])
        .with_context(|| format!("读取 PostgreSQL schema 版本失败（{redacted}）"))?
        .get(0);
    Ok(version.unwrap_or(0))
}

fn supported_schema(backend: &Backend) -> i64 {
    match backend {
        Backend::Sqlite => SQLITE_SCHEMA_VERSION,
        Backend::Postgres => POSTGRES_SCHEMA_VERSION,
    }
}

/// 恢复前的 schema 门禁：v1.0.0 只接受 v9 备份，旧 schema 一律在写目标前拒绝。
///
/// 启动路径（SQLite/PG）同样 fail closed；这里提前到 restore 入口，避免先
/// 覆盖目标数据库/证书/配置、直到下次打开数据库才发现不兼容。
fn validate_manifest_schema(backend: Backend, schema: i64) -> Result<()> {
    ensure_schema_supported(backend, schema).with_context(|| {
        format!(
            "备份 manifest 的 schema 版本为 v{schema}，当前程序要求 v{}",
            supported_schema(&backend)
        )
    })
}

/// v1.0.0 的 schema 门禁：只接受当前支持版本，旧版本统一给 fresh-install 文案。
///
/// 备份源、恢复 manifest 与迁移目标共用这一判定；调用方必须在使用
/// `--force` 的 dump/TRUNCATE 或写入任何目标文件之前执行。
fn ensure_schema_supported(backend: Backend, schema: i64) -> Result<()> {
    let supported = supported_schema(&backend);
    if schema > supported {
        bail!(
            "数据库 schema 版本 {schema} 高于本程序支持的 {supported}；\
             请升级 rustboard-hub 后再试"
        );
    }
    if schema < supported {
        bail!(
            "检测到已有数据库 schema v{schema}：v1.0.0 只支持全新安装，\
             不执行任何旧 schema 升级或数据回填；旧数据兼容将在首个正式版本之后提供。\
             请先备份该数据库，再按全新安装部署（本程序不会修改旧库）"
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    Sqlite,
    Postgres,
}

fn backend_name(kind: &DatabaseKind) -> &'static str {
    match kind {
        DatabaseKind::Sqlite(_) => "sqlite",
        DatabaseKind::Postgres(_) => "postgres",
    }
}

fn backend_of(kind: &DatabaseKind) -> Backend {
    match kind {
        DatabaseKind::Sqlite(_) => Backend::Sqlite,
        DatabaseKind::Postgres(_) => Backend::Postgres,
    }
}

fn backend_name_of(backend: Backend) -> &'static str {
    match backend {
        Backend::Sqlite => "sqlite",
        Backend::Postgres => "postgres",
    }
}

fn parse_backend(raw: &str) -> Result<Backend> {
    match raw {
        "sqlite" => Ok(Backend::Sqlite),
        "postgres" | "postgresql" => Ok(Backend::Postgres),
        other => bail!("备份 manifest 的 backend 非法: {other}"),
    }
}

fn database_file_name(backend: Backend) -> &'static str {
    match backend {
        Backend::Sqlite => "rustboard.db",
        Backend::Postgres => "rustboard.dump",
    }
}

fn database_file_name_from_kind(kind: &DatabaseKind) -> &'static str {
    match kind {
        DatabaseKind::Sqlite(_) => "rustboard.db",
        DatabaseKind::Postgres(_) => "rustboard.dump",
    }
}

fn dsn_redacted(dsn: &str) -> String {
    redact_database_url(dsn)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("打开文件失败: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("读取文件失败: {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn sync_file(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("fsync 文件失败: {}", path.display()))
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .with_context(|| format!("fsync 目录失败: {}", path.display()))
}

fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…（截断）", &text[..end])
}

fn rand_suffix() -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
        .hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    hasher.finish()
}

/// UTC 时间：`YYYY-MM-DDTHH:MM:SS.mmmZ`。
fn format_rfc3339(ms: i64) -> String {
    let (year, month, day, hour, minute, second, millis) = utc_parts(ms);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// 备份目录名：`YYYYMMDDTHHMMSS.mmmZ`。
pub(crate) fn format_timestamp(ms: i64) -> String {
    let (year, month, day, hour, minute, second, millis) = utc_parts(ms);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}.{millis:03}Z")
}

fn utc_parts(ms: i64) -> (i64, u32, u32, u32, u32, u32, u32) {
    let seconds = ms.div_euclid(1000);
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = (second_of_day / 3_600) as u32;
    let minute = ((second_of_day % 3_600) / 60) as u32;
    let second = (second_of_day % 60) as u32;
    let millis = ms.rem_euclid(1000) as u32;
    (year, month, day, hour, minute, second, millis)
}

/// Howard Hinnant `civil_from_days`：Unix 天数 → 公历年月日（UTC）。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    (
        year + if month <= 2 { 1 } else { 0 },
        month as u32,
        day as u32,
    )
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, MutexGuard};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);
    /// 进程级环境变量 + PATH 读取/修改必须串行，避免测试相互干扰。
    static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct TestRoot {
        path: PathBuf,
    }

    impl TestRoot {
        fn new(tag: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default();
            let path = std::env::temp_dir().join(format!(
                "rb-backup-unit-{tag}-{}-{}-{nanos}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("创建测试根目录");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 测试结束（含 panic）时恢复被修改的环境变量。
    struct EnvRestore {
        values: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvRestore {
        fn capture(keys: &[&'static str]) -> Self {
            Self {
                values: keys
                    .iter()
                    .map(|key| (*key, std::env::var_os(key)))
                    .collect(),
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (key, value) in &self.values {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    fn write_db(path: &Path) {
        let conn = SqliteConnection::open(path).expect("创建测试 SQLite");
        conn.pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
            .expect("设置测试 schema 版本");
    }

    fn make_certs(data_dir: &Path) {
        tls::ensure_self_signed_server(
            data_dir,
            &["127.0.0.1".to_string()],
            tls::CertPolicy::default(),
        )
        .expect("生成测试证书");
    }

    fn sqlite_cfg(data_dir: &Path, db: &Path) -> HubConfig {
        HubConfig {
            data_dir: data_dir.to_path_buf(),
            database: format!("sqlite://{}", db.display()),
            ..HubConfig::default()
        }
    }

    fn manifest_paths(manifest: &Manifest) -> Vec<String> {
        manifest
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect()
    }

    fn assert_no_timestamp_dirs(out: &Path) {
        let entries: Vec<_> = fs::read_dir(out)
            .expect("读取备份根目录")
            .map(|entry| entry.expect("目录项").path())
            .collect();
        assert!(entries.is_empty(), "失败备份不得留下目录: {entries:?}");
    }

    /// #52：正常备份包含配套证书，manifest 成功；恢复后 TLS 服务端配置可构建。
    #[test]
    fn snapshot_copies_consistent_certs_and_restore_builds_server_config() {
        let root = TestRoot::new("certs-ok");
        let data_dir = root.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        make_certs(&data_dir);
        let db = data_dir.join("rustboard.db");
        write_db(&db);
        let cfg = sqlite_cfg(&data_dir, &db);

        // 模拟 rotate-cert 持久锁文件：不能进入备份/manifest。
        fs::write(tls::cert_dir(&data_dir).join(CERT_LOCK_FILE), b"lock").unwrap();
        let out = root.path().join("backups");
        let backup = snapshot_to(&out, &cfg, b"data_dir = \"placeholder\"\n", false)
            .expect("正常备份必须成功");
        let manifest = read_manifest(&backup).expect("manifest 必须可读");
        let paths = manifest_paths(&manifest);
        for rel in [
            "certs/server.crt",
            "certs/server.key",
            "certs/ca.crt",
            "certs/ca.key",
        ] {
            assert!(
                paths.contains(&rel.to_string()),
                "manifest 缺少 {rel}: {paths:?}"
            );
        }
        assert!(
            paths.iter().all(|path| !path.ends_with(CERT_LOCK_FILE)),
            "锁文件不得进入备份: {paths:?}"
        );
        verify_manifest_files(&backup, &manifest).expect("manifest 哈希必须自洽");
        validate_backup_cert_material(&backup, &manifest).expect("备份证书必须配套");

        // 删除目标证书后恢复：材料配套，TLS 配置可构建（等价于可启动）。
        fs::remove_dir_all(tls::cert_dir(&data_dir)).unwrap();
        restore_certs(&backup, &manifest, &data_dir, None).expect("配套证书必须能恢复");
        let config = tls::server_config(&data_dir).expect("恢复后 TLS 服务端配置必须可构建");
        assert!(!config.alpn_protocols.is_empty());
    }

    /// #52：HTTP hub 没有证书目录时不因缺目录失败，也不创建空 certs。
    #[test]
    fn snapshot_allows_missing_cert_dir_for_plain_http_hub() {
        let root = TestRoot::new("no-certs");
        let data_dir = root.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let db = data_dir.join("rustboard.db");
        write_db(&db);
        let cfg = sqlite_cfg(&data_dir, &db);

        let out = root.path().join("backups");
        let backup = snapshot_to(&out, &cfg, b"data_dir = \"placeholder\"\n", false)
            .expect("无证书目录不得导致备份失败");
        let manifest = read_manifest(&backup).unwrap();
        assert!(
            manifest_paths(&manifest)
                .iter()
                .all(|path| !path.starts_with("certs")),
            "无证书时 manifest 不应包含 certs"
        );
        assert!(!backup.join("certs").exists());
        restore_certs(&backup, &manifest, &data_dir, None).expect("无证书备份恢复应为空操作");
        assert!(!tls::cert_dir(&data_dir).exists(), "不应创建空证书目录");
    }

    /// P0：旧 v8 SQLite 源库必须在生成 manifest 前拒绝，且文案与启动一致。
    #[test]
    fn snapshot_rejects_legacy_sqlite_source_before_manifest() {
        let root = TestRoot::new("legacy-source");
        let data_dir = root.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let db = data_dir.join("rustboard.db");
        {
            let conn = SqliteConnection::open(&db).expect("创建测试 SQLite");
            conn.pragma_update(None, "user_version", 8)
                .expect("设置旧 schema 版本");
        }
        let cfg = sqlite_cfg(&data_dir, &db);
        let out = root.path().join("backups");
        let err = snapshot_to(&out, &cfg, b"data_dir = \"placeholder\"\n", false)
            .expect_err("v8 源库不得产出备份");
        let message = format!("{err:#}");
        assert!(message.contains("只支持全新安装"), "{message}");
        assert!(
            message.contains("旧数据兼容将在首个正式版本之后提供"),
            "{message}"
        );
        assert_no_timestamp_dirs(&out);
    }

    /// P1 复审：PG schema 探测失败必须 fail closed，不能回退成 v9 后继续 dump。
    #[test]
    fn snapshot_fails_closed_when_pg_schema_probe_is_unreachable() {
        let _guard = env_lock();
        let root = TestRoot::new("pg-probe-unreachable");
        let fake_bin = root.path().join("bin");
        let argv_file = root.path().join("argv.txt");
        let env_file = root.path().join("env.txt");
        install_fake_pg_tool(&fake_bin, "pg_dump", &argv_file, &env_file);

        let _restore = EnvRestore::capture(&["PATH"]);
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut new_path = OsString::from(fake_bin.display().to_string());
        new_path.push(":");
        new_path.push(old_path);
        std::env::set_var("PATH", new_path);

        let data_dir = root.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        let cfg = HubConfig {
            data_dir,
            database: "postgres://u:secret@127.0.0.1:1/db?sslmode=disable".to_string(),
            db_connect_timeout_ms: 200,
            ..HubConfig::default()
        };
        let out = root.path().join("backups");
        let err = snapshot_to(&out, &cfg, b"data_dir = \"placeholder\"\n", false)
            .expect_err("不可达目标不得产出备份");
        let message = format!("{err:#}");
        assert!(
            message.contains("读取 schema 版本失败"),
            "应报 PG schema 探测失败: {message}"
        );
        assert!(!argv_file.exists(), "schema 探测失败后不得执行 pg_dump");
        assert_no_timestamp_dirs(&out);
    }

    /// P0：恢复侧不能只信 manifest；真实 SQLite 版本/表清单必须校验。
    #[test]
    fn sqlite_assert_v9_rejects_legacy_and_incomplete_database() {
        let root = TestRoot::new("assert-v9");
        let legacy = root.path().join("legacy.db");
        {
            let conn = SqliteConnection::open(&legacy).unwrap();
            conn.pragma_update(None, "user_version", 8).unwrap();
        }
        let err = sqlite_assert_v9(&legacy, "测试 SQLite ").expect_err("v8 必须拒绝");
        assert!(format!("{err:#}").contains("只支持全新安装"), "{err:#}");

        let incomplete = root.path().join("incomplete.db");
        {
            let conn = SqliteConnection::open(&incomplete).unwrap();
            conn.pragma_update(None, "user_version", SQLITE_SCHEMA_VERSION)
                .unwrap();
        }
        let err = sqlite_assert_v9(&incomplete, "测试 SQLite ").expect_err("缺表必须拒绝");
        let message = format!("{err:#}");
        assert!(message.contains("缺少表"), "{message}");
        assert!(message.contains("拒绝恢复"), "{message}");
    }

    /// #52：旧 crt + 新 key 的交错快照必须拒绝，且不留下半成品目录。
    #[test]
    fn snapshot_rejects_interleaved_old_cert_new_key() {
        let root = TestRoot::new("cert-mismatch");
        let data_dir = root.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        make_certs(&data_dir);
        let db = data_dir.join("rustboard.db");
        write_db(&db);
        let cfg = sqlite_cfg(&data_dir, &db);

        let new_key = rcgen::KeyPair::generate().expect("生成新 key");
        let key_path = tls::cert_dir(&data_dir).join(tls::SERVER_KEY_FILE);
        fs::write(&key_path, new_key.serialize_pem()).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let out = root.path().join("backups");
        let err = snapshot_to(&out, &cfg, b"data_dir = \"placeholder\"\n", false)
            .expect_err("证书/私钥不配套必须拒绝备份");
        let message = format!("{err:#}");
        assert!(message.contains("不配套"), "{message}");
        assert_no_timestamp_dirs(&out);
    }

    /// #52：持有 CertLock 时，备份有界等待后安全失败（不会无锁复制）。
    #[test]
    fn snapshot_fails_bounded_when_cert_lock_is_held() {
        let root = TestRoot::new("cert-lock");
        let data_dir = root.path().join("data");
        fs::create_dir_all(&data_dir).unwrap();
        make_certs(&data_dir);
        let db = data_dir.join("rustboard.db");
        write_db(&db);
        let cfg = sqlite_cfg(&data_dir, &db);

        let _lock = CertLock::acquire(&tls::cert_dir(&data_dir)).expect("测试先持有证书锁");
        let out = root.path().join("backups");
        let started = Instant::now();
        let err = snapshot_to(&out, &cfg, b"data_dir = \"placeholder\"\n", false)
            .expect_err("持锁期间备份必须失败");
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_secs(4),
            "锁冲突应有界等待，实际 {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(30),
            "锁冲突等待必须有限，实际 {elapsed:?}"
        );
        let message = format!("{err:#}");
        assert!(message.contains("证书轮换锁"), "{message}");
        assert_no_timestamp_dirs(&out);
    }

    /// #52：恢复时备份证书不配套 → 拒绝且不覆盖现有材料。
    #[test]
    fn restore_rejects_mismatched_backup_certs_without_overwriting() {
        let root = TestRoot::new("restore-mismatch");
        let source_dir = root.path().join("source");
        let target_dir = root.path().join("target");
        fs::create_dir_all(&source_dir).unwrap();
        fs::create_dir_all(&target_dir).unwrap();
        make_certs(&source_dir);
        make_certs(&target_dir);

        let backup = root.path().join("backup");
        fs::create_dir_all(&backup).unwrap();
        copy_tree(&tls::cert_dir(&source_dir), &backup.join("certs"), "certs").unwrap();
        // 篡改备份的 key，让证书与私钥不配套。
        let new_key = rcgen::KeyPair::generate().expect("生成新 key");
        let key_path = backup.join("certs").join(tls::SERVER_KEY_FILE);
        fs::write(&key_path, new_key.serialize_pem()).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let manifest = Manifest {
            manifest_version: MANIFEST_VERSION,
            version: "test".to_string(),
            schema: SQLITE_SCHEMA_VERSION,
            backend: "sqlite".to_string(),
            created_at: format_rfc3339(now_ms()),
            created_at_ms: now_ms(),
            files: vec![
                ManifestFile {
                    path: format!("certs/{}", tls::SERVER_CERT_FILE),
                    sha256: "0".repeat(64),
                    size: 0,
                    mode: "0600".to_string(),
                },
                ManifestFile {
                    path: format!("certs/{}", tls::SERVER_KEY_FILE),
                    sha256: "0".repeat(64),
                    size: 0,
                    mode: "0600".to_string(),
                },
            ],
        };
        let target_key = tls::cert_dir(&target_dir).join(tls::SERVER_KEY_FILE);
        let before = fs::read(&target_key).unwrap();
        let err = restore_certs(&backup, &manifest, &target_dir, None)
            .expect_err("不配套的备份证书必须拒绝恢复");
        assert!(format!("{err:#}").contains("不配套"), "{err:#}");
        assert_eq!(
            fs::read(&target_key).unwrap(),
            before,
            "拒绝恢复时不得覆盖现有私钥"
        );
    }

    /// 只校验 manifest 实际会写入的证书集合：目录里多出的 key 不能“补全”一对。
    #[test]
    fn restore_validates_only_manifest_cert_set() {
        let root = TestRoot::new("manifest-cert-set");
        let source_dir = root.path().join("source");
        fs::create_dir_all(&source_dir).unwrap();
        make_certs(&source_dir);
        let backup = root.path().join("backup");
        fs::create_dir_all(&backup).unwrap();
        copy_tree(&tls::cert_dir(&source_dir), &backup.join("certs"), "certs").unwrap();

        // manifest 只列出 server.crt；磁盘上的 server.key 不得被用来补全。
        let manifest = Manifest {
            manifest_version: MANIFEST_VERSION,
            version: "test".to_string(),
            schema: SQLITE_SCHEMA_VERSION,
            backend: "sqlite".to_string(),
            created_at: format_rfc3339(now_ms()),
            created_at_ms: now_ms(),
            files: vec![ManifestFile {
                path: format!("certs/{}", tls::SERVER_CERT_FILE),
                sha256: "0".repeat(64),
                size: 0,
                mode: "0600".to_string(),
            }],
        };
        let target_dir = root.path().join("target");
        fs::create_dir_all(&target_dir).unwrap();
        let err = restore_certs(&backup, &manifest, &target_dir, None)
            .expect_err("manifest 缺 key 时必须拒绝");
        let message = format!("{err:#}");
        assert!(message.contains("manifest"), "{message}");
        assert!(message.contains(tls::SERVER_KEY_FILE), "{message}");
        assert!(
            !tls::cert_dir(&target_dir).exists(),
            "拒绝时不得创建目标证书目录"
        );
    }

    /// 旧的 manifest schema（v8）必须在写任何目标前拒绝。
    #[test]
    fn restore_rejects_legacy_schema_before_any_write() {
        for schema in [0, 8] {
            let err =
                validate_manifest_schema(Backend::Sqlite, schema).expect_err("旧 schema 必须拒绝");
            let message = format!("{err:#}");
            assert!(message.contains("只支持全新安装"), "{message}");
            assert!(
                message.contains("旧数据兼容将在首个正式版本之后提供"),
                "{message}"
            );
        }
        assert!(validate_manifest_schema(Backend::Sqlite, SQLITE_SCHEMA_VERSION).is_ok());
        let err = validate_manifest_schema(Backend::Sqlite, SQLITE_SCHEMA_VERSION + 1)
            .expect_err("过新的 schema 必须拒绝");
        assert!(format!("{err:#}").contains("高于"));
    }

    /// #61：配置 TOML 解析错误只保留路径，不回显含 token 的原始行。
    #[test]
    fn config_toml_errors_are_sanitized() {
        let root = TestRoot::new("toml-sanitize");
        let path = root.path().join("hub.toml");
        let secret = "toml-canary-admin-token-77c1";
        for content in [
            // 重复键
            format!("admin_token = \"{secret}\"\nadmin_token = \"other\"\ndata_dir = \"/tmp\"\n"),
            // 类型错误
            format!("admin_token = \"{secret}\"\ndb_pool_size = \"not-a-number\"\n"),
            // 语法错误（未闭合字符串）
            format!("admin_token = \"{secret}\ndata_dir = \"/tmp\"\n"),
        ] {
            fs::write(&path, content.as_bytes()).unwrap();
            let err = load_config_snapshot(&path).expect_err("非法 TOML 必须失败");
            let message = format!("{err:#}");
            assert!(message.contains("TOML 解析失败"), "{message}");
            assert!(message.contains(&path.display().to_string()), "{message}");
            assert!(
                !message.contains(secret),
                "TOML 错误链泄露配置原文: {message}"
            );
        }

        // 恢复备份 hub.toml 的解析路径同样脱敏。
        let backup_toml = root.path().join("backup-hub.toml");
        let invalid = format!("admin_token = \"{secret}\"\nbroken = [\n");
        fs::write(&backup_toml, invalid.as_bytes()).unwrap();
        let backup_cfg = HubConfig::default();
        let err = rewrite_config_paths(
            &backup_cfg,
            &backup_toml,
            invalid.as_bytes(),
            Path::new("/new-data"),
            "postgres://u@h/db",
        )
        .expect_err("非法备份配置必须失败");
        let message = format!("{err:#}");
        assert!(message.contains("TOML 解析失败"), "{message}");
        assert!(!message.contains(secret), "恢复路径泄露配置原文: {message}");
    }

    /// #64：两处密码的优先级与驱动一致（query 覆盖 authority、重复 query 后者）。
    #[test]
    fn pg_dsn_password_priority_matches_driver_semantics() {
        // `PgDsnSecrets::parse` 会读 RUSTBOARD_DATABASE_PASSWORD；与写 env 的测试串行。
        let _guard = env_lock();
        let cfg = HubConfig::default();
        for (dsn, expected) in [
            ("postgres://u:auth-secret@h/db", "auth-secret"),
            ("postgres://u@h/db?password=query-secret", "query-secret"),
            (
                "postgres://u:auth-secret@h/db?password=query-secret",
                "query-secret",
            ),
            (
                "postgres://u@h/db?password=first-secret&password=second-secret",
                "second-secret",
            ),
            (
                "postgres://u:auth-secret@h/db?pass%77ord=encoded-secret",
                "encoded-secret",
            ),
            (
                "postgres://u@h/db?%70assword=encoded-secret",
                "encoded-secret",
            ),
        ] {
            let secrets = PgDsnSecrets::parse(dsn, &cfg).expect("合法 DSN 必须解析成功");
            assert_eq!(
                secrets.password.as_deref(),
                Some(expected),
                "DSN 密码优先级错误: {dsn}"
            );
            for secret in [
                "auth-secret",
                "query-secret",
                "first-secret",
                "second-secret",
                "encoded-secret",
            ] {
                assert!(
                    !secrets.sanitized.contains(secret),
                    "argv DSN 泄露密码 {secret}: {}",
                    secrets.sanitized
                );
            }
            assert!(!secrets.sanitized.contains("password="));
            assert!(!secrets.sanitized.contains("sslpassword="));
        }
    }

    /// #64：非空 `RUSTBOARD_DATABASE_PASSWORD` 覆盖 URL 密码并传给 PGPASSWORD。
    #[test]
    fn pg_dsn_env_password_override_is_used() {
        let _guard = env_lock();
        let _restore = EnvRestore::capture(&["RUSTBOARD_DATABASE_PASSWORD"]);
        std::env::set_var("RUSTBOARD_DATABASE_PASSWORD", "env-secret-override");
        let secrets = PgDsnSecrets::parse(
            "postgres://u:url-secret@h/db?password=query-secret",
            &HubConfig::default(),
        )
        .unwrap();
        assert_eq!(secrets.password.as_deref(), Some("env-secret-override"));
        assert_eq!(secrets.url_password.as_deref(), Some("query-secret"));
        assert!(!secrets.sanitized.contains("url-secret"));
        assert!(!secrets.sanitized.contains("query-secret"));
    }

    /// 在 PATH 前置一个捕获 argv/env 的 fake 工具目录。
    fn install_fake_pg_tool(dir: &Path, name: &str, argv_file: &Path, env_file: &Path) {
        fs::create_dir_all(dir).unwrap();
        let script = format!(
            "#!/bin/sh\n\
             if [ \"${{1:-}}\" = \"--version\" ]; then echo '{name} (fake) 1'; exit 0; fi\n\
             : > {argv}\n\
             for arg in \"$@\"; do printf '%s\\n' \"$arg\" >> {argv}; done\n\
             env > {env}\n\
             prev=\"\"\n\
             for arg in \"$@\"; do\n\
               if [ \"$prev\" = \"--file\" ]; then printf 'fake dump' > \"$arg\"; fi\n\
               prev=\"$arg\"\n\
             done\n\
             exit 0\n",
            argv = sh_quote(&argv_file.display().to_string()),
            env = sh_quote(&env_file.display().to_string()),
        );
        let path = dir.join(name);
        fs::write(&path, script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn sh_quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    fn env_has(text: &str, key: &str) -> bool {
        let prefix = format!("{key}=");
        text.lines().any(|line| line.starts_with(&prefix))
    }

    fn env_value(text: &str, key: &str) -> Option<String> {
        let prefix = format!("{key}=");
        text.lines()
            .find_map(|line| line.strip_prefix(&prefix).map(str::to_string))
    }

    /// #67：fake `pg_dump` 捕获 argv + env：无密码、默认 verify-full、根 CA 正确，
    /// 且清理会降级/覆盖的继承环境。
    #[test]
    fn pg_dump_inherits_hub_tls_policy_and_clears_environment() {
        let _guard = env_lock();
        let root = TestRoot::new("fake-pg-dump");
        let fake_bin = root.path().join("bin");
        let argv_file = root.path().join("argv.txt");
        let env_file = root.path().join("env.txt");
        install_fake_pg_tool(&fake_bin, "pg_dump", &argv_file, &env_file);
        let ca = root.path().join("private-ca.pem");
        fs::write(&ca, b"dummy ca").unwrap();
        let cfg = HubConfig {
            db_sslrootcert: Some(ca.clone()),
            ..HubConfig::default()
        };
        // 无密码 DSN：验证清理继承的 PGPASSWORD，而不是把宿主旧密码带进工具。
        let dsn = "postgres://rb_user@db.example.com:5432/rustboard";

        let _restore = EnvRestore::capture(&[
            "PATH",
            "PGSSLMODE",
            "PGSSLROOTCERT",
            "PGPASSWORD",
            "PGSSLPASSWORD",
            "PGREQUIRESSL",
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGSSLNEGOTIATION",
            "PGUSER",
            "PGPASSFILE",
            "PGSSLCERT",
            "PGOPTIONS",
        ]);
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut new_path = OsString::from(fake_bin.display().to_string());
        new_path.push(":");
        new_path.push(old_path);
        std::env::set_var("PATH", new_path);
        std::env::set_var("PGSSLMODE", "disable");
        std::env::set_var("PGSSLROOTCERT", "/bogus-root.pem");
        std::env::set_var("PGPASSWORD", "inherited-leak");
        std::env::set_var("PGSSLPASSWORD", "inherited-ssl-leak");
        std::env::set_var("PGREQUIRESSL", "1");
        std::env::set_var("PGSERVICE", "evil");
        std::env::set_var("PGSERVICEFILE", "/bogus-service.conf");
        std::env::set_var("PGSSLNEGOTIATION", "direct");
        std::env::set_var("PGUSER", "inherited-user");
        std::env::set_var("PGPASSFILE", "/bogus-pgpass");
        std::env::set_var("PGSSLCERT", "/bogus-client.crt");
        std::env::set_var("PGOPTIONS", "-c search_path=evil");

        let destination = root.path().join("rustboard.dump");
        pg_dump_to(&cfg, dsn, &destination).expect("fake pg_dump 应成功");
        assert!(destination.is_file());

        let argv = fs::read_to_string(&argv_file).unwrap();
        assert!(!argv.contains("db-secret"), "argv 泄露密码: {argv}");
        assert!(
            argv.lines()
                .any(|line| line == "postgres://rb_user@db.example.com:5432/rustboard"),
            "argv --dbname 必须剥离密码: {argv}"
        );
        assert!(!argv.contains("sslmode"), "argv 不应携带 sslmode: {argv}");

        let env = fs::read_to_string(&env_file).unwrap();
        assert_eq!(
            env_value(&env, "PGSSLMODE").as_deref(),
            Some("verify-full"),
            "缺省必须是 verify-full"
        );
        assert_eq!(
            env_value(&env, "PGSSLROOTCERT"),
            Some(ca.display().to_string()),
            "根 CA 必须来自 db_sslrootcert"
        );
        assert!(!env_has(&env, "PGPASSWORD"), "无密码时不得设置 PGPASSWORD");
        assert!(
            !env.contains("inherited-leak") && !env.contains("inherited-ssl-leak"),
            "继承的密码环境必须被清理"
        );
        for key in [
            "PGSSLPASSWORD",
            "PGREQUIRESSL",
            "PGSERVICE",
            "PGSERVICEFILE",
            "PGSSLNEGOTIATION",
            "PGUSER",
            "PGPASSFILE",
            "PGSSLCERT",
            "PGOPTIONS",
        ] {
            assert!(!env_has(&env, key), "继承的 {key} 必须清理");
        }
    }

    /// P1 复审：密码含裸 `/` 时，fake pg_dump 的 argv 仍不得出现密码。
    #[test]
    fn pg_dump_argv_never_contains_raw_slash_password() {
        let _guard = env_lock();
        let root = TestRoot::new("raw-slash-password");
        let fake_bin = root.path().join("bin");
        let argv_file = root.path().join("argv.txt");
        let env_file = root.path().join("env.txt");
        install_fake_pg_tool(&fake_bin, "pg_dump", &argv_file, &env_file);

        let _restore = EnvRestore::capture(&["PATH", "PGPASSWORD"]);
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut new_path = OsString::from(fake_bin.display().to_string());
        new_path.push(":");
        new_path.push(old_path);
        std::env::set_var("PATH", new_path);

        let dsn = "postgres://rb_user:2024/secret@127.0.0.1:1/db?sslmode=disable";
        let destination = root.path().join("rustboard.dump");
        pg_dump_to(&HubConfig::default(), dsn, &destination).expect("fake pg_dump 应成功");
        let argv = fs::read_to_string(&argv_file).unwrap();
        for secret in ["2024/secret", "secret"] {
            assert!(
                !argv.contains(secret),
                "argv 泄露裸 / 密码 {secret}: {argv}"
            );
        }
        assert!(
            argv.lines()
                .any(|line| line == "postgres://rb_user@127.0.0.1:1/db"),
            "argv --dbname 必须按第一个 @ 剥离 userinfo: {argv}"
        );
        let env = fs::read_to_string(&env_file).unwrap();
        assert_eq!(
            env_value(&env, "PGPASSWORD").as_deref(),
            Some("2024/secret"),
            "密码必须只通过 PGPASSWORD 传递"
        );
    }

    /// #67：显式 disable 与 DSN sslrootcert 的处理；fake pg_restore 捕获 env。
    #[test]
    fn pg_restore_honours_disable_and_dsn_rootcert() {
        let _guard = env_lock();
        let root = TestRoot::new("fake-pg-restore");
        let fake_bin = root.path().join("bin");
        let argv_file = root.path().join("argv.txt");
        let env_file = root.path().join("env.txt");
        install_fake_pg_tool(&fake_bin, "pg_restore", &argv_file, &env_file);

        let _restore = EnvRestore::capture(&["PATH", "PGSSLMODE", "PGSSLROOTCERT"]);
        let old_path = std::env::var_os("PATH").unwrap_or_default();
        let mut new_path = OsString::from(fake_bin.display().to_string());
        new_path.push(":");
        new_path.push(old_path);
        std::env::set_var("PATH", new_path);
        std::env::set_var("PGSSLMODE", "verify-full");
        std::env::set_var("PGSSLROOTCERT", "/bogus-root.pem");

        let dump = root.path().join("rustboard.dump");
        fs::write(&dump, b"fake").unwrap();
        let dsn = "postgres://u:auth-secret@h/db?sslmode=disable&\
                   sslrootcert=%2Ftmp%2Fdsn-ca.pem&password=query-secret";
        pg_restore_from(&HubConfig::default(), dsn, &dump).expect("fake pg_restore 应成功");

        let argv = fs::read_to_string(&argv_file).unwrap();
        assert!(!argv.contains("auth-secret") && !argv.contains("query-secret"));
        assert!(
            argv.lines().any(|line| line == "postgres://u@h/db"),
            "argv 必须剥离密码/TLS 参数: {argv}"
        );
        let env = fs::read_to_string(&env_file).unwrap();
        assert_eq!(env_value(&env, "PGSSLMODE").as_deref(), Some("disable"));
        assert!(
            !env_has(&env, "PGSSLROOTCERT"),
            "disable 下不得传递根 CA: {env}"
        );
        assert_eq!(
            env_value(&env, "PGPASSWORD").as_deref(),
            Some("query-secret"),
            "query password 覆盖 authority"
        );

        // 缺省 verify-full + DSN sslrootcert：根 CA 必须传给外部工具。
        let verify_dsn = "postgres://u@h/db?sslrootcert=%2Ftmp%2Fdsn-ca.pem";
        pg_restore_from(&HubConfig::default(), verify_dsn, &dump).expect("fake pg_restore 应成功");
        let env = fs::read_to_string(&env_file).unwrap();
        assert_eq!(
            env_value(&env, "PGSSLMODE").as_deref(),
            Some("verify-full"),
            "缺省必须 verify-full: {env}"
        );
        assert_eq!(
            env_value(&env, "PGSSLROOTCERT").as_deref(),
            Some("/tmp/dsn-ca.pem"),
            "DSN sslrootcert 必须传给外部工具: {env}"
        );
        assert!(!env_has(&env, "PGPASSWORD"));

        // 配置根 CA 与 DSN 根 CA 冲突：在启动 fake 工具前 fail closed。
        let _ = fs::remove_file(&argv_file);
        let cfg = HubConfig {
            db_sslrootcert: Some(PathBuf::from("/tmp/other-ca.pem")),
            ..HubConfig::default()
        };
        let err = pg_restore_from(&cfg, dsn, &dump).expect_err("根 CA 冲突必须拒绝");
        assert!(format!("{err:#}").contains("不同文件"), "{err:#}");
        assert!(!argv_file.exists(), "冲突时不得执行 pg_restore");
    }
}
