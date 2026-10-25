//! `rustboard-hub backup / restore`（M5 Phase D5b）。
//!
//! 设计约束：
//!
//! - SQLite 用 `VACUUM INTO` 生成一致快照；PG 用 `pg_dump --format=custom` /
//!   `pg_restore`。外部命令一律用参数数组，绝不拼 shell；
//! - `pg_dump` / `pg_restore` 的 `--dbname` 参数**不含密码**：密码从 DSN 中
//!   提取后只通过 `PGPASSWORD` / `PGSSLPASSWORD` 环境变量传递；
//! - 备份目录 `<out>/<UTC timestamp>/`，内部 `manifest.json` 记录版本、schema、
//!   后端、创建时间与每个文件的 SHA256/大小；配置与证书 0600、目录 0700；
//! - 恢复前校验 manifest 里每个文件的 SHA256 与大小，只接受相对、无 `..`、
//!   无符号链接的路径；恢复前尽可能备份当前目标；恢复配置/证书是显式行为；
//! - 错误信息不输出 DSN 密码；日志只出现 `user:***@host`。

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::SystemTime;

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rusqlite::{Connection as SqliteConnection, OpenFlags};
use rustboard_common::config::{redact_database_url, DatabaseKind, HubConfig};
use rustboard_common::fsutil;
use rustboard_common::tls;
use rustboard_common::util::now_ms;
use rustboard_common::DEFAULT_HUB_CONFIG;
use rustboard_core::storage::postgres::{
    connect_for_schema, PostgresStorage, POSTGRES_SCHEMA_VERSION,
};
use rustboard_install::Prompt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// manifest 格式版本；恢复只接受完全匹配的版本，避免未来格式被旧二进制误读。
const MANIFEST_VERSION: u32 = 1;
/// 本程序支持的 SQLite schema 版本（与 core 的 `SQLITE_SCHEMA_VERSION` 对齐）。
pub(crate) const SQLITE_SCHEMA_VERSION: i64 = 7;
/// 备份/恢复时单个外部命令输出的最大收集长度，避免故障时把巨量日志读入内存。
const MAX_TOOL_OUTPUT: usize = 8 * 1024;

/// hub schema v7 的 21 张业务表。
///
/// 与 `rustboard-core/src/storage/postgres/schema.rs` 的 `TABLES` 保持一致；
/// 只用于 `--force` 前确认目标库没有未知表，以及在迁移 CLIs 中展示。若核心
/// 新增表而这里没更新，`--force` 会因「未知表」拒绝清空，属于 fail-closed。
pub(crate) const HUB_TABLES: [&str; 21] = [
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
    /// 目标非空时仍恢复（恢复前尽可能备份当前目标）。
    #[arg(long)]
    pub force: bool,
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
    let cfg: HubConfig =
        toml::from_str(text).with_context(|| format!("解析配置失败: {}", path.display()))?;
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
    let dir = snapshot_to(&args.out, &cfg, &config_bytes)?;
    println!("备份完成: {}", dir.display());
    println!(
        "后端: {}；schema: {}；文件: {} 个",
        backend_name(&kind),
        read_manifest(&dir)?.schema,
        read_manifest(&dir)?.files.len()
    );
    Ok(())
}

/// `restore` 子命令。
pub fn restore(args: RestoreArgs) -> Result<()> {
    let config_path = config_path(args.config);
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
    if manifest.schema > supported_schema(&backend) {
        bail!(
            "备份 schema 版本 {} 高于当前程序支持的 {}；请升级 rustboard-hub 后再恢复",
            manifest.schema,
            supported_schema(&backend)
        );
    }
    let verified = verify_manifest_files(&args.from, &manifest)?;
    let config_rel = verified
        .get("hub.toml")
        .ok_or_else(|| anyhow!("备份缺少 hub.toml（不完整的备份不能恢复）"))?;
    let db_name = database_file_name(backend);
    if !verified.contains_key(db_name) {
        bail!("备份缺少数据库文件 {db_name}（不完整的备份不能恢复）");
    }
    let backup_config_bytes = fs::read(config_rel)?;
    let backup_config_text =
        std::str::from_utf8(&backup_config_bytes).context("备份中的 hub.toml 不是合法 UTF-8")?;
    let backup_cfg: HubConfig =
        toml::from_str(backup_config_text).context("解析备份中的 hub.toml 失败")?;
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
    if !backup_cfg.data_dir.is_absolute() {
        bail!(
            "备份中的 data_dir 不是绝对路径: {}；拒绝恢复",
            backup_cfg.data_dir.display()
        );
    }
    match &backup_kind {
        DatabaseKind::Sqlite(path) if !path.is_absolute() => {
            bail!(
                "备份中的 SQLite 路径不是绝对路径: {}；拒绝恢复",
                path.display()
            );
        }
        _ => {}
    }

    // 2. 外部工具预检（PG 恢复必须在写入任何文件前失败）。
    if backend == Backend::Postgres {
        ensure_tool("pg_restore")?;
    }

    // 3. 检查目标是否可覆盖。
    let target_non_empty = target_has_data(&backup_cfg, &backup_kind)
        .with_context(|| format!("检查恢复目标是否为空失败（{}）", backup_kind.redacted()))?;
    if target_non_empty && !args.force {
        bail!(
            "恢复目标非空（{}）；请先备份并使用 --force，或恢复到一个空数据库",
            backup_kind.redacted()
        );
    }

    // 4. 运行中的 hub 会持续写数据库，恢复会与写入竞争；与 migrate 同样拒绝。
    super::migrate_cmd::ensure_hub_stopped("restore")?;

    // 5. 目标路径安全检查必须在任何破坏性写入之前完成。
    let certs_dst = tls::cert_dir(&backup_cfg.data_dir);
    reject_existing_symlinks(&certs_dst)?;
    reject_existing_symlinks(&config_path)?;
    if let DatabaseKind::Sqlite(path) = &backup_kind {
        reject_existing_symlinks(path)?;
    }

    // 6. 当前配置（如果存在）与当前目标：用于 best-effort 预备份与 .bak。
    let current = load_optional_config_snapshot(&config_path)?;

    // 7. 确认。
    let action = if target_non_empty {
        "恢复目标非空：将先尽可能备份当前目标，再覆盖数据库/配置/证书"
    } else {
        "将恢复数据库/配置/证书到目标位置"
    };
    confirm(
        args.yes,
        &format!(
            "从 {} 恢复 {} 备份？{action}。",
            args.from.display(),
            backend_name(&backup_kind)
        ),
    )?;

    // 8. 非空目标先尽力备份（失败只告警；--force 已由用户显式确认）。
    if target_non_empty {
        match pre_restore_snapshot(&backup_cfg, &config_path, &backup_config_bytes) {
            Ok(path) => println!("恢复前目标备份: {}", path.display()),
            Err(err) => eprintln!("WARN: 恢复前目标备份失败（best effort，继续恢复）: {err:#}"),
        }
    }

    // 9. 先恢复数据，再恢复证书，最后写配置（配置决定下次启动读哪里）。
    match &backup_kind {
        DatabaseKind::Sqlite(path) => {
            restore_sqlite_file(&verified[db_name], path)
                .with_context(|| format!("恢复 SQLite 数据库失败: {}", path.display()))?;
            println!("SQLite 数据库已恢复: {}", path.display());
        }
        DatabaseKind::Postgres(dsn) => {
            pg_restore_from(dsn, &verified[db_name])?;
            println!("PostgreSQL 数据库已恢复: {}", dsn_redacted(dsn));
        }
    }

    restore_certs(&args.from, &manifest, &backup_cfg.data_dir)?;
    println!(
        "证书目录已恢复: {}",
        tls::cert_dir(&backup_cfg.data_dir).display()
    );

    // 配置写最后：数据/证书失败时旧配置仍指向旧路径，避免启动到半恢复状态。
    if let Some((current_bytes, _)) = &current {
        backup_file_next_to(&config_path, current_bytes, "bak")?;
    }
    write_private_file(&config_path, &backup_config_bytes)?;
    println!("配置文件已恢复: {}", config_path.display());

    Ok(())
}

/// 把 manifest、DB、配置和证书写入 `<out_root>/<timestamp>/`，返回目录。
///
/// 仅供 `backup` 与 restore 的 best-effort 预备份使用；调用方负责确认与参数
/// 校验。失败时会删除本次新建的时间戳目录，不留下半成品 manifest。
pub(crate) fn snapshot_to(
    out_root: &Path,
    cfg: &HubConfig,
    config_bytes: &[u8],
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
            sqlite_schema_version(path)?
        }
        DatabaseKind::Postgres(dsn) => postgres_schema_version(dsn),
    };

    match &kind {
        DatabaseKind::Sqlite(path) => {
            let dump = dir.join("rustboard.db");
            sqlite_backup_to(path, &dump, false)?;
        }
        DatabaseKind::Postgres(dsn) => {
            let dump = dir.join("rustboard.dump");
            pg_dump_to(dsn, &dump)?;
        }
    }
    write_private_file(&dir.join("hub.toml"), config_bytes)?;
    copy_tree(&tls::cert_dir(&cfg.data_dir), &dir.join("certs"), "certs").with_context(|| {
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
    let conn = open_sqlite_readonly(path)?;
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
fn restore_sqlite_file(source: &Path, destination: &Path) -> Result<()> {
    // 先在旁路验证备份文件，避免覆盖目标后才发现文件损坏。
    let check = open_sqlite_readonly(source)?
        .query_row("PRAGMA quick_check(1)", [], |row| row.get::<_, String>(0))
        .context("校验待恢复 SQLite 文件失败")?;
    if check != "ok" {
        bail!("待恢复 SQLite 文件完整性校验失败: {check}");
    }
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("SQLite 目标没有父目录: {}", destination.display()))?;
    fsutil::ensure_dir(parent, 0o700)
        .with_context(|| format!("创建 SQLite 目标目录失败: {}", parent.display()))?;
    reject_existing_symlinks(destination)?;
    if fs::symlink_metadata(destination).is_ok_and(|meta| meta.is_dir()) {
        bail!("SQLite 目标是目录，拒绝覆盖: {}", destination.display());
    }

    // 同目录临时文件 + fsync + rename，避免半写数据库。
    let tmp = parent.join(format!(
        ".{}.restore.{}.{:016x}",
        destination
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("rustboard.db"),
        std::process::id(),
        rand_suffix()
    ));
    let mut src =
        File::open(source).with_context(|| format!("打开备份数据库失败: {}", source.display()))?;
    let mut dst = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("创建临时数据库失败: {}", tmp.display()))?;
    std::io::copy(&mut src, &mut dst).context("复制 SQLite 备份失败")?;
    dst.sync_all().context("fsync 临时数据库失败")?;
    drop(dst);
    fs::rename(&tmp, destination)
        .with_context(|| format!("替换 SQLite 数据库失败: {}", destination.display()))?;
    // 备份文件是独立快照；旧 WAL/SHM 必须删除，否则会和新主库不匹配。
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(destination, suffix);
        match fs::remove_file(&sidecar) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("清理旧 SQLite sidecar 失败: {}", sidecar.display()))
            }
        }
    }
    fsutil::harden(destination, 0o600)?;
    sync_dir(parent)?;
    Ok(())
}

/// 外部 `pg_dump` 备份。
pub(crate) fn pg_dump_to(dsn: &str, destination: &Path) -> Result<()> {
    ensure_tool("pg_dump")?;
    if destination.exists() {
        bail!(
            "PostgreSQL 备份目标已存在，拒绝覆盖: {}",
            destination.display()
        );
    }
    let secrets = PgDsnSecrets::parse(dsn)?;
    let mut command = Command::new("pg_dump");
    command
        .arg("--format=custom")
        .arg("--no-owner")
        .arg("--file")
        .arg(destination)
        .arg("--dbname")
        .arg(&secrets.sanitized);
    apply_pg_env(&mut command, &secrets);
    run_pg_tool(command, "pg_dump", dsn, &secrets)?;
    fsutil::harden(destination, 0o600)
        .with_context(|| format!("收紧 PostgreSQL 备份权限失败: {}", destination.display()))?;
    sync_file(destination)?;
    Ok(())
}

/// 外部 `pg_restore` 恢复；`--single-transaction` 保证失败时目标不被半恢复。
fn pg_restore_from(dsn: &str, dump: &Path) -> Result<()> {
    ensure_tool("pg_restore")?;
    let secrets = PgDsnSecrets::parse(dsn)?;
    let mut command = Command::new("pg_restore");
    command
        .arg("--clean")
        .arg("--if-exists")
        .arg("--no-owner")
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

fn apply_pg_env(command: &mut Command, secrets: &PgDsnSecrets) {
    if let Some(password) = secrets.effective_password() {
        command.env("PGPASSWORD", password);
    }
    if let Some(sslpassword) = &secrets.sslpassword {
        command.env("PGSSLPASSWORD", sslpassword);
    }
}

/// 从 PostgreSQL DSN 中提取密码，并生成可以放进 argv 的脱敏 DSN。
///
/// 处理两处密码：authority 的 `user:password@` 与 query 的 `password=`；同时
/// 把 `sslpassword=` 从 DSN 剥离，避免进入 argv。百分号编码的密码会先解码，
/// 再通过环境变量传给 libpq。
#[derive(Debug)]
struct PgDsnSecrets {
    sanitized: String,
    password: Option<String>,
    sslpassword: Option<String>,
}

impl PgDsnSecrets {
    fn parse(dsn: &str) -> Result<Self> {
        let (scheme, rest) = dsn
            .split_once("://")
            .ok_or_else(|| anyhow!("PostgreSQL DSN 缺少 scheme（{}）", dsn_redacted(dsn)))?;
        if !matches!(scheme, "postgres" | "postgresql") {
            bail!("database 不是 PostgreSQL DSN（{}）", dsn_redacted(dsn));
        }
        let authority_end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);
        let (sanitized_authority, password) = match authority.rsplit_once('@') {
            Some((userinfo, host)) => match userinfo.split_once(':') {
                Some((user, raw)) => {
                    let password = percent_decode(raw)?;
                    (format!("{user}@{host}"), Some(password))
                }
                None => (authority.to_string(), None),
            },
            None => (authority.to_string(), None),
        };

        let (head, fragment) = match tail.split_once('#') {
            Some((head, fragment)) => (head, Some(fragment)),
            None => (tail, None),
        };
        let (path, query) = match head.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (head, None),
        };
        let mut sanitized_query = Vec::new();
        let mut query_password = None;
        let mut sslpassword = None;
        if let Some(query) = query {
            for pair in query.split('&') {
                if pair.is_empty() {
                    continue;
                }
                let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
                let key = percent_decode(raw_key)?;
                if key.eq_ignore_ascii_case("password") {
                    query_password = Some(percent_decode(raw_value)?);
                } else if key.eq_ignore_ascii_case("sslpassword") {
                    sslpassword = Some(percent_decode(raw_value)?);
                } else {
                    sanitized_query.push(pair.to_string());
                }
            }
        }
        let password = password.or(query_password);
        let mut sanitized = format!("{scheme}://{sanitized_authority}{path}");
        if !sanitized_query.is_empty() {
            sanitized.push('?');
            sanitized.push_str(&sanitized_query.join("&"));
        }
        if let Some(fragment) = fragment {
            sanitized.push('#');
            sanitized.push_str(fragment);
        }
        // 最后再做一次保守脱敏：即使上游校验漏掉了畸形 userinfo，argv 也不应
        // 出现密码。合法 DSN 不含密码时该函数原样返回。
        let sanitized = redact_database_url(&sanitized);
        Ok(Self {
            sanitized,
            password,
            sslpassword,
        })
    }

    fn effective_password(&self) -> Option<String> {
        match std::env::var("RUSTBOARD_DATABASE_PASSWORD") {
            Ok(password) if !password.is_empty() => Some(password),
            _ => self.password.clone(),
        }
    }

    fn scrub(&self, text: &str, dsn: &str) -> String {
        let mut value = text.replace(dsn, &dsn_redacted(dsn));
        for secret in [self.password.as_deref(), self.sslpassword.as_deref()]
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

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                bail!("PostgreSQL DSN 百分号编码不完整");
            }
            let hex = std::str::from_utf8(&bytes[index + 1..index + 3])
                .context("PostgreSQL DSN 百分号编码不是 ASCII")?;
            let byte = u8::from_str_radix(hex, 16)
                .with_context(|| format!("PostgreSQL DSN 百分号编码非法: %{hex}"))?;
            out.push(byte);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).context("PostgreSQL DSN 中的百分号编码不是 UTF-8")
}

/// 把证书目录复制到备份目录（目录 0700、文件 0600，拒绝符号链接）。
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

/// 恢复证书目录：manifest 中 `certs/` 下的文件逐个写回目标证书目录。
fn restore_certs(backup_dir: &Path, manifest: &Manifest, data_dir: &Path) -> Result<()> {
    let certs_dst = tls::cert_dir(data_dir);
    reject_existing_symlinks(&certs_dst)?;
    fsutil::ensure_dir(&certs_dst, 0o700)
        .with_context(|| format!("创建证书目录失败: {}", certs_dst.display()))?;
    for file in &manifest.files {
        let rel = safe_relative_path(&file.path)?;
        if !rel.starts_with("certs") || rel.as_os_str() == "certs" {
            continue;
        }
        let source = safe_join(backup_dir, &rel)?;
        let within = rel.strip_prefix("certs").expect("前面已确认 certs 前缀");
        let destination = certs_dst.join(within);
        reject_existing_symlinks(&destination)?;
        let bytes =
            fs::read(&source).with_context(|| format!("读取备份证书失败: {}", source.display()))?;
        write_private_file(&destination, &bytes)?;
    }
    Ok(())
}

/// restore 前对当前目标做 best-effort 快照。
fn pre_restore_snapshot(
    target_cfg: &HubConfig,
    config_path: &Path,
    target_config_bytes: &[u8],
) -> Result<PathBuf> {
    // 优先用当前配置字节；若当前配置描述的并不是本恢复目标，则用备份里的配置，
    // 保证快照自身的 manifest.backend 与 hub.toml 一致。
    let config_bytes = match load_optional_config_snapshot(config_path)? {
        Some((bytes, cfg)) => {
            if same_database(&cfg, target_cfg) {
                bytes
            } else {
                target_config_bytes.to_vec()
            }
        }
        None => target_config_bytes.to_vec(),
    };
    let out_root = target_cfg.data_dir.join("backups");
    snapshot_to(&out_root, target_cfg, &config_bytes).context("创建恢复前目标备份失败")
}

fn same_database(left: &HubConfig, right: &HubConfig) -> bool {
    match (left.database_kind(), right.database_kind()) {
        (Ok(DatabaseKind::Sqlite(a)), Ok(DatabaseKind::Sqlite(b))) => a == b,
        (Ok(DatabaseKind::Postgres(a)), Ok(DatabaseKind::Postgres(b))) => a == b,
        _ => false,
    }
}

fn load_optional_config_snapshot(path: &Path) -> Result<Option<(Vec<u8>, HubConfig)>> {
    match fs::symlink_metadata(path) {
        Ok(_) => load_config_snapshot(path).map(Some),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("检查配置文件失败: {}", path.display())),
    }
}

/// PostgreSQL schema 版本：只读连接可用时查实际值，否则回退到当前支持版本。
///
/// 回退只影响 manifest 的展示字段；恢复仍由 `pg_restore` 原样恢复。
fn postgres_schema_version(dsn: &str) -> i64 {
    let Ok(mut client) = connect_for_schema(dsn) else {
        return POSTGRES_SCHEMA_VERSION;
    };
    let exists = client.query_one(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name = 'schema_migrations')",
        &[],
    );
    let Ok(row) = exists else {
        return 0;
    };
    let exists: bool = row.get(0);
    if !exists {
        return 0;
    }
    client
        .query_one("SELECT MAX(version) FROM schema_migrations", &[])
        .ok()
        .and_then(|row| row.get::<_, Option<i64>>(0))
        .unwrap_or(POSTGRES_SCHEMA_VERSION)
}

fn supported_schema(backend: &Backend) -> i64 {
    match backend {
        Backend::Sqlite => SQLITE_SCHEMA_VERSION,
        Backend::Postgres => POSTGRES_SCHEMA_VERSION,
    }
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
