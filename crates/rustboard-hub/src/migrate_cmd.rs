//! `rustboard-hub migrate`（M5 Phase D5b）。
//!
//! 离线把当前 SQLite 源库迁移到 PostgreSQL，成功后原子切换 `hub.toml` 的
//! `database`。核心迁移/校验在 `rustboard-core::storage::migrate`（D5），本模块
//! 只负责 CLI 语义：
//!
//! 1. 源必须是 SQLite，`--to` 必须是结构合法的 PostgreSQL DSN；
//! 2. 有 systemd 时用 `systemctl is-active rustboard-hub` 拒绝运行中的 hub；
//!    容器/手工部署没有 systemd 时只依赖 `--yes` 与迁移前备份（**不伪造 PID 检查**）；
//! 3. 非 dry-run 先 `VACUUM INTO` 备份 SQLite，再备份 `hub.toml`（0600）；
//! 4. 目标非空必须 `--force`：先 `pg_dump` 目标，再二次确认并清空 21 张业务表；
//! 5. 核心迁移 + 校验全部成功后才改写配置；失败不改配置、不删 SQLite。
//!
//! `--dry-run` 只读：连接源库与目标库，检查目标是否为空/版本是否可迁移，
//! 不 apply schema、不写数据、不创建备份目录、不改配置。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rustboard_common::config::DatabaseKind;
use rustboard_common::fsutil;
use rustboard_core::storage::migrate::{migrate_sqlite_to_postgres, validate_target_empty};
use rustboard_core::storage::postgres::{connect_for_schema, PostgresStorage};

use super::backup_cmd;
use super::backup_cmd::HUB_TABLES;

/// `rustboard-hub migrate` 参数。
#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// 目标 PostgreSQL DSN（`postgres://` / `postgresql://`）。
    #[arg(long, value_name = "DSN")]
    pub to: String,
    /// hub 配置文件；默认 `/etc/rustboard/hub.toml`。
    #[arg(short, long)]
    pub config: Option<PathBuf>,
    /// 只校验源/目标并打印计划；不写数据、不备份、不改配置。
    #[arg(long)]
    pub dry_run: bool,
    /// 目标非空时先备份目标并清空 21 张业务表（必须二次确认）。
    #[arg(long)]
    pub force: bool,
    /// 非交互执行（不读取 stdin）。
    #[arg(long)]
    pub yes: bool,
}

/// 目标 PostgreSQL 当前状态。
enum TargetState {
    Empty,
    NonEmpty,
}

/// `migrate` 子命令入口。
pub fn migrate(args: MigrateArgs) -> Result<()> {
    let config_path = backup_cmd::config_path(args.config);
    let (config_bytes, cfg) = backup_cmd::load_config_snapshot(&config_path)?;

    // 1. 源必须是 SQLite；目标 DSN 走 common 的结构校验（错误只含脱敏 URL）。
    let source_kind = cfg.database_kind().context("解析当前 database 配置失败")?;
    let source = match source_kind {
        DatabaseKind::Sqlite(path) => path,
        DatabaseKind::Postgres(dsn) => bail!(
            "当前配置已经是 PostgreSQL（{}），migrate 只支持从 SQLite 迁移",
            dsn_redacted(&dsn)
        ),
    };
    let source_meta = fs::symlink_metadata(&source)
        .with_context(|| format!("SQLite 源库不存在: {}", source.display()))?;
    if source_meta.file_type().is_symlink() || !source_meta.is_file() {
        bail!(
            "SQLite 源库必须是普通文件（拒绝符号链接）: {}",
            source.display()
        );
    }
    let source_version = backup_cmd::sqlite_schema_version(&source)?;
    if source_version != backup_cmd::SQLITE_SCHEMA_VERSION {
        bail!(
            "SQLite 源库 schema 版本为 {source_version}，migrate 只支持 v{}；\
             请先用能升级到该版本的 rustboard-hub 打开一次源库",
            backup_cmd::SQLITE_SCHEMA_VERSION
        );
    }

    let mut target_cfg = cfg.clone();
    target_cfg.database = args.to.clone();
    let target_kind = target_cfg
        .database_kind()
        .context("解析 --to 目标 PostgreSQL DSN 失败")?;
    let target_dsn = match target_kind {
        DatabaseKind::Postgres(dsn) => dsn,
        DatabaseKind::Sqlite(_) => {
            bail!("--to 必须是 postgres:// 或 postgresql:// 连接串，不能是 SQLite 路径")
        }
    };
    let target_redacted = dsn_redacted(&target_dsn);

    // 2. 运行中的 hub 会持续写源库，迁移必须离线。
    ensure_hub_stopped("migrate")?;

    // 3. 连接目标（PostgresStorage::open 只做 SELECT 1，不 apply schema），
    //    只读校验空库/版本。同步 PG 驱动不能在 tokio runtime 内，CLI 本身安全。
    let target = PostgresStorage::open_from_config(&target_cfg)
        .with_context(|| format!("连接目标 PostgreSQL 失败（{target_redacted}）"))?;
    let target_state = inspect_target(&target, &target_redacted)?;
    if matches!(target_state, TargetState::NonEmpty) && !args.force {
        bail!(
            "目标 PostgreSQL 非空（{target_redacted}）；核心迁移拒绝覆盖。\
             请先备份并清空目标，或使用 --force（会先 pg_dump 目标并二次确认）"
        );
    }
    if matches!(target_state, TargetState::NonEmpty) && args.force {
        ensure_force_target_supported(&target_dsn, &target_redacted)?;
        backup_cmd::ensure_tool("pg_dump")?;
    }

    if args.dry_run {
        print_dry_run(
            &source,
            source_version,
            &target_redacted,
            &target_state,
            args.force,
        )?;
        return Ok(());
    }

    // 4. 交互确认（--dry-run 已在上方直接返回；非 TTY 且无 --yes 会在这里失败）。
    backup_cmd::confirm(
        args.yes,
        &format!(
            "将把 SQLite 源库 {} 迁移到 {}。迁移前会备份 SQLite 与 hub.toml，\
             全部校验通过后才切换配置。继续？",
            source.display(),
            target_redacted
        ),
    )?;
    if matches!(target_state, TargetState::NonEmpty) {
        backup_cmd::confirm(
            args.yes,
            &format!(
                "目标 {} 非空。--force 会先执行 pg_dump 备份，然后清空 21 张业务表；\
                 数据丢失风险由该备份兜底。确认继续？",
                target_redacted
            ),
        )?;
    }

    // 5. 先备份源 SQLite + hub.toml（失败则不迁移）。
    let backup_root = cfg.data_dir.join("backups");
    let backup_dir = backup_cmd::snapshot_to(&backup_root, &cfg, &config_bytes)
        .context("迁移前备份 SQLite / hub.toml 失败，已中止（未修改源库与配置）")?;
    println!("迁移前备份: {}", backup_dir.display());

    // 6. 目标非空：先 pg_dump，成功后才清空；任何一步失败都不改配置、不删 SQLite。
    if matches!(target_state, TargetState::NonEmpty) {
        let target_backup = backup_dir.join("target-before-migrate.dump");
        backup_cmd::pg_dump_to(&target_dsn, &target_backup).with_context(|| {
            format!(
                "备份目标 PostgreSQL 失败（{}）；未清空目标、未迁移、未改配置",
                target_redacted
            )
        })?;
        println!("目标侧备份: {}", target_backup.display());
        clear_target(&target_dsn, &target_redacted)?;
        // 清空后再次确认核心迁移看到的是空目标。
        validate_target_empty(&target).with_context(|| {
            format!("清空目标后仍无法通过空库校验（{target_redacted}）；已中止，未改配置")
        })?;
    }

    // 7. 核心迁移（单事务导入 + 全量校验，失败自动回滚目标事务）。
    let report = migrate_sqlite_to_postgres(&source, &target).with_context(|| {
        format!(
            "SQLite → PostgreSQL 迁移失败（{}）；目标事务已回滚，SQLite 未修改，配置未切换",
            target_redacted
        )
    })?;

    // 8. 只有核心迁移与校验全过才切换配置；旧配置保留 .bak-<ts> 与备份目录副本。
    let config_backup = switch_config(&config_path, &config_bytes, &args.to).context(
        "核心迁移已成功并已提交到 PostgreSQL，但切换 hub.toml 失败；\
         SQLite 源库未删除，请手工修改 database 或从迁移前备份恢复配置",
    )?;

    // 9. 输出报告（表数/行数/范围/耗时），不含任何 DSN 密码。
    println!("迁移完成: {} -> {}", source.display(), target_redacted);
    println!("迁移前备份: {}", backup_dir.display());
    println!("旧配置备份: {}", config_backup.display());
    println!(
        "配置已切换: {}（database 已指向 PostgreSQL）",
        config_path.display()
    );
    println!();
    println!(
        "{:24} {:>12} {:>14} {:>14}",
        "table", "rows", "id range", "ts range"
    );
    for table in &report.tables {
        println!(
            "{:24} {:>12} {:>14} {:>14}",
            table.table,
            table.rows,
            format_range(table.id_min, table.id_max),
            format_range(table.ts_min, table.ts_max)
        );
    }
    println!();
    println!(
        "合计: {} 张表 / {} 行；schema sqlite v{} -> postgres v{}；耗时 {} ms",
        report.tables.len(),
        report.total_rows,
        report.sqlite_schema_version,
        report.postgres_schema_version,
        report.duration_ms
    );
    println!(
        "samples: {} 行，ts {}；alert_states: {}；alert_events: {}；api_tokens: {}；archive_objects: {}",
        report.tables.iter().find(|t| t.table == "samples").map_or(0, |t| t.rows),
        format_range(report.samples_range.ts_min, report.samples_range.ts_max),
        report.alert_states,
        report.alert_events,
        report.api_tokens,
        report.archive_objects
    );

    Ok(())
}

/// 拒绝运行中的 hub。没有 systemd 时只告警，由 `--yes`/交互确认与迁移前备份兜底。
///
/// 不读取、也不伪造 PID 文件：systemd 部署用 `systemctl is-active`，其它部署
/// 形态无法可靠判断，强行检查只会误报或漏报。
pub(crate) fn ensure_hub_stopped(operation: &str) -> Result<()> {
    if !Path::new("/run/systemd/system").is_dir() {
        eprintln!(
            "WARN: 未检测到 systemd，无法自动确认 rustboard-hub 是否已停止；\
             请自行确认没有 hub/容器在写数据库（{operation} 前必须离线）"
        );
        return Ok(());
    }
    let output = match Command::new("systemctl")
        .args(["is-active", "--quiet", "rustboard-hub"])
        .stdin(Stdio::null())
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "WARN: 存在 /run/systemd/system 但找不到 systemctl，无法确认 hub 状态；\
                 请自行确认已停止（{operation} 前必须离线）"
            );
            return Ok(());
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!("执行 systemctl is-active rustboard-hub 失败，无法确认 hub 是否已停止；请先停 hub 后重试")
            })
        }
    };
    if output.status.success() {
        bail!(
            "检测到 rustboard-hub 正在运行（systemctl is-active rustboard-hub）；\
             {operation} 必须在 hub 停止后执行：sudo systemctl stop rustboard-hub"
        );
    }
    if output.status.code().is_none() {
        bail!("无法确认 rustboard-hub 状态（systemctl 被信号终止）；请先停 hub 后重试");
    }
    Ok(())
}

fn inspect_target(target: &PostgresStorage, redacted: &str) -> Result<TargetState> {
    match validate_target_empty(target) {
        Ok(()) => Ok(TargetState::Empty),
        Err(err) => {
            if backup_cmd::is_too_new_target_error(&err) {
                return Err(err).with_context(|| {
                    format!("目标 PostgreSQL schema 版本高于当前程序支持（{redacted}）")
                });
            }
            if backup_cmd::is_non_empty_target_error(&err) {
                return Ok(TargetState::NonEmpty);
            }
            Err(err).with_context(|| format!("校验目标 PostgreSQL 是否为空失败（{redacted}）"))
        }
    }
}

/// `--force` 清空依赖 D2 的 `connect_for_schema`，目前只支持 `sslmode=disable`。
fn ensure_force_target_supported(dsn: &str, redacted: &str) -> Result<()> {
    match dsn_sslmode(dsn)? {
        Some(mode) if mode == "disable" => Ok(()),
        Some(mode) => bail!(
            "目标非空且指定了 --force，但当前版本清空目标只支持 sslmode=disable（实际 {mode}，{redacted}）。\
             请先手工备份并 TRUNCATE 21 张业务表后重试（不带 --force），或使用 sslmode=disable 的本地/内网目标"
        ),
        None => bail!(
            "目标非空且指定了 --force，但当前版本清空目标只支持显式 sslmode=disable（{redacted}）。\
             请先手工备份并 TRUNCATE 21 张业务表后重试（不带 --force），或使用 sslmode=disable 的本地/内网目标"
        ),
    }
}

/// 清空目标库中已存在的 hub 业务表。
///
/// 只允许清空已知的 21 张表 + `schema_migrations`；发现其它表时拒绝（避免把
/// 同一 schema 中无关应用的数据一起清掉）。`schema_migrations` 保留，核心迁移
/// 会幂等补齐/校验版本。
fn clear_target(dsn: &str, redacted: &str) -> Result<()> {
    let mut client = connect_for_schema(dsn)
        .with_context(|| format!("以 sslmode=disable 连接目标 PostgreSQL 失败（{redacted}）"))?;
    let mut tx = client.transaction().context("开启清空目标事务失败")?;
    let rows = tx
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_type = 'BASE TABLE'",
            &[],
        )
        .context("读取目标 PostgreSQL 表列表失败")?;
    let mut existing_hub = Vec::new();
    let mut unknown = Vec::new();
    for row in rows {
        let name: String = row.get(0);
        if name == "schema_migrations" {
            continue;
        }
        if HUB_TABLES.contains(&name.as_str()) {
            existing_hub.push(name);
        } else {
            unknown.push(name);
        }
    }
    if !unknown.is_empty() {
        bail!(
            "目标库存在未知表（{}），--force 拒绝清空；请手工确认后清理",
            unknown.join("、")
        );
    }
    if existing_hub.is_empty() {
        tx.commit().context("提交空目标事务失败")?;
        return Ok(());
    }
    // 只接受 HUB_TABLES 中的常量名；仍做一次白名单顺序输出，绝不拼用户输入。
    existing_hub.sort_by_key(|name| {
        HUB_TABLES
            .iter()
            .position(|candidate| candidate == name)
            .unwrap_or(usize::MAX)
    });
    let list = existing_hub
        .iter()
        .map(|name| format!("\"{}\"", name.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!("TRUNCATE TABLE {list} RESTART IDENTITY");
    tx.execute(&sql, &[])
        .with_context(|| format!("清空目标业务表失败（{redacted}）"))?;
    tx.commit().context("提交清空目标事务失败")?;
    println!(
        "目标已清空: {} 张业务表（schema_migrations 保留）",
        existing_hub.len()
    );
    Ok(())
}

fn switch_config(config_path: &Path, old_bytes: &[u8], new_dsn: &str) -> Result<PathBuf> {
    // 先把旧配置成对备份到配置文件旁边；写失败则配置保持不变。
    let backup = config_path.with_file_name(format!(
        "{}.bak-{}",
        config_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("hub.toml"),
        backup_cmd::format_timestamp(rustboard_common::util::now_ms())
    ));
    fsutil::atomic_write(&backup, old_bytes, 0o600)
        .with_context(|| format!("备份旧配置失败: {}", backup.display()))?;

    // 用 toml::Value 只替换 database，保留其它字段（包括本版本不认识的字段）。
    let text = std::str::from_utf8(old_bytes).context("旧 hub.toml 不是合法 UTF-8")?;
    let mut value: toml::Value = toml::from_str(text).context("解析旧 hub.toml 失败")?;
    let table = value
        .as_table_mut()
        .ok_or_else(|| anyhow!("旧 hub.toml 顶层不是 TOML table"))?;
    table.insert(
        "database".to_string(),
        toml::Value::String(new_dsn.to_string()),
    );
    let new_text = toml::to_string_pretty(&value).context("序列化新 hub.toml 失败")?;
    fsutil::atomic_write(config_path, new_text.as_bytes(), 0o600)
        .with_context(|| format!("写入新 hub.toml 失败: {}", config_path.display()))?;
    Ok(backup)
}

fn print_dry_run(
    source: &Path,
    source_version: i64,
    target_redacted: &str,
    state: &TargetState,
    force: bool,
) -> Result<()> {
    println!("migrate --dry-run（只读校验，不写数据/不备份/不改配置）");
    println!(
        "  源: sqlite://{}（schema v{source_version}）",
        source.display()
    );
    println!("  目标: {target_redacted}");
    match state {
        TargetState::Empty => println!("  目标状态: 空库（schema 版本可迁移）"),
        TargetState::NonEmpty if force => {
            println!("  目标状态: 非空；--force 会先 pg_dump 目标、二次确认后清空 21 张业务表");
        }
        TargetState::NonEmpty => {
            println!("  目标状态: 非空；未指定 --force，实际迁移会被拒绝");
        }
    }
    println!(
        "  计划: 连接源只读 + 目标 SELECT 1/空库校验；不 apply schema、不写业务行、不改 hub.toml"
    );
    println!(
        "  备份计划: {}",
        if force && matches!(state, TargetState::NonEmpty) {
            "迁移前 VACUUM INTO 源库 + pg_dump 目标；成功后切换配置"
        } else {
            "迁移前 VACUUM INTO 源库；成功后切换配置"
        }
    );
    Ok(())
}

fn dsn_sslmode(dsn: &str) -> Result<Option<String>> {
    let Some(query) = dsn.split_once('?').map(|(_, tail)| tail) else {
        return Ok(None);
    };
    let query = query.split('#').next().unwrap_or(query);
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.eq_ignore_ascii_case("sslmode") {
            return Ok(Some(value.to_string()));
        }
    }
    Ok(None)
}

fn dsn_redacted(dsn: &str) -> String {
    rustboard_common::config::redact_database_url(dsn)
}

fn format_range(min: Option<i64>, max: Option<i64>) -> String {
    match (min, max) {
        (Some(min), Some(max)) => format!("{min}..{max}"),
        _ => "-".to_string(),
    }
}

// 仅供单元测试使用：确保 HubConfig 迁移配置克隆不会改动源配置。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sslmode_parser_ignores_password_and_reads_query() {
        assert_eq!(
            dsn_sslmode("postgres://u:p@host/db?sslmode=disable").unwrap(),
            Some("disable".to_string())
        );
        assert_eq!(
            dsn_sslmode("postgres://u:p@host/db?sslmode=verify-full&x=1").unwrap(),
            Some("verify-full".to_string())
        );
        assert_eq!(dsn_sslmode("postgres://u:p@host/db").unwrap(), None);
        // 密码里出现 sslmode=disable 不能被当成 query 参数。
        assert_eq!(
            dsn_sslmode("postgres://u:sslmode=disable@host/db").unwrap(),
            None
        );
    }

    #[test]
    fn ensure_force_target_supported_rejects_non_disable() {
        assert!(ensure_force_target_supported(
            "postgres://u:p@host/db?sslmode=disable",
            "postgres://u:***@host/db"
        )
        .is_ok());
        let err = ensure_force_target_supported(
            "postgres://u:p@host/db?sslmode=verify-full",
            "postgres://u:***@host/db",
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("sslmode=disable"));
    }
}
