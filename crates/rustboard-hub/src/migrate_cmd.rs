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
//! 4. 目标非空必须 `--force`：先 `pg_dump` 目标，再二次确认并清空 22 张业务表；
//! 5. 核心迁移 + 校验全部成功后才改写配置；失败不改配置、不删 SQLite。
//!
//! `--dry-run` 只读：连接源库与目标库，检查目标是否为空/版本是否可迁移，
//! 不 apply schema、不写数据、不创建备份目录、不改配置。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};
use clap::Args;
use rustboard_common::config::{DatabaseKind, HubConfig};
use rustboard_common::fsutil;
use rustboard_core::storage::migrate::{migrate_sqlite_to_postgres, validate_target_empty};
use rustboard_core::storage::postgres::{connect_with_config, PostgresStorage};

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
    /// 目标非空时先备份目标并清空 22 张业务表（必须二次确认）。
    #[arg(long)]
    pub force: bool,
    /// 非交互执行（不读取 stdin）。
    #[arg(long)]
    pub yes: bool,
    /// 显式声明 hub 已停止（无 systemd / unit 不存在时必须提供）。
    #[arg(long)]
    pub hub_stopped: bool,
}

/// 迁移 CLI 的会话级 advisory lock：固定 key，与 core 的 schema/维护锁区分。
///
/// 覆盖 `inspect_target → pg_dump → TRUNCATE → core import → 配置切换` 整个流程。
/// 多进程同时 `migrate --force` 时，第二个会在 `pg_advisory_lock` 上等待，不会在
/// 第一个清空/导入期间再次 dump+TRUNCATE。
const MIGRATE_ADVISORY_LOCK_KEY: i64 = 0x5242_5047_0000_0013;

/// 持有 session 级 advisory lock 的 RAII guard。
///
/// 用 `Box<dyn FnOnce()>` 持有连接，避免在 hub 里直接命名 `postgres::Client`
/// （hub 不是 `postgres` crate 的直接依赖）。Drop 时先 unlock 再关闭连接；
/// 即使 unlock 失败，连接关闭也会释放 session lock。
struct MigrateLock {
    release: Option<Box<dyn FnOnce()>>,
}

impl MigrateLock {
    fn acquire(cfg: &HubConfig, dsn: &str) -> Result<Self> {
        // 与 Hub 运行连接、pg_dump/pg_restore 使用同一套 DSN/TLS/密码策略。
        let mut client = connect_with_config(cfg, dsn)
            .context("建立迁移串行化连接失败（目标 DSN/TLS 策略无效）")?;
        client
            .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATE_ADVISORY_LOCK_KEY])
            .context("获取迁移 advisory lock 失败（可能有另一个 migrate 正在运行）")?;
        let release: Box<dyn FnOnce()> = Box::new(move || {
            if let Err(err) = client.query_one(
                "SELECT pg_advisory_unlock($1)",
                &[&MIGRATE_ADVISORY_LOCK_KEY],
            ) {
                eprintln!("WARN: 释放迁移 advisory lock 失败（连接关闭仍会释放）: {err}");
            }
        });
        Ok(Self {
            release: Some(release),
        })
    }
}

impl Drop for MigrateLock {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
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
    // 预检一次性读取版本/22 张表/samples；有未 checkpoint WAL 时会在临时副本
    // 上读取，dry-run 不会在源目录创建 -shm/-wal。`sqlite_source_info` 内部
    // 先判版本（旧库统一 fresh-install 文案）再判 22 张表。
    let source_info = backup_cmd::sqlite_source_info(&source)?;
    let source_version = source_info.schema_version;

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

    // 2. 运行中的 hub 会持续写源库，迁移必须离线。无 systemd/无法确认时必须
    //    显式 --hub-stopped，不能仅凭 WARN 继续。
    ensure_hub_stopped("migrate", args.hub_stopped)?;

    // 2.1 在任何交互确认/写盘前校验目标 DSN 的密码与 TLS 策略（与运行连接、
    //     pg_dump/pg_restore 共用同一份解析）。非法 sslmode、根证书冲突、
    //     畸形参数都在这里 fail closed。
    backup_cmd::validate_pg_connection_policy(&target_cfg, &target_dsn)
        .with_context(|| format!("目标 PostgreSQL 连接策略校验失败（{target_redacted}）"))?;

    // 2.2 串行化整个迁移流程（TLS 目标同样可以获取会话级 advisory lock）。
    //     非 force 路径拿不到锁时仍可依赖 core 导入事务的空库复验与表锁，但这里
    //     明确 WARN，避免声称覆盖了 dump/clear 阶段。
    let _migrate_lock = match MigrateLock::acquire(&target_cfg, &target_dsn) {
        Ok(lock) => Some(lock),
        Err(_) if args.force => {
            return Err(anyhow!(
                "--force 迁移必须获取会话级 advisory lock（{}）；请先结束其它 migrate/维护进程后重试",
                target_redacted
            ));
        }
        Err(_) => {
            // 不打印底层错误链：连接错误可能带出连接串细节。只报告脱敏目标
            // 和事实，避免密码进日志。
            eprintln!(
                "WARN: 无法获取会话级迁移锁（{}）；非 force 迁移仅依赖 core 的导入事务空库复验/表锁，\
                 并发 migrate 请先手工串行",
                target_redacted
            );
            None
        }
    };

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
        // TLS/密码策略已在上方校验；这里只确认外部工具存在。
        backup_cmd::ensure_tool("pg_dump")?;
    }

    if args.dry_run {
        print_dry_run(
            &source,
            source_version,
            source_info.sample_count,
            &target_redacted,
            &target_state,
            args.force,
        )?;
        if matches!(target_state, TargetState::NonEmpty) && !args.force {
            bail!("dry-run 检测到目标非空且未指定 --force；实际 migrate 会被拒绝");
        }
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
                "目标 {} 非空。--force 会先执行 pg_dump 备份，然后清空 22 张业务表；\
                 数据丢失风险由该备份兜底。确认继续？",
                target_redacted
            ),
        )?;
    }

    // 5. 先备份源 SQLite + hub.toml（失败则不迁移）。
    let backup_root = cfg.data_dir.join("backups");
    let backup_dir = backup_cmd::snapshot_to(&backup_root, &cfg, &config_bytes, true)
        .context("迁移前备份 SQLite / hub.toml 失败，已中止（未修改源库与配置）")?;
    println!("迁移前备份: {}", backup_dir.display());

    // 6. 目标非空：先 pg_dump，成功后才清空；任何一步失败都不改配置、不删 SQLite。
    if matches!(target_state, TargetState::NonEmpty) {
        let target_backup = backup_dir.join("target-before-migrate.dump");
        // 目标侧备份同样继承 Hub TLS 策略（默认 verify-full），不允许 --force
        // 路径绕过 pg_dump 的证书校验。
        backup_cmd::pg_dump_to(&target_cfg, &target_dsn, &target_backup).with_context(|| {
            format!(
                "备份目标 PostgreSQL 失败（{}）；未清空目标、未迁移、未改配置",
                target_redacted
            )
        })?;
        println!("目标侧备份: {}", target_backup.display());
        clear_target(&target_cfg, &target_dsn, &target_redacted)?;
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
pub(crate) fn ensure_hub_stopped(operation: &str, declared_stopped: bool) -> Result<()> {
    if !Path::new("/run/systemd/system").is_dir() {
        if declared_stopped {
            return Ok(());
        }
        bail!(
            "无法确认 rustboard-hub 已停止（未检测到 systemd）；请先停 hub，\
             确认后加 --hub-stopped 重试（{operation} 前必须离线）"
        );
    }

    let active = Command::new("systemctl")
        .args(["is-active", "rustboard-hub"])
        .stdin(Stdio::null())
        .output();
    let state = match active {
        Ok(output) => {
            let state = String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_ascii_lowercase();
            if output.status.success()
                || matches!(
                    state.as_str(),
                    "active" | "activating" | "reloading" | "deactivating"
                )
            {
                bail!(
                    "检测到 rustboard-hub 正在运行（systemctl is-active: {state}）；\
                     {operation} 必须在 hub 停止后执行：sudo systemctl stop rustboard-hub"
                );
            }
            state
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            if declared_stopped {
                return Ok(());
            }
            bail!(
                "存在 /run/systemd/system 但找不到 systemctl，无法确认 hub 已停止；\
                 请先停 hub，确认后加 --hub-stopped 重试（{operation} 前必须离线）"
            );
        }
        Err(err) => {
            if declared_stopped {
                return Ok(());
            }
            return Err(err).with_context(|| {
                format!(
                    "执行 systemctl is-active rustboard-hub 失败，无法确认 hub 是否已停止；\
                     请先停 hub 后加 --hub-stopped 重试（{operation} 前必须离线）"
                )
            });
        }
    };

    // `is-active` 对不存在的 unit 也可能输出 inactive（exit 4），不能只凭状态
    // 判断。用 LoadState 区分「unit 已加载且未运行」与「unit 不存在/无法确认」。
    let loaded = Command::new("systemctl")
        .args(["show", "rustboard-hub", "-p", "LoadState", "--value"])
        .stdin(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .trim()
                .to_ascii_lowercase()
        })
        .is_some_and(|state| state == "loaded");
    if loaded && matches!(state.as_str(), "inactive" | "failed") {
        return Ok(());
    }
    if declared_stopped {
        return Ok(());
    }
    bail!(
        "无法确认 rustboard-hub 已停止（systemctl is-active: {}，unit {}）；\
         请先停 hub，确认后加 --hub-stopped 重试（{operation} 前必须离线）",
        if state.is_empty() { "<empty>" } else { &state },
        if loaded {
            "已加载"
        } else {
            "不存在或状态无法确认"
        }
    )
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
            if backup_cmd::is_old_schema_target_error(&err) {
                // 旧 schema 绝不归入 Empty/NonEmpty：--force 会先 dump+TRUNCATE，
                // 必须在任何清空动作前把错误返回给调用方。
                return Err(err).with_context(|| {
                    format!(
                        "目标 PostgreSQL 是旧 schema（v1.0.0 只支持全新安装），拒绝迁移（{redacted}）"
                    )
                });
            }
            if backup_cmd::is_non_empty_target_error(&err) {
                return Ok(TargetState::NonEmpty);
            }
            Err(err).with_context(|| format!("校验目标 PostgreSQL 是否为空失败（{redacted}）"))
        }
    }
}

/// 清空目标库中已存在的 hub 业务表。
///
/// 只允许清空已知的 22 张表 + `schema_migrations`；发现其它表时拒绝（避免把
/// 同一 schema 中无关应用的数据一起清掉）。`schema_migrations` 保留，核心迁移
/// 会幂等补齐/校验版本。连接继承 Hub 的 DSN/TLS 策略。
fn clear_target(cfg: &HubConfig, dsn: &str, redacted: &str) -> Result<()> {
    let mut client = connect_with_config(cfg, dsn)
        .with_context(|| format!("连接目标 PostgreSQL 失败（{redacted}）"))?;
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
    // 解析错误走固定诊断：toml 的 source line 可能含 token/密码。
    let text = std::str::from_utf8(old_bytes).context("旧 hub.toml 不是合法 UTF-8")?;
    let mut value: toml::Value = backup_cmd::parse_toml_sanitized(text, config_path)?;
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
    samples: i64,
    target_redacted: &str,
    state: &TargetState,
    force: bool,
) -> Result<()> {
    println!("migrate --dry-run（只读校验，不写数据/不备份/不改配置）");
    println!(
        "  源: sqlite://{}（schema v{source_version}，samples {samples} 行，22 张表齐全）",
        source.display()
    );
    println!("  目标: {target_redacted}");
    match state {
        TargetState::Empty => println!("  目标状态: 空库（schema 版本可迁移）"),
        TargetState::NonEmpty if force => {
            println!("  目标状态: 非空；--force 会先 pg_dump 目标、二次确认后清空 22 张业务表");
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
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let path =
            std::env::temp_dir().join(format!("rb-migrate-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("创建测试目录");
        path
    }

    /// #67：migrate 的目标连接策略与运行连接共用解析。
    #[test]
    fn target_connection_policy_matches_runtime_rules() {
        let cfg = HubConfig::default();
        // 缺省 verify-full（DSN 中没有 sslmode）。
        backup_cmd::validate_pg_connection_policy(&cfg, "postgres://u:secret@h/db").unwrap();
        // 显式 disable。
        backup_cmd::validate_pg_connection_policy(&cfg, "postgres://u:secret@h/db?sslmode=disable")
            .unwrap();

        // require/prefer 会静默降级，与运行连接一样拒绝，且错误不含密码。
        for mode in ["require", "prefer"] {
            let dsn = format!("postgres://u:topsecret@h/db?sslmode={mode}");
            let err = backup_cmd::validate_pg_connection_policy(&cfg, &dsn)
                .expect_err("不安全的 sslmode 必须拒绝");
            let message = format!("{err:#}");
            assert!(message.contains("verify-full") && message.contains("disable"));
            assert!(!message.contains("topsecret"), "错误泄露密码: {message}");
        }

        // 配置根 CA 与 DSN sslrootcert 冲突：与运行连接相同的错误。
        let dsn = "postgres://u@h/db?sslrootcert=%2Ftmp%2Fa.pem";
        let cfg = HubConfig {
            db_sslrootcert: Some(PathBuf::from("/tmp/b.pem")),
            ..HubConfig::default()
        };
        let err =
            backup_cmd::validate_pg_connection_policy(&cfg, dsn).expect_err("根证书冲突必须拒绝");
        assert!(format!("{err:#}").contains("不同文件"));
    }

    /// #61：迁移切换配置时的 TOML 解析错误不得回显配置原文（token/密码）。
    #[test]
    fn switch_config_toml_error_does_not_echo_secrets() {
        let dir = temp_dir("switch-config-secret");
        let config_path = dir.join("hub.toml");
        let secret = "migrate-toml-canary-9f3a";
        let invalid = format!(
            "admin_token = \"{secret}\"\n\
             duplicate = 1\n\
             duplicate = 2\n\
             database = \"sqlite:///tmp/x.db\"\n"
        );
        let err = switch_config(&config_path, invalid.as_bytes(), "postgres://u@h/db")
            .expect_err("重复键必须解析失败");
        let message = format!("{err:#}");
        assert!(message.contains("TOML 解析失败"), "{message}");
        assert!(
            !message.contains(secret),
            "TOML 错误链泄露配置原文: {message}"
        );
        // 配置本身未被改写；旧配置 .bak 允许存在（写在解析之前）。
        assert!(!config_path.exists(), "失败时不得写入新配置");
        let _ = fs::remove_dir_all(&dir);
    }

    /// 迁移前备份失败时不得改配置/留半成品（`switch_config` 只替换 database）。
    #[test]
    fn switch_config_rewrites_only_database() {
        let dir = temp_dir("switch-config-ok");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let config_path = dir.join("hub.toml");
        let old = "data_dir = \"/var/lib/rustboard/hub\"\n\
                   database = \"sqlite:///var/lib/rustboard/hub/rustboard.db\"\n\
                   admin_token = \"keep-me\"\n";
        let backup = switch_config(&config_path, old.as_bytes(), "postgres://u@h/db").unwrap();
        assert!(backup.exists(), "旧配置应成对备份");
        let new_text = fs::read_to_string(&config_path).unwrap();
        assert!(new_text.contains("postgres://u@h/db"));
        assert!(new_text.contains("keep-me"));
        assert_eq!(
            fs::metadata(&config_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// P0：迁移源库必须先判版本再判表；v8 源库要给统一的 fresh-install 文案，
    /// 不能只报缺 v9 新表。
    #[test]
    fn sqlite_source_version_is_checked_before_tables() {
        let dir = temp_dir("legacy-source");
        let db = dir.join("v8.db");
        {
            let conn = rusqlite::Connection::open(&db).expect("创建测试 SQLite");
            conn.pragma_update(None, "user_version", 8)
                .expect("设置 v8 user_version");
        }
        let err = match backup_cmd::sqlite_source_info(&db) {
            Ok(_) => panic!("v8 源库必须拒绝"),
            Err(err) => err,
        };
        let message = format!("{err:#}");
        assert!(message.contains("只支持全新安装"), "{message}");
        assert!(
            message.contains("旧数据兼容将在首个正式版本之后提供"),
            "{message}"
        );
        assert!(
            !message.contains("缺少表"),
            "必须先报版本而不是只报缺表: {message}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
