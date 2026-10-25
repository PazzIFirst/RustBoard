//! M5 Phase D5b：`migrate / backup / restore` CLI 黑盒回归。
//!
//! 覆盖：
//! - SQLite 全链路：backup → 删库 → restore → 行数/时间范围/告警/token/归档一致；
//! - manifest SHA256、文件/目录权限、配置/证书恢复；
//! - restore 非空拒绝、`--force`、manifest 篡改与路径穿越；
//! - migrate 失败时 hub.toml 字节不变、错误不回显密码；
//! - 有 `RUSTBOARD_TEST_PG` 时跑真实 PG 迁移 / 配置切换 / `--force` 编排；
//!   `pg_dump`/`pg_restore` 不在 PATH 时 PG 备份恢复用例明确 SKIP（不假绿）。
//!
//! 本文件不启动 hub 监听器，只调用 `rustboard-hub` 子命令。

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustboard_common::config::HubConfig;
use rustboard_common::model::{AgentRecord, Sample, SampleBatch};
use rustboard_core::alerts::{AlertState, AlertStateKind};
use rustboard_core::archive::{ArchiveObject, ArchiveStatus};
use rustboard_core::storage::migrate::validate_target_empty;
use rustboard_core::storage::postgres::{connect_for_schema, PostgresStorage};
use rustboard_core::storage::StorageHandle;
use serde_json::Value;
use sha2::{Digest, Sha256};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

/// 测试目录；Drop 时递归删除。
struct TestRoot {
    path: PathBuf,
}

impl TestRoot {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "rb-d5b-{tag}-{}-{}",
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

fn hub(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustboard-hub"));
    command.args(args);
    // 本地测试机没有 rustboard-hub unit（systemd 视为无法确认），显式声明已停。
    if matches!(args.first(), Some(&"migrate") | Some(&"restore")) {
        command.arg("--hub-stopped");
    }
    command
        .env_remove("RUSTBOARD_DATABASE_PASSWORD")
        .output()
        .expect("执行 rustboard-hub")
}

fn remove_sqlite_sidecars(path: &Path) {
    for suffix in ["-wal", "-shm", "-journal"] {
        let sidecar = path.with_file_name(format!(
            "{}{suffix}",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("db")
        ));
        match fs::remove_file(&sidecar) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => panic!("清理 {} 失败: {err}", sidecar.display()),
        }
    }
}

fn read_config(path: &Path) -> HubConfig {
    let text = fs::read_to_string(path).expect("读配置");
    toml::from_str(&text).expect("解析配置")
}

/// 列出测试目录下的所有文件/目录相对路径，用于断言 dry-run 零新文件。
fn list_tree(root: &Path) -> Vec<String> {
    fn walk(root: &Path, current: &Path, out: &mut Vec<String>) {
        let mut entries: Vec<_> = fs::read_dir(current)
            .expect("读取目录")
            .map(|entry| entry.expect("目录项").path())
            .collect();
        entries.sort();
        for path in entries {
            out.push(
                path.strip_prefix(root)
                    .expect("相对路径")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

fn sqlite_sidecar(db: &Path, suffix: &str) -> PathBuf {
    let mut os = db.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}

/// 重写备份 manifest 中某个文件的 sha256/size，模拟“哈希自洽的恶意备份”。
fn refresh_manifest_file(backup: &Path, rel: &str) {
    let file_path = backup.join(rel);
    let bytes = fs::read(&file_path).expect("读备份文件");
    let manifest_path = backup.join("manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("读 manifest")).expect("解析");
    let mut found = false;
    for file in manifest["files"].as_array_mut().expect("files") {
        if file["path"] == rel {
            file["sha256"] = Value::String(sha256(&bytes));
            file["size"] = Value::Number(bytes.len().into());
            found = true;
        }
    }
    assert!(found, "manifest 缺少 {rel}");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn quick_check_ok(path: &Path) {
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("打开 SQLite 校验");
    let check: String = conn
        .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
        .expect("quick_check");
    assert_eq!(check, "ok");
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn file_sha(path: &Path) -> String {
    sha256(&fs::read(path).expect("读取文件"))
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("读取元数据")
        .permissions()
        .mode()
        & 0o777
}

fn write_config(root: &Path, data_dir: &Path, database: &str) -> (PathBuf, Vec<u8>) {
    let config_path = root.join("etc/hub.toml");
    let cfg = HubConfig {
        data_dir: data_dir.to_path_buf(),
        database: database.to_string(),
        admin_token: "d5b-canary-admin-token".to_string(),
        ..HubConfig::default()
    };
    cfg.save(&config_path).expect("写 hub.toml");
    let bytes = fs::read(&config_path).expect("读 hub.toml");
    (config_path, bytes)
}

fn write_certs(data_dir: &Path) {
    let certs = data_dir.join("certs");
    fs::create_dir_all(&certs).expect("创建证书目录");
    fs::set_permissions(&certs, fs::Permissions::from_mode(0o700)).expect("certs 0700");
    // 模拟旧安装遗留的 0644 cert；备份必须收紧为 0600。
    fs::write(certs.join("ca.crt"), b"d5b-ca-cert\n").expect("写 ca.crt");
    fs::set_permissions(certs.join("ca.crt"), fs::Permissions::from_mode(0o644))
        .expect("ca.crt 0644");
    fs::write(certs.join("server.key"), b"d5b-server-key\n").expect("写 server.key");
    fs::set_permissions(certs.join("server.key"), fs::Permissions::from_mode(0o600))
        .expect("server.key 0600");
}

fn seed_sqlite(db_path: &Path) {
    let storage = StorageHandle::sqlite(db_path, 4).expect("打开 SQLite");
    storage
        .upsert_agent(&AgentRecord {
            agent_id: "a1".to_string(),
            name: "node1".to_string(),
            hostname: "h1".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            version: "d5b".to_string(),
            boot_id: "boot-1".to_string(),
            status: "online".to_string(),
            last_seen_at: 2_000,
            created_at: 1_000,
        })
        .expect("写 agent");
    let mut batch = SampleBatch {
        agent_id: "a1".to_string(),
        epoch: 1,
        seq: 0,
        boot_id: "boot-1".to_string(),
        sent_at: 2_000,
        ..SampleBatch::default()
    };
    batch
        .samples
        .push(Sample::new("cpu", 1_000, 1.5).with_label("host", "h1"));
    batch
        .samples
        .push(Sample::new("cpu", 2_000, 2.5).with_label("host", "h1"));
    batch
        .samples
        .push(Sample::new("mem", 1_000, 10.0).with_label("host", "h1"));
    storage.insert_batch(&batch).expect("写采样");
    storage
        .create_api_token("panel", "hash-panel", "read", 1_000)
        .expect("写 token");
    storage
        .upsert_alert_state(&AlertState {
            rule_id: "r1".to_string(),
            agent_id: "a1".to_string(),
            series_key: "s1".to_string(),
            state: AlertStateKind::Firing,
            since: 900,
            last_eval_at: 1_000,
            last_value: Some(1.5),
            last_notified_at: None,
        })
        .expect("写告警状态");
    storage
        .insert_archive_object(&ArchiveObject {
            id: 0,
            backend: "s3".to_string(),
            object_key: "d5b/key1".to_string(),
            manifest_key: "d5b/key1.manifest.json".to_string(),
            from_ts: 0,
            to_ts: 2_000,
            rows: 3,
            bytes: 100,
            sha256: "a".repeat(64),
            status: ArchiveStatus::Uploaded,
            error: String::new(),
            created_at: 1_000,
            uploaded_at: Some(1_000),
            deleted_at: None,
        })
        .expect("写归档对象");
}

fn setup_sqlite(root: &Path) -> (PathBuf, PathBuf, PathBuf, Vec<u8>) {
    let data_dir = root.join("data");
    fs::create_dir_all(&data_dir).expect("创建 data_dir");
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).expect("data_dir 0700");
    write_certs(&data_dir);
    let db_path = data_dir.join("rustboard.db");
    seed_sqlite(&db_path);
    let (config_path, config_bytes) =
        write_config(root, &data_dir, &format!("sqlite://{}", db_path.display()));
    (config_path, db_path, data_dir, config_bytes)
}

fn assert_seeded(storage: &StorageHandle) {
    assert_eq!(storage.sample_count("a1").expect("sample_count"), 3);
    let stats = storage.raw_stats().expect("raw_stats");
    assert_eq!(stats.rows, 3);
    assert_eq!(stats.oldest_ts, Some(1_000));
    assert_eq!(stats.newest_ts, Some(2_000));
    assert_eq!(storage.list_api_tokens().expect("list tokens").len(), 1);
    let state = storage
        .get_alert_state("r1", "a1", "s1")
        .expect("get alert state")
        .expect("alert state 存在");
    assert_eq!(state.state, AlertStateKind::Firing);
    assert_eq!(storage.count_archive_objects().expect("archive count"), 1);
    let agent = storage
        .get_agent("a1")
        .expect("get agent")
        .expect("agent 存在");
    assert_eq!(agent.name, "node1");
}

fn backup_dirs(out: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(out)
        .expect("读取备份根目录")
        .map(|entry| entry.expect("目录项").path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs
}

fn manifest_of(backup: &Path) -> Value {
    serde_json::from_slice(&fs::read(backup.join("manifest.json")).expect("读 manifest"))
        .expect("解析 manifest")
}

fn assert_manifest_hashes(backup: &Path) {
    let manifest = manifest_of(backup);
    assert_eq!(manifest["manifest_version"], 1);
    assert_eq!(manifest["backend"], "sqlite");
    assert_eq!(manifest["schema"], 7);
    assert!(!manifest["files"].as_array().unwrap().is_empty());
    for file in manifest["files"].as_array().unwrap() {
        let rel = file["path"].as_str().unwrap();
        let path = backup.join(rel);
        assert!(path.is_file(), "manifest 文件不存在: {rel}");
        assert_eq!(
            file["sha256"].as_str().unwrap(),
            file_sha(&path),
            "SHA256 不匹配: {rel}"
        );
        assert_eq!(
            file["size"].as_u64().unwrap(),
            fs::metadata(&path).unwrap().len(),
            "大小不匹配: {rel}"
        );
        assert_eq!(file["mode"].as_str().unwrap(), "0600", "mode: {rel}");
        assert_eq!(mode_of(&path), 0o600, "文件权限: {rel}");
    }
    assert_eq!(mode_of(&backup.join("manifest.json")), 0o600);
    assert_eq!(mode_of(backup), 0o700);
    assert_eq!(mode_of(&backup.join("certs")), 0o700);
}

fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        } else if path.file_name().and_then(|value| value.to_str()) == Some(name) {
            return Some(path);
        }
    }
    None
}

#[test]
fn sqlite_backup_restore_roundtrip_manifest_and_permissions() {
    let root = TestRoot::new("sqlite-roundtrip");
    let (config_path, db_path, data_dir, config_bytes) = setup_sqlite(root.path());
    let source_config_sha = sha256(&config_bytes);
    let source_db_sha = file_sha(&db_path);

    let out = root.path().join("backups");
    let output = hub(&[
        "backup",
        "--config",
        config_path.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "backup 失败: {}",
        combined(&output)
    );
    let text = combined(&output);
    assert!(
        !text.contains("d5b-canary-admin-token"),
        "backup 输出不得包含 admin_token: {text}"
    );

    let dirs = backup_dirs(&out);
    assert_eq!(dirs.len(), 1, "应生成一个时间戳目录");
    let backup = &dirs[0];
    assert_manifest_hashes(backup);
    assert_eq!(fs::read(backup.join("hub.toml")).unwrap(), config_bytes);
    assert_eq!(mode_of(&backup.join("hub.toml")), 0o600);
    assert_eq!(mode_of(&backup.join("rustboard.db")), 0o600);
    assert_eq!(mode_of(&backup.join("certs/server.key")), 0o600);
    // 源配置与源库在 backup 后保持不变。
    assert_eq!(sha256(&fs::read(&config_path).unwrap()), source_config_sha);
    assert_eq!(file_sha(&db_path), source_db_sha);

    // 删库后从空目标恢复。
    fs::remove_file(&db_path).expect("删除 SQLite");
    for suffix in ["-wal", "-shm"] {
        let path = db_path.with_file_name(format!("rustboard.db{suffix}"));
        let _ = fs::remove_file(path);
    }
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "restore 失败: {}",
        combined(&output)
    );
    let storage = StorageHandle::sqlite(&db_path, 4).expect("恢复后打开 SQLite");
    assert_seeded(&storage);
    drop(storage);
    // 模拟干净停机：测试里刚打开的 StorageHandle 可能留下空 -wal，force 恢复
    // 前必须清掉；带旧 WAL 的场景由专门用例覆盖「拒绝恢复」。
    remove_sqlite_sidecars(&db_path);
    assert_eq!(
        fs::read(&config_path).unwrap(),
        config_bytes,
        "配置应恢复原字节"
    );
    assert_eq!(mode_of(&config_path), 0o600);
    assert_eq!(mode_of(&data_dir.join("certs/server.key")), 0o600);

    // 非空目标默认拒绝，且不改动目标库。
    let before = file_sha(&db_path);
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--yes",
    ]);
    assert!(!output.status.success(), "非空目标必须拒绝");
    assert!(combined(&output).contains("非空"), "{}", combined(&output));
    assert_eq!(file_sha(&db_path), before, "拒绝时不得改动目标库");

    // --force 允许覆盖，并留下 pre-restore 备份。
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--force",
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "--force restore 失败: {}",
        combined(&output)
    );
    assert!(
        combined(&output).contains("恢复前目标备份"),
        "--force 应报告预备份: {}",
        combined(&output)
    );
    assert!(
        data_dir.join("backups").is_dir(),
        "--force 应在 data_dir/backups 留下预备份"
    );
    let storage = StorageHandle::sqlite(&db_path, 4).expect("force 后打开 SQLite");
    assert_seeded(&storage);
}

#[test]
fn restore_rejects_tampered_manifest_and_path_traversal() {
    let root = TestRoot::new("sqlite-tamper");
    let (config_path, db_path, _data_dir, _config_bytes) = setup_sqlite(root.path());
    let out = root.path().join("backups");
    let output = hub(&[
        "backup",
        "--config",
        config_path.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--yes",
    ]);
    assert!(output.status.success(), "{}", combined(&output));
    let backup = backup_dirs(&out).remove(0);

    // 1) 篡改备份 DB：SHA256 校验必须失败，目标库保持不变。
    let backup_db = backup.join("rustboard.db");
    let mut bytes = fs::read(&backup_db).unwrap();
    // 原地翻转一个字节：大小不变，只有 SHA256 能发现篡改。
    let index = bytes.len() / 2;
    bytes[index] ^= 0x42;
    fs::write(&backup_db, bytes).unwrap();
    let target_before = file_sha(&db_path);
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--force",
        "--yes",
    ]);
    assert!(!output.status.success(), "篡改备份必须拒绝恢复");
    let text = combined(&output);
    assert!(text.contains("SHA256"), "{text}");
    assert_eq!(file_sha(&db_path), target_before, "校验失败不得改目标库");

    // 2) manifest 路径穿越：重新生成 manifest，把证书路径改成 ../ca.crt。
    let manifest_path = backup.join("manifest.json");
    let mut manifest = manifest_of(&backup);
    for file in manifest["files"].as_array_mut().unwrap() {
        if file["path"] == "certs/ca.crt" {
            file["path"] = Value::String("../ca.crt".to_string());
        }
    }
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--force",
        "--yes",
    ]);
    assert!(!output.status.success(), "路径穿越必须拒绝");
    assert!(combined(&output).contains(".."), "{}", combined(&output));
    assert_eq!(file_sha(&db_path), target_before, "路径穿越不得写目标");
}

#[test]
fn migrate_failure_keeps_config_byte_identical_and_redacts_password() {
    let root = TestRoot::new("migrate-fail");
    let (_config_path, db_path, _data_dir, _config_bytes) = setup_sqlite(root.path());
    let config_path = root.path().join("etc/hub.toml");
    let before_config = fs::read(&config_path).unwrap();
    let before_db = file_sha(&db_path);
    let dsn = "postgres://d5b_user:d5b-super-secret@127.0.0.1:1/rustboard?sslmode=disable";

    let output = hub(&[
        "migrate",
        "--config",
        config_path.to_str().unwrap(),
        "--to",
        dsn,
        "--yes",
    ]);
    assert!(!output.status.success(), "不可达目标必须失败");
    let text = combined(&output);
    assert!(
        !text.contains("d5b-super-secret"),
        "错误信息泄露密码: {text}"
    );
    assert!(text.contains("***"), "目标 DSN 应脱敏: {text}");
    assert_eq!(
        fs::read(&config_path).unwrap(),
        before_config,
        "迁移失败后 hub.toml 必须字节相同"
    );
    assert_eq!(file_sha(&db_path), before_db, "迁移失败不得改 SQLite");
}

fn pg_dsn() -> Option<String> {
    match std::env::var("RUSTBOARD_TEST_PG") {
        Ok(dsn) if !dsn.is_empty() => Some(dsn),
        _ => {
            eprintln!("SKIP: 未设置 RUSTBOARD_TEST_PG，跳过真实 PostgreSQL 用例");
            None
        }
    }
}

static NEXT_DB: AtomicU64 = AtomicU64::new(0);

/// 每个 PG 用例使用独立的临时数据库，避免与同进程/其它 cargo test（以及并行
/// 的开发者测试）争用同一个 `RUSTBOARD_TEST_PG` 库。CI 的测试角色是 superuser，
/// 本地测试库角色也需要 CREATEDB（与 core 的 PG 测试前提一致）。
struct PgTestDb {
    dsn: String,
    admin_dsn: String,
    name: String,
}

impl Drop for PgTestDb {
    fn drop(&mut self) {
        if let Ok(mut admin) = connect_for_schema(&self.admin_dsn) {
            if let Err(err) = admin.batch_execute(&format!(
                "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
                self.name
            )) {
                eprintln!("WARN: 删除测试数据库 {} 失败: {err}", self.name);
            }
        }
    }
}

fn dsn_with_database(base: &str, name: &str) -> String {
    let (before_query, query) = match base.split_once('?') {
        Some((before, query)) => (before, Some(query)),
        None => (base, None),
    };
    let (prefix, _old) = before_query
        .rsplit_once('/')
        .expect("测试 DSN 必须包含数据库路径");
    match query {
        Some(query) => format!("{prefix}/{name}?{query}"),
        None => format!("{prefix}/{name}"),
    }
}

impl PgTestDb {
    fn create() -> Option<Self> {
        let base = pg_dsn()?;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let name = format!(
            "rb_d5b_{}_{}_{}",
            std::process::id(),
            nanos,
            NEXT_DB.fetch_add(1, Ordering::Relaxed)
        );
        let mut admin = connect_for_schema(&base).expect("连接 RUSTBOARD_TEST_PG 管理库");
        admin
            .batch_execute(&format!("CREATE DATABASE \"{name}\""))
            .unwrap_or_else(|err| panic!("创建测试数据库 {name} 失败: {err}"));
        Some(Self {
            dsn: dsn_with_database(&base, &name),
            admin_dsn: base,
            name,
        })
    }
}

fn dsn_password(dsn: &str) -> Option<String> {
    let authority = dsn.split_once("://")?.1.split(['/', '?']).next()?;
    let userinfo = authority.rsplit_once('@')?.0;
    let (_, password) = userinfo.split_once(':')?;
    Some(password.to_string())
}

fn reset_pg(dsn: &str) {
    let mut client = connect_for_schema(dsn).expect("连接 RUSTBOARD_TEST_PG");
    client
        .batch_execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .expect("重置 PostgreSQL public schema");
}

fn pg_storage(dsn: &str) -> PostgresStorage {
    let cfg = HubConfig {
        database: dsn.to_string(),
        ..HubConfig::default()
    };
    PostgresStorage::open_from_config(&cfg).expect("打开 PostgreSQL")
}

fn assert_pg_empty(dsn: &str) {
    let storage = pg_storage(dsn);
    validate_target_empty(&storage).expect("目标应为空");
}

fn pg_config(root: &Path, dsn: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    let data_dir = root.join("data");
    fs::create_dir_all(&data_dir).expect("创建 data_dir");
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).expect("data_dir 0700");
    write_certs(&data_dir);
    let (config_path, config_bytes) = write_config(root, &data_dir, dsn);
    (config_path, data_dir, config_bytes)
}

fn seed_pg(dsn: &str) {
    let cfg = HubConfig {
        database: dsn.to_string(),
        ..HubConfig::default()
    };
    let pg = PostgresStorage::open_from_config(&cfg).expect("打开 PG");
    pg.apply_schema().expect("apply schema");
    let storage = StorageHandle::postgres(pg);
    storage
        .upsert_agent(&AgentRecord {
            agent_id: "a1".to_string(),
            name: "node1".to_string(),
            hostname: "h1".to_string(),
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            version: "d5b".to_string(),
            boot_id: "boot-1".to_string(),
            status: "online".to_string(),
            last_seen_at: 2_000,
            created_at: 1_000,
        })
        .expect("PG 写 agent");
    let mut batch = SampleBatch {
        agent_id: "a1".to_string(),
        epoch: 1,
        seq: 0,
        boot_id: "boot-1".to_string(),
        sent_at: 2_000,
        ..SampleBatch::default()
    };
    batch
        .samples
        .push(Sample::new("cpu", 1_000, 1.5).with_label("host", "h1"));
    batch
        .samples
        .push(Sample::new("cpu", 2_000, 2.5).with_label("host", "h1"));
    batch
        .samples
        .push(Sample::new("mem", 1_000, 10.0).with_label("host", "h1"));
    storage.insert_batch(&batch).expect("PG 写采样");
    storage
        .create_api_token("panel", "hash-panel", "read", 1_000)
        .expect("PG 写 token");
    storage
        .upsert_alert_state(&AlertState {
            rule_id: "r1".to_string(),
            agent_id: "a1".to_string(),
            series_key: "s1".to_string(),
            state: AlertStateKind::Firing,
            since: 900,
            last_eval_at: 1_000,
            last_value: Some(1.5),
            last_notified_at: None,
        })
        .expect("PG 写告警状态");
    storage
        .insert_archive_object(&ArchiveObject {
            id: 0,
            backend: "s3".to_string(),
            object_key: "d5b/key1".to_string(),
            manifest_key: "d5b/key1.manifest.json".to_string(),
            from_ts: 0,
            to_ts: 2_000,
            rows: 3,
            bytes: 100,
            sha256: "a".repeat(64),
            status: ArchiveStatus::Uploaded,
            error: String::new(),
            created_at: 1_000,
            uploaded_at: Some(1_000),
            deleted_at: None,
        })
        .expect("PG 写归档对象");
}

#[test]
fn pg_migrate_dry_run_success_force_and_config_switch() {
    let Some(db) = PgTestDb::create() else {
        return;
    };
    let dsn = db.dsn.clone();
    let root = TestRoot::new("pg-migrate");
    let (config_path, db_path, data_dir, config_bytes) = setup_sqlite(root.path());
    let source_db_sha = file_sha(&db_path);
    let password = dsn_password(&dsn).expect("测试 DSN 必须带密码");

    // --dry-run：配置/SQLite/目标均零写入。
    let output = hub(&[
        "migrate",
        "--config",
        config_path.to_str().unwrap(),
        "--to",
        &dsn,
        "--dry-run",
    ]);
    assert!(
        output.status.success(),
        "dry-run 失败: {}",
        combined(&output)
    );
    let text = combined(&output);
    assert!(!text.contains(&password), "dry-run 泄露密码: {text}");
    assert!(text.contains("***"), "dry-run 目标 DSN 应脱敏: {text}");
    assert!(text.contains("只读校验"), "{text}");
    assert_eq!(fs::read(&config_path).unwrap(), config_bytes);
    assert_eq!(file_sha(&db_path), source_db_sha);
    assert_pg_empty(&dsn);

    // 真实迁移：21 表 + 配置切换。
    let output = hub(&[
        "migrate",
        "--config",
        config_path.to_str().unwrap(),
        "--to",
        &dsn,
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "migrate 失败: {}",
        combined(&output)
    );
    let text = combined(&output);
    assert!(!text.contains(&password), "migrate 泄露密码: {text}");
    assert!(text.contains("迁移完成"), "{text}");
    assert!(text.contains("21 张表"), "{text}");
    assert_eq!(file_sha(&db_path), source_db_sha, "迁移不得修改源 SQLite");
    let new_config = fs::read_to_string(&config_path).unwrap();
    assert!(
        new_config.contains(&dsn),
        "hub.toml 应切换到目标 DSN: {new_config}"
    );
    assert!(
        new_config.contains("d5b-canary-admin-token"),
        "配置切换必须保留其它字段"
    );
    let baks: Vec<_> = fs::read_dir(root.path().join("etc"))
        .unwrap()
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("hub.toml.bak-")
        })
        .collect();
    assert_eq!(baks.len(), 1, "应保留一份旧配置备份");
    assert_eq!(mode_of(&baks[0].path()), 0o600);

    let storage = StorageHandle::postgres(pg_storage(&dsn));
    assert_seeded(&storage);
    drop(storage);

    // --force：目标已经非空；用 stub pg_dump 验证「先备份、再清空」的编排。
    // 真实 pg_dump 用例见 `pg_backup_restore_requires_real_client_tools`，缺工具时 SKIP。
    fs::write(&config_path, &config_bytes).unwrap();
    fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
    // 目标非空、未带 --force：dry-run 也必须明确失败，不能假绿。
    let output = hub(&[
        "migrate",
        "--config",
        config_path.to_str().unwrap(),
        "--to",
        &dsn,
        "--dry-run",
    ]);
    assert!(!output.status.success(), "非空目标 dry-run 必须失败");
    assert!(combined(&output).contains("非空"), "{}", combined(&output));
    assert_eq!(fs::read(&config_path).unwrap(), config_bytes);
    let storage = StorageHandle::postgres(pg_storage(&dsn));
    assert_seeded(&storage);
    drop(storage);

    // pg_dump 失败：不得清空目标、不得改配置、不得删 SQLite。
    let fail_bin = root.path().join("fakebin-fail");
    fs::create_dir_all(&fail_bin).unwrap();
    let fail_dump = fail_bin.join("pg_dump");
    fs::write(
        &fail_dump,
        "#!/bin/sh\n\
         if [ \"${1:-}\" = \"--version\" ]; then echo 'pg_dump (fake) 1'; exit 0; fi\n\
         echo 'fake pg_dump failure' >&2\n\
         exit 1\n",
    )
    .unwrap();
    fs::set_permissions(&fail_dump, fs::Permissions::from_mode(0o755)).unwrap();
    let source_sha = file_sha(&db_path);
    let fail_path = format!(
        "{}:{}",
        fail_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rustboard-hub"))
        .args([
            "migrate",
            "--config",
            config_path.to_str().unwrap(),
            "--to",
            &dsn,
            "--force",
            "--yes",
            "--hub-stopped",
        ])
        .env("PATH", fail_path)
        .env_remove("RUSTBOARD_DATABASE_PASSWORD")
        .output()
        .expect("执行失败注入 migrate");
    assert!(!output.status.success(), "pg_dump 失败时 migrate 必须失败");
    assert!(
        combined(&output).contains("备份目标 PostgreSQL 失败"),
        "{}",
        combined(&output)
    );
    assert_eq!(fs::read(&config_path).unwrap(), config_bytes);
    assert_eq!(file_sha(&db_path), source_sha);
    let storage = StorageHandle::postgres(pg_storage(&dsn));
    assert_seeded(&storage);
    drop(storage);
    assert!(
        find_file(&data_dir.join("backups"), "target-before-migrate.dump").is_none(),
        "pg_dump 失败时不得留下目标备份/清空步骤"
    );

    let fake_bin = root.path().join("fakebin");
    fs::create_dir_all(&fake_bin).unwrap();
    let fake_dump = fake_bin.join("pg_dump");
    fs::write(
        &fake_dump,
        "#!/bin/sh\n\
         if [ \"${1:-}\" = \"--version\" ]; then echo 'pg_dump (fake) 1'; exit 0; fi\n\
         out=''\n\
         prev=''\n\
         for arg in \"$@\"; do\n\
           if [ \"$prev\" = '--file' ]; then out=\"$arg\"; fi\n\
           prev=\"$arg\"\n\
         done\n\
         if [ -z \"$out\" ]; then echo 'missing --file' >&2; exit 1; fi\n\
         printf 'FAKE-PG-DUMP' > \"$out\"\n\
         printf '%s\\n' \"$@\" > \"$RB_FAKE_ARGV\"\n\
         printf '%s' \"${PGPASSWORD:-}\" > \"$RB_FAKE_PASSWORD\"\n",
    )
    .unwrap();
    fs::set_permissions(&fake_dump, fs::Permissions::from_mode(0o755)).unwrap();
    let argv_file = root.path().join("fake-argv.txt");
    let password_file = root.path().join("fake-password.txt");
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rustboard-hub"))
        .args([
            "migrate",
            "--config",
            config_path.to_str().unwrap(),
            "--to",
            &dsn,
            "--force",
            "--yes",
            "--hub-stopped",
        ])
        .env("PATH", path)
        .env("RB_FAKE_ARGV", &argv_file)
        .env("RB_FAKE_PASSWORD", &password_file)
        .env_remove("RUSTBOARD_DATABASE_PASSWORD")
        .output()
        .expect("执行 force migrate");
    assert!(
        output.status.success(),
        "--force migrate 失败: {}",
        combined(&output)
    );
    let text = combined(&output);
    assert!(text.contains("目标侧备份"), "{text}");
    let fake_argv = fs::read_to_string(&argv_file).unwrap();
    assert!(
        !fake_argv.contains(&password),
        "pg_dump argv 不得包含密码: {fake_argv}"
    );
    assert!(fake_argv.contains("--dbname"), "{fake_argv}");
    assert_eq!(
        fs::read_to_string(&password_file).unwrap(),
        password,
        "PGPASSWORD 环境变量应传递密码"
    );
    let target_dump = find_file(&data_dir.join("backups"), "target-before-migrate.dump")
        .expect("应生成目标侧 pg_dump 备份");
    assert_eq!(mode_of(&target_dump), 0o600);
    assert_eq!(fs::read(&target_dump).unwrap(), b"FAKE-PG-DUMP");
    assert!(
        fs::read_to_string(&config_path).unwrap().contains(&dsn),
        "force 成功后配置应切换"
    );
    let storage = StorageHandle::postgres(pg_storage(&dsn));
    assert_seeded(&storage);
}

fn tool_available(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn pg_server_major(dsn: &str) -> Option<u32> {
    let mut client = connect_for_schema(dsn).ok()?;
    let version: String = client.query_one("SHOW server_version", &[]).ok()?.get(0);
    version.split('.').next()?.parse().ok()
}

fn pg_tool_major(tool: &str) -> Option<u32> {
    let output = Command::new(tool).arg("--version").output().ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    text.split_whitespace()
        .find_map(|word| word.trim_start_matches('(').split('.').next()?.parse().ok())
}

#[test]
fn pg_backup_restore_requires_real_client_tools() {
    let Some(db) = PgTestDb::create() else {
        return;
    };
    let dsn = db.dsn.clone();
    if !tool_available("pg_dump") || !tool_available("pg_restore") {
        eprintln!(
            "SKIP: pg_dump/pg_restore 不在 PATH，跳过真实 PostgreSQL backup/restore 用例\
             （安装 postgresql-client 后重跑；见 docs/install/postgres.md §6）"
        );
        return;
    }
    // pg_dump/pg_restore 大版本高于服务端时，17 的 dump 会带
    // `SET transaction_timeout`，PG16 服务端无法执行；这是客户端/服务端版本
    // 不匹配，不是产品回归。CI 固定 postgres:16 + postgresql-client 16。
    if let Some(server) = pg_server_major(&dsn) {
        if let Some(client) = pg_tool_major("pg_dump") {
            if client > server {
                eprintln!(
                    "SKIP: pg_dump 大版本 {client} 高于服务端 {server}（transaction_timeout 不兼容）；\
                     请安装与 postgres:16 匹配的 postgresql-client-16 后重跑"
                );
                return;
            }
        }
    }
    seed_pg(&dsn);
    let root = TestRoot::new("pg-backup");
    let (config_path, data_dir, _config_bytes) = pg_config(root.path(), &dsn);
    assert_seeded(&StorageHandle::postgres(pg_storage(&dsn)));

    let out = root.path().join("backups");
    let output = hub(&[
        "backup",
        "--config",
        config_path.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "PG backup 失败: {}",
        combined(&output)
    );
    let backup = backup_dirs(&out).remove(0);
    let manifest = manifest_of(&backup);
    assert_eq!(manifest["backend"], "postgres");
    assert_eq!(manifest["schema"], 7);
    assert!(backup.join("rustboard.dump").is_file());
    assert_eq!(mode_of(&backup.join("rustboard.dump")), 0o600);

    // 目标非空时 restore 默认拒绝。
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--yes",
    ]);
    assert!(!output.status.success(), "PG 非空目标必须拒绝");
    assert!(combined(&output).contains("非空"), "{}", combined(&output));

    // 清空目标后从备份恢复。
    reset_pg(&dsn);
    assert_pg_empty(&dsn);
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "PG restore 失败: {}",
        combined(&output)
    );
    assert_seeded(&StorageHandle::postgres(pg_storage(&dsn)));
    assert!(data_dir.join("certs").is_dir());
}

/// 恶意备份：把备份内 hub.toml 的 data_dir/database 改到目标外，并同步刷新
/// manifest 的 SHA256/大小（哈希完全自洽）。restore 必须忽略它，只写当前配置
/// 指向的目标。
#[test]
fn restore_ignores_malicious_backup_paths_even_with_valid_manifest() {
    let root = TestRoot::new("restore-malicious-target");
    let (config_path, db_path, data_dir, _config_bytes) = setup_sqlite(root.path());
    let out = root.path().join("backups");
    let output = hub(&[
        "backup",
        "--config",
        config_path.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--yes",
    ]);
    assert!(output.status.success(), "{}", combined(&output));
    let backup = backup_dirs(&out).remove(0);
    remove_sqlite_sidecars(&db_path);

    let evil = root.path().join("evil-target");
    let backup_config_path = backup.join("hub.toml");
    let mut evil_cfg: toml::Value =
        toml::from_str(&fs::read_to_string(&backup_config_path).unwrap()).unwrap();
    evil_cfg["data_dir"] = toml::Value::String(evil.display().to_string());
    evil_cfg["database"] = toml::Value::String(format!("sqlite://{}/rustboard.db", evil.display()));
    fs::write(
        &backup_config_path,
        toml::to_string_pretty(&evil_cfg).unwrap(),
    )
    .unwrap();
    refresh_manifest_file(&backup, "hub.toml");

    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--force",
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "恶意备份路径不应阻止合法恢复: {}",
        combined(&output)
    );
    assert!(!evil.exists(), "绝不能写到备份 hub.toml 指定目录");
    let restored = read_config(&config_path);
    assert_eq!(restored.data_dir, data_dir);
    assert_eq!(restored.database, format!("sqlite://{}", db_path.display()));
    assert_eq!(restored.admin_token, "d5b-canary-admin-token");
    let storage = StorageHandle::sqlite(&db_path, 4).expect("打开恢复后的 SQLite");
    assert_seeded(&storage);
}

#[test]
fn restore_without_config_requires_explicit_data_dir() {
    let root = TestRoot::new("restore-no-config");
    let (config_path, _db_path, _data_dir, _config_bytes) = setup_sqlite(root.path());
    let out = root.path().join("backups");
    let output = hub(&[
        "backup",
        "--config",
        config_path.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--yes",
    ]);
    assert!(output.status.success(), "{}", combined(&output));
    let backup = backup_dirs(&out).remove(0);
    fs::remove_file(&config_path).expect("删除当前配置");

    let new_config = root.path().join("new/etc/hub.toml");
    let new_data = root.path().join("new-data");
    let output = hub(&[
        "restore",
        "--config",
        new_config.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--yes",
    ]);
    assert!(!output.status.success(), "缺 --data-dir 必须拒绝");
    assert!(
        combined(&output).contains("--data-dir"),
        "{}",
        combined(&output)
    );
    assert!(!new_data.exists(), "拒绝时不得创建目标目录");

    let output = hub(&[
        "restore",
        "--config",
        new_config.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--data-dir",
        new_data.to_str().unwrap(),
        "--db",
        "postgres://u:p@127.0.0.1/db?sslmode=disable",
        "--yes",
    ]);
    assert!(!output.status.success(), "SQLite 备份不接受 --db");
    assert!(
        combined(&output).contains("不接受 --db"),
        "{}",
        combined(&output)
    );

    let output = hub(&[
        "restore",
        "--config",
        new_config.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--data-dir",
        new_data.to_str().unwrap(),
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "显式 --data-dir 应恢复成功: {}",
        combined(&output)
    );
    let restored_db = new_data.join("rustboard.db");
    assert!(restored_db.is_file());
    assert_eq!(mode_of(&restored_db), 0o600);
    assert_eq!(mode_of(&new_data.join("certs/server.key")), 0o600);
    let restored = read_config(&new_config);
    assert_eq!(restored.data_dir, new_data);
    assert_eq!(
        restored.database,
        format!("sqlite://{}", restored_db.display())
    );
    let storage = StorageHandle::sqlite(&restored_db, 4).expect("打开恢复后的 SQLite");
    assert_seeded(&storage);
}

/// PG 备份在配置缺失时：缺 --data-dir / 缺 --db 都必须拒绝，而且发生在
/// `pg_restore` 工具检查之前（本机没有 pg_restore 也能验证参数校验）。
#[test]
fn restore_pg_without_config_requires_data_dir_and_db() {
    let root = TestRoot::new("restore-pg-no-config");
    let dsn = "postgres://rustboard:secret@127.0.0.1:1/rustboard?sslmode=disable";
    let backup = root.path().join("pg-backup");
    fs::create_dir_all(&backup).unwrap();
    let cfg = HubConfig {
        data_dir: root.path().join("original-data"),
        database: dsn.to_string(),
        ..HubConfig::default()
    };
    let cfg_bytes = toml::to_string_pretty(&cfg).unwrap().into_bytes();
    fs::write(backup.join("hub.toml"), &cfg_bytes).unwrap();
    let dump = b"fake-pg-dump";
    fs::write(backup.join("rustboard.dump"), dump).unwrap();
    let manifest = serde_json::json!({
        "manifest_version": 1,
        "version": "test",
        "schema": 7,
        "backend": "postgres",
        "created_at": "2026-01-01T00:00:00.000Z",
        "created_at_ms": 0,
        "files": [
            {"path": "hub.toml", "sha256": sha256(&cfg_bytes), "size": cfg_bytes.len(), "mode": "0600"},
            {"path": "rustboard.dump", "sha256": sha256(dump), "size": dump.len(), "mode": "0600"}
        ]
    });
    fs::write(
        backup.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        backup.join("manifest.json"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let config_path = root.path().join("missing/hub.toml");
    let data_dir = root.path().join("restore-data");
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--yes",
    ]);
    assert!(!output.status.success());
    assert!(
        combined(&output).contains("--data-dir"),
        "{}",
        combined(&output)
    );

    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--data-dir",
        data_dir.to_str().unwrap(),
        "--yes",
    ]);
    assert!(!output.status.success(), "缺 --db 必须拒绝");
    assert!(combined(&output).contains("--db"), "{}", combined(&output));
    assert!(!data_dir.exists(), "拒绝时不得创建目标目录");
}

/// `--force` 的 pre-restore 快照失败必须中止；只有显式
/// `--no-pre-restore-backup` 才允许在无备份情况下继续。
#[test]
fn restore_force_aborts_when_pre_restore_backup_fails() {
    let root = TestRoot::new("restore-prebackup-fail");
    let (config_path, db_path, data_dir, config_bytes) = setup_sqlite(root.path());
    let out = root.path().join("backups");
    let output = hub(&[
        "backup",
        "--config",
        config_path.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--yes",
    ]);
    assert!(output.status.success(), "{}", combined(&output));
    let backup = backup_dirs(&out).remove(0);
    remove_sqlite_sidecars(&db_path);
    // 让 pre-restore 快照的 certs 复制失败。
    fs::remove_dir_all(data_dir.join("certs")).unwrap();
    let before_db = file_sha(&db_path);
    let before_config = fs::read(&config_path).unwrap();

    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--force",
        "--yes",
    ]);
    assert!(!output.status.success(), "pre-restore 失败必须中止");
    assert!(
        combined(&output).contains("恢复前备份当前目标失败"),
        "{}",
        combined(&output)
    );
    assert_eq!(file_sha(&db_path), before_db, "中止时不得改目标库");
    assert_eq!(fs::read(&config_path).unwrap(), before_config);

    remove_sqlite_sidecars(&db_path);
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--force",
        "--no-pre-restore-backup",
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "显式跳过预备份后应成功: {}",
        combined(&output)
    );
    assert_seeded(&StorageHandle::sqlite(&db_path, 4).expect("打开 SQLite"));
    assert_eq!(mode_of(&data_dir.join("certs/server.key")), 0o600);
    let _ = config_bytes;
}

/// 恢复前存在旧 `-wal`：必须拒绝；清理 sidecar 后再恢复，旧 WAL 中的旧表不能
/// 重现，且新库 `quick_check` 通过。
#[test]
fn restore_refuses_stale_wal_and_never_replays_old_table() {
    let root = TestRoot::new("restore-stale-wal");
    let (config_path, db_path, data_dir, _config_bytes) = setup_sqlite(root.path());
    let out = root.path().join("backups");
    let output = hub(&[
        "backup",
        "--config",
        config_path.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
        "--yes",
    ]);
    assert!(output.status.success(), "{}", combined(&output));
    let backup = backup_dirs(&out).remove(0);
    remove_sqlite_sidecars(&db_path);

    // 目标旧库多一张备份里没有的表，模拟旧 WAL 可能带回的历史数据。
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE old_marker (value TEXT);\
             INSERT INTO old_marker (value) VALUES ('stale');",
        )
        .unwrap();
    }
    remove_sqlite_sidecars(&db_path);
    fs::write(sqlite_sidecar(&db_path, "-wal"), b"stale-wal").unwrap();
    let before = file_sha(&db_path);

    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--force",
        "--yes",
    ]);
    assert!(!output.status.success(), "带旧 WAL 必须拒绝恢复");
    let text = combined(&output);
    assert!(text.contains("-wal"), "{text}");
    assert_eq!(file_sha(&db_path), before, "拒绝时不得改目标库");

    remove_sqlite_sidecars(&db_path);
    let output = hub(&[
        "restore",
        "--config",
        config_path.to_str().unwrap(),
        "--from",
        backup.to_str().unwrap(),
        "--force",
        "--yes",
    ]);
    assert!(
        output.status.success(),
        "清理 sidecar 后应恢复成功: {}",
        combined(&output)
    );
    quick_check_ok(&db_path);
    let conn =
        rusqlite::Connection::open_with_flags(&db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let old: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='old_marker'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(old, 0, "旧表不能从旧 WAL 重现");
    drop(conn);
    let storage = StorageHandle::sqlite(&db_path, 4).expect("打开恢复后的 SQLite");
    assert_seeded(&storage);
    assert_eq!(mode_of(&data_dir.join("certs/server.key")), 0o600);
}

/// dry-run 只读：源目录在命令前后不能多出 `-shm/-wal` 或备份目录。
#[test]
fn migrate_dry_run_does_not_create_sqlite_sidecars() {
    let root = TestRoot::new("migrate-dry-run-sidecars");
    let (config_path, db_path, data_dir, _config_bytes) = setup_sqlite(root.path());
    remove_sqlite_sidecars(&db_path);
    let before = list_tree(&data_dir);
    let output = hub(&[
        "migrate",
        "--config",
        config_path.to_str().unwrap(),
        "--to",
        "postgres://u:p@127.0.0.1:1/rustboard?sslmode=disable",
        "--dry-run",
    ]);
    assert!(!output.status.success(), "不可达目标应失败");
    assert!(
        !combined(&output).contains("panicked"),
        "{}",
        combined(&output)
    );
    let after = list_tree(&data_dir);
    assert_eq!(before, after, "dry-run 不得在源目录创建任何新文件");
    assert!(
        !data_dir.join("backups").exists(),
        "dry-run 不得创建备份目录"
    );
}

/// 无 systemd unit / 状态 unknown 时 fail-closed；有 unit 且 active 时即使给了
/// `--hub-stopped` 也必须拒绝。
#[test]
fn migrate_hub_stopped_is_fail_closed() {
    let root = TestRoot::new("migrate-hub-stopped");
    let (config_path, _db_path, _data_dir, config_bytes) = setup_sqlite(root.path());
    let fake_bin = root.path().join("fake-systemctl");
    fs::create_dir_all(&fake_bin).unwrap();
    let systemctl = fake_bin.join("systemctl");
    fs::write(
        &systemctl,
        "#!/bin/sh\n\
         case \"$1\" in\n\
           show) echo not-found; exit 0;;\n\
           is-active) echo unknown; exit 4;;\n\
         esac\n\
         exit 4\n",
    )
    .unwrap();
    fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_rustboard-hub"))
        .args([
            "migrate",
            "--config",
            config_path.to_str().unwrap(),
            "--to",
            "postgres://u:p@127.0.0.1:1/rustboard?sslmode=disable",
            "--yes",
        ])
        .env("PATH", &path)
        .env_remove("RUSTBOARD_DATABASE_PASSWORD")
        .output()
        .unwrap();
    assert!(!output.status.success(), "无法确认 hub 状态必须拒绝");
    assert!(
        combined(&output).contains("--hub-stopped"),
        "{}",
        combined(&output)
    );
    assert_eq!(fs::read(&config_path).unwrap(), config_bytes);

    if Path::new("/run/systemd/system").is_dir() {
        fs::write(
            &systemctl,
            "#!/bin/sh\n\
             case \"$1\" in\n\
               show) echo loaded; exit 0;;\n\
               is-active) echo active; exit 0;;\n\
             esac\n\
             exit 0\n",
        )
        .unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_rustboard-hub"))
            .args([
                "migrate",
                "--config",
                config_path.to_str().unwrap(),
                "--to",
                "postgres://u:p@127.0.0.1:1/rustboard?sslmode=disable",
                "--yes",
                "--hub-stopped",
            ])
            .env("PATH", path)
            .env_remove("RUSTBOARD_DATABASE_PASSWORD")
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "active 时 --hub-stopped 也不能放行"
        );
        assert!(
            combined(&output).contains("正在运行"),
            "{}",
            combined(&output)
        );
    }
}

/// 两个进程同时 `migrate --force`：CLI 的会话级 advisory lock 必须让
/// pg_dump/TRUNCATE/import 串行；否则第二个会在第一个导入期间清空目标。
#[test]
fn concurrent_force_migrate_is_serialized_by_advisory_lock() {
    let Some(db) = PgTestDb::create() else {
        return;
    };
    let dsn = db.dsn.clone();
    seed_pg(&dsn);
    let root = TestRoot::new("pg-concurrent-force");
    let (config_path, _db_path, data_dir, _config_bytes) = setup_sqlite(root.path());

    let fake_bin = root.path().join("fakebin-concurrent");
    fs::create_dir_all(&fake_bin).unwrap();
    let fake_dump = fake_bin.join("pg_dump");
    fs::write(
        &fake_dump,
        "#!/bin/sh\n\
         if [ \"${1:-}\" = \"--version\" ]; then echo 'pg_dump (fake) 2'; exit 0; fi\n\
         out=''\n\
         prev=''\n\
         for arg in \"$@\"; do\n\
           if [ \"$prev\" = '--file' ]; then out=\"$arg\"; fi\n\
           prev=\"$arg\"\n\
         done\n\
         if [ -z \"$out\" ]; then echo 'missing --file' >&2; exit 1; fi\n\
         start=$(date +%s%N)\n\
         printf '%s start %s\\n' \"$$\" \"$start\" >> \"$RB_FAKE_LOG\"\n\
         sleep 2\n\
         printf 'FAKE-CONCURRENT' > \"$out\"\n\
         end=$(date +%s%N)\n\
         printf '%s end %s\\n' \"$$\" \"$end\" >> \"$RB_FAKE_LOG\"\n",
    )
    .unwrap();
    fs::set_permissions(&fake_dump, fs::Permissions::from_mode(0o755)).unwrap();
    let log = root.path().join("pgdump.log");
    let path = format!(
        "{}:{}",
        fake_bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let spawn = || {
        Command::new(env!("CARGO_BIN_EXE_rustboard-hub"))
            .args([
                "migrate",
                "--config",
                config_path.to_str().unwrap(),
                "--to",
                &dsn,
                "--force",
                "--yes",
                "--hub-stopped",
            ])
            .env("PATH", &path)
            .env("RB_FAKE_LOG", &log)
            .env_remove("RUSTBOARD_DATABASE_PASSWORD")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("启动 migrate")
    };

    let first = spawn();
    // 等第一个进程真正进入 pg_dump（说明它已持有 advisory lock）。
    let mut saw_start = false;
    for _ in 0..100 {
        if fs::read_to_string(&log)
            .map(|text| text.contains(" start "))
            .unwrap_or(false)
        {
            saw_start = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(saw_start, "第一个 migrate 未进入 pg_dump");
    let second = spawn();
    let first = first.wait_with_output().expect("等待第一个 migrate");
    let second = second.wait_with_output().expect("等待第二个 migrate");
    assert!(
        first.status.success(),
        "第一个 migrate 失败: {}{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        second.status.success(),
        "第二个 migrate 失败: {}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );

    // 两个 pg_dump 的时间区间必须不重叠。
    let mut intervals: Vec<(u128, u128)> = Vec::new();
    let mut starts = std::collections::BTreeMap::new();
    for line in fs::read_to_string(&log).unwrap().lines() {
        let mut parts = line.split_whitespace();
        let pid = parts.next().expect("pid");
        let phase = parts.next().expect("phase");
        let ns: u128 = parts.next().expect("ns").parse().expect("ns");
        match phase {
            "start" => {
                starts.insert(pid.to_string(), ns);
            }
            "end" => {
                let start = starts
                    .remove(pid)
                    .unwrap_or_else(|| panic!("{pid} 缺 start"));
                intervals.push((start, ns));
            }
            other => panic!("未知日志 phase: {other}"),
        }
    }
    assert_eq!(intervals.len(), 2, "应观察到两次 pg_dump: {intervals:?}");
    intervals.sort();
    assert!(
        intervals[0].1 <= intervals[1].0,
        "pg_dump 区间重叠，说明 force migrate 未被串行化: {intervals:?}"
    );

    let storage = StorageHandle::postgres(pg_storage(&dsn));
    assert_seeded(&storage);
    assert!(
        fs::read_to_string(&config_path).unwrap().contains(&dsn),
        "最终配置应指向 PG"
    );
    let _ = data_dir;
}

/// pentest 回归：v7 源库有未 checkpoint 的 `-wal` 时，immutable 只看主库会把
/// user_version 读成 0。预检必须复制 DB+WAL 到临时目录读取；dry-run 成功、
/// 能识别 21 表与 WAL 中的新增行，且源目录不新增任何文件。
#[test]
fn migrate_dry_run_reads_uncheckpointed_wal_source() {
    let Some(db) = PgTestDb::create() else {
        return;
    };
    let dsn = db.dsn.clone();
    let root = TestRoot::new("migrate-wal-source");
    let (config_path, db_path, data_dir, _config_bytes) = setup_sqlite(root.path());
    remove_sqlite_sidecars(&db_path);
    {
        let conn = rusqlite::Connection::open(&db_path).expect("打开 SQLite");
        conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
        conn.execute(
            "INSERT INTO samples(agent_id, metric, labels, ts, value) \
             VALUES('a1', 'cpu', '{}', 3000, 3.5)",
            [],
        )
        .expect("写入 WAL");
        // 模拟崩溃/未 checkpoint：不 close，保留 WAL 供读取。
        std::mem::forget(conn);
    }
    let wal = sqlite_sidecar(&db_path, "-wal");
    assert!(wal.is_file(), "测试未生成 -wal");
    assert!(
        fs::metadata(&wal).unwrap().len() > 0,
        "测试 -wal 为空，无法覆盖未 checkpoint 场景"
    );
    let before = list_tree(&data_dir);
    let output = hub(&[
        "migrate",
        "--config",
        config_path.to_str().unwrap(),
        "--to",
        &dsn,
        "--dry-run",
    ]);
    assert!(
        output.status.success(),
        "带 WAL 的 dry-run 失败: {}",
        combined(&output)
    );
    let text = combined(&output);
    assert!(text.contains("schema v7"), "{text}");
    assert!(
        text.contains("samples 4 行"),
        "必须读到 WAL 中的新增行: {text}"
    );
    assert!(text.contains("21 张表齐全"), "{text}");
    let after = list_tree(&data_dir);
    assert_eq!(before, after, "dry-run 不得在源目录创建/删除文件");
    assert_pg_empty(&dsn);
}
