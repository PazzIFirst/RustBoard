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
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use rustboard_common::config::HubConfig;
use rustboard_common::model::{AgentRecord, Sample, SampleBatch};
use rustboard_core::alerts::{AlertState, AlertStateKind};
use rustboard_core::archive::{ArchiveObject, ArchiveStatus};
use rustboard_core::storage::migrate::validate_target_empty;
use rustboard_core::storage::postgres::{connect_for_schema, PostgresStorage};
use rustboard_core::storage::StorageHandle;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// 同一测试二进制内串行化所有真实 PG 用例（共用 RUSTBOARD_TEST_PG 数据库）。
static PG_SERIAL: Mutex<()> = Mutex::new(());
static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

fn pg_serial() -> MutexGuard<'static, ()> {
    PG_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

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
    Command::new(env!("CARGO_BIN_EXE_rustboard-hub"))
        .args(args)
        .env_remove("RUSTBOARD_DATABASE_PASSWORD")
        .output()
        .expect("执行 rustboard-hub")
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
    let _ = data_dir;
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
    let mut cfg = HubConfig::default();
    cfg.database = dsn.to_string();
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
    let mut cfg = HubConfig::default();
    cfg.database = dsn.to_string();
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
    let Some(dsn) = pg_dsn() else {
        return;
    };
    let _guard = pg_serial();
    reset_pg(&dsn);
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

#[test]
fn pg_backup_restore_requires_real_client_tools() {
    let Some(dsn) = pg_dsn() else {
        return;
    };
    if !tool_available("pg_dump") || !tool_available("pg_restore") {
        eprintln!(
            "SKIP: pg_dump/pg_restore 不在 PATH，跳过真实 PostgreSQL backup/restore 用例\
             （安装 postgresql-client 后重跑；见 docs/install/postgres.md §6）"
        );
        return;
    }
    let _guard = pg_serial();
    reset_pg(&dsn);
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
