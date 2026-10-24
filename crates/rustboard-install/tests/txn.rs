//! 安装事务：备份、原子替换、逆序回滚、dry-run 与 Drop。

mod common;

use std::fs;
use std::path::Path;

use rustboard_install::{InstallTxn, PathOverrides, Paths, Role};

fn paths_for(temp: &common::TempDir, role: Role) -> Paths {
    Paths::for_role(role, temp.path(), PathOverrides::default()).unwrap()
}

#[test]
fn new_file_write_is_removed_by_rollback() {
    let temp = common::TempDir::new("txn-new");
    let paths = paths_for(&temp, Role::Hub);
    let mut txn = InstallTxn::begin(&paths, false).unwrap();

    txn.write(&paths.config, b"schema = 1\n", 0o600).unwrap();
    assert_eq!(fs::read(&paths.config).unwrap(), b"schema = 1\n");
    assert_eq!(common::mode_of(&paths.config), 0o600);
    let backup_dir = txn.backup_dir().to_path_buf();

    txn.rollback().unwrap();
    assert!(!paths.config.exists());
    assert!(!backup_dir.exists());
    // 事务自动创建的父目录若已空也应收回。
    assert!(!temp.join("etc").exists());
}

#[test]
fn existing_file_is_backed_up_and_restored() {
    let temp = common::TempDir::new("txn-existing");
    let paths = paths_for(&temp, Role::Hub);
    common::write_file(&paths.config, b"old", 0o600);
    // 模拟已有数据目录：回滚绝不能碰它。
    fs::create_dir_all(&paths.data_dir).unwrap();
    common::write_file(&paths.data_dir.join("hub.db"), b"data", 0o600);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.write(&paths.config, b"new", 0o600).unwrap();
    assert_eq!(fs::read(&paths.config).unwrap(), b"new");
    assert!(txn.backup_dir().exists());
    let backup_files = fs::read_dir(txn.backup_dir()).unwrap().count();
    assert_eq!(backup_files, 1);

    txn.rollback().unwrap();
    assert_eq!(fs::read(&paths.config).unwrap(), b"old");
    assert_eq!(common::mode_of(&paths.config), 0o600);
    assert!(!txn.backup_dir().exists());
    assert_eq!(fs::read(paths.data_dir.join("hub.db")).unwrap(), b"data");
}

#[test]
fn rollback_restores_original_mode() {
    let temp = common::TempDir::new("txn-mode");
    let paths = paths_for(&temp, Role::Agent);
    common::write_file(&paths.config, b"old", 0o640);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.write(&paths.config, b"new", 0o600).unwrap();
    assert_eq!(common::mode_of(&paths.config), 0o600);
    txn.rollback().unwrap();
    assert_eq!(common::mode_of(&paths.config), 0o640);
    assert_eq!(fs::read(&paths.config).unwrap(), b"old");
}

#[test]
fn dry_run_makes_no_changes_and_creates_no_backup_dir() {
    let temp = common::TempDir::new("txn-dry");
    let paths = paths_for(&temp, Role::Panel);
    fs::create_dir_all(&paths.data_dir).unwrap();
    common::write_file(&paths.config, b"old", 0o600);
    let source = temp.join("new-binary");
    common::write_file(&source, b"binary", 0o755);

    let mut txn = InstallTxn::begin(&paths, true).unwrap();
    txn.write(&paths.config, b"new", 0o600).unwrap();
    txn.create_dir(&paths.data_dir, 0o700).unwrap();
    txn.create_dir(&temp.join("brand/new/dir"), 0o700).unwrap();
    txn.create_owned_dir(&temp.join("owned-dry"), 0o700)
        .unwrap();
    txn.remove(&paths.config).unwrap();
    txn.copy_file(&source, &paths.binary, 0o755).unwrap();
    assert_eq!(fs::read(&paths.config).unwrap(), b"old");
    assert!(!paths.binary.exists());
    assert!(!temp.join("brand").exists());
    assert!(!temp.join("owned-dry").exists());
    assert!(!txn.backup_dir().exists());

    txn.commit().unwrap();
    assert_eq!(fs::read(&paths.config).unwrap(), b"old");
    assert!(!txn.backup_dir().exists());
}

#[test]
fn create_dir_only_removes_dirs_created_by_transaction() {
    let temp = common::TempDir::new("txn-dirs");
    let paths = paths_for(&temp, Role::Agent);
    fs::create_dir_all(&paths.data_dir).unwrap();
    common::write_file(&paths.data_dir.join("keep"), b"keep", 0o600);
    let new_dir = temp.join("var/lib/rustboard/agent/certs");

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.create_dir(&paths.data_dir, 0o700).unwrap();
    txn.create_dir(&new_dir, 0o700).unwrap();
    assert!(new_dir.is_dir());
    assert_eq!(common::mode_of(&new_dir), 0o700);
    txn.rollback().unwrap();

    assert!(paths.data_dir.is_dir());
    assert!(paths.data_dir.join("keep").is_file());
    assert!(!new_dir.exists());
}

#[test]
fn owned_dir_removes_runtime_files_on_rollback() {
    let temp = common::TempDir::new("txn-owned");
    let paths = paths_for(&temp, Role::Hub);
    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.create_owned_dir(&paths.data_dir, 0o700).unwrap();
    assert_eq!(common::mode_of(&paths.data_dir), 0o700);

    // 模拟服务启动后写入了未经过事务的文件（证书 / SQLite）。
    fs::create_dir_all(paths.data_dir.join("certs")).unwrap();
    common::write_file(&paths.data_dir.join("hub.db"), b"db", 0o600);
    common::write_file(&paths.data_dir.join("certs/server.crt"), b"cert", 0o644);

    txn.rollback().unwrap();
    assert!(!paths.data_dir.exists());
    assert!(!temp.join("var/lib/rustboard").exists());
}

#[test]
fn preexisting_dir_is_never_removed_by_owned_dir_rollback() {
    let temp = common::TempDir::new("txn-owned-existing");
    let paths = paths_for(&temp, Role::Panel);
    fs::create_dir_all(&paths.data_dir).unwrap();
    common::write_file(&paths.data_dir.join("keep.db"), b"keep", 0o600);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.create_owned_dir(&paths.data_dir, 0o700).unwrap();
    txn.write(&paths.data_dir.join("new.crt"), b"new", 0o600)
        .unwrap();
    txn.rollback().unwrap();

    assert!(paths.data_dir.is_dir());
    assert_eq!(fs::read(paths.data_dir.join("keep.db")).unwrap(), b"keep");
    assert!(!paths.data_dir.join("new.crt").exists());
}

#[cfg(unix)]
#[test]
fn owned_dir_replaced_by_symlink_is_not_recursively_deleted() {
    let temp = common::TempDir::new("txn-owned-symlink");
    let paths = paths_for(&temp, Role::Agent);
    let victim = temp.join("victim");
    fs::create_dir_all(&victim).unwrap();
    common::write_file(&victim.join("keep"), b"keep", 0o600);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.create_owned_dir(&paths.data_dir, 0o700).unwrap();
    fs::remove_dir(&paths.data_dir).unwrap();
    std::os::unix::fs::symlink(&victim, &paths.data_dir).unwrap();

    assert!(txn.rollback().is_err());
    assert_eq!(fs::read(victim.join("keep")).unwrap(), b"keep");
}

#[test]
fn remove_backs_up_and_rollback_restores() {
    let temp = common::TempDir::new("txn-remove");
    let paths = paths_for(&temp, Role::Hub);
    common::write_file(&paths.config, b"old", 0o600);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.remove(&paths.config).unwrap();
    assert!(!paths.config.exists());
    txn.rollback().unwrap();
    assert_eq!(fs::read(&paths.config).unwrap(), b"old");
    assert_eq!(common::mode_of(&paths.config), 0o600);
}

#[test]
fn remove_refuses_directories_and_symlinks() {
    let temp = common::TempDir::new("txn-remove-refuse");
    let paths = paths_for(&temp, Role::Hub);
    fs::create_dir_all(&paths.data_dir).unwrap();
    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    assert!(txn.remove(&paths.data_dir).is_err());

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", temp.join("link")).unwrap();
        assert!(txn.remove(&temp.join("link")).is_err());
    }
}

#[test]
fn copy_file_streams_replacement_and_restores_backup() {
    let temp = common::TempDir::new("txn-copy");
    let paths = paths_for(&temp, Role::Hub);
    let source = temp.join("build/rustboard-hub");
    let payload = vec![0x5a_u8; 256 * 1024];
    common::write_file(&source, &payload, 0o755);
    common::write_file(&paths.binary, b"old-binary", 0o755);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.copy_file(&source, &paths.binary, 0o755).unwrap();
    assert_eq!(fs::read(&paths.binary).unwrap(), payload);
    assert_eq!(common::mode_of(&paths.binary), 0o755);
    txn.rollback().unwrap();
    assert_eq!(fs::read(&paths.binary).unwrap(), b"old-binary");
    assert_eq!(common::mode_of(&paths.binary), 0o755);
}

#[test]
fn copy_file_rejects_missing_source_and_symlink_source() {
    let temp = common::TempDir::new("txn-copy-bad");
    let paths = paths_for(&temp, Role::Hub);
    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    assert!(txn
        .copy_file(&temp.join("missing"), &paths.binary, 0o755)
        .is_err());

    #[cfg(unix)]
    {
        common::write_file(&temp.join("real"), b"x", 0o755);
        std::os::unix::fs::symlink(temp.join("real"), temp.join("link")).unwrap();
        assert!(txn
            .copy_file(&temp.join("link"), &paths.binary, 0o755)
            .is_err());
    }
}

#[test]
fn commit_cleans_backup_and_keeps_changes() {
    let temp = common::TempDir::new("txn-commit");
    let paths = paths_for(&temp, Role::Panel);
    common::write_file(&paths.config, b"old", 0o600);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.write(&paths.config, b"new", 0o600).unwrap();
    let backup_dir = txn.backup_dir().to_path_buf();
    assert!(backup_dir.exists());
    txn.commit().unwrap();
    assert_eq!(fs::read(&paths.config).unwrap(), b"new");
    assert!(!backup_dir.exists());
    // commit 后 rollback 是 no-op。
    txn.rollback().unwrap();
    assert_eq!(fs::read(&paths.config).unwrap(), b"new");
}

#[test]
fn drop_rolls_back_uncommitted_transaction() {
    let temp = common::TempDir::new("txn-drop");
    let paths = paths_for(&temp, Role::Agent);
    common::write_file(&paths.config, b"old", 0o600);
    {
        let mut txn = InstallTxn::begin(&paths, false).unwrap();
        txn.write(&paths.config, b"uncommitted", 0o600).unwrap();
        assert_eq!(fs::read(&paths.config).unwrap(), b"uncommitted");
    }
    assert_eq!(fs::read(&paths.config).unwrap(), b"old");
}

#[test]
fn symlink_targets_are_rejected_without_touching_link_target() {
    let temp = common::TempDir::new("txn-symlink");
    let paths = paths_for(&temp, Role::Hub);
    let victim = temp.join("victim");
    common::write_file(&victim, b"victim", 0o600);
    #[cfg(unix)]
    {
        fs::create_dir_all(paths.config.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&victim, &paths.config).unwrap();
    }

    #[cfg(unix)]
    {
        let mut txn = InstallTxn::begin(&paths, false).unwrap();
        assert!(txn.write(&paths.config, b"new", 0o600).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert!(fs::symlink_metadata(&paths.config)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[test]
fn relative_paths_are_rejected_by_all_operations() {
    let temp = common::TempDir::new("txn-relative");
    let paths = paths_for(&temp, Role::Hub);
    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    assert!(txn.write(Path::new("relative"), b"x", 0o600).is_err());
    assert!(txn.create_dir(Path::new("relative"), 0o700).is_err());
    assert!(txn.remove(Path::new("relative")).is_err());
    assert!(txn
        .copy_file(&paths.config, Path::new("relative"), 0o600)
        .is_err());
}

#[test]
fn failed_restore_keeps_backup_dir_and_reports_path() {
    let temp = common::TempDir::new("txn-rollback-failed");
    let paths = paths_for(&temp, Role::Hub);
    common::write_file(&paths.config, b"old", 0o600);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.write(&paths.config, b"new", 0o600).unwrap();
    let backup_dir = txn.backup_dir().to_path_buf();
    assert!(backup_dir.is_dir());

    // 模拟备份被破坏 / 被人工移走：回滚无法恢复，必须保留目录并报出路径。
    for entry in fs::read_dir(&backup_dir).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            fs::remove_file(entry.path()).unwrap();
        }
    }

    let err = txn.rollback().unwrap_err();
    let message = format!("{err:#}");
    let backup_text = backup_dir.display().to_string();
    assert!(message.contains(&backup_text), "{message}");
    assert!(
        format!("{err}").contains(&backup_text),
        "最外层错误也必须带备份路径: {err}"
    );
    assert!(
        backup_dir.is_dir(),
        "回滚失败后备份目录必须保留: {}",
        backup_dir.display()
    );
    // 恢复失败时目标保持本次写入内容，人工可按备份目录处理。
    assert_eq!(fs::read(&paths.config).unwrap(), b"new");
}

#[test]
fn successful_rollback_cleans_backup_dir() {
    let temp = common::TempDir::new("txn-rollback-ok");
    let paths = paths_for(&temp, Role::Panel);
    common::write_file(&paths.config, b"old", 0o600);

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    txn.write(&paths.config, b"new", 0o600).unwrap();
    let backup_dir = txn.backup_dir().to_path_buf();
    txn.rollback().unwrap();

    assert_eq!(fs::read(&paths.config).unwrap(), b"old");
    assert!(!backup_dir.exists(), "全部恢复成功后应清理备份目录");
}

#[cfg(unix)]
#[test]
fn write_rejects_symlink_parent_without_writing_target() {
    use std::os::unix::fs::symlink;

    let temp = common::TempDir::new("txn-symlink-parent");
    let paths = paths_for(&temp, Role::Hub);
    let victim_dir = temp.join("victim");
    fs::create_dir_all(&victim_dir).unwrap();
    let link_dir = temp.join("linked-parent");
    symlink(&victim_dir, &link_dir).unwrap();
    let target = link_dir.join("escaped.toml");

    let mut txn = InstallTxn::begin(&paths, false).unwrap();
    let err = txn.write(&target, b"escaped", 0o600).unwrap_err();
    assert!(format!("{err:#}").contains("符号链接"), "{err:#}");
    assert!(
        !victim_dir.join("escaped.toml").exists(),
        "符号链接父目录未被拒绝，写入逃逸到链接目标"
    );
}
