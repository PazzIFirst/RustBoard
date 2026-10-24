//! 私有文件读取：拒绝符号链接、要求 0600、限制大小。

mod common;

use rustboard_install::read_private_file;

#[test]
fn reads_0600_regular_file() {
    let temp = common::TempDir::new("files-ok");
    let path = temp.join("token");
    common::write_file(&path, b"secret-token\n", 0o600);
    assert_eq!(read_private_file(&path, 1024).unwrap(), b"secret-token\n");
}

#[test]
fn rejects_group_or_other_accessible_file() {
    let temp = common::TempDir::new("files-mode");
    let path = temp.join("token");
    for mode in [0o644, 0o640, 0o604, 0o400, 0o700] {
        common::write_file(&path, b"secret", mode);
        let err = read_private_file(&path, 1024).unwrap_err();
        assert!(
            format!("{err:#}").contains("0600"),
            "mode {mode:04o}: {err:#}"
        );
    }
}

#[test]
fn rejects_symlink() {
    let temp = common::TempDir::new("files-symlink");
    let target = temp.join("real");
    common::write_file(&target, b"secret", 0o600);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, temp.join("link")).unwrap();
        let err = read_private_file(&temp.join("link"), 1024).unwrap_err();
        assert!(format!("{err:#}").contains("符号链接"), "{err:#}");
    }
}

#[test]
fn rejects_oversized_file_without_truncating() {
    let temp = common::TempDir::new("files-size");
    let path = temp.join("token");
    common::write_file(&path, b"1234567890", 0o600);
    let err = read_private_file(&path, 4).unwrap_err();
    assert!(format!("{err:#}").contains("上限"), "{err:#}");
    assert_eq!(read_private_file(&path, 10).unwrap(), b"1234567890");
}

#[test]
fn rejects_directory_and_missing_file() {
    let temp = common::TempDir::new("files-bad");
    assert!(read_private_file(temp.path(), 1024).is_err());
    assert!(read_private_file(&temp.join("missing"), 1024).is_err());
}
