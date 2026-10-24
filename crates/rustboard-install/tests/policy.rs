//! 安装前缀与卸载路径 allowlist。
//!
//! 前缀测试的临时目录放在 `$HOME` 下（不放 `/tmp`）：`/tmp` 本身是 1777，
//! 会被 `validate_install_prefix` 正确拒绝；`$HOME` 在 root/CI runner 下都由
//! 当前用户拥有且非 sticky，可作为“通过”用例的祖先。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rustboard_install::{validate_install_prefix, validate_managed_path, ManagedPathKind, Role};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// 前缀校验要求从 `/` 到 prefix 的每个已存在组件都由当前 euid 拥有；非 root
/// 环境（GitHub Actions runner）无法构造满足条件的 `/home`/`/tmp` 祖先，跳过
/// 这些 root-only 行为测试。CI 的 root 容器仍会执行。
fn skip_if_not_root() -> bool {
    if rustboard_install::detect_system().euid != 0 {
        eprintln!("跳过 root-only prefix 测试（euid != 0）");
        return true;
    }
    false
}

/// `$HOME` 下的临时目录；Drop 时递归删除。
struct TargetTempDir {
    path: PathBuf,
}

impl TargetTempDir {
    fn new(tag: &str) -> Self {
        let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .expect("prefix 测试需要 HOME 指向当前用户可写目录");
        let root = home.join(".rustboard-install-policy-tests");
        fs::create_dir_all(&root).unwrap();
        set_mode(&root, 0o755);
        let path = root.join(format!("{tag}-{}-{sequence}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        set_mode(&path, 0o755);
        // 去掉 `../../` 等组件，validate_install_prefix 会拒绝非归一化路径。
        let path = fs::canonicalize(&path).unwrap();
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TargetTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

#[test]
fn accepts_root_and_clean_temp_prefix() {
    if skip_if_not_root() {
        return;
    }
    validate_install_prefix(Path::new("/")).unwrap();

    let temp = TargetTempDir::new("prefix-ok");
    validate_install_prefix(temp.path()).unwrap();
    // 不存在的前缀只检查最近祖先。
    validate_install_prefix(&temp.path().join("etc/rustboard")).unwrap();
}

#[cfg(unix)]
#[test]
fn rejects_group_writable_sticky_prefix() {
    if skip_if_not_root() {
        return;
    }
    let temp = TargetTempDir::new("prefix-1777");
    let sticky = temp.path().join("sticky");
    fs::create_dir(&sticky).unwrap();
    set_mode(&sticky, 0o1777);
    let err = validate_install_prefix(&sticky).unwrap_err();
    assert!(format!("{err:#}").contains("group/other"), "{err:#}");
    assert!(validate_install_prefix(&sticky.join("child")).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_prefix_and_ancestor() {
    if skip_if_not_root() {
        return;
    }
    use std::os::unix::fs::symlink;

    let temp = TargetTempDir::new("prefix-symlink");
    let real = temp.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = temp.path().join("link");
    symlink(&real, &link).unwrap();

    let err = validate_install_prefix(&link).unwrap_err();
    assert!(format!("{err:#}").contains("符号链接"), "{err:#}");
    assert!(validate_install_prefix(&link.join("child")).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_non_directory_prefix_component() {
    if skip_if_not_root() {
        return;
    }
    let temp = TargetTempDir::new("prefix-file");
    let file = temp.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert!(validate_install_prefix(&file).is_err());
    assert!(validate_install_prefix(&file.join("child")).is_err());
}

#[test]
fn rejects_non_normalized_or_injectable_prefixes() {
    for prefix in [
        "",
        "relative",
        "/opt/../etc",
        "/opt/./rb",
        "/opt//rb",
        "/opt/rb/",
        "/opt/rb$",
        "/opt/rb%",
        "/opt/rb\"",
        "/opt/rb'",
        "/opt/rb\\",
        "/opt/rb\n",
        "/opt/rb\u{7}",
    ] {
        assert!(
            validate_install_prefix(Path::new(prefix)).is_err(),
            "{prefix:?} 应被拒绝"
        );
    }
}

#[test]
fn prefixed_managed_paths_stay_under_prefix() {
    if skip_if_not_root() {
        return;
    }
    let prefix = Path::new("/opt/P");
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/P/etc/rustboard/hub.toml"),
        ManagedPathKind::Config,
    )
    .unwrap();
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/P/var/lib/rustboard/hub"),
        ManagedPathKind::Data,
    )
    .unwrap();
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/P/usr/local/bin/rustboard-hub"),
        ManagedPathKind::Binary,
    )
    .unwrap();
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/P/etc/systemd/system/rustboard-hub.service"),
        ManagedPathKind::Unit,
    )
    .unwrap();
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/run/systemd/system/rustboard-hub.service"),
        ManagedPathKind::Unit,
    )
    .unwrap();

    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/other/hub.toml"),
        ManagedPathKind::Config,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/P-other/hub.toml"),
        ManagedPathKind::Config,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/P/../opt/other/hub.toml"),
        ManagedPathKind::Config,
    )
    .is_err());
    assert!(validate_managed_path(Role::Hub, prefix, prefix, ManagedPathKind::Data,).is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/P/etc/systemd/system/evil.service"),
        ManagedPathKind::Unit,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/run/systemd/system/rustboard-agent.service"),
        ManagedPathKind::Unit,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/evil.service"),
        ManagedPathKind::Unit,
    )
    .is_err());
}

#[test]
fn root_prefix_managed_paths_use_fixed_roots() {
    let prefix = Path::new("/");
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/etc/rustboard/hub.toml"),
        ManagedPathKind::Config,
    )
    .unwrap();
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/var/lib/rustboard/hub"),
        ManagedPathKind::Data,
    )
    .unwrap();
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/usr/local/bin/rustboard-hub"),
        ManagedPathKind::Binary,
    )
    .unwrap();
    validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/run/systemd/system/rustboard-hub.service"),
        ManagedPathKind::Unit,
    )
    .unwrap();

    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/etc/shadow"),
        ManagedPathKind::Config,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/etc/rustboardx/hub.toml"),
        ManagedPathKind::Config,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/var/lib/rustboard-other/hub"),
        ManagedPathKind::Data,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/usr/local/bin/rustboard-agent"),
        ManagedPathKind::Binary,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/opt/evil.service"),
        ManagedPathKind::Unit,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/run/systemd/system/rustboard-agent.service"),
        ManagedPathKind::Unit,
    )
    .is_err());
    assert!(validate_managed_path(
        Role::Hub,
        prefix,
        Path::new("/etc/systemd/system/ssh.service"),
        ManagedPathKind::Unit,
    )
    .is_err());
}

#[test]
fn managed_path_never_targets_system_roots() {
    for path in ["/", "/etc", "/usr", "/var", "/home", "/opt"] {
        for kind in [
            ManagedPathKind::Config,
            ManagedPathKind::Data,
            ManagedPathKind::Unit,
            ManagedPathKind::Binary,
        ] {
            assert!(
                validate_managed_path(Role::Hub, Path::new("/"), Path::new(path), kind).is_err(),
                "{path} ({kind:?}) 应被拒绝"
            );
        }
    }
    for path in ["relative", "/opt/P/../etc"] {
        assert!(validate_managed_path(
            Role::Hub,
            Path::new("/opt/P"),
            Path::new(path),
            ManagedPathKind::Config,
        )
        .is_err());
    }
}
