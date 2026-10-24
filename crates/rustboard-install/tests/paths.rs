//! 路径规划：生产默认、prefix 派生、override 与拒绝规则。

mod common;

use std::path::{Path, PathBuf};

use rustboard_install::{PathOverrides, Paths, Role};

#[test]
fn default_paths_are_production_paths() {
    let expected = [
        (
            Role::Hub,
            "/etc/rustboard/hub.toml",
            "/var/lib/rustboard/hub",
            "/etc/systemd/system/rustboard-hub.service",
            "/usr/local/bin/rustboard-hub",
        ),
        (
            Role::Agent,
            "/etc/rustboard/agent.toml",
            "/var/lib/rustboard/agent",
            "/etc/systemd/system/rustboard-agent.service",
            "/usr/local/bin/rustboard-agent",
        ),
        (
            Role::Panel,
            "/etc/rustboard/panel.toml",
            "/var/lib/rustboard/panel",
            "/etc/systemd/system/rustboard-panel.service",
            "/usr/local/bin/rustboard-panel",
        ),
    ];
    for (role, config, data, unit, binary) in expected {
        let paths = Paths::for_role(role, Path::new("/"), PathOverrides::default()).unwrap();
        assert!(paths.is_root_prefix());
        assert_eq!(paths.config, PathBuf::from(config));
        assert_eq!(paths.data_dir, PathBuf::from(data));
        assert_eq!(paths.unit, PathBuf::from(unit));
        assert_eq!(paths.binary, PathBuf::from(binary));
        assert_eq!(
            paths.state,
            PathBuf::from("/var/lib/rustboard/install-state.toml")
        );
        assert_eq!(
            paths.backup_root,
            PathBuf::from("/var/lib/rustboard/backups")
        );
    }
}

#[test]
fn prefix_derives_all_paths_under_it() {
    let temp = common::TempDir::new("paths-prefix");
    let prefix = temp.path();
    let paths = Paths::for_role(Role::Hub, prefix, PathOverrides::default()).unwrap();
    assert_eq!(paths.prefix, prefix);
    assert!(!paths.is_root_prefix());
    assert_eq!(paths.config, prefix.join("etc/rustboard/hub.toml"));
    assert_eq!(paths.data_dir, prefix.join("var/lib/rustboard/hub"));
    assert_eq!(
        paths.unit,
        prefix.join("etc/systemd/system/rustboard-hub.service")
    );
    assert_eq!(paths.binary, prefix.join("usr/local/bin/rustboard-hub"));
    assert_eq!(
        paths.state,
        prefix.join("var/lib/rustboard/install-state.toml")
    );
    assert_eq!(paths.backup_root, prefix.join("var/lib/rustboard/backups"));
}

#[test]
fn overrides_are_absolute_and_individual() {
    let paths = Paths::for_role(
        Role::Agent,
        Path::new("/opt/rb"),
        PathOverrides {
            config: Some(PathBuf::from("/etc/custom-agent.toml")),
            data_dir: Some(PathBuf::from("/srv/agent-data")),
            unit_dir: Some(PathBuf::from("/run/systemd/system")),
            bin_dir: Some(PathBuf::from("/usr/bin")),
        },
    )
    .unwrap();
    assert_eq!(paths.config, PathBuf::from("/etc/custom-agent.toml"));
    assert_eq!(paths.data_dir, PathBuf::from("/srv/agent-data"));
    assert_eq!(
        paths.unit,
        PathBuf::from("/run/systemd/system/rustboard-agent.service")
    );
    assert_eq!(paths.binary, PathBuf::from("/usr/bin/rustboard-agent"));
    // state/backup 只跟 prefix 走，避免 data_dir 覆盖后状态散落。
    assert_eq!(
        paths.state,
        PathBuf::from("/opt/rb/var/lib/rustboard/install-state.toml")
    );
    assert_eq!(
        paths.backup_root,
        PathBuf::from("/opt/rb/var/lib/rustboard/backups")
    );
}

#[test]
fn relative_empty_and_parent_prefixes_are_rejected() {
    for prefix in [
        "",
        "relative",
        "../rustboard",
        "/tmp/../etc",
        "C:\\rustboard",
    ] {
        let result = Paths::for_role(Role::Hub, Path::new(prefix), PathOverrides::default());
        assert!(result.is_err(), "prefix {prefix:?} 应被拒绝");
    }
}

#[test]
fn relative_or_parent_overrides_are_rejected() {
    for value in ["", "relative", "../x", "/tmp/../etc"] {
        for field in ["config", "data_dir", "unit_dir", "bin_dir"] {
            let mut overrides = PathOverrides::default();
            match field {
                "config" => overrides.config = Some(PathBuf::from(value)),
                "data_dir" => overrides.data_dir = Some(PathBuf::from(value)),
                "unit_dir" => overrides.unit_dir = Some(PathBuf::from(value)),
                "bin_dir" => overrides.bin_dir = Some(PathBuf::from(value)),
                _ => unreachable!(),
            }
            assert!(
                Paths::for_role(Role::Hub, Path::new("/"), overrides).is_err(),
                "{field} = {value:?} 应被拒绝"
            );
        }
    }
}
