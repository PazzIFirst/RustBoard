//! 安装状态：合并、0600、坏文件报错。

mod common;

use std::fs;
use std::path::Path;

use rustboard_install::{
    InstallState, PathOverrides, Paths, Role, RoleState, INSTALL_STATE_SCHEMA,
};

fn role_state(role: Role, prefix: &Path, version: &str) -> RoleState {
    let paths = Paths::for_role(role, prefix, PathOverrides::default()).unwrap();
    RoleState::new(
        &paths,
        version,
        paths.backup_root.join(format!("{role}-backup")),
    )
}

#[test]
fn missing_state_is_empty_schema_one() {
    let temp = common::TempDir::new("state-missing");
    let state = InstallState::load(&temp.join("missing.toml")).unwrap();
    assert_eq!(state.schema, INSTALL_STATE_SCHEMA);
    assert!(state.roles.is_empty());
}

#[test]
fn hub_and_panel_records_merge_in_one_file() {
    let temp = common::TempDir::new("state-merge");
    let state_path = temp.join("install-state.toml");
    let prefix = Path::new("/opt/rb");

    let mut state = InstallState::new();
    state.upsert(Role::Hub, role_state(Role::Hub, prefix, "0.4.2"));
    state.save(&state_path).unwrap();
    assert_eq!(common::mode_of(&state_path), 0o600);

    let mut loaded = InstallState::load(&state_path).unwrap();
    assert!(loaded.role(Role::Hub).is_some());
    assert!(loaded.role(Role::Panel).is_none());
    loaded.upsert(Role::Panel, role_state(Role::Panel, prefix, "0.4.2"));
    loaded.save(&state_path).unwrap();

    let loaded = InstallState::load(&state_path).unwrap();
    assert_eq!(loaded.roles.len(), 2);
    assert_eq!(loaded.role(Role::Hub).unwrap().version, "0.4.2");
    assert_eq!(
        loaded.role(Role::Panel).unwrap().config,
        prefix.join("etc/rustboard/panel.toml")
    );
    assert_eq!(
        loaded.role(Role::Hub).unwrap().data_dir,
        prefix.join("var/lib/rustboard/hub")
    );
    assert_eq!(
        loaded.role(Role::Hub).unwrap().config,
        prefix.join("etc/rustboard/hub.toml")
    );

    let text = fs::read_to_string(&state_path).unwrap();
    assert!(text.contains("schema = 1"));
    assert!(text.contains("[roles.hub]"));
    assert!(text.contains("[roles.panel]"));

    let mut loaded = InstallState::load(&state_path).unwrap();
    assert!(loaded.remove_role(Role::Hub).is_some());
    assert!(loaded.role(Role::Panel).is_some());
}

#[test]
fn corrupt_toml_fails_instead_of_rebuilding() {
    let temp = common::TempDir::new("state-corrupt");
    let state_path = temp.join("install-state.toml");
    common::write_file(&state_path, b"schema = 1\n[roles.hub\n", 0o600);
    let err = InstallState::load(&state_path).unwrap_err();
    assert!(format!("{err:#}").contains("解析安装状态"), "{err:#}");
    // 坏文件不能被自动覆盖成空状态。
    assert_eq!(fs::read(&state_path).unwrap(), b"schema = 1\n[roles.hub\n");
}

#[test]
fn unsupported_schema_and_role_are_rejected() {
    let temp = common::TempDir::new("state-schema");
    let state_path = temp.join("install-state.toml");

    common::write_file(&state_path, b"schema = 2\n[roles]\n", 0o600);
    let err = InstallState::load(&state_path).unwrap_err();
    assert!(format!("{err:#}").contains("schema=2"), "{err:#}");

    common::write_file(
        &state_path,
        b"schema = 1\n[roles.mystery]\nversion = \"1\"\n",
        0o600,
    );
    assert!(InstallState::load(&state_path).is_err());
}

#[test]
fn save_rejects_wrong_schema() {
    let temp = common::TempDir::new("state-save-schema");
    let mut state = InstallState::new();
    state.schema = 99;
    let err = state.save(&temp.join("state.toml")).unwrap_err();
    assert!(format!("{err:#}").contains("schema=99"), "{err:#}");
}

#[test]
fn rejects_state_not_exactly_0600() {
    let temp = common::TempDir::new("state-mode");
    let state_path = temp.join("install-state.toml");
    InstallState::new().save(&state_path).unwrap();
    common::set_mode(&state_path, 0o644);
    let err = InstallState::load(&state_path).unwrap_err();
    assert!(format!("{err:#}").contains("0600"), "{err:#}");
}

#[cfg(unix)]
#[test]
fn rejects_symlink_state_even_with_valid_target() {
    use std::os::unix::fs::symlink;

    let temp = common::TempDir::new("state-symlink");
    let real = temp.join("real-state.toml");
    InstallState::new().save(&real).unwrap();
    let link = temp.join("link-state.toml");
    symlink(&real, &link).unwrap();

    let err = InstallState::load(&link).unwrap_err();
    assert!(format!("{err:#}").contains("符号链接"), "{err:#}");
}

#[cfg(unix)]
#[test]
fn rejects_symlink_ancestor_for_load_and_save() {
    use std::os::unix::fs::symlink;

    let temp = common::TempDir::new("state-symlink-parent");
    let real_dir = temp.join("real");
    fs::create_dir_all(&real_dir).unwrap();
    InstallState::new()
        .save(&real_dir.join("install-state.toml"))
        .unwrap();
    let link_dir = temp.join("linked");
    symlink(&real_dir, &link_dir).unwrap();

    let err = InstallState::load(&link_dir.join("install-state.toml")).unwrap_err();
    assert!(format!("{err:#}").contains("符号链接"), "{err:#}");

    let err = InstallState::new()
        .save(&link_dir.join("new-state.toml"))
        .unwrap_err();
    assert!(format!("{err:#}").contains("符号链接"), "{err:#}");
    assert!(!real_dir.join("new-state.toml").exists());
}

#[test]
fn parse_error_never_echoes_state_contents() {
    let temp = common::TempDir::new("state-secret");
    let state_path = temp.join("install-state.toml");
    let secret = "SUPER_SECRET_TOKEN_9f3a";
    let contents = format!("schema = 1\nadmin_token = \"{secret}\"\n[roles.hub\n");
    common::write_file(&state_path, contents.as_bytes(), 0o600);

    let err = InstallState::load(&state_path).unwrap_err();
    let message = format!("{err:#}");
    assert!(message.contains("解析安装状态"), "{message}");
    assert!(
        !message.contains(secret),
        "错误信息泄露了 state 内容: {message}"
    );
    assert!(!message.contains("admin_token"), "{message}");
    assert!(!message.contains("roles.hub"), "{message}");
}
