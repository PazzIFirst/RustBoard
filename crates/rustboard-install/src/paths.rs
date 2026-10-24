//! 安装路径规划。

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::path_validate::normalize_absolute;
use crate::Role;

/// 一次安装涉及的全部路径。
///
/// 所有字段都是绝对路径；由 [`Paths::for_role`] 保证。`prefix` 为测试/容器用的
/// 安装前缀，生产环境为 `/`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub prefix: PathBuf,
    pub config: PathBuf,
    pub data_dir: PathBuf,
    pub unit: PathBuf,
    pub binary: PathBuf,
    pub state: PathBuf,
    pub backup_root: PathBuf,
}

/// 路径覆盖项。只覆盖显式给出的项，其余仍按 prefix 推导。
///
/// `config` / `data_dir` 允许落在 prefix 外（容器挂载等场景）；`unit_dir` /
/// `bin_dir` 是目录，安装器会在其中写入 `<role>.service` / `rustboard-<role>`。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathOverrides {
    pub config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub unit_dir: Option<PathBuf>,
    pub bin_dir: Option<PathBuf>,
}

impl Paths {
    /// 按角色和前缀推导安装路径。
    ///
    /// `prefix = "/"` 时使用生产默认路径：
    ///
    /// | 项 | 路径 |
    /// |---|---|
    /// | config | `/etc/rustboard/<role>.toml` |
    /// | data | `/var/lib/rustboard/<role>` |
    /// | unit | `/etc/systemd/system/rustboard-<role>.service` |
    /// | binary | `/usr/local/bin/rustboard-<role>` |
    /// | state | `/var/lib/rustboard/install-state.toml` |
    ///
    /// 非根 prefix 把同样的相对路径拼到 prefix 下。prefix、override 都会拒绝
    /// 空路径、相对路径、`..` 组件与 Windows 前缀。
    pub fn for_role(role: Role, prefix: &Path, overrides: PathOverrides) -> Result<Self> {
        let prefix = normalize_absolute(prefix, "安装前缀")?;

        let config = match overrides.config {
            Some(path) => normalize_absolute(&path, "配置路径")?,
            None => under_prefix(&prefix, &format!("etc/rustboard/{}", role.config_name())),
        };
        let data_dir = match overrides.data_dir {
            Some(path) => normalize_absolute(&path, "数据目录")?,
            None => under_prefix(&prefix, &format!("var/lib/rustboard/{}", role.as_str())),
        };
        let unit_dir = match overrides.unit_dir {
            Some(path) => normalize_absolute(&path, "unit 目录")?,
            None => under_prefix(&prefix, "etc/systemd/system"),
        };
        let bin_dir = match overrides.bin_dir {
            Some(path) => normalize_absolute(&path, "二进制目录")?,
            None => under_prefix(&prefix, "usr/local/bin"),
        };

        let unit = unit_dir.join(role.unit_name());
        let binary = bin_dir.join(role.binary_name());
        let state = under_prefix(&prefix, "var/lib/rustboard/install-state.toml");
        let backup_root = under_prefix(&prefix, "var/lib/rustboard/backups");

        Ok(Self {
            prefix,
            config,
            data_dir,
            unit,
            binary,
            state,
            backup_root,
        })
    }

    /// 是否使用生产根 prefix（`/`）。
    pub fn is_root_prefix(&self) -> bool {
        self.prefix == Path::new("/")
    }
}

/// 把相对路径拼到 prefix 下；根 prefix 保持绝对路径而不是生成相对路径。
fn under_prefix(prefix: &Path, relative: &str) -> PathBuf {
    if prefix == Path::new("/") {
        Path::new("/").join(relative)
    } else {
        prefix.join(relative)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_prefix_uses_production_paths() {
        for role in Role::ALL {
            let paths = Paths::for_role(role, Path::new("/"), PathOverrides::default()).unwrap();
            assert!(paths.is_root_prefix());
            assert_eq!(
                paths.config,
                PathBuf::from(format!("/etc/rustboard/{}", role.config_name()))
            );
            assert_eq!(
                paths.data_dir,
                PathBuf::from(format!("/var/lib/rustboard/{role}"))
            );
            assert_eq!(
                paths.unit,
                PathBuf::from(format!("/etc/systemd/system/{}", role.unit_name()))
            );
            assert_eq!(
                paths.binary,
                PathBuf::from(format!("/usr/local/bin/{}", role.binary_name()))
            );
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
    fn prefixed_paths_are_under_prefix() {
        let paths = Paths::for_role(
            Role::Hub,
            Path::new("/tmp/rb-install/"),
            PathOverrides::default(),
        )
        .unwrap();
        assert_eq!(paths.prefix, PathBuf::from("/tmp/rb-install"));
        assert_eq!(
            paths.config,
            PathBuf::from("/tmp/rb-install/etc/rustboard/hub.toml")
        );
        assert_eq!(
            paths.data_dir,
            PathBuf::from("/tmp/rb-install/var/lib/rustboard/hub")
        );
        assert_eq!(
            paths.unit,
            PathBuf::from("/tmp/rb-install/etc/systemd/system/rustboard-hub.service")
        );
        assert_eq!(
            paths.binary,
            PathBuf::from("/tmp/rb-install/usr/local/bin/rustboard-hub")
        );
        assert!(!paths.is_root_prefix());
    }

    #[test]
    fn overrides_replace_individual_items() {
        let paths = Paths::for_role(
            Role::Panel,
            Path::new("/opt/rb"),
            PathOverrides {
                config: Some(PathBuf::from("/etc/custom/panel.toml")),
                data_dir: Some(PathBuf::from("/srv/panel-data")),
                unit_dir: Some(PathBuf::from("/run/systemd/system")),
                bin_dir: Some(PathBuf::from("/opt/bin")),
            },
        )
        .unwrap();
        assert_eq!(paths.config, PathBuf::from("/etc/custom/panel.toml"));
        assert_eq!(paths.data_dir, PathBuf::from("/srv/panel-data"));
        assert_eq!(
            paths.unit,
            PathBuf::from("/run/systemd/system/rustboard-panel.service")
        );
        assert_eq!(paths.binary, PathBuf::from("/opt/bin/rustboard-panel"));
        // state 与 backup_root 始终跟着 prefix，不跟 data_dir override 走。
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
    fn rejects_relative_empty_and_parent_prefixes() {
        for prefix in ["", "relative", "../escape", "/tmp/../etc"] {
            assert!(
                Paths::for_role(Role::Hub, Path::new(prefix), PathOverrides::default()).is_err(),
                "{prefix:?} 应被拒绝"
            );
        }
    }

    #[test]
    fn rejects_bad_overrides() {
        for override_path in ["", "relative/path", "/tmp/../etc"] {
            let overrides = PathOverrides {
                config: Some(PathBuf::from(override_path)),
                ..PathOverrides::default()
            };
            assert!(
                Paths::for_role(Role::Hub, Path::new("/"), overrides).is_err(),
                "config override {override_path:?} 应被拒绝"
            );

            let overrides = PathOverrides {
                data_dir: Some(PathBuf::from(override_path)),
                ..PathOverrides::default()
            };
            assert!(
                Paths::for_role(Role::Hub, Path::new("/"), overrides).is_err(),
                "data override {override_path:?} 应被拒绝"
            );

            let overrides = PathOverrides {
                unit_dir: Some(PathBuf::from(override_path)),
                ..PathOverrides::default()
            };
            assert!(
                Paths::for_role(Role::Hub, Path::new("/"), overrides).is_err(),
                "unit_dir override {override_path:?} 应被拒绝"
            );

            let overrides = PathOverrides {
                bin_dir: Some(PathBuf::from(override_path)),
                ..PathOverrides::default()
            };
            assert!(
                Paths::for_role(Role::Hub, Path::new("/"), overrides).is_err(),
                "bin_dir override {override_path:?} 应被拒绝"
            );
        }
    }
}
