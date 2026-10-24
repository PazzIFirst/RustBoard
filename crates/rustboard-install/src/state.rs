//! 安装状态：单文件、按角色合并、0600、坏文件必须报错。
//!
//! 状态文件是安装器私有文件，不是用户配置；默认位置
//! `/var/lib/rustboard/install-state.toml`。hub + panel 同机安装时两条记录共存，
//! 每次写入都原子替换整个文件，避免“先清空再写”造成状态丢失。
//!
//! 安全边界：state 是安装器判断“系统上装了什么”的唯一可信来源，读取前必须
//! 确认它是当前 euid 拥有的 0600 普通文件，且路径上没有符号链接祖先；否则
//! 以 root 运行时会读到攻击者控制的文件，后续删除/覆盖操作会作用到错误目标。
//! 解析失败只报告文件损坏，不回显 TOML 原文或行内容（可能含路径/主机名等
//! 敏感信息），由人工检查。

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustboard_common::fsutil;
use serde::{Deserialize, Serialize};

use crate::path_validate::reject_symlink_components;
use crate::Paths;
use crate::Role;

/// 当前安装状态 schema 版本。
pub const INSTALL_STATE_SCHEMA: u32 = 1;

/// 单个角色的安装记录。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleState {
    pub version: String,
    pub config: PathBuf,
    pub data_dir: PathBuf,
    pub unit: PathBuf,
    pub binary: PathBuf,
    pub installed_at_ms: i64,
    pub backup_dir: PathBuf,
}

impl RoleState {
    /// 从路径规划生成记录；`backup_dir` 通常是 [`crate::InstallTxn::backup_dir`]。
    pub fn new(paths: &Paths, version: impl Into<String>, backup_dir: impl Into<PathBuf>) -> Self {
        Self {
            version: version.into(),
            config: paths.config.clone(),
            data_dir: paths.data_dir.clone(),
            unit: paths.unit.clone(),
            binary: paths.binary.clone(),
            installed_at_ms: rustboard_common::util::now_ms(),
            backup_dir: backup_dir.into(),
        }
    }
}

/// 安装状态根结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallState {
    pub schema: u32,
    /// 按角色排序，保证同内容序列化结果稳定。
    pub roles: BTreeMap<Role, RoleState>,
}

impl Default for InstallState {
    fn default() -> Self {
        Self {
            schema: INSTALL_STATE_SCHEMA,
            roles: BTreeMap::new(),
        }
    }
}

impl InstallState {
    /// 空状态（schema = 1）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 读取状态；文件不存在返回空状态，存在但解析失败 / schema 不支持必须报错。
    ///
    /// 读取前依次执行：
    /// 1. 从 `/` 开始拒绝任何符号链接路径组件（父目录也可能是攻击者可控链接）；
    /// 2. `symlink_metadata` 确认目标是当前 euid 拥有的 0600 普通文件；
    /// 3. 以 `O_NOFOLLOW` 打开并再次校验元数据，缩小检查与打开之间的替换窗口。
    ///
    /// 不能静默重建：坏状态意味着安装器对系统现状的判断不可信，继续操作可能
    /// 覆盖未知安装。TOML 解析错误只返回固定文案，**不挂接**底层错误链，避免
    /// 把文件行内容带进日志或终端。
    pub fn load(path: &Path) -> Result<Self> {
        reject_symlink_components(path)
            .with_context(|| format!("检查安装状态路径 {} 失败", path.display()))?;

        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(err).with_context(|| format!("读取安装状态 {} 失败", path.display()));
            }
        };
        check_state_metadata(path, &meta)?;

        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Self::default()),
            Err(err) => {
                return Err(err).with_context(|| format!("读取安装状态 {} 失败", path.display()));
            }
        };
        // open 后重新校验，防止检查与打开之间目标被替换成符号链接 / 其他文件。
        let opened_meta = file
            .metadata()
            .with_context(|| format!("读取安装状态 {} 元数据失败", path.display()))?;
        check_state_metadata(path, &opened_meta)?;

        let mut text = String::new();
        file.read_to_string(&mut text)
            .with_context(|| format!("读取安装状态 {} 失败", path.display()))?;

        let state: InstallState = match toml::from_str(&text) {
            Ok(state) => state,
            Err(_) => {
                // 故意丢弃 toml 错误：它的 Display 会包含行号与原始行内容。
                bail!(
                    "解析安装状态 {} 失败（文件损坏，需人工检查）",
                    path.display()
                );
            }
        };
        if state.schema != INSTALL_STATE_SCHEMA {
            bail!(
                "安装状态 {} 的 schema={}，当前安装器只支持 schema={}",
                path.display(),
                state.schema,
                INSTALL_STATE_SCHEMA
            );
        }
        Ok(state)
    }

    /// 原子写入状态文件并设置 0600；父目录不存在时创建。
    ///
    /// 写入前拒绝符号链接祖先：状态路径通常位于 `/var/lib/rustboard`，如果该
    /// 父目录被替换成链接，root 写入会逃逸到链接目标。目标文件本身由原子
    /// rename 替换，不会跟随已有链接。
    pub fn save(&self, path: &Path) -> Result<()> {
        if self.schema != INSTALL_STATE_SCHEMA {
            bail!(
                "拒绝写入 schema={} 的安装状态（当前只支持 schema={}）",
                self.schema,
                INSTALL_STATE_SCHEMA
            );
        }
        reject_symlink_components(path)
            .with_context(|| format!("检查安装状态路径 {} 失败", path.display()))?;
        let text = toml::to_string_pretty(self).context("序列化安装状态失败")?;
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fsutil::ensure_dir(parent, 0o755)
                    .with_context(|| format!("创建安装状态父目录 {} 失败", parent.display()))?;
            }
        }
        fsutil::atomic_write(path, text.as_bytes(), 0o600)
            .with_context(|| format!("写入安装状态 {} 失败", path.display()))
    }

    /// 读取某角色记录。
    pub fn role(&self, role: Role) -> Option<&RoleState> {
        self.roles.get(&role)
    }

    /// 插入或替换某角色记录，保留其他角色。
    pub fn upsert(&mut self, role: Role, state: RoleState) {
        self.roles.insert(role, state);
    }

    /// 删除某角色记录，返回被删除的记录。
    pub fn remove_role(&mut self, role: Role) -> Option<RoleState> {
        self.roles.remove(&role)
    }
}

/// 校验 state 文件：普通文件、当前 euid 拥有、Unix 权限正好 0600。
fn check_state_metadata(path: &Path, meta: &fs::Metadata) -> Result<()> {
    if meta.file_type().is_symlink() {
        bail!("安装状态 {} 是符号链接，拒绝读取", path.display());
    }
    if !meta.is_file() {
        bail!("安装状态 {} 不是普通文件，拒绝读取", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode() & 0o777;
        if mode != 0o600 {
            bail!(
                "安装状态 {} 权限为 {mode:04o}，state 文件要求正好 0600",
                path.display()
            );
        }
        let uid = meta.uid();
        let euid = crate::system::effective_uid();
        if uid != euid {
            bail!(
                "安装状态 {} 属主 uid={uid}（当前 euid={euid}），拒绝读取他人文件",
                path.display()
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, meta);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_state(role: Role, paths: &Paths, version: &str) -> RoleState {
        RoleState {
            version: version.to_string(),
            config: paths.config.clone(),
            data_dir: paths.data_dir.clone(),
            unit: paths.unit.clone(),
            binary: paths.binary.clone(),
            installed_at_ms: 1_760_000_000_000,
            backup_dir: paths.backup_root.join(format!("{role}-20261024T000000Z")),
        }
    }

    #[test]
    fn role_state_roundtrip_shape() {
        let paths =
            Paths::for_role(Role::Hub, Path::new("/"), crate::PathOverrides::default()).unwrap();
        let state = InstallState {
            schema: INSTALL_STATE_SCHEMA,
            roles: BTreeMap::from([(Role::Hub, sample_state(Role::Hub, &paths, "0.4.2"))]),
        };
        let text = toml::to_string_pretty(&state).unwrap();
        assert!(text.contains("schema = 1"));
        assert!(text.contains("[roles.hub]"));
        assert!(text.contains("backup_dir ="));
        assert!(text.contains("installed_at_ms = 1760000000000"));
        let back: InstallState = toml::from_str(&text).unwrap();
        assert_eq!(back, state);
    }
}
