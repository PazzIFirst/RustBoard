//! 安装前缀与卸载路径的安全策略。
//!
//! 安装器以 root 运行，`--prefix` 和 `uninstall` 的目标路径都可能来自命令行或
//! state 文件。这里集中做两道 allowlist：
//!
//! 1. [`validate_install_prefix`]：只接受“从 `/` 到 prefix 的每个已存在组件都由
//!    当前 euid 拥有、且 group/other 不可写、无 sticky 位”的绝对路径。`/tmp`、
//!    `/var/tmp`、`/dev/shm` 以及所有 1777 目录因此被拒绝——这些目录里的普通
//!    用户可以预置符号链接，让 root 安装过程写入逃逸或覆盖任意文件。
//! 2. [`validate_managed_path`]：卸载 / 升级只允许删除固定类别、固定根之下的
//!    路径，禁止把 `/`、`/etc`、`/usr`、`/var`、`/home`、`/opt` 等系统目录本身
//!    交给删除流程。
//!
//! 两个函数只做路径字符串与目录元数据检查，**不**检查目标文件本身的类型和
//! 符号链接；调用方在真正删除前仍须用 `symlink_metadata` 拒绝目录 / 链接。

use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::path_validate::normalize_absolute;
use crate::service::is_systemd_unit_dir;
use crate::Role;

/// 安装前缀中禁止出现的字符：`$` / `%` 会被 systemd 展开，引号与反斜杠会与
/// unit / shell 的转义规则冲突。
const FORBIDDEN_PREFIX_CHARS: &[char] = &['$', '%', '"', '\'', '\\'];

/// 任何 kind 都不得作为“待删除项”的系统目录本身。
///
/// 这里只列通用系统目录；`/etc/rustboard`、`/var/lib/rustboard` 这类应用目录
/// 由下面的类别 allowlist 管理，不在此列。
const PROTECTED_SYSTEM_PATHS: &[&str] = &[
    "/",
    "/bin",
    "/boot",
    "/dev",
    "/etc",
    "/etc/systemd",
    "/etc/systemd/system",
    "/home",
    "/lib",
    "/lib64",
    "/media",
    "/mnt",
    "/opt",
    "/proc",
    "/root",
    "/run",
    "/sbin",
    "/srv",
    "/sys",
    "/tmp",
    "/usr",
    "/usr/lib",
    "/usr/lib/systemd",
    "/usr/lib/systemd/system",
    "/usr/local",
    "/usr/local/bin",
    "/usr/local/lib",
    "/usr/local/lib/systemd",
    "/usr/local/lib/systemd/system",
    "/usr/local/share",
    "/usr/local/share/systemd",
    "/usr/local/share/systemd/system",
    "/var",
    "/var/lib",
];

/// 卸载 / 升级时可删除的路径类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagedPathKind {
    Config,
    Data,
    Unit,
    Binary,
}

/// 校验安装前缀可作为 root 安装根。
///
/// 规则：
/// - 必须是绝对路径；拒绝空、`..`、`.`、重复分隔符与结尾 `/`（`/` 本身除外）；
/// - 拒绝控制字符、`$`、`%`、`"`、`'`、`\`（systemd / shell 注入与转义歧义）；
/// - 从 `/` 开始检查已存在组件：符号链接、非目录、非当前 euid 拥有、
///   group/other 可写（`mode & 0o022 != 0`）或带 sticky 位（`mode & 0o1000 != 0`）
///   一律拒绝；`/` 本身跳过；
/// - prefix 不存在时只检查到最近一个已存在祖先。
///
/// 注意：这不是完整的 TOCTOU 防护。校验与后续写入之间路径仍可能被替换，因此
/// 安装器要求 prefix 的已有组件不可被其他用户改写；再配合事务层逐个操作拒绝
/// 符号链接组件，覆盖“父目录被换成链接”的主要逃逸路径。
pub fn validate_install_prefix(prefix: &Path) -> Result<()> {
    let text = prefix.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "安装前缀不是有效 UTF-8，无法用于 systemd unit: {}",
            prefix.display()
        )
    })?;
    if text.is_empty() {
        bail!("安装前缀不能为空");
    }
    if !text.starts_with('/') {
        bail!("安装前缀必须是绝对路径: {}", prefix.display());
    }
    if text.len() > 1 && text.ends_with('/') {
        bail!("安装前缀不能以 / 结尾: {text:?}");
    }
    if text.contains("//") {
        bail!("安装前缀不能包含重复分隔符: {text:?}");
    }
    if text.split('/').any(|component| component == ".") {
        bail!("安装前缀不能包含 `.` 组件: {text:?}");
    }
    if let Some(ch) = text.chars().find(|ch| ch.is_control()) {
        bail!("安装前缀不能包含控制字符 {ch:?}: {text:?}");
    }
    if let Some(ch) = text.chars().find(|ch| FORBIDDEN_PREFIX_CHARS.contains(ch)) {
        bail!("安装前缀不能包含 `{ch}`（systemd / shell 转义歧义）: {text:?}");
    }

    let normalized = normalize_absolute(prefix, "安装前缀")?;
    if normalized == Path::new("/") {
        return Ok(());
    }

    let mut current = PathBuf::from("/");
    for component in normalized.components() {
        match component {
            Component::RootDir => {
                // `/` 由系统拥有，按需求跳过元数据检查。
            }
            Component::Normal(part) => {
                current.push(part);
                let meta = match std::fs::symlink_metadata(&current) {
                    Ok(meta) => meta,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
                    Err(err) => {
                        return Err(err).with_context(|| {
                            format!("检查安装前缀组件 {} 失败", current.display())
                        });
                    }
                };
                if meta.file_type().is_symlink() {
                    bail!(
                        "安装前缀 {} 的组件 {} 是符号链接，拒绝安装",
                        normalized.display(),
                        current.display()
                    );
                }
                if !meta.is_dir() {
                    bail!(
                        "安装前缀 {} 的组件 {} 不是目录",
                        normalized.display(),
                        current.display()
                    );
                }
                check_prefix_dir(&meta, &current)?;
            }
            Component::Prefix(_) | Component::CurDir | Component::ParentDir => {
                bail!("安装前缀必须是归一化的绝对路径: {}", prefix.display());
            }
        }
    }
    Ok(())
}

/// 校验单个已存在的 prefix 目录组件：属主、group/other 写位与 sticky 位。
fn check_prefix_dir(meta: &std::fs::Metadata, path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = meta.mode();
        let euid = crate::system::effective_uid();
        // 允许 root 拥有的祖先目录（常见 `/home`、`/opt` 0755）：root 本来
        // 就可以替换这些路径，普通用户安装在其下不会因此获得额外权限。其他
        // 非当前 euid 的属主仍拒绝，避免在他人可控目录中落安装文件。
        if meta.uid() != euid && meta.uid() != 0 {
            bail!(
                "安装前缀组件 {} 属主 uid={}（当前 euid={euid}），拒绝使用他人拥有的路径",
                path.display(),
                meta.uid()
            );
        }
        if mode & 0o022 != 0 {
            bail!(
                "安装前缀组件 {} 权限为 {:04o}，group/other 可写，拒绝安装",
                path.display(),
                mode & 0o7777
            );
        }
        if mode & 0o1000 != 0 {
            bail!(
                "安装前缀组件 {} 带 sticky 位（{:04o}），拒绝安装",
                path.display(),
                mode & 0o7777
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (meta, path);
    }
    Ok(())
}

/// 校验卸载 / 升级要删除的路径在 allowlist 内。
///
/// - `prefix != "/"` 时，Config / Data / Binary 必须位于 prefix 之下（组件级
///   `Path::starts_with`）；Unit 的父目录必须是 systemd unit 目录，或 unit 位于
///   prefix 之下；
/// - `prefix == "/"` 时，Config 必须在 `/etc/rustboard` 下，Data 必须在
///   `/var/lib/rustboard` 下，Binary 必须精确等于 `/usr/local/bin/{role}`，
///   Unit 的父目录必须是 systemd unit 目录；
/// - 两种 prefix 下 Unit 的文件名都必须精确等于 `rustboard-<role>.service`，
///   防止伪造 state 把 unit 指向同目录下的其他服务（例如 `ssh.service`）；
/// - 所有 kind 都拒绝系统目录本身、`/` 以及路径等于 prefix 的情况。
///
/// 调用方仍需自行拒绝符号链接、目录等非预期类型；本函数不访问目标文件。
pub fn validate_managed_path(
    role: Role,
    prefix: &Path,
    path: &Path,
    kind: ManagedPathKind,
) -> Result<()> {
    let prefix = normalize_absolute(prefix, "安装前缀")?;
    let path = normalize_absolute(path, "卸载路径")?;

    if path == Path::new("/") {
        bail!("拒绝删除系统根目录 /");
    }
    if path == prefix {
        bail!("拒绝删除安装前缀本身: {}", path.display());
    }
    if PROTECTED_SYSTEM_PATHS
        .iter()
        .any(|protected| path == Path::new(protected))
    {
        bail!("拒绝删除系统目录本身: {}", path.display());
    }

    if prefix == Path::new("/") {
        match kind {
            ManagedPathKind::Config => {
                if !path.starts_with("/etc/rustboard") {
                    bail!(
                        "root prefix 下配置路径必须位于 /etc/rustboard 下: {}",
                        path.display()
                    );
                }
            }
            ManagedPathKind::Data => {
                if !path.starts_with("/var/lib/rustboard") {
                    bail!(
                        "root prefix 下数据路径必须位于 /var/lib/rustboard 下: {}",
                        path.display()
                    );
                }
            }
            ManagedPathKind::Binary => {
                let expected = Path::new("/usr/local/bin").join(role.binary_name());
                if path != expected {
                    bail!(
                        "root prefix 下二进制路径必须精确为 {}: {}",
                        expected.display(),
                        path.display()
                    );
                }
            }
            ManagedPathKind::Unit => {
                check_unit_file_name(role, &path)?;
                let parent = path
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("unit 路径缺少父目录: {}", path.display()))?;
                if !is_systemd_unit_dir(parent) {
                    bail!(
                        "root prefix 下 unit 路径必须位于 systemd unit 目录: {}",
                        path.display()
                    );
                }
            }
        }
        return Ok(());
    }

    match kind {
        ManagedPathKind::Unit => {
            check_unit_file_name(role, &path)?;
            let parent = path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("unit 路径缺少父目录: {}", path.display()))?;
            if !is_systemd_unit_dir(parent) && !path.starts_with(&prefix) {
                bail!(
                    "unit 路径必须位于 systemd unit 目录或安装前缀 {} 下: {}",
                    prefix.display(),
                    path.display()
                );
            }
        }
        ManagedPathKind::Config | ManagedPathKind::Data | ManagedPathKind::Binary => {
            if !path.starts_with(&prefix) {
                bail!(
                    "{kind:?} 路径必须位于安装前缀 {} 下: {}",
                    prefix.display(),
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// Unit 文件名必须精确等于角色的固定 unit 名。
///
/// 父目录 allowlist 只能限制“在哪个目录删”，不能限制“删目录里的哪个文件”；
/// 伪造 state 可把 unit 指向 `/run/systemd/system/ssh.service`。这里锁死文件名，
/// 让卸载流程最多只能删除 RustBoard 自己的 unit。
fn check_unit_file_name(role: Role, path: &Path) -> Result<()> {
    if path.file_name().and_then(|name| name.to_str()) != Some(role.unit_name()) {
        bail!(
            "unit 路径文件名必须精确为 {}: {}",
            role.unit_name(),
            path.display()
        );
    }
    Ok(())
}
