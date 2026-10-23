//! 敏感文件的原子写入与目录权限。
//!
//! 配置、token、私钥这类文件必须从创建的第一刻起就是 0600，不能先按 umask
//! 创建再 chmod（两者之间存在可被读取的窗口）。这里统一用「同目录临时文件 +
//! rename」实现原子替换，并尽量把父目录 fsync 落盘。
//!
//! H3：临时文件名必须是随机的，并以 `create_new` + `O_NOFOLLOW` 打开，
//! 防止攻击者提前在可预测的临时名上放符号链接，把敏感内容写进别的文件。
//! 目标路径本身是符号链接时也直接拒绝，避免误改链接指向。
//!
//! v0.3.5：Linux 下 [`ensure_private_dir`] / [`harden_dir`] 改为从 `/` 逐组件用
//! `openat2(2)` 打开目录 fd，创建用 `mkdirat`、收紧用 `fchmod`，全部基于已打开
//! 的 fd；路径在打开后被替换成符号链接也不会作用到新目标。非 Linux 保留原
//! lstat 路径实现（完整 fd 保证仅 Linux）。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// 临时文件随机名的最大重试次数；冲突时换一个随机名继续。
const TMP_CREATE_ATTEMPTS: usize = 16;

/// 顶层共享目录（精确匹配）：不能直接当作本程序的私有目录。
///
/// 它们本身归系统或所有用户共享，收紧为 0700 会破坏其他程序；其专属子目录
/// （如 `/tmp/rustboard`、`/var/lib/rustboard/hub`）仍然允许。
#[cfg(unix)]
const SHARED_TOP_LEVEL_DIRS: &[&str] = &[
    "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc", "root",
    "run", "sbin", "srv", "sys", "tmp", "usr", "var",
];

/// 恰好两级时整体视为共享 / 系统目录的顶层目录（KI-21 复审修复）。
///
/// `/var/log`、`/mnt/data`、`/media/usb`、`/srv/www`、`/home/alice` 本身都归
/// 系统或所有用户共享，不能作为本程序的私有目录；其下再深一层才可能由本程序
/// 独占（例如 `/var/lib/rustboard/hub`、`/home/<user>/.local/share/rustboard`）。
/// `/tmp/<app>`、`/opt/<app>` 不属于共享目录，仍然允许。
#[cfg(unix)]
const SHARED_TWO_LEVEL_PARENTS: &[&str] = &["home", "media", "mnt", "srv", "var"];

/// 不能存放数据 / 证书目录的系统前缀：其下任何路径都拒绝（KI-21）。
#[cfg(unix)]
const SYSTEM_DIR_PREFIXES: &[&str] = &[
    "bin", "boot", "dev", "etc", "lib", "lib64", "proc", "run", "sbin", "sys", "usr",
];

/// 系统目录的多级前缀：这些目录及其所有子目录一律拒绝（KI-21 复审修复）。
///
/// 只列出典型系统数据目录；`/var/lib/rustboard` 等本程序专属子目录不在其中，
/// 因此默认数据目录仍然合法。前缀按**完整路径组件**匹配，`/var/logfoo` 不会被
/// `/var/log` 误伤。
#[cfg(unix)]
const SYSTEM_PATH_PREFIXES: &[&str] = &[
    "var/log",
    "var/cache",
    "var/spool",
    "var/mail",
    "var/backups",
    "var/www",
    "var/run",
    "var/lock",
    "var/crash",
    "var/metrics",
    "var/opt",
    "var/local",
    "var/lib/systemd",
    "var/lib/docker",
    "var/lib/containers",
    "var/lib/snapd",
    "var/lib/apt",
    "var/lib/dpkg",
    "var/lib/nginx",
    "var/lib/postgresql",
    "var/lib/mysql",
    "var/lib/redis",
];

/// 创建目录（含父目录），新建目录的权限为 `mode`。
///
/// 已经存在的目录保持原权限不变：这是给配置文件父目录等**通用路径**用的，
/// 无条件收紧会把系统目录改坏。数据目录、证书目录这类完全由本程序拥有的
/// 私有目录请使用 [`ensure_private_dir`]，它会先拒绝共享 / 系统目录。
///
/// H3：用 `symlink_metadata` 检查目标本身，是符号链接就报错，绝不跟随。
pub fn ensure_dir(path: &Path, mode: u32) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            let hint = if mode & 0o700 != 0 {
                "（敏感目录不允许跟随符号链接）"
            } else {
                "（拒绝跟随符号链接）"
            };
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} 是符号链接{hint}", path.display()),
            ));
        }
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} 已存在且不是目录", path.display()),
            ))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        // mode 只作用于本次新建的目录；umask 最多去掉组/其他位，不会影响 0700。
        builder.recursive(true).mode(mode);
        builder.create(path)
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
        fs::create_dir_all(path)
    }
}

/// 校验私有目录的目标模式不含 group/other 位。
///
/// 私有目录一旦带共享位，`harden_dir` 的「只收紧」语义就可能变成误设共享目录，
/// 因此把这类 mode 视为调用方的编程错误。也用于在创建目录**之前**校验，避免
/// `ensure_private_dir` 先按 0755 创建再报错。
fn validate_private_dir_mode(path: &Path, mode: u32) -> io::Result<()> {
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "目录 {} 的目标权限 {mode:04o} 含 group/other 位，私有目录只接受 owner-only 权限",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// 把私有目录路径归一化为**不带尾斜杠**的绝对路径（KI-21 复审修复）。
///
/// `Path::components()` 会归一化重复分隔符、结尾的 `/` 与结尾的 `/.`，但
/// `symlink_metadata` / `set_permissions` 仍按原始路径解析。若直接使用原始路径，
/// `link/`、`link/.`、`link//` 会被解析进符号链接目标，绕过最终组件检查。
/// 因此 [`validate_private_dir_path`]、[`harden_dir`]、[`ensure_private_dir`]
/// 之后的所有文件系统操作都必须使用本函数返回的路径。
///
/// 拒绝空路径、相对路径、含 `..`（或残留 `.`）组件的路径以及 Windows 前缀；
/// 根目录 `/` 本身保留（层级规则会在后续校验中拒绝它）。
fn normalize_private_dir_path(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;

    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "目录路径不能为空",
        ));
    }

    let mut normalized = PathBuf::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::Prefix(_) => {
                return Err(invalid_private_dir_reason(path, "必须是 Unix 绝对路径"));
            }
            Component::RootDir => {
                rooted = true;
                normalized.push(Path::new("/"));
            }
            Component::CurDir => {
                return Err(invalid_private_dir_reason(path, "不能包含 `.` 组件"));
            }
            Component::ParentDir => {
                return Err(invalid_private_dir_reason(path, "不能包含 `..` 组件"));
            }
            Component::Normal(part) => {
                if !rooted {
                    return Err(invalid_private_dir_reason(path, "必须是绝对路径"));
                }
                normalized.push(part);
            }
        }
    }
    if !rooted {
        return Err(invalid_private_dir_reason(path, "必须是绝对路径"));
    }
    Ok(normalized)
}

/// 校验目录路径能否作为本程序的私有数据 / 证书目录（KI-21）。
///
/// 只读取路径和元数据，**不创建目录、不修改权限**，因此可以在创建之前调用。
/// 路径会先经 [`normalize_private_dir_path`] 去掉尾斜杠 / `/.`，之后的所有
/// 检查都基于规范化路径，避免 `link/` 这类写法跟随最终符号链接。拒绝以下情况：
/// - 空路径、相对路径，以及含 `.` / `..` 组件的路径；
/// - 顶层共享目录本身（`/tmp`、`/etc`、`/var` 等）；
/// - 恰好两级且位于 `/var`、`/mnt`、`/media`、`/srv`、`/home` 下的路径；
/// - 系统目录多级前缀（`/var/log`、`/var/cache`、`/var/lib/systemd` 等）下的路径；
/// - `/etc/`、`/usr/`、`/bin/`、`/sbin/`、`/lib/`、`/lib64/`、`/boot/`、`/proc/`、
///   `/sys/`、`/dev/`、`/run/` 下的任何路径；
/// - 从根 `/` 开始逐组件检查时，任何祖先或最终组件是符号链接；
/// - 已存在的最终路径不是目录、带 sticky 位，或不属于当前有效用户
///   （root 运行时也必须由 root 拥有）。
///
/// 由本程序独占的子目录可以通过，例如 `/tmp/<app>`、`/var/lib/<app>`、`/opt/<app>`。
/// [`harden_dir`] 与 [`ensure_private_dir`] 内部都会调用本函数；配置校验也复用它，
/// 让 `--data-dir /tmp` 这类配置在启动前就失败，而不是把共享目录 chmod 成 0700。
pub fn validate_private_dir_path(path: &Path) -> io::Result<()> {
    let normalized = normalize_private_dir_path(path)?;
    validate_normalized_private_dir_path(&normalized)
}

/// 对已经归一化的路径做形状、符号链接与最终元数据检查。
fn validate_normalized_private_dir_path(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        validate_unix_private_dir_path(path)?;
        validate_no_symlink_components(path)?;
    }
    #[cfg(not(unix))]
    {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} 必须是绝对路径", path.display()),
            ));
        }
    }

    validate_existing_private_dir(path)
}

/// 从根 `/` 开始逐组件检查，任何祖先或最终组件是符号链接都拒绝（KI-21 复审修复）。
///
/// 中间路径的符号链接同样危险：`/safe/link/sub`（`link -> /etc`）会让
/// `ensure_dir` / `set_permissions` 作用到链接目标。路径不存在时停止检查：
/// 后续组件都尚不存在，`ensure_dir` 会从第一个缺失组件开始创建。
#[cfg(unix)]
fn validate_no_symlink_components(path: &Path) -> io::Result<()> {
    use std::path::Component;

    let normal_count = path
        .components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count();
    let mut current = PathBuf::from("/");
    let mut seen = 0usize;
    for component in path.components() {
        let part = match component {
            Component::RootDir => continue,
            Component::Normal(part) => part,
            _ => return Err(invalid_private_dir_reason(path, "路径未归一化")),
        };
        seen += 1;
        current.push(part);
        let meta = match fs::symlink_metadata(&current) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => break,
            Err(err) => return Err(err),
        };
        // 必须用 symlink_metadata：`metadata` 会跟随链接，看不到中间组件的链接本身。
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} 的路径组件 {} 是符号链接，不能作为私有目录",
                    path.display(),
                    current.display()
                ),
            ));
        }
        if seen < normal_count && !meta.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "{} 的路径组件 {} 不是目录",
                    path.display(),
                    current.display()
                ),
            ));
        }
    }
    Ok(())
}

/// Unix 下的路径形状校验：绝对路径、至少两级、不含 `.` / `..`，且不落在共享 / 系统目录。
#[cfg(unix)]
fn validate_unix_private_dir_path(path: &Path) -> io::Result<()> {
    use std::ffi::OsStr;
    use std::path::Component;

    // `components()` 会归一化重复分隔符和中间的 `.`；剩余的 `.` / `..` 都不可接受。
    let mut components: Vec<&OsStr> = Vec::new();
    let mut rooted = false;
    for component in path.components() {
        match component {
            Component::RootDir => rooted = true,
            Component::Normal(part) => components.push(part),
            Component::CurDir => {
                return Err(invalid_private_dir_reason(path, "不能包含 `.` 组件"));
            }
            Component::ParentDir => {
                return Err(invalid_private_dir_reason(path, "不能包含 `..` 组件"));
            }
            Component::Prefix(_) => {
                return Err(invalid_private_dir_reason(path, "必须是 Unix 绝对路径"));
            }
        }
    }
    if !rooted {
        return Err(invalid_private_dir_reason(path, "必须是绝对路径"));
    }

    // 顶层共享目录（/tmp、/etc、/var ...）本身不能当私有目录；其专属子目录允许。
    if components.len() == 1
        && SHARED_TOP_LEVEL_DIRS
            .iter()
            .any(|dir| components[0] == OsStr::new(*dir))
    {
        return Err(shared_private_dir_error(path));
    }
    // 至少两级：既拦截 `/tmp`、`/etc`，也拦截 `/foo` 这类任意顶层目录。
    if components.len() < 2 {
        return Err(invalid_private_dir_reason(
            path,
            "至少需要两级目录（例如 /var/lib/rustboard/hub）",
        ));
    }
    let first = components[0];
    // 恰好两级：/var/*、/mnt/*、/media/*、/srv/*、/home/* 本身都是共享目录。
    if components.len() == 2
        && SHARED_TWO_LEVEL_PARENTS
            .iter()
            .any(|dir| first == OsStr::new(*dir))
    {
        return Err(shared_private_dir_error(path));
    }
    if SYSTEM_DIR_PREFIXES
        .iter()
        .any(|dir| first == OsStr::new(*dir))
    {
        return Err(invalid_private_dir_reason(
            path,
            "不能放在 /etc、/usr、/bin、/sbin、/lib、/lib64、/boot、/proc、/sys、/dev、/run 下",
        ));
    }
    // 系统目录多级前缀：/var/log/foo、/var/lib/systemd 等一律拒绝。
    if SYSTEM_PATH_PREFIXES
        .iter()
        .any(|prefix| has_component_prefix(&components, prefix))
    {
        return Err(invalid_private_dir_reason(
            path,
            "位于系统目录（/var/log、/var/cache、/var/lib/<服务> 等），不能作为私有目录",
        ));
    }
    Ok(())
}

/// 判断 `components` 是否以 `prefix` 的完整路径组件开头。
#[cfg(unix)]
fn has_component_prefix(components: &[&std::ffi::OsStr], prefix: &str) -> bool {
    use std::path::{Component, Path};

    let mut index = 0usize;
    for component in Path::new(prefix).components() {
        if let Component::Normal(part) = component {
            if components.get(index) != Some(&part) {
                return false;
            }
            index += 1;
        }
    }
    index > 0
}

#[cfg(unix)]
fn invalid_private_dir_reason(path: &Path, reason: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{} 不能作为私有目录：{reason}", path.display()),
    )
}

#[cfg(unix)]
fn shared_private_dir_error(path: &Path) -> io::Error {
    invalid_private_dir_reason(
        path,
        "是共享 / 系统目录本身，请使用由本程序独占的子目录（例如 /var/lib/rustboard/hub）",
    )
}

/// 检查已存在的最终路径：符号链接、非目录、sticky 位、其他用户所有都拒绝。
///
/// 路径不存在时返回 `Ok(())`，交由调用方创建。本函数只检查最终组件；
/// 祖先组件的符号链接由 [`validate_no_symlink_components`] 统一检查。
fn validate_existing_private_dir(path: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} 是符号链接，不能作为私有目录", path.display()),
        ));
    }
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} 已存在且不是目录", path.display()),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        // sticky 位（/tmp、/var/tmp 等）说明目录是多人共享的，不能收紧为私有目录。
        if meta.permissions().mode() & 0o1000 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} 带 sticky 位，是共享目录，不能作为私有目录",
                    path.display()
                ),
            ));
        }
        // SAFETY: geteuid 只返回当前进程的有效用户 ID，没有指针参数或内存安全前提。
        let euid = unsafe { libc::geteuid() };
        // v0.3.5 收紧：所有进程（包括 root）都必须拥有最终目录。
        // root 服务不能再使用其他用户（例如服务用户 home）拥有的 data_dir；
        // 这类部署需迁移到 root 拥有的专用目录，或改用服务用户运行。
        if meta.uid() != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} 属于其他用户（uid {}），当前有效用户为 {euid}；私有目录必须由当前用户拥有",
                    path.display(),
                    meta.uid()
                ),
            ));
        }
    }
    Ok(())
}

/// 收紧已经存在目录的权限（KI-21）。
///
/// 与 [`harden`] 的区别：目标必须**已存在且是目录**，非目录、符号链接都拒绝，
/// 不会替调用方创建目录。路径会先归一化（去掉 `link/`、`link/.` 的尾斜杠）
/// 并从根开始逐组件拒绝符号链接；随后再经 [`validate_private_dir_path`] 校验，
/// 共享 / 系统目录、sticky 目录、非本人目录一律不 chmod；同时只允许收紧到不含
/// group/other 位的私有模式（`mode & 0o077 != 0` 直接报错）。
/// 当前权限没有超出 `mode` 允许的位时不调用 `chmod`，重复调用幂等。
///
/// Linux 下实际打开 / 校验 / 收紧全部基于 `openat2` 打开的目录 fd：从 `/`
/// 逐组件拒绝符号链接，祖先 owner 与 group/other 写位在同一 fd 上校验，最后
/// 对最终目录 fd 执行 `fchmod`。因此校验之后路径被换成指向 victim 的符号链接
/// 也不会 chmod 到 victim。非 Linux 保留原 lstat 路径实现。
pub fn harden_dir(path: &Path, mode: u32) -> io::Result<()> {
    // 先校验 mode 与路径：两者都是调用方的编程错误，必须在 chmod 之前失败。
    validate_private_dir_mode(path, mode)?;
    // 归一化后所有元数据 / chmod 操作都作用于不带尾斜杠的路径，避免 `link/`
    // 被内核解析进符号链接目标。
    let path = normalize_private_dir_path(path)?;
    validate_normalized_private_dir_path(&path)?;

    #[cfg(target_os = "linux")]
    {
        // 不允许创建：目标缺失时 openat2 返回 ENOENT，映射为 NotFound。
        let dir = linux_fd::open_private_dir(&path, false)?;
        linux_fd::harden_open_dir(&path, &dir, mode)
    }
    #[cfg(not(target_os = "linux"))]
    {
        harden_validated_dir(&path, mode)
    }
}

/// 对已经归一化并校验过的目录执行「只收紧」的 chmod。
///
/// 仅用于非 Linux 平台的兼容路径；Linux 下由 [`linux_fd::harden_open_dir`]
/// 基于目录 fd 完成。
#[cfg(not(target_os = "linux"))]
fn harden_validated_dir(path: &Path, mode: u32) -> io::Result<()> {
    // 路径校验已保证目标存在且是普通目录；这里再取一次元数据用于比较当前权限
    // （路径不存在时 symlink_metadata 会返回 NotFound，保持「要求目标已存在」语义）。
    let meta = fs::symlink_metadata(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let current = meta.permissions().mode() & 0o777;
        // `current & !mode` 表示当前权限里有 mode 不允许的位（例如 0755 对 0700）。
        // 只收紧、不放宽：比 mode 更严格的目录保持原样。
        if current & !mode != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            tracing::warn!(
                path = %path.display(),
                from = format!("{current:04o}"),
                to = format!("{mode:04o}"),
                "目录权限过宽，已收紧"
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (meta, mode);
    }
    Ok(())
}

/// 创建（或复用）私有目录，并把已存在目录的过宽权限收紧到 `mode`（KI-21）。
///
/// 顺序：mode 校验 → 路径归一化 → [`validate_private_dir_path`] → [`ensure_dir`] →
/// [`harden_dir`]。因此 `/tmp`、`/etc`、`/` 这类共享 / 系统目录会在创建或
/// chmod **之前**被拒绝；新建目录直接是 `mode`，旧版本遗留的 0755 专属目录
/// 也会在启动时被收紧。**只用于数据目录、证书目录这类完全由本程序拥有的
/// 目录**；`/etc/rustboard` 等共享配置父目录仍应使用 [`ensure_dir`]，以免改坏
/// 系统目录的既有语义。
///
/// 路径会先归一化（`/tmp/x/`、`/tmp/x/.` 都按 `/tmp/x` 处理），`ensure_dir` 与
/// 后续 chmod 都使用规范化路径，不能再用原始路径跟随最终符号链接。
///
/// Linux 下创建与收紧都基于 fd：从 `/` 逐组件 `openat2` 打开（缺失组件用
/// `mkdirat(父 fd, 名字, 0o700)` 创建），最终目录用 `fchmod` 收紧；祖先 owner /
/// 可写性在同一 fd 上校验。非 Linux 保留 `ensure_dir` + lstat 的旧实现。
///
/// 空路径保持 [`ensure_dir`] 的 no-op 语义：它表示当前工作目录（例如相对路径
/// 数据库的父目录），不是由本程序拥有的私有目录，不能校验也不能 chmod。
pub fn ensure_private_dir(path: &Path, mode: u32) -> io::Result<()> {
    // 先校验 mode，避免参数非法时先按公开权限把目录创建出来。
    validate_private_dir_mode(path, mode)?;
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    // 路径校验必须发生在创建 / chmod 之前：共享目录先创建再报错就来不及了。
    let path = normalize_private_dir_path(path)?;
    validate_normalized_private_dir_path(&path)?;

    #[cfg(target_os = "linux")]
    {
        // 允许创建中间与最终组件；创建出的目录一律先按 0700 建立。
        let dir = linux_fd::open_private_dir(&path, true)?;
        linux_fd::harden_open_dir(&path, &dir, mode)
    }
    #[cfg(not(target_os = "linux"))]
    {
        ensure_dir(&path, mode)?;
        // 复用已校验结果，避免第二次校验与创建之间再引入新的解析差异。
        harden_validated_dir(&path, mode)
    }
}

/// Linux 专用：从根 `/` 逐组件用 `openat2` 打开目录 fd，创建与收紧全部基于 fd。
///
/// 与「先 lstat、再按原始路径操作」相比，本实现没有 TOCTOU 窗口：
/// - 祖先组件以 `O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` +
///   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS` 打开，
///   任一组件是符号链接、magic link 或借 `..` 逃逸根目录都由内核直接拒绝；
/// - 缺失组件用 `mkdirat(父 fd, 名字, 0o700)` 创建，再基于父 fd 重新打开；
/// - 每个已打开的祖先都 `fstat` 校验 owner 与 group/other 写位，**先校验父目录
///   再向下打开**；
/// - 最终目录以 `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` 打开
///   （`O_PATH` fd 不支持 `fchmod`），校验 euid 归属与 sticky 后对**同一个 fd**
///   执行 `fchmod`。路径在打开后被 rename 走并换成指向 victim 的符号链接，
///   也只会改到原目录 fd，不会 chmod victim。
///
/// 内核不支持 `openat2`（ENOSYS）时明确失败，不降级为路径检查。
#[cfg(target_os = "linux")]
mod linux_fd {
    use std::ffi::{CString, OsStr};
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path, PathBuf};

    // `openat2(2)` 的 resolve 标志；libc 只暴露 SYS_openat2，不暴露这些常量。
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    /// `openat2(2)` 的参数结构；字段由内核读取，Rust 侧只负责内存布局。
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    /// 打开（必要时创建）私有目录，返回最终目录 fd。
    ///
    /// `create` 为 `false` 时只打开已有目录：缺失组件返回 `NotFound`，与
    /// [`super::harden_dir`]「要求目标已存在」的语义一致。返回前只校验祖先的
    /// owner / 可写性；最终目录的 sticky / owner 由 [`harden_open_dir`] 在同一个
    /// fd 上校验并收紧，不再二次解析路径。
    pub(super) fn open_private_dir(path: &Path, create: bool) -> io::Result<File> {
        let names: Vec<&OsStr> = path
            .components()
            .filter_map(|component| match component {
                Component::Normal(name) => Some(name),
                _ => None,
            })
            .collect();
        if names.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} 必须是至少两级目录", path.display()),
            ));
        }

        let root = open_root_dir()?;
        let euid = effective_uid();
        let mut displayed = PathBuf::from("/");
        // 根目录也是祖先：先校验再向下打开。
        validate_ancestor(path, &displayed, &root, euid)?;
        let mut parent = root;

        for (index, name) in names.iter().enumerate() {
            displayed.push(name);
            let final_component = index + 1 == names.len();
            let child = open_child(&parent, name, final_component, create, path, &displayed)?;
            if !final_component {
                // 先校验刚打开的父目录，再在下一轮用它打开子组件。
                validate_ancestor(path, &displayed, &child, euid)?;
            }
            // 子目录打开后旧的父 fd 才会释放。
            parent = child;
        }
        Ok(parent)
    }

    /// 校验并收紧已打开的最终目录 fd（`harden_dir` / `ensure_private_dir` 共用）。
    ///
    /// 校验只读 fd 元数据：最终目录必须由当前 euid 拥有、不得带 sticky 位；
    /// 只有当前权限含 `mode` 不允许的位时才 `fchmod`，更严格的权限不放宽。
    pub(super) fn harden_open_dir(path: &Path, dir: &File, mode: u32) -> io::Result<()> {
        let stat = validate_final(path, dir)?;
        let current = stat.st_mode as u32 & 0o777;
        // `current & !mode` 表示当前权限里有 mode 不允许的位（例如 0755 对 0700）。
        // 只收紧、不放宽：比 mode 更严格的目录保持原样。
        if current & !mode != 0 {
            // SAFETY: dir 是已打开的目录 fd，mode 只含权限位；fchmod(2) 只修改该
            // fd 指向目录自身的权限，不涉及指针或内存所有权。
            if unsafe { libc::fchmod(dir.as_raw_fd(), mode as libc::mode_t) } < 0 {
                return Err(io::Error::last_os_error());
            }
            tracing::warn!(
                path = %path.display(),
                from = format!("{current:04o}"),
                to = format!("{mode:04o}"),
                "目录权限过宽，已收紧"
            );
        }
        Ok(())
    }

    /// 最终目录的 fd 元数据校验：sticky 与 owner（root 也必须是 root 拥有）。
    pub(super) fn validate_final(path: &Path, dir: &File) -> io::Result<libc::stat> {
        let stat = stat_fd(dir)?;
        let st_mode = stat.st_mode as u32;
        // sticky 位（/tmp、/var/tmp 等）说明目录是多人共享的，不能作为私有目录。
        if st_mode & 0o1000 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} 带 sticky 位，是共享目录，不能作为私有目录",
                    path.display()
                ),
            ));
        }
        let euid = effective_uid();
        if stat.st_uid != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} 属于其他用户（uid {}），当前有效用户为 {euid}；私有目录必须由当前用户拥有",
                    path.display(),
                    stat.st_uid
                ),
            ));
        }
        Ok(stat)
    }

    /// 打开一个路径组件；`final_component` 决定 O_PATH（祖先）还是 O_RDONLY（最终）。
    fn open_at(parent: &File, name: &OsStr, final_component: bool) -> io::Result<File> {
        let name_c = component_cstring(name)?;
        let flags = if final_component {
            // O_PATH fd 不能 fchmod，最终目录必须用可读写元数据的普通目录 fd。
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        } else {
            // 祖先只需要目录引用，不需要读权限。
            libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
        };
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: openat2(2) 只读取 how 指向的 POD 结构；parent fd 与 name_c 在
        // 调用期间均有效，结构大小由 size_of 精确给出，内核只写返回的 fd。
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                parent.as_raw_fd(),
                name_c.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd 由 openat2(2) 新建并返回，调用方是唯一所有者；所有权交给 File。
        Ok(unsafe { File::from_raw_fd(fd as RawFd) })
    }

    /// 打开缺失的路径组件：`ENOENT` 时先 `mkdirat` 再重开；其他错误上抛。
    fn open_child(
        parent: &File,
        name: &OsStr,
        final_component: bool,
        create: bool,
        path: &Path,
        component: &Path,
    ) -> io::Result<File> {
        match open_at(parent, name, final_component) {
            Ok(dir) => Ok(dir),
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) && create => {
                match make_dir_at(parent, name) {
                    Ok(()) => {}
                    Err(err) if err.raw_os_error() == Some(libc::EEXIST) => {
                        // 并发创建或同名条目抢先出现：重开一次并走完整校验；
                        // 仍失败时保留 EEXIST 线索，便于诊断。
                        return open_at(parent, name, final_component).map_err(|reopen_err| {
                            let mapped =
                                map_open_error(path, component, final_component, reopen_err);
                            io::Error::new(
                                mapped.kind(),
                                format!(
                                    "{mapped}（mkdirat 返回 EEXIST：目录条目已存在但无法作为目录复用）"
                                ),
                            )
                        });
                    }
                    Err(err) => {
                        return Err(io::Error::new(
                            err.kind(),
                            format!("mkdirat 创建目录 {} 失败: {err}", component.display()),
                        ))
                    }
                }
                open_at(parent, name, final_component)
                    .map_err(|err| map_open_error(path, component, final_component, err))
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                Err(not_found_error(path, component, final_component))
            }
            Err(err) => Err(map_open_error(path, component, final_component, err)),
        }
    }

    /// 以 0700 创建一级目录（创建时即私有，不经过公开权限窗口）。
    fn make_dir_at(parent: &File, name: &OsStr) -> io::Result<()> {
        let name_c = component_cstring(name)?;
        // SAFETY: parent fd 与 name_c 在调用期间有效；mkdirat(2) 只创建一级目录
        // 项，mode 只含权限位，不涉及指针或内存所有权。
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// 校验已打开祖先目录的 owner 与 group/other 写位。
    ///
    /// owner 规则：root 拥有的目录允许所有进程；非 root-owned 的祖先必须等于
    /// `geteuid()`，其他 uid 一律拒绝（root 进程因此只接受 root-owned）。
    /// mode 规则：group/other 写位必须为 0；唯一例外是 root 拥有的 sticky
    /// 目录（`/tmp`、`/var/tmp`），它只能作为祖先，不能作为最终目录。
    fn validate_ancestor(
        path: &Path,
        component: &Path,
        dir: &File,
        euid: libc::uid_t,
    ) -> io::Result<()> {
        let stat = stat_fd(dir)?;
        let st_mode = stat.st_mode as u32;
        if stat.st_uid != 0 && stat.st_uid != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "私有目录 {} 的祖先 {} 属于其他用户（uid {}），当前有效用户为 {euid}",
                    path.display(),
                    component.display(),
                    stat.st_uid
                ),
            ));
        }
        let root_sticky = stat.st_uid == 0 && st_mode & 0o1000 != 0;
        if st_mode & 0o022 != 0 && !root_sticky {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "私有目录 {} 的祖先 {} 权限 {:04o} 对 group/other 可写（且不是 root 拥有的 sticky 目录），拒绝使用",
                    path.display(),
                    component.display(),
                    st_mode & 0o7777
                ),
            ));
        }
        Ok(())
    }

    /// 打开根目录 fd；后续所有组件都相对它解析。
    fn open_root_dir() -> io::Result<File> {
        // SAFETY: `c"/"` 是合法的 NUL 结尾 C 字符串；open(2) 只读取该字符串，
        // 返回的 fd 归调用方所有。O_PATH 只需要目录引用，不需要读权限。
        let fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fd 由 open(2) 返回且没有其他持有者，所有权交给 File。
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// 把单组件文件名转成 C 字符串；路径含 NUL 时在 syscall 前拒绝。
    fn component_cstring(name: &OsStr) -> io::Result<CString> {
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "目录路径的组件包含 NUL 字节"))
    }

    /// 取 fd 元数据；`O_PATH` fd 也支持 `fstat`。
    fn stat_fd(dir: &File) -> io::Result<libc::stat> {
        // SAFETY: fstat(2) 只写调用方提供的 stat 结构；dir 的 fd 在调用期间有效。
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(dir.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fstat(2) 成功返回时已完整初始化 stat。
        Ok(unsafe { stat.assume_init() })
    }

    /// 当前进程的有效用户 ID（目录 owner 规则以它为准）。
    fn effective_uid() -> libc::uid_t {
        // SAFETY: geteuid 没有参数，也没有内存安全前提。
        unsafe { libc::geteuid() }
    }

    /// 目标缺失时的可诊断错误（`harden_dir` 不创建目录）。
    fn not_found_error(path: &Path, component: &Path, final_component: bool) -> io::Error {
        let detail = if final_component {
            "不存在；harden_dir 要求目标目录已存在，不会创建"
        } else {
            "不存在，目录层级不完整"
        };
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{} 的目录组件 {} {detail}",
                path.display(),
                component.display()
            ),
        )
    }

    /// 把 `openat2` 的错误映射成带路径上下文的可诊断错误。
    ///
    /// `ELOOP` 一定映射为 `PermissionDenied` 且信息含「符号链接」；`ENOTDIR`
    /// 映射为 `AlreadyExists` 并点明非目录组件；`ENOSYS` 明确失败、不降级。
    fn map_open_error(
        path: &Path,
        component: &Path,
        final_component: bool,
        err: io::Error,
    ) -> io::Error {
        match err.raw_os_error() {
            Some(libc::ELOOP) => io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} 的路径组件 {} 是符号链接，不能作为私有目录",
                    path.display(),
                    component.display()
                ),
            ),
            Some(libc::ENOTDIR) => {
                if final_component {
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "{} 已存在且不是目录（组件 {} 不是目录）",
                            path.display(),
                            component.display()
                        ),
                    )
                } else {
                    io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!(
                            "{} 的路径组件 {} 不是目录",
                            path.display(),
                            component.display()
                        ),
                    )
                }
            }
            Some(libc::ENOSYS) => io::Error::new(
                io::ErrorKind::Unsupported,
                "内核不支持 openat2(2)：无法为私有目录提供 fd 级校验，拒绝降级为路径检查",
            ),
            _ => io::Error::new(
                err.kind(),
                format!(
                    "打开目录 {} 的路径组件 {} 失败: {err}",
                    path.display(),
                    component.display()
                ),
            ),
        }
    }
}

/// 测试用：用 fd walk 打开一个**已存在**的私有目录（不创建、不 chmod）。
///
/// TOCTOU 测试需要先拿到目录 fd，再把路径 rename 走并换成指向 victim 的
/// 符号链接，最后验证基于 fd 的收紧不会作用到 victim。
#[cfg(all(test, target_os = "linux"))]
fn open_existing_private_dir_fd(path: &Path) -> io::Result<File> {
    linux_fd::open_private_dir(path, false)
}

/// 测试用：在已打开的目录 fd 上做最终校验并「只收紧」地 `fchmod`。
#[cfg(all(test, target_os = "linux"))]
fn harden_open_dir_fd(path: &Path, dir: &File, mode: u32) -> io::Result<()> {
    linux_fd::harden_open_dir(path, dir, mode)
}

/// 测试用：只校验已打开最终目录 fd 的 sticky / owner，不执行 chmod。
#[cfg(all(test, target_os = "linux"))]
fn validate_final_dir_fd(path: &Path, dir: &File) -> io::Result<()> {
    linux_fd::validate_final(path, dir).map(|_| ())
}

/// 把进程 umask 收紧到 `0o077`：此后新建文件默认 0600、目录默认 0700（Unix）。
///
/// 这是进程级全局状态，只应在进程启动的最早期调用一次（hub / agent 的 `main`
/// 在创建线程与打开日志/数据库之前），避免和已有线程的创建行为竞争。需要显式
/// 指定权限的路径（证书 0644、私钥/配置 0600）仍然由 [`atomic_write`] 等函数
/// 设置，不受 umask 影响。
///
/// 返回调用前的旧 umask，便于排障或需要恢复时使用；非 Unix 平台是 no-op，
/// 返回 `None`。
pub fn set_private_umask() -> Option<u32> {
    #[cfg(unix)]
    {
        // SAFETY: `umask` 只读写进程级全局 umask，没有指针参数，也没有内存安全
        // 前提；按约定在 main 最早期单线程调用，且返回值仅用于记录旧值。
        let old = unsafe { libc::umask(0o077) };
        tracing::debug!(old = format!("{:04o}", old), "已设置私有 umask 0o077");
        Some(old as u32)
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// 收紧已经存在文件的权限（M3）。
///
/// 老版本或人为操作可能留下 0644 的配置 / 私钥。读取前检查组与其他位，
/// 发现过宽就 `chmod` 到 `mode` 并打 warn 日志；已经合规时不做系统调用。
/// 文件是符号链接时同样拒绝，避免 chmod 到链接目标。
pub fn harden(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let meta = fs::symlink_metadata(path)?;
        if meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} 是符号链接，拒绝收紧权限", path.display()),
            ));
        }
        let current = meta.permissions().mode() & 0o777;
        if current & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
            tracing::warn!(
                path = %path.display(),
                from = format!("{current:04o}"),
                to = format!("{mode:04o}"),
                "文件权限过宽，已收紧"
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

/// 原子写入文件并设置权限。
///
/// 流程：同目录**随机名**临时文件 → 写入 → fsync → rename 覆盖目标 →
/// 尽力 fsync 父目录。Unix 下临时文件以 `create_new + O_NOFOLLOW` 创建，
/// 从第一刻起就是 `mode`，因此目标文件不会出现权限过宽的窗口。
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "目标路径缺少文件名"))?;

    // 目标本身是符号链接时拒绝写入：原子 rename 会替换链接而不是跟随，
    // 但配置路径被替换成链接通常意味着攻击，直接失败更安全。
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{} 是符号链接，拒绝写入", path.display()),
            ));
        }
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    let mut last_conflict = None;
    for _ in 0..TMP_CREATE_ATTEMPTS {
        let tmp = parent.join(format!(
            ".{}.tmp.{}.{:016x}",
            name.to_string_lossy(),
            std::process::id(),
            rand::random::<u64>()
        ));
        match open_tmp(&tmp, mode) {
            Ok(file) => return write_tmp_and_rename(file, &tmp, path, &parent, data),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                // 随机名撞车或被人抢先占用；换一个名字重试。
                last_conflict = Some(err);
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_conflict.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "{} 的临时文件在 {TMP_CREATE_ATTEMPTS} 次尝试后仍无法创建",
                path.display()
            ),
        )
    }))
}

/// 以独占方式创建临时文件；Unix 下禁止跟随符号链接并固定权限。
fn open_tmp(path: &Path, mode: u32) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(not(unix))]
    let _ = mode;

    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // umask 可能收窄权限位；显式设置为调用方要求的固定权限。
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    Ok(file)
}

fn write_tmp_and_rename(
    mut file: File,
    tmp: &Path,
    path: &Path,
    parent: &Path,
    data: &[u8],
) -> io::Result<()> {
    let write_result = file.write_all(data).and_then(|_| file.sync_all());
    drop(file);
    if let Err(err) = write_result {
        // 失败时清掉临时文件，避免留下半成品或敏感内容。
        let _ = fs::remove_file(tmp);
        return Err(err);
    }

    if let Err(err) = fs::rename(tmp, path) {
        let _ = fs::remove_file(tmp);
        return Err(err);
    }

    #[cfg(unix)]
    {
        // rename 只有在父目录落盘后才算持久化；失败不影响本次写入结果。
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::sync::Mutex;

    #[cfg(unix)]
    static UMASK_LOCK: Mutex<()> = Mutex::new(());

    /// 临时把进程 umask 设为指定值，Drop 时恢复。
    ///
    /// MSRV 1.80 不支持 `unsafe extern "C"` 语法，直接使用 libc 里的声明。
    #[cfg(unix)]
    struct UmaskGuard(Option<libc::mode_t>);

    #[cfg(unix)]
    impl UmaskGuard {
        fn set(mask: u32) -> Self {
            // SAFETY: umask 是进程级全局状态。测试内用 UMASK_LOCK 串行化，
            // 并在 Drop 中恢复原值，不存在内存安全问题。
            let old = unsafe { libc::umask(mask as libc::mode_t) };
            Self(Some(old))
        }
    }

    #[cfg(unix)]
    impl Drop for UmaskGuard {
        fn drop(&mut self) {
            if let Some(old) = self.0 {
                // SAFETY: 恢复 UmaskGuard::set 之前的进程 umask。
                unsafe {
                    libc::umask(old);
                }
            }
        }
    }

    #[cfg(unix)]
    fn umask_lock() -> std::sync::MutexGuard<'static, ()> {
        UMASK_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rb-fsutil-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn issue_6_atomic_write_creates_0600_file_under_umask_0022() {
        let _lock = umask_lock();
        let _guard = UmaskGuard::set(0o022);
        let dir = temp_dir("write-0600");
        ensure_dir(&dir, 0o700).unwrap();

        let path = dir.join("agent.toml");
        atomic_write(&path, b"token = \"secret\"", 0o600).unwrap();

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"token = \"secret\"");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn issue_6_ensure_dir_creates_0700_directory() {
        let _lock = umask_lock();
        let _guard = UmaskGuard::set(0o022);
        let dir = temp_dir("dir-0700");
        let nested = dir.join("data");

        ensure_dir(&nested, 0o700).unwrap();

        assert_eq!(mode_of(&nested), 0o700);
        assert_eq!(mode_of(&dir), 0o700);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn issue_6_atomic_write_tightens_existing_0644_file() {
        let dir = temp_dir("tighten");
        ensure_dir(&dir, 0o700).unwrap();
        let path = dir.join("agent.secret");

        fs::write(&path, b"old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&path), 0o644);

        atomic_write(&path, b"new", 0o600).unwrap();

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"new");
        let _ = fs::remove_dir_all(&dir);
    }

    /// issue #6：写入失败时不能把含敏感内容的临时文件留在目录里。
    ///
    /// 目标路径故意用目录：临时文件能正常创建并写入，但 `rename` 必然失败，
    /// 正好覆盖「写完一半后失败」的清理路径。这里不用只读目录，是因为测试
    /// 进程可能以 root 运行，权限位拦不住写入。
    #[cfg(unix)]
    #[test]
    fn issue_6_atomic_write_failure_leaves_no_tmp_file() {
        let dir = temp_dir("atomic-fail");
        ensure_dir(&dir, 0o700).unwrap();
        let target = dir.join("agent.key");
        fs::create_dir(&target).unwrap();

        assert!(atomic_write(&target, b"super-secret", 0o600).is_err());

        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().contains(".tmp."))
            .collect();
        assert!(
            leftovers.is_empty(),
            "写入失败后遗留临时文件: {leftovers:?}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// H3：目标被预先替换成符号链接时写入必须失败，且链接指向的文件不改动。
    #[cfg(unix)]
    #[test]
    fn h3_atomic_write_refuses_symlink_target_without_polluting_victim() {
        let dir = temp_dir("symlink-target");
        ensure_dir(&dir, 0o700).unwrap();
        let victim = dir.join("victim.conf");
        fs::write(&victim, b"original").unwrap();
        let target = dir.join("agent.secret");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        let err = atomic_write(&target, b"attacker-controlled", 0o600).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    /// H3：临时文件名被预先占成符号链接时，`create_new + O_NOFOLLOW` 拒绝打开。
    #[cfg(unix)]
    #[test]
    fn h3_tmp_open_refuses_precreated_symlink() {
        let dir = temp_dir("symlink-tmp");
        ensure_dir(&dir, 0o700).unwrap();
        let victim = dir.join("victim");
        fs::write(&victim, b"original").unwrap();
        let tmp = dir.join(".agent.key.tmp.preexisting");
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        assert!(open_tmp(&tmp, 0o600).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"original");
        let _ = fs::remove_dir_all(&dir);
    }

    /// H3：`ensure_dir` 不跟随符号链接，敏感目录直接报错。
    #[cfg(unix)]
    #[test]
    fn h3_ensure_dir_refuses_symlink_target() {
        let dir = temp_dir("symlink-dir");
        ensure_dir(&dir, 0o700).unwrap();
        let victim = dir.join("victim-dir");
        fs::create_dir(&victim).unwrap();
        let target = dir.join("data");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        let err = ensure_dir(&target, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    /// M3：已存在的 0644 文件在 `harden` 后被收紧到 0600。
    #[cfg(unix)]
    #[test]
    fn m3_harden_tightens_existing_wide_file() {
        let dir = temp_dir("harden");
        ensure_dir(&dir, 0o700).unwrap();
        let path = dir.join("agent.toml");
        fs::write(&path, b"token = \"secret\"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        harden(&path, 0o600).unwrap();

        assert_eq!(mode_of(&path), 0o600);
        // 已经合规时再调用不应报错，也不改变内容。
        harden(&path, 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"token = \"secret\"");
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：新建数据目录必须从第一刻起就是 0700（含缺失的父目录）。
    #[cfg(unix)]
    #[test]
    fn ki21_ensure_private_dir_creates_0700() {
        let dir = temp_dir("private-new");
        let nested = dir.join("data");

        ensure_private_dir(&nested, 0o700).unwrap();

        assert_eq!(mode_of(&nested), 0o700);
        assert_eq!(mode_of(&dir), 0o700);
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：旧版本留下的 0755 目录在启动时必须被收紧；重复调用幂等。
    #[cfg(unix)]
    #[test]
    fn ki21_ensure_private_dir_tightens_existing_0755() {
        let dir = temp_dir("private-old");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(mode_of(&dir), 0o755);

        ensure_private_dir(&dir, 0o700).unwrap();
        assert_eq!(mode_of(&dir), 0o700, "已存在的过宽目录必须被收紧");

        // 已经合规时再做一次不能报错，也不能把权限改回旧值。
        ensure_private_dir(&dir, 0o700).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：`harden_dir` 只收紧、不放宽：比目标更严格的目录保持原样。
    #[cfg(unix)]
    #[test]
    fn ki21_harden_dir_is_idempotent_and_never_widens() {
        let dir = temp_dir("private-narrow");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();

        harden_dir(&dir, 0o700).unwrap();

        assert_eq!(mode_of(&dir), 0o500, "已经比 0700 更严格的目录不能被放宽");
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：目标存在但不是目录时必须拒绝，不能 chmod 普通文件。
    #[cfg(unix)]
    #[test]
    fn ki21_harden_dir_rejects_non_directory() {
        let dir = temp_dir("harden-file");
        ensure_dir(&dir, 0o700).unwrap();
        let file = dir.join("not-a-dir");
        fs::write(&file, b"x").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        let err = harden_dir(&file, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(mode_of(&file), 0o644, "普通文件不能被当成目录 chmod");
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：目录是符号链接时拒绝收紧，且链接指向的目标权限不变。
    #[cfg(unix)]
    #[test]
    fn ki21_harden_dir_refuses_symlink_target() {
        let dir = temp_dir("harden-symlink");
        ensure_dir(&dir, 0o700).unwrap();
        let victim = dir.join("victim-dir");
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
        let target = dir.join("data");
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        let err = harden_dir(&target, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(mode_of(&victim), 0o755, "不能 chmod 到符号链接目标");
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：`harden_dir` 不允许含 group/other 位的 mode，避免误用成共享目录。
    #[cfg(unix)]
    #[test]
    fn ki21_harden_dir_rejects_public_mode() {
        let dir = temp_dir("harden-public-mode");
        ensure_dir(&dir, 0o700).unwrap();

        let err = harden_dir(&dir, 0o750).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(mode_of(&dir), 0o700, "参数非法时不能改动目录权限");
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：`ensure_private_dir` 的 mode 校验必须发生在创建目录之前，
    /// 否则非法参数会先留下一个公开目录。
    #[cfg(unix)]
    #[test]
    fn ki21_ensure_private_dir_rejects_public_mode_before_creating() {
        let dir = temp_dir("private-public-mode");
        let nested = dir.join("data");

        let err = ensure_private_dir(&nested, 0o755).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!nested.exists(), "参数非法时不能先创建公开目录");
    }

    /// KI-21：`harden_dir` 要求目标已存在（不负责创建目录）。
    #[cfg(unix)]
    #[test]
    fn ki21_harden_dir_requires_existing_path() {
        let dir = temp_dir("harden-missing");
        ensure_dir(&dir, 0o700).unwrap();
        let missing = dir.join("missing");

        let err = harden_dir(&missing, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：共享 / 系统目录本身、系统前缀下的路径都不能作为私有目录。
    ///
    /// 这里只调用只读的 `validate_private_dir_path`，**不会**对真实的
    /// `/tmp`、`/etc`、`/` 执行 chmod。
    #[cfg(unix)]
    #[test]
    fn ki21_validate_private_dir_path_rejects_shared_and_system_dirs() {
        for path in [
            "/",
            "/tmp",
            "/var/tmp",
            "/etc",
            "/etc/foo",
            "/etc/rustboard",
            "/var/lib",
            "/var",
            "/usr",
            "/usr/local/share",
            "/bin",
            "/sbin",
            "/lib",
            "/lib64",
            "/boot",
            "/proc",
            "/sys",
            "/dev",
            "/run",
            "/root",
            "/home",
            "/opt",
            "/srv",
            "/mnt",
            "/media",
            // KI-21 复审：恰好两级的 /var/*、/mnt/*、/media/*、/srv/*、/home/*
            // 都是共享 / 系统目录本身。
            "/var/log",
            "/var/cache",
            "/var/spool",
            "/var/mail",
            "/var/backups",
            "/var/www",
            "/var/run",
            "/var/lock",
            "/var/crash",
            "/var/metrics",
            "/var/opt",
            "/var/local",
            "/mnt/data",
            "/media/usb",
            "/srv/www",
            "/home/alice",
            // 三级及以上的系统目录前缀（含子目录）同样拒绝。
            "/var/log/foo",
            "/var/cache/foo/bar",
            "/var/spool/cron",
            "/var/lib/systemd",
            "/var/lib/systemd/coredump",
            "/var/lib/docker",
            "/var/lib/containers/storage",
            "/var/lib/snapd",
            "/var/lib/apt",
            "/var/lib/dpkg",
            "/var/lib/nginx",
            "/var/lib/postgresql",
            "/var/lib/mysql",
            "/var/lib/redis",
        ] {
            let err = validate_private_dir_path(Path::new(path))
                .expect_err(&format!("{path} 必须被拒绝"));
            assert_eq!(
                err.kind(),
                io::ErrorKind::InvalidInput,
                "path={path} 的错误类型不对: {err}"
            );
            assert!(!err.to_string().is_empty(), "path={path} 必须给出可读错误");
        }
    }

    /// KI-21：空路径、相对路径以及含 `.` / `..` 的路径必须拒绝。
    #[cfg(unix)]
    #[test]
    fn ki21_validate_private_dir_path_rejects_relative_and_dot_components() {
        for path in [
            "",
            "relative/path",
            "data",
            ".",
            "./data",
            "..",
            "../data",
            "/tmp/../etc",
            "/tmp/./x/../y",
        ] {
            assert!(
                validate_private_dir_path(Path::new(path)).is_err(),
                "path={path:?} 必须被拒绝"
            );
        }

        // 只有末尾的 `.` 会被 Path 归一化掉，但层级不足仍然拒绝。
        assert!(validate_private_dir_path(Path::new("/tmp/.")).is_err());
    }

    /// KI-21：本程序独占的子目录合法；不存在的目标也能在创建前通过路径校验。
    #[cfg(unix)]
    #[test]
    fn ki21_validate_private_dir_path_accepts_owned_subdirs() {
        let dir = temp_dir("validate-accept");
        ensure_dir(&dir, 0o700).unwrap();

        // /tmp/<unique-subdir> 是允许的。
        validate_private_dir_path(&dir).expect("temp 下的专属子目录必须合法");
        // 尚未创建的目标只做语法校验，应该通过且不得被创建。
        let missing = dir.join("nested").join("data");
        validate_private_dir_path(&missing).expect("创建前的目标路径必须合法");
        assert!(!missing.exists(), "路径校验不得创建目录");
        // 默认 hub / agent 数据目录只做校验，不 chmod 真实目录。
        validate_private_dir_path(Path::new("/var/lib/rustboard/hub"))
            .expect("/var/lib/<app> 必须合法");
        validate_private_dir_path(Path::new("/var/lib/rustboard/agent"))
            .expect("/var/lib/<app> 必须合法");
        validate_private_dir_path(Path::new("/opt/rustboard/data")).expect("/opt/<app> 必须合法");
        // 用户目录下的默认数据目录（三级以上，不在系统前缀里）必须合法。
        // 用一个明确不存在的用户名，避免测试依赖运行机器的真实 /home 内容。
        validate_private_dir_path(Path::new(
            "/home/rustboard-test-user/.local/share/rustboard",
        ))
        .expect("/home/<user>/.local/share/rustboard 必须合法");

        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：已存在目录带 sticky 位时拒绝，且 `harden_dir` 不得先去掉 sticky 再 chmod。
    #[cfg(unix)]
    #[test]
    fn ki21_validate_private_dir_path_rejects_sticky_dir_without_chmod() {
        let dir = temp_dir("validate-sticky");
        ensure_dir(&dir, 0o700).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o1700)).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            0o1700
        );

        let err = validate_private_dir_path(&dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("sticky"), "错误信息: {err}");

        let err = harden_dir(&dir, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            0o1700,
            "校验失败时不能改动目录权限"
        );

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：最终路径是符号链接时拒绝；`ensure_private_dir` 不能跟随链接创建 / chmod。
    #[cfg(unix)]
    #[test]
    fn ki21_validate_private_dir_path_rejects_symlink_target() {
        let dir = temp_dir("validate-symlink");
        ensure_dir(&dir, 0o700).unwrap();
        let victim = dir.join("victim");
        ensure_dir(&victim, 0o700).unwrap();
        let link = dir.join("data");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = validate_private_dir_path(&link).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("符号链接"), "错误信息: {err}");

        let err = ensure_private_dir(&link, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(mode_of(&victim), 0o700, "不能 chmod 到符号链接目标");

        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21 复审：归一化必须去掉尾斜杠、末尾 `/.` 与重复分隔符。
    #[cfg(unix)]
    #[test]
    fn ki21_review_normalize_private_dir_path_strips_trailing_separators() {
        for (raw, expected) in [
            ("/tmp/rb//data/", "/tmp/rb/data"),
            ("/tmp/rb/data/.", "/tmp/rb/data"),
            ("/tmp/rb/./data", "/tmp/rb/data"),
            ("/tmp/rb/data///", "/tmp/rb/data"),
            ("/", "/"),
        ] {
            let got = normalize_private_dir_path(Path::new(raw)).unwrap();
            assert_eq!(got, PathBuf::from(expected), "raw={raw}");
            assert!(
                !got.to_string_lossy().ends_with('/') || expected == "/",
                "归一化结果不能带尾斜杠: {raw} -> {}",
                got.display()
            );
        }
        for raw in [
            "",
            "relative",
            "./data",
            "../data",
            "/tmp/../etc",
            "/tmp/a/..",
        ] {
            assert!(
                normalize_private_dir_path(Path::new(raw)).is_err(),
                "raw={raw:?} 必须被拒绝"
            );
        }
    }

    /// KI-21 复审：`link`、`link/`、`link/.`、`link//` 都不得跟随最终符号链接。
    ///
    /// 内核会把带尾斜杠 / `/.` 的路径解析进链接目标，归一化后必须统一按
    /// 链接本身检查；失败时 victim 的权限不能有任何变化。
    #[cfg(unix)]
    #[test]
    fn ki21_review_trailing_separator_symlink_bypass_is_rejected() {
        let dir = temp_dir("review-trailing-symlink");
        ensure_dir(&dir, 0o700).unwrap();
        let victim = dir.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();
        let link = dir.join("data");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let link_text = link.to_string_lossy().into_owned();
        for raw in [
            link.clone(),
            PathBuf::from(format!("{link_text}/")),
            PathBuf::from(format!("{link_text}/.")),
            PathBuf::from(format!("{link_text}//")),
        ] {
            let err = validate_private_dir_path(&raw).unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::PermissionDenied,
                "raw={} 必须按符号链接拒绝: {err}",
                raw.display()
            );
            assert!(
                err.to_string().contains("符号链接"),
                "raw={} 错误信息应点明符号链接: {err}",
                raw.display()
            );

            let err = harden_dir(&raw, 0o700).unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::PermissionDenied,
                "raw={} harden_dir 必须拒绝: {err}",
                raw.display()
            );

            let err = ensure_private_dir(&raw, 0o700).unwrap_err();
            assert_eq!(
                err.kind(),
                io::ErrorKind::PermissionDenied,
                "raw={} ensure_private_dir 必须拒绝: {err}",
                raw.display()
            );

            assert_eq!(
                mode_of(&victim),
                0o755,
                "raw={} 不能 chmod 到符号链接目标",
                raw.display()
            );
            assert!(fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21 复审：中间组件的符号链接同样拒绝，且不能通过链接创建 / chmod 目标。
    #[cfg(unix)]
    #[test]
    fn ki21_review_intermediate_symlink_is_rejected_without_touching_target() {
        let dir = temp_dir("review-intermediate-symlink");
        ensure_dir(&dir, 0o700).unwrap();
        let other = dir.join("other");
        fs::create_dir(&other).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
        let real = dir.join("real");
        fs::create_dir(&real).unwrap();
        let link = real.join("link");
        std::os::unix::fs::symlink(&other, &link).unwrap();

        let target = link.join("sub");
        let err = validate_private_dir_path(&target).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("符号链接"), "错误信息: {err}");

        let err = ensure_private_dir(&target, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let err = harden_dir(&target, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        assert!(
            !other.join("sub").exists(),
            "不能通过中间符号链接创建目标目录"
        );
        assert_eq!(mode_of(&other), 0o755, "不能 chmod 到中间符号链接目标");
        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21 复审：正常目录的尾斜杠 / 末尾 `/.` 归一化后可以创建与收紧。
    #[cfg(unix)]
    #[test]
    fn ki21_review_trailing_separator_real_dir_is_normalized_and_usable() {
        let dir = temp_dir("review-trailing-real");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        // harden_dir 接受 `dir/` 并收紧真实目录。
        let with_slash = PathBuf::from(format!("{}/", dir.display()));
        harden_dir(&with_slash, 0o700).unwrap();
        assert_eq!(mode_of(&dir), 0o700);

        // ensure_private_dir 用 `nested/` 创建的是不带尾斜杠的同一目录。
        let nested = dir.join("nested");
        let nested_slash = PathBuf::from(format!("{}/.", nested.display()));
        ensure_private_dir(&nested_slash, 0o700).unwrap();
        assert_eq!(mode_of(&nested), 0o700);
        assert!(fs::symlink_metadata(&nested).unwrap().is_dir());

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn ki21_validate_then_harden_safe_dir_is_idempotent() {
        let dir = temp_dir("validate-harden");
        ensure_private_dir(&dir, 0o700).unwrap();
        validate_private_dir_path(&dir).expect("安全目录必须通过校验");

        harden_dir(&dir, 0o700).unwrap();
        harden_dir(&dir, 0o700).unwrap();
        assert_eq!(mode_of(&dir), 0o700);

        ensure_private_dir(Path::new(""), 0o700).expect("空路径保持 no-op");
        let err = harden_dir(Path::new(""), 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(validate_private_dir_path(Path::new("")).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    /// KI-21：`set_private_umask` 签名固定（返回旧 umask，非 Unix 为 `None`）。
    ///
    /// 该函数会修改进程级全局 umask，测试并行时无法安全调用，因此这里只做
    /// 编译期的签名验证，不实际执行。
    #[test]
    fn ki21_set_private_umask_has_stable_signature() {
        let f: fn() -> Option<u32> = set_private_umask;
        let _ = f;
    }

    /// v0.3.5 确定性 TOCTOU：先拿到已校验目录的 fd，再把路径 rename 走并换成
    /// 指向 victim 的符号链接；最后基于 fd 收紧权限，victim 必须保持不变。
    ///
    /// 不使用 sleep 竞态：`open_existing_private_dir_fd` 与 `harden_open_dir_fd`
    /// 分别对应真实实现的「打开并校验」与「基于 fd 收紧」两步，路径替换发生在
    /// 两者之间，与攻击者的替换窗口完全等价。
    #[cfg(target_os = "linux")]
    #[test]
    fn v035_linux_toctou_fd_chmod_does_not_follow_replaced_path() {
        let root = temp_dir("v035-toctou");
        ensure_dir(&root, 0o700).unwrap();
        let target = root.join("data");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let victim = root.join("victim");
        fs::create_dir(&victim).unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o755)).unwrap();

        // 1. 打开并校验目标目录，拿到 fd（此后不再信任路径）。
        let dir = open_existing_private_dir_fd(&target).expect("已有目录必须能打开");

        // 2. 路径被替换：原目录改名，原位置变成指向 victim 的符号链接。
        let moved = root.join("moved");
        fs::rename(&target, &moved).unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();

        // 3. 基于 fd 收紧：只能作用于第 1 步打开的原目录。
        harden_open_dir_fd(&target, &dir, 0o700).unwrap();

        assert_eq!(mode_of(&moved), 0o700, "原目录必须按 fd 被收紧");
        assert_eq!(
            mode_of(&victim),
            0o755,
            "路径已被替换成符号链接，绝不能 chmod 到 victim"
        );
        assert!(fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());

        // 4. 公共 API 重新解析路径时必须拒绝该符号链接（不是 fd 后门）。
        let err = harden_dir(&target, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("符号链接"), "错误信息: {err}");
        let err = ensure_private_dir(&target, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(mode_of(&victim), 0o755, "公共 API 也不能 chmod victim");

        let _ = fs::remove_dir_all(&root);
    }

    /// v0.3.5：非 sticky 的 group/other 可写祖先目录必须拒绝，且不能先创建子目录。
    #[cfg(target_os = "linux")]
    #[test]
    fn v035_linux_rejects_world_writable_non_sticky_ancestor() {
        let root = temp_dir("v035-wide-ancestor");
        fs::create_dir_all(&root).unwrap();
        let wide = root.join("wide");
        fs::create_dir(&wide).unwrap();
        fs::set_permissions(&wide, fs::Permissions::from_mode(0o777)).unwrap();
        let child = wide.join("data");

        let err = ensure_private_dir(&child, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("可写"),
            "错误信息应点明祖先可写: {err}"
        );
        assert!(!child.exists(), "拒绝时不能通过可写祖先创建子目录");
        assert_eq!(mode_of(&wide), 0o777, "拒绝时不能改动祖先权限");

        let _ = fs::remove_dir_all(&root);
    }

    /// v0.3.5：root 拥有的 sticky `/tmp` 可以作为祖先遍历，但作为最终目录必须拒绝，
    /// 且校验 / 收紧都不能改动真实 `/tmp` 的权限位。
    #[cfg(target_os = "linux")]
    #[test]
    fn v035_linux_root_sticky_tmp_allowed_as_ancestor_but_rejected_as_final() {
        // 祖先：/tmp 是 root 拥有的 sticky 目录，允许在其专属子目录下创建私有目录。
        let owned = temp_dir("v035-tmp-ancestor");
        ensure_private_dir(&owned, 0o700).unwrap();
        assert_eq!(mode_of(&owned), 0o700);

        // 最终：直接对 /tmp 的 fd 做最终目录校验必须因 sticky 拒绝。
        let tmp = Path::new("/tmp");
        let before = fs::metadata(tmp).unwrap().permissions().mode() & 0o7777;
        let dir = open_existing_private_dir_fd(tmp).expect("/tmp 作为 sticky 祖先必须能打开");

        let err = validate_final_dir_fd(tmp, &dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("sticky"), "错误信息: {err}");

        let err = harden_open_dir_fd(tmp, &dir, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            fs::metadata(tmp).unwrap().permissions().mode() & 0o7777,
            before,
            "拒绝 sticky 最终目录时绝不能 chmod 真实 /tmp"
        );

        // 公共 API 在静态规则阶段就拒绝 /tmp，同样不能改动其权限。
        assert!(ensure_private_dir(tmp, 0o700).is_err());
        assert!(harden_dir(tmp, 0o700).is_err());
        assert_eq!(
            fs::metadata(tmp).unwrap().permissions().mode() & 0o7777,
            before
        );

        let _ = fs::remove_dir_all(&owned);
    }

    /// v0.3.5：最终目录 owner 必须等于 euid（root 运行时必须 root 拥有）。
    ///
    /// root 可以直接 chown 到 nobody 来构造「他人拥有」；非 root 进程无法 chown，
    /// 直接跳过该用例。
    #[cfg(target_os = "linux")]
    #[test]
    fn v035_linux_rejects_final_dir_owned_by_other_user() {
        // SAFETY: geteuid 没有参数，也没有内存安全前提。
        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let root = temp_dir("v035-owner");
        ensure_dir(&root, 0o700).unwrap();
        let other = root.join("other-owned");
        fs::create_dir(&other).unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::chown(&other, Some(65534), Some(65534))
            .expect("root 必须能把测试目录 chown 到 nobody");

        // 静态校验：所有进程（含 root）都要求 euid 拥有最终目录。
        let err = validate_private_dir_path(&other).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("其他用户"), "错误信息: {err}");

        // 创建 / 收紧都在改动之前失败，权限保持不变。
        let err = ensure_private_dir(&other, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        let err = harden_dir(&other, 0o700).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(mode_of(&other), 0o755, "拒绝时不能 chmod 他人拥有的目录");

        // fd 层最终校验同样拒绝（不依赖路径 lstat 规则）。
        let dir = open_existing_private_dir_fd(&other).expect("祖先均为 root 拥有，fd 必须能打开");
        let err = validate_final_dir_fd(&other, &dir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().contains("其他用户"), "错误信息: {err}");
        assert_eq!(mode_of(&other), 0o755);
        drop(dir);

        // 恢复 ownership 后再清理，避免把 nobody 拥有的目录留在 /tmp。
        let _ = std::os::unix::fs::chown(&other, Some(0), Some(0));
        let _ = fs::remove_dir_all(&root);
    }
}
