//! 敏感文件的原子写入与目录权限。
//!
//! 配置、token、私钥这类文件必须从创建的第一刻起就是 0600，不能先按 umask
//! 创建再 chmod（两者之间存在可被读取的窗口）。这里统一用「同目录临时文件 +
//! rename」实现原子替换，并尽量把父目录 fsync 落盘。
//!
//! H3：临时文件名必须是随机的，并以 `create_new` + `O_NOFOLLOW` 打开，
//! 防止攻击者提前在可预测的临时名上放符号链接，把敏感内容写进别的文件。
//! 目标路径本身是符号链接时也直接拒绝，避免误改链接指向。

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
/// - 已存在的最终路径不是目录、带 sticky 位，或（非 root 运行时）不属于当前
///   有效用户。
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
        // root 允许其他 owner（常见部署：数据目录预留给服务用户）；非 root 必须自己拥有。
        if euid != 0 && meta.uid() != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} 属于其他用户（uid {}），当前有效用户为 {euid}",
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
pub fn harden_dir(path: &Path, mode: u32) -> io::Result<()> {
    // 先校验 mode 与路径：两者都是调用方的编程错误，必须在 chmod 之前失败。
    validate_private_dir_mode(path, mode)?;
    // 归一化后所有元数据 / chmod 操作都作用于不带尾斜杠的路径，避免 `link/`
    // 被内核解析进符号链接目标。
    let path = normalize_private_dir_path(path)?;
    validate_normalized_private_dir_path(&path)?;

    harden_validated_dir(&path, mode)
}

/// 对已经归一化并校验过的目录执行「只收紧」的 chmod。
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
    ensure_dir(&path, mode)?;
    // 复用已校验结果，避免第二次校验与创建之间再引入新的解析差异。
    harden_validated_dir(&path, mode)
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
}
