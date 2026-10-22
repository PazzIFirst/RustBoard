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

/// 创建目录（含父目录），新建目录的权限为 `mode`。
///
/// 已经存在的目录保持原权限不变：调用方可能传入 `/tmp`、`/etc` 这类共享目录，
/// 无条件收紧会把系统目录改坏。敏感目录应位于私有父目录下。
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
}
