//! 安装锁：全局锁（跨角色）与兼容用的角色锁。
//!
//! 安装 / 卸载 / 升级会同时改 config / unit / state，必须串行；否则两个进程
//! 各自 load→save `install-state.toml` 时，后写者会把先写者的角色记录整个覆盖。
//! 这里用 `flock` 排他锁，**不阻塞**——拿不到锁立即报错，避免运维脚本无限等待。
//!
//! 两把锁：
//! - **全局锁** [`InstallLock::acquire_global`]：固定 `/run/rustboard-install.lock`，
//!   保护同机共享的 `install-state.toml` 与 unit / 二进制等资源，hub / panel /
//!   agent 之间也互斥。新代码一律使用这把锁。
//! - **角色锁** [`InstallLock::acquire`]：`/run/rustboard-install-<role>.lock`，
//!   保留给旧调用方与兼容测试；它只串行同一角色，**不能**防止不同角色并发写
//!   state，因此不能替代全局锁。
//!
//! 锁放在 `/run`（0755、root 拥有），**不用** `/run/lock`：后者是 1777 sticky，
//! 普通用户可以预置或长期占用锁文件，造成 root 安装 DoS。`O_NOFOLLOW` 与属主 /
//! 权限校验进一步避免他人预置符号链接或文件来干扰 root 安装。锁文件保留在磁盘上
//! （不删除），进程退出或 [`InstallLock`] 被 Drop 时内核自动释放 flock；残留的锁
//! 文件本身不表示“正在运行”。
//!
//! hub 调起 panel 子进程时，父子进程共享同一个安装流程，子进程**不能再次获取
//! 全局锁**（同一进程内两次 open + flock 也会自锁）。父进程持锁后设置
//! `RUSTBOARD_INSTALL_LOCK_HELD=1`，子进程用 [`InstallLock::inherited`] 判断并跳过。
//! 该环境变量只是父子进程间的约定，**不是安全边界**：安装器本身已经要求 root，
//! 任何能设置该变量的调用者本来就拥有 root 能力；绝不能把它当作权限校验。

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::Role;

/// 全局安装锁文件；跨角色保护共享的安装状态。
pub const GLOBAL_LOCK_PATH: &str = "/run/rustboard-install.lock";

/// 父进程已持有全局锁的标记环境变量；值为精确的 `1` 时视为已继承。
pub const LOCK_HELD_ENV: &str = "RUSTBOARD_INSTALL_LOCK_HELD";

/// 锁的作用域，仅用于生成准确的错误信息。
#[derive(Clone, Copy)]
enum LockScope {
    Global,
    Role(Role),
}

/// 安装锁；Drop 时关闭 fd（内核释放 flock），锁文件保留。
pub struct InstallLock {
    /// 持有打开的文件描述符即持有 flock；不读取内容。
    _file: File,
    path: PathBuf,
}

impl InstallLock {
    /// 获取**全局**排他锁；已被占用时立即返回错误，不阻塞。
    ///
    /// 锁路径固定为 [`GLOBAL_LOCK_PATH`]。`/run` 是 root 拥有的 0755 目录，普通
    /// 用户无法预置或占用锁文件；文件以 0600 创建，打开时使用 `O_NOFOLLOW`，
    /// 并校验权限正好 0600、属主为当前 euid，最后 `flock(LOCK_EX | LOCK_NB)`。
    ///
    /// 任何会写 `install-state.toml` / unit / 二进制的安装、卸载、升级流程都必须
    /// 在读取 state 之前获取本锁，并持有到全部写入结束。角色锁 [`Self::acquire`]
    /// 不覆盖其他角色，不能替代本方法。
    pub fn acquire_global() -> Result<Self> {
        Self::lock(PathBuf::from(GLOBAL_LOCK_PATH), LockScope::Global)
    }

    /// 获取角色排他锁；已被占用时立即返回错误，不阻塞。
    ///
    /// 锁路径固定为 `/run/rustboard-install-<role>.lock`。`/run` 是 root 拥有的
    /// 0755 目录，普通用户无法预置或占用锁文件；文件以 0600 创建，Unix 下使用
    /// `flock(LOCK_EX | LOCK_NB)`。
    ///
    /// 本方法保留给旧调用方与兼容测试。它只串行同一角色，**不能**保护 hub / panel
    /// / agent 共享的 `install-state.toml`；新代码应使用 [`Self::acquire_global`]。
    pub fn acquire(role: Role) -> Result<Self> {
        Self::lock(lock_path(role), LockScope::Role(role))
    }

    /// 父进程是否已持有全局锁（`RUSTBOARD_INSTALL_LOCK_HELD=1`）。
    ///
    /// 只用于 hub 调起 panel 等子进程时避免重复加锁：父进程持锁后设置该环境变量，
    /// 子进程据此跳过 [`Self::acquire_global`]，而不是让子进程再拿同一把锁导致
    /// 必然失败。父进程必须**一直持有全局锁到子进程退出**；该标记本身不延长锁的
    /// 生命周期，父进程提前释放后子进程就失去了串行保护。值必须精确为 `1`；其他值
    /// （包括 `true` / `0` / 空串）都视为未继承。
    ///
    /// **这不是安全边界**：环境变量可以被调用者伪造，但调用者已经是能执行安装器
    /// 的 root；安全判断只依赖锁文件本身（路径、0600、属主、O_NOFOLLOW、flock）。
    /// [`Self::acquire_global`] 不会自动读取该标记，调用方必须显式判断：
    ///
    /// ```ignore
    /// let _global = if InstallLock::inherited() {
    ///     None
    /// } else {
    ///     Some(InstallLock::acquire_global()?)
    /// };
    /// ```
    pub fn inherited() -> bool {
        inherited_from(std::env::var_os(LOCK_HELD_ENV).as_deref())
    }

    /// 本次持有的锁文件路径（文件会保留，供排查占用者）。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 打开（不存在则创建）、校验并加锁。
    fn lock(path: PathBuf, scope: LockScope) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("创建安装锁 {} 失败", path.display()))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = file
                .metadata()
                .with_context(|| format!("读取安装锁 {} 元数据失败", path.display()))?;
            if !meta.is_file() {
                bail!(
                    "安装锁 {} 不是普通文件，拒绝使用（可能是他人预置的 FIFO / 设备）",
                    path.display()
                );
            }
            let mode = meta.mode() & 0o777;
            if mode != 0o600 {
                bail!(
                    "安装锁 {} 权限为 {mode:04o}，要求正好 0600（拒绝使用他人预置的锁文件）",
                    path.display()
                );
            }
            let uid = meta.uid();
            let euid = crate::system::effective_uid();
            if uid != euid {
                bail!(
                    "安装锁 {} 属主 uid={uid}（当前 euid={euid}），拒绝使用他人预置的锁文件",
                    path.display()
                );
            }
        }

        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;

            // SAFETY: fd 来自仍存活的 File，flock 只对该 fd 操作，不涉及内存安全。
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    bail!("{}", busy_message(scope, &path));
                }
                return Err(err).with_context(|| format!("获取安装锁 {} 失败", path.display()));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = scope;
            bail!("安装锁仅支持 Unix 平台");
        }

        Ok(Self { _file: file, path })
    }
}

/// 被占用错误文案：全局锁不区分角色，角色锁带上角色名（保持既有文案）。
#[cfg(unix)]
fn busy_message(scope: LockScope, path: &Path) -> String {
    match scope {
        LockScope::Global => format!(
            "另一个 RustBoard 安装/卸载/升级正在运行（锁 {} 已被占用）",
            path.display()
        ),
        LockScope::Role(role) => format!(
            "另一个 RustBoard {role} 安装/卸载/升级正在运行（锁 {} 已被占用）",
            path.display()
        ),
    }
}

/// 环境变量解析：只有精确的 `1` 表示继承。
fn inherited_from(value: Option<&OsStr>) -> bool {
    value == Some(OsStr::new("1"))
}

/// 角色锁文件路径：固定 `/run`（root 0755），不使用 1777 的 `/run/lock`。
fn lock_path(role: Role) -> PathBuf {
    Path::new("/run").join(format!("rustboard-install-{role}.lock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_flag_is_exactly_one() {
        assert!(inherited_from(Some(OsStr::new("1"))));
        for value in ["0", "true", "yes", "", " 1", "1\n", "01"] {
            assert!(
                !inherited_from(Some(OsStr::new(value))),
                "{value:?} 不应被视为已继承"
            );
        }
        assert!(!inherited_from(None));
    }

    #[cfg(unix)]
    #[test]
    fn occupied_message_distinguishes_global_and_role() {
        let global_path = Path::new(GLOBAL_LOCK_PATH);
        let message = busy_message(LockScope::Global, global_path);
        assert!(
            message.contains("另一个 RustBoard 安装/卸载/升级正在运行"),
            "{message}"
        );
        assert!(message.contains(GLOBAL_LOCK_PATH), "{message}");

        let role_message = busy_message(LockScope::Role(Role::Panel), global_path);
        assert!(
            role_message.contains("另一个 RustBoard panel 安装/卸载/升级正在运行"),
            "{role_message}"
        );
    }
}
