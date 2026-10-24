//! 安装锁：全局锁跨角色互斥、角色锁同角色互斥、不阻塞、Drop 后释放。
//!
//! 锁文件位于 `/run`，只有 root 能创建；非 root 环境跳过（锁逻辑本身由这些
//! 用例覆盖，CI 容器通常以非 root 运行）。

use std::path::Path;

use rustboard_install::{detect_system, InstallLock, Role, GLOBAL_LOCK_PATH};

#[test]
fn role_lock_is_exclusive_and_released_on_drop() {
    let first = match InstallLock::acquire(Role::Agent) {
        Ok(lock) => lock,
        Err(err) => {
            // 非 root / 无 /run 写权限的 CI 环境跳过；锁逻辑本身由这里覆盖。
            eprintln!("跳过安装锁测试（无法创建锁文件）: {err:#}");
            return;
        }
    };

    assert_eq!(
        first.path(),
        Path::new("/run/rustboard-install-agent.lock"),
        "锁必须放在 root 拥有的 /run，不能使用 1777 的 /run/lock"
    );
    assert!(first.path().is_file(), "锁文件应保留在磁盘上");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(first.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "锁文件必须是 0600");
    }

    let second = match InstallLock::acquire(Role::Agent) {
        Ok(_lock) => panic!("同角色第二次 acquire 必须失败"),
        Err(err) => err,
    };
    let message = format!("{second:#}");
    assert!(
        message.contains("另一个 RustBoard agent 安装/卸载/升级正在运行"),
        "{message}"
    );
    // 不阻塞：第二次 acquire 立即返回错误，第一次仍持锁。
    assert!(first.path().is_file());

    drop(first);
    let third = InstallLock::acquire(Role::Agent).expect("Drop 释放后应能再次获取");
    drop(third);
}

#[test]
fn global_lock_is_exclusive_and_released_on_drop() {
    if detect_system().euid != 0 {
        eprintln!("非 root，跳过全局安装锁测试");
        return;
    }

    let first = InstallLock::acquire_global().expect("root 应能获取全局安装锁");
    assert_eq!(
        first.path(),
        Path::new(GLOBAL_LOCK_PATH),
        "全局锁必须位于 /run/rustboard-install.lock"
    );
    assert_eq!(GLOBAL_LOCK_PATH, "/run/rustboard-install.lock");
    assert!(
        !first.path().starts_with(Path::new("/run/lock")),
        "不能使用 1777 的 /run/lock"
    );
    assert!(first.path().is_file(), "锁文件应保留在磁盘上");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(first.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "锁文件必须是 0600");
    }

    // 同一进程内再次 open + flock 也会冲突：全局锁必须只允许一个持有者。
    let second = match InstallLock::acquire_global() {
        Ok(_lock) => panic!("全局锁第二次 acquire 必须失败"),
        Err(err) => err,
    };
    let message = format!("{second:#}");
    assert!(
        message.contains("另一个 RustBoard 安装/卸载/升级正在运行"),
        "{message}"
    );
    assert!(message.contains(GLOBAL_LOCK_PATH), "{message}");

    drop(first);
    let third = InstallLock::acquire_global().expect("Drop 释放后应能再次获取全局锁");
    drop(third);
}
