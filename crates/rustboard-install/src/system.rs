//! 系统探测与安装前置条件。

use std::net::TcpListener;
use std::path::Path;

use anyhow::{bail, Result};

use crate::util::random_u64;

/// 空闲端口范围：五位数，避开 10000 以下与常见服务端口。
pub const PORT_MIN: u16 = 20_000;
/// 端口范围上界（含）。
pub const PORT_MAX: u16 = 64_999;
/// 随机尝试次数；避免固定端口扫描死循环。
const PORT_ATTEMPTS: usize = 256;

/// 当前系统信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemInfo {
    pub os_name: String,
    pub arch: String,
    pub systemd: bool,
    pub euid: u32,
}

/// 探测系统信息。
///
/// `systemd` 以 `/run/systemd/system` 是否存在判断（容器里通常不存在），
/// `euid` 取当前进程有效用户 ID。
pub fn detect_system() -> SystemInfo {
    SystemInfo {
        os_name: rustboard_common::util::os_pretty_name(),
        arch: std::env::consts::ARCH.to_string(),
        systemd: systemd_available(),
        euid: effective_uid(),
    }
}

/// 要求以 root 运行。
///
/// Phase A 统一以 root 运行：配置/私钥必须 0600，非 root 服务读不到；
/// 专用用户在 Phase E 评估。
pub fn require_root() -> Result<()> {
    let euid = effective_uid();
    if euid != 0 {
        bail!("需要 root 权限安装系统服务（当前 euid={euid}）");
    }
    Ok(())
}

/// 要求 systemd 可用。
pub fn require_systemd() -> Result<()> {
    if !systemd_available() {
        bail!("未检测到 systemd（缺少 /run/systemd/system）；请使用 --no-systemd 或容器环境");
    }
    Ok(())
}

/// 在 20000–64999 中随机选一个可绑定到 127.0.0.1 的端口。
///
/// 先随机挑端口再 bind，不做固定端口顺序扫描；排除列表里的端口直接跳过。
/// 最多尝试固定次数（256），失败时返回错误，不静默回退到内核临时端口
/// （安装器打印的端口必须稳定落在五位数范围内）。
pub fn pick_free_port(exclude: &[u16]) -> Result<u16> {
    let span = u32::from(PORT_MAX) - u32::from(PORT_MIN) + 1;
    for _ in 0..PORT_ATTEMPTS {
        let port = PORT_MIN + (random_u64() % u64::from(span)) as u16;
        if exclude.contains(&port) {
            continue;
        }
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    bail!(
        "在 {PORT_MIN}–{PORT_MAX} 范围内随机尝试 {PORT_ATTEMPTS} 次仍未找到空闲端口（排除 {} 个）",
        exclude.len()
    )
}

fn systemd_available() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// 当前进程有效用户 ID。
///
/// state / 安装前缀归属校验与安装锁共用这一个入口，避免各处对“当前用户”的
/// 判断漂移。
pub(crate) fn effective_uid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: geteuid 没有指针参数，也没有内存安全前提，只返回当前进程 euid。
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_port_is_in_range_and_free() {
        let port = pick_free_port(&[]).unwrap();
        assert!((PORT_MIN..=PORT_MAX).contains(&port), "{port}");
        TcpListener::bind(("127.0.0.1", port)).unwrap();
    }

    #[test]
    fn excluded_ports_are_never_returned() {
        let all: Vec<u16> = (PORT_MIN..=PORT_MAX).collect();
        assert!(pick_free_port(&all).is_err());
    }

    #[test]
    fn system_info_is_consistent() {
        let info = detect_system();
        assert!(!info.os_name.is_empty());
        assert_eq!(info.arch, std::env::consts::ARCH);
        assert_eq!(info.systemd, Path::new("/run/systemd/system").is_dir());
        assert_eq!(info.euid, effective_uid());
    }

    #[test]
    fn root_check_matches_euid() {
        if effective_uid() == 0 {
            require_root().unwrap();
        } else {
            assert!(require_root().is_err());
        }
    }
}
