use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// 当前 Unix 毫秒时间戳。
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 读取文件并去掉首尾空白。
pub fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn hostname() -> String {
    read_trimmed("/etc/hostname")
        .or_else(|| read_trimmed("/proc/sys/kernel/hostname"))
        .unwrap_or_else(|| "unknown".to_string())
}

/// 内核启动标识。用于判断计数器是否因重启归零。
pub fn boot_id() -> String {
    read_trimmed("/proc/sys/kernel/random/boot_id").unwrap_or_else(|| "unknown".to_string())
}

/// `/etc/os-release` 里的 PRETTY_NAME。
pub fn os_pretty_name() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|v| v.trim_matches('"').to_string())
            })
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

pub fn arch() -> String {
    std::env::consts::ARCH.to_string()
}

/// 确保目录存在。
pub fn ensure_dir(path: impl AsRef<Path>) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

/// 常量时间比较。用于 token 校验，避免按字节提前返回泄漏前缀。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// 选一个五位数随机端口（20000–64999），并确认当前能绑定。
///
/// 刻意避开 10000 以下和常见的 8080/8443 等，降低与既有服务冲突、被扫描爆破的概率。
pub fn pick_free_port() -> std::io::Result<u16> {
    pick_free_port_excluding(&[])
}

/// 同上，但排除已占用的端口（用于同一进程内分配多个端口）。
pub fn pick_free_port_excluding(exclude: &[u16]) -> std::io::Result<u16> {
    use std::net::TcpListener;
    for _ in 0..64 {
        let port = 20_000 + (rand::random::<u16>() % 45_000);
        if exclude.contains(&port) {
            continue;
        }
        if TcpListener::bind(("0.0.0.0", port)).is_ok() {
            return Ok(port);
        }
    }
    // 极端情况下退回内核分配的临时端口
    let listener = TcpListener::bind("0.0.0.0:0")?;
    Ok(listener.local_addr()?.port())
}

/// 探测本机默认出口 IPv4（UDP connect 只查路由表，不发包）。
pub fn primary_ipv4() -> Option<std::net::IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// 从 `host:port` 或 `[::1]:port` 中取出端口。
pub fn port_of(addr: &str) -> Option<u16> {
    addr.rsplit(':').next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picked_port_is_five_digits_and_free() {
        let port = pick_free_port().unwrap();
        assert!(port >= 10_000, "端口 {port} 不是五位数");
        // 分配后应能立即绑定
        std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    }

    #[test]
    fn parses_port_from_addr() {
        assert_eq!(port_of("0.0.0.0:27431"), Some(27431));
        assert_eq!(port_of("127.0.0.1:51877"), Some(51877));
        assert_eq!(port_of("[::1]:9000"), Some(9000));
        assert_eq!(port_of("bad"), None);
    }

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
