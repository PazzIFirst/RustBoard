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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_works() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
