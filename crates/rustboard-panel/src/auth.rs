//! 面板认证：Argon2id 密码校验、内存会话表、按 IP 登录限速。
//!
//! 三条安全约束：
//! 1. Argon2id 参数固定为 m=64 MiB、t=3、p=4，哈希以 PHC 串落盘；
//! 2. 登录限速必须先于哈希校验（被锁定时不再消耗 64 MiB 内存）；
//! 3. 内存表都有上限与过期清理，避免登录接口被打爆内存。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};

use anyhow::{anyhow, Result};
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::http::{header, HeaderMap};
use rand::RngCore;

/// 会话 Cookie 名。
pub const SESSION_COOKIE: &str = "rb_session";
/// 同一 IP 连续失败多少次后锁定。
pub const MAX_LOGIN_FAILURES: u32 = 5;
/// 锁定时长（毫秒）。
pub const LOCKOUT_MS: i64 = 15 * 60 * 1000;
/// 会话令牌随机字节数（hex 后 64 个字符）。
pub const SESSION_TOKEN_BYTES: usize = 32;
/// 内存会话表上限，超出后淘汰最早过期的会话。
const MAX_SESSIONS: usize = 1024;
/// 登录限速表上限，超出后淘汰最久未活动的记录。
const MAX_RATE_ENTRIES: usize = 4096;
/// Argon2 内存开销（KiB）。
const ARGON2_M_COST_KIB: u32 = 64 * 1024;
/// Argon2 迭代次数。
const ARGON2_T_COST: u32 = 3;
/// Argon2 并行度。
const ARGON2_P_COST: u32 = 4;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // 认证数据被 poison 时也应继续服务（旧数据仍可读），而不是整站 panic。
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 固定参数的 Argon2id 实例。
pub fn argon2id() -> Result<Argon2<'static>> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .map_err(|e| anyhow!("Argon2 参数非法: {e}"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// 生成 Argon2id PHC 串。调用方负责只在首次初始化时展示明文密码。
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2id()?
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("生成密码哈希失败: {e}"))?;
    Ok(hash.to_string())
}

/// 判断一个串是否是合法的 Argon2id PHC（启动时快速失败，避免带着坏配置起服务）。
pub fn validate_phc(phc: &str) -> bool {
    PasswordHash::new(phc.trim())
        .map(|parsed| parsed.algorithm.as_str() == "argon2id")
        .unwrap_or(false)
}

/// 校验密码。只接受 Argon2id 的 PHC 串；参数以 PHC 串里的为准。
pub fn verify_password(password: &str, phc: &str) -> bool {
    let phc = phc.trim();
    if phc.is_empty() {
        return false;
    }
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    if parsed.algorithm.as_str() != "argon2id" {
        return false;
    }
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// 随机 hex 串，使用操作系统 CSPRNG。
fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// 内存会话表。重启后全部失效，符合方案要求。
#[derive(Debug)]
pub struct SessionStore {
    inner: Mutex<HashMap<String, i64>>,
    ttl_ms: i64,
}

impl SessionStore {
    pub fn new(ttl_hours: u64) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl_ms: (ttl_hours.max(1) as i64).saturating_mul(3_600_000),
        }
    }

    /// 创建会话，返回随机令牌。
    pub fn create(&self, now_ms: i64) -> String {
        self.cleanup(now_ms);
        let mut sessions = lock(&self.inner);
        if sessions.len() >= MAX_SESSIONS {
            if let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, expires_at)| **expires_at)
                .map(|(token, _)| token.clone())
            {
                sessions.remove(&oldest);
            }
        }
        let token = random_hex(SESSION_TOKEN_BYTES);
        sessions.insert(token.clone(), now_ms.saturating_add(self.ttl_ms));
        token
    }

    /// 校验会话；过期条目顺手删除。
    pub fn is_authenticated(&self, token: &str, now_ms: i64) -> bool {
        if token.is_empty() {
            return false;
        }
        let mut sessions = lock(&self.inner);
        match sessions.get(token) {
            Some(expires_at) if *expires_at > now_ms => true,
            Some(_) => {
                sessions.remove(token);
                false
            }
            None => false,
        }
    }

    /// 登出：删除会话。
    pub fn revoke(&self, token: &str) {
        if token.is_empty() {
            return;
        }
        lock(&self.inner).remove(token);
    }

    /// 清理过期会话。
    pub fn cleanup(&self, now_ms: i64) {
        lock(&self.inner).retain(|_, expires_at| *expires_at > now_ms);
    }

    /// 当前会话数（仅测试用）。
    #[cfg(test)]
    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }
}

#[derive(Debug, Default)]
struct AttemptState {
    failures: u32,
    last_failure_ms: i64,
    locked_until_ms: i64,
}

/// 一次登录尝试的限流决策。
pub enum AttemptDecision<'a> {
    /// 已在同一把锁内预占一个失败名额；guard 必须在成功/失败后显式 disarm，
    /// 提前返回或被取消时由 Drop 归还名额。
    Allowed(AttemptGuard<'a>),
    /// 锁定中或并发尝试已满额；附带建议的 Retry-After 秒数。
    TooMany(u64),
}

/// 登录限流预占名额的 RAII 守卫。
///
/// 密码校验成功 → 调用 `record_success` 后 `disarm`；
/// 密码错误 → 调用 `record_failure` 后 `disarm`；
/// 内部错误 / 客户端断开 / handler 被取消 → 直接 Drop，归还预占名额，避免
/// 5 个被取消的请求把该 IP 白锁 15 分钟。
pub struct AttemptGuard<'a> {
    limiter: &'a LoginLimiter,
    ip: IpAddr,
    armed: bool,
}

impl AttemptGuard<'_> {
    /// 正常结束本次尝试，不再归还名额（失败计数已由 record_failure 接管）。
    pub fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for AttemptGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.limiter.release_attempt(self.ip);
        }
    }
}

/// 按 IP 的登录限速器。
#[derive(Debug, Default)]
pub struct LoginLimiter {
    inner: Mutex<HashMap<IpAddr, AttemptState>>,
}

impl LoginLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// 原子地检查锁定状态并预占一个失败名额。
    ///
    /// 必须在 Argon2 校验之前调用：即使 N 个请求同时到达，同一把锁也保证
    /// 最多 `MAX_LOGIN_FAILURES` 个进入校验，其余立即 `TooMany`，
    /// 不存在“先检查后计数”的并发窗口。
    pub fn begin_attempt(&self, ip: IpAddr, now_ms: i64) -> AttemptDecision<'_> {
        let mut attempts = lock(&self.inner);
        prune(&mut attempts, now_ms);
        if attempts.len() >= MAX_RATE_ENTRIES && !attempts.contains_key(&ip) {
            if let Some(oldest) = attempts
                .iter()
                .min_by_key(|(_, state)| state.last_failure_ms)
                .map(|(ip, _)| *ip)
            {
                attempts.remove(&oldest);
            }
        }
        let state = attempts.entry(ip).or_default();

        if state.locked_until_ms > now_ms {
            return AttemptDecision::TooMany(retry_after_secs(state.locked_until_ms - now_ms));
        }
        if state.locked_until_ms != 0 {
            // 锁定期已过：重新计数，而不是延续上一轮的失败次数。
            state.locked_until_ms = 0;
            state.failures = 0;
        }
        // 距上次失败超过一个锁定时长，视为“连续失败”已中断。
        if now_ms.saturating_sub(state.last_failure_ms) > LOCKOUT_MS {
            state.failures = 0;
        }
        if state.failures >= MAX_LOGIN_FAILURES {
            // 并发窗口已满额：后续请求直接 429，但不再额外延长锁定；
            // 这批在途尝试若都失败，record_failure 会把锁定窗口正式开启。
            return AttemptDecision::TooMany(retry_after_secs(LOCKOUT_MS));
        }

        state.failures = state.failures.saturating_add(1);
        state.last_failure_ms = now_ms;
        AttemptDecision::Allowed(AttemptGuard {
            limiter: self,
            ip,
            armed: true,
        })
    }

    /// 一次密码校验失败后调用；名额已在 `begin_attempt` 预占，这里只负责到达阈值时锁定。
    pub fn record_failure(&self, ip: IpAddr, now_ms: i64) {
        let mut attempts = lock(&self.inner);
        let Some(state) = attempts.get_mut(&ip) else {
            return;
        };
        if state.locked_until_ms > now_ms {
            return;
        }
        state.last_failure_ms = now_ms;
        if state.failures >= MAX_LOGIN_FAILURES {
            state.failures = 0;
            state.locked_until_ms = now_ms.saturating_add(LOCKOUT_MS);
        }
    }

    /// 归还 `begin_attempt` 预占的名额（仅用于内部错误 / 请求取消，成功后由 record_success 清空）。
    fn release_attempt(&self, ip: IpAddr) {
        let mut attempts = lock(&self.inner);
        if let Some(state) = attempts.get_mut(&ip) {
            if state.locked_until_ms == 0 {
                state.failures = state.failures.saturating_sub(1);
                if state.failures == 0 {
                    attempts.remove(&ip);
                }
            }
        }
    }

    /// 登录成功后清空该 IP 的失败记录与预占名额。
    pub fn record_success(&self, ip: IpAddr) {
        lock(&self.inner).remove(&ip);
    }
}

fn retry_after_secs(remaining_ms: i64) -> u64 {
    (((remaining_ms.max(1) + 999) / 1000) as u64).max(1)
}

fn prune(attempts: &mut HashMap<IpAddr, AttemptState>, now_ms: i64) {
    attempts.retain(|_, state| {
        state.locked_until_ms > now_ms || now_ms.saturating_sub(state.last_failure_ms) <= LOCKOUT_MS
    });
}

/// 构造会话 Cookie。`Secure` 只会在反代声明了 https 时添加。
pub fn session_cookie(token: &str, secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// 登出时清除 Cookie 的 Set-Cookie 值。
pub fn clear_cookie(secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// 从请求头提取会话令牌。
pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            (name.trim() == SESSION_COOKIE).then(|| value.trim().to_string())
        })
        .find(|token| !token.is_empty())
}

/// 判断反代是否声明了 https。只信任第一个 `X-Forwarded-Proto` 值。
pub fn is_secure_request(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|value| value.trim().eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASSWORD: &str = "correct horse battery staple";

    #[test]
    fn argon2id_hash_and_verify() {
        let phc = hash_password(TEST_PASSWORD).unwrap();
        assert!(
            phc.starts_with("$argon2id$v=19$m=65536,t=3,p=4$"),
            "PHC 参数不符合约定: {phc}"
        );
        assert!(verify_password(TEST_PASSWORD, &phc));
        assert!(!verify_password("wrong password", &phc));
        assert!(!verify_password(TEST_PASSWORD, ""));
        assert!(!verify_password(TEST_PASSWORD, "not-a-phc-string"));
        // 非 Argon2id 的 PHC 串必须拒绝
        assert!(!verify_password(
            TEST_PASSWORD,
            "$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"
        ));
    }

    #[test]
    fn session_expires_and_revokes() {
        let store = SessionStore::new(12);
        let now = 1_700_000_000_000;
        let token = store.create(now);
        assert_eq!(token.len(), SESSION_TOKEN_BYTES * 2);
        assert!(store.is_authenticated(&token, now));
        assert!(store.is_authenticated(&token, now + 12 * 3_600_000 - 1));
        assert!(!store.is_authenticated(&token, now + 12 * 3_600_000));
        assert_eq!(store.len(), 0, "过期会话应被删除");

        let token = store.create(now);
        store.revoke(&token);
        assert!(!store.is_authenticated(&token, now));
        assert!(!store.is_authenticated("", now));
        assert!(!store.is_authenticated("deadbeef", now));
    }

    #[test]
    fn session_cleanup_removes_expired_only() {
        let store = SessionStore::new(1);
        let now = 1_700_000_000_000;
        let old = store.create(now);
        let fresh = store.create(now + 2 * 3_600_000);
        store.cleanup(now + 2 * 3_600_000 + 1);
        assert!(!store.is_authenticated(&old, now + 2 * 3_600_000 + 1));
        assert!(store.is_authenticated(&fresh, now + 2 * 3_600_000 + 1));
    }

    #[test]
    fn session_table_is_bounded() {
        let store = SessionStore::new(1);
        let now = 1_700_000_000_000;
        for i in 0..(MAX_SESSIONS + 8) {
            store.create(now + i as i64);
        }
        assert!(store.len() <= MAX_SESSIONS);
    }

    /// 模拟一次“预占名额 + 密码错误”的完整尝试。
    fn fail_once(limiter: &LoginLimiter, ip: IpAddr, now_ms: i64) {
        let guard = match limiter.begin_attempt(ip, now_ms) {
            AttemptDecision::Allowed(guard) => guard,
            AttemptDecision::TooMany(retry_after) => {
                panic!("此时不应被限速（Retry-After {retry_after}s）")
            }
        };
        limiter.record_failure(ip, now_ms);
        guard.disarm();
    }

    /// 客户端在密码校验完成前断开时，Drop 必须归还预占名额，不能白锁 15 分钟。
    #[test]
    fn dropped_attempt_guard_releases_reservation() {
        let limiter = LoginLimiter::new();
        let ip: IpAddr = "203.0.113.10".parse().unwrap();
        let now = 1_700_000_000_000;
        for i in 0..MAX_LOGIN_FAILURES {
            let guard = match limiter.begin_attempt(ip, now + i as i64) {
                AttemptDecision::Allowed(guard) => guard,
                AttemptDecision::TooMany(_) => panic!("取消的尝试不应累计到锁定"),
            };
            drop(guard);
        }
        assert!(matches!(
            limiter.begin_attempt(ip, now + 10),
            AttemptDecision::Allowed(_)
        ));
    }

    #[test]
    fn limiter_locks_after_five_failures() {
        let limiter = LoginLimiter::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let now = 1_700_000_000_000;
        for i in 0..MAX_LOGIN_FAILURES {
            fail_once(&limiter, ip, now + i as i64);
        }
        match limiter.begin_attempt(ip, now + 10) {
            AttemptDecision::TooMany(retry) => assert_eq!(retry, 900, "应锁定 15 分钟"),
            AttemptDecision::Allowed(_) => panic!("5 次失败后必须锁定"),
        }
        // 锁定期内不再放行
        assert!(matches!(
            limiter.begin_attempt(ip, now + 20),
            AttemptDecision::TooMany(_)
        ));
        // 其他 IP 不受影响
        let other: IpAddr = "203.0.113.8".parse().unwrap();
        assert!(matches!(
            limiter.begin_attempt(other, now + 20),
            AttemptDecision::Allowed(_)
        ));
        // 15 分钟后解锁，计数归零：新尝试可以再次进入校验
        let later = now + LOCKOUT_MS + 10;
        assert!(matches!(
            limiter.begin_attempt(ip, later),
            AttemptDecision::Allowed(_)
        ));
    }

    #[test]
    fn limiter_success_resets_failures() {
        let limiter = LoginLimiter::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let now = 1_700_000_000_000;
        for i in 0..(MAX_LOGIN_FAILURES - 1) {
            fail_once(&limiter, ip, now + i as i64);
        }
        limiter.record_success(ip);
        for i in 0..(MAX_LOGIN_FAILURES - 1) {
            fail_once(&limiter, ip, now + 100 + i as i64);
        }
        // 若上次成功没有重置，此时累计失败已达 8 次，会直接 TooMany。
        assert!(matches!(
            limiter.begin_attempt(ip, now + 200),
            AttemptDecision::Allowed(_)
        ));
        limiter.record_success(ip);
    }

    #[test]
    fn failed_attempts_outside_window_start_over() {
        let limiter = LoginLimiter::new();
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let now = 1_700_000_000_000;
        for i in 0..(MAX_LOGIN_FAILURES - 1) {
            fail_once(&limiter, ip, now + i as i64);
        }
        // 超过一个锁定时长后，连续失败链中断，下一次失败从头计数。
        let later = now + LOCKOUT_MS + 10;
        fail_once(&limiter, ip, later);
        assert!(matches!(
            limiter.begin_attempt(ip, later + 1),
            AttemptDecision::Allowed(_)
        ));
        limiter.record_success(ip);
    }

    /// 回归：10 个并发错误尝试必须被原子预占限制为最多 5 个进入校验，
    /// 其余至少 5 个直接 TooMany（不能全部 401）。
    #[test]
    fn concurrent_attempts_are_capped_at_five() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{Arc, Barrier};

        let limiter = Arc::new(LoginLimiter::new());
        let barrier = Arc::new(Barrier::new(10));
        let allowed = Arc::new(AtomicUsize::new(0));
        let limited = Arc::new(AtomicUsize::new(0));
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        let now = 1_700_000_000_000;

        let mut handles = Vec::new();
        for _ in 0..10 {
            let limiter = limiter.clone();
            let barrier = barrier.clone();
            let allowed = allowed.clone();
            let limited = limited.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                match limiter.begin_attempt(ip, now) {
                    AttemptDecision::Allowed(guard) => {
                        allowed.fetch_add(1, Ordering::SeqCst);
                        limiter.record_failure(ip, now);
                        guard.disarm();
                    }
                    AttemptDecision::TooMany(_) => {
                        limited.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            allowed.load(Ordering::SeqCst),
            MAX_LOGIN_FAILURES as usize,
            "最多只能有 5 个尝试预占成功"
        );
        assert!(
            limited.load(Ordering::SeqCst) >= MAX_LOGIN_FAILURES as usize,
            "10 个并发错误尝试至少 5 个必须被限速"
        );
        assert!(matches!(
            limiter.begin_attempt(ip, now + 1),
            AttemptDecision::TooMany(_)
        ));
    }

    #[test]
    fn cookie_attributes() {
        let cookie = session_cookie("abc123", false);
        assert_eq!(cookie, "rb_session=abc123; HttpOnly; SameSite=Lax; Path=/");
        let cookie = session_cookie("abc123", true);
        assert!(cookie.ends_with("; Secure"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));

        let cleared = clear_cookie(false);
        assert!(cleared.starts_with("rb_session=;"));
        assert!(cleared.contains("Max-Age=0"));
        assert!(!cleared.contains("Secure"));
        assert!(clear_cookie(true).ends_with("; Secure"));
    }

    #[test]
    fn extracts_cookie_and_forwarded_proto() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            "foo=1; rb_session=deadbeef".parse().unwrap(),
        );
        assert_eq!(token_from_headers(&headers).as_deref(), Some("deadbeef"));

        headers.insert(header::COOKIE, "foo=1".parse().unwrap());
        assert_eq!(token_from_headers(&headers), None);

        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert!(is_secure_request(&headers));
        headers.insert("x-forwarded-proto", "HTTPS, http".parse().unwrap());
        assert!(is_secure_request(&headers));
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert!(!is_secure_request(&headers));
        assert!(!is_secure_request(&HeaderMap::new()));
    }
}
