//! 面板认证：Argon2id 密码校验、内存会话表、按 IP 登录限速。
//!
//! 三条安全约束：
//! 1. Argon2id 参数固定为 m=64 MiB、t=3、p=4，哈希以 PHC 串落盘；
//! 2. 登录限速必须先于哈希校验（被锁定时不再消耗 64 MiB 内存）；
//! 3. 内存表都有上限与过期清理，避免登录接口被打爆内存。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard};

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::http::{header, HeaderMap};
use rand::RngCore;
use rustboard_common::config::CookieSecure;

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

    /// 吊销全部会话，返回被清除的会话数；空表返回 0。
    ///
    /// 密码变更后调用：清空后所有旧 Cookie 立即失效，之后仍可正常 [`create`]
    /// 新会话。持锁期间只做 `clear`，不回调外部代码，避免锁顺序问题。
    ///
    /// [`create`]: Self::create
    pub fn revoke_all(&self) -> usize {
        let mut sessions = lock(&self.inner);
        let revoked = sessions.len();
        sessions.clear();
        revoked
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

/// XFF 最多接受的跳数。超过时视为不可信，拒绝请求。
pub const MAX_XFF_HOPS: usize = 8;
/// XFF 头部总字节上限，避免用超长头部打满解析路径。
pub const MAX_XFF_BYTES: usize = 4096;

/// 可信反代条目：精确 IP 或 CIDR（IPv4 / IPv6）。
///
/// 输入不必是网络地址；`contains` 按前缀逐位比较，因此 `10.1.2.3/8` 与
/// `10.0.0.0/8` 等价。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    network: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        let (addr, prefix) = match input.rsplit_once('/') {
            Some((addr, prefix)) => (addr.trim(), Some(prefix.trim())),
            None => (input, None),
        };
        let network: IpAddr = addr
            .parse()
            .with_context(|| format!("不是合法 IP 地址: {addr:?}"))?;
        let max_prefix = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .with_context(|| format!("前缀长度不是 0–{max_prefix} 的整数: {prefix:?}"))?,
            None => max_prefix,
        };
        if prefix > max_prefix {
            return Err(anyhow!(
                "前缀长度 {prefix} 超过 {} 的上限 {max_prefix}",
                if network.is_ipv4() { "IPv4" } else { "IPv6" }
            ));
        }
        Ok(Self { network, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                masked_v4(network, self.prefix) == masked_v4(ip, self.prefix)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                masked_v6(network, self.prefix) == masked_v6(ip, self.prefix)
            }
            _ => false,
        }
    }
}

fn masked_v4(ip: Ipv4Addr, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::from(ip) & (u32::MAX << (32 - u32::from(prefix)))
    }
}

fn masked_v6(ip: Ipv6Addr, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::from(ip) & (u128::MAX << (128 - u32::from(prefix)))
    }
}

/// 解析配置里的可信反代列表；任何一条非法都让面板启动失败。
pub fn parse_trusted_proxies(entries: &[String]) -> Result<Vec<IpNet>> {
    entries
        .iter()
        .map(|entry| {
            IpNet::parse(entry).with_context(|| format!("trusted_proxies 含非法条目 {entry:?}"))
        })
        .collect()
}

/// 计算请求的真实客户端地址。
///
/// - 直连对端不在 `trusted_proxies` 中时，完全忽略 `X-Forwarded-For`，返回直连地址；
/// - 对端可信但没有 XFF 时返回直连地址；
/// - 对端可信时，从 XFF 最右侧开始向左跳过可信代理，返回第一个合法非可信 IP；
/// - 任一 hop 非法、总字节数超过 [`MAX_XFF_BYTES`]、跳数超过 [`MAX_XFF_HOPS`]
///   时返回 `None`，调用方必须拒绝请求，不能回退到共享的直连地址；
/// - 没有 XFF 或全部 hop 都是可信地址（无法确定客户端）时返回直连地址。
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNet]) -> Option<IpAddr> {
    if !trusted.iter().any(|net| net.contains(peer)) {
        return Some(peer);
    }
    let mut hops: Vec<&str> = Vec::new();
    let mut total_bytes = 0usize;
    for value in headers.get_all("x-forwarded-for").iter() {
        let value = value.to_str().ok()?;
        total_bytes = total_bytes.saturating_add(value.len());
        if total_bytes > MAX_XFF_BYTES {
            return None;
        }
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if hops.len() >= MAX_XFF_HOPS {
                return None;
            }
            hops.push(part);
        }
    }
    if hops.is_empty() {
        return Some(peer);
    }
    for raw in hops.iter().rev() {
        let ip = raw.parse::<IpAddr>().ok()?;
        if trusted.iter().any(|net| net.contains(ip)) {
            continue;
        }
        return Some(ip);
    }
    // 所有 hop 都是可信代理：没有可用的客户端地址。
    Some(peer)
}

/// 按配置决定会话 Cookie 是否加 `Secure`。
///
/// `Auto` 只信任「直连对端是可信反代 + 该反代声明 XFP=https」，
/// 不能被直连客户端伪造的 `X-Forwarded-Proto` 影响。
pub fn secure_cookie(
    mode: CookieSecure,
    peer: IpAddr,
    headers: &HeaderMap,
    trusted: &[IpNet],
) -> bool {
    match mode {
        CookieSecure::Always => true,
        CookieSecure::Never => false,
        CookieSecure::Auto => {
            trusted.iter().any(|net| net.contains(peer)) && is_secure_request(headers)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OriginScheme {
    Http,
    Https,
}

impl OriginScheme {
    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginUrl {
    scheme: OriginScheme,
    host: String,
    port: u16,
}

/// 解析 `scheme://host[:port]`；只用于 Origin / public_origin，不接受路径。
fn parse_origin_url(raw: &str) -> Option<OriginUrl> {
    let raw = raw.trim();
    let (scheme, rest) = if let Some(rest) = raw.strip_prefix("https://") {
        (OriginScheme::Https, rest)
    } else {
        let rest = raw.strip_prefix("http://")?;
        (OriginScheme::Http, rest)
    };
    if rest.is_empty()
        || rest.contains('/')
        || rest.contains('?')
        || rest.contains('#')
        || rest.contains('@')
    {
        return None;
    }
    let (host, port) = parse_host_port(rest, scheme.default_port())?;
    Some(OriginUrl { scheme, host, port })
}

/// 解析 `host[:port]`，支持 IPv6 方括号；无端口时用 `default_port`。
fn parse_host_port(value: &str, default_port: u16) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after {
            "" => default_port,
            _ => after.strip_prefix(':')?.parse::<u16>().ok()?,
        };
        (host.to_string(), port)
    } else {
        match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => {
                (host.to_string(), port.parse::<u16>().ok()?)
            }
            // 无端口，或未加方括号的 IPv6（Host/Origin 不允许这种写法）。
            _ if value.contains(':') => return None,
            _ => (value.to_string(), default_port),
        }
    };
    if host.is_empty() || host.chars().any(|c| c.is_whitespace()) {
        return None;
    }
    Some((
        host.to_ascii_lowercase().trim_end_matches('.').to_string(),
        port,
    ))
}

/// 校验变更类请求的 `Origin` 是否与当前站点同源。
///
/// 同源判定：`Origin` 与 `Host` 的 host+port 一致，或与显式配置的 `public_origin`
/// 的 scheme+host+port 完全一致。默认端口按 scheme 归一化（http→80，https→443），
/// 因此 `Origin: https://panel.example.com` 能匹配 `Host: panel.example.com`。
pub fn same_origin(origin: &str, host: Option<&str>, public_origin: &str) -> bool {
    let Some(origin) = parse_origin_url(origin) else {
        return false;
    };
    let public = public_origin.trim();
    if !public.is_empty() && parse_origin_url(public).as_ref() == Some(&origin) {
        return true;
    }
    let Some(host) = host.filter(|host| !host.trim().is_empty()) else {
        return false;
    };
    let Some((host, port)) = parse_host_port(host, origin.scheme.default_port()) else {
        return false;
    };
    host == origin.host && port == origin.port
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

    #[test]
    fn revoke_all_clears_sessions_and_allows_new_ones() {
        let store = SessionStore::new(12);
        let now = 1_700_000_000_000;
        let first = store.create(now);
        let second = store.create(now);
        assert_ne!(first, second);
        assert_eq!(store.len(), 2);

        assert_eq!(store.revoke_all(), 2, "应返回被清除的会话数");
        assert_eq!(store.len(), 0);
        assert!(!store.is_authenticated(&first, now));
        assert!(!store.is_authenticated(&second, now));

        // 空表返回 0，重复调用幂等。
        assert_eq!(store.revoke_all(), 0);

        // 吊销后新会话可正常创建与认证，旧 token 不会复活。
        let fresh = store.create(now);
        assert!(store.is_authenticated(&fresh, now));
        assert!(!store.is_authenticated(&first, now));
    }

    #[test]
    fn revoke_all_is_thread_safe() {
        use std::sync::Arc;

        let store = Arc::new(SessionStore::new(1));
        let now = 1_700_000_000_000;
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..16 {
                    let token = store.create(now);
                    assert!(store.is_authenticated(&token, now));
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        let created = store.len();
        assert_eq!(created, 8 * 16);
        assert_eq!(store.revoke_all(), created);
        assert_eq!(store.len(), 0, "并发创建后 revoke_all 必须清空全部会话");
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

    fn net(value: &str) -> IpNet {
        IpNet::parse(value).unwrap()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn ipnet_parses_exact_and_cidr_v4_v6() {
        assert!(net("10.1.2.3").contains("10.1.2.3".parse().unwrap()));
        assert!(!net("10.1.2.3").contains("10.1.2.4".parse().unwrap()));
        assert!(net("10.0.0.0/8").contains("10.255.1.2".parse().unwrap()));
        assert!(!net("10.0.0.0/8").contains("11.0.0.1".parse().unwrap()));
        assert!(net("192.168.1.7/24").contains("192.168.1.99".parse().unwrap()));
        assert!(net("0.0.0.0/0").contains("203.0.113.9".parse().unwrap()));
        assert!(net("2001:db8::/32").contains("2001:db8::1".parse().unwrap()));
        assert!(net("2001:db8::1/128").contains("2001:db8::1".parse().unwrap()));
        assert!(!net("2001:db8::1/128").contains("2001:db8::2".parse().unwrap()));
        assert!(!net("10.0.0.0/8").contains("2001:db8::1".parse().unwrap()));
        assert!(!net("::/0").contains("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn ipnet_rejects_invalid_prefix_and_address() {
        assert!(IpNet::parse("10.0.0.0/33").is_err());
        assert!(IpNet::parse("2001:db8::/129").is_err());
        assert!(IpNet::parse("10.0.0.0/abc").is_err());
        assert!(IpNet::parse("not-an-ip").is_err());
        assert!(IpNet::parse("10.0.0.0/").is_err());
        assert!(IpNet::parse("").is_err());
    }

    #[test]
    fn trusted_proxies_parse_list_and_name_bad_entry() {
        let list =
            parse_trusted_proxies(&["127.0.0.1".into(), "10.0.0.0/8".into(), "::1/128".into()])
                .unwrap();
        assert_eq!(list.len(), 3);
        let err = parse_trusted_proxies(&["10.0.0.0/99".into()]).unwrap_err();
        assert!(format!("{err:#}").contains("trusted_proxies"));
        assert!(format!("{err:#}").contains("10.0.0.0/99"));
    }

    #[test]
    fn client_ip_ignores_xff_from_untrusted_peer() {
        let peer: IpAddr = "198.51.100.1".parse().unwrap();
        let h = headers(&[("x-forwarded-for", "203.0.113.7")]);
        let trusted = vec![net("10.0.0.0/8")];
        assert_eq!(client_ip(peer, &h, &trusted), Some(peer));
    }

    #[test]
    fn client_ip_skips_trusted_proxies_from_the_right() {
        let trusted = vec![net("10.0.0.0/8")];
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        let h = headers(&[("x-forwarded-for", "203.0.113.7, 10.0.0.3")]);
        assert_eq!(
            client_ip(peer, &h, &trusted),
            Some("203.0.113.7".parse::<IpAddr>().unwrap())
        );

        // 右侧继续出现可信地址时继续跳过。
        let h = headers(&[("x-forwarded-for", "203.0.113.7, 10.0.0.3, 10.0.0.2")]);
        assert_eq!(
            client_ip(peer, &h, &trusted),
            Some("203.0.113.7".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn client_ip_rejects_invalid_or_too_many_hops_without_falling_back() {
        let trusted = vec![net("10.0.0.0/8")];
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        for value in [
            "not-an-ip",
            "203.0.113.7, garbage",
            "1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5,6.6.6.6,7.7.7.7,8.8.8.8,9.9.9.9",
        ] {
            let h = headers(&[("x-forwarded-for", value)]);
            assert_eq!(client_ip(peer, &h, &trusted), None, "value={value:?}");
        }

        // 空 XFF == 没有 XFF，仍返回直连地址。
        assert_eq!(
            client_ip(peer, &headers(&[("x-forwarded-for", "")]), &trusted),
            Some(peer)
        );

        // 总字节数超限也必须拒绝，而不是回退共享 peer。
        let long = format!("203.0.113.7,{}", "1".repeat(MAX_XFF_BYTES));
        assert_eq!(
            client_ip(peer, &headers(&[("x-forwarded-for", &long)]), &trusted),
            None
        );
    }

    #[test]
    fn client_ip_returns_peer_when_all_hops_are_trusted() {
        let trusted = vec![net("10.0.0.0/8")];
        let peer: IpAddr = "10.0.0.2".parse().unwrap();
        let h = headers(&[("x-forwarded-for", "10.0.0.3")]);
        assert_eq!(client_ip(peer, &h, &trusted), Some(peer));
        assert_eq!(client_ip(peer, &HeaderMap::new(), &trusted), Some(peer));
    }

    #[test]
    fn secure_cookie_respects_policy_and_trust() {
        let trusted = vec![net("10.0.0.0/8")];
        let trusted_peer: IpAddr = "10.0.0.2".parse().unwrap();
        let plain_peer: IpAddr = "198.51.100.1".parse().unwrap();
        let https = headers(&[("x-forwarded-proto", "https")]);

        assert!(secure_cookie(
            CookieSecure::Auto,
            trusted_peer,
            &https,
            &trusted
        ));
        assert!(!secure_cookie(
            CookieSecure::Auto,
            plain_peer,
            &https,
            &trusted
        ));
        assert!(!secure_cookie(
            CookieSecure::Auto,
            trusted_peer,
            &headers(&[("x-forwarded-proto", "http")]),
            &trusted
        ));
        assert!(secure_cookie(
            CookieSecure::Always,
            plain_peer,
            &HeaderMap::new(),
            &trusted
        ));
        assert!(!secure_cookie(
            CookieSecure::Never,
            trusted_peer,
            &https,
            &trusted
        ));
    }

    #[test]
    fn same_origin_matches_host_and_public_origin() {
        assert!(same_origin(
            "https://panel.example.com",
            Some("panel.example.com"),
            ""
        ));
        assert!(same_origin(
            "https://panel.example.com:443",
            Some("panel.example.com"),
            ""
        ));
        assert!(same_origin(
            "http://panel.example.com:80",
            Some("panel.example.com:80"),
            ""
        ));
        assert!(!same_origin(
            "https://panel.example.com:8443",
            Some("panel.example.com"),
            ""
        ));
        assert!(!same_origin(
            "https://evil.example.com",
            Some("panel.example.com"),
            ""
        ));
        assert!(!same_origin(
            "https://sub.panel.example.com",
            Some("panel.example.com"),
            ""
        ));
        assert!(same_origin(
            "https://panel.example.com",
            Some("internal:8080"),
            "https://panel.example.com"
        ));
        assert!(same_origin(
            "https://panel.example.com:8443",
            Some("internal:8080"),
            "https://panel.example.com:8443"
        ));
        assert!(!same_origin(
            "https://panel.example.com/evil",
            Some("panel.example.com"),
            ""
        ));
        assert!(!same_origin("null", Some("panel.example.com"), ""));
        assert!(same_origin(
            "https://[2001:db8::1]",
            Some("[2001:db8::1]"),
            ""
        ));
    }
}
