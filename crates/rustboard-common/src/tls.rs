//! TLS 材料生成与 rustls 配置。
//!
//! 信任模型：hub 自建一个私有 CA；agent 首次连接时用**服务端证书指纹**固定校验，
//! enrollment 成功后拿到属于自己的客户端证书与 CA 证书，之后全程 mTLS。
//! 已纳管的 agent 可以改用 CA 信任（[`client_config_ca`]），这样服务端证书
//! 轮换后无需重新纳管；未纳管阶段仍然只能靠指纹钉扎。
//!
//! CA 证书落盘后就不再重建（重建会让所有 agent 失效）。运行时为了给 CSR 签名，
//! 需要构造 rcgen 的 `Certificate` 作为 issuer —— 这里用固定参数 + CA 私钥
//! 重新推导一份，仅用于取 subject/AKI，不会覆盖磁盘上的 CA 证书。
//!
//! 有效期：所有新签发的证书都显式设置 `notBefore = now - 5min`（容忍时钟偏差）
//! 与 `notAfter = now + N 天`。rcgen 的默认有效期是 1975–4096 年，既不便于轮换，
//! 也让「剩余寿命」这类运维判断失去意义。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest,
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use x509_parser::extensions::{GeneralName, ParsedExtension};

pub const CA_COMMON_NAME: &str = "RustBoard Root CA";
pub const SERVER_COMMON_NAME: &str = "rustboard-hub";

pub const CA_CERT_FILE: &str = "ca.crt";
pub const CA_KEY_FILE: &str = "ca.key";
pub const SERVER_CERT_FILE: &str = "server.crt";
pub const SERVER_KEY_FILE: &str = "server.key";
pub const AGENT_CERT_FILE: &str = "agent.crt";
pub const AGENT_KEY_FILE: &str = "agent.key";

/// 默认 CA 有效期（天）。
pub const DEFAULT_CA_DAYS: u32 = 3_650;
/// 默认服务端证书有效期（天）。
pub const DEFAULT_SERVER_DAYS: u32 = 365;
/// 默认客户端证书有效期（天）。
pub const DEFAULT_CLIENT_DAYS: u32 = 90;

/// 有效期允许的范围（天）：至少 1 天，最多 100 年。
const MIN_VALIDITY_DAYS: u32 = 1;
const MAX_VALIDITY_DAYS: u32 = 36_500;

/// 新证书的 notBefore 统一往前拨 1 小时，容忍签发端与校验端的时钟偏差。
///
/// 1 小时是业界（如 Let's Encrypt / cert-manager）常用的回拨量：NTP 严重漂移、
/// 时区误配、虚拟机挂起恢复都可能造成分钟级偏差，5 分钟过于激进。
const CLOCK_SKEW_BACKDATE_SECS: i64 = 3_600;

const DAY_MS: i64 = 86_400_000;
const HOUR_MS: i64 = 3_600_000;

/// hub 的证书目录。
pub fn cert_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("certs")
}

/// 证书有效期策略（天）。
///
/// 只影响**新签发**的证书：已存在的证书不会被覆盖（覆盖会让已安装 agent 失联）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CertPolicy {
    pub ca_days: u32,
    pub server_days: u32,
    pub client_days: u32,
}

impl Default for CertPolicy {
    fn default() -> Self {
        Self {
            ca_days: DEFAULT_CA_DAYS,
            server_days: DEFAULT_SERVER_DAYS,
            client_days: DEFAULT_CLIENT_DAYS,
        }
    }
}

impl CertPolicy {
    /// 三个有效期都必须落在允许范围内，否则拒绝签发（避免出现 0 天或上千年证书）。
    pub fn validate(&self) -> Result<()> {
        validate_validity_days(self.ca_days, "CA")?;
        validate_validity_days(self.server_days, "服务端证书")?;
        validate_validity_days(self.client_days, "客户端证书")
    }
}

fn validate_validity_days(days: u32, what: &str) -> Result<()> {
    if !(MIN_VALIDITY_DAYS..=MAX_VALIDITY_DAYS).contains(&days) {
        return Err(anyhow!(
            "{what}有效期必须在 {MIN_VALIDITY_DAYS}–{MAX_VALIDITY_DAYS} 天之间，实际 {days} 天"
        ));
    }
    Ok(())
}

/// 计算显式有效期窗口：`[now - 1h, now + days]`。
fn validity_window(days: u32) -> Result<(OffsetDateTime, OffsetDateTime)> {
    validate_validity_days(days, "证书")?;
    let now = OffsetDateTime::now_utc();
    let not_before = now - TimeDuration::seconds(CLOCK_SKEW_BACKDATE_SECS);
    let not_after = now + TimeDuration::days(i64::from(days));
    Ok((not_before, not_after))
}

fn ca_params(days: u32) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let (not_before, not_after) = validity_window(days)?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params.key_identifier_method = KeyIdMethod::Sha256;
    Ok(params)
}

/// 用 CA 私钥推导出 issuer 对象（仅取 subject / AKI，DER 不入库）。
///
/// 这里的有效期不参与任何校验（issuer 只提供 subject 与公钥），用默认天数即可。
fn ca_issuer(ca_key: &KeyPair) -> Result<Certificate> {
    Ok(ca_params(DEFAULT_CA_DAYS)?.self_signed(ca_key)?)
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    crate::fsutil::atomic_write(path, data, 0o600)?;
    Ok(())
}

fn write_public(path: &Path, data: &[u8]) -> Result<()> {
    crate::fsutil::atomic_write(path, data, 0o644)?;
    Ok(())
}

/// 服务端证书的一个 SAN 条目（校验通过后的中间表示）。
///
/// 不直接暴露 rcgen 的类型，避免公共 API 绑定到 rcgen 版本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerSan {
    Ip(std::net::IpAddr),
    Dns(String),
}

/// 把配置里的 `server_names` 转换成 SAN 条目；**任何一条非法都报错**。
///
/// 安全决策：旧实现用 `filter_map` 静默丢弃非法条目，极端情况下会签出一张
/// 没有 SAN 的服务端证书——所有 CA 信任的 agent 都会在下次握手时失败，而且
/// 问题发生在运行期、很难定位。这里在签发前就拒绝：
/// - 空列表：至少需要一个 IP 或域名；
/// - 空白/控制字符/非法 DNS 标签/超长：直接报错；
/// - 合法 IP 走 IP SAN，其余必须是合法 DNS 名。
pub fn parse_server_sans(hosts: &[String]) -> Result<Vec<ServerSan>> {
    if hosts.is_empty() {
        return Err(anyhow!(
            "server_names 为空：服务端证书至少需要一个 IP 或域名 SAN（检查 hub 配置 / 首次 init 的 --san）"
        ));
    }
    let mut out = Vec::with_capacity(hosts.len());
    for raw in hosts {
        let host = raw.trim();
        if host.is_empty() {
            return Err(anyhow!("server_names 含空条目，无法作为证书 SAN"));
        }
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            out.push(ServerSan::Ip(ip));
            continue;
        }
        validate_dns_name(host)?;
        out.push(ServerSan::Dns(host.to_string()));
    }
    Ok(out)
}

/// 校验一个非 IP 的 SAN 条目是否是可用于证书的 DNS 名。
fn validate_dns_name(host: &str) -> Result<()> {
    // `{:?}` 会转义控制字符，错误信息进日志/终端时不会被注入。
    let invalid = |reason: &str| Err(anyhow!("server_names 条目 {host:?} 不是合法 SAN：{reason}"));
    if host.len() > 253 {
        return invalid("长度超过 253 字节");
    }
    if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return invalid("标签为空（首尾点或连续点）");
    }
    if host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return invalid("含控制字符或空白");
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return invalid("单个标签长度为 0 或超过 63 字节");
        }
        if label.starts_with('-') || label.ends_with('-') {
            return invalid("标签不能以 '-' 开头或结尾");
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return invalid("标签只能包含字母、数字、'-'、'_'");
        }
    }
    Ok(())
}

fn san_entries(hosts: &[String]) -> Result<Vec<SanType>> {
    parse_server_sans(hosts)?
        .into_iter()
        .map(|san| match san {
            ServerSan::Ip(ip) => Ok(SanType::IpAddress(ip)),
            ServerSan::Dns(name) => rcgen::Ia5String::try_from(name.clone())
                .map(SanType::DnsName)
                .map_err(|err| anyhow!("server_names 条目 {name:?} 无法编码为 DNS SAN: {err}")),
        })
        .collect()
}

/// 收紧已有 hub 私钥的权限（升级路径：旧安装可能是 0644）。
pub fn harden_hub_material(data_dir: &Path) -> Result<()> {
    let dir = cert_dir(data_dir);
    for name in [CA_KEY_FILE, SERVER_KEY_FILE] {
        let path = dir.join(name);
        if path.exists() {
            crate::fsutil::harden(&path, 0o600)?;
        }
    }
    Ok(())
}

/// 每类证书材料（cert / key）备份保留的最近份数。
pub const BACKUP_KEEP: usize = 5;

/// 备份后缀中进程内序号的十进制位数（`{:08}`）。
const BACKUP_SEQ_DIGITS: usize = 8;

/// 进程内单调递增的备份序号。
///
/// 同一毫秒内可能连续备份多次（重签重试、引导流程、测试），毫秒前缀不足以区分
/// 先后。序号从 1 开始，保证新格式的序号严格大于旧格式缺省值 0；`fetch_add`
/// 只有在 2^64 次备份后才会回绕，实际不可达。
static BACKUP_SEQ: AtomicU64 = AtomicU64::new(1);

/// 一次备份操作共用的文件名后缀：`<毫秒>-<8 位序号>-<pid>-<uuid>`。
///
/// 毫秒 + 进程内序号 + PID + UUID 保证同一毫秒内连续重签也不会互相覆盖；序号让
/// 淘汰顺序不再依赖 UUID 的字典序。crt 与 key 复用同一个后缀，便于把两份备份
/// 配成一对。
fn backup_suffix() -> String {
    let seq = BACKUP_SEQ.fetch_add(1, Ordering::Relaxed);
    format_backup_suffix(
        crate::util::now_ms(),
        seq,
        &uuid::Uuid::new_v4().simple().to_string(),
    )
}

/// 按给定毫秒、序号与 UUID 组装后缀（纯格式化，生产与测试共用）。
fn format_backup_suffix(now_ms: i64, seq: u64, uuid: &str) -> String {
    format!("{now_ms}-{seq:08}-{}-{uuid}", std::process::id())
}

/// 测试专用的确定性后缀：固定 UUID，毫秒/序号可注入，不依赖真实时钟与随机数。
#[cfg(test)]
fn backup_suffix_at(now_ms: i64, seq: u64) -> String {
    format_backup_suffix(now_ms, seq, "00112233445566778899aabbccddeeff")
}

/// 解析本模块备份后缀，返回淘汰排序用的 `(毫秒, 序号)`。
///
/// 识别两种格式：
/// - 新 4 段 `<毫秒>-<8 位序号>-<pid>-<uuid>` → `(毫秒, 序号)`；
/// - 旧 3 段 `<毫秒>-<pid>-<uuid>`（v0.3.3 及更早）→ `(毫秒, 0)`，旧格式没有序号。
///
/// 段数不对、数字段非法、UUID 段非法时返回 `None`；任何输入都不会 panic。
fn parse_managed_backup_suffix(suffix: &str) -> Option<(u64, u64)> {
    let parts: Vec<&str> = suffix.split('-').collect();
    match parts.as_slice() {
        [ms, seq, pid, uuid] => {
            // 新格式的序号固定 8 位十进制，用来与旧格式的 pid 段区分。
            if seq.len() != BACKUP_SEQ_DIGITS || !is_backup_uuid(uuid) {
                return None;
            }
            let ms = parse_backup_decimal(ms)?;
            let seq = parse_backup_decimal(seq)?;
            parse_backup_decimal(pid)?;
            Some((ms, seq))
        }
        [ms, pid, uuid] => {
            if !is_backup_uuid(uuid) {
                return None;
            }
            let ms = parse_backup_decimal(ms)?;
            parse_backup_decimal(pid)?;
            Some((ms, 0))
        }
        _ => None,
    }
}

/// 备份后缀里的十进制段：只接受纯 ASCII 数字，拒绝空串、符号与溢出。
fn parse_backup_decimal(part: &str) -> Option<u64> {
    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}

/// 本模块统一使用 `Uuid::new_v4().simple()`：32 位十六进制、无连字符。
fn is_backup_uuid(part: &str) -> bool {
    part.len() == 32 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// 是否是本模块生成的备份文件名。
///
/// 同时识别：
/// - 新 4 段：`<name>.bak-<毫秒>-<8 位序号>-<pid>-<uuid>`；
/// - 旧 3 段：`<name>.bak-<毫秒>-<pid>-<uuid>`（v0.3.3 及更早的遗留备份）。
///
/// 运维 CLI 的两段式 `bak-<秒>` 不算，保留策略不会误删。
pub fn is_managed_backup(file_name: &str, base: &str) -> bool {
    file_name
        .strip_prefix(&format!("{base}.bak-"))
        .and_then(parse_managed_backup_suffix)
        .is_some()
}

/// 成对备份服务端 crt(0644) + key(0600)，返回本次生成的备份路径（crt 在前）。
///
/// 只备份磁盘上存在的文件（自愈补签时可能没有 server.crt）；每类只保留最近
/// [`BACKUP_KEEP`] 份，且只清理本模块生成的备份。
///
/// **调用时机**：必须在 CA 配对、SAN、新证书自检全部通过之后、真正写盘之前调用，
/// 这样失败路径不会留下无意义的备份。
pub fn backup_server_material(data_dir: &Path) -> Result<Vec<PathBuf>> {
    let dir = cert_dir(data_dir);
    let suffix = backup_suffix();
    let mut created = Vec::new();
    for (file_name, mode) in [(SERVER_CERT_FILE, 0o644), (SERVER_KEY_FILE, 0o600)] {
        let source = dir.join(file_name);
        let data = match std::fs::read(&source) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                tracing::warn!(path = %source.display(), "备份时源文件不存在，跳过");
                continue;
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("读取 {} 失败，拒绝在无备份的情况下重签", source.display())
                })
            }
        };
        let target = dir.join(format!("{file_name}.bak-{suffix}"));
        crate::fsutil::atomic_write(&target, &data, mode)
            .with_context(|| format!("备份 {} 失败: {}", file_name, target.display()))?;
        // 默认 filter 只放行 rustboard_common=warn：备份是重签/重建的关键审计点，
        // 必须让运维在不设置 RUST_LOG 时也能看到备份文件路径。
        tracing::warn!(path = %target.display(), "重签/重建前已备份服务端证书材料");
        prune_managed_backups(&dir, file_name)?;
        created.push(target);
    }
    Ok(created)
}

/// 只保留最近 [`BACKUP_KEEP`] 份本模块生成的备份。
///
/// 按解析出的 `(毫秒, 序号)` 降序保留：同一毫秒内序号大的（后创建）优先；旧 3 段
/// 格式的序号按 0 处理。只有 `(毫秒, 序号)` 完全相同时才用文件名倒序兜底，因此
/// UUID 的字典序不会把刚创建的备份挤出保留区。
fn prune_managed_backups(dir: &Path, base: &str) -> Result<()> {
    let prefix = format!("{base}.bak-");
    let mut backups: Vec<((u64, u64), String)> = std::fs::read_dir(dir)
        .with_context(|| format!("读取证书目录失败: {}", dir.display()))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().to_string();
            let suffix = name.strip_prefix(&prefix)?;
            Some((parse_managed_backup_suffix(suffix)?, name))
        })
        .collect();
    if backups.len() <= BACKUP_KEEP {
        return Ok(());
    }
    backups.sort_unstable_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));
    for (_, stale) in backups.iter().skip(BACKUP_KEEP) {
        let path = dir.join(stale);
        if let Err(err) = std::fs::remove_file(&path) {
            // 清理失败不影响本次备份/续签，只影响磁盘占用。
            tracing::warn!(path = %path.display(), error = %err, "清理旧备份失败");
        }
    }
    Ok(())
}

/// 已校验的 CA 材料（私钥只用于本进程内签发，不实现 Debug、不得写入日志）。
pub struct ValidatedCa {
    pub cert_pem: String,
    pub key_pem: String,
}

impl ValidatedCa {
    /// 用已校验的 CA 私钥签发客户端证书。CN 强制取会话身份。
    pub fn sign_client_csr(
        &self,
        csr_pem: &str,
        agent_id: &str,
        validity_days: u32,
    ) -> Result<String> {
        sign_client_csr(&self.key_pem, csr_pem, agent_id, validity_days)
    }
}

/// 读取并校验 hub 的 CA 材料：两者都存在、可解析、且私钥与证书配套。
///
/// 所有使用 CA 的入口（启动、enrollment、客户端续签、服务端重签）都必须先过这里，
/// 避免用不配套的 CA 签出无效证书链。错误信息给出可执行的恢复方式，并明确
/// `init --force` 会重建 CA、所有 agent 需要重新纳管。
pub fn load_validated_ca(data_dir: &Path) -> Result<ValidatedCa> {
    load_validated_ca_at(&cert_dir(data_dir))
}

/// 同 [`load_validated_ca`]，但直接接收证书目录（供持有 cert_dir 的调用方复用）。
pub fn load_validated_ca_at(cert_dir_path: &Path) -> Result<ValidatedCa> {
    let ca_cert_path = cert_dir_path.join(CA_CERT_FILE);
    let ca_key_path = cert_dir_path.join(CA_KEY_FILE);

    let read = |path: &Path, what: &str| -> Result<String> {
        match std::fs::read_to_string(path) {
            Ok(data) => Ok(data),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
                "{what}缺失（{}）：无法签发或校验证书。请从备份恢复；如果确实要重建 CA，\
                 请先手动移除 ca.crt+ca.key+旧 server 材料（ca.crt / ca.key / server.crt / server.key），\
                 再执行 `rustboard-hub init --force`（会重建 CA、重置端口与配置，所有 agent 都需要重新纳管）",
                path.display()
            ),
            Err(err) => Err(err).with_context(|| format!("读取{what}失败: {}", path.display())),
        }
    };

    let cert_pem = read(&ca_cert_path, "CA 证书")?;
    // 旧安装的 CA 私钥可能是 0644，读取前收紧。
    if ca_key_path.exists() {
        crate::fsutil::harden(&ca_key_path, 0o600).context("收紧 CA 私钥权限失败")?;
    }
    let key_pem = read(&ca_key_path, "CA 私钥")?;

    let matches = cert_matches_key(&cert_pem, &key_pem).with_context(|| {
        format!(
            "CA 私钥或 CA 证书无法解析（{} / {}）；请从备份恢复配套的一对材料。\
             如果确实要重建 CA，请先手动移除 ca.crt+ca.key+旧 server 材料，\
             再执行 `rustboard-hub init --force`（会重建 CA、重置端口与配置，所有 agent 都需要重新纳管）",
            ca_cert_path.display(),
            ca_key_path.display()
        )
    })?;
    if !matches {
        bail!(
            "CA 私钥与 CA 证书不配套（{} / {}）：拒绝签发证书（会签出无效证书链）。\
             请从备份恢复配套材料；如果确实要重建 CA，请先手动移除 ca.crt+ca.key+旧 server 材料，\
             再执行 `rustboard-hub init --force`（会重建 CA、重置端口与配置，所有 agent 都需要重新纳管）",
            ca_cert_path.display(),
            ca_key_path.display()
        );
    }
    Ok(ValidatedCa { cert_pem, key_pem })
}

/// 确保客户端证书 CA（`ca.crt` / `ca.key`）存在且配套。
///
/// C3 拆分后，CA 只用于签发/校验**客户端证书**（mTLS、enrollment、续期），
/// 不再参与服务端证书来源。本函数只创建/校验 CA，绝不创建、读取或改写
/// `server.crt` / `server.key`，因此 ACME 模式可以安全地只准备客户端 CA。
///
/// 规则与旧 `ensure_hub_material` 的 CA 部分完全一致：
/// - `ca.crt` / `ca.key` 只缺一个：直接报错，绝不静默重建；
/// - 两个都在但不配套：报错；
/// - 两个都不在：才允许新建。
pub fn ensure_client_ca(data_dir: &Path, policy: CertPolicy) -> Result<()> {
    policy.validate()?;
    let dir = cert_dir(data_dir);
    // KI-21：证书目录完全由 hub 拥有，旧版本遗留的 0755 也要收紧到 0700。
    crate::fsutil::ensure_private_dir(&dir, 0o700)?;
    ensure_client_ca_at(&dir, policy).map(|_created| ())
}

/// 内部实现：返回本次是否新建了 CA（仅用于日志语义）。
fn ensure_client_ca_at(dir: &Path, policy: CertPolicy) -> Result<bool> {
    let ca_cert_path = dir.join(CA_CERT_FILE);
    let ca_key_path = dir.join(CA_KEY_FILE);
    match (ca_cert_path.exists(), ca_key_path.exists()) {
        (true, true) => {
            // 已存在：必须可解析且配套（不重新生成）。
            load_validated_ca_at(dir).context("已有 CA 材料校验失败，拒绝继续签发")?;
            Ok(false)
        }
        (false, false) => {
            let key = KeyPair::generate()?;
            let cert = ca_params(policy.ca_days)?.self_signed(&key)?;
            write_private(&ca_key_path, key.serialize_pem().as_bytes())?;
            write_public(&ca_cert_path, cert.pem().as_bytes())?;
            tracing::info!(path = %ca_cert_path.display(), days = policy.ca_days, "已生成 CA");
            // 新建 CA 既可能是全新安装，也可能是「整目录被删后恢复」。用 println 明确提示，
            // 保证与 RUST_LOG/日志级别无关；替换 CA 后旧 agent 的 ca.crt 与客户端证书
            // 都属于旧 CA，必须重新纳管才能继续 mTLS。
            println!("已新建 CA；如果这是恢复/替换场景，所有已纳管 agent 都需要重新纳管。");
            Ok(true)
        }
        (true, false) => bail!(
            "CA 私钥缺失（{}），但 CA 证书仍在：拒绝自动重建 CA（会签出无效链并让所有 agent 失效）。\
             请从备份恢复；如果确实要重建 CA，请先手动移除 ca.crt+ca.key+旧 server 材料（ca.crt / ca.key / \
             server.crt / server.key），再执行 `rustboard-hub init --force`——那会重建 CA、重置端口与配置，\
             所有 agent 都需要重新纳管",
            ca_key_path.display()
        ),
        (false, true) => bail!(
            "CA 证书缺失（{}），但 CA 私钥仍在：拒绝自动重建 CA（会签出无效链并让所有 agent 失效）。\
             请从备份恢复；如果确实要重建 CA，请先手动移除 ca.crt+ca.key+旧 server 材料（ca.crt / ca.key / \
             server.crt / server.key），再执行 `rustboard-hub init --force`——那会重建 CA、重置端口与配置，\
             所有 agent 都需要重新纳管",
            ca_cert_path.display()
        ),
    }
}

/// 确保自签服务端证书存在且由当前客户端 CA 签发、SAN 覆盖 `sans`。
///
/// 这是 C3 拆分后的 self-signed 服务端材料入口：CA 必须已存在（缺失时先按
/// [`ensure_client_ca`] 的规则创建），返回服务端证书的 SHA-256 指纹（hex）。
///
/// 自签模式的文件/备份/指纹语义与旧 [`ensure_hub_material`] 完全一致：
/// - 已存在的 CA + 服务端材料不会被覆盖（覆盖会让已安装 agent 立即失联）；
/// - 现存材料失配/半套/CA 被替换时，成对备份后用当前 CA 重签；
/// - 先写 key（0600）再写 cert（0644），失败路径不产生无意义备份。
pub fn ensure_self_signed_server(
    data_dir: &Path,
    sans: &[String],
    policy: CertPolicy,
) -> Result<String> {
    policy.validate()?;
    // SAN 先校验：失败时不创建任何 CA 文件（不留下半个 CA）。
    parse_server_sans(sans)?;
    let dir = cert_dir(data_dir);
    crate::fsutil::ensure_private_dir(&dir, 0o700)?;
    let created_new_ca = ensure_client_ca_at(&dir, policy)?;
    ensure_self_signed_server_with_ca(data_dir, sans, policy, created_new_ca)
}

/// 旧入口：确保 CA + 自签服务端证书都存在，返回服务端证书指纹。
///
/// 保留为 wrapper 以维持既有调用方与测试的行为；ACME 模式请分别调用
/// [`ensure_client_ca`] + `rustboard-hub tls issue`，**不要**调用本函数。
pub fn ensure_hub_material(data_dir: &Path, sans: &[String], policy: CertPolicy) -> Result<String> {
    policy.validate()?;
    // 1) SAN 先校验：确保 init 失败时不会留下半个 CA 目录。
    parse_server_sans(sans)?;

    let dir = cert_dir(data_dir);
    // KI-21：证书目录完全由 hub 拥有，旧版本遗留的 0755 也要在启动时收紧到 0700。
    // 这里只改目录创建；备份命名/清理逻辑不在本任务的范围内。
    crate::fsutil::ensure_private_dir(&dir, 0o700)?;
    let created_new_ca = ensure_client_ca_at(&dir, policy)?;
    ensure_self_signed_server_with_ca(data_dir, sans, policy, created_new_ca)
}

/// 已确保 CA 存在后的自签服务端材料实现。
fn ensure_self_signed_server_with_ca(
    data_dir: &Path,
    sans: &[String],
    policy: CertPolicy,
    created_new_ca: bool,
) -> Result<String> {
    let dir = cert_dir(data_dir);
    let ca = load_validated_ca_at(&dir).context("读取新建/既有 CA 失败")?;

    let server_cert_path = dir.join(SERVER_CERT_FILE);
    let server_key_path = dir.join(SERVER_KEY_FILE);
    let server_complete = server_cert_path.exists() && server_key_path.exists();
    // 重建 CA 时是否原本就有 server 材料——这决定了是否必须提示「所有 agent 需重新纳管」。
    let had_server_material = server_cert_path.exists() || server_key_path.exists();

    // CA 已存在且 server 对也齐全时，必须确认现存 server 证书确实由当前 CA
    // 签发、SAN 覆盖 server_names、且 **与 server.key 配套**；否则说明 CA 被换过、
    // 配置加了 SAN，或上次写盘中断留下半套材料——留着旧 server 会让 hub 起不来
    // 或在 run 阶段被自愈成另一个指纹。
    let mut server_needs_reissue = !server_complete || created_new_ca;
    if !server_needs_reissue {
        let server_pem = std::fs::read_to_string(&server_cert_path)
            .with_context(|| format!("读取服务端证书失败: {}", server_cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&server_key_path)
            .with_context(|| format!("读取服务端私钥失败: {}", server_key_path.display()))?;
        let pair_ok = match cert_matches_key(&server_pem, &key_pem) {
            Ok(ok) => ok,
            Err(err) => {
                tracing::warn!(error = %err, "现存服务端私钥不可解析，按配对损坏处理");
                false
            }
        };
        if !pair_ok {
            tracing::warn!(
                path = %server_cert_path.display(),
                "现存服务端证书与私钥不配套，将用当前 CA 重签并备份旧材料"
            );
            server_needs_reissue = true;
        } else {
            match validate_existing_server_cert(
                &server_pem,
                &ca.cert_pem,
                sans,
                crate::util::now_ms(),
            )
            .context("现存的服务端证书不可用，拒绝静默沿用")
            {
                Ok(()) => {}
                Err(err) => {
                    tracing::warn!(
                        error = %err,
                        "现存服务端证书与当前 CA / server_names 不一致，将用当前 CA 重签并备份旧材料"
                    );
                    server_needs_reissue = true;
                }
            }
        }
    }

    if server_needs_reissue {
        let (cert_pem, key_pem) = issue_server_cert(&ca.key_pem, sans, policy.server_days)?;
        // 自检：链由当前 CA 签发、CN/SAN/有效期符合预期，然后才写盘。
        validate_server_cert(&cert_pem, &ca.cert_pem, sans, crate::util::now_ms())?;
        let new_fingerprint = fingerprint_of_pem(&cert_pem)?;

        // 全部校验通过后才备份（失败路径不产生 bak），再原子写盘。
        // 覆盖既有材料（新 CA 重签 / 旧 server 失配 / 半套材料修复）时必须先留备份。
        let backups = if had_server_material {
            backup_server_material(data_dir)?
        } else {
            Vec::new()
        };
        let backup_list = backups
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // 先写 key 再写 cert：任何时刻都不会出现「新 cert + 旧 key」的一对可用组合。
        write_private(&server_key_path, key_pem.as_bytes())?;
        write_public(&server_cert_path, cert_pem.as_bytes())?;

        // 重建 CA 是最危险的操作：无条件用 WARN 输出，默认 filter（rustboard_common=warn）
        // 必须可见。覆盖三种情况：新 CA + 旧 server、CA 未变但 server 失配、半套材料修复。
        if created_new_ca {
            if had_server_material {
                tracing::warn!(
                    fingerprint = %new_fingerprint,
                    backups = %backup_list,
                    "CA 已重建且服务端证书已用新 CA 重签：所有 agent 都需要重新纳管；\
                      旧服务端材料备份: {backup_list}"
                );
            } else {
                tracing::info!(
                    fingerprint = %new_fingerprint,
                    "已生成新 CA 与服务端证书（全新安装）"
                );
            }
        } else {
            tracing::warn!(
                fingerprint = %new_fingerprint,
                backups = %backup_list,
                "已用当前 CA 重签服务端证书：服务端指纹变化，使用指纹钉扎的旧版 agent 需升级；\
                  如果 CA 也被替换过，所有 agent 都需要重新纳管；旧材料备份: {backup_list}"
            );
        }
        tracing::info!(
            path = %server_cert_path.display(),
            days = policy.server_days,
            "已签发服务端证书"
        );
    }

    let cert_pem = std::fs::read_to_string(&server_cert_path)?;
    fingerprint_of_pem(&cert_pem)
}

/// 用 CA 签发 hub 的服务端证书。SAN 里同时放 IP 和 DNS。
///
/// `sans` 为空或含非法条目时直接报错（见 [`parse_server_sans`]），
/// 绝不静默签出一张没有 SAN 的服务端证书。
pub fn issue_server_cert(
    ca_key_pem: &str,
    sans: &[String],
    validity_days: u32,
) -> Result<(String, String)> {
    // 先校验 SAN 再碰私钥/签名，配置错误能尽早失败。
    let san_types = san_entries(sans)?;

    let ca_key = KeyPair::from_pem(ca_key_pem).context("解析 CA 私钥失败")?;
    let ca_cert = ca_issuer(&ca_key)?;

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    let (not_before, not_after) = validity_window(validity_days)?;
    params.not_before = not_before;
    params.not_after = not_after;
    params
        .distinguished_name
        .push(DnType::CommonName, SERVER_COMMON_NAME);
    params.subject_alt_names = san_types;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    // 严格校验（OpenSSL -x509_strict / Python VERIFY_X509_STRICT）要求非自签证书带 AKI
    params.use_authority_key_identifier_extension = true;

    let cert = params.signed_by(&key, &ca_cert, &ca_key)?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// agent 首次纳管：生成密钥对与 CSR。私钥只在 agent 本地。
pub fn make_csr() -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let csr = csr_for(&key)?;
    Ok((csr, key.serialize_pem()))
}

/// 用**已有私钥**生成 CSR（证书轮换复用原私钥）。
///
/// 轮换不换私钥有两个好处：旧证书与私钥的对应关系不变，且 hub 无需接触任何私钥。
pub fn make_csr_with_key(key_pem: &str) -> Result<String> {
    let key = KeyPair::from_pem(key_pem).context("解析 agent 私钥失败")?;
    csr_for(&key)
}

fn csr_for(key: &KeyPair) -> Result<String> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "rustboard-agent-pending");
    let csr: CertificateSigningRequest = params.serialize_request(key)?;
    Ok(csr.pem()?)
}

/// 校验 CSR 并用 CA 签出客户端证书，CN 固定为 hub 分配的 agent_id。
///
/// `agent_id` 必须来自**会话身份**（客户端证书 CN / 服务端分配），绝不能取 CSR 里的 CN，
/// 否则 agent 可以拿合法 CSR 冒充别的 agent。
pub fn sign_client_csr(
    ca_key_pem: &str,
    csr_pem: &str,
    agent_id: &str,
    validity_days: u32,
) -> Result<String> {
    let (not_before, not_after) = validity_window(validity_days)?;
    sign_client_csr_with_window(ca_key_pem, csr_pem, agent_id, not_before, not_after)
}

/// 指定有效期窗口的签发实现：单测用它构造「已过期」证书验证校验器行为。
fn sign_client_csr_with_window(
    ca_key_pem: &str,
    csr_pem: &str,
    agent_id: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
) -> Result<String> {
    let ca_key = KeyPair::from_pem(ca_key_pem).context("解析 CA 私钥失败")?;
    let ca_cert = ca_issuer(&ca_key)?;

    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .context("CSR 解析失败（可能不是合法的 PEM CSR）")?;

    csr.params.not_before = not_before;
    csr.params.not_after = not_after;
    csr.params.distinguished_name = DistinguishedName::new();
    csr.params
        .distinguished_name
        .push(DnType::CommonName, agent_id);
    csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    csr.params.subject_alt_names = Vec::new();
    csr.params.use_authority_key_identifier_extension = true;

    let cert = csr.signed_by(&ca_cert, &ca_key)?;
    Ok(cert.pem())
}

/// 从客户端证书 DER 里取出 subject CN。
///
/// 只做解析，不做链校验：证书链已经由 rustls 在 TLS 握手阶段验证过。
/// 解析失败或没有 CN 时返回 `None`，调用方按「无身份」处理。
pub fn peer_common_name(der: &[u8]) -> Option<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(der).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?;
    Some(cn.to_string())
}

/// 证书的公开信息摘要（绝不含私钥）。
///
/// CN 用于 `rustboard-agent cert-info` 展示 / 排障；有效期用于轮换判断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertSummary {
    pub common_name: Option<String>,
    /// Unix 秒。
    pub not_before: i64,
    /// Unix 秒。
    pub not_after: i64,
}

/// 解析证书的 subject CN 与有效期。
pub fn cert_summary(pem: &str) -> Result<CertSummary> {
    let certs = load_certs(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|err| anyhow!("解析证书失败: {err:?}"))?;
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|cn| cn.to_string());
    let validity = cert.validity();
    Ok(CertSummary {
        common_name,
        not_before: validity.not_before.timestamp(),
        not_after: validity.not_after.timestamp(),
    })
}

/// 证书有效期窗口（Unix 秒）：`(not_before, not_after)`。
pub fn validity_unix(pem: &str) -> Result<(i64, i64)> {
    let summary = cert_summary(pem)?;
    Ok((summary.not_before, summary.not_after))
}

/// 证书到期时间（Unix 秒）。
pub fn not_after_unix(pem: &str) -> Result<i64> {
    Ok(cert_summary(pem)?.not_after)
}

/// 判断证书与私钥是否配套（比较 SubjectPublicKeyInfo）。
///
/// rustls 的 `with_single_cert` 不做这项校验，握手时才会暴露问题。续签是先写
/// key 后写 cert，进程在中途被 kill 会留下不匹配的一对；启动与续签自检都必须
/// 显式比对 SPKI，才能发现并修复这种状态。
pub fn cert_matches_key(cert_pem: &str, key_pem: &str) -> Result<bool> {
    let key = KeyPair::from_pem(key_pem).context("解析私钥失败")?;
    let key_der = key.public_key_der();
    let key_spki: &[u8] = key_der.as_ref();

    let certs = load_certs(cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|err| anyhow!("解析证书失败: {err:?}"))?;
    Ok(cert.public_key().raw == key_spki)
}

/// 判断证书是否由给定 CA 签发（用 CA 公钥验签 + 检查有效期）。
///
/// 不限制 EKU：服务端证书（ServerAuth）与客户端证书（ClientAuth）都适用。
/// 用途：
/// - agent 落盘 hub 返回的新证书前，确认它确实由本地 `ca.crt` 签发，
///   防止被错误/伪造的响应换上一张下次连不上的证书；
/// - hub 自愈后自检新服务端证书仍由原 CA 签发。
pub fn cert_issued_by_ca(cert_pem: &str, ca_pem: &str, now_ms: i64) -> Result<bool> {
    let certs = load_certs(cert_pem)?;
    let ca_certs = load_certs(ca_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|err| anyhow!("解析证书失败: {err:?}"))?;
    let (_, ca) = x509_parser::parse_x509_certificate(ca_certs[0].as_ref())
        .map_err(|err| anyhow!("解析 CA 证书失败: {err:?}"))?;

    // 签名不匹配说明不是这张 CA 签的：按「不属于本 CA」处理，而不是内部错误。
    if cert.verify_signature(Some(ca.public_key())).is_err() {
        return Ok(false);
    }

    let validity = cert.validity();
    let not_before_ms = validity.not_before.timestamp().saturating_mul(1_000);
    let not_after_ms = validity.not_after.timestamp().saturating_mul(1_000);
    Ok(not_before_ms <= now_ms && now_ms <= not_after_ms)
}

/// 校验一张**新签发的服务端证书**是否符合预期。
///
/// 在写盘之前调用。覆盖四项：
/// 1. subject CN 必须是 [`SERVER_COMMON_NAME`]；
/// 2. 有效期合理：已生效、未过期、不超过最大允许天数；
/// 3. SAN 覆盖 `expected_sans` 里的每一个 IP / DNS 条目；
/// 4. 由 `ca_cert_pem` 签发（CA 公钥验签 + 链上有效期）。
///
/// 任何一项失败都返回错误，调用方据此在写盘前放弃，旧 key/cert 保持不变。
pub fn validate_server_cert(
    cert_pem: &str,
    ca_cert_pem: &str,
    expected_sans: &[String],
    now_ms: i64,
) -> Result<()> {
    check_server_cert(
        cert_pem,
        ca_cert_pem,
        expected_sans,
        now_ms,
        "新签发的服务端证书",
        true,
    )
}

/// 校验**磁盘上现存**的服务端证书：CN / 有效期 / SAN 覆盖 / 由当前 CA 签发。
///
/// 与 [`validate_server_cert`] 共用同一套规则：启动与 `init` 用它拦住
/// 「CA 被替换但 server 证书没换」这种链无效状态。失败信息会点名缺失的 SAN。
pub fn validate_existing_server_cert(
    cert_pem: &str,
    ca_cert_pem: &str,
    expected_sans: &[String],
    now_ms: i64,
) -> Result<()> {
    check_server_cert(
        cert_pem,
        ca_cert_pem,
        expected_sans,
        now_ms,
        "现存的服务端证书",
        // v0.1.0 的历史材料 notAfter=4096 年：现存证书只校验是否有效，
        // 不能套用「新签发证书 ≤36500 天」的上限，否则升级后会直接起不来。
        false,
    )
}

/// 服务端证书校验的共用实现；`what` 只用于错误信息（新签发 / 现存）。
fn check_server_cert(
    cert_pem: &str,
    ca_cert_pem: &str,
    expected_sans: &[String],
    now_ms: i64,
    what: &str,
    enforce_max_validity: bool,
) -> Result<()> {
    // 先验证期望的 SAN 列表本身合法（空列表/非法条目直接失败）。
    let expected = parse_server_sans(expected_sans)?;

    let certs = load_certs(cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|err| anyhow!("解析{what}失败: {err:?}"))?;

    // 1) CN。
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|value| value.as_str().ok());
    if cn != Some(SERVER_COMMON_NAME) {
        bail!(
            "{what}的 CN 不是 {SERVER_COMMON_NAME}（实际 {}）",
            cn.unwrap_or("(无)")
        );
    }

    // 2) 有效期。
    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let now_s = now_ms / 1_000;
    if not_after <= now_s {
        bail!("{what}已过期（notAfter={not_after}）");
    }
    if not_before > now_s + 60 {
        bail!("{what}尚未生效（notBefore={not_before}，now={now_s}）");
    }
    if enforce_max_validity {
        let max_not_after = now_s
            .saturating_add(i64::from(MAX_VALIDITY_DAYS) * 86_400)
            .saturating_add(CLOCK_SKEW_BACKDATE_SECS);
        if not_after > max_not_after {
            bail!("{what}有效期超过 {MAX_VALIDITY_DAYS} 天上限（notAfter={not_after}）");
        }
    }

    // 3) SAN 覆盖：从证书扩展里收集实际 DNS / IP，逐项比对。
    let mut dns_names: Vec<String> = Vec::new();
    let mut raw_ips: Vec<Vec<u8>> = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(name) => dns_names.push((*name).to_string()),
                    GeneralName::IPAddress(raw) => raw_ips.push(raw.to_vec()),
                    _ => {}
                }
            }
        }
    }
    for san in &expected {
        match san {
            ServerSan::Dns(name) => {
                if !dns_names.iter().any(|actual| actual == name) {
                    bail!("{what}的 SAN 未覆盖 {name:?}（实际 DNS SAN: {dns_names:?}）");
                }
            }
            ServerSan::Ip(ip) => {
                let octets: Vec<u8> = match ip {
                    std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                    std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                };
                if !raw_ips.iter().any(|raw| raw == &octets) {
                    bail!("{what}的 SAN 未覆盖 IP {ip}");
                }
            }
        }
    }

    // 4) 由当前 CA 签发（验签 + 有效期）。
    if !cert_issued_by_ca(cert_pem, ca_cert_pem, now_ms)? {
        bail!("{what}不是由当前 CA 签发（ca.crt 可能已被替换，或 server.crt 来自另一套 CA）");
    }
    Ok(())
}

/// 校验一张**公开 CA 签发**的服务端叶子证书（ACME 证书）。
///
/// 与 [`validate_server_cert`] 的区别：ACME 证书通常没有 CN 或 CN 是域名，
/// 因此**不要求** `CN = rustboard-hub`；也不要求由本地 CA 签发（链由 TLS
/// 握手阶段按系统根 / 自定义根验证）。这里只校验与证书来源无关的硬性条件：
/// 1. 有效期：已生效、未过期；
/// 2. SAN 覆盖 `expected_sans`（DNS / IP 精确匹配）；
/// 3. EKU 扩展存在时必须包含 `serverAuth`（`anyExtendedKeyUsage` 视为满足）；
/// 4. BasicConstraints 扩展存在时不得是 CA（叶子证书不允许 ca=true）。
///
/// 任何一项失败都返回中文错误，调用方据此在写盘前放弃，旧材料保持不变。
pub fn validate_public_server_cert(
    cert_pem: &str,
    expected_sans: &[String],
    now_ms: i64,
) -> Result<()> {
    let expected =
        parse_server_sans(expected_sans).context("期望的服务端证书 SAN 列表非法，拒绝校验证书")?;

    let certs = load_certs(cert_pem).context("解析服务端证书 PEM 失败")?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|err| anyhow!("解析服务端证书失败: {err:?}"))?;

    // 1) 有效期。ACME 证书的 notBefore 由 CA 决定，给 60s 时钟偏差容忍。
    let validity = cert.validity();
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();
    let now_s = now_ms / 1_000;
    if not_after <= now_s {
        bail!(
            "服务端证书已过期（notAfter={}，now={}）；请执行 `rustboard-hub tls renew` 续期",
            format_unix_utc(not_after),
            format_unix_utc(now_s)
        );
    }
    if not_before > now_s + 60 {
        bail!(
            "服务端证书尚未生效（notBefore={}，now={}）；请检查系统时间",
            format_unix_utc(not_before),
            format_unix_utc(now_s)
        );
    }

    // 2) 遍历扩展：收集 SAN、EKU、BasicConstraints。
    let mut dns_names: Vec<String> = Vec::new();
    let mut raw_ips: Vec<Vec<u8>> = Vec::new();
    let mut saw_eku = false;
    let mut server_auth = false;
    for extension in cert.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                for name in &san.general_names {
                    match name {
                        GeneralName::DNSName(name) => dns_names.push((*name).to_string()),
                        GeneralName::IPAddress(raw) => raw_ips.push(raw.to_vec()),
                        _ => {}
                    }
                }
            }
            ParsedExtension::ExtendedKeyUsage(eku) => {
                saw_eku = true;
                // RFC 5280：anyExtendedKeyUsage 等价于不限制用途。
                server_auth = eku.server_auth || eku.any;
            }
            ParsedExtension::BasicConstraints(basic) if basic.ca => {
                bail!("服务端证书是 CA 证书（BasicConstraints ca=true），不能作为服务端叶子证书");
            }
            _ => {}
        }
    }
    if saw_eku && !server_auth {
        bail!("服务端证书的 EKU 不含 serverAuth（当前证书不能用于 TLS 服务端）");
    }

    for san in &expected {
        match san {
            ServerSan::Dns(name) => {
                // DNS SAN 大小写不敏感；配置保留用户输入，证书里可能被 CA 规范化。
                if !dns_names
                    .iter()
                    .any(|actual| actual.eq_ignore_ascii_case(name))
                {
                    bail!("服务端证书的 SAN 未覆盖域名 {name:?}（实际 DNS SAN: {dns_names:?}）");
                }
            }
            ServerSan::Ip(ip) => {
                let octets: Vec<u8> = match ip {
                    std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
                    std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
                };
                if !raw_ips.iter().any(|raw| raw == &octets) {
                    bail!("服务端证书的 SAN 未覆盖 IP {ip}");
                }
            }
        }
    }
    Ok(())
}

/// 校验 ACME 返回的**服务端证书链**：叶子 + 至少一张 CA，并逐级验签。
///
/// 仅做形状校验的 [`validate_public_server_cert`] 无法区分「真正由 CA 签发的
/// ACME 叶子」与「旧的 self-signed 服务端证书」：两者都可以有合法 SAN / 有效期。
/// 本函数在形状校验之外强制：
/// 1. 至少两张证书（叶子 + 至少一张 CA），拒绝单证书与自签叶子；
/// 2. 叶子 issuer == 下一张证书 subject，且叶子由下一张证书公钥验签；
/// 3. 链中每一张后续证书都必须是 CA（`BasicConstraints.ca = true`）；
/// 4. 逐级向上验证 issuer / 签名，直到链尾（链尾可以是 intermediate 或 root）。
///
/// 链尾**不做信任锚校验**：公共根由 TLS 客户端（系统根 / 自定义根）验证，
/// 私有链由 `agent-ca.pem` / 配置的 CA 验证；但链尾不是 CA 时直接拒绝。
///
/// 同时要求 PEM 只含 CERTIFICATE 区块，防止把 cert+key 混合内容或裸 base64
/// 当作证书链写盘。所有错误只包含证书序号/公开主题匹配结果，不含私钥。
pub fn validate_acme_chain(cert_pem: &str, expected_sans: &[String], now_ms: i64) -> Result<()> {
    ensure_certificate_only_pem(cert_pem)
        .context("ACME 证书 PEM 只允许 CERTIFICATE 区块，拒绝私钥/公钥/CSR/块外文本")?;
    validate_public_server_cert(cert_pem, expected_sans, now_ms)
        .context("ACME 叶子证书形状校验失败")?;

    let ders = load_certs(cert_pem).context("解析 ACME 证书链 PEM 失败")?;
    if ders.len() < 2 {
        bail!(
            "ACME 证书链不完整：只包含 {} 张证书，至少需要叶子证书 + 一张 CA；\
             拒绝把自签证书或单证书当作 ACME 证书",
            ders.len()
        );
    }

    let certs = ders
        .iter()
        .enumerate()
        .map(|(index, der)| {
            x509_parser::parse_x509_certificate(der.as_ref())
                .map(|(_, cert)| cert)
                .map_err(|err| anyhow!("解析 ACME 证书链第 {} 张证书失败: {err:?}", index + 1))
        })
        .collect::<Result<Vec<_>>>()?;

    // 逐级验证 issuer / subject 匹配与签名；链尾没有下一张证书，不做锚校验。
    for (index, pair) in certs.windows(2).enumerate() {
        let child = &pair[0];
        let issuer = &pair[1];
        // 按 DER 原始字节比较：证书链要求 issuer 与上一级 subject 完全一致。
        if child.issuer().as_raw() != issuer.subject().as_raw() {
            bail!(
                "ACME 证书链第 {} 张证书的 issuer 与第 {} 张证书的 subject 不匹配；\
                 请确认 WFE 返回完整且顺序正确的证书链",
                index + 1,
                index + 2
            );
        }
        if child.verify_signature(Some(issuer.public_key())).is_err() {
            bail!(
                "ACME 证书链第 {} 张证书不是由第 {} 张证书签发（签名校验失败）；\
                 拒绝使用伪造/错配的证书链",
                index + 1,
                index + 2
            );
        }
    }

    // 链尾同样必须是 CA；这里覆盖叶子之后的所有证书（intermediate / root）。
    for (index, cert) in certs.iter().enumerate().skip(1) {
        let mut is_ca = false;
        for extension in cert.extensions() {
            if let ParsedExtension::BasicConstraints(basic) = extension.parsed_extension() {
                is_ca = basic.ca;
            }
        }
        if !is_ca {
            bail!(
                "ACME 证书链第 {} 张证书不是 CA（BasicConstraints.ca 不是 true）；\
                 链尾可以是 intermediate 或 root，但必须是 CA",
                index + 1
            );
        }
    }
    Ok(())
}

/// 读取证书里的公开 SAN 列表（`DNS:example.com` / `IP:192.0.2.1`），供 CLI 展示。
///
/// 只解析叶子证书扩展，不做任何信任判断；绝不含私钥/账户信息。
pub fn public_cert_names(pem: &str) -> Result<Vec<String>> {
    let certs = load_certs(pem).context("解析证书 PEM 失败")?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|err| anyhow!("解析证书失败: {err:?}"))?;
    let mut names = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => names.push(format!("DNS:{dns}")),
                    GeneralName::IPAddress(raw) => {
                        let text = match raw.len() {
                            4 => {
                                std::net::Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).to_string()
                            }
                            16 => {
                                let mut octets = [0u8; 16];
                                octets.copy_from_slice(raw);
                                std::net::Ipv6Addr::from(octets).to_string()
                            }
                            _ => format!("<非法 IP SAN: {raw:?}>"),
                        };
                        names.push(format!("IP:{text}"));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(names)
}

/// 解析并校验客户端 CSR（不签发），用于在消费一次性 token 之前拒绝无效 CSR。
pub fn validate_client_csr(csr_pem: &str) -> Result<()> {
    CertificateSigningRequestParams::from_pem(csr_pem)
        .map(|_| ())
        .context("CSR 解析失败（可能不是合法的 PEM CSR）")
}

/// 剩余寿命（天），向上取整：「还能用几天」。///
/// - 新签发的 30 天证书立即返回 30（而不是 29），便于阈值判断与展示；
/// - `0` 表示正好到期或已过期不足 1 天，负数表示已过期更多天；
/// - 真正的过期判定由 rustls / webpki 在握手时完成，这里只服务于续签决策与展示。
pub fn days_left(pem: &str, now_ms: i64) -> Result<i64> {
    let not_after = not_after_unix(pem)?;
    let remaining_ms = not_after
        .checked_mul(1_000)
        .and_then(|deadline| deadline.checked_sub(now_ms))
        .ok_or_else(|| anyhow!("计算证书剩余寿命溢出"))?;
    Ok((remaining_ms + DAY_MS - 1).div_euclid(DAY_MS))
}

/// 剩余寿命（小时），向上取整：「还能用几小时」。
///
/// 与 [`days_left`] 同源同语义，只是把粒度细到小时：告警阈值单位是小时
/// （`HubAlertsConfig::cert_warn_hours`），用天粒度比较会把 48 小时放大成
/// 48 天，导致证书快到期时不触发。
///
/// - 新签发的 30 天证书返回 720（而不是 719）；
/// - `0` 表示正好到期或已过期不足 1 小时，负数表示已过期更多小时；
/// - 真正的过期判定仍由 rustls / webpki 在握手时完成。
pub fn hours_left(pem: &str, now_ms: i64) -> Result<i64> {
    let not_after = not_after_unix(pem)?;
    let remaining_ms = not_after
        .checked_mul(1_000)
        .and_then(|deadline| deadline.checked_sub(now_ms))
        .ok_or_else(|| anyhow!("计算证书剩余寿命溢出"))?;
    Ok((remaining_ms + HOUR_MS - 1).div_euclid(HOUR_MS))
}

/// Unix 秒格式化成 UTC 的 `YYYY-MM-DDTHH:MM:SSZ`（运维展示用）。
///
/// `time` 只启用了默认的 `std` 特性（未启用 `formatting`），这里用日期组件拼装。
/// 时间戳超出可表示范围时退回原始秒数，展示层不应因此报错。
pub fn format_unix_utc(ts: i64) -> String {
    match OffsetDateTime::from_unix_timestamp(ts) {
        Ok(dt) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            dt.year(),
            dt.month() as u8,
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second()
        ),
        Err(_) => ts.to_string(),
    }
}

pub fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("解析证书 PEM 失败")?;
    if certs.is_empty() {
        return Err(anyhow!("PEM 中没有证书"));
    }
    Ok(certs)
}

/// 校验 PEM 文本只包含 `CERTIFICATE` 区块，拒绝混入任何私钥/公钥/CSR。
///
/// 这里用严格状态机，而不是「扫描 BEGIN 行」：
/// - 证书块外只允许空行 / 纯空白行；
/// - 每个块必须以精确的 `-----BEGIN CERTIFICATE-----` 开始、以精确的
///   `-----END CERTIFICATE-----` 结束，块内只允许 base64 字符
///   （`A-Za-z0-9+/=`）；
/// - 任何块外非空内容（裸 base64/JSON/注释/垃圾）、任何非 `CERTIFICATE`
///   区块、嵌套块、缺失 END 边界都拒绝。
///
/// 这样 `load_certs` 宽松的「跳过无关行」行为就不能被利用：调用方拿到的
/// 文本若通过本函数，就不可能在证书块外夹带私钥或账户 JSON。
///
/// 错误只包含行号与区块类型，不回显证书/私钥内容。
pub fn ensure_certificate_only_pem(text: &str) -> Result<()> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let mut in_certificate = false;
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        let line_no = index + 1;

        if !in_certificate {
            // 块外：空行/纯空白行可以出现，其余一律拒绝。
            if line.trim().is_empty() {
                continue;
            }
            if line == BEGIN {
                in_certificate = true;
                continue;
            }
            if line == END {
                return Err(anyhow!(
                    "PEM 第 {line_no} 行出现没有对应 BEGIN 的 END CERTIFICATE，拒绝解析"
                ));
            }
            if line.starts_with("-----BEGIN ") || line.starts_with("-----END ") {
                let label = pem_block_label(line);
                return Err(anyhow!(
                    "PEM 第 {line_no} 行包含非 CERTIFICATE 区块（{}）；只允许 CERTIFICATE，拒绝私钥/公钥/CSR",
                    if label.is_empty() { "未知区块" } else { label }
                ));
            }
            if line.contains("-----BEGIN ") || line.contains("-----END ") {
                return Err(anyhow!(
                    "PEM 第 {line_no} 行的 CERTIFICATE 边界前后有多余字符，拒绝解析"
                ));
            }
            return Err(anyhow!(
                "PEM 第 {line_no} 行在 CERTIFICATE 块之外包含非空白内容；\
                 只允许空行与 CERTIFICATE 区块，拒绝裸 base64/JSON/注释/垃圾文本；\
                 不是合法 PEM 证书"
            ));
        }

        // 块内：只允许 base64 正文档与精确的 END 边界。
        if line == END {
            in_certificate = false;
            continue;
        }
        if line == BEGIN {
            return Err(anyhow!(
                "PEM 第 {line_no} 行证书块嵌套（上一个 CERTIFICATE 缺少 END 边界），拒绝解析"
            ));
        }
        if line.starts_with("-----BEGIN ") || line.starts_with("-----END ") {
            let label = pem_block_label(line);
            return Err(anyhow!(
                "PEM 第 {line_no} 行在 CERTIFICATE 区块内出现非 CERTIFICATE 区块（{}）；\
                 只允许 CERTIFICATE，拒绝私钥/公钥/CSR",
                if label.is_empty() {
                    "未知区块"
                } else {
                    label
                }
            ));
        }
        if line.is_empty() || line.chars().all(char::is_whitespace) {
            return Err(anyhow!(
                "PEM 第 {line_no} 行在 CERTIFICATE 区块内出现空行/空白行，拒绝解析"
            ));
        }
        if !line
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
        {
            return Err(anyhow!(
                "PEM 第 {line_no} 行不是合法的 base64 证书正文（只允许 A-Za-z0-9+/=）"
            ));
        }
    }

    if in_certificate {
        return Err(anyhow!("PEM 中的 CERTIFICATE 块缺少 END 边界"));
    }
    Ok(())
}

/// 从 PEM 边界行里取出区块类型，仅用于错误信息（不回显正文）。
fn pem_block_label(line: &str) -> &str {
    line.strip_prefix("-----BEGIN ")
        .or_else(|| line.strip_prefix("-----END "))
        .unwrap_or(line)
        .trim_end_matches('-')
        .trim()
}

/// 从 PEM 证书链中提取最后一张 `CERTIFICATE`，按 PEM 原样返回。
///
/// ACME 返回的 `server.crt` 通常是「叶子 + 中间/根」的链；agent 的信任锚必须
/// 用链尾的 CA，而不是 ACME WFE 的 HTTPS 根。这里只接受 CERTIFICATE 区块，
/// 缺少结束边界、块嵌套、无证书或块本身无法解析都返回中文错误。
pub fn last_certificate_pem(chain_pem: &str) -> Result<String> {
    ensure_certificate_only_pem(chain_pem)?;

    let mut blocks: Vec<Vec<&str>> = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for (index, raw) in chain_pem.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if line == "-----BEGIN CERTIFICATE-----" {
            if current.is_some() {
                return Err(anyhow!("PEM 第 {} 行证书块嵌套，拒绝解析", index + 1));
            }
            current = Some(vec![line]);
        } else if line == "-----END CERTIFICATE-----" {
            let mut block = current.take().ok_or_else(|| {
                anyhow!(
                    "PEM 第 {} 行出现没有对应 BEGIN 的 END CERTIFICATE",
                    index + 1
                )
            })?;
            block.push(line);
            blocks.push(block);
        } else if let Some(block) = current.as_mut() {
            block.push(line);
        }
    }
    if current.is_some() {
        return Err(anyhow!("PEM 中的 CERTIFICATE 块缺少 END 边界"));
    }

    let last = blocks
        .pop()
        .ok_or_else(|| anyhow!("PEM 中没有 CERTIFICATE 区块，无法提取信任锚"))?;
    let mut pem = last.join("\n");
    pem.push('\n');
    // 提取出的块本身也必须可解析：坏 base64 / 截断 DER 在这里就失败，
    // 不能把一张无法作为信任锚的内容写盘后再让 agent 报错。
    load_certs(&pem).context("提取的链尾证书无法解析")?;
    Ok(pem)
}

/// 判断一张证书是否为 CA（`BasicConstraints.ca = true`）。
///
/// 没有 BasicConstraints 扩展时按 `false` 处理（不是 CA）；解析失败报错，
/// 不把坏证书当成可信任锚。
pub fn certificate_is_ca(pem: &str) -> Result<bool> {
    let certs = load_certs(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(certs[0].as_ref())
        .map_err(|err| anyhow!("解析证书失败: {err:?}"))?;
    let mut is_ca = false;
    for extension in cert.extensions() {
        if let ParsedExtension::BasicConstraints(basic) = extension.parsed_extension() {
            is_ca = basic.ca;
        }
    }
    Ok(is_ca)
}

pub fn load_key(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).context("解析私钥 PEM 失败")
}

pub fn fingerprint_of_pem(pem: &str) -> Result<String> {
    let certs = load_certs(pem)?;
    Ok(hex::encode(Sha256::digest(certs[0].as_ref())))
}

/// 接受 `sha256:ab:cd:...`、`abcd...` 等写法。
pub fn parse_fingerprint(text: &str) -> Result<[u8; 32]> {
    let cleaned: String = text
        .trim()
        .trim_start_matches("sha256:")
        .chars()
        .filter(|c| *c != ':' && !c.is_whitespace())
        .collect();
    let bytes = hex::decode(&cleaned).context("指纹不是合法 hex")?;
    if bytes.len() != 32 {
        return Err(anyhow!("指纹应为 32 字节，实际 {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// hub 的 TLS 服务端配置：要求客户端证书，但允许未认证连接进来做 enrollment。
///
/// 只启用 TLS 1.3（显式指定版本，不依赖 feature 开关；将来若有人打开 tls12
/// feature，也不会静默回退到 TLS 1.2）。证书与私钥必须配套，否则直接报错并提示
/// 修复命令——不能等到握手时才失败。
pub fn server_config(data_dir: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let dir = cert_dir(data_dir);
    let cert_path = dir.join(SERVER_CERT_FILE);
    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let key_path = dir.join(SERVER_KEY_FILE);
    // M3：服务端私钥也属于敏感文件，旧版本可能留下过宽权限。
    crate::fsutil::harden(&key_path, 0o600)?;
    let key_pem = std::fs::read_to_string(&key_path)?;
    let ca_pem = std::fs::read_to_string(dir.join(CA_CERT_FILE))?;

    if !cert_matches_key(&cert_pem, &key_pem)? {
        return Err(anyhow!(
            "服务端证书与私钥不匹配（{} 与 {} 不是一对，可能是上次续签在写盘中途被中断）；\
             执行 `rustboard-hub rotate-cert --force` 重新签发，或直接启动 hub 触发自动修复",
            cert_path.display(),
            key_path.display()
        ));
    }

    let certs = load_certs(&cert_pem)?;
    let key = load_key(&key_pem)?;

    let mut roots = rustls::RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(load_certs(&ca_pem)?);
    if added == 0 {
        return Err(anyhow!("CA 证书无法载入信任库"));
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .allow_unauthenticated()
    .build()
    .context("构建客户端证书校验器失败")?;

    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 管理 API 的 TLS 服务端配置：server-auth，**不要求客户端证书**。
///
/// 复用 agent 入口同一对 `server.crt` / `server.key`，但管理端只验证服务端，
/// 因此不能复用 [`server_config`]（它还要求客户端证书）。构建前显式校验：
/// key/cert 配套、证书由当前 CA 签发、CN/SAN 覆盖 `expected_sans`、未过期。
///
/// 只启用 TLS 1.3，ALPN 固定 `http/1.1`（管理 API 是手写 hyper HTTP/1 服务）。
pub fn admin_server_config(
    data_dir: &Path,
    expected_sans: &[String],
) -> Result<Arc<rustls::ServerConfig>> {
    let dir = cert_dir(data_dir);
    let cert_path = dir.join(SERVER_CERT_FILE);
    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("读取服务端证书失败: {}", cert_path.display()))?;
    let key_path = dir.join(SERVER_KEY_FILE);
    // 与服务端入口一致：旧版本可能留下过宽权限，加载前收紧到 0600。
    crate::fsutil::harden(&key_path, 0o600)?;
    let key_pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("读取服务端私钥失败: {}", key_path.display()))?;
    let ca_path = dir.join(CA_CERT_FILE);
    let ca_pem = std::fs::read_to_string(&ca_path)
        .with_context(|| format!("读取 CA 证书失败: {}", ca_path.display()))?;

    if !cert_matches_key(&cert_pem, &key_pem)? {
        return Err(anyhow!(
            "服务端证书与私钥不匹配（{} 与 {} 不是一对，可能是上次续签在写盘中途被中断）；\
             执行 `rustboard-hub rotate-cert --force` 重新签发，或直接启动 hub 触发自动修复",
            cert_path.display(),
            key_path.display()
        ));
    }
    validate_existing_server_cert(&cert_pem, &ca_pem, expected_sans, crate::util::now_ms())
        .context("管理 API TLS 证书校验失败（CA 链 / SAN / 有效期）")?;

    let certs = load_certs(&cert_pem)?;
    let key = load_key(&key_pem)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 管理 API 的 TLS 服务端配置（公开 CA / ACME 证书）：server-auth，不要求客户端证书。
///
/// 与 [`admin_server_config`] 的区别：不要求证书由本地 `ca.crt` 签发，改用
/// [`validate_acme_chain`] 校验 SAN / 有效期 / EKU / 非 CA + 叶子到 CA 的链，
/// 因此 ACME（含 IP identifier、回环 IP SAN）签发的证书可以直接用于管理端口。
/// 链尾的信任锚仍由客户端在握手阶段按系统根 / 自定义根验证。
pub fn admin_server_config_public(
    data_dir: &Path,
    expected_sans: &[String],
) -> Result<Arc<rustls::ServerConfig>> {
    let dir = cert_dir(data_dir);
    let cert_path = dir.join(SERVER_CERT_FILE);
    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("读取服务端证书失败: {}", cert_path.display()))?;
    let key_path = dir.join(SERVER_KEY_FILE);
    // 与服务端入口一致：旧版本可能留下过宽权限，加载前收紧到 0600。
    crate::fsutil::harden(&key_path, 0o600)?;
    let key_pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("读取服务端私钥失败: {}", key_path.display()))?;

    if !cert_matches_key(&cert_pem, &key_pem)? {
        return Err(anyhow!(
            "服务端证书与私钥不匹配（{} 与 {} 不是一对，可能是签发/写盘中途被中断）；\
             执行 `rustboard-hub tls issue --config <config>` 重新获取证书",
            cert_path.display(),
            key_path.display()
        ));
    }
    validate_acme_chain(&cert_pem, expected_sans, crate::util::now_ms()).context(
        "管理 API TLS 证书链校验失败（SAN / 有效期 / EKU / CA 链），请重新执行 tls issue",
    )?;

    let certs = load_certs(&cert_pem)?;
    let key = load_key(&key_pem)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// agent 的 TLS 客户端配置：固定服务端证书指纹，可选携带客户端证书。
///
/// 只用于 bootstrap（尚未纳管）与「拿不到 CA 证书」的兼容回退：
/// 指纹钉扎在服务端证书轮换后会立即失效，已纳管 agent 应改用 [`client_config_ca`]。
pub fn client_config_pinned(
    fingerprint: &str,
    client_cert_pem: Option<&str>,
    client_key_pem: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>> {
    let pinned = parse_fingerprint(fingerprint)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedCertVerifier {
        fingerprint: pinned,
        provider: provider.clone(),
    });

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    let mut config = match (client_cert_pem, client_key_pem) {
        (Some(cert), Some(key)) => {
            builder.with_client_auth_cert(load_certs(cert)?, load_key(key)?)?
        }
        _ => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 已纳管 agent 的 TLS 客户端配置：用 hub 的 CA 做标准链校验 + 主机名校验。
///
/// 与指纹钉扎的区别：
/// - 服务端证书轮换（同一 CA 重签）后 agent 仍能连上，无需重新纳管（A4）；
/// - 必须同时通过证书链与 URL 主机名，防止被持有同一 CA 证书的其它端点冒充。
pub fn client_config_ca(
    ca_pem: &str,
    client_cert_pem: &str,
    client_key_pem: &str,
) -> Result<Arc<rustls::ClientConfig>> {
    let mut roots = rustls::RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(load_certs(ca_pem)?);
    if added == 0 {
        return Err(anyhow!("CA 证书无法载入信任库（{ignored} 张被忽略）"));
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(load_certs(client_cert_pem)?, load_key(client_key_pem)?)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 从 PEM 构建信任根集合：可包含多张证书，但至少要有一张能解析。
fn root_store_from_pem(ca_pem: &str) -> Result<rustls::RootCertStore> {
    if ca_pem.trim().is_empty() {
        return Err(anyhow!("CA 证书 PEM 为空"));
    }
    let certs = load_certs(ca_pem).context("解析 CA 证书 PEM 失败")?;
    let mut roots = rustls::RootCertStore::empty();
    let (added, ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!(
            "CA 证书中没有可用的信任根（{ignored} 张证书无法解析）"
        ));
    }
    Ok(roots)
}

/// 用给定信任根与可选客户端证书构建 TLS 1.3 客户端配置。
///
/// 客户端证书与私钥必须成对出现：只给其中一个会直接报错，不能静默退化成
/// 单向 TLS（否则 mTLS 端会在握手阶段以难懂的错误拒绝连接）。
fn client_config_with_roots(
    roots: rustls::RootCertStore,
    client_cert_pem: Option<&str>,
    client_key_pem: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>> {
    let identity = match (client_cert_pem, client_key_pem) {
        (None, None) => None,
        (Some(cert), Some(key)) => Some((load_certs(cert)?, load_key(key)?)),
        _ => return Err(anyhow!("客户端证书与私钥必须成对提供")),
    };

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots);
    let mut config = match identity {
        Some((certs, key)) => builder.with_client_auth_cert(certs, key)?,
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 用**操作系统根证书**做链校验 + URL 主机名校验，可选携带客户端证书。
///
/// 用于 `tls_mode = "system-roots"`（公共 ACME 证书）。根证书由
/// `rustls-native-certs` 读取（尊重 `SSL_CERT_FILE` / `SSL_CERT_DIR`）；
/// 读取不到任何可用证书时明确报错，绝不静默退化为「不校验」。
pub fn client_config_system_roots(
    client_cert_pem: Option<&str>,
    client_key_pem: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>> {
    let native = rustls_native_certs::load_native_certs();
    let error_count = native.errors.len();
    let mut roots = rustls::RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        return Err(anyhow!(
            "无法加载系统根证书（0 张可用证书，{error_count} 个读取错误）；\
             请安装 CA 证书包（如 ca-certificates）或改用 custom-ca"
        ));
    }
    client_config_with_roots(roots, client_cert_pem, client_key_pem)
}

/// bootstrap 专用：系统根 + 无客户端证书（尚未纳管）。
pub fn client_config_bootstrap_system_roots() -> Result<Arc<rustls::ClientConfig>> {
    client_config_system_roots(None, None)
}

/// 用显式传入的 CA 证书（可多张）做链校验 + 主机名校验，可选客户端证书。
///
/// 用于 `tls_mode = "custom-ca"`：私有 ACME / 自签 hub。CA 必须至少有一张
/// 可解析证书；客户端证书与私钥必须成对提供。
pub fn client_config_custom_ca(
    server_ca_pem: &str,
    client_cert_pem: Option<&str>,
    client_key_pem: Option<&str>,
) -> Result<Arc<rustls::ClientConfig>> {
    let roots = root_store_from_pem(server_ca_pem).context("server_ca 证书无效")?;
    client_config_with_roots(roots, client_cert_pem, client_key_pem)
}

/// bootstrap 专用：指定 CA + 无客户端证书（尚未纳管）。
pub fn client_config_bootstrap_custom_ca(server_ca_pem: &str) -> Result<Arc<rustls::ClientConfig>> {
    client_config_custom_ca(server_ca_pem, None, None)
}

/// 从 PEM 内容构建**不要求客户端证书**的服务端 TLS 配置。
///
/// 用于面板直连 HTTPS（C7）与未来 ACME 证书加载：TLS 1.3、ALPN `http/1.1`。
/// 只做 server-auth；需要 mTLS 的 agent 入口仍用 [`server_config`]。
/// 函数名沿用计划中的 `server_config_from_paths`，但参数是已读取的 PEM 内容，
/// 以便调用方自行决定路径权限/符号链接策略。
pub fn server_config_from_paths(
    cert_pem: &str,
    key_pem: &str,
) -> Result<Arc<rustls::ServerConfig>> {
    if cert_pem.trim().is_empty() {
        return Err(anyhow!("服务端证书 PEM 为空"));
    }
    if key_pem.trim().is_empty() {
        return Err(anyhow!("服务端私钥 PEM 为空"));
    }
    if !cert_matches_key(cert_pem, key_pem)? {
        return Err(anyhow!("服务端证书与私钥不匹配"));
    }
    let certs = load_certs(cert_pem)?;
    let key = load_key(key_pem)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// 只比对服务端证书的 SHA-256 指纹。
///
/// 自签模式下没有公共信任链可用，指纹随安装命令带外分发，等价于 SSH 的 known_hosts。
struct PinnedCertVerifier {
    fingerprint: [u8; 32],
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl std::fmt::Debug for PinnedCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinnedCertVerifier")
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let digest = Sha256::digest(end_entity.as_ref());
        if digest.as_slice() == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "服务端证书指纹不匹配，实际为 {}",
                hex::encode(digest)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// 口令/密钥的 SHA-256 hex，用于落库比对。
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    use rcgen::PublicKeyData;
    use rustls::pki_types::UnixTime;
    use rustls::server::danger::ClientCertVerifier;

    /// 测试专用临时目录：进程 id + 自增序号，避免并行测试互相覆盖。
    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rb-tls-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn read_cert(data_dir: &Path, name: &str) -> String {
        std::fs::read_to_string(cert_dir(data_dir).join(name)).unwrap()
    }

    /// 在证书目录写一个指定后缀的备份文件，用于注入确定的时间/序号。
    fn write_backup(data_dir: &Path, base: &str, suffix: &str) -> PathBuf {
        let dir = cert_dir(data_dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{base}.bak-{suffix}"));
        std::fs::write(&path, b"backup").unwrap();
        path
    }

    /// 收集某类材料当前被识别为托管备份的文件名。
    fn managed_backup_names(data_dir: &Path, base: &str) -> Vec<String> {
        std::fs::read_dir(cert_dir(data_dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_managed_backup(name, base))
            .collect()
    }

    /// A1：`notAfter` 必须是配置的天数，`notBefore` 必须是 now-1h（容差 5 分钟）。
    fn assert_validity(pem: &str, days: u32) {
        let (not_before, not_after) = validity_unix(pem).unwrap();
        let now = crate::util::now_ms() / 1_000;
        let expected_after = now + i64::from(days) * 86_400;
        assert!(
            (not_after - expected_after).abs() <= 300,
            "notAfter 偏离 {days} 天超过 5 分钟，差 {} 秒",
            not_after - expected_after
        );
        let expected_before = now - CLOCK_SKEW_BACKDATE_SECS;
        assert!(
            (not_before - expected_before).abs() <= 300,
            "notBefore 没有回拨 1 小时（期望 {}，实际 {not_before}）",
            expected_before
        );
        assert!(not_before < not_after);
    }

    fn client_verifier(ca_der: CertificateDer<'static>) -> Arc<dyn ClientCertVerifier> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_der).unwrap();
        rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap()
    }

    /// 在进程内驱动一次完整 TLS 握手（不经过 socket），用于验证真实配置对象。
    ///
    /// 返回握手后的两端连接；调用方可以检查协商版本与对端证书。
    fn handshake(
        client_config: Arc<rustls::ClientConfig>,
        server_config: Arc<rustls::ServerConfig>,
        server_name: &str,
    ) -> Result<(rustls::ClientConnection, rustls::ServerConnection)> {
        let name = ServerName::try_from(server_name.to_string()).unwrap();
        let mut client = rustls::ClientConnection::new(client_config, name)?;
        let mut server = rustls::ServerConnection::new(server_config)?;
        let mut c2s = Vec::new();
        let mut s2c = Vec::new();
        for _ in 0..20 {
            while client.wants_write() {
                client.write_tls(&mut c2s)?;
            }
            if !c2s.is_empty() {
                server.read_tls(&mut std::io::Cursor::new(c2s.as_slice()))?;
                server.process_new_packets()?;
                c2s.clear();
            }
            while server.wants_write() {
                server.write_tls(&mut s2c)?;
            }
            if !s2c.is_empty() {
                client.read_tls(&mut std::io::Cursor::new(s2c.as_slice()))?;
                client.process_new_packets()?;
                s2c.clear();
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok((client, server));
            }
        }
        Err(anyhow!("握手未在 20 轮内完成"))
    }

    #[test]
    fn fingerprint_roundtrip() {
        let hexstr = "ab".repeat(32);
        let parsed = parse_fingerprint(&hexstr).unwrap();
        assert_eq!(hex::encode(parsed), hexstr);

        let colon = parsed
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse_fingerprint(&colon).unwrap(), parsed);
        assert_eq!(
            parse_fingerprint(&format!("sha256:{colon}")).unwrap(),
            parsed
        );
    }

    /// A2：CA / 服务端 / 客户端三种证书都按策略里的天数签发。
    #[test]
    fn a1_new_certs_use_configured_validity() {
        let dir = temp_dir("validity");
        let policy = CertPolicy {
            ca_days: 3_650,
            server_days: 365,
            client_days: 90,
        };
        ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();

        let ca_pem = read_cert(&dir, CA_CERT_FILE);
        let ca_key_pem = read_cert(&dir, CA_KEY_FILE);
        assert_validity(&ca_pem, policy.ca_days);
        assert_validity(&read_cert(&dir, SERVER_CERT_FILE), policy.server_days);

        let (csr_pem, _key_pem) = make_csr().unwrap();
        let client_pem =
            sign_client_csr(&ca_key_pem, &csr_pem, "agent-a1", policy.client_days).unwrap();
        assert_validity(&client_pem, policy.client_days);

        // hub 不落盘任何客户端私钥。
        assert!(!cert_dir(&dir).join(AGENT_KEY_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A1：not_after 解析与剩余天数（向上取整）必须自洽。
    #[test]
    fn a1_not_after_and_days_left_are_parsed() {
        let dir = temp_dir("days-left");
        let policy = CertPolicy {
            ca_days: 3_650,
            server_days: 30,
            client_days: 90,
        };
        ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let server_pem = read_cert(&dir, SERVER_CERT_FILE);

        let now = crate::util::now_ms();
        assert_eq!(
            not_after_unix(&server_pem).unwrap(),
            validity_unix(&server_pem).unwrap().1
        );
        // 刚签发的 30 天证书显示 30 天，而不是 29 天。
        assert_eq!(days_left(&server_pem, now).unwrap(), 30);
        assert_eq!(
            days_left(&server_pem, now + 30 * DAY_MS).unwrap(),
            0,
            "到期当天应返回 0"
        );
        assert!(
            days_left(&server_pem, now + 31 * DAY_MS).unwrap() < 0,
            "过期后必须返回负数"
        );

        // 非证书输入必须报错，不能 panic。
        assert!(not_after_unix("not a cert").is_err());
        assert!(days_left("not a cert", now).is_err());
        // 展示格式：UTC ISO8601。
        let text = format_unix_utc(0);
        assert_eq!(text, "1970-01-01T00:00:00Z");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// M4-B1 修复：剩余小时数必须向上取整，且与到期时刻精确对齐。
    ///
    /// 告警阈值单位是小时（`cert_warn_hours`）；用天粒度比较会把 48 小时
    /// 放大成 48 天，因此这里逐毫秒验证 0 / 1 / 多小时的边界。
    #[test]
    fn m4_b1fix_hours_left_rounds_up_and_matches_deadline() {
        let dir = temp_dir("hours-left");
        let policy = CertPolicy {
            ca_days: 3_650,
            server_days: 30,
            client_days: 90,
        };
        ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let server_pem = read_cert(&dir, SERVER_CERT_FILE);
        let deadline_ms = not_after_unix(&server_pem).unwrap() * 1_000;

        // 刚签发的 30 天证书 = 720 小时，而不是 719 / 29。
        let now = crate::util::now_ms();
        assert_eq!(hours_left(&server_pem, now).unwrap(), 30 * 24);
        assert_eq!(
            hours_left(&server_pem, deadline_ms).unwrap(),
            0,
            "正好到期必须返回 0"
        );

        // 到期前 1 毫秒：向上取整为 1 小时。
        assert_eq!(hours_left(&server_pem, deadline_ms - 1).unwrap(), 1);
        // 正好剩余 N 小时仍返回 N；多 1 毫秒必须进位到 N+1。
        assert_eq!(hours_left(&server_pem, deadline_ms - HOUR_MS).unwrap(), 1);
        assert_eq!(
            hours_left(&server_pem, deadline_ms - HOUR_MS - 1).unwrap(),
            2
        );
        assert_eq!(
            hours_left(&server_pem, deadline_ms - 48 * HOUR_MS).unwrap(),
            48
        );
        assert_eq!(
            hours_left(&server_pem, deadline_ms - 48 * HOUR_MS - 1).unwrap(),
            49
        );

        // 过期：不足 1 小时按 0，整小时按负数。
        assert_eq!(hours_left(&server_pem, deadline_ms + 1).unwrap(), 0);
        assert_eq!(hours_left(&server_pem, deadline_ms + HOUR_MS).unwrap(), -1);
        assert_eq!(
            hours_left(&server_pem, deadline_ms + HOUR_MS + 1).unwrap(),
            -1
        );
        assert_eq!(
            hours_left(&server_pem, deadline_ms + 2 * HOUR_MS).unwrap(),
            -2
        );

        // 非证书输入必须报错，不能 panic。
        assert!(hours_left("not a cert", now).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A1：CA 签发的客户端证书能被 `WebPkiClientVerifier` 接受，过期证书被拒。
    #[test]
    fn a1_ca_signed_client_cert_is_accepted_but_expired_is_rejected() {
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&ca_key)
            .unwrap();
        let ca_key_pem = ca_key.serialize_pem();
        let verifier = client_verifier(ca_cert.der().clone());

        let (csr_pem, _key_pem) = make_csr().unwrap();

        // 正常签发：CA 签发 + 90 天有效期，必须被接受。
        let fresh = sign_client_csr(&ca_key_pem, &csr_pem, "agent-ok", 90).unwrap();
        let fresh_der = load_certs(&fresh).unwrap()[0].clone();
        verifier
            .verify_client_cert(&fresh_der, &[], UnixTime::now())
            .expect("CA 签发的有效客户端证书必须被接受");

        // 过期证书：链本身正确，但有效期已过，必须被拒。
        let now = OffsetDateTime::now_utc();
        let expired = sign_client_csr_with_window(
            &ca_key_pem,
            &csr_pem,
            "agent-expired",
            now - TimeDuration::days(2),
            now - TimeDuration::days(1),
        )
        .unwrap();
        let expired_der = load_certs(&expired).unwrap()[0].clone();
        let err = verifier
            .verify_client_cert(&expired_der, &[], UnixTime::now())
            .expect_err("过期证书必须被拒绝");
        assert!(
            matches!(
                err,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::Expired
                        | rustls::CertificateError::ExpiredContext { .. }
                )
            ),
            "过期证书应因 Expired 被拒，实际: {err:?}"
        );

        // 不是这张 CA 签发的证书也必须被拒（防止任意自签证书混入）。
        let foreign_key = KeyPair::generate().unwrap();
        let foreign_params = ca_params(DEFAULT_CA_DAYS).unwrap();
        let foreign_ca = foreign_params.self_signed(&foreign_key).unwrap();
        let foreign =
            sign_client_csr(&foreign_key.serialize_pem(), &csr_pem, "agent-foreign", 90).unwrap();
        let _ = foreign_ca;
        let foreign_der = load_certs(&foreign).unwrap()[0].clone();
        assert!(verifier
            .verify_client_cert(&foreign_der, &[], UnixTime::now())
            .is_err());
    }

    /// A4：用 `client_config_ca` 的**结果**做真实 TLS 握手（而不是另建 verifier）：
    /// - 自有 CA + 正确主机名：握手成功，协商 TLS 1.3，双方都看到对方证书；
    /// - 错误主机名：握手失败；
    /// - 无关 CA：握手失败。
    #[test]
    fn a4_client_config_ca_completes_real_handshake() {
        let dir = temp_dir("ca-trust");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let ca_pem = read_cert(&dir, CA_CERT_FILE);
        let ca_key_pem = read_cert(&dir, CA_KEY_FILE);
        let server_pem = read_cert(&dir, SERVER_CERT_FILE);
        let server_config = server_config(&dir).unwrap();

        // agent 侧：CA 签发的客户端证书 + 原私钥。
        let (csr_pem, key_pem) = make_csr().unwrap();
        let client_pem = sign_client_csr(&ca_key_pem, &csr_pem, "agent-ca", 90).unwrap();
        let client_config = client_config_ca(&ca_pem, &client_pem, &key_pem).unwrap();
        assert_eq!(client_config.alpn_protocols, vec![b"http/1.1".to_vec()]);

        let (client, server) = handshake(client_config, server_config.clone(), "localhost")
            .expect("自有 CA + 正确主机名必须握手成功");
        // 显式 TLS 1.3（防止未来打开 tls12 feature 后静默回退）。
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3),
            "客户端必须协商 TLS 1.3"
        );
        assert_eq!(
            server.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        // 双向认证：服务端看到客户端证书，客户端看到服务端证书。
        let server_seen = server
            .peer_certificates()
            .expect("服务端必须看到客户端证书");
        assert_eq!(
            server_seen[0].as_ref(),
            load_certs(&client_pem).unwrap()[0].as_ref()
        );
        let client_seen = client
            .peer_certificates()
            .expect("客户端必须看到服务端证书");
        assert_eq!(
            client_seen[0].as_ref(),
            load_certs(&server_pem).unwrap()[0].as_ref()
        );

        // 主机名不在 SAN 里：必须拒绝（否则 CA 信任模式等于放弃身份绑定）。
        let wrong_name = client_config_ca(&ca_pem, &client_pem, &key_pem).unwrap();
        assert!(
            handshake(wrong_name, server_config.clone(), "wrong.example").is_err(),
            "错误主机名必须握手失败"
        );

        // 换一张无关的 CA：同一张服务端证书也必须被拒绝。
        let other_key = KeyPair::generate().unwrap();
        let other_pem = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&other_key)
            .unwrap()
            .pem();
        let foreign_config = client_config_ca(&other_pem, &client_pem, &key_pem).unwrap();
        assert!(
            handshake(foreign_config, server_config, "localhost").is_err(),
            "无关 CA 必须握手失败"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C2：`client_config_system_roots` 必须能在不访问网络的情况下构建，并保留
    /// 客户端证书成对约束；系统 CA 包缺失时才报错，不能静默忽略。
    #[test]
    fn c2_client_config_system_roots_builds_without_network() {
        let config =
            client_config_system_roots(None, None).expect("系统根证书应能在常规 Linux 环境构建");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);

        // 只给证书或只给私钥：必须显式报错，而不是退化成单向 TLS。
        let err = client_config_system_roots(Some("-----BEGIN CERTIFICATE-----"), None)
            .expect_err("客户端证书/私钥必须成对");
        assert!(format!("{err:#}").contains("成对"), "{err:#}");
    }

    /// C2：自定义 CA（多证书 bundle）+ 客户端证书做真实双向握手。
    #[test]
    fn c2_custom_ca_bundle_completes_real_handshake_with_client_cert() {
        let dir = temp_dir("custom-ca-bundle");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let ca_pem = read_cert(&dir, CA_CERT_FILE);
        let ca_key_pem = read_cert(&dir, CA_KEY_FILE);
        let server_pem = read_cert(&dir, SERVER_CERT_FILE);
        let server_key_pem = read_cert(&dir, SERVER_KEY_FILE);

        // 第二个无关 CA 混在 bundle 里：多根必须被接受，且不能影响正常链校验。
        let extra_key = KeyPair::generate().unwrap();
        let extra_pem = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&extra_key)
            .unwrap()
            .pem();
        let bundle = format!("{ca_pem}{extra_pem}");

        let (csr_pem, key_pem) = make_csr().unwrap();
        let client_pem = sign_client_csr(&ca_key_pem, &csr_pem, "agent-c2", 90).unwrap();
        let client_config =
            client_config_custom_ca(&bundle, Some(&client_pem), Some(&key_pem)).unwrap();
        assert_eq!(client_config.alpn_protocols, vec![b"http/1.1".to_vec()]);

        let mtls_server = server_config(&dir).unwrap();
        let (client, server) = handshake(client_config, mtls_server, "localhost")
            .expect("自定义 CA + 客户端证书必须握手成功");
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert_eq!(
            server.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert!(
            server.peer_certificates().is_some(),
            "服务端必须看到客户端证书"
        );
        assert!(
            client.peer_certificates().is_some(),
            "客户端必须看到服务端证书"
        );

        // 无关 CA 必须被拒：bundle 里只有正确的第一张能验证这张服务端证书。
        let foreign_config =
            client_config_custom_ca(&extra_pem, Some(&client_pem), Some(&key_pem)).unwrap();
        assert!(
            handshake(foreign_config, server_config(&dir).unwrap(), "localhost").is_err(),
            "无关 CA 必须握手失败"
        );

        // 错误主机名同样必须失败（custom-ca 不是「只信任 CA」）。
        let wrong_name =
            client_config_custom_ca(&bundle, Some(&client_pem), Some(&key_pem)).unwrap();
        assert!(
            handshake(wrong_name, server_config(&dir).unwrap(), "wrong.example").is_err(),
            "错误主机名必须握手失败"
        );

        // bootstrap：无客户端证书也能完成 server-auth 握手（服务端不要求客户端证书）。
        let bootstrap = client_config_bootstrap_custom_ca(&bundle).unwrap();
        let public_server = server_config_from_paths(&server_pem, &server_key_pem).unwrap();
        assert_eq!(public_server.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let (client, server) = handshake(bootstrap, public_server, "localhost")
            .expect("bootstrap custom-ca 必须握手成功");
        assert_eq!(
            client.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        assert!(
            server.peer_certificates().is_none(),
            "bootstrap 不应携带客户端证书"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C2：非法/空 CA PEM 与不配套的 server cert/key 必须在构建阶段报错。
    #[test]
    fn c2_tls_config_helpers_reject_invalid_material() {
        for bad in [
            "",
            "not a pem",
            "-----BEGIN CERTIFICATE-----\n\0\n-----END CERTIFICATE-----",
        ] {
            let err = client_config_custom_ca(bad, None, None)
                .expect_err("非法 CA PEM 必须被拒绝")
                .to_string();
            assert!(err.contains("server_ca"), "错误应点名 server_ca: {err}");
        }

        let dir = temp_dir("server-config-paths");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let cert_pem = read_cert(&dir, SERVER_CERT_FILE);
        let (_csr, wrong_key) = make_csr().unwrap();
        let err = server_config_from_paths(&cert_pem, &wrong_key)
            .expect_err("不配套的 server cert/key 必须被拒绝")
            .to_string();
        assert!(err.contains("不匹配"), "错误应说明不匹配: {err}");
        assert!(server_config_from_paths("", &wrong_key).is_err());
        assert!(server_config_from_paths(&cert_pem, "").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C4：CA 文件只允许 CERTIFICATE 区块；cert+key 混合 PEM 必须拒绝。
    #[test]
    fn c4_ensure_certificate_only_pem_rejects_private_key_bundles() {
        let cert_key = KeyPair::generate().unwrap();
        let cert_pem = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&cert_key)
            .unwrap()
            .pem();
        ensure_certificate_only_pem(&cert_pem).expect("纯证书 PEM 必须通过");

        // base64 正文出现「PRIVATE KEY」字样不得误伤（PEM 边界才是判据）。
        let base64_lookalike =
            "-----BEGIN CERTIFICATE-----\nUFJJVkFURSBLRVk=\n-----END CERTIFICATE-----\n";
        ensure_certificate_only_pem(base64_lookalike).expect("base64 正文不是 PEM 边界");

        let mixed = format!("{cert_pem}{}", cert_key.serialize_pem());
        let err = ensure_certificate_only_pem(&mixed).unwrap_err().to_string();
        assert!(err.contains("PRIVATE KEY"), "错误信息: {err}");
        assert!(err.contains("非 CERTIFICATE"), "错误信息: {err}");

        for label in [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "PUBLIC KEY",
            "CERTIFICATE REQUEST",
        ] {
            let text = format!("-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n");
            let err = ensure_certificate_only_pem(&text).unwrap_err().to_string();
            assert!(err.contains(label), "错误必须点名区块类型 {label}: {err}");
        }

        // 证书边界前后有多余字符（可能躲过宽松解析器）同样拒绝。
        let padded = format!("junk{cert_pem}");
        assert!(ensure_certificate_only_pem(&padded).is_err());
    }

    /// C4：块外只允许空白；裸 base64/JSON/注释/垃圾必须拒绝，多证书 bundle 通过。
    #[test]
    fn c4_ensure_certificate_only_pem_rejects_text_outside_blocks() {
        let key1 = KeyPair::generate().unwrap();
        let cert1 = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&key1)
            .unwrap()
            .pem();
        let key2 = KeyPair::generate().unwrap();
        let cert2 = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&key2)
            .unwrap()
            .pem();

        // 合法：单证书、CRLF、多证书 bundle、块间空行。
        ensure_certificate_only_pem(&cert1).expect("单证书必须通过");
        ensure_certificate_only_pem(&cert1.replace('\n', "\r\n")).expect("CRLF 必须通过");
        let bundle = format!("{cert1}\n\n{cert2}");
        ensure_certificate_only_pem(&bundle).expect("多证书 bundle 必须通过");

        // 块后裸 base64（私钥正文）与块前/块后 JSON 都必须拒绝。
        let bare_base64 = cert1
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<String>();
        for text in [
            format!("{cert1}{bare_base64}\n"),
            format!("{bare_base64}\n{cert1}"),
            format!("{{\"key_pkcs8\":\"AAAA\"}}\n{cert1}"),
            format!("{cert1}{{\"key_pkcs8\":\"AAAA\"}}\n"),
            format!("# 这是证书\n{cert1}"),
            format!("{cert1}trailing garbage\n"),
            format!("{cert1}-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"),
            format!("{cert1}{}", key1.serialize_pem()),
        ] {
            let err =
                ensure_certificate_only_pem(&text).expect_err("证书块外出现非空白内容必须拒绝");
            let text = format!("{err:#}");
            assert!(
                text.contains("块之外")
                    || text.contains("非 CERTIFICATE")
                    || text.contains("边界前后"),
                "错误应说明块外内容: {text}"
            );
        }

        // 块内非 base64、空行、缺 END、嵌套、块内夹带其他 PEM 都必须拒绝。
        for text in [
            "-----BEGIN CERTIFICATE-----\nAAAA\nnot base64!\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAAAA\n\nBBBB\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAAAA\n",
            "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n-----END CERTIFICATE-----\n",
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END PRIVATE KEY-----\n",
        ] {
            ensure_certificate_only_pem(text).expect_err("非法块结构必须拒绝");
        }

        // 缩进的 BEGIN 不在行首，按块外非空内容拒绝。
        ensure_certificate_only_pem(&format!(" {cert1}")).expect_err("缩进边界必须拒绝");
    }

    /// C4：从 ACME 证书链提取最后一张 CA，并判断 BasicConstraints.ca。
    #[test]
    fn c4_last_certificate_pem_and_ca_detection() {
        let ca_key = KeyPair::generate().unwrap();
        let ca_key_pem = ca_key.serialize_pem();
        let ca_pem = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&ca_key)
            .unwrap()
            .pem();
        let (csr_pem, _key_pem) = make_csr().unwrap();
        let leaf_pem = sign_client_csr(&ca_key_pem, &csr_pem, "agent-c4", 90).unwrap();
        let chain = format!("{leaf_pem}{ca_pem}");

        let last = last_certificate_pem(&chain).expect("链尾证书必须可提取");
        assert!(last.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(last.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(
            fingerprint_of_pem(&last).unwrap(),
            fingerprint_of_pem(&ca_pem).unwrap(),
            "必须提取链尾的 CA，而不是叶子证书"
        );
        assert!(
            certificate_is_ca(&last).unwrap(),
            "链尾 CA 的 BasicConstraints.ca 必须为 true"
        );
        assert!(
            !certificate_is_ca(&leaf_pem).unwrap(),
            "叶子证书不得被判为 CA"
        );

        // 无证书 / 未闭合 / 嵌套 / 混入私钥：全部拒绝。
        assert!(last_certificate_pem("not a pem").is_err());
        assert!(last_certificate_pem("-----BEGIN CERTIFICATE-----\nAAAA\n").is_err());
        assert!(last_certificate_pem(&format!("{ca_pem}{ca_pem}")).is_ok());
        let nested = "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n";
        let err = last_certificate_pem(nested).unwrap_err().to_string();
        assert!(err.contains("嵌套"), "错误信息: {err}");
        let mixed = format!("{ca_pem}{}", ca_key.serialize_pem());
        assert!(last_certificate_pem(&mixed).is_err());

        // 链尾是叶子（非 CA）时，调用方必须能识别并拒绝把它当信任锚。
        let leaf_only_chain = leaf_pem.clone();
        let leaf_last = last_certificate_pem(&leaf_only_chain).unwrap();
        assert!(!certificate_is_ca(&leaf_last).unwrap());
    }

    /// A4/安全：证书与私钥不配套时必须显式报错，而不是等握手才失败。
    #[test]
    fn a4_server_config_rejects_mismatched_key() {
        let dir = temp_dir("mismatch");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let cert_pem = read_cert(&dir, SERVER_CERT_FILE);
        let key_pem = read_cert(&dir, SERVER_KEY_FILE);
        assert!(cert_matches_key(&cert_pem, &key_pem).unwrap());
        assert!(server_config(&dir).is_ok());

        // 换成另一把合法但不配套的私钥（模拟续签写盘中途崩溃）。
        let other_key = KeyPair::generate().unwrap().serialize_pem();
        assert!(!cert_matches_key(&cert_pem, &other_key).unwrap());
        crate::fsutil::atomic_write(
            &cert_dir(&dir).join(SERVER_KEY_FILE),
            other_key.as_bytes(),
            0o600,
        )
        .unwrap();
        let err = server_config(&dir).expect_err("不配套时必须报错");
        let text = format!("{err:#}");
        assert!(text.contains("不匹配"), "错误信息: {text}");
        assert!(
            text.contains("rotate-cert"),
            "错误信息必须给出修复命令: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `cert_issued_by_ca`：自有 CA 通过、无关 CA / 过期证书拒绝。
    #[test]
    fn a5_cert_issued_by_ca_checks_chain_and_expiry() {
        let ca_key = KeyPair::generate().unwrap();
        let ca_key_pem = ca_key.serialize_pem();
        let ca_pem = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&ca_key)
            .unwrap()
            .pem();
        let (csr_pem, _key_pem) = make_csr().unwrap();
        let cert_pem = sign_client_csr(&ca_key_pem, &csr_pem, "agent-issuer", 90).unwrap();

        let now = crate::util::now_ms();
        assert!(cert_issued_by_ca(&cert_pem, &ca_pem, now).unwrap());

        let other_key = KeyPair::generate().unwrap();
        let other_ca = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&other_key)
            .unwrap()
            .pem();
        assert!(!cert_issued_by_ca(&cert_pem, &other_ca, now).unwrap());

        // 过期证书即使链正确也必须返回 false。
        let future = now + 120 * DAY_MS;
        assert!(!cert_issued_by_ca(&cert_pem, &ca_pem, future).unwrap());
    }

    /// A5：轮换复用私钥——同一把 key 生成的 CSR / 证书公钥必须一致。
    #[test]
    fn a5_make_csr_with_key_reuses_private_key() {
        let (_csr, key_pem) = make_csr().unwrap();
        let first = make_csr_with_key(&key_pem).unwrap();
        let second = make_csr_with_key(&key_pem).unwrap();

        let public_key = |csr_pem: &str| {
            CertificateSigningRequestParams::from_pem(csr_pem)
                .unwrap()
                .public_key
                .der_bytes()
                .to_vec()
        };
        assert_eq!(
            public_key(&first),
            public_key(&second),
            "同一私钥生成的 CSR 公钥必须一致"
        );

        // 同一 key 签两次证书，落盘证书里的公钥也必须一致、且等于本地私钥的公钥。
        let ca_key = KeyPair::generate().unwrap();
        let ca_key_pem = ca_key.serialize_pem();
        let cert_a = sign_client_csr(&ca_key_pem, &first, "agent-a", 90).unwrap();
        let cert_b = sign_client_csr(&ca_key_pem, &second, "agent-b", 90).unwrap();
        let spki = |pem: &str| {
            let der = load_certs(pem).unwrap()[0].clone();
            let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
            cert.public_key().raw.to_vec()
        };
        assert_eq!(spki(&cert_a), spki(&cert_b));
        let key = KeyPair::from_pem(&key_pem).unwrap();
        let key_der = key.public_key_der();
        let key_spki: &[u8] = key_der.as_ref();
        assert_eq!(spki(&cert_a), key_spki.to_vec());

        // 非法私钥必须报错，不能静默生成新 key。
        assert!(make_csr_with_key("not a key").is_err());
    }

    /// A3 前置：已存在的证书（以及 CA）绝不能被 ensure_hub_material 覆盖。
    #[test]
    fn ensure_hub_material_never_replaces_existing_material() {
        let dir = temp_dir("idempotent");
        let sans = ["localhost".to_string()];
        let first = ensure_hub_material(&dir, &sans, CertPolicy::default()).unwrap();
        let second = ensure_hub_material(&dir, &sans, CertPolicy::default()).unwrap();
        assert_eq!(first, second);

        // 传入更短的有效期也不会重建已存在的证书。
        let third = ensure_hub_material(
            &dir,
            &sans,
            CertPolicy {
                ca_days: 1,
                server_days: 1,
                client_days: 1,
            },
        )
        .unwrap();
        assert_eq!(first, third);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A2：非法有效期（0 天 / 超过 100 年）必须拒绝签发。
    #[test]
    fn invalid_validity_days_are_rejected() {
        let dir = temp_dir("bad-days");
        let sans = vec!["localhost".to_string()];
        assert!(ensure_hub_material(
            &dir,
            &sans,
            CertPolicy {
                ca_days: 0,
                ..CertPolicy::default()
            }
        )
        .is_err());
        assert!(ensure_hub_material(
            &dir,
            &sans,
            CertPolicy {
                server_days: MAX_VALIDITY_DAYS + 1,
                ..CertPolicy::default()
            }
        )
        .is_err());

        let ca_key = KeyPair::generate().unwrap();
        let ca_key_pem = ca_key.serialize_pem();
        let (csr_pem, _key_pem) = make_csr().unwrap();
        assert!(issue_server_cert(&ca_key_pem, &sans, 0).is_err());
        assert!(sign_client_csr(&ca_key_pem, &csr_pem, "agent-x", 0).is_err());
        assert!(sign_client_csr(&ca_key_pem, "not a csr", "agent-x", 90).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 指纹钉扎模式保留给 bootstrap，配置构造与指纹校验都不能退化。
    #[test]
    fn client_config_pinned_still_builds() {
        let config = client_config_pinned(&"ab".repeat(32), None, None).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(client_config_pinned("not-hex", None, None).is_err());
    }

    /// 安全：ca.crt 存在但内容非法时必须报错，agent 侧不允许静默降级到钉扎。
    #[test]
    fn corrupt_ca_is_a_hard_error() {
        let (csr, key_pem) = make_csr().unwrap();
        let ca_key = KeyPair::generate().unwrap();
        let ca_key_pem = ca_key.serialize_pem();
        let cert_pem = sign_client_csr(&ca_key_pem, &csr, "agent-corrupt-ca", 90).unwrap();

        let err = client_config_ca("not a certificate", &cert_pem, &key_pem)
            .expect_err("非法 CA 必须报错");
        assert!(format!("{err:#}").contains("证书"), "错误信息: {err:#}");
        assert!(cert_issued_by_ca(&cert_pem, "not a certificate", crate::util::now_ms()).is_err());
    }

    /// S1：server_names → SAN 必须逐条校验，不允许静默丢弃/签出空 SAN 证书。
    #[test]
    fn s1_server_sans_are_validated_not_silently_dropped() {
        // 空列表直接拒绝（签出无 SAN 证书会让所有 CA 信任 agent 握手失败）。
        assert!(parse_server_sans(&[]).is_err());

        // 合法条目：IP / localhost / 带连字符的域名。
        let sans = parse_server_sans(&[
            "127.0.0.1".to_string(),
            "localhost".to_string(),
            "a-b.example".to_string(),
        ])
        .unwrap();
        assert_eq!(sans.len(), 3);
        assert!(matches!(sans[0], ServerSan::Ip(ip) if ip.is_loopback()));
        assert_eq!(sans[1], ServerSan::Dns("localhost".to_string()));
        assert_eq!(sans[2], ServerSan::Dns("a-b.example".to_string()));

        // 非法条目：空、空白、控制字符、空标签、非法字符、通配符、超长。
        for bad in [
            "",
            "   ",
            "bad name",
            "evil\nhost",
            ".example.com",
            "example.com.",
            "a..b",
            "*.example.com",
            "例子.example",
        ] {
            assert!(
                parse_server_sans(&[bad.to_string()]).is_err(),
                "应拒绝非法 SAN 条目 {bad:?}"
            );
        }
        assert!(parse_server_sans(&["a".repeat(64)]).is_err(), "标签超过 63");
        assert!(
            parse_server_sans(&[vec!["a"; 130].join(".")]).is_err(),
            "总长超过 253"
        );

        // 签发入口同样拒绝（不能绕开校验）。
        let ca_key = KeyPair::generate().unwrap();
        let ca_key_pem = ca_key.serialize_pem();
        assert!(issue_server_cert(&ca_key_pem, &[], 365).is_err());
        assert!(issue_server_cert(&ca_key_pem, &["bad name".to_string()], 365).is_err());
    }

    /// S1：新签发的服务端证书必须通过 CN / 有效期 / SAN 覆盖 / 签发者四项校验。
    #[test]
    fn s1_validate_server_cert_checks_san_cn_issuer_and_validity() {
        let dir = temp_dir("validate-server");
        ensure_hub_material(
            &dir,
            &["localhost".to_string(), "127.0.0.1".to_string()],
            CertPolicy::default(),
        )
        .unwrap();
        let ca_pem = read_cert(&dir, CA_CERT_FILE);
        let ca_key_pem = read_cert(&dir, CA_KEY_FILE);
        let cert_pem = read_cert(&dir, SERVER_CERT_FILE);
        let now = crate::util::now_ms();
        let expected = vec!["localhost".to_string(), "127.0.0.1".to_string()];

        validate_server_cert(&cert_pem, &ca_pem, &expected, now).expect("正常证书必须通过");

        // SAN 未覆盖期望的域名 / IP。
        let err = validate_server_cert(&cert_pem, &ca_pem, &["other.example".to_string()], now)
            .unwrap_err();
        assert!(format!("{err}").contains("SAN"), "错误信息: {err}");

        let (only_dns, _key) =
            issue_server_cert(&ca_key_pem, &["localhost".to_string()], 30).unwrap();
        let err =
            validate_server_cert(&only_dns, &ca_pem, &["127.0.0.1".to_string()], now).unwrap_err();
        assert!(format!("{err}").contains("IP"), "错误信息: {err}");

        // 空期望列表本身就是配置错误。
        assert!(validate_server_cert(&cert_pem, &ca_pem, &[], now).is_err());

        // 无关 CA 签发的证书：CN/SAN 都对，但验签失败。
        let other = temp_dir("validate-server-other");
        ensure_hub_material(&other, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let other_key_pem = read_cert(&other, CA_KEY_FILE);
        let (foreign, _key) =
            issue_server_cert(&other_key_pem, &["localhost".to_string()], 30).unwrap();
        let err =
            validate_server_cert(&foreign, &ca_pem, &["localhost".to_string()], now).unwrap_err();
        assert!(format!("{err}").contains("CA"), "错误信息: {err}");

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// S1：CA 私钥与 CA 证书不配套时，init 的签发路径必须在写服务端证书前失败。
    #[test]
    fn s1_ensure_hub_material_rejects_mismatched_ca_pair() {
        let dir = temp_dir("ca-pair");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let other = temp_dir("ca-pair-other");
        ensure_hub_material(&other, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let other_ca_key = read_cert(&other, CA_KEY_FILE);
        crate::fsutil::atomic_write(
            &cert_dir(&dir).join(CA_KEY_FILE),
            other_ca_key.as_bytes(),
            0o600,
        )
        .unwrap();
        // 删掉服务端材料，强制走「签发」路径。
        std::fs::remove_file(cert_dir(&dir).join(SERVER_CERT_FILE)).unwrap();
        std::fs::remove_file(cert_dir(&dir).join(SERVER_KEY_FILE)).unwrap();

        let err = ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default())
            .expect_err("CA 不配套必须失败");
        assert!(format!("{err:#}").contains("不配套"), "错误信息: {err:#}");
        assert!(
            !cert_dir(&dir).join(SERVER_CERT_FILE).exists(),
            "失败时不得写服务端证书"
        );
        assert!(!cert_dir(&dir).join(SERVER_KEY_FILE).exists());

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// S1-3：CA 两件套只缺一个时必须失败，绝不静默重建 CA。
    #[test]
    fn s13_ensure_hub_material_rejects_partial_ca() {
        for (keep, remove) in [(CA_CERT_FILE, CA_KEY_FILE), (CA_KEY_FILE, CA_CERT_FILE)] {
            let dir = temp_dir(&format!("partial-ca-{remove}"));
            ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
            let cert_before = read_cert(&dir, SERVER_CERT_FILE);
            let key_before = read_cert(&dir, SERVER_KEY_FILE);
            std::fs::remove_file(cert_dir(&dir).join(remove)).unwrap();

            let err = ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default())
                .expect_err("只缺一个 CA 文件必须失败");
            let text = format!("{err:#}");
            assert!(text.contains("拒绝自动重建"), "错误信息: {text}");
            assert!(text.contains("init --force"), "必须给出可执行建议: {text}");
            assert!(
                text.contains("所有 agent 都需要重新纳管"),
                "必须明确 init --force 的后果: {text}"
            );
            // 不得静默补回缺失的 CA 文件，也不得改服务端材料。
            assert!(
                !cert_dir(&dir).join(remove).exists(),
                "不得自动生成缺失的 {remove}"
            );
            assert!(cert_dir(&dir).join(keep).exists(), "已有的 CA 文件不应被删");
            assert_eq!(read_cert(&dir, SERVER_CERT_FILE), cert_before);
            assert_eq!(read_cert(&dir, SERVER_KEY_FILE), key_before);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// S1-3：CA 两件套都被删除后重新 init，会新建 CA，并强制重签旧服务端证书。
    #[test]
    fn s13_ensure_hub_material_rebuilds_server_when_ca_recreated() {
        let dir = temp_dir("recreate-ca");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let old_ca = read_cert(&dir, CA_CERT_FILE);
        let old_server = read_cert(&dir, SERVER_CERT_FILE);
        std::fs::remove_file(cert_dir(&dir).join(CA_CERT_FILE)).unwrap();
        std::fs::remove_file(cert_dir(&dir).join(CA_KEY_FILE)).unwrap();

        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default())
            .expect("CA 两件套都不在时应允许新建并重签");

        let new_ca = read_cert(&dir, CA_CERT_FILE);
        let new_server = read_cert(&dir, SERVER_CERT_FILE);
        assert_ne!(new_ca, old_ca, "必须生成新的 CA");
        assert_ne!(new_server, old_server, "必须强制重签服务端证书");
        assert!(cert_matches_key(&new_server, &read_cert(&dir, SERVER_KEY_FILE)).unwrap());
        assert!(
            cert_issued_by_ca(&new_server, &new_ca, crate::util::now_ms()).unwrap(),
            "新服务端证书必须由新 CA 签发"
        );
        // 旧服务端材料必须留备份（否则无法回滚/取证）。
        let backups: Vec<String> = std::fs::read_dir(cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_managed_backup(name, SERVER_CERT_FILE))
            .collect();
        assert_eq!(backups.len(), 1, "旧服务端证书必须被备份: {backups:?}");
        assert_eq!(
            std::fs::read_to_string(cert_dir(&dir).join(&backups[0])).unwrap(),
            old_server
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S1-3：SAN 非法时 init 不能留下半个 CA（连目录都不创建）。
    #[test]
    fn s13_ensure_hub_material_checks_sans_before_creating_ca() {
        let dir = temp_dir("bad-san-no-ca");
        for bad in [
            Vec::new(),
            vec!["bad name".to_string()],
            vec!["".to_string()],
        ] {
            let err = ensure_hub_material(&dir, &bad, CertPolicy::default())
                .expect_err("非法 SAN 必须失败");
            assert!(
                format!("{err:#}").contains("server_names"),
                "错误信息: {err:#}"
            );
            let certs = cert_dir(&dir);
            assert!(!certs.join(CA_CERT_FILE).exists(), "不得留下 ca.crt");
            assert!(!certs.join(CA_KEY_FILE).exists(), "不得留下 ca.key");
            assert!(!certs.exists(), "失败时不应创建证书目录");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `load_validated_ca`：CA 缺失/不配套时必须 actionable fail；正常时可用于签发。
    #[test]
    fn load_validated_ca_detects_missing_and_mismatched_material() {
        let dir = temp_dir("validated-ca");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();

        // 正常：返回的 CA 可以直接签发客户端证书，且能被自身 CA 校验。
        let ca = load_validated_ca(&dir).unwrap();
        let (csr_pem, _key) = make_csr().unwrap();
        let client = ca.sign_client_csr(&csr_pem, "agent-validated", 90).unwrap();
        assert!(cert_issued_by_ca(&client, &ca.cert_pem, crate::util::now_ms()).unwrap());

        // ca.key 缺失。
        let other = temp_dir("validated-ca-other");
        ensure_hub_material(&other, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let other_key = read_cert(&other, CA_KEY_FILE);
        let saved_key = read_cert(&dir, CA_KEY_FILE);
        std::fs::remove_file(cert_dir(&dir).join(CA_KEY_FILE)).unwrap();
        let err = load_validated_ca(&dir).err().expect("ca.key 缺失必须报错");
        assert!(
            format!("{err:#}").contains("CA 私钥缺失"),
            "错误信息: {err:#}"
        );
        assert!(format!("{err:#}").contains("所有 agent 都需要重新纳管"));

        // ca.key 不配套。
        std::fs::write(cert_dir(&dir).join(CA_KEY_FILE), &other_key).unwrap();
        let err = load_validated_ca(&dir).err().expect("CA 不配套必须报错");
        assert!(format!("{err:#}").contains("不配套"), "错误信息: {err:#}");

        // ca.crt 损坏。
        let good_ca = read_cert(&dir, CA_CERT_FILE);
        std::fs::write(cert_dir(&dir).join(CA_CERT_FILE), b"not a cert").unwrap();
        std::fs::write(cert_dir(&dir).join(CA_KEY_FILE), &saved_key).unwrap();
        let err = load_validated_ca(&dir).err().expect("ca.crt 损坏必须报错");
        assert!(format!("{err:#}").contains("无法解析"), "错误信息: {err:#}");
        std::fs::write(cert_dir(&dir).join(CA_CERT_FILE), &good_ca).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// 备份：成对同后缀、权限正确、保留最近 KEEP 份，且不删运维 CLI 的两段式备份。
    #[test]
    fn backup_server_material_pairs_prunes_and_keeps_legacy_backups() {
        let dir = temp_dir("backups");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let cert_pem = read_cert(&dir, SERVER_CERT_FILE);

        // 模拟运维 CLI（rotate-cert）留下的两段式备份，保留策略不能删它。
        let legacy = cert_dir(&dir).join("server.crt.bak-1234567890");
        std::fs::write(&legacy, &cert_pem).unwrap();

        let mut last_created = Vec::new();
        for _ in 0..(BACKUP_KEEP + 2) {
            let created = backup_server_material(&dir).unwrap();
            assert_eq!(created.len(), 2, "cert/key 必须成对备份");
            let cert_name = created[0]
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let key_name = created[1]
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let cert_suffix = cert_name
                .strip_prefix(&format!("{SERVER_CERT_FILE}.bak-"))
                .unwrap();
            let key_suffix = key_name
                .strip_prefix(&format!("{SERVER_KEY_FILE}.bak-"))
                .unwrap();
            assert_eq!(cert_suffix, key_suffix, "cert/key 备份必须共用同一后缀");
            assert_eq!(
                cert_suffix.split('-').count(),
                4,
                "新后缀必须是 4 段: {cert_suffix}"
            );
            let seq = cert_suffix.split('-').nth(1).unwrap();
            assert_eq!(seq.len(), 8, "进程内序号必须固定 8 位: {seq}");
            assert!(is_managed_backup(&cert_name, SERVER_CERT_FILE));
            assert!(is_managed_backup(&key_name, SERVER_KEY_FILE));
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode =
                    |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode(&created[0]), 0o644);
                assert_eq!(mode(&created[1]), 0o600);
            }
            last_created = created;
        }

        let managed: Vec<String> = std::fs::read_dir(cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_managed_backup(name, SERVER_CERT_FILE))
            .collect();
        assert_eq!(
            managed.len(),
            BACKUP_KEEP,
            "必须恰好保留最近 {BACKUP_KEEP} 份: {managed:?}"
        );
        assert!(!managed.is_empty(), "保留策略不能把最新备份也删掉");
        assert!(
            last_created.iter().all(|path| path.exists()),
            "最后创建的 cert/key 备份必须仍存在: {last_created:?}"
        );
        assert!(legacy.exists(), "不得删除运维 CLI 的两段式备份");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6：同一毫秒内连续备份时，按进程内序号保留最近 KEEP 份，最后一份不得被删。
    #[test]
    fn prune_keeps_newest_backups_within_same_millisecond() {
        let dir = temp_dir("prune-same-ms");
        let ms = 1_700_000_000_000_i64;
        // cert/key 共用同一后缀，模拟同毫秒内连续生成 KEEP+2 对备份。
        let pairs: Vec<(PathBuf, PathBuf)> = (0..(BACKUP_KEEP as u64 + 2))
            .map(|seq| {
                let suffix = backup_suffix_at(ms, seq);
                (
                    write_backup(&dir, SERVER_CERT_FILE, &suffix),
                    write_backup(&dir, SERVER_KEY_FILE, &suffix),
                )
            })
            .collect();

        for base in [SERVER_CERT_FILE, SERVER_KEY_FILE] {
            prune_managed_backups(&cert_dir(&dir), base).unwrap();
            let managed = managed_backup_names(&dir, base);
            assert_eq!(
                managed.len(),
                BACKUP_KEEP,
                "每类必须恰好保留 {BACKUP_KEEP} 份: {managed:?}"
            );
        }

        let stale = pairs.len() - BACKUP_KEEP;
        for (idx, (cert, key)) in pairs.iter().enumerate() {
            assert_eq!(
                cert.exists(),
                key.exists(),
                "cert/key 必须成对保留或淘汰: {idx}"
            );
            if idx < stale {
                assert!(!cert.exists(), "最旧的备份应被清理: {}", cert.display());
            } else {
                assert!(cert.exists(), "最近的备份应被保留: {}", cert.display());
            }
        }
        let (last_cert, last_key) = pairs.last().unwrap();
        assert!(last_cert.exists(), "最后创建的证书备份必须保留");
        assert!(last_key.exists(), "最后创建的私钥备份必须保留");
        let cert_suffix = last_cert
            .file_name()
            .unwrap()
            .to_string_lossy()
            .strip_prefix(&format!("{SERVER_CERT_FILE}.bak-"))
            .unwrap()
            .to_string();
        let key_suffix = last_key
            .file_name()
            .unwrap()
            .to_string_lossy()
            .strip_prefix(&format!("{SERVER_KEY_FILE}.bak-"))
            .unwrap()
            .to_string();
        assert_eq!(cert_suffix, key_suffix, "cert/key 备份必须共用同一后缀");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6：旧 3 段格式仍被识别并参与保留策略；2 段式运维备份不识别、不被误删。
    #[test]
    fn legacy_backups_are_managed_and_pruned_but_ops_backups_are_kept() {
        let dir = temp_dir("legacy-prune");
        let ms = 1_700_000_000_000_i64;
        // KEEP+1 份旧格式备份，毫秒递增；最早的一份应被淘汰。
        let legacy: Vec<PathBuf> = (0..=(BACKUP_KEEP as i64))
            .map(|offset| {
                write_backup(
                    &dir,
                    SERVER_CERT_FILE,
                    &format!("{}-{}-{:032x}", ms + offset, 1000 + offset, offset + 1),
                )
            })
            .collect();
        let ops = write_backup(&dir, SERVER_CERT_FILE, "1234567890");

        for path in &legacy {
            let name = path.file_name().unwrap().to_string_lossy();
            assert!(
                is_managed_backup(&name, SERVER_CERT_FILE),
                "旧 3 段格式必须被识别: {name}"
            );
            let suffix = name
                .strip_prefix(&format!("{SERVER_CERT_FILE}.bak-"))
                .unwrap();
            assert_eq!(
                parse_managed_backup_suffix(suffix).map(|(_, seq)| seq),
                Some(0),
                "旧格式没有序号，必须按 0 处理: {suffix}"
            );
        }
        let ops_name = ops.file_name().unwrap().to_string_lossy();
        assert!(
            !is_managed_backup(&ops_name, SERVER_CERT_FILE),
            "运维 CLI 的 2 段式备份不得被识别: {ops_name}"
        );

        prune_managed_backups(&cert_dir(&dir), SERVER_CERT_FILE).unwrap();

        let managed = managed_backup_names(&dir, SERVER_CERT_FILE);
        assert_eq!(managed.len(), BACKUP_KEEP, "保留份数: {managed:?}");
        assert!(!legacy[0].exists(), "最旧的旧格式备份应被清理");
        assert!(legacy.last().unwrap().exists(), "最新的旧格式备份必须保留");
        assert!(ops.exists(), "不得删除运维 CLI 的 2 段式备份");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6：新旧格式混排且同毫秒时，新格式（序号 >= 1）优先于旧格式（序号 0）。
    #[test]
    fn prune_prefers_new_format_over_legacy_in_same_millisecond() {
        let dir = temp_dir("mixed-format-prune");
        let ms = 1_700_000_000_000_i64;
        let legacy: Vec<PathBuf> = (0..2)
            .map(|i| {
                write_backup(
                    &dir,
                    SERVER_CERT_FILE,
                    &format!("{ms}-{}-{:032x}", 100 + i, i + 1),
                )
            })
            .collect();
        let new: Vec<PathBuf> = (1..=BACKUP_KEEP as u64)
            .map(|seq| write_backup(&dir, SERVER_CERT_FILE, &backup_suffix_at(ms, seq)))
            .collect();

        prune_managed_backups(&cert_dir(&dir), SERVER_CERT_FILE).unwrap();

        let managed = managed_backup_names(&dir, SERVER_CERT_FILE);
        assert_eq!(managed.len(), BACKUP_KEEP, "保留份数: {managed:?}");
        assert!(
            new.iter().all(|path| path.exists()),
            "新格式（同毫秒序号更大）必须优先保留: {managed:?}"
        );
        assert!(
            legacy.iter().all(|path| !path.exists()),
            "同毫秒的旧格式应被淘汰: {managed:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A6：非法段数/非数字/UUID 非法的文件名返回 false 且不 panic。
    #[test]
    fn is_managed_backup_rejects_malformed_names_without_panicking() {
        let uuid = "00112233445566778899aabbccddeeff";
        let malformed = [
            format!("{SERVER_CERT_FILE}.bak-"),
            // 运维 CLI 的两段式 `bak-<秒>`。
            format!("{SERVER_CERT_FILE}.bak-1234567890"),
            // 毫秒非数字。
            format!("{SERVER_CERT_FILE}.bak-abc-123-{uuid}"),
            // 旧格式 pid 非数字。
            format!("{SERVER_CERT_FILE}.bak-1000-abc-{uuid}"),
            // 新格式 pid 非数字。
            format!("{SERVER_CERT_FILE}.bak-1000-00000001-abc-{uuid}"),
            // 新格式序号不足 8 位。
            format!("{SERVER_CERT_FILE}.bak-1000-000001-123-{uuid}"),
            // UUID 不是 32 位十六进制。
            format!("{SERVER_CERT_FILE}.bak-1000-00000001-123-nothex"),
            // 段数过多。
            format!("{SERVER_CERT_FILE}.bak-1000-00000001-123-{uuid}-extra"),
            // 空毫秒段。
            format!("{SERVER_CERT_FILE}.bak--00000001-123-{uuid}"),
            // base 不匹配（key 备份不能按 cert 识别）。
            format!("server.key.bak-1000-00000001-123-{uuid}"),
            // 非 ASCII 尾巴。
            format!("{SERVER_CERT_FILE}.bak-1000-00000001-123-{uuid}中"),
        ];
        for name in &malformed {
            assert!(
                !is_managed_backup(name, SERVER_CERT_FILE),
                "非法文件名必须返回 false: {name}"
            );
        }

        // 合法的新/旧格式仍为 true。
        let new = format!("{SERVER_CERT_FILE}.bak-1000-00000001-123-{uuid}");
        let old = format!("{SERVER_CERT_FILE}.bak-1000-123-{uuid}");
        assert!(is_managed_backup(&new, SERVER_CERT_FILE));
        assert!(is_managed_backup(&old, SERVER_CERT_FILE));
        assert_eq!(
            parse_managed_backup_suffix("1000-00000001-123-00112233445566778899aabbccddeeff"),
            Some((1000, 1))
        );
        assert_eq!(
            parse_managed_backup_suffix("1000-123-00112233445566778899aabbccddeeff"),
            Some((1000, 0))
        );
    }

    /// A6：后缀是 `<毫秒>-<8 位序号>-<pid>-<uuid>`，且进程内序号严格递增。
    #[test]
    fn backup_suffix_has_fixed_width_monotonic_sequence() {
        let ms = 1_700_000_000_123_i64;
        let first = backup_suffix_at(ms, 1);
        let second = backup_suffix_at(ms, 2);
        assert!(
            first.starts_with("1700000000123-00000001-"),
            "后缀必须固定 8 位序号: {first}"
        );
        assert!(
            second.starts_with("1700000000123-00000002-"),
            "后缀必须固定 8 位序号: {second}"
        );
        assert_eq!(
            parse_managed_backup_suffix(&first),
            Some((1_700_000_000_123, 1))
        );
        assert_eq!(
            parse_managed_backup_suffix(&second),
            Some((1_700_000_000_123, 2))
        );
        assert!(
            parse_managed_backup_suffix(&first) < parse_managed_backup_suffix(&second),
            "同毫秒内序号大的排序键必须更大"
        );

        // 生产路径的进程内序号必须严格递增（不看毫秒，避免依赖真实时钟）。
        let a = parse_managed_backup_suffix(&backup_suffix()).expect("生产后缀必须可解析");
        let b = parse_managed_backup_suffix(&backup_suffix()).expect("生产后缀必须可解析");
        assert!(b.1 > a.1, "进程内序号必须严格递增: {a:?} vs {b:?}");
    }

    /// S1：SAN 的 DNS 标签不允许以 '-' 开头/结尾。
    #[test]
    fn s1_dns_labels_reject_leading_or_trailing_dash() {
        for bad in ["-example.com", "example-.com", "a.-b", "a.b-"] {
            assert!(
                parse_server_sans(&[bad.to_string()]).is_err(),
                "应拒绝 {bad:?}"
            );
        }
        assert!(parse_server_sans(&["a-b.example".to_string()]).is_ok());
    }

    /// 第五轮 S1：CA 被另一套 ca.crt+ca.key 覆盖后，init 必须用当前 CA 重签 server
    /// （成对备份），而不是静默沿用旧证书返回旧指纹。
    #[test]
    fn s5_ensure_hub_material_reissues_when_ca_replaced() {
        let dir = temp_dir("replaced-ca");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let old_server = read_cert(&dir, SERVER_CERT_FILE);
        let old_fingerprint = fingerprint_of_pem(&old_server).unwrap();

        // 用另一套 CA 的两件套整体覆盖（模拟拷错备份）。
        let other = temp_dir("replaced-ca-other");
        ensure_hub_material(&other, &["localhost".to_string()], CertPolicy::default()).unwrap();
        for name in [CA_CERT_FILE, CA_KEY_FILE] {
            let data = read_cert(&other, name);
            crate::fsutil::atomic_write(&cert_dir(&dir).join(name), data.as_bytes(), 0o600)
                .unwrap();
        }

        let fingerprint =
            ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default())
                .expect("CA 变化后 init 必须能重签 server");
        let server = read_cert(&dir, SERVER_CERT_FILE);
        assert_ne!(fingerprint, old_fingerprint, "必须返回新指纹");
        assert!(cert_matches_key(&server, &read_cert(&dir, SERVER_KEY_FILE)).unwrap());
        assert!(
            cert_issued_by_ca(
                &server,
                &read_cert(&dir, CA_CERT_FILE),
                crate::util::now_ms()
            )
            .unwrap(),
            "新 server 证书必须由当前 CA 签发"
        );
        let backups: Vec<String> = std::fs::read_dir(cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_managed_backup(name, SERVER_CERT_FILE))
            .collect();
        assert_eq!(backups.len(), 1, "旧 server 证书必须成对备份");
        assert_eq!(
            std::fs::read_to_string(cert_dir(&dir).join(&backups[0])).unwrap(),
            old_server
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// 第五轮 S1：`server_names` 新增 SAN 后，init 必须重签使新证书覆盖它。
    #[test]
    fn s5_ensure_hub_material_reissues_when_san_added() {
        let dir = temp_dir("added-san");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let old_server = read_cert(&dir, SERVER_CERT_FILE);

        let sans = vec!["localhost".to_string(), "added.example".to_string()];
        ensure_hub_material(&dir, &sans, CertPolicy::default()).expect("新增 SAN 后必须重签");
        let server = read_cert(&dir, SERVER_CERT_FILE);
        assert_ne!(server, old_server);
        validate_existing_server_cert(
            &server,
            &read_cert(&dir, CA_CERT_FILE),
            &sans,
            crate::util::now_ms(),
        )
        .expect("重签后的证书必须覆盖新 SAN 且由当前 CA 签发");
        let backups: Vec<String> = std::fs::read_dir(cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_managed_backup(name, SERVER_CERT_FILE))
            .collect();
        assert_eq!(backups.len(), 1, "旧 server 证书必须被备份");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 第五轮 S1：现存证书校验必须点名缺失的 SAN。
    #[test]
    fn s5_validate_existing_server_cert_names_missing_san() {
        let dir = temp_dir("existing-missing-san");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let cert = read_cert(&dir, SERVER_CERT_FILE);
        let ca = read_cert(&dir, CA_CERT_FILE);
        let err = validate_existing_server_cert(
            &cert,
            &ca,
            &["missing.example".to_string()],
            crate::util::now_ms(),
        )
        .expect_err("缺失 SAN 必须失败");
        let text = format!("{err:#}");
        assert!(
            text.contains("missing.example"),
            "错误信息必须点名缺失 SAN: {text}"
        );
        assert!(text.contains("现存的服务端证书"), "错误信息: {text}");
    }

    /// 第五轮建议：enrollment 在消费 token 前先解析 CSR（短非法 CSR 不烧 token）。
    #[test]
    fn s5_validate_client_csr_rejects_garbage_without_panicking() {
        let (csr, _key) = make_csr().unwrap();
        validate_client_csr(&csr).expect("合法 CSR 必须通过");
        assert!(validate_client_csr("not a csr").is_err());
        assert!(validate_client_csr("").is_err());
        assert!(validate_client_csr(
            "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----"
        )
        .is_err());
    }

    /// 构造 v0.1.0 风格的「现存」服务端材料：rcgen 默认有效期 1975–4096 年。
    fn mint_legacy_server_pair(ca_key_pem: &str, sans: &[String]) -> (String, String) {
        let ca_key = KeyPair::from_pem(ca_key_pem).unwrap();
        let ca_cert = ca_issuer(&ca_key).unwrap();
        let key = KeyPair::generate().unwrap();
        // 注意：不用 CertificateParams::new 之外的任何有效期覆盖——默认即 1975–4096。
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, SERVER_COMMON_NAME);
        params.subject_alt_names = san_entries(sans).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// 第六轮：v0.1.0 的现存证书（notAfter=4096）必须能通过「现存证书」校验，
    /// 但不允许作为「新签发证书」通过（新签发仍限制 36500 天）。
    #[test]
    fn s6_existing_cert_skips_max_validity_but_new_cert_enforces_it() {
        let dir = temp_dir("legacy-validity");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let ca_pem = read_cert(&dir, CA_CERT_FILE);
        let ca_key_pem = read_cert(&dir, CA_KEY_FILE);
        let (legacy_cert, _legacy_key) =
            mint_legacy_server_pair(&ca_key_pem, &["localhost".to_string()]);
        let now = crate::util::now_ms();

        // 现存证书：只校验有效性/链/SAN，不套用最大有效期上限。
        validate_existing_server_cert(&legacy_cert, &ca_pem, &["localhost".to_string()], now)
            .expect("v0.1 材料（notAfter=4096）必须被接受");

        // 同一张证书作为「新签发」则必须因为有效期超过上限被拒。
        let err = validate_server_cert(&legacy_cert, &ca_pem, &["localhost".to_string()], now)
            .expect_err("新签发证书必须限制最大有效期");
        assert!(format!("{err:#}").contains("上限"), "错误信息: {err:#}");
    }

    /// 第六轮：init 遇到 v0.1.0 的现存材料时不应重签（保持升级兼容）。
    #[test]
    fn s6_ensure_hub_material_keeps_legacy_v01_server_pair() {
        let dir = temp_dir("legacy-keep");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let ca_key_pem = read_cert(&dir, CA_KEY_FILE);
        let (legacy_cert, legacy_key) =
            mint_legacy_server_pair(&ca_key_pem, &["localhost".to_string()]);
        crate::fsutil::atomic_write(
            &cert_dir(&dir).join(SERVER_CERT_FILE),
            legacy_cert.as_bytes(),
            0o644,
        )
        .unwrap();
        crate::fsutil::atomic_write(
            &cert_dir(&dir).join(SERVER_KEY_FILE),
            legacy_key.as_bytes(),
            0o600,
        )
        .unwrap();

        let fingerprint =
            ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default())
                .expect("v0.1 材料必须能继续使用");
        assert_eq!(
            fingerprint,
            fingerprint_of_pem(&legacy_cert).unwrap(),
            "不得重签 v0.1 材料"
        );
        assert_eq!(read_cert(&dir, SERVER_CERT_FILE), legacy_cert);
        let backups: Vec<String> = std::fs::read_dir(cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_managed_backup(name, SERVER_CERT_FILE))
            .collect();
        assert!(backups.is_empty(), "未重签时不应产生备份: {backups:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 第六轮：init 时 server.crt/key 都在但不配套，必须按失配重签（备份 + 新链）。
    #[test]
    fn s6_ensure_hub_material_reissues_when_server_key_mismatched() {
        let dir = temp_dir("key-mismatch-init");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let old_cert = read_cert(&dir, SERVER_CERT_FILE);
        let old_fingerprint = fingerprint_of_pem(&old_cert).unwrap();

        // 换成另一把合法但不配套的私钥。
        let other = temp_dir("key-mismatch-init-other");
        ensure_hub_material(&other, &["localhost".to_string()], CertPolicy::default()).unwrap();
        let bad_key = read_cert(&other, SERVER_KEY_FILE);
        crate::fsutil::atomic_write(
            &cert_dir(&dir).join(SERVER_KEY_FILE),
            bad_key.as_bytes(),
            0o600,
        )
        .unwrap();

        let fingerprint =
            ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default())
                .expect("不配套时必须重签而不是静默返回");
        assert_ne!(fingerprint, old_fingerprint, "必须返回新指纹");
        let new_cert = read_cert(&dir, SERVER_CERT_FILE);
        let new_key = read_cert(&dir, SERVER_KEY_FILE);
        assert!(cert_matches_key(&new_cert, &new_key).unwrap());
        assert!(cert_issued_by_ca(
            &new_cert,
            &read_cert(&dir, CA_CERT_FILE),
            crate::util::now_ms()
        )
        .unwrap());
        let backups: Vec<String> = std::fs::read_dir(cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| is_managed_backup(name, SERVER_CERT_FILE))
            .collect();
        assert_eq!(backups.len(), 1, "旧 server 证书必须被备份");
        assert_eq!(
            std::fs::read_to_string(cert_dir(&dir).join(&backups[0])).unwrap(),
            old_cert
        );
        assert_eq!(
            std::fs::read_to_string(
                cert_dir(&dir).join(backups[0].replace(SERVER_CERT_FILE, SERVER_KEY_FILE))
            )
            .unwrap(),
            bad_key,
            "旧私钥（不配套的那把）也必须备份"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn ca_signs_client_csr() {
        // 生成 CA
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&ca_key)
            .unwrap();
        let ca_key_pem = ca_key.serialize_pem();

        // agent 侧 CSR
        let (csr_pem, _key_pem) = make_csr().unwrap();

        // 签名
        let signed = sign_client_csr(&ca_key_pem, &csr_pem, "agent-123", 90).unwrap();
        let certs = load_certs(&signed).unwrap();
        assert_eq!(certs.len(), 1);

        // 用 CA 校验链（只验证能解析、能被 webpki 接受）
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca_cert.der().clone()).unwrap();
        let parsed = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build();
        assert!(parsed.is_ok());
    }

    #[test]
    fn peer_common_name_reads_subject_cn() {
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params(DEFAULT_CA_DAYS)
            .unwrap()
            .self_signed(&ca_key)
            .unwrap();
        let (csr_pem, _key_pem) = make_csr().unwrap();
        let signed = sign_client_csr(&ca_key.serialize_pem(), &csr_pem, "agent-cn-42", 90).unwrap();
        let certs = load_certs(&signed).unwrap();
        assert_eq!(
            peer_common_name(certs[0].as_ref()).as_deref(),
            Some("agent-cn-42")
        );
        assert_eq!(peer_common_name(b"not a certificate"), None);
        // CA 证书的 CN 是固定的，也能被解析出来。
        assert_eq!(
            peer_common_name(ca_cert.der().as_ref()).as_deref(),
            Some(CA_COMMON_NAME)
        );
        // cert_summary 与 peer_common_name 对 CN 的判断必须一致。
        assert_eq!(
            cert_summary(&signed).unwrap().common_name.as_deref(),
            Some("agent-cn-42")
        );
    }

    /// 证书 subject 没有 CN 时应返回 None，由调用方按「无身份」拒绝。
    #[test]
    fn peer_common_name_returns_none_without_cn() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        // rcgen 默认会塞一个 CN，先清空再只放 O。
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "RustBoard Test");
        let cert = params.self_signed(&key).unwrap();

        assert_eq!(peer_common_name(cert.der().as_ref()), None);
    }

    /// subject 里出现多个 CN 时只取第一个，不能让后面的 CN 覆盖身份绑定结果。
    #[test]
    fn peer_common_name_uses_first_cn_when_subject_has_multiple() {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "agent-first");
        // rcgen 的 DistinguishedName 按 DnType 去重；用同一 OID（2.5.4.3）的
        // 自定义类型才能构造出两个 CN 属性。
        params
            .distinguished_name
            .push(DnType::CustomDnType(vec![2, 5, 4, 3]), "agent-second");
        let cert = params.self_signed(&key).unwrap();

        assert_eq!(
            peer_common_name(cert.der().as_ref()).as_deref(),
            Some("agent-first")
        );
    }

    /// 生成一张"公开 CA 风格"的测试叶子证书：无 CN、指定 SAN / 有效期 / EKU。
    fn public_leaf(
        sans: &[&str],
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        eku: Option<ExtendedKeyUsagePurpose>,
        is_ca: IsCa,
    ) -> String {
        let mut params = CertificateParams::new(
            sans.iter()
                .map(|san| (*san).to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        // ACME 证书可以没有 CN：这里显式清空，确保校验器不依赖 CN。
        params.distinguished_name = DistinguishedName::new();
        params.not_before = not_before;
        params.not_after = not_after;
        params.is_ca = is_ca;
        params.extended_key_usages = eku.into_iter().collect();
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    fn ok_window() -> (OffsetDateTime, OffsetDateTime) {
        let now = OffsetDateTime::now_utc();
        (now - TimeDuration::hours(1), now + TimeDuration::days(30))
    }

    /// 测试用 CA：自签、BasicConstraints.ca=true。
    fn test_ca(cn: &str) -> (Certificate, KeyPair, String) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, cn.to_string());
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();
        (cert, key, pem)
    }

    /// 测试用下级 CA：由 `issuer` 真实签名，`is_ca` 控制 BasicConstraints。
    fn test_signed_ca(
        cn: &str,
        issuer: &Certificate,
        issuer_key: &KeyPair,
        is_ca: IsCa,
    ) -> (Certificate, KeyPair, String) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = is_ca;
        params
            .distinguished_name
            .push(DnType::CommonName, cn.to_string());
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, issuer, issuer_key).unwrap();
        let pem = cert.pem();
        (cert, key, pem)
    }

    /// 测试用 ACME 叶子：生成 CSR 后由 `ca` 签名。
    fn test_acme_leaf(
        ca: &Certificate,
        ca_key: &KeyPair,
        sans: &[&str],
        eku: Option<ExtendedKeyUsagePurpose>,
        is_ca: IsCa,
    ) -> (String, String) {
        let mut params = CertificateParams::new(
            sans.iter()
                .map(|san| (*san).to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let subject_alt_names = params.subject_alt_names.clone();
        params.distinguished_name = DistinguishedName::new();
        let eku_list: Vec<_> = eku.into_iter().collect();
        params.is_ca = is_ca.clone();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = eku_list.clone();
        let key = KeyPair::generate().unwrap();
        let csr = params.serialize_request(&key).unwrap();
        let mut csr = CertificateSigningRequestParams::from_pem(&csr.pem().unwrap()).unwrap();
        // 显式带上 SAN / EKU，避免依赖 rcgen 在 CSR 中是否保留这些参数。
        csr.params.subject_alt_names = subject_alt_names;
        csr.params.is_ca = is_ca;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = eku_list;
        let cert = csr.signed_by(ca, ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// C3：公开证书校验不要求 CN=rustboard-hub，只看 SAN / 有效期 / EKU / 非 CA。
    #[test]
    fn c3_validate_public_cert_accepts_acme_style_leaf_without_cn() {
        let (not_before, not_after) = ok_window();
        let pem = public_leaf(
            &["board.example.com", "127.0.0.1"],
            not_before,
            not_after,
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        validate_public_server_cert(
            &pem,
            &["board.example.com".into(), "127.0.0.1".into()],
            crate::util::now_ms(),
        )
        .expect("ACME 风格证书必须通过公开校验");
        let names = public_cert_names(&pem).unwrap();
        assert!(names.contains(&"DNS:board.example.com".to_string()));
        assert!(names.contains(&"IP:127.0.0.1".to_string()));
    }

    /// EKU 扩展不存在时允许（部分私有 CA 不写 EKU），存在时必须含 serverAuth。
    #[test]
    fn c3_validate_public_cert_eku_rules() {
        let (not_before, not_after) = ok_window();
        let sans = ["board.example.com".to_string()];
        let without_eku = public_leaf(
            &["board.example.com"],
            not_before,
            not_after,
            None,
            IsCa::NoCa,
        );
        validate_public_server_cert(&without_eku, &sans, crate::util::now_ms())
            .expect("缺少 EKU 扩展时应放行");

        let client_only = public_leaf(
            &["board.example.com"],
            not_before,
            not_after,
            Some(ExtendedKeyUsagePurpose::ClientAuth),
            IsCa::NoCa,
        );
        let err = validate_public_server_cert(&client_only, &sans, crate::util::now_ms())
            .expect_err("EKU 只有 clientAuth 必须拒绝");
        assert!(
            format!("{err:#}").contains("serverAuth"),
            "错误信息: {err:#}"
        );
    }

    /// SAN 未覆盖 / 已过期 / 尚未生效 / CA 证书都必须拒绝，且错误信息可执行。
    #[test]
    fn c3_validate_public_cert_rejects_bad_san_expiry_and_ca() {
        let (not_before, not_after) = ok_window();
        let sans = ["board.example.com".to_string()];
        let pem = public_leaf(
            &["board.example.com"],
            not_before,
            not_after,
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );

        let err = validate_public_server_cert(
            &pem,
            &["other.example.com".to_string()],
            crate::util::now_ms(),
        )
        .expect_err("SAN 不覆盖必须拒绝");
        assert!(
            format!("{err:#}").contains("SAN 未覆盖"),
            "错误信息: {err:#}"
        );

        let now = OffsetDateTime::now_utc();
        let expired = public_leaf(
            &["board.example.com"],
            now - TimeDuration::days(10),
            now - TimeDuration::days(1),
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        let err = validate_public_server_cert(&expired, &sans, crate::util::now_ms())
            .expect_err("过期证书必须拒绝");
        assert!(format!("{err:#}").contains("已过期"), "错误信息: {err:#}");

        let future = public_leaf(
            &["board.example.com"],
            now + TimeDuration::hours(2),
            now + TimeDuration::days(1),
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        let err = validate_public_server_cert(&future, &sans, crate::util::now_ms())
            .expect_err("尚未生效的证书必须拒绝");
        assert!(format!("{err:#}").contains("尚未生效"), "错误信息: {err:#}");

        let ca = public_leaf(
            &["board.example.com"],
            not_before,
            not_after,
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::Ca(BasicConstraints::Unconstrained),
        );
        let err = validate_public_server_cert(&ca, &sans, crate::util::now_ms())
            .expect_err("CA 证书不能作为服务端叶子证书");
        assert!(format!("{err:#}").contains("CA 证书"), "错误信息: {err:#}");
    }

    /// 安全：ACME 链校验必须要求至少叶子 + CA，单证书/自签叶子一律拒绝。
    #[test]
    fn c4_validate_acme_chain_rejects_self_signed_and_missing_chain() {
        let (not_before, not_after) = ok_window();
        let sans = ["board.example.com".to_string()];

        // 旧实现只做形状校验：自签叶子可以通过 validate_public_server_cert。
        let self_signed = public_leaf(
            &["board.example.com"],
            not_before,
            not_after,
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        validate_public_server_cert(&self_signed, &sans, crate::util::now_ms())
            .expect("形状校验仍应接受自签叶子（只校验 SAN/有效期/EKU）");
        let err = validate_acme_chain(&self_signed, &sans, crate::util::now_ms())
            .expect_err("单证书自签叶子不能作为 ACME 证书");
        assert!(format!("{err:#}").contains("至少需要"), "错误信息: {err:#}");

        // 真叶子但缺 CA：同样拒绝（链缺失）。
        let (ca, ca_key, _ca_pem) = test_ca("Test ACME Root");
        let (leaf, _leaf_key) = test_acme_leaf(
            &ca,
            &ca_key,
            &["board.example.com"],
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        let err = validate_acme_chain(&leaf, &sans, crate::util::now_ms())
            .expect_err("缺 CA 的叶子不能作为 ACME 证书");
        assert!(format!("{err:#}").contains("至少需要"), "错误信息: {err:#}");
    }

    /// 安全：叶子 + CA（含 intermediate）逐级验签通过；链尾可以是 intermediate。
    #[test]
    fn c4_validate_acme_chain_accepts_leaf_ca_and_intermediate() {
        let sans = ["board.example.com".to_string(), "127.0.0.1".to_string()];
        let (root, root_key, root_pem) = test_ca("Test ACME Root");
        let (leaf, _key) = test_acme_leaf(
            &root,
            &root_key,
            &["board.example.com", "127.0.0.1"],
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        validate_acme_chain(&format!("{leaf}{root_pem}"), &sans, crate::util::now_ms())
            .expect("叶子 + 根必须通过");

        // 三级链：叶子 -> intermediate -> root。链尾不做信任锚校验。
        let (inter, inter_key, inter_pem) = test_signed_ca(
            "Test ACME Intermediate",
            &root,
            &root_key,
            IsCa::Ca(BasicConstraints::Unconstrained),
        );
        let (leaf2, _key2) = test_acme_leaf(
            &inter,
            &inter_key,
            &["board.example.com", "127.0.0.1"],
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        validate_acme_chain(
            &format!("{leaf2}{inter_pem}{root_pem}"),
            &sans,
            crate::util::now_ms(),
        )
        .expect("叶子 + intermediate + root 必须通过");
    }

    /// 安全：issuer 匹配但签名不符、中间证书非 CA 都必须拒绝。
    #[test]
    fn c4_validate_acme_chain_rejects_bad_signature_and_non_ca() {
        let sans = ["board.example.com".to_string()];

        // 两个 CA 使用相同 subject：leaf 的 issuer 能匹配，但签名验不过。
        let (ca_a, ca_a_key, _ca_a_pem) = test_ca("Same Subject CA");
        let (_ca_b, _ca_b_key, ca_b_pem) = test_ca("Same Subject CA");
        let (leaf, _key) = test_acme_leaf(
            &ca_a,
            &ca_a_key,
            &["board.example.com"],
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        let err = validate_acme_chain(&format!("{leaf}{ca_b_pem}"), &sans, crate::util::now_ms())
            .expect_err("签名不符的链必须拒绝");
        assert!(
            format!("{err:#}").contains("签名校验失败"),
            "错误信息: {err:#}"
        );

        // 非 CA 的“中间证书”即使签名正确也不能作为链的一部分。
        let (root, root_key, root_pem) = test_ca("Test ACME Root");
        let (fake_inter, fake_inter_key, fake_inter_pem) =
            test_signed_ca("Not A CA Intermediate", &root, &root_key, IsCa::NoCa);
        let (leaf2, _key2) = test_acme_leaf(
            &fake_inter,
            &fake_inter_key,
            &["board.example.com"],
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        let err = validate_acme_chain(
            &format!("{leaf2}{fake_inter_pem}{root_pem}"),
            &sans,
            crate::util::now_ms(),
        )
        .expect_err("中间证书非 CA 必须拒绝");
        assert!(format!("{err:#}").contains("不是 CA"), "错误信息: {err:#}");

        // 链尾（这里是非 CA 的 intermediate）同样必须满足 BasicConstraints.ca=true。
        let err = validate_acme_chain(
            &format!("{leaf2}{fake_inter_pem}"),
            &sans,
            crate::util::now_ms(),
        )
        .expect_err("链尾不是 CA 必须拒绝");
        assert!(format!("{err:#}").contains("不是 CA"), "错误信息: {err:#}");
    }

    /// 安全：链校验前先拒绝块外内容，防止 cert+key 混合 PEM 绕过。
    #[test]
    fn c4_validate_acme_chain_rejects_pem_with_extra_content() {
        let sans = ["board.example.com".to_string()];
        let (root, root_key, root_pem) = test_ca("Test ACME Root");
        let (leaf, leaf_key) = test_acme_leaf(
            &root,
            &root_key,
            &["board.example.com"],
            Some(ExtendedKeyUsagePurpose::ServerAuth),
            IsCa::NoCa,
        );
        let chain = format!("{leaf}{root_pem}");
        validate_acme_chain(&chain, &sans, crate::util::now_ms()).unwrap();

        let err = validate_acme_chain(&format!("{chain}{leaf_key}"), &sans, crate::util::now_ms())
            .expect_err("cert+key 混合 PEM 必须拒绝");
        assert!(
            format!("{err:#}").contains("只允许 CERTIFICATE"),
            "错误信息: {err:#}"
        );
        let err = validate_acme_chain(
            &format!("{chain}{{\"key\":\"AAAA\"}}\n"),
            &sans,
            crate::util::now_ms(),
        )
        .expect_err("块后 JSON 必须拒绝");
        assert!(
            format!("{err:#}").contains("块之外") || format!("{err:#}").contains("只允许"),
            "错误信息: {err:#}"
        );
    }

    /// C3 拆分：ensure_client_ca 只创建 ca.crt/ca.key，不碰 server 材料；
    /// 随后 ensure_self_signed_server 复用同一 CA，重复调用指纹不变。
    #[test]
    fn c3_client_ca_and_self_signed_server_are_split() {
        let dir = temp_dir("split-ca");
        let sans = ["localhost".to_string()];
        ensure_client_ca(&dir, CertPolicy::default()).unwrap();
        let certs = cert_dir(&dir);
        assert!(certs.join(CA_CERT_FILE).exists());
        assert!(certs.join(CA_KEY_FILE).exists());
        assert!(
            !certs.join(SERVER_CERT_FILE).exists(),
            "CA 拆分后不得顺手写 server.crt"
        );
        assert!(
            !certs.join(SERVER_KEY_FILE).exists(),
            "CA 拆分后不得顺手写 server.key"
        );

        let first = ensure_self_signed_server(&dir, &sans, CertPolicy::default()).unwrap();
        assert!(certs.join(SERVER_CERT_FILE).exists());
        assert!(certs.join(SERVER_KEY_FILE).exists());
        // 再次调用必须复用已有材料，指纹/文件都不变。
        let second = ensure_self_signed_server(&dir, &sans, CertPolicy::default()).unwrap();
        assert_eq!(first, second);
        // wrapper 入口在同一材料上也必须返回相同指纹。
        let third = ensure_hub_material(&dir, &sans, CertPolicy::default()).unwrap();
        assert_eq!(first, third);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A8：私钥 0600、证书 0644、目录 0700 的既有断言不退化。
    #[cfg(unix)]
    #[test]
    fn issue_6_hub_material_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("permissions");
        ensure_hub_material(&dir, &["localhost".to_string()], CertPolicy::default()).unwrap();

        let certs = cert_dir(&dir);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&certs), 0o700);
        assert_eq!(mode(&certs.join(CA_KEY_FILE)), 0o600);
        assert_eq!(mode(&certs.join(SERVER_KEY_FILE)), 0o600);
        assert_eq!(mode(&certs.join(CA_CERT_FILE)), 0o644);
        assert_eq!(mode(&certs.join(SERVER_CERT_FILE)), 0o644);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
