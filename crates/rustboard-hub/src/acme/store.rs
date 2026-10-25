//! ACME 账户、状态与服务端证书材料的原子落盘。
//!
//! 路径与权限（D3）：
//! ```text
//! <data_dir>/certs/acme/account.json  0600  # 账户 credentials（含私钥）
//! <data_dir>/certs/acme/state.toml    0600  # 公开状态，不含 secret
//! <data_dir>/certs/server.crt         0644  # 当前 leaf + chain
//! <data_dir>/certs/server.key         0600
//! ```
//!
//! 所有写入走 `fsutil::atomic_write`（同目录临时文件 + rename），失败保留旧材料；
//! 证书切换必须持有 [`CertLock`]（与 `rotate-cert` / 自动续期互斥）。

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use rustboard_common::config::{AcmeChallenge, TlsConfig};
use rustboard_common::util::now_ms;
use rustboard_common::{fsutil, tls};
use serde::{Deserialize, Serialize};

use crate::cert_rotation::CertLock;

/// ACME 状态文件名。
pub const STATE_FILE: &str = "state.toml";
/// ACME 账户 credentials 文件名。
pub const ACCOUNT_FILE: &str = "account.json";

/// ACME 私有目录：`<data_dir>/certs/acme`。
pub fn acme_dir(data_dir: &Path) -> PathBuf {
    tls::cert_dir(data_dir).join("acme")
}

/// ACME 状态文件路径。
pub fn state_path(data_dir: &Path) -> PathBuf {
    acme_dir(data_dir).join(STATE_FILE)
}

/// ACME 账户文件路径。
pub fn account_path(data_dir: &Path) -> PathBuf {
    acme_dir(data_dir).join(ACCOUNT_FILE)
}

/// 启动期收紧 ACME 私有文件权限（L-01）：`account.json` 与 `state.toml` 只允许 0600。
///
/// 语义：
/// - 只处理**已经存在**的文件；目录或文件不存在时正常返回（首次启动 / 尚未启用 ACME）；
/// - 先用 [`std::fs::symlink_metadata`] 检查**目标本身**：符号链接直接报错，
///   绝不跟随读取，也绝不 chmod 链接目标；
/// - 普通文件交给 [`fsutil::harden`] 只收紧到 0600：已是 0600 时不调用 chmod，
///   比 0600 更严格（例如 0400）也保持原样，不放宽；
/// - 目录 / FIFO / 设备等非普通文件同样报错，避免把非文件当成 ACME 材料；
/// - `chmod` 失败（只读文件系统、EACCES、非属主等）必须返回错误，由调用方阻止启动。
///
/// 由 `hub run` 在数据目录 `ensure_private_dir(0700)` 之后、任何 TLS/ACME 读取之前
/// 调用，且与 `tls.mode` 无关（切换回 self-signed 后旧 ACME 文件仍可能留在盘上）。
pub fn harden_acme_material(data_dir: &Path) -> Result<()> {
    for path in [account_path(data_dir), state_path(data_dir)] {
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("检查 ACME 私有文件失败: {}", path.display()))
            }
        };
        if meta.file_type().is_symlink() {
            bail!(
                "ACME 私有文件是符号链接: {}；拒绝跟随，也拒绝修改链接目标。请删除该链接并\
                 恢复真实的 ACME 账户/状态文件；账户文件丢失时可执行 \
                 `rustboard-hub tls issue` 重新创建账户后再启动 hub。",
                path.display()
            );
        }
        if !meta.file_type().is_file() {
            bail!(
                "ACME 私有路径不是普通文件: {}（可能是目录、FIFO 或设备）；拒绝收紧权限。\
                 请移除它并恢复真实的 ACME 账户/状态文件，或执行 `rustboard-hub tls issue` \
                 重新创建账户后再启动 hub。",
                path.display()
            );
        }
        fsutil::harden(&path, 0o600).with_context(|| {
            format!(
                "收紧 ACME 私有文件权限失败: {}；hub 启动需要当前用户能修改该文件。\
                 请先手工执行 `chmod 600 {}`（确认文件属于运行 hub 的用户），再重启 hub",
                path.display(),
                path.display()
            )
        })?;
    }
    Ok(())
}

/// 落盘的 ACME 公开状态；**不含任何 secret**。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeState {
    /// ACME directory URL。
    pub directory: String,
    /// 证书标识（域名或 IP）。
    pub domains: Vec<String>,
    /// 实际使用的 profile；空表示未设置。
    pub profile: String,
    /// 挑战类型。
    pub challenge: AcmeChallenge,
    /// 最近一次成功签发的 Unix 秒。
    pub last_issue_unix: Option<i64>,
    /// 下一次计划尝试的 Unix 秒（续期阈值或退避）。
    pub next_attempt_unix: Option<i64>,
    /// 最近一次失败的公开错误摘要（截断，不含 token/key）。
    pub last_error: Option<String>,
}

impl Default for AcmeState {
    fn default() -> Self {
        Self {
            directory: String::new(),
            domains: Vec::new(),
            profile: String::new(),
            challenge: AcmeChallenge::Http01,
            last_issue_unix: None,
            next_attempt_unix: None,
            last_error: None,
        }
    }
}

impl AcmeState {
    /// 从配置生成一条不含 secret 的状态记录。
    pub fn from_config(tls: &TlsConfig) -> Self {
        Self {
            directory: tls.acme_directory.clone(),
            domains: tls.domains.clone(),
            profile: super::effective_profile(tls)
                .unwrap_or_default()
                .to_string(),
            challenge: tls.challenge,
            last_issue_unix: None,
            next_attempt_unix: None,
            last_error: None,
        }
    }
}

/// 读取状态；文件不存在返回 `None`，损坏时先备份再报错（绝不静默覆盖）。
pub fn read_state(data_dir: &Path) -> Result<Option<AcmeState>> {
    let path = state_path(data_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("读取 ACME 状态失败: {}", path.display()))
        }
    };
    match toml::from_str::<AcmeState>(&text) {
        Ok(state) => Ok(Some(state)),
        Err(err) => {
            let backup = backup_corrupt(&path)
                .with_context(|| format!("ACME 状态文件损坏（{}），且备份失败", path.display()))?;
            bail!(
                "ACME 状态文件损坏（{}）: {err}；已备份到 {}，请修复或删除该备份后重新执行 \
                 `rustboard-hub tls issue`。不会静默覆盖损坏文件。",
                path.display(),
                backup.display()
            )
        }
    }
}

/// 原子写入状态（0600）。目录不存在时创建为 0700。
pub fn write_state(data_dir: &Path, state: &AcmeState) -> Result<()> {
    let dir = acme_dir(data_dir);
    fsutil::ensure_private_dir(&dir, 0o700)
        .with_context(|| format!("创建 ACME 目录失败: {}", dir.display()))?;
    let text = toml::to_string(state).context("序列化 ACME 状态失败")?;
    fsutil::atomic_write(&state_path(data_dir), text.as_bytes(), 0o600)
        .with_context(|| format!("写入 ACME 状态失败: {}", state_path(data_dir).display()))
}

/// 读取账户 credentials JSON；不存在返回 `None`，损坏时备份并报错。
///
/// 读取前先对目标本身做 [`std::fs::symlink_metadata`]：账户文件含私钥，是符号链接
/// 时必须直接拒绝，不能先跟随读取；随后的 [`fsutil::harden`] 同样不会 chmod 链接目标。
pub fn read_account(data_dir: &Path) -> Result<Option<String>> {
    let path = account_path(data_dir);
    match std::fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => bail!(
            "ACME 账户文件是符号链接: {}；拒绝跟随读取（账户文件含私钥）。请删除该链接并\
             恢复真实文件，或执行 `rustboard-hub tls issue` 重新创建账户。",
            path.display()
        ),
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("检查 ACME 账户失败: {}", path.display()))
        }
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("读取 ACME 账户失败: {}", path.display()))
        }
    };
    // 升级路径：旧版本可能把 account.json 写成 0644（其中含账户私钥）。
    // 读取后立即基于路径收紧；harden 只收紧不放宽，已是 0600 时不做任何事。
    fsutil::harden(&path, 0o600)
        .with_context(|| format!("收紧 ACME 账户文件权限失败: {}", path.display()))?;
    // 只校验 JSON 结构；账户 key 的解析交给 instant-acme，避免在本模块重复实现。
    if let Err(err) = serde_json::from_str::<serde_json::Value>(&text) {
        let backup = backup_corrupt(&path)
            .with_context(|| format!("ACME 账户文件损坏（{}），且备份失败", path.display()))?;
        bail!(
            "ACME 账户文件损坏（{}）: {err}；已备份到 {}。请恢复备份或删除它后重新执行 \
             `rustboard-hub tls issue` 以创建新账户。不会静默覆盖损坏文件。",
            path.display(),
            backup.display()
        );
    }
    Ok(Some(text))
}

/// 原子写入账户 credentials JSON（0600）。
pub fn write_account(data_dir: &Path, credentials_json: &str) -> Result<()> {
    // 先拒绝非法 JSON：避免把损坏内容写进去，下次启动只能走备份恢复。
    serde_json::from_str::<serde_json::Value>(credentials_json)
        .context("拒绝写入非法 JSON 作为 ACME 账户 credentials")?;
    let dir = acme_dir(data_dir);
    fsutil::ensure_private_dir(&dir, 0o700)
        .with_context(|| format!("创建 ACME 目录失败: {}", dir.display()))?;
    fsutil::atomic_write(&account_path(data_dir), credentials_json.as_bytes(), 0o600)
        .with_context(|| format!("写入 ACME 账户失败: {}", account_path(data_dir).display()))
}

/// 读取当前生效的服务端材料；缺失一半时报错，两份都不存在返回 `None`。
///
/// 不实现 `Debug`：结构体含 `key_pem`，避免被 `{:?}` / 日志意外打印。
#[derive(Clone)]
pub struct ServerMaterial {
    pub cert_pem: String,
    pub key_pem: String,
}

/// 读取 `server.crt` + `server.key`（不做信任判断，只检测半套材料）。
pub fn read_server_material(data_dir: &Path) -> Result<Option<ServerMaterial>> {
    let dir = tls::cert_dir(data_dir);
    let cert_path = dir.join(tls::SERVER_CERT_FILE);
    let key_path = dir.join(tls::SERVER_KEY_FILE);
    let cert = read_optional(&cert_path)?;
    let key = read_optional(&key_path)?;
    match (cert, key) {
        (None, None) => Ok(None),
        (Some(cert_pem), Some(key_pem)) => Ok(Some(ServerMaterial { cert_pem, key_pem })),
        (Some(_), None) => bail!(
            "服务端证书存在但私钥缺失（{}）；拒绝继续，请执行 `rustboard-hub tls issue` \
             重新获取证书，或从备份恢复配套材料",
            key_path.display()
        ),
        (None, Some(_)) => bail!(
            "服务端私钥存在但证书缺失（{}）；拒绝继续，请执行 `rustboard-hub tls issue` \
             重新获取证书，或从备份恢复配套材料",
            cert_path.display()
        ),
    }
}

/// 安装 ACME 签发结果：先取 [`CertLock`]，再调用 [`install_server_material_locked`]。
///
/// 当前 CLI / 自动续期都在更外层持锁（覆盖网络请求阶段），因此走 `_locked`
/// 变体；本函数保留给不持锁的调用方（后续 installer）。
#[allow(dead_code)]
pub fn install_server_material(
    data_dir: &Path,
    cert_pem: &str,
    key_pem: &str,
    expected_sans: &[String],
) -> Result<()> {
    let cert_dir = tls::cert_dir(data_dir);
    let _lock = CertLock::acquire(&cert_dir)
        .context("获取证书安装锁失败（另一个 tls issue/renew/rotate-cert 正在运行）")?;
    install_server_material_locked(data_dir, cert_pem, key_pem, expected_sans)
}

/// 已持有 [`CertLock`] 时安装 ACME 签发结果。
///
/// 顺序（失败保留旧材料）：
/// 1. 校验 cert/key 配套、公开证书 SAN/有效期/EKU/非 CA；
/// 2. 成对备份旧材料（`tls::backup_server_material`）；
/// 3. 先写 key（0600）再写 cert（0644），均为原子写；
/// 4. cert 写失败时回滚 key，保证不会留下「新 key + 旧 cert」。
pub fn install_server_material_locked(
    data_dir: &Path,
    cert_pem: &str,
    key_pem: &str,
    expected_sans: &[String],
) -> Result<()> {
    if cert_pem.trim().is_empty() {
        bail!("ACME 返回的服务端证书为空，拒绝写入");
    }
    if key_pem.trim().is_empty() {
        bail!("ACME 返回的服务端私钥为空，拒绝写入");
    }
    // WFE 可能返回 cert+key 混合 PEM；先拒绝块外内容/非 CERTIFICATE 区块，
    // 避免把私钥原样写进 0644 的 server.crt。
    tls::ensure_certificate_only_pem(cert_pem)
        .context("ACME 返回的服务端证书不是纯 CERTIFICATE PEM，拒绝写入")?;
    if !tls::cert_matches_key(cert_pem, key_pem).context("校验 ACME 证书与私钥是否配套失败")?
    {
        bail!("ACME 返回的服务端证书与私钥不配套，拒绝写入（旧材料保持不变）");
    }
    // 至少叶子 + CA，且叶子确实由链中下一张证书签发；单证书/自签/缺失链一律拒绝。
    tls::validate_acme_chain(cert_pem, expected_sans, now_ms())
        .context("ACME 服务端证书链校验失败，拒绝写入（旧材料保持不变）")?;

    let dir = tls::cert_dir(data_dir);
    fsutil::ensure_private_dir(&dir, 0o700)
        .with_context(|| format!("创建证书目录失败: {}", dir.display()))?;
    let cert_path = dir.join(tls::SERVER_CERT_FILE);
    let key_path = dir.join(tls::SERVER_KEY_FILE);

    let old_cert = read_optional(&cert_path)?;
    let old_key = read_optional(&key_path)?;
    let backups = if old_cert.is_some() || old_key.is_some() {
        tls::backup_server_material(data_dir)
            .context("安装 ACME 证书前备份旧服务端材料失败，已放弃写入")?
    } else {
        Vec::new()
    };

    // 先写 key：任何时刻都不会出现「新 cert + 旧 key」的一对可用组合。
    fsutil::atomic_write(&key_path, key_pem.as_bytes(), 0o600)
        .context("写入 ACME 服务端私钥失败（旧材料保持不变）")?;
    if let Err(write_err) = fsutil::atomic_write(&cert_path, cert_pem.as_bytes(), 0o644) {
        // cert 没变，把 key 恢复成旧的就能回到原来的一对；原本没有 key 则删除新 key。
        let rollback = match old_key.as_deref() {
            Some(old_key) => fsutil::atomic_write(&key_path, old_key.as_bytes(), 0o600)
                .map_err(anyhow::Error::from),
            None => remove_file_if_exists(&key_path),
        };
        return Err(match rollback {
            Ok(()) => anyhow::Error::new(write_err)
                .context("写入 ACME 服务端证书失败，已回滚私钥（旧证书未被覆盖）"),
            Err(rollback_err) => anyhow::Error::new(write_err).context(format!(
                "写入 ACME 服务端证书失败，且回滚私钥失败（需要人工检查 {}）: {rollback_err}",
                key_path.display()
            )),
        });
    }

    let fingerprint = tls::fingerprint_of_pem(cert_pem)?;
    let not_after = tls::not_after_unix(cert_pem)?;
    let backup_list = backups
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!(
        fingerprint = %fingerprint,
        not_after = %tls::format_unix_utc(not_after),
        backups = %backup_list,
        "已安装 ACME 服务端证书（旧材料已成对备份）"
    );
    Ok(())
}

fn read_optional(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("读取 {} 失败", path.display())),
    }
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("删除 {} 失败", path.display())),
    }
}

/// 把损坏文件改名备份（0600），返回备份路径；不覆盖原文件内容。
fn backup_corrupt(path: &Path) -> Result<PathBuf> {
    let data =
        std::fs::read(path).with_context(|| format!("读取损坏文件失败: {}", path.display()))?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "acme".to_string());
    let backup = path.with_file_name(format!(
        "{file_name}.corrupt-{}-{}",
        now_ms(),
        std::process::id()
    ));
    fsutil::atomic_write(&backup, &data, 0o600)
        .with_context(|| format!("备份损坏文件失败: {}", backup.display()))?;
    tracing::warn!(
        path = %path.display(),
        backup = %backup.display(),
        "检测到损坏的 ACME 文件，已备份（不静默覆盖）"
    );
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
        DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
    };
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rb-acme-store-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 生成 ACME 风格的测试证书链：叶子由测试 CA 真实签名（不是 self-signed），
    /// SAN 指定域名、无 CN、serverAuth、非 CA；返回「叶子 + CA」与叶子私钥。
    fn leaf(domain: &str) -> (String, String) {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test ACME CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let ca_pem = ca_cert.pem();

        let mut params = CertificateParams::new(vec![domain.to_string()]).unwrap();
        let subject_alt_names = params.subject_alt_names.clone();
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let csr = params.serialize_request(&key).unwrap();
        let mut csr = CertificateSigningRequestParams::from_pem(&csr.pem().unwrap()).unwrap();
        csr.params.subject_alt_names = subject_alt_names;
        csr.params.is_ca = IsCa::NoCa;
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let cert = csr.signed_by(&ca_cert, &ca_key).unwrap();
        (format!("{}{}", cert.pem(), ca_pem), key.serialize_pem())
    }

    #[test]
    fn state_roundtrip_atomic_and_private() {
        let dir = temp_dir("state");
        let tls = TlsConfig {
            mode: rustboard_common::config::ServerTlsMode::AcmeDomain,
            domains: vec!["board.example.com".into()],
            ..TlsConfig::default()
        };
        let mut state = AcmeState::from_config(&tls);
        state.last_issue_unix = Some(1_700_000_000);
        state.last_error = Some("network timeout".into());
        write_state(&dir, &state).unwrap();
        assert_eq!(read_state(&dir).unwrap().unwrap(), state);
        // 再写一次必须原子替换且不留临时文件。
        state.last_issue_unix = Some(1_700_000_100);
        write_state(&dir, &state).unwrap();
        assert_eq!(
            read_state(&dir).unwrap().unwrap().last_issue_unix,
            Some(1_700_000_100)
        );
        let leftovers: Vec<_> = std::fs::read_dir(acme_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "不应留下临时文件: {leftovers:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&acme_dir(&dir)), 0o700);
            assert_eq!(mode(&state_path(&dir)), 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_state_is_backed_up_and_not_overwritten() {
        let dir = temp_dir("corrupt-state");
        std::fs::create_dir_all(acme_dir(&dir)).unwrap();
        std::fs::write(state_path(&dir), b"not = [valid").unwrap();
        let err = read_state(&dir).expect_err("损坏状态必须报错");
        assert!(format!("{err:#}").contains("已备份"), "错误信息: {err:#}");
        // 原文件仍在（没有被静默覆盖），备份文件也存在。
        assert!(state_path(&dir).exists());
        let backups: Vec<_> = std::fs::read_dir(acme_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".corrupt-"))
            .collect();
        assert_eq!(backups.len(), 1, "备份文件: {backups:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn account_roundtrip_private_and_corruption_backup() {
        let dir = temp_dir("account");
        let json = r#"{"id":"https://acme.test/account/1","key_pkcs8":"AAAA","directory":"https://acme.test/dir"}"#;
        write_account(&dir, json).unwrap();
        assert_eq!(read_account(&dir).unwrap().as_deref(), Some(json));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(account_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);

            // 升级路径：既有 0644 account.json 读取时必须收紧到 0600。
            std::fs::set_permissions(account_path(&dir), std::fs::Permissions::from_mode(0o644))
                .unwrap();
        }
        assert_eq!(read_account(&dir).unwrap().as_deref(), Some(json));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(account_path(&dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "读取既有 0644 账户文件后必须收紧到 0600");
        }
        std::fs::write(account_path(&dir), b"{broken").unwrap();
        let err = read_account(&dir).expect_err("损坏账户必须报错");
        assert!(format!("{err:#}").contains("已备份"), "错误信息: {err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_valid_material_backs_up_and_keeps_permissions() {
        let dir = temp_dir("install");
        let sans = vec!["board.example.com".to_string()];
        let (cert1, key1) = leaf("board.example.com");
        install_server_material(&dir, &cert1, &key1, &sans).unwrap();
        let cert_path = tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE);
        let key_path = tls::cert_dir(&dir).join(tls::SERVER_KEY_FILE);
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), cert1);
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), key1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&tls::cert_dir(&dir)), 0o700);
            assert_eq!(mode(&cert_path), 0o644);
            assert_eq!(mode(&key_path), 0o600);
        }

        // 第二次安装必须成对备份旧材料，并替换为新材料。
        let (cert2, key2) = leaf("board.example.com");
        install_server_material(&dir, &cert2, &key2, &sans).unwrap();
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), cert2);
        let backups: Vec<_> = std::fs::read_dir(tls::cert_dir(&dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name.contains(".bak-"))
            .collect();
        // cert + key 各一份。
        assert_eq!(backups.len(), 2, "备份文件: {backups:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_mismatched_bad_san_and_keeps_old_material() {
        let dir = temp_dir("reject");
        let sans = vec!["board.example.com".to_string()];
        let (cert, key) = leaf("board.example.com");
        install_server_material(&dir, &cert, &key, &sans).unwrap();
        let cert_path = tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE);
        let key_path = tls::cert_dir(&dir).join(tls::SERVER_KEY_FILE);

        // 证书/私钥不配套：直接拒绝，旧材料保持。
        let (other_cert, _) = leaf("board.example.com");
        let err = install_server_material(&dir, &other_cert, &key, &sans)
            .expect_err("不配套材料必须拒绝");
        assert!(format!("{err:#}").contains("不配套"), "错误信息: {err:#}");
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), cert);
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), key);

        // SAN 不覆盖：拒绝，旧材料保持。
        let (wrong_cert, wrong_key) = leaf("other.example.com");
        let err = install_server_material(&dir, &wrong_cert, &wrong_key, &sans)
            .expect_err("SAN 不覆盖必须拒绝");
        assert!(format!("{err:#}").contains("SAN"), "错误信息: {err:#}");
        assert_eq!(std::fs::read_to_string(&cert_path).unwrap(), cert);
        assert_eq!(std::fs::read_to_string(&key_path).unwrap(), key);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_rejects_self_signed_and_mixed_pem() {
        let dir = temp_dir("reject-chain");
        let sans = vec!["board.example.com".to_string()];

        // 旧的 self-signed leaf：形状合法但不是 ACME 链，必须拒绝。
        let mut params = CertificateParams::new(vec!["board.example.com".to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().unwrap();
        let self_signed = params.self_signed(&key).unwrap().pem();
        let err = install_server_material(&dir, &self_signed, &key.serialize_pem(), &sans)
            .expect_err("单证书 self-signed 必须拒绝");
        assert!(format!("{err:#}").contains("至少需要"), "错误信息: {err:#}");
        assert!(!tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE).exists());

        // WFE 返回 cert+key 混合 PEM：写盘前直接拒绝，不能把私钥写进 0644。
        let (chain, leaf_key) = leaf("board.example.com");
        let mixed = format!("{chain}{leaf_key}");
        let err = install_server_material(&dir, &mixed, &leaf_key, &sans)
            .expect_err("cert+key 混合 PEM 必须拒绝");
        assert!(
            format!("{err:#}").contains("只允许 CERTIFICATE"),
            "错误信息: {err:#}"
        );
        assert!(!tls::cert_dir(&dir).join(tls::SERVER_CERT_FILE).exists());

        // 合法链仍然可以安装。
        install_server_material(&dir, &chain, &leaf_key, &sans).expect("合法链必须可以安装");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_server_material_detects_half_pair() {
        let dir = temp_dir("half-pair");
        assert!(read_server_material(&dir).unwrap().is_none());
        let certs = tls::cert_dir(&dir);
        std::fs::create_dir_all(&certs).unwrap();
        std::fs::write(certs.join(tls::SERVER_CERT_FILE), "cert").unwrap();
        let err = match read_server_material(&dir) {
            Ok(_) => panic!("半套材料必须报错"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("私钥缺失"), "错误信息: {err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
