//! TLS 材料生成与 rustls 配置。
//!
//! 信任模型：hub 自建一个私有 CA；agent 首次连接时用**服务端证书指纹**固定校验，
//! enrollment 成功后拿到属于自己的客户端证书，之后全程 mTLS。
//!
//! CA 证书落盘后就不再重建（重建会让所有 agent 失效）。运行时为了给 CSR 签名，
//! 需要构造 rcgen 的 `Certificate` 作为 issuer —— 这里用固定参数 + CA 私钥
//! 重新推导一份，仅用于取 subject/AKI，不会覆盖磁盘上的 CA 证书。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CertificateSigningRequest,
    CertificateSigningRequestParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, SanType,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

pub const CA_COMMON_NAME: &str = "RustBoard Root CA";
pub const SERVER_COMMON_NAME: &str = "rustboard-hub";

pub const CA_CERT_FILE: &str = "ca.crt";
pub const CA_KEY_FILE: &str = "ca.key";
pub const SERVER_CERT_FILE: &str = "server.crt";
pub const SERVER_KEY_FILE: &str = "server.key";
pub const AGENT_CERT_FILE: &str = "agent.crt";
pub const AGENT_KEY_FILE: &str = "agent.key";

/// hub 的证书目录。
pub fn cert_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("certs")
}

fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
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
fn ca_issuer(ca_key: &KeyPair) -> Result<Certificate> {
    Ok(ca_params()?.self_signed(ca_key)?)
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    crate::fsutil::atomic_write(path, data, 0o600)?;
    Ok(())
}

fn write_public(path: &Path, data: &[u8]) -> Result<()> {
    crate::fsutil::atomic_write(path, data, 0o644)?;
    Ok(())
}

fn san_entries(hosts: &[String]) -> Vec<SanType> {
    hosts
        .iter()
        .filter_map(|host| match host.parse::<std::net::IpAddr>() {
            Ok(ip) => Some(SanType::IpAddress(ip)),
            Err(_) => rcgen::Ia5String::try_from(host.clone())
                .ok()
                .map(SanType::DnsName),
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

/// 确保 hub 的 CA 与服务端证书存在，返回服务端证书的 SHA-256 指纹（hex）。
///
/// 已存在的证书不会被覆盖——覆盖会改变指纹，所有已安装 agent 立即失联。
pub fn ensure_hub_material(data_dir: &Path, sans: &[String]) -> Result<String> {
    let dir = cert_dir(data_dir);
    crate::fsutil::ensure_dir(&dir, 0o700)?;

    let ca_cert_path = dir.join(CA_CERT_FILE);
    let ca_key_path = dir.join(CA_KEY_FILE);
    if !ca_cert_path.exists() || !ca_key_path.exists() {
        let key = KeyPair::generate()?;
        let cert = ca_params()?.self_signed(&key)?;
        write_private(&ca_key_path, key.serialize_pem().as_bytes())?;
        write_public(&ca_cert_path, cert.pem().as_bytes())?;
        tracing::info!(path = %ca_cert_path.display(), "已生成 CA");
    }

    let server_cert_path = dir.join(SERVER_CERT_FILE);
    let server_key_path = dir.join(SERVER_KEY_FILE);
    if !server_cert_path.exists() || !server_key_path.exists() {
        // M3：已有 CA 私钥可能是旧版本按 0644 留下的，先收紧再读取。
        crate::fsutil::harden(&ca_key_path, 0o600)?;
        let ca_key_pem = std::fs::read_to_string(&ca_key_path)?;
        let (cert_pem, key_pem) = issue_server_cert(&ca_key_pem, sans)?;
        write_public(&server_cert_path, cert_pem.as_bytes())?;
        write_private(&server_key_path, key_pem.as_bytes())?;
        tracing::info!(path = %server_cert_path.display(), "已签发服务端证书");
    }

    let cert_pem = std::fs::read_to_string(&server_cert_path)?;
    fingerprint_of_pem(&cert_pem)
}

/// 用 CA 签发 hub 的服务端证书。SAN 里同时放 IP 和 DNS。
pub fn issue_server_cert(ca_key_pem: &str, sans: &[String]) -> Result<(String, String)> {
    let ca_key = KeyPair::from_pem(ca_key_pem).context("解析 CA 私钥失败")?;
    let ca_cert = ca_issuer(&ca_key)?;

    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, SERVER_COMMON_NAME);
    params.subject_alt_names = san_entries(sans);
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

/// agent 侧生成密钥对与 CSR。私钥只在 agent 本地。
pub fn make_csr() -> Result<(String, String)> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "rustboard-agent-pending");
    let csr: CertificateSigningRequest = params.serialize_request(&key)?;
    Ok((csr.pem()?, key.serialize_pem()))
}

/// 校验 CSR 并用 CA 签出客户端证书，CN 固定为 hub 分配的 agent_id。
pub fn sign_client_csr(ca_key_pem: &str, csr_pem: &str, agent_id: &str) -> Result<String> {
    let ca_key = KeyPair::from_pem(ca_key_pem).context("解析 CA 私钥失败")?;
    let ca_cert = ca_issuer(&ca_key)?;

    let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .context("CSR 解析失败（可能不是合法的 PEM CSR）")?;

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

pub fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("解析证书 PEM 失败")?;
    if certs.is_empty() {
        return Err(anyhow!("PEM 中没有证书"));
    }
    Ok(certs)
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
pub fn server_config(data_dir: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let dir = cert_dir(data_dir);
    let cert_pem = std::fs::read_to_string(dir.join(SERVER_CERT_FILE))?;
    let key_path = dir.join(SERVER_KEY_FILE);
    // M3：服务端私钥也属于敏感文件，旧版本可能留下过宽权限。
    crate::fsutil::harden(&key_path, 0o600)?;
    let key_pem = std::fs::read_to_string(&key_path)?;
    let ca_pem = std::fs::read_to_string(dir.join(CA_CERT_FILE))?;

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
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// agent 的 TLS 客户端配置：固定服务端证书指纹，可选携带客户端证书。
pub fn client_config(
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
        .with_safe_default_protocol_versions()?
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

    #[test]
    fn ca_signs_client_csr() {
        // 生成 CA
        let ca_key = KeyPair::generate().unwrap();
        let ca_cert = ca_params().unwrap().self_signed(&ca_key).unwrap();
        let ca_key_pem = ca_key.serialize_pem();

        // agent 侧 CSR
        let (csr_pem, _key_pem) = make_csr().unwrap();

        // 签名
        let signed = sign_client_csr(&ca_key_pem, &csr_pem, "agent-123").unwrap();
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
        let ca_cert = ca_params().unwrap().self_signed(&ca_key).unwrap();
        let (csr_pem, _key_pem) = make_csr().unwrap();
        let signed = sign_client_csr(&ca_key.serialize_pem(), &csr_pem, "agent-cn-42").unwrap();
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

    #[cfg(unix)]
    #[test]
    fn issue_6_hub_material_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("rb-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        ensure_hub_material(&dir, &["localhost".to_string()]).unwrap();

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
