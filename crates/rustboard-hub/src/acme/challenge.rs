//! ACME HTTP-01 / TLS-ALPN-01 临时挑战服务。
//!
//! 生产端口：HTTP-01 `0.0.0.0:80`、TLS-ALPN-01 `0.0.0.0:443`。测试/私有 ACME
//! 可以用环境变量覆盖（**仅用于测试与私有 CA，不替代生产端口诊断**）：
//! - `RUSTBOARD_ACME_HTTP_PORT`
//! - `RUSTBOARD_ACME_TLS_PORT`
//!
//! 挑战服务只在订单验证期间存在，返回的 [`ChallengeServer`] drop 或
//! [`ChallengeServer::shutdown`] 都会关闭监听端口；请求有 8 KiB / 5s 上限，
//! 日志绝不记录 token 或 key authorization。

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustboard_common::config::AcmeChallenge;
use rustboard_common::tls;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

/// HTTP-01 请求上限（含请求行与全部 header）。
const MAX_HTTP_REQUEST_BYTES: usize = 8 * 1024;
/// 单连接读/写与 TLS 握手超时。
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// ACME HTTP-01 的固定路径前缀。
const HTTP_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
/// TLS-ALPN-01 唯一允许的 ALPN。
const ACME_TLS_ALPN: &[u8] = b"acme-tls/1";
/// 生产 HTTP-01 端口。
const DEFAULT_HTTP_PORT: u16 = 80;
/// 生产 TLS-ALPN-01 端口。
const DEFAULT_TLS_PORT: u16 = 443;
/// 测试/私有 ACME 的 HTTP 端口覆盖变量。
pub const HTTP_PORT_ENV: &str = "RUSTBOARD_ACME_HTTP_PORT";
/// 测试/私有 ACME 的 TLS-ALPN 端口覆盖变量。
pub const TLS_PORT_ENV: &str = "RUSTBOARD_ACME_TLS_PORT";

/// 一条 HTTP-01 挑战应答。`Debug` 会隐藏 token / key authorization。
#[derive(Clone)]
pub struct Http01Entry {
    /// 该 token 对应的证书标识（DNS 或 IP 字符串）。
    pub domain: String,
    /// ACME challenge token。
    pub token: String,
    /// ACME key authorization 明文。
    pub key_authorization: String,
}

impl fmt::Debug for Http01Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Http01Entry")
            .field("domain", &self.domain)
            .field("token_len", &self.token.len())
            .field("key_authorization", &"<redacted>")
            .finish()
    }
}

/// 一条 TLS-ALPN-01 挑战证书。`Debug` 会隐藏 key authorization 摘要。
#[derive(Clone)]
pub struct TlsAlpn01Entry {
    /// 该 challenge 对应的证书标识（DNS 或 IP 字符串）。
    pub domain: String,
    /// `SHA-256(key authorization)`，32 字节。
    pub key_authorization_digest: Vec<u8>,
}

impl fmt::Debug for TlsAlpn01Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsAlpn01Entry")
            .field("domain", &self.domain)
            .field("digest", &"<redacted>")
            .finish()
    }
}

/// 运行中的挑战服务。drop 时关闭监听；需要等待端口释放时调用 [`Self::shutdown`]。
pub struct ChallengeServer {
    local_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl ChallengeServer {
    /// 实际绑定的地址（`port=0` 的测试场景可据此连接）。
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// 关闭监听并等待 accept 任务退出（端口已释放）。
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for ChallengeServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// 启动 HTTP-01 挑战服务（生产 80，测试可用 `RUSTBOARD_ACME_HTTP_PORT`）。
pub async fn start_http01(entries: Vec<Http01Entry>) -> Result<ChallengeServer> {
    let port = challenge_port(AcmeChallenge::Http01)?;
    let from_env = std::env::var_os(HTTP_PORT_ENV).is_some();
    start_http01_on(SocketAddr::from(([0, 0, 0, 0], port)), entries, from_env).await
}

/// 启动 TLS-ALPN-01 挑战服务（生产 443，测试可用 `RUSTBOARD_ACME_TLS_PORT`）。
pub async fn start_tls_alpn01(entries: Vec<TlsAlpn01Entry>) -> Result<ChallengeServer> {
    let port = challenge_port(AcmeChallenge::TlsAlpn01)?;
    let from_env = std::env::var_os(TLS_PORT_ENV).is_some();
    start_tls_alpn01_on(SocketAddr::from(([0, 0, 0, 0], port)), entries, from_env).await
}

fn challenge_port(challenge: AcmeChallenge) -> Result<u16> {
    let (name, default) = match challenge {
        AcmeChallenge::Http01 => (HTTP_PORT_ENV, DEFAULT_HTTP_PORT),
        AcmeChallenge::TlsAlpn01 => (TLS_PORT_ENV, DEFAULT_TLS_PORT),
    };
    match std::env::var(name) {
        Ok(value) => {
            let trimmed = value.trim();
            let port: u16 = trimmed.parse().map_err(|_| {
                anyhow::anyhow!("环境变量 {name}={value:?} 不是合法端口（1–65535）")
            })?;
            if port == 0 {
                bail!("环境变量 {name} 不能为 0；请指定 1–65535 的端口");
            }
            Ok(port)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("环境变量 {name} 不是合法 UTF-8，拒绝启动挑战服务")
        }
    }
}

async fn start_http01_on(
    addr: SocketAddr,
    entries: Vec<Http01Entry>,
    from_env: bool,
) -> Result<ChallengeServer> {
    if entries.is_empty() {
        bail!("HTTP-01 挑战列表为空，拒绝启动临时监听");
    }
    let mut responses: HashMap<String, (String, String)> = HashMap::with_capacity(entries.len());
    for entry in entries {
        validate_entry(&entry.domain, "HTTP-01")?;
        if entry.token.is_empty() || !entry.token.bytes().all(is_token_byte) {
            bail!("HTTP-01 token 非法（只允许 base64url 字符），拒绝启动挑战服务");
        }
        if entry.key_authorization.is_empty() {
            bail!("HTTP-01 key authorization 为空，拒绝启动挑战服务");
        }
        if responses
            .insert(entry.token, (entry.domain, entry.key_authorization))
            .is_some()
        {
            bail!("HTTP-01 token 重复，拒绝启动有歧义的挑战服务");
        }
    }
    let listener = TcpListener::bind(addr).await.with_context(|| {
        format!(
            "HTTP-01 挑战服务无法绑定 {addr}：端口可能被 nginx/其它服务占用；\
             生产环境请释放 80（或确认安全组/防火墙放行），测试可设置 {HTTP_PORT_ENV}"
        )
    })?;
    let local_addr = listener.local_addr()?;
    log_test_port_override(from_env, HTTP_PORT_ENV);
    tracing::info!(
        %local_addr,
        source = if from_env { HTTP_PORT_ENV } else { "默认" },
        "HTTP-01 挑战服务已启动（临时监听，不记录 token）"
    );
    let responses = Arc::new(responses);
    let (tx, mut rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let responses = responses.clone();
                        tokio::spawn(async move {
                            handle_http_connection(stream, peer, responses).await;
                        });
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "HTTP-01 临时监听 accept 失败，关闭挑战服务");
                        break;
                    }
                }
            }
        }
    });
    Ok(ChallengeServer {
        local_addr,
        shutdown: Some(tx),
        handle: Some(handle),
    })
}

async fn handle_http_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    responses: Arc<HashMap<String, (String, String)>>,
) {
    match tokio::time::timeout(IO_TIMEOUT, serve_http(&mut stream, &responses)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => tracing::debug!(%peer, error = %err, "HTTP-01 连接处理失败"),
        Err(_) => tracing::debug!(%peer, "HTTP-01 连接超时（5s）"),
    }
}

async fn serve_http(
    stream: &mut TcpStream,
    responses: &HashMap<String, (String, String)>,
) -> std::io::Result<()> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        if find_header_end(&buffer).is_some() {
            break;
        }
        if buffer.len() >= MAX_HTTP_REQUEST_BYTES {
            return respond(stream, 413, "Payload Too Large", "request too large").await;
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HTTP_REQUEST_BYTES {
            return respond(stream, 413, "Payload Too Large", "request too large").await;
        }
    }
    let Some(header_end) = find_header_end(&buffer) else {
        return respond(stream, 400, "Bad Request", "bad request").await;
    };
    let header = match std::str::from_utf8(&buffer[..header_end]) {
        Ok(text) => text,
        Err(_) => return respond(stream, 400, "Bad Request", "bad request").await,
    };
    let mut lines = header.split("\r\n");
    let Some(request_line) = lines.next() else {
        return respond(stream, 400, "Bad Request", "bad request").await;
    };
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return respond(stream, 400, "Bad Request", "bad request").await;
    };
    if !version.starts_with("HTTP/1.") {
        return respond(stream, 400, "Bad Request", "bad request").await;
    }
    if method != "GET" {
        return respond(stream, 405, "Method Not Allowed", "method not allowed").await;
    }
    let mut host: Option<&str> = None;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return respond(stream, 400, "Bad Request", "bad request").await;
        };
        if name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return respond(stream, 400, "Bad Request", "bad request").await;
            }
            host = Some(value.trim());
        }
    }
    let Some(host) = host else {
        return respond(stream, 404, "Not Found", "not found").await;
    };
    // 只接受精确的 `/.well-known/acme-challenge/<token>`；带 query/fragment 一律 404。
    let Some(token) = target.strip_prefix(HTTP_CHALLENGE_PREFIX) else {
        return respond(stream, 404, "Not Found", "not found").await;
    };
    if token.is_empty()
        || !token.bytes().all(is_token_byte)
        || token.contains('/')
        || token.contains('?')
        || token.contains('#')
    {
        return respond(stream, 404, "Not Found", "not found").await;
    }
    let Some((domain, key_authorization)) = responses.get(token) else {
        return respond(stream, 404, "Not Found", "not found").await;
    };
    // Host 必须是 identifier（允许带端口）；未知 Host 按 404 处理，不泄露 token 是否存在。
    if !host_matches(host, domain) {
        tracing::debug!("HTTP-01 Host 与 identifier 不匹配，拒绝应答");
        return respond(stream, 404, "Not Found", "not found").await;
    }
    respond(stream, 200, "OK", key_authorization).await
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}

/// Host 头是否等于 identifier（DNS 大小写不敏感、IP 精确，允许带端口）。
fn host_matches(host: &str, domain: &str) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    let domain = domain.trim();
    let Ok(expected_ip) = domain.parse::<IpAddr>() else {
        let host_without_port = strip_port(host);
        return host_without_port
            .trim_end_matches('.')
            .eq_ignore_ascii_case(domain.trim_end_matches('.'));
    };
    // IPv4 / [IPv6]:port / [IPv6]
    let host_ip = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or_default()
    } else {
        strip_port(host)
    };
    host_ip
        .parse::<IpAddr>()
        .map(|actual| actual == expected_ip)
        .unwrap_or(false)
}

/// 去掉 `host:port` 的端口；IPv6 字面量（无方括号）保持原样。
fn strip_port(host: &str) -> &str {
    if host.matches(':').count() == 1 {
        if let Some((name, port)) = host.rsplit_once(':') {
            if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) {
                return name;
            }
        }
    }
    host
}

/// 环境变量覆盖端口只用于测试/私有 CA；日志明确提示，避免被当成生产诊断结论。
fn log_test_port_override(from_env: bool, env_name: &str) {
    if from_env {
        tracing::warn!(
            env = env_name,
            "使用环境变量覆盖 ACME 挑战端口：仅用于测试/私有 CA，不替代生产 80/443 端口诊断"
        );
    }
}

fn validate_entry(domain: &str, what: &str) -> Result<()> {
    let domain = domain.trim();
    if domain.is_empty() {
        bail!("{what} 挑战的 identifier 为空，拒绝启动挑战服务");
    }
    if domain
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("{what} 挑战的 identifier 含控制字符或空白，拒绝启动挑战服务");
    }
    Ok(())
}

/// TLS-ALPN-01 证书解析器：按 SNI 选择挑战证书；没有 SNI 且只有一张证书时回退。
#[derive(Debug)]
struct AcmeAlpnResolver {
    certs: HashMap<String, Arc<CertifiedKey>>,
    sole: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for AcmeAlpnResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // 只有明确协商 acme-tls/1 的 ClientHello 才下发挑战证书；无 ALPN
        // 的普通 TLS 客户端应在证书阶段之前失败，避免泄露挑战证书。
        let alpn_ok = hello
            .alpn()
            .map(|mut protocols| protocols.any(|proto| proto == ACME_TLS_ALPN))
            .unwrap_or(false);
        if !alpn_ok {
            return None;
        }
        if let Some(name) = hello.server_name() {
            if let Some(cert) = self.certs.get(&name.to_ascii_lowercase()) {
                return Some(cert.clone());
            }
            // 多域名时未知 SNI 绝不回退到其它域名的证书。
            return None;
        }
        self.sole.clone()
    }
}

async fn start_tls_alpn01_on(
    addr: SocketAddr,
    entries: Vec<TlsAlpn01Entry>,
    from_env: bool,
) -> Result<ChallengeServer> {
    let config = build_tls_alpn_config(&entries)?;
    let listener = TcpListener::bind(addr).await.with_context(|| {
        format!(
            "TLS-ALPN-01 挑战服务无法绑定 {addr}：端口可能被占用；\
             生产环境请释放 443（或确认安全组/防火墙放行），测试可设置 {TLS_PORT_ENV}"
        )
    })?;
    let local_addr = listener.local_addr()?;
    log_test_port_override(from_env, TLS_PORT_ENV);
    tracing::info!(
        %local_addr,
        source = if from_env { TLS_PORT_ENV } else { "默认" },
        "TLS-ALPN-01 挑战服务已启动（仅 ALPN acme-tls/1）"
    );
    let acceptor = TlsAcceptor::from(config);
    let (tx, mut rx) = oneshot::channel();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(IO_TIMEOUT, acceptor.accept(stream)).await {
                                Ok(Ok(mut tls_stream)) => {
                                    // 只接受 acme-tls/1；普通 ALPN 或无 ALPN 一律不提供任何数据。
                                    let ok = tls_stream
                                        .get_ref()
                                        .1
                                        .alpn_protocol()
                                        .map(|proto| proto == ACME_TLS_ALPN)
                                        .unwrap_or(false);
                                    if !ok {
                                        tracing::debug!(%peer, "TLS-ALPN-01 客户端未协商 acme-tls/1，关闭连接");
                                        return;
                                    }
                                    let _ = tokio::time::timeout(IO_TIMEOUT, tls_stream.shutdown()).await;
                                }
                                Ok(Err(err)) => {
                                    // 握手失败只 debug：可能来自扫描器/普通 HTTPS 客户端。
                                    tracing::debug!(%peer, error = %err, "TLS-ALPN-01 握手失败");
                                }
                                Err(_) => tracing::debug!(%peer, "TLS-ALPN-01 握手超时（5s）"),
                            }
                        });
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "TLS-ALPN-01 临时监听 accept 失败，关闭挑战服务");
                        break;
                    }
                }
            }
        }
    });
    Ok(ChallengeServer {
        local_addr,
        shutdown: Some(tx),
        handle: Some(handle),
    })
}

fn build_tls_alpn_config(entries: &[TlsAlpn01Entry]) -> Result<Arc<rustls::ServerConfig>> {
    if entries.is_empty() {
        bail!("TLS-ALPN-01 挑战列表为空，拒绝启动临时监听");
    }
    let mut certs: HashMap<String, Arc<CertifiedKey>> = HashMap::with_capacity(entries.len());
    for entry in entries {
        validate_entry(&entry.domain, "TLS-ALPN-01")?;
        if entry.key_authorization_digest.len() != 32 {
            bail!(
                "TLS-ALPN-01 key authorization 摘要必须是 32 字节（SHA-256），实际 {} 字节",
                entry.key_authorization_digest.len()
            );
        }
        let mut params = CertificateParams::new(vec![entry.domain.clone()])
            .context("生成 TLS-ALPN-01 挑战证书参数失败")?;
        // 挑战证书不需要 CN；SAN 必须覆盖 identifier。
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params
            .custom_extensions
            .push(CustomExtension::new_acme_identifier(
                &entry.key_authorization_digest,
            ));
        let key = KeyPair::generate().context("生成 TLS-ALPN-01 挑战私钥失败")?;
        let cert = params
            .self_signed(&key)
            .context("生成 TLS-ALPN-01 挑战证书失败")?;
        // 不依赖 rustls 的校验路径，自己确认私钥与证书公钥一致。
        if !tls::cert_matches_key(&cert.pem(), &key.serialize_pem())
            .context("校验 TLS-ALPN-01 挑战证书与私钥是否配套失败")?
        {
            bail!("TLS-ALPN-01 挑战证书与私钥不配套，拒绝启动挑战服务");
        }
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .context("加载 TLS-ALPN-01 挑战私钥失败")?;
        let certified = Arc::new(CertifiedKey::new(vec![cert.der().clone()], signing_key));
        let name = entry.domain.to_ascii_lowercase();
        if certs.insert(name, certified).is_some() {
            bail!("TLS-ALPN-01 identifier 重复，拒绝启动有歧义的挑战服务");
        }
    }
    let sole = if certs.len() == 1 {
        certs.values().next().cloned()
    } else {
        None
    };
    let resolver = AcmeAlpnResolver { certs, sole };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("构建 TLS-ALPN-01 rustls 配置失败")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    /// 接受任意证书的测试客户端：TLS-ALPN 挑战证书带 critical 扩展，
    /// webpki 按设计会拒绝，因此测试只关心连接与扩展内容。
    #[derive(Debug)]
    struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

    impl ServerCertVerifier for AcceptAny {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        // 挑战证书带 critical 的 id-pe-acmeIdentifier；webpki 的
        // `verify_tls1{2,3}_signature` 会在验签前解析证书并拒绝未知 critical
        // 扩展（与 C0 spike §6 的服务端限制同源）。测试只验证 ALPN 与扩展内容，
        // 因此这里直接返回 assertion，不承担生产校验职责。
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    fn http_entry() -> Http01Entry {
        Http01Entry {
            domain: "board.example.com".into(),
            token: "test-token_123".into(),
            key_authorization: "test-token_123.thumbprint".into(),
        }
    }

    async fn send(addr: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8_lossy(&response).to_string()
    }

    #[tokio::test]
    async fn http01_serves_known_token_for_matching_host() {
        let server = start_http01_on(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            vec![http_entry()],
            false,
        )
        .await
        .unwrap();
        let addr = server.local_addr();
        let response = send(
            addr,
            "GET /.well-known/acme-challenge/test-token_123 HTTP/1.1\r\n\
             Host: board.example.com:5002\r\n\r\n",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 200 OK"), "响应: {response}");
        assert!(
            response.ends_with("test-token_123.thumbprint"),
            "响应: {response}"
        );
        // 非法端口环境变量不影响已启动服务；正常 shutdown 后端口可立即重绑。
        server.shutdown().await;
        let rebound = TcpListener::bind(addr)
            .await
            .expect("shutdown 后端口必须释放");
        drop(rebound);
    }

    #[tokio::test]
    async fn http01_rejects_unknown_token_wrong_host_and_bad_method() {
        let server = start_http01_on(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            vec![http_entry()],
            false,
        )
        .await
        .unwrap();
        let addr = server.local_addr();

        let wrong_token = send(
            addr,
            "GET /.well-known/acme-challenge/other HTTP/1.1\r\n\
             Host: board.example.com\r\n\r\n",
        )
        .await;
        assert!(
            wrong_token.starts_with("HTTP/1.1 404"),
            "响应: {wrong_token}"
        );

        let wrong_host = send(
            addr,
            "GET /.well-known/acme-challenge/test-token_123 HTTP/1.1\r\n\
             Host: attacker.example.com\r\n\r\n",
        )
        .await;
        assert!(wrong_host.starts_with("HTTP/1.1 404"), "响应: {wrong_host}");

        let post = send(
            addr,
            "POST /.well-known/acme-challenge/test-token_123 HTTP/1.1\r\n\
             Host: board.example.com\r\n\r\n",
        )
        .await;
        assert!(post.starts_with("HTTP/1.1 405"), "响应: {post}");

        let query = send(
            addr,
            "GET /.well-known/acme-challenge/test-token_123?x=1 HTTP/1.1\r\n\
             Host: board.example.com\r\n\r\n",
        )
        .await;
        assert!(query.starts_with("HTTP/1.1 404"), "响应: {query}");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn http01_rejects_oversized_request() {
        let server = start_http01_on(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            vec![http_entry()],
            false,
        )
        .await
        .unwrap();
        let addr = server.local_addr();
        let request = format!(
            "GET /.well-known/acme-challenge/test-token_123 HTTP/1.1\r\n\
             Host: board.example.com\r\nX-Padding: {}\r\n\r\n",
            "a".repeat(MAX_HTTP_REQUEST_BYTES)
        );
        let response = send(addr, &request).await;
        assert!(
            response.starts_with("HTTP/1.1 413"),
            "超 8KiB 必须拒绝: {response}"
        );
        server.shutdown().await;
    }

    #[tokio::test]
    async fn tls_alpn01_serves_critical_acme_identifier_cert() {
        let digest = vec![7u8; 32];
        let server = start_tls_alpn01_on(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            vec![TlsAlpn01Entry {
                domain: "board.example.com".into(),
                key_authorization_digest: digest.clone(),
            }],
            false,
        )
        .await
        .unwrap();
        let addr = server.local_addr();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(AcceptAny(provider.clone()));
        let mut client = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        client.alpn_protocols = vec![ACME_TLS_ALPN.to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("board.example.com".to_string()).unwrap();
        let mut tls_stream = connector
            .connect(name, tcp)
            .await
            .expect("TLS-ALPN 握手必须成功");
        assert_eq!(
            tls_stream.get_ref().1.alpn_protocol(),
            Some(ACME_TLS_ALPN),
            "必须协商 acme-tls/1"
        );
        let peer = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .expect("挑战证书必须可读")
            .to_vec();
        assert!(!peer.is_empty());
        let (_, cert) = x509_parser::parse_x509_certificate(peer[0].as_ref()).unwrap();
        let extension = cert
            .extensions()
            .iter()
            .find(|ext| ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("挑战证书必须包含 id-pe-acmeIdentifier 扩展");
        assert!(extension.critical, "acmeIdentifier 扩展必须是 critical");
        // RFC 8737：extnValue 是 DER OCTET STRING，内容为 SHA-256 digest。
        assert_eq!(extension.value.len(), 34, "扩展内容: {:?}", extension.value);
        assert_eq!(&extension.value[..2], &[0x04, 0x20]);
        assert_eq!(&extension.value[2..], digest.as_slice());
        let _ = tls_stream.shutdown().await;
        server.shutdown().await;
    }

    #[tokio::test]
    async fn tls_alpn01_rejects_other_alpn() {
        let server = start_tls_alpn01_on(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            vec![TlsAlpn01Entry {
                domain: "board.example.com".into(),
                key_authorization_digest: vec![1u8; 32],
            }],
            false,
        )
        .await
        .unwrap();
        let addr = server.local_addr();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("board.example.com".to_string()).unwrap();
        let result = connector.connect(name, tcp).await;
        assert!(result.is_err(), "非 acme-tls/1 的 ALPN 不能完成握手");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn tls_alpn01_rejects_missing_alpn_before_certificate() {
        let server = start_tls_alpn01_on(
            SocketAddr::from(([127, 0, 0, 1], 0)),
            vec![TlsAlpn01Entry {
                domain: "board.example.com".into(),
                key_authorization_digest: vec![1u8; 32],
            }],
            false,
        )
        .await
        .unwrap();
        let addr = server.local_addr();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from("board.example.com".to_string()).unwrap();
        let result = connector.connect(name, tcp).await;
        assert!(result.is_err(), "无 ALPN 的客户端不得拿到挑战证书");
        server.shutdown().await;
    }

    #[test]
    fn host_matching_allows_ports_and_rejects_mismatch() {
        assert!(host_matches("board.example.com:80", "board.example.com"));
        assert!(host_matches("BOARD.EXAMPLE.COM", "board.example.com"));
        assert!(host_matches("127.0.0.1:5002", "127.0.0.1"));
        assert!(host_matches("[::1]:5002", "::1"));
        assert!(!host_matches("evil.example.com", "board.example.com"));
        assert!(!host_matches("127.0.0.2", "127.0.0.1"));
        assert!(!host_matches("", "board.example.com"));
    }

    #[test]
    fn challenge_port_env_rejects_invalid_values() {
        let key = "RUSTBOARD_ACME_HTTP_PORT";
        let old = std::env::var_os(key);
        std::env::set_var(key, "0");
        assert!(challenge_port(AcmeChallenge::Http01).is_err());
        std::env::set_var(key, "not-a-port");
        assert!(challenge_port(AcmeChallenge::Http01).is_err());
        std::env::set_var(key, "5002");
        assert_eq!(challenge_port(AcmeChallenge::Http01).unwrap(), 5002);
        match old {
            Some(value) => std::env::set_var(key, value),
            None => std::env::remove_var(key),
        }
    }
}
