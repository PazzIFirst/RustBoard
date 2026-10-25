//! ACME 客户端：账户 load-or-create、订单、挑战、CSR 与证书获取。
//!
//! 使用 `instant-acme = 0.8.5`（ring + hyper-rustls，不引入 aws-lc）。账户
//! credentials 只保存在 `<data_dir>/certs/acme/account.json`（0600），不进入
//! 配置、日志或命令行参数。
//!
//! 订单总超时 180s；错误按 rate limit / validation / network 分类，信息只含
//! 公开的域名、状态与 ACME 返回的 problem detail，绝不打印 token、key
//! authorization、账户 key 或证书私钥。
//!
//! # 真实 Pebble 集成测试（默认跳过）
//!
//! 文件末尾三个 `pebble_*` 测试依赖本机 Pebble（host network，`14000` 目录、
//! HTTP `5002`、TLS-ALPN `5001`）与 `/tmp/pebble-test/certs/pebble.minica.pem`。
//! 默认 `cargo test` 因 `#[ignore]` 不会运行；显式运行时**必须**设置
//! `RUSTBOARD_PEBBLE=1`，缺少环境会 panic（而不是 0 退出伪装成功）：
//!
//! ```text
//! RUSTBOARD_PEBBLE=1 cargo test -p rustboard-hub --locked -- \
//!     --ignored pebble --test-threads=1
//! ```

use std::net::IpAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Error as AcmeError,
    Identifier, NewAccount, NewOrder, RetryPolicy,
};
use rcgen::{
    CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustboard_common::config::{AcmeChallenge, ServerTlsMode, TlsConfig};
use rustboard_common::tls;

use super::challenge::{start_http01, start_tls_alpn01, Http01Entry, TlsAlpn01Entry};
use super::store;

/// 单次 ACME 获取证书的总超时。
const ISSUE_TIMEOUT: Duration = Duration::from_secs(180);
/// 单次轮询的 RetryPolicy 超时（总超时由 [`ISSUE_TIMEOUT`] 兜底）。
const POLL_TIMEOUT: Duration = Duration::from_secs(60);
/// 错误信息里 problem detail 的最大字符数，避免异常响应撑爆日志/状态文件。
const MAX_ERROR_DETAIL_CHARS: usize = 300;

/// 一次成功签发的证书材料；只由调用方写盘。
pub struct IssuedCert {
    /// PEM：leaf 第一，其后是中间链（由 ACME 返回）。
    pub cert_pem: String,
    /// PKCS#8 PEM 私钥。
    pub key_pem: String,
    /// 到期时间（Unix 秒）。
    pub not_after: i64,
}

impl std::fmt::Debug for IssuedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedCert")
            .field("cert_bytes", &self.cert_pem.len())
            .field("key", &"<redacted>")
            .field("not_after", &self.not_after)
            .finish()
    }
}

/// 获取一张新证书（强制新建订单），不写 `server.crt/key`。
///
/// 调用方负责校验并安装；本函数只在成功后返回一次性材料。
pub async fn obtain_certificate(data_dir: &Path, tls_cfg: &TlsConfig) -> Result<IssuedCert> {
    tls_cfg
        .validate()
        .context("ACME 配置校验失败，拒绝发起订单")?;
    if !tls_cfg.mode.is_acme() {
        bail!(
            "当前 tls.mode = {}，不是 ACME 模式；自签证书请使用 `rustboard-hub rotate-cert`",
            tls_cfg.mode.as_str()
        );
    }
    match tokio::time::timeout(ISSUE_TIMEOUT, obtain_inner(data_dir, tls_cfg)).await {
        Ok(result) => result,
        Err(_) => bail!(
            "ACME 获取证书超时（{} 秒）；请检查网络/防火墙/ACME 服务状态；旧证书保持不变",
            ISSUE_TIMEOUT.as_secs()
        ),
    }
}

async fn obtain_inner(data_dir: &Path, tls_cfg: &TlsConfig) -> Result<IssuedCert> {
    let identifiers = build_identifiers(tls_cfg)?;
    let builder = build_account_builder(tls_cfg)?;
    let account = load_or_create_account(data_dir, tls_cfg, builder).await?;

    let profile = super::effective_profile(tls_cfg).map(str::to_string);
    if let Some(profile) = profile.as_deref() {
        // directory 未声明 profile 时提前给出配置错误，而不是等 NewOrder 返回模糊错误。
        if !account.profiles().any(|meta| meta.name == profile) {
            bail!(
                "ACME directory 未声明 profile {profile:?}；请检查 tls.acme_profile 或改用支持该 \
                 profile 的 ACME 服务（acme-ip 默认 shortlived）"
            );
        }
    }

    let mut order_request = NewOrder::new(&identifiers);
    if let Some(profile) = profile.as_deref() {
        order_request = order_request.profile(profile);
    }
    let mut order = account
        .new_order(&order_request)
        .await
        .map_err(|err| classify("ACME 新建订单失败", err))?;
    tracing::info!(
        domains = %tls_cfg.domains.join(","),
        profile = profile.as_deref().unwrap_or("(未设置)"),
        challenge = tls_cfg.challenge.as_str(),
        "ACME 订单已创建"
    );

    let challenge_type = match tls_cfg.challenge {
        AcmeChallenge::Http01 => ChallengeType::Http01,
        AcmeChallenge::TlsAlpn01 => ChallengeType::TlsAlpn01,
    };

    // 第一遍：收集所有待验证 challenge，启动一个覆盖全部 token/SNI 的临时服务。
    // 先启动再逐个 set_ready，避免多域名订单里第一个域名的验证还没完成就切端口。
    let mut http_entries = Vec::new();
    let mut tls_entries = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization =
                authorization.map_err(|err| classify("ACME 读取 authorization 失败", err))?;
            let domain = authorization.identifier().to_string();
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    bail!("ACME authorization {domain} 状态为 {other:?}，无法继续；请重新发起订单")
                }
            }
            let Some(challenge) = authorization.challenge(challenge_type.clone()) else {
                bail!(
                    "ACME 服务端没有为 {domain} 提供 {} 挑战；请检查 tls.challenge 配置",
                    tls_cfg.challenge.as_str()
                );
            };
            let token = challenge.token.clone();
            if token.is_empty() {
                bail!("ACME challenge token 为空（{domain}），拒绝继续");
            }
            match tls_cfg.challenge {
                AcmeChallenge::Http01 => http_entries.push(Http01Entry {
                    domain,
                    token,
                    key_authorization: challenge.key_authorization().as_str().to_string(),
                }),
                AcmeChallenge::TlsAlpn01 => tls_entries.push(TlsAlpn01Entry {
                    domain,
                    key_authorization_digest: challenge
                        .key_authorization()
                        .digest()
                        .as_ref()
                        .to_vec(),
                }),
            }
        }
    }

    let challenge_server = if http_entries.is_empty() && tls_entries.is_empty() {
        None
    } else {
        let server = match tls_cfg.challenge {
            AcmeChallenge::Http01 => start_http01(http_entries).await?,
            AcmeChallenge::TlsAlpn01 => start_tls_alpn01(tls_entries).await?,
        };
        tracing::debug!(
            addr = %server.local_addr(),
            challenge = tls_cfg.challenge.as_str(),
            "ACME 临时挑战服务已启动"
        );
        Some(server)
    };

    // 第二遍：逐个 set_ready。challenge 句柄只在单次循环内借用 authorization。
    {
        let mut authorizations = order.authorizations();
        while let Some(authorization) = authorizations.next().await {
            let mut authorization =
                authorization.map_err(|err| classify("ACME 读取 authorization 失败", err))?;
            if authorization.status == AuthorizationStatus::Valid {
                continue;
            }
            let domain = authorization.identifier().to_string();
            let Some(mut challenge) = authorization.challenge(challenge_type.clone()) else {
                bail!(
                    "ACME 服务端没有为 {domain} 提供 {} 挑战；请重新发起订单",
                    tls_cfg.challenge.as_str()
                );
            };
            challenge
                .set_ready()
                .await
                .map_err(|err| classify("ACME 提交挑战失败", err))?;
            tracing::info!(domain = %domain, "ACME 挑战已提交，等待 CA 验证");
        }
    }

    let status = order
        .poll_ready(&retry_policy())
        .await
        .map_err(|err| classify("ACME 等待订单就绪失败", err))?;
    // 验证完成后立即关闭临时端口；后续 finalize/poll 不需要挑战服务。
    if let Some(server) = challenge_server {
        server.shutdown().await;
    }
    if status != instant_acme::OrderStatus::Ready {
        bail!("ACME 订单未就绪（状态 {status:?}）；请检查域名解析/80/443 可达性后重试");
    }

    let key = KeyPair::generate().context("生成 ACME 证书私钥失败")?;
    let mut params =
        CertificateParams::new(tls_cfg.domains.clone()).context("生成 ACME CSR 参数失败")?;
    params.distinguished_name = DistinguishedName::new();
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let csr = params
        .serialize_request(&key)
        .context("生成 ACME CSR 失败")?;
    order
        .finalize_csr(csr.der())
        .await
        .map_err(|err| classify("ACME finalize CSR 失败", err))?;
    let cert_pem = order
        .poll_certificate(&retry_policy())
        .await
        .map_err(|err| classify("ACME 下载证书失败", err))?;
    let key_pem = key.serialize_pem();

    if cert_pem.trim().is_empty() {
        bail!("ACME 返回空证书，拒绝继续");
    }
    if !tls::cert_matches_key(&cert_pem, &key_pem).context("校验 ACME 证书与私钥配套失败")?
    {
        bail!("ACME 返回的证书与本地私钥不配套，拒绝继续");
    }
    // 写盘前先做公开校验；store 安装时会再校验一次（双保险）。
    tls::validate_public_server_cert(
        &cert_pem,
        &tls_cfg.domains,
        rustboard_common::util::now_ms(),
    )
    .context("ACME 返回的证书未通过公开校验，拒绝继续")?;
    let not_after = tls::not_after_unix(&cert_pem)?;
    tracing::info!(
        not_after = %tls::format_unix_utc(not_after),
        fingerprint = %tls::fingerprint_of_pem(&cert_pem)?,
        "ACME 证书签发成功"
    );
    Ok(IssuedCert {
        cert_pem,
        key_pem,
        not_after,
    })
}

fn build_identifiers(tls_cfg: &TlsConfig) -> Result<Vec<Identifier>> {
    match tls_cfg.mode {
        ServerTlsMode::AcmeDomain => Ok(tls_cfg
            .domains
            .iter()
            .map(|domain| Identifier::Dns(domain.clone()))
            .collect()),
        ServerTlsMode::AcmeIp => {
            let mut out = Vec::with_capacity(tls_cfg.domains.len());
            for domain in &tls_cfg.domains {
                // 配置校验已保证是 IPv4；这里仍严格解析，不能把 IP 塞进 Dns identifier。
                let ip: IpAddr = domain
                    .parse()
                    .with_context(|| format!("acme-ip 的 domains 条目 {domain:?} 不是合法 IP"))?;
                out.push(Identifier::Ip(ip));
            }
            Ok(out)
        }
        ServerTlsMode::SelfSigned => bail!("self-signed 模式不使用 ACME 订单"),
    }
}

fn build_account_builder(tls_cfg: &TlsConfig) -> Result<instant_acme::AccountBuilder> {
    let ca_file = tls_cfg.acme_ca_file.trim();
    if ca_file.is_empty() {
        return Account::builder().map_err(|err| classify("初始化 ACME HTTP 客户端失败", err));
    }
    // 私有/Pebble CA 文件由配置指定；拒绝符号链接，避免把 ACME 信任根指向
    // 任意的可被替换路径（D4）。
    let metadata = std::fs::symlink_metadata(ca_file)
        .with_context(|| format!("读取 tls.acme_ca_file 元数据失败: {ca_file}"))?;
    if metadata.file_type().is_symlink() {
        bail!("tls.acme_ca_file 是符号链接，拒绝读取: {ca_file}");
    }
    if !metadata.is_file() {
        bail!("tls.acme_ca_file 不是普通文件: {ca_file}");
    }
    // `Account::builder_with_root` 只读取一张 PEM 证书。多根私有 CA 需要自建
    // `HttpClient`（hyper + rustls + 自定义 RootCertStore）。当前 Phase C 明确
    // 限制为单根；后续要支持多根时在这里扩展，不要静默只取第一张。
    let pem = std::fs::read_to_string(ca_file)
        .with_context(|| format!("读取 tls.acme_ca_file 失败: {ca_file}"))?;
    let certificates =
        tls::load_certs(&pem).with_context(|| format!("解析 tls.acme_ca_file 失败: {ca_file}"))?;
    if certificates.len() != 1 {
        bail!(
            "tls.acme_ca_file 当前只支持单根 PEM 证书，但 {ca_file} 含 {} 张证书；\
             请拆分为只包含一个根证书的文件（多根加载需后续实现自定义 HttpClient）",
            certificates.len()
        );
    }
    Account::builder_with_root(ca_file)
        .map_err(|err| classify("初始化使用自定义 CA 的 ACME HTTP 客户端失败", err))
}

async fn load_or_create_account(
    data_dir: &Path,
    tls_cfg: &TlsConfig,
    builder: instant_acme::AccountBuilder,
) -> Result<Account> {
    if let Some(json) = store::read_account(data_dir)? {
        // 账户 credentials 自带 directory URL；配置换 directory 时必须显式重建账户，
        // 否则会拿着 A 服务的账户 key 去 B 服务下订单（通常被拒，且难以定位）。
        ensure_same_directory(&json, &tls_cfg.acme_directory)?;
        let credentials: AccountCredentials = serde_json::from_str(&json).context(
            "ACME 账户 credentials 无法反序列化（不会覆盖原文件）；请恢复备份或删除 account.json 重建账户",
        )?;
        let account = builder
            .from_credentials(credentials)
            .await
            .map_err(|err| classify("加载已有 ACME 账户失败", err))?;
        tracing::debug!("已加载已有 ACME 账户");
        return Ok(account);
    }

    let contact = format!("mailto:{}", tls_cfg.acme_email);
    let contacts = [contact.as_str()];
    let (account, credentials) = builder
        .create(
            &NewAccount {
                contact: &contacts,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            tls_cfg.acme_directory.clone(),
            None,
        )
        .await
        .map_err(|err| classify("创建 ACME 账户失败", err))?;
    let json = serde_json::to_string(&credentials).context("序列化 ACME 账户 credentials 失败")?;
    store::write_account(data_dir, &json).context("保存 ACME 账户失败（0600）")?;
    tracing::info!("已创建并保存 ACME 账户（credentials 0600）");
    Ok(account)
}

fn ensure_same_directory(json: &str, configured: &str) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_str(json).context("ACME 账户 credentials 不是合法 JSON")?;
    if let Some(stored) = value.get("directory").and_then(serde_json::Value::as_str) {
        if stored != configured {
            bail!(
                "ACME 账户属于另一个 directory（account.json: {stored}，配置: {configured}）；\
                 请恢复原 directory 配置，或删除 account.json 后重新执行 `rustboard-hub tls issue` \
                 创建新账户（不会自动覆盖旧账户）"
            );
        }
    }
    Ok(())
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy::new().timeout(POLL_TIMEOUT)
}

/// 把 instant-acme 错误分类成中文、可执行且不含 secret 的错误。
fn classify(context: &str, err: AcmeError) -> anyhow::Error {
    let detail = match &err {
        AcmeError::Api(problem) => {
            let kind = if problem.status == Some(429)
                || problem
                    .r#type
                    .as_deref()
                    .is_some_and(|kind| kind.contains("rateLimited"))
            {
                "rate limit（请稍后重试，勿频繁重签）"
            } else if problem.status.is_some_and(|status| status >= 500) {
                "服务端错误（可稍后重试）"
            } else {
                let kind = problem.r#type.as_deref().unwrap_or_default();
                if [
                    "unauthorized",
                    "connection",
                    "dns",
                    "caa",
                    "tls",
                    "incorrectResponse",
                    "rejectedIdentifier",
                    "malformed",
                ]
                .iter()
                .any(|candidate| kind.contains(candidate))
                {
                    "验证失败（检查域名解析、80/443 可达性与防火墙）"
                } else {
                    "API 错误"
                }
            };
            format!(
                "ACME {kind}: {}",
                truncate_chars(
                    &redact_challenge_paths(&problem.to_string()),
                    MAX_ERROR_DETAIL_CHARS
                )
            )
        }
        AcmeError::Timeout(_) => "ACME 轮询超时（CA 长时间未完成验证）".to_string(),
        AcmeError::Hyper(err) => format!("网络错误（连接 ACME 服务失败）: {err}"),
        AcmeError::Http(err) => format!("网络错误（构造 ACME 请求失败）: {err}"),
        AcmeError::InvalidUri(err) => format!("ACME directory URL 非法: {err}"),
        AcmeError::Unsupported(capability) => {
            format!("ACME 服务端不支持该能力: {capability}")
        }
        AcmeError::Json(err) => format!("ACME 响应 JSON 解析失败: {err}"),
        AcmeError::Other(err) => {
            // instant-acme 把部分 hyper/连接错误包成 Other；按文本归类为网络错误，
            // 便于运维区分「ACME 服务不可达」与协议/配置问题。
            let text = err.to_string();
            let network = [
                "client error",
                "Connect",
                "connect",
                "dns",
                "timed out",
                "timeout",
            ]
            .iter()
            .any(|needle| text.contains(needle));
            if network {
                format!("网络错误（连接 ACME 服务失败）: {text}")
            } else {
                format!("ACME 客户端错误: {text}")
            }
        }
        other => format!("ACME 客户端错误: {other}"),
    };
    anyhow::anyhow!("{context}: {detail}")
}

/// ACME problem detail 可能回显 `/.well-known/acme-challenge/<token>`。
/// token 虽然会发给 CA，但按 C4 约束不得进入日志/状态文件，这里统一脱敏。
fn redact_challenge_paths(text: &str) -> String {
    const PREFIX: &str = "/.well-known/acme-challenge/";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find(PREFIX) {
        out.push_str(&rest[..index + PREFIX.len()]);
        out.push_str("<redacted>");
        rest = &rest[index + PREFIX.len()..];
        let end = rest
            .find(|ch: char| {
                ch.is_whitespace() || matches!(ch, '"' | '\'' | ')' | ']' | '}' | ',' | ';')
            })
            .unwrap_or(rest.len());
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

fn truncate_chars(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= max {
            out.push_str("…（已截断）");
            break;
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustboard_common::config::AcmeChallenge;

    fn acme_tls(domains: &[&str]) -> TlsConfig {
        TlsConfig {
            mode: ServerTlsMode::AcmeDomain,
            acme_email: "admin@example.com".into(),
            acme_directory: "https://localhost:14000/dir".into(),
            challenge: AcmeChallenge::Http01,
            domains: domains.iter().map(|domain| (*domain).to_string()).collect(),
            acme_ca_file: "/tmp/pebble-test/certs/pebble.minica.pem".into(),
            ..TlsConfig::default()
        }
    }

    #[test]
    fn identifiers_use_dns_or_ip_variant() {
        let dns = build_identifiers(&acme_tls(&["board.example.com"])).unwrap();
        assert!(matches!(dns[0], Identifier::Dns(ref name) if name == "board.example.com"));

        let mut ip = acme_tls(&["127.0.0.1"]);
        ip.mode = ServerTlsMode::AcmeIp;
        let ids = build_identifiers(&ip).unwrap();
        assert!(matches!(ids[0], Identifier::Ip(addr) if addr.to_string() == "127.0.0.1"));
    }

    #[test]
    fn profile_defaults_follow_mode() {
        let mut domain = acme_tls(&["board.example.com"]);
        assert_eq!(super::super::effective_profile(&domain), None);
        domain.mode = ServerTlsMode::AcmeIp;
        assert_eq!(super::super::effective_profile(&domain), Some("shortlived"));
        domain.acme_profile = "tlsserver".into();
        assert_eq!(super::super::effective_profile(&domain), Some("tlsserver"));
    }

    #[cfg(unix)]
    #[test]
    fn acme_ca_file_rejects_symlink_and_multi_root() {
        use rcgen::{CertificateParams, DistinguishedName, KeyPair};

        let dir = temp_dir("ca-file");
        let pair = || {
            let mut params = CertificateParams::new(vec!["ca.example.com".to_string()]).unwrap();
            params.distinguished_name = DistinguishedName::new();
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let key = KeyPair::generate().unwrap();
            params.self_signed(&key).unwrap().pem()
        };

        // 多张证书必须明确报错，不能静默只取第一张。
        let bundle_file = dir.join("bundle.pem");
        std::fs::write(&bundle_file, format!("{}{}", pair(), pair())).unwrap();
        let mut cfg = acme_tls(&["board.example.com"]);
        cfg.acme_ca_file = bundle_file.to_string_lossy().to_string();
        let err = match build_account_builder(&cfg) {
            Ok(_) => panic!("多根 PEM 必须拒绝"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("单根 PEM"), "错误信息: {err:#}");

        // 符号链接：拒绝读取。
        let real = dir.join("real.pem");
        let link = dir.join("link.pem");
        std::fs::write(&real, pair()).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        cfg.acme_ca_file = link.to_string_lossy().to_string();
        let err = match build_account_builder(&cfg) {
            Ok(_) => panic!("符号链接必须拒绝"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("符号链接"), "错误信息: {err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn account_directory_mismatch_is_rejected() {
        let json = r#"{"id":"1","key_pkcs8":"AAAA","directory":"https://other.example/dir"}"#;
        let err = ensure_same_directory(json, "https://localhost:14000/dir").unwrap_err();
        assert!(format!("{err:#}").contains("另一个 directory"));
    }

    #[test]
    fn error_classification_does_not_leak_secrets() {
        let err = classify("测试", AcmeError::Str("some public failure"));
        let text = format!("{err:#}");
        assert!(text.contains("some public failure"));
        assert!(!text.to_ascii_lowercase().contains("keyauth"));
    }

    #[test]
    fn challenge_paths_are_redacted_from_error_text() {
        let redacted = redact_challenge_paths(
            "fetch http://board.example.com/.well-known/acme-challenge/secret-token_1 failed",
        );
        assert!(!redacted.contains("secret-token_1"), "脱敏失败: {redacted}");
        assert!(redacted.contains("<redacted>"));
        assert!(redacted.contains("fetch http://board.example.com/"));
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rb-acme-client-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Pebble 集成测试的硬性前置检查。
    ///
    /// `#[ignore]` 只保证默认 `cargo test` 跳过；当维护者显式 `--ignored`
    /// 请求这些测试时，缺少环境必须失败，不能静默 return 造成假绿。
    fn pebble_root() -> &'static str {
        const ROOT: &str = "/tmp/pebble-test/certs/pebble.minica.pem";
        if std::env::var("RUSTBOARD_PEBBLE").ok().as_deref() != Some("1") {
            panic!(
                "Pebble 集成测试必须显式设置 RUSTBOARD_PEBBLE=1；\
                 运行方式：RUSTBOARD_PEBBLE=1 cargo test -p rustboard-hub --locked -- \
                 --ignored pebble --test-threads=1"
            );
        }
        if !Path::new(ROOT).exists() {
            panic!(
                "已设置 RUSTBOARD_PEBBLE=1，但缺少 Pebble 根证书 {ROOT}；\
                 请先启动 Pebble（host network）：\
                 docker run -d --name rb-pebble --network host \
                 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
                 ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199 && \
                 mkdir -p /tmp/pebble-test/certs && \
                 docker cp rb-pebble:/test/certs/pebble.minica.pem \
                 /tmp/pebble-test/certs/pebble.minica.pem"
            );
        }
        ROOT
    }

    /// IP identifier + `shortlived` profile 的 Pebble 集成（C-G3 的本地验证）。
    #[tokio::test]
    #[ignore = "需要 RUSTBOARD_PEBBLE=1 + 本机 Pebble（host network 14000/5002）与 /tmp/pebble-test/certs/pebble.minica.pem"]
    async fn pebble_ip_shortlived_issues_real_certificate() {
        let _root = pebble_root();
        std::env::set_var("RUSTBOARD_ACME_HTTP_PORT", "5002");
        let dir = temp_dir("pebble-ip");
        let mut tls_cfg = acme_tls(&["127.0.0.1"]);
        tls_cfg.mode = ServerTlsMode::AcmeIp;
        let issued = obtain_certificate(&dir, &tls_cfg)
            .await
            .expect("Pebble IP shortlived 必须签发成功");
        tls::validate_acme_chain(
            &issued.cert_pem,
            &tls_cfg.domains,
            rustboard_common::util::now_ms(),
        )
        .expect("Pebble 必须返回真实叶子 + CA 链，且逐级验签通过");
        let names = tls::public_cert_names(&issued.cert_pem).unwrap();
        assert!(
            names.iter().any(|name| name == "IP:127.0.0.1"),
            "证书 SAN 必须包含 IP:127.0.0.1，实际 {names:?}"
        );
        let days = tls::days_left(&issued.cert_pem, rustboard_common::util::now_ms()).unwrap();
        assert!(days <= 7, "shortlived 应约 6 天，实际 {days} 天");
        std::env::remove_var("RUSTBOARD_ACME_HTTP_PORT");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 真实 Pebble 集成：需要本机 `rb-pebble`（14000/5002）与 Pebble 根证书。
    /// 不进入默认门禁；手动运行：
    /// `RUSTBOARD_PEBBLE=1 cargo test -p rustboard-hub --locked -- --ignored pebble --test-threads=1`
    #[tokio::test]
    #[ignore = "需要 RUSTBOARD_PEBBLE=1 + 本机 Pebble（host network 14000/5002）与 /tmp/pebble-test/certs/pebble.minica.pem"]
    async fn pebble_http01_issues_real_certificate() {
        let _root = pebble_root();
        std::env::set_var("RUSTBOARD_ACME_HTTP_PORT", "5002");
        let dir = temp_dir("pebble-http01");
        let tls_cfg = acme_tls(&["localhost"]);
        let issued = obtain_certificate(&dir, &tls_cfg)
            .await
            .expect("Pebble HTTP-01 必须签发成功");
        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!issued.key_pem.is_empty());
        tls::validate_acme_chain(
            &issued.cert_pem,
            &tls_cfg.domains,
            rustboard_common::util::now_ms(),
        )
        .expect("Pebble 必须返回真实叶子 + CA 链，且逐级验签通过");
        assert!(
            tls::not_after_unix(&issued.cert_pem).unwrap()
                > rustboard_common::util::now_ms() / 1000
        );
        std::env::remove_var("RUSTBOARD_ACME_HTTP_PORT");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// TLS-ALPN-01 的 Pebble 集成（Pebble tlsPort=5001）。
    #[tokio::test]
    #[ignore = "需要 RUSTBOARD_PEBBLE=1 + 本机 Pebble（host network 14000/5001）与 /tmp/pebble-test/certs/pebble.minica.pem"]
    async fn pebble_tls_alpn01_issues_real_certificate() {
        let _root = pebble_root();
        std::env::set_var("RUSTBOARD_ACME_TLS_PORT", "5001");
        let dir = temp_dir("pebble-tlsalpn");
        let mut tls_cfg = acme_tls(&["localhost"]);
        tls_cfg.challenge = AcmeChallenge::TlsAlpn01;
        let issued = obtain_certificate(&dir, &tls_cfg)
            .await
            .expect("Pebble TLS-ALPN-01 必须签发成功");
        tls::validate_acme_chain(
            &issued.cert_pem,
            &tls_cfg.domains,
            rustboard_common::util::now_ms(),
        )
        .expect("Pebble 必须返回真实叶子 + CA 链，且逐级验签通过");
        std::env::remove_var("RUSTBOARD_ACME_TLS_PORT");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
