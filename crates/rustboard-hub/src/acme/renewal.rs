//! ACME 证书续期：到期判断、周期检查、指数退避与热加载。
//!
//! 阈值（D8）：剩余寿命 ≤ `min(lifetime/3, 48h)` 时续期。6 天的 IP 短期证书
//! 因此约在剩余 2 天时续期；已过期证书也视为需要续期。
//!
//! 失败退避：1m / 5m / 15m / 1h / 最大 6h。续期失败只 WARN 并保留旧证书，
//! **绝不退出 hub**。成功安装后重建 `tls::server_config` 并 `watch::send_replace`，
//! 同一临界区用实际推送的证书 PEM 更新 live 摘要；文件 watcher 仍保留作为兜底
//! （CLI issue 也会被它加载）。

use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustboard_common::config::HubConfig;
use rustboard_common::tls;
use rustboard_common::util::now_ms;
use rustls::ServerConfig;

use crate::cert_rotation::{write_live, CertLock, CertStatus, TlsConfigSender};

use super::client::{self, IssuedCert};
use super::store;

/// 失败退避序列；超过最后一档后保持 6h。
const BACKOFFS: [Duration; 5] = [
    Duration::from_secs(60),
    Duration::from_secs(5 * 60),
    Duration::from_secs(15 * 60),
    Duration::from_secs(60 * 60),
    Duration::from_secs(6 * 60 * 60),
];
/// 状态文件里 last_error 的最大字符数。
const MAX_STATE_ERROR_CHARS: usize = 500;
const HOUR_MS: i64 = 3_600_000;
const MAX_RENEW_AHEAD_MS: i64 = 48 * HOUR_MS;

/// 是否需要在当前时刻续期。
///
/// - 已过期（`now >= notAfter`）→ `true`；
/// - 剩余寿命 ≤ `min(lifetime/3, 48h)` → `true`；
/// - 其余 → `false`。
pub fn needs_renewal(cert_pem: &str, now_ms: i64) -> Result<bool> {
    let (not_before, not_after) =
        tls::validity_unix(cert_pem).context("解析证书有效期失败，无法判断是否续期")?;
    if not_after <= not_before {
        bail!("证书有效期非法（notBefore={not_before} >= notAfter={not_after}），拒绝自动续期");
    }
    let now_s = now_ms.div_euclid(1_000);
    if now_s >= not_after {
        return Ok(true);
    }
    let threshold_ms = renewal_threshold_ms(not_before, not_after);
    let remaining_ms = not_after
        .saturating_mul(1_000)
        .saturating_sub(now_ms)
        .max(0);
    Ok(remaining_ms <= threshold_ms)
}

/// 按 D8 公式计算下一次续期时间（Unix 秒）。仅用于状态展示。
pub fn next_renewal_unix(cert_pem: &str) -> Result<i64> {
    let (not_before, not_after) = tls::validity_unix(cert_pem)?;
    if not_after <= not_before {
        bail!("证书有效期非法（notBefore={not_before} >= notAfter={not_after}）");
    }
    let threshold_ms = renewal_threshold_ms(not_before, not_after);
    Ok(not_after.saturating_sub(threshold_ms.div_euclid(1_000)))
}

fn renewal_threshold_ms(not_before: i64, not_after: i64) -> i64 {
    let lifetime_ms = not_after
        .saturating_sub(not_before)
        .saturating_mul(1_000)
        .max(0);
    (lifetime_ms / 3).min(MAX_RENEW_AHEAD_MS)
}

fn backoff_delay(failures: usize) -> Duration {
    BACKOFFS[failures.min(BACKOFFS.len() - 1)]
}

/// 启动 ACME 续期任务；非 ACME 模式直接返回（自签续期由 cert_rotation 负责）。
pub fn spawn_acme_renewal(cfg: Arc<HubConfig>, tx: TlsConfigSender, live: Arc<RwLock<CertStatus>>) {
    if !cfg.tls.mode.is_acme() {
        tracing::debug!(
            mode = cfg.tls.mode.as_str(),
            "非 ACME 模式，不启动 ACME 续期任务"
        );
        return;
    }
    tokio::spawn(async move {
        let period = Duration::from_secs(cfg.cert_check_interval_secs.max(60));
        let mut failures = 0usize;
        loop {
            match renew_if_due(&cfg, Some(&tx), Some(&live)).await {
                Ok(Some(issued)) => {
                    failures = 0;
                    tracing::info!(
                        not_after = %tls::format_unix_utc(issued.not_after),
                        "ACME 证书续期完成，新连接已使用新证书"
                    );
                }
                Ok(None) => {
                    failures = 0;
                }
                Err(err) => {
                    let delay = backoff_delay(failures);
                    failures = failures.saturating_add(1);
                    // 只记录公开信息（域名/错误摘要）；issue 过程本身不打印 secret。
                    tracing::warn!(
                        error = %format!("{err:#}"),
                        retry_after_secs = delay.as_secs(),
                        "ACME 证书续期失败，保留旧证书，稍后重试（hub 不退出）"
                    );
                    record_failure(&cfg, &err, delay);
                    tokio::time::sleep(delay).await;
                    continue;
                }
            }
            tokio::time::sleep(period).await;
        }
    });
}

/// 手动强制签发并安装（`rustboard-hub tls issue`）。
pub async fn issue_and_install(cfg: &HubConfig) -> Result<IssuedCert> {
    if !cfg.tls.mode.is_acme() {
        bail!(
            "当前 tls.mode = {}，不是 ACME 模式；自签证书请使用 `rustboard-hub rotate-cert --force`",
            cfg.tls.mode.as_str()
        );
    }
    let cert_dir = tls::cert_dir(&cfg.data_dir);
    let _lock = CertLock::acquire(&cert_dir)
        .context("获取证书安装锁失败（另一个 tls issue/renew/rotate-cert 正在运行）")?;
    let (issued, _config) = issue_locked(cfg).await?;
    Ok(issued)
}

/// 到期才签发（`rustboard-hub tls renew` 与自动续期共用）。
///
/// `Ok(None)` 表示剩余寿命充足，未发起任何网络请求/写入。
pub async fn renew_if_due(
    cfg: &HubConfig,
    tx: Option<&TlsConfigSender>,
    live: Option<&RwLock<CertStatus>>,
) -> Result<Option<IssuedCert>> {
    if !cfg.tls.mode.is_acme() {
        bail!("当前 tls.mode 不是 ACME 模式，不能执行 tls renew");
    }
    let cert_dir = tls::cert_dir(&cfg.data_dir);
    // 与 CLI issue / 自签 rotate 互斥；锁内再读一次证书，避免并发重复签发。
    let _lock = CertLock::acquire(&cert_dir)
        .context("获取证书续期锁失败（另一个 tls issue/renew/rotate-cert 正在运行）")?;
    let material = store::read_server_material(&cfg.data_dir)?;
    let due = match &material {
        None => true,
        Some(material) => {
            needs_renewal(&material.cert_pem, now_ms()).context("判断 ACME 证书是否需要续期失败")?
        }
    };
    if !due {
        return Ok(None);
    }
    let (issued, config) = issue_locked(cfg).await?;
    if let Some(tx) = tx {
        // 与 cert_rotation 的 watch 使用同一通道：accept 循环每条新连接读一次。
        tx.send_replace(config);
    }
    if let Some(live) = live {
        sync_live_from_pem(live, &issued.cert_pem);
    }
    Ok(Some(issued))
}

/// 用刚安装并推送的证书 PEM 更新 live 摘要。
///
/// 调用时仍持有 `CertLock`，`issued.cert_pem` 就是写入磁盘并构建 watch 配置的
/// 同一份材料；摘要解析失败只 WARN，文件 watcher 下个周期仍会补上。
fn sync_live_from_pem(live: &RwLock<CertStatus>, cert_pem: &str) {
    match CertStatus::from_pem(cert_pem) {
        Ok(status) => write_live(live, status),
        Err(err) => tracing::warn!(
            error = %err,
            "ACME 续期后计算 live 证书摘要失败；下个 watcher 周期会补齐"
        ),
    }
}

/// 已持锁的签发 + 安装 + 重建配置。
async fn issue_locked(cfg: &HubConfig) -> Result<(IssuedCert, Arc<ServerConfig>)> {
    // 客户端证书 CA 与 ACME 服务端证书无关，但安装后重建 mTLS 配置必须用到它；
    // 先校验可以避免「网络签发成功、写盘后才发现 ca.key 缺失」的半成品状态。
    tls::load_validated_ca(&cfg.data_dir).context(
        "客户端证书 CA 校验失败（ACME 模式的 agent mTLS 仍需要 ca.crt/ca.key）；         请先执行 `rustboard-hub init` 准备客户端 CA",
    )?;
    let issued = client::obtain_certificate(&cfg.data_dir, &cfg.tls).await?;
    let expected_sans = cfg.effective_server_names();
    // 写盘前先用 rustls 解析一遍 leaf + chain，确认证书链/私钥能被 TLS 栈接受。
    let _ = tls::server_config_from_paths(&issued.cert_pem, &issued.key_pem)
        .context("ACME 证书无法被 rustls 接受，拒绝写入")?;
    store::install_server_material_locked(
        &cfg.data_dir,
        &issued.cert_pem,
        &issued.key_pem,
        &expected_sans,
    )?;
    // 安装后用**刚写入的同一份证书 PEM** 重建启用 mTLS 的完整配置；失败说明
    // client CA 等前置条件异常。不能重新读盘，否则并发 rotate 可能换掉证书。
    let config = tls::server_config_with_cert_pem(&cfg.data_dir, &issued.cert_pem)
        .context("安装 ACME 证书后重建 TLS 配置失败（检查 ca.crt/ca.key）")?;
    record_success(cfg, &issued.cert_pem);
    Ok((issued, config))
}

fn record_success(cfg: &HubConfig, cert_pem: &str) {
    let mut state = match store::read_state(&cfg.data_dir) {
        Ok(Some(state)) => state,
        Ok(None) => store::AcmeState::from_config(&cfg.tls),
        Err(err) => {
            tracing::warn!(error = %format!("{err:#}"), "读取 ACME 状态失败，改用配置重建");
            store::AcmeState::from_config(&cfg.tls)
        }
    };
    state.directory = cfg.tls.acme_directory.clone();
    state.domains = cfg.tls.domains.clone();
    state.profile = super::effective_profile(&cfg.tls)
        .unwrap_or_default()
        .to_string();
    state.challenge = cfg.tls.challenge;
    state.last_issue_unix = Some(now_ms().div_euclid(1_000));
    state.next_attempt_unix = next_renewal_unix(cert_pem).ok();
    state.last_error = None;
    if let Err(err) = store::write_state(&cfg.data_dir, &state) {
        tracing::warn!(error = %format!("{err:#}"), "写入 ACME 状态失败（不影响证书）");
    }
}

fn record_failure(cfg: &HubConfig, err: &anyhow::Error, retry_after: Duration) {
    let mut state = match store::read_state(&cfg.data_dir) {
        Ok(Some(state)) => state,
        Ok(None) => store::AcmeState::from_config(&cfg.tls),
        Err(read_err) => {
            tracing::warn!(error = %format!("{read_err:#}"), "读取 ACME 状态失败，改用配置重建");
            store::AcmeState::from_config(&cfg.tls)
        }
    };
    state.directory = cfg.tls.acme_directory.clone();
    state.domains = cfg.tls.domains.clone();
    state.profile = super::effective_profile(&cfg.tls)
        .unwrap_or_default()
        .to_string();
    state.challenge = cfg.tls.challenge;
    state.last_error = Some(truncate_chars(&format!("{err:#}"), MAX_STATE_ERROR_CHARS));
    state.next_attempt_unix = Some(
        now_ms()
            .div_euclid(1_000)
            .saturating_add(retry_after.as_secs() as i64),
    );
    if let Err(write_err) = store::write_state(&cfg.data_dir, &state) {
        tracing::warn!(
            error = %format!("{write_err:#}"),
            "写入 ACME 失败状态失败（不影响旧证书）"
        );
    }
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
    use rcgen::{
        date_time_ymd, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };

    fn cert(not_before: time::OffsetDateTime, not_after: time::OffsetDateTime) -> String {
        let mut params = CertificateParams::new(vec!["board.example.com".to_string()]).unwrap();
        params.distinguished_name = DistinguishedName::new();
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = not_before;
        params.not_after = not_after;
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    /// 6 天短期证书：阈值 = min(2d, 48h) = 48h。
    #[test]
    fn needs_renewal_short_lived_uses_48h() {
        let not_before = date_time_ymd(2020, 1, 1);
        let not_after = date_time_ymd(2020, 1, 7);
        let pem = cert(not_before, not_after);
        let after_s = not_after.unix_timestamp();
        assert!(!needs_renewal(&pem, (after_s - 49 * 3600) * 1_000).unwrap());
        assert!(needs_renewal(&pem, (after_s - 47 * 3600) * 1_000).unwrap());
        // 已过期也必须续期。
        assert!(needs_renewal(&pem, after_s * 1_000).unwrap());
    }

    /// 90 天证书：lifetime/3 = 30d，但 D8 上限是 48h。
    #[test]
    fn needs_renewal_long_lived_caps_at_48h() {
        let not_before = date_time_ymd(2020, 1, 1);
        let not_after = date_time_ymd(2020, 3, 31);
        let pem = cert(not_before, not_after);
        let after_s = not_after.unix_timestamp();
        assert!(!needs_renewal(&pem, (after_s - 49 * 3600) * 1_000).unwrap());
        assert!(needs_renewal(&pem, (after_s - 47 * 3600) * 1_000).unwrap());
    }

    #[test]
    fn next_renewal_is_not_after_minus_threshold() {
        let not_before = date_time_ymd(2020, 1, 1);
        let not_after = date_time_ymd(2020, 1, 7);
        let pem = cert(not_before, not_after);
        assert_eq!(
            next_renewal_unix(&pem).unwrap(),
            not_after.unix_timestamp() - 48 * 3600
        );
    }

    /// #68：ACME 证书安装/推送后 live 立即使用刚签发的证书，不等 watcher。
    #[test]
    fn live_status_uses_just_installed_cert() {
        let old_pem = cert(date_time_ymd(2020, 1, 1), date_time_ymd(2020, 2, 1));
        let new_pem = cert(date_time_ymd(2020, 6, 1), date_time_ymd(2020, 9, 1));
        let old_status = CertStatus::from_pem(&old_pem).unwrap();
        let live = RwLock::new(old_status.clone());

        sync_live_from_pem(&live, &new_pem);
        let live_after = live.read().unwrap().clone();
        assert_eq!(
            live_after.fingerprint,
            tls::fingerprint_of_pem(&new_pem).unwrap(),
            "ACME 续期后 live 必须指向刚安装的证书"
        );
        assert_eq!(live_after.not_after, tls::not_after_unix(&new_pem).unwrap());
        assert_ne!(live_after.fingerprint, old_status.fingerprint);
    }

    #[test]
    fn backoff_sequence_matches_plan() {
        assert_eq!(backoff_delay(0), Duration::from_secs(60));
        assert_eq!(backoff_delay(1), Duration::from_secs(300));
        assert_eq!(backoff_delay(2), Duration::from_secs(900));
        assert_eq!(backoff_delay(3), Duration::from_secs(3600));
        assert_eq!(backoff_delay(4), Duration::from_secs(6 * 3600));
        // 超过上限后保持 6h，不会无限增长。
        assert_eq!(backoff_delay(99), Duration::from_secs(6 * 3600));
    }
}
