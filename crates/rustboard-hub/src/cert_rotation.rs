//! 服务端证书续签与启动自愈。
//!
//! 三个入口：
//! - [`renew_server_cert_files`]：**文件级**签发，只判断 + 校验 + 签发 + 原子写
//!   key/cert，全程不读、不重建现有 TLS 配置。因此即使磁盘上的 key/cert 已经不配套
//!   （上次续签在写盘中途被 kill），它也能把目录修复成一对可用的新材料。
//! - [`check_and_renew`]：自动续签。先按同一套规则成对备份，再调用文件级签发，
//!   最后重建 `tls::server_config` 自检并通过 `watch` 推给 accept 循环；
//!   自检失败回滚旧材料，且不推送新配置。
//! - [`load_or_repair_tls_config`]：hub 启动入口。先尝试加载，只有「服务端 key/cert
//!   配对损坏 / 缺失」才自愈；CA 材料有问题、服务端证书不可解析等一律直接报错，
//!   不写任何 server 文件（避免每次启动都换一张证书、指纹漂移）。
//!
//! 安全决策（第二轮评审 S1/S2）：
//! - 签发前校验 `ca.key` 与 `ca.crt` 配套、`server_names` 非空且逐条合法；
//! - 写盘前用 [`tls::validate_server_cert`] 自检新证书（CN / 有效期 / SAN 覆盖 /
//!   由当前 CA 签发），任何一项失败都不落盘；
//! - 重签前成对备份 crt(0644)+key(0600)，文件名带毫秒+PID+随机后缀，避免同秒覆盖，
//!   每类只保留最近 [`tls::BACKUP_KEEP`] 份；
//! - 私钥 0600、证书 0644，写入走 `fsutil::atomic_write`（随机临时名 + rename）；
//! - 日志只打指纹与到期时间，绝不打印私钥或证书内容。
//!
//! 关于检查周期：配置层要求 `cert_check_interval_secs ≥ 60`。方案文档里写的是
//! 「最小 1」，实现采用更严格的安全下限——秒级检查在证书未到期时只是无意义的
//! 磁盘读取，还会放大错误配置（有效期 ≤ 续签阈值）造成的重写频率。

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use rustboard_common::config::HubConfig;
use rustboard_common::util::now_ms;
use rustboard_common::{fsutil, tls};
use rustls::ServerConfig;
use tokio::sync::watch;

/// 续签后的 TLS 配置通过 watch 广播：每个新连接读一次最新值。
pub type TlsConfigSender = watch::Sender<Arc<ServerConfig>>;

/// 证书文件轮询周期：运行中 `rotate-cert` 后，新连接最迟 10s 生效。
pub const CERT_FILE_POLL_INTERVAL: Duration = Duration::from_secs(10);
/// 热加载失败告警的最小间隔，避免坏证书每 10s 刷一条日志。
const CERT_LOAD_WARN_INTERVAL: Duration = Duration::from_secs(60);
/// rotate-cert 锁文件的名称（位于证书目录）。
pub const CERT_LOCK_FILE: &str = ".rotate.lock";
/// 锁文件超过该时长视为陈旧（持锁进程可能已崩溃）。
const STALE_LOCK_AGE: Duration = Duration::from_secs(10 * 60);

/// 监听器当前实际使用的服务端证书摘要（只含公开信息）。
///
/// `system_info` 用它区分「磁盘上的证书」与「TLS 监听器实际在用的证书」；
/// 热加载成功后更新，失败时保留旧值。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CertStatus {
    pub fingerprint: String,
    /// Unix 秒。
    pub not_after: i64,
    pub days_left: i64,
}

impl CertStatus {
    /// 尚未加载任何证书时的占位值（只用于测试 / 初始化前的状态）。
    #[cfg(test)]
    pub fn unknown() -> Self {
        Self {
            fingerprint: String::new(),
            not_after: 0,
            days_left: 0,
        }
    }

    /// 从证书 PEM 计算公开摘要。
    pub fn from_pem(pem: &str) -> Result<Self> {
        Ok(Self {
            fingerprint: tls::fingerprint_of_pem(pem)?,
            not_after: tls::not_after_unix(pem)?,
            days_left: tls::days_left(pem, now_ms())?,
        })
    }

    /// 按当前时间重新计算剩余天数。
    ///
    /// `live` 只在证书变化时更新，若直接复用加载时的 `days_left`，长期运行的
    /// hub 会在 `/api/v1/system` 里展示过期天数（甚至证书已过期仍显示旧值）。
    pub fn with_current_days_left(mut self, now_ms: i64) -> Self {
        const DAY_MS: i64 = 24 * 60 * 60 * 1000;
        let remaining_ms = self.not_after.saturating_mul(1_000).saturating_sub(now_ms);
        self.days_left = (remaining_ms + DAY_MS - 1).div_euclid(DAY_MS);
        self
    }
}

/// 读取磁盘上服务端证书的公开摘要。
pub fn read_disk_cert_status(cfg: &HubConfig) -> Result<CertStatus> {
    let path = tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE);
    let pem = std::fs::read_to_string(&path)
        .with_context(|| format!("读取服务端证书失败: {}", path.display()))?;
    CertStatus::from_pem(&pem)
}

fn read_live(live: &RwLock<CertStatus>) -> CertStatus {
    live.read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn write_live(live: &RwLock<CertStatus>, status: CertStatus) {
    *live
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = status;
}

/// 一次文件级续签的结果。
///
/// `old_*` 字段只用于「重建 TLS 配置失败」时回滚，不实现 Debug、也不进日志。
pub struct RenewedServerCert {
    pub old_fingerprint: String,
    pub fingerprint: String,
    /// 新证书到期时间（Unix 秒）。
    pub not_after: i64,
    /// 新证书有效期（天）。
    pub validity_days: u32,
    /// 本次生成的成对备份路径（crt 在前，key 在后；无旧材料时为空）。
    pub backup_paths: Vec<PathBuf>,
    /// 续签前的证书；`None` 表示原来没有服务端证书（补签场景）。
    old_cert_pem: Option<String>,
    old_key_pem: Option<String>,
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("删除 {} 失败", path.display())),
    }
}

impl RenewedServerCert {
    /// 回滚到续签前磁盘上的状态。
    ///
    /// 返回 `Ok(false)` 表示没有可回滚的旧材料（理论上只在新旧状态无法区分时出现）。
    /// - 旧 crt+key 都在：成对恢复；
    /// - 旧证书在、旧私钥缺失：恢复旧证书并删除本次写出的新私钥；
    /// - 旧证书缺失：删除本次写出的 crt/key，回到「没有服务端证书」的状态。
    fn rollback(&self, cfg: &HubConfig) -> Result<bool> {
        let dir = tls::cert_dir(&cfg.data_dir);
        let cert_path = dir.join(tls::SERVER_CERT_FILE);
        let key_path = dir.join(tls::SERVER_KEY_FILE);

        match (&self.old_cert_pem, &self.old_key_pem) {
            (Some(old_cert), Some(old_key)) => {
                fsutil::atomic_write(&key_path, old_key.as_bytes(), 0o600)
                    .context("回滚服务端私钥失败")?;
                fsutil::atomic_write(&cert_path, old_cert.as_bytes(), 0o644)
                    .context("回滚服务端证书失败")?;
            }
            (Some(old_cert), None) => {
                fsutil::atomic_write(&cert_path, old_cert.as_bytes(), 0o644)
                    .context("回滚服务端证书失败")?;
                remove_file_if_exists(&key_path)?;
            }
            (None, old_key) => {
                if let Some(old_key) = old_key {
                    fsutil::atomic_write(&key_path, old_key.as_bytes(), 0o600)
                        .context("回滚服务端私钥失败")?;
                } else {
                    remove_file_if_exists(&key_path)?;
                }
                remove_file_if_exists(&cert_path)?;
            }
        }
        Ok(true)
    }
}

/// 启动后台续签任务。
///
/// 任务本身不会 panic：单次失败只记日志，下个周期继续尝试（证书不会因为一次
/// 写盘失败就永远不续签）。
///
/// `live` 参数保留仅为兼容调用方；续签成功后**不在这里**更新 live，
/// 而是由文件 watcher 在校验并热加载成功后统一更新。否则自动续签读到的
/// 磁盘摘要可能覆盖并发 CLI `rotate-cert` 刚写入的新证书，导致 watcher
/// 误判「已加载」而跳过真正的热加载。`/system` 最多滞后一个轮询周期（≤10s）。
pub fn spawn_server_renewal(
    cfg: Arc<HubConfig>,
    tx: TlsConfigSender,
    _live: Arc<RwLock<CertStatus>>,
) {
    tokio::spawn(async move {
        // 配置层要求 ≥ 60 秒；这里再 max(1) 只是防御「手工改配置绕过校验」导致的
        // 0 周期忙循环（见文件头关于检查周期的说明）。
        let period = Duration::from_secs(cfg.cert_check_interval_secs.max(1));
        // tokio 的 interval 第一次 tick 立即完成：启动时先检查一次，
        // 「启动前就已经进入续签窗口」的证书会马上被换掉。
        let mut ticker = tokio::time::interval(period);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;

            let check_cfg = cfg.clone();
            let check_tx = tx.clone();
            // 文件读写与签名都是阻塞操作，放到 blocking 线程池，避免卡住 reactor。
            let result = tokio::task::spawn_blocking(move || {
                check_and_renew(&check_cfg, &check_tx, false, None)
            })
            .await;

            match result {
                Ok(Ok(Some(fingerprint))) => {
                    tracing::info!(fingerprint, "服务端证书续签完成，新连接已使用新证书");
                }
                Ok(Ok(None)) => {}
                Ok(Err(err)) => tracing::warn!(error = %err, "服务端证书续签失败，下个周期重试"),
                Err(err) => tracing::warn!(error = %err, "服务端证书续签任务失败，下个周期重试"),
            }
        }
    });
}

/// 每 10s 检查磁盘证书；指纹变化且校验通过时热替换监听器的 TLS 配置。
///
/// 校验顺序：证书/私钥配套 → CA 链与 SAN → rustls 可构建。任何一步失败都
/// **保留旧配置**并告警（同一错误每分钟最多一条）；坏证书绝不会替换 live。
pub fn spawn_cert_file_watcher(
    cfg: Arc<HubConfig>,
    tx: TlsConfigSender,
    live: Arc<RwLock<CertStatus>>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(CERT_FILE_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // 第一次 tick 立即完成：启动路径刚加载并校验过证书，直接跳过。
        ticker.tick().await;

        let mut last_warn: Option<Instant> = None;
        loop {
            ticker.tick().await;

            let check_cfg = cfg.clone();
            let check_tx = tx.clone();
            let check_live = live.clone();
            let result = tokio::task::spawn_blocking(move || {
                reload_server_config_if_changed(&check_cfg, &check_tx, &check_live)
            })
            .await;

            match result {
                Ok(Ok(true)) => {
                    tracing::info!("检测到服务端证书文件变化，已热加载到监听器（无需重启）");
                }
                Ok(Ok(false)) => {}
                Ok(Err(err)) => {
                    let now = Instant::now();
                    let should_warn = match last_warn {
                        Some(last) => now.duration_since(last) >= CERT_LOAD_WARN_INTERVAL,
                        None => true,
                    };
                    if should_warn {
                        last_warn = Some(now);
                        tracing::warn!(
                            error = %format!("{err:#}"),
                            "服务端证书热加载失败，保留旧配置（每分钟最多告警一次）"
                        );
                    }
                }
                Err(err) => {
                    let now = Instant::now();
                    let should_warn = match last_warn {
                        Some(last) => now.duration_since(last) >= CERT_LOAD_WARN_INTERVAL,
                        None => true,
                    };
                    if should_warn {
                        last_warn = Some(now);
                        tracing::warn!(error = %err, "证书文件轮询任务失败，下个周期重试");
                    }
                }
            }
        }
    });
}

/// 读磁盘证书；校验通过且指纹与 live 不同才替换 watch 配置并更新 live。
///
/// 返回 `Ok(true)` 表示本次发生了热替换，`Ok(false)` 表示证书没变（或读取期间
/// 又被 rotate 改了一次，留到下个周期处理）。
pub fn reload_server_config_if_changed(
    cfg: &HubConfig,
    tx: &TlsConfigSender,
    live: &RwLock<CertStatus>,
) -> Result<bool> {
    let dir = tls::cert_dir(&cfg.data_dir);
    let cert_path = dir.join(tls::SERVER_CERT_FILE);
    let key_path = dir.join(tls::SERVER_KEY_FILE);
    let ca_path = dir.join(tls::CA_CERT_FILE);

    let cert_pem = std::fs::read_to_string(&cert_path)
        .with_context(|| format!("读取服务端证书失败: {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(&key_path)
        .with_context(|| format!("读取服务端私钥失败: {}", key_path.display()))?;
    let ca_pem = std::fs::read_to_string(&ca_path)
        .with_context(|| format!("读取 CA 证书失败: {}", ca_path.display()))?;

    // 1) key/cert 必须配套：rotate 先写 key 后写 cert，中间状态不能热加载。
    if !tls::cert_matches_key(&cert_pem, &key_pem).context("校验证书与私钥配套失败")? {
        bail!("服务端证书与私钥不配套，拒绝热加载");
    }
    // 2) CA 链、CN、有效期与 SAN 覆盖。
    tls::validate_existing_server_cert(&cert_pem, &ca_pem, &cfg.server_names, now_ms())
        .context("热加载证书校验失败（CA 链 / SAN / 有效期）")?;
    let status = CertStatus::from_pem(&cert_pem)?;

    // 3) 指纹没变：无需替换（避免每 10s 重建 rustls 配置）。
    if read_live(live).fingerprint == status.fingerprint {
        return Ok(false);
    }

    // 4) 用同一批文件构建 rustls 配置；随后复核指纹，防止读写之间又被 rotate 覆盖。
    let server_config = tls::server_config(&cfg.data_dir).context("构建热加载 TLS 配置失败")?;
    let confirmed = CertStatus::from_pem(&std::fs::read_to_string(&cert_path)?)?;
    if confirmed.fingerprint != status.fingerprint {
        tracing::debug!("证书在热加载过程中再次变化，本周期跳过，下个周期重试");
        return Ok(false);
    }

    tx.send_replace(server_config);
    write_live(live, confirmed);
    tracing::info!(
        fingerprint = %status.fingerprint,
        not_after = %tls::format_unix_utc(status.not_after),
        days_left = status.days_left,
        "监听器已切换到磁盘上的新证书"
    );
    Ok(true)
}

/// rotate-cert 的进程间互斥锁：`<证书目录>/.rotate.lock`，`create_new` + 0600。
///
/// RAII：正常返回、出错返回、panic 展开时都会在 `Drop` 里删除锁文件。
/// 持锁进程被 kill -9 时会留下锁文件，超过 [`STALE_LOCK_AGE`] 视为陈旧并自动清理。
#[derive(Debug)]
pub struct CertLock {
    path: PathBuf,
}

impl CertLock {
    /// 在证书目录获取锁；已有未过期的锁时返回错误。
    pub fn acquire(cert_dir: &Path) -> Result<Self> {
        fsutil::ensure_dir(cert_dir, 0o700)
            .with_context(|| format!("创建证书目录失败: {}", cert_dir.display()))?;
        let path = cert_dir.join(CERT_LOCK_FILE);
        match create_lock_file(&path) {
            Ok(()) => Ok(Self { path }),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if is_stale_lock(&path) {
                    tracing::warn!(
                        path = %path.display(),
                        "检测到超过 10 分钟的陈旧 rotate-cert 锁，清理后重试"
                    );
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(remove_err) if remove_err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(remove_err) => {
                            return Err(remove_err)
                                .with_context(|| format!("清理陈旧锁文件失败: {}", path.display()))
                        }
                    }
                    create_lock_file(&path).with_context(|| {
                        format!(
                            "另一个 rotate-cert 正在运行（锁文件 {}）；请等待其结束",
                            path.display()
                        )
                    })?;
                    Ok(Self { path })
                } else {
                    bail!(
                        "另一个 rotate-cert 正在运行（锁文件 {}）；\
                         若确认没有进程在运行，可等待 10 分钟后陈旧锁自动恢复，或手动删除该文件",
                        path.display()
                    )
                }
            }
            Err(err) => {
                Err(err).with_context(|| format!("创建 rotate-cert 锁文件失败: {}", path.display()))
            }
        }
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for CertLock {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => tracing::warn!(
                path = %self.path.display(),
                error = %err,
                "删除 rotate-cert 锁文件失败，请手工清理"
            ),
        }
    }
}

/// `create_new` 创建锁文件并写入 pid / 时间；已存在时返回 `AlreadyExists`。
fn create_lock_file(path: &Path) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 从创建的第一刻起就是 0600（不受 umask 影响）。
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    writeln!(file, "pid={} time_ms={}", std::process::id(), now_ms())?;
    Ok(())
}

/// 锁文件是否已超过陈旧阈值（mtime 在未来或读不到时按不陈旧处理）。
fn is_stale_lock(path: &Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    modified
        .elapsed()
        .map(|age| age >= STALE_LOCK_AGE)
        .unwrap_or(false)
}

/// 是否现在需要续签；返回 `Some(新证书有效期天数)` 表示需要续签。
///
/// 判断顺序与旧实现一致：阈值 → 配置自洽性护栏。`force` 跳过两者。
fn plan_renewal(
    cfg: &HubConfig,
    force: bool,
    override_days: Option<u32>,
    old_cert_pem: &str,
) -> Result<Option<u32>> {
    let days_left = tls::days_left(old_cert_pem, now_ms())?;
    let days = override_days.unwrap_or(cfg.server_cert_validity_days);

    if !force && days_left > i64::from(cfg.renew_before_days) {
        tracing::debug!(
            days_left,
            threshold = cfg.renew_before_days,
            "服务端证书剩余寿命充足，跳过续签"
        );
        return Ok(None);
    }

    // 新证书的有效期本身不大于续签阈值时，续签完「立刻又到期」：
    // 既不解决问题，还会每个检查周期重写一次磁盘、并让指纹不断变化。
    // 显式传 override_days 或 force 时不限制，交给签发时的天数校验给出明确错误。
    if !force && override_days.is_none() && i64::from(days) <= i64::from(cfg.renew_before_days) {
        tracing::warn!(
            validity_days = days,
            renew_before_days = cfg.renew_before_days,
            "证书有效期不大于续签阈值，自动续签无法生效；请调整 server_cert_validity_days / renew_before_days"
        );
        return Ok(None);
    }
    Ok(Some(days))
}

/// 文件级续签：判断 → 校验 → 签发 → 自检 → 原子写 key/cert，不重建 TLS 配置。
///
/// - `force`：忽略剩余寿命阈值立即重签；也允许在 `server.crt` 缺失时直接补签；
/// - `override_days`：覆盖本次新证书的有效期（天），`None` 用配置值。
///
/// 返回 `Ok(None)` 表示未到续签时机，且磁盘没有任何写入。
///
/// 所有失败都发生在写盘之前（CA 不配套、SAN 非法、新证书自检不通过等），
/// 因此调用方可以放心把「失败」当成「磁盘未改动」处理。
pub fn renew_server_cert_files(
    cfg: &HubConfig,
    force: bool,
    override_days: Option<u32>,
) -> Result<Option<RenewedServerCert>> {
    let dir = tls::cert_dir(&cfg.data_dir);
    let cert_path = dir.join(tls::SERVER_CERT_FILE);
    let key_path = dir.join(tls::SERVER_KEY_FILE);

    // 1) 配置里的 SAN 先校验：空列表/非法条目直接失败，不碰任何文件。
    tls::parse_server_sans(&cfg.server_names)
        .context("server_names 校验失败，拒绝签发服务端证书")?;

    // 2) 旧证书（可能缺失）：决定是否续签，并用于回滚与旧指纹。
    let old_cert_pem = match std::fs::read_to_string(&cert_path) {
        Ok(pem) => Some(pem),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && force => {
            tracing::warn!(
                path = %cert_path.display(),
                "服务端证书缺失，直接补签一对新的 key/cert"
            );
            None
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "读取服务端证书失败: {}（先执行 rustboard-hub init）",
                    cert_path.display()
                )
            })
        }
    };
    let old_fingerprint = match &old_cert_pem {
        Some(pem) => tls::fingerprint_of_pem(pem)?,
        None => "(无旧证书)".to_string(),
    };
    let days = match &old_cert_pem {
        Some(pem) => match plan_renewal(cfg, force, override_days, pem)? {
            Some(days) => days,
            None => return Ok(None),
        },
        // 证书缺失时只能补签；有效期仍走签发校验。
        None => override_days.unwrap_or(cfg.server_cert_validity_days),
    };

    // 升级路径：旧安装的服务端私钥可能是 0644，读取前收紧。
    if key_path.exists() {
        fsutil::harden(&key_path, 0o600).context("收紧服务端私钥权限失败")?;
    }

    // 3) CA 材料必须存在、可解析且配套；不配套时签出的证书链无效，
    //    所有 CA 信任 agent 下次握手都会失败，必须在写盘前拦住。
    let ca = tls::load_validated_ca_at(&dir).context("CA 材料校验失败，拒绝签发服务端证书")?;

    // 旧 key 只用于回滚：读不到（例如上次崩溃只留下 cert）不是失败理由，
    // 反而正是需要修复的场景，降级为告警后继续签发。
    let old_key_pem = match std::fs::read_to_string(&key_path) {
        Ok(pem) => Some(pem),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %key_path.display(),
                "服务端私钥缺失，续签后无法回滚旧材料（本次会写出一对新的 key/cert）"
            );
            None
        }
        Err(err) => {
            return Err(err).with_context(|| format!("读取服务端私钥失败: {}", key_path.display()))
        }
    };

    let (cert_pem, key_pem) = tls::issue_server_cert(&ca.key_pem, &cfg.server_names, days)
        .context("用 CA 重新签发服务端证书失败")?;

    // 4) 写盘前自检新证书：CN、有效期、SAN 覆盖、由当前 CA 签发。
    tls::validate_server_cert(&cert_pem, &ca.cert_pem, &cfg.server_names, now_ms())
        .context("新签发的服务端证书自检失败，未写入磁盘")?;

    let new_fingerprint = tls::fingerprint_of_pem(&cert_pem)?;
    let not_after = tls::not_after_unix(&cert_pem)?;

    // 5) 全部校验通过后才备份并写盘（失败路径不产生无意义的 bak）。
    let backup_paths = tls::backup_server_material(&cfg.data_dir)
        .context("重签前备份服务端证书材料失败，已放弃写入")?;

    // 先写 key 再写 cert：进程内失败可以回滚，硬崩溃留下的不配套由启动自愈兜底。
    fsutil::atomic_write(&key_path, key_pem.as_bytes(), 0o600).context("写入服务端私钥失败")?;
    if let Err(write_err) = fsutil::atomic_write(&cert_path, cert_pem.as_bytes(), 0o644) {
        // cert 没变，把 key 恢复成旧的就能回到原来的一对。
        if let Some(old_key) = old_key_pem.as_deref() {
            if let Err(rollback_err) = fsutil::atomic_write(&key_path, old_key.as_bytes(), 0o600) {
                tracing::error!(error = %rollback_err, "写入证书失败后回滚私钥也失败");
            }
        }
        return Err(anyhow::Error::new(write_err).context("写入服务端证书失败"));
    }

    Ok(Some(RenewedServerCert {
        old_fingerprint,
        fingerprint: new_fingerprint,
        not_after,
        validity_days: days,
        backup_paths,
        old_cert_pem,
        old_key_pem,
    }))
}

/// 重建服务端 TLS 配置。
///
/// 生产路径就是 `tls::server_config`；测试可对指定 data_dir 注入一次失败，
/// 用来覆盖「新材料已写盘、重建却失败 → 必须回滚」的分支（没有别的故障注入点）。
fn rebuild_server_config(cfg: &HubConfig) -> Result<Arc<ServerConfig>> {
    #[cfg(test)]
    {
        let mut fail_for = FAIL_REBUILD_FOR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if fail_for.as_deref() == Some(cfg.data_dir.as_path()) {
            *fail_for = None;
            anyhow::bail!("测试注入：重建 TLS 配置失败");
        }
    }
    tls::server_config(&cfg.data_dir)
}

#[cfg(test)]
static FAIL_REBUILD_FOR: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

/// 检查并在需要时重签服务端证书；返回 `Some(新指纹)` 表示实际发生了续签。
///
/// 流程：获取进程间文件锁 → 判断是否需要续签 → 成对备份 → 文件级签发
/// （含全部 S1 校验）→ 重建配置自检 → 推送 watch。重建失败会回滚旧材料并
/// 返回错误，**不会**推送新配置。
///
/// 锁被 CLI `rotate-cert` 占用时返回可读错误且不写任何文件，由续签任务下个
/// 周期重试。CLI 自己已持锁并直接调用 [`renew_server_cert_files`]，不会走到
/// 这里，因此不存在嵌套获取锁的死锁。
pub fn check_and_renew(
    cfg: &HubConfig,
    tx: &TlsConfigSender,
    force: bool,
    override_days: Option<u32>,
) -> Result<Option<String>> {
    let cert_dir = tls::cert_dir(&cfg.data_dir);
    // KI-11（严重项）：自动续签与 CLI rotate-cert 必须互斥，否则可能交错
    // 写 key/cert，得到一对不配套的材料。
    let _lock = CertLock::acquire(&cert_dir)
        .context("获取证书续签锁失败（另一个 rotate-cert 正在运行），本次不写盘，下个周期重试")?;

    // 先判断是否真要续签，避免每次都产生无意义备份。
    let cert_path = cert_dir.join(tls::SERVER_CERT_FILE);
    let old_cert_pem = std::fs::read_to_string(&cert_path).with_context(|| {
        format!(
            "读取服务端证书失败: {}（先执行 rustboard-hub init）",
            cert_path.display()
        )
    })?;
    if plan_renewal(cfg, force, override_days, &old_cert_pem)?.is_none() {
        return Ok(None);
    }

    // 备份在文件级函数内部、全部校验通过之后才发生（失败路径不新增 bak）。
    let Some(renewed) = renew_server_cert_files(cfg, force, override_days)? else {
        // plan 与签发之间条件发生变化（当前实现下不会发生，保守处理）。
        return Ok(None);
    };

    let server_config = match rebuild_server_config(cfg) {
        Ok(config) => config,
        Err(err) => {
            return Err(match renewed.rollback(cfg) {
                Ok(true) => err.context("重建 TLS 配置失败，已回滚旧证书与私钥"),
                Ok(false) => {
                    err.context("重建 TLS 配置失败；旧私钥缺失无法回滚，保留新签发的证书对")
                }
                Err(rollback_err) => err.context(format!(
                    "重建 TLS 配置失败，且回滚失败（需要人工检查证书目录）: {rollback_err}"
                )),
            });
        }
    };

    // 只有自检通过才推送；订阅端（accept 循环）下次取用时立即生效。
    tx.send_replace(server_config);
    tracing::info!(
        old_fingerprint = %renewed.old_fingerprint,
        new_fingerprint = %renewed.fingerprint,
        not_after = %tls::format_unix_utc(renewed.not_after),
        days = renewed.validity_days,
        "服务端证书已续签"
    );
    Ok(Some(renewed.fingerprint))
}

/// 启动时加载 TLS 配置；**只**对「服务端 key/cert 配对损坏或缺失」做自愈。
/// 启动/init 可用的恢复指引：恢复备份优先，重签用 rotate-cert，重建 CA 必须手动清材料。
const TLS_RECOVERY_HINT: &str = "请从备份恢复匹配的 CA 与服务端材料；     若只是证书链过期/失配，可执行 `rustboard-hub rotate-cert --force` 用当前 CA 重签（CA 未变时 agent 会自动重连）；     若要重建 CA，需先手动移除 ca.crt+ca.key+旧 server 材料（ca.crt / ca.key / server.crt / server.key），     再执行 `rustboard-hub init --force`（会重建 CA、重置端口与配置）；     若 CA 也被整体替换，所有 agent 必须重新纳管（旧 ca.crt/客户端证书属于旧 CA，会 mTLS 失败）";

pub fn load_or_repair_tls_config(cfg: &HubConfig) -> Result<Arc<ServerConfig>> {
    // S1-1：任何启动路径都先校验 CA 材料与 server_names，再尝试加载。
    // `server_config` 只把 ca.crt 当信任根，并不会发现 ca.key 缺失/不配套；
    // 所以这两个检查必须在进入 repair 分支之前无条件执行。
    let ca = tls::load_validated_ca(&cfg.data_dir).context("CA 材料校验失败，拒绝启动")?;
    tls::parse_server_sans(&cfg.server_names).context("server_names 校验失败，拒绝启动")?;

    // 第五轮 S1：现存 server.crt 必须由当前 CA 签发、且 SAN 覆盖 server_names。
    // 只校验 CA 自身不够——把另一套 CA 的 ca.crt+ca.key 覆盖进来时，
    // server_config 仍能构建成功（它不校验签发者），hub 会带着无效链启动。
    let cert_path = tls::cert_dir(&cfg.data_dir).join(tls::SERVER_CERT_FILE);
    if cert_path.exists() {
        let server_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("读取服务端证书失败: {}", cert_path.display()))?;
        tls::validate_existing_server_cert(&server_pem, &ca.cert_pem, &cfg.server_names, now_ms())
            .with_context(|| {
                format!("现存服务端证书与当前 CA/SAN 不一致，拒绝启动；{TLS_RECOVERY_HINT}")
            })?;
    }

    match tls::server_config(&cfg.data_dir) {
        Ok(config) => Ok(config),
        Err(original) => repair_tls_material(cfg, original),
    }
}

/// 对不可自愈的 TLS 故障给出可执行错误（不回显任何密钥材料）。
fn unrepairable(original: anyhow::Error, hint: &str) -> anyhow::Error {
    original.context(format!(
        "TLS 材料异常，无法自动修复：不属于可自愈的「服务端 key/cert 配对」问题（{hint}）；\
         {TLS_RECOVERY_HINT}"
    ))
}

fn repair_tls_material(cfg: &HubConfig, original: anyhow::Error) -> Result<Arc<ServerConfig>> {
    let dir = tls::cert_dir(&cfg.data_dir);
    // KI-11：启动自愈同样会写服务端材料，必须与 CLI rotate-cert 互斥；
    // 锁被占用时宁可拒绝启动，也不能和运维进程交错写 key/cert。
    let _lock = CertLock::acquire(&dir).context(
        "获取证书修复锁失败（另一个 rotate-cert 正在运行），拒绝启动以免写坏材料；请等待其结束后重试",
    )?;
    let cert_path = dir.join(tls::SERVER_CERT_FILE);
    let key_path = dir.join(tls::SERVER_KEY_FILE);

    // CA 材料与 server_names 已由 `load_or_repair_tls_config` 校验，这里只分类
    // 服务端材料：只有「配对损坏 / 缺失」才允许自愈。
    let repair_reason = if !cert_path.exists() {
        Some("服务端证书缺失")
    } else {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("读取服务端证书失败: {}", cert_path.display()))?;
        tls::cert_summary(&cert_pem).map_err(|err| {
            unrepairable(
                err,
                &format!("服务端证书无法解析（{}）", cert_path.display()),
            )
        })?;
        if !key_path.exists() {
            Some("服务端私钥缺失")
        } else {
            let key_pem = std::fs::read_to_string(&key_path)
                .with_context(|| format!("读取服务端私钥失败: {}", key_path.display()))?;
            match tls::cert_matches_key(&cert_pem, &key_pem) {
                Ok(true) => None,
                Ok(false) => Some("服务端证书与私钥不配套"),
                Err(err) => {
                    tracing::warn!(error = %err, "服务端私钥不可解析，按配对损坏处理");
                    Some("服务端私钥不可解析")
                }
            }
        }
    };

    let Some(repair_reason) = repair_reason else {
        return Err(unrepairable(
            original,
            "服务端证书与私钥配对正常（检查 CA 证书、文件权限与磁盘）",
        ));
    };

    tracing::warn!(
        error = %original,
        reason = repair_reason,
        "检测到可自愈的 TLS 材料问题（可能是上次续签写盘中途被中断），将用 CA 重签服务端证书"
    );

    // 3) 文件级签发内部会在全部校验通过后成对备份、再写盘；失败路径不产生 bak。
    let renewed = renew_server_cert_files(cfg, true, None)
        .context("自动修复服务端证书失败（失败发生在写盘之前，磁盘材料未改动）")?;
    let Some(renewed) = renewed else {
        return Err(original.context("自动修复没有产生新证书（内部状态异常）"));
    };

    // 4) 重建配置；失败必须回到旧材料。
    let config = match rebuild_server_config(cfg) {
        Ok(config) => config,
        Err(err) => {
            return Err(match renewed.rollback(cfg) {
                Ok(true) => err.context("自动修复后重建 TLS 配置失败，已回滚到修复前的材料"),
                Ok(false) => err.context("自动修复后重建 TLS 配置失败，且没有可回滚的旧材料"),
                Err(rollback_err) => err.context(format!(
                    "自动修复后重建 TLS 配置失败，且回滚失败（需要人工检查证书目录）: {rollback_err}"
                )),
            });
        }
    };

    tracing::error!(
        old_fingerprint = %renewed.old_fingerprint,
        new_fingerprint = %renewed.fingerprint,
        "已自动重签服务端证书完成自愈；服务端指纹已变化，仍使用指纹钉扎的旧版 agent \
         需要升级到 v0.2 或重新纳管"
    );
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    use rustboard_common::tls::{CA_CERT_FILE, CA_KEY_FILE, SERVER_CERT_FILE, SERVER_KEY_FILE};

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rb-rotation-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn test_config(dir: &Path, server_days: u32, renew_before_days: u32) -> HubConfig {
        HubConfig {
            data_dir: dir.to_path_buf(),
            database: format!("sqlite://{}", dir.join("rustboard.db").display()),
            self_monitor: false,
            admin_token: "test-token".into(),
            server_names: vec!["localhost".to_string()],
            server_cert_validity_days: server_days,
            renew_before_days,
            cert_check_interval_secs: 60,
            ..HubConfig::default()
        }
    }

    /// 准备材料并构造一个与 run() 相同的 watch 通道。
    fn prepare(
        dir: &Path,
        policy: tls::CertPolicy,
    ) -> (TlsConfigSender, watch::Receiver<Arc<ServerConfig>>) {
        tls::ensure_hub_material(dir, &["localhost".to_string()], policy).unwrap();
        watch::channel(tls::server_config(dir).unwrap())
    }

    fn read(dir: &Path, name: &str) -> String {
        std::fs::read_to_string(tls::cert_dir(dir).join(name)).unwrap()
    }

    fn write(dir: &Path, name: &str, data: &[u8]) {
        fsutil::atomic_write(&tls::cert_dir(dir).join(name), data, 0o600).unwrap();
    }

    /// 用另一套 hub 材料里的私钥覆盖 `server.key`，模拟续签中断留下的不配套状态。
    fn break_key_pair(dir: &Path) {
        let other = temp_dir("other-key");
        tls::ensure_hub_material(
            &other,
            &["localhost".to_string()],
            tls::CertPolicy::default(),
        )
        .unwrap();
        let other_key = read(&other, SERVER_KEY_FILE);
        write(dir, SERVER_KEY_FILE, other_key.as_bytes());
        let _ = std::fs::remove_dir_all(&other);
    }

    /// 用另一套 CA 私钥覆盖 `ca.key`，模拟备份拷错导致的 CA 不配套。
    fn break_ca_pair(dir: &Path) {
        let other = temp_dir("other-ca-key");
        tls::ensure_hub_material(
            &other,
            &["localhost".to_string()],
            tls::CertPolicy::default(),
        )
        .unwrap();
        let other_key = read(&other, CA_KEY_FILE);
        write(dir, CA_KEY_FILE, other_key.as_bytes());
        let _ = std::fs::remove_dir_all(&other);
    }

    fn server_fingerprint(dir: &Path) -> String {
        tls::fingerprint_of_pem(&read(dir, SERVER_CERT_FILE)).unwrap()
    }

    fn managed_backups(dir: &Path, base: &str) -> Vec<String> {
        std::fs::read_dir(tls::cert_dir(dir))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| tls::is_managed_backup(name, base))
            .collect()
    }

    /// A3：剩余寿命高于阈值时不动作——不写盘、不备份、不推送。
    #[test]
    fn does_not_renew_before_threshold() {
        let dir = temp_dir("not-due");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        let (tx, rx) = prepare(&dir, policy);
        let cfg = test_config(&dir, 365, 30);
        let before = server_fingerprint(&dir);

        assert!(check_and_renew(&cfg, &tx, false, None).unwrap().is_none());
        assert_eq!(server_fingerprint(&dir), before, "未到期不得覆盖证书");
        assert!(!rx.has_changed().unwrap(), "未到期不得推送新配置");
        assert!(
            managed_backups(&dir, SERVER_CERT_FILE).is_empty(),
            "未到期不应产生备份"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A3：force 立即重签——指纹变化、watch 收到新配置、权限不退化。
    #[test]
    fn force_rotates_cert_and_pushes_new_config() {
        let dir = temp_dir("force");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        let (tx, rx) = prepare(&dir, policy);
        let cfg = test_config(&dir, 365, 30);
        let old_fingerprint = server_fingerprint(&dir);

        let new_fingerprint = check_and_renew(&cfg, &tx, true, Some(10))
            .unwrap()
            .expect("force 必须重签");
        assert_ne!(new_fingerprint, old_fingerprint);

        let cert_pem = read(&dir, SERVER_CERT_FILE);
        assert_eq!(
            tls::fingerprint_of_pem(&cert_pem).unwrap(),
            new_fingerprint,
            "返回的指纹必须与磁盘一致"
        );
        // 新证书按 override_days(10) 签发。
        assert_eq!(tls::days_left(&cert_pem, now_ms()).unwrap(), 10);
        assert!(rx.has_changed().unwrap(), "watch 必须收到新配置");

        // 续签后私钥 0600 / 证书 0644（A8）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |name: &str| {
                std::fs::metadata(tls::cert_dir(&dir).join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(SERVER_KEY_FILE), 0o600);
            assert_eq!(mode(SERVER_CERT_FILE), 0o644);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A3：现有证书只有 1 天寿命（进入 30 天阈值窗口）时自动续签为配置的 365 天。
    #[test]
    fn renews_when_within_threshold() {
        let dir = temp_dir("due");
        // 已有证书是 1 天签出来的，配置要求新证书 365 天。
        let policy = tls::CertPolicy {
            server_days: 1,
            ..Default::default()
        };
        let (tx, rx) = prepare(&dir, policy);
        let cfg = test_config(&dir, 365, 30);
        let old_fingerprint = server_fingerprint(&dir);

        let new_fingerprint = check_and_renew(&cfg, &tx, false, None)
            .unwrap()
            .expect("进入续签窗口必须自动重签");
        assert_ne!(new_fingerprint, old_fingerprint);
        assert!(rx.has_changed().unwrap());
        // 新证书按配置的 365 天签发，且私钥与证书是配套的（自检通过才会返回）。
        let cert_pem = read(&dir, SERVER_CERT_FILE);
        assert_eq!(tls::days_left(&cert_pem, now_ms()).unwrap(), 365);
        assert!(tls::server_config(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A3：有效期本身就不大于阈值时，自动续签只会造成「每周期重写一次磁盘」，
    /// 必须跳过并告警；`force` 不受限制。
    #[test]
    fn skip_auto_renewal_when_validity_is_not_longer_than_threshold() {
        let dir = temp_dir("misconfig");
        let policy = tls::CertPolicy {
            server_days: 1,
            ..Default::default()
        };
        let (tx, rx) = prepare(&dir, policy);
        let cfg = test_config(&dir, 1, 30);
        let before = read(&dir, SERVER_CERT_FILE);

        assert!(
            check_and_renew(&cfg, &tx, false, None).unwrap().is_none(),
            "有效期 1 天 + 阈值 30 天时不能自动续签"
        );
        assert_eq!(read(&dir, SERVER_CERT_FILE), before, "不得改写磁盘");
        assert!(!rx.has_changed().unwrap());

        // 显式 force 仍然可以重签（rotate-cert --force / --days 的语义）。
        assert!(check_and_renew(&cfg, &tx, true, Some(1)).unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 严重项（崩溃窗口）：文件级续签不依赖旧 TLS 配置，key/cert 不配套时也能修复。
    #[test]
    fn file_level_renewal_recovers_from_mismatched_key() {
        let dir = temp_dir("repair-files");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 30, 30);
        let old_fingerprint = server_fingerprint(&dir);

        break_key_pair(&dir);
        assert!(
            tls::server_config(&dir).is_err(),
            "不配套时旧配置必须构建失败（这正是启动会卡住的原因）"
        );

        // 关键：本函数不读旧 server_config，所以仍能成功签发。
        let renewed = renew_server_cert_files(&cfg, true, Some(30))
            .unwrap()
            .expect("force 必须重签");
        assert_ne!(renewed.fingerprint, old_fingerprint);
        assert_eq!(renewed.validity_days, 30);
        assert_eq!(
            renewed.not_after,
            tls::not_after_unix(&read(&dir, SERVER_CERT_FILE)).unwrap()
        );

        // 修复后 key/cert 配套，配置可构建。
        assert!(
            tls::cert_matches_key(&read(&dir, SERVER_CERT_FILE), &read(&dir, SERVER_KEY_FILE))
                .unwrap()
        );
        assert!(tls::server_config(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 严重项（启动自愈）：配对不匹配时自动重签并返回可用配置。
    #[test]
    fn load_or_repair_tls_config_self_heals_mismatched_key() {
        let dir = temp_dir("self-heal");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        let old_fingerprint = server_fingerprint(&dir);

        break_key_pair(&dir);
        assert!(tls::server_config(&dir).is_err());

        let config = load_or_repair_tls_config(&cfg).expect("启动路径必须能自愈");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
        let cert_pem = read(&dir, SERVER_CERT_FILE);
        let key_pem = read(&dir, SERVER_KEY_FILE);
        assert!(tls::cert_matches_key(&cert_pem, &key_pem).unwrap());
        assert_ne!(
            tls::fingerprint_of_pem(&cert_pem).unwrap(),
            old_fingerprint,
            "自愈必须换一对新证书"
        );
        // 自愈后的材料仍然由原 CA 签发（使用 CA 信任的 agent 无需重新纳管）。
        assert!(tls::cert_issued_by_ca(&cert_pem, &read(&dir, CA_CERT_FILE), now_ms()).unwrap());
        // 自愈前做了成对备份（crt 0644 / key 0600）。
        let backups = managed_backups(&dir, SERVER_CERT_FILE);
        assert_eq!(backups.len(), 1, "自愈前必须有证书备份");
        assert_eq!(managed_backups(&dir, SERVER_KEY_FILE).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 严重项（启动自愈）：server.key 缺失也属于可自愈的配对问题。
    #[test]
    fn load_or_repair_reissues_when_server_key_missing() {
        let dir = temp_dir("self-heal-no-key");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        std::fs::remove_file(tls::cert_dir(&dir).join(SERVER_KEY_FILE)).unwrap();
        assert!(tls::server_config(&dir).is_err());

        load_or_repair_tls_config(&cfg).expect("私钥缺失必须能自愈");
        assert!(tls::server_config(&dir).is_ok());
        assert!(
            tls::cert_matches_key(&read(&dir, SERVER_CERT_FILE), &read(&dir, SERVER_KEY_FILE))
                .unwrap()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2：server.crt 缺失但 CA 完好时，启动路径直接补签一对。
    #[test]
    fn s2_missing_server_cert_is_reissued() {
        let dir = temp_dir("self-heal-no-cert");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        std::fs::remove_file(tls::cert_dir(&dir).join(SERVER_CERT_FILE)).unwrap();

        load_or_repair_tls_config(&cfg).expect("证书缺失必须能补签");
        let cert_pem = read(&dir, SERVER_CERT_FILE);
        assert!(tls::cert_matches_key(&cert_pem, &read(&dir, SERVER_KEY_FILE)).unwrap());
        assert!(tls::cert_issued_by_ca(&cert_pem, &read(&dir, CA_CERT_FILE), now_ms()).unwrap());
        assert!(tls::days_left(&cert_pem, now_ms()).unwrap() > 300);
        // 旧私钥被成对备份。
        assert_eq!(managed_backups(&dir, SERVER_KEY_FILE).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2：ca.crt 损坏时两次启动都必须失败，且服务端证书指纹不变、不产生备份。
    #[test]
    fn s2_corrupt_ca_fails_twice_without_touching_server_material() {
        let dir = temp_dir("corrupt-ca");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        let cert_before = read(&dir, SERVER_CERT_FILE);
        let key_before = read(&dir, SERVER_KEY_FILE);
        write(
            &dir,
            CA_CERT_FILE,
            b"-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n",
        );

        for round in 0..2 {
            let err = load_or_repair_tls_config(&cfg)
                .expect_err(&format!("CA 损坏时不允许自愈（第 {round} 次）"));
            let text = format!("{err:#}");
            assert!(
                text.contains("无法自动修复") || text.contains("CA"),
                "错误信息: {text}"
            );
            assert!(text.contains("init --force"), "必须给出可执行建议: {text}");
            assert_eq!(
                read(&dir, SERVER_CERT_FILE),
                cert_before,
                "不得改写服务端证书"
            );
            assert_eq!(
                read(&dir, SERVER_KEY_FILE),
                key_before,
                "不得改写服务端私钥"
            );
        }
        assert!(
            managed_backups(&dir, SERVER_CERT_FILE).is_empty(),
            "不可自愈时不应产生备份"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2：CA 私钥缺失时给出可执行错误，且不写服务端文件。
    #[test]
    fn load_or_repair_without_ca_key_is_actionable_error() {
        let dir = temp_dir("self-heal-no-ca");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        break_key_pair(&dir);
        let cert_before = read(&dir, SERVER_CERT_FILE);
        std::fs::remove_file(tls::cert_dir(&dir).join(CA_KEY_FILE)).unwrap();

        let err = load_or_repair_tls_config(&cfg).expect_err("缺 CA 私钥必须报错");
        let text = format!("{err:#}");
        assert!(text.contains("CA 私钥缺失"), "错误信息: {text}");
        assert!(
            text.contains("init --force"),
            "错误信息必须给出可执行建议: {text}"
        );
        assert!(
            text.contains("所有 agent 都需要重新纳管"),
            "必须说明重建 CA 的后果: {text}"
        );
        assert_eq!(
            read(&dir, SERVER_CERT_FILE),
            cert_before,
            "不得改写服务端证书"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S1-1：即使服务端 key/cert 完全正常，只要 CA 缺失/不配套，启动也必须失败，
    /// 且不写任何服务端文件（server_config 本身不读 ca.key，不能只依赖它）。
    #[test]
    fn s11_startup_rejects_bad_ca_even_when_server_pair_is_healthy() {
        // 场景 A：ca.key 缺失，服务端 pair 正常。
        let dir = temp_dir("startup-no-ca-key");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        assert!(tls::server_config(&dir).is_ok(), "前提：服务端 pair 正常");
        let cert_before = read(&dir, SERVER_CERT_FILE);
        let key_before = read(&dir, SERVER_KEY_FILE);
        std::fs::remove_file(tls::cert_dir(&dir).join(CA_KEY_FILE)).unwrap();

        let err = load_or_repair_tls_config(&cfg).expect_err("ca.key 缺失必须拒绝启动");
        assert!(
            format!("{err:#}").contains("CA 私钥缺失"),
            "错误信息: {err:#}"
        );
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before);
        assert_eq!(read(&dir, SERVER_KEY_FILE), key_before);
        let _ = std::fs::remove_dir_all(&dir);

        // 场景 B：ca.key 与 ca.crt 不配套，服务端 pair 正常。
        let dir = temp_dir("startup-mismatched-ca");
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        let cert_before = read(&dir, SERVER_CERT_FILE);
        let key_before = read(&dir, SERVER_KEY_FILE);
        break_ca_pair(&dir);

        let err = load_or_repair_tls_config(&cfg).expect_err("CA 不配套必须拒绝启动");
        assert!(format!("{err:#}").contains("不配套"), "错误信息: {err:#}");
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before);
        assert_eq!(read(&dir, SERVER_KEY_FILE), key_before);
        assert!(
            managed_backups(&dir, SERVER_CERT_FILE).is_empty(),
            "拒绝启动时不得产生备份"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S1-1：server_names 为空/非法时，启动路径也必须拒绝（不依赖 server_config）。
    #[test]
    fn s11_startup_rejects_invalid_server_names() {
        let dir = temp_dir("startup-bad-sans");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let mut cfg = test_config(&dir, 365, 30);
        cfg.server_names = vec!["bad name".to_string()];
        let err = load_or_repair_tls_config(&cfg).expect_err("非法 server_names 必须拒绝启动");
        assert!(
            format!("{err:#}").contains("server_names"),
            "错误信息: {err:#}"
        );
        assert!(tls::server_config(&dir).is_ok(), "服务端材料不应被改动");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2：服务端证书不可解析时直接报错，不重签（避免每次启动换一张证书）。
    #[test]
    fn s2_unparsable_server_cert_is_not_repaired() {
        let dir = temp_dir("bad-server-cert");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        write(&dir, SERVER_CERT_FILE, b"not a certificate");
        let cert_before = read(&dir, SERVER_CERT_FILE);

        // 第五轮起：启动阶段先做「现存证书」校验，不可解析会在进入 repair 前失败，
        // 错误信息必须给出恢复/重签指引。
        let err = load_or_repair_tls_config(&cfg).expect_err("证书不可解析必须失败");
        let text = format!("{err:#}");
        assert!(text.contains("拒绝启动"), "错误信息: {text}");
        assert!(text.contains("rotate-cert"), "必须给出重签命令: {text}");
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before);
        assert!(managed_backups(&dir, SERVER_CERT_FILE).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 构造 v0.1.0 风格的现存服务端材料（rcgen 默认有效期 1975–4096 年）。
    fn legacy_server_pair(dir: &Path, sans: &[String]) -> (String, String) {
        let ca_key_pem = read(dir, CA_KEY_FILE);
        let ca_key = rcgen::KeyPair::from_pem(&ca_key_pem).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, tls::CA_COMMON_NAME);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        ca_params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();

        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, tls::SERVER_COMMON_NAME);
        params.subject_alt_names = sans
            .iter()
            .map(|name| rcgen::SanType::DnsName(rcgen::Ia5String::try_from(name.clone()).unwrap()))
            .collect();
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &ca_cert, &ca_key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// 第六轮：v0.1.0 材料（notAfter=4096）必须能正常启动，不得被有效期上限拒绝。
    #[test]
    fn s6_load_or_repair_accepts_legacy_v01_material() {
        let dir = temp_dir("legacy-startup");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        let (legacy_cert, legacy_key) = legacy_server_pair(&dir, &["localhost".to_string()]);
        write(&dir, SERVER_CERT_FILE, legacy_cert.as_bytes());
        write(&dir, SERVER_KEY_FILE, legacy_key.as_bytes());

        load_or_repair_tls_config(&cfg).expect("v0.1 材料必须能启动，不能被 36500 天上限拒绝");
        assert_eq!(
            read(&dir, SERVER_CERT_FILE),
            legacy_cert,
            "启动不得重签 v0.1 材料"
        );
        assert!(
            managed_backups(&dir, SERVER_CERT_FILE).is_empty(),
            "未重签时不应产生备份"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 第五轮 S1：把另一套 CA 的 ca.crt+ca.key 覆盖进来后，启动必须拒绝
    /// （即使 server 证书本身完好、server_config 能构建），且不写任何文件。
    #[test]
    fn s5_startup_rejects_server_cert_from_other_ca() {
        let dir = temp_dir("startup-foreign-server");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        assert!(tls::server_config(&dir).is_ok(), "前提：正常材料可构建配置");
        let cert_before = read(&dir, SERVER_CERT_FILE);
        let key_before = read(&dir, SERVER_KEY_FILE);

        // 另一套完整 CA（自身配套）覆盖当前 CA 两件套。
        let other = temp_dir("startup-foreign-ca");
        tls::ensure_hub_material(&other, &["localhost".to_string()], policy).unwrap();
        for name in [CA_CERT_FILE, CA_KEY_FILE] {
            let data = read(&other, name);
            write(&dir, name, data.as_bytes());
        }

        let err =
            load_or_repair_tls_config(&cfg).expect_err("server 证书非当前 CA 签发必须拒绝启动");
        let text = format!("{err:#}");
        assert!(text.contains("不是由当前 CA 签发"), "错误信息: {text}");
        assert!(text.contains("rotate-cert"), "必须给出重签命令: {text}");
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before, "不得改写证书");
        assert_eq!(read(&dir, SERVER_KEY_FILE), key_before, "不得改写私钥");
        assert!(
            managed_backups(&dir, SERVER_CERT_FILE).is_empty(),
            "拒绝启动时不得产生备份"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&other);
    }

    /// 第五轮 S1：给 server_names 追加一个证书未覆盖的 SAN，启动必须拒绝并点名。
    #[test]
    fn s5_startup_rejects_missing_san() {
        let dir = temp_dir("startup-missing-san");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let mut cfg = test_config(&dir, 365, 30);
        cfg.server_names.push("added.example".to_string());
        let cert_before = read(&dir, SERVER_CERT_FILE);

        let err = load_or_repair_tls_config(&cfg).expect_err("SAN 未覆盖必须拒绝启动");
        let text = format!("{err:#}");
        assert!(
            text.contains("added.example"),
            "错误信息必须点名缺失 SAN: {text}"
        );
        assert!(text.contains("rotate-cert"), "必须给出重签命令: {text}");
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2：自愈写到磁盘后重建配置失败，必须回滚到修复前的材料。
    #[test]
    fn s2_self_heal_rolls_back_when_rebuild_fails() {
        let dir = temp_dir("heal-rollback");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        break_key_pair(&dir);
        let cert_before = read(&dir, SERVER_CERT_FILE);
        let key_before = read(&dir, SERVER_KEY_FILE);

        // 注入一次重建失败（只对本次 data_dir 生效）。
        *FAIL_REBUILD_FOR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(dir.clone());

        let err = load_or_repair_tls_config(&cfg).expect_err("重建失败必须报错");
        assert!(
            format!("{err:#}").contains("已回滚"),
            "错误信息应说明已回滚: {err:#}"
        );
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before, "必须回滚旧证书");
        assert_eq!(read(&dir, SERVER_KEY_FILE), key_before, "必须回滚旧私钥");
        // 回滚后仍是原来的「不配套」状态，说明确实回到了修复前。
        assert!(tls::server_config(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S1：CA 私钥与 CA 证书不配套时，文件级签发必须失败且不动磁盘。
    #[test]
    fn s1_renew_rejects_mismatched_ca_pair() {
        let dir = temp_dir("ca-mismatch");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        let cert_before = read(&dir, SERVER_CERT_FILE);
        let key_before = read(&dir, SERVER_KEY_FILE);

        break_ca_pair(&dir);
        let err = renew_server_cert_files(&cfg, true, Some(30))
            .err()
            .expect("CA 不配套必须失败");
        assert!(format!("{err:#}").contains("不配套"), "错误信息: {err:#}");
        assert_eq!(
            read(&dir, SERVER_CERT_FILE),
            cert_before,
            "不得改写服务端证书"
        );
        assert_eq!(
            read(&dir, SERVER_KEY_FILE),
            key_before,
            "不得改写服务端私钥"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S1：CA 证书损坏时，文件级签发必须失败且不动磁盘。
    #[test]
    fn s1_renew_rejects_corrupt_ca_cert() {
        let dir = temp_dir("ca-corrupt");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        let cert_before = read(&dir, SERVER_CERT_FILE);

        write(&dir, CA_CERT_FILE, b"not a certificate");
        let err = renew_server_cert_files(&cfg, true, Some(30))
            .err()
            .expect("CA 损坏必须失败");
        assert!(format!("{err:#}").contains("无法解析"), "错误信息: {err:#}");
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S1：server_names 为空或含非法条目时必须拒绝签发（不静默签出无 SAN 证书）。
    #[test]
    fn s1_renew_rejects_empty_or_invalid_server_names() {
        let dir = temp_dir("bad-sans");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cert_before = read(&dir, SERVER_CERT_FILE);

        for bad in [
            Vec::new(),
            vec!["bad name".to_string()],
            vec!["".to_string()],
        ] {
            let mut cfg = test_config(&dir, 365, 30);
            cfg.server_names = bad.clone();
            let err = renew_server_cert_files(&cfg, true, Some(30))
                .err()
                .expect("非法 server_names 必须失败");
            assert!(
                format!("{err:#}").contains("server_names") || format!("{err:#}").contains("SAN"),
                "错误信息: {err:#}"
            );
            assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before, "不得改写证书");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2：自动续签成功时成对备份，且每类最多保留 tls::BACKUP_KEEP 份。
    #[test]
    fn s2_auto_renewal_backs_up_pair_and_retains_recent() {
        let dir = temp_dir("backups");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        let (tx, _rx) = prepare(&dir, policy);
        let cfg = test_config(&dir, 365, 30);
        let first_cert = read(&dir, SERVER_CERT_FILE);
        let first_key = read(&dir, SERVER_KEY_FILE);
        // 运维 CLI（rotate-cert）留下的两段式备份：保留策略不得删除它。
        let legacy = tls::cert_dir(&dir).join("server.crt.bak-1234567890");
        std::fs::write(&legacy, &first_cert).unwrap();

        check_and_renew(&cfg, &tx, true, Some(30))
            .unwrap()
            .expect("force 必须续签");

        let cert_backups = managed_backups(&dir, SERVER_CERT_FILE);
        let key_backups = managed_backups(&dir, SERVER_KEY_FILE);
        assert_eq!(cert_backups.len(), 1, "必须有一份证书备份");
        assert_eq!(key_backups.len(), 1, "必须有一份私钥备份");
        // 备份内容等于重签前的磁盘材料（同一时间戳后缀由 backup_file_name 保证成对）。
        let cert_stamp = cert_backups[0]
            .strip_prefix(&format!("{}.bak-", SERVER_CERT_FILE))
            .unwrap();
        let expected_key = format!("{}.bak-{cert_stamp}", SERVER_KEY_FILE);
        assert_eq!(key_backups[0], expected_key, "证书与私钥备份必须成对");
        assert_eq!(
            std::fs::read_to_string(tls::cert_dir(&dir).join(&cert_backups[0])).unwrap(),
            first_cert
        );
        assert_eq!(
            std::fs::read_to_string(tls::cert_dir(&dir).join(&expected_key)).unwrap(),
            first_key
        );
        // 权限：证书备份 0644 / 私钥备份 0600。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |name: &str| {
                std::fs::metadata(tls::cert_dir(&dir).join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&cert_backups[0]), 0o644);
            assert_eq!(mode(&expected_key), 0o600);
        }

        // 连续重签 7 次：每类备份恰好保留最近 tls::BACKUP_KEEP 份（且至少 1 份）。
        for _ in 0..7 {
            check_and_renew(&cfg, &tx, true, Some(30))
                .unwrap()
                .expect("force 必须续签");
        }
        let cert_backups = managed_backups(&dir, SERVER_CERT_FILE);
        let key_backups = managed_backups(&dir, SERVER_KEY_FILE);
        assert_eq!(
            cert_backups.len(),
            tls::BACKUP_KEEP,
            "证书备份必须恰好保留最近 {} 份（实际 {}）",
            tls::BACKUP_KEEP,
            cert_backups.len()
        );
        assert!(!cert_backups.is_empty(), "保留策略不能把最新证书备份也删掉");
        assert_eq!(
            key_backups.len(),
            tls::BACKUP_KEEP,
            "私钥备份必须恰好保留最近 {} 份（实际 {}）",
            tls::BACKUP_KEEP,
            key_backups.len()
        );
        assert!(!key_backups.is_empty(), "保留策略不能把最新私钥备份也删掉");
        assert!(legacy.exists(), "不得删除 rotate-cert 的两段式备份");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2：自动续签失败时不推送 watch、也不改动磁盘服务端材料。
    #[test]
    fn s2_auto_renewal_failure_does_not_push_watch_or_touch_material() {
        let dir = temp_dir("auto-fail");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        let (tx, rx) = prepare(&dir, policy);
        let cfg = test_config(&dir, 365, 30);
        let cert_before = read(&dir, SERVER_CERT_FILE);
        let key_before = read(&dir, SERVER_KEY_FILE);
        // 破坏 CA：文件级签发的写前校验会失败。
        break_ca_pair(&dir);

        let err = check_and_renew(&cfg, &tx, true, Some(30)).expect_err("CA 不配套必须失败");
        assert!(format!("{err:#}").contains("不配套"), "错误信息: {err:#}");
        assert!(!rx.has_changed().unwrap(), "失败时不得推送新配置");
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before, "不得改写证书");
        assert_eq!(read(&dir, SERVER_KEY_FILE), key_before, "不得改写私钥");
        assert!(
            managed_backups(&dir, SERVER_CERT_FILE).is_empty(),
            "失败路径不得产生备份（备份在全部校验之后）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A3 错误路径：天数非法 / 证书缺失 / CA 私钥缺失都要报错，不能 panic 或静默成功。
    #[test]
    fn missing_material_and_invalid_days_are_errors() {
        let dir = temp_dir("errors");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        let (tx, _rx) = prepare(&dir, policy);
        let cfg = test_config(&dir, 365, 30);

        // 天数非法：先于任何写盘拒绝。
        let err = check_and_renew(&cfg, &tx, true, Some(0)).unwrap_err();
        assert!(format!("{err:#}").contains("有效期"), "错误信息: {err:#}");

        // 证书缺失（非 force）：明确报错并提示初始化。
        std::fs::remove_file(tls::cert_dir(&dir).join(SERVER_CERT_FILE)).unwrap();
        let err = check_and_renew(&cfg, &tx, false, None).unwrap_err();
        assert!(
            format!("{err:#}").contains("读取服务端证书失败"),
            "错误信息: {err:#}"
        );

        // CA 私钥缺失（证书还在）：续签必须失败，而不是签出一张无主证书。
        let ca_key_pem = read(&dir, CA_KEY_FILE);
        let (cert_pem, key_pem) =
            tls::issue_server_cert(&ca_key_pem, &["localhost".to_string()], 30).unwrap();
        std::fs::write(tls::cert_dir(&dir).join(SERVER_CERT_FILE), cert_pem).unwrap();
        std::fs::write(tls::cert_dir(&dir).join(SERVER_KEY_FILE), key_pem).unwrap();
        std::fs::remove_file(tls::cert_dir(&dir).join(CA_KEY_FILE)).unwrap();
        let (tx2, _rx2) = watch::channel(tls::server_config(&dir).unwrap());

        let err = check_and_renew(&cfg, &tx2, true, None).unwrap_err();
        assert!(format!("{err:#}").contains("CA 私钥"), "错误信息: {err:#}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KI-10：磁盘证书指纹没变时不重建、不推送；rotate 后指纹变化才热替换。
    #[test]
    fn v021_cert_watcher_reloads_only_when_fingerprint_changes() {
        let dir = temp_dir("watcher-reload");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        let (tx, rx) = watch::channel(tls::server_config(&dir).unwrap());
        let old_status = read_disk_cert_status(&cfg).unwrap();
        let live = RwLock::new(old_status.clone());

        // 未变化：不推送。
        assert!(!reload_server_config_if_changed(&cfg, &tx, &live).unwrap());
        assert!(!rx.has_changed().unwrap());
        assert_eq!(read_live(&live), old_status);

        // 只改磁盘（模拟运维手工执行 rotate-cert），不发 watch。
        let renewed = renew_server_cert_files(&cfg, true, Some(60))
            .unwrap()
            .expect("force 必须重签");
        assert_ne!(renewed.fingerprint, old_status.fingerprint);
        assert!(!rx.has_changed().unwrap(), "文件级续签本身不推送 watch");

        assert!(
            reload_server_config_if_changed(&cfg, &tx, &live).unwrap(),
            "指纹变化必须触发热加载"
        );
        assert!(rx.has_changed().unwrap(), "watch 必须收到新配置");
        let live_after = read_live(&live);
        assert_eq!(live_after.fingerprint, renewed.fingerprint);
        assert_eq!(live_after.not_after, renewed.not_after);
        assert_eq!(
            live_after,
            read_disk_cert_status(&cfg).unwrap(),
            "live 摘要必须与磁盘一致"
        );

        // 再次轮询：指纹相同，保持无动作。
        assert!(!reload_server_config_if_changed(&cfg, &tx, &live).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KI-10：坏证书（不配套 / 不可解析 / SAN 不覆盖）绝不替换 live 配置。
    #[test]
    fn v021_cert_watcher_rejects_bad_certificate_and_keeps_old() {
        let dir = temp_dir("watcher-bad-cert");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let cfg = test_config(&dir, 365, 30);
        let (tx, rx) = watch::channel(tls::server_config(&dir).unwrap());
        let old_status = read_disk_cert_status(&cfg).unwrap();
        let live = RwLock::new(old_status.clone());
        let cert_before = read(&dir, SERVER_CERT_FILE);

        // 场景 A：证书与私钥不配套（rotate 写盘中途被 kill 的状态）。
        break_key_pair(&dir);
        let err = reload_server_config_if_changed(&cfg, &tx, &live)
            .expect_err("不配套的 key/cert 必须拒绝热加载");
        assert!(format!("{err:#}").contains("不配套"), "错误信息: {err:#}");
        assert!(!rx.has_changed().unwrap(), "失败不得推送新配置");
        assert_eq!(read_live(&live), old_status, "失败必须保留旧 live");
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before, "不得改写证书");

        // 恢复配套后，换成不可解析的证书。
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        write(&dir, SERVER_CERT_FILE, b"not a certificate");
        let err = reload_server_config_if_changed(&cfg, &tx, &live)
            .expect_err("不可解析的证书必须拒绝热加载");
        assert!(format!("{err:#}").contains("证书"), "错误信息: {err:#}");
        assert!(!rx.has_changed().unwrap());
        assert_eq!(read_live(&live), old_status);

        // 场景 C：证书本身可解析且配套，但 SAN 不覆盖配置新增的条目。
        tls::ensure_hub_material(&dir, &["localhost".to_string()], policy).unwrap();
        let mut stricter = cfg.clone();
        stricter.server_names.push("added.example".to_string());
        let err = reload_server_config_if_changed(&stricter, &tx, &live)
            .expect_err("SAN 未覆盖必须拒绝热加载");
        assert!(
            format!("{err:#}").contains("added.example"),
            "错误信息必须点名缺失 SAN: {err:#}"
        );
        assert!(!rx.has_changed().unwrap());
        assert_eq!(read_live(&live), old_status);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 严重项（KI-11）：自动续签必须与 CLI `rotate-cert` 共用文件锁。
    ///
    /// 锁被占用时 `check_and_renew` 必须失败且不碰任何服务端材料；
    /// 释放后才允许续签。否则两者交错写 key/cert 会得到不配套的一对。
    #[test]
    fn v021_auto_renewal_respects_cert_lock_and_never_writes_when_held() {
        let dir = temp_dir("auto-renew-lock");
        let policy = tls::CertPolicy {
            server_days: 365,
            ..Default::default()
        };
        let (tx, rx) = prepare(&dir, policy);
        let cfg = test_config(&dir, 365, 30);
        let cert_dir = tls::cert_dir(&dir);
        let cert_before = read(&dir, SERVER_CERT_FILE);
        let key_before = read(&dir, SERVER_KEY_FILE);
        let fingerprint_before = tls::fingerprint_of_pem(&cert_before).unwrap();

        let lock = CertLock::acquire(&cert_dir).expect("测试先持有 CLI 侧锁");
        let err =
            check_and_renew(&cfg, &tx, true, Some(30)).expect_err("锁被占用时自动续签必须失败");
        let text = format!("{err:#}");
        assert!(
            text.contains("另一个 rotate-cert 正在运行"),
            "错误信息必须说明锁被占用: {text}"
        );
        assert_eq!(read(&dir, SERVER_CERT_FILE), cert_before, "不得改写证书");
        assert_eq!(read(&dir, SERVER_KEY_FILE), key_before, "不得改写私钥");
        assert!(
            managed_backups(&dir, SERVER_CERT_FILE).is_empty(),
            "获取锁失败时不得产生备份"
        );
        assert!(!rx.has_changed().unwrap(), "失败时不得推送新配置");
        assert!(lock.path().exists(), "失败方不得删除他人的锁");

        // 释放锁后可正常续签，且锁文件随 RAII 删除。
        drop(lock);
        let renewed = check_and_renew(&cfg, &tx, true, Some(30))
            .unwrap()
            .expect("释放锁后必须续签");
        assert_ne!(renewed, fingerprint_before);
        assert!(rx.has_changed().unwrap());
        assert_eq!(
            managed_backups(&dir, SERVER_CERT_FILE).len(),
            1,
            "成功续签必须成对备份旧材料"
        );
        assert!(!cert_dir.join(CERT_LOCK_FILE).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KI-11：锁文件 0600、内容含 pid；第二个 acquire 失败，Drop 后释放。
    #[test]
    fn v021_cert_lock_blocks_concurrent_rotate_and_releases_on_drop() {
        let dir = temp_dir("cert-lock");
        fsutil::ensure_dir(&dir, 0o700).unwrap();
        let cert_dir = tls::cert_dir(&dir);
        let lock = CertLock::acquire(&cert_dir).expect("首次获取锁必须成功");
        let lock_path = lock.path().to_path_buf();
        assert_eq!(lock_path.file_name().unwrap(), CERT_LOCK_FILE);
        assert!(lock_path.exists());
        let content = std::fs::read_to_string(&lock_path).unwrap();
        assert!(
            content.contains(&format!("pid={}", std::process::id())),
            "锁文件必须记录 pid: {content}"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "锁文件必须是 0600");
        }

        let err = CertLock::acquire(&cert_dir).expect_err("并发第二个必须失败");
        assert!(
            format!("{err:#}").contains("另一个 rotate-cert 正在运行"),
            "错误信息: {err:#}"
        );
        assert!(lock_path.exists(), "失败方不得删除他人的锁");

        drop(lock);
        assert!(!lock_path.exists(), "RAII 必须删除锁文件");
        // 释放后可以再次获取。
        let again = CertLock::acquire(&cert_dir).expect("释放后必须能重新获取");
        drop(again);
        assert!(!lock_path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// KI-11：超过 10 分钟的陈旧锁可自动恢复；未超时的锁不被误删。
    #[test]
    fn v021_cert_lock_recovers_stale_lock() {
        use std::time::{Duration, SystemTime};

        let dir = temp_dir("cert-lock-stale");
        fsutil::ensure_dir(&dir, 0o700).unwrap();
        let cert_dir = tls::cert_dir(&dir);
        let lock = CertLock::acquire(&cert_dir).unwrap();
        let lock_path = lock.path().to_path_buf();

        // 模拟持锁进程被 kill -9：只留下锁文件（用 forget 跳过 Drop）。
        std::mem::forget(lock);
        assert!(lock_path.exists());

        // 刚创建的锁未超时：仍必须拒绝。
        let err = CertLock::acquire(&cert_dir).expect_err("新鲜锁不得被清理");
        assert!(format!("{err:#}").contains("另一个 rotate-cert 正在运行"));

        // 把 mtime 改成 11 分钟前：下一次 acquire 必须清理并成功。
        let old = SystemTime::now() - Duration::from_secs(11 * 60);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .unwrap();
        file.set_modified(old).unwrap();
        drop(file);

        let recovered = CertLock::acquire(&cert_dir).expect("陈旧锁必须可恢复");
        assert!(lock_path.exists(), "恢复后应持有一把新锁");
        drop(recovered);
        assert!(!lock_path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
