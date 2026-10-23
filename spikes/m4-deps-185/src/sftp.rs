//! russh + russh-sftp 最小示例（方案 §7.3 / §7.4）。
//!
//! 验证点：
//! - 纯 Rust：`russh` 使用 `ring` 后端（不启用默认 `aws-lc-rs`）；
//! - 密码认证与 ed25519 私钥加载两种方式；
//! - 连接超时（`tokio::time::timeout`）；
//! - SFTP 目录创建、写入、读取、删除；
//! - 不调用任何 `ssh` 子进程。
//!
//! 安全提示：这里为 spike 演示，`check_server_key` 接受任意主机密钥。
//! 生产实现必须校验配置中的主机公钥指纹（等同 known_hosts），失败返回 `Ok(false)`。

use anyhow::{anyhow, bail, Context, Result};
use russh::client::Handler;
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh_sftp::client::SftpSession;
use std::sync::Arc;
use std::time::Duration;

/// 连接超时：连接建立与认证阶段都受它约束。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 空闲超时：避免半开连接永久占用任务。
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

pub struct SftpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key_path: Option<String>,
    pub remote_dir: String,
}

impl SftpConfig {
    /// 从环境变量读取，避免把真实凭据写进仓库。
    pub fn from_env() -> Result<Self> {
        let host = std::env::var("M4_SPIKE_SFTP_HOST").context("缺少 M4_SPIKE_SFTP_HOST")?;
        let username = std::env::var("M4_SPIKE_SFTP_USER").context("缺少 M4_SPIKE_SFTP_USER")?;
        let port = std::env::var("M4_SPIKE_SFTP_PORT")
            .ok()
            .map(|p| p.parse::<u16>())
            .transpose()
            .context("M4_SPIKE_SFTP_PORT 不是合法端口")?
            .unwrap_or(22);
        let password = std::env::var("M4_SPIKE_SFTP_PASSWORD").ok();
        let private_key_path = std::env::var("M4_SPIKE_SFTP_KEY").ok();
        let remote_dir = std::env::var("M4_SPIKE_SFTP_DIR")
            .unwrap_or_else(|_| "/tmp/rustboard-spike".to_owned());

        if password.is_none() && private_key_path.is_none() {
            bail!("archive.sftp 需要 password 或 private_key_path");
        }

        Ok(Self {
            host,
            port,
            username,
            password,
            private_key_path,
            remote_dir,
        })
    }
}

/// 仅 spike 用：接受任意服务器主机密钥。生产必须校验指纹。
struct AcceptAnyServerKey;

impl Handler for AcceptAnyServerKey {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// 建立 SSH 连接并完成认证，返回会话句柄。
async fn connect_and_auth(cfg: &SftpConfig) -> Result<russh::client::Handle<AcceptAnyServerKey>> {
    let ssh_config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(INACTIVITY_TIMEOUT),
        ..Default::default()
    });

    let mut session = tokio::time::timeout(
        CONNECT_TIMEOUT,
        russh::client::connect(
            ssh_config,
            (cfg.host.as_str(), cfg.port),
            AcceptAnyServerKey,
        ),
    )
    .await
    .map_err(|_| anyhow!("SSH 连接超时（{CONNECT_TIMEOUT:?}）"))??;

    // 私钥优先，其次密码（方案 §7.3）。
    let auth = if let Some(key_path) = &cfg.private_key_path {
        // 支持 OpenSSH 格式（含 ed25519）；加密私钥的 passphrase 从配置读取。
        let passphrase = std::env::var("M4_SPIKE_SFTP_KEY_PASSPHRASE").ok();
        let key = load_secret_key(key_path, passphrase.as_deref())
            .with_context(|| format!("加载私钥失败：{key_path}"))?;
        // ed25519 会忽略 hash_alg；RSA 私钥应传 `session.best_supported_rsa_hash()`。
        session
            .authenticate_publickey(
                &cfg.username,
                PrivateKeyWithHashAlg::new(Arc::new(key), None),
            )
            .await?
    } else {
        let password = cfg
            .password
            .as_deref()
            .ok_or_else(|| anyhow!("archive.sftp 需要 password 或 private_key_path"))?;
        session
            .authenticate_password(&cfg.username, password)
            .await?
    };

    if !auth.success() {
        bail!("SSH 认证失败：用户 {}", cfg.username);
    }
    Ok(session)
}

/// 逐级创建远端目录（SFTP 没有 mkdir -p）。
async fn ensure_remote_dir(sftp: &SftpSession, dir: &str) -> Result<()> {
    let mut current = String::new();
    for part in dir.trim_end_matches('/').split('/') {
        if part.is_empty() {
            continue;
        }
        current.push('/');
        current.push_str(part);
        if sftp
            .try_exists(current.clone())
            .await
            .with_context(|| format!("检查远端目录失败：{current}"))?
        {
            continue;
        }
        sftp.create_dir(current.clone())
            .await
            .with_context(|| format!("创建远端目录失败：{current}"))?;
    }
    Ok(())
}

/// 完整走一遍：连接 → 认证 → 子系统 → mkdir → write → read → 清理。
pub async fn smoke(cfg: &SftpConfig) -> Result<()> {
    let session = connect_and_auth(cfg).await?;

    let channel = session
        .channel_open_session()
        .await
        .context("打开 SSH channel 失败")?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("请求 sftp 子系统失败")?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .context("SFTP 协议初始化失败")?;

    ensure_remote_dir(&sftp, &cfg.remote_dir).await?;

    let file_path = format!("{}/probe.csv.gz", cfg.remote_dir.trim_end_matches('/'));
    let payload = b"agent_id,metric,labels,ts,value\nspike,disk_used,,1,1\n";
    sftp.write(file_path.clone(), payload)
        .await
        .with_context(|| format!("写入失败：{file_path}"))?;

    let read_back = sftp
        .read(file_path.clone())
        .await
        .with_context(|| format!("读取失败：{file_path}"))?;
    if read_back != payload {
        bail!("SFTP 回读内容与写入不一致：{file_path}");
    }
    println!("sftp ok: {} 字节 -> {}", read_back.len(), file_path);

    if let Err(err) = sftp.remove_file(file_path.clone()).await {
        eprintln!("清理远端文件失败（忽略）：{file_path}: {err}");
    }
    sftp.close().await.ok();
    session
        .disconnect(russh::Disconnect::ByApplication, "spike done", "en")
        .await
        .ok();

    Ok(())
}
