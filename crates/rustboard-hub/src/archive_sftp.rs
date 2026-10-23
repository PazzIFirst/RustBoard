//! M4-C3：SFTP 冷存储后端。
//!
//! 使用 vendored `russh` 0.60.3（`ring` 后端）+ `russh-sftp` 3.0.1 实现
//! [`ColdStore`]；不调用 `ssh` 子进程，不依赖 openssl / cmake。
//!
//! 安全约定：
//! - **主机密钥强校验**：配置里的 `host_key_fingerprint`（`SHA256:<base64>`，
//!   允许一个末尾 `=`）与服务器握手公钥的 SHA-256 指纹逐字节比较；不匹配在
//!   `check_server_key` 返回 `Ok(false)`，连接随即失败。不存在
//!   `AcceptAnyServerKey` 一类降级，也不读取 `known_hosts` 或用户 SSH 配置。
//! - 认证优先使用 `private_key_path`（只接受 ed25519），其次 `password`；
//!   认证失败统一映射为固定错误，不区分“用户不存在 / 密码错 / 密钥错”，避免
//!   账号枚举。私钥文件在构造（启动）与每次连接前校验：Unix 上 group/other
//!   不得有权限，否则固定失败。
//! - **密钥类型限制**：vendored 去 `rsa` 后，**不支持 RSA 用户密钥，也不支持
//!   RSA 主机密钥**；用户私钥仅 ed25519，主机密钥需为 ed25519 或 ECDSA。
//!   配置中的主机指纹仍只接受 `SHA256:<base64>`（不接受 MD5 / SHA1）。仅提供
//!   RSA 主机密钥的旧服务器会握手失败。
//! - 所有对外错误都是 [`ArchiveError`] 的固定分类：`Display` 不包含 host、
//!   端口、用户名、密码、私钥路径、远端目录、协议响应正文或 SFTP 状态消息。
//!   连接 / 主机密钥 / 认证 / 私钥权限 / 协议 / IO 在内部用 [`SftpFailure`]
//!   分别归类，对外只暴露固定错误的 `ArchiveError`（`NotFound` 除外）。
//! - 对象 key 在拼接前重新校验：拒绝绝对路径、`..`、`.` 段、反斜杠、控制字符
//!   与空段；远端路径固定为 `remote_dir.trim_end_matches('/') + "/" + key`。
//! - `put` 会按 key 逐级创建父目录（SFTP 没有 `mkdir -p`）；`get` 先查远端
//!   大小再流式读取，硬上限 1 GiB，防止异常对象打爆 hub 内存。
//! - `test` 只在 `health/<uuid>.probe` 下写读删探针，失败也会尽力删除；删除
//!   probe 后尝试删除空的 `health/` 目录，非空 / 失败一律忽略。
//!
//! 连接策略：每次 `ColdStore` 操作建立一条新 SSH 连接并在结束时断开，避免
//! 共享可变会话、半开连接和跨请求重连状态；`test` 的写读删复用同一条连接。
//! 连接超时 10s，russh 空闲超时 30s，底层 SFTP 请求超时使用库默认 10s。
//!
//! 缺失路径语义：SFTP v3 只有 `SSH_FX_NO_SUCH_FILE`；`russh-sftp 3.0.1` 的
//! [`StatusCode`] 没有 v6 的 `NoSuchPath` variant（未知码会被反序列化成协议
//! 错误）。因此 `head` / `get` / `delete` 对缺失文件或父目录统一按
//! `None` / `NotFound` / 幂等成功处理，测试覆盖该映射。
//!
//! 验证说明：单元测试只覆盖指纹、路径、私钥权限、错误脱敏与构造，不建立真实
//! SFTP 连接；C3 交付前需按 `docs/plans/2026-10-24-m4-alerting-archive.md` 用
//! 手工环境对真实服务器验证密码 / ed25519、ed25519 或 ECDSA 主机密钥、目录
//! 创建、写入与下载。

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use russh::client::{Handle, Handler};
use russh::keys::{load_secret_key, HashAlg, PrivateKeyWithHashAlg, PublicKey};
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::fs::Metadata;
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::StatusCode;
use rustboard_common::config::ArchiveSftpConfig;
use rustboard_core::archive::{ArchiveError, ArchiveResult, ColdObjectMeta, ColdStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// 连接建立 + SSH 密钥交换的超时。
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// SSH 会话空闲超时；服务器长时间无响应时由 russh 回收，避免任务永久挂起。
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);
/// 关闭 SFTP / SSH 会话的单步超时；清理失败不影响已经得到的操作结果。
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

/// `ColdStore::get` / `put` 的单对象硬上限（1 GiB）。
const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// 读取对象时的分块大小。
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// 对象 key 最大字节数；C1a 生成的 key 远小于该值。
const MAX_KEY_BYTES: usize = 1024;

/// 健康探针固定内容（不含任何配置或凭据）。
const HEALTH_PROBE_PAYLOAD: &[u8] = b"rustboard-archive-sftp-health-probe";

// ---------------------------------------------------------------------------
// 固定错误分类
// ---------------------------------------------------------------------------

/// SFTP 内部的固定失败分类。
///
/// 不实现 `Display` 把底层错误串带出来：所有分类都只能映射到固定的
/// [`ArchiveError`]。内部保留分类是为了让代码路径 / 单测能区分连接、主机密钥、
/// 认证与 IO 失败，对外仍只有固定文案。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SftpFailure {
    /// TCP / SSH 握手失败（不可达、超时、版本协商失败等）。
    Connect,
    /// 服务器主机公钥指纹与配置不符（可能的中间人）。
    HostKey,
    /// 密码或 ed25519 私钥认证失败。
    Auth,
    /// 私钥文件权限不安全（Unix: group/other 有权限）或不是普通文件。
    KeyPermissions,
    /// SFTP 子系统 / 协议初始化失败。
    Protocol,
    /// 读写、删文件、建目录等 SFTP 操作失败。
    Io,
    /// 远端对象不存在（仅 `get` / `head` 对外映射为 `NotFound`）。
    NotFound,
    /// 对象超过 1 GiB 或远端返回的大小异常。
    TooLarge,
}

impl SftpFailure {
    /// 固定英文分类码；只用于 debug 日志与测试，不含任何远端信息。
    fn reason(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::HostKey => "host_key",
            Self::Auth => "auth",
            Self::KeyPermissions => "key_permissions",
            Self::Protocol => "protocol",
            Self::Io => "io",
            Self::NotFound => "not_found",
            Self::TooLarge => "too_large",
        }
    }
}

impl From<SftpFailure> for ArchiveError {
    fn from(failure: SftpFailure) -> Self {
        // 分类码固定且不含凭据 / 路径；debug 级别便于排障，不会进入用户错误。
        if failure != SftpFailure::NotFound {
            tracing::debug!(reason = failure.reason(), "SFTP 冷存储操作失败");
        }
        match failure {
            SftpFailure::NotFound => ArchiveError::NotFound,
            _ => ArchiveError::BackendUnavailable,
        }
    }
}

/// `russh` 客户端 handler 的错误类型。
///
/// `russh` 要求 `Handler::Error: From<russh::Error> + Send + Debug`。这里只保留
/// 两个固定分类；底层错误串不会出现在 `Display` 中。
#[derive(Debug)]
enum ClientError {
    /// `check_server_key` 拒绝主机密钥后，russh 返回的 `UnknownKey`。
    HostKey,
    /// 其它握手 / 协议错误。
    Connect,
}

impl ClientError {
    fn into_failure(self) -> SftpFailure {
        match self {
            Self::HostKey => SftpFailure::HostKey,
            Self::Connect => SftpFailure::Connect,
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HostKey => "SFTP 主机密钥校验失败",
            Self::Connect => "SFTP 连接失败",
        })
    }
}

impl std::error::Error for ClientError {}

impl From<russh::Error> for ClientError {
    fn from(error: russh::Error) -> Self {
        match error {
            russh::Error::UnknownKey => Self::HostKey,
            _ => Self::Connect,
        }
    }
}

// ---------------------------------------------------------------------------
// 主机密钥 handler
// ---------------------------------------------------------------------------

/// 只接受配置指纹的 SSH 客户端 handler。
///
/// `expected` 是解码后的 SHA-256 摘要（32 字节）；`check_server_key` 返回
/// `Ok(false)` 即拒绝，russh 会把连接置为失败。绝不返回无条件 `Ok(true)`。
struct SftpHostKeyHandler {
    expected: [u8; 32],
}

impl Handler for SftpHostKeyHandler {
    type Error = ClientError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // 使用与 OpenSSH `SHA256:` 指纹相同的算法；比较原始摘要，避免 base64
        // 填充差异（配置允许 43 字符或带一个 `=` 的 44 字符）。
        let actual = server_public_key.fingerprint(HashAlg::Sha256);
        Ok(actual.as_bytes() == self.expected.as_slice())
    }
}

/// 解析并校验 `SHA256:<base64>` 主机公钥指纹。
///
/// 配置校验已保证格式；这里做同样严格的再校验，供构造器与单测使用。
/// 返回 32 字节摘要，任何格式错误都返回 `None`（调用方映射为固定错误）。
fn decode_host_key_fingerprint(fingerprint: &str) -> Option<[u8; 32]> {
    let rest = fingerprint.strip_prefix("SHA256:")?;
    if !rest
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
    {
        return None;
    }
    let padded = match rest.len() {
        43 => format!("{rest}="),
        44 if rest.ends_with('=') => rest.to_string(),
        _ => return None,
    };
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(padded)
        .ok()?;
    decoded.try_into().ok()
}

/// 校验私钥文件权限；Unix 上 group/other 不得有任何权限（等价 OpenSSH 的
/// `bad permissions` 检查），且必须是普通文件。Windows 不做 POSIX 权限检查。
#[cfg(unix)]
fn check_private_key_permissions(path: &str) -> Result<(), SftpFailure> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).map_err(|_| SftpFailure::KeyPermissions)?;
    if !metadata.is_file() {
        return Err(SftpFailure::KeyPermissions);
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SftpFailure::KeyPermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_key_permissions(_path: &str) -> Result<(), SftpFailure> {
    Ok(())
}

// ---------------------------------------------------------------------------
// 冷存储实现
// ---------------------------------------------------------------------------

/// SFTP 冷存储。
///
/// 不实现 `Debug`：结构体持有密码与私钥路径，诊断输出不应带出配置。
pub struct SftpColdStore {
    config: ArchiveSftpConfig,
    expected_fingerprint: [u8; 32],
}

impl SftpColdStore {
    /// 构造后端；只做本地配置 / 指纹 / 私钥权限校验，不发起网络请求。
    ///
    /// 配置不合法、指纹格式错误或私钥权限不安全统一返回
    /// [`ArchiveError::BackendUnavailable`]，不拼接字段值。
    pub fn new(config: &ArchiveSftpConfig) -> ArchiveResult<Self> {
        config
            .validate()
            .map_err(|_| ArchiveError::BackendUnavailable)?;
        let expected_fingerprint = decode_host_key_fingerprint(&config.host_key_fingerprint)
            .ok_or(ArchiveError::BackendUnavailable)?;
        if !config.private_key_path.is_empty() {
            check_private_key_permissions(&config.private_key_path)?;
        }
        Ok(Self {
            config: config.clone(),
            expected_fingerprint,
        })
    }

    /// 校验 key 并拼成远端绝对路径。
    fn object_path(&self, key: &str) -> ArchiveResult<String> {
        validate_object_key(key)?;
        let base = self.config.remote_dir.trim_end_matches('/');
        Ok(format!("{base}/{key}"))
    }

    /// 建立 SSH 连接并完成认证；私钥优先，其次密码。
    async fn connect_and_auth(&self) -> Result<Handle<SftpHostKeyHandler>, SftpFailure> {
        // 在发起 TCP 连接前完成私钥权限校验与加载：配置错误不应触达远端，
        // 也避免“连接成功后才因本地私钥失败”的误导。
        let private_key = if !self.config.private_key_path.is_empty() {
            check_private_key_permissions(&self.config.private_key_path)?;
            // 配置没有 passphrase 字段，不支持加密私钥。只允许 ed25519：
            // rsa feature 已被 vendor patch 删除，ECDSA / RSA 不作为 C3
            // 用户私钥支持范围。
            let key = load_secret_key(&self.config.private_key_path, None)
                .map_err(|_| SftpFailure::Auth)?;
            if !key.algorithm().is_ed25519() {
                return Err(SftpFailure::Auth);
            }
            Some(key)
        } else {
            None
        };

        let ssh_config = Arc::new(russh::client::Config {
            inactivity_timeout: Some(INACTIVITY_TIMEOUT),
            ..Default::default()
        });
        let handler = SftpHostKeyHandler {
            expected: self.expected_fingerprint,
        };
        let mut session = tokio::time::timeout(
            CONNECT_TIMEOUT,
            russh::client::connect(
                ssh_config,
                (self.config.host.as_str(), self.config.port),
                handler,
            ),
        )
        .await
        .map_err(|_| SftpFailure::Connect)?
        .map_err(ClientError::into_failure)?;

        let auth = if let Some(key) = private_key {
            session
                .authenticate_publickey(
                    self.config.username.as_str(),
                    PrivateKeyWithHashAlg::new(Arc::new(key), None),
                )
                .await
                .map_err(|_| SftpFailure::Auth)?
        } else {
            session
                .authenticate_password(self.config.username.as_str(), self.config.password.as_str())
                .await
                .map_err(|_| SftpFailure::Auth)?
        };
        if !auth.success() {
            return Err(SftpFailure::Auth);
        }
        Ok(session)
    }

    /// 在已认证的连接上打开 SFTP 子系统。
    async fn open_sftp(session: &Handle<SftpHostKeyHandler>) -> Result<SftpSession, SftpFailure> {
        let channel = session
            .channel_open_session()
            .await
            .map_err(|_| SftpFailure::Connect)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|_| SftpFailure::Connect)?;
        SftpSession::new(channel.into_stream())
            .await
            .map_err(|_| SftpFailure::Protocol)
    }

    /// 建立连接 + 打开 SFTP；失败时尽力断开 SSH 会话。
    async fn connect_sftp(&self) -> Result<(Handle<SftpHostKeyHandler>, SftpSession), SftpFailure> {
        let session = self.connect_and_auth().await?;
        match Self::open_sftp(&session).await {
            Ok(sftp) => Ok((session, sftp)),
            Err(error) => {
                let _ = tokio::time::timeout(
                    CLEANUP_TIMEOUT,
                    session.disconnect(russh::Disconnect::ByApplication, "rustboard archive", "en"),
                )
                .await;
                Err(error)
            }
        }
    }

    /// 尽力关闭 SFTP 与 SSH 会话；清理错误被忽略，不覆盖主操作结果。
    async fn close_sftp(&self, session: &Handle<SftpHostKeyHandler>, sftp: &SftpSession) {
        let _ = tokio::time::timeout(CLEANUP_TIMEOUT, sftp.close()).await;
        let _ = tokio::time::timeout(
            CLEANUP_TIMEOUT,
            session.disconnect(russh::Disconnect::ByApplication, "rustboard archive", "en"),
        )
        .await;
    }

    /// 逐级创建远端目录（等价 `mkdir -p`）。
    ///
    /// 只接受绝对路径；调用方传入的路径由配置或已校验的 key 派生。并发创建
    /// 导致的“已存在”通过再次 `try_exists` 容忍。
    async fn ensure_remote_dir(&self, sftp: &SftpSession, dir: &str) -> Result<(), SftpFailure> {
        if !dir.starts_with('/') {
            return Err(SftpFailure::Protocol);
        }
        let mut current = String::new();
        for part in dir.trim_end_matches('/').split('/') {
            if part.is_empty() {
                continue;
            }
            current.push('/');
            current.push_str(part);
            match sftp.try_exists(current.clone()).await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(_) => return Err(SftpFailure::Io),
            }
            if sftp.create_dir(current.clone()).await.is_err()
                && !matches!(sftp.try_exists(current.clone()).await, Ok(true))
            {
                return Err(SftpFailure::Io);
            }
        }
        Ok(())
    }

    /// 创建对象路径的父目录；路径必须已经过 [`validate_object_key`] 校验。
    async fn ensure_parent_dir(&self, sftp: &SftpSession, path: &str) -> Result<(), SftpFailure> {
        let (parent, name) = path.rsplit_once('/').ok_or(SftpFailure::Protocol)?;
        if name.is_empty() {
            return Err(SftpFailure::Protocol);
        }
        let parent = if parent.is_empty() { "/" } else { parent };
        self.ensure_remote_dir(sftp, parent).await
    }

    /// 覆盖写对象（CREATE | TRUNCATE），自动补齐父目录。
    ///
    /// 注意 `russh_sftp::SftpSession::write` 只带 `WRITE` 标志，不会 create /
    /// truncate，因此不能直接使用。
    async fn write_object(&self, sftp: &SftpSession, path: &str, data: &[u8]) -> ArchiveResult<()> {
        if data.len() as u64 > MAX_OBJECT_BYTES {
            return Err(SftpFailure::TooLarge.into());
        }
        self.ensure_parent_dir(sftp, path).await?;
        let mut file = sftp
            .create(path.to_string())
            .await
            .map_err(map_sftp_error)?;
        file.write_all(data).await.map_err(|_| SftpFailure::Io)?;
        file.close().await.map_err(|_| SftpFailure::Io)?;
        Ok(())
    }

    /// 读取完整对象；先查远端大小，再分块读取并强制 1 GiB 上限。
    async fn read_object(&self, sftp: &SftpSession, path: &str) -> ArchiveResult<Vec<u8>> {
        let meta = sftp
            .metadata(path.to_string())
            .await
            .map_err(map_sftp_error)?;
        if meta.size.is_some_and(|size| size > MAX_OBJECT_BYTES) {
            return Err(SftpFailure::TooLarge.into());
        }
        let mut file = sftp.open(path.to_string()).await.map_err(map_sftp_error)?;
        let mut out = Vec::new();
        let mut buffer = vec![0u8; READ_CHUNK_BYTES];
        loop {
            let read = match file.read(&mut buffer).await {
                Ok(read) => read,
                Err(_) => {
                    let _ = tokio::time::timeout(CLEANUP_TIMEOUT, file.close()).await;
                    return Err(SftpFailure::Io.into());
                }
            };
            if read == 0 {
                break;
            }
            if out.len().saturating_add(read) > MAX_OBJECT_BYTES as usize {
                let _ = tokio::time::timeout(CLEANUP_TIMEOUT, file.close()).await;
                return Err(SftpFailure::TooLarge.into());
            }
            out.extend_from_slice(&buffer[..read]);
        }
        file.close().await.map_err(|_| SftpFailure::Io)?;
        Ok(out)
    }

    /// 幂等删除对象；文件或父目录不存在视为成功。
    async fn remove_object(&self, sftp: &SftpSession, path: &str) -> ArchiveResult<()> {
        map_delete_result(sftp.remove_file(path.to_string()).await)
    }

    async fn put_inner(&self, key: &str, data: &[u8]) -> ArchiveResult<()> {
        let path = self.object_path(key)?;
        let (session, sftp) = self.connect_sftp().await?;
        let result = self.write_object(&sftp, &path, data).await;
        self.close_sftp(&session, &sftp).await;
        result
    }

    async fn get_inner(&self, key: &str) -> ArchiveResult<Vec<u8>> {
        let path = self.object_path(key)?;
        let (session, sftp) = self.connect_sftp().await?;
        let result = self.read_object(&sftp, &path).await;
        self.close_sftp(&session, &sftp).await;
        result
    }

    async fn delete_inner(&self, key: &str) -> ArchiveResult<()> {
        let path = self.object_path(key)?;
        let (session, sftp) = self.connect_sftp().await?;
        let result = self.remove_object(&sftp, &path).await;
        self.close_sftp(&session, &sftp).await;
        result
    }

    async fn head_inner(&self, key: &str) -> ArchiveResult<Option<ColdObjectMeta>> {
        let path = self.object_path(key)?;
        let (session, sftp) = self.connect_sftp().await?;
        let result = map_head_result(sftp.metadata(path.to_string()).await);
        self.close_sftp(&session, &sftp).await;
        result
    }

    /// 探针所在目录：`<remote_dir>/health`（`remote_dir = "/"` 时为 `/health`）。
    fn health_dir(&self) -> String {
        format!("{}/health", self.config.remote_dir.trim_end_matches('/'))
    }

    async fn test_inner(&self) -> ArchiveResult<()> {
        let key = format!("health/{}.probe", Uuid::new_v4().simple());
        let path = self.object_path(&key)?;
        let (session, sftp) = self.connect_sftp().await?;

        let probe = async {
            self.write_object(&sftp, &path, HEALTH_PROBE_PAYLOAD)
                .await?;
            let meta = sftp
                .metadata(path.to_string())
                .await
                .map_err(map_sftp_error)?;
            if meta.size != Some(HEALTH_PROBE_PAYLOAD.len() as u64) {
                return Err(SftpFailure::Protocol.into());
            }
            let read_back = self.read_object(&sftp, &path).await?;
            if read_back != HEALTH_PROBE_PAYLOAD {
                return Err(SftpFailure::Protocol.into());
            }
            Ok(())
        }
        .await;

        // 无论探针成功与否都尝试删除；不存在（例如 write 失败）按幂等成功处理。
        let cleanup = self.remove_object(&sftp, &path).await;
        // 仅当 health/ 为空时 remove_dir 才成功；非空（并发探针）或失败一律忽略。
        let _ = sftp.remove_dir(self.health_dir()).await;
        self.close_sftp(&session, &sftp).await;
        match (probe, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
        }
    }
}

#[async_trait]
impl ColdStore for SftpColdStore {
    async fn put(&self, key: &str, data: &[u8]) -> ArchiveResult<()> {
        self.put_inner(key, data).await
    }

    async fn get(&self, key: &str) -> ArchiveResult<Vec<u8>> {
        self.get_inner(key).await
    }

    async fn delete(&self, key: &str) -> ArchiveResult<()> {
        self.delete_inner(key).await
    }

    async fn head(&self, key: &str) -> ArchiveResult<Option<ColdObjectMeta>> {
        self.head_inner(key).await
    }

    async fn test(&self) -> ArchiveResult<()> {
        self.test_inner().await
    }
}

// ---------------------------------------------------------------------------
// 校验 / 错误映射
// ---------------------------------------------------------------------------

/// 重新校验对象 key：只允许相对路径片段与 `[A-Za-z0-9._-]`。
///
/// 拒绝绝对路径、`..` / `.` 段、空段、反斜杠与控制字符；即使调用方已经用
/// `build_object_keys` 生成过 key，这里也不信任它。
fn validate_object_key(key: &str) -> ArchiveResult<()> {
    if key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || key.starts_with('/')
        || key.ends_with('/')
        || key.contains("//")
        || key.contains("..")
        || key.contains('\\')
        || key.chars().any(char::is_control)
    {
        return Err(ArchiveError::InvalidKey);
    }
    if !key
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(ArchiveError::InvalidKey);
    }
    if key
        .split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(ArchiveError::InvalidKey);
    }
    Ok(())
}

/// 判断 SFTP 错误是否表示文件 / 父目录不存在。
///
/// `russh-sftp 3.0.1` 只实现 SFTP v3，`StatusCode` 中只有
/// `SSH_FX_NO_SUCH_FILE`（2），没有 v6 的 `SSH_FX_NO_SUCH_PATH`（10）；
/// 该版本遇到未知状态码会在反序列化阶段返回协议错误，不会构造 `Status`。
/// 因此这里只能匹配 `NoSuchFile`：OpenSSH 等 v3 服务器对缺失文件或缺失父
/// 目录均返回该码。升级到支持 `NoSuchPath` 的依赖时需要在此同步扩展。
fn is_not_found(error: &SftpError) -> bool {
    matches!(
        error,
        SftpError::Status(status) if status.status_code == StatusCode::NoSuchFile
    )
}

/// SFTP 错误 → 固定内部失败分类；不读取 / 不保存 status 的描述文本。
fn map_sftp_error(error: SftpError) -> SftpFailure {
    if is_not_found(&error) {
        SftpFailure::NotFound
    } else {
        SftpFailure::Io
    }
}

/// `head` 的 metadata 结果映射：文件或父目录不存在 → `Ok(None)`。
fn map_head_result(result: Result<Metadata, SftpError>) -> ArchiveResult<Option<ColdObjectMeta>> {
    match result {
        Ok(meta) => match meta.size {
            Some(size) => Ok(Some(ColdObjectMeta { size })),
            // 无法确认大小时返回固定错误，避免上传校验把对象误判成 0 字节。
            None => Err(SftpFailure::Protocol.into()),
        },
        Err(error) if is_not_found(&error) => Ok(None),
        Err(_) => Err(SftpFailure::Io.into()),
    }
}

/// `delete` 的 remove_file 结果映射：文件或父目录不存在 → 幂等成功。
fn map_delete_result(result: Result<(), SftpError>) -> ArchiveResult<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if is_not_found(&error) => Ok(()),
        Err(_) => Err(SftpFailure::Io.into()),
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) const TEST_HOST_PUBLIC_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6tkzHwktBtL3lofRHDFcZAOmWAo+XqV1ELwgnn4+NR rustboard-c3-fixture";
#[cfg(test)]
pub(crate) const TEST_HOST_FINGERPRINT: &str = "SHA256:nxKam8d6Yv8NNqv5pZBcaRKHGLPGLZGnuVG87WUuOzA";

#[cfg(test)]
pub(crate) fn test_config() -> ArchiveSftpConfig {
    ArchiveSftpConfig {
        host: "sftp.example.com".to_string(),
        port: 22,
        username: "ops".to_string(),
        password: "test-password".to_string(),
        private_key_path: String::new(),
        remote_dir: "/backup/rustboard".to_string(),
        host_key_fingerprint: TEST_HOST_FINGERPRINT.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::Status;

    fn handler_for(fingerprint: &str) -> SftpHostKeyHandler {
        SftpHostKeyHandler {
            expected: decode_host_key_fingerprint(fingerprint).expect("测试指纹必须可解析"),
        }
    }

    fn status_error(code: StatusCode, message: &str) -> SftpError {
        SftpError::Status(Status {
            id: 1,
            status_code: code,
            error_message: message.to_string(),
            language_tag: "en".to_string(),
        })
    }

    fn store() -> SftpColdStore {
        SftpColdStore::new(&test_config()).expect("测试配置必须合法")
    }

    /// 固定的测试主机公钥必须与硬编码的 SHA256 指纹一致。
    #[tokio::test]
    async fn host_key_accepts_configured_fingerprint() {
        let key = PublicKey::from_openssh(TEST_HOST_PUBLIC_KEY).expect("测试公钥必须可解析");
        let mut handler = handler_for(TEST_HOST_FINGERPRINT);
        assert!(handler.check_server_key(&key).await.expect("校验不应报错"));
    }

    /// 配置允许末尾一个 `=`（44 字符）；比较必须与无填充形式等价。
    #[tokio::test]
    async fn host_key_accepts_trailing_base64_padding() {
        assert_eq!(
            decode_host_key_fingerprint(&format!("{TEST_HOST_FINGERPRINT}=")),
            decode_host_key_fingerprint(TEST_HOST_FINGERPRINT)
        );
        let key = PublicKey::from_openssh(TEST_HOST_PUBLIC_KEY).expect("测试公钥必须可解析");
        let mut handler = handler_for(&format!("{TEST_HOST_FINGERPRINT}="));
        assert!(handler.check_server_key(&key).await.expect("校验不应报错"));
    }

    /// 指纹不符时 handler 必须返回 Ok(false)，不能接受任意主机密钥。
    #[tokio::test]
    async fn host_key_rejects_mismatched_fingerprint() {
        let key = PublicKey::from_openssh(TEST_HOST_PUBLIC_KEY).expect("测试公钥必须可解析");
        let mut handler = SftpHostKeyHandler {
            expected: [0u8; 32],
        };
        assert!(!handler.check_server_key(&key).await.expect("校验不应报错"));
    }

    #[test]
    fn host_key_fingerprint_rejects_invalid_forms() {
        for invalid in [
            "",
            "SHA256:",
            "SHA1:nxKam8d6Yv8NNqv5pZBcaRKHGLPGLZGnuVG87WUuOzA",
            "SHA256:AAAA",
            "SHA256:!!!!",
            // 长度不是 43 / 44，无法得到 32 字节摘要。
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            // 44 字符但末尾不是 `=`。
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "SHA256: nxKam8d6Yv8NNqv5pZBcaRKHGLPGLZGnuVG87WUuOzA",
        ] {
            assert!(
                decode_host_key_fingerprint(invalid).is_none(),
                "非法指纹必须拒绝: {invalid:?}"
            );
        }
    }

    #[test]
    fn object_path_uses_configured_remote_dir_only() {
        let store = store();
        assert_eq!(
            store
                .object_path("rustboard/2026/10/24/part-00001.csv.gz")
                .expect("合法 key 必须接受"),
            "/backup/rustboard/rustboard/2026/10/24/part-00001.csv.gz"
        );
        assert_eq!(
            store.object_path("health/probe.probe").unwrap(),
            "/backup/rustboard/health/probe.probe"
        );
    }

    #[test]
    fn object_key_validation_rejects_traversal_and_absolute_paths() {
        let store = store();
        for invalid in [
            "",
            "/etc/passwd",
            "../escape",
            "a/../b",
            "a/./b",
            "a//b",
            "a/b/",
            "a\\b",
            "a\nb",
            "a\tb",
            "a b",
            "a?b",
            "a#b",
        ] {
            assert_eq!(
                store.object_path(invalid).unwrap_err(),
                ArchiveError::InvalidKey,
                "非法 key 必须拒绝: {invalid:?}"
            );
        }
        for valid in [
            "rustboard/2026/10/24/part-00001.csv.gz",
            "health/4f4e2f2f-0f6c-4e3c-9e9f-0f6c4e3c9e9f.probe",
            "a.b_c-d/e.f",
        ] {
            assert!(
                store.object_path(valid).is_ok(),
                "合法 key 必须接受: {valid:?}"
            );
        }
    }

    /// 探针目录必须固定落在 remote_dir 下（remote_dir="/" 时退化为 /health）。
    #[test]
    fn health_probe_dir_is_under_remote_dir() {
        assert_eq!(store().health_dir(), "/backup/rustboard/health");

        let mut config = test_config();
        config.remote_dir = "/".to_string();
        let root = SftpColdStore::new(&config).expect("remote_dir=/ 必须合法");
        assert_eq!(root.health_dir(), "/health");
    }

    /// 缺失文件 / 父目录（SFTP v3 统一为 `NoSuchFile`）在 head/get/delete 中按
    /// 不存在处理；status 描述文本不参与判定。
    #[test]
    fn missing_file_or_parent_is_absent_for_head_get_delete() {
        for message in ["No such file", "No such file or directory", "No such path"] {
            let error = status_error(StatusCode::NoSuchFile, message);
            assert!(is_not_found(&error));
            assert_eq!(map_head_result(Err(error.clone())).unwrap(), None);
            assert!(map_delete_result(Err(error.clone())).is_ok());
            assert_eq!(
                ArchiveError::from(map_sftp_error(error)),
                ArchiveError::NotFound
            );
        }

        let meta = Metadata {
            size: Some(7),
            ..Default::default()
        };
        assert_eq!(
            map_head_result(Ok(meta)).unwrap(),
            Some(ColdObjectMeta { size: 7 })
        );
        assert_eq!(
            map_head_result(Ok(Metadata::default())).unwrap_err(),
            ArchiveError::BackendUnavailable
        );
    }

    /// 非缺失状态码（包括 Failure）一律按后端错误处理，不能因描述文本伪装成
    /// 缺失对象。
    #[test]
    fn non_missing_statuses_are_backend_errors() {
        for code in [
            StatusCode::PermissionDenied,
            StatusCode::Failure,
            StatusCode::OpUnsupported,
            StatusCode::NoConnection,
        ] {
            let error = status_error(code, "No such file");
            assert!(!is_not_found(&error), "状态码 {code:?} 不能按缺失处理");
            assert_eq!(
                map_head_result(Err(error.clone())).unwrap_err(),
                ArchiveError::BackendUnavailable
            );
            assert_eq!(
                map_delete_result(Err(error.clone())).unwrap_err(),
                ArchiveError::BackendUnavailable
            );
            assert_eq!(
                ArchiveError::from(map_sftp_error(error)),
                ArchiveError::BackendUnavailable
            );
        }
    }

    /// Unix 上私钥必须只能由 owner 访问；0644 在构造期即固定失败。
    #[cfg(unix)]
    #[test]
    fn private_key_permissions_must_be_owner_only() {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let path = std::env::temp_dir().join(format!(
            "rustboard-sftp-key-{}.tmp",
            Uuid::new_v4().simple()
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("创建临时私钥失败");
        file.write_all(b"not-a-real-private-key").unwrap();
        drop(file);

        let path_text = path.to_str().expect("临时目录必须为 UTF-8").to_string();
        assert_eq!(check_private_key_permissions(&path_text), Ok(()));

        let mut config = test_config();
        config.password = String::new();
        config.private_key_path = path_text.clone();
        assert!(SftpColdStore::new(&config).is_ok());

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            check_private_key_permissions(&path_text),
            Err(SftpFailure::KeyPermissions)
        );
        let error = SftpColdStore::new(&config)
            .err()
            .expect("0644 私钥必须拒绝");
        assert_eq!(error, ArchiveError::BackendUnavailable);
        assert_eq!(error.to_string(), "冷存储后端不可用");

        let missing = std::env::temp_dir().join(format!(
            "rustboard-sftp-missing-{}.tmp",
            Uuid::new_v4().simple()
        ));
        assert_eq!(
            check_private_key_permissions(missing.to_str().expect("临时目录必须为 UTF-8")),
            Err(SftpFailure::KeyPermissions)
        );

        std::fs::remove_file(&path).ok();
    }

    /// 构造错误只返回固定文案，绝不回显 host / 用户名 / 密码 / 私钥路径 /
    /// 远端目录 / 指纹。
    #[test]
    fn constructor_error_never_leaks_configuration() {
        let mut config = test_config();
        config.host = "secret-host.invalid".to_string();
        config.username = "secret-user".to_string();
        config.password = "secret-password".to_string();
        config.private_key_path = "/secret/private/key".to_string();
        config.remote_dir = "/secret/remote/dir".to_string();
        config.host_key_fingerprint = "SHA256:not-a-valid-fingerprint".to_string();

        let error = SftpColdStore::new(&config).err().expect("非法指纹必须失败");
        let text = error.to_string();
        assert_eq!(text, "冷存储后端不可用");
        for secret in [
            config.host.as_str(),
            config.username.as_str(),
            config.password.as_str(),
            config.private_key_path.as_str(),
            config.remote_dir.as_str(),
            config.host_key_fingerprint.as_str(),
        ] {
            assert!(!text.contains(secret), "错误泄露配置: {text}");
        }
    }

    /// 连接 / 主机密钥 / 认证 / 协议 / IO / 超大对象分别固定分类，对外只
    /// 暴露 `BackendUnavailable`（NotFound 映射为 `NotFound`）。
    #[test]
    fn failure_categories_map_to_fixed_archive_errors() {
        for failure in [
            SftpFailure::Connect,
            SftpFailure::HostKey,
            SftpFailure::Auth,
            SftpFailure::KeyPermissions,
            SftpFailure::Protocol,
            SftpFailure::Io,
            SftpFailure::TooLarge,
        ] {
            let error = ArchiveError::from(failure);
            assert_eq!(error, ArchiveError::BackendUnavailable);
            assert_eq!(error.to_string(), "冷存储后端不可用");
            assert!(!failure.reason().is_empty());
        }
        assert_eq!(
            ArchiveError::from(SftpFailure::NotFound),
            ArchiveError::NotFound
        );
    }

    /// 缺少 host_key_fingerprint / 非 SHA256 / 非法 base64 均在构造期失败，
    /// 不会进入网络阶段。
    #[test]
    fn constructor_rejects_missing_or_invalid_fingerprint() {
        let mut config = test_config();
        config.host_key_fingerprint = String::new();
        assert_eq!(
            SftpColdStore::new(&config).err(),
            Some(ArchiveError::BackendUnavailable)
        );

        config.host_key_fingerprint = "SHA512:AAAA".to_string();
        assert_eq!(
            SftpColdStore::new(&config).err(),
            Some(ArchiveError::BackendUnavailable)
        );
    }

    /// 密码与私钥都为空、remote_dir 非绝对路径等配置错误也固定失败。
    #[test]
    fn constructor_rejects_invalid_configuration() {
        let mut config = test_config();
        config.password = String::new();
        config.private_key_path = String::new();
        assert_eq!(
            SftpColdStore::new(&config).err(),
            Some(ArchiveError::BackendUnavailable)
        );

        let mut config = test_config();
        config.remote_dir = "relative/dir".to_string();
        assert_eq!(
            SftpColdStore::new(&config).err(),
            Some(ArchiveError::BackendUnavailable)
        );
    }
}
