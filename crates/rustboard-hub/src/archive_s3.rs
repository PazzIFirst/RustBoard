//! M4-C2a/C2b：S3 / MinIO 冷存储实现。
//!
//! 本模块提供 [`S3ColdStore`]（`rustboard_core::archive::ColdStore` 的 S3 后端）
//! 与构造器 [`build_s3_store`]；C2b 起由 `archive::build_store` 接线到归档
//! worker、`archive run/test` 与下载 API。
//!
//! 安全约定：
//! - 所有对外错误都映射为 [`ArchiveError`] 的固定分类，**绝不**拼接
//!   endpoint / bucket / access key / secret / 上游响应正文；本模块也不打印配置；
//! - 对象 key 只接受 C1a 生成的相对 key（字符白名单、拒绝 `..` 与绝对路径），
//!   不接受任何外部拼接的路径；
//! - [`ColdStore::get`] 在读取前检查对象大小，超过 [`MAX_OBJECT_BYTES`]（1 GiB）
//!   直接拒绝，避免后端异常对象打爆内存；
//! - 健康检查只写 `health/` 前缀的随机探针对象，失败时尽力删除，不写真实归档目录；
//! - 构造 [`AmazonS3Builder`] 不发网络请求：凭据、endpoint 只是填入配置，
//!   连通性由 [`ColdStore::test`] / `archive test` 显式触发。
//!
//! TLS：`object_store` 只启用 `aws-base` + `reqwest` + `ring`，不使用会拉入
//! aws-lc-rs 的 `aws` feature；reqwest 0.13 由 hub 的 `reqwest13` 别名启用
//! `rustls-no-provider`，因此这里在进程内安装一次 ring provider（重复安装无害）。

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{ClientOptions, ObjectStore, ObjectStoreExt, PutPayload, RetryConfig};
use rustboard_common::config::ArchiveS3Config;
use rustboard_core::archive::{ArchiveError, ArchiveResult, ColdObjectMeta, ColdStore};

/// 单个对象读取 / 写入的硬上限（1 GiB）。
///
/// 归档对象大小由调用方按 `archive.max_object_bytes`（≤ 1 GiB）控制；这里再设
/// 一道防御，防止数据库 key 指向异常大对象时一次性分配过多内存。
pub const MAX_OBJECT_BYTES: u64 = 1024 * 1024 * 1024;

/// S3 对象 key 的字节上限（S3 规范）。
const MAX_KEY_BYTES: usize = 1024;

/// 健康探针对象 key 前缀。
const HEALTH_PROBE_PREFIX: &str = "health/";

/// 健康探针写入的固定内容（不含任何配置或凭据）。
const HEALTH_PROBE_PAYLOAD: &[u8] = b"rustboard-archive-health-probe";

/// 建连超时：避免不可达 endpoint 长期占住归档任务。
const S3_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 单次请求总超时：32 MiB 分片在慢链路上的宽裕上限。
const S3_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
/// 最大重试次数（不含首次请求），不做无限重试。
const S3_MAX_RETRIES: usize = 2;
/// 重试总窗口：超过后不再重试，直接返回固定错误。
const S3_RETRY_TIMEOUT: Duration = Duration::from_secs(30);

/// 基于 `object_store` 的 S3 / MinIO 冷存储。
///
/// 对象 key 直接使用 bucket 内的相对路径；C1a 的 `build_object_keys` 已经包含
/// 配置的 prefix，本实现不再额外拼接前缀。
pub struct S3ColdStore {
    store: Arc<dyn ObjectStore>,
    /// 单对象读取上限；生产固定为 [`MAX_OBJECT_BYTES`]，测试可注入更小值。
    max_object_bytes: u64,
}

impl S3ColdStore {
    /// 用注入的 [`ObjectStore`] 构造。
    ///
    /// 面向测试（`object_store::memory::InMemory`）与后续复用；生产路径请用
    /// [`build_s3_store`]，它会校验配置并构造真实的 `AmazonS3` 客户端。
    pub fn with_store(store: Arc<dyn ObjectStore>) -> Self {
        Self {
            store,
            max_object_bytes: MAX_OBJECT_BYTES,
        }
    }

    /// 测试专用：注入自定义读取上限。
    #[cfg(test)]
    fn with_store_limit(store: Arc<dyn ObjectStore>, max_object_bytes: u64) -> Self {
        Self {
            store,
            max_object_bytes,
        }
    }

    /// 把合法的相对 key 转成 `object_store::path::Path`。
    ///
    /// 规则比 C1a 的 `build_object_keys` 更保守：只允许
    /// `[A-Za-z0-9._/-]`、非空、≤ 1024 字节、不以 `/` 开头或结尾、无 `//`、
    /// 无 `.` / `..` 段、无反斜杠。任何不满足的 key 都返回
    /// [`ArchiveError::InvalidKey`]，不会传到后端。
    fn object_path(key: &str) -> ArchiveResult<ObjectPath> {
        if key.is_empty()
            || key.len() > MAX_KEY_BYTES
            || key.starts_with('/')
            || key.ends_with('/')
            || key.contains("//")
            || key.contains("..")
            || key.contains('\\')
        {
            return Err(ArchiveError::InvalidKey);
        }
        if !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        {
            return Err(ArchiveError::InvalidKey);
        }
        if key
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        {
            return Err(ArchiveError::InvalidKey);
        }
        Ok(ObjectPath::from(key))
    }

    /// `put` 的错误统一为后端不可用；key 非法在进入这里之前已返回。
    async fn put_inner(&self, key: &str, data: &[u8]) -> ArchiveResult<()> {
        let path = Self::object_path(key)?;
        if data.len() as u64 > MAX_OBJECT_BYTES {
            return Err(ArchiveError::BackendUnavailable);
        }
        self.store
            .put(&path, PutPayload::from(data.to_vec()))
            .await
            .map(|_| ())
            .map_err(|_| ArchiveError::BackendUnavailable)
    }

    /// 读取对象；不存在返回 `NotFound`，其它错误（含超大对象）返回后端不可用。
    async fn get_inner(&self, key: &str) -> ArchiveResult<Vec<u8>> {
        let path = Self::object_path(key)?;
        let result = self.store.get(&path).await.map_err(map_read_error)?;
        if result.meta.size > self.max_object_bytes {
            return Err(ArchiveError::BackendUnavailable);
        }
        let data = result.bytes().await.map_err(map_read_error)?;
        // 防御后端 meta.size 与实际 body 不一致的情况。
        if data.len() as u64 > self.max_object_bytes {
            return Err(ArchiveError::BackendUnavailable);
        }
        Ok(data.to_vec())
    }

    /// 删除对象；不存在按成功处理（幂等）。
    async fn delete_inner(&self, key: &str) -> ArchiveResult<()> {
        let path = Self::object_path(key)?;
        match self.store.delete(&path).await {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(_) => Err(ArchiveError::BackendUnavailable),
        }
    }

    /// 查询对象元数据；不存在返回 `Ok(None)`。
    async fn head_inner(&self, key: &str) -> ArchiveResult<Option<ColdObjectMeta>> {
        let path = Self::object_path(key)?;
        match self.store.head(&path).await {
            Ok(meta) => Ok(Some(ColdObjectMeta { size: meta.size })),
            Err(error) if is_not_found(&error) => Ok(None),
            Err(_) => Err(ArchiveError::BackendUnavailable),
        }
    }

    /// 生成 `health/<uuid>.probe` 形式的随机探针 key。
    fn probe_key() -> String {
        format!(
            "{HEALTH_PROBE_PREFIX}{}.probe",
            uuid::Uuid::new_v4().simple()
        )
    }
}

#[async_trait]
impl ColdStore for S3ColdStore {
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

    /// 写 / 读 / 删一个 `health/` 前缀的随机探针对象。
    ///
    /// 失败时仍尝试删除探针，避免在后端留下垃圾；但原始错误优先返回，清理失败
    /// 不会覆盖真正的故障原因。成功路径只删除一次，删除失败按后端不可用处理。
    async fn test(&self) -> ArchiveResult<()> {
        let key = Self::probe_key();
        let probe = async {
            self.put_inner(&key, HEALTH_PROBE_PAYLOAD).await?;
            let read_back = self.get_inner(&key).await?;
            if read_back.as_slice() != HEALTH_PROBE_PAYLOAD {
                return Err(ArchiveError::BackendUnavailable);
            }
            Ok(())
        }
        .await;

        let cleanup = self.delete_inner(&key).await;
        match probe {
            Ok(()) => cleanup,
            // 尽力清理；不把清理失败暴露给调用方，也不泄露后端细节。
            Err(error) => {
                let _ = cleanup;
                Err(error)
            }
        }
    }
}

/// 用管理端配置构造真实 S3 客户端。
///
/// 只做配置校验与客户端构建，**不发起网络请求**。`endpoint` 为空表示 AWS，
/// 强制 virtual-hosted style（配置里的 `path_style = true` 只用于 MinIO 等自建
/// 服务，避免默认值把 AWS 请求改成已不推荐的 path-style）；`endpoint` 非空时
/// 按 `path_style` 选择寻址方式，并仅在 `http://` 时允许明文 HTTP。
pub fn build_s3_store(cfg: &ArchiveS3Config) -> ArchiveResult<S3ColdStore> {
    cfg.validate()
        .map_err(|_| ArchiveError::BackendUnavailable)?;
    install_ring_provider();

    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(&cfg.bucket)
        .with_region(&cfg.region)
        .with_access_key_id(&cfg.access_key_id)
        .with_secret_access_key(&cfg.secret_access_key)
        .with_retry(RetryConfig {
            max_retries: S3_MAX_RETRIES,
            retry_timeout: S3_RETRY_TIMEOUT,
            ..RetryConfig::default()
        })
        .with_client_options(
            ClientOptions::new()
                .with_connect_timeout(S3_CONNECT_TIMEOUT)
                .with_timeout(S3_REQUEST_TIMEOUT),
        );

    if cfg.endpoint.is_empty() {
        // AWS：`with_virtual_hosted_style_request(true)` 才是 virtual-hosted style；
        // region 已由 config 校验保证非空。
        builder = builder.with_virtual_hosted_style_request(true);
    } else {
        builder = builder
            .with_endpoint(&cfg.endpoint)
            .with_virtual_hosted_style_request(!cfg.path_style);
        // 仅当配置明确是 http:// 时放开明文；https 保持默认。
        if cfg.endpoint.starts_with("http://") {
            builder = builder.with_allow_http(true);
        }
    }

    // 构造失败只可能是配置/客户端初始化问题；错误内容可能包含 endpoint，
    // 因此映射为固定分类，绝不外泄。
    let store = builder
        .build()
        .map_err(|_| ArchiveError::BackendUnavailable)?;
    Ok(S3ColdStore::with_store(Arc::new(store)))
}

/// 安装 ring 加密 provider。
///
/// object_store 的 reqwest 传递依赖启用了 `rustls-no-provider`；reqwest 建 client
/// 时若进程没有默认 provider 会 panic。安装失败说明已有 provider，保持现状即可。
fn install_ring_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn is_not_found(error: &object_store::Error) -> bool {
    matches!(error, object_store::Error::NotFound { .. })
}

/// 读取错误映射：只有明确不存在才返回 `NotFound`，其余一律固定后端不可用。
fn map_read_error(error: object_store::Error) -> ArchiveError {
    if is_not_found(&error) {
        ArchiveError::NotFound
    } else {
        ArchiveError::BackendUnavailable
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use futures_util::stream::BoxStream;
    use futures_util::TryStreamExt;
    use object_store::memory::InMemory;
    use object_store::path::Path as ObjectPath;
    use object_store::{
        CopyOptions, GetOptions, GetResult, ListResult, MultipartUpload, ObjectMeta, ObjectStore,
        PutMultipartOptions, PutOptions, PutResult, Result as ObjectResult,
    };

    use super::*;

    const LEAKY: &str = "https://minio.internal/secret-bucket?X-Amz-Credential=AKIA_LEAK";

    fn sample_key() -> &'static str {
        "rustboard/2026/10/24/part-00001.csv.gz"
    }

    #[tokio::test]
    async fn put_get_head_delete_roundtrip() {
        let store = Arc::new(InMemory::new());
        let cold = S3ColdStore::with_store(store.clone());
        let data = b"agent_id,metric,labels,ts,value\n";

        cold.put(sample_key(), data).await.unwrap();
        assert_eq!(
            cold.head(sample_key()).await.unwrap(),
            Some(ColdObjectMeta {
                size: data.len() as u64
            })
        );
        assert_eq!(cold.get(sample_key()).await.unwrap(), data);

        cold.delete(sample_key()).await.unwrap();
        assert_eq!(cold.head(sample_key()).await.unwrap(), None);
        assert_eq!(
            cold.get(sample_key()).await.unwrap_err(),
            ArchiveError::NotFound
        );
        // 删除不存在的对象是幂等的。
        cold.delete(sample_key()).await.unwrap();
    }

    #[tokio::test]
    async fn missing_key_maps_to_not_found() {
        let cold = S3ColdStore::with_store(Arc::new(InMemory::new()));
        assert_eq!(
            cold.get("rustboard/2026/10/24/part-99999.csv.gz")
                .await
                .unwrap_err(),
            ArchiveError::NotFound
        );
        assert_eq!(
            cold.head("rustboard/2026/10/24/part-99999.csv.gz")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn rejects_keys_outside_c1_schema() {
        let cold = S3ColdStore::with_store(Arc::new(InMemory::new()));
        let long_key = "a".repeat(MAX_KEY_BYTES + 1);
        let invalid = [
            "",
            "/absolute/object.csv.gz",
            "../escape.csv.gz",
            "rustboard/../../escape.csv.gz",
            "rustboard//part-00001.csv.gz",
            "rustboard/./part-00001.csv.gz",
            "rustboard\\part-00001.csv.gz",
            "rustboard/part 00001.csv.gz",
            "rustboard/part-00001.csv.gz?x=1",
            "rustboard/part-00001.csv.gz#frag",
            long_key.as_str(),
        ];
        for key in invalid {
            assert_eq!(
                cold.put(key, b"x").await.unwrap_err(),
                ArchiveError::InvalidKey,
                "put 应拒绝 key {key:?}"
            );
            assert_eq!(
                cold.get(key).await.unwrap_err(),
                ArchiveError::InvalidKey,
                "get 应拒绝 key {key:?}"
            );
            assert_eq!(
                cold.head(key).await.unwrap_err(),
                ArchiveError::InvalidKey,
                "head 应拒绝 key {key:?}"
            );
            assert_eq!(
                cold.delete(key).await.unwrap_err(),
                ArchiveError::InvalidKey,
                "delete 应拒绝 key {key:?}"
            );
        }
    }

    #[tokio::test]
    async fn get_rejects_object_over_limit() {
        let inner = Arc::new(InMemory::new());
        let key = "rustboard/2026/10/24/part-00001.csv.gz";
        inner
            .put(&ObjectPath::from(key), PutPayload::from(vec![0u8; 32]))
            .await
            .unwrap();

        let cold = S3ColdStore::with_store_limit(inner, 16);
        assert_eq!(
            cold.get(key).await.unwrap_err(),
            ArchiveError::BackendUnavailable
        );
        // head 仍应报告真实大小，便于调用方判断对象是否异常。
        assert_eq!(
            cold.head(key).await.unwrap(),
            Some(ColdObjectMeta { size: 32 })
        );
    }

    #[tokio::test]
    async fn test_writes_reads_and_cleans_probe() {
        let inner = Arc::new(InMemory::new());
        let cold = S3ColdStore::with_store(inner.clone());

        cold.test().await.unwrap();

        let remaining: Vec<ObjectMeta> = inner.list(None).try_collect().await.unwrap();
        assert!(
            remaining.is_empty(),
            "健康探针必须清理干净，实际残留 {:?}",
            remaining
        );
    }

    #[tokio::test]
    async fn test_failure_is_sanitized_and_attempts_cleanup() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fake = FakeStore {
            calls: calls.clone(),
            leak: LEAKY,
        };
        let cold = S3ColdStore::with_store(Arc::new(fake));

        let error = cold.test().await.unwrap_err();
        assert_eq!(error, ArchiveError::BackendUnavailable);
        assert_no_leak(&error);

        let calls = calls.lock().unwrap().clone();
        assert!(calls.contains(&"put"), "应尝试写入探针：{calls:?}");
        assert!(
            calls.contains(&"delete"),
            "写入失败后仍应尽力清理探针：{calls:?}"
        );
    }

    #[tokio::test]
    async fn errors_are_sanitized_for_all_operations() {
        let fake = FakeStore {
            calls: Arc::new(Mutex::new(Vec::new())),
            leak: LEAKY,
        };
        let cold = S3ColdStore::with_store(Arc::new(fake));

        let errors = [
            cold.put(sample_key(), b"x").await.unwrap_err(),
            cold.get(sample_key()).await.unwrap_err(),
            cold.head(sample_key()).await.unwrap_err(),
            cold.delete(sample_key()).await.unwrap_err(),
        ];
        for error in errors {
            assert_eq!(error, ArchiveError::BackendUnavailable);
            assert_no_leak(&error);
        }
    }

    #[test]
    fn build_s3_store_validates_config_without_network() {
        // 空配置（缺 bucket / region / 凭据）必须被拒绝，且错误不包含配置内容。
        let result = build_s3_store(&ArchiveS3Config::default());
        assert!(result.is_err());
        let error = result.err().expect("已确认是 Err");
        assert_eq!(error, ArchiveError::BackendUnavailable);
        assert_no_leak(&error);

        // 非法 endpoint scheme 同样拒绝。
        let mut cfg = valid_http_config();
        cfg.endpoint = "ftp://minio.internal".to_string();
        assert_eq!(
            build_s3_store(&cfg).err(),
            Some(ArchiveError::BackendUnavailable)
        );

        // 合法 http endpoint：只构造客户端，不连接。
        let store = build_s3_store(&valid_http_config()).unwrap();
        drop(store);

        // AWS（endpoint 为空）+ 默认 path_style = true 也必须能构造。
        let mut aws = valid_http_config();
        aws.endpoint.clear();
        let store = build_s3_store(&aws).unwrap();
        drop(store);
    }

    fn valid_http_config() -> ArchiveS3Config {
        ArchiveS3Config {
            bucket: "rustboard-test".to_string(),
            region: "us-east-1".to_string(),
            endpoint: "http://127.0.0.1:9000".to_string(),
            access_key_id: "test-access-key".to_string(),
            secret_access_key: "test-secret-key".to_string(),
            path_style: true,
        }
    }

    fn assert_no_leak(error: &ArchiveError) {
        let message = format!("{error}");
        assert!(
            !message.contains("minio.internal"),
            "错误泄露 endpoint：{message}"
        );
        assert!(
            !message.contains("secret-bucket"),
            "错误泄露 bucket：{message}"
        );
        assert!(!message.contains("AKIA"), "错误泄露 access key：{message}");
        assert!(!message.contains("secret"), "错误泄露 secret：{message}");
    }

    /// 所有操作都返回带敏感信息的 `Generic` 错误，用于验证脱敏与清理路径。
    #[derive(Debug)]
    struct FakeStore {
        calls: Arc<Mutex<Vec<&'static str>>>,
        leak: &'static str,
    }

    impl std::fmt::Display for FakeStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("fake-store")
        }
    }

    impl FakeStore {
        fn record(&self, call: &'static str) {
            self.calls.lock().unwrap().push(call);
        }

        fn error(&self) -> object_store::Error {
            object_store::Error::Generic {
                store: "fake-store",
                source: self.leak.to_string().into(),
            }
        }
    }

    #[async_trait]
    impl ObjectStore for FakeStore {
        async fn put_opts(
            &self,
            _location: &ObjectPath,
            _payload: PutPayload,
            _opts: PutOptions,
        ) -> ObjectResult<PutResult> {
            self.record("put");
            Err(self.error())
        }

        async fn put_multipart_opts(
            &self,
            _location: &ObjectPath,
            _opts: PutMultipartOptions,
        ) -> ObjectResult<Box<dyn MultipartUpload>> {
            unimplemented!("fake store 不支持 multipart")
        }

        async fn get_opts(
            &self,
            _location: &ObjectPath,
            _options: GetOptions,
        ) -> ObjectResult<GetResult> {
            self.record("get");
            Err(self.error())
        }

        fn delete_stream(
            &self,
            _locations: BoxStream<'static, ObjectResult<ObjectPath>>,
        ) -> BoxStream<'static, ObjectResult<ObjectPath>> {
            self.record("delete");
            let leak = self.leak;
            Box::pin(futures_util::stream::once(async move {
                Err(object_store::Error::Generic {
                    store: "fake-store",
                    source: leak.to_string().into(),
                })
            }))
        }

        fn list(
            &self,
            _prefix: Option<&ObjectPath>,
        ) -> BoxStream<'static, ObjectResult<ObjectMeta>> {
            Box::pin(futures_util::stream::empty())
        }

        async fn list_with_delimiter(
            &self,
            _prefix: Option<&ObjectPath>,
        ) -> ObjectResult<ListResult> {
            unimplemented!("fake store 不支持 list_with_delimiter")
        }

        async fn copy_opts(
            &self,
            _from: &ObjectPath,
            _to: &ObjectPath,
            _options: CopyOptions,
        ) -> ObjectResult<()> {
            unimplemented!("fake store 不支持 copy")
        }
    }
}
