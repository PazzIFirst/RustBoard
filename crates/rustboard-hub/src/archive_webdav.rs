//! M4-C1b：WebDAV 冷存储后端。
//!
//! 只使用现有 `reqwest`（rustls）实现 `ColdStore` 的 `PUT / GET / DELETE / HEAD`
//! 与探针 `test`，不引入新依赖：
//!
//! - base URL 来自 `hub.toml` 的 `[archive.webdav].url`，对象 key 只能由
//!   [`rustboard_core::archive::build_object_keys`] 或本模块的探针生成；本模块
//!   仍会再次校验 key（拒绝绝对路径、`..`、空段、反斜杠与控制字符），不拼接
//!   任何外部输入；
//! - Basic auth 只出现在请求头，**不写日志、不进入错误**；客户端固定
//!   `.no_proxy()`、总超时、禁止重定向（避免把凭据带到别的主机）；
//! - 非 2xx 统一映射为固定 [`ArchiveError`]，不透传 reqwest 错误串、URL、
//!   用户名 / 密码或响应正文；`HEAD` / `GET` 的 404 分别映射为 `None` /
//!   [`ArchiveError::NotFound`]，`DELETE` 的 404 按幂等成功处理；
//! - `put` 按 key 后缀设置 `Content-Type`：`.csv.gz` → `application/gzip`，
//!   `.manifest.json` → `application/json`，其余探针对象用
//!   `application/octet-stream`；
//! - `head` 只返回对象大小，不暴露 ETag / URL / 响应头。
//!
//! 网络层不打印任何后端信息；失败时上层只看到固定的中文错误。

use std::time::Duration;

use async_trait::async_trait;
use axum::http::header;
use reqwest::redirect::Policy;
use reqwest::Url;
use rustboard_common::config::ArchiveWebdavConfig;
use rustboard_core::archive::{ArchiveError, ArchiveResult, ColdObjectMeta, ColdStore};

/// 单次 WebDAV 请求总超时（连接 + 发送 + 读取响应头 / body）。
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `get` 允许读取的最大对象字节数（与配置上限 1 GiB 对齐）。
///
/// `ColdStore::get` 返回完整 `Vec<u8>`，设置硬上限避免恶意 / 配置错误的后端
/// 用超大响应打爆内存。
const MAX_GET_OBJECT_BYTES: usize = 1024 * 1024 * 1024;

/// key 最大字节数；正常对象 key 由 prefix + 日期 + 分片组成，远小于该值。
const MAX_KEY_BYTES: usize = 1024;

/// WebDAV 冷存储实现。
///
/// 不实现 `Debug`：结构体持有 Basic auth 密码，任何诊断输出都不应带出。
pub struct WebdavColdStore {
    client: reqwest::Client,
    base: Url,
    username: String,
    password: String,
}

impl WebdavColdStore {
    /// 构造后端；只校验本地配置与 URL，不发起网络请求。
    ///
    /// 配置错误与客户端构建失败都映射为 [`ArchiveError::BackendUnavailable`]：
    /// 上层只需要知道「后端不可用」，错误字符串不包含 URL 或凭据。
    pub fn new(config: &ArchiveWebdavConfig) -> ArchiveResult<Self> {
        let mut base = Url::parse(&config.url).map_err(|_| ArchiveError::BackendUnavailable)?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(ArchiveError::BackendUnavailable);
        }
        if base.host_str().is_none() || base.cannot_be_a_base() {
            return Err(ArchiveError::BackendUnavailable);
        }
        // URL 里自带 userinfo 会让凭据来源不明确（且可能进日志），一律拒绝。
        if !base.username().is_empty() || base.password().is_some() {
            return Err(ArchiveError::BackendUnavailable);
        }
        if base.query().is_some() || base.fragment().is_some() {
            return Err(ArchiveError::BackendUnavailable);
        }
        // 配置校验已要求非空；这里再兜一次，避免 `archive test` 在 disabled
        // 配置上发出没有意义的 Basic auth。
        if config.username.is_empty() || config.password.is_empty() {
            return Err(ArchiveError::BackendUnavailable);
        }
        if !base.path().ends_with('/') {
            base.set_path(&format!("{}/", base.path()));
        }

        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| ArchiveError::BackendUnavailable)?;

        Ok(Self {
            client,
            base,
            username: config.username.clone(),
            password: config.password.clone(),
        })
    }

    /// 把已校验的 key 拼到固定 base URL 上。
    fn object_url(&self, key: &str) -> ArchiveResult<Url> {
        validate_key(key)?;
        self.base.join(key).map_err(|_| ArchiveError::InvalidKey)
    }

    async fn require_success(response: reqwest::Response) -> ArchiveResult<reqwest::Response> {
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(ArchiveError::BackendUnavailable)
        }
    }
}

#[async_trait]
impl ColdStore for WebdavColdStore {
    async fn put(&self, key: &str, data: &[u8]) -> ArchiveResult<()> {
        let url = self.object_url(key)?;
        let response = self
            .client
            .put(url)
            .basic_auth(&self.username, Some(&self.password))
            .header(header::CONTENT_TYPE, content_type_for(key))
            .body(data.to_vec())
            .send()
            .await
            .map_err(|_| ArchiveError::BackendUnavailable)?;
        Self::require_success(response).await.map(|_| ())
    }

    async fn get(&self, key: &str) -> ArchiveResult<Vec<u8>> {
        let url = self.object_url(key)?;
        let response = self
            .client
            .get(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|_| ArchiveError::BackendUnavailable)?;
        let response = match response.status() {
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE => {
                return Err(ArchiveError::NotFound);
            }
            status if status.is_success() => response,
            _ => return Err(ArchiveError::BackendUnavailable),
        };
        read_body_limited(response).await
    }

    async fn delete(&self, key: &str) -> ArchiveResult<()> {
        let url = self.object_url(key)?;
        let response = self
            .client
            .delete(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|_| ArchiveError::BackendUnavailable)?;
        match response.status() {
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE => Ok(()),
            status if status.is_success() => Ok(()),
            _ => Err(ArchiveError::BackendUnavailable),
        }
    }

    async fn head(&self, key: &str) -> ArchiveResult<Option<ColdObjectMeta>> {
        let url = self.object_url(key)?;
        let response = self
            .client
            .head(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|_| ArchiveError::BackendUnavailable)?;
        match response.status() {
            reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::GONE => Ok(None),
            status if status.is_success() => {
                // 注意：reqwest 对 HEAD 响应的 `Response::content_length()` 返回的是
                // **body 长度**（HEAD 无 body，恒为 0），必须显式读 `Content-Length`
                // 头，否则会把所有对象都误判成 0 字节。
                let size = response
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.trim().parse::<u64>().ok())
                    .ok_or(ArchiveError::BackendUnavailable)?;
                Ok(Some(ColdObjectMeta { size }))
            }
            _ => Err(ArchiveError::BackendUnavailable),
        }
    }

    async fn test(&self) -> ArchiveResult<()> {
        // 每次随机 key，避免并发测试互相覆盖；失败也一定尝试清理。
        let key = format!("health/{}.probe", uuid::Uuid::new_v4());
        let payload = b"rustboard-archive-probe";

        let probe = async {
            self.put(&key, payload).await?;
            let meta = self
                .head(&key)
                .await?
                .ok_or(ArchiveError::BackendUnavailable)?;
            if meta.size != payload.len() as u64 {
                return Err(ArchiveError::BackendUnavailable);
            }
            let read_back = self.get(&key).await?;
            if read_back != payload {
                return Err(ArchiveError::BackendUnavailable);
            }
            Ok(())
        }
        .await;

        let cleanup = self.delete(&key).await;
        match (probe, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), _) => Err(err),
            (Ok(()), Err(err)) => Err(err),
        }
    }
}

/// key 只允许相对路径片段：`[A-Za-z0-9._-]` 与 `/`，不含空段 / `.` / `..`。
fn validate_key(key: &str) -> ArchiveResult<()> {
    if key.is_empty()
        || key.len() > MAX_KEY_BYTES
        || key.starts_with('/')
        || key.ends_with('/')
        || key.contains("//")
        || !key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
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

/// 按对象后缀选择 Content-Type；未知类型（探针）用 `application/octet-stream`。
fn content_type_for(key: &str) -> &'static str {
    if key.ends_with(".manifest.json") {
        "application/json"
    } else if key.ends_with(".csv.gz") {
        "application/gzip"
    } else {
        "application/octet-stream"
    }
}

/// 读取响应体并强制 1 GiB 上限；任何底层错误都折叠成固定错误。
async fn read_body_limited(mut response: reqwest::Response) -> ArchiveResult<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_GET_OBJECT_BYTES as u64)
    {
        return Err(ArchiveError::BackendUnavailable);
    }
    let mut out = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ArchiveError::BackendUnavailable)?
    {
        if out.len().saturating_add(chunk.len()) > MAX_GET_OBJECT_BYTES {
            return Err(ArchiveError::BackendUnavailable);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 测试：本地 axum mock WebDAV
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use axum::body::Bytes;
    use axum::extract::{Path as AxumPath, State};
    use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::any;
    use axum::Router;
    use rustboard_common::config::ArchiveWebdavConfig;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// 一条 mock WebDAV 收到的请求；测试据此断言 path / body / 头。
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct DavRequest {
        pub method: String,
        /// 去掉 `/dav/` 前缀后的对象路径。
        pub path: String,
        pub content_type: Option<String>,
        pub authorization: Option<String>,
        pub body: Vec<u8>,
    }

    /// mock 的可变状态；所有字段由同一个 `Mutex` 保护，测试直接读写。
    #[derive(Debug, Default)]
    pub(crate) struct DavInner {
        pub objects: BTreeMap<String, Vec<u8>>,
        pub requests: Vec<DavRequest>,
        pub fail_put: Option<u16>,
        pub fail_get: Option<u16>,
        pub fail_head: Option<u16>,
        pub fail_delete: Option<u16>,
        /// PUT 返回 302 并带 Location，用于验证客户端不跟随重定向。
        pub redirect_put: bool,
    }

    #[derive(Clone)]
    struct DavState {
        inner: Arc<Mutex<DavInner>>,
    }

    /// 本地 mock WebDAV 服务；`Drop` 时 abort 服务任务。
    pub(crate) struct MockDav {
        pub inner: Arc<Mutex<DavInner>>,
        pub base_url: String,
        handle: JoinHandle<()>,
    }

    impl MockDav {
        pub(crate) async fn spawn() -> Self {
            let inner = Arc::new(Mutex::new(DavInner::default()));
            let app = Router::new()
                .route("/dav/{*path}", any(dav_handler))
                .with_state(DavState {
                    inner: inner.clone(),
                });
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("mock WebDAV 绑定端口失败");
            let addr = listener.local_addr().expect("读取 mock WebDAV 端口失败");
            let handle = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            Self {
                inner,
                base_url: format!("http://{addr}/dav"),
                handle,
            }
        }

        pub(crate) fn config(&self) -> ArchiveWebdavConfig {
            ArchiveWebdavConfig {
                url: self.base_url.clone(),
                username: "dav-user".to_string(),
                password: "dav-password".to_string(),
            }
        }
    }

    impl Drop for MockDav {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    async fn dav_handler(
        State(state): State<DavState>,
        method: Method,
        AxumPath(path): AxumPath<String>,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response {
        let mut inner = state.inner.lock().expect("mock WebDAV 状态锁未被毒化");
        inner.requests.push(DavRequest {
            method: method.as_str().to_string(),
            path: path.clone(),
            content_type: headers
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            authorization: headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            body: body.to_vec(),
        });

        if method == Method::PUT && inner.redirect_put {
            drop(inner);
            let mut response = StatusCode::FOUND.into_response();
            response.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_static("/dav/redirected"),
            );
            return response;
        }

        let failure = match method {
            Method::PUT => inner.fail_put,
            Method::GET => inner.fail_get,
            Method::HEAD => inner.fail_head,
            Method::DELETE => inner.fail_delete,
            _ => None,
        };
        if let Some(status) = failure {
            drop(inner);
            return fixed_response(status);
        }

        match method {
            Method::PUT => {
                inner.objects.insert(path, body.to_vec());
                drop(inner);
                StatusCode::CREATED.into_response()
            }
            Method::GET => {
                let value = inner.objects.get(&path).cloned();
                drop(inner);
                match value {
                    Some(value) => (StatusCode::OK, value).into_response(),
                    None => fixed_response(404),
                }
            }
            Method::HEAD => {
                // axum / hyper 会按 body 的精确大小重写 Content-Length；空 body 会
                // 得到 0，无法模拟真实 WebDAV 的 HEAD。这里用同长度占位 body
                // （长度由 hyper 写入 Content-Length；reqwest 对 HEAD 不读取 body）。
                let value = inner.objects.get(&path).cloned();
                drop(inner);
                match value {
                    Some(value) => {
                        let size = value.len();
                        let mut response = StatusCode::OK.into_response();
                        response.headers_mut().insert(
                            header::CONTENT_LENGTH,
                            HeaderValue::from_str(&size.to_string())
                                .expect("对象大小必须能转成 header"),
                        );
                        response
                    }
                    None => fixed_response(404),
                }
            }
            Method::DELETE => {
                inner.objects.remove(&path);
                drop(inner);
                StatusCode::NO_CONTENT.into_response()
            }
            _ => {
                drop(inner);
                fixed_response(405)
            }
        }
    }

    fn fixed_response(status: u16) -> Response {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, "upstream-secret-body").into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::MockDav;
    use super::*;
    use base64::Engine as _;
    use rustboard_core::archive::ArchiveManifest;

    fn store(mock: &MockDav) -> WebdavColdStore {
        WebdavColdStore::new(&mock.config()).expect("mock WebDAV 配置必须可构造")
    }

    fn basic_auth_header(username: &str, password: &str) -> String {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        format!("Basic {encoded}")
    }

    #[tokio::test]
    async fn put_get_head_delete_roundtrip_sets_path_body_and_headers() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        let object_key = "rustboard/2026/10/18/part-00001.csv.gz";
        let manifest_key = "rustboard/2026/10/18/part-00001.manifest.json";

        store.put(object_key, b"gzip-payload").await.unwrap();
        store.put(manifest_key, b"{}").await.unwrap();

        {
            let inner = mock.inner.lock().unwrap();
            assert_eq!(inner.requests.len(), 2);
            let put_object = &inner.requests[0];
            assert_eq!(put_object.method, "PUT");
            assert_eq!(put_object.path, object_key);
            assert_eq!(put_object.content_type.as_deref(), Some("application/gzip"));
            assert_eq!(
                put_object.authorization.as_deref(),
                Some(basic_auth_header("dav-user", "dav-password").as_str())
            );
            assert_eq!(put_object.body, b"gzip-payload");
            let put_manifest = &inner.requests[1];
            assert_eq!(
                put_manifest.content_type.as_deref(),
                Some("application/json")
            );
            assert_eq!(inner.objects.get(object_key).unwrap(), b"gzip-payload");
        }

        assert_eq!(
            store.head(object_key).await.unwrap(),
            Some(ColdObjectMeta { size: 12 })
        );
        assert_eq!(store.get(object_key).await.unwrap(), b"gzip-payload");
        store.delete(object_key).await.unwrap();
        assert_eq!(store.head(object_key).await.unwrap(), None);
        // DELETE 对不存在对象按幂等成功处理。
        store.delete(object_key).await.unwrap();
    }

    #[tokio::test]
    async fn non_success_statuses_are_fixed_errors_without_backend_details() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        let key = "rustboard/2026/10/18/part-00001.csv.gz";
        {
            let mut inner = mock.inner.lock().unwrap();
            inner.fail_put = Some(401);
        }
        let err = store.put(key, b"secret-data").await.unwrap_err();
        assert_eq!(err, ArchiveError::BackendUnavailable);
        let message = err.to_string();
        assert_eq!(message, "冷存储后端不可用");
        for leaked in [
            "http://",
            "dav-user",
            "dav-password",
            "upstream-secret-body",
            "secret-data",
        ] {
            assert!(!message.contains(leaked), "错误泄露了 {leaked}: {message}");
        }

        {
            let mut inner = mock.inner.lock().unwrap();
            inner.fail_put = None;
            inner.fail_get = Some(500);
            inner.fail_head = Some(500);
            inner.fail_delete = Some(500);
        }
        assert_eq!(
            store.get(key).await.unwrap_err(),
            ArchiveError::BackendUnavailable
        );
        assert_eq!(
            store.head(key).await.unwrap_err(),
            ArchiveError::BackendUnavailable
        );
        assert_eq!(
            store.delete(key).await.unwrap_err(),
            ArchiveError::BackendUnavailable
        );

        // 404：GET 固定 NotFound，HEAD 返回 None（先清掉失败注入）。
        {
            let mut inner = mock.inner.lock().unwrap();
            inner.fail_get = None;
            inner.fail_head = None;
            inner.fail_delete = None;
        }
        assert_eq!(
            store.get("rustboard/missing.csv.gz").await.unwrap_err(),
            ArchiveError::NotFound
        );
        assert_eq!(store.head("rustboard/missing.csv.gz").await.unwrap(), None);
    }

    #[tokio::test]
    async fn unsafe_keys_are_rejected_before_any_request() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        for key in [
            "",
            "/absolute/path.csv.gz",
            "../escape.csv.gz",
            "a/../../b.csv.gz",
            "a/./b.csv.gz",
            "a//b.csv.gz",
            "a\\b.csv.gz",
            "a?query=1",
            "a#fragment",
            "a b.csv.gz",
        ] {
            assert_eq!(
                store.put(key, b"x").await.unwrap_err(),
                ArchiveError::InvalidKey,
                "key 必须被拒绝: {key:?}"
            );
        }
        assert!(
            mock.inner.lock().unwrap().requests.is_empty(),
            "非法 key 不得发出任何网络请求"
        );
    }

    #[tokio::test]
    async fn constructor_rejects_invalid_urls_and_credentials_in_url() {
        for url in [
            "",
            "not a url",
            "ftp://127.0.0.1/dav",
            "file:///tmp/dav",
            "http://user:pass@127.0.0.1/dav",
            "http://127.0.0.1/dav?token=secret",
            "http://127.0.0.1/dav#fragment",
        ] {
            let config = ArchiveWebdavConfig {
                url: url.to_string(),
                username: "user".to_string(),
                password: "password".to_string(),
            };
            assert_eq!(
                WebdavColdStore::new(&config).err(),
                Some(ArchiveError::BackendUnavailable),
                "URL 必须被拒绝: {url:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_probe_roundtrip_leaves_no_object() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        store.test().await.unwrap();
        let inner = mock.inner.lock().unwrap();
        assert!(inner.objects.is_empty(), "探针对象必须清理");
        let methods: Vec<&str> = inner
            .requests
            .iter()
            .map(|request| request.method.as_str())
            .collect();
        assert_eq!(methods, vec!["PUT", "HEAD", "GET", "DELETE"]);
        let probe = &inner.requests[0];
        assert!(
            probe.path.starts_with("health/") && probe.path.ends_with(".probe"),
            "探针 key 格式不符: {}",
            probe.path
        );
        assert_eq!(
            probe.content_type.as_deref(),
            Some("application/octet-stream")
        );
    }

    #[tokio::test]
    async fn test_probe_cleans_up_when_verification_fails() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        mock.inner.lock().unwrap().fail_get = Some(500);
        assert_eq!(
            store.test().await.unwrap_err(),
            ArchiveError::BackendUnavailable
        );
        let inner = mock.inner.lock().unwrap();
        assert!(inner.objects.is_empty(), "失败后仍必须删除探针对象");
        let methods: Vec<&str> = inner
            .requests
            .iter()
            .map(|request| request.method.as_str())
            .collect();
        assert_eq!(methods, vec!["PUT", "HEAD", "GET", "DELETE"]);
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        mock.inner.lock().unwrap().redirect_put = true;
        assert_eq!(
            store
                .put("rustboard/2026/10/18/part-00001.csv.gz", b"x")
                .await
                .unwrap_err(),
            ArchiveError::BackendUnavailable
        );
        assert_eq!(
            mock.inner.lock().unwrap().requests.len(),
            1,
            "禁止重定向：不得向 Location 再发请求"
        );
    }

    #[tokio::test]
    async fn get_reads_back_manifest_json_bytes() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        let key = "rustboard/2026/10/18/part-00001.manifest.json";
        let manifest = ArchiveManifest::new(
            "rustboard/2026/10/18/part-00001.csv.gz",
            1,
            2,
            3,
            4,
            "sha",
            5,
        );
        let json = rustboard_core::archive::manifest_json(&manifest).unwrap();
        store.put(key, json.as_bytes()).await.unwrap();
        assert_eq!(store.get(key).await.unwrap(), json.as_bytes());
    }
}
