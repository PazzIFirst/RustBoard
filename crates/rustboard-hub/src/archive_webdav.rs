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
//! - `put` 之前自 base 逐级 `MKCOL` 父 collection（201 = 新建，405 = 已存在）：
//!   base collection 必须由运维预先创建且可写，本模块不会 `MKCOL` base 本身，
//!   也不会回收空 collection；探针对象仍会删除。已创建的 collection 按 store
//!   实例缓存，并发首次创建时依赖 405 幂等成功；
//! - `head` 只返回对象大小，不暴露 ETag / URL / 响应头。
//!
//! 网络层不打印任何后端信息；失败时上层只看到固定的中文错误。

use std::collections::BTreeSet;
use std::sync::Mutex;
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
    /// 已确认存在的 collection（相对 base 的路径，不含首尾 `/`）。
    ///
    /// 只在同步代码段内加锁、绝不跨 `.await` 持有，避免异步锁与 `Send` 约束；
    /// 并发首次创建时可能重复发 MKCOL，后到者按 405 已存在处理。
    created_collections: Mutex<BTreeSet<String>>,
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
            created_collections: Mutex::new(BTreeSet::new()),
        })
    }

    /// 把已校验的 key 拼到固定 base URL 上。
    fn object_url(&self, key: &str) -> ArchiveResult<Url> {
        validate_key(key)?;
        self.base.join(key).map_err(|_| ArchiveError::InvalidKey)
    }

    /// 计算 key 的全部父 collection，按从浅到深排列。
    ///
    /// 例如 `rustboard/2026/10/18/part-00001.csv.gz` 返回
    /// `rustboard`、`rustboard/2026`、`rustboard/2026/10`、
    /// `rustboard/2026/10/18`。base collection 由运维预先创建，不在此列。
    fn parent_collections(key: &str) -> ArchiveResult<Vec<String>> {
        validate_key(key)?;
        let segments = key.split('/').collect::<Vec<_>>();
        let mut collections = Vec::with_capacity(segments.len().saturating_sub(1));
        for depth in 1..segments.len() {
            collections.push(segments[..depth].join("/"));
        }
        Ok(collections)
    }

    fn is_collection_cached(&self, collection: &str) -> bool {
        self.created_collections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(collection)
    }

    fn cache_collection(&self, collection: &str) {
        self.created_collections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(collection.to_string());
    }

    /// 清除 key 父链的缓存，用于 PUT 409 后重建被外部删除 / 迁移的 collection。
    fn forget_parent_collections(&self, key: &str) -> ArchiveResult<()> {
        let collections = Self::parent_collections(key)?;
        let mut cached = self
            .created_collections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for collection in collections {
            cached.remove(&collection);
        }
        Ok(())
    }

    /// 逐级创建 key 的父 collection。
    ///
    /// 201 表示新建成功，405 表示已存在（并发创建 / 缓存未命中），两者都成功；
    /// 401 / 403 / 409 / 3xx / 5xx 统一折叠为固定的
    /// [`ArchiveError::BackendUnavailable`]。客户端已禁用重定向，3xx 不会被跟随。
    async fn ensure_parent_collections(&self, key: &str) -> ArchiveResult<()> {
        for collection in Self::parent_collections(key)? {
            if self.is_collection_cached(&collection) {
                continue;
            }
            self.create_collection(&collection).await?;
            self.cache_collection(&collection);
        }
        Ok(())
    }

    /// 对单个 collection 发 `MKCOL`；错误不包含 URL、凭据或响应正文。
    async fn create_collection(&self, collection: &str) -> ArchiveResult<()> {
        let url = self
            .base
            .join(&format!("{collection}/"))
            .map_err(|_| ArchiveError::BackendUnavailable)?;
        // `MKCOL` 不是 reqwest 预置常量，但它是合法的 HTTP 方法。
        let method =
            reqwest::Method::from_bytes(b"MKCOL").map_err(|_| ArchiveError::BackendUnavailable)?;
        let response = self
            .client
            .request(method, url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await
            .map_err(|_| ArchiveError::BackendUnavailable)?;
        match response.status() {
            // 201：新建成功；200 / 204：部分后端对已存在 collection 的返回；
            // 405：collection 已存在。
            reqwest::StatusCode::OK
            | reqwest::StatusCode::CREATED
            | reqwest::StatusCode::NO_CONTENT
            | reqwest::StatusCode::METHOD_NOT_ALLOWED => Ok(()),
            // 202（异步接受、尚未建好）等其它 2xx 不得视为已创建，否则会写进
            // 缓存，导致之后 PUT 永久 409。401 / 403 / 409 / 3xx / 5xx 同理。
            _ => Err(ArchiveError::BackendUnavailable),
        }
    }

    async fn require_success(response: reqwest::Response) -> ArchiveResult<reqwest::Response> {
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(ArchiveError::BackendUnavailable)
        }
    }

    /// 发送对象 PUT；传输层错误折叠为固定错误。
    async fn send_put(&self, url: Url, key: &str, data: &[u8]) -> ArchiveResult<reqwest::Response> {
        self.client
            .put(url)
            .basic_auth(&self.username, Some(&self.password))
            .header(header::CONTENT_TYPE, content_type_for(key))
            .body(data.to_vec())
            .send()
            .await
            .map_err(|_| ArchiveError::BackendUnavailable)
    }
}

#[async_trait]
impl ColdStore for WebdavColdStore {
    async fn put(&self, key: &str, data: &[u8]) -> ArchiveResult<()> {
        // 严格 DAV 后端要求父 collection 存在，否则 PUT 会返回 409。
        self.ensure_parent_collections(key).await?;
        let url = self.object_url(key)?;
        let response = self.send_put(url.clone(), key, data).await?;
        if response.status() == reqwest::StatusCode::CONFLICT {
            // 409 多半是 collection 被外部删除 / 迁移：清父链缓存，重新逐级
            // MKCOL 后只重试一次 PUT；仍失败则返回固定错误，不无限重试。
            self.forget_parent_collections(key)?;
            self.ensure_parent_collections(key).await?;
            let response = self.send_put(url, key, data).await?;
            return Self::require_success(response).await.map(|_| ());
        }
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
        // `put` 会复用同一套逐级 MKCOL 逻辑创建 `health` collection。
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
    use std::collections::{BTreeMap, BTreeSet};
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
        /// 去掉 `/dav/` 前缀与末尾 `/` 后的对象 / collection 路径。
        pub path: String,
        /// 去掉 `/dav/` 前缀后的原始路径，保留 MKCOL 末尾 `/` 等细节。
        pub raw_path: String,
        pub content_type: Option<String>,
        pub authorization: Option<String>,
        pub body: Vec<u8>,
    }

    /// mock 的可变状态；所有字段由同一个 `Mutex` 保护，测试直接读写。
    ///
    /// 默认是**严格 DAV**：父 collection 不存在时 PUT 返回 409，必须用 MKCOL
    /// 逐级创建；base collection `/dav` 视为预先存在。
    #[derive(Debug, Default)]
    pub(crate) struct DavInner {
        pub objects: BTreeMap<String, Vec<u8>>,
        /// 已存在的 collection（相对 `/dav` 的路径，不含首尾 `/`）。
        pub collections: BTreeSet<String>,
        pub requests: Vec<DavRequest>,
        pub fail_put: Option<u16>,
        pub fail_mkcol: Option<u16>,
        pub fail_get: Option<u16>,
        pub fail_head: Option<u16>,
        pub fail_delete: Option<u16>,
        /// PUT 返回 302 并带 Location，用于验证客户端不跟随重定向。
        pub redirect_put: bool,
        /// MKCOL 返回 302 并带 Location，用于验证客户端不跟随重定向。
        pub redirect_mkcol: bool,
        /// MKCOL 实际新建 / 命中已存在的次数；用于断言 201 / 405 处理。
        pub mkcol_created: u32,
        pub mkcol_existing: u32,
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
        // 保留原始 URI 供断言（MKCOL 必须以 `/` 结尾）；规范化路径用于查找。
        let raw_path = path;
        let path = raw_path.trim_end_matches('/').to_string();
        inner.requests.push(DavRequest {
            method: method.as_str().to_string(),
            path: path.clone(),
            raw_path,
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
            return redirect_response();
        }
        if method.as_str() == "MKCOL" && inner.redirect_mkcol {
            drop(inner);
            return redirect_response();
        }

        let failure = match method.as_str() {
            "PUT" => inner.fail_put,
            "MKCOL" => inner.fail_mkcol,
            "GET" => inner.fail_get,
            "HEAD" => inner.fail_head,
            "DELETE" => inner.fail_delete,
            _ => None,
        };
        if let Some(status) = failure {
            drop(inner);
            return fixed_response(status);
        }

        if method.as_str() == "MKCOL" {
            return mkcol(&mut inner, &path);
        }

        match method {
            Method::PUT => {
                // 严格 DAV：父 collection 不存在时拒绝写入（RFC 4918 409）。
                let parent = parent_collection(&path);
                if !parent.is_empty() && !inner.collections.contains(parent) {
                    drop(inner);
                    return fixed_response(409);
                }
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

    /// 严格 DAV 的 MKCOL：已存在 → 405，父缺失 → 409，新建 → 201。
    fn mkcol(inner: &mut DavInner, path: &str) -> Response {
        if path.is_empty() || inner.collections.contains(path) {
            inner.mkcol_existing = inner.mkcol_existing.saturating_add(1);
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        let parent = parent_collection(path);
        if !parent.is_empty() && !inner.collections.contains(parent) {
            return fixed_response(409);
        }
        inner.collections.insert(path.to_string());
        inner.mkcol_created = inner.mkcol_created.saturating_add(1);
        StatusCode::CREATED.into_response()
    }

    /// 对象 / collection 的父路径；顶层返回空串（base collection 恒存在）。
    fn parent_collection(path: &str) -> &str {
        path.rsplit_once('/').map_or("", |(parent, _)| parent)
    }

    fn redirect_response() -> Response {
        let mut response = StatusCode::FOUND.into_response();
        response.headers_mut().insert(
            header::LOCATION,
            HeaderValue::from_static("/dav/redirected"),
        );
        response
    }

    fn fixed_response(status: u16) -> Response {
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, "upstream-secret-body").into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::test_support::{DavRequest, MockDav};
    use super::*;
    use base64::Engine as _;
    use rustboard_core::archive::ArchiveManifest;

    fn store(mock: &MockDav) -> WebdavColdStore {
        WebdavColdStore::new(&mock.config()).expect("mock WebDAV 配置必须可构造")
    }

    /// 每个 MKCOL 请求的原始 URI 都必须以 `/` 结尾（collection URI 规范）。
    fn assert_mkcol_raw_paths_end_with_slash(requests: &[DavRequest]) {
        let mut seen = false;
        for request in requests.iter().filter(|request| request.method == "MKCOL") {
            seen = true;
            assert!(
                request.raw_path.ends_with('/'),
                "MKCOL URI 必须以 / 结尾: {:?}",
                request.raw_path
            );
        }
        assert!(seen, "应至少有一个 MKCOL 请求");
    }

    fn basic_auth_header(username: &str, password: &str) -> String {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        format!("Basic {encoded}")
    }

    /// 固定错误且不得回显 base URL、凭据或上游响应正文。
    fn assert_fixed_error_without_leak(error: &ArchiveError, base_url: &str) {
        assert_eq!(error, &ArchiveError::BackendUnavailable);
        let message = error.to_string();
        assert_eq!(message, "冷存储后端不可用");
        for leaked in [base_url, "dav-user", "dav-password", "upstream-secret-body"] {
            assert!(!message.contains(leaked), "错误泄露了 {leaked}: {message}");
        }
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
            let puts = inner
                .requests
                .iter()
                .filter(|request| request.method == "PUT")
                .collect::<Vec<_>>();
            assert_eq!(puts.len(), 2);
            let put_object = puts[0];
            assert_eq!(put_object.path, object_key);
            assert_eq!(put_object.content_type.as_deref(), Some("application/gzip"));
            assert_eq!(
                put_object.authorization.as_deref(),
                Some(basic_auth_header("dav-user", "dav-password").as_str())
            );
            assert_eq!(put_object.body, b"gzip-payload");
            let put_manifest = puts[1];
            assert_eq!(
                put_manifest.content_type.as_deref(),
                Some("application/json")
            );
            assert_eq!(inner.objects.get(object_key).unwrap(), b"gzip-payload");
            // 两个对象共享父 collection：只在首次 PUT 前逐级创建一次。
            assert_eq!(
                inner
                    .requests
                    .iter()
                    .filter(|request| request.method == "MKCOL")
                    .map(|request| request.path.as_str())
                    .collect::<Vec<_>>(),
                vec![
                    "rustboard",
                    "rustboard/2026",
                    "rustboard/2026/10",
                    "rustboard/2026/10/18"
                ]
            );
            assert_eq!(inner.mkcol_created, 4);
            assert_mkcol_raw_paths_end_with_slash(&inner.requests);
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
    async fn test_probe_roundtrip_leaves_no_object_and_reuses_health_collection() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        store.test().await.unwrap();
        {
            let inner = mock.inner.lock().unwrap();
            assert!(inner.objects.is_empty(), "探针对象必须清理");
            let methods: Vec<&str> = inner
                .requests
                .iter()
                .map(|request| request.method.as_str())
                .collect();
            assert_eq!(
                methods,
                vec!["MKCOL", "PUT", "HEAD", "GET", "DELETE"],
                "首次 test 必须先创建 health collection"
            );
            assert_eq!(inner.requests[0].path, "health");
            assert_eq!(
                inner.requests[0].authorization.as_deref(),
                Some(basic_auth_header("dav-user", "dav-password").as_str()),
                "MKCOL 也必须携带 Basic auth"
            );
            let probe = &inner.requests[1];
            assert!(
                probe.path.starts_with("health/") && probe.path.ends_with(".probe"),
                "探针 key 格式不符: {}",
                probe.path
            );
            assert_eq!(
                probe.content_type.as_deref(),
                Some("application/octet-stream")
            );
            assert_eq!(inner.mkcol_created, 1);
            assert_mkcol_raw_paths_end_with_slash(&inner.requests);
        }

        // 第二次 test 命中 collection 缓存，不再 MKCOL。
        store.test().await.unwrap();
        let inner = mock.inner.lock().unwrap();
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "MKCOL")
                .count(),
            1,
            "health collection 必须按 store 实例缓存"
        );
        assert!(inner.objects.is_empty(), "探针对象必须清理");
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
        assert_eq!(methods, vec!["MKCOL", "PUT", "HEAD", "GET", "DELETE"]);
        assert_eq!(inner.requests[0].path, "health");
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
        let inner = mock.inner.lock().unwrap();
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "PUT")
                .count(),
            1,
            "禁止重定向：302 后不得重发 PUT"
        );
        assert!(
            inner
                .requests
                .iter()
                .all(|request| request.path != "redirected"),
            "不得向 Location 再发请求"
        );
        assert_eq!(inner.mkcol_created, 4, "PUT 前父 collection 应已创建");
    }

    #[tokio::test]
    async fn mkcol_redirects_are_not_followed() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        mock.inner.lock().unwrap().redirect_mkcol = true;
        let error = store
            .put("rustboard/2026/10/18/part-00001.csv.gz", b"x")
            .await
            .unwrap_err();
        assert_fixed_error_without_leak(&error, &mock.base_url);
        let inner = mock.inner.lock().unwrap();
        assert_eq!(inner.requests.len(), 1, "MKCOL 302 后不得跟随");
        assert_eq!(inner.requests[0].method, "MKCOL");
        assert!(inner.objects.is_empty(), "MKCOL 失败不得写入对象");
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

    /// mock 自身必须是严格 DAV：父 collection 缺失时 PUT=409，逐级 MKCOL 后才 201。
    #[tokio::test]
    async fn strict_mock_rejects_put_until_parent_collections_exist() {
        let mock = MockDav::spawn().await;
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let key = "rustboard/2026/10/18/part-00001.csv.gz";
        let object_url = format!("{}/{key}", mock.base_url);

        let response = client.put(&object_url).body("x").send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);

        let method = reqwest::Method::from_bytes(b"MKCOL").unwrap();
        // 直接父 collection 也不能跳过中间层级。
        let direct_parent = format!("{}/rustboard/2026/10/18/", mock.base_url);
        let response = client
            .request(method.clone(), direct_parent)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::CONFLICT);

        for collection in [
            "rustboard",
            "rustboard/2026",
            "rustboard/2026/10",
            "rustboard/2026/10/18",
        ] {
            let url = format!("{}/{collection}/", mock.base_url);
            let response = client.request(method.clone(), url).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::CREATED);
        }

        let response = client.put(&object_url).body("x").send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::CREATED);
        assert_eq!(mock.inner.lock().unwrap().objects.get(key).unwrap(), b"x");
    }

    /// 跨新日期只创建缺失的那一级 collection；同日期 / 同父路径全部命中缓存。
    #[tokio::test]
    async fn new_date_creates_only_missing_collection() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        store
            .put("rustboard/2026/10/18/part-00001.csv.gz", b"day-18")
            .await
            .unwrap();
        store
            .put("rustboard/2026/10/18/part-00002.csv.gz", b"day-18-again")
            .await
            .unwrap();
        store
            .put("rustboard/2026/10/19/part-00001.csv.gz", b"day-19")
            .await
            .unwrap();

        let inner = mock.inner.lock().unwrap();
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "MKCOL")
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            vec![
                "rustboard",
                "rustboard/2026",
                "rustboard/2026/10",
                "rustboard/2026/10/18",
                "rustboard/2026/10/19",
            ],
            "只应创建缺失的 collection"
        );
        assert_eq!(inner.mkcol_created, 5);
        assert_eq!(inner.mkcol_existing, 0);
        assert!(inner.collections.contains("rustboard/2026/10/19"));
        assert_eq!(inner.objects.len(), 3);
        assert_mkcol_raw_paths_end_with_slash(&inner.requests);
    }

    /// 其他客户端已建好 collection 时 MKCOL 返回 405：视为成功并写入缓存。
    #[tokio::test]
    async fn existing_collections_from_other_clients_are_treated_as_success() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        let collections = [
            "rustboard",
            "rustboard/2026",
            "rustboard/2026/10",
            "rustboard/2026/10/18",
        ];
        {
            let mut inner = mock.inner.lock().unwrap();
            for collection in collections {
                inner.collections.insert(collection.to_string());
            }
        }

        let key = "rustboard/2026/10/18/part-00001.csv.gz";
        store.put(key, b"payload").await.unwrap();
        {
            let inner = mock.inner.lock().unwrap();
            assert_eq!(inner.mkcol_created, 0);
            assert_eq!(inner.mkcol_existing, 4, "405 必须按已存在处理");
            assert_eq!(inner.objects.get(key).unwrap(), b"payload");
            assert_eq!(
                inner
                    .requests
                    .iter()
                    .filter(|request| request.method == "PUT")
                    .count(),
                1,
                "405 后仍必须继续 PUT"
            );
        }

        // 已确认存在的 collection 进缓存，再传其它对象不再 MKCOL。
        store
            .put("rustboard/2026/10/18/part-00002.csv.gz", b"payload-2")
            .await
            .unwrap();
        let inner = mock.inner.lock().unwrap();
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "MKCOL")
                .count(),
            4,
            "同一 store 不得重复 MKCOL"
        );
        assert_eq!(inner.objects.len(), 2);
    }

    /// 并发首次上传共享父 collection：所有 PUT 都必须成功（405 幂等）。
    #[tokio::test]
    async fn concurrent_puts_share_collection_creation() {
        let mock = MockDav::spawn().await;
        let store = Arc::new(store(&mock));
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let mut tasks = Vec::new();
        for shard in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                store
                    .put(
                        &format!("rustboard/2026/10/18/part-{shard:05}.csv.gz"),
                        b"concurrent",
                    )
                    .await
            }));
        }
        for task in tasks {
            task.await.expect("并发任务不得 panic").unwrap();
        }

        let inner = mock.inner.lock().unwrap();
        assert_eq!(inner.objects.len(), 8, "所有并发对象都必须写入");
        for collection in [
            "rustboard",
            "rustboard/2026",
            "rustboard/2026/10",
            "rustboard/2026/10/18",
        ] {
            assert!(
                inner.collections.contains(collection),
                "collection 未创建: {collection}"
            );
        }
        assert!(
            inner.mkcol_created >= 1,
            "至少应有一个 MKCOL 真正创建 collection"
        );
        assert_eq!(
            inner.mkcol_created + inner.mkcol_existing,
            inner
                .requests
                .iter()
                .filter(|request| request.method == "MKCOL")
                .count() as u32,
            "每个 MKCOL 请求都应有 201 / 405 结果"
        );
    }

    /// 202 / 401 / 403 / 409 / 5xx：固定错误、不继续 PUT、不泄露后端信息。
    ///
    /// 202 尤其不能被当成“已创建”，否则 collection 缓存会永久命中，后续 PUT 409。
    #[tokio::test]
    async fn mkcol_failures_are_fixed_errors_without_leaks() {
        for status in [202, 401, 403, 409, 500] {
            let mock = MockDav::spawn().await;
            let store = store(&mock);
            mock.inner.lock().unwrap().fail_mkcol = Some(status);
            let error = store
                .put("rustboard/2026/10/18/part-00001.csv.gz", b"secret-data")
                .await
                .unwrap_err();
            assert_fixed_error_without_leak(&error, &mock.base_url);

            let inner = mock.inner.lock().unwrap();
            assert_eq!(
                inner.requests.len(),
                1,
                "MKCOL 失败（{status}）后不得继续 PUT"
            );
            assert_eq!(inner.requests[0].method, "MKCOL");
            assert!(inner.objects.is_empty());
            assert_eq!(inner.mkcol_created, 0);
        }
    }

    /// PUT 409：清父链缓存、重新 MKCOL 后重试一次，覆盖外部删除 collection。
    #[tokio::test]
    async fn put_retries_once_after_external_collection_deletion() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        let key = "rustboard/2026/10/18/part-00001.csv.gz";
        store.put(key, b"before").await.unwrap();
        {
            // 模拟另一个客户端删除日期 collection（其下对象一并消失）。
            let mut inner = mock.inner.lock().unwrap();
            inner.collections.remove("rustboard/2026/10/18");
            inner.objects.remove(key);
        }

        store.put(key, b"after").await.unwrap();
        let inner = mock.inner.lock().unwrap();
        assert_eq!(inner.objects.get(key).unwrap(), b"after");
        assert!(inner.collections.contains("rustboard/2026/10/18"));
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "PUT")
                .count(),
            3,
            "首次成功 + 409 + 重试成功"
        );
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "MKCOL")
                .count(),
            8,
            "409 后必须清父链缓存并逐级重建"
        );
        assert_mkcol_raw_paths_end_with_slash(&inner.requests);
    }

    /// PUT 409 只重试一次；重建后仍冲突必须失败关闭，不无限重试。
    #[tokio::test]
    async fn put_conflict_retries_only_once_then_fails_closed() {
        let mock = MockDav::spawn().await;
        let store = store(&mock);
        mock.inner.lock().unwrap().fail_put = Some(409);
        let error = store
            .put("rustboard/2026/10/18/part-00001.csv.gz", b"x")
            .await
            .unwrap_err();
        assert_fixed_error_without_leak(&error, &mock.base_url);

        let inner = mock.inner.lock().unwrap();
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "PUT")
                .count(),
            2,
            "首次 PUT 409 后只允许重试一次"
        );
        assert_eq!(
            inner
                .requests
                .iter()
                .filter(|request| request.method == "MKCOL")
                .count(),
            8,
            "重试前必须重新逐级 MKCOL"
        );
        assert_eq!(inner.mkcol_created, 4);
        assert_eq!(inner.mkcol_existing, 4);
        assert!(inner.objects.is_empty());
        assert_mkcol_raw_paths_end_with_slash(&inner.requests);
    }
}
