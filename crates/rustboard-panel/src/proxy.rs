//! hub 管理 API 的反向代理。
//!
//! 浏览器只同源访问面板的 `/api/*`；面板在服务端注入 Bearer token。
//! 代理层只放行方案 §3.1 里列出的端点，并对 agent_id / 查询参数做白名单校验，
//! 避免把面板变成任意 URL 的开放代理。
//!
//! 错误映射（方案 §3.2）：
//! - hub 401 → 面板 502 `hub_auth_failed`（token 错误不能让浏览器误以为会话失效）；
//! - 其余状态码原样保留；
//! - 连接失败 / 超时 / 响应体读失败 → 502 `hub_unreachable`。

use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use reqwest::redirect::Policy;
use reqwest::Url;
use serde_json::Value;

/// hub 响应体上限，防止异常响应打爆面板内存。
///
/// hub 的 series 正常响应远小于此（单曲线 ≤2000 点、总线数 ≤50），8 MiB 足够；
/// 读取时用 `chunk()` 流式累计，超过上限立即中止，而不是先 `bytes()` 全量读入。
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// 面板 → hub 的请求超时。series 查询最多 32 天，留足时间。
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

/// hub 响应。
#[derive(Debug)]
pub struct HubReply {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

/// 访问 hub 失败。
#[derive(Debug)]
pub enum ProxyError {
    /// 连接失败、超时等。
    Unreachable(String),
    /// hub 返回了异常巨大的响应。
    TooLarge,
    /// 读响应体失败。
    Body(String),
}

impl ProxyError {
    fn code(&self) -> &'static str {
        match self {
            ProxyError::Unreachable(_) => "hub_unreachable",
            ProxyError::TooLarge => "hub_response_too_large",
            ProxyError::Body(_) => "hub_body_error",
        }
    }
}

/// hub 管理 API 客户端。
#[derive(Clone)]
pub struct ProxyClient {
    client: reqwest::Client,
    base: Url,
    token: String,
}

impl ProxyClient {
    pub fn new(hub_url: &str, token: &str) -> Result<Self> {
        if token.trim().is_empty() {
            bail!("hub token 为空，面板无法访问管理 API");
        }
        let base =
            Url::parse(hub_url.trim()).with_context(|| format!("hub 地址非法: {hub_url}"))?;
        if base.scheme() != "http" {
            bail!(
                "M2 面板只支持 http:// 的 hub 地址（当前 {}）",
                base.scheme()
            );
        }
        if base.host_str().is_none() {
            bail!("hub 地址缺少主机名: {hub_url}");
        }
        if base.query().is_some() || base.fragment().is_some() {
            bail!("hub 地址不能带查询串或片段: {hub_url}");
        }
        let client = reqwest::Client::builder()
            // 面板 → hub 是固定的服务端地址，且请求带 `Authorization: Bearer`。
            // 必须禁用 reqwest 默认的 HTTP_PROXY/ALL_PROXY 环境代理：否则运维机器/
            // 容器里一个全局代理变量就会把 hub 管理 token 发给环境代理。
            .no_proxy()
            .redirect(Policy::none())
            .timeout(UPSTREAM_TIMEOUT)
            .build()
            .context("构建 hub HTTP 客户端失败")?;
        Ok(Self {
            client,
            base,
            token: token.to_string(),
        })
    }

    /// 由固定的 API 路径与白名单查询参数构造上游 URL。
    fn endpoint(&self, path: &str, query: &[(String, String)]) -> Result<Url> {
        debug_assert!(path.starts_with('/'));
        let mut url = self.base.clone();
        url.set_path(path);
        if !query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }
        Ok(url)
    }

    pub async fn get(
        &self,
        path: &str,
        query: &[(String, String)],
    ) -> std::result::Result<HubReply, ProxyError> {
        let url = self
            .endpoint(path, query)
            .map_err(|e| ProxyError::Unreachable(e.to_string()))?;
        let request = self
            .client
            .get(url)
            .bearer_auth(&self.token)
            .header(header::ACCEPT, "application/json");
        send(request).await
    }

    pub async fn put_json(
        &self,
        path: &str,
        value: &Value,
    ) -> std::result::Result<HubReply, ProxyError> {
        let url = self
            .endpoint(path, &[])
            .map_err(|e| ProxyError::Unreachable(e.to_string()))?;
        let request = self
            .client
            .put(url)
            .bearer_auth(&self.token)
            .header(header::ACCEPT, "application/json")
            .json(value);
        send(request).await
    }
}

async fn send(request: reqwest::RequestBuilder) -> std::result::Result<HubReply, ProxyError> {
    let response = request
        .send()
        .await
        .map_err(|e| ProxyError::Unreachable(redact_url(&e.to_string())))?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = read_body_limited(response, MAX_RESPONSE_BYTES).await?;
    Ok(HubReply { status, body })
}

/// 流式读取响应体，最多保留 `limit` 字节；一旦超出立即中止并丢弃已读内容。
///
/// 不信任 `Content-Length`：先做快速拒绝，再在 `chunk()` 循环里逐块累计，
/// 防止分块传输（或 Content-Length 撒谎）把整个异常响应读进内存。
async fn read_body_limited(
    mut response: reqwest::Response,
    limit: usize,
) -> std::result::Result<Vec<u8>, ProxyError> {
    if response
        .content_length()
        .is_some_and(|len| len > limit as u64)
    {
        return Err(ProxyError::TooLarge);
    }
    let mut body = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|e| ProxyError::Body(redact_url(&e.to_string())))?;
        let Some(chunk) = chunk else {
            return Ok(body);
        };
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(ProxyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
}

/// reqwest 的错误串可能带完整 URL；URL 不含 token，但仍去掉查询串避免泄露部署细节。
fn redact_url(message: &str) -> String {
    message.split('?').next().unwrap_or(message).to_string()
}

/// 把 hub 的响映射成浏览器可用的响应。
///
/// 无论上游返回什么 `Content-Type`，面板 `/api/*` 一律声明 `application/json`：
/// 若原样透传 `text/html`，上游一旦返回 HTML，浏览器会在面板 origin 下解析执行。
pub fn hub_reply_to_response(reply: HubReply) -> Response {
    if reply.status == StatusCode::UNAUTHORIZED {
        tracing::error!(
            status = 401,
            "hub 管理 API 拒绝面板 token（401）；请检查 panel.toml 的 token 是否与 hub 的 admin_token 一致"
        );
        return json_error(StatusCode::BAD_GATEWAY, "hub_auth_failed");
    }
    let mut response = Response::new(Body::from(reply.body));
    *response.status_mut() = reply.status;
    set_common_headers(response.headers_mut());
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// 代理失败统一返回 502；具体原因只进日志。
pub fn proxy_error_to_response(error: &ProxyError) -> Response {
    if let Some(detail) = match error {
        ProxyError::Unreachable(detail) | ProxyError::Body(detail) => Some(detail),
        ProxyError::TooLarge => None,
    } {
        tracing::warn!(error = %detail, "访问 hub 失败");
    }
    json_error(StatusCode::BAD_GATEWAY, error.code())
}

/// 统一的 JSON 错误响应。
pub fn json_error(status: StatusCode, code: &str) -> Response {
    let body = serde_json::json!({ "error": code }).to_string();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    set_common_headers(response.headers_mut());
    response
}

fn set_common_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

/// 只允许 hub 真实生成的安全字符集（UUID / hub-self），并排除 `.`、`..` 段。
pub fn validate_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id != "."
        && id != ".."
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// 查询串解析错误。
#[derive(Debug, PartialEq, Eq)]
pub enum QueryError {
    BadEncoding,
    UnknownParam(String),
}

impl QueryError {
    pub fn message(&self) -> String {
        match self {
            QueryError::BadEncoding => "查询参数编码非法".to_string(),
            QueryError::UnknownParam(name) => format!("不支持的查询参数: {name}"),
        }
    }
}

/// 解析并过滤查询串。只保留白名单参数，保留重复键（`metric` 可重复）。
pub fn parse_query(
    raw: Option<&str>,
    allowed: &[&str],
) -> std::result::Result<Vec<(String, String)>, QueryError> {
    let mut out = Vec::new();
    let Some(raw) = raw else {
        return Ok(out);
    };
    for pair in raw.split('&').filter(|part| !part.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key).ok_or(QueryError::BadEncoding)?;
        let value = percent_decode(value).ok_or(QueryError::BadEncoding)?;
        if !allowed.contains(&key.as_str()) {
            return Err(QueryError::UnknownParam(key));
        }
        out.push((key, value));
    }
    Ok(out)
}

/// 只解码 percent-encoding 与 `+`，非法 UTF-8 / 非法转义直接拒绝。
fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                let high = *bytes.get(index + 1)?;
                let low = *bytes.get(index + 2)?;
                out.push(hex_value(high)? << 4 | hex_value(low)?);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    fn client() -> ProxyClient {
        ProxyClient::new("http://127.0.0.1:8444", "test-token").unwrap()
    }

    #[test]
    fn rejects_bad_hub_urls() {
        assert!(ProxyClient::new("https://127.0.0.1:8444", "t").is_err());
        assert!(ProxyClient::new("ftp://127.0.0.1:8444", "t").is_err());
        assert!(ProxyClient::new("http://127.0.0.1:8444?x=1", "t").is_err());
        assert!(ProxyClient::new("http://127.0.0.1:8444", "  ").is_err());
        assert!(ProxyClient::new("http://127.0.0.1:8444/", "t").is_ok());
    }

    #[test]
    fn builds_encoded_upstream_url() {
        let client = client();
        let url = client
            .endpoint(
                "/api/v1/agents/hub-self/series",
                &[
                    ("metric".to_string(), "cpu.usage".to_string()),
                    ("metric".to_string(), "cpu.iowait".to_string()),
                    ("from".to_string(), "1000".to_string()),
                ],
            )
            .unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8444/api/v1/agents/hub-self/series?metric=cpu.usage&metric=cpu.iowait&from=1000"
        );
    }

    #[test]
    fn parses_and_filters_query() {
        let allowed = ["window_ms"];
        let parsed = parse_query(Some("window_ms=60000"), &allowed).unwrap();
        assert_eq!(parsed, vec![("window_ms".to_string(), "60000".to_string())]);
        assert!(parse_query(None, &allowed).unwrap().is_empty());
        assert!(parse_query(Some("from=1&window_ms=2"), &allowed).is_err());
        assert!(parse_query(Some("window_ms=%ZZ"), &allowed).is_err());

        let allowed = ["metric"];
        let parsed = parse_query(
            Some("metric=cpu.usage&metric=cpu.iowait&metric=cpu%2Eusage"),
            &allowed,
        )
        .unwrap();
        assert_eq!(parsed.len(), 3, "重复键必须保留，len={}", parsed.len());
        assert_eq!(parsed[2].1, "cpu.usage");
        assert!(parse_query(Some("metric=%FF"), &allowed).is_err());
    }

    #[test]
    fn validates_agent_id() {
        assert!(validate_agent_id("0f8fad5b-d9cb-469f-a165-70867728950e"));
        assert!(validate_agent_id("hub-self"));
        assert!(validate_agent_id("a_b"));
        assert!(!validate_agent_id(""));
        assert!(!validate_agent_id("."));
        assert!(!validate_agent_id(".."));
        assert!(!validate_agent_id("../etc/passwd"));
        assert!(!validate_agent_id("a/b"));
        assert!(!validate_agent_id("a b"));
        assert!(!validate_agent_id("代理"));
        assert!(!validate_agent_id(&"a".repeat(65)));
    }

    #[tokio::test]
    async fn maps_hub_401_to_502_without_leaking_upstream_body() {
        let response = hub_reply_to_response(HubReply {
            status: StatusCode::UNAUTHORIZED,
            body: br#"{"error":"unauthorized","token":"secret"}"#.to_vec(),
        });
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("hub_auth_failed"));
        assert!(!text.contains("secret"));
    }

    #[tokio::test]
    async fn preserves_other_status_codes_and_body() {
        let response = hub_reply_to_response(HubReply {
            status: StatusCode::NOT_FOUND,
            body: br#"{"error":"not_found"}"#.to_vec(),
        });
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json",
            "面板 /api/* 必须丢弃上游 Content-Type"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], br#"{"error":"not_found"}"#);

        let response = hub_reply_to_response(HubReply {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: b"boom".to_vec(),
        });
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }

    #[tokio::test]
    async fn maps_proxy_errors_to_502() {
        let response = proxy_error_to_response(&ProxyError::Unreachable(
            "tcp connect error: connection refused (os error 111)".into(),
        ));
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("hub_unreachable"));
    }

    /// 起一个只服务一次请求的原始 HTTP 服务器；返回 URL。
    fn spawn_raw_server(response: Vec<u8>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut scratch = [0u8; 1024];
                let _ = stream.read(&mut scratch);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        format!("http://{address}/api/v1/system")
    }

    fn chunked_response(chunks: &[&[u8]]) -> Vec<u8> {
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
            Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            .to_vec();
        for chunk in chunks {
            response.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            response.extend_from_slice(chunk);
            response.extend_from_slice(b"\r\n");
        }
        response.extend_from_slice(b"0\r\n\r\n");
        response
    }

    async fn get_without_proxy(url: &str) -> reqwest::Response {
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .get(url)
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn streams_body_and_rejects_oversized_responses() {
        let url = spawn_raw_server(chunked_response(&[b"abcd", b"efgh"]));
        let response = get_without_proxy(&url).await;
        assert_eq!(
            read_body_limited(response, 16).await.unwrap(),
            b"abcdefgh",
            "未超限的分块响应必须完整读出"
        );

        // 分块累计超过上限：必须在读完整个响应前中止，而不是先 bytes() 全量读入。
        let chunk = vec![b'a'; 128];
        let url = spawn_raw_server(chunked_response(&[&chunk, &chunk, &chunk]));
        let response = get_without_proxy(&url).await;
        assert!(matches!(
            read_body_limited(response, 256).await,
            Err(ProxyError::TooLarge)
        ));

        // Content-Length 撒谎/超限时先快速拒绝，不读响应体。
        let url = spawn_raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n".to_vec(),
        );
        let response = get_without_proxy(&url).await;
        assert!(matches!(
            read_body_limited(response, 32).await,
            Err(ProxyError::TooLarge)
        ));
    }

    /// reqwest 默认会读取 HTTP_PROXY/ALL_PROXY；面板访问 hub 时会带上 Bearer token，
    /// 这些环境变量必须被 `.no_proxy()` 忽略，否则 token 会被发给环境代理。
    #[tokio::test]
    async fn ignores_http_proxy_environment() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Mutex};

        static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _lock = ENV_LOCK.lock().await;

        /// 测试结束后恢复原始代理环境变量，避免影响同进程的其它测试。
        struct EnvRestore {
            saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
        }

        impl EnvRestore {
            /// `Some` 设置变量，`None` 删除变量；结束时全部恢复原值。
            fn set(values: &[(&'static str, Option<String>)]) -> Self {
                let mut saved = Vec::new();
                for (key, value) in values {
                    saved.push((*key, std::env::var_os(key)));
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
                Self { saved }
            }
        }

        impl Drop for EnvRestore {
            fn drop(&mut self) {
                for (key, value) in &self.saved {
                    match value {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }

        // 假 hub：记录 Authorization，再返回 200 + text/html（用于验证 Content-Type 被替换）。
        let hub = TcpListener::bind("127.0.0.1:0").unwrap();
        let hub_address = hub.local_addr().unwrap();
        let seen_authorization = Arc::new(Mutex::new(None::<String>));
        let seen = seen_authorization.clone();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = hub.accept() {
                let mut request = Vec::new();
                let mut scratch = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut scratch) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => request.extend_from_slice(&scratch[..read]),
                    }
                }
                let text = String::from_utf8_lossy(&request).to_string();
                let authorization = text
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("authorization:"))
                    .and_then(|line| line.split_once(':'))
                    .map(|(_, value)| value.trim().to_string());
                *seen.lock().unwrap() = authorization;
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\
                      Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
            }
        });

        // 假代理：只要收到连接就记录，并立即返回 502，避免回归时测试长时间挂住。
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        proxy.set_nonblocking(true).unwrap();
        let proxy_hit = Arc::new(AtomicBool::new(false));
        let hit = proxy_hit.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_proxy = stop.clone();
        std::thread::spawn(move || {
            while !stop_proxy.load(Ordering::SeqCst) {
                match proxy.accept() {
                    Ok((mut stream, _)) => {
                        hit.store(true, Ordering::SeqCst);
                        let _ = stream.write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\
                              Connection: close\r\n\r\n",
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        let proxy_url = format!("http://{proxy_address}");
        let _env = EnvRestore::set(&[
            ("HTTP_PROXY", Some(proxy_url.clone())),
            ("http_proxy", Some(proxy_url.clone())),
            ("ALL_PROXY", Some(proxy_url.clone())),
            ("all_proxy", Some(proxy_url)),
            // 必须显式清空免代理名单：若 CI/开发机的 NO_PROXY 含 127.0.0.1，
            // 即使删掉 `.no_proxy()` 请求也会绕过假代理，测试会假阳性。
            ("NO_PROXY", None),
            ("no_proxy", None),
            ("HTTPS_PROXY", None),
            ("https_proxy", None),
        ]);

        let client = ProxyClient::new(&format!("http://{hub_address}"), "test-hub-token").unwrap();
        let reply = client.get("/api/v1/system", &[]).await.unwrap();
        assert_eq!(reply.status, StatusCode::OK, "请求应直连 hub，而不是假代理");
        assert_eq!(
            seen_authorization.lock().unwrap().as_deref(),
            Some("Bearer test-hub-token"),
            "Bearer token 必须只发给 hub"
        );
        let response = hub_reply_to_response(reply);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json",
            "上游的 text/html 必须被丢弃"
        );

        // 给假代理一点时间“接收”本不该出现的连接，再断言零连接。
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !proxy_hit.load(Ordering::SeqCst),
            "HTTP_PROXY/ALL_PROXY 指向的假代理不应收到任何连接"
        );
        stop.store(true, Ordering::SeqCst);
    }
}
