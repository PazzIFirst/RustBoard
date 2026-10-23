//! hub 管理 API 的反向代理。
//!
//! 浏览器只同源访问面板的 `/api/*`；面板在服务端注入 Bearer token。
//! 代理层只放行方案 §3.1 里列出的端点，并对 agent_id / 查询参数做白名单校验，
//! 避免把面板变成任意 URL 的开放代理。
//!
//! 错误映射（方案 §3.2）：
//! - hub 401 → 面板 502 `hub_auth_failed`（token 错误不能让浏览器误以为会话失效）；
//! - 其余状态码原样保留（含 hub 自己的 504 `control_timeout`）；
//! - 普通 GET/PUT 连接失败 / 超时 / 响应体读失败 → 502 既有错误码；
//! - 控制 POST 超过专用超时 → 504 `control_result_unknown`（动作可能已执行）。

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
/// 面板 → hub 的普通请求超时。series 查询最多 32 天，留足时间。
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);
/// 控制 POST 专用的上游超时。
///
/// 必须严格大于 Hub 允许的最大控制等待 `MAX_REQUEST_TIMEOUT_MS`（60s）+ 执行余量：
/// Hub 会等 agent 最多 60s 才返回 `504 control_timeout`，面板若沿用 30s 会先超时，
/// 把“结果可能已执行”误报成普通网络错误。固定 70s 而不是做成配置项，避免新增一个
/// 可能被配错的字段；若 Hub 提高上限，必须同步调大本常量并由测试断言兜底。
const CONTROL_UPSTREAM_TIMEOUT: Duration = Duration::from_secs(70);
/// 控制 POST 超时后的固定说明；前端按 `control_result_unknown` 展示同语义提示。
const CONTROL_RESULT_UNKNOWN_MESSAGE: &str = "控制请求结果未知，动作可能已执行，请核对状态";

/// hub 响应。
#[derive(Debug)]
pub struct HubReply {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

/// 访问 hub 失败。
#[derive(Debug)]
pub enum ProxyError {
    /// 连接失败等普通上游错误。
    Unreachable(String),
    /// 控制 POST 超过面板专用超时：hub 是否完成执行未知。
    Timeout(String),
    /// hub 返回了异常巨大的响应。
    TooLarge,
    /// 读响应体失败。
    Body(String),
    /// 读响应体超时（已收到响应头、未读完 body）；控制路径会转成 [`Self::Timeout`]。
    BodyTimeout(String),
}

impl ProxyError {
    fn code(&self) -> &'static str {
        match self {
            ProxyError::Unreachable(_) => "hub_unreachable",
            ProxyError::Timeout(_) => "control_result_unknown",
            ProxyError::TooLarge => "hub_response_too_large",
            ProxyError::Body(_) | ProxyError::BodyTimeout(_) => "hub_body_error",
        }
    }
}

/// 判断 host 是否只指向本机回环。
///
/// `Url::host_str()` 对 IPv6 返回带方括号的形式（例如 `[::1]`），必须先去掉方括号
/// 再交给 `IpAddr` 解析，否则合法回环地址会被误判为非回环。
fn is_loopback_host(host: &str) -> bool {
    let bare = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    bare.eq_ignore_ascii_case("localhost")
        || bare
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// hub 管理 API 客户端。
#[derive(Clone)]
pub struct ProxyClient {
    client: reqwest::Client,
    base: Url,
    token: String,
    /// 配置的私有 CA 路径；仅用于错误提示，请求已由 reqwest 内置信任库持有。
    hub_ca: Option<String>,
}

impl ProxyClient {
    /// 构造 hub 客户端。
    ///
    /// 安全约束（v0.3.3）：
    /// - `http://` 只允许回环 host（`localhost`、127.0.0.0/8、`::1`）：面板会把 Bearer token
    ///   发给 hub，明文链路不能出本机；远程 hub 必须 `https://`。
    /// - `https://` 允许任意 host；`hub_ca` 非空时只信任该 PEM（可含多张证书），
    ///   系统根证书不参与校验；为空时使用系统根证书。
    /// - `http://` + `hub_ca` 是配置矛盾：不会加密，必须拒绝，避免误以为已启用 TLS。
    pub fn new(hub_url: &str, token: &str, hub_ca: &str) -> Result<Self> {
        if token.trim().is_empty() {
            bail!("hub token 为空，面板无法访问管理 API");
        }
        let base =
            Url::parse(hub_url.trim()).with_context(|| format!("hub 地址非法: {hub_url}"))?;
        let scheme = base.scheme();
        if scheme != "http" && scheme != "https" {
            bail!("hub 地址只支持 http:// 或 https://（当前 {scheme}）");
        }
        let Some(host) = base.host_str() else {
            bail!("hub 地址缺少主机名: {hub_url}");
        };
        if scheme == "http" && !is_loopback_host(host) {
            bail!(
                "hub 地址 {hub_url} 是非回环的明文 http：面板会把 hub token 发到网络上；\
                 请改用 https://（私有 CA 需同时配置 hub_ca），或只连回环地址\
                 （localhost、127.0.0.0/8、::1）"
            );
        }
        if base.query().is_some() || base.fragment().is_some() {
            bail!("hub 地址不能带查询串或片段: {hub_url}");
        }

        let ca_path = hub_ca.trim();
        if !ca_path.is_empty() && scheme != "https" {
            bail!(
                "hub_ca 只能与 https:// 的 hub 地址一起使用（当前 {scheme}）；\
                 明文 http 配了 CA 不会加密，请先把 hub_url 改成 https://"
            );
        }

        let mut builder = reqwest::Client::builder()
            // 面板 → hub 是固定的服务端地址，且请求带 `Authorization: Bearer`。
            // 必须禁用 reqwest 默认的 HTTP_PROXY/ALL_PROXY 环境代理：否则运维机器/
            // 容器里一个全局代理变量就会把 hub 管理 token 发给环境代理。
            .no_proxy()
            .redirect(Policy::none())
            .timeout(UPSTREAM_TIMEOUT);
        let hub_ca = if ca_path.is_empty() {
            builder = builder.tls_built_in_root_certs(true);
            None
        } else {
            // 配了私有 CA 就只信任它：不叠加系统根/公共 CA，避免本应只被私有 CA
            // 保护的 hub 被任意公网证书冒充。空 PEM、非 PEM 与无法解析的证书都在启动期拒绝。
            builder = builder.tls_built_in_root_certs(false);
            let pem = std::fs::read_to_string(ca_path)
                .with_context(|| format!("读取 hub_ca 失败: {ca_path}"))?;
            let certs = rustboard_common::tls::load_certs(&pem)
                .with_context(|| format!("hub_ca 不是有效的 PEM 证书: {ca_path}"))?;
            for cert in certs {
                let cert = reqwest::Certificate::from_der(cert.as_ref())
                    .with_context(|| format!("hub_ca 中的证书无法载入: {ca_path}"))?;
                builder = builder.add_root_certificate(cert);
            }
            Some(ca_path.to_string())
        };
        if let Some(ca_path) = hub_ca.as_deref() {
            tracing::info!(
                hub_ca = ca_path,
                "hub 使用私有 CA：仅信任 hub_ca，系统根证书不参与校验"
            );
        }
        let client = builder.build().context("构建 hub HTTP 客户端失败")?;
        Ok(Self {
            client,
            base,
            token: token.to_string(),
            hub_ca,
        })
    }

    /// 网络错误详情：配置私有 CA 时明确提示系统根不参与，便于排查证书链问题。
    ///
    /// 只追加固定说明与 CA 路径，不包含 token。
    fn describe_error(&self, error: &reqwest::Error) -> String {
        let detail = redact_url(&error.to_string());
        match self.hub_ca.as_deref() {
            Some(ca_path) => {
                format!("{detail}（已配置 hub_ca={ca_path}：仅信任该 CA，系统根证书不参与校验）")
            }
            None => detail,
        }
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
        send(self, request).await
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
        send(self, request).await
    }

    /// POST 一个 JSON 请求体到 hub。
    ///
    /// 控制面写操作固定使用 [`CONTROL_UPSTREAM_TIMEOUT`]：它必须覆盖 Hub 的
    /// 最长控制等待，否则面板会在 hub 仍等待 agent 时先报网络错误。
    pub async fn post_json(
        &self,
        path: &str,
        value: &Value,
    ) -> std::result::Result<HubReply, ProxyError> {
        self.post_json_with_timeout(path, value, CONTROL_UPSTREAM_TIMEOUT)
            .await
    }

    /// POST 一个 JSON 请求体到 hub，并使用请求级超时覆盖 client 的全局 30s。
    ///
    /// 单独暴露 `timeout` 是为了让测试能用毫秒级超时覆盖真实的 reqwest 超时路径，
    /// 而不必在常规 CI 里等待几十秒；生产代码只经由 [`Self::post_json`] 使用它。
    async fn post_json_with_timeout(
        &self,
        path: &str,
        value: &Value,
        timeout: Duration,
    ) -> std::result::Result<HubReply, ProxyError> {
        let url = self
            .endpoint(path, &[])
            .map_err(|e| ProxyError::Unreachable(e.to_string()))?;
        let request = self
            .client
            .post(url)
            .bearer_auth(&self.token)
            .header(header::ACCEPT, "application/json")
            .json(value);
        send_with_timeout(self, request, timeout).await
    }
}

async fn send(
    client: &ProxyClient,
    request: reqwest::RequestBuilder,
) -> std::result::Result<HubReply, ProxyError> {
    let response = request
        .send()
        .await
        .map_err(|e| ProxyError::Unreachable(client.describe_error(&e)))?;
    collect_reply(response).await
}

/// 带请求级超时的发送；只用于控制 POST（普通 GET/PUT 保持 30s 与既有错误语义）。
///
/// `.timeout(timeout)` 覆盖 client 的全局 `UPSTREAM_TIMEOUT`；请求阶段超时映射为
/// [`ProxyError::Timeout`]，其它连接错误仍是 [`ProxyError::Unreachable`]。
/// 已收到响应头、读 body 阶段才超时时，`read_body_limited` 返回
/// [`ProxyError::BodyTimeout`]；控制路径同样视为“结果未知”，统一转成 `Timeout`。
async fn send_with_timeout(
    client: &ProxyClient,
    request: reqwest::RequestBuilder,
    timeout: Duration,
) -> std::result::Result<HubReply, ProxyError> {
    let response = request.timeout(timeout).send().await.map_err(|e| {
        if e.is_timeout() {
            ProxyError::Timeout(redact_url(&e.to_string()))
        } else {
            ProxyError::Unreachable(client.describe_error(&e))
        }
    })?;
    collect_reply(response).await.map_err(|error| match error {
        ProxyError::BodyTimeout(detail) => ProxyError::Timeout(detail),
        other => other,
    })
}

/// 读取状态码与受限响应体；`send` / `send_with_timeout` 共用。
async fn collect_reply(response: reqwest::Response) -> std::result::Result<HubReply, ProxyError> {
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
        let chunk = response.chunk().await.map_err(|e| {
            let detail = redact_url(&e.to_string());
            if e.is_timeout() {
                // 单独标记：控制 POST 会把“读 body 超时”视为结果未知，
                // 普通 GET/PUT 仍按既有 502 `hub_body_error` 语义处理。
                ProxyError::BodyTimeout(detail)
            } else {
                ProxyError::Body(detail)
            }
        })?;
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

/// 代理失败统一映射：普通错误 502；控制 POST 超时 504 且标记结果未知。
///
/// 具体原因只进日志；响应体只暴露固定的错误码与说明，不回显上游内容。
pub fn proxy_error_to_response(error: &ProxyError) -> Response {
    match error {
        ProxyError::Timeout(detail) => {
            // 不能把控制超时当普通网络错误：hub/agent 可能已经执行了动作。
            tracing::warn!(error = %detail, "控制请求超时，结果未知");
            json_error_with_message(
                StatusCode::GATEWAY_TIMEOUT,
                error.code(),
                CONTROL_RESULT_UNKNOWN_MESSAGE,
            )
        }
        ProxyError::BodyTimeout(detail) => {
            // 只有普通 GET/PUT 会走到这里：控制 POST 已在 `send_with_timeout`
            // 把读 body 超时转成 `Timeout`；普通请求保持既有 502 语义。
            tracing::warn!(error = %detail, "读取 hub 响应体超时");
            json_error(StatusCode::BAD_GATEWAY, error.code())
        }
        ProxyError::Unreachable(detail) | ProxyError::Body(detail) => {
            tracing::warn!(error = %detail, "访问 hub 失败");
            json_error(StatusCode::BAD_GATEWAY, error.code())
        }
        ProxyError::TooLarge => json_error(StatusCode::BAD_GATEWAY, error.code()),
    }
}

/// 统一的 JSON 错误响应。
pub fn json_error(status: StatusCode, code: &str) -> Response {
    json_response(status, serde_json::json!({ "error": code }))
}

/// 带固定说明的 JSON 错误响应；`message` 是面板自己的文案，不来自上游。
pub fn json_error_with_message(status: StatusCode, code: &str, message: &str) -> Response {
    json_response(
        status,
        serde_json::json!({ "error": code, "message": message }),
    )
}

/// 构造带统一响应头的 JSON 响应。
fn json_response(status: StatusCode, body: Value) -> Response {
    let body = body.to_string();
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
    use std::path::{Path, PathBuf};

    use super::*;
    use axum::body::to_bytes;
    use rustboard_common::control::MAX_REQUEST_TIMEOUT_MS;
    use rustboard_common::tls::{cert_dir, ensure_hub_material, server_config, CertPolicy};

    fn client() -> ProxyClient {
        ProxyClient::new("http://127.0.0.1:8444", "test-token", "").unwrap()
    }

    /// 回环 http 继续可用（同机部署不需要证书）。
    #[test]
    fn accepts_loopback_http_hub_urls() {
        for url in [
            "http://127.0.0.1:8444",
            "http://127.0.0.1:8444/",
            "http://127.10.20.30:8444",
            "http://localhost:8444",
            "http://LOCALHOST:8444",
            "http://[::1]:8444",
        ] {
            assert!(
                ProxyClient::new(url, "t", "").is_ok(),
                "回环 http 地址必须被接受: {url}"
            );
        }
    }

    /// 远程/容器部署的明文 http 会把 Bearer token 发到网络上，启动必须失败并提示 https。
    #[test]
    fn rejects_non_loopback_http_hub_urls() {
        for url in [
            "http://hub.example.com:8444",
            "http://192.168.1.10:8444",
            "http://10.0.0.5:8444",
            "http://0.0.0.0:8444",
            "http://[2001:db8::1]:8444",
        ] {
            let error = ProxyClient::new(url, "super-secret-token", "")
                .err()
                .expect("非回环明文 http 必须拒绝");
            let text = error.to_string();
            assert!(
                text.contains("https://"),
                "错误信息必须提示改用 https://: {text}"
            );
            assert!(
                !text.contains("super-secret-token"),
                "错误信息不得回显 token: {text}"
            );
        }
    }

    #[test]
    fn accepts_https_hub_urls() {
        for url in [
            "https://127.0.0.1:8444",
            "https://hub.example.com",
            "https://10.1.2.3:8444",
            "https://[2001:db8::1]:8444",
        ] {
            assert!(
                ProxyClient::new(url, "t", "").is_ok(),
                "https 允许任意主机: {url}"
            );
        }
    }

    #[test]
    fn rejects_bad_hub_urls() {
        assert!(ProxyClient::new("ftp://127.0.0.1:8444", "t", "").is_err());
        assert!(ProxyClient::new("http://127.0.0.1:8444?x=1", "t", "").is_err());
        assert!(ProxyClient::new("http://127.0.0.1:8444#frag", "t", "").is_err());
        assert!(ProxyClient::new("http://127.0.0.1:8444", "  ", "").is_err());
        assert!(ProxyClient::new("not a url", "t", "").is_err());
        assert!(ProxyClient::new("", "t", "").is_err());
    }

    /// `http` + `hub_ca` 是配置矛盾：不会加密，必须拒绝，避免误以为已启用 TLS。
    #[test]
    fn rejects_http_with_hub_ca() {
        let error = ProxyClient::new("http://127.0.0.1:8444", "t", "/does/not/exist.crt")
            .err()
            .expect("http + hub_ca 必须拒绝，而不是静默忽略 CA");
        let text = error.to_string();
        assert!(text.contains("hub_ca"), "错误信息: {text}");
        assert!(text.contains("https"), "错误信息: {text}");
    }

    #[test]
    fn rejects_missing_hub_ca_file() {
        let dir = TempDir::new("missing-ca");
        let path = dir.path().join("nope.crt");
        let error = ProxyClient::new("https://127.0.0.1:8444", "t", path.to_str().unwrap())
            .err()
            .expect("hub_ca 文件不存在必须启动失败");
        assert!(
            error.to_string().contains(path.to_str().unwrap()),
            "错误信息必须给出 CA 路径: {error}"
        );
    }

    #[test]
    fn rejects_non_pem_hub_ca() {
        let dir = TempDir::new("non-pem-ca");
        let path = dir.path().join("ca.crt");
        std::fs::write(&path, "this is not a certificate\n").unwrap();
        let error = ProxyClient::new("https://127.0.0.1:8444", "t", path.to_str().unwrap())
            .err()
            .expect("非 PEM 的 hub_ca 必须启动失败");
        assert!(error.to_string().contains("PEM"), "错误信息: {error}");
    }

    #[test]
    fn rejects_empty_pem_hub_ca() {
        let dir = TempDir::new("empty-ca");
        let path = dir.path().join("ca.crt");
        std::fs::write(&path, "  \n\n").unwrap();
        let error = ProxyClient::new("https://127.0.0.1:8444", "t", path.to_str().unwrap())
            .err()
            .expect("空 PEM 的 hub_ca 必须启动失败");
        assert!(error.to_string().contains("PEM"), "错误信息: {error}");
    }

    /// 私有 CA 支持 bundle（多张证书），客户端构建成功；字段记录用于错误提示。
    #[test]
    fn accepts_https_with_private_ca_bundle() {
        let (_dir_a, ca_a) = test_ca_material("ca-a");
        let (_dir_b, ca_b) = test_ca_material("ca-b");
        let bundle_dir = TempDir::new("ca-bundle");
        let bundle = bundle_dir.path().join("bundle.pem");
        let mut pem = std::fs::read_to_string(&ca_a).unwrap();
        pem.push_str(&std::fs::read_to_string(&ca_b).unwrap());
        std::fs::write(&bundle, pem).unwrap();

        let client =
            ProxyClient::new("https://127.0.0.1:8444", "t", bundle.to_str().unwrap()).unwrap();
        assert_eq!(
            client.hub_ca.as_deref(),
            Some(bundle.to_str().unwrap()),
            "配置了私有 CA 时必须记录路径，供错误提示说明系统根不参与"
        );
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

    #[test]
    fn control_timeout_exceeds_hub_max_request_timeout() {
        assert!(
            CONTROL_UPSTREAM_TIMEOUT > Duration::from_millis(MAX_REQUEST_TIMEOUT_MS),
            "面板控制超时 {CONTROL_UPSTREAM_TIMEOUT:?} 必须严格大于 Hub 最大控制等待 \
             {MAX_REQUEST_TIMEOUT_MS}ms，否则面板会先于 Hub 报错"
        );
    }

    #[tokio::test]
    async fn maps_control_post_timeout_to_504_result_unknown() {
        let url = spawn_delayed_server(
            Duration::from_millis(100),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
        );
        let client = ProxyClient::new(&url, "test-token", "").unwrap();
        let error = client
            .post_json_with_timeout(
                "/api/v1/agents/hub-self/control",
                &serde_json::json!({ "capability": "process", "action": "list" }),
                Duration::from_millis(10),
            )
            .await
            .expect_err("10ms 超时必须返回 Timeout");
        assert!(
            matches!(error, ProxyError::Timeout(_)),
            "超时必须映射为 Timeout，实际: {error:?}"
        );
        assert_eq!(error.code(), "control_result_unknown");

        let response = proxy_error_to_response(&error);
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"], "control_result_unknown");
        assert_eq!(value["message"], CONTROL_RESULT_UNKNOWN_MESSAGE);
        assert!(
            value["message"]
                .as_str()
                .unwrap()
                .contains("动作可能已执行"),
            "504 文案必须明确结果未知、动作可能已执行"
        );
    }

    #[tokio::test]
    async fn control_post_succeeds_within_timeout() {
        let url = spawn_delayed_server(
            Duration::from_millis(100),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
        );
        let client = ProxyClient::new(&url, "test-token", "").unwrap();
        let reply = client
            .post_json_with_timeout(
                "/api/v1/agents/hub-self/control",
                &serde_json::json!({ "capability": "process", "action": "list" }),
                Duration::from_secs(5),
            )
            .await
            .expect("慢于 10ms 但在 5s 内的响应必须成功");
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body, b"{}");
    }

    #[tokio::test]
    async fn passes_through_hub_control_timeout_body() {
        // Hub 自己等待 agent 超时后的 504 body 必须原样透传，不能被面板改写成 502。
        let hub_body =
            r#"{"error":{"code":"control_timeout","message":"agent 未在限定时间内响应"}}"#
                .as_bytes()
                .to_vec();
        let response = hub_reply_to_response(HubReply {
            status: StatusCode::GATEWAY_TIMEOUT,
            body: hub_body.clone(),
        });
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], &hub_body[..], "Hub 的 504 body 必须原样保留");
    }

    #[tokio::test]
    async fn maps_control_body_timeout_to_504_result_unknown() {
        // 已收到响应头 + 部分 body，随后 body 卡住：控制 POST 仍必须标记结果未知。
        let url = spawn_slow_body_server(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\
              Connection: close\r\n\r\n{"
                .to_vec(),
            b"}".to_vec(),
            Duration::from_millis(200),
        );
        let client = ProxyClient::new(&url, "test-token", "").unwrap();
        let error = client
            .post_json_with_timeout(
                "/api/v1/agents/hub-self/control",
                &serde_json::json!({ "capability": "process", "action": "list" }),
                Duration::from_millis(50),
            )
            .await
            .expect_err("收到响应头后读 body 超时必须返回 Timeout");
        assert!(
            matches!(error, ProxyError::Timeout(_)),
            "控制路径的 body 读超时必须映射为 Timeout，实际: {error:?}"
        );
        assert_eq!(error.code(), "control_result_unknown");

        let response = proxy_error_to_response(&error);
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"], "control_result_unknown");
        assert_eq!(value["message"], CONTROL_RESULT_UNKNOWN_MESSAGE);
    }

    #[tokio::test]
    async fn plain_request_body_timeout_stays_502_hub_body_error() {
        // 普通 GET/PUT 的 body 读超时保持既有 502 `hub_body_error` 语义。
        let url = spawn_slow_body_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{".to_vec(),
            b"}".to_vec(),
            Duration::from_millis(400),
        );
        let response = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap()
            .get(&url)
            .send()
            .await
            .unwrap();
        let error = read_body_limited(response, 4096)
            .await
            .expect_err("读 body 超过 client 超时必须失败");
        assert!(
            matches!(error, ProxyError::BodyTimeout(_)),
            "普通请求 body 读超时必须标记为 BodyTimeout，实际: {error:?}"
        );
        let response = proxy_error_to_response(&error);
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("hub_body_error"));
    }

    /// 测试用临时目录：进程 id + 自增序号，Drop 时清理。
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            use std::sync::atomic::{AtomicU32, Ordering};
            static COUNTER: AtomicU32 = AtomicU32::new(0);
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("rb-panel-{}-{tag}-{seq}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// 生成一套真实 CA + 服务端证书（SAN=127.0.0.1）；返回临时目录与 CA 证书路径。
    fn test_ca_material(tag: &str) -> (TempDir, PathBuf) {
        let dir = TempDir::new(tag);
        ensure_hub_material(
            dir.path(),
            &["127.0.0.1".to_string()],
            CertPolicy::default(),
        )
        .unwrap();
        let ca_path = cert_dir(dir.path()).join(rustboard_common::tls::CA_CERT_FILE);
        (dir, ca_path)
    }

    /// 起一个只服务一次请求的 TLS mock hub（TLS 1.3，服务端证书由测试 CA 签发）。
    async fn spawn_tls_hub(data_dir: &Path) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let acceptor = tokio_rustls::TlsAcceptor::from(server_config(data_dir).unwrap());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut tls) = acceptor.accept(stream).await else {
                // 客户端使用错误 CA 时握手在服务端也会失败；这里不 panic，
                // 让测试通过客户端错误断言握手确实被拒绝。
                return;
            };
            let mut request = Vec::new();
            let mut scratch = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match tls.read(&mut scratch).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&scratch[..read]),
                }
            }
            let _ = tls
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                      Content-Length: 2\r\nConnection: close\r\n\r\n{}",
                )
                .await;
            let _ = tls.flush().await;
            let _ = tls.shutdown().await;
        });
        (address, handle)
    }

    /// 正确 CA：真实 TLS 握手必须成功，并完成一次 GET。
    #[tokio::test]
    async fn https_with_private_ca_handshakes_against_tls_hub() {
        let (dir, ca_path) = test_ca_material("tls-ok");
        let (address, handle) = spawn_tls_hub(dir.path()).await;
        let client = ProxyClient::new(
            &format!("https://{address}"),
            "test-token",
            ca_path.to_str().unwrap(),
        )
        .unwrap();

        let reply = client
            .get("/api/v1/system", &[])
            .await
            .expect("正确 hub_ca 必须完成 TLS 握手并读到响应");
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.body, b"{}");
        handle.await.unwrap();
    }

    /// 错误 CA：真实 TLS 握手必须失败，且错误详情说明只信任 hub_ca。
    #[tokio::test]
    async fn https_with_wrong_private_ca_fails_handshake() {
        let (server_dir, _) = test_ca_material("tls-server");
        let (_client_dir, client_ca) = test_ca_material("tls-client");
        let (address, handle) = spawn_tls_hub(server_dir.path()).await;
        let client = ProxyClient::new(
            &format!("https://{address}"),
            "test-token",
            client_ca.to_str().unwrap(),
        )
        .unwrap();

        let error = client
            .get("/api/v1/system", &[])
            .await
            .expect_err("错误 hub_ca 必须握手失败，不能退化为明文或信任系统根");
        assert!(
            matches!(error, ProxyError::Unreachable(_)),
            "错误 CA 必须映射为 Unreachable，实际: {error:?}"
        );
        if let ProxyError::Unreachable(detail) = &error {
            assert!(
                detail.contains("系统根证书不参与校验"),
                "错误详情应说明只信任 hub_ca: {detail}"
            );
        }
        handle.await.unwrap();
    }

    /// 起一个只服务一次请求的原始 HTTP 服务器；返回 URL。
    fn spawn_raw_server(response: Vec<u8>) -> String {
        format!(
            "{}/api/v1/system",
            spawn_delayed_server(Duration::ZERO, response)
        )
    }

    /// 起一个延迟 `delay` 后才返回固定响应的原始 HTTP 服务器；返回 base URL。
    fn spawn_delayed_server(delay: Duration, response: Vec<u8>) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut scratch = [0u8; 1024];
                let _ = stream.read(&mut scratch);
                std::thread::sleep(delay);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        format!("http://{address}")
    }

    /// 先发 `head`（含响应头与部分 body），延迟 `delay` 后再发 `tail`。
    ///
    /// 用于覆盖“已收到响应头、读 body 阶段才超时”的边界。
    fn spawn_slow_body_server(head: Vec<u8>, tail: Vec<u8>, delay: Duration) -> String {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut scratch = [0u8; 1024];
                let _ = stream.read(&mut scratch);
                let _ = stream.write_all(&head);
                let _ = stream.flush();
                std::thread::sleep(delay);
                let _ = stream.write_all(&tail);
                let _ = stream.flush();
            }
        });
        format!("http://{address}")
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

        let client =
            ProxyClient::new(&format!("http://{hub_address}"), "test-hub-token", "").unwrap();
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
