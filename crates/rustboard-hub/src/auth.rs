//! 管理 API 鉴权与 scoped token 授权。
//!
//! 一次请求的完整顺序（与 v0.2 的单一 admin_token 行为兼容）：
//! 1. 解析 `Authorization: Bearer <token>`（scheme 大小写不敏感，只接受两段）；
//! 2. 先常量时间比较旧 `admin_token`，命中即 `admin` scope 的兼容主体；
//! 3. 否则 SHA-256(token) 后查 `api_tokens`，只认未吊销行；
//! 4. 认证失败固定 401 + `WWW-Authenticate: Bearer`，不回显 token / 内部错误，
//!    不写审计，只 `warn` 记录来源 IP；
//! 5. 认证成功后才进入每 IP 限速（401 先于 429，未认证请求不消耗额度）；
//! 6. 按「已知路由 + 方法」精确校验 scope（见 [`required_scope`]）：
//!    `read < write < admin`，权限不足 403 `forbidden_scope`，不写控制审计；
//! 7. 把 [`AuthPrincipal`] 放进 request extensions，供控制面写审计 actor。
//!
//! `/healthz` 不经过本中间件；未知 `/api/v1/*` 先认证，再由路由返回 404/405，
//! 不因为 token scope 变成 403（避免用 403 泄露路由是否存在）。

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rustboard_common::tls::sha256_hex;
use rustboard_common::util::{constant_time_eq, now_ms};

use crate::AppState;

/// 管理 API token 的权限层级：`read < write < admin`。
///
/// `write` 隐含 `read`；`admin` 通过全部检查（预留给未来的 HTTP token 管理，
/// 本阶段 token 管理只走 CLI）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenScope {
    Read,
    Write,
    Admin,
}

impl TokenScope {
    /// 把数据库 / CLI 里的字符串解析成枚举；非法值返回 `None`。
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }

    /// 字符串形式，与 `api_tokens.scope` 的 CHECK 约束一致。
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Write => 1,
            Self::Admin => 2,
        }
    }
}

/// `granted` 是否覆盖 `required`（层级比较，`admin` 通过一切）。
pub fn scope_allows(granted: TokenScope, required: TokenScope) -> bool {
    granted.rank() >= required.rank()
}

/// 通过鉴权的请求主体；控制面用它写审计 actor。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPrincipal {
    /// 旧 `admin_token` 为 `"admin"`；scoped token 为 token name。
    pub name: String,
    pub scope: TokenScope,
    /// 是否来自旧 `admin_token` 兼容路径（审计 actor 保持 `"admin"`）。
    pub legacy: bool,
}

/// 认证失败原因：只用于日志分类，绝不回显给客户端。
enum AuthFailure {
    /// 缺失 / 格式错误 / 查无此 token / 已吊销。
    Unauthorized,
    /// 数据库里的 scope 非法：按未认证处理并 warn（不猜测权限）。
    IllegalScope(String),
    /// 存储错误：安全默认拒绝（401），不能放行。
    Backend(String),
}

/// 管理 API 鉴权 + 限速 + scope 授权中间件。
///
/// 401 固定 `{"error":"unauthorized"}`，403 固定 `{"error":"forbidden_scope"}`；
/// 两者都不写审计，只 warn 记录来源 IP。
pub(crate) async fn require_auth(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let principal = match resolve_principal(&state, request.headers()).await {
        Ok(principal) => principal,
        Err(AuthFailure::Unauthorized) => {
            tracing::warn!(ip = %peer.ip(), "管理 API 鉴权失败");
            return unauthorized();
        }
        Err(AuthFailure::IllegalScope(name)) => {
            tracing::warn!(
                ip = %peer.ip(),
                token_name = %name,
                "api_tokens.scope 非法，按未认证处理"
            );
            return unauthorized();
        }
        Err(AuthFailure::Backend(err)) => {
            tracing::warn!(
                ip = %peer.ip(),
                error = %err,
                "校验 api_token 失败，按未认证拒绝"
            );
            return unauthorized();
        }
    };

    // 401 先于 429：未认证请求不能消耗限速额度（沿用 v0.2.1 KI-05 顺序）。
    let is_write = crate::is_admin_write_method(request.method());
    if let Err(retry_after) = state.admin_rate.check(peer.ip(), is_write) {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({ "error": "rate_limited" })),
        )
            .into_response();
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&retry_after.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("60")),
        );
        return response;
    }

    // 只对「已知路由 + 方法」做 scope 校验；未知路由留给 axum 返回 404/405。
    if let Some(required) = required_scope(request.method(), request.uri().path()) {
        if !scope_allows(principal.scope, required) {
            tracing::warn!(
                ip = %peer.ip(),
                token_name = %principal.name,
                path = %request.uri().path(),
                required = required.as_str(),
                "管理 API token scope 不足"
            );
            return forbidden_scope();
        }
    }

    request.extensions_mut().insert(principal);
    next.run(request).await
}

/// 认证主体解析：旧 admin_token 优先，其次查 scoped token。
async fn resolve_principal(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<AuthPrincipal, AuthFailure> {
    if bearer_token(headers).is_none() {
        return Err(AuthFailure::Unauthorized);
    }

    // 兼容路径：常量时间比较旧 admin_token；空 token 永远不匹配。
    if bearer_matches(headers, &state.cfg.admin_token) {
        return Ok(AuthPrincipal {
            name: "admin".to_string(),
            scope: TokenScope::Admin,
            legacy: true,
        });
    }

    let Some(token) = bearer_token(headers) else {
        return Err(AuthFailure::Unauthorized);
    };
    let token_hash = sha256_hex(token);
    let now = now_ms();
    let storage = state.storage.clone();
    let record =
        tokio::task::spawn_blocking(move || storage.authenticate_api_token(&token_hash, now))
            .await
            .map_err(|err| AuthFailure::Backend(err.to_string()))?
            .map_err(|err| AuthFailure::Backend(err.to_string()))?;

    let Some(record) = record else {
        return Err(AuthFailure::Unauthorized);
    };
    let Some(scope) = TokenScope::parse(&record.scope) else {
        return Err(AuthFailure::IllegalScope(record.name));
    };
    Ok(AuthPrincipal {
        name: record.name,
        scope,
        legacy: false,
    })
}

/// 解析 `Authorization: Bearer <token>`，只接受「scheme + 单个 token」两段。
///
/// scheme 大小写不敏感；多余分段（token 里带空格）与空 token 直接拒绝。
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let mut parts = value.split_ascii_whitespace();
    let (Some(scheme), Some(token), None, None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() {
        return None;
    }
    Some(token)
}

/// 当前请求携带的 Bearer token 是否等于 `expected`（常量时间比较）。
///
/// 旧 `admin_token` 兼容路径与既有单测都走这里；`expected` 为空永远不匹配。
pub(crate) fn bearer_matches(headers: &HeaderMap, expected: &str) -> bool {
    if expected.is_empty() {
        return false;
    }
    bearer_token(headers)
        .is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes()))
}

/// 已知路由所需的 scope；未知路由 / 方法返回 `None`（认证后交给路由 404/405）。
///
/// 精确到「路径 + 方法」，不能按 HTTP 方法一刀切：`GET /api/v1/agents/{id}/control`
/// 是只读（Read），而 `POST` 同一路径才是 Write。
pub(crate) fn required_scope(method: &Method, path: &str) -> Option<TokenScope> {
    let is_read_route = matches!(
        path,
        "/api/v1/system"
            | "/api/v1/agents"
            | "/api/v1/series"
            | "/api/v1/overview"
            | "/api/v1/audit"
    ) || ["/latest", "/series", "/settings", "/control"]
        .iter()
        .any(|suffix| is_agent_subroute(path, suffix));

    if *method == Method::GET || *method == Method::HEAD {
        return is_read_route.then_some(TokenScope::Read);
    }
    if *method == Method::POST && is_agent_subroute(path, "/control") {
        return Some(TokenScope::Write);
    }
    if *method == Method::PUT && is_agent_subroute(path, "/settings") {
        return Some(TokenScope::Write);
    }
    None
}

/// 匹配 `/api/v1/agents/<id><suffix>`；`<id>` 必须是非空单段。
fn is_agent_subroute(path: &str, suffix: &str) -> bool {
    path.strip_prefix("/api/v1/agents/")
        .and_then(|rest| rest.strip_suffix(suffix))
        .is_some_and(|id| !id.is_empty() && !id.contains('/'))
}

/// 固定 401：不带 token / 内部错误信息，只告诉客户端该用 Bearer。
fn unauthorized() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({ "error": "unauthorized" })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// 固定 403：已认证但 scope 不足；不进入 handler，也不写控制审计。
fn forbidden_scope() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({ "error": "forbidden_scope" })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// scope 是全序层级：read < write < admin，低 scope 不能越级。
    #[test]
    fn scope_hierarchy_is_total_order() {
        use TokenScope::{Admin, Read, Write};

        assert!(scope_allows(Read, Read));
        assert!(!scope_allows(Read, Write));
        assert!(!scope_allows(Read, Admin));

        assert!(scope_allows(Write, Read));
        assert!(scope_allows(Write, Write));
        assert!(!scope_allows(Write, Admin));

        assert!(scope_allows(Admin, Read));
        assert!(scope_allows(Admin, Write));
        assert!(scope_allows(Admin, Admin));
    }

    #[test]
    fn scope_string_roundtrip_and_invalid_values() {
        for scope in [TokenScope::Read, TokenScope::Write, TokenScope::Admin] {
            assert_eq!(TokenScope::parse(scope.as_str()), Some(scope));
        }
        for invalid in ["", "root", "READ", "write ", "admin\n"] {
            assert_eq!(TokenScope::parse(invalid), None, "value={invalid:?}");
        }
    }

    /// 精确路由映射：GET 全部只读；control POST / settings PUT 才需要 Write。
    #[test]
    fn required_scope_maps_known_routes_only() {
        use TokenScope::{Read, Write};

        for path in [
            "/api/v1/system",
            "/api/v1/agents",
            "/api/v1/series",
            "/api/v1/overview",
            "/api/v1/audit",
            "/api/v1/agents/a1/latest",
            "/api/v1/agents/a1/series",
            "/api/v1/agents/a1/settings",
            "/api/v1/agents/a1/control",
        ] {
            assert_eq!(
                required_scope(&Method::GET, path),
                Some(Read),
                "path={path}"
            );
            assert_eq!(
                required_scope(&Method::HEAD, path),
                Some(Read),
                "path={path}"
            );
        }
        assert_eq!(
            required_scope(&Method::POST, "/api/v1/agents/a1/control"),
            Some(Write)
        );
        assert_eq!(
            required_scope(&Method::PUT, "/api/v1/agents/a1/settings"),
            Some(Write)
        );

        // 未知路径 / 已知路径的错误方法 → None：认证后交给路由 404/405，
        // read token 不能因为「路径未知」或「方法不匹配」被 403 挡住。
        for (method, path) in [
            (&Method::GET, "/api/v1/nope"),
            (&Method::POST, "/api/v1/nope"),
            (&Method::PUT, "/api/v1/nope"),
            (&Method::DELETE, "/api/v1/agents/a1/settings"),
            (&Method::POST, "/api/v1/agents"),
            (&Method::GET, "/api/v1/agents/"),
            (&Method::GET, "/api/v1/agents/a1/settings/extra"),
            (&Method::POST, "/api/v1/agents/a1/settings"),
        ] {
            assert_eq!(
                required_scope(method, path),
                None,
                "method={method} path={path}"
            );
        }
    }

    #[test]
    fn bearer_parsing_is_strict_and_case_insensitive() {
        use axum::http::HeaderMap;

        let mut headers = HeaderMap::new();
        assert_eq!(bearer_token(&headers), None);
        assert!(!bearer_matches(&headers, "secret"));
        assert!(!bearer_matches(&headers, ""));

        for scheme in ["Bearer", "bearer", "BEARER", "bEaReR"] {
            let value = format!("{scheme} secret");
            headers.insert(
                header::AUTHORIZATION,
                HeaderValue::from_str(&value).unwrap(),
            );
            assert_eq!(bearer_token(&headers), Some("secret"), "scheme={scheme}");
            assert!(bearer_matches(&headers, "secret"), "scheme={scheme}");
            assert!(!bearer_matches(&headers, "wrong"), "scheme={scheme}");
        }

        for value in [
            "secret",
            "Bearer",
            "Bearer secret extra",
            "Basic secret",
            "Bearer ",
        ] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
            assert_eq!(bearer_token(&headers), None, "value={value}");
            assert!(!bearer_matches(&headers, "secret"), "value={value}");
        }
    }
}
