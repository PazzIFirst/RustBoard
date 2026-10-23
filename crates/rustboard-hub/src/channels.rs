//! M4-B2b：通知渠道管理 API 与测试发送。
//!
//! 路由（写在 `admin_router` 的受保护路由树里，统一先过 Bearer 鉴权）：
//! - `GET    /api/v1/alerts/channels`          read
//! - `POST   /api/v1/alerts/channels`          write
//! - `PUT    /api/v1/alerts/channels/{id}`     write
//! - `DELETE /api/v1/alerts/channels/{id}`     write
//! - `POST   /api/v1/alerts/channels/{id}/test` write
//!
//! 安全约定：
//! - 响应一律使用 [`ChannelView`]，只含非敏感字段与「已配置哪些 secret」；
//!   `NotificationChannel` / `ChannelConfig` 永不直接作为 API 响应；
//! - 请求体 `deny_unknown_fields`；错误只描述资源与字段范围，不回显 secret；
//! - 测试发送失败统一 502 `notify_failed`，不回显上游 URL / token / 响应正文；
//! - 渠道 id 由服务端生成 UUID，`updated_by` 取 [`AuthPrincipal::name`]；
//! - 渠道上限 / 重名 / 被告警规则引用分别映射 409 `channel_limit` /
//!   `channel_name_exists` / `channel_in_use`。

use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use rustboard_common::util::now_ms;
use rustboard_core::channels::{
    validate_channel_name, ChannelConfigInput, ChannelKind, ChannelView, NotificationChannel,
};
use rustboard_core::storage::sqlite::{ChannelStoreError, MAX_NOTIFICATION_CHANNELS};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthPrincipal;
use crate::{ApiError, AppState};

/// 渠道名称默认启用：新建渠道只有在告警规则引用它之后才会真正发送。
fn default_enabled() -> bool {
    true
}

/// 新建渠道请求体。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelCreateInput {
    /// 渠道名称，1–64 字节，全局唯一。
    name: String,
    /// 渠道类型。
    kind: ChannelKind,
    /// 是否启用；缺省 true。
    #[serde(default = "default_enabled")]
    enabled: bool,
    /// 渠道配置（secret 字段创建时必填）。
    #[serde(default)]
    config: ChannelConfigInput,
}

/// 更新渠道请求体：所有字段可缺省，缺省表示保留原值。
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChannelUpdateInput {
    /// 新名称；`None` = 保留。
    #[serde(default)]
    name: Option<String>,
    /// 新类型；与现有类型不同时必须提供完整配置。
    #[serde(default)]
    kind: Option<ChannelKind>,
    /// 是否启用；`None` = 保留。
    #[serde(default)]
    enabled: Option<bool>,
    /// 配置字段；secret 缺省 / null = 保留旧值。
    #[serde(default)]
    config: ChannelConfigInput,
}

/// 在阻塞线程池执行存储操作（SQLite 写锁是阻塞的，不能占用 async worker）。
async fn run_blocking<T, F>(task: F) -> Result<T, ApiError>
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .map_err(ApiError::from)?
        .map_err(map_store_error)
}

/// 把渠道存储错误映射成固定的 HTTP 状态码与错误码。
fn map_store_error(err: anyhow::Error) -> ApiError {
    if let Some(store_error) = err.downcast_ref::<ChannelStoreError>() {
        return match store_error {
            ChannelStoreError::NotFound => ApiError::not_found("通知渠道不存在"),
            ChannelStoreError::NameExists => {
                ApiError::conflict("channel_name_exists", "通知渠道名称已存在")
            }
            ChannelStoreError::LimitReached => ApiError::conflict(
                "channel_limit",
                format!("通知渠道数量已达上限 {MAX_NOTIFICATION_CHANNELS} 条"),
            ),
            ChannelStoreError::InUse => {
                ApiError::conflict("channel_in_use", "通知渠道仍被告警规则引用")
            }
            ChannelStoreError::Invalid(message) => ApiError::bad_request(*message),
        };
    }
    ApiError::from(err)
}

/// 解析请求体：未知字段 / 非法枚举 / 超大请求体都走固定错误码。
fn parse_body<T: DeserializeOwned>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
    match body {
        Ok(Json(input)) => Ok(input),
        Err(rejection) => {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                return Err(ApiError::PayloadTooLarge);
            }
            // 不回传 serde 原文：其中可能回显字段名 / 值（包括 secret）。
            Err(ApiError::bad_request("请求体不是合法 JSON 或包含未知字段"))
        }
    }
}

/// 取 `updated_by`；受保护路由一定经过鉴权中间件，扩展缺失说明接线错误。
fn principal_name(principal: Option<Extension<AuthPrincipal>>) -> Result<String, ApiError> {
    match principal {
        Some(Extension(principal)) => Ok(principal.name),
        None => {
            tracing::error!("通知渠道请求缺少 AuthPrincipal 扩展（路由接线错误）");
            Err(ApiError::Internal(anyhow::anyhow!(
                "通知渠道请求缺少认证主体"
            )))
        }
    }
}

/// `GET /api/v1/alerts/channels`：列出全部渠道（secret 只以字段名出现）。
pub(crate) async fn list_channels(
    State(state): State<AppState>,
) -> Result<Json<Vec<ChannelView>>, ApiError> {
    let storage = state.storage.clone();
    let channels = run_blocking(move || storage.list_notification_channels()).await?;
    Ok(Json(
        channels.iter().map(NotificationChannel::to_view).collect(),
    ))
}

/// `POST /api/v1/alerts/channels`：新建渠道，id 由服务端生成 UUID。
pub(crate) async fn create_channel(
    State(state): State<AppState>,
    principal: Option<Extension<AuthPrincipal>>,
    body: Result<Json<ChannelCreateInput>, JsonRejection>,
) -> Result<Json<ChannelView>, ApiError> {
    let input = parse_body(body)?;
    validate_channel_name(&input.name).map_err(ApiError::bad_request)?;
    let updated_by = principal_name(principal)?;
    let now = now_ms();

    let config = input
        .config
        .resolve(input.kind, None)
        .map_err(ApiError::bad_request)?;
    let channel = NotificationChannel {
        id: Uuid::new_v4().to_string(),
        name: input.name,
        kind: input.kind,
        config,
        enabled: input.enabled,
        updated_by,
        created_at: now,
        updated_at: now,
    };
    channel.validate().map_err(ApiError::bad_request)?;

    let storage = state.storage.clone();
    let to_store = channel.clone();
    run_blocking(move || storage.create_notification_channel(&to_store)).await?;
    Ok(Json(channel.to_view()))
}

/// `PUT /api/v1/alerts/channels/{id}`：部分更新渠道。
///
/// - `name` / `enabled` / 配置字段缺省或 null = 保留旧值；
/// - secret 缺省或 null = 保留已保存的 secret（绝不因响应掩码而误清空）；
/// - `kind` 变更时必须重新提供完整配置，旧类型的 secret 不会被跨类型复用。
pub(crate) async fn update_channel(
    State(state): State<AppState>,
    Path(id): Path<String>,
    principal: Option<Extension<AuthPrincipal>>,
    body: Result<Json<ChannelUpdateInput>, JsonRejection>,
) -> Result<Json<ChannelView>, ApiError> {
    let input = parse_body(body)?;
    let updated_by = principal_name(principal)?;

    let storage = state.storage.clone();
    let existing = {
        let storage = storage.clone();
        let id = id.clone();
        run_blocking(move || storage.get_notification_channel(&id)).await?
    };
    let Some(existing) = existing else {
        return Err(ApiError::not_found("通知渠道不存在"));
    };

    let kind = input.kind.unwrap_or(existing.kind);
    let name = input.name.unwrap_or_else(|| existing.name.clone());
    validate_channel_name(&name).map_err(ApiError::bad_request)?;

    // 类型变更：必须重新提供完整配置（existing = None），防止把旧类型的
    // secret 静默套到新类型上。类型不变时按 B2a 语义保留缺省 secret。
    let config = if kind == existing.kind {
        input
            .config
            .resolve(kind, Some(&existing.config))
            .map_err(ApiError::bad_request)?
    } else {
        input
            .config
            .resolve(kind, None)
            .map_err(ApiError::bad_request)?
    };
    let channel = NotificationChannel {
        id: existing.id,
        name,
        kind,
        config,
        enabled: input.enabled.unwrap_or(existing.enabled),
        updated_by,
        created_at: existing.created_at,
        updated_at: now_ms(),
    };
    channel.validate().map_err(ApiError::bad_request)?;

    let to_store = channel.clone();
    run_blocking(move || storage.update_notification_channel(&to_store)).await?;
    Ok(Json(channel.to_view()))
}

/// `DELETE /api/v1/alerts/channels/{id}`：删除渠道。
///
/// 仍被任何告警规则的 `channel_ids` 引用时返回 409 `channel_in_use`；引用检查
/// 与删除在存储层的同一事务内完成。
pub(crate) async fn delete_channel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let storage = state.storage.clone();
    run_blocking(move || storage.delete_notification_channel(&id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/v1/alerts/channels/{id}/test`：用已保存配置发送固定测试消息。
///
/// 成功 200 `{"ok":true}`；任何发送失败统一 502 `notify_failed`，日志只记录
/// 渠道 id / kind / 固定错误码，不记录 URL、token 或上游响应正文。
pub(crate) async fn test_channel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let storage = state.storage.clone();
    let channel = run_blocking(move || storage.get_notification_channel(&id)).await?;
    let Some(channel) = channel else {
        return Err(ApiError::not_found("通知渠道不存在"));
    };

    match state.notifier.test(&channel).await {
        Ok(()) => Ok(Json(serde_json::json!({ "ok": true }))),
        Err(error) => {
            tracing::warn!(
                channel_id = %channel.id,
                kind = channel.kind.as_str(),
                error = error.code(),
                "通知渠道测试发送失败"
            );
            Err(ApiError::bad_gateway("notify_failed", "通知发送失败"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::Router;
    use rustboard_common::config::HubConfig;
    use rustboard_core::alerts::{AlertRule, AlertSource, Comparator};
    use rustboard_core::channels::{test_message, ChannelConfig, Secret};
    use rustboard_core::storage::sqlite::SqliteStorage;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::AuthFailureLimiter;
    use crate::cert_rotation::CertStatus;
    use crate::notify::{MockNotifier, NotifyError};
    use crate::session::SessionRegistry;
    use crate::{admin_router, AdminRateLimiter, RenewalContext};

    const LEGACY_TOKEN: &str = "channels-test-legacy-admin-token";
    const TELEGRAM_TOKEN: &str = "123456789:AAH_channels-test-token_01";
    const TELEGRAM_CHAT_ID: &str = "-1001234567890";
    const WECOM_KEY: &str = "00000000-1111-2222-3333-444444444444";

    fn channels_state(mock: Arc<MockNotifier>) -> AppState {
        let cfg = HubConfig {
            admin_token: LEGACY_TOKEN.to_string(),
            admin_rate_limit_per_min: 0,
            admin_write_rate_limit_per_min: 0,
            ..HubConfig::default()
        };
        AppState {
            storage: Arc::new(SqliteStorage::open_in_memory().unwrap()),
            cfg: Arc::new(cfg.clone()),
            sessions: SessionRegistry::new(),
            renewal: RenewalContext::new(PathBuf::from("/tmp/rb-hub-channels-test-unused-ca"), 90),
            live_cert: Arc::new(RwLock::new(CertStatus::unknown())),
            admin_rate: Arc::new(AdminRateLimiter::from_config(&cfg)),
            auth_failures: Arc::new(AuthFailureLimiter::new(
                cfg.admin_auth_failure_limit_per_min,
            )),
            notifier: mock,
        }
    }

    fn seed_token(state: &AppState, name: &str, scope: &str) -> String {
        let token = format!("test-token-{name}");
        state
            .storage
            .create_api_token(
                name,
                &rustboard_common::tls::sha256_hex(&token),
                scope,
                now_ms(),
            )
            .unwrap();
        token
    }

    async fn call(
        router: &Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(token) = token {
            builder = builder.header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if body.is_some() {
            builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
        }
        let mut request = builder
            .body(
                body.map(|body| Body::from(body.to_string()))
                    .unwrap_or_else(Body::empty),
            )
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 54321))));
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 2_000_000)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("响应必须是 JSON")
        };
        (status, value)
    }

    fn telegram_body(name: &str) -> String {
        json!({
            "name": name,
            "kind": "telegram",
            "enabled": true,
            "config": {
                "bot_token": TELEGRAM_TOKEN,
                "chat_id": TELEGRAM_CHAT_ID,
            }
        })
        .to_string()
    }

    fn created_id(body: &Value) -> String {
        body["id"].as_str().expect("响应必须含渠道 id").to_string()
    }

    /// 渠道 CRUD + scope 矩阵 + 响应脱敏 + 空 secret 保留 + 引用删除 409。
    #[tokio::test]
    async fn m4_b2b_channel_crud_scope_masking_and_in_use() {
        let mock = Arc::new(MockNotifier::new());
        let state = channels_state(mock);
        let read = seed_token(&state, "channels-read", "read");
        let write = seed_token(&state, "channels-write", "write");
        let router = admin_router(state.clone());

        // 认证 / 授权。
        let (status, _) = call(&router, "GET", "/api/v1/alerts/channels", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) =
            call(&router, "GET", "/api/v1/alerts/channels", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!([]));
        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&read),
            Some(&telegram_body("运维通知")),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "forbidden_scope"}));

        // 创建：响应必须走 ChannelView，不含 secret 原文。
        let (status, created) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(&telegram_body("运维通知")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(created["name"], "运维通知");
        assert_eq!(created["kind"], "telegram");
        assert_eq!(created["enabled"], true);
        assert_eq!(created["updated_by"], "channels-write");
        assert_eq!(created["chat_id"], TELEGRAM_CHAT_ID);
        assert_eq!(created["secret_fields"], json!(["bot_token"]));
        let rendered = serde_json::to_string(&created).unwrap();
        assert!(!rendered.contains(TELEGRAM_TOKEN), "响应泄露 bot_token");
        assert!(!rendered.contains("config"), "响应不应含 config 结构");
        let id = created_id(&created);

        // 列表同样脱敏。
        let (status, listed) =
            call(&router, "GET", "/api/v1/alerts/channels", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert!(!serde_json::to_string(&listed)
            .unwrap()
            .contains(TELEGRAM_TOKEN));

        // 重名 → 409。
        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(&telegram_body("运维通知")),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "channel_name_exists");

        // PUT 空 secret：保留数据库中的旧 token，但响应仍不含原文。
        let (status, updated) = call(
            &router,
            "PUT",
            &format!("/api/v1/alerts/channels/{id}"),
            Some(&write),
            Some(r#"{"name":"运维通知-2","config":{"chat_id":"-1009999999999"}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(updated["name"], "运维通知-2");
        assert_eq!(updated["chat_id"], "-1009999999999");
        assert!(!serde_json::to_string(&updated)
            .unwrap()
            .contains(TELEGRAM_TOKEN));
        let stored = state
            .storage
            .get_notification_channel(&id)
            .unwrap()
            .expect("渠道必须存在");
        assert_eq!(
            stored.config,
            ChannelConfig::Telegram {
                bot_token: Secret::new(TELEGRAM_TOKEN),
                chat_id: "-1009999999999".to_string(),
            },
            "缺省 secret 必须保留旧值"
        );
        assert_eq!(stored.updated_by, "channels-write");

        // 被规则引用时禁止删除（同一事务内检查）。
        let rule = AlertRule {
            id: "rule-uses-channel".to_string(),
            name: "引用渠道规则".to_string(),
            enabled: false,
            source: AlertSource::Metric,
            metric: "disk.used_percent".to_string(),
            comparator: Comparator::Gt,
            threshold: 90.0,
            duration_secs: 0,
            cooldown_secs: 1_800,
            filter_agent_id: None,
            filter_labels: Default::default(),
            channel_ids: vec![id.clone()],
            notify_on_resolve: true,
            is_builtin: false,
            updated_by: "admin".to_string(),
            created_at: now_ms(),
            updated_at: now_ms(),
        };
        state.storage.create_alert_rule(&rule).unwrap();
        let (status, body) = call(
            &router,
            "DELETE",
            &format!("/api/v1/alerts/channels/{id}"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body["error"], "channel_in_use");
        assert!(state
            .storage
            .get_notification_channel(&id)
            .unwrap()
            .is_some());

        state.storage.delete_alert_rule(&rule.id).unwrap();
        let (status, _) = call(
            &router,
            "DELETE",
            &format!("/api/v1/alerts/channels/{id}"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, body) = call(
            &router,
            "DELETE",
            &format!("/api/v1/alerts/channels/{id}"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");
    }

    /// kind 变更必须重新提供完整配置；同 kind 的部分更新保留旧配置。
    #[tokio::test]
    async fn m4_b2b_channel_kind_change_requires_full_config() {
        let mock = Arc::new(MockNotifier::new());
        let state = channels_state(mock);
        let write = seed_token(&state, "channels-write", "write");
        let router = admin_router(state.clone());

        let (_, created) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(&telegram_body("类型变更")),
        )
        .await;
        let id = created_id(&created);

        // 只给 kind、不给完整配置 → 400，数据库保持原渠道。
        let (status, body) = call(
            &router,
            "PUT",
            &format!("/api/v1/alerts/channels/{id}"),
            Some(&write),
            Some(r#"{"kind":"wecom","config":{}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "bad_request");
        assert!(state
            .storage
            .get_notification_channel(&id)
            .unwrap()
            .is_some());
        assert_eq!(
            state
                .storage
                .get_notification_channel(&id)
                .unwrap()
                .unwrap()
                .kind,
            ChannelKind::Telegram
        );

        // 完整新配置 → 200，响应不含旧 token。
        let body = json!({
            "kind": "wecom",
            "config": {"webhook_key": WECOM_KEY},
        })
        .to_string();
        let (status, updated) = call(
            &router,
            "PUT",
            &format!("/api/v1/alerts/channels/{id}"),
            Some(&write),
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(updated["kind"], "wecom");
        assert_eq!(updated["secret_fields"], json!(["webhook_key"]));
        assert_eq!(updated["chat_id"], Value::Null);
        let rendered = serde_json::to_string(&updated).unwrap();
        assert!(!rendered.contains(TELEGRAM_TOKEN));
        assert!(!rendered.contains(WECOM_KEY));
        assert_eq!(
            state
                .storage
                .get_notification_channel(&id)
                .unwrap()
                .unwrap()
                .config,
            ChannelConfig::Wecom {
                webhook_key: Secret::new(WECOM_KEY),
            }
        );
    }

    /// 测试发送：成功 200；失败固定 502 且响应不含 URL / token；不存在 404。
    #[tokio::test]
    async fn m4_b2b_channel_test_send_uses_saved_config() {
        let mock = Arc::new(MockNotifier::new());
        let state = channels_state(mock.clone());
        let write = seed_token(&state, "channels-write", "write");
        let router = admin_router(state.clone());

        let (_, created) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(&telegram_body("测试渠道")),
        )
        .await;
        let id = created_id(&created);

        let (status, body) = call(
            &router,
            "POST",
            &format!("/api/v1/alerts/channels/{id}/test"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!({"ok": true}));
        let sent = mock.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].channel_id, id);
        assert_eq!(sent[0].text, test_message("测试渠道"));
        assert!(!sent[0].text.contains(TELEGRAM_TOKEN));

        // 发送失败：固定 502，不泄露 token / 固定端点。
        mock.push_result(Err(NotifyError::Timeout));
        let (status, body) = call(
            &router,
            "POST",
            &format!("/api/v1/alerts/channels/{id}/test"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"], "notify_failed");
        let rendered = body.to_string();
        assert!(!rendered.contains(TELEGRAM_TOKEN));
        assert!(!rendered.contains("https://"));
        assert!(!rendered.contains("api.telegram.org"));

        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels/missing/test",
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");
    }

    /// 请求体白名单、未知字段与 1 MiB 上限；超过 64 KiB 但低于 1 MiB 的合法
    /// 渠道请求不能被全局 64 KiB 限制误杀。
    #[tokio::test]
    async fn m4_b2b_channel_body_limit_and_unknown_fields() {
        let mock = Arc::new(MockNotifier::new());
        let state = channels_state(mock);
        let write = seed_token(&state, "channels-write", "write");
        let router = admin_router(state);

        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(r#"{"name":"x","kind":"telegram","unknown":true}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "bad_request");

        let (status, _) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(r#"{"name":"x","kind":"telegram","config":{"unknown":1}}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // 70 KiB：大于全局 64 KiB、小于渠道路由 1 MiB。未知字段应由 JSON
        // 解析器拒绝（400），而不是被 64 KiB 限制提前截断（413）。
        let padding = "x".repeat(70 * 1024);
        let body = json!({
            "name": "big",
            "kind": "telegram",
            "config": {"bot_token": TELEGRAM_TOKEN, "chat_id": TELEGRAM_CHAT_ID},
            "pad": padding,
        })
        .to_string();
        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(&body),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "70 KiB 应进入 JSON 解析（未知字段 400），实际 {status:?} {body:?}"
        );

        // 超过 1 MiB：413，解析器不得读入超大请求体。
        let huge = format!(
            r#"{{"name":"huge","kind":"telegram","pad":"{}"}}"#,
            "x".repeat(1024 * 1024 + 1024)
        );
        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(&huge),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["error"], "payload_too_large");

        // 非法 secret 长度：400 且错误回显不回显原文。
        let bad_body = json!({
            "name": "bad",
            "kind": "telegram",
            "config": {"bot_token": "short", "chat_id": TELEGRAM_CHAT_ID},
        })
        .to_string();
        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/channels",
            Some(&write),
            Some(&bad_body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.to_string().contains("short"));
    }
}
