//! M4-B1a：告警规则管理 API。
//!
//! 只实现规则 CRUD；告警评估、事件、静默与通知渠道属于 B1b / B2。
//!
//! 路由（写在 `admin_router` 的受保护路由树里，统一先过 Bearer 鉴权）：
//! - `GET    /api/v1/alerts/rules`      read
//! - `POST   /api/v1/alerts/rules`      write
//! - `PUT    /api/v1/alerts/rules/{id}` write
//! - `DELETE /api/v1/alerts/rules/{id}` write
//!
//! 安全约定：
//! - 请求体 `deny_unknown_fields`，错误一律 400，不回显 serde 原文；
//! - 错误信息只描述规则，不回显用户输入；`is_builtin` / `id` / `created_at`
//!   只能由服务端维护，内置规则只允许禁停与修改，不允许删除；
//! - `updated_by` 取 [`AuthPrincipal::name`]（旧 admin token 为 `"admin"`）。

use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use rustboard_common::model::Labels;
use rustboard_common::util::now_ms;
use rustboard_core::alerts::{
    AlertRule, AlertRuleInput, AlertRuleStoreError, AlertSource, Comparator, MAX_ALERT_RULES,
};
use uuid::Uuid;

use crate::auth::AuthPrincipal;
use crate::{ApiError, AppState};

/// 与 `alert_rules` 表默认值一致的初始规则；POST 时在其上合并请求体。
///
/// `enabled` 默认 `false`（与表默认一致）：新建规则先禁用，确认阈值与渠道后
/// 再由面板显式启用，避免「创建即通知」的意外。
fn default_rule(now: i64, updated_by: String) -> AlertRule {
    AlertRule {
        id: Uuid::new_v4().to_string(),
        name: String::new(),
        enabled: false,
        source: AlertSource::Metric,
        metric: String::new(),
        comparator: Comparator::Gt,
        threshold: 0.0,
        duration_secs: 0,
        cooldown_secs: 1_800,
        filter_agent_id: None,
        filter_labels: Labels::new(),
        channel_ids: Vec::new(),
        notify_on_resolve: true,
        is_builtin: false,
        updated_by,
        created_at: now,
        updated_at: now,
    }
}

/// 在阻塞线程池执行存储操作（SQLite 写锁是阻塞的，不能占用 async worker）。
///
/// 存储层的领域错误（重名 / 上限 / 内置 / 不存在）在这里映射成固定 HTTP 码，
/// 其余错误按内部错误处理（响应只回 `internal_error`）。
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

/// 把告警规则存储错误映射成固定的 HTTP 状态码与错误码。
fn map_store_error(err: anyhow::Error) -> ApiError {
    if let Some(store_error) = err.downcast_ref::<AlertRuleStoreError>() {
        return match store_error {
            AlertRuleStoreError::NotFound => ApiError::not_found("告警规则不存在"),
            AlertRuleStoreError::NameExists => {
                ApiError::conflict("rule_name_exists", "告警规则名称已存在")
            }
            AlertRuleStoreError::LimitReached => ApiError::conflict(
                "rule_limit",
                format!("告警规则数量已达上限 {MAX_ALERT_RULES} 条"),
            ),
            AlertRuleStoreError::BuiltinRule => {
                ApiError::forbidden("builtin_rule", "内置规则不允许删除")
            }
        };
    }
    ApiError::from(err)
}

/// 解析请求体：未知字段 / 非法枚举 / 超大请求体都走固定错误码。
fn parse_body(
    body: Result<Json<AlertRuleInput>, JsonRejection>,
) -> Result<AlertRuleInput, ApiError> {
    match body {
        Ok(Json(input)) => Ok(input),
        Err(rejection) => {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                return Err(ApiError::PayloadTooLarge);
            }
            // 不回传 serde 原文：其中可能回显字段名 / 值。
            Err(ApiError::bad_request("请求体不是合法 JSON 或包含未知字段"))
        }
    }
}

/// 取 `updated_by`；受保护路由一定经过鉴权中间件，扩展缺失说明接线错误。
fn principal_name(principal: Option<Extension<AuthPrincipal>>) -> Result<String, ApiError> {
    match principal {
        Some(Extension(principal)) => Ok(principal.name),
        None => {
            tracing::error!("告警规则请求缺少 AuthPrincipal 扩展（路由接线错误）");
            Err(ApiError::Internal(anyhow::anyhow!(
                "告警规则请求缺少认证主体"
            )))
        }
    }
}

/// `GET /api/v1/alerts/rules`：列出全部规则（内置在前，同组按名称升序）。
pub(crate) async fn list_rules(
    State(state): State<AppState>,
) -> Result<Json<Vec<AlertRule>>, ApiError> {
    let storage = state.storage.clone();
    let rules = run_blocking(move || storage.list_alert_rules()).await?;
    Ok(Json(rules))
}

/// `POST /api/v1/alerts/rules`：新建自定义规则，id 由服务端生成 UUID。
pub(crate) async fn create_rule(
    State(state): State<AppState>,
    principal: Option<Extension<AuthPrincipal>>,
    body: Result<Json<AlertRuleInput>, JsonRejection>,
) -> Result<Json<AlertRule>, ApiError> {
    let input = parse_body(body)?;
    input.validate().map_err(ApiError::bad_request)?;
    let updated_by = principal_name(principal)?;
    let now = now_ms();

    let mut rule = default_rule(now, updated_by);
    input.apply_to(&mut rule);
    // 合并后校验最终状态：metric 来源缺 metric / 非 metric 来源残留 metric 都在这里拒绝。
    rule.validate_semantics().map_err(ApiError::bad_request)?;

    let storage = state.storage.clone();
    let to_store = rule.clone();
    run_blocking(move || storage.create_alert_rule(&to_store)).await?;
    Ok(Json(rule))
}

/// `PUT /api/v1/alerts/rules/{id}`：修改 / 启停规则。
///
/// - 请求体只覆盖出现的字段（例如 `{"enabled": true}` 只切换启停）；
/// - id / `is_builtin` / `created_at` 保持数据库原值，内置规则同样可改可停；
/// - 规则不存在返回 404。
pub(crate) async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    principal: Option<Extension<AuthPrincipal>>,
    body: Result<Json<AlertRuleInput>, JsonRejection>,
) -> Result<Json<AlertRule>, ApiError> {
    let input = parse_body(body)?;
    input.validate().map_err(ApiError::bad_request)?;
    let updated_by = principal_name(principal)?;

    let storage = state.storage.clone();
    let existing = {
        let storage = storage.clone();
        let id = id.clone();
        run_blocking(move || storage.get_alert_rule(&id)).await?
    };
    let Some(mut rule) = existing else {
        return Err(ApiError::not_found("告警规则不存在"));
    };
    input.apply_to(&mut rule);
    rule.validate_semantics().map_err(ApiError::bad_request)?;
    rule.updated_by = updated_by;
    rule.updated_at = now_ms();

    let to_store = rule.clone();
    run_blocking(move || storage.update_alert_rule(&to_store)).await?;
    Ok(Json(rule))
}

/// `DELETE /api/v1/alerts/rules/{id}`：删除自定义规则；内置规则 403 `builtin_rule`。
pub(crate) async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let storage = state.storage.clone();
    run_blocking(move || storage.delete_alert_rule(&id)).await?;
    Ok(StatusCode::NO_CONTENT)
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
    use rustboard_core::alerts::{builtin_rules, AlertRuleStoreError, BUILTIN_AGENT_OFFLINE};
    use rustboard_core::storage::sqlite::SqliteStorage;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::auth::AuthFailureLimiter;
    use crate::cert_rotation::CertStatus;
    use crate::session::SessionRegistry;
    use crate::{admin_router, AdminRateLimiter, RenewalContext};

    const LEGACY_TOKEN: &str = "alerts-test-legacy-admin-token";

    /// 测试用 hub 状态：旧 admin_token 可用，关闭限速（矩阵测试请求数超过默认额度）。
    fn alerts_state() -> AppState {
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
            renewal: RenewalContext::new(PathBuf::from("/tmp/rb-hub-alerts-test-unused-ca"), 90),
            live_cert: Arc::new(RwLock::new(CertStatus::unknown())),
            admin_rate: Arc::new(AdminRateLimiter::from_config(&cfg)),
            auth_failures: Arc::new(AuthFailureLimiter::new(
                cfg.admin_auth_failure_limit_per_min,
            )),
        }
    }

    /// 直接在库里种一个 scoped token，返回明文（只在本进程测试内使用）。
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

    /// 直接调用管理 API（不绑定端口），返回状态与 JSON 响应体。
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
        let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("响应必须是 JSON")
        };
        (status, value)
    }

    fn seed_builtins(state: &AppState) -> usize {
        let now = now_ms();
        state
            .storage
            .seed_builtin_alert_rules(&builtin_rules(now), now)
            .unwrap()
    }

    /// 完整 CRUD：read token 只读、write token 增改删；响应不回显内部字段。
    #[tokio::test]
    async fn m4_b1_alert_rule_crud_and_scope_matrix() {
        let state = alerts_state();
        let read = seed_token(&state, "alerts-read", "read");
        let write = seed_token(&state, "alerts-write", "write");
        let router = admin_router(state.clone());

        // 未认证 → 401；read token 可以列规则，但不能写。
        let (status, _) = call(&router, "GET", "/api/v1/alerts/rules", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) = call(&router, "GET", "/api/v1/alerts/rules", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!([]), "初始没有规则");

        let create_body = json!({
            "name": "磁盘告警",
            "source": "metric",
            "metric": "disk.used_percent",
            "comparator": "gte",
            "threshold": 85.5,
            "duration_secs": 120,
            "cooldown_secs": 600,
            "filter_agent_id": "agent-1",
            "filter_labels": {"mount": "/"},
            "channel_ids": ["channel-a"],
            "notify_on_resolve": false
        })
        .to_string();
        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/rules",
            Some(&read),
            Some(&create_body),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "read token 不能写规则");
        assert_eq!(body, json!({"error": "forbidden_scope"}));

        let (status, created) = call(
            &router,
            "POST",
            "/api/v1/alerts/rules",
            Some(&write),
            Some(&create_body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "创建失败: {created}");
        let id = created["id"].as_str().expect("必须返回规则 id").to_string();
        assert_eq!(
            Uuid::parse_str(&id).map(|_| ()),
            Ok(()),
            "自定义规则 id 必须是 UUID"
        );
        assert_eq!(created["name"], "磁盘告警");
        assert_eq!(created["enabled"], false, "新建规则默认 disabled");
        assert_eq!(created["is_builtin"], json!(false));
        assert_eq!(created["updated_by"], "alerts-write");
        assert_eq!(created["metric"], "disk.used_percent");
        assert_eq!(created["comparator"], "gte");
        assert_eq!(created["threshold"], 85.5);
        assert_eq!(created["duration_secs"], 120);
        assert_eq!(created["cooldown_secs"], 600);
        assert_eq!(created["filter_agent_id"], "agent-1");
        assert_eq!(created["filter_labels"], json!({"mount": "/"}));
        assert_eq!(created["channel_ids"], json!(["channel-a"]));
        assert_eq!(created["notify_on_resolve"], json!(false));

        // 列表可见。
        let (status, list) = call(&router, "GET", "/api/v1/alerts/rules", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 1);
        assert_eq!(list[0]["id"], id);

        // 部分更新（启停）：只传 enabled，其他字段不变。
        let (status, updated) = call(
            &router,
            "PUT",
            &format!("/api/v1/alerts/rules/{id}"),
            Some(&write),
            Some(r#"{"enabled":true}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "启停失败: {updated}");
        assert_eq!(updated["enabled"], json!(true));
        assert_eq!(updated["name"], "磁盘告警", "未提供字段必须保持原值");
        assert_eq!(updated["id"], id, "id 不能改变");
        assert_eq!(updated["created_at"], created["created_at"]);
        assert_eq!(updated["updated_by"], "alerts-write");

        // 修改阈值与名称。
        let (status, updated) = call(
            &router,
            "PUT",
            &format!("/api/v1/alerts/rules/{id}"),
            Some(&write),
            Some(r#"{"name":"磁盘告警2","threshold":90}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "更新失败: {updated}");
        assert_eq!(updated["name"], "磁盘告警2");
        assert_eq!(updated["threshold"], 90.0);

        // 删除自定义规则；再删同一个 id → 404。
        let (status, body) = call(
            &router,
            "DELETE",
            &format!("/api/v1/alerts/rules/{id}"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(body, Value::Null);
        let (status, body) = call(
            &router,
            "DELETE",
            &format!("/api/v1/alerts/rules/{id}"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "not_found");
        assert_eq!(state.storage.alert_rule_count().unwrap(), 0);
    }

    /// 旧 admin_token 兼容：`updated_by` 固定为 "admin"。
    #[tokio::test]
    async fn m4_b1_legacy_admin_token_sets_updated_by_admin() {
        let state = alerts_state();
        let router = admin_router(state);
        let (status, created) = call(
            &router,
            "POST",
            "/api/v1/alerts/rules",
            Some(LEGACY_TOKEN),
            Some(r#"{"name":"legacy 规则","source":"hub_cert","comparator":"lt","threshold":24}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "创建失败: {created}");
        assert_eq!(created["updated_by"], "admin");
        assert_eq!(created["source"], "hub_cert");
        assert_eq!(created["metric"], "", "非 metric 规则 metric 必须为空");
    }

    /// 内置规则：初始 disabled、不可删、可改；is_builtin / id 不被请求体篡改。
    #[tokio::test]
    async fn m4_b1_builtin_rules_are_seeded_undeletable_but_editable() {
        let state = alerts_state();
        let router = admin_router(state.clone());
        assert_eq!(seed_builtins(&state), 5, "首次启动必须种入 5 条内置规则");
        assert_eq!(seed_builtins(&state), 0, "重复种入必须幂等");

        let (status, list) = call(
            &router,
            "GET",
            "/api/v1/alerts/rules",
            Some(LEGACY_TOKEN),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let list = list.as_array().unwrap().to_vec();
        assert_eq!(list.len(), 5);
        assert!(list.iter().all(|rule| rule["is_builtin"] == json!(true)));
        assert!(list.iter().all(|rule| rule["enabled"] == json!(false)));
        assert!(list.iter().all(|rule| rule["channel_ids"] == json!([])));

        // 内置规则禁用 / 改阈值：允许，id 与 is_builtin 保持不变。
        // 请求体不能写 id / is_builtin：未知字段直接 400，服务端字段不可篡改。
        let (status, body) = call(
            &router,
            "PUT",
            "/api/v1/alerts/rules/builtin-disk-percent",
            Some(LEGACY_TOKEN),
            Some(r#"{"enabled":true,"is_builtin":false,"id":"hijack"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "bad_request");

        let (status, updated) = call(
            &router,
            "PUT",
            "/api/v1/alerts/rules/builtin-disk-percent",
            Some(LEGACY_TOKEN),
            Some(r#"{"enabled":true,"threshold":95}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "内置规则应允许修改: {updated}");
        assert_eq!(updated["id"], "builtin-disk-percent");
        assert_eq!(updated["is_builtin"], json!(true));
        assert_eq!(updated["enabled"], json!(true));
        assert_eq!(updated["threshold"], 95.0);

        // 内置规则不能删除：403 builtin_rule，且仍然存在。
        let (status, body) = call(
            &router,
            "DELETE",
            "/api/v1/alerts/rules/builtin-disk-percent",
            Some(LEGACY_TOKEN),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "builtin_rule");
        assert_eq!(state.storage.alert_rule_count().unwrap(), 5);
        assert!(state
            .storage
            .get_alert_rule("builtin-disk-percent")
            .unwrap()
            .is_some());

        // 内置规则名可以改（用户自定义展示），但种子重启不会覆盖。
        let (status, renamed) = call(
            &router,
            "PUT",
            "/api/v1/alerts/rules/builtin-disk-percent",
            Some(LEGACY_TOKEN),
            Some(r#"{"name":"磁盘告警（自定义）"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "改名失败: {renamed}");
        assert_eq!(renamed["name"], "磁盘告警（自定义）");
    }

    /// 非法请求体：未知字段 / 非法枚举 / 越界值 / 非 metric 带 metric 全部 400。
    #[tokio::test]
    async fn m4_b1_invalid_bodies_are_400_without_echo() {
        let state = alerts_state();
        let router = admin_router(state);

        for body in [
            // 未知字段
            r#"{"name":"x","unknown":1}"#,
            // 非法枚举
            r#"{"name":"x","source":"every_metric"}"#,
            r#"{"name":"x","comparator":"between"}"#,
            // 空名称 / 超长名称
            r#"{"source":"metric","metric":"disk.used_percent"}"#,
            r#"{"name":""}"#,
            // 非法 metric
            r#"{"name":"x","source":"metric","metric":"Disk Used"}"#,
            // 越界 duration / cooldown
            r#"{"name":"x","source":"metric","metric":"disk.used_percent","duration_secs":86401}"#,
            r#"{"name":"x","source":"metric","metric":"disk.used_percent","cooldown_secs":604801}"#,
            // 非 metric 带 metric
            r#"{"name":"x","source":"hub_cert","metric":"disk.used_percent"}"#,
            // metric 规则缺 metric
            r#"{"name":"x","source":"metric"}"#,
            // labels 非法
            r#"{"name":"x","source":"metric","metric":"disk.used_percent","filter_labels":{"bad key":"v"}}"#,
            // channel_ids 非法
            r#"{"name":"x","source":"metric","metric":"disk.used_percent","channel_ids":["bad id"]}"#,
        ] {
            let (status, value) = call(
                &router,
                "POST",
                "/api/v1/alerts/rules",
                Some(LEGACY_TOKEN),
                Some(body),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "body={body} resp={value}");
            assert_eq!(value["error"], "bad_request", "body={body}");
        }

        // 超过 64 KiB 请求体：413 payload_too_large，进入解析前就被拒绝。
        let huge = format!(r#"{{"name":"{}"}}"#, "a".repeat(70 * 1024));
        let (status, value) = call(
            &router,
            "POST",
            "/api/v1/alerts/rules",
            Some(LEGACY_TOKEN),
            Some(&huge),
        )
        .await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(value["error"], "payload_too_large");

        // PUT 不存在的规则：404；非法 body 仍然是 400（先校验再查库）。
        let (status, value) = call(
            &router,
            "PUT",
            "/api/v1/alerts/rules/missing",
            Some(LEGACY_TOKEN),
            Some(r#"{"unknown":true}"#),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(value["error"], "bad_request");
        let (status, value) = call(
            &router,
            "PUT",
            "/api/v1/alerts/rules/missing",
            Some(LEGACY_TOKEN),
            Some(r#"{"enabled":true}"#),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value["error"], "not_found");
    }

    /// 规则名唯一 → 409 `rule_name_exists`（创建与更新都覆盖）。
    #[tokio::test]
    async fn m4_b1_duplicate_rule_name_conflicts() {
        let state = alerts_state();
        let router = admin_router(state.clone());
        let (status, first) = call(
            &router,
            "POST",
            "/api/v1/alerts/rules",
            Some(LEGACY_TOKEN),
            Some(r#"{"name":"重名规则","source":"metric","metric":"disk.used_percent"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "创建失败: {first}");
        let first_id = first["id"].as_str().unwrap().to_string();

        let (status, value) = call(
            &router,
            "POST",
            "/api/v1/alerts/rules",
            Some(LEGACY_TOKEN),
            Some(r#"{"name":"重名规则","source":"metric","metric":"disk.used_percent"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"], "rule_name_exists");

        // 第二条改成与第一条重名：同样 409，且原值不变。
        let (status, second) = call(
            &router,
            "POST",
            "/api/v1/alerts/rules",
            Some(LEGACY_TOKEN),
            Some(r#"{"name":"另一条","source":"metric","metric":"disk.used_percent"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "创建失败: {second}");
        let second_id = second["id"].as_str().unwrap().to_string();
        let (status, value) = call(
            &router,
            "PUT",
            &format!("/api/v1/alerts/rules/{second_id}"),
            Some(LEGACY_TOKEN),
            Some(r#"{"name":"重名规则"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"], "rule_name_exists");
        assert_eq!(
            state
                .storage
                .get_alert_rule(&first_id)
                .unwrap()
                .unwrap()
                .name,
            "重名规则"
        );
        assert_eq!(
            state
                .storage
                .get_alert_rule(&second_id)
                .unwrap()
                .unwrap()
                .name,
            "另一条"
        );
    }

    /// 规则数上限（含内置）：第 201 条 409 `rule_limit`。
    #[tokio::test]
    async fn m4_b1_rule_limit_conflicts() {
        let state = alerts_state();
        let router = admin_router(state.clone());
        assert_eq!(seed_builtins(&state), 5);

        // 直接用存储层补齐到 200 条，避免 195 次 HTTP 调用。
        for index in 5..MAX_ALERT_RULES {
            let mut rule = default_rule(now_ms(), "test".into());
            rule.name = format!("批量规则-{index}");
            rule.metric = "disk.used_percent".into();
            state.storage.create_alert_rule(&rule).unwrap();
        }
        assert_eq!(state.storage.alert_rule_count().unwrap(), MAX_ALERT_RULES);

        let (status, value) = call(
            &router,
            "POST",
            "/api/v1/alerts/rules",
            Some(LEGACY_TOKEN),
            Some(r#"{"name":"再一条","source":"metric","metric":"disk.used_percent"}"#),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(value["error"], "rule_limit");
        assert_eq!(state.storage.alert_rule_count().unwrap(), MAX_ALERT_RULES);
    }

    /// 存储层领域错误映射：未知错误不能泄露成 4xx。
    #[test]
    fn m4_b1_store_error_mapping_is_fixed() {
        assert!(matches!(
            map_store_error(AlertRuleStoreError::NotFound.into()),
            ApiError::NotFound(_)
        ));
        match map_store_error(AlertRuleStoreError::NameExists.into()) {
            ApiError::Conflict { code, .. } => assert_eq!(code, "rule_name_exists"),
            other => panic!("应为 409 Conflict: {other:?}"),
        }
        match map_store_error(AlertRuleStoreError::LimitReached.into()) {
            ApiError::Conflict { code, .. } => assert_eq!(code, "rule_limit"),
            other => panic!("应为 409 Conflict: {other:?}"),
        }
        match map_store_error(AlertRuleStoreError::BuiltinRule.into()) {
            ApiError::Forbidden { code, .. } => assert_eq!(code, "builtin_rule"),
            other => panic!("应为 403 Forbidden: {other:?}"),
        }
        assert!(matches!(
            map_store_error(anyhow::anyhow!("boom")),
            ApiError::Internal(_)
        ));
    }

    /// 内置规则 id 常量与种子一致（避免面板 / 文档引用漂移）。
    #[test]
    fn m4_b1_builtin_ids_are_stable() {
        let ids: Vec<String> = builtin_rules(0).into_iter().map(|rule| rule.id).collect();
        for id in [
            BUILTIN_AGENT_OFFLINE,
            "builtin-disk-percent",
            "builtin-agent-cert",
            "builtin-hub-cert",
            "builtin-buffer-backlog",
        ] {
            assert!(ids.iter().any(|value| value == id), "缺少内置规则 {id}");
        }
    }
}
