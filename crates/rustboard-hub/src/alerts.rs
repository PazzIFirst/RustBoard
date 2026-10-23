//! M4-B1：告警规则、事件与静默管理 API。
//!
//! 规则 CRUD 属于 B1a；事件查询与静默创建 / 撤销属于 B1b。告警评估由
//! `alerts_engine` 后台任务执行，通知渠道属于 B2（本模块不发送任何通知）。
//!
//! 路由（写在 `admin_router` 的受保护路由树里，统一先过 Bearer 鉴权）：
//! - `GET    /api/v1/alerts/rules`          read
//! - `POST   /api/v1/alerts/rules`          write
//! - `PUT    /api/v1/alerts/rules/{id}`     write
//! - `DELETE /api/v1/alerts/rules/{id}`     write
//! - `GET    /api/v1/alerts/events`         read（`limit` 1–200，`before_id` 排他游标）
//! - `GET    /api/v1/alerts/silences`       read（只返回生效中的静默）
//! - `POST   /api/v1/alerts/silences`       write
//! - `DELETE /api/v1/alerts/silences/{id}`  write
//!
//! 安全约定：
//! - 请求体 `deny_unknown_fields`，错误一律 400，不回显 serde 原文；
//! - 错误信息只描述资源，不回显用户输入；`is_builtin` / `id` / `created_at`
//!   只能由服务端维护，内置规则只允许禁停与修改，不允许删除；
//! - `updated_by` / `created_by` 取 [`AuthPrincipal::name`]（旧 admin token 为
//!   `"admin"`）；
//! - 事件响应包含 `silenced` / `notified` / `notify_error`，但 B1b 的 `notified`
//!   恒为 false，且不包含任何 secret。

use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, RawQuery, State};
use axum::http::StatusCode;
use axum::Json;
use rustboard_common::model::Labels;
use rustboard_common::util::now_ms;
use rustboard_core::alerts::{
    AlertEvent, AlertRule, AlertRuleInput, AlertRuleStoreError, AlertSilence, AlertSilenceInput,
    AlertSource, Comparator, MAX_ALERT_RULES,
};
use serde::de::DeserializeOwned;
use uuid::Uuid;

/// 事件分页默认条数。
const DEFAULT_ALERT_EVENT_LIMIT: usize = 100;
/// 事件分页单页上限（B1b 约定 1..=200）。
const MAX_ALERT_EVENT_LIMIT: usize = 200;

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
fn parse_body<T: DeserializeOwned>(body: Result<Json<T>, JsonRejection>) -> Result<T, ApiError> {
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

/// 事件分页响应：`events` 按 id 倒序；`next_before_id` 是下一页的排他游标。
#[derive(Debug, serde::Serialize)]
pub(crate) struct AlertEventListResponse {
    events: Vec<AlertEvent>,
    /// 本页满时返回最后一条 id；没有更多数据为 `null`。
    next_before_id: Option<i64>,
}

/// 取单值查询参数；重复出现视为参数错误（不猜客户端意图）。
fn single_query_value<'a>(
    pairs: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, String> {
    let mut found: Option<&str> = None;
    for (name, value) in pairs {
        if name == key {
            if found.is_some() {
                return Err(format!("查询参数 {key} 重复"));
            }
            found = Some(value.as_str());
        }
    }
    Ok(found)
}

/// 解析 `limit`：缺省 100，范围 1..=200。
fn parse_event_limit(pairs: &[(String, String)]) -> Result<usize, String> {
    let Some(raw) = single_query_value(pairs, "limit")? else {
        return Ok(DEFAULT_ALERT_EVENT_LIMIT);
    };
    let limit: usize = raw.parse().map_err(|_| "limit 必须是正整数".to_string())?;
    if !(1..=MAX_ALERT_EVENT_LIMIT).contains(&limit) {
        return Err(format!("limit 必须在 1–{MAX_ALERT_EVENT_LIMIT} 之间"));
    }
    Ok(limit)
}

/// 解析排他游标 `before_id`：必须是正整数。
fn parse_before_id(pairs: &[(String, String)]) -> Result<Option<i64>, String> {
    let Some(raw) = single_query_value(pairs, "before_id")? else {
        return Ok(None);
    };
    let value: i64 = raw
        .parse()
        .map_err(|_| "before_id 必须是正整数".to_string())?;
    if value <= 0 {
        return Err("before_id 必须是正整数".to_string());
    }
    Ok(Some(value))
}

/// `GET /api/v1/alerts/events`：按 id 倒序分页查询事件。
pub(crate) async fn list_events(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
) -> Result<Json<AlertEventListResponse>, ApiError> {
    let pairs = crate::parse_query_pairs(raw.as_deref()).map_err(ApiError::bad_request)?;
    let limit = parse_event_limit(&pairs).map_err(ApiError::bad_request)?;
    let before_id = parse_before_id(&pairs).map_err(ApiError::bad_request)?;

    let storage = state.storage.clone();
    let events = run_blocking(move || storage.list_alert_events(limit, before_id)).await?;
    // 排他游标：本页满时下一页从最后一条 id 继续（严格小于），不会漏也不会重。
    let next_before_id = if events.len() == limit {
        events.last().map(|event| event.id).filter(|id| *id > 1)
    } else {
        None
    };
    Ok(Json(AlertEventListResponse {
        events,
        next_before_id,
    }))
}

/// `GET /api/v1/alerts/silences`：列出当前生效的静默（`until_ts > now`）。
pub(crate) async fn list_silences(
    State(state): State<AppState>,
) -> Result<Json<Vec<AlertSilence>>, ApiError> {
    let now = now_ms();
    let storage = state.storage.clone();
    let silences = run_blocking(move || storage.list_active_silences(now)).await?;
    Ok(Json(silences))
}

/// `POST /api/v1/alerts/silences`：创建静默。
///
/// `rule_id` / `agent_id` 缺省或 null 表示全部；给出 `rule_id` 时规则必须存在
/// （404），避免为拼错的 id 建立永不命中的静默。`created_by` 取当前认证主体。
pub(crate) async fn create_silence(
    State(state): State<AppState>,
    principal: Option<Extension<AuthPrincipal>>,
    body: Result<Json<AlertSilenceInput>, JsonRejection>,
) -> Result<Json<AlertSilence>, ApiError> {
    let input = parse_body(body)?;
    input.validate().map_err(ApiError::bad_request)?;
    let created_by = principal_name(principal)?;

    if let Some(rule_id) = input.rule_id.clone() {
        let storage = state.storage.clone();
        let existing = run_blocking(move || storage.get_alert_rule(&rule_id)).await?;
        if existing.is_none() {
            return Err(ApiError::not_found("告警规则不存在"));
        }
    }

    let now = now_ms();
    let mut silence = input.into_silence(now, created_by);
    let storage = state.storage.clone();
    let to_store = silence.clone();
    let id = run_blocking(move || storage.create_alert_silence(&to_store)).await?;
    silence.id = id;
    Ok(Json(silence))
}

/// `DELETE /api/v1/alerts/silences/{id}`：撤销一条静默；不存在 / 非法 id 均为 404。
pub(crate) async fn delete_silence(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let Ok(id) = id.parse::<i64>() else {
        return Err(ApiError::not_found("静默不存在"));
    };
    if id <= 0 {
        return Err(ApiError::not_found("静默不存在"));
    }
    let storage = state.storage.clone();
    let deleted = run_blocking(move || storage.delete_alert_silence(id)).await?;
    if !deleted {
        return Err(ApiError::not_found("静默不存在"));
    }
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

    // ------------------------------------------------------------------
    // M4-B1b：事件 / 静默 API
    // ------------------------------------------------------------------

    use rustboard_core::alerts::AlertStateKind;

    fn seed_event(state: &AppState, ts: i64, silenced: bool) -> i64 {
        state
            .storage
            .insert_alert_event(&AlertEvent {
                id: 0,
                ts,
                rule_id: "rule-1".into(),
                rule_name: "事件规则".into(),
                agent_id: "agent-1".into(),
                state: AlertStateKind::Firing,
                value: Some(1.5),
                message: "规则「事件规则」触发：agent agent-1 指标「disk.used_percent」当前值 95，阈值 > 90".into(),
                notified: false,
                notify_error: String::new(),
                silenced,
            })
            .unwrap()
    }

    /// 事件分页：limit / before_id、排他游标、字段完整性、非法参数 400。
    #[tokio::test]
    async fn m4_b1b_alert_events_pagination_and_validation() {
        let state = alerts_state();
        let read = seed_token(&state, "events-read", "read");
        let router = admin_router(state.clone());
        let now = now_ms();
        for index in 0..5 {
            seed_event(&state, now + index, index == 4);
        }

        let (status, body) = call(&router, "GET", "/api/v1/alerts/events", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK, "响应: {body}");
        assert_eq!(body["events"].as_array().unwrap().len(), 5);
        assert_eq!(body["next_before_id"], Value::Null);
        let newest = &body["events"][0];
        assert_eq!(newest["id"], 5, "最新事件必须排在最前");
        assert_eq!(newest["state"], "firing");
        assert_eq!(newest["silenced"], json!(true));
        assert_eq!(newest["notified"], json!(false), "B1b 不发送通知");
        assert_eq!(newest["notify_error"], "");
        assert_eq!(newest["rule_id"], "rule-1");
        assert_eq!(newest["agent_id"], "agent-1");
        assert!(newest["message"].as_str().unwrap().contains("事件规则"));

        let (status, page) = call(
            &router,
            "GET",
            "/api/v1/alerts/events?limit=2",
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            page["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| event["id"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![5, 4]
        );
        assert_eq!(page["next_before_id"], 4);

        let (status, page) = call(
            &router,
            "GET",
            "/api/v1/alerts/events?limit=2&before_id=4",
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            page["events"]
                .as_array()
                .unwrap()
                .iter()
                .map(|event| event["id"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![3, 2]
        );
        assert_eq!(page["next_before_id"], 2);

        let (status, page) = call(
            &router,
            "GET",
            "/api/v1/alerts/events?limit=2&before_id=2",
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(page["events"].as_array().unwrap().len(), 1);
        assert_eq!(page["events"][0]["id"], 1);
        assert_eq!(page["next_before_id"], Value::Null);

        // 未认证先 401。
        let (status, body) = call(&router, "GET", "/api/v1/alerts/events", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "unauthorized");

        // 非法分页参数：固定 400 bad_request，不回显原始值。
        for uri in [
            "/api/v1/alerts/events?limit=0",
            "/api/v1/alerts/events?limit=201",
            "/api/v1/alerts/events?limit=abc",
            "/api/v1/alerts/events?limit=1&limit=2",
            "/api/v1/alerts/events?before_id=0",
            "/api/v1/alerts/events?before_id=-1",
            "/api/v1/alerts/events?before_id=abc",
        ] {
            let (status, body) = call(&router, "GET", uri, Some(&read), None).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "uri={uri} body={body}");
            assert_eq!(body["error"], "bad_request", "uri={uri}");
        }
    }

    /// 静默 CRUD：scope 矩阵、规则存在校验、时长 / 字段校验、404 与生效窗口。
    #[tokio::test]
    async fn m4_b1b_alert_silence_crud_scope_and_validation() {
        let state = alerts_state();
        let read = seed_token(&state, "silence-read", "read");
        let write = seed_token(&state, "silence-write", "write");
        let router = admin_router(state.clone());

        let mut target = default_rule(now_ms(), "test".into());
        target.name = "静默目标".into();
        target.metric = "disk.used_percent".into();
        state.storage.create_alert_rule(&target).unwrap();

        // 未认证 401；read 可查不可写。
        let (status, _) = call(&router, "GET", "/api/v1/alerts/silences", None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, body) =
            call(&router, "GET", "/api/v1/alerts/silences", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, json!([]));
        let (status, body) = call(
            &router,
            "POST",
            "/api/v1/alerts/silences",
            Some(&read),
            Some(r#"{"duration_secs":60}"#),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "forbidden_scope");
        let (status, body) = call(
            &router,
            "DELETE",
            "/api/v1/alerts/silences/1",
            Some(&read),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "forbidden_scope");

        // 指定规则 + agent：created_by 取 token name，until_ts = created_at + 时长。
        let body = json!({
            "rule_id": target.id,
            "agent_id": "agent-1",
            "duration_secs": 60
        })
        .to_string();
        let (status, created) = call(
            &router,
            "POST",
            "/api/v1/alerts/silences",
            Some(&write),
            Some(&body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "创建静默失败: {created}");
        let first_id = created["id"].as_i64().expect("必须返回 id");
        assert!(first_id > 0);
        assert_eq!(created["rule_id"], target.id);
        assert_eq!(created["agent_id"], "agent-1");
        assert_eq!(created["created_by"], "silence-write");
        assert_eq!(
            created["until_ts"].as_i64().unwrap(),
            created["created_at"].as_i64().unwrap() + 60_000
        );

        // 全局静默（rule_id/agent_id 缺省）与 legacy admin 的 created_by。
        let (status, global) = call(
            &router,
            "POST",
            "/api/v1/alerts/silences",
            Some(LEGACY_TOKEN),
            Some(r#"{"duration_secs":1}"#),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "创建全局静默失败: {global}");
        assert_eq!(global["rule_id"], Value::Null);
        assert_eq!(global["agent_id"], Value::Null);
        assert_eq!(global["created_by"], "admin");

        let (status, list) =
            call(&router, "GET", "/api/v1/alerts/silences", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 2);
        assert!(list
            .as_array()
            .unwrap()
            .iter()
            .any(|silence| silence["id"] == first_id));

        // 参数错误：固定 400；规则不存在：404。
        for body in [
            r#"{"duration_secs":0}"#,
            r#"{"duration_secs":604801}"#,
            r#"{"rule_id":"some-rule"}"#,
            r#"{"duration_secs":60,"unknown":true}"#,
            r#"{"duration_secs":60,"agent_id":"bad agent"}"#,
            r#"{"duration_secs":60,"rule_id":""}"#,
        ] {
            let (status, value) = call(
                &router,
                "POST",
                "/api/v1/alerts/silences",
                Some(&write),
                Some(body),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "body={body} resp={value}");
            assert_eq!(value["error"], "bad_request", "body={body}");
        }
        let (status, value) = call(
            &router,
            "POST",
            "/api/v1/alerts/silences",
            Some(&write),
            Some(r#"{"rule_id":"missing-rule","duration_secs":60}"#),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value["error"], "not_found");

        // 过期静默不出现在 GET（直接写库构造）。
        state
            .storage
            .create_alert_silence(&AlertSilence {
                id: 0,
                rule_id: None,
                agent_id: None,
                until_ts: now_ms() - 1_000,
                created_by: "seed".into(),
                created_at: now_ms() - 2_000,
            })
            .unwrap();
        let (status, list) =
            call(&router, "GET", "/api/v1/alerts/silences", Some(&read), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 2, "过期静默不能被返回");

        // 撤销：成功 204；再次删除 / 非法 id 都 404。
        let (status, _) = call(
            &router,
            "DELETE",
            &format!("/api/v1/alerts/silences/{first_id}"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let (status, value) = call(
            &router,
            "DELETE",
            &format!("/api/v1/alerts/silences/{first_id}"),
            Some(&write),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(value["error"], "not_found");
        for id in ["abc", "0", "-1", "999999"] {
            let (status, value) = call(
                &router,
                "DELETE",
                &format!("/api/v1/alerts/silences/{id}"),
                Some(&write),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::NOT_FOUND, "id={id} resp={value}");
            assert_eq!(value["error"], "not_found");
        }
    }
}
