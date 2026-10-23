//! M4-B2a：四渠道通知发送器、签名、重试与错误脱敏。
//!
//! 端点全部写死（禁止用户填任意 URL，防 SSRF）：
//! - Telegram：`https://api.telegram.org/bot{token}/sendMessage`
//! - 企业微信：`https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={key}`
//! - 钉钉：`https://oapi.dingtalk.com/robot/send?access_token={token}&timestamp={ms}&sign={sign}`
//! - 飞书：`https://open.feishu.cn/open-apis/bot/v2/hook/{token}`
//!
//! 安全约定：
//! - token 只进固定端点的 URL path/query，字符集由
//!   [`rustboard_core::channels::ChannelConfig`] 校验；secret 只参与 HMAC；
//! - 任何错误只返回固定 code 与固定中文原因，**不包含 URL、token、secret 或
//!   上游响应正文**；
//! - 响应体解析按渠道校验 `ok` / `errcode` / `code`，并把读取上限卡在 64 KiB；
//! - `reqwest` 固定 `.no_proxy()`、总超时、禁止重定向、仅 HTTPS。
//!
//! 生产代码只通过 [`HttpNotifier::new`] 构造；测试用 [`MockNotifier`] 或模块内
//! 的 fake transport，不需要、也不允许把任意 URL 暴露到配置/API。

// B2a 只落地发送器，B2b 才会在告警路由/队列中接线；接线前允许未使用。
#![allow(dead_code)]

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use reqwest::redirect::Policy;
use reqwest::Url;
use rustboard_common::util::now_ms;
use rustboard_core::channels::{
    test_message, validate_notification_text, ChannelConfig, ChannelKind, NotificationChannel,
};
use serde_json::{json, Value};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const TELEGRAM_API_BASE: &str = "https://api.telegram.org/";
const WECOM_WEBHOOK_URL: &str = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send";
const DINGTALK_WEBHOOK_URL: &str = "https://oapi.dingtalk.com/robot/send";
const FEISHU_WEBHOOK_BASE: &str = "https://open.feishu.cn/open-apis/bot/v2/hook";

/// 默认重试间隔（方案 §6.2）：第 1/2/3 次失败后分别等待 1s/5s/15s。
const DEFAULT_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(5),
    Duration::from_secs(15),
];

/// 单次通知最多尝试次数上限（与 `alerts.notify_max_attempts` 的配置范围一致）。
const MAX_ATTEMPTS_LIMIT: u32 = 10;

/// 上游响应体读取上限；正常成功响应只有几十到几百字节。
const MAX_RESPONSE_BODY_BYTES: usize = 64 * 1024;

/// 通知发送失败原因。
///
/// 这是一个**固定、脱敏**的错误：不携带 reqwest 的错误串、URL、token、secret
/// 或上游响应正文。`HttpStatus` 只带状态码（便于日志与面板区分 4xx/5xx）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyError {
    /// 渠道配置不合法（字段范围 / 类型不匹配等）。
    InvalidConfig,
    /// 通知文本为空或超过 2000 字节。
    InvalidText,
    /// 无法构造 HTTP 客户端（系统 TLS 根证书等）。
    ClientBuild,
    /// 请求超时。
    Timeout,
    /// 网络层失败（连接失败、TLS 失败等），不含底层错误串。
    Transport,
    /// 上游返回非 2xx。
    HttpStatus(u16),
    /// 上游 2xx 但响应体不是该渠道的成功结构。
    ResponseInvalid,
}

impl NotifyError {
    /// 稳定的错误码（可写入 `alert_events.notify_error`）。
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::InvalidText => "invalid_text",
            Self::ClientBuild => "client_build",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::HttpStatus(_) => "http_status",
            Self::ResponseInvalid => "response_invalid",
        }
    }

    /// 是否值得重试。
    ///
    /// 配置/文本错误与 4xx（除 408/429）重试也不会成功；超时、网络错误、
    /// 响应异常、429 与 5xx 是瞬态失败，按 `max_attempts` 退避重试。
    pub fn is_retryable(self) -> bool {
        match self {
            Self::Timeout | Self::Transport | Self::ResponseInvalid => true,
            Self::HttpStatus(status) => matches!(status, 408 | 429) || status >= 500,
            Self::InvalidConfig | Self::InvalidText | Self::ClientBuild => false,
        }
    }
}

impl fmt::Display for NotifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig => f.write_str("渠道配置不合法"),
            Self::InvalidText => f.write_str("通知文本不合法"),
            Self::ClientBuild => f.write_str("HTTP 客户端初始化失败"),
            Self::Timeout => f.write_str("通知请求超时"),
            Self::Transport => f.write_str("通知请求失败"),
            Self::HttpStatus(status) => write!(f, "通知端点返回 HTTP {status}"),
            Self::ResponseInvalid => f.write_str("通知端点响应异常"),
        }
    }
}

impl std::error::Error for NotifyError {}

/// 通知发送接口。
///
/// B2b 通过这个 trait 持有 `Arc<dyn Notifier>`；测试可换成 [`MockNotifier`]。
#[async_trait]
pub trait Notifier: Send + Sync {
    /// 发送一条文本；实现方负责校验与重试。
    async fn send(&self, channel: &NotificationChannel, text: &str) -> Result<(), NotifyError>;

    /// 发送固定测试消息（不读取数据库、不包含任何 secret）。
    async fn test(&self, channel: &NotificationChannel) -> Result<(), NotifyError> {
        self.send(channel, &test_message(&channel.name)).await
    }
}

/// 一次 HTTP POST 的完整形状（URL 里可能含 token，故意不实现 `Debug`）。
#[derive(Clone, PartialEq)]
struct PreparedRequest {
    url: Url,
    body: Value,
}

/// 上游响应（只保留状态码与受限长度的 body）。
struct TransportResponse {
    status: u16,
    body: Vec<u8>,
}

/// HTTP 传输层。
///
/// 生产实现是 [`ReqwestTransport`]，私有；测试可注入 fake，避免真实外网请求。
#[async_trait]
trait NotifyTransport: Send + Sync {
    async fn post(&self, request: &PreparedRequest) -> Result<TransportResponse, NotifyError>;
}

/// 生产 HTTP 发送器。
pub struct HttpNotifier {
    transport: Arc<dyn NotifyTransport>,
    max_attempts: u32,
    retry_delays: Vec<Duration>,
}

impl HttpNotifier {
    /// 构造生产发送器。
    ///
    /// `timeout` 是单次请求总超时；`max_attempts` 含首次发送，会被夹到
    /// 1..=10（与配置校验范围一致）。
    pub fn new(timeout: Duration, max_attempts: u32) -> Result<Self, NotifyError> {
        let client = reqwest::Client::builder()
            // 固定端点不需要代理；也避免环境变量把请求带向别处。
            .no_proxy()
            // 四个端点全部是 HTTPS；禁止降级与重定向。
            .https_only(true)
            .redirect(Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|_| NotifyError::ClientBuild)?;
        Ok(Self {
            transport: Arc::new(ReqwestTransport { client }),
            max_attempts: max_attempts.clamp(1, MAX_ATTEMPTS_LIMIT),
            retry_delays: DEFAULT_RETRY_DELAYS.to_vec(),
        })
    }

    /// 第 `failed_attempts` 次失败后的退避时间（0 表示首次失败）。
    fn retry_delay(&self, failed_attempts: u32) -> Duration {
        if self.retry_delays.is_empty() {
            return Duration::ZERO;
        }
        let index = (failed_attempts as usize).min(self.retry_delays.len() - 1);
        self.retry_delays[index]
    }
}

#[async_trait]
impl Notifier for HttpNotifier {
    async fn send(&self, channel: &NotificationChannel, text: &str) -> Result<(), NotifyError> {
        let max_attempts = self.max_attempts.max(1);
        let mut attempt = 1;
        loop {
            // 每次重试都重新取时间：钉钉/飞书的签名必须在发送时有效。
            let request = build_request(channel, text, now_ms())?;
            let outcome = self
                .transport
                .post(&request)
                .await
                .and_then(|response| classify_response(channel.kind, response));
            let error = match outcome {
                Ok(()) => return Ok(()),
                Err(error) => error,
            };
            if attempt >= max_attempts || !error.is_retryable() {
                return Err(error);
            }
            let delay = self.retry_delay(attempt - 1);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            attempt += 1;
        }
    }
}

struct ReqwestTransport {
    client: reqwest::Client,
}

#[async_trait]
impl NotifyTransport for ReqwestTransport {
    async fn post(&self, request: &PreparedRequest) -> Result<TransportResponse, NotifyError> {
        let response = self
            .client
            .post(request.url.clone())
            .json(&request.body)
            .send()
            .await
            .map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        if !(200..=299).contains(&status) {
            // 非 2xx 不读 body：错误信息里绝不能出现上游正文。
            return Ok(TransportResponse {
                status,
                body: Vec::new(),
            });
        }
        let body = read_body_limited(response).await?;
        Ok(TransportResponse { status, body })
    }
}

async fn read_body_limited(mut response: reqwest::Response) -> Result<Vec<u8>, NotifyError> {
    if response
        .content_length()
        .is_some_and(|len| len > MAX_RESPONSE_BODY_BYTES as u64)
    {
        return Err(NotifyError::ResponseInvalid);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY_BYTES {
            return Err(NotifyError::ResponseInvalid);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// 把 reqwest 错误压成固定错误码；绝不保留底层错误串（可能含完整 URL）。
fn map_reqwest_error(error: reqwest::Error) -> NotifyError {
    if error.is_timeout() {
        NotifyError::Timeout
    } else {
        NotifyError::Transport
    }
}

/// 构造固定端点的请求。
///
/// `now` 为 Unix 毫秒：钉钉 query 用毫秒，飞书 body 用秒。
fn build_request(
    channel: &NotificationChannel,
    text: &str,
    now: i64,
) -> Result<PreparedRequest, NotifyError> {
    channel.validate().map_err(|_| NotifyError::InvalidConfig)?;
    validate_notification_text(text).map_err(|_| NotifyError::InvalidText)?;
    match &channel.config {
        ChannelConfig::Telegram { bot_token, chat_id } => {
            let mut url = fixed_url(TELEGRAM_API_BASE);
            url.path_segments_mut()
                .expect("固定通知端点必须支持路径分段")
                .push(&format!("bot{}", bot_token.expose()))
                .push("sendMessage");
            Ok(PreparedRequest {
                url,
                body: json!({
                    "chat_id": chat_id,
                    "text": text,
                    "disable_web_page_preview": true,
                }),
            })
        }
        ChannelConfig::Wecom { webhook_key } => {
            let mut url = fixed_url(WECOM_WEBHOOK_URL);
            url.query_pairs_mut()
                .append_pair("key", webhook_key.expose());
            Ok(PreparedRequest {
                url,
                body: json!({
                    "msgtype": "text",
                    "text": { "content": text },
                }),
            })
        }
        ChannelConfig::Dingtalk {
            access_token,
            secret,
        } => {
            let timestamp_ms = now;
            let sign = dingtalk_sign(secret.expose(), timestamp_ms);
            let mut url = fixed_url(DINGTALK_WEBHOOK_URL);
            url.query_pairs_mut()
                .append_pair("access_token", access_token.expose())
                .append_pair("timestamp", &timestamp_ms.to_string())
                .append_pair("sign", &sign);
            Ok(PreparedRequest {
                url,
                body: json!({
                    "msgtype": "text",
                    "text": { "content": text },
                }),
            })
        }
        ChannelConfig::Feishu {
            webhook_token,
            secret,
        } => {
            let timestamp_secs = now.div_euclid(1_000);
            let sign = feishu_sign(secret.expose(), timestamp_secs);
            let mut url = fixed_url(FEISHU_WEBHOOK_BASE);
            url.path_segments_mut()
                .expect("固定通知端点必须支持路径分段")
                .push(webhook_token.expose());
            Ok(PreparedRequest {
                url,
                body: json!({
                    // 飞书官方示例的 timestamp 是字符串类型（秒）。
                    "timestamp": timestamp_secs.to_string(),
                    "sign": sign,
                    "msg_type": "text",
                    "content": { "text": text },
                }),
            })
        }
    }
}

fn fixed_url(base: &str) -> Url {
    Url::parse(base).expect("固定通知端点必须是合法 URL")
}

/// 钉钉加签：`base64(HMAC-SHA256(key=secret, msg="{timestamp_ms}\n{secret}"))`。
fn dingtalk_sign(secret: &str, timestamp_ms: i64) -> String {
    let message = format!("{timestamp_ms}\n{secret}");
    hmac_sha256_base64(secret.as_bytes(), message.as_bytes())
}

/// 飞书加签：`base64(HMAC-SHA256(key="{timestamp_secs}\n{secret}", msg=""))`。
fn feishu_sign(secret: &str, timestamp_secs: i64) -> String {
    let key = format!("{timestamp_secs}\n{secret}");
    hmac_sha256_base64(key.as_bytes(), b"")
}

fn hmac_sha256_base64(key: &[u8], message: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 支持任意长度密钥");
    mac.update(message);
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// 校验上游 2xx 响应的成功结构。
fn classify_response(kind: ChannelKind, response: TransportResponse) -> Result<(), NotifyError> {
    if !(200..=299).contains(&response.status) {
        return Err(NotifyError::HttpStatus(response.status));
    }
    let value: Value =
        serde_json::from_slice(&response.body).map_err(|_| NotifyError::ResponseInvalid)?;
    let success = match kind {
        ChannelKind::Telegram => value.get("ok").and_then(Value::as_bool) == Some(true),
        ChannelKind::Wecom | ChannelKind::Dingtalk => {
            value.get("errcode").and_then(Value::as_i64) == Some(0)
        }
        ChannelKind::Feishu => value.get("code").and_then(Value::as_i64) == Some(0),
    };
    if success {
        Ok(())
    } else {
        Err(NotifyError::ResponseInvalid)
    }
}

/// 测试用通知记录（只含渠道标识与文本，不含配置 / secret）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentNotification {
    /// 渠道 id。
    pub channel_id: String,
    /// 渠道名称。
    pub channel_name: String,
    /// 渠道类型。
    pub kind: ChannelKind,
    /// 发送文本。
    pub text: String,
}

#[derive(Default)]
struct MockState {
    sent: Vec<SentNotification>,
    results: std::collections::VecDeque<Result<(), NotifyError>>,
    default_error: Option<NotifyError>,
}

/// 可注入的假通知器：记录调用并按队列返回成功/失败。
///
/// 用于 B2b/B3 的路由、队列与 API 测试；不会发起任何网络请求。
pub struct MockNotifier {
    state: Mutex<MockState>,
}

impl MockNotifier {
    /// 全部发送成功。
    pub fn new() -> Self {
        Self {
            state: Mutex::new(MockState::default()),
        }
    }

    /// 默认返回给定失败（队列为空时）。
    pub fn failing(error: NotifyError) -> Self {
        let notifier = Self::new();
        notifier
            .state
            .lock()
            .expect("MockNotifier 状态锁未被毒化")
            .default_error = Some(error);
        notifier
    }

    /// 压入下一次 `send` / `test` 的返回值；队列优先于默认值。
    pub fn push_result(&self, result: Result<(), NotifyError>) {
        self.state
            .lock()
            .expect("MockNotifier 状态锁未被毒化")
            .results
            .push_back(result);
    }

    /// 已记录的发送，按调用顺序。
    pub fn sent(&self) -> Vec<SentNotification> {
        self.state
            .lock()
            .expect("MockNotifier 状态锁未被毒化")
            .sent
            .clone()
    }

    /// 已调用次数。
    pub fn send_count(&self) -> usize {
        self.state
            .lock()
            .expect("MockNotifier 状态锁未被毒化")
            .sent
            .len()
    }
}

impl Default for MockNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Notifier for MockNotifier {
    async fn send(&self, channel: &NotificationChannel, text: &str) -> Result<(), NotifyError> {
        let mut state = self.state.lock().expect("MockNotifier 状态锁未被毒化");
        state.sent.push(SentNotification {
            channel_id: channel.id.clone(),
            channel_name: channel.name.clone(),
            kind: channel.kind,
            text: text.to_string(),
        });
        if let Some(result) = state.results.pop_front() {
            result
        } else if let Some(error) = state.default_error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use rustboard_core::channels::Secret;

    const TELEGRAM_TOKEN: &str = "123456789:AAH_test-token_0123456789";
    const TELEGRAM_CHAT_ID: &str = "-1001234567890";
    const WECOM_KEY: &str = "00000000-1111-2222-3333-444444444444";
    const DINGTALK_TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const DINGTALK_SECRET: &str = "SEC0123456789abcdef0123456789abcdef";
    const FEISHU_TOKEN: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const FEISHU_SECRET: &str = "feishu-secret-0123456789";
    const NOW_MS: i64 = 1_700_000_000_000;

    const DINGTALK_SIGN: &str = "hJ95/XWePTzrSwXDHEJJY1Ta0B6qiG/YMxNzB4v4U2w=";
    const FEISHU_SIGN: &str = "d3gGsFz+AHToelzC26bbD1t6jbk8R9u46n1N6K0Bj8o=";

    fn telegram() -> NotificationChannel {
        NotificationChannel {
            id: "0b6f9a2e-6a1d-4c5e-9f3a-1d2c3b4a5e6f".to_string(),
            name: "运维通知".to_string(),
            kind: ChannelKind::Telegram,
            config: ChannelConfig::Telegram {
                bot_token: Secret::new(TELEGRAM_TOKEN),
                chat_id: TELEGRAM_CHAT_ID.to_string(),
            },
            enabled: true,
            updated_by: "admin".to_string(),
            created_at: NOW_MS,
            updated_at: NOW_MS,
        }
    }

    fn wecom() -> NotificationChannel {
        NotificationChannel {
            kind: ChannelKind::Wecom,
            config: ChannelConfig::Wecom {
                webhook_key: Secret::new(WECOM_KEY),
            },
            ..telegram()
        }
    }

    fn dingtalk() -> NotificationChannel {
        NotificationChannel {
            kind: ChannelKind::Dingtalk,
            config: ChannelConfig::Dingtalk {
                access_token: Secret::new(DINGTALK_TOKEN),
                secret: Secret::new(DINGTALK_SECRET),
            },
            ..telegram()
        }
    }

    fn feishu() -> NotificationChannel {
        NotificationChannel {
            kind: ChannelKind::Feishu,
            config: ChannelConfig::Feishu {
                webhook_token: Secret::new(FEISHU_TOKEN),
                secret: Secret::new(FEISHU_SECRET),
            },
            ..telegram()
        }
    }

    fn ok_body(kind: ChannelKind) -> Vec<u8> {
        match kind {
            ChannelKind::Telegram => br#"{"ok":true}"#.to_vec(),
            ChannelKind::Wecom | ChannelKind::Dingtalk => {
                br#"{"errcode":0,"errmsg":"ok"}"#.to_vec()
            }
            ChannelKind::Feishu => br#"{"code":0,"msg":"success"}"#.to_vec(),
        }
    }

    fn response(status: u16, body: &[u8]) -> TransportResponse {
        TransportResponse {
            status,
            body: body.to_vec(),
        }
    }

    #[derive(Default)]
    struct RecordingTransport {
        responses: Mutex<VecDeque<Result<TransportResponse, NotifyError>>>,
        requests: Mutex<Vec<PreparedRequest>>,
    }

    impl RecordingTransport {
        fn new(responses: Vec<Result<TransportResponse, NotifyError>>) -> Arc<Self> {
            Arc::new(Self {
                responses: Mutex::new(responses.into()),
                requests: Mutex::new(Vec::new()),
            })
        }

        fn requests(&self) -> Vec<PreparedRequest> {
            self.requests
                .lock()
                .expect("测试 transport 请求锁未被毒化")
                .clone()
        }
    }

    #[async_trait]
    impl NotifyTransport for RecordingTransport {
        async fn post(&self, request: &PreparedRequest) -> Result<TransportResponse, NotifyError> {
            self.requests
                .lock()
                .expect("测试 transport 请求锁未被毒化")
                .push(request.clone());
            self.responses
                .lock()
                .expect("测试 transport 响应锁未被毒化")
                .pop_front()
                .unwrap_or(Ok(TransportResponse {
                    status: 200,
                    body: Vec::new(),
                }))
        }
    }

    fn notifier_with(transport: Arc<RecordingTransport>, max_attempts: u32) -> HttpNotifier {
        HttpNotifier {
            transport,
            max_attempts,
            retry_delays: vec![Duration::ZERO],
        }
    }

    fn text() -> &'static str {
        "【RustBoard】渠道：运维通知\n磁盘告警"
    }

    #[test]
    fn m4_b2a_four_channel_requests_have_fixed_shapes() {
        let telegram_request = build_request(&telegram(), text(), NOW_MS).unwrap();
        assert_eq!(
            telegram_request.url.as_str(),
            format!("https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage")
        );
        assert_eq!(
            telegram_request.body,
            json!({
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text(),
                "disable_web_page_preview": true,
            })
        );

        let wecom_request = build_request(&wecom(), text(), NOW_MS).unwrap();
        assert_eq!(
            wecom_request.url.as_str(),
            format!("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key={WECOM_KEY}")
        );
        assert_eq!(
            wecom_request.body,
            json!({"msgtype": "text", "text": {"content": text()}})
        );

        let dingtalk_request = build_request(&dingtalk(), text(), NOW_MS).unwrap();
        assert_eq!(
            dingtalk_request.url.as_str(),
            "https://oapi.dingtalk.com/robot/send?access_token=0123456789abcdef0123456789abcdef&timestamp=1700000000000&sign=hJ95%2FXWePTzrSwXDHEJJY1Ta0B6qiG%2FYMxNzB4v4U2w%3D"
        );
        assert_eq!(
            dingtalk_request.body,
            json!({"msgtype": "text", "text": {"content": text()}})
        );

        let feishu_request = build_request(&feishu(), text(), NOW_MS).unwrap();
        assert_eq!(
            feishu_request.url.as_str(),
            format!("https://open.feishu.cn/open-apis/bot/v2/hook/{FEISHU_TOKEN}")
        );
        assert_eq!(
            feishu_request.body,
            json!({
                "timestamp": "1700000000",
                "sign": FEISHU_SIGN,
                "msg_type": "text",
                "content": {"text": text()},
            })
        );
    }

    #[test]
    fn m4_b2a_dingtalk_and_feishu_signatures_match_fixed_vectors() {
        assert_eq!(dingtalk_sign(DINGTALK_SECRET, NOW_MS), DINGTALK_SIGN);
        assert_eq!(
            feishu_sign(FEISHU_SECRET, NOW_MS.div_euclid(1_000)),
            FEISHU_SIGN
        );

        // 防止把 key / message 写反：交换二者必须得到不同结果。
        assert_ne!(
            dingtalk_sign(DINGTALK_SECRET, NOW_MS),
            hmac_sha256_base64(
                format!("{NOW_MS}\n{DINGTALK_SECRET}").as_bytes(),
                DINGTALK_SECRET.as_bytes()
            )
        );
        assert_ne!(
            feishu_sign(FEISHU_SECRET, 1_700_000_000),
            hmac_sha256_base64(
                FEISHU_SECRET.as_bytes(),
                b"1700000000\nfeishu-secret-0123456789"
            )
        );
    }

    #[test]
    fn m4_b2a_invalid_token_chars_are_rejected() {
        for token in [
            "123456789:AAH/token_0123456789",
            "123456789:AAH?token_0123456789",
            "123456789:AAH token_0123456789",
        ] {
            let mut channel = telegram();
            channel.config = ChannelConfig::Telegram {
                bot_token: Secret::new(token),
                chat_id: TELEGRAM_CHAT_ID.to_string(),
            };
            assert_eq!(
                build_request(&channel, text(), NOW_MS).err(),
                Some(NotifyError::InvalidConfig)
            );
        }

        let mut channel = wecom();
        channel.config = ChannelConfig::Wecom {
            webhook_key: Secret::new("bad&key=with-enough-length"),
        };
        assert_eq!(
            build_request(&channel, text(), NOW_MS).err(),
            Some(NotifyError::InvalidConfig)
        );

        let mut channel = dingtalk();
        channel.config = ChannelConfig::Dingtalk {
            access_token: Secret::new(DINGTALK_TOKEN),
            secret: Secret::new("SEC0123456789\nabcdef0123456789abcdef"),
        };
        assert_eq!(
            build_request(&channel, text(), NOW_MS).err(),
            Some(NotifyError::InvalidConfig)
        );
    }

    #[test]
    fn m4_b2a_invalid_text_is_rejected_before_transport() {
        assert_eq!(
            build_request(&telegram(), "", NOW_MS).err(),
            Some(NotifyError::InvalidText)
        );
        assert_eq!(
            build_request(&telegram(), &"a".repeat(2_001), NOW_MS).err(),
            Some(NotifyError::InvalidText)
        );
    }

    #[tokio::test]
    async fn m4_b2a_errors_never_contain_secrets_or_urls() {
        for (channel, secret_values) in [
            (telegram(), vec![TELEGRAM_TOKEN]),
            (wecom(), vec![WECOM_KEY]),
            (
                dingtalk(),
                vec![DINGTALK_TOKEN, DINGTALK_SECRET, DINGTALK_SIGN],
            ),
            (feishu(), vec![FEISHU_TOKEN, FEISHU_SECRET, FEISHU_SIGN]),
        ] {
            for status in [500, 401] {
                let transport = RecordingTransport::new(vec![Ok(response(status, b""))]);
                let notifier = notifier_with(transport, 1);
                let error = notifier
                    .send(&channel, text())
                    .await
                    .expect_err("非 2xx 必须失败");
                let rendered = format!("{error} {error:?}");
                assert_eq!(error, NotifyError::HttpStatus(status));
                assert!(!rendered.contains("https://"));
                assert!(!rendered.contains("api.telegram.org"));
                for secret in &secret_values {
                    assert!(!rendered.contains(secret), "错误泄露了 secret: {rendered}");
                }
            }

            let transport = RecordingTransport::new(vec![Err(NotifyError::Timeout)]);
            let notifier = notifier_with(transport, 1);
            let error = notifier.send(&channel, text()).await.unwrap_err();
            let rendered = format!("{error} {error:?}");
            assert_eq!(error, NotifyError::Timeout);
            for secret in &secret_values {
                assert!(!rendered.contains(secret));
            }
        }
    }

    #[tokio::test]
    async fn m4_b2a_retries_transient_failures_then_succeeds() {
        let transport = RecordingTransport::new(vec![
            Err(NotifyError::Timeout),
            Err(NotifyError::Transport),
            Ok(response(200, &ok_body(ChannelKind::Telegram))),
        ]);
        let notifier = notifier_with(transport.clone(), 3);
        notifier.send(&telegram(), text()).await.unwrap();
        assert_eq!(transport.requests().len(), 3);
    }

    #[tokio::test]
    async fn m4_b2a_retries_stop_at_max_attempts() {
        let transport = RecordingTransport::new(vec![
            Ok(response(500, b"")),
            Ok(response(500, b"")),
            Ok(response(500, b"")),
        ]);
        let notifier = notifier_with(transport.clone(), 2);
        assert_eq!(
            notifier.send(&telegram(), text()).await.unwrap_err(),
            NotifyError::HttpStatus(500)
        );
        assert_eq!(transport.requests().len(), 2);
    }

    #[tokio::test]
    async fn m4_b2a_non_retryable_status_is_attempted_once() {
        let transport = RecordingTransport::new(vec![Ok(response(401, b""))]);
        let notifier = notifier_with(transport.clone(), 5);
        assert_eq!(
            notifier.send(&telegram(), text()).await.unwrap_err(),
            NotifyError::HttpStatus(401)
        );
        assert_eq!(transport.requests().len(), 1);
    }

    #[tokio::test]
    async fn m4_b2a_invalid_config_does_not_call_transport() {
        let mut channel = telegram();
        channel.kind = ChannelKind::Wecom;
        let transport = RecordingTransport::new(Vec::new());
        let notifier = notifier_with(transport.clone(), 3);
        assert_eq!(
            notifier.send(&channel, text()).await.unwrap_err(),
            NotifyError::InvalidConfig
        );
        assert!(transport.requests().is_empty());
    }

    #[test]
    fn m4_b2a_response_bodies_are_validated_per_channel() {
        assert!(classify_response(ChannelKind::Telegram, response(200, br#"{"ok":true}"#)).is_ok());
        assert_eq!(
            classify_response(ChannelKind::Telegram, response(200, br#"{"ok":false}"#))
                .unwrap_err(),
            NotifyError::ResponseInvalid
        );
        assert_eq!(
            classify_response(ChannelKind::Telegram, response(200, b"not-json")).unwrap_err(),
            NotifyError::ResponseInvalid
        );

        for kind in [ChannelKind::Wecom, ChannelKind::Dingtalk] {
            assert!(classify_response(kind, response(200, br#"{"errcode":0}"#)).is_ok());
            assert_eq!(
                classify_response(kind, response(200, br#"{"errcode":1}"#)).unwrap_err(),
                NotifyError::ResponseInvalid
            );
            assert_eq!(
                classify_response(kind, response(200, br#"{"msg":"ok"}"#)).unwrap_err(),
                NotifyError::ResponseInvalid
            );
        }

        assert!(classify_response(ChannelKind::Feishu, response(200, br#"{"code":0}"#)).is_ok());
        assert_eq!(
            classify_response(ChannelKind::Feishu, response(200, br#"{"code":19001}"#))
                .unwrap_err(),
            NotifyError::ResponseInvalid
        );
        assert_eq!(
            classify_response(ChannelKind::Feishu, response(500, b"")).unwrap_err(),
            NotifyError::HttpStatus(500)
        );
    }

    #[tokio::test]
    async fn m4_b2a_mock_notifier_records_success_and_failure() {
        let mock = MockNotifier::new();
        mock.send(&telegram(), "hello").await.unwrap();
        assert_eq!(mock.send_count(), 1);
        let sent = mock.sent();
        assert_eq!(sent[0].channel_id, telegram().id);
        assert_eq!(sent[0].text, "hello");
        assert_eq!(sent[0].kind, ChannelKind::Telegram);

        let failing = MockNotifier::failing(NotifyError::Transport);
        assert_eq!(
            failing.send(&telegram(), "hello").await.unwrap_err(),
            NotifyError::Transport
        );
        assert_eq!(failing.send_count(), 1);

        let queued = MockNotifier::new();
        queued.push_result(Err(NotifyError::InvalidText));
        assert_eq!(
            queued.send(&telegram(), "hello").await.unwrap_err(),
            NotifyError::InvalidText
        );
        queued.send(&telegram(), "hello").await.unwrap();
        assert_eq!(queued.send_count(), 2);
    }

    #[tokio::test]
    async fn m4_b2a_mock_test_uses_fixed_message_and_no_secret() {
        let mock = MockNotifier::new();
        mock.test(&telegram()).await.unwrap();
        let sent = mock.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].text, test_message(&telegram().name));
        for secret in [TELEGRAM_TOKEN, TELEGRAM_CHAT_ID] {
            assert!(!sent[0].text.contains(secret));
        }
    }

    #[test]
    fn m4_b2a_attempt_count_is_clamped() {
        // 这里只验证夹取逻辑；不构造 reqwest client，避免测试依赖系统根证书。
        let clamp = |attempts: u32| attempts.clamp(1, MAX_ATTEMPTS_LIMIT);
        assert_eq!(clamp(0), 1);
        assert_eq!(clamp(3), 3);
        assert_eq!(clamp(99), MAX_ATTEMPTS_LIMIT);
    }

    #[test]
    fn m4_b2a_retry_backoff_follows_plan_schedule() {
        let notifier = HttpNotifier {
            transport: RecordingTransport::new(Vec::new()),
            max_attempts: 3,
            retry_delays: DEFAULT_RETRY_DELAYS.to_vec(),
        };
        assert_eq!(notifier.retry_delay(0), Duration::from_secs(1));
        assert_eq!(notifier.retry_delay(1), Duration::from_secs(5));
        assert_eq!(notifier.retry_delay(2), Duration::from_secs(15));
        assert_eq!(notifier.retry_delay(99), Duration::from_secs(15));

        let no_delay = HttpNotifier {
            transport: RecordingTransport::new(Vec::new()),
            max_attempts: 3,
            retry_delays: Vec::new(),
        };
        assert_eq!(no_delay.retry_delay(0), Duration::ZERO);
    }

    #[tokio::test]
    async fn m4_b2a_invalid_response_body_is_not_echoed() {
        let body = format!("{{\"ok\":false,\"description\":\"{TELEGRAM_TOKEN}\"}}");
        let transport = RecordingTransport::new(vec![Ok(response(200, body.as_bytes()))]);
        let notifier = notifier_with(transport, 1);
        let error = notifier.send(&telegram(), text()).await.unwrap_err();
        let rendered = format!("{error} {error:?}");
        assert_eq!(error, NotifyError::ResponseInvalid);
        assert!(!rendered.contains(TELEGRAM_TOKEN));
        assert!(!rendered.contains("description"));
    }
}
