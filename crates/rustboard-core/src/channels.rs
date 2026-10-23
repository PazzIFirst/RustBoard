//! M4-B2a：通知渠道模型、配置校验与脱敏。
//!
//! 本模块只负责**渠道本身**：类型、序列化结构、输入校验、API 视图与通知文本。
//! HTTP 发送、签名与重试在 `rustboard-hub::notify`（B2a），渠道 CRUD、存储与
//! 告警路由在 B2b 接入。
//!
//! 安全约定：
//! - [`Secret`] 的 `Debug` 恒为 `<redacted>`，任何错误信息都不回显原文；
//! - [`ChannelView`] 只含非敏感字段与「哪些 secret 字段已配置」，**绝不包含
//!   secret 值**；`ChannelConfig` 的序列化保留原文，只用于写 SQLite 的
//!   `config_json`，不得直接返回给 API；
//! - token 会进入固定端点的 URL path/query，因此只允许 URL 安全字符；
//!   secret 只参与 HMAC，拒绝控制字符；
//! - 通知文本长度有硬上限（企微 2048 字节最严格），超长按 UTF-8 字符边界截断。

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::alerts::{AlertEvent, AlertStateKind};

/// 渠道名称最大字节数（与方案 §8.1 的「1..64 字节」一致）。
pub const MAX_CHANNEL_NAME_BYTES: usize = 64;
/// 渠道名称最大字符数：字节与字符双上限，避免多字节字符绕过长度检查。
pub const MAX_CHANNEL_NAME_CHARS: usize = 64;

/// 单条通知文本的硬上限。
///
/// 四家渠道里企业微信最严格（text 内容上限 2048 字节），这里留出 JSON 与
/// 头部余量取 2000；事件描述本身只有 ≤512 字节，正常不会触发截断。
pub const MAX_NOTIFICATION_TEXT_BYTES: usize = 2000;

/// Telegram bot_token 最小字节数。
pub const MIN_TELEGRAM_BOT_TOKEN_BYTES: usize = 20;
/// Telegram bot_token 最大字节数。
pub const MAX_TELEGRAM_BOT_TOKEN_BYTES: usize = 128;
/// Telegram chat_id 最大字节数。
pub const MAX_TELEGRAM_CHAT_ID_BYTES: usize = 64;

/// 企业微信 webhook key 最小字节数。
pub const MIN_WECOM_WEBHOOK_KEY_BYTES: usize = 10;
/// 企业微信 webhook key 最大字节数。
pub const MAX_WECOM_WEBHOOK_KEY_BYTES: usize = 128;

/// 钉钉 access_token 最小字节数。
pub const MIN_DINGTALK_ACCESS_TOKEN_BYTES: usize = 10;
/// 钉钉 access_token 最大字节数。
pub const MAX_DINGTALK_ACCESS_TOKEN_BYTES: usize = 128;
/// 钉钉加签 secret 最小字节数。
pub const MIN_DINGTALK_SECRET_BYTES: usize = 32;
/// 钉钉加签 secret 最大字节数。
pub const MAX_DINGTALK_SECRET_BYTES: usize = 128;

/// 飞书 webhook token 最小字节数。
pub const MIN_FEISHU_WEBHOOK_TOKEN_BYTES: usize = 8;
/// 飞书 webhook token 最大字节数。
pub const MAX_FEISHU_WEBHOOK_TOKEN_BYTES: usize = 128;
/// 飞书加签 secret 最小字节数。
pub const MIN_FEISHU_SECRET_BYTES: usize = 8;
/// 飞书加签 secret 最大字节数。
pub const MAX_FEISHU_SECRET_BYTES: usize = 128;

/// 渠道类型；数据库 / API 使用稳定小写字符串。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelKind {
    /// Telegram Bot API。
    Telegram,
    /// 企业微信机器人。
    Wecom,
    /// 钉钉自定义机器人。
    Dingtalk,
    /// 飞书自定义机器人。
    Feishu,
}

impl ChannelKind {
    /// 全部渠道类型，顺序稳定，供测试与面板枚举使用。
    pub const ALL: [Self; 4] = [Self::Telegram, Self::Wecom, Self::Dingtalk, Self::Feishu];

    /// 数据库 / API 使用的稳定字符串。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Telegram => "telegram",
            Self::Wecom => "wecom",
            Self::Dingtalk => "dingtalk",
            Self::Feishu => "feishu",
        }
    }

    /// 解析稳定字符串；未知值返回 `None`（不静默降级）。
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "telegram" => Some(Self::Telegram),
            "wecom" => Some(Self::Wecom),
            "dingtalk" => Some(Self::Dingtalk),
            "feishu" => Some(Self::Feishu),
            _ => None,
        }
    }

    /// 该渠道的 secret 字段名（固定顺序）；只给字段名，不含值。
    pub fn secret_fields(self) -> &'static [&'static str] {
        match self {
            Self::Telegram => &["bot_token"],
            Self::Wecom => &["webhook_key"],
            Self::Dingtalk => &["access_token", "secret"],
            Self::Feishu => &["webhook_token", "secret"],
        }
    }
}

/// 敏感字符串。
///
/// - `Debug` 恒输出 `<redacted>`：结构体、错误与日志可以安全地 `{:?}`；
/// - `Serialize` / `Deserialize` 保留原文：只用于持久化到 SQLite 的
///   `config_json`，不得直接进 API 响应；
/// - [`Self::expose`] 只允许在真正构造 HTTP 请求（或计算签名）的地方调用。
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// 包装一个 sensitive 值。
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 取出原文。**只允许**在发送请求 / 计算签名的边界调用。
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// 原文字节长度；不暴露内容。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空；不暴露内容。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// 单个渠道的配置。
///
/// 序列化为 `{"kind": "...", ...}`，稳定且自描述；B2b 的 `config_json` 列直接
/// 存这个 JSON，加载时可用 `kind` 校验数据库列与配置是否一致。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ChannelConfig {
    /// Telegram：bot token 走 URL path，chat_id 走 JSON body。
    Telegram {
        /// Bot token（`<bot_id>:<secret>`）。
        bot_token: Secret,
        /// 目标会话 / 群 id。
        chat_id: String,
    },
    /// 企业微信群机器人：key 走 URL query。
    Wecom {
        /// Webhook key。
        webhook_key: Secret,
    },
    /// 钉钉自定义机器人：access_token 走 query，secret 用于加签。
    Dingtalk {
        /// 机器人 access_token。
        access_token: Secret,
        /// 加签 secret（以 `SEC` 开头的字符串）。
        secret: Secret,
    },
    /// 飞书自定义机器人：webhook token 走 URL path，secret 用于加签。
    Feishu {
        /// Webhook token。
        webhook_token: Secret,
        /// 加签 secret。
        secret: Secret,
    },
}

impl ChannelConfig {
    /// 配置对应的渠道类型。
    pub fn kind(&self) -> ChannelKind {
        match self {
            Self::Telegram { .. } => ChannelKind::Telegram,
            Self::Wecom { .. } => ChannelKind::Wecom,
            Self::Dingtalk { .. } => ChannelKind::Dingtalk,
            Self::Feishu { .. } => ChannelKind::Feishu,
        }
    }

    /// 该配置的 secret 字段名（固定顺序）。
    pub fn secret_fields(&self) -> &'static [&'static str] {
        self.kind().secret_fields()
    }

    /// 按渠道类型校验字段。
    ///
    /// 错误信息只描述字段与范围，不回显 token / secret 原文。
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Telegram { bot_token, chat_id } => {
                validate_url_token(
                    "Telegram bot_token",
                    bot_token,
                    MIN_TELEGRAM_BOT_TOKEN_BYTES,
                    MAX_TELEGRAM_BOT_TOKEN_BYTES,
                )?;
                validate_telegram_chat_id(chat_id)?;
            }
            Self::Wecom { webhook_key } => {
                validate_url_token(
                    "企业微信 webhook_key",
                    webhook_key,
                    MIN_WECOM_WEBHOOK_KEY_BYTES,
                    MAX_WECOM_WEBHOOK_KEY_BYTES,
                )?;
            }
            Self::Dingtalk {
                access_token,
                secret,
            } => {
                validate_url_token(
                    "钉钉 access_token",
                    access_token,
                    MIN_DINGTALK_ACCESS_TOKEN_BYTES,
                    MAX_DINGTALK_ACCESS_TOKEN_BYTES,
                )?;
                validate_hmac_secret(
                    "钉钉 secret",
                    secret,
                    MIN_DINGTALK_SECRET_BYTES,
                    MAX_DINGTALK_SECRET_BYTES,
                )?;
            }
            Self::Feishu {
                webhook_token,
                secret,
            } => {
                validate_url_token(
                    "飞书 webhook_token",
                    webhook_token,
                    MIN_FEISHU_WEBHOOK_TOKEN_BYTES,
                    MAX_FEISHU_WEBHOOK_TOKEN_BYTES,
                )?;
                validate_hmac_secret(
                    "飞书 secret",
                    secret,
                    MIN_FEISHU_SECRET_BYTES,
                    MAX_FEISHU_SECRET_BYTES,
                )?;
            }
        }
        Ok(())
    }
}

/// 一条通知渠道（`notification_channels` 表的一行，JSON 即完整存储结构）。
///
/// **序列化会包含 secret**，只用于写库；API 响应必须使用 [`Self::to_view`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NotificationChannel {
    /// 渠道 id（B2b 使用 UUID）。
    pub id: String,
    /// 渠道名称，1–64 字节，全局唯一。
    pub name: String,
    /// 渠道类型；必须与 `config.kind()` 一致。
    pub kind: ChannelKind,
    /// 渠道配置（含 secret）。
    pub config: ChannelConfig,
    /// 是否启用。
    pub enabled: bool,
    /// 最近更新者（旧 admin token 为 `"admin"`）。
    pub updated_by: String,
    /// 创建时间（Unix 毫秒）。
    pub created_at: i64,
    /// 更新时间（Unix 毫秒）。
    pub updated_at: i64,
}

impl NotificationChannel {
    /// 校验整条渠道：id / 名称 / 类型一致 / 配置范围。
    ///
    /// 错误信息不回显任何配置原文。
    pub fn validate(&self) -> Result<(), String> {
        crate::alerts::validate_channel_id(&self.id).map_err(|_| "渠道 id 格式非法".to_string())?;
        validate_channel_name(&self.name)?;
        if self.config.kind() != self.kind {
            return Err("渠道类型与配置不匹配".to_string());
        }
        self.config.validate()
    }

    /// 生成 API 视图：只含非敏感字段与已配置的 secret 字段名。
    pub fn to_view(&self) -> ChannelView {
        ChannelView {
            id: self.id.clone(),
            name: self.name.clone(),
            kind: self.kind,
            enabled: self.enabled,
            updated_by: self.updated_by.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            chat_id: match &self.config {
                ChannelConfig::Telegram { chat_id, .. } => Some(chat_id.clone()),
                _ => None,
            },
            secret_fields: self.config.secret_fields().to_vec(),
        }
    }
}

/// 通知渠道的 API 视图。
///
/// `chat_id` 是四家渠道里唯一的非敏感配置字段；`secret_fields` 只列出
/// 「配置了哪些 secret」，值永远不会出现在这里。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChannelView {
    /// 渠道 id。
    pub id: String,
    /// 渠道名称。
    pub name: String,
    /// 渠道类型。
    pub kind: ChannelKind,
    /// 是否启用。
    pub enabled: bool,
    /// 最近更新者。
    pub updated_by: String,
    /// 创建时间（Unix 毫秒）。
    pub created_at: i64,
    /// 更新时间（Unix 毫秒）。
    pub updated_at: i64,
    /// Telegram 的 chat_id；其他渠道为 `None`（JSON 中为 `null`）。
    pub chat_id: Option<String>,
    /// 已配置的 secret 字段名，固定顺序；不含值。
    pub secret_fields: Vec<&'static str>,
}

/// 渠道配置的部分更新输入（B2b 的 HTTP 层使用）。
///
/// 语义：
/// - secret 字段缺省 / `null` = 保留现有值；创建时必须由调用方保证已有值；
/// - 非 secret 字段（`chat_id`）缺省 / `null` = 保留现有值，创建时必填；
/// - 与渠道类型无关的字段非空即报错，避免把用户填错的 secret 静默丢弃；
/// - 不直接落库：先 [`Self::resolve`] 合并现有配置并做全量校验。
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelConfigInput {
    /// Telegram bot token；`None` = 保留。
    #[serde(default)]
    pub bot_token: Option<Secret>,
    /// Telegram chat_id；`None` = 保留。
    #[serde(default)]
    pub chat_id: Option<String>,
    /// 企业微信 key；`None` = 保留。
    #[serde(default)]
    pub webhook_key: Option<Secret>,
    /// 钉钉 access_token；`None` = 保留。
    #[serde(default)]
    pub access_token: Option<Secret>,
    /// 钉钉 / 飞书加签 secret；`None` = 保留。
    #[serde(default)]
    pub secret: Option<Secret>,
    /// 飞书 webhook token；`None` = 保留。
    #[serde(default)]
    pub webhook_token: Option<Secret>,
}

impl ChannelConfigInput {
    /// 合并现有配置并校验，返回可直接落库的完整配置。
    ///
    /// `existing` 为 `None` 表示创建；此时缺失的必填字段会报错。
    /// 调用方必须先校验 `kind` 不允许修改（更新时 `existing.kind()` 必须一致）。
    pub fn resolve(
        &self,
        kind: ChannelKind,
        existing: Option<&ChannelConfig>,
    ) -> Result<ChannelConfig, String> {
        self.reject_fields_for_other_kinds(kind)?;
        if let Some(existing) = existing {
            if existing.kind() != kind {
                return Err("渠道类型与现有配置不匹配".to_string());
            }
        }

        let config = match kind {
            ChannelKind::Telegram => ChannelConfig::Telegram {
                bot_token: self
                    .bot_token
                    .clone()
                    .or_else(|| existing.and_then(telegram_bot_token))
                    .ok_or_else(|| "Telegram 渠道缺少 bot_token".to_string())?,
                chat_id: self
                    .chat_id
                    .clone()
                    .or_else(|| existing.and_then(telegram_chat_id))
                    .ok_or_else(|| "Telegram 渠道缺少 chat_id".to_string())?,
            },
            ChannelKind::Wecom => ChannelConfig::Wecom {
                webhook_key: self
                    .webhook_key
                    .clone()
                    .or_else(|| existing.and_then(wecom_webhook_key))
                    .ok_or_else(|| "企业微信渠道缺少 webhook_key".to_string())?,
            },
            ChannelKind::Dingtalk => ChannelConfig::Dingtalk {
                access_token: self
                    .access_token
                    .clone()
                    .or_else(|| existing.and_then(dingtalk_access_token))
                    .ok_or_else(|| "钉钉渠道缺少 access_token".to_string())?,
                secret: self
                    .secret
                    .clone()
                    .or_else(|| existing.and_then(dingtalk_secret))
                    .ok_or_else(|| "钉钉渠道缺少 secret".to_string())?,
            },
            ChannelKind::Feishu => ChannelConfig::Feishu {
                webhook_token: self
                    .webhook_token
                    .clone()
                    .or_else(|| existing.and_then(feishu_webhook_token))
                    .ok_or_else(|| "飞书渠道缺少 webhook_token".to_string())?,
                secret: self
                    .secret
                    .clone()
                    .or_else(|| existing.and_then(feishu_secret))
                    .ok_or_else(|| "飞书渠道缺少 secret".to_string())?,
            },
        };
        config.validate()?;
        Ok(config)
    }

    /// 只允许出现当前 kind 的字段；多余字段很可能填错了渠道。
    fn reject_fields_for_other_kinds(&self, kind: ChannelKind) -> Result<(), String> {
        let mismatch = match kind {
            ChannelKind::Telegram => {
                self.webhook_key.is_some()
                    || self.access_token.is_some()
                    || self.secret.is_some()
                    || self.webhook_token.is_some()
            }
            ChannelKind::Wecom => {
                self.bot_token.is_some()
                    || self.chat_id.is_some()
                    || self.access_token.is_some()
                    || self.secret.is_some()
                    || self.webhook_token.is_some()
            }
            ChannelKind::Dingtalk => {
                self.bot_token.is_some()
                    || self.chat_id.is_some()
                    || self.webhook_key.is_some()
                    || self.webhook_token.is_some()
            }
            ChannelKind::Feishu => {
                self.bot_token.is_some()
                    || self.chat_id.is_some()
                    || self.webhook_key.is_some()
                    || self.access_token.is_some()
            }
        };
        if mismatch {
            return Err("渠道配置字段与渠道类型不匹配".to_string());
        }
        Ok(())
    }
}

fn telegram_bot_token(config: &ChannelConfig) -> Option<Secret> {
    match config {
        ChannelConfig::Telegram { bot_token, .. } => Some(bot_token.clone()),
        _ => None,
    }
}

fn telegram_chat_id(config: &ChannelConfig) -> Option<String> {
    match config {
        ChannelConfig::Telegram { chat_id, .. } => Some(chat_id.clone()),
        _ => None,
    }
}

fn wecom_webhook_key(config: &ChannelConfig) -> Option<Secret> {
    match config {
        ChannelConfig::Wecom { webhook_key } => Some(webhook_key.clone()),
        _ => None,
    }
}

fn dingtalk_access_token(config: &ChannelConfig) -> Option<Secret> {
    match config {
        ChannelConfig::Dingtalk { access_token, .. } => Some(access_token.clone()),
        _ => None,
    }
}

fn dingtalk_secret(config: &ChannelConfig) -> Option<Secret> {
    match config {
        ChannelConfig::Dingtalk { secret, .. } => Some(secret.clone()),
        _ => None,
    }
}

fn feishu_webhook_token(config: &ChannelConfig) -> Option<Secret> {
    match config {
        ChannelConfig::Feishu { webhook_token, .. } => Some(webhook_token.clone()),
        _ => None,
    }
}

fn feishu_secret(config: &ChannelConfig) -> Option<Secret> {
    match config {
        ChannelConfig::Feishu { secret, .. } => Some(secret.clone()),
        _ => None,
    }
}

/// 渠道名称校验：1–64 字节且不超过 64 字符，首尾无空白，不含控制字符。
///
/// 允许中文；错误信息不回显名称。
pub fn validate_channel_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("渠道名称不能为空".to_string());
    }
    if name.len() > MAX_CHANNEL_NAME_BYTES || name.chars().count() > MAX_CHANNEL_NAME_CHARS {
        return Err(format!(
            "渠道名称必须在 1–{MAX_CHANNEL_NAME_BYTES} 字节以内"
        ));
    }
    if name.trim() != name {
        return Err("渠道名称首尾不能有空白".to_string());
    }
    if name.chars().any(char::is_control) {
        return Err("渠道名称不能包含控制字符".to_string());
    }
    Ok(())
}

/// token 校验：长度 + URL 安全字符集（`[A-Za-z0-9._:-]`）。
///
/// 这些 token 会拼进固定端点的 path 或 query，字符集之外的字符（`/`、`?`、
/// `&`、`%`、空白等）一律拒绝，防止越出既定端点。
fn validate_url_token(label: &str, token: &Secret, min: usize, max: usize) -> Result<(), String> {
    if token.is_empty() || !(min..=max).contains(&token.len()) {
        return Err(format!("{label} 长度必须在 {min}–{max} 字节之间"));
    }
    if !token
        .0
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!("{label} 含非法字符"));
    }
    Ok(())
}

/// HMAC secret 校验：长度 + 拒绝控制字符。
///
/// secret 不进 URL，只作为 HMAC key，因此允许任意非控制字符（含非 ASCII）；
/// 换行等控制字符会破坏签名串结构，必须拒绝。
fn validate_hmac_secret(
    label: &str,
    secret: &Secret,
    min: usize,
    max: usize,
) -> Result<(), String> {
    if secret.is_empty() || !(min..=max).contains(&secret.len()) {
        return Err(format!("{label} 长度必须在 {min}–{max} 字节之间"));
    }
    if secret.0.chars().any(char::is_control) {
        return Err(format!("{label} 含非法字符"));
    }
    Ok(())
}

/// Telegram chat_id 校验：1–64 字节的 `[A-Za-z0-9_:-]`（与方案 §6.4 一致）。
fn validate_telegram_chat_id(chat_id: &str) -> Result<(), String> {
    if chat_id.is_empty()
        || chat_id.len() > MAX_TELEGRAM_CHAT_ID_BYTES
        || !chat_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b':' | b'-'))
    {
        return Err(format!(
            "Telegram chat_id 必须是 1–{MAX_TELEGRAM_CHAT_ID_BYTES} 个 [A-Za-z0-9_:-] 字符"
        ));
    }
    Ok(())
}

/// 通知文本校验：非空、≤ 2000 字节、除 `\n` / `\r` / `\t` 外不含控制字符。
pub fn validate_notification_text(text: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err("通知文本不能为空".to_string());
    }
    if text.len() > MAX_NOTIFICATION_TEXT_BYTES {
        return Err(format!(
            "通知文本不能超过 {MAX_NOTIFICATION_TEXT_BYTES} 字节"
        ));
    }
    if text
        .chars()
        .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
    {
        return Err("通知文本包含非法控制字符".to_string());
    }
    Ok(())
}

/// 生成通用通知文本：`【RustBoard】渠道：<name>\n<body>`。
///
/// 渠道名与 body 中的控制字符会被替换成空格，最终严格 ≤
/// [`MAX_NOTIFICATION_TEXT_BYTES`]（按 UTF-8 字符边界截断）。
pub fn render_text(channel_name: &str, body: &str) -> String {
    let channel = sanitize_inline(channel_name, MAX_CHANNEL_NAME_BYTES);
    let body = sanitize_body(body);
    truncate_notification_text(format!("【RustBoard】渠道：{channel}\n{body}"))
}

/// 固定测试消息；`/channels/{id}/test` 与 [`crate::channels::test_message`] 使用。
pub fn test_message(channel_name: &str) -> String {
    render_text(
        channel_name,
        "这是一条来自 RustBoard 的测试消息，收到即表示该渠道配置可用。",
    )
}

/// 用告警事件生成通知文本；B2b 发送告警时调用。
///
/// 只使用事件快照里的规则名、agent 与描述，不查询数据库，也不含任何 secret。
pub fn build_text(channel_name: &str, event: &AlertEvent) -> String {
    let state = match event.state {
        AlertStateKind::Firing => "触发",
        AlertStateKind::Resolved => "恢复",
        AlertStateKind::Pending => "状态更新",
    };
    let rule = sanitize_inline(&event.rule_name, MAX_CHANNEL_NAME_BYTES);
    let target = if event.agent_id.is_empty() {
        "全局".to_string()
    } else {
        format!(
            "agent {}",
            sanitize_inline(&event.agent_id, MAX_CHANNEL_NAME_BYTES)
        )
    };
    render_text(
        channel_name,
        &format!(
            "状态：{state}\n规则：{rule}\n对象：{target}\n详情：{}",
            event.message
        ),
    )
}

/// 行内字段净化：控制字符替换为空格，并按字节上限截断（保持 UTF-8 边界）。
fn sanitize_inline(value: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max_bytes));
    for ch in value.chars() {
        let ch = if ch.is_control() { ' ' } else { ch };
        if out.len() + ch.len_utf8() > max_bytes {
            break;
        }
        out.push(ch);
    }
    out
}

/// 正文净化：允许换行 / 回车 / 制表符，其他控制字符替换为空格。
fn sanitize_body(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                ' '
            } else {
                ch
            }
        })
        .collect()
}

/// 严格按 UTF-8 字符边界截断到 [`MAX_NOTIFICATION_TEXT_BYTES`]，追加省略号。
fn truncate_notification_text(mut text: String) -> String {
    if text.len() <= MAX_NOTIFICATION_TEXT_BYTES {
        return text;
    }
    let ellipsis = '…';
    let budget = MAX_NOTIFICATION_TEXT_BYTES - ellipsis.len_utf8();
    let mut boundary = budget;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    text.truncate(boundary);
    text.push(ellipsis);
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TELEGRAM_TOKEN: &str = "123456789:AAH_test-token_0123456789";
    const TELEGRAM_CHAT_ID: &str = "-1001234567890";
    const WECOM_KEY: &str = "00000000-1111-2222-3333-444444444444";
    const DINGTALK_TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const DINGTALK_SECRET: &str = "SEC0123456789abcdef0123456789abcdef";
    const FEISHU_TOKEN: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const FEISHU_SECRET: &str = "feishu-secret-0123456789";

    fn telegram_config() -> ChannelConfig {
        ChannelConfig::Telegram {
            bot_token: Secret::new(TELEGRAM_TOKEN),
            chat_id: TELEGRAM_CHAT_ID.to_string(),
        }
    }

    fn wecom_config() -> ChannelConfig {
        ChannelConfig::Wecom {
            webhook_key: Secret::new(WECOM_KEY),
        }
    }

    fn dingtalk_config() -> ChannelConfig {
        ChannelConfig::Dingtalk {
            access_token: Secret::new(DINGTALK_TOKEN),
            secret: Secret::new(DINGTALK_SECRET),
        }
    }

    fn feishu_config() -> ChannelConfig {
        ChannelConfig::Feishu {
            webhook_token: Secret::new(FEISHU_TOKEN),
            secret: Secret::new(FEISHU_SECRET),
        }
    }

    fn channel(kind: ChannelKind, config: ChannelConfig) -> NotificationChannel {
        NotificationChannel {
            id: "0b6f9a2e-6a1d-4c5e-9f3a-1d2c3b4a5e6f".to_string(),
            name: "运维通知".to_string(),
            kind,
            config,
            enabled: true,
            updated_by: "admin".to_string(),
            created_at: 1_700_000_000_000,
            updated_at: 1_700_000_001_000,
        }
    }

    fn event(state: AlertStateKind) -> AlertEvent {
        AlertEvent {
            id: 7,
            ts: 1_700_000_000_000,
            rule_id: "rule-1".to_string(),
            rule_name: "磁盘告警".to_string(),
            agent_id: "agent-1".to_string(),
            state,
            value: Some(91.5),
            message: "agent agent-1 指标「disk.used_percent」当前值 91.5，阈值 >= 90".to_string(),
            notified: false,
            notify_error: String::new(),
            silenced: false,
        }
    }

    #[test]
    fn m4_b2a_channel_kind_strings_are_stable() {
        for kind in ChannelKind::ALL {
            let text = serde_json::to_string(&kind).unwrap();
            assert_eq!(text, format!("\"{}\"", kind.as_str()));
            assert_eq!(ChannelKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(ChannelKind::parse("Telegram"), None);
        assert_eq!(ChannelKind::parse(""), None);
        assert_eq!(ChannelKind::parse("unknown"), None);
    }

    #[test]
    fn m4_b2a_secret_debug_is_redacted_but_serde_keeps_value() {
        let secret = Secret::new("super-secret-value");
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("super-secret-value"));
        assert_eq!(
            serde_json::to_string(&secret).unwrap(),
            "\"super-secret-value\""
        );

        let config = telegram_config();
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(TELEGRAM_TOKEN));

        let channel = channel(ChannelKind::Telegram, config);
        let debug = format!("{channel:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(TELEGRAM_TOKEN));
    }

    #[test]
    fn m4_b2a_channel_config_json_roundtrips_all_kinds() {
        let cases = [
            (
                telegram_config(),
                json!({
                    "kind": "telegram",
                    "bot_token": TELEGRAM_TOKEN,
                    "chat_id": TELEGRAM_CHAT_ID
                }),
            ),
            (
                wecom_config(),
                json!({"kind": "wecom", "webhook_key": WECOM_KEY}),
            ),
            (
                dingtalk_config(),
                json!({
                    "kind": "dingtalk",
                    "access_token": DINGTALK_TOKEN,
                    "secret": DINGTALK_SECRET
                }),
            ),
            (
                feishu_config(),
                json!({
                    "kind": "feishu",
                    "webhook_token": FEISHU_TOKEN,
                    "secret": FEISHU_SECRET
                }),
            ),
        ];
        for (config, expected) in cases {
            let value = serde_json::to_value(&config).unwrap();
            assert_eq!(value, expected);
            let back: ChannelConfig = serde_json::from_value(value).unwrap();
            assert_eq!(back, config);
        }

        let back: NotificationChannel = serde_json::from_value(json!({
            "id": "0b6f9a2e-6a1d-4c5e-9f3a-1d2c3b4a5e6f",
            "name": "运维通知",
            "kind": "telegram",
            "config": {"kind": "telegram", "bot_token": TELEGRAM_TOKEN, "chat_id": TELEGRAM_CHAT_ID},
            "enabled": true,
            "updated_by": "admin",
            "created_at": 1_700_000_000_000i64,
            "updated_at": 1_700_000_001_000i64
        }))
        .unwrap();
        assert_eq!(back, channel(ChannelKind::Telegram, telegram_config()));
    }

    #[test]
    fn m4_b2a_channel_name_bounds_and_control_chars() {
        validate_channel_name("运维通知").unwrap();
        validate_channel_name(&"a".repeat(MAX_CHANNEL_NAME_BYTES)).unwrap();
        assert!(validate_channel_name("").is_err());
        assert!(validate_channel_name(&"a".repeat(MAX_CHANNEL_NAME_BYTES + 1)).is_err());
        assert!(validate_channel_name(" lead").is_err());
        assert!(validate_channel_name("trail ").is_err());
        assert!(validate_channel_name("line\nbreak").is_err());
        assert!(validate_channel_name("nul\0byte").is_err());
        // 多字节字符：63 字节可以，66 字节超限（字符数本身没超）。
        assert!(validate_channel_name(&"中".repeat(21)).is_ok());
        assert!(validate_channel_name(&"中".repeat(22)).is_err());
    }

    #[test]
    fn m4_b2a_telegram_field_bounds() {
        validate_channel_name("x").unwrap();
        telegram_config().validate().unwrap();

        for len in [
            MIN_TELEGRAM_BOT_TOKEN_BYTES - 1,
            MAX_TELEGRAM_BOT_TOKEN_BYTES + 1,
        ] {
            let config = ChannelConfig::Telegram {
                bot_token: Secret::new("a".repeat(len)),
                chat_id: TELEGRAM_CHAT_ID.to_string(),
            };
            assert!(config.validate().is_err(), "token 长度 {len} 必须被拒");
        }
        for token in [
            "bad/token-with-enough-length",
            "bad?token-with-enough-length",
            "bad token-with-enough-length",
            "bad\ntoken-with-enough-length",
        ] {
            let config = ChannelConfig::Telegram {
                bot_token: Secret::new(token),
                chat_id: TELEGRAM_CHAT_ID.to_string(),
            };
            assert!(config.validate().is_err(), "非法 token 字符必须被拒");
        }
        let with_chat_id = |chat_id: &str| ChannelConfig::Telegram {
            bot_token: Secret::new(TELEGRAM_TOKEN),
            chat_id: chat_id.to_string(),
        };
        with_chat_id(&"a".repeat(MAX_TELEGRAM_CHAT_ID_BYTES))
            .validate()
            .unwrap();
        assert!(with_chat_id("").validate().is_err());
        assert!(with_chat_id(&"a".repeat(MAX_TELEGRAM_CHAT_ID_BYTES + 1))
            .validate()
            .is_err());
        assert!(with_chat_id("bad id").validate().is_err());
        assert!(with_chat_id("bad/id").validate().is_err());
        assert!(with_chat_id("bad\nid").validate().is_err());
    }

    #[test]
    fn m4_b2a_wecom_and_dingtalk_field_bounds() {
        wecom_config().validate().unwrap();
        for len in [
            MIN_WECOM_WEBHOOK_KEY_BYTES - 1,
            MAX_WECOM_WEBHOOK_KEY_BYTES + 1,
        ] {
            let config = ChannelConfig::Wecom {
                webhook_key: Secret::new("a".repeat(len)),
            };
            assert!(config.validate().is_err(), "wecom key 长度 {len} 必须被拒");
        }
        let config = ChannelConfig::Wecom {
            webhook_key: Secret::new("bad&key=with-enough-length"),
        };
        assert!(config.validate().is_err(), "wecom key 不能越出 query");

        dingtalk_config().validate().unwrap();
        for len in [
            MIN_DINGTALK_ACCESS_TOKEN_BYTES - 1,
            MAX_DINGTALK_ACCESS_TOKEN_BYTES + 1,
        ] {
            let config = ChannelConfig::Dingtalk {
                access_token: Secret::new("a".repeat(len)),
                secret: Secret::new(DINGTALK_SECRET),
            };
            assert!(config.validate().is_err(), "钉钉 token 长度 {len} 必须被拒");
        }
        for len in [MIN_DINGTALK_SECRET_BYTES - 1, MAX_DINGTALK_SECRET_BYTES + 1] {
            let config = ChannelConfig::Dingtalk {
                access_token: Secret::new(DINGTALK_TOKEN),
                secret: Secret::new("a".repeat(len)),
            };
            assert!(
                config.validate().is_err(),
                "钉钉 secret 长度 {len} 必须被拒"
            );
        }
        let config = ChannelConfig::Dingtalk {
            access_token: Secret::new(DINGTALK_TOKEN),
            secret: Secret::new("SEC0123456789\nabcdef0123456789abcdef"),
        };
        assert!(config.validate().is_err(), "secret 不能含控制字符");
    }

    #[test]
    fn m4_b2a_feishu_field_bounds() {
        feishu_config().validate().unwrap();
        for len in [
            MIN_FEISHU_WEBHOOK_TOKEN_BYTES - 1,
            MAX_FEISHU_WEBHOOK_TOKEN_BYTES + 1,
        ] {
            let config = ChannelConfig::Feishu {
                webhook_token: Secret::new("a".repeat(len)),
                secret: Secret::new(FEISHU_SECRET),
            };
            assert!(config.validate().is_err(), "飞书 token 长度 {len} 必须被拒");
        }
        for len in [MIN_FEISHU_SECRET_BYTES - 1, MAX_FEISHU_SECRET_BYTES + 1] {
            let config = ChannelConfig::Feishu {
                webhook_token: Secret::new(FEISHU_TOKEN),
                secret: Secret::new("a".repeat(len)),
            };
            assert!(
                config.validate().is_err(),
                "飞书 secret 长度 {len} 必须被拒"
            );
        }
        let config = ChannelConfig::Feishu {
            webhook_token: Secret::new(FEISHU_TOKEN),
            secret: Secret::new("feishu\tsecret-0123456789"),
        };
        assert!(config.validate().is_err(), "secret 不能含控制字符");
    }

    #[test]
    fn m4_b2a_config_input_resolves_partial_updates() {
        let existing = telegram_config();
        let input: ChannelConfigInput =
            serde_json::from_str(r#"{"chat_id":"-1009999999999"}"#).unwrap();
        assert_eq!(
            input
                .resolve(ChannelKind::Telegram, Some(&existing))
                .unwrap(),
            ChannelConfig::Telegram {
                bot_token: Secret::new(TELEGRAM_TOKEN),
                chat_id: "-1009999999999".to_string(),
            }
        );

        // null = 保留，不是清空。
        let input: ChannelConfigInput =
            serde_json::from_str(r#"{"bot_token":null,"chat_id":null}"#).unwrap();
        assert_eq!(
            input
                .resolve(ChannelKind::Telegram, Some(&existing))
                .unwrap(),
            existing
        );

        // 新 secret 覆盖旧值。
        let input = ChannelConfigInput {
            bot_token: Some(Secret::new("123456789:AAH_new-token_0123456789")),
            ..ChannelConfigInput::default()
        };
        match input
            .resolve(ChannelKind::Telegram, Some(&existing))
            .unwrap()
        {
            ChannelConfig::Telegram { bot_token, .. } => {
                assert_eq!(bot_token, Secret::new("123456789:AAH_new-token_0123456789"));
            }
            other => panic!("配置类型错误: {other:?}"),
        }

        // 创建时缺字段必须报错。
        assert!(ChannelConfigInput::default()
            .resolve(ChannelKind::Telegram, None)
            .is_err());
        let input = ChannelConfigInput {
            bot_token: Some(Secret::new(TELEGRAM_TOKEN)),
            ..ChannelConfigInput::default()
        };
        assert!(input.resolve(ChannelKind::Telegram, None).is_err());
        assert!(input
            .resolve(ChannelKind::Wecom, Some(&wecom_config()))
            .is_err());
        assert!(input
            .resolve(ChannelKind::Telegram, Some(&wecom_config()))
            .is_err());
    }

    #[test]
    fn m4_b2a_config_input_rejects_mismatched_fields() {
        let input = ChannelConfigInput {
            bot_token: Some(Secret::new(TELEGRAM_TOKEN)),
            chat_id: Some(TELEGRAM_CHAT_ID.to_string()),
            webhook_key: Some(Secret::new(WECOM_KEY)),
            ..ChannelConfigInput::default()
        };
        let err = input
            .resolve(ChannelKind::Telegram, None)
            .expect_err("多余字段必须被拒");
        assert!(!err.contains(TELEGRAM_TOKEN));
        assert!(!err.contains(WECOM_KEY));

        let input = ChannelConfigInput {
            bot_token: Some(Secret::new(TELEGRAM_TOKEN)),
            ..ChannelConfigInput::default()
        };
        assert!(input.resolve(ChannelKind::Wecom, None).is_err());

        // 未知字段直接反序列化失败（HTTP 层会映射 400）。
        assert!(serde_json::from_str::<ChannelConfigInput>(r#"{"unknown_field":"x"}"#).is_err());
    }

    #[test]
    fn m4_b2a_channel_view_never_contains_secrets() {
        let telegram = channel(ChannelKind::Telegram, telegram_config()).to_view();
        assert_eq!(telegram.chat_id.as_deref(), Some(TELEGRAM_CHAT_ID));
        assert_eq!(telegram.secret_fields, vec!["bot_token"]);

        let dingtalk = channel(ChannelKind::Dingtalk, dingtalk_config()).to_view();
        assert_eq!(dingtalk.chat_id, None);
        assert_eq!(dingtalk.secret_fields, vec!["access_token", "secret"]);

        let feishu = channel(ChannelKind::Feishu, feishu_config()).to_view();
        assert_eq!(feishu.secret_fields, vec!["webhook_token", "secret"]);

        let wecom = channel(ChannelKind::Wecom, wecom_config()).to_view();
        assert_eq!(wecom.secret_fields, vec!["webhook_key"]);

        let encoded = serde_json::to_string(&telegram).unwrap();
        assert!(!encoded.contains(TELEGRAM_TOKEN));
        assert!(encoded.contains("secret_fields"));

        let encoded = serde_json::to_string(&dingtalk).unwrap();
        assert!(!encoded.contains(DINGTALK_TOKEN));
        assert!(!encoded.contains(DINGTALK_SECRET));
    }

    #[test]
    fn m4_b2a_notification_channel_validation_and_kind_mismatch() {
        let channel = channel(ChannelKind::Telegram, telegram_config());
        channel.validate().unwrap();

        let mut wrong_kind = channel.clone();
        wrong_kind.kind = ChannelKind::Wecom;
        assert!(wrong_kind.validate().is_err());

        let mut bad_name = channel.clone();
        bad_name.name = "bad\nname".to_string();
        assert!(bad_name.validate().is_err());

        let mut bad_id = channel;
        bad_id.id = "../escape".to_string();
        assert!(bad_id.validate().is_err());
    }

    #[test]
    fn m4_b2a_notification_text_validation_and_truncation() {
        validate_notification_text("第一行\n第二行").unwrap();
        assert!(validate_notification_text("").is_err());
        assert!(validate_notification_text(&"a".repeat(MAX_NOTIFICATION_TEXT_BYTES + 1)).is_err());
        assert!(validate_notification_text("nul\0byte").is_err());

        let text = test_message("运维群");
        assert!(text.contains("运维群"));
        assert!(text.contains("测试消息"));
        assert!(text.len() <= MAX_NOTIFICATION_TEXT_BYTES);
        validate_notification_text(&text).unwrap();

        // 多字节字符截断不能切坏 UTF-8。
        let long = "中".repeat(MAX_NOTIFICATION_TEXT_BYTES);
        let rendered = render_text("运维群", &long);
        assert!(rendered.len() <= MAX_NOTIFICATION_TEXT_BYTES);
        assert!(rendered.ends_with('…'));
        validate_notification_text(&rendered).unwrap();
        assert!(rendered.is_char_boundary(rendered.len()));

        // 头部字段里的控制字符被替换，不会伪造新行。
        let rendered = render_text("a\nb", "body");
        assert!(!rendered.contains("a\nb"));
    }

    #[test]
    fn m4_b2a_build_text_contains_event_snapshot() {
        let text = build_text("运维群", &event(AlertStateKind::Firing));
        assert!(text.contains("状态：触发"));
        assert!(text.contains("规则：磁盘告警"));
        assert!(text.contains("agent agent-1"));
        assert!(text.contains("disk.used_percent"));
        validate_notification_text(&text).unwrap();

        let resolved = build_text("运维群", &event(AlertStateKind::Resolved));
        assert!(resolved.contains("状态：恢复"));

        let mut global = event(AlertStateKind::Firing);
        global.agent_id.clear();
        let text = build_text("运维群", &global);
        assert!(text.contains("对象：全局"));
    }
}
