use serde::{Deserialize, Serialize};

/// agent 建立连接后发送的第一帧。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentHello {
    pub agent_id: String,
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub protocol: u16,
    pub boot_id: String,
    pub epoch: u64,
    /// enrollment 时由 hub 下发、每台机器独立的密钥，用于身份绑定。
    pub secret: String,
    /// 已启用的控制面能力，空表示纯采集。
    pub capabilities: Vec<String>,
}

/// hub 对 Hello 的应答。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Welcome {
    pub agent_id: String,
    pub server_version: String,
    pub protocol: u16,
    /// hub 下发（或确认）的采样间隔，agent 应以此覆盖本地配置。
    pub sample_interval_ms: u64,
    pub server_time: i64,
}

/// 首次接入：agent 用一次性 token 换客户端证书。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub token: String,
    pub csr_pem: String,
    pub requested_name: String,
    pub hostname: String,
    pub protocol: u16,
}

/// enrollment 成功后的应答。`agent_secret` 只在这里出现一次，agent 必须落盘。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub agent_id: String,
    pub agent_secret: String,
    pub cert_pem: String,
    pub ca_pem: String,
}

/// 线协议帧。
///
/// 使用外部标签枚举（`{"Batch": {...}}`）而不是 `#[serde(tag)]`：
/// MessagePack 不是自描述格式，内部标签需要 `deserialize_any`，rmp-serde 不支持。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Frame {
    Enroll(EnrollRequest),
    Enrolled(EnrollResponse),
    Hello(AgentHello),
    Welcome(Welcome),
    Batch(crate::model::SampleBatch),
    Ack { seq: u64 },
    Ping { ts: i64 },
    Pong { ts: i64 },
    Problem { code: String, message: String },
}

impl Frame {
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        Ok(rmp_serde::from_slice(bytes)?)
    }
}

/// 错误码常量，避免字符串散落。
pub mod codes {
    pub const BAD_TOKEN: &str = "bad_token";
    pub const BAD_PROTOCOL: &str = "bad_protocol";
    pub const BAD_FRAME: &str = "bad_frame";
    pub const REVOKED: &str = "revoked";
    pub const ENROLL_DENIED: &str = "enroll_denied";
    pub const INTERNAL: &str = "internal";
    pub const UNSUPPORTED: &str = "unsupported";
}
