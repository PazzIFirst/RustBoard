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
///
/// `Debug` 是手写的，只输出变体名：`Hello`/`Enroll`/`Enrolled` 里带
/// secret、token 与 CSR，一旦被 `tracing::debug!(?frame)` 打出来就是泄露。
#[derive(Clone, Serialize, Deserialize)]
pub enum Frame {
    Enroll(EnrollRequest),
    Enrolled(EnrollResponse),
    Hello(AgentHello),
    Welcome(Welcome),
    Batch(crate::model::SampleBatch),
    /// 确认某个 epoch 下 `seq`（含）之前的批次；epoch 必须与批次自身一致。
    Ack {
        epoch: u64,
        seq: u64,
    },
    Ping {
        ts: i64,
    },
    Pong {
        ts: i64,
    },
    Problem {
        code: String,
        message: String,
    },
}

impl Frame {
    /// 变体名，用于日志；不包含任何字段值。
    pub fn kind(&self) -> &'static str {
        match self {
            Frame::Enroll(_) => "Enroll",
            Frame::Enrolled(_) => "Enrolled",
            Frame::Hello(_) => "Hello",
            Frame::Welcome(_) => "Welcome",
            Frame::Batch(_) => "Batch",
            Frame::Ack { .. } => "Ack",
            Frame::Ping { .. } => "Ping",
            Frame::Pong { .. } => "Pong",
            Frame::Problem { .. } => "Problem",
        }
    }

    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        Ok(rmp_serde::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> crate::Result<Self> {
        Ok(rmp_serde::from_slice(bytes)?)
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.kind())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_3_ack_roundtrip_carries_epoch() {
        let frame = Frame::Ack { epoch: 7, seq: 42 };
        let bytes = frame.encode().unwrap();
        match Frame::decode(&bytes).unwrap() {
            Frame::Ack { epoch, seq } => {
                assert_eq!(epoch, 7);
                assert_eq!(seq, 42);
            }
            other => panic!("解码出意外帧: {other:?}"),
        }
    }

    /// L6：Debug 只输出变体名，不能把 Hello/Enroll/Enrolled 里的凭据打进日志。
    #[test]
    fn l6_frame_debug_never_prints_secrets() {
        let hello = Frame::Hello(AgentHello {
            agent_id: "a1".into(),
            name: "n".into(),
            hostname: "h".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "0.1.0".into(),
            protocol: crate::PROTOCOL_VERSION,
            boot_id: "b".into(),
            epoch: 1,
            secret: "hello-secret-value".into(),
            capabilities: Vec::new(),
        });
        let enroll = Frame::Enroll(EnrollRequest {
            token: "enroll-token-value".into(),
            csr_pem: "csr-private-material".into(),
            requested_name: "n".into(),
            hostname: "h".into(),
            protocol: crate::PROTOCOL_VERSION,
        });
        let enrolled = Frame::Enrolled(EnrollResponse {
            agent_id: "a1".into(),
            agent_secret: "agent-secret-value".into(),
            cert_pem: "cert".into(),
            ca_pem: "ca".into(),
        });

        for frame in [hello, enroll, enrolled] {
            let text = format!("{frame:?}");
            assert_eq!(text, frame.kind());
            for leaked in [
                "hello-secret-value",
                "enroll-token-value",
                "csr-private-material",
                "agent-secret-value",
            ] {
                assert!(!text.contains(leaked), "Debug 泄露了 {leaked}: {text}");
            }
        }
    }
}
