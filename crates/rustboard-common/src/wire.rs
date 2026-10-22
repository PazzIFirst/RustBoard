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
/// `RenewCert`/`CertRenewed` 同样按变体名处理，避免证书与 CSR 内容进日志。
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
    /// agent → hub：用当前私钥换一张新客户端证书（只在已认证会话内发送）。
    ///
    /// 旧 hub 收到未知变体会走「解码失败、跳过」分支，不会因此断开会话；
    /// 旧 agent 永远不会发送这一帧，因此协议版本保持 v2 不变。
    RenewCert {
        csr_pem: String,
    },
    /// hub → agent：客户端证书续签结果。
    CertRenewed {
        cert_pem: String,
    },
    /// hub → agent：一次控制面请求（只在已认证会话、能力协商之后发送）。
    ///
    /// 旧 agent 收到未知变体会走「解码失败、跳过」分支，不会因此断开会话；
    /// 旧 hub 永远不会发送这一帧，因此协议版本保持 v2 不变。
    ControlRequest(crate::control::ControlRequest),
    /// agent → hub：控制面请求的应答。
    ControlResponse(crate::control::ControlResponse),
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
            Frame::RenewCert { .. } => "RenewCert",
            Frame::CertRenewed { .. } => "CertRenewed",
            Frame::ControlRequest(_) => "ControlRequest",
            Frame::ControlResponse(_) => "ControlResponse",
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
    /// 同一会话内重复发起证书续签：拒绝但**不关闭连接**。
    pub const RATE_LIMITED: &str = "rate_limited";
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

    /// A6：新增的续签帧必须能完整往返，且不改变其他帧的解码行为。
    #[test]
    fn a6_renew_frames_roundtrip() {
        let renew = Frame::RenewCert {
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\ncsr\n".to_string(),
        };
        let bytes = renew.encode().unwrap();
        match Frame::decode(&bytes).unwrap() {
            Frame::RenewCert { csr_pem } => {
                assert_eq!(csr_pem, "-----BEGIN CERTIFICATE REQUEST-----\ncsr\n");
            }
            other => panic!("解码出意外帧: {other:?}"),
        }

        let renewed = Frame::CertRenewed {
            cert_pem: "-----BEGIN CERTIFICATE-----\ncert\n".to_string(),
        };
        let bytes = renewed.encode().unwrap();
        match Frame::decode(&bytes).unwrap() {
            Frame::CertRenewed { cert_pem } => {
                assert_eq!(cert_pem, "-----BEGIN CERTIFICATE-----\ncert\n");
            }
            other => panic!("解码出意外帧: {other:?}"),
        }

        assert_eq!(renew.kind(), "RenewCert");
        assert_eq!(renewed.kind(), "CertRenewed");
    }

    /// A6：续签帧的 Debug 同样只输出变体名，CSR / 证书内容不能进日志。
    #[test]
    fn a6_renew_frames_debug_never_prints_material() {
        let renew = Frame::RenewCert {
            csr_pem: "csr-private-material".to_string(),
        };
        let renewed = Frame::CertRenewed {
            cert_pem: "cert-material".to_string(),
        };
        for frame in [renew, renewed] {
            let text = format!("{frame:?}");
            assert_eq!(text, frame.kind());
            assert!(!text.contains("csr-private-material"));
            assert!(!text.contains("cert-material"));
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

    fn control_ops() -> Vec<crate::control::ControlOp> {
        use crate::control::{ControlOp, DockerAction, KillSignal, SystemdAction};
        vec![
            ControlOp::SystemdList,
            ControlOp::SystemdAction {
                unit: "nginx.service".to_string(),
                action: SystemdAction::Restart,
            },
            ControlOp::DockerList,
            ControlOp::DockerAction {
                container: "web-1".to_string(),
                action: DockerAction::Stop,
            },
            ControlOp::ProcessList,
            ControlOp::ProcessKill {
                pid: 4242,
                name: "nginx".to_string(),
                signal: KillSignal::Term,
            },
            ControlOp::LogList,
            ControlOp::LogTail {
                source: "nginx-error".to_string(),
                lines: 200,
            },
        ]
    }

    /// M3：每一种控制操作都必须能完整往返；协议版本保持 2。
    #[test]
    fn m3_control_request_roundtrip_all_ops() {
        assert_eq!(crate::PROTOCOL_VERSION, 2);
        for (id, op) in control_ops().into_iter().enumerate() {
            let frame = Frame::ControlRequest(crate::control::ControlRequest {
                id: id as u64,
                op: op.clone(),
            });
            let bytes = frame.encode().unwrap();
            let decoded = Frame::decode(&bytes).unwrap();
            assert_eq!(decoded.kind(), "ControlRequest");
            match decoded {
                Frame::ControlRequest(request) => {
                    assert_eq!(request.id, id as u64);
                    assert_eq!(request.op, op);
                }
                other => panic!("解码出意外帧: {other:?}"),
            }
        }
    }

    /// M3：成功与错误两类应答都能往返，且 kind() 正确。
    #[test]
    fn m3_control_response_roundtrip_and_kind() {
        use crate::config::LogSourceKind;
        use crate::control::{
            ControlError, ControlResponse, ControlResult, DockerContainer, LogSourceInfo,
            ProcessInfo, SystemdUnit,
        };

        let responses = vec![
            ControlResponse::success(
                1,
                ControlResult::SystemdUnits(vec![SystemdUnit {
                    unit: "nginx.service".into(),
                    load: "loaded".into(),
                    active: "active".into(),
                    sub: "running".into(),
                    description: "Nginx".into(),
                }]),
            ),
            ControlResponse::success(
                2,
                ControlResult::DockerContainers(vec![DockerContainer {
                    name: "web-1".into(),
                    image: "nginx:latest".into(),
                    state: "running".into(),
                    status: "Up 1 hour".into(),
                    id: "abc123".into(),
                }]),
            ),
            ControlResponse::success(
                3,
                ControlResult::Processes(vec![ProcessInfo {
                    pid: 42,
                    name: "nginx".into(),
                    cmdline: "nginx -g daemon off;".into(),
                    uid: 0,
                    rss_kb: 1024,
                }]),
            ),
            ControlResponse::success(
                4,
                ControlResult::LogSources(vec![LogSourceInfo {
                    id: "nginx-error".into(),
                    kind: LogSourceKind::File,
                    target: "/var/log/nginx/error.log".into(),
                    name: "Nginx 错误日志".into(),
                }]),
            ),
            ControlResponse::success(
                5,
                ControlResult::LogLines {
                    source: "nginx-error".into(),
                    lines: vec!["line1".into(), "line2".into()],
                    truncated: true,
                    size_bytes: 123,
                },
            ),
            ControlResponse::success(
                6,
                ControlResult::ActionOutput {
                    stdout: "ok".into(),
                    stderr: "warn".into(),
                    exit_code: Some(0),
                },
            ),
            ControlResponse::failure(7, ControlError::not_whitelisted("unit 不在白名单")),
        ];

        for response in responses {
            let frame = Frame::ControlResponse(response.clone());
            let bytes = frame.encode().unwrap();
            assert_eq!(Frame::decode(&bytes).unwrap().kind(), "ControlResponse");
            match Frame::decode(&bytes).unwrap() {
                Frame::ControlResponse(decoded) => assert_eq!(decoded, response),
                other => panic!("解码出意外帧: {other:?}"),
            }
        }
    }

    /// M3：控制帧的 Debug 不打印命令输出、日志行、错误详情与目标参数。
    #[test]
    fn m3_control_debug_redacts_payloads() {
        use crate::control::{ControlError, ControlOp, ControlResponse, ControlResult};

        let op = ControlOp::SystemdAction {
            unit: "secret-unit.service".into(),
            action: crate::control::SystemdAction::Restart,
        };
        let request = crate::control::ControlRequest { id: 11, op };
        let request_text = format!("{request:?}");
        assert!(request_text.contains("11"), "应保留 id: {request_text}");
        assert!(
            request_text.contains("SystemdAction"),
            "应保留变体名: {request_text}"
        );
        assert!(
            !request_text.contains("secret-unit.service"),
            "不得打印目标: {request_text}"
        );
        assert_eq!(format!("{:?}", request.op), "SystemdAction");

        let result = ControlResult::ActionOutput {
            stdout: "stdout-secret".into(),
            stderr: "stderr-secret".into(),
            exit_code: Some(1),
        };
        let result_text = format!("{result:?}");
        assert_eq!(result_text, "ActionOutput");
        assert!(!result_text.contains("secret"));

        let lines = ControlResult::LogLines {
            source: "secret-source".into(),
            lines: vec!["log-secret".into()],
            truncated: false,
            size_bytes: 1,
        };
        let lines_text = format!("{lines:?}");
        assert_eq!(lines_text, "LogLines");
        assert!(!lines_text.contains("secret"));

        let error = ControlError::control_failed("stderr-secret-detail");
        let error_text = format!("{error:?}");
        assert!(error_text.contains("control_failed"));
        assert!(!error_text.contains("stderr-secret-detail"));

        let response = ControlResponse {
            id: 12,
            result: None,
            error: Some(error),
        };
        let response_text = format!("{response:?}");
        assert!(response_text.contains("12"));
        assert!(response_text.contains("control_failed"));
        assert!(!response_text.contains("stderr-secret-detail"));

        let frame = Frame::ControlRequest(crate::control::ControlRequest {
            id: 13,
            op: ControlOp::ProcessKill {
                pid: 99,
                name: "process-secret".into(),
                signal: crate::control::KillSignal::Kill,
            },
        });
        assert_eq!(format!("{frame:?}"), "ControlRequest");
    }
}
