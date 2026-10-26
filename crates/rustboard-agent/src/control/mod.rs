//! M3 agent 控制面：能力计算、入口二次校验、按操作分发。
//!
//! 纵深防御：即便 hub 已经按 Hello capabilities 过滤过，agent 在执行入口仍会
//! 按本地 `[control]` 配置重新校验能力、白名单与参数。配置不信任 hub。

pub mod docker;
pub mod exec;
pub mod logs;
pub mod process;
pub mod systemd;

use std::sync::Arc;
use std::time::Duration;

use rustboard_common::config::ControlConfig;
use rustboard_common::control::{
    self, ControlError, ControlOp, ControlRequest, ControlResponse, ControlResult,
    MAX_CONTROL_RESPONSE_BYTES, MAX_LOG_LINES,
};
use rustboard_common::wire::Frame;
use tokio::sync::{mpsc, Semaphore};

/// 单个会话最多同时执行的控制操作数；超限立即回错误，避免无限 spawn。
const MAX_CONCURRENT_CONTROL: usize = 4;
/// 应答通道容量；满了以后控制任务会等待会话消费。
const CONTROL_RESPONSE_BUFFER: usize = 8;
/// 外层超时相对单条命令超时的余量（进程扫描 / 日志解析等）。
const CONTROL_TIMEOUT_GRACE_SECS: u64 = 5;

/// 实际启用的控制能力，按固定顺序返回；总开关关闭时永远为空。
pub fn enabled_capabilities(cfg: &ControlConfig) -> Vec<String> {
    if !cfg.enabled {
        return Vec::new();
    }
    let mut capabilities = Vec::new();
    if cfg.systemd {
        capabilities.push(control::CAP_SYSTEMD.to_string());
    }
    if cfg.docker {
        capabilities.push(control::CAP_DOCKER.to_string());
    }
    if cfg.process {
        capabilities.push(control::CAP_PROCESS.to_string());
    }
    if cfg.logs {
        capabilities.push(control::CAP_LOGS.to_string());
    }
    capabilities
}

/// 启动时的控制配置 I/O 预检：只校验已启用日志的文件来源。
///
/// 配置值本身的校验在 `ControlConfig::validate` 里完成；这里只碰文件系统。
pub fn validate_io(cfg: &ControlConfig) -> anyhow::Result<()> {
    if !cfg.enabled || !cfg.logs {
        return Ok(());
    }
    logs::validate_sources_io(cfg)
}

/// 执行一次控制操作。入口再次校验能力 / 白名单 / 参数，不信任 hub。
pub fn execute(cfg: &ControlConfig, op: &ControlOp) -> Result<ControlResult, ControlError> {
    if !cfg.enabled {
        return Err(ControlError::capability_disabled());
    }
    match op {
        ControlOp::SystemdList => {
            require(cfg.systemd)?;
            systemd::list(cfg)
        }
        ControlOp::SystemdAction { unit, action } => {
            require(cfg.systemd)?;
            control::validate_unit_name(unit).map_err(ControlError::invalid_request)?;
            if control::is_forbidden_unit(unit)
                || !control::unit_matches_whitelist(unit, &cfg.systemd_units)
            {
                return Err(ControlError::not_whitelisted("unit 不在白名单"));
            }
            systemd::action(cfg, unit, *action)
        }
        ControlOp::DockerList => {
            require(cfg.docker)?;
            docker::list(cfg)
        }
        ControlOp::DockerAction { container, action } => {
            require(cfg.docker)?;
            control::validate_container_name(container).map_err(ControlError::invalid_request)?;
            if !control::container_matches_whitelist(container, &cfg.docker_containers) {
                return Err(ControlError::not_whitelisted("容器不在白名单"));
            }
            docker::action(cfg, container, *action)
        }
        ControlOp::ProcessList => {
            require(cfg.process)?;
            process::list()
        }
        ControlOp::ProcessKill { pid, name, signal } => {
            require(cfg.process)?;
            process::kill(*pid, name, *signal)
        }
        ControlOp::LogList => {
            require(cfg.logs)?;
            logs::list(cfg)
        }
        ControlOp::LogTail { source, lines } => {
            require(cfg.logs)?;
            control::validate_source_id(source).map_err(ControlError::invalid_request)?;
            if *lines == 0 || *lines > MAX_LOG_LINES {
                return Err(ControlError::invalid_request(format!(
                    "lines 必须在 1–{MAX_LOG_LINES} 之间"
                )));
            }
            let Some(config_source) = cfg.log_sources.iter().find(|item| item.id == *source) else {
                return Err(ControlError::not_whitelisted("日志来源不在白名单"));
            };
            logs::tail(cfg, config_source, *lines)
        }
    }
}

fn require(capability_enabled: bool) -> Result<(), ControlError> {
    if capability_enabled {
        Ok(())
    } else {
        Err(ControlError::capability_disabled())
    }
}

/// 在独立任务里执行控制请求，并把应答通过 channel 交回会话循环。
///
/// - `spawn_blocking` 避免 `systemctl` / `/proc` 扫描阻塞 async runtime；
/// - 外层超时兜底（单条命令自身也有超时）；
/// - 并发上限用信号量控制，超限立刻回错误而不是无限排队。
pub struct ControlDispatcher {
    cfg: ControlConfig,
    slots: Arc<Semaphore>,
    tx: mpsc::Sender<ControlResponse>,
}

impl ControlDispatcher {
    pub fn new(cfg: ControlConfig) -> (Self, mpsc::Receiver<ControlResponse>) {
        let (tx, rx) = mpsc::channel(CONTROL_RESPONSE_BUFFER);
        let dispatcher = Self {
            cfg,
            slots: Arc::new(Semaphore::new(MAX_CONCURRENT_CONTROL)),
            tx,
        };
        (dispatcher, rx)
    }

    /// 启动一个控制任务。控制应答稍后从 `Receiver` 取回并发送给 hub。
    pub fn spawn(&self, request: ControlRequest) {
        let ControlRequest { id, op } = request;
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            let _ = self.tx.try_send(ControlResponse::failure(
                id,
                ControlError::control_failed("并发控制请求过多，请稍后重试"),
            ));
            return;
        };

        let cfg = self.cfg.clone();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let timeout = Duration::from_secs(
                cfg.command_timeout_secs
                    .saturating_add(CONTROL_TIMEOUT_GRACE_SECS),
            );
            // #46：许可必须由真正执行 `execute` 的 blocking 任务持有。外层
            // `timeout` 只决定何时回错误，即使超时先到，许可也要等命令及其
            // 进程组被回收、`execute` 真正返回后才释放，避免“超时后仍可无限
            // 创建新命令”。
            let joined = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                execute(&cfg, &op)
            });
            let response = match tokio::time::timeout(timeout, joined).await {
                Ok(Ok(Ok(result))) => ControlResponse::success(id, result),
                Ok(Ok(Err(error))) => ControlResponse::failure(id, error),
                Ok(Err(join_error)) => ControlResponse::failure(
                    id,
                    ControlError::control_failed(format!("控制任务失败: {join_error}")),
                ),
                Err(_) => {
                    tracing::warn!(
                        id,
                        "控制操作执行超时；后台任务仍在运行，容量许可将在其返回后释放"
                    );
                    ControlResponse::failure(id, ControlError::control_failed("控制操作执行超时"))
                }
            };
            // 配置驱动的大结果（例如 512 条 LogSources）编码后可能超过 hub 的
            // 1 MiB WS 消息上限；超限时回固定小错误，不能发出去导致断连。
            let response = fit_response_budget(response);
            // 会话结束时接收端已 drop，发送失败直接忽略。
            let _ = tx.send(response).await;
        });
    }

    /// 无法解码的控制帧：只回错误，不断连接。
    pub fn unsupported(&self, id: u64, message: &str) {
        let _ = self.tx.try_send(ControlResponse::failure(
            id,
            ControlError::unsupported(message),
        ));
    }
}

/// 控制应答编码后的预算兜底。
///
/// 结果大小由配置 / 系统状态决定（例如 512 条 `LogSources`、超长 target），
/// 编码后可能超过 hub 的 1 MiB WebSocket 消息上限。超限时必须回固定小错误：
/// 把超限帧发出去只会让 hub 以 `Message too long` 关闭整个会话，结果仍然丢失，
/// 而且 agent 会被迫重连。id 必须保留，hub 才能把错误匹配回对应请求。
fn fit_response_budget(response: ControlResponse) -> ControlResponse {
    let id = response.id;
    match Frame::ControlResponse(response.clone()).encode() {
        Ok(encoded) if encoded.len() <= MAX_CONTROL_RESPONSE_BYTES => response,
        Ok(encoded) => {
            tracing::warn!(
                id,
                encoded_bytes = encoded.len(),
                limit = MAX_CONTROL_RESPONSE_BYTES,
                "控制结果超过单帧预算，改为错误应答"
            );
            ControlResponse::failure(id, ControlError::result_too_large())
        }
        Err(err) => {
            // 编码失败同样不能 panic / 发半帧；回一个可解释的固定错误。
            tracing::warn!(id, error = %err, "控制应答编码失败，改为错误应答");
            ControlResponse::failure(id, ControlError::control_failed("控制结果编码失败"))
        }
    }
}

/// 从一个无法完整解码的帧里尽力取出 `ControlRequest.id`。
///
/// 未知操作变体会让 `Frame::decode` 整体失败；此时只要外层是
/// `ControlRequest` 且 id 可读，就可以回 `unsupported` 而不是直接丢帧。
pub fn probe_control_request_id(bytes: &[u8]) -> Option<u64> {
    decode_control_probe(bytes).ok()
}

#[derive(serde::Deserialize)]
enum ProbeFrame {
    ControlRequest(ProbeRequest),
}

#[derive(serde::Deserialize)]
struct ProbeRequest {
    id: u64,
    /// rmp-serde 默认把结构体编码成数组（紧凑格式）：第二个元素是 op。
    /// 这里只关心 id，op 用 `IgnoredAny` 消费掉。
    #[allow(dead_code)]
    op: serde::de::IgnoredAny,
}

fn decode_control_probe(bytes: &[u8]) -> std::result::Result<u64, rmp_serde::decode::Error> {
    match rmp_serde::from_slice::<ProbeFrame>(bytes) {
        Ok(ProbeFrame::ControlRequest(request)) => Ok(request.id),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustboard_common::control::{
        codes, ControlError, KillSignal, LogSourceInfo, ProcessInfo, MAX_CMDLINE_BYTES,
        MAX_LOG_TARGET_BYTES, MAX_NAME_LEN, MAX_OUTPUT_BYTES, MAX_PROCESS_ITEMS,
    };
    use rustboard_common::wire::Frame;

    fn cfg() -> ControlConfig {
        ControlConfig {
            enabled: true,
            ..ControlConfig::default()
        }
    }

    #[test]
    fn capabilities_follow_switches_and_master_switch() {
        assert!(enabled_capabilities(&ControlConfig::default()).is_empty());

        // 总开关关闭时，即使单项为 true 也不上报（配置校验会拒绝，函数仍防御）。
        let inconsistent = ControlConfig {
            systemd: true,
            ..ControlConfig::default()
        };
        assert!(enabled_capabilities(&inconsistent).is_empty());

        let all = ControlConfig {
            enabled: true,
            systemd: true,
            docker: true,
            process: true,
            logs: true,
            ..ControlConfig::default()
        };
        assert_eq!(
            enabled_capabilities(&all),
            ["systemd", "docker", "process", "logs"]
        );

        let logs_only = ControlConfig {
            enabled: true,
            logs: true,
            ..ControlConfig::default()
        };
        assert_eq!(enabled_capabilities(&logs_only), ["logs"]);
    }

    #[test]
    fn execute_rejects_disabled_capabilities() {
        let err = execute(&ControlConfig::default(), &ControlOp::ProcessList).unwrap_err();
        assert_eq!(err.code, codes::CAPABILITY_DISABLED);

        // 总开关开、单项关：同样是 capability_disabled。
        let err = execute(&cfg(), &ControlOp::ProcessList).unwrap_err();
        assert_eq!(err.code, codes::CAPABILITY_DISABLED);
        let err = execute(&cfg(), &ControlOp::SystemdList).unwrap_err();
        assert_eq!(err.code, codes::CAPABILITY_DISABLED);
        let err = execute(&cfg(), &ControlOp::DockerList).unwrap_err();
        assert_eq!(err.code, codes::CAPABILITY_DISABLED);
        let err = execute(&cfg(), &ControlOp::LogList).unwrap_err();
        assert_eq!(err.code, codes::CAPABILITY_DISABLED);
    }

    #[test]
    fn execute_enforces_whitelist_before_running_anything() {
        let mut systemd_cfg = cfg();
        systemd_cfg.systemd = true;
        systemd_cfg.systemd_units = vec!["nginx*".into()];
        let err = execute(
            &systemd_cfg,
            &ControlOp::SystemdAction {
                unit: "redis.service".into(),
                action: rustboard_common::control::SystemdAction::Restart,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, codes::NOT_WHITELISTED);

        // 禁止项优先：sshd 即使在白名单里（这里直接构造）也必须拒绝。
        let mut forbidden_cfg = systemd_cfg.clone();
        forbidden_cfg.systemd_units = vec!["sshd*".into()];
        let err = execute(
            &forbidden_cfg,
            &ControlOp::SystemdAction {
                unit: "sshd.service".into(),
                action: rustboard_common::control::SystemdAction::Start,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, codes::NOT_WHITELISTED);

        let mut docker_cfg = cfg();
        docker_cfg.docker = true;
        docker_cfg.docker_containers = vec!["web-*".into()];
        let err = execute(
            &docker_cfg,
            &ControlOp::DockerAction {
                container: "db-1".into(),
                action: rustboard_common::control::DockerAction::Stop,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, codes::NOT_WHITELISTED);
    }

    #[test]
    fn execute_rejects_invalid_parameters_before_io() {
        let mut systemd_cfg = cfg();
        systemd_cfg.systemd = true;
        systemd_cfg.systemd_units = vec!["nginx*".into()];
        let err = execute(
            &systemd_cfg,
            &ControlOp::SystemdAction {
                unit: "nginx/../service\n".into(),
                action: rustboard_common::control::SystemdAction::Restart,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, codes::INVALID_REQUEST);

        let mut logs_cfg = cfg();
        logs_cfg.logs = true;
        logs_cfg.log_sources = vec![rustboard_common::config::LogSourceConfig {
            id: "app".into(),
            kind: rustboard_common::config::LogSourceKind::File,
            target: "/var/log/app.log".into(),
            name: String::new(),
        }];
        for lines in [0, MAX_LOG_LINES + 1] {
            let err = execute(
                &logs_cfg,
                &ControlOp::LogTail {
                    source: "app".into(),
                    lines,
                },
            )
            .unwrap_err();
            assert_eq!(err.code, codes::INVALID_REQUEST);
        }
        let err = execute(
            &logs_cfg,
            &ControlOp::LogTail {
                source: "not-configured".into(),
                lines: 10,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, codes::NOT_WHITELISTED);

        let mut process_cfg = cfg();
        process_cfg.process = true;
        let err = execute(
            &process_cfg,
            &ControlOp::ProcessKill {
                pid: 1,
                name: "systemd".into(),
                signal: KillSignal::Term,
            },
        )
        .unwrap_err();
        assert_eq!(err.code, codes::INVALID_REQUEST);
    }

    #[test]
    fn probe_extracts_id_from_unknown_control_op() {
        // 合法请求也能被 probe 识别（回归保护）。
        let valid = Frame::ControlRequest(ControlRequest::new(7, ControlOp::ProcessList))
            .encode()
            .unwrap();
        match decode_control_probe(&valid) {
            Ok(id) => assert_eq!(id, 7),
            Err(err) => panic!("probe 解码合法控制帧失败: {err}"),
        }

        // 未知操作变体：Frame 解码失败，但 id 仍可读，交给 unsupported 分支。
        let unknown = serde_json::json!({
            "ControlRequest": {"id": 9, "op": {"SomethingNew": {"x": 1}}}
        });
        let bytes = rmp_serde::to_vec(&unknown).unwrap();
        assert!(Frame::decode(&bytes).is_err(), "未知操作必须解码失败");
        assert_eq!(probe_control_request_id(&bytes), Some(9));

        // 非控制帧 / 垃圾数据不会误报。
        let bogus = rmp_serde::to_vec("not-a-frame").unwrap();
        assert_eq!(probe_control_request_id(&bogus), None);
        assert_eq!(probe_control_request_id(&[0x81]), None);
    }

    #[tokio::test]
    async fn dispatcher_returns_error_without_blocking_session() {
        let (dispatcher, mut rx) = ControlDispatcher::new(cfg());
        dispatcher.spawn(ControlRequest::new(41, ControlOp::LogList));
        let response = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("控制应答不应超时")
            .expect("控制应答通道不应关闭");
        assert_eq!(response.id, 41);
        let error = response.error.expect("logs 未开启必须返回错误");
        assert_eq!(error.code, codes::CAPABILITY_DISABLED);
    }

    #[tokio::test]
    async fn dispatcher_unsupported_is_an_error_response_not_a_disconnect() {
        let (dispatcher, mut rx) = ControlDispatcher::new(cfg());
        dispatcher.unsupported(42, "不支持的控制操作");
        let response = rx.recv().await.expect("应收到错误应答");
        assert_eq!(response.id, 42);
        assert_eq!(response.error.unwrap().code, codes::UNSUPPORTED);
    }

    /// 评审严重回归：约 300 条超长 `LogSources` 编码后 >1 MiB，必须改为
    /// `control_failed` 小错误，不能发出超限帧导致 hub 断开会话。
    #[test]
    fn v032_oversized_control_response_is_replaced_with_error() {
        let sources: Vec<LogSourceInfo> = (0..300)
            .map(|index| LogSourceInfo {
                id: format!("src-{index}"),
                kind: rustboard_common::config::LogSourceKind::File,
                target: "t".repeat(MAX_LOG_TARGET_BYTES),
                name: "n".repeat(128),
            })
            .collect();
        let response = ControlResponse::success(7, ControlResult::LogSources(sources));
        let encoded_before = Frame::ControlResponse(response.clone())
            .encode()
            .expect("测试响应必须可编码");
        assert!(
            encoded_before.len() > 1024 * 1024,
            "测试数据编码后必须超过 hub 1 MiB 消息上限，实际 {}",
            encoded_before.len()
        );

        let fitted = fit_response_budget(response);
        assert_eq!(fitted.id, 7, "id 必须保留");
        assert!(fitted.result.is_none(), "超限结果必须被丢弃");
        let encoded_after = Frame::ControlResponse(fitted.clone()).encode().unwrap();
        let error = fitted.error.as_ref().expect("必须返回错误");
        assert_eq!(error.code, codes::RESULT_TOO_LARGE);
        assert!(
            error.message.contains("核对状态"),
            "错误信息: {}",
            error.message
        );
        assert!(
            encoded_after.len() < 4096,
            "错误应答必须远小于预算，实际 {}",
            encoded_after.len()
        );
    }

    /// 正常小响应原样通过；合法的 256 KiB stdout + 256 KiB stderr 也不会被误杀。
    #[test]
    fn v032_legal_control_responses_pass_budget_unchanged() {
        let small = ControlResponse::success(
            1,
            ControlResult::LogSources(vec![LogSourceInfo {
                id: "app".into(),
                kind: rustboard_common::config::LogSourceKind::File,
                target: "/var/log/app.log".into(),
                name: "app".into(),
            }]),
        );
        assert_eq!(
            fit_response_budget(small.clone()),
            small,
            "小响应必须原样通过"
        );

        let output = ControlResponse::success(
            2,
            ControlResult::ActionOutput {
                stdout: "o".repeat(MAX_OUTPUT_BYTES),
                stderr: "e".repeat(MAX_OUTPUT_BYTES),
                exit_code: Some(0),
            },
        );
        let encoded = Frame::ControlResponse(output.clone()).encode().unwrap();
        assert!(
            encoded.len() <= MAX_CONTROL_RESPONSE_BYTES,
            "合法的双 256 KiB 输出应在预算内，实际 {}",
            encoded.len()
        );
        assert_eq!(
            fit_response_budget(output.clone()),
            output,
            "预算内的合法输出不得被误杀"
        );
    }

    /// 未启用日志时不做文件 I/O 预检（旧配置里的过期路径不应阻止启动）。
    #[test]
    fn validate_io_skips_when_logs_disabled() {
        let cfg = ControlConfig {
            enabled: true,
            logs: false,
            log_sources: vec![rustboard_common::config::LogSourceConfig {
                id: "gone".into(),
                kind: rustboard_common::config::LogSourceKind::File,
                target: "/definitely/not/here/app.log".into(),
                name: String::new(),
            }],
            ..ControlConfig::default()
        };
        validate_io(&cfg).expect("logs 关闭时不应做文件校验");
    }

    /// Processes 最坏值：200 条 × 4096B cmdline 编码后仍在预算内，不得被改写。
    #[test]
    fn v032_processes_worst_case_pass_budget_unchanged() {
        let processes: Vec<ProcessInfo> = (0..MAX_PROCESS_ITEMS)
            .map(|index| ProcessInfo {
                pid: index as u32 + 2,
                name: "p".repeat(MAX_NAME_LEN),
                cmdline: "c".repeat(MAX_CMDLINE_BYTES),
                uid: 0,
                rss_kb: 0,
            })
            .collect();
        let response = ControlResponse::success(9, ControlResult::Processes(processes));
        let encoded = Frame::ControlResponse(response.clone()).encode().unwrap();
        assert!(
            encoded.len() <= MAX_CONTROL_RESPONSE_BYTES,
            "200 条 × 4096B cmdline 应仍在预算内，实际 {}",
            encoded.len()
        );
        assert_eq!(
            fit_response_budget(response.clone()),
            response,
            "预算内的 Processes 结果不得被改写"
        );
    }

    #[test]
    fn control_error_helpers_use_stable_codes() {
        assert_eq!(
            ControlError::capability_disabled().code,
            codes::CAPABILITY_DISABLED
        );
        assert_eq!(
            ControlError::not_whitelisted("x").code,
            codes::NOT_WHITELISTED
        );
        assert_eq!(
            ControlError::invalid_request("x").code,
            codes::INVALID_REQUEST
        );
        assert_eq!(
            ControlError::control_failed("x").code,
            codes::CONTROL_FAILED
        );
        assert_eq!(ControlError::unsupported("x").code, codes::UNSUPPORTED);
        assert_eq!(
            ControlError::result_too_large().code,
            codes::RESULT_TOO_LARGE
        );
    }
}
