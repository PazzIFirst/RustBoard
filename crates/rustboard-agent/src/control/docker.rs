//! Docker 容器管理：只允许 list / start / stop / restart。
//!
//! 列表使用 `docker ps -a --no-trunc --format` 的固定模板，结果按容器名白名单
//! （精确或尾部 `*` 前缀）过滤；动作枚举固定，`exec` / `run` / `rm` 不可达。

use rustboard_common::config::ControlConfig;
use rustboard_common::control::{
    self, ControlError, ControlResult, DockerAction, DockerContainer, MAX_LIST_ITEMS,
    MAX_OUTPUT_BYTES, MAX_TARGET_LEN,
};

use super::exec;

/// `docker ps` 的固定模板：TAB 分隔，顺序与 [`DockerContainer`] 字段一致。
pub const PS_FORMAT: &str = "{{.Names}}\t{{.Image}}\t{{.State}}\t{{.Status}}\t{{.ID}}";
/// `docker ps` 的固定参数；`--no-trunc` 保证 ID 完整。
pub const DOCKER_PS_ARGS: [&str; 5] = ["ps", "-a", "--no-trunc", "--format", PS_FORMAT];

/// 列出白名单内的容器。
pub fn list(cfg: &ControlConfig) -> Result<ControlResult, ControlError> {
    let tool = exec::resolve_tool(&cfg.docker_path, "docker")?;
    let output = exec::run(
        &tool,
        &DOCKER_PS_ARGS,
        exec::command_timeout(cfg),
        MAX_OUTPUT_BYTES,
    )?;
    exec::ensure_success(&output, "docker ps")?;
    Ok(ControlResult::DockerContainers(parse_ps_output(
        &output.stdout,
        &cfg.docker_containers,
    )))
}

/// 对白名单容器执行 start / stop / restart。
///
/// 非零退出码作为 `ActionOutput.exit_code` 返回；启动失败 / 超时返回 `control_failed`。
pub fn action(
    cfg: &ControlConfig,
    container: &str,
    action: DockerAction,
) -> Result<ControlResult, ControlError> {
    let tool = exec::resolve_tool(&cfg.docker_path, "docker")?;
    let output = exec::run(
        &tool,
        &[action.as_str(), container],
        exec::command_timeout(cfg),
        MAX_OUTPUT_BYTES,
    )?;
    Ok(output.into_action_output())
}

/// 解析 `docker ps --format` 的 TAB 分隔输出，并按白名单过滤。
fn parse_ps_output(output: &str, patterns: &[String]) -> Vec<DockerContainer> {
    let mut containers = Vec::new();
    for line in output.lines() {
        let mut fields = line.split('\t').map(str::trim);
        let (Some(name), Some(image), Some(state), Some(status), Some(id)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if name.is_empty()
            || name.len() > MAX_TARGET_LEN
            || !control::validate_container_name(name).is_ok()
        {
            continue;
        }
        if !control::container_matches_whitelist(name, patterns) {
            continue;
        }
        containers.push(DockerContainer {
            name: name.to_string(),
            image: image.to_string(),
            state: state.to_string(),
            status: status.to_string(),
            id: id.to_string(),
        });
        if containers.len() >= MAX_LIST_ITEMS {
            break;
        }
    }
    containers
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "rb-agent-docker-{}-{tag}-{seq}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    fn patterns(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    const SAMPLE: &str = "web-1\tnginx:latest\trunning\tUp 2 hours\tabc123\n\
db-1\tpostgres:16\trunning\tUp 2 hours\tdef456\n\
web-bad!\tnginx:latest\texited\tExited (1)\tghi789\n\
malformed-without-tabs\n";

    #[test]
    fn ps_parser_filters_by_container_prefix() {
        let containers = parse_ps_output(SAMPLE, &patterns(&["web-*"]));
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].name, "web-1");
        assert_eq!(containers[0].image, "nginx:latest");
        assert_eq!(containers[0].state, "running");
        assert_eq!(containers[0].status, "Up 2 hours");
        assert_eq!(containers[0].id, "abc123");

        let all = parse_ps_output(SAMPLE, &patterns(&["web*", "db"]));
        let names: Vec<&str> = all
            .iter()
            .map(|container| container.name.as_str())
            .collect();
        assert_eq!(
            names,
            ["web-1"],
            "精确白名单 db 不匹配 db-1，非法容器名也必须跳过"
        );

        let both = parse_ps_output(SAMPLE, &patterns(&["web-1", "db-*"]));
        let names: Vec<&str> = both
            .iter()
            .map(|container| container.name.as_str())
            .collect();
        assert_eq!(names, ["web-1", "db-1"]);
    }

    #[test]
    fn ps_parser_caps_items() {
        let mut text = String::new();
        for index in 0..(MAX_LIST_ITEMS + 5) {
            text.push_str(&format!(
                "web-{index}\tnginx:latest\trunning\tUp\tid{index}\n"
            ));
        }
        let containers = parse_ps_output(&text, &patterns(&["web-*"]));
        assert_eq!(containers.len(), MAX_LIST_ITEMS);
    }

    #[test]
    fn list_runs_fixed_args_and_filters_output() {
        let dir = temp_dir("list");
        let args_file = dir.join("args.txt");
        let script = write_script(
            &dir,
            "docker",
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf 'web-1\\tnginx:latest\\trunning\\tUp 1 hour\\tabc\\n'\nprintf 'db-1\\tpostgres:16\\trunning\\tUp 1 hour\\tdef\\n'",
                args_file.display()
            ),
        );
        let cfg = ControlConfig {
            enabled: true,
            docker: true,
            docker_containers: patterns(&["web-*"]),
            docker_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        match list(&cfg).unwrap() {
            ControlResult::DockerContainers(containers) => {
                assert_eq!(containers.len(), 1);
                assert_eq!(containers[0].name, "web-1");
            }
            other => panic!("意外结果: {other:?}"),
        }
        let args = std::fs::read_to_string(&args_file).unwrap();
        let args: Vec<&str> = args.lines().collect();
        assert_eq!(args, DOCKER_PS_ARGS);
        assert!(args.contains(&"--no-trunc"), "必须使用 --no-trunc");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn action_uses_verb_and_container() {
        let dir = temp_dir("action");
        let args_file = dir.join("args.txt");
        let script = write_script(
            &dir,
            "docker",
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf 'web-1\\n'\nexit 0",
                args_file.display()
            ),
        );
        let cfg = ControlConfig {
            enabled: true,
            docker: true,
            docker_containers: patterns(&["web-*"]),
            docker_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        match action(&cfg, "web-1", DockerAction::Restart).unwrap() {
            ControlResult::ActionOutput {
                stdout, exit_code, ..
            } => {
                assert_eq!(stdout, "web-1\n");
                assert_eq!(exit_code, Some(0));
            }
            other => panic!("意外结果: {other:?}"),
        }
        let args = std::fs::read_to_string(&args_file).unwrap();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            ["restart", "web-1"],
            "docker 动作必须使用固定动作 + 容器名"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_tool_is_control_failed() {
        let cfg = ControlConfig {
            enabled: true,
            docker: true,
            docker_containers: patterns(&["web-*"]),
            docker_path: "/definitely/not/here/docker".to_string(),
            ..ControlConfig::default()
        };
        let err = list(&cfg).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("不存在"), "{}", err.message);
    }

    #[test]
    fn actions_expose_expected_verbs() {
        assert_eq!(DockerAction::Start.as_str(), "start");
        assert_eq!(DockerAction::Stop.as_str(), "stop");
        assert_eq!(DockerAction::Restart.as_str(), "restart");
    }
}
