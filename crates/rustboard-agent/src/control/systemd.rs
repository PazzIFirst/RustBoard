//! systemd 白名单管理：只允许 list / start / stop / restart。
//!
//! 白名单支持精确 unit 与尾部 `*` 前缀；禁止项（sshd、agent / hub 自身、
//! systemd/dbus 关键服务）优先于白名单，配置层与执行层各校验一次。

use rustboard_common::config::ControlConfig;
use rustboard_common::control::{
    self, ControlError, ControlResult, SystemdAction, SystemdUnit, MAX_LIST_ITEMS,
    MAX_OUTPUT_BYTES, MAX_TARGET_LEN,
};

use super::exec;

/// `systemctl list-units` 的固定参数；不经过 shell，参数顺序与方案一致。
pub const SYSTEMCTL_LIST_ARGS: [&str; 6] = [
    "list-units",
    "--type=service",
    "--all",
    "--no-legend",
    "--no-pager",
    "--plain",
];

/// 列出白名单内（且不在禁止列表）的 service unit。
pub fn list(cfg: &ControlConfig) -> Result<ControlResult, ControlError> {
    let tool = exec::resolve_tool(&cfg.systemctl_path, "systemctl")?;
    let output = exec::run(
        &tool,
        &SYSTEMCTL_LIST_ARGS,
        exec::command_timeout(cfg),
        MAX_OUTPUT_BYTES,
    )?;
    exec::ensure_success(&output, "systemctl list-units")?;
    Ok(ControlResult::SystemdUnits(parse_list_output(
        &output.stdout,
        &cfg.systemd_units,
    )))
}

/// 对白名单 unit 执行 start / stop / restart。
///
/// 非零退出码作为 `ActionOutput.exit_code` 返回（hub 可据此审计失败），
/// 只有启动失败 / 超时 / 工具缺失才返回 `control_failed`。
pub fn action(
    cfg: &ControlConfig,
    unit: &str,
    action: SystemdAction,
) -> Result<ControlResult, ControlError> {
    let tool = exec::resolve_tool(&cfg.systemctl_path, "systemctl")?;
    let output = exec::run(
        &tool,
        &[action.as_str(), unit],
        exec::command_timeout(cfg),
        MAX_OUTPUT_BYTES,
    )?;
    Ok(output.into_action_output())
}

/// 解析 `systemctl list-units --plain` 的输出，并按白名单 / 禁止项过滤。
///
/// 每行格式为 `UNIT LOAD ACTIVE SUB DESCRIPTION`；只保留 service（命令已限定），
/// 描述里的空格原样拼回。无法解析的行直接跳过。
fn parse_list_output(output: &str, patterns: &[String]) -> Vec<SystemdUnit> {
    let mut units = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let (Some(unit), Some(load), Some(active), Some(sub)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if unit.len() > MAX_TARGET_LEN || !unit.contains('.') {
            continue;
        }
        if !control::unit_allowed(unit, patterns) {
            continue;
        }
        let description = fields.collect::<Vec<_>>().join(" ");
        units.push(SystemdUnit {
            unit: unit.to_string(),
            load: load.to_string(),
            active: active.to_string(),
            sub: sub.to_string(),
            description,
        });
        if units.len() >= MAX_LIST_ITEMS {
            break;
        }
    }
    units
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
            "rb-agent-systemd-{}-{tag}-{seq}",
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

    const SAMPLE: &str = "\
nginx.service loaded active running A high performance web server
sshd.service loaded active running OpenSSH server daemon
redis.service loaded active running Redis
web@blue.service loaded inactive dead Web blue
rustboard-agent.service loaded active running RustBoard agent
foo.mount loaded active mounted /mnt/foo
malformed line
";

    #[test]
    fn list_parser_filters_whitelist_and_forbidden_units() {
        let units = parse_list_output(SAMPLE, &patterns(&["nginx*", "redis.service", "sshd*"]));
        let names: Vec<&str> = units.iter().map(|unit| unit.unit.as_str()).collect();
        assert_eq!(names, ["nginx.service", "redis.service"]);
        assert_eq!(units[0].load, "loaded");
        assert_eq!(units[0].active, "active");
        assert_eq!(units[0].sub, "running");
        assert_eq!(
            units[0].description, "A high performance web server",
            "描述必须原样拼回"
        );
        assert_eq!(units[1].description, "Redis");
    }

    #[test]
    fn list_parser_caps_items_and_skips_non_service_junk() {
        let mut text = String::new();
        for index in 0..(MAX_LIST_ITEMS + 10) {
            text.push_str(&format!(
                "svc{index}.service loaded active running service {index}\n"
            ));
        }
        let units = parse_list_output(&text, &patterns(&["svc*"]));
        assert_eq!(units.len(), MAX_LIST_ITEMS);

        // 没有 `.` 的垃圾行 / 列数不足的行必须跳过。
        let junk = "garbage\nfoo bar baz\n";
        assert!(parse_list_output(junk, &patterns(&["garbage"])).is_empty());
    }

    #[test]
    fn list_runs_fixed_args_and_parses_fake_output() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("list");
        let args_file = dir.join("args.txt");
        let script = write_script(
            &dir,
            "systemctl",
            &format!(
                "printf '%s\\n' \"$@\" > {}\ncat <<'EOF'\nnginx.service loaded active running Nginx\nsshd.service loaded active running SSH\nredis.service loaded inactive dead Redis\nEOF",
                args_file.display()
            ),
        );
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*", "redis.service", "sshd*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let result = list(&cfg).unwrap();
        match result {
            ControlResult::SystemdUnits(units) => {
                assert_eq!(units.len(), 2);
                assert_eq!(units[0].unit, "nginx.service");
                assert_eq!(units[1].unit, "redis.service");
            }
            other => panic!("意外结果: {other:?}"),
        }
        let args = std::fs::read_to_string(&args_file).unwrap();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            SYSTEMCTL_LIST_ARGS,
            "systemctl 必须以固定参数数组调用"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn action_uses_verb_and_unit_and_reports_exit_code() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("action");
        let args_file = dir.join("args.txt");
        let script = write_script(
            &dir,
            "systemctl",
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf 'restarting\\n'\nprintf 'boom\\n' >&2\nexit 5",
                args_file.display()
            ),
        );
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let result = action(&cfg, "nginx.service", SystemdAction::Restart).unwrap();
        match result {
            ControlResult::ActionOutput {
                stdout,
                stderr,
                exit_code,
            } => {
                assert_eq!(stdout, "restarting\n");
                assert_eq!(stderr, "boom\n");
                assert_eq!(exit_code, Some(5), "非零退出码必须原样返回");
            }
            other => panic!("意外结果: {other:?}"),
        }
        let args = std::fs::read_to_string(&args_file).unwrap();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            ["restart", "nginx.service"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_tool_and_failed_list_are_control_failed() {
        let _guard = exec::test_serial_guard();
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*"]),
            systemctl_path: "/definitely/not/here/systemctl".to_string(),
            ..ControlConfig::default()
        };
        let err = list(&cfg).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);

        let dir = temp_dir("list-fail");
        let script = write_script(&dir, "systemctl", "printf 'no bus\\n' >&2\nexit 1");
        let cfg = ControlConfig {
            systemctl_path: script.to_str().unwrap().to_string(),
            ..cfg
        };
        let err = list(&cfg).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("退出码 1"), "{}", err.message);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn actions_expose_expected_verbs() {
        assert_eq!(SystemdAction::Start.as_str(), "start");
        assert_eq!(SystemdAction::Stop.as_str(), "stop");
        assert_eq!(SystemdAction::Restart.as_str(), "restart");
    }
}
