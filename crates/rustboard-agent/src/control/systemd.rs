//! systemd 白名单管理：只允许 list / start / stop / restart。
//!
//! 列表合并 `list-units` 与 `list-unit-files`：前者给出已加载 unit 的真实状态，
//! 后者补充已安装但未加载的 service（`load=not-loaded`、`active=inactive`、
//! `sub=dead`）。白名单支持精确 unit 与尾部 `*` 前缀；禁止项（sshd、agent / hub
//! 自身、systemd/dbus 关键服务）优先于白名单，配置层与执行层各校验一次。

use std::collections::HashSet;
use std::time::{Duration, Instant};

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

/// `systemctl list-unit-files` 的固定参数；用于补充已安装但未加载的 service。
/// 同样不经过 shell，参数固定且顺序与方案一致。
pub const SYSTEMCTL_LIST_UNIT_FILES_ARGS: [&str; 5] = [
    "list-unit-files",
    "--type=service",
    "--no-legend",
    "--no-pager",
    "--plain",
];

/// 列出白名单内（且不在禁止列表）的 service unit。
///
/// 两次 `systemctl` 共享同一个总 deadline（`command_timeout_secs`），避免两次
/// 各自用满超时导致最坏耗时翻倍；任一非零退出或输出被截断都直接返回
/// `control_failed`，绝不静默退化成只有一份列表或“看似完整”的残列表。
pub fn list(cfg: &ControlConfig) -> Result<ControlResult, ControlError> {
    let tool = exec::resolve_tool(&cfg.systemctl_path, "systemctl")?;
    let timeout = exec::command_timeout(cfg);
    let deadline = Instant::now() + timeout;

    let loaded = exec::run(&tool, &SYSTEMCTL_LIST_ARGS, timeout, MAX_OUTPUT_BYTES)?;
    exec::ensure_success(&loaded, "systemctl list-units")?;
    ensure_output_complete(&loaded, "systemctl list-units")?;

    let remaining = remaining_budget(deadline)?;
    let installed = exec::run(
        &tool,
        &SYSTEMCTL_LIST_UNIT_FILES_ARGS,
        remaining,
        MAX_OUTPUT_BYTES,
    )?;
    exec::ensure_success(&installed, "systemctl list-unit-files")?;
    ensure_output_complete(&installed, "systemctl list-unit-files")?;

    Ok(ControlResult::SystemdUnits(merge_units(
        &loaded.stdout,
        &installed.stdout,
        &cfg.systemd_units,
    )))
}

/// 第二次命令可用的剩余预算：两次 `systemctl` 共享 [`list`] 里的总 deadline。
///
/// 第一次已经花掉的时间必须扣掉；预算耗尽时直接报固定错误，不再启动子进程。
fn remaining_budget(deadline: Instant) -> Result<Duration, ControlError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ControlError::control_failed("systemctl 列表总超时"));
    }
    Ok(remaining)
}

/// `exec::run` 只保留 stdout 前 [`MAX_OUTPUT_BYTES`] 字节；被截断时列表可能
/// 静默丢掉尾部 unit，因此宁可报 `control_failed`，也不返回不完整列表。
fn ensure_output_complete(output: &exec::ExecOutput, what: &str) -> Result<(), ControlError> {
    if output.stdout_truncated {
        return Err(ControlError::control_failed(format!(
            "{what} 输出超过 {} KiB 上限，已截断，拒绝返回不完整列表",
            MAX_OUTPUT_BYTES / 1024
        )));
    }
    Ok(())
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

/// 解析 `systemctl list-units --plain` 的输出。
///
/// 每行格式为 `UNIT LOAD ACTIVE SUB DESCRIPTION`；描述里的空格原样拼回。
/// 这里只做语法解析：空行 / 列数不足 / 超长 / 无 `.` 的无法解析行直接跳过，
/// 白名单与禁止项统一在 [`merge_units`] 里过滤。
fn parse_list_units(output: &str) -> Vec<SystemdUnit> {
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
        let description = fields.collect::<Vec<_>>().join(" ");
        units.push(SystemdUnit {
            unit: unit.to_string(),
            load: load.to_string(),
            active: active.to_string(),
            sub: sub.to_string(),
            description,
        });
    }
    units
}

/// 解析 `systemctl list-unit-files --plain` 的输出，只取 `.service` 的 unit 名。
///
/// 每行至少 `UNIT STATE [PRESET]` 两列；STATE 是 enable 状态（enabled / disabled /
/// static …），**不是**运行状态，因此这里只取第一列，绝不把 STATE 当作 active 状态。
/// 空行 / 列数不足 / 超长 / 非 `.service` 的行跳过。
fn parse_unit_files(output: &str) -> Vec<String> {
    let mut units = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let (Some(unit), Some(_state)) = (fields.next(), fields.next()) else {
            continue;
        };
        if unit.len() > MAX_TARGET_LEN || !unit.ends_with(".service") {
            continue;
        }
        units.push(unit.to_string());
    }
    units
}

/// 合并两份列表：`list-units` 记录优先，`list-unit-files` 只补充缺失项。
///
/// 统一在这里做白名单 / 禁止项过滤、按 unit 名去重、升序稳定排序，最后截断到
/// [`MAX_LIST_ITEMS`]。先收集完整并集再排序截断，避免因先解析哪份列表而丢掉
/// 字典序更靠前、本应保留的 unit。
fn merge_units(
    loaded_output: &str,
    installed_output: &str,
    patterns: &[String],
) -> Vec<SystemdUnit> {
    let mut units = Vec::new();
    let mut seen = HashSet::new();

    // 第一优先级：list-units 的真实 load / active / sub / description。
    for unit in parse_list_units(loaded_output) {
        if !control::unit_allowed(&unit.unit, patterns) {
            continue;
        }
        if seen.insert(unit.unit.clone()) {
            units.push(unit);
        }
    }

    // 补充：只在 list-unit-files 出现的是已安装未加载，状态不能伪造。
    for name in parse_unit_files(installed_output) {
        if !control::unit_allowed(&name, patterns) {
            continue;
        }
        if seen.insert(name.clone()) {
            units.push(SystemdUnit {
                unit: name,
                load: "not-loaded".to_string(),
                active: "inactive".to_string(),
                sub: "dead".to_string(),
                description: String::new(),
            });
        }
    }

    units.sort_by(|a, b| a.unit.cmp(&b.unit));
    units.truncate(MAX_LIST_ITEMS);
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

    /// 写一个按 argv 返回两份输出的 fake systemctl。
    ///
    /// 两个子命令各自把 argv 落到文件里，未知子命令直接退出 99；这样测试既能
    /// 校验参数固定、不经过 shell，也能保证 `list` 只调用了预期命令。
    fn fake_systemctl(dir: &Path, loaded: &str, installed: &str) -> PathBuf {
        let list_units_args = dir.join("list-units.args").display().to_string();
        let list_unit_files_args = dir.join("list-unit-files.args").display().to_string();
        let loaded = if loaded.ends_with('\n') {
            loaded.to_string()
        } else {
            format!("{loaded}\n")
        };
        let installed = if installed.ends_with('\n') {
            installed.to_string()
        } else {
            format!("{installed}\n")
        };
        write_script(
            dir,
            "systemctl",
            &format!(
                "case \"$1\" in
  list-units)
    printf '%s\\n' \"$@\" > {list_units_args}
    cat <<'EOF'
{loaded}EOF
    ;;
  list-unit-files)
    printf '%s\\n' \"$@\" > {list_unit_files_args}
    cat <<'EOF'
{installed}EOF
    ;;
  *)
    printf 'unexpected verb: %s\\n' \"$1\" >&2
    exit 99
    ;;
esac"
            ),
        )
    }

    fn read_args(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| line.to_string())
            .collect()
    }

    fn list_units(cfg: &ControlConfig) -> Vec<SystemdUnit> {
        match list(cfg).unwrap() {
            ControlResult::SystemdUnits(units) => units,
            other => panic!("意外结果: {other:?}"),
        }
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
        let units = merge_units(SAMPLE, "", &patterns(&["nginx*", "redis.service", "sshd*"]));
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
                "svc{index:04}.service loaded active running service {index}\n"
            ));
        }
        let units = merge_units(&text, "", &patterns(&["svc*"]));
        assert_eq!(units.len(), MAX_LIST_ITEMS);
        assert_eq!(units[0].unit, "svc0000.service");
        assert_eq!(units[MAX_LIST_ITEMS - 1].unit, "svc0511.service");

        // 没有 `.` 的垃圾行 / 列数不足的行必须跳过。
        let junk = "garbage\nfoo bar baz\n";
        assert!(merge_units(junk, "", &patterns(&["garbage"])).is_empty());
    }

    #[test]
    fn list_runs_fixed_args_and_parses_fake_output() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("list");
        let script = fake_systemctl(
            &dir,
            "nginx.service loaded active running Nginx\nsshd.service loaded active running SSH\nredis.service loaded inactive dead Redis\n",
            "nginx.service enabled\nredis.service disabled\nsshd.service enabled\n",
        );
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*", "redis.service", "sshd*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let units = list_units(&cfg);
        assert_eq!(units.len(), 2);
        assert_eq!(units[0].unit, "nginx.service");
        assert_eq!(units[1].unit, "redis.service");

        let list_args = read_args(&dir.join("list-units.args"));
        assert_eq!(
            list_args, SYSTEMCTL_LIST_ARGS,
            "list-units 必须以固定参数数组调用"
        );
        let files_args = read_args(&dir.join("list-unit-files.args"));
        assert_eq!(
            files_args, SYSTEMCTL_LIST_UNIT_FILES_ARGS,
            "list-unit-files 必须以固定参数数组调用"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_merges_installed_but_not_loaded_units() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("merge");
        let script = fake_systemctl(
            &dir,
            "nginx.service loaded active running Nginx\n",
            "nginx.service enabled\ndemo.service disabled\n",
        );
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*", "demo*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let units = list_units(&cfg);
        assert_eq!(units.len(), 2, "未加载的 demo.service 必须出现在结果里");
        assert_eq!(
            units[0],
            SystemdUnit {
                unit: "demo.service".to_string(),
                load: "not-loaded".to_string(),
                active: "inactive".to_string(),
                sub: "dead".to_string(),
                description: String::new(),
            },
            "未加载 unit 的状态必须 exactly not-loaded/inactive/dead，描述为空"
        );
        assert_eq!(units[1].unit, "nginx.service");
        assert_eq!(units[1].load, "loaded", "已加载 unit 必须保留真实状态");
        assert_eq!(units[1].active, "active");
        assert_eq!(units[1].sub, "running");
        assert_eq!(units[1].description, "Nginx");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_deduplicates_units_and_prefers_loaded_state() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("dedupe");
        let script = fake_systemctl(
            &dir,
            "web.service loaded active running Web\n",
            "web.service enabled\nweb.service disabled\n",
        );
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["web*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let units = list_units(&cfg);
        assert_eq!(units.len(), 1, "同一 unit 在两份输出里只能出现一次");
        assert_eq!(units[0].unit, "web.service");
        assert_eq!(
            units[0].load, "loaded",
            "list-units 记录必须优先于 list-unit-files"
        );
        assert_eq!(units[0].active, "active");
        assert_eq!(units[0].sub, "running");
        assert_eq!(units[0].description, "Web");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_filters_both_sources_by_whitelist_and_forbidden() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("filter");
        let script = fake_systemctl(
            &dir,
            "sshd.service loaded active running SSH\n\
             rustboard-agent.service loaded active running Agent\n\
             foo.service loaded active running Foo\n\
             nginx.service loaded active running Nginx\n",
            "sshd.service enabled\n\
             rustboard-agent.service enabled\n\
             foo.service enabled\n\
             nginx.service enabled\n\
             demo.service disabled\n",
        );
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            // 即使配置层把禁止项写进白名单，执行层也必须拒绝。
            systemd_units: patterns(&["nginx*", "demo*", "sshd*", "rustboard-*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let names: Vec<String> = list_units(&cfg).into_iter().map(|unit| unit.unit).collect();
        assert_eq!(names, ["demo.service", "nginx.service"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_truncates_after_sorting_merged_units() {
        // list-units 故意逆序给满 MAX_LIST_ITEMS + 10 条：若在合并前先截断，
        // 会保留字典序更大的 zz0010..zz0521，而不是正确并集的前 512 条。
        let mut loaded = String::new();
        for index in (0..(MAX_LIST_ITEMS + 10)).rev() {
            loaded.push_str(&format!("zz{index:04}.service loaded active running z\n"));
        }
        let units = merge_units(
            &loaded,
            "aa.service enabled\n",
            &patterns(&["aa.service", "zz*"]),
        );
        assert_eq!(units.len(), MAX_LIST_ITEMS);
        assert_eq!(units[0].unit, "aa.service");
        assert_eq!(units[0].load, "not-loaded");
        assert_eq!(units[1].unit, "zz0000.service");
        assert_eq!(units[MAX_LIST_ITEMS - 1].unit, "zz0510.service");
        assert!(
            !units.iter().any(|unit| unit.unit == "zz0511.service"),
            "必须按 unit 名升序排序后再截断"
        );
    }

    #[test]
    fn truncated_systemctl_output_is_control_failed() {
        let _guard = exec::test_serial_guard();
        let huge_units = "nginx.service loaded active running Nginx\n".repeat(7000);
        let huge_files = "demo.service enabled\n".repeat(15000);
        assert!(huge_units.len() > MAX_OUTPUT_BYTES);
        assert!(huge_files.len() > MAX_OUTPUT_BYTES);

        // list-units 超出 256 KiB：不能返回被截断的残列表。
        let dir = temp_dir("truncated-units");
        let script = fake_systemctl(&dir, &huge_units, "nginx.service enabled\n");
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*", "demo*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let err = list(&cfg).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("list-units"), "{}", err.message);
        assert!(err.message.contains("256"), "{}", err.message);
        assert!(err.message.contains("截断"), "{}", err.message);
        let _ = std::fs::remove_dir_all(&dir);

        // list-unit-files 超出 256 KiB：同样必须失败，不能只返回已加载部分。
        let dir = temp_dir("truncated-files");
        let script = fake_systemctl(
            &dir,
            "nginx.service loaded active running Nginx\n",
            &huge_files,
        );
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*", "demo*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let err = list(&cfg).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("list-unit-files"), "{}", err.message);
        assert!(err.message.contains("256"), "{}", err.message);
        assert!(err.message.contains("截断"), "{}", err.message);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remaining_budget_rejects_expired_deadline() {
        // 刚创建的 1s deadline 应返回接近 1s 的剩余预算，供第二次命令使用。
        let deadline = Instant::now() + Duration::from_secs(1);
        let remaining = remaining_budget(deadline).unwrap();
        assert!(remaining <= Duration::from_secs(1));
        assert!(
            remaining >= Duration::from_millis(100),
            "剩余预算不应瞬间耗尽: {remaining:?}"
        );

        // deadline 已过：不再启动第二次命令，直接返回固定的总超时错误。
        let expired = Instant::now() - Duration::from_millis(1);
        let err = remaining_budget(expired).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("总超时"), "{}", err.message);
    }

    #[test]
    fn unit_files_parser_skips_short_long_and_non_service_rows() {
        let too_long = format!("{}.service", "a".repeat(MAX_TARGET_LEN));
        let text = format!(
            "\n\nsingle-column\nfoo.socket enabled\n{too_long} enabled\nvalid.service enabled\nvalid.service disabled\n"
        );
        let names = parse_unit_files(&text);
        assert_eq!(
            names,
            ["valid.service", "valid.service"],
            "只取两列齐全的 .service 行，超长与非 service 行必须跳过"
        );
        assert_eq!(
            merge_units("", &text, &patterns(&["valid.service"])).len(),
            1,
            "合并阶段必须对重复 unit 去重"
        );
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
    fn either_systemctl_list_call_failing_is_control_failed() {
        let _guard = exec::test_serial_guard();

        // 第一次 list-units 失败：不得继续拿 list-unit-files 伪造结果。
        let dir = temp_dir("list-units-fail");
        let script = write_script(&dir, "systemctl", "printf 'no bus\\n' >&2\nexit 1");
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let err = list(&cfg).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("list-units"), "{}", err.message);
        let _ = std::fs::remove_dir_all(&dir);

        // 第二次 list-unit-files 失败：即使 list-units 成功也必须报错。
        let dir = temp_dir("list-unit-files-fail");
        let script = write_script(
            &dir,
            "systemctl",
            "if [ \"$1\" = list-unit-files ]; then\n  printf 'not supported\\n' >&2\n  exit 3\nfi\ncat <<'EOF'\nnginx.service loaded active running Nginx\nEOF",
        );
        let cfg = ControlConfig {
            enabled: true,
            systemd: true,
            systemd_units: patterns(&["nginx*"]),
            systemctl_path: script.to_str().unwrap().to_string(),
            ..ControlConfig::default()
        };
        let err = list(&cfg).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("list-unit-files"), "{}", err.message);
        assert!(err.message.contains("退出码 3"), "{}", err.message);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn actions_expose_expected_verbs() {
        assert_eq!(SystemdAction::Start.as_str(), "start");
        assert_eq!(SystemdAction::Stop.as_str(), "stop");
        assert_eq!(SystemdAction::Restart.as_str(), "restart");
    }
}
