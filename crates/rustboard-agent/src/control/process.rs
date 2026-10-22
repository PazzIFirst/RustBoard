//! 进程查看与结束。
//!
//! 列表直接扫描 `/proc` 数字目录（最多 [`MAX_PROCESS_ITEMS`] 条）；结束进程前必须
//! 同时满足：PID > 1、PID != agent 自身、`/proc/<pid>/comm` 与请求 name 完全一致。
//! 信号只有 SIGTERM / SIGKILL，直接使用 `kill(2)`，不经过 `kill` 命令。

use std::fs;
use std::io;

use rustboard_common::control::{
    ControlError, ControlResult, KillSignal, ProcessInfo, MAX_CMDLINE_BYTES, MAX_NAME_LEN,
    MAX_PROCESS_ITEMS,
};

/// 扫描 `/proc` 列出进程。PID 升序，最多 200 条；已退出的进程跳过。
pub fn list() -> Result<ControlResult, ControlError> {
    let mut pids: Vec<u32> = fs::read_dir("/proc")
        .map_err(|err| ControlError::control_failed(format!("读取 /proc 失败: {err}")))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
        })
        .collect();
    pids.sort_unstable();
    pids.truncate(MAX_PROCESS_ITEMS);

    let mut processes = Vec::with_capacity(pids.len());
    for pid in pids {
        if let Some(info) = read_process(pid) {
            processes.push(info);
        }
    }
    Ok(ControlResult::Processes(processes))
}

/// 结束进程。任何一项校验不通过都不会发送信号。
pub fn kill(pid: u32, name: &str, signal: KillSignal) -> Result<ControlResult, ControlError> {
    if pid <= 1 {
        return Err(ControlError::invalid_request(
            "不能结束 PID 0 / 1（init 进程）",
        ));
    }
    if pid > i32::MAX as u32 {
        return Err(ControlError::invalid_request("PID 超出内核范围"));
    }
    if pid == std::process::id() {
        return Err(ControlError::invalid_request("不能结束 agent 自身进程"));
    }
    if name.is_empty() {
        return Err(ControlError::invalid_request("进程名不能为空"));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(ControlError::invalid_request(format!(
            "进程名不能超过 {MAX_NAME_LEN} 字节"
        )));
    }
    if name.chars().any(char::is_control) {
        return Err(ControlError::invalid_request("进程名不能包含控制字符"));
    }

    let comm_path = format!("/proc/{pid}/comm");
    let comm = fs::read_to_string(&comm_path).map_err(|err| {
        ControlError::control_failed(format!("读取 {comm_path} 失败（进程可能已退出）: {err}"))
    })?;
    let comm = comm.trim_end_matches('\n');
    if comm != name {
        // 名称不匹配就不发信号：防止 PID 复用导致误杀。
        return Err(ControlError::not_whitelisted(format!(
            "进程名不匹配（实际 {}）",
            super::exec::summarize(comm, MAX_NAME_LEN)
        )));
    }

    let signal_number = signal_number(signal);
    // SAFETY: pid 已校验 > 1、不是自身、且 <= i32::MAX；signal_number 是固定常量；
    // kill(2) 只有整数参数，不解引用任何指针。
    let rc = unsafe { libc::kill(pid as libc::pid_t, signal_number) };
    if rc != 0 {
        return Err(ControlError::control_failed(format!(
            "发送信号失败: {}",
            io::Error::last_os_error()
        )));
    }

    Ok(ControlResult::ActionOutput {
        stdout: String::new(),
        stderr: String::new(),
        exit_code: Some(0),
    })
}

/// 信号映射固定为 SIGTERM / SIGKILL，不接受数字信号。
fn signal_number(signal: KillSignal) -> libc::c_int {
    match signal {
        KillSignal::Term => libc::SIGTERM,
        KillSignal::Kill => libc::SIGKILL,
    }
}

fn read_process(pid: u32) -> Option<ProcessInfo> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = truncate_bytes(comm.trim_end_matches('\n'), MAX_NAME_LEN);
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let (uid, rss_kb) = parse_status(&status);
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let cmdline = cmdline
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ");
    Some(ProcessInfo {
        pid,
        name,
        cmdline: truncate_bytes(&cmdline, MAX_CMDLINE_BYTES),
        uid,
        rss_kb,
    })
}

/// 从 `/proc/<pid>/status` 提取 real UID 与 VmRSS（KiB）。缺失字段按 0 处理。
fn parse_status(status: &str) -> (u32, u64) {
    let mut uid = 0u32;
    let mut rss_kb = 0u64;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            uid = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("VmRSS:") {
            rss_kb = rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
        }
    }
    (uid, rss_kb)
}

/// 按字节上限截断，保证仍在 UTF-8 字符边界上。
fn truncate_bytes(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn wait_for_comm(pid: u32) -> String {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(comm) = fs::read_to_string(format!("/proc/{pid}/comm")) {
                return comm.trim_end_matches('\n').to_string();
            }
            assert!(Instant::now() < deadline, "进程 {pid} 的 comm 一直不可读");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn signal_mapping_is_fixed_to_term_and_kill() {
        assert_eq!(signal_number(KillSignal::Term), libc::SIGTERM);
        assert_eq!(signal_number(KillSignal::Kill), libc::SIGKILL);
    }

    #[test]
    fn rejects_pid_one_and_agent_itself_before_any_signal() {
        let err = kill(1, "systemd", KillSignal::Term).unwrap_err();
        assert_eq!(err.code, rustboard_common::control::codes::INVALID_REQUEST);

        let err = kill(0, "init", KillSignal::Kill).unwrap_err();
        assert_eq!(err.code, rustboard_common::control::codes::INVALID_REQUEST);

        let err = kill(std::process::id(), "rustboard-agent", KillSignal::Kill).unwrap_err();
        assert!(
            err.message.contains("自身"),
            "必须拒绝结束 agent 自身: {}",
            err.message
        );
        assert_eq!(err.code, rustboard_common::control::codes::INVALID_REQUEST);
    }

    #[test]
    fn rejects_bad_names_without_touching_proc() {
        let too_long = "a".repeat(MAX_NAME_LEN + 1);
        for name in ["", too_long.as_str()] {
            let err = kill(999_999, name, KillSignal::Term).unwrap_err();
            assert_eq!(err.code, rustboard_common::control::codes::INVALID_REQUEST);
        }
        let err = kill(999_999, "bad\nname", KillSignal::Term).unwrap_err();
        assert_eq!(err.code, rustboard_common::control::codes::INVALID_REQUEST);
    }

    #[test]
    fn missing_process_is_control_failed_and_does_not_signal() {
        // 999999 可能恰好不存在；若存在也不影响本测试的断言分支，跳过。
        if fs::metadata("/proc/999999").is_ok() {
            return;
        }
        let err = kill(999_999, "whatever", KillSignal::Term).unwrap_err();
        assert_eq!(err.code, rustboard_common::control::codes::CONTROL_FAILED);
    }

    #[test]
    fn kill_requires_matching_comm_then_sends_sigterm() {
        let mut child = Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("测试需要 sleep 命令");
        let pid = child.id();
        let comm = wait_for_comm(pid);

        // 名称不匹配：必须拒绝且进程仍然存活。
        let err = kill(pid, "definitely-not-the-process-name", KillSignal::Term).unwrap_err();
        assert_eq!(
            err.code,
            rustboard_common::control::codes::NOT_WHITELISTED,
            "{err:?}"
        );
        assert!(
            child.try_wait().unwrap().is_none(),
            "名称不匹配时绝不能发送信号"
        );

        // 名称匹配：发送 SIGTERM，sleep 以信号退出。
        let result = kill(pid, &comm, KillSignal::Term).expect("PID + 名称匹配时必须成功");
        match result {
            ControlResult::ActionOutput { exit_code, .. } => assert_eq!(exit_code, Some(0)),
            other => panic!("意外结果: {other:?}"),
        }
        let status = child.wait().expect("回收子进程");
        assert!(!status.success(), "SIGTERM 后 sleep 不应正常退出");
    }

    #[test]
    fn list_is_sorted_and_capped() {
        let result = list().unwrap();
        match result {
            ControlResult::Processes(processes) => {
                assert!(processes.len() <= MAX_PROCESS_ITEMS);
                for pair in processes.windows(2) {
                    assert!(pair[0].pid <= pair[1].pid, "进程列表必须按 PID 升序");
                }
            }
            other => panic!("意外结果: {other:?}"),
        }
    }

    #[test]
    fn read_process_reports_current_process() {
        let info = read_process(std::process::id()).expect("当前进程必须可读");
        assert_eq!(info.pid, std::process::id());
        assert!(!info.name.is_empty());
        assert!(!info.cmdline.is_empty(), "测试进程应有命令行");
        assert!(info.cmdline.len() <= MAX_CMDLINE_BYTES);
    }

    #[test]
    fn status_parser_extracts_uid_and_rss() {
        let (uid, rss) =
            parse_status("Name:\tx\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t  2048 kB\n");
        assert_eq!(uid, 1000);
        assert_eq!(rss, 2048);
        assert_eq!(parse_status("Name:\tx\n"), (0, 0));
    }
}
