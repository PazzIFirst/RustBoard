//! 无 shell 的外部命令执行：参数数组、环境变量白名单、超时与输出截断。
//!
//! 安全约束：
//! - 一律 `Command::new(绝对路径).args([...])`，不经过 shell；
//! - `env_clear()` 后只保留固定的 `PATH` 与 `LANG=C`；
//! - 每个命令有超时，超时 `kill()` + `wait()`；
//! - stdout / stderr 各自只保留前 `max_output` 字节，其余持续读空防止子进程阻塞。

use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rustboard_common::config::ControlConfig;
use rustboard_common::control::{ControlError, ControlResult, TRUNCATED_MARKER};

/// 工具绝对路径的固定候选目录（配置留空时按顺序探测）。
pub const TOOL_DIRS: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
/// 子进程唯一的 `PATH`；必须配合 `env_clear()` 使用。
pub const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

const READ_CHUNK: usize = 8 * 1024;
const WAIT_POLL: Duration = Duration::from_millis(10);

/// 一次命令执行的结果。
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    /// 正常退出为 `Some(code)`；被信号终止为 `None`。
    pub exit_code: Option<i32>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl ExecOutput {
    /// 转成线协议里的 `ActionOutput`：被截断的流追加固定标记。
    pub fn into_action_output(self) -> ControlResult {
        let mut stdout = self.stdout;
        let mut stderr = self.stderr;
        if self.stdout_truncated {
            stdout.push_str(TRUNCATED_MARKER);
        }
        if self.stderr_truncated {
            stderr.push_str(TRUNCATED_MARKER);
        }
        ControlResult::ActionOutput {
            stdout,
            stderr,
            exit_code: self.exit_code,
        }
    }
}

/// 配置里的命令超时（秒）。配置层已保证 1–60，这里再 clamp 一次。
pub fn command_timeout(cfg: &ControlConfig) -> Duration {
    Duration::from_secs(cfg.command_timeout_secs.clamp(
        rustboard_common::control::MIN_COMMAND_TIMEOUT_SECS,
        rustboard_common::control::MAX_COMMAND_TIMEOUT_SECS,
    ))
}

/// 解析工具绝对路径：配置优先，其次按 [`TOOL_DIRS`] 探测。
pub fn resolve_tool(configured: &str, name: &str) -> Result<PathBuf, ControlError> {
    if !configured.is_empty() {
        let path = PathBuf::from(configured);
        if !path.is_absolute() {
            return Err(ControlError::control_failed(format!(
                "{name} 的配置路径不是绝对路径"
            )));
        }
        if !path.is_file() {
            return Err(ControlError::control_failed(format!(
                "{name} 不存在或不是普通文件: {}",
                path.display()
            )));
        }
        return Ok(path);
    }
    for dir in TOOL_DIRS {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(ControlError::control_failed(format!(
        "找不到 {name}；请在 control 配置里指定绝对路径"
    )))
}

/// 执行命令并等待结果。超时 / 启动失败 / 等待失败都返回 `control_failed`；
/// 非零退出码属于正常结果，由调用方决定如何解释。
pub fn run(
    program: &Path,
    args: &[&str],
    timeout: Duration,
    max_output: usize,
) -> Result<ExecOutput, ControlError> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", CHILD_PATH)
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(|err| {
        ControlError::control_failed(format!("启动 {} 失败: {err}", program.display()))
    })?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ControlError::control_failed("无法捕获命令 stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ControlError::control_failed("无法捕获命令 stderr"))?;
    let stdout_reader = spawn_reader(stdout, max_output);
    let stderr_reader = spawn_reader(stderr, max_output);

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() >= timeout {
                    // 超时：先杀进程再回收，避免留下僵尸；读线程在管道关闭后结束。
                    let _ = child.kill();
                    let _ = child.wait();
                    join_reader(stdout_reader);
                    join_reader(stderr_reader);
                    return Err(ControlError::control_failed(format!(
                        "命令执行超时（{}ms）",
                        timeout.as_millis()
                    )));
                }
                std::thread::sleep(WAIT_POLL);
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                join_reader(stdout_reader);
                join_reader(stderr_reader);
                return Err(ControlError::control_failed(format!(
                    "等待命令退出失败: {err}"
                )));
            }
        }
    };

    let (stdout_bytes, stdout_truncated) = join_reader(stdout_reader);
    let (stderr_bytes, stderr_truncated) = join_reader(stderr_reader);
    Ok(ExecOutput {
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        exit_code: status.code(),
        stdout_truncated,
        stderr_truncated,
    })
}

/// 非零退出 / 被信号终止统一转成 `control_failed`；stderr 只保留摘要。
pub fn ensure_success(output: &ExecOutput, what: &str) -> Result<(), ControlError> {
    if output.exit_code == Some(0) {
        return Ok(());
    }
    let code = output
        .exit_code
        .map_or_else(|| "signal".to_string(), |code| code.to_string());
    Err(ControlError::control_failed(format!(
        "{what} 失败（退出码 {code}）: {}",
        summarize(&output.stderr, 512)
    )))
}

/// 错误消息里使用的安全摘要：控制字符替换为空格并按字符数截断。
pub fn summarize(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, ch) in text.chars().enumerate() {
        if count >= max_chars {
            out.push('…');
            break;
        }
        out.push(if ch.is_control() { ' ' } else { ch });
    }
    out.trim().to_string()
}

fn spawn_reader<R>(reader: R, cap: usize) -> JoinHandle<(Vec<u8>, bool)>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || read_capped(reader, cap))
}

fn join_reader(handle: JoinHandle<(Vec<u8>, bool)>) -> (Vec<u8>, bool) {
    handle.join().unwrap_or_else(|_| (Vec::new(), true))
}

/// 只保留前 `cap` 字节，但继续读空管道，防止子进程因写满 pipe buffer 卡死。
fn read_capped<R: Read>(mut reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; READ_CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(read) => {
                let room = cap.saturating_sub(kept.len());
                if room == 0 {
                    truncated = true;
                    continue;
                }
                let take = room.min(read);
                kept.extend_from_slice(&buf[..take]);
                if take < read {
                    truncated = true;
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    (kept, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rb-agent-exec-{}-{tag}-{seq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 写一个 0755 的 shell 脚本；脚本里不能依赖自定义环境变量（执行时 env_clear）。
    fn write_script(dir: &Path, name: &str, body: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
        path
    }

    #[test]
    fn resolve_tool_prefers_configured_absolute_path() {
        let dir = temp_dir("resolve");
        let script = write_script(&dir, "fake-tool", "exit 0");
        let resolved = resolve_tool(script.to_str().unwrap(), "systemctl").unwrap();
        assert_eq!(resolved, script);

        let err = resolve_tool("relative/tool", "systemctl").unwrap_err();
        assert_eq!(err.code, rustboard_common::control::codes::CONTROL_FAILED);
        assert!(err.message.contains("绝对路径"), "{}", err.message);

        let err = resolve_tool("/definitely/not/here/tool", "systemctl").unwrap_err();
        assert!(err.message.contains("不存在"), "{}", err.message);

        // 留空时从固定候选目录找到常见工具。
        let sh = resolve_tool("", "sh").expect("候选目录里应能找到 sh");
        assert!(sh.is_absolute());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_clear_keeps_only_path_and_lang() {
        let tool = resolve_tool("", "env").expect("env 应存在");
        let out = run(&tool, &[], Duration::from_secs(5), 4096).unwrap();
        assert_eq!(out.exit_code, Some(0));
        let mut lines: Vec<&str> = out.stdout.lines().collect();
        lines.sort_unstable();
        assert_eq!(lines, ["LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"]);
        assert!(!out.stdout.contains("HOME="), "env_clear 后不应继承 HOME");
        assert!(
            !out.stdout.contains("CARGO"),
            "env_clear 后不应继承 CARGO_*"
        );
    }

    #[test]
    fn timeout_kills_command_and_returns_control_failed() {
        let dir = temp_dir("timeout");
        // exec sleep：kill 直接命中 sleep，读线程随管道关闭退出，不会等满 5s。
        let script = write_script(&dir, "hang", "exec sleep 5");
        let started = Instant::now();
        let err = run(&script, &[], Duration::from_millis(100), 1024)
            .err()
            .expect("超时命令必须失败");
        assert_eq!(err.code, rustboard_common::control::codes::CONTROL_FAILED);
        assert!(err.message.contains("超时"), "错误信息: {}", err.message);
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "超时 kill 后不应继续阻塞: {:?}",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_output_is_truncated_with_marker() {
        let dir = temp_dir("truncate");
        let script = write_script(&dir, "noisy", "head -c 300000 /dev/zero");
        let out = run(&script, &[], Duration::from_secs(5), 1024).unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout_truncated, "超过上限必须标记截断");
        assert_eq!(out.stdout.len(), 1024, "只保留前 1024 字节");
        assert!(!out.stderr_truncated);

        let result = out.into_action_output();
        match result {
            ControlResult::ActionOutput { stdout, .. } => {
                assert!(stdout.ends_with(TRUNCATED_MARKER));
                assert_eq!(stdout.len(), 1024 + TRUNCATED_MARKER.len());
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_zero_exit_is_a_result_not_a_transport_error() {
        let dir = temp_dir("exit");
        let script = write_script(&dir, "fails", "printf 'oops' >&2\nexit 7");
        let out = run(&script, &[], Duration::from_secs(5), 4096).unwrap();
        assert_eq!(out.exit_code, Some(7));
        assert_eq!(out.stderr, "oops");
        assert_eq!(out.stdout, "");

        let err = ensure_success(&out, "fake").unwrap_err();
        assert!(err.message.contains("退出码 7"), "{}", err.message);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_program_returns_control_failed() {
        let err = run(
            Path::new("/definitely/not/here/program"),
            &[],
            Duration::from_secs(1),
            1024,
        )
        .err()
        .expect("缺失工具必须失败");
        assert_eq!(err.code, rustboard_common::control::codes::CONTROL_FAILED);
        assert!(err.message.contains("启动"), "{}", err.message);
    }

    #[test]
    fn summarize_escapes_control_chars_and_truncates() {
        let text = "a\nb\tc".to_string() + &"x".repeat(100);
        let summary = summarize(&text, 5);
        assert!(!summary.contains('\n'));
        assert!(!summary.contains('\t'));
        assert_eq!(summary.chars().count(), 6, "5 个字符 + 省略号");
    }
}
