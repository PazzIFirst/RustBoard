//! 无 shell 的外部命令执行：参数数组、环境变量白名单、超时与输出截断。
//!
//! 安全 / 资源约束：
//! - 一律 `Command::new(绝对路径).args([...])`，不经过 shell；
//! - `env_clear()` 后只保留固定的 `PATH` 与 `LANG=C`；
//! - Unix 下子进程通过 `process_group(0)` 成为独立进程组组长；超时或父进程已退出
//!   但后代仍持有输出管道时，对**整个进程组**发 `SIGKILL` 并回收；
//! - stdout / stderr 设为非阻塞，用 `poll(2)` + deadline 读取，不创建无法取消的
//!   reader 线程；每次唤醒最多读固定次数，deadline 始终可检查；
//! - 每个流只保留前 `max_output` 字节，超出部分继续读空防止子进程写满管道阻塞。

use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;

use rustboard_common::config::ControlConfig;
use rustboard_common::control::{ControlError, ControlResult, TRUNCATED_MARKER};

/// 工具绝对路径的固定候选目录（配置留空时按顺序探测）。
pub const TOOL_DIRS: [&str; 4] = ["/usr/bin", "/bin", "/usr/sbin", "/sbin"];
/// 子进程唯一的 `PATH`；必须配合 `env_clear()` 使用。
pub const CHILD_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

const READ_CHUNK: usize = 8 * 1024;
const WAIT_POLL: Duration = Duration::from_millis(10);
/// 父进程退出后等待后代关闭输出管道的宽限时间；超过则杀掉整个进程组。
const READER_GRACE: Duration = Duration::from_millis(500);
/// 杀掉进程组后等待管道 EOF 的宽限时间。仍不 EOF 就关闭读端，绝不无限等待。
const KILL_DRAIN_GRACE: Duration = Duration::from_millis(250);
/// 每次 poll 唤醒最多读多少次：高速写入时也要回到主循环检查 deadline。
const MAX_DRAIN_READS: usize = 64;

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
    // 独立进程组：超时 / 后代持有管道时可以一次结束命令及其全部后代。
    command.process_group(0);

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

    if let Err(err) =
        set_nonblocking(stdout.as_raw_fd()).and_then(|()| set_nonblocking(stderr.as_raw_fd()))
    {
        // 子进程可能已经阻塞在写管道上；先结束整组再回收，避免留下卡死的命令。
        let _ = kill_process_group(child.id());
        let _ = child.wait();
        return Err(ControlError::control_failed(format!(
            "设置命令输出管道非阻塞失败: {err}"
        )));
    }

    let mut pipes = [OutputPipe::new(stdout), OutputPipe::new(stderr)];
    let started = Instant::now();
    let deadline = started + timeout;

    loop {
        // 先观察退出但**不回收**：进程保持 zombie，PID 在后续 killpg 前不会被复用，
        // 因此“父进程已退出、后代仍持有管道”时杀进程组不会误伤新进程。
        match child_exited_without_reaping(&child) {
            Ok(true) => break,
            Ok(false) => {}
            Err(err) => {
                let _ = kill_process_group(child.id());
                let _ = child.wait();
                drain_until_eof(&mut pipes, max_output, Instant::now() + KILL_DRAIN_GRACE);
                return Err(ControlError::control_failed(format!(
                    "等待命令退出失败: {err}"
                )));
            }
        }

        let now = Instant::now();
        if now >= deadline {
            let _ = kill_process_group(child.id());
            let _ = child.wait();
            drain_until_eof(&mut pipes, max_output, Instant::now() + KILL_DRAIN_GRACE);
            return Err(ControlError::control_failed(format!(
                "命令执行超时（{}ms）",
                timeout.as_millis()
            )));
        }

        let wait = (deadline - now).min(WAIT_POLL);
        if let Err(err) = wait_readable(&pipes, wait) {
            let _ = kill_process_group(child.id());
            let _ = child.wait();
            drain_until_eof(&mut pipes, max_output, Instant::now() + KILL_DRAIN_GRACE);
            return Err(ControlError::control_failed(format!(
                "等待命令输出失败: {err}"
            )));
        }
        for pipe in &mut pipes {
            if !pipe.eof {
                pipe.drain(max_output);
            }
        }
    }

    // 子进程已退出：先把管道读空。若后代仍持有写端（例如 `sleep 30 &`），
    // READER_GRACE 内等不到 EOF 就杀整组，再给一小段回收时间。
    drain_until_eof(&mut pipes, max_output, Instant::now() + READER_GRACE);
    if pipes.iter().any(|pipe| !pipe.eof) {
        match kill_process_group(child.id()) {
            Ok(()) => tracing::warn!(
                pid = child.id(),
                "命令父进程已退出但后代仍持有输出管道，已结束整个进程组"
            ),
            Err(err) => tracing::warn!(
                pid = child.id(),
                error = %err,
                "命令后代仍持有输出管道，结束进程组失败"
            ),
        }
        drain_until_eof(&mut pipes, max_output, Instant::now() + KILL_DRAIN_GRACE);
    }
    if pipes.iter().any(|pipe| !pipe.eof) {
        // 后代脱离进程组且仍持有管道（例如自行 setsid）。没有 reader 线程，
        // 关闭读端即可返回，不会泄漏线程或无限等待；记录错误供运维排查。
        tracing::error!(
            pid = child.id(),
            "命令后代进程未在宽限期内退出；关闭输出管道并返回"
        );
    }

    // waitid 只观察不回收，这里才真正 reap；失败则无法确认退出状态。
    let status = child
        .wait()
        .map_err(|err| ControlError::control_failed(format!("回收命令进程失败: {err}")))?;
    let [stdout_pipe, stderr_pipe] = pipes;
    let (stdout_bytes, stdout_truncated) = stdout_pipe.finish();
    let (stderr_bytes, stderr_truncated) = stderr_pipe.finish();
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

/// 子进程退出但没有被 `wait` 回收时返回 `true`。
///
/// 使用 `waitid(..., WNOWAIT)` 只观察、不 reap：保留 zombie 可以让 PID（同时是
/// 进程组 ID）在后续 `killpg` 之前不被内核复用。真正的回收在 [`run`] 末尾的
/// `child.wait()` 完成。
fn child_exited_without_reaping(child: &Child) -> std::io::Result<bool> {
    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "子进程 PID 超出范围"))?;
    // SAFETY: siginfo_t 是内核写入的 POD 结构；调用前清零，waitid 只写该结构。
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: pid 是本进程刚 spawn 的子进程；info 是本次调用内有效的可写指针。
    let rc = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if rc == 0 {
        // si_pid == 0 表示还没有已退出的子进程。
        return Ok(unsafe { info.si_pid() } != 0);
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == ErrorKind::Interrupted {
        return Ok(false);
    }
    Err(err)
}

/// 对子进程所在的独立进程组发 `SIGKILL`。
///
/// `process_group(0)` 保证 PGID == 子进程 PID。组已经不存在（后代全部退出）
/// 时视为成功；其他错误向上报告，由调用方记录。
fn kill_process_group(pid: u32) -> std::io::Result<()> {
    let pgid = libc::pid_t::try_from(pid)
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "进程组 ID 超出范围"))?;
    // SAFETY: kill(2) 只接收整数；负 PGID 表示进程组，信号固定为 SIGKILL。
    let rc = unsafe { libc::kill(-pgid, libc::SIGKILL) };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(err)
}

/// 把 pipe 设为非阻塞读，配合 `poll(2)` 实现可取消的 deadline 读取。
fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl 只操作整数 fd 与标志位，不涉及 Rust 侧内存所有权。
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: 同上；F_SETFL 只修改该 fd 的文件状态标志。
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// 等待任一未 EOF 的管道可读，或超时。
fn wait_readable(pipes: &[OutputPipe; 2], timeout: Duration) -> std::io::Result<()> {
    let mut fds: Vec<libc::pollfd> = pipes
        .iter()
        .filter(|pipe| !pipe.eof)
        .map(|pipe| libc::pollfd {
            fd: pipe.fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    if fds.is_empty() {
        // 两个流都已 EOF 但子进程尚未退出：有界睡眠，避免忙等。
        std::thread::sleep(timeout.min(WAIT_POLL));
        return Ok(());
    }
    let millis = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    loop {
        // SAFETY: fds 是本函数内有效的数组；长度与指针一致，内核只写 revents。
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis) };
        if ready >= 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

/// stdout / stderr 的公共读接口：两者都是 `Read + AsRawFd`，但类型不同，
/// 用 trait object 放进同一个数组。
trait ReadFd: Read + AsRawFd {}
impl<T: Read + AsRawFd> ReadFd for T {}

/// 非阻塞读取一个输出流；EOF / 读错误都把该流标记为结束。
struct OutputPipe {
    reader: Box<dyn ReadFd>,
    fd: RawFd,
    kept: Vec<u8>,
    truncated: bool,
    eof: bool,
}

impl OutputPipe {
    fn new<R: Read + AsRawFd + 'static>(reader: R) -> Self {
        let fd = reader.as_raw_fd();
        Self {
            reader: Box::new(reader),
            fd,
            kept: Vec::new(),
            truncated: false,
            eof: false,
        }
    }

    /// 只保留前 `cap` 字节，但继续读空管道，防止子进程因写满 pipe buffer 卡死。
    fn drain(&mut self, cap: usize) {
        let mut buf = [0u8; READ_CHUNK];
        for _ in 0..MAX_DRAIN_READS {
            match self.reader.read(&mut buf) {
                Ok(0) => {
                    self.eof = true;
                    return;
                }
                Ok(read) => {
                    let room = cap.saturating_sub(self.kept.len());
                    if room == 0 {
                        self.truncated = true;
                        continue;
                    }
                    let take = room.min(read);
                    self.kept.extend_from_slice(&buf[..take]);
                    if take < read {
                        self.truncated = true;
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => return,
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(_) => {
                    self.eof = true;
                    return;
                }
            }
        }
    }

    fn finish(self) -> (Vec<u8>, bool) {
        (self.kept, self.truncated)
    }
}

/// 在 deadline 内持续读空两个管道；deadline 到期或全部 EOF 即返回。
fn drain_until_eof(pipes: &mut [OutputPipe; 2], cap: usize, deadline: Instant) {
    loop {
        for pipe in pipes.iter_mut() {
            if !pipe.eof {
                pipe.drain(cap);
            }
        }
        if pipes.iter().all(|pipe| pipe.eof) {
            return;
        }
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let wait = (deadline - now).min(WAIT_POLL);
        if let Err(err) = wait_readable(pipes, wait) {
            tracing::debug!(error = %err, "等待命令输出管道失败，提前结束读取");
            return;
        }
    }
}

/// 测试用全局锁：多个测试会写临时可执行脚本并 spawn 子进程；并行 fork 时
/// 另一个线程继承的写 fd 会让 exec 偶发 ETXTBSY。串行化所有 spawn 测试。
#[cfg(test)]
pub(crate) fn test_serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
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

    fn sh() -> PathBuf {
        resolve_tool("", "sh").expect("候选目录里应能找到 sh")
    }

    /// 当前进程打开的文件描述符数量（用于泄漏回归）。
    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|entries| entries.count())
            .unwrap_or(0)
    }

    /// 当前进程线程数量（用于泄漏回归）。
    fn thread_count() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|status| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix("Threads:")?.trim().parse::<usize>().ok())
            })
            .unwrap_or(0)
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
        let _guard = test_serial_guard();
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
        let _guard = test_serial_guard();
        let dir = temp_dir("timeout");
        // exec sleep：kill 进程组后管道关闭，读取有界结束，不会等满 5s。
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

    /// #46：父 shell 在前台 `wait` 一个后台 sleep 时，超时必须杀掉整个进程组，
    /// 而不是只杀 sh 后继续等后台 sleep 关管道。
    #[test]
    fn timeout_kills_whole_process_group() {
        let _guard = test_serial_guard();
        let sh = sh();
        let started = Instant::now();
        let err = run(
            &sh,
            &["-c", "sleep 2 & wait"],
            Duration::from_millis(100),
            1024,
        )
        .err()
        .expect("超时必须失败");
        assert_eq!(err.code, rustboard_common::control::codes::CONTROL_FAILED);
        assert!(err.message.contains("超时"), "错误信息: {}", err.message);
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "必须杀掉整个进程组，不能等后台 sleep 自然结束: {:?}",
            started.elapsed()
        );
    }

    /// #46：父进程立即退出、后台后代持有 stdout/stderr 时，读取必须在
    /// READER_GRACE 内结束，并杀掉后代，避免命令永久挂住。
    #[test]
    fn parent_exit_with_background_descendant_is_bounded_and_killed() {
        let _guard = test_serial_guard();
        let dir = temp_dir("bg-descendant");
        let marker = dir.join("descendant-alive");
        let sh = sh();
        // 后台子 shell 1s 后写 marker；父 shell 立即退出。若没有 killpg，
        // marker 会在宽限期后被写出，测试失败。
        let body = format!("(sleep 1; echo alive > '{}') &", marker.display());
        let started = Instant::now();
        let out = run(&sh, &["-c", &body], Duration::from_secs(5), 1024)
            .expect("父进程正常退出本身不是错误");
        let elapsed = started.elapsed();
        assert_eq!(out.exit_code, Some(0));
        assert!(
            elapsed < Duration::from_secs(3),
            "后代持有管道时必须在 grace 内返回: {elapsed:?}"
        );

        std::thread::sleep(Duration::from_millis(1_200));
        assert!(
            !marker.exists(),
            "后台后代必须在 grace 内被 killpg 结束，不能继续执行"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #46：连续超时不得泄漏 FD / 线程。用独立子进程运行探针，避免其他并行
    /// 测试的临时 FD / 线程干扰计数。
    #[test]
    fn repeated_timeouts_do_not_leak_fds_or_threads() {
        let _guard = test_serial_guard();
        if std::env::var_os("RUSTBOARD_EXEC_LEAK_PROBE").is_some() {
            let sh = sh();
            let before = (open_fd_count(), thread_count());
            for _ in 0..12 {
                let err = run(
                    &sh,
                    &["-c", "sleep 30 & wait"],
                    Duration::from_millis(20),
                    256,
                )
                .err()
                .expect("超时必须失败");
                assert!(err.message.contains("超时"), "{}", err.message);
            }
            let after = (open_fd_count(), thread_count());
            println!(
                "EXEC_LEAK_PROBE fd_before={} fd_after={} threads_before={} threads_after={}",
                before.0, after.0, before.1, after.1
            );
            return;
        }

        let exe = std::env::current_exe().expect("无法定位测试二进制");
        let output = Command::new(exe)
            .arg("--exact")
            .arg("control::exec::tests::repeated_timeouts_do_not_leak_fds_or_threads")
            .arg("--nocapture")
            .env("RUSTBOARD_EXEC_LEAK_PROBE", "1")
            .output()
            .expect("无法启动泄漏检测子进程");
        assert!(
            output.status.success(),
            "泄漏检测子进程失败: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        // 先去掉 "EXEC_LEAK_PROBE " 前缀再取值。
        let fields: Vec<&str> = stdout
            .lines()
            .find_map(|line| line.strip_prefix("EXEC_LEAK_PROBE "))
            .unwrap_or_else(|| panic!("探针没有输出计数: {stdout}"))
            .split_whitespace()
            .collect();
        let mut values = std::collections::HashMap::new();
        for field in fields {
            if let Some((key, value)) = field.split_once('=') {
                values.insert(key, value.parse::<usize>().unwrap());
            }
        }
        let fd_before = values["fd_before"];
        let fd_after = values["fd_after"];
        let threads_before = values["threads_before"];
        let threads_after = values["threads_after"];
        assert!(
            fd_after <= fd_before,
            "连续超时泄漏 FD: before={fd_before} after={fd_after}"
        );
        assert!(
            threads_after <= threads_before,
            "连续超时泄漏线程: before={threads_before} after={threads_after}"
        );
    }

    #[test]
    fn large_output_is_truncated_with_marker() {
        let _guard = test_serial_guard();
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
        let _guard = test_serial_guard();
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
        let _guard = test_serial_guard();
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
