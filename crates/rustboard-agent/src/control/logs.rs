//! 只读日志：白名单文件 tail（`openat2` 防逃逸）与 journald tail。
//!
//! 文件日志的防护：
//! - 启动时校验父目录存在、不是符号链接、路径不经过符号链接；target 本身也必须是
//!   普通文件（不存在则允许，读取时报错）；
//! - 读取时以父目录 fd + 文件名调用 Linux `openat2(2)`，使用
//!   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`；
//! - `O_NONBLOCK` 打开后再 `fstat`，只接受普通文件；FIFO / 设备 / 目录一律拒绝，
//!   避免日志文件被替换成 FIFO 后永久阻塞控制线程；
//! - 内核不支持 `openat2`（ENOSYS）时直接失败并返回错误，**不降级**到 `fs::read`；
//! - 只从文件尾部倒读，最多 2000 行、单行 4096 字节、总输出 256 KiB。

use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use anyhow::{bail, Context};
use rustboard_common::config::{ControlConfig, LogSourceConfig, LogSourceKind};
use rustboard_common::control::{
    self, ControlError, ControlResult, LogSourceInfo, MAX_LIST_ITEMS, MAX_LOG_LINES,
    MAX_LOG_LINE_BYTES, MAX_OUTPUT_BYTES,
};

use super::exec;

/// 倒读时每次读取的块大小。
const READ_CHUNK: usize = 32 * 1024;

// `openat2(2)` 的 resolve 标志；libc crate 只暴露 SYS_openat2，不暴露这些常量。
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

/// `openat2(2)` 的参数结构。字段由内核读取，Rust 侧只负责布局。
#[repr(C)]
#[allow(dead_code)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// 启动时校验所有 file 来源的父目录 / 文件本身（I/O 校验，不做实际读取）。
pub fn validate_sources_io(cfg: &ControlConfig) -> anyhow::Result<()> {
    for source in &cfg.log_sources {
        if source.kind != LogSourceKind::File {
            continue;
        }
        validate_file_source(&source.target)
            .with_context(|| format!("日志来源 {}（{}）校验失败", source.id, source.target))?;
    }
    Ok(())
}

fn validate_file_source(target: &str) -> anyhow::Result<()> {
    let path = Path::new(target);
    let Some(parent) = path.parent() else {
        bail!("日志路径没有父目录");
    };

    let parent_meta = std::fs::symlink_metadata(parent)
        .with_context(|| format!("父目录不存在或不可访问: {}", parent.display()))?;
    if parent_meta.file_type().is_symlink() {
        bail!("父目录是符号链接: {}", parent.display());
    }
    if !parent_meta.is_dir() {
        bail!("父目录不是目录: {}", parent.display());
    }
    // 父目录的任一祖先是符号链接时，canonicalize 结果会与配置路径不同。
    let canonical = std::fs::canonicalize(parent)
        .with_context(|| format!("父目录无法规范化: {}", parent.display()))?;
    if canonical.as_path() != parent {
        bail!(
            "父目录路径经过符号链接或包含非规范分量: {}（实际 {}）",
            parent.display(),
            canonical.display()
        );
    }

    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                bail!("日志文件是符号链接: {}", path.display());
            }
            if !meta.is_file() {
                bail!("日志文件不是普通文件: {}", path.display());
            }
        }
        // 文件尚未创建是允许的（例如 logrotate 正在轮转），真正读取时再报错。
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("检查日志文件失败: {}", path.display()))
        }
    }
    Ok(())
}

/// 只返回配置中的日志来源，不读取文件内容。
pub fn list(cfg: &ControlConfig) -> Result<ControlResult, ControlError> {
    let sources = cfg
        .log_sources
        .iter()
        .take(MAX_LIST_ITEMS)
        .map(|source| LogSourceInfo {
            id: source.id.clone(),
            kind: source.kind,
            target: source.target.clone(),
            name: if source.name.is_empty() {
                source.id.clone()
            } else {
                source.name.clone()
            },
        })
        .collect();
    Ok(ControlResult::LogSources(sources))
}

/// 按配置来源读取末尾日志。`requested_lines` 会被配置上限与协议上限双重截断。
pub fn tail(
    cfg: &ControlConfig,
    source: &LogSourceConfig,
    requested_lines: u32,
) -> Result<ControlResult, ControlError> {
    let upper = cfg.max_log_lines.clamp(1, MAX_LOG_LINES);
    let max_lines = requested_lines.clamp(1, upper) as usize;
    match source.kind {
        LogSourceKind::File => tail_file(&source.target, &source.id, max_lines),
        LogSourceKind::Journal => tail_journal(cfg, source, max_lines),
    }
}

fn tail_file(
    target: &str,
    source_id: &str,
    max_lines: usize,
) -> Result<ControlResult, ControlError> {
    let path = Path::new(target);
    let parent = path
        .parent()
        .ok_or_else(|| ControlError::control_failed("日志路径没有父目录"))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| ControlError::control_failed("日志路径没有文件名"))?;

    let mut file = open_beneath(parent, file_name).map_err(|err| {
        ControlError::control_failed(format!("打开日志文件失败（openat2）: {err}"))
    })?;
    let size = file
        .metadata()
        .map_err(|err| ControlError::control_failed(format!("读取日志文件信息失败: {err}")))?
        .len();
    let (lines, truncated) = read_tail(&mut file, size, max_lines)?;
    Ok(ControlResult::LogLines {
        source: source_id.to_string(),
        lines,
        truncated,
        size_bytes: size,
    })
}

fn tail_journal(
    cfg: &ControlConfig,
    source: &LogSourceConfig,
    max_lines: usize,
) -> Result<ControlResult, ControlError> {
    let unit = source.target.as_str();
    // 配置层已校验；执行层再校验一次，防止运行时配置被绕过。
    if !control::unit_allowed(unit, &cfg.systemd_units) {
        return Err(ControlError::not_whitelisted("journal 日志来源不在白名单"));
    }
    let tool = exec::resolve_tool(&cfg.journalctl_path, "journalctl")?;
    let lines_arg = max_lines.to_string();
    // `--reverse` 让 journalctl 按新→旧输出；`exec::run` 的 `read_capped` 只保留
    // 前 256 KiB，此时留下的正好是最新内容，而不是最旧内容。
    let output = exec::run(
        &tool,
        &[
            "-u",
            unit,
            "-n",
            lines_arg.as_str(),
            "--no-pager",
            "--reverse",
            "-o",
            "short-iso",
        ],
        exec::command_timeout(cfg),
        MAX_OUTPUT_BYTES,
    )?;
    exec::ensure_success(&output, "journalctl")?;

    let mut truncated = output.stdout_truncated;
    // 注意不能用 `str::lines()`：判断末尾是否有换行关系到能否识别被截断的半行。
    let ends_with_newline = output.stdout.ends_with('\n');
    let mut raw_lines: Vec<&str> = output.stdout.split('\n').collect();
    if raw_lines.last().is_some_and(|line| line.is_empty()) {
        // 末尾换行产生的空段不是日志行。
        raw_lines.pop();
    }
    if output.stdout_truncated && !ends_with_newline {
        // 输出被 256 KiB 上限截断且末行不完整：--reverse 下它是已保留内容里最旧的
        // 一条半行，必须丢弃，不能返回给客户端。
        raw_lines.pop();
    }
    // 反转回旧→新，后续 max_lines / cap_output 才能继续丢最旧行。
    raw_lines.reverse();

    let mut lines = Vec::with_capacity(raw_lines.len());
    for raw in raw_lines {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if line.is_empty() {
            continue;
        }
        lines.push(truncate_line(line, MAX_LOG_LINE_BYTES, &mut truncated));
    }
    if lines.len() > max_lines {
        let drop_count = lines.len() - max_lines;
        lines.drain(..drop_count);
        truncated = true;
    }
    let (lines, output_truncated) = cap_output(lines);
    truncated |= output_truncated;
    Ok(ControlResult::LogLines {
        source: source.id.clone(),
        lines,
        truncated,
        // journal 为截断后保留的 stdout 字节数，不是 journalctl 原始总输出；
        // 文件日志仍是文件总字节数。
        size_bytes: output.stdout.len() as u64,
    })
}

/// 从文件尾部倒读最多 `max_lines` 行。
fn read_tail(
    file: &mut File,
    size: u64,
    max_lines: usize,
) -> Result<(Vec<String>, bool), ControlError> {
    if size == 0 || max_lines == 0 {
        return Ok((Vec::new(), false));
    }

    let read_budget = MAX_OUTPUT_BYTES + MAX_LOG_LINE_BYTES;
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut pos = size;
    let mut newlines = 0usize;
    let mut read_bytes = 0usize;
    let mut reached_start = false;
    let mut budget_hit = false;
    let mut file_changed = false;

    loop {
        if pos == 0 {
            reached_start = true;
            break;
        }
        let take = (READ_CHUNK as u64).min(pos) as usize;
        pos -= take as u64;
        let chunk = read_at(file, pos, take)
            .map_err(|err| ControlError::control_failed(format!("读取日志文件失败: {err}")))?;
        if chunk.is_empty() {
            // 文件在读取期间被清空 / 截断；已读内容是当前可用的全部数据。
            reached_start = true;
            file_changed = true;
            break;
        }
        let short = chunk.len() < take;
        newlines += chunk.iter().filter(|byte| **byte == b'\n').count();
        read_bytes += chunk.len();
        chunks.push(chunk);
        if short {
            reached_start = true;
            file_changed = true;
            break;
        }
        if newlines > max_lines {
            break;
        }
        if read_bytes >= read_budget {
            budget_hit = true;
            break;
        }
    }

    let mut bytes = Vec::with_capacity(read_bytes);
    for chunk in chunks.iter().rev() {
        bytes.extend_from_slice(chunk);
    }
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let mut segments: Vec<String> = text.split('\n').map(str::to_string).collect();
    if segments.last().is_some_and(String::is_empty) {
        segments.pop();
    }

    let mut truncated = budget_hit || file_changed;
    if !reached_start && !segments.is_empty() {
        if segments.len() == 1 {
            // 整个可读尾部只是某一行的一部分：按单行 tail 返回，但明确标记截断。
            truncated = true;
        } else {
            // 首段可能是从文件中间截断的半行；停止条件保证后面还有足够行数。
            segments.remove(0);
        }
    }

    let start = segments.len().saturating_sub(max_lines);
    let mut lines = Vec::with_capacity(segments.len() - start);
    for line in &segments[start..] {
        let line = line.strip_suffix('\r').unwrap_or(line);
        lines.push(truncate_line(line, MAX_LOG_LINE_BYTES, &mut truncated));
    }
    let (lines, capped) = cap_output(lines);
    truncated |= capped;
    Ok((lines, truncated))
}

/// 从 `offset` 读取最多 `len` 字节；文件变短时返回实际读到的部分。
fn read_at(file: &mut File, offset: u64, len: usize) -> io::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut chunk = vec![0u8; len];
    let mut filled = 0usize;
    while filled < len {
        match file.read(&mut chunk[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    chunk.truncate(filled);
    Ok(chunk)
}

/// 单行按字节上限截断，保证落在 UTF-8 字符边界。
fn truncate_line(line: &str, max_bytes: usize, truncated: &mut bool) -> String {
    if line.len() <= max_bytes {
        return line.to_string();
    }
    *truncated = true;
    let mut end = max_bytes;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    line[..end].to_string()
}

/// 输出总字节上限：从最新一行往前保留，超出的旧行丢弃并标记 truncated。
fn cap_output(lines: Vec<String>) -> (Vec<String>, bool) {
    let mut kept = Vec::with_capacity(lines.len());
    let mut total = 0usize;
    let mut truncated = false;
    for line in lines.into_iter().rev() {
        let needed = line.len().saturating_add(1);
        if total.saturating_add(needed) > MAX_OUTPUT_BYTES && !kept.is_empty() {
            truncated = true;
            break;
        }
        total += needed;
        kept.push(line);
    }
    kept.reverse();
    (kept, truncated)
}

/// 以父目录 fd 为基准打开文件，禁止 `..`、绝对路径、符号链接与跨挂载点。
fn open_beneath(parent: &Path, file_name: &OsStr) -> io::Result<File> {
    if !parent.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "父目录必须是绝对路径",
        ));
    }
    if file_name.is_empty() || file_name == OsStr::new(".") || file_name == OsStr::new("..") {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "文件名非法"));
    }
    let parent_c = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "父目录包含 NUL"))?;
    let name_c = CString::new(file_name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "文件名包含 NUL"))?;

    // SAFETY: parent_c 是以 NUL 结尾的合法路径；open(2) 只读取该 C 字符串。
    let dirfd = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if dirfd < 0 {
        return Err(io::Error::last_os_error());
    }

    let how = OpenHow {
        // O_NONBLOCK：日志文件若被替换成 FIFO，open 不会因为没有写端而永久阻塞；
        // 打开后再用 fstat 拒绝任何非普通文件。
        flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV,
    };
    // SAFETY: openat2(2) 只读取 how 指向的 POD 结构；dirfd 与 name_c 在调用期间有效。
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            name_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    let open_err = io::Error::last_os_error();
    // SAFETY: dirfd 由本函数创建，尚未关闭，且没有其他持有者。
    unsafe {
        libc::close(dirfd);
    }
    if fd < 0 {
        // 注意：ENOSYS 也走到这里，按方案不做任何降级读取。
        return Err(open_err);
    }
    // SAFETY: fd 由 openat2(2) 返回，是唯一所有者的文件描述符，交给 File 管理。
    let file = unsafe { File::from_raw_fd(fd as libc::c_int) };
    // 只允许普通文件：FIFO / 设备 / 目录即使被放进白名单目录也要拒绝。
    // 这是 O_NONBLOCK 打开后的二次确认，保证后续 read/seek 不会永久阻塞。
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "日志文件不是普通文件（FIFO / 设备 / 目录）",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};

    fn temp_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("rb-agent-logs-{}-{tag}-{seq}", std::process::id()));
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

    fn cfg_with(sources: Vec<LogSourceConfig>) -> ControlConfig {
        ControlConfig {
            enabled: true,
            logs: true,
            log_sources: sources,
            ..ControlConfig::default()
        }
    }

    fn file_source(id: &str, target: &Path) -> LogSourceConfig {
        LogSourceConfig {
            id: id.to_string(),
            kind: LogSourceKind::File,
            target: target.to_string_lossy().into_owned(),
            name: String::new(),
        }
    }

    fn journal_source(id: &str, unit: &str) -> LogSourceConfig {
        LogSourceConfig {
            id: id.to_string(),
            kind: LogSourceKind::Journal,
            target: unit.to_string(),
            name: "journal".to_string(),
        }
    }

    /// 解析 fake journal 行序号：`line-<序号> ...`。
    fn journal_line_number(line: &str) -> u64 {
        line.strip_prefix("line-")
            .and_then(|rest| rest.split(' ').next())
            .and_then(|number| number.parse().ok())
            .unwrap_or_else(|| panic!("无法解析 fake journal 行: {line}"))
    }

    #[test]
    fn validate_io_accepts_existing_plain_file() {
        let dir = temp_dir("io-ok");
        let log = dir.join("app.log");
        std::fs::write(&log, b"hello\n").unwrap();
        let cfg = cfg_with(vec![file_source("app", &log)]);
        validate_sources_io(&cfg).expect("普通文件应通过启动校验");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_io_rejects_missing_symlinked_and_non_regular_targets() {
        let dir = temp_dir("io-bad");
        let real = dir.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("app.log"), b"hello\n").unwrap();

        // 父目录不存在。
        let missing = dir.join("missing-dir").join("app.log");
        let cfg = cfg_with(vec![file_source("missing", &missing)]);
        assert!(validate_sources_io(&cfg).is_err());

        // 父目录本身是符号链接。
        let link_dir = dir.join("link-dir");
        std::os::unix::fs::symlink(&real, &link_dir).unwrap();
        let cfg = cfg_with(vec![file_source("link-dir", &link_dir.join("app.log"))]);
        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("符号链接"), "{err}");

        // 日志文件本身是符号链接。
        let link_file = dir.join("link.log");
        std::os::unix::fs::symlink(real.join("app.log"), &link_file).unwrap();
        let cfg = cfg_with(vec![file_source("link-file", &link_file)]);
        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("符号链接"), "{err}");

        // target 是目录而不是普通文件。
        let cfg = cfg_with(vec![file_source("dir", &real)]);
        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("不是普通文件"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_returns_last_lines_in_order() {
        let dir = temp_dir("tail");
        let log = dir.join("app.log");
        std::fs::write(&log, b"line1\nline2\nline3\nline4\n").unwrap();
        let cfg = cfg_with(vec![file_source("app", &log)]);

        match tail(&cfg, &cfg.log_sources[0], 2).unwrap() {
            ControlResult::LogLines {
                source,
                lines,
                truncated,
                size_bytes,
            } => {
                assert_eq!(source, "app");
                assert_eq!(lines, ["line3", "line4"]);
                assert!(!truncated);
                assert_eq!(size_bytes, 24);
            }
            other => panic!("意外结果: {other:?}"),
        }

        // 请求行数超过文件行数：返回全部，且不算截断。
        match tail(&cfg, &cfg.log_sources[0], 100).unwrap() {
            ControlResult::LogLines {
                lines, truncated, ..
            } => {
                assert_eq!(lines, ["line1", "line2", "line3", "line4"]);
                assert!(!truncated);
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_clamps_to_config_max_lines() {
        let dir = temp_dir("clamp");
        let log = dir.join("app.log");
        std::fs::write(&log, b"1\n2\n3\n4\n5\n").unwrap();
        let mut cfg = cfg_with(vec![file_source("app", &log)]);
        cfg.max_log_lines = 2;
        match tail(&cfg, &cfg.log_sources[0], MAX_LOG_LINES).unwrap() {
            ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["4", "5"]),
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_truncates_long_lines_and_handles_crlf() {
        let dir = temp_dir("long-line");
        let log = dir.join("app.log");
        let long = "a".repeat(MAX_LOG_LINE_BYTES + 1000);
        std::fs::write(&log, format!("short\r\n{long}\n")).unwrap();
        let cfg = cfg_with(vec![file_source("app", &log)]);
        match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
            ControlResult::LogLines {
                lines, truncated, ..
            } => {
                assert_eq!(lines[0], "short", "CRLF 必须去掉 \\r");
                assert_eq!(lines[1].len(), MAX_LOG_LINE_BYTES);
                assert!(truncated, "单行超长必须标记截断");
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_enforces_total_output_cap() {
        let dir = temp_dir("output-cap");
        let log = dir.join("app.log");
        let mut content = String::new();
        for index in 0..200 {
            content.push_str(&format!("{index:04}-{}\n", "x".repeat(2000)));
        }
        std::fs::write(&log, content).unwrap();
        let cfg = cfg_with(vec![file_source("app", &log)]);
        match tail(&cfg, &cfg.log_sources[0], 200).unwrap() {
            ControlResult::LogLines {
                lines, truncated, ..
            } => {
                assert!(truncated, "超过 256 KiB 必须标记截断");
                assert!(!lines.is_empty());
                assert!(lines.len() < 200, "必须丢去部分旧行");
                let total: usize = lines.iter().map(|line| line.len() + 1).sum();
                assert!(total <= MAX_OUTPUT_BYTES, "输出总量超限: {total}");
                assert!(
                    lines.last().unwrap().starts_with("0199-"),
                    "必须保留最新一行"
                );
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn openat2_rejects_parent_absolute_and_symlink_escapes() {
        let dir = temp_dir("escape");
        std::fs::write(dir.join("ok.log"), b"ok\n").unwrap();
        open_beneath(&dir, OsStr::new("ok.log")).expect("白名单文件必须能打开");

        for name in ["../etc/passwd", "/etc/passwd", "sub/../../etc/passwd"] {
            assert!(
                open_beneath(&dir, OsStr::new(name)).is_err(),
                "{name} 必须被拒绝"
            );
        }

        std::os::unix::fs::symlink("/etc/hostname", dir.join("evil.log")).unwrap();
        let err = open_beneath(&dir, OsStr::new("evil.log")).unwrap_err();
        assert!(
            matches!(
                err.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::EXDEV) | Some(libc::EACCES)
            ),
            "符号链接必须被 openat2 拒绝，实际: {err:?}"
        );

        // 父目录不是绝对路径时直接拒绝。
        assert!(open_beneath(Path::new("relative"), OsStr::new("x")).is_err());

        // 目录同样不是普通文件，打开后必须被拒绝。
        std::fs::create_dir(dir.join("subdir")).unwrap();
        assert!(
            open_beneath(&dir, OsStr::new("subdir")).is_err(),
            "目录必须被拒绝"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 安全回归：日志文件被替换成 FIFO 时，打开必须立即失败而不是阻塞控制线程。
    #[test]
    fn fifo_log_target_is_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;

        let dir = temp_dir("fifo");
        let fifo = dir.join("app.fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_c 是以 NUL 结尾的合法路径，mkfifo(2) 只读取该 C 字符串。
        let rc = unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo 失败: {}", io::Error::last_os_error());

        // 启动校验：已存在的 FIFO 不是普通文件，必须拒绝启动。
        let cfg = cfg_with(vec![file_source("fifo", &fifo)]);
        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("不是普通文件"), "{err}");

        // 运行期（启动后文件被替换成 FIFO）：tail 必须快速返回错误，不能挂起。
        let started = Instant::now();
        let err = tail(&cfg, &cfg.log_sources[0], 10).expect_err("FIFO 必须被拒绝");
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(
            err.message.contains("普通文件") || err.message.contains("openat2"),
            "错误信息应说明非普通文件: {}",
            err.message
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "FIFO 打开不能阻塞: {:?}",
            started.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_returns_only_configured_sources() {
        let cfg = cfg_with(vec![
            LogSourceConfig {
                id: "first".into(),
                kind: LogSourceKind::File,
                target: "/var/log/first.log".into(),
                name: String::new(),
            },
            LogSourceConfig {
                id: "second".into(),
                kind: LogSourceKind::Journal,
                target: "nginx.service".into(),
                name: "Nginx".into(),
            },
        ]);
        match list(&cfg).unwrap() {
            ControlResult::LogSources(sources) => {
                assert_eq!(sources.len(), 2);
                assert_eq!(sources[0].id, "first");
                assert_eq!(sources[0].name, "first", "空 name 回退为 id");
                assert_eq!(sources[1].name, "Nginx");
            }
            other => panic!("意外结果: {other:?}"),
        }
    }

    #[test]
    fn journal_tail_uses_fixed_args_for_whitelisted_unit() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("journal");
        let args_file = dir.join("args.txt");
        // `--reverse` 后 journalctl 的输出是新→旧：two 在 one 之前。
        let script = write_script(
            &dir,
            "journalctl",
            &format!(
                "printf '%s\\n' \"$@\" > {}\nprintf '2026-10-22T10:00:01+00:00 host app: two\\n2026-10-22T10:00:00+00:00 host app: one\\n'",
                args_file.display()
            ),
        );
        let mut cfg = cfg_with(vec![journal_source("j", "nginx.service")]);
        cfg.systemd_units = vec!["nginx*".into()];
        cfg.journalctl_path = script.to_str().unwrap().to_string();

        match tail(&cfg, &cfg.log_sources[0], 5).unwrap() {
            ControlResult::LogLines {
                source,
                lines,
                truncated,
                size_bytes,
            } => {
                assert_eq!(source, "j");
                assert_eq!(lines.len(), 2);
                assert!(lines[0].contains("one"), "旧行必须在前: {lines:?}");
                assert!(lines[1].contains("two"), "最新行必须最后: {lines:?}");
                assert!(!truncated, "小于 256 KiB 且未超行数不应标记截断");
                assert_eq!(size_bytes, 80, "size_bytes 应为实际保留的 stdout 字节数");
            }
            other => panic!("意外结果: {other:?}"),
        }
        let args = std::fs::read_to_string(&args_file).unwrap();
        assert!(
            args.lines().any(|arg| arg == "--reverse"),
            "journalctl 必须使用 --reverse 让输出变为新→旧: {args}"
        );
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            [
                "-u",
                "nginx.service",
                "-n",
                "5",
                "--no-pager",
                "--reverse",
                "-o",
                "short-iso"
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// #19 核心回归：journalctl 输出远超 256 KiB 时必须保留最新内容并恢复旧→新顺序。
    #[test]
    fn journal_tail_keeps_newest_lines_when_output_is_truncated() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("journal-big");
        // 新→旧输出 line-1000…line-1，每行约 1 KiB，总量约 1 MiB；read_capped
        // 只保留前 256 KiB，即最新的一批行。
        let script = write_script(
            &dir,
            "journalctl",
            r#"awk 'BEGIN {
    pad = sprintf("%1023s", "");
    gsub(/ /, "x", pad);
    for (i = 1000; i >= 1; i--) {
        printf "line-%d %s\n", i, pad;
    }
}'"#,
        );
        let mut cfg = cfg_with(vec![journal_source("j", "nginx.service")]);
        cfg.systemd_units = vec!["nginx*".into()];
        cfg.journalctl_path = script.to_str().unwrap().to_string();

        match tail(&cfg, &cfg.log_sources[0], MAX_LOG_LINES).unwrap() {
            ControlResult::LogLines {
                lines,
                truncated,
                size_bytes,
                ..
            } => {
                assert!(truncated, "丢弃较旧内容必须标记 truncated");
                assert!(!lines.is_empty());
                assert!(lines.len() < 1000, "超过 256 KiB 必须丢弃较旧行");
                let pad = "x".repeat(1023);
                assert!(
                    lines.iter().all(|line| line.ends_with(&pad)),
                    "不能返回被截断的半行"
                );
                let numbers: Vec<u64> =
                    lines.iter().map(|line| journal_line_number(line)).collect();
                assert_eq!(
                    *numbers.last().unwrap(),
                    1000,
                    "最新一行 line-1000 必须保留"
                );
                assert!(*numbers.first().unwrap() < 1000, "必须丢弃最旧的部分行");
                assert!(
                    numbers.windows(2).all(|pair| pair[1] == pair[0] + 1),
                    "返回顺序必须是旧→新且连续: {numbers:?}"
                );
                let total: usize = lines.iter().map(|line| line.len() + 1).sum();
                assert!(total <= MAX_OUTPUT_BYTES, "输出总量超限: {total}");
                assert_eq!(
                    size_bytes, MAX_OUTPUT_BYTES as u64,
                    "size_bytes 是截断后保留的 stdout 字节数"
                );
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 输出恰好在行中间被 256 KiB 上限截断：丢弃末尾半行，保留最新完整行。
    #[test]
    fn journal_tail_drops_partial_line_at_output_cap() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("journal-partial");
        // 每行恰好 1000 字节（含换行），共 300 行；上限 262144 落在第 263 行中间，
        // 该行是已保留内容里最旧的一条，必须整行丢弃。
        let script = write_script(
            &dir,
            "journalctl",
            r#"awk 'BEGIN {
    pad = sprintf("%990s", "");
    gsub(/ /, "x", pad);
    for (i = 300; i >= 1; i--) {
        printf "line-%03d %s\n", i, pad;
    }
}'"#,
        );
        let mut cfg = cfg_with(vec![journal_source("j", "nginx.service")]);
        cfg.systemd_units = vec!["nginx*".into()];
        cfg.journalctl_path = script.to_str().unwrap().to_string();

        match tail(&cfg, &cfg.log_sources[0], MAX_LOG_LINES).unwrap() {
            ControlResult::LogLines {
                lines,
                truncated,
                size_bytes,
                ..
            } => {
                assert!(truncated);
                assert_eq!(lines.len(), 262, "半行必须丢弃，其余完整行保留");
                assert!(lines.iter().all(|line| line.len() == 999), "不能返回半行");
                assert_eq!(journal_line_number(&lines[0]), 39, "最旧的完整行应保留");
                assert_eq!(
                    journal_line_number(lines.last().unwrap()),
                    300,
                    "最新一行必须保留"
                );
                let numbers: Vec<u64> =
                    lines.iter().map(|line| journal_line_number(line)).collect();
                assert!(
                    numbers.windows(2).all(|pair| pair[1] == pair[0] + 1),
                    "返回顺序必须是旧→新且连续: {numbers:?}"
                );
                assert_eq!(size_bytes, MAX_OUTPUT_BYTES as u64);
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_tail_drops_oldest_lines_beyond_max_lines() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("journal-max-lines");
        let script = write_script(&dir, "journalctl", "printf 'line-3\\nline-2\\nline-1\\n'");
        let mut cfg = cfg_with(vec![journal_source("j", "nginx.service")]);
        cfg.systemd_units = vec!["nginx*".into()];
        cfg.journalctl_path = script.to_str().unwrap().to_string();

        match tail(&cfg, &cfg.log_sources[0], 2).unwrap() {
            ControlResult::LogLines {
                lines, truncated, ..
            } => {
                assert_eq!(lines, ["line-2", "line-3"], "只保留最新 2 行且旧→新");
                assert!(truncated, "丢弃最旧行必须标记 truncated");
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 多字节 UTF-8、CRLF、空行过滤与单行 4096 字节上限在反转后仍按旧→新处理。
    #[test]
    fn journal_tail_handles_utf8_crlf_empty_and_long_lines() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("journal-edge");
        // 新→旧：line-new（最新）、空行、6000 字节汉字的超长行、CRLF 行、line-old。
        let script = write_script(
            &dir,
            "journalctl",
            r#"long=$(yes '汉' | head -n 2000 | tr -d '\n')
printf 'line-new 最新消息\n\nline-long %s\r\nline-crlf 旧日志\r\nline-old 最旧日志\n' "$long""#,
        );
        let mut cfg = cfg_with(vec![journal_source("j", "nginx.service")]);
        cfg.systemd_units = vec!["nginx*".into()];
        cfg.journalctl_path = script.to_str().unwrap().to_string();

        match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
            ControlResult::LogLines {
                lines,
                truncated,
                size_bytes,
                ..
            } => {
                assert_eq!(lines.len(), 4, "空行必须被过滤: {lines:?}");
                assert_eq!(lines[0], "line-old 最旧日志");
                assert_eq!(lines[1], "line-crlf 旧日志", "CRLF 必须去掉 \\r");
                assert!(
                    lines[2].starts_with("line-long "),
                    "超长行必须保留开头: {}",
                    &lines[2][..lines[2].len().min(32)]
                );
                assert_eq!(
                    lines[2].len(),
                    MAX_LOG_LINE_BYTES,
                    "单行超过 4096 字节必须按字节上限截断"
                );
                assert!(
                    lines[2].ends_with('汉'),
                    "截断必须落在 UTF-8 字符边界，不能产生乱码"
                );
                assert_eq!(lines[3], "line-new 最新消息", "最新行必须在最后");
                assert!(truncated, "单行截断必须标记 truncated");
                assert!(
                    size_bytes < MAX_OUTPUT_BYTES as u64,
                    "本次 stdout 未达 256 KiB"
                );
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn journal_tail_rejects_unit_outside_whitelist() {
        let cfg = cfg_with(vec![journal_source("j", "nginx.service")]);
        // 直接构造未通过配置校验的 cfg：执行层必须再次校验。
        let err = tail(&cfg, &cfg.log_sources[0], 5).unwrap_err();
        assert_eq!(err.code, control::codes::NOT_WHITELISTED);
    }

    #[test]
    fn journal_tail_non_zero_exit_is_control_failed() {
        let _guard = exec::test_serial_guard();
        let dir = temp_dir("journal-fail");
        let script = write_script(&dir, "journalctl", "printf 'no journal\\n' >&2\nexit 1");
        let mut cfg = cfg_with(vec![journal_source("j", "nginx.service")]);
        cfg.systemd_units = vec!["nginx*".into()];
        cfg.journalctl_path = script.to_str().unwrap().to_string();
        let err = tail(&cfg, &cfg.log_sources[0], 5).unwrap_err();
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("退出码 1"), "{}", err.message);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
