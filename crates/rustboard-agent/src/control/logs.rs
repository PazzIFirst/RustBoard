//! 只读日志：白名单文件 tail（`openat2` 单次完整路径解析）与 journald tail。
//!
//! 文件日志的防护：
//! - 每次打开（启动校验与运行期 tail 共用同一 helper）都把配置的绝对路径去掉前导 `/`，
//!   以根目录 fd 为基准在**一次** `openat2(2)` 内解析全部父目录与最终文件。父路径不再
//!   先 `open()` 再用其结果打开文件名，因此父目录在两次 syscall 之间被替换为符号链接的
//!   TOCTOU 窗口不存在；
//! - `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`：
//!   任一分量是符号链接、经过 magic link 或借 `..` 逃逸根目录都会被拒绝；不限制跨挂载点
//!   （兼容独立 `/var` 分区、bind mount 与 `/tmp`），跨挂载本身不构成路径逃逸；
//! - `O_NONBLOCK` 打开后再 `fstat`，只接受普通文件；FIFO / 设备 / 目录一律拒绝，
//!   避免日志文件被替换成 FIFO 后永久阻塞控制线程；
//! - 内核不支持 `openat2`（ENOSYS）时直接失败并返回错误，**不降级**到 `fs::read`；
//! - 文件不存在允许启动（logrotate 场景），但父目录不存在 / 是符号链接
//!   会在启动时报清晰错误；每次 tail 都重新打开，不缓存 fd；
//! - 只从文件尾部倒读，最多 2000 行、单行 4096 字节、总输出 256 KiB。

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
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
    if !path.is_absolute() {
        bail!("日志路径必须是绝对路径: {}", path.display());
    }
    match open_log_path_absolute(path) {
        Ok(file) => {
            // 与运行期 tail 使用同一 helper；启动校验只打开并立即关闭，不缓存 fd。
            drop(file);
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // 文件尚未创建是允许的（例如 logrotate 正在轮转），但父目录必须存在、
            // 不是符号链接，否则运行期永远读不到日志。
            validate_parent_dir(path)
                .with_context(|| format!("日志来源父目录校验失败: {}", path.display()))
        }
        Err(err) => {
            let message = match err.raw_os_error() {
                Some(libc::ELOOP) => {
                    format!("日志路径包含符号链接（openat2 拒绝）: {}", path.display())
                }
                Some(libc::ENOTDIR) => {
                    format!("日志路径中的父目录不是目录: {}", path.display())
                }
                _ => format!("打开日志文件失败（openat2）: {}", path.display()),
            };
            Err(anyhow::Error::new(err)).with_context(|| message)
        }
    }
}

/// 文件尚不存在时单独确认父目录：必须存在、是目录、不是符号链接。
///
/// 只用于启动校验，且仅在文件缺失（logrotate 场景）时执行；正常读取路径仍然只做
/// 一次完整的 `openat2`。
fn validate_parent_dir(path: &Path) -> anyhow::Result<()> {
    let Some(parent) = path.parent() else {
        bail!("日志路径没有父目录: {}", path.display());
    };
    if parent.as_os_str().is_empty() {
        bail!("日志路径没有父目录: {}", path.display());
    }
    if parent == Path::new("/") {
        // 根目录必然存在；openat2 不接受去掉前导 `/` 后的空相对路径。
        drop(open_root_dir()?);
        return Ok(());
    }
    match open_directory_absolute(parent) {
        Ok(dir) => {
            drop(dir);
            Ok(())
        }
        Err(err) => match err.raw_os_error() {
            Some(libc::ENOENT) => bail!(
                "父目录不存在: {}（文件可由 logrotate 稍后创建，但父目录必须已存在）",
                parent.display()
            ),
            Some(libc::ELOOP) => bail!("父目录是符号链接或被替换为符号链接: {}", parent.display()),
            Some(libc::ENOTDIR) => bail!("父目录路径中有分量不是目录: {}", parent.display()),
            _ => Err(anyhow::Error::new(err))
                .with_context(|| format!("打开父目录失败（openat2）: {}", parent.display())),
        },
    }
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
    // 每次 tail 都重新解析完整路径并打开，不缓存父目录 fd 或文件 fd：日志轮转/替换后
    // 立即读取新文件，同时父目录被替换成符号链接会被 openat2 拒绝。
    let mut file = open_log_path_absolute(path).map_err(|err| {
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

/// 打开绝对路径日志文件：从根目录 fd 出发，用一次 `openat2(2)` 解析完整路径。
///
/// 父目录与文件名在同一次 syscall 内解析，避免“先打开父目录、再打开文件”之间父目录
/// 被替换成符号链接的 TOCTOU 窗口。路径中任一分量是符号链接、magic link，或借 `..`
/// 逃逸根目录都会被拒绝；跨挂载点不受限制（独立 `/var` 分区等部署仍可用）。
/// 内核不支持 `openat2` 时直接失败，不降级。
fn open_log_path_absolute(path: &Path) -> io::Result<File> {
    let file = open_absolute_at_root(
        path,
        // O_NONBLOCK：日志文件若被替换成 FIFO，open 不会因为没有写端而永久阻塞；
        // 打开后再用 fstat 拒绝任何非普通文件。
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
    )?;
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

/// 启动校验用：打开绝对路径目录。仅在文件尚不存在、需要确认父目录时使用。
fn open_directory_absolute(path: &Path) -> io::Result<File> {
    open_absolute_at_root(
        path,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )
}

/// 以根目录 fd 为基准，单次 `openat2(2)` 打开绝对路径。
fn open_absolute_at_root(path: &Path, flags: libc::c_int) -> io::Result<File> {
    let relative = path_beneath_root(path)?;
    let name_c = CString::new(relative)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "日志路径包含 NUL"))?;
    let root = open_root_dir()?;
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: openat2(2) 只读取 how 指向的 POD 结构；root fd 与 name_c 在调用期间有效。
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        // 明确拒绝降级：旧内核 / 不允许 openat2 的 sandbox 直接报错。
        if err.raw_os_error() == Some(libc::ENOSYS) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "内核不支持 openat2(2)，拒绝降级读取日志文件",
            ));
        }
        return Err(err);
    }
    // SAFETY: fd 由 openat2(2) 返回，是唯一所有者的文件描述符，交给 File 管理。
    Ok(unsafe { File::from_raw_fd(fd as libc::c_int) })
}

/// 打开根目录 fd；`openat2` 的 dirfd 固定为 `/`。
fn open_root_dir() -> io::Result<File> {
    // SAFETY: `c"/"` 是合法的以 NUL 结尾的 C 字符串；open(2) 只读取该字符串。
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd 由 open(2) 返回且没有其他持有者。
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// 将绝对路径转换成相对根目录的字节串；保留 `..`，由 `RESOLVE_BENEATH` 拒绝逃逸。
fn path_beneath_root(path: &Path) -> io::Result<&[u8]> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "日志路径必须是绝对路径",
        ));
    }
    let bytes = path.as_os_str().as_bytes();
    let mut relative = bytes;
    while relative.first() == Some(&b'/') {
        relative = &relative[1..];
    }
    if relative.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "日志路径必须指向文件",
        ));
    }
    Ok(relative)
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
        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("父目录不存在"), "{err}");

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
    fn validate_io_allows_missing_file_but_requires_existing_parent() {
        let dir = temp_dir("io-missing-file");
        let log = dir.join("rotating.log");
        let cfg = cfg_with(vec![file_source("rotating", &log)]);
        // 文件尚未创建（logrotate 场景）允许启动。
        validate_sources_io(&cfg).expect("父目录存在时缺失文件应允许启动");
        // 但运行期 tail 必须报错，而不是静默返回空内容。
        let err = tail(&cfg, &cfg.log_sources[0], 10).expect_err("文件不存在时 tail 必须失败");
        assert_eq!(err.code, control::codes::CONTROL_FAILED);

        // 父目录随后被删除：启动校验必须失败。
        std::fs::remove_dir_all(&dir).unwrap();
        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("父目录不存在"), "{err}");
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
    fn open_absolute_rejects_relative_escape_symlink_and_directory() {
        let dir = temp_dir("escape");
        let ok = dir.join("ok.log");
        std::fs::write(&ok, b"ok\n").unwrap();
        open_log_path_absolute(&ok).expect("绝对路径普通文件必须能打开");

        // 相对路径与根目录本身都不是可读取的日志文件，必须在 syscall 前拒绝。
        for bad in [Path::new("relative/x.log"), Path::new("/")] {
            let err = open_log_path_absolute(bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}: {err}");
        }

        // 从根向上 `..` 逃逸必须被 RESOLVE_BENEATH 拒绝。
        let err = open_log_path_absolute(Path::new("/../etc/passwd")).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::EXDEV),
            "`..` 逃逸必须被拒绝: {err:?}"
        );

        // 最终分量是符号链接（绝对目标）。
        let victim = dir.join("victim.log");
        std::fs::write(&victim, b"victim\n").unwrap();
        let final_link = dir.join("final-link.log");
        std::os::unix::fs::symlink(&victim, &final_link).unwrap();
        let err = open_log_path_absolute(&final_link).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "最终文件符号链接必须被拒绝: {err:?}"
        );

        // 中间父目录是符号链接（相对目标）。
        let victim_dir = dir.join("victim-dir");
        std::fs::create_dir_all(&victim_dir).unwrap();
        std::fs::write(victim_dir.join("app.log"), b"victim\n").unwrap();
        let mid_link = dir.join("mid-link");
        std::os::unix::fs::symlink("victim-dir", &mid_link).unwrap();
        let err = open_log_path_absolute(&mid_link.join("app.log")).unwrap_err();
        assert_eq!(
            err.raw_os_error(),
            Some(libc::ELOOP),
            "中间父目录符号链接必须被拒绝: {err:?}"
        );

        // 目录不是普通文件。
        let subdir = dir.join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        let err = open_log_path_absolute(&subdir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("普通文件"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 把 `path` 改名为 `<name>-real`，再在原名处创建符号链接。
    fn rename_to_real_and_link(path: &Path, target: &Path) {
        let real = path.with_file_name(format!(
            "{}-real",
            path.file_name().unwrap().to_string_lossy()
        ));
        std::fs::rename(path, &real).unwrap();
        std::os::unix::fs::symlink(target, path).unwrap();
    }

    fn assert_victim_sentinel_readable(victim_log: &Path) {
        let cfg = cfg_with(vec![file_source("victim", victim_log)]);
        match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
            ControlResult::LogLines { lines, .. } => {
                assert_eq!(lines, ["VICTIM-SENTINEL"], "victim 场景构造必须有效");
            }
            other => panic!("意外结果: {other:?}"),
        }
    }

    /// TOCTOU 核心回归：启动校验通过后，把多级中间父目录替换为指向 victim 的符号链接。
    fn exercise_intermediate_parent_swap(tag: &str, relative_link: bool) {
        let dir = temp_dir(tag);
        let victim = dir.join("victim");
        let victim_logs = victim.join("three");
        std::fs::create_dir_all(&victim_logs).unwrap();
        std::fs::write(victim_logs.join("app.log"), b"VICTIM-SENTINEL\n").unwrap();

        let deep = dir.join("one").join("two").join("three");
        std::fs::create_dir_all(&deep).unwrap();
        let log = deep.join("app.log");
        std::fs::write(&log, b"real-line\n").unwrap();
        let cfg = cfg_with(vec![file_source("app", &log)]);

        // 启动校验与正常运行都先通过。
        validate_sources_io(&cfg).expect("正常多级目录应通过启动校验");
        match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
            ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["real-line"]),
            other => panic!("意外结果: {other:?}"),
        }

        // 攻击：`one/two` 改为指向 victim 的符号链接（绝对或相对目标）。
        let link = if relative_link {
            PathBuf::from("../victim")
        } else {
            victim.clone()
        };
        rename_to_real_and_link(&dir.join("one").join("two"), &link);

        // 启动策略与运行期策略必须一致拒绝，且绝不能返回 victim 内容。
        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("符号链接"), "{err}");
        let err = tail(&cfg, &cfg.log_sources[0], 10)
            .expect_err("中间父目录变成符号链接后 tail 必须失败");
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(err.message.contains("openat2"), "{err:?}");
        assert!(
            !err.message.contains("VICTIM-SENTINEL"),
            "不能回显 victim 内容: {err:?}"
        );

        // 证明 victim 的 sentinel 本身可读：若跟随符号链接就会泄露。
        assert_victim_sentinel_readable(&victim_logs.join("app.log"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_rejects_intermediate_parent_symlink_after_validation() {
        exercise_intermediate_parent_swap("toctou-mid-abs", false);
        exercise_intermediate_parent_swap("toctou-mid-rel", true);
    }

    /// 最终父目录（文件名所在目录）被替换为符号链接，tail 必须失败。
    fn exercise_final_parent_swap(tag: &str, relative_link: bool) {
        let dir = temp_dir(tag);
        let victim = dir.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("app.log"), b"VICTIM-SENTINEL\n").unwrap();

        let logs = dir.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let log = logs.join("app.log");
        std::fs::write(&log, b"real-line\n").unwrap();
        let cfg = cfg_with(vec![file_source("app", &log)]);
        validate_sources_io(&cfg).expect("正常路径应通过启动校验");
        match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
            ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["real-line"]),
            other => panic!("意外结果: {other:?}"),
        }

        let link = if relative_link {
            PathBuf::from("victim")
        } else {
            victim.clone()
        };
        rename_to_real_and_link(&logs, &link);

        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("符号链接"), "{err}");
        let err =
            tail(&cfg, &cfg.log_sources[0], 10).expect_err("最终父目录变成符号链接后必须失败");
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(
            !err.message.contains("VICTIM-SENTINEL"),
            "不能回显 victim 内容: {err:?}"
        );

        assert_victim_sentinel_readable(&victim.join("app.log"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_rejects_final_parent_symlink_after_validation() {
        exercise_final_parent_swap("toctou-parent-abs", false);
        exercise_final_parent_swap("toctou-parent-rel", true);
    }

    /// 最终文件被替换为符号链接，tail 必须失败（绝对 / 相对目标都覆盖）。
    fn exercise_file_swap(tag: &str, relative_link: bool) {
        let dir = temp_dir(tag);
        let victim = dir.join("victim.log");
        std::fs::write(&victim, b"VICTIM-SENTINEL\n").unwrap();
        let log = dir.join("app.log");
        std::fs::write(&log, b"real-line\n").unwrap();
        let cfg = cfg_with(vec![file_source("app", &log)]);
        validate_sources_io(&cfg).expect("正常路径应通过启动校验");
        match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
            ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["real-line"]),
            other => panic!("意外结果: {other:?}"),
        }

        let link = if relative_link {
            PathBuf::from("victim.log")
        } else {
            victim.clone()
        };
        rename_to_real_and_link(&log, &link);

        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("符号链接"), "{err}");
        let err = tail(&cfg, &cfg.log_sources[0], 10).expect_err("文件变成符号链接后必须失败");
        assert_eq!(err.code, control::codes::CONTROL_FAILED);
        assert!(
            !err.message.contains("VICTIM-SENTINEL"),
            "不能回显 victim 内容: {err:?}"
        );

        assert_victim_sentinel_readable(&victim);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tail_rejects_file_symlink_after_validation() {
        exercise_file_swap("toctou-file-abs", false);
        exercise_file_swap("toctou-file-rel", true);
    }

    /// 运行期每次重新打开：日志轮转后必须读新文件，不能复用旧 fd。
    #[test]
    fn tail_reopens_after_log_rotation() {
        let dir = temp_dir("rotate");
        let log = dir.join("app.log");
        std::fs::write(&log, b"old-line\n").unwrap();
        let cfg = cfg_with(vec![file_source("app", &log)]);
        match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
            ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["old-line"]),
            other => panic!("意外结果: {other:?}"),
        }

        // 模拟 logrotate：旧文件改名，新文件顶替原名。
        std::fs::rename(&log, dir.join("app.log.1")).unwrap();
        std::fs::write(&log, b"new-line\n").unwrap();
        match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
            ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["new-line"]),
            other => panic!("轮转后必须读新文件: {other:?}"),
        }

        // 文件被删除后立即失败，而不是返回下一次打开缓存的旧内容。
        std::fs::remove_file(&log).unwrap();
        assert!(tail(&cfg, &cfg.log_sources[0], 10).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 大文件 tail 不回归：从 2 MB+ 文件中只返回最新几行。
    #[test]
    fn tail_large_file_returns_newest_lines() {
        use std::io::{BufWriter, Write};

        let dir = temp_dir("large");
        let log = dir.join("app.log");
        {
            let file = std::fs::File::create(&log).unwrap();
            let mut writer = BufWriter::new(file);
            for index in 0..200_000 {
                writeln!(writer, "line-{index:06}").unwrap();
            }
            writer.flush().unwrap();
        }
        let size = std::fs::metadata(&log).unwrap().len();
        assert!(size > 2 * 1024 * 1024, "场景必须是大文件: {size}");
        let cfg = cfg_with(vec![file_source("app", &log)]);
        match tail(&cfg, &cfg.log_sources[0], 7).unwrap() {
            ControlResult::LogLines {
                lines, size_bytes, ..
            } => {
                assert_eq!(size_bytes, size);
                assert_eq!(
                    lines,
                    [
                        "line-199993",
                        "line-199994",
                        "line-199995",
                        "line-199996",
                        "line-199997",
                        "line-199998",
                        "line-199999"
                    ]
                );
            }
            other => panic!("意外结果: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 兼容性回归：日志路径允许跨挂载点（独立 `/var` 分区、bind mount、tmpfs）。
    ///
    /// 单次 `openat2` + `RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_BENEATH`
    /// 仍然完整关闭父路径 TOCTOU / 符号链接逃逸；跨挂载本身不构成路径逃逸。
    #[test]
    fn cross_mount_log_path_is_readable() {
        use std::os::unix::fs::MetadataExt;

        let root_dev = std::fs::metadata("/").unwrap().dev();
        let content = b"cross-mount-line\n";
        let mut checked = false;
        // 优先 /dev/shm（通常是独立 tmpfs），其次 $TMPDIR。
        for base in [PathBuf::from("/dev/shm"), std::env::temp_dir()] {
            let Ok(base) = std::fs::canonicalize(&base) else {
                continue;
            };
            let Ok(metadata) = std::fs::metadata(&base) else {
                continue;
            };
            if !metadata.is_dir() || metadata.dev() == root_dev {
                continue;
            }
            let dir = base.join(format!("rb-agent-logs-xdev-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            if std::fs::create_dir_all(&dir).is_err() {
                continue;
            }
            let log = dir.join("app.log");
            if std::fs::write(&log, content).is_err() {
                let _ = std::fs::remove_dir_all(&dir);
                continue;
            }
            // 确认场景有效：文件确实位于与 `/` 不同的 st_dev。
            assert_ne!(
                std::fs::metadata(&log).unwrap().dev(),
                root_dev,
                "跨挂载用例必须落在不同设备上"
            );

            open_log_path_absolute(&log).expect("跨挂载点的普通文件必须能打开");
            let cfg = cfg_with(vec![file_source("xdev", &log)]);
            validate_sources_io(&cfg).expect("跨挂载点日志不应阻止启动");
            match tail(&cfg, &cfg.log_sources[0], 10).unwrap() {
                ControlResult::LogLines {
                    lines, size_bytes, ..
                } => {
                    assert_eq!(lines, ["cross-mount-line"]);
                    assert_eq!(size_bytes, content.len() as u64);
                }
                other => panic!("意外结果: {other:?}"),
            }
            checked = true;
            eprintln!("跨挂载兼容用例实际使用: {}", dir.display());
            let _ = std::fs::remove_dir_all(&dir);
            break;
        }
        if !checked {
            eprintln!("找不到与 `/` 不同 st_dev 的可写目录，跳过跨挂载兼容用例");
        }
    }

    /// 目录与设备（`/dev/null` 字符设备）都必须被 fstat 拒绝。
    #[test]
    fn non_regular_targets_are_rejected() {
        let dir = temp_dir("non-regular");

        let subdir = dir.join("logs-dir");
        std::fs::create_dir(&subdir).unwrap();
        let err = open_log_path_absolute(&subdir).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("不是普通文件"), "{err}");

        // `/dev` 是独立挂载点；跨挂载已允许，因此这里会真正打开设备后由 fstat 拒绝。
        // 这样无需 CAP_MKNOD，CI 非 root 也能覆盖设备路径。
        let device = Path::new("/dev/null");
        let err = open_log_path_absolute(device).expect_err("设备节点不能被当作普通日志文件打开");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{err:?}");
        assert!(err.to_string().contains("不是普通文件"), "{err}");

        let cfg = cfg_with(vec![file_source("dev", device)]);
        let err = format!("{:#}", validate_sources_io(&cfg).unwrap_err());
        assert!(err.contains("不是普通文件"), "{err}");
        let err = tail(&cfg, &cfg.log_sources[0], 10).expect_err("设备必须被拒绝");
        assert_eq!(err.code, control::codes::CONTROL_FAILED);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 安全回归：日志文件被替换成 FIFO 时，打开必须立即失败而不是阻塞控制线程。
    #[test]
    fn fifo_log_target_is_rejected_without_blocking() {
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
