//! KI-22 独立单元测试：控制面日志白名单的硬链接逃逸。
//!
//! 本文件由 `logs.rs` 里 `#[cfg(test)] mod tests` 的
//! `#[path = "logs_hardlink_tests.rs"] mod hardlink;` 引入，因此可经
//! `use super::*;` 使用 `temp_dir`、`cfg_with`、`file_source` 等测试辅助
//! 函数，以及父模块导入的 `open_log_path_absolute`、`validate_sources_io`、
//! `tail`、`control`、`ControlResult` 等名字。
//!
//! 这里只按验收行为断言（拒绝、错误文案、不泄露、可恢复），不依赖
//! `openat2` / `fstat` 的实现细节。

use super::*;
use std::os::unix::fs::MetadataExt;

/// 写入 victim 文件的唯一哨兵；任何错误文本都不得回显它。
const VICTIM_SENTINEL: &str = "KI22-VICTIM-SENTINEL-DO-NOT-LEAK";

/// 测试结束（包括断言 panic 展开）时清理临时目录。
struct CleanupGuard(PathBuf);

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// 创建独立临时目录，并返回随作用域自动清理的 guard。
fn scratch_dir(tag: &str) -> (PathBuf, CleanupGuard) {
    let dir = temp_dir(tag);
    let guard = CleanupGuard(dir.clone());
    (dir, guard)
}

/// 创建含哨兵的 victim 文件，返回其路径。
fn write_victim(dir: &Path, name: &str) -> PathBuf {
    let victim = dir.join(name);
    std::fs::write(
        &victim,
        format!("victim-prefix\n{VICTIM_SENTINEL}\nvictim-suffix\n"),
    )
    .expect("写入 victim 文件失败");
    victim
}

/// 错误必须明确提到硬链接，不能退化成泛化错误。
fn assert_mentions_hardlink(text: &str) {
    assert!(
        text.contains("硬链接"),
        "错误文本必须明确提到“硬链接”，实际为: {text}"
    );
}

/// 任何对外错误文本都不得回显被保护文件的内容。
fn assert_no_sentinel(text: &str, sentinel: &str) {
    assert!(
        !text.contains(sentinel),
        "错误文本泄露了被保护文件内容（{sentinel}），实际为: {text}"
    );
}

/// 断言 tail 失败并返回错误；成功会 panic，确保不会把内容当结果返回。
fn expect_tail_failure(
    cfg: &ControlConfig,
    source: &LogSourceConfig,
    requested_lines: u32,
    scenario: &str,
) -> ControlError {
    match tail(cfg, source, requested_lines) {
        Ok(result) => panic!("{scenario}：tail 不应成功，实际返回 {}", result.kind()),
        Err(err) => err,
    }
}

/// 验收点 1：硬链接被拒绝，且 open / 启动校验 / tail 都不泄露目标内容。
#[test]
fn hardlink_rejected_and_content_not_leaked() {
    let (dir, _cleanup) = scratch_dir("ki22-hardlink");
    let victim = write_victim(&dir, "victim.log");
    let alias = dir.join("app.log");
    std::fs::hard_link(&victim, &alias).expect("创建硬链接失败");

    assert_eq!(
        std::fs::metadata(&alias).unwrap().nlink(),
        2,
        "场景前置：白名单路径必须与 victim 构成双硬链接"
    );

    let open_err = open_log_path_absolute(&alias).expect_err("硬链接必须被 open 拒绝");
    assert_eq!(
        open_err.kind(),
        std::io::ErrorKind::InvalidInput,
        "硬链接拒绝必须返回 InvalidInput，实际为 {open_err:?}"
    );
    assert_mentions_hardlink(&open_err.to_string());
    assert_no_sentinel(&open_err.to_string(), VICTIM_SENTINEL);

    let cfg = cfg_with(vec![file_source("app", &alias)]);
    let validation_err = validate_sources_io(&cfg).expect_err("启动校验必须拒绝硬链接来源");
    let validation_text = format!("{validation_err:#}");
    assert!(
        validation_text.contains("日志来源"),
        "启动校验错误缺少来源上下文: {validation_text}"
    );
    assert!(
        validation_text.contains("日志来源 app"),
        "启动校验错误缺少来源 id app: {validation_text}"
    );
    let alias_text = alias.to_string_lossy();
    assert!(
        validation_text.contains(alias_text.as_ref()),
        "启动校验错误缺少绝对路径: {validation_text}"
    );
    assert_mentions_hardlink(&validation_text);
    assert_no_sentinel(&validation_text, VICTIM_SENTINEL);

    let tail_err = expect_tail_failure(&cfg, &cfg.log_sources[0], 50, "硬链接来源");
    assert_eq!(tail_err.code, control::codes::CONTROL_FAILED);
    assert!(
        tail_err.message.contains("app"),
        "运行期 tail 错误缺少来源 id app: {}",
        tail_err.message
    );
    assert!(
        tail_err.message.contains(alias_text.as_ref()),
        "运行期 tail 错误缺少绝对路径: {}",
        tail_err.message
    );
    assert_mentions_hardlink(&tail_err.message);
    assert_no_sentinel(&tail_err.message, VICTIM_SENTINEL);
}

/// 验收点 2：nlink == 1 的普通文件允许打开、通过启动校验并正确 tail。
#[test]
fn single_link_plain_file_is_allowed() {
    let (dir, _cleanup) = scratch_dir("ki22-single-link");
    let log = dir.join("app.log");
    std::fs::write(&log, b"first-line\nsecond-line\nlast-line\n").expect("写入普通日志失败");

    assert_eq!(
        std::fs::metadata(&log).unwrap().nlink(),
        1,
        "场景前置：普通文件必须为单硬链接"
    );

    let file = open_log_path_absolute(&log).expect("单链接普通文件应允许打开");
    let metadata = file.metadata().expect("fstat 失败");
    assert!(metadata.is_file(), "普通文件必须被识别为文件");
    assert_eq!(metadata.nlink(), 1);
    drop(file);

    let cfg = cfg_with(vec![file_source("app", &log)]);
    validate_sources_io(&cfg).expect("单链接普通文件应通过启动校验");

    let result = tail(&cfg, &cfg.log_sources[0], 10).expect("单链接普通文件应能 tail");
    match result {
        ControlResult::LogLines {
            source,
            lines,
            truncated,
            size_bytes,
        } => {
            assert_eq!(source, "app");
            assert_eq!(lines, ["first-line", "second-line", "last-line"]);
            assert!(!truncated);
            assert_eq!(size_bytes, std::fs::metadata(&log).unwrap().len());
        }
        other => panic!("意外结果类型: {}", other.kind()),
    }
}

/// 验收点 3：运行期新出现硬链接也拒绝；删除后重新写入单链接文件可恢复。
#[test]
fn runtime_new_hardlink_is_rejected_then_recovers() {
    const RUNTIME_SENTINEL: &str = "KI22-RUNTIME-SENTINEL-DO-NOT-LEAK";
    let (dir, _cleanup) = scratch_dir("ki22-runtime-hardlink");
    let log = dir.join("app.log");
    std::fs::write(&log, format!("generation-1\n{RUNTIME_SENTINEL}\n")).expect("写入初始日志失败");
    let cfg = cfg_with(vec![file_source("app", &log)]);

    match tail(&cfg, &cfg.log_sources[0], 10).expect("初始单链接日志应能 tail") {
        ControlResult::LogLines { lines, .. } => {
            assert_eq!(lines, ["generation-1", RUNTIME_SENTINEL]);
        }
        other => panic!("意外结果类型: {}", other.kind()),
    }

    let extra_link = dir.join("app.log.keep");
    std::fs::hard_link(&log, &extra_link).expect("创建额外硬链接失败");
    assert_eq!(
        std::fs::metadata(&log).unwrap().nlink(),
        2,
        "场景前置：运行期日志必须出现第二个硬链接"
    );

    let tail_err = expect_tail_failure(&cfg, &cfg.log_sources[0], 10, "运行期新增硬链接");
    assert_eq!(tail_err.code, control::codes::CONTROL_FAILED);
    assert_mentions_hardlink(&tail_err.message);
    assert_no_sentinel(&tail_err.message, RUNTIME_SENTINEL);

    // 删除额外硬链接后立即恢复为单链接；再删掉重建新文件，证明没有缓存旧 fd。
    std::fs::remove_file(&extra_link).expect("删除额外硬链接失败");
    assert_eq!(std::fs::metadata(&log).unwrap().nlink(), 1);
    std::fs::remove_file(&log).expect("删除旧日志失败");
    std::fs::write(&log, b"generation-2\nrecovered\n").expect("重建单链接日志失败");
    assert_eq!(
        std::fs::metadata(&log).unwrap().nlink(),
        1,
        "重建文件必须是单链接"
    );

    match tail(&cfg, &cfg.log_sources[0], 10).expect("删除额外硬链接后必须恢复成功") {
        ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["generation-2", "recovered"]),
        other => panic!("意外结果类型: {}", other.kind()),
    }
}

/// 验收点 4：启动校验 fail-closed，错误同时可定位到来源、target 与硬链接原因。
#[test]
fn startup_validation_fails_closed_with_locatable_error() {
    let (dir, _cleanup) = scratch_dir("ki22-startup");
    let victim = write_victim(&dir, "victim.log");
    let alias = dir.join("app.log");
    std::fs::hard_link(&victim, &alias).expect("创建硬链接失败");
    assert_eq!(std::fs::metadata(&alias).unwrap().nlink(), 2);

    let cfg = cfg_with(vec![file_source("app", &alias)]);
    let err = validate_sources_io(&cfg).expect_err("启动校验必须对硬链接来源 fail-closed");
    let text = format!("{err:#}");
    assert!(text.contains("日志来源"), "错误必须包含“日志来源”: {text}");
    assert!(
        text.contains("日志来源 app"),
        "错误必须包含来源 id app: {text}"
    );
    assert!(
        text.contains(alias.to_string_lossy().as_ref()),
        "错误必须包含 target 绝对路径: {text}"
    );
    assert_mentions_hardlink(&text);
    assert_no_sentinel(&text, VICTIM_SENTINEL);
}

/// 边界：nlink > 2 也必须拒绝，避免实现只特判恰好 2 个链接。
#[test]
fn nlink_above_two_is_also_rejected() {
    let (dir, _cleanup) = scratch_dir("ki22-multi-hardlink");
    let victim = write_victim(&dir, "victim.log");
    let alias = dir.join("app.log");
    std::fs::hard_link(&victim, &alias).expect("创建第一条硬链接失败");
    std::fs::hard_link(&victim, dir.join("third.log")).expect("创建第二条硬链接失败");
    assert_eq!(
        std::fs::metadata(&alias).unwrap().nlink(),
        3,
        "场景前置：必须出现三个硬链接"
    );

    let err = open_log_path_absolute(&alias).expect_err("nlink > 1 一律拒绝");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_mentions_hardlink(&err.to_string());
    assert_no_sentinel(&err.to_string(), VICTIM_SENTINEL);
}

/// 验收点 5：保持日志轮转兼容性——rename 后创建的新单链接文件仍能 tail。
#[test]
fn tail_succeeds_after_log_rotation() {
    let (dir, _cleanup) = scratch_dir("ki22-rotate");
    let log = dir.join("app.log");
    std::fs::write(&log, b"rotated-old\n").expect("写入轮转前日志失败");
    let cfg = cfg_with(vec![file_source("app", &log)]);

    match tail(&cfg, &cfg.log_sources[0], 10).expect("轮转前应能 tail") {
        ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["rotated-old"]),
        other => panic!("意外结果类型: {}", other.kind()),
    }

    std::fs::rename(&log, dir.join("app.log.1")).expect("模拟 logrotate rename 失败");
    std::fs::write(&log, b"rotated-new\n").expect("写入轮转后新日志失败");
    assert_eq!(
        std::fs::metadata(&log).unwrap().nlink(),
        1,
        "轮转后的新文件必须是单链接"
    );

    match tail(&cfg, &cfg.log_sources[0], 10).expect("轮转后应读取新文件") {
        ControlResult::LogLines { lines, .. } => assert_eq!(lines, ["rotated-new"]),
        other => panic!("意外结果类型: {}", other.kind()),
    }
}
