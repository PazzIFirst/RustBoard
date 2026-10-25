//! C5 安装器 CLI 级回归：离线 / ACME 互斥、ACME 参数校验、dry-run 计划。
//!
//! 这些用例只启动 `rustboard-hub install` 的参数/预检路径：
//! - 负例必须在读取安装状态、写盘、联网之前失败；
//! - `--dry-run` 用例不写文件、不调用 systemctl；
//! - 真实的 ACME 签发（Pebble / staging）不在本文件里伪造，依赖 C4 的
//!   `tls issue` 子命令与 e2e 环境。

use std::process::{Command, Output};

fn hub(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustboard-hub"))
        .args(args)
        .env_remove("RUSTBOARD_INSTALL_LOCK_HELD")
        .output()
        .expect("执行 rustboard-hub")
}

fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn assert_fails(output: &Output, needles: &[&str]) {
    let text = combined(output);
    assert!(
        !output.status.success(),
        "命令本应失败但成功了；输出: {text}"
    );
    for needle in needles {
        assert!(text.contains(needle), "错误输出缺少 {needle:?}: {text}");
    }
}

#[test]
fn offline_with_acme_mode_fails_before_any_write() {
    let output = hub(&[
        "install",
        "--yes",
        "--offline",
        "--tls",
        "acme-domain",
        "--acme-email",
        "admin@example.com",
        "--domain",
        "board.example.com",
        "--panel",
        "no",
    ]);
    assert_fails(&output, &["--offline", "ACME"]);
}

#[test]
fn offline_with_acme_only_argument_fails_before_any_write() {
    let output = hub(&[
        "install",
        "--yes",
        "--offline",
        "--acme-email",
        "admin@example.com",
        "--panel",
        "no",
    ]);
    assert_fails(&output, &["--offline", "ACME"]);
}

#[test]
fn explicit_self_signed_with_acme_args_is_rejected() {
    let output = hub(&[
        "install",
        "--yes",
        "--dry-run",
        "--tls",
        "self-signed",
        "--acme-email",
        "admin@example.com",
        "--domain",
        "board.example.com",
        "--panel",
        "no",
    ]);
    assert_fails(&output, &["self-signed", "ACME"]);
}

#[test]
fn acme_domain_requires_email() {
    let output = hub(&[
        "install",
        "--yes",
        "--tls",
        "acme-domain",
        "--domain",
        "board.example.com",
        "--panel",
        "no",
    ]);
    assert_fails(&output, &["--acme-email"]);
}

#[test]
fn acme_ip_requires_exactly_one_domain() {
    let output = hub(&[
        "install",
        "--yes",
        "--tls",
        "acme-ip",
        "--acme-email",
        "admin@example.com",
        "--domain",
        "203.0.113.10",
        "--domain",
        "203.0.113.11",
        "--panel",
        "no",
    ]);
    assert_fails(&output, &["acme-ip", "恰好一个"]);
}

#[test]
fn acme_args_in_dry_run_require_explicit_tls_mode() {
    let output = hub(&[
        "install",
        "--yes",
        "--dry-run",
        "--acme-email",
        "admin@example.com",
        "--panel",
        "no",
    ]);
    assert_fails(&output, &["--dry-run", "--tls"]);
}

#[test]
fn acme_dry_run_prints_plan_without_network() {
    let output = hub(&[
        "install",
        "--yes",
        "--dry-run",
        "--tls",
        "acme-domain",
        "--acme-email",
        "admin@example.com",
        "--domain",
        "board.example.com",
        "--panel",
        "no",
    ]);
    let text = combined(&output);
    assert!(output.status.success(), "dry-run 应成功；输出: {text}");
    assert!(text.contains("TLS: acme-domain"), "{text}");
    assert!(text.contains("ACME:"), "{text}");
    assert!(text.contains("不联网"), "{text}");
}

#[test]
fn default_self_signed_dry_run_stays_offline() {
    let output = hub(&[
        "install",
        "--yes",
        "--dry-run",
        "--offline",
        "--panel",
        "no",
    ]);
    let text = combined(&output);
    assert!(output.status.success(), "dry-run 应成功；输出: {text}");
    assert!(text.contains("TLS: self-signed"), "{text}");
}

#[test]
fn install_help_lists_phase_c_flags() {
    let output = hub(&["install", "--help"]);
    let text = combined(&output);
    assert!(output.status.success(), "help 应成功；输出: {text}");
    for flag in [
        "--tls",
        "--acme-email",
        "--acme-directory",
        "--acme-challenge",
        "--domain",
        "--acme-profile",
        "--acme-ca",
        "--admin-tls",
    ] {
        assert!(text.contains(flag), "help 缺少 {flag}: {text}");
    }
}
