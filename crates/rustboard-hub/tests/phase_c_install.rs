//! C5 安装器 CLI 级回归：离线 / ACME 互斥、ACME 参数校验、dry-run 计划。
//!
//! 这些用例只启动 `rustboard-hub install` 的参数/预检路径：
//! - 负例必须在读取安装状态、写盘、联网之前失败；
//! - `--dry-run` 用例不写文件、不调用 systemctl；
//! - 真实的 ACME 签发（Pebble / staging）不在本文件里伪造，依赖 C4 的
//!   `tls issue` 子命令与 e2e 环境。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use rustboard_common::config::{AcmeChallenge, HubConfig, ServerTlsMode, TlsConfig};
use rustboard_install::detect_system;
use sha2::{Digest, Sha256};

fn hub(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rustboard-hub"))
        .args(args)
        .env_remove("RUSTBOARD_INSTALL_LOCK_HELD")
        .output()
        .expect("执行 rustboard-hub")
}

/// root-only：真实 install 流程需要写受管前缀并获取 /run 全局锁。
fn skip_if_not_root() -> bool {
    if detect_system().euid != 0 {
        eprintln!("跳过 root-only 安装流程测试（euid != 0）");
        return true;
    }
    false
}

static NEXT_PREFIX: AtomicU64 = AtomicU64::new(0);

/// 测试前缀放在测试二进制所在 target 目录，避免 /tmp 的 sticky 位被拒绝。
struct TestPrefix {
    path: PathBuf,
}

impl TestPrefix {
    fn new(tag: &str) -> Self {
        let base = std::env::current_exe()
            .expect("current_exe")
            .parent()
            .expect("test binary dir")
            .to_path_buf();
        let path = base.join(format!(
            "rb-hub-c5-{tag}-{}-{}",
            std::process::id(),
            NEXT_PREFIX.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("创建测试 prefix");
        Self { path }
    }
}

impl Drop for TestPrefix {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn hub_data_dir(prefix: &Path) -> PathBuf {
    prefix.join("var/lib/rustboard/hub")
}

fn acme_config(prefix: &Path, fallback: bool, challenge: AcmeChallenge) -> HubConfig {
    let data_dir = hub_data_dir(prefix);
    HubConfig {
        data_dir: data_dir.clone(),
        database: format!("sqlite://{}/rustboard.db", data_dir.display()),
        admin_token: "phase-c-install-test-token".to_string(),
        server_names: vec!["127.0.0.1".to_string()],
        tls: TlsConfig {
            mode: ServerTlsMode::AcmeDomain,
            acme_email: "admin@example.com".to_string(),
            // 本地不可达的假 directory：不接触真实 Let's Encrypt。
            acme_directory: "https://127.0.0.1:1/dir".to_string(),
            challenge,
            domains: vec!["board.example.com".to_string()],
            staging_check: false,
            fallback_to_self_signed: fallback,
            ..TlsConfig::default()
        },
        ..HubConfig::default()
    }
}

fn write_hub_config(prefix: &Path, cfg: &HubConfig) -> PathBuf {
    let path = prefix.join("etc/rustboard/hub.toml");
    fs::create_dir_all(path.parent().unwrap()).expect("创建配置目录");
    let text = toml::to_string_pretty(cfg).expect("序列化 hub 配置");
    fs::write(&path, &text).expect("写 hub 配置");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("配置 0600");
    }
    path
}

fn install_output(prefix: &Path, extra: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rustboard-hub"));
    command
        .arg("install")
        .arg("--yes")
        .arg("--force")
        .arg("--prefix")
        .arg(prefix)
        .arg("--no-systemd")
        .arg("--panel")
        .arg("no");
    command.args(extra);
    command.env_remove("RUSTBOARD_INSTALL_LOCK_HELD");
    command.output().expect("执行 rustboard-hub install")
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[test]
fn offline_with_existing_acme_config_fails_and_keeps_config_byte_identical() {
    if skip_if_not_root() {
        return;
    }
    let prefix = TestPrefix::new("offline-acme");
    let cfg = acme_config(&prefix.path, true, AcmeChallenge::TlsAlpn01);
    let config_path = write_hub_config(&prefix.path, &cfg);
    let before = fs::read(&config_path).unwrap();
    let before_hash = sha256(&before);

    let output = install_output(&prefix.path, &["--offline"]);
    let text = combined(&output);
    assert!(
        !output.status.success(),
        "既有 ACME + --offline 必须失败: {text}"
    );
    assert!(text.contains("--offline"), "{text}");
    assert!(text.contains("ACME"), "{text}");

    // 必须在 Diagnostics / InstallTxn 之前失败：配置内容与 sha256 均不变。
    let after = fs::read(&config_path).unwrap();
    assert_eq!(after, before, "失败路径不得改写配置");
    assert_eq!(sha256(&after), before_hash, "配置 sha256 必须不变");
    assert!(!hub_data_dir(&prefix.path).exists(), "不得创建数据目录");
}

#[test]
fn new_acme_failure_cleans_data_dir_and_allows_self_signed_retry() {
    if skip_if_not_root() {
        return;
    }
    // 假 directory 只需要挑战端口可用即可走到 txn；用 443（tls-alpn-01）避免
    // 依赖本机 80。端口被占用时跳过，避免把环境问题当成失败。
    if std::net::TcpListener::bind(("0.0.0.0", 443)).is_err() {
        eprintln!("跳过：本机 443 已被占用，无法构造 ACME 失败路径");
        return;
    }
    let prefix = TestPrefix::new("acme-cleanup");
    let cfg = acme_config(&prefix.path, false, AcmeChallenge::TlsAlpn01);
    let config_path = write_hub_config(&prefix.path, &cfg);
    let before = fs::read(&config_path).unwrap();
    let before_hash = sha256(&before);
    let data_dir = hub_data_dir(&prefix.path);
    assert!(!data_dir.exists(), "前置条件：全新安装 data_dir 不存在");

    let output = install_output(&prefix.path, &[]);
    let text = combined(&output);
    assert!(
        !output.status.success(),
        "fallback=false 的 ACME 失败必须中止: {text}"
    );
    assert!(text.contains("fallback_to_self_signed"), "{text}");
    assert_eq!(
        fs::read(&config_path).unwrap(),
        before,
        "事务必须恢复失败前的配置"
    );
    assert_eq!(sha256(&fs::read(&config_path).unwrap()), before_hash);
    assert!(
        !data_dir.exists(),
        "全新 ACME 失败后不得残留 data_dir / CA / account / state: {}",
        data_dir.display()
    );
    assert!(!data_dir.join("certs").exists(), "certs 不得残留");

    // 失败后 self-signed 重试：不能被“证书不完整/已有数据目录”卡住。
    let retry = install_output(&prefix.path, &["--tls", "self-signed"]);
    let retry_text = combined(&retry);
    assert!(
        retry.status.success(),
        "ACME 失败清理后 self-signed 重试应成功: {retry_text}"
    );
    assert!(!retry_text.contains("证书不完整"), "{retry_text}");
    let installed = HubConfig::load(&config_path).expect("读取重试后的配置");
    assert_eq!(installed.tls.mode, ServerTlsMode::SelfSigned);
    assert!(
        data_dir.join("certs/server.crt").is_file(),
        "self-signed 重试必须生成服务端证书"
    );
}

#[test]
fn existing_data_dir_missing_ca_is_refused_without_creating_one() {
    if skip_if_not_root() {
        return;
    }
    if std::net::TcpListener::bind(("0.0.0.0", 443)).is_err() {
        eprintln!("跳过：本机 443 已被占用");
        return;
    }
    let prefix = TestPrefix::new("acme-missing-ca");
    let cfg = acme_config(&prefix.path, true, AcmeChallenge::TlsAlpn01);
    let config_path = write_hub_config(&prefix.path, &cfg);
    let config_before = fs::read(&config_path).unwrap();
    let data_dir = hub_data_dir(&prefix.path);
    fs::create_dir_all(&data_dir).unwrap();
    let sentinel = data_dir.join("rustboard.db");
    fs::write(&sentinel, b"existing-db").unwrap();

    let output = install_output(&prefix.path, &[]);
    let text = combined(&output);
    assert!(
        !output.status.success(),
        "缺 CA 的已有 data_dir 必须拒绝: {text}"
    );
    assert!(text.contains("拒绝静默重建"), "{text}");
    assert!(
        !data_dir.join("certs").exists(),
        "拒绝路径不得创建 certs/CA"
    );
    assert_eq!(fs::read(&sentinel).unwrap(), b"existing-db");
    assert_eq!(
        fs::read(&config_path).unwrap(),
        config_before,
        "拒绝路径不得改写配置"
    );
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
