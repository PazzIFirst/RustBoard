//! M5 Phase C C3/C4：`rustboard-hub tls status|issue|renew` 与 ACME 启动路径的集成测试。
//!
//! 不依赖 Pebble：这里验证「没有 ACME 证书时绝不生成自签 server 材料、CLI 非零退出
//! 并给出可执行提示」。真实 Pebble 签发/续期由 `src/acme/client.rs` 里的
//! `#[ignore]` 测试覆盖（需要本机 Pebble）。

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use rustboard_common::config::HubConfig;
use rustboard_common::tls;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_rustboard-hub")
}

fn temp_dir(tag: &str) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let dir = base.join(format!(
        "phase-c-acme-{}-{tag}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn run(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("启动 rustboard-hub 失败")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

/// 初始化一个 self-signed 安装，再把配置改成 ACME 模式，并删除自签服务端材料。
fn prepare_acme_install(tag: &str, directory: &str) -> (PathBuf, PathBuf) {
    let dir = temp_dir(tag);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("hub.toml");
    let data_dir = dir.join("data");
    let output = run(&[
        "init",
        "--config",
        config.to_str().unwrap(),
        "--data-dir",
        data_dir.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "init 失败: {}", stderr(&output));

    // init 产出的 TOML 已有 [tls] 默认段；按行替换为 ACME 配置（保持其他字段不变）。
    let text = std::fs::read_to_string(&config).unwrap();
    let text = text
        .replace("mode = \"self-signed\"", "mode = \"acme-domain\"")
        .replace("acme_email = \"\"", "acme_email = \"admin@example.com\"")
        .replace(
            "acme_directory = \"https://acme-v02.api.letsencrypt.org/directory\"",
            &format!("acme_directory = \"{directory}\""),
        )
        .replace("domains = []", "domains = [\"board.example.com\"]");
    std::fs::write(&config, text).unwrap();

    // 确认配置确实解析为 ACME 模式（防止替换没命中导致测试假通过）。
    let cfg = HubConfig::load(&config).unwrap();
    assert!(cfg.tls.mode.is_acme(), "配置未被改为 ACME 模式");

    // 删除 init 写出的自签服务端材料，只保留客户端 CA。
    let certs = tls::cert_dir(&data_dir);
    let _ = std::fs::remove_file(certs.join(tls::SERVER_CERT_FILE));
    let _ = std::fs::remove_file(certs.join(tls::SERVER_KEY_FILE));
    (dir, config)
}

fn assert_no_self_signed_server(data_dir: &Path) {
    let certs = tls::cert_dir(data_dir);
    assert!(
        !certs.join(tls::SERVER_CERT_FILE).exists(),
        "ACME 模式不得自动写自签 server.crt"
    );
    assert!(
        !certs.join(tls::SERVER_KEY_FILE).exists(),
        "ACME 模式不得自动写自签 server.key"
    );
}

#[test]
fn tls_status_without_cert_is_nonzero_and_never_self_signs() {
    let (dir, config) = prepare_acme_install("status-missing", "https://127.0.0.1:1/dir");
    let output = run(&["tls", "status", "--config", config.to_str().unwrap()]);
    assert!(!output.status.success(), "缺失证书时 status 必须非零退出");
    let out = stdout(&output);
    assert!(out.contains("证书来源: acme-domain"), "输出: {out}");
    assert!(out.contains("服务端证书: 未签发"), "输出: {out}");
    assert!(out.contains("tls issue"), "必须给出可执行提示: {out}");
    assert_no_self_signed_server(&dir.join("data"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn acme_run_without_cert_fails_actionably_without_self_signing() {
    let (dir, config) = prepare_acme_install("run-missing", "https://127.0.0.1:1/dir");
    let output = run(&["run", "--config", config.to_str().unwrap()]);
    assert!(!output.status.success(), "无 ACME 证书时 run 必须失败");
    let err = stderr(&output);
    assert!(err.contains("tls issue"), "错误必须给出可执行命令: {err}");
    assert!(
        err.contains("不会自动生成自签证书"),
        "错误必须说明不会自签: {err}"
    );
    assert_no_self_signed_server(&dir.join("data"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tls_issue_and_renew_fail_closed_and_keep_no_partial_server_material() {
    let (dir, config) = prepare_acme_install("issue-fail", "https://127.0.0.1:1/dir");
    let data_dir = dir.join("data");

    let issue = run(&["tls", "issue", "--config", config.to_str().unwrap()]);
    assert!(!issue.status.success(), "不可达 ACME 必须让 issue 非零退出");
    assert_no_self_signed_server(&data_dir);

    // renew 在没有证时同样必须 fail-closed，不能留下半套 key/cert。
    let renew = run(&["tls", "renew", "--config", config.to_str().unwrap()]);
    assert!(!renew.status.success(), "不可达 ACME 必须让 renew 非零退出");
    assert_no_self_signed_server(&data_dir);
    let _ = std::fs::remove_dir_all(&dir);
}
