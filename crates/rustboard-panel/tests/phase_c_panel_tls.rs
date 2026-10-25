//! C7：面板直连 TLS 的端到端测试。
//!
//! 通过真实 `rustboard-panel` 二进制覆盖：
//! - 安装器复制证书/私钥/hub CA、写绝对路径、强制 Cookie Secure；
//! - 真实 TLS 1.3 握手 + SNI 校验、`/healthz`、静态页、登录 Set-Cookie；
//! - 旧配置缺 `tls_cert`/`tls_key` 时 HTTP 行为不回归；
//! - `--force` 中途失败时 InstallTxn 回滚旧证书/配置；
//! - 参数组合负例（只给一个、key 0644、符号链接、http hub + --hub-ca）。
//!
//! 不依赖网络与 systemd（安装统一 `--no-systemd`；健康检查由进程内 TLS 服务
//! 或真实面板进程完成）。证书用 rcgen 在测试内生成，不落仓库。

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustboard_common::config::{CookieSecure, PanelConfig};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

const PASSWORD: &str = "phase-c-panel-password";
const HUB_TOKEN: &str = "phase-c-hub-token";
static NEXT_DIR: AtomicU64 = AtomicU64::new(0);
/// 安装器使用全局 flock（/run/rustboard-install.lock），测试进程内必须串行。
static INSTALL_LOCK: Mutex<()> = Mutex::new(());

fn dns(name: &str) -> SanType {
    SanType::DnsName(rcgen::Ia5String::try_from(name.to_string()).expect("合法 DNS SAN"))
}

fn ip_san(raw: &str) -> SanType {
    SanType::IpAddress(raw.parse().expect("合法 IP SAN"))
}

/// 测试用私有 CA + 服务端证书。
struct TestPki {
    ca_pem: String,
    ca_der: CertificateDer<'static>,
    /// leaf + CA 的 fullchain；安装器/rustls 都能直接使用。
    fullchain_pem: String,
    key_pem: String,
}

impl TestPki {
    fn new(sans: &[SanType]) -> Self {
        let ca_key = KeyPair::generate().expect("生成 CA key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "RustBoard Test CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        ca_params.key_identifier_method = rcgen::KeyIdMethod::Sha256;
        let ca_cert = ca_params.self_signed(&ca_key).expect("自签 CA");

        let leaf_key = KeyPair::generate().expect("生成 leaf key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, "rustboard-panel test");
        params.subject_alt_names = sans.to_vec();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.use_authority_key_identifier_extension = true;
        let leaf = params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("CA 签发 leaf");

        Self {
            ca_pem: ca_cert.pem(),
            ca_der: ca_cert.der().clone(),
            fullchain_pem: format!("{}{}", leaf.pem(), ca_cert.pem()),
            key_pem: leaf_key.serialize_pem(),
        }
    }
}

/// 安装前缀必须在非 sticky 目录下（`validate_install_prefix` 会拒绝 /tmp）。
/// 与既有安装器测试一致，放在测试二进制所在的 target 目录。
struct Fixture {
    root: PathBuf,
    prefix: PathBuf,
    token_file: PathBuf,
    password_file: PathBuf,
    site: PathBuf,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let base = std::env::current_exe()
            .expect("current_exe")
            .parent()
            .expect("test binary dir")
            .to_path_buf();
        let unique = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let root = base.join(format!("rb-panel-c7-{tag}-{}-{unique}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let prefix = root.join("prefix");
        let site = root.join("site");
        fs::create_dir_all(&prefix).expect("创建 prefix");
        fs::create_dir_all(site.join("assets")).expect("创建静态目录");
        fs::write(
            site.join("index.html"),
            "<!doctype html><html><body>RustBoard panel</body></html>",
        )
        .expect("写 index.html");
        fs::write(site.join("assets/app.js"), "console.log('ok');").expect("写静态资源");

        let token_file = root.join("hub-token");
        let password_file = root.join("password");
        write_private(&token_file, HUB_TOKEN);
        write_private(&password_file, PASSWORD);

        Self {
            root,
            prefix,
            token_file,
            password_file,
            site,
        }
    }

    fn config(&self) -> PathBuf {
        self.prefix.join("etc/rustboard/panel.toml")
    }

    fn installed_bin(&self) -> PathBuf {
        self.prefix.join("usr/local/bin/rustboard-panel")
    }

    fn tls_dir(&self) -> PathBuf {
        self.prefix.join("etc/rustboard/panel-tls")
    }

    fn tls_cert(&self) -> PathBuf {
        self.tls_dir().join("cert.pem")
    }

    fn tls_key(&self) -> PathBuf {
        self.tls_dir().join("key.pem")
    }

    fn hub_ca(&self) -> PathBuf {
        self.tls_dir().join("hub-ca.pem")
    }

    /// 基础 install 命令（不含 TLS 参数，调用方可继续 `.arg(...)`）。
    fn install_cmd(&self, port: u16, hub_url: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustboard-panel"));
        cmd.arg("install")
            .arg("--prefix")
            .arg(&self.prefix)
            .arg("--no-systemd")
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--hub-url")
            .arg(hub_url)
            .arg("--hub-token-file")
            .arg(&self.token_file)
            .arg("--password-file")
            .arg(&self.password_file)
            .arg("--static-dir")
            .arg(&self.site);
        // 与 hub 调起 panel 子进程时相同：测试前缀彼此独立，父进程（测试）负责
        // 串行；跳过 /run 全局锁避免与同一 workspace 的其他测试二进制互相干扰。
        cmd.env("RUSTBOARD_INSTALL_LOCK_HELD", "1");
        cmd
    }

    fn write_source_pair(&self, pki: &TestPki) -> (PathBuf, PathBuf) {
        let cert = self.root.join("source-cert.pem");
        let key = self.root.join("source-key.pem");
        write_mode(&cert, pki.fullchain_pem.as_bytes(), 0o644);
        write_mode(&key, pki.key_pem.as_bytes(), 0o600);
        (cert, key)
    }

    /// 与 [`Fixture::install_cmd`] 相同，但不传 `--hub-token-file`（测试 --force 复用）。
    fn install_cmd_without_token(&self, port: u16, hub_url: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustboard-panel"));
        cmd.arg("install")
            .arg("--prefix")
            .arg(&self.prefix)
            .arg("--no-systemd")
            .arg("--listen")
            .arg(format!("127.0.0.1:{port}"))
            .arg("--hub-url")
            .arg(hub_url)
            .arg("--password-file")
            .arg(&self.password_file)
            .arg("--static-dir")
            .arg(&self.site);
        cmd.env("RUSTBOARD_INSTALL_LOCK_HELD", "1");
        cmd
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("写测试文件");
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("设置测试文件权限");
}

fn write_private(path: &Path, text: &str) {
    write_mode(path, text.as_bytes(), 0o600);
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path)
        .expect("读取文件元数据")
        .permissions()
        .mode()
        & 0o777
}

fn pick_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("绑定临时端口");
    listener.local_addr().expect("读取临时端口").port()
}

fn run_checked(cmd: &mut Command, what: &str) -> Output {
    let output = cmd.output().expect("启动面板命令");
    if !output.status.success() {
        panic!(
            "{what} 失败（status={}）\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output
}

fn run_failed(cmd: &mut Command, what: &str) -> String {
    let output = cmd.output().expect("启动面板命令");
    if output.status.success() {
        panic!(
            "{what} 本应失败却成功\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// 真正的面板进程；Drop 时 kill，避免测试失败泄漏进程。
struct PanelProcess {
    child: Child,
    out_path: PathBuf,
    err_path: PathBuf,
}

impl PanelProcess {
    fn start(binary: &Path, config: &Path, log_dir: &Path) -> Self {
        let out_path = log_dir.join("panel.stdout.log");
        let err_path = log_dir.join("panel.stderr.log");
        let out = fs::File::create(&out_path).expect("创建 stdout 日志");
        let err = fs::File::create(&err_path).expect("创建 stderr 日志");
        let child = Command::new(binary)
            .arg("run")
            .arg("--config")
            .arg(config)
            .env("RUST_LOG", "rustboard_panel=debug")
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .expect("启动面板进程");
        Self {
            child,
            out_path,
            err_path,
        }
    }

    fn logs(&self) -> String {
        format!(
            "stdout:\n{}\nstderr:\n{}",
            fs::read_to_string(&self.out_path).unwrap_or_default(),
            fs::read_to_string(&self.err_path).unwrap_or_default()
        )
    }

    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for PanelProcess {
    fn drop(&mut self) {
        self.stop();
    }
}

fn tls_client(ca_der: CertificateDer<'static>) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(ca_der).expect("加入测试 CA");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 客户端配置")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

/// 发起一次真实 TLS 请求；证书/主机名验证失败会返回 Err（不会跳过验证）。
fn tls_request(
    config: &Arc<ClientConfig>,
    port: u16,
    sni: &str,
    request: &str,
) -> Result<Vec<u8>, String> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("连接失败: {e}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("读超时设置失败: {e}"))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("写超时设置失败: {e}"))?;
    let name = ServerName::try_from(sni.to_string()).map_err(|e| format!("SNI 非法: {e}"))?;
    let connection =
        ClientConnection::new(config.clone(), name).map_err(|e| format!("TLS 初始化失败: {e}"))?;
    let mut stream = StreamOwned::new(connection, tcp);
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("TLS 写入失败: {e}"))?;
    stream.flush().map_err(|e| format!("TLS flush 失败: {e}"))?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        if let Some(headers_end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            let header_end = headers_end + 4;
            let headers = String::from_utf8_lossy(&response[..headers_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    if key.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if response.len() >= header_end + content_length {
                break;
            }
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => response.extend_from_slice(&buffer[..read]),
            // 已拿到响应后，对端未发 close_notify 的 EOF 不应让测试误判。
            Err(_) if !response.is_empty() => break,
            Err(error) => return Err(format!("TLS 读取失败: {error}")),
        }
    }
    Ok(response)
}

fn get_request(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

fn login_request(host: &str, origin: &str) -> String {
    let body = format!("{{\"password\":\"{PASSWORD}\"}}");
    format!(
        "POST /api/login HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
}

fn status_code(response: &[u8]) -> u16 {
    let text = String::from_utf8_lossy(response);
    text.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn header_value(response: &[u8], name: &str) -> Option<String> {
    let text = String::from_utf8_lossy(response);
    let headers = text.split("\r\n\r\n").next().unwrap_or("");
    headers.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.eq_ignore_ascii_case(name) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn body_text(response: &[u8]) -> String {
    let text = String::from_utf8_lossy(response);
    text.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default()
}

fn wait_for_https(
    config: &Arc<ClientConfig>,
    port: u16,
    host: &str,
    panel: &PanelProcess,
) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = String::from("尚未连接");
    while Instant::now() < deadline {
        match tls_request(config, port, host, &get_request(host, "/healthz")) {
            Ok(response) if status_code(&response) == 200 => return response,
            Ok(response) => last = format!("HTTP {}", status_code(&response)),
            Err(error) => last = error,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("HTTPS 面板未在 20s 内就绪: {last}\n{}", panel.logs());
}

fn wait_for_http(port: u16, host: &str, panel: &PanelProcess) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last = String::from("尚未连接");
    while Instant::now() < deadline {
        let attempt = (|| -> Result<Vec<u8>, String> {
            let mut stream =
                TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("连接失败: {e}"))?;
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| format!("读超时设置失败: {e}"))?;
            stream
                .write_all(get_request(host, "/healthz").as_bytes())
                .map_err(|e| format!("写请求失败: {e}"))?;
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .map_err(|e| format!("读响应失败: {e}"))?;
            Ok(response)
        })();
        match attempt {
            Ok(response) if status_code(&response) == 200 => return response,
            Ok(response) => last = format!("HTTP {}", status_code(&response)),
            Err(error) => last = error,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("HTTP 面板未在 20s 内就绪: {last}\n{}", panel.logs());
}

#[test]
fn installed_panel_serves_https_with_secure_cookie() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("https");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (source_cert, source_key) = fixture.write_source_pair(&pki);

    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key),
        "安装面板（TLS）",
    );

    // 安装器：复制到固定路径、写绝对路径、强制 cookie_secure=always。
    let cfg = PanelConfig::load(&fixture.config()).expect("读取安装后的配置");
    assert_eq!(
        cfg.tls_cert,
        fixture.tls_cert().to_string_lossy(),
        "tls_cert 必须写安装后的绝对路径"
    );
    assert_eq!(cfg.tls_key, fixture.tls_key().to_string_lossy());
    assert_eq!(cfg.cookie_secure, CookieSecure::Always);
    assert_eq!(cfg.public_origin, "https://panel.test");
    assert!(Path::new(&cfg.tls_cert).is_absolute());
    assert_eq!(
        fs::read(fixture.tls_cert()).unwrap(),
        pki.fullchain_pem.as_bytes()
    );
    assert_eq!(fs::read(fixture.tls_key()).unwrap(), pki.key_pem.as_bytes());
    assert_eq!(mode_of(&fixture.tls_cert()), 0o644);
    assert_eq!(mode_of(&fixture.tls_key()), 0o600);
    assert_eq!(mode_of(&fixture.tls_dir()), 0o700);

    let mut panel = PanelProcess::start(&fixture.installed_bin(), &fixture.config(), &fixture.root);
    let client = tls_client(pki.ca_der.clone());
    let health = wait_for_https(&client, port, "panel.test", &panel);
    assert_eq!(body_text(&health), "ok");

    let page = tls_request(&client, port, "panel.test", &get_request("panel.test", "/"))
        .expect("HTTPS 静态页面请求失败");
    assert_eq!(status_code(&page), 200);
    assert!(body_text(&page).contains("RustBoard panel"));
    let csp = header_value(&page, "content-security-policy").expect("缺少 CSP");
    assert!(csp.contains("default-src 'self'"), "CSP 不回归: {csp}");
    assert_eq!(
        header_value(&page, "x-frame-options").as_deref(),
        Some("DENY")
    );

    let login = tls_request(
        &client,
        port,
        "panel.test",
        &login_request("panel.test", "https://panel.test"),
    )
    .expect("HTTPS 登录请求失败");
    assert_eq!(status_code(&login), 204);
    let cookie = header_value(&login, "set-cookie").expect("登录响应缺少 Set-Cookie");
    assert!(cookie.contains("rb_session="), "{cookie}");
    assert!(
        cookie.contains("; Secure"),
        "直连 HTTPS 必须带 Secure: {cookie}"
    );
    assert!(cookie.contains("HttpOnly"), "{cookie}");
    assert!(cookie.contains("SameSite=Lax"), "{cookie}");

    // Origin 不是 public_origin 时必须拒绝（同一源策略不回归）。
    let wrong_origin = tls_request(
        &client,
        port,
        "panel.test",
        &login_request("panel.test", "https://evil.example"),
    )
    .expect("跨源登录请求失败");
    assert_eq!(status_code(&wrong_origin), 403);
    assert!(body_text(&wrong_origin).contains("origin_mismatch"));

    // IP SAN 覆盖 127.0.0.1；证书/SNI 不匹配必须握手失败。
    let by_ip = tls_request(
        &client,
        port,
        "127.0.0.1",
        &get_request("127.0.0.1", "/healthz"),
    )
    .expect("IP SAN 健康检查失败");
    assert_eq!(status_code(&by_ip), 200);
    let wrong_sni = tls_request(
        &client,
        port,
        "wrong.example",
        &get_request("wrong.example", "/healthz"),
    );
    assert!(
        wrong_sni.is_err(),
        "SNI 不被证书覆盖时必须握手失败，实际: {:?}",
        wrong_sni.map(|response| status_code(&response))
    );

    panel.stop();
}

#[test]
fn legacy_config_without_tls_fields_serves_http() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("http");
    let port = pick_port();
    run_checked(
        &mut fixture.install_cmd(port, "http://127.0.0.1:1"),
        "安装面板（HTTP）",
    );

    // 模拟 v0.4.2 旧配置：删掉 C2 之后才出现的字段，验证 serde default 不回归。
    let mut text = fs::read_to_string(fixture.config()).expect("读取配置");
    text = text
        .lines()
        .filter(|line| {
            !line.starts_with("tls_cert")
                && !line.starts_with("tls_key")
                && !line.starts_with("cookie_secure")
        })
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    write_mode(&fixture.config(), text.as_bytes(), 0o600);
    let cfg = PanelConfig::load(&fixture.config()).expect("旧配置必须可解析");
    assert!(cfg.tls_cert.is_empty() && cfg.tls_key.is_empty());
    assert_eq!(cfg.cookie_secure, CookieSecure::Auto);

    let mut panel = PanelProcess::start(&fixture.installed_bin(), &fixture.config(), &fixture.root);
    let health = wait_for_http(port, &format!("127.0.0.1:{port}"), &panel);
    assert_eq!(body_text(&health), "ok");

    let origin = format!("http://127.0.0.1:{port}");
    let target = format!("127.0.0.1:{port}");
    let login = {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("HTTP 登录连接");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(login_request(&target, &origin).as_bytes())
            .expect("写 HTTP 登录请求");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("读 HTTP 登录响应");
        response
    };
    assert_eq!(status_code(&login), 204);
    let cookie = header_value(&login, "set-cookie").expect("HTTP 登录缺少 Set-Cookie");
    assert!(cookie.contains("rb_session="));
    assert!(
        !cookie.contains("; Secure"),
        "旧 HTTP 配置（auto）不得擅自加 Secure: {cookie}"
    );

    panel.stop();
}

#[test]
fn installer_rejects_incomplete_or_unsafe_tls_sources() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("negative");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (source_cert, source_key) = fixture.write_source_pair(&pki);

    // 只给 --tls-cert。
    let error = run_failed(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert),
        "只给 --tls-cert",
    );
    assert!(error.contains("--tls-key"), "{error}");
    assert!(!fixture.config().exists(), "失败安装不得写配置");

    // 源 key 0644。
    fs::set_permissions(&source_key, fs::Permissions::from_mode(0o644)).unwrap();
    let error = run_failed(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key),
        "源 key 0644",
    );
    assert!(error.contains("0600"), "{error}");
    fs::set_permissions(&source_key, fs::Permissions::from_mode(0o600)).unwrap();

    // 源 key 符号链接。
    let link = fixture.root.join("source-key-link.pem");
    std::os::unix::fs::symlink(&source_key, &link).expect("创建符号链接");
    let error = run_failed(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&link),
        "源 key 符号链接",
    );
    assert!(error.contains("符号链接"), "{error}");

    // public_origin 主机不在证书 SAN 内。
    let error = run_failed(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key)
            .arg("--public-origin")
            .arg("https://evil.example"),
        "public_origin 未被 SAN 覆盖",
    );
    assert!(
        error.contains("SAN") || error.contains("public_origin"),
        "{error}"
    );

    assert!(!fixture.config().exists(), "所有失败分支都必须零写入");
    assert!(!fixture.tls_dir().exists(), "失败安装不得创建 panel-tls");
}

#[test]
fn dry_run_with_tls_writes_nothing_and_forces_cookie_secure() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("dry-run");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (source_cert, source_key) = fixture.write_source_pair(&pki);

    let output = run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key)
            .arg("--cookie-secure")
            .arg("never")
            .arg("--dry-run"),
        "dry-run TLS 安装",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("HTTPS"), "{stdout}");
    assert!(stdout.contains("Cookie Secure: always"), "{stdout}");
    assert!(stderr.contains("强制"), "应提示强制 always: {stderr}");
    assert!(!fixture.config().exists(), "dry-run 不得写配置");
    assert!(!fixture.tls_dir().exists(), "dry-run 不得创建 TLS 目录");
}

#[test]
fn hub_ca_requires_https_hub_and_is_copied_into_prefix() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("hub-ca");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test")]);
    let ca_source = fixture.root.join("hub-ca-source.pem");
    write_mode(&ca_source, pki.ca_pem.as_bytes(), 0o644);

    let error = run_failed(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--hub-ca")
            .arg(&ca_source),
        "http hub + --hub-ca",
    );
    assert!(error.contains("https"), "{error}");
    assert!(!fixture.config().exists());

    run_checked(
        fixture
            .install_cmd(port, "https://hub.example:8444")
            .arg("--hub-ca")
            .arg(&ca_source),
        "https hub + --hub-ca",
    );
    let cfg = PanelConfig::load(&fixture.config()).expect("读取 hub_ca 配置");
    assert_eq!(cfg.hub_url, "https://hub.example:8444");
    assert_eq!(cfg.hub_ca, fixture.hub_ca().to_string_lossy());
    assert_eq!(fs::read(fixture.hub_ca()).unwrap(), pki.ca_pem.as_bytes());
    assert_eq!(mode_of(&fixture.hub_ca()), 0o644);
}

#[test]
fn required_hub_admin_tls_accepts_https_with_hub_ca() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("required-hub");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test")]);
    let ca_source = fixture.root.join("hub-ca-source.pem");
    write_mode(&ca_source, pki.ca_pem.as_bytes(), 0o644);

    let hub_toml = fixture.prefix.join("etc/rustboard/hub.toml");
    fs::create_dir_all(hub_toml.parent().unwrap()).unwrap();
    write_mode(
        &hub_toml,
        b"admin_listen = \"127.0.0.1:18444\"\nadmin_tls = \"required\"\nadmin_token = \"phase-c-hub-token\"\n",
        0o600,
    );

    // 即使显式给了 --hub-url http://...，required hub 也必须拒绝。
    let error = run_failed(
        &mut fixture.install_cmd(port, "http://127.0.0.1:18444"),
        "required hub + http 地址",
    );
    assert!(error.contains("admin_tls=required"), "{error}");
    assert!(error.contains("https"), "{error}");
    assert!(!fixture.config().exists());

    // 显式 https + --hub-ca 时必须通过（hub 安装器走这条路径）。
    run_checked(
        fixture
            .install_cmd(port, "https://hub.example:18444")
            .arg("--hub-ca")
            .arg(&ca_source),
        "required hub + https + --hub-ca",
    );
    let cfg = PanelConfig::load(&fixture.config()).expect("读取 required hub 配置");
    assert_eq!(cfg.hub_url, "https://hub.example:18444");
    assert_eq!(cfg.hub_ca, fixture.hub_ca().to_string_lossy());
    assert_eq!(fs::read(fixture.hub_ca()).unwrap(), pki.ca_pem.as_bytes());

    // hub 切回 admin_tls=off 后 --force：旧 hub_ca 必须被清掉，不能留下
    // http hub + hub_ca 的矛盾配置（ProxyClient 启动会拒绝）。
    write_mode(
        &hub_toml,
        b"admin_listen = \"127.0.0.1:18444\"\nadmin_tls = \"off\"\nadmin_token = \"phase-c-hub-token\"\n",
        0o600,
    );
    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:18444")
            .arg("--force"),
        "hub 切回 off 的 --force 安装",
    );
    let cfg = PanelConfig::load(&fixture.config()).expect("读取切回 off 的配置");
    assert_eq!(cfg.hub_url, "http://127.0.0.1:18444");
    assert!(
        cfg.hub_ca.is_empty(),
        "http hub 不得保留旧 hub_ca: {:?}",
        cfg.hub_ca
    );
}

#[test]
fn force_install_rolls_back_tls_files_on_key_write_failure() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("rollback");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (source_cert, source_key) = fixture.write_source_pair(&pki);
    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key),
        "首次 TLS 安装",
    );
    let config_before = fs::read(fixture.config()).expect("读取旧配置");
    let cert_before = fs::read(fixture.tls_cert()).expect("读取旧证书");

    // 把目标 key 换成目录：事务写 key 时必然失败，触发回滚。
    fs::remove_file(fixture.tls_key()).expect("删除旧 key");
    fs::create_dir(fixture.tls_key()).expect("用目录占位 key");

    let pki2 = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (cert2, key2) = fixture.write_source_pair(&pki2);
    let error = run_failed(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--force")
            .arg("--tls-cert")
            .arg(&cert2)
            .arg("--tls-key")
            .arg(&key2),
        "key 目标为目录的 --force 安装",
    );
    assert!(
        error.contains("不是普通文件") || error.contains("回滚"),
        "错误信息应说明事务拒绝/回滚: {error}"
    );

    assert_eq!(
        fs::read(fixture.config()).unwrap(),
        config_before,
        "回滚必须恢复旧配置"
    );
    assert_eq!(
        fs::read(fixture.tls_cert()).unwrap(),
        cert_before,
        "回滚必须恢复旧证书"
    );
    let cfg = PanelConfig::load(&fixture.config()).expect("回滚后的配置必须可解析");
    assert_eq!(cfg.tls_cert, fixture.tls_cert().to_string_lossy());
}

#[test]
fn force_without_tls_args_reuses_existing_installed_files() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("reuse");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (source_cert, source_key) = fixture.write_source_pair(&pki);
    let mut first = fixture.install_cmd(port, "http://127.0.0.1:1");
    run_checked(
        first
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key),
        "首次 TLS 安装",
    );
    let cert_before = fs::read(fixture.tls_cert()).expect("读取证书");
    let key_before = fs::read(fixture.tls_key()).expect("读取私钥");

    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--force"),
        "--force 复用旧 TLS 配置",
    );
    assert_eq!(fs::read(fixture.tls_cert()).unwrap(), cert_before);
    assert_eq!(fs::read(fixture.tls_key()).unwrap(), key_before);
    let cfg = PanelConfig::load(&fixture.config()).expect("配置可解析");
    assert_eq!(cfg.cookie_secure, CookieSecure::Always);
    assert_eq!(cfg.public_origin, "https://panel.test");
}

#[test]
fn merged_cert_or_hub_ca_pem_is_rejected_before_write() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("merged-pem");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (_, source_key) = fixture.write_source_pair(&pki);

    // cert+key 合并 PEM 传给 --tls-cert：load_certs 会跳过私钥块，若不拦截会把
    // 面板私钥以 0644 复制到 panel-tls/cert.pem。
    let merged_cert = fixture.root.join("merged-cert.pem");
    write_mode(
        &merged_cert,
        format!("{}{}", pki.fullchain_pem, pki.key_pem).as_bytes(),
        0o644,
    );
    let error = run_failed(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&merged_cert)
            .arg("--tls-key")
            .arg(&source_key),
        "cert+key 合并 PEM",
    );
    assert!(
        error.contains("CERTIFICATE") || error.contains("私钥"),
        "{error}"
    );
    assert!(!fixture.config().exists(), "失败安装不得写配置");
    assert!(!fixture.tls_dir().exists(), "失败安装不得创建 panel-tls");

    // hub-ca+key 合并 PEM：同样必须在写盘前拒绝。
    let merged_hub_ca = fixture.root.join("merged-hub-ca.pem");
    write_mode(
        &merged_hub_ca,
        format!("{}{}", pki.ca_pem, pki.key_pem).as_bytes(),
        0o644,
    );
    let error = run_failed(
        fixture
            .install_cmd(port, "https://hub.example:8444")
            .arg("--hub-ca")
            .arg(&merged_hub_ca),
        "hub-ca+key 合并 PEM",
    );
    assert!(
        error.contains("CERTIFICATE") || error.contains("私钥"),
        "{error}"
    );
    assert!(!fixture.config().exists());
    assert!(!fixture.tls_dir().exists());
}

#[test]
fn force_refuses_silent_https_downgrade_and_explicit_http_cleans_up() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("downgrade");
    let port = pick_port();
    run_checked(
        &mut fixture.install_cmd(port, "http://127.0.0.1:1"),
        "首次 HTTP 安装",
    );

    // 旧配置损坏 + 残留 panel-tls 材料：--force 未传 TLS 参数时不得静默降级。
    fs::create_dir_all(fixture.tls_dir()).unwrap();
    fs::set_permissions(fixture.tls_dir(), fs::Permissions::from_mode(0o700)).unwrap();
    write_mode(&fixture.tls_cert(), b"stale-cert", 0o644);
    write_mode(&fixture.tls_key(), b"stale-private-key", 0o600);
    write_mode(&fixture.hub_ca(), b"stale-ca", 0o644);
    let corrupt = b"this is not = [valid toml";
    write_mode(&fixture.config(), corrupt, 0o600);

    let error = run_failed(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--force"),
        "--force 无 TLS 参数且旧配置损坏",
    );
    assert!(
        error.contains("拒绝") && (error.contains("--http") || error.contains("--tls-cert")),
        "{error}"
    );
    assert_eq!(
        fs::read(fixture.config()).unwrap(),
        corrupt,
        "fail-closed 不得改写旧配置"
    );
    assert_eq!(
        fs::read(fixture.tls_key()).unwrap(),
        b"stale-private-key",
        "fail-closed 不得删除私钥"
    );

    // 显式 --http：允许降级，并用事务删除 cert/key/hub-ca，随后删除空目录。
    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--force")
            .arg("--http"),
        "--force --http 显式降级",
    );
    let cfg = PanelConfig::load(&fixture.config()).expect("降级后的配置必须可解析");
    assert!(cfg.tls_cert.is_empty() && cfg.tls_key.is_empty(), "{cfg:?}");
    assert!(!fixture.tls_key().exists(), "显式降级必须删除旧面板私钥");
    assert!(
        !fixture.tls_dir().exists(),
        "已知 TLS 材料删完后应删除空 panel-tls 目录"
    );
}

/// 构造不带 `--hub-url` / `--hub-token-file` 的 --force 安装命令。
fn force_install_cmd(fixture: &Fixture, port: u16) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustboard-panel"));
    cmd.arg("install")
        .arg("--prefix")
        .arg(&fixture.prefix)
        .arg("--no-systemd")
        .arg("--listen")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--password-file")
        .arg(&fixture.password_file)
        .arg("--static-dir")
        .arg(&fixture.site)
        .arg("--force");
    cmd.env("RUSTBOARD_INSTALL_LOCK_HELD", "1");
    cmd
}

#[test]
fn force_preserves_hub_url_and_token_from_base_config() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("force-hub");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test")]);
    let ca_source = fixture.root.join("hub-ca-source.pem");
    write_mode(&ca_source, pki.ca_pem.as_bytes(), 0o644);
    run_checked(
        fixture
            .install_cmd(port, "https://remote.example:8444")
            .arg("--hub-ca")
            .arg(&ca_source),
        "首次 HTTPS 远程 hub 安装",
    );
    let before = PanelConfig::load(&fixture.config()).expect("读取首次安装配置");
    assert_eq!(before.hub_url, "https://remote.example:8444");
    assert_eq!(before.token, HUB_TOKEN);
    assert_eq!(before.hub_ca, fixture.hub_ca().to_string_lossy());

    // 未显式 --hub-url / --hub-token-file：必须保留旧地址与 token。
    run_checked(
        &mut force_install_cmd(&fixture, port),
        "--force 保留旧 hub_url/token",
    );
    let after = PanelConfig::load(&fixture.config()).expect("读取 --force 配置");
    assert_eq!(after.hub_url, "https://remote.example:8444");
    assert_eq!(after.token, HUB_TOKEN);
    assert_eq!(after.hub_ca, fixture.hub_ca().to_string_lossy());

    // 显式改到不同地址但没有 token 文件：拒绝，避免旧 token 被发到新地址。
    let before_bytes = fs::read(fixture.config()).unwrap();
    let error = run_failed(
        fixture
            .install_cmd_without_token(port, "http://127.0.0.1:18444")
            .arg("--force"),
        "--force 改 hub_url 且无 token 文件",
    );
    assert!(error.contains("--hub-token-file"), "{error}");
    assert_eq!(
        fs::read(fixture.config()).unwrap(),
        before_bytes,
        "拒绝时不得改写配置"
    );

    // 显式 token 文件：允许切换地址。
    let token_file = fixture.root.join("new-hub-token");
    write_private(&token_file, "new-hub-token-value");
    run_checked(
        fixture
            .install_cmd_without_token(port, "http://127.0.0.1:18444")
            .arg("--force")
            .arg("--hub-token-file")
            .arg(&token_file),
        "--force 切换地址且显式提供 token",
    );
    let switched = PanelConfig::load(&fixture.config()).expect("读取切换后的配置");
    assert_eq!(switched.hub_url, "http://127.0.0.1:18444");
    assert_eq!(switched.token, "new-hub-token-value");
}

fn uninstall_cmd(fixture: &Fixture, purge: bool) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rustboard-panel"));
    cmd.arg("uninstall")
        .arg("--prefix")
        .arg(&fixture.prefix)
        .arg("--yes");
    if purge {
        cmd.arg("--purge");
    }
    cmd.env("RUSTBOARD_INSTALL_LOCK_HELD", "1");
    cmd
}

#[test]
fn uninstall_purge_removes_panel_tls_private_key() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("purge-tls");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (source_cert, source_key) = fixture.write_source_pair(&pki);
    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key),
        "安装面板（TLS，准备 purge）",
    );
    assert!(fixture.tls_key().exists());

    run_checked(&mut uninstall_cmd(&fixture, true), "uninstall --purge");
    assert!(!fixture.config().exists(), "--purge 应删除配置");
    assert!(
        !fixture.prefix.join("var/lib/rustboard/panel").exists(),
        "--purge 应删除数据目录"
    );
    assert!(
        !fixture.tls_dir().exists(),
        "--purge 应删除 panel-tls 目录（含私钥）"
    );
    assert!(!fixture.tls_key().exists(), "私钥不得残留");
}

#[test]
fn uninstall_without_purge_keeps_panel_tls_private_key() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("keep-tls");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (source_cert, source_key) = fixture.write_source_pair(&pki);
    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key),
        "安装面板（TLS，准备非 purge）",
    );

    run_checked(&mut uninstall_cmd(&fixture, false), "uninstall（保留）");
    assert!(fixture.config().exists(), "非 --purge 必须保留配置");
    assert!(fixture.tls_key().exists(), "非 --purge 必须保留私钥");
    assert_eq!(mode_of(&fixture.tls_key()), 0o600);
}

#[test]
fn force_explicit_http_downgrades_valid_tls_config_and_removes_key() {
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new("downgrade-valid");
    let port = pick_port();
    let pki = TestPki::new(&[dns("panel.test"), ip_san("127.0.0.1")]);
    let (source_cert, source_key) = fixture.write_source_pair(&pki);
    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--tls-cert")
            .arg(&source_cert)
            .arg("--tls-key")
            .arg(&source_key),
        "首次 TLS 安装（准备显式降级）",
    );
    let before = PanelConfig::load(&fixture.config()).expect("读取 TLS 配置");
    assert!(!before.tls_cert.is_empty() && !before.tls_key.is_empty());
    assert_eq!(before.cookie_secure, CookieSecure::Always);
    assert_eq!(before.public_origin, "https://panel.test");

    run_checked(
        fixture
            .install_cmd(port, "http://127.0.0.1:1")
            .arg("--force")
            .arg("--http"),
        "--force --http 显式降级有效 TLS 配置",
    );
    let after = PanelConfig::load(&fixture.config()).expect("读取降级后的配置");
    assert!(
        after.tls_cert.is_empty() && after.tls_key.is_empty(),
        "{after:?}"
    );
    assert_eq!(
        after.cookie_secure,
        CookieSecure::Auto,
        "HTTP 不得沿用 always"
    );
    assert!(
        after.public_origin.is_empty(),
        "显式降级不得沿用直连 TLS 推导的 https origin"
    );
    assert_eq!(after.hub_url, "http://127.0.0.1:1");
    assert_eq!(after.token, HUB_TOKEN);
    assert!(!fixture.tls_dir().exists(), "旧 panel-tls 目录应删除");
    assert!(!fixture.tls_key().exists(), "旧私钥不得残留");
}
