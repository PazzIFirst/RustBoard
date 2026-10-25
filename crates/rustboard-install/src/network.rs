//! 安装器使用的 HTTPS 健康检查客户端。
//!
//! `hub install` 在 `admin_tls = "required"` 时必须用 HTTPS + 配置里的主机名
//! （SNI / 证书主机名校验）访问 `/healthz`。这里不引入 openssl / aws-lc，直接
//! 用工作区既有的 rustls（ring provider）：
//!
//! - 给定 CA PEM 时只信任该 CA（自签 hub / 私有 ACME）；否则使用系统根；
//! - `ServerName` 必须来自配置（`server_names` / `tls.domains`），证书链与
//!   主机名都必须通过校验，**没有任何跳过校验的分支**；
//! - 与 [`crate::wait_http_ok`] 一致，最多等待 30 秒，每 1 秒重试一次；
//! - 错误信息只含地址、SNI 与公开的 TLS 错误原因，不含私钥 / token。

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

/// 等待上限与 [`crate::wait_http_ok`] 一致（调用方传更长也会截断）。
const MAX_TIMEOUT: Duration = Duration::from_secs(30);
/// 单次连接/读写的上限，避免一次 TLS 握手拖满整个等待窗口。
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
/// 只读取响应头，避免健康检查把大响应读进内存。
const MAX_RESPONSE: usize = 64 * 1024;

/// 等待 `addr` 上的 HTTPS `/healthz` 返回 200。
///
/// - `addr`：实际连接地址（通常是 hub 管理口的回环 / 绑定地址）；
/// - `server_name`：配置中的主机名或 IP，用于 SNI 与证书主机名校验；
/// - `ca_pem`：`Some(pem)` 时只信任该 PEM 中的 CA；`None` 使用系统根。
///
/// 证书链、主机名、有效期全部由 rustls 校验；不会走任何“跳过校验”的路径。
pub fn wait_https_ok_with_server_name(
    addr: SocketAddr,
    server_name: &str,
    ca_pem: Option<&str>,
    timeout: Duration,
) -> Result<()> {
    let server_name = server_name.trim();
    if server_name.is_empty() {
        bail!("HTTPS 健康检查缺少 server_name（配置里的 server_names / tls.domains 为空）");
    }
    let config = client_config(ca_pem)?;
    let name = ServerName::try_from(server_name.to_string()).map_err(|err| {
        anyhow!("HTTPS 健康检查的 server_name {server_name:?} 不是合法 DNS 名或 IP: {err}")
    })?;

    let timeout = timeout.min(MAX_TIMEOUT);
    let deadline = Instant::now() + timeout;
    let last_error = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let attempt_timeout = if remaining.is_zero() {
            Duration::from_millis(1)
        } else {
            remaining.min(ATTEMPT_TIMEOUT)
        };
        match probe_https(
            addr,
            name.clone(),
            server_name,
            config.clone(),
            attempt_timeout,
        ) {
            Ok(()) => return Ok(()),
            Err(err) => {
                let message = format!("{err:#}");
                let now = Instant::now();
                if now >= deadline {
                    break message;
                }
                std::thread::sleep(Duration::from_secs(1).min(deadline - now));
            }
        }
    };
    bail!(
        "等待 https://{server_name}:{}/healthz 返回 200 超时（上限 {:.1}s，连接 {addr}），\
         最后一次错误: {last_error}",
        addr.port(),
        timeout.as_secs_f64()
    )
}

/// 构造客户端 TLS 配置：给定 CA 或系统根；两者都验证链与主机名。
fn client_config(ca_pem: Option<&str>) -> Result<Arc<ClientConfig>> {
    match ca_pem {
        Some(pem) if !pem.trim().is_empty() => {
            rustboard_common::tls::client_config_custom_ca(pem, None, None)
                .context("加载 HTTPS 健康检查使用的 hub CA 失败")
        }
        _ => rustboard_common::tls::client_config_system_roots(None, None)
            .context("加载系统根证书失败（HTTPS 健康检查）"),
    }
}

/// 单次 HTTPS 探测：TCP → TLS（校验链/主机名）→ GET /healthz → 要求 200。
fn probe_https(
    addr: SocketAddr,
    server_name: ServerName<'static>,
    // 原始配置主机名，仅用于 Host 头与可读错误；证书校验用 `server_name`。
    host: &str,
    config: Arc<ClientConfig>,
    timeout: Duration,
) -> Result<()> {
    let tcp =
        TcpStream::connect_timeout(&addr, timeout).with_context(|| format!("连接 {addr} 失败"))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    let connection = ClientConnection::new(config, server_name.clone())
        .with_context(|| format!("初始化 TLS 连接失败（SNI {server_name:?}）"))?;
    let mut stream = StreamOwned::new(connection, tcp);

    // 写入时会驱动 TLS 握手；证书 / 主机名校验失败会在这里返回。
    let request = format!(
        "GET /healthz HTTP/1.1\r\nHost: {host}\r\n\
         User-Agent: rustboard-install-healthcheck\r\nAccept: */*\r\n\
         Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .with_context(|| format!("TLS 握手或发送健康检查请求失败（SNI {server_name:?}）"))?;
    stream.flush().context("刷新 HTTPS 健康检查请求失败")?;

    let mut response = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let read = stream.read(&mut chunk).context(
            "读取 HTTPS 健康检查响应失败（TLS 证书链 / 主机名校验不通过也会在这里报错）",
        )?;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&chunk[..read]);
        if response.windows(4).any(|window| window == b"\r\n\r\n") || response.len() >= MAX_RESPONSE
        {
            break;
        }
    }
    if response.is_empty() {
        bail!("HTTPS 健康检查没有收到响应（SNI {server_name:?}）");
    }
    let head = String::from_utf8_lossy(&response);
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| anyhow!("HTTPS 健康检查响应缺少状态行"))?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code: u16 = parts
        .next()
        .ok_or_else(|| anyhow!("HTTPS 健康检查状态行非法: {status_line:?}"))?
        .parse()
        .with_context(|| format!("HTTPS 健康检查状态码非法: {status_line:?}"))?;
    if !version.starts_with("HTTP/1.") {
        bail!("HTTPS 健康检查响应不是 HTTP/1.x: {status_line:?}");
    }
    if code != 200 {
        bail!("HTTPS 健康检查返回 HTTP {code}，期望 200（SNI {server_name:?}）");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    use rcgen::CertifiedKey;

    /// 生成自签服务端证书（SAN = host），返回 `(cert_pem, key_pem)`。
    fn self_signed(host: &str) -> (String, String) {
        let CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![host.to_string()]).expect("生成测试证书");
        (cert.pem(), key_pair.serialize_pem())
    }

    /// 起一个只响应 `/healthz 200` 的本地 TLS 服务；最多处理 4 条连接。
    fn spawn_tls_server(cert_pem: &str, key_pem: &str) -> SocketAddr {
        let config = rustboard_common::tls::server_config_from_paths(cert_pem, key_pem)
            .expect("构建测试 TLS 服务端配置");
        let listener = TcpListener::bind("127.0.0.1:0").expect("绑定 TLS 测试端口");
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            for _ in 0..4 {
                let Ok((tcp, _)) = listener.accept() else {
                    return;
                };
                let config = config.clone();
                thread::spawn(move || {
                    let Ok(connection) = rustls::ServerConnection::new(config) else {
                        return;
                    };
                    let mut stream = rustls::StreamOwned::new(connection, tcp);
                    let mut request = [0u8; 2048];
                    let _ = stream.read(&mut request);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    );
                    let _ = stream.flush();
                    stream.conn.send_close_notify();
                    let _ = stream.flush();
                });
            }
        });
        addr
    }

    #[test]
    fn accepts_matching_ca_and_server_name() {
        let (cert, key) = self_signed("localhost");
        let addr = spawn_tls_server(&cert, &key);
        wait_https_ok_with_server_name(addr, "localhost", Some(&cert), Duration::from_secs(5))
            .expect("正确 CA + 主机名应通过");
    }

    #[test]
    fn rejects_wrong_server_name() {
        let (cert, key) = self_signed("localhost");
        let addr = spawn_tls_server(&cert, &key);
        let err = wait_https_ok_with_server_name(
            addr,
            "wrong.example",
            Some(&cert),
            Duration::from_millis(700),
        )
        .expect_err("错误 SNI 必须失败");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("超时") || rendered.to_ascii_lowercase().contains("certificate"),
            "错误信息应可读: {rendered}"
        );
    }

    #[test]
    fn rejects_wrong_ca() {
        let (cert, key) = self_signed("localhost");
        let (other_cert, _other_key) = self_signed("localhost");
        let addr = spawn_tls_server(&cert, &key);
        let err = wait_https_ok_with_server_name(
            addr,
            "localhost",
            Some(&other_cert),
            Duration::from_millis(700),
        )
        .expect_err("错误 CA 必须失败");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("超时") || rendered.contains("证书") || rendered.contains("CA"),
            "错误信息应可读: {rendered}"
        );
    }

    #[test]
    fn system_roots_do_not_trust_local_self_signed() {
        let (cert, key) = self_signed("localhost");
        let addr = spawn_tls_server(&cert, &key);
        let err =
            wait_https_ok_with_server_name(addr, "localhost", None, Duration::from_millis(700))
                .expect_err("系统根不应信任本地自签证书");
        assert!(format!("{err:#}").contains("超时"), "{err:#}");
    }

    #[test]
    fn rejects_invalid_server_name_argument() {
        let err = wait_https_ok_with_server_name(
            SocketAddr::from(([127, 0, 0, 1], 9)),
            "",
            None,
            Duration::from_millis(1),
        )
        .expect_err("空 server_name 必须拒绝");
        assert!(err.to_string().contains("server_name"), "{err}");

        let err = wait_https_ok_with_server_name(
            SocketAddr::from(([127, 0, 0, 1], 9)),
            "bad name/with spaces",
            None,
            Duration::from_millis(1),
        )
        .expect_err("非法 server_name 必须拒绝");
        assert!(err.to_string().contains("server_name"), "{err}");
    }

    #[test]
    fn closed_port_fails_within_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let started = Instant::now();
        let err =
            wait_https_ok_with_server_name(addr, "localhost", None, Duration::from_millis(300))
                .expect_err("拒绝连接必须失败");
        assert!(format!("{err:#}").contains("超时"), "{err:#}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "超时没有生效: {:?}",
            started.elapsed()
        );
    }
}
