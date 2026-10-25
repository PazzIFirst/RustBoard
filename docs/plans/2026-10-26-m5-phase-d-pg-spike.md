# M5 Phase D D0：PostgreSQL 驱动、连接池、TLS 与阻塞边界 spike 结论

> 状态：完成（D0 的 PostgreSQL 部分）｜执行日期：2026-10-26｜基线：`3cbeb9b`
> 关联：[Phase D 计划](2026-10-26-m5-phase-d-postgres-backup-l01-l03.md) §3.2、§5 D0、§8；
> [Phase C spike](2026-10-25-m5-phase-c-spike.md)。
>
> 本 spike 只改临时目录 `/tmp/rb-pg-spike`，未修改仓库 `Cargo.toml`、`Cargo.lock`
> 或任何生产源码；仓库内唯一新增文件是本文档。

## 0. 结论摘要

| 未知项 | 结论 | 关键证据 |
|---|---|---|
| `postgres 0.19.14` 同步客户端能否自定义 `MakeTlsConnect` 包装 `rustls::StreamOwned<ClientConnection, TcpStream>` | **不可行** | `postgres::Socket` 是不透明类型，没有 `into_std()`；`StreamOwned` 也不是 `AsyncRead`/`AsyncWrite`。最小原型编译报 `E0599` + 两个 `E0277` |
| 同步 `postgres` 客户端能否完成 `sslmode=verify-full` | **可以**，但必须用 `tokio-postgres-rustls` 提供 async TLS 流；**驱动本身不接受 `verify-full` 字面值** | TLS 1.3 连接成功；空根证书/错误主机名均被 rustls 拒绝；`sslmode=verify-full` 由配置层剥离后映射为 `require` + 校验型 `ClientConfig` |
| 同步客户端能否直接在 tokio worker 上调用 | **不能，会 panic**，不是“慢”而是运行时嵌套 | 在 tokio 任务内 `postgres::Config::connect` panic：`Cannot start a runtime from within a runtime`（`postgres-0.19.14/src/config.rs:465`） |
| 连接池 | **r2d2 0.8.10 + 自定义 `ManageConnection`** | 有界、`get_timeout`、`test_on_check_out`、断线自动替换；实测 reconnect 13–19 ms，容器重启后 519.7 ms 恢复 |
| 是否必须 `spawn_blocking` | **必须，所有 PG 调用都要在 blocking 线程上** | 8 worker + 200 任务：`spawn_blocking` 时 ticker p95 0.7 ms、轻量请求 p50 32–43 ms；直接阻塞模型 ticker/轻量请求被拖到约 1.48 s |
| 依赖/MSRV | 可满足 MSRV 1.89，且无 openssl / aws-lc / native-tls / cmake | `cargo +1.89.0 build --release` 成功并实际跑通查询；`cargo tree -i` 全部 absent；`ldd` 无 libssl/libcrypto |
| `sslmode` 语义 | 只支持显式 `disable` 与 `verify-full`；**拒绝** `require`/`prefer`/`verify-ca`/`allow` | 实测 `prefer` 会在服务端不支持 TLS 时静默回落明文；`require` 只保证加密、不保证主机名校验，语义易误用 |
| 根证书 | 默认系统根；私有 CA 用 `sslrootcert` 文件覆盖系统根 | 系统根 148 张时私有 CA 仍 `UnknownIssuer`；`SSL_CERT_FILE` 注入测试 CA 后成功；`sslrootcert` 在 DSN 中会被驱动当作未知参数拒绝，需配置层解析 |
| 额外发现 | `rustls-pemfile 2.2.0` 已 unmaintained（RUSTSEC-2025-0134），不要引入 | 改用 `rustls-pki-types` 的 `CertificateDer::pem_file_iter`，编译/运行通过，`cargo audit` 干净 |

**一句话结论**：D0 不改驱动方向，选 **`postgres 0.19.14` 同步 API + `tokio-postgres-rustls 0.14.0`（ring）+ `r2d2 0.8.10` 自定义 Manager**；但 D1/D3 必须把“所有 PG 调用在 `spawn_blocking` 上、连接池生命周期在 tokio runtime 之外”作为硬约束，而不是性能优化项。

## 1. 实测环境

| 项 | 值 |
|---|---|
| 主机 | Linux x86_64，Debian GNU/Linux 13 (trixie)，内核 6.12.111 |
| CPU / 内存 | 16 vCPU / 17 GiB |
| 当前工具链 | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` / `cargo 1.99.1` |
| MSRV 工具链 | `rustc 1.89.0 (29483883e 2025-08-04)` / `cargo 1.89.0` |
| Docker | `Docker version 29.7.2` |
| PostgreSQL | `postgres:16`，容器内 `PostgreSQL 16.15 (Debian 16.15-1.pgdg13+2)`，`ssl=on` |
| 测试拓扑 | 宿主机经 `127.0.0.1:55432` → 容器 `5432`；服务端地址 `172.17.0.2/32`，TLS 1.3 / `TLS_AES_256_GCM_SHA384` |
| 明文对照库 | `postgres:16`，`ssl=off`，`127.0.0.1:55433`，仅用于验证 `prefer`/`require` 语义 |
| 临时 crate | `/tmp/rb-pg-spike`（spike 结束后删除）；`CARGO_TARGET_DIR=/root/.cache/rb-pg-spike-target`（避免 `/tmp` 空间不足） |
| 测试证书 | 临时自签 CA + `CN=localhost`、`SAN=DNS:localhost` 的服务端证书；只用于本地回环，已随临时目录删除 |
| 密码 | 文档与命令中统一用 `<TEST_PASSWORD>`；实际测试密码只存在于临时 env 文件，未写入本文 |
| 时间 | 2026-10-26（Asia/Manila） |

> 说明：所有“DB 时间”都是本机 Docker 回环，不代表生产网络 RTT。生产网络可能把 20–100 ms 的 DB 工作进一步放大；这不改变阻塞边界的结论，只会让 `spawn_blocking` 更必要。

## 2. 依赖与版本

临时 crate 的关键依赖（精确版本）：

```toml
[dependencies]
postgres = "=0.19.14"
r2d2 = "=0.8.10"
rustls = { version = "=0.23.46", default-features = false, features = ["ring", "std", "logging"] }
rustls-native-certs = "=0.8.3"
tokio = { version = "=1.54.1", features = ["rt-multi-thread", "macros", "time", "sync"] }
tokio-postgres-rustls = { version = "=0.14.0", default-features = false, features = ["ring"] }
tokio-postgres = "=0.7.18"   # 仅 fallback 实验直接使用
```

实际解析到的关键版本：

| crate | 版本 | rust-version | 说明 |
|---|---|---|---|
| `postgres` | 0.19.14 | 1.85 | 同步客户端 |
| `tokio-postgres` | 0.7.18 | 1.85 | `postgres` 的底层 async 驱动 |
| `tokio-postgres-rustls` | 0.14.0 | 未声明（1.89 实测通过） | async rustls TLS 适配，启用 `ring` |
| `rustls` | 0.23.46 | 1.71 | 只启用 `ring`，无 aws-lc |
| `tokio-rustls` | 0.26.6 | 1.71 | 传递依赖 |
| `ring` | 0.17.14 | 1.66 | 加密后端 |
| `r2d2` | 0.8.10 | 未声明（1.89 实测通过） | 连接池 |
| `rustls-native-certs` | 0.8.3 | 1.71 | 系统根证书 |
| `sha2` | 0.11.1 | 1.88 | 工作区 `Cargo.lock` 已有同版本，不是新增版本 |
| `x509-cert` | 0.2.5 | 1.65 | `tokio-postgres-rustls` 新增；用于 channel binding 计算 |

依赖图检查（完整输出保存在临时 `results/final_deps_env.txt`，结论如下）：

```text
$ cargo tree --locked -e normal,build | grep -Ei 'openssl|aws-lc|native-tls|cmake'
│   ├── openssl-probe v0.2.1

$ for c in openssl openssl-sys aws-lc-rs aws-lc-sys native-tls cmake; do
    cargo tree --locked -i "$c" >/dev/null 2>&1 \
      && echo "FOUND: $c" || echo "absent: $c"
  done
absent: openssl
absent: openssl-sys
absent: aws-lc-rs
absent: aws-lc-sys
absent: native-tls
absent: cmake
```

`openssl-probe 0.2.1` 不是 OpenSSL，也不链接 libssl：它是 `rustls-native-certs` 用来探测系统证书路径的纯 Rust 小 crate；工作区基线本来就有它。二进制 `ldd` 检查：

```text
$ ldd /root/.cache/rb-pg-spike-target/release/rb-pg-spike | grep -Ei 'ssl|crypto|cmake'
no libssl/libcrypto linkage
```

MSRV 验证：

```text
$ rustup run 1.89.0 cargo build --release --locked
Finished `release` profile [optimized + debuginfo] target(s) in 25.25s

$ rustup run 1.89.0 rustc --version
rustc 1.89.0 (29483883e 2025-08-04)

$ RB_PG_DSN=... ./rb-pg-spike probe-tls file:/tmp/rb-pg-spike/tls/ca.crt
{"flavor":"sync-postgres+tokio-postgres-rustls", ..., "ssl":true,
 "tls_version":"TLSv1.3","cipher":"TLS_AES_256_GCM_SHA384"}
```

### 2.1 不要引入 `rustls-pemfile`

第一版原型用 `rustls-pemfile = "=2.2.0"` 解析 `sslrootcert`。`cargo audit` 报：

```text
Crate:     rustls-pemfile
Version:   2.2.0
Warning:   unmaintained
Title:     rustls-pemfile is unmaintained
ID:        RUSTSEC-2025-0134
```

已改为 `rustls::pki_types::pem::PemObject` + `CertificateDer::pem_file_iter`（`rustls-pki-types` 已由 rustls 传递引入，不需要新增直接依赖）：

```rust
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;

let iter = CertificateDer::pem_file_iter(path)
    .map_err(|e| format!("open {}: {e}", path.display()))?;
for cert in iter {
    roots.add(cert.map_err(|e| format!("parse: {e}"))?)?;
}
```

改完后 `cargo audit` 扫描 129 个包无输出（无漏洞/无 unmaintained 警告）。**D1 不要添加 `rustls-pemfile`。**

## 3. 实验一：同步驱动 + rustls TLS

### 3.1 判定标准

1. 能用 `postgres::Client` 的同步 API 连接启用 TLS 的 PG；
2. 必须同时校验证书链和主机名（等价 libpq `sslmode=verify-full`）；
3. 空根证书、错误主机名必须失败；
4. 系统根与私有 CA 文件两种根来源都要可用；
5. 不引入 openssl/aws-lc/cmake，MSRV 1.89 可编译运行。

### 3.2 方案 A：自定义 `MakeTlsConnect` 包装 `StreamOwned`（失败）

最初的最小原型是：

```rust
use postgres::tls::{MakeTlsConnect, TlsConnect, TlsStream};
use postgres::Socket;
use rustls::{ClientConnection, StreamOwned};
use std::net::TcpStream;

struct SyncConnector { config: Arc<rustls::ClientConfig> }

impl MakeTlsConnect<Socket> for SyncConnector {
    type Stream = BlockingTlsStream;
    type TlsConnect = SyncConnect;
    type Error = std::io::Error;

    fn make_tls_connect(&mut self, domain: &str) -> Result<Self::TlsConnect, Self::Error> {
        let server_name = rustls::pki_types::ServerName::try_from(domain.to_owned())?;
        Ok(SyncConnect { config: self.config.clone(), server_name })
    }
}

impl TlsConnect<Socket> for SyncConnect {
    type Stream = BlockingTlsStream;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<Self::Stream, Self::Error>>;

    fn connect(self, socket: Socket) -> Self::Future {
        std::future::ready((|| {
            // 关键：postgres::Socket 没有 into_std()
            let tcp: TcpStream = socket.into_std()?;
            tcp.set_nonblocking(false)?;
            let conn = ClientConnection::new(self.config, self.server_name)?;
            Ok(BlockingTlsStream { inner: StreamOwned::new(conn, tcp) })
        })())
    }
}
```

实际编译错误（最小复现 crate `/tmp/rb-pg-spike/attempt-sync-adapter`）：

```text
error[E0599]: no method named `into_std` found for struct `Socket` in the current scope
  --> src/lib.rs:12:22
   |
12 |     let tcp = socket.into_std()?;
   |                      ^^^^^^^^

error[E0277]: the trait bound `StreamOwned<rustls::ClientConnection, std::net::TcpStream>: AsyncRead` is not satisfied
error[E0277]: the trait bound `StreamOwned<rustls::ClientConnection, std::net::TcpStream>: AsyncWrite` is not satisfied
```

原因有三层：

1. `postgres::Socket` 是 `tokio_postgres::socket::Socket`，内部是 `enum { Tcp(TcpStream), Unix(UnixStream) }`，字段私有，只实现 `AsyncRead`/`AsyncWrite`；**没有公开的 `into_std()` 或 `AsRawFd`**。因此拿不到 `std::net::TcpStream`，无法构造 `StreamOwned<ClientConnection, TcpStream>`。
2. 即便拿到，`rustls::StreamOwned` 只实现 `std::io::Read`/`Write`，而 `tokio_postgres::tls::TlsStream` 要求 `AsyncRead + AsyncWrite`。同步流必须再加一层 adapter。
3. 若把该 adapter 写成“在 `poll_read` 里阻塞读 `std::net::TcpStream`”，由于 `postgres` 每个连接使用自己的 **current-thread** runtime，并且连接 future 就在该 runtime 上被 `block_on`，阻塞 adapter 会卡住这个 runtime 的 I/O driver；即使不 panic，也无法在等待数据时驱动 socket。要正确实现，只能基于 rustls 的 `ClientConnection` + 原始 `Socket` 手写 async 状态机，这实质上就是重写 `tokio-postgres-rustls`。

**结论：该路线不可行，不进入生产。** 不是“缺少一个 feature”，而是 `postgres` 的公开 API 没有暴露原始 socket；不要为它做 fork/private API。

### 3.3 方案 B：`postgres` 同步 API + `tokio-postgres-rustls`（采用）

`postgres::Config::connect` 接受任意 `MakeTlsConnect<Socket>`；`tokio-postgres-rustls::MakeRustlsConnect` 的 stream 是 async 的 `tokio_rustls::client::TlsStream<Socket>`，正好满足 trait。`postgres::Config::connect` 内部已经为每个连接建了一个专用 current-thread runtime，因此**不需要再起外部 runtime/线程**：

```rust
use postgres::config::SslMode;
use rustls::{ClientConfig, RootCertStore};
use tokio_postgres_rustls::MakeRustlsConnect;

fn build_tls_config(roots: RootCertStore) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth()
}

fn connect(dsn_without_sslmode: &str, roots: RootCertStore) -> Result<postgres::Client, String> {
    let mut config: postgres::Config = dsn_without_sslmode.parse().map_err(|e| e.to_string())?;
    config.ssl_mode(SslMode::Require); // 只表示“必须 TLS”；校验由 rustls 完成
    let connector = MakeRustlsConnect::new(build_tls_config(roots)?);
    config.connect(connector).map_err(|e| format!("{e}"))
}
```

关键点：

- `sslmode=verify-full` 不能直接传给 `postgres`/`tokio-postgres`。驱动只接受 `disable`/`prefer`/`require`，`verify-full` 会报 `InvalidValue("sslmode")`。
- 应用配置层先识别 `verify-full`，把该参数从 DSN 去掉，再设置 `SslMode::Require`；证书链和主机名校验由 rustls 的 `ClientConfig` 完成。这样 `Require` 不再等于“只加密”，而是真正的 verify-full。
- `ClientConfig` 显式使用 `rustls::crypto::ring::default_provider()`，不依赖进程全局 provider，避免被 aws-lc feature 意外接管。

验证命令（密码只经环境变量，不进入 argv/文档）：

```bash
export RB_PG_DSN='postgres://rustboard:<TEST_PASSWORD>@localhost:55432/rustboard?sslmode=verify-full'
./rb-pg-spike probe-tls file:/tmp/rb-pg-spike/tls/ca.crt
./rb-pg-spike expect-fail file:/tmp/rb-pg-spike/tls/ca.crt wrong-hostname
./rb-pg-spike expect-fail empty empty-roots
./rb-pg-spike probe-tls system          # 先 unset SSL_CERT_FILE
SSL_CERT_FILE=/tmp/rb-pg-spike/tls/ca.crt ./rb-pg-spike probe-tls system
```

实测原始输出（最终代码）：

```json
{"flavor":"sync-postgres+tokio-postgres-rustls","roots":"File(\"/tmp/rb-pg-spike/tls/ca.crt\")",
 "connect_ms":17.64,"query_ms":3.91,"one":1,"sum":5,"user":"rustboard","db":"rustboard",
 "server_addr":"172.17.0.2/32","server_port":5432,"ssl":true,
 "tls_version":"TLSv1.3","cipher":"TLS_AES_256_GCM_SHA384"}

{"case":"empty-roots","failed_as_expected":true,
 "error":"error performing TLS handshake <- invalid peer certificate: UnknownIssuer"}

{"case":"wrong-hostname","failed_as_expected":true,
 "error":"error performing TLS handshake <- invalid peer certificate: certificate not valid for name \"127.0.0.1\"; certificate is only valid for DnsName(\"localhost\")"}

{"case":"system-default","failed_as_expected":true,
 "error":"error performing TLS handshake <- invalid peer certificate: UnknownIssuer"}
```

系统根行为：

- 不设置 `SSL_CERT_FILE`：`system roots: loaded=148 added=148 ignored=0 errors=0`；私有测试 CA 不在系统根，连接按预期失败 `UnknownIssuer`；
- 设置 `SSL_CERT_FILE` 指向测试 CA：`system roots: loaded=1 added=1`，`verify-full` 成功；
- 文件根（未来 `sslrootcert`）：`file roots: ... added=1`，成功。

TLS 汇总：

| 用例 | 结果 | 说明 |
|---|---|---|
| 文件根 + `host=localhost`，证书 `SAN=DNS:localhost` | 成功，TLS 1.3 | 证书链 + 主机名都验证 |
| 系统根（未注入私有 CA） | 失败 `UnknownIssuer` | 默认系统根确实生效 |
| 系统根 + `SSL_CERT_FILE=test-ca` | 成功 | 模拟私有 CA 加入信任库 |
| 空根 | 失败 `UnknownIssuer` | 证明不是“只加密不验证” |
| `host=127.0.0.1`，证书只有 DNS SAN | 失败 `certificate not valid for name "127.0.0.1"` | 主机名校验生效；生产按 IP 连接时证书必须有 IP SAN |
| `sslmode=disable` | 成功，`ssl=false` | 显式关闭 TLS 的路径可用 |
| `sslmode=verify-full` 原样交给驱动 | 驱动 `ConfigParse` 拒绝 | 必须由配置层剥离/映射 |

连接耗时（本机回环，含 TCP + TLS 握手）：13.3–17.6 ms；4 条查询（含 `pg_stat_ssl`）合计 2.8–4.6 ms。同步 API 的 TLS 开销主要在建连，不在单条查询。

### 3.4 方案 C：纯 async `tokio-postgres` + 专用 runtime/线程（fallback，未采用）

为了满足“若方案 A 不可行，验证替代方案并量化代价”，另做了一个最小 fallback：一个专用 OS 线程持有 current-thread runtime 和一条 `tokio-postgres` 连接，同步调用方通过 `std::sync::mpsc` 发请求、阻塞等回复。

```rust
// 线程内：
let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
let (client, connection) = rt.block_on(async {
    let mut cfg: tokio_postgres::Config = dsn.parse()?;
    cfg.ssl_mode(SslMode::Require);
    cfg.connect(connector).await
})?;
rt.spawn(connection);
// 同步侧：
tx.send(Job::QueryOne { sql, reply })?;
reply.recv_timeout(Duration::from_secs(10))?
```

1000 次串行 `SELECT 1` 对比（同一台机器、同一 PG）：

| 路径 | p50 | p95 | 连接耗时 |
|---|---:|---:|---:|
| async 专用线程 + channel | 495.0 / 581.5 / 610.4 µs | 632.5 / 791.6 / 922.8 µs | 15.6–19.3 ms |
| 同步 `postgres`（无 channel） | 418.3 / 466.5 / 617.0 µs | 631.2 / 729.2 / 862.5 µs | 14.0–17.6 ms |

三组数据（单位 µs，三个 run）显示：channel + 专用线程的额外延迟在本机回环上约 **0–100 µs/次**，相对 0.4–0.6 ms 的查询 RTT 很小；代价主要是**多一组线程、多一层请求协议、生命周期/错误传播更复杂**。

**结论**：既然方案 B 已经能保持同步 API，且不需要外部 runtime，就不采用方案 C。只有 D3 发现 sync 客户端的生命周期/panic 边界无法安全收敛时，才回退到“专用 runtime/线程 + channel”方案；其延迟代价已量化，可接受。

## 4. 实验二：tokio runtime 内的 panic 边界（关键发现）

这一节比性能数字更重要：同步 `postgres` 不是“可以但会阻塞”，而是**在 tokio runtime 上下文内根本不能调用**。

### 4.1 在 tokio 任务内 connect

```rust
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(2).enable_all().build()?;
rt.block_on(async {
    let _client = postgres::Client::connect(&dsn, connector)?; // 同步调用
});
```

实际结果：进程 exit 101，panic：

```text
thread 'main' panicked at .../postgres-0.19.14/src/config.rs:465:44:
Cannot start a runtime from within a runtime. This happens because a function (like
`block_on`) attempted to block the current thread while the thread is being used to
drive asynchronous tasks.
```

原因：`postgres::Config::connect` 内部创建 current-thread runtime 并立即 `block_on`。tokio 禁止在已进入的 runtime 上下文中再次 `block_on`，所以这不是“占用 worker 很久”，而是直接失败。

### 4.2 在 tokio 任务内丢连接池

```rust
let pool = r2d2_pool(...); // 在 runtime 外创建
rt.block_on(async move { drop(pool); });
```

实际结果：exit 101，panic：

```text
thread 'main' panicked at .../postgres-0.19.14/src/connection.rs:66:22:
Cannot start a runtime from within a runtime. ...
```

`r2d2::Pool` 最后一个引用被 drop 时会 drop 其中的 `postgres::Client`，而 `Client::Drop` 调 `close_inner()` → 内部 runtime `block_on`，同样触发嵌套 runtime panic。

### 4.3 什么可以、什么不可以

| 操作 | 在 tokio worker/async 任务内 | 在 `spawn_blocking` 或普通线程内 |
|---|---|---|
| `postgres::Client::connect` | **panic** | 可以 |
| `client.query_*` / `execute` | **panic**（同一 `block_on` 路径） | 可以 |
| 把 `PooledConnection` 还给仍存活的池并 drop guard | 可以（只是把连接放回池，不 drop `Client`） | 可以 |
| 直接 drop 一个 `postgres::Client` | **panic** | 可以 |
| drop 池的最后一个引用 | **panic** | 可以 |
| `spawn_blocking(move || drop(pool))` | 可以（在 blocking 线程上） | 可以 |

实测：在 async 任务里 `drop(pooled_conn)` 是安全的（连接回到池）；`drop(pool)` 或 `drop(Client)` 才 panic。`spawn_blocking(move || drop(pool))` 成功：

```text
dropping the r2d2 pool inside spawn_blocking...
OK: pool dropped on a blocking thread
```

### 4.4 对生产的硬约束

1. **所有** `postgres::Client` 的 connect、query、execute、transaction、drop 都必须在 `spawn_blocking`（或普通 OS 线程）上执行，绝不能在 tokio worker 上直接调用。
2. 连接池应在 `runtime.block_on` **之前**创建；不要在 async 初始化块里 `open_storage` 时创建 PG 池。
3. 池的最后引用必须在 runtime 外释放，或通过 `spawn_blocking` 释放；不能在 async 任务 drop 池。
4. `Storage` 方法是同步签名，D3 的 call site 必须逐个包 `spawn_blocking`；不能指望“查询很快所以直接调”。

> 这也解释了为什么“直接阻塞 vs spawn_blocking”的真实 PG 版本无法测完成时间：直接版本在第一个连接就 panic。第 5 节用相同 20–100 ms 的阻塞 sleep 模拟“直接阻塞”的 worker 行为，用真实 PG 测 `spawn_blocking` 版本；两者对 reactor 的影响可直接对比。

## 5. 实验三：200 agent / 8 worker 阻塞基准

### 5.1 负载

- tokio multi-thread runtime：固定 **8 worker**；
- 200 个并发任务，每个任务 20–100 ms（确定性 `20 + (i*37)%81` ms）；
- 连接池大小 8；
- 三个模式：
  - `direct`：在 async 任务里直接 `std::thread::sleep(work_ms)`，模拟“同步 DB 调用直接占用 worker”（真实 PG 会 panic，见 §4，所以不能直接用 PG 测）；
  - `spawn`：`tokio::task::spawn_blocking` 内取连接、真实写 3 行 + 查询 `count(*)` + `pg_sleep` 补足 20–100 ms；
  - `async`：`tokio::time::sleep(work_ms)`，作为 reactor 理想响应参照。
- 同时运行：
  - 10 ms ticker，记录实际间隔减 10 ms 的偏差（p50/p95/max）；
  - 20 个轻量 async 请求，在 DB 负载开始后 20–30 ms 到达，每个做 5 ms async 工作，记录从负载开始到完成的延迟。
- `spawn` 模式用真实 PG 写入/查询；`direct` 只是阻塞等价物，不产生 PG 流量。

核心代码（`spawn` 分支）：

```rust
let pool = pool.clone();
let agent = format!("agent-{i:03}");
tokio::task::spawn_blocking(move || {
    let mut client = pool.get_timeout(Duration::from_secs(5))?;
    let mut tx = client.transaction()?;
    for j in 0..3 {
        tx.execute(
            "INSERT INTO spike_samples (agent_id, ts, value) VALUES ($1, $2, $3)",
            &[&agent, &(i as i64 + j), &(j as f64)],
        )?;
    }
    tx.commit()?;
    let _: i64 = client.query_one(
        "SELECT count(*) FROM spike_samples WHERE agent_id = $1", &[&agent],
    )?.get(0);
    let target = Duration::from_millis(work_ms);
    let elapsed = started.elapsed();
    if elapsed < target {
        client.query_one("SELECT pg_sleep($1)", &[&(target - elapsed).as_secs_f64()])?;
    }
    Ok::<(), String>(())
}).await
```

### 5.2 结果（每模式 3 次，表中为 3 次的中位数；原始值见 §5.3）

| 模式 | 总完成时间 | 任务 p50 | 任务 p95 | ticker p95 | ticker max | 轻量请求 p50 | 轻量请求 p95 | 进程线程数 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `spawn`（默认 blocking 上限） | **1580 ms** | 801 ms | 1502 ms | **0.7 ms** | 15.7 ms | **32.5 ms** | 35.9 ms | 220 |
| `spawn`（`max_blocking_threads=32`） | 1591 ms | 799 ms | 1485 ms | **0.7 ms** | 1.0 ms | 34.6 ms | 37.4 ms | 52 |
| `spawn`（`max_blocking_threads=8`） | 1577 ms | 793 ms | 1498 ms | **0.7 ms** | 1.2 ms | 32.2 ms | 35.7 ms | 28 |
| `direct`（同步阻塞模型） | 1549 ms | 778 ms | 1451 ms | **1475.8 ms** | 1475.8 ms | **1480.7 ms** | 1480.7 ms | 20 |
| `async`（无 DB，理想参照） | **102 ms** | 62 ms | 98 ms | 0.6 ms | 0.6 ms | 31.7 ms | 36.2 ms | 20 |

真实写入/查询版（`spawn`，200 任务 × 3 行，3 次，全部 `errors=0`）：

| run | 总时间 | 任务 p50 | 任务 p95 | ticker p95 | ticker max | 轻量 p50 | 轻量 p95 | 线程数 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1574.2 ms | 799.9 ms | 1486.3 ms | 0.6 ms | 19.4 ms | 31.6 ms | 35.9 ms | 220 |
| 2 | 1592.9 ms | 816.2 ms | 1494.6 ms | 0.6 ms | 17.7 ms | 45.2 ms | 50.0 ms | 220 |
| 3 | 1608.2 ms | 797.3 ms | 1488.8 ms | 0.6 ms | 7.0 ms | 48.1 ms | 51.8 ms | 220 |

### 5.3 原始 JSONL（节选，保留每次 run）

```jsonl
{"mode":"spawn","workers":8,"tasks":200,"pool":8,"total_ms":1585.5,"task_p50_ms":814.0,"task_p95_ms":1501.8,"task_max_ms":1585.4,"ticker_p50_ms":0.1,"ticker_p95_ms":0.7,"ticker_max_ms":15.7,"probe_p50_ms":43.0,"probe_p95_ms":47.4,"threads":220,"errors":0}
{"mode":"spawn","workers":8,"tasks":200,"pool":8,"total_ms":1599.9,"task_p50_ms":799.4,"task_p95_ms":1492.9,"task_max_ms":1599.9,"ticker_p50_ms":0.1,"ticker_p95_ms":0.7,"ticker_max_ms":1.1,"probe_p50_ms":32.3,"probe_p95_ms":35.6,"threads":52,"errors":0}
{"mode":"spawn","workers":8,"tasks":200,"pool":8,"total_ms":1589.9,"task_p50_ms":813.9,"task_p95_ms":1498.4,"task_max_ms":1589.8,"ticker_p50_ms":0.1,"ticker_p95_ms":0.7,"ticker_max_ms":1.2,"probe_p50_ms":32.3,"probe_p95_ms":35.7,"threads":28,"errors":0}
{"mode":"direct","workers":8,"tasks":200,"pool":8,"total_ms":1548.7,"task_p50_ms":798.4,"task_p95_ms":1449.6,"task_max_ms":1548.6,"ticker_p50_ms":0.1,"ticker_p95_ms":1460.1,"ticker_max_ms":1460.1,"probe_p50_ms":1464.9,"probe_p95_ms":1464.9,"threads":20,"errors":0}
{"mode":"async","workers":8,"tasks":200,"pool":8,"total_ms":101.6,"task_p50_ms":61.9,"task_p95_ms":98.2,"task_max_ms":101.5,"ticker_p50_ms":0.0,"ticker_p95_ms":0.6,"ticker_max_ms":0.6,"probe_p50_ms":31.9,"probe_p95_ms":36.3,"threads":20,"errors":0}
```

```jsonl
{"mode":"spawn","workers":8,"tasks":200,"pool":8,"total_ms":1574.2,"task_p50_ms":799.9,"task_p95_ms":1486.3,"task_max_ms":1574.2,"ticker_p50_ms":0.1,"ticker_p95_ms":0.6,"ticker_max_ms":19.4,"probe_p50_ms":31.6,"probe_p95_ms":35.9,"threads":220,"errors":0}
{"mode":"spawn","workers":8,"tasks":200,"pool":8,"total_ms":1592.9,"task_p50_ms":816.2,"task_p95_ms":1494.6,"task_max_ms":1592.8,"ticker_p50_ms":0.1,"ticker_p95_ms":0.6,"ticker_max_ms":17.7,"probe_p50_ms":45.2,"probe_p95_ms":50.0,"threads":220,"errors":0}
{"mode":"spawn","workers":8,"tasks":200,"pool":8,"total_ms":1608.2,"task_p50_ms":797.3,"task_p95_ms":1488.8,"task_max_ms":1608.1,"ticker_p50_ms":0.1,"ticker_p95_ms":0.6,"ticker_max_ms":7.0,"probe_p50_ms":48.1,"probe_p95_ms":51.8,"threads":220,"errors":0}
```

### 5.4 解读

1. **吞吐不由 worker 数决定，而由 DB 池决定**：`direct`、`spawn`、`max_blocking=8/32` 的总时间都在 1.55–1.61 s，符合 `200 × 平均 60 ms / 8 连接 ≈ 1.5 s`。`spawn_blocking` 不会提高 DB 吞吐。
2. **差别在 reactor 是否被饿死**：`direct` 的 ticker p95 = 1475.8 ms，轻量请求 p50 = 1480.7 ms；`spawn` 的 ticker p95 = 0.7 ms，轻量请求 p50 = 32.5 ms。生产里这意味着 WebSocket 心跳、ACK、面板请求、吊销 watcher 在 DB 繁忙时是否还能响应。
3. **真实 PG 的 `spawn` 版本**：3 次写入/查询全部 `errors=0`，总时间 1.57–1.61 s，与 sleep 模型一致；说明 `spawn_blocking` 路径不仅能跑，还能在 200 并发下稳定完成。
4. **线程数**：默认 blocking 池为 200 个任务创建了约 200 个线程（进程 220）；`max_blocking_threads=32` 时 52；`=8` 时 28。总时间没有恶化，说明该负载下应优先限制线程数，避免 1000 agent 时线程爆炸。
5. **`spawn_blocking` 自身开销**：空任务 2000 次，p50 17.9–23.4 µs，p95 30.2–35.8 µs（3 次）。相对 20–100 ms 的 DB 工作可忽略；相对 SQLite 级内存操作则不可忽略，所以该建议只针对 PG 网络调用。

### 5.5 生产应在哪些边界 `spawn_blocking`

以下边界全部走 `spawn_blocking`，不能只包“慢查询”：

| 边界 | 现有位置/说明 | 建议 |
|---|---|---|
| ingest 每批写入 | `main.rs:5242`、`:5718` 已经包了 SQLite；PG 必须继续包 | 连接获取、事务、commit 全在闭包内 |
| 面板/管理查询 | `main.rs:3631`、`:3666`、`:3713`、`:3765` 等已有 `spawn_blocking` | 保持；不要把 `PooledConnection` 返回到 async |
| 告警引擎 | `alerts_engine.rs:600` 每轮 `spawn_blocking` | 保持；单轮串行 |
| 维护/降采样/归档 | `main.rs:5755`、`archive` 相关 | 保持；注意 statement_timeout |
| token / API 鉴权 | `auth.rs:507` | 保持；PG 查询也要包 |
| 启动时 `reset_online_status` | `main.rs:1762`，目前直接在 async 初始化块调用 SQLite | PG 必须改到 runtime 外或 `spawn_blocking` |
| 启动时 `open_storage` | `main.rs:1758`，在 `runtime.block_on` 内 | PG 池必须在 runtime 外创建；见 §7 |
| 自监控/吊销 watcher | `spawn_self_monitor`、`spawn_revoke_watcher` | 所有 DB 调用包 blocking |

不要做的事：

- 不要在 `Storage` trait 方法内部偷偷 `block_on`/起 runtime；
- 不要把 `postgres::Client` 或 `PooledConnection` 作为 async future 的局部变量跨 `.await` 持有；
- 不要在 async 任务 drop 连接池（见 §4）；
- 不要让 `spawn_blocking` 队列无界增长：用信号量/`try_acquire` 做背压，超限返回 503/繁忙，而不是无限堆任务。

## 6. 实验四：连接池

### 6.1 候选

**A. r2d2 0.8.10 + 自定义 `ManageConnection`（推荐）**

```rust
#[derive(Clone)]
struct PgManager {
    config: postgres::Config,
    connector: MakeRustlsConnect,
}

impl ManageConnection for PgManager {
    type Connection = postgres::Client;
    type Error = postgres::Error;

    fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let mut client = self.config.connect(self.connector.clone())?;
        client.batch_execute(
            "SET statement_timeout = 30000; SET application_name = 'rustboard-hub'",
        )?;
        Ok(client)
    }

    fn is_valid(&self, client: &mut Self::Connection) -> Result<(), Self::Error> {
        client.simple_query("").map(|_| ()) // 与 r2d2_postgres 0.18 相同的空查询探活
    }

    fn has_broken(&self, client: &mut Self::Connection) -> bool {
        client.is_closed()
    }
}
```

**B. 自建有界池**：`Mutex<Vec<Client>>` + `Condvar` + `total/max`，checkout 时 `is_closed` + 空查询探活，超时返回。约 150 行；本次只作为对照，不进入生产。

### 6.2 实测

测试：8 线程 × 100 次 checkout，每次 checkout 后执行 `SELECT 1`；池 8/8 表示 8 连接无争用，池 4/8 表示 8 线程抢 4 连接。`validation_on/off` 是 500 次 checkout 的中位数。

| 池 | 配置 | checkout p50 | checkout p95 | checkout max | 探活 on/off |
|---|---|---:|---:|---:|---:|
| r2d2 | max 8 / 8 线程 | 288.9 µs | 507.4 µs | 1.95 ms | 160 µs / 0.19 µs |
| r2d2 | max 4 / 8 线程 | 250.1 µs | 3954.8 µs | 21.2 ms | 164 µs / 0.20 µs |
| 自建 | max 8 / 8 线程 | 252.6 µs | 387.0 µs | 57.7 ms | 每次 checkout 探活 |
| 自建 | max 4 / 8 线程 | 223.9 µs | 337.0 µs | 83.5 ms | 每次 checkout 探活 |

行为：

| 场景 | r2d2 | 自建池 |
|---|---|---|
| 连接被服务端 `pg_terminate_backend` 杀掉后 checkout | 通过 `is_valid` 发现并重建；13–19 ms | 通过 `simple_query("")` 发现并重建；13–18 ms |
| 整个容器重启（TCP 全断） | 第 1 次尝试恢复，519.7 ms | 未单独测；同机制 |
| 池耗尽（max=2 持有 2 条） | `get_timeout(300ms)` → `timed out waiting for connection`，300.1 ms | `checkout timeout`，300.1 ms |
| `test_on_check_out=false` + 杀连接 | 前 2 次 checkout 返回死连接，第 3 次才恢复（max=2，2 条死连接各失败一次） | 未测 |
| 空闲连接回收/最小空闲 | 内建 reaper、`min_idle`、`max_lifetime`、`idle_timeout` | 需自己实现 |
| 公平性/尾延迟 | p95 稳定在 0.4–4.4 ms，max 1.3–29 ms | p95 更好但 max 43–105 ms（condvar 唤醒竞争导致个别线程饥饿） |
| 代码量/维护 | ~40 行 Manager | ~150 行 + 自己处理超时/公平性/回收 |

原始 JSONL（6 条，含两个配置的三次 run）：

```jsonl
{"pool":"r2d2","max":4,"threads":8,"checkout_p50_us":250.1,"checkout_p95_us":3921.9,"checkout_max_us":16453.5,"validation_on_ns":162045,"validation_off_ns":207,"reconnect_ms":16.9,"old_pids":4,"new_pids":1,"reconnected":true,"exhaustion_ms":300.1,"exhaustion_error":"timed out waiting for connection","nocheck_query_ok":true,"nocheck_attempt":3,"nocheck_error":""}
{"pool":"custom","max":4,"threads":8,"checkout_p50_us":217.2,"checkout_p95_us":308.2,"checkout_max_us":83527.2,"reconnect_ms":13.7,"old_pids":4,"new_pids":1,"reconnected":true,"exhaustion_ms":300.1,"exhaustion_error":"checkout timeout"}
{"pool":"r2d2","max":8,"threads":8,"checkout_p50_us":277.6,"checkout_p95_us":507.4,"checkout_max_us":1949.2,"validation_on_ns":136629,"validation_off_ns":194,"reconnect_ms":15.6,"old_pids":4,"new_pids":1,"reconnected":true,"exhaustion_ms":300.1,"exhaustion_error":"timed out waiting for connection","nocheck_query_ok":true,"nocheck_attempt":3,"nocheck_error":""}
{"pool":"custom","max":8,"threads":8,"checkout_p50_us":227.5,"checkout_p95_us":326.0,"checkout_max_us":65443.2,"reconnect_ms":14.7,"old_pids":4,"new_pids":1,"reconnected":true,"exhaustion_ms":300.1,"exhaustion_error":"checkout timeout"}
{"pool":"r2d2","max":4,"threads":8,"checkout_p50_us":242.1,"checkout_p95_us":3954.8,"checkout_max_us":28860.3,"validation_on_ns":166659,"validation_off_ns":198,"reconnect_ms":18.7,"old_pids":4,"new_pids":1,"reconnected":true,"exhaustion_ms":300.1,"exhaustion_error":"timed out waiting for connection","nocheck_query_ok":true,"nocheck_attempt":3,"nocheck_error":""}
{"pool":"custom","max":4,"threads":8,"checkout_p50_us":258.5,"checkout_p95_us":377.0,"checkout_max_us":92966.0,"reconnect_ms":17.6,"old_pids":4,"new_pids":1,"reconnected":true,"exhaustion_ms":300.1,"exhaustion_error":"checkout timeout"}
```

容器重启恢复的原始输出：

```json
{"pool":"r2d2","outage_recovered":true,"attempt":1,"recovery_ms":519.7}
```

### 6.3 选择与理由

**选 r2d2 + 自定义 Manager**，理由：

1. 成熟的有界池：`max_size`、`min_idle`、`connection_timeout`、`get_timeout`、`max_lifetime`、`idle_timeout`、后台 reaper 都是现成的；自建池要自己补齐这些，且本次测得尾延迟更差。
2. `ManageConnection` 可精确控制新连接初始化（`SET statement_timeout`、`application_name`、未来可加 `SET idle_in_transaction_session_timeout`），也可以把 TLS connector 封装在 Manager 内。
3. `is_valid` 每次 checkout 做一次空查询，实测约 **160 µs**；200 agent 每 5 s 一批约 40 批/s，成本约 6 ms/s（0.6%），可接受；换来“断线后自动替换、不让用户请求第一次撞死连接”。
4. 需要更激进性能时可把 `test_on_check_out=false`，但必须配合连接错误分类 + 幂等重试；本次实测关闭后 max=2 时有 2 次请求拿到死连接，说明不能只关探活不做重试。

建议初始参数：

```text
max_size = db_pool_size (默认 8，上限 64)
min_idle = 1..=pool_size（启动时至少预热 1 条；D3 可在启动阶段预热）
connection_timeout = db_connect_timeout_ms (默认 5000)
get_timeout = 5000 ms（或 db_connect_timeout_ms，另加等待余量）
test_on_check_out = true
max_lifetime = 30 min（防止长期连接积累服务端状态）
idle_timeout = 10 min
statement_timeout = db_statement_timeout_ms (默认 30000，每条新连接 SET)
```

`statement_timeout` 实测：`SET statement_timeout=150` 后 `SELECT pg_sleep(1)` 在 150.9 ms 返回：

```text
db error [SQLSTATE 57014: canceling statement due to statement timeout]
<- ERROR: canceling statement due to statement timeout
```

`connect_timeout=1` 连不可达地址实测 1005 ms 返回 `connection timed out`，配置生效。

## 7. 实验五：`sslmode` 语义与根证书

### 7.1 驱动实际接受的值

`tokio-postgres 0.7.18` 的 `SslMode` 只有 `Disable`/`Prefer`/`Require`。实测：

| 输入 | 驱动解析 | 说明 |
|---|---|---|
| `sslmode=verify-full` | **拒绝** `ConfigParse / InvalidValue("sslmode")` | 必须由应用层映射 |
| `sslmode=verify-ca` | **拒绝** | 驱动没有 verify-ca |
| `sslmode=allow` | **拒绝** | 驱动没有 allow |
| `sslmode=require` | 接受 | 只表示必须 TLS；校验取决于传入的 `MakeTlsConnect` |
| `sslmode=prefer` | 接受 | 服务端不支持 TLS 时静默回落明文（见下） |
| `sslmode=disable` | 接受 | 明文 |

### 7.2 实测行为

同一套代码（传入校验型 rustls connector）分别在 TLS 库和明文库上测试：

| 场景 | `disable` | `prefer`（rustls connector） | `prefer-nolts`（NoTls） | `require`（rustls connector） | `verify-full`（我们的配置层） |
|---|---|---|---|---|---|
| TLS 库 :55432 | 成功，`ssl=false` | 成功，`ssl=true` | 成功，`ssl=false`（**降级**） | 成功，`ssl=true` | 成功，TLS 1.3 |
| 明文库 :55433 | 成功，`ssl=false` | 成功，`ssl=false`（**静默降级**） | 成功，`ssl=false` | **失败** `server does not support TLS` | **失败** `server does not support TLS` |

关键原始输出：

```json
{"flavor":"policy-prefer","roots":"File(\"test-ca.crt\")", ... "ssl":false, "tls_version":""}
{"flavor":"policy-prefer-nolts","roots":"File(\"test-ca.crt\")", ... "ssl":false, "tls_version":""}
{"flavor":"policy-require","connect_ok":false,
 "error":"error performing TLS handshake <- server does not support TLS"}
```

结论：

- `prefer` 在明文库上会**成功且无警告**地降级为明文；即使传了校验型 connector，服务端回 `N` 时驱动也回落。**生产拒绝 `prefer`。**
- `require` 只保证加密；它不承诺主机名校验。我们的 connector 虽然会校验，但语义与 libpq 的 `require` 不一致（libpq 用户会以为“不校验证书也行”），容易造成误配。**生产拒绝 `require`，要求显式 `verify-full`。**
- `verify-ca` 只校验证书链不校验主机名；Plan 没有需求，且驱动不支持。**拒绝**，不做半吊子实现。
- 只支持两种显式模式，默认 `verify-full`；`disable` 必须显式写出，并在启动时打一次 WARN（不含密码/完整 DSN）。

### 7.3 映射与启动拒绝策略

| 配置值 | 行为 |
|---|---|
| `verify-full` | 从 DSN 剥离 `sslmode`；解析 DSN；`config.ssl_mode(SslMode::Require)`；用系统根/`sslrootcert` 构建校验型 `ClientConfig`；连接 |
| `disable` | 从 DSN 剥离 `sslmode`；`config.ssl_mode(SslMode::Disable)`；`NoTls`；启动 WARN |
| 缺省 | **默认 `verify-full`**（fail-closed）；不静默走 `prefer` |
| `require` / `prefer` / `verify-ca` / `allow` / 其他 | **启动失败**，错误信息只列允许值，不回显 DSN userinfo；发生在写配置/启动监听之前 |

建议错误文案（不含密码）：

```text
database 的 sslmode 只支持 "verify-full" 或 "disable"；
"require"/"prefer" 无法保证主机名校验或会静默降级，已拒绝。
请改成 sslmode=verify-full（推荐）或显式 sslmode=disable。
```

### 7.4 根证书来源

- **默认**：`rustls-native-certs 0.8.3` 加载系统根；Linux 下尊重 `SSL_CERT_FILE`/`SSL_CERT_DIR`。实测未注入私有 CA 时 `loaded=148`，连接私有 CA 库得到 `UnknownIssuer`。
- **私有 CA / 自签**：增加可选 `db_sslrootcert = "/path/ca.pem"`（或等价环境变量），用 `CertificateDer::pem_file_iter` 读取；**设置后替换系统根**（与 libpq 的 `sslrootcert` 语义一致），而不是悄悄追加。若同时需要公共 CA 与私有 CA，让运维把两张 CA 合并在同一个 PEM 文件。
- `sslrootcert` **不能**直接放进 DSN 交给驱动：`tokio-postgres` 会报 `UnknownOption("sslrootcert")`。D1 的 DSN 解析层必须识别并剥离，或者直接拒绝并指向配置字段。
- 主机名验证使用 DSN 的 `host`（不是 `hostaddr`）；按 IP 连接时证书必须有对应 IP SAN。实测 `host=127.0.0.1` + 仅 `DNS:localhost` 证书失败，错误明确给出 `certificate not valid for name "127.0.0.1"`。
- 公共 CA 场景不需要 `sslrootcert`；系统根即可。私有 CA/自签场景需要。

### 7.5 安全注意

- `tokio-postgres-rustls` 0.14 通过 x509-cert 计算 `tls-server-end-point` channel binding；这是比“自定义 adapter 返回 `ChannelBinding::none`”更强的一点。D3 不需要自己实现 SCRAM channel binding。
- 任何错误/日志都不能打印带 userinfo 的 DSN；`postgres::Error` 的 `Display` 有时只有 `db error`，D1 的 redact 层要先于日志格式化。
- `disable` 只应允许回环/受信内网并显式配置；启动 WARN 必须包含“流量为明文”但不得包含密码。

## 8. 结论表

| 决策 | 选择 | 依据 |
|---|---|---|
| 驱动 | `postgres 0.19.14`（同步 API） | 保持现有 `Storage` 同步 trait；MSRV 1.85<1.89 |
| TLS | `tokio-postgres-rustls 0.14.0` + rustls 0.23 ring | 自定义 `StreamOwned` 不可行；该组合实测 verify-full 成功 |
| TLS 模式 | 只支持 `disable` / `verify-full`，默认 verify-full | 驱动只接受 disable/prefer/require；prefer 实测可静默降级；require 语义不校验主机名 |
| 根证书 | 默认系统根；私有 CA 用 `db_sslrootcert` 文件替换 | 系统根 148 张时私有 CA 仍 UnknownIssuer；文件根成功 |
| 连接池 | `r2d2 0.8.10` + 自定义 `ManageConnection` | 有界/探活/超时/重连成熟；自建池尾延迟更差、代码更多 |
| 探活 | `test_on_check_out = true`，空查询 | 160 µs/次；可接受；关闭后需重试逻辑 |
| 超时 | connect 5 s、checkout 5 s、statement 30 s | 实测 connect_timeout=1 s 生效；statement_timeout=150 ms 生效；池耗尽 300 ms 超时 |
| 阻塞边界 | **所有 PG 调用 `spawn_blocking`** | 直接调用 panic；200 任务实测 spawn 保持 ticker p95 0.7 ms |
| blocking 线程 | 限制 `max_blocking_threads`（建议 32 对 pool 8），外加信号量背压 | 默认 512 时 200 任务创建 220 线程；32 时 52 线程，总时间不变 |
| PG 池生命周期 | 在 runtime 外创建；在 runtime 外或 `spawn_blocking` 内 drop | drop 池/Client 在 runtime 内 panic；blocking drop 实测 OK |
| MSRV | 1.89 | `cargo +1.89.0 build --release` + 实际查询通过 |
| 依赖红线 | 无 openssl/aws-lc/native-tls/cmake | `cargo tree -i` 全部 absent；`ldd` 无 libssl/libcrypto |
| PEM 解析 | 用 rustls-pki-types，不用 rustls-pemfile | rustls-pemfile 2.2.0 已 unmaintained（RUSTSEC-2025-0134） |

## 9. 风险与缓解

| 风险 | 级别 | 缓解 |
|---|---|---|
| 在 tokio worker 直接调用同步 PG，启动/查询 panic | 高 | D1/D3 强制所有调用走 `spawn_blocking`；加编译期/测试约束；启动路径单独审计 |
| PG 池在 async 上下文 drop 导致 shutdown panic | 高 | 池在 runtime 外构造并持有外部 Arc；shutdown 用 `spawn_blocking(move || drop(pool))`；增加启动-停止集成测试 |
| 200/1000 agent 下 blocking 线程膨胀 | 高 | `max_blocking_threads ≈ 2×pool`（8 连接建议 32）；`Semaphore` 限制 in-flight DB 请求；超限快速失败/503 |
| `spawn_blocking` 队列无界增长 | 中 | 信号量/`try_acquire` 背压；监控队列与等待时间；statement_timeout 30 s 兜底 |
| 长查询/锁等待占满池 | 中 | `statement_timeout`、`get_timeout`、池指标；慢查询日志；D6 故障注入 |
| `sslmode=prefer` 被误用为默认 | 高 | 启动拒绝 prefer/require/verify-ca/allow；默认 verify-full；文档明确 |
| 私有 CA 未配 `sslrootcert` | 中 | 启动时 TLS 握手失败即拒绝；错误提示“系统根不包含该 CA，请设置 db_sslrootcert”；文档给 openssl 校验命令 |
| 证书只有 DNS SAN，生产按 IP 连 | 中 | 启动连接失败；文档要求按实际连接 host 配置 IP SAN；错误信息不泄露证书细节 |
| `sslrootcert` 文件路径/符号链接/权限 | 中 | 只读打开；D1 校验文件存在、常规文件、权限 0644/0600；不接受 `..` 逃逸；错误脱敏 |
| 连接池探活 160 µs 拖慢高频小查询 | 低 | 200 agent 成本约 0.6%；如 profiling 证明有影响，改 `test_on_check_out=false` + 连接错误重试 |
| 自建池尾延迟/公平性差 | 中 | 不采用；如未来必须自建，需要 FIFO waiter/ticket，并重跑本基准 |
| `rustls-pemfile` unmaintained | 中 | 不引入；用 rustls-pki-types；`cargo audit` 门禁 |
| 本 spike 只测回环，未测真实网络 RTT/丢包/长稳 | 中 | D6/Phase E 用真实网络与 100/500/1000 agent；本结论不替代 24h 压测 |
| 直接 PG 无法测“阻塞完成时间” | 低 | 用等价 sleep 测 reactor 饥饿，用真实 PG 测 spawn 路径；两者都记录，不混淆 |

## 10. 对 D1 的具体建议

1. **配置模型**
   - `HubConfig` 增加 `db_pool_size`、`db_connect_timeout_ms`、`db_statement_timeout_ms`、`db_sslrootcert: Option<PathBuf>`；
   - `database` 解析为 `SqlitePath`/`PostgresDsn`；PG DSN 先做 `PgSettings` 解析（host/port/user/db/sslmode/sslrootcert/密码来源），再生成“驱动可接受”的干净 DSN；
   - `sslmode` 只允许 `disable`/`verify-full`，缺省 `verify-full`；非法值在写盘/监听前失败；
   - 密码优先 `RUSTBOARD_DATABASE_PASSWORD`，其次 URL；任何日志/错误/`--dry-run` 统一 `redact_dsn`，单测覆盖。
2. **池生命周期**
   - `open_pg_pool` 放在 `run()` 的 `runtime.block_on` 之前（或在 `spawn_blocking` 内构造后马上移出 runtime）；
   - `PostgresStorage` 持有 `Pool`；`StorageHandle` 只做静态 enum 转发；
   - 增加显式 `shutdown()`：停止接受/等待任务退出 → `spawn_blocking(move || drop(storage))`；
   - 不要在 `runtime.block_on` 的 async 块里创建或 drop 池。
3. **接入点审计**
   - 当前 `main.rs:1758` 在 async 块内 `open_storage`；`:1762` 直接 `reset_online_status`。PG 路径必须改。
   - `Arc<SqliteStorage>` 出现 261 处、`storage.` 调用约 325 处；`sqlite.rs` 约 72 个 `pub fn`（trait 29 个方法 + 大量 inherent 方法）。D1 拆 trait 时按实际调用点建清单，不能只覆盖 `Storage` trait 的 29 个。
   - 优先保证启动路径、ingest、面板查询、告警、维护、token 鉴权六类；其余按调用图补齐。
4. **测试**
   - 启动/停止 PG 后端 10 次，断言无 panic、无“Cannot start a runtime”；
   - async 任务中直接调用 PG 的负向测试（应 panic）仅作为回归护栏，不放进生产路径；
   - shutdown 测试覆盖“仍有 Arc 克隆”“池内空闲连接”“正在 checkout”的情况。

## 11. 对 D3 的具体建议

1. **统一 blocking helper**：

   ```rust
   async fn db_blocking<T, F>(f: F) -> Result<T>
   where
       T: Send + 'static,
       F: FnOnce() -> Result<T> + Send + 'static,
   {
       tokio::task::spawn_blocking(f)
           .await
           .context("DB blocking task join failed")?
   }
   ```

   闭包内完成“取连接 → 查询/事务 → drop guard”，不要把 `PooledConnection` 返回到 async 侧。
2. **背压**：`Semaphore` permits = `max_blocking_threads`（或 `pool_size * 2`）；`try_acquire` 失败返回 503/“busy”，不要无限 `spawn_blocking`。指标记录 `db_inflight`、`db_wait_ms`、`pool_checkout_timeout_total`。
3. **超时**：
   - 新连接 `SET statement_timeout = db_statement_timeout_ms`（默认 30 s）；
   - `get_timeout` 5 s；`connection_timeout` 5 s；
   - 考虑 `tcp_user_timeout`/keepalives；PG 侧 `idle_in_transaction_session_timeout` 由 D3 评估。
4. **重连/重试**：
   - 初始保持 `test_on_check_out=true`；若 profiling 决定关闭，必须对连接级错误（SQLSTATE `08xxx`、`57P01`，或 `is_closed`）做“丢弃 + 重连 + 幂等重试一次”；
   - ingest 的 `(agent_id, epoch, seq)` 幂等允许重试；只读查询可重试；非幂等写不要盲目重试，先回滚事务。
5. **错误脱敏**：`postgres::Error` 链里可能带 SQL、表名、DSN；统一 `log_safe_error`，密码/DSN 永不进日志；D3 的单测覆盖 `sslmode`/`sslrootcert` 解析错误。
6. **验收**：
   - 200 agent 真实 ingest（不是 pg_sleep）达到 Gate D3 指标；
   - 断连/容器重启后已提交数据不丢，失败请求可重试；
   - 200 并发下 ticker/心跳 p95 不劣化（参考本 spike 的 0.7 ms 量级）；
   - 所有 PG 调用点都有 `spawn_blocking` 审计记录。

## 12. 未完成/不在本 spike 范围

- 没有测 100/500/1000 agent、24h 长稳、真实网络 RTT、PG 主备切换；留给 D6/Phase E。
- 没有实现 PG schema、迁移、备份/恢复；D2/D5。
- 没有把依赖写进仓库 `Cargo.toml`/`Cargo.lock`；D1 才做，届时需重新跑 `cargo tree` 与 `cargo audit`。
- 没有验证 SCRAM channel binding 的运行时行为（只从 `tokio-postgres-rustls` 源码确认实现）；PG 默认 SCRAM-SHA-256 可用，verify-full 下不依赖 channel binding 防 MITM。
- 没有验证 `verify-ca`（不支持）或客户端证书（本 spike 只用密码认证）。

## 13. 复现命令（容器与临时目录已清理）

以下命令保留作复现记录；容器名/端口均独立，不碰已有 `rb-pebble`。密码用占位符。

```bash
# 1. 生成测试 CA + 服务端证书（仅本地）
mkdir -p /tmp/rb-pg-spike/tls
cd /tmp/rb-pg-spike/tls
openssl genrsa -out ca.key 2048
openssl req -x509 -new -key ca.key -sha256 -days 2 -out ca.crt \
  -subj "/CN=rb-pg-spike-test-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 2 -sha256 -extfile server.ext

# 2. TLS 库（独立名字/端口）
docker run -d --name rb-pg-spike \
  -e POSTGRES_USER=rustboard -e POSTGRES_PASSWORD='<TEST_PASSWORD>' \
  -e POSTGRES_DB=rustboard -p 127.0.0.1:55432:5432 \
  -v /tmp/rb-pg-spike/tls:/certs:ro postgres:16 \
  -c ssl=on -c ssl_cert_file=/certs/server.crt \
  -c ssl_key_file=/certs/server.key -c ssl_ca_file=/certs/ca.crt

# 3. 明文对照库（验证 prefer/require）
docker run -d --name rb-pg-spike-nossl \
  -e POSTGRES_USER=rustboard -e POSTGRES_PASSWORD='<TEST_PASSWORD>' \
  -e POSTGRES_DB=rustboard -p 127.0.0.1:55433:5432 postgres:16 -c ssl=off

# 4. 编译与运行
cd /tmp/rb-pg-spike
export CARGO_TARGET_DIR=/root/.cache/rb-pg-spike-target
cargo build --release
export RB_PG_DSN='postgres://rustboard:<TEST_PASSWORD>@localhost:55432/rustboard?sslmode=verify-full'
"$CARGO_TARGET_DIR/release/rb-pg-spike" probe-tls file:/tmp/rb-pg-spike/tls/ca.crt
"$CARGO_TARGET_DIR/release/rb-pg-spike" pool file:/tmp/rb-pg-spike/tls/ca.crt 8 8
"$CARGO_TARGET_DIR/release/rb-pg-spike" bench spawn file:/tmp/rb-pg-spike/tls/ca.crt 8 200 8 32

# 5. 清理
docker rm -f rb-pg-spike rb-pg-spike-nossl
rm -rf /tmp/rb-pg-spike
```

> 实际执行时 `/tmp` 空间紧张，构建产物放在 `/root/.cache/rb-pg-spike-target`，源码/证书/结果在 `/tmp/rb-pg-spike`；spike 结束后全部删除。本文不含测试密码、私钥或真实域名。

## 14. D0 Gate 判定

| Gate D0 项 | 结果 |
|---|---|
| PG 驱动有实测依据 | 通过：sync + tokio-postgres-rustls 实测 verify-full；自定义 `StreamOwned` 不可行有编译证据 |
| 连接池有实测依据 | 通过：r2d2 vs 自建，探活/超时/重连/耗尽/容器重启数据齐全 |
| 阻塞边界有实测依据 | 通过：8 worker + 200 任务 + 真实写/查；同时发现直接调用会 panic |
| `cargo tree` 无 openssl/aws-lc | 通过：`cargo tree -i` 全 absent，`ldd` 无 libssl/libcrypto |
| MSRV 1.89 | 通过：`cargo +1.89.0 build --release` + 实际查询 |
| 与 Plan §3.2/§8 一致 | 通过；但 §3.2 的“连接池 + 必要时 spawn_blocking”需升级为“所有 PG 调用必须 spawn_blocking，池生命周期在 runtime 外” |

**D0 PostgreSQL 部分通过。** 不需要改回 async 大改现有调用；但 D1/D3 必须按 §10/§11 的硬约束实现，否则会出现运行时 panic，而不是单纯性能问题。
