# M5 Phase C C0：ACME 依赖与 Pebble spike 结论

> 状态：完成｜执行日期：2026-10-25｜基线：`6263d17`
> 关联：[Phase C 计划](2026-10-25-m5-phase-c-tls-release-gates.md) §5 C0、§D1、§D7

## 1. 结论摘要

| 未知项 | 结论 | 证据 |
|---|---|---|
| `instant-acme 0.8.5` + ring 是否可在 MSRV 1.89 编译 | **可以** | `cargo +1.89.0 check` 成功；`cargo tree -i aws-lc-rs` / `openssl-sys` / `cmake` 均无输出 |
| Pebble 是否接受 DNS 与 IP identifier | **都接受** | HTTP-01 分别对 `localhost` 与 `127.0.0.1` 签发成功 |
| `shortlived` profile | **Pebble 接受**，签发 6 天证书 | `NewOrder::profile("shortlived")`；Pebble 配置 `validityPeriod=518400` |
| TLS-ALPN-01 是否可用 rcgen 扩展 | **可以** | `CustomExtension::new_acme_identifier` + 自定义 `ResolvesServerCert` 签发成功 |
| 自定义 CA 如何注入 | `Account::builder_with_root` 可用，但**只读取一张 PEM 证书** | Pebble 根证书 `pebble.minica.pem`；生产多根 CA 需自定义 `HttpClient` 或多根加载 |
| 本机 80/443 是否可绑定 | **80 被宿主 nginx 占用**；443 未监听 | `ss -ltnp`；Pebble 测试改用 `httpPort=5002` / `tlsPort=5001` |

C0 没有发现需要更换 ACME crate 的理由。继续按计划使用：

```toml
instant-acme = { version = "=0.8.5", default-features = false, features = ["ring", "hyper-rustls"] }
```

## 2. 环境与版本

| 项 | 值 |
|---|---|
| 主机 | Linux x86_64 |
| 当前工具链 | `rustc 1.99.1` / `cargo 1.99.1` |
| MSRV 工具链 | `rustc 1.89.0 (29483883e 2025-08-04)` |
| Pebble 镜像 | `ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199` |
| 86/443 | 80 由宿主 `nginx` 占用；443 空 |
| Pebble 挑战端口 | HTTP `5002`、TLS-ALPN `5001`（Pebble 配置默认值） |

## 3. 依赖 spike

临时 crate：`/tmp/rb-acme-spike`（不入库）。

```toml
[package]
name = "rb-acme-spike"
version = "0.1.0"
edition = "2021"
rust-version = "1.89"

[dependencies]
instant-acme = { version = "=0.8.5", default-features = false, features = ["ring", "hyper-rustls"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
serde_json = "1"
rcgen = { version = "0.13", default-features = false, features = ["crypto", "pem", "ring", "x509-parser"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
```

验证命令：

```bash
cd /tmp/rb-acme-spike
export PATH=/root/.cargo/bin:$PATH
cargo +1.89.0 check
cargo tree -i aws-lc-rs
cargo tree -i openssl-sys
cargo tree -i cmake
```

结果：

- `cargo +1.89.0 check`：exit 0；
- 三个反向依赖查询均为 `error: package ID specification ... did not match any packages`；
- 没有 cmake / aws-lc / openssl 构建依赖。

## 4. Pebble 启动

```bash
docker run -d --name rb-pebble --network host \
  -e PEBBLE_VA_NOSLEEP=1 \
  -e PEBBLE_WFE_NONCEREJECT=0 \
  ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199

curl -sk https://localhost:14000/dir | head
```

必须使用 `--network host`：Pebble 的 VA 会主动连接 `httpPort`/`tlsPort` 上的挑战服务；若用 Docker 端口映射，容器内访问不到宿主端口，且 5001/5002 会与宿主测试服务冲突。生产验收/CI 中应把 Pebble 与 challenge 服务放在同一 netns，或显式配置 Pebble 可访问的地址。

Pebble 目录 `https://localhost:14000/dir`，根证书从镜像 `/test/certs/pebble.minica.pem` 提取（仅测试用，不入库）。Pebble 配置已启用：

```json
"httpPort": 5002,
"tlsPort": 5001,
"profiles": {
  "default": { "validityPeriod": 7776000 },
  "shortlived": { "validityPeriod": 518400 }
}
```

## 5. HTTP-01：DNS 与 IP

`rb-acme-spike` 用 `Account::builder_with_root("/tmp/pebble-test/certs/pebble.minica.pem")` 创建账户，`NewOrder::new(&[Identifier::Dns("localhost")])` 或 `Identifier::Ip(127.0.0.1)`，启动最小 HTTP 服务返回 key authorization。

成功输出（节选）：

```text
account=https://localhost:14000/my-account/...
order=https://localhost:14000/my-order/... state=Pending
authz AuthorizedIdentifier { identifier: Dns("localhost"), wildcard: false } status=Pending
challenge token_len=43 keyauth_len=87
ready=Ready
cert_bytes=1259 key_bytes=241
```

IP 模式：

```text
authz AuthorizedIdentifier { identifier: Ip(127.0.0.1), wildcard: false } status=Pending
ready=Ready
cert_bytes=1251 key_bytes=241
```

`Identifier` 必须按输入选择 `Dns` 或 `Ip`；把 IP 填进 `Dns` 会被 Pebble 以 `malformed` 拒绝。产品实现必须复用同一分支逻辑，不能只拼字符串。

`shortlived` profile：

```bash
ACME_IDENT=127.0.0.1 ACME_PROFILE=shortlived cargo run
```

Pebble 接受 profile，签发证书 `notBefore=2026-10-25`、`notAfter=2026-10-31`，约 6 天，符合 D8 的 48h 续期阈值设计。`NewOrder::profile` 在 directory 未声明 profile 时会返回明确错误；产品应在启动前检查 directory `meta.profiles` 或把错误归类为配置错误。

## 6. TLS-ALPN-01

挑战证书用 rcgen：

```rust
let mut params = CertificateParams::new(vec![ident.to_string()])?;
params.is_ca = IsCa::NoCa;
params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
params.custom_extensions.push(
    CustomExtension::new_acme_identifier(key_authorization.digest().as_ref()),
);
let key = KeyPair::generate()?;
let cert = params.self_signed(&key)?;
```

**关键限制：不能用 `rustls::ServerConfig::builder().with_single_cert(...)`。**
`with_single_cert` 经 `CertifiedKey::from_der` → `keys_match` → rustls-webpki 解析叶子证书，遇到 critical 的 `id-pe-acmeIdentifier` 会返回：

```text
InvalidCertificate(Other(OtherError(UnsupportedCriticalExtension)))
```

这与 RFC 8737 要求该扩展必须 critical 冲突。正确做法是绕过 webpki 的 SPKI 匹配校验：

```rust
let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)?;
let certified = rustls::sign::CertifiedKey::new(vec![cert.der().clone()], signing_key);

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);
impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

let config = rustls::ServerConfig::builder()
    .with_no_client_auth()
    .with_cert_resolver(Arc::new(FixedCert(Arc::new(certified))));
```

产品 `acme/challenge.rs` 必须使用这个 resolver；同时仍要自行校验私钥与证书公钥一致（例如用 rcgen 生成配对材料，或单独比较 SPKI），不能因为绕过 rustls 检查而放松安全性。

成功输出：

```text
challenge token_len=43 keyauth_len=87
ready=Ready
cert_bytes=1259 key_bytes=241
```

ALPN 只配置 `acme-tls/1`；普通 HTTP 不在此端口提供。

## 7. 对 Phase C 计划的修订/确认

1. **D1 依赖确认**：`instant-acme 0.8.5` 的 `ring` + `hyper-rustls` 组合可用，不引入 aws-lc。
2. **D1 自定义 CA**：`Account::builder_with_root` 只读取单个 `CertificateDer`。如果 `acme_ca_file` 可能是多根 PEM（企业 CA），C4 需要：
   - 自建 `RootCertStore` 加载所有证书；
   - 用 hyper-rustls 构造 `HttpClient`，再 `Account::builder_with_http`；或
   - 明确限制 `acme_ca_file` 只能单根并在文档/校验中说明。
   建议实现多根加载，避免私有 CA 轮换时被迫改文件格式。
3. **D7 TLS-ALPN**：增加上述自定义 `ResolvesServerCert` 约束，写入 C4 实现任务。
4. **D9 端口诊断**：本机 80 被 nginx 占用，正好验证“安装器不得假设 80 可用”。e2e 使用 Pebble 5001/5002 时需在测试内显式说明这是测试端口，不替代生产 80/443 诊断。
5. **CI 端口**：GitHub hosted runner 的 80/443 通常可用，但 `delivery-*` 不应依赖固定端口；ACME e2e 用 Pebble 可配置端口或独立 netns。

## 8. 未覆盖 / 后续验证

- 真实 Let's Encrypt staging（域名 + 公网 IP 的 `shortlived`）需要公网入口，留 C9 手工门禁；本次只用 Pebble。
- Pebble 的 `shortlived` 只是配置有效期，不验证 LE 的 profile 策略/速率限制；RC 前必须做真实 staging。
- 多根自定义 CA 的加载与错误分类在 C4 实现并单测。
- TLS-ALPN 的 IP identifier（无 SNI）未单独跑；C4 测试覆盖 IP 时需确认 Pebble 行为，必要时补 spike。

## 9. 复现清理

```bash
docker rm -f rb-pebble
rm -rf /tmp/rb-acme-spike /tmp/pebble-test
```

测试材料（Pebble 根证书、账户 key、证书私钥）只在 `/tmp`，未提交、未写入仓库。
