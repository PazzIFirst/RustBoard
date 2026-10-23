# M4 冷归档依赖 spike —— Rust 1.85 方案 A 复验报告

- 日期：2026-10-24
- 分支：`chore/m4-dep-spike`（基于 main `7cfba78`）
- 工程：`spikes/m4-deps-185/`（独立 workspace，`resolver = "3"`，不加入根 workspace）
- 对照：`spikes/m4-deps/`（Rust 1.80 基线，见其 `REPORT.md`）
- 补充复验：`spikes/m4-deps-187/`（Rust 1.87，验证 ctutils 修复边界）
- 性质：**编译期 spike**；未连接真实 S3/MinIO 或 SFTP 服务器。

---

## 0. 结论（TL;DR）

| 检查项 | 结果 | 依据 |
|---|---|---|
| Rust 1.85.0 下编译 | **通过** | `cargo +1.85.0 check --locked` exit 0 |
| 本地 run（gzip/HMAC/ColdStore） | **通过** | `cargo +1.85.0 run --locked` exit 0 |
| ed25519 私钥加载 API 编译 | **通过** | `load_secret_key` + `PrivateKeyWithHashAlg` + `authenticate_publickey` |
| 无 `openssl` / `openssl-sys` / `cmake` / `aws-lc-*` | **通过** | `cargo tree` 无这些包；ring 0.17.14 |
| quick-xml >= 0.41 | **通过** | object_store 0.14.2 → quick-xml 0.41.0 |
| `cargo audit` **0 高危（1.85）** | **不通过** | ctutils 0.4.2 按 high 处理（RUSTSEC-2026-0385）；rsa 为 medium |
| `cargo audit` **0 高危（1.87）** | **通过** | ctutils 升 0.4.5；只剩 rsa medium（optional/未编译） |
| `cargo audit` **0 advisory** | **不通过（1.85/1.87）** | 1.85 有 ctutils+rsa；1.87 仍有 rsa，且无修复 |
| **C2（S3）** | **可继续** | S3 链路无 advisory；object_store/reqwest/rustls/quick-xml 均干净 |
| **C3（SFTP）audit 0** | **不通过** | russh 的 optional `rsa` 必然进入 Cargo.lock，带 medium Marvin 公告；不 ignore 就无法 audit 0 |

**一句话**：1.85 能把 S3/SFTP 依赖编过，但**达不到「0 高危」**：ctutils 0.4.2
有 crypto-failure 公告（按 high 处理，修复需 1.87）。升到 1.87 后 ctutils 修复、
**0 高危成立**，但**做不到字面上的 audit 0**：**russh 的 optional rsa 依赖仍会留在
lock 中并被 audit 标记**
（`cargo tree -i rsa` 为空，未编译，但 audit 扫 lock）。因此：
**SFTP 要 audit 0，必须 fork/patch russh 去掉 optional rsa 依赖，或放弃 C3；
不允许静默 `--ignore`。** C2（S3）不受此影响，可在 1.85/1.87 继续。

---

## 1. 环境与工程

```text
rustc 1.85.0 (4d91de4e4 2025-02-17)
cargo 1.85.0 (d73d2caf9 2024-12-31)
RUSTUP_HOME=/tmp/rustup
CARGO_HOME=/tmp/cargo
CARGO_TARGET_DIR=/root/code/serverdashboard/target/m4-spike-185
```

- `Cargo.lock` 为 **version 4**（Cargo 1.83+ 默认格式；与 1.80 工程的 v3 不同）。
- `[workspace] resolver = "3"`：按 `rust-version = 1.85` 做 MSRV-aware 解析。
  **这是必需的**：resolver 2 会选到 `aes 0.9.3`（1.89）、`crc-fast 1.10.0`（1.89）、
  `ctutils 0.4.5`（1.87）、`icu 2.4`（1.88）、`sha2 0.11.1`（1.88）等，
  `cargo +1.85.0 check` 直接报「rustc 1.85.0 is not supported」。
- 工程结构与 1.80 相同：`src/main.rs`、`src/coldstore.rs`、`src/sftp.rs`。
- **未修改根 workspace / 根 Cargo.toml / 根 Cargo.lock / MSRV。**
- **未做真实网络测试**：S3/SFTP 真连由环境变量开关控制，本次只验证编译期与本地逻辑。

---

## 2. 选定的直接依赖（精确版本）

| crate | 版本 | features | 许可证 | 声明 MSRV | edition | 用途 |
|---|---|---|---|---|---|---|
| `object_store` | **0.14.2** | `default-features=false`, `aws-base`, `reqwest`, `ring` | MIT/Apache-2.0 | 1.85 | 2024 | S3/MinIO：endpoint、path_style、静态凭证、put/get/head/delete |
| `russh` | **0.60.3** | `default-features=false`, `ring`（**不启用 rsa / aws-lc-rs**） | Apache-2.0 | 1.85 | 2024 | SSH：密码认证、ed25519 私钥、超时 |
| `russh-sftp` | **3.0.1** | 默认 | Apache-2.0 | 未声明（1.85 实测可编译） | 2021 | SFTP：mkdir/write/read/remove |
| `reqwest` | **0.13.3** | `default-features=false`, `rustls-no-provider`, `http2`, `stream` | MIT OR Apache-2.0 | 1.64 | 2021 | object_store 的 HTTP 传输 |
| `rustls` | **0.23.46** | `default-features=false`, `ring`, `std` | Apache-2.0 OR ISC OR MIT | 1.71 | 2021 | 安装 ring CryptoProvider |
| `flate2` | **1.1.10** | `default-features=false`, `rust_backend` | MIT OR Apache-2.0 | 1.67 | 2018 | `csv.gz` 压缩（纯 Rust miniz_oxide） |
| `hmac` | **0.12.1** | 默认 | MIT OR Apache-2.0 | 未声明 | 2018 | HMAC-SHA256 |
| `sha2` | **0.10.9** | 默认 | MIT OR Apache-2.0 | 未声明 | 2018 | SHA-256（仓库已有） |
| `async-trait` | **0.1.92** | 默认 | MIT OR Apache-2.0 | 1.71 | 2021 | `ColdStore` 异步 trait |
| `tokio` | **1.54.1** | rt-multi-thread/macros/time/io-util/net | MIT | 1.85 | 2021 | 示例运行时 |
| `anyhow` | **1.0.104** | 默认 | MIT OR Apache-2.0 | 1.68 | 2021 | 示例错误类型 |

### 2.1 必须说明的 feature 选择（与「features=["aws"]」的差异）

**object_store 0.14.2 的 `aws` feature 会强制启用 `aws-lc-rs`**：

```toml
# object_store 0.14.2 的原始定义
aws = ["aws-base", "reqwest", "reqwest/rustls", "aws-lc-rs"]
```

`reqwest/rustls` 在 reqwest 0.13 中也走 `__rustls-aws-lc-rs`。因此**直接使用
`features=["aws"]` 会引入 aws-lc-rs / aws-lc-sys（通常还会触发 cmake），
违反「无 aws-lc/cmake」约束**。本 spike 改用功能等价的细粒度组合：

```toml
object_store = { version = "=0.14.2", default-features = false,
                 features = ["aws-base", "reqwest", "ring"] }
reqwest = { version = "=0.13.3", default-features = false,
            features = ["rustls-no-provider", "http2", "stream"] }
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
```

- `aws-base` 提供 S3 客户端、SigV4、CRC 等；`ring` 提供签名/CRC 的加密后端；
- `reqwest` 不选 provider，运行时在 `main` 中安装 ring provider：
  `rustls::crypto::ring::default_provider().install_default()`；
- 编译与 feature tree 已确认没有 `aws-lc-rs` / `aws-lc-sys`。

这不是静默降级，而是为满足约束必须做的 feature 重选；**若主 Agent 要求字面
`features=["aws"]`，则无法同时满足「无 aws-lc」**，需要明确取舍。

### 2.2 未启用 rsa 的后果

`russh` 的 `rsa` feature 未启用，因此**不支持 RSA 主机密钥/RSA 用户密钥**；
连接只提供 RSA 主机密钥的旧服务器会失败。ed25519（以及 russh 内置的其他算法）
正常。若启用 `rsa`，会额外把 `rsa 0.9/0.10` 的 Marvin medium 公告带入运行时代码，
不建议。

---

## 3. 1.85 实测结果

### 3.1 编译与运行

```console
$ rustc +1.85.0 --version
rustc 1.85.0 (4d91de4e4 2025-02-17)

$ cargo +1.85.0 check --locked
    Finished `dev` profile [unoptimized + debuginfo] target(s) in ...
    # exit 0

$ cargo +1.85.0 run --locked
declared rust-version = 1.85
flate2(rust_backend) ok: 67 -> 90 字节
hmac-sha256 ok: 5650a314a6c1d440555811f9f7c580c4169c0a313f5f4ba1074d97d5896df757
async-trait ColdStore ok
m4-deps spike: 本地检查全部通过
    # exit 0
```

`src/sftp.rs` 覆盖：`client::connect` + 10s `tokio::time::timeout`、密码认证、
`load_secret_key`（ed25519/OpenSSH 私钥）+ `PrivateKeyWithHashAlg` +
`authenticate_publickey`、`request_subsystem(true, "sftp")`、
`SftpSession::create_dir/write/read/remove_file`。**ed25519 API 编译通过。**

### 3.2 依赖树证明

```console
$ cargo +1.85.0 tree --locked | grep -nE ' (openssl|openssl-sys|cmake|aws-lc-sys|aws-lc-rs) v'
# 无输出

$ cargo +1.85.0 tree --locked -i quick-xml
quick-xml v0.41.0
└── object_store v0.14.2
    └── m4-deps-spike-185 v0.1.0 (...)

$ cargo +1.85.0 tree --locked -e features -i object_store | grep 'object_store feature'
├── object_store feature "aws-base"
├── object_store feature "reqwest"
└── object_store feature "ring"
# 没有 "aws" / "aws-lc-rs" feature

$ cargo +1.85.0 tree --locked -e features -i rustls | grep 'rustls feature'
├── rustls feature "ring"

$ cargo +1.85.0 tree --locked -i ring
ring v0.17.14
├── object_store v0.14.2
├── russh v0.60.3
├── rustls v0.23.46
│   ├── hyper-rustls v0.27.10
│   ├── reqwest v0.13.3
│   └── tokio-rustls v0.26.6
└── rustls-webpki v0.103.16
```

两个非 OpenSSL 的误报点与 1.80 相同：

1. `openssl-probe 0.2.1` 来自 `rustls-platform-verifier` → `rustls-native-certs`，
   是**纯 Rust** 的系统证书路径探测，不链接 OpenSSL；没有 `openssl-sys`。
2. `cc 1.10.0` 仅作为 `ring` 的 build-dependency（编译 ring 的 C/汇编）；
   **没有 `cmake`**。

### 3.3 MSRV 审计

- Linux 构建图 **255 个包**；声明 `rust-version > 1.85` 的包：**0 个**。
- 构建图最大声明 MSRV：`hashbrown 0.17.1` 的 **1.85.0**；
  `object_store 0.14.2`、`russh 0.60.3`、`tokio 1.54.1` 也都是 1.85。
- 结论：1.85 是这套依赖的**精确下限**；1.85.0 实测编译通过。

---

## 4. 安全审计（关键）

```console
$ cargo +stable audit --file Cargo.lock
error: 2 vulnerabilities found!
```

| crate | 版本 | 公告 | 严重度 | 修复 | 是否编译 |
|---|---|---|---|---|---|
| `ctutils` | 0.4.2 | RUSTSEC-2026-0385（non-constant-time mask/u128 compare，crypto-failure） | RustSec 无 CVSS 字段；**按主 Agent 复核按 high 处理** | >= 0.4.4（要求 Rust 1.87） | **是**，经 russh → crypto-bigint/p256/p384/p521 |
| `rsa` | 0.10.0-rc.16 | RUSTSEC-2023-0071（Marvin timing，CVE-2023-49092） | 5.9 **medium** | 无修复版本 | **否**（russh 的 optional dep，未启用 rsa feature；`cargo tree -i rsa` 无输出） |

### 4.1 1.85 的结论

- **1.85 不满足「0 高危」**：ctutils 0.4.2 是 crypto-failure 且被编译进 SSH 依赖
  （即使只协商 ed25519，代码仍在），按主 Agent 复核按 **high** 处理；1.85 无法升到
  修复版 0.4.4（需 1.87）。rsa 为 medium。
- 因此 1.85 同时不满足 audit 0：1 high + 1 medium。
- rsa 虽未编译，但**只要用官方 russh，optional 依赖就会进入 Cargo.lock**，
  `cargo audit --file Cargo.lock` 就会报。**无法通过 feature 关闭来消除。**

### 4.2 Rust 1.87 复验（ctutils 修复边界）

工程：`spikes/m4-deps-187/`（同样的依赖与代码，`rust-version = "1.87"`、
`resolver = "3"`）。

```console
$ rustc +1.87.0 --version
rustc 1.87.0 (17067e9ac 2025-05-09)

$ cargo +1.87.0 check --locked    # exit 0
$ cargo +1.87.0 run --locked      # exit 0，本地检查全部通过

$ grep -A1 'name = "ctutils"' Cargo.lock
name = "ctutils"
version = "0.4.5"                  # >= 0.4.4，公告已修复

$ cargo +stable audit --file Cargo.lock
Crate:     rsa
Version:   0.10.0-rc.16
ID:        RUSTSEC-2023-0071
Severity:  5.9 (medium)
error: 1 vulnerability found!
```

**1.87 只剩 rsa 一条（medium，optional/未编译）。** 这证明：
- ctutils 的问题可以靠「Rust 1.87 + resolver 3」解决；
- **rsa 无法通过升 Rust 解决**——它在 lock 里，且没有修复版本。

### 4.3 SFTP 达到 audit 0 的硬条件

由 4.1/4.2 可得：

1. 必须把 MSRV 至少提到 **1.87**（ctutils >= 0.4.4）；
2. 必须**移除 russh 的 optional `rsa` 依赖**（fork/patch russh 的 Cargo.toml，
   删除 `rsa`/`pkcs1` optional deps 与 `rsa` feature，保留 `#[cfg(feature="rsa")]`
   代码不编译），或**放弃 C3**；
3. **不能静默 `cargo audit --ignore RUSTSEC-2023-0071`**：rsa 确实未编译，
   但 ignore 会掩盖「官方 russh 依赖树含不可修复 medium」这一事实；若确要
   ignore，必须作为显式风险接受项由人类签字，而不是 spike 静默处理。

---

## 5. 许可证

构建图 255 个包，全部为宽松许可，无 GPL/AGPL/SSPL：

| 许可证 | 包数 |
|---|---|
| MIT OR Apache-2.0 | 129 |
| Apache-2.0 OR MIT | 47 |
| MIT | 32 |
| Unicode-3.0（ICU 数据） | 18 |
| MIT/Apache-2.0 | 6 |
| Apache-2.0 | 5 |
| BSD-3-Clause | 3 |
| Apache-2.0 OR ISC OR MIT | 3 |
| Unlicense OR MIT / ISC / 0BSD / Zlib / BSL-1.0 / BSD-1-Clause 等 | 12 |

- `object_store`：MIT/Apache-2.0；`russh`/`russh-sftp`：Apache-2.0。
- `Unicode-3.0` 需随分发保留声明；发布时用 `cargo about` 生成第三方许可清单。
- `fiat-crypto` 的 `MIT OR Apache-2.0 OR BSD-1-Clause` 属宽松许可。
- **注意 pre-release 加密栈**：1.85/1.87 lock 中 `ed25519-dalek 3.0.0-pre.6`、
  `curve25519-dalek 5.0.0-pre.6`、`rsa 0.10.0-rc.16` 等来自 russh 的
  `internal-russh-forked-ssh-key 0.6.18`；pre-release 的稳定性/维护性需纳入风险。

---

## 6. 与 1.80 基线的差异

| 维度 | 1.80 方案 | 1.85/1.87 方案 |
|---|---|---|
| object_store | 0.11.2（quick-xml 0.37.5） | **0.14.2**（quick-xml 0.41.0） |
| russh | 0.53.0 | **0.60.3** |
| russh-sftp | 3.0.1 | 3.0.1 |
| reqwest | 0.12.28（间接） | **0.13.3**（直接依赖，控制 TLS provider） |
| tokio | 1.53.3 | **1.54.1** |
| resolver | 2 | **3**（MSRV-aware） |
| Cargo.lock | version 3 | **version 4** |
| 构建图包数 | 233 | **255** |
| audit 结果 | 10 项（构建图 4 high + 1 medium，另 5 quinn） | **2 项**（ctutils 未分级 + rsa medium；0 high） |
| API 差异 | `ObjectStore` 直接提供 put/get/head/delete | 0.14 需 `use object_store::ObjectStoreExt`；`ObjectMeta.size` 为 `u64` |
| TLS | object_store `aws` → ring（0.11 的 cloud 内含 ring） | `aws-base`+`ring`，reqwest `rustls-no-provider` + 手动装 ring provider |
| MSRV 下限 | 1.80（但 audit 不通过） | 1.85（0 high）/ 1.87（ctutils 修复） |

1.80 方案引入的 quick-xml/russh/russh-cryptovec 高危在 1.85 方案中**已全部消失**；
新增的是 ctutils（1.85 上无法修）和 rsa（optional，无修复）。

---

## 7. 风险清单

| 风险 | 影响 | 建议 |
|---|---|---|
| rsa 在 lock 中（未编译） | 官方 russh 下 audit 永远非 0 | fork/patch 去掉 optional rsa，或放弃 C3；不要静默 ignore |
| ctutils 0.4.2（1.85） | crypto-failure，SSH 代码路径可触发 | 提到 1.87+，或放弃 C3 |
| pre-release 加密依赖 | 稳定性/兼容性/供应链 | 锁定版本、跟踪 russh/ssh-key fork 上游；发布前复核 |
| `object_store` 的 `aws` feature | 会拉 aws-lc-rs/cmake | 只用 `aws-base`+`reqwest`+`ring`；在代码评审中卡住 |
| resolver 2 与 MSRV | 1.85 下会选到 1.87/1.88/1.89 的依赖 | 根 workspace 若升 1.85，需启用 `resolver = "3"` 或精确 pin |
| lock v4 | Cargo <1.83 无法读取 | 1.85/1.87 工程独立；1.80 工程保持 v3 |
| 运行时 TLS provider | reqwest `rustls-no-provider` 未安装会 panic | hub 启动时安装一次 ring provider；避免重复安装冲突 |
| 无 RSA 主机密钥 | 只提供 RSA host key 的旧服务器失败 | 目标服务器确认支持 ed25519/ECDSA；否则评估 fork 启用 rsa 的 medium 风险 |
| 未做真实连通性测试 | 权限/路径/协议细节后置暴露 | C2/C3 实现阶段各加 MinIO/OpenSSH 集成测试 |
| 根 workspace 仍 resolver 2 / MSRV 1.80 | 直接集成可能重新解析失败 | 本次未改根；M4 集成时单独 PR 处理 resolver/MSRV |

---

## 8. 结论与方案 B

### 8.1 通过/不通过

- **Rust 1.85 编译与「无 openssl/aws-lc/cmake」：通过。**
- **1.85「0 高危」：不通过**（ctutils 按 high 处理）。
- **1.87「0 高危」：通过**（ctutils 0.4.5 修复；仅剩 rsa medium）。
- **字面「audit 0」：1.85/1.87 均不通过**：ctutils（仅 1.85）+ rsa（无修复、optional）。
- **C2（S3）：可以继续**：object_store 0.14.2 + quick-xml 0.41 + reqwest/rustls/ring
  链路 audit 干净，无 openssl/aws-lc/cmake。
- **C3（SFTP）：按 audit 0 门禁不通过**：必须 fork/patch russh 去掉 optional rsa
  且 MSRV ≥1.87，或放弃 C3。

### 8.2 方案 B（若必须 audit 0，且不 fork/patch russh）

1. **停止 C3（SFTP）**。不引入 russh，即没有 ctutils/rsa 公告。
2. **C2（S3）保留**：
   - 首选 object_store 0.14.2（本报告已验证）；
   - 或自研最小 S3 SigV4 客户端（reqwest + hmac + sha2，put/get/head/delete 不需要 XML），
     避免 object_store 的 feature 复杂度；
   - WebDAV 继续用现有 reqwest。
3. **MSRV**：若保留 C2 的 object_store 0.14.2，需要至少 1.85；建议直接用 1.85
   （C2 链路在 1.85 下 audit 干净）。
4. **不要**使用 `--ignore` 掩盖 rsa/ctutils；如确需接受风险，必须由人类签字并
   记录在 known-issues，且不能作为「audit 0」宣称。

---

## 9. 复现

```bash
export RUSTUP_HOME=/tmp/rustup CARGO_HOME=/tmp/cargo PATH=/tmp/cargo/bin:$PATH
export CARGO_TARGET_DIR=/root/code/serverdashboard/target/m4-spike-185
cd /root/code/serverdashboard/.worktrees/m4-spike/spikes/m4-deps-185

rustup toolchain install 1.85.0 --profile minimal
cargo +1.85.0 check --locked
cargo +1.85.0 run --locked
cargo +1.85.0 tree --locked
cargo +stable audit --file Cargo.lock   # 预期 ctutils + rsa，0 high

# 1.87 复验
cd ../m4-deps-187
export CARGO_TARGET_DIR=/root/code/serverdashboard/target/m4-spike-187
rustup toolchain install 1.87.0 --profile minimal
cargo +1.87.0 check --locked
cargo +1.87.0 run --locked
cargo +stable audit --file Cargo.lock   # 预期只剩 rsa medium
```

关键版本固定：

```bash
# 1.85 lock 必须锁 ctutils 0.4.2（0.4.3+ 需要 1.87）
cargo +1.85.0 update -p ctutils --precise 0.4.2
```

---

## 10. 相关文件

- `spikes/m4-deps/REPORT.md`：Rust 1.80 基线报告（audit 不通过，历史记录）。
- `spikes/m4-deps-185/`：本报告工程与 lock（1.85）。
- `spikes/m4-deps-187/`：1.87 边界复验工程与 lock。
