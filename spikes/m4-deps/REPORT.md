# M4 冷归档依赖 spike 报告

- 日期：2026-10-24
- 分支：`chore/m4-dep-spike`（基于 main `7cfba78`）
- 工程：`spikes/m4-deps/`（独立 workspace，带空 `[workspace]`，不加入根 workspace）
- 对应方案：`docs/plans/2026-10-24-m4-alerting-archive.md` §7.3 / §12
- 性质：**编译期 spike**。已用 Rust 1.80.0 实际编译并运行本地检查；**未连接真实
  S3/MinIO 或 SFTP 服务器**（示例中的网络路径由环境变量显式开启，本次未执行）。

---

## 0. 结论（TL;DR）

| 检查项 | 结果 | 依据 |
|---|---|---|
| Rust 1.80.0 下编译 | **通过** | `cargo +1.80.0 check --locked`、`run --locked` 均 exit 0 |
| 无 `openssl` / `openssl-sys` / `cmake` | **通过** | `cargo tree` 中无这些包 |
| 无 `aws-lc-sys` / `aws-lc-rs`，使用 ring | **通过** | `rustls feature "ring"`；ring 0.17.14 |
| object_store（AWS only）编译 | **通过** | 0.11.2，`default-features=false` + `aws` |
| russh + russh-sftp 编译 | **通过** | russh 0.53.0（ring）+ russh-sftp 3.0.1 |
| flate2 rust_backend / HMAC / async-trait | **通过** | 本地运行验证压缩往返、HMAC-SHA256、trait object |
| `cargo audit` 高危为 0 | **不通过** | 10 项：构建图内 4 高危 + 1 中危，另有未启用的 quinn 5 项 |
| **M4-C2/C3 按现约束放行** | **不通过（建议停止 C2/C3，或先决策 MSRV）** | 见 §7、§9 |

**一句话结论**：在 Rust 1.80 + rustls/ring + 无 openssl/cmake 的前提下，这些依赖
**能编译、能跑通本地逻辑**；但在 1.80 可用的最新版本中，`object_store` 依赖的
`quick-xml < 0.41` 和 `russh 0.53.0` 都带有**高危** RustSec 公告，修复版本要求
Rust 1.85。按仓库 §8.5/§14「`cargo audit` 高危即卡、发布前 audit 为 0」的门禁，
**不能直接进入 C2/C3**。需要显式选择：升 MSRV 到 1.85（推荐，且 main 现有 lock
实际已需要 1.85），或保持 1.80 并调整范围（停 C3；C2 改自研最小 S3 客户端或延后）。

---

## 1. 环境与工程

```text
rustc 1.80.0 (051478957 2024-07-21)
cargo 1.80.0 (376290515 2024-07-16)
RUSTUP_HOME=/tmp/rustup
CARGO_HOME=/tmp/cargo
CARGO_TARGET_DIR=/root/code/serverdashboard/target/m4-spike
```

`spikes/m4-deps/Cargo.toml` 带空 `[workspace]`，根 workspace 的 `members` 是显式
列表，因此两边互不影响；根 `cargo fmt/clippy/test` 不会把它当成员。

目录：

```text
spikes/m4-deps/
├── Cargo.toml        # 直接依赖与 MSRV 锁定说明
├── Cargo.lock        # 1.80 可解析的精确版本（lock version 3）
├── REPORT.md         # 本报告
└── src/
    ├── main.rs       # flate2 / HMAC / ColdStore 本地检查 + 可选联网冒烟
    ├── coldstore.rs  # ColdStore trait、内存实现、S3 实现（put/get/head/delete/test）
    └── sftp.rs       # russh 密码/ed25519、连接超时、SFTP mkdir/write/read/remove
```

---

## 2. 选定的直接依赖

| crate | 版本 | features | 许可证 | 声明 MSRV | 用途 |
|---|---|---|---|---|---|
| `object_store` | **0.11.2** | `default-features=false`, `aws` | MIT/Apache-2.0 | 1.64.0 | S3/MinIO：自定义 endpoint、path_style、静态凭证、put/get/head/delete |
| `russh` | **0.53.0** | `default-features=false`, `ring` | Apache-2.0 | 1.75 | SSH 传输：密码认证、ed25519 私钥、超时 |
| `russh-sftp` | **3.0.1** | 默认 | Apache-2.0 | 未声明（实测 1.80 可编译） | SFTP 子系统：mkdir/write/read/remove |
| `flate2` | **1.1.10** | `default-features=false`, `rust_backend` | MIT OR Apache-2.0 | 1.67.0 | `csv.gz` 压缩（纯 Rust miniz_oxide） |
| `hmac` | **0.12.1** | 默认 | MIT OR Apache-2.0 | 未声明（edition 2018） | HMAC-SHA256（与 sha2 0.10 配对） |
| `sha2` | **0.10.9** | 默认 | MIT OR Apache-2.0 | 未声明（edition 2018） | SHA-256（仓库已有） |
| `async-trait` | **0.1.92** | 默认 | MIT OR Apache-2.0 | 1.71 | `ColdStore` 异步 trait |
| `tokio` | **1.53.3** | rt-multi-thread/macros/time/io-util/net | MIT | 1.71 | 示例运行时；主仓库已有 |
| `anyhow` | **1.0.104** | 默认 | MIT OR Apache-2.0 | 1.68 | 示例错误类型；主仓库已有 |

### 2.1 直接依赖的替代方案

| crate | 1.80 可用替代 | 说明 |
|---|---|---|
| `object_store` | **无「1.80 + audit 干净」版本**；可自研 S3 SigV4 客户端（reqwest + hmac + sha2） | 0.12.5 仍是 `quick-xml ^0.38`（同样受公告影响）；0.13/0.14 用加快捷修复的 quick-xml，但要求 Rust 1.85 |
| `russh` + `russh-sftp` | **无** | `ssh2`/libssh2 是 C 且通常链接 OpenSSL；`openssh` crate 拉起 `ssh` 子进程（方案明确禁止）；russh 是唯一纯 Rust 路线 |
| `flate2` | 无（保持 `rust_backend`） | `zlib`/`zlib-ng` 需要 C 工具链，违反约束 |
| `hmac` | 无（0.13 需 digest 0.11 / Rust 1.85） | 与仓库现有 `sha2 0.10.9` 配对，保持 0.12.1 |
| `async-trait` | 1.75+ 原生 `async fn` in trait | 但 `dyn ColdStore` 对象安全仍需 `async-trait`，保留 |
| `tokio` | 跟随主仓库 | 本 spike 锁 1.53.3 仅为 1.80 实测 |

---

## 3. 为满足 1.80 锁定的传递依赖（关键）

`cargo generate-lockfile` 默认会取到 2026-10 的最新传递依赖，其中不少已要求
Rust 1.85 或使用 edition 2024（Cargo 1.80 连 manifest 都无法解析）。以下版本由
`Cargo.lock` 固化；**不要直接 `cargo update`**，否则会重新拉高。

| crate | 锁定版本 | 更新版本的问题 |
|---|---|---|
| `tokio` | 1.53.3 | 1.54.1 声明 rust-version 1.85 |
| `tokio-util` | 0.7.19 | 0.7.20 声明 1.85 |
| `hyper-util` | 0.1.20 | 0.1.21 为 edition 2024 |
| `hyper-rustls` | 0.27.7 | 0.27.10 声明 1.85 |
| `indexmap` | 2.11.4 | 2.14.2 为 edition 2024；同时把 `hashbrown` 降到 0.16.1 |
| `ed25519-dalek` | 2.1.1 | 2.2.0 声明 1.81 |
| `zeroize` | 1.8.2 | 1.9.1 为 edition 2024 |
| `home` | 0.5.9 | 0.5.12 声明 1.81（russh 的依赖） |
| `idna_adapter` | 1.2.0 | 1.2.2 拉 `icu_* 2.4`（edition 2024）；1.2.0 用 icu 1.5 |
| `litemap` | 0.7.4 | 0.7.5 声明 1.81 |
| `quinn` / `quinn-proto` / `quinn-udp` | 0.11.9 / 0.11.14 / 0.5.14 | 更新的 quinn-proto 为 edition 2024 / 1.85；这是 reqwest 的**可选 http3 依赖，本构建未启用**，但 cargo 1.80 解析 lock 时仍会碰到 |

### 3.1 版本选择过程中的失败记录

1. **russh 0.54.6 无法解析**：它依赖 `libcrux-ml-kem ^0.0.3`，该版本已从 crates.io
   索引消失（`could not find libcrux-ml-kem@0.0.3`），无法生成 lock。
2. **russh 0.55.0–0.64.1 全部要求 Rust 1.85**，不能在 1.80 使用。
3. 因此 SFTP 只能退到 **russh 0.53.0**（MSRV 1.75，无 libcrux）。
4. **object_store 0.12.5 声明 MSRV 1.64**，但其 `quick-xml ^0.38` 同样低于修复版本
   0.41；0.13.0 起要求 1.85。按任务要求优先 0.11.x，选 **0.11.2**。
5. `cargo +1.80.0 metadata` 仍会失败（例如 macOS-only 的
   `security-framework 3.7.0` 是 edition 2024）——`metadata` 会解析 lock 里所有
   目标的 manifest；`cargo tree` / `check` 只处理当前 Linux 构建图，**均通过**。
   rust-version 审计因此用 stable 的 `cargo metadata` 完成，再与 1.80 的构建图交叉核对。

---

## 4. MSRV 实测

### 4.1 编译与本地运行

```console
$ rustc +1.80.0 --version
rustc 1.80.0 (051478957 2024-07-21)

$ cargo +1.80.0 check --locked
    Checking m4-deps-spike v0.1.0 (...)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.87s
    # exit 0

$ cargo +1.80.0 run --locked
declared rust-version = 1.80
flate2(rust_backend) ok: 67 -> 90 字节
hmac-sha256 ok: 5650a314a6c1d440555811f9f7c580c4169c0a313f5f4ba1074d97d5896df757
async-trait ColdStore ok
m4-deps spike: 本地检查全部通过
    # exit 0
```

覆盖内容：

- `AmazonS3Builder` 自定义 endpoint / path_style / access key / secret，以及
  `put` / `get` / `head` / `delete`（编译期；`put` 后做 head 长度校验）；
- russh 密码认证 + `load_secret_key` 加载 ed25519 私钥 + 10s 连接超时 +
  `request_subsystem("sftp")` + `SftpSession::create_dir/write/read/remove_file`；
- `flate2` `GzEncoder`/`GzDecoder` 往返；
- `Hmac<Sha256>`；
- `#[async_trait] ColdStore` 的 `dyn` 调用。

### 4.2 rust-version 审计

- Linux 构建图 **233 个包**，声明 `rust-version > 1.80` 的包：**0 个**；
  构建图内最大声明 MSRV 是 spike 自身的 `1.80`。
- 声明 MSRV 不等于真实 MSRV，**1.80.0 实际 `check` 通过**才是最终依据。
- `Cargo.lock` 里仍有 14 个**未参与 Linux 构建**的包（wasm/macOS/windows/可选
  quinn）声明 > 1.80，例如 `security-framework 3.7.0`、`wasm-bindgen 0.2.129`、
  `wit-bindgen 0.57.1`。它们不影响 `cargo +1.80.0 check`，但会让
  `cargo +1.80.0 metadata` 失败。

### 4.3 与主工作区现状的差异（重要）

main 现有的 `Cargo.lock` **本身已经不能用 1.80 构建**：

```console
$ cargo +1.80.0 check --locked   # 在仓库根执行，CARGO_TARGET_DIR 指到仓库外
error: failed to download `cpufeatures v0.3.1`
...
feature `edition2024` is required
```

main lock 中已有 `tokio 1.54.1`（rust-version 1.85）、`indexmap 2.14.2`
（edition 2024）、`hyper-util 0.1.21`、`zeroize 1.9.1` 等。也就是说
**「MSRV 1.80」在本次 spike 之前就已经不是 main 的真实状态**，这一点应作为
是否继续坚持 1.80 的决策输入。本 spike 未修改 main。

---

## 5. 依赖树证明：无 openssl / cmake / aws-lc

```console
$ cargo +1.80.0 tree --locked | grep -E ' (openssl|openssl-sys|cmake|aws-lc-sys|aws-lc-rs) v'
# 无输出

$ cargo +1.80.0 tree --locked -e features -i rustls | grep 'rustls feature'
├── rustls feature "ring"

$ cargo +1.80.0 tree --locked -i ring
ring v0.17.14
├── object_store v0.11.2
├── russh v0.53.0
├── rustls v0.23.46
│   ├── hyper-rustls v0.27.7
│   ├── reqwest v0.12.28
│   └── tokio-rustls v0.26.6
└── rustls-webpki v0.103.16
```

两个容易误判的点：

1. **`openssl-probe 0.2.1` 会出现**，它是 `rustls-native-certs` 用来探测系统证书
   目录的**纯 Rust** 小 crate，不链接 OpenSSL，也没有 `openssl-sys`。
2. **`cc 1.10.0` 会出现**，仅作为 `ring` 的 build-dependency，用来编译 ring 自带的
   C/汇编（rustls/ring 基线本来就如此）；**没有 `cmake`**。

`Cargo.lock` 中同样没有 `openssl` / `openssl-sys` / `aws-lc-sys` / `aws-lc-rs` /
`cmake` 包（只有 `openssl-probe`，见上）。

---

## 6. 许可证

直接依赖均为宽松许可：MIT / Apache-2.0 / Apache-2.0 OR MIT；`russh` 与
`russh-sftp` 为 Apache-2.0，`object_store` 为 MIT/Apache-2.0。

构建图 233 个包的许可证分布：

| 许可证 | 包数 |
|---|---|
| MIT OR Apache-2.0 | 111 |
| Apache-2.0 OR MIT | 38 |
| MIT | 33 |
| Unicode-3.0（ICU 数据） | 19 |
| MIT/Apache-2.0 | 7 |
| Apache-2.0 | 5 |
| BSD-3-Clause | 3 |
| Apache-2.0 OR ISC OR MIT | 3 |
| Unlicense OR MIT | 2 |
| Unlicense/MIT | 2 |
| ISC | 2 |
| 0BSD、Zlib、BSL-1.0、BSD-2-Clause 等组合 | 8 |

- **无 GPL / AGPL / SSPL / 商业限制许可**。
- `Unicode-3.0`（ICU4X 数据）要求随分发保留版权与许可声明；发布时建议用
  `cargo about`（或等价工具）生成第三方许可清单。
- 供应链注意：russh 0.53.0 依赖 russh 自己发布的
  `internal-russh-forked-ssh-key 0.6.11+upstream-0.6.7` 与 `russh-cryptovec`，
  不是 upstream `ssh-key`；升级/审计时要一并跟踪。

---

## 7. 安全审计（阻断项）

```console
$ cargo +stable audit --file Cargo.lock
error: 10 vulnerabilities found!
```

| crate | 版本 | 公告 | 严重度 | 修复版本 | 是否进入构建 |
|---|---|---|---|---|---|
| `quick-xml` | 0.37.5 | RUSTSEC-2026-0195 / RUSTSEC-2026-0194 | **7.5 high** ×2 | >= 0.41.0 | **是**（object_store 的 S3 XML） |
| `russh` | 0.53.0 | RUSTSEC-2026-0154（Unbounded 32-bit allocation） | **7.5 high** | >= 0.60.3（Rust 1.85） | **是** |
| `russh-cryptovec` | 0.52.0 | RUSTSEC-2026-0153（Unchecked allocation） | **7.5 high** | >= 0.60.3 | **是** |
| `rsa` | 0.9.10 | RUSTSEC-2023-0071（Marvin timing） | 5.9 medium | 无修复版本 | **是**（russh 0.53 无条件依赖） |
| `quinn-proto` | 0.11.14 | RUSTSEC-2026-0342 / 0340 / 0339 / 0338 / 0185 | 2 high + 3 未分级 | >= 0.11.18 | **否**（reqwest 的可选 http3 未启用） |

关键事实：

- 构建图内实际编译的是前 4 行：**4 个高危 + 1 个中危**。
- 把 `quinn-proto` 升到修复版 0.11.18 会让 `rand 0.10` / `cpufeatures 0.3.1`
  （edition 2024）重新进入 lock，`cargo +1.80.0 check` 直接无法解析 manifest；
  1.80 能解析的 0.11.14 又带 5 项公告。**在 1.80 上无法同时满足「可解析」与
  「quinn 无公告」**，虽然它并未被编译。
- `object_store 0.12.5` 使用 `quick-xml ^0.38`，仍 < 0.41；0.14.2 才用 `^0.41`，
  但要求 Rust 1.85。**不存在 1.80 可用的 object_store 版本能通过 audit**。
- `russh 0.60.3`（修复版）要求 Rust 1.85；0.55–0.64 全部 1.85。
  **不存在 1.80 可用的 russh 版本能通过 audit**。
- 对照：**main 当前 `cargo audit` 为 0**（268 个包，exit 0），上述公告是本次新增
  依赖引入的，不是既有基线。

> 因此，严格按照仓库门禁（§8.5：`cargo audit` 存在高危 advisory 禁止发布；
> §14：audit 为 0），**C2/C3 不能放行**。若用 `--ignore` 静默，会违反 §12
> 「不静默降级」的要求。

---

## 8. 风险清单

| 风险 | 影响 | 建议 |
|---|---|---|
| M4 依赖引入高危 advisory | 无法过 audit 门禁 | 决策 MSRV 或砍范围（见 §9） |
| 传递依赖锁定漂移 | `cargo update` 后 1.80 构建失败 | 保留本 lock，CI 增加 1.80 job；升级依赖时重跑本 spike |
| Cargo.lock v4 | Cargo 1.80 无法读取 v4 lock | 保持 `version = 3`；用 1.80 生成/更新 lock |
| SFTP 主机密钥未校验 | MITM | 生产 `check_server_key` 必须比对配置中的 SHA256 指纹，不能像示例那样 `Ok(true)` |
| 私钥 / 密码泄露 | 凭据泄露 | 配置 0600、私钥 0600、日志脱敏、secret 不进 DB/API |
| rsa Marvin（medium，无修复） | RSA 私钥时序侧信道 | 优先 ed25519；如不需要 RSA 主机密钥可尝试关掉（0.60+ 有 `rsa` feature；0.53 不可关） |
| 未做真实 S3/SFTP 连通性测试 | 协议细节/权限问题后置暴露 | C2/C3 开工前各加一次显式 `--ignored` 集成测试（MinIO/OpenSSH） |
| S3 `test()` 用 ListObjects | 需要额外 `s3:ListBucket` 权限 | 或改成对固定测试 key 做 HEAD/PUT+DELETE |
| Unicode-3.0 数据许可 | 分发合规 | 发布时生成第三方许可清单 |
| object_store 版本升级 API 差异 | 迁移成本 | 0.11 的 `PutPayload`、`with_virtual_hosted_style_request` 与 0.14 有差异，升级需重跑示例 |

---

## 9. 建议（需人工决策）

### 方案 A：把 MSRV 提到 1.85（推荐）

理由：main 现有 lock 已经要求 1.85（`tokio 1.54.1` 等），继续声明 1.80 与实测不符；
1.85 能同时拿到 S3/SFTP 的修复版本。

- `object_store` **0.14.2**（quick-xml 0.41，声明 1.85）
- `russh` **0.60.3+**，`default-features=false, features=["ring"]`（避免 aws-lc-rs；
  是否启用 `rsa` 由主机密钥兼容性决定，启用则有 Marvin 中危）
- `quinn-proto` **0.11.18**（audit 修复）
- Cargo.lock 升到 v4（Cargo 1.85+）

需要另开一次 spike 复验 1.85 下的 `check + audit + tree`，并同步改
`[workspace.package] rust-version` 与 CI。不能在本分支静默修改。

### 方案 B：坚持 1.80（必须砍范围）

- **停止 C3（SFTP）**：1.80 下没有既纯 Rust 又无高危的 SSH/SFTP 方案；
  `ssh2`/libssh2（C + OpenSSL）和 `openssh` crate（子进程）都违反方案约束。
- **C2（S3）二选一**：
  - B1：自研最小 S3 客户端（SigV4：`hmac` + `sha2`；HTTP：仓库现有
    `reqwest` rustls/ring；`put/get/head/delete` 不需要 XML 解析），从而不引入
    `object_store` / `quick-xml`；需要改方案并补签名测试。
  - B2：C2 也暂停，M4-C 只保留 WebDAV（现有 `reqwest`，无新增依赖、audit 干净）。
- 不建议：`--ignore` 公告、`ssh` 子进程、C 库 SSH。

### 方案 C：接受风险（不推荐）

保持当前版本并记录 audit 例外。这违反 AGENTS.md §8.5/§14，必须由人类维护者明确
签字，且发布门槛不能通过。

---

## 10. 复现

```bash
export RUSTUP_HOME=/tmp/rustup CARGO_HOME=/tmp/cargo PATH=/tmp/cargo/bin:$PATH
export CARGO_TARGET_DIR=/root/code/serverdashboard/target/m4-spike
cd /root/code/serverdashboard/.worktrees/m4-spike/spikes/m4-deps

rustup toolchain install 1.80.0 --profile minimal
cargo +1.80.0 check --locked
cargo +1.80.0 run --locked
cargo +1.80.0 tree --locked
cargo +stable audit --file Cargo.lock   # 预期 10 项（见 §7）
```

可选的真实联网冒烟（本次**未执行**）：

```bash
# S3 / MinIO
M4_SPIKE_S3=1 M4_SPIKE_S3_BUCKET=... M4_SPIKE_S3_ENDPOINT=http://127.0.0.1:9000 \
M4_SPIKE_S3_ACCESS_KEY=... M4_SPIKE_S3_SECRET_KEY=... \
cargo +1.80.0 run --locked

# SFTP（私钥优先；也支持密码）
M4_SPIKE_SFTP=1 M4_SPIKE_SFTP_HOST=... M4_SPIKE_SFTP_USER=... \
M4_SPIKE_SFTP_KEY=/path/to/id_ed25519 M4_SPIKE_SFTP_DIR=/tmp/rustboard-spike \
cargo +1.80.0 run --locked
```

复现 lock 的关键 `cargo update --precise`（顺序不敏感）：

```bash
cargo +1.80.0 update -p home --precise 0.5.9
cargo +1.80.0 update -p idna_adapter --precise 1.2.0
cargo +1.80.0 update -p litemap --precise 0.7.4
cargo +1.80.0 update -p ed25519-dalek --precise 2.1.1
cargo +1.80.0 update -p zeroize --precise 1.8.2
cargo +1.80.0 update -p indexmap --precise 2.11.4
cargo +1.80.0 update -p hyper-rustls --precise 0.27.7
cargo +1.80.0 update -p hyper-util --precise 0.1.20
cargo +1.80.0 update -p tokio --precise 1.53.3
cargo +1.80.0 update -p tokio-util --precise 0.7.19
cargo +1.80.0 update -p quinn --precise 0.11.9
cargo +1.80.0 update -p quinn-proto --precise 0.11.14
cargo +1.80.0 update -p quinn-udp --precise 0.5.14
```
