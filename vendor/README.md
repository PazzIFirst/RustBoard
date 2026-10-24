# Vendored 依赖

本目录包含两个**只改 manifest**的 vendored crate，用于满足 `cargo audit`
为 0 的要求。所有 `src/` 代码与 crates.io 发布包逐字节一致，SSH 协议实现与
SFTP 相关逻辑完全来自上游。

| 目录 | 包名 | 版本 | 许可证 | 改动 |
| --- | --- | --- | --- | --- |
| `russh/` | `russh` | `0.64.1` | Apache-2.0（`russh/LICENSE`） | 删除 optional `rsa` / `pkcs1` 依赖、`rsa` feature、`default` 中的 `"rsa"` |
| `ssh-key/` | `ssh-key` | `0.7.0-rc.11` | Apache-2.0 OR MIT（两个 LICENSE 均保留） | 删除 optional `rsa` 依赖、`rsa` feature、`crypto` feature 中的 `"rsa"` |

上游：

- <https://github.com/warp-tech/russh>
- <https://github.com/RustCrypto/SSH>（crates.io `ssh-key`）
- crates.io 发布包 checksum：
  - `russh 0.64.1`：`ba61e87b9ec9a39a59a6bbed4c0b8ff7fb07073405b24a767a1f2c8560ac8f58`
  - `ssh-key 0.7.0-rc.11`：`f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3`

## 为什么需要 vendor

`russh 0.64.1` 的 `Cargo.toml` 仍声明 optional `rsa = "=0.10.0-rc.18"` /
`pkcs1`。即使构建不启用 `rsa` feature，Cargo 仍会把 optional 依赖写进
`Cargo.lock`，`cargo audit` 会命中 **RUSTSEC-2023-0071**（rsa Marvin 侧信道，
上游无修复版本）。项目门禁要求 audit 0，且不允许 `--ignore` 静默放行，因此：

- `russh` 删除 `rsa` / `pkcs1` 依赖与 `rsa` feature，并从 `default` 移除 `"rsa"`；
- `ssh-key` 删除 `rsa` 依赖、`rsa` feature 与 `crypto` feature 中的 `"rsa"`；
- 根 `Cargo.toml` 通过 `[patch.crates-io]` 指向本目录。

`russh 0.64.1` 使用稳定的 `elliptic-curve 0.14.1` / `ecdsa 0.17.0` /
`p256/p384/p521 0.14.0`，依赖解析到 **`crypto-bigint 0.7.6`**，同时修复
**RUSTSEC-2026-0387**（`0.7.0-rc.28` 的时序可变性；2026-10-23 披露）。

```toml
[patch.crates-io]
russh = { path = "vendor/russh" }
ssh-key = { path = "vendor/ssh-key" }
```

## 限制：RSA 密钥不再支持

删除 optional `rsa` 后，russh / ssh-key 的 RSA 代码路径不再编译。SFTP 后端
因此明确：

- **用户私钥只支持 ed25519**（不支持 RSA，也不支持 ECDSA 用户私钥）；
  加密私钥不支持（配置没有 passphrase 字段）；密码认证仍可用。
- **主机密钥只支持 ed25519 / ECDSA**；仅提供 RSA 主机密钥的旧服务器会在
  握手阶段失败，不会降级到 RSA。
- **主机指纹只接受 `SHA256:<base64>`**（不接受 MD5 / SHA1），且必须显式配置；
  ECDSA 主机密钥同样用 SHA256 指纹固定。
- **SSH 主机证书统一拒绝**：证书会绕过固定主机公钥指纹的信任模型；只接受
  原始主机公钥（与 v0.4.1 行为一致，旧实现也无法处理证书类型）。
- 私钥文件在 Unix 上必须 group/other 无权限（0600），否则启动 / 连接前固定
  失败。

这样做是为了 `cargo audit` 0，不提供“只用 RSA 的兼容开关”。若部署环境只有
RSA 主机密钥，需要升级服务器或改用 WebDAV / S3 后端，不能通过关闭校验绕过。

## 文件清理

为减小仓库体积，两个目录保留构建所需的 `src/`、`Cargo.toml`、`README.md`
与许可证；删除发布包里的 `Cargo.lock`、`Cargo.toml.orig`、
`.cargo_vcs_info.json`、`.cargo-ok`。`russh` 的 `tests/`、`examples/`、
`benches/` 因 manifest 显式声明保留，不参与本仓库构建。

`ssh-key` 上游 manifest 自带 `[lints]`；`russh` 源码中残留的
`cfg(feature = "rsa")` 在依赖编译时只产生 warning（Cargo cap-lints），
不影响 rustboard 自身的 `-D warnings` 门禁。

## 升级 / 重新生成步骤

1. 从 crates.io 下载目标版本并校验 checksum：

   ```bash
   VERSION=0.64.1
   TMP=$(mktemp -d)
   curl -fsSL "https://crates.io/api/v1/crates/russh/${VERSION}/download" \
     -o "$TMP/russh-${VERSION}.crate"
   sha256sum "$TMP/russh-${VERSION}.crate"
   tar -xzf "$TMP/russh-${VERSION}.crate" -C "$TMP"
   ```

   `ssh-key` 从 `https://crates.io/api/v1/crates/ssh-key/0.7.0-rc.11/download`
   下载，checksum 必须与 `Cargo.lock` 的 registry 条目一致。

2. 用发布包内容替换对应目录（保留本 README）：

   ```bash
   rm -rf vendor/russh && mkdir -p vendor/russh
   cp -a "$TMP/russh-${VERSION}/." vendor/russh/
   rm -f vendor/russh/Cargo.lock vendor/russh/Cargo.toml.orig \
         vendor/russh/.cargo-ok vendor/russh/.cargo_vcs_info.json
   cp /path/to/Apache-2.0.txt vendor/russh/LICENSE
   ```

3. 按上表编辑 manifest；不要改任何 `src/` 文件，否则升级 diff 会失去可审计性。

4. 同步根 `Cargo.toml` 的 `[patch.crates-io]` 与
   `crates/rustboard-hub/Cargo.toml` 中固定的 `russh` 版本，然后：

   ```bash
   cargo update -p russh --precise <version>
   cargo tree -i rsa        # 必须无包
   cargo tree -i crypto-bigint
   cargo audit              # 必须 0
   cargo test --workspace --locked
   ```

5. 在 `CHANGELOG.md` 中记录 vendor 版本、advisory 与 SFTP 真实验证结果。

## 上游修复后

若上游新版本已移除 optional `rsa` 依赖（或 RustSec 提供修复），应优先升级到
上游版本并删除本目录与 `[patch.crates-io]`，不要长期维护 fork。
