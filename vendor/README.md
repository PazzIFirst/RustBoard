# Vendored 依赖

本目录包含两个**只改 manifest**的 vendored crate，用于满足 M4-C3 的
`cargo audit` 为 0 的要求。所有 `src/` 代码与 crates.io 发布包逐字节一致，
SSH 协议实现与 SFTP 相关逻辑完全来自上游。

| 目录 | 包名 | 版本 | 许可证 | 改动 |
| --- | --- | --- | --- | --- |
| `russh/` | `russh` | `0.60.3` | Apache-2.0（`russh/LICENSE`） | 删除 optional `rsa` 依赖、`rsa` feature、`default` 中的 `"rsa"`；增加 `[lints]` 关闭第三方包 warning |
| `ssh-key/` | `internal-russh-forked-ssh-key` | `0.6.18+upstream-0.6.7` | Apache-2.0 OR MIT（两个 LICENSE 均保留） | 删除 optional `rsa` 依赖、`rsa` / `rsa-sha1` feature、`crypto` feature 中的 `"rsa"`、`std` feature 中的弱引用 `"rsa?/std"`；增加 `[lints]` |

`[lints]` 只关闭这两个第三方包自身的 warning（新版 rustc 对源码里残留的
`cfg(feature = "rsa")` 报 `unexpected_cfgs`，以及未启用分支产生的
`unused` / `dead_code`）。它不会影响 rustboard 代码的 `-D warnings` 门禁。

上游：

- <https://github.com/warp-tech/russh>
- <https://github.com/Eugeny/RustCrypto-SSH/>（`ssh-key` fork；russh 将其
  重命名为 `ssh-key` 依赖）
- crates.io 发布包 checksum：
  - `russh 0.60.3`：`324b92f459d3e42da294e14e8eb150d2215fcfb7c966838bc1127cd68bc05a0d`
  - `internal-russh-forked-ssh-key 0.6.18+upstream-0.6.7`：`25f8a978272e3cbdf4768f7363eb1c8e1e6ba63c52a3ed05e29e222da4aec7cb`

## 为什么需要两个 vendor

`russh 0.60.3` 的 `Cargo.toml` 声明了 optional `rsa = "=0.10.0-rc.16"`。
即使不启用该 feature、rsa 不进入编译图，Cargo 仍会把它写进 `Cargo.lock`，
`cargo audit` 会命中 **RUSTSEC-2023-0071**（rsa Marvin 侧信道，截至 vendor
时上游无修复版本）。项目门禁要求 audit 0，且不允许 `--ignore` 静默放行。

只在 `russh` 里删掉 `rsa` **还不够**：它的依赖
`internal-russh-forked-ssh-key` 在已启用的 `std` feature 中带有弱引用
`rsa?/std`。Cargo 解析 lockfile 时会把弱引用的 optional 依赖也写进
`Cargo.lock`，因此 audit 仍会报告 `rsa`。所以第二个 patch 只做一件事：
从 fork 的 `std` feature 删除 `"rsa?/std"`，并同时删除不再可用的
`rsa` / `rsa-sha1` feature 与依赖声明。

根 `Cargo.toml`：

```toml
[patch.crates-io]
russh = { path = "vendor/russh" }
internal-russh-forked-ssh-key = { path = "vendor/ssh-key" }
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
- 私钥文件在 Unix 上必须 group/other 无权限（0600），否则启动 / 连接前固定
  失败。

这样做是为了 `cargo audit` 0，不提供“只用 RSA 的兼容开关”。若部署环境只有
RSA 主机密钥，需要升级服务器或改用 WebDAV / S3 后端，不能通过关闭校验绕过。

## 文件清理

为减小仓库体积，两个目录都只保留构建所需的 `src/`、`Cargo.toml`、`README.md`
与许可证；删除了发布包里的 `Cargo.lock`、`Cargo.toml.orig`、`.cargo-ok`、
`.cargo_vcs_info.json`、`tests/`、`examples/`、`benches/`、`CHANGELOG.md`。
这些文件不参与本仓库构建。`ssh-key` 的 `Cargo.toml` 同时移除了指向已删除
`tests/` 的 `[[test]]` 段。

## 升级 / 重新生成步骤

升级任一 crate 或重新生成 vendor 时：

1. 从 crates.io 下载目标版本并校验 checksum（应与 `Cargo.lock` 的
   registry 条目、或上表 checksum 一致）：

   ```bash
   VERSION=0.60.3
   TMP=$(mktemp -d)
   curl -fsSL "https://crates.io/api/v1/crates/russh/${VERSION}/download" \
     -o "$TMP/russh-${VERSION}.crate"
   sha256sum "$TMP/russh-${VERSION}.crate"
   tar -xzf "$TMP/russh-${VERSION}.crate" -C "$TMP"
   ```

   `ssh-key` 同理：`https://crates.io/api/v1/crates/internal-russh-forked-ssh-key/0.6.18+upstream-0.6.7/download`。

2. 用发布包内容替换对应目录（保留本 README）：

   ```bash
   rm -rf vendor/russh && mkdir -p vendor/russh
   cp -a "$TMP/russh-${VERSION}/." vendor/russh/
   rm -rf vendor/russh/{tests,examples,benches} \
          vendor/russh/Cargo.lock vendor/russh/Cargo.toml.orig \
          vendor/russh/.cargo-ok vendor/russh/.cargo_vcs_info.json
   cp /path/to/Apache-2.0.txt vendor/russh/LICENSE
   ```

3. 按上表逐项编辑 manifest；不要改任何 `src/` 文件，否则升级 diff 会失去
   可审计性。

4. 同步根 `Cargo.toml` 的 `[patch.crates-io]` 与
   `crates/rustboard-hub/Cargo.toml` 中固定的 `russh` 版本，然后：

   ```bash
   cargo update -p russh --precise <version>
   cargo tree -i rsa        # 必须无输出
   cargo audit              # 必须 0
   cargo test --workspace --locked
   ```

5. 在 `CHANGELOG.md` 的 `[Unreleased]` 中记录 vendor 版本与改动原因。

## 上游修复后

若上游新版本已移除 optional `rsa` 依赖（或 RustSec 提供修复），应优先升级到
上游版本并删除本目录与 `[patch.crates-io]`，不要长期维护 fork。
