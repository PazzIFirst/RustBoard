# vendored `ssh-key` 偏差记录（P8：#99/#100/#101/#102）

基线：`ssh-key 0.7.0-rc.11`（crates.io，checksum
`f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3`），
即 `vendor/README.md` 中记录的上游发布包。`Cargo.lock` 中 `ssh-key` 为
`0.7.0-rc.11`（根 `Cargo.toml` 的 `[patch.crates-io]` 指向本目录）。

本文件记录在 `src/` 上新增的**最小上游补丁**，用于修复四个已确认的
`ssh-key` 缺陷。除下表列出的文件外，`src/` 其余文件仍与 0.7.0-rc.11
发布包逐字节一致；manifest 的既有改动（删除 optional `rsa`）仍按
`vendor/README.md` 维护。

## 1. 上游是否已有修复

2026-10-28 核查结果：**上游没有修复，升级无收益**。

| 检查 | 结果 |
| --- | --- |
| crates.io 最新 release | `0.7.0-rc.11`（2026-06-29），没有 rc.12 / 0.7.0 正式版 |
| 上游最新 tag | `ssh-key/v0.7.0-rc.11` |
| 上游 `master`（`8eac39f`，2026-10-17） | 四处代码仍是旧实现：`iqmp.ct_eq(&self.iqmp)`、`line.matches(' ')`、`MIN_SIZE = 32`、直接 `Self { id: ... }` 构造 `AlgorithmName` |
| rc.11 之后的相关提交 | #603（证书文档链接）、#604（证书 CA key 处理）与本 patch 的四个问题无关 |

因此选择 patch `0.7.0-rc.11`，而不是升级：没有可用的已修复版本；上游
`master` 的四个问题仍可从源码直接复现。若未来上游发布修复，应优先升级并
删除本文件与 `vendor/ssh-key/Cargo.lock`，不要长期维护 fork。

## 2. 变更清单

### #99 RSA 私钥 `PartialEq` 漏比较 `iqmp`

文件：`src/private/rsa.rs`

- `RsaPrivateKey::ct_eq` 的第二个比较从 `self.iqmp.ct_eq(&self.iqmp)`
  改为 `self.iqmp.ct_eq(&other.iqmp)`；`RsaKeypair` / `PrivateKey` 的
  `PartialEq` 经此委托后仍保持常量时间比较。
- `d`、`iqmp`、`p`、`q` 任一字段不同都必须不相等；相同字段必须相等。

单测（`src/private/rsa.rs`，`mod tests`）：

- `eq_compares_iqmp`（分别构造 `iqmp=8` 与 `iqmp=9`，断言 `!=`）
- `eq_compares_all_private_components`（d/iqmp/p/q 四项逐一变化，均断言 `!=`）

### #100 证书算法解析器构造非法 `AlgorithmName`

文件：`src/algorithm/name.rs`

- `AlgorithmName::from_certificate_type` 在剥离 `-cert-v01` 后，用
  `Self::new(format!("{name}@{domain}"))` 重新走完整校验，而不是直接构造
  `Self { id }`。
- 空 name（例如 `-cert-v01@example.com`）现在返回 `LabelError`，不会产生
  内部标识为 `@example.com` 的非法值；所有构造成功的值调用
  `certificate_type()` 都不会触发 `expect` panic。
- 同时校验派生 name 的 64 字符上限，并拒绝空白/控制字符等非 printable
  ASCII（RFC 4251 §6）；`from_certificate_type` 的输入与派生值都受此约束。

单测（`src/algorithm/name.rs`，`mod tests`）：

- `from_certificate_type_rejects_empty_name`（含原 panic 输入
  `-cert-v01@example.com`）
- `from_certificate_type_rejects_invalid_identifiers`（非证书标识、空域名、
  多余 `@`、非 ASCII）
- `algorithm_name_rejects_whitespace_and_control_characters`（空格、tab、
  换行、DEL；合法标点仍接受）
- `certificate_type_roundtrip`（合法扩展算法往返）
- `certificate_type_length_boundary`（73 字节上限的合法/超长边界）

### #101 `authorized_keys` 有 options 且无 comment 的合法行解析失败

文件：`src/authorized_keys.rs`

- `Entry::from_str` 不再按空格数量猜测是否有 options。解析顺序改为：
  1. 先按完整 `PublicKey`（含任意空格 comment）解析；
  2. 再尝试把空格/tab 分隔的 keytype、base64、comment 规范化为单空格
     `PublicKey` 后解析；
  3. 最后才把首字段当 options，拆分 options + key。
- `split_options_and_key` 以**引号外**的第一个空格/tab 为分隔符：
  `command="echo hello, world"` 中的空格/逗号不参与切分。
- **注释语义对齐 OpenSSH**：只有首个非空白字符为 `#` 的整行才是注释；
  行内 `#` 属于 key 的 comment（例如 `user#name` 会完整保留），
  `ssh-ed25519 <key>#junk` 会因 base64 非法而拒绝，不会被静默截断成合法 key。
  `Entry::from_str` 也直接拒绝这种行，避免直接调用者把
  `# ssh-ed25519 ...` 误解析成 `config_opts="#"` 的条目。
- **转义对齐 OpenSSH `opt_dequote`**：`\` 只转义 `"`（`\"`），不转义任意字符；
  引号内外规则一致。引号内允许真实 tab；引号内控制字符拒绝；未闭合引号
  （包括以 `\"` 结尾的未闭合值）仍返回错误。
- `ConfigOptsIter` 允许引号内空格、逗号、真实 tab 和 `\"`，拒绝未闭合引号；
  不再把 `command="echo hi"` 判为非法。
- 增加长度/数量上限，避免超长行或海量 options 造成 CPU 放大：
  - 单行 `authorized_keys` 最长 64 KiB；
  - options 字段最长 64 KiB；
  - 最多 1024 个逗号分隔 option；
  - options 扫描保持单次左到右游标扫描。
- 支持 options + 无 comment、options + 有 comment、tab 分隔、无 options、
  空 comment 等合法组合。

单测（`src/authorized_keys.rs`，`mod tests`）：

- `entry_options_without_comment`（#101 的核心回归：`no-pty ssh-ed25519 ...`）
- `entry_options_with_comment`
- `entry_key_without_options`
- `entry_tab_separated_fields`
- `entry_quoted_options`（引号内空格、逗号、`#`、真实 tab、`\"`、`\` 后接
  普通字符、引号外 `\"`）
- `entry_comment_may_contain_hash`（`user#name` 不被截断）
- `entry_rejects_inline_hash_after_base64`（`<key>#junk` 拒绝）
- `entry_rejects_comment_line`（直接 `FromStr` 调用拒绝 `# ...` 行）
- `entry_rejects_invalid_lines`（非法 base64、未引用的 option 空格、未闭合
  引号、只有 options）
- `entry_rejects_oversized_input`（行长度与 options 数量上限）
- `authorized_keys_ignores_blank_and_comment_lines`（含前导空白的 `#` 整行）
- `options_quoted_space_and_escape`
- `options_length_limit`
- `options_unterminated_quote_is_error`
- `options_control_character_inside_quotes_is_error`

### #102 拒绝规范编码不足 32 字节的合法 ECDSA 私钥标量

文件：`src/private/ecdsa.rs`

- `EcdsaPrivateKey::decode` 删除硬编码的 `MIN_SIZE = 32`：短的正数 mpint
  标量按大端左补零到曲线字段宽度后接受。
- 对齐 OpenSSH 的正数 mpint 归一化：**接受并去除多余的 `00` 前导零**
  （包括多个）；只按首个非零字节判断符号，带前导零的 `0x80...` 仍视为正数。
  仍拒绝负值（无前导零且首字节 MSB 为 1）、零值、去零后超过曲线字段宽度
  的载荷。
- 新增曲线阶范围校验：P-256 / P-384 / P-521 的 `1 <= d < n`，零值和
  `d >= n` 均拒绝；未知字段宽度只做零值/编码校验。
- `EcdsaPrivateKey::encode` 同步改为规范 mpint 输出（去掉固定 `SIZE`
  宽度的前导零，仅在需要符号零时补 `0x00`）。否则短标量解码后重新编码
  会补回固定宽度前导零，无法完成 canonical roundtrip。

单测（`src/private/ecdsa.rs`，`mod tests`，`#[cfg(all(test, feature = "alloc"))]`）：

- `decode_short_p256_scalar`（`d = 2^240 + 1` 的 31 字节编码，左补零、
  重新编码为 31 字节、再解码）
- `decode_short_p384_and_p521_scalars`（P-384 47 字节、P-521 65 字节）
- `decode_accepts_redundant_leading_zeros`（单个/多个多余 `00`、固定宽度
  符号零、去零后重编码）
- `decode_rejects_zero_negative_and_out_of_range_scalars`（零值、负值、
  `d = n`、P-521 `d > n`、去零后超宽）
- `decode_openssh_p256_short_scalar_fixture`（31 字节 P-256 OpenSSH 夹具，
  断言私钥 d、曲线、重编码/再解码一致；该夹具为确定性公开测试向量，
  `d = 2^240 + 1`，不是真实凭据）

## 3. 测试与运行方式（以及为此做的 manifest/CI 基建改动）

`vendor/ssh-key` 原先不是根 workspace member，直接运行验收命令会报：

```text
error: current package believes it's in a workspace when it's not
```

为保持 `vendor/README.md` 的独立测试约定，做以下**仅测试基建**改动：

1. `Cargo.toml` 末尾增加空 `[workspace]`，使其成为独立 workspace 根，
   可直接运行 `cargo test --manifest-path vendor/ssh-key/Cargo.toml --locked`。
   作为主 workspace 的 path dependency 时该表不改变依赖图。
2. 新增 `vendor/ssh-key/Cargo.lock`（83 个 package 条目，含本 crate），
   使 `--locked` 可复现；根 `Cargo.lock` 未改，也没有依赖 checksum 变化。
   本 crate 独立解析 crates.io 依赖，不需要 `[patch.crates-io]`。
3. `.github/workflows/ci.yml` 的既有 `test` job 增加三个 step：
   ```yaml
   - name: vendored ssh-key 格式检查
     run: cargo fmt --manifest-path vendor/ssh-key/Cargo.toml -- --check

   - name: vendored ssh-key 单元测试（#99–#102）
     env:
       CARGO_TARGET_DIR: target
     run: cargo test --manifest-path vendor/ssh-key/Cargo.toml --locked

   - name: vendored ssh-key no_std ECDSA 编译
     env:
       CARGO_TARGET_DIR: target
     run: >-
       cargo test
       --manifest-path vendor/ssh-key/Cargo.toml
       --locked
       --no-default-features
       --features ecdsa
       --no-run
   ```
   未新增/修改任何 action，第三方 action 仍全部固定到 SHA。
4. `.gitignore` 已增加 `vendor/*/target/`，独立测试产生的 `target/` 不进入
   版本库；`vendor/ssh-key/target/` 在验证后已删除。

验证命令与结果（2026-10-28）：

```text
cargo test --manifest-path vendor/ssh-key/Cargo.toml --locked
  -> unittests: 59 passed; 0 failed
  -> doctests:    2 passed; 0 failed; 7 ignored

CARGO_TARGET_DIR=target cargo test \
  --manifest-path vendor/ssh-key/Cargo.toml --locked
  -> 同上（CI step 同款环境）

cargo test --manifest-path vendor/ssh-key/Cargo.toml --locked \
  --no-default-features --features ecdsa --no-run
  -> Finished（仅剩上游 manifest 删除 rsa feature 带来的 unexpected_cfgs warning）

cargo fmt --manifest-path vendor/ssh-key/Cargo.toml -- --check
  -> 通过
```

`cargo check --workspace --all-targets --locked` 在“HEAD + 仅本 patch”的干净
worktree 中通过（Finished，23.78s，2026-10-28）。主工作区会随其他并行改动
变化，最终集成后应以完整工作区复跑该命令。

## 4. 兼容性与回滚

- 只改 `vendor/ssh-key` 的解析/比较/编码实现，不改变产品代码、根
  `Cargo.lock` 或产品依赖图。当前 RustBoard SFTP 仅支持 Ed25519 用户私钥，
  不依赖 ECDSA 私钥解析；因此这些库级修复对现有产品路径无行为回归。
- 公开行为变化：
  - `AlgorithmName::from_certificate_type` 对空 name 等非法输入由“成功但
    后续 panic”改为返回 `Err`；`AlgorithmName::new` / certificate type
    均拒绝空白与控制字符；
  - `AuthorizedKeys` 的注释语义对齐 OpenSSH（只跳过整行 `#`），行内 `#`
    保留在 comment 中；引号/转义、真实 tab 与未闭合引号校验同步对齐，
    并增加行/options 长度与数量上限；
  - `EcdsaPrivateKey` 解码接受并归一化多余的 `00` 前导零，仍拒绝负值、
    零值和越界标量；编码输出规范化 mpint。
- manifest 的 `[workspace]`、独立 `Cargo.lock`、CI steps、`.gitignore` 只影响
  独立测试，不改变产品构建。
- 回滚：恢复 0.7.0-rc.11 原始 `src/` 与 manifest 后删除独立 workspace 的
  `Cargo.lock`，并移除 CI 中的三个 vendor step：

  ```bash
  git checkout -- vendor/ssh-key
  rm -f vendor/ssh-key/Cargo.lock vendor/ssh-key/PATCHES.md
  # 手动移除 .github/workflows/ci.yml 中
  # "vendored ssh-key 格式检查"、
  # "vendored ssh-key 单元测试（#99–#102）"、
  # "vendored ssh-key no_std ECDSA 编译" step
  ```

  `vendor/ssh-key/target/` 已被 `.gitignore` 忽略，可直接删除。根
  `Cargo.lock` 无需回滚。

## 5. 重放步骤

1. 从 crates.io 下载并校验基线包：

   ```bash
   VERSION=0.7.0-rc.11
   TMP=$(mktemp -d)
   curl -fsSL "https://crates.io/api/v1/crates/ssh-key/${VERSION}/download" \
     -o "$TMP/ssh-key-${VERSION}.crate"
   sha256sum "$TMP/ssh-key-${VERSION}.crate"
   # 必须为 f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3
   tar -xzf "$TMP/ssh-key-${VERSION}.crate" -C "$TMP"
   ```

2. 用发布包内容替换 `vendor/ssh-key`（保留本文件），删除包内
   `Cargo.lock`、`Cargo.toml.orig`、`.cargo-ok`、`.cargo_vcs_info.json`，
   按 `vendor/README.md` 删除 optional `rsa` 依赖/feature，并加入空
   `[workspace]`。

3. 应用第 2 节的四个文件补丁（`src/private/rsa.rs`、
   `src/algorithm/name.rs`、`src/authorized_keys.rs`、
   `src/private/ecdsa.rs`）。

4. 生成独立 lock 并验证：

   ```bash
   cargo generate-lockfile --manifest-path vendor/ssh-key/Cargo.toml
   cargo test --manifest-path vendor/ssh-key/Cargo.toml --locked
   ```

5. 可选：用下面 2026-10-28 的补丁文件 SHA-256 快照核对重放结果：

   | 文件 | SHA-256 |
   | --- | --- |
   | `Cargo.toml` | `ba05a37c424ffda600f1357a5d097623700b95a431fb12ef20488c581311d4ea` |
   | `Cargo.lock` | `a46859fe729f4549ae048e5ccb5854773f5137b98eb887d27854d34f136e932a` |
   | `src/algorithm/name.rs` | `f2efdbcc040355d797bf565e4474d2bee2f78423f69ed03ddfbcfad94b8c218d` |
   | `src/authorized_keys.rs` | `53fef3d2076ea0f51a07ee373772925d9129a0b93c1e6a0faed4777d77e3de2c` |
   | `src/private/ecdsa.rs` | `58109de0ed7ebfb08f5a085633b8a683099b644036b9a660f0bec8b40d97968f` |
   | `src/private/rsa.rs` | `0590db4a73b832fbcddf5ce305b93bce837b185f667c4a1c03a2b6dd33f15bdd` |

   上游 crate 原始 checksum 为
   `f9a32fae177b74a22aa9c5b01bf7e68b33545be32d9e381e248058d2adc15ce3`。
