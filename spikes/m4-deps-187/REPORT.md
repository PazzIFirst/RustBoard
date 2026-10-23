# M4 冷归档依赖 spike —— Rust 1.87 边界复验（ctutils 修复）

- 日期：2026-10-24
- 分支：`chore/m4-dep-spike`
- 工程：`spikes/m4-deps-187/`（独立 workspace，`resolver = "3"`，不加入根 workspace）
- 目的：验证 Rust 1.87 + `ctutils >= 0.4.4` 后，1.85 报告中的 ctutils 公告是否消失，
  并确认剩余公告是否只有 `rsa`。完整分析见 `../m4-deps-185/REPORT.md`。
- 性质：编译期 spike；未连接真实 S3/SFTP。

## 结果

| 检查项 | 结果 |
|---|---|
| `rustc 1.87.0` / `cargo 1.87.0` | 已安装 |
| `cargo +1.87.0 check --locked` | **通过**（exit 0） |
| `cargo +1.87.0 run --locked` | **通过**（gzip/HMAC/ColdStore） |
| `ctutils` 版本 | **0.4.5**（>= 0.4.4，RUSTSEC-2026-0385 已修复） |
| `Cargo.lock` version | **4** |
| 无 openssl / openssl-sys / cmake / aws-lc-* | **通过**（ring 0.17.14；quick-xml 0.41.0） |
| `cargo +stable audit --file Cargo.lock` | **1 项：rsa 0.10.0-rc.16，medium（5.9）** |

```console
$ cargo +stable audit --file Cargo.lock
Crate:     rsa
Version:   0.10.0-rc.16
Title:     Marvin Attack: potential key recovery through timing sidechannels
ID:        RUSTSEC-2023-0071
Severity:  5.9 (medium)
Solution:  No fixed upgrade is available!
error: 1 vulnerability found!
```

`rsa` 是 russh 0.60.3 的 **optional** 依赖：本工程未启用 `rsa` feature，
`cargo +1.87.0 tree --locked -i rsa` 无输出（未编译），但 Cargo 仍把它写进
`Cargo.lock`，所以 `cargo audit --file Cargo.lock` 会扫描到。

## 结论

1. **Rust 1.87 + ctutils 0.4.5：0 高危成立**（只剩 rsa medium）。
2. **不能达到 audit 0**：rsa 在官方 russh 的 lock 中无法移除，且没有修复版本。
3. **SFTP 要 audit 0**，必须：
   - 使用 Rust >= 1.87（修 ctutils），且
   - fork/patch russh，删除 optional `rsa` 依赖（不是仅关闭 feature），或放弃 C3；
   - **不要**用 `--ignore` 静默掩盖。
4. **C2（S3）不受影响**：object_store 0.14.2 + quick-xml 0.41 + reqwest/rustls/ring
   链路无公告，可在 1.85 或 1.87 继续。

## 复现

```bash
export RUSTUP_HOME=/tmp/rustup CARGO_HOME=/tmp/cargo PATH=/tmp/cargo/bin:$PATH
export CARGO_TARGET_DIR=/root/code/serverdashboard/target/m4-spike-187
cd /root/code/serverdashboard/.worktrees/m4-spike/spikes/m4-deps-187

rustup toolchain install 1.87.0 --profile minimal
cargo +1.87.0 check --locked
cargo +1.87.0 run --locked
cargo +1.87.0 tree --locked
cargo +stable audit --file Cargo.lock   # 预期只有 rsa medium
```
