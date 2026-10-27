# vendored `russh` 偏差记录（P5：#96/#97/#98）

基线：`russh 0.64.1`（crates.io，checksum
`ba61e87b9ec9a39a59a6bbed4c0b8ff7fb07073405b24a767a1f2c8560ac8f58`），
即 `vendor/README.md` 中记录的上游发布包。`Cargo.lock` 中 `russh` 为
`0.64.1`（`[patch.crates-io]` 指向本目录）。

本文件记录在 `src/` 上新增的**最小上游补丁**，用于修复三个已确认的 SFTP/russh
缺陷。除下表列出的文件外，`src/` 其余文件仍与 0.64.1 发布包逐字节一致；manifest
的改动（删除 optional `rsa`）仍按 `vendor/README.md` 维护。

## 1. 上游是否已有修复

2026-10-28 核查结果：**上游没有修复，升级无收益**。

| 检查 | 结果 |
| --- | --- |
| 上游最新 release | `v0.65.0`（2026-10-25），`v0.64.1`（2026-10-05） |
| `v0.64.1..v0.65.0` 的相关文件 | `rx.rs` / `tx.rs` / `negotiation.rs` / `kex/mod.rs` 均无修复（`kex/mod.rs` 仅新增 agent session binding） |
| 上游 `main`（2026-10-28） | `channels/io/rx.rs`、`channels/io/tx.rs`、`negotiation.rs` 与本 patch 前文件**逐字节一致** |
| 相关 open PR | 无（#801/#800/#793/#781 等均与空 Data / 零窗口 / 双向 cipher 无关） |

因此选择 patch `0.64.1`，而不是升级到 `0.65.0`：升级不会改变问题代码，只会引入
agent session binding 等无关变更，增加 SFTP 回归面。

## 2. 变更清单

### #96 空 `CHANNEL_DATA` 被当成 EOF

文件：`src/channels/io/rx.rs`

- `ChannelRx` 新增 `eof: bool`。只有 `ChannelMsg::Eof`、`ChannelMsg::Close`、
  channel 队列结束（`poll_recv` 返回 `None`）才进入 EOF；进入后重复读取保持 EOF。
- 空 `Data` / 匹配的空 `ExtendedData` **不再**返回 `Ready(Ok(()))`（`AsyncRead`
  的 EOF 语义），而是跳过该帧继续 poll。
- 不匹配的 `ExtendedData`、`Success`/`Failure`/`WindowAdjusted` 等非字节流消息：
  旧代码 `wake_by_ref()` + `Pending` 是忙轮询；现在继续 poll 下一帧，队列空时由
  `poll_recv` 正常注册 waker 并返回 `Pending`。
- `buf.remaining() == 0`（零长度读）仍返回 `Ready(Ok(()))`，不消费数据，也不视作 EOF。

单测（`src/channels/io/rx.rs`，`mod tests`）：

- `empty_data_frames_are_skipped_not_eof`
- `empty_data_in_the_middle_of_a_framed_read`（SFTP `read_u32`/`read_exact` 半包）
- `eof_after_data_is_normal_eof`（**sender 保持存活**，只由 Eof 帧结束，5s 超时）
- `close_ends_the_reader_permanently`（**sender 保持存活**，只由 Close 帧结束）
- `zero_length_read_does_not_consume_or_eof`（`remaining()==0` 不消费、不产生 EOF）
- `dropped_sender_is_eof_after_empty_frames`
- `extended_data_routing_skips_non_matching_frames`
- `ignored_messages_do_not_self_wake`（计数 waker：跳帧不得自唤醒）

### #97 窗口归零后断连不唤醒 writer

文件：`src/channels/io/tx.rs`、`src/channels/mod.rs`、
`src/channels/channel_ref.rs`

- `WindowSizeRef` 新增 `closed: Arc<AtomicBool>` 与 `close()`；`close()` 置位后
  用 `notify_waiters()` 唤醒**所有**窗口等待者（窗口更新仍用 `notify_one`）。
- `ChannelRef` 实现 `Drop`：session 丢弃 channel（对端 `CHANNEL_CLOSE`、open
  失败、session 结束）时调用 `window_size.close()`。这是 channel 级关闭的广播点，
  原有 session 代码无需改动。
- `ChannelTx`：
  - 新增字段 `session_closed: BoxedThreadsafeFuture<()>`，内部持有一个
    `Sender` clone 并 await `Sender::closed()`，避免“临时 `Closed` future 被丢弃
    导致 waker 注销、断连永远不唤醒”的问题；
  - `poll_writable` 改为返回 `Poll<io::Result<NonZeroUsize>>`，同时监视
    channel closed 标志、session closed future 与窗口通知，任一关闭即返回
    `BrokenPipe`；
  - `poll_write` / `poll_mk_msg` 透传该错误；
  - 公共 API `ChannelTx::new(...)` 签名保持不变；新增 `pub(crate)
    new_with_window(...)` 供 `ChannelWriteHalf::make_writer_ext` 传入
    `WindowSizeRef`（含 closed 标志）。
- `Channel::into_stream()`（`archive_sftp.rs:360` 的生产路径）改为
  `ChannelTx::new_with_window(...)`：此前仍用 `ChannelTx::new()`，`window_closed`
  为 `None`，零窗口 + 对端 CHANNEL_CLOSE 时 writer 收不到关闭而永久 `Pending`。
- `ChannelWriteHalf::reserve_writable_chunk`（`data`/`data_bytes`/`exec` 等
  异步写路径）：
  - 在释放窗口锁、检查标志前先 `Notified::enable()` + 创建 `Sender::closed()`
    future，再用 `futures::future::select` 同时等待窗口更新与 session 关闭，
    关闭时返回 `Error::IO(BrokenPipe)`；
  - 修复旧代码“只 await `notified()`”导致的零窗口断连永久挂起。

单测：

- `src/channels/io/tx.rs`：
  - `zero_window_receiver_drop_returns_broken_pipe_on_repoll`（验收：drop receiver
    后再次 poll 返回 `BrokenPipe`，不再 `Pending`）
  - `zero_window_receiver_drop_wakes_blocked_writer`
  - `zero_window_channel_close_wakes_blocked_writer`
  - `zero_window_update_still_wakes_blocked_writer`（正常窗口更新不被破坏）
- `src/channels/mod.rs`（走 `ChannelRef::drop` 真实关闭路径）：
  - `into_stream_returns_broken_pipe_after_channel_ref_drop_at_zero_window`
    （生产 `into_stream()` 路径，窗口=0，保持 session 队列存活）
  - `into_stream_returns_broken_pipe_after_channel_ref_drop_with_window`
    （非零窗口：关闭前写入成功，关闭后 `BrokenPipe`）
  - `data_bytes_returns_broken_pipe_after_channel_ref_drop`
  - `data_bytes_returns_broken_pipe_when_channel_closes_at_zero_window`
    （直接 `WindowSizeRef::close()`，覆盖标志/唤醒原语本身）
  - `data_bytes_returns_broken_pipe_when_session_closes_at_zero_window`

### #98 协商丢弃反向 cipher 列表

文件：`src/negotiation.rs`、`src/kex/mod.rs`、`src/kex/{curve25519,ecdh_nistp,
hybrid_mlkem,none,dh/mod}.rs`、`src/client/kex.rs`、`src/server/kex.rs`

- `Names` 新增 `pub server_cipher: cipher::Name`；`cipher` 明确为 client-to-server。
- `read_kex` 分别 decode 并选择 c2s / s2c cipher（RFC 4253 §6.3）。两方向都按
  “client 偏好优先”的既有 `Select` 规则选择；任一方向无交集都返回
  `Error::NoCommonAlgo { kind: Cipher }`，不静默回退。
- MAC 的 `needs_mac` 改为**按方向**判断：一侧 AEAD（如 chacha20-poly1305）不再
  掩盖另一侧对 MAC 的需求；`none` 仍只在对应方向为 AEAD 时允许。
- `KexAlgorithmImplementor::compute_keys`（`pub(crate)` trait）与共享
  `kex::compute_keys` 增加
  `client_cipher` / `server_cipher` 参数；按 `is_server` 映射方向后，分别使用
  各自 cipher 的 `key_len()` / `nonce_len()` 派生 C/D 加密密钥、A/B IV、E/F
  MAC key，再 `make_sealing_key` / `make_opening_key`。
- client/server kex 调用点传入 `names.cipher` + `names.server_cipher`。

单测：

- `src/negotiation.rs`：
  - `ciphers_are_negotiated_per_direction`（双向不同 AES，client/server 协商一致）
  - `default_preferences_keep_single_cipher_when_lists_match`（默认 OpenSSH 同列表）
  - `single_algorithm_peer_is_selected_for_both_directions`（只支持单一算法）
  - `no_common_cipher_in_one_direction_is_explicit_error`（任一方向无交集）
  - `mac_requirement_follows_each_direction_cipher`（按方向 need_mac）
- `src/kex/mod.rs`：
  - `c2s_and_s2c_round_trip_with_different_ciphers`
  - `s2c_receive_key_uses_the_server_cipher`（反向使用 c2s 密钥必须失败）
  - `c2s_send_key_uses_the_client_cipher`

## 3. 测试与运行方式（以及为此做的 manifest/测试基建改动）

`vendor/russh` 原先不是 workspace member（根 `Cargo.toml` 的 `members` 不含
`vendor/*`），因此以下两条命令都不能直接跑：

```text
cargo test --manifest-path vendor/russh/Cargo.toml --locked
  -> error: current package believes it's in a workspace when it's not
cargo test -p russh --lib --locked
  -> error: package `russh` cannot be tested because it requires
     dev-dependencies and is not a member of the workspace
```

按 `vendor/ssh-key` 的同一约定，让本 crate 可独立测试（**均为测试基建改动，
不影响产品依赖图**）：

1. `Cargo.toml` 末尾增加 `[workspace]`，使其成为独立 workspace 根，可直接
   `cargo test --manifest-path vendor/russh/Cargo.toml --locked`。
2. 增加 `[patch.crates-io] ssh-key = { path = "../ssh-key" }`：独立运行时使用同
   仓库的 vendored ssh-key（避免 crates.io 版本重新带回 optional rsa）。
   作为主 workspace 路径依赖时 Cargo 只读取根 manifest 的 patch，此项不生效。
3. 删除 lib 单测/doctest 未使用的 dev-dependencies：
   anyhow / clap / ratatui / shell-escape / rand / russh-sftp / termion /
   tokio-fd（`tests/`、`examples/`、`benches/` 已不在 vendor 包内；保留
   env_logger、tempfile、tokio、tokio-stream 供单测与 doctest 使用）。
4. `default` feature 从上游的 `["flate2", "aws-lc-rs"]` 改为
   `["flate2", "ring"]`：本仓库统一使用纯 Rust 的 ring（产品依赖在
   `crates/rustboard-hub/Cargo.toml` 中显式
   `russh = { default-features = false, features = ["ring"] }`），避免独立测试
   走 aws-lc-rs/cmake 路径。作为路径依赖时该默认值不生效。
5. 增加 `files/id_ed25519.pub`（上游仓库 `files/` 下的 doctest fixture，发布包
   未携带），并把 `keys::load_public_key` 的 doctest 路径从 `../files/...` 改为
   `files/...`，使 `cargo test` 的 doctest 能真实运行（不是 `no_run`/`ignore`）。
6. 新增 `Cargo.lock`（258 包），使 `--locked` 可复现；`Cargo.lock` 与
   `files/id_ed25519.pub` 都是**必须随 patch 一起提交**的新文件（不应被
   `.gitignore` 忽略），否则 `--locked`/doctest 会失败。

验证命令与结果（2026-10-28，russh 0.64.1 + ring）：

```text
cargo test --manifest-path vendor/russh/Cargo.toml --locked
  -> unittests: 217 passed; 0 failed（含 25 个新增测试）
  -> doctests:    3 passed; 0 failed; 8 ignored（上游原有 ```ignore）

cargo test -p rustboard-hub --bin rustboard-hub archive_sftp --locked
  -> 14 passed（`--lib` 变体不存在：hub 只有 bin target）

cargo check --workspace --all-targets --locked
  -> Finished（exit 0）
```

反向验证（mutation，**一次性人工执行、未进 CI**；CI 只跑单测）：分别还原
#96 的空帧 EOF、#97 的关闭检查/`ChannelRef::drop`/`into_stream` 共享标志、
#98 的双向共用 c2s cipher，对应测试均失败：
- #96：3 个测试失败（空帧/半包/ExtendedData 路由）；
- #97：去掉 `impl Drop for ChannelRef` → 3 个 `ChannelRef::drop` 路径测试全部
  失败；`into_stream` 退回 `ChannelTx::new` → 2 个 into_stream 测试失败；
  其余关闭检查 mutation → repoll/断连唤醒测试失败；
- #98：`s2c_receive_key_uses_the_server_cipher` 失败。
确认测试不是恒真。

## 4. 兼容性与回滚

- 三处修复只改 vendor fork 内部代码，不改变根 `Cargo.lock`、不新增产品依赖；
  `vendor/russh/Cargo.lock` 仅用于独立测试。
- manifest 的 `[workspace]` / dev-dependencies / `default` feature 改动只影响
  独立运行 `cargo test --manifest-path vendor/russh/...`；产品构建由
  `crates/rustboard-hub/Cargo.toml` 中的 `default-features = false,
  features = ["ring"]` 决定，行为不变。
- `Names` 虽是 `pub` 结构体，但含私有字段（`strict_kex`；`host_key_is_certificate`
  为 `pub(crate)`），外部代码本来就无法用结构体字面量构造它；新增
  `pub server_cipher` 只是允许外部读取，不属于破坏性变更。
  `KexAlgorithmImplementor` 是 `pub(crate)`，无外部 API 影响。若未来与上游同步，
  这些改动应作为上游 PR 重新提交，而不是长期维护 fork。
- 回滚：`git checkout -- vendor/russh`（并删除未跟踪的
  `vendor/russh/Cargo.lock`、`vendor/russh/PATCHES.md`）即可回到 0.64.1 原始
  代码；本文件可一并删除。
