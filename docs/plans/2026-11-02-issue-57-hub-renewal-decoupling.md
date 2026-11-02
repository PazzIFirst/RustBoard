# #57 Hub 侧续签与控制应答解耦

## 1. 背景与目标

Issue #57 的 Agent 侧修复（`wait_for_cert_renewed` 在等待续签期间轮询
`control_rx`）已合入 main，但 Hub 侧仍有同一个窗口：

- `handle_session` 的会话循环在收到 `Frame::RenewCert` 后直接
  `handle_renewal(...).await`；
- `handle_renewal` 内部 `spawn_blocking` 读 CA 私钥并签发，`await` 期间会话
  循环不再读取同一条 WebSocket；
- 同连接上 `Frame::ControlResponse` 只能排队，管理 API 的 15 秒 deadline
  独立推进，导致“动作已执行、API 却超时”，可能诱发重复执行。

本阶段目标是**在不改变协议帧、不改变数据库 schema、不改变单发送者约束**的
前提下，让 Hub 在证书签发期间继续处理入站帧，尤其是已派发控制命令的应答。

### 验收标准（可验证）

1. 慢签发（测试中由闸门人为挂起）期间，同连接收到 `ControlResponse` 后，
   对应的 `ControlCommand` oneshot 在 1 秒内收到 `Ok`，不依赖签发完成。
2. 签发完成后仍只由会话循环发送 `CertRenewed` / `Problem`，不出现并发写
   WebSocket。
3. 续签成功后 `RenewState::last_success_ms` 仍被正确更新；失败 / 超时路径仍
   返回与旧实现一致的 `Problem`，不更新成功时间。
4. 同一会话已有续签在途时，再收到 `RenewCert` 返回明确的 `Problem`，不会
   并发启动第二个签发任务；已有任务的结果仍正常返回。
5. 会话在续签在途时关闭（吊销 / 配置变更 / 断连），后台任务被取消或至少
   不向已关闭的 socket 写入；不产生任务 / channel 泄漏。
6. `cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets
   --locked -- -D warnings`、`cargo test --workspace --locked` 全绿。

## 2. 范围

### 涉及文件

- `crates/rustboard-hub/src/main.rs`
  - `handle_session` 会话循环：把 `RenewCert` 处理改为“启动独立任务 + 结果
    回到 select”。
  - `handle_renewal`：去掉“必须在会话循环内 await”的调用约定；保留签发与
    限流语义，返回结果帧。
  - 测试模块：新增 `#[cfg(test)]` 慢签发闸门和会话级回归测试。
- `crates/rustboard-hub/Cargo.toml`
  - 仅新增 dev-dependency `tokio-tungstenite`（workspace 已有依赖），用于
    在 Rust 测试中连接本地 axum WebSocket 测试路由。
- `CHANGELOG.md`、`docs/status.md`、版本号：发布阶段处理，不在编码提交里做。

### 不涉及

- 协议帧定义、Agent 代码、数据库 schema、管理 API 参数。
- 证书格式、CA 文件布局、续签冷却窗口（仍为每 agent 10 分钟）。
- 管理 API 的超时语义（仍由 API 侧独立 deadline 控制）。

## 3. 接口与数据变更

### 3.1 无外部接口变更

`Frame::RenewCert` / `Frame::CertRenewed` / `Frame::Problem` 的 wire 格式不变。
Agent 不需要升级；旧 Agent 若在续签期间收到 `Problem(RATE_LIMITED)`（仅在同
会话重复续签时）会按既有失败路径处理。

### 3.2 内部结构

新增（仅 Hub 内部）：

```rust
struct RenewalCompletion {
    frame: Frame,
    renew: RenewState,
}
```

- 后台任务只做“限流 + 读 CA + 签发”，通过 `mpsc::Sender` 把
  `RenewalCompletion` 交回会话循环。
- 会话循环仍是唯一 WebSocket 写入者。
- 每个续签任务使用独立的一次性 channel；会话只保留 `Option<Receiver>`，任务
  结束（成功、失败或 panic）后 receiver 必然关闭。
- `RenewState` 增加 `Clone, Copy`（仅含一个 `i64`），任务返回更新后的副本；
  会话收到结果后覆盖本地值。

### 3.3 测试专用闸门

在 `RenewalContext` 下增加 `#[cfg(test)]` 字段：

```rust
#[cfg(test)]
struct RenewalTestGate {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
```

`handle_renewal` 在 `spawn_blocking` 前（仅测试构建）：

```rust
if let Some(gate) = ctx.test_gate() {
    gate.started.notify_one();
    gate.release.notified().await;
}
```

生产构建不包含该字段、分支和等待。测试通过 `set_test_gate` 安装闸门，从而
确定性地制造“签发在途”窗口，不依赖 sleep 竞态。

## 4. 兼容性影响

- **协议**：无变化；protocol v2 不变。
- **数据库**：无变化；schema v9 不变。
- **已安装 Agent**：无需升级。Hub 行为变化仅是续签期间继续读帧。
- **旧数据**：无影响。
- **并发**：同一会话最多一个在途续签任务；任务数量上限与会话数相同，仍受
  每 agent 10 分钟冷却和 4096 条冷却表上限约束。
- **回滚**：回退本提交即可；无迁移、无持久化状态。

## 5. 实现要点

1. `handle_session` 增加：
   - `renewal_rx: Option<mpsc::Receiver<RenewalCompletion>>`
   - `renewal_task: Option<RenewalTask>`（`Drop` 时 `abort` 未完成任务）
2. `Frame::RenewCert` 分支：
   - 若 `renewal_rx.is_some()`：回 `Problem`（固定错误码，建议
     `RATE_LIMITED`，文案“续签正在进行，请稍后再试”），不启动第二个任务。
   - 否则创建一次性 channel，`tokio::spawn` 调用 `handle_renewal`，任务结束
     发送 `RenewalCompletion`。
3. `select!` 增加 `RenewalDone(Option<RenewalCompletion>)` 分支：
   - 收到 `Some`：更新 `renew`；若帧是 `CertRenewed` 则 `mark_seen`；再
     `send_frame`。
   - 收到 `None`：任务在发送前结束 / panic，记 error 并回
     `Problem(INTERNAL, "hub 无法签发证书")`，与旧 JoinError 路径一致。
   - 清空 receiver 与任务句柄。
4. `handle_renewal` 去掉对 `&mut WebSocket` 的任何依赖（当前本来就没有）；
   保留现有签名与日志，只由任务调用。
5. 续签期间 `ControlResponse` 仍走 `handle_message` 的
   `control.complete(response)`；`Ping` / `Pong` / `Batch` 也继续处理。
6. 会话退出时 `RenewalTask` 的 `Drop` 调用 `abort()`；阻塞中的 `spawn_blocking`
   本身不可取消，但不再有等待结果的任务或 socket 写入。

## 6. 测试点清单

### 6.1 会话级回归（新增）

用本地 axum WebSocket 测试路由 + `tokio-tungstenite` 客户端：

1. 建立会话，收到 `Welcome`。
2. 通过 `SessionRegistry::control_sender` 投递 `ControlCommand`。
3. 客户端收到 `ControlRequest`，暂不回复。
4. 安装测试闸门，发送 `RenewCert`，等待 `started`。
5. 客户端发送 `ControlResponse`。
6. 断言 `ControlCommand` 的 oneshot 在 1 秒内得到 `Ok`（旧实现会超过）。
7. `release` 闸门，断言客户端随后收到 `CertRenewed`。
8. 断言会话仍可正常处理后续帧 / 关闭。

### 6.2 边界与错误路径

- 续签在途时第二个 `RenewCert`：收到固定 `Problem`，第一个任务仍完成。
- 续签失败（坏 CSR / CA 不配套）：返回 `Problem`，`last_success_ms` 不更新。
- 续签任务在发送前 panic / 中止：会话回 `INTERNAL`，不挂死。
- 会话在续签在途时被吊销 / 配置变更：任务被 abort，socket 不再收到续签帧。
- 会话空闲超时不被续签等待错误延长。

### 6.3 既有回归

- 现有 `handle_renewal` 单元测试（冷却、CN 强制、CSR 上限、失败）全部保留。
- 现有控制面测试 `control::tests` 全部保留。
- Agent 侧 #57 五个续签期间控制应答测试全部保留。

## 7. 质量门禁与流程

1. 编码子 Agent 实现生产代码；只改 `main.rs` 与 `Cargo.toml`。
2. 测试子 Agent 在编码完成后，根据本方案与公开接口添加会话级测试；
   不参考生产实现细节。
3. 主 Agent 集成后运行：
   - `cargo fmt --all -- --check`
   - `cargo clippy --workspace --all-targets --locked -- -D warnings`
   - `cargo test --workspace --locked`
   - `cargo audit`
4. 独立只读评审子 Agent 复核：单发送者、任务取消、channel 生命周期、重复
   续签、错误路径、测试是否真正覆盖验收点。
5. 修复后重跑全部门禁；严重问题由新的评审子 Agent 复审。
6. 发布 `v1.0.2` 前补压力 / 故障注入的最小回归（续签 + 控制并发），并按
   `CHANGELOG` 归档、tag、Release、镜像流程执行。

## 8. 回滚方式

- 代码回滚：`git revert <commit>`；无数据库迁移、无协议变更。
- 运行时回滚：直接换回 `v1.0.1` 二进制；数据目录兼容。
- 若新逻辑导致异常，可先禁用后台任务路径回到旧行为（不推荐长期保留），但
  发布版本必须包含完整修复。

## 9. 风险与对策

| 风险 | 对策 |
|---|---|
| 后台任务在会话关闭后继续签发 | `RenewalTask::Drop` abort；签发本身在 blocking 线程不可取消，但不会写 socket |
| 并发写 WebSocket | 任务只发 channel，所有写仍在会话循环 |
| 续签结果丢失 / task panic | 一次性 channel 关闭被当作 `None`，回 `INTERNAL` |
| 恶意重复 RenewCert 放大 | 在途时只回一个固定 `Problem`，不启动第二个任务；冷却窗口仍生效 |
| 测试依赖真实时间 | 使用 `Notify` 闸门，不用 sleep 判定 |
| 测试引入新依赖 | 仅 dev-dependency，复用 workspace 已锁定的 `tokio-tungstenite` |

## 10. 执行结果（2026-11-02）

- 生产实现：Hub 续签改为后台任务，结果经一次性 `mpsc` 回到会话循环；
  `RenewalTask::Drop` abort；在途重复 `RenewCert` 固定 `RATE_LIMITED`；
  测试闸门仅 `#[cfg(test)]`。
- 新增 4 条真实本地 WebSocket 会话回归：
  `v102_control_response_handled_while_renewal_in_flight`、
  `v102_duplicate_renew_rejected_while_first_in_flight`、
  `v102_bad_csr_returns_problem_and_session_continues`、
  `v102_revoke_during_renewal_closes_session_without_hang`。
- 门禁：fmt / clippy 通过；`cargo test --workspace --locked`
  1652 passed / 0 failed / 5 ignored；`cargo test -p rustboard-hub --locked
  v102_` 4 passed；`cargo audit` 仅既有 yanked 允许项；`tests/e2e/v032.sh`
  66/66 PASS。
- 独立评审：未发现严重问题；采纳其失败路径、无第二任务、状态单一判据、
  `dead_code` 清理、测试入口注释与取消计数语义建议。
- 发布：`v1.0.2` tag / GitHub Release / 镜像 digest 在发布完成后补记录。

## 11. 取消计数语义

`handle_renewal` 在任务开始时即调用 `RenewGuard::begin_attempt` 写入冷却表。
会话提前退出导致 `RenewalTask::Drop` abort 时，这次尝试**仍然计数**：agent
重连后 10 分钟内续签会收到 `RATE_LIMITED`。这是有意的防刷语义（取消不退
名额），不是任务/状态泄漏；如需改变，必须同时评估签名放大风险。
