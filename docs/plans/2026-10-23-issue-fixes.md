# 2026-10-23 Issue #1–#8 修复方案

> 状态：实施中　｜　对应 issue：#1 #2 #3 #4 #5 #6 #7 #8
> 流程：AGENTS.md §2 → §3 → §4

## 1. 目标

修复 review 提出的 8 个缺陷，核心是把「身份」从应用层自证改成传输层强制：

- 正式会话必须持有 hub CA 签发的客户端证书，且证书 CN 必须等于 Hello 的 `agent_id`
- 批次身份一律以会话身份为准，不信任报文里的 `agent_id`
- 吊销对已建立连接立即生效
- 缓冲 ACK、存储去重都以 `(agent_id, epoch)` 为边界
- 敏感文件从创建第一刻就是 0600

## 2. 范围与文件

| Issue | 主要文件 |
|---|---|
| #1 #2 #5 #7 | `crates/rustboard-hub/src/main.rs`、`crates/rustboard-common/src/tls.rs`、`crates/rustboard-hub/Cargo.toml` |
| #3 | `crates/rustboard-core/src/buffer.rs`、`crates/rustboard-common/src/wire.rs`、`crates/rustboard-agent/src/main.rs` |
| #4 | `crates/rustboard-core/src/storage/{mod,sqlite}.rs` |
| #6 | 新增 `crates/rustboard-common/src/fsutil.rs`、`error.rs`、`tls.rs`、`agent/src/main.rs` |
| #8 | `crates/rustboard-core/src/collect/disk.rs` |

## 3. 关键设计

### D1 传输层：自己接管 TLS accept（#2 的前置）

axum-server 不暴露对端证书，无法做 CN 绑定。改为：

```rust
let tls = TlsAcceptor::from(server_config).accept(tcp).await?;
let cn = tls.get_ref().1.peer_certificates()
    .and_then(|certs| extract_common_name(&certs[0]));
// 把 cn 放进每个请求的 extensions
```

- 依赖：`hyper`、`hyper-util`、`tower`、`tokio-rustls`、`x509-parser`；移除 `axum-server`
- 用 `hyper_util::server::conn::auto::Builder` + `TowerToHyperService` 驱动现有 axum Router
- 新增 `PeerIdentity(Option<String>)` 扩展，`/agent/ws` 处理函数用 `Extension` 取

### D2 会话身份绑定（#1 #2）

- 无客户端证书（`cn == None`）→ **只允许** `Enroll`，其它帧一律 `Problem` 并关闭
- 有证书 → Hello 的 `agent_id` 必须等于 cn，否则拒绝
- 会话内的 `Batch`：`batch.agent_id != 会话 agent_id` → 拒绝且不 ACK
- 入库时使用会话身份，`hub-self` 只能由本地采集写入，网络侧不可声明

### D3 连接注册表 + 吊销（#5 #7）

```rust
struct SessionRegistry { inner: Mutex<HashMap<String, SessionEntry>> }
struct SessionEntry { conn_id: u64, shutdown: watch::Sender<()> }
```

- 会话注册；`Drop` guard 注销（对照 conn_id，旧连接不覆盖新连接）
- 吊销传播：hub 内每 2s 轮询 `revoked_agents`，对已连接的 agent 发 shutdown
- 原子性：`insert_batch` 在同一个事务里检查 `revoked_agents`，命中则回滚并返回 `Rejected`
- 心跳：`recv` 设 45s 超时；收到 Batch/Ping 时更新 `last_seen_at`
- 状态：只有注册表里的当前连接掉线才置 `offline`；`revoked` 永不被覆盖

### D4 缓冲 ACK 按 epoch（#3）

- `Pending { epoch, seq, offset, len }`
- `DiskBuffer::ack(epoch, seq)`：只推进队首同 epoch 且 `seq <=` 的参数，遇到 epoch 变化立即停止
- `Frame::Ack { epoch, seq }`，hub 回传被确认批次的 epoch

### D5 存储按 epoch 去重（#4）

- `ingest_state` 改为 `PRIMARY KEY (agent_id, epoch)`，每 epoch 独立 `last_seq`
- `PRAGMA user_version` 迁移：v1 → v2 建新表、搬数据、改名
- `insert_batch` 返回值改为：

```rust
pub enum IngestOutcome {
    Inserted { inserted: usize },
    Duplicate,
    Rejected(RejectReason),   // Revoked
}
```

### D6 敏感文件原子写（#6）

新增 `fsutil`：

```rust
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> io::Result<()>
pub fn ensure_dir(path: &Path, mode: u32) -> io::Result<()>
```

- 同目录临时文件 + `OpenOptions::mode(0o600)` + `rename` 原子替换
- 配置（含 token）、私钥、secret → 0600；证书 → 0644；数据目录 → 0700
- 已存在且权限更宽的文件，写入时收紧

### D7 diskstats 解析（#8）

- 解析函数 `parse_diskstats(&str) -> HashMap<String, IoCounters>`，可注入文本做单测
- `IoCounters` 增加 `read_ticks`(f[6])、`write_ticks`(f[10])
- `await_ms = (Δread_ticks + Δwrite_ticks) / (Δread_ops + Δwrite_ops)`；`util` 继续用 `io_ticks`

## 4. 兼容性

| 变更 | 影响 | 处理 |
|---|---|---|
| `Frame::Ack` 增 `epoch` | 协议不兼容 | 尚未发布 v0.1.0，允许破坏性变更；CHANGELOG 标注 |
| `ingest_state` 表结构 | 已有库 | `user_version` 迁移，保留旧数据 |
| 移除 axum-server | 无外部行为变化 | 端口、路径、TLS 行为保持不变 |
| 正式会话强制客户端证书 | 已纳管 agent 本来就带证书 | 无影响；仅阻止无证书连接 |

## 5. 测试点

- #1：A 会话提交 B / hub-self 的批次 → 被拒、不 ACK、B 的样本数不变
- #2：无客户端证书发 Hello → 拒绝；CN≠agent_id → 拒绝；正常证书 → 通过
- #3：epoch A 高 seq ACK 不删除 epoch B 低 seq；交叉重传全保留
- #4：A→B→A 重放不增加样本；旧 epoch 不覆盖新 epoch 状态
- #5：吊销后既有连接无法写入；重新连接被拒；其他 agent 不受影响
- #6：umask 0022 下配置文件 0600；私钥创建即 0600；目录 0700
- #7：RST / 超时 / 发送失败都置 offline；旧连接关闭不覆盖新连接
- #8：`(1000+500, 100+50) → (1500+1000, 110+60)` 期望 await = 50ms

## 6. 回滚

按 issue 独立提交，任一回归可单独 revert；协议变更与存储迁移集中在单独提交，回滚时需同时回滚 agent 与 hub。

---

## 7. Hub 改造细节（#1 #2 #5 #7）

### 7.1 依赖

```toml
hyper = { version = "1", features = ["server", "http1", "http2"] }
hyper-util = { version = "0.1", features = ["server", "server-auto", "tokio", "service"] }
tower = { version = "0.5", features = ["util"] }
tokio-rustls = "0.26"
x509-parser = "0.16"
# 移除 axum-server
```

### 7.2 自建 TLS accept

```rust
async fn serve_tls(app: Router, addr: SocketAddr, tls: Arc<ServerConfig>) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (tcp, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let Ok(stream) = acceptor.accept(tcp).await else { return };
            let cn = stream.get_ref().1.peer_certificates()
                .and_then(|certs| peer_common_name(&certs[0]));
            let svc = tower::service_fn(move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(PeerIdentity(cn.clone()));
                let app = app.clone();
                async move { app.oneshot(req).await.map_err(|e| match e {}) }
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(svc))
                .await;
        });
    }
}
```

`peer_common_name` 用 `x509_parser::parse_x509_certificate` + `cert.subject().iter_common_name()`。

### 7.3 身份绑定

- `agent_ws(ws, Extension(peer): Extension<PeerIdentity>, State(state))`
- `dispatch` 收到首帧后：
  - `Enroll`：仅当 `peer.0.is_none()` 时允许；有证书的连接不允许再 enroll
  - `Hello`：仅当 `Some(cn)` 且 `cn == hello.agent_id` 时允许
- 会话循环：`batch.agent_id != session_agent` → `Problem` + 关闭，不 ACK
- `hub-self` 在 `dispatch` 阶段直接拒绝网络侧声明

### 7.4 连接注册表

```rust
struct SessionRegistry { inner: Mutex<HashMap<String, SessionEntry>> }
struct SessionEntry { conn_id: u64, shutdown: watch::Sender<()> }

impl SessionRegistry {
    fn register(&self, agent_id: &str) -> (u64, watch::Receiver<()>);
    fn unregister(&self, agent_id: &str, conn_id: u64) -> bool; // 仅当前连接返回 true
    fn shutdown(&self, agent_id: &str);
}
```

会话循环用 `tokio::select!` 同时监听 `shutdown.changed()` 与 `socket.recv()`。
收到 shutdown → 记 `Problem{code:"revoked"}` 后关闭。

### 7.5 吊销传播

- hub 启动一个 2s 轮询任务：`SELECT agent_id FROM revoked_agents`
- 对每个被吊销且当前在注册表中的 agent 调 `registry.shutdown(id)`
- 批次入库的原子检查在 storage 层（#4 已实现 `Rejected(Revoked)`），hub 收到后关闭连接
- CLI `agent revoke` 仍只写库；运行中的 hub 在 ≤2s 内感知

### 7.6 心跳与状态

- `socket.recv()` 外层 `tokio::time::timeout(Duration::from_secs(45), ...)`
- 收到 Batch / Ping / Pong 都 `mark_seen(agent_id, now_ms())`
- 会话结束时：`if registry.unregister(agent_id, conn_id) { set_status("offline") }`
- `revoked` 状态保持不变（`set_status` 已有 SQL 保护）

### 7.7 验收测试

1. 无证书连接发 Hello → 收不到 Welcome
2. 用 A 的证书 + A 的 secret 发 `agent_id=B` 的 Hello → 拒绝
3. A 连接中提交 `batch.agent_id=B` → Problem、无 ACK、B 的计数不变
4. 吊销后用同一条连接发 Batch → 被拒；≤2s 内连接被关闭
5. 同一 agent 两条连接，关闭旧的 → 状态仍 online；关闭新的 → offline
6. 静默 45s 无帧 → 连接关闭并置 offline
