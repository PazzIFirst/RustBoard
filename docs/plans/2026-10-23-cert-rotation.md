# 方案：证书有效期与自动轮换（v0.2.0 前置）

> 目标里程碑：v0.2.0（与 M2 面板同批发布，本阶段单独打 checkpoint tag）
> 关联：[requirements.md](../requirements.md) §8.1 / §9；[status.md](../status.md) 已知限制 1

## 1. 目标与验收标准

| # | 验收标准 | 验证方式 |
|---|---|---|
| A1 | 新签发的 CA / 服务端 / 客户端证书都有显式 `notBefore`/`notAfter` | 单测解析证书，断言有效期落在预期天数 ±5 分钟 |
| A2 | 有效期天数可配置，默认 CA 3650 天、服务端 365 天、客户端 90 天 | 单测 + `hub init --help` |
| A3 | 服务端证书剩余寿命 ≤ 阈值时，运行中的 hub 自动续签、原子落盘、无需重启即用新证书握手 | 单测 `check_and_renew` + e2e 观察指纹变化 |
| A4 | 已完成纳管的 agent 改用「CA 信任 + 主机名校验」，服务端证书轮换后**无需重新纳管**即可重连 | e2e：轮换后重启 hub，agent 自动恢复上报 |
| A5 | 客户端证书剩余寿命 ≤ 阈值时，agent 在已认证会话内发起轮换，复用原私钥，新证书落盘 | 单测 + e2e `rustboard-agent renew` |
| A6 | 新增帧只在新 agent 主动请求时出现，旧 hub 不会因此断开会话；旧 agent 不受影响 | 单测 + 兼容性说明 |
| A7 | 运维可查：`rustboard-agent cert-info`、`/api/v1/system`、`rustboard-hub rotate-cert` | e2e 断言输出 |
| A8 | 私钥/证书权限不退化（key 0600、cert 0644、目录 0700） | 单测（沿用既有断言） |

**非目标**：ACME、CRL/OCSP、旧客户端证书立即失效（依赖 90 天有效期 + 吊销兜底）、CA 轮换。

## 2. 范围（文件边界）

只允许改：

```
Cargo.toml                                  # 仅 time 依赖（主 Agent 预置）
crates/rustboard-common/Cargo.toml          # + time
crates/rustboard-common/src/tls.rs
crates/rustboard-common/src/config.rs
crates/rustboard-common/src/wire.rs
crates/rustboard-hub/src/main.rs
crates/rustboard-hub/src/cert_rotation.rs   # 新文件
crates/rustboard-agent/src/main.rs
```

禁止改：`crates/rustboard-core/**`、`crates/rustboard-panel/**`、`web/**`、`tests/e2e/**`、`docs/**`、`CHANGELOG.md`、`.github/**`（由主 Agent 或其它路线负责）。

## 3. 接口与数据变更

### 3.1 协议帧（`wire.rs`，`PROTOCOL_VERSION` 保持 2）

```rust
/// agent → hub：请求用当前私钥换一张新客户端证书。
RenewCert { csr_pem: String },
/// hub → agent：签发结果。
CertRenewed { cert_pem: String },
```

- `kind()` 补两个变体；`Debug` 继续只输出变体名。
- 轮换请求只由**已认证会话**发出；hub 只接受 `capabilities`/上下文允许的请求，CN 强制取会话身份。
- 旧 hub 收到未知帧会走「解码失败、跳过」分支，不断连（现有行为，需保留）；旧 agent 永不发送该帧。
- 旧 agent 连新 hub：hub 不主动发 `CertRenewed`，无影响。

### 3.2 配置（`config.rs`，全部带 serde 默认值）

`AgentConfig` 新增：

| 字段 | 默认 | 说明 |
|---|---|---|
| `cert_renew_before_days` | 30 | 客户端证书续签阈值（≥1） |
| `session_max_hours` | 12 | 主动重连周期（±10% 抖动）；0 表示不主动重连 |

`HubConfig` 新增：

| 字段 | 默认 | 说明 |
|---|---|---|
| `ca_validity_days` | 3650 | 仅新建 CA 时生效 |
| `server_cert_validity_days` | 365 | 服务端证书 |
| `client_cert_validity_days` | 90 | agent 客户端证书 |
| `renew_before_days` | 30 | 剩余寿命 ≤ 该值触发续签 |
| `cert_check_interval_secs` | 21600 | 服务端续签检查周期，最小 60（低于 60 会造成无意义的重复签名） |

校验：有效期 1–36500 天；`renew_before_days ≥ 1` 且**必须小于** `server_cert_validity_days`；
`cert_check_interval_secs ≥ 60`；`server_names` 必须非空且每项都能编码为 IP / DNS SAN。

### 3.3 CLI

- `rustboard-hub init` 新增可选 `--ca-days`、`--server-cert-days`、`--client-cert-days`、`--renew-before-days`。
- `rustboard-hub rotate-cert [--config] [--force] [--days N]`：用 CA 立即重签服务端证书并打印新旧指纹；运行中的 hub 需重启才使用（`--force` 用于测试）。
- `rustboard-agent cert-info [--config]`：打印证书路径、CN、notBefore/notAfter、剩余天数。
- `rustboard-agent renew [--config]`：连上 hub 完成一次客户端证书轮换后退出（运维手段 + e2e 入口）。

### 3.4 内部 API（`tls.rs`）

```rust
pub struct CertPolicy { ca_days, server_days, client_days }
pub fn ensure_hub_material(data_dir, sans, policy) -> Result<String>;
pub fn issue_server_cert(ca_key_pem, sans, validity_days) -> Result<(String, String)>;
pub fn sign_client_csr(ca_key_pem, csr_pem, agent_id, validity_days) -> Result<String>;
pub fn make_csr_with_key(key_pem) -> Result<String>;      // 轮换复用私钥
pub fn not_after_unix(pem) -> Result<i64>;
pub fn days_left(pem, now_ms) -> Result<i64>;
pub fn client_config_pinned(...) -> ...;                  // 原 client_config，改名
pub fn client_config_ca(ca_pem, cert_pem, key_pem) -> Result<Arc<ClientConfig>>;
```

`client_config_ca` 用 `RootCertStore::add_parsable_certificates(ca.crt)` + 标准链/主机名校验；
bootstrap（未纳管）仍走指纹钉扎。`ensure_hub_material` 已存在的证书不覆盖。

### 3.5 存储 / 数据库

本阶段**无 schema 变更**。

## 4. 实现要点

### 4.1 hub 服务端续签（`cert_rotation.rs`）

```rust
pub fn spawn_server_renewal(cfg: Arc<HubConfig>, tx: watch::Sender<Arc<rustls::ServerConfig>>);
pub fn check_and_renew(cfg: &HubConfig, tx: &watch::Sender<...>, force: bool, override_days: Option<u32>)
    -> Result<Option<String>>; // Some(new_fingerprint)
```

流程：读 `server.crt` → `days_left` → 不满足阈值则返回 `None`；否则
`issue_server_cert(ca.key, cfg.server_names, days)` → **校验 ca.key 与 ca.crt 配套**、
新证书由 ca.crt 签发、有效期合理、SAN 覆盖 `server_names` → 成对备份旧 key/cert
（`.bak-<毫秒/PID>`，key 0600）→ 原子写 → `tls::server_config` 自检 → `tx.send_replace`。
任一步失败都保留/恢复旧材料，不更新 watch。

启动时 `load_or_repair_tls_config`：只对「server key/cert 不匹配」或「server.key 缺失」
自愈；ca.crt/ca.key 缺失或损坏、server.crt 不可解析等错误直接 actionable fail，
不写 server 文件。server.crt 缺失但 CA 完好时用 CA 直接补签。

`serve_tls` 改为接收 `watch::Receiver<Arc<ServerConfig>>`，每条新连接
`acceptor = TlsAcceptor::from(rx.borrow().clone())`，已建立连接不受影响。

### 4.2 hub 处理客户端续签（`main.rs`）

在 `handle_message` 中：

```
Frame::RenewCert { csr_pem } =>
    - 每个会话最多成功签发 1 次（重复返回 Problem{codes::RATE_LIMITED}，新增该常量）
    - 读取 ca.key；sign_client_csr(ca_key, csr, agent_id /* 会话身份 */, client_days)
    - send CertRenewed { cert_pem }
    - 日志只记 agent_id 与新证书 notAfter，不记 CSR/证书内容
```

CSR 长度上限 16 KiB；超限/解析失败回 `Problem{BAD_FRAME}` 但**不断连**。

### 4.3 agent 侧

1. `connect()`：已纳管 → `client_config_ca(ca.crt, agent.crt, agent.key)`；
   未纳管 → `client_config_pinned(server_fingerprint, None, None)`。
2. 会话收到 Welcome 后调用 `maybe_renew_client_cert()`：
   - `days_left(agent.crt) > cert_renew_before_days` → 跳过；
   - 否则读 `agent.key` → `make_csr_with_key` → 发 `RenewCert` → 等 `CertRenewed`
     （20s 超时；期间处理 Ping）；成功则 `atomic_write(agent.crt, 0644)` 并记日志；
   - 失败只告警，不影响本次会话（证书通常仍有 ≥30 天）。
3. 主循环每 `session_max_hours`（±10% 抖动）主动断开重连，使续签后的证书生效。
4. `renew` / `cert-info` 子命令复用上述逻辑。

### 4.4 `/api/v1/system`

`GET /api/v1/system`（自 v0.2.0 起与其它管理 API 一样要求 Bearer token，`/healthz` 除外）返回：

```json
{ "version": "...", "protocol": 2, "server_time": 0,
  "cert": { "fingerprint": "hex", "not_after": 0, "days_left": 0 } }
```

## 5. 兼容性结论

| 场景 | 结论 |
|---|---|
| 已安装 v0.1 agent + 升级 hub | 旧 agent 仍指纹钉扎；**服务端证书不轮换时不受影响**。仅当执行 `rotate-cert` 或新证书到期续签时旧 agent 会失联，需升级 agent（README/CHANGELOG 写明） |
| v0.2 agent + 旧 hub | bootstrap 不变；启用 CA 信任需 `ca.crt`（enrollment 已有）；续签请求旧 hub 会忽略，agent 告警后继续，不丢数据 |
| 协议 | 仍为 v2；新增帧按需发送，不改变握手 |
| 数据库 | 无变更 |
| 既有证书（notAfter 4096） | 不会触发自动续签，行为同 v0.1 |

## 6. 测试点清单

单测（common/tls）：
- 显式有效期（CA/服务端/客户端）；
- `not_after_unix` / `days_left` 解析；
- CA 签发的客户端证书能被 `WebPkiClientVerifier` 接受；过期证书被拒；
- 轮换 CSR 与既有公钥匹配（同一 key 签两次证书，公钥一致）；
- `client_config_ca` 用错误 CA 时握手校验失败（可用 webpki 单元级验证）。

单测（hub/cert_rotation）：
- `check_and_renew`：未到期不动作；到期后续签、指纹变化、`watch` 收到新配置；
- 续签后 `server.key` 0600 / `server.crt` 0644。

单测（hub/main）：
- `RenewCert` 只按会话身份签发（伪造 CN 无效）；
- 同一会话第二次续签被限流；
- `RenewCert` 帧 roundtrip / Debug 不泄露内容。

e2e（`tests/e2e/cert-rotation.sh`，由测试子 Agent 写）：
1. init + 启动 hub + 纳管 agent，agent 上线；
2. `agent cert-info` 输出 notAfter；`agent renew` 后 notAfter 变大，agent 重启仍在线；
3. 停 hub → `hub rotate-cert --force` → 起 hub，agent 自动重连并继续上报（不重新纳管）；
4. `/api/v1/system` 指纹与磁盘一致。

## 7. 回滚方式

- 新增配置项都有默认值，删除/回退代码后旧配置仍可解析；
- 无数据库迁移，回滚不涉及数据；
- 服务端证书轮换不可逆（旧指纹失效）：`rotate-cert` 与自动续签都会成对备份
  `server.crt` / `server.key`（同后缀），恢复后重启即可回到旧指纹；
  运行中轮换前应先停 hub，避免两个写者竞争。

## 8. 风险

| 风险 | 缓解 |
|---|---|
| CA 信任模式下主机名校验失败导致升级后失联 | agent 连接失败时打印证书 SAN 与错误；README 说明 SAN 必须包含安装命令里的地址；保留 `server_fingerprint` 仅作 bootstrap |
| 服务端续签写文件中途崩溃 | 原子写 + 先写 key 后写 cert，旧配置仍在 watch 中；重启会重新签发 |
| 旧 agent 在服务端轮换后失联 | 明确升级说明；默认 365 天寿命，v0.1 证书实际 4096 年，不会自动触发 |
