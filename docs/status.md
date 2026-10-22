# 实现进度

> 最后更新：2026-10-23　｜　对应需求稿：[requirements.md](requirements.md)

## 总体

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M1 骨架与闭环 | 🟢 基本完成 | 采集→缓冲→TLS 上报→入库→查询；enrollment + mTLS + 吊销已通 |
| M2 面板 | ⬜ 未开始 | 仅占位页 |
| M3 控制面 | ⬜ 未开始 | |
| M4 告警与归档 | ⬜ 未开始 | |
| M5 安装与交付 | ⬜ 未开始 | |

## M1 明细

已完成：

- [x] Cargo workspace 与 5 个 crate 的边界划分
- [x] 线协议：MessagePack 帧（Enroll / Enrolled / Hello / Welcome / Batch / Ack / Ping / Pong / Problem）
- [x] 采集器：CPU（含每核可选、load average）、内存/Swap、磁盘容量与 inode、
      磁盘 IO（含 await / util 差分）、网卡（8 项计数器）、系统辅助指标
- [x] 本地磁盘缓冲：追加日志 + 已确认偏移持久化 + 超限丢弃最旧 + 损坏尾部自愈
- [x] SQLite 存储：WAL、批量事务、`(agent_id, epoch, seq)` 幂等
- [x] hub 本机采集（agent_id = `hub-self`，本地直写，不走网络）
- [x] 只读 API：`/healthz`、`/api/v1/agents`、`/api/v1/series`
- [x] agent 断线指数退避重连；新数据即时唤醒上传（Notify，不再等心跳）
- [x] **TLS 1.3 + 私有 CA**：hub 自签 CA，签发服务端与客户端证书
- [x] **证书指纹钉扎**：agent 首次连接严格比对 SHA-256 指纹，不符立即拒绝
- [x] **一次性 enrollment**：`agent add` 生成 token（默认 30 分钟、单次使用），
      CSR 签发 90 天客户端证书，下发每机独立 secret
- [x] **mTLS**：客户端证书校验 + Hello 中的 secret 二次身份绑定
- [x] **吊销**：`agent revoke` 清除 secret、状态置为 revoked，重连被拒
- [x] **离线检测**：连接断开即置 offline（revoked 状态不被覆盖）
- [x] 单元测试 14 个，端到端联调通过（含错误指纹拒绝、吊销生效）

未完成（M1 收尾 / 后续）：

- [ ] 证书自动轮换（客户端证书 90 天，需在到期前换发）
- [ ] 服务端证书轮换与指纹变更流程（目前重建 CA 会使全部 agent 失效）
- [ ] ACME：域名证书 / 公网 IP 6 天短证书（M5，需公网可达与 80/443 自检）
- [ ] hub 侧计数器结转（epoch 切换时累计流量归集）
- [ ] 心跳超时判定（目前只依赖 TCP 断开）
- [ ] 采样间隔动态下发（Welcome 已下发值，agent 尚未应用）
- [ ] PostgreSQL 存储实现
- [ ] 降采样与保留期任务
- [ ] 结构化日志与 `RUST_LOG` 文档

## 已验证（2026-10-23，本机）

- `rustboard-hub init` 生成 CA + 服务端证书并打印指纹；
- `agent add` 生成一次性 token 与可直接粘贴的安装命令；
- agent 首次连接自动 enrollment，写入 `agent.crt/key/secret/ca.crt`（0600）后立即重连；
- 重连后 mTLS 握手成功，5 秒内开始上报，`net.rx_bytes` 带 `if=eth0` 正常入库；
- **错误指纹**：agent 收到“服务端证书指纹不匹配”，未获得证书，持续退避重试；
- **吊销**：revoke 后 agent 重启连接被拒（`revoked`），状态保持 revoked；
- 单元测试 14/14 通过。

## 已知限制

1. **证书不会自动轮换**：客户端证书 90 天有效，到期需重新 enrollment；
   服务端证书 10 年，但重建 CA 会导致全部 agent 失联（指纹变了）。
2. 身份绑定依赖 Hello 里的 `agent_secret`，不是从 mTLS 证书里取 CN。
   已纳管机器互冒名需要同时拿到对方的 secret，风险可控但不如 CN 绑定严格。
3. 采集器首次调用只建立基线、不上报（CPU/磁盘 IO 需要差分）。
4. SQLite 单连接 + 全局锁，写入吞吐够用但不是最终形态；PG 实现待补。
5. 面板是静态占位页。
6. 管理 API 仍是明文 HTTP（仅回环），公网访问需要反代或 VPN。

## 下一步建议

**面板 M2**（把四类曲线画出来）→ 计数器结转与降采样 → 控制面 M3。

TLS 已经就位，控制面可以安全地接在后面做。
