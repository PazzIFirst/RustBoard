# 实现进度

> 最后更新：2026-10-23　｜　对应需求稿：[requirements.md](requirements.md)

## 总体

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M1 骨架与闭环 | 🟢 基本完成 | 采集→缓冲→TLS 上报→入库→查询；协议 v2 + enrollment + mTLS + 吊销已通 |
| M2 面板 | ⬜ 未开始 | 仅占位页 |
| M3 控制面 | ⬜ 未开始 | |
| M4 告警与归档 | ⬜ 未开始 | |
| M5 安装与交付 | ⬜ 未开始 | |

## M1 明细

已完成：

- [x] Cargo workspace 与 5 个 crate 的边界划分
- [x] 线协议：MessagePack 帧（Enroll / Enrolled / Hello / Welcome / Batch / Ack / Ping / Pong / Problem）
- [x] **协议版本 2**：hub 与 agent 必须严格一致；版本不符回 `bad_protocol` 且不发 Welcome，
      agent 收到后明确报错并以非零码退出，不再进入重连循环
- [x] 采集器：CPU（含每核可选、load average）、内存/Swap、磁盘容量与 inode、
      磁盘 IO（含 await / util 差分）、网卡（8 项计数器）、系统辅助指标
- [x] 本地磁盘缓冲：追加日志 + 已确认偏移持久化 + 超限丢弃最旧 + 损坏尾部自愈
- [x] SQLite 存储：WAL、批量事务、`(agent_id, epoch, seq)` 精确幂等（`ingest_batches`，48h 清理）
- [x] hub 本机采集（agent_id = `hub-self`，本地直写，不走网络）
- [x] 只读 API：`/healthz`、`/api/v1/agents`、`/api/v1/series`
- [x] agent 断线指数退避重连；新数据即时唤醒上传（Notify，不再等心跳）
- [x] **TLS 1.3 + 私有 CA**：hub 自签 CA，签发服务端与客户端证书
- [x] **证书指纹钉扎**：agent 首次连接严格比对 SHA-256 指纹，不符立即拒绝
- [x] **一次性 enrollment**：`agent add` 生成 token（默认 30 分钟、单次使用），
      CSR 签发 90 天客户端证书，下发每机独立 secret
- [x] **mTLS**：客户端证书校验 + Hello 中的 secret 二次身份绑定
- [x] **吊销**：`agent revoke` 清除 secret、状态置为 revoked，重连被拒
- [x] **离线检测**：连接断开即置 offline（revoked 状态不被覆盖）；
      45s 收不到任何帧即判定心跳超时并关闭会话
- [x] **随机五位数端口**：安装时自动挑选并 bind 探测，支持自定义；
      `rustboard-hub ports` / `rustboard-panel ports` / `rustboard-agent info` 随时查看
- [x] 安装命令自动带上正确端口、hub 地址（自动探测出口 IP，可用 `--advertise` 覆盖）
- [x] 单元测试 65 个，端到端联调 9/9 通过（含协议门禁、错误指纹拒绝、吊销生效）
- [x] 修复 review 提出的 #1–#8（身份伪造、mTLS 绑定、跨 epoch 去重、
      吊销即时生效、文件权限、在线状态、磁盘 await 公式）
- [x] 修复独立评审提出的高危 / 中危 / 低危项：协议版本门禁、慢速攻击与连接上限、
      原子写符号链接劫持、revoked 覆盖、跨 epoch 乱序丢数据、既有宽权限、
      写超时、吊销事务、迁移并发、判重水位回退、启动状态重置、Frame 日志脱敏

未完成（M1 收尾 / 后续）：

- [ ] 证书自动轮换（客户端证书 90 天，需在到期前换发）
- [ ] 服务端证书轮换与指纹变更流程（目前重建 CA 会使全部 agent 失效）
- [ ] ACME：域名证书 / 公网 IP 6 天短证书（M5，需公网可达与 80/443 自检）
- [ ] hub 侧计数器结转（epoch 切换时累计流量归集）
- [ ] 采样间隔动态下发（Welcome 已下发值，agent 尚未应用）
- [ ] PostgreSQL 存储实现
- [ ] 降采样与保留期任务
- [ ] 结构化日志与 `RUST_LOG` 文档

## 已验证（2026-10-23，本机）

- `rustboard-hub init` 生成 CA + 服务端证书并打印指纹；
- `agent add` 生成一次性 token 与可直接粘贴的安装命令；
- agent 首次连接自动 enrollment，写入 `agent.crt/key/secret/ca.crt`
  （私钥 / secret / 配置 0600，证书 0644）后立即重连；
- 重连后 mTLS 握手成功，5 秒内开始上报，`net.rx_bytes` 带 `if=eth0` 正常入库；
- **错误指纹**：agent 收到“服务端证书指纹不匹配”，未获得证书，持续退避重试；
- **协议门禁**：协议版本 1 的 Hello 收到 `bad_protocol` +「需要 agent ≥ 2」，无 Welcome；
- **吊销**：revoke 后 agent 重启连接被拒（`revoked`），状态保持 revoked；
- 单元测试 65/65 通过；`bash tests/e2e/security.sh` 9/9 通过。

## 已知限制

1. **证书不会自动轮换**：客户端证书 90 天有效，到期需重新 enrollment；
   服务端证书 10 年，但重建 CA 会导致全部 agent 失联（指纹变了）。
2. 身份绑定已改为「客户端证书 CN == agent_id」+ secret 双因子；
   `agent_secret` 仍保留作为第二因子。
3. 采集器首次调用只建立基线、不上报（CPU/磁盘 IO 需要差分）。
4. SQLite 单连接 + 全局锁，写入吞吐够用但不是最终形态；PG 实现待补。
5. 面板是静态占位页。
6. 管理 API 仍是明文 HTTP（仅回环），公网访问需要反代或 VPN。

## 下一步建议

**面板 M2**（把四类曲线画出来）→ 计数器结转与降采样 → 控制面 M3。

TLS 已经就位，控制面可以安全地接在后面做。
