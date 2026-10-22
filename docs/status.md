# 实现进度

> 最后更新：2026-10-23　｜　对应需求稿：[requirements.md](requirements.md)

## 总体

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M1 骨架与闭环 | 🟢 完成 | 采集→缓冲→TLS 上报→入库→查询；协议 v2 + enrollment + mTLS + 吊销 |
| 证书有效期与轮换 | 🟢 完成 | 显式有效期、服务端热续签、客户端会话内轮换、启动自愈（并入 v0.2.0） |
| M2 面板 | 🟢 完成 | React/TS 前端、登录与代理、概览/详情四类图表、多指标分桶查询、采样间隔下发 |
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
      CSR 签发客户端证书（有效期见下），下发每机独立 secret
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

- [x] 证书有效期与自动轮换（CA 3650 天、服务端 365 天、客户端 90 天，可配置）
- [x] 服务端证书热续签（watch 推送，新连接立即生效）与启动自愈（key/cert 不匹配）
- [x] 客户端证书会话内轮换（复用私钥，CN 强制为会话身份，按 agent 冷却）
- [x] 服务端证书成对备份、CA 链/SAN 校验
- [ ] ACME：域名证书 / 公网 IP 6 天短证书（M5，需公网可达与 80/443 自检）
- [ ] hub 侧计数器结转（epoch 切换时累计流量归集）
- [ ] PostgreSQL 存储实现
- [ ] 降采样与保留期任务
- [ ] 结构化日志与 `RUST_LOG` 文档

## M2 明细

已完成：

- [x] `web/`：Vite + React 18 + TypeScript + uPlot；登录页、概览页、单机详情
- [x] 概览：状态、last_seen、CPU/内存/最高磁盘使用率、采样间隔，30s 轮询
- [x] 详情：CPU、内存、按挂载点的磁盘百分比、按网卡的 rx/tx 速率；
      1h/6h/24h/7d/自定义范围，uPlot 拖拽缩放与重置
- [x] 面板登录：单管理员 Argon2id（m=64MiB,t=3,p=4）、HttpOnly/SameSite=Lax Cookie、
      按 IP 5 次失败锁 15 分钟、Argon2 并发上限 2
- [x] 面板 → hub 代理：Bearer 只在服务端使用，浏览器拿不到 token；
      `/api/*` 强制 JSON、CSP、8MiB 流式响应上限、禁用环境代理
- [x] hub 管理 API：Bearer 鉴权（`/healthz` 除外）、`overview`、`latest`、
      多指标 `series`（自动分桶）、`settings`、`/api/v1/system`
- [x] 采样间隔：面板修改 → 落库 → Reconfigure 踢会话 → agent 在 ≤2s 内采用
- [x] SQLite v4：`agent_settings`；旧 v3 库幂等迁移
- [x] 测试：单元/集成 211 个；`panel.sh` 156 断言、`cert-rotation.sh` 103 断言、
      `security.sh` 9 断言；web 22 个 vitest
- [x] 三轮独立评审与渗透测试发现的问题（面板 token 代理泄露、默认 0.0.0.0、
      上游 HTML 透传、响应体无上限、间隔生效超时等）

## 已验证（2026-10-23，本机）

- `rustboard-hub init` 生成 CA + 服务端证书并打印指纹，同时生成管理 API token；
- `agent add` 生成一次性 token 与可直接粘贴的安装命令；
- agent 首次连接自动 enrollment（错误指纹会拒绝且不消耗 token），
  写入 `agent.crt/key/secret/ca.crt`（私钥 / secret / 配置 0600，证书 0644）；
- 纳管后 CA 信任握手成功，5 秒内开始上报；服务端证书 `rotate-cert` 后 agent 自动重连、不重新纳管；
- 错误指纹 / 无客户端证书 / 过期证书 / 别的 CA 证书 / TLS 1.2 均被拒；
- 面板登录、5 次失败锁定、Cookie、登出、未登录 401 均验证；
- 面板修改采样间隔后 60s 内 agent 日志出现 `采样间隔已更新`，重连后继续上报；
- series 多指标、自动分桶、32 天/点数上限与非法参数 400 均验证；
- 证书轮换失败场景（CA 不配套、缺 ca.key、坏 ca.crt、空 SAN、缺 server.crt）均有 e2e 断言；
- 测试：`cargo test --workspace` 211 通过；`cargo audit` 0 漏洞；
  `security.sh` 9/9、`cert-rotation.sh` 103/103、`panel.sh` 156/156、web `pnpm test` 22/22。

## 已知限制

1. **服务端证书轮换会让 v0.1 agent 失联**：v0.1 仍使用指纹钉扎，轮换/到期续签后必须升级
   到 v0.2（CA 信任）或重新纳管；v0.2 起无需重新纳管。
2. 客户端证书轮换复用原私钥，因此轮换不能补救私钥泄露；私钥/secret 泄露必须
   `agent revoke` 后重新纳管。CA 私钥是最高敏感资产，泄露等于全部身份失守。
3. 启动时会强校验 CA 与 server 证书的链和 SAN；给 `server_names` 新增地址后，
   需要先 `rotate-cert --force` 才能启动（错误信息会点名缺失的 SAN）。
4. 采集器首次调用只建立基线、不上报（CPU/磁盘 IO 需要差分）。
5. SQLite 单连接 + 全局锁；32 天 × 20 指标的大查询会阻塞写入，后续需要预聚合/读写分离。
6. 面板默认只监听 `127.0.0.1` 且是明文 HTTP；远程访问必须显式 `--listen` 并走 VPN/反代。
   反代场景登录限速仍按直连 IP 统计，反向代理需要自行限速以避免锁定 DoS。
7. 未认证连接仍可占满 `max_connections`（1024）导致 agent 入口拒绝服务：
   10s 握手超时可缓解，后续按来源 IP 限流并预留槽位（已记录为待修复）。
8. 运行中的 hub 执行 `rotate-cert` 后，`/api/v1/system` 报告磁盘新证书而监听器仍用旧证书，
   重启后一致；并发执行多个 `rotate-cert` 未加文件锁。
9. 客户端证书只在每会话握手时检查续签阈值；`session_max_hours=0` 且超长连接时可能错过窗口，
   默认 12 小时重连不存在该问题。

## 下一步建议

**M3 控制面**（systemd / Docker / 进程 / 日志，能力默认关闭 + 审计）→ 计数器结转与降采样 →
告警与冷归档 → 安装器与镜像。

TLS 与面板已经就位，控制面可以安全地接在后面做。
