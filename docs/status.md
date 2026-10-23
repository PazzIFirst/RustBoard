# 实现进度

> 最后更新：2026-10-23　｜　对应需求稿：[requirements.md](requirements.md)

## 总体

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M1 骨架与闭环 | 🟢 完成 | 采集→缓冲→TLS 上报→入库→查询；协议 v2 + enrollment + mTLS + 吊销 |
| 证书有效期与轮换 | 🟢 完成 | 显式有效期、服务端热续签、客户端会话内轮换、启动自愈（并入 v0.2.0） |
| M2 面板 | 🟢 完成 | React/TS 前端、登录与代理、概览/详情四类图表、多指标分桶查询、采样间隔下发 |
| v0.2.1 硬化 | 🟢 完成 | 修复 known-issues KI-01 ~ KI-12；单元/集成 259 个，hardening e2e 29/29 |
| M3 控制面 | 🟢 完成 | systemd / Docker / 进程 / 日志 + 双端能力开关 + 审计页；单元 379，control e2e 99/99 |
| v0.3.1 硬化 | 🟢 完成 | #10 缓冲物理上界/崩溃恢复、#12 发送超时、#13 过期证书自愈、#14 会话清理原子化、KI-17 慢连接；单元/集成 420，hardening 34/34，v031 94/94 |
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
- [x] 测试：单元/集成 222 个；`panel.sh` 159 断言、`cert-rotation.sh` 103 断言、
      `security.sh` 9 断言；web 22 个 vitest
- [x] 三轮独立评审与渗透测试发现的问题（面板 token 代理泄露、默认 0.0.0.0、
      上游 HTML 透传、响应体无上限、间隔生效超时等）

## v0.2.1 硬化明细

已完成（对应 [known-issues.md](known-issues.md) KI-01 ~ KI-12）：

- [x] KI-01：agent 入口按来源 IP 限流（默认 16），单 IP 洪水不能挤掉合法会话；
      TLS/header 超时收紧到 5s
- [x] KI-02：SQLite 写连接 + 只读连接池（默认 4），长查询不阻塞写入与心跳
- [x] KI-03：面板 `trusted_proxies` / `cookie_secure`；不可信 XFF/XFP 完全忽略
- [x] KI-04：`admin_token` 强度校验（长度 / 字符集 / 多样性 / 占位符）
- [x] KI-05：管理 API 每 IP 读 60/min、写 10/min，429 + `Retry-After`
- [x] KI-06：管理端口非回环启动 WARN
- [x] KI-07：面板变更请求 Origin 同源校验
- [x] KI-08：未知 `/api/v1/*` 先 Bearer 再 404
- [x] KI-09：`rustboard-panel reset-password`
- [x] KI-10：运行中 `rotate-cert` ≤10s 热加载；`/api/v1/system` 同时返回 live/disk
- [x] KI-11：`rotate-cert` 进程间文件锁（10 分钟陈旧锁自动恢复）
- [x] KI-12：agent `cert_check_interval_hours`，`session_max_hours=0` 也会周期检查续签
- [x] 测试：单元/集成 259 个；`hardening.sh` 29 断言、`security.sh` 9、`cert-rotation.sh` 103、
      `panel.sh` 159；web 22
- [x] 独立评审 + 渗透：无高危；低危项记录在 known-issues / status

## M3 控制面明细

已完成：

- [x] 线协议：`ControlRequest` / `ControlResponse`（协议版本仍 2，能力协商后发送，旧端兼容）
- [x] agent 控制模块：systemd / Docker / 进程 / 只读日志，执行入口二次校验能力与白名单
- [x] hub 控制 API：`GET/POST /api/v1/agents/{id}/control`、`GET /api/v1/audit`
- [x] 会话复用：每连接控制命令队列、pending 上限、超时、未知 id 丢弃、断线回 503
- [x] 面板控制台 `/agents/:id/control` 与审计页 `/audit`，浏览器不接触 hub token
- [x] SQLite schema v5：`agent_control`、`audit_log`（180 天保留）
- [x] 安全：双端开关、固定动作枚举、无 shell、openat2 路径校验、FIFO/设备拒绝、
      pidfd 结束进程、非 0 退出/信号终止审计失败
- [x] 测试：单元/集成 379；`control.sh` 99/99；`cargo audit` 0 漏洞
- [x] 独立评审 + 渗透：无高危；审计信任边界与低危限制已记录

## v0.3.1 硬化明细

已完成（对应 GitHub #10 / #12 / #13 / #14、KI-17，#9/#11 复验）：

- [x] #10：DiskBuffer 原子持久化 `read_offset`；物理文件压实水位
      `max(2*max_bytes, max_bytes+1MiB)`；`recover()` 后重新限额；单条超大记录策略；
      子进程崩溃注入覆盖“淘汰后 meta 落盘前”和“compact rename 后 meta 落盘前”
- [x] #12：`AgentConfig.send_timeout_secs`（默认 15，1–120）；所有 WS 写路径超时；
      真实假 hub 停读 + `session_max_hours=0` 下 1.0s 退出会话（独立测试）
- [x] #13：仅过期证书启动自愈；CA/SAN/CN/key 异常仍拒绝；`CertLock` 内复核、
      成对备份、自检失败回滚；e2e 验证原 agent 用原 CA 自动重连
- [x] #14：`SessionRegistry` 两级锁（global map → per-agent slot）；最后连接注销与
      offline/revoked 写库在 slot 锁内原子完成；Barrier/mpsc 确定性交错 + 100 轮并发
- [x] KI-17：管理 API / 面板手工 HTTP/1 accept，5s header 超时 + 10s 请求体总超时，
      全局 256 / 每 IP 32，
      拒绝即关 TCP；30 条半截 header 5.0s 内全部关闭，`/healthz` 期间/之后均 200
- [x] #11 复验：hardening 7.6–7.10（非法/超长/9 跳 XFF 400、不可信来源伪造无效、
      锁定隔离）通过；#9 仅补认证/限速/告警证据，scoped token 与管理端 TLS 仍未实现
- [x] 测试：单元/集成 420；hardening 34/34、v031 94/94、security/panel/cert/control
      全量回归；`cargo audit` 0 漏洞

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
- 测试：`cargo test --workspace` 420 通过；`cargo audit` 0 漏洞；
  `security.sh` 9/9、`cert-rotation.sh` 103/103、`panel.sh` 159/159、
  `hardening.sh` 34/34、`v031.sh` 92/92、`control.sh` 99/99、web `pnpm test` 46/46。

## 已知限制

> 可修复的缺陷统一登记在 [known-issues.md](known-issues.md)，本节只保留设计取舍与部署限制。

1. **服务端证书轮换会让 v0.1 agent 失联**：v0.1 仍使用指纹钉扎，轮换/到期续签后必须升级
   到 v0.2（CA 信任）或重新纳管；v0.2 起无需重新纳管。
2. 启动时会强校验 CA 与 server 证书的链和 SAN；给 `server_names` 新增地址后，
   需要先 `rotate-cert --force` 才能启动（错误信息会点名缺失的 SAN）。
3. 采集器首次调用只建立基线、不上报（CPU/磁盘 IO 需要差分）。
4. 连接洪水的来源 IP 上限为 16，但攻击者若控制大量来源 IP（或 IPv6 前缀）仍可能耗尽总
   `max_connections`；生产环境应在网络层/防火墙做入口限速。
5. 面板默认只监听 `127.0.0.1` 且是明文 HTTP；远程访问必须显式 `--listen` 并走 VPN/反代。
   反代场景必须配置 `trusted_proxies` 并确保反代**覆盖**客户端传入的 `X-Forwarded-For`，
   否则攻击者可轮换伪造 IP 绕过登录失败锁定（已知低危，见渗透报告 L1）。
6. SQLite 数据库文件默认 0644（目录 0755），库内是指标与 agent 元数据，不含明文 secret；
   多用户宿主机可手工收紧到 0600/0700。
7. 客户端证书轮换复用原私钥，因此轮换不能补救私钥泄露；私钥/secret 泄露必须
   `agent revoke` 后重新纳管。CA 私钥是最高敏感资产，泄露等于全部身份失守。
8. 管理 API 限速按直连来源 IP 统计；置于反代后所有客户端共享反代 IP 的额度。管理口
   默认只绑回环，反代场景需自行评估并额外限速。
9. `reset-password` 只热加载新密码，不吊销已有会话 Cookie；若怀疑会话泄露，重置密码后
   仍需等待 TTL 或重启面板（KI-18，后续版本修复）。
10. **控制面信任边界**：agent 是 systemd/Docker/进程动作的实际执行者与结果来源。拿到
    agent 证书 + secret 的主体可以伪造执行结果；hub 审计不能抵抗被控 agent。能力默认关闭、
   白名单与操作确认是主要防线（KI-25）。
11. `nginx*` 这类前缀白名单会匹配 `nginx-evil`；需要更精确时请写完整 unit 名或更细前缀。
    日志白名单文件的硬链接不会被 openat2 拦截（需日志目录写权限，KI-22）。
12. 同 agent 多连接时，能力缓存以最新 Hello 为准；旧连接断开后可能短暂陈旧（KI-24，
    后续版本修复）。

## 下一步建议

**M4 告警与归档**（规则引擎、通知渠道、降采样、冷归档）→ 计数器结转 → 安装器与镜像。

控制面已按“默认关闭 + 双端开关 + 审计”交付，可以安全进入告警阶段。
