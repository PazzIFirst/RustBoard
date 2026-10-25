# 实现进度

> 最后更新：2026-10-25　｜　对应需求稿：[requirements.md](requirements.md)

## 总体

| 里程碑 | 状态 | 说明 |
|---|---|---|
| M1 骨架与闭环 | 🟢 完成 | 采集→缓冲→TLS 上报→入库→查询；协议 v2 + enrollment + mTLS + 吊销 |
| 证书有效期与轮换 | 🟢 完成 | 显式有效期、服务端热续签、客户端会话内轮换、启动自愈（并入 v0.2.0） |
| M2 面板 | 🟢 完成 | React/TS 前端、登录与代理、概览/详情四类图表、多指标分桶查询、采样间隔下发 |
| v0.2.1 硬化 | 🟢 完成 | 修复 known-issues KI-01 ~ KI-12；单元/集成 259 个，hardening e2e 29/29 |
| M3 控制面 | 🟢 完成 | systemd / Docker / 进程 / 日志 + 双端能力开关 + 审计页；单元 379，control e2e 99/99 |
| v0.3.1 硬化 | 🟢 完成 | #10 缓冲物理上界/崩溃恢复、#12 发送超时、#13 过期证书自愈、#14 会话清理原子化、KI-17 慢连接；单元/集成 420，hardening 34/34，v031 94/94 |
| v0.3.2 控制面可靠性 | 🟢 完成 | #15/#16/#18/#19、1MiB 控制应答帧预算、45s idle 回归；单元/集成 447，v032 66/66、control 100/100、hardening 34/34、v031 94/94、security 9/9、cert 103/103、panel 159/159 |
| v0.3.3 管理面安全 | 🟢 完成 | #9 scoped token + 管理端 TLS/ Panel `https`+`hub_ca`、#17 吊销窗口、#20 日志 TOCTOU、#21 systemd 未加载 unit；单元/集成 495，v033 100/100、security 9/9、cert 103/103、hardening 36/36、control 100/100、v031 94/94、v032 66/66、panel 159/159 |
| v0.3.4 低风险硬化 | 🟢 完成 | KI-26 未认证 401 限速、KI-18 重置会话/登录代际、KI-19 Hello 元数据、KI-21 权限与 data_dir 防护、KI-24 多连接能力、备份稳定性；单元/集成 562，v034 97/97，既有 8 套 e2e 全绿 |
| v0.3.5 安全收口 | 🟢 完成 | KI-27 WS 会话许可、data_dir `openat2` fd/owner 加固、limit=0 与 DB 外置 WARN；单元/集成 569，v035 48/48，既有 9 套 e2e 全绿 |
| M4 告警与归档 | 🟢 完成 | A 降采样/选层/保留期；B 告警/事件/静默/四渠道通知/面板；C WebDAV/S3/SFTP 归档与下载；D v040 27/27、panel 159/159、security 9/9、web 79/79、workspace/clippy/audit 全绿；v0.4.0 |
| v0.4.1 已知问题修复 | 🟢 完成 | KI-29 rowid 竞态、KI-31 64 MiB 配置/下载一致性、KI-28 拒绝日志采样、KI-20 安装命令引用；SFTP 真实环境 29/29，M4 基线渗透无高危；v041 26/26；v0.4.1 发布 |
| v0.4.2 安全/测试修复 | 🟢 完成 | v041 KI-28 计数兼容 CI ANSI；vendored russh 0.64.1 + ssh-key 0.7.0-rc.11 + crypto-bigint 0.7.6（RUSTSEC-2026-0387）；v0.4.2 发布 |
| M5 安装与交付 | 🟡 进行中（Phase C 主体已实现，待 RC） | Phase A 安装器/e2e 121/121；Phase B 两架构静态 musl、离线包 122/122、arm64 qemu 40/40、Docker 126/126（arm64 QEMU + 来源校验）；Phase C C0–C8 已实现 ACME/agent TLS/面板 TLS/管理端 TLS/Docker 与文档，尚未完成 C9 全量 e2e、独立评审/渗透与 `v1.0.0-rc.1`；正式 v1.0.0 待 Phase E |

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
- [x] 降采样与保留期任务（M4-A，v0.4.0）
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
- [x] KI-06：v0.2.1 非回环启动 WARN；v0.3.3 起非回环 + `admin_tls=off` 拒绝启动
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

## v0.3.5 安全收口明细

已完成（对应 KI-27、data_dir TOCTOU 与两项低风险告警）：

- [x] KI-27：TLS 全局 + per-IP 许可由 `ConnectionGuards` 持有到 WebSocket 会话结束；
      删除重复计数的 `session_slots`；超限在 accept 阶段关闭 TCP，其他来源 IP 不受影响
- [x] data_dir：Linux 下从 `/` 逐组件 `openat2` + 目录 fd + `mkdirat`/`fchmod`；
      祖先不可被非特权用户写，最终目录必须 euid 拥有且无 sticky；确定性 TOCTOU 单测
- [x] `admin_auth_failure_limit_per_min=0` 仍保留每 IP 每窗口首条失败 WARN，不恢复 429
- [x] `database` 在 data_dir 外/相对路径时启动 WARN 一次，不收紧父目录、DB 仍 0600
- [x] 测试：Rust 569（agent 100、common 113、core 73、hub 180、panel 103）；
      `v035.sh` 48/48；`security.sh` 9/9、`cert-rotation.sh` 103/103、
      `panel.sh` 159/159、`hardening.sh` 36/36、`control.sh` 100/100、
      `v031.sh` 94/94、`v032.sh` 66/66、`v033.sh` 100/100、`v034.sh` 97/97；
      `cargo audit` 0
- [x] 独立评审：A1、A2/A3 均无 [严重]；A1 建议的 guard 释放顺序/注释已处理；
      A2/A3 建议的“静态预检不覆盖祖先权限”和“O_RDONLY 极严目录会 EACCES”已写入限制，
      非 root owner 测试跳过、DB 外置 WARN 由 `v035.sh` 覆盖
- [x] 独立渗透：本地实例全清单，**无高危/中危**；KI-27 与 data_dir 修复实跑通过；
      新登记低危 KI-28（连接拒绝 WARN 未采样，既有行为，v0.4.0 处理）与 4 条信息项
- [x] 兼容：协议 v2 / DB schema v6 / 证书格式不变；data_dir owner 规则收紧需发布说明

## M4 告警与归档明细

已完成（v0.4.0）：

- [x] **A**：schema v7（`samples_1m`/`samples_1h`/`maintenance_state` 等）；1m/1h 降采样、
      迟到 raw 回放、保留期、`maintenance run|status`；查询按 ≤6h raw / ≤7d 1m / >7d 1h
      选层，跨度 730 天，桶过小自动提升
- [x] **B**：5 条内置规则、规则 CRUD、pending→firing→resolved 状态机、事件、静默、
      后台评估（raw-only、每规则 5000 序列/状态上限、5s 预算、每小时清理）；
      Telegram/企微/钉钉/飞书四渠道，签名/重试/脱敏；面板 `/alerts`
- [x] **C**：`[archive]` 配置、CSV.gz/manifest、WebDAV/S3/SFTP 三后端、
      按 UTC 天/分片 worker、归档水位与 retention 门禁、对象列表/下载 API、
      面板 `/archive`
- [x] **D**：v040 e2e 27/27、panel e2e 159/159、security 9/9、web 79/79；
      workspace/clippy/audit 全绿；CI 加入 v040；v0.4.0 发布
- [x] 文档：CHANGELOG 0.4.0、known-issues KI-30、vendor 说明、升级/回滚说明
- [x] 评审：B1/B2、C1/C2/C4、C3 均经过独立评审；C4 下载内存/公平性问题经三轮
      修复（64 MiB、body 期限、按主体限流）；C3 的 rsa 依赖通过 vendor patch 移除
- 限制：SFTP 真实服务器联网验证未执行（本机无可用 SSH 测试账户），仅完成
  指纹/路径/私钥权限/错误脱敏单测与编译；vendored `russh`/`ssh-key` 仅支持
  ed25519/ECDSA 主机密钥和 ed25519 用户私钥，RSA 旧服务器不兼容

## M5 安装与交付明细

### Phase A（2026-10-24 完成）

- [x] `rustboard-install`：路径/state/txn/systemd/health 库；`create_owned_dir`
      只拥有本次新建的数据目录，失败递归删除，已有目录绝不动
- [x] `rustboard-hub install|upgrade|uninstall`：自签 + SQLite + 可选同机 panel；
      `--prefix`/`--dry-run`/`--offline`/`--force`；旧手工配置 `upgrade` 导入
- [x] `rustboard-panel install|uninstall`：hub token 只走 0600 文件、初始密码
      仅打印一次、静态资源校验、systemd 健康检查
- [x] `rustboard-agent install|uninstall`：`--token-file`、指纹归一化、30s
      enrollment 等待、失败停服务并回滚
- [x] systemd unit：`NoNewPrivileges`/`PrivateTmp`/`ProtectSystem=strict`/
      最小 `ReadWritePaths`；配置/私钥 0600、data 0700
- [x] e2e：`tests/e2e/v100-install.sh` 121/121，覆盖安装、重复幂等、admin 端口
      占用回滚、agent 真实 enrollment 与 3 个数据点、默认/`--purge` 卸载、
      `hub init` 旧配置 upgrade（config/cert/data hash 不变）
- [x] 门禁：workspace 1079 tests、fmt/clippy/audit 0；独立评审 + 渗透三轮，
      高危/严重项修复后由新评审/渗透复验（报告见
      `docs/security/2026-10-24-m5-phase-a-install-pentest.md`）
### Phase B（2026-10-25 完成）

- [x] 静态构建入口 `docker/Dockerfile.build`：固定
      `rust:1.89-alpine@sha256:4b800f2e...`，buildx 在目标平台 native 构建；x86_64 已验证 static-pie，aarch64 已验证
      statically linked；二者均无 `INTERP`、`--version` 0.4.2
- [x] 离线包：`packaging/build-release.sh` 生成两架构 tarball、包内/外部
      `SHA256SUMS`、确定性 tar；`packaging/install.sh` 先校验再写，prefix 安全、
      web 原子安装、拒绝明文 secret argv
- [x] 离线 netns e2e：`tests/e2e/v100-offline.sh` **122 PASS / 0 FAIL / 0 SKIP**（含 agent 真实 enrollment、STRICT=1 复测）；
      只允许 Unix/loopback connect；hub/panel 实际启动 healthz；重复安装幂等；
      篡改包与明文 argv 在写盘前失败
- [x] Docker：`docker/Dockerfile` 四 target、三 entrypoint、compose 示例；
      `tests/e2e/v100-docker.sh` **126 PASS / 0 FAIL / 0 SKIP**（含 agent 真实 enrollment、panel `--user`、arm64 QEMU 镜像、来源校验）；
      hub/panel 主进程 UID 10001、tini root、8444 不发布、panel 共享 netns、
      restart 幂等、空 volume `--user` fail-fast、agent 空 env 零落盘
- [x] Release workflow：`v*` tag 触发、tag/版本/main 祖先门禁、两架构原生构建、
      三镜像 staging→正式/sha/latest、SBOM/attestation、delivery-e2e、draft→publish；
      `actionlint` 通过
- [x] arm64 离线包 e2e（B-G4）：`tests/e2e/v100-arm64.sh` **40 PASS / 0 FAIL / 2 SKIP**
      （x86 主机不直接执行 package install.sh，按设计 SKIP；二进制 qemu 运行/hub healthz 通过）
- [x] 多架构 manifest：本地 registry 实测三 role 的 `v0.4.2`/`sha-<12>`/`latest` digest 一致，
      amd64+arm64 均在 manifest；GHCR 真实推送仍待 v1.0.0 发布
- [x] 独立评审 + 渗透：首轮 + 第三轮独立评审、渗透复测完成；H-01/H-02 关闭，
      S1 信号残余书面接受；证据见 [Phase B 交付证据](security/2026-10-25-m5-phase-b-delivery-evidence.md)、
      [渗透报告](security/2026-10-25-m5-phase-b-pentest.md)
- [ ] 正式 `v1.0.0`：CHANGELOG 归档、tag、Release、镜像在 Phase E 完成

### Phase C（2026-10-25，进行中：主体已实现，待评审与 RC）

- [x] **C0** ACME 依赖与 Pebble spike：`instant-acme 0.8.5` + ring 在 MSRV 1.89
      可编译、无 aws-lc/cmake；Pebble 验证 DNS/IP、`shortlived`、TLS-ALPN-01；
      结论见 [C0 spike](plans/2026-10-25-m5-phase-c-spike.md)
- [x] **C1** 发布门禁：`tests/e2e/v100-docker.sh` 支持 `DOCKER_ARCH`/`SKIP_ARM64`；
      release workflow 增加 `delivery-docker`/`delivery-arm64`、checkout 固定
      `github.sha`、release environment；hosted 验证留 C9
- [x] **C2** 配置与 agent TLS：`[tls]`、`tls_mode`/`server_ca`，旧配置默认
      `self-signed`/`fingerprint`；安装器 `--tls-mode`/`--server-ca`；
      `hub agent add` 按 ACME/自签输出信任命令并提示旧 agent 升级
- [x] **C3** 证书存储与 client CA 拆分：`ca.crt/key` 只作客户端 CA；
      `server.crt/key` 由 self-signed 或 ACME 写入；原子写、成对备份（每类 5 份）、
      `CertLock`；ACME 模式下 `cert_rotation` 不接管服务端证书
- [x] **C4** ACME 客户端与挑战：账户 load-or-create、订单/轮询/finalize、CSR、
      HTTP-01（80）与 TLS-ALPN-01（443，自定义 `ResolvesServerCert`）、
      自定义 ACME CA、错误分类；私钥/账户 key 不打印
- [x] **C5** 安装器 80/443 诊断与回退：本地 bind + `ss`、防火墙只读探测、
      云元数据 1s、staging 实跑、最多 3 轮；失败回退 self-signed；`--offline`
      与 ACME 在写盘前互斥；`admin_tls=required` HTTPS 健康检查
- [x] **C6** 续期/热加载/告警：剩余寿命 ≤ `min(lifetime/3, 48h)` 续期，
      1m/5m/15m/1h/6h 退避，失败保留旧证书；成功原子写并触发热加载；
      `tls status|issue|renew` 与自动续期共用锁
- [x] **C7** 面板 TLS 与管理端 TLS：`--tls-cert/--tls-key/--hub-ca/--public-origin/
      --cookie-secure`，证书/私钥配套、权限、SAN、符号链接校验；直连 TLS
      强制 Cookie Secure；hub `--admin-tls required` 与面板 `hub_ca`
- [x] **C8** Docker/离线/文档：hub 镜像 `EXPOSE 8443 80 443`（80/443 仅 ACME
      元数据，默认 compose 不发布）；`RUSTBOARD_TLS_MODE`/`RUSTBOARD_ACME_*`；
      降权保留 `NET_BIND_SERVICE`；新增 `docker/compose.acme.example.yml`；
      `docs/install/tls.md`、`panel-tls.md`、`troubleshooting.md` 与
      acme/docker/offline/release/README/CHANGELOG 更新
- [ ] **C9** 全量 e2e：`v100-acme.sh`（Pebble HTTP-01/TLS-ALPN）、
      `v100-acme-ip.sh`、`v100-acme-renew.sh`、`v100-acme-fallback.sh`、
      `v100-tls-agent.sh`、`v100-panel-tls.sh`、`v100-admin-tls.sh`，以及
      install/offline/arm64/docker 回归
- [ ] 独立评审（只读）与渗透（本地实例）：ACME 目录 SSRF、挑战端口、key 权限、
      token 日志、旧 agent 降级、admin/panel TLS、Docker 端口/证书卷
- [ ] RC 前手工门禁：真实 Let's Encrypt staging（域名 HTTP-01/TLS-ALPN +
      公网 IPv4 `shortlived`），记录 SAN/链/到期/续期；不得伪造成功
- [ ] `v1.0.0-rc.1`：版本/CHANGELOG 归档、tag、真实 release workflow
      （`delivery-e2e`/`delivery-docker`/`delivery-arm64`、staging 镜像、SBOM、
      attestation、pre-release 不 latest）；RC 通过后才进入 Phase D/E

**Phase C 已验证（本地）**：`bash -n docker/entrypoint-hub.sh`；默认与 ACME 叠加
Compose `config` 语法；`docker/Dockerfile` hub `EXPOSE 8443 80 443`；
`DOCKER_ARCH=amd64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh`
**123 PASS / 0 FAIL / 1 SKIP**（可选 arm64/QEMU 检查按设计 SKIP，由
`delivery-arm64` 原生覆盖）；O.hub/O.union 已同步 80/443 元数据，C.3/H.13/H.14
仍断言默认 compose 不发布 80/443、8444 不发布。**未验证**：真实 ACME 签发、
Docker 内 ACME 端到端、面板 HTTPS e2e、管理端 TLS e2e、hosted RC。

**Phase C 限制**：面板证书无热加载，续期后需重启；ACME volume 用非 root
`--user 10001` 启动时没有 `NET_BIND_SERVICE`，自动续期可能无法绑定 80/443；
默认 compose 不发布 80/443，需要 ACME 叠加文件；旧 v0.4 指纹 agent 不兼容 ACME
hub，需升级。

计划：[Phase B 交付计划](plans/2026-10-25-m5-phase-b-delivery.md)；
[Phase C 计划](plans/2026-10-25-m5-phase-c-tls-release-gates.md)。
离线/Docker/发布文档：[offline](install/offline.md)、[docker](install/docker.md)、
[release](install/release.md)；TLS 文档：[tls](install/tls.md)、
[acme](install/acme.md)、[panel-tls](install/panel-tls.md)、
[troubleshooting](install/troubleshooting.md)。

- [ ] Phase D/E：PostgreSQL/备份迁移、压力/长稳/v1.0.0

> Phase A 的 e2e 只覆盖 x86_64 本机 systemd；arm64、离线 netns、Docker 镜像与
> 真实 ACME/PG 属于后续 Phase，不作为本阶段完成项。

## v0.3.4 低风险硬化明细

已完成（对应 KI-26 / KI-18 / KI-19 / KI-21 / KI-24 与备份稳定性）：

- [x] KI-26：`admin_auth_failure_limit_per_min`（默认 60、0 关闭、最大 600）；按来源 IP
      固定窗口失败限速，超限 429 + `Retry-After` 且不查库；旧 `admin_token` 应急旁路；
      401/429 WARN 采样
- [x] KI-18：密码重置后 ≤2s 吊销全部会话；登录认证代际关闭“Argon2 期间重置后旧会话
      复活”的 TOCTOU（评审/渗透发现后补修）
- [x] KI-19：Hello 全字段 UTF-8 字节长度/控制字符校验，非法帧 `bad_frame`、不写库不回显
- [x] KI-21：数据/证书目录 0700、SQLite 主库/WAL/SHM 0600、私有 umask；共享/系统/
      sticky/符号链接/相对 `data_dir` 拒绝启动，避免误 chmod `/tmp`、`/etc`、`/`
- [x] KI-24：能力以最新连接为准，旧 Hello 不覆盖，最新断开回退剩余最新已登记能力
- [x] 证书备份后缀 4 段并按 `(毫秒, 序号)` 淘汰，修复同毫秒偶发误删
- [x] 测试：Rust 562（agent 100、common 109、core 73、hub 177、panel 103）；
      `v034.sh` 97/97；`security.sh` 9/9、`cert-rotation.sh` 103/103、
      `panel.sh` 159/159、`hardening.sh` 36/36、`control.sh` 100/100、
      `v031.sh` 94/94、`v032.sh` 66/66、`v033.sh` 100/100；`cargo audit` 0
- [x] 独立评审：首轮 2 个 [严重]（登录竞态、共享目录 chmod）、第二轮 2 个
      [严重]（尾斜杠/中间符号链接、系统目录漏检）均已修复；第三轮复审无严重项，
      残余的 validate→create/chmod TOCTOU 需祖先不可被他人写，已在限制中记录
- [x] 独立渗透（本地实例）：无高危；KI-18 竞态与 data_dir 误 chmod 已修复；
      新登记中危 KI-27（单 IP WS 会话上限绕过，v0.3.5）与低危/权衡见 known-issues/status
- [x] 兼容：协议 v2 / DB schema v6 / 证书格式不变；滚动升级；回滚 v0.3.3 只需回代码

## v0.3.3 管理面安全明细

已完成（对应 GitHub #9 / #17 / #20 / #21）：

- [x] #9 scoped token：SQLite schema v6 `api_tokens`（只存 SHA-256）、
      `read` / `write` / `admin` 三级权限、`token create/list/rotate/revoke`；
      审计 actor 记录 token name，旧 `admin_token` 兼容并固定 `admin`；
      `admin` 为保留名（大小写不敏感拒绝）
- [x] #9 管理端 TLS：`admin_tls = "off" | "required"`；非回环 + off 拒绝启动；
      required 复用 server.crt/key 做 server-auth（TLS1.3 + ALPN h1），
      支持证书热加载；Panel 支持 `https://` + 私有 `hub_ca`（只信任该 CA）
- [x] #17：控制 API 两道吊销门禁 + 会话 dispatch 前门禁；死吊销返回 403
      `agent_revoked`、审计 denied；API 不投递、会话不发 ControlRequest
- [x] #20：日志文件从根 fd 对完整绝对路径单次 `openat2`
      （`NO_SYMLINKS|NO_MAGICLINKS|BENEATH`），关闭父路径 TOCTOU；
      保留跨挂载点兼容（不启用 `NO_XDEV`）
- [x] #21：systemd 合并 `list-unit-files`，已安装未加载 unit 以
      `not-loaded/inactive/dead` 展示并可 start；两次命令共享总超时，
      输出 >256 KiB 拒绝不完整列表
- [x] 测试：单元/集成 495；`v033.sh` 100/100、`hardening.sh` 36/36、
      `security.sh` 9/9、`cert-rotation.sh` 103/103、`control.sh` 100/100、
      `v031.sh` 94/94、`v032.sh` 66/66、`panel.sh` 159/159；web 48/48；
      `cargo audit` 0 漏洞
- [x] 独立评审：A1/A2/C/D 分项评审；[严重] 项（actor 撞名、hardening e2e、
      `NO_XDEV` 启动回归）均已修复；最终安全复审无 [严重]
- [x] 独立渗透（本地实例）：**无未修复高危**；中危 1 项 KI-26（未认证 401 不受
      管理限速，计划 v0.3.4），低危 systemd 超时 join / #17 在途窗口已记录；
      认证、TLS、注入、路径逃逸、资源、泄露、Panel CA 等必测项通过
- [x] 升级顺序：先升级 hub（自动 v6 迁移），按需启用 `admin_tls` 并
      `rotate-cert`；Panel 最后改 `https://` + `hub_ca`；回滚前先把
      `admin_listen` 改回回环

## v0.3.2 控制面可靠性明细

已完成（对应 GitHub #15 / #16 / #18 / #19）：

- [x] #18：`ControlSession` pending 记录增加绝对 deadline；会话 1s timer 清理到期项并回
      `control_timeout`，清理优先于新控制命令与入站消息；晚到应答只计未知 id，不再永久占用
      `max_pending` 配额
- [x] #16：证书续签等待期间收到 `ControlRequest` 立即回 `busy_renewing`，不执行动作；
      Hub 映射 503 / 固定文案 / 审计 `error`，不落 502/504
- [x] #15：Panel 控制 POST 使用 70s 专用超时（Hub 最大 60s + 余量）；最终超时返回
      504 `control_result_unknown`，响应体与前端文案明确“动作可能已执行、不要直接重试”
- [x] #19：journald 使用 `journalctl --reverse`，截断时保留最新内容并丢弃最旧半行，
      返回顺序恢复旧→新；`size_bytes` 为实际保留的 stdout 字节数
- [x] 额外加固：Hub WS 单帧上限提升到 1 MiB（与消息上限一致）；agent 发送控制应答前检查
      1 MiB−4 KiB 编码预算，超限回 `control_result_too_large`，避免大结果触发断连；
      45s 会话空闲超时改为绝对 deadline，不被 1s 控制清理 timer 重置
- [x] 测试：单元/集成 447；`v032.sh` 66/66、`control.sh` 100/100、`v031.sh` 94/94、
      `security.sh` 9/9、`cert-rotation.sh` 103/103、`hardening.sh` 34/34、`panel.sh` 159/159；
      web 48/48；`cargo audit` 0 漏洞
- [x] 独立评审两轮：严重项（45s idle、256KiB 帧、>1MiB 控制结果）已修复并复审；无未修复严重项
- [x] 独立渗透（本地实例）：认证 35/35、传输、注入、资源、泄露、依赖、配置均通过；
      无未修复高危；低危 L1/L2 即既有 KI-19/KI-21，不阻塞 v0.3.2

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
- series 多指标、自动分桶、730 天/点数上限与非法参数 400 均验证；
- 证书轮换失败场景（CA 不配套、缺 ca.key、坏 ca.crt、空 SAN、缺 server.crt）均有 e2e 断言；
- 测试：`cargo test --workspace` 495 通过；`cargo audit` 0 漏洞；
  `security.sh` 9/9、`cert-rotation.sh` 103/103、`panel.sh` 159/159、
  `hardening.sh` 36/36、`v031.sh` 94/94、`control.sh` 100/100、`v032.sh` 66/66、
  `v033.sh` 100/100、web `pnpm test` 48/48。

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
6. v0.3.5 起 Linux 下数据目录/证书目录的创建与收紧改为从 `/` 逐组件 `openat2` +
   目录 fd + `mkdirat`/`fchmod`，消除了 validate→create/chmod 的路径替换窗口；祖先
   必须不可被非特权用户写，最终目录必须由当前 euid 拥有且无 sticky。`data_dir` 必须是
   本程序独占的绝对子目录（至少两级）：`/tmp`、`/var/tmp`、`/etc`、`/var/log`、`/` 等
   共享/系统目录、sticky 目录、相对路径、任一祖先或最终组件为符号链接、他人拥有的
   最终目录都会拒绝启动。root 服务只能使用 root 拥有的最终目录，非 root 必须使用
   自己拥有的最终目录；root-owned sticky 目录（`/tmp`、`/var/tmp`）只能作为祖先。
   非 Linux 平台仍保留静态路径检查，完整 fd 保证仅 Linux。配置阶段的静态预检只做
   路径形状 / 符号链接 / 最终 owner；祖先 owner 与可写性在 fd 打开时校验，预检可能
   放过运行期会拒绝的路径（fail-closed）。最终目录用 `O_RDONLY` 打开后 `fchmod`，
   因此 0300/0100 这类 owner 不可读的极严目录会 EACCES，需先恢复读权限。数据库位于
   `data_dir` 外时会打一次 WARN，但不收紧其父目录（DB 文件仍 0600）。证书目录 0700
   后，同机以不同用户运行且直接读 hub `ca.crt` 的 Panel 需复制 CA 或以同用户运行。
7. 客户端证书轮换复用原私钥，因此轮换不能补救私钥泄露；私钥/secret 泄露必须
   `agent revoke` 后重新纳管。CA 私钥是最高敏感资产，泄露等于全部身份失守。
8. 管理 API 限速按直连来源 IP 统计；置于反代后所有客户端共享反代 IP 的额度。管理口
   默认只绑回环，反代场景需自行评估并额外限速。v0.3.4 的未认证失败限速同样按直连 IP：
   NAT 后达到阈值的合法 scoped token 可能收到 429；4096 个来源把失败表填满后，新来源
   （含合法 scoped token）在窗口内 429，旧 `admin_token` 仍可应急。管理口默认回环，
   非回环必须置于 VPN/防火墙后。
9. **控制面信任边界**：agent 是 systemd/Docker/进程动作的实际执行者与结果来源。拿到
   agent 证书 + secret 的主体可以伪造执行结果；hub 审计不能抵抗被控 agent。能力默认关闭、
   白名单与操作确认是主要防线（KI-25）。
10. `nginx*` 这类前缀白名单会匹配 `nginx-evil`；需要更精确时请写完整 unit 名或更细前缀。
    日志白名单文件的硬链接不会被 openat2 拦截（需日志目录写权限，KI-22）。
11. 升级 v0.3.2 时先升级 hub，再升级 agent。v0.3.1 hub 的 WebSocket 单帧上限仍是
    256 KiB；新 agent 发送超过 256 KiB 的控制结果仍可能被旧 hub 拒绝并断开会话。
12. v0.3.3 起非回环 `admin_listen` 必须 `admin_tls = "required"`，否则拒绝启动；
    远程 Panel 必须 `hub_url = "https://..."` + `hub_ca`（私有 CA）。管理证书 SAN
    不覆盖访问名时需先更新 `server_names` 并 `rotate-cert --force`。
13. 回滚到 v0.3.2 前必须先把 `admin_listen` 改回回环：旧二进制不认识 `admin_tls`，
    非回环时会按明文 HTTP 启动。scoped token 的 `api_tokens` 表可保留，旧二进制忽略。
14. #17 的吊销门禁是“检查后再投递”：revoke 提交前已通过会话侧最后一次检查的
    1 条在途命令仍可能执行（`dispatch` 写帧最多等 5s），审计按实际结果记录；
    revoke 之后新发起的请求一律 403。需要零窗口时应引入协议级可取消/租约，
    列入后续版本评估。
15. Hello 字段超过 WebSocket 单消息上限（1 MiB）时由帧层关闭（1009），客户端收不到
    `Problem(bad_frame)`；元数据校验覆盖帧上限内的字段，均不写库、不回显。
16. 同步 SQLite 写（Hello upsert、mark_seen 等）在 DB 被外部长时间持锁/慢盘时可阻塞
    hub 管理面；正常远程负载下未复现，后续可移入 `spawn_blocking` 并收紧 busy_timeout。
17. `database` 指向 `data_dir` 外或相对路径时 hub 仍启动：会打一次 WARN，DB 文件 0600、
    父目录不收紧；非默认配置建议把数据库放在专用 `data_dir` 内。
18. **KI-28（v0.4.1 已修复）**：单 IP 连接超限日志改为 60s 窗口首条 WARN、其余
    DEBUG；采样表 4096 IP 上限，拒绝行为不变。
19. **SFTP 密钥算法**：vendored 去掉 optional `rsa` 后，SFTP 不支持 RSA 主机密钥与
    RSA 用户私钥；仅支持 ed25519/ECDSA 主机密钥、ed25519 用户私钥。仅提供 RSA
    主机密钥的旧服务器会握手失败，配置仍接受 SHA256 指纹，部署前需确认算法。
20. **归档下载内存上限（v0.4.1 已收敛）**：`archive.max_object_bytes` 上限 64 MiB，
    下载硬限固定 64 MiB；已有 >64 MiB 旧对象不删除/不重传，列表
    `downloadable=false`，下载 413。流式下载仍留待 v0.5.0。
21. **直接 SQL 删除 raw 不受 prune 保护**：v0.4.1 的 rowid/generation CAS 只覆盖
    生产路径 `prune_samples_before`；运行中手工 `DELETE FROM samples` 绕过维护状态，
    仍可能造成迟到行漏算。生产/运维应使用 maintenance CLI。
22. **Phase A 服务以 root 运行**：配置/私钥要求 0600，systemd 用
    `NoNewPrivileges` + `ProtectSystem=strict` + 最小 `ReadWritePaths` 收紧；
    专用服务用户 + `LoadCredential` 在 Phase E 评估，未完成前不要把安装器用于
    不受信任的多用户主机。
23. **不要给 unit 加 `RestrictSUIDSGID=true`**：systemd 257 的该 seccomp 过滤器会让
    `openat2(2)` 返回 ENOSYS，而 `fsutil::ensure_private_dir` 以 openat2 做 fd 级
    校验并 fail-closed；`NoNewPrivileges` 已覆盖 setuid/setgid 提权。此为兼容性
    约束，新增 unit hardening 时必须用真实 systemd 验证。
24. **`--prefix` 必须是 root 拥有、非 sticky、group/other 不可写的路径**：
    安装器安全检查会拒绝 `/tmp`、`/var/tmp` 等共享前缀（除 unit 的
    `PrivateTmp=true` 会隐藏这两处外，也防止本地用户预置 state/符号链接）。
    e2e 使用 `/opt`；生产默认 prefix 为 `/`，不受影响。非 root prefix 下
    `--config`/`--data-dir` 必须位于 prefix 内；root prefix 只允许
    `/etc/rustboard`、`/var/lib/rustboard` 与 `/usr/local/bin/rustboard-*`。

## 磁盘清理记录

- **2026-10-24 安全窗口**（按 [AGENTS.md](../AGENTS.md) §12）：根分区
  `/dev/sda1` 从 **141G 已用 / 11G 可用（93%）** 降到 **68G 已用 / 84G 可用（45%）**，
  释放约 **73 GiB**。
- 清理：主仓库 `target/debug`、`target/v040-t1`；`.worktrees/*/target`；
  `web/node_modules`、`web/dist`、`.pnpm-store`。
- 保留：`target/baseline-bin`（3 个 v0.4.0 冻结二进制 + `SHA256SUMS`，校验 OK）、
  `.git`、源码、docs、vendor、`tests/pentest` 脚本与本地证据。
- 清理前确认无 cargo/rustc/rustboard/vite/pnpm 写目标目录；前端 dev 进程属于其他项目。

## 下一步建议

v0.4.1 已完成并发布；v0.4.2 修复 CI ANSI 测试助手，并把 vendored SFTP 依赖
升级到稳定 ECC 栈（crypto-bigint 0.7.6，RUSTSEC-2026-0387）。M5 Phase A 已完成
安装器内核与自签三步安装（e2e 121/121）；Phase B 已完成两架构静态 musl、离线包、
Docker/多架构与 tag 触发 release workflow 的本地验收。Phase C 的 ACME、agent TLS、
面板 TLS、管理端 TLS、Docker/文档已实现 C0–C8，当前待 C9 全量 e2e、独立评审/
渗透与 `v1.0.0-rc.1`，**尚未发布**；之后进入 Phase D（PostgreSQL/备份迁移），
v1.0.0 正式发布在 Phase E。
计划见
[M5 计划](plans/2026-10-24-m5-install-delivery.md)、
[Phase A 设计](plans/2026-10-24-m5-phase-a-installer.md) 与
[Phase B 交付计划](plans/2026-10-25-m5-phase-b-delivery.md)、
[Phase C 计划](plans/2026-10-25-m5-phase-c-tls-release-gates.md)。控制面/告警/归档均按
“默认关闭或最小暴露 + 审计/固定错误码”交付。
