# Changelog

本文件记录 RustBoard 的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

更新时机见 [AGENTS.md](AGENTS.md) 第 7 节：日常只往 `[Unreleased]` 追加条目，
**仅在里程碑发布时**归档为正式版本段落。

## [Unreleased]

## [0.3.2] - 2026-10-23

### Added

- 控制面新增 `control_result_too_large` 错误码与 agent 发送前编码预算：超过
  1 MiB−4 KiB 的控制结果改为固定小错误，保留请求 id，不再让 Hub 因 WS 帧/消息超限关闭会话
- `tests/e2e/v032.sh` + `v032_agent.py`：66 项断言，覆盖 #18 pending 清理、#16
  `busy_renewing` Hub 映射、#19 journald 尾部保留与真实大帧传输
- 面板控制错误 `control_result_unknown` 的前端文案：结果未知、动作可能已执行、
  不要直接重试，先核对状态

### Changed

- 面板控制 POST 使用 70s 专用上游超时（普通 GET/PUT 仍 30s），严格大于 Hub 最大 60s 控制等待
- Hub WebSocket 单帧上限从 256 KiB 提升到 1 MiB，与消息上限一致；内存边界不变
- journald tail 改用 `journalctl --reverse` 后反转行序，截断时保留最新内容并丢弃最旧半行；
  `size_bytes` 表示实际保留的 stdout 字节数
- 控制 pending 记录改为 `{reply, deadline}`，会话每秒清理到期项；清理 timer 优先于
  入站消息与控制命令，避免 pending 长期占用配额

### Fixed

- #18 控制 HTTP 超时后 pending 不清理，连续请求会被历史上限永久变成 429
- #16 证书续签等待期间 ControlRequest 被静默丢弃；现在立即回 `busy_renewing`
  （Hub 503、审计 error）
- #15 Panel 30s 超时短于 Hub 60s，命令可能已执行但面板报网络错误；现在返回
  504 `control_result_unknown`
- #19 journald 输出超 256 KiB 时保留最早内容、丢失最新日志；现在保留最新并恢复旧→新顺序
- 约 256 KiB 控制结果经 MessagePack 编码后超过旧 256 KiB 单帧上限，agent 会话被踢下线
- 45s 会话空闲超时被每秒控制清理 timer 重置，静默连接永不关闭

### Security

- 控制应答编码预算（1 MiB−4 KiB）与 Hub 1 MiB WS 消息上限留出余量；超限只丢结果并回
  `control_result_too_large`，不关闭会话，避免控制动作已执行却返回 `agent_offline`
- v0.3.2 未实现 #9 的 scoped token / 管理端强制 TLS；#9/#17/#20/#21 仍 open

## [0.3.1] - 2026-10-23

### Added

- 管理 API 与面板的 HTTP accept 层：5s header 读超时、10s 请求体总超时、全局 256 / 每来源 IP 32 并发连接上限，
  超限立即关闭 TCP；半截 header 的慢连接不再长期占用 fd（KI-17）
- agent 配置 `send_timeout_secs`（默认 15，范围 1–120）：Hello / Batch / Ping / Pong / 续签 /
  控制应答 / Enroll / close 的每次 WebSocket 写都有独立超时
- 服务端证书**仅因过期**时的启动自愈：持 `CertLock` 用当前 CA 重签、成对备份、自检失败回滚；
  CA/SAN/CN/密钥异常仍拒绝启动
- 会话注册表新增 `unregister_last_and_run`：最后一条连接注销与 offline/revoked 单行写库
  在 per-agent slot 锁内原子完成
- DiskBuffer 物理文件压实水位、淘汰偏移原子持久化、重启后重新限额；新增确定性崩溃注入测试
- 新增 `tests/e2e/v031.sh`：#13 过期证书启动自愈 + 原 agent 自动重连、KI-17 管理口/面板慢连接

### Changed

- 管理 API 与面板改为手工 `hyper` HTTP/1 accept + `TowerToHyperService`，不再使用无 header
  超时/无连接上限的 `axum::serve`；请求体套一次性 10s deadline（不随 frame 重置），
  `ConnectInfo` 逐请求注入，限速与可信代理行为不变
- agent 会话内证书续签遇到**发送超时**时结束当前会话并重连；普通续签失败仍只告警
- `SessionCleanup` 不再“先注销、再 has_active、再写 offline”；状态写入与同 agent 新连接注册串行化
- DiskBuffer 压实改为 rename 前先打开新文件句柄，避免 rename 后打开失败仍持有旧 inode
- 发布门槛更新：单元/集成 420 个，hardening 34 项、v031 94 项、security/panel/cert/control 全量回归

### Fixed

- Agent 本地缓冲物理文件可无限增长、淘汰偏移未落盘、重启后已淘汰记录复活（#10）
- Agent 对端停止读取时 WebSocket 写可永久挂起，`session_max_hours=0` 无兜底（#12）
- 服务端证书过期导致 hub 启动失败、自动续签任务无法运行（#13）
- 旧会话清理可把新会话的 `online` 覆盖成 `offline`（#14）
- 管理 API / 面板无 header 超时与连接上限，慢速连接可耗尽 fd（KI-17）

### Security

- 复验 #11：非法/超长/9 跳 `X-Forwarded-For` 返回 400；不可信直连来源伪造 XFF 不影响限速分桶；
  锁定一个可信客户端不影响其他客户端（hardening 7.6–7.10）
- #9 的 Bearer 鉴权、弱 token 拒绝、未知 API 先鉴权、非回环告警由本轮 hardening 再次验证；
  **scoped read/write token 与管理端强制 TLS 仍未实现**，不宣称 #9 全部完成

## [0.3.0] - 2026-10-23

### Added

- M3 控制面：systemd / Docker / 进程 / 只读日志四个模块，全部默认关闭，安装/配置时逐项开启
- agent 控制配置 `[control]`：能力开关、systemd unit 白名单、Docker 容器白名单、
  日志来源（journald / 白名单文件）、命令超时与日志行数上限
- hub 控制配置 `[control]`：总开关、四项能力开关、请求超时、每会话 pending 上限、输出上限
- 线协议新增 `ControlRequest` / `ControlResponse` 帧（协议版本仍为 2；只在能力协商后发送，
  旧 hub/旧 agent 完全兼容）
- 管理 API：`GET/POST /api/v1/agents/{id}/control`、`GET /api/v1/audit`
- 面板控制台 `/agents/:id/control` 与审计页 `/audit`（systemd/Docker 操作、进程结束、
  日志 tail、审计分页过滤）
- SQLite schema v5：`agent_control`、`audit_log`（180 天保留）
- 审计记录成功/拒绝/失败/超时，actor 固定 `admin`；非 0 退出码与信号终止都记 error

### Changed

- 进程列表按 PID 降序（新进程优先）截断 200 条，保证刚启动的进程可见
- 面板控制/审计 API 走同源代理，浏览器仍不接触 hub Bearer token
- 控制动作全部使用固定枚举与参数数组，无 shell；systemd/docker 只允许 start/stop/restart，
  进程只允许 SIGTERM/SIGKILL

### Security

- 控制面双端能力校验：hub 发送前核对配置 + agent 上报能力，agent 执行入口再次校验
- systemd 禁止 `sshd` / `rustboard-*` / `sd-*` / `systemd-*` / `dbus*`；裸 `*` 拒绝
- 日志文件使用 Linux `openat2`（RESOLVE_BENEATH/NO_SYMLINKS/NO_MAGICLINKS/NO_XDEV），
  拒绝符号链接/目录/设备/FIFO；ENOSYS 不降级
- 进程结束使用 `pidfd_open` + `pidfd_send_signal` 固定目标，PID+comm 双重校验；
  旧内核无 pidfd 时保守回退 `kill(2)`
- 审计不记录命令输出/stderr；agent 错误 message 不回显
- 明确信任边界：agent 是控制动作的执行者与结果来源，hub 审计不能抵抗被控 agent 伪造

## [0.2.1] - 2026-10-23

### Added

- 管理 API 每 IP 固定窗口限速：读 60 req/min、写 10 req/min，429 + `Retry-After`；
  `admin_rate_limit_per_min` / `admin_write_rate_limit_per_min` 可配置（0 关闭）
- agent 接入层每来源 IP 并发连接上限 `max_connections_per_ip`（默认 16）
- 面板可信反代配置 `trusted_proxies`、`cookie_secure`（auto/always/never）与 `public_origin`；
  只有可信来源的 `X-Forwarded-For` / `X-Forwarded-Proto` 才会被采信
- `rustboard-panel reset-password`：重新生成管理员密码并写回配置（0600），解决初始密码只显示一次
- `/api/v1/system` 同时返回 `cert.live`（监听器实际证书）与 `cert.disk`（磁盘证书），顶层字段保持旧语义
- 运行中 `rotate-cert` 后 ≤10s 自动热加载，无需重启；`rotate-cert` 增加进程间文件锁
- agent 配置 `cert_check_interval_hours`（默认 6）：超长会话也会周期检查客户端证书续签窗口

### Changed

- hub 的 TLS 握手与 HTTP header 读取超时从 10s 收紧到 5s
- 面板登录/登出限速键改用可信代理解析后的客户端 IP；`Secure` 只由可信代理声明或显式配置决定
- 面板变更请求增加 Origin 同源校验（无 Origin 时必须为 JSON）
- `admin_token` 增加字符集/多样性/占位符校验；v0.2 生成的 64 位 hex token 保持兼容

### Fixed

- SQLite 读路径改为独立只读连接池（默认 4 条），大查询不再阻塞写入与心跳刷新
- 未知 `/api/v1/*` 先 Bearer 鉴权再返回 404，避免泄露路由存在性
- 面板初始密码丢失后只能手改配置的问题
- 运行中 `rotate-cert` 后 `/api/v1/system` 显示磁盘新证书、监听器仍用旧证书的不一致
- `session_max_hours=0` 时客户端证书续签窗口可能被错过的问题

### Security

- 单 IP 空闲连接洪水不能挤占合法 agent 的入口连接；连接计数归零清理、来源表有上限
- 管理 API 的弱 token 拒绝启动；管理端口非回环时启动告警
- 面板不可信来源伪造 `X-Forwarded-For` / `X-Forwarded-Proto` 不再影响限速分桶与 Cookie 安全属性
- `rotate-cert` 并发执行被文件锁拒绝，避免 key/cert 交错写坏

## [0.2.0] - 2026-10-23

### Added

- M2 面板：React + TypeScript + Vite 前端（登录、概览、单机详情四类图表、时间范围与拖拽缩放）
- 面板后端：Argon2id 单管理员登录、HttpOnly 会话 Cookie、按 IP 登录限速、
  服务端代理 hub 管理 API（token 不下发浏览器）、静态资源与 SPA 回退
- hub 管理 API 鉴权：`admin_token`（Bearer），`/healthz` 除外；
  `rustboard-hub admin-token` 查看/补生成
- 管理 API：`overview`、`agents/{id}/latest`、多指标 `agents/{id}/series`
  （服务端按时间跨度自动分桶）、`agents/{id}/settings`
- 采样间隔动态下发：面板修改后 hub 落库并向活跃会话发送 Reconfigure，
  agent 在 ≤2s 内采用新间隔（采集循环分片休眠）
- SQLite schema v4：`agent_settings`（每台 agent 的采样间隔）
- 证书显式有效期：CA 3650 天、服务端 365 天、客户端 90 天，均可通过配置 / `hub init` 参数调整
- 服务端证书自动续签：剩余寿命低于 `renew_before_days` 时用私有 CA 重签、原子落盘，
  通过 `watch` 通道热加载，新连接立即使用新证书，无需重启
- 客户端证书自动轮换：agent 在剩余寿命低于阈值时通过已认证会话提交 CSR（复用私钥），
  hub 强制以会话身份作为 CN 签发；`rustboard-agent renew` 可手动强制轮换
- 运维命令：`rustboard-hub rotate-cert`（成对备份旧 key/cert）、
  `rustboard-agent cert-info`、`GET /api/v1/system`（证书指纹与到期时间）
- agent 纳管后改用 CA 信任 + 主机名校验；服务端证书轮换不再需要重新纳管
  （v0.1 指纹钉扎 agent 需先升级，见升级提示）
- 崩溃自愈：续签中途断电留下 key/cert 不匹配时，hub 启动会用 CA 重新签发一对；
  重签前校验 ca.key/ca.crt 配套、新证书链与 SAN，失败不覆盖旧材料

### Changed

- 面板默认只监听 `127.0.0.1`（明文 HTTP），对外访问必须显式 `--listen` 并走 VPN/反代
- 管理 API 必须携带 `admin_token`；v0.1 配置缺少该字段时需运行 `rustboard-hub admin-token`
- 管理 API 的 500 响应统一为 `{"error":"internal_error"}`，内部细节只进日志
- TLS 版本显式固定为 1.3（不再依赖 feature 默认值）
- agent 会话最长存活 `session_max_hours`（默认 12 小时，±10% 抖动）到点主动重连，
  让轮换后的证书与 hub 配置变更生效
- `rustboard-hub init` 新增 `--ca-days`、`--server-cert-days`、`--client-cert-days`、
  `--renew-before-days`

### Security

- 面板 → hub 的 HTTP 客户端禁用环境代理（`HTTP_PROXY`/`ALL_PROXY`），避免 Bearer token 泄露
- 面板 `/api/*` 强制 JSON Content-Type 与 CSP，避免上游 HTML 在面板 origin 执行
- 证书签发/续签前校验 ca.key 与 ca.crt 配套、新证书链与 SAN；失败不落盘
- 管理 API Bearer scheme 大小写不敏感，token 仍常量时间比较

### Fixed

- 证书未设置有效期（实际到 4096 年）的问题
- `rotate-cert` 只备份证书、不备份私钥导致无法回滚的问题
- 续签写盘中断后 hub 因 `KeyMismatch` 无法启动的问题
- 服务端证书轮换后仍靠指纹钉扎的旧 agent 失联问题（v0.2 agent 已改用 CA 信任）
- 面板采样间隔在旧间隔较长时无法在 60s 内生效的问题

## [0.1.0] - 2026-10-23

### Added

- M1 骨架：`rustboard-{common,core,agent,hub,panel}` 五 crate workspace
- 指标采集：CPU（含每核与 load average）、内存/Swap、磁盘容量与 inode、
  磁盘 IO（await/util 差分）、网卡 8 项计数器、系统辅助指标
- 本地磁盘缓冲：追加日志、已确认偏移持久化、超限丢弃最旧、损坏尾部自愈；
  新增 24h 时间上限（与 500MB 上限取先到者），避免离线过久的数据撑大判重窗口
- 传输：TLS 1.3 + 私有 CA，agent 首次连接使用服务端证书 SHA-256 指纹钉扎
- 纳管：一次性 enrollment token（30 分钟、单次使用）→ CSR → 客户端证书 + 每机独立 secret
- 吊销：清除 secret、状态锁死 `revoked`，重连被拒
- 存储：SQLite WAL，批次在 `(agent_id, epoch, seq)` 上幂等
- 只读 API：`/healthz`、`/api/v1/agents`、`/api/v1/series`
- 随机五位数端口（20000–64999），支持自定义；`rustboard-hub ports`、
  `rustboard-panel ports`、`rustboard-agent info` 随时查看
- hub 本机采集（`agent_id = hub-self`，本地直写，不经过网络）
- 测试体系：八类测试矩阵（评审 / 静态分析 / 单测 / fuzz / 故障注入 / 并发 / 长稳 / 供应链）
  与分阶段执行规则，见 `AGENTS.md` §8
- CI：`.github/workflows/ci.yml` 跑 fmt、clippy、test 与 `cargo audit`
  （push / PR / 每周定时），并作为发布门槛
- `ingest_batches` 表：按 `(agent_id, epoch, seq)` 精确判重，48 小时自动清理
- hub 配置项 `max_connections`（默认 1024）：agent 接入层并发连接上限

### Changed

- **线协议从 v1 提到 v2**：hub 与 agent 必须严格一致；版本不符时 hub 回
  `bad_protocol` 且不下发 Welcome
- `rustboard-hub agent add` 生成的安装命令自动带上当前端口与 hub 地址；
  hub 地址默认探测出口 IPv4，可用 `--advertise` 覆盖

### Fixed

- **#1** 已纳管 Agent 可在自己会话里提交他人 `agent_id` 的批次，造成跨机数据伪造；
  现强制 `batch.agent_id == 会话身份`，`hub-self` 禁止网络侧声明
- **#2** mTLS 未绑定身份：无客户端证书的连接也能建立正式会话；现无证书只允许 `Enroll`，
  正式会话必须携带 CA 签发的证书且 `CN == agent_id`
- **#3** 重启后旧 epoch 的高 `seq` ACK 会误删新 epoch 的低 `seq` 缓冲；
  `Ack` 增加 `epoch`，`DiskBuffer::ack(epoch, seq)` 只推进同 epoch 前缀
- **#4** 跨 epoch 重放（A→B→A）会重复入库；`ingest_state` 主键改为
  `(agent_id, epoch)`，并带 v1→v2 迁移
- **#5** 吊销后既有连接仍可继续上传；hub 每 2s 检测并关闭活跃会话，
  入库事务内复核吊销状态
- **#6** 配置/私钥先创建后 chmod，存在明文窗口；改为创建即 0600 的原子替换，
  目录 0700
- **#7** 异常断线后状态可能长期显示 online；统一清理 guard + 45s 心跳超时 +
  多连接接管判断
- **#8** `diskio.await_ms` 误用设备忙碌时间；改用读/写 ticks 差分
- **H1** 协议版本没有门禁：hub 现在对 Hello/Enroll 严格校验协议版本，
  不符回 `bad_protocol`（「需要 agent ≥ 2」）且不发 Welcome；agent 视为致命错误，
  打印明确日志后非零退出，不再每秒重连
- **H2** 传输层慢速攻击与连接上限：HTTP/1 请求头读取超时 10s、WebSocket 入口
  `http1_only`、并发连接信号量（默认 1024，可配置）、`TCP_NODELAY`，
  保留 10s TLS 握手超时
- **H3** `atomic_write` 临时文件改为随机名 + `create_new + O_NOFOLLOW`，
  冲突最多重试 16 次；目标 / 临时路径是符号链接时拒绝写入；
  `ensure_dir` 不再跟随符号链接
- **M1** revoked 会被 `mark_seen` / `upsert_agent` 覆盖回 online；两处 SQL
  均改为保留 revoked 终态
- **M2** 跨 epoch 乱序 `seq` 被水位误判为 Duplicate 导致丢数据；
  新增 `ingest_batches` 按 `(agent_id, epoch, seq)` 精确判重，判重 TTL 以 hub 接收时间计、48h；
  改用 `ingest_batches` 精确判重，水位仅作统计，迁移版本 `user_version=3`
- **M3** 既有 0644 配置 / 私钥不会收紧；新增 `fsutil::harden`，
  读取配置、agent secret/key、hub 服务端私钥前自动收紧到 0600 并告警
- **M4** `send_frame` 无写超时导致会话卡死；所有 WebSocket 发送（含
  `reject_and_close` 的 Close 帧）统一 15s 超时并走清理路径
- **L2** `revoke_agent` 的三条 SQL 改为同一事务
- **L3** 迁移先 `BEGIN IMMEDIATE` 再读版本；建表用 `IF NOT EXISTS`，
  迁移前清理残留的 `ingest_state_v2`
- **L4** `await_ms` 逐项检查 read_ops / read_ticks / write_ops / write_ticks，
  任一回退都放弃样本
- **L5** hub 启动监听前把残留的 `online` 重置为 `offline`（保留 revoked）
- **L6** `Frame` 的 Debug 只输出变体名，日志不再可能打印 Hello/Enroll/Enrolled
  中的 secret、token 或 CSR
- **MSRV** 测试里的 `unsafe extern "C"` 改用 `libc::umask`，兼容 rust-version 1.80
- agent 空缓冲时只能等 15s 心跳才上传新数据，改为写入即唤醒
- agent 断开后状态未更新，现置为 `offline`，且不覆盖 `revoked`

### Security

- 未携带客户端证书的连接只允许发送 `Enroll`
- 私钥 / secret / 配置 0600，证书 0644；既有宽权限文件读取前自动收紧
- 协议版本严格一致，拒绝旧协议连接
- 原子写拒绝符号链接目标与临时路径，防止敏感文件被劫持写入
- SQL 全部使用参数化查询

### Known limitations

- 证书未设置有效期（`notAfter` 到 4096 年），也不会自动轮换；泄露后需 `agent revoke`
- 面板、控制面、告警、ACME、PostgreSQL 尚未实现
