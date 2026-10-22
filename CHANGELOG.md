# Changelog

本文件记录 RustBoard 的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

更新时机见 [AGENTS.md](AGENTS.md) 第 7 节：日常只往 `[Unreleased]` 追加条目，
**仅在里程碑发布时**归档为正式版本段落。

## [Unreleased]

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
