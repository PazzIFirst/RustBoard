# Changelog

本文件记录 RustBoard 的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

更新时机见 [AGENTS.md](AGENTS.md) 第 7 节：日常只往 `[Unreleased]` 追加条目，
**仅在里程碑发布时**归档为正式版本段落。

## [Unreleased]

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
