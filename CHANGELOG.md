# Changelog

本文件记录 RustBoard 的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

更新时机见 [AGENTS.md](AGENTS.md) 第 7 节：日常只往 `[Unreleased]` 追加条目，
**仅在里程碑发布时**归档为正式版本段落。

## [Unreleased]

### Added

- M1 骨架：`rustboard-{common,core,agent,hub,panel}` 五 crate workspace
- 指标采集：CPU（含每核与 load average）、内存/Swap、磁盘容量与 inode、
  磁盘 IO（await/util 差分）、网卡 8 项计数器、系统辅助指标
- 本地磁盘缓冲：追加日志、已确认偏移持久化、超限丢弃最旧、损坏尾部自愈
- 传输：TLS 1.3 + 私有 CA，agent 首次连接使用服务端证书 SHA-256 指纹钉扎
- 纳管：一次性 enrollment token（30 分钟、单次使用）→ CSR → 90 天客户端证书 + 每机独立 secret
- 吊销：清除 secret、状态锁死 `revoked`，重连被拒
- 存储：SQLite WAL，批次在 `(agent_id, epoch, seq)` 上幂等
- 只读 API：`/healthz`、`/api/v1/agents`、`/api/v1/series`
- 随机五位数端口（20000–64999），支持自定义；`rustboard-hub ports`、
  `rustboard-panel ports`、`rustboard-agent info` 随时查看
- hub 本机采集（`agent_id = hub-self`，本地直写，不经过网络）

### Changed

- `rustboard-hub agent add` 生成的安装命令自动带上当前端口与 hub 地址；
  hub 地址默认探测出口 IPv4，可用 `--advertise` 覆盖

### Fixed

- agent 空缓冲时只能等 15s 心跳才上传新数据，改为写入即唤醒
- agent 断开后状态未更新，现置为 `offline`，且不覆盖 `revoked`

### Security

- 未携带客户端证书的连接只允许发送 `Enroll`
- 证书与私钥文件权限 0600
- SQL 全部使用参数化查询

### Known limitations

- 客户端证书不会自动轮换（90 天到期需重新纳管）
- 面板、控制面、告警、ACME、PostgreSQL 尚未实现
