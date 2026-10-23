# Changelog

本文件记录 RustBoard 的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

更新时机见 [AGENTS.md](AGENTS.md) 第 7 节：日常只往 `[Unreleased]` 追加条目，
**仅在里程碑发布时**归档为正式版本段落。

## [Unreleased]

### Added

- M4 降采样与查询选层：schema v7 新增 `samples_1m`/`samples_1h`/`maintenance_state`；
  `maintenance run|status`、迟到 raw 回放、1m/1h 水位与 `ArchiveGate`；面板按
  ≤6h raw / ≤7d 1m / >7d 1h 选层，跨度上限 730 天，桶过小自动提升
- M4 告警：内置 5 条规则（离线/磁盘/agent/hub 证书/缓冲）、规则 CRUD、
  pending→firing→resolved 状态机、事件、静默、后台评估（raw-only、每规则 5000
  序列/状态上限、5s 预算、每小时清理）
- M4 通知：Telegram / 企业微信 / 钉钉 / 飞书四渠道，固定端点、签名、3 次重试、
  有界 worker、首次启动不补发存量、按 `(rule,agent,series)` 冷却、发送前复查静默
- M4 面板 `/alerts`：规则/事件/渠道/静默四个 tab；渠道 secret 只写不读、测试发送
- M4 冷归档核心：`[archive]` 配置、CSV.gz/manifest、`ColdStore`、WebDAV 与 S3
  后端、按 UTC 天/分片 worker、`archive test|status|run`、retention 归档门禁
- M4-C2b/C4：S3 冷存储接入归档 worker / `archive test` / `archive run`；
  hub 新增 `GET /api/v1/archive/objects` 游标分页与
  `GET /api/v1/archive/objects/{id}/download`（read scope、64 MiB 内存上限、
  固定 502）；面板新增 `/archive` 数据页与 1 GiB 上限的流式下载代理
- M4 数据页：归档对象列表/下载、sha256/状态展示、`/archive` 页面

### Changed

- SQLite schema v7（纯新增表/列/索引）：降采样、告警、归档、渠道、维护水位；
  `alert_events` 增加 `series_key`，旧 v7 库启动时自动补列，不提升版本号
- MSRV 提升到 Rust 1.89（`object_store`/`time` 等实际依赖要求；CI 使用 stable）
- agent 新增 `disk.used_percent`、`buffer.pending_*`、`cert.hours_left`（保留
  `cert.days_left`）；内置证书阈值 48 小时、离线 90 秒，首次种入取配置
- 通知测试发送 `POST /api/v1/alerts/channels/{id}/test` 成功返回 204

### Fixed

- 归档下载内存安全：单对象下载上限降为 64 MiB（超限 413
  `archive_too_large`），读取用 1 permit 串行化且许可持有到响应 body 结束，
  `get` 后校验长度与 SHA-256；面板下载在 EOF 校验累计字节与
  `Content-Length`，短读让 body 报错
- 归档 `status` 的 `last_error` 改为固定码写入 + 读取精确白名单掩码，历史库里的
  URL / 凭据 / 路径 / 超长内容统一显示 `archive_error`
- 归档下载 body 增加 120s 发送期限：客户端不读 body 时由后台任务释放 64 MiB
  数据与下载许可，避免唯一 permit 永久阻塞；body drop 自动取消定时任务

### Security

- 通知渠道 secret 只在 SQLite `config_json` 与发送边界出现；API 只返回
  `secret_fields`/非敏感字段，错误与日志不含 token/secret/URL
- 归档读取/下载只接受合法对象 key，错误固定码；WebDAV Basic/S3 凭据只在配置中，
  不进入 API/前端
- 告警评估资源上限：raw-only 索引查询、每规则序列/状态 5000 上限、单轮预算、
  事件 100k/90 天、静默 1000/7 天
- SFTP 后端尚未实现：`russh` 依赖在 Rust 1.87+ 仍带 `rsa` medium advisory
  （RUSTSEC-2023-0071），审计 0 需 patch/vendor 或放弃；v0.4.0 不发布该后端，
  待维护者决策

### Known

- 归档 SFTP 未实现；WebDAV/S3 已接入，`archive.enabled` 但未配置后端时启动拒绝
- KI-29 降采样 rowid 复用边界（低风险，v0.4.1）


## [0.3.5] - 2026-10-24

### Added

- `tests/e2e/v035.sh` + `v035_agent.py`：KI-27 单 IP WebSocket 上限、data_dir
  中间符号链接拒绝、外置 database WARN、`limit=0` 首失败 WARN 回归（48 项）；
  `probe.py` 增加可选源地址绑定，用于模拟不同来源 IP

### Changed

- KI-27：TLS accept 取得的全局 `max_connections` 与 per-IP 许可通过
  `ConnectionGuards` 随请求扩展转交 WebSocket upgrade future，持有到会话结束；
  删除 v0.3.4 为弥补许可提前释放而增加的 `session_slots`，避免每条 WS 占用
  两个全局槽。超限在 TLS accept 阶段直接关闭 TCP，不再返回 503
- data_dir 目录创建/权限收紧在 Linux 上改为从 `/` 逐组件 `openat2` + 目录 fd +
  `mkdirat`/`fchmod`，关闭 validate→create/chmod 的路径替换窗口；祖先必须不可被
  非特权用户写，最终目录必须由当前 euid 拥有且无 sticky。默认
  `/var/lib/rustboard/{hub,agent}` 不受影响，非 Linux 仍保留静态路径检查
- `admin_auth_failure_limit_per_min = 0` 时仍保留每 IP 每 60s 窗口首条失败 WARN，
  后续降为 DEBUG；仅影响日志，不恢复 429
- `database` 不在 `data_dir` 下（含相对路径）时 hub 启动打一次 WARN，明确
  “父目录不收紧、DB 文件仍 0600”；不拒绝启动、不改变权限行为

### Fixed

- KI-27（中危）：同一来源 IP 可用合法 agent 证书建立任意数量 WebSocket，占满全局
  session slots，导致其他 agent 重连/新纳管 503
- data_dir 在他人可写祖先下仍存在 validate→create/chmod 本地 TOCTOU 的 v0.3.4
  残余问题；Linux 下改为 fd 级操作并有确定性路径替换单测
- `database` 外置时无显式告警，误配下难以发现父目录未被收紧

### Security

- 协议仍为 v2、SQLite schema 仍为 v6、证书格式不变，可滚动升级
- data_dir owner/祖先可写性校验比 v0.3.4 更严格：root 服务必须使用 root 拥有的
  最终目录，非 root 必须使用自己拥有的最终目录；使用他人 home 等目录的部署会
  拒绝启动，需要迁移到专用目录或改用服务用户运行
- 独立渗透（本地临时实例）无高危/中危；新登记低危 KI-28（连接拒绝 WARN 未采样，
  既有行为，计划 v0.4.0 处理）
- 回滚 v0.3.4 只回代码；已收紧的 0700/0600 权限保留，KI-27 风险回归

## [0.3.4] - 2026-10-23

### Added

- KI-26：管理 API 新增未认证失败限速 `admin_auth_failure_limit_per_min`
  （默认 60，0 关闭，最大 600）；同一来源 IP 超限返回 429 + `Retry-After`，
  超限路径不计算 SHA-256、不查 SQLite；旧 `admin_token` 保留应急旁路
- KI-18：`rustboard-panel reset-password` 后运行中的 Panel 在 ≤2s 内吊销全部已有会话；
  登录增加认证代际，重置瞬间在途的旧密码登录也不能在清空后新建会话
- `tests/e2e/v034.sh` + `v034_agent.py`：KI-26/18/19/21/24 与权限、日志脱敏回归（97 项）

### Changed

- KI-26：401 认证失败 WARN 按来源 IP、每 60s 窗口采样；429 固定
  `{"error":"rate_limited"}` 且不写审计。NAT / 反代共享来源 IP 时，阈值后的合法
  scoped token 也可能在窗口结束前收到 429，旧 `admin_token` 不受影响
- KI-19：Hello 的 `agent_id/name/hostname/os/arch/version/boot_id` 统一做 UTF-8
  字节长度与控制字符校验；非法帧固定 `Problem(bad_frame)` 并关闭，不写库/审计，
  日志不回显字段值
- KI-21：hub 启动设置私有 umask（Unix 0o077）；数据目录/证书目录 0700，
  SQLite 主库与 `-wal`/`-shm` 0600；已有过宽权限在启动时收紧。数据库位于
  `data_dir` 之外时不会 chmod 其父目录（DB 文件仍收紧）。`data_dir` 必须是
  本程序独占的绝对子目录（至少两级）：`/tmp`、`/var/tmp`、`/etc`、`/var/log`、`/` 等
  共享/系统目录、sticky 目录、相对路径、任一祖先或最终组件为符号链接、非 root 指向
  他人目录都会拒绝启动，防止误 chmod。该校验是启动时的静态检查；`data_dir`
  祖先必须不可被非特权用户写（推荐 root 拥有的专用目录），否则本地竞态仍可能
  在 validate→create/chmod 之间重定向路径
- KI-24：同一 agent 多连接的能力以最新连接为准；旧连接晚到的 Hello 不覆盖新连接，
  最新连接断开后回退到剩余最新已登记能力，全部断开保留历史能力
- 证书备份后缀改为 `<毫秒>-<8 位序号>-<pid>-<uuid>`，按 `(毫秒, 序号)` 而非
  UUID 字典序淘汰；旧 3 段格式仍识别，运维 CLI 的 2 段式备份不受影响

### Fixed

- KI-26 未认证 401 可无限驱动 SQLite 查询与 WARN 日志、放大 CPU/日志
- KI-18 密码重置后旧 Cookie 仍可使用到会话 TTL；并发登录在清空后可能复活旧密码会话
- KI-19 超长或含控制字符的 Hello 元数据被写入 agents 表与日志
- KI-21 SQLite 默认 0644、数据目录默认 0755，旧安装权限不会自动收紧；
  `data_dir` 指向 `/tmp`、`/etc`、`/` 等共享目录时会被误 chmod 0700
- KI-24 旧连接能力覆盖新连接、最新连接断开后能力陈旧
- 证书备份在同一毫秒连续生成时可能因 UUID 字典序误删刚创建的备份（测试偶发失败）

### Security

- 未认证管理请求达到阈值后按来源 IP 429，避免 401 放大；旧 `admin_token`
  仍作为应急入口，`admin_tls` 只加密不认证客户端，管理口仍应限制来源
- 密码重置即吊销全部面板会话，旧 Cookie 与重置瞬间在途的旧密码登录均不再有效
- Hello 元数据校验阻断日志注入与超长字段写入
- 数据目录/SQLite/SQLite sidecar 权限收紧，降低本机其他用户读取指标与哈希的风险；
  数据目录路径先经共享/系统目录、sticky、owner 校验，避免把 `/tmp`、`/etc`、`/` 改坏
- 协议仍为 v2、SQLite schema 仍为 v6、证书格式不变；hub/agent/panel 可滚动升级。
  回滚 v0.3.3 只需回代码，旧二进制忽略新配置；权限收紧不可逆但无害。
  `data_dir` 必须是独占绝对子目录（至少两级，祖先/最终组件不能是符号链接）；
  `data_dir`/`certs` 为符号链接的部署会 fail-closed，需要改为真实目录。证书目录 0700 后，同机以不同用户运行且直接读取 hub `ca.crt`
  的 Panel 需要复制 CA 或以同用户运行
- 已知未修复中危 **KI-27**（v0.3.5）：WebSocket 升级后 TLS 单 IP 许可提前释放，
  同一 IP 可占满全局 session slots；管理口默认回环可缓解管理面风险，但 agent 入口
  需限制已纳管证书的信任范围。v0.3.4 渗透未发现其他高危；KI-26 失败表满后的
  新来源 429、DB 位于 data_dir 外不告警、慢 DB 同步写阻塞等低危/权衡见 status.md

## [0.3.3] - 2026-10-23

### Added

- #9 管理 API scoped token：SQLite schema v6 `api_tokens`，`read` / `write` / `admin`
  三级权限；`rustboard-hub token create/list/rotate/revoke`；审计 actor 记录 token 名称，
  旧 `admin_token` 继续兼容并固定为 `admin`
- #9 管理端 TLS：`admin_tls = "off" | "required"`；`required` 复用 server.crt/server.key
  做 server-auth（不要求客户端证书），支持证书热加载
- Panel 支持 `https://` hub 与私有 CA `hub_ca`；配置私有 CA 时只信任该 CA
- #21 systemd 列表合并 `list-unit-files`，已安装但未加载的 service 以
  `not-loaded/inactive/dead` 出现在面板并可 start
- `tests/e2e/v033.sh`：scoped token、admin TLS、Panel HTTPS、#17/#20/#21 回归

### Changed

- 非回环 `admin_listen` + `admin_tls="off"` 现在拒绝启动（此前仅 WARN）；
  迁移方式：`admin_tls="required"` 或只绑回环 + TLS 反向代理
- 远程 Panel 的 `http://hub` 现在拒绝启动；改用 `https://` + `hub_ca`
- #20 日志文件打开改为从根 fd 对完整绝对路径单次 `openat2`，保留跨挂载点兼容
- #21 两次 `systemctl` 共享总超时；输出超过 256 KiB 时失败而不是返回截断列表

### Fixed

- #17 `agent revoke` 之后新发起的控制请求返回 403 `agent_revoked`、审计 `denied`；
  已进入会话的最后 1 条在途命令仍可能执行（写帧最多等 5s），审计按实际结果记录
- #20 日志父目录在启动校验后被替换为符号链接的 TOCTOU 窗口
- #21 已安装未加载的 systemd service 在面板不可见、无法 start
- token CLI 的 stdout 与日志分离（日志固定 stderr），避免脚本捕获 token 时混入日志

### Security

- scoped token 只存 SHA-256 哈希，明文仅 `create/rotate` 输出一次；`admin` 为审计
  actor 保留名，禁止作为 token 名称
- 管理端 HTTPS 与非回环明文拒绝、Panel 私有 CA 严格信任，关闭非回环管理面明文路径
- 升级顺序：先升级 hub 到 v0.3.3（自动迁移 DB v6），再按需启用 `admin_tls`；
  Panel 最后升级并使用 `https://` + `hub_ca`。旧 `admin_token` 仍可用
- 回滚到 v0.3.2 前必须先把 `admin_listen` 改回回环：旧二进制不识别 `admin_tls`，
  非回环配置会按明文 HTTP 启动
- 已知中危 KI-26（计划 v0.3.4）：未认证 401 不受管理限速，错误 token 可驱动
  SQLite 查询与 WARN 日志；管理口默认回环，非回环必须置于 VPN/防火墙后，
  `admin_tls` 只加密不认证客户端

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
- 升级顺序：先升级 hub 到 v0.3.2，再升级 agent。v0.3.1 hub 的单帧上限仍是 256 KiB，
  新 agent 发送超过 256 KiB 的控制结果仍可能被旧 hub 拒绝并断开会话
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
