# 已知问题清单

> 维护规则：新问题分配 `KI-<两位序号>`，必须写清「现象 / 影响 / 复现 / 根因 / 修复方案 / 验收标准」。
> 修复后在条目里补「修复版本 + 提交/PR + 回归测试」，状态改为 `已修复`；不要删除历史条目。
> 设计取舍与部署限制单独放在 [status.md](status.md#已知限制)，本文件只跟踪**可修复的缺陷**。
>
> 最后更新：2026-10-24

## 状态与级别

| 状态 | 含义 |
|---|---|
| 待修复 | 已确认，尚未排期或尚未开始 |
| 修复中 | 有分支/PR 正在处理 |
| 待验证 | 代码已合并，等待独立复测 |
| 已修复 | 复测通过并记录回归用例 |
| 不修复 | 设计取舍或环境限制，需在 status.md 说明 |

级别沿用评审口径：**严重**（安全/数据丢失/协议不兼容）、**中**（可远程触发或明显影响可用性）、**低**（需要额外前提或影响有限）。

## 总览

| ID | 级别 | 模块 | 状态 | 目标版本 | 摘要 |
|---|---|---|---|---|---|
| KI-01 | 中 | hub 接入层 | 已修复 | v0.2.1 | 未认证 TCP 连接可占满 `max_connections`，导致 agent 入口拒绝服务 |
| KI-02 | 中 | SQLite 存储 | 已修复 | v0.2.1 | 单连接全局锁，大查询会阻塞写入与心跳刷新 |
| KI-03 | 中 | panel 认证 | 已修复 | v0.2.1 | 反代后登录限速按直连 IP 统计；`X-Forwarded-Proto` 可伪造 Secure 判定 |
| KI-04 | 低 | hub 管理 API | 已修复 | v0.2.1 | `admin_token` 只校验长度，不校验字符集与最低熵 |
| KI-05 | 低 | hub 管理 API | 已修复 | v0.2.1 | 除登录外没有全局限速，Bearer 泄露后可高速爆破/读取 |
| KI-06 | 低 | hub 配置 | 已修复 | v0.3.3 | 管理端口显式监听 `0.0.0.0` 只有 INFO；v0.2.1 加 WARN，v0.3.3 起非回环 + `admin_tls=off` 拒绝启动 |
| KI-07 | 低 | panel Web | 已修复 | v0.2.1 | 变更请求没有 Origin/CSRF 校验，依赖 SameSite=Lax 单层防护 |
| KI-08 | 低 | hub 管理 API | 已修复 | v0.2.1 | 未知 `/api/v1/*` 在鉴权前直接 404，泄露路由存在性 |
| KI-09 | 低 | 初始化 | 已修复 | v0.2.1 | 面板初始密码只打印一次，丢失后只能手工改配置 |
| KI-10 | 低 | 证书轮换 | 已修复 | v0.2.1 | 运行中 `rotate-cert` 不生效；`/api/v1/system` 报磁盘证书而非监听器实际证书 |
| KI-11 | 低 | 证书轮换 | 已修复 | v0.2.1 | 并发执行 `rotate-cert` 没有文件锁，可能交错写坏 key/cert |
| KI-12 | 低 | agent 证书 | 已修复 | v0.2.1 | `session_max_hours=0` 且连接超长时，客户端续签检查只发生在握手 |
| KI-17 | 中 | hub/panel HTTP | 已修复 | v0.3.1 | 管理 API / 面板监听没有 header 读超时与连接上限，未认证慢速连接可长期占 fd |
| KI-18 | 低 | panel 会话 | 已修复 | v0.3.4 | `reset-password` 不吊销已有会话 Cookie；v0.3.4 起密码变化后 ≤2s 清空全部会话 |
| KI-19 | 低 | hub Hello | 已修复 | v0.3.4 | `name` / `os` / `arch` / `version` / `boot_id` 未做长度与控制字符校验；v0.3.4 起统一 `bad_frame` 拒绝 |
| KI-20 | 低 | 安装命令 | 待修复 | v0.3.1 | `agent add --name` 打印的安装命令未对 name 做 shell 转义 |
| KI-21 | 低 | 文件权限 | 已修复 | v0.3.4 | SQLite 数据库默认 0644、数据目录 0755；v0.3.4 起数据目录 0700、DB/WAL/SHM 0600 |
| KI-22 | 低 | 控制面日志 | 待修复 | v0.3.1 | 白名单日志文件的硬链接不会被 openat2 拦截（需目录写权限） |
| KI-23 | 低 | 控制面白名单 | 不修复 | 文档 | `nginx*` 前缀会匹配 `nginx-evil`；这是前缀通配语义，部署时需写更精确的模式 |
| KI-24 | 低 | 控制面能力 | 已修复 | v0.3.4 | 同 agent 多连接时能力缓存可被新 Hello 覆盖；v0.3.4 起以最新连接为准并支持断开回退 |
| KI-26 | 中 | 管理 API 认证 | 已修复 | v0.3.4 | 未认证 401 不受管理限速；v0.3.4 起按来源 IP 失败限速，超限 429 且不查库 |
| KI-27 | 中 | hub 接入层 | 已修复 | v0.3.5 | WebSocket 升级后 TLS 单 IP 许可提前释放；v0.3.5 起全局 + per-IP 许可持有到会话结束 |
| KI-25 | — | 审计信任边界 | 不修复 | 文档 | agent 是控制动作执行者与结果来源，被控 agent 可伪造成功；审计不能抵抗 |
| KI-13 | — | agent 升级 | 不修复 | 文档 | v0.1 agent 使用指纹钉扎，服务端证书轮换后会失联 |
| KI-14 | — | 客户端轮换 | 不修复 | 文档 | 续签复用原私钥，无法补救私钥泄露 |
| KI-15 | — | 服务端证书 | 不修复 | 文档 | 给 `server_names` 新增 SAN 后必须先 `rotate-cert` 才能启动 |
| KI-16 | — | 采集器 | 不修复 | 文档 | 首次采集只建立差分基线，不上报 |

## 详细条目

### KI-01 未认证连接耗尽连接池

- **现象**：攻击者与 agent 端口建立 1024 条 TCP 连接后不发送 ClientHello，10s 握手超时前所有 `max_connections` 许可被占满；合法 agent 的新连接被直接关闭。
- **影响**：单机即可让 agent 入口拒绝服务；hub 仍存活，但所有 agent 掉线并进入重连退避。
- **复现**：`for i in $(seq 1024); do nc -z <hub> <agent_port> & done` 后新开 TLS 连接，服务端日志出现 `agent 连接数已达上限`。
- **根因**：连接许可只在 accept 后按全局计数，没有来源 IP 维度；TLS 握手超时 10s，慢速连接持有许可时间过长。
- **修复方案**：
  1. 增加按来源 IP 的并发连接上限（默认 16，可配置），超限立即关闭 TCP；
  2. 全局未认证阶段保留槽位：预认证连接最多占 `max_connections` 的一半，剩余槽位留给完成 TLS 握手的会话；
  3. 将 TLS 握手与 HTTP header 超时收紧到 5s；
  4. 记录被限流的来源 IP 与计数（不记录端口）。
- **验收标准**：
  - 单 IP 打开超过上限的空连接时，新连接被立即关闭，已有合法会话不受影响；
  - 全局预认证槽位耗尽后，已完成握手的 agent 仍能建立会话（在总上限内）；
  - 断开连接后计数正确回落，长时间运行不泄漏 map 条目；
  - e2e 覆盖单 IP 限流与合法 agent 重连。
- **关联**：status.md 已知限制 7；v0.2.0 渗透报告 F1。

### KI-02 SQLite 单连接阻塞写入

- **现象**：`SqliteStorage` 只有一个 `Mutex<Connection>`；面板查询 32 天 × 20 指标的分桶 SQL 时，agent 批次入库、心跳刷新 `last_seen_at`、吊销检查都要排队。
- **影响**：大查询期间写入延迟升高，批次 ACK 变慢，极端情况下触发 agent 20s ACK 超时并断线重连。
- **根因**：读路径与写路径共用同一把全局锁；WAL 允许多读者，但实现没有利用。
- **修复方案**：
  1. 写连接保持单连接 + 事务；
  2. 增加只读连接池（默认 4 条，`PRAGMA query_only=ON`），读方法轮询取连接；
  3. 内存库测试用共享缓存 URI 保持多连接看到同一份数据；
  4. 对读查询保留 `busy_timeout`，不引入新的全局锁。
- **验收标准**：
  - 一个长查询执行期间，`insert_batch` 与 `mark_seen` 能在 200ms 内完成（测试用可注入的慢查询/大表验证）；
  - 读连接池数量可配置且有上限；池耗尽时排队而不是报错；
  - 现有 222 个测试与 e2e 全部通过，schema 不变。
- **关联**：status.md 已知限制 5；v0.2.0 渗透报告 F2。

### KI-03 反代部署的登录限速与 Secure Cookie

- **现象**：面板登录限速使用 `ConnectInfo` 的直连 IP；部署在 nginx/Caddy 后所有用户共享反代 IP，攻击者 5 次失败即可让全体用户被锁 15 分钟。另一方面，`X-Forwarded-Proto` 由客户端可伪造，面板据此决定 `Secure` 属性。
- **影响**：反代场景下可远程锁定管理员登录；Secure 判定不可信，HTTPS 部署可能下发非 Secure Cookie。
- **根因**：没有「可信反代」概念；安全属性依赖未认证的请求头。
- **修复方案**：
  1. 新增 `trusted_proxies`（精确 IP/CIDR）与 `cookie_secure`（`auto` / `always` / `never`）配置；
  2. 仅当直连对端在可信列表内时，才取 `X-Forwarded-For` 最右侧非可信地址作为客户端 IP；否则一律用直连 IP；
  3. `cookie_secure=always` 时无条件加 Secure；`auto` 仅在可信反代声明 https 时加；
  4. 文档给出 nginx/Caddy 的可信代理配置示例。
- **验收标准**：
  - 不可信来源伪造 `X-Forwarded-For` / `X-Forwarded-Proto` 不影响限速键与 Cookie 属性；
  - 可信反代下不同 XFF 客户端分别计数，锁一个不影响另一个；
  - 配置非法 CIDR 启动失败并点名字段；
  - 单测覆盖 IPv4/IPv6/CIDR 与 XFF 链。
- **关联**：status.md 已知限制 6；v0.2.0 渗透报告 F3。

### KI-04 admin_token 最低强度

- **现象**：`admin_token_is_strong` 只检查字符数 ≥ 32；`"aaaaaaaa...（32 个）"` 可以通过。
- **影响**：运维手工写入弱 token 时，管理 API 可被离线/在线猜测；默认生成值不受影响。
- **修复方案**：在长度之外要求仅含 ASCII 可见字符、至少 16 个不同字符，并拒绝常见占位符（`changeme`、`secret`、`password`、全零等）；`hub init` / `admin-token` 生成的 64 位 hex 保持兼容。
- **验收标准**：弱 token 启动失败且错误信息说明原因；v0.2.0 生成的 64 位 hex token 仍可启动；单测覆盖边界。
- **关联**：v0.2.0 评审 F4。

### KI-05 管理 API 全局限速

- **现象**：`/api/v1/*` 只有 Bearer 鉴权，没有每 IP 请求速率限制；token 泄露后可高速拉取全量数据或尝试其他攻击。
- **修复方案**：管理 API 增加每 IP 60 req/min 的固定窗口限流（`/healthz` 除外），超限返回 `429` + `Retry-After`；登录/设置等敏感写操作单独收紧到 10 req/min；限流表有容量上限与过期清理。
- **验收标准**：第 61 次请求返回 429 且有 `Retry-After`；不同 IP 互不影响；容量上限内不泄漏内存；单测覆盖窗口边界。
- **关联**：requirements.md §8.2；v0.2.0 评审 F5。

### KI-06 管理监听非回环告警

- **现象**：`admin_listen = "0.0.0.0:..."` 时只有一行 INFO，没有显式安全告警。
- **修复方案**：v0.2.1 启动时解析监听地址并打 WARN；**v0.3.3 起收紧**：
  `admin_tls = "off"` 且管理监听为非回环时直接拒绝启动，迁移方式为
  `admin_tls = "required"`（HTTPS）或只绑回环 + TLS 反向代理。
- **验收标准**：回环 `off` 正常；`0.0.0.0` / 内网 IP / 公网 IP + `off`
  均拒绝启动并给出迁移提示；`required` 下 HTTPS `/healthz` 可用、明文不可用。
- **关联**：AGENTS.md §9；v0.2.0 评审 F6；v0.3.3 #9。

### KI-07 面板变更请求的 Origin/CSRF 校验

- **现象**：面板只依赖 `SameSite=Lax` Cookie；同站子域被攻陷时可发起同站跨源请求。
- **修复方案**：对所有非 GET/HEAD/OPTIONS 的 `/api/*` 请求校验 `Origin`（存在时必须与 `Host` 或配置的 `public_origin` 同源）；缺失 Origin 的非浏览器请求允许，但必须带 `Content-Type: application/json`。登录接口同样适用。
- **验收标准**：跨源 Origin 返回 403；同源与无 Origin 的 JSON 请求通过；`text/plain` 跨源表单被拒；单测覆盖端口/协议/子域差异。
- **关联**：v0.2.0 评审 F7。

### KI-08 未知 API 路由先鉴权再 404

- **现象**：`GET /api/v1/does-not-exist` 无 Bearer 时返回 404，而不是 401。
- **修复方案**：在受保护路由树内增加 `/api/v1` 与 `/api/v1/{*rest}` 的兜底 handler，先过 Bearer 中间件再返回 404。
- **验收标准**：无 token 的未知 API 返回 401；带 token 返回 404；`/healthz` 仍公开。
- **关联**：v0.2.0 评审 F8。

### KI-09 面板初始密码可重置

- **现象**：`panel init` 只打印一次随机密码；丢失后只能手工生成 PHC 串并改配置。
- **修复方案**：新增 `rustboard-panel reset-password` 子命令：生成新密码、写回 `admin_password_hash`（0600）、打印一次并提示保存；`init` 输出中补充该命令提示。
- **验收标准**：重置后旧密码失效、新密码可登录；配置文件权限保持 0600；单测/e2e 覆盖。
- **关联**：v0.2.0 评审 F9。

### KI-10 rotate-cert 运行期生效与证书状态

- **现象**：运行中的 hub 执行 `rotate-cert` 后，监听器仍用旧证书直到重启；`/api/v1/system` 读磁盘文件，显示的是新证书，与实际握手证书不一致。
- **修复方案**：
  1. hub 增加证书文件轮询任务（默认 10s），发现 server.crt/key 指纹变化后校验并热替换 `watch::Sender<Arc<ServerConfig>>`；
  2. `AppState` 保存「当前监听器证书」的公开摘要（指纹/到期时间），在初始加载与每次热替换时更新；
  3. `/api/v1/system` 同时返回 `cert.disk` 与 `cert.live`，字段保持向后兼容；
  4. `rotate-cert` 输出提示最长 10s 自动生效，无需重启。
- **验收标准**：运行中 rotate 后 ≤15s 新连接使用新指纹；`system` 的 live 与磁盘指纹最终一致；坏证书不会被热加载（保留旧配置并告警）；e2e 覆盖。
- **关联**：status.md 已知限制 8。

### KI-11 rotate-cert 并发文件锁

- **现象**：两个 `rotate-cert` 同时执行会同时备份、同时写 key/cert，可能得到不配套的一对。
- **修复方案**：在证书目录使用 `create_new` 锁文件（0600），内容为 pid + 时间；已存在且超过 10 分钟视为陈旧锁并清理；正常/失败路径都删除锁文件；获取失败返回非零并提示。
- **验收标准**：并发第二个进程立即失败且不写文件；持锁进程崩溃后陈旧锁可恢复；单测覆盖。
- **关联**：status.md 已知限制 8。

### KI-12 超长会话的客户端续签检查

- **现象**：客户端证书只在握手后检查一次；`session_max_hours=0` 时若连接保持超过证书剩余寿命，续签窗口被错过。
- **修复方案**：会话空闲等待分支增加证书检查定时器（默认 6 小时，可配置 `cert_check_interval_hours`，最小 1）；到点且当前无在途批次时执行 `maybe_renew_client_cert`；失败只告警。
- **验收标准**：`session_max_hours=0` 的会话在阈值到达后能触发续签；续签失败不影响上报；定时器不会与 ACK 等待争抢同一 stream；单测覆盖到期计算。
- **关联**：status.md 已知限制 9。

### KI-17 管理 API / 面板慢连接

- **现象**：hub 管理口与 panel 直接使用 `axum::serve`，没有 header 读超时与全局/每 IP 连接上限；半截 header 的 TCP 可长期占用 fd。
- **修复方案**：手工 hyper HTTP/1 accept；5s `header_read_timeout`；请求体一次性 10s 总 deadline（慢 body 不能无限占用）；全局 256、每来源 IP 32 并发上限，超限立即关闭 TCP；`ConnectInfo` 逐请求注入；计数归零删键、来源表容量 4096。
- **验收标准**：30 条半截 header 在 10s 内全部关闭，期间/之后 `/healthz` 仍 200；单 IP 第 33 条立即关闭；hub 与 panel 各有单测/e2e。
- **回归**：`cargo test -p rustboard-hub` / `-p rustboard-panel`；`tests/e2e/v031.sh` 阶段 7。
- **关联**：GitHub #9 的剩余部署风险（管理端强制 TLS 仍未实现）。

### KI-26 未认证 401 不受管理限速

- **现象**：v0.3.3 起 scoped token 每次请求查库；401 在限速之前，错误 token 可无限触发
  SHA-256 + SQLite 索引查询并写 WARN。本地渗透 32 并发 4000 次错误 token 约 1s、
  2.45 CPU-s、日志 +368KB。
- **影响**：管理口以 `admin_tls=required` 暴露到非回环时，未认证者可造成 CPU/日志
  可用性压力；默认 `127.0.0.1` 不可远程利用。
- **缓解（当前版本）**：管理口默认只绑回环；非回环应置于 VPN/防火墙后，并限制来源。
  `admin_tls` 只做传输加密，不认证客户端，不能替代网络边界。
- **修复方案（v0.3.4）**：认证前增加宽松的每 IP 失败计数/令牌桶（超限 429 且不查库），
  并对 401 WARN 采样；需评估 NAT 共享 IP 的误伤。
- **关联**：v0.3.3 渗透报告 M1；#9 scoped token。

### v0.3.4 已修复条目（KI-18/19/21/24/26）

- **KI-18**：`SessionStore::revoke_all()`；`reload_password_hash` 检测到哈希变化后清空全部
  会话；登录增加认证代际，重置瞬间在途的旧密码登录不能在清空后新建会话。
  回归：`cargo test -p rustboard-panel`；`v034.sh` 3.1–3.8（旧 Cookie ≤2s 401）。
- **KI-19**：`validate_hello_metadata` 对所有 Hello 元数据做 UTF-8 字节长度与控制字符校验，
  失败固定 `Problem(bad_frame)`，不写库、不回显字段值。回归：`cargo test -p rustboard-hub`；
  `v034.sh` 2.1–2.18。
- **KI-21**：数据/证书目录 0700，SQLite 主库/WAL/SHM 0600；旧 0755/0644 启动时收紧；
  hub 启动设置私有 umask；`data_dir` 先归一化并逐组件拒绝符号链接，再经共享/系统目录、
  sticky、owner 与相对路径校验，避免误 chmod `/tmp`、`/etc`、`/var/log`、`/`；
  不收紧 data_dir 外的共享父目录。回归：`cargo test -p
  rustboard-common -p rustboard-core -p rustboard-agent -p rustboard-hub`；`v034.sh` 5.1–5.17。
- **KI-24**：能力按连接保存，只有最新连接写库；最新断开回退到剩余最新已登记能力，
  全部断开保留历史；`None`（未 Hello）与 `Some(empty)` 区分。回归：`cargo test -p
  rustboard-hub`；`v034.sh` 4.1–4.19。
- **KI-26**：新增 `admin_auth_failure_limit_per_min`（默认 60、0 关闭、最大 600），
  按来源 IP 固定窗口失败限速；超限 429 + `Retry-After` 且不查库，旧 `admin_token`
  保持应急旁路，401/429 WARN 采样。回归：`cargo test -p rustboard-hub -p
  rustboard-common`；`v034.sh` 1.1–1.12。
- 同时修复证书备份同毫秒排序不稳定（`v034` 发布说明），回归：`cargo test -p
  rustboard-common` 与原偶发测试连续运行。
- 共同回归：Rust 543 个测试、`v034.sh` 97/97、既有 8 套 e2e 全绿、`cargo audit` 0。

### KI-27 单 IP WebSocket 会话上限绕过

- **现象**（v0.3.4 独立渗透）：`max_connections_per_ip = 16`、`max_connections = 1024`
  时，同一来源 IP 用合法 agent 证书连续建立 64 条 WebSocket 均成功；小实例
  `max_connections=8`、`max_connections_per_ip=2` 时同一 IP 占满 8 条，其他合法
  agent 连接被拒绝（旧实现表现为 503 `too many sessions`）。
- **影响**：任一持有有效 agent 证书的主体都能从单 IP 耗尽全局 session slots，使其他
  agent 重连/新纳管失败，监控整体不可用；TLS 层的单 IP 并发限制没有覆盖 WebSocket
  会话生命周期。
- **根因**：`serve_tls` 的全局与 per-IP `ConnectionPermit` 在 HTTP 升级完成、
  `serve_connection` 返回时释放；`agent_ws` 只重新占全局 `session_slots`，没有占
  session 级 per-IP 许可。
- **修复（v0.3.5）**：新增 `ConnectionGuards`，把 TLS 层的全局 + per-IP 许可放入
  请求扩展并移入 `on_upgrade` future，持有到 WebSocket 会话结束；删除重复计数的
  `session_slots`。超限在 TLS accept 阶段直接关闭 TCP。回归：`cargo test -p
  rustboard-hub`（guard clone/drop）与 `v035.sh` 3.1–3.11（per-IP 2 / 全局 8，第 3 条
  同源连接被拒、另一源 IP 可用、已有 agent 保持 online）。
- **关联**：v0.3.4 渗透报告 M2；KI-01 / v0.2.1 单 IP 连接限制的覆盖缺口。

### KI-13 ~ KI-16 设计/部署限制（不修复）

- **KI-13**：v0.1 agent 仍用指纹钉扎，服务端证书轮换后失联。升级到 v0.2+ 或重新纳管；发布说明与 status.md 保留。
- **KI-14**：客户端证书轮换复用私钥，私钥泄露必须 `agent revoke` 后重新纳管；不把私钥上传 hub 是刻意设计。
- **KI-15**：`server_names` 新增 SAN 后，已签发证书不含新地址；先 `rotate-cert --force` 再重启/等待热加载。
- **KI-16**：CPU / 磁盘 IO 首次采集只建立基线，5s 后才有第一个点；这是差分采集的正确行为。

## 修复记录

| 日期 | 版本 | 条目 | 提交 | 回归 |
|---|---|---|---|---|
| 2026-10-23 | v0.2.1 | KI-01 ~ KI-12 | `42c98c9`..`f8136ef` | 单元 259；hardening 29/29；security 9/9；cert 103/103；panel 159/159 |
| 2026-10-23 | v0.3.1 | KI-17 | `258f3b9` | 单元 420；v031 94/94；hardening 34/34 |
| 2026-10-23 | v0.3.4 | KI-18/19/21/24/26 | `97965c2`..`3f78656` | 单元 562；v034 97/97；既有 8 套 e2e 全绿；audit 0；评审后补修 693899f/106b6d4/3a218ea |
| 2026-10-24 | v0.3.5 | KI-27 | `c6baf4f`/`e9ebe51` | 单元 569；v035 48/48；既有 9 套 e2e 全绿；audit 0 |
