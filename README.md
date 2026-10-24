# RustBoard

自建的多服务器监控与轻量运维平台。三个可独立部署的组件：

| 组件 | 二进制 | 职责 |
|---|---|---|
| 采集端 | `rustboard-agent` | 采集 CPU / 内存 / 磁盘 / 网卡指标，本地磁盘缓冲，断网续传 |
| 汇聚端 | `rustboard-hub` | 接收上报、落库（SQLite）、管理 API 与控制面，自带同等采集能力 |
| 面板 | `rustboard-panel` | 浏览器界面，只通过 HTTP API 访问 hub |

设计文档见 [docs/requirements.md](docs/requirements.md)，实现进度见 [docs/status.md](docs/status.md)，
已知问题见 [docs/known-issues.md](docs/known-issues.md)。
协作流程见 [AGENTS.md](AGENTS.md)，变更记录见 [CHANGELOG.md](CHANGELOG.md)。

> **当前状态：M1/M2、v0.2.1 安全硬化、M3 控制面、v0.3.x 硬化、M4 告警/归档、v0.4.1 已知问题修复与 v0.4.2 安全补丁已完成（v0.4.2）。**
> 证书目前只有自签模式，ACME（域名 / 公网 IP 自动续期）在 M5 交付。
>
> 线协议版本为 **2**：hub 与 agent 必须严格一致。版本不符时 hub 回 `bad_protocol`
> 且不下发 Welcome，agent 打印明确错误并以非零码退出，不会进入重连循环。
>
> **升级提示（v0.1 → v0.2）**：v0.2 的 agent 在纳管后改用「CA 信任 + 主机名校验」，
> 因此服务端证书轮换后无需重新纳管；v0.1 的 agent 仍使用服务端指纹钉扎，
> 一旦执行 `rustboard-hub rotate-cert` 或服务端证书到期续签就会失联，请先升级 agent。
> 自动续签只在证书剩余寿命低于 `renew_before_days`（默认 30 天）时触发。

## 安全模型

1. `rustboard-hub init` 生成本地私有 CA 与服务端证书，打印 **SHA-256 指纹**。
2. `rustboard-hub agent add --name web-01` 生成**一次性** enrollment token（默认 30 分钟）。
3. agent 首次连接用安装命令里带过来的**指纹钉扎**校验 hub（等价 SSH 的 known_hosts），
   发送 CSR，hub 用私有 CA 签发客户端证书，并下发该机器独有的 `agent_secret`。
   证书有效期默认：CA 3650 天、服务端 365 天、客户端 90 天，均可配置。
4. 纳管成功后 agent 改用 **CA 信任 + 主机名校验**；客户端证书在剩余
   `cert_renew_before_days`（默认 30 天）时通过已认证会话自动轮换（复用私钥），
   服务端证书由 hub 在剩余 `renew_before_days` 时自动续签并热加载，无需重启。
5. 之后所有连接走 mTLS；Hello 里再带 `agent_secret` 做身份绑定（防止已纳管机器互相冒名）。
6. `rustboard-hub agent revoke --id <id>` 立即清除 secret 并拒绝该 agent 重连。
7. 敏感文件从创建起就是 0600（配置 / 私钥 / secret），证书为 0644；数据目录与证书目录
   为 0700，SQLite 主库 / WAL / SHM 为 0600（v0.3.4 起旧安装的过宽权限也会在启动时收紧）；
   agent 接入层限制每来源 IP 并发与总连接数、5s TLS 握手超时、5s 请求头读取超时与 15s 写超时。
8. 运维命令：
   - `rustboard-agent cert-info` 查看证书 CN / notBefore / notAfter / 剩余天数；
   - `rustboard-agent renew` 立即强制轮换客户端证书；
   - `rustboard-hub rotate-cert [--force] [--days N]` 重签服务端证书（成对备份旧 key/cert）；
     运行中的 hub 会在 ≤15s 内自动热加载新证书（含管理端 TLS），无需重启；`--force` 用于未到阈值时强制轮换。

## 控制面（v0.3.0，默认关闭）

控制面是 **root 权限操作**，默认全部关闭；必须同时在 agent 与 hub 两端显式开启：

```toml
# agent.toml
[control]
enabled = true
systemd = true
systemd_units = ["nginx*"]        # 精确名或前缀通配；禁止 sshd / rustboard-* 等
process = true
logs = true
[[control.log_sources]]
id = "nginx-error"
kind = "file"                     # file | journal
target = "/var/log/nginx/error.log"

# hub.toml
[control]
enabled = true
systemd = true
process = true
logs = true
```

- systemd / Docker 只允许 start / stop / restart；进程结束只允许 SIGTERM / SIGKILL；
  日志只读，按配置的 journald unit 或白名单文件 tail。
- 所有变更类操作写审计（`GET /api/v1/audit`，面板“审计”页）；非 0 退出码与信号终止记失败。
- **信任边界**：agent 是控制动作的实际执行者与结果来源。拿到 agent 证书 + secret 的主体
  可以伪造执行结果；hub 审计不能抵抗被控 agent。控制面能力默认关闭、白名单与操作确认
  是主要防线。
- 操作前请在面板上二次确认；`curl` 直接调用时必须带 `"confirm": true`（start 除外）。

## 快速开始（开发环境）

需要 Rust 1.89+ 与 C 编译器（MSRV 1.89；CI 使用 stable）。

```bash
cargo build --release
BIN=./target/release

# 1) 初始化 hub（生成 CA + 服务端证书），记下输出的“服务端证书指纹”
sudo $BIN/rustboard-hub init

# 2) 启动 hub
sudo $BIN/rustboard-hub run &

# 3) 查看分配到的端口（随机五位数）
sudo $BIN/rustboard-hub ports

# 4) 生成一次性 token，按输出里的命令去目标机器上装 agent
sudo $BIN/rustboard-hub agent add --name web-01
#   → 会打印完整命令，形如：
#   rustboard-agent init --hub wss://<ip>:<agent端口>/agent/ws \
#     --token <token> --fingerprint <指纹> --name web-01

# 5) 目标机器上执行上面打印的命令，然后
sudo $BIN/rustboard-agent run &
sudo $BIN/rustboard-agent info          # 随时查看纳管状态

# 6) 查数据（管理端口用 ports 命令看；v0.3.3 起建议用 scoped token）
ADMIN=$(sudo $BIN/rustboard-hub ports | awk '/管理 API 端口/{print $NF}')
TOKEN=$(sudo $BIN/rustboard-hub token create --name panel-prod --scope write)
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:$ADMIN/api/v1/agents"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:$ADMIN/api/v1/agents/hub-self/series?metric=cpu.usage&from=0&to=9999999999999"
# 旧 admin_token 仍兼容：rustboard-hub admin-token

# 7) 构建并启动面板（默认只绑 127.0.0.1；远程访问请走 VPN/反代）
(cd web && pnpm install --frozen-lockfile && pnpm build)
sudo $BIN/rustboard-panel init --hub "http://127.0.0.1:$ADMIN"
#   → 打印一次初始管理员密码；token 默认从 /etc/rustboard/hub.toml 读取
sudo $BIN/rustboard-panel run &
sudo $BIN/rustboard-panel ports        # 查看面板端口
# 浏览器打开 http://127.0.0.1:<面板端口>，用刚打印的密码登录
```

不想污染系统目录时，全部用 `--config` / `--data-dir` 指到临时目录：

```bash
./target/debug/rustboard-hub init --config /tmp/rb/hub.toml \
  --data-dir /tmp/rb/hub --agent-listen 127.0.0.1:18443 \
  --admin-listen 127.0.0.1:18444 --san 127.0.0.1
```

### 管理 API token 与 TLS

v0.3.3 起管理 API 支持三级 scoped token（旧 `admin_token` 仍兼容）：

```bash
rustboard-hub token create --name panel-prod --scope write   # 明文只输出一次
rustboard-hub token list                                     # TSV，不含明文/哈希
rustboard-hub token rotate --name panel-prod                 # 旧 token 立即失效
rustboard-hub token revoke --name panel-prod                 # 不删行，保留审计
```

- `read`：所有 GET；`write`：GET + 控制/设置；`admin`：全部（当前无 HTTP 管理接口）。
- 审计 actor 记录 token name；旧 `admin_token` 固定为 `admin`，因此 `admin`
  是保留名（大小写不敏感拒绝）。
- 管理口默认只绑 `127.0.0.1:...` 明文。绑非回环时必须：
  ```toml
  admin_listen = "0.0.0.0:8444"
  admin_tls = "required"       # 复用 server.crt / server.key（server-auth）
  server_names = ["hub.example.com", "10.0.0.5"]  # 管理端访问名必须在 SAN 内
  ```
  否则拒绝启动。修改 `server_names` 后先 `rotate-cert --force`。
- 管理证书复用 hub 的 `certs/server.crt`；Panel 连私有 CA 时配置 `hub_ca`。
- v0.3.4 起增加未认证失败限速：同一来源 IP 每分钟失败达到
  `admin_auth_failure_limit_per_min`（默认 60，0 关闭，最大 600）后返回
  429 + `Retry-After`，超限路径不再计算 SHA-256 或查询 SQLite，401 WARN 也按窗口采样。
  旧 `admin_token` 常量时间路径不受此限速影响，保留为应急入口。NAT / 反代后多个客户端
  共享来源 IP 时，达到阈值的合法 scoped token 也可能在窗口结束前收到 429；这是为避免
  未认证请求放大而接受的可用性权衡。v0.3.5 起即使设为 0（关闭限速），每个窗口首条
  认证失败仍打一条 WARN，后续降为 DEBUG，不恢复 429。
- v0.3.5 起 Linux 下 `data_dir` 的创建与权限收紧使用 `openat2` + 目录 fd：
  `data_dir` 必须是本程序独占的绝对子目录（至少两级，如 `/var/lib/rustboard/hub`）；
  `/tmp`、`/var/tmp`、`/etc`、`/var/log`、`/` 等共享/系统目录、sticky 目录、相对路径、
  任一祖先或最终组件为符号链接、他人拥有的最终目录都会拒绝启动。祖先必须不可被
  非特权用户写（推荐 root 拥有的专用目录），root 服务只能使用 root 拥有的最终目录。
  非 Linux 平台保留静态路径检查。数据库位于 `data_dir` 外时启动会 WARN，但不会收紧
  其父目录（DB 文件仍 0600）。证书目录收紧为 0700；同机以不同用户运行 Panel 且直接
  读取 hub `ca.crt` 时，需要复制 CA 或以同用户运行。

### 告警与归档（v0.4.0）

- 告警规则、事件、静默与通知渠道在面板 **`/alerts`** 管理；也可用管理 API：
  `GET/POST /api/v1/alerts/rules`、`GET /events`、`GET/POST/DELETE /silences`、
  `GET/POST/PUT/DELETE /channels`、`POST /channels/{id}/test`。
- 内置 5 条规则初始 **disabled**；启用并绑定渠道后才会发送。通知渠道 secret
  只写不读，API 只返回 `secret_fields`，错误/日志不含 token。
- 冷归档配置在 hub.toml 的 `[archive]`（`enabled`、`backend=webdav|s3|sftp`、
  `after_days`、`schedule_hour_utc`、`max_object_bytes`、`prefix` 及对应后端段）。
  `max_object_bytes` 自 v0.4.1 起限 **1–64 MiB**，只控制 worker 分片；下载硬限
  固定 64 MiB，超过 64 MiB 的旧配置会拒绝启动（有意 breaking change）。SFTP
  必须配置 `host_key_fingerprint`，只支持 ed25519/ECDSA 主机密钥与 ed25519
  用户私钥（vendored 去掉 optional rsa）；WebDAV/S3 也需显式配置。
- 手动运维：
  ```bash
  rustboard-hub archive test   --config /etc/rustboard/hub.toml
  rustboard-hub archive status --config /etc/rustboard/hub.toml
  rustboard-hub archive run    --config /etc/rustboard/hub.toml
  rustboard-hub maintenance run --task downsample
  rustboard-hub maintenance run --task retention
  ```
  归档对象在面板 **`/archive`** 查看/下载；hub 下载单对象硬限 64 MiB，
  1 个认证主体并发 + 120s 发送期限。`archive.enabled=true` 但水位未推进时，
  retention 不会删除 raw。v0.4.1 起对象列表新增 `downloadable`；状态就绪但
  >64 MiB 的旧对象显示“不可下载”，下载直接 413，不读后端。
- 详细接口、配置与验收见
  [M4 方案](docs/plans/2026-10-24-m4-alerting-archive.md)；已知问题/修复排期见
  [known-issues](docs/known-issues.md)、
  [修复计划](docs/plans/2026-10-24-known-issues-fix.md) 与
  [M4 渗透测试计划](docs/plans/2026-10-24-m4-pentest.md)；
  渗透结果与 SFTP 真实验证见
  [M4 渗透报告](docs/security/2026-10-24-m4-pentest-report.md)。

### 远程面板

面板默认只监听 `127.0.0.1`，且只提供明文 HTTP。推荐三种方式（按安全性排序）：

1. **SSH 隧道（最简单）**：面板仍绑回环，浏览器侧建隧道
   `ssh -L 8080:127.0.0.1:<面板端口> user@hub-host`，然后访问 `http://127.0.0.1:8080`。
   面板到 hub 也可继续走 `http://127.0.0.1:<管理端口>`（回环明文）。
2. **VPN / Tailscale**：只把面板绑到 VPN 地址并只对该网段放行。v0.3.3 起
   **非回环的 hub 管理口不允许明文 HTTP**：hub 需 `admin_tls = "required"`，
   panel 的 `hub_url` 用 `https://...` 并配置 `hub_ca`（hub 的 `certs/ca.crt`），例如：
   ```toml
   # hub.toml
   admin_listen = "10.8.0.1:8444"
   admin_tls = "required"
   server_names = ["10.8.0.1", "hub.example.com"]  # 管理端访问 IP 必须在 SAN 内

   # panel.toml
   hub_url = "https://10.8.0.1:8444"
   hub_ca  = "/etc/rustboard/hub/certs/ca.crt"
   ```
   修改 `server_names` 后需 `rustboard-hub rotate-cert --force` 再重启/热加载。
3. **同机反代 + TLS**：面板绑回环，由 nginx/Caddy 终止 TLS 并反向代理到面板。
   面板默认**不信任**任何 `X-Forwarded-*`；必须显式配置可信反代地址才采信：
   ```toml
   trusted_proxies = ["127.0.0.1"]      # 反代的直连地址，也支持 CIDR
   cookie_secure = "auto"               # auto 依据可信 XFP；也可 always / never
   public_origin = "https://panel.example.com"  # 反代后的对外 Origin
   ```
   反代需设置 `X-Forwarded-Proto: https` 并正确传递 `X-Forwarded-For`；未配置
   `trusted_proxies` 时所有 XFF/XFP 都被忽略，避免伪造头绕过登录限速或 Cookie 安全属性。

面板自身监听仍是明文 HTTP（M5 前不提供面板 TLS）；对外暴露必须走 VPN/SSH/反代。
面板访问 hub 的 HTTP 客户端强制直连（忽略 `HTTP_PROXY`），且远程 `http://` 会拒绝启动。

## 端口

**不占用 8080 / 8443 这类常见端口。** 每个端口在安装时随机挑一个五位数（20000–64999），
并先 `bind` 一次确认未被占用；也可以用 `--agent-listen` / `--admin-listen` / `--listen` 自定义。

| 用途 | 默认端口 | 协议 | 暴露建议 |
|---|---|---|---|
| agent 接入 | 随机五位数 | WSS + mTLS | 必须公网可达 |
| 管理 API | 随机五位数 | HTTP（回环）/ HTTPS（`admin_tls=required`） | 默认只绑回环；非回环必须 `admin_tls=required`，远程面板走 HTTPS + `hub_ca` |
| 面板 | 随机五位数 | HTTP | 默认只绑回环；对外必须走 VPN/反代，M5 前不提供面板自身 TLS |

随时在终端查看当前端口：

```bash
rustboard-hub ports       # agent 端口、管理端口、证书指纹
rustboard-panel ports     # 面板端口、hub API
rustboard-agent info      # hub 地址、agent_id、纳管状态
```

## 目录结构

```
crates/
  rustboard-common/   协议帧、数据模型、配置、TLS 材料与校验
  rustboard-core/     采集器、磁盘缓冲、SQLite 存储
  rustboard-agent/    采集端二进制
  rustboard-hub/      汇聚端二进制
  rustboard-panel/    面板二进制
docs/                 需求确认稿、实现进度
```

## 数据模型约定

- 采样点统一是 `(agent_id, metric, labels, ts, value)` 的窄表。
- 网络与磁盘 IO 上报**自开机以来的累计计数器**，不做本地累加；
  重启归零的结转由 hub 侧处理（M1 待补）。
- 批次在 `agent_id + epoch + seq` 上幂等，断线重传不会产生重复点。

## 测试

```bash
cargo test --workspace --locked
bash tests/e2e/security.sh
bash tests/e2e/v035.sh   # v0.3.5 安全收口
bash tests/e2e/v040.sh   # M4 告警/归档
bash tests/e2e/v041.sh   # v0.4.1 已知问题修复
```

单元与集成测试覆盖：CPU/内存解析、计数器重置容纳、磁盘缓冲落盘与恢复、
SQLite 批次精确幂等与 v1/v2→v3 迁移、跨 epoch 乱序与 48h 判重清理、
一次性 token 单次使用与过期、吊销清除 secret / 状态不被覆盖、
指纹解析、CA 签发 CSR、原子写符号链接防护、配置权限收紧、协议版本门禁。

`tests/e2e/security.sh` 会自行构建并用临时目录启动 hub/agent（随机五位数端口），
实际覆盖 9 项：正常采集与 online/offline、无客户端证书 Hello 被拒、
证书 CN≠agent_id、跨 agent 伪造 Batch、多连接下线的状态语义、
协议版本 1 收到 `bad_protocol`、吊销后 ≤3s 断开且重连被拒。

`tests/e2e/v035.sh` 覆盖 v0.3.5 安全收口：同源 IP 的 WebSocket 连接上限
（第 3 条拒绝、另一源 IP 可用、已有 agent 保持 online）、`data_dir` 中间符号链接
拒绝启动且不触碰链接目标、外置 `database` 的启动 WARN 与 DB 0600、
`admin_auth_failure_limit_per_min=0` 时错误 Bearer 仍返回 401 且首条 WARN 可见。

`tests/e2e/v040.sh` 覆盖 M4：规则 CRUD/409、事件分页与 `series_key`、静默、
渠道脱敏、归档 status/objects/download 404、无 Bearer 401 与未知路由先鉴权后 404
（27 项）。

`tests/e2e/v041.sh` 覆盖 v0.4.1：KI-29 rowid 复用后的 1m/1h 重算、KI-31
64 MiB 配置边界/`downloadable`/413、KI-28 同 IP 拒连日志采样、KI-20 安装命令
shell 引用（26 项，另 2 项面板/采样表上界由 web 与单元测试覆盖）。

## License

[MIT](LICENSE) © 2026 PazzIFirst
