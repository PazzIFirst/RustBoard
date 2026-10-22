# ServerDashboard v1 需求与设计确认稿

> 状态：待确认　｜　最后更新：2026-10-23
> 本文是开工前的范围冻结稿。确认后按第 12 节的里程碑推进，范围变更走第 15 节的流程。

---

## 1. 一句话定义

一套自建的多服务器监控与轻量运维平台：**采集端（agent）** 常驻每台服务器采集指标并本地缓冲，**汇聚端（hub）** 接收、存储、降采样、触发告警（并自带完整的本机采集能力），**面板（panel）** 提供浏览器界面。三者可分别独立安装，面板还能装在与服务器完全无关的设备上。

## 2. 产品与仓库布局

Cargo workspace，单一仓库，三个可独立发布的二进制：

```
serverdashboard/
├── crates/
│   ├── sd-common/     # 协议帧、数据模型、配置、加密、安装器公共逻辑
│   ├── sd-core/       # 采集器、本地缓冲、存储、降采样、告警引擎（共用）
│   ├── sd-agent/      # 采集端：sd-core 的采集 + 缓冲 + 上传
│   ├── sd-hub/        # 汇聚端：接入 + 本机采集 + 存储 + 告警 + API
│   └── sd-panel/      # 面板：axum + 内嵌前端静态资源
├── web/               # React + TypeScript + Vite 前端
├── docs/              # 本文档与运维文档
├── packaging/         # systemd unit、Dockerfile、离线打包脚本
└── installer/         # 一键安装 shell 引导
```

| 产品 | 二进制 | unit | 依赖 | 定位 |
|---|---|---|---|---|
| 采集端 | `sd-agent` | `sd-agent.service` | 无（静态链接 musl） | 轻量版 hub：只采集、缓存、上传 |
| 汇聚端 | `sd-hub` | `sd-hub.service` | SQLite 或 PostgreSQL（安装时选） | 完整版：采集 + 存储 + 告警 + API |
| 面板 | `sd-panel` | `sd-panel.service` | 无（前端已内嵌） | 纯前端服务，只调 hub API |

> **hub 与 agent 共用 `sd-core` 的采集与入库管线**。hub 的主机自身指标走本地直写，不经过网络回环，因此 hub 所在机器在面板里就是一台普通服务器，schema 与 UI 完全一致。

配置文件统一放在 `/etc/serverdashboard/`，数据放在 `/var/lib/serverdashboard/`，日志走 journald。

## 3. 范围

### v1（本期交付）

- 指标采集：CPU、内存、磁盘容量与磁盘 IO、网卡速率与累计流量
- hub 自带同等采集能力，纳管自身无需额外安装 agent
- 本地环形缓冲，hub 断连不丢数据，恢复后自动补传
- hub 存储：SQLite 或 PostgreSQL，安装时二选一
- 三级降采样与可配置保留期，超期自动删除或归档
- 冷归档：S3 兼容 / WebDAV / SFTP 三选一（安装时配）
- 面板：服务器概览、单机详情图表、任意时间范围、采样精度动态下发
- 面板可同机安装，也可装在家里/办公网等独立设备，仅通过 HTTPS 调 hub API
- 告警：阈值规则 + 离线检测 + 冷却/静默 + Telegram / 企业微信 / 钉钉 / 飞书
- 控制面：systemd 服务管理、Docker 容器管理、进程查看与结束、日志查看（只读）
- 审计日志：所有变更类操作可追溯
- 安装器：三个产品各自支持交互式与非交互安装；hub 安装时询问是否一并安装面板；**自动自检 80/443 可达性并引导放行**
- 交付形态：Linux x86_64 / arm64 静态二进制、Docker 镜像、离线安装包

### v2（明确延后）

- 文件管理（上传/下载/重命名/删除/在线编辑）
- Web 终端（网页 SSH）
- 多用户与角色权限
- OIDC / SSO 对接
- 移动端专门适配
- IPv6 采集与监听

> 注意：v1 的“日志查看”按**只读**实现——`journalctl` 按 unit 过滤 + 白名单内文件的 tail/下载，**不提供**任意路径浏览。它与 v2 的文件管理不是同一套能力，也不共用写接口。

## 4. 已确认的关键决策

| 决策点 | 结论 | 影响 |
|---|---|---|
| 连接方向 | agent 主动外连 hub，长连接上复用双向请求 | hub 只需一个公网入口；服务器无需开放入站端口 |
| 传输协议 | TLS 1.3 + WebSocket + MessagePack 帧 | 对防火墙最友好，单端口复用 |
| 身份认证 | 一次性 enrollment token 换取每机独立 mTLS 证书 | 可单机吊销，token 泄露不波及全网 |
| 存储引擎 | 安装时选 SQLite 或 PG | `Storage` trait 抽象，两者共用 SQL 方言子集 |
| 采样精度 | 运行时动态可调（hub 下发） | 无需重装即可从 60s 切到 1s 排查问题 |
| 冷数据 | 超期后归档到对象存储或直接删除 | 归档仅作冷备，面板不查询冷数据 |
| 面板鉴权 | 单管理员 + 密码（Argon2id）+ 可选 TOTP | v1 不做多用户 |
| 面板部署 | 默认同机，支持远程独立部署 | 远程时只依赖 hub 的管理 API，不碰 agent 入口 |
| 母进程角色 | **hub 内置完整采集能力**，agent 是其轻量裁剪版 | 单机部署时不需要装两个进程 |
| 端口策略 | 默认随机五位数，可自定义；agent 与管理 API 端口隔离 | 避免与既有服务冲突、降低被扫描爆破概率 |
| 证书 | 域名 ACME / 公网 IP 短证书 / 自签+指纹 三模式 | 见第 9 节；安装器负责探测 |
| 控制面 | **默认全部关闭**，安装时逐项开启 | root 权限操作，必须显式授权 |

## 5. 架构

### 5.1 拓扑

```
┌──────────── 服务器 A ────────────┐
│  sd-agent (root)                 │
│   ├─ 采集器（/proc, /sys, statfs）│
│   ├─ 本地环形缓冲（磁盘，有上限） │
│   └─ 上传器 ────────────┐        │
└─────────────────────────┼────────┘
                          │ WSS/TLS1.3 + mTLS  :8443
                          ▼
                    ┌──────────────┐
                    │   sd-hub     │
                    │  ├ 接入层     │  :8443（只收 agent）
                    │  ├ 本机采集器 │  与 agent 同一套 collector
                    │  ├ 存储层     │──> SQLite / PostgreSQL
                    │  ├ 降采样器   │──> S3 / WebDAV / SFTP
                    │  ├ 告警引擎   │──> Telegram / 企微 / 钉钉 / 飞书
                    │  └ 管理 API   │  :8444（只收面板）
                    └──────┬───────┘
                           │ HTTPS + scoped token
              ┌────────────┴────────────┐
              │                         │
      ┌───────▼──────┐          ┌───────▼──────────┐
      │  sd-panel    │          │  sd-panel（远程） │
      │  同机 :8080  │          │  家里/办公网       │
      └──────┬───────┘          └───────┬──────────┘
             ▼                          ▼
           浏览器                     浏览器
```

> 图中端口仅为示例。实际安装时默认随机五位数，见 5.5。

### 5.2 连接与复用

- agent 启动后与 hub 建立 **一条** WSS 长连接，路径 `/agent/ws`，端口由配置决定（默认随机五位数）。
- 连接上是带 `id` 的帧多路复用：`Hello` / `SampleBatch` / `Ack` / `Cmd` / `CmdResult` / `ConfigPush` / `Ping`。
- 心跳 15s，3 次未响应判定断线；指数退避重连（1s → 60s，带抖动）。
- **管理 API 独立监听**（默认只绑回环），使用独立的 TLS 配置与身份体系（面板 token / 会话），与 agent 入口在端口、证书用途、认证方式上三重隔离。
- v2 的批量传输（文件、终端）走独立路径 `/agent/bulk`，避免大流量阻塞指标上报的 TCP 连接（队头阻塞）。

### 5.3 数据流

1. agent 按当前采样间隔采集 → 写入本地 WAL 缓冲区 → 攒批（默认 10s 或 512 条）上传。
2. hub 校验、去重（`agent_id + seq`）、入库，返回 `Ack`；agent 收到 Ack 才推进缓冲读指针。
3. 缓冲保留上限（默认 500MB 或 24h，取先到者），超限丢最旧并记一条 `gap` 事件。
4. hub 自身的采集结果直接走同一条入库管线（`agent_id = hub-self`），不经过网络。
5. 后台任务每分钟做一次降采样，每小时裁剪一次超期分区。

### 5.4 单进程多角色

hub 与 agent 不是两个代码库，而是同一套 `sd-core` 的两种装配：

| 能力 | sd-agent | sd-hub |
|---|---|---|
| 采集器 | ✅ | ✅ |
| 本地缓冲 | ✅ | ✅（本机数据直接写库，缓冲仅用于入库失败重试） |
| WSS 客户端 | ✅ | ❌ |
| WSS 服务端 | ❌ | ✅ |
| 存储/降采样/告警 | ❌ | ✅ |
| 管理 API | ❌ | ✅ |

这样“hub 兼管自己”是零成本的，也不会出现两套采集逻辑跑偏的问题。

### 5.5 端口策略

所有监听端口由安装时**随机挑选五位数（20000–64999）**，并在写入配置前实际 `bind` 一次确认未被占用。

- 不使用 8080 / 8443 这类常见端口：既避免和机器上既有服务撞车，也降低被批量扫描爆破的概率。
- 用户可用 `--agent-listen` / `--admin-listen` / `--listen` 显式指定，自定义优先。
- 端口写入配置后不再变动，重启保持。
- 随时查看：`rustboard-hub ports`、`rustboard-panel ports`、`rustboard-agent info`。
- `rustboard-hub agent add` 生成的安装命令会自动带上当前端口与证书指纹。

## 6. 采集指标清单

采样默认 **5s**，可按机器配置 1s–300s。所有值统一按浮点存储，采集时附 `ts`（agent 单调时钟 + 墙钟校正）。

| 类别 | 指标 key | 说明 |
|---|---|---|
| CPU | `cpu.usage` `cpu.user` `cpu.system` `cpu.iowait` `cpu.steal` `cpu.idle` | 百分比 |
| CPU | `cpu.cores.<n>.usage` | 每核百分比（可按配置关掉以省空间） |
| 负载 | `load.1` `load.5` `load.15` | 原值 |
| 内存 | `mem.total` `mem.used` `mem.available` `mem.cached` `mem.buffers` | 字节 |
| Swap | `swap.total` `swap.used` | 字节 |
| 磁盘容量 | `disk.used` `disk.total` `disk.inode.used` | 按挂载点打 label |
| 磁盘 IO | `diskio.read_bytes` `diskio.write_bytes` `diskio.read_iops` `diskio.write_iops` `diskio.await_ms` `diskio.util` | 按设备打 label |
| 网络 | `net.rx_bytes` `net.tx_bytes` `net.rx_packets` `net.tx_packets` | **累计计数器**，按网卡打 label |
| 网络 | `net.rx_errors` `net.tx_errors` `net.rx_drops` `net.tx_drops` | 累计计数器 |
| 网络 | `net.rx_rate` `net.tx_rate` | 派生值，hub 侧按窗口计算，不落原始表 |
| 系统 | `uptime` `boot_time` `proc.count` | 辅助判断重启 |

### 6.1 计数器重置处理（重要）

网卡与磁盘 IO 都是单调递增计数器，内核重启、网卡 reset、驱动 reload 都会归零。直接把差值画进曲线会出现巨大负跳变。

处理方式：
- agent 侧记录 `boot_id`（`/proc/sys/kernel/random/boot_id`）+ 自身启动序号 `agent_epoch`。
- 上传时计数器**原样上报**，不做本地累加，避免 agent 重启丢历史。
- hub 侧维护 `counters` 表：每个 `(agent_id, metric, labels, epoch)` 保存 `last_value` 与累计偏移量。检测到 `value < last_value` 或 `epoch` 变化，就开启新 epoch 并把旧 epoch 的总量结转。
- 面板展示的“累计流量”= 所有 epoch 结转总和，可切换“自开机 / 自纳管 / 本月”三种口径。

### 6.2 网卡过滤

默认排除 `lo`、`docker*`、`veth*`、`br-*`、`virbr*`，排除列表可配置。可在面板按机器勾选要展示的网卡。

## 7. 存储设计

### 7.1 表结构（SQLite / PG 共用子集）

```sql
agents(id, name, hostname, ip, os, arch, agent_version, boot_id,
       cert_serial, status, last_seen_at, labels_json, created_at)

samples(agent_id, metric, labels, ts, value)          -- 窄表，按 ts 分区/分片
rollups(agent_id, metric, labels, bucket, ts,
        min, max, avg, last, count)                    -- bucket ∈ {1m, 1h}
counters(agent_id, metric, labels, epoch, last_ts, last_value, total)
gaps(agent_id, from_ts, to_ts, reason)

alert_rules(id, name, expr_json, for_secs, severity, channels_json, enabled)
alert_events(id, rule_id, agent_id, started_at, resolved_at, status, payload_json)
audit_log(id, actor, agent_id, action, args_json, result, client_ip, ts)
users(id, username, password_hash, totp_secret, created_at)
sessions(id, user_id, token_hash, expires_at, client_ip)
cold_exports(id, day, backend, object_key, size_bytes, sha256, status, created_at)
```

- `labels` 用 JSON 文本 + `label_hash`（xxhash）建索引，避免为两种库写两套。
- SQLite 开 WAL，`synchronous=NORMAL`，批量事务写入；单机 100 台 × 30 指标 / 5s ≈ 600 行/秒，可轻松承载。
- PG 用按月 `PARTITION BY RANGE (ts)`，索引 `(agent_id, metric, ts)` + BRIN on `ts`。

### 7.2 分层与保留

| 层 | 粒度 | 默认保留 | 可配置 |
|---|---|---|---|
| raw | 采样间隔 | 7 天 | 是 |
| 1m | 1 分钟（min/max/avg/last/count） | 90 天 | 是 |
| 1h | 1 小时 | 2 年 | 是 |
| cold | 原始行打包 | 由对象存储决定 | 是（X 天） |

查询时按时间跨度自动选层：≤6h 读 raw，≤7d 读 1m，更长读 1h。前端图表按像素宽度再降采样（LTTB），避免传输上万点。

### 7.3 冷归档

- 每天 03:00 把超过 X 天的 raw 行导出为 `parquet`（无 parquet 依赖时降级 `csv.gz`），连同 `manifest.json`（含行数、sha256、时间范围）上传。
- 上传成功后**先标记、再删除**本地行；删除失败则保留并告警。
- 三个后端实现同一个 `ColdStore` trait：`put(key, reader) / get(key) / delete(key) / test()`。
- 归档文件可在面板“数据管理”页手动下载，**不支持直接查询**（v1 明确决策）。

## 8. 安全模型

### 8.1 纳管流程（enrollment）

1. 在 hub 上执行 `sd-hub agent add --name web-01`，生成一次性 token（默认 30 分钟有效、单次使用）。
2. 安装命令形如：
   `curl -fsSL https://<hub>:<agent端口>/install.sh | sh -s -- --token <t> --hub <ip:agent端口>`
   安装脚本把 hub 的证书指纹也带进去（自签模式必需）。
3. agent 首启生成 Ed25519 密钥对 → 用 token 认证 → 提交 CSR → hub 的私有 CA 签发 90 天客户端证书 → 返回 hub CA 证书链。
4. 之后所有连接走 mTLS；agent 每 60 天自动轮换证书。
5. 吊销：`sd-hub agent revoke <id>`，hub 侧 CRL/内存黑名单立即生效，对应 agent 被拒。

### 8.2 面板

- 密码 Argon2id，`m=64MB, t=3, p=4`。
- 会话用 HttpOnly + Secure + SameSite=Lax Cookie，默认 12 小时，支持“记住我”延长到 7 天。
- 登录失败 5 次锁 15 分钟（按 IP + 用户名）；支持 TOTP，开启后必须二次验证。
- **远程面板**：hub 生成 scoped token（只读/读写两种），面板携带 `Authorization: Bearer` 调管理端口；面板自己也有一层登录，两者是不同信任域。
- 因为管理端口一旦对公网开放就是爆破目标，默认**只监听内网/回环**。远程面板推荐三条路（安装器会说明）：
  1. WireGuard / Tailscale 组网，管理端口完全不对公网暴露（推荐）；
  2. 反代 + IP 白名单 + 限速；
  3. 确实要裸奔时，强制 TOTP + 失败锁定 + 只读 token。
- 管理 API 全局限速：每 IP 60 req/min，登录接口 10 req/min。

### 8.3 控制面（root 操作）

这是整套系统最危险的部分。约束：

- 安装时**逐项**询问：systemd 管理 / Docker 管理 / 进程管理 / 日志查看，默认全否。
- 未开启的能力，hub 侧直接返回 `403 capability_disabled`，agent 侧也不加载对应模块。
- systemd 只允许操作**白名单 unit**（安装时填写，支持前缀通配如 `nginx*`），禁止 `sd-agent`、`sd-hub` 和 `sshd`。
- Docker 只允许对**白名单容器/镜像前缀**操作，禁止 `exec`、`--privileged`、挂载宿主机路径。
- 进程结束必须带 PID + 进程名二次校验，防 PID 复用误杀。
- 日志查看路径必须在白名单内，且禁止符号链接逃逸（`openat2` + `RESOLVE_BENEATH`）。
- 所有变更操作写审计：谁（面板用户）、何时、哪台机器、什么动作、参数、结果、耗时。
- 危险操作（停止服务、结束进程、删除容器）在面板上二次确认，v1 不做“批量执行”。

## 9. TLS 与证书

三种模式，安装时选择，自动探测可用性：

| 模式 | 适用 | 证书来源 | 续期 |
|---|---|---|---|
| `acme-domain` | 有域名解析到 hub | Let's Encrypt 90 天 | 到期前 30 天自动续 |
| `acme-ip` | 有**公网** IP，80/443 可达 | LE 6 天短证书（IP SAN） | 每 4 天自动续 |
| `self-signed` | 内网 / 无公网 / 离线 | 本地自签 CA | 10 年，指纹随安装命令分发 |

关于 `acme-ip` 的硬性约束（必须让用户知道）：

- LE 的 IP 证书**只有 6 天有效期**，没有 90 天选项；因此“7 天续一次”不可行，实际是每 4 天左右轮换一次（剩余寿命 1/3 处）。
- 校验方式仅 `http-01`（需 80 端口）或 `tls-alpn-01`（需 443 端口），不支持 DNS 校验。
- IP 必须是**公网可路由地址**；`10/8`、`172.16/12`、`192.168/16`、`100.64/10` 等无法签发。
- 短证书有独立的速率限制，正常续期不会触发，但**续期失败 6 天内必然全节点失联**——hub 必须监控自己的证书剩余时间并在 <48h 时告警。
- 备选：ZeroSSL 的 IP 证书（90 天，需 EAB 凭据），续期压力小但要多注册一个账号。安装器提供该选项。
- 若 hub 的公网 IP 会变，IP 证书在变更后即失效，此时应改用 `acme-domain` + DDNS。

自签模式的引导：安装命令里带 `--fingerprint <sha256>`，agent 首次连接严格比对；指纹不符直接拒绝并打印实际指纹。

## 10. 安装器

### 10.1 交互式

`sd-hub install` / `sd-agent install` / `sd-panel install`，纯 ANSI 交互（不依赖 `dialog`），逐项引导：

1. 检测系统（发行版、架构、systemd、已有端口占用）
2. **网络环境自检**（见 10.4）
3. 选择角色与目录（默认值可回车接受）
4. hub：选存储（SQLite / PG，PG 则探测连通性）、监听地址、TLS 模式、保留策略、冷归档后端、告警渠道
5. 询问“是否一并安装面板”（默认是，同机）
6. 生成配置、写 systemd unit、`systemctl enable --now`
7. 打印摘要：访问地址、初始管理员密码（或设置密码的链接）、agent 纳管命令、证书指纹、下一步

### 10.2 非交互

所有交互项都有对应 flag，支持 `--yes` 全默认：

```
sd-hub install --yes --db postgres://... --listen 0.0.0.0:<agent端口> \
  --tls acme-ip --retention raw=7d,1m=90d,1h=2y --panel yes
```

### 10.3 交付形态

- **静态二进制**：`x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`，单文件无动态依赖。
- **离线包**：`serverdashboard-<ver>-<arch>.tar.gz`，含三个二进制 + systemd unit + 安装脚本 + SHA256SUMS，内网 `--offline` 模式跳过所有网络探测。
- **Docker 镜像**：`ghcr.io/<org>/serverdashboard:{hub,panel,agent}`，多阶段构建，非 root 运行（agent 需 root 时用 `--privileged` 或挂载 `/proc`、`/var/run/docker.sock`，文档明确警告）。
- **升级/卸载**：`sd-<role> upgrade --from <file>`、`sd-<role> uninstall [--purge]`；卸载默认保留数据目录。

### 10.4 端口与网络自检（`acme-ip` 模式必做）

在生成任何配置之前，安装器按下面的顺序检查，并**逐步引导用户放行**：

1. **本地监听检查**：`ss -ltnp` 看 80 / 443 是否已被占用。
   - 被 nginx 等占用 → 提示改用 `tls-alpn-01` 或反代模式，或让用户停掉占用进程。
2. **本机防火墙检查**：识别 `ufw` / `firewalld` / `nftables` / `iptables`。
   - 打印对应的放行命令（如 `ufw allow 80,443/tcp`），询问是否代为执行；执行后重新检查。
3. **云厂商安全组提示**：探测 `169.254.169.254` 元数据判断是否在云上（AWS/阿里云/腾讯云）。
   - 这类规则无法从机器内部修改，安装器打印控制台操作路径，等用户确认已放行。
4. **真实公网可达性验证**：用 ACME **staging** 环境实跑一次 `http-01` / `tls-alpn-01` 挑战。
   - 成功 → 说明 80/443 从公网可达，继续正式签发。
   - 失败 → 按“本地监听正常 / 外部不通”这一判据直接指出问题在安全组或运营商侧，并给出排查命令。
5. **失败兜底**：最多重试 3 轮；用户可随时放弃并自动回退到 `self-signed` + 指纹模式，安装继续进行，不阻塞交付。

> 这项自检同样适用于 `acme-domain` 模式（只是挑战类型可能换成 DNS-01），以及独立安装的面板（检查面板端口是否可达）。

## 11. 告警

- 规则：`metric` + `比较符` + `阈值` + `持续时长`（如“CPU > 90% 持续 5 分钟”），可按机器/标签筛选。
- 内置：agent 离线（心跳丢失 > 90s）、磁盘使用率 > 阈值、证书剩余 < 48h、缓冲区积压。
- 抑制：同一规则同一机器在冷却期（默认 30 分钟）内不重复通知；支持手动静默 N 小时。
- 通知渠道：Telegram Bot（token + chat_id）、企业微信机器人（webhook key）、钉钉（webhook + 加签）、飞书（webhook + 签名）。每个渠道有“发送测试消息”按钮。
- 存续状态：`firing` / `resolved`，恢复时发一条恢复通知（可关）。

## 12. 里程碑

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| **M1** 骨架与闭环 | workspace 结构、协议帧、采集器、本地缓冲、WSS 上传、hub 接入与入库、SQLite 存储、enrollment 与 mTLS、hub 本机采集 | 一条命令跑起 hub，面板里能看到 hub 自身指标；再纳管一台 agent，`sd-hub query` 能查到真实数据；断网 10 分钟后恢复可自动补传且无重复 |
| **M2** 面板 | 前端工程、登录、概览页、单机详情图表、时间范围切换、降采样查询、采样精度下发 | 浏览器里能看到四类曲线自由缩放；改采样间隔 1 分钟内生效 |
| **M3** 控制面 | systemd / Docker / 进程 / 日志四个模块，能力开关，审计日志页 | 重启 nginx 成功且产生审计记录；越权 unit 被拒绝 |
| **M4** 告警与归档 | 规则引擎、四个通知渠道、S3/WebDAV/SFTP 归档、降采样任务 | 拔网线后 90s 内收到 Telegram 告警；归档文件可下载且 sha256 一致 |
| **M5** 交付 | 安装器（交互 + 非交互 + 网络自检）、离线包、Docker 镜像、交叉编译、文档 | 全新 arm64 机器上三步完成安装；离线包可在无网环境装通；80/443 未开时安装器能准确定位并引导 |

M1、M2 完成即为可演示的最小产品。

## 13. 假设与未决项

| # | 假设 / 问题 | 状态 |
|---|---|---|
| 1 | hub 有**固定的公网 IPv4**，面板可装在家里或服务器上 | ✅ 已确认 |
| 2 | hub 内置 agent 全部能力，agent 是其轻量裁剪版 | ✅ 已确认 |
| 3 | IPv6 不在 v1 范围，代码预留字段 | ✅ 已确认 |
| 4 | 目标服务器数量 ≤ 200 台；初始采样 5s | 待确认（不影响开工） |
| 5 | 安装 agent 的机器都允许 root 与 systemd | 待确认（不影响开工） |
| 6 | 项目命名：`RustBoard`（GitHub 有两个同名小仓库，crates.io 未验证） | 待你拍板 |
| 7 | 冷归档只做冷备，不提供查询 | ✅ 已确认 |

## 14. 风险清单

| 风险 | 等级 | 缓解 |
|---|---|---|
| agent 以 root 被远程操控，凭据泄露等于整机失守 | 高 | mTLS + 单机吊销 + 能力默认关闭 + 白名单 + 审计 |
| 6 天 IP 证书续期失败导致全节点失联 | 高 | 续期看门狗 + 剩余 <48h 告警 + 保留自签回退开关 |
| 管理接口暴露公网被爆破 | 高 | 默认只监听内网 + 随机端口 + 限速 + 失败锁定 + 推荐组网访问 |
| 三个冷存储后端 + 四个告警渠道工作量被低估 | 中 | 全部走 trait/工厂，M4 单独排期 |
| Docker 管理需要 socket 权限（等价 root） | 中 | 文档明确警告；建议只挂载 socket 而非 privileged |
| SQLite 在大量小写入下锁竞争 | 中 | 批量事务 + WAL + 单写线程；超过 100 台默认推荐 PG |
| 母进程单点故障，磁盘损坏丢全部历史 | 高 | SQLite 每日 `VACUUM INTO` 备份 / PG dump；备份到冷存储 |
| 服务器时钟不同步导致曲线错位 | 中 | 采集带单调时钟，hub 记录 `clock_skew`，偏差 >5s 告警 |
| 前端图表在长跨度下卡顿 | 中 | 服务端选层 + LTTB 降采样，单次返回点数上限 2000 |

---

## 15. 变更流程

v1 期间新增需求进入 backlog，不插队到当前里程碑；只有影响数据模型或协议帧的变更需要重新评审（因为会破坏已安装节点的兼容性）。协议帧带 `version` 字段，hub 兼容低一个版本的 agent。
