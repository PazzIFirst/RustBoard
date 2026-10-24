# M5 安装与交付计划（v1.0.0）

> 状态：计划（未开工）　｜　基线：`v0.4.2`（`ada9d19`）　｜　目标版本：`v1.0.0`
> 输入：[requirements.md](../requirements.md) §3/§9/§10/§12/§14、[AGENTS.md](../../AGENTS.md) §6/§8、
> [status.md](../status.md)、[known-issues.md](../known-issues.md)
> 目标：把现有 hub/agent/panel 从“源码可运行”交付为**可在全新 Linux 机器上安装、
> 升级、卸载、离线部署、容器化运行**的 v1.0.0 产品，并补齐 ACME 与 PostgreSQL。

## 1. 目标与验收

### 1.1 必须达成

| # | 目标 | 可验证验收 |
|---|---|---|
| G1 | 交互/非交互安装器 | 全新 x86_64 与 arm64 机器上，hub/agent/panel 各自可用一条命令安装；`--yes` 非交互完成 |
| G2 | 三步安装 | 全新 arm64 机器：下载/解包 → 安装 hub（含面板）→ 纳管 agent，三步内可登录面板看到数据 |
| G3 | 离线安装 | 断网环境用离线包完成安装，`--offline` 不发起任何网络探测/ACME |
| G4 | 80/443 自检 | 端口被占用/防火墙/云安全组/ACME staging 失败时，安装器能定位到具体层并给出放行命令；不阻塞回退自签 |
| G5 | 多架构交付 | `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl` 静态二进制；GHCR 多架构镜像 |
| G6 | ACME | `acme-domain` 与 `acme-ip` 可签发、热加载、自动续期；失败 <48h 告警；可回退自签 |
| G7 | PostgreSQL | `database = "postgres://..."` 安装并运行；与 SQLite 行为一致；迁移/备份/恢复可验证 |
| G8 | 面板 TLS | 面板可配置证书/私钥直接 HTTPS，或文档化反代；不再要求“M5 前只能明文” |
| G9 | 升级/卸载 | `upgrade` 保留数据与配置；`uninstall` 默认保留数据，`--purge` 明确删除 |
| G10 | 可回滚 | 安装失败自动恢复 systemd/config；ACME 失败回退自签；PG 失败不破坏旧库 |
| G11 | 安全 | 安装器不泄露 secret、不以 argv 传 token、文件和 systemd 权限收紧；独立渗透无高危 |

### 1.2 发布门槛

- 全部功能测试 + 安装/升级/离线/容器/ACME/PG 端到端通过；
- 100/500/1000 agent 压力和 ≥24h 长稳（RSS 增长 ≤10%）；
- 独立评审 + 渗透无未修复高危；
- `cargo audit` 0、CI 全绿；
- `v1.0.0` tag 只打在通过全部门禁的 main 提交上，镜像同步推送。

## 2. 范围

### 2.1 在范围内

1. **安装器**：交互/非交互、系统探测、网络自检、配置生成、systemd、自检、回滚；
2. **交付物**：musl 静态二进制、离线 tar.gz、systemd unit、Docker 镜像、SHA256/
   GitHub attestation；
3. **TLS/ACME**：`self-signed` / `acme-domain` / `acme-ip` 三模式，ACME 续期与看门狗；
4. **PostgreSQL**：`Storage` 后端、schema v7 等价迁移、安装探测、备份/恢复；
5. **面板 TLS**：证书/私钥直接监听，或文档化反代方案；
6. **运维**：`install` / `upgrade` / `uninstall` / `backup` / `restore`；
7. **文档**：安装、TLS、PG、Docker、离线、arm64、升级、卸载、故障排查；
8. **发布流水线**：tag 触发的多架构构建、镜像、Release 资产、SBOM/attestation。

### 2.2 不在范围内

- v2 功能：文件管理、Web 终端、多用户/RBAC、OIDC、移动端、IPv6；
- HA/集群、Kubernetes Operator、Windows/macOS 服务端；
- ACME DNS-01（v1 只做 HTTP-01 / TLS-ALPN-01；需要 DNS-01 的部署走反代/外部证书）；
- 第三方对象存储/通知渠道的额外适配（M4 已有范围）；
- 现有 KI-22 硬链接防护（仍 v0.5+ 评估）。

## 3. 现状与差距

| 能力 | 现状 | M5 需要补 |
|---|---|---|
| 安装 | 只能手工 `init` + 写配置 + 自建 systemd | 安装器、探测、回滚、幂等 |
| 证书 | 自签 CA + 固定指纹 | ACME domain/IP、独立 client CA、续期热加载 |
| 存储 | SQLite 具体类型 `SqliteStorage` | `Storage` 抽象 + PG 实现 + 迁移 |
| 面板 | 明文 HTTP，回环 | 直接 TLS（证书/私钥）或反代文档 |
| 打包 | 无 Dockerfile/离线包 | musl、tar.gz、多架构镜像、SBOM |
| 运维 | 无 upgrade/uninstall/backup 命令 | 四个生命周期命令 + 数据保留 |
| 发布 | 手工 tag + Release | tag 触发 release workflow、镜像推送 |

## 4. 关键设计决策

### 4.1 安装器形态

- 新增 **`rustboard-install` 库 crate**，承载系统探测、提示、配置生成、systemd、
  网络自检、回滚；**不新增独立用户入口**，在三个现有二进制上加子命令：
  - `rustboard-hub install|upgrade|uninstall`
  - `rustboard-agent install|upgrade|uninstall`
  - `rustboard-panel install|upgrade|uninstall`
- 分发包同时提供 `sd-hub` / `sd-agent` / `sd-panel` 兼容 symlink，指向
  `rustboard-*`，兼容 requirements 中的历史命令名。
- 安装状态写入 `/var/lib/rustboard/install-state.toml`（角色、版本、文件清单、
  systemd unit、备份路径），供升级/卸载；数据目录与状态分离。
- 非交互全部 flag 化；token 只从 stdin/0600 文件读取，**禁止 argv**（进程列表泄露）。
- 先写临时目录并校验，再原子替换/启动；失败自动恢复旧 unit/config，数据目录不动。
- 支持 `--dry-run`、`--yes`、`--offline`、`--force`、`--prefix`（测试用）。

### 4.2 TLS 与 ACME / mTLS

- 保留现有私有 CA 作为**客户端证书 CA**（agent mTLS），新增独立的服务端证书来源：
  - `self-signed`：现有私有 CA 签发服务端证书；agent 用 `server_fingerprint` 钉扎；
  - `acme-domain`：ACME 公网证书；agent 用系统根证书/`server_ca` + server name 校验；
  - `acme-ip`：LE 6 天 IP 证书（或 ZeroSSL 90 天，需 EAB）；agent 同样不钉扎。
- **关键兼容性**：ACME 证书每次续期都会变化，v0.4 的 `server_fingerprint` 钉扎
  无法用于 ACME。v1 agent 增加 `server_ca`/`tls_mode`；ACME 模式要求 agent 升级到
  v1，安装器必须显式提示。自签模式继续支持旧 agent 的指纹钉扎。
- 新增 `[tls]` 配置段（仅服务端证书来源；管理 API 的 `admin_tls` 保留）：
  ```toml
  [tls]
  mode = "self-signed" | "acme-domain" | "acme-ip"
  acme_email = "..."
  acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
  challenge = "http-01" | "tls-alpn-01"
  domains = ["board.example.com"]
  ```
- ACME 账户 key / 证书 / 私钥固定 0600；续期在剩余寿命 1/3 时执行；`acme-ip` 约
  每 4 天续期；续期写文件后走现有 TLS 热加载；<48h 触发内置告警。
- 挑战失败 → 安装器最多重试 3 轮 → 回退 `self-signed` + 指纹，继续安装。
- 80/443 自检顺序（与 requirements §10.4 一致）：本地监听 → 防火墙（ufw/firewalld/
  nftables/iptables）→ 云元数据（169.254.169.254）→ ACME staging 实跑 → 明确分层
  结论；未开放时给出控制台操作路径，不假装成功。
- 面板：新增 `tls_cert` / `tls_key`，直接 HTTPS；**v1 不做面板内置 ACME**，远程
  面板推荐 Caddy/nginx 反代并给出示例；安装器同机面板可选“复用 hub 证书”仅在
  SAN 覆盖时允许。

### 4.3 PostgreSQL 存储

- 保持 SQLite 为默认后端；`database` 为 `postgres://` / `postgresql://` 时启用 PG。
- 把 hub 对 `SqliteStorage` 的依赖抽象为 `StorageBackend`（trait 或受控 enum），
  覆盖现有全部查询：ingest 幂等、查询选层、降采样/retention、告警状态/事件/静默、
  归档、审计、token、维护状态。
- schema 与 SQLite v7 等价；PG 独立 migration 表，SQL 只使用两边共同子集；批量
  ingest 用事务 + 唯一约束保证 `(agent_id, epoch, seq)` 幂等。
- 连接池与超时；TLS 连接；密码只从配置/环境读，日志/错误不输出 DSN。
- 迁移路径：SQLite → PG 提供**离线导出/导入工具**（`rustboard-hub migrate --to`），
  不自动双写；迁移前强制备份，失败不切换。
- 备份：SQLite `VACUUM INTO`；PG 使用 `pg_dump`（文档要求安装客户端）或等价只读
  导出；`restore` 前校验目标空/显式 `--force`。

### 4.4 交付与镜像

- 二进制：`x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl`，release +
  `strip`/`lto` 已有；检查 `ldd` 为 static。
- 离线包：`serverdashboard-v1.0.0-<arch>.tar.gz`，含三个二进制、systemd unit、
  安装说明、`SHA256SUMS`、LICENSE；`--offline` 跳过网络与 ACME。
- Docker：多阶段构建；`ghcr.io/pazzifirst/rustboard-{hub,panel,agent}:v1.0.0` 与
  `latest`，`linux/amd64,linux/arm64`；hub/panel 非 root，agent 默认非 root，
  控制面需要宿主 `/proc`、systemd/Docker socket 时文档明确风险，不默认 privileged。
- CI：tag `v*` 触发 release workflow；build matrix → 静态检查 → 多架构镜像 →
  SBOM/attestation → GitHub Release 资产；普通 push 只跑测试，不推镜像。

### 4.5 生命周期

- `upgrade --from <tar>`：校验版本/架构/签名 → 备份 config/unit → 停服务 → 替换
  二进制 → 迁移检查 → 启动/健康检查 → 失败回滚。
- `uninstall [--purge]`：默认停服务、删 unit/二进制/状态，**保留数据目录**；
  `--purge` 二次确认后删除数据；绝不静默删证书私钥。
- 备份 systemd timer（可选）每日执行 `backup` 到指定目录，保留 N 份；不覆盖冷归档。

## 5. 接口与数据变更

### 5.1 CLI（新增）

```text
rustboard-hub install [--yes] [--offline] [--dry-run] [--force]
  [--db sqlite|postgres://...] [--listen ...] [--admin-listen ...]
  [--tls self-signed|acme-domain|acme-ip] [--acme-email ...]
  [--retention raw=7d,1m=90d,1h=2y] [--panel yes|no] [--prefix /]
rustboard-agent install [--yes] [--offline] [--hub wss://...]
  [--token-file <0600>] [--fingerprint SHA256:... | --server-ca <pem>]
  [--name <name>] [--prefix /]
rustboard-panel install [--yes] [--offline] [--hub-url ...]
  [--hub-token-file <0600>] [--tls-cert <pem> --tls-key <pem>] [--listen ...]
rustboard-hub upgrade --from <tar> | uninstall [--purge]
rustboard-hub backup --to <dir> | restore --from <file> [--force]
rustboard-hub migrate --to postgres://... [--dry-run]
```

所有路径/值经参数数组传给 `Command`，不拼 shell；安装器打印的命令复用 v0.4.1 的
POSIX 引用函数。`--token`/密码不接受明文 argv，只接受 stdin/文件。

### 5.2 配置

- `[tls]`：新增（见 §4.2）；缺省 `self-signed`，旧配置无需改动。
- `database`：已有字段扩展为 SQLite 路径或 PG URL；旧 SQLite 配置完全兼容。
- `[panel.tls]` 或顶层 `tls_cert`/`tls_key`：面板可选。
- `/var/lib/rustboard/install-state.toml`：安装器私有状态，非用户配置。
- systemd unit：`packaging/systemd/rustboard-{hub,agent,panel}.service`，含
  `NoNewPrivileges`、`ProtectSystem=strict`、最小 `ReadWritePaths`；agent 控制面
  所需权限单独 drop-in，不全局放宽。

### 5.3 协议/数据库兼容

- **协议 v2 不变**；不新增帧类型，不改变 Hello/Batch/Control 语义。
- SQLite schema v7 不变；M5 只增加安装状态与 PG 后端。PG schema 与 v7 同构，
  独立 migration 版本，不改 SQLite `user_version`。
- 证书格式：自签模式不变；ACME 模式新增 PEM 文件与服务端证书来源，客户端证书
  仍由私有 CA 签发。ACME 模式是**有意兼容性变化**：v0.4 agent 需升级并改用 CA
  信任（安装器检测并提示）；自签模式不受影响。

## 6. 阶段拆解

### Phase A：安装器内核与自签安装（2026-10-27 – 11-07）

交付：

- `crates/rustboard-install` 库：系统探测、ANSI 交互、flags、配置生成、systemd、
  `--dry-run`/`--offline`、安装状态、回滚；
- 三个二进制 `install` 子命令；自签 hub + 同机 panel + agent 纳管；
- `packaging/systemd/*.service`；
- 安装 e2e（systemd 容器 + 临时 prefix）。

验收：

- 全新 x86_64/arm64 容器三步安装；重复执行幂等；失败注入回滚不破坏旧服务；
- 旧 v0.4 手工配置可被 `upgrade` 识别（不重写数据）；
- 配置/私钥 0600，unit 通过 `systemd-analyze verify`。

### Phase B：离线包、静态构建与 Docker（11-03 – 11-14）

交付：

- musl x86_64/aarch64 构建与 `SHA256SUMS`；
- 离线 tar.gz + `--offline` 全流程；
- Dockerfile（hub/panel/agent），多架构 buildx，GHCR 推送；
- release workflow（tag 触发）、SBOM/attestation。

验收：

- 无网 netns 安装成功且不发起 DNS/HTTP；
- qemu arm64 启动并完成 healthz/install；
- Docker 三镜像 `linux/amd64,linux/arm64` 启动，hub/panel 非 root；agent 控制面
  风险文档有明确警告；
- `docker run` 无法读取宿主配置/私钥（仅挂载所需目录）。

### Phase C：ACME 与面板 TLS（11-10 – 11-21）

交付：

- `[tls]` 配置、ACME 客户端、HTTP-01/TLS-ALPN-01、staging 自检、续期热加载、
  <48h 告警、回退自签；
- 独立 client CA 与服务端证书来源拆分；agent `server_ca`/`tls_mode` 配置与迁移；
- 面板手动 TLS（cert/key）与反代文档；
- Pebble 本地 ACME e2e + LE staging 手工门禁。

验收：

- 域名/公网 IP 两种模式签发与续期模拟；证书 SAN/链/到期正确；
- 80/443 被占用、防火墙、云安全组、staging 失败四类诊断输出准确；
- 失败 3 轮回退自签且安装继续；
- v0.4 指纹 agent 在 ACME 模式下被明确拒绝并给出升级指引；v1 agent 可连接；
- 面板 HTTPS 可登录，CSP/Cookie 不回归。

### Phase D：PostgreSQL、备份与迁移（11-10 – 12-04，可与 C 并行）

交付：

- `StorageBackend` 抽象与 `PostgresStorage`；
- schema/migration、连接池、TLS、错误脱敏；
- SQLite ↔ PG 迁移/备份/恢复；
- 安装器 `--db postgres://` 探测与配置；
- PG 与 SQLite 的 parity/concurrency/性能测试。

验收：

- 同一批次数据在两种后端查询结果一致（数值容差/时间边界一致）；
- 事务中断、重复 `(agent,epoch,seq)`、retention/downsample/alert/archive 全绿；
- PG 200 agent 写入/查询达标；连接断开自动重连且不丢已提交数据；
- 备份恢复后点数/时间范围/告警状态一致；迁移失败不切换、不破坏 SQLite。

### Phase E：文档、安全、压力与发布（12-01 – 12-12）

交付：

- `docs/install/*`、README 快速开始、TLS/PG/Docker/离线/升级/卸载/故障排查；
- 独立评审 + 渗透（安装器提权、路径/命令注入、secret、ACME key、镜像/供应链）；
- 100/500/1000 agent 压力、24h 长稳、恢复演练；
- CHANGELOG/status/known-issues、`v1.0.0` tag/Release/镜像。

验收：

- 全新 arm64 三步安装；离线包；80/443 未开准确引导；
- 渗透无未修复高危；24h RSS 增长 ≤10%；
- 所有门禁 + 镜像 digest 可追溯；v1.0.0 release notes 完整。

## 7. 测试矩阵

| 类别 | 用例 | 门禁 |
|---|---|---|
| 安装器单元 | 参数解析、探测、引用、路径、回滚、幂等 | 每次提交 |
| systemd e2e | 三角色安装/启动/健康/重启/卸载 | 阶段 |
| 离线 | netns 无网安装 + `--offline` 无探测 | 阶段 |
| 跨架构 | x86_64 + qemu arm64 musl 静态二进制 | 阶段 |
| Docker | 三镜像、非 root、只读根、健康检查 | 阶段 |
| ACME | Pebble http-01/tls-alpn-01、续期、回退、80/443 诊断 | 阶段 |
| PG | parity、并发、迁移、备份恢复、断开重连 | 阶段 |
| 升级 | v0.4.2 → v1.0.0、失败回滚、数据保留 | 阶段 |
| 卸载 | 默认保留数据；`--purge` 二次确认 | 阶段 |
| 压力 | 100/500/1000 agent、24h、磁盘满/断网 | 发布 |
| 安全 | 安装器提权、secret argv、路径/命令注入、ACME key、供应链 | 发布 |

## 8. 兼容性、迁移与回滚

### 8.1 兼容性

- 协议 v2、SQLite schema v7、API 路径不变；
- 旧 SQLite 配置与自签 agent 继续可用；v0.4 agent 保持指纹连接自签 hub；
- ACME 模式要求 v1 agent（CA 信任）；安装器必须提示，不静默切换；
- 面板默认仍可明文回环；启用 TLS 后旧反代可继续终止 TLS。

### 8.2 迁移

1. 备份 config/DB/证书到 `/var/lib/rustboard/backups/<timestamp>`；
2. 停服务 → 校验新二进制/签名 → 迁移（SQLite 无需 schema 变更；PG 走 migration）→
   启动 → healthz/API/agent 连接检查；
3. 失败恢复旧二进制/config/unit；PG 切换失败不删除旧 SQLite。

### 8.3 回滚

- 安装器保留上一版本二进制与 unit；`upgrade` 失败自动回滚；
- ACME 失败回退自签，保留旧私钥/证书备份，不删除账户 key；
- PG 回滚使用迁移前备份；SQLite 原文件不动；
- tag 只打通过门禁的提交；已推送 tag 不移动，修复走新 patch。

## 9. 安全要求

- 安装器以 root 执行：所有外部输入用参数数组，不拼 shell；路径规范化/拒绝 `..`；
- token/password 只走 stdin/0600 文件，禁止出现在 `ps`/日志/错误；
- 配置/证书/私钥 0600，数据目录 0700；systemd 最小权限 + `NoNewPrivileges`；
- ACME 账户 key、证书私钥 0600；失败日志不含 DNS/账号敏感信息；
- 离线包/SHA256/attestation 校验；镜像固定 digest，不使用 `latest` 作为默认；
- Docker agent 控制面默认关闭；需要 socket/privileged 时文档高亮风险；
- 独立渗透覆盖安装器提权、命令注入、路径穿越、secret 泄露、供应链。

## 10. 风险与未决项

| 风险 | 等级 | 缓解 |
|---|---|---|
| ACME IP 证书外部依赖/速率限制/公网 IP 变化 | 高 | staging 自检、4 天续期、<48h 告警、回退自签；文档说明 |
| ACME 与 mTLS 双 CA 迁移破坏旧 agent | 高 | 自签默认不变；ACME 显式升级提示；安装器拒绝静默切换 |
| PG 与 SQLite 行为漂移 | 高 | parity 测试矩阵、同一 SQL 子集、迁移前备份、先只读校验 |
| musl/arm64/ring 交叉构建失败 | 中 | CI matrix + qemu；提前 spike |
| 安装器 root 提权/命令注入 | 高 | 参数数组、路径校验、独立渗透、最小权限 unit |
| Docker 控制面需宿主权限 | 中 | 默认关闭；文档警告；非 root 优先 |
| 范围过大（ACME+PG+打包） | 高 | Phase C/D 并行；11-21 go/no-go；不满足则不发 v1.0.0 |
| 面板直接 ACME 复杂 | 中 | v1 只做手动证书/反代；不把面板 ACME 作为阻塞项 |

未决项（Phase A 前定）：

1. ACME 库选型（`instant-acme` 或等价纯 Rust）与 ZeroSSL EAB 支持；
2. PG 驱动/连接池（同步 `postgres` + 池，或 `sqlx`）与迁移工具；
3. 面板是否在 v1 内置 ACME（当前建议：不内置，只支持手动证书/反代）；
4. 二进制兼容名：保留 `rustboard-*` + `sd-*` symlink 是否足够；
5. 包签名方案：GitHub attestation + SHA256，是否再加 minisign。

## 11. 时间表（建议）

| 日期 | 交付 |
|---|---|
| 2026-10-27 – 11-07 | Phase A：安装器 + 自签 + systemd e2e |
| 11-03 – 11-14 | Phase B：musl/离线包/Docker/release workflow |
| 11-10 – 11-21 | Phase C：ACME + 面板 TLS + Pebble/staging |
| 11-10 – 12-04 | Phase D：PostgreSQL + 备份/迁移（与 C 并行） |
| 11-21 | go/no-go：ACME 与 PG 是否满足 v1 门槛 |
| 12-01 – 12-12 | Phase E：文档/渗透/压力/长稳/v1.0.0 |

人员假设：1 名主程 + 1 名测试/运维；若只有 1 人，Phase C/D 顺序执行，目标顺延，
不降低验收标准。

## 12. 完成定义（DoD）

- [ ] 全新 arm64 机器三步安装，面板可见 hub 自身与 agent 数据；
- [ ] 离线包无网安装成功，`--offline` 无网络探测；
- [ ] 80/443 被占用/防火墙/云安全组/staging 失败均能准确定位并引导；
- [ ] ACME domain 与 IP 模式签发、续期、热加载、<48h 告警、回退自签通过；
- [ ] PostgreSQL 后端 parity/并发/迁移/备份恢复通过；
- [ ] 面板直接 TLS 或反代方案可用，无 Cookie/CSP 回归；
- [ ] `upgrade`/`uninstall`/`backup`/`restore` 通过，默认保留数据；
- [ ] Docker amd64/arm64 三镜像可运行，非 root 默认，风险文档完整；
- [ ] 100/500/1000 agent 与 24h 长稳达标；
- [ ] 独立评审/渗透无未修复高危，CI 全绿，audit 0；
- [ ] `v1.0.0` tag/GitHub Release/镜像 digest 可追溯，CHANGELOG 完整。

## 13. 关联

- [requirements.md](../requirements.md) §9/§10/§12/§14
- [status.md](../status.md)
- [known-issues.md](../known-issues.md)
- [AGENTS.md](../../AGENTS.md) §6/§8
- [M4 方案](2026-10-24-m4-alerting-archive.md)
- [v0.4.1 修复计划](2026-10-24-known-issues-fix.md)
- [M4 渗透报告](../security/2026-10-24-m4-pentest-report.md)
