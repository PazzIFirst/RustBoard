# 服务端 TLS 与证书（M5 Phase C）

本文说明 hub 的**服务端证书来源**、目录布局、ACME 申请/续期、80/443 前提，以及
agent 的三种信任模式。面板直连 HTTPS 见 [panel-tls.md](panel-tls.md)，ACME 安装器
细节见 [acme.md](acme.md)，按错误信息排查见 [troubleshooting.md](troubleshooting.md)。

> **实现状态**：Phase C 的 C0–C8 已在主线实现（ACME 客户端/挑战/续期、安装器
> 诊断与回退、面板 TLS、管理端 TLS、Docker/Compose 与本文档）；**尚未完成 C9
> 全量 e2e、独立评审/渗透与 `v1.0.0-rc.1` 的真实 Let's Encrypt staging 验证**。
> 本文不声称 RC 已完成或 v1.0.0 已发布。
>
> 兼容性：协议仍是 v2、SQLite schema 仍是 v7；旧 `hub.toml` 没有 `[tls]` 时
> 等价于 `mode = "self-signed"`，行为与 v0.4.2 一致。

## 1. 三种服务端证书来源

| `tls.mode` | 证书标识 | 证书签发者 | 适用场景 | agent 信任 |
|---|---|---|---|---|
| `self-signed`（默认） | `server_names` | 本地私有 CA（`certs/ca.crt`） | 内网、不开放 80/443 | `fingerprint`（指纹钉扎） |
| `acme-domain` | 1–20 个 DNS 名 | Let's Encrypt / 私有 ACME | 有公网域名，可开放 80 或 443 | `system-roots`（公共 ACME）或 `custom-ca`（私有 ACME） |
| `acme-ip` | 恰好 1 个公网 IPv4 | Let's Encrypt `shortlived` / 私有 ACME | 没有域名，用短期 IP 证书 | 同上 |

要点：

- 客户端证书 CA（`certs/ca.crt|ca.key`）与**服务端**证书来源已拆分。ACME 只替换
  `server.crt|server.key`；agent 的 mTLS/enrollment/renew 仍由本地客户端 CA 负责。
- ACME 证书是 leaf + 中间链，`server.crt` 里 **leaf 在第一张**；`server.key` 为
  PKCS8、0600。
- `self-signed` 的自签续期由既有 `cert_rotation` 管理；ACME 模式由
  `acme_renewal` 管理，两者互斥。
- 不支持 ACME DNS-01、通配符证书、HA/负载均衡；面板没有内置 ACME（远程面板用
  反代或手工证书）。

## 2. 证书目录、权限与备份

默认数据目录为 `/var/lib/rustboard/hub`（Docker 为 `/data/var/lib/rustboard/hub`）：

```text
<data_dir>/certs/
├── ca.crt                  0644  # mTLS 客户端证书 CA（不是 ACME 服务端证书）
├── ca.key                  0600
├── server.crt              0644  # 当前生效的服务端 leaf + chain
├── server.key              0600
├── server.crt.bak-*        0644  # 续期/切换备份，每类保留最近 5 份
├── server.key.bak-*        0600
├── .rotate.lock                  # CertLock：issue/renew/rotate-cert 互斥
└── acme/
    ├── account.json        0600  # ACME 账户 credentials（含账户私钥）
    └── state.toml          0600  # directory/domains/profile/上次签发/下次尝试/错误摘要
```

- 所有证书切换走同目录临时文件 + `rename` 原子写；失败保留旧材料，不会出现
  “配置指向新证书、磁盘还是旧证书”的半完成状态。
- 目录 `0700`；配置、私钥、账户文件 `0600`；证书 `0644`。启动时会收紧已有
  过宽权限，但不要把证书目录改回共享权限。
- 备份同时含 cert/key，按时间后缀成对保留；**不要手工拼凑**不同批次的
  cert/key。恢复时整对替换，或用安装事务/备份回滚。
- 私钥、ACME 账户 key、key authorization 不进入配置、日志、argv 或镜像。

## 3. 默认：self-signed

旧配置不需要新增任何字段：

```toml
# hub.toml（可省略整段）
[tls]
mode = "self-signed"
```

- 服务端证书 SAN 来自 `server_names`（安装时默认含 hostname、`127.0.0.1`、
  `localhost`、`--advertise` 与 `--san`）。
- agent 用指纹钉扎完成首次 enrollment，之后改用 CA + 主机名校验；服务端证书
  轮换由 hub 自动续签并热加载，不需要重新纳管。
- 手工重签：`rustboard-hub rotate-cert [--force] [--days N]`。ACME 模式下该命令
  会被拒绝，提示改用 `tls issue` / `tls renew`。
- 给 `server_names` 新增地址后，需要先 `rotate-cert --force`，否则管理端 TLS
  或 agent 主机名校验可能失败。

## 4. ACME：域名证书与 IP 证书

### 4.1 配置

```toml
[tls]
mode = "acme-domain"            # acme-domain | acme-ip
acme_email = "admin@example.com" # ACME 模式必填
acme_directory = "https://acme-v02.api.letsencrypt.org/directory"
challenge = "http-01"           # http-01 | tls-alpn-01
domains = ["board.example.com"] # acme-domain: 1–20 个 DNS；acme-ip: 恰好 1 个 IPv4
acme_profile = ""               # 例如 shortlived；acme-ip 留空时默认 shortlived
acme_ca_file = ""               # 仅私有/Pebble ACME；PEM 绝对路径
staging_check = true            # 安装时先跑一次 staging（acme-ip 默认跳过）
fallback_to_self_signed = true  # ACME 失败时回退自签继续安装
```

字段约束（在启动/安装校验阶段 fail-closed）：

- `acme_email` 非空、无空白/控制字符；`acme_directory` 必须 `https://`，不能带
  userinfo（`@`）或 fragment（`#`）。
- `acme-domain` 的域名不能是 IP、不能含通配符 `*`、不能有首尾点/空标签；
  `acme-ip` 只接受公网 IPv4，恰好一个。
- `acme_profile` 只允许字母、数字、`-`、`_`，最长 64 字节。
- `acme_ca_file` 必须是绝对路径、普通文件；只用于私有/Pebble ACME。公共
  Let's Encrypt 使用系统根，不要设置它。

### 4.2 安装与签发命令

```bash
# 域名 + HTTP-01
sudo rustboard-hub install --yes \
  --tls acme-domain --acme-email admin@example.com \
  --domain board.example.com --acme-challenge http-01

# 公网 IP + shortlived
sudo rustboard-hub install --yes \
  --tls acme-ip --acme-email admin@example.com \
  --domain 203.0.113.10 --acme-challenge http-01 --acme-profile shortlived

# 只开 443：TLS-ALPN-01
sudo rustboard-hub install --yes \
  --tls acme-domain --acme-email admin@example.com \
  --domain board.example.com --acme-challenge tls-alpn-01

# 查看 / 强制重签 / 到期续期（都必须指向同一配置文件）
sudo rustboard-hub tls status --config /etc/rustboard/hub.toml
sudo rustboard-hub tls issue  --config /etc/rustboard/hub.toml
sudo rustboard-hub tls renew  --config /etc/rustboard/hub.toml
```

- `tls status` 只读：模式、域名、challenge、目录、证书 SAN/到期/指纹、上次签发、
  下次尝试和最近错误摘要。不会打印私钥或账户 key。
- `tls issue` 强制重签；`tls renew` 只在到期窗口内发起网络请求和写入。
- 两个命令与自动续期、`rotate-cert` 共用 `<cert_dir>/.rotate.lock`，并发执行只会
  有一个成功；失败保留旧证书并非零退出。
- 容器内执行（默认入口已初始化 volume）：
  `docker compose exec hub rustboard-hub tls status --config /data/etc/rustboard/hub.toml`。
  `tls renew/issue` 需要 root 绑定 80/443 和写证书目录，`docker compose exec`
  默认以容器 root 执行；不要用 `--user 10001` 执行签发。

### 4.3 80/443 与诊断

| 挑战 | 签发/续期时临时绑定 | ACME 服务端访问 |
|---|---|---|
| `http-01` | `0.0.0.0:80` | `GET http://<domain>/.well-known/acme-challenge/<token>` |
| `tls-alpn-01` | `0.0.0.0:443` | 只以 ALPN `acme-tls/1` 握手 |

- 安装器在写配置/unit/二进制前做四层只读诊断：本地 bind、本机防火墙
  （ufw/firewalld/nftables/iptables）、云元数据（AWS/阿里云/腾讯云）、ACME
  staging 实跑。**不会自动修改防火墙或安全组**。
- 本地 bind 失败是硬失败；防火墙/云安全组只打印精确放行命令与控制台路径。
- 最多尝试 3 轮；失败按 `fallback_to_self_signed` 回退自签并继续安装，打印
  `install --force --tls acme-*` 重试命令。
- 80/443 被 nginx/apache/Caddy/另一个 hub 占用时：停止占用服务，或改用另一种
  挑战。容器里还要确认 `ports` 已发布；详见 [troubleshooting.md](troubleshooting.md)。

### 4.4 staging 与 production

- 默认 directory 为 Let's Encrypt production；`staging_check = true` 时安装器先
  用 staging 目录申请一次临时证书（不可信、可丢弃），再走 production。
- `acme-ip` 默认跳过自动 staging（`shortlived` 在 staging 的策略可能不同），以
  production 结果为准；需要手工验证时显式设置 staging directory。
- 自定义 `acme_directory`（Pebble/私有 ACME）不会自动叠加 staging：你指定的
  目录就是实际使用的目录。
- 公共 staging 证书不被 agent/浏览器信任，只用于验证 DNS、端口、挑战链路。
- 调试务必先用 staging，避免消耗 production 速率限制；见
  [acme.md §11](acme.md#11-lets-encrypt-速率限制)。

## 5. 续期、退避与热加载

- 续期阈值：剩余寿命 ≤ `min(lifetime/3, 48h)`。因此 90 天证书在剩余约 48 小时
  续期；6 天的 IP `shortlived` 证书也在剩余 48 小时续期。
- 检查周期复用 `cert_check_interval_secs`（最小 60 秒）；每次检查读当前
  `server.crt` 判断是否到期。
- 失败退避：1m → 5m → 15m → 1h → 6h（封顶 6h），失败**保留旧证书**，hub
  不退出、不重启；`state.toml` 记录 `next_attempt_unix` 与脱敏错误摘要。
- 成功后原子写 `server.crt|server.key`，重建启用 mTLS 的 `ServerConfig` 并通过
  既有 cert watcher 推送；**新连接**立即使用新证书，无需重启 hub。既有的
  agent 会话不强制断开。
- 剩余寿命低于既有告警配置 `alerts.cert_warn_hours`（默认 48 小时）时，按现有
  证书告警规则告警；续期失败本身只写 WARN/状态，不触发 hub 重启。
- 手动 `tls renew` 与自动续期共用锁；不要并发执行多个 `issue`/`renew`。

## 6. 失败回退与恢复

- 安装失败最多 3 轮；`fallback_to_self_signed = true`（默认）时：
  1. 打印分层诊断和修复后的重试命令；
  2. 把配置写为 `self-signed`，用本地 CA 签服务端证书继续完成安装；
  3. 已有 agent 不会因为一次 ACME 失败而失联（仍是自签指纹/CA 信任）。
- `fallback_to_self_signed = false` 时安装中止，配置/unit/二进制由安装事务回滚；
  不会留下半份 ACME 配置。
- 已有安装的 `server.crt|server.key` 在 ACME 尝试前会成对快照；后续安装失败时
  恢复旧证书。全新安装失败时由事务回滚删除本次新建的数据目录。
- ACME 账户/状态可能保留在数据目录中，便于修复后重试；证书和配置只会是
  self-signed 或 ACME 中的一种。
- 回退后务必用 `rustboard-hub tls status` 确认真实来源，不要把自签安装误当成
  ACME；然后修复端口/DNS/防火墙，执行打印的 `install --force --tls acme-*`。

## 7. agent 三种信任模式

`agent.toml` 新增 `tls_mode` 与 `server_ca`（均有默认值，旧配置不变）：

```toml
tls_mode = "fingerprint"   # fingerprint | system-roots | custom-ca
server_ca = ""             # custom-ca 必填；PEM 绝对路径
server_fingerprint = ""    # fingerprint 必填；旧配置兼容
```

| 模式 | 服务端信任 | 适用 | 安装参数 |
|---|---|---|---|
| `fingerprint` | 固定 SHA-256 指纹；自签 hub 的默认 | self-signed | `--fingerprint <64-hex>` |
| `system-roots` | 系统根证书 + URL 主机名校验 | 公共 ACME | `--tls-mode system-roots` |
| `custom-ca` | `server_ca` 指定的 CA + 主机名校验 | 私有 ACME / 私有 CA | `--tls-mode custom-ca --server-ca <pem>` |

- 旧配置缺 `tls_mode` → `fingerprint`；旧指纹 agent 接入 self-signed hub 不受影响。
- **ACME hub 不兼容 v0.4 指纹 agent**：ACME 证书不是本地 CA 签发，旧 agent 的指纹
  钉扎/本地 CA 校验会失败。hub 启动日志会 WARN；`hub agent add` 会按模式输出
  `--tls-mode system-roots` 或 `--tls-mode custom-ca --server-ca ...`，并附带
  “请升级 agent”提示，不会输出无法使用的指纹命令。
- 已纳管 agent 仍使用 `agent_data/ca.crt` 校验**客户端证书**的签发者；它不再自动
  作为服务端信任根。安装器把 `--server-ca` 复制到 `<data_dir>/server-ca.pem`（0644）。
- 自定义 CA 文件可以是多张 PEM 的 bundle；不要指向可被普通用户替换的路径。
- 详细迁移与逐模式示例见 [acme.md §7](acme.md#7-失败与回退) 与 agent 安装帮助。

## 8. 兼容、迁移与回滚

- **协议/数据库不变**：不新增协议帧、不改 SQLite schema v7；只新增配置字段与
  证书来源。
- **旧 hub 配置**：缺 `[tls]` → self-signed；已有 `server.crt/key` 不覆盖。
- **模式切换**：安装器不会因为改环境变量/配置就自动重签。self-signed ↔ ACME
  需要 `rustboard-hub install --force --tls ...`（或 `tls issue`），并由管理员
  确认 SAN/80/443 前提；Docker 见 [docker.md](docker.md#6-acme-与证书持久化)。
- **升级**：`upgrade` 不重写证书/ACME 账户；已有 ACME 配置继续使用原目录/
  profile。切换 directory 或 profile 需要 `install --force` + `tls issue`。
- **回滚**：安装失败由事务回滚；ACME 失败回退自签；续期失败保留旧证书；
  证书成对备份保留最近 5 份。已发布 tag 不移动。
- **ACME 与离线互斥**：`--offline` + ACME 会在写盘前失败；默认 self-signed 仍
  自动离线。详见 [offline.md §4.1](offline.md#41-离线与-acme-互斥)。

## 9. 相关文档

- [ACME 安装与 80/443 诊断](acme.md)
- [面板直连 HTTPS 与 hub CA](panel-tls.md)
- [Docker 部署与 ACME 叠加](docker.md) / [docker/README.md](../../docker/README.md)
- [离线安装](offline.md) / [发布流水线](release.md)
- [故障排查](troubleshooting.md)
- 设计依据：[Phase C 计划](../plans/2026-10-25-m5-phase-c-tls-release-gates.md)、
  [C0 spike](../plans/2026-10-25-m5-phase-c-spike.md)
