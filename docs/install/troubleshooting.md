# TLS / ACME 故障排查（M5 Phase C）

本文按“最常见的失败顺序”组织：端口 → 防火墙/安全组 → DNS → ACME 限额 →
证书/SNI → 权限 → 容器/管理端。命令中的域名、IP、路径都是占位符。

> 先保护证据再排障：`hub.toml` 含 `admin_token`，`certs/` 含私钥与 ACME 账户
> key。不要把配置原文、私钥、key authorization、enrollment token 贴到工单或
> 聊天里；只提供错误摘要、公开证书信息（SAN/有效期/指纹）与端口状态。

## 1. 快速分诊

| 现象 | 先看 |
|---|---|
| 安装器报 80/443 被占用 | §2 |
| 本机 bind 成功，但公网访问超时 | §3、§4 |
| ACME 报 `rate limited` / 验证失败次数过多 | §5 |
| 证书签发成功，agent/面板仍报证书错误 | §6、§7 |
| `tls_key` / `tls_cert` 权限或符号链接被拒 | §8 |
| 容器里 ACME 端口不通、entrypoint 跳过安装、healthcheck 红 | §9 |
| `admin_tls=required` 后面板/健康检查失败 | §10 |
| 启动报“管理 API 只绑定回环地址...没有该回环 IP 的 SAN” | §10.1 |
| 想确认当前证书来源与到期 | `rustboard-hub tls status --config ...` |

## 2. 80/443 被占用

ACME 签发/续期时 hub 会临时绑定：

- `http-01` → `0.0.0.0:80`
- `tls-alpn-01` → `0.0.0.0:443`

本机已有 nginx/apache/Caddy/另一个 hub 时，安装器在写配置前就会硬失败：

```text
[失败] 本地 bind: 80 端口占用，ACME http-01 无法完成验证：...
```

排查：

```bash
# 谁占用了 80/443（root 才能看到 PID/进程名）
sudo ss -ltnp 'sport = :80'
sudo ss -ltnp 'sport = :443'
sudo lsof -nP -iTCP:80 -sTCP:LISTEN
sudo lsof -nP -iTCP:443 -sTCP:LISTEN

# systemd 服务
systemctl list-units --type=service --state=running | grep -Ei 'nginx|apache|caddy|traefik'
```

处理：

- 停止占用服务：`sudo systemctl stop nginx`（确认不是生产入口后再停）；
- 或改用另一种挑战：只开 443 用 `--acme-challenge tls-alpn-01`；
- 容器里还要确认 `ports` 已发布：`docker compose port hub 80` /
  `docker compose port hub 443`；
- 不要让 hub 和反代同时抢占 80/443；需要反代时由反代终止 TLS，hub 用
  self-signed 或反代后的上游，不要对同一域名同时跑两套 ACME。

安装器只会打印 `ss`/防火墙建议，**不会自动停止服务或改防火墙**。

## 3. 本机防火墙

只读检测 `ufw`、`firewalld`、`nftables`、`iptables`；只打印命令，不执行。

```bash
# ufw
sudo ufw status verbose
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# firewalld
sudo firewall-cmd --state
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --permanent --add-port=443/tcp
sudo firewall-cmd --reload

# nftables（示例；按现有表/链调整，不要整表覆盖）
sudo nft list ruleset
sudo nft add rule inet filter input tcp dport { 80, 443 } accept

# iptables（示例；持久化方式取决于发行版）
sudo iptables -S
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
```

验证本机监听与外网可达是两件事：`ss` 只能证明本机 bind，云主机还要看 §4。

## 4. 云安全组与公网入口

安装器只做 1 秒超时的云元数据探测（AWS/阿里云/腾讯云），打印控制台路径，
不读取凭证、不修改安全组。

| 云 | 入站放行 |
|---|---|
| AWS EC2 | 实例 → 安全组 → 入站规则 → TCP 80/443（验证期间可先 `0.0.0.0/0`，之后收紧） |
| 阿里云 ECS | 实例 → 安全组 → 入方向 → TCP 80/443 |
| 腾讯云 CVM | 实例 → 安全组 → 入站规则 → TCP 80/443 |

常见坑：

- 只放了 443，但用的是 `http-01`（需要 80）；
- 只放了 80，但用的是 `tls-alpn-01`（需要 443）；
- 云账号默认封禁 80（部分厂商/账号），需工单解封；
- 有公网 IP 但实例在 NAT/负载均衡后面，80/443 没转发到本机；
- IPv6 AAAA 指向了不可达地址，ACME 优先走 IPv6 时验证失败；
- 主机名解析到旧 IP 或 CDN，ACME 校验的是 DNS 当前指向的入口。

```bash
# 从公网另一台机器验证（不要只在 hub 本机 curl）
curl -v http://board.example.com/.well-known/acme-challenge/test
curl -vk --resolve board.example.com:443:<公网IP> https://board.example.com/
```

## 5. DNS、CAA 与 ACME 速率限制

### 5.1 DNS

```bash
dig +short board.example.com A
dig +short board.example.com AAAA
dig +short CAA board.example.com
```

- 每个域名都必须解析到本机公网入口；多域名证书的**每个** SAN 都要可验证；
- TTL 很长的记录提前降低，签发期间不要改 DNS；
- CAA 记录若限制签发者，Let's Encrypt 会被拒绝；需要允许
  `letsencrypt.org`（或你的私有 ACME CA）；
- `acme-ip` 使用固定/弹性公网 IP，签发期间不能变。

### 5.2 速率限制

以 Let's Encrypt 官方文档为准（数值会调整）：

- 每注册域名 7 天 50 张证书；
- 相同 SAN 集合 7 天 5 张；
- 每账户 3 小时 300 个新订单；
- 每账户/主机名每小时 5 次验证失败。

处理：

- 调试先用 staging：
  `--acme-directory https://acme-staging-v02.api.letsencrypt.org/directory`；
- 不要反复 `--force` 生产重装；先修端口/DNS/安全组；
- 多域名合并到一张证书；
- 自动续期有退避（1m/5m/15m/1h/6h），不要手工高频重试；
- staging 证书不被信任，验证链路后去掉 staging 重新签发（`--force`）。

## 6. SNI、SAN 与主机名

TLS 校验同时看**证书链**和**主机名**。浏览器、agent 的 `system-roots`/
`custom-ca`、面板到 hub 的 HTTPS 都会校验。

```bash
# 按 SNI 看服务端实际下发的证书
openssl s_client -connect board.example.com:8443 \
  -servername board.example.com -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# 看证书链（leaf → 中间）
openssl s_client -connect board.example.com:8443 \
  -servername board.example.com -showcerts </dev/null 2>/dev/null \
  | grep -E '^ [0-9]+ s:|^ [0-9]+ i:'
```

常见原因：

- 证书 SAN 没有包含实际访问名（例如只签了 `board.example.com`，agent 用 IP 连）；
- 用 IP 访问 ACME 域名证书（ACME 域名证书通常没有 IP SAN；IP 场景用 `acme-ip`）；
- 管理口/面板用了 `127.0.0.1`，但证书没有回环 SAN（ACME 域名证书不会包含，
  见 §10.1）；
- `server_names` 改了但没重签：self-signed 先 `rotate-cert --force`，ACME 先
  `tls issue`；
- 中间链缺失：`server.crt` 必须 leaf 第一、后面跟中间 CA；
- 客户端/系统时间错误，证书“尚未生效”或“已过期”。

## 7. 证书链、配套与备份

| 错误 | 含义 | 处理 |
|---|---|---|
| `tls_cert 与 tls_key 不匹配` | 证书公钥与私钥不是一对 | 换回配套的 cert/key；不要手工拼接 |
| `证书链...` / rustls 拒绝 | 缺中间 CA / 顺序错 / 证书损坏 | 用完整 fullchain，leaf 第一；重新签发 |
| `tls_cert 已过期` / `尚未生效` | 时间或证书过期 | 续期/校时；ACME 用 `tls renew` |
| `tls_cert 的 SAN 未覆盖...` | SAN 与访问名/监听 IP 不一致 | 补 SAN 后重签，或改用匹配的访问名 |
| `tls_key 权限必须是 0600` | 私钥 group/other 可读 | `chmod 600`；不要放宽 |
| `tls_cert ... 权限过宽` | 证书允许 group/other 写 | `chmod 644` |
| `... 是符号链接，拒绝使用` | cert/key/CA/hub_ca 是链接 | 改用真实文件路径 |

证书目录里 `server.crt.bak-*` / `server.key.bak-*` 是成对备份（每类保留最近 5
份）。不要只恢复其中一个；不要把运维 CLI 的两段式 `bak-<秒>` 备份手工混用。
ACME 的账户/状态在 `certs/acme/`，恢复时与 `server.crt/key` 一起备份。

## 8. 权限与路径

- hub 数据/证书目录 `0700`；`hub.toml`、`panel.toml`、私钥、ACME 账户 `0600`；
  证书 `0644`。启动会收紧过宽权限，但共享目录/符号链接会直接拒绝。
- **L-01 ACME 私有文件**：`certs/acme/account.json`（含账户私钥）与
  `certs/acme/state.toml` 必须是 `0600`。`hub run` 启动时会在数据目录 `0700`
  收紧之后、任何 TLS/ACME 读取之前，把已存在的这两个文件**只收紧**到 `0600`
  （已是 0600 或更严格时不 chmod，绝不放宽）。若其中任一是符号链接、不是普通
  文件，或 chmod 失败（只读文件系统、EACCES、属主不对），hub **拒绝启动**，
  不会静默带着过宽权限继续。`tls status` 只读：发现 group/other 位或符号链接
  只打印 `WARN` 和修复建议，绝不调用 chmod、不修改链接目标。
- 安装器 root prefix 只允许 `/etc/rustboard`、`/var/lib/rustboard` 与
  `/usr/local/bin/rustboard-*`；测试 prefix 必须是 root 拥有、非 sticky、group/
  other 不可写（不要用 `/tmp`）。
- `--acme-ca`/`--hub-ca`/`--tls-cert` 等路径必须是普通文件；容器挂载的
  ConfigMap 常是符号链接，必要时复制成真实文件。
- Docker 证书持久化在 `hub_data` / `panel_data`；`docker compose down -v` 会删除
  volume 与证书/账户，**不要**用它做“重置证书”的常规手段。

```bash
# 查看 ACME 私有文件权限（应是 600）
sudo stat -c '%a %U:%G %n' /var/lib/rustboard/hub/certs/acme/account.json \
  /var/lib/rustboard/hub/certs/acme/state.toml 2>/dev/null

# 手工收紧；也可以重启 hub，由启动期自检自动收紧普通文件
sudo chmod 600 /var/lib/rustboard/hub/certs/acme/account.json \
  /var/lib/rustboard/hub/certs/acme/state.toml
sudo systemctl restart rustboard-hub

# 如果是符号链接：先确认指向，再删除链接并恢复真实文件；不要用 chmod -L
ls -l /var/lib/rustboard/hub/certs/acme/
```

`tls status` 的告警形如（路径与 mode 按实际显示）：

```text
WARN: ACME 账户文件（含私钥） 权限为 0644（含 group/other 位）：...；修复：`chmod 600 ...`，或重启 hub（启动期会只收紧到 0600）。tls status 只读，不会自动修改文件。
WARN: ACME 账户文件（含私钥） 是符号链接（...）；tls status 不会跟随或修改链接目标，hub 启动会直接拒绝。
```

```bash
sudo stat -c '%a %U:%G %n' /var/lib/rustboard/hub/certs/* \
  /var/lib/rustboard/hub/certs/acme/* 2>/dev/null
```

## 9. Docker 特有

| 现象 | 原因 / 处理 |
|---|---|
| `RUSTBOARD_TLS_MODE` 非法 | 只接受 `self-signed` / `acme-domain` / `acme-ip`；环境变量拼写检查 |
| ACME 模式仍报 `--offline 与 ACME 互斥` | 用了旧镜像或旧 entrypoint；ACME 模式绝不能加 `--offline`，升级镜像 |
| entrypoint 跳过 install，改了环境变量不生效 | 已有 `/data/etc/rustboard/hub.toml`；TLS 模式只在首次初始化生效。用 `rustboard-hub install --force ...` 或删除 volume（会丢数据） |
| 80/443 在容器内可 bind，公网仍不通 | 默认 compose **不发布** 80/443；用 `docker/compose.acme.example.yml` 叠加或手工 `-p 80:80 -p 443:443`；再查安全组 |
| 证书重启后丢失/重新申请 | `hub_data` 没挂载或被 `down -v` 删除；证书在 `/data/var/lib/rustboard/hub/certs` |
| `admin_tls=required` 后 hub unhealthy | 镜像 healthcheck 固定 HTTP 回环；按 §10 覆盖成 HTTPS + CA/SNI |
| `--user 10001` 启动 ACME 续期失败 | 非 root 没有 `NET_BIND_SERVICE`；用默认 root entrypoint（降权时保留该能力），不要用 `--user` 跑 ACME |
| 只读根启动失败 | 需要可写 `/data` 与 `/run`（首启安装锁/共享 token）；见 [docker.md](docker.md) |

## 10. 管理端 TLS 与面板

- `admin_tls = "required"` 时管理口只接受 HTTPS。hub 内置 Docker healthcheck
  仍是 `http://127.0.0.1:8444/healthz`，会一直 unhealthy；必须覆盖为：

  ```yaml
  healthcheck:
    test: ["CMD", "curl", "-fsS", "--cacert", "/data/var/lib/rustboard/hub/certs/ca.crt",
           "--resolve", "hub.example.com:8444:127.0.0.1",
           "https://hub.example.com:8444/healthz"]
  ```

  `--resolve` 的 host 必须是证书 SAN 覆盖的名字；公共 ACME 用系统根，去掉
  `--cacert` 即可。不要用 `-k`/跳过校验。
- 面板 `hub_ca` 只与 `https://` hub 一起用；自签/私有 ACME 用 hub 的 `ca.crt`
  或私有 ACME 根，公共 ACME 用系统根（不要传 `hub_ca`）。
- 面板直连 TLS 的 `public_origin` 必须是 `https://`，且证书 SAN 覆盖它；
  续期后重启面板（无热加载）。见 [panel-tls.md](panel-tls.md)。
- 远程面板不要靠“把 8444 改成 0.0.0.0 + admin_tls=off”绕过；默认仍应
  VPN/SSH/反代，非回环必须 HTTPS。

### 10.1 ACME 域名证书 + 回环管理口启动失败

现象：`admin_tls = "required"` 且 `admin_listen` 绑定回环 IP（如
`127.0.0.1:8444`），hub 启动失败，错误以
`admin_tls="required" 且管理 API 只绑定回环地址 ...` 开头。

原因：管理端按 IP 直连时证书 SAN 必须**精确包含该回环 IP**，而 ACME 域名证书
只有 DNS SAN。这是**刻意的 fail-closed**，不是证书没装好；不要用 `-k`、跳过
校验或改写二进制来绕过。任选一种部署方式：

1. 管理口绑定对外地址，用防火墙 / 云安全组限制来源：

   ```toml
   # /etc/rustboard/hub.toml（根表键）
   admin_tls = "required"
   admin_listen = "0.0.0.0:8444"
   ```

   ```bash
   # tls.domains 需覆盖管理端实际访问的 DNS 名
   sudo rustboard-hub tls issue --config /etc/rustboard/hub.toml
   # 占位网段，替换为受信管理来源
   sudo ufw allow from 203.0.113.0/24 to any port 8444 proto tcp
   ```

   云安全组同样只放行管理来源，不要对公网开放 8444。

2. 同机 panel 走回环明文 HTTP，TLS 交给反向代理：

   ```toml
   # /etc/rustboard/hub.toml（根表键）
   admin_tls = "off"
   admin_listen = "127.0.0.1:8444"
   ```

   ```bash
   curl -fsS http://127.0.0.1:8444/healthz
   ```

   面板连 `http://127.0.0.1:8444`，由 nginx / Caddy 等反代对外提供 HTTPS 并
   终止 TLS；Bearer token 仍然必需，不要把 8444 直接暴露到公网。

3. 改用包含回环 IP SAN 的 self-signed 证书（仅 self-signed）：

   ```toml
   # /etc/rustboard/hub.toml
   # server_names 是根表键，必须写在 [tls] 段之前
   server_names = ["127.0.0.1", "::1", "hub.example.com"]

   [tls]
   mode = "self-signed"
   ```

   ```bash
   sudo rustboard-hub rotate-cert --force --config /etc/rustboard/hub.toml
   ```

> **不要**把 `127.0.0.1` / `::1` 加进公共 ACME 域名证书的 `tls.domains`：
> Let's Encrypt 等公共 CA 不会为回环 IP 签发 SAN；`acme-ip` 也只接受公网 IPv4，
> 不能用来签回环地址。ACME 模式请用方式 1 或 2。

## 11. 常见错误信息对照

| 信息（摘要） | 位置 | 处理 |
|---|---|---|
| `--offline 与 ACME 互斥` | hub install / 离线 install.sh | 去掉 `--offline` 或改 self-signed；见 [offline.md](offline.md) |
| `--tls ... 需要 --acme-email` | hub install | 补邮箱，或改 self-signed |
| `--tls ... 需要至少一个 --domain` | hub install | 补 `--domain`（DNS 或 IPv4） |
| `--tls acme-ip 需要恰好一个 --domain` | hub install | 只给一个 IPv4 |
| `--acme-ca 必须是绝对路径` | hub install | 用容器/主机绝对路径 |
| `unrecognized subcommand 'tls'` | 旧二进制 | 升级到包含 C4 的构建；旧版本不支持 ACME 客户端 |
| `RUSTBOARD_TLS_MODE 只接受...` | Docker entrypoint | 合法值只有三种 |
| `RUSTBOARD_ACME_EMAIL 格式非法` | Docker entrypoint | 非空、单个 `@`、无空白 |
| `RUSTBOARD_ACME_CA_FILE 不是普通文件` | Docker entrypoint | 只读挂载 PEM，路径为绝对路径 |
| `本地 bind: 80 端口占用...` | 安装诊断 | §2 |
| `rate limited` / `too many failed authorizations` | ACME | §5，换 staging |
| `tls_cert 与 tls_key 不匹配` | panel install/run | 换配套文件 |
| `... 是符号链接，拒绝使用` | panel/hub | 改用真实文件 |
| `admin_tls=required 需要...` | hub 启动/安装 | SAN 覆盖管理端访问名；见 §10 |
| `... 只绑定回环地址 ... 没有该回环 IP 的 SAN` | hub 启动 | 按 §10.1 三选一；不要给公共 ACME 证书加回环 IP |

## 12. 收集证据（脱敏）

```bash
# 公开信息，可提供
rustboard-hub tls status --config /etc/rustboard/hub.toml
rustboard-hub ports --config /etc/rustboard/hub.toml
ss -ltnp 'sport = :80 or sport = :443'
openssl x509 -in /var/lib/rustboard/hub/certs/server.crt -noout \
  -subject -issuer -dates -ext subjectAltName

# 不要提供
# - hub.toml / panel.toml 原文（含 admin_token / token / 密码哈希）
# - certs/*.key、certs/acme/account.json
# - ACME key authorization、enrollment token、完整环境变量
```

日志里如果出现 `key`/`token`/`authorization` 字样，先确认是否只是路径或
“不打印”的提示；真实 secret 不应出现在日志中。发现泄露时按事故处理：吊销
agent、轮换 token、重新签发证书，并保留审计记录。

## 13. 相关文档

- [服务端 TLS](tls.md) / [ACME 安装](acme.md) / [面板 TLS](panel-tls.md)
- [Docker](docker.md) / [离线](offline.md) / [发布](release.md)
- [Phase C 计划](../plans/2026-10-25-m5-phase-c-tls-release-gates.md)
