# ACME 证书安装（M5 Phase C）

本文只讲**安装器**如何为 hub 申请和续期 ACME 证书，以及安装前后需要人工确认的
DNS、端口、防火墙与云安全组。ACME 客户端、挑战服务与续期的内部实现见
[Phase C 计划](../plans/2026-10-25-m5-phase-c-tls-release-gates.md)；证书来源、
目录/权限、agent 三种信任模式与续期机制见 [tls.md](tls.md)；按错误信息排查见
[troubleshooting.md](troubleshooting.md)。

> **实现状态**：Phase C C4（ACME 客户端/挑战）、C5（安装器 80/443 诊断、回退、
> HTTPS 健康检查）与 C6（续期/热加载）已随主线落地；`rustboard-hub tls
> status|issue|renew` 已可用。但尚未完成 C9 全量 e2e、独立评审/渗透与
> `v1.0.0-rc.1` 的真实 Let's Encrypt staging 验证。
> 未包含 C4 的旧二进制会明确提示“当前二进制没有 `tls issue`”，并按
> `tls.fallback_to_self_signed` 回退为自签证书，**不会假装 ACME 成功**。
> 本文不声称已经通过真实 Let's Encrypt 生产环境的 RC 验证。

## 1. 适用范围

| 模式 | 证书标识 | 适用场景 | 默认挑战 |
|---|---|---|---|
| `self-signed`（默认） | `server_names` | 内网 / 不暴露 80/443；agent 用指纹钉扎 | 无 |
| `acme-domain` | 1–20 个 DNS 名 | 有公网域名、能开放 80 或 443 | `http-01` |
| `acme-ip` | 恰好 1 个公网 IPv4 | 没有域名，使用短期 IP 证书 | `http-01` |

ACME 只支持 HTTP-01 与 TLS-ALPN-01；不支持 DNS-01、通配符、HA/负载均衡。
`acme-ip` 通常需要 Let's Encrypt 的 `shortlived` profile（6 天证书），安装时用
`--acme-profile shortlived` 显式指定。

## 2. 安装前：DNS、80/443 与安全组

### 2.1 DNS

`acme-domain` 的每个 `--domain` 必须解析到本机公网地址（A / AAAA），并且从
公网可达：

```bash
dig +short board.example.com A
dig +short board.example.com AAAA
```

- 多域名会全部写入同一张证书的 SAN，每个域名都要解析到本机；
- 证书签发期间不要改 DNS；TTL 很长的记录建议提前降低；
- `acme-ip` 不需要 DNS，但云厂商的公网 IP 必须是**固定/弹性 IP**，不能在签发
  期间变化。

### 2.2 80 / 443 入站

| 挑战 | 必须可用的入站端口 | 说明 |
|---|---|---|
| `http-01` | TCP **80** | ACME 服务端 GET `/.well-known/acme-challenge/<token>` |
| `tls-alpn-01` | TCP **443** | 只接受 ALPN `acme-tls/1`，不提供普通 HTTPS |

签发期间 hub 会临时占用对应端口；本机已有 nginx / apache / Caddy 监听 80/443
时，安装器会在**写任何配置之前**判定端口不可用并回退自签（或中止）。请先停止
占用端口的服务，或改用另一种挑战。

### 2.3 云安全组

安装器只做只读探测，**不会自动修改防火墙或安全组**，`--yes` 也一样。识别到
AWS / 阿里云 / 腾讯云时只打印控制台路径：

- AWS EC2：实例 → 安全组 → 入站规则，放行 TCP 80 / 443（可限制源为
  `0.0.0.0/0`，验证完成后收紧）；
- 阿里云 ECS：实例 → 安全组 → 入方向，放行 TCP 80 / 443；
- 腾讯云 CVM：实例 → 安全组 → 入站规则，放行 TCP 80 / 443。

本机防火墙同理：`ufw` / `firewalld` / `nftables` / `iptables` 只生成精确放行
命令文本，需要人工执行。例如：

```bash
# ufw
ufw allow 80/tcp
ufw allow 443/tcp

# firewalld
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --reload
```

放行后重新执行安装。公网 IP 的 `http-01` 还必须确认云厂商没有做 80 端口封禁
（部分账号默认封禁，需要工单解封）。

## 3. 安装参数

| 参数 | 说明 |
|---|---|
| `--tls self-signed\|acme-domain\|acme-ip` | 证书来源；默认 `self-signed` |
| `--acme-email EMAIL` | ACME 账户联系邮箱，ACME 模式必填 |
| `--acme-directory URL` | ACME directory；默认 Let's Encrypt production |
| `--acme-challenge http-01\|tls-alpn-01` | 挑战类型；默认 `http-01` |
| `--domain DNS\|IPv4` | 证书标识，可重复；`acme-domain` 1–20 个，`acme-ip` 恰好 1 个 |
| `--acme-profile PROFILE` | 例如 `shortlived`；留空按 ACME 客户端默认 |
| `--acme-ca PEM` | 私有 / Pebble ACME 的根 CA 绝对路径；留空用系统根 |
| `--admin-tls off\|required` | 管理 API 明文（仅回环，默认）或 HTTPS |
| `--offline` | 不发起任何外部网络探测；**与 ACME 互斥** |

`--offline` 与任何 ACME 模式或 ACME 参数同时出现时，安装器会在读状态 / 写盘 /
联网之前失败。ACME 证书无法离线签发，这是硬约束，不是警告。

## 4. 安装示例

### 4.1 域名 + HTTP-01（最常见）

```bash
sudo ./install.sh hub --yes \
  --tls acme-domain \
  --acme-email admin@example.com \
  --domain board.example.com \
  --acme-challenge http-01
```

### 4.2 多个域名（同一张证书）

```bash
sudo ./install.sh hub --yes \
  --tls acme-domain \
  --acme-email admin@example.com \
  --domain board.example.com \
  --domain www.board.example.com
```

### 4.3 只开 443：TLS-ALPN-01

```bash
sudo ./install.sh hub --yes \
  --tls acme-domain \
  --acme-email admin@example.com \
  --domain board.example.com \
  --acme-challenge tls-alpn-01
```

### 4.4 公网 IP + shortlived

```bash
sudo ./install.sh hub --yes \
  --tls acme-ip \
  --acme-email admin@example.com \
  --domain 203.0.113.10 \
  --acme-challenge http-01 \
  --acme-profile shortlived
```

### 4.5 管理 API 同时启用 HTTPS

```bash
sudo ./install.sh hub --yes \
  --tls acme-domain \
  --acme-email admin@example.com \
  --domain board.example.com \
  --admin-tls required
```

`--admin-tls required` 不要求管理口绑回环：绑 `0.0.0.0` 时健康检查连回环但用
证书里的域名做 SNI / 主机名校验。若管理口绑定指定 IP，则该 IP 或可访问的 DNS
名必须出现在证书 SAN 中；否则安装器会在写盘前提示先补 `--domain` / `--san`。

### 4.6 私有 / Pebble ACME（测试环境）

```bash
sudo ./install.sh hub --yes \
  --tls acme-domain \
  --acme-email admin@example.com \
  --domain hub.test \
  --acme-directory https://pebble:14000/dir \
  --acme-ca /etc/rustboard/pebble-ca.pem
```

Pebble 的根 CA 只用于测试；生产环境不要使用自建 CA 的 `--acme-ca`，除非你明确
在管理自己的私有 ACME。

## 5. 安装器诊断输出

ACME 安装会在写配置 / unit / 二进制之前执行四层只读诊断，并在失败时打印分层
结论。示例（域名、PID 均为占位）：

```text
ACME 端口 / 防火墙 / 云环境诊断（只读；安装器不会自动修改防火墙或安全组）：
  [失败] 本地 bind: 80 端口占用，ACME http-01 无法完成验证：80: 已被占用（pid=123, 进程=nginx）；443: 可绑定
        建议: ss -ltnp 'sport = :80'
        建议: 停止占用 80 的服务后重试（如 systemctl stop <service>）
        建议: 或改用 --acme-challenge tls-alpn-01
  [警告] 防火墙: 检测到已启用的防火墙：ufw；如未放行 80/443，请手工执行下列命令（安装器不会自动修改）：
        建议: ufw allow 80/tcp
        建议: ufw allow 443/tcp
  [警告] 云安全组: 识别到 AWS；请确认安全组入站已放行 TCP 80 与 443。
        建议: AWS EC2：控制台 → 实例 → 安全组 → 入站规则，放行 TCP 80 与 443（ACME 验证期间）
  [跳过] ACME 尝试: 尚未执行（dry-run 或当前二进制没有 tls issue）
```

四层含义：

1. **本地 bind**：挑战端口（http-01 = 80，tls-alpn-01 = 443）必须能绑定；
   另一个端口只告警。失败时用 `ss -ltnp` 找 PID / 进程名；没有 `ss` 时给通用
   排查命令。这一层失败是硬失败。
2. **防火墙**：只读取 `ufw status`、`firewall-cmd --state`、`nft list ruleset`、
   `iptables -S`，生成放行命令文本；不执行任何修改。
3. **云安全组**：仅非 offline + ACME 时，用 1 秒超时探测云厂商元数据根路径；
   只打印厂商与安全组路径，不读取凭证、不打印响应体。识别不到不会阻止安装，
   但需要你手工确认。
4. **ACME 尝试**：由 C4 的 `tls issue` 执行 staging / production；安装器最多
   重试 3 轮。失败会打印最后一次脱敏输出。

`--dry-run` 不联网、不做诊断，只打印计划。

## 6. Staging 与 production

- `tls.staging_check = true`（默认）且 `--acme-directory` 为 Let's Encrypt
  production 默认值时，安装器会先向 staging 申请一次临时证书，再走 production；
  staging 失败会按回退策略处理，避免直接消耗 production 的失败额度。
- `acme-ip` 默认跳过自动 staging（shortlived profile 在 staging 的支持依
  Let's Encrypt 策略），直接以 production 结果为准；需要手工验证时显式给
  staging directory。
- 自定义 `--acme-directory`（Pebble / 私有 ACME）不会自动套一层 staging：
  你指定的就是实际使用的目录。
- 公共 Let's Encrypt 的 staging 证书**不被客户端信任**，只用于验证域名 / 端口 /
  挑战链路，不能用于生产。
- 手工测试 staging：

```bash
sudo ./install.sh hub --yes \
  --tls acme-domain \
  --acme-email admin@example.com \
  --domain board.example.com \
  --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory
```

  验证通过后，去掉 `--acme-directory`（或改回 production）并加 `--force` 重装，
  以获取受信任证书：

```bash
sudo rustboard-hub install --force --tls acme-domain \
  --acme-email admin@example.com --domain board.example.com
```

- 使用 `--acme-ca` 的私有 ACME 不受公共 staging / production 限制，但仍建议
  先在测试目录验证。

## 7. 失败与回退

安装器最多尝试 3 轮 `tls issue`。失败后：

- `tls.fallback_to_self_signed = true`（默认）：打印分层诊断与重试命令，然后写
  **self-signed** 配置继续完成安装。自签模式沿用 v0.4 的指纹钉扎；已纳管 agent
  不会因为一次 ACME 失败而失联。
- `tls.fallback_to_self_signed = false`：安装中止，配置 / unit / 二进制由安装
  事务回滚；不会留下 ACME 模式的配置。
- 全新安装失败时，数据目录由事务回滚删除；已有安装失败时，安装前的
  `server.crt` / `server.key` 会被恢复。
- ACME 账户 / 订单状态可能保留在数据目录中，便于修复后重试；配置本身一定是
  self-signed 或 ACME 中的一种，不会“半份 ACME 配置”。

回退后打印的重试命令形如：

```bash
rustboard-hub install --force --tls acme-domain \
  --acme-email admin@example.com --domain board.example.com \
  --acme-challenge http-01 [--admin-tls required]
```

常见失败原因按层排查：

| 层 | 现象 | 处理 |
|---|---|---|
| 本地 bind | 80/443 被 nginx/其他 hub 占用 | 停止占用服务；或改用另一挑战 |
| 防火墙 | ufw/firewalld 未放行 | 手工执行安装器打印的放行命令 |
| 云安全组 | 公网访问超时 | 控制台放行 80/443；确认账号未被封禁 80 |
| DNS | `NXDOMAIN` / 解析到旧 IP | 修正 A/AAAA，等 TTL 生效 |
| ACME | `rate limited` / `order failed` | 查看第 11 节；换 staging 验证链路 |
| C4 CLI | `unrecognized subcommand 'tls'` | 当前二进制没有 ACME 客户端；升级后再试 |

ACME 模式下 agent 不能继续用 v0.4 的指纹钉扎。`hub agent add` 会按模式打印
`--tls-mode system-roots`（公共 ACME）或 `--tls-mode custom-ca --server-ca ...`
（私有 ACME）；旧 agent 需要先升级。

## 8. 与离线安装的互斥

- 显式 `--tls acme-domain|acme-ip` 时，`packaging/install.sh` **不会**自动追加
  `--offline`；
- 同时给 `--offline` 与 ACME 模式 / 任何 ACME 参数时，脚本在写 web、解包、
  校验和之前直接失败；
- 默认 self-signed（未显式 `--tls`）仍按 Phase B 行为自动离线安装；
- 离线包内的二进制可以在线使用；离线约束只针对本次安装是否允许联网。

## 9. 续期与状态

- hub 运行期间自动检查证书剩余寿命：普通证书到 1/3 寿命、IP 短寿命证书到
  48 小时阈值时续期；成功原子替换 `server.crt` / `server.key` 并热加载新连接，
  不需要重启。
- 续期失败保留旧证书并告警，不会把运行中的服务停掉。
- 手动查看 / 续期（C4/C6 已实现；旧二进制没有 `tls` 子命令）：

```bash
rustboard-hub tls status --config /etc/rustboard/hub.toml
sudo rustboard-hub tls renew --config /etc/rustboard/hub.toml
sudo rustboard-hub tls issue --config /etc/rustboard/hub.toml
```

  `status` 只读；`issue` 强制重签；`renew` 与自动续期共用锁，输出 SAN / 到期 /
  来源，失败保留旧证书并非零退出。不要并发执行多个 `issue` / `renew`。

- 证书与 ACME 账户材料在 `<data_dir>/certs` 与 ACME 状态目录；私钥必须 0600。
  备份时同时备份二者；恢复后不要手工拼凑 cert/key。

## 10. 防火墙与安全组的最小化

- 仅 ACME 验证期间需要 80（http-01）或 443（tls-alpn-01）对公网开放；
- 验证完成后可以关闭 80，但 HTTP-01 续期需要再次开放；TLS-ALPN-01 续期需要
  443。若不能周期性开放 80，建议使用 443 + TLS-ALPN-01，或保留 80 的 ACME
  路径；
- hub 的 agent 接入端口（默认随机五位数）与管理端口是独立监听，不要为了 ACME
  把它们暴露到公网；管理 API 默认只绑回环；
- `--admin-tls required` 时，同机 panel 使用
  `https://<证书 SAN 覆盖的主机名>:<管理端口>`；自签 / 私有 ACME 会附
  `--hub-ca <hub data_dir>/certs/ca.crt`，公共 ACME 使用系统根。若 panel 版本
  尚不支持 `--hub-ca`，安装会以未知参数失败；用 `--panel no` 跳过同机面板，
  升级 panel 后按 [panel-tls.md](panel-tls.md)
  手工配置，不会静默降级成不校验证书。
- 面板直连 HTTPS（`--tls-cert/--tls-key/--public-origin`）与 ACME 是两件独立
  的事：ACME 签的是 hub 的 `server.crt`，面板仍需自己的证书；详见
  [panel-tls.md](panel-tls.md)。

## 11. Let's Encrypt 速率限制

以 Let's Encrypt 当前文档为准（数值会调整，部署前请核对官方 Rate Limits）：

- 每个注册域名每 7 天 50 张证书；
- 相同证书（同一组 SAN）每 7 天 5 张；
- 每个账户每 3 小时 300 个新订单；
- 每个账户 / 主机名每小时 5 次验证失败；
- staging 限额宽松得多，调试务必先用 staging。

因此：

- 不要反复 `--force` 重装生产证书；先用 staging 验证；
- 失败后先看分层诊断，修好端口 / DNS / 安全组再重试；
- 多域名尽量合并到一张证书，减少重复申请；
- 自动续期本身有退避与阈值，不要在续期失败后手工高频重试。

## 12. 安全注意事项

- ACME 账户 key、证书私钥、key authorization 不会出现在安装器输出中；
  `tls issue` 的输出也会过滤私钥块与 keyAuth 再打印。
- 安装器不会执行任何防火墙 / 安全组修改命令，只打印建议。
- 不要把 `--acme-ca` 指向可被普通用户替换的路径；该文件会被 hub 读取用于校验
  ACME 服务端。
- ACME 域名证书是公开信任的，任何能解析到该域名的人都能看到 hub 的 TLS 身份；
  管理 API 仍需要 Bearer token。
- 生产环境建议保留 `fallback_to_self_signed = true` 作为兜底，但回退后必须用
  `rustboard-hub tls status` 确认实际证书来源，不要把自签安装误当成 ACME。

## 13. Docker、面板与其他交付方式

- **Docker**：默认 `docker/compose.example.yml` 是 self-signed，不发布 80/443，
  安装阶段 `--offline`；ACME 用 `docker/compose.acme.example.yml` 叠加，把
  80/443、`RUSTBOARD_TLS_MODE=acme-domain`、邮箱/域名/挑战传进容器。证书/账户
  持久化在 `hub_data`，entrypoint 降权时保留 `NET_BIND_SERVICE` 供续期绑定
  80/443。变量、端口、只读根、healthcheck 与模式切换见
  [docker.md §6](docker.md#6-acme-与证书持久化) 和
  [docker/README.md](../../docker/README.md)。
- **离线**：`--offline` 与 ACME 互斥；默认 self-signed 仍自动离线。失败示例与
  规则见 [offline.md §4.1](offline.md#41-离线与-acme-互斥)。
- **面板**：面板没有内置 ACME；直连 HTTPS 用 `--tls-cert/--tls-key`，反代终止
  TLS 时保持回环 HTTP。与 hub 的 `admin_tls=required`、`hub_ca`、Cookie/CSP、
  续期重启见 [panel-tls.md](panel-tls.md)。
- **发布**：ACME 不改变 tag/RC 门禁；RC 前需人工跑 LE staging（域名 + 公网 IP），
  见 [release.md §7](release.md#7-acme-与发布门禁)。
- **总览**：证书来源、目录权限、续期/退避/热加载、agent 三模式与回滚见
  [tls.md](tls.md)；80/443、DNS、SNI、权限等排错见
  [troubleshooting.md](troubleshooting.md)。

> **未验证项**：真实 Let's Encrypt staging/production、Docker 内 ACME 端到端
> （需要公网 80/443 或 Pebble 映射）尚未在 C8 执行；本文只描述已实现行为与
> 手工步骤，不把 compose/脚本静态检查当作签发成功。
