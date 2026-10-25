# 面板直连 HTTPS（M5 Phase C）

面板有两种对外提供 TLS 的方式：

1. **直连 HTTPS**：`rustboard-panel` 自己加载证书，监听 HTTPS（本文重点）；
2. **反向代理终止 TLS**：面板仍监听回环 HTTP，由 nginx/Caddy 等代理 HTTPS
   并转发到面板（见 §7）。

> **实现状态**：Phase C C7 已实现面板直连 HTTPS、`hub_ca` 与管理端 HTTPS 对接；
> 但尚未完成 C9 的面板 HTTPS e2e、独立评审/渗透与 RC。本文不声称已经过
> `v1.0.0-rc.1` 发布验证。
>
> 面板证书**不做热加载**：续期或替换证书后需要重启 `rustboard-panel`。

## 1. 直连 HTTPS 的最小安装

```bash
sudo rustboard-panel install --yes \
  --tls-cert /etc/ssl/panel.crt \
  --tls-key  /etc/ssl/panel.key \
  --public-origin https://panel.example.com \
  --listen 0.0.0.0:8443 \
  --hub-url http://127.0.0.1:8444 \
  --hub-token-file /root/rustboard-hub-admin.token
```

同机 hub 管理口默认是回环 HTTP，`--hub-url http://127.0.0.1:8444` 仍然可用；
面板自身对浏览器提供 HTTPS。若 hub 已启用 `admin_tls = "required"`，见 §6。

安装器会：

- 校验源证书/私钥、配套关系、有效期、SAN、权限与符号链接；
- 把证书复制到 `<prefix>/etc/rustboard/panel-tls/cert.pem`（0644）与
  `key.pem`（0600），目录 0700；配置写**复制后**的绝对路径；
- 直连 TLS 时强制 `cookie_secure = "always"`，并把 `public_origin` 写成
  `https://...`（未显式给定时按证书第一个非通配 SAN 推导）；
- 启动后用 HTTPS + 正确 SNI + 证书链做 `/healthz` 健康检查；失败则事务回滚，
  不会留下“配置是 HTTPS、服务仍是 HTTP”的半完成状态。

## 2. 参数

| 参数 | 说明 |
|---|---|
| `--tls-cert PATH` | 面板 HTTPS 证书 PEM；可含 leaf + 中间链，leaf 第一张 |
| `--tls-key PATH` | 与证书配套的私钥 PEM，必须是普通文件、非符号链接、仅属主可读 |
| `--public-origin URL` | 浏览器访问面板的源，例如 `https://panel.example.com`；直连 TLS 时必须是 `https://` |
| `--listen HOST:PORT` | 面板监听地址；具体 IP 会被写入 SAN 校验（`0.0.0.0`/`::` 通配绑定除外） |
| `--hub-url URL` | hub 管理 API；`https://` 时必须配合 `--hub-ca`（私有 CA）或系统根（公共 ACME） |
| `--hub-ca PATH` | hub 管理 API 的私有 CA（PEM，可多张）；只能与 `https://` hub 一起使用 |
| `--cookie-secure auto\|always\|never` | 直连 TLS 下强制 `always`；`auto` 仅用于可信反代 |

只给 `--tls-cert` 或只给 `--tls-key` 会在写盘前失败。要回到 HTTP，需显式
`--force` 并同时不提供两者（或使用 `panel.toml` 手工清空后重启；推荐安装器）。

## 3. 证书与私钥的权限/格式

| 文件 | 要求 |
|---|---|
| `tls_cert` | 普通文件、非符号链接、≤1 MiB、UTF-8 PEM；不能允许 group/other 写（推荐 0644；0444/0600 也可）；属主可读 |
| `tls_key` | 普通文件、非符号链接、≤1 MiB、UTF-8 PEM；必须 0600（或 0400 这类更严格的仅属主可读）；group/other 任何权限都拒绝 |
| 证书链 | leaf 第一张，后面可跟中间 CA；不需要把根证书塞进 `tls_cert` |
| 配套关系 | 证书公钥必须与私钥一致，否则安装失败 |
| 有效期 | 已过期或尚未生效（允许 60 秒时钟偏差）会失败 |
| SAN | 至少一个 DNS/IP SAN；必须覆盖监听的具体 IP（非通配绑定）与 `public_origin` 主机名 |

常见修复：

```bash
sudo chmod 600 /etc/ssl/panel.key
sudo chmod 644 /etc/ssl/panel.crt
# 符号链接会被拒绝：改用真实文件路径
sudo readlink -f /etc/ssl/panel.crt /etc/ssl/panel.key
# 查看 SAN / 到期
openssl x509 -in /etc/ssl/panel.crt -noout -subject -issuer -dates -ext subjectAltName
```

安装器复制后的文件权限固定为 `cert.pem 0644` / `key.pem 0600`。不要直接改
`panel.toml` 指回可被普通用户替换的源路径。

## 4. Cookie、CSP 与 Origin

- 直连 HTTPS 会强制会话 Cookie 带 `Secure`；`HttpOnly`、`SameSite=Lax`、
  会话 TTL 与登录失败限速不变。
- CSP 仍由面板统一设置；直连 TLS 不改变脚本/样式/连接源策略。
- `public_origin` 参与 Origin 校验：浏览器的 `Origin` 必须与 `Host` 同源，或与
  `public_origin` 完全一致；不一致的变更请求会被拒绝。
- 直连 TLS 下 `public_origin` 为空或不是 `https://` 会启动失败；不要用
  `http://panel...` 配 HTTPS 监听。
- 反向代理模式才使用 `cookie_secure = "auto"` 和可信 `X-Forwarded-Proto`。

## 5. hub 管理 API 的信任：`hub_ca`

`--hub-ca` 只允许与 `https://` 的 hub 地址一起使用：

```bash
# 自签 hub / 私有 ACME hub：信任 hub 的 ca.crt（或私有 ACME 根）
sudo rustboard-panel install --yes \
  --hub-url https://hub.example.com:8444 \
  --hub-ca /etc/rustboard/hub/certs/ca.crt \
  --tls-cert /etc/ssl/panel.crt --tls-key /etc/ssl/panel.key \
  --public-origin https://panel.example.com

# 公共 ACME hub：使用系统根，不要传 hub_ca
sudo rustboard-panel install --yes \
  --hub-url https://hub.example.com:8444 \
  --tls-cert /etc/ssl/panel.crt --tls-key /etc/ssl/panel.key \
  --public-origin https://panel.example.com
```

- `hub_ca` 是**签发 hub 服务端证书的 CA**，不是 hub 的 leaf 证书；PEM 可以包含
  多张证书（bundle），安装器会复制到 `panel-tls/hub-ca.pem`（0644）。
- 配置了 `hub_ca` 时只信任该 CA，**不再叠加系统根**；公共 ACME 证书不要传
  自签 `ca.crt`，否则校验失败。
- 私有 CA 的 fullchain：把签发 hub 证书的根/中间 CA 放进 `hub_ca`；hub 的
  `server.crt` 通常已带中间链，面板侧只需信任锚。不要只放服务端 leaf。
- 明文 `http://` + `hub_ca` 是矛盾配置，安装器/启动会拒绝；先把 hub 切到
  `admin_tls = "required"` 并确认 SAN 覆盖访问名。

## 6. 管理端 TLS：`admin_tls = "required"` + 面板

hub 的管理口默认回环 HTTP。非回环必须启用 HTTPS：

```toml
# hub.toml
admin_listen = "0.0.0.0:8444"
admin_tls = "required"
server_names = ["hub.example.com", "10.8.0.1"]
```

```bash
# 同机面板：hub_url 用证书 SAN 覆盖的主机名；自签/私有 CA 再给 hub_ca
sudo rustboard-panel install --yes \
  --hub-url https://hub.example.com:8444 \
  --hub-ca /etc/rustboard/hub/certs/ca.crt \
  --tls-cert /etc/ssl/panel.crt --tls-key /etc/ssl/panel.key \
  --public-origin https://panel.example.com
```

注意：

- 面板到 hub 的 HTTPS **会验证证书链和主机名**，不能用“TCP 能连上”代替。
- 用 `https://127.0.0.1:8444` 时，证书 SAN 必须包含 `127.0.0.1`；ACME 域名证书
  通常不包含它。ACME + `admin_tls=required` 时应使用 ACME 域名访问管理口
  （DNS 需能从面板所在主机解析到 hub，或使用 hosts/内部 DNS），并让该域名在
  `tls.domains` 中。
- 修改 `server_names` 后先 `rotate-cert --force`（self-signed）或 `tls issue`
  （ACME），再重启/热加载 hub；否则面板可能报 SAN 不匹配。
- 回环同机面板仍优先用 `http://127.0.0.1:8444`，除非确有必要启用管理端 TLS；
  启用后 hub 的内置 healthcheck 也要改为 HTTPS（见 [docker.md §6.3](docker.md#63-端口只读根与-healthcheck)）。

## 7. 反代 vs 直连

### 7.1 反向代理终止 TLS（推荐给多实例/统一入口）

面板保持回环 HTTP，由 nginx/Caddy 终止 TLS：

```toml
# panel.toml
listen = "127.0.0.1:8080"
trusted_proxies = ["127.0.0.1"]
cookie_secure = "auto"
public_origin = "https://panel.example.com"
```

反代要求：

- 只信任反代直连地址；未配置 `trusted_proxies` 时所有 `X-Forwarded-*` 都被忽略；
- 反代必须**覆盖**客户端传入的 `X-Forwarded-For`，不要透传伪造值；
- 设置 `X-Forwarded-Proto: https`；否则 `cookie_secure=auto` 不会加 `Secure`；
- 不要把面板回环 HTTP 直接暴露到公网；反代到面板的链路应在本机/VPN 内。

### 7.2 直连 HTTPS

适合单机、无统一反代、希望减少一跳的场景。注意：

- 面板自己占 443/8443 等端口，需处理与 hub/nginx 的端口冲突；
- 证书续期后必须重启面板（无热加载）；
- 反向代理和直连 TLS **不要同时启用**：反代到 HTTPS 面板会多一层 TLS，
  且 `X-Forwarded-*` 语义会变得复杂。

## 8. 续期与重启

面板不监听证书文件变化，也没有 ACME 客户端：

1. 用 ACME 工具/Caddy/企业 CA 在**面板之外**续期证书；
2. 将新的 cert/key 放到安装器复制后的路径（或重新执行 `panel install --force`
   带 `--tls-cert/--tls-key`，事务会备份旧文件）；
3. `sudo systemctl restart rustboard-panel`；
4. 确认新证书生效：
   ```bash
   openssl s_client -connect panel.example.com:8443 \
     -servername panel.example.com -showcerts </dev/null 2>/dev/null \
     | openssl x509 -noout -subject -dates -ext subjectAltName
   ```
5. 如果只替换文件，保持 `key.pem 0600`、`cert.pem 0644`；启动时会再次校验
   配套、SAN、有效期与权限。

用安装器更新时，`--force` 会以旧配置为底保留 `trusted_proxies`、token 等字段，
只更新显式给出的 TLS 字段；仍建议先备份 `panel_data`。

## 9. Docker 中的面板 TLS

默认 `docker/entrypoint-panel.sh` 没有面板 TLS 的环境变量，`compose.example.yml`
也不发布面板端口。要在容器里用直连 HTTPS：

1. 把证书/私钥只读挂载到容器（例如 `/run/rustboard/panel-tls/`）；
2. 用容器 root 执行一次安装/更新（entrypoint 有参数时直接 exec，不进入初始化）：
   ```bash
   docker compose -f docker/compose.example.yml run --rm \
     -v /host/panel.crt:/run/rustboard/panel-tls/cert.pem:ro \
     -v /host/panel.key:/run/rustboard/panel-tls/key.pem:ro \
     panel rustboard-panel install --force --no-systemd --prefix /data \
       --hub-url http://127.0.0.1:8444 \
       --hub-token-file /run/rustboard/admin_token \
       --static-dir /usr/share/rustboard/web \
       --tls-cert /run/rustboard/panel-tls/cert.pem \
       --tls-key /run/rustboard/panel-tls/key.pem \
       --public-origin https://panel.example.com \
       --listen 0.0.0.0:8080
   ```
   注意 `docker compose run` 默认不会继承 `depends_on` 的健康等待；hub 需已运行。
3. 重新 `up -d` 让入口以 UID 10001 启动面板。证书已复制进 `panel_data` 的
   `/data/etc/rustboard/panel-tls/`，后续重启不依赖宿主挂载。
4. 面板改为 HTTPS 后，hub 服务发布的 8080 映射仍在，但容器内 8080 已经是
   TLS；浏览器需用 `https://<面板主机>:8080`。若要改成 443/8443 等端口，需要
   在 hub 服务的 `ports` 中调整映射（默认示例只发布 8443 与回环 8080），或继续
   放在反代/VPN 后。

本阶段不把面板 TLS 纳入默认 compose 门禁；Docker 面板 TLS 的端到端验证留 C9。

## 10. 相关文档

- [服务端 TLS 总览](tls.md)
- [ACME 安装](acme.md)
- [Docker 部署](docker.md) / [docker/README.md](../../docker/README.md)
- [故障排查](troubleshooting.md)
- 设计依据：[Phase C 计划 D6](../plans/2026-10-25-m5-phase-c-tls-release-gates.md)
