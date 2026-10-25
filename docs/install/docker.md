# Docker 部署（M5 Phase B/C/D）

Phase B 提供 hub / panel / agent 三个运行时镜像，基础镜像固定为 Debian bookworm
slim，镜像内只复制静态 musl 二进制和前端资源，不在镜像里编译 Rust。Phase C 在
同一镜像上增加 ACME 端口元数据、`RUSTBOARD_TLS_MODE`/`RUSTBOARD_ACME_*` 环境变量
与降权后的 `NET_BIND_SERVICE` 保留；Phase D 增加 PostgreSQL 显式 opt-in
（`RUSTBOARD_DATABASE*` 与 `docker/compose.postgres.example.yml`），默认 compose
仍使用 SQLite。

> 完整构建/运行说明、故障排查与安全边界见
> [docker/README.md](../../docker/README.md)。本文只给最短路径与关键限制。
>
> 当前 `Cargo.toml`/本地验证版本为 `1.0.0-rc.2`；Phase C 已以 `v1.0.0-rc.2`
> 发布，Phase D 已实现 PostgreSQL 显式 opt-in 与迁移/备份/恢复 CLI。正式镜像
> `v1.0.0` 在 Phase E 版本归档后由 release workflow 推送。

## 1. 构建前提

```bash
# 1) 前端
(cd web && pnpm install --frozen-lockfile && pnpm build)

# 2) 两架构静态二进制与离线包
packaging/build-release.sh

# 3) 单架构本地镜像（多架构由 release workflow 构建）
docker buildx build --load --platform linux/amd64 \
  -f docker/Dockerfile --target hub \
  --build-arg VERSION=1.0.0-rc.2 --build-arg REVISION="$(git rev-parse HEAD)" \
  -t ghcr.io/pazzifirst/rustboard-hub:dev .
```

`panel`、`agent` 同理，改 `--target` 与镜像名。`TARGETARCH` 由 buildx 自动注入，
对应 `dist/amd64` / `dist/arm64`。

## 2. 最短 Compose 启动

```bash
# 先按 docker/compose.example.yml 修改占位符：
#   RUSTBOARD_HUB_ADVERTISE   agent 实际连接的域名/IP（写入证书 SAN）
#   RUSTBOARD_HUB_URL         wss://<hub>:8443/agent/ws
#   RUSTBOARD_HUB_FINGERPRINT hub 证书 SHA-256 指纹
#   RUSTBOARD_ENROLL_TOKEN_FILE 0600 enrollment token 文件
RUSTBOARD_VERSION=dev \
RUSTBOARD_HUB_ADVERTISE=hub.example.com \
docker compose -f docker/compose.example.yml up -d

docker compose -f docker/compose.example.yml ps
docker compose -f docker/compose.example.yml logs -f hub
```

默认只启动 hub + panel，agent 在 `profiles: ["agent"]` 中，需要显式
`--profile agent`。panel 通过 `network_mode: "service:hub"` 共享 hub 的 loopback，
默认管理 API 仍只允许 `127.0.0.1:8444`。

需要 ACME 时叠加专用文件（会给 hub 发布 80/443）：

```bash
RUSTBOARD_VERSION=dev \
RUSTBOARD_ACME_EMAIL=admin@example.com \
RUSTBOARD_ACME_DOMAIN=board.example.com \
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml up -d
```

完整变量、证书持久化与端口说明见 §6。

## 3. 不能做的事

- **不要把 8444 发布到宿主**。管理口默认没有 TLS；Phase C 支持
  `RUSTBOARD_ADMIN_TLS=required` 的 HTTPS，但默认示例仍只绑回环。非回环管理口
  必须启用 `required`，并覆盖 healthcheck。
- 不要给 panel 加 `ports`；panel 的 8080 由 hub 服务发布（示例绑宿主回环）。
- 默认 compose **不发布 80/443**；只有 ACME 模式才需要，用 §6 的叠加文件。
- 不要把 panel 放到独立 network namespace；否则它访问不到 `127.0.0.1:8444`。
- 不要默认给 agent `--privileged`、`/proc` 宿主挂载或 `docker.sock`；控制面默认关闭，
  需要时单独评估宿主权限风险。
- 不要把 token 放进环境变量、Compose 文件或镜像；只挂载 0600 文件，或在 hub 与
  panel 之间使用专用 `hub_run` 敏感 volume。

## 4. 运行身份与数据

- 镜像 `Config.User` 为 root，仅用于首启安装/chown；entrypoint 在安装成功后用
  `setpriv` 降权，**主进程 UID/GID 为 10001**。降权时只保留 `NET_BIND_SERVICE`
  （inheritable + ambient），供 ACME 自动续期绑定 80/443；其余能力清空，
  `--no-new-privs` 保持。
- `/data` 是唯一运行期数据 volume；首启前必须是 root:root 0750，安装完成后 entrypoint
  统一 chown 到 10001。
- 已初始化的 volume 可以用 `--user 10001:10001` 启动；空 volume 直接 `--user` 必须
  失败，entrypoint 不会假装初始化成功。
- hub 的 `/run/rustboard` 是共享 admin token 的敏感 volume：hub 写、panel 只读挂载。
  不需要同机 panel 时不要挂载或不要设置 `RUSTBOARD_ADMIN_TOKEN_SHARE`。
- 健康检查：hub `127.0.0.1:8444/healthz`（HTTP），panel `127.0.0.1:8080/healthz`，
  agent `cert-info`（未 enrollment 前必然 unhealthy）。`admin_tls=required` 时
  必须把 hub healthcheck 覆盖为 HTTPS + CA/SNI，见 §6 与
  [docker/README.md §8](../../docker/README.md)。
- 可选只读根：`--read-only --tmpfs /tmp --tmpfs /run`；`/run` 必须可写，因为
  首启安装锁 `/run/rustboard-install.lock` 需要创建。同时保留 `/data` 与
  `/run/rustboard` 可写 volume。

## 5. 验证命令

```bash
# 镜像标签/版本/修订
docker image inspect ghcr.io/pazzifirst/rustboard-hub:dev \
  --format '{{json .Config.Labels}}'

# 主进程 UID（tini 为 root，rustboard-* 必须是 10001）
docker top <hub-container> -o pid,uid,gid,cmd

# 8444 不应出现在宿主端口；默认 EXPOSE 为 8443 80 443（80/443 仅 ACME 元数据，
# 默认 compose 不发布）
docker port <hub-container>
docker image inspect ghcr.io/pazzifirst/rustboard-hub:dev \
  --format '{{json .Config.ExposedPorts}}'

# 隔离：镜像内无生产配置
docker run --rm --entrypoint /bin/sh \
  ghcr.io/pazzifirst/rustboard-hub:dev -c 'test ! -e /etc/rustboard/hub.toml'

# 健康
docker exec <hub-container> curl -fsS http://127.0.0.1:8444/healthz
docker exec <panel-container> curl -fsS http://127.0.0.1:8080/healthz
```

完整的本地 e2e：`bash tests/e2e/v100-docker.sh`。它会构建三镜像、检查隔离/端口/
非 root/健康检查/重启幂等/`--user`/panel 共享 netns/agent 空环境 fail-fast，并在
arm64 产物存在时用 QEMU 构建运行 arm64 hub；多架构 manifest 与 GHCR 推送由 release
workflow 验证。

C8 文档变更后的本地复跑：`DOCKER_ARCH=amd64 SKIP_ARM64=1 bash
tests/e2e/v100-docker.sh` → **123 PASS / 0 FAIL / 1 SKIP**（SKIP 为可选 arm64/QEMU
检查，由 `delivery-arm64` 原生覆盖）。O.hub/O.union 断言默认 `EXPOSE 8443 80 443`；
C.3 仍断言默认 compose 只发布 8443/8080，H.14 仍断言 8444 不发布。

## 6. ACME 与证书持久化

默认 compose 是 **self-signed + install 阶段 `--offline`**，不发布 80/443。
ACME 用叠加文件：

```bash
RUSTBOARD_VERSION=dev \
RUSTBOARD_ACME_EMAIL=admin@example.com \
RUSTBOARD_ACME_DOMAIN=board.example.com \
RUSTBOARD_ACME_CHALLENGE=http-01 \
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml up -d
```

叠加后 hub 的端口为 8443（agent）、80（HTTP-01）、443（TLS-ALPN）与
`127.0.0.1:8080`（panel）；**8444 仍不 EXPOSE、不发布**。panel 继续与 hub
共享 network namespace，通过 `127.0.0.1:8444` 访问管理 API。

### 6.1 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `RUSTBOARD_TLS_MODE` | `self-signed` | `self-signed` / `acme-domain` / `acme-ip`；只允许这三种 |
| `RUSTBOARD_ACME_EMAIL` | 无（ACME 必填） | ACME 账户邮箱；不打印 |
| `RUSTBOARD_ACME_DOMAIN` | 无（ACME 必填） | 逗号分隔；`acme-domain` 1–20 个 DNS，`acme-ip` 恰好一个 IPv4 |
| `RUSTBOARD_ACME_CHALLENGE` | `http-01` | `http-01` 或 `tls-alpn-01` |
| `RUSTBOARD_ACME_PROFILE` | 空 | 例如 `shortlived`；`acme-ip` 留空运行时默认 `shortlived` |
| `RUSTBOARD_ACME_CA_FILE` | 空 | 容器内绝对路径；仅私有/Pebble ACME，需只读挂载 PEM |
| `RUSTBOARD_ACME_DIRECTORY` | LE production | 自定义 ACME directory；调试用 staging |
| `RUSTBOARD_ADMIN_TLS` | 空（off） | `off` / `required`；required 时必须覆盖 healthcheck |
| `RUSTBOARD_ADVERTISE` | compose 的 `hub.example.com` | agent 安装 URL 主机名；ACME 下必须是 ACME 标识之一，否则 entrypoint 忽略并使用第一个域名 |
| `RUSTBOARD_SAN` | 空 | 额外 SAN；仅 self-signed 证书/ACME 回退证书覆盖，ACME 证书 SAN 由域名决定 |

ACME 模式 entrypoint **不会追加 `--offline`**；self-signed 保持 `--offline`。
缺失/非法的 ACME 变量在 install 之前退出，不写配置。`--offline` + ACME 的
命令行负例见 [offline.md](offline.md)。

### 6.2 证书卷与权限

- 证书、ACME 账户与状态都在 `hub_data`：
  `/data/var/lib/rustboard/hub/certs/{server.crt,server.key,ca.crt,ca.key,acme/}`。
  重建容器不会重新申请；`docker compose down -v` 会删除它们。
- `server.key`/`ca.key`/`acme/account.json` 0600，证书 0644，目录 0700；备份
  `hub_data` 等同于备份私钥与账户，按 secret 管理。
- 首次安装成功后 entrypoint 统一 chown 到 10001；后续 root 启动会修复属主。
- 非 root `--user 10001` 启动不会保留 `NET_BIND_SERVICE`，ACME 自动续期可能
  无法绑定 80/443；ACME volume 请用默认 root entrypoint 启动。

### 6.3 端口、只读根与 healthcheck

- 80/443 只在签发/续期挑战期间被绑定，但 compose 的发布是常驻的；不需要时
  从叠加文件删掉对应 `ports`。
- 只读根（`read_only: true` + `/tmp`、`/run` tmpfs）仍可用：证书/ACME 状态在
  `/data`，首启安装锁与共享 token 在 `/run`。
- `admin_tls=required` 时镜像内置 HTTP healthcheck 会失败。覆盖示例：

  ```yaml
  healthcheck:
    test: ["CMD", "curl", "-fsS",
           "--cacert", "/data/var/lib/rustboard/hub/certs/ca.crt",
           "--resolve", "board.example.com:8444:127.0.0.1",
           "https://board.example.com:8444/healthz"]
  ```

  公共 ACME 用系统根，去掉 `--cacert`；不要用 `-k` 跳过校验。

### 6.4 模式切换

已有 `hub.toml` 时 entrypoint 跳过 install，改 `RUSTBOARD_TLS_MODE` 不会改变
已有配置。切换 self-signed ↔ ACME 需要显式安装（会成对备份旧证书）：

```bash
# 1) 停掉旧 hub/panel，释放 80/443/8443/8080（会短暂中断服务）
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml stop panel hub

# 2) 以 root 直接执行安装器；带参数时 entrypoint 不再初始化 volume。
#    --service-ports 必须保留：ACME 挑战要从公网访问 80/443。
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml run --rm --service-ports hub \
  rustboard-hub install --force --no-systemd --prefix /data \
    --listen 0.0.0.0:8443 --admin-listen 127.0.0.1:8444 --panel no \
    --tls acme-domain --acme-email admin@example.com \
    --domain board.example.com --acme-challenge http-01

# 3) 用新配置重建服务
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml up -d
```

或删除 `hub_data` 重新初始化（会丢数据/账户，仅限可重建环境）。切换前备份
`hub_data`，切换后先 `up -d` 再执行
`docker compose exec hub rustboard-hub tls status --config /data/etc/rustboard/hub.toml`
确认来源。

> 本地/Docker 的 ACME 端到端验证依赖真实公网入口或 Pebble 端口映射；C8 只做
> compose/脚本静态检查，**不伪造** ACME 成功。真实 LE staging 留 C9 手工门禁。

## 7. 升级、回滚与限制

- 升级镜像前备份 `hub_data` / `panel_data`；备份含私钥/token，必须按 secret 管理。
- entrypoint 检测到已有配置会跳过 install；新版本运行期可能执行 SQLite schema
  迁移。回滚镜像前先确认数据库兼容性，必要时恢复 volume 快照。
- ACME 证书在 `hub_data` 中持久化；升级不会重写证书/账户。切换 ACME
  directory/profile 需要 `install --force` + `tls issue`。
- 已发布 tag 不移动；镜像 digest 与 `REVISION` label 一起记录。
- 从 systemd 安装迁移到 Docker 不复用 `/etc/rustboard`、`/var/lib/rustboard`；需要
  重新初始化，agent 需重新 enrollment。
- Phase C 支持 ACME、面板直连 HTTPS 与管理端 TLS；不提供 Kubernetes Operator、
  HA 或内置 DNS-01。远程 panel 的直连 TLS 仍建议认证/审计后按
  [panel-tls.md](panel-tls.md) 配置，默认示例不发布面板端口。
- 默认 compose 仍 SQLite。PostgreSQL 通过
  `docker/compose.postgres.example.yml` 显式叠加，使用 `RUSTBOARD_DATABASE`、
  `RUSTBOARD_DATABASE_SSLROOTCERT`、`RUSTBOARD_DATABASE_PASSWORD(_FILE)`；
  5432 不发布，默认不包含 PG。PG 备份/恢复需要宿主 `pg_dump`/`pg_restore`，
  且当前为单 hub 语义。详见 [postgres.md](postgres.md) §7 与
  [docker/README.md](../../docker/README.md) §14。
