# RustBoard Docker 镜像与 Compose

本文覆盖 Phase B/C 的 hub / panel / agent 三个运行时镜像。镜像**不编译 Rust**，只复制
`packaging/build-release.sh` 产出的 musl 静态二进制和 `web/dist` 前端产物；基础镜像、
端口、降权和 healthcheck 都在 `docker/Dockerfile` 中固定。Phase C 增加 ACME
（80/443 元数据、`RUSTBOARD_TLS_MODE`/`RUSTBOARD_ACME_*`）、面板直连 HTTPS
与管理端 TLS 的容器侧说明。

> 安全基线：hub 管理 API **默认**仍只绑 `127.0.0.1:8444`；Phase C 支持
> `RUSTBOARD_ADMIN_TLS=required` 的 HTTPS，但默认示例不启用。panel 默认与 hub
> 共享 network namespace，且**任何情况下都不要把 8444 发布到宿主**。

## 1. 构建前提

### 1.1 准备静态二进制与前端

Dockerfile 只接受发布产物，不接受 `cargo build` 的 glibc 二进制：

```text
dist/amd64/bin/rustboard-hub
dist/amd64/bin/rustboard-panel
dist/amd64/bin/rustboard-agent
dist/arm64/bin/rustboard-hub
dist/arm64/bin/rustboard-panel
dist/arm64/bin/rustboard-agent
web/dist/index.html
web/dist/assets/...
```

`amd64` / `arm64` 是 Docker 的 `TARGETARCH` 名称，不是 Rust target 名称。
先准备前端产物（`build-release.sh` 会校验 `web/dist/index.html`）：

```bash
(cd web && pnpm install --frozen-lockfile && pnpm build)
```

再运行 Phase B 构建入口，生成 `dist/<arch>/bin` 与离线包：

```bash
packaging/build-release.sh
```

要求：

- 二进制必须是 musl 静态构建（`file` 显示 static/static-pie，`ldd` 显示
  `statically linked` 或 `not a dynamic executable`）；
- `dist/<arch>/bin` 与 `web/dist` 必须是真实目录，不是符号链接；
- `.dockerignore` 已保留 `dist/`、`web/dist/`、`docker/`、`packaging/`，不要改成排除它们；
- 镜像内不包含 `/etc/rustboard`、私钥、token 或构建 secret。

### 1.2 基础镜像

`debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8`

只安装 `ca-certificates`、`curl`、`tini`、`util-linux`（含 `setpriv`），不安装编译工具链。
`tini` 路径为 `/usr/bin/tini`，entrypoint 的 `setpriv` 为 `/usr/bin/setpriv`。

## 2. 构建三个镜像

在仓库根目录执行。单架构本地构建示例：

```bash
VERSION=v1.0.0
REVISION=$(git rev-parse --short=12 HEAD)

for role in hub panel agent; do
  docker buildx build \
    --platform linux/amd64 \
    --target "$role" \
    --build-arg VERSION="$VERSION" \
    --build-arg REVISION="$REVISION" \
    -t "ghcr.io/pazzifirst/rustboard-$role:$VERSION" \
    -t "ghcr.io/pazzifirst/rustboard-$role:latest" \
    --load .
done
```

- `TARGETARCH` 由 buildx 根据 `--platform` 自动注入，对应 `dist/amd64` / `dist/arm64`；
  使用旧版 `docker build` 时显式加 `--build-arg TARGETARCH=amd64`。
- 多架构推送：

  ```bash
  docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --target hub \
    --build-arg VERSION="$VERSION" \
    --build-arg REVISION="$REVISION" \
    -t ghcr.io/pazzifirst/rustboard-hub:"$VERSION" \
    -t ghcr.io/pazzifirst/rustboard-hub:latest \
    --push .
  ```

  三个 target 分别构建。镜像构建本身仍要执行 arm64 的 `apt-get`/`useradd` 层，
  因此需要 binfmt/QEMU 或 arm64 builder；Rust 编译不在此 Dockerfile 内发生。
- `latest` 只用于稳定版本；生产建议固定 `vX.Y.Z` 或 digest。
- hub 镜像的默认 `EXPOSE` 为 `8443 80 443`：8443 是 agent 入口；80/443 是
  ACME HTTP-01/TLS-ALPN-01 挑战期间的元数据，默认 compose **不发布**，8444
  永不 EXPOSE。
- 本地调试可以只构造成 `rustboard-hub:dev`，再 `docker tag` 成 Compose 里使用的
  `ghcr.io/pazzifirst/rustboard-hub:dev`，并用 `RUSTBOARD_VERSION=dev` 启动。

镜像默认 target 是文件最后一个 `agent`；**必须显式传 `--target`**。

`ENTRYPOINT` 是 `tini + entrypoint-<role>.sh`。带参数运行（例如 `--version`、
`test ! -e ...`）会跳过首次初始化，直接 exec 指定命令；这只用于版本/隔离验证，
不要用参数启动生产服务。

## 3. 用 Compose 启动

Compose 示例在 `docker/compose.example.yml`，默认启动 hub + panel；agent 放在
`profiles: ["agent"]` 中，默认不启动。

```bash
# 先把 compose 中的占位符换成真实值：
#   RUSTBOARD_HUB_ADVERTISE / RUSTBOARD_HUB_URL / RUSTBOARD_HUB_FINGERPRINT
#   RUSTBOARD_ENROLL_TOKEN_FILE（0600 文件）
RUSTBOARD_VERSION=v1.0.0 \
RUSTBOARD_HUB_ADVERTISE=hub.example.com \
docker compose -f docker/compose.example.yml up -d

docker compose -f docker/compose.example.yml ps
docker compose -f docker/compose.example.yml logs -f hub
```

需要 ACME 时叠加专用文件（ACME 默认不发布 80/443，见 §13）：

```bash
RUSTBOARD_VERSION=v1.0.0 \
RUSTBOARD_ACME_EMAIL=admin@example.com \
RUSTBOARD_ACME_DOMAIN=board.example.com \
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml up -d
```

启动 agent（下面的 fingerprint 从 `rustboard-hub ports` 的“证书指纹”读取）：

```bash
RUSTBOARD_VERSION=v1.0.0 \
RUSTBOARD_HUB_URL=wss://hub.example.com:8443/agent/ws \
RUSTBOARD_HUB_FINGERPRINT=REPLACE_WITH_64_HEX_FINGERPRINT \
RUSTBOARD_ENROLL_TOKEN_FILE=/absolute/path/to/enroll.token \
docker compose -f docker/compose.example.yml --profile agent up -d
```

要点：

- enrollment token 只以 **0600 普通文件**挂载，禁止放进环境变量、Compose 文件或镜像；
  示例路径 `./secrets/enroll.token` 是占位符，建议放到仓库外并用绝对路径覆盖。
- `RUSTBOARD_HUB_ADVERTISE` 只在 hub **首次初始化**时生效，会写进服务端证书 SAN。
  不设置时证书只覆盖容器 hostname、127.0.0.1、localhost；agent 用外部域名/IP 连接时
  会在 enrollment 后的 CA + 主机名校验阶段失败。`RUSTBOARD_SAN` 可追加逗号分隔的 SAN。
  ACME 模式下证书 SAN 由 `RUSTBOARD_ACME_DOMAIN` 决定；`RUSTBOARD_ADVERTISE` 必须
  是其中一个标识，否则 entrypoint 会忽略它并使用第一个域名。
- 配置已存在后，entrypoint 会跳过 install；此时改 SAN 需要修改
  `/data/etc/rustboard/hub.toml` 的 `server_names`，再在容器内执行
  `rustboard-hub rotate-cert --force --config /data/etc/rustboard/hub.toml`。
- panel 首次启动会在日志中打印一次初始管理员密码；这是设计行为，见 §7。

## 4. 为什么 hub / panel 共享 network namespace

hub 管理 API **默认**只绑回环。Phase C 虽支持 `admin_tls = "required"`，默认
compose 仍未启用；panel 要访问 `http://127.0.0.1:8444`，只能和 hub 处于同一
loopback 命名空间：

```yaml
panel:
  network_mode: "service:hub"
```

于是：

- panel 没有自己的 `ports`，8080 由 **hub 服务**统一发布（示例绑到宿主 `127.0.0.1`）；
- 8444 既不 `EXPOSE` 也不发布；不要额外加 `-p 8444:8444`；
- 远程访问 panel 请用 SSH 隧道、VPN、反代或面板直连 HTTPS；直接暴露面板明文
  HTTP 仍不在默认安全范围内；
- 远程 panel（独立主机/容器）需要管理端 HTTPS + 面板 TLS/反代，不能通过把
  `admin_listen` 改成 `0.0.0.0` 且保持 `admin_tls=off` 绕过（hub 会拒绝启动）。

## 5. 首次启动、root 与 UID 10001

镜像的 `Config.User` 是 root（Dockerfile 没有 `USER`），但**主进程不是 root**：

1. 容器以 root 启动 entrypoint；
2. 首启执行 `rustboard-<role> install --prefix /data --no-systemd`；
3. `chown` 到 `10001:10001`，收紧配置/数据目录权限；
4. `exec setpriv --reuid=10001 --regid=10001 --clear-groups --no-new-privs
   --inh-caps=+net_bind_service --ambient-caps=+net_bind_service ... run`。

验证：

```bash
docker compose -f docker/compose.example.yml exec hub id
docker compose -f docker/compose.example.yml exec panel id
docker compose -f docker/compose.example.yml exec agent id
# 或：docker top rustboard-hub-1 -o pid,uid,gid,cmd
```

应看到 `uid=10001 gid=10001`。`docker inspect ... .Config.User` 为空/root 是正常的，
它描述的是 entrypoint 的启动身份，不是主进程身份。降权后仅保留
`NET_BIND_SERVICE`（inheritable + ambient），用于 ACME 自动续期绑定 80/443；
`--no-new-privs` 仍生效。非 root `--user 10001` 启动没有该能力，ACME 续期可能
失败，见 §13。

### 5.1 首启时 /data 必须是 root:root

Phase A 安装器的 `validate_install_prefix` 要求 prefix 现有组件属主等于当前 euid（root）
且 group/other 不可写。因此 entrypoint 首启先执行：

```bash
install -d -m 0750 -o root -g root /data
```

安装成功后再 `chown` 到 10001。**不能**在首启前把空 volume chown 给 10001，否则安装器
会以“prefix 属主不是 root”拒绝。空 Docker volume 首次挂载时通常是 root:root；
entrypoint 会再显式把 `/data` 设为 `root:root 0750`，因此不需要手工 chown。

如果卷来自旧实验且属主已是 10001、但配置已存在，root 启动会检测到非 10001 属主并修复；
如果配置存在且属主已经是 10001，则跳过 chown。

### 5.2 已初始化 volume 用 `--user 10001:10001`

首启完成后，可以不再以 root 启动：

```bash
docker run -d --name rb-hub \
  --user 10001:10001 \
  -p 8443:8443 \
  -v rb-hub-data:/data \
  -v rb-hub-run:/run/rustboard \
  -e RUSTBOARD_ADMIN_TOKEN_SHARE=/run/rustboard/admin_token \
  ghcr.io/pazzifirst/rustboard-hub:v1.0.0
```

此时 entrypoint 只校验 `/data/etc/rustboard/hub.toml` 存在且可读，然后直接
`exec rustboard-hub run`，不执行 install/chown。panel、agent 同理。

限制：

- 非 root 不会生成共享 admin token；`--user 10001` 启动前必须已由 root 写过一次，
  或不要设置 `RUSTBOARD_ADMIN_TOKEN_SHARE`；
- 非 root 无法修复属主；如果 volume 权限不对，会以非零码退出并提示先用 root 启动；
- 首次启动不能直接 `--user 10001`。

## 6. 三个镜像的单独运行示例

以下命令用于排障/验证，生产推荐 Compose。`ghcr.io/...` 可替换成本地 tag。

### hub

```bash
docker run -d --name rb-hub \
  -p 8443:8443 \
  -p 127.0.0.1:8080:8080 \
  -v rb-hub-data:/data \
  -v rb-hub-run:/run/rustboard \
  -e RUSTBOARD_LISTEN=0.0.0.0:8443 \
  -e RUSTBOARD_ADMIN_LISTEN=127.0.0.1:8444 \
  -e RUSTBOARD_ADMIN_TOKEN_SHARE=/run/rustboard/admin_token \
  -e RUSTBOARD_ADVERTISE=hub.example.com \
  ghcr.io/pazzifirst/rustboard-hub:v1.0.0
```

- 8444 不发布；8080 这里由后续 panel 监听。
- 生产建议把 8080 改为 `127.0.0.1:8080:8080`（Compose 示例已这样做）。

### panel

```bash
docker run -d --name rb-panel \
  --network container:rb-hub \
  -v rb-panel-data:/data \
  -v rb-hub-run:/run/rustboard:ro \
  -e HUB_URL=http://127.0.0.1:8444 \
  -e HUB_TOKEN_FILE=/run/rustboard/admin_token \
  -e PANEL_LISTEN=0.0.0.0:8080 \
  -e PANEL_STATIC_DIR=/usr/share/rustboard/web \
  ghcr.io/pazzifirst/rustboard-panel:v1.0.0
```

panel 不发布端口，也不能独立于 hub 的 netns 运行（否则 127.0.0.1:8444 不可达）。

### agent

```bash
docker run -d --name rb-agent \
  -v rb-agent-data:/data \
  -v /secure/path/enroll.token:/run/rustboard/enroll_token:ro \
  -e RUSTBOARD_HUB_URL=wss://hub.example.com:8443/agent/ws \
  -e RUSTBOARD_TOKEN_FILE=/run/rustboard/enroll_token \
  -e RUSTBOARD_FINGERPRINT=REPLACE_WITH_64_HEX_FINGERPRINT \
  -e RUSTBOARD_NAME=agent-01 \
  ghcr.io/pazzifirst/rustboard-agent:v1.0.0
```

agent 默认非 privileged、不挂 `docker.sock`、控制面关闭，也没有新端口。

## 7. 敏感数据与安全

| 路径/数据 | 内容 | 处理 |
|---|---|---|
| `hub_data:/data` | SQLite、CA/服务端私钥、`admin_token`、agent secret | 按最高敏感级别备份/访问控制 |
| `panel_data:/data` | `panel.toml`（含 hub token、密码哈希） | 敏感 |
| `hub_run:/run/rustboard` | 共享 `admin_token`（0600，10001:10001） | 只给 hub 写、panel 只读挂载 |
| agent enrollment token 文件 | 一次性 token | 只读挂载，0600，用后轮换/删除 |
| 容器日志 | panel 初始密码（仅首次）、普通运行日志 | 限制日志系统访问；不要把日志公开 |

- 镜像内没有 `/etc/rustboard`：

  ```bash
  docker run --rm ghcr.io/pazzifirst/rustboard-hub:v1.0.0 \
    test ! -e /etc/rustboard/hub.toml
  ```

- `RUSTBOARD_ADMIN_TOKEN_SHARE` 只读取 `hub.toml` 顶层 `admin_token`，原子写入
  0600 文件，不打印；解析失败会直接退出，服务不会启动。
- panel 的 `HUB_TOKEN_FILE` 必须是普通文件、非符号链接、权限正好 `0600`，
  否则安装失败。
- entrypoint 会拒绝 `/data` 内受管路径（配置、数据、二进制、state、token 文件）的
  符号链接，防止 root 首启被 volume 内的链接诱导写到 volume 之外。
- 不要把 token 放进环境变量；`docker inspect`、Compose 文件和进程环境都可能泄露。
- 不要给 agent 默认加 `--privileged`、`/proc` 宿主挂载或 `docker.sock`。

### agent 控制面风险

agent 控制面（systemd / Docker / 进程 / 日志）默认关闭。要启用必须同时修改 agent 与 hub
两端 `[control]` 配置，并给 agent 宿主权限；启用后拿到 agent 凭据的主体可以执行
start/stop/restart、结束进程、读日志，也能伪造执行结果（hub 审计不能抵抗被控 agent）。
容器场景如需控制面，优先把 agent 以 systemd 方式运行在宿主机，而不是给容器 privileged；
确需 Docker 控制时，`docker.sock` 等同于宿主 root，必须单独评估并限制。

### 管理口

- hub 管理 API 默认只绑 `127.0.0.1:8444`，不 `EXPOSE`、不发布；
- 如果覆盖 `RUSTBOARD_ADMIN_LISTEN` 为非回环，必须同时设置
  `RUSTBOARD_ADMIN_TLS=required`，否则 hub 拒绝启动（`admin_tls=off`）；
- 远程面板需要 HTTPS/反代；不要在未启用管理端 TLS 时开放明文 8444。

## 8. 健康检查

| 服务 | 检查 | 说明 |
|---|---|---|
| hub | `curl -fsS http://127.0.0.1:8444/healthz` | 默认管理口回环 HTTP，免鉴权；`admin_tls=required` 时必须改用 HTTPS（见 §13） |
| panel | `curl -fsS http://127.0.0.1:8080/healthz` | panel 自身端口 |
| agent | `rustboard-agent cert-info --config /data/etc/rustboard/agent.toml` | 未 enrollment/证书过期时非零 |

agent 的 healthcheck 在 enrollment 完成前必然 unhealthy，Dockerfile 给了
`start-period=90s`；若超过仍 unhealthy，查看日志：

```bash
docker compose -f docker/compose.example.yml logs agent
docker compose -f docker/compose.example.yml exec agent \
  rustboard-agent cert-info --config /data/etc/rustboard/agent.toml
```

Docker 不会因为 unhealthy 自动重启容器（`restart` 只处理进程退出），需要自己监控
`State.Health.Status`。

手动检查：

```bash
docker compose -f docker/compose.example.yml exec hub \
  curl -fsS http://127.0.0.1:8444/healthz
docker compose -f docker/compose.example.yml exec panel \
  curl -fsS http://127.0.0.1:8080/healthz
# panel 与 hub 同 netns，也可以从 hub 容器访问 8080
```

healthcheck 的端口硬编码为 8444 / 8080。若覆盖 `RUSTBOARD_ADMIN_LISTEN` 或
`PANEL_LISTEN`，必须同步覆盖镜像 healthcheck，否则会一直 unhealthy。
启用 `admin_tls=required` 后内置 HTTP healthcheck 必然失败，必须改为 HTTPS +
正确 SNI/CA（示例见 §13），不能用 `-k` 跳过校验。

## 9. 只读根文件系统 / tmpfs（可选）

三镜像运行时只写 `/data`；hub 额外写 `/run/rustboard`（共享 token）。因此可以只读根：

```bash
docker run --rm --read-only --tmpfs /tmp --tmpfs /run \
  ghcr.io/pazzifirst/rustboard-hub:v1.0.0 --version
```

Compose 可在服务下增加：

```yaml
    read_only: true
    tmpfs:
      - /tmp
      - /run
```

前提：

- `/data` 必须是可写 volume；首次启动仍以 root 完成 install/chown；
- `/run` 必须是可写 tmpfs：Phase A 的 `/run/rustboard-install.lock` 首启需要写；
  只读根只加 `/tmp` 会失败。
- hub 的 `/run/rustboard` 必须是可写 volume（或 tmpfs），panel 以 `:ro` 挂载；
- 如果应用/底层库还需要其它可写路径，按日志补 `tmpfs`，不要为了“能跑”直接去掉
  `read_only`；
- ACME 证书/账户在 `/data`，只读根不影响签发；挑战端口绑定不需要写文件系统；
- 验证方法同 §8：healthz、`docker exec ... id`、日志无 permission denied。

## 10. 升级与回滚

- 镜像标签：`vX.Y.Z`、`sha-<short>`、稳定版 `latest`；不要在发布后移动已推送 tag。
- 常规升级：

  ```bash
  RUSTBOARD_VERSION=v1.0.1 \
  docker compose -f docker/compose.example.yml pull hub panel
  RUSTBOARD_VERSION=v1.0.1 \
  docker compose -f docker/compose.example.yml up -d
  ```

  entrypoint 检测到已有配置会跳过 install，数据/证书/配置保留；但新版本可能自动执行
  SQLite schema 迁移。ACME 部署升级时同样要带 `-f docker/compose.acme.example.yml`，
  否则端口/环境变量会退回默认 self-signed 叠加（已有配置仍不会被改写）。
- 升级前先停机备份 `hub_data` / `panel_data`；备份含私钥/token，必须加密并按 secret 管理。
- ACME 证书、账户与状态都在 `hub_data`，升级不会重写；切换 ACME directory/profile
  需要 `install --force` + `tls issue`，不要只改环境变量（见 §13.4）。
- 回滚：

  ```bash
  RUSTBOARD_VERSION=v1.0.0 \
  docker compose -f docker/compose.example.yml up -d
  ```

  如果新版本已迁移数据库，旧镜像可能无法打开；此时应恢复升级前的 volume 快照，
  而不是只回退镜像。不要通过删除 volume 来“修复”。
- 从 systemd 安装迁移到 Docker 不复用 `/etc/rustboard`、`/var/lib/rustboard`；容器使用
  独立 volume，需要重新初始化（agent 需重新 enrollment 或按文档迁移数据）。

## 11. 镜像标签与 revision

构建参数：

- `VERSION`：发布版本（如 `v1.0.0`），写入 `org.opencontainers.image.version`；
- `REVISION`：构建提交（如 `git rev-parse --short=12 HEAD`），写入
  `org.opencontainers.image.revision`。

检查：

```bash
docker image inspect ghcr.io/pazzifirst/rustboard-hub:v1.0.0 \
  --format '{{json .Config.Labels}}'
```

应至少包含：

```text
org.opencontainers.image.source=https://github.com/pazzifirst/rustboard
org.opencontainers.image.revision=<commit>
org.opencontainers.image.version=<version>
org.opencontainers.image.description=...
org.opencontainers.image.licenses=MIT
```

生产发布建议同时记录镜像 digest（`docker image inspect --format '{{index .RepoDigests 0}}'`）
与 `REVISION`，而不是只记录可变的 `latest`。

## 12. 故障排查

| 现象 | 原因/处理 |
|---|---|
| `安装前缀组件 /data 属主 uid=10001` | 首启前 volume 被 chown 给 10001；`chown 0:0 /data` 后 root 重试，或直接换新卷 |
| panel 报缺少 hub 管理 token | hub 未 healthy、`hub_run` 未挂载、或 `RUSTBOARD_ADMIN_TOKEN_SHARE` 未设置 |
| panel 报 token 权限不是 0600 | `chmod 0600 /run/rustboard/admin_token`；不要放宽到 0644 |
| agent healthcheck unhealthy | enrollment token 过期/已用、hub URL 不可达、指纹错误、证书 SAN 不匹配；看 agent 日志并重新 `agent add` |
| agent 提示证书 SAN/主机名不匹配 | 首次未设置 `RUSTBOARD_ADVERTISE`/`RUSTBOARD_SAN`；更新 `hub.toml` 的 `server_names` 后 `rotate-cert --force`，agent 重新 enrollment |
| hub/panel 一直 unhealthy | 覆盖了 8444/8080 但没改 healthcheck；或服务启动失败，先看容器日志。`admin_tls=required` 时必须用 HTTPS healthcheck |
| ACME 容器内 80/443 可 bind、公网不通 | 默认 compose 不发布 80/443；用 ACME 叠加文件/`-p`，再查云安全组；见 §13 |
| 改了 `RUSTBOARD_TLS_MODE` 不生效 | 已有 `/data/etc/rustboard/hub.toml`，entrypoint 跳过 install；见 §13.4 |
| `--user 10001` 下 ACME 续期报绑定失败 | 非 root 无 `NET_BIND_SERVICE`；ACME 用默认 root entrypoint |
| `RUSTBOARD_ACME_*` 缺失/非法 | entrypoint 在 install 前退出；按提示补变量，不要加 `--offline` |
| `COPY dist/... not found` | 未先运行构建脚本，或 `--platform` 对应架构的 `dist/<arch>/bin` 不存在 |
| 镜像内找不到 web | `web/dist` 未构建，或 `.dockerignore` 误排除了 `web/dist` |

## 13. ACME 模式（Phase C）

### 13.1 叠加启动

默认 compose 是 **self-signed + 安装阶段 `--offline`**，且**不发布 80/443**，
因此既有 Docker 门禁（panel 共享 netns、8444 不发布）不受影响。ACME 用叠加文件：

```bash
RUSTBOARD_VERSION=v1.0.0 \
RUSTBOARD_ACME_EMAIL=admin@example.com \
RUSTBOARD_ACME_DOMAIN=board.example.com \
RUSTBOARD_ACME_CHALLENGE=http-01 \
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml up -d
```

叠加后 hub 发布 `8443`（agent）、`80`（HTTP-01）、`443`（TLS-ALPN-01）与
`127.0.0.1:8080`（panel）；8444 仍不 EXPOSE、不发布。panel 仍共享 hub 的
network namespace。

### 13.2 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `RUSTBOARD_TLS_MODE` | `self-signed` | `self-signed` / `acme-domain` / `acme-ip` |
| `RUSTBOARD_ACME_EMAIL` | 无（ACME 必填） | 账户邮箱；不打印 |
| `RUSTBOARD_ACME_DOMAIN` | 无（ACME 必填） | 逗号分隔；domain 1–20 个 DNS，IP 恰好一个 IPv4 |
| `RUSTBOARD_ACME_CHALLENGE` | `http-01` | `http-01` / `tls-alpn-01` |
| `RUSTBOARD_ACME_PROFILE` | 空 | 例如 `shortlived`；IP 留空运行时默认 |
| `RUSTBOARD_ACME_CA_FILE` | 空 | 容器内绝对路径；仅私有/Pebble ACME，需只读挂载 |
| `RUSTBOARD_ACME_DIRECTORY` | LE production | 自定义目录；调试用 staging |
| `RUSTBOARD_ADMIN_TLS` | 空（off） | `off` / `required`；required 必须覆盖 healthcheck |

- self-signed 仍由 entrypoint 追加 `--offline`；ACME 模式**绝不**追加。
- ACME 变量缺失/非法时在 install 前退出，不写配置；不要用 `--offline` 绕过。
- `RUSTBOARD_ADVERTISE` 在 ACME 模式下必须是证书标识之一，否则被忽略并使用
  第一个域名（避免 agent 安装 URL 与证书不一致）。

### 13.3 证书持久化、能力与 healthcheck

- 证书、ACME 账户与状态在 `hub_data`：
  `/data/var/lib/rustboard/hub/certs/`。重建容器不会重新申请；`down -v` 会
  删除它们（含私钥/账户），不要把删除 volume 当作常规“重置证书”手段。
- 私钥/账户 0600、证书 0644、目录 0700；备份 `hub_data` 等于备份私钥。
- 首次安装以 root 完成；之后 `setpriv` 降权到 10001，但保留
  `NET_BIND_SERVICE` 供自动续期绑定 80/443。只读根（`/tmp`、`/run` tmpfs）仍可用。
- `admin_tls=required` 时覆盖 healthcheck（示例；公共 ACME 去掉 `--cacert`）：

  ```yaml
  healthcheck:
    test: ["CMD", "curl", "-fsS",
           "--cacert", "/data/var/lib/rustboard/hub/certs/ca.crt",
           "--resolve", "board.example.com:8444:127.0.0.1",
           "https://board.example.com:8444/healthz"]
  ```

### 13.4 模式变更

已有 `hub.toml` 时 entrypoint 跳过 install；改环境变量不会切换证书来源。用
root 直接执行安装器（会成对备份旧证书）：

```bash
# 1) 停掉旧 hub/panel，释放 80/443/8443/8080（会短暂中断服务）
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml stop panel hub

# 2) 以 root 执行安装器；--service-ports 让 ACME 挑战从公网可达 80/443
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

或删除 `hub_data` 重新初始化（丢数据，仅可重建环境）。切换后先 `up -d`，再执行
`docker compose exec hub rustboard-hub tls status --config /data/etc/rustboard/hub.toml`
确认来源。

> Docker ACME 的端到端验证需要公网 80/443 或 Pebble 端口映射；C8 只做
> compose/脚本静态检查，不伪造签发成功。真实 LE staging 留 C9 手工门禁。

## 14. 相关文档

- [M5 Phase B 交付计划](../docs/plans/2026-10-25-m5-phase-b-delivery.md)
- [M5 Phase A 安装器计划](../docs/plans/2026-10-24-m5-phase-a-installer.md)
- [服务端 TLS](../docs/install/tls.md) / [ACME](../docs/install/acme.md) /
  [面板 TLS](../docs/install/panel-tls.md) / [故障排查](../docs/install/troubleshooting.md)
- [AGENTS.md](../AGENTS.md) §6/§9
- 构建脚本：`packaging/build-release.sh`（由 Phase B 构建流水线提供）
