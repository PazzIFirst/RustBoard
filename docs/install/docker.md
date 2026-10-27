# Docker 部署（M5 Phase B/C/D）

Phase B 提供 hub / panel / agent 三个运行时镜像，基础镜像固定为 Debian bookworm
slim，镜像内只复制静态 musl 二进制和前端资源，不在镜像里编译 Rust。Phase C 在
同一镜像上增加 ACME 端口元数据、`RUSTBOARD_TLS_MODE`/`RUSTBOARD_ACME_*` 环境变量
与降权后的 `NET_BIND_SERVICE` 保留；Phase D 增加 PostgreSQL 显式 opt-in
（`RUSTBOARD_DATABASE*` 与 `docker/compose.postgres.example.yml`），默认 compose
仍使用 SQLite。agent 增加显式服务端信任模式
（`fingerprint` / `system-roots` / `custom-ca`），ACME Hub 不再被迫用指纹；
已初始化 volume 的 TLS/监听重配置使用保留数据的受控流程。

> 完整构建/运行说明、故障排查与安全边界见
> [docker/README.md](../../docker/README.md)。本文只给最短路径与关键限制。
>
> 当前版本以根 `Cargo.toml` 的 `[workspace.package].version` 为准；Phase C
> RC 已发布，Phase D 已实现 PostgreSQL 显式 opt-in 与迁移/备份/恢复 CLI。正式镜像
> `v1.0.0` 在 Phase E 版本归档后由 release workflow 推送。

## 1. 构建前提

```bash
# 1) 前端
(cd web && pnpm install --frozen-lockfile && pnpm build)

# 2) 两架构静态二进制与离线包
packaging/build-release.sh

# 3) 单架构本地镜像（多架构由 release workflow 构建）
#    从 Cargo.toml 派生版本；所有构建命令都在仓库根执行，
#    -f docker/Dockerfile 与末尾的 .（仓库根 context）都不能省
VERSION=$(cargo metadata --no-deps --format-version 1 --offline \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "rustboard-hub"))')
docker buildx build --load --platform linux/amd64 \
  -f docker/Dockerfile --target hub \
  --build-arg VERSION="$VERSION" --build-arg REVISION="$(git rev-parse HEAD)" \
  -t ghcr.io/pazzifirst/rustboard-hub:dev .
```

`panel`、`agent` 同理，改 `--target` 与镜像名。所有 `docker build` /
`docker buildx build` 都必须在仓库根执行并显式带 `-f docker/Dockerfile`；
末尾的 `.` 就是仓库根 build context，不能改成 `docker/`。`TARGETARCH` 由
buildx 自动注入，对应 `dist/amd64` / `dist/arm64`。

## 2. 最短 Compose 启动

```bash
# 先按 docker/compose.example.yml 修改占位符：
#   RUSTBOARD_HUB_ADVERTISE   agent 实际连接的域名/IP（写入证书 SAN）
#   RUSTBOARD_HUB_URL         wss://<hub>:8443/agent/ws
#   RUSTBOARD_HUB_FINGERPRINT self-signed hub 的证书 SHA-256 指纹
#   RUSTBOARD_ENROLL_TOKEN_FILE 0600 enrollment token 文件
# ACME hub 的 agent 用 system-roots（公共证书）或 custom-ca（私有 CA），
# 不再用 fingerprint；见 §6.5。
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
  失败，entrypoint 不会假装初始化成功。已初始化 volume 要改 TLS 模式/监听参数时，
  不能直接把 `/data` chown 给 root 后跑 `install --force`；按 §6.6 的受控重配置
  流程，安装后必须恢复 10001 属主。
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

# 主进程真实 UID：读取唯一的 `rustboard-hub run` 进程的 /proc/<pid>/status，
# 而不是 exec 新进程的 id；agent 的 healthcheck 会执行 `cert-info`，必须过滤掉。
# 失败即非零退出：run 进程必须唯一，Uid 四列必须全为 10001。
docker compose -f docker/compose.example.yml exec hub sh -c '
  set -eu
  pid=""
  for p in $(pidof rustboard-hub 2>/dev/null || true); do
    cmd=$(tr "\0" " " < "/proc/$p/cmdline" 2>/dev/null || true)
    case "$cmd" in
      *"rustboard-hub run "*)
        [ -z "$pid" ] || { echo "rustboard-hub 有多个 run PID: $pid 与 $p" >&2; exit 1; }
        pid="$p"
        ;;
    esac
  done
  [ -n "$pid" ] || { echo "未找到 rustboard-hub run 进程" >&2; exit 1; }
  uid=$(awk "/^Uid:/ {print \$2, \$3, \$4, \$5}" "/proc/$pid/status")
  [ "$uid" = "10001 10001 10001 10001" ] \
    || { echo "rustboard-hub UID 不是 10001: $uid" >&2; exit 1; }
  echo "rustboard-hub Uid: $uid"
'

# panel / agent 同理，把 rustboard-hub 换成 rustboard-panel / rustboard-agent。
# 依赖容器内 pidof（Debian 基础层的 sysvinit-utils）；若自定义镜像裁掉了它，
# 改用 docker top <container> -o pid,uid,gid,cmd 人工确认 rustboard-* 为 10001。
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

**历史 C8 本地复跑（rc.2 阶段，不可用作当前 HEAD 门禁）**：
`DOCKER_ARCH=amd64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh` 当时记录
**123 PASS / 0 FAIL / 1 SKIP**（SKIP 为可选 arm64/QEMU 检查，由
`delivery-arm64` 原生覆盖）。当前 HEAD/新 dist 必须重新跑，不能引用旧结果。

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

> 上表的 `RUSTBOARD_TLS_MODE` 是 **hub** 的证书来源。agent 的
> `RUSTBOARD_TLS_MODE` 是另一组取值（`fingerprint` / `system-roots` /
> `custom-ca`），compose 用 `RUSTBOARD_AGENT_TLS_MODE` 传入，见 §6.5；不要把
> `acme-domain` 直接设给 agent。

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
已有配置。切换 self-signed ↔ ACME 必须按 §6.6 的受控重配置流程执行
`install --yes --force --no-systemd --prefix /data`；**不能**直接把 `/data`
chown 给 root 后跑完就启动，也不能删除 `hub_data` 当作“重置证书”。

§6.6 第 3 步的 ACME 安装命令（必须带 `--service-ports`，让 80/443 从公网可达）：

```bash
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml run --rm --service-ports hub \
  rustboard-hub install --yes --force --no-systemd --prefix /data \
    --listen 0.0.0.0:8443 --admin-listen 127.0.0.1:8444 --panel no \
    --tls acme-domain --advertise board.example.com \
    --acme-email admin@example.com \
    --domain board.example.com --acme-challenge http-01
```

完成后按 §6.6 第 4 步恢复 10001 属主，再带 ACME 叠加文件 `up -d`，最后执行
`docker compose exec --user 10001:10001 hub rustboard-hub tls status --config /data/etc/rustboard/hub.toml`
确认来源（`exec` 默认 root，会被 data_dir 属主校验拒绝）。安装器会成对备份旧证书；只有回滚未完成时才保留并打印 txn `backup_dir`，
成功安装或回滚成功都会删除该临时目录（证书 `.bak` 与它不同）。

> 本地/Docker 的 ACME 端到端验证依赖真实公网入口或 Pebble 端口映射；只做
> compose/脚本静态检查时**不伪造** ACME 成功。真实 LE staging 留手工门禁。

### 6.5 agent 信任模式（ACME / 私有 CA）

Hub 的证书来源（§6.1）和 agent 的**服务端信任模式**是两件事。agent 容器内的
`RUSTBOARD_TLS_MODE` 只接受：

| 模式 | 适用 | 首次安装必填 | 必须为空 |
|---|---|---|---|
| `fingerprint`（默认） | self-signed Hub | `RUSTBOARD_FINGERPRINT` | `RUSTBOARD_SERVER_CA` |
| `system-roots` | 公共 ACME（LE 等） | 无 | `RUSTBOARD_FINGERPRINT` / `RUSTBOARD_SERVER_CA` |
| `custom-ca` | 私有 ACME / 私有 CA | `RUSTBOARD_SERVER_CA` | 无（fingerprint 可留空） |

- 未知模式在写盘前失败，不会回退 fingerprint；非 fingerprint 模式必须用
  `wss://`。
- 安装器把模式写入 `agent.toml`；custom-ca 会把 CA 复制到
  `/data/var/lib/rustboard/agent/server-ca.pem`。重启/重连直接读配置，不需要
  重新 enrollment。
- compose 变量是 `RUSTBOARD_AGENT_TLS_MODE`（容器内映射为
  `RUSTBOARD_TLS_MODE`）和 `RUSTBOARD_AGENT_SERVER_CA_FILE`（宿主 CA 路径）；
  不要把它们和 hub 的 `RUSTBOARD_TLS_MODE` 混用。

公共 ACME（`compose.acme.example.yml` 已把 agent 设为 `system-roots`）：

```bash
RUSTBOARD_HUB_URL=wss://board.example.com:8443/agent/ws \
RUSTBOARD_ENROLL_TOKEN_FILE=/absolute/path/to/enroll.token \
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml --profile agent up -d
```

私有 ACME / 私有 CA（必须最后叠加 custom-ca 文件，覆盖成 `custom-ca`）：

```bash
# 公开的 agent 信任锚（不是私钥）；从运行中的 hub 提取
install -d -m 0700 ./secrets
docker compose -f docker/compose.example.yml \
  cp hub:/data/var/lib/rustboard/hub/certs/agent-ca.pem ./secrets/agent-ca.pem
chmod 0644 ./secrets/agent-ca.pem

RUSTBOARD_HUB_URL=wss://board.example.com:8443/agent/ws \
RUSTBOARD_AGENT_SERVER_CA_FILE="$PWD/secrets/agent-ca.pem" \
RUSTBOARD_ENROLL_TOKEN_FILE=/absolute/path/to/enroll.token \
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml \
  -f docker/compose.agent-custom-ca.example.yml \
  --profile agent up -d
```

- `agent-ca.pem` 只由**私有 ACME** 安装器生成；公共 ACME 用 system-roots，
  不要用它。CA 只用于验证 Hub **服务端**证书；不要放客户端 CA、agent 证书或私钥。
- 不要用 fingerprint 给会轮换的 ACME 证书兜底；续期换证后会失联。
- `hub agent add` 在 ACME 模式会按证书来源打印 `--tls-mode system-roots` 或
  `--tls-mode custom-ca --server-ca ...`；优先照该输出执行。
- self-signed Hub 继续用 fingerprint：设置 `RUSTBOARD_HUB_FINGERPRINT`（或
  `RUSTBOARD_AGENT_FINGERPRINT`），不要设置 `RUSTBOARD_AGENT_TLS_MODE`。
- 模式只在 agent 首次初始化时生效；已有 agent volume 的环境变量不会改写
  `agent.toml`。迁移见 §6.6 末尾。

### 6.6 已初始化 volume 的受控重配置（保留数据）

已初始化 `/data` 归 `10001:10001`；`rustboard-hub install` 需要 root，且
`validate_install_prefix`、`data_dir` 与 `install-state.toml` 都会检查属主。
所以直接 `docker compose ... run hub rustboard-hub install --force --prefix /data`
会失败。不要删除 volume、不要把 `/data` 改成 0777，也不要放宽安装器校验。按下面
顺序执行（以 self-signed 重配为例；ACME 命令见 §6.4）：

```bash
# 0) 先停服；停服前记录 tls status / hub.toml 基线
docker compose -f docker/compose.example.yml \
  exec --user 10001:10001 hub \
  rustboard-hub tls status --config /data/etc/rustboard/hub.toml \
  > /tmp/rb-tls-before.txt
docker compose -f docker/compose.example.yml \
  cp hub:/data/etc/rustboard/hub.toml /tmp/rb-hub-before.toml
docker compose -f docker/compose.example.yml stop panel hub

# 1) 停服后备份（含私钥/admin token；放仓库外并按 secret 保管）。
#    不要对运行中的 SQLite volume 直接 tar；在线快照用 rustboard-hub backup。
BACKUP_DIR=${RUSTBOARD_BACKUP_DIR:-$HOME/rustboard-backups}
install -d -m 0700 "$BACKUP_DIR"
docker compose -f docker/compose.example.yml run --rm --no-deps \
  -v "$BACKUP_DIR:/backup" --entrypoint /bin/sh hub \
  -c 'umask 077; tar -C /data -czf /backup/hub-data-$(date +%Y%m%dT%H%M%S).tgz .'

# 2) 只切安装必需路径；先拒绝符号链接/子挂载，再 -xdev + chown -h
docker compose -f docker/compose.example.yml run --rm --no-deps hub sh -c '
  set -eu
  bad=$(find /data -xdev -type l -print -quit)
  [ -z "$bad" ] || { echo "拒绝：$bad 是符号链接" >&2; exit 1; }
  dev=$(stat -c %d /data)
  bad_mount=$(find /data -xdev -type d -exec stat -c "%d %n" {} + \
    | awk -v dev="$dev" "\$1 != dev { print \$2; exit }")
  [ -z "$bad_mount" ] || { echo "拒绝：$bad_mount 是子挂载" >&2; exit 1; }
  chown -h 0:0 /data /data/var /data/var/lib
  find /data/var/lib/rustboard -xdev -exec chown -h 0:0 {} +
'

# 3) 以 root 安装；非 TTY 必须 --yes
docker compose -f docker/compose.example.yml run --rm hub \
  rustboard-hub install --yes --force --no-systemd --prefix /data \
    --listen 0.0.0.0:8443 --admin-listen 127.0.0.1:8444 --panel no \
    --tls self-signed

# 4) 成功或失败都恢复 10001；同样拒绝符号链接/子挂载，-xdev + chown -h
docker compose -f docker/compose.example.yml run --rm --no-deps hub sh -c '
  set -eu
  bad=$(find /data -xdev -type l -print -quit)
  [ -z "$bad" ] || { echo "拒绝：$bad 是符号链接" >&2; exit 1; }
  dev=$(stat -c %d /data)
  bad_mount=$(find /data -xdev -type d -exec stat -c "%d %n" {} + \
    | awk -v dev="$dev" "\$1 != dev { print \$2; exit }")
  [ -z "$bad_mount" ] || { echo "拒绝：$bad_mount 是子挂载" >&2; exit 1; }
  find /data -xdev -exec chown -h 10001:10001 {} +
  bad_owner=$(find /data -xdev \( ! -uid 10001 -o ! -gid 10001 \) -print -quit)
  [ -z "$bad_owner" ] || { echo "属主未恢复: $bad_owner" >&2; exit 1; }
'

# 5) 启动；ACME 配置必须继续带 compose.acme.example.yml
docker compose -f docker/compose.example.yml up -d
```

失败处理：

- 第 2/4 步在 chown 前已拒绝符号链接/子挂载；若 chown 中途失败，重跑第 4 步。
- 第 3 步失败/中断后，先单独重跑第 4 步恢复属主；不要用 `--user 10001` 启动
  “修复”，也不要在 root 属主状态下直接 `up -d`。
- **backup_dir**：成功安装会 commit 并删除临时事务备份；只有回滚未完成时才
  打印并保留 `txn backup_dir`（旧 config/unit/binary/state），从它人工恢复后
  再执行第 4 步。不要声称成功安装还有该目录。
- 证书成对备份在 `certs/server.crt.bak-*` / `server.key.bak-*`，与 txn backup
  不是同一个东西；需要回滚证书时按 `.bak` 恢复并再次执行第 4 步。
- 若 `find ... chown -h` 本身失败，保留现场并检查只读挂载/文件系统错误；
  不要删除 volume。

恢复验收至少包括：§5 的 `check_uid`（只匹配 `run` 进程）、
`tls status`（before/after）、`hub.toml` hash、`server.crt/server.key` 配对、
SQLite `quick_check`/计数与 `agents` 数。完整可执行命令见
[docker/README.md §5.3](../../docker/README.md#53-已初始化-volume-的受控重配置保留数据)；
其中 `rustboard-hub backup` 用 `VACUUM INTO` 生成一致快照并做 `quick_check`。

可复现脚本：`bash tests/e2e/v100-docker-tls-volume.sh`（默认启动一次性 Pebble；
已有 Pebble 可设 `PEBBLE_REUSE=rb-pebble`；需要本地 local-s4 镜像，不进入 CI）。

> agent volume 也是 10001；已有 agent 需要 `install --force` 时按同样顺序执行
> （`--profile agent agent` + `rustboard-agent install --yes --force --no-systemd
> --prefix /data ...`），随后恢复 10001。entrypoint 的环境变量只在首次初始化时
> 生效；从 `custom-ca` 改到其他模式时安装器不会自动清空旧 `server_ca`，需先备份
> 并处理该字段，或新建 volume 重新 enrollment。

## 7. 升级、回滚与限制

- 升级镜像前备份 `hub_data` / `panel_data`；备份含私钥/token，必须按 secret 管理。
- entrypoint 检测到已有配置会跳过 install；新版本运行期可能执行 SQLite schema
  迁移。回滚镜像前先确认数据库兼容性，必要时恢复 volume 快照。
- ACME 证书在 `hub_data` 中持久化；升级不会重写证书/账户。切换 ACME
  directory/profile 需要 §6.6 的受控 `install --force` + `tls issue`。
- 已有 volume 改 TLS 模式/监听参数必须按 §6.6 做；直接 root `install --force`
  会被 prefix/data_dir 属主校验拒绝。不要删除 volume 或放宽校验。
- ACME Hub 的证书不是本地客户端 CA 签发：agent 不能再靠 fingerprint/本地
  `ca.crt` 校验服务端。公共 ACME 用 `system-roots`，私有 ACME 用
  `custom-ca`；已有 fingerprint agent 需改信任或重新 enrollment，见 §6.5。
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

## 8. Phase E S4：PostgreSQL overlay e2e

> **历史证据（不可用于当前门禁）**：2026-10-26 在 `v1.0.0-rc.2` 提交
> `68f24e0` 上记录 **PASS=104 / FAIL=0 / SKIP=1（arm64 由 S5 覆盖）**，退出码 0；
> 证据 `target/docker-pg-e2e/20261026t133124z-3736044/`（含 provenance、日志、
> PG 计数，hub sha256 `1a23fa5e…`）。该结果绑定的是当时 rc.2 dist，不是当前 HEAD/
> 新 dist；当前代码必须重建 dist 并重跑后才能作为门禁证据。下面的 PASS 条件仍是
> 脚本判定标准，历史结果不能回填到本次运行。

脚本必须带 dist 来源绑定运行（**验证码版本号不够**，同名旧 dist 也可能
通过 `--version`；manifest 把本次源码产物与 e2e 强绑定）：

```bash
# 主 Agent 在 S4 前用 packaging/build-release.sh --arch amd64 重建 dist，
# 然后生成 manifest（顺序不能反；重建 dist 后必须重新生成）：
mkdir -p target
{
  printf 'hub=%s\n'   "$(sha256sum dist/amd64/bin/rustboard-hub   | awk '{ print $1 }')"
  printf 'panel=%s\n' "$(sha256sum dist/amd64/bin/rustboard-panel | awk '{ print $1 }')"
  printf 'agent=%s\n' "$(sha256sum dist/amd64/bin/rustboard-agent | awk '{ print $1 }')"
  printf 'web=%s\n'   "$(sha256sum web/dist/index.html             | awk '{ print $1 }')"
} > target/dist-manifest.txt

# 从 Cargo.toml 派生当前版本，与 dist/包名/镜像 label 使用同一来源
EXPECTED_VERSION=$(cargo metadata --no-deps --format-version 1 --offline \
  | python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"] == "rustboard-hub"))')
EXPECTED_VERSION="$EXPECTED_VERSION" \
  bash tests/e2e/v100-docker-pg.sh --dist-manifest target/dist-manifest.txt
# 或：EXPECTED_DIST_SHA256='hub=... panel=... agent=... web=...' \
#       bash tests/e2e/v100-docker-pg.sh
```

`--dist-manifest` 与 `EXPECTED_DIST_SHA256` 二选一且**必填**；缺失、格式非法或
四个 sha256 任一与当前 dist 不符都会在 build 前 FATAL。脚本把 HEAD、四个 dist
sha256、三个本地镜像 ID 写入 `target/docker-pg-e2e/<UTC>-<PID>/provenance.txt`
作为来源证据。它只使用当前源码重建的 dist 与本地镜像，不联网拉取、不构建
arm64（S5 独立）：

1. 用 `dist/amd64/bin` 与 `web/dist` 构建
   `ghcr.io/pazzifirst/rustboard-{hub,panel,agent}:local-s4`；断言 hub 镜像内
   `rustboard-hub --version` 与当前源码一致（期望上面从 `Cargo.toml` 派生的
   `EXPECTED_VERSION`），`org.opencontainers.image.revision` 等于当前 HEAD，
   且 dist sha256 与 manifest 强匹配，**不是**旧 RC GHCR 镜像或同名旧 dist；
2. 断言 hub 镜像内没有 `pg_dump` / `pg_restore` / `psql`；
3. 默认 compose（`RUSTBOARD_VERSION=local-s4`）`config` 无 postgres service、
   无 5432/8444 发布；实跑 hub+panel healthy，hub 配置为
   `sqlite:///data/var/lib/rustboard/hub/rustboard.db`，`hub_data` volume 内的
   `rustboard.db` 通过 SQLite integrity/schema 检查；
4. PG overlay（默认文件 + `docker/compose.postgres.example.yml`）启动
   postgres+hub（含 panel）；密码只落 0600 secret；hub 配置为
   `postgres://rustboard@postgres:5432/rustboard?sslmode=disable`，没有
   `db_sslrootcert`，5432 不发布；管理口 `/healthz` 与 Bearer
   `/api/v1/agents` 可用且不打印 token；
5. 真实 agent 用一次性 token + `hub ports` 指纹启动，达到 cert-info
   healthy/online，PG `samples` / `ingest_batches` / `agents` 均 >0；
6. 按顺序停/启 postgres 与 hub 后，hub.toml 哈希不变、计数不减少；
7. 已初始化 hub volume 以 `--user 10001:10001` 启动短时 hub，health 200、
   日志无权限错误、配置哈希不变；
8. 用外部 `postgres:16` client 容器 `pg_dump -Fc`，恢复到新库
   `rustboard_restore` 后四张核心表计数一致，原库计数不变；
9. 默认 SQLite 与 PG overlay 的项目、**network 与 volume 名集合**完全独立；
10. 默认 compose `restart hub` 后 `hub.toml` 与 `admin_token` 哈希不变。

运行前置：

- Linux amd64、Docker 24+、compose v2+、buildx（缺失时回退 `docker build`，
  并显式传 `--build-arg TARGETARCH=amd64`）、curl、python3；
- 本机已有 `debian:bookworm-slim` 与 `postgres:16`（或
  `postgres:16-alpine`）。overlay 默认 pin `postgres:16-alpine`；本机没有
  alpine 时脚本只在临时 compose override 中改用本地 `postgres:16`，
  **不会 pull**；两者都没有时明确 FAIL；
- 宿主 8443/8080 空闲；脚本不会停止无关容器；
- `docker build` 的 `apt-get` 层可能需要访问 Debian 软件源；若本机没有构建
  缓存/网络，请预先准备好基础镜像与构建缓存。脚本本身不 pull；
- `--user 10001` 用例需要 root 才能 `chown` 0600 测试密码文件到 10001；它使用
  已初始化 volume，不重新安装；
- 当前源码版本由上面的 `cargo metadata` 从 `Cargo.toml` 派生；脚本内置的
  `EXPECTED_VERSION` 默认值可能落后于源码，重跑时始终显式传入派生值（或
  `EXPECTED_VERSION=<新版本>`），否则 preflight 会拒绝不一致的 dist。

成功且 cleanup 无残留时最后一行是 `全部 N 项通过`；失败、中断（HUP/INT/TERM）
或资源残留只输出“未通过/中断”，以非 0 退出。证据（脱敏日志、计数、
`provenance.txt`）在 `target/docker-pg-e2e/<UTC>-<PID>/`，失败保留。密码/token
在独立 `/tmp` secret 目录，脚本退出时**尝试**删除；删除失败会计入 FAIL，且
不会进入证据目录。hub/postgres 的 compose 配置与容器 inspect 不得出现密码
明文；PG client 容器以 `PGPASSWORD` 环境变量取得密码，是明确的临时例外
（`--rm` 容器）。

限制：

- 只验证 `linux/amd64`；多架构/arm64 由 S5 覆盖；
- PG overlay 用 stock postgres 镜像，`sslmode=disable` 只适合本机/受信内网；
  生产 TLS 见 [postgres.md](postgres.md) §3.1 与 §7.1；
- hub 镜像不含 PostgreSQL client，备份/恢复必须用宿主 `postgresql-client`
  或临时 `postgres:16` 容器；不要为了备份给镜像加包；
- 当前是单 hub 语义，e2e 不会启动多个写同一个 PG 的 hub；
- 该脚本依赖 Docker、固定宿主端口与本地镜像，**不进入 CI**。
