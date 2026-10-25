# Docker 部署（M5 Phase B）

Phase B 提供 hub / panel / agent 三个运行时镜像，基础镜像固定为 Debian bookworm
slim，镜像内只复制静态 musl 二进制和前端资源，不在镜像里编译 Rust。

> 完整构建/运行说明、故障排查与安全边界见
> [docker/README.md](../../docker/README.md)。本文只给最短路径与关键限制。
>
> 当前本地验证版本为 `0.4.2`；正式镜像 `v1.0.0` 在 Phase E 版本归档后由 release
> workflow 推送。

## 1. 构建前提

```bash
# 1) 前端
(cd web && pnpm install --frozen-lockfile && pnpm build)

# 2) 两架构静态二进制与离线包
packaging/build-release.sh

# 3) 单架构本地镜像（多架构由 release workflow 构建）
docker buildx build --load --platform linux/amd64 \
  -f docker/Dockerfile --target hub \
  --build-arg VERSION=0.4.2 --build-arg REVISION="$(git rev-parse HEAD)" \
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
因为 Phase B 管理 API 仍只允许 `127.0.0.1:8444`。

## 3. 不能做的事

- **不要把 8444 发布到宿主**。管理口没有 TLS，Phase B 不承诺安全地开放明文管理口；
  远程 panel 要等 Phase C 的 HTTPS/反代。
- 不要给 panel 加 `ports`；panel 的 8080 由 hub 服务发布（示例绑宿主回环）。
- 不要把 panel 放到独立 network namespace；否则它访问不到 `127.0.0.1:8444`。
- 不要默认给 agent `--privileged`、`/proc` 宿主挂载或 `docker.sock`；控制面默认关闭，
  需要时单独评估宿主权限风险。
- 不要把 token 放进环境变量、Compose 文件或镜像；只挂载 0600 文件，或在 hub 与
  panel 之间使用专用 `hub_run` 敏感 volume。

## 4. 运行身份与数据

- 镜像 `Config.User` 为 root，仅用于首启安装/chown；entrypoint 在安装成功后用
  `setpriv` 降权，**主进程 UID/GID 为 10001**。
- `/data` 是唯一运行期数据 volume；首启前必须是 root:root 0750，安装完成后 entrypoint
  统一 chown 到 10001。
- 已初始化的 volume 可以用 `--user 10001:10001` 启动；空 volume 直接 `--user` 必须
  失败，entrypoint 不会假装初始化成功。
- hub 的 `/run/rustboard` 是共享 admin token 的敏感 volume：hub 写、panel 只读挂载。
  不需要同机 panel 时不要挂载或不要设置 `RUSTBOARD_ADMIN_TOKEN_SHARE`。
- 健康检查：hub `127.0.0.1:8444/healthz`，panel `127.0.0.1:8080/healthz`，agent
  `cert-info`（未 enrollment 前必然 unhealthy）。
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

# 8444 不应出现在宿主端口
docker port <hub-container>

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

## 6. 升级、回滚与限制

- 升级镜像前备份 `hub_data` / `panel_data`；备份含私钥/token，必须按 secret 管理。
- entrypoint 检测到已有配置会跳过 install；新版本运行期可能执行 SQLite schema
  迁移。回滚镜像前先确认数据库兼容性，必要时恢复 volume 快照。
- 已发布 tag 不移动；镜像 digest 与 `REVISION` label 一起记录。
- 从 systemd 安装迁移到 Docker 不复用 `/etc/rustboard`、`/var/lib/rustboard`；需要
  重新初始化，agent 需重新 enrollment。
- Phase B 不提供远程 panel、管理端 TLS、Kubernetes Operator 或 HA。
