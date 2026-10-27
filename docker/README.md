# RustBoard Docker 镜像与 Compose

本文覆盖 Phase B/C 的 hub / panel / agent 三个运行时镜像。镜像**不编译 Rust**，只复制
`packaging/build-release.sh` 产出的 musl 静态二进制和 `web/dist` 前端产物；基础镜像、
端口、降权和 healthcheck 都在 `docker/Dockerfile` 中固定。Phase C 增加 ACME
（80/443 元数据、`RUSTBOARD_TLS_MODE`/`RUSTBOARD_ACME_*`）、面板直连 HTTPS
与管理端 TLS 的容器侧说明；Phase D 增加 PostgreSQL（显式 opt-in）的容器侧说明，
默认仍是 SQLite。

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

在仓库根目录执行。所有 `docker build` / `docker buildx build` 都必须显式带
`-f docker/Dockerfile`，末尾的 `.` 是仓库根 build context；不要进入 `docker/`
目录构建。单架构本地构建示例：

```bash
VERSION=v1.0.0
REVISION=$(git rev-parse --short=12 HEAD)

for role in hub panel agent; do
  docker buildx build \
    -f docker/Dockerfile \
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
    -f docker/Dockerfile \
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
# 读取服务进程自己的 /proc/<pid>/status；`exec id` 只反映新进程身份，不能证明降权。
# 只接受唯一的 `... run ...` 进程：agent healthcheck 会短暂执行 `cert-info`，
# 不能把 healthcheck 进程混进 UID 判断或误报“PID 不唯一”。
check_uid() {
  docker compose -f docker/compose.example.yml exec "$1" sh -c '
    set -eu
    pid=""
    for p in $(pidof "$1" 2>/dev/null || true); do
      cmd=$(tr "\0" " " < "/proc/$p/cmdline" 2>/dev/null || true)
      case "$cmd" in
        *"$1 run "*)
          [ -z "$pid" ] || { echo "进程 $1 有多个 run PID: $pid 与 $p" >&2; exit 1; }
          pid="$p"
          ;;
      esac
    done
    [ -n "$pid" ] || { echo "未找到 $1 run 进程" >&2; exit 1; }
    uid=$(awk "/^Uid:/ {print \$2, \$3, \$4, \$5}" "/proc/$pid/status")
    [ "$uid" = "10001 10001 10001 10001" ] \
      || { echo "进程 $1 的 UID 不是 10001: $uid" >&2; exit 1; }
    echo "进程 $1 Uid: $uid"
  ' sh "$2"
}

check_uid hub rustboard-hub
check_uid panel rustboard-panel
check_uid agent rustboard-agent

# 或从宿主查看容器内全部进程（tini 为 root，rustboard-* 必须是 10001）
docker top rustboard-hub-1 -o pid,uid,gid,cmd
```

应看到服务进程的 `Uid: 10001 10001 10001 10001`（real/effective/saved/fs 四列），
而不是 PID 1（tini）的 root；缺少唯一 `run` 进程或 UID 不符都会非零退出。agent
的 healthcheck 会短暂执行 `cert-info`，上面的过滤只接受 `run`，不会误报。
以上检查依赖容器内的 `pidof`（Debian 基础层的 `sysvinit-utils`）；若自定义镜像
裁掉了它，改用 `docker top` 或遍历 `/proc/*/comm` 人工确认。
`docker inspect ... .Config.User` 为空/root 是正常的，
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
如果配置存在且属主已经是 10001，则跳过 chown。需要对**已初始化** volume 重跑
`install --force` 时，不能只做这一步；按 §5.3 做受控属主切换并在安装后恢复。

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

### 5.3 已初始化 volume 的受控重配置（保留数据）

已初始化的 volume 归 `10001:10001` 所有；`rustboard-hub install` 又必须以 root
运行，并会检查 prefix、`data_dir` 和 `install-state.toml` 的属主。因此直接执行：

```bash
# 错误：会被 prefix / data_dir 校验拒绝
docker compose -f docker/compose.example.yml run --rm hub \
  rustboard-hub install --force --no-systemd --prefix /data ...
```

会得到 `安装前缀组件 /data 属主 uid=10001（当前 euid=0）` 或
`data_dir … 属于其他用户`。**不要**删除 volume、不要把 `/data` 改成 0777，也不要
放宽 `validate_install_prefix`。正确流程是临时、受控地切换属主，安装后立即恢复：

```bash
# 0) 先停服。不要对运行中的 SQLite volume 直接 tar（WAL 可能不一致）；
#    停服前顺手记录验收基线（tls status 与 hub.toml）
docker compose -f docker/compose.example.yml \
  exec --user 10001:10001 hub \
  rustboard-hub tls status --config /data/etc/rustboard/hub.toml \
  > /tmp/rb-tls-before.txt
docker compose -f docker/compose.example.yml \
  cp hub:/data/etc/rustboard/hub.toml /tmp/rb-hub-before.toml
docker compose -f docker/compose.example.yml stop panel hub

# 1) 停服后备份（含私钥/admin token；放仓库外并按 secret 保管）。
#    tar 会带上 rustboard.db、-wal、-shm；在线一致性快照请用
#    `rustboard-hub backup`（VACUUM INTO + quick_check），不要用 tar。
BACKUP_DIR=${RUSTBOARD_BACKUP_DIR:-$HOME/rustboard-backups}
install -d -m 0700 "$BACKUP_DIR"
docker compose -f docker/compose.example.yml run --rm --no-deps \
  -v "$BACKUP_DIR:/backup" --entrypoint /bin/sh hub \
  -c 'umask 077; tar -C /data -czf /backup/hub-data-$(date +%Y%m%dT%H%M%S).tgz .'

# 2) 只把安装必需路径切到 root。先拒绝符号链接/子挂载，再用 -xdev + chown -h，
#    避免 root chown 跟随链接或跨文件系统改到宿主/其它卷的属主。
#    第 2 步不碰 /data/etc 与 /data/usr；后面的 install 才会按参数重写它们。
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

# 3) 以 root 执行安装器。非 TTY 必须 --yes，否则会在确认处失败
docker compose -f docker/compose.example.yml run --rm hub \
  rustboard-hub install --yes --force --no-systemd --prefix /data \
    --listen 0.0.0.0:8443 --admin-listen 127.0.0.1:8444 --panel no \
    --tls self-signed

# 4) 无论第 3 步成功还是失败，都恢复 10001；同样先拒绝符号链接/子挂载，
#    再 -xdev + chown -h，最后断言没有残留非 10001 属主
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

# 5) 启动。若配置是 ACME，必须继续带 ACME 叠加文件，否则 80/443 不发布，
#    自动续期会失败
docker compose -f docker/compose.example.yml up -d
```

切换到 ACME 时，把第 3 步换成（**必须带 `--service-ports`**，让挑战端口从
公网可达）：

```bash
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml \
  run --rm --service-ports hub \
  rustboard-hub install --yes --force --no-systemd --prefix /data \
    --listen 0.0.0.0:8443 --admin-listen 127.0.0.1:8444 --panel no \
    --tls acme-domain --advertise board.example.com \
    --acme-email admin@example.com \
    --domain board.example.com --acme-challenge http-01
```

第 5 步也改为带 `-f docker/compose.acme.example.yml up -d`。私有/Pebble ACME
还需要 `--acme-directory`、`--acme-ca` 和只读 CA 挂载，见 §13 与
[acme.md](../docs/install/acme.md)；安装参数必须与最终要运行的配置一致。

失败处理：

- 第 0/1 步失败：服务已停止，修复后重新执行；不要用运行中 volume 的 tar 覆盖
  已停服备份。
- 第 2/4 步失败：脚本在 chown 前先拒绝符号链接/子挂载，不会跟随链接改宿主；
  若 chown 中途失败（磁盘/只读挂载等），重跑第 4 步。仍失败时保留报错与
  volume 现场，不要删除 volume。
- 第 3 步失败或 shell 中断后，**先单独重跑第 4 步**恢复属主，再排查；不要用
  `--user 10001` 启动“修复”（root entrypoint 启动会自动修复属主，但不会回滚
  配置）。
- **`backup_dir` 语义**：成功安装会 `txn.commit()` 并删除临时事务备份，不要
  去 `/data/var/lib/rustboard/backups/hub-*` 找“成功安装的 backup_dir”。只有
  **回滚未完成**时安装器才打印并保留 `txn backup_dir`（旧 config/unit/binary/
  state），此时从该目录人工恢复，恢复后再次执行第 4 步。回滚成功时也会打印
  “临时安装备份已清理”。
- **证书备份**不在 txn backup_dir：自签/ACME 在成对替换
  `certs/server.crt|server.key` 前会写 `server.crt.bak-*` / `server.key.bak-*`
  （ACME 派生 `agent-ca.pem` 的回滚由安装器 guard 负责）。成功或失败都可能
  保留这些 `.bak` 文件；需要回滚服务端证书时按 `.bak` 手工恢复并再次执行
  第 4 步。不要把证书 `.bak` 当成配置备份。

#### 恢复验收（可执行断言）

先按 §5 定义 `check_uid`，再执行：

```bash
check_uid hub rustboard-hub

# 1) tls status：纯属主修复/重启应与 /tmp/rb-tls-before.txt 一致；
#    TLS 模式切换允许不同，但必须确认模式/域名/SAN 符合预期。
docker compose -f docker/compose.example.yml \
  exec --user 10001:10001 hub \
  rustboard-hub tls status --config /data/etc/rustboard/hub.toml \
  > /tmp/rb-tls-after.txt
diff -u /tmp/rb-tls-before.txt /tmp/rb-tls-after.txt || true
grep -E '证书来源|证书名字|SAN' /tmp/rb-tls-after.txt
# 以下仅用于切到 ACME；self-signed 重配请改断言 self-signed。
grep -q '证书来源: acme-domain' /tmp/rb-tls-after.txt

# 2) hub.toml hash：纯属主/重启必须相同；TLS 模式切换会变，以 tls status 为准
docker compose -f docker/compose.example.yml \
  cp hub:/data/etc/rustboard/hub.toml /tmp/rb-hub-after.toml
sha256sum /tmp/rb-hub-before.toml /tmp/rb-hub-after.toml

# 3) 服务端 cert/key 必须配对（宿主机需 openssl；临时私钥检查后删除）
docker compose -f docker/compose.example.yml \
  cp hub:/data/var/lib/rustboard/hub/certs/server.crt /tmp/rb-server.crt
docker compose -f docker/compose.example.yml \
  cp hub:/data/var/lib/rustboard/hub/certs/server.key /tmp/rb-server.key
chmod 0600 /tmp/rb-server.key
cert_pub=$(openssl x509 -in /tmp/rb-server.crt -pubkey -noout \
  | openssl pkey -pubin -outform der | sha256sum | awk '{print $1}')
key_pub=$(openssl pkey -in /tmp/rb-server.key -pubout -outform der \
  | sha256sum | awk '{print $1}')
[ "$cert_pub" = "$key_pub" ] && echo "cert/key 配对"
rm -f /tmp/rb-server.crt /tmp/rb-server.key

# 4) SQLite 一致快照 + quick_check + 计数（在线 VACUUM INTO；备份含敏感材料）
docker compose -f docker/compose.example.yml \
  exec --user 10001:10001 hub \
  rustboard-hub backup --config /data/etc/rustboard/hub.toml \
    --out /data/var/lib/rustboard/backups --yes
SNAP=$(docker compose -f docker/compose.example.yml \
  exec --user 10001:10001 hub sh -c \
  'ls -1dt /data/var/lib/rustboard/backups/*/ | head -1')
docker compose -f docker/compose.example.yml \
  cp "hub:${SNAP}rustboard.db" /tmp/rb-db-check.db
python3 - <<'PY'
import sqlite3
con = sqlite3.connect('/tmp/rb-db-check.db')
assert con.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
for table in ('agents', 'samples', 'ingest_batches', 'alert_rules'):
    print(table, con.execute(f'SELECT count(*) FROM {table}').fetchone()[0])
assert con.execute('SELECT count(*) FROM agents').fetchone()[0] >= 1
PY
rm -f /tmp/rb-db-check.db
```

`agents` 数量至少 1（hub-self）；samples/ingest_batches 与停服前备份对比不得
下降。验收完成后可删除 `backups/` 下本次在线快照（含私钥），或按 secret 保管。

可复现的本机双 CA/真实 volume 脚本：

```bash
bash tests/e2e/v100-docker-tls-volume.sh
# 复用已运行的 Pebble：PEBBLE_REUSE=rb-pebble bash tests/e2e/v100-docker-tls-volume.sh
```

脚本使用本地 `HUB_IMAGE`/`AGENT_IMAGE`（默认 local-s4），不 pull 镜像，不进入 CI；
证据写到 `target/docker-tls-volume-e2e/<UTC>-<PID>/`。

> agent volume 也是 10001。已有 agent 需要 `install --force` 时按同样的
> 停服 → scoped chown → install → 恢复 10001 流程；但 entrypoint 的
> `RUSTBOARD_TLS_MODE` 只在首次初始化时生效，已有 `agent.toml` 不会被环境变量
> 改写。从 `custom-ca` 改到其他模式时安装器不会自动清空旧 `server_ca`，需先
> 备份并处理该字段，或新建 volume 重新 enrollment。

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
# self-signed hub：fingerprint（默认，兼容旧部署）
docker run -d --name rb-agent \
  -v rb-agent-data:/data \
  -v /secure/path/enroll.token:/run/rustboard/enroll_token:ro \
  -e RUSTBOARD_HUB_URL=wss://hub.example.com:8443/agent/ws \
  -e RUSTBOARD_TOKEN_FILE=/run/rustboard/enroll_token \
  -e RUSTBOARD_TLS_MODE=fingerprint \
  -e RUSTBOARD_FINGERPRINT=REPLACE_WITH_64_HEX_FINGERPRINT \
  -e RUSTBOARD_NAME=agent-01 \
  ghcr.io/pazzifirst/rustboard-agent:v1.0.0

# 公共 ACME hub：系统根 + 主机名校验；不要设置 RUSTBOARD_FINGERPRINT
docker run -d --name rb-agent \
  -v rb-agent-data:/data \
  -v /secure/path/enroll.token:/run/rustboard/enroll_token:ro \
  -e RUSTBOARD_HUB_URL=wss://board.example.com:8443/agent/ws \
  -e RUSTBOARD_TOKEN_FILE=/run/rustboard/enroll_token \
  -e RUSTBOARD_TLS_MODE=system-roots \
  -e RUSTBOARD_NAME=agent-01 \
  ghcr.io/pazzifirst/rustboard-agent:v1.0.0

# 私有 ACME / 私有 CA：custom-ca + 只读挂载服务端 CA
docker run -d --name rb-agent \
  -v rb-agent-data:/data \
  -v /secure/path/enroll.token:/run/rustboard/enroll_token:ro \
  -v /secure/path/agent-ca.pem:/run/rustboard/server-ca.pem:ro \
  -e RUSTBOARD_HUB_URL=wss://board.example.com:8443/agent/ws \
  -e RUSTBOARD_TOKEN_FILE=/run/rustboard/enroll_token \
  -e RUSTBOARD_TLS_MODE=custom-ca \
  -e RUSTBOARD_SERVER_CA=/run/rustboard/server-ca.pem \
  -e RUSTBOARD_NAME=agent-01 \
  ghcr.io/pazzifirst/rustboard-agent:v1.0.0
```

agent 默认非 privileged、不挂 `docker.sock`、控制面关闭，也没有新端口。
信任模式只在**首次初始化**（`/data/etc/rustboard/agent.toml` 不存在）时生效，
之后重启/重连读取配置，不需要重新 enroll；已有 volume 换模式见 §5.3 末尾。
公共 ACME 去掉 `RUSTBOARD_FINGERPRINT` 后使用系统根；私有 ACME 的 CA 只用于
验证 Hub **服务端**证书，不要放客户端 CA 或私钥。

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
- 验证方法同 §5/§8：healthz、读取服务进程 `/proc/<pid>/status` 的 `Uid`
  （见 §5，不要只用 `exec id`）、日志无 permission denied。

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
  需要按 §5.3 受控 `install --force` + `tls issue`，不要只改环境变量（见 §13.4）。
- 回滚：

  ```bash
  RUSTBOARD_VERSION=v1.0.0 \
  docker compose -f docker/compose.example.yml up -d
  ```

  如果新版本已迁移数据库，旧镜像可能无法打开；此时应恢复升级前的 volume 快照，
  而不是只回退镜像。不要通过删除 volume 来“修复”。
- 从 systemd 安装迁移到 Docker 不复用 `/etc/rustboard`、`/var/lib/rustboard`；容器使用
  独立 volume，需要重新初始化（agent 需重新 enrollment 或按文档迁移数据）。
  ACME Hub 的 agent 必须使用 `system-roots` 或 `custom-ca`，v0.4 指纹 agent
  不能直接接入 ACME 证书（见 §13.5）；已有 fingerprint agent 需改信任或重新 enrollment。

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
| `安装前缀组件 /data 属主 uid=10001` | 已初始化 volume 直接 root install；按 §5.3 受控重配置（临时 chown prefix/data/state，安装后恢复 10001），不要删除 volume |
| agent 报 `RUSTBOARD_TLS_MODE 只接受 ...` | agent 只接受 `fingerprint` / `system-roots` / `custom-ca`；不要把 hub 的 `acme-domain`/`self-signed` 传给 agent，见 §13.5 |
| agent 报 `system-roots 模式不接受 RUSTBOARD_FINGERPRINT` | compose 同时带了旧指纹变量；ACME agent 清空 `RUSTBOARD_HUB_FINGERPRINT` / `RUSTBOARD_AGENT_FINGERPRINT` |
| agent 报 `custom-ca 模式必须设置 RUSTBOARD_SERVER_CA` | 未设 `RUSTBOARD_AGENT_SERVER_CA` 或未叠加 `compose.agent-custom-ca.example.yml`，见 §13.5 |
| panel 报缺少 hub 管理 token | hub 未 healthy、`hub_run` 未挂载、或 `RUSTBOARD_ADMIN_TOKEN_SHARE` 未设置 |
| panel 报 token 权限不是 0600 | `chmod 0600 /run/rustboard/admin_token`；不要放宽到 0644 |
| agent healthcheck unhealthy | enrollment token 过期/已用、hub URL 不可达、指纹错误、证书 SAN 不匹配；看 agent 日志并重新 `agent add` |
| agent 提示证书 SAN/主机名不匹配 | 首次未设置 `RUSTBOARD_ADVERTISE`/`RUSTBOARD_SAN`；更新 `hub.toml` 的 `server_names` 后 `rotate-cert --force`，agent 重新 enrollment |
| hub/panel 一直 unhealthy | 覆盖了 8444/8080 但没改 healthcheck；或服务启动失败，先看容器日志。`admin_tls=required` 时必须用 HTTPS healthcheck |
| ACME 容器内 80/443 可 bind、公网不通 | 默认 compose 不发布 80/443；用 ACME 叠加文件/`-p`，再查云安全组；见 §13 |
| 改了 `RUSTBOARD_TLS_MODE` 不生效 | 已有 `hub.toml` / `agent.toml`；entrypoint 只在首次初始化应用。hub 见 §13.4，agent 见 §13.5 |
| `--user 10001` 下 ACME 续期报绑定失败 | 非 root 无 `NET_BIND_SERVICE`；ACME 用默认 root entrypoint |
| `RUSTBOARD_ACME_*` 缺失/非法 | entrypoint 在 install 前退出；按提示补变量，不要加 `--offline` |
| hub 首启日志报连接 PostgreSQL 失败 | 数据库未就绪/密码文件缺失/DSN 错；compose 已用 healthcheck 排序，检查 `RUSTBOARD_PG_PASSWORD_FILE` 与 `RUSTBOARD_DATABASE`；见 §14 |
| `RUSTBOARD_DATABASE_PASSWORD_FILE` 不是普通文件 | secret 未挂载或路径写错；Compose secret 必须存在于宿主且可读，路径是容器内绝对路径 |
| 改了 `RUSTBOARD_DATABASE` 但仍是 SQLite | 已有 `hub.toml`，entrypoint 只在首次初始化应用该变量；按 §14.2 迁移，不要删 volume |
| `--offline` 与 PostgreSQL 互斥 | PG 安装需要联网探测；去掉 `--offline`，或继续用 SQLite |
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

该叠加文件还会把 **agent** 的信任模式设为 `system-roots`（见 §13.5）。私有
ACME / 私有 CA 的 Hub 证书不受公共根信任，需再叠加
`docker/compose.agent-custom-ca.example.yml` 改为 `custom-ca`。

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
- agent 的 `RUSTBOARD_TLS_MODE` / `RUSTBOARD_FINGERPRINT` /
  `RUSTBOARD_SERVER_CA` 是**另一个容器**的变量，不要和 hub 的
  `RUSTBOARD_TLS_MODE` 混用；compose 用 `RUSTBOARD_AGENT_TLS_MODE` 和
  `RUSTBOARD_AGENT_SERVER_CA_FILE` 传入，详见 §13.5。

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

已有 `hub.toml` 时 entrypoint 跳过 install；改环境变量不会切换证书来源。
已初始化 volume 的 `/data` 归 10001，直接以 root 执行安装器会被 prefix /
data_dir 校验拒绝；必须按 §5.3 的**受控重配置**流程：停服 → scoped chown →
`install --yes --force --no-systemd --prefix /data` → 恢复 10001 属主 → 启动。
不要删除 `hub_data` 来“重置证书”（会丢数据库、agent secret 与证书）。

按 §5.3 完成属主切换后，ACME 切换的安装命令是（**必须带 `--service-ports`**，
让挑战从公网可达 80/443）：

```bash
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml run --rm --service-ports hub \
  rustboard-hub install --yes --force --no-systemd --prefix /data \
    --listen 0.0.0.0:8443 --admin-listen 127.0.0.1:8444 --panel no \
    --tls acme-domain --advertise board.example.com \
    --acme-email admin@example.com \
    --domain board.example.com --acme-challenge http-01
```

执行后按 §5.3 第 4 步恢复属主，再带 ACME 叠加文件启动：

```bash
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml up -d
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml \
  exec --user 10001:10001 hub \
  rustboard-hub tls status --config /data/etc/rustboard/hub.toml
```

`tls status` 会校验 `data_dir` 属主；`docker compose exec` 默认以 root 进入，
必须加 `--user 10001:10001`，否则会报 `data_dir 不安全`。

安装器会成对备份旧服务端证书；失败时按 §5.3 恢复属主。只有回滚未完成时
才会保留并打印 txn `backup_dir`；证书 `.bak` 与它不同，不要手工拼配置。

> Docker ACME 的端到端验证需要公网 80/443 或 Pebble 端口映射；本机只做
> compose/脚本静态检查时**不伪造**签发成功。真实 LE staging 仍留手工门禁。

### 13.5 agent 信任模式（ACME / 私有 CA）

Hub 的证书来源和 agent 的**服务端信任模式**是两件事。agent 的
`RUSTBOARD_TLS_MODE`（compose 里用 `RUSTBOARD_AGENT_TLS_MODE` 传入）只接受：

| 模式 | 适用 | 首次安装必填 | 必须为空 |
|---|---|---|---|
| `fingerprint`（默认） | self-signed Hub | `RUSTBOARD_FINGERPRINT` | `RUSTBOARD_SERVER_CA` |
| `system-roots` | 公共 ACME（Let's Encrypt 等） | 无 | `RUSTBOARD_FINGERPRINT` / `RUSTBOARD_SERVER_CA` |
| `custom-ca` | 私有 ACME / 私有 CA | `RUSTBOARD_SERVER_CA` | 无（fingerprint 可留空） |

- 未知模式在任何写盘前失败，不会静默回退到 fingerprint；非 fingerprint 模式
  还必须是 `wss://`（明文 `ws://` 会忽略 CA/主机名校验）。
- 安装器把最终模式写进 `agent.toml`；`custom-ca` 会把 CA 复制到
  `/data/var/lib/rustboard/agent/server-ca.pem`（0644）。重启/重连直接读取配置，
  不需要重新 enrollment。
- 模式只在 `/data/etc/rustboard/agent.toml` **不存在**时生效；已有 agent
  volume 不会因环境变量改写，迁移见 §5.3 末尾。

公共 ACME Hub 用叠加文件启动 agent（`compose.acme.example.yml` 已把 agent
切到 `system-roots` 并清空 fingerprint）：

```bash
RUSTBOARD_HUB_URL=wss://board.example.com:8443/agent/ws \
RUSTBOARD_ENROLL_TOKEN_FILE=/absolute/path/to/enroll.token \
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml --profile agent up -d
```

私有 ACME / 私有 CA 再叠加 custom-ca 文件（必须放在最后，覆盖成
`custom-ca`），CA 源文件用绝对路径：

```bash
# 从运行中的 hub 提取安装器生成的 agent 信任锚（公开证书，不是私钥）
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

- `agent-ca.pem` 是**私有 ACME** 安装器从服务端链尾提取的信任锚；公共 ACME
  用 system-roots，不要拿这个文件。不要放客户端 CA、agent 证书或私钥。
- 不要用 fingerprint 给会轮换的 ACME 证书兜底；轮换后旧指纹会失联。
- `hub agent add` 在 ACME 模式会按证书来源打印 `--tls-mode system-roots` 或
  `--tls-mode custom-ca --server-ca ...`；优先照该输出执行，不要手写指纹命令。
- self-signed Hub 继续用 fingerprint：设置 `RUSTBOARD_HUB_FINGERPRINT`（或
  `RUSTBOARD_AGENT_FINGERPRINT`），不要带 `RUSTBOARD_AGENT_TLS_MODE`。
- Hub 的 `RUSTBOARD_TLS_MODE`（`self-signed` / `acme-*`）与 agent 的模式不是
  同一组取值；不要互相复制。

## 14. PostgreSQL（Phase D，显式 opt-in）

默认 compose **不包含 PostgreSQL**，hub 仍使用 `hub_data` volume 内的 SQLite。
PostgreSQL 只通过专用叠加文件启用，且**不是默认行为**：

```bash
install -d -m 0700 docker/secrets
openssl rand -base64 32 > docker/secrets/postgres_password
chmod 0600 docker/secrets/postgres_password

RUSTBOARD_VERSION=v1.0.0 \
docker compose -f docker/compose.example.yml \
  -f docker/compose.postgres.example.yml up -d
```

叠加文件增加 `postgres:16-alpine`（与 CI/文档的 PG16 备份客户端对齐；17 需自行
同步 client 版本）、`postgres_data` volume，并给 hub 注入数据库环境变量。
**5432 不发布**，只在 compose 默认网络内可达。完整的安装/权限/备份说明见
[PostgreSQL 安装文档](../docs/install/postgres.md)。

### 14.1 数据库环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `RUSTBOARD_DATABASE` | 空（SQLite） | `postgres://` / `postgresql://` DSN；**只在首次初始化**（hub.toml 不存在）时映射为 `--db`；已有 volume 不会改写配置 |
| `RUSTBOARD_DATABASE_SSLROOTCERT` | 空 | 容器内绝对路径的 PEM 根 CA，映射 `--db-sslrootcert`；必须与 `RUSTBOARD_DATABASE` 同时设置 |
| `RUSTBOARD_DATABASE_PASSWORD` | 空 | 数据库密码；优先级高于 DSN 内密码；由 install / run 继承 |
| `RUSTBOARD_DATABASE_PASSWORD_FILE` | 空 | entrypoint 读取该文件并导出为 `RUSTBOARD_DATABASE_PASSWORD`；适合 Docker secret；不能与直接设置密码同时使用 |

- entrypoint **不打印** DSN 或密码，日志只说“PostgreSQL（连接串与密码不打印）”；
  若 DSN 的 URL 里带密码会额外警告（它会出现在进程参数/容器元数据中），建议
  使用无密码 DSN + `RUSTBOARD_DATABASE_PASSWORD(_FILE)`。
- 设置 `RUSTBOARD_DATABASE` 后，entrypoint **不会**再追加 `--offline`（PG 探测
  需要联网）；SQLite 默认路径的 `--offline` 行为不变。
- 安装器只做 schema（幂等，advisory lock）与 `ping`，**不会**建库/建角色。
  示例中的库/角色由 postgres 镜像首次初始化时按 `POSTGRES_DB`/`POSTGRES_USER`
  创建；非容器部署要手工 `CREATE ROLE` / `CREATE DATABASE`。
- 示例用 `sslmode=disable`（stock 镜像无 TLS），只适合本机/受信内网。生产请给
  PostgreSQL 配证书，把 DSN 改成 `?sslmode=verify-full`，并用
  `RUSTBOARD_DATABASE_SSLROOTCERT` 只读挂载私有 CA。不要用 `require`/`prefer`。
- **只设密码、不设 `RUSTBOARD_DATABASE` 时**：全新 volume 会直接失败（拒绝静默
  初始化 SQLite）；已初始化 volume 仅当 `hub.toml` 的 `database` 已是
  `postgres://` 时允许（密码用于运行时连接），否则同样失败。不要只挂密码
  secret 就启动一个空 volume。

### 14.2 已有 volume / 迁移

`RUSTBOARD_DATABASE` 只在 hub 首次初始化时生效。已有 `/data/etc/rustboard/hub.toml`
的 volume 改环境变量**不会**切换数据库；entrypoint 会跳过 install 并打印提示。

切换/迁移固定顺序（详见 [postgres.md](../docs/install/postgres.md)）：

1. **停 hub**（`docker compose ... stop hub panel`）并备份：`hub_data` +
   PostgreSQL 逻辑备份；
2. 在宿主用 release 二进制执行
   `rustboard-hub backup --config <hub.toml> --out /var/lib/rustboard/backups --yes`
   （PG 备份需要宿主 `pg_dump`），或手工 `pg_dump --format=custom`；
3. 在 hub 停止后，用 release 二进制执行
   `rustboard-hub migrate --config <hub.toml> --to 'postgres://...' --dry-run`
   预检，再 `--yes` 迁移；非空 PG 目标见下方限制；
4. 改 `hub.toml` 的 `database`（和 `db_sslrootcert`）后 `up -d`；
5. 验证 `/healthz`、agent、面板与告警；保留 SQLite 与备份，观察后再清理。

回滚：把 `database` 改回 SQLite 路径并重启；SQLite 文件全程不动。
**迁移前必须停 hub**，不要在运行中直接复制 PG 数据目录。

### 14.3 非 root 与备份工具

- `docker run --user 10001:10001` / Compose `user:` 只在**已初始化** volume 上
  支持：entrypoint 跳过 install，因此 `RUSTBOARD_DATABASE` 不会生效（不会改写
  `hub.toml`）；配置必须已经是 PostgreSQL。数据库密码环境变量仍会传给 hub run。
- hub 镜像基于 `debian:bookworm-slim`，**不含** `pg_dump`/`pg_restore`。备份请在
  宿主执行，或临时用 `postgres:16` 容器；不要为了备份给 hub 镜像加包。
- `pg_dump` 的一致性快照适合日常备份；迁移/切换场景仍要求先停 hub。
  `postgres_data` 是 PG 自己管理的目录，运行中直接复制不保证一致。
- 客户端主版本最好与 PG 服务端一致（PG16 client 对 PG16 验证通过；PG17 client
  对 PG16 会因 `transaction_timeout` 失败）。
- 备份文件含 agent secret 与 token 哈希，按 secret 管理（0600/0700）。
- **单 hub 限制**：PG 后端没有 leader 选举；同一数据库只允许一个 active hub，
  多个 hub 会重复告警/归档。需要多活时当前版本不支持，见
  [postgres.md](../docs/install/postgres.md) §9。
- **`migrate --force` 限制**：清空非空 PG 目标目前只支持 `sslmode=disable`；
  `verify-full` 目标需先手工备份并 `TRUNCATE` 21 张业务表，再不带 `--force`
  迁移。
- **恢复属主**：root 执行 `restore` 后文件属主是 root；`--user 10001:10001`
  启动前需用 `find /data -xdev -exec chown -h 10001:10001 {} +` 恢复（不要用
  会跟随链接的递归 chown），或以该用户运行恢复。

### 14.4 验证

```bash
# 1) 数据库已就绪（不打印密码）
docker compose -f docker/compose.example.yml \
  -f docker/compose.postgres.example.yml exec postgres \
  pg_isready -U rustboard -d rustboard

# 2) hub 初始化日志应包含“数据库: PostgreSQL（连接串与密码不打印）”
docker compose -f docker/compose.example.yml \
  -f docker/compose.postgres.example.yml logs hub | grep -E '数据库|apply_schema|安装完成'

# 3) schema 表存在（21 张业务表 + schema_migrations）
docker compose -f docker/compose.example.yml \
  -f docker/compose.postgres.example.yml exec postgres \
  psql -U rustboard -d rustboard -c '\dt'
```

排障时不要 `cat` 完整 `hub.toml`、不要 `docker inspect` 全量环境变量。

## 15. 相关文档

- [M5 Phase B 交付计划](../docs/plans/2026-10-25-m5-phase-b-delivery.md)
- [M5 Phase A 安装器计划](../docs/plans/2026-10-24-m5-phase-a-installer.md)
- [服务端 TLS](../docs/install/tls.md) / [ACME](../docs/install/acme.md) /
  [面板 TLS](../docs/install/panel-tls.md) / [故障排查](../docs/install/troubleshooting.md)
- [AGENTS.md](../AGENTS.md) §6/§9
- 构建脚本：`packaging/build-release.sh`（由 Phase B 构建流水线提供）
