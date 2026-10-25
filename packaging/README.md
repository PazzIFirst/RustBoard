# RustBoard 离线发布包

本目录是 M5 Phase B 的离线交付物：静态 musl 二进制、可选的 systemd unit 参考文件、
前端静态资源，以及一个负责包校验、web 原子安装/回滚并调用 Phase A 安装器的引导脚本 `install.sh`。

目标平台：`linux/amd64`（包名 `x86_64`）与 `linux/arm64`（包名 `aarch64`）。
协议、SQLite schema 与配置字段与 Phase A 一致；本包不改变运行时行为。

## 1. 包布局

```text
serverdashboard-v<version>-<x86_64|aarch64>/
├── bin/rustboard-hub
├── bin/rustboard-panel
├── bin/rustboard-agent
├── share/rustboard/web/          # 前端构建产物（index.html + assets）
├── systemd/rustboard-{hub,panel,agent}.service
├── install.sh                    # 0755
├── SHA256SUMS                    # 包内逐文件校验和
├── VERSION                       # 仅一行 <version>
├── LICENSE
└── README.md
```

发布目录（默认 `dist/`）：

```text
dist/<amd64|arm64>/bin/rustboard-{hub,panel,agent}   # 静态构建产物
dist/serverdashboard-v<version>-<x86_64|aarch64>/    # 解包后的包根
dist/serverdashboard-v<version>-<x86_64|aarch64>.tar.gz
dist/SHA256SUMS.<x86_64|aarch64>                     # 只包含对应架构 tarball
```

tarball 使用固定 `mtime`、owner/group、numeric-owner、`--sort=name` 和 `gzip -n`
生成；`SOURCE_DATE_EPOCH` 默认取 HEAD 提交时间，可由环境变量覆盖。

## 2. 校验

发布目录里先校验 tarball，再校验包内文件：

```bash
sha256sum -c SHA256SUMS.x86_64
tar -xzf serverdashboard-v<version>-x86_64.tar.gz
cd serverdashboard-v<version>-x86_64
sha256sum -c --strict SHA256SUMS
```

`install.sh` 自己也会先执行 `sha256sum -c --strict SHA256SUMS`；清单路径集合必须与
包内普通文件集合精确相等（排除 `SHA256SUMS` 自身），未列出、重复、symlink/FIFO/
device 都会在写文件之前被拒绝。

## 3. 安装

要求 root（Phase A 安装器写配置、证书与 systemd unit）。默认 prefix 是 `/`：

```bash
sudo ./install.sh hub --yes
sudo ./install.sh panel --yes
sudo ./install.sh agent --yes \
  --hub wss://<hub-host>:8443/agent/ws \
  --token-file /root/rustboard-agent.token \
  --fingerprint SHA256:<64-hex>
```

测试或容器可用独立 prefix：

```bash
sudo ./install.sh hub --yes --prefix /opt/rustboard-v100-test --no-systemd --panel no
```

**prefix 安全要求**：必须是绝对路径、无 `.` / `..` 组件，且不得包含 Phase A
禁用的 `$`、`%`、`"`、`'`、`\`、反引号或控制字符；从 `/` 到 prefix 的每个已存在
组件必须 root 所有、不是符号链接、group/other 不可写，且不能带 sticky。目标不存在
时检查最近一个存在的祖先。因此不要用 `/tmp`（通常 `1777`）作为测试 prefix；用
`/opt` 下的新目录。该检查在写 web 之前完成，Rust 安装器内部还会做一次完整校验。

### Web 静态资源

hub / panel 会把包内 `share/rustboard/web` 原子安装到：

```text
<prefix>/usr/share/rustboard/web          # prefix=/ 时即 /usr/share/rustboard/web
```

成功后自动追加 `--panel-static-dir`（hub）或 `--static-dir`（panel）；如果你显式
传了同名参数，脚本不会覆盖。已有 web 目录是符号链接或路径组件不安全时直接拒绝。
`--dry-run` 不写 web；目标目录尚不存在时也不会追加静态目录参数，避免 dry-run
因“显式指定不存在的目录”失败。

### systemd 默认行为

- 默认 prefix `/` 且系统有 systemd 时，Phase A 安装器会写 unit 并 `enable --now`；
  `/healthz` 通过后才记录安装状态。
- `--no-systemd` 只写配置/二进制/状态，不写 unit、不调用 `systemctl`，用于测试、
  容器或用户自行托管服务。
- 包内 `systemd/*.service` 是生产默认路径参考；实际 unit 由安装器按 prefix 渲染。
- 服务日志：`journalctl -u rustboard-<role>`。

### 离线语义

`install.sh` 默认追加 `--offline`（幂等，不覆盖显式参数）。它只表示**不发起外部
网络探测**；本地端口 bind、loopback `/healthz` 检查、systemd 操作仍会发生。安装
本身不需要外网，包内已包含二进制、前端和 unit。

离线安装示例：

```bash
sudo ./install.sh hub --offline --yes --prefix /opt/rustboard-v100-offline
# 或者不写 --offline，脚本会自动追加
sudo ./install.sh hub --yes --prefix /opt/rustboard-v100-offline
```

### secret 参数

`install.sh` 禁止明文 secret argv：`--token`、`--password`、`--admin-token`、
`--hub-token` 等一律拒绝。只接受 0600 文件：

- agent：`--token-file`
- panel：`--hub-token-file`、`--password-file`

错误信息、复现命令和日志会过滤常见 token/password/URL query 形态，但模式化脱敏
不是安全边界；不要把 secret 放进 `--prefix`、`--listen` 等非 secret 参数。

### 失败与复现

失败时脚本会打印只读复现命令（自动加 `--dry-run`）和日志位置；例如：

```bash
sudo ./install.sh hub --prefix /opt/rustboard-v100-test --yes --dry-run
```

`--dry-run` 零写入、不调用 systemctl；它用于确认参数和计划，不代表包外其他步骤
（解压、下载）也被执行。

## 4. 升级与回滚

升级：

1. 下载新版本 tarball，先校验 `SHA256SUMS.<arch>` 与包内 `SHA256SUMS`；
2. 备份 `/etc/rustboard` 与 `/var/lib/rustboard`（Phase A 也会做安装事务备份，
   但手工备份便于整体回滚）；
3. 执行 `sudo ./install.sh <role> --yes --force`。systemd 模式下由安装器更新
   unit、重启服务并做 `/healthz` 检查；`--no-systemd` 模式需自行重启服务；
4. 用 `journalctl -u rustboard-<role>` 与 `/healthz` 验证。

回滚：保留旧版本 tarball 与安装前备份，重新解包旧版本并执行
`install.sh <role> --yes --force`。安装失败时 Phase A 安装器按事务逆序回滚，不会
删除安装前已有的数据目录；手工恢复前先停止服务并确认备份路径。已发布 tag 不移
动，缺陷用新 patch 版本修复。

## 5. 构建（维护者）

前置：

- Docker + buildx；arm64 需要 binfmt/QEMU 或 arm64 builder；
- GNU tar、`file`、`readelf`、`sha256sum`、`git`；
- 前端先构建：`pnpm -C web build`（产物默认 `web/dist`，必须含 `index.html`）。

常用命令：

```bash
# 两架构（默认 all），输出到 dist/
packaging/build-release.sh

# 单架构；CI 建议按架构分别调用
packaging/build-release.sh --arch amd64
packaging/build-release.sh --arch arm64

# 版本必须与根 Cargo.toml 的 [workspace.package].version 一致，否则失败
packaging/build-release.sh --arch amd64 --version 0.4.2

# 复用已有的 dist/<arch>/bin，不调用 Docker
packaging/build-release.sh --arch arm64 --skip-build

# 自定义前端产物 / 输出目录 / 修订号
packaging/build-release.sh --web-dir web/dist --out /opt/rustboard-release \
  --revision <12-hex>
```

`--out` 只允许仓库内（但拒绝 `.git`）、`/tmp`、`/opt`；其他路径（包括 `/usr`、
`/var`、`/etc`、`/root`、`/home`、`/srv`、`/mnt`）一律拒绝。脚本先 `realpath`
再判断，避免通过符号链接绕过。

构建脚本对每个目标架构执行：

```bash
docker buildx build \
  --platform linux/<amd64|arm64> \
  --target export \
  --output type=local,dest=dist/<amd64|arm64> \
  -f docker/Dockerfile.build .
```

`SOURCE_DATE_EPOCH` 默认取 HEAD 提交时间；需要完全可复现的 tar 时显式设置：

```bash
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) packaging/build-release.sh
```

构建后校验：

- 三个二进制必须是 static / static-pie ELF，且 `readelf -l` 无 `INTERP`；
- 本机架构直接执行 `--version`；arm64 在 x86_64 主机上若有
  `qemu-aarch64-static`，用 qemu 执行；没有 qemu 时只做静态校验，并在输出中明确
  标注“未执行 --version”，不会伪装成运行通过；
- `--version` 输出的最后一个 token 必须精确等于包版本；
- `--skip-build` 还会通过 `.comment` 断言二进制来自 Alpine/musl 构建，拒绝 glibc
  或 stale 产物。

## 6. 静态构建结论（B1 spike）

最终采用 **buildx 原生构建**，不使用 `cross`、`cargo-zigbuild` 或手工拼接的交叉
工具链：

- 固定构建镜像：`rust:1.89-alpine@sha256:4b800f2e72e04be908e5f634c504c741bd943b763d1d8ad7b096cc340e1b5b46`；
- 镜像内 `apk add --no-cache musl-dev perl make file`（`readelf` 已随基础镜像提供）；
- 每个架构用 `docker buildx build --platform linux/<arch>` 在目标平台容器里 native
  编译，`CARGO_INCREMENTAL=0`，`cargo build --locked --release -p rustboard-hub
  -p rustboard-panel -p rustboard-agent`；
- x86_64 已验证 `file` 显示 `static-pie linked`，Debian 上 `ldd` 显示
  `statically linked`，`--version` 正常；
- 最终导出阶段是 `FROM scratch AS export`，只包含
  `/bin/rustboard-{hub,panel,agent}`，不含 target/、.git、配置、token 或私钥。

## 7. 安全说明

- 发布物只来自 tag 对应的提交；版本必须等于 Cargo.toml；离线包/校验和可用
  `sha256sum` 复核；
- `install.sh` 的顺序固定为：校验和/清单集合 → ELF 架构 → `--version` → prefix
  安全 →（hub/panel）获取 Phase A 全局锁 → 写 web → 以子进程运行
  `bin/rustboard-<role> install`；hub/panel 的 child 继承
  `RUSTBOARD_INSTALL_LOCK_HELD=1`，锁持有到 child 退出；agent 不写 web，wrapper
  不加锁、不设置继承标记，由 Phase A 自己加锁；Phase A 非零退出时恢复旧 web
  并返回同一退出码；校验和失败零写入；
- 架构检查读 ELF 头，不依赖“运行失败”判断；即使宿主启用了 binfmt，也不会把
  另一架构的包安装到本机；
- web 使用同目录 staging + `mv -T` 原子替换；Phase A 失败时由 EXIT trap 恢复旧
  目录，只在 Phase A 成功后才删除备份；child stderr 写入 0600 临时文件，脱敏后
  再输出，stdout 保持透传（panel 初始密码仍可见）；
- `install.sh` 不回显、不落盘 secret；panel 初始密码由 Phase A 安装器按设计仅
  在安装成功时打印一次。脚本自身不写 `/etc`、`/var/lib/rustboard`、`/usr/local`
  （这些路径只由目标二进制按 prefix 自行管理）；
- `--offline` 不发起外部网络探测，但本地 bind / loopback / systemd 仍会发生。

## 8. Docker 说明

离线包**不包含**容器镜像，也不承诺 Docker 安装方式。容器交付、compose 示例与
多架构镜像验证见仓库的 `docker/README.md`（Phase B 独立交付）。
