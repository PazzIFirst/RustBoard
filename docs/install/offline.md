# 离线安装（M5 Phase B）

离线包面向不能访问外网、也不允许安装器做任何外部网络探测的服务器。包内已经包含
hub / panel / agent 三个静态 musl 二进制、前端静态资源、systemd unit 参考文件和
`install.sh`；安装时不需要下载依赖。

> 当前版本按 `Cargo.toml` 为 `0.4.2`，Phase B 产物用 `v0.4.2` 验证；正式
> `v1.0.0` 发布在 Phase E 完成版本归档后触发。包布局与命令不随版本变化。
>
> 构建/维护说明见 [packaging/README.md](../../packaging/README.md)；Docker 交付见
> [docker.md](docker.md)。

## 1. 产物与校验

```text
serverdashboard-v<version>-x86_64.tar.gz
serverdashboard-v<version>-aarch64.tar.gz
SHA256SUMS.<x86_64|aarch64>
```

每个 tarball 解包后的顶层目录包含：

```text
serverdashboard-v<version>-<arch>/
├── bin/rustboard-{hub,panel,agent}
├── share/rustboard/web/
├── systemd/rustboard-{hub,panel,agent}.service
├── install.sh
├── SHA256SUMS
├── VERSION
├── LICENSE
└── README.md
```

先校验 tarball，再校验包内文件：

```bash
sha256sum -c SHA256SUMS.x86_64
tar -xzf serverdashboard-v0.4.2-x86_64.tar.gz
cd serverdashboard-v0.4.2-x86_64
sha256sum -c --strict SHA256SUMS
```

`install.sh` 会再次执行包内校验；校验和失败时不会写任何文件。

注意：包内 `SHA256SUMS` 只防传输损坏/单文件替换，不是签名；能同时改写 web
与清单的人仍可伪造。正式发布请先校验外层 `SHA256SUMS.<arch>` 和 GitHub
attestation，再解包安装。

正式 GitHub Release 资产还提供 artifact attestation；本地/未发布包没有 attestation，只能用 SHA256 校验：

```bash
gh attestation verify serverdashboard-v1.0.0-x86_64.tar.gz \
  --repo PazzIFirst/RustBoard
```

## 2. 静态与架构检查

```bash
file bin/rustboard-hub
# 期望 static-pie linked 或 statically linked
ldd bin/rustboard-hub
# 期望 statically linked / not a dynamic executable
./bin/rustboard-hub --version
```

`install.sh` 会读取 ELF 头中的 `e_machine` 拒绝异架构包；即使宿主机启用了
binfmt_misc，也不会把 aarch64 包安装到 x86_64 主机。arm64 包应在 arm64 主机上
安装；x86_64 上只做 qemu 运行验收时，使用二进制直接运行（见
[Phase B 计划](../plans/2026-10-25-m5-phase-b-delivery.md) B-G4）。

## 3. 安装

前置命令：`sha256sum`、GNU coreutils（`mv -T`）、`flock`（util-linux）。
最小系统缺少 `flock` 或 BusyBox `mv` 不支持 `-T` 时，hub/panel 会在写 web 前失败。

要求 root。默认 prefix 为 `/`，会写 `/etc/rustboard`、`/var/lib/rustboard`、
`/usr/local/bin` 和 systemd unit：

```bash
sudo ./install.sh hub --yes
sudo ./install.sh panel --yes
sudo ./install.sh agent --yes \
  --hub wss://<hub-host>:8443/agent/ws \
  --token-file /root/rustboard-agent.token \
  --fingerprint SHA256:<64-hex>
```

`install.sh` 会自动追加 `--offline`，并调用对应二进制的 Phase A 安装器；配置、
证书、事务回滚、systemd 与健康检查逻辑全部复用 Phase A，不在脚本里重写。

常用参数：

| 参数 | 用途 |
|---|---|
| `--yes` | 非交互 |
| `--prefix DIR` | 测试/容器 prefix；必须是 root 所有、无符号链接、group/other 不可写 |
| `--no-systemd` | 只写文件，不写 unit、不调用 systemctl（测试/自托管） |
| `--dry-run` | 只打印计划，零写入 |
| `--panel no` | hub 不同机安装 panel |
| `--token-file F` | agent enrollment token（0600） |
| `--hub-token-file F` | panel 读取的 hub 管理 token（0600） |
| `--password-file F` | panel 初始管理员密码（0600） |

`--token`、`--password`、`--admin-token`、`--hub-token` 等明文 argv 一律拒绝。

### 测试/容器 prefix

```bash
sudo ./install.sh hub --yes --no-systemd --panel no \
  --prefix /opt/rustboard-test \
  --listen 127.0.0.1:28443 --admin-listen 127.0.0.1:28444
```

不要用 `/tmp` 作为 prefix（通常是 `1777`，安装器会拒绝）；用 `/opt` 下新建目录。
`install.sh` 会把 web 安装到 `<prefix>/usr/share/rustboard/web`，并自动给 hub 追加
`--panel-static-dir`、给 panel 追加 `--static-dir`。

### 同机 panel

包内 `install.sh hub --yes` 默认会尝试安装同机 panel（Phase A 默认 `--panel yes`）；
需要 panel 二进制在同一个 `bin/` 目录。只用 hub 时加 `--panel no`。单独安装 panel：

```bash
sudo ./install.sh panel --yes \
  --hub-token-file /root/rustboard-hub-admin.token
```

panel 默认从同 prefix 的 `hub.toml` 读取 token；跨 prefix 时必须显式传
`--hub-token-file`。

## 4. 离线语义

`--offline` 只表示**安装器不发起外部网络探测**，不是“禁用本机网络”：

- 允许本地端口 bind、loopback `/healthz`、systemd 操作；
- 不允许外部 DNS/HTTP/HTTPS 探测；
- `tests/e2e/v100-offline.sh` 在 `unshare -n` 中运行安装与 hub/panel/agent 启动，并用
  `strace -f -e trace=connect` 断言连接只指向 Unix socket / `127.0.0.1` / `::1`。
  DNS 的外部 `connect` 也会被拒绝；测试不把 `sendto/sendmsg` 当作外部探测，
  真实无网验收仍应结合 netns 路由断言。

真正无网环境建议先在测试机校验 tarball 与包内 `SHA256SUMS`，再拷贝到目标机。

## 5. systemd、升级与回滚

- 默认 root prefix 且系统有 systemd 时，安装器写 unit、`enable --now`，通过
  `/healthz` 后才写安装状态。
- `--no-systemd` 适合容器、测试或用户自行托管；包内 unit 仅作为参考，实际 unit
  由安装器按 prefix 渲染。
- 升级：校验新包 → `sudo ./install.sh <role> --yes --force`。Phase A 事务会备份被
  替换文件，已有 data/config 不删除。
- 回滚：保留旧 tarball 与安装前备份，重新解包旧版本并执行 `--force`。如果数据库
  已被新版本迁移，优先恢复升级前的数据快照，不要只回退二进制。
- 已发布 tag 不移动；缺陷用新 patch 版本修复。

## 6. 故障排查

| 现象 | 处理 |
|---|---|
| `SHA256SUMS 校验失败` | 包损坏或被篡改；重新下载并校验，勿绕过 |
| `安装前缀的路径组件权限不安全` | 换 root 所有的 `/opt/...`；不要用 `/tmp` 或 group/other 可写目录 |
| `未检测到 systemd` | 加 `--no-systemd`，或用 systemd 主机 |
| agent `--token-file` 失败 | 确认文件 0600、普通文件、非符号链接；token 不通过 argv |
| panel 缺 hub token | 用 `--hub-token-file`，或先安装 hub 使其同 prefix 的 `hub.toml` 存在 |
| 面板页面 503 | 包内 `web/` 未安装到 prefix；检查 `share/rustboard/web/index.html` 与安装日志 |
| 服务启动失败 | `journalctl -u rustboard-<role>`；不要删除 `/var/lib/rustboard` 数据目录 |
