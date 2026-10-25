# M5 Phase B：离线包、静态构建与 Docker

> 状态：计划（未开工）｜上游：[M5 安装与交付计划](2026-10-24-m5-install-delivery.md) §6 Phase B
> 基线：`v0.4.2` + Phase A checkpoint（`checkpoint/2026-10-24-m5-phase-a-install-r2`）
> 目标版本：`v1.0.0`（Phase B 只产出交付物，不改变协议/数据库）
> 关联：[Phase A 方案](2026-10-24-m5-phase-a-installer.md)、
> [Phase A 渗透报告](../security/2026-10-24-m5-phase-a-install-pentest.md)、
> [requirements.md](../requirements.md) §10.3/§14、[AGENTS.md](../../AGENTS.md) §6/§8/§9

## 1. 目标与验收

### 1.1 必须达成

| # | 目标 | 可验证验收 |
|---|---|---|
| B-G1 | musl 静态二进制 | `x86_64-unknown-linux-musl`、`aarch64-unknown-linux-musl` 各三个二进制；`file` 显示 static，`ldd` 返回 not a dynamic executable；`--version` 为发布版本 |
| B-G2 | 离线包 | 两架构 `serverdashboard-v1.0.0-<arch>.tar.gz`，含三二进制、systemd unit、前端、`install.sh`、`SHA256SUMS`、LICENSE、VERSION；`install.sh` 先校验 checksum 再安装 |
| B-G3 | 真离线安装 | 无网 netns 中 `install.sh --offline` 完成 hub/panel/agent 文件安装与本地启动；不发起外部 DNS/HTTP；重复执行幂等 |
| B-G4 | arm64 可运行 | qemu-user 或 arm64 容器中 arm64 musl 二进制完成 `--version`、`init/install --dry-run`、hub `/healthz`；不只“编译成功” |
| B-G5 | Docker 三镜像 | `ghcr.io/pazzifirst/rustboard-{hub,panel,agent}:v1.0.0` 与 `latest`，manifest 同时含 `linux/amd64,linux/arm64`；hub/panel 主进程非 root；agent 默认非 root、控制面关闭 |
| B-G6 | 容器隔离 | 默认不挂载宿主 `/etc`/`/var/lib`/`/usr/local`；`docker run image cat /etc/rustboard/hub.toml` 失败；只暴露声明的端口；镜像内无构建 secret |
| B-G7 | Release 流水线 | tag `v*` 触发：测试门禁 → 两架构构建 → 离线包/校验和 → 三镜像多架构推送 → SBOM/attestation → GitHub Release 资产；普通 push 不推镜像 |
| B-G8 | 可追溯 | 镜像 label 含 source/revision/version；Release 资产与镜像 digest、SBOM、provenance 可对应；`SHA256SUMS` 可用脚本校验 |
| B-G9 | 回滚 | 构建/推送失败不发布 Release；已发布版本用新 patch 修复，不移动 tag；旧镜像/离线包继续可安装 |

### 1.2 代表性验收命令

```bash
# 静态与版本
file dist/amd64/bin/rustboard-hub           # 期望 static-linked / static-pie
ldd  dist/amd64/bin/rustboard-hub           # 期望 statically linked / not a dynamic executable
dist/arm64/bin/rustboard-hub --version

# 包与校验
tar -tzf serverdashboard-v1.0.0-x86_64.tar.gz
( cd serverdashboard-v1.0.0-x86_64 && sha256sum -c SHA256SUMS )
sha256sum -c SHA256SUMS

# 无网离线安装（root）
unshare -n bash -c 'ip link set lo up; ./install.sh hub --offline --prefix /opt/rb-test --no-systemd'
# 断言无外部 connect（strace 只允许 loopback/Unix）

# arm64
qemu-aarch64-static dist/arm64/bin/rustboard-hub --version
docker run --rm --platform linux/arm64 ghcr.io/pazzifirst/rustboard-hub:v1.0.0 --version

# 多架构与隔离
docker buildx imagetools inspect ghcr.io/pazzifirst/rustboard-hub:v1.0.0
docker top <hub-container> -o uid,pid,cmd          # 主进程 uid=10001
docker run --rm ghcr.io/pazzifirst/rustboard-hub:v1.0.0 \
  test ! -e /etc/rustboard/hub.toml
```

### 1.3 非目标

- 不做 ACME、面板 TLS、PostgreSQL（Phase C/D）。
- 不做 Windows/macOS、Kubernetes Operator、HA。
- 不把 Docker 控制面默认打开；agent 的 Docker/systemd 控制能力仍默认关闭。
- 不在本阶段引入新的协议帧、SQLite schema 或配置必填项。

## 2. 现状与差距

| 能力 | 现状 | Phase B 需要 |
|---|---|---|
| 静态构建 | 仅 glibc debug/release | musl x86_64/aarch64 + 静态校验 |
| 打包 | 只有 `packaging/systemd` | 版本化 tar.gz、install.sh、checksums |
| 前端交付 | 运行期依赖 `web/dist` 或 `/usr/share/rustboard/web` | 包/镜像统一安装到 `/usr/share/rustboard/web` |
| 容器 | 无 Dockerfile | 三镜像、多架构、entrypoint、健康检查 |
| 发布 | 手工 tag + GitHub Release | tag 触发 workflow、资产/镜像/SBOM/attestation |
| 测试 | 本机 `v100-install.sh` | netns 离线、qemu arm64、Docker 多架构、隔离 |

Phase A 已提供 `install --yes --prefix --no-systemd --dry-run --offline`、
`--panel-static-dir`、`--token-file`、系统 unit 和全局锁；Phase B 直接复用，
不另写一套安装逻辑。

## 3. 关键设计决策

### 3.1 musl 构建方式

先做 1 天 spike，按以下优先级选一种，结论写入 `packaging/README.md`：

1. **推荐：buildx/qemu 原生构建**。每个架构用对应平台的 `rust:1.89-alpine`
   （固定 digest）+ `musl-dev` 在容器内 native 编译；arm64 用 QEMU binfmt 或
   arm64 builder。优点：不跨 C 工具链、`rusqlite bundled`/`ring` 行为与发布
   架构一致；缺点：arm64 构建慢。
2. 备选：`cross` + musl 镜像（固定版本/摘要），或用 `cargo-zigbuild`。
3. 不选：手工拼 `aarch64-linux-musl-gcc` 交叉工具链作为唯一路径；作为 spike
   对照即可。

构建入口统一为 `docker/Dockerfile.build`，参数 `TARGETARCH`、`PROFILE`；
x86_64/arm64 产物分别输出到 `dist/<arch>/bin/`。禁止在 workflow 里直接
`cargo build` 一个未固定工具链的宿主二进制充当发布物。

### 3.2 前端静态资源

Phase B 采用**外置静态目录**，不启用 `embedded-web`：

- 包内 `share/rustboard/web/`；`install.sh` 安装到 `/usr/share/rustboard/web`。
- Docker 镜像 `COPY web/dist /usr/share/rustboard/web`。
- panel 默认 `StaticFiles::discover("")` 会找到该目录；不新增配置字段。
- `embedded-web` 保留为未来可选，不在本阶段启用（避免 release 构建顺序耦合）。

### 3.3 离线包

```text
serverdashboard-v1.0.0-x86_64/
├── bin/rustboard-{hub,panel,agent}
├── share/rustboard/web/
├── systemd/rustboard-{hub,panel,agent}.service   # 默认生产路径参考
├── install.sh
├── SHA256SUMS                                    # 包内逐文件
├── VERSION
├── LICENSE
└── README.md
```

- 包名 `serverdashboard-v1.0.0-{x86_64|aarch64}.tar.gz`。
- `install.sh <hub|panel|agent> [install flags]`：
  1. 校验自身架构与 `VERSION`；
  2. 用 `sha256sum -c` 校验包内二进制/web/unit；
  3. 把 web 安装到 `/usr/share/rustboard/web`（仅 hub/panel 包或同包）；
  4. 以子进程调用 `bin/rustboard-<role> install --offline ...`（不 `exec`，失败时由
     `install.sh` 恢复旧 web），不重复实现配置逻辑；
  5. token/密码仍走 Phase A 的 0600 文件/stdin，不接受 argv。
- `--offline` 的语义固定为“**不发起外部网络探测**”；本地端口 bind、
  loopback `/healthz`、systemd 操作仍可发生。文档和 `--help` 必须写清。
- `SHA256SUMS` 用发布脚本生成；Release 再提供跨 tarball 的
  `SHA256SUMS`。包内/包外校验都覆盖。

### 3.4 Docker 镜像

统一多阶段构建，产物为静态 musl 二进制：

```text
docker/
├── Dockerfile              # 多 target：hub / panel / agent
├── entrypoint-hub.sh
├── entrypoint-panel.sh
├── entrypoint-agent.sh
├── compose.example.yml
└── README.md
```

镜像：

- base：`debian:bookworm-slim` 固定 digest；安装 `ca-certificates`、`curl`、
  `tini`、`util-linux`（`setpriv`），不放编译工具链。
- 静态二进制复制到 `/usr/local/bin/`；web 到 `/usr/share/rustboard/web/`。
- `ENTRYPOINT ["/usr/sbin/tini","--","/usr/local/bin/entrypoint-<role>.sh"]`。
- 运行时数据/配置：`/data`（volume），初始属主 root；entrypoint 以 root
  完成首次 `install --prefix /data --no-systemd`，chown 到 UID/GID `10001`，
  然后 `exec setpriv --reuid=10001 --regid=10001 --clear-groups
  /usr/local/bin/rustboard-<role> run --config /data/etc/rustboard/<role>.toml`。
  **主进程 UID=10001**；镜像默认 `Config.User` 为 root 仅用于首启初始化，
  文档明确说明。已初始化 volume 支持 `--user 10001:10001`（entrypoint 跳过
  install/chown，只校验配置可读）。
- hub：固定 `--listen 0.0.0.0:8443 --admin-listen 127.0.0.1:8444`；
  因 Phase A 管理口不允许 `admin_tls=off` 非回环，**hub 与 panel 必须共享
  网络命名空间**（`--network container:<hub>` 或 compose `network_mode: host`），
  panel 才能访问 `127.0.0.1:8444`。远程 panel 需 Phase C 的 HTTPS/反代，
  Phase B 文档不承诺不安全地开放管理口。
- panel：`--no-systemd --prefix /data`，hub URL/token 从环境/共享 volume
  读取；初始密码只在容器日志打印一次（文档警告）。
- agent：token 只从挂载的 0600 文件读取；默认 `--no-systemd`，不启用控制面；
  需要 systemd/Docker 控制时文档给出 `--privileged`、`/proc`、Docker socket
  的风险警告，不作为默认。
- 健康检查：hub/panel `curl -fsS http://127.0.0.1:<port>/healthz`；agent 用
  `rustboard-agent cert-info`/配置存在性检查，失败退出非零。
- 安全：镜像不含配置/私钥/token；构建 `.dockerignore` 排除 `target/`、
  `.git/`、`web/node_modules`、测试证据；`--read-only` + `--tmpfs /tmp`
  可选，文档给出验证命令。
- 镜像名：`ghcr.io/pazzifirst/rustboard-{hub,panel,agent}`；tag
  `v1.0.0`、`sha-<short>`、`latest`（仅稳定 tag）。多架构 manifest。

### 3.5 Release workflow

新增 `.github/workflows/release.yml`，只由 `push: tags: ['v*']` 触发：

```text
verify (version/tag/main 祖先/测试门禁)
  → build-musl matrix (x86_64, aarch64, web)
  → package + SHA256SUMS
  → docker buildx (linux/amd64,linux/arm64) + push GHCR
  → SBOM + provenance/attestation
  → draft GitHub Release → 全部成功才 publish
```

- `permissions` 最小化：`contents: write`、`packages: write`、`id-token: write`、
  `attestations: write`；第三方 action 全部固定到 SHA。
- 版本来源：`Cargo.toml` workspace version 必须等于 tag（`v` 去掉），否则失败。
- tag 必须指向 main 祖先；`--force` 移动 tag 不处理（workflow 失败并告警）。
- 普通 push 只跑现有 CI，不推镜像；Release 失败时资产/镜像不发布，重跑同一
  tag 可重建，但**不移动已推送 tag**。
- SBOM：优先用 `cargo metadata` 生成 SPDX JSON（脚本入库，避免依赖未固定
  的第三方生成器）；Docker 镜像用 buildx `--sbom` 或 syft 固定 action。
  结论在 spike 后写入 `packaging/README.md`。
- Attestation：`actions/attest-build-provenance`（固定 SHA）对 tarball/镜像
  digest 生成 provenance；buildx `--provenance=mode=max` 作为镜像侧补充。
- Release notes 从 `CHANGELOG.md` 对应 `[vX.Y.Z]` 段提取；无段落即失败。
- 签名：v1 先采用 **SHA256 + GitHub attestation**；是否加 minisign 作为
  Phase E 决策，不阻塞 B。

### 3.6 CI 与本地测试入口

- 新增 `tests/e2e/v100-offline.sh`：构建/解包离线包，`unshare -n` + lo up，
  以 `--offline --no-systemd --prefix /opt/...` 安装三角色，断言不发起外部
  连接（`strace -f -e trace=connect` 只允许 loopback/Unix），重复执行幂等。
- 新增 `tests/e2e/v100-docker.sh`：buildx 构建三镜像，检查 manifest 两架构、
  主进程 UID 10001、healthz、只读根/无宿主 secret、agent 默认控制面关闭。
- 新增 `tests/e2e/v100-arm64.sh`：qemu-user 或 arm64 容器跑 `--version`、
  `init`、`install --dry-run`、hub `/healthz`。
- `v100-install.sh` 保持本机 root+systemd 全链路；Phase B 不重复写一套。
- CI：先以 `workflow_dispatch` 或 main 上的独立 `install-e2e` job 试运行
  root+systemd 的 v100；稳定后再纳入默认 CI。GitHub hosted runner 需要
  `sudo`，若 systemd 不可用则明确 skip 并保留本地门禁，不伪装通过。
- 发布脚本 `set -euo pipefail`；e2e 用 `set -uo pipefail` + PASS/FAIL 计数；
  临时目录 `mktemp` + trap 清理、`/opt` 前缀、
  不碰生产路径。

## 4. 文件与接口

### 4.1 新增文件

```text
packaging/
├── build-release.sh          # 生成包/校验和/清单
├── install.sh                # 包内引导，调用 Phase A install
├── README.md                 # 包布局、验证、离线、签名
└── lib.sh                    # 共用版本/架构/静态校验/redact
docker/
├── Dockerfile
├── entrypoint-hub.sh
├── entrypoint-panel.sh
├── entrypoint-agent.sh
├── compose.example.yml
└── README.md
.github/workflows/release.yml
tests/e2e/v100-offline.sh
tests/e2e/v100-docker.sh
tests/e2e/v100-arm64.sh
docs/install/offline.md
docs/install/docker.md
docs/install/release.md
```

### 4.2 修改文件

- `.github/workflows/ci.yml`：增加可选 `install-e2e`（或保持手动，见 §3.6）。
- `CHANGELOG.md`：`[Unreleased]` 增加交付物条目；**不归档版本**。
- `docs/status.md`、`README.md`：Phase B 状态与最短安装命令。
- `packaging/systemd/*.service`：如包内安装需要，保持与 `render_unit` 默认
  路径一致；不改变 Phase A 的 hardening。
- 原则上**不改** `Cargo.toml` 版本、协议、配置、SQLite schema。

### 4.3 包内 `install.sh` 契约

```text
install.sh <hub|panel|agent> [--yes] [--offline] [--dry-run] [--force]
  [--prefix P] [--panel yes|no] [--token-file F] [--hub WSS] [--fingerprint F]
```

- 角色参数只允许三个值；其余原样传给对应二进制。
- `--offline` 默认加上；用户可显式 `--offline`（幂等）。
- 不接受 `--password` / `--token` 明文 argv；只透传 `--token-file` /
  `--hub-token-file`。
- 失败时打印可复现的 `--dry-run` 命令与日志位置，不打印 secret。

## 5. 兼容性

- 协议 v2、SQLite schema v7、配置字段不变；Phase B 只新增交付物。
- 静态 musl 替换 glibc 构建不改变行为；`rustls` 仍 `ring`。
- Panel 静态目录固定 `/usr/share/rustboard/web`；已有自定义 `static_dir`
  安装不受影响。
- Docker 镜像使用固定端口与 `/data`，与 systemd 安装并存但不共享配置；
  从 systemd 迁移到 Docker 需重新初始化（文档说明）。
- 离线包使用 Phase A 的 `--prefix`/`--offline`；不改变安装状态格式。

## 6. 测试矩阵

| 类别 | 用例 | 门禁 |
|---|---|---|
| 静态构建 | 两架构 `file`/`ldd`/`--version` | 每次 release |
| 包内容 | 文件清单、权限、checksum、无 secret | 每次 release |
| 离线 | netns 无外部连接、三角色安装、幂等 | Phase B |
| arm64 | qemu/arm64 容器启动与 healthz | Phase B |
| Docker | 三镜像两架构、非 root、health、隔离 | Phase B |
| Release | tag 触发、资产、SBOM/attestation、draft→publish | Phase B |
| 回归 | v100-install、workspace tests、audit、web | 每次 release |
| 故障 | 构建失败/推送失败不发布；重复重跑 | Phase B |

## 7. 实施顺序（建议 10 个工作日）

| 天 | 工作 |
|---|---|
| B1 | musl/arm64 buildx spike；确定 base digest、编译方式、产物路径 |
| B2–B3 | `Dockerfile.build`、x86_64/aarch64 构建、静态/版本校验 |
| B3–B4 | `install.sh`、包布局、确定性 tar、SHA256SUMS |
| B5 | netns 离线 e2e、arm64 qemu 测试 |
| B6–B7 | Dockerfile/entrypoint、非 root 降权、healthcheck、隔离测试 |
| B8 | 多架构 buildx、GHCR 推送、manifest 校验 |
| B9 | release workflow、SBOM/attestation、release notes 提取 |
| B10 | 文档、全量门禁、独立评审/渗透、checkpoint tag |

若 arm64 原生构建在 CI 超时，退回“x86_64 构建 + arm64 qemu 构建”的矩阵，
但不降低 B-G4 的运行验收。

## 8. 回滚

- 构建失败：不创建/不发布 Release；不推 `latest`；重跑同一 tag 只重建，
  已推送 tag 不移动。
- 镜像发布后发现缺陷：发布新 patch tag；GHCR 旧 digest 保留可追溯，不覆盖
  v1.0.0 的 digest。
- 离线包校验失败：安装脚本在写任何系统文件前退出；用户保留旧包。
- Docker 初始化失败：entrypoint 不启动服务；已有 `/data` 不被清空；
  失败信息不含 token。
- 包安装失败：沿用 Phase A 事务回滚；不删除已有数据。

## 9. 安全要求

- 发布物只来自 tag 对应的 main 提交；工作流校验 tag/版本/祖先。
- 构建容器固定基础镜像 digest；`cargo --locked`；不在镜像层写入 secret。
- 包校验 `SHA256SUMS`；Release 提供 attestation；镜像 buildx provenance。
- Docker entrypoint 首启 root 仅做 install/chown，随后 `setpriv` 降权；
  文档明确 `Config.User=root` 与主进程 UID 的区别。
- 镜像不含 `/etc/rustboard`、私钥、token；默认只暴露 8443/8444/8080。
- Agent 控制面默认关闭；启用需要宿主权限时文档高亮风险，不默认 privileged。
- 第三方 action 固定 SHA；GHCR 推送使用 `GITHUB_TOKEN` 最小权限。

## 10. 风险与未决项

| 风险 | 等级 | 缓解 |
|---|---|---|
| arm64 musl/qemu 构建失败或超时 | 高 | B1 spike；buildx native/QEMU 矩阵；不把“交叉编译成功”当运行验收 |
| Docker hub/panel 管理口回环限制 | 高 | 共享 network namespace/host network；远程 panel 留 Phase C TLS；不开放明文管理口 |
| 非 root 首启初始化复杂 | 中 | root entrypoint 仅首启、setpriv 降权；预初始化 volume 支持 `--user 10001` |
| SBOM/attestation 工具链不固定 | 中 | 自写 `cargo metadata` SPDX；固定 action SHA；spike 后二选一 |
| 包/镜像体积过大 | 低 | strip/lto、Debian slim、排除 docs/node_modules、静态二进制 |
| CI runner 无 systemd/root | 中 | `install-e2e` 先 workflow_dispatch；本地 v100 为硬门禁，CI 明确 skip |
| Release 误推 latest | 中 | 仅稳定 tag 推 latest；draft→publish；失败不推 |
| 包签名方案未定 | 低 | v1 先 SHA256+attestation；minisign 留 Phase E |

未决项（Phase B 开工后 1 天内定）：

1. musl 构建：buildx/QEMU 还是 `cross`/zigbuild；arm64 是否用原生 arm64 runner。
2. Docker 首启：root entrypoint→setpriv（推荐）还是预初始化 volume + `--user`。
3. SBOM 生成器与 attestation action 的固定版本。
4. 是否在 v1 加 minisign 包签名。
5. `latest` 是否仅稳定版；预发布是否推 `v1.0.0-rc.N`。

## 11. 完成定义（DoD）

- [ ] 两架构 musl 二进制静态校验通过，版本/commit label 正确；
- [ ] 离线包 checksum/内容/权限通过，netns 无网安装成功且无外部连接；
- [ ] arm64 qemu/容器完成 healthz；
- [ ] 三镜像两架构、hub/panel 主进程非 root、隔离/healthcheck 通过；
- [ ] tag 触发 release workflow，资产/镜像/SBOM/attestation 可追溯；
- [ ] v100 安装回归、workspace tests、audit、web 全绿；
- [ ] 独立评审/渗透无未修复高危；文档与回滚说明完整；
- [ ] 打 `checkpoint/<日期>-m5-phase-b-delivery`，不移动已推送 tag。

## 12. 关联

- [M5 安装与交付计划](2026-10-24-m5-install-delivery.md)
- [Phase A 方案](2026-10-24-m5-phase-a-installer.md)
- [Phase A 渗透报告](../security/2026-10-24-m5-phase-a-install-pentest.md)
- [requirements.md](../requirements.md) §10.3
- [AGENTS.md](../../AGENTS.md) §6/§8/§9
