# 发布流水线与产物验证（M5 Phase B/C/D）

Phase B 新增 `.github/workflows/release.yml`：只由 `v*` tag push 触发。流水线负责
静态离线包、多架构镜像、SBOM、artifact attestation 与 GitHub Release；普通 push
只跑现有 CI，不推镜像。Phase C 的 C1 补齐了 Docker 与原生 arm64 运行时门禁，并给
正式发布 job 增加 `environment: release` 人工闸门；Phase D 增加 PostgreSQL
显式 opt-in，不改变发布流水线或默认 SQLite。

> **当前状态**：Phase B/C workflow 已由 `v1.0.0-rc.2` 真实执行并通过
> `delivery-e2e`、`delivery-docker`、`delivery-arm64`、SBOM 与 attestation；
> Phase D 已实现 PostgreSQL 与迁移/备份/恢复，全 workspace 测试 **1364 passed /
> 0 failed / 5 ignored**（含 PG load），本地测试证据已记录。
> `Cargo.toml` 为 `1.0.0-rc.2`，版本归档、CHANGELOG `[v1.0.0]` 与正式发布属于
> Phase E；`v1.0.0-rc.2` 不移动，Phase D checkpoint 不创建/移动 `v1.0.0`。

## 1. 触发条件

```bash
git tag -a v1.0.0 -m "v1.0.0 M5 安装与交付"
git push origin v1.0.0
```

workflow 在构建前校验：

- tag 形如 `vX.Y.Z`（可带预发布后缀）；
- tag 去掉 `v` 后与根 `Cargo.toml` 的 `[workspace.package].version` 完全一致；
- 触发提交是 `origin/main` 的祖先；
- `cargo fmt` / `clippy -D warnings` / `cargo test --workspace --locked` /
  `cargo audit` / 前端 tsc、单测、build 全绿；
- 同 tag 已存在已发布 GitHub Release 时直接失败，不覆盖资产。

已推送 tag 永不移动；修复走新 patch tag。

## 2. 流水线阶段

```text
verify（版本/tag/main 祖先 + 全部门禁 + release notes + SPDX SBOM）
  → build matrix（ubuntu-latest x86_64、ubuntu-24.04-arm aarch64）
      静态 musl 二进制 + 离线包 + 包内/外部 SHA256SUMS
  → delivery-e2e（x86_64 离线包在 netns 中安装/启动）
  → delivery-docker（amd64 三镜像本地构建 + 运行时/compose e2e，不推 GHCR）
  → delivery-arm64（原生 arm64 离线包安装/启动 + arm64 Docker e2e）
  → images matrix（每个架构原生构建 hub/panel/agent，推临时架构 tag）
      provenance=mode=max + sbom=true
  → manifest（只合成 `${TAG}-staging`；断言两架构并记录 staging digest）
  → release（environment: release，人工审批）
      资产/attestation → staging 提升正式 `${TAG}` 与 `sha-<short>`
      → latest → draft publish
```

`delivery-e2e`、`delivery-docker`、`delivery-arm64` 都只依赖 `build`，与 `images`
在 build 之后并行；`manifest` 等 `images` 完成，`release` 必须等 `verify`、
`manifest` 与三个 delivery 门禁全部成功。任一 delivery 门禁失败都不会进入正式
tag/Release 提升。

| 门禁 job | runner | 覆盖 | 不覆盖 |
|---|---|---|---|
| `delivery-e2e` | `ubuntu-latest` | x86_64 离线包在 `unshare -n` 中安装并启动 hub/panel/agent；无网安装、配置权限、健康检查 | 容器镜像、arm64 |
| `delivery-docker` | `ubuntu-latest` | `SKIP_ARM64=1 DOCKER_ARCH=amd64 bash tests/e2e/v100-docker.sh`：本地 buildx `--load` 构建 `linux/amd64` 三镜像，覆盖隔离/端口/非 root/healthcheck/重启幂等/`--user`/panel 共享 netns/agent fail-fast/真实 enrollment/compose；只建本地 tag，不登录、不推送 GHCR | arm64 镜像 |
| `delivery-arm64` | `ubuntu-24.04-arm` | 原生 arm64：`sudo env PACKAGE=... SKIP_BUILD=1 STRICT=1 bash tests/e2e/v100-arm64.sh` 校验并安装/启动 aarch64 离线包；再 `DOCKER_ARCH=arm64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh` 原生构建/运行三镜像；全程无 QEMU、不推 GHCR | 多架构 manifest（由 `manifest` job 覆盖） |

架构策略：构建/镜像使用 GitHub 原生 arm64 runner（公开仓库可用），避免 QEMU 下
Rust 编译超时；`delivery-arm64` 的包安装与 Docker e2e 同样在原生 arm64 执行，
`delivery-docker` 显式 `SKIP_ARM64=1` 跳过 amd64 runner 上可选的 QEMU arm64 附加
检查，避免同一门禁重复。本地 x86_64 仍可用 `docker buildx --platform linux/arm64`
配合 QEMU 做单架构预演，多架构 manifest 以 release workflow 为准。

正式 `${TAG}` 不在 manifest 阶段创建：staging 多架构 manifest 先存在，等所有资产、
SBOM、tarball/镜像 attestation 成功后才提升，并逐 role 校验 staging/正式/sha 三者
digest 完全一致；latest 只在正式与 sha tag 都成功后、且仅稳定版提升。

`release` job 带 `environment: release`。GitHub 仓库需在
**Settings → Environments → release** 配置 required reviewers（建议同时限制可部署
的 tag/branch）；未配置时该键不提供任何保护。需要审批的只是正式提升/发布这一步：
在人工批准前，`manifest` 已成功，staging 镜像与临时架构 tag 已经推送。

`delivery-e2e` 会在 `ubuntu-latest` 上用 sudo 在 `unshare -n` 中运行 x86_64 离线包
安装/启动 e2e；失败不会创建正式 tag 或 Release。该 job 依赖 hosted runner 的
sudo/unshare 能力；若受限会阻塞发布，而不是绕过。

## 3. Release 资产

一次成功发布应包含：

```text
serverdashboard-v1.0.0-x86_64.tar.gz
serverdashboard-v1.0.0-aarch64.tar.gz
SHA256SUMS
SHA256SUMS.x86_64
SHA256SUMS.aarch64
sbom-x86_64.spdx.json
sbom-aarch64.spdx.json
image-digests.txt
```

镜像：

```text
ghcr.io/pazzifirst/rustboard-hub:v1.0.0
ghcr.io/pazzifirst/rustboard-panel:v1.0.0
ghcr.io/pazzifirst/rustboard-agent:v1.0.0
# 同一 digest 另打 sha-<12-hex>（稳定版还打 latest）
```

稳定版同时推 `latest`；预发布（如 `v1.0.0-rc.2`）不推 `latest`。三个镜像均带
`org.opencontainers.image.source/revision/version/licenses` label，并同时包含
`linux/amd64` 与 `linux/arm64` manifest。

## 4. 校验

```bash
# tarball 与包内文件
sha256sum -c SHA256SUMS
tar -xzf serverdashboard-v1.0.0-x86_64.tar.gz
(cd serverdashboard-v1.0.0-x86_64 && sha256sum -c --strict SHA256SUMS)

# GitHub artifact attestation
gh attestation verify serverdashboard-v1.0.0-x86_64.tar.gz \
  --repo PazzIFirst/RustBoard

# 多架构 manifest 与 digest
docker buildx imagetools inspect ghcr.io/pazzifirst/rustboard-hub:v1.0.0
docker buildx imagetools inspect ghcr.io/pazzifirst/rustboard-hub:v1.0.0 \
  --format '{{.Manifest.Digest}}'

# 镜像标签
docker image inspect ghcr.io/pazzifirst/rustboard-hub:v1.0.0 \
  --format '{{json .Config.Labels}}'
```

Release 资产、`SHA256SUMS`、镜像 digest、SBOM 与 attestation 应能按 version +
revision 对应；镜像 digest 以 registry 的不可变 digest 为准，不只看可变的 tag。

## 5. 失败、重跑与回滚

- 构建/推送/attestation 任一失败：Release 保持 draft，不 publish；镜像 staging /
  临时架构 tag 可能已推送，但正式 tag 与 `latest` 不提升。
- `delivery-e2e` / `delivery-docker` / `delivery-arm64` 任一失败：`release` job 不会
  运行，因此不会创建正式 `${TAG}`、`sha-<short>`、`latest` 或发布 Release。由于
  `images`/`manifest` 与 delivery 门禁并行，staging `${TAG}-staging` 与临时架构 tag
  可能已经推送；重跑前先用 `docker buildx imagetools inspect` 确认 staging digest
  与预期一致，不要假设 registry 仍停留在上一次状态。
- `environment: release` 的 required reviewers 未批准或拒绝：正式提升/发布步骤不会
  执行，正式 tag 与 Release 不产生；staging 与临时 tag 保留。批准后重跑同一 tag，
  或人工按 digest 清理未提升的 staging。
- 正式 tag/sha tag 提升后、publish 之前失败：Release 仍为 draft；可能已有部分
  role 的正式 tag（registry 无法跨三个仓库原子操作），需重跑同一 tag 覆盖或人工
  按 digest 清理；不会自动 publish。
- 同一 tag 重跑：允许复用/覆盖 draft 资产；已发布 Release 拒绝重跑。
- RC/预发布（如 `v1.0.0-rc.2`）：`stable=false`，Release 以 prerelease 创建，
  `latest` 提升步骤不执行；正式 RC tag 与 `sha-<short>` 仍会生成用于验证，但
  `latest` 保持指向最近稳定版。提升为稳定版必须发布新的 `vX.Y.Z`。
- 发布后发现缺陷：发新 patch 版本（如 `v1.0.1`），不移动 `v1.0.0`；旧镜像 digest
  与旧 tarball 继续可追溯。
- 离线包校验失败：`install.sh` 在写任何文件前退出；用户保留旧包。
- 镜像发布失败：不创建/不 publish Release；已推送的旧版本不受影响。

## 6. 本地预演（不推 GHCR）

Phase B/C 的验收以本地可重复命令为主：

```bash
# 包（单架构，避免 QEMU 重复构建可加 --skip-build）
packaging/build-release.sh --arch amd64
(cd dist && sha256sum -c SHA256SUMS.x86_64)

# Docker 交付 e2e（x86_64；本地 tag 形如 rustboard-test/hub:local-amd64）
DOCKER_ARCH=amd64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh

# 原生 arm64 主机：同一脚本改用 arm64 平台与产物，不依赖 QEMU
DOCKER_ARCH=arm64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh

# 原生 arm64 离线包（root；STRICT=1 让 SKIP 也失败）
PACKAGE="$(readlink -f dist/serverdashboard-v*-aarch64.tar.gz)"
sudo env PACKAGE="$PACKAGE" SKIP_BUILD=1 STRICT=1 bash tests/e2e/v100-arm64.sh

# SPDX SBOM
packaging/sbom.py --output /tmp/sbom.spdx.json \
  --version 1.0.0-rc.2 --revision "$(git rev-parse HEAD)" --arch x86_64

# release notes 提取
packaging/release-notes.sh 1.0.0-rc.2 CHANGELOG.md

# workflow 静态检查
actionlint .github/workflows/release.yml

# Compose（默认、ACME 与 PostgreSQL 叠加）语法
docker compose -f docker/compose.example.yml config >/dev/null
docker compose -f docker/compose.example.yml \
  -f docker/compose.acme.example.yml config >/dev/null
docker compose -f docker/compose.example.yml \
  -f docker/compose.postgres.example.yml config >/dev/null

# PostgreSQL 实库测试（本地 postgres:16；角色需要 CREATEDB + pg_terminate_backend）
RUSTBOARD_TEST_PG='postgres://rustboard:<TEST_PASSWORD>@127.0.0.1:5432/rustboard?sslmode=disable' \
  cargo test -p rustboard-core --locked \
    --test postgres_schema --test postgres_core \
    --test postgres_parity --test postgres_migrate --test postgres_load
```

`tests/e2e/v100-offline.sh`、`tests/e2e/v100-docker.sh`、`tests/e2e/v100-arm64.sh`
分别覆盖离线安装、容器交付（`DOCKER_ARCH=amd64|arm64`）和 arm64 离线包运行。
`delivery-docker` 在 amd64 runner 上只跑原生 amd64（`SKIP_ARM64=1`），
`delivery-arm64` 在 `ubuntu-24.04-arm` 上原生跑包安装与容器 e2e，不使用 QEMU。
真正的 tag 触发、GHCR 推送、多架构 manifest、GitHub Release、attestation 与
hosted arm64 完整链路只能在 RC（当前为 `v1.0.0-rc.2`）/正式 tag 的发布环境验证。

## 7. ACME 与发布门禁

ACME 是**运行期/安装期**能力，不改变 tag 触发条件、版本一致性、main 祖先或
`delivery-*` 门禁：

- `verify` 仍只校验版本/tag/main 与 fmt/clippy/test/audit/web；
- `delivery-docker` 仍使用默认 `docker/compose.example.yml`（self-signed，不发布
  80/443），不会主动申请公网证书；ACME 叠加文件只做 `compose config` 语法检查；
- 证书、ACME 账户、CA 私钥不进镜像、SBOM 或 GitHub Release 资产；
- 发布失败/RC 失败仍按 §5 处理，不因为 ACME 是可选能力而跳过门禁。

**RC 前手工门禁**（不放进 CI，因为需要真实公网入口/DNS 与 Let's Encrypt 配额）：

1. 用当前 RC（如 `v1.0.0-rc.2`）二进制 + staging directory 验证域名 `http-01` 与
   `tls-alpn-01`，记录证书 SAN/链/到期；
2. 至少在一种公网 IPv4 上验证 `acme-ip` + `shortlived`（或等价 6 天证书）；
3. 验证 80/443 四层诊断（本地 bind、本机防火墙、云安全组、staging 实跑）与
   失败回退 self-signed；
4. 验证续期阈值/退避/热加载与失败保留旧证书；
5. 结果记录到 Phase C 证据文档；真实 production 证书可在 RC 环境按需申请，
   但**不得**把 staging 证书当生产证书，也不得伪造 ACME 成功。

操作步骤见 [acme.md](acme.md) 与 [tls.md](tls.md)；Docker 叠加见
[docker.md §6](docker.md#6-acme-与证书持久化) 与
[docker/README.md](../../docker/README.md)。

## 8. PostgreSQL 与发布门禁

PostgreSQL 是**运行期/安装期**的显式 opt-in，不改变 tag 触发条件、版本一致性、
main 祖先或 `delivery-*` 门禁；默认 SQLite 路径与发布资产不变。发布前仍需确认：

1. **同一 commit 的 CI `postgres` job 全绿**：覆盖 `postgres_schema`、
   `postgres_core`、`postgres_parity`、`postgres_migrate`、`postgres_load`，
   使用 `postgres:16` service。该 job 独立于 release workflow 的 `verify`，
   不能拿 `verify` 代替 PG job 的结论。
2. **PG 压力/长稳不在 release workflow**：`postgres_load` 是 storage 级
   200 agent 压测，不等于 hub 端 200 agent 端到端；hub 端真实 200 agent ingest、
   100/500/1000 与 24h 长稳仍按 Phase E 门禁执行，未完成前不发布 `v1.0.0`。
3. **外部客户端**：`pg_dump`/`pg_restore` 不在离线包、静态二进制或 hub 镜像内；
   发布说明应提示 PG 备份/恢复需要宿主安装 `postgresql-client`，并尽量使用与
   PG 服务端相同主版本的客户端。
4. **不改默认交付**：默认 compose、离线包和镜像仍以 SQLite 为默认；PG 只通过
   `database = "postgres://..."` 或叠加文件启用，不自动建库/建角色。
5. **不泄露**：发布资产、SBOM、镜像与构建日志不得包含数据库密码、完整 DSN、
   PG 数据或备份文件；CI 的测试 DSN 只存在于 job 环境。
6. **单 hub 语义**：PG 后端没有 leader 选举；发布说明不得暗示多 hub 多活。
   `migrate --force` 对非空目标目前只支持 `sslmode=disable`，该限制应写入
   release notes。
7. **发布演练**：至少在一个测试 PG 上执行 `backup → restore` 与
   `migrate → 启动 → 回切 SQLite`；不得用 mock 或“仅编译通过”代替。

操作与限制见 [postgres.md](postgres.md)；Docker 场景见
[docker.md §7](docker.md#7-升级回滚与限制) 与
[docker/README.md](../../docker/README.md) §14。
