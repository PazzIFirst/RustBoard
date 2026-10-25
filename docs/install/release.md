# 发布流水线与产物验证（M5 Phase B）

Phase B 新增 `.github/workflows/release.yml`：只由 `v*` tag push 触发。流水线负责
静态离线包、多架构镜像、SBOM、artifact attestation 与 GitHub Release；普通 push
只跑现有 CI，不推镜像。

> **当前状态**：workflow 已随 Phase B 落地，但尚未用真实 `v1.0.0` tag 执行。
> `Cargo.toml` 仍是 `0.4.2`，版本归档、CHANGELOG `[v1.0.0]` 与正式发布属于 Phase E；
> Phase B 的 checkpoint 不创建/移动 `v1.0.0` tag。

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
  → delivery-e2e（x86_64 离线包在 netns 中安装/启动，与 images 并行）
  → images matrix（每个架构原生构建 hub/panel/agent，推临时架构 tag）
      provenance=mode=max + sbom=true
  → manifest（只合成 `${TAG}-staging`；断言两架构并记录 staging digest）
  → release（资产/attestation → staging 提升正式 `${TAG}` 与 `sha-<short>`
      → latest → draft publish）
```

架构策略：构建/镜像使用 GitHub 原生 arm64 runner（公开仓库可用），避免 QEMU 下
Rust 编译超时；本地 x86_64 可用 `docker buildx --platform linux/arm64` + QEMU 做
单架构验收，多架构 manifest 以 release workflow 为准。

正式 `${TAG}` 不在 manifest 阶段创建：staging 多架构 manifest 先存在，等所有资产、
SBOM、tarball/镜像 attestation 成功后才提升，并逐 role 校验 staging/正式/sha 三者
digest 完全一致；latest 只在正式与 sha tag 都成功后、且仅稳定版提升。

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

稳定版同时推 `latest`；预发布（如 `v1.0.0-rc.1`）不推 `latest`。三个镜像均带
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
- 正式 tag/sha tag 提升后、publish 之前失败：Release 仍为 draft；可能已有部分
  role 的正式 tag（registry 无法跨三个仓库原子操作），需重跑同一 tag 覆盖或人工
  按 digest 清理；不会自动 publish。
- `delivery-e2e` 失败时不会创建正式 tag/Release；但 `images`/`manifest` 与其并行，
  staging 与临时架构 tag 可能已推送，需在重跑前确认 staging digest 不被复用。
- 同一 tag 重跑：允许复用/覆盖 draft 资产；已发布 Release 拒绝重跑。
- 发布后发现缺陷：发新 patch 版本（如 `v1.0.1`），不移动 `v1.0.0`；旧镜像 digest
  与旧 tarball 继续可追溯。
- 离线包校验失败：`install.sh` 在写任何文件前退出；用户保留旧包。
- 镜像发布失败：不创建/不 publish Release；已推送的旧版本不受影响。

## 6. 本地预演（不推 GHCR）

Phase B 的验收以本地可重复命令为主：

```bash
# 包（单架构，避免 QEMU 重复构建可加 --skip-build）
packaging/build-release.sh --arch amd64
(cd dist && sha256sum -c SHA256SUMS.x86_64)

# SPDX SBOM
packaging/sbom.py --output /tmp/sbom.spdx.json \
  --version 0.4.2 --revision "$(git rev-parse HEAD)" --arch x86_64

# release notes 提取
packaging/release-notes.sh 0.4.2 CHANGELOG.md

# workflow 静态检查
actionlint .github/workflows/release.yml
```

`tests/e2e/v100-offline.sh`、`tests/e2e/v100-arm64.sh`、`tests/e2e/v100-docker.sh`
分别覆盖离线安装、arm64 运行和容器交付。真正的 tag 触发、GHCR 推送、多架构
manifest、GitHub Release 与 attestation 只能在具备 tag/GHCR 权限的发布环境验证。
