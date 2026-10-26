# Phase E S5/S6：发布演练、最终评审与 v1.0.0 发布

> 日期：2026-10-26｜基线：S1/S3/S4 已完成，S2 短档通过、24h 长稳运行中。
> 关联：[M5 收尾计划](2026-10-26-m5-phase-e-and-ki22.md) §1.5、[M5 总计划](2026-10-24-m5-install-delivery.md)。

## 1. S5 发布演练

| 项目 | 命令/证据 | 通过条件 |
|---|---|---|
| arm64 三步安装 | `STRICT=1 SKIP_BUILD=1 tests/e2e/v100-arm64.sh`（`PACKAGE` 指向当前源码 aarch64 包；复用前校验 hash） | 包布局/架构/静态链接；qemu 或原生 `--version`；hub install/healthz；STRICT 下任何 SKIP 都失败 |
| 离线包 | `tests/e2e/v100-offline.sh`（当前 x86_64 包；`STRICT=1`） | netns 无外网；三角色安装/启动；重复安装幂等；篡改包被拒；生产路径不变 |
| 升级/卸载/恢复 | `v100-install.sh` 中可在本环境执行的部分 + 手工 `--no-systemd`；systemd 不可用时明确 SKIP，不伪造 | 旧配置/数据保留；uninstall 默认保留 config/data，`--purge` 删除；恢复后点数一致 |
| Docker/镜像 | S4 rc.2 预发布证据 104/104；**版本升 1.0.0 后必须重建 dist/镜像并用 `EXPECTED_VERSION=1.0.0` 重跑 amd64**；arm64 PG overlay 未覆盖时明确记录范围，不能把 arm64 SKIP 写成通过 | v1.0.0 自身证据 |
| 最终评审/渗透 | 独立只读评审 + 本地渗透清单（认证/传输/注入/资源/泄露/依赖/配置） | 无未修复高危；严重问题修复后换人复审 |
| 门禁 | fmt/clippy/test（含 PG）/audit、actionlint、shellcheck、同一 commit CI + release `postgres` job | 全绿；shellcheck 范围为本阶段新增脚本（`v100-load.sh`/`v100-pg-tls.sh`/`v100-docker-pg.sh`），既有 `control.sh`/`v100-install.sh` 的 SC2034/SC2318 单列，不作为本阶段新增回归 |

**环境限制**：本机 systemd 未运行，`v100-install.sh` 的 unit 用例无法完整执行；
必须记录 SKIP 原因，不能把“未执行”写成通过。arm64 依赖 qemu/binfmt 与当前
aarch64 包；缺任一则记录 SKIP，不伪造。

## 2. S6 v1.0.0 发布

1. 确认 24h 长稳通过（RSS ≤10%、FD/线程不泄漏、0 丢点/重复、health 0 失败）；
2. 全量门禁 + CI 绿；`cargo audit` 无高危；
3. 更新 `CHANGELOG.md`：`[Unreleased]` 归档为 `[1.0.0] - <实际发布日>`，新开空
   `[Unreleased]`；保留 Phase D/E 限制与 KI-22 修复说明；24h 最早 10-27 结束，
   不得预写 10-26；
4. 根 `Cargo.toml` workspace 版本 `1.0.0`，`Cargo.lock` 同步；重新构建 amd64/arm64
   静态产物与 Docker 镜像（不能用 rc.2 旧镜像）；
5. **在干净的 1.0.0 树重跑 S3/S4**：`EXPECTED_VERSION=1.0.0`、重新生成
   dist manifest、重建 `:local-s4` 镜像；arm64 PG overlay 若未覆盖，发布 notes
   必须写“PG overlay 仅 amd64 验证”，不能把 S4 的 arm64 SKIP 当通过；
6. 打 annotated tag `v1.0.0` 并推送；**不移动 `v1.0.0-rc.2`**；
7. GitHub Release（notes 取自 CHANGELOG）；多架构镜像 + `latest`、SBOM/attestation；
   记录 digest；
8. 发布后验证：release 资产、镜像 manifest、`--version`、安装命令；不回写 rc.2。

## 3. 停止条件

- 24h 任一硬门禁失败：停止发布，按缺陷修复后从 200/10min 基线重跑；
- 评审/渗透存在未修复高危：禁止 tag；
- CI 未全绿或 release 资产不完整：禁止发布；
- 不得用旧 rc.2 镜像/包冒充 `v1.0.0`；不得移动已推送 tag。
