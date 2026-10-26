# Phase E 发布就绪独立评审与整改记录（2026-10-26）

> 评审对象：`main` `64d3afe`（Phase E S1/S2 短档/S3/S4 之后）
> 方式：只读评审 + `git`/`read`/`grep`/`bash -n`/`shellcheck -S warning`/`actionlint`；
> 未运行 cargo/Docker/负载。
> 结论：**当时不可发布 v1.0.0**；下列阻塞项已按提交整改，仍需 S5/S6 与
> 24h 长稳最终签收。

## 1. 阻塞项与整改

| # | 评审发现 | 整改 | 状态 |
|---|---|---|---|
| 1 | S4 104/104 是 `1.0.0-rc.2` 预发布证据；arm64 PG overlay 是 SKIP，却被 S5 计划写成“已通过” | 发布计划改为“rc.2 预发布证据；1.0.0 重建 dist/镜像后重跑 amd64；arm64 未覆盖必须明说”；S6 增加 1.0.0 重跑步骤 | 计划已改；**1.0.0 重跑待 S6** |
| 2 | release workflow 的 verify 不设 `RUSTBOARD_TEST_PG`，PG 用例 SKIP 仍可能发布 | release workflow 新增独立 `postgres` job（schema/core/parity/migrate/load + phase_d_backup + install_cmd），`release.needs` 依赖它；actionlint 通过 | 已修复（`1afdd37`） |
| 3 | CHANGELOG/Release notes 缺 PG TLS 客户端证书、compose `sslmode=disable`、单 hub、S4 仅 amd64、PG hub 级压测缺失等限制 | `[Unreleased]` 增加“已知限制”段落；发布时随 1.0.0 归档 | 已补（`1afdd37`） |
| 4 | 24h 用 debug/glibc，RSS 增长不可接受；短档 RSS 不能当长稳 | 首轮 24h 提前停止；定位 glibc arena；hub `.max_blocking_threads(64)`（`3f916a0`）；重建静态 musl；24h 改用静态发布产物重启（22:31） | 已修复并重启；**24h 待签收** |
| 5 | 发布文档状态漂移（S3 24/24 vs 27/27、S4 “尚未执行”、1364 tests、checkpoint 待打） | status/README/release/PG-TLS 计划/S4 计划统一为当前事实；S1 后 1386 tests；checkpoint 已打 | 已修复（`1afdd37` 等） |
| 6 | S5 arm64 命令缺 `STRICT=1`，SKIP 可能 exit 0 | 发布计划改为 `STRICT=1 SKIP_BUILD=1` | 已修复 |
| 7 | `tests/e2e/__pycache__/probe.pyc` 被跟踪，`__pycache__` 未忽略 | `git rm` tracked pyc，`.gitignore` 增加 `__pycache__/`、`*.pyc` | 已修复（`889b7eb`） |
| 8 | 发布说明日期预写 10-26，但 24h 最早 10-27 结束 | 发布计划改为 `<实际发布日>`；CHANGELOG 归档时填实际日期 | 已修复 |

## 2. 仍未完成的发布门禁

1. **24h 长稳**：静态 musl 200 agent 自 2026-10-26 22:31 运行；RSS 从 600s
   基线 ≤10%、FD/线程 +≤32、0 丢点/重复/错误、health 0 失败；未完成前不得
   签收 S2。
2. **1.0.0 自身证据**：版本升 1.0.0 后重建静态包/镜像；用
   `EXPECTED_VERSION=1.0.0` 重跑 S3 与 S4（至少 amd64；arm64 未覆盖必须写明）。
3. **S5**：arm64 三步安装、离线包、升级/卸载/恢复、最终独立评审 + 完整渗透；
   systemd 不可用部分记 SKIP，不能写成通过。
4. **门禁**：fmt/clippy/test（含 PG）/audit/actionlint/shellcheck/CI；同一 commit
   的 PG CI 与 release `postgres` job 全绿。
5. **S6**：Cargo.toml/Cargo.lock 1.0.0、CHANGELOG 实际日期归档、tag/Release/
   多架构镜像/SBOM/attestation/digest；不移动 `v1.0.0-rc.2`。

## 3. 残余风险（发布说明必须保留）

- PostgreSQL TLS 仅服务端认证，不支持 PG 要求客户端证书（`ssl_ca_file`）；
- stock compose PG overlay 使用 `sslmode=disable`，只适合本机/受信内网；
- 单 hub，无 HA；
- PG hub 级 200/100/500/1000 压测未实现，只有 SQLite hub 级与 storage 级 PG；
- Docker PG overlay 仅 amd64 在 rc.2 预发布上通过，arm64 未覆盖；
- 24h 是静态 musl 200 agent 单机回环源 IP 测试，不模拟公网 RTT/丢包/多主机；
- 测试机 `target/load` 含测试 admin token/CA 私钥（0600、已忽略），不得 force-add，
  发布前按需清理/轮换。

## 4. 结论

评审提出的阻塞项已完成可立即修复的部分；**当前仍不能打 `v1.0.0` tag**。待
24h 与 S5/S6 完成后，用同一 commit 的 1.0.0 产物重新出具证据并签收。
