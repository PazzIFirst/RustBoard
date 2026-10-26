# M5 收尾：KI-22 + Phase E 执行计划

> 日期：2026-10-26｜基线：`main` `6bb3fb0`（与 origin 同步，CI 全绿）
> 状态：**执行中**。S0 计划已确认，从 S1（KI-22）开始；其余阶段按顺序推进。
>
> 关联：[M5 总计划](2026-10-24-m5-install-delivery.md)、
> [Phase D 计划](2026-10-26-m5-phase-d-postgres-backup-l01-l03.md)、
> [Phase D 评审/渗透](../security/2026-10-26-m5-phase-d-review-pentest.md)、
> [当前实现状态](../status.md)、[已知问题](../known-issues.md)。

## 0. 当前基线与结论

- Phase A/B/C/D 已完成；Phase D checkpoint tag 为
  `checkpoint/2026-10-26-m5-phase-d-postgres-backup`（`78bc80e`，已推送）。
- `main` 当前 `6bb3fb0`；其后只有 CI/测试修复，产品代码未变；CI 最新 run
  `40285952672` 全绿。
- 全 workspace：**1380 passed / 0 failed / 5 ignored**；`fmt`、`clippy -D warnings`、
  `cargo audit` 通过；`v1.0.0-rc.2` 未移动，`v1.0.0` 未发布。
- 已知问题登记 **31 条**：24 已修复、1 待修复（KI-22，低危）、6 不修复
  （设计取舍/部署约束）；另有 Phase D 专项限制 7 条。
- 下一步顺序：**先修 KI-22，再做 Phase E 压力/长稳、TLS PG、Docker PG、发布门禁**。

## 1. 目标与验收

### 1.1 KI-22（待修复问题，先做）

**问题**：控制面日志白名单文件的硬链接不会被 `openat2` 拦截；拥有日志目录
写权限的人可把白名单路径替换为指向其他文件的硬链接，读取不该读的内容。
当前为低危，登记目标 v0.5.0。

**验收**：

- [ ] `open_log_path_absolute` 在 `openat2` 打开后检查 `nlink == 1`；多硬链接
      一律拒绝，错误信息明确，不读取内容。
- [ ] `validate_file_source` 启动校验与运行期 tail 使用同一拒绝逻辑；启动时
      对硬链接来源 fail-closed，错误包含 `日志来源 <id>` 与路径。
- [ ] 单链接普通日志、日志轮转（rename/recreate）、跨挂载点、现有符号链接/
      父目录/设备/FIFO/目录拒绝测试不回归。
- [ ] 新增单测：临时文件 + 硬链接 → 拒绝；单链接 → 允许；`nlink` 检查发生
      在读取前；不泄露目标文件内容。
- [ ] 可选 e2e：`tests/e2e/control.sh` 增加硬链接白名单拒绝断言。
- [ ] 文档：`docs/known-issues.md` 增加 KI-22 详情并标记已修复；`status.md`
      的已知限制 10 更新；若兼容性需要，`docs/install/control.md`/agent 日志
      白名单文档说明“硬链接日志文件会被拒绝”。
- [ ] 版本归属：修完后把目标版本从 v0.5.0 改为 `v1.0.0`（本次提前修复），
      不留下“已修复但仍列在待修复”的状态。

### 1.2 Phase E-1：hub 级压力与长稳

- [ ] 新增可重复的 hub 级负载工具；能启动真实 hub（SQLite 与 PostgreSQL），
      生成 N 个虚拟 agent，完成 TLS/Enroll/Hello/Batch，校验 ACK 与库内点数。
- [ ] 200 agent 端到端（不是 Storage 级）：0 丢点、0 重复、0 未处理 panic，
      `/healthz` 与面板/管理 API 可用；记录 ACK p50/p95、吞吐、CPU、RSS、
      FD/线程数、DB 大小。
- [ ] 100 / 500 / 1000 agent 三档，逐档运行并记录：
      - 0 丢失/重复；错误率 0；无 hub panic/重启；
      - ACK/查询延迟与资源曲线可解释，作为 v1.0.0 发布基线；
      - 连接风暴/断连重连后不丢已提交数据。
- [ ] ≥24h 长稳：RSS 增长 ≤10%；FD/线程/任务不泄漏；`/healthz` 持续可用；
      数据完整性抽查通过；日志无未预期 ERROR。
- [ ] 结果归档到 `docs/security/` 或 `docs/status.md`（含命令、环境、原始指标
      摘要，不提交 secret）。
- [ ] 若压力暴露产品缺陷：按“修复→全量门禁→200 基线→三档→24h”重跑，不用
      单条失败测试代替整轮。

**建议基线**：200/500/1000 每档 10 分钟、5s 采样、每批 3 点；24h 用 200 agent
（避免无意义数据膨胀），保留期按测试配置收敛。具体数值在工具落地后固化，
但“0 丢点/0 重复、RSS ≤10%、无泄漏”是硬门禁。

### 1.3 Phase E-2：真实 TLS PostgreSQL

- [ ] 用真实 TLS 启用的 PostgreSQL（非 `sslmode=disable`）完成
      `verify-full` 安装→启动→读写 smoke。
- [ ] 正确 CA/SAN/`db_sslrootcert` 成功；错误 CA、错误主机名、缺失根证书必须
      失败且不回退 `disable`；错误不打印密码/完整 DSN。
- [ ] 覆盖 hub 启动、agent 上报、查询、维护任务；至少一次重启后仍可连接。
- [ ] 文档补充可复制的测试证书/实例步骤；不提交真实测试私钥。
- [ ] 通过后把 status 的 Phase D 已知限制 5 标为已闭环；未通过则继续留在
      Phase E 门禁，不带病发布。

### 1.4 Phase E-3：PostgreSQL Docker 镜像内 e2e

- [ ] 重建当前源码的 hub 镜像（不拿 rc.2 旧镜像冒充），验证：
      - 默认 compose 仍 SQLite，无 PG 服务/无 5432 暴露；
      - PG overlay 能启动 hub + PG，完成 agent enroll/上报/查询；
      - 容器重启后 PG 数据仍在；`--user 10001` 权限路径可用；
      - 容器内不内置 `pg_dump`，backup/restore 的文档前置条件仍成立。
- [ ] backup/restore：用带 PostgreSQL client 的受控环境对容器 PG 执行
      `rustboard-hub backup/restore`（或明确记录为镜像外步骤），并做一次恢复
      后数据一致性检查。
- [ ] 结果写入 `docs/install/docker.md`/`postgres.md`；更新 status 的 D-G9
      为“镜像 e2e 已通过”。

### 1.5 Phase E-4：v1.0.0 发布

- [ ] 全新 arm64 三步安装、离线包、Docker 镜像、升级/卸载、备份恢复演练。
- [ ] 最终独立评审 + 渗透（安装器提权、路径/命令注入、secret、ACME key、
      镜像/供应链）；无未修复高危。
- [ ] 全量门禁：fmt、clippy、test（含 PG）、audit、CI、actionlint/shellcheck、
      镜像 digest 可追溯。
- [ ] CHANGELOG 把 `[Unreleased]` 归档为 `[1.0.0] - 日期`；版本字段升到
      `1.0.0`；打 `v1.0.0` annotated tag、GitHub Release、多架构镜像 + `latest`、
      SBOM/attestation。
- [ ] **不移动 `v1.0.0-rc.2`**；发布 notes 明确 PostgreSQL 限制、KI-22 已修、
      Phase E 测试结果与已知运维限制。

## 2. 范围与文件

### 2.1 KI-22

- `crates/rustboard-agent/src/control/logs.rs`：`open_log_path_absolute` 的
  `nlink` 检查、错误文案、单测。
- `crates/rustboard-agent/src/control/logs.rs` 启动校验错误映射（同文件）。
- `docs/known-issues.md`、`docs/status.md`、相关控制面日志文档。
- 不改变协议帧、配置必填项、数据库 schema。

### 2.2 Phase E 负载工具

建议新增（具体文件在实现时确认）：

- `tests/load/README.md`：运行方式、指标口径、secret 处理。
- `tests/load/hub_scale.py`：复用现有 `tests/e2e/probe.py` 的 WebSocket/
  MessagePack 编解码；真实 TLS + Enroll/Hello/Batch；N agent 并发。
- `tests/load/assert_metrics.py` 或脚本内断言：点数、重复、ACK、RSS/FD。
- `tests/e2e/v100-soak.sh`（可选）：编排 hub/PG、跑 200/500/1000/24h、
  收集指标；默认不进 CI 的短门禁，作为手工/定时阶段测试。
- 不改生产依赖；测试工具不入镜像/离线包。

### 2.3 TLS/Docker/发布

- `docs/install/postgres.md`、`docs/install/docker.md`、`docs/install/release.md`。
- `tests/e2e/v100-docker.sh`（或新增 PG overlay 用例）。
- `docker/compose.postgres.example.yml` 仅在必要时调整；默认 compose 不变。
- `.github/workflows/ci.yml` 仅在新增可稳定运行的短门禁时修改；24h 不进普通 CI。
- `CHANGELOG.md`、`Cargo.toml`、`Cargo.lock`（版本字段）及 release 工作流。

## 3. KI-22 设计要点

### 3.1 拒绝策略

- `openat2` 单次解析保持不变（`RESOLVE_BENEATH | NO_SYMLINKS | NO_MAGICLINKS`）。
- 打开后对 fd 做 `fstat`：
  - 必须 `is_file()`（现有）；
  - 必须 `nlink() == 1`；否则返回带明确文案的错误，例如
    “日志文件存在多个硬链接，拒绝读取（可能是硬链接逃逸）”。
- 检查必须在任何读取/tail/seek 之前；失败不读取内容、不缓存 fd。
- 对 `nlink != 1` 不提供静默降级；如需支持硬链接日志，应另立显式配置项并
  重新做安全评审，不能在本修复中放宽。

### 3.2 兼容性

- 普通日志、logrotate `copytruncate`/`create`、跨挂载点路径不受影响。
- 使用硬链接保留日志的非常规部署会被拒绝；在 known-issues 与日志文档中
  说明，属于 fail-closed 的安全取舍。
- 仅影响 agent 控制面日志读取；不影响 hub/panel、协议、数据库。

### 3.3 测试

- 单元：硬链接拒绝、单链接允许、错误文案、启动校验路径。
- 回归：现有符号链接、`..` 逃逸、FIFO/设备/目录、跨挂载点测试。
- 可选 e2e：在 `control.sh` 中创建硬链接白名单，断言 `control_failed` 且
  不返回文件内容。

## 4. Phase E 执行顺序与门禁

### 4.1 顺序

1. **S0 计划确认**（本文件；当前停止点）。
2. **S1 KI-22**：修复 + 单测 + e2e + 文档；全量门禁；独立复审；提交。
3. **S2 负载工具**：先 200 agent 基线；修任何产品问题；再 100/500/1000；
   最后 24h。每档记录证据。
4. **S3 TLS PG**：真实 TLS 实例 smoke；失败修复后重跑。
5. **S4 Docker PG**：重建镜像、overlay e2e、备份恢复。
6. **S5 发布演练**：arm64/离线/升级/卸载/恢复；最终评审/渗透。
7. **S6 v1.0.0**：CHANGELOG/版本/tag/Release/镜像。

S2 与 S3 可并行准备环境，但**发布门禁按顺序全部通过**；S2 失败时不得进入
S6。

### 4.2 每步硬门禁

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit
```

另加：

- PG 实库：`postgres_schema`、`postgres_core`、`postgres_parity`、
  `postgres_migrate`、`postgres_load`、`phase_d_backup`、
  `install_cmd::tests`；
- `actionlint .github/workflows/ci.yml`；脚本改动跑 `bash -n`/`shellcheck`；
- CI 必须全绿；不得用“本地过”替代；
- 严重问题修复后换新独立评审复审；渗透清单重跑，不只复测失败项。

### 4.3 停止/回退条件

- 任一档出现丢点、重复、panic、数据损坏、未修复高危：停止后续门禁，修复后
  从受影响档位重跑，必要时回到 200 基线。
- 24h RSS >10% 或 FD/任务泄漏：按缺陷处理，不带病发布。
- TLS PG 回退到明文/`disable`：视为失败。
- Docker e2e 使用旧 rc.2 镜像或跳过 backup/restore：不算通过。
- 发布前 `git status` 必须干净、`main` 与 origin 同步；tag 只打在最终通过
  门禁的提交上。

## 5. 风险与待确认决策

| 风险/决策 | 处理 |
|---|---|
| KI-22 硬链接日志兼容性 | fail-closed；文档说明；不接受静默放宽 |
| 负载工具实现成本 | 优先复用 `probe.py` 的协议编解码；先 200，再扩展 |
| 1000 agent 资源 | 本机/测试机能力不足时用受控多进程/远程压测；记录环境 |
| 24h 时长 | 单独定时任务/人工窗口；结果归档，不塞进普通 CI |
| TLS PG 环境 | 用临时 CA/证书；私钥不提交；测试后清理 |
| Docker 镜像无 pg client | 镜像内只做 hub/PG 连接；backup/restore 用外部 client，文档明确 |
| KI-22 版本归属 | 原 v0.5.0 提前到 v1.0.0；修后更新 known-issues/status |
| v1.0.0 与 rc.2 | 不移动 rc.2；v1.0.0 新 tag/Release |

## 6. 明确不做

- 不在本阶段实现多 hub/leader 选举（保持单 hub 语义，文档约束）。
- 不扩大 `migrate --force` 的 TLS 支持；仍只支持 `sslmode=disable`，除非另立
  安全设计。
- 不把外部 `pg_dump`/`pg_restore` 打进 hub 镜像/静态包。
- 不把 24h/1000 agent 压测放进每次 push 的 CI；作为阶段/发布门禁。
- 不修改 `v1.0.0-rc.2` tag 或已推送的 Phase D checkpoint tag。

## 7. 完成定义（Exit Criteria）

- KI-22 已修复、测试通过、known-issues/status 已更新；
- hub 级 200/100/500/1000 与 24h 证据齐全，0 丢点/0 重复、RSS ≤10%；
- 真实 TLS PG `verify-full` smoke 通过；
- PostgreSQL Docker 镜像内 e2e 与恢复演练通过；
- 最终独立评审/渗透无未修复高危；全量门禁与 CI 全绿；
- `v1.0.0` CHANGELOG/tag/Release/多架构镜像完成，`v1.0.0-rc.2` 未移动。

> **当前动作：S1（KI-22）执行中。**
