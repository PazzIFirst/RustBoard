# 2026-10-28 第二轮开放 issue 修复执行记录

对应方案：[2026-10-28-open-issues-round2.md](2026-10-28-open-issues-round2.md)

## 1. 范围与结论

- 基线：`73be1ad`。
- 原方案 51 条（#51–#102，排除已关闭 #55）全部 CONFIRMED。
- 执行中发现并补入 4 条仍 OPEN、且 v1.0.0 可达的问题：
  - `#33` 1m 清理后 legacy raw 覆盖完整 1h（P1 数据一致性）。
  - `#39` panel init 自动推导不可连接 Hub 地址（P2）。
  - `#58` SQLite→PG 迁移通知游标高水位丢失（P1）。该路径 v1.0.0 仍可用。
  - `#59` SQLite→PG 迁移 `SUM(last_ts)` i64 溢出（P2）。该路径 v1.0.0 仍可用。
- 最终 **52 条**代码/测试/文档修复；仅 `#51` 延后：
  - `#51` 只涉及 v7→v8 旧库迁移。v1.0.0 只支持全新安装，schema<9 在启动、
    备份、恢复、migrate 全部 fail closed，fresh install 不可达。
  - `#51` 保持 OPEN，已补评论请维护者确认转 P9 或 out-of-scope；未自行关闭。
- `v1.0.0-rc.2`、`v1.0.0-rc.3` 未移动；`v1.0.0` 未 tag、未发布。

## 2. 代码提交

| 提交 | 内容 |
|---|---|
| `cfcb8f3` | P0–P8 主修复（schema v9、告警、备份、安装器、SFTP、门禁、文档） |
| `8df45e4` | 版本升 `1.0.0`、发布文档与 Docker PG 门禁 |
| `6bd4201` | DSN 误杀修复、release 拉取 PG 镜像 |
| `0675153` | CHANGELOG 归档、状态与 24h 启动记录 |
| `04d0e0f` | v034 reset-password 落盘检查退出竞态 |
| `f14c700` | 配置语义校验不再回显 URL/路径敏感值 |
| `ffcbc76` | 补修 #33/#39/#58/#59 |

## 3. 已验证门禁

| 门禁 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS |
| `cargo test --workspace --locked` + 真实 PG | **1648 passed / 0 failed** |
| `cargo audit` | 无高危；`crypto-bigint 0.7.6` yanked 为已知 allowed warning |
| vendor `ssh-key` | 59 单测 + doctest PASS |
| vendor `russh` | 217 单测 + doctest PASS |
| security e2e | 9/9 |
| cert-rotation e2e | 103/103 |
| panel e2e | 159/159 |
| hardening e2e | 36/36 |
| control e2e | 103/103 |
| v041 e2e | 26/26 + 2 SKIP |
| SFTP e2e（新二进制） | 29/29 |
| CI `04d0e0f` | success；v034 97/97 |
| CI `ffcbc76` | success |

## 4. 长稳证据

- 旧 24h（`f14c700`）：`target/load/20261027T184322Z-200a/`，约 1h19m 后因补修
  #33/#39/#58/#59 主动停止；**已标记无效，不用于发布**。
- 当前 24h（`ffcbc76`）：`target/load/20261027T212205Z-200a/`，2026-10-28
  05:22 HKT 启动，200 agent / 5s；待 3h 与 24h 检查点。
- 3h 门禁：RssAnon 2h 基线到 3h 增长 ≤10%；FD/线程增量 ≤32；0 loss/dup/error。
- 24h 门禁：同一 2h 基线到 24h；最终 `summary.passed=true`。

## 5. 待完成

- 24h 最终结果与 3h 检查点。
- 100 / 500 / 1000 agent 三档。
- Docker PG overlay、TLS PG、离线安装/升级/卸载、arm64 包。
- 最终独立评审与渗透（本地实例）。
- `v1.0.0` tag、GitHub Release、三镜像多架构。
- 52 条 issue 评论；不关闭，等待用户确认。
