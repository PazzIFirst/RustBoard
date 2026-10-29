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
  - `#51` 由维护者按 `not_planned` 关闭，不计入“已修复”；v1.0.0 继续以
    schema<9 fail closed 保护旧数据。
- `v1.0.0-rc.2`、`v1.0.0-rc.3` 未移动；`v1.0.0` 已 tag 并发布：
  <https://github.com/PazzIFirst/RustBoard/releases/tag/v1.0.0>。
  发布 tag `de135d6`；Release workflow 全绿。

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
| `c49b52a` | 执行记录、范围与长期证据文档 |
| `bf6f81b` | #80 Dockerfile 示例、#88 整数 published 门禁 |
| `064c026` | 最终渗透 AUTH-07 期望对齐 #38 502 语义 |

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

## 4. 压力与长稳

- 旧 24h（`f14c700`）：`target/load/20261027T184322Z-200a/`，约 1h19m 后因补修
  #33/#39/#58/#59 主动停止；**已标记无效，不用于发布**。
- 3h 预检（`ffcbc76`）：2h RssAnon 52,720 KB → 3h 52,892 KB（+0.3263%），
  FD 223、线程 81、0 error/retry/reconnect；确认 2h 预热后平稳。
- 24h（`ffcbc76`，`target/load/20261027T212205Z-200a/`）：
  - 200 agent / 5s，3,456,000/3,456,000 批 ACK，10,368,000 采样点，
    0 丢失/重复、0 error/retry/reconnect，health 86,401/86,401，hub 未重启。
  - 脚本默认 10min 基线 RssAnon 41,788 → 50,524 KB（+20.906%）判 FAIL；
    该窗口包含启动爬坡。
  - 按方案 R5 的 2h 基线：52,720 KB → 峰值 56,940 KB（+8.005%）、
    结束 50,524 KB（-4.165%）；FD/线程 0 增量。用户明确选择按 2h 基线
    判定通过（2026-10-29），证据 `out/rss-2h-gate.json`。
- 100 / 500 / 1000 agent（各 600s，最终二进制）：
  - 100：12,000/12,000 批，0 丢/重/错，p99 89.8ms，FD 124→124。
  - 500：60,000/60,000 批，0 丢/重/错，p99 326.0ms，FD 524→524。
  - 1000：120,000/120,000 批，0 丢/重/错，p99 2,032.7ms，FD 1,024→1,024。

## 5. 安装/交付/渗透

| 门禁 | 结果 |
|---|---|
| Docker PostgreSQL overlay | 106 PASS / 0 FAIL / 1 SKIP（arm64 另测） |
| Docker TLS volume / ACME / custom-ca / system-roots | PASS |
| TLS PostgreSQL（verify-full + 负向） | 27/27 |
| 安装器（systemd、回滚、升级、卸载） | 121/121 |
| 离线包 / 无网 netns | 122/122 |
| arm64 离线包（qemu） | 40 PASS / 0 FAIL / 2 SKIP（非原生主机） |
| 最终渗透矩阵 | 30 PASS / 0 FAIL（AUTH-07 对齐 #38 的 502 语义） |
| 渗透压力（DOS-01/ALERT） | 4 PASS / 0 FAIL（100k 事件淘汰未构造，另由单测覆盖） |
| SFTP/ARCH 真实环境 | 29 PASS / 0 FAIL |

## 6. 发布结果

- `v1.0.0` tag：`de135d6`；Release workflow 全绿。
- GitHub Release：<https://github.com/PazzIFirst/RustBoard/releases/tag/v1.0.0>
- 资产：amd64/aarch64 离线包、SBOM、SHA256SUMS、image-digests。
- 镜像（多架构 amd64/arm64）：
  - `ghcr.io/pazzifirst/rustboard-hub:v1.0.0` `sha256:84d5da62…`
  - `ghcr.io/pazzifirst/rustboard-panel:v1.0.0` `sha256:a948efbf…`
  - `ghcr.io/pazzifirst/rustboard-agent:v1.0.0` `sha256:0eb33332…`
- issue 状态由用户确认；9 条仍 OPEN（#33/#39/#52/#53/#54/#56/#57/#80/#88），
  已修复的 #80/#88 等不自行关闭。

## 7. v1.0.1 补丁（#79 Panel 分支）

- `#79` 复核指出 v1.0.0 只修了 Hub Docker 重配置，Panel 分支仍按旧文档
  直接 root install，会被 `/data` 10001 属主的 prefix 校验拒绝。
- 修复：`docs/install/panel-tls.md` §9 增加停服、备份、受控 chown
  （含 `/data/etc`、`/data/etc/rustboard`）、root `install --force`、恢复
  10001、`--user 10001` 启动与 HTTPS 健康验收；cert/key 改挂
  `/run/rustboard-panel-tls/`，避开只读 `hub_run` 的 mountpoint 冲突。
- 新增 `tests/e2e/v100-docker-panel-reconfig.sh`：真实初始化 panel_data →
  按文档重配 → HTTPS healthz 200，断言密码哈希/hub token 保留、TLS/config
  权限、进程 UID 10001；本地连续 3 次 **PASS=33 FAIL=0**。
- Release `delivery-docker` 增加该 E2E 门禁；`Cargo.toml`/锁版本升 1.0.1，
  `CHANGELOG` 增 `[1.0.1]`。无协议/schema/产品行为变更。
- `v1.0.1` 已发布：<https://github.com/PazzIFirst/RustBoard/releases/tag/v1.0.1>
  tag `847d6e9`；Release workflow 全绿（含 Panel reconfig E2E、Docker PG、
  arm64、离线/安装、镜像 manifest）。
