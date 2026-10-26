# Phase E：hub 级多 agent 压力与长稳证据（2026-10-26）

> 方案：[Phase E S2 方案](../plans/2026-10-26-phase-e-hub-scale.md)
> 工具：`tests/e2e/v100-load.sh` + `tests/load/hub_scale.py`（SQLite 校验）
> 状态：**短档 200/100/500/1000 已完成；200 agent 24h 长稳运行中，尚无 24h
> 结论。** 本文不把短档资源高水位当作长稳通过。

## 1. 环境与口径

| 项 | 值 |
|---|---|
| 主机 | 16 vCPU / 17 GiB RAM / Linux 6.12（x86_64），根分区约 55 GiB 可用 |
| hub | 当前源码 `target/debug/rustboard-hub`，SQLite/WAL，`self_monitor=false`，`max_connections=2048`，`max_connections_per_ip=256`，管理限速关闭 |
| 协议 | 真实 TLS Enrollment → Hello → Batch/Ack；协议 v2；每批 3 点（`load.cpu/mem/disk`），5s/agent |
| 源 IP | 100/200 用 1 个回环源 IP；500 用 3 个；1000 用 5 个（`127.0.0.10..`，每 IP ≤200），不绕过 per-IP 上限 |
| 证据 | `target/load/<UTC>-<N>a/`（`metrics.jsonl`/`summary.json`/`hub.log`），不入库 |
| 数据校验 | `ingest_batches`/`samples` 总数、每 agent 计数、两组重复；agents 关闭会话后只读快照，前后计数一致 |

## 2. 短档结果（每档 10min）

| agent | 计划/ACK 批 | 点数 | ACK p50/p95/p99 (ms) | FD 基线→结束 | 线程 基线→结束 | RSS 基线→结束 (KiB) | 错误/重试/重连 |
|---:|---:|---:|---|---|---|---|---|
| 200 | 24000/24000 | 72000 | 118.7 / 175.0 / 211.9 | 223→223 | 218→218 | 85736→113822 (+32.8%) | 0 / 0 / 0 |
| 100 | 12000/12000 | 36000 | 58.3 / 93.5 / 455.2 | 123→123 | 118→118 | 64630→83916 (+29.8%) | 0 / 0 / 0 |
| 500 | 60000/60000 | 180000 | 304.2 / 442.7 / 1113.6 | 523→523 | 517→517 | 141742→197460 (+39.3%) | 0 / 0 / 0 |
| 1000 | 120000/120000 | 360000 | 454.9 / 733.6 / 824.8 | 1023→1023 | 529→529 | 215284→277600 (+28.9%) | 0 / 0 / 0 |

- 四档均：0 丢点、0 重复、0 未处理错误；`/healthz` 601/601 成功；hub
  PID/starttime 未变；`hub.log` 0 `panicked`/`ERROR`；管理 API 返回全部 agent。
- 1000 档的 529 线程/1023 FD 是 1000 条 TLS 会话 + tokio blocking pool 的
  高水位，结束时未继续增长；短档 FD/线程只记录，不作“无泄漏”结论。
- 短档 RSS 增长 28.9%–39.3% 主要来自 blocking 线程/allocator 与 SQLite 数据
  高水位；按方案 §1.2，**短档不启用 RSS 10% 硬门禁**，只记录，不能据此宣称
  24h 长稳通过。
- 关键证据目录：
  - 200：`target/load/20261026T121910Z-200a/`
  - 100：`target/load/20261026T122935Z-100a/`
  - 500：`target/load/20261026T130712Z-500a/`
  - 1000：`target/load/20261026T131809Z-1000a/`

## 3. 200 agent 24h 长稳（运行中）

- 启动：2026-10-26 21:33（本地），计划 86400s；200 agent、5s/agent、3 点/批；
- 硬门禁：0 丢点/重复、0 未处理错误、`/healthz` 0 失败、hub 未重启、
  RSS ≤10%、FD/线程相对基线 +≤32、`hub.log` 无 panic/ERROR；
- 状态：**运行中，尚无最终结论**。1h 与结束时检查 RSS/FD/线程曲线；若 RSS
  仍持续单边上涨或 24h >10%，按缺陷处理，不发布 `v1.0.0`。
- 结束后在本文件补：`summary.json` 关键字段、RSS/FD/线程起点/终点、ACK
  p50/p95/p99、DB 点数/重复、health 次数、证据路径。

## 4. 工具与门禁可信度

- 独立评审发现并修复：retry/ACK mismatch 计入错误；默认档 retries/reconnects
  即失败；metrics 缺失/health 样本为 0 必失败；`set_cfg` 顶层键校验；summary
  `passed` 与进程退出码交叉校验；证据绑定 git HEAD/hub sha256/DB sha256；
  扫描 admin token/私钥/异常 64hex；主动重连测试单独豁免。
- 500/600 曾因线程 +34 触发旧 +32 门禁；确认是短档 blocking pool 高水位后，
  将 FD/线程 +32 门禁限定为 ≥1h 长稳档，短档仅记录；24h 仍硬门禁。
- 200/100 的 `summary` 生成于较早工具版本（无 git 字段），数据路径与
  DB 校验一致；500/1000 由修复后工具生成并绑定提交/二进制哈希。

## 5. 结论与限制

- 短档结论：hub 在 200/100/500/1000 真实 agent 下 10min 内 0 丢点/重复/错误，
  无 panic/重启，ACK/资源曲线可解释；可作为发布前短档基线。
- **24h 未完成前不能签收 S2，也不能发布 v1.0.0。**
- 工具只校验 SQLite；PostgreSQL hub-level 压测未实现（Phase D storage 级
  200 agent 另见 `docs/status.md`），不作为本次 v1.0.0 发布门禁。
- 单 hub 语义、测试机同机压测、回环源 IP 模拟多主机，均需在发布说明/运维
  文档中如实说明。
