# Phase E：hub 级多 agent 压力与长稳证据（2026-10-26）

> 方案：[Phase E S2 方案](../plans/2026-10-26-phase-e-hub-scale.md)
> 工具：`tests/e2e/v100-load.sh` + `tests/load/hub_scale.py`（SQLite 校验）
> 状态：**短档 200/100/500/1000 已完成；200 agent 24h 长稳运行中，尚无 24h
> 结论。** 本文不把短档资源高水位当作长稳通过。

## 1. 环境与口径

| 项 | 值 |
|---|---|
| 主机 | 16 vCPU / 17 GiB RAM / Linux 6.12（x86_64），根分区约 55 GiB 可用 |
| hub | 短档排查用 `target/debug/rustboard-hub`（glibc）；**24h 用当前源码重建的静态 musl `dist/amd64/bin/rustboard-hub`**，SQLite/WAL，`self_monitor=false`，`max_connections=2048`，`max_connections_per_ip=256`，管理限速关闭 |
| 协议 | 真实 TLS Enrollment → Hello → Batch/Ack；协议 v2；每批 3 点（`load.cpu/mem/disk`），5s/agent |
| 源 IP | 100/200 用 1 个回环源 IP；500 用 3 个；1000 用 5 个（`127.0.0.10..`，每 IP ≤200），不绕过 per-IP 上限 |
| 证据 | `target/load/<UTC>-<N>a/`（`metrics.jsonl`/`summary.json`/`hub.log`），不入库 |
| 数据校验 | `ingest_batches`/`samples` 总数、每 agent 计数、两组重复；agents 关闭会话后只读快照，前后计数一致 |

## 1.1 构建差异与 RSS 修复（重要）

- 首轮 24h 使用 **debug/glibc** 二进制；21min 时 RSS 从 10min 基线 113MiB 涨到
  157MiB，趋势不可接受，已提前停止，未签收。
- 同一 200/300 档：默认 glibc `MALLOC_ARENA_MAX` 为 +13.5%，`MALLOC_ARENA_MAX=2`
  仅 **+2.9%**；确认主要是数百个 spawn_blocking 线程各自的 glibc arena 高水位。
- 修复：hub 主 runtime `.max_blocking_threads(64)`（提交 `3f916a0`），把
  200/1000 agent 的 blocking 线程从约 200/529 收敛到 **81** 总线程（含 worker）。
- 重新构建静态 **musl** 发布产物后复验：
  - 200/300：RSS 49.4→50.4MiB（**+2.06%**），线程 81，ACK p95 99ms；
  - 1000/300：RSS 175.1→182.4MiB（**+4.16%**），线程 81、FD 1023，
    **60000 批/180000 点**（300s×200 批/s）0 丢/重/错，ACK p95 468ms；
    这不是 10min 档，发布前需补 1000/600。
- 因此 24h 改为在 **静态 musl 发布产物**上运行，而不是 debug 构建；短档表中的
  10min 数字是修复前 debug 基线，保留用于对照，不能替代 24h 结论。
- 静态 24h 首次仍以 600s 为 RSS 基线：RssAnon 在约 40min 内从 39.5MiB 升到
  49.7MiB 后**持平**，对应 SQLite 连接页缓存/线程栈预热，而不是持续泄漏；
  600s 基线会把预热误判为增长。工具已改为采 `RssAnon`/`RssFile`，长稳 10%
  硬门禁用 **RssAnon**（静态 musl 的代码页 demand paging 不计入）；24h 采用
  **1h warmup 基线**，并在 2h 检查趋势。

## 2. 短档结果（修复前 debug，每档 10min）

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

## 3. 200 agent 24h 长稳（静态 musl，运行中）

- 启动：**2026-10-26 23:58（本地）**，计划 86400s（最早 10-27 23:58 结束）；
  200 agent、5s/agent、3 点/批；静态 musl 发布二进制，git `3f916a0`，
  hub sha256 `62dd9b7e…`；**WARMUP_SECS=3600**；证据
  `target/load/20261026T155852Z-200a/`。
- 硬门禁：0 丢点/重复、0 未处理错误、`/healthz` 0 失败、hub 未重启、
  **RssAnon 增长 ≤10%**、FD/线程相对 1h 基线 +≤32、`hub.log` 无 panic/ERROR；
  总 RSS/RssFile 仅报告（静态二进制代码页 demand paging 不是堆泄漏）。
- **1h 基线（01:00）**：RssAnon 46.2MiB、总 RSS 59.0MiB、RssFile 12.8MiB、
  DB 105MiB、线程 81、FD 223、health 100%、0 错误/重试；40–60min RssAnon 在
  45.4–46.4MiB 平台，未随 DB（55→105MiB）继续上涨，符合“页缓存/线程栈预热后
  稳定”的预期。
- 状态：**运行中，尚无最终结论**。2h 与结束时检查 RssAnon/FD/线程曲线；若
  RssAnon 仍持续单边上涨或 24h >10%，按缺陷处理，不发布 `v1.0.0`。
- 前两次 24h 已提前停止（debug/glibc 21min RSS 趋势；600s 基线把 SQLite 页
  缓存预热当增长），**均不作为通过证据**。
- 结束后在本文件补：`summary.json` 关键字段、RssAnon/总 RSS/FD/线程起点/终点、
  ACK p50/p95/p99、DB 点数/重复、health 次数、证据路径。

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
