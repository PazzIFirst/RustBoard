# hub 级多 agent 负载与长稳（Phase E S2）

本目录存放 **hub 级**压力 / 长稳工具。它不是 Storage 直调或假协议测试，而是：

1. 真实启动 `rustboard-hub`（默认 SQLite，mTLS + `/healthz` + 管理 API）；
2. 用 `rustboard-hub agent add` 为每个虚拟 agent 生成一次性 token；
3. 用真实 TLS 完成 `Enrollment → Hello → Welcome`；
4. 在统一 barrier 后并发发送 `Batch`，串行等待匹配 `epoch/seq` 的 `Ack`；
5. 每秒采集 hub 资源与健康指标；
6. 结束后用只读 SQLite 连接核对 `ingest_batches` / `samples` 的丢点与重复；
7. 输出 `metrics.jsonl` 与 `summary.json`，以 `summary.passed` 和进程退出码作为门禁。

方案见 [`docs/plans/2026-10-26-phase-e-hub-scale.md`](../../docs/plans/2026-10-26-phase-e-hub-scale.md)。
本工具不修改 `crates/`、协议帧、数据库 schema、安装器、Docker 或 CI。

## 文件

| 文件 | 作用 |
|---|---|
| `hub_scale.py` | 单进程压测器：身份准备、Enrollment、会话、Batch/Ack、重连、指标采样、DB 校验、summary。复用 `tests/e2e/probe.py` 的 TLS/WebSocket/MessagePack 实现 |
| `../e2e/v100-load.sh` | 编排：构建 hub、随机端口、`hub init`、改配置、启动/停止 hub、调用 Python、扫描 hub.log、打印 summary |
| `README.md` | 本文 |

## 环境要求

| 依赖 | 说明 |
|---|---|
| Linux | `127.0.0.0/8` 回环源 IP、`/proc/<pid>/{stat,status,fd}`；macOS/Windows 不支持 |
| Python 3.11+ | **仅标准库**，无需 `pip install`；`tomllib` 用于校验 hub 配置顶层键，已在 3.13 验证 |
| `openssl` | 生成共享 ECDSA P-256 私钥与每 agent 的 CSR |
| `curl` / `timeout` | 编排脚本等待 `/healthz`、控制超时 |
| cargo / rustc | 构建 `rustboard-hub`；`HUB_BIN=...` 可跳过构建 |
| 资源 | 建议 16 vCPU / 16 GiB+；1000 agent 时 `ulimit -n` ≥ 8192（本机 524288） |

编排脚本会导出 `PYTHONDONTWRITEBYTECODE=1`，复用 `probe.py` 时不会改写仓库里
已跟踪的 `tests/e2e/__pycache__/*.pyc`。

## 快速开始

在仓库根目录执行：

```bash
# 必跑冒烟：10 agent / 60s（验收门禁）
bash tests/e2e/v100-load.sh 10 60

# 基线：200 agent / 10min
bash tests/e2e/v100-load.sh 200 600

# 扩展档：100 / 500 / 1000 agent，各 10min
bash tests/e2e/v100-load.sh 100 600
bash tests/e2e/v100-load.sh 500 600
bash tests/e2e/v100-load.sh 1000 600

# 长稳：200 agent / 24h（默认 warmup 自动提高到 600s）
bash tests/e2e/v100-load.sh 200 86400

# 重连专项：前 10% agent 每 ACK 2 批主动断一次再重连
bash tests/e2e/v100-load.sh 200 60 --reconnect-every 2
```

脚本会构建 `target/debug/rustboard-hub`（除非显式设置 `HUB_BIN`），在
`target/load/<UTC 时间>-<N>a/` 下建立 `config/`、`data/`、`out/`，随机选择
回环 agent/admin 端口，启动临时 hub，完成后停止 hub 并保留全部证据。

**24h / 1000 agent 不进普通 CI**，只手工运行；不要与同机其它高负载测试并行。

## 参数与环境变量

```text
bash tests/e2e/v100-load.sh AGENTS DURATION_SECS [--reconnect-every N] [--backend sqlite]
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `AGENTS` | 必填 | 虚拟 agent 数，1–2048（hub max_connections 至少 2048；计划档位 1000） |
| `DURATION_SECS` | 必填 | barrier 后统一运行秒数；24h = 86400 |
| `--reconnect-every N` | `0` | 仅前 10% agent，每 ACK N 批主动断连重连；`0` 不主动断 |
| `--backend sqlite` | `sqlite` | 当前只实现 SQLite 校验；其它值直接拒绝 |

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `HUB_BIN` | 空 | 指定已构建的 hub，跳过 cargo build（绝对路径优先） |
| `CARGO` | 自动查找 | `cargo` 不在 PATH 时可显式指定 |
| `PYTHON` | `python3` | Python 解释器 |
| `INTERVAL_MS` | `5000` | 每 agent 发批间隔，必须 < hub 45s 空闲超时 |
| `WARMUP_SECS` | 短档 60 / ≥1h 时 600 | 资源基线预热；也可显式覆盖 |
| `RUST_LOG` | `rustboard_hub=info` | hub 日志级别 |

## 连接、身份与源 IP

- **一次性 token**：每个 agent 由 `rustboard-hub agent add --config ... --name load-<i>`
  单独生成；token 只在 Python 内存中存在，不写文件、不打印、不进入 argv。
- **共享私钥 + 每 agent CSR**：`openssl genpkey` 生成 ECDSA P-256 私钥（0600），
  每个 agent 用 `openssl req -new -key <共享 key> -subj /CN=load-<i>` 生成 CSR。
  Enrollment 后 hub 强制证书 CN=`agent_id`，因此每个 agent 拿到独立证书；
  证书写入 0600 文件，私钥全程 0600。
- **Enrollment**：无客户端证书连 `wss://.../agent/ws`，发 `Enroll`（协议 2），
  收 `Enrolled`（agent_id / secret / cert_pem / ca_pem）。secret 只在内存。
- **Hello**：用 agent 自己的证书 + 共享私钥连接，`bind_ip` 绑定独立回环源 IP；
  发送 `Hello`（协议 2，epoch=1，无控制面能力），收 `Welcome`。
- **源 IP 分配**：源 IP 数 = `max(1, ceil(N / 200))`，从 `127.0.0.10` 起；按
  `index % 源IP数` **轮询**分配，每个 IP 严格 ≤200 条会话。1000 agent → 5 个源 IP。
  hub 的 `max_connections_per_ip` 上限是 256，`max_connections=max(2048, agents+256)`；轮询同时保证
  “前 10% 主动重连 agent”分散在各 IP 上，避免重连瞬间把单个 IP 推到 256。
  这不是绕过安全限制，而是模拟多台真实主机来源；Enrollment 仍从 `127.0.0.1`
  串行进行，避免与 `agent add` 的 SQLite 写操作撞锁。
- **身份准备**：`agent add`、CSR、Enrollment 串行执行。三者都会写 SQLite，
  并发时（实测 200 agent）会出现 `database is locked`，hub 因此关闭 enrollment
  连接；准备阶段不计入 `duration`，串行换取确定性，耗时见 `summary.prep_secs`。
- **并发模型**：每 agent 一个 512 KiB 栈 I/O 线程；全部完成会话 + Welcome 后才
  通过 `threading.Barrier(N+1)` 放行，再用启动事件同时开始发批。barrier 超时 40s
  （hub 空闲 45s）。建连失败有上限与指数退避，失败会 `abort()` barrier，不会卡死。
- **重连**：ACK 超时 / 连接关闭 / `Problem` 后重连，**重发同一 seq 的同一帧**
  （`sent_at`/`ts` 不变），由 hub 的 `(agent_id, epoch, seq)` 判重保证只入库一次；
  `retries` 记录连接/重发次数，`reconnects` 记录成功的新会话数。默认档
  `--reconnect-every 0` 下**任何** retries/reconnects 都会失败；主动重连测试
  （`--reconnect-every>0`）豁免这两项，但仍要求 0 errors。ACK epoch/seq 不匹配、
  Hello 返回 `Problem` 一律计入 errors，重试成功也不能洗白。Probe 的 WebSocket
  构造用 `SafeWebSocket` 包装：TLS 后 HTTP Upgrade 失败时会关闭已建 socket，避免
  fd 泄漏。

## 指标与门禁口径

每个 agent 每 `INTERVAL_MS` 发一批 3 点（`load.cpu` / `load.mem` / `load.disk`，
labels 为空，`ts` 每批唯一）；默认 5s，60s 档每 agent 12 批。

| 字段 | 口径 |
|---|---|
| `planned` | 计划批次数 = `agents × (满足 k×interval < duration 的 k 个数)` |
| `sent` | 实际发出的**唯一**批次数；重发不重复计数 |
| `acked` | 收到匹配 `(epoch, seq)` ACK 的批次数 |
| `unacked` | `sent - acked`；运行结束时仍未 ACK 的批次 |
| 丢点 | `sent - db.batches`（agent 认为已发、DB 中不存在） |
| 重复 | `ingest_batches` 的 `(agent_id, epoch, seq)` 重复组数；`samples` 的 `(agent_id, metric, ts)` 重复组数，均必须为 0 |
| ACK 延迟 | 从 `send_binary` 返回到收到匹配 ACK 的毫秒数；输出 p50/p95/p99/min/max/mean |
| 吞吐 | `acked / duration`（batch/s）与 ×3（sample/s），按名义运行时长 |
| RSS | 基线：`warmup` 后 30s 窗口的中位数；结束：最后 10 个样本中位数。增长 >10% **仅对 ≥1h 长稳档**作为失败门禁（默认 `duration_secs >= 3600` 启用，可用 Python `--rss-gate on/off` 覆盖）；10min/短档只记录高水位。60s 短档没有 warmup 后样本时，基线 warmup 夹到 `duration/2`，并在 `resources.rss_kb.baseline_mode` 标注 |
| FD / 线程 | 同样基线/结束口径；结束值相对基线允许 +32 |
| health | 每秒 `GET /healthz`，状态必须 200 且 body 去空白后等于 `ok`；失败次数必须 0，样本数必须 >0 |
| hub 重启 | `/proc/<pid>/stat` 的 starttime 运行前后必须一致，PID 必须存活 |
| CPU | `/proc/<pid>/stat` utime+stime 增量 / 采样间隔；含所有 tokio 线程，可能 >100% |
| DB 大小 | SQLite 主库 + `-wal` 字节数（每 1s 采样） |
| 管理 API | 结束后带 Bearer 请求 `/api/v1/agents`：HTTP 200 且 agent 集合与预期完全一致 |
| hub 日志 | 结束时扫描 `panicked` / `ERROR`；读取失败也算门禁失败；编排脚本在 hub 停止后会再扫一遍 |

`summary.json` 关键顶层字段：`agents`、`duration_secs`、`interval_ms`、
`source_ips`、`planned/sent/acked/unacked`、`retries/reconnects/errors`、
`retry_gate`、`ack_ms`、`throughput`、`resources`、`db`、`hub`、`admin_api`、
`hub_log`、`git_head`、`hub_bin_sha256`、`sqlite_db_sha256`、`failures`、`passed`。
`metrics.jsonl` 每秒一行，含 `health_status/health_body_ok/health_ok/health_ms`、
`rss_kb`、`threads`、`fds`、`cpu_pct`、`db_main_bytes/db_wal_bytes` 与累计计数。
`db.snapshot_mode` 记录 SQLite 只读快照口径，`db.snapshot_consistent` 记录查询前后
`ingest_batches` 计数是否一致。

### 通过条件（全部满足）

- 0 丢点、0 重复；`db.batches == planned` 且 `db.samples == planned×3`；
  `db.snapshot_consistent == true`；
- `unacked == 0`、`sent == planned`、`errors == 0`；
- 默认档 `retries == 0 && reconnects == 0`；主动重连测试可豁免这两项，但仍要求
  `errors == 0`（ACK mismatch / Hello Problem 均计入 errors）；
- metrics 样本数 ≥ `duration×0.9`；`health.samples > 0`；`/healthz` 每次必须
  200 且 body 为 `ok`，失败 0 次；hub PID/starttime 未变化；
- FD / 线程增长 ≤32，且 baseline/end 必须非空（读不到 /proc 指标即失败）；
- RSS 增长 ≤10%（**仅 ≥1h 长稳档**；门禁启用时 baseline/end 必须非空；10min/短档
  只记录，不据此判失败）；
- 管理 API 检查通过；`hub.log` 读取成功且无 `panicked`/`ERROR`；
- `git_head`（40 hex）、`hub_bin_sha256`、`sqlite_db_sha256` 均存在，证据可绑定
  提交、构建产物与数据库；编排脚本的泄露扫描通过；
- 所有 agent 线程在 join 时限内退出。

### RSS 门禁适用范围

方案 §1.2 只对 **≥24h 长稳**要求 RSS 增长 ≤10%；10min 档（100 / 200 / 500 /
1000 agent）的要求是 0 丢点/重复/未处理错误/panic、healthz 可用，并记录资源
曲线。因此工具按以下口径执行：

- 默认只有 `duration_secs >= 3600` 才把 `growth_pct > 10` 加入 `failures`；
- Python 可用 `--rss-gate on` 显式启用、`--rss-gate off` 显式关闭（bare
  `--rss-gate` 等价于 `on`）；
- `summary.resources.rss_kb` 始终记录 `baseline`、`end`、`max`、`growth_pct`，
  并额外记录 `gate_enabled`、`gate_threshold_pct=10`、`gate_mode`；
- 门禁关闭时 `summary.notes` 会注明“只记录高水位”，短档结果**不能**用来宣称
  24h 长稳通过；24h 若 RSS 仍 >10%，必须按缺陷处理。

任一失败都会写 `summary.json` 并以非零码退出；编排脚本另外把 hub 崩溃、
SIGTERM 超时、日志命中写回 `summary.failures`。

## 数据校验（SQLite / PostgreSQL）

- **SQLite（已实现）**：只读连接 `file:<db>?mode=ro`，在所有 agent 关闭会话后
  读取；先等待 `ingest_batches` 计数稳定（最多 10s），再核对总数、每 agent 计数、
  `samples` 中 `metric LIKE 'load.%'` 的数量与两组重复。查询结束后会重新计数并
  要求与查询前一致，`db.snapshot_mode` 标注为
  `agents_closed_hub_running_readonly` —— **不是停 hub 后的离线快照**。hub 的维护
  任务不会改写 load.* 原始样本，但若计数变化仍判失败，避免跨快照假通过。数据库
  文件在 `target/load/<run>/data/rustboard.db`。
- **PostgreSQL（后续）**：`hub_scale.py` 已预留 `check_postgres` 接口，目前会
  明确报错而不是静默跳过；编排脚本只接受 `--backend sqlite`。后续要求：
  `psql -Atc` + `PGPASSWORD` 环境变量，密码与完整 DSN 不得进入 argv、日志或证据。

## 证据与磁盘清理

每次运行一个独立目录：

```text
target/load/<UTC>-<N>a/
├── config/hub.toml        # 0600；含 hub 必需的 admin_token
├── data/certs/            # 测试 CA 私钥、服务端私钥/证书（hub 运行必需）
├── data/rustboard.db      # SQLite（0700 目录）
├── out/metrics.jsonl      # 每秒指标
├── out/summary.json       # 门禁与汇总
├── init.log               # hub init 输出（admin token 已替换为 [REDACTED]）
├── hub.log                # hub 运行日志
├── hub_scale.log          # Python 输出
└── out/work/              # 运行中临时私钥/agent 证书；退出时删除
```

- 成功和失败都**保留**运行目录（24h 证据供后续分析），脚本不自动 `rm -rf`。
  只会在退出时停止本次启动的 hub，并删除本 run 目录内的临时 `admin.token`。
- 清理时只删明确列出的历史 run 目录，**不要**删除整个 `target/load/`，也不要
  在压测进行中清理：

  ```bash
  du -sh target/load/*
  rm -rf -- target/load/20261026T114327Z-10a
  ```

- 24h 运行会积累大量 `samples`（200 agent × 17280 批 × 3 点 ≈ 1037 万行），
  以及约 86400 行 `metrics.jsonl`；归档后再删除对应 run 目录。
- `target/` 已被 git 忽略；仍不要把任何 run 目录、私钥、token 提交进仓库。
- **整个 run 目录不可提交**：`data/certs` 含测试 CA 私钥与 hub 服务端私钥，
  `config/hub.toml`/`config/admin.token` 含管理 token。工具不删除 CA/服务端私钥
  （hub 运行必需），只删除临时 `admin.token` 与 `out/work` 下的 agent 私钥/证书；
  归档 `out/summary.json`、`out/metrics.jsonl`、`hub.log` 后按上面的命令删除 rundir。

## 安全纪律

- **管理 token**：`hub init` 写入 0600 的 `hub.toml`；编排脚本从配置读出后写入
  本 run 目录的 0600 `config/admin.token`，Python 用 `--admin-token-file` 读取并
  **立即 unlink**。token 不进入 Python argv，不出现在 `metrics.jsonl`、
  `summary.json`、`hub.log`、`hub_scale.log`；脚本退出时还会兜底删除该文件。
- **一次性 enrollment token**：只从 `agent add` 的 stdout 解析到内存，随后发给
  hub 的 `Enroll` 帧；不写磁盘、不打印、不进入 argv。`agent add` 失败时只报
  `rc`，不回显输出（输出里有 token）。
- **agent_secret / 证书**：secret 只在内存；cert_pem 写在 0700 临时目录、0600
  文件，运行结束整体删除；从不打印证书或私钥内容。
- `config/hub.toml` 为了 hub 运行必须包含 admin_token，权限 0600；整个
  `target/load/` 视为**不可提交的测试材料**，归档证据后按上面的命令清理。
- 脚本退出时会扫描 `init.log`、`hub.log`、`summary.json`、`metrics.jsonl`、
  `hub_scale.log`：命中 admin token、PEM 私钥或无解释的 64hex 即失败；公开的
  服务端证书指纹与 `summary` 里的 hub/db sha256 明确豁免。扫描只输出文件名与
  类型，不输出秘密本身。
- 日志只记录 agent UUID、seq、计数、错误类型，不记录 token / secret / 证书。

## 失败与重跑

1. 先看 `out/summary.json` 的 `failures`、`error_samples`、`db`、`resources`，
   再看 `hub.log` 中的 `panicked`/`ERROR` 与 `metrics.jsonl` 曲线。
2. 修复产品缺陷或工具缺陷后，按“200 agent / 10min 基线 → 失败档位”重跑整轮；
   不要只重跑单条失败用例，也不得为通过而放宽断言。
3. 任何心跳超时、ACK 超时、Problem、丢点、重复、healthz 失败、hub 重启都按
   缺陷处理，不能记录为“环境抖动”后跳过。
4. 1000 agent / 24h 只手工运行；如果资源不足，先降档定位并如实记录实际规模，
   不能把“500 跑通”写成“1000 通过”。
5. 失败现场（run 目录）必须保留到问题定位完成；修复重跑通过后再按需清理旧目录。

## 工具自检

```bash
bash -n tests/e2e/v100-load.sh
# py_compile 显式写字节码，用临时 PYCACHEPREFIX，避免 tests/load/__pycache__ 入库
PYTHONPYCACHEPREFIX=/tmp/rustboard-pycache python3 -m py_compile tests/load/hub_scale.py
# 自检：空 metrics 必须失败；默认档 retries/reconnects 门禁；主动重连豁免
PYTHONDONTWRITEBYTECODE=1 python3 -B tests/load/hub_scale.py --self-check
bash tests/e2e/v100-load.sh 10 60
bash tests/e2e/v100-load.sh 200 60
```

`tests/load/__pycache__` 只是本地编译产物，不提交。

## 明确不做

- 不模拟公网 RTT / 丢包 / 带宽限制（由部署环境决定）；
- 不做多 hub / HA；
- 不把 1000 agent / 24h 放进每次 push 的 CI；
- 不提交测试私钥、token、secret、证书或完整 DSN。
