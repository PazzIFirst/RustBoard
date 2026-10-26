# Phase E S2：hub 级多 agent 压力与长稳方案

> 日期：2026-10-26｜基线：`main` `26f9549`（S1 已提交）
> 关联：[M5 收尾计划](2026-10-26-m5-phase-e-and-ki22.md) §1.2/§2.2。
> 状态：执行中（S1 已完成）。

## 1. 目标与硬门禁

用**真实 hub + 真实 TLS/Enrollment/Hello/Batch**（不是 Storage 直调）验证：

| 档位 | 规模 | 时长 | 通过条件 |
|---|---|---|---|
| 基线 | 200 agent | 10 min | 0 丢点/0 重复/0 未处理错误；`/healthz` 可用 |
| 扩展 | 100 / 500 / 1000 agent | 各 10 min | 同上；无 hub panic/重启；ACK 延迟与资源曲线可解释 |
| 长稳 | 200 agent | ≥24 h | RSS 增长 ≤10%；FD/线程不泄漏；0 丢点/重复；健康检查持续 200 |
| 重连 | 每档按计划断连重连 | 内嵌 | 同一 `(agent, epoch, seq)` 重传只入库一次，不丢已 ACK 批次 |

**丢点定义**：agent 认为已发送的批次，在 hub 数据库中不存在；
**重复定义**：同一 `(agent_id, epoch, seq)` 在 `ingest_batches`/samples 中出现多份；
**错误**：连接异常、ACK 超时最终未恢复、Problem 帧、hub panic/重启、healthz 失败。

## 2. 范围与文件边界

新增，不改生产依赖/协议/schema：

- `tests/load/hub_scale.py`：单进程压测器。复用 `tests/e2e/probe.py` 的
  MessagePack/WebSocket/TLS 编解码；负责 token 创建、CSR/Enrollment、Hello、
  Batch/ACK、重连、指标采样、数据库校验、JSON 证据。
- `tests/e2e/v100-load.sh`：编排临时 hub（随机端口/临时 data_dir）、配置连接上限、
  启动、调用压测器、失败现场保留；参数 `AGENTS DURATION_SECS [BACKEND]`。
- `tests/load/README.md`：命令、指标口径、secret 处理、证据位置、24h 运行方式。
- 可能新增 `tests/load/check_db.py` 或把校验放在主脚本（优先单文件，避免碎片）。
- 不改 `crates/`、协议帧、数据库 schema、Docker/安装器。
- 24h/1000 agent 不进普通 CI；只提交可手工运行的脚本与文档。

## 3. 连接与身份设计

1. **token**：编排器/Python 调用 `rustboard-hub agent add --config ... --name load-<i>`，
   每 agent 一个一次性 token；token 只存内存，不打印。
2. **共享私钥 + 每 agent CSR**：测试用临时 ECDSA P-256 私钥（0600），
   每个 agent 用 `openssl req -new -key ... -subj /CN=load-<i>` 生成 CSR；
   hub 强制证书 CN=agent_id，因此 CSR 的 CN 不参与身份。
3. **Enrollment**：无客户端证书连接 `wss://.../agent/ws`，发 `Enroll`；
   收 `Enrolled`，保存 `agent_id`、`agent_secret`、`cert_pem`（证书 0600，私钥共享）；
   不记录 secret/token/证书内容到 stdout/证据。
4. **Hello**：用每个 agent 自己的证书连接，`bind_ip` 绑定 `127.0.0.x`；
   发 `Hello`（协议 v2，epoch=1，`capabilities=[]`），收 `Welcome`。
5. **同 IP 上限**：hub 的 `max_connections_per_ip` 最大 256；1000 agent 必须分散到
   至少 5 个回环源 IP（工具分配 `127.0.0.10..`，每 IP ≤200），
   `max_connections=2048`。这不是绕过安全限制，而是按真实多主机来源建模。
6. **并发模型**：每 agent 一个线程（I/O 为主），设置较小线程栈；Enrollment/
   CSR 可先并发准备，会话线程用 barrier 同时开始发 Batch。

## 4. Batch/ACK 与重连

- 每批 3 点：`load.cpu`、`load.mem`、`load.disk`（labels `{}`，`ts` 每批唯一），
  `sent_at=now_ms`；seq 从 1 递增，epoch 固定 1。
- 每 agent 按 `interval_ms`（默认 5000）发一批，串行等 ACK；ACK 的
  `epoch/seq` 必须匹配当前批次。
- 收到应用层 `Ping` 回 `Pong`；收到 `Problem` 记错误并重连；WS 关闭/超时重连。
- 重连：同一 agent 重新 Hello 后**重发当前未 ACK 的 seq**；hub 的
  `(agent_id, epoch, seq)` 幂等必须只入库一次。记录 retries/reconnects。
- 重连风暴仅在受控的 `--reconnect-every N` 下触发；基线档默认不主动断连。
- 结束：所有线程在统一 deadline 停止；最后一批未被 ACK 不计入 sent，避免把
  “没发出去”算丢点。

## 5. 指标与证据

每秒采样（写入 `metrics.jsonl`）：

- hub `/healthz` HTTP 状态/延迟；
- `/proc/<pid>/status` 的 VmRSS/Threads；
- `/proc/<pid>/fd` 数量；
- `/proc/<pid>/stat` 的 utime/stime（CPU 百分比）；
- SQLite 主库+WAL 大小（PG 用 `pg_database_size`）；
- 累计 sent/acked/retries/reconnects/errors。

结束输出 `summary.json`：

- 规模/时长/间隔/源 IP 数、开始结束时间；
- sent/acked/failed、DB 中 batches/samples、重复计数；
- ACK p50/p95/p99、吞吐（batch/s、sample/s）；
- 初始/结束 RSS、增长率、FD、线程、DB 大小；
- health 成功/失败次数、hub PID/starttime（证明未重启）；
- 错误/失败样本（脱敏）。

**RSS 口径**：连接建立完成并稳定 60s 后作为起点（短档）或 10min 后作为起点
（24h）；结束值为最后 10 个样本中位数。超过 10% 直接失败。
**数据校验**用 SQLite 只读连接/PG `psql -Atc`，在 hub 停止写入后执行；
不把数据库密码写入 argv。

## 6. 执行顺序

1. 10 agent / 60s 冒烟：Enrollment、Hello、ACK、DB 计数、指标。
2. 200 agent / 10min：修复所有产品/工具问题，归档基线。
3. 100 / 500 / 1000 agent / 各 10min：逐档执行；失败按“修复→200 基线→该档”
   重跑，不用单条失败测试代替整轮。
4. 200 agent / 24h：独立 data_dir；保留 metrics.jsonl/summary.json/hub.log；
   期间不做同机高负载压测。
5. 更新 `docs/status.md` 与 `docs/security/2026-10-26-m5-phase-e-load.md`，
   记录环境（16 vCPU/17 GiB/磁盘）、命令、原始指标摘要、任何 flake。

## 7. 停止/回退

- 丢点/重复/panic/healthz 失败：停止当前档，保留证据，按缺陷修复；
- 1000 档线程/FD 达到系统上限：记录实际规模，先降档定位，不能把“只跑通 500”
  写成 1000 通过；
- 24h RSS >10% 或 FD/线程增长：按缺陷处理，不带病发布；
- 环境资源不足：换受控测试机/远程压测，结果注明环境，不得伪造。

## 8. 明确不做

- 不模拟真实公网 RTT/丢包/带宽限制（由部署环境决定）；
- 不做多 hub/HA；
- 不把 24h/1000 agent 放进每次 push 的 CI；
- 不提交测试私钥、token、secret、完整 DSN。
