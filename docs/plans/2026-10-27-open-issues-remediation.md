# v1.0.0 全量缺陷修复方案（#27–#50）

> 日期：2026-10-27｜基线：`main` `344bc46`（与 origin 同步）
> 状态：**执行中**（2026-10-27 用户确认开工）。
>
> 协作硬约束：**issue 不得由 Agent 自行关闭**；只能补充评论（修复提交、测试
> 证据、兼容性说明），关闭动作必须由用户确认后执行。
>
> 关联：[问题核对结论](#0-结论与目标)、[M5 收尾计划](2026-10-26-m5-phase-e-and-ki22.md)、
> [当前状态](../status.md)、[已知问题](../known-issues.md)、
> [仓库发布门槛](../../AGENTS.md#85-发布门槛)。
>
> 硬约束：**不移动 `v1.0.0-rc.2`，不在门禁前发布 `v1.0.0`。**

## 0. 结论与目标

GitHub #27–#50 共 24 个 open issue。按 `344bc46` 逐条复核：

- 已修复：**#47**（`d66a643`，在 rc.2 内）、**#49**（`1553514`，仅 main，**不在 rc.2**）。
- 仍存在：**22 个**，其中 **4 个 P1**（#27/#32/#33/#50）和 **#34**（数据丢失类）
  应视为 1.0.0 硬阻断；其余 P2/P3 按本方案全部修复。
- 不是“基于旧 tag 的过期 issue”：除上述两条外，其余缺陷在 HEAD 均可复现或由
  当前源码确定。

### 0.1 总目标

1. 关闭 #27–#50 中全部可修复缺陷；不做“只改文档/降级为已知限制”的假修复。
2. 保持协议 v2 不变；不新增必需帧、不改证书格式；旧 agent 在升级 hub 后仍可连接。
3. 数据库升到 schema v8，迁移**可回滚**（备份恢复）；v8 二进制新增“更高版本
   拒绝”门禁。v8 是单向升级，旧 v7 二进制无法识别新列，升级后不得再用旧二进制
   打开；回退必须恢复迁移前备份。
4. 所有数据一致性修复必须有单元、SQLite/PG parity、并发/故障注入和端到端证据。
5. 最终用**修复后的二进制**重跑：100/500/1000 agent、24h 长稳、TLS PostgreSQL、
   Docker PG、arm64 安装与发布演练，再发布 `v1.0.0`。

### 0.2 成功标准

- [ ] 22 条待修 issue 全部有修复提交、回归测试、独立评审记录，并在 GitHub
      补充证据评论；关闭由用户确认，Agent 不自行关闭。#47/#49 复核已修，
      补评论与回归。
- [ ] `cargo fmt`、`clippy -D warnings`、`cargo test --workspace`、`cargo audit` 全绿。
- [ ] SQLite 与 PostgreSQL 的 schema、archive、downsample/retention、alert 查询
      parity 全绿。
- [ ] 新增 e2e（本方案 §6）全绿；`v031.sh` 进入 CI；CI 全绿。
- [ ] 独立评审无严重项；渗透清单全量重跑无高危/中危。
- [ ] 修复后代码的 24h 长稳通过（RssAnon 增长 ≤10%，FD/线程无泄漏，0 丢点/重复）。
- [ ] `v1.0.0-rc.3`（新 tag）完成发布演练后，才允许 `v1.0.0`。

## 1. 范围

### 1.1 涉及 crate

| crate | 主要内容 |
|---|---|
| `rustboard-core` | schema v8、archive/downsample/retention、buffer 恢复、disk/cpu 采集、PG parity |
| `rustboard-hub` | Batch 时间校验、archive worker、maintenance、WebDAV、告警查询/状态、panel init 辅助、CLI |
| `rustboard-agent` | connect 超时、续签调度、enrollment 完成标记、exec 进程组、ws 策略 |
| `rustboard-panel` | 告警 401 映射、init TLS/CA、CLI `--hub-ca` |
| `rustboard-common` | 配置字段、URL/loopback 校验、共享 endpoint 解析 |
| `web` | AgentDetail 刷新、告警标签、401 行为测试 |
| `tests/e2e`、`tests/load`、CI | 新数据/agent/panel e2e、v031 入 CI、长稳重跑 |

### 1.2 明确不做

- 不升协议 v3，不新增必需帧，不改证书/密钥格式。
- 不做多 hub HA、PG 客户端证书、冷数据在线查询。
- 不重写 DiskBuffer 记录格式；用双 meta + 向前重同步，保持旧 agent 可降级。
- 不自动删除旧归档对象；v8 新对象使用新 key 后缀，旧对象保留供审计。
- 不在本方案阶段发布 `v1.0.0`；rc.2 不移动。

## 2. 修复总览

| Issue | 级别 | 阶段 | 修复要点 | 主要验收 |
|---|---|---|---|---|
| #27 | P1 | R1a | 每条 raw 记录归档归属；迟到行不再被归档水位“证明已归档” | 归档后补传 B，B 进入新对象；删除前 join uploaded 对象 |
| #28 | P2 | R1a | 先 claim 固定行集，再上传；重试读同一行集和 `created_at` | 失败→补 B→重试，对象/DB 行数、hash、大小一致且可下载 |
| #29 | P2 | R3a | WebDAV 逐级 MKCOL，探针和每日目录共用 | 严格 DAV 首次 test/跨日归档成功；403/409/并发正确 |
| #30 | P2 | R3b | 告警状态 UPSERT 不再覆盖 `last_notified_at` | Barrier 固定评估/通知时序，时间不倒退、cooldown 生效 |
| #31 | P2 | R3b | `filter_labels` 下推到 SQL，在 LIMIT 前过滤 | 5001 条时目标在界外仍触发；空/多标签/无匹配 |
| #32 | P1 | R1b | raw 行级 `aggregated_1m`，retention 只删已聚合行 | downsample 后、retention 前入库的 late 不被删 |
| #33 | P1 | R1b | 1m/1h 改为增量合并，不再用残缺 raw 全桶覆盖 | raw 删后 late 30 正确合并为 count=3/avg=20 |
| #34 | P2 | R1c | 双 meta + 记录边界校验 + 中间损坏向前重同步 | meta=1/中间 0xc1/尾部撕裂均不丢后续记录 |
| #35 | P2 | R3c | 八进制转义按字节解码，路径用 `OsString` | 中文/混合转义挂载点可采集；非 UTF-8 不崩 |
| #36 | P2 | R3c | 保留 `cpuN` 的 N，按 ID 配对旧基线 | 稀疏编号/热插拔标签正确，不出现假 100% |
| #37 | P2 | R3d | 预设范围刷新时按 `Date.now()` 重算 | T0→T1 刷新 to=T1；custom 范围不变 |
| #38 | P2 | R3d | 告警 Hub 401 映射 502 `hub_auth_failed` | 有效 Panel Cookie + Hub 401 不登出；真正 Panel 401 仍登出 |
| #39 | P2 | R3d | init 读取 `admin_tls`/TLS 模式并推导 https/hub_ca；新增 `--hub-ca` | 自签 HTTPS Hub init 后 overview 可用；无法推导时明确失败 |
| #40 | P2 | R3e | CI 增加 `v031.sh` 和 cryptography 依赖 | CI 日志证明过期证书自愈/慢连接断言实际执行 |
| #41 | P3 | R3d | `Object.create(null)` 构造 labels | `__proto__`/constructor 创建、编辑、roundtrip 保留 |
| #42 | P2 | R2 | 整个 DNS/TCP/TLS/101 建连加总超时 | 黑洞 Hub 在超时内失败并进入退避；三种调用点覆盖 |
| #43 | P2 | R2 | 去掉“同会话永久一次”，改由 agent 冷却准入 | 同会话跨两个周期第二次成功；10min 内仍拒绝 |
| #44 | P2 | R2 | 证书检查移到每批 ACK 之后/空闲分支 | 持续 pending 时仍按周期续签，ACK 不丢 |
| #45 | P2 | R2 | `enrollment.complete` 最后写；缺失 ID 从 cert CN 恢复或失败 | 每个写点崩溃不产生随机身份；旧安装迁移不重纳管 |
| #46 | P2 | R2 | 子进程独立进程组；超时/正常退出都杀整组并限时回收管道 | `sleep 2 & wait`、`sleep 30 &` 均有界返回，无泄漏 |
| #48 | P2 | R2 | 默认拒绝非回环 `ws://`；显式 `allow_insecure_ws` 才放行 | 远程 ws 在发网络请求前失败；loopback/wss 不回归 |
| #50 | P1 | R1b | 时间戳范围校验、取消全局水位回拨、checked bucket 算术 | 超界/未来/i64 边界不写库；单 agent 旧样本不阻塞其他 agent |
| #47 | 已修 | — | 保持 `flock`，不回归 | 独立/同进程并发锁测试；滚动升级残余记录 |
| #49 | 已修 | — | 保持 `nlink == 1`，不回归 | 6 个硬链接测试；rc.3 必须包含 |

## 3. 数据模型 schema v8

### 3.1 变更

SQLite 与 PostgreSQL 同步升到 v8；全部为**新增列/索引**，不改既有列类型。

```sql
-- samples：归档归属 + 1m 聚合认领
ALTER TABLE samples ADD COLUMN archive_object_id INTEGER;
ALTER TABLE samples ADD COLUMN aggregated_1m INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_samples_unarchived ON samples(ts)
  WHERE archive_object_id IS NULL;
CREATE INDEX idx_samples_unaggregated ON samples(ts)
  WHERE aggregated_1m = 0;

-- 1m：增量合并所需的 last_ts + 1h 认领
ALTER TABLE samples_1m ADD COLUMN last_ts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE samples_1m ADD COLUMN aggregated_1h INTEGER NOT NULL DEFAULT 0;

CREATE INDEX idx_samples_1m_unaggregated ON samples_1m(bucket_ts)
  WHERE aggregated_1h = 0;

-- 归档对象：区分 v7 旧对象与 v8 claim 对象，并记录 failed 重试次数
ALTER TABLE archive_objects ADD COLUMN ledger_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE archive_objects ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;
```

- SQLite 使用 `rowid` 作为 raw 稳定行键；PG 使用 `samples.id`。Storage 新增
  `claim_archive_rows` / `claim_aggregated_rows` 抽象，调用方不直接拼 rowid。
- `last_ts` 是 1m 桶内最新 raw 的 `ts`，用于增量合并 `last_value`；1h 仍由
  1m 重算，不需要额外列。
- 不新增 `samples_1m.source_complete`：本方案不做“残缺源全桶重算”，而是
  始终对未认领行做增量 delta 合并。
- 不新增 `samples_1h` 列；1h 由 1m 重算，受 §4.2 的 late 边界约束。

### 3.2 迁移与旧数据

1. **SQLite 版本门禁**：新 v8 二进制在迁移开头增加
   `if version > 8 { bail!("schema v{version} 高于当前支持的 v8") }`。
   当前 SQLite 只判断 `version < SCHEMA_VERSION`，会误开未来版本；PG 已有同类
   门禁。**注意：已发布的 v7 二进制无法被追溯修改**，它不会拒绝 v8；因此升级
   文档必须写明 v8 单向、回退恢复备份，安装器/升级脚本检查版本并阻止旧二进制
   启动。
2. `archive_object_id` 初始为 NULL；`ledger_version=0`、`attempts=0` 表示 v7 旧对象。
3. `aggregated_1m`：**按 1m 桶 count/rowid 顺序对账，不读维护水位**（v7
   先写 1m 再推进水位，崩溃窗口会双计/漏计）：
   - 同一 `(agent_id, metric, labels, 分钟桶)` 的 raw 按 `rowid` 升序编号；
     编号 `<= 1m.count` 的 raw 置 1，其余（含崩溃窗口后才到的 late raw）置 0；
   - raw 少于 `1m.count` 时全部置 1；无 1m 行的桶全部 0；
   - `ts` 超出可归档范围的旧行单独计数并保持 0（见 §4.2），不参与对账。
4. `samples_1m.last_ts`：每个桶按 `rowid` 升序取最早 `1m.count` 条 raw 的
   `MAX(ts)`；raw 已删（无现存 raw）的桶才回填 `bucket_ts + 59999`，不得直接
   用全部现存 raw 或桶尾，避免迟到行被错误当成已聚合的 last。
5. `samples_1m.aggregated_1h`：**按整点小时累计 count 对账，不读 1h 水位**：
   同小时 1m 行按 `(bucket_ts, rowid)` 排序累计 `count`，累计值 `<= 1h.count`
   的行置 1，其余（崩溃窗口后的 late 1m）置 0；无 1h 行全部 0。
6. **归档账本迁移**：
   - `archive.enabled=false` 或水位为空：不进入 ledger 重建。
   - `archive.enabled=true` 且已有水位：写 `archive_state.archive_ledger_pending=1`，
     raw retention 立即 fail-closed；archive worker 把所有**仍存在的、可归档的
     unclaimed raw** 重新导出为 v8 对象（key 加 `-v8` 后缀），旧对象保留；
     完成后清 pending。
   - 已被 v7 删除且只剩旧对象的 raw 无法重新证明；旧对象保留，文档明确这是
     历史迁移边界，不回写、不删除旧对象。新产生的迟到行全部走 v8 claim。
   - 新增 CLI：`rustboard-hub archive ledger status` / `archive ledger rebuild`
     （后者用于中断后续跑；默认 worker 自动执行，retention 始终阻塞直到完成）。
7. 迁移在一个 `BEGIN IMMEDIATE`/PG 事务内完成；失败整体回滚，不部分写。
8. 备份：迁移前 `rustboard-hub backup` 或运维快照；v8 库不应再由 v7 二进制打开
   （v7 不会识别新列），升级后不得回退；回滚必须恢复备份。

### 3.3 索引与查询

- 归档扫描只走 `idx_samples_unarchived`，不按时间水位全表扫。
- 降采样扫描只走 `idx_samples_unaggregated`；`aggregated_1m=1` 的行不再进入
  维护查询。
- 1h 调度只查 `samples_1m.aggregated_1h=0` 的小时；retention 只删
  `aggregated_1h=1`。
- PG 的 `samples.id` 与 SQLite `rowid` 在 claim 事务内固定；跨事务 claim 必须
  同时校验行身份（agent/metric/labels/ts/value），不得只用可能复用的裸 rowid。

## 4. 分阶段设计

### 4.1 R1a：归档正确性（#27/#28）

**目标**：每条被 retention 删除的 raw 都能指向一个已成功上传的归档对象；
迟到行、重试、崩溃都不能绕过。

**claim 短事务 + 事务外编码/上传**：

1. 选 `archive_object_id IS NULL`、`ts` 在可归档日内且未超界的 raw，按
   `ts,rowid`（PG 为 `ts,id`）排序，按 `max_shard_rows` / `max_object_bytes`
   预切分为一个或多个对象。
2. 单事务插入 `archive_objects`：`ledger_version=1`、key 加 `-v8`、
   status=pending、rows/from_ts/to_ts 来自行集；bytes/sha256 先留占位。
3. 同一事务内 `UPDATE samples SET archive_object_id=? WHERE rowid=? AND
   archive_object_id IS NULL AND agent_id=? AND metric=? AND labels=? AND ts=?
   AND value=?`（PG 用 `id`）；**必须带行身份条件**，否则 rowid 被删除复用后
   会误认领新行。affected 行数必须等于选中数，否则整事务回滚并返回可重试
   `ClaimConflict`。
4. 提交后在事务外生成 CSV.GZ（gzip mtime=0，确定性）与 manifest；
   `created_at=now` 固定；生成完成后由 `update_archive_object_metadata`
   补 `bytes/sha256`（仅 pending/failed 允许）。
5. 上传对象 + manifest；开始每次尝试前 `record_archive_attempt` 递增
   `attempts`（仅 pending/failed）；成功置 uploaded，失败置 failed。
6. 失败/崩溃后的重试：按 `archive_object_id` 读取**同一行集**（按 `ts,rowid`
   排序，与 claim/scan 一致），用对象 `created_at` 重建完全相同的
   CSV/manifest；不重新扫描 raw，不纳入新 late 行；元数据只允许在
   pending/failed 状态更新。
7. 新 late 行仍是 NULL，下一轮生成**新对象**（`part-00002-v8`），不需要重扫
   已归档日。

**retention（archive 启用）**：

```sql
DELETE FROM samples WHERE rowid IN (
  SELECT s.rowid FROM samples s
  JOIN archive_objects o ON o.id = s.archive_object_id
  WHERE s.ts < ?1 AND s.aggregated_1m = 1
    AND o.status = 'uploaded'
  ORDER BY s.ts LIMIT ?2
)
```

`archive_ledger_pending=1` 时直接跳过 raw 删除。`last_archived_ts` 继续用于
status/UI，但**不再单独证明可删**。

**验收**：

- 归档 A 后补传同日 B：B 不被误删，进入第二个 v8 对象；对象 A/B 的
  rows/sha256 与下载逐字节一致。
- 首次上传失败，补 B 后重试：重试对象仍只含 A，元数据与 A 一致；B 另起对象；
  不存在“新内容+旧 hash”。
- 在 claim 后、上传前、上传后/状态前 `kill -9`：重启后续跑，不重复、不丢、
  不产生不可下载对象。
- 两个 archive worker 并发：只有一个能 claim 同一批行；另一个跳过。
- 旧 v7 对象/水位迁移：retention 在 ledger pending 时完全阻塞；rebuild 完成后
  才恢复，旧对象不被删除。

### 4.2 R1b：降采样/保留期/时间戳（#32/#33/#50）

**核心改变**：取消“迟到 → 回拨全局 1m/1h 水位 → 从旧桶全量重算”的路径。
未聚合 raw 行按桶做**增量 delta**，1h 由受影响的 1m 小时重算；全局水位只前进。

**配置**：

```toml
[ingest]
max_late_days = 30          # 默认 30；不得 >= retention_1m_days（非 0 时至少留 2 天）
max_future_skew_secs = 300  # 默认 5 分钟
```

- `ts < now - max_late_days*86400_000` 或 `ts > now + skew`：整批拒绝，**不写
  samples、不改任何维护水位**。
- 协议 v2 没有负 ACK；为避免坏批次重连风暴，hub 返回 **ACK 丢弃**（表示“已处理，
  未入库”），同时写审计计数和采样 WARN；响应/日志不回显样本值。该语义在
  CHANGELOG/运维文档明确；若要求严格负 ACK，需协议 v3，另立里程碑。
- 校验在 hub `handle_message` 与 self-monitor 共同调用；storage 的
  `invalid_batch` 仍保留 NUL/NaN 防御。
- 旧库中已存在的超界行：迁移计数并以 `aggregated_1m=1` 隔离，不参与维护；
  `maintenance status` 暴露 `invalid_timestamp_rows`，由运维清理/归档。

**1m 处理（每轮）**：

1. 从 `samples` 选 `aggregated_1m=0 AND ts < closed_end` 的行，按
   `(agent_id, metric, labels, bucket_ts)` 分块（≤5000 行）。
2. 对每个桶计算 delta：count、min、max、avg、last_ts、last_value。
3. 单事务：
   - 无 1m 行：插入 `count/min/max/avg/last_value/last_ts`。
   - 已有 1m 行：`count += delta.count`；
     `min=min(...)`、`max=max(...)`；
     `avg=(avg*count_old + delta.avg*delta.count)/(count_old+delta.count)`；
     `last_value/last_ts = delta.last` 当且仅当 `delta.last_ts > last_ts`。
   - 置该桶 `aggregated_1h=0`。
   - 将本批 raw 行置 `aggregated_1m=1`；`UPDATE ... WHERE rowid IN (...) AND
     aggregated_1m=0` 的 affected 必须等于本批行数，否则回滚重试。选择与认领
     必须在同一个写事务内完成，禁止两个 worker 重复合并同一行。
4. 水位只推进到已处理的 `closed_end`，不后退；不再调用
   `rewind_hour_watermark`。

**1h 处理**：

1. 选 `samples_1m.aggregated_1h=0 AND bucket_ts < closed_hour` 的小时。
2. 单事务按该小时全部 1m 行重算 1h（沿用加权 avg/min/max/last 规则）。
3. 将该小时所有 1m 行置 `aggregated_1h=1`；写入 1h 水位（只前进）。

**retention**：

- raw：`aggregated_1m=1`；archive 启用时再加 §4.1 的 uploaded join；
  `archive_ledger_pending=1` 时禁止。
- 1m：`aggregated_1h=1`；迟到 1m 更新会置 0，从而自动跳过。
- 约束：`retention_1m_days >= max_late_days + 2`（非 0 时），保证受迟到影响的
  小时仍有完整 1m 源；否则启动失败并点名字段。
- `bucket_floor` 改为 `checked_mul`，溢出返回显式错误；维护任务遇到坏行
  记录错误并跳过，不 panic、不回绕水位。

**验收**：

- #32：downsample 完成后、retention 前入库旧 ts 行 → 行未被删；下一轮增量
  聚合后保留期才可删。
- #33：桶 10/20 聚合为 count=2/avg=15；raw 删除；迟到 30 → 1m 变
  count=3/avg=20、min=10/max=30/last=30；1h 同步正确，不出现 1/30。
- 多个迟到值、重复重放、1m 已过期边界：幂等，count 不重复。
- #50：i64::MIN/MAX、百年前、未来 1 年 → 不写库、水位不变；正常边界
  （30d/5m）接受；`bucket_floor` 无 panic/回绕。
- 全局：一个 agent 连续提交 30d 前样本，其他 agent 的 1m/1h 推进与 retention
  不被阻塞（无全局回拨）。
- SQLite/PG parity + 1h 边界 + 维护中断恢复。

### 4.3 R1c：DiskBuffer 恢复（#34）

不改变 `[len][msgpack]` 记录格式，避免旧 agent 降级不兼容。

1. **双 meta**：保留 `buffer.meta` 十进制 `read_offset`；新增
   `buffer.meta.bak`。`save_meta` 先原子写 backup（旧值），再写 primary；
   启动时优先 primary，primary 非法/不在记录边界时用 backup；两者都非法则
   **fail-closed**，保留文件并返回明确错误，不静默从 0 复活已 ACK 数据。
   提供显式恢复入口 `rustboard-agent buffer repair --from-start`（会重发已 ACK
   前缀，依赖 hub 的 `(agent_id,epoch,seq)` 判重），不在启动时自动执行。
2. **边界校验**：`read_offset == len` 或该偏移处能读出合法 header 且
   `BatchCodec::decode` 成功，才算 boundary；否则触发 backup/重同步。
3. **中间损坏向前重同步**：
   - 顺序扫描；遇到非法长度/解码失败，先判断是否在尾部（`offset+4+len > len`
     或后续无有效记录）→ 按尾部撕裂截断；
   - 否则从 `offset+1` 起寻找下一个“header + 可解码 + 后续至少一条连续有效”
     的位置；保留后续 pending，记录坏区间并 WARN；
   - 修复前先把原 `buffer.log` 复制为 `buffer.log.corrupt-<ts>`（0600）。
4. 只有尾部损坏才 `set_len` 到最后有效记录；中间损坏保留后续记录；随后由
   正常压实去掉坏区间。
5. 测试：meta=1（有 backup → 全部恢复；无 backup → fail-closed）、第二条
   payload 改 `0xc1`（第 3 条保留）、尾部半写、已 ACK 前缀、重复打开幂等。
6. 可选 fuzz：对 `buffer.log` 随机翻转字节，断言不 panic、不删除后续有效
   记录、不错误复活已 ACK 前缀。

### 4.4 R2：Agent 生命周期与安全（#42/#43/#44/#45/#46/#48）

**#42 建连总超时**

- `AgentConfig.connect_timeout_secs`，默认 10，范围 1–60；旧配置缺省兼容。
- `connect()` 对建连整体包 `tokio::time::timeout`；超时返回可重试错误，进入
  现有指数退避。DNS 必须在 deadline 内用 `tokio::net::lookup_host` 预解析，
  不能把同步 `getaddrinfo` 留在 timeout 内部；TCP connect、TLS 握手和 HTTP 101
  共用剩余 deadline。
- 覆盖 `run_async`、`try_enroll`、`renew_once` 三个调用点。
- 测试：TCP 接受但不回 ServerHello；TLS 完成但不回 101；连接拒绝；慢但
  在超时内成功；首次纳管/常规/手工续签均不无限挂起。

**#43 同会话续签**

- 删除 `RenewState.succeeded` 的永久拒绝；保留 `RenewGuard` 的每 agent
  10 分钟冷却与容量上限。
- 成功后续签只记录 `last_success_ms` 用于日志/指标；同会话冷却后可再次成功。
- 更新现有“第二次必拒”测试为“冷却内拒、冷却后成功”；新增跨两个证书周期的
  时钟注入测试。

**#44 证书检查饥饿**

- 保留握手后检查与空闲 `cert_timer` 分支；新增 `next_cert_check` deadline。
- 每批 ACK 完成后、发送下一批前检查 deadline；到期且无在途 ACK 时执行
  周期检查；检查失败只 WARN，不丢当前批 ACK。
- 测试：持续有 pending 批次、推进时钟进入续签窗口，断言续签发生且
  batch ACK/ControlRequest 不丢。

**#45 Enrollment 原子完成**

- 新增 `enrollment.complete`（JSON：agent_id、cert_sha256、created_at），
  在 cert/key/secret/CA/agent_id 全部写完后最后原子写入。
- `is_enrolled` 要求 marker + 五个文件；`load_or_create_agent_id` 在已纳管
  状态只读 marker/ID，**绝不随机补 UUID**。
- 半完成状态（有 cert/key/secret、无 marker/ID）：启动 fail-closed，提示
  重新纳管或恢复备份；若仅缺 ID 且 cert 可解析 CN，可从 CN 恢复并补 marker，
  不生成新身份。CA 缺失时不猜测，明确失败。
- 旧安装无 marker：启动时校验 cert/key/secret/ID，能对上 cert CN 则补 marker；
  对不上则报错，不重纳管、不覆盖。
- 测试：在 cert/key/secret/CA/ID 每个写点后注入崩溃/ENOSPC，重启后身份
  一致；旧安装升级；token 消耗后不产生错误身份。

**#46 控制命令进程组**

- Unix 下 `CommandExt::process_group(0)` 让子进程成为新进程组组长。
- stdout/stderr 设为非阻塞，Unix 用 `poll(2)` + deadline 读取，不再创建
  不可取消的 reader 线程；若平台只能保留线程，必须有界回收，不能在 deadline
  后只丢弃 `JoinHandle`。
- 超时/等待失败：`killpg(SIGKILL)`，再 `wait`；正常父退出后若管道在
  `READER_GRACE` 内未 EOF，也杀整组。容量许可在 `execute` 真正返回后才释放，
  进程组被杀后管道关闭，读取有界结束；仍不结束时记录错误并拒绝继续创建
  新命令，不允许无限增长。
- 测试：`/bin/sh -c 'sleep 2 & wait'`（100ms 超时）有界返回；`sleep 30 &`
  （父立即退出）也有界；连续超时不泄漏线程/FD；无后代场景不回归。

**#48 明文 ws 策略**

- `AgentConfig.allow_insecure_ws`，默认 false。
- `hub_url` 为 `ws://` 时：仅允许 loopback（`127.0.0.0/8`、`::1`、`localhost`）；
  非回环必须显式 `allow_insecure_ws = true`，启动时 WARN（不打印 token）。
- 仍然拒绝 `ws://` + custom-ca/system-roots；`wss://` 的指纹/CA/mTLS 不变。
- 测试：远程 ws 在发网络请求前失败；loopback ws 允许；显式 opt-in 才放行；
  wss 正常；错误不泄露 token/secret。
- 文档：安全边界与迁移说明（远程 ws 用户必须改 wss 或显式接受风险）。

### 4.5 R3a：WebDAV（#29）

- 新增 `ensure_parent_collections(key)`：从 base URL 逐级 MKCOL；
  201=创建，405=已存在，409=父缺失/权限错误，3xx 因禁用重定向视为失败。
- `put` 前调用；`test()` 的 `health/<uuid>.probe` 复用同一逻辑。
- 每个 store 实例缓存已创建 collection（避免重复 MKCOL）；并发创建时
  405 视为成功；401/403 映射为固定后端不可用，不泄露 URL/凭据。
- 测试用严格 DAV mock（父不存在 PUT=409）：首次 test、跨新日期、重复/并发
  MKCOL、403/409、无重定向；对照手工 MKCOL 后成功。
- 空 collection 不清理（探针对象仍删除）；文档说明 base collection 必须
  预先存在且可写。

### 4.6 R3b：告警（#30/#31）

**#30 通知时间不被覆盖**

- `ALERT_STATE_UPSERT_SQL` 冲突分支不再更新 `last_notified_at`（保留库中值）；
  插入新行时仍写 NULL。`notify_worker` 继续用专用
  `update_alert_state_notified` 独占该字段。
- 评估器不再把旧快照的通知时间写回；`next_alert_state` 可继续复制用于
  状态机判断，但持久化冲突不覆盖。
- 测试：Barrier 固定“引擎读→worker 写 T→引擎提交”，断言 T 保留；
  cooldown 内不重复通知；resolve/re-fire 仍正确；更新现有反断言测试。

**#31 标签过滤下推**

- `Storage::latest_alert_series` 增加 `filter_labels: &Labels`。
- SQLite：为每个标签加
  `EXISTS (SELECT 1 FROM json_each(samples.labels) WHERE key=? AND value=?)`；
  全部参数化，路径不做字符串拼接。
- PostgreSQL：`labels::jsonb @> $n::jsonb`，JSON 由 serde 生成。
- `LIMIT` 在过滤后的最新序列集合上执行；引擎不再在截断后过滤。
- 测试：5001 条、目标第 5001 条；多标签；`__proto__`/特殊字符键；空过滤；
  无匹配；查询计划仍走 `(metric, ts)` 索引；SQLite/PG parity。

### 4.7 R3c：采集器（#35/#36）

**#35 UTF-8 挂载路径**

- `unescape` 返回 `Vec<u8>`（八进制转义解码为字节）；`read_mounts` 用
  `OsString::from_vec` 保留原始字节。
- `statvfs` 用 `CString` 原始字节；指标 label 用 `to_string_lossy()`（无效
  UTF-8 不崩溃，损失可诊断）。
- 测试：ASCII、中文、空格 `\040`、反斜杠 `\134`、混合转义；真实 UTF-8
  临时目录 statvfs；无效 UTF-8 路径不 panic。

**#36 per-core CPU ID**

- `read_stat` 返回 `Vec<(u32, CpuTimes)>`，解析 `cpuN` 的 N。
- `CpuCollector.prev` 用 `BTreeMap<u32, CpuTimes>`；标签用实际 N；新上线
  核心首帧只建基线，不下发 0/假值；下线核心移除。
- 测试：稀疏 cpu0/2/4；cpu1 下线后 cpu2 仍 10% 而非 100%；恢复；总数不变；
  标签准确。

### 4.8 R3d：面板/Web（#37/#38/#39/#41）

**#37 刷新时间窗口**

- 抽取纯函数 `refreshRange(rangeKey)`：非 custom 用 `presetRange` 当前时间
  重算，custom 保持用户范围。
- 刷新/错误重试都走该函数；请求仍由 `queryRange` 驱动。
- 测试：固定时钟 T0/T1，刷新后 to=T1；custom 不变；加载失败后重试；
  多次刷新不累积偏移。

**#38 告警 401**

- `hub_reply_to_response_verbatim`（告警与归档透传）对 401 改为
  `json_error(502, "hub_auth_failed")`；其余 400/403/404/409/502 保持透传。
  普通代理路径已有同样映射。
- 前端 401 全局登出逻辑不变；这些路由不再收到 Hub 401。
- 测试：Panel 告警/归档全部 route 的 401→502；有效 Panel Cookie 不登出；
  Panel 自身 401 仍登出；响应不泄露上游 body/token。

**#39 panel init TLS**

- `panel init` 无 `--hub` 时读取 Hub 的 `admin_tls` 与 `tls.mode`：
  - Off → http；
  - Required + 自签 → https + `hub_ca=<hub data_dir>/certs/ca.crt`；
  - Required + ACME → https + 系统根（hub_ca 空）；
  - 无法判断 CA → 失败并提示 `--hub-ca`，不生成“看似成功但连不上”的配置。
- 新增 `--hub-ca`（复制/校验 PEM，写 `hub_ca`）；显式 `--hub` 仍按 URL
  scheme，缺 CA 时明确报错。
- 测试：Off/Required、自签/ACME、回环/通配、显式覆盖；本地 HTTPS Hub init
  后 overview 成功；错误 CA 不被静默关闭校验。

**#41 标签原型键**

- `buildFilterLabels` 用 `Object.create(null)` 或 `Object.fromEntries`。
- 测试：普通键、`__proto__`、`constructor` 创建/编辑/JSON roundtrip；
  与后端 `filter_labels` 语义一致。

### 4.9 R3e：CI（#40）

- `.github/workflows/ci.yml` 增加 `python3-cryptography` 安装与
  `bash tests/e2e/v031.sh`，放在 control 之后、v032 之前。
- 断言 CI 日志出现 v031 的过期证书自愈/慢连接阶段；失败必须 job 非零。
- `actionlint`、`bash -n`、`shellcheck` 纳入门禁；`v031.sh` 依赖写入
  tests/e2e/README。
- 普通 CI 不跑 24h/1000 agent；长稳仍由发布阶段手工/定时任务执行。

## 5. 接口、配置与兼容性

### 5.1 协议与 API

- 协议仍为 v2；不新增帧、不改 Hello/Batch/Ack 语义。
- #50 时间戳拒绝使用现有 ACK（丢弃）语义，不新增负 ACK；审计/指标记录。
- 归档对象 key 新增 `-v8` 后缀；API 字段仍为字符串，列表/下载/UI 兼容。
- `archive status` 增加 `ledger_pending`、`ledger_rebuild` 进度字段（additive）。
- `maintenance status` 增加 `unaggregated_rows`、`invalid_timestamp_rows`、
  `archive_ledger_pending`（additive）。
- 其余 HTTP API 不变；告警 401 改为 502 是行为修复，错误码 `hub_auth_failed`
  已有普通代理先例。

### 5.2 配置

| 配置 | 默认 | 说明 |
|---|---|---|
| `agent.toml` `connect_timeout_secs` | 10 | 1–60；覆盖 DNS/TCP/TLS/101 |
| `agent.toml` `allow_insecure_ws` | false | 非回环 ws 必须显式开启；仅开发/隔离网络 |
| `hub.toml` `[ingest] max_late_days` | 30 | 不得 >= `retention_1m_days`（非 0，至少留 2 天）；0 表示只接受未来偏差内的样本 |
| `hub.toml` `[ingest] max_future_skew_secs` | 300 | 0–3600 |
| `panel init --hub-ca PATH` | — | 新 CLI 参数；写入 `hub_ca` |

- 旧配置缺字段使用默认值；`max_late_days` 对旧 agent 的长缓冲是行为收紧，
  写入 CHANGELOG/升级说明。
- `allow_insecure_ws` 默认 false 是安全收紧；远程 ws 用户必须改 wss 或显式
  开启并接受明文风险。
- schema v8 是单向升级；升级前必须备份。

### 5.3 兼容性结论

| 对象 | 结论 |
|---|---|
| 旧 agent → 新 hub | 协议不变；时间戳超界批次会被 ACK 丢弃（审计）；其余正常 |
| 新 agent → 旧 hub | 新配置字段旧 hub 不使用；`connect_timeout` 在客户端生效；ws 策略在客户端生效 |
| v7 SQLite 库 | 自动迁移 v8；新 v8 二进制拒绝更高版本；v7 旧二进制无法识别 v8，升级后不得再用，回退恢复备份 |
| v7 PostgreSQL | `schema_migrations` 升 8；旧二进制已有拒绝门禁 |
| v7 归档对象 | 保留；ledger pending 时重新导出仍存在的 raw；旧对象不删除 |
| v7 buffer | 记录格式不变；新增 `buffer.meta.bak`，旧 agent 忽略；可降级 |
| 远程 ws 部署 | 默认拒绝，需 wss 或 `allow_insecure_ws=true`（破坏性安全修复） |
| 长缓冲 >30d | 超界样本 ACK 丢弃；需调大 `max_late_days` 且同步 1m 保留 |
| rc.2 | 不移动；新修复进入 `v1.0.0-rc.3` |

## 6. 测试计划

### 6.1 单元与集成

- 每条 issue 至少：正常路径、边界值、错误路径；数据类加 SQLite/PG parity。
- 关键并发/故障注入：
  - archive claim 并发、kill -9 于 claim/upload/status 三个点；
  - downsample/retention/ingest Barrier 交错；
  - alert engine/notify worker Barrier；
  - buffer meta/中间字节/尾部撕裂；
  - enrollment 每个写点崩溃/ENOSPC；
  - exec 父/后代/超时/正常退出；
  - connect 黑洞/DNS/TLS/101；
  - 证书跨两个周期；
  - panel init Off/Required/自签/ACME。
- Fuzz：buffer 恢复随机翻转；Batch/Frame 解码；archive key/CSV manifest
  解析（阶段测试 ≥5 分钟，语料入库）。

### 6.2 端到端

新增或扩展：

- `tests/e2e/v100-data-integrity.sh`
  - 归档迟到/重试/崩溃/ledger 迁移；
  - downsample→retention 交错、raw 删除后 late、1h 重算；
  - 时间戳边界/i64；SQLite + PG 两套。
- `tests/e2e/v100-agent-lifecycle.sh`
  - 建连黑洞、续签两周期、持续 backlog 证书检查、enrollment 崩溃恢复、
    exec 进程组、ws 策略。
- `tests/e2e/v100-panel.sh`
  - 刷新窗口（web 单测 + 浏览器可选）、告警 401、init TLS/CA、`__proto__`。
- `tests/e2e/v031.sh` 入 CI。
- 重跑 `v100-pg-tls.sh`（27/27）、`v100-docker-pg.sh`（104/104）、
  `v100-install.sh`、`v100-arm64.sh`、`v100-load.sh`。
- 24h：200 agent，RssAnon 基线按 R5 预检确定的 warmup（当前 1h 基线在 2h
  出现 +11.49% 台阶，见 §8.7；先做 3h/2h warmup 预检），FD/线程 delta ≤32，
  0 丢/重/错，health 0 失败，hub PID 不变；最终二进制。

### 6.3 门禁

每次提交：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo audit
```

阶段另加：

- PG 实库：`postgres_schema`、`postgres_core`、`postgres_parity`、
  `postgres_migrate`、`phase_d_backup`；
- `actionlint .github/workflows/ci.yml`；`bash -n` / `shellcheck` 脚本；
- `web`: `pnpm test`、`pnpm typecheck`、`pnpm build`；
- 独立评审 + 渗透；严重问题修复后换新评审复审；
- CI 全绿，不以本地通过替代。

## 7. 执行顺序与角色

### 7.1 阶段

| 阶段 | 内容 | 依赖 | 粗略人日 |
|---|---|---|---|
| R0 | 失败测试/复现资产、schema/接口评审、worktree | 本计划确认 | 1–2 |
| R1a | schema v8 + archive ledger（#27/#28） | R0 | 6–8 |
| R1b | downsample/retention/时间戳（#32/#33/#50） | R1a schema | 6–8 |
| R1c | DiskBuffer（#34） | 可与 R1b 并行 | 2–3 |
| R2 | agent 生命周期/安全（#42–#46/#48） | R0 | 6–8 |
| R3a | WebDAV（#29） | R0 | 2 |
| R3b | 告警（#30/#31） | R0 | 2–3 |
| R3c | 采集器（#35/#36） | R0 | 2 |
| R3d | 面板/Web（#37/#38/#39/#41） | R0 | 3–4 |
| R3e | CI（#40） | R3a–R3d 脚本 | 0.5 |
| R4 | 集成、全量门禁、评审、渗透 | 全部 | 4–5 |
| R5 | 重建 dist、rc.3、24h、PG/Docker、发布 | R4 | 3 + 24h |

粗略 **35–45 人日**；#27/#28/#32/#33 占一半以上。R1c/R2/R3 可在不同
worktree 并行，但共享 schema 的 R1a→R1b 必须串行。

### 7.2 角色与提交

- 主 Agent：方案、拆任务、集成、提交、tag；不写业务实现。
- 每个 cluster：编码子 Agent + 独立测试子 Agent + 独立评审子 Agent；
  同一个人格不得既写又评。
- 提交按 Conventional Commits 中文摘要；一 issue 或一个内聚 cluster 一提交；
  修复用追加提交，不改写已推送历史。
- 独立评审发现严重项：回到修改→全量门禁→换新评审复审；同一问题 3 轮
  不通过停止报告。
- 渗透测试整份清单重跑，不只复测失败项。

## 8. 发布门禁与长稳

1. 22 条待修全部修复并补充证据评论；#47/#49 复核已修并补评论；issue
   关闭由用户确认。`v1.0.0-rc.2` 不动。
2. 修复后重建 amd64/arm64 dist、Docker 镜像、离线包，重新生成
   `target/dist-manifest.txt`（当前 manifest 已过时）。
3. 打 **`v1.0.0-rc.3`**（新 tag），跑：
   - 全量门禁 + PG 实库 + web；
   - 100/500/1000 agent（1000 至少 10min，记录 60000 批/180000 点口径）；
   - **24h 200 agent** 在 rc.3 最终二进制上重跑，RssAnon 门禁；
   - TLS PG 27/27、Docker PG 104/104、arm64 安装/离线/升级/卸载/恢复。
4. 最终独立评审 + 全量渗透；无未修复高危/中危。
5. 只有全部通过，才归档 CHANGELOG、升版本、打 `v1.0.0`、发 Release/镜像。
6. 当前 `3f916a0` 的 24h soak 仅作为基线参考，**不能作为修复后最终证据**；
   #27/#32/#33/#50 都在 hub 维护/入库路径，修复后必须重跑。
7. **1h warmup 尚未被证明足够**：2026-10-27 的静态 musl 200 agent 运行在
   2h 时 RssAnon 从 1h 中位 46,028 KiB 升到 51,316 KiB（**+11.49%**，超过
   10% 门禁），但上升是 elapsed≈6739s 的一次 3.5 MiB 台阶，随后基本持平；
   FD 223、线程 81、0 错误/重试/重连。已停止并保留证据，不能据此判定产品
   泄漏，也不能让 1h 基线直接进入最终签发。
   R5 必须先做 **3h 预检**：2h warmup 后 2h→3h RssAnon 平稳则改用 2h
   warmup；若仍持续上涨，按产品缺陷处理，不得换基线掩盖。

## 9. 回滚

| 变更 | 回滚 |
|---|---|
| schema v8 | 迁移前备份；v7 二进制无法识别 v8、升级后不得再用；回滚需恢复 DB 备份，不能直接降级 |
| archive ledger | 旧对象保留；`-v8` 对象可保留/人工清理；恢复 v7 备份后水位回旧 |
| downsample 增量 | 旧 1m/1h 数据保留；回滚恢复备份；不自动重建 |
| DiskBuffer | 记录格式不变；`buffer.meta.bak` 旧 agent 忽略；可直接降级 |
| 配置新增 | 旧配置缺省；`allow_insecure_ws` 回滚为 false 仍安全；`max_late_days` 调大/关闭需重启 |
| 发布 | rc.3 失败不打 v1.0.0；新问题打 rc.4，不移动 rc.2/rc.3 |

## 10. 风险与待确认决策

| 决策/风险 | 建议 |
|---|---|
| 归档 ledger 迁移需要重导仍存在的 raw，冷存储出现重复对象 | 自动执行、retention fail-closed；旧对象保留；文档给清理命令。大量数据时在维护窗口升级 |
| #50 采用 ACK 丢弃而非负 ACK | 协议 v2 无负 ACK；ACK 丢弃避免重连风暴，审计计数；若要求严格负 ACK，另立协议 v3 |
| `max_late_days=30` 对超长离线缓冲是行为收紧 | 默认与 1m 保留留 60d 余量；需要更长补传时同步调大 1m 保留并验证 |
| `ws://` 默认拒绝是 breaking change | 安全修复；远程用户改 wss 或显式 opt-in；CHANGELOG/升级说明 |
| 24h 需重跑，发布延后 | 修复路径影响 hub 维护，不能复用旧 soak；按 R5 重跑 |
| 1h RssAnon 基线过早 | 当前 2h 已有 +11.49% 单台阶；R5 先做 3h/2h warmup 预检，平稳才改基线，否则按产品缺陷处理，不能用调基线掩盖 |
| #34 双 meta 两者都坏时 fail-closed | 不静默复活 ACK 数据；保留文件并给恢复指引；比丢数据安全 |
| 全量 22 条周期长 | 先做 R1/R2 硬阻断；R3 可并行；不建议拆到 1.0.1 后再修数据类 |

## 11. 停止点

本文件确认前：不创建 worktree、不改业务代码、不打 tag、不移动 rc.2。
确认后按 R0 → R1a → R1b → R1c/R2/R3 → R4 → R5 执行；每个阶段完成即更新
本文件状态与证据链接。
