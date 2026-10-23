# M4 告警与归档方案（v0.4.0）

> 基线：`main@5420a36`（v0.3.5 发布后）。对应需求：
> [requirements.md](../requirements.md) §7.2/§7.3/§11 与 M4 验收标准。
>
> 目标：在 SQLite 单机形态下交付 **分层降采样/保留期、阈值与内置告警、
> Telegram/企业微信/钉钉/飞书通知、S3/WebDAV/SFTP 冷归档**，并提供面板端
> 告警与数据管理页面。**不引入 PostgreSQL、ACME、安装器**，不改变线协议版本
> 与证书格式。

## 0. 执行要求

1. 本方案分 M4-A/B/C/D 四个阶段，每阶段独立提交、独立测试；任何阶段不通过
   不得进入下一阶段。阶段完成可打 `checkpoint/<日期>-m4-<阶段>`，最终才打
   `v0.4.0`。
2. 所有 schema 变更必须是**纯新增表/索引**，不重写 `samples`、`agents` 等既有表；
   v0.4.0 库必须能被 v0.3.5 二进制打开（旧版本忽略新表，不回滚 `user_version`）。
3. 告警通知、归档上传、保留期删除都必须是**可重试、幂等、失败不丢数据**；
   删除本地行之前必须有成功的归档记录（归档启用时）。
4. 通知渠道/归档后端的 secret 不得进入 API 响应、日志、错误消息或前端 bundle；
   数据库/配置必须 0600，data_dir 0700。
5. M4 的所有时间窗口统一使用 **UTC 毫秒**；bucket 边界按 UTC 对齐。
6. 方案提交后暂停，不写业务代码；等用户压缩上下文并给出开工指示后，再创建
   `.worktrees/m4`，从 M4-A1 开始。

## 1. 目标与验收

### 1.1 降采样与保留

- raw（原始点）默认保留 7 天；1m（min/max/avg/last/count）默认 90 天；
  1h 默认 2 年；三者均可配置，`0` 表示该层不自动删除。
- 后台任务每分钟把已关闭的 1m bucket 从 raw 聚合，每小时把已关闭的 1h bucket
  从 1m 聚合；重复执行结果不变，迟到数据可被最近窗口重算修正。
- 查询按跨度自动选层：≤6h raw，≤7d 1m，更长 1h；显式 `bucket_ms` 低于当前层
  粒度时自动提升到层粒度并在响应返回实际值，不因旧客户端的细分桶请求而报错。
  默认曲线值取 `avg`；min/max/last/count 保留在库中供后续 API 使用。
- 保留期任务按层分批删除过期行；启用归档时 raw 只有在对应范围归档成功后才删除。

### 1.2 告警

- 规则：`metric` + `comparator` + `threshold` + `duration_secs`，可按 agent 与
  labels 过滤；支持 `gt/gte/lt/lte/eq/ne`。
- 内置规则：agent 离线（`last_seen` > 90s）、磁盘使用率 > 90%、
  证书剩余 < 48h（agent 客户端证书 + hub 服务端证书）、agent 缓冲积压 > 80%。
- 状态机：`pending` → `firing` → `resolved`；同一规则同一序列在冷却期
  （默认 30 分钟）内不重复通知；恢复通知可开关；支持手动静默 N 小时。
- 每个 firing/resolved 产生 `alert_events` 记录；静默期间事件仍记录但
  `notified=false`。通知失败只记录错误，不丢事件、不影响规则评估。
- 四个渠道：Telegram、企业微信、钉钉（加签）、飞书（签名）；每个渠道可
  “发送测试消息”。真实发送失败不得 panic，不得回显 secret。

### 1.3 冷归档

- 每天 UTC 03:00 把超过 `archive.after_days`（默认 7 天）的 raw 行导出为
  `csv.gz` + `manifest.json`，上传到 S3 / WebDAV / SFTP 之一。
- manifest 包含行数、时间范围、对象 key、sha256、格式版本；上传成功后写
  `archive_objects` 状态，再分批删除本地 raw 行；上传/校验失败保留本地行并告警。
- 归档文件可在面板“数据管理”页下载；下载流式转发，不进入浏览器内存；
  不支持直接查询冷数据。
- 三个后端实现同一个 `ColdStore` trait；`test()` 必须能验证凭据/连通性，
  面板/CLI 可触发。

### 1.4 验收

- M4-A：v6→v7 迁移幂等，旧表数据不变；1m/1h 聚合值与 SQL 手算一致；重复
  downsample 不增行/不改值；raw/1m/1h 保留删除边界正确；查询选层正确。
- M4-B：配置阈值/持续时长/冷却/静默后，firing/resolved 与事件数符合预期；
  离线默认 90s、可配短值用于 e2e；四渠道 test 成功；通知失败可重试；
  secret 在 API/日志/前端均不可见。
- M4-C：WebDAV mock 上文件可下载且 sha256 与 manifest 一致；上传失败不删除
  raw；先标记后删除；S3/SFTP 通过 fake `ColdStore` 单测与依赖 spike。
- M4-D：新增 `v040.sh`，既有 10 套 e2e 全绿；CI、audit、review、pentest 全绿。

## 2. 范围与非目标

### 2.1 范围

| 阶段 | 内容 | 主要文件 |
|---|---|---|
| M4-A | schema v7、downsample/retention、查询选层、maintenance CLI | `core/storage/{mod,sqlite}.rs`、`core/downsample.rs`、`common/config.rs`、`hub/main.rs`、测试 |
| M4-B | 告警规则/状态/事件/静默、内置指标、四渠道通知、告警 API/UI | `core/alerts.rs`、`core/storage/*`、`hub/{alerts,notify,main,auth}.rs`、`agent/main.rs`、`core/collect/disk.rs`、`panel/*`、`web/*` |
| M4-C | ColdStore、S3/WebDAV/SFTP、归档任务/对象/下载、数据管理页 | `hub/{archive,main}.rs`、`hub/archive/*`、`core/storage/*`、`common/config.rs`、`panel/*`、`web/*` |
| M4-D | e2e、CI、文档、评审/渗透、发布 | `tests/e2e/v040.sh`、`v040_*.py`、CI、README、CHANGELOG、status、known-issues |

### 2.2 明确不做

- PostgreSQL 存储、`label_hash`/xxhash 索引优化：当前 SQLite 单机先保证正确性，
  PG 与跨库优化留到 M5 或单独里程碑。
- ACME / 证书短周期、安装器、离线包、Docker 镜像（M5）。
- 告警表达式语言、布尔组合、日志告警、APM/追踪、异常检测。
- 任意自定义 webhook URL、SMTP/短信、企业微信应用消息（只做群机器人）。
- 冷数据在线查询、按标签跨 agent 聚合查询、归档增量压缩/去重。
- 字段级加密/KMS、TOTP、多用户 RBAC。
- 修改协议帧、协议版本、DB 既有表、证书格式。

## 3. 现状与设计约束

- 当前 schema v6：`samples` 为窄表 `(agent_id, metric, labels, ts, value)`；
  `query_series_bucketed` 目前直接对 raw 做 SQL 分桶；没有 1m/1h 表。
- `HubConfig` 已有 `retention_raw_days` / `retention_1m_days` / `retention_1h_days`
  字段，但尚未被后台任务使用，也缺少完整校验。
- hub 已有 `tokio` 后台任务模式（证书续签、吊销轮询、自监控），可直接承载
  maintenance 与 alert ticker；写 SQLite 必须 `spawn_blocking`，不能阻塞 runtime。
- 当前 agent 指标包含 `disk.used/disk.total`，但没有百分比、缓冲积压或
  `cert.days_left`；M4 需要新增这三个 additive 指标，不新增协议帧。
- 面板代理目前是显式 allowlist，归档下载不能复用 8MiB JSON 缓冲逻辑，需要独立
  流式下载路由。
- 通知/归档涉及新的出站 HTTP 与文件传输依赖，必须先做依赖 spike（见 §12）。

## 4. 数据模型（schema v7，纯新增）

### 4.1 降采样

```sql
CREATE TABLE samples_1m (
  agent_id TEXT NOT NULL,
  metric TEXT NOT NULL,
  labels TEXT NOT NULL DEFAULT '{}',
  bucket_ts INTEGER NOT NULL,
  min_value REAL NOT NULL,
  max_value REAL NOT NULL,
  avg_value REAL NOT NULL,
  last_value REAL NOT NULL,
  count INTEGER NOT NULL,
  PRIMARY KEY (agent_id, metric, labels, bucket_ts)
);
CREATE INDEX idx_samples_1m_lookup ON samples_1m(agent_id, metric, bucket_ts);
CREATE INDEX idx_samples_1m_ts ON samples_1m(bucket_ts);

CREATE TABLE samples_1h ( ... 同构，bucket_ts 为 UTC 整点 ... );

CREATE TABLE maintenance_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
```

### 4.2 告警

```sql
CREATE TABLE alert_rules (
  id TEXT PRIMARY KEY,              -- UUID；内置规则用 builtin-* 固定 id
  name TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'metric', -- metric | agent_offline | hub_cert
  metric TEXT NOT NULL DEFAULT '',
  comparator TEXT NOT NULL DEFAULT 'gt', -- gt|gte|lt|lte|eq|ne
  threshold REAL NOT NULL DEFAULT 0,
  duration_secs INTEGER NOT NULL DEFAULT 0,
  cooldown_secs INTEGER NOT NULL DEFAULT 1800,
  filter_agent_id TEXT,             -- NULL=全部
  filter_labels TEXT NOT NULL DEFAULT '{}',
  channel_ids TEXT NOT NULL DEFAULT '[]', -- JSON 数组，引用 notification_channels.id
  notify_on_resolve INTEGER NOT NULL DEFAULT 1,
  is_builtin INTEGER NOT NULL DEFAULT 0,
  updated_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE alert_states (
  rule_id TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  series_key TEXT NOT NULL DEFAULT '', -- metric+labels 的稳定编码；合成规则为空
  state TEXT NOT NULL DEFAULT 'pending', -- pending|firing|resolved
  since INTEGER NOT NULL,
  last_eval_at INTEGER NOT NULL,
  last_value REAL,
  last_notified_at INTEGER,
  PRIMARY KEY (rule_id, agent_id, series_key)
);

CREATE TABLE alert_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  agent_id TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL,              -- firing|resolved
  value REAL,
  message TEXT NOT NULL DEFAULT '',
  notified INTEGER NOT NULL DEFAULT 0,
  notify_error TEXT NOT NULL DEFAULT '',
  silenced INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_alert_events_ts ON alert_events(ts);
CREATE INDEX idx_alert_events_rule_ts ON alert_events(rule_id, ts);
CREATE INDEX idx_alert_events_agent_ts ON alert_events(agent_id, ts);

CREATE TABLE alert_silences (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id TEXT,                     -- NULL=全部规则
  agent_id TEXT,                    -- NULL=全部 agent
  until_ts INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE notification_channels (
  id TEXT PRIMARY KEY,              -- UUID
  name TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL,               -- telegram|wecom|dingtalk|feishu
  config_json TEXT NOT NULL,        -- 渠道参数，含 secret；API 永不返回原文
  enabled INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
```

`alert_rules` 的 `channel_ids` 不做外键，保存/更新时校验所有 id 存在且 enabled；
删除渠道前若被规则引用，返回 409 `channel_in_use`，不静默解绑。

### 4.3 归档

```sql
CREATE TABLE archive_objects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  backend TEXT NOT NULL,            -- s3|webdav|sftp
  object_key TEXT NOT NULL UNIQUE,
  manifest_key TEXT NOT NULL,
  from_ts INTEGER NOT NULL,
  to_ts INTEGER NOT NULL,
  rows INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  status TEXT NOT NULL,             -- uploading|uploaded|local_deleted|failed
  error TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  uploaded_at INTEGER,
  deleted_at INTEGER
);
CREATE INDEX idx_archive_objects_range ON archive_objects(from_ts, to_ts);
CREATE INDEX idx_archive_objects_status ON archive_objects(status);

CREATE TABLE archive_state (
  key TEXT PRIMARY KEY,             -- last_archived_ts 等
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
```

## 5. 降采样与保留（M4-A）

### 5.1 聚合任务

- 任务循环每分钟（可配置 `maintenance_interval_secs`，默认 60）执行：
  1. 计算已关闭的 1m bucket：`bucket_end <= now - 60_000`；
  2. **重算最近 2 个已关闭 bucket**（覆盖迟到/重传批次），按主键 upsert；
  3. 从 `samples_1m` 聚合已关闭的 1h bucket，重算最近 2 个小时；
  4. 更新 `maintenance_state` 水位；只推进到已完整聚合的 bucket。
- 聚合 SQL 不做字符串拼接；labels 原样比较/分组，避免 JSON 归一化不一致。
- `last_value` 取 bucket 内 `MAX(ts)` 对应行；同 ts 多行取稳定排序（ts desc,
  rowid desc）后第一条。聚合在单写事务中分批提交，单批不超过 5,000 行。
- 首次启用时做 backfill：从 raw 最旧行开始按小时分块生成 1m/1h；不阻塞启动，
  进度写入 `maintenance_state`；backfill 完成前保留任务仍按归档/保留规则保护 raw。
- 迟到数据容错：最近 2 个 bucket 每次重算；1h 依赖 1m 已更新；幂等 upsert。
- 失败只记录 `WARN` 与 `maintenance_state.last_error`，不 panic；下一轮重试。

### 5.2 查询选层

- `GET /api/v1/agents/{id}/series` 计算时间跨度，选层：
  - `≤6h` → raw；
  - `≤7d` → 1m（若 1m 保留期更短，取可用范围）；
  - 更长 → 1h。
- 现有 `series` 最大跨度只有 32 天，与 1h 默认保留 730 天冲突；M4 放宽到
  **730 天**，仍受单次 20,000 点 / 50 序列上限约束。超出 730 天返回参数错误。
- 显式 `bucket_ms`：小于当前层粒度时**自动提升**到层粒度（例如 30d 查询请求
  60s → 实际 1h），响应回显实际值；不返回 400，避免旧面板/客户端长跨度请求
  突然失败。响应保留 `points: [[ts,value]]`，新增 `tier: "raw"|"1m"|"1h"` 与
  非破坏性 `bucket_ms`；`value` 默认为 avg。
- 1m/1h 表也支持 `latest_samples` 的回退查询：raw 窗口无数据时，按 tier 回落，
  避免保留期删除后面板空白。
- 现有 `query_series_bucketed` 保留作 raw 路径；新路径按客户端跨度的层选择，
  不改变原有 2000 点/20000 点上限。

### 5.3 保留期

- 每日 UTC 04:00（或 maintenance 循环中的 `retention_due`）按层删除：
  raw `ts < now - retention_raw_days`，1m/1h 同理；`0` 表示该层不删。
- 删除按 5,000 行/批，单批事务；批间让出写锁，避免长时间阻塞 ingest。
- 归档启用时：raw 只删除 `archive_state.last_archived_ts` 之前且已成功归档的范围；
  未归档成功的最旧 raw 行及其后行保留，并记录 `archive_blocked` 状态。
- 保留期不能删除尚未完成 downsample 的最近窗口；水位不足时跳过并下轮重试。
- 校验：`retention_raw_days` 0..3650、1m 0..3650、1h 0..7300；
  非 0 时要求 `1m_days >= raw_days`、`1h_days >= 1m_days`（可在启动时放宽为
  WARN + 自动取 max，但默认拒绝明显倒挂）。

### 5.4 运维 CLI

新增只读/一次性命令，便于排障和 e2e，不依赖运行中的 hub：

```bash
rustboard-hub maintenance run --config hub.toml --task downsample
rustboard-hub maintenance run --config hub.toml --task retention
rustboard-hub maintenance run --config hub.toml --task archive
rustboard-hub maintenance status --config hub.toml
```

输出 JSON：处理 bucket 数、删除行数、归档对象数、watermark、错误。任务使用
同一 SQLite 写锁语义，不与运行中的 hub 并行迁移；若锁忙返回明确错误。

## 6. 告警引擎（M4-B）

### 6.1 规则与内置项

- 规则来源 `metric`：查询该 metric 的最新 raw 样本；按 `filter_agent_id` /
  `filter_labels`（精确子集）匹配序列；每个匹配序列独立状态。
- `agent_offline`：比较 `now - agents.last_seen_at` 与阈值（默认 90s）；每个
  agent 一条状态，agent 恢复 online 后 resolved。
- `hub_cert`：读取当前 live/disk 服务端证书 `days_left`；低于阈值 firing；
  hub 证书轮换/续签后自动 resolved。
- 内置规则初始 **disabled**，避免升级后无渠道时产生意外通知；面板“启用”并
  绑定渠道后生效。种子规则 id：
  `builtin-agent-offline`、`builtin-disk-percent`、`builtin-agent-cert`、
  `builtin-hub-cert`、`builtin-buffer-backlog`。
- 新 agent 指标（additive，不改协议）：
  - `disk.used_percent`：每个 mount 的已用百分比 0..100；
  - `buffer.pending_ratio`：本地待发送字节/上限，0..1；
  - `buffer.pending_bytes`：绝对字节数；
  - `cert.days_left`：客户端证书剩余天数。
  旧 agent 不上报这些指标时，对应规则只跳过，不报错、不误 firing。

### 6.2 状态机与通知

- 每 `alerts.evaluation_interval_secs`（默认 15s）执行一轮；每轮最多处理
  `max_rules`（默认 200）条规则，查询使用 `spawn_blocking`，单轮不得超过
  `evaluation_budget_ms`（默认 5s），超时记录 WARN 并跳过本轮。
- 条件连续满足 `duration_secs` 后进入 firing；条件不满足即 resolved（不做额外
  恢复持续时长，避免恢复延迟）；firing 后 `cooldown_secs` 内不重复通知。
- `alert_events` 每个状态转换一条；静默命中时写 `silenced=true`、`notified=false`，
  不发送；静默到期后下一次状态转换才重新通知。
- 通知在独立有界队列（容量 256）中异步执行；队列满时事件 `notify_error=queue_full`，
  不阻塞评估。每个通知最多重试 `notify_max_attempts`（默认 3）次，指数退避
  1s/5s/15s；HTTP 超时 `notify_timeout_secs`（默认 10s）。
- 事件保留 90 天或 100,000 行（先到者），每小时清理；resolved 状态保留 30 天。

### 6.3 静默与恢复

- `POST /api/v1/alerts/silences`：`rule_id`/`agent_id` 可空（空=全部），
  `duration_secs` 1..=7d；`DELETE` 撤销。
- 同一规则/序列在静默期内不通知；状态仍更新；面板显示“静默至”。
- 恢复通知 `notify_on_resolve` 默认开；恢复通知不受 cooldown 限制，但受静默限制。

### 6.4 通知渠道

| kind | 必填配置 | 端点（固定） | 签名 |
|---|---|---|---|
| Telegram | `token`、`chat_id` | `https://api.telegram.org` | 无 |
| 企业微信 | `key` | `https://qyapi.weixin.qq.com/cgi-bin/webhook/send` | 无 |
| 钉钉 | `access_token`、`secret` | `https://oapi.dingtalk.com/robot/send` | timestamp + HMAC-SHA256 |
| 飞书 | `webhook_token`、`secret` | `https://open.feishu.cn/open-apis/bot/v2/hook` | timestamp + HMAC-SHA256 |

- **禁止用户填写任意 URL**，只允许上述 host + 固定 path，防 SSRF；渠道配置只
  保存 token/secret 等参数。
- `config_json` 中的 token/secret 只存 SQLite（0600，data_dir 0700）；API 返回
  `configured=true` 与掩码字段，永不返回原文；日志/错误只记录渠道 id/kind/HTTP
  状态，不记录请求体与 URL query。
- `POST /api/v1/alerts/channels/{id}/test` 使用已保存配置发送固定测试消息；
  成功返回 204，失败返回 502 `notify_failed`（不含上游响应正文）。
- 测试可通过注入 `NotifyTransport`（test-only base URL / fake HTTP）覆盖四渠道；
  生产固定端点，不提供任意 URL 配置。

## 7. 冷归档（M4-C）

### 7.1 配置与后端

```toml
[archive]
enabled = false
backend = "webdav"          # s3 | webdav | sftp
after_days = 7              # 必须 <= retention_raw_days（retention 非 0 时）
schedule_hour_utc = 3
max_object_bytes = 33554432 # 单对象上限 32 MiB
prefix = "rustboard"

[archive.webdav]
url = "https://dav.example.com/rustboard"
username = "..."
password = "..."            # 0600 配置

[archive.s3]
bucket = "..."
region = "..."
endpoint = ""               # 空=AWS；兼容 MinIO 时填写
access_key_id = "..."
secret_access_key = "..."
path_style = true

[archive.sftp]
host = "..."
port = 22
username = "..."
password = ""               # 或 private_key_path
private_key_path = "/etc/rustboard/id_ed25519"
remote_dir = "/backup/rustboard"
# 必填：服务器主机公钥的 SHA256 指纹（`SHA256:<base64>`，不含末尾 `=`）。
# 禁止空值 / 接受任意主机密钥；不匹配立即拒绝连接，防中间人。
host_key_fingerprint = "SHA256:..."
```

- 后端 secret 只在 hub.toml（0600）中，不进入 DB/API/前端；面板只显示
  `backend/configured/last_run`。
- 启动时若 `archive.enabled=true`，校验配置完整性与 `after_days` 约束；不
  在线测试后端（避免启动阻塞），`rustboard-hub archive test --config hub.toml`
  或面板“测试”按钮显式测试。
- `prefix` 只允许 `[A-Za-z0-9._-]` 且不得含 `..`/绝对路径；S3 endpoint/WebDAV
  URL 只允许 `http`/`https`，配置由管理员持有（0600），对象 key 全部由
  `prefix + 日期 + 分片` 生成，不接受 API 输入。
- `after_days` 默认 7，必须 `<= retention_raw_days`（retention_raw_days=0 除外）；
  否则拒绝启动，防止“还没归档就被保留期删除”。
- SFTP **必须**配置 `host_key_fingerprint` 并在 SSH 握手时校验；空值、格式错误或
  不匹配一律失败，禁止 `AcceptAnyServerKey` 一类降级。主机密钥轮换需管理员显式
  更新配置。

### 7.2 文件与上传

- 归档单位：按 UTC 天 + 分片（每片最多 100,000 行或 `max_object_bytes`），
  避免单文件内存峰值。
- 文件格式：`csv.gz`（`flate2` rust_backend，纯 Rust），首行
  `agent_id,metric,labels,ts,value`；labels 为原 JSON 文本，字段按 CSV 规则转义。
- 先写临时文件到 `data_dir/archive-tmp/`（0700），计算 sha256/行数；上传
  `objects/<yyyy>/<mm>/<dd>/<shard>.csv.gz` 与同名 `.manifest.json`；manifest
  包含 `format_version/from_ts/to_ts/rows/bytes/sha256/object_key`。
- 所有写入后 `test/head` 校验（后端能力允许时）；失败删除临时文件并保留 raw。
- 上传成功 → 写 `archive_objects(status=uploaded)` → 删除 raw 行（按对象范围，
  5,000 行/批）→ `status=local_deleted`；删除中断可从状态继续。
- 若删除部分失败：保留对象记录，下一轮按范围重试；不会重复上传同一 key
  （`object_key` UNIQUE，先查再传）。
- 归档任务每天 UTC `schedule_hour_utc` 执行；也可 `maintenance run --task archive`
  手动执行。`archive_state.last_archived_ts` 只推进到连续成功范围。
- hub 启动/唤醒时若今天已过计划时间且上次成功日早于今天，立即补跑一次；不会
  等到第二天，也不会因删除任务先跑而丢数据（保留期受 last_archived_ts 门禁）。

### 7.3 ColdStore 与依赖

```rust
trait ColdStore: Send + Sync {
    async fn put(&self, key: &str, data: &[u8]) -> Result<()>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn test(&self) -> Result<()>;
}
```

- S3：`object_store`（AWS feature，rustls），MinIO 用 endpoint/path_style。
- WebDAV：现有 `reqwest`（rustls），PUT/GET/DELETE/HEAD + Basic auth。
- SFTP：`russh` + `russh-sftp`（纯 Rust），私钥优先，密码可选；**必须校验
  `host_key_fingerprint`**，禁止接受任意主机密钥；禁止拉起 `ssh` 子进程。
- 压缩：`flate2` + rust_backend；签名：`hmac` + 已有 `sha2`；异步 trait：
  `async-trait`。
- 新增依赖必须先跑 §12 的 spike；不得引入 openssl/cmake 或改变 rustls/ring
  基线。若 SFTP 依赖无法满足 MSRV/许可，停止并报告，不静默降级为外部命令。

### 7.4 下载

- `GET /api/v1/archive/objects/{id}/download`：Bearer/read scope；校验对象属于
  当前 backend 且 `status in (uploaded, local_deleted)`，从 ColdStore 流式读取。
- 单文件上限 1 GiB；响应带 `Content-Disposition: attachment`，文件名只允许
  `[A-Za-z0-9._-]`，防 header 注入。
- 面板新增独立流式代理（不复用 8MiB JSON 缓冲），同样有 1 GiB 上限；浏览器
  直接收到下载流。
- 下载失败返回固定 502 `archive_unavailable`，不回显后端 URL/凭据。

## 8. API、配置与面板

### 8.1 管理 API（hub）

| 方法 | 路径 | scope | 说明 |
|---|---|---|---|
| GET | `/api/v1/alerts/rules` | read | 规则列表 |
| POST | `/api/v1/alerts/rules` | write | 新建规则 |
| PUT | `/api/v1/alerts/rules/{id}` | write | 修改/启停 |
| DELETE | `/api/v1/alerts/rules/{id}` | write | 删除自定义规则；内置规则只允许禁停 |
| GET | `/api/v1/alerts/events` | read | 分页事件 |
| GET/POST/DELETE | `/api/v1/alerts/silences` | read/write | 静默查询/创建/撤销 |
| GET | `/api/v1/alerts/channels` | read | 渠道列表（secret 掩码） |
| POST/PUT/DELETE | `/api/v1/alerts/channels[/{id}]` | write | 渠道 CRUD |
| POST | `/api/v1/alerts/channels/{id}/test` | write | 测试消息 |
| GET | `/api/v1/archive/objects` | read | 归档对象列表 |
| GET | `/api/v1/archive/objects/{id}/download` | read | 流式下载 |
| GET | `/api/v1/maintenance/status` | read | 降采样/保留/归档水位 |
| POST | `/api/v1/maintenance/run` | write | 手动触发一次任务（可选，CLI 已够） |

- 所有写接口校验 JSON 大小（现有 64 KiB）与字段白名单；规则名称/渠道名称限长
  1..64 字节，labels 过滤最多 16 对、键/值限长，channel_ids 最多 16。
- `required_scope` 增加上述路径；未知路由仍先鉴权后 404。
- 事件/对象分页使用 `before_id` + `limit`（1..100），响应不回显 channel secret。

### 8.2 配置

```toml
[alerts]
enabled = true
evaluation_interval_secs = 15
offline_after_secs = 90
cert_warn_hours = 48
event_retention_days = 90
max_events = 100000
notify_timeout_secs = 10
notify_max_attempts = 3
```

- 旧配置无 `[alerts]`/`[archive]` 时使用默认值；不新增必填字段。
- `retention_*` 从“未使用字段”变为生效字段，保留 `0=不删` 语义；新增范围校验。
- secret 字段在 Debug/错误/日志中必须 `#[serde(skip_serializing)]` 或自定义
  redaction；配置 `Debug` 不得打印 secret。

### 8.3 面板

- 新增 `/alerts` 页面：
  - 规则列表（启用开关、编辑阈值/持续时间/冷却/过滤/渠道）；
  - 事件流分页、状态/静默标记、静默操作；
  - 渠道列表（掩码）、测试按钮、增删改（secret 输入只写不读）。
- 新增 `/data` 页面：
  - 降采样/保留水位、各层行数、最近任务结果；
  - 归档对象列表（时间范围、行数、sha256 前 12 位、状态）、下载按钮；
  - 归档后端 configured/backend 状态（不显示凭据）。
- API client 类型严格；所有新页面复用现有会话/同源保护；浏览器 bundle 中不得
  出现 hub token 或渠道 secret。
- 导航增加“告警”“数据管理”；移动端表格可横向滚动。

## 9. 协议与兼容性

| 变更 | 兼容性 |
|---|---|
| 协议帧 | 不新增/不修改，仍 v2 |
| agent 指标 | 新增 `disk.used_percent` / `buffer.pending_*` / `cert.days_left`，旧 hub 忽略未知 metric |
| SQLite schema | v7 纯新增表/索引；旧表不动；v0.3.5 二进制可打开 v7 库并忽略新表 |
| 证书格式 | 不变 |
| 配置 | 新段有默认值；旧配置可直接启动 |
| 面板 API | 新增路由；旧端点不变 |
| 回滚 | 回 v0.3.5 停止告警/降采样/归档任务；v7 表保留；已删除的 raw 不可恢复（归档对象仍在） |

升级提示：

- 先升级 hub，再升级 agent 以启用磁盘百分比/缓冲/cert 指标；旧 agent 不会
  触发这些内置规则（无数据），其余功能正常。
- 启用归档前先备份 data_dir 并跑 `archive test`；`after_days` 必须不大于 raw
  保留期。
- 渠道 secret 存在 SQLite 0600 中，依赖 data_dir 0700 与宿主机磁盘保护；
  M4 不做字段级加密。

## 10. 实施拆分与顺序

| 任务 | 内容 | 文件边界 | 依赖 |
|---|---|---|---|
| A1 | schema v7、迁移、`maintenance_state`、Storage trait | `core/storage/{mod,sqlite}.rs` | 无 |
| A2 | downsample/retention worker、选层查询、CLI；实施拆为 A2a（worker/CLI）与 A2b（选层查询）两个提交 | `core/downsample.rs`、`core/storage/*`、`hub/main.rs`、`common/config.rs` | A1 |
| B1 | 告警表/状态机/内置规则/规则 API、agent 新指标 | `core/alerts.rs`、`core/storage/*`、`hub/{alerts,main,auth}.rs`、`agent/main.rs`、`core/collect/disk.rs` | A1 |
| B2 | 四渠道通知、测试、重试、脱敏 | `hub/notify.rs`、`hub/main.rs` | B1 |
| B3 | 面板告警 API/页面 | `panel/{main,proxy}.rs`、`web/src/*` | B1/B2 |
| C1 | ColdStore trait、CSV.GZ/manifest、WebDAV | `hub/archive.rs`、`hub/archive/webdav.rs`、`core/storage/*` | A1 |
| C2 | S3（object_store） | `hub/archive/s3.rs`、`Cargo.toml` | C1 + 依赖 spike |
| C3 | SFTP（russh） | `hub/archive/sftp.rs`、`Cargo.toml` | C1 + 依赖 spike |
| C4 | 归档 worker、下载 API、面板数据页 | `hub/archive.rs`、`panel/*`、`web/src/*` | C1–C3 |
| D | `v040.sh`、CI、文档、评审/渗透、发布 | `tests/e2e/*`、CI、README/CHANGELOG/status | 全部 |

顺序：A1 → A2；A1/B1/C1 的 schema 部分先串行落地，随后 A2、B1、C1 可并行
（不同文件）；B2/B3 与 C2/C3/C4 并行；D 最后。B1 与 C1 都改
`core/storage/*`，不得并行，由主 Agent 串行集成。

## 11. 测试策略

### 11.1 Rust 单元/集成

- schema：v6→v7 迁移幂等、旧表行不变、`user_version=7`、重复打开不重复建表；
  旧查询仍可读；新表索引存在。
- downsample：1m/1h 的 min/max/avg/last/count 与手算一致；空 bucket 不建行；
  重复执行幂等；迟到数据重算最近 bucket；跨 UTC 日/小时边界；labels 不同不合并；
  backfill 中断可续。
- retention：三层 cutoff 边界、`0=不删`、分批删除、归档未完成时 raw 不删、
  downsample 水位不足时跳过。
- query tier：≤6h raw、≤7d 1m、>7d 1h；bucket 过小 400；无 raw 时 1m 回退；
  点数上限不变。
- alerts：duration/cooldown/resolve/silence；多 agent/labels；离线 90s；证书
  阈值；磁盘/缓冲指标；规则过滤；事件去重；状态持久化重启；规则数上限。
- notify：四渠道 payload/签名（固定向量测试）、超时/重试/队列满、secret 不出现在
  Debug/日志/错误；test 端点成功/失败；钉钉/飞书签名使用固定时间戳向量。
- archive：CSV 转义/UTF-8/gzip 解压后内容、manifest sha256、分片上限、上传成功
  才删 raw、上传失败不删、删除中断恢复、对象 key 唯一、下载鉴权/文件名净化；
  S3/WebDAV/SFTP 各自 fake ColdStore + 失败注入。
- 面板：新 API 类型/错误映射、secret 掩码、下载流上限、同源/会话、路径穿越。

### 11.2 e2e（`v040.sh`）

新增 `tests/e2e/v040.sh`（可加 `v040_archive_mock.py` / `v040_notify_mock.py`），
使用真实 hub/agent + 本地 mock，覆盖：

1. **downsample/retention**：用 fake agent 写入跨 8 天的旧 raw（或调用
   `maintenance run` 前用测试 helper 注入），触发 downsample；断言 1m/1h 行数、
   查询 tier、raw 过期删除、1m 保留；重启后幂等。
2. **alert**：创建离线规则（`offline_after_secs=3` 仅测试配置），停 agent 后
   ≤5s 产生 firing 事件、冷却内不重复、恢复后 resolved；静默期间 notified=false；
   mock 渠道收到测试消息/告警消息，日志不含 secret。
3. **archive**：WebDAV mock 接收 PUT/GET/HEAD；触发 archive；断言对象+manifest
   存在、sha256/行数一致、raw 对应范围已删、面板下载流 sha256 一致；上传失败
   （mock 500）时 raw 保留。
4. **四个渠道**：通过 `NotifyTransport` 的测试注入验证 payload；真实外部网络不
   在 CI 使用，Telegram/企微/钉钉/飞书固定端点只做签名/payload 单测。
5. **安全**：渠道 secret/admin token 不出现在 hub/panel 日志或 API；归档 key
   不能穿越；下载未登录 401；规则/渠道写接口 scope 403；未知路由先鉴权。
6. 既有 10 套 e2e 全量回归；CI 增加 v040 step；Rust 测试数 ≥ v0.3.5 的 569。

### 11.3 强化

- 并发：downsample 与 ingest 并发、retention 与查询并发、alert tick 与规则
  修改并发、归档删除与查询并发；无死锁、无重复/丢失。
- 故障注入：归档后端 500/超时/中途断连、通知 429/超时、SQLite busy、进程
  kill -9 后任务恢复；不得丢 raw 或重复通知（允许 at-least-once 重复，事件去重）。
- 压力：100 agent × 5s × 30 metric 持续写入时 downsample/alert 延迟可接受；
  1000 条规则上限；归档大表分片。
- 渗透：webhook SSRF、secret 泄露、归档路径/下载、SQL 注入（规则过滤）、
  资源耗尽（规则/事件/归档分片）、权限 scope。

## 12. 依赖 spike（先于 C2/C3）

在动 C2/C3 前单独跑一个 spike 分支，验证：

1. `object_store`（aws feature）在 rust-version 1.80、rustls/ring 下可编译，
   支持自定义 endpoint/path_style、put/get/head/delete；记录版本与许可证。
2. `russh` + `russh-sftp` 不引入 openssl/cmake，能在 rust-version 1.80 下编译，
   支持 ed25519 私钥、密码、超时、目录创建。
3. `flate2` rust_backend、`hmac`、`async-trait` 版本与现有 lock 兼容。
4. 若任一项不满足：停止 C2/C3，提交 spike 报告与替代方案，不静默改用
   `ssh` 子进程或非纯 Rust 依赖。

新增依赖必须写入 PR 说明理由、许可证、MSRV 与替代方案；CI `cargo audit` 保持 0。

### 12.1 spike 结果（2026-10-24，分支 `chore/m4-dep-spike`）

- **1.80**：`object_store 0.11.2` + `russh 0.53.0` 可编译且无 openssl/cmake，
  但 `cargo audit` 为 4 高危 + 1 中危（quick-xml / russh / russh-cryptovec / rsa），
  **不可放行**。
- **1.85**：`object_store 0.14.2`（quick-xml 0.41）可用；`russh 0.60.3` 的
  `ctutils 0.4.2` 仍有 1 高危，升 `ctutils 0.4.4` 需 Rust 1.87；`rsa` 为可选
  依赖、未编译，但仍在 lock 中，cargo audit 报 1 中危。
- **1.87**：`ctutils 0.4.5` 修复高危；`cargo +1.87 check/run` 通过，
  `cargo audit` 只剩 `rsa 0.10.0-rc.16`（RUSTSEC-2023-0071，medium，无修复）。
  `rsa` 是 `russh` 的 optional 依赖，未启用 feature、不在编译图，但 Cargo 会写入
  lock，audit 仍会扫描到。
- **C2（S3）**：`object_store 0.14.2` + `aws-base`/`reqwest`/`ring`，
  quick-xml 0.41，可在 1.85+ 通过 audit；不使用 `aws` 大 feature（会拉
  aws-lc-rs/cmake）。
- **C3（SFTP）**：要同时满足纯 Rust、SFTP、`cargo audit` 0，必须在 1.87+ 且
  对 `russh` 做 **最小 vendor/patch 删除 optional `rsa` 依赖**；否则只能
  放弃 C3，或显式接受一条未编译的 rsa 中危 allowlist。**不得静默 `--ignore`。**
  该选择需在 C3 开工前由维护者确认；C1/C2 不受影响。
- 报告：分支 `chore/m4-dep-spike` 的
  `spikes/m4-deps{,-185,-187}/REPORT*.md`（未合入 main）。

## 13. 风险与回滚

| 风险 | 影响 | 缓解 |
|---|---|---|
| M4 范围大，四渠道 × 三后端 | 延期/质量下降 | 分阶段提交与 checkpoint；C2/C3 依赖 spike 前置 |
| SFTP/ S3 依赖不兼容 | 无法交付全部后端 | spike 失败即停，报告；不以 `ssh` 子进程绕过 |
| 通知重复/丢失 | 告警噪声/漏报 | at-least-once + 事件状态/冷却；失败不丢事件；测试重试 |
| 告警评估使用最新样本 | 短尖峰漏报 | duration 窗口由状态机累计；文档说明 15s 粒度；可配间隔 |
| 保留期删除未归档 raw | 数据丢失 | 归档 watermark + 先标记后删；失败阻塞删除并告警 |
| SQLite 长删除阻塞 ingest | 写入延迟 | 5,000 行/批、批间让锁、spawn_blocking |
| 渠道 secret 存 DB | 磁盘泄露 | DB 0600/data_dir 0700；API 掩码；日志脱敏；建议宿主 LUKS |
| 归档文件过大 | 内存/代理超时 | 32MiB 分片、流式下载、1GiB 硬上限 |
| 规则/事件无限增长 | DB 膨胀 | 规则上限 200、渠道 50、事件保留 100k/90d |
| 旧 hub 打开 v7 | 兼容性 | 纯新增表；v0.3.5 启动验证；不回滚 user_version |

回滚：

- 代码回 v0.3.5：告警/降采样/归档任务停止；v7 新表保留；既有 samples 不变。
- 已归档并删除的 raw 不可恢复；对象仍在冷存储，可手工取回。
- 保留期删除不可逆；启用前备份 data_dir。
- 已发送通知不可撤回；渠道 secret 可轮换。

## 14. 发布门槛

1. M4-A/B/C/D 全部完成，schema v7、协议 v2、证书格式不变。
2. Rust 测试 ≥ 569 + 新增；fmt/clippy/test/audit 全绿；既有 10 套 e2e + v040 全绿。
3. v040 验收：离线告警（测试短阈值）≤5s、四渠道 mock、归档下载 sha256 一致、
   retention 不删未归档数据、secret 0 泄露。
4. 独立评审无 [严重]；渗透无高危；中危必须修复或明确不发布。
5. 更新 CHANGELOG/status/known-issues/README，打 `v0.4.0` tag 并发布 GitHub Release。

## 15. 暂停点

本方案提交后暂停，不写业务代码。等待用户压缩上下文并给出开工指示后，再同步
`main`、创建 `.worktrees/m4`，从 **M4-A1 schema v7** 开始。
