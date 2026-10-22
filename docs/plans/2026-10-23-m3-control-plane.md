# M3 控制面方案（v0.3.0）

> 关联：[requirements.md](../requirements.md) §8.3 / §12 M3；[known-issues.md](../known-issues.md)；[v0.2.1 硬化方案](2026-10-23-v0.2.1-hardening.md)。
> 基线：`main@170e48e` + v0.2.1 修复。协议版本**保持 2**，新增帧只在能力协商后发送。

## 1. 目标与验收

为已纳管 agent 提供四个**默认关闭**的控制面能力：

1. systemd 白名单 unit 的查看、启动、停止、重启；
2. Docker 白名单容器的查看、启动、停止、重启；
3. 进程列表查看、按「PID + 进程名」二次校验后结束；
4. 只读日志：journald 按白名单 unit、白名单文件 tail。

所有变更操作写审计日志，面板提供控制台与审计页。

验收（可直接复现）：

- 重启白名单内 nginx 成功，返回 systemctl 退出码，审计页出现 `systemd.restart / nginx` 记录；
- 对白名单外 unit 操作被拒绝（403/400），审计记录 `denied`；
- 关闭能力后 hub 直接返回 `403 capability_disabled`，agent 也不加载对应模块；
- 日志路径穿越、符号链接逃逸、非白名单文件全部拒绝；
- 进程结束必须 PID + 名称同时匹配，错误名称不发送信号；
- 旧 agent / 旧 hub 互通行为不变（控制能力不可用，但不影响采集）。

## 2. 范围

### 新增文件

| 文件 | 内容 |
|---|---|
| `crates/rustboard-common/src/control.rs` | 控制面线协议类型、能力常量、长度上限 |
| `crates/rustboard-agent/src/control/mod.rs` | 能力校验、分发、错误码 |
| `crates/rustboard-agent/src/control/exec.rs` | 无 shell 命令执行 + 超时 + 输出截断 |
| `crates/rustboard-agent/src/control/systemd.rs` | `systemctl` 列表/动作 |
| `crates/rustboard-agent/src/control/docker.rs` | `docker ps` / 动作 |
| `crates/rustboard-agent/src/control/process.rs` | `/proc` 列表、PID+名称校验、`kill(2)` |
| `crates/rustboard-agent/src/control/logs.rs` | journald / 文件 tail，openat2 防逃逸 |
| `crates/rustboard-hub/src/control.rs` | 控制 API、能力校验、审计写入 |
| `crates/rustboard-hub/src/cert_reload.rs` | v0.2.1 的证书热加载（若未在修复线落地） |
| `web/src/pages/AgentControl.tsx` | 控制台 |
| `web/src/pages/Audit.tsx` | 审计页 |
| `tests/e2e/control.sh` | M3 端到端 |
| `tests/e2e/control_probe.py` | 如需直接发帧/原始 HTTP |

### 修改文件

- `common`：`lib.rs`、`wire.rs`、`config.rs`
- `agent`：`main.rs`、`Cargo.toml`（libc）
- `hub`：`main.rs`、`session.rs`、`Cargo.toml`（如需要）
- `core`：`storage/mod.rs`、`storage/sqlite.rs`（schema v5）
- `panel`：`main.rs`、`proxy.rs`（新增 `post_json`）
- `web`：`App.tsx`、`api.ts`、`types.ts`、`components/Layout.tsx`、`styles.css`
- 文档：`README.md`、`CHANGELOG.md`、`docs/status.md`、`tests/e2e/README.md`

## 3. 接口与数据变更

### 3.1 线协议（MessagePack，协议版本仍为 2）

```rust
pub enum Frame {
    // ... 现有变体 ...
    ControlRequest(ControlRequest),
    ControlResponse(ControlResponse),
}

pub struct ControlRequest { pub id: u64, pub op: ControlOp }

pub enum ControlOp {
    SystemdList,
    SystemdAction { unit: String, action: SystemdAction },   // Start/Stop/Restart
    DockerList,
    DockerAction { container: String, action: DockerAction }, // Start/Stop/Restart
    ProcessList,
    ProcessKill { pid: u32, name: String, signal: KillSignal }, // Term/Kill
    LogList,
    LogTail { source: String, lines: u32 },
}

pub struct ControlResponse {
    pub id: u64,
    pub result: Option<ControlResult>,
    pub error: Option<ControlError>,
}

pub enum ControlResult {
    SystemdUnits(Vec<SystemdUnit>),
    DockerContainers(Vec<DockerContainer>),
    Processes(Vec<ProcessInfo>),
    LogSources(Vec<LogSourceInfo>),
    LogLines { source: String, lines: Vec<String>, truncated: bool, size_bytes: u64 },
    ActionOutput { stdout: String, stderr: String, exit_code: Option<i32> },
}
```

- `id` 由 hub 会话内单调递增分配，只用于匹配；不跨会话复用。
- 所有字符串字段有硬上限：unit/container/source ≤ 128，name ≤ 64，单条日志行 ≤ 4096，输出 ≤ 256 KiB，列表 ≤ 512 项。
- Debug 只输出变体名与 id，不输出命令输出（可能含敏感信息）。
- `Frame::kind()` 增加 `ControlRequest` / `ControlResponse`。

能力常量：`systemd` / `docker` / `process` / `logs`。`AgentHello.capabilities` 只放**实际启用**的能力；旧 hub 忽略该字段，新 hub 对空列表不发送控制帧。

### 3.2 配置

```toml
# agent.toml
[control]
enabled = false
systemd = false
docker = false
process = false
logs = false
systemd_units = []                  # 精确名或尾部 * 前缀，如 ["nginx*"]
docker_containers = []              # 容器名前缀，如 ["web-*"]
command_timeout_secs = 10           # 1–60
max_log_lines = 500                 # 1–2000
systemctl_path = ""                 # 留空按固定候选路径探测
docker_path = ""
journalctl_path = ""

[[control.log_sources]]
id = "nginx-error"
kind = "file"                       # file | journal
target = "/var/log/nginx/error.log" # file 必须是绝对路径；journal 必须是白名单 unit
name = "Nginx 错误日志"

# hub.toml
[control]
enabled = false                     # 总开关
systemd = false
docker = false
process = false
logs = false
request_timeout_ms = 15000          # 1000–60000
max_pending_per_session = 32        # 1–128
max_output_bytes = 262144           # 1024–1048576
```

校验规则：

- 任一能力开启但 `enabled=false` → 启动失败（避免“看起来开了实际没开”）；
- 能力开启但白名单为空 → 启动失败（process 除外，进程列表天然全量）；
- unit 含空白/控制字符/`..`/以 `-` 开头 → 拒绝；禁止 `sshd`、`ssh.service`、`rustboard-*`、`sd-*`、`systemd-*`、`dbus*`；
- 容器名只允许 `[a-zA-Z0-9][a-zA-Z0-9_.-]*` 或尾部 `*`；
- 文件日志必须是绝对路径、父目录存在、非符号链接；`id` 唯一；
- journal 日志的 `target` 必须同时匹配 systemd 白名单，且不在禁止列表。

### 3.3 管理 API

基础：`/api/v1/agents/{id}/control`，Bearer + 限速（写 10/min）+ Origin 校验（面板侧）。

`GET` → 能力状态：

```json
{
  "control_enabled": true,
  "online": true,
  "capabilities": ["systemd", "process", "logs"],
  "hub_capabilities": ["systemd", "process", "logs"]
}
```

`POST` → 执行（请求体）：

```json
{"capability":"systemd","action":"list"}
{"capability":"systemd","action":"restart","target":"nginx.service","confirm":true}
{"capability":"docker","action":"restart","target":"web-1","confirm":true}
{"capability":"process","action":"kill","pid":1234,"name":"sleep","signal":"term","confirm":true}
{"capability":"logs","action":"list"}
{"capability":"logs","action":"tail","source":"nginx-error","lines":200}
```

响应：

```json
{"ok":true,"result":{"type":"systemd_units","units":[...]}}
{"ok":false,"error":{"code":"not_whitelisted","message":"unit 不在白名单"}}
```

错误码与 HTTP：

| 场景 | HTTP | code |
|---|---|---|
| hub 控制面关闭 / 能力未开 | 403 | `capability_disabled` |
| agent 未上报该能力 | 403 | `capability_disabled` |
| 目标不在白名单 | 403 | `not_whitelisted` |
| 参数非法 | 400 | `invalid_request` |
| agent 不在线 | 503 | `agent_offline` |
| 超过 hub 超时 | 504 | `control_timeout` |
| agent 执行失败 | 502 | `control_failed` |
| 待处理命令过多 | 429 | `too_many_pending` |

审计 API：`GET /api/v1/audit?limit=100&before_id=<id>&agent_id=<id>&capability=systemd`

```json
{
  "entries": [{
    "id": 42, "ts": 0, "actor": "admin", "agent_id": "…",
    "capability": "systemd", "action": "restart", "target": "nginx.service",
    "result": "ok", "error_code": "", "error_message": "", "duration_ms": 83
  }],
  "next_before_id": 41
}
```

只读接口不写审计；所有 `POST /control`（成功、拒绝、超时、失败）都写一条。`params` 只存 target/pid/signal/lines，绝不存命令输出。

### 3.4 数据库 schema v5（纯新增）

```sql
CREATE TABLE IF NOT EXISTS agent_control (
    agent_id     TEXT PRIMARY KEY,
    capabilities TEXT NOT NULL DEFAULT '[]',
    updated_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            INTEGER NOT NULL,
    actor         TEXT NOT NULL,
    agent_id      TEXT NOT NULL,
    capability    TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT NOT NULL DEFAULT '',
    params        TEXT NOT NULL DEFAULT '{}',
    result        TEXT NOT NULL,
    error_code    TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT '',
    duration_ms   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit_log(agent_id, ts);
```

- `SCHEMA_VERSION` 4 → 5；迁移 `CREATE TABLE IF NOT EXISTS` 幂等。
- audit 保留 180 天，hub 启动时与每 1000 条写入后清理一次。
- `agent_control` 在每次 Hello 后 upsert，断线不清空（面板仍可看历史能力）。

## 4. 安全模型

### 4.1 能力开关

- 双端开关：hub `[control]` + agent `[control]`，默认全关；任一端关闭都返回 403。
- agent 只把实际启用的能力放进 Hello；hub 发送前再次核对 `get_agent_control`。
- agent 执行入口再次校验配置（纵深防御），不信任 hub 传来的 capability。
- hub 控制 API 与 agent 接入端口隔离；沿用 Bearer + 面板会话两层。

### 4.2 命令执行

- 全部 `std::process::Command` 参数数组，**不用 shell**；`env_clear()` 后只保留 `PATH=/usr/sbin:/usr/bin:/sbin:/bin`、`LANG=C`。
- systemctl/docker/journalctl 使用绝对路径：配置优先，其次固定候选 `/usr/bin`、`/bin`、`/usr/sbin`、`/sbin`；找不到返回 `control_failed`。
- 每个命令 10s 超时（可配 1–60s）；超时 `kill()` + `wait()`，输出截断到 256 KiB。
- 禁止 `docker exec/run/rm`、`systemctl` 非白名单动作；动作枚举固定。

### 4.3 白名单与路径

- systemd：只接受配置中的精确 unit 或 `prefix*`；禁止项优先于白名单。
- Docker：只接受名称匹配白名单的容器；列表结果也过滤。
- 进程：PID > 1、PID != agent 自身、`/proc/<pid>/comm` 与请求 `name` 完全一致才发信号；只允许 SIGTERM/SIGKILL；不使用 `kill` 命令。
- 文件日志：
  - 启动时校验每个 `file` target：绝对路径、父目录存在、`symlink_metadata` 非符号链接；
  - 读取时以父目录 fd + 文件名调用 Linux `openat2`，`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`；
  - `ENOSYS` / 内核不支持直接失败并记录 ERROR，不降级到 `fs::read`；
  - 按行 tail，最多 2000 行、单行 4096 字节，超出截断并置 `truncated`。
- journald：`journalctl -u <白名单 unit> -n <lines> --no-pager -o short-iso`，参数数组。

### 4.4 会话复用与审计

- 每个 agent 会话注册 `mpsc::channel<ControlCommand>(16)`；`SessionRegistry::control_sender` 取最新连接。
- 会话循环 `select!` 增加命令分支；待处理表上限 32，超限立即回 `too_many_pending`。
- 命令 id 只在会话内有效；收到未知 id 的 Response 直接丢弃并计数。
- 会话结束时 drop 全部 oneshot，等待中的 API 得到 `agent_offline`。
- 审计写失败只记 ERROR，不回滚已执行的动作；响应仍返回真实结果。
- 审计 `actor` v1 固定 `admin`（单管理员）；后续多用户再扩展。

## 5. 兼容性

| 场景 | 行为 |
|---|---|
| 新 hub + 旧 agent | Hello capabilities 为空；控制 API 403；不发送新帧；采集不受影响 |
| 旧 hub + 新 agent | 旧 hub 忽略 capabilities；不会发控制帧；agent 正常采集 |
| 协议版本 | 保持 2；控制帧只在已认证会话、能力协商后出现 |
| 数据库 | v5 纯新增表；旧 v4 库启动时幂等迁移；回滚旧二进制可忽略新表 |
| 配置 | 新字段全部默认关闭；旧配置启动后控制面不可用 |
| 面板 | 新路由纯新增；旧 API 不变；`/api/v1/system` 的 v0.2.1 字段保持 |

## 6. 测试点

### 单元/集成

- wire：ControlRequest/Response 编解码往返、Debug 不含输出、长度上限。
- 配置：能力开启但白名单为空、禁止 unit、非法容器名、日志路径非绝对/符号链接、超时范围。
- systemd：白名单匹配（精确、前缀、禁止项优先）、列表解析、动作参数。
- docker：名称过滤、格式解析、动作参数。
- process：PID+name 匹配、PID 1/自身拒绝、信号映射、列表上限。
- logs：`openat2` 逃逸（`../`、绝对路径、符号链接、硬链接）、tail 行数/长度、journal 参数。
- exec：超时 kill、输出截断、非零退出、工具缺失。
- session：多连接取最新、pending 上限、超时、会话结束回调、未知 id。
- storage：v5 迁移、audit 写入/分页/过滤/清理、agent_control upsert。
- API：鉴权、能力 403、agent 离线 503、超时 504、审计落库、错误映射。
- panel：`post_json` 不泄露 token、路径/方法白名单、Origin 校验。

### e2e `control.sh`

用临时 fake `systemctl`/`docker`/`journalctl`（绝对路径写入 agent 配置）验证参数与白名单，不依赖宿主机服务：

1. hub/agent init + enrollment；agent 开启 systemd/docker/process/logs，白名单 `nginx*` / `web*`；
2. systemd list 只出现白名单 unit；restart nginx 调用 fake 脚本并返回退出码；审计有 `ok`；
3. 非白名单 unit → 403 + 审计 `denied`；
4. docker 容器列表过滤；restart web-1 成功；非白名单拒绝；
5. 进程列表包含测试进程；错误名称 kill → 拒绝且进程仍存活；正确名称 → 进程退出；PID 1 拒绝；
6. 日志 list/tail：白名单文件内容正确；`../`、符号链接、非配置路径全部拒绝；journal tail 参数正确；
7. 关闭 agent 能力 → 403；关闭 hub 控制面 → 403；agent 离线 → 503；
8. 审计分页/过滤；面板登录后经代理执行一次重启，确认 `admin` 审计；
9. 旧 agent（不启用控制）仍能上报，控制 API 403。

## 7. 实施拆分（文件边界）

| 任务 | 负责文件 | 依赖 |
|---|---|---|
| B1 线协议 + 配置 | `common/control.rs`、`common/lib.rs`、`common/wire.rs`、`common/config.rs` | 无 |
| B2 agent 控制模块 | `agent/src/control/**`、`agent/Cargo.toml` | B1 类型 |
| B3 agent 会话接入 | `agent/main.rs` | B2 |
| B4 storage v5 + 审计 | `core/storage/{mod,sqlite}.rs` | B1 类型（仅 AuditEntry） |
| B5 hub 会话/注册表 | `hub/session.rs`、`hub/main.rs` | B1 |
| B6 hub 控制 API | `hub/control.rs`、`hub/main.rs` | B4/B5 |
| B7 面板代理/页面 | `panel/{main,proxy}.rs`、`web/**` | B6 API |
| T1 独立 e2e | `tests/e2e/control.sh`、`README.md` | B6 |
| R1 评审 / P1 渗透 | 只读 | 全部 |

编码 Agent 不修改测试 Agent 的文件；测试 Agent 不修改实现文件。

## 8. 回滚

- 关闭 `hub.control.enabled` / `agent.control.enabled` 即回到纯采集；无需改协议。
- 二进制回滚到 v0.2.x：v5 表被忽略，采集与面板正常；审计数据保留。
- 若控制面出现高危问题，发布 v0.3.1 默认关闭全部能力，不移动已发布 tag。
- 文件日志实现若在特定内核不可用（`openat2` ENOSYS），只禁用 `logs` 能力，不影响其他三项。
