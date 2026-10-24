# M5 Phase A：安装器内核与自签安装

> 状态：Phase A 完成（2026-10-24，checkpoint）｜上游：[M5 安装与交付计划](2026-10-24-m5-install-delivery.md) §6 Phase A
> 目标：交付 `rustboard-install` 库、三个二进制的 `install` 子命令、systemd unit 与
> 可重复的三步安装 e2e；ACME、PostgreSQL、离线包、Docker 不在本阶段实现。
>
> 验收证据：workspace 1079 tests、fmt/clippy/audit 0；`tests/e2e/v100-install.sh`
> 121/121。独立评审/渗透共三轮：首轮 1 高危 + 5 严重，第二轮 4 严重 + 1 中危，
> 第三轮发现并修复最后 1 处 systemd 回滚停服守卫；最终未修复高危/中危 0。
> 报告：[M5 Phase A 渗透报告](../security/2026-10-24-m5-phase-a-install-pentest.md)。

## 1. 验收

1. `rustboard-hub install --yes --prefix <p>` 在临时 prefix 下生成配置/证书/unit，
   通过 systemd 启动，`/healthz` 200，`admin_token` 可从 0600 配置读取。
2. `rustboard-panel install` 复用 hub token，启动后 `/healthz` 200，初始密码只打印一次。
3. `rustboard-agent install --token-file` 启动后 30s 内完成 enrollment，
   hub 管理 API 能查到该 agent 并收到数据。
4. 重复执行同一安装命令不产生第二套配置，返回 0 且服务仍健康。
5. 启动失败时回滚本次新建的 config/unit/binary/state，已有数据目录不被删除；
   失败的 unit 不残留在 systemd。
6. 配置、token、私钥 0600；数据目录 0700；unit 通过 `systemd-analyze verify`。
7. 旧版手工生成的 `/etc/rustboard/hub.toml` 可被 `rustboard-hub upgrade` 识别，
   导入 install-state，不重写数据/cert。
8. `--dry-run` 零写入、零 systemctl；`--offline` 不做任何网络探测。

## 2. 新 crate：`rustboard-install`

位置 `crates/rustboard-install/`，库 crate，依赖 `rustboard-common`（复用
`fsutil` 的原子写入/私有目录校验）、`anyhow`、`serde`、`toml`、`libc`。
**不依赖** hub/agent/panel，避免循环依赖。

### 2.1 公开 API

```rust
pub enum Role { Hub, Agent, Panel } // serde: "hub" | "agent" | "panel"

pub struct Paths {
    pub prefix: PathBuf,
    pub config: PathBuf,
    pub data_dir: PathBuf,
    pub unit: PathBuf,
    pub binary: PathBuf,
    pub state: PathBuf,
    pub backup_root: PathBuf,
}

pub struct PathOverrides {
    pub config: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub unit_dir: Option<PathBuf>,
    pub bin_dir: Option<PathBuf>,
}

impl Paths {
    pub fn for_role(role: Role, prefix: &Path, overrides: PathOverrides) -> anyhow::Result<Self>;
    pub fn is_root_prefix(&self) -> bool;
}
```

默认（`prefix = "/"`）：

| 项 | 路径 |
|---|---|
| config | `/etc/rustboard/<role>.toml` |
| data | `/var/lib/rustboard/<role>` |
| unit | `/etc/systemd/system/rustboard-<role>.service` |
| binary | `/usr/local/bin/rustboard-<role>` |
| state | `/var/lib/rustboard/install-state.toml` |

`--prefix P` 时对应 `P/etc/rustboard/...`、`P/var/lib/rustboard/...`、
`P/etc/systemd/system/...`、`P/usr/local/bin/...`。所有路径必须是绝对路径，
拒绝 `..` 与空路径；`unit_dir`/`bin_dir` 可指向 prefix 外（测试/容器用）。

### 2.2 系统与交互

```rust
pub struct SystemInfo { pub os_name: String, pub arch: String, pub systemd: bool, pub euid: u32 }
pub fn detect_system() -> SystemInfo;
pub fn require_root() -> anyhow::Result<()>;
pub fn require_systemd() -> anyhow::Result<()>;
pub fn pick_free_port(exclude: &[u16]) -> anyhow::Result<u16>; // 20000-64999

pub struct Prompt { /* assume_yes, stdin_is_tty */ }
impl Prompt {
    pub fn new(assume_yes: bool) -> Self;
    pub fn confirm(&self, question: &str, default: bool) -> anyhow::Result<bool>;
    pub fn text(&self, question: &str, default: &str) -> anyhow::Result<String>;
}
```

非交互（stdin 非 TTY）且未 `--yes` 时 `Prompt` 必须报错，不允许读空串当默认。
交互提示只在 TTY 输出 ANSI 颜色。

### 2.3 安装状态

```toml
schema = 1

[roles.hub]
version = "0.4.2"
config = "/etc/rustboard/hub.toml"
data_dir = "/var/lib/rustboard/hub"
unit = "/etc/systemd/system/rustboard-hub.service"
binary = "/usr/local/bin/rustboard-hub"
installed_at_ms = 1760000000000
backup_dir = "/var/lib/rustboard/backups/hub-20261024T..."
```

`InstallState { schema, roles: BTreeMap<Role, RoleState> }`；单文件合并写，
`save` 用原子写入 0600；读坏文件必须报错，不能静默重建。hub+panel 同机时
两条记录共存。`load` 不存在时返回空状态。

### 2.4 事务与回滚

```rust
pub struct InstallTxn { /* backup dir, created paths, replaced paths */ }
impl InstallTxn {
    pub fn begin(paths: &Paths, dry_run: bool) -> anyhow::Result<Self>;
    pub fn write(&mut self, path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()>;
    pub fn create_dir(&mut self, path: &Path, mode: u32) -> anyhow::Result<()>;
    pub fn remove(&mut self, path: &Path) -> anyhow::Result<()>;
    pub fn commit(&mut self) -> anyhow::Result<()>;
    pub fn rollback(&mut self) -> anyhow::Result<()>;
    pub fn backup_dir(&self) -> &Path;
}
```

- 已存在文件先复制到备份目录（保留权限），再原子替换；新建文件登记为 created。
- `rollback` 逆序恢复/删除；只删除本事务创建的路径，绝不动已有数据目录。
- `dry_run` 只记录计划，不创建目录/备份/文件。
- `Drop` 未 `commit` 时尽力回滚并记录警告；`commit` 清理备份（升级场景保留由调用方决定）。

### 2.5 systemd / 健康检查 / unit

```rust
pub struct ServiceManager { pub unit_dir: PathBuf, pub manage: bool, pub dry_run: bool }
impl ServiceManager {
    pub fn new(unit_dir: PathBuf, manage: bool, dry_run: bool) -> Self;
    pub fn write_unit(&self, name: &str, contents: &str) -> anyhow::Result<PathBuf>;
    pub fn daemon_reload(&self) -> anyhow::Result<()>;
    pub fn enable_now(&self, unit: &str) -> anyhow::Result<()>;
    pub fn restart(&self, unit: &str) -> anyhow::Result<()>;
    pub fn stop_disable(&self, unit: &str) -> anyhow::Result<()>;
    pub fn is_active(&self, unit: &str) -> anyhow::Result<bool>;
}

pub fn render_unit(role: Role, paths: &Paths) -> anyhow::Result<String>;
pub fn wait_http_ok(url: &str, timeout: Duration) -> anyhow::Result<()>;
pub fn shell_arg(value: &str) -> String;
```

- `manage=false` 只写 unit（若调用方要求），不调用 `systemctl`；`--no-systemd` 两者都跳过。
- 命令一律 `Command::new("systemctl").args([...])`，失败带 stderr，不拼 shell。
- `wait_http_ok` 仅支持 `http://`，最多 30s，1s 间隔；连接失败/非 200 继续。
- unit 模板在 `packaging/systemd/rustboard-{hub,agent,panel}.service`，安装器
  用 `include_str!` 读取并替换 `@EXEC_START@` 等占位符；默认路径的静态 unit
  必须能直接 `systemd-analyze verify`。

## 3. CLI

### 3.1 hub

```text
rustboard-hub install [--yes] [--offline] [--dry-run] [--force]
  [--prefix P] [--config F] [--data-dir D] [--unit-dir U]
  [--listen ADDR] [--admin-listen ADDR] [--advertise HOST] [--san HOST]...
  [--name NAME] [--retention raw=7d,1m=90d,1h=2y] [--db sqlite]
  [--tls self-signed] [--panel yes|no] [--systemd] [--no-systemd]
rustboard-hub upgrade [--prefix P] [--dry-run]
rustboard-hub uninstall [--prefix P] [--purge] [--yes] [--dry-run]
```

- 未显式指定端口时各挑一个空闲五位数；agent 监听 `0.0.0.0:<p>`，管理口
  `127.0.0.1:<p>`（保持 v0.4 默认）。
- `--tls` 本阶段只接受 `self-signed`；ACME 取值明确报错“Phase C”。
- `--db` 本阶段只接受 `sqlite`；`postgres://` 明确报错“Phase D”。
- `--panel` 默认 `yes`；`--yes` 时取默认 yes。面板二进制从当前可执行文件同目录查找
  `rustboard-panel`，找不到则失败并提示 `--panel no`。
- 面板 token 用 0600 临时文件传给子进程 `--hub-token-file`，禁止出现在 argv；
  子进程退出后删除临时文件。面板静态目录默认 `/usr/share/rustboard/web`，
  可用 `--panel-static-dir` 覆盖（测试用）。
- 安装顺序：校验 → 创建 data/config/unit/binary（事务）→ `daemon-reload` →
  `enable --now` → `/healthz` 200 → 写 state → 可选 panel → 打印摘要。
  state 写入必须在服务健康之后；失败则停服务并回滚。
- 重复执行：state 已存在且 config/unit/binary 都在，且服务 active → 直接打印
  “已安装”并返回 0；`--force` 强制重写配置/unit 并重启。
- 已有 config 但无 state（旧手工安装）→ 报错并指向 `upgrade`，除非 `--force`。
- `upgrade`：无 state 但 config 存在时，加载并校验配置，补齐 unit/binary/state，
  不重写 cert/data；已有 state 时只刷新二进制/unit/state。`--dry-run` 只打印。
- `uninstall`：停服务、删 unit/binary/state 条目；默认保留 config/data。
  `--purge` 删除数据与配置，必须 `--yes` 或交互二次确认。

### 3.2 panel

```text
rustboard-panel install [--yes] [--offline] [--dry-run] [--force]
  [--prefix P] [--config F] [--unit-dir U] [--hub-url URL]
  [--hub-token-file F] [--password-file F] [--listen ADDR] [--static-dir D]
  [--systemd] [--no-systemd]
rustboard-panel uninstall [--prefix P] [--purge] [--yes] [--dry-run]
```

- token 只从 `--hub-token-file`（0600，拒绝符号链接，≤4 KiB）或同机
  `/etc/rustboard/hub.toml` 的 `admin_token` 读取；未找到则失败。
- 密码只从 `--password-file` 或自动生成；自动生成时只打印一次。禁止 `--password` argv。
- `--static-dir` 显式指定时必须存在；否则依次尝试 `web/dist`、`/usr/share/rustboard/web`，
  都没有只警告，不阻塞安装。
- 默认监听随机回环端口；`hub_url` 默认从同机 hub 配置推导。

### 3.3 agent

```text
rustboard-agent install [--yes] [--offline] [--dry-run] [--force]
  [--prefix P] [--config F] [--data-dir D] [--unit-dir U]
  [--hub URL] [--token-file F] [--fingerprint SHA256:...]
  [--name NAME] [--systemd] [--no-systemd]
rustboard-agent uninstall [--prefix P] [--purge] [--yes] [--dry-run]
```

- `--token-file` 必填（`--yes` 非交互），0600，拒绝符号链接，读后 trim；空值失败。
- 本阶段只支持 `--fingerprint`（自签）；`--server-ca` 明确报错“Phase C”。
- 启动后轮询 `data_dir/agent.crt`、`agent.key`、`agent.secret`、`agent_id`，最长 30s；
  失败则停服务并回滚本次安装。
- 不打印 token。

## 4. systemd unit

三个 unit 均包含：

```ini
[Unit]
Description=RustBoard ...
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/rustboard-... run --config /etc/rustboard/....toml
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
LockPersonality=true
ReadWritePaths=/var/lib/rustboard/...

[Install]
WantedBy=multi-user.target
```

不启用 `RestrictSUIDSGID=true`：systemd 257 上该 seccomp 过滤器会让 `openat2(2)` 返回
ENOSYS，而 `fsutil::ensure_private_dir` 依赖 openat2，会导致服务启动失败；已有的
`NoNewPrivileges=true` 已阻止 setuid/setgid 提权，去掉它不降低安全性。

Phase A 统一以 root 运行：配置/私钥必须 0600，非 root 服务读不到；专用用户 +
`LoadCredential` 在 Phase E 评估。hub/panel 不监听 <1024 端口，root 不是绑定需求。
`ReadWritePaths` 只列各自数据目录；agent 控制面能力本阶段默认关闭，不额外放宽。
unit 不放 token、密码、环境变量 secret。

## 5. 兼容性

- 协议 v2、SQLite schema v7 不变；本阶段不改 `rustboard-common` 配置结构（面板 TLS/PG
  留到 C/D）。
- 旧 `/etc/rustboard/{hub,agent,panel}.toml` 继续可读；`install` 不静默覆盖，
  `upgrade` 导入 state 并保留数据。
- 新增 `install-state.toml` 是安装器私有文件，不是用户配置；不存在时旧安装正常工作。
- `--prefix` 只用于测试/容器，不改变生产默认路径。

## 6. 测试点

- 单元：路径解析/拒绝 `..`、state 合并与坏文件、txn 备份/回滚/dry-run、
  shell_arg、unit 渲染、retention 解析、端口选择、Prompt 非交互报错。
- e2e `tests/e2e/v100-install.sh`：
  1. 构建三二进制；临时 prefix 放 `/opt`（不能放 `/tmp` 或 `/var/tmp`：unit 的
     `PrivateTmp=true` 会让服务看不到这两处的 binary/config），unit 目录用
     `/run/systemd/system`；
  2. hub install（`--panel yes`）→ healthz、config/unit/私钥 0600、`systemd-analyze verify`；
  3. 重复 install → 0 且无第二套文件；
  4. agent add 输出取 token → agent install → 30s 内 enrollment + hub API 有数据；
  5. 失败注入：占用 admin 端口或 panel token 缺失 → 安装失败且无残留 unit；
  6. uninstall 默认保留 data，`--purge --yes` 删除。
- 旧配置 upgrade：`hub init` 生成临时配置 → `hub upgrade` → state 存在、数据未动。

## 7. 回滚

安装失败按事务逆序恢复 config/unit/binary；停用并删本次 unit；仅删除本次新建的
data 目录。升级失败保留旧二进制/unit 备份，数据不动。已推送 tag 不移动。
