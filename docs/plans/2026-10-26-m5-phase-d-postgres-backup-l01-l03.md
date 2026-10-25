# M5 Phase D：PostgreSQL、迁移/备份/恢复 + L-01/L-03 收口

> 日期：2026-10-26｜基线：`main`（Phase C `v1.0.0-rc.2` 已发布）
> 目标：一次性完成 L-01、L-03 与 Phase D 全部交付；默认 SQLite 行为不变，
> PostgreSQL 为显式 opt-in，不自动双写。Phase E 仍负责 24h/1000 agent 与
> `v1.0.0` 正式发布。
>
> 关联：
> [M5 总计划](2026-10-24-m5-install-delivery.md) §4.3/Phase D、
> [Phase C 计划](2026-10-25-m5-phase-c-tls-release-gates.md)、
> [Phase C 渗透报告](../security/2026-10-25-m5-phase-c-pentest.md)、
> [RC 证据](../security/2026-10-25-m5-phase-c-rc-evidence.md)。

## 0. 决策摘要

| 项 | 决策 |
|---|---|
| L-01 | **修**：hub 启动时只收紧 `account.json`/`state.toml` 到 0600；`tls status` 只告警不改文件 |
| L-03 | **不改放行逻辑**：保持 fail-closed；改错误信息 + 文档，给出三种可用部署方式 |
| PostgreSQL | **显式 opt-in**：`database = "postgres://..."`，默认仍 SQLite；不自动双写 |
| 迁移 | **离线工具**：SQLite → PG，迁移前强制备份；失败不切换、不删 SQLite |
| 备份/恢复 | SQLite 用 `VACUUM INTO`；PG 用 `pg_dump`/`pg_restore`；统一 manifest |
| 发布 | L-01/L-03 不单独发 RC；Phase D 全绿后按需发 `v1.0.0-rc.3`，`v1.0.0` 仍在 Phase E |

## 1. 目标与可验证验收

### 1.1 L-01：ACME 账户文件权限收紧

**现状**：`crates/rustboard-hub/src/acme/store.rs:131` 的 `read_account` 读取后
才 `harden(0600)`；`hub run` 启动和 `tls status` 不读取 account，旧 0644 文件
会一直保留。`certs/acme` 目录本身是 0700，所以实际风险低。

**验收**：

- 预置 0644 `account.json` + 0644 `state.toml`，`hub run` 启动后均变成 0600；
- 文件不存在时启动无错误；
- `account.json` 是符号链接时启动失败，错误不跟随链接、不改目标；
- `tls status` 不写文件；检测到 0644 时输出 `WARN` 和修复建议；
- 权限收紧失败（只读文件系统/EACCES）时启动失败，不能静默继续；
- 新增测试覆盖 0644→0600、无文件、符号链接、status 不写。

### 1.2 L-03：ACME 域名证书 + 回环管理口

**现状**：`crates/rustboard-hub/src/main.rs:1959` 的 `validate_admin_tls` 对
回环绑定要求精确 IP SAN；ACME 域名证书只有 DNS SAN，因此拒绝启动。这是
正确的 fail-closed，但错误信息会误导用户把回环 IP 加进公共 ACME 域名。

**验收**：

- 不放宽 `validate_admin_tls` 的放行条件；
- 该场景错误信息明确给出三条路：
  1. `admin_listen = "0.0.0.0:8444"` + 防火墙限制来源；
  2. 同机 panel 用 `admin_tls = "off"` 回环 HTTP，TLS 放反向代理；
  3. 使用含 `127.0.0.1`/`::1` SAN 的 self-signed 证书；
- `docs/install/acme.md`、`tls.md`、`troubleshooting.md` 同步；
- 新增测试断言错误信息包含上述选项，且不会建议给公共 ACME 证书加回环 IP。

### 1.3 Phase D 功能验收

| # | 验收 |
|---|---|
| D-G1 | `database = "postgres://..."` 可安装、启动、迁移；默认 SQLite 完全不变 |
| D-G2 | SQLite v7 的 21 张表/索引在 PG 有等价 schema + PG 独立 migration 表 |
| D-G3 | 同一批数据在 SQLite/PG 的查询结果一致（数值容差、时间边界、排序、分页） |
| D-G4 | ingest 幂等 `(agent_id, epoch, seq)`、吊销、retention、downsample、alert、archive、audit、token 全绿 |
| D-G5 | PG 200 agent 写入/查询达标；连接断开自动重连，不丢已提交数据 |
| D-G6 | `migrate --to` 失败不切换、不破坏 SQLite；成功后可回切 SQLite |
| D-G7 | `backup`/`restore` 后点数、时间范围、告警状态、token 数量一致 |
| D-G8 | 安装器 `--db postgres://` 探测、配置、错误脱敏；不自动建库/建角色 |
| D-G9 | Docker `RUSTBOARD_DATABASE` 可接 PG；默认 compose 仍 SQLite |
| D-G10 | 全量 fmt/clippy/test/audit、独立评审、本地渗透；无未修复高危 |

## 2. 范围与文件

### 2.1 L-01/L-03

- `crates/rustboard-hub/src/acme/store.rs`
- `crates/rustboard-hub/src/main.rs`
- `crates/rustboard-hub/src/install_cmd.rs`（错误文案/帮助文本）
- `docs/install/acme.md`、`tls.md`、`troubleshooting.md`
- 测试：`crates/rustboard-hub/src/install_cmd.rs` 单测、
  `crates/rustboard-hub/tests/phase_c_install.rs`

### 2.2 Phase D

- `crates/rustboard-core/src/storage/mod.rs`：`StorageBackend` 抽象、连接/健康接口
- `crates/rustboard-core/src/storage/postgres.rs`（新）
- `crates/rustboard-core/src/storage/sqlite.rs`：仅接口适配，不改 schema v7
- `crates/rustboard-core/src/storage/migrate.rs`（新）：SQLite ↔ PG 导出/导入
- `crates/rustboard-common/src/config.rs`：`database` 解析、PG 连接参数
- `crates/rustboard-hub/src/main.rs`：storage 初始化、迁移/备份命令挂载
- `crates/rustboard-hub/src/install_cmd.rs`：`--db postgres://`、探测、帮助
- `crates/rustboard-hub/src/main.rs` 的 token 子命令：走 backend
- `crates/rustboard-hub/src/migrate_cmd.rs` / `backup_cmd.rs`（新）
- `docker/entrypoint-hub.sh`、`docker/compose.example.yml`、`docker/README.md`
- `.github/workflows/ci.yml`：PG service 测试 job
- `docs/install/postgres.md`（新）、`offline.md`、`docker.md`、`release.md`
- `docs/status.md`、`CHANGELOG.md`

不修改：协议帧、SQLite schema v7、证书格式、Panel/Agent 协议。

## 3. 接口与数据变更

### 3.1 配置

保持 `database` 单字段兼容：

```toml
# 默认，不变
database = "sqlite:///var/lib/rustboard/hub/rustboard.db"

# 新增 opt-in
database = "postgres://rustboard@127.0.0.1/rustboard?sslmode=verify-full"
```

新增可选字段（全部有默认值，旧配置无需迁移）：

```toml
db_pool_size = 8                 # 1–64
db_connect_timeout_ms = 5000     # 连接/探活超时
db_statement_timeout_ms = 30000  # PG statement_timeout
```

密码来源优先级：

1. `RUSTBOARD_DATABASE_PASSWORD` 环境变量（推荐，不进配置文件）；
2. URL 内密码（兼容；配置文件 0600，日志/错误必须脱敏）。

禁止：日志、错误、`--dry-run` 输出 DSN 的 userinfo/password。

### 3.2 Storage 抽象

不引入 `dyn Storage` 大改；用**静态枚举**避免 async/dyn 复杂性：

```rust
pub enum StorageBackend {
    Sqlite(SqliteStorage),
    Postgres(PostgresStorage),
}

pub struct StorageHandle(Arc<StorageBackend>);
```

- 先审计 `Arc<SqliteStorage>` 全部调用点，按域拆 trait：
  `CoreStorage`（agent/samples/ingest）、`AdminStorage`（token/audit/control）、
  `AlertArchiveStorage`（告警/归档/维护水位）；
- `StorageHandle` 逐方法 match 转发，保持现有同步签名；
- 不在本阶段把所有调用改成 async；PG 的网络阻塞通过：
  - 连接池 + `statement_timeout`；
  - hub 的 ingestion/查询边界用 `spawn_blocking` 包装（D3 基准决定范围）；
  - 200 agent 压测证明 tokio worker 不被长时间占满。
- SQLite 实现不重写；PG 实现独立 SQL，不强行共用带 `?1`/`$1` 占位符的字符串。

### 3.3 PostgreSQL schema

- 初始版本 `7`，PG 独立 `schema_migrations(version BIGINT PRIMARY KEY, applied_at BIGINT)`；
- 21 张表与索引等价；类型映射：
  - `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL PRIMARY KEY`
  - `INTEGER` 时间/计数 → `BIGINT`
  - `REAL` → `DOUBLE PRECISION`
  - `TEXT` JSON → `TEXT`（保持现有序列化，不改 JSON 格式）
  - 布尔列 → `BOOLEAN`，读取层显式转换（不让 `i64` 假设泄漏）
- 唯一约束/主键与 SQLite 一致：
  `samples(agent_id, metric, labels, ts)`、
  `ingest_batches(agent_id, epoch, seq)`、
  `alert_states(rule_id, agent_id, series_key)` 等；
- 所有 upsert 用 PG `ON CONFLICT`，批量 ingest 单事务；
- 启动迁移持 PG advisory lock，避免多实例并发迁移；
- 只使用两边共同 SQL 语义；差异集中在 per-backend 常量。

### 3.4 迁移/备份/恢复 CLI

```text
rustboard-hub migrate --to postgres://... [--dry-run] [--force] [--yes]
rustboard-hub backup --out <dir> [--yes]
rustboard-hub restore --from <dir> [--force] [--yes]
```

规则：

- `migrate` 默认要求 hub 已停止；检测安装锁/运行中 PID 时拒绝；
- 迁移前 SQLite `VACUUM INTO <backup>/rustboard.db`，配置文件成对备份；
- `--dry-run` 只连源/目标、校验 schema 与目标空，不写数据；
- 目标非空必须 `--force`，且先做目标侧备份；
- 导入后校验：每表行数、samples 时间范围、alert_states/events 数量、
  api_tokens 哈希数量、archive 对象数量；不一致则回滚目标事务并保留 SQLite；
- 只有校验通过才改写 `hub.toml` 的 `database`；旧配置备份保留；
- `backup` 生成 `<timestamp>/` + `manifest.json`（文件 SHA256、版本、schema、
  后端类型）；配置/证书 0600，归档目录 0700；
- `restore` 只允许空目标或 `--force`；恢复前备份当前目标。

## 4. 兼容性与迁移

| 项 | 结论 |
|---|---|
| 协议 | v2 不变 |
| SQLite schema | v7 不变；旧库直接打开 |
| PG schema | 新增，独立版本 7；不影响 SQLite |
| 旧配置 | 无新字段默认 SQLite；`database` 路径语义不变 |
| 旧 agent | 不变；PG 只影响 hub 存储 |
| 回滚 | 配置改回 SQLite 路径即可；SQLite 文件全程不动 |
| 双写 | **不做**；迁移是离线一次性操作 |
| L-01 | 只收紧文件 mode；旧版本回滚后文件权限保持 0600，无害 |
| L-03 | 仅文案/文档；行为不变 |

迁移步骤（生产）：

1. `hub backup --out /var/lib/rustboard/backups/<ts>`；
2. 停 hub；
3. `hub migrate --to postgres://... --dry-run`；
4. `hub migrate --to postgres://... --yes`；
5. 启动 hub，检查 healthz/agents/面板/告警；
6. 保留 SQLite 与备份，观察 24h 后再清理。

## 5. 任务拆解

### D0：L-01/L-03 + PG spike（0.5–1 天）

- L-01：新增 `harden_acme_material(data_dir)`，启动调用；`tls status` 只告警；
- L-03：错误信息/文档；
- PG spike：
  - 选 `postgres` sync + 连接池 + rustls TLS 适配；确认 MSRV 1.89、无 openssl/aws-lc；
  - 在 200 agent 模拟写入下测同步调用的 reactor 阻塞；
  - 结论写入 `docs/plans/2026-10-26-m5-phase-d-pg-spike.md`；
  - 若 sync 驱动不达标，改为 async 驱动方案并更新本计划，不直接开工。

**Gate D0**：L-01/L-03 测试通过；PG 驱动/池/TLS 选择有实测依据；`cargo tree`
无 openssl/aws-lc。

### D1：Storage 抽象与配置（2 天）

- 审计 `Arc<SqliteStorage>` 调用点，按域拆 trait；
- `StorageBackend`/`StorageHandle` 静态转发；
- `HubConfig::database` 解析：sqlite 路径/`sqlite://`/`postgres://`/`postgresql://`；
- 新增 pool/timeout 字段与校验；
- DSN 脱敏工具 + 单测；
- hub 启动/CLI/token 命令改用 `StorageHandle`。

**Gate D1**：SQLite 全量测试行为不变；非法 DSN 在写盘前失败；日志无密码。

### D2：PG schema/migration（3 天）

- 21 张表/索引 DDL、`schema_migrations`、advisory lock；
- 类型映射/唯一约束/索引；
- migration 幂等、版本校验、失败回滚；
- 测试：空库、半迁移、重复启动、并发启动。

**Gate D2**：`\dt`/索引数量与 SQLite 对照；重复启动无变化；并发迁移只有一个成功。

### D3：PostgresStorage 实现（4 天）

- 全部 Core/Admin/AlertArchive 方法；
- ingest 事务 + 幂等 + 吊销；
- 查询/聚合/分页/排序/时间边界；
- 连接池、重连、statement timeout、错误脱敏；
- 同步阻塞边界：基准后决定 `spawn_blocking` 调用点。

**Gate D3**：Storage trait 全方法 parity 测试通过；PG 200 agent 写入/查询达标；
断连重连不丢已提交数据。

### D4：hub/安装器/Docker 接线（2 天）

- `open_storage(cfg)` 按 database 选择 backend；
- `hub install --db postgres://` 探测 `SELECT 1`、写配置、不建库；
- `hub migrate/backup/restore` 命令注册、帮助、错误码；
- Docker entrypoint 支持 `RUSTBOARD_DATABASE`；默认 compose 仍 SQLite；
- 备份/迁移文档。

**Gate D4**：安装器 e2e（PG + SQLite）；Docker PG 场景；旧配置零改动。

### D5：迁移/备份/恢复（4 天）

- SQLite `VACUUM INTO`；PG `pg_dump --format=custom` / `pg_restore`；
- 导入顺序/外键、批量大小、进度、断点失败清理；
- 校验器（计数/范围/告警/token/归档）；
- 目标非空/`--force`/`--dry-run`；
- 配置切换事务与回滚。

**Gate D5**：迁移成功/失败注入/回切；备份恢复后点数、范围、告警状态一致。

### D6：测试与故障注入（3 天）

- CI 增加 `postgres:16` service job，`RUSTBOARD_TEST_PG` 控制；
- parity 矩阵：每张表、每类查询、边界值、NULL/labels/排序/分页；
- 并发：多 agent 同批、重复 seq、乱序、吊销竞争；
- 故障：PG kill/断网/连接池耗尽/statement timeout/磁盘满；
- 迁移中断、备份中断、restore 目标非空；
- 200 agent 压测（Phase E 再做 100/500/1000 + 24h）。

**Gate D6**：CI 全绿；故障注入不丢已提交数据；SQLite 原文件不被修改。

### D7：文档、评审、渗透、checkpoint（2 天）

- `docs/install/postgres.md`、备份/恢复/迁移、Docker、offline、troubleshooting；
- 独立评审（只读）覆盖 SQL 注入/DSN 泄露/权限/事务；
- 本地渗透：PG 错误信息、备份文件权限、迁移目标非空、`--force` 滥用；
- 全量门禁 + `cargo audit`；
- 打 `checkpoint/2026-xx-xx-m5-phase-d-postgres`；
- 如需 hosted 验证，发 `v1.0.0-rc.3`；**不移动 rc.2**。

**Gate D7**：无未修复高危；文档可执行；checkpoint tag 只打全绿提交。

## 6. 测试清单

### 6.1 L-01/L-03

- [ ] account 0644→0600；state 0644→0600
- [ ] account 符号链接拒绝且不 chmod 目标
- [ ] account 不存在启动正常
- [ ] `tls status` 输出 WARN 且文件 mode 不变
- [ ] L-03 错误包含三条路，不包含“给公共 ACME 加回环 IP”的误导
- [ ] 文档三个场景命令可复制

### 6.2 PG parity

- [ ] agents/upsert/revoked 状态机
- [ ] samples raw/1m/1h 查询、时间边界、limit+1
- [ ] ingest 幂等/吊销/重复 seq/乱序
- [ ] enroll token/agent secret/revoke
- [ ] control 能力
- [ ] audit 分页/过滤/保留
- [ ] api tokens 创建/列表/rotate/revoke
- [ ] maintenance state
- [ ] alert rules/states/events/silences/channels
- [ ] archive objects/state/download
- [ ] 空库/单行/大批量/NULL/特殊 labels
- [ ] 排序/分页/游标稳定
- [ ] 事务回滚/连接断开/重连
- [ ] SQL 注入字符串作为值不改变查询结构

### 6.3 迁移/备份/恢复

- [ ] SQLite v7 → PG 全表 + 计数 + 时间范围
- [ ] 迁移中途 kill → 目标回滚、SQLite 不变、配置不改
- [ ] 目标非空拒绝；`--force` 先备份
- [ ] `--dry-run` 零写入
- [ ] SQLite `VACUUM INTO` 可打开
- [ ] PG `pg_dump`/`pg_restore` 后 parity
- [ ] 备份 manifest SHA256/权限
- [ ] restore 空目标成功；非空拒绝
- [ ] 迁移后回切 SQLite，旧数据仍在

### 6.4 安全

- [ ] DSN 密码不出现在日志/错误/`--dry-run`
- [ ] 配置文件 0600；备份 0600/0700
- [ ] PG 角色最小权限（不 SUPERUSER/CREATEDB）
- [ ] TLS `sslmode=verify-full` 可用；禁用时显式警告
- [ ] 迁移/备份命令参数数组，不拼 shell
- [ ] 目标路径符号链接/`..` 拒绝
- [ ] `pg_dump` 失败不产生半成品 manifest

## 7. 回滚

| 变更 | 回滚 |
|---|---|
| L-01 | 回代码即可；已收紧的 0600 保留，无害 |
| L-03 | 仅文案/文档，回滚无数据影响 |
| PG 运行 | `database` 改回 SQLite 路径，重启；SQLite 文件未动 |
| PG schema | 保留 PG 数据；删除库需人工确认，工具不自动删 |
| 迁移 | 迁移前 SQLite 备份 + 配置备份；失败不切换 |
| 备份/恢复 | 归档目录独立；restore 前先备份当前目标 |
| 新 CLI | 旧二进制忽略新命令；无 schema 变更 |

## 8. 风险与缓解

| 风险 | 级别 | 缓解 |
|---|---|---|
| PG SQL 方言/类型差异导致 parity 漂移 | 高 | 每表/每查询 parity；类型映射表；CI PG service |
| 同步 PG 调用阻塞 tokio worker | 高 | D0 基准；池 + timeout；必要时 `spawn_blocking` 边界 |
| DSN 密码泄露 | 高 | 环境变量优先；统一 redact；日志/错误测试 |
| 迁移中断/半写 | 高 | 事务/目标回滚；迁移前备份；失败不切配置 |
| 备份不一致 | 高 | 停写/快照；`VACUUM INTO`；`pg_dump` 一致性快照 |
| 目标非空误覆盖 | 中 | 默认拒绝；`--force` + 预备份 + 二次确认 |
| PG 连接池耗尽 | 中 | 有界池、超时、健康检查、指标 |
| 旧 SQLite 被误改 | 高 | 迁移只读 SQLite；测试文件 hash 不变 |
| L-01 符号链接/TOCTOU | 低 | `symlink_metadata`、父目录 0700、启动 fail-closed |
| L-03 用户误配 | 低 | fail-closed + 明确三条路 + 文档 |

## 9. 时间与交付

| 阶段 | 预计 |
|---|---|
| D0 L-01/L-03 + PG spike | 0.5–1 天 |
| D1 抽象/配置 | 2 天 |
| D2 schema/migration | 3 天 |
| D3 PG 实现 | 4 天 |
| D4 hub/安装器/Docker | 2 天 |
| D5 迁移/备份/恢复 | 4 天 |
| D6 测试/故障注入 | 3 天 |
| D7 文档/评审/渗透/checkpoint | 2 天 |
| 合计 | 约 3 周（可与 Phase E 文档并行，但 D6 完成前不进入正式发布） |

## 10. 完成定义（DoD）

- L-01/L-03 验收全过，文档同步；
- PG 后端可安装、启动、查询、告警、归档、审计、token 全链路；
- SQLite v7 不受影响，默认路径行为不变；
- 迁移/备份/恢复演练通过，失败不切换、不破坏源库；
- 200 agent PG 压测达标，断连重连不丢已提交数据；
- CI 增加 PG job 且全绿；本地 fmt/clippy/test/audit 全绿；
- 独立评审 + 本地渗透无未修复高危；
- 文档、CHANGELOG、status 更新；
- checkpoint tag 只打全绿提交；`v1.0.0-rc.2` 不移动，`v1.0.0` 仍留 Phase E。
