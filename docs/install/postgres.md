# PostgreSQL 后端安装与运维（M5 Phase D）

RustBoard Hub 默认仍是 **SQLite**（`<data-dir>/rustboard.db`），文件与权限行为不变。
PostgreSQL 是**显式 opt-in**：只有在 `hub.toml` 写 `database = "postgres://…"` 或
安装时显式给 `--db postgres://…` 才会使用。两者不双写、不自动切换。

> 安装器**不会**自动创建数据库、角色或 `CREATEDB` 权限；DBA 必须先准备好实例与
> 最小权限角色。安装器只做 schema v7 的幂等 `CREATE TABLE`/索引（持 advisory
> lock）和 `SELECT 1` 探活。

## 1. 前提

- PostgreSQL **16 或 17**（本地验证与 CI 测试镜像为 `postgres:16`；17 使用同一 schema 与驱动）；
- hub 到数据库的网络可达；生产建议 TLS + 私有 CA；
- 一个已存在的数据库和一个能建表的登录角色。

### 1.1 最小权限角色（在 PG 实例上以管理员执行）

```sql
-- 密码用强随机值；不要使用示例占位符。
CREATE ROLE rustboard LOGIN PASSWORD 'REPLACE_WITH_STRONG_PASSWORD'
  NOSUPERUSER NOCREATEDB NOCREATEROLE;

CREATE DATABASE rustboard OWNER rustboard ENCODING 'UTF8';
```

说明：

- `OWNER rustboard` 让该角色在库内（含 `public` schema，PG 15+ 默认由
  `pg_database_owner` 拥有）有建表权限，足够安装器应用 schema；
- **不要**给 `SUPERUSER`、`CREATEDB` 或 `CREATEROLE`；
- 如果实例策略禁止角色建表，需额外 `GRANT CREATE ON SCHEMA public TO rustboard;`
  （以该库 owner/管理员执行），否则安装探测会明确失败；
- 安装器不会创建角色/数据库，也不会写 `pg_hba.conf`。

## 2. 安装

### 2.1 推荐：密码走环境变量

```bash
# root shell（或 sudo -E / sudo --preserve-env=RUSTBOARD_DATABASE_PASSWORD）
export RUSTBOARD_DATABASE_PASSWORD='REPLACE_WITH_STRONG_PASSWORD'

rustboard-hub install \
  --db 'postgres://rustboard@db.example.com:5432/rustboard?sslmode=verify-full' \
  --db-sslrootcert /etc/rustboard/pg-ca.pem
```

- DSN 里**不建议**写密码：它会进入 argv / shell history / 进程列表；推荐
  `RUSTBOARD_DATABASE_PASSWORD`（优先级高于 URL 内密码）；
- `--db-sslrootcert` 只接受**绝对路径的普通 PEM 文件**（拒绝符号链接/目录），
  仅在 PostgreSQL 下有效；公共 CA 可省略（使用系统根证书）；
- 其余安装参数（`--prefix`、`--listen`、`--tls` 等）与 SQLite 安装完全一致。

### 2.2 安装器的执行顺序（失败不写配置）

非 `--dry-run` 时，安装器在**写配置 / unit / 二进制之前**完成：

1. `--db` 结构校验（scheme / authority / host / database path；不联网）；
2. `--db-sslrootcert` 文件检查（绝对路径、普通文件、非符号链接）；
3. `--offline` 互斥检查（PostgreSQL 探测必须联网）；
4. 连接池建立 + 首次 `SELECT 1`（连接/认证/TLS 错误在这里失败）；
5. `apply_schema`：幂等应用 schema v7，事务级 advisory lock 串行化多实例并发迁移；
6. `ping`：`SELECT 1`，确认 schema 应用后连接仍可用。

任一步失败都会在 `InstallTxn` 开始之前返回：**已有 `hub.toml`、systemd unit、
二进制不会被改写**；PG 上失败的事务自动回滚。`apply_schema` 只建表/索引，不建库。

### 2.3 `--dry-run`

```bash
rustboard-hub install --dry-run --yes --db 'postgres://rustboard@db.example.com/rustboard?sslmode=verify-full'
```

只打印计划：DSN 以 `user:***@host` 脱敏形式出现，并说明将执行
`连接 → apply_schema → ping`、不建库/建角色；**不联网、不写盘**。若 DSN 含密码，
输出中也不会出现密码。

### 2.4 `--offline` 与 PG 互斥

`--offline` 表示“安装过程不做任何网络探测”。PostgreSQL 安装必须连接数据库执行
schema 与探活，因此：

- `install --offline --db postgres://…` 在写盘前明确失败；
- 已有 `hub.toml` 是 PG、又被注入 `--offline`（例如打包脚本）时同样失败；
- 不能“离线写一个未验证的 PG URL 等启动时再试”。

需要离线时请继续用 SQLite。

### 2.5 切回 SQLite

```bash
sudo rustboard-hub install --force --db sqlite
```

`--db sqlite` 把 `database` 重写为当前 `data_dir` 下的 `rustboard.db`，并清掉
`db_sslrootcert`；PG 数据不会被删除。也可以直接编辑 `hub.toml` 后重启 hub。

## 3. TLS 与 `sslmode`

只支持两种显式模式：

| `sslmode` | 行为 |
|---|---|
| `verify-full`（**默认**，推荐） | rustls 校验证书链 + 主机名；`db_sslrootcert` 存在时**替换**系统根 |
| `disable` | 明文；仅限本机回环 / 受信内网，启动时打印一次 WARN（不含 DSN） |

**拒绝** `require` / `prefer` / `verify-ca` / `allow` 或其他值：

- `require` 只保证加密、不承诺主机名校验，与 libpq 语义不一致；
- `prefer` 在服务端不支持 TLS 时会**静默降级明文**；
- `verify-ca` 不校验主机名，驱动也不支持。

配置方式（二选一，推荐配置文件字段）：

```toml
# /etc/rustboard/hub.toml
database = "postgres://rustboard@db.example.com:5432/rustboard?sslmode=verify-full"
db_sslrootcert = "/etc/rustboard/pg-ca.pem"
```

或安装时 `--db-sslrootcert /etc/rustboard/pg-ca.pem`。DSN query 里的
`sslrootcert=` 也会被识别，但**不要同时写两处不同文件**（安装/启动会拒绝）。
`db_sslrootcert` 替换系统根而非追加：既要公共 CA 又要私有 CA 时，把多张 CA
合并在同一个 PEM 文件里。

`verify-full` 的主机名校验使用 DSN 的 `host`：用 IP 连接时证书必须有对应
**IP SAN**，只有 `DNS:localhost` 的证书连 `127.0.0.1` 会失败。

## 4. 密码来源与保密

优先级：

1. `RUSTBOARD_DATABASE_PASSWORD` 环境变量（推荐，不进配置文件）；
2. URL 内密码（兼容；`hub.toml` 0600，日志/错误/`--dry-run` 一律脱敏）。

约定：

- 不要把密码写进 unit 的 `ExecStart`、Compose 文件或仓库；
- systemd 部署可用 0600 的 `EnvironmentFile`（如 `/etc/rustboard/hub.env`，
  `RUSTBOARD_DATABASE_PASSWORD=...`），unit 里只写 `EnvironmentFile=`；
- 日志、错误、`--dry-run`、`docker inspect` 都可能暴露环境变量；限制访问，
  排障时只贴脱敏后的 DSN（`postgres://user:***@host/db`）；
- 安装器 / hub 的错误信息不会回显 userinfo 密码。

## 5. 已有配置与切换

- 安装器只在**显式**给 `--db` 时改写 `database`；`--db postgres://…` 会同时更新
  `database`（和 `--db-sslrootcert`，若给出），保留 `admin_token`、`data_dir`、
  `server_name`、证书等其它字段；
- 探测失败时配置一个字节都不改（写盘发生在探测成功之后）；
- Docker entrypoint 只在**首次初始化**把 `RUSTBOARD_DATABASE` 传给安装器；已有
  volume 不会因环境变量改变数据库。切换方式：
  1. 停 hub；
  2. 备份 SQLite 与配置；
  3. 用 `rustboard-hub migrate --to postgres://…`（D5 交付后）或
     `install --force --db …` + 数据导入；
  4. 启动并检查 `/healthz`、agent、面板与告警；
  5. 保留 SQLite 与备份，观察后再清理。
- 回滚：把 `database` 改回 SQLite 路径并重启；SQLite 文件全程保持原样。

> **迁移前必须停 hub**。运行中的 hub 会持续写入 SQLite / PG，边写边迁移无法保证
> 一致性；迁移失败不得切换配置、不得删除 SQLite。

## 6. 备份与恢复

### 6.1 统一入口（D5）

Phase D5 提供：

```bash
rustboard-hub backup --out /var/lib/rustboard/backups/<timestamp> --yes
rustboard-hub restore --from /var/lib/rustboard/backups/<timestamp> --yes
```

- `backup` 生成 `<timestamp>/` + `manifest.json`（文件 SHA256、版本、schema、
  后端类型）；配置/证书 0600，归档目录 0700；
- PG 后端内部使用 `pg_dump --format=custom`；SQLite 使用 `VACUUM INTO`；
- `restore` 只允许空目标或 `--force`，恢复前会备份当前目标。

> D5 命令在当前分支尚未交付时，请按 6.2 手工执行，并遵循同样的“先停 hub、
> 再备份”规则。不要用 `cp` 直接复制运行中的 PG 数据目录。

### 6.2 手工备份 / 恢复（PG）

```bash
# 1) 停 hub，确保没有写入
sudo systemctl stop rustboard-hub

# 2) 一致性备份（custom 格式，便于 pg_restore 选择性恢复）
TS=$(date +%Y%m%dT%H%M%S)
OUT=/var/lib/rustboard/backups/pg-$TS
install -d -m 0700 "$OUT"
# 重定向由 root shell 完成，备份文件不会以 postgres 用户身份落到目录外
sudo -u postgres pg_dump --format=custom --no-owner rustboard > "$OUT/rustboard.dump"
chmod 0600 "$OUT/rustboard.dump"

# 3) 恢复前先备份当前目标；恢复到空库或全新数据库
sudo -u postgres pg_restore --clean --if-exists --no-owner \
  --dbname=rustboard "$OUT/rustboard.dump"

# 4) 启动并验证
sudo systemctl start rustboard-hub
curl -fsS http://127.0.0.1:8444/healthz
```

要点：

- `pg_dump` 使用一致性快照，但迁移/切换场景仍要求先停 hub；
- 密码不要写在命令行：用 `PGPASSWORD` 环境变量或 0600 的 `~/.pgpass`；
- 备份文件含 agent secret、API token 哈希等敏感数据，按 secret 管理；
- 恢复后核对：samples 点数/时间范围、agents、alert_states/events、api_tokens
  数量、archive 对象数量（D5 校验器会做同样检查）。

## 7. Docker

Docker 默认仍是 SQLite。PostgreSQL 用叠加文件（**不是默认**）：

```bash
install -d -m 0700 docker/secrets
openssl rand -base64 32 > docker/secrets/postgres_password
chmod 0600 docker/secrets/postgres_password

RUSTBOARD_VERSION=v1.0.0 \
docker compose -f docker/compose.example.yml \
  -f docker/compose.postgres.example.yml up -d
```

- `postgres` 服务不发布 5432，只走 compose 内网；
- 密码用 Docker secret：PG 侧 `POSTGRES_PASSWORD_FILE`，hub 侧
  `RUSTBOARD_DATABASE_PASSWORD_FILE`（entrypoint 读取后导出为
  `RUSTBOARD_DATABASE_PASSWORD`，不打印）；
- `RUSTBOARD_DATABASE_SSLROOTCERT` 对应 `--db-sslrootcert`，需只读挂载 PEM；
- 示例为 stock 镜像无 TLS，使用 `sslmode=disable`；生产请给 PG 配证书并改成
  `verify-full`；
- `RUSTBOARD_DATABASE` 只在首次初始化生效；已有 volume 改环境变量无效，按 §5
  切换；
- Docker 内的非 root 启动（`--user 10001`）不会执行 install，也不会读取
  `RUSTBOARD_DATABASE` 改写配置；`pg_dump`/`pg_restore` 不在 hub 镜像内，备份
  请在宿主或专用容器执行。

详见 [docker/README.md](../../docker/README.md) §14。

## 8. 测试与排错

- 单元测试：`cargo test -p rustboard-hub --locked --bin rustboard-hub install_cmd::tests`
  （无 PG 时真实探测用例打印 `SKIP`）。
- 集成测试：设置 `RUSTBOARD_TEST_PG`（本地测试库，角色需能建表）后可跑
  `postgres_probe_applies_schema_when_test_pg_available`；未设置时明确 SKIP。

常见错误：

| 现象 | 原因 / 处理 |
|---|---|
| `连接 PostgreSQL 失败` / `password authentication failed` | 密码来源不对（env 优先于 URL）、角色不存在或 `pg_hba.conf` 拒绝 |
| `schema 初始化失败` / `permission denied for schema public` | 角色不是库 owner，或缺少 `GRANT CREATE ON SCHEMA public` |
| `sslmode 只支持 "verify-full" 或 "disable"` | 配置了 `require`/`prefer`/`verify-ca`；改成 `verify-full`（或显式 `disable`） |
| `certificate not valid for name` | DSN host 与证书 SAN 不匹配（IP 连接需要 IP SAN） |
| `UnknownIssuer` / 根证书错误 | 私有 CA 未通过 `db_sslrootcert` / `--db-sslrootcert` 提供，或 PEM 不含 CA |
| `schema 版本高于当前二进制` | 用旧二进制连了已迁移的新库；升级二进制，不要降 schema |
| `--offline 与 PostgreSQL 互斥` | 去掉 `--offline`，或改用 SQLite |
| 安装卡在 schema | 另有实例持有 advisory lock（正在迁移）；等待其完成，不要强杀事务 |

排障时不要粘贴含密码的完整 DSN、`docker inspect` 全量环境或 `pg_dump` 内容。
