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
- `packaging/install.sh` 会检测透传的 `--db postgres://…`：**不会**自动追加
  `--offline`，显式 `--offline` 会在写任何文件之前失败（与 Docker entrypoint
  一致）；`--db sqlite` / 未给 `--db` 仍按原逻辑自动追加；
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
- **systemd 托管 + 无密码 DSN**：密码只来自安装进程的
  `RUSTBOARD_DATABASE_PASSWORD`，unit 默认**不会**继承该环境变量，重启后会认证
  失败。安装器检测到该组合时会打印 WARN；必须手工持久化（0600，root 所有）：

  ```bash
  install -d -m 0700 /etc/rustboard
  printf '%s\n' 'RUSTBOARD_DATABASE_PASSWORD=REPLACE_WITH_STRONG_PASSWORD' \
    > /etc/rustboard/hub.env
  chmod 0600 /etc/rustboard/hub.env

  install -d -m 0755 /etc/systemd/system/rustboard-hub.service.d
  cat >/etc/systemd/system/rustboard-hub.service.d/10-rustboard-env.conf <<'EOF'
  [Service]
  EnvironmentFile=/etc/rustboard/hub.env
  EOF

  systemctl daemon-reload
  systemctl restart rustboard-hub
  ```

  也可以用带密码的 0600 `hub.toml`（不推荐：密码会进配置）。容器部署由
  entrypoint 导出环境变量，不受此限制。
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
  2. 备份 SQLite、配置与证书（或先执行 `rustboard-hub backup`）；
  3. `rustboard-hub migrate --to 'postgres://…' --dry-run` 预检；
  4. `rustboard-hub migrate --to 'postgres://…' --yes` 迁移；
  5. 启动并检查 `/healthz`、agent、面板与告警；
  6. 保留 SQLite 与备份，观察后再清理。
- 迁移命令的细节、非空目标与回滚见 §6；SQLite 文件全程保持原样。
- **不要用 `install --db postgres://…` 直接切换有数据的 SQLite**：安装器只改写
  `hub.toml`、不迁移数据；已有业务数据必须用 `rustboard-hub migrate`。只有全新
  安装或空 SQLite 才可直接安装到 PostgreSQL。
- 回滚：把 `database` 改回 SQLite 路径并重启；SQLite 文件全程保持原样。

> **迁移前必须停 hub**。运行中的 hub 会持续写入 SQLite / PG，边写边迁移无法保证
> 一致性；迁移失败不得切换配置、不得删除 SQLite。

## 6. 迁移、备份与恢复

> Phase D5 的统一入口已交付：`backup` / `restore` / `migrate`。`backup` 可在 hub
> 运行时生成一致性快照（SQLite `VACUUM INTO` / PG `pg_dump`）；`migrate` 与
> `restore` 要求**先停 hub**：有 systemd 时用 `systemctl is-active
> rustboard-hub` 检查，无 systemd 时打印 WARN，由确认与迁移前备份兜底。不要用
> `cp` 直接复制运行中的 PG 数据目录。

### 6.1 备份

```bash
rustboard-hub backup --out /var/lib/rustboard/backups --yes
```

- `--out` 只给根目录，命令会在其下创建 `<UTC timestamp>/`；`restore --from`
  指向这个具体子目录。备份目录包含：
  - SQLite：`rustboard.db`（`VACUUM INTO` 快照）；PostgreSQL：`rustboard.dump`
    （`pg_dump --format=custom --no-owner --no-privileges`）；
  - `hub.toml`、`certs/`（证书与私钥）和 `manifest.json`；
- `manifest.json` 记录 manifest 格式版本、RustBoard 版本、schema、后端、创建时间，
  以及每个文件的相对路径、SHA256、大小和权限；目录 0700，配置/私钥/备份文件 0600；
- PG 备份在创建目录前检查 `pg_dump`；缺失时直接失败，不留下半成品目录；
- 备份含 agent secret、API token 哈希、证书私钥，必须按 secret 管理；
- `--config` 指定 `hub.toml`（默认 `/etc/rustboard/hub.toml`）；`--yes` 用于
  非交互执行。

### 6.2 恢复

```bash
# 当前 /etc/rustboard/hub.toml 存在：目标 data_dir/database 以该配置为准
rustboard-hub restore --from /var/lib/rustboard/backups/<timestamp> --yes

# 当前配置不存在（裸机/新主机）：必须显式给 --data-dir（绝对路径）
rustboard-hub restore --from /var/lib/rustboard/backups/<timestamp> \
  --data-dir /var/lib/rustboard/hub --yes

# 恢复 PostgreSQL 备份且配置不存在：还必须给 --db 指向当前目标
rustboard-hub restore --from /var/lib/rustboard/backups/<timestamp> \
  --data-dir /var/lib/rustboard/hub \
  --db 'postgres://rustboard@db.example.com:5432/rustboard?sslmode=verify-full' \
  --yes
```

- 只接受包含 `manifest.json` 的备份目录；先完整校验 manifest 版本与每个文件的
  SHA256/大小/路径，任何不一致都在写目标前失败；备份目录中的 `hub.toml` **不会**
  被信任为写入路径；
- **目标路径只来自本机当前 `--config`**：当前配置存在时，`data_dir` / `database`
  以配置为准；配置不存在时必须给 `--data-dir`（绝对路径），SQLite 的 DB 固定为
  `<data-dir>/rustboard.db`，PG 还必须用 `--db` 指定当前目标。恢复时会打印
  绝对目标（数据库、`certs/`、`hub.toml`）；备份内 hub.toml 的这两个路径会被
  重写为目标值后写回，其余字段保留；
- 当前配置存在时不允许再给 `--data-dir`/`--db`（避免配置与参数打架）；配置不存在
  且缺 `--data-dir`（SQLite/PG）或 PG 缺 `--db`，在写任何文件前失败；
- 依次恢复数据库、证书、配置（配置最后写）；PG 需要外部 `pg_restore`
  （`--clean --if-exists --no-owner --no-privileges --single-transaction`）；
- 目标非空时默认拒绝，必须 `--force`；非空目标的恢复前快照失败会**直接中止**，
  不会在无备份情况下覆盖。只有显式 `--no-pre-restore-backup` 才跳过这个保护；
- 目标路径含符号链接或 `..` 会在写入前拒绝。**SQLite 目标若存在 `-wal`/`-shm`/
  `-journal`，restore 直接拒绝**：必须先干净停止 hub 并确认/删除这些 sidecar，
  否则 SQLite 会重放旧 WAL。rename 前后还会校验 SHA256、`quick_check` 与 21 张
  表行数；失败会用恢复前副本回滚（没有旧库则删除新库）并报错；
- 恢复同样要求 hub 已停止：有 systemd unit 且明确 inactive 可继续；无 systemd、
  unit 不存在或状态无法确认时，必须显式 `--hub-stopped`；
- **文件属主**：恢复以哪个用户执行，写出的配置/证书/数据库就归哪个用户。root
  执行后需把 `/etc/rustboard`、`/var/lib/rustboard` 交回 hub 运行用户；Docker
  `--user 10001:10001` 场景需 `chown -R 10001:10001`，或直接以该用户运行恢复，
  否则下次启动会因权限失败；
- 恢复后核对：samples 点数/时间范围、agents、alert_states/events、api_tokens
  数量、archive 对象数量。

### 6.3 迁移 SQLite → PostgreSQL

```bash
# 1) 停 hub
sudo systemctl stop rustboard-hub

# 2) 预检：只连接源/目标、校验 schema 与目标是否为空，不写数据
rustboard-hub migrate \
  --to 'postgres://rustboard@db.example.com:5432/rustboard?sslmode=verify-full' \
  --dry-run

# 3) 正式迁移（非交互）
rustboard-hub migrate \
  --to 'postgres://rustboard@db.example.com:5432/rustboard?sslmode=verify-full' \
  --yes
```

- 源必须是 SQLite v7；`--to` 必须是 `postgres://`/`postgresql://`；
- 迁移前在 `<data_dir>/backups/<timestamp>/` 备份 SQLite、`hub.toml` 与证书；
  导入在单个目标事务中完成并逐表校验；失败自动回滚目标事务，**不改写配置、
  不删除 SQLite**；
- 只有迁移与校验全部成功后才原子改写 `hub.toml` 的 `database`，并保留旧配置
  `.bak-<ts>`；随后启动 hub，检查 `/healthz`、agent、面板与告警；
- `--dry-run` 不 apply schema、不写数据、不创建备份目录、不改配置；源库预检在
  无 `-wal`/`-journal` 时用 immutable 只读打开，存在未 checkpoint WAL 时先复制
  DB+WAL 到 0700 临时目录再读，源目录零写入；但**目标非空且未指定 `--force`
  时仍以非零码退出**，提示实际迁移会被拒绝；
- 有 `/run/systemd/system` 时用 `systemctl is-active rustboard-hub` 拒绝运行中的
  hub；unit 明确 `inactive`/`failed` 可继续；没有 systemd、unit 不存在或状态无法
  确认时**必须显式 `--hub-stopped`**（先停 hub，再由人工确认）。不读取/伪造 PID
  文件；迁移开始即持有目标端的会话级 advisory lock，覆盖
  `inspect → pg_dump → TRUNCATE → import → 配置切换`，并发 migrate 会串行等待。
  该锁使用 `sslmode=disable` 的专用连接；`verify-full` 目标拿不到锁时非 force
  迁移会 WARN 并依赖 core 导入事务的空库复验与表锁，`--force` 非空目标仍要求
  `sslmode=disable`；
- 目标非空：默认拒绝；`--force` 会先 `pg_dump` 目标、二次确认后清空 21 张业务表
  （保留 `schema_migrations`）。**当前限制**：`--force` 的清空路径只支持显式
  `sslmode=disable`（内部使用 NoTls）；`verify-full` 的非空目标需先手工备份并
  `TRUNCATE` 21 张业务表，再不带 `--force` 迁移；
- `--force` 目标非空时需要外部 `pg_dump`（`--format=custom --no-owner
  --no-privileges`）；目标为空时不需要；
- 回滚：把 `database` 改回 SQLite 路径，或 `install --force --db sqlite`；
  SQLite 文件全程未被修改，迁移不是双写。

### 6.4 手工备份 / 恢复（PG）

统一命令不可用、或需要 `pg_restore` 选择性恢复时，可在宿主手工执行。此时
`pg_dump`/`pg_restore` 必须已安装（Debian/Ubuntu 包名 `postgresql-client`）。
单纯备份可用一致性快照在线执行；迁移/切换/恢复场景仍要求先停 hub。

> **客户端版本尽量与服务端主版本一致**：本机用 PG16 client 对 PG16 验证通过；
> PG17 client 对 PG16 会因 `transaction_timeout` 参数失败。安装前用
> `pg_dump --version` 与 `psql --version` 确认版本；跨大版本时优先装与服务端
> 匹配的客户端，或临时用 `postgres:<major>` 容器执行。

```bash
# 1) 停 hub，确保没有写入
sudo systemctl stop rustboard-hub

# 2) 一致性备份（custom 格式，便于 pg_restore 选择性恢复）
TS=$(date +%Y%m%dT%H%M%S)
OUT=/var/lib/rustboard/backups/pg-$TS
install -d -m 0700 "$OUT"
# 重定向由 root shell 完成，备份文件不会以 postgres 用户身份落到目录外
sudo -u postgres pg_dump --format=custom --no-owner --no-privileges rustboard > "$OUT/rustboard.dump"
chmod 0600 "$OUT/rustboard.dump"

# 3) 恢复前先备份当前目标；恢复到空库或全新数据库
sudo -u postgres pg_restore --clean --if-exists --no-owner --no-privileges \
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
  数量、archive 对象数量。

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

- `postgres` 服务默认 pin `postgres:16-alpine`，与 CI/文档的 PG16 备份客户端
  （`pg_dump`/`pg_restore`）对齐；换 17 时需同步 client 版本。**不发布 5432**，
  只走 compose 内网；
- 密码用 Docker secret：PG 侧 `POSTGRES_PASSWORD_FILE`，hub 侧
  `RUSTBOARD_DATABASE_PASSWORD_FILE`（entrypoint 读取后导出为
  `RUSTBOARD_DATABASE_PASSWORD`，不打印）；
- 只设 `RUSTBOARD_DATABASE_PASSWORD(_FILE)`、未设 `RUSTBOARD_DATABASE` 时：
  全新 volume 直接失败（拒绝静默 SQLite）；已初始化 volume 仅当 `hub.toml`
  已使用 `postgres://` 时允许（运行时密码），否则失败；
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

- PG 实库测试（需要本地 PostgreSQL 16/17，登录角色需 `CREATEDB`；
  `postgres_load` 还需要 `pg_terminate_backend` 权限，superuser 或
  `pg_signal_backend`）：

  ```bash
  RUSTBOARD_TEST_PG='postgres://rustboard:<TEST_PASSWORD>@127.0.0.1:5432/rustboard?sslmode=disable' \
    cargo test -p rustboard-core --locked \
      --test postgres_schema --test postgres_core \
      --test postgres_parity --test postgres_migrate --test postgres_load
  ```

  未设置 `RUSTBOARD_TEST_PG` 时每个用例打印 `SKIP` 并返回（cargo 记为 passed），
  不能把“0 failed”当作已执行；CI 的 `postgres` job 会设置该变量并跑上述五个 target。
  `postgres_load` 3/3 通过：200 OS 线程/200 agent，每 agent 5 批×3 点，3000
  samples / 1000 ingest_batches / 0 失败，pool=8，总耗时 1.45–2.83s；kill 4 条
  池连接后首次重试成功、53 行无丢失；并发同键每轮 1 Inserted + 1 Duplicate。
  **这是 storage 级压测，不是 hub 端 200 agent 端到端。**
- CLI/备份/L-01：先安装 PG16 client，再跑
  `cargo test -p rustboard-hub --locked --test phase_d_backup --test phase_d_l01_l03`。
  本机 `phase_d_backup` **5/5 通过**（含真实 PG `pg_dump`/`pg_restore`）；缺
  `pg_dump`/`pg_restore` 时该用例明确 SKIP（不假绿），不能据此声称已覆盖 PG 备份。
- L-01 的权限收紧失败用例默认 `#[ignore]`，root + `CAP_LINUX_IMMUTABLE` 门禁额外执行：

  ```bash
  sudo cargo test -p rustboard-hub --locked --test phase_d_l01_l03 -- \
    --ignored --exact run_fails_when_account_hardening_is_denied
  ```

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
| `pg_dump 不存在或不在 PATH` / `pg_restore 不存在` | 安装 `postgresql-client`，并让客户端主版本与服务端一致；见 §6.4 |
| `pg_dump: error: parameter "transaction_timeout"` | PG17 client 连 PG16 服务端；换 PG16 client 或与服务端匹配的客户端 |
| 安装卡在 schema | 另有实例持有 advisory lock（正在迁移）；等待其完成，不要强杀事务 |

排障时不要粘贴含密码的完整 DSN、`docker inspect` 全量环境或 `pg_dump` 内容。

## 9. 部署限制（Phase D）

1. **单 hub 语义**：PG 后端没有 leader 选举或多活协调。同一数据库只允许一个
   active hub；多个 hub 同时连接会重复评估告警、重复发送通知/归档。需要 HA 时
   由部署方保证单写者；当前版本不承诺多活。
2. **`migrate --force` 的 TLS 限制**：非空 PG 目标清空路径内部使用 NoTls，目前
   只支持显式 `sslmode=disable`；`verify-full` 非空目标必须手工备份并清空
   21 张业务表（保留 `schema_migrations`）后，再不带 `--force` 迁移。
3. **外部 `pg_dump`/`pg_restore`**：hub 静态构建、离线包与 Docker 镜像不内置
   PostgreSQL 客户端；PG 备份/恢复缺少命令时会失败并提示安装
   `postgresql-client`。客户端主版本最好与服务端一致；PG17 client 对 PG16 会
   因 `transaction_timeout` 失败，验证环境使用 PG16 client + PG16 服务端。
4. **恢复后的文件属主**：root 执行 `restore` 后文件归 root；systemd 部署需交回
   hub 用户，Docker `--user 10001:10001` 需先 `chown -R 10001:10001`，否则启动
   会因权限失败。
5. **TLS verify-full 端到端**：已有配置层/单元测试与 D0 spike（本地 TLS PG
   连接、证书链与主机名校验）证据；尚未在真实 TLS PostgreSQL 上做完整
   “安装→启动→读写” smoke，生产启用前请先用测试实例复核 CA/SAN/
   `db_sslrootcert`。
6. **压力与长稳**：storage 级 200 agent（`postgres_load`）已通过；hub 端真实
   200 agent 端到端、100/500/1000 agent 与 24h 长稳仍在 Phase E。storage 级
   load 只验证并发写入/查询与断连重连，不能替代 hub 端真实压测。
7. 备份含 agent secret、API token 哈希、证书私钥与数据库内容，必须按 secret
   管理；迁移/恢复前必须停 hub。
