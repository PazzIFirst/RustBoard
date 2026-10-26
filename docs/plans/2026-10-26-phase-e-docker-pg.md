# Phase E S4：PostgreSQL Docker 镜像内 e2e 方案

> 日期：2026-10-26｜基线：S2 工具 `1cd56d9`；S4 使用当前源码重建的
> amd64 静态产物（dist 由 `packaging/build-release.sh` 生成，version 仍为
> `1.0.0-rc.2`，发布时统一升 1.0.0）。
> 关联：[M5 收尾计划](2026-10-26-m5-phase-e-and-ki22.md) §1.4。

## 1. 目标

用**当前源码重建的 hub 镜像**（不是 rc.2 旧镜像冒充），验证：

1. 默认 compose 仍 SQLite：无 postgres service、无 5432 暴露；
2. PG overlay 能启动 hub + PostgreSQL，真实 agent enroll/上报、管理 API 可查；
3. 容器/volume 重启后 PG 数据仍在；`--user 10001:10001` 已初始化 volume 可用；
4. hub 镜像内没有 `pg_dump`/`pg_restore`，备份/恢复是镜像外步骤；
5. 用外部 PostgreSQL client 对 compose 内 PG 做一次 dump/restore，恢复后点数一致。

## 2. 文件与边界

- 新增 `tests/e2e/v100-docker-pg.sh`：只创建带唯一前缀的 compose 项目、
  容器/网络/volume/临时目录；trap 清理自己的资源；不 push、不碰生产。
- `docs/install/docker.md` / `docs/install/postgres.md`：补 PG overlay 容器内 e2e
  与“镜像不含 pg_dump、备份必须用外部 client”的运维说明。
- 不改生产 Rust、协议、schema、Dockerfile（除非 e2e 暴露缺陷，另立修复）。

## 3. 构建来源

- `packaging/build-release.sh --arch amd64` 已产出当前 `dist/amd64/bin`、
  `web/dist`；Dockerfile 只复制这些产物，不重新编译。
- 本地镜像 tag 为 `ghcr.io/pazzifirst/rustboard-{hub,panel,agent}:local-s4`
  （与 compose 的 `${RUSTBOARD_VERSION}` 拼接一致）；构建后检查
  `org.opencontainers.image.revision` 或二进制 `--version`，避免误用旧镜像。
- 镜像内 `command -v pg_dump` 必须为空；备份/恢复由宿主 `psql/pg_dump`
  或临时 `postgres:16` client 容器完成。

## 4. 运行矩阵

| 场景 | 断言 |
|---|---|
| 默认 compose 配置 | `docker compose config` 无 postgres/5432；hub 仍发布 8443、panel 只回环 8080 |
| 默认 compose 实跑 | hub healthy；hub 配置 database 为 `sqlite:///data/...`；重启后配置哈希不变 |
| PG overlay | postgres healthy；hub 用 `RUSTBOARD_DATABASE` + 密码文件启动；`/healthz` 200 |
| agent | 真实 token/指纹 enroll；PG `samples`/`ingest_batches`/`agents` > 0 |
| 重启 | `docker compose restart` 后 PG 数据不减少、agent 记录仍在 |
| `--user 10001` | 已初始化 hub volume 可启动，日志无权限错误 |
| backup/restore | `pg_dump -Fc` → 新库 `pg_restore` → 样本数/表数一致；原库不动 |
| 镜像无 client | hub/agent 镜像内无 `pg_dump`/`pg_restore` |
| 默认 SQLite | 默认 compose 无 PG 依赖，数据落在 hub_data volume |

## 5. 安全与清理

- PG 密码只写 0600 临时 secret 文件，不打印/不进 argv；证据只保存脱敏日志。
- compose 项目名 `rb-s4-<UTC>-<PID>`；只删本项目容器/网络/volume 与临时目录。
- 不删除 `rb-pebble`、其它用户容器/volume；失败保留证据目录并打印路径。
- 不把私钥、token、数据库密码写入仓库；`target/` 与 `dist/` 均不入库。

## 6. 通过标准

- 默认 compose 与 PG overlay 均通过；重启/`--user`/备份恢复无数据丢失；
- hub 镜像无 PostgreSQL client，文档明确外部备份前置条件；
- 失败不得用旧 rc.2 镜像或跳过 backup/restore 冒充通过。
