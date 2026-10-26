# Phase E S3：真实 TLS PostgreSQL `verify-full` 验证方案

> 日期：2026-10-26｜基线：`main` `d92cf92`（S1/S2 计划已提交）
> 关联：[M5 收尾计划](2026-10-26-m5-phase-e-and-ki22.md) §1.3、
> [Phase D 计划](2026-10-26-m5-phase-d-postgres-backup-l01-l03.md) D-G5。
> 状态：**已完成**（功能 e2e 27/27；证据基于 rc.2 预发布二进制，v1.0.0
> 发布前需在干净树重跑并重新绑定版本/hash）。

## 1. 目标

用真实启用 TLS 的 PostgreSQL（不是 `sslmode=disable`，也不是 mock）验证：

1. 正确 CA/SAN/`db_sslrootcert`：hub 启动、agent 上报、查询、重启后仍可连接；
2. 错误 CA、错误主机名、缺失/非法根证书：hub 启动失败，**不回退 disable**；
3. 密码/完整 DSN 不进入日志、错误、argv；测试私钥不提交；
4. 形成可复制的本机 e2e 脚本与文档。

## 2. 范围

新增/修改：

- `tests/e2e/v100-pg-tls.sh`：临时 CA/服务端证书、Docker PG16、hub 配置、
  真实 agent 上报、重启持久化、负向 TLS 用例、证据归档。
- `docs/install/postgres.md`：真实 TLS 验证步骤、客户端证书限制、错误排查。
- 不改生产 Rust、协议、schema、安装器；若发现产品缺陷，单独立项修复。

## 3. 测试矩阵

| 场景 | 期望 |
|---|---|
| 正确 CA + SAN `IP:127.0.0.1` + `verify-full` + `db_sslrootcert` | hub 启动 200；agent enroll/上报；查询到样本 |
| hub 重启（同一 PG） | 启动成功；点数量/agent 记录仍在 |
| 错误 CA（另一 CA 签的根） | 启动非 0；TLS 证书校验失败；不监听/不降级 |
| 主机名不匹配（经 127.0.0.2:port 代理，证书仅 SAN 127.0.0.1） | 启动非 0；hostname verification 失败 |
| `db_sslrootcert` 指向缺失/目录/符号链接 | 配置层拒绝；不读取 |
| 错误日志 | 不含 PG 密码/完整 DSN（脱敏 `***`） |
| server 要求客户端证书 | 记录为当前限制（驱动 `with_no_client_auth`），不宣称通过 |

## 4. 证书与 PG

- 临时 CA（2 天）、server key/cert，SAN `DNS:localhost,IP:127.0.0.1`，
  `extendedKeyUsage=serverAuth`；私钥 0600，证书 0644。
- Docker `postgres:16`，随机宿主端口（127.0.0.1），
  `-c ssl=on -c ssl_cert_file=... -c ssl_key_file=...`；
  **不设置 `ssl_ca_file`**，避免服务端请求客户端证书（当前 hub 不支持客户端证书）。
- PG 用户/库用一次性强密码，只写临时 env/配置（0600），不打印。
- 端口尽量随机；容器名带 PID/随机后缀；trap 清理容器/临时目录（保留失败日志摘要）。

## 5. Hub/agent 流程

1. `rustboard-hub init` 生成 CA/服务端证书和配置；把 `database` 改成 PG DSN，
   **在第一个 `[section]` 之前**插入 `db_sslrootcert`（TOML 顶层；脚本必须校验
   `grep '^db_sslrootcert'`）。
2. 启动 hub，等待 `/healthz` 200；用 `hub agent add` 生成 token，写 agent 配置，
   启动真实 agent，等待 `agent_id`/online，等待至少一批样本写入 PG。
3. 用 `psql`（`PGPASSWORD` 环境变量，密码不进 argv）或管理 API 验证样本 >0。
4. 停止 hub/agent，重启 hub，验证样本数量不减少、agent 记录仍在。
5. 负向：复制配置改 `db_sslrootcert` 到错误 CA/缺失路径/目录/符号链接；
   启动 hub 必须非 0；日志脱敏检查。
6. 主机名负向：Python TCP 代理监听 `127.0.0.2:<port>` 转发到
   `127.0.0.1:<pgport>`；DSN 用 `127.0.0.2`，证书只含 `127.0.0.1`，
   hub 必须失败。
7. 记录 hub 日志、psql 计数、负向退出码/关键错误（脱敏）到
   `target/pg-tls-e2e/<timestamp>/`；不提交私钥/密码。

## 6. 验收与停止

**执行结果（2026-10-26）**：`tests/e2e/v100-pg-tls.sh` **27/27** 通过，覆盖正确
CA/SAN、真实 agent 上报、hub 重启持久化、错误 CA、缺失/目录/符号链接根证书、
主机名不匹配与日志脱敏。证据：
`target/pg-tls-e2e/20261026T114916Z-3488392/evidence/`。当前限制：hub 仅做
服务端认证 TLS，不支持 PG 要求客户端证书（`ssl_ca_file`），已在
`docs/install/postgres.md` §3.2 记录，未声称通过。

- 正确路径、重启、三类负向全部通过；错误日志不含密码/完整 DSN；
- 若正确路径失败：先确认是配置/证书/驱动问题；若产品缺陷，停止并报告，
  不带病发布；
- `server 要求客户端证书` 若失败，记录为已知限制（需另立 `db_sslcert/key`
  设计），不静默改测试绕过；
- 脚本可在 CI 之外的 Linux + Docker 环境重复运行，依赖 `openssl`、`psql`、
  `docker`；不联网拉取镜像（镜像缺失时明确 SKIP/失败，不伪造）。
