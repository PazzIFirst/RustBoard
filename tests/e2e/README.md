# RustBoard 端到端回归

本目录包含多套可重复执行的端到端验收脚本，都在 `127.0.0.1` 的随机五位数端口上
启动临时实例，用真实 TLS / WebSocket 会话验证行为，结束后清理进程和临时目录：

| 脚本 | 覆盖 |
|---|---|
| `security.sh` | issue #1–#8 与协议门禁：身份绑定、协议版本、吊销、在线状态 |
| `cert-rotation.sh` | 证书有效期、`cert-info` / `renew`、服务端 `rotate-cert`、CA 信任自动重连、指纹一致性 |
| `panel.sh` | M2 面板：admin token 鉴权、登录/限速/Cookie、overview/series/settings、采样间隔 60s 内生效、静态与路径穿越 |
| `hardening.sh` | v0.2.1 硬化：弱 token、未知 API 鉴权、管理限速、非回环 WARN、单 IP 连接洪水、rotate 热加载、可信代理 XFF（含非法/超长/9 跳拒绝、不可信来源伪造无效）、Origin、reset-password |
| `control.sh` | M3 控制面：能力协商、systemd/Docker 白名单、进程 PID+名称、日志 tail/逃逸、审计分页与面板代理、能力关闭/离线 |
| `v031.sh` | v0.3.1 硬化 #13 / KI-17：过期服务端证书启动自愈（同 CA 重签、成对备份/权限、指纹、原 agent CA 信任重连）；hub/panel 各 30 条半截 header 慢连接下 `/healthz` 仍 200 且按 5s header 超时关闭 |
| `v032.sh` | v0.3.2 控制面可靠性 #18/#16/#19：pending 超时后清理（fake agent 不回复，连续 4×`504 control_timeout`、不出现 `429 too_many_pending`）、续签窗口 `busy_renewing`（`503` / 固定文案 / 审计 error）、journald tail 保留最新（`--reverse`、`truncated=true`、旧→新、≤256 KiB） |

`security.sh` 是最早的一套，下文细节以它为例；其余脚本的断言清单见各自文件头部注释。

## 依赖

| 依赖 | 说明 |
|---|---|
| Linux | 脚本使用 `mktemp`、`sed -i`、`awk`、`date +%s%3N` 等 GNU 工具 |
| bash 4.4+ | 使用数组与 `set -euo pipefail` |
| Python 3.8+ | **仅标准库**（`ssl` / `socket` / `hashlib` / `urllib`）；无需 `pip install`，也不联网。`v031.sh` 额外需要已安装的 `cryptography`（只用于生成过期证书） |
| cargo / rustc | 用于 `cargo build --locked`（`hardening.sh` / `control.sh` / `v031.sh` / `v032.sh` 构建 hub/agent，前三套还会构建 panel） |
| curl | `control.sh` 用 curl 访问 hub 管理 API 与面板 API |

脚本不会安装任何依赖，也不会访问网络。`probe.py` 里自带最小 MessagePack
编解码器和 RFC 6455 客户端。

## 运行

在仓库根目录执行：

```bash
bash tests/e2e/security.sh
```

脚本会：

1. `cargo build --locked -p rustboard-hub -p rustboard-agent`
2. 用 `rustboard-hub init` 生成临时 CA、服务端证书和配置（`agent_listen` /
   `admin_listen` 均显式绑定 `127.0.0.1`）
3. 用 `rustboard-hub agent add` 生成两个一次性 token，启动两个独立 agent
   完成 enrollment 并上报样本
4. 依次执行下面的断言
5. 无论成功失败都 kill 掉自己启动的所有进程；成功时删除临时目录

端口从 `20000–64999` 随机挑选并先做 bind 探测；两个端口保证不同。

**失败时**脚本会以非零码退出，并打印 `hub.log`、两个 `agent.log` 以及
hold 探针日志的尾部。调试时希望保留临时目录和全部日志：

```bash
KEEP_E2E_TMP=1 bash tests/e2e/security.sh
```

## 断言清单

| # | 场景 | 判定 |
|---|---|---|
| a | 正常流程 | A/B 两个 agent 状态均为 `online`，A 的 `/api/v1/series` 行数 > 0 |
| b | 无客户端证书发 `Hello` | 收到 `Problem`（`mtls_required`），**没有** `Welcome` |
| c | 用 A 的证书/私钥 + B 的 secret 发 `agent_id=B` 的 `Hello` | 被拒，B 的样本数不变 |
| d | A 的合法会话发 `agent_id=B` 的 `Batch` | 收到 `Problem`、无 `Ack`，B 的样本数不变 |
| e | `agent revoke` | 已建立连接在 ≤3s 内被关闭（并收到 `Problem revoked`），状态变为 `revoked`，重连被拒 |
| f | 关闭 agent（SIGKILL 模拟异常断线） | ≤10s 内状态变为 `offline` |
| g1 | 同一 agent 两条连接，关闭旧的那条 | 仍为 `online` |
| g2 | 再关闭最后一条连接 | ≤10s 内变为 `offline` |
| h | 用协议版本 1 发 `Hello`（当前协议 2） | 收到 `Problem`（`bad_protocol`），**没有** `Welcome` |

断言 e 的实际关闭耗时来自 `date +%s%3N` 的墙钟差；hub 的吊销轮询周期是 2s，
因此正常情况下耗时在 2s 出头。

每次运行输出形如：

```
PASS [a] A/B 均 online，A 样本数=47
PASS [f] A/B 断线后均 ≤10s 变为 offline
...
e2e 结果: 全部 9 项通过
```

## 环境变量

| 变量 | 默认值 | 用途 |
|---|---|---|
| `PYTHON` | `python3` | 指定 Python 解释器 |
| `CARGO` | `cargo` | 指定 cargo（绝对路径也可） |
| `CARGO_TARGET_DIR` | `<repo>/target` | 与 cargo 保持一致；脚本从对应目录取二进制 |
| `TMPDIR` | `/tmp` | 临时目录的父目录 |
| `KEEP_E2E_TMP` | `0` | 设为 `1` 时保留临时目录与日志 |

## 目录内容

- `security.sh`：身份/协议/吊销回归（本节断言的执行脚本）
- `cert-rotation.sh`：证书轮换与 CA 信任回归
- `v031.sh` + `v031_cert.py`：v0.3.1 过期证书启动自愈与 KI-17 慢连接回归；
  `v031_cert.py` 用当前 CA 生成 2020 年窗口的过期证书并离线校验证书/私钥/CA 关系；
  panel 场景不依赖 `web/dist`，未构建前端时只影响页面（503），`/healthz` 仍 200
- `panel.sh` + `panel_probe.py`：M2 面板与 hub 管理 API 回归（需要 `web/dist` 已构建）
- `hardening.sh` + `hardening_probe.py`：v0.2.1 硬化回归；覆盖弱 token、管理 API 限速、
  未知 API 鉴权、非回环 WARN、单 IP 连接洪水、`rotate-cert` 热加载、
  面板可信代理 XFF / Secure Cookie、非法/超长/9 跳 XFF 拒绝、不可信直连来源伪造 XFF
  无效、锁定 XFF 隔离、Origin 校验与 `reset-password`
- `control.sh`：M3 控制面回归；使用临时 fake `systemctl` / `docker` / `journalctl`，
  不依赖宿主机服务，也不需要 root
- `v032.sh` + `v032_agent.py`：v0.3.2 控制面可靠性与 journal tail 回归；
  `v032_agent.py` 用真实 enrollment 留下的 agent_id / secret / 客户端证书建立
  mTLS 会话，`ignore` 模式故意不回复 `ControlRequest`（验证 #18 pending 清理），
  `busy` 模式按请求 id 回 `busy_renewing`（验证 #16 Hub 映射与审计）；
  场景 3 使用 fake `journalctl`（输出 1000 行 × 约 1KiB 新→旧）验证 #19
- `probe.py`：TLS + WebSocket + MessagePack 测试客户端；子命令
  `hello` / `batch` / `hold` / `status` / `series-count` / `health`

`panel.sh` 需要先构建前端：

```bash
cd web && pnpm install --frozen-lockfile && pnpm build
bash tests/e2e/panel.sh
```

`hardening.sh` 会自行构建 hub / agent / panel，同样可选使用已构建的 `web/dist`：

```bash
bash tests/e2e/hardening.sh
KEEP_E2E_TMP=1 bash tests/e2e/hardening.sh   # 保留日志与临时证书/数据库
```

它按方案契约断言；实现未完成时对应项会如实 FAIL，不会修改实现。

`v031.sh` 会自行构建 hub / agent / panel，不需要 `web/dist`（panel 场景只访问
`/healthz`）；运行约 20s，覆盖过期证书启动自愈与两个监听口的慢连接：

```bash
bash tests/e2e/v031.sh
KEEP_E2E_TMP=1 bash tests/e2e/v031.sh   # 保留临时证书/日志
```

`v032.sh` 会自行构建 hub / agent，不需要 panel 或 `web/dist`；运行约 10–15s，
覆盖 #18 pending 超时清理、#16 续签窗口 `busy_renewing` 与 #19 journald
tail 保留最新。fake agent 只保持在线并选择是否应答，不执行任何控制动作：

```bash
bash tests/e2e/v032.sh
KEEP_E2E_TMP=1 bash tests/e2e/v032.sh   # 保留临时日志与 fake journalctl 参数
```

## 范围说明

以下行为不在本脚本内，避免测试时间过长或依赖不可控的网络条件：

- 45s 心跳超时（issue #7 的另一条路径）需要真实静默等待，未纳入
- 吊销与并发写入的精确竞态（`insert_batch` 事务内复核吊销）由单元测试
  `issue_4_revoked_agent_batch_is_rejected_without_samples` 覆盖
- `agent revoke` 对**其他**未吊销 agent 无影响的交叉验证未单独建连；断言 d/g
  已使用同一实例里的两个独立 agent，可观察到 B 未受影响
