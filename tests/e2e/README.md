# RustBoard 端到端回归

本目录包含三套可重复执行的端到端验收脚本，都在 `127.0.0.1` 的随机五位数端口上
启动临时实例，用真实 TLS / WebSocket 会话验证行为，结束后清理进程和临时目录：

| 脚本 | 覆盖 |
|---|---|
| `security.sh` | issue #1–#8 与协议门禁：身份绑定、协议版本、吊销、在线状态 |
| `cert-rotation.sh` | 证书有效期、`cert-info` / `renew`、服务端 `rotate-cert`、CA 信任自动重连、指纹一致性 |
| `panel.sh` | M2 面板：admin token 鉴权、登录/限速/Cookie、overview/series/settings、采样间隔 60s 内生效、静态与路径穿越 |

`security.sh` 是最早的一套，下文细节以它为例；另外两套脚本的断言清单见各自文件头部注释。

## 依赖

| 依赖 | 说明 |
|---|---|
| Linux | 脚本使用 `mktemp`、`sed -i`、`awk`、`date +%s%3N` 等 GNU 工具 |
| bash 4.4+ | 使用数组与 `set -euo pipefail` |
| Python 3.8+ | **仅标准库**（`ssl` / `socket` / `hashlib` / `urllib`）；无需 `pip install`，也不联网 |
| cargo / rustc | 用于 `cargo build --locked -p rustboard-hub -p rustboard-agent` |

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
- `panel.sh` + `panel_probe.py`：M2 面板与 hub 管理 API 回归（需要 `web/dist` 已构建）
- `probe.py`：TLS + WebSocket + MessagePack 测试客户端；子命令
  `hello` / `batch` / `hold` / `status` / `series-count` / `health`

`panel.sh` 需要先构建前端：

```bash
cd web && pnpm install --frozen-lockfile && pnpm build
bash tests/e2e/panel.sh
```

## 范围说明

以下行为不在本脚本内，避免测试时间过长或依赖不可控的网络条件：

- 45s 心跳超时（issue #7 的另一条路径）需要真实静默等待，未纳入
- 吊销与并发写入的精确竞态（`insert_batch` 事务内复核吊销）由单元测试
  `issue_4_revoked_agent_batch_is_rejected_without_samples` 覆盖
- `agent revoke` 对**其他**未吊销 agent 无影响的交叉验证未单独建连；断言 d/g
  已使用同一实例里的两个独立 agent，可观察到 B 未受影响
