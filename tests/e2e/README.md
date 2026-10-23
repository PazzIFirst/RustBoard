# RustBoard 端到端回归

本目录包含多套可重复执行的端到端验收脚本，都在 `127.0.0.1` 的随机五位数端口上
启动临时实例，用真实 TLS / WebSocket 会话验证行为，结束后清理进程和临时目录：

| 脚本 | 覆盖 |
|---|---|
| `security.sh` | issue #1–#8 与协议门禁：身份绑定、协议版本、吊销、在线状态 |
| `cert-rotation.sh` | 证书有效期、`cert-info` / `renew`、服务端 `rotate-cert`、CA 信任自动重连、指纹一致性 |
| `panel.sh` | M2 面板：admin token 鉴权、登录/限速/Cookie、overview/series/settings、采样间隔 60s 内生效、静态与路径穿越 |
| `hardening.sh` | v0.2.1 硬化 + v0.3.3 管理面收紧：弱 token、未知 API 鉴权、管理限速、非回环 + `admin_tls=off` 拒绝启动、单 IP 连接洪水、rotate 热加载、可信代理 XFF（含非法/超长/9 跳拒绝、不可信来源伪造无效）、Origin、reset-password |
| `control.sh` | M3 控制面：能力协商、systemd/Docker 白名单、进程 PID+名称、日志 tail/逃逸、审计分页与面板代理、能力关闭/离线 |
| `v031.sh` | v0.3.1 硬化 #13 / KI-17：过期服务端证书启动自愈（同 CA 重签、成对备份/权限、指纹、原 agent CA 信任重连）；hub/panel 各 30 条半截 header 慢连接下 `/healthz` 仍 200 且按 5s header 超时关闭 |
| `v032.sh` | v0.3.2 控制面可靠性 #18/#16/#19：pending 超时后清理（fake agent 不回复，连续 4×`504 control_timeout`、不出现 `429 too_many_pending`）、续签窗口 `busy_renewing`（`503` / 固定文案 / 审计 error）、journald tail 保留最新（`--reverse`、`truncated=true`、旧→新、≤256 KiB） |
| `v033.sh` | v0.3.3 管理面安全 #9/#17/#20/#21：scoped token 权限矩阵与审计 actor、admin TLS 与 Panel `https`+`hub_ca`、吊销后 403 `agent_revoked`、systemd 未加载 unit 合并、日志 tail 与跨挂载兼容、日志脱敏 |
| `v034.sh` | v0.3.4 低风险硬化 KI-26/18/19/21/24：401 失败限速（阈值 5 → 429 + `Retry-After`、旧 `admin_token` 应急旁路、日志不刷屏）、`reset-password` 后 ≤2s 旧会话 401、Hello 元数据 `bad_frame` 且不写库、数据目录/SQLite 权限收紧与重启自愈、多连接能力最新优先/断开回退/旧连接晚到 Hello 不覆盖 |
| `v035.sh` | v0.3.5 安全收口 KI-27 与 data_dir TOCTOU：同源 IP 2 条 WS 后第 3 条硬失败、另一源 IP 可连且已有 agent 保持 online；data_dir 中间 symlink 拒绝且 victim 不变；外置 database WARN/DB 0600；`limit=0` 两次 401 无 429 且首条 WARN |

`security.sh` 是最早的一套，下文细节以它为例；其余脚本的断言清单见各自文件头部注释。

## 依赖

| 依赖 | 说明 |
|---|---|
| Linux | 脚本使用 `mktemp`、`sed -i`、`awk`、`date +%s%3N` 等 GNU 工具 |
| bash 4.4+ | 使用数组与 `set -euo pipefail` |
| Python 3.8+ | **仅标准库**（`ssl` / `socket` / `hashlib` / `urllib`）；无需 `pip install`，也不联网。`v031.sh` 额外需要已安装的 `cryptography`（只用于生成过期证书）；`v034.sh` 的 fake agent (`v034_agent.py`) 与 `v035.sh` 的 flood helper 复用 `probe.py` |
| cargo / rustc | 用于 `cargo build --locked`（`hardening.sh` / `control.sh` / `v031.sh` / `v032.sh` / `v033.sh` / `v034.sh` / `v035.sh` 构建 hub/agent，前三套与 `v033.sh` / `v034.sh` 还会构建 panel；`v033.sh` / `v034.sh` / `v035.sh` 仅使用隔离 target） |
| curl | `control.sh` / `v032.sh` / `v033.sh` / `v034.sh` 用 curl 访问 hub 管理 API（`control.sh` / `v033.sh` 还访问面板 API；`v033.sh` 用 `--cacert` 校验 admin TLS；`v034.sh` 用 curl 轮询面板会话失效与 `Retry-After`） |

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
  未知 API 鉴权、非回环 + `admin_tls=off` 拒绝启动、单 IP 连接洪水、`rotate-cert` 热加载、
  面板可信代理 XFF / Secure Cookie、非法/超长/9 跳 XFF 拒绝、不可信直连来源伪造 XFF
  无效、锁定 XFF 隔离、Origin 校验与 `reset-password`
- `control.sh`：M3 控制面回归；使用临时 fake `systemctl` / `docker` / `journalctl`，
  不依赖宿主机服务，也不需要 root
- `v032.sh` + `v032_agent.py`：v0.3.2 控制面可靠性与 journal tail 回归；
  `v032_agent.py` 用真实 enrollment 留下的 agent_id / secret / 客户端证书建立
  mTLS 会话，`ignore` 模式故意不回复 `ControlRequest`（验证 #18 pending 清理），
  `busy` 模式按请求 id 回 `busy_renewing`（验证 #16 Hub 映射与审计）；
  场景 3 使用 fake `journalctl`（输出 1000 行 × 约 1KiB 新→旧）验证 #19
- `v033.sh`：v0.3.3 管理面安全回归；真实 hub/agent/panel + fake systemctl，覆盖
  `admin_tls=required` HTTPS、Panel `https`+`hub_ca`、scoped token 权限矩阵与审计 actor、
  #17 revoke 后 `agent_revoked`、#21 未加载 unit、#20 日志 tail 与日志脱敏；
  使用隔离 `CARGO_TARGET_DIR`，不要与其它 worktree 共用 target
- `v034.sh` + `v034_agent.py`：v0.3.4 低风险硬化回归；真实 hub/agent/panel +
  fake mTLS agent（复用 `probe.py`），覆盖 KI-26 未认证 401 限速（第 6 次 429、
  `Retry-After`、旧 `admin_token` 应急旁路与计数清除、日志不刷屏）、KI-18
  `reset-password` 后 ≤2s 旧会话失效、KI-19 Hello 元数据 `bad_frame` 且不写库、
  KI-21 数据目录 0700 / SQLite 三件套 0600 与过宽权限重启收紧、KI-24 多连接能力
  （最新连接优先、断开回退、旧连接晚到 Hello 不覆盖、控制 sender 指向剩余旧连接）；
  默认使用 `<repo>/target/v034-t1` 隔离 target
- `v035.sh` + `v035_agent.py`：v0.3.5 安全收口回归；`v035_agent.py` 复用
  `probe.py` 并支持 `bind_ip`，从不同 loopback 源地址验证 KI-27 per-IP WS 许可、
  data_dir 中间 symlink 拒绝、外置 database WARN、`limit=0` 首失败 WARN
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

说明：#15 的 Panel 控制专用 70s 超时与 `control_result_unknown` 由 panel 单元测试
覆盖，不做 31s 长 e2e；#16 的真实 `renew_client_cert()` 续签循环由 agent 单元测试
覆盖，本脚本只验证 Hub 的 `503 busy_renewing` 映射与审计。

`v033.sh` 会构建 hub/agent/panel，使用真实 enrollment、fake systemctl 与 Panel 登录，
覆盖 v0.3.3 管理面安全；运行约 12s（不含首次编译）。**必须使用隔离 target**，否则
多 worktree 共用 target 可能复用其它分支的测试/二进制：

```bash
export CARGO_TARGET_DIR=/tmp/rustboard-v033-target
bash tests/e2e/v033.sh
KEEP_E2E_TMP=1 bash tests/e2e/v033.sh   # 保留临时证书/日志
```

`v034.sh` 会构建 hub/agent/panel，并用真实 enrollment 留下的证书 / secret 建立
mTLS 会话验证 v0.3.4 的 KI-26/18/19/21/24；运行约 25s（不含首次编译），共 97 条
断言。未显式设置 `CARGO_TARGET_DIR` 时脚本会使用 `<repo>/target/v034-t1` 作为隔离
target；它不运行既有 8 套 e2e（CI 分别执行）：

```bash
bash tests/e2e/v034.sh
KEEP_E2E_TMP=1 bash tests/e2e/v034.sh   # 保留临时证书/数据库/脱敏日志
```

失败时脚本会打印脱敏后的 hub/agent/panel 日志，并以非零码退出；不会为了通过而
跳过或弱化断言。KI-21 场景会先用同版本 CLI 打开一次存储触发 SQLite checkpoint，
再删除 WAL/SHM，确保测的是“权限收紧 + sidecar 重建”，而不是数据丢失。

`v035.sh` 会构建 hub/agent，使用真实 enrollment 与 `v035_agent.py` 从
`127.0.0.2` 建立同源 WebSocket 洪水，验证第 3 条硬失败、`127.0.0.3` 仍可连接、
已有 agent 保持 online；同时验证 data_dir 中间 symlink 拒绝、外置 database WARN、
DB/WAL/SHM 0600 与 `limit=0` 首失败 WARN。运行约 15s（不含首次编译），共 48 条断言；
默认使用 `<repo>/target/v035-t1` 隔离 target：

```bash
bash tests/e2e/v035.sh
KEEP_E2E_TMP=1 bash tests/e2e/v035.sh   # 保留临时证书/数据库/脱敏日志
```

## 范围说明

以下行为不在本脚本内，避免测试时间过长或依赖不可控的网络条件：

- 45s 心跳超时（issue #7 的另一条路径）需要真实静默等待，未纳入
- 吊销与并发写入的精确竞态（`insert_batch` 事务内复核吊销）由单元测试
  `issue_4_revoked_agent_batch_is_rejected_without_samples` 覆盖
- `agent revoke` 对**其他**未吊销 agent 无影响的交叉验证未单独建连；断言 d/g
  已使用同一实例里的两个独立 agent，可观察到 B 未受影响
