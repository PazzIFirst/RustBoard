# RustBoard

自建的多服务器监控与轻量运维平台。三个可独立部署的组件：

| 组件 | 二进制 | 职责 |
|---|---|---|
| 采集端 | `rustboard-agent` | 采集 CPU / 内存 / 磁盘 / 网卡指标，本地磁盘缓冲，断网续传 |
| 汇聚端 | `rustboard-hub` | 接收上报、落库（SQLite）、提供只读 API，并自带同等采集能力 |
| 面板 | `rustboard-panel` | 浏览器界面，只通过 HTTP API 访问 hub |

设计文档见 [docs/requirements.md](docs/requirements.md)，实现进度见 [docs/status.md](docs/status.md)。

> **当前状态：M1 已闭环（含 TLS / mTLS / enrollment）。** 面板、控制面、告警尚未实现。
> 证书目前只有自签模式，ACME（域名 / 公网 IP 自动续期）在 M5 交付。

## 安全模型

1. `rustboard-hub init` 生成本地私有 CA 与服务端证书，打印 **SHA-256 指纹**。
2. `rustboard-hub agent add --name web-01` 生成**一次性** enrollment token（默认 30 分钟）。
3. agent 首次连接用安装命令里带过来的**指纹钉扎**校验 hub（等价 SSH 的 known_hosts），
   发送 CSR，hub 用私有 CA 签发 90 天客户端证书，并下发该机器独有的 `agent_secret`。
4. 之后所有连接走 mTLS；Hello 里再带 `agent_secret` 做身份绑定（防止已纳管机器互相冒名）。
5. `rustboard-hub agent revoke --id <id>` 立即清除 secret 并拒绝该 agent 重连。

## 快速开始（开发环境）

需要 Rust 1.80+ 与 C 编译器。

```bash
cargo build --release
BIN=./target/release

# 1) 初始化 hub（生成 CA + 服务端证书），记下输出的“服务端证书指纹”
sudo $BIN/rustboard-hub init

# 2) 启动 hub
sudo $BIN/rustboard-hub run &

# 3) 查看分配到的端口（随机五位数）
sudo $BIN/rustboard-hub ports

# 4) 生成一次性 token，按输出里的命令去目标机器上装 agent
sudo $BIN/rustboard-hub agent add --name web-01
#   → 会打印完整命令，形如：
#   rustboard-agent init --hub wss://<ip>:<agent端口>/agent/ws \
#     --token <token> --fingerprint <指纹> --name web-01

# 5) 目标机器上执行上面打印的命令，然后
sudo $BIN/rustboard-agent run &
sudo $BIN/rustboard-agent info          # 随时查看纳管状态

# 6) 查数据（管理端口用 ports 命令看）
ADMIN=$(sudo $BIN/rustboard-hub ports | awk '/管理 API 端口/{print $NF}')
curl -s "http://127.0.0.1:$ADMIN/api/v1/agents"
curl -s "http://127.0.0.1:$ADMIN/api/v1/series?agent=hub-self&metric=cpu.usage&from=0&to=9999999999999"

# 7) 面板占位页
sudo $BIN/rustboard-panel init --hub "http://127.0.0.1:$ADMIN"
sudo $BIN/rustboard-panel run &
sudo $BIN/rustboard-panel ports        # 查看面板端口
```

不想污染系统目录时，全部用 `--config` / `--data-dir` 指到临时目录：

```bash
./target/debug/rustboard-hub init --config /tmp/rb/hub.toml \
  --data-dir /tmp/rb/hub --agent-listen 127.0.0.1:18443 \
  --admin-listen 127.0.0.1:18444 --san 127.0.0.1
```

## 端口

**不占用 8080 / 8443 这类常见端口。** 每个端口在安装时随机挑一个五位数（20000–64999），
并先 `bind` 一次确认未被占用；也可以用 `--agent-listen` / `--admin-listen` / `--listen` 自定义。

| 用途 | 默认端口 | 协议 | 暴露建议 |
|---|---|---|---|
| agent 接入 | 随机五位数 | WSS + mTLS | 必须公网可达 |
| 管理 API | 随机五位数 | HTTP | 只绑回环/内网，远程面板走 VPN |
| 面板 | 随机五位数 | HTTP | 同上 |

随时在终端查看当前端口：

```bash
rustboard-hub ports       # agent 端口、管理端口、证书指纹
rustboard-panel ports     # 面板端口、hub API
rustboard-agent info      # hub 地址、agent_id、纳管状态
```

## 目录结构

```
crates/
  rustboard-common/   协议帧、数据模型、配置、TLS 材料与校验
  rustboard-core/     采集器、磁盘缓冲、SQLite 存储
  rustboard-agent/    采集端二进制
  rustboard-hub/      汇聚端二进制
  rustboard-panel/    面板二进制
docs/                 需求确认稿、实现进度
```

## 数据模型约定

- 采样点统一是 `(agent_id, metric, labels, ts, value)` 的窄表。
- 网络与磁盘 IO 上报**自开机以来的累计计数器**，不做本地累加；
  重启归零的结转由 hub 侧处理（M1 待补）。
- 批次在 `agent_id + epoch + seq` 上幂等，断线重传不会产生重复点。

## 测试

```bash
cargo test --workspace
```

覆盖：CPU/内存解析、计数器重置容纳、磁盘缓冲落盘与恢复、
SQLite 批次幂等、一次性 token 单次使用与过期、吊销清除 secret、
指纹解析、CA 签发 CSR。

## License

[MIT](LICENSE) © 2026 PazzIFirst
