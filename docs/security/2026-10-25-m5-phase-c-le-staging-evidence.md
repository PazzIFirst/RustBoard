# M5 Phase C：真实 LE staging 与 t4g.nano 内存证据

> 日期：2026-10-25（Asia/Shanghai）｜执行机：AWS EC2 `t4g.nano`（Debian 13 arm64）
> 目的：补 Phase C C-G3（公网 IPv4 `shortlived` staging）与三角色运行时内存基线
> 关联：[Phase C 计划](2026-10-25-m5-phase-c-tls-release-gates.md)、
> [RC Runbook](2026-10-25-m5-phase-c-rc-runbook.md)、[status](../status.md)

## 1. 测试机

| 项 | 值 |
|---|---|
| 实例 | AWS EC2 `t4g.nano` |
| 架构 | `arm64` / Debian 13 (trixie) |
| vCPU / 内存 | 2 / 430 MiB（无 swap） |
| 公网 IPv4 | `<TEST_IP>` |
| SSH | 必须经 `px-hub` 跳板；用户 `admin`（sudo） |
| 安全组 | 80/443 入站可达；启动前外部探测为 `Connection refused`，说明入站未被丢弃，仅无监听 |
| 测试包 | `serverdashboard-v0.4.2-aarch64.tar.gz`，SHA256 `046d1d34…70fcd20` |
| 构建方式 | 本地 QEMU 快速构建 `LTO=false`，**仅功能验证，不替代发布 profile** |

> 该机是临时测试机；未把任何私钥、token 或证书私钥写入仓库。

## 2. 真实 Let's Encrypt staging

命令（在测试机 root 下执行）：

```bash
RUSTBOARD_ACME_TLS_PORT=443 rustboard-hub install --yes --no-systemd \
  --prefix /root/rb-le-ip --panel no \
  --tls acme-ip --acme-email ops@<TEST_DOMAIN> \
  --domain <TEST_IP> --acme-challenge http-01 \
  --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory \
  --acme-profile shortlived \
  --listen 127.0.0.1:28443 --admin-listen 127.0.0.1:28444
```

结果：成功，未回退自签。

| 项 | 值 |
|---|---|
| ACME directory | `https://acme-staging-v02.api.letsencrypt.org/directory` |
| Identifier | `IP:<TEST_IP>` |
| Challenge | HTTP-01（80） |
| Profile | `shortlived` |
| Issuer | `C=US, O=Let's Encrypt, CN=(STAGING) Artificial Amaranth YE1` |
| Subject | 空（ACME 风格） |
| SAN | `IP Address:<TEST_IP>`（critical） |
| notBefore | `2026-10-25T15:14:35Z` |
| notAfter | `2026-11-01T07:14:34Z`（约 6.7 天） |
| SHA-256 | `6C:54:EC:A8:21:AF:F8:74:04:2B:6B:0D:22:D3:25:D8:36:D4:79:9D:08:3F:15:2E:F4:95:8C:D3:62:0D:82:3C` |
| 续期计划 | `2026-10-30T07:14:34Z`（notAfter − 48h） |
| `tls status` | mode=`acme-ip`, profile=`shortlived`, 剩余 7 天 |

权限：

```text
700 root:root certs
700 root:root certs/acme
600 root:root certs/acme/account.json
600 root:root certs/acme/state.toml
600 root:root certs/ca.key
600 root:root certs/server.key
644 root:root certs/ca.crt
644 root:root certs/server.crt
600 root:root certs/.rotate.lock
```

公网 TLS：

```bash
openssl s_client -connect <TEST_IP>:443 -servername <TEST_IP> </dev/null
```

- TLS 1.3 握手成功，返回上述 LE staging 证书；
- `Verify return code: 20 (unable to get local issuer certificate)` 是预期：
  客户端未预置 LE staging 根，不代表服务端错误；
- `/healthz` 本地回环 200；未把 admin 8444 发布到公网。

## 2.1 域名 staging（HTTP-01 / TLS-ALPN-01）

同一测试机、同一 LE staging 目录，域名 `<TEST_DOMAIN>`（A 记录指向 `<TEST_IP>`）：

| 项 | HTTP-01 | TLS-ALPN-01 |
|---|---|---|
| Identifier | `<TEST_DOMAIN>` | `<TEST_DOMAIN>` |
| 结果 | 成功 | 成功 |
| Issuer | `(STAGING) Baloney Bulgur YE2` | 同 staging 中间 CA |
| SAN | `DNS:<TEST_DOMAIN>` | `DNS:<TEST_DOMAIN>` |
| 有效期 | 64 天 | 64 天 |
| 指纹 | `54:23:70:…:63` | `f6:49:01:…:66` |
| 说明 | 80 端口真实挑战 | 443 端口真实挑战 |

两条路径都没有回退 self-signed；证书均由 `tls status` 识别为 `acme-domain`。

## 3. 三角色内存（t4g.nano）

方法：release 静态包，三个角色分别安装/启动，`self_monitor=false`，panel HTTP，
agent 已 enrollment；启动后 10s、60s 读取 `/proc/<pid>/status` 与 `smaps_rollup`。

| 服务 | RSS（60s） | PSS | VmHWM | 条件 |
|---|---:|---:|---:|---|
| hub | 10 MiB | 10 MiB | 11184 kB | 无 agent，SQLite，admin HTTP 回环 |
| panel | 5 MiB | 5 MiB | 5240 kB | HTTP，连接本地 hub，静态资源空闲 |
| agent | 4 MiB | 4 MiB | 4856 kB | 已 enrollment，5s 采样，本机 hub |

合计约 **19 MiB**（RSS 取整）。t4g.nano 0.5 GiB 运行三服务足够；但该机不能
在本机编译 workspace/构建 Docker 镜像（0.5 GiB 会 OOM）。

> 与 x86_64 release 基线（hub 15.2 / panel 7.7 / agent 7.45 MiB）相比，arm64
> 数值更低；差异来自架构、分配器、构建 profile（本地 arm64 为 LTO=false），
> 不作为精确跨架构比较。

## 4. 未覆盖 / 下一轮

- 域名（A 记录）HTTP-01 / TLS-ALPN staging：本次用公网 IP `acme-ip`，未用域名。
- 生产 LE IP 证书：只跑 staging，未消耗生产限额。
- 发布 profile 的 arm64 原生构建与 hosted `delivery-arm64`：仍由 GitHub
  `ubuntu-24.04-arm` 验证。
- `v1.0.0-rc.1`：未打 tag、未 push。
