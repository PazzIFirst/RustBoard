# M5 Phase C：ACME / 面板 TLS 与发布门禁补齐

> 状态：计划（待执行）｜基线：`a03d872`（Phase B checkpoint）
> 上游：[M5 安装与交付计划](2026-10-24-m5-install-delivery.md) Phase C、
> [requirements.md](../requirements.md) §9/§10.4/§14、
> [Phase B 交付计划](2026-10-25-m5-phase-b-delivery.md)、
> [Phase B 交付证据](../security/2026-10-25-m5-phase-b-delivery-evidence.md)、
> [Phase B 渗透报告](../security/2026-10-25-m5-phase-b-pentest.md)
> 目标版本：先做 `v1.0.0-rc.1` 验证真实发布链；最终 `v1.0.0` 仍在 Phase E
> 关联：[AGENTS.md](../../AGENTS.md) §2/§4/§5/§6/§8/§9

## 0. 执行交接（压缩上下文后从这里开始）

1. 开工前按 AGENTS §1 同步：
   ```bash
   git status --porcelain
   git fetch --prune origin
   git rev-list --left-right --count HEAD...origin/main
   ```
   必须 `0	0` 且工作区干净；基线应为 `a03d872`，Phase B tag 指向同一提交。
2. 不移动/删除 `checkpoint/2026-10-25-m5-phase-b-delivery`；不提前打 `v1.0.0`。
3. 本计划分两段：
   - **C1 发布门禁补齐**（0.5–1 天）：先修 release workflow 的 Docker/arm64 运行时门禁；
   - **C2–C8 Phase C 主体**（约 2–3 周）：ACME + 面板 TLS；
   - **C9**：全量 e2e、独立评审/渗透、`v1.0.0-rc.1` 真实 RC。
4. 每个编码任务至少配独立测试子 Agent；完成后独立评审子 Agent 只读评审；
   阶段收尾按 AGENTS §5 跑渗透并打新 checkpoint，**不移动旧 tag**。
5. 本阶段只新增配置字段/证书来源，不改协议 v2、SQLite schema v7 或已有配置必填项。

## 1. 目标与验收

### 1.1 必须达成

| # | 目标 | 可验证验收 |
|---|---|---|
| C-G1 | 配置兼容 | 旧 `hub.toml`/`agent.toml`/`panel.toml` 无 `[tls]`/`tls_mode` 时行为与 v0.4.2 完全一致；旧指纹 agent 仍可接入自签 hub |
| C-G2 | ACME 域名证书 | `acme-domain` + HTTP-01 在 Pebble 本地签发成功；证书 SAN/链/到期正确；真实 LE staging 手工门禁通过 |
| C-G3 | ACME IP 证书 | `acme-ip` 用 LE `shortlived` profile（或等价 6 天证书）签发/续期；至少覆盖一个公网 IPv4 的 staging 手工验证 |
| C-G4 | ACME TLS-ALPN-01 | `tls-alpn-01` 在 Pebble 签发成功；只接受 `acme-tls/1`，证书含 critical acmeIdentifier |
| C-G5 | 续期与热加载 | 剩余寿命 ≤ 1/3（IP 证书 ≤ 48h）自动续期；失败保留旧证书并告警；成功后新连接使用新证书，无需重启 |
| C-G6 | 失败回退 | 本地端口/防火墙/安全组/ACME staging 失败时最多 3 轮，回退 self-signed 继续安装；输出分层诊断，不假装成功 |
| C-G7 | 80/443 自检 | 本地监听、ufw/firewalld/nftables/iptables、云元数据、staging 实跑四层；每层给出可执行命令/控制台路径 |
| C-G8 | Agent TLS 迁移 | v1 agent 支持 `fingerprint`/`system-roots`/`custom-ca`；ACME 模式拒绝 v0.4 指纹 agent 并给出升级指引；自签模式不破坏旧 agent |
| C-G9 | 面板 TLS | 面板 `tls_cert`/`tls_key` 直接 HTTPS；Cookie Secure、CSP、登录不回归；反代文档完整 |
| C-G10 | 管理端 TLS | `admin_tls=required` 可用于非回环管理 API；安装器 HTTPS 健康检查、panel `hub_ca`/`hub_url=https` 可用；回环同机 panel 默认仍走 HTTP |
| C-G11 | 发布门禁补齐 | release workflow 增加 x86 Docker 与 arm64 原生离线/容器运行时门禁；正式 tag 只在全部 job 成功后提升；`v1.0.0-rc.1` 真实跑通 |
| C-G12 | 安全 | 账户 key/私钥 0600、token 不进 argv/日志、ACME 目录/挑战输入校验、无 SSRF/路径穿越；独立渗透无高危 |
| C-G13 | 文档/交付 | 离线包/Docker 支持 ACME 端口/证书卷；`--offline` 与 ACME 明确互斥；安装/升级/回滚文档完整 |

### 1.2 代表性命令

```bash
# 自签（默认，必须与 v0.4.2 一致）
rustboard-hub install --yes --tls self-signed --panel yes

# ACME 域名 + HTTP-01
rustboard-hub install --yes --tls acme-domain \
  --acme-email admin@example.com \
  --domain board.example.com \
  --acme-challenge http-01 --panel yes

# ACME IP + shortlived
rustboard-hub install --yes --tls acme-ip \
  --acme-email admin@example.com --domain 203.0.113.10 \
  --acme-challenge http-01

# TLS-ALPN
rustboard-hub install --yes --tls acme-domain \
  --acme-email admin@example.com --domain board.example.com \
  --acme-challenge tls-alpn-01

# 面板直连 HTTPS
rustboard-panel install --yes --tls-cert /etc/ssl/panel.crt \
  --tls-key /etc/ssl/panel.key --public-origin https://panel.example.com

# agent 接入 ACME hub（系统根）
rustboard-agent install --yes --tls-mode system-roots \
  --hub wss://board.example.com:8443/agent/ws --token-file /root/enroll.token
```

### 1.3 非目标

- 不做 ACME DNS-01、通配符证书、HA/负载均衡、Kubernetes Operator。
- 不做面板内置 ACME；远程面板用 Caddy/nginx 反代或手工证书。
- 不做 PostgreSQL（Phase D）；不改 SQLite schema、控制面协议、告警协议。
- 不把 `admin_listen` 默认改成非回环；不把 ACME 证书用于回环管理口（除非 SAN 覆盖且显式配置）。

## 2. 现状与差距

| 能力 | 现状（Phase B） | Phase C 需要 |
|---|---|---|
| 服务端证书 | 自签 CA + `server.crt/key`；`cert_rotation` 自动续签 | 服务端来源拆分：self-signed/ACME；client CA 只签客户端 |
| 配置 | `HubConfig` 无 `[tls]`；agent 只有 `server_fingerprint` | 新增 `[tls]`、`tls_mode`/`server_ca`，旧配置默认不变 |
| 安装器 | `--tls` 只允许 self-signed；`admin_tls=required` 被拒绝 | ACME 签发/回退、80/443 自检、HTTPS 健康检查、面板 TLS |
| 面板 | 只能 HTTP；`admin_tls=required` 时拒绝安装 | `tls_cert/tls_key` 直接 HTTPS；支持 hub `hub_ca` |
| Agent | 指纹钉扎 + enrollment 后本地 CA 校验 | 服务端信任来源可配；ACME 用系统根/custom CA |
| 续期 | 自签续期；无 ACME 状态机 | ACME 账户/订单/挑战/续期/告警/热加载 |
| 诊断 | 无 | 本地监听/防火墙/云元数据/staging 四层 |
| 发布 | checkpoint 已打；release 只有 x86 offline delivery-e2e | 增加 Docker/arm64 运行时门禁；RC 真实验证 |

## 3. 关键设计决策

### D1. ACME 客户端

采用 **`instant-acme 0.8.5`**，但关闭默认 aws-lc：

```toml
instant-acme = { version = "0.8.5", default-features = false, features = ["ring", "hyper-rustls"] }
```

- 理由：纯 Rust、支持 RFC 8555、IP identifier、profiles、`finalize_csr`；不引入 cmake/aws-lc。
- 证书 CSR/ TLS-ALPN 证书复用项目现有 `rcgen 0.13.2`；链解析复用 `x509-parser 0.16`。
- C0 先编译 spike；若 `ring` 组合在 MSRV 1.89 下不可用，才评估
  `rustls-acme 0.15.4`（必须同样使用 ring，不得引入 aws-lc）。
- ACME HTTPS 默认系统根；`tls.acme_ca_file` 可为 Pebble/私有 ACME 指定 PEM 根。
- **C0 已验收**（2026-10-25）：MSRV 1.89 编译通过、无 aws-lc；Pebble DNS/IP、`shortlived`、
  TLS-ALPN-01 均跑通。`Account::builder_with_root` 只读取单张 PEM，多根私有 CA 需
  自建 `HttpClient`。详见 [C0 spike 结论](2026-10-25-m5-phase-c-spike.md)。

### D2. 服务端证书与客户端 CA 拆分

- `certs/ca.crt|ca.key` 只作为 **客户端证书 CA**（mTLS/enrollment/renew），不再用于 ACME 服务端证书。
- `certs/server.crt|server.key` 是当前生效的服务端证书：
  - self-signed：由本地 CA 签发；
  - ACME：LE/Pebble 签发的 leaf + 中间链。
- `cert_rotation` 只在 `self-signed` 模式运行；ACME 模式由新的 `acme_renewal` 任务管理。
- ACME 账户 key 只在 `certs/acme/account.json`（0600）；不进入配置/日志/镜像。

### D3. 证书目录与原子性

```text
<data_dir>/certs/
├── ca.crt                  0644  # mTLS client CA
├── ca.key                  0600
├── server.crt              0644  # 当前 leaf + chain
├── server.key              0600
├── server.crt.bak.*        0644  # 续期/切换备份（保留最近 N 份）
├── server.key.bak.*        0600
├── .rotate.lock                  # 复用 CertLock
└── acme/
    ├── account.json        0600  # 账户 credentials（含私钥）
    ├── state.toml          0600  # directory/domains/profile/last_issue/next_attempt
    └── .lock                     # 可与 .rotate.lock 共用/独立
```

- 所有写入用 `fsutil::atomic_write` + 文件锁；失败保留旧证书。
- 切换 ACME/self-signed 前成对备份；失败恢复。
- `server.crt` 只写 leaf+chain（leaf 第一）；`server.key` PKCS8 0600。

### D4. Hub `[tls]` 配置

```toml
[tls]
mode = "self-signed"          # self-signed | acme-domain | acme-ip
acme_email = ""
acme_directory = "https://acme-v02.api.letsencrypt.org/directory"
challenge = "http-01"         # http-01 | tls-alpn-01
domains = []                  # acme-domain: DNS；acme-ip: 恰好一个 IPv4
acme_profile = ""             # acme-ip 默认 shortlived；acme-domain 留空
acme_ca_file = ""             # 仅私有/Pebble ACME；PEM 根证书
staging_check = true          # 安装时先跑 staging 挑战（acme-ip 可选）
fallback_to_self_signed = true
```

- `#[serde(default)]`，旧配置缺省 `mode=self-signed`，行为不变。
- `acme-domain` 必须有 1–20 个合法 DNS；`acme-ip` 必须恰好一个公网 IPv4；禁止通配符。
- `acme_email` 在 ACME 模式必填；`acme_directory` 必须 `https://`、无 userinfo/片段。
- `acme_ca_file` 仅允许非 LE 目录（Pebble/私有 CA）；读取 0644 PEM，拒绝符号链接。
- `acme_profile` 为空时：`acme-ip` 用 `shortlived`，domain 不设置 profile。
- `server_names` 仍用于 self-signed SAN 与 admin TLS 校验；ACME 模式证书 SAN 来自 `domains`，
  `advertise_host` 未设置时取 `domains[0]`。

### D5. Agent 信任模型

新增：

```toml
tls_mode = "fingerprint"  # fingerprint | system-roots | custom-ca
server_ca = ""            # custom-ca 时必填；PEM 路径（安装器复制到 data_dir/server-ca.pem）
server_fingerprint = ""   # fingerprint 时必填；向下兼容
```

规则：

- `fingerprint`：当前行为；bootstrap 与已纳管都用指纹钉扎（或本地 CA，自签模式）。
- `system-roots`：ACME 公共证书；bootstrap 用系统根 + URL 主机名校验；不要求 fingerprint。
- `custom-ca`：私有 ACME/自签 CA；bootstrap 用 `server_ca` 链 + 主机名校验；不要求 fingerprint。
- 已纳管后仍使用 `agent_data/ca.crt` 校验**客户端证书**的签发者；它不再自动作为服务端信任根。
  新增 `client_config_with_server_roots(...)`，将“服务端信任根”与“客户端证书”分离。
- 旧配置无 `tls_mode` → `fingerprint`；旧 `server_fingerprint` 保留。
- `wss://` + `fingerprint` 仍要求非空指纹；`wss://` + `system-roots`/`custom-ca` 不要求。
- `ws://` 明文配置不改变，但安装器在 ACME/远程场景拒绝生成明文 URL。

### D6. 面板 TLS 与管理端 TLS

- `PanelConfig` 新增 `tls_cert`、`tls_key`（字符串路径；默认空）。
  - 两者同时非空 → HTTPS；都空 → HTTP；只设一个 → 启动/安装失败。
  - key 必须 0600、普通文件、非符号链接；cert 0644；证书/私钥必须配套且 SAN 覆盖访问名。
  - 安装器把用户提供的 cert/key 复制到 `<prefix>/etc/rustboard/panel-tls/{cert.pem,key.pem}`，
    配置写绝对路径；`--force` 时事务备份。
  - 直接 HTTPS 时安装器写 `cookie_secure="always"`、`public_origin=https://...`；
    保留 `auto` 兼容反代。
  - v1 不做面板证书热加载；续期后 `systemctl restart rustboard-panel`。
- Hub `admin_tls=required`：
  - 新增 `--admin-tls off|required`；未指定时保持 Phase A 行为（回环默认 off）。
  - 非回环 `admin_listen` + `off` 仍拒绝启动；`required` 时用当前服务端证书，
    并要求 `server_names`/ACME `domains` 覆盖访问名。
  - 回环管理口默认仍用 HTTP；同机 panel 默认 `hub_url=http://127.0.0.1:<port>`。
    若显式 required，panel 必须 `hub_url=https://<SAN 覆盖的主机名>` + `hub_ca`（自签/私有）
    或系统根（ACME），且安装器用自定义 SNI 健康检查。
- 管理端 HTTPS 健康检查新增 `wait_https_ok_with_server_name`：TCP 连 127.0.0.1，
  TLS ServerName 用配置的 admin 主机名，CA 用 hub CA 或系统根；不得跳过验证。

### D7. ACME 挑战服务

- HTTP-01：临时绑定 `0.0.0.0:80`（Docker 映射 80），只提供
  `GET /.well-known/acme-challenge/<token>`；未知 token 404；Host 必须是目标域名；
  请求上限 8 KiB、超时 5s；不记录 token/keyAuth。
- TLS-ALPN-01：临时绑定 `0.0.0.0:443`，仅 ALPN `acme-tls/1`；按 SNI 返回
  含 `id-pe-acmeIdentifier` critical 扩展的自签证书；不提供普通 HTTP。
  **C0 限制**：rustls `with_single_cert` 会因 critical 扩展拒绝该证书，必须用
  `CertifiedKey::new` + 自定义 `ResolvesServerCert`，并自行校验 key 配对；见 spike §6。
- 证书：
  ```rust
  let mut params = CertificateParams::new(vec![domain])?;
  params.custom_extensions.push(
      rcgen::CustomExtension::new_acme_identifier(&sha256(key_authorization))
  );
  params.is_ca = IsCa::NoCa;
  // 自签，SAN=domain，EKU serverAuth
  ```
- 挑战服务在订单验证前后启动/停止；任何错误停止并清理端口；不长期监听 80/443。
- 需要 root 绑定 <1024；Phase A hub 已 root；Docker entrypoint 首启 root。

### D8. 续期与告警

- ACME 证书：`renew_at = min(not_after - lifetime/3, not_after - 48h)`；
  IP 6 天证书约在剩余 2 天续期；检查周期复用 `cert_check_interval_secs`（≥60s）。
- 失败指数退避（1m/5m/15m/1h，最大 6h），保留旧证书；<48h 触发既有
  `alerts.cert_warn_hours` 告警；不因续期失败重启 hub。
- 成功后原子写 `server.crt/key`，复用现有 cert file watcher 热加载 agent 与 admin TLS；
  记录 state；日志只打指纹/到期时间，不打 key/账户。
- 手动 `rustboard-hub tls renew` 与自动续期共用 `CertLock`；并发只允许一个。

### D9. 80/443 诊断与回退

安装器在写配置前执行（C0 已确认本机 80 被 nginx 占用，诊断必须 fail-closed；
ACME e2e 用 Pebble 5001/5002 仅作测试，不替代生产 80/443 检查）：

1. **本地 bind**：TcpListener 试绑 80/443；失败用 `ss -ltnp` 找 PID（无 ss 则报通用占用）。
2. **防火墙**：识别 `ufw status` / `firewall-cmd --state` / `nft list ruleset` /
   `iptables -S`；只打印精确放行命令；`--yes` 不自动改防火墙，交互模式二次确认后
   才执行。
3. **云元数据**：仅 ACME + 非 offline，1s 超时 GET `169.254.169.254`；识别
   AWS/阿里云/腾讯云，打印安全组路径；不做任何凭证请求。
4. **ACME staging 实跑**：先 staging 目录签一次（可丢弃）；成功再 production；
   失败按“本地 bind 成功/失败”分层给出结论。
5. 最多 3 轮；用户可随时放弃；失败自动 self-signed + 指纹继续安装，打印
   `hub install --force --tls acme-*` 重试命令。
- `--offline` + ACME 在写任何文件前失败；包内 `install.sh` 不得自动追加 `--offline`
  当显式 `--tls acme-*`；两者同时出现明确报错。

### D10. 发布门禁补齐

当前缺口（Phase B 评审 M-01）：

- `release.yml` 只有 x86 `delivery-e2e`，没有 Docker/arm64 运行时门禁；
- `v100-docker.sh` 固定 amd64；`v100-arm64.sh` 只在本地跑过 QEMU；
- `release` 的 checkout 未固定 `github.sha`；无 environment/tag protection。

补齐：

1. `tests/e2e/v100-docker.sh` 支持 `DOCKER_ARCH=amd64|arm64`、`SKIP_ARM64=1`；
   镜像 tag/平台/源 dist/包名按架构映射；arm64 在 arm64 runner 原生跑。
2. `release.yml` 增加：
   - `delivery-arm64`（`ubuntu-24.04-arm`）：下载 `dist-arm64` + `web-dist`，
     `sudo env ... STRICT=1 bash tests/e2e/v100-arm64.sh`；
     `DOCKER_ARCH=arm64 bash tests/e2e/v100-docker.sh`；
   - `delivery-docker`（`ubuntu-latest`）：下载 `dist-amd64` + `web-dist`，
     `SKIP_ARM64=1 bash tests/e2e/v100-docker.sh`；
   - `release` `needs` 增加两者；正式 tag/latest 仍只在全部 attestation 之后；
   - 所有 checkout `ref: ${{ github.sha }}`、`persist-credentials: false`；
   - `release` job 加 `environment: release`（GitHub 侧配置 required reviewers）。
3. 文档明确 `delivery-e2e`/Docker/arm64 失败时 staging 可能已推送，但正式 tag/
   Release 不发布；重跑前确认 staging digest。
4. 真实验证：Phase C 完成后打 `v1.0.0-rc.1`，跑完整 workflow；RC 不允许 `latest`。
5. 不在主仓库造测试 tag；本地用 registry/fake gh 预演，真实 hosted 验证用 RC。

## 4. 接口与文件清单

### 4.1 配置/命令

| 角色 | 新增 |
|---|---|
| hub | `[tls]`、`--tls self-signed\|acme-domain\|acme-ip`、`--acme-email`、`--acme-directory`、`--acme-challenge`、`--domain`（可重复）、`--acme-profile`、`--acme-ca`、`--admin-tls off\|required`、`hub tls status\|issue\|renew` |
| panel | `tls_cert`/`tls_key`、`--tls-cert`、`--tls-key`、`--hub-ca`、`--public-origin`、`--cookie-secure` |
| agent | `tls_mode`、`server_ca`、`--tls-mode fingerprint\|system-roots\|custom-ca`、`--server-ca`；`--fingerprint` 按模式可选 |

### 4.2 代码文件

```text
crates/rustboard-common/src/config.rs          # TlsConfig/ServerTlsMode/AcmeChallenge/AgentTlsMode/Panel字段
crates/rustboard-common/src/tls.rs             # client_config_* / server_config_paths / cert validation
crates/rustboard-hub/src/acme/mod.rs           # 模块入口
crates/rustboard-hub/src/acme/client.rs        # instant-acme account/order
crates/rustboard-hub/src/acme/challenge.rs     # HTTP-01 / TLS-ALPN-01
crates/rustboard-hub/src/acme/store.rs         # cert/account/state 原子写
crates/rustboard-hub/src/acme/renewal.rs       # 续期/退避/告警
crates/rustboard-hub/src/tls_diag.rs           # 80/443 四层诊断
crates/rustboard-hub/src/install_cmd.rs        # ACME 安装流/HTTP 健康检查/回退
crates/rustboard-hub/src/cert_rotation.rs      # self-signed 守卫
crates/rustboard-hub/src/main.rs               # 启动/热加载/status
crates/rustboard-agent/src/main.rs             # TLS connector 选择
crates/rustboard-agent/src/install_cmd.rs      # tls_mode/server_ca
crates/rustboard-panel/src/main.rs             # 面板 TLS serve
crates/rustboard-panel/src/install_cmd.rs      # cert/key/hub_ca/health
crates/rustboard-panel/src/auth.rs             # 直接 TLS Cookie Secure
crates/rustboard-install/src/network.rs        # 安装器网络自检（可选，hub 侧复用）
packaging/install.sh                           # offline 与 acme 互斥/不自动 offline
docker/entrypoint-hub.sh                       # ACME 环境/端口
docker/Dockerfile                              # EXPOSE 80/443
docker/compose.example.yml                     # 80/443/证书卷
.github/workflows/release.yml                  # delivery-arm64/delivery-docker
tests/e2e/v100-docker.sh                       # DOCKER_ARCH/SKIP_ARM64
tests/e2e/v100-acme.sh                         # Pebble 域名 HTTP-01/TLS-ALPN
tests/e2e/v100-acme-ip.sh                      # IP/shortlived（Pebble 支持则本地，否则 mock+LE staging 手工）
tests/e2e/v100-acme-renew.sh                   # 续期/热加载
tests/e2e/v100-acme-fallback.sh                # 端口/防火墙/staging 失败回退
tests/e2e/v100-panel-tls.sh                    # 面板 HTTPS/Cookie/CSP
tests/e2e/v100-tls-agent.sh                    # 三种 agent 信任模型/旧 agent
tests/e2e/v100-admin-tls.sh                    # admin required/panel hub_ca
docs/install/acme.md
docs/install/panel-tls.md
docs/install/tls.md
docs/install/troubleshooting.md
docs/install/docker.md / offline.md / release.md
```

### 4.3 新增依赖

只在 `crates/rustboard-hub/Cargo.toml`：

```toml
instant-acme = { version = "0.8.5", default-features = false, features = ["ring", "hyper-rustls"] }
```

- 不启用 `aws-lc-rs`/`rcgen`/`x509-parser` features；CSR 用项目 rcgen 0.13，链解析用项目 x509-parser 0.16。
- `cargo tree -i aws-lc-rs` 必须无输出；`cargo audit` 0 高危；MSRV 1.89 编译通过。
- 若 `instant-acme` 的 `hyper-rustls` 仍强制平台根导致 Pebble 不可用，C0 实现自定义
  `HttpClient`（hyper + rustls + 自定义 RootCertStore），不要引入 openssl。

## 5. 工作包（按顺序执行）

### C0. 依赖与 Pebble spike（0.5–1 天）

目标：在写产品代码前确认三个未知项。

1. 在 `/tmp` 或临时分支创建最小 Cargo 项目，依赖 `instant-acme 0.8.5` + `ring`
   + `hyper-rustls`，编译；确认无 aws-lc/cmake。
2. 用 Pebble 启动本地 ACME，验证：
   - `NewOrder` 支持 DNS 与 IP identifier；
   - `profile("shortlived")` 是否被 Pebble 接受（不支持则记录，IP 用 mock/LE staging 手工）；
   - TLS-ALPN-01 可用 rcgen `CustomExtension::new_acme_identifier`；
   - 自定义 CA（Pebble）如何注入 `AccountBuilder`/HttpClient。
3. 检查 80/443 在本机/CI 是否可用；记录端口冲突处理。
4. 把结论写入 `docs/plans/2026-10-25-m5-phase-c-spike.md`，并更新本计划 D1/D9
   的已知限制；如果 instant-acme 不满足，停下报告，不直接换 crate。

验收：spike 文档有版本、features、Pebble digest、成功/失败命令；`cargo tree -i aws-lc-rs` 为空。

### C1. 发布门禁补齐（0.5–1 天）

1. 修改 `tests/e2e/v100-docker.sh`：
   - `DOCKER_ARCH=${DOCKER_ARCH:-amd64}`；平台 `linux/$DOCKER_ARCH`；
     源 `dist/$DOCKER_ARCH/bin`、包名映射 `x86_64/aarch64`；
   - 镜像 tag 带 arch；`SKIP_ARM64=1` 跳过 arm64 检查；
   - 所有 preflight 的包/源 hash 按 arch；在 arm64 host 原生运行全部用例。
2. 修改 `.github/workflows/release.yml`：
   - 新增 `delivery-arm64`、`delivery-docker`（D10 细节）；
   - `release` needs 增加两者；checkout `ref: ${{ github.sha }}`；
   - `release` environment；保留 staging→正式/latest 顺序；
   - 不新增 `workflow_dispatch` 改变 tag-only 契约。
3. 更新 `docs/install/release.md`：门禁表、失败语义、RC 流程。
4. 本地验证：actionlint、YAML、`v100-docker.sh` 在 x86 至少 preflight；arm64 路径
   逻辑单测/静态；不推 GHCR。

验收：actionlint 0；本地 x86 Docker e2e 通过；workflow job 图/权限/顺序断言；
arm64 runner 的 hosted 验证留 C9 RC。

### C2. 配置与 Agent TLS 迁移（2 天）

1. `config.rs` 新增 `ServerTlsMode`/`AcmeChallenge`/`TlsConfig`/`AgentTlsMode`；
   `HubConfig.tls`、`AgentConfig.tls_mode/server_ca`、`PanelConfig.tls_cert/tls_key`；
   全部 `#[serde(default)]`。
2. 校验：
   - mode/email/directory/challenge/domains/profile；
   - agent 三模式互斥；wss 必须有可用信任源；
   - panel cert/key 成对；
   - 旧配置反序列化默认值测试。
3. `tls.rs` 新增：
   - `client_config_system_roots(client_cert,key)`；
   - `client_config_custom_ca(server_ca, client_cert,key)`；
   - `client_config_*_bootstrap`（无 client cert）；
   - `server_config_from_paths(cert,key)`；
   - `validate_server_chain`（leaf SAN/key/expiry，不依赖 CA）。
4. Agent `main.rs`：
   - bootstrap：按 `tls_mode` 选指纹/系统根/custom CA；
   - 已纳管：服务端信任按 `tls_mode`，客户端证书仍来自 `agent.crt/key`；
   - `agent_data/ca.crt` 只用于客户端证书续签校验；
   - 旧 `ca.crt` 缺失且 fingerprint 模式保留现有 fallback 告警。
5. Installer agent：
   - `--tls-mode`/`--server-ca`；`--fingerprint` 按模式必填/可选；
   - 复制 server CA 到 data_dir `server-ca.pem` 0644，事务回滚；
   - `hub agent add` 输出按 hub TLS 模式生成命令（ACME 不输出 fingerprint）。
6. 测试：旧 agent.toml 默认 fingerprint；三种模式连接 mock/Pebble；v0.4 配置不改。

验收：无 TLS 配置行为不变；`cargo test --workspace` 全绿；agent e2e 三模式。

### C3. 证书存储与 client CA 拆分（2 天）

1. 从 `tls::ensure_hub_material` 拆出 `ensure_client_ca` 与
   `ensure_self_signed_server`；self-signed 行为/文件/指纹不变。
2. 新 `acme/store.rs`：
   - `CertMaterialPaths`、`AcmeState`、`read/write` 0600/0644；
   - `install_server_material(cert_pem,key_pem)`：配对/链/SAN/expiry 校验，成对备份，
     `CertLock`，原子写；
   - `read_account`/`write_account`；损坏时备份并报错，不静默覆盖。
3. `cert_rotation`：
   - `renew_server_cert_files`/`check_and_renew`/`spawn_server_renewal` 在
     `tls.mode != self-signed` 时返回“由 ACME 管理”，不写 server；
   - 启动 `load_or_repair_tls_config` 在 ACME 模式只加载/校验，不自签修复。
4. 测试：CA/server 拆分后自签指纹不变；ACME 模式下自签任务不运行；备份/回滚；
   key 0600/cert 0644；旧证书兼容。

### C4. ACME 客户端与两种挑战（3–4 天）

1. `acme/client.rs`：
   - 账户 load-or-create；目录 URL 校验；custom CA；账户 credentials 0600；
   - `order(domains, profile, challenge)`：new order → authorizations → challenge →
     poll → CSR（rcgen）→ finalize → certificate chain；
   - 超时/退避/Retry-After；错误分类（rate limit/validation/network）；
   - 不打印 account key/keyAuth/证书私钥。
2. `acme/challenge.rs`：
   - HTTP-01 server（port 80）与 TLS-ALPN server（port 443）；
   - TLS-ALPN cert 用 `CustomExtension::new_acme_identifier`，ALPN `acme-tls/1`；
   - Host/SNI 校验、大小/超时限制、启动/停止生命周期；
   - 无 token 时 404/握手失败；挑战结束立即关端口。
3. `acme/store.rs` 与 `client` 连接：账户/证书/状态原子写；`CertLock`。
4. `main.rs` 启动时的 `tls::server_config` 加载 ACME 证书；无证书时明确报错。
5. 单测：mock HTTP-01/TLS-ALPN 响应；错误 token/SNI/超时；CSR SAN；
   证书链解析；key 权限。
6. Pebble e2e（C9 主脚本）先做 HTTP-01 domain；再做 TLS-ALPN；IP/profile 按 C0 结论。

### C5. 安装器 80/443 自检与回退（3 天）

1. `tls_diag.rs`/`rustboard-install`：
   - 本地 bind + `ss` PID；防火墙检测；云元数据 1s；staging 实跑；
   - 分层结论、精确命令、`--yes` 不自动改防火墙；
   - 所有外部请求有超时；offline 不调用。
2. `hub install`：
   - `--tls acme-*` 参数解析/校验；`--offline` 冲突在写盘前失败；
   - 预检 → 获取/校验证书 → 写 config/unit/binary → 启动/health；
   - 失败 3 轮 → self-signed 回退，写 config 并打印重试命令；
   - `admin_tls=required` 支持 HTTPS 健康检查（自定义 SNI/CA）；
   - 同机 panel 传递 `hub_url`/`hub_ca`/TLS 模式。
3. `packaging/install.sh`：
   - 显式 `--tls acme-*` 时不自动追加 `--offline`；`--offline` + ACME 失败；
   - 其余默认行为不变（自签仍 offline）。
4. `hub tls status|issue|renew` CLI：
   - status 只读；issue 强制重签；renew 走统一锁；输出 SAN/到期/来源；
   - 失败保留旧证书，非零退出。
5. 测试：
   - 端口占用/防火墙/元数据/staging 失败 mock；
   - 3 轮回退；失败零残留；`--offline` 零写入；
   - dns/域名/IP 参数负例；ACME 目录 URL/自定义 CA。

### C6. 续期、热加载与告警（2 天）

1. `acme/renewal.rs`：
   - 计算 1/3 / IP 48h 阈值；周期检查；指数退避；
   - 成功原子写并触发热加载；失败保留旧证书，告警一次；
   - 手动 `tls renew` 与自动共用锁。
2. 复用 `cert_rotation` 的 cert file watcher；agent/admin TLS 新连接生效；
   不重启。
3. 证书状态：`hub tls status`；`/healthz` 不含敏感；日志只打公开字段。
4. 测试：
   - 短寿命 Pebble 证书到期前续期；热加载指纹变化；
   - ACME 500/超时/坏链/磁盘失败保留旧证书；
   - 并发 renew/rotate；<48h 告警。

### C7. 面板 TLS 与管理端 TLS（2–3 天）

1. `PanelConfig` + installer：
   - `--tls-cert/--tls-key` 复制/校验/事务；`cookie_secure=always`；`public_origin`；
   - 只设一个/证书不配套/key 0644/符号链接失败；
   - `panel install` 健康检查支持 HTTPS（SNI/CA）。
2. `panel main`：
   - 直接 rustls accept loop（复用 KI-17 限流/超时）；HTTP 无回归；
   - `hub_ca` + `https` hub；`admin_tls=required` 不再拒绝；
   - Cookie Secure/CSP/Origin 回归测试。
3. Hub admin TLS：
   - `--admin-tls`；非回环 required；健康检查 HTTPS；
   - 同机 panel 的 `hub_url`/`hub_ca` 选择；回环默认 HTTP 策略文档化。
4. E2E：panel HTTPS 登录/静态资源/CSP/Cookie；反代文档；
   `admin_tls=required` + panel `hub_ca`；证书错误 SNI 失败。

### C8. Docker / 离线包 / 文档（1–2 天）

1. Hub Docker：
   - `EXPOSE 80 443`（仅 ACME 时需要，元数据）；
   - entrypoint 读取 `RUSTBOARD_TLS_MODE`/`RUSTBOARD_ACME_*`；ACME 时**不加** `--offline`；
   - `/data` 证书卷保留；ACME 账户/cert 持久化；
   - healthcheck 对 `admin_tls=required` 使用 HTTPS/CA（自定义 SNI）。
2. Compose：
   - 可选 80/443 端口、`RUSTBOARD_TLS_MODE`、`RUSTBOARD_ACME_DOMAIN`；
   - 面板 TLS 证书卷/端口；`hub_ca`/`HUB_URL=https`；
   - 说明 8444 仍不发布，ACME 只暴露 80/443/8443。
3. 离线包：
   - `--offline` + ACME 失败；默认自签仍 offline；
   - 包内 README/install.sh help/文档更新。
4. 文档：`docs/install/acme.md`、`tls.md`、`panel-tls.md`、troubleshooting；
   README/CHANGELOG/status；Docker/离线/发布文档交叉链接。
5. 测试：Docker ACME HTTP-01（Pebble 映射 80）、只读根 + `/run`、证书卷；
   离线+ACME 负例。

### C9. 全量测试、评审、渗透、RC（3–4 天）

1. 单测/集成：
   - 配置/agent TLS/证书存储/ACME client/challenge/renewal/diag/面板；
   - 失败注入：ACME 500/超时/坏链/磁盘 full/端口占用/证书不配套；
   - 并发：renew + rotate + 多 agent 连接；无死锁/半写。
2. E2E：
   - `v100-acme.sh`（Pebble HTTP-01/TLS-ALPN）
   - `v100-acme-ip.sh`（按 C0 结论；Pebble IP/profile 或 mock + LE staging 手工）
   - `v100-acme-renew.sh`
   - `v100-acme-fallback.sh`
   - `v100-tls-agent.sh`（fingerprint/system-roots/custom-ca；v0.4 旧 agent）
   - `v100-panel-tls.sh`
   - `v100-admin-tls.sh`
   - `v100-install.sh`、`v100-offline.sh`、`v100-arm64.sh`、`v100-docker.sh` 回归。
3. 独立评审（只读）+ 渗透（本地实例）：重点 ACME 目录 SSRF、挑战端口、key 权限、
   token 日志、旧 agent 降级、admin/panel TLS、Docker 端口/证书卷。
4. 文档/状态/CHANGELOG 更新；`v1.0.0-rc.1` 前不归档正式版本。
5. 全部门禁 + e2e 绿后，版本改 `1.0.0-rc.1`，CHANGELOG 增加
   `[1.0.0-rc.1]`，打 `v1.0.0-rc.1`，跑真实 release workflow：
   - 验证 hosted `delivery-e2e`/`delivery-arm64`/`delivery-docker`；
   - GHCR 多架构、SBOM、attestation、pre-release（不 latest）；
   - 手工 LE staging 域名/IP 验证（非 CI 自动）。
6. RC 通过后打 `checkpoint/2026-11-xx-m5-phase-c-tls`；不移动 Phase B tag。

## 6. 测试矩阵

| 类别 | 用例 | 门禁 |
|---|---|---|
| 配置 | 旧配置默认值；三模式互斥；域名/IP/email/directory 校验 | 每次提交 |
| Agent TLS | fingerprint/system-roots/custom-ca；bootstrap/已纳管；旧 agent | 每次提交 |
| 证书存储 | 原子写/备份/回滚/权限/链/key 配套 | 每次提交 |
| ACME 单元 | order/challenge/poll/finalize；Retry-After/超时/错误分类 | 每次提交 |
| 挑战 | HTTP-01 token/Host；TLS-ALPN SNI/ALPN/扩展；错误请求 | 每次提交 |
| 续期 | 1/3、IP 48h、退避、热加载、失败保旧 | 阶段 |
| 安装器 | 80/443 四层诊断、3 轮回退、offline 冲突、admin TLS health | 阶段 |
| 面板 | HTTPS/Cookie/CSP/Origin/反代；cert/key 负例 | 阶段 |
| Pebble | 域名 HTTP-01/TLS-ALPN；IP/profile（按 C0） | 阶段 |
| 真实 LE staging | 域名 + 公网 IP 手工门禁 | RC 前人工 |
| 故障注入 | ACME 500/超时/坏链/端口占用/磁盘 full | 阶段 |
| 并发 | renew/rotate/多连接 | 阶段 |
| 安全 | key 0600、日志/argv、SSRF、旧 agent、Docker 端口 | 阶段 |
| 回归 | v100 install/offline/arm64/docker/workspace/web | 每次提交/阶段 |

## 7. 兼容性与迁移

- **协议 v2 / SQLite schema v7 不变**；不新增帧/表。
- **Hub 配置**：缺 `[tls]` → self-signed；已有 `server.crt/key` 不覆盖。
- **Agent**：缺 `tls_mode` → fingerprint；旧 agent 接入 self-signed hub 不变；
  ACME hub 明确不兼容 v0.4 指纹 agent；安装器/`hub agent add` 打印升级指引，
  hub 启动日志 WARN。
- **Panel**：缺 `tls_cert/key` → HTTP；已有反代配置 `cookie_secure=auto` 不变。
- **Admin TLS**：旧 `admin_tls=required` 配置此前安装器拒绝；Phase C upgrade 支持，
  但同机 panel 需 `hub_ca`/SNI 覆盖；回环默认仍 HTTP。
- **升级**：`upgrade` 不重写证书/ACME 账户；模式变化需 `--force`/`tls issue`。
- **回滚**：
  - 安装失败：Phase A 事务 + 证书成对备份；不删数据；
  - ACME 失败：回退 self-signed，旧证书可恢复；
  - 续期失败：保留旧证书，不重启；
  - 面板 TLS 配置错误：安装事务回滚，旧配置/服务保留；
  - 已发 tag 不移动。

## 8. RC 与最终发布

1. C 完成且门禁绿：`Cargo.toml` workspace → `1.0.0-rc.1`；
   `CHANGELOG.md` 增加 `[1.0.0-rc.1] - 日期`；不归档 `[Unreleased]` 到 `v1.0.0`。
2. 打 annotated tag `v1.0.0-rc.1`，push；workflow：
   - verify 版本/tag/main；
   - build x86/arm64；delivery-e2e/arm64/docker；
   - images staging；manifest staging；assets/attestation；
   - 正式 `v1.0.0-rc.1` + `sha-<12>`；不 latest；pre-release。
3. 手工 LE staging：域名/公网 IP 两种；记录证书链/SAN/到期/续期。
4. RC 失败：修 main → 新 `rc.2`，不移动 rc.1 tag。
5. Phase D 完成、24h/压力/恢复演练后，Phase E 发 `v1.0.0` + latest。

## 9. 风险与待决

| 风险 | 级别 | 缓解 |
|---|---|---|
| 80/443 被占用/云安全组不可控 | 高 | 四层诊断、3 轮、回退自签、文档；不假装成功 |
| ACME rate limit / IP profile 不支持 | 高 | staging 先跑；IP 用 shortlived；C0 验证；RC 手工 |
| ACME 目录 SSRF/自定义 CA | 高 | 只允许 https、无 userinfo；私有 CA 需显式 `acme_ca_file`；测试/mock |
| 旧 v0.4 agent 在 ACME 下失联 | 高 | 启动 WARN、安装器拒绝生成指纹命令、升级文档；不静默降级 |
| 管理口 SNI/回环证书不匹配 | 中 | 回环默认 HTTP；required 需 SAN/自定义 SNI；panel `hub_ca` |
| TLS-ALPN 需要 root/443 | 中 | 安装器 root；Docker root entrypoint；端口预检 |
| 续期写盘/热加载竞态 | 中 | CertLock、成对备份、原子写、失败保旧 |
| Pebble IP/profile 不可用 | 中 | C0 决定 mock/LE staging 手工；不伪造通过 |
| release RC 失败/部分提升 | 中 | staging→正式/sha/latest 顺序；失败保持 draft；文档 |
| 面板直连 TLS 的 Cookie/CSP 回归 | 中 | `cookie_secure=always`/public_origin；浏览器 e2e |
| 证书/账户 key 泄露 | 高 | 0600、红act、无 argv/日志、渗透 |

## 10. DoD

- [ ] 旧配置/旧 agent 自签兼容测试通过；
- [ ] ACME domain HTTP-01 + TLS-ALPN Pebble e2e 通过；
- [ ] ACME IP shortlived 验证（本地 mock/Pebble 或 LE staging 手工，不得伪造）；
- [ ] 续期/热加载/失败保旧/48h 告警通过；
- [ ] 80/443 四层诊断 + 3 轮 + 回退自签通过；
- [ ] panel 直连 HTTPS + Cookie/CSP/登录通过；
- [ ] admin TLS required + panel hub_ca 通过；
- [ ] v0.4 指纹 agent 在 ACME 下明确失败/升级指引；
- [ ] 离线包 `--offline` + ACME 冲突零写入；
- [ ] Docker ACME 端口/证书卷/只读根通过；
- [ ] release `delivery-docker`/`delivery-arm64` 与真实 RC 通过；
- [ ] 独立评审/渗透无未修复高危；
- [ ] fmt/clippy/test/audit/web/actionlint 全绿；
- [ ] 文档/CHANGELOG/status 完整；
- [ ] 打 `checkpoint/<日期>-m5-phase-c-tls`，不移动旧 tag。

## 11. 起始动作（直接执行）

```bash
# 1. 同步与基线
git status --porcelain
git fetch --prune origin
git rev-list --left-right --count HEAD...origin/main
git log -1 --oneline   # 期望 a03d872

# 2. 读本计划 + M5 计划 Phase C + AGENTS
# 3. C0 spike：/tmp 最小 crate + Pebble，写 spike 结论
# 4. C1：先改 release 门禁（不影响产品代码）
# 5. C2：配置/agent TLS（先写测试再实现）
# 6. C3–C8 按顺序；C9 全量+评审+渗透+RC
```

**不要**在 C 完成前打 `v1.0.0`/推 `latest`；**不要**为了验证 GHCR 在主仓库造测试 tag；
**不要**把 ACME 目录/账户 key/证书私钥写进日志、镜像或 argv。
