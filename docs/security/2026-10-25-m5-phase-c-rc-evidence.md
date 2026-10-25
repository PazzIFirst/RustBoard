# M5 Phase C：`v1.0.0-rc.2` 发布证据

> 日期：2026-10-26（Asia/Shanghai）｜基线：`main@603c3ee`
> 目标：记录 Phase C RC 的真实发布门禁、资产、镜像与残余风险。
> **未发布 `v1.0.0`，未移动 Phase B tag。**

## 1. 结论

| 项 | 结果 |
|---|---|
| RC tag | `v1.0.0-rc.2`（commit `603c3eec438c`） |
| Release | <https://github.com/PazzIFirst/RustBoard/releases/tag/v1.0.0-rc.2> |
| Release 类型 | **prerelease=true**，非 draft |
| Workflow | Release run `40216991342`：全部 job 成功 |
| `v1.0.0` | 未创建 |
| Phase B tag | `checkpoint/2026-10-25-m5-phase-b-delivery` 未移动 |

`v1.0.0-rc.1` 已保留为失败 tag，未移动/删除。其失败原因是 GitHub runner 的
`/opt` 为 0777、以及 Docker e2e 的宿主 bind-mount 可见性预检假阴性；修复后以
`v1.0.0-rc.2` 重新发布。

## 2. Workflow 门禁

Release run `40216991342` 的 job：

- `校验与发布门禁`：tag/版本/main 祖先、fmt、clippy、workspace test、audit、
  SBOM、CHANGELOG 发布说明
- `构建 amd64 离线包`、`构建 arm64 离线包`
- `离线安装 e2e（x86_64）`：**122 PASS / 0 FAIL / 0 SKIP，STRICT=1**
- `Docker 交付 e2e（amd64）`：**123 PASS / 0 FAIL / 1 SKIP**（可选 arm64/QEMU）
- `arm64 交付 e2e（原生）`：通过（原生 arm64 runner）
- `镜像 hub/panel/agent（amd64 + arm64）`：全部成功
- `合成多架构 manifest`：成功
- `发布 GitHub Release`：成功

## 3. 资产与多架构镜像

Release 资产：

- `serverdashboard-v1.0.0-rc.2-x86_64.tar.gz`
- `serverdashboard-v1.0.0-rc.2-aarch64.tar.gz`
- `SHA256SUMS` / `SHA256SUMS.x86_64` / `SHA256SUMS.aarch64`
- `sbom-x86_64.spdx.json` / `sbom-aarch64.spdx.json`
- `image-digests.txt`

GHCR manifest（`linux/amd64` + `linux/arm64`）：

| 镜像 | digest |
|---|---|
| `ghcr.io/pazzifirst/rustboard-hub:v1.0.0-rc.2` | `sha256:1c3dae6df0e9dd7b89dc5c0ce55dfeed39b1f8c7884d747f339ad3f59fb824a5` |
| `ghcr.io/pazzifirst/rustboard-panel:v1.0.0-rc.2` | `sha256:37503d668b3b95caebc75f439e2e02c7e8ea753a8831061c56c72464d690eaf3` |
| `ghcr.io/pazzifirst/rustboard-agent:v1.0.0-rc.2` | `sha256:87714de690fbf56157aadee6b67bc996723afe998b4fa13328e4634754b05790` |

Attestation：

```bash
gh attestation verify oci://ghcr.io/pazzifirst/rustboard-hub:v1.0.0-rc.2 \
  --repo PazzIFirst/RustBoard
```

返回 0；panel/agent 同一 workflow 产出。RC 不提升 `latest`（workflow 仅在
stable tag 执行 latest）。

## 4. 本地 + 实机门禁

- workspace **1221 passed / 0 failed / 4 ignored**；MSRV 1.89、fmt、clippy、
  audit、actionlint 通过
- Pebble **3/3**：HTTP-01、TLS-ALPN-01、IP `shortlived`
- ACME → self-signed 切换：`tests/e2e/v100-acme-upgrade.sh` 通过
- panel → HTTPS hub `hub_ca`：`tests/e2e/v100-admin-panel-tls.sh` 通过
- 真实 LE staging：域名 HTTP-01、域名 TLS-ALPN-01、公网 IPv4 `shortlived`
  三路签发成功；详见
  [LE staging 证据](2026-10-25-m5-phase-c-le-staging-evidence.md)
- 独立渗透：高危 0 / 中危 0 / 低危 2（L-01、L-03；L-02 已修复）
- t4g.nano（arm64 release 包）空闲内存：hub 10 MiB、panel 5 MiB、agent 4 MiB
  （合计约 19 MiB）

## 5. 残余风险（不阻断 RC）

- 私有 ACME 未设置 `tls.agent_ca_file` 时仍从签发链尾派生 intermediate；CA
  轮换需要人工更新已分发锚。
- L-01：旧 `account.json` 权限只在 `tls issue` 读取时收紧；acme 目录 0700。
- L-03：ACME 域名证书 + `admin_tls=required` + 回环绑定被 fail-closed 拒绝；
  需绑 0.0.0.0 或补回环 IP SAN。
- QEMU/本地 arm64 快速包不是发布 profile；发布 profile 的 arm64 由 hosted
  `delivery-arm64` 原生构建覆盖。

## 6. 未执行 / 后续

- `v1.0.0` 正式发布：等 RC 试用与 Phase D/E 完成后再评估。
- 域名生产证书（非 staging）未消耗生产限额。
- 24h 长稳、100–1000 agent 压力：属于里程碑发布前的后续验收，不在本次 RC
  证据内。
