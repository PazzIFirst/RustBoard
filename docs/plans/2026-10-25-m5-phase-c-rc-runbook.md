# M5 Phase C：LE staging 与 `v1.0.0-rc.1` 验证 Runbook

> 状态：待执行｜基线：本地 `main`，Phase C 代码与 checkpoint 未 push
> 关联：[Phase C 计划](2026-10-25-m5-phase-c-tls-release-gates.md)、
> [发布文档](../install/release.md)、[ACME 文档](../install/acme.md)
> 目标：在独立测试机完成真实 LE staging、hosted 发布门禁，验证
> `v1.0.0-rc.1`；**不发布 `v1.0.0`、不移动 Phase B tag**。

## 0. 机器准入

测试机必须满足：

| 项 | 要求 |
|---|---|
| OS | Linux x86_64 或 arm64（aarch64） |
| 权限 | root 或可 `sudo`；能写 `/opt` / `/tmp` |
| 网络 | 出站 443 可用；入站 80/443 从公网可达 |
| DNS | 一个 A 记录指向测试机公网 IPv4，例如 `board.example.com` |
| 端口 | 80/443 未被其他服务占用；8443/8444 可本地使用 |
| Docker | 可用；没有则安装 |
| systemd | 可用（离线包/管理端验证需要） |
| 数据 | 临时机器，允许安装/卸载/重装；不要放生产数据 |

若做 `acme-ip` shortlived：公网 IPv4 必须直接落在测试机网卡上，且 80/443
入站可达；NAT/共享公网 IP 不满足。

先在测试机执行只读预检：

```bash
set -euo pipefail
uname -a
id
ss -ltnp '( sport = :80 or sport = :443 or sport = :8443 or sport = :8444 )' || true
curl -4 -sS --max-time 5 https://api.ipify.org; echo
getent ahostsv4 board.example.com | head
curl -4 -sS -o /dev/null -w 'http=%{http_code}\n' --max-time 5 http://board.example.com/ || true
curl -4 -sS -o /dev/null -w 'https=%{http_code}\n' --max-time 5 https://board.example.com/ || true
command -v docker && docker version
command -v cargo && cargo --version || true
```

外网侧建议用另一网络检查 80/443（不要在测试机自己 curl 自己的公网 IP 作为
唯一证据，NAT hairpin 可能误导）：

```bash
# 在另一台机器执行
curl -v --max-time 5 http://board.example.com/
curl -vk --max-time 5 https://board.example.com/
```

## 1. 代码同步

当前本地 `main` 领先 origin；二选一：

```bash
# A. 允许推临时分支（推荐）
git push origin main:refs/heads/feat/m5-phase-c
# 测试机
git clone --branch feat/m5-phase-c https://github.com/PazzIFirst/RustBoard.git
```

或：

```bash
# B. 不打远程分支，用 bundle 传到测试机
git bundle create /tmp/rustboard-phase-c.bundle main
scp /tmp/rustboard-phase-c.bundle root@TEST_HOST:/tmp/
# 测试机
git clone /tmp/rustboard-phase-c.bundle rustboard
```

测试机确认：

```bash
cd rustboard
git log -1 --oneline
git status --porcelain
```

## 2. 本地门禁（测试机）

```bash
export PATH="$HOME/.cargo/bin:$PATH"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo audit
actionlint .github/workflows/release.yml
pnpm -C web test
pnpm -C web build
```

期望：workspace `1221 passed / 0 failed / 4 ignored`（以实际为准），
audit 0 高危，web 80/80。

MSRV：

```bash
rustup toolchain install 1.89.0 --profile minimal
CARGO_TARGET_DIR=/tmp/rb-msrv cargo +1.89.0 check --workspace --all-targets --locked
```

## 3. 交付物与 e2e

```bash
# amd64（测试机 arch 按需）
packaging/build-release.sh --arch amd64 --version 0.4.2 \
  --revision "$(git rev-parse --short=12 HEAD)" --web-dir web/dist --out dist

PACKAGE=$(readlink -f dist/serverdashboard-v0.4.2-x86_64.tar.gz)
PACKAGE="$PACKAGE" SKIP_BUILD=1 STRICT=1 bash tests/e2e/v100-offline.sh

DOCKER_ARCH=amd64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh
```

arm64 原生机：

```bash
packaging/build-release.sh --arch arm64 --version 0.4.2 \
  --revision "$(git rev-parse --short=12 HEAD)" --web-dir web/dist --out dist
PACKAGE=$(readlink -f dist/serverdashboard-v0.4.2-aarch64.tar.gz)
sudo env PACKAGE="$PACKAGE" SKIP_BUILD=1 STRICT=1 bash tests/e2e/v100-arm64.sh
DOCKER_ARCH=arm64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh
```

注意：x86 上的 QEMU 结果只能作为本地预演，hosted `delivery-arm64` 仍需原生
runner 证据。

## 4. Pebble / 本地 ACME

```bash
# 若没有现成 Pebble（host network；测试机 5001/5002/14000 可用）
docker run -d --name rb-pebble --network host \
  -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
  ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199

PEBBLE_NAME=rb-pebble bash tests/e2e/v100-acme.sh
bash tests/e2e/v100-acme-upgrade.sh
sudo bash tests/e2e/v100-admin-panel-tls.sh
```

## 5. 真实 LE staging

前置：域名解析到测试机，80/443 入站可达，邮箱不是 `example.com`。

```bash
rm -rf /root/rb-le-staging
sudo RUSTBOARD_ACME_TLS_PORT=443 target/debug/rustboard-hub install \
  --yes --no-systemd --prefix /root/rb-le-staging --panel no \
  --tls acme-domain --acme-email ops@your-domain.example \
  --domain board.example.com --acme-challenge tls-alpn-01 \
  --acme-directory https://acme-staging-v02.api.letsencrypt.org/directory \
  --listen 127.0.0.1:28443 --admin-listen 127.0.0.1:28444
```

或 HTTP-01（需要 80 入站）：

```bash
sudo target/debug/rustboard-hub install ... --acme-challenge http-01 ...
```

验收：

```bash
HUB=/root/rb-le-staging
grep -A12 '^\[tls\]' "$HUB/etc/rustboard/hub.toml"
openssl x509 -in "$HUB/var/lib/rustboard/hub/certs/server.crt" \
  -noout -issuer -dates -ext subjectAltName
sudo target/debug/rustboard-hub tls status --config "$HUB/etc/rustboard/hub.toml"
```

记录：目录 URL、challenge、SAN、issuer、notBefore/notAfter、指纹、staging
是否成功；证书链必须是 LE staging，不是 Pebble/自签。

公网 IP `shortlived`（如测试机持有公网 IPv4）：

```bash
sudo target/debug/rustboard-hub install ... \
  --tls acme-ip --domain 203.0.113.10 --acme-challenge http-01 \
  --acme-directory https://acme-v02.api.letsencrypt.org/directory \
  --acme-profile shortlived
```

若 staging 失败：保留 `diagnostics` 输出、`ss -ltnp`、云安全组截图/命令输出；
不要用 fallback self-signed 结果冒充 LE 通过。

## 6. RC 版本与 tag

只有第 2–5 节全绿才执行。

```bash
# 版本 0.4.2 -> 1.0.0-rc.1
# 更新 Cargo.toml [workspace.package].version 与所有 workspace 继承
# CHANGELOG 新增 [1.0.0-rc.1]，不归档 [Unreleased] 到 v1.0.0
cargo metadata --locked --no-deps --format-version 1 >/dev/null
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit -m "chore: 准备 v1.0.0-rc.1"

# 全部门禁再跑一遍
git tag -a v1.0.0-rc.1 -m "v1.0.0-rc.1 M5 Phase C RC"
git push origin main
git push origin v1.0.0-rc.1
```

workflow 会：verify → build x86/arm64 → delivery-e2e/docker/arm64 →
images staging → manifest → release environment 审批 → 资产/attestation →
正式 RC tag + sha tag；RC 不提升 `latest`，Release 为 prerelease。

验证：

```bash
gh run watch <run-id> --exit-status
gh release view v1.0.0-rc.1 --json isPrerelease,tagName,assets,url
docker buildx imagetools inspect ghcr.io/pazzifirst/rustboard-hub:v1.0.0-rc.1
```

确认：三镜像双架构、SBOM、attestation、RC 无 `latest`、draft 已 publish。
`v1.0.0` 不创建，Phase B tag 不移动。

## 7. 失败处理

- LE staging 失败：保留旧安装/证书；修 DNS/端口/安全组后重试；不伪造通过。
- delivery 门禁失败：正式 tag/Release 不发布；staging 可能已推送，重跑前核对
  `<tag>-staging` digest。
- RC workflow 失败：修 main → `v1.0.0-rc.2`，不移动 `v1.0.0-rc.1`。
- 需要回滚测试机：`rustboard-hub uninstall --prefix /root/rb-le-staging --purge --yes`
  或直接销毁临时机器；不碰生产数据。

## 8. 证据归档

写入 `docs/security/2026-11-xx-m5-phase-c-rc-evidence.md`：

- 测试机 arch/OS、公网 IP、域名、LE staging 目录
- 每条门禁命令与 PASS/FAIL/SKIP 计数
- 证书 SAN/issuer/有效期/指纹（公开信息）
- hosted run URL、Release URL、GHCR digest、attestation 验证
- 未覆盖项与残余风险
