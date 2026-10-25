#!/usr/bin/env bash
#
# M5 Phase C：ACME → self-signed 升级切换 e2e。
#
# 前置：
#   - root（安装器 prefix 校验；用 /root 下的临时目录）
#   - 本机 Pebble host network（14000 / TLS-ALPN 5001）
#   - /tmp/pebble-test/certs/pebble.minica.pem（v100-acme.sh 会生成）
#
# 验证：
#   1. `hub install --tls acme-domain --acme-challenge tls-alpn-01` 真实签发；
#   2. `hub install --force --tls self-signed` 用现有客户端 CA 重签；
#   3. 新证书能被 ca.crt 验证，配置与证书来源一致。
#
# 用法：
#   bash tests/e2e/v100-acme-upgrade.sh
#   HUB_BIN=target/debug/rustboard-hub bash tests/e2e/v100-acme-upgrade.sh
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
HUB_BIN=${HUB_BIN:-target/debug/rustboard-hub}
PEBBLE_ROOT=${PEBBLE_ROOT:-/tmp/pebble-test/certs/pebble.minica.pem}
PREFIX=""
LOG=$(mktemp /root/rustboard-v100-acme-upgrade.XXXXXX.log)

cleanup() {
  if [ -n "$PREFIX" ] && [ -d "$PREFIX" ]; then
    rm -rf -- "$PREFIX"
  fi
  rm -f -- "$LOG"
}
trap cleanup EXIT INT TERM

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

pass() {
  printf 'PASS: %s\n' "$*"
}

[ "$(id -u)" -eq 0 ] || fail "需要 root（安装器 prefix 校验）"
[ -f "$PEBBLE_ROOT" ] || fail "缺少 Pebble 根证书 $PEBBLE_ROOT；先运行 v100-acme.sh"
curl -sk --max-time 2 https://localhost:14000/dir >/dev/null 2>&1 \
  || fail "Pebble 未运行（https://localhost:14000/dir）"
if [ ! -x "$HUB_BIN" ]; then
  fail "找不到可执行 hub: $HUB_BIN（先 cargo build -p rustboard-hub）"
fi
command -v openssl >/dev/null 2>&1 || fail "缺少 openssl"

PREFIX=$(mktemp -d /root/rustboard-v100-acme-upgrade.XXXXXX)
chmod 0700 "$PREFIX"
CONFIG="$PREFIX/etc/rustboard/hub.toml"
DATA="$PREFIX/var/lib/rustboard/hub"

common=(
  --yes --no-systemd --prefix "$PREFIX" --panel no
  --listen 127.0.0.1:28443 --admin-listen 127.0.0.1:28444
)

RUSTBOARD_ACME_TLS_PORT=5001 "$HUB_BIN" install "${common[@]}" \
  --tls acme-domain --acme-email admin@example.com --domain localhost \
  --acme-challenge tls-alpn-01 \
  --acme-directory https://localhost:14000/dir \
  --acme-ca "$PEBBLE_ROOT" >"$LOG" 2>&1 \
  || { tail -n 80 "$LOG" >&2; fail "ACME 安装失败"; }

grep -q '^mode = "acme-domain"' "$CONFIG" || fail "配置未切换到 acme-domain"
openssl x509 -in "$DATA/certs/server.crt" -noout -issuer 2>/dev/null \
  | grep -q 'Pebble Intermediate' \
  || fail "ACME 证书 issuer 不是 Pebble Intermediate"
pass "ACME HTTP/TLS-ALPN 安装成功，配置与证书均为 ACME"

"$HUB_BIN" install "${common[@]}" --force --tls self-signed >>"$LOG" 2>&1 \
  || { tail -n 80 "$LOG" >&2; fail "切回 self-signed 失败"; }

grep -q '^mode = "self-signed"' "$CONFIG" || fail "配置未切回 self-signed"
openssl verify -CAfile "$DATA/certs/ca.crt" "$DATA/certs/server.crt" >/dev/null 2>&1 \
  || fail "self-signed 证书无法由 ca.crt 验证"
openssl x509 -in "$DATA/certs/server.crt" -noout -issuer 2>/dev/null \
  | grep -q 'RustBoard Root CA' \
  || fail "self-signed 证书 issuer 不是 RustBoard Root CA"
pass "ACME → self-signed 切换成功：既有 CA 重签、证书链可验证、配置一致"
