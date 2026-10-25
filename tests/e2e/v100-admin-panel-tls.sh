#!/usr/bin/env bash
#
# M5 Phase C：同机 panel → hub HTTPS（admin_tls=required + hub_ca）e2e。
#
# 前置：root（临时 prefix 在 /root）、curl、openssl、target/debug/{hub,panel}。
# 验证：
#   1. hub 以 self-signed 证书、admin_tls=required 启动，HTTPS /healthz 200；
#   2. panel 用 https hub + hub_ca 安装并启动；
#   3. panel 登录 + /api/overview 代理到 hub 成功。
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
HUB_BIN=${HUB_BIN:-target/debug/rustboard-hub}
PANEL_BIN=${PANEL_BIN:-target/debug/rustboard-panel}
PREFIX=""
HUB_PID=""
PANEL_PID=""
LOG=$(mktemp /root/rustboard-v100-admin-panel.XXXXXX.log)

cleanup() {
  [ -n "$PANEL_PID" ] && kill "$PANEL_PID" 2>/dev/null || true
  [ -n "$HUB_PID" ] && kill "$HUB_PID" 2>/dev/null || true
  [ -n "$PREFIX" ] && rm -rf -- "$PREFIX"
  rm -f -- "$LOG"
}
trap cleanup EXIT INT TERM

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || fail "需要 root（/root 临时 prefix）"
[ -x "$HUB_BIN" ] || fail "缺少 $HUB_BIN"
[ -x "$PANEL_BIN" ] || fail "缺少 $PANEL_BIN"
command -v curl >/dev/null 2>&1 || fail "缺少 curl"

PREFIX=$(mktemp -d /root/rustboard-v100-admin-panel.XXXXXX)
chmod 0700 "$PREFIX"
HUB_CONFIG="$PREFIX/etc/rustboard/hub.toml"
PANEL_CONFIG="$PREFIX/etc/rustboard/panel.toml"
CA="$PREFIX/var/lib/rustboard/hub/certs/ca.crt"

"$HUB_BIN" install --yes --no-systemd --prefix "$PREFIX" --panel no \
  --tls self-signed --admin-tls required \
  --admin-listen 0.0.0.0:28444 --listen 127.0.0.1:28443 >"$LOG" 2>&1 \
  || { tail -n 60 "$LOG" >&2; fail "hub 安装失败"; }

"$HUB_BIN" run --config "$HUB_CONFIG" >>"$LOG" 2>&1 &
HUB_PID=$!
for _ in $(seq 1 100); do
  if curl -fsS --max-time 1 --cacert "$CA" \
    --resolve localhost:28444:127.0.0.1 https://localhost:28444/healthz >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -fsS --max-time 2 --cacert "$CA" \
  --resolve localhost:28444:127.0.0.1 https://localhost:28444/healthz >/dev/null \
  || { tail -n 60 "$LOG" >&2; fail "hub HTTPS /healthz 未就绪"; }
pass "hub admin_tls=required HTTPS /healthz 200"

printf 'TestPass123!\n' >"$PREFIX/panel-password"
chmod 0600 "$PREFIX/panel-password"
"$PANEL_BIN" install --yes --no-systemd --prefix "$PREFIX" \
  --hub-url https://localhost:28444 --hub-ca "$CA" \
  --password-file "$PREFIX/panel-password" --listen 127.0.0.1:28080 >"$LOG" 2>&1 \
  || { tail -n 60 "$LOG" >&2; fail "panel 安装失败"; }

"$PANEL_BIN" run --config "$PANEL_CONFIG" >>"$LOG" 2>&1 &
PANEL_PID=$!
for _ in $(seq 1 100); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 1 \
    http://127.0.0.1:28080/healthz || true)
  [ "$code" = 200 ] && break
  sleep 0.2
done
[ "${code:-}" = 200 ] || { tail -n 60 "$LOG" >&2; fail "panel /healthz 未就绪"; }
pass "panel 以 https hub + hub_ca 启动"

curl -fsS -c "$PREFIX/cookies" -o /dev/null \
  -H 'Content-Type: application/json' \
  -H 'Origin: http://127.0.0.1:28080' \
  -d '{"password":"TestPass123!"}' \
  http://127.0.0.1:28080/api/login >/dev/null \
  || { tail -n 60 "$LOG" >&2; fail "panel 登录失败"; }
body=$(curl -fsS -b "$PREFIX/cookies" \
  -H 'Origin: http://127.0.0.1:28080' \
  http://127.0.0.1:28080/api/overview) \
  || { tail -n 60 "$LOG" >&2; fail "panel 代理 /api/overview 失败"; }
printf '%s' "$body" | grep -q '"hub-self"' \
  || fail "panel 代理响应未包含 hub-self（hub_ca 可能未生效）"
pass "panel 登录并代理 hub /api/overview 成功（hub_ca 生效）"
