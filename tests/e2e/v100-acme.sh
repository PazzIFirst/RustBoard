#!/usr/bin/env bash
#
# M5 Phase C：真实 Pebble ACME e2e（HTTP-01 / TLS-ALPN-01 / IP shortlived）。
#
# 依赖：
#   - docker（host network；Pebble 的 VA 需要直接访问宿主 5001/5002）
#   - cargo；本机 5001/5002/14000 可用
#   - 不需要公网、不需要真实域名或 Let's Encrypt 账号
#
# Pebble 的 VA 使用宿主端口：
#   HTTP-01     -> 127.0.0.1:5002
#   TLS-ALPN-01 -> 127.0.0.1:5001
# Pebble 自身监听 14000（ACME directory）与 15000（management）。
#
# 用法：
#   bash tests/e2e/v100-acme.sh
#   PEBBLE_NAME=rb-pebble bash tests/e2e/v100-acme.sh   # 复用已运行容器
#
# 注意：这是 ACME 客户端/挑战/证书链的本地真实签发测试，不替代生产 80/443
# 的 LE staging 手工门禁；Pebble 根仅用于测试，不入库。
set -uo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$ROOT" || {
  printf 'FATAL: 无法进入仓库根目录: %s\n' "$ROOT" >&2
  exit 1
}

PEBBLE_NAME=${PEBBLE_NAME:-rb-e2e-acme-pebble}
PEBBLE_IMAGE=${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199}
PEBBLE_ROOT_DIR=${PEBBLE_ROOT_DIR:-/tmp/pebble-test}
PEBBLE_ROOT="$PEBBLE_ROOT_DIR/certs/pebble.minica.pem"
STARTED=0
LOG=$(mktemp /tmp/rustboard-v100-acme.XXXXXX.log)

cleanup() {
  if [ "$STARTED" = "1" ]; then
    docker rm -f "$PEBBLE_NAME" >/dev/null 2>&1 || true
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

command -v docker >/dev/null 2>&1 || fail "缺少 docker"
command -v cargo >/dev/null 2>&1 || {
  if [ -x "$HOME/.cargo/bin/cargo" ]; then
    export PATH="$HOME/.cargo/bin:$PATH"
  else
    fail "缺少 cargo"
  fi
}

for port in 14000 5001 5002; do
  if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN; then
    if [ "$port" = "14000" ] && docker inspect "$PEBBLE_NAME" >/dev/null 2>&1; then
      continue
    fi
    fail "端口 $port 已被占用；Pebble e2e 需要 14000/5001/5002 空闲"
  fi
done

if docker inspect "$PEBBLE_NAME" >/dev/null 2>&1; then
  printf 'INFO: 复用已存在的 Pebble 容器 %s\n' "$PEBBLE_NAME"
else
  docker run -d --name "$PEBBLE_NAME" --network host \
    -e PEBBLE_VA_NOSLEEP=1 \
    -e PEBBLE_WFE_NONCEREJECT=0 \
    "$PEBBLE_IMAGE" >/dev/null || fail "启动 Pebble 失败"
  STARTED=1
fi

mkdir -p "$PEBBLE_ROOT_DIR/certs"
for _ in $(seq 1 50); do
  if curl -sk --max-time 1 https://localhost:14000/dir >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done
curl -sk --max-time 2 https://localhost:14000/dir >/dev/null 2>&1 \
  || fail "Pebble ACME directory 未就绪（https://localhost:14000/dir）"

docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$PEBBLE_ROOT.tmp" >/dev/null 2>&1 \
  || fail "从 Pebble 容器提取 pebble.minica.pem 失败"
mv -f -- "$PEBBLE_ROOT.tmp" "$PEBBLE_ROOT"
chmod 0644 "$PEBBLE_ROOT"

pass "Pebble 就绪：$PEBBLE_IMAGE，根证书 $PEBBLE_ROOT"

# 真实签发；缺 RUSTBOARD_PEBBLE=1 或缺根时测试内部会 panic，不会静默 skip。
if ! RUSTBOARD_PEBBLE=1 cargo test -p rustboard-hub --locked -- \
  --ignored pebble --test-threads=1 >"$LOG" 2>&1; then
  tail -n 80 "$LOG" >&2
  fail "Pebble ACME e2e 失败"
fi
grep -q '3 passed' "$LOG" || {
  tail -n 80 "$LOG" >&2
  fail "期望 3 个 Pebble 测试全部通过，实际输出不匹配"
}

pass "Pebble ACME e2e：HTTP-01、TLS-ALPN-01、IP shortlived 全部通过"
