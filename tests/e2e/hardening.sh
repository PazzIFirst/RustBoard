#!/usr/bin/env bash
#
# RustBoard v0.2.1 硬化回归（docs/plans/2026-10-23-v0.2.1-hardening.md §6）。
#
# 覆盖：
#   1. 弱 admin_token 拒绝启动
#   2. 未知 /api/v1/*：无 token 401，有 token 404
#   3. 管理 API 每 IP 限速：第 N+1 次 429 + Retry-After
#   4. hub 管理端口非回环监听的明文 HTTP WARN
#   5. 单 IP 空连接洪水（127.0.0.2）不影响合法 agent
#   6. 运行中 rotate-cert 热加载 ≤15s（live / disk / 实际 TLS 指纹）
#   7. 面板 trusted_proxies：XFF 分桶、Secure Cookie
#   8. 跨源 POST 403 origin_mismatch，同源正常
#   9. reset-password：旧密码失效、新密码可用
#
# 依赖：bash 4+、python3（仅标准库）、cargo/rustc、GNU coreutils。
# 用法：bash tests/e2e/hardening.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/hardening.sh
#
# 注意：本脚本按方案契约断言；实现未完成时对应断言会如实 FAIL，脚本不会改实现。
#

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}
HARDEN_PROBE="$SCRIPT_DIR/hardening_probe.py"
PANEL_PROBE="$SCRIPT_DIR/panel_probe.py"

PASSES=0
FAILS=0
PIDS=()
LAST_STATUS=""
KEEP=${KEEP_E2E_TMP:-0}

pass() { PASSES=$((PASSES + 1)); printf 'PASS [%s] %s\n' "$1" "$2"; }
fail() { FAILS=$((FAILS + 1)); printf 'FAIL [%s] %s\n' "$1" "$2" >&2; }
die() { printf 'FATAL: %s\n' "$*" >&2; exit 1; }

command -v "$PYTHON" >/dev/null 2>&1 || die "找不到 python3（需要 3.8+）"
command -v "$CARGO" >/dev/null 2>&1 || die "找不到 cargo（请放进 PATH 或设置 CARGO=...）"
[[ -f "$HARDEN_PROBE" ]] || die "缺少 $HARDEN_PROBE"
[[ -f "$PANEL_PROBE" ]] || die "缺少 $PANEL_PROBE"

# 随机五位数端口，一次选够并保证互不相同。
read -r AGENT_PORT ADMIN_PORT PANEL_PORT WEAK_AGENT_PORT WEAK_ADMIN_PORT \
  NONLOOP_ADMIN_PORT RATE_AGENT_PORT RATE_ADMIN_PORT < <(
  "$PYTHON" - <<'PY'
import random
import socket

ports = []
while len(ports) < 8:
    port = random.randint(20000, 64999)
    if port in ports:
        continue
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", port))
    except OSError:
        continue
    ports.append(port)
print(*ports)
PY
)
[[ ${#AGENT_PORT} -eq 5 && ${#ADMIN_PORT} -eq 5 ]] || die "端口选择失败"

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-hardening.XXXXXX")
HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
AGENT_CFG="$TMP_DIR/agent.toml"
AGENT_DATA="$TMP_DIR/agent"
AGENT_LOG="$TMP_DIR/agent.log"
PANEL_CFG="$TMP_DIR/panel.toml"
PANEL_LOG="$TMP_DIR/panel.log"
PANEL_INIT_LOG="$TMP_DIR/panel-init.log"
PANEL_RESET_LOG="$TMP_DIR/panel-reset.log"
WEAK_CFG="$TMP_DIR/weak.toml"
WEAK_DATA="$TMP_DIR/weak"
WEAK_LOG="$TMP_DIR/weak.log"
NONLOOP_CFG="$TMP_DIR/nonloop.toml"
NONLOOP_DATA="$TMP_DIR/nonloop"
NONLOOP_LOG="$TMP_DIR/nonloop.log"
RATE_CFG="$TMP_DIR/rate.toml"
RATE_DATA="$TMP_DIR/rate"
RATE_LOG="$TMP_DIR/rate.log"
FLOOD_LOG="$TMP_DIR/flood.log"
BUILD_LOG="$TMP_DIR/build.log"

ADMIN_URL="http://127.0.0.1:$ADMIN_PORT"
PANEL_URL="http://127.0.0.1:$PANEL_PORT"
OLD_PASSWORD="old-pass-$(date +%s)"
NEW_PASSWORD="new-pass-$(date +%s)"
WRONG_PASSWORD="wrong-$(date +%s)"

cleanup() {
  local code=$?
  trap - EXIT

  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    kill -9 "$pid" 2>/dev/null || true
  done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    wait "$pid" 2>/dev/null || true
  done

  if (( code != 0 || FAILS > 0 )); then
    echo "===== hardening e2e 失败现场 =====" >&2
    for log in "$HUB_LOG" "$AGENT_LOG" "$PANEL_LOG" "$WEAK_LOG" \
               "$NONLOOP_LOG" "$RATE_LOG" "$FLOOD_LOG" "$BUILD_LOG"; do
      if [[ -s "$log" ]]; then
        echo "---- $(basename "$log") (tail -n 100) ----" >&2
        tail -n 100 "$log" >&2 || true
      fi
    done
  fi

  if [[ "$KEEP" == "1" ]]; then
    echo "临时目录已保留: $TMP_DIR" >&2
  else
    rm -rf "$TMP_DIR"
  fi
  exit "$code"
}
trap cleanup EXIT

json_get() {
  # $1: 点分路径，例如 cert.live.fingerprint 或 headers.retry-after
  "$PYTHON" -c '
import json
import sys

try:
    value = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for key in sys.argv[1].split("."):
    if isinstance(value, dict) and key in value:
        value = value[key]
    else:
        sys.exit(1)
if isinstance(value, (dict, list)):
    print(json.dumps(value, ensure_ascii=False))
else:
    print(value)
' "$1" 2>/dev/null
}

http_call() {
  "$PYTHON" "$HARDEN_PROBE" http "$@"
}

wait_http_200() {
  local url=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local out status
  LAST_STATUS=""
  while :; do
    out=$(http_call --url "$url" --timeout 0.5 2>/dev/null || true)
    status=$(printf '%s' "$out" | json_get status || true)
    if [[ "$status" == "200" ]]; then
      return 0
    fi
    LAST_STATUS=${status:-unavailable}
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.1
  done
}

wait_for_file() {
  local file=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  while [[ ! -s "$file" ]]; do
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.1
  done
  return 0
}

cfg_str() {
  "$PYTHON" - "$1" "$2" <<'PY'
import re
import sys

path, key = sys.argv[1], sys.argv[2]
pattern = re.compile(r'^\s*' + re.escape(key) + r'\s*=\s*"([^"]*)"\s*(?:#.*)?$')
values = []
with open(path, encoding="utf-8") as handle:
    for line in handle:
        match = pattern.match(line)
        if match:
            values.append(match.group(1))
if len(values) != 1:
    print(f"{path} 中 {key} 出现 {len(values)} 次（期望 1 次）", file=sys.stderr)
    raise SystemExit(1)
print(values[0])
PY
}

set_cfg() {
  # 覆盖已有键（v0.2.1 的 init 可能写入默认值），不存在则追加；必须恰好处理一行。
  local path=$1 key=$2 line=$3
  "$PYTHON" - "$path" "$key" "$line" <<'PY'
import re
import sys

path, key, line = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
pattern = re.compile(r'(?m)^[ \t]*' + re.escape(key) + r'[ \t]*=.*$')
text, count = pattern.subn(line, text)
if count == 0:
    text = text.rstrip("\n") + "\n\n" + line + "\n"
elif count > 1:
    raise SystemExit(f"{path} 中 {key} 出现 {count} 次，拒绝写入")
open(path, "w", encoding="utf-8").write(text)
PY
}

launch_hub() {
  local cfg=$1 log=$2
  RUST_LOG=rustboard_hub=info,rustboard_common=warn,rustboard_panel=info \
    "$HUB_BIN" run --config "$cfg" > "$log" 2>&1 &
  LAST_PID=$!
  PIDS+=("$LAST_PID")
}

add_agent_token() {
  local name=$1 out token
  out=$("$HUB_BIN" agent add --config "$HUB_CFG" --name "$name") \
    || die "agent add --name $name 失败"
  token=$(printf '%s\n' "$out" \
    | awk '/一次性 token/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}')
  [[ "$token" =~ ^[0-9a-f]{64}$ ]] || die "无法从 agent add 输出解析 token"
  printf '%s' "$token"
}

write_agent_config() {
  local path=$1 name=$2 token=$3 data=$4
  mkdir -p "$data"
  chmod 700 "$data"
  cat > "$path" <<EOF
hub_url = "wss://127.0.0.1:$AGENT_PORT/agent/ws"
token = "$token"
server_fingerprint = "$SERVER_FPR"
name = "$name"
data_dir = "$data"
sample_interval_ms = 1000
buffer_max_bytes = 10485760
EOF
  chmod 600 "$path"
}

agent_field() {
  local agent_id=$1 field=$2 out
  out=$(http_call --url "$ADMIN_URL/api/v1/agents" --bearer-env 2>/dev/null || true)
  printf '%s' "$out" | "$PYTHON" -c '
import json
import sys

try:
    rows = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for row in rows:
    if row.get("agent_id") == sys.argv[1]:
        print(row.get(sys.argv[2], ""))
        sys.exit(0)
sys.exit(1)
' "$agent_id" "$field" 2>/dev/null
}

wait_agent_online() {
  local agent_id=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local status
  LAST_STATUS=""
  while :; do
    status=$(agent_field "$agent_id" status || true)
    if [[ "$status" == "online" ]]; then
      return 0
    fi
    LAST_STATUS=${status:-missing}
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

agent_samples() {
  local agent_id=$1 out
  out=$(http_call --url "$ADMIN_URL/api/v1/series?agent=$agent_id&metric=cpu.usage&from=0&to=9999999999999&limit=50000" \
    --bearer-env 2>/dev/null || true)
  printf '%s' "$out" | "$PYTHON" -c '
import json
import sys
try:
    rows = json.load(sys.stdin)
except Exception:
    sys.exit(1)
print(len(rows))
' 2>/dev/null
}

wait_samples_at_least() {
  local agent_id=$1 minimum=$2 timeout=$3
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local count
  LAST_STATUS=""
  while :; do
    count=$(agent_samples "$agent_id" || true)
    if [[ "$count" =~ ^[0-9]+$ ]] && (( count >= minimum )); then
      return 0
    fi
    LAST_STATUS=${count:-unavailable}
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

panel_login() {
  # $1 密码，$2 XFF（可空），$3 XFP（可空），$4 cookie 输出（可空）
  local password=$1 xff=$2 xfp=$3 cookie_out=$4
  local args=(login --url "$PANEL_URL/api/login" --password "$password")
  [[ -n "$xff" ]] && args+=(--header "X-Forwarded-For: $xff")
  [[ -n "$xfp" ]] && args+=(--header "X-Forwarded-Proto: $xfp")
  [[ -n "$cookie_out" ]] && args+=(--cookie-out "$cookie_out")
  "$PYTHON" "$PANEL_PROBE" "${args[@]}"
}

echo "==> 构建 rustboard-hub / rustboard-agent / rustboard-panel"
(cd "$ROOT" && "$CARGO" build --locked --bin rustboard-hub --bin rustboard-agent --bin rustboard-panel) \
  > "$BUILD_LOG" 2>&1 || die "cargo build 失败（日志: $BUILD_LOG）"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
[[ "$TARGET_DIR" = /* ]] || TARGET_DIR="$ROOT/$TARGET_DIR"
HUB_BIN="$TARGET_DIR/debug/rustboard-hub"
AGENT_BIN="$TARGET_DIR/debug/rustboard-agent"
PANEL_BIN="$TARGET_DIR/debug/rustboard-panel"
for bin in "$HUB_BIN" "$AGENT_BIN" "$PANEL_BIN"; do
  [[ -x "$bin" ]] || die "找不到 $bin"
done

# ---------------------------------------------------------------------------
# 0. 主 hub：强 token、关闭管理限速、单 IP 上限 4
# ---------------------------------------------------------------------------
echo "==> 初始化主 hub（agent=$AGENT_PORT admin=$ADMIN_PORT）"
"$HUB_BIN" init --config "$HUB_CFG" --data-dir "$HUB_DATA" \
  --agent-listen "127.0.0.1:$AGENT_PORT" \
  --admin-listen "127.0.0.1:$ADMIN_PORT" \
  --san 127.0.0.1 --force > "$TMP_DIR/init-main.log" 2>&1 \
  || die "主 hub init 失败"

sed -i 's/^self_monitor = true$/self_monitor = false/' "$HUB_CFG"
sed -i 's/^sample_interval_ms = 5000$/sample_interval_ms = 1000/' "$HUB_CFG"
set_cfg "$HUB_CFG" admin_rate_limit_per_min 'admin_rate_limit_per_min = 0'
set_cfg "$HUB_CFG" max_connections_per_ip 'max_connections_per_ip = 4'

ADMIN_TOKEN=$(cfg_str "$HUB_CFG" admin_token) || die "无法解析 admin_token"
[[ -n "$ADMIN_TOKEN" ]] || die "hub init 未生成 admin_token"
export RB_E2E_ADMIN_TOKEN="$ADMIN_TOKEN"
SERVER_FPR=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p')
[[ "$SERVER_FPR" =~ ^[0-9a-f]{64}$ ]] || die "无法读取服务端证书指纹"

echo "==> 启动主 hub"
launch_hub "$HUB_CFG" "$HUB_LOG"
wait_http_200 "$ADMIN_URL/healthz" 15 || die "主 hub 未就绪（最后状态: $LAST_STATUS）"

# ---------------------------------------------------------------------------
# 1. 弱 token 拒绝启动
# ---------------------------------------------------------------------------
echo
echo "==> 1/9 弱 admin_token 拒绝启动"
"$HUB_BIN" init --config "$WEAK_CFG" --data-dir "$WEAK_DATA" \
  --agent-listen "127.0.0.1:$WEAK_AGENT_PORT" \
  --admin-listen "127.0.0.1:$WEAK_ADMIN_PORT" \
  --san 127.0.0.1 --force > "$TMP_DIR/init-weak.log" 2>&1 \
  || fail "1.0" "弱 token 用例 hub init 失败"
"$PYTHON" - "$WEAK_CFG" <<'PY'
import re
import sys
path = sys.argv[1]
text = open(path, encoding="utf-8").read()
pattern = re.compile(r'(?m)^admin_token\s*=\s*"[^"]*"\s*$')
replacement = 'admin_token = "' + "a" * 32 + '"'
text, count = pattern.subn(replacement, text)
if count != 1:
    raise SystemExit(f"admin_token 行数异常: {count}")
open(path, "w", encoding="utf-8").write(text)
PY
set +e
timeout -s KILL 8 "$HUB_BIN" run --config "$WEAK_CFG" > "$WEAK_LOG" 2>&1
WEAK_RC=$?
set -e
if (( WEAK_RC == 0 || WEAK_RC == 124 || WEAK_RC == 137 )); then
  fail "1.1" "弱 token 仍启动（rc=$WEAK_RC）"
else
  if grep -qiE 'admin_token|token.*(强度|字符)|admin-token' "$WEAK_LOG"; then
    pass "1.1" "弱 token 启动失败（rc=$WEAK_RC），错误提示可操作"
  else
    fail "1.1" "弱 token 启动失败，但错误未提示 token 强度/admin-token"
  fi
fi

# ---------------------------------------------------------------------------
# 2. 未知 API：无 token 401，有 token 404
# ---------------------------------------------------------------------------
echo
echo "==> 2/9 未知 /api/v1/* 先鉴权"
out=$(http_call --url "$ADMIN_URL/api/v1/definitely-not-a-route" 2>/dev/null || true)
status=$(printf '%s' "$out" | json_get status || true)
if [[ "$status" == "401" ]]; then
  pass "2.1" "无 token 未知 API 返回 401"
else
  fail "2.1" "无 token 未知 API 返回 $status（期望 401）"
fi

out=$(http_call --url "$ADMIN_URL/api/v1/definitely-not-a-route" --bearer-env 2>/dev/null || true)
status=$(printf '%s' "$out" | json_get status || true)
body=$(printf '%s' "$out" | json_get body || true)
if [[ "$status" == "404" ]] && [[ "$body" == *"not_found"* ]]; then
  pass "2.2" "带 token 未知 API 返回 404 not_found"
else
  fail "2.2" "带 token 未知 API 返回 $status / $body（期望 404 not_found）"
fi

# ---------------------------------------------------------------------------
# 3. 管理 API 限速 429 + Retry-After
# ---------------------------------------------------------------------------
echo
echo "==> 3/9 管理 API 每 IP 限速"
"$HUB_BIN" init --config "$RATE_CFG" --data-dir "$RATE_DATA" \
  --agent-listen "127.0.0.1:$RATE_AGENT_PORT" \
  --admin-listen "127.0.0.1:$RATE_ADMIN_PORT" \
  --san 127.0.0.1 --force > "$TMP_DIR/init-rate.log" 2>&1 \
  || die "限速 hub init 失败"
set_cfg "$RATE_CFG" admin_rate_limit_per_min 'admin_rate_limit_per_min = 5'
RATE_TOKEN=$(cfg_str "$RATE_CFG" admin_token) || die "无法解析限速 hub 的 admin_token"
launch_hub "$RATE_CFG" "$RATE_LOG"
RATE_URL="http://127.0.0.1:$RATE_ADMIN_PORT"
wait_http_200 "$RATE_URL/healthz" 15 || die "限速 hub 未就绪"

STATUSES=()
for i in 1 2 3 4 5 6; do
  out=$(http_call --url "$RATE_URL/api/v1/agents" \
    --header "Authorization: Bearer $RATE_TOKEN" 2>/dev/null || true)
  STATUSES+=("$(printf '%s' "$out" | json_get status || echo 000)")
  if (( i == 6 )); then
    SIXTH_HEADERS=$(printf '%s' "$out" | json_get headers || true)
    SIXTH_BODY=$(printf '%s' "$out" | json_get body || true)
  fi
done
if [[ "${STATUSES[0]}" == "200" && "${STATUSES[4]}" == "200" && "${STATUSES[5]}" == "429" ]]; then
  pass "3.1" "第 1–5 次 200，第 6 次 429（实际: ${STATUSES[*]}）"
else
  fail "3.1" "限速状态不符（实际: ${STATUSES[*]}，期望 200 200 200 200 200 429）"
fi
retry_after=$(printf '%s' "$SIXTH_HEADERS" | json_get retry-after || true)
if [[ "$retry_after" =~ ^[0-9]+$ ]] && (( retry_after >= 1 && retry_after <= 60 )); then
  pass "3.2" "429 带 Retry-After: $retry_after"
else
  fail "3.2" "429 缺少合法 Retry-After（实际: ${retry_after:-none}）"
fi
if [[ "$SIXTH_BODY" == *"rate_limited"* ]]; then
  pass "3.3" "429 响应体为 rate_limited"
else
  fail "3.3" "429 响应体不是 rate_limited: $SIXTH_BODY"
fi

# ---------------------------------------------------------------------------
# 4. hub 管理端口非回环监听的明文 HTTP WARN
# ---------------------------------------------------------------------------
echo
echo "==> 4/9 hub 非回环管理监听 WARN"
"$HUB_BIN" init --config "$NONLOOP_CFG" --data-dir "$NONLOOP_DATA" \
  --agent-listen "127.0.0.1:$WEAK_AGENT_PORT" \
  --admin-listen "0.0.0.0:$NONLOOP_ADMIN_PORT" \
  --san 127.0.0.1 --force > "$TMP_DIR/init-nonloop.log" 2>&1 \
  || die "非回环 hub init 失败"
launch_hub "$NONLOOP_CFG" "$NONLOOP_LOG"
if wait_http_200 "http://127.0.0.1:$NONLOOP_ADMIN_PORT/healthz" 15; then
  if grep -qiE '明文 HTTP|非回环|VPN|可信反代' "$NONLOOP_LOG"; then
    pass "4.1" "管理端口 0.0.0.0 启动时打印明文 HTTP WARN"
  else
    fail "4.1" "管理端口 0.0.0.0 启动但日志无明文 HTTP WARN"
  fi
else
  fail "4.1" "非回环 hub 未就绪（最后状态: $LAST_STATUS）"
fi

# ---------------------------------------------------------------------------
# 5. 单 IP 空连接洪水不影响合法 agent
# ---------------------------------------------------------------------------
echo
echo "==> 5/9 单 IP 空连接洪水（127.0.0.2）"
A_TOKEN=$(add_agent_token "hardening-a")
write_agent_config "$AGENT_CFG" "hardening-a" "$A_TOKEN" "$AGENT_DATA"
"$AGENT_BIN" run --config "$AGENT_CFG" > "$AGENT_LOG" 2>&1 &
AGENT_PID=$!
PIDS+=("$AGENT_PID")
AGENT_ID_FILE="$AGENT_DATA/agent_id"
wait_for_file "$AGENT_ID_FILE" 20 || die "agent 未在 20s 内完成纳管"
AGENT_ID=$(tr -d '[:space:]' < "$AGENT_ID_FILE")
[[ -n "$AGENT_ID" ]] || die "agent_id 为空"
wait_agent_online "$AGENT_ID" 20 || die "agent 未 online（最后状态: $LAST_STATUS）"
wait_samples_at_least "$AGENT_ID" 3 20 || die "agent 未上报样本（最后: $LAST_STATUS）"
BASELINE=$(agent_samples "$AGENT_ID")
[[ "$BASELINE" =~ ^[0-9]+$ ]] || BASELINE=0

"$PYTHON" "$HARDEN_PROBE" flood --host 127.0.0.1 --port "$AGENT_PORT" \
  --source 127.0.0.2 --count 32 --hold 10 > "$FLOOD_LOG" 2>&1 &
FLOOD_PID=$!
PIDS+=("$FLOOD_PID")
if wait_for_file "$FLOOD_LOG" 10; then
  FLOOD_OPENED=$(json_get opened < "$FLOOD_LOG" || true)
  if [[ "$FLOOD_OPENED" =~ ^[0-9]+$ ]] && (( FLOOD_OPENED >= 16 )); then
    pass "5.1" "从 127.0.0.2 建立 $FLOOD_OPENED 条空闲连接"
  else
    fail "5.1" "洪水连接数不足（opened=${FLOOD_OPENED:-none}）"
  fi
else
  fail "5.1" "洪水探针未在 10s 内就绪"
fi

sleep 2
if wait_agent_online "$AGENT_ID" 5; then
  pass "5.2" "洪水期间合法 agent 仍 online"
else
  fail "5.2" "洪水期间合法 agent 掉线（最后状态: $LAST_STATUS）"
fi
AFTER_FLOOD=$(agent_samples "$AGENT_ID")
if [[ "$AFTER_FLOOD" =~ ^[0-9]+$ ]] && (( AFTER_FLOOD > BASELINE )); then
  pass "5.3" "洪水期间样本继续增长（$BASELINE → $AFTER_FLOOD）"
else
  fail "5.3" "洪水期间样本未增长（$BASELINE → ${AFTER_FLOOD:-none}）"
fi
if grep -q '来源 IP 并发连接已达上限' "$HUB_LOG"; then
  pass "5.4" "hub 记录单 IP 连接上限告警"
else
  fail "5.4" "hub 未记录单 IP 连接上限告警"
fi

kill -9 "$FLOOD_PID" 2>/dev/null || true
wait "$FLOOD_PID" 2>/dev/null || true
sleep 1
BEFORE_AFTER_FLOOD=$(agent_samples "$AGENT_ID")
sleep 2
AFTER_AFTER_FLOOD=$(agent_samples "$AGENT_ID")
if [[ "$BEFORE_AFTER_FLOOD" =~ ^[0-9]+$ && "$AFTER_AFTER_FLOOD" =~ ^[0-9]+$ ]] \
   && (( AFTER_AFTER_FLOOD > BEFORE_AFTER_FLOOD )); then
  pass "5.5" "洪水断开后 agent 继续上报（$BEFORE_AFTER_FLOOD → $AFTER_AFTER_FLOOD）"
else
  fail "5.5" "洪水断开后样本未增长（$BEFORE_AFTER_FLOOD → ${AFTER_AFTER_FLOOD:-none}）"
fi

# ---------------------------------------------------------------------------
# 6. rotate-cert 热加载 ≤15s
# ---------------------------------------------------------------------------
echo
echo "==> 6/9 rotate-cert 热加载（live/disk/实际 TLS）"
system_json() {
  http_call --url "$ADMIN_URL/api/v1/system" --bearer-env 2>/dev/null || true
}
old_sys=$(system_json)
OLD_LIVE=$(printf '%s' "$old_sys" | json_get cert.live.fingerprint || true)
OLD_DISK=$(printf '%s' "$old_sys" | json_get cert.disk.fingerprint || true)
OLD_TOP=$(printf '%s' "$old_sys" | json_get cert.fingerprint || true)
OLD_TLS=$("$PYTHON" "$HARDEN_PROBE" tls-fingerprint --host 127.0.0.1 --port "$AGENT_PORT" 2>/dev/null || true)
if [[ "$OLD_LIVE" =~ ^[0-9a-f]{64}$ && "$OLD_DISK" == "$OLD_LIVE" && "$OLD_TLS" == "$OLD_LIVE" ]]; then
  pass "6.1" "初始 live/disk/实际 TLS 指纹一致"
else
  fail "6.1" "初始指纹不一致（live=${OLD_LIVE:-none} disk=${OLD_DISK:-none} tls=${OLD_TLS:-none} top=${OLD_TOP:-none}）"
fi

if "$HUB_BIN" rotate-cert --config "$HUB_CFG" --force > "$TMP_DIR/rotate.log" 2>&1; then
  pass "6.2" "运行中 rotate-cert --force 成功"
else
  fail "6.2" "运行中 rotate-cert --force 失败"
fi

DEADLINE=$(( $(date +%s%3N) + 15000 ))
NEW_LIVE=""
while (( $(date +%s%3N) < DEADLINE )); do
  sys=$(system_json)
  live=$(printf '%s' "$sys" | json_get cert.live.fingerprint || true)
  disk=$(printf '%s' "$sys" | json_get cert.disk.fingerprint || true)
  if [[ "$live" =~ ^[0-9a-f]{64}$ && "$live" == "$disk" && "$live" != "$OLD_LIVE" ]]; then
    NEW_LIVE=$live
    break
  fi
  sleep 0.2
done
if [[ -n "$NEW_LIVE" ]]; then
  pass "6.3" "live 在 15s 内追上 disk 且指纹变化（$NEW_LIVE）"
else
  fail "6.3" "live 未在 15s 内追上 disk"
fi

if [[ -n "$NEW_LIVE" ]]; then
  DEADLINE=$(( $(date +%s%3N) + 15000 ))
  NEW_TLS=""
  while (( $(date +%s%3N) < DEADLINE )); do
    tls=$("$PYTHON" "$HARDEN_PROBE" tls-fingerprint --host 127.0.0.1 --port "$AGENT_PORT" 2>/dev/null || true)
    if [[ "$tls" == "$NEW_LIVE" ]]; then
      NEW_TLS=$tls
      break
    fi
    sleep 0.2
  done
  if [[ -n "$NEW_TLS" ]]; then
    pass "6.4" "新 TLS 连接在 15s 内使用新证书"
  else
    fail "6.4" "新 TLS 连接未在 15s 内使用新证书"
  fi
else
  fail "6.4" "live 未更新，跳过实际 TLS 指纹断言"
fi

if wait_agent_online "$AGENT_ID" 5; then
  pass "6.5" "轮换后 agent 仍 online"
else
  fail "6.5" "轮换后 agent 掉线（最后状态: $LAST_STATUS）"
fi
ROTATE_BEFORE=$(agent_samples "$AGENT_ID")
sleep 2
ROTATE_AFTER=$(agent_samples "$AGENT_ID")
if [[ "$ROTATE_BEFORE" =~ ^[0-9]+$ && "$ROTATE_AFTER" =~ ^[0-9]+$ ]] \
   && (( ROTATE_AFTER > ROTATE_BEFORE )); then
  pass "6.6" "轮换后样本继续增长（$ROTATE_BEFORE → $ROTATE_AFTER）"
else
  fail "6.6" "轮换后样本未增长（$ROTATE_BEFORE → ${ROTATE_AFTER:-none}）"
fi

# ---------------------------------------------------------------------------
# 7. 面板 trusted_proxies + Secure Cookie
# ---------------------------------------------------------------------------
echo
echo "==> 7/9 面板 trusted_proxies / XFF 分桶 / Secure Cookie"
PANEL_ARGS=(init --config "$PANEL_CFG" --listen "127.0.0.1:$PANEL_PORT" \
  --hub "$ADMIN_URL" --hub-token "$ADMIN_TOKEN" --password "$OLD_PASSWORD" --force)
if [[ -f "$ROOT/web/dist/index.html" ]]; then
  PANEL_ARGS+=(--static-dir "$ROOT/web/dist")
fi
"$PANEL_BIN" "${PANEL_ARGS[@]}" > "$PANEL_INIT_LOG" 2>&1 \
  || die "panel init 失败（日志: $PANEL_INIT_LOG）"

set_cfg "$PANEL_CFG" trusted_proxies 'trusted_proxies = ["127.0.0.1"]'
set_cfg "$PANEL_CFG" cookie_secure 'cookie_secure = "auto"'
set_cfg "$PANEL_CFG" public_origin 'public_origin = ""'

RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$PANEL_CFG" >> "$PANEL_LOG" 2>&1 &
PANEL_PID=$!
PIDS+=("$PANEL_PID")
wait_http_200 "$PANEL_URL/healthz" 20 || die "面板未就绪（最后状态: $LAST_STATUS）"

# 直连登录：auto 模式下没有可信 XFP，不应加 Secure。
out=$(panel_login "$OLD_PASSWORD" "" "" "$TMP_DIR/cookie-direct.txt" 2>/dev/null || true)
status=$(printf '%s' "$out" | json_get status || true)
secure=$(printf '%s' "$out" | json_get secure || true)
if [[ "$status" == "204" ]]; then
  pass "7.1" "面板直连登录成功"
else
  fail "7.1" "面板直连登录返回 $status（期望 204）"
fi
if [[ "$secure" == "False" || "$secure" == "false" || "$secure" == "0" ]]; then
  pass "7.2" "无 XFP 时 Cookie 不带 Secure（auto 模式）"
else
  fail "7.2" "无 XFP 时 Cookie secure=${secure:-none}（期望 false）"
fi

# 可信代理 + XFP=https：Secure；XFF 决定限速桶。
IP_A="203.0.113.10"
IP_B="203.0.113.20"
out=$(panel_login "$OLD_PASSWORD" "$IP_A" "https" "$TMP_DIR/cookie-a.txt" 2>/dev/null || true)
status=$(printf '%s' "$out" | json_get status || true)
secure=$(printf '%s' "$out" | json_get secure || true)
if [[ "$status" == "204" && ( "$secure" == "True" || "$secure" == "true" || "$secure" == "1" ) ]]; then
  pass "7.3" "可信代理 XFP=https 时 Cookie 带 Secure"
else
  fail "7.3" "可信代理 Secure Cookie 断言失败（status=$status secure=${secure:-none}）"
fi

for i in 1 2 3 4 5; do
  out=$(panel_login "$WRONG_PASSWORD" "$IP_A" "https" 2>/dev/null || true)
  status=$(printf '%s' "$out" | json_get status || true)
  if [[ "$status" != "401" ]]; then
    fail "7.4.$i" "IP A 第 $i 次错误密码返回 $status（期望 401）"
    break
  fi
done
out=$(panel_login "$OLD_PASSWORD" "$IP_A" "https" 2>/dev/null || true)
status=$(printf '%s' "$out" | json_get status || true)
if [[ "$status" == "429" ]]; then
  pass "7.4" "同一 XFF 连续失败后正确密码 429"
else
  fail "7.4" "同一 XFF 失败 5 次后正确密码返回 $status（期望 429）"
fi

out=$(panel_login "$OLD_PASSWORD" "$IP_B" "https" "$TMP_DIR/cookie-b.txt" 2>/dev/null || true)
status=$(printf '%s' "$out" | json_get status || true)
secure=$(printf '%s' "$out" | json_get secure || true)
if [[ "$status" == "204" && ( "$secure" == "True" || "$secure" == "true" || "$secure" == "1" ) ]]; then
  pass "7.5" "不同可信 XFF 独立分桶（IP B 登录 204 + Secure）"
else
  fail "7.5" "不同 XFF 未独立分桶（status=$status secure=${secure:-none}）"
fi

# ---------------------------------------------------------------------------
# 8. Origin 校验
# ---------------------------------------------------------------------------
echo
echo "==> 8/9 Origin 跨源校验"
out=$(http_call --url "$PANEL_URL/api/login" --method POST \
  --header 'Content-Type: application/json' \
  --header 'Origin: https://evil.example' \
  --data "{\"password\":\"$OLD_PASSWORD\"}" 2>/dev/null || true)
status=$(printf '%s' "$out" | json_get status || true)
body=$(printf '%s' "$out" | json_get body || true)
if [[ "$status" == "403" && "$body" == *"origin_mismatch"* ]]; then
  pass "8.1" "跨源 POST /api/login 返回 403 origin_mismatch"
else
  fail "8.1" "跨源 POST 返回 $status / $body（期望 403 origin_mismatch）"
fi

out=$(http_call --url "$PANEL_URL/api/login" --method POST \
  --header 'Content-Type: application/json' \
  --header "Origin: http://127.0.0.1:$PANEL_PORT" \
  --data "{\"password\":\"$OLD_PASSWORD\"}" 2>/dev/null || true)
status=$(printf '%s' "$out" | json_get status || true)
if [[ "$status" == "204" ]]; then
  pass "8.2" "同源 POST /api/login 返回 204"
else
  fail "8.2" "同源 POST 返回 $status（期望 204）"
fi

# ---------------------------------------------------------------------------
# 9. reset-password：旧密码失效、新密码可用
# ---------------------------------------------------------------------------
echo
echo "==> 9/9 panel reset-password"
kill -9 "$PANEL_PID" 2>/dev/null || true
wait "$PANEL_PID" 2>/dev/null || true

if "$PANEL_BIN" reset-password --config "$PANEL_CFG" --password "$NEW_PASSWORD" \
    > "$PANEL_RESET_LOG" 2>&1; then
  pass "9.1" "reset-password 命令成功"
else
  fail "9.1" "reset-password 命令失败（日志: $PANEL_RESET_LOG）"
fi

RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$PANEL_CFG" >> "$PANEL_LOG" 2>&1 &
PANEL_PID=$!
PIDS+=("$PANEL_PID")
if wait_http_200 "$PANEL_URL/healthz" 20; then
  pass "9.2" "重置密码后面板重新就绪"
else
  fail "9.2" "重置密码后面板未就绪（最后状态: $LAST_STATUS）"
fi

IP_C="203.0.113.30"
out=$(panel_login "$OLD_PASSWORD" "$IP_C" "" 2>/dev/null || true)
OLD_STATUS=$(printf '%s' "$out" | json_get status || true)
out=$(panel_login "$NEW_PASSWORD" "$IP_C" "" "$TMP_DIR/cookie-new.txt" 2>/dev/null || true)
NEW_STATUS=$(printf '%s' "$out" | json_get status || true)
if [[ "$OLD_STATUS" == "401" ]]; then
  pass "9.3" "旧密码登录返回 401"
else
  fail "9.3" "旧密码登录返回 $OLD_STATUS（期望 401）"
fi
if [[ "$NEW_STATUS" == "204" ]]; then
  pass "9.4" "新密码登录返回 204"
else
  fail "9.4" "新密码登录返回 $NEW_STATUS（期望 204）"
fi

echo
if (( FAILS > 0 )); then
  echo "hardening e2e 结果: $PASSES 项通过，$FAILS 项失败" >&2
  exit 1
fi
echo "hardening e2e 结果: 全部 $PASSES 项通过"
