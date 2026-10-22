#!/usr/bin/env bash
#
# RustBoard M3 控制面端到端回归。
#
# 目标：用临时 fake systemctl / docker / journalctl 驱动真实的 hub + agent，
# 覆盖方案 docs/plans/2026-10-23-m3-control-plane.md §6 的验收点：
#   能力状态、systemd/docker 白名单与越权、进程 PID+名称校验、日志 tail 与逃逸拒绝、
#   能力关闭/离线错误、审计分页过滤、面板代理审计 actor、旧式无能力 agent。
#
# 依赖：bash 4+、python3（仅标准库）、curl、cargo/rustc。
# 用法：bash tests/e2e/control.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/control.sh
#
# 说明：本脚本只写测试，不修改实现。当前实现若尚未接入控制 API，会在
#      对应断言处 FAIL，而不是跳过；便于逐项定位未完成部分。
#

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}

PASSES=0
FAILS=0
STATUS=""
BODY=""
HTTP_BODY_FILE=""
PIDS=()
HUB_PID=""
A_PID=""
B_PID=""
C_PID=""
PANEL_PID=""
TEST_PID=""

pass() {
  PASSES=$((PASSES + 1))
  echo "PASS $*"
}

fail() {
  FAILS=$((FAILS + 1))
  echo "FAIL $*" >&2
}

die() {
  echo "FATAL: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# 临时目录与清理
# ---------------------------------------------------------------------------

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-control.XXXXXX")
FAKE_DIR="$TMP_DIR/fake"
LOG_DIR="$TMP_DIR/logs"
mkdir -p "$FAKE_DIR" "$LOG_DIR"
chmod 700 "$TMP_DIR" "$FAKE_DIR" "$LOG_DIR"

HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
A_CFG="$TMP_DIR/agent-a.toml"
A_DATA="$TMP_DIR/agent-a"
A_LOG="$TMP_DIR/agent-a.log"
B_CFG="$TMP_DIR/agent-b.toml"
B_DATA="$TMP_DIR/agent-b"
B_LOG="$TMP_DIR/agent-b.log"
C_CFG="$TMP_DIR/agent-c.toml"
C_DATA="$TMP_DIR/agent-c"
C_LOG="$TMP_DIR/agent-c.log"
D_CFG="$TMP_DIR/agent-d.toml"
D_DATA="$TMP_DIR/agent-d"
D_LOG="$TMP_DIR/agent-d.log"
PANEL_CFG="$TMP_DIR/panel.toml"
PANEL_LOG="$TMP_DIR/panel.log"
PANEL_JAR="$TMP_DIR/panel.cookies"
HTTP_BODY_FILE="$TMP_DIR/http-body"

SYSTEMCTL_LOG="$LOG_DIR/systemctl.argv"
DOCKER_LOG="$LOG_DIR/docker.argv"
JOURNAL_LOG="$LOG_DIR/journalctl.argv"
NGINX_LOG="$LOG_DIR/nginx.log"
SYMLINK_LOG="$LOG_DIR/evil-link"

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
    echo "===== control e2e 失败现场 =====" >&2
    for log in "$HUB_LOG" "$A_LOG" "$B_LOG" "$C_LOG" "$D_LOG" "$PANEL_LOG" \
               "$TMP_DIR/init.log" "$TMP_DIR/panel-init.log" "$TMP_DIR/curl.err"; do
      if [[ -s "$log" ]]; then
        echo "---- $(basename "$log") (tail -n 80) ----" >&2
        tail -n 80 "$log" >&2 || true
      fi
    done
    for log in "$SYSTEMCTL_LOG" "$DOCKER_LOG" "$JOURNAL_LOG"; do
      if [[ -s "$log" ]]; then
        echo "---- $(basename "$log") ----" >&2
        tail -n 40 "$log" >&2 || true
      fi
    done
  fi

  if [[ "${KEEP_E2E_TMP:-0}" == "1" ]]; then
    echo "临时目录已保留: $TMP_DIR" >&2
  else
    rm -rf "$TMP_DIR"
  fi
  exit "$code"
}
trap cleanup EXIT

command -v "$PYTHON" >/dev/null 2>&1 || die "找不到 python3（需要 3.8+）"
command -v "$CARGO" >/dev/null 2>&1 || die "找不到 cargo（请放进 PATH 或设置 CARGO=...）"
command -v curl >/dev/null 2>&1 || die "找不到 curl"
command -v timeout >/dev/null 2>&1 || die "找不到 timeout"

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

pick_port() {
  "$PYTHON" - <<'PY'
import random
import socket

for _ in range(200):
    port = random.randint(20000, 64999)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", port))
    except OSError:
        continue
    print(port)
    break
else:
    raise SystemExit("找不到空闲的五位数端口")
PY
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
    raise SystemExit(f"{path} 中 {key} 出现 {len(values)} 次")
print(values[0])
PY
}

json_get() {
  "$PYTHON" -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(eval(sys.argv[1], {"__builtins__": {}}, {"d": d, "len": len, "sorted": sorted, "any": any, "all": all}))
except Exception:
    print("")
' "$1" <<<"$BODY" 2>/dev/null || true
}

check_eq() {
  local label=$1 expected=$2 actual=$3
  if [[ "$expected" == "$actual" ]]; then
    pass "$label"
  else
    fail "$label（期望 [$expected]，实际 [$actual]）"
  fi
}

check_contains() {
  local label=$1 haystack=$2 needle=$3
  if [[ "$haystack" == *"$needle"* ]]; then
    pass "$label"
  else
    fail "$label（未找到 [$needle]）"
  fi
}

check_not_contains() {
  local label=$1 haystack=$2 needle=$3
  if [[ "$haystack" != *"$needle"* ]]; then
    pass "$label"
  else
    fail "$label（不应出现 [$needle]）"
  fi
}

expect_status() {
  local label=$1 expected=$2
  if [[ "$STATUS" == "$expected" ]]; then
    pass "$label"
  else
    fail "$label（期望 HTTP $expected，实际 $STATUS；body=$(printf '%s' "$BODY" | head -c 400)）"
  fi
}

expect_status_in() {
  local label=$1; shift
  local code
  for code in "$@"; do
    if [[ "$STATUS" == "$code" ]]; then
      pass "$label"
      return
    fi
  done
  fail "$label（期望 HTTP {$*}，实际 $STATUS；body=$(printf '%s' "$BODY" | head -c 400)）"
}

expect_error_code() {
  local label=$1 expected=$2
  local code
  code=$(json_get 'd.get("error", {}).get("code", "")' 2>/dev/null || true)
  if [[ "$code" == "$expected" ]]; then
    pass "$label"
  else
    fail "$label（期望 code=$expected，实际 [$code]；body=$(printf '%s' "$BODY" | head -c 400)）"
  fi
}

# GET/POST 管理 API，自动带 Bearer。参数：METHOD PATH [JSON_BODY]
api() {
  local method=$1 path=$2 data=${3:-}
  local -a args=(
    -sS --max-time 25 -o "$HTTP_BODY_FILE" -w '%{http_code}'
    -X "$method" "${ADMIN_URL}${path}"
    -H "Authorization: Bearer ${ADMIN_TOKEN}"
    -H 'Content-Type: application/json'
    -H 'Accept: application/json'
  )
  [[ -n "$data" ]] && args+=(--data-binary "$data")
  STATUS=$(curl "${args[@]}" 2>"$TMP_DIR/curl.err") || STATUS="000"
  BODY=$(cat "$HTTP_BODY_FILE" 2>/dev/null || true)
}

# 面板 API，使用 Cookie jar；参数：METHOD PATH [JSON_BODY]
panel_api() {
  local method=$1 path=$2 data=${3:-}
  local -a args=(
    -sS --max-time 25 -o "$HTTP_BODY_FILE" -w '%{http_code}'
    -X "$method" "${PANEL_URL}${path}"
    -b "$PANEL_JAR" -c "$PANEL_JAR"
    -H "Origin: ${PANEL_URL}"
    -H "Referer: ${PANEL_URL}/"
    -H 'Content-Type: application/json'
    -H 'Accept: application/json'
  )
  [[ -n "$data" ]] && args+=(--data-binary "$data")
  STATUS=$(curl "${args[@]}" 2>"$TMP_DIR/curl.err") || STATUS="000"
  BODY=$(cat "$HTTP_BODY_FILE" 2>/dev/null || true)
}

wait_health() {
  local url=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  while :; do
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$url" || true)" == "200" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

wait_file() {
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

agent_status() {
  local agent_id=$1
  curl -sS --max-time 5 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${ADMIN_URL}/api/v1/agents" 2>/dev/null \
    | "$PYTHON" -c '
import json, sys
agent = sys.argv[1]
try:
    data = json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit(0)
for item in data if isinstance(data, list) else []:
    if item.get("agent_id") == agent:
        print(item.get("status", ""))
        break
' "$agent_id"
}

wait_agent_status() {
  local agent_id=$1 expected=$2 timeout=$3
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local status
  while :; do
    status=$(agent_status "$agent_id" || true)
    if [[ "$status" == "$expected" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      LAST_STATUS=$status
      return 1
    fi
    sleep 0.2
  done
}

add_agent_token() {
  local name=$1 out token
  out=$("$HUB_BIN" agent add --config "$HUB_CFG" --name "$name") \
    || die "agent add --name $name 失败"
  token=$(printf '%s\n' "$out" \
    | awk '/一次性 token/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}')
  [[ "$token" =~ ^[0-9a-f]{64}$ ]] || die "无法从 agent add 输出解析 token: $out"
  printf '%s' "$token"
}

# 替换或追加一个 TOML 表（从第一个 [control] 开始截断，再把新表追加到末尾）。
set_control_table() {
  local path=$1 section_file=$2
  "$PYTHON" - "$path" "$section_file" <<'PY'
import sys

path, section_path = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
marker = "[control]"
index = text.find(marker)
if index != -1:
    text = text[:index]
section = open(section_path, encoding="utf-8").read().strip()
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text.rstrip() + "\n\n" + section + "\n")
PY
  chmod 600 "$path"
}

write_base_agent_config() {
  local path=$1 name=$2 token=$3 data=$4
  mkdir -p "$data"
  chmod 700 "$data"
  cat > "$path" <<EOF
hub_url = "wss://127.0.0.1:${AGENT_PORT}/agent/ws"
token = "${token}"
server_fingerprint = "${FPR}"
name = "${name}"
data_dir = "${data}"
sample_interval_ms = 1000
buffer_max_bytes = 10485760
EOF
  chmod 600 "$path"
}

write_hub_control() {
  local enabled=$1 systemd=$2 docker=$3 process=$4 logs=$5
  cat > "$TMP_DIR/hub-control.toml" <<EOF
[control]
enabled = ${enabled}
systemd = ${systemd}
docker = ${docker}
process = ${process}
logs = ${logs}
request_timeout_ms = 15000
max_pending_per_session = 32
max_output_bytes = 262144
EOF
  set_control_table "$HUB_CFG" "$TMP_DIR/hub-control.toml"
}

start_hub() {
  RUST_LOG=rustboard_hub=info "$HUB_BIN" run --config "$HUB_CFG" >> "$HUB_LOG" 2>&1 &
  HUB_PID=$!
  PIDS+=("$HUB_PID")
  wait_health "$ADMIN_URL/healthz" 20 || die "hub 未在 20s 内就绪"
}

stop_hub() {
  if [[ -n "${HUB_PID:-}" ]]; then
    kill -9 "$HUB_PID" 2>/dev/null || true
    wait "$HUB_PID" 2>/dev/null || true
    HUB_PID=""
  fi
}

start_agent() {
  local cfg=$1 log=$2 data=$3
  RUST_LOG=rustboard_agent=info "$AGENT_BIN" run --config "$cfg" > "$log" 2>&1 &
  local pid=$!
  PIDS+=("$pid")
  wait_file "$data/agent_id" 20 || die "agent 未在 20s 内完成 enrollment（$(basename "$log")）"
  printf '%s' "$pid"
}

# ---------------------------------------------------------------------------
# 构建与 fake 工具
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub / rustboard-agent / rustboard-panel"
(cd "$ROOT" && "$CARGO" build --locked \
  -p rustboard-hub -p rustboard-agent -p rustboard-panel) \
  || die "cargo build 失败"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
HUB_BIN="$TARGET_DIR/debug/rustboard-hub"
AGENT_BIN="$TARGET_DIR/debug/rustboard-agent"
PANEL_BIN="$TARGET_DIR/debug/rustboard-panel"
[[ -x "$HUB_BIN" ]] || die "找不到 $HUB_BIN"
[[ -x "$AGENT_BIN" ]] || die "找不到 $AGENT_BIN"
[[ -x "$PANEL_BIN" ]] || die "找不到 $PANEL_BIN"

echo "==> 生成 fake systemctl / docker / journalctl"
cat > "$FAKE_DIR/systemctl" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >> "${SYSTEMCTL_LOG}"
if [ "\$1" = "list-units" ]; then
  cat <<'OUT'
nginx.service loaded active running A high performance web server
nginx-worker.service loaded active running nginx worker process
db.service loaded active running Database
sshd.service loaded active running OpenSSH server
systemd-journald.service loaded active running Journal service
OUT
  exit 0
fi
echo "fake-systemctl \$*"
exit 0
EOF
chmod 0755 "$FAKE_DIR/systemctl"

cat > "$FAKE_DIR/docker" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >> "${DOCKER_LOG}"
if [ "\$1" = "ps" ]; then
  printf 'web-1\\tnginx:1.27\\trunning\\tUp 2 hours\\t1111111111111111\\n'
  printf 'web-2\\tredis:7\\texited\\tExited (0) 1 hour ago\\t2222222222222222\\n'
  printf 'db-1\\tpostgres:16\\trunning\\tUp 1 hour\\t3333333333333333\\n'
  exit 0
fi
echo "fake-docker \$*"
exit 0
EOF
chmod 0755 "$FAKE_DIR/docker"

cat > "$FAKE_DIR/journalctl" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >> "${JOURNAL_LOG}"
printf '2026-10-23T00:00:01+0000 fake nginx line one\\n'
printf '2026-10-23T00:00:02+0000 fake nginx line two\\n'
exit 0
EOF
chmod 0755 "$FAKE_DIR/journalctl"

printf 'line-1\nline-2\nline-3\n' > "$NGINX_LOG"
ln -s /etc/passwd "$SYMLINK_LOG"

# ---------------------------------------------------------------------------
# 初始化 hub/agent/panel
# ---------------------------------------------------------------------------

AGENT_PORT=$(pick_port)
ADMIN_PORT=$(pick_port)
PANEL_PORT=$(pick_port)
while [[ "$ADMIN_PORT" == "$AGENT_PORT" || "$PANEL_PORT" == "$AGENT_PORT" || "$PANEL_PORT" == "$ADMIN_PORT" ]]; do
  ADMIN_PORT=$(pick_port)
  PANEL_PORT=$(pick_port)
done

ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}"
PANEL_URL="http://127.0.0.1:${PANEL_PORT}"
CA="$HUB_DATA/certs/ca.crt"

echo "==> 初始化 hub（agent=${AGENT_PORT} admin=${ADMIN_PORT}）"
"$HUB_BIN" init \
  --config "$HUB_CFG" \
  --data-dir "$HUB_DATA" \
  --agent-listen "127.0.0.1:${AGENT_PORT}" \
  --admin-listen "127.0.0.1:${ADMIN_PORT}" \
  --force > "$TMP_DIR/init.log" 2>&1 || die "hub init 失败（见 $TMP_DIR/init.log）"

sed -i 's/^self_monitor = true$/self_monitor = false/' "$HUB_CFG"
sed -i 's/^sample_interval_ms = 5000$/sample_interval_ms = 1000/' "$HUB_CFG"
# 控制面用例会连续 POST；关闭管理写限速，避免第 11 次起被 429 干扰业务断言。
if ! grep -q '^admin_write_rate_limit_per_min' "$HUB_CFG"; then
  printf '\nadmin_write_rate_limit_per_min = 0\n' >> "$HUB_CFG"
fi
[[ -f "$CA" ]] || die "缺少 CA 证书: $CA"

ADMIN_TOKEN=$(cfg_str "$HUB_CFG" admin_token) || die "无法解析 hub admin_token"
[[ -n "$ADMIN_TOKEN" ]] || die "hub 配置缺少 admin_token"
FPR=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p')
[[ "$FPR" =~ ^[0-9a-f]{64}$ ]] || die "无法读取服务端证书指纹: $FPR"

write_hub_control true true true true true
start_hub

A_TOKEN=$(add_agent_token "control-a")
B_TOKEN=$(add_agent_token "control-b")
C_TOKEN=$(add_agent_token "control-c")

write_base_agent_config "$A_CFG" "control-a" "$A_TOKEN" "$A_DATA"
write_base_agent_config "$B_CFG" "control-b" "$B_TOKEN" "$B_DATA"
write_base_agent_config "$C_CFG" "control-c" "$C_TOKEN" "$C_DATA"

cat > "$TMP_DIR/control-a.toml" <<EOF
[control]
enabled = true
systemd = true
docker = true
process = true
logs = true
systemd_units = ["nginx*"]
docker_containers = ["web-*"]
command_timeout_secs = 10
max_log_lines = 200
systemctl_path = "${FAKE_DIR}/systemctl"
docker_path = "${FAKE_DIR}/docker"
journalctl_path = "${FAKE_DIR}/journalctl"

[[control.log_sources]]
id = "nginx-file"
kind = "file"
target = "${NGINX_LOG}"
name = "Nginx file"

[[control.log_sources]]
id = "nginx-journal"
kind = "journal"
target = "nginx.service"
name = "Nginx journal"
EOF
set_control_table "$A_CFG" "$TMP_DIR/control-a.toml"

# C：agent 侧关闭 systemd，但开启 docker/process/logs；用于「能力未上报」。
cat > "$TMP_DIR/control-c.toml" <<EOF
[control]
enabled = true
systemd = false
docker = true
process = true
logs = true
docker_containers = ["web-*"]
command_timeout_secs = 10
max_log_lines = 200
systemctl_path = "${FAKE_DIR}/systemctl"
docker_path = "${FAKE_DIR}/docker"
journalctl_path = "${FAKE_DIR}/journalctl"

[[control.log_sources]]
id = "nginx-file"
kind = "file"
target = "${NGINX_LOG}"
name = "Nginx file"
EOF
set_control_table "$C_CFG" "$TMP_DIR/control-c.toml"

# B 保持旧式配置：完全没有 [control]，模拟 v0.2 agent。

echo "==> 启动 agent A（全能力）/ B（旧式）/ C（缺 systemd）"
A_PID=$(start_agent "$A_CFG" "$A_LOG" "$A_DATA")
B_PID=$(start_agent "$B_CFG" "$B_LOG" "$B_DATA")
C_PID=$(start_agent "$C_CFG" "$C_LOG" "$C_DATA")
A_ID=$(tr -d '[:space:]' < "$A_DATA/agent_id")
B_ID=$(tr -d '[:space:]' < "$B_DATA/agent_id")
C_ID=$(tr -d '[:space:]' < "$C_DATA/agent_id")
[[ -n "$A_ID" && -n "$B_ID" && -n "$C_ID" ]] || die "agent_id 为空"

wait_agent_status "$A_ID" online 20 || die "agent A 未 online"
wait_agent_status "$B_ID" online 20 || die "agent B 未 online"
wait_agent_status "$C_ID" online 20 || die "agent C 未 online"

# ---------------------------------------------------------------------------
# 1. 能力状态 / 旧式 agent / agent 侧关闭能力
# ---------------------------------------------------------------------------

echo
echo "==> 1) 能力状态"
api GET "/api/v1/agents/${A_ID}/control"
expect_status "1.1 A 控制状态 200" 200
check_eq "1.2 control_enabled=true" "True" "$(json_get 'd.get("control_enabled")')"
check_eq "1.3 online=true" "True" "$(json_get 'd.get("online")')"
CAPS=$(json_get '",".join(sorted(d.get("capabilities", [])))')
HCAPS=$(json_get '",".join(sorted(d.get("hub_capabilities", [])))')
check_eq "1.4 A 上报四项能力" "docker,logs,process,systemd" "$CAPS"
check_eq "1.5 hub 开启四项能力" "docker,logs,process,systemd" "$HCAPS"

api GET "/api/v1/agents/${B_ID}/control"
expect_status "1.6 旧式 agent 状态 200" 200
check_eq "1.7 旧式 agent 能力为空" "" "$(json_get '",".join(d.get("capabilities", []))')"
api POST "/api/v1/agents/${B_ID}/control" '{"capability":"systemd","action":"list"}'
expect_status "1.8 旧式 agent 控制请求 403" 403
expect_error_code "1.9 旧式 agent capability_disabled" "capability_disabled"

api GET "/api/v1/agents/${C_ID}/control"
expect_status "1.10 C 控制状态 200" 200
check_eq "1.11 C 缺 systemd" "docker,logs,process" "$(json_get '",".join(sorted(d.get("capabilities", [])))')"
api POST "/api/v1/agents/${C_ID}/control" '{"capability":"systemd","action":"list"}'
expect_status "1.12 C 请求未开启能力 403" 403
expect_error_code "1.13 C capability_disabled" "capability_disabled"

# ---------------------------------------------------------------------------
# 2. systemd
# ---------------------------------------------------------------------------

echo
echo "==> 2) systemd 白名单"
api POST "/api/v1/agents/${A_ID}/control" '{"capability":"systemd","action":"list"}'
expect_status "2.1 systemd list 200" 200
check_eq "2.2 list ok" "True" "$(json_get 'd.get("ok")')"
check_eq "2.3 result 类型" "systemd_units" "$(json_get 'd.get("result",{}).get("type")')"
UNITS=$(json_get '",".join(sorted(u.get("unit","") for u in d.get("result",{}).get("units", [])))')
check_eq "2.4 只返回白名单 unit" "nginx-worker.service,nginx.service" "$UNITS"
check_contains "2.5 fake systemctl 参数" "$(cat "$SYSTEMCTL_LOG" 2>/dev/null || true)" "list-units --type=service --all --no-legend --no-pager --plain"

api POST "/api/v1/agents/${A_ID}/control" \
  '{"capability":"systemd","action":"restart","target":"nginx.service","confirm":true}'
expect_status "2.6 restart nginx 200" 200
check_eq "2.7 restart ok" "True" "$(json_get 'd.get("ok")')"
check_eq "2.8 action_output 类型" "action_output" "$(json_get 'd.get("result",{}).get("type")')"
check_eq "2.9 restart exit_code=0" "0" "$(json_get 'd.get("result",{}).get("exit_code")')"
check_contains "2.10 fake systemctl 收到 restart" "$(cat "$SYSTEMCTL_LOG" 2>/dev/null || true)" "restart nginx.service"

api POST "/api/v1/agents/${A_ID}/control" \
  '{"capability":"systemd","action":"restart","target":"unrelated.service","confirm":true}'
expect_status "2.11 非白名单 unit 403" 403
expect_error_code "2.12 not_whitelisted" "not_whitelisted"
check_not_contains "2.13 越权 unit 未执行命令" "$(cat "$SYSTEMCTL_LOG" 2>/dev/null || true)" "restart unrelated.service"

api POST "/api/v1/agents/${A_ID}/control" \
  '{"capability":"systemd","action":"restart","target":"sshd.service","confirm":true}'
expect_status "2.14 禁止 unit 403" 403
check_not_contains "2.15 禁止 unit 未执行命令" "$(cat "$SYSTEMCTL_LOG" 2>/dev/null || true)" "restart sshd.service"

# ---------------------------------------------------------------------------
# 3. docker
# ---------------------------------------------------------------------------

echo
echo "==> 3) Docker 白名单"
api POST "/api/v1/agents/${A_ID}/control" '{"capability":"docker","action":"list"}'
expect_status "3.1 docker list 200" 200
check_eq "3.2 docker result 类型" "docker_containers" "$(json_get 'd.get("result",{}).get("type")')"
CONTAINERS=$(json_get '",".join(sorted(c.get("name","") for c in d.get("result",{}).get("containers", [])))')
check_eq "3.3 只返回白名单容器" "web-1,web-2" "$CONTAINERS"
check_contains "3.4 fake docker ps 参数" "$(cat "$DOCKER_LOG" 2>/dev/null || true)" "ps -a --no-trunc --format"

api POST "/api/v1/agents/${A_ID}/control" \
  '{"capability":"docker","action":"restart","target":"web-1","confirm":true}'
expect_status "3.5 restart web-1 200" 200
check_eq "3.6 docker action 类型" "action_output" "$(json_get 'd.get("result",{}).get("type")')"
check_eq "3.7 docker exit_code=0" "0" "$(json_get 'd.get("result",{}).get("exit_code")')"
check_contains "3.8 fake docker 收到 restart" "$(cat "$DOCKER_LOG" 2>/dev/null || true)" "restart web-1"

api POST "/api/v1/agents/${A_ID}/control" \
  '{"capability":"docker","action":"restart","target":"db-1","confirm":true}'
expect_status "3.9 非白名单容器 403" 403
expect_error_code "3.10 docker not_whitelisted" "not_whitelisted"
check_not_contains "3.11 越权容器未执行命令" "$(cat "$DOCKER_LOG" 2>/dev/null || true)" "restart db-1"

# ---------------------------------------------------------------------------
# 4. 进程
# ---------------------------------------------------------------------------

echo
echo "==> 4) 进程列表 / PID + 名称校验"
sleep 300 &
TEST_PID=$!
PIDS+=("$TEST_PID")
deadline=$(( $(date +%s%3N) + 5000 ))
while [[ ! -r "/proc/${TEST_PID}/comm" ]]; do
  if (( $(date +%s%3N) >= deadline )); then
    die "测试进程 ${TEST_PID} 未就绪"
  fi
  sleep 0.05
done
TEST_NAME=$(tr -d '\n' < "/proc/${TEST_PID}/comm")

api POST "/api/v1/agents/${A_ID}/control" '{"capability":"process","action":"list"}'
expect_status "4.1 process list 200" 200
check_eq "4.2 process result 类型" "processes" "$(json_get 'd.get("result",{}).get("type")')"
if "$PYTHON" - "$BODY" "$TEST_PID" "$TEST_NAME" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
want_pid = int(sys.argv[2])
want_name = sys.argv[3]
processes = data.get("result", {}).get("processes", [])
if any(int(p.get("pid", -1)) == want_pid and p.get("name") == want_name for p in processes):
    raise SystemExit(0)
raise SystemExit(1)
PY
then
  pass "4.3 进程列表包含测试进程 PID=${TEST_PID} name=${TEST_NAME}"
else
  fail "4.3 进程列表缺少测试进程 PID=${TEST_PID} name=${TEST_NAME}"
fi

api POST "/api/v1/agents/${A_ID}/control" \
  "{\"capability\":\"process\",\"action\":\"kill\",\"pid\":${TEST_PID},\"name\":\"definitely-not-${TEST_NAME}\",\"signal\":\"term\",\"confirm\":true}"
expect_status_in "4.4 错误名称 kill 被拒" 400 403
if kill -0 "$TEST_PID" 2>/dev/null; then
  pass "4.5 错误名称未发送信号，进程仍存活"
else
  fail "4.5 错误名称 kill 误杀了进程 ${TEST_PID}"
fi

api POST "/api/v1/agents/${A_ID}/control" \
  "{\"capability\":\"process\",\"action\":\"kill\",\"pid\":${TEST_PID},\"name\":\"${TEST_NAME}\",\"signal\":\"term\",\"confirm\":true}"
expect_status "4.6 正确名称 kill 200" 200
deadline=$(( $(date +%s%3N) + 5000 ))
GONE=0
while (( $(date +%s%3N) < deadline )); do
  if ! kill -0 "$TEST_PID" 2>/dev/null; then
    GONE=1
    break
  fi
  sleep 0.05
done
if (( GONE == 1 )); then
  pass "4.7 正确名称进程已退出"
else
  fail "4.7 正确名称进程未退出"
fi

api POST "/api/v1/agents/${A_ID}/control" \
  '{"capability":"process","action":"kill","pid":1,"name":"systemd","signal":"term","confirm":true}'
expect_status_in "4.8 PID 1 被拒绝" 400 403

# ---------------------------------------------------------------------------
# 5. 日志
# ---------------------------------------------------------------------------

echo
echo "==> 5) 日志 list / tail / 逃逸"
api POST "/api/v1/agents/${A_ID}/control" '{"capability":"logs","action":"list"}'
expect_status "5.1 logs list 200" 200
check_eq "5.2 logs result 类型" "log_sources" "$(json_get 'd.get("result",{}).get("type")')"
SOURCES=$(json_get '",".join(sorted(s.get("id","") for s in d.get("result",{}).get("sources", [])))')
check_eq "5.3 日志来源 id" "nginx-file,nginx-journal" "$SOURCES"

api POST "/api/v1/agents/${A_ID}/control" \
  '{"capability":"logs","action":"tail","source":"nginx-file","lines":2}'
expect_status "5.4 file tail 200" 200
check_eq "5.5 file tail 类型" "log_lines" "$(json_get 'd.get("result",{}).get("type")')"
LINES=$(json_get '"|".join(d.get("result",{}).get("lines", []))')
check_contains "5.6 file tail 包含最后一行" "$LINES" "line-3"
check_contains "5.7 file tail 包含倒数第二行" "$LINES" "line-2"
check_not_contains "5.8 file tail 未返回更早的行" "$LINES" "line-1"

for BAD_SOURCE in "../../etc/passwd" "/etc/passwd" "..%2f..%2fetc%2fpasswd"; do
  api POST "/api/v1/agents/${A_ID}/control" \
    "{\"capability\":\"logs\",\"action\":\"tail\",\"source\":\"${BAD_SOURCE}\",\"lines\":10}"
  expect_status_in "5.9 日志路径逃逸被拒（${BAD_SOURCE}）" 400 403 404
  check_not_contains "5.10 响应不含 /etc/passwd 内容（${BAD_SOURCE}）" "$BODY" "root:"
done

api POST "/api/v1/agents/${A_ID}/control" \
  '{"capability":"logs","action":"tail","source":"nginx-journal","lines":50}'
expect_status "5.11 journal tail 200" 200
JOURNAL_ARGS=$(cat "$JOURNAL_LOG" 2>/dev/null || true)
check_contains "5.12 journalctl 使用 -u" "$JOURNAL_ARGS" "-u nginx.service"
check_contains "5.13 journalctl 使用 -n 50" "$JOURNAL_ARGS" "-n 50"
check_contains "5.14 journalctl 禁 pager" "$JOURNAL_ARGS" "--no-pager"
check_contains "5.15 journalctl 输出格式" "$JOURNAL_ARGS" "short-iso"

# 启动期符号链接拒绝：单独 agent，logs 文件指向 ./evil-link -> /etc/passwd。
D_TOKEN=$(add_agent_token "control-d")
write_base_agent_config "$D_CFG" "control-d" "$D_TOKEN" "$D_DATA"
cat > "$TMP_DIR/control-d.toml" <<EOF
[control]
enabled = true
systemd = false
docker = false
process = false
logs = true
command_timeout_secs = 10
max_log_lines = 200
journalctl_path = "${FAKE_DIR}/journalctl"

[[control.log_sources]]
id = "evil-link"
kind = "file"
target = "${SYMLINK_LOG}"
name = "Symlink"
EOF
set_control_table "$D_CFG" "$TMP_DIR/control-d.toml"
set +e
timeout 15 "$AGENT_BIN" run --config "$D_CFG" > "$D_LOG" 2>&1
D_RC=$?
set -e
if (( D_RC != 0 )); then
  pass "5.16 符号链接日志源启动失败（rc=${D_RC}）"
else
  fail "5.16 符号链接日志源仍能启动"
fi
if grep -Eiq 'symbolic|symlink|符号链接' "$D_LOG"; then
  pass "5.17 符号链接错误可读"
else
  fail "5.17 启动日志未说明符号链接"
fi

# ---------------------------------------------------------------------------
# 6. 审计
# ---------------------------------------------------------------------------

echo
echo "==> 6) 审计写入 / 分页 / 过滤"
api GET "/api/v1/audit?limit=2"
expect_status "6.1 audit 分页 200" 200
AUDIT_LEN=$(json_get 'len(d.get("entries", []))')
check_eq "6.2 limit=2" "2" "$AUDIT_LEN"
NEXT_ID=$(json_get 'd.get("next_before_id")')
if [[ "$NEXT_ID" =~ ^[0-9]+$ ]]; then
  pass "6.3 next_before_id=$NEXT_ID"
  api GET "/api/v1/audit?limit=2&before_id=${NEXT_ID}"
  expect_status "6.4 before_id 分页 200" 200
  if "$PYTHON" - "$BODY" "$NEXT_ID" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
before = int(sys.argv[2])
ids = [int(e.get("id", 0)) for e in data.get("entries", [])]
if ids and all(i < before for i in ids):
    raise SystemExit(0)
raise SystemExit(1)
PY
  then
    pass "6.5 第二页 id 均小于 before_id"
  else
    fail "6.5 第二页 id 未按 before_id 过滤"
  fi
else
  fail "6.3 next_before_id 缺失或非法: [$NEXT_ID]"
fi

api GET "/api/v1/audit?limit=50&capability=systemd"
expect_status "6.6 capability 过滤 200" 200
if "$PYTHON" - "$BODY" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
entries = data.get("entries", [])
if entries and all(e.get("capability") == "systemd" for e in entries):
    raise SystemExit(0)
raise SystemExit(1)
PY
then
  pass "6.7 capability 过滤只返回 systemd"
else
  fail "6.7 capability 过滤包含其它能力"
fi

api GET "/api/v1/audit?limit=50&agent_id=${A_ID}"
expect_status "6.8 agent_id 过滤 200" 200
if "$PYTHON" - "$BODY" "$A_ID" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
agent = sys.argv[2]
entries = data.get("entries", [])
if entries and all(e.get("agent_id") == agent for e in entries):
    raise SystemExit(0)
raise SystemExit(1)
PY
then
  pass "6.9 agent_id 过滤正确"
else
  fail "6.9 agent_id 过滤错误"
fi

# 成功 / 拒绝的审计结果与 actor。
api GET "/api/v1/audit?limit=100&capability=systemd"
if "$PYTHON" - "$BODY" <<'PY'
import json, sys
entries = json.loads(sys.argv[1]).get("entries", [])
results = {e.get("result") for e in entries}
codes = {e.get("error_code") for e in entries if e.get("result") != "ok"}
actors = {e.get("actor") for e in entries}
if "ok" not in results or "denied" not in results:
    raise SystemExit(1)
if "not_whitelisted" not in codes:
    raise SystemExit(2)
if actors != {"admin"}:
    raise SystemExit(3)
PY
then
  AUDIT_RC=0
else
  AUDIT_RC=$?
fi
if (( AUDIT_RC == 0 )); then
  pass "6.10 审计含 ok/denied/not_whitelisted，actor=admin"
else
  fail "6.10 审计结果/actor 不符（rc=${AUDIT_RC}）"
fi

# ---------------------------------------------------------------------------
# 7. 面板代理 + 审计 actor
# ---------------------------------------------------------------------------

echo
echo "==> 7) 面板控制代理"
PANEL_PASSWORD="Control-E2E-$(date +%s)-pw"
"$PANEL_BIN" init \
  --config "$PANEL_CFG" \
  --listen "127.0.0.1:${PANEL_PORT}" \
  --hub "$ADMIN_URL" \
  --hub-token "$ADMIN_TOKEN" \
  --password "$PANEL_PASSWORD" \
  --force > "$TMP_DIR/panel-init.log" 2>&1 || die "panel init 失败（见 $TMP_DIR/panel-init.log）"

RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$PANEL_CFG" > "$PANEL_LOG" 2>&1 &
PANEL_PID=$!
PIDS+=("$PANEL_PID")
wait_health "$PANEL_URL/healthz" 20 || die "panel 未在 20s 内就绪"

rm -f "$PANEL_JAR"
LOGIN_STATUS=$(curl -sS --max-time 15 -o "$HTTP_BODY_FILE" -w '%{http_code}' \
  -X POST "$PANEL_URL/api/login" \
  -c "$PANEL_JAR" -H 'Content-Type: application/json' -H "Origin: $PANEL_URL" \
  --data-binary "{\"password\":\"${PANEL_PASSWORD}\"}" 2>"$TMP_DIR/curl.err") || LOGIN_STATUS="000"
STATUS=$LOGIN_STATUS
BODY=$(cat "$HTTP_BODY_FILE" 2>/dev/null || true)
expect_status "7.1 面板登录 204" 204
if [[ -s "$PANEL_JAR" ]] && grep -q 'rb_session' "$PANEL_JAR"; then
  pass "7.2 登录写入 rb_session Cookie"
else
  fail "7.2 登录未写入会话 Cookie"
fi

panel_api GET "/api/agents/${A_ID}/control"
expect_status "7.3 面板读取控制状态 200" 200
check_eq "7.4 面板状态 control_enabled" "True" "$(json_get 'd.get("control_enabled")')"

panel_api POST "/api/agents/${A_ID}/control" \
  '{"capability":"systemd","action":"restart","target":"nginx.service","confirm":true}'
expect_status "7.5 面板 restart nginx 200" 200
check_eq "7.6 面板代理 restart ok" "True" "$(json_get 'd.get("ok")')"

panel_api GET "/api/audit?limit=1&capability=systemd"
expect_status "7.7 面板审计 200" 200
check_eq "7.8 面板审计 actor=admin" "admin" "$(json_get 'd.get("entries",[{}])[0].get("actor")')"
check_eq "7.9 面板审计 action=restart" "restart" "$(json_get 'd.get("entries",[{}])[0].get("action")')"
check_eq "7.10 面板审计 target=nginx.service" "nginx.service" "$(json_get 'd.get("entries",[{}])[0].get("target")')"

# ---------------------------------------------------------------------------
# 8. 离线 503 / hub 能力关闭 / hub 总开关关闭
# ---------------------------------------------------------------------------

echo
echo "==> 8) 离线与能力关闭"
kill -9 "$C_PID" 2>/dev/null || true
wait "$C_PID" 2>/dev/null || true
wait_agent_status "$C_ID" offline 10 || true
api POST "/api/v1/agents/${C_ID}/control" '{"capability":"docker","action":"list"}'
expect_status "8.1 离线 agent 503" 503
expect_error_code "8.2 agent_offline" "agent_offline"

echo "==> 重启 hub：关闭 docker 能力（其余保持）"
stop_hub
write_hub_control true true false true true
start_hub
wait_agent_status "$A_ID" online 20 || die "hub 重启后 agent A 未 online"
api GET "/api/v1/agents/${A_ID}/control"
expect_status "8.3 hub 能力关闭后状态 200" 200
check_eq "8.4 hub_capabilities 不含 docker" "logs,process,systemd" "$(json_get '",".join(sorted(d.get("hub_capabilities", [])))')"
api POST "/api/v1/agents/${A_ID}/control" '{"capability":"docker","action":"list"}'
expect_status "8.5 hub 关闭 docker 后 403" 403
expect_error_code "8.6 hub capability_disabled" "capability_disabled"
api POST "/api/v1/agents/${A_ID}/control" '{"capability":"systemd","action":"list"}'
expect_status "8.7 未关闭的 systemd 仍可用" 200

echo "==> 重启 hub：关闭控制面总开关"
stop_hub
write_hub_control false false false false false
start_hub
wait_agent_status "$A_ID" online 20 || die "hub 再次重启后 agent A 未 online"
api GET "/api/v1/agents/${A_ID}/control"
expect_status "8.8 总开关关闭状态 200" 200
check_eq "8.9 control_enabled=false" "False" "$(json_get 'd.get("control_enabled")')"
api POST "/api/v1/agents/${A_ID}/control" '{"capability":"systemd","action":"list"}'
expect_status "8.10 总开关关闭 403" 403
expect_error_code "8.11 hub control capability_disabled" "capability_disabled"

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

echo
if (( FAILS > 0 )); then
  echo "control e2e 结果: ${PASSES} 项通过，${FAILS} 项失败" >&2
  exit 1
fi
echo "control e2e 结果: 全部 ${PASSES} 项通过"
