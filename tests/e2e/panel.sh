#!/usr/bin/env bash
#
# RustBoard M2 面板端到端回归。
# 方案：docs/plans/2026-10-23-m2-panel.md §3（接口契约）、§5/§6（行为）、§11（测试点）。
#
# 覆盖：
#   1. hub init 生成 admin_token；/healthz 免鉴权；/api/v1/agents 缺/错/对 token 的 401/200；
#   2. agent add + 启动 agent，online 且样本数 > 0；
#   3. panel init（固定密码）→ 配置 0600、Argon2id PHC；启动后面板 /healthz、SPA HTML、
#      未登录 /api/* 为 401 JSON；
#   4. 登录：错误密码 401；连续 5 次失败后正确密码 429（独立 panel 进程，不等待 15 分钟）；
#      正确密码 204 + rb_session Cookie 属性；带 Cookie /api/session=true、/api/overview=200；
#   5. series 多指标、bucket_ms、points 形状/上限；非法参数（from>=to、>32d、非法 metric、
#      21 个 metric）均为 400；
#   6. settings 默认值、PUT 10000 生效、agent 日志 60s 内出现 `采样间隔已更新 ms=10000`、
#      重连后 online 且数据继续增长；999/300001/非数字 400；不存在的 agent 404；
#   7. 静态 HTML/JS 不含 admin token 或明文密码；`..` / `%2e%2e` 路径穿透被拒；
#      未知 /api/* 始终 JSON；
#   8. 登出后 /api/session=false，旧 Cookie 不能再访问 /api/overview；
#   9. 默认 listen 只绑 127.0.0.1（未显式 --listen）；显式 static_dir 无效时拒绝启动；
#  10. 设置假 HTTP_PROXY/ALL_PROXY 启动面板：/api/* 仍直连 hub，假代理收不到任何连接；
#      `/api/*` Content-Type 恒为 application/json，页面与 API 均带 CSP 安全头。
#
# 自己构建三个 bin，在 127.0.0.1 的随机空闲端口与 mktemp 临时目录中运行；失败时打印
# hub/panel/agent 日志尾部（已脱敏），结束后清理进程与目录。
#
# 依赖：bash 4.4+、python3 3.8+（仅标准库）、cargo/rustc、GNU timeout/stat/date。
# 前端静态资源需预先构建：web/dist/index.html（本脚本不执行 pnpm build）。
# 用法：bash tests/e2e/panel.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/panel.sh   # 保留临时目录与日志
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PROBE="$SCRIPT_DIR/panel_probe.py"
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}

# 按任务约定固定使用这套 cargo/rustup 环境。
export PATH="/tmp/cargo/bin:${PATH}"
export CARGO_HOME=/tmp/cargo
export RUSTUP_HOME=/tmp/rustup

PASSES=0
FAILS=0
LAST_STATUS=""
PIDS=()

HUB_PID=""
AGENT_PID=""
PANEL_PID=""
RATE_PID=""
BADTOKEN_PID=""
PROXY_PID=""
NO_PROXY_PID=""

ADMIN_TOKEN=""
ENROLL_TOKEN=""
WRONG_HUB_TOKEN=""
PASSWORD='RustBoard-E2E-Password-2026'
WRONG_PASSWORD='RustBoard-E2E-Wrong-Password-2026'
HUB_URL=""
PANEL_URL=""
RATE_URL=""
BADTOKEN_URL=""
NO_PROXY_URL=""
A_ID=""
HUB_INTERVAL=""
HUB_BIN=""
AGENT_BIN=""
PANEL_BIN=""
STATIC_DIR="$ROOT/web/dist"
EXPECTED_CSP="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"

pass() {
  local id=$1
  shift
  PASSES=$((PASSES + 1))
  echo "PASS [$id] $*"
}

fail() {
  local id=$1
  shift
  FAILS=$((FAILS + 1))
  echo "FAIL [$id] $*" >&2
}

die() {
  echo "FATAL: $*" >&2
  exit 1
}

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-panel-e2e.XXXXXX")
HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
HUB_INIT_LOG="$TMP_DIR/hub-init.log"
EMPTY_CFG="$TMP_DIR/hub-empty-token.toml"
EMPTY_LOG="$TMP_DIR/hub-empty-token.log"
AGENT_CFG="$TMP_DIR/agent.toml"
AGENT_DATA="$TMP_DIR/agent"
AGENT_LOG="$TMP_DIR/agent.log"
AGENT_ADD_LOG="$TMP_DIR/agent-add.log"
PANEL_CFG="$TMP_DIR/panel.toml"
PANEL_LOG="$TMP_DIR/panel.log"
PANEL_INIT_LOG="$TMP_DIR/panel-init.log"
RATE_CFG="$TMP_DIR/panel-rate.toml"
RATE_LOG="$TMP_DIR/panel-rate.log"
RATE_INIT_LOG="$TMP_DIR/panel-rate-init.log"
BAD_CFG="$TMP_DIR/panel-badtoken.toml"
BAD_LOG="$TMP_DIR/panel-badtoken.log"
BAD_INIT_LOG="$TMP_DIR/panel-badtoken-init.log"
NO_PROXY_CFG="$TMP_DIR/panel-noproxy.toml"
NO_PROXY_LOG="$TMP_DIR/panel-noproxy.log"
NO_PROXY_INIT_LOG="$TMP_DIR/panel-noproxy-init.log"
NO_PROXY_COOKIE_FILE="$TMP_DIR/session-noproxy.cookie"
NO_PROXY_OVERVIEW="$TMP_DIR/noproxy-overview.json"
PROXY_LOG="$TMP_DIR/proxy.log"
PROXY_READY="$TMP_DIR/proxy.ready"
PROXY_HITS="$TMP_DIR/proxy.hits"
BAD_STATIC_CFG="$TMP_DIR/panel-bad-static.toml"
BAD_STATIC_LOG="$TMP_DIR/panel-bad-static.log"
BAD_STATIC_INIT_LOG="$TMP_DIR/panel-bad-static-init.log"
BUILD_LOG="$TMP_DIR/build.log"
COOKIE_FILE="$TMP_DIR/session.cookie"
XFP_COOKIE_FILE="$TMP_DIR/session-xfp.cookie"
BAD_COOKIE_FILE="$TMP_DIR/session-badtoken.cookie"
INDEX_HTML="$TMP_DIR/index.html"
LOGIN_HTML="$TMP_DIR/login.html"
AGENTS_HTML="$TMP_DIR/agents.html"
ASSET_LIST="$TMP_DIR/assets.list"
OVERVIEW_BODY="$TMP_DIR/overview.json"
SERIES_BODY="$TMP_DIR/series.json"
SETTINGS_BODY="$TMP_DIR/settings.json"
HUB_SETTINGS_BODY="$TMP_DIR/hub-settings.json"
BAD_OVERVIEW_BODY="$TMP_DIR/bad-overview.json"
SESSION_AFTER_LOGOUT="$TMP_DIR/session-after-logout.json"
TRAVERSAL_BODY="$TMP_DIR/traversal.body"
mkdir -p "$TMP_DIR/assets"

# 日志里如果意外出现 secret/token，打印现场时先脱敏；扫描断言会单独报失败。
dump_redacted() {
  local file=$1
  local lines=${2:-120}
  [[ -f "$file" ]] || return 0
  "$PYTHON" - "$file" "$lines" "${ADMIN_TOKEN:-}" "${PASSWORD:-}" \
    "${WRONG_PASSWORD:-}" "${ENROLL_TOKEN:-}" "${WRONG_HUB_TOKEN:-}" <<'PY'
import sys

path, lines = sys.argv[1], int(sys.argv[2])
try:
    with open(path, encoding="utf-8", errors="replace") as handle:
        text = handle.read()
except OSError:
    raise SystemExit(0)
for secret in sys.argv[3:]:
    if secret:
        text = text.replace(secret, "<redacted>")
for line in text.splitlines()[-lines:]:
    print(line)
PY
}

cleanup() {
  local code=$?
  local pid
  trap - EXIT

  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    kill -9 "$pid" 2>/dev/null || true
  done
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    wait "$pid" 2>/dev/null || true
  done

  if (( code != 0 || FAILS > 0 )); then
    echo "===== panel e2e 失败现场（日志已脱敏）=====" >&2
    for log in "$HUB_LOG" "$PANEL_LOG" "$AGENT_LOG" "$RATE_LOG" "$BAD_LOG" \
               "$EMPTY_LOG" "$NO_PROXY_LOG" "$PROXY_LOG" "$BAD_STATIC_LOG" "$BUILD_LOG"; do
      [[ -n "$log" && -s "$log" ]] || continue
      echo "---- $(basename "$log")（tail -n 120）----" >&2
      dump_redacted "$log" 120 >&2 || true
    done
    echo "已通过 $PASSES 项，失败 $FAILS 项" >&2
  fi

  if [[ "${KEEP_E2E_TMP:-0}" == "1" ]]; then
    echo "临时目录已保留: $TMP_DIR" >&2
  else
    # 只删除本脚本 mktemp 出来的目录，避免误删其它路径。
    if [[ -n "${TMP_DIR:-}" && "$TMP_DIR" == "${TMPDIR:-/tmp}"/rustboard-panel-e2e.* ]]; then
      rm -rf -- "$TMP_DIR"
    else
      echo "警告: 临时目录不符合预期，未删除: $TMP_DIR" >&2
    fi
  fi
  exit "$code"
}
trap cleanup EXIT

for tool in "$PYTHON" "$CARGO" env timeout stat mktemp date tail awk sed grep sleep; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "找不到命令: $tool（python3 需 3.8+；cargo 请放进 PATH 或设置 CARGO=...）"
done
[[ -f "$PROBE" ]] || die "缺少 $PROBE"
[[ -f "$STATIC_DIR/index.html" ]] \
  || die "缺少面板静态资源 $STATIC_DIR/index.html；请先在 web/ 执行 pnpm build（panel.sh 不构建前端）"

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

# 一次挑 6 个互不相同的端口。放在同一个 python 进程里选，避免
# `$(...)` 子 shell 丢失已用端口集合、导致多个实例撞端口。
pick_ports() {
  "$PYTHON" - <<'PY'
import random
import socket

chosen = []
while len(chosen) < 6:
    port = random.randint(20000, 64999)
    if port in chosen:
        continue
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", port))
    except OSError:
        continue
    chosen.append(port)
print(" ".join(str(port) for port in chosen))
PY
}

wait_for_file() {
  local file=$1
  local timeout=$2
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
pattern = re.compile(
    r'^\s*' + re.escape(key) + r'\s*=\s*"([^"]*)"\s*(?:#.*)?$'
)
values = []
try:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            match = pattern.match(line)
            if match:
                values.append(match.group(1))
except OSError as exc:
    print(f"读取配置失败 {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)
if len(values) != 1:
    print(f"配置 {path} 中 {key} 出现 {len(values)} 次（期望 1 次）", file=sys.stderr)
    raise SystemExit(1)
print(values[0])
PY
}

cfg_num() {
  "$PYTHON" - "$1" "$2" <<'PY'
import re
import sys

path, key = sys.argv[1], sys.argv[2]
pattern = re.compile(r'^\s*' + re.escape(key) + r'\s*=\s*([0-9]+)\s*(?:#.*)?$')
values = []
try:
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            match = pattern.match(line)
            if match:
                values.append(match.group(1))
except OSError as exc:
    print(f"读取配置失败 {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)
if len(values) != 1:
    print(f"配置 {path} 中 {key} 出现 {len(values)} 次（期望 1 次）", file=sys.stderr)
    raise SystemExit(1)
print(values[0])
PY
}

json_field() {
  "$PYTHON" -c '
import json
import sys

try:
    value = json.load(sys.stdin)
except Exception:
    print("__INVALID__")
    raise SystemExit(0)
for part in sys.argv[1].split("."):
    if isinstance(value, dict) and part in value:
        value = value[part]
    else:
        print("__MISSING__")
        raise SystemExit(0)
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("null")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
else:
    print(value)
' "$1"
}

http_call() {
  local method=$1
  local url=$2
  shift 2
  "$PYTHON" "$PROBE" http --method "$method" --url "$url" "$@"
}

login_call() {
  "$PYTHON" "$PROBE" login "$@"
}

json_file_get() {
  "$PYTHON" "$PROBE" json-get --file "$1" --key "$2"
}

overview_panel() {
  "$PYTHON" "$PROBE" overview --url "$PANEL_URL/api/overview" \
    --cookie-file "$COOKIE_FILE" --agent "$A_ID" "$@"
}

hub_series() {
  local from=$1
  local to=$2
  local extra=${3:-}
  "$PYTHON" "$PROBE" series \
    --url "$HUB_URL/api/v1/agents/$A_ID/series?metric=cpu.usage&metric=mem.used&from=$from&to=$to${extra}" \
    --bearer-env --metric cpu.usage --metric mem.used
}

panel_series() {
  local from=$1
  local to=$2
  shift 2
  local extra=""
  # 第三个位置参数仅当以 & 开头时视为额外 query；其余参数原样转发给 probe。
  if [[ $# -gt 0 && "$1" == \&* ]]; then
    extra=$1
    shift
  fi
  "$PYTHON" "$PROBE" series \
    --url "$PANEL_URL/api/agents/$A_ID/series?metric=cpu.usage&metric=mem.used&from=$from&to=$to${extra}" \
    --cookie-file "$COOKIE_FILE" --metric cpu.usage --metric mem.used "$@"
}

wait_url_status() {
  local url=$1
  local expected=$2
  local timeout=$3
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local out status
  LAST_STATUS=""
  while :; do
    out=$(http_call GET "$url" 2>/dev/null || true)
    status=$(printf '%s' "$out" | json_field status)
    LAST_STATUS=$status
    if [[ "$status" == "$expected" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

wait_agent_status() {
  local expected=$1
  local timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local status
  LAST_STATUS=""
  while :; do
    status=$("$PYTHON" "$PROBE" agents-status \
      --url "$HUB_URL/api/v1/agents" --agent "$A_ID" 2>/dev/null || true)
    LAST_STATUS=$status
    if [[ "$status" == "$expected" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

wait_series_ready() {
  local timeout=$1
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local now out total missing
  LAST_STATUS=""
  while :; do
    now=$(date +%s%3N)
    out=$(hub_series "$((now - 3600000))" "$now" 2>/dev/null || true)
    total=$(printf '%s' "$out" | json_field total_points)
    missing=$(printf '%s' "$out" | json_field missing_count)
    LAST_STATUS="points=${total:-?} missing=${missing:-?}"
    if [[ "$total" =~ ^[0-9]+$ && "$missing" =~ ^[0-9]+$ ]] \
        && (( total > 0 && missing == 0 )); then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.3
  done
}

wait_overview_metrics() {
  local timeout=$1
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local out status cpu mem
  LAST_STATUS=""
  while :; do
    out=$(overview_panel 2>/dev/null || true)
    status=$(printf '%s' "$out" | json_field status)
    cpu=$(printf '%s' "$out" | json_field latest_has_cpu)
    mem=$(printf '%s' "$out" | json_field latest_has_mem)
    LAST_STATUS="status=${status:-?} cpu=${cpu:-?} mem=${mem:-?}"
    if [[ "$status" == "200" && "$cpu" == "true" && "$mem" == "true" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.5
  done
}

wait_series_gt() {
  local baseline=$1
  local timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local now out total
  LAST_STATUS=""
  while :; do
    now=$(date +%s%3N)
    out=$(panel_series "$((now - 3600000))" "$now" 2>/dev/null || true)
    total=$(printf '%s' "$out" | json_field total_points)
    LAST_STATUS="points=${total:-?} baseline=$baseline"
    if [[ "$total" =~ ^[0-9]+$ ]] && (( total > baseline )); then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.5
  done
}

wait_for_log() {
  local file=$1
  local pattern=$2
  local timeout=$3
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  while :; do
    if [[ -f "$file" ]] && grep -Fq -- "$pattern" "$file"; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

start_hub() {
  RUST_LOG=rustboard_hub=info "$HUB_BIN" run --config "$HUB_CFG" >> "$HUB_LOG" 2>&1 &
  HUB_PID=$!
  PIDS+=("$HUB_PID")
}

start_agent() {
  RUST_LOG=rustboard_agent=info "$AGENT_BIN" run --config "$AGENT_CFG" >> "$AGENT_LOG" 2>&1 &
  AGENT_PID=$!
  PIDS+=("$AGENT_PID")
}

stop_pid() {
  local pid=$1
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  local i
  for i in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 断言小工具
# ---------------------------------------------------------------------------

check_status() {
  local id=$1
  local desc=$2
  local expected=$3
  local out=$4
  local actual
  actual=$(printf '%s' "$out" | json_field status)
  if [[ "$actual" == "$expected" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 HTTP $expected，实际 ${actual:-<无响应>}）"
  fi
}

check_json_status() {
  local id=$1
  local desc=$2
  local expected=$3
  local out=$4
  local status ct ok kind
  status=$(printf '%s' "$out" | json_field status)
  ct=$(printf '%s' "$out" | json_field content_type_base)
  ok=$(printf '%s' "$out" | json_field json_ok)
  kind=$(printf '%s' "$out" | json_field json_type)
  if [[ "$status" == "$expected" && "$ct" == "application/json" && "$ok" == "true" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 HTTP $expected JSON，实际 status=${status:-?} ct=${ct:-?} json_ok=${ok:-?} kind=${kind:-?}）"
  fi
}

check_eq() {
  local id=$1
  local desc=$2
  local expected=$3
  local actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望: $expected，实际: ${actual:-<空>}）"
  fi
}

check_true() {
  local id=$1
  local desc=$2
  local actual=$3
  if [[ "$actual" == "true" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（实际: ${actual:-<空>}）"
  fi
}

check_file_mode() {
  local id=$1
  local path=$2
  local expected=$3
  local actual
  actual=$(stat -c '%a' "$path" 2>/dev/null || echo "missing")
  check_eq "$id" "$path 权限" "$expected" "$actual"
}

check_csp() {
  local id=$1
  local desc=$2
  local out=$3
  check_eq "$id" "$desc" "$EXPECTED_CSP" "$(printf '%s' "$out" | json_field csp)"
}

# 假 HTTP 代理：绑定端口后写 ready 文件；任何连接都会被记入 hits 文件并返回 502。
# 用来证明面板没有把带 Bearer token 的 hub 请求发给环境代理。
start_fake_proxy() {
  local port=$1
  local ready=$2
  local hits=$3
  "$PYTHON" - "$port" "$ready" "$hits" >> "$PROXY_LOG" 2>&1 <<'PY' &
import socket
import sys
import time

port = int(sys.argv[1])
ready = sys.argv[2]
hits = sys.argv[3]

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("127.0.0.1", port))
server.listen(16)
server.settimeout(0.2)
with open(ready, "w", encoding="utf-8") as handle:
    handle.write("ready\n")

deadline = time.time() + 120
while time.time() < deadline:
    try:
        conn, addr = server.accept()
    except socket.timeout:
        continue
    except OSError:
        break
    with open(hits, "a", encoding="utf-8") as handle:
        handle.write(f"{addr[0]}:{addr[1]}\n")
    try:
        conn.sendall(
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    finally:
        conn.close()
server.close()
PY
  PROXY_PID=$!
  PIDS+=("$PROXY_PID")
}

scan_files_no_secret() {
  local id=$1
  local desc=$2
  local secret=$3
  shift 3
  local hits=""
  local file
  for file in "$@"; do
    if [[ ! -f "$file" ]]; then
      hits+=" 缺少:$(basename "$file")"
      continue
    fi
    if grep -Fq -- "$secret" "$file"; then
      hits+=" $(basename "$file")"
    fi
  done
  if [[ -n "$hits" ]]; then
    fail "$id" "$desc（命中/异常:$hits）"
  else
    pass "$id" "$desc"
  fi
}

scan_logs_no_secret() {
  local id=$1
  local desc=$2
  local secret=$3
  local hits=""
  local log
  for log in "$HUB_LOG" "$PANEL_LOG" "$AGENT_LOG" "$RATE_LOG" "$BAD_LOG"; do
    [[ -f "$log" ]] || continue
    if grep -Fq -- "$secret" "$log"; then
      hits+=" $(basename "$log")"
    fi
  done
  if [[ -n "$hits" ]]; then
    fail "$id" "$desc（命中:$hits）"
  else
    pass "$id" "$desc"
  fi
}

# ---------------------------------------------------------------------------
# 构建与端口
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub / rustboard-agent / rustboard-panel"
if ! (cd "$ROOT" && "$CARGO" build \
    --bin rustboard-hub --bin rustboard-agent --bin rustboard-panel) \
    > "$BUILD_LOG" 2>&1; then
  dump_redacted "$BUILD_LOG" 100 >&2 || true
  die "cargo build 失败（日志: $BUILD_LOG）"
fi
pass "0.1" "cargo build 三个 bin 成功"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
HUB_BIN="$TARGET_DIR/debug/rustboard-hub"
AGENT_BIN="$TARGET_DIR/debug/rustboard-agent"
PANEL_BIN="$TARGET_DIR/debug/rustboard-panel"
[[ -x "$HUB_BIN" ]] || die "找不到可执行文件 $HUB_BIN"
[[ -x "$AGENT_BIN" ]] || die "找不到可执行文件 $AGENT_BIN"
[[ -x "$PANEL_BIN" ]] || die "找不到可执行文件 $PANEL_BIN"

PORT_LINE=$(pick_ports) || die "无法挑选 6 个空闲端口"
read -r AGENT_PORT ADMIN_PORT PANEL_PORT RATE_PORT BADTOKEN_PORT PROXY_PORT <<< "$PORT_LINE"
for port in "$AGENT_PORT" "$ADMIN_PORT" "$PANEL_PORT" "$RATE_PORT" "$BADTOKEN_PORT" "$PROXY_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] || die "端口解析失败: $PORT_LINE"
done
HUB_URL="http://127.0.0.1:$ADMIN_PORT"
PANEL_URL="http://127.0.0.1:$PANEL_PORT"
RATE_URL="http://127.0.0.1:$RATE_PORT"
BADTOKEN_URL="http://127.0.0.1:$BADTOKEN_PORT"

# ---------------------------------------------------------------------------
# 1. hub init / 启动 / Bearer 鉴权
# ---------------------------------------------------------------------------

echo
echo "==> 1/8 hub init + admin_token + Bearer 鉴权"
if ! "$HUB_BIN" init \
    --config "$HUB_CFG" \
    --data-dir "$HUB_DATA" \
    --agent-listen "127.0.0.1:$AGENT_PORT" \
    --admin-listen "127.0.0.1:$ADMIN_PORT" \
    --force > "$HUB_INIT_LOG" 2>&1; then
  dump_redacted "$HUB_INIT_LOG" 60 >&2 || true
  die "hub init 失败（日志: $HUB_INIT_LOG）"
fi
pass "1.0" "hub init 成功"

AGENT_LISTEN=$(cfg_str "$HUB_CFG" agent_listen) || die "无法解析 agent_listen"
ADMIN_LISTEN=$(cfg_str "$HUB_CFG" admin_listen) || die "无法解析 admin_listen"
HUB_DATA_CFG=$(cfg_str "$HUB_CFG" data_dir) || die "无法解析 data_dir"
check_eq "1.0a" "config 的 agent_listen 为回环指定端口" \
  "127.0.0.1:$AGENT_PORT" "$AGENT_LISTEN"
check_eq "1.0b" "config 的 admin_listen 为回环指定端口" \
  "127.0.0.1:$ADMIN_PORT" "$ADMIN_LISTEN"
check_eq "1.0c" "config 的 data_dir 与 init 一致" "$HUB_DATA" "$HUB_DATA_CFG"
[[ "$AGENT_LISTEN" == 127.0.0.1:* && "$ADMIN_LISTEN" == 127.0.0.1:* ]] \
  || die "监听地址不是 127.0.0.1: agent=$AGENT_LISTEN admin=$ADMIN_LISTEN"

ADMIN_TOKEN=$(cfg_str "$HUB_CFG" admin_token) || die "无法解析 admin_token"
if [[ -z "$ADMIN_TOKEN" ]]; then
  fail "1.1" "hub init 未生成 admin_token（方案 §3.3 要求随机生成；空值应拒绝启动）"
  die "admin_token 为空，无法继续 Bearer 鉴权测试"
fi
export RB_E2E_ADMIN_TOKEN="$ADMIN_TOKEN"
if [[ "$ADMIN_TOKEN" =~ ^[0-9a-f]{64}$ ]]; then
  pass "1.1" "hub init 生成 64 位十六进制 admin_token"
else
  fail "1.1" "admin_token 不是 64 位十六进制（长度 ${#ADMIN_TOKEN}）"
  if [[ ! "$ADMIN_TOKEN" =~ ^[0-9a-fA-F]+$ ]]; then
    die "admin_token 非十六进制，无法继续"
  fi
fi

HUB_INTERVAL=$(cfg_num "$HUB_CFG" sample_interval_ms) || die "无法解析 hub sample_interval_ms"
[[ "$HUB_INTERVAL" =~ ^[0-9]+$ ]] || die "hub sample_interval_ms 不是整数: $HUB_INTERVAL"

# 空 admin_token 必须拒绝启动，并在错误里提示 admin-token 修复命令（方案 §3.1）。
EMPTY_READY=0
if "$PYTHON" - "$HUB_CFG" "$EMPTY_CFG" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
new, count = re.subn(
    r'(?m)^admin_token\s*=\s*".*"\s*$', 'admin_token = ""', text
)
if count != 1:
    raise SystemExit(f"admin_token 行数不是 1: {count}")
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write(new)
PY
then
  EMPTY_READY=1
else
  fail "1.2" "无法生成空 admin_token 的临时配置"
fi

if (( EMPTY_READY == 1 )); then
  set +e
  timeout 10 "$HUB_BIN" run --config "$EMPTY_CFG" > "$EMPTY_LOG" 2>&1
  EMPTY_RC=$?
  set -e
  if (( EMPTY_RC == 124 )); then
    fail "1.2" "空 admin_token 时 hub 仍在运行（10s 内未拒绝启动）"
  elif (( EMPTY_RC == 0 )); then
    fail "1.2" "空 admin_token 时 hub 正常退出（未拒绝启动）"
  else
    pass "1.2" "空 admin_token 时 hub 拒绝启动（退出码 $EMPTY_RC）"
  fi
  if grep -Eqi 'admin[-_]token' "$EMPTY_LOG"; then
    pass "1.3" "空 token 错误信息提示 admin-token"
  else
    fail "1.3" "空 token 错误信息未提示 admin-token"
  fi
  sleep 0.2
fi

# agent add 必须在 hub 启动前执行，避免运维 CLI 与运行中的 hub 并发写 SQLite。
ADD_OUT=$("$HUB_BIN" agent add --config "$HUB_CFG" --name "e2e-panel" 2>&1) \
  || die "hub agent add 失败"
printf '%s\n' "$ADD_OUT" > "$AGENT_ADD_LOG"
ENROLL_TOKEN=$(printf '%s\n' "$ADD_OUT" \
  | awk '/一次性 token/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}')
[[ "$ENROLL_TOKEN" =~ ^[0-9a-f]{64}$ ]] || die "无法从 agent add 输出解析 64 位 token"
pass "2.1" "agent add 生成 64 位一次性 token"

FPR=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p' || true)
[[ "$FPR" =~ ^[0-9a-f]{64}$ ]] || die "无法读取服务端证书指纹: $FPR"

mkdir -p "$AGENT_DATA"
chmod 700 "$AGENT_DATA"
cat > "$AGENT_CFG" <<EOF
hub_url = "wss://127.0.0.1:$AGENT_PORT/agent/ws"
token = "$ENROLL_TOKEN"
server_fingerprint = "$FPR"
name = "e2e-panel"
data_dir = "$AGENT_DATA"
sample_interval_ms = $HUB_INTERVAL
buffer_max_bytes = 10485760
EOF
chmod 600 "$AGENT_CFG"

start_hub
if ! wait_url_status "$HUB_URL/healthz" 200 25; then
  fail "1.4" "hub /healthz 未在 25s 内返回 200（最后: $LAST_STATUS）"
  die "hub 未就绪"
fi
pass "1.4" "hub /healthz 免鉴权返回 200"

out=$(http_call GET "$HUB_URL/api/v1/agents")
check_json_status "1.5" "无 Bearer 访问 /api/v1/agents 返回 401 JSON" 401 "$out"
check_eq "1.6" "无 Bearer 的 401 错误码为 unauthorized" \
  "unauthorized" "$(printf '%s' "$out" | json_field json_error)"

WRONG_HUB_TOKEN=$("$PYTHON" -c '
import os
import secrets

while True:
    token = secrets.token_hex(32)
    if token != os.environ.get("RB_E2E_ADMIN_TOKEN"):
        print(token)
        break
')
out=$(http_call GET "$HUB_URL/api/v1/agents" \
  --header "Authorization: Bearer $WRONG_HUB_TOKEN")
check_json_status "1.7" "错误 Bearer token 返回 401 JSON" 401 "$out"
check_eq "1.8" "错误 token 的 401 错误码为 unauthorized" \
  "unauthorized" "$(printf '%s' "$out" | json_field json_error)"

out=$(http_call GET "$HUB_URL/api/v1/agents" \
  --header "Authorization: Bearer $ADMIN_TOKEN" --body-out "$TMP_DIR/agents.json")
check_json_status "1.9" "正确 Bearer token 访问 /api/v1/agents 返回 200 JSON" 200 "$out"
check_eq "1.10" "正确 token 的响应是 JSON 数组" \
  "list" "$(printf '%s' "$out" | json_field json_type)"

out=$(http_call GET "$HUB_URL/api/v1/agents" \
  --header "Authorization: $ADMIN_TOKEN")
check_json_status "1.11" "缺少 Bearer 前缀的 Authorization 返回 401 JSON" 401 "$out"

# ---------------------------------------------------------------------------
# 2. agent 上线与样本
# ---------------------------------------------------------------------------

echo
echo "==> 2/8 启动 agent 并等待 online + 样本"
start_agent
if ! wait_for_file "$AGENT_DATA/agent_id" 30; then
  fail "2.2" "agent 未在 30s 内完成 enrollment（agent_id 文件缺失）"
  die "agent 未 enrollment"
fi
if ! wait_for_file "$AGENT_DATA/agent.secret" 10; then
  fail "2.2" "agent 未在 10s 内写入 agent.secret"
  die "agent 未完成 enrollment"
fi
A_ID=$(tr -d '[:space:]' < "$AGENT_DATA/agent_id")
AGENT_SECRET=$(tr -d '[:space:]' < "$AGENT_DATA/agent.secret")
[[ -n "$A_ID" && -n "$AGENT_SECRET" ]] || die "agent_id / agent.secret 为空"
pass "2.2" "agent enrollment 成功（agent_id=$A_ID）"

if ! wait_agent_status online 45; then
  fail "2.3" "agent 未在 45s 内 online（最后: $LAST_STATUS）"
  die "agent 未上线"
fi
pass "2.3" "agent 状态为 online"

if ! wait_series_ready 45; then
  fail "2.4" "agent 未在 45s 内产生 cpu.usage/mem.used 样本（$LAST_STATUS）"
  die "没有样本"
fi
SAMPLE_OUT=$(hub_series "$(( $(date +%s%3N) - 3600000 ))" "$(date +%s%3N)" \
  2>/dev/null || true)
SAMPLE_COUNT=$(printf '%s' "$SAMPLE_OUT" | json_field total_points)
pass "2.4" "样本数 > 0（最近 1h 共 $SAMPLE_COUNT 个点）"

# ---------------------------------------------------------------------------
# 3. panel init / 启动 / 静态与未登录 API
# ---------------------------------------------------------------------------

echo
echo "==> 3/8 panel init + 启动 + 静态/未登录 API"
if ! "$PANEL_BIN" init \
    --config "$PANEL_CFG" \
    --listen "127.0.0.1:$PANEL_PORT" \
    --hub "$HUB_URL" \
    --hub-token "$ADMIN_TOKEN" \
    --password "$PASSWORD" \
    --static-dir "$STATIC_DIR" \
    --force > "$PANEL_INIT_LOG" 2>&1; then
  dump_redacted "$PANEL_INIT_LOG" 60 >&2 || true
  die "panel init 失败（日志: $PANEL_INIT_LOG）"
fi
pass "3.1" "panel init 成功"

[[ -f "$PANEL_CFG" ]] || die "panel init 未生成配置: $PANEL_CFG"
check_file_mode "3.2" "$PANEL_CFG" "600"

PANEL_HASH=$(cfg_str "$PANEL_CFG" admin_password_hash) || die "无法解析 admin_password_hash"
if [[ "$PANEL_HASH" =~ ^\$argon2id\$v=19\$m=[0-9]+,t=[0-9]+,p=[0-9]+\$ ]]; then
  pass "3.3" "admin_password_hash 是 Argon2id PHC 字符串"
else
  fail "3.3" "admin_password_hash 不是 Argon2id PHC 字符串"
fi
if grep -Fq -- "$PASSWORD" "$PANEL_CFG"; then
  fail "3.4" "panel 配置包含明文密码"
else
  pass "3.4" "panel 配置不含明文密码"
fi

PANEL_TOKEN=$(cfg_str "$PANEL_CFG" token) || die "无法解析 panel token"
if [[ "$PANEL_TOKEN" == "$ADMIN_TOKEN" ]]; then
  pass "3.5" "panel 配置保存了 hub admin_token（仅服务端使用）"
else
  fail "3.5" "panel 配置的 token 与 hub admin_token 不一致"
fi

PANEL_LISTEN=$(cfg_str "$PANEL_CFG" listen) || die "无法解析 panel listen"
PANEL_HUB=$(cfg_str "$PANEL_CFG" hub_url) || die "无法解析 panel hub_url"
PANEL_STATIC=$(cfg_str "$PANEL_CFG" static_dir) || die "无法解析 panel static_dir"
PANEL_TTL=$(cfg_num "$PANEL_CFG" session_ttl_hours) || die "无法解析 session_ttl_hours"
check_eq "3.6" "panel listen 只绑 127.0.0.1 指定端口" \
  "127.0.0.1:$PANEL_PORT" "$PANEL_LISTEN"
check_eq "3.7" "panel hub_url 等于临时 hub 管理地址" "$HUB_URL" "$PANEL_HUB"
check_eq "3.8" "panel static_dir 指向构建产物" "$STATIC_DIR" "$PANEL_STATIC"
check_eq "3.9" "session_ttl_hours 默认 12" "12" "$PANEL_TTL"

RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$PANEL_CFG" \
  >> "$PANEL_LOG" 2>&1 &
PANEL_PID=$!
PIDS+=("$PANEL_PID")
if ! wait_url_status "$PANEL_URL/healthz" 200 25; then
  fail "3.10" "panel /healthz 未在 25s 内返回 200（最后: $LAST_STATUS）"
  die "panel 未就绪"
fi
pass "3.10" "panel /healthz 返回 200"

out=$(http_call GET "$PANEL_URL/" --body-out "$INDEX_HTML")
check_status "3.11" "GET / 返回 200" 200 "$out"
check_eq "3.11a" "GET / 的 Content-Type 是 text/html" \
  "text/html" "$(printf '%s' "$out" | json_field content_type_base)"
if grep -Fqi '<html' "$INDEX_HTML"; then
  pass "3.11b" "GET / 返回 HTML"
else
  fail "3.11b" "GET / 的响应体不是 HTML"
fi
check_csp "3.11c" "GET / 带 CSP 安全头" "$out"

out=$(http_call GET "$PANEL_URL/agents/$A_ID" --body-out "$AGENTS_HTML")
check_status "3.12" "GET /agents/<id> 返回 200" 200 "$out"
check_eq "3.12a" "GET /agents/<id> 的 Content-Type 是 text/html" \
  "text/html" "$(printf '%s' "$out" | json_field content_type_base)"
if grep -Fqi '<html' "$AGENTS_HTML"; then
  pass "3.12b" "GET /agents/<id> 回退 index.html"
else
  fail "3.12b" "GET /agents/<id> 未返回 HTML"
fi

out=$(http_call GET "$PANEL_URL/login" --body-out "$LOGIN_HTML")
check_status "3.13" "GET /login 返回 200" 200 "$out"
check_eq "3.13a" "GET /login 的 Content-Type 是 text/html" \
  "text/html" "$(printf '%s' "$out" | json_field content_type_base)"

out=$("$PYTHON" "$PROBE" session --url "$PANEL_URL/api/session")
check_status "3.14" "无 Cookie GET /api/session 返回 200" 200 "$out"
check_json_status "3.14a" "无 Cookie /api/session 是 JSON" 200 "$out"
check_eq "3.14b" "无 Cookie /api/session authenticated=false" \
  "false" "$(printf '%s' "$out" | json_field authenticated)"
check_csp "3.14c" "GET /api/session 带 CSP 安全头" "$out"

out=$(http_call GET "$PANEL_URL/api/nope")
check_json_status "3.15" "未登录访问未知 /api/* 返回 401 JSON（不是 HTML）" 401 "$out"

out=$(http_call GET "$PANEL_URL/api/overview")
check_json_status "3.16" "无 Cookie GET /api/overview 返回 401 JSON" 401 "$out"

# ---------------------------------------------------------------------------
# 4. 登录 / Cookie / 会话
# ---------------------------------------------------------------------------

echo
echo "==> 4/8 登录、Cookie 属性与会话"
export RB_E2E_PANEL_PASSWORD="$PASSWORD"

out=$(login_call --url "$PANEL_URL/api/login" --password "$WRONG_PASSWORD")
check_status "4.1" "错误密码登录返回 401" 401 "$out"

out=$(login_call --url "$PANEL_URL/api/login" --password-env RB_E2E_PANEL_PASSWORD \
  --cookie-out "$COOKIE_FILE")
check_status "4.2" "正确密码登录返回 204" 204 "$out"
check_eq "4.2a" "登录 204 的 Content-Type 仍是 application/json" \
  "application/json" "$(printf '%s' "$out" | json_field content_type_base)"
check_eq "4.3" "Set-Cookie 的会话名是 rb_session" \
  "rb_session" "$(printf '%s' "$out" | json_field cookie_name)"
SESSION_LEN=$(printf '%s' "$out" | json_field cookie_value_len)
if [[ "$SESSION_LEN" =~ ^[0-9]+$ ]] && (( SESSION_LEN >= 16 )); then
  pass "4.4" "rb_session 值是不短于 16 字符的不透明串（长度 $SESSION_LEN）"
else
  fail "4.4" "rb_session 值长度异常（$SESSION_LEN）"
fi
check_true "4.5" "Cookie 带 HttpOnly" \
  "$(printf '%s' "$out" | json_field http_only)"
check_eq "4.6" "Cookie 带 SameSite=Lax" \
  "Lax" "$(printf '%s' "$out" | json_field same_site)"
check_eq "4.7" "Cookie 带 Path=/" \
  "/" "$(printf '%s' "$out" | json_field path)"
check_eq "4.8" "无 X-Forwarded-Proto 时 Cookie 不带 Secure" \
  "false" "$(printf '%s' "$out" | json_field secure)"
check_true "4.9" "会话 Cookie 已写入临时文件" \
  "$(printf '%s' "$out" | json_field cookie_saved)"

out=$("$PYTHON" "$PROBE" session --url "$PANEL_URL/api/session" \
  --cookie-file "$COOKIE_FILE")
check_status "4.10" "带 Cookie GET /api/session 返回 200" 200 "$out"
check_eq "4.10a" "带 Cookie /api/session authenticated=true" \
  "true" "$(printf '%s' "$out" | json_field authenticated)"

out=$(login_call --url "$PANEL_URL/api/login" --password-env RB_E2E_PANEL_PASSWORD \
  --header 'X-Forwarded-Proto: https' --cookie-out "$XFP_COOKIE_FILE")
check_status "4.11" "带 X-Forwarded-Proto: https 的正确登录返回 204" 204 "$out"
check_true "4.12" "X-Forwarded-Proto: https 时 Cookie 带 Secure" \
  "$(printf '%s' "$out" | json_field secure)"

# ---------------------------------------------------------------------------
# 5. 登录限速（独立 panel 进程，避免锁住主面板的 127.0.0.1）
# ---------------------------------------------------------------------------

echo
echo "==> 5/8 登录限速（独立 panel 进程）"
RATE_READY=0
if "$PANEL_BIN" init \
    --config "$RATE_CFG" \
    --listen "127.0.0.1:$RATE_PORT" \
    --hub "$HUB_URL" \
    --hub-token "$ADMIN_TOKEN" \
    --password "$PASSWORD" \
    --static-dir "$STATIC_DIR" \
    --force > "$RATE_INIT_LOG" 2>&1; then
  RATE_READY=1
else
  fail "5.0" "限速用的独立 panel init 失败（见 $RATE_INIT_LOG）"
fi

if (( RATE_READY == 1 )); then
  RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$RATE_CFG" \
    >> "$RATE_LOG" 2>&1 &
  RATE_PID=$!
  PIDS+=("$RATE_PID")
  if wait_url_status "$RATE_URL/healthz" 200 25; then
    RATE_FIRST4=0
    for i in 1 2 3 4; do
      out=$(login_call --url "$RATE_URL/api/login" \
        --password "$WRONG_PASSWORD")
      status=$(printf '%s' "$out" | json_field status)
      if [[ "$status" == "401" ]]; then
        RATE_FIRST4=$((RATE_FIRST4 + 1))
      else
        fail "5.1.$i" "第 $i 次错误密码期望 401，实际 ${status:-<无响应>}"
      fi
    done
    if (( RATE_FIRST4 == 4 )); then
      pass "5.1" "前 4 次错误密码均返回 401"
    else
      fail "5.1" "前 4 次错误密码只有 $RATE_FIRST4 次返回 401"
    fi

    # 第 5 次失败是“触发锁定”的边界：方案只规定锁定后返回 429，
    # 未规定第 5 次本身是 401 还是 429；两种都接受，但必须已进入锁定。
    out=$(login_call --url "$RATE_URL/api/login" \
      --password "$WRONG_PASSWORD")
    status=$(printf '%s' "$out" | json_field status)
    if [[ "$status" == "401" || "$status" == "429" ]]; then
      pass "5.1a" "第 5 次错误密码被拒绝（HTTP $status）"
    else
      fail "5.1a" "第 5 次错误密码未被拒绝（HTTP ${status:-<无响应>}）"
    fi

    out=$(login_call --url "$RATE_URL/api/login" --password-env RB_E2E_PANEL_PASSWORD)
    check_status "5.2" "连续 5 次失败后即使密码正确也返回 429" 429 "$out"
    check_eq "5.3" "429 响应不下发会话 Cookie" \
      "" "$(printf '%s' "$out" | json_field cookie_name)"
  else
    fail "5.0a" "限速 panel 未在 25s 内就绪（最后: $LAST_STATUS）"
  fi
  stop_pid "$RATE_PID"
  RATE_PID=""
fi

# ---------------------------------------------------------------------------
# 5b. 面板 → hub 认证失败映射（独立 panel，错误 hub token）
# ---------------------------------------------------------------------------

echo
echo "==> 5b/8 面板 → hub 认证失败映射（502 hub_auth_failed）"
BAD_READY=0
if "$PANEL_BIN" init \
    --config "$BAD_CFG" \
    --listen "127.0.0.1:$BADTOKEN_PORT" \
    --hub "$HUB_URL" \
    --hub-token "$WRONG_HUB_TOKEN" \
    --password "$PASSWORD" \
    --static-dir "$STATIC_DIR" \
    --force > "$BAD_INIT_LOG" 2>&1; then
  BAD_READY=1
else
  fail "5b.0" "错误 hub token 的独立 panel init 失败（见 $BAD_INIT_LOG）"
fi

if (( BAD_READY == 1 )); then
  RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$BAD_CFG" \
    >> "$BAD_LOG" 2>&1 &
  BADTOKEN_PID=$!
  PIDS+=("$BADTOKEN_PID")
  if wait_url_status "$BADTOKEN_URL/healthz" 200 25; then
    out=$(login_call --url "$BADTOKEN_URL/api/login" \
      --password-env RB_E2E_PANEL_PASSWORD --cookie-out "$BAD_COOKIE_FILE")
    check_status "5b.1" "错误 hub token 的 panel 仍可登录（204）" 204 "$out"

    out=$(http_call GET "$BADTOKEN_URL/api/overview" \
      --cookie-file "$BAD_COOKIE_FILE" --body-out "$BAD_OVERVIEW_BODY")
    check_status "5b.2" "hub 返回 401 时 panel 返回 502" 502 "$out"
    check_json_status "5b.3" "502 响应是 JSON" 502 "$out"
    if grep -Fq 'hub_auth_failed' "$BAD_OVERVIEW_BODY"; then
      pass "5b.4" "502 错误码为 hub_auth_failed"
    else
      fail "5b.4" "502 响应未包含 hub_auth_failed"
    fi
    scan_files_no_secret "5b.5" "502 响应不回显 hub admin_token" \
      "$ADMIN_TOKEN" "$BAD_OVERVIEW_BODY"
    scan_files_no_secret "5b.5a" "502 响应不回显该 panel 配置的（错误）hub token" \
      "$WRONG_HUB_TOKEN" "$BAD_OVERVIEW_BODY"
  else
    fail "5b.0a" "错误 hub token 的 panel 未在 25s 内就绪（最后: $LAST_STATUS）"
  fi
  stop_pid "$BADTOKEN_PID"
  BADTOKEN_PID=""
fi

# ---------------------------------------------------------------------------
# 5c. 默认 listen / HTTP_PROXY 不泄露 / Content-Type / CSP（独立 panel）
# ---------------------------------------------------------------------------

echo
echo "==> 5c/8 默认只监听 127.0.0.1、HTTP_PROXY 不泄露、/api/* JSON、CSP"
NO_PROXY_READY=0

# 缺 listen 的配置必须回落到固定的 127.0.0.1:8080，且多次 ports 输出一致
# （随机端口只属于 panel init，不属于 PanelConfig::default）。
DEFAULT_PORTS_1=$("$PANEL_BIN" ports --config "$TMP_DIR/no-such-config.toml" 2>&1) \
  || fail "5c.0" "panel ports 在无配置时执行失败"
DEFAULT_PORTS_2=$("$PANEL_BIN" ports --config "$TMP_DIR/no-such-config.toml" 2>&1) \
  || fail "5c.0" "panel ports 在无配置时执行失败"
if [[ "$DEFAULT_PORTS_1" == "$DEFAULT_PORTS_2" ]] \
    && grep -Fq "监听: 127.0.0.1:8080" <<< "$DEFAULT_PORTS_1"; then
  pass "5c.0a" "缺 listen 时 Default 固定为 127.0.0.1:8080 且多次输出一致"
else
  fail "5c.0a" "缺 listen 时 Default 不稳定或不是 127.0.0.1:8080（$DEFAULT_PORTS_1）"
fi

# 不传 --listen：验证 init 默认生成 127.0.0.1:<随机端口>。
# hub 地址先写一个占位值，运行时再用 --hub 覆盖，顺便验证覆盖地址的 WARN。
if "$PANEL_BIN" init \
    --config "$NO_PROXY_CFG" \
    --hub "http://127.0.0.1:1" \
    --hub-token "$ADMIN_TOKEN" \
    --password "$PASSWORD" \
    --static-dir "$STATIC_DIR" \
    --force > "$NO_PROXY_INIT_LOG" 2>&1; then
  NO_PROXY_READY=1
else
  fail "5c.0" "默认 listen 的独立 panel init 失败（见 $NO_PROXY_INIT_LOG）"
fi

if (( NO_PROXY_READY == 1 )); then
  NO_PROXY_LISTEN=$(cfg_str "$NO_PROXY_CFG" listen) || die "无法解析默认 panel listen"
  if [[ "$NO_PROXY_LISTEN" =~ ^127\.0\.0\.1:([0-9]+)$ ]]; then
    NO_PROXY_PORT=${BASH_REMATCH[1]}
    NO_PROXY_URL="http://127.0.0.1:$NO_PROXY_PORT"
    pass "5c.1" "未显式 --listen 时默认只绑 127.0.0.1 随机端口（$NO_PROXY_LISTEN）"
  else
    fail "5c.1" "未显式 --listen 时默认 listen 不是 127.0.0.1:<端口>: $NO_PROXY_LISTEN"
    NO_PROXY_READY=0
  fi
fi

if (( NO_PROXY_READY == 1 )); then
  PORTS_OUT=$("$PANEL_BIN" ports --config "$NO_PROXY_CFG" 2>&1) \
    || fail "5c.2" "panel ports 读取默认配置失败"
  if grep -Fq "监听: $NO_PROXY_LISTEN" <<< "$PORTS_OUT" \
      && grep -Fq "浏览器: http://127.0.0.1:$NO_PROXY_PORT" <<< "$PORTS_OUT" \
      && grep -Fq "提示: 面板只监听回环地址" <<< "$PORTS_OUT"; then
    pass "5c.2" "ports 输出回环地址与访问方式提示"
  else
    fail "5c.2" "ports 输出缺少回环地址/提示（$PORTS_OUT）"
  fi

  start_fake_proxy "$PROXY_PORT" "$PROXY_READY" "$PROXY_HITS"
  if wait_for_file "$PROXY_READY" 10; then
    pass "5c.3" "假 HTTP 代理已监听 127.0.0.1:$PROXY_PORT"
    PROXY_URL="http://127.0.0.1:$PROXY_PORT"
    # 显式清空 NO_PROXY/HTTPS_PROXY 再启动面板：若 CI 预置了 NO_PROXY=127.0.0.1，
    # 即使 .no_proxy() 被误删，请求也会绕过假代理，测试会假阳性。
    # env -u 只影响该子进程，不修改当前 shell 的环境，因此无需在脚本里恢复。
    env -u NO_PROXY -u no_proxy -u HTTPS_PROXY -u https_proxy \
      HTTP_PROXY="$PROXY_URL" http_proxy="$PROXY_URL" \
      ALL_PROXY="$PROXY_URL" all_proxy="$PROXY_URL" \
      RUST_LOG=rustboard_panel=info \
      "$PANEL_BIN" run --config "$NO_PROXY_CFG" --hub "$HUB_URL" \
      >> "$NO_PROXY_LOG" 2>&1 &
    NO_PROXY_PID=$!
    PIDS+=("$NO_PROXY_PID")

    if wait_url_status "$NO_PROXY_URL/healthz" 200 25; then
      pass "5c.4" "带 HTTP_PROXY/ALL_PROXY 时面板仍能启动"
      if wait_for_log "$NO_PROXY_LOG" "仍沿用配置里的 hub token" 5; then
        pass "5c.5" "--hub 覆盖地址时打印沿用配置 token 的 WARN"
      else
        fail "5c.5" "--hub 覆盖地址但未打印沿用配置 token 的 WARN"
      fi

      out=$(login_call --url "$NO_PROXY_URL/api/login" \
        --password-env RB_E2E_PANEL_PASSWORD --cookie-out "$NO_PROXY_COOKIE_FILE")
      check_status "5c.6" "默认回环面板可登录（204）" 204 "$out"

      out=$(http_call GET "$NO_PROXY_URL/api/overview" \
        --cookie-file "$NO_PROXY_COOKIE_FILE" --body-out "$NO_PROXY_OVERVIEW")
      check_json_status "5c.7" "设置假 HTTP_PROXY 后 /api/overview 仍直连 hub 返回 200 JSON" \
        200 "$out"
      check_eq "5c.7a" "假 HTTP_PROXY 下 API Content-Type 恒为 application/json" \
        "application/json" "$(printf '%s' "$out" | json_field content_type_base)"
      check_csp "5c.7b" "假 HTTP_PROXY 下 API 响应带 CSP" "$out"

      out=$(http_call GET "$NO_PROXY_URL/")
      check_csp "5c.8" "页面响应带 CSP" "$out"

      # 请求已经完成；再给假代理一点时间接收本不该出现的连接。
      sleep 0.5
      if [[ -e "$PROXY_HITS" ]]; then
        fail "5c.9" "假 HTTP_PROXY 收到了面板发往 hub 的请求（hub token 可能泄露给环境代理）: $(cat "$PROXY_HITS")"
      else
        pass "5c.9" "假 HTTP_PROXY 未收到任何连接（Bearer token 不会发给环境代理）"
      fi
      scan_files_no_secret "5c.10" "带代理环境的面板 API 响应不含 hub admin_token" \
        "$ADMIN_TOKEN" "$NO_PROXY_OVERVIEW"
    else
      fail "5c.4" "设置假 HTTP_PROXY 后默认面板未在 25s 内就绪（最后: $LAST_STATUS）"
    fi
    stop_pid "$NO_PROXY_PID"
    NO_PROXY_PID=""
  else
    fail "5c.3" "假 HTTP 代理未能在 10s 内监听 127.0.0.1:$PROXY_PORT"
  fi
  stop_pid "$PROXY_PID"
  PROXY_PID=""
fi

# ---------------------------------------------------------------------------
# 5d. 显式 static_dir 无效时拒绝启动（不静默回退）
# ---------------------------------------------------------------------------

echo
echo "==> 5d/8 显式 static_dir 无效时拒绝启动"
BAD_STATIC_READY=0
if "$PANEL_BIN" init \
    --config "$BAD_STATIC_CFG" \
    --listen "127.0.0.1:$PROXY_PORT" \
    --hub "$HUB_URL" \
    --hub-token "$ADMIN_TOKEN" \
    --password "$PASSWORD" \
    --static-dir "$TMP_DIR/no-such-static-dir" \
    --force > "$BAD_STATIC_INIT_LOG" 2>&1; then
  BAD_STATIC_READY=1
else
  fail "5d.0" "static_dir 用例的 panel init 失败（见 $BAD_STATIC_INIT_LOG）"
fi

if (( BAD_STATIC_READY == 1 )); then
  set +e
  timeout 10 "$PANEL_BIN" run --config "$BAD_STATIC_CFG" > "$BAD_STATIC_LOG" 2>&1
  BAD_STATIC_RC=$?
  set -e
  if (( BAD_STATIC_RC == 124 )); then
    fail "5d.1" "static_dir 无效时 panel 仍在运行（10s 内未拒绝启动）"
  elif (( BAD_STATIC_RC == 0 )); then
    fail "5d.1" "static_dir 无效时 panel 正常退出（未报错）"
  else
    pass "5d.1" "static_dir 无效时 panel 拒绝启动（退出码 $BAD_STATIC_RC）"
  fi
  if grep -Fq "static_dir" "$BAD_STATIC_LOG"; then
    pass "5d.2" "错误信息点名 static_dir"
  else
    fail "5d.2" "错误信息未点名 static_dir"
  fi
fi

# ---------------------------------------------------------------------------
# 6. overview
# ---------------------------------------------------------------------------

echo
echo "==> 6/8 overview 键/类型/latest/settings"
if ! wait_overview_metrics 30; then
  fail "6.3" "overview.latest 在 30s 内未同时出现 cpu.usage 与 mem.used（$LAST_STATUS）"
else
  pass "6.3" "overview.latest 同时包含 cpu.usage 与 mem.used"
fi

out=$(overview_panel --body-out "$OVERVIEW_BODY")
check_json_status "6.1" "带 Cookie GET /api/overview 返回 200 JSON" 200 "$out"
check_csp "6.1a" "overview 响应带 CSP 安全头" "$out"
check_true "6.2a" "overview 含 server_time" \
  "$(printf '%s' "$out" | json_field has_server_time)"
check_true "6.2b" "overview.server_time 是数字" \
  "$(printf '%s' "$out" | json_field server_time_number)"
check_true "6.2c" "overview.agents 是数组" \
  "$(printf '%s' "$out" | json_field agents_is_list)"
check_true "6.2d" "overview.latest 是数组" \
  "$(printf '%s' "$out" | json_field latest_is_list)"
check_true "6.2e" "overview.settings 是数组" \
  "$(printf '%s' "$out" | json_field settings_is_list)"
check_true "6.4a" "overview.agents 含本测试 agent" \
  "$(printf '%s' "$out" | json_field agent_present)"
check_eq "6.4b" "overview.agents 中本 agent 为 online" \
  "online" "$(printf '%s' "$out" | json_field agent_status)"
check_true "6.5a" "overview.latest 含 cpu.usage" \
  "$(printf '%s' "$out" | json_field latest_has_cpu)"
check_true "6.5b" "overview.latest 含 mem.used" \
  "$(printf '%s' "$out" | json_field latest_has_mem)"

out=$(http_call GET "$PANEL_URL/api/overview?window_ms=999" \
  --cookie-file "$COOKIE_FILE")
check_json_status "6.1b" "overview window_ms=999 返回 400 JSON（与 hub 1s 下限对齐）" \
  400 "$out"
out=$(http_call GET "$PANEL_URL/api/overview?window_ms=1000" \
  --cookie-file "$COOKIE_FILE")
check_json_status "6.1c" "overview window_ms=1000 返回 200 JSON" 200 "$out"

# ---------------------------------------------------------------------------
# 7. series
# ---------------------------------------------------------------------------

echo
echo "==> 7/8 series 查询与非法参数"
NOW=$(date +%s%3N)
out=$(panel_series "$((NOW - 3600000))" "$NOW" --body-out "$SERIES_BODY")
check_json_status "7.1" "面板多指标 series 返回 200 JSON" 200 "$out"
check_true "7.2" "series 的 points 均为 [ts, value]" \
  "$(printf '%s' "$out" | json_field shape_ok)"
check_true "7.3" "series 的 bucket_ms > 0 且属于方案档位" \
  "$(printf '%s' "$out" | json_field bucket_allowed)"
check_eq "7.4" "series 同时返回请求的两个 metric" \
  "0" "$(printf '%s' "$out" | json_field missing_count)"
MAX_POINTS=$(printf '%s' "$out" | json_field max_points_per_curve)
TOTAL_POINTS=$(printf '%s' "$out" | json_field total_points)
SERIES_COUNT=$(printf '%s' "$out" | json_field series_count)
if [[ "$MAX_POINTS" =~ ^[0-9]+$ ]] && (( MAX_POINTS <= 2000 )); then
  pass "7.5" "单曲线点数 ≤ 2000（实际 $MAX_POINTS）"
else
  fail "7.5" "单曲线点数超过 2000（实际 $MAX_POINTS）"
fi
if [[ "$TOTAL_POINTS" =~ ^[0-9]+$ && "$SERIES_COUNT" =~ ^[0-9]+$ ]] \
    && (( TOTAL_POINTS <= 20000 && SERIES_COUNT <= 50 )); then
  pass "7.6" "总点数 ≤ 20000 且序列数 ≤ 50（$TOTAL_POINTS / $SERIES_COUNT）"
else
  fail "7.6" "总点数或序列数超限（$TOTAL_POINTS / $SERIES_COUNT）"
fi

out=$(panel_series "$((NOW - 3600000))" "$NOW" "&bucket_ms=60000")
check_json_status "7.7" "显式 bucket_ms=60000 的 series 返回 200 JSON" 200 "$out"
check_eq "7.7a" "显式 bucket_ms 被原样返回" \
  "60000" "$(printf '%s' "$out" | json_field bucket_ms)"
check_true "7.7b" "显式 bucket 下 points 形状仍正确" \
  "$(printf '%s' "$out" | json_field shape_ok)"

out=$(hub_series "$((NOW - 3600000))" "$NOW")
check_json_status "7.8" "hub 直连多指标 series 返回 200 JSON" 200 "$out"
check_true "7.8a" "hub 直连 series 的 points 形状正确" \
  "$(printf '%s' "$out" | json_field shape_ok)"
check_true "7.8b" "hub 直连 series 的 bucket_ms 合法" \
  "$(printf '%s' "$out" | json_field bucket_allowed)"

check_series_400() {
  local id=$1
  local desc=$2
  local query=$3
  local out
  out=$("$PYTHON" "$PROBE" series \
    --url "$PANEL_URL/api/agents/$A_ID/series?$query" \
    --cookie-file "$COOKIE_FILE" 2>/dev/null || true)
  check_json_status "$id" "$desc" 400 "$out"
}

check_series_400 "7.9" "from == to 返回 400 JSON" \
  "metric=cpu.usage&from=$NOW&to=$NOW"
check_series_400 "7.10" "from > to 返回 400 JSON" \
  "metric=cpu.usage&from=$NOW&to=$((NOW - 1000))"
check_series_400 "7.11" "跨度 > 32 天返回 400 JSON" \
  "metric=cpu.usage&from=$((NOW - 33 * 86400000))&to=$NOW"
check_series_400 "7.12" "metric 含非法字符返回 400 JSON" \
  "metric=cpu%20usage&from=$((NOW - 3600000))&to=$NOW"
check_series_400 "7.13" "21 个 metric 返回 400 JSON" \
  "metric=m1&metric=m2&metric=m3&metric=m4&metric=m5&metric=m6&metric=m7&metric=m8&metric=m9&metric=m10&metric=m11&metric=m12&metric=m13&metric=m14&metric=m15&metric=m16&metric=m17&metric=m18&metric=m19&metric=m20&metric=m21&from=$((NOW - 3600000))&to=$NOW"
check_series_400 "7.14" "缺少 metric 返回 400 JSON" \
  "from=$((NOW - 3600000))&to=$NOW"
LONG_METRIC=$(printf 'a%.0s' {1..65})
check_series_400 "7.15" "单个 metric 超过 64 字符返回 400 JSON" \
  "metric=$LONG_METRIC&from=$((NOW - 3600000))&to=$NOW"

# ---------------------------------------------------------------------------
# 8. settings
# ---------------------------------------------------------------------------

echo
echo "==> 8/8 settings 默认值/更新/生效/边界"
out=$(http_call GET "$PANEL_URL/api/agents/$A_ID/settings" \
  --cookie-file "$COOKIE_FILE" --body-out "$SETTINGS_BODY")
check_json_status "8.1" "面板 GET settings 返回 200 JSON" 200 "$out"
SETTINGS_AGENT=$(json_file_get "$SETTINGS_BODY" agent_id)
check_eq "8.1a" "settings.agent_id 等于本 agent" "$A_ID" "$SETTINGS_AGENT"
SETTINGS_DEFAULT=$(json_file_get "$SETTINGS_BODY" sample_interval_ms)
check_eq "8.1b" "settings 默认值等于 hub sample_interval_ms" \
  "$HUB_INTERVAL" "$SETTINGS_DEFAULT"

out=$(http_call GET "$HUB_URL/api/v1/agents/$A_ID/settings" \
  --bearer-env --body-out "$HUB_SETTINGS_BODY")
check_json_status "8.2" "hub 直连 GET settings 返回 200 JSON" 200 "$out"
HUB_SETTINGS_DEFAULT=$(json_file_get "$HUB_SETTINGS_BODY" sample_interval_ms)
check_eq "8.2a" "hub GET settings 默认值等于配置值" \
  "$HUB_INTERVAL" "$HUB_SETTINGS_DEFAULT"

# 更新前的样本基线；PUT 会踢会话，agent 重连后继续上报。
BASELINE_OUT=$(panel_series "$(( $(date +%s%3N) - 3600000 ))" "$(date +%s%3N)" \
  2>/dev/null || true)
BASELINE=$(printf '%s' "$BASELINE_OUT" | json_field total_points)
[[ "$BASELINE" =~ ^[0-9]+$ ]] || BASELINE=0

out=$(http_call PUT "$PANEL_URL/api/agents/$A_ID/settings" \
  --cookie-file "$COOKIE_FILE" \
  --header 'Content-Type: application/json' \
  --data '{"sample_interval_ms":10000}')
PUT_STATUS=$(printf '%s' "$out" | json_field status)
if [[ "$PUT_STATUS" =~ ^2[0-9][0-9]$ ]]; then
  pass "8.3" "PUT settings sample_interval_ms=10000 返回 2xx（$PUT_STATUS）"
else
  fail "8.3" "PUT settings 返回 ${PUT_STATUS:-<无响应>}（期望 2xx）"
fi

out=$(http_call GET "$PANEL_URL/api/agents/$A_ID/settings" \
  --cookie-file "$COOKIE_FILE" --body-out "$SETTINGS_BODY")
check_json_status "8.4" "PUT 后面板 GET settings 返回 200 JSON" 200 "$out"
check_eq "8.4a" "PUT 后面板回读 10000" \
  "10000" "$(json_file_get "$SETTINGS_BODY" sample_interval_ms)"

out=$(http_call GET "$HUB_URL/api/v1/agents/$A_ID/settings" \
  --bearer-env --body-out "$HUB_SETTINGS_BODY")
check_json_status "8.5" "PUT 后 hub 直连 GET settings 返回 200 JSON" 200 "$out"
check_eq "8.5a" "PUT 后 hub 回读 10000" \
  "10000" "$(json_file_get "$HUB_SETTINGS_BODY" sample_interval_ms)"

out=$(overview_panel)
check_json_status "8.6" "PUT 后 overview 返回 200 JSON" 200 "$out"
check_eq "8.6a" "overview.settings 中该 agent 的间隔为 10000" \
  "10000" "$(printf '%s' "$out" | json_field agent_interval)"

if wait_for_log "$AGENT_LOG" "采样间隔已更新 ms=10000" 60; then
  pass "8.7" "agent 日志在 60s 内出现「采样间隔已更新 ms=10000」"
else
  fail "8.7" "agent 日志未在 60s 内出现「采样间隔已更新 ms=10000」"
fi

if wait_agent_status online 30; then
  pass "8.8" "配置变更重连后 agent 仍 online"
else
  fail "8.8" "配置变更后 agent 未在 30s 内恢复 online（最后: $LAST_STATUS）"
fi

if wait_series_gt "$BASELINE" 45; then
  pass "8.9" "配置变更后样本数继续增长（基线 $BASELINE，最后 $LAST_STATUS）"
else
  fail "8.9" "配置变更后样本数未继续增长（基线 $BASELINE，最后 $LAST_STATUS）"
fi

check_settings_400() {
  local id=$1
  local desc=$2
  local body=$3
  local out
  out=$(http_call PUT "$PANEL_URL/api/agents/$A_ID/settings" \
    --cookie-file "$COOKIE_FILE" \
    --header 'Content-Type: application/json' --data "$body" 2>/dev/null || true)
  check_json_status "$id" "$desc" 400 "$out"
}

check_settings_400 "8.10" "sample_interval_ms=999 返回 400 JSON" \
  '{"sample_interval_ms":999}'
check_settings_400 "8.11" "sample_interval_ms=300001 返回 400 JSON" \
  '{"sample_interval_ms":300001}'
check_settings_400 "8.12" "sample_interval_ms 为非数字返回 400 JSON" \
  '{"sample_interval_ms":"abc"}'

out=$(http_call GET "$PANEL_URL/api/agents/$A_ID/settings" \
  --cookie-file "$COOKIE_FILE" --body-out "$SETTINGS_BODY")
check_json_status "8.13" "非法 PUT 后 GET settings 仍返回 200 JSON" 200 "$out"
check_eq "8.13a" "非法 PUT 未改变已保存的 10000" \
  "10000" "$(json_file_get "$SETTINGS_BODY" sample_interval_ms)"

NOPE_ID="e2e-no-such-agent-0001"
out=$(http_call GET "$PANEL_URL/api/agents/$NOPE_ID/settings" \
  --cookie-file "$COOKIE_FILE")
check_json_status "8.14" "不存在的 agent GET settings 返回 404 JSON" 404 "$out"
out=$(http_call PUT "$PANEL_URL/api/agents/$NOPE_ID/settings" \
  --cookie-file "$COOKIE_FILE" \
  --header 'Content-Type: application/json' \
  --data '{"sample_interval_ms":10000}')
check_json_status "8.15" "不存在的 agent PUT settings 返回 404 JSON" 404 "$out"
out=$(http_call GET "$HUB_URL/api/v1/agents/$NOPE_ID/settings" --bearer-env)
check_json_status "8.16" "hub 直连不存在的 agent 返回 404 JSON" 404 "$out"

# ---------------------------------------------------------------------------
# 9. 静态安全 / API JSON / 秘密泄露
# ---------------------------------------------------------------------------

echo
echo "==> 9/8 静态路径穿越、/api/* JSON、秘密泄露"

check_traversal() {
  local id=$1
  local desc=$2
  shift 2
  local bad=""
  local path out status
  for path in "$@"; do
    rm -f -- "$TRAVERSAL_BODY" 2>/dev/null || true
    out=$(http_call GET "$PANEL_URL/" --raw-path "$path" \
      --body-out "$TRAVERSAL_BODY" 2>/dev/null || true)
    status=$(printf '%s' "$out" | json_field status)
    if [[ "$status" == "200" ]]; then
      bad+=" $path(200)"
      continue
    fi
    if [[ -f "$TRAVERSAL_BODY" ]] && grep -q 'root:x:0:0' "$TRAVERSAL_BODY"; then
      bad+=" $path(泄露 /etc/passwd)"
      continue
    fi
    if [[ "$status" != "400" && "$status" != "403" && "$status" != "404" ]]; then
      bad+=" $path(status=${status:-?})"
    fi
  done
  if [[ -n "$bad" ]]; then
    fail "$id" "$desc（异常:$bad）"
  else
    pass "$id" "$desc"
  fi
}

check_traversal "9.1" "含 .. 的静态路径被拒绝" \
  "/../etc/passwd" \
  "/assets/../../../../etc/passwd" \
  "/static/../../etc/passwd"
check_traversal "9.2" "含 %2e%2e 的静态路径被拒绝" \
  "/%2e%2e/%2e%2e/etc/passwd" \
  "/assets/%2e%2e/%2e%2e/%2e%2e/etc/passwd" \
  "/..%2f..%2fetc%2fpasswd"

out=$(http_call GET "$PANEL_URL/api/nope" --cookie-file "$COOKIE_FILE")
check_json_status "9.3" "已登录访问未知 /api/* 返回 404 JSON（不是 HTML）" 404 "$out"
out=$(http_call GET "$PANEL_URL/api/" --cookie-file "$COOKIE_FILE")
check_json_status "9.3a" "已登录访问 /api/ 返回 404 JSON（不回退 SPA HTML）" 404 "$out"

# 从 index.html 提取构建产物 JS/CSS，逐个抓取并扫描秘密。
SCAN_FILES=("$INDEX_HTML" "$LOGIN_HTML" "$AGENTS_HTML")
if "$PYTHON" "$PROBE" assets --html "$INDEX_HTML" --base "$PANEL_URL" \
    > "$ASSET_LIST" 2>/dev/null; then
  :
else
  fail "9.4" "无法从 index.html 提取静态资源"
fi
mapfile -t ASSETS < "$ASSET_LIST"
ASSET_JS=0
if (( ${#ASSETS[@]} == 0 )); then
  fail "9.4a" "index.html 未引用任何 JS/CSS 资源"
else
  idx=0
  for asset in ${ASSETS[@]+"${ASSETS[@]}"}; do
    asset_body="$TMP_DIR/assets/asset_$idx"
    out=$(http_call GET "$asset" --body-out "$asset_body" 2>/dev/null || true)
    status=$(printf '%s' "$out" | json_field status)
    if [[ "$status" != "200" ]]; then
      fail "9.4b" "静态资源 $asset 返回 ${status:-<无响应>}"
    fi
    SCAN_FILES+=("$asset_body")
    case "$asset" in
      *".js"*) ASSET_JS=$((ASSET_JS + 1)) ;;
    esac
    idx=$((idx + 1))
  done
  if (( ASSET_JS > 0 )); then
    pass "9.4a" "发现 $ASSET_JS 个 JS 构建产物（共 ${#ASSETS[@]} 个静态资源）"
  else
    fail "9.4a" "未发现 JS 构建产物"
  fi
fi

scan_files_no_secret "9.5" "登录 HTML/JS 不含 hub admin_token" \
  "$ADMIN_TOKEN" "${SCAN_FILES[@]}"
scan_files_no_secret "9.6" "登录 HTML/JS 不含明文密码" \
  "$PASSWORD" "${SCAN_FILES[@]}"

SCAN_API_FILES=("$OVERVIEW_BODY" "$SERIES_BODY" "$SETTINGS_BODY" "$BAD_OVERVIEW_BODY")
scan_files_no_secret "9.7" "面板 API 响应不含 hub admin_token" \
  "$ADMIN_TOKEN" "${SCAN_API_FILES[@]}"
scan_files_no_secret "9.8" "面板 API 响应不含明文密码" \
  "$PASSWORD" "${SCAN_API_FILES[@]}"

# ---------------------------------------------------------------------------
# 10. 登出
# ---------------------------------------------------------------------------

echo
echo "==> 10/8 登出与会话失效"
out=$("$PYTHON" "$PROBE" logout --url "$PANEL_URL/api/logout" \
  --cookie-file "$COOKIE_FILE")
LOGOUT_STATUS=$(printf '%s' "$out" | json_field status)
if [[ "$LOGOUT_STATUS" =~ ^2[0-9][0-9]$ ]]; then
  pass "10.1" "POST /api/logout 返回 2xx（$LOGOUT_STATUS）"
else
  fail "10.1" "POST /api/logout 返回 ${LOGOUT_STATUS:-<无响应>}（期望 2xx）"
fi
check_true "10.2" "登出响应清除 rb_session Cookie" \
  "$(printf '%s' "$out" | json_field cleared)"
check_eq "10.2a" "登出 204 的 Content-Type 仍是 application/json" \
  "application/json" "$(printf '%s' "$out" | json_field content_type_base)"

out=$("$PYTHON" "$PROBE" session --url "$PANEL_URL/api/session" \
  --cookie-file "$COOKIE_FILE" --body-out "$SESSION_AFTER_LOGOUT")
check_status "10.3" "登出后旧 Cookie 访问 /api/session 返回 200" 200 "$out"
check_eq "10.3a" "登出后 /api/session authenticated=false" \
  "false" "$(printf '%s' "$out" | json_field authenticated)"

out=$(http_call GET "$PANEL_URL/api/overview" --cookie-file "$COOKIE_FILE")
check_json_status "10.4" "登出后旧 Cookie 访问 /api/overview 返回 401 JSON" 401 "$out"

scan_files_no_secret "10.5" "登出后的 session 响应不含 hub admin_token" \
  "$ADMIN_TOKEN" "$SESSION_AFTER_LOGOUT"
scan_files_no_secret "10.6" "登出后的 session 响应不含明文密码" \
  "$PASSWORD" "$SESSION_AFTER_LOGOUT"

# 日志扫描放在所有运行动作之后，覆盖登录/登出/代理错误等全部日志。
scan_logs_no_secret "9.9" "hub/panel/agent 运行日志不含 hub admin_token" "$ADMIN_TOKEN"
scan_logs_no_secret "9.10" "hub/panel/agent 运行日志不含明文密码" "$PASSWORD"

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

echo
if (( FAILS > 0 )); then
  echo "panel e2e 结果: PASS $PASSES，FAIL $FAILS" >&2
  exit 1
fi
echo "panel e2e 结果: 全部 $PASSES 项通过"
