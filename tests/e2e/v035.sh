#!/usr/bin/env bash
#
# RustBoard v0.3.5 安全收口端到端回归：
#   KI-27  同一来源 IP 的 WebSocket 会话数不超过 max_connections_per_ip；
#          超限连接在建立阶段被拒，全球 max_connections 不被单 IP 占满；
#          另一个源 IP 仍可连接；已 online 的 agent 在洪水期间/之后保持 online。
#   data_dir TOCTOU：data_dir 的中间组件是符号链接时 hub 拒绝启动，
#          链接目标下不得创建子目录、不得 chmod 链接目标。
#   低风险项：admin_auth_failure_limit_per_min=0 时错误 Bearer 仍 401（不 429），
#          每个窗口首条认证失败仍有 WARN；database 外置时启动日志恰好一条 WARN，
#          且不收紧 data_dir 之外的父目录；data_dir 已有 0755 启动后收紧到 0700，
#          外置 DB 文件 0600。
#
# 方案：docs/plans/2026-10-24-v0.3.5-security-followup.md §1、§6.2
#
# 说明：只写测试，不修改实现；断言失败就是失败，不跳过、不弱化。
#      不使用网络；不打印任何凭据；不运行既有 e2e（CI 分别运行）。
#
# 依赖：bash 4.4+、python3 3.8+（仅标准库）、curl、cargo/rustc、timeout、ln。
# 用法：bash tests/e2e/v035.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/v035.sh   # 保留临时目录与脱敏日志
#
set -euo pipefail
# 所有落盘文件（配置、日志、JSON、cookie）默认 0600/0700。
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
V035_AGENT="$SCRIPT_DIR/v035_agent.py"
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}
# 仓库历史遗留跟踪了 tests/e2e/__pycache__/*.pyc；禁止 Python 写字节码。
export PYTHONDONTWRITEBYTECODE=1

# 隔离 target：不同 worktree / 任务不要共用可执行文件；调用方显式设置时优先。
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  export CARGO_TARGET_DIR="$ROOT/target/v035-t1"
fi

PASSES=0
FAILS=0
STATUS=""
BODY=""
LAST_STATUS=""
HUB_PID=""
AGENT_PID=""
FLOOD_PID=""
PIDS=()

ADMIN_TOKEN=""
ENROLL=""
AGENT_ID=""
AGENT_SECRET=""
HUB_BIN=""
AGENT_BIN=""
ADMIN_URL=""
CA=""
FPR=""

pass() {
  PASSES=$((PASSES + 1))
  echo "PASS [$1] $2"
}

fail() {
  FAILS=$((FAILS + 1))
  echo "FAIL [$1] $2" >&2
}

die() {
  echo "FATAL: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# 临时目录与失败现场
# ---------------------------------------------------------------------------

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-v035.XXXXXX")
chmod 700 "$TMP_DIR"
# 记录父目录 / TMP_DIR / 外置 DB 目录启动前的权限：本脚本不得改动它们。
PARENT_DIR=${TMPDIR:-/tmp}
PARENT_MODE_BEFORE=$(stat -c %a "$PARENT_DIR")
TMP_MODE_BEFORE=$(stat -c %a "$TMP_DIR")

HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
HUB_INIT_LOG="$TMP_DIR/hub-init.log"
EXTERNAL_DIR="$TMP_DIR/external"
EXTERNAL_DB="$EXTERNAL_DIR/rustboard.db"
A_CFG="$TMP_DIR/agent.toml"
A_DATA="$TMP_DIR/agent"
A_LOG="$TMP_DIR/agent.log"
BUILD_LOG="$TMP_DIR/build.log"
CURL_ERR="$TMP_DIR/curl.err"
HTTP_BODY_FILE="$TMP_DIR/http-body"
HTTP_HEADERS_FILE="$TMP_DIR/http-headers"
AUTH_SEGMENT="$TMP_DIR/auth-fail-segment.log"
FLOOD_JSON="$TMP_DIR/flood.json"
FLOOD_ERR="$TMP_DIR/flood.err"

SYM_CFG="$TMP_DIR/hub-symlink.toml"
SYM_LOG="$TMP_DIR/hub-symlink.log"
VICTIM="$TMP_DIR/victim"
LINK="$TMP_DIR/link"
SYM_DATA="$LINK/sub"

: > "$HUB_LOG"
: > "$FLOOD_JSON"
: > "$FLOOD_ERR"

mkdir -p "$EXTERNAL_DIR"
chmod 700 "$EXTERNAL_DIR"
EXTERNAL_MODE_BEFORE=$(stat -c %a "$EXTERNAL_DIR")

# 失败现场先脱敏：所有 token / agent secret / Bearer 头。
redact_log() {
  RB_V035_SECRETS="$ADMIN_TOKEN|$ENROLL|$AGENT_SECRET" \
  "$PYTHON" -c '
import os
import re
import sys

secrets = [item for item in os.environ.get("RB_V035_SECRETS", "").split("|") if item]
text = sys.stdin.buffer.read().decode("utf-8", "replace")
for secret in secrets:
    text = text.replace(secret, "<redacted>")
text = re.sub(r"(Bearer )[^\s]+", r"\1<redacted>", text)
text = re.sub(r"(管理 API token:).*", r"\1 <redacted>", text)
text = re.sub(r"(一次性 token[^:：]*[:：]).*", r"\1 <redacted>", text)
sys.stdout.write(text)
'
}

dump_log() {
  local log=$1 lines=${2:-100}
  if [[ -s "$log" ]]; then
    echo "---- $(basename "$log") (tail -n $lines) ----" >&2
    redact_log < "$log" | tail -n "$lines" >&2 || true
  fi
}

drop_pid() {
  local target=$1
  local remaining=()
  local pid
  for pid in ${PIDS[@]+"${PIDS[@]}"}; do
    if [[ "$pid" != "$target" ]]; then
      remaining+=("$pid")
    fi
  done
  PIDS=(${remaining[@]+"${remaining[@]}"})
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
    echo "===== v035 e2e 失败现场（日志已脱敏）=====" >&2
    for log in "$HUB_LOG" "$A_LOG" "$HUB_INIT_LOG" "$SYM_LOG" "$BUILD_LOG" \
               "$FLOOD_ERR" "$CURL_ERR"; do
      dump_log "$log" 120
    done
    if [[ -s "$FLOOD_JSON" ]]; then
      echo "---- $(basename "$FLOOD_JSON") ----" >&2
      cat "$FLOOD_JSON" >&2 || true
    fi
    echo "已通过 $PASSES 项，失败 $FAILS 项" >&2
  fi

  if [[ "${KEEP_E2E_TMP:-0}" == "1" ]]; then
    echo "临时目录已保留: $TMP_DIR" >&2
  else
    # 只删除本脚本 mktemp 出来的目录，避免误删其它路径。
    if [[ -n "${TMP_DIR:-}" && "$TMP_DIR" == "${TMPDIR:-/tmp}"/rustboard-v035.* ]]; then
      rm -rf -- "$TMP_DIR"
    else
      echo "警告: 临时目录不符合预期，未删除: ${TMP_DIR:-<unset>}" >&2
    fi
  fi
  exit "$code"
}
trap cleanup EXIT

for tool in "$PYTHON" "$CARGO" curl mktemp date tail awk sed grep stat tr cat find wc \
            timeout ln; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "找不到命令: $tool（python3 需 3.8+；cargo 请放进 PATH 或设置 CARGO=...）"
done
[[ -f "$V035_AGENT" ]] || die "缺少 v035 fake agent: $V035_AGENT"

# ---------------------------------------------------------------------------
# 通用工具（与 v034.sh 同风格，本脚本自带，不 source）
# ---------------------------------------------------------------------------

pick_ports() {
  local count=${1:-3}
  "$PYTHON" - "$count" <<'PY'
import random
import socket
import sys

count = int(sys.argv[1])
chosen = []
while len(chosen) < count:
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

# 从 TOML 配置读取一个字符串标量（只匹配 key = "value" 行）。
cfg_str() {
  "$PYTHON" - "$1" "$2" <<'PY'
import re
import sys

path, key = sys.argv[1], sys.argv[2]
pattern = re.compile(r'^\s*' + re.escape(key) + r'\s*=\s*"([^"]*)"\s*(?:#.*)?$')
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

# 覆盖或插入一个顶层 TOML 标量；RHS 已是合法字面量（数字/布尔/带引号字符串）。
# 必须插在第一个 [section] 之前，否则会落进 [control] 表。
set_top_scalar() {
  "$PYTHON" - "$1" "$2" "$3" <<'PY'
import re
import sys

path, key, rhs = sys.argv[1], sys.argv[2], sys.argv[3]
with open(path, encoding="utf-8") as handle:
    lines = handle.read().splitlines()
pattern = re.compile(r'^\s*' + re.escape(key) + r'\s*=')
indexes = [i for i, line in enumerate(lines) if pattern.match(line)]
if len(indexes) > 1:
    raise SystemExit(f"配置 {path} 中 {key} 出现 {len(indexes)} 次（期望 0/1）")
new_line = f"{key} = {rhs}"
if indexes:
    lines[indexes[0]] = new_line
else:
    insert_at = next(
        (i for i, line in enumerate(lines) if line.lstrip().startswith("[")),
        len(lines),
    )
    lines.insert(insert_at, new_line)
with open(path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
PY
  chmod 600 "$1"
}

# 从 JSON 文件取字段；表达式里 d 是解析后的对象。
json_get() {
  local expr=$1 file=${2:-$HTTP_BODY_FILE}
  "$PYTHON" - "$expr" "$file" <<'PY'
import json
import sys

expr, path = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding="utf-8") as handle:
        d = json.load(handle)
    value = eval(expr, {"__builtins__": {}}, {
        "d": d,
        "len": len,
        "sorted": sorted,
        "any": any,
        "all": all,
        "int": int,
        "str": str,
    })
    print(value)
except Exception:
    print("__ERR__")
PY
}

# 文件名模式；文件缺失返回 MISSING。
file_mode() {
  stat -c %a "$1" 2>/dev/null || printf 'MISSING'
}

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$expected]，实际 [$actual]）"
  fi
}

check_ne() {
  local id=$1 desc=$2 unexpected=$3 actual=$4
  if [[ "$unexpected" != "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（不应为 [$unexpected]）"
  fi
}

expect_status() {
  local id=$1 desc=$2 expected=$3
  if [[ "$STATUS" == "$expected" ]]; then
    pass "$id" "$desc：HTTP $expected"
  else
    local preview
    preview=$(printf '%s' "$BODY" | head -c 300)
    fail "$id" "$desc（期望 HTTP $expected，实际 $STATUS；body=${preview}）"
  fi
}

# 鉴权错误结构：{"error":"unauthorized"} / {"error":"rate_limited"}。
expect_flat_error() {
  local id=$1 desc=$2 expected=$3
  local value
  value=$(json_get 'd.get("error")')
  if [[ "$value" == "$expected" ]]; then
    pass "$id" "$desc：error=$expected"
  else
    fail "$id" "$desc（期望 error=$expected，实际 [$value]）"
  fi
}

# 管理 API；token 可覆盖（默认 admin_token）。可选第 5 个参数保存响应头。
api_as() {
  local token=$1 method=$2 path=$3 data=${4:-} hdrs=${5:-}
  local -a args=(
    -sS --noproxy '*' --max-time 25 -o "$HTTP_BODY_FILE" -w '%{http_code}'
    -X "$method" "${ADMIN_URL}${path}"
    -H "Authorization: Bearer ${token}"
    -H 'Content-Type: application/json'
    -H 'Accept: application/json'
  )
  if [[ -n "$hdrs" ]]; then
    args+=(-D "$hdrs")
  fi
  if [[ -n "$data" ]]; then
    args+=(--data-binary "$data")
  fi
  STATUS=$(curl "${args[@]}" 2>"$CURL_ERR") || STATUS="000"
  BODY=$(cat "$HTTP_BODY_FILE" 2>/dev/null || true)
}

api() {
  api_as "$ADMIN_TOKEN" "$@"
}

http_code() {
  local url=$1
  local code
  code=$(curl -sS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' \
    "$url" 2>/dev/null) || code="000"
  printf '%s' "$code"
}

wait_health() {
  local url=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local code
  while :; do
    code=$(http_code "$url")
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.15
  done
}

read_agent_status() {
  local id=$1
  api GET "/api/v1/agents"
  if [[ "$STATUS" != "200" ]]; then
    echo ""
    return 0
  fi
  "$PYTHON" - "$id" "$HTTP_BODY_FILE" <<'PY'
import json
import sys

agent_id, path = sys.argv[1], sys.argv[2]
try:
    with open(path, encoding="utf-8") as handle:
        agents = json.load(handle)
except Exception:
    print("")
    raise SystemExit(0)
for agent in agents if isinstance(agents, list) else []:
    if agent.get("agent_id") == agent_id:
        print(agent.get("status", ""))
        break
PY
}

wait_agent_status() {
  local id=$1 expected=$2 timeout=$3
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local status
  while :; do
    status=$(read_agent_status "$id" 2>/dev/null || true)
    if [[ "$status" == "$expected" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      LAST_STATUS=$status
      return 1
    fi
    sleep 0.15
  done
}

# `hub agent add` 的一次性 token（只解析，不打印）。
add_agent_token() {
  local name=$1 out token
  out=$("$HUB_BIN" agent add --config "$HUB_CFG" --name "$name" 2>/dev/null) \
    || die "agent add --name $name 失败"
  token=$(printf '%s\n' "$out" \
    | awk '/一次性 token/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}')
  [[ "$token" =~ ^[0-9a-f]{64}$ ]] \
    || die "无法从 agent add 输出解析 enrollment token（不打印内容）"
  printf '%s' "$token"
}

write_agent_config() {
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

start_hub() {
  RUST_LOG=rustboard_hub=info "$HUB_BIN" run --config "$HUB_CFG" >> "$HUB_LOG" 2>&1 &
  HUB_PID=$!
  PIDS+=("$HUB_PID")
  wait_health "$ADMIN_URL/healthz" 20 \
    || die "hub 未在 20s 内就绪（${ADMIN_URL}/healthz，见 hub.log）"
}

# 启动 agent 并等待 enrollment；PID 通过全局 STARTED_AGENT_PID 返回。
start_agent() {
  local cfg=$1 log=$2 data=$3
  RUST_LOG=rustboard_agent=info "$AGENT_BIN" run --config "$cfg" > "$log" 2>&1 &
  STARTED_AGENT_PID=$!
  PIDS+=("$STARTED_AGENT_PID")
  wait_for_file "$data/agent_id" 20 \
    || die "agent 未在 20s 内完成 enrollment（$(basename "$log")）"
}

check_log_absent() {
  local id=$1 file=$2 desc=$3 value=$4
  if [[ -z "$value" ]]; then
    fail "$id" "$desc（待检查凭据为空，无法断言）"
  elif [[ ! -s "$file" ]]; then
    fail "$id" "$desc（日志为空，无法断言不包含）"
  elif grep -Fq -- "$value" "$file"; then
    fail "$id" "$desc（日志出现凭据明文）"
  else
    pass "$id" "$desc"
  fi
}

panic_count() {
  local file=$1
  awk '/panicked at|thread .* panicked|RUST_BACKTRACE/ { n++ } END { print n + 0 }' \
    "$file" 2>/dev/null || true
}

# 进程仍存活且不是在等回收的僵尸（flood 保持阶段的判据）。
is_running() {
  local pid=$1 state
  kill -0 "$pid" 2>/dev/null || return 1
  if [[ -r "/proc/$pid/stat" ]]; then
    state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
    [[ "$state" != "Z" ]] || return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 构建与初始化
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub / rustboard-agent（CARGO_TARGET_DIR=$CARGO_TARGET_DIR）"
if ! (cd "$ROOT" && "$CARGO" build --locked -p rustboard-hub -p rustboard-agent) \
      > "$BUILD_LOG" 2>&1; then
  dump_log "$BUILD_LOG" 100
  die "cargo build 失败"
fi
TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
HUB_BIN="$TARGET_DIR/debug/rustboard-hub"
AGENT_BIN="$TARGET_DIR/debug/rustboard-agent"
[[ -x "$HUB_BIN" ]] || die "找不到 $HUB_BIN"
[[ -x "$AGENT_BIN" ]] || die "找不到 $AGENT_BIN"
pass "0.1" "cargo build rustboard-hub / rustboard-agent 成功（隔离 target）"

PORT_LINE=$(pick_ports 4) || die "无法挑选 4 个空闲端口"
read -r AGENT_PORT ADMIN_PORT SYM_AGENT_PORT SYM_ADMIN_PORT <<< "$PORT_LINE"
for port in "$AGENT_PORT" "$ADMIN_PORT" "$SYM_AGENT_PORT" "$SYM_ADMIN_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] || die "端口解析失败: $PORT_LINE"
done
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}"

echo "==> 初始化 hub（agent=${AGENT_PORT} admin=${ADMIN_PORT}）"
if ! "$HUB_BIN" init \
    --config "$HUB_CFG" \
    --data-dir "$HUB_DATA" \
    --agent-listen "127.0.0.1:${AGENT_PORT}" \
    --admin-listen "127.0.0.1:${ADMIN_PORT}" \
    --san 127.0.0.1 \
    --force > "$HUB_INIT_LOG" 2>&1; then
  dump_log "$HUB_INIT_LOG" 80
  die "hub init 失败"
fi
chmod 600 "$HUB_CFG"
pass "0.2" "hub init 成功（config 0600）"

# 小实例：per-IP 2、全局 8；关闭管理面限速以便单独观察 limit=0 的 WARN 行为。
# data_dir 与 database 显式写回，避免 init 默认值影响断言。
set_top_scalar "$HUB_CFG" data_dir "\"$HUB_DATA\""
set_top_scalar "$HUB_CFG" database "\"sqlite://$EXTERNAL_DB\""
set_top_scalar "$HUB_CFG" max_connections_per_ip "2"
set_top_scalar "$HUB_CFG" max_connections "8"
set_top_scalar "$HUB_CFG" admin_auth_failure_limit_per_min "0"
set_top_scalar "$HUB_CFG" admin_rate_limit_per_min "0"
set_top_scalar "$HUB_CFG" admin_write_rate_limit_per_min "0"
set_top_scalar "$HUB_CFG" self_monitor "false"
grep -q '^max_connections_per_ip = 2$' "$HUB_CFG" || die "max_connections_per_ip 未写入"
grep -q '^max_connections = 8$' "$HUB_CFG" || die "max_connections 未写入"
grep -q '^admin_auth_failure_limit_per_min = 0$' "$HUB_CFG" \
  || die "admin_auth_failure_limit_per_min 未写入"
grep -q '^admin_rate_limit_per_min = 0$' "$HUB_CFG" || die "admin_rate_limit_per_min 未写入"
grep -q '^admin_write_rate_limit_per_min = 0$' "$HUB_CFG" \
  || die "admin_write_rate_limit_per_min 未写入"
grep -q '^self_monitor = false$' "$HUB_CFG" || die "self_monitor 未写入"
check_eq "0.3a" "配置 data_dir 指向临时目录" "$HUB_DATA" "$(cfg_str "$HUB_CFG" data_dir)"
check_eq "0.3b" "配置 database 指向外置路径" "sqlite://$EXTERNAL_DB" \
  "$(cfg_str "$HUB_CFG" database)"
pass "0.3" "小实例配置就绪（per-IP 2 / 全局 8 / limit=0 / 外置 DB）"

ADMIN_TOKEN=$(cfg_str "$HUB_CFG" admin_token) || die "无法解析 hub admin_token"
[[ "$ADMIN_TOKEN" =~ ^[0-9a-f]{64}$ ]] || die "hub admin_token 非法（不打印内容）"
CA="$HUB_DATA/certs/ca.crt"
[[ -f "$CA" ]] || die "缺少 CA 证书: $CA"
FPR=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p') \
  || die "无法读取服务端证书指纹"
[[ "$FPR" =~ ^[0-9a-f]{64}$ ]] || die "服务端证书指纹非法"

# enrollment token / agent 配置在 hub 启动前生成，避免 CLI 与运行中的 hub 抢 DB 写锁。
ENROLL=$(add_agent_token "v035-flood")
write_agent_config "$A_CFG" "v035-flood" "$ENROLL" "$A_DATA"
pass "0.3c" "enrollment token 与 agent 配置已生成（token 不打印）"

# 启动前把已有 data_dir 放宽到 0755；hub 启动后必须收紧回 0700。
chmod 0755 "$HUB_DATA"
check_eq "0.4" "启动前 data_dir 已预置 0755" "755" "$(file_mode "$HUB_DATA")"

echo "==> 启动 hub（外置 DB: $EXTERNAL_DIR，data_dir 0755 待收紧）"
start_hub
pass "0.5" "hub 管理口 /healthz 返回 200（${ADMIN_URL}）"

echo "==> 1) data_dir / 外置 DB / 权限"

check_eq "1.1" "hub 启动后 data_dir 收紧为 0700" "700" "$(file_mode "$HUB_DATA")"

if wait_for_file "$EXTERNAL_DB" 10; then
  pass "1.2" "外置数据库文件已创建（$EXTERNAL_DIR）"
  check_eq "1.3" "外置数据库文件权限 0600" "600" "$(file_mode "$EXTERNAL_DB")"
else
  fail "1.2" "外置数据库文件未在 10s 内创建：$EXTERNAL_DB"
fi
for suffix in -wal -shm; do
  if [[ -e "$EXTERNAL_DB$suffix" ]]; then
    check_eq "1.4$suffix" "外置数据库 ${suffix} 文件权限 0600" "600" \
      "$(file_mode "$EXTERNAL_DB$suffix")"
  fi
done

DB_WARN_COUNT=$(awk '/WARN/ && /数据库/ && /data_dir/ { n++ } END { print n + 0 }' "$HUB_LOG")
check_eq "1.5" "外置 database 启动 WARN 恰好 1 条" "1" "$DB_WARN_COUNT"

check_eq "1.6" "外置 DB 目录权限未被改动（$EXTERNAL_MODE_BEFORE）" \
  "$EXTERNAL_MODE_BEFORE" "$(file_mode "$EXTERNAL_DIR")"
check_eq "1.7" "TMP_DIR 权限未被改动（$TMP_MODE_BEFORE）" \
  "$TMP_MODE_BEFORE" "$(file_mode "$TMP_DIR")"
check_eq "1.8" "父目录权限未被改动（$PARENT_DIR=$PARENT_MODE_BEFORE）" \
  "$PARENT_MODE_BEFORE" "$(file_mode "$PARENT_DIR")"

# ---------------------------------------------------------------------------
# 2) 真实 agent 上线
# ---------------------------------------------------------------------------

echo
echo "==> 2) 启动真实 agent A（源 IP 127.0.0.1）"

start_agent "$A_CFG" "$A_LOG" "$A_DATA"
AGENT_PID=$STARTED_AGENT_PID
AGENT_ID=$(tr -d '[:space:]' < "$A_DATA/agent_id")
AGENT_SECRET=$(tr -d '[:space:]' < "$A_DATA/agent.secret")
[[ -n "$AGENT_ID" ]] || die "agent_id 为空"
[[ "$AGENT_SECRET" =~ ^[0-9a-f]{64}$ ]] || die "agent secret 非法（不打印内容）"
[[ -f "$A_DATA/agent.crt" && -f "$A_DATA/agent.key" ]] || die "缺少 agent 证书/私钥"
wait_agent_status "$AGENT_ID" online 20 \
  || die "agent A 未 online（最后: $LAST_STATUS）"
pass "2.1" "agent A 完成 enrollment 并 online（源 IP 127.0.0.1）"

# ---------------------------------------------------------------------------
# 3) KI-27：per-IP 连接上限（flood）
# ---------------------------------------------------------------------------

echo
echo "==> 3) KI-27 同源 IP 第 3 条 WS 拒绝、另一源 IP 可连、A 保持 online"

"$PYTHON" "$V035_AGENT" flood \
  --url "wss://127.0.0.1:${AGENT_PORT}/agent/ws" \
  --ca "$CA" \
  --cert "$A_DATA/agent.crt" \
  --key "$A_DATA/agent.key" \
  --agent-id "$AGENT_ID" \
  --secret-file "$A_DATA/agent.secret" \
  --primary-ip 127.0.0.2 \
  --primary-count 2 \
  --other-ip 127.0.0.3 \
  --hold-seconds 10 \
  > "$FLOOD_JSON" 2> "$FLOOD_ERR" &
FLOOD_PID=$!
PIDS+=("$FLOOD_PID")

# helper 在连接全部建立后先输出 JSON，再保持连接 hold-seconds 秒；
# JSON 文件非空即表示 flood 已进入“保持打开”阶段。
if ! wait_for_file "$FLOOD_JSON" 30; then
  dump_log "$FLOOD_ERR"
  fail "3.1" "flood helper 未在 30s 内输出 JSON（连接未能建立）"
else
  pass "3.1" "flood helper 已建立连接并输出 JSON"
fi

FLOOD_DURING=no
if is_running "$FLOOD_PID"; then
  FLOOD_DURING=yes
fi
DURING_STATUS=$(read_agent_status "$AGENT_ID")
DURING_HTTP=$STATUS
check_eq "3.2" "flood 保持期间管理 API 查询返回 200" "200" "$DURING_HTTP"
check_eq "3.3" "flood 保持期间 A 仍 online" "online" "$DURING_STATUS"
check_eq "3.4" "查询时 flood helper 仍在运行（连接仍保持）" "yes" "$FLOOD_DURING"

FLOOD_RC=0
wait "$FLOOD_PID" || FLOOD_RC=$?
drop_pid "$FLOOD_PID"
FLOOD_PID=""
check_eq "3.5" "flood helper 正常退出" "0" "$FLOOD_RC"

if [[ -s "$FLOOD_JSON" ]]; then
  check_eq "3.6" "同源 IP 前 2 条均拿到 Welcome（opened）" "2" \
    "$(json_get 'd.get("opened")' "$FLOOD_JSON")"
  check_eq "3.7" "第 3 条同源连接被拒绝（same_ip_rejected）" "True" \
    "$(json_get 'str(d.get("same_ip_rejected"))' "$FLOOD_JSON")"
  SAME_IP_TYPE=$(json_get 'd.get("same_ip_error_type")' "$FLOOD_JSON")
  if [[ -n "$SAME_IP_TYPE" && "$SAME_IP_TYPE" != "__ERR__" ]]; then
    pass "3.8" "拒绝已记录异常类型：$SAME_IP_TYPE"
  else
    fail "3.8" "拒绝未记录异常类型（实际 [$SAME_IP_TYPE]）"
  fi
  check_eq "3.9" "另一源 IP 127.0.0.3 可连接（other_ip_ok）" "True" \
    "$(json_get 'str(d.get("other_ip_ok"))' "$FLOOD_JSON")"
  check_eq "3.10" "flood helper 未记录内部错误" "" \
    "$(json_get 'd.get("error")' "$FLOOD_JSON")"
else
  fail "3.6" "flood JSON 缺失，无法断言 opened / same_ip_rejected / other_ip_ok"
  fail "3.7" "flood JSON 缺失，无法断言同源拒绝"
  fail "3.8" "flood JSON 缺失，无法断言拒绝异常类型"
  fail "3.9" "flood JSON 缺失，无法断言另一源 IP 可用"
  fail "3.10" "flood JSON 缺失，无法断言 helper 无内部错误"
fi

# flood 结束后真实 agent 可能被同 agent_id 的新连接顶掉并重连；等待恢复 online。
if wait_agent_status "$AGENT_ID" online 30; then
  pass "3.11" "flood 结束后 A 仍为 online"
else
  fail "3.11" "flood 结束后 A 未恢复 online（最后: $LAST_STATUS）"
fi

# per-IP 拒绝日志：方案未固定文案，有明确日志时给出观测值，不作为硬断言。
PER_IP_LOG_COUNT=$(awk '/WARN|INFO/ && (/per[-_ ]?ip/ || /连接数.*上限/ || /连接上限/ || /too many connections/) { n++ } END { print n + 0 }' "$HUB_LOG")
echo "NOTE [3.12] per-IP 拒绝日志行数（参考，不强制）：$PER_IP_LOG_COUNT"

# ---------------------------------------------------------------------------
# 4) limit=0：错误 Bearer 始终 401、不 429，首条 WARN 仍可见
# ---------------------------------------------------------------------------

echo
echo "==> 4) admin_auth_failure_limit_per_min=0 的边界"

AUTH_BOUNDARY=$(wc -l < "$HUB_LOG") || true
WRONG1="v035-wrong-$(date +%s)-$RANDOM-a"
WRONG2="v035-wrong-$(date +%s)-$RANDOM-b"

api_as "$WRONG1" GET "/api/v1/agents"
S1=$STATUS
expect_status "4.1" "limit=0 第 1 次错误 Bearer 返回 401" "401"
expect_flat_error "4.2" "第 1 次错误 Bearer 错误结构" "unauthorized"

api_as "$WRONG2" GET "/api/v1/agents"
S2=$STATUS
expect_status "4.3" "limit=0 第 2 次错误 Bearer 返回 401" "401"
expect_flat_error "4.4" "第 2 次错误 Bearer 错误结构" "unauthorized"

if [[ "$S1" != "429" && "$S2" != "429" ]]; then
  pass "4.5" "limit=0 连续两次错误 Bearer 均未出现 429"
else
  fail "4.5" "limit=0 出现 429（实际 [$S1] [$S2]）"
fi

tail -n +$((AUTH_BOUNDARY + 1)) "$HUB_LOG" > "$AUTH_SEGMENT" 2>/dev/null || true
WARN_COUNT=$(awk '/WARN/ && /管理 API 鉴权失败/ { n++ } END { print n + 0 }' "$AUTH_SEGMENT")
check_eq "4.6" "limit=0 时首条认证失败 WARN 恰好 1 条" "1" "$WARN_COUNT"

# ---------------------------------------------------------------------------
# 5) data_dir 中间符号链接：拒绝启动且不触碰链接目标
# ---------------------------------------------------------------------------

echo
echo "==> 5) data_dir 中间 symlink 拒绝启动"

mkdir -p "$VICTIM"
chmod 0755 "$VICTIM"
ln -s "$VICTIM" "$LINK"
[[ -L "$LINK" ]] || die "无法创建符号链接: $LINK"
pass "5.1" "已创建 $LINK -> $VICTIM（victim 0755）"

cp "$HUB_CFG" "$SYM_CFG"
chmod 600 "$SYM_CFG"
set_top_scalar "$SYM_CFG" data_dir "\"$SYM_DATA\""
set_top_scalar "$SYM_CFG" database "\"sqlite://$SYM_DATA/rustboard.db\""
set_top_scalar "$SYM_CFG" agent_listen "\"127.0.0.1:${SYM_AGENT_PORT}\""
set_top_scalar "$SYM_CFG" admin_listen "\"127.0.0.1:${SYM_ADMIN_PORT}\""
check_eq "5.2" "symlink 用例 data_dir 指向 link/sub" "$SYM_DATA" \
  "$(cfg_str "$SYM_CFG" data_dir)"

SYM_RC=0
timeout 10 "$HUB_BIN" run --config "$SYM_CFG" > "$SYM_LOG" 2>&1 || SYM_RC=$?

if (( SYM_RC > 0 && SYM_RC < 128 )); then
  pass "5.3" "中间 symlink 的 data_dir 使 hub 非零退出（rc=$SYM_RC）"
else
  fail "5.3" "中间 symlink 的 data_dir 未以普通错误退出（rc=$SYM_RC；124 表示超时挂起）"
fi
check_ne "5.4" "hub 未因超时被杀（rc≠124）" "124" "$SYM_RC"

if [[ -e "$VICTIM/sub" || -L "$VICTIM/sub" ]]; then
  fail "5.5" "拒绝启动后链接目标下不应存在 sub（$VICTIM/sub）"
else
  pass "5.5" "拒绝启动未在链接目标下创建 sub"
fi
check_eq "5.6" "链接目标 victim 权限仍为 0755" "755" "$(file_mode "$VICTIM")"
check_eq "5.7" "symlink 用例日志无 panic" "0" "$(panic_count "$SYM_LOG")"

# ---------------------------------------------------------------------------
# 6) 日志不泄露凭据、不 panic
# ---------------------------------------------------------------------------

echo
echo "==> 6) 日志脱敏与稳定性"

check_log_absent "6.1" "$HUB_LOG" "hub 日志不含 agent secret" "$AGENT_SECRET"
check_log_absent "6.2" "$HUB_LOG" "hub 日志不含 admin token" "$ADMIN_TOKEN"
check_log_absent "6.3" "$A_LOG" "agent 日志不含 agent secret" "$AGENT_SECRET"
check_log_absent "6.4" "$A_LOG" "agent 日志不含 admin token" "$ADMIN_TOKEN"
check_eq "6.5" "hub 日志无 panic" "0" "$(panic_count "$HUB_LOG")"
check_eq "6.6" "agent 日志无 panic" "0" "$(panic_count "$A_LOG")"

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

echo
echo "=============================================="
echo "v0.3.5 e2e 汇总：PASSES=$PASSES FAILS=$FAILS"
echo "=============================================="
if (( FAILS > 0 )); then
  echo "结果：FAIL" >&2
  exit 1
fi
echo "结果：PASS"
