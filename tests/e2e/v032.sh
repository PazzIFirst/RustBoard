#!/usr/bin/env bash
#
# RustBoard v0.3.2 端到端回归：
#   #18 ControlSession pending 超时清理
#   #16 续签期间 busy_renewing 的 Hub/API 映射与审计
#   #19 journald tail 保留最新内容
#
# 方案：docs/plans/2026-10-23-v0.3.2-control-reliability.md
#       §4.1 / §4.2 / §4.4 / §6.2
#
# 覆盖：
#   1. 真实 agent 完成 enrollment 后停掉，用它的 agent_id / agent.secret /
#      客户端证书启动 fake agent（Hello capabilities=["systemd"]），保持在线但
#      故意不回复 ControlRequest。hub 配置 request_timeout_ms=1000、
#      max_pending_per_session=2；连续 3 个控制请求都必须约 1s 返回
#      504 control_timeout，第 3 个绝不能因 pending 泄漏变成 429
#      too_many_pending；再等 2s 发第 4 个仍为 504；审计 4 条
#      result=error / error_code=control_timeout。
#   2. fake agent 切到 busy 模式：收到 ControlRequest 立即按请求 id 回
#      busy_renewing。HTTP 503、固定文案、耗时远小于 1s（不是 504/502），
#      审计 result=error / error_code=busy_renewing；连续 2 次都成立，证明
#      id 匹配没有退化成超时。真实 renew_client_cert() 分支由 Rust 单元测试
#      覆盖，本脚本只验证 Hub 的映射与审计。
#   3. 第二个真实 agent 开启 logs=true、systemd_units=["nginx*"]，
#      journalctl_path 指向 fake 脚本。fake 记录参数，输出 1000 行 × 约 1KiB、
#      新→旧（模拟 journalctl --reverse）；tail 返回旧→新、最后一行含
#      line-1000、truncated=true、总字节 ≤256 KiB，journalctl 参数含
#      --reverse 与 -n；另用小输出验证不截断、顺序正确。
#
# 说明：fake agent 不执行任何控制动作，不伪造成功；测试不会弱化断言。
#
# 依赖：bash 4.4+、python3（仅标准库）、curl、cargo/rustc。
# 用法：bash tests/e2e/v032.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/v032.sh   # 保留临时目录与脱敏日志
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}
FAKE_AGENT="$SCRIPT_DIR/v032_agent.py"
# 仓库历史遗留跟踪了 tests/e2e/__pycache__/probe.*.pyc；禁止 Python 写字节码，
# 避免运行 e2e 后把已跟踪的 pyc 改脏（不影响脚本自身逻辑）。
export PYTHONDONTWRITEBYTECODE=1

PASSES=0
FAILS=0
PIDS=()
LAST_STATUS=""
HUB_PID=""
A_PID=""
B_PID=""
FAKE_PID=""
STARTED_AGENT_PID=""
A_ID=""
B_ID=""
A_SECRET=""
ADMIN_TOKEN=""
TOKEN_A=""
TOKEN_B=""
ADMIN_URL=""
AGENT_URL=""
STATUS=""
API_SECONDS="0"
BODY=""
HUB_BIN=""
AGENT_BIN=""

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

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-v032.XXXXXX")
HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
HUB_CTL="$TMP_DIR/hub-control.toml"
A_CFG="$TMP_DIR/agent-a.toml"
A_DATA="$TMP_DIR/agent-a"
A_LOG="$TMP_DIR/agent-a.log"
B_CFG="$TMP_DIR/agent-b.toml"
B_DATA="$TMP_DIR/agent-b"
B_LOG="$TMP_DIR/agent-b.log"
FAKE_LOG="$TMP_DIR/fake-agent.log"
FAKE_READY="$TMP_DIR/fake-agent.ready"
FAKE_MODE="$TMP_DIR/fake-agent.mode"
FAKE_DIR="$TMP_DIR/fake"
JOURNAL_ARGV="$FAKE_DIR/journalctl.argv"
JOURNAL_BIG_OUT="$FAKE_DIR/journal-big.out"
JOURNAL_SMALL_OUT="$FAKE_DIR/journal-small.out"
BUILD_LOG="$TMP_DIR/build.log"
INIT_LOG="$TMP_DIR/init.log"
HTTP_BODY_FILE="$TMP_DIR/http-body"
AUDIT_JSON="$TMP_DIR/audit.json"
AGENTS_JSON="$TMP_DIR/agents.json"
mkdir -p "$FAKE_DIR"
chmod 700 "$TMP_DIR" "$FAKE_DIR"

# 失败现场先脱敏：token / agent secret / Bearer 头一律替换后再打印。
redact_log() {
  RB_ADMIN_TOKEN="${ADMIN_TOKEN:-}" RB_TOKEN_A="${TOKEN_A:-}" \
  RB_TOKEN_B="${TOKEN_B:-}" RB_AGENT_SECRET="${A_SECRET:-}" \
  "$PYTHON" -c '
import os
import re
import sys

secrets = [
    os.environ.get("RB_ADMIN_TOKEN", ""),
    os.environ.get("RB_TOKEN_A", ""),
    os.environ.get("RB_TOKEN_B", ""),
    os.environ.get("RB_AGENT_SECRET", ""),
]
text = sys.stdin.buffer.read().decode("utf-8", "replace")
for secret in secrets:
    if secret:
        text = text.replace(secret, "<redacted>")
text = re.sub(r"(Bearer )[^\s]+", r"\1<redacted>", text)
text = re.sub(r"(管理 API token:).*", r"\1 <redacted>", text)
text = re.sub(r"(一次性 token[^:：]*[:：]).*", r"\1 <redacted>", text)
sys.stdout.write(text)
'
}

dump_log() {
  local log=$1 lines=${2:-80}
  if [[ -s "$log" ]]; then
    echo "---- $(basename "$log") (tail -n $lines) ----" >&2
    redact_log < "$log" | tail -n "$lines" >&2 || true
  fi
}

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
    echo "===== v032 e2e 失败现场 =====" >&2
    for log in "$HUB_LOG" "$A_LOG" "$B_LOG" "$FAKE_LOG" "$INIT_LOG" "$BUILD_LOG" \
               "$TMP_DIR/curl.err"; do
      dump_log "$log" 100
    done
    if [[ -s "$JOURNAL_ARGV" ]]; then
      echo "---- journalctl.argv ----" >&2
      cat "$JOURNAL_ARGV" >&2 || true
    fi
    echo "已通过 $PASSES 项，失败 $FAILS 项" >&2
  fi

  if [[ "${KEEP_E2E_TMP:-0}" == "1" ]]; then
    echo "临时目录已保留: $TMP_DIR" >&2
  else
    rm -rf "$TMP_DIR"
  fi
  exit "$code"
}
trap cleanup EXIT

for tool in "$PYTHON" "$CARGO" curl timeout mktemp date tail awk sed grep stat cat; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "找不到命令: $tool（python3 需 3.8+；cargo 请放进 PATH 或设置 CARGO=...）"
done
[[ -f "$FAKE_AGENT" ]] || die "缺少 fake agent: $FAKE_AGENT"

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

# 从 TOML 配置里读取一个字符串标量（只匹配 key = "value" 的行）。
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

# 从 JSON 文件取字段；表达式里 d 是解析后的对象。
json_get() {
  "$PYTHON" - "$1" "$2" <<'PY'
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

api() {
  local method=$1 path=$2 data=${3:-}
  local -a args=(
    -sS --max-time 15 -o "$HTTP_BODY_FILE" -w '%{http_code} %{time_total}'
    -X "$method" "${ADMIN_URL}${path}"
    -H "Authorization: Bearer ${ADMIN_TOKEN}"
    -H 'Content-Type: application/json'
    -H 'Accept: application/json'
  )
  [[ -n "$data" ]] && args+=(--data-binary "$data")
  local out
  if out=$(curl "${args[@]}" 2>"$TMP_DIR/curl.err"); then
    :
  else
    out="000 0"
  fi
  STATUS=${out%% *}
  API_SECONDS=${out##* }
  BODY=$(cat "$HTTP_BODY_FILE" 2>/dev/null || true)
}

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$expected]，实际 [$actual]）"
  fi
}

check_contains() {
  local id=$1 desc=$2 haystack=$3 needle=$4
  if [[ "$haystack" == *"$needle"* ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（未找到 [$needle]）"
  fi
}

check_not_contains() {
  local id=$1 desc=$2 haystack=$3 needle=$4
  if [[ "$haystack" != *"$needle"* ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（不应出现 [$needle]）"
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

expect_error_code() {
  local id=$1 desc=$2 expected=$3
  local code
  code=$(json_get 'd.get("error", {}).get("code", "")' "$HTTP_BODY_FILE")
  if [[ "$code" == "$expected" ]]; then
    pass "$id" "$desc：code=$expected"
  else
    fail "$id" "$desc（期望 code=$expected，实际 [$code]）"
  fi
}

check_elapsed_min() {
  local id=$1 desc=$2 minimum=$3
  if "$PYTHON" -c 'import sys; sys.exit(0 if float(sys.argv[1]) >= float(sys.argv[2]) else 1)' \
      "$API_SECONDS" "$minimum"; then
    pass "$id" "$desc：${API_SECONDS}s"
  else
    fail "$id" "$desc（期望 ≥${minimum}s，实际 ${API_SECONDS}s）"
  fi
}

check_elapsed_max() {
  local id=$1 desc=$2 maximum=$3
  if "$PYTHON" -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= float(sys.argv[2]) else 1)' \
      "$API_SECONDS" "$maximum"; then
    pass "$id" "$desc：${API_SECONDS}s"
  else
    fail "$id" "$desc（期望 ≤${maximum}s，实际 ${API_SECONDS}s）"
  fi
}

check_log_absent_value() {
  local id=$1 file=$2 desc=$3 value=$4
  if [[ -z "$value" ]]; then
    fail "$id" "$desc（待检查的凭据为空，无法断言）"
  elif [[ ! -s "$file" ]]; then
    fail "$id" "$desc（日志为空，无法断言不包含）"
  elif grep -Fq -- "$value" "$file"; then
    fail "$id" "$desc（日志出现凭据明文）"
  else
    pass "$id" "$desc"
  fi
}

check_no_panic() {
  local id=$1 file=$2 desc=$3
  if [[ ! -s "$file" ]]; then
    fail "$id" "$desc（日志为空）"
  elif grep -q 'panicked at' "$file"; then
    fail "$id" "$desc（日志出现 panic）"
  else
    pass "$id" "$desc"
  fi
}

wait_health() {
  local timeout=$1
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  while :; do
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 \
          "${ADMIN_URL}/healthz" || true)" == "200" ]]; then
      return 0
    fi
    if [[ -n "$HUB_PID" ]] && ! kill -0 "$HUB_PID" 2>/dev/null; then
      return 1
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.1
  done
}

agent_status() {
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
  LAST_STATUS=""
  while :; do
    status=$(agent_status "$id" 2>/dev/null || echo "error")
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

# 轮询审计直到某个 error_code 的条数达到期望（审计写入是 spawn_blocking，可能
# 略晚于控制响应）。只同步，不降低断言：最终仍按精确条数断言。
wait_audit_code_count() {
  local agent=$1 capability=$2 code=$3 expected=$4 timeout=$5
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local count=0
  LAST_STATUS=""
  while :; do
    if curl -sS --max-time 5 -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        "${ADMIN_URL}/api/v1/audit?limit=200&agent_id=${agent}&capability=${capability}" \
        -o "$AUDIT_JSON" 2>"$TMP_DIR/curl.err"; then
      count=$(RB_CODE="$code" "$PYTHON" - "$AUDIT_JSON" <<'PY'
import json
import os
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        entries = json.load(handle).get("entries", [])
except Exception:
    print(-1)
    raise SystemExit(0)
print(sum(1 for item in entries if item.get("error_code") == os.environ["RB_CODE"]))
PY
)
      LAST_STATUS=$count
      if [[ "$count" == "$expected" ]]; then
        return 0
      fi
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

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

# 把配置文件里第一个 [control] 起的内容替换成给定表（hub 配置里它在末尾）。
set_control_table() {
  local path=$1 section_file=$2
  "$PYTHON" - "$path" "$section_file" <<'PY'
import sys

path, section_path = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
index = text.find("[control]")
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
hub_url = "${AGENT_URL}"
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
  wait_health 20 || die "hub 未在 20s 内就绪（${ADMIN_URL}/healthz）"
}

# 启动 agent 并等待 enrollment。PID 通过全局 STARTED_AGENT_PID 返回，且 PIDS
# 登记发生在当前 shell（函数不在命令替换子 shell 里执行），失败路径也能回收。
start_agent() {
  local cfg=$1 log=$2 data=$3
  RUST_LOG=rustboard_agent=info "$AGENT_BIN" run --config "$cfg" > "$log" 2>&1 &
  STARTED_AGENT_PID=$!
  PIDS+=("$STARTED_AGENT_PID")
  wait_for_file "$data/agent_id" 20 \
    || die "agent 未在 20s 内完成 enrollment（$(basename "$log")）"
}

stop_pid() {
  local pid=$1
  [[ -n "$pid" ]] || return 0
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub / rustboard-agent"
(cd "$ROOT" && "$CARGO" build --locked -p rustboard-hub -p rustboard-agent) \
  > "$BUILD_LOG" 2>&1 || die "cargo build 失败（见 $(basename "$BUILD_LOG")）"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
HUB_BIN="$TARGET_DIR/debug/rustboard-hub"
AGENT_BIN="$TARGET_DIR/debug/rustboard-agent"
[[ -x "$HUB_BIN" ]] || die "找不到 $HUB_BIN"
[[ -x "$AGENT_BIN" ]] || die "找不到 $AGENT_BIN"

# ---------------------------------------------------------------------------
# 初始化 hub / fake journalctl
# ---------------------------------------------------------------------------

AGENT_PORT=$(pick_port)
ADMIN_PORT=$(pick_port)
while [[ "$ADMIN_PORT" == "$AGENT_PORT" ]]; do
  ADMIN_PORT=$(pick_port)
done
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}"
AGENT_URL="wss://127.0.0.1:${AGENT_PORT}/agent/ws"

echo "==> 初始化 hub（agent=${AGENT_PORT} admin=${ADMIN_PORT}）"
"$HUB_BIN" init \
  --config "$HUB_CFG" \
  --data-dir "$HUB_DATA" \
  --agent-listen "127.0.0.1:${AGENT_PORT}" \
  --admin-listen "127.0.0.1:${ADMIN_PORT}" \
  --force > "$INIT_LOG" 2>&1 || die "hub init 失败（见 $(basename "$INIT_LOG")）"

sed -i 's/^self_monitor = true$/self_monitor = false/' "$HUB_CFG"
# 测试会连续 POST；默认 60/min、10/min 的管理限速会把自己打成 429。
for key in admin_rate_limit_per_min admin_write_rate_limit_per_min; do
  if grep -q "^${key} = " "$HUB_CFG"; then
    sed -i "s/^${key} = .*/${key} = 0/" "$HUB_CFG"
  else
    printf '\n%s = 0\n' "$key" >> "$HUB_CFG"
  fi
done
grep -q '^self_monitor = false' "$HUB_CFG" \
  || die "无法关闭 hub 的 self_monitor"
grep -q '^admin_rate_limit_per_min = 0' "$HUB_CFG" \
  || die "无法放宽管理 API 读限速"
grep -q '^admin_write_rate_limit_per_min = 0' "$HUB_CFG" \
  || die "无法放宽管理 API 写限速"

ADMIN_TOKEN=$(cfg_str "$HUB_CFG" admin_token) || die "无法解析 hub admin_token"
[[ -n "$ADMIN_TOKEN" ]] || die "hub 配置缺少 admin_token"
FPR=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p') \
  || die "无法读取服务端证书指纹"
[[ "$FPR" =~ ^[0-9a-f]{64}$ ]] || die "服务端证书指纹非法"

cat > "$HUB_CTL" <<'EOF'
[control]
enabled = true
systemd = true
docker = false
process = false
logs = true
request_timeout_ms = 1000
max_pending_per_session = 2
max_output_bytes = 262144
EOF
set_control_table "$HUB_CFG" "$HUB_CTL"

# 两个 token 都在 hub 启动前生成（运维 CLI 不与运行中的 hub 抢 SQLite）。
TOKEN_A=$(add_agent_token "v032-a")
TOKEN_B=$(add_agent_token "v032-b")

write_base_agent_config "$A_CFG" "v032-a" "$TOKEN_A" "$A_DATA"

# B：只开启 logs；journalctl 白名单指向测试 fake，两个来源分别验证
# “大输出截断保留最新”和“小输出不截断”。
mkdir -p "$B_DATA"
chmod 700 "$B_DATA"
cat > "$B_CFG" <<EOF
hub_url = "${AGENT_URL}"
token = "${TOKEN_B}"
server_fingerprint = "${FPR}"
name = "v032-b"
data_dir = "${B_DATA}"
sample_interval_ms = 1000
buffer_max_bytes = 10485760

[control]
enabled = true
systemd = false
docker = false
process = false
logs = true
systemd_units = ["nginx*"]
docker_containers = []
command_timeout_secs = 10
max_log_lines = 2000
systemctl_path = ""
docker_path = ""
journalctl_path = "${FAKE_DIR}/journalctl"

[[control.log_sources]]
id = "j"
kind = "journal"
target = "nginx.service"
name = "journal big"

[[control.log_sources]]
id = "js"
kind = "journal"
target = "nginx-small.service"
name = "journal small"
EOF
chmod 600 "$B_CFG"

echo "==> 生成 fake journalctl（1000 行 × 1KiB 新→旧 + 3 行小输出）"
"$PYTHON" - "$JOURNAL_BIG_OUT" "$JOURNAL_SMALL_OUT" <<'PY'
import sys

big_path, small_path = sys.argv[1], sys.argv[2]
lines = []
for number in range(1000, 0, -1):
    prefix = f"2026-10-23T00:00:00+00:00 e2e-host nginx: line-{number} "
    lines.append(prefix + "x" * (1023 - len(prefix)))
with open(big_path, "w", encoding="utf-8", newline="\n") as handle:
    handle.write("\n".join(lines) + "\n")

small_lines = []
for number in (3, 2, 1):
    prefix = f"2026-10-23T00:00:0{number}+00:00 e2e-host nginx: small-{number} "
    small_lines.append(prefix + "y" * (120 - len(prefix)))
with open(small_path, "w", encoding="utf-8", newline="\n") as handle:
    handle.write("\n".join(small_lines) + "\n")
PY

CAT_BIN=$(command -v cat)
cat > "$FAKE_DIR/journalctl" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >> "$JOURNAL_ARGV"

case "\$*" in
  *nginx-small.service*)
    exec "$CAT_BIN" "$JOURNAL_SMALL_OUT"
    ;;
  *)
    exec "$CAT_BIN" "$JOURNAL_BIG_OUT"
    ;;
esac
EOF
chmod 0755 "$FAKE_DIR/journalctl"

# ---------------------------------------------------------------------------
# 启动 hub、真实 agent A，完成 enrollment 后停掉
# ---------------------------------------------------------------------------

echo
echo "==> 1) 基线：hub 就绪、真实 agent enrollment"
start_hub
pass "1.1" "hub /healthz 就绪（agent=127.0.0.1:${AGENT_PORT} admin=127.0.0.1:${ADMIN_PORT}）"

start_agent "$A_CFG" "$A_LOG" "$A_DATA"
A_PID=$STARTED_AGENT_PID
for name in agent_id agent.crt agent.key agent.secret ca.crt; do
  wait_for_file "$A_DATA/$name" 10 \
    || die "agent A enrollment 后缺少 $name"
done
A_ID=$(tr -d '[:space:]' < "$A_DATA/agent_id")
[[ -n "$A_ID" ]] || die "agent_id 为空"
A_SECRET=$(tr -d '[:space:]' < "$A_DATA/agent.secret")
[[ -n "$A_SECRET" ]] || die "agent secret 为空"
pass "1.2" "真实 agent A enrollment 完成，证书 / 私钥 / secret / CA 已落盘"
check_eq "1.3" "agent.secret 权限为 0600" "600" "$(stat -c '%a' "$A_DATA/agent.secret")"
if wait_agent_status "$A_ID" online 20; then
  pass "1.4" "真实 agent A 状态 online"
else
  fail "1.4" "真实 agent A 未在 20s 内 online（最后状态: $LAST_STATUS）"
  die "无法继续：真实 agent 未上线"
fi

stop_pid "$A_PID"
A_PID=""
if wait_agent_status "$A_ID" offline 10; then
  pass "1.5" "停掉真实 agent 后状态变为 offline（保留 enrollment 材料）"
else
  fail "1.5" "停掉真实 agent 后 10s 内未离线（最后状态: $LAST_STATUS）"
fi

# ---------------------------------------------------------------------------
# fake agent：ignore 模式（#18）
# ---------------------------------------------------------------------------

echo
echo "==> fake agent 以同一 agent_id + 证书连接（ignore 模式）"
printf 'ignore\n' > "$FAKE_MODE"
"$PYTHON" "$FAKE_AGENT" \
  --url "$AGENT_URL" \
  --ca "$A_DATA/ca.crt" \
  --cert "$A_DATA/agent.crt" \
  --key "$A_DATA/agent.key" \
  --agent-id "$A_ID" \
  --secret-file "$A_DATA/agent.secret" \
  --ready-file "$FAKE_READY" \
  --mode-file "$FAKE_MODE" \
  --capability systemd \
  > "$FAKE_LOG" 2>&1 &
FAKE_PID=$!
PIDS+=("$FAKE_PID")
if wait_for_file "$FAKE_READY" 10; then
  pass "1.6" "fake agent 用 enrollment 材料完成 mTLS Hello 并收到 Welcome"
else
  fail "1.6" "fake agent 未在 10s 内收到 Welcome"
  die "无法继续：fake agent 未就绪"
fi
if wait_agent_status "$A_ID" online 10; then
  pass "1.7" "fake agent 会话被 hub 识别为 online"
else
  fail "1.7" "fake agent 会话未 online（最后状态: $LAST_STATUS）"
  die "无法继续：fake agent 未上线"
fi
api GET "/api/v1/agents/${A_ID}/control"
expect_status "1.8" "读取 A 控制状态" 200
CAPS=$(json_get '",".join(sorted(d.get("capabilities", [])))' "$HTTP_BODY_FILE")
check_eq "1.9" "Hello capabilities=[systemd] 已写入 hub" "systemd" "$CAPS"

# ---------------------------------------------------------------------------
# 2) #18：pending 超时清理
# ---------------------------------------------------------------------------

echo
echo "==> 2) #18 pending 超时清理（request_timeout_ms=1000, max_pending=2）"

control_systemd_list() {
  api POST "/api/v1/agents/${A_ID}/control" '{"capability":"systemd","action":"list"}'
}

check_timeout_request() {
  local start=$1 desc=$2
  control_systemd_list
  expect_status "2.$start" "$desc：HTTP 504" 504
  expect_error_code "2.$((start + 1))" "$desc：不是 429/502" "control_timeout"
  check_elapsed_min "2.$((start + 2))" "$desc：耗时 ≥0.8s" 0.8
  check_elapsed_max "2.$((start + 3))" "$desc：耗时 <5s" 5
}

# 连续发送、不在中间 sleep：若 pending 泄漏，第 3 个会先撞上 max_pending=2。
check_timeout_request 1 "第1个连续请求"
check_timeout_request 5 "第2个连续请求"
check_timeout_request 9 "第3个连续请求"

sleep 2
check_timeout_request 13 "等待 2s 后的第4个请求"

check_not_contains "2.17" "第4个响应不是 too_many_pending" "$BODY" "too_many_pending"

api GET "/api/v1/audit?limit=200&agent_id=${A_ID}&capability=systemd"
expect_status "2.18" "查询控制审计" 200

wait_audit_code_count "$A_ID" systemd control_timeout 4 5 || true

if "$PYTHON" - "$AUDIT_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
selected = [
    item for item in entries
    if item.get("capability") == "systemd" and item.get("action") == "list"
]
timeouts = [item for item in selected if item.get("error_code") == "control_timeout"]
if len(timeouts) != 4:
    raise SystemExit(1)
if any(item.get("result") != "error" for item in timeouts):
    raise SystemExit(2)
PY
then
  pass "2.19" "审计恰好 4 条 control_timeout，result 全为 error"
else
  fail "2.19" "审计 control_timeout 条数或 result 不符（最后计数: $LAST_STATUS）"
fi

if "$PYTHON" - "$AUDIT_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
selected = [
    item for item in entries
    if item.get("capability") == "systemd" and item.get("action") == "list"
]
for item in selected:
    if item.get("error_code") != "control_timeout":
        raise SystemExit(1)
    if item.get("error_message") != "agent 未在限定时间内响应":
        raise SystemExit(2)
    if int(item.get("duration_ms", -1)) < 800:
        raise SystemExit(3)
PY
then
  pass "2.20" "4 条审计均为固定文案且 duration_ms ≥800"
else
  fail "2.20" "审计文案或 duration_ms 不符（不是真正的超时路径）"
fi

IGNORED=$(grep -c '^IGNORE id=' "$FAKE_LOG" 2>/dev/null || true)
check_eq "2.21" "fake agent 实际收到 4 个 ControlRequest（说明不是本地 429 短路）" \
  "4" "$IGNORED"

# ---------------------------------------------------------------------------
# 3) #16：续签期间 busy_renewing
# ---------------------------------------------------------------------------

echo
echo "==> 3) #16 续签期间 busy_renewing（fake agent 立即按 id 回复）"

# 等第 4 个 pending 被 expire 清理，避免与上一个场景的残留混在一起。
sleep 1.5
printf 'busy\n' > "$FAKE_MODE"

check_busy_request() {
  local start=$1 desc=$2
  control_systemd_list
  expect_status "3.$start" "$desc：HTTP 503" 503
  expect_error_code "3.$((start + 1))" "$desc" "busy_renewing"
  local message
  message=$(json_get 'd.get("error", {}).get("message", "")' "$HTTP_BODY_FILE")
  check_eq "3.$((start + 2))" "$desc：固定文案" \
    "agent 正在续签证书，请稍后重试" "$message"
  check_elapsed_max "3.$((start + 3))" "$desc：耗时远小于 1s（不是 504）" 0.5
}

check_busy_request 1 "busy 第1次请求"
check_busy_request 5 "busy 第2次请求（id 匹配再次成立）"

wait_audit_code_count "$A_ID" systemd busy_renewing 2 5 || true

if "$PYTHON" - "$AUDIT_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
selected = [
    item for item in entries
    if item.get("capability") == "systemd" and item.get("action") == "list"
]
busy = [item for item in selected if item.get("error_code") == "busy_renewing"]
timeouts = [item for item in selected if item.get("error_code") == "control_timeout"]
if len(busy) != 2:
    raise SystemExit(1)
if any(item.get("result") != "error" for item in busy):
    raise SystemExit(2)
if len(timeouts) != 4:
    raise SystemExit(3)
if any(item.get("error_code") not in ("control_timeout", "busy_renewing")
       for item in selected):
    raise SystemExit(4)
PY
then
  pass "3.9" "审计 busy_renewing 恰好 2 条且 result=error；原 4 条超时未增加"
else
  fail "3.9" "审计 busy_renewing 条数/结果不符（最后计数: $LAST_STATUS）"
fi

BUSY_IDS=$(grep '^BUSY id=' "$FAKE_LOG" 2>/dev/null | sed 's/^BUSY id=//' | sort -n | tr '\n' ',' || true)
BUSY_COUNT=$(grep -c '^BUSY id=' "$FAKE_LOG" 2>/dev/null || true)
UNIQUE_BUSY=$(printf '%s' "$BUSY_IDS" | tr ',' '\n' | grep -c . || true)
if [[ "$BUSY_COUNT" == "2" && "$UNIQUE_BUSY" == "2" ]]; then
  pass "3.10" "fake agent 按 2 个不同请求 id 发出 busy_renewing"
else
  fail "3.10" "fake agent busy 应答数不符（count=$BUSY_COUNT unique=$UNIQUE_BUSY ids=$BUSY_IDS）"
fi

# ---------------------------------------------------------------------------
# 4) #19：journald tail 保留最新
# ---------------------------------------------------------------------------

echo
echo "==> 4) #19 journald tail 保留最新内容（1000 行 × 1KiB 新→旧）"

start_agent "$B_CFG" "$B_LOG" "$B_DATA"
B_PID=$STARTED_AGENT_PID
B_ID=$(tr -d '[:space:]' < "$B_DATA/agent_id")
[[ -n "$B_ID" ]] || die "agent B 的 agent_id 为空"
if wait_agent_status "$B_ID" online 20; then
  pass "4.1" "真实 agent B（logs=true）状态 online"
else
  fail "4.1" "agent B 未在 20s 内 online（最后状态: $LAST_STATUS）"
  die "无法继续：agent B 未上线"
fi

api GET "/api/v1/agents/${B_ID}/control"
expect_status "4.2" "读取 agent B 控制状态" 200
BCAPS=$(json_get '",".join(sorted(d.get("capabilities", [])))' "$HTTP_BODY_FILE")
check_eq "4.3" "agent B 上报的 capabilities=[logs]" "logs" "$BCAPS"

api POST "/api/v1/agents/${B_ID}/control" \
  '{"capability":"logs","action":"tail","source":"j","lines":1000}'
expect_status "4.4" "journal tail 1000 行" 200
check_eq "4.5" "响应 ok=true" "True" "$(json_get 'd.get("ok")' "$HTTP_BODY_FILE")"
check_eq "4.6" "result.type=log_lines" "log_lines" \
  "$(json_get 'd.get("result", {}).get("type")' "$HTTP_BODY_FILE")"
check_eq "4.7" "result.source=j" "j" \
  "$(json_get 'd.get("result", {}).get("source")' "$HTTP_BODY_FILE")"
check_eq "4.8" "超过 256KiB 标记 truncated=true" "True" \
  "$(json_get 'd.get("result", {}).get("truncated")' "$HTTP_BODY_FILE")"
cp "$HTTP_BODY_FILE" "$TMP_DIR/journal-big.json"

if "$PYTHON" - "$TMP_DIR/journal-big.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle).get("result", {})
lines = result.get("lines") or []
if not lines:
    raise SystemExit(1)
if "line-1000" not in lines[-1]:
    raise SystemExit(2)
numbers = [int(match.group(1)) for match in
           (re.search(r"line-(\d+)", line) for line in lines) if match]
if len(numbers) != len(lines):
    raise SystemExit(3)
if numbers[-1] != 1000:
    raise SystemExit(4)
for previous, current in zip(numbers, numbers[1:]):
    if current != previous + 1:
        raise SystemExit(5)
PY
then
  pass "4.9" "最后一行含最新 line-1000，且行序为连续旧→新（无乱序/回退）"
else
  fail "4.9" "最后一行或行序不符（最新内容可能被丢弃）"
fi

if "$PYTHON" - "$TMP_DIR/journal-big.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle).get("result", {})
lines = result.get("lines") or []
total = sum(len(line.encode("utf-8")) + 1 for line in lines)
if len(lines) < 200:
    raise SystemExit(1)
if total > 256 * 1024:
    raise SystemExit(2)
PY
then
  pass "4.10" "返回行数 ≥200 且行总字节（含换行）≤256KiB"
else
  fail "4.10" "返回行数过少或总字节超过 256KiB"
fi

FIRST_NUM=$("$PYTHON" - "$TMP_DIR/journal-big.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    lines = json.load(handle).get("result", {}).get("lines") or []
match = re.search(r"line-(\d+)", lines[0]) if lines else None
print(match.group(1) if match else "")
PY
)
if [[ "$FIRST_NUM" =~ ^[0-9]+$ ]] && (( FIRST_NUM > 1 )); then
  pass "4.11" "首行序号 ${FIRST_NUM} >1：旧内容被丢弃，不是首部截断"
else
  fail "4.11" "首行序号非法或为最旧行（first=[$FIRST_NUM]）"
fi

SIZE_BYTES=$(json_get 'd.get("result", {}).get("size_bytes")' "$TMP_DIR/journal-big.json")
if [[ "$SIZE_BYTES" =~ ^[0-9]+$ ]] && (( SIZE_BYTES > 200000 && SIZE_BYTES <= 262144 )); then
  pass "4.12" "size_bytes=${SIZE_BYTES} 在 (200000, 262144] 内（保留了接近上限的最新内容）"
else
  fail "4.12" "size_bytes 不合理（[$SIZE_BYTES]）"
fi

if "$PYTHON" - "$JOURNAL_ARGV" <<'PY'
import sys

with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
    lines = [line.strip() for line in handle if line.strip()]
big = [line for line in lines
       if "nginx-small.service" not in line and "nginx.service" in line]
if len(lines) != 1 or len(big) != 1:
    raise SystemExit(1)
if "--reverse" not in big[0]:
    raise SystemExit(2)
if "-n 1000" not in big[0]:
    raise SystemExit(3)
PY
then
  pass "4.13" "大输出 journalctl 参数包含 --reverse 与 -n 1000"
else
  fail "4.13" "journalctl 大输出参数缺少 --reverse 或 -n 1000"
fi

# 小输出：不截断、顺序正确。
api POST "/api/v1/agents/${B_ID}/control" \
  '{"capability":"logs","action":"tail","source":"js","lines":3}'
expect_status "4.14" "journal 小输出 tail" 200
check_eq "4.15" "小输出 ok=true" "True" "$(json_get 'd.get("ok")' "$HTTP_BODY_FILE")"
check_eq "4.16" "小输出 truncated=false" "False" \
  "$(json_get 'd.get("result", {}).get("truncated")' "$HTTP_BODY_FILE")"
cp "$HTTP_BODY_FILE" "$TMP_DIR/journal-small.json"

if "$PYTHON" - "$TMP_DIR/journal-small.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle).get("result", {})
lines = result.get("lines") or []
if len(lines) != 3:
    raise SystemExit(1)
for line, number in zip(lines, (1, 2, 3)):
    if f"small-{number}" not in line:
        raise SystemExit(2)
PY
then
  pass "4.17" "小输出行序为旧→新（small-1, small-2, small-3）"
else
  fail "4.17" "小输出行序或内容不符"
fi

SMALL_SIZE=$(stat -c '%s' "$JOURNAL_SMALL_OUT")
check_eq "4.18" "小输出 size_bytes 等于实际 stdout 字节数" "$SMALL_SIZE" \
  "$(json_get 'd.get("result", {}).get("size_bytes")' "$TMP_DIR/journal-small.json")"

if "$PYTHON" - "$JOURNAL_ARGV" <<'PY'
import sys

with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
    lines = [line.strip() for line in handle if line.strip()]
small = [line for line in lines if "nginx-small.service" in line]
if len(lines) != 2 or len(small) != 1:
    raise SystemExit(1)
if "--reverse" not in small[0]:
    raise SystemExit(2)
if "-n 3" not in small[0]:
    raise SystemExit(3)
PY
then
  pass "4.19" "小输出 journalctl 参数包含 --reverse 与 -n 3（两次调用都被记录）"
else
  fail "4.19" "小输出 journalctl 参数不符或调用次数不是 2"
fi

# 审计：两次 logs tail 成功。
api GET "/api/v1/audit?limit=100&agent_id=${B_ID}&capability=logs"
expect_status "4.20" "查询 logs 审计" 200
if "$PYTHON" - "$HTTP_BODY_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
tails = [item for item in entries if item.get("action") == "tail"]
if len(tails) != 2:
    raise SystemExit(1)
if any(item.get("result") != "ok" or item.get("error_code") != "" for item in tails):
    raise SystemExit(2)
if {item.get("target") for item in tails} != {"j", "js"}:
    raise SystemExit(3)
PY
then
  pass "4.21" "审计 2 条 logs tail：result=ok、error_code 为空、target=j/js"
else
  fail "4.21" "logs 审计条数、结果或 target 不符"
fi

# 安全：日志里不出现凭据。
check_log_absent_value "4.22" "$HUB_LOG" "hub 日志不含 admin_token 明文" "$ADMIN_TOKEN"
check_log_absent_value "4.23" "$HUB_LOG" "hub 日志不含 enrollment token 明文" "$TOKEN_A"
check_log_absent_value "4.24" "$HUB_LOG" "hub 日志不含 agent secret 明文" "$A_SECRET"
check_no_panic "4.25" "$HUB_LOG" "hub 日志无 panic"
check_no_panic "4.26" "$B_LOG" "agent B 日志无 panic"

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

echo
if (( FAILS > 0 )); then
  echo "v032 e2e 结果: ${PASSES} 项通过，${FAILS} 项失败" >&2
  exit 1
fi
echo "v032 e2e 结果: 全部 ${PASSES} 项通过"
