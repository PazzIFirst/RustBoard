#!/usr/bin/env bash
#
# RustBoard v0.3.4 低风险硬化端到端回归：
#   KI-26  未认证 401 限速（429 + Retry-After、旧 admin_token 旁路、日志不刷屏）
#   KI-18  Panel reset-password 后旧会话 ≤2s 失效
#   KI-19  Hello 元数据（超长 / 控制字符）返回 bad_frame 且不写库
#   KI-21  数据目录 0700、SQLite 主库/WAL/SHM 0600；过宽权限启动时收紧
#   KI-24  同一 agent 多连接能力以最新连接为准、断开回退、旧连接晚到 Hello 不覆盖
#
# 方案：docs/plans/2026-10-24-v0.3.4-low-risk-hardening.md §1、§4、§6.2
#
# 覆盖：
#   1. KI-26：hub 配置 admin_auth_failure_limit_per_min=5；合法 scoped token 在
#      阈值前 GET 200；连续 5 次错误 token 均 401，第 6 次 429 且 Retry-After
#      在 1..=60；401/429 body 不含 token；429 后旧 admin_token 仍 200（应急
#      旁路）且失败计数被清除（再一次错误 token 回到 401）；同一窗口内
#      “管理 API 鉴权失败” WARN ≤2 条、429 日志 1 条。
#   2. KI-19：用真实 enrollment 的证书 / secret 建 mTLS 会话，发送 name 129 字节
#      与含换行的 Hello，必须 Problem(bad_frame) 且连接关闭；agents 列表的
#      name/hostname 保持原值、agent_control 能力不变、审计无新增；正常 Hello
#      仍拿到 Welcome 并保持会话。
#   3. KI-18：Panel 旧密码登录拿到 Cookie → reset-password → 从配置落盘计时，
#      ≤2000ms 内旧 Cookie 访问受保护端点 /api/overview 返回 401；公开端点
#      /api/session 仍 200 且 authenticated=false（不作为 401 依据）；旧密码
#      登录 401、新密码 204、新 Cookie 可用。
#   4. KI-21：hub 启动后数据目录 0700、主库/WAL/SHM 0600；停 hub 后把目录
#      改成 0755、DB 改成 0644 并删除 WAL/SHM，重启后权限收紧且服务可用；
#      全程不修改测试临时目录的父目录（尤其不 chmod /tmp）。
#   5. KI-24：同一 agent 的两条真实 mTLS 连接。旧连接报能力 B、新连接报能力 A
#      → API 看到 A；旧连接在会话建立后再补发能力 C 的 Hello，不得覆盖 A；
#      关闭新连接后能力回退为 B、控制 sender 指向旧连接（fake agent 用角色化
#      unit 名应答）；全部关闭后 offline、能力仍保留 B。
#   6. 日志：hub/agent/panel 不出现 token / secret / 面板密码明文，无 panic。
#
# 说明：本脚本只写测试，不修改实现；断言失败就是失败，不跳过、不弱化。
#      不运行既有 8 套 e2e（由 CI 分别运行）；不访问网络；不打印任何凭据。
#
# 依赖：bash 4.4+、python3 3.8+（仅标准库）、curl、cargo/rustc。
# 用法：bash tests/e2e/v034.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/v034.sh   # 保留临时目录与脱敏日志
#
set -euo pipefail
# 所有落盘文件（配置、日志、Cookie、假 agent 元数据）默认 0600/0700。
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PANEL_PROBE="$SCRIPT_DIR/panel_probe.py"
V034_AGENT="$SCRIPT_DIR/v034_agent.py"
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}
# 仓库历史遗留跟踪了 tests/e2e/__pycache__/*.pyc；禁止 Python 写字节码。
export PYTHONDONTWRITEBYTECODE=1

# 隔离 target：不同 worktree / 任务不要共用可执行文件；调用方显式设置时优先。
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  export CARGO_TARGET_DIR="$ROOT/target/v034-t1"
fi

PASSES=0
FAILS=0
KI24_FAILS=0
STATUS=""
BODY=""
HELPER_OUT=""
HELPER_RC=0
LAST_CAPS=""
HUB_PID=""
AGENT1_PID=""
AGENT2_PID=""
PANEL_PID=""
MULTI_PID=""
PIDS=()

ADMIN_TOKEN=""
READ_TOKEN=""
ENROLL1=""
ENROLL2=""
AGENT1_SECRET=""
AGENT2_SECRET=""
WRONG_TOKEN=""
PANEL_OLD_PASSWORD=""
PANEL_NEW_PASSWORD=""

HUB_BIN=""
AGENT_BIN=""
PANEL_BIN=""
ADMIN_URL=""
PANEL_URL=""
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

# KI-24 相关断言单独计数，便于在汇总里区分“多连接能力缓存”失败；
# 与其他断言一样是硬失败，不删除、不弱化。
fail_ki24() {
  FAILS=$((FAILS + 1))
  KI24_FAILS=$((KI24_FAILS + 1))
  echo "FAIL [$1][KI-24] $2" >&2
}

die() {
  echo "FATAL: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# 临时目录与失败现场
# ---------------------------------------------------------------------------

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-v034.XXXXXX")
chmod 700 "$TMP_DIR"
# 记录父目录权限，KI-21 结束时验证脚本没有 chmod 测试目录之外的东西。
PARENT_DIR=${TMPDIR:-/tmp}
PARENT_MODE_BEFORE=$(stat -c %a "$PARENT_DIR")
TMP_MODE_BEFORE=$(stat -c %a "$TMP_DIR")

HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
HUB_INIT_LOG="$TMP_DIR/hub-init.log"
A1_CFG="$TMP_DIR/agent-hello.toml"
A1_DATA="$TMP_DIR/agent-hello"
A1_LOG="$TMP_DIR/agent-hello.log"
A2_CFG="$TMP_DIR/agent-multi.toml"
A2_DATA="$TMP_DIR/agent-multi"
A2_LOG="$TMP_DIR/agent-multi.log"
PANEL_CFG="$TMP_DIR/panel.toml"
PANEL_LOG="$TMP_DIR/panel.log"
PANEL_INIT_LOG="$TMP_DIR/panel-init.log"
PANEL_RESET_LOG="$TMP_DIR/panel-reset.log"
PANEL_COOKIE="$TMP_DIR/panel.cookie"
PANEL_COOKIE_NEW="$TMP_DIR/panel-new.cookie"
BUILD_LOG="$TMP_DIR/build.log"
CURL_ERR="$TMP_DIR/curl.err"
PROBE_ERR="$TMP_DIR/probe.err"
HELPER_ERR="$TMP_DIR/helper.err"
HTTP_BODY_FILE="$TMP_DIR/http-body"
HTTP_HEADERS_FILE="$TMP_DIR/http-headers"
KI26_BODIES="$TMP_DIR/ki26-bodies"
KI26_SEGMENT="$TMP_DIR/ki26-log-segment"
META_LONG="$TMP_DIR/hello-long-name.json"
META_CONTROL="$TMP_DIR/hello-control-name.json"
MULTI_CMD="$TMP_DIR/multi.cmd"
MULTI_STATUS="$TMP_DIR/multi.status"
MULTI_LOG="$TMP_DIR/multi.log"
HUB_CONTROL_SECTION="$TMP_DIR/hub-control-section.toml"

: > "$KI26_BODIES"

# 失败现场先脱敏：所有 token / agent secret / 面板密码 / Bearer 头。
redact_log() {
  RB_V034_SECRETS="$ADMIN_TOKEN|$READ_TOKEN|$ENROLL1|$ENROLL2|$AGENT1_SECRET|$AGENT2_SECRET|$WRONG_TOKEN|$PANEL_OLD_PASSWORD|$PANEL_NEW_PASSWORD" \
  "$PYTHON" -c '
import os
import re
import sys

secrets = [item for item in os.environ.get("RB_V034_SECRETS", "").split("|") if item]
text = sys.stdin.buffer.read().decode("utf-8", "replace")
for secret in secrets:
    text = text.replace(secret, "<redacted>")
text = re.sub(r"(Bearer )[^\s]+", r"\1<redacted>", text)
text = re.sub(r"(管理 API token:).*", r"\1 <redacted>", text)
text = re.sub(r"(一次性 token[^:：]*[:：]).*", r"\1 <redacted>", text)
text = re.sub(r"(已重置面板密码[^:：]*[:：]).*", r"\1 <redacted>", text)
text = re.sub(r"(密码（仅显示一次[^:：]*[:：]).*", r"\1 <redacted>", text)
text = re.sub(r"(面板密码[^:：]*[:：]).*", r"\1 <redacted>", text)
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
    echo "===== v034 e2e 失败现场（日志已脱敏）=====" >&2
    for log in "$HUB_LOG" "$A1_LOG" "$A2_LOG" "$PANEL_LOG" "$PANEL_RESET_LOG" \
               "$HUB_INIT_LOG" "$PANEL_INIT_LOG" "$BUILD_LOG" "$MULTI_LOG" \
               "$PROBE_ERR" "$HELPER_ERR" "$CURL_ERR"; do
      dump_log "$log" 120
    done
    if [[ -s "$MULTI_STATUS" ]]; then
      echo "---- $(basename "$MULTI_STATUS") ----" >&2
      cat "$MULTI_STATUS" >&2 || true
    fi
    echo "已通过 $PASSES 项，失败 $FAILS 项（其中 KI-24 相关 $KI24_FAILS 项）" >&2
  fi

  if [[ "${KEEP_E2E_TMP:-0}" == "1" ]]; then
    echo "临时目录已保留: $TMP_DIR" >&2
  else
    # 只删除本脚本 mktemp 出来的目录，避免误删其它路径。
    if [[ -n "${TMP_DIR:-}" && "$TMP_DIR" == "${TMPDIR:-/tmp}"/rustboard-v034.* ]]; then
      rm -rf -- "$TMP_DIR"
    else
      echo "警告: 临时目录不符合预期，未删除: ${TMP_DIR:-<unset>}" >&2
    fi
  fi
  exit "$code"
}
trap cleanup EXIT

for tool in "$PYTHON" "$CARGO" curl mktemp date tail awk sed grep stat tr cat find wc \
            sha256sum; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "找不到命令: $tool（python3 需 3.8+；cargo 请放进 PATH 或设置 CARGO=...）"
done
[[ -f "$PANEL_PROBE" ]] || die "缺少 panel probe: $PANEL_PROBE"
[[ -f "$V034_AGENT" ]] || die "缺少 v034 fake agent: $V034_AGENT"

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

pick_ports() {
  "$PYTHON" - <<'PY'
import random
import socket

chosen = []
while len(chosen) < 3:
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

# 替换一个 TOML 标量（只允许恰好一处匹配）。
set_scalar() {
  "$PYTHON" - "$1" "$2" "$3" <<'PY'
import re
import sys

path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
pattern = re.compile(r'(?m)^' + re.escape(key) + r'\s*=\s*.*$')
replacement = f"{key} = {value}"
text, count = pattern.subn(lambda _m: replacement, text)
if count != 1:
    raise SystemExit(f"配置 {path} 中 {key} 匹配 {count} 次（期望 1 次）")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
}

# 替换或追加 [control] 表（从第一个 [control] 开始截断）。
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

# 管理 API；token 可覆盖（默认旧 admin_token）。可选第 5 个参数保存响应头。
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

# 取 agents 列表里某个 agent 的字段；不存在返回 __ABSENT__。
agents_field() {
  local agent_id=$1 field=$2
  "$PYTHON" - "$agent_id" "$field" "$HTTP_BODY_FILE" <<'PY'
import json
import sys

agent_id, field, path = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path, encoding="utf-8") as handle:
        agents = json.load(handle)
except Exception:
    print("__ERR__")
    raise SystemExit(0)
for agent in agents if isinstance(agents, list) else []:
    if agent.get("agent_id") == agent_id:
        value = agent.get(field)
        print("__ABSENT__" if value is None else value)
        break
else:
    print("__ABSENT__")
PY
}

audit_max_id() {
  "$PYTHON" - "$HTTP_BODY_FILE" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        entries = json.load(handle).get("entries", [])
except Exception:
    print("__ERR__")
    raise SystemExit(0)
print(max((int(item.get("id", 0)) for item in entries), default=0))
PY
}

# 轮询 GET /control，直到 capabilities（排序后逗号连接）等于期望值。
wait_control_caps() {
  local id=$1 expected=$2 timeout=$3
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  LAST_CAPS=""
  while :; do
    api GET "/api/v1/agents/${id}/control"
    if [[ "$STATUS" == "200" ]]; then
      LAST_CAPS=$(json_get '",".join(sorted(d.get("capabilities", [])))')
      if [[ "$LAST_CAPS" == "$expected" ]]; then
        return 0
      fi
    else
      LAST_CAPS="HTTP $STATUS"
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.1
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

# `token create` 只输出一次明文；校验为 64 位 hex 后返回。
create_token() {
  local name=$1 scope=$2 out
  out=$("$HUB_BIN" token create --config "$HUB_CFG" --name "$name" --scope "$scope" \
    2>"$TMP_DIR/token-create.err") \
    || die "token create --name $name --scope $scope 失败（$(cat "$TMP_DIR/token-create.err" 2>/dev/null)）"
  [[ "$out" =~ ^[0-9a-f]{64}$ ]] || die "token create 输出不是 64 位 hex（不打印内容）"
  printf '%s' "$out"
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

start_hub() {
  RUST_LOG=rustboard_hub=info "$HUB_BIN" run --config "$HUB_CFG" >> "$HUB_LOG" 2>&1 &
  HUB_PID=$!
  PIDS+=("$HUB_PID")
  wait_health "$ADMIN_URL/healthz" 20 \
    || die "hub 未在 20s 内就绪（${ADMIN_URL}/healthz，见 hub.log）"
}

# SIGTERM → 最多等 10s → SIGKILL；期间另起 watchdog，避免 wait 永久阻塞。
stop_hub() {
  local pid=$HUB_PID
  if [[ -z "$pid" ]]; then
    return 0
  fi
  kill "$pid" 2>/dev/null || true
  ( sleep 10; kill -9 "$pid" 2>/dev/null || true ) &
  local watchdog=$!
  wait "$pid" 2>/dev/null || true
  kill "$watchdog" 2>/dev/null || true
  wait "$watchdog" 2>/dev/null || true
  drop_pid "$pid"
  HUB_PID=""
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

# 面板登录：只回显 HTTP 状态；成功时把 Cookie 写进指定文件。
panel_login() {
  local password=$1 cookie_out=${2:-}
  local -a args=(login --url "$PANEL_URL/api/login" --password-env RB_E2E_PANEL_PASSWORD)
  if [[ -n "$cookie_out" ]]; then
    args+=(--cookie-out "$cookie_out")
  fi
  local out
  if ! out=$(RB_E2E_PANEL_PASSWORD="$password" "$PYTHON" "$PANEL_PROBE" \
      "${args[@]}" 2>"$PROBE_ERR"); then
    printf 'PROBE_ERROR'
    return 0
  fi
  printf '%s' "$out" | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("status",""))'
}

# 用 Cookie 访问面板受保护端点，返回 http_code。
panel_cookie_code() {
  local cookie_file=$1 path=$2
  local cookie code
  cookie=$(tr -d '\n' < "$cookie_file")
  code=$(curl -sS --noproxy '*' --max-time 10 -o "$HTTP_BODY_FILE" -w '%{http_code}' \
    -H "Cookie: ${cookie}" -H "Origin: ${PANEL_URL}" -H 'Accept: application/json' \
    "${PANEL_URL}${path}" 2>"$CURL_ERR") || code="000"
  printf '%s' "$code"
}

# 运行 v034_agent.py，结果放到 HELPER_OUT / HELPER_RC，不直接失败。
run_agent_helper() {
  HELPER_RC=0
  HELPER_OUT=$("$PYTHON" "$V034_AGENT" "$@" 2>"$HELPER_ERR") || HELPER_RC=$?
}

# 用 fake agent 单行 JSON 输出取字段；先落到临时文件再复用 json_get，
# 避免 heredoc 脚本与管道 stdin 争用同一个标准输入。
helper_field() {
  printf '%s' "$HELPER_OUT" > "$TMP_DIR/helper.json"
  json_get "$1" "$TMP_DIR/helper.json"
}

append_multi_cmd() {
  printf '%s\n' "$1" >> "$MULTI_CMD"
}

wait_status_line() {
  local file=$1 pattern=$2 timeout=$3
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  while :; do
    if grep -Eq -- "$pattern" "$file" 2>/dev/null; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.05
  done
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

# ---------------------------------------------------------------------------
# 构建与初始化
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub / rustboard-agent / rustboard-panel（CARGO_TARGET_DIR=$CARGO_TARGET_DIR）"
if ! (cd "$ROOT" && "$CARGO" build --locked \
      -p rustboard-hub -p rustboard-agent -p rustboard-panel) \
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
PANEL_BIN="$TARGET_DIR/debug/rustboard-panel"
[[ -x "$HUB_BIN" ]] || die "找不到 $HUB_BIN"
[[ -x "$AGENT_BIN" ]] || die "找不到 $AGENT_BIN"
[[ -x "$PANEL_BIN" ]] || die "找不到 $PANEL_BIN"
pass "0.1" "cargo build 三个 bin 成功（隔离 target）"

PORT_LINE=$(pick_ports) || die "无法挑选 3 个空闲端口"
read -r AGENT_PORT ADMIN_PORT PANEL_PORT <<< "$PORT_LINE"
for port in "$AGENT_PORT" "$ADMIN_PORT" "$PANEL_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] || die "端口解析失败: $PORT_LINE"
done
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}"
PANEL_URL="http://127.0.0.1:${PANEL_PORT}"

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
pass "0.2" "hub init 成功"

# KI-26：本脚本把失败阈值调到 5（第 6 次必须 429）。
set_scalar "$HUB_CFG" self_monitor false
set_scalar "$HUB_CFG" sample_interval_ms 1000
set_scalar "$HUB_CFG" admin_rate_limit_per_min 0
set_scalar "$HUB_CFG" admin_write_rate_limit_per_min 0
set_scalar "$HUB_CFG" admin_auth_failure_limit_per_min 5
grep -q '^admin_auth_failure_limit_per_min = 5$' "$HUB_CFG" \
  || die "无法把 admin_auth_failure_limit_per_min 设为 5"

cat > "$HUB_CONTROL_SECTION" <<'EOF'
[control]
enabled = true
systemd = true
docker = false
process = false
logs = false
request_timeout_ms = 15000
max_pending_per_session = 32
max_output_bytes = 262144
EOF
set_control_table "$HUB_CFG" "$HUB_CONTROL_SECTION"

ADMIN_TOKEN=$(cfg_str "$HUB_CFG" admin_token) || die "无法解析 hub admin_token"
[[ -n "$ADMIN_TOKEN" ]] || die "hub 配置缺少 admin_token"
CA="$HUB_DATA/certs/ca.crt"
[[ -f "$CA" ]] || die "缺少 CA 证书: $CA"
FPR=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p') \
  || die "无法读取服务端证书指纹"
[[ "$FPR" =~ ^[0-9a-f]{64}$ ]] || die "服务端证书指纹非法"
pass "0.3" "hub 配置就绪（失败阈值 5、控制面 systemd 开启、CA/指纹可用）"

# 两个 agent 都在 hub 启动前生成 enrollment token。
ENROLL1=$(add_agent_token "v034-hello")
ENROLL2=$(add_agent_token "v034-multi")
write_base_agent_config "$A1_CFG" "v034-hello" "$ENROLL1" "$A1_DATA"
write_base_agent_config "$A2_CFG" "v034-multi" "$ENROLL2" "$A2_DATA"

echo "==> 启动 hub"
start_hub
pass "0.4" "hub 管理口 /healthz 就绪（${ADMIN_URL}）"

READ_TOKEN=$(create_token "v034-reader" "read")
api_as "$READ_TOKEN" GET "/api/v1/agents"
expect_status "0.5" "read scope token 可用" 200

echo "==> 初始化并启动 Panel"
PANEL_OLD_PASSWORD="V034-e2e-$(date +%s)-old"
PANEL_NEW_PASSWORD="V034-e2e-$(date +%s)-new"
PANEL_INIT_ARGS=(init --config "$PANEL_CFG" --listen "127.0.0.1:${PANEL_PORT}"
  --hub "$ADMIN_URL" --hub-token "$READ_TOKEN" --password "$PANEL_OLD_PASSWORD" --force)
if [[ -f "$ROOT/web/dist/index.html" ]]; then
  PANEL_INIT_ARGS+=(--static-dir "$ROOT/web/dist")
fi
if ! "$PANEL_BIN" "${PANEL_INIT_ARGS[@]}" > "$PANEL_INIT_LOG" 2>&1; then
  dump_log "$PANEL_INIT_LOG" 80
  die "panel init 失败"
fi
chmod 600 "$PANEL_CFG"
RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$PANEL_CFG" > "$PANEL_LOG" 2>&1 &
PANEL_PID=$!
PIDS+=("$PANEL_PID")
wait_health "$PANEL_URL/healthz" 20 || die "panel 未在 20s 内就绪"
pass "0.6" "panel /healthz 就绪（${PANEL_URL}）"

rm -f "$PANEL_COOKIE"
LOGIN_STATUS=$(panel_login "$PANEL_OLD_PASSWORD" "$PANEL_COOKIE")
check_eq "0.7" "旧密码登录返回 204" "204" "$LOGIN_STATUS"
if [[ -s "$PANEL_COOKIE" ]] && grep -q '^rb_session=' "$PANEL_COOKIE"; then
  pass "0.8" "登录写入 rb_session Cookie"
else
  fail "0.8" "登录未写入 rb_session Cookie"
fi

echo "==> 启动两个真实 agent"
start_agent "$A1_CFG" "$A1_LOG" "$A1_DATA"
AGENT1_PID=$STARTED_AGENT_PID
start_agent "$A2_CFG" "$A2_LOG" "$A2_DATA"
AGENT2_PID=$STARTED_AGENT_PID
A1_ID=$(tr -d '[:space:]' < "$A1_DATA/agent_id")
A2_ID=$(tr -d '[:space:]' < "$A2_DATA/agent_id")
AGENT1_SECRET=$(tr -d '[:space:]' < "$A1_DATA/agent.secret")
AGENT2_SECRET=$(tr -d '[:space:]' < "$A2_DATA/agent.secret")
[[ -n "$A1_ID" && -n "$A2_ID" ]] || die "agent_id 为空"
wait_agent_status "$A1_ID" online 20 || die "agent A1 未 online（最后: $LAST_STATUS）"
wait_agent_status "$A2_ID" online 20 || die "agent A2 未 online（最后: $LAST_STATUS）"
pass "0.9" "两个真实 agent 完成 enrollment 并 online"

# ---------------------------------------------------------------------------
# 1. KI-26：未认证 401 限速
# ---------------------------------------------------------------------------

echo
echo "==> 1) KI-26 未认证 401 限速（阈值 5）"

WRONG_TOKEN="v034-wrong-token-$(date +%s)-$RANDOM"

# 进入限速窗口前的日志边界。
LOG_BOUNDARY=$(wc -l < "$HUB_LOG")

api_as "$READ_TOKEN" GET "/api/v1/agents"
expect_status "1.1" "阈值前合法 scoped token GET 200" 200

WRONG_STATUSES=""
for _ in 1 2 3 4 5; do
  api_as "$WRONG_TOKEN" GET "/api/v1/agents" "" "$HTTP_HEADERS_FILE"
  WRONG_STATUSES+="${STATUS} "
  cat "$HTTP_BODY_FILE" >> "$KI26_BODIES" 2>/dev/null || true
done
WRONG_STATUSES=${WRONG_STATUSES% }
check_eq "1.2" "连续 5 次错误 token 均 401" "401 401 401 401 401" "$WRONG_STATUSES"

api_as "$WRONG_TOKEN" GET "/api/v1/agents" "" "$HTTP_HEADERS_FILE"
check_eq "1.3" "第 6 次错误 token 返回 429" "429" "$STATUS"
cat "$HTTP_BODY_FILE" >> "$KI26_BODIES" 2>/dev/null || true
expect_flat_error "1.4" "429 body 为固定 rate_limited" "rate_limited"

RETRY_AFTER=$(tr -d '\r' < "$HTTP_HEADERS_FILE" \
  | awk 'tolower($1) == "retry-after:" { print $2; exit }')
if [[ "$RETRY_AFTER" =~ ^[0-9]+$ ]] && (( RETRY_AFTER >= 1 && RETRY_AFTER <= 60 )); then
  pass "1.5" "429 带 Retry-After（${RETRY_AFTER}s，范围 1..=60）"
else
  fail "1.5" "429 的 Retry-After 非法或缺失（[$RETRY_AFTER]）"
fi

KI26_BODY_TEXT=$(cat "$KI26_BODIES" 2>/dev/null || true)
check_not_contains "1.6" "401/429 body 不含错误 token" "$KI26_BODY_TEXT" "$WRONG_TOKEN"
check_not_contains "1.7" "401/429 body 不含旧 admin_token" "$KI26_BODY_TEXT" "$ADMIN_TOKEN"

api GET "/api/v1/agents"
expect_status "1.8" "429 后旧 admin_token 仍 GET 200（应急旁路）" 200

api_as "$WRONG_TOKEN" GET "/api/v1/agents"
check_eq "1.9" "旧 admin_token 清除失败计数：再次错误 token 回到 401" "401" "$STATUS"

sed -n "$((LOG_BOUNDARY + 1)),\$p" "$HUB_LOG" > "$KI26_SEGMENT"
WARN_COUNT=$(awk '/WARN.*管理 API 鉴权失败/ { n++ } END { print n + 0 }' "$KI26_SEGMENT")
LIMIT_COUNT=$(awk '/429/ { n++ } END { print n + 0 }' "$KI26_SEGMENT")
if (( WARN_COUNT >= 1 && WARN_COUNT <= 2 )); then
  pass "1.10" "同一窗口“管理 API 鉴权失败” WARN 不超过 2 条（实际 ${WARN_COUNT}）"
else
  fail "1.10" "同一窗口“管理 API 鉴权失败” WARN 数量异常（实际 ${WARN_COUNT}，期望 1..2）"
fi
if (( LIMIT_COUNT == 1 )); then
  pass "1.11" "429 日志不超过 1 条（实际 1）"
else
  fail "1.11" "429 日志数量异常（实际 ${LIMIT_COUNT}，期望 1）"
fi
check_not_contains "1.12" "限速日志不含 token 明文" "$(cat "$KI26_SEGMENT")" "$WRONG_TOKEN"

# ---------------------------------------------------------------------------
# 2. KI-19：Hello 元数据校验
# ---------------------------------------------------------------------------

echo
echo "==> 2) KI-19 Hello 元数据（超长 / 控制字符）"

"$PYTHON" - "$META_LONG" "$META_CONTROL" <<'PY'
import json
import sys

prefix = "v034-evil-name-"
long_name = prefix + "x" * (129 - len(prefix))
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump({"name": long_name, "hostname": "v034-evil-host"}, handle)
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump({"name": "v034-evil-name\ninjected", "hostname": "v034-evil-host"}, handle)
PY
chmod 600 "$META_LONG" "$META_CONTROL"

api GET "/api/v1/agents"
expect_status "2.1" "读取 agents 列表作为基线" 200
A1_NAME_BEFORE=$(agents_field "$A1_ID" name)
A1_HOST_BEFORE=$(agents_field "$A1_ID" hostname)
check_eq "2.2" "基线 name 为真实 agent 配置名" "v034-hello" "$A1_NAME_BEFORE"
check_ne "2.3" "基线 hostname 非空" "" "$A1_HOST_BEFORE"

api GET "/api/v1/agents/${A1_ID}/control"
expect_status "2.4" "读取 agent_control 基线" 200
CAPS_BEFORE=$(json_get '",".join(sorted(d.get("capabilities", [])))')

api GET "/api/v1/audit?limit=200&agent_id=${A1_ID}"
expect_status "2.5" "读取审计基线" 200
AUDIT_BEFORE=$(audit_max_id)

run_agent_helper hello \
  --url "wss://127.0.0.1:${AGENT_PORT}/agent/ws" \
  --ca "$CA" --cert "$A1_DATA/agent.crt" --key "$A1_DATA/agent.key" \
  --agent-id "$A1_ID" --secret-file "$A1_DATA/agent.secret" \
  --metadata-file "$META_LONG" --expect problem
LONG_RESULT="$HELPER_RC|$(helper_field 'd.get("code","")')|$(helper_field 'd.get("closed")')"
check_eq "2.6" "name 129 字节的 Hello 收到 bad_frame 且关闭" "0|bad_frame|True" "$LONG_RESULT"

run_agent_helper hello \
  --url "wss://127.0.0.1:${AGENT_PORT}/agent/ws" \
  --ca "$CA" --cert "$A1_DATA/agent.crt" --key "$A1_DATA/agent.key" \
  --agent-id "$A1_ID" --secret-file "$A1_DATA/agent.secret" \
  --metadata-file "$META_CONTROL" --expect problem
CONTROL_RESULT="$HELPER_RC|$(helper_field 'd.get("code","")')|$(helper_field 'd.get("closed")')"
check_eq "2.7" "name 含换行的 Hello 收到 bad_frame 且关闭" "0|bad_frame|True" "$CONTROL_RESULT"

api GET "/api/v1/agents"
expect_status "2.8" "非法 Hello 后读取 agents 列表" 200
A1_NAME_AFTER=$(agents_field "$A1_ID" name)
A1_HOST_AFTER=$(agents_field "$A1_ID" hostname)
check_eq "2.9" "非法 Hello 未覆盖 agent name" "$A1_NAME_BEFORE" "$A1_NAME_AFTER"
check_eq "2.10" "非法 Hello 未覆盖 agent hostname" "$A1_HOST_BEFORE" "$A1_HOST_AFTER"
check_not_contains "2.11" "agents 列表不含恶意 name/hostname" \
  "${A1_NAME_AFTER}|${A1_HOST_AFTER}" "v034-evil"

api GET "/api/v1/agents/${A1_ID}/control"
expect_status "2.12" "非法 Hello 后读取 agent_control" 200
CAPS_AFTER=$(json_get '",".join(sorted(d.get("capabilities", [])))')
check_eq "2.13" "非法 Hello 未新增控制能力" "$CAPS_BEFORE" "$CAPS_AFTER"

api GET "/api/v1/audit?limit=200&agent_id=${A1_ID}"
expect_status "2.14" "非法 Hello 后读取审计" 200
AUDIT_AFTER=$(audit_max_id)
check_eq "2.15" "非法 Hello 未写审计" "$AUDIT_BEFORE" "$AUDIT_AFTER"

HUB_LOG_TEXT=$(cat "$HUB_LOG" 2>/dev/null || true)
check_not_contains "2.16" "hub 日志不打印恶意 name/hostname 值" "$HUB_LOG_TEXT" "v034-evil"

run_agent_helper hold \
  --url "wss://127.0.0.1:${AGENT_PORT}/agent/ws" \
  --ca "$CA" --cert "$A1_DATA/agent.crt" --key "$A1_DATA/agent.key" \
  --agent-id "$A1_ID" --secret-file "$A1_DATA/agent.secret" \
  --hold-seconds 2
HOLD_RESULT="$HELPER_RC|$(helper_field 'd.get("welcome")')|$(helper_field 'd.get("held")')"
check_eq "2.17" "正常 Hello 仍拿到 Welcome 并保持会话" "0|True|True" "$HOLD_RESULT"

check_eq "2.18" "非法 Hello 后真实 agent 仍 online" "online" "$(read_agent_status "$A1_ID")"

# ---------------------------------------------------------------------------
# 3. KI-18：Panel reset-password 吊销已有会话
# ---------------------------------------------------------------------------

echo
echo "==> 3) KI-18 reset-password 后旧会话失效（≤2s）"

COOKIE_CODE=$(panel_cookie_code "$PANEL_COOKIE" "/api/overview")
check_eq "3.1" "重置前旧 Cookie 访问 /api/overview 200" "200" "$COOKIE_CODE"

# 用配置内容哈希判断“落盘”，而不是 mtime：并发/高负载下 mtime 的更新与可见性
# 不够可靠，哈希变化是 reset-password 真正写入新密码哈希的直接证据。
PANEL_CFG_HASH_BEFORE=$(sha256sum "$PANEL_CFG" | awk '{print $1}')
RESET_START=$(date +%s%3N)
"$PANEL_BIN" reset-password --config "$PANEL_CFG" --password "$PANEL_NEW_PASSWORD" \
  > "$PANEL_RESET_LOG" 2>&1 &
RESET_PID=$!
PIDS+=("$RESET_PID")
chmod 600 "$PANEL_RESET_LOG"

RESET_WRITE_MS=""
# Argon2 在并发/高负载下可能明显变慢，等待窗口放宽到 30s；
# 下面的 watchdog 60s 只兜底真挂死，避免把“慢”误判成失败后 kill。
RESET_DEADLINE=$(( $(date +%s%3N) + 30000 ))
while :; do
  CURRENT_HASH=$(sha256sum "$PANEL_CFG" 2>/dev/null | awk '{print $1}')
  NOW_MS=$(date +%s%3N)
  if [[ -n "$CURRENT_HASH" && "$CURRENT_HASH" != "$PANEL_CFG_HASH_BEFORE" ]]; then
    RESET_WRITE_MS=$NOW_MS
    break
  fi
  if ! kill -0 "$RESET_PID" 2>/dev/null; then
    break
  fi
  if (( NOW_MS >= RESET_DEADLINE )); then
    break
  fi
  sleep 0.02
done

RESET_RC=0
( sleep 60; kill -9 "$RESET_PID" 2>/dev/null || true ) &
RESET_WATCHDOG=$!
wait "$RESET_PID" 2>/dev/null || RESET_RC=$?
kill "$RESET_WATCHDOG" 2>/dev/null || true
wait "$RESET_WATCHDOG" 2>/dev/null || true
drop_pid "$RESET_PID"

if [[ -n "$RESET_WRITE_MS" && "$RESET_RC" == "0" ]]; then
  pass "3.2" "reset-password 成功且配置已落盘（耗时 $(( RESET_WRITE_MS - RESET_START ))ms）"
else
  fail "3.2" "reset-password 失败或配置未落盘（rc=$RESET_RC）"
fi

REVOKE_CODE=""
REVOKE_MS=""
if [[ -n "$RESET_WRITE_MS" ]]; then
  while :; do
    REVOKE_CODE=$(panel_cookie_code "$PANEL_COOKIE" "/api/overview")
    NOW_MS=$(date +%s%3N)
    if [[ "$REVOKE_CODE" == "401" ]]; then
      REVOKE_MS=$(( NOW_MS - RESET_WRITE_MS ))
      break
    fi
    if (( NOW_MS - RESET_WRITE_MS >= 2500 )); then
      REVOKE_MS=$(( NOW_MS - RESET_WRITE_MS ))
      break
    fi
    sleep 0.03
  done
fi
if [[ "$REVOKE_CODE" == "401" ]] && (( ${REVOKE_MS:-99999} <= 2000 )); then
  pass "3.3" "落盘后 ${REVOKE_MS}ms 内旧 Cookie 访问 /api/overview 返回 401（≤2000ms）"
else
  fail "3.3" "旧 Cookie 未在 2s 内失效（code=$REVOKE_CODE，elapsed=${REVOKE_MS:-none}ms）"
fi

SESSION_CODE=$(panel_cookie_code "$PANEL_COOKIE" "/api/session")
check_eq "3.4" "公开端点 /api/session 仍 200（不作为 401 依据）" "200" "$SESSION_CODE"
SESSION_AUTH=$(json_get 'd.get("authenticated")')
check_eq "3.5" "/api/session 对旧 Cookie 返回 authenticated=false" "False" "$SESSION_AUTH"

OLD_LOGIN=$(panel_login "$PANEL_OLD_PASSWORD")
check_eq "3.6" "旧密码登录返回 401" "401" "$OLD_LOGIN"
NEW_LOGIN=$(panel_login "$PANEL_NEW_PASSWORD" "$PANEL_COOKIE_NEW")
check_eq "3.7" "新密码登录返回 204" "204" "$NEW_LOGIN"
NEW_COOKIE_CODE=$(panel_cookie_code "$PANEL_COOKIE_NEW" "/api/overview")
check_eq "3.8" "新 Cookie 可访问 /api/overview" "200" "$NEW_COOKIE_CODE"

# ---------------------------------------------------------------------------
# 4. KI-24：同一 agent 多连接能力缓存
# ---------------------------------------------------------------------------

echo
echo "==> 4) KI-24 多连接能力缓存（最新连接 / 断开回退 / 晚到 Hello）"

kill -9 "$AGENT2_PID" 2>/dev/null || true
wait "$AGENT2_PID" 2>/dev/null || true
drop_pid "$AGENT2_PID"
AGENT2_PID=""
if wait_agent_status "$A2_ID" offline 10; then
  pass "4.1" "关闭真实 agent 后状态 offline，多连接测试只剩 fake 连接"
else
  fail "4.1" "真实 agent 未在 10s 内变为 offline（最后: $LAST_STATUS）"
fi

: > "$MULTI_CMD"
: > "$MULTI_STATUS"
"$PYTHON" "$V034_AGENT" multi \
  --url "wss://127.0.0.1:${AGENT_PORT}/agent/ws" \
  --ca "$CA" --cert "$A2_DATA/agent.crt" --key "$A2_DATA/agent.key" \
  --agent-id "$A2_ID" --secret-file "$A2_DATA/agent.secret" \
  --cmd-file "$MULTI_CMD" --status-file "$MULTI_STATUS" \
  --caps-b "systemd" --caps-a "systemd,logs" --caps-c "logs,process,systemd" \
  > "$MULTI_LOG" 2>&1 &
MULTI_PID=$!
PIDS+=("$MULTI_PID")
if wait_status_line "$MULTI_STATUS" '^MAIN READY$' 20; then
  pass "4.2" "同一 agent 两条真实 mTLS 连接建立（旧 B、新 A）并收到 Welcome"
else
  die "multi fake agent 未在 20s 内就绪（见 multi.log / multi.status）"
fi

if wait_control_caps "$A2_ID" "logs,systemd" 5; then
  pass "4.3" "新连接能力 A 被 API 看到（capabilities=logs,systemd）"
else
  fail "4.3" "API 未看到新连接能力 A（实际 [$LAST_CAPS]）"
fi

# 旧连接已经完成过 Hello（能力 B）。会话建立后再补发一条 Hello（能力 C），
# 等价于“旧连接晚到的 Hello”：无论 hub 忽略还是拒绝，都不得改写 DB 里的 A。
append_multi_cmd "late-hello"
if wait_status_line "$MULTI_STATUS" '^old LATE_SENT$' 5; then
  pass "4.4" "旧连接已发出晚到 Hello（能力 C）"
else
  fail "4.4" "旧连接的晚到 Hello 未发出"
fi
sleep 0.5
if grep -Eq '^old (CLOSED|PROBLEM)' "$MULTI_STATUS"; then
  fail "4.5" "旧连接因晚到 Hello 被关闭/拒绝，无法验证“不覆盖能力”"
else
  pass "4.5" "旧连接仍保持会话（晚到 Hello 未导致断开）"
fi
api GET "/api/v1/agents/${A2_ID}/control"
if [[ "$STATUS" == "200" ]]; then
  LATE_CAPS=$(json_get '",".join(sorted(d.get("capabilities", [])))')
else
  LATE_CAPS="HTTP $STATUS"
fi
if [[ "$LATE_CAPS" == "logs,systemd" ]]; then
  pass "4.6" "旧连接晚到的 Hello（能力 C）未覆盖新连接能力 A"
else
  fail_ki24 "4.6" "旧连接晚到的 Hello 覆盖了能力（期望 logs,systemd，实际 [$LATE_CAPS]）"
fi

append_multi_cmd "close-new"
if wait_status_line "$MULTI_STATUS" '^new CLOSED$' 5; then
  pass "4.7" "已关闭新连接，旧连接保持打开"
else
  fail "4.7" "新连接未按命令关闭"
fi
if wait_control_caps "$A2_ID" "systemd" 5; then
  pass "4.8" "新连接断开后 API 能力回退为旧连接的 B（systemd）"
else
  fail_ki24 "4.8" "新连接断开后能力未回退为 B（实际 [$LAST_CAPS]）"
fi

api GET "/api/v1/agents/${A2_ID}/control"
ONLINE_AFTER_NEW_CLOSE=$(json_get 'd.get("online")')
check_eq "4.9" "仍有旧连接时 online=true" "True" "$ONLINE_AFTER_NEW_CLOSE"

api POST "/api/v1/agents/${A2_ID}/control" '{"capability":"systemd","action":"list"}'
expect_status "4.10" "关闭新连接后控制请求 200" 200
check_eq "4.11" "控制请求 ok=true" "True" "$(json_get 'd.get("ok")')"
check_eq "4.12" "控制结果类型 systemd_units" "systemd_units" \
  "$(json_get 'd.get("result",{}).get("type")')"
OLD_UNITS=$(json_get '",".join(sorted(u.get("unit","") for u in d.get("result",{}).get("units",[])))')
check_eq "4.13" "控制 sender 指向旧连接（角色化 unit 名）" "v034-old-conn.service" "$OLD_UNITS"
if wait_status_line "$MULTI_STATUS" '^old CTRL id=[0-9]+$' 2; then
  pass "4.14" "旧连接实际收到 ControlRequest 并应答"
else
  fail "4.14" "旧连接未收到 ControlRequest"
fi
if grep -Eq '^old CLOSED$' "$MULTI_STATUS"; then
  fail "4.15" "旧连接在发送控制请求前已关闭"
else
  pass "4.15" "旧连接在发送控制请求时仍存活"
fi

append_multi_cmd "close-old"
if wait_status_line "$MULTI_STATUS" '^old CLOSED$' 5; then
  pass "4.16" "最后一条连接已关闭"
else
  fail "4.16" "最后一条连接未关闭"
fi
if wait_agent_status "$A2_ID" offline 10; then
  pass "4.17" "所有连接关闭后状态 offline"
else
  fail "4.17" "所有连接关闭后状态未在 10s 内变为 offline（最后: $LAST_STATUS）"
fi

api GET "/api/v1/agents/${A2_ID}/control"
if [[ "$STATUS" == "200" ]]; then
  FINAL_ONLINE=$(json_get 'd.get("online")')
  FINAL_CAPS=$(json_get '",".join(sorted(d.get("capabilities", [])))')
else
  FINAL_ONLINE="HTTP $STATUS"
  FINAL_CAPS="HTTP $STATUS"
fi
check_eq "4.18" "全部断开后 online=false" "False" "$FINAL_ONLINE"
if [[ "$FINAL_CAPS" == "systemd" ]]; then
  pass "4.19" "全部断开后能力保留 B（systemd）"
else
  fail_ki24 "4.19" "全部断开后能力未保留 B（实际 [$FINAL_CAPS]）"
fi

# ---------------------------------------------------------------------------
# 5. KI-21：数据目录与 SQLite 文件权限
# ---------------------------------------------------------------------------

echo
echo "==> 5) KI-21 数据目录 / SQLite 权限（0700 / 0600）"

DB_COUNT=0
DB_PATH=""
while IFS= read -r candidate; do
  DB_COUNT=$((DB_COUNT + 1))
  DB_PATH=$candidate
done < <(find "$HUB_DATA" -maxdepth 1 -type f -name '*.db' -print 2>/dev/null)
check_eq "5.1" "数据目录下恰好一个 SQLite 主库" "1" "$DB_COUNT"
[[ -n "$DB_PATH" ]] || die "找不到 hub SQLite 主库"
WAL_PATH="$DB_PATH-wal"
SHM_PATH="$DB_PATH-shm"

check_eq "5.2" "hub 启动后数据目录为 0700" "700" "$(file_mode "$HUB_DATA")"
check_eq "5.3" "SQLite 主库为 0600" "600" "$(file_mode "$DB_PATH")"
check_eq "5.4" "SQLite WAL 为 0600" "600" "$(file_mode "$WAL_PATH")"
check_eq "5.5" "SQLite SHM 为 0600" "600" "$(file_mode "$SHM_PATH")"

echo "==> 停止 hub，预置过宽权限（目录 0755、DB 0644、删除 WAL/SHM）"
stop_hub
# 删 sidecar 前先用同版本 CLI 打开一次存储，触发 SQLite checkpoint。
# 否则 SIGTERM 退出时尚未 checkpoint 的已提交事务（含 agent 纳管记录）只存在于
# WAL 里，删除 WAL/SHM 会真的丢数据，后续“重启后服务仍可用”就变成在测数据丢失，
# 而不是测权限收紧。checkpoint 后 WAL/SHM 会被正常清掉，再显式 rm 一次兜底。
if ! "$HUB_BIN" token list --config "$HUB_CFG" > "$TMP_DIR/checkpoint.log" 2>&1; then
  dump_log "$TMP_DIR/checkpoint.log" 40
  die "停止 hub 后无法用 CLI 打开存储做 checkpoint"
fi
if [[ ! -e "$WAL_PATH" && ! -e "$SHM_PATH" ]]; then
  pass "5.6" "停止后 WAL/SHM 已 checkpoint 清理，可安全预置 SQLite 过宽权限"
else
  fail "5.6" "停止后 WAL/SHM 仍存在，无法在不丢数据的前提下预置权限"
fi
chmod 0755 "$HUB_DATA"
chmod 0644 "$DB_PATH"
rm -f "$WAL_PATH" "$SHM_PATH"
if [[ "$(file_mode "$HUB_DATA")" == "755" && "$(file_mode "$DB_PATH")" == "644" ]]; then
  pass "5.7" "已预置 data_dir=0755、DB=0644，并删除 WAL/SHM"
else
  fail "5.7" "预置过宽权限失败（dir=$(file_mode "$HUB_DATA") db=$(file_mode "$DB_PATH")）"
fi

echo "==> 重启 hub，验证权限被收紧且服务可用"
start_hub
pass "5.8" "过宽权限下 hub 仍能启动（/healthz 200）"

check_eq "5.9" "重启后数据目录收紧为 0700" "700" "$(file_mode "$HUB_DATA")"
check_eq "5.10" "重启后 SQLite 主库收紧为 0600" "600" "$(file_mode "$DB_PATH")"

if ! wait_for_file "$WAL_PATH" 5 || ! wait_for_file "$SHM_PATH" 5; then
  fail "5.11" "重启后未重新创建 WAL/SHM（wal=$(file_mode "$WAL_PATH"), shm=$(file_mode "$SHM_PATH")）"
else
  check_eq "5.11" "重启后 WAL/SHM 重新创建且为 0600" "600|600" \
    "$(file_mode "$WAL_PATH")|$(file_mode "$SHM_PATH")"
fi

if wait_agent_status "$A1_ID" online 20; then
  pass "5.12" "重启后真实 agent 重新 online（纳管数据未丢失）"
else
  fail "5.12" "重启后真实 agent 未在 20s 内重新 online（最后: $LAST_STATUS）"
fi
api GET "/api/v1/agents"
expect_status "5.13" "重启后管理 API 仍可用（agents 列表）" 200

check_eq "5.14" "未修改测试临时目录的父目录权限" "$PARENT_MODE_BEFORE" "$(stat -c %a "$PARENT_DIR")"
check_eq "5.15" "未修改脚本临时目录权限" "$TMP_MODE_BEFORE" "$(file_mode "$TMP_DIR")"

# 重启后 WAL/SHM 的 0600 断言放在 5.11 内完成；再确认一次避免并发创建时序。
check_eq "5.16" "重启后 WAL 仍为 0600" "600" "$(file_mode "$WAL_PATH")"
check_eq "5.17" "重启后 SHM 仍为 0600" "600" "$(file_mode "$SHM_PATH")"

# ---------------------------------------------------------------------------
# 6. 日志脱敏与稳定性
# ---------------------------------------------------------------------------

echo
echo "==> 6) 日志脱敏与稳定性"

check_log_absent "6.1" "$HUB_LOG" "hub 日志不含 admin_token" "$ADMIN_TOKEN"
check_log_absent "6.2" "$HUB_LOG" "hub 日志不含 read token" "$READ_TOKEN"
check_log_absent "6.3" "$HUB_LOG" "hub 日志不含 enrollment token" "$ENROLL1"
check_log_absent "6.4" "$HUB_LOG" "hub 日志不含 agent secret" "$AGENT1_SECRET"
check_log_absent "6.5" "$HUB_LOG" "hub 日志不含面板旧密码" "$PANEL_OLD_PASSWORD"
check_log_absent "6.6" "$HUB_LOG" "hub 日志不含面板新密码" "$PANEL_NEW_PASSWORD"
check_log_absent "6.7" "$PANEL_LOG" "panel 日志不含 hub read token" "$READ_TOKEN"
check_log_absent "6.8" "$PANEL_LOG" "panel 日志不含面板新密码" "$PANEL_NEW_PASSWORD"
check_log_absent "6.9" "$A1_LOG" "agent 日志不含 enrollment token" "$ENROLL1"
check_log_absent "6.10" "$A1_LOG" "agent 日志不含 agent secret" "$AGENT1_SECRET"
check_log_absent "6.11" "$A2_LOG" "agent 日志不含 agent secret" "$AGENT2_SECRET"

if [[ -s "$HUB_LOG" ]] && ! grep -q 'panicked at' "$HUB_LOG"; then
  pass "6.12" "hub 日志无 panic"
else
  fail "6.12" "hub 日志为空或出现 panic"
fi
if [[ -s "$A1_LOG" ]] && ! grep -q 'panicked at' "$A1_LOG"; then
  pass "6.13" "agent A1 日志无 panic"
else
  fail "6.13" "agent A1 日志为空或出现 panic"
fi
if [[ -s "$PANEL_LOG" ]] && ! grep -q 'panicked at' "$PANEL_LOG"; then
  pass "6.14" "panel 日志无 panic"
else
  fail "6.14" "panel 日志为空或出现 panic"
fi

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

echo
if (( FAILS > 0 )); then
  echo "v034 e2e 结果: ${PASSES} 项通过，${FAILS} 项失败" >&2
  if (( KI24_FAILS > 0 )); then
    echo "其中 ${KI24_FAILS} 项属于 KI-24 多连接能力缓存（最新连接能力 / 断开回退 / 晚到 Hello 不覆盖）。" >&2
  fi
  exit 1
fi
echo "v034 e2e 结果: 全部 ${PASSES} 项通过"
