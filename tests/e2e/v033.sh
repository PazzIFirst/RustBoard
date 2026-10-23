#!/usr/bin/env bash
#
# RustBoard v0.3.3 管理面安全端到端回归：
#   #9  scoped token（read / write / 吊销 / 轮换 / 列表不泄露）
#   #9  管理端 TLS（required 下 HTTPS、明文失败、非回环明文拒绝启动）
#   #9  Panel HTTPS + hub_ca（Panel → Hub 只信任私有 CA）
#   #17 agent 吊销后控制命令被拒、fake systemctl 不再执行、审计无 ok
#   #20 正常文件日志 tail 不回归
#   #21 systemd list-units + list-unit-files 合并（未加载 unit 可见且可 start）
#
# 方案：docs/plans/2026-10-23-v0.3.3-admin-security.md §4.1–§4.5、§6.2
#
# 覆盖：
#   1. 管理端 TLS：`hub init --admin-tls required --san 127.0.0.1` 后
#      `curl --cacert certs/ca.crt https://…/healthz` 与 `/api/v1/agents` 均 200；
#      不带 CA 的 HTTPS 与明文 HTTP 都不得返回 200；另用一份非回环 +
#      `admin_tls="off"` 的配置执行 `timeout 10 hub run`，必须非 0 退出且日志
#      点名 admin_tls / 回环。
#   2. token scope：read token GET agents 200、POST control 403 forbidden_scope；
#      write token POST systemd list 200、GET audit 200 且控制审计 actor 是 token
#      名称；revoke 后旧 token 401、旧 admin_token 仍 200；rotate 后旧 token 立即
#      401、新 token 200；`token list` 不含任何明文/64 位哈希；`token create
#      --name admin` 因保留 actor 名被拒。
#   3. Panel HTTPS：用 write token 初始化 Panel（`--hub https://…`），把 hub 的
#      ca.crt 写进 panel.toml 的 `hub_ca`；启动后用 `panel_probe.py` 登录，
#      `/api/overview` 与 `/api/audit` 均 200；Panel 日志明确“仅信任 hub_ca”。
#      另用非 PEM 的 hub_ca 验证启动失败；换成另一套合法 CA 时访问 hub 必须 502
#      （系统根证书不参与，证明成功路径确实依赖 hub_ca）。
#   4. #21：fake systemctl 按 `$1` 返回 list-units（nginx.service loaded）与
#      list-unit-files（demo.service disabled）。控制面 list 合并后 demo.service
#      恰好一条且状态为 not-loaded/inactive/dead、description 为空；nginx.service
#      保留 loaded 状态并去重；start demo.service 返回 200 且 fake argv 记录
#      `start demo.service`。
#   5. #20：agent 配置 logs=true + 文件来源 app.log，正常 tail 返回最新内容；
#      写新行后再 tail 能看到新内容（每次重新安全打开文件）。
#   6. #17：agent 在线时 `hub agent revoke --config … --id …`；随后立即 POST
#      control 返回 403 agent_revoked，fake systemctl argv 不再增加；审计最新一条
#      为 result=denied / error_code=agent_revoked，吊销后没有 ok；agent 连接在
#      ≤3s 内关闭（进程退出或日志出现吊销/不可重试）。
#   7. 兜底：hub/agent/panel 日志不出现各类 token 明文、无 panic。
#
# 说明：本脚本只写测试，不修改实现；断言失败就是失败，不跳过、不弱化。
#      控制命令只通过 HTTP/CLI 发出，没有任何 shell 拼接的命令字符串。
#
# 依赖：bash 4.4+、python3 3.8+（仅标准库）、curl、cargo/rustc。
# 用法：bash tests/e2e/v033.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/v033.sh   # 保留临时目录与脱敏日志
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PANEL_PROBE="$SCRIPT_DIR/panel_probe.py"
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}
# 仓库历史遗留跟踪了 tests/e2e/__pycache__/*.pyc；禁止 Python 写字节码。
export PYTHONDONTWRITEBYTECODE=1

PASSES=0
FAILS=0
STATUS=""
BODY=""
PIDS=()
HUB_PID=""
AGENT1_PID=""
AGENT2_PID=""
PANEL_PID=""
STARTED_AGENT_PID=""

ADMIN_TOKEN=""
READ_TOKEN=""
WRITE_TOKEN=""
TEMP_TOKEN=""
ROTOR_TOKEN_OLD=""
ROTOR_TOKEN_NEW=""
PANEL_TOKEN=""
ENROLL1=""
ENROLL2=""
AGENT1_SECRET=""
AGENT2_SECRET=""

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

die() {
  echo "FATAL: $*" >&2
  exit 1
}

# ---------------------------------------------------------------------------
# 临时目录与失败现场
# ---------------------------------------------------------------------------

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-v033.XXXXXX")
chmod 700 "$TMP_DIR"

FAKE_DIR="$TMP_DIR/fake"
mkdir -p "$FAKE_DIR"
chmod 700 "$FAKE_DIR"

HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
HUB_INIT_LOG="$TMP_DIR/hub-init.log"
NONLOOP_CFG="$TMP_DIR/hub-nonloop-off.toml"
NONLOOP_LOG="$TMP_DIR/hub-nonloop-off.log"
A1_CFG="$TMP_DIR/agent-control.toml"
A1_DATA="$TMP_DIR/agent-control"
A1_LOG="$TMP_DIR/agent-control.log"
A2_CFG="$TMP_DIR/agent-revoke.toml"
A2_DATA="$TMP_DIR/agent-revoke"
A2_LOG="$TMP_DIR/agent-revoke.log"
APP_LOG="$TMP_DIR/app.log"
PANEL_CFG="$TMP_DIR/panel.toml"
PANEL_LOG="$TMP_DIR/panel.log"
PANEL_INIT_LOG="$TMP_DIR/panel-init.log"
PANEL_COOKIE="$TMP_DIR/panel.cookie"
PANEL_AUDIT_JSON="$TMP_DIR/panel-audit.json"
PANEL_BADCA_CFG="$TMP_DIR/panel-badca.toml"
PANEL_BADCA_LOG="$TMP_DIR/panel-badca.log"
PANEL_WRONGCA_CFG="$TMP_DIR/panel-wrongca.toml"
PANEL_WRONGCA_LOG="$TMP_DIR/panel-wrongca.log"
PANEL_WRONGCA_COOKIE="$TMP_DIR/panel-wrongca.cookie"
OTHER_HUB_CFG="$TMP_DIR/other-hub.toml"
OTHER_HUB_DATA="$TMP_DIR/other-hub"
OTHER_HUB_LOG="$TMP_DIR/other-hub-init.log"
BUILD_LOG="$TMP_DIR/build.log"
CURL_ERR="$TMP_DIR/curl.err"
REVOKE_LOG="$TMP_DIR/revoke.log"
HTTP_BODY_FILE="$TMP_DIR/http-body"
AUDIT_JSON="$TMP_DIR/audit.json"

SYSTEMCTL_LOG="$FAKE_DIR/systemctl.argv"
JOURNALCTL_LOG="$FAKE_DIR/journalctl.argv"

# 失败现场先脱敏：所有 token / agent secret / Bearer 头 / 一次性 token 行。
redact_log() {
  RB_V033_SECRETS="$ADMIN_TOKEN|$READ_TOKEN|$WRITE_TOKEN|$TEMP_TOKEN|$ROTOR_TOKEN_OLD|$ROTOR_TOKEN_NEW|$PANEL_TOKEN|$ENROLL1|$ENROLL2|$AGENT1_SECRET|$AGENT2_SECRET" \
  "$PYTHON" -c '
import os
import re
import sys

secrets = [item for item in os.environ.get("RB_V033_SECRETS", "").split("|") if item]
text = sys.stdin.buffer.read().decode("utf-8", "replace")
for secret in secrets:
    text = text.replace(secret, "<redacted>")
text = re.sub(r"(Bearer )[^\s]+", r"\1<redacted>", text)
text = re.sub(r"(管理 API token:).*", r"\1 <redacted>", text)
text = re.sub(r"(一次性 token[^:：]*[:：]).*", r"\1 <redacted>", text)
text = re.sub(r"(面板密码（仅显示一次，请立即保存）[:：]).*", r"\1 <redacted>", text)
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
    echo "===== v033 e2e 失败现场（日志已脱敏）=====" >&2
    for log in "$HUB_LOG" "$A1_LOG" "$A2_LOG" "$PANEL_LOG" "$PANEL_BADCA_LOG" \
               "$PANEL_WRONGCA_LOG" "$HUB_INIT_LOG" "$OTHER_HUB_LOG" "$NONLOOP_LOG" \
               "$PANEL_INIT_LOG" "$BUILD_LOG" "$REVOKE_LOG" "$CURL_ERR"; do
      dump_log "$log" 120
    done
    for log in "$SYSTEMCTL_LOG" "$JOURNALCTL_LOG"; do
      if [[ -s "$log" ]]; then
        echo "---- $(basename "$log") ----" >&2
        tail -n 60 "$log" >&2 || true
      fi
    done
    echo "已通过 $PASSES 项，失败 $FAILS 项" >&2
  fi

  if [[ "${KEEP_E2E_TMP:-0}" == "1" ]]; then
    echo "临时目录已保留: $TMP_DIR" >&2
  else
    # 只删除本脚本 mktemp 出来的目录，避免误删其它路径。
    if [[ -n "${TMP_DIR:-}" && "$TMP_DIR" == "${TMPDIR:-/tmp}"/rustboard-v033.* ]]; then
      rm -rf -- "$TMP_DIR"
    else
      echo "警告: 临时目录不符合预期，未删除: ${TMP_DIR:-<unset>}" >&2
    fi
  fi
  exit "$code"
}
trap cleanup EXIT

for tool in "$PYTHON" "$CARGO" curl timeout mktemp date tail awk sed grep stat tr cat; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "找不到命令: $tool（python3 需 3.8+；cargo 请放进 PATH 或设置 CARGO=...）"
done
[[ -f "$PANEL_PROBE" ]] || die "缺少 panel probe: $PANEL_PROBE"

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

# 一次挑 8 个互不相同的空闲端口：agent / admin / panel / 非回环 / 坏 PEM panel /
# 错 CA panel / 另一套 hub init 的 agent+admin。
pick_ports() {
  "$PYTHON" - <<'PY'
import random
import socket

chosen = []
while len(chosen) < 8:
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

# 控制面错误结构：{"ok":false,"error":{"code":…,"message":…}}。
expect_control_error_code() {
  local id=$1 desc=$2 expected=$3
  local code
  code=$(json_get 'd.get("error", {}).get("code", "")')
  if [[ "$code" == "$expected" ]]; then
    pass "$id" "$desc：code=$expected"
  else
    fail "$id" "$desc（期望 code=$expected，实际 [$code]）"
  fi
}

# 鉴权错误结构：{"error":"unauthorized"} / {"error":"forbidden_scope"}。
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

# 管理 API；token 可覆盖（默认旧 admin_token）。ADMIN_URL 为 https 时带 CA。
api_as() {
  local token=$1 method=$2 path=$3 data=${4:-}
  local -a args=(
    -sS --noproxy '*' --max-time 25 -o "$HTTP_BODY_FILE" -w '%{http_code}'
    -X "$method" "${ADMIN_URL}${path}"
    -H "Authorization: Bearer ${token}"
    -H 'Content-Type: application/json'
    -H 'Accept: application/json'
  )
  [[ "$ADMIN_URL" == https://* ]] && args+=(--cacert "$CA")
  [[ -n "$data" ]] && args+=(--data-binary "$data")
  STATUS=$(curl "${args[@]}" 2>"$CURL_ERR") || STATUS="000"
  BODY=$(cat "$HTTP_BODY_FILE" 2>/dev/null || true)
}

api() {
  api_as "$ADMIN_TOKEN" "$@"
}

# 直接 curl 探测（不做 JSON 断言），返回 http_code，失败时为 000。
http_code() {
  local url=$1 cacert=${2:-}
  local -a args=(-sS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}')
  [[ -n "$cacert" ]] && args+=(--cacert "$cacert")
  local code
  code=$(curl "${args[@]}" "$url" 2>/dev/null) || code="000"
  printf '%s' "$code"
}

wait_health() {
  local url=$1 timeout=$2 cacert=${3:-}
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local code
  while :; do
    code=$(http_code "$url" "$cacert")
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

# `token create` 只输出一次明文；校验为 64 位 hex 后返回。
create_token() {
  local name=$1 scope=$2 out
  out=$("$HUB_BIN" token create --config "$HUB_CFG" --name "$name" --scope "$scope" \
    2>"$TMP_DIR/token-create.err") \
    || die "token create --name $name --scope $scope 失败（$(cat "$TMP_DIR/token-create.err" 2>/dev/null)）"
  [[ "$out" =~ ^[0-9a-f]{64}$ ]] || die "token create 输出不是 64 位 hex（不打印内容）"
  printf '%s' "$out"
}

# 替换或追加一个 TOML 表（从第一个 [control] 开始截断，再把新表追加到末尾）。
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
  wait_health "$ADMIN_URL/healthz" 20 "$CA" || die "hub 未在 20s 内就绪（${ADMIN_URL}/healthz）"
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

# 面板 API，使用 panel_probe.py 登录得到的 rb_session Cookie。
panel_api() {
  local method=$1 path=$2 data=${3:-}
  local cookie
  cookie=$(tr -d '\n' < "$PANEL_COOKIE")
  local -a args=(
    -sS --noproxy '*' --max-time 25 -o "$HTTP_BODY_FILE" -w '%{http_code}'
    -X "$method" "${PANEL_URL}${path}"
    -H "Cookie: ${cookie}"
    -H "Origin: ${PANEL_URL}"
    -H "Referer: ${PANEL_URL}/"
    -H 'Content-Type: application/json'
    -H 'Accept: application/json'
  )
  [[ -n "$data" ]] && args+=(--data-binary "$data")
  STATUS=$(curl "${args[@]}" 2>"$CURL_ERR") || STATUS="000"
  BODY=$(cat "$HTTP_BODY_FILE" 2>/dev/null || true)
}

# ---------------------------------------------------------------------------
# 构建与 fake 工具
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub / rustboard-agent / rustboard-panel"
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
pass "0.1" "cargo build 三个 bin 成功"

echo "==> 生成 fake systemctl（按 \$1 返回 list-units / list-unit-files）"
cat > "$FAKE_DIR/systemctl" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >> "${SYSTEMCTL_LOG}"
if [ "\$1" = "list-units" ]; then
  cat <<'OUT'
nginx.service loaded active running A high performance web server
OUT
  exit 0
fi
if [ "\$1" = "list-unit-files" ]; then
  cat <<'OUT'
demo.service disabled
nginx.service enabled
other.service disabled
OUT
  exit 0
fi
echo "fake-systemctl \$*"
exit 0
EOF
chmod 0755 "$FAKE_DIR/systemctl"

cat > "$FAKE_DIR/journalctl" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >> "${JOURNALCTL_LOG}"
exit 1
EOF
chmod 0755 "$FAKE_DIR/journalctl"

# #20：正常文件日志。app.log 放在临时目录（通常是 tmpfs），同时覆盖
# “日志路径跨挂载点仍可打开”的兼容性回归。
for i in 1 2 3 4 5; do
  printf 'v033-line-%s\n' "$i"
done > "$APP_LOG"

# ---------------------------------------------------------------------------
# 初始化 hub（管理口 TLS）与 agent 配置
# ---------------------------------------------------------------------------

PORT_LINE=$(pick_ports) || die "无法挑选 8 个空闲端口"
read -r AGENT_PORT ADMIN_PORT PANEL_PORT NONLOOP_PORT BADCA_PORT \
  WRONGCA_PORT OTHER_AGENT_PORT OTHER_ADMIN_PORT <<< "$PORT_LINE"
for port in "$AGENT_PORT" "$ADMIN_PORT" "$PANEL_PORT" "$NONLOOP_PORT" "$BADCA_PORT" \
            "$WRONGCA_PORT" "$OTHER_AGENT_PORT" "$OTHER_ADMIN_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] || die "端口解析失败: $PORT_LINE"
done
ADMIN_URL="https://127.0.0.1:${ADMIN_PORT}"
PANEL_URL="http://127.0.0.1:${PANEL_PORT}"
CA="$HUB_DATA/certs/ca.crt"

echo "==> 初始化 hub（agent=${AGENT_PORT} admin=${ADMIN_PORT} HTTPS）"
if ! "$HUB_BIN" init \
    --config "$HUB_CFG" \
    --data-dir "$HUB_DATA" \
    --agent-listen "127.0.0.1:${AGENT_PORT}" \
    --admin-listen "127.0.0.1:${ADMIN_PORT}" \
    --admin-tls required \
    --san 127.0.0.1 \
    --force > "$HUB_INIT_LOG" 2>&1; then
  dump_log "$HUB_INIT_LOG" 80
  die "hub init 失败"
fi
pass "0.2" "hub init --admin-tls required --san 127.0.0.1 成功"

sed -i 's/^self_monitor = true$/self_monitor = false/' "$HUB_CFG"
sed -i 's/^sample_interval_ms = .*/sample_interval_ms = 1000/' "$HUB_CFG"
# 管理 API 连续请求很多；关闭限速避免测试自己打成 429。
for key in admin_rate_limit_per_min admin_write_rate_limit_per_min; do
  if grep -q "^${key} = " "$HUB_CFG"; then
    sed -i "s/^${key} = .*/${key} = 0/" "$HUB_CFG"
  else
    printf '\n%s = 0\n' "$key" >> "$HUB_CFG"
  fi
done
grep -q '^admin_tls = "required"' "$HUB_CFG" || die "hub 配置缺少 admin_tls=required"
grep -q '^self_monitor = false' "$HUB_CFG" || die "无法关闭 self_monitor"
grep -q '^admin_rate_limit_per_min = 0' "$HUB_CFG" || die "无法放宽管理读限速"
grep -q '^admin_write_rate_limit_per_min = 0' "$HUB_CFG" || die "无法放宽管理写限速"

ADMIN_TOKEN=$(cfg_str "$HUB_CFG" admin_token) || die "无法解析 hub admin_token"
[[ -n "$ADMIN_TOKEN" ]] || die "hub 配置缺少 admin_token"
[[ -f "$CA" ]] || die "缺少 CA 证书: $CA"
FPR=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p') \
  || die "无法读取服务端证书指纹"
[[ "$FPR" =~ ^[0-9a-f]{64}$ ]] || die "服务端证书指纹非法"

cat > "$TMP_DIR/hub-control.toml" <<'EOF'
[control]
enabled = true
systemd = true
docker = false
process = false
logs = true
request_timeout_ms = 15000
max_pending_per_session = 32
max_output_bytes = 262144
EOF
set_control_table "$HUB_CFG" "$TMP_DIR/hub-control.toml"

# 两个 agent 都在 hub 启动前生成 enrollment token。
ENROLL1=$(add_agent_token "v033-control")
ENROLL2=$(add_agent_token "v033-revoke")
write_base_agent_config "$A1_CFG" "v033-control" "$ENROLL1" "$A1_DATA"
write_base_agent_config "$A2_CFG" "v033-revoke" "$ENROLL2" "$A2_DATA"

cat > "$TMP_DIR/control-a1.toml" <<EOF
[control]
enabled = true
systemd = true
docker = false
process = false
logs = true
systemd_units = ["nginx*", "demo*"]
command_timeout_secs = 10
max_log_lines = 200
systemctl_path = "${FAKE_DIR}/systemctl"
journalctl_path = "${FAKE_DIR}/journalctl"

[[control.log_sources]]
id = "app"
kind = "file"
target = "${APP_LOG}"
name = "App file"
EOF
set_control_table "$A1_CFG" "$TMP_DIR/control-a1.toml"

cat > "$TMP_DIR/control-a2.toml" <<EOF
[control]
enabled = true
systemd = true
docker = false
process = false
logs = false
systemd_units = ["nginx*"]
command_timeout_secs = 10
max_log_lines = 200
systemctl_path = "${FAKE_DIR}/systemctl"
journalctl_path = "${FAKE_DIR}/journalctl"
EOF
set_control_table "$A2_CFG" "$TMP_DIR/control-a2.toml"

echo "==> 启动 hub 与两个真实 agent"
start_hub
pass "0.3" "hub 以 HTTPS 管理口就绪（${ADMIN_URL}）"

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
pass "0.4" "两个真实 agent 完成 enrollment 并 online"

# ---------------------------------------------------------------------------
# 1. 管理端 TLS
# ---------------------------------------------------------------------------

echo
echo "==> 1) 管理端 TLS：HTTPS / 明文 / 非回环 off 拒绝启动"

code=$(http_code "$ADMIN_URL/healthz" "$CA")
check_eq "1.1" "curl --cacert ca.crt 访问 HTTPS /healthz" "200" "$code"

api GET "/api/v1/agents"
expect_status "1.2" "HTTPS 管理 API 使用旧 admin_token" 200
if "$PYTHON" - "$HTTP_BODY_FILE" <<'PY'
import json
import sys

try:
    with open(sys.argv[1], encoding="utf-8") as handle:
        value = json.load(handle)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if isinstance(value, list) else 1)
PY
then
  pass "1.3" "HTTPS /api/v1/agents 响应是 JSON 数组"
else
  fail "1.3" "HTTPS /api/v1/agents 响应不是 JSON 数组"
fi

NO_CA_CODE=$(http_code "$ADMIN_URL/healthz")
check_ne "1.5" "不提供 CA 时 HTTPS 校验失败（未信任私有 CA）" "200" "$NO_CA_CODE"

PLAIN_CODE=$(http_code "http://127.0.0.1:${ADMIN_PORT}/healthz")
check_ne "1.6" "明文 HTTP 访问管理口不返回 200" "200" "$PLAIN_CODE"

# 非回环 + admin_tls=off 必须拒绝启动。
"$PYTHON" - "$HUB_CFG" "$NONLOOP_CFG" "$NONLOOP_PORT" <<'PY'
import re
import sys

source, target, port = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(source, encoding="utf-8").read()
text, n1 = re.subn(r'(?m)^admin_listen\s*=.*$',
                   lambda _m: f'admin_listen = "0.0.0.0:{port}"', text)
text, n2 = re.subn(r'(?m)^admin_tls\s*=.*$',
                   lambda _m: 'admin_tls = "off"', text)
if n1 != 1 or n2 != 1:
    raise SystemExit(f"改写非回环配置失败: admin_listen={n1} admin_tls={n2}")
with open(target, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
chmod 600 "$NONLOOP_CFG"
set +e
timeout 10 "$HUB_BIN" run --config "$NONLOOP_CFG" > "$NONLOOP_LOG" 2>&1
NONLOOP_RC=$?
set -e
if (( NONLOOP_RC == 124 )); then
  fail "1.7" "非回环 + admin_tls=off 的 hub 仍在运行（10s 内未拒绝启动）"
elif (( NONLOOP_RC == 0 )); then
  fail "1.7" "非回环 + admin_tls=off 的 hub 正常退出（未拒绝启动）"
else
  pass "1.7" "非回环 + admin_tls=off 时 hub 拒绝启动（退出码 $NONLOOP_RC）"
fi
if grep -q 'admin_tls' "$NONLOOP_LOG" && grep -Eq '回环|拒绝启动' "$NONLOOP_LOG"; then
  pass "1.8" "拒绝启动日志点名 admin_tls 与回环地址限制"
else
  fail "1.8" "拒绝启动日志未点名 admin_tls/回环（见 $(basename "$NONLOOP_LOG")）"
fi
check_contains "1.9" "hub 日志标明管理 API 使用 HTTPS" \
  "$(cat "$HUB_LOG" 2>/dev/null || true)" "管理 API 监听（HTTPS"

# ---------------------------------------------------------------------------
# 2. scoped token：read / write / 吊销 / 轮换 / 列表
# ---------------------------------------------------------------------------

echo
echo "==> 2) scoped token：scope、actor、revoke、rotate、list"

READ_TOKEN=$(create_token "reader" read)
WRITE_TOKEN=$(create_token "writer" write)
TEMP_TOKEN=$(create_token "temp-revoke" read)
ROTOR_TOKEN_OLD=$(create_token "rotor" write)
PANEL_TOKEN=$(create_token "panel-prod" write)
pass "2.1" "token create 生成 5 个 64 位 hex token（只输出一次）"

# 2.2 read scope：GET 200，POST control 403 forbidden_scope。
api_as "$READ_TOKEN" GET "/api/v1/agents"
expect_status "2.2" "read token GET /api/v1/agents" 200
api_as "$READ_TOKEN" GET "/api/v1/audit?limit=1"
expect_status "2.3" "read token GET /api/v1/audit" 200
api_as "$READ_TOKEN" POST "/api/v1/agents/${A1_ID}/control" \
  '{"capability":"systemd","action":"list"}'
expect_status "2.4" "read token POST control 被拒" 403
expect_flat_error "2.5" "read token 写操作错误码 forbidden_scope" "forbidden_scope"

# 2.6 write scope：POST 200；GET audit 200，actor 是 token 名称。
api_as "$WRITE_TOKEN" POST "/api/v1/agents/${A1_ID}/control" \
  '{"capability":"systemd","action":"list"}'
expect_status "2.6" "write token POST systemd list" 200
check_eq "2.7" "write token 的 systemd list ok=true" "True" "$(json_get 'd.get("ok")')"

AUDIT_ACTOR_OK=0
deadline=$(( $(date +%s%3N) + 5000 ))
while :; do
  api_as "$WRITE_TOKEN" GET "/api/v1/audit?limit=200&agent_id=${A1_ID}&capability=systemd"
  if [[ "$STATUS" == "200" ]] && "$PYTHON" - "$HTTP_BODY_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
if any(item.get("actor") == "writer" and item.get("action") == "list"
       and item.get("result") == "ok" for item in entries):
    raise SystemExit(0)
raise SystemExit(1)
PY
  then
    AUDIT_ACTOR_OK=1
    break
  fi
  if (( $(date +%s%3N) >= deadline )); then
    break
  fi
  sleep 0.1
done
if (( AUDIT_ACTOR_OK == 1 )); then
  pass "2.8" "write token GET audit 200，控制审计 actor=writer"
else
  fail "2.8" "审计未出现 actor=writer 的 systemd list 记录"
fi
if [[ "$STATUS" == "200" ]]; then
  pass "2.9" "write token GET /api/v1/audit 返回 200"
else
  fail "2.9" "write token GET /api/v1/audit 返回 $STATUS"
fi
check_not_contains "2.10" "审计响应不回显 write token 明文" "$BODY" "$WRITE_TOKEN"

# 2.11 吊销：吊销前可用，吊销后 401，旧 admin_token 仍 200。
api_as "$TEMP_TOKEN" GET "/api/v1/agents"
expect_status "2.11" "待吊销 token 吊销前 GET 200" 200
if "$HUB_BIN" token revoke --config "$HUB_CFG" --name "temp-revoke" \
    > "$TMP_DIR/token-revoke.out" 2>&1; then
  pass "2.12" "token revoke 命令成功"
else
  fail "2.12" "token revoke 命令失败（见 token-revoke.out）"
fi
api_as "$TEMP_TOKEN" GET "/api/v1/agents"
expect_status "2.13" "已吊销 token GET 401" 401
expect_flat_error "2.14" "已吊销 token 错误码 unauthorized" "unauthorized"
api GET "/api/v1/agents"
expect_status "2.15" "吊销 scoped token 后旧 admin_token 仍 200" 200

# 2.16 轮换：旧 token 立即 401，新 token 200。
api_as "$ROTOR_TOKEN_OLD" GET "/api/v1/agents"
expect_status "2.16" "rotor 旧 token 轮换前 200" 200
ROTOR_TOKEN_NEW=$("$HUB_BIN" token rotate --config "$HUB_CFG" --name "rotor" \
  2>"$TMP_DIR/token-rotate.err") \
  || die "token rotate 失败（$(cat "$TMP_DIR/token-rotate.err" 2>/dev/null)）"
if [[ "$ROTOR_TOKEN_NEW" =~ ^[0-9a-f]{64}$ && "$ROTOR_TOKEN_NEW" != "$ROTOR_TOKEN_OLD" ]]; then
  pass "2.17" "token rotate 输出新的 64 位 hex（与旧值不同）"
else
  fail "2.17" "token rotate 输出非法或与旧 token 相同"
fi
api_as "$ROTOR_TOKEN_OLD" GET "/api/v1/agents"
expect_status "2.18" "rotate 后旧 token 立即 401" 401
api_as "$ROTOR_TOKEN_NEW" GET "/api/v1/agents"
expect_status "2.19" "rotate 后新 token 200" 200

# 2.20 token list：TSV 只含元信息，不含明文/哈希。
TOKEN_LIST=$("$HUB_BIN" token list --config "$HUB_CFG" 2>"$TMP_DIR/token-list.err") \
  || die "token list 失败（$(cat "$TMP_DIR/token-list.err" 2>/dev/null)）"
if TOKEN_LIST="$TOKEN_LIST" RB_SECRETS="$READ_TOKEN|$WRITE_TOKEN|$TEMP_TOKEN|$ROTOR_TOKEN_NEW|$PANEL_TOKEN" \
    "$PYTHON" - <<'PY'
import os
import re

text = os.environ["TOKEN_LIST"]
lines = text.splitlines()
if not lines or lines[0].split("\t") != [
    "name", "scope", "created_at", "last_used_at", "revoked_at"
]:
    raise SystemExit(1)
rows = {}
for line in lines[1:]:
    parts = line.split("\t")
    if len(parts) != 5:
        raise SystemExit(2)
    rows[parts[0]] = parts
for name, scope in (("reader", "read"), ("writer", "write"), ("panel-prod", "write"),
                    ("rotor", "write"), ("temp-revoke", "read")):
    if name not in rows or rows[name][1] != scope:
        raise SystemExit(3)
if rows["temp-revoke"][4] == "-":
    raise SystemExit(4)
for secret in os.environ["RB_SECRETS"].split("|"):
    if secret and secret in text:
        raise SystemExit(5)
if re.search(r"[0-9a-f]{64}", text):
    raise SystemExit(6)
PY
then
  pass "2.20" "token list 含 name/scope/时间，temp-revoke 已吊销，且无明文/哈希"
else
  fail "2.20" "token list 格式、吊销状态或泄露检查失败"
fi
check_not_contains "2.21" "token list 不含 admin_token 明文" "$TOKEN_LIST" "$ADMIN_TOKEN"

# 2.22 保留 actor 名：--name admin 必须拒绝。
set +e
ADMIN_NAME_OUT=$("$HUB_BIN" token create --config "$HUB_CFG" --name admin --scope read 2>&1)
ADMIN_NAME_RC=$?
set -e
if (( ADMIN_NAME_RC != 0 )); then
  pass "2.22" "token create --name admin 被拒绝（退出码 $ADMIN_NAME_RC）"
else
  fail "2.22" "token create --name admin 未被拒绝"
fi
if [[ "$ADMIN_NAME_OUT" == *"保留名"* || "$ADMIN_NAME_OUT" == *"actor"* ]]; then
  pass "2.23" "拒绝原因说明 admin 是保留 actor 名"
else
  fail "2.23" "拒绝原因未说明保留 actor 名"
fi

# ---------------------------------------------------------------------------
# 3. #21 systemd list-units + list-unit-files 合并
# ---------------------------------------------------------------------------

echo
echo "==> 3) #21 systemd 合并列表（demo.service 已安装未加载）"

api POST "/api/v1/agents/${A1_ID}/control" '{"capability":"systemd","action":"list"}'
expect_status "3.1" "systemd list 200" 200
check_eq "3.2" "systemd list ok=true" "True" "$(json_get 'd.get("ok")')"
check_eq "3.3" "result 类型 systemd_units" "systemd_units" \
  "$(json_get 'd.get("result",{}).get("type")')"
cp "$HTTP_BODY_FILE" "$TMP_DIR/systemd-list.json"

if "$PYTHON" - "$TMP_DIR/systemd-list.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    units = json.load(handle).get("result", {}).get("units", [])
by_name = {}
for unit in units:
    name = unit.get("unit")
    by_name.setdefault(name, []).append(unit)
demo = by_name.get("demo.service", [])
nginx = by_name.get("nginx.service", [])
if len(demo) != 1 or len(nginx) != 1:
    raise SystemExit(1)
demo = demo[0]
nginx = nginx[0]
if demo.get("load") != "not-loaded":
    raise SystemExit(2)
if demo.get("active") != "inactive":
    raise SystemExit(3)
if demo.get("sub") != "dead":
    raise SystemExit(4)
if demo.get("description") != "":
    raise SystemExit(5)
if (nginx.get("load"), nginx.get("active"), nginx.get("sub")) != (
        "loaded", "active", "running"):
    raise SystemExit(6)
if "other.service" in by_name:
    raise SystemExit(7)
PY
then
  pass "3.4" "demo.service 恰好一条，状态 not-loaded/inactive/dead，description 为空"
  pass "3.5" "nginx.service 保留 loaded/active/running 且与 list-unit-files 去重"
  pass "3.6" "非白名单 other.service 被过滤"
else
  fail "3.4" "demo.service 合并状态不符（见 systemd-list.json）"
  fail "3.5" "nginx.service 未保留 loaded 状态或出现重复"
  fail "3.6" "非白名单 other.service 未被过滤"
fi

ARGV=$(cat "$SYSTEMCTL_LOG" 2>/dev/null || true)
check_contains "3.7" "fake systemctl 收到固定 list-units 参数" "$ARGV" \
  "list-units --type=service --all --no-legend --no-pager --plain"
check_contains "3.8" "fake systemctl 收到固定 list-unit-files 参数" "$ARGV" \
  "list-unit-files --type=service --no-legend --no-pager --plain"

ARGV_BEFORE_START=$(wc -l < "$SYSTEMCTL_LOG" 2>/dev/null || echo 0)
api POST "/api/v1/agents/${A1_ID}/control" \
  '{"capability":"systemd","action":"start","target":"demo.service","confirm":true}'
expect_status "3.9" "start 已安装未加载的 demo.service 200" 200
check_eq "3.10" "start demo.service ok=true" "True" "$(json_get 'd.get("ok")')"
check_eq "3.11" "start 返回 action_output" "action_output" \
  "$(json_get 'd.get("result",{}).get("type")')"
check_eq "3.12" "start exit_code=0" "0" \
  "$(json_get 'd.get("result",{}).get("exit_code")')"
ARGV_AFTER_START=$(wc -l < "$SYSTEMCTL_LOG" 2>/dev/null || echo 0)
if (( ARGV_AFTER_START == ARGV_BEFORE_START + 1 )) \
    && tail -n 1 "$SYSTEMCTL_LOG" | grep -Fq 'start demo.service'; then
  pass "3.13" "fake argv 记录 start demo.service（仅新增 1 条）"
else
  fail "3.13" "fake argv 未记录 start demo.service（before=${ARGV_BEFORE_START} after=${ARGV_AFTER_START}）"
fi

# ---------------------------------------------------------------------------
# 4. #20 正常文件日志 tail
# ---------------------------------------------------------------------------

echo
echo "==> 4) #20 正常文件日志 tail（每次重新安全打开）"

api POST "/api/v1/agents/${A1_ID}/control" '{"capability":"logs","action":"list"}'
expect_status "4.1" "logs list 200" 200
if "$PYTHON" - "$HTTP_BODY_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    result = json.load(handle).get("result", {})
if result.get("type") != "log_sources":
    raise SystemExit(1)
sources = result.get("sources") or []
if not any(item.get("id") == "app" for item in sources):
    raise SystemExit(2)
PY
then
  pass "4.2" "logs list 含文件来源 app"
else
  fail "4.2" "logs list 类型或来源不符"
fi

api POST "/api/v1/agents/${A1_ID}/control" \
  '{"capability":"logs","action":"tail","source":"app","lines":2}'
expect_status "4.3" "file tail 200" 200
check_eq "4.4" "tail ok=true" "True" "$(json_get 'd.get("ok")')"
check_eq "4.5" "tail result.type=log_lines" "log_lines" \
  "$(json_get 'd.get("result",{}).get("type")')"
if "$PYTHON" - "$HTTP_BODY_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    lines = json.load(handle).get("result", {}).get("lines") or []
if len(lines) != 2:
    raise SystemExit(1)
if "v033-line-4" not in lines[0] or "v033-line-5" not in lines[1]:
    raise SystemExit(2)
if any("v033-line-3" in line for line in lines):
    raise SystemExit(3)
PY
then
  pass "4.6" "tail 返回最新两行（line-4/line-5），不含更早的 line-3"
else
  fail "4.6" "tail 行数、内容或顺序不符"
fi

# 运行期追加：每次 tail 重新打开文件，新内容必须可见。
printf 'v033-line-6\n' >> "$APP_LOG"
api POST "/api/v1/agents/${A1_ID}/control" \
  '{"capability":"logs","action":"tail","source":"app","lines":1}'
expect_status "4.7" "追加后 file tail 200" 200
if "$PYTHON" - "$HTTP_BODY_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    lines = json.load(handle).get("result", {}).get("lines") or []
raise SystemExit(0 if lines and "v033-line-6" in lines[-1] else 1)
PY
then
  pass "4.8" "tail 能看到运行期追加的 v033-line-6"
else
  fail "4.8" "tail 未看到运行期追加的新内容"
fi

# ---------------------------------------------------------------------------
# 5. Panel HTTPS + 私有 CA
# ---------------------------------------------------------------------------

echo
echo "==> 5) Panel HTTPS + hub_ca（Panel → Hub 只信任私有 CA）"

PANEL_PASSWORD="V033-E2E-$(date +%s)-pw"
if ! "$PANEL_BIN" init \
    --config "$PANEL_CFG" \
    --listen "127.0.0.1:${PANEL_PORT}" \
    --hub "$ADMIN_URL" \
    --hub-token "$PANEL_TOKEN" \
    --password "$PANEL_PASSWORD" \
    --force > "$PANEL_INIT_LOG" 2>&1; then
  dump_log "$PANEL_INIT_LOG" 80
  die "panel init 失败"
fi
if [[ "$(cfg_str "$PANEL_CFG" hub_url)" == "$ADMIN_URL" ]] \
    && [[ "$(cfg_str "$PANEL_CFG" token)" == "$PANEL_TOKEN" ]]; then
  pass "5.1" "panel init 写入 https hub_url 与 write scope token"
else
  fail "5.1" "panel 配置的 hub_url/token 不符"
fi

# panel init 会写 hub_ca = ""；用 hub 的 CA 证书替换该值。
"$PYTHON" - "$PANEL_CFG" "$CA" <<'PY'
import re
import sys

path, ca = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
line = f'hub_ca = "{ca}"'
text, count = re.subn(r'(?m)^hub_ca\s*=.*$', lambda _m: line, text)
if count == 0:
    text, count = re.subn(r'(?m)^(hub_url\s*=.*)$',
                          lambda m: m.group(1) + "\n" + line, text)
if count != 1:
    raise SystemExit(f"无法写入 hub_ca（匹配 {count} 次）")
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
chmod 600 "$PANEL_CFG"
check_eq "5.2" "panel hub_ca 指向 hub 的 ca.crt" "$CA" "$(cfg_str "$PANEL_CFG" hub_ca)"

RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$PANEL_CFG" > "$PANEL_LOG" 2>&1 &
PANEL_PID=$!
PIDS+=("$PANEL_PID")
wait_health "$PANEL_URL/healthz" 20 || die "panel 未在 20s 内就绪"
pass "5.3" "panel /healthz 就绪"

# 用 panel_probe.py 登录（密码只经环境变量传入该子进程）。
rm -f "$PANEL_COOKIE"
LOGIN_OUT=$(RB_E2E_PANEL_PASSWORD="$PANEL_PASSWORD" "$PYTHON" "$PANEL_PROBE" login \
  --url "$PANEL_URL/api/login" --password-env RB_E2E_PANEL_PASSWORD \
  --cookie-out "$PANEL_COOKIE" 2>"$TMP_DIR/probe.err") \
  || die "panel_probe.py 登录失败（见 probe.err）"
LOGIN_STATUS=$(printf '%s' "$LOGIN_OUT" \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')
LOGIN_SAVED=$(printf '%s' "$LOGIN_OUT" \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("cookie_saved",False))')
check_eq "5.4" "panel_probe.py 登录 204" "204" "$LOGIN_STATUS"
if [[ "$LOGIN_SAVED" == "True" && -s "$PANEL_COOKIE" ]] \
    && grep -q '^rb_session=' "$PANEL_COOKIE"; then
  pass "5.5" "登录写入 rb_session Cookie"
else
  fail "5.5" "登录未写入 rb_session Cookie"
fi

# /api/overview 走 Panel → Hub HTTPS；agent 必须出现在 overview 里。
OVERVIEW_OUT=$("$PYTHON" "$PANEL_PROBE" overview \
  --url "$PANEL_URL/api/overview" --cookie-file "$PANEL_COOKIE" --agent "$A1_ID" \
  2>"$TMP_DIR/probe.err") || die "panel_probe.py overview 失败（见 probe.err）"
OVERVIEW_STATUS=$(printf '%s' "$OVERVIEW_OUT" \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')
OVERVIEW_JSON=$(printf '%s' "$OVERVIEW_OUT" \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("json_ok",False))')
OVERVIEW_PRESENT=$(printf '%s' "$OVERVIEW_OUT" \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("agent_present",False))')
OVERVIEW_AGENT_STATUS=$(printf '%s' "$OVERVIEW_OUT" \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("agent_status",""))')
check_eq "5.6" "Panel /api/overview 经 HTTPS 返回 200" "200" "$OVERVIEW_STATUS"
check_eq "5.7" "Panel overview 是 JSON" "True" "$OVERVIEW_JSON"
check_eq "5.8" "Panel overview 含在线 agent" "online" "$OVERVIEW_AGENT_STATUS"
if [[ "$OVERVIEW_PRESENT" == "True" ]]; then
  pass "5.9" "Panel overview.agents 含测试 agent"
else
  fail "5.9" "Panel overview.agents 不含测试 agent"
fi

# /api/audit 同样经 Panel → Hub HTTPS 代理。
panel_api GET "/api/audit?limit=50"
expect_status "5.10" "Panel /api/audit 200" 200
cp "$HTTP_BODY_FILE" "$PANEL_AUDIT_JSON"
if "$PYTHON" - "$PANEL_AUDIT_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
if not entries:
    raise SystemExit(1)
if not any(item.get("actor") == "writer" for item in entries):
    raise SystemExit(2)
PY
then
  pass "5.11" "Panel 审计非空且能看到 write token(actor=writer) 的控制记录"
else
  fail "5.11" "Panel 审计为空或缺少 actor=writer 记录"
fi

# 证明私有 CA 真的生效：Panel 启动日志明确“仅信任 hub_ca”。
PANEL_LOG_TEXT=$(cat "$PANEL_LOG" 2>/dev/null || true)
check_contains "5.12" "Panel 日志说明只信任 hub_ca、系统根不参与" \
  "$PANEL_LOG_TEXT" "仅信任 hub_ca"
check_contains "5.13" "Panel 日志带 hub_ca 路径" "$PANEL_LOG_TEXT" "$CA"

# 非 PEM 的 hub_ca 必须让 Panel 启动失败（不会静默忽略）。
printf 'this is not a pem certificate\n' > "$TMP_DIR/not-a-cert.pem"
"$PYTHON" - "$PANEL_CFG" "$PANEL_BADCA_CFG" "$TMP_DIR/not-a-cert.pem" "$BADCA_PORT" <<'PY'
import re
import sys

source, target, ca, port = sys.argv[1:5]
text = open(source, encoding="utf-8").read()
text, n1 = re.subn(r'(?m)^hub_ca\s*=.*$',
                   lambda _m: f'hub_ca = "{ca}"', text)
text, n2 = re.subn(r'(?m)^listen\s*=.*$',
                   lambda _m: f'listen = "127.0.0.1:{port}"', text)
if n1 != 1 or n2 != 1:
    raise SystemExit(f"改写坏 CA 配置失败: hub_ca={n1} listen={n2}")
with open(target, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
chmod 600 "$PANEL_BADCA_CFG"
set +e
timeout 10 "$PANEL_BIN" run --config "$PANEL_BADCA_CFG" > "$PANEL_BADCA_LOG" 2>&1
BADCA_RC=$?
set -e
if (( BADCA_RC == 124 )); then
  fail "5.14" "错误 hub_ca 时 panel 仍在运行（10s 内未拒绝启动）"
elif (( BADCA_RC == 0 )); then
  fail "5.14" "错误 hub_ca 时 panel 正常退出（未拒绝启动）"
else
  pass "5.14" "非 PEM 的 hub_ca 使 panel 拒绝启动（退出码 $BADCA_RC）"
fi
if grep -q 'hub_ca' "$PANEL_BADCA_LOG"; then
  pass "5.15" "错误信息点名 hub_ca"
else
  fail "5.15" "错误信息未点名 hub_ca"
fi

# 功能性证明“只信任 hub_ca”：换成另一套合法 CA 后，Panel 能启动、能登录，
# 但访问 hub 必须 502（系统根证书不参与，私有 CA 不匹配就失败）。
if ! "$HUB_BIN" init \
    --config "$OTHER_HUB_CFG" \
    --data-dir "$OTHER_HUB_DATA" \
    --agent-listen "127.0.0.1:${OTHER_AGENT_PORT}" \
    --admin-listen "127.0.0.1:${OTHER_ADMIN_PORT}" \
    --force > "$OTHER_HUB_LOG" 2>&1; then
  die "生成错误 CA 的临时 hub 失败（见 other-hub-init.log）"
fi
OTHER_CA="$OTHER_HUB_DATA/certs/ca.crt"
[[ -f "$OTHER_CA" ]] || die "缺少另一套 CA: $OTHER_CA"
"$PYTHON" - "$PANEL_CFG" "$PANEL_WRONGCA_CFG" "$OTHER_CA" "$WRONGCA_PORT" <<'PY'
import re
import sys

source, target, ca, port = sys.argv[1:5]
text = open(source, encoding="utf-8").read()
text, n1 = re.subn(r'(?m)^hub_ca\s*=.*$',
                   lambda _m: f'hub_ca = "{ca}"', text)
text, n2 = re.subn(r'(?m)^listen\s*=.*$',
                   lambda _m: f'listen = "127.0.0.1:{port}"', text)
if n1 != 1 or n2 != 1:
    raise SystemExit(f"改写错 CA 配置失败: hub_ca={n1} listen={n2}")
with open(target, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
chmod 600 "$PANEL_WRONGCA_CFG"
WRONGCA_URL="http://127.0.0.1:${WRONGCA_PORT}"
RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$PANEL_WRONGCA_CFG" \
  > "$PANEL_WRONGCA_LOG" 2>&1 &
WRONGCA_PID=$!
PIDS+=("$WRONGCA_PID")
if wait_health "$WRONGCA_URL/healthz" 20; then
  pass "5.16" "hub_ca 指向另一套合法 CA 时 Panel 仍能启动"
else
  fail "5.16" "错 CA 的 Panel 未在 20s 内就绪"
fi
WRONGCA_LOGIN=$(RB_E2E_PANEL_PASSWORD="$PANEL_PASSWORD" "$PYTHON" "$PANEL_PROBE" login \
  --url "$WRONGCA_URL/api/login" --password-env RB_E2E_PANEL_PASSWORD \
  --cookie-out "$PANEL_WRONGCA_COOKIE" 2>"$TMP_DIR/probe.err") \
  || die "错 CA 的 Panel 登录失败（见 probe.err）"
WRONGCA_LOGIN_STATUS=$(printf '%s' "$WRONGCA_LOGIN" \
  | "$PYTHON" -c 'import json,sys; print(json.load(sys.stdin).get("status",""))')
check_eq "5.17" "错 CA 的 Panel 仍可登录" "204" "$WRONGCA_LOGIN_STATUS"
WRONGCA_COOKIE=$(tr -d '\n' < "$PANEL_WRONGCA_COOKIE")
WRONGCA_CODE=$(curl -sS --noproxy '*' --max-time 15 -o "$HTTP_BODY_FILE" \
  -w '%{http_code}' -H "Cookie: ${WRONGCA_COOKIE}" -H 'Accept: application/json' \
  "$WRONGCA_URL/api/overview" 2>"$CURL_ERR") || WRONGCA_CODE="000"
check_eq "5.18" "错 CA 的 Panel 访问 hub 返回 502" "502" "$WRONGCA_CODE"
BODY=$(cat "$HTTP_BODY_FILE" 2>/dev/null || true)
check_eq "5.19" "错 CA 的 502 错误码为 hub_unreachable" "hub_unreachable" \
  "$(json_get 'd.get("error")')"
if grep -q '已配置 hub_ca' "$PANEL_WRONGCA_LOG"; then
  pass "5.20" "错 CA 日志说明只信任 hub_ca、系统根不参与"
else
  fail "5.20" "错 CA 日志未说明 hub_ca 信任范围"
fi
kill -9 "$WRONGCA_PID" 2>/dev/null || true
wait "$WRONGCA_PID" 2>/dev/null || true
WRONGCA_PID=""

# ---------------------------------------------------------------------------
# 6. #17 agent 吊销后的控制窗口
# ---------------------------------------------------------------------------

echo
echo "==> 6) #17 agent 吊销后拒绝控制命令"

ARGV_BEFORE_REVOKE=$(wc -l < "$SYSTEMCTL_LOG" 2>/dev/null || echo 0)

REVOKE_START=$(date +%s%3N)

# revoke 前先确认 A2 真的在线且进程存活，避免“连接早已断开”被误判为吊销生效。
if kill -0 "$AGENT2_PID" 2>/dev/null \
    && [[ "$(read_agent_status "$A2_ID")" == "online" ]]; then
  pass "6.1" "revoke 前 agent A2 进程存活且状态 online"
else
  fail "6.1" "revoke 前 agent A2 不在线或进程已退出（最后: $(read_agent_status "$A2_ID")）"
fi

# 记录 revoke 前的审计边界（agent A2 没有历史控制记录，仍按 max id 计算）。
api GET "/api/v1/audit?limit=200&agent_id=${A2_ID}"
expect_status "6.2" "revoke 前读取 agent A2 审计" 200
AUDIT_BOUNDARY=$("$PYTHON" - "$HTTP_BODY_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
print(max((int(item.get("id", 0)) for item in entries), default=0))
PY
)

if "$HUB_BIN" agent revoke --config "$HUB_CFG" --id "$A2_ID" \
    > "$REVOKE_LOG" 2>&1; then
  pass "6.3" "hub agent revoke 命令成功"
else
  fail "6.3" "hub agent revoke 命令失败（见 revoke.log）"
fi
check_contains "6.4" "revoke 输出确认吊销目标" "$(cat "$REVOKE_LOG")" "已吊销 agent: ${A2_ID}"

# 立即 POST control：必须 403 agent_revoked，且命令不能投递到 agent。
api POST "/api/v1/agents/${A2_ID}/control" '{"capability":"systemd","action":"list"}'
expect_status "6.5" "revoke 后立即 POST control 403" 403
expect_control_error_code "6.6" "revoke 后错误码 agent_revoked" "agent_revoked"
check_eq "6.7" "revoke 后错误文案固定" "agent 已被吊销" \
  "$(json_get 'd.get("error",{}).get("message","")')"

# 等待 watcher 关闭会话（从 revoke 命令开始计时，≤3s）：
# 进程退出或日志出现吊销/不可重试/EOF 均可。
CLOSED=0
while :; do
  if ! kill -0 "$AGENT2_PID" 2>/dev/null; then
    CLOSED=1
    break
  fi
  if grep -Eqi 'revoked|吊销|不可重试|EOF' "$A2_LOG" 2>/dev/null; then
    CLOSED=1
    break
  fi
  if (( $(date +%s%3N) - REVOKE_START >= 3000 )); then
    break
  fi
  sleep 0.05
done
CLOSE_MS=$(( $(date +%s%3N) - REVOKE_START ))
if (( CLOSED == 1 && CLOSE_MS <= 3000 )); then
  pass "6.8" "revoke 后 ${CLOSE_MS}ms 内连接关闭（进程退出或日志出现吊销/EOF）"
else
  fail "6.8" "revoke 后连接未在 3s 内关闭（closed=${CLOSED} elapsed=${CLOSE_MS}ms）"
fi
if grep -Eqi 'revoked|吊销|不可重试' "$A2_LOG" 2>/dev/null; then
  pass "6.9" "agent 日志记录被吊销后停止重连"
else
  fail "6.9" "agent 日志未记录 revoked/吊销原因"
fi

# fake systemctl 在本 revoke 之后不能再增加任何 argv。
ARGV_AFTER_REVOKE=$(wc -l < "$SYSTEMCTL_LOG" 2>/dev/null || echo 0)
if (( ARGV_AFTER_REVOKE == ARGV_BEFORE_REVOKE )); then
  pass "6.10" "revoke 后 fake systemctl 未再执行（argv ${ARGV_BEFORE_REVOKE} 条不变）"
else
  fail "6.10" "revoke 后 fake systemctl 仍被执行（${ARGV_BEFORE_REVOKE} → ${ARGV_AFTER_REVOKE}）"
fi

if wait_agent_status "$A2_ID" revoked 3; then
  pass "6.11" "hub 状态变为 revoked"
else
  fail "6.11" "hub 状态未在 3s 内变为 revoked（最后: $LAST_STATUS）"
fi

# 审计：最新一条必须是 denied/agent_revoked，revoke 之后不得出现 ok。
AUDIT_READY=0
deadline=$(( $(date +%s%3N) + 5000 ))
while :; do
  api GET "/api/v1/audit?limit=200&agent_id=${A2_ID}"
  if [[ "$STATUS" == "200" ]] \
      && "$PYTHON" - "$HTTP_BODY_FILE" "$AUDIT_BOUNDARY" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
boundary = int(sys.argv[2])
after = [item for item in entries if int(item.get("id", 0)) > boundary]
if not after:
    raise SystemExit(1)
newest = max(after, key=lambda item: int(item.get("id", 0)))
if newest.get("result") != "denied" or newest.get("error_code") != "agent_revoked":
    raise SystemExit(2)
raise SystemExit(0)
PY
  then
    AUDIT_READY=1
    cp "$HTTP_BODY_FILE" "$AUDIT_JSON"
    break
  fi
  if (( $(date +%s%3N) >= deadline )); then
    cp "$HTTP_BODY_FILE" "$AUDIT_JSON" 2>/dev/null || true
    break
  fi
  sleep 0.1
done
if (( AUDIT_READY == 1 )); then
  pass "6.12" "审计最新一条为 result=denied / error_code=agent_revoked"
else
  fail "6.12" "审计未出现吊销后的 denied/agent_revoked 记录"
fi

if "$PYTHON" - "$AUDIT_JSON" "$AUDIT_BOUNDARY" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    entries = json.load(handle).get("entries", [])
boundary = int(sys.argv[2])
after = [item for item in entries if int(item.get("id", 0)) > boundary]
if any(item.get("result") == "ok" for item in after):
    raise SystemExit(1)
if not any(item.get("error_code") == "agent_revoked"
           and item.get("result") == "denied" for item in after):
    raise SystemExit(2)
if entries and int(entries[0].get("id", 0)) <= boundary:
    raise SystemExit(3)
PY
then
  pass "6.13" "revoke 后没有 ok 审计；最新记录就是 agent_revoked denied"
else
  fail "6.13" "revoke 后出现 ok 审计或最新记录不是 agent_revoked denied"
fi

# ---------------------------------------------------------------------------
# 7. 凭据不落日志 / 无 panic
# ---------------------------------------------------------------------------

echo
echo "==> 7) 日志脱敏与稳定性"

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

check_log_absent "7.1" "$HUB_LOG" "hub 日志不含 admin_token" "$ADMIN_TOKEN"
check_log_absent "7.2" "$HUB_LOG" "hub 日志不含 write token" "$WRITE_TOKEN"
check_log_absent "7.3" "$HUB_LOG" "hub 日志不含 panel token" "$PANEL_TOKEN"
check_log_absent "7.4" "$HUB_LOG" "hub 日志不含 enrollment token" "$ENROLL1"
check_log_absent "7.5" "$HUB_LOG" "hub 日志不含 agent secret" "$AGENT1_SECRET"
check_log_absent "7.6" "$PANEL_LOG" "panel 日志不含 hub write token" "$PANEL_TOKEN"
check_log_absent "7.7" "$PANEL_LOG" "panel 日志不含 admin_token" "$ADMIN_TOKEN"

# 其余 scoped token（含已吊销/已轮换的旧值）同样不能出现在日志里。
LEAK_HITS=""
for secret in "$READ_TOKEN" "$TEMP_TOKEN" "$ROTOR_TOKEN_OLD" "$ROTOR_TOKEN_NEW" "$PANEL_TOKEN"; do
  if grep -Fq -- "$secret" "$HUB_LOG" 2>/dev/null; then
    LEAK_HITS=" hub.log"
    break
  fi
done
if [[ -z "$LEAK_HITS" ]]; then
  pass "7.8" "hub 日志不含其它 scoped token（含吊销/轮换旧值）"
else
  fail "7.8" "hub 日志出现 scoped token 明文（${LEAK_HITS# }）"
fi

if [[ -s "$HUB_LOG" ]] && ! grep -q 'panicked at' "$HUB_LOG"; then
  pass "7.9" "hub 日志无 panic"
else
  fail "7.9" "hub 日志为空或出现 panic"
fi
if [[ -s "$A1_LOG" ]] && ! grep -q 'panicked at' "$A1_LOG"; then
  pass "7.10" "agent A1 日志无 panic"
else
  fail "7.10" "agent A1 日志为空或出现 panic"
fi
if [[ -s "$PANEL_LOG" ]] && ! grep -q 'panicked at' "$PANEL_LOG"; then
  pass "7.11" "panel 日志无 panic"
else
  fail "7.11" "panel 日志为空或出现 panic"
fi

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

echo
if (( FAILS > 0 )); then
  echo "v033 e2e 结果: ${PASSES} 项通过，${FAILS} 项失败" >&2
  exit 1
fi
echo "v033 e2e 结果: 全部 ${PASSES} 项通过"
