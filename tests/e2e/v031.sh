#!/usr/bin/env bash
#
# RustBoard v0.3.1 端到端回归：#13 过期服务端证书启动自愈 + KI-17 慢连接。
# 方案：docs/plans/2026-10-23-v0.3.1-hardening.md §3.1 / §3.4 / §5.4 / §5.8。
#
# 覆盖：
#   1. 基线：hub 正常启动，agent 纳管、online、样本持续增长；
#   2. 停 hub（agent 保持运行），用**当前 CA 私钥**签一张已过期服务端证书：
#      CN=rustboard-hub、有效期 2020-01-01T00:00:00Z～2020-02-01T00:00:00Z、
#      SAN 覆盖配置里的 server_names（含 127.0.0.1）、与 server.key 配套，
#      写回 <data_dir>/certs/server.crt 与 server.key（key 0600），CA 不变；
#   3. 重启 hub（`rustboard-hub run`）必须成功，不因过期证书退出，/healthz 200；
#   4. 磁盘 server.crt 被替换为**未过期、仍由当前 CA 签发、与 server.key 配套**
#      的新证书；旧 crt/key 有同后缀成对备份；新 key 0600、证书 0644；
#   5. /api/v1/system：cert.disk.not_after 在未来、days_left > 0，指纹较替换前
#      变化；hub 日志有“仅因过期 / 自动重签”文本，且不含证书/私钥正文或 token；
#   6. 原 agent 进程不重启、不重新纳管，用原 ca.crt 自动重连：online 且
#      样本数继续增长（真实 HTTP 查询，不只看日志）；
#   7. KI-17：hub 管理口与 panel 监听口各并发 30 条只发半截 header 的 TCP，
#      慢连接存续时 /healthz 仍 200；30 条在 10s 内全部收到 EOF/关闭，且关闭
#      窗口符合 5s header 读超时；全部关闭后 /healthz 仍 200。
#
# 依赖：bash 4+、python3（cryptography + 标准库）、cargo/rustc、GNU coreutils。
# panel 不依赖 web/dist：未构建前端时页面 503，/healthz 仍 200。
# 用法：bash tests/e2e/v031.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/v031.sh   # 保留临时目录与日志
#
# 扩展点：后续场景可仿照阶段 7 追加；复用 `pick_port` / `start_hub` /
# `stop_pid` / `PIDS` / `pass`/`fail` 计数，并为独立实例设置自己的
# config/data_dir/端口。进程一律登记进 `PIDS`，由 `cleanup` 统一回收。
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}
CERT_HELPER="$SCRIPT_DIR/v031_cert.py"

PASSES=0
FAILS=0
PIDS=()
LAST_STATUS=""
HUB_PID=""
A_PID=""
PANEL_PID=""
A_ID=""
ADMIN_TOKEN=""
ENROLL_TOKEN=""
ADMIN_URL=""
PANEL_URL=""
HUB_BIN=""
AGENT_BIN=""
PANEL_BIN=""
SCRIPT_STARTED_MS=$(date +%s%3N)

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

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-v031.XXXXXX")
HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
AGENT_CFG="$TMP_DIR/agent.toml"
AGENT_DATA="$TMP_DIR/agent"
AGENT_LOG="$TMP_DIR/agent.log"
PANEL_CFG="$TMP_DIR/panel.toml"
PANEL_LOG="$TMP_DIR/panel.log"
PANEL_INIT_LOG="$TMP_DIR/panel-init.log"
SLOW_HUB_JSON="$TMP_DIR/slow-hub.json"
SLOW_HUB_ERR="$TMP_DIR/slow-hub.err"
SLOW_PANEL_JSON="$TMP_DIR/slow-panel.json"
SLOW_PANEL_ERR="$TMP_DIR/slow-panel.err"
BUILD_LOG="$TMP_DIR/build.log"
INIT_LOG="$TMP_DIR/init.log"
TOKEN_ERR="$TMP_DIR/admin-token.err"
SNAPSHOT_DIR="$TMP_DIR/snapshots"
EXPIRED_META="$TMP_DIR/expired.json"
EXPIRED_CRT_TMP="$TMP_DIR/expired.crt"
EXPIRED_KEY_TMP="$TMP_DIR/expired.key"
SYSTEM_JSON="$TMP_DIR/system.json"
SYSTEM_ERR="$TMP_DIR/system.err"
mkdir -p "$SNAPSHOT_DIR"

# 失败现场只打印日志尾部，并先脱敏 token / 面板密码行（日志文件本身也可能含）。
redact_log() {
  local args=(
    -E
    -e 's/(管理 API token:).*/\1 <redacted>/'
    -e 's/(面板密码[^:：]*[:：]).*/\1 <redacted>/'
    -e 's/(Bearer )[A-Za-z0-9._~+\/=-]+/\1<redacted>/g'
  )
  # 防御性：即使实现意外把 token 写进日志，失败现场也不回显。
  if [[ -n "${ADMIN_TOKEN:-}" ]]; then
    args+=(-e "s/${ADMIN_TOKEN}/<redacted>/g")
  fi
  if [[ -n "${ENROLL_TOKEN:-}" ]]; then
    args+=(-e "s/${ENROLL_TOKEN}/<redacted>/g")
  fi
  sed "${args[@]}"
}

dump_log() {
  local log=$1 lines=${2:-120}
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

  # KEEP_E2E_TMP 也要保留脱敏后的日志：先把已知会含 token/密码的行改写掉。
  if [[ -f "$INIT_LOG" ]]; then
    sed -i -E 's/(管理 API token:).*/\1 <redacted>/' "$INIT_LOG" 2>/dev/null || true
  fi
  if [[ -f "$PANEL_INIT_LOG" ]]; then
    sed -i -E 's/(面板密码[^:：]*[:：]).*/\1 <redacted>/' "$PANEL_INIT_LOG" \
      2>/dev/null || true
  fi

  if (( code != 0 || FAILS > 0 )); then
    echo "===== v031 e2e 失败现场 =====" >&2
    for log in "$HUB_LOG" "$AGENT_LOG" "$PANEL_LOG" "$INIT_LOG" "$BUILD_LOG" \
               "$TOKEN_ERR" "$SYSTEM_ERR" "$SLOW_HUB_ERR" "$SLOW_PANEL_ERR"; do
      dump_log "$log" 120
    done
    if [[ -d "$HUB_DATA/certs" ]]; then
      echo "---- 证书目录（仅文件名/权限/大小，不含内容）----" >&2
      find "$HUB_DATA/certs" -maxdepth 1 -type f \
        -printf '%f mode=%m size=%s\n' 2>/dev/null | sort >&2 || true
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

for tool in "$PYTHON" "$CARGO" timeout stat mktemp date tail awk sed grep find \
            sleep install wc; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "找不到命令: $tool（python3 需 3.8+；cargo 请放进 PATH 或设置 CARGO=...）"
done
[[ -f "$CERT_HELPER" ]] || die "缺少证书辅助脚本: $CERT_HELPER"
"$PYTHON" -c 'import cryptography' >/dev/null 2>&1 \
  || die "python 缺少 cryptography 模块（脚本不会联网安装依赖）"

# ---------------------------------------------------------------------------
# 通用小工具
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

# 从 hub/agent 的 TOML 配置里读取一个字符串标量。只匹配形如 key = "value" 的行。
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

file_sha256() {
  "$PYTHON" - "$1" <<'PY'
import hashlib
import sys

with open(sys.argv[1], "rb") as handle:
    print(hashlib.sha256(handle.read()).hexdigest())
PY
}

json_get() {
  "$PYTHON" - "$1" "$2" <<'PY'
import json
import sys

path, dotted = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as handle:
    value = json.load(handle)
for part in dotted.split("."):
    if not isinstance(value, dict) or part not in value:
        print("__MISSING__")
        raise SystemExit(0)
    value = value[part]
print(value)
PY
}

# 通过管理 API 读取 JSON；token 只放进 Authorization 头，不打印。
# token 只对这一条 Python 子进程可见，不 export 给 hub/agent/panel 进程。
http_json() {
  RB_E2E_ADMIN_TOKEN="$ADMIN_TOKEN" "$PYTHON" - "$1" <<'PY'
import json
import os
import sys
import urllib.request

url = sys.argv[1]
headers = {}
token = os.environ.get("RB_E2E_ADMIN_TOKEN", "")
if token:
    headers["Authorization"] = f"Bearer {token}"
try:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        body = response.read()
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}")
        print(json.dumps(json.loads(body), ensure_ascii=False))
except Exception as exc:
    print(f"请求 {url} 失败: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
}

health_ok() {
  health_ok_url "$ADMIN_URL/healthz"
}

health_ok_url() {
  "$PYTHON" - "$1" <<'PY' >/dev/null 2>&1
import sys
import urllib.request

try:
    with urllib.request.urlopen(sys.argv[1], timeout=0.5) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
}

# 轮询一个 URL 直到 200；$3 传入进程 pid 时，进程退出立即返回失败。
wait_health_url() {
  local url=$1 timeout=$2 pid=${3:-}
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  while :; do
    if health_ok_url "$url"; then
      return 0
    fi
    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

agent_status() {
  RB_E2E_ADMIN_TOKEN="$ADMIN_TOKEN" "$PYTHON" - "$ADMIN_URL/api/v1/agents" "${A_ID:-}" <<'PY'
import json
import os
import sys
import urllib.request

url, target = sys.argv[1], sys.argv[2]
headers = {}
token = os.environ.get("RB_E2E_ADMIN_TOKEN", "")
if token:
    headers["Authorization"] = f"Bearer {token}"
try:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        agents = json.loads(response.read())
except Exception as exc:
    print(f"error: {exc}", file=sys.stderr)
    raise SystemExit(1)
for agent in agents:
    if agent.get("agent_id") == target:
        print(agent.get("status", ""))
        raise SystemExit(0)
print("absent")
PY
}

series_count() {
  RB_E2E_ADMIN_TOKEN="$ADMIN_TOKEN" "$PYTHON" - "$ADMIN_URL" "$A_ID" <<'PY'
import json
import os
import sys
import urllib.parse
import urllib.request

admin, agent = sys.argv[1], sys.argv[2]
headers = {}
token = os.environ.get("RB_E2E_ADMIN_TOKEN", "")
if token:
    headers["Authorization"] = f"Bearer {token}"
query = urllib.parse.urlencode({
    "agent": agent,
    "from": 0,
    "to": 4_102_444_800_000,
    "limit": 50_000,
})
url = admin.rstrip("/") + "/api/v1/series?" + query
try:
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=3) as response:
        rows = json.loads(response.read())
    print(len(rows))
except Exception as exc:
    print(f"error: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
}

agents_len() {
  local file="$SNAPSHOT_DIR/agents.json"
  http_json "$ADMIN_URL/api/v1/agents" > "$file" || return 1
  "$PYTHON" - "$file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    print(len(json.load(handle)))
PY
}

wait_health() {
  local timeout=$1
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  while :; do
    if health_ok; then
      return 0
    fi
    if [[ -n "$HUB_PID" ]] && ! kill -0 "$HUB_PID" 2>/dev/null; then
      return 1
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

wait_agent_status() {
  local expected=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local status
  LAST_STATUS=""
  while :; do
    status=$(agent_status 2>/dev/null || echo "error")
    LAST_STATUS=$status
    if [[ "$status" == "$expected" ]]; then
      return 0
    fi
    if [[ -n "$A_PID" ]] && ! kill -0 "$A_PID" 2>/dev/null; then
      return 1
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.25
  done
}

wait_series_min() {
  local minimum=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local count
  LAST_STATUS=""
  while :; do
    count=$(series_count 2>/dev/null || echo "error")
    LAST_STATUS=$count
    if [[ "$count" =~ ^[0-9]+$ ]] && (( count >= minimum )); then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.25
  done
}

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望: $expected，实际: $actual）"
  fi
}

check_mode() {
  local id=$1 path=$2 expected=$3
  local actual
  actual=$(stat -c '%a' "$path" 2>/dev/null || echo "missing")
  check_eq "$id" "$path 权限" "$expected" "$actual"
}

check_log_has() {
  local id=$1 log=$2 desc=$3 pattern=$4
  if [[ -s "$log" ]] && grep -Eiq -- "$pattern" "$log"; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（日志未匹配 /$pattern/：$log）"
  fi
}

check_log_absent() {
  local id=$1 log=$2 desc=$3 pattern=$4
  if [[ ! -s "$log" ]]; then
    fail "$id" "$desc（日志为空，无法断言不包含）"
  elif grep -Eiq -- "$pattern" "$log"; then
    fail "$id" "$desc（日志匹配到 /$pattern/：$log）"
  else
    pass "$id" "$desc"
  fi
}

check_no_panic() {
  local id=$1 log=$2 desc=$3
  if [[ ! -s "$log" ]]; then
    fail "$id" "$desc（日志为空）"
  elif grep -q 'panicked at' "$log"; then
    fail "$id" "$desc（日志出现 panic）"
  else
    pass "$id" "$desc"
  fi
}

# 检查日志里没有 admin_token / enrollment token。token 仅经环境变量传入 Python，
# 不出现在命令行参数、也不打印。
check_log_no_tokens() {
  local id=$1 log=$2 desc=$3
  if RB_LOG="$log" RB_ADMIN_TOKEN="$ADMIN_TOKEN" \
      RB_ENROLL_TOKEN="$ENROLL_TOKEN" "$PYTHON" - <<'PY'
import os
import sys

path = os.environ["RB_LOG"]
tokens = [
    os.environ.get("RB_ADMIN_TOKEN", ""),
    os.environ.get("RB_ENROLL_TOKEN", ""),
]
with open(path, encoding="utf-8", errors="replace") as handle:
    text = handle.read()
for token in tokens:
    if token and token in text:
        raise SystemExit(1)
raise SystemExit(0)
PY
  then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（日志出现 token 明文）"
  fi
}

# 证书元数据（JSON）。参数顺序：cert [key] [ca]。
cert_inspect() {
  local cert=$1 key=${2:-} ca=${3:-}
  local args=(--cert "$cert")
  [[ -n "$key" ]] && args+=(--key "$key")
  [[ -n "$ca" ]] && args+=(--ca "$ca")
  "$PYTHON" "$CERT_HELPER" inspect "${args[@]}"
}

check_meta() {
  local id=$1 desc=$2 meta=$3 field=$4 expected=$5
  local actual
  actual=$(json_get "$meta" "$field" 2>/dev/null || echo "__ERR__")
  check_eq "$id" "$desc" "$expected" "$actual"
}

# 对一个监听口执行 KI-17 五条断言。$4/$5 是编号前缀与起始序号。
slow_assert_target() {
  local label=$1 json=$2 err=$3 prefix=$4 start=$5 expected=$6
  local id1="$prefix.$start" id2="$prefix.$((start + 1))" id3="$prefix.$((start + 2))"
  local id4="$prefix.$((start + 3))" id5="$prefix.$((start + 4))"
  if [[ ! -s "$json" ]] || ! "$PYTHON" -m json.tool "$json" >/dev/null 2>&1; then
    fail "$id1" "$label 慢连接探针未产生有效 JSON（见 $(basename "$err")）"
    fail "$id2" "$label 无法断言慢连接存续时的 /healthz"
    fail "$id3" "$label 无法断言 30 条连接全部关闭"
    fail "$id4" "$label 无法证明 5s header 读超时"
    fail "$id5" "$label 无法断言全部关闭后的 /healthz"
    if [[ -s "$err" ]]; then
      echo "---- $(basename "$err") (tail -n 60) ----" >&2
      tail -n 60 "$err" >&2 || true
    fi
    return 0
  fi

  local opened sent held closed timed_out failed delay barrier_wait during during_body \
        during_secs after after_secs min max during_error after_error
  opened=$(json_get "$json" opened)
  sent=$(json_get "$json" sent)
  held=$(json_get "$json" held_at_health)
  closed=$(json_get "$json" closed)
  timed_out=$(json_get "$json" timed_out)
  failed=$(json_get "$json" failed)
  delay=$(json_get "$json" health_delay_secs)
  barrier_wait=$(json_get "$json" barrier_wait_secs)
  during=$(json_get "$json" health_during_status)
  during_body=$(json_get "$json" health_during_body)
  during_secs=$(json_get "$json" health_during_secs)
  after=$(json_get "$json" health_after_status)
  after_secs=$(json_get "$json" health_after_secs)
  min=$(json_get "$json" min_close_secs)
  max=$(json_get "$json" max_close_secs)
  during_error=$(json_get "$json" health_during_error)
  after_error=$(json_get "$json" health_after_error)

  if [[ "$opened" == "$expected" && "$sent" == "$expected" \
        && "$held" == "$expected" \
        && "$delay" =~ ^[0-9]+(\.[0-9]+)?$ \
        && "$barrier_wait" =~ ^[0-9]+(\.[0-9]+)?$ ]] \
      && awk -v d="$delay" -v b="$barrier_wait" \
           'BEGIN { exit !(d >= 0 && d < 3.0 && b >= 0 && b < 3.0) }'; then
    pass "$id1" "$label 30 条半截 header 已建立并保持到 health 请求（$held/$expected，建连等待 ${barrier_wait}s，health 延迟 ${delay}s）"
  else
    fail "$id1" "$label 半截 header 未全部建立/保持（opened=$opened sent=$sent held=$held，期望 $expected，建连等待 ${barrier_wait}s，health 延迟 ${delay}s）"
  fi

  if [[ "$during" == "200" && "$during_body" == "ok" ]]; then
    pass "$id2" "$label 慢连接存续时 /healthz=200（请求耗时 ${during_secs}s，$held 条仍打开）"
  else
    fail "$id2" "$label 慢连接存续时 /healthz 非 200（status=$during body=$during_body error=$during_error）"
  fi

  if [[ "$closed" == "$expected" && "$timed_out" == "0" && "$failed" == "0" \
        && "$max" =~ ^[0-9]+(\.[0-9]+)?$ ]] \
      && awk -v m="$max" 'BEGIN { exit !(m <= 10.0) }'; then
    pass "$id3" "$label 30 条半截 header 全部收到 EOF/关闭（closed=$closed/$expected，timeout=$timed_out，max=${max}s）"
  else
    fail "$id3" "$label 半截 header 未在 10s 内全部关闭（closed=$closed/$expected timeout=$timed_out failed=$failed max=${max}s）"
  fi

  if [[ "$min" =~ ^[0-9]+(\.[0-9]+)?$ && "$max" =~ ^[0-9]+(\.[0-9]+)?$ ]] \
      && awk -v a="$min" -v b="$max" \
           'BEGIN { exit !(a >= 4.0 && b <= 8.0) }'; then
    pass "$id4" "$label 关闭窗口 ${min}–${max}s，符合 5s header 读超时（非立即拒绝或 10s 级超时）"
  else
    fail "$id4" "$label 关闭窗口 ${min}–${max}s，不符合 5s header 读超时（期望 4s–8s）"
  fi

  if [[ "$after" == "200" ]]; then
    pass "$id5" "$label 全部关闭后 /healthz 仍 200（请求耗时 ${after_secs}s）"
  else
    fail "$id5" "$label 全部关闭后 /healthz 非 200（status=$after error=$after_error）"
  fi
}

list_bak() {
  find "$1" -maxdepth 1 -type f -name "$2" -printf '%f\n' 2>/dev/null | sort
}

# 建立到 agent 入口的 TLS 连接（不带客户端证书），返回服务端证书 DER SHA-256。
served_cert_fpr() {
  "$PYTHON" - "$1" "$2" "$3" <<'PY'
import hashlib
import socket
import ssl
import sys

host, port, ca = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    context = ssl.create_default_context(cafile=ca)
    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise RuntimeError("对端没有返回证书")
            print(hashlib.sha256(der).hexdigest())
except Exception as exc:
    print(f"TLS 握手失败: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
}

# KI-17 慢连接探针：并发建立 N 条只发半截 HTTP header 的 TCP 连接，在它们全部
# 保持打开时请求 /healthz，并在统一截止时间内用 recv/select 等待服务端关闭。
#
# 关键点：
# - 用 threading.Barrier 让 N 条连接都完成 sendall 后才请求 health，避免固定
#   sleep 造成的“碰巧”通过；
# - 关闭时间从每条连接 sendall 完成开始计时，用 select + 总截止时间读取 EOF，
#   不做长时间固定 sleep；
# - 输出 JSON 供 bash 逐项断言（连接数、关闭数、最大/最小关闭耗时、health 状态）。
slow_header_probe() {
  local host=$1 port=$2 count=$3 budget=$4
  "$PYTHON" - "$host" "$port" "$count" "$budget" <<'PY'
import json
import select
import socket
import sys
import threading
import time
import urllib.request

host, port, count, budget = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
partial = b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Slow: "
records = [None] * count
lock = threading.Lock()
barrier = threading.Barrier(count + 1)
release = threading.Event()


def health_request():
    url = f"http://{host}:{port}/healthz"
    started = time.monotonic()
    try:
        with urllib.request.urlopen(url, timeout=3.0) as response:
            body = response.read().decode("utf-8", "replace").strip()
            return response.status, body, None, time.monotonic() - started
    except Exception as exc:
        return 0, "", f"{type(exc).__name__}: {exc}", time.monotonic() - started


def worker(index):
    record = {
        "index": index,
        "opened": False,
        "sent": False,
        "closed": False,
        "timed_out": False,
        "error": None,
        "close_secs": None,
        "peer_bytes": 0,
        "sent_at": None,
    }
    with lock:
        records[index] = record
    sock = None
    try:
        sock = socket.create_connection((host, port), timeout=3.0)
        sock.settimeout(None)
        record["opened"] = True
        sock.sendall(partial)
        record["sent_at"] = time.monotonic()
        record["sent"] = True
        # 所有连接都发出半截 header 后，才允许主线程请求 /healthz。
        barrier.wait(timeout=10.0)
        release.wait(timeout=budget + 5.0)

        deadline = record["sent_at"] + budget
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                record["timed_out"] = True
                break
            ready, _, _ = select.select([sock], [], [], remaining)
            if not ready:
                record["timed_out"] = True
                break
            try:
                data = sock.recv(4096)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                record["closed"] = True
                record["close_secs"] = time.monotonic() - record["sent_at"]
                break
            if data:
                # 服务端可能先发 408/400 再关闭；继续读到 EOF。
                record["peer_bytes"] += len(data)
                continue
            record["closed"] = True
            record["close_secs"] = time.monotonic() - record["sent_at"]
            break
    except Exception as exc:
        record["error"] = f"{type(exc).__name__}: {exc}"
        try:
            barrier.abort()
        except Exception:
            pass
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


threads = [
    threading.Thread(target=worker, args=(index,), daemon=True)
    for index in range(count)
]
for thread in threads:
    thread.start()

barrier_error = None
try:
    barrier.wait(timeout=10.0)
except threading.BrokenBarrierError as exc:
    barrier_error = str(exc)
barrier_passed_at = time.monotonic()

with lock:
    opened_at_health = sum(1 for record in records if record and record["opened"])
    sent_at_health = sum(1 for record in records if record and record["sent"])
    sent_times = [
        record["sent_at"]
        for record in records
        if record and record["sent_at"] is not None
    ]

barrier_wait_secs = barrier_passed_at - min(sent_times) if sent_times else None
health_delay_secs = time.monotonic() - barrier_passed_at
during_status, during_body, during_error, during_secs = health_request()
release.set()

join_deadline = time.monotonic() + budget + 3.0
for thread in threads:
    thread.join(timeout=max(0.05, join_deadline - time.monotonic()))

with lock:
    snapshot = [dict(record) for record in records if record]

closed = sum(1 for record in snapshot if record["closed"])
timed_out = sum(1 for record in snapshot if record["timed_out"])
errors = [record["error"] for record in snapshot if record["error"]]
close_times = [
    record["close_secs"] for record in snapshot if record["close_secs"] is not None
]
peer_bytes = sum(record["peer_bytes"] for record in snapshot)

after_status, after_body, after_error, after_secs = health_request()
result = {
    "target": f"{host}:{port}",
    "requested": count,
    "opened": opened_at_health,
    "sent": sent_at_health,
    "held_at_health": sent_at_health,
    "closed": closed,
    "timed_out": timed_out,
    "failed": len(errors),
    "errors": errors,
    "barrier_error": barrier_error,
    "peer_bytes": peer_bytes,
    "health_delay_secs": round(health_delay_secs, 3),
    "barrier_wait_secs": round(barrier_wait_secs, 3)
    if barrier_wait_secs is not None
    else None,
    "health_during_status": during_status,
    "health_during_body": during_body,
    "health_during_error": during_error,
    "health_during_secs": round(during_secs, 3),
    "health_after_status": after_status,
    "health_after_body": after_body,
    "health_after_error": after_error,
    "health_after_secs": round(after_secs, 3),
    "min_close_secs": round(min(close_times), 3) if close_times else None,
    "max_close_secs": round(max(close_times), 3) if close_times else None,
    "all_closed": closed == count and timed_out == 0 and not errors,
}
print(json.dumps(result, ensure_ascii=False))
PY
}

write_agent_config() {
  mkdir -p "$AGENT_DATA"
  chmod 700 "$AGENT_DATA"
  cat > "$AGENT_CFG" <<EOF
hub_url = "wss://127.0.0.1:$AGENT_PORT_CFG/agent/ws"
token = "$ENROLL_TOKEN"
server_fingerprint = "$ORIGINAL_FPR"
name = "e2e-v031"
data_dir = "$AGENT_DATA"
sample_interval_ms = 1000
buffer_max_bytes = 10485760
session_max_hours = 0
EOF
  chmod 600 "$AGENT_CFG"
}

start_hub() {
  local timeout=${1:-30}
  RUST_LOG=rustboard_hub=info "$HUB_BIN" run --config "$HUB_CFG" >> "$HUB_LOG" 2>&1 &
  HUB_PID=$!
  PIDS+=("$HUB_PID")
  wait_health "$timeout"
}

start_agent() {
  RUST_LOG=rustboard_agent=info "$AGENT_BIN" run --config "$AGENT_CFG" >> "$AGENT_LOG" 2>&1 &
  A_PID=$!
  PIDS+=("$A_PID")
}

stop_pid() {
  local pid=$1 name=$2 timeout=${3:-10}
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))

  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null || true
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    if (( $(date +%s%3N) >= deadline )); then
      echo "警告: $name (pid $pid) 未在 ${timeout}s 内退出，强制 kill -9" >&2
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 0.1
  done
  wait "$pid" 2>/dev/null || true
  kill -0 "$pid" 2>/dev/null && return 1
  return 0
}

# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub / rustboard-agent / rustboard-panel（cargo build --locked -p ...）"
(cd "$ROOT" && "$CARGO" build --locked \
    -p rustboard-hub -p rustboard-agent -p rustboard-panel) \
  > "$BUILD_LOG" 2>&1 \
  || die "cargo build --locked -p rustboard-hub -p rustboard-agent -p rustboard-panel 失败（日志: $BUILD_LOG）"

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

AGENT_PORT=$(pick_port)
ADMIN_PORT=$(pick_port)
while [[ "$ADMIN_PORT" == "$AGENT_PORT" ]]; do
  ADMIN_PORT=$(pick_port)
done

# ---------------------------------------------------------------------------
# 场景 1：基线（hub 启动 + agent 纳管 + 上报）
# ---------------------------------------------------------------------------

echo
echo "==> 阶段 1/7：基线 hub 启动、agent 纳管与样本上报"

if "$HUB_BIN" init \
    --config "$HUB_CFG" \
    --data-dir "$HUB_DATA" \
    --agent-listen "127.0.0.1:$AGENT_PORT" \
    --admin-listen "127.0.0.1:$ADMIN_PORT" \
    --force > "$INIT_LOG" 2>&1; then
  pass "1.1" "hub init 成功（config=$HUB_CFG data_dir=$HUB_DATA）"
  # init 输出包含 admin_token；落盘日志先脱敏，避免 KEEP_E2E_TMP 或失败现场泄露。
  sed -i -E 's/(管理 API token:).*/\1 <redacted>/' "$INIT_LOG" 2>/dev/null || true
else
  die "hub init 失败（日志: $INIT_LOG）"
fi

[[ -f "$HUB_CFG" ]] || die "hub init 未生成配置: $HUB_CFG"

AGENT_LISTEN=$(cfg_str "$HUB_CFG" agent_listen) || die "无法从配置解析 agent_listen"
ADMIN_LISTEN=$(cfg_str "$HUB_CFG" admin_listen) || die "无法从配置解析 admin_listen"
HUB_DATA_CFG=$(cfg_str "$HUB_CFG" data_dir) || die "无法从配置解析 data_dir"
AGENT_HOST=${AGENT_LISTEN%:*}
AGENT_PORT_CFG=${AGENT_LISTEN##*:}
ADMIN_HOST=${ADMIN_LISTEN%:*}
ADMIN_PORT_CFG=${ADMIN_LISTEN##*:}

check_eq "1.2" "config 的 agent_listen 与 init 参数一致（仅回环）" \
  "127.0.0.1:$AGENT_PORT" "$AGENT_LISTEN"
check_eq "1.3" "config 的 admin_listen 与 init 参数一致（仅回环）" \
  "127.0.0.1:$ADMIN_PORT" "$ADMIN_LISTEN"
check_eq "1.4" "config 的 data_dir 与 init 参数一致" "$HUB_DATA" "$HUB_DATA_CFG"
[[ "$AGENT_HOST" == "127.0.0.1" && "$ADMIN_HOST" == "127.0.0.1" ]] \
  || die "监听地址不是回环: agent=$AGENT_LISTEN admin=$ADMIN_LISTEN"
[[ "$AGENT_PORT_CFG" =~ ^[0-9]+$ && "$ADMIN_PORT_CFG" =~ ^[0-9]+$ ]] \
  || die "无法从 config 解析端口: agent=$AGENT_PORT_CFG admin=$ADMIN_PORT_CFG"

ADMIN_URL="http://127.0.0.1:$ADMIN_PORT_CFG"

# 管理 API 必须有 Bearer token。用官方 CLI 读取；token 只进变量与 curl/Python header。
ADMIN_TOKEN=$("$HUB_BIN" admin-token --config "$HUB_CFG" 2> "$TOKEN_ERR") \
  || die "rustboard-hub admin-token 失败（见 $TOKEN_ERR）"
[[ "$ADMIN_TOKEN" =~ ^[0-9a-f]{64}$ ]] \
  || die "admin-token 输出不是 64 位十六进制（长度 ${#ADMIN_TOKEN}；不打印内容）"
pass "1.5" "已通过 admin-token 取得 64 位 hex 管理 token（不打印内容）"

# 本场景高频轮询管理 API；管理限速由 hardening.sh 单独覆盖，这里放宽避免 429
# 干扰证书断言（仍是同一套鉴权与中间件）。
sed -i 's/^self_monitor = true$/self_monitor = false/' "$HUB_CFG"
sed -i 's/^sample_interval_ms = 5000$/sample_interval_ms = 1000/' "$HUB_CFG"
if grep -q '^admin_rate_limit_per_min' "$HUB_CFG"; then
  sed -i 's/^admin_rate_limit_per_min.*/admin_rate_limit_per_min = 6000/' "$HUB_CFG"
else
  printf '\nadmin_rate_limit_per_min = 6000\n' >> "$HUB_CFG"
fi
grep -q '^self_monitor = false' "$HUB_CFG" || die "无法关闭 hub 的 self_monitor"
grep -q '^sample_interval_ms = 1000' "$HUB_CFG" || die "无法调整 hub 采样间隔"
grep -q '^admin_rate_limit_per_min = 6000' "$HUB_CFG" \
  || die "无法放宽管理 API 限速（避免轮询被 429）"

CA_CRT="$HUB_DATA/certs/ca.crt"
CA_KEY="$HUB_DATA/certs/ca.key"
SERVER_CRT="$HUB_DATA/certs/server.crt"
SERVER_KEY="$HUB_DATA/certs/server.key"
[[ -f "$CA_CRT" && -f "$CA_KEY" && -f "$SERVER_CRT" && -f "$SERVER_KEY" ]] \
  || die "hub 证书文件不完整（$HUB_DATA/certs）"

CA_HASH_BASELINE=$(file_sha256 "$CA_CRT") || die "无法计算 ca.crt 哈希"
CA_KEY_HASH_BASELINE=$(file_sha256 "$CA_KEY") || die "无法计算 ca.key 哈希"
ORIGINAL_CERT_HASH=$(file_sha256 "$SERVER_CRT") || die "无法计算 server.crt 哈希"
ORIGINAL_KEY_HASH=$(file_sha256 "$SERVER_KEY") || die "无法计算 server.key 哈希"
cert_inspect "$SERVER_CRT" "$SERVER_KEY" "$CA_CRT" \
  > "$SNAPSHOT_DIR/server-original.json" || die "无法解析原始 server.crt"
ORIGINAL_FPR=$(json_get "$SNAPSHOT_DIR/server-original.json" fingerprint)
ORIGINAL_NOT_AFTER=$(json_get "$SNAPSHOT_DIR/server-original.json" not_after)
CA_CN=$(json_get "$SNAPSHOT_DIR/server-original.json" ca_cn)
[[ "$ORIGINAL_FPR" =~ ^[0-9a-f]{64}$ ]] || die "原始 server.crt 指纹不合法"
[[ -n "$CA_CN" && "$CA_CN" != "__MISSING__" ]] || die "无法从原始证书解析当前 CA 的 CN"
check_meta "1.6" "原始 server.crt 未过期" "$SNAPSHOT_DIR/server-original.json" \
  "expired" "False"

# 先在 hub 未运行时写 DB，避免运维 CLI 与运行中的 hub 并发访问 SQLite。
ENROLL_TOKEN=$("$HUB_BIN" agent add --config "$HUB_CFG" --name "e2e-v031" \
  | awk '/一次性 token/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}')
[[ "$ENROLL_TOKEN" =~ ^[0-9a-f]{64}$ ]] \
  || die "无法从 agent add 输出解析 enrollment token（不打印内容）"
write_agent_config

if ! start_hub 30; then
  fail "1.7" "hub 未在 30s 内就绪（/healthz）"
  die "hub 启动失败，无法继续"
fi
pass "1.7" "hub /healthz 就绪（agent=127.0.0.1:$AGENT_PORT_CFG admin=$ADMIN_PORT_CFG）"

start_agent
if ! wait_for_file "$AGENT_DATA/agent_id" 30; then
  fail "1.8" "agent 未在 30s 内完成 enrollment"
  die "agent enrollment 失败"
fi
if ! wait_for_file "$AGENT_DATA/agent.crt" 10 \
    || ! wait_for_file "$AGENT_DATA/agent.key" 10; then
  fail "1.8" "agent enrollment 未写出 agent.crt / agent.key"
  die "agent 证书材料不完整"
fi
A_ID=$(tr -d '[:space:]' < "$AGENT_DATA/agent_id")
[[ -n "$A_ID" ]] || die "agent_id 为空"
pass "1.8" "agent 完成 enrollment（agent_id=$A_ID）"

if wait_agent_status online 60; then
  pass "1.9" "agent 状态为 online"
else
  fail "1.9" "agent 未在 60s 内 online（最后状态: $LAST_STATUS）"
  die "无法继续：agent 未上线"
fi

if wait_series_min 1 30; then
  pass "1.10" "agent 开始上报样本（已入库 ≥1 行）"
else
  fail "1.10" "agent 未在 30s 内上报任何样本（last=$LAST_STATUS）"
  die "无法继续：没有样本"
fi
COUNT_BASELINE=$(series_count 2>/dev/null || echo 0)
if wait_series_min $((COUNT_BASELINE + 2)) 25; then
  pass "1.11" "样本数持续增长（从 $COUNT_BASELINE 继续增加）"
else
  fail "1.11" "样本数未继续增长（基线 $COUNT_BASELINE，last=$LAST_STATUS）"
fi

if http_json "$ADMIN_URL/api/v1/system" > "$SNAPSHOT_DIR/system-baseline.json" \
    2> "$SYSTEM_ERR"; then
  check_eq "1.12" "基线 /api/v1/system 的 cert.disk 指纹与磁盘 server.crt 一致" \
    "$ORIGINAL_FPR" "$(json_get "$SNAPSHOT_DIR/system-baseline.json" cert.disk.fingerprint)"
  check_eq "1.13" "基线 /api/v1/system 的 cert.disk.not_after 与磁盘一致" \
    "$ORIGINAL_NOT_AFTER" "$(json_get "$SNAPSHOT_DIR/system-baseline.json" cert.disk.not_after)"
else
  fail "1.12" "基线 GET /api/v1/system 失败"
  tail -n 40 "$SYSTEM_ERR" >&2 || true
fi

if [[ -f "$AGENT_DATA/ca.crt" ]]; then
  pass "1.14" "enrollment 已把原 ca.crt 写入 agent 数据目录（重连依赖）"
else
  fail "1.14" "enrollment 未写入 ca.crt，无法验证 CA 信任重连"
  die "缺少 $AGENT_DATA/ca.crt"
fi

A_PID_BEFORE=$A_PID
AGENT_ID_HASH_BEFORE=$(file_sha256 "$AGENT_DATA/agent_id")
AGENT_SECRET_HASH_BEFORE=$(file_sha256 "$AGENT_DATA/agent.secret")
AGENT_CA_HASH_BEFORE=$(file_sha256 "$AGENT_DATA/ca.crt")
COUNT_BEFORE_RESTART=$(series_count 2>/dev/null || echo 0)
ORIGINAL_FPR_BEFORE_REPLACE=$ORIGINAL_FPR

# ---------------------------------------------------------------------------
# 场景 2：停 hub，写入「仅过期」服务端证书（CA 不变）
# ---------------------------------------------------------------------------

echo
echo "==> 阶段 2/7：停 hub，用当前 CA 写入已过期服务端证书（2020-01-01～2020-02-01）"

if stop_pid "$HUB_PID" "hub" 10; then
  HUB_PID=""
  pass "2.1" "hub 已停止（agent 保持运行，用于验证自动重连）"
else
  fail "2.1" "hub 未能在 10s 内停止"
  die "hub 未停止，无法安全替换证书"
fi

if kill -0 "$A_PID" 2>/dev/null && [[ "$A_PID" == "$A_PID_BEFORE" ]]; then
  pass "2.2" "替换证书期间 agent 进程仍在运行（pid=$A_PID）"
else
  fail "2.2" "agent 进程意外退出或被重启（before=$A_PID_BEFORE now=$A_PID）"
fi

CA_HASH_BEFORE_INJECT=$(file_sha256 "$CA_CRT") || die "无法计算 ca.crt 哈希"
check_eq "2.3" "替换前 CA 与基线一致" "$CA_HASH_BASELINE" "$CA_HASH_BEFORE_INJECT"

if "$PYTHON" "$CERT_HELPER" make-expired \
    --config "$HUB_CFG" \
    --ca-cert "$CA_CRT" \
    --ca-key "$CA_KEY" \
    --out-cert "$EXPIRED_CRT_TMP" \
    --out-key "$EXPIRED_KEY_TMP" > "$EXPIRED_META" 2> "$TMP_DIR/expired.err"; then
  pass "2.4" "已用当前 CA 私钥生成过期服务端证书"
else
  fail "2.4" "生成过期证书失败"
  tail -n 60 "$TMP_DIR/expired.err" >&2 || true
  die "无法构造过期证书"
fi

cert_inspect "$EXPIRED_CRT_TMP" "$EXPIRED_KEY_TMP" "$CA_CRT" \
  > "$SNAPSHOT_DIR/expired.json" || die "无法解析生成的过期证书"
EXPIRED_FPR=$(json_get "$SNAPSHOT_DIR/expired.json" fingerprint)
check_meta "2.5" "过期证书的 CN 为 rustboard-hub" "$SNAPSHOT_DIR/expired.json" \
  "subject_cn" "rustboard-hub"
check_meta "2.6" "过期证书 notBefore 为 2020-01-01T00:00:00Z" \
  "$SNAPSHOT_DIR/expired.json" "not_before_iso" "2020-01-01T00:00:00Z"
check_meta "2.7" "过期证书 notAfter 为 2020-02-01T00:00:00Z" \
  "$SNAPSHOT_DIR/expired.json" "not_after_iso" "2020-02-01T00:00:00Z"
check_meta "2.8" "过期证书当前确实已过期" "$SNAPSHOT_DIR/expired.json" "expired" "True"
check_meta "2.9" "过期证书 SAN 覆盖 127.0.0.1" "$SNAPSHOT_DIR/expired.json" \
  "has_ip_127_0_0_1" "True"
check_meta "2.10" "过期证书 SAN 覆盖 localhost" "$SNAPSHOT_DIR/expired.json" \
  "has_localhost" "True"
check_meta "2.11" "过期证书仍由当前 CA 签发（签名可验）" \
  "$SNAPSHOT_DIR/expired.json" "signature_valid" "True"
check_meta "2.12" "过期证书与配套私钥匹配" "$SNAPSHOT_DIR/expired.json" \
  "key_matches" "True"
check_eq "2.13" "生成的过期证书 issuer 是当前 CA" \
  "$CA_CN" "$(json_get "$SNAPSHOT_DIR/expired.json" issuer_cn)"

# 写回磁盘：证书 0644、私钥 0600；CA 与 ca.key 保持原样。
install -m 0644 "$EXPIRED_CRT_TMP" "$SERVER_CRT"
install -m 0600 "$EXPIRED_KEY_TMP" "$SERVER_KEY"
EXPIRED_CERT_HASH=$(file_sha256 "$SERVER_CRT") || die "无法计算过期证书哈希"
EXPIRED_KEY_HASH=$(file_sha256 "$SERVER_KEY") || die "无法计算过期私钥哈希"
check_eq "2.14" "磁盘 server.crt 已换成过期证书" \
  "$(file_sha256 "$EXPIRED_CRT_TMP")" "$EXPIRED_CERT_HASH"
check_eq "2.15" "磁盘 server.key 已换成配套私钥" \
  "$(file_sha256 "$EXPIRED_KEY_TMP")" "$EXPIRED_KEY_HASH"
check_mode "2.16" "$SERVER_CRT" "644"
check_mode "2.17" "$SERVER_KEY" "600"
check_eq "2.18" "写入过期证书未改动 ca.crt" \
  "$CA_HASH_BASELINE" "$(file_sha256 "$CA_CRT")"
check_eq "2.19" "写入过期证书未改动 ca.key" \
  "$CA_KEY_HASH_BASELINE" "$(file_sha256 "$CA_KEY")"
[[ "$EXPIRED_CERT_HASH" != "$ORIGINAL_CERT_HASH" ]] \
  && pass "2.20" "替换后的 server.crt 与原始证书不同" \
  || fail "2.20" "替换后的 server.crt 与原始证书相同"
[[ "$EXPIRED_KEY_HASH" != "$ORIGINAL_KEY_HASH" ]] \
  && pass "2.21" "替换后的 server.key 与原始私钥不同" \
  || fail "2.21" "替换后的 server.key 与原始私钥相同"

# ---------------------------------------------------------------------------
# 场景 3：重启 hub，过期证书启动自愈
# ---------------------------------------------------------------------------

echo
echo "==> 阶段 3/7：重启 hub（仅因过期的证书必须自愈），原 agent 自动重连"

if ! start_hub 40; then
  fail "3.1" "过期证书下 hub 未在 40s 内启动（/healthz 不可用）"
  die "hub 未能自愈启动（见 hub 日志尾部）"
fi
pass "3.1" "过期证书下 hub 启动成功且 /healthz 200"

if kill -0 "$HUB_PID" 2>/dev/null; then
  pass "3.2" "hub 进程在自愈后持续运行（未因过期证书退出）"
else
  fail "3.2" "hub 进程启动后已退出"
fi

cert_inspect "$SERVER_CRT" "$SERVER_KEY" "$CA_CRT" \
  > "$SNAPSHOT_DIR/server-healed.json" || die "无法解析自愈后的 server.crt"
NEW_FPR=$(json_get "$SNAPSHOT_DIR/server-healed.json" fingerprint)
NEW_NOT_AFTER=$(json_get "$SNAPSHOT_DIR/server-healed.json" not_after)
[[ "$NEW_FPR" =~ ^[0-9a-f]{64}$ ]] || die "自愈后 server.crt 指纹不合法"
[[ "$NEW_NOT_AFTER" =~ ^[0-9]+$ ]] || die "自愈后 not_after 不是整数"

if [[ "$NEW_FPR" != "$EXPIRED_FPR" ]]; then
  pass "3.3" "启动自愈替换了磁盘 server.crt（${EXPIRED_FPR:0:12}… → ${NEW_FPR:0:12}…）"
else
  fail "3.3" "启动后磁盘仍是那张过期证书（指纹未变化: $NEW_FPR）"
fi

check_meta "3.4" "自愈后的证书未过期" "$SNAPSHOT_DIR/server-healed.json" "expired" "False"
if (( NEW_NOT_AFTER > $(date +%s) )); then
  pass "3.5" "自愈后的 notAfter 在未来（$NEW_NOT_AFTER > now）"
else
  fail "3.5" "自愈后的 notAfter 不在未来（$NEW_NOT_AFTER）"
fi
NEW_DAYS_LEFT=$(json_get "$SNAPSHOT_DIR/server-healed.json" days_left)
if [[ "$NEW_DAYS_LEFT" =~ ^-?[0-9]+$ ]] && (( NEW_DAYS_LEFT > 0 )); then
  pass "3.6" "自愈后的证书 days_left > 0（$NEW_DAYS_LEFT 天）"
else
  fail "3.6" "自愈后的证书 days_left 不大于 0（$NEW_DAYS_LEFT）"
fi
check_meta "3.7" "自愈后的证书仍由当前 CA 签发" \
  "$SNAPSHOT_DIR/server-healed.json" "signature_valid" "True"
check_meta "3.8" "自愈后的证书 issuer 是当前 CA" \
  "$SNAPSHOT_DIR/server-healed.json" "issuer_cn" "$CA_CN"
check_meta "3.9" "自愈后的证书与 server.key 配套" \
  "$SNAPSHOT_DIR/server-healed.json" "key_matches" "True"
check_meta "3.10" "自愈后的证书 CN 为 rustboard-hub" \
  "$SNAPSHOT_DIR/server-healed.json" "subject_cn" "rustboard-hub"
check_meta "3.11" "自愈后的证书 SAN 覆盖 127.0.0.1" \
  "$SNAPSHOT_DIR/server-healed.json" "has_ip_127_0_0_1" "True"
check_mode "3.12" "$SERVER_KEY" "600"
check_mode "3.13" "$SERVER_CRT" "644"
check_eq "3.14" "启动自愈未改动 ca.crt" \
  "$CA_HASH_BASELINE" "$(file_sha256 "$CA_CRT")"
check_eq "3.15" "启动自愈未改动 ca.key" \
  "$CA_KEY_HASH_BASELINE" "$(file_sha256 "$CA_KEY")"
if [[ "$NEW_FPR" != "$ORIGINAL_FPR_BEFORE_REPLACE" ]]; then
  pass "3.16" "自愈后指纹较替换前发生变化（${ORIGINAL_FPR_BEFORE_REPLACE:0:12}… → ${NEW_FPR:0:12}…）"
else
  fail "3.16" "自愈后指纹与替换前相同（$NEW_FPR），无法证明重签"
fi

# 监听器实际使用新证书：用原 ca.crt 对 agent 入口做一次真实 TLS 握手。
if SERVED_FPR=$(served_cert_fpr "127.0.0.1" "$AGENT_PORT_CFG" "$CA_CRT" 2> "$TMP_DIR/tls.err"); then
  check_eq "3.17" "监听器实际提供的证书就是自愈后的 server.crt" \
    "$NEW_FPR" "$SERVED_FPR"
  [[ "$SERVED_FPR" != "$EXPIRED_FPR" ]] \
    && pass "3.18" "监听器不再提供那张过期证书" \
    || fail "3.18" "监听器仍在提供过期证书"
else
  fail "3.17" "用当前 CA 对 agent 入口做 TLS 握手失败"
  tail -n 40 "$TMP_DIR/tls.err" >&2 || true
fi

# --- 阶段 4：备份与权限 ----------------------------------------------------
echo
echo "==> 阶段 4/7：成对备份与文件权限"
mapfile -t CRT_BAKS < <(list_bak "$HUB_DATA/certs" 'server.crt.bak-*')
mapfile -t KEY_BAKS < <(list_bak "$HUB_DATA/certs" 'server.key.bak-*')
if (( ${#CRT_BAKS[@]} == 1 && ${#KEY_BAKS[@]} == 1 )); then
  pass "4.1" "旧证书/私钥有成对备份（crt/key 各 1 个）"

  CRT_SUFFIX=${CRT_BAKS[0]#server.crt.bak-}
  KEY_SUFFIX=${KEY_BAKS[0]#server.key.bak-}
  check_eq "4.2" "备份 crt/key 使用同一时间戳后缀" "$CRT_SUFFIX" "$KEY_SUFFIX"

  CRT_BAK="$HUB_DATA/certs/${CRT_BAKS[0]}"
  KEY_BAK="$HUB_DATA/certs/${KEY_BAKS[0]}"
  check_eq "4.3" "crt 备份内容就是被替换的过期证书" \
    "$EXPIRED_CERT_HASH" "$(file_sha256 "$CRT_BAK")"
  check_eq "4.4" "key 备份内容就是被替换的过期私钥" \
    "$EXPIRED_KEY_HASH" "$(file_sha256 "$KEY_BAK")"
  check_mode "4.5" "$CRT_BAK" "644"
  check_mode "4.6" "$KEY_BAK" "600"
else
  fail "4.1" "备份不是成对的一份（crt=${#CRT_BAKS[@]} key=${#KEY_BAKS[@]}）"
  fail "4.2" "备份后缀无法比较"
  fail "4.3" "无法校验 crt 备份内容"
  fail "4.4" "无法校验 key 备份内容"
  fail "4.5" "无法校验 crt 备份权限"
  fail "4.6" "无法校验 key 备份权限"
fi

# --- 阶段 5：管理 API 与日志 ----------------------------------------------
echo
echo "==> 阶段 5/7：管理 API、自愈日志与泄露检查"
if http_json "$ADMIN_URL/api/v1/system" > "$SYSTEM_JSON" 2> "$SYSTEM_ERR"; then
  SYS_DISK_FPR=$(json_get "$SYSTEM_JSON" cert.disk.fingerprint)
  SYS_DISK_NOT_AFTER=$(json_get "$SYSTEM_JSON" cert.disk.not_after)
  SYS_DISK_DAYS=$(json_get "$SYSTEM_JSON" cert.disk.days_left)
  SYS_LIVE_FPR=$(json_get "$SYSTEM_JSON" cert.live.fingerprint)
  SYS_TOP_FPR=$(json_get "$SYSTEM_JSON" cert.fingerprint)

  check_eq "5.1" "/api/v1/system 的 cert.disk 指纹与磁盘自愈后证书一致" \
    "$NEW_FPR" "$SYS_DISK_FPR"
  check_eq "5.2" "/api/v1/system 的 cert.live 指纹与自愈后证书一致" \
    "$NEW_FPR" "$SYS_LIVE_FPR"
  check_eq "5.3" "/api/v1/system 顶层 cert.fingerprint 等于 live 新指纹" \
    "$NEW_FPR" "$SYS_TOP_FPR"
  if [[ "$SYS_DISK_NOT_AFTER" =~ ^[0-9]+$ ]] \
      && (( SYS_DISK_NOT_AFTER > $(date +%s) )); then
    pass "5.4" "/api/v1/system 的 cert.disk.not_after 在未来（$SYS_DISK_NOT_AFTER）"
  else
    fail "5.4" "/api/v1/system 的 cert.disk.not_after 不在未来（$SYS_DISK_NOT_AFTER）"
  fi
  if [[ "$SYS_DISK_DAYS" =~ ^-?[0-9]+$ ]] && (( SYS_DISK_DAYS > 0 )); then
    pass "5.5" "/api/v1/system 的 cert.disk.days_left > 0（$SYS_DISK_DAYS 天）"
  else
    fail "5.5" "/api/v1/system 的 cert.disk.days_left 不大于 0（$SYS_DISK_DAYS）"
  fi
  [[ "$SYS_DISK_FPR" != "$ORIGINAL_FPR_BEFORE_REPLACE" \
      && "$SYS_DISK_FPR" != "$EXPIRED_FPR" ]] \
    && pass "5.6" "/api/v1/system 报告的指纹较替换前和过期证书都不同" \
    || fail "5.6" "/api/v1/system 指纹未按预期变化（$SYS_DISK_FPR）"
else
  fail "5.1" "GET /api/v1/system 失败（自愈后）"
  for id in 5.2 5.3 5.4 5.5 5.6; do
    fail "$id" "跳过：/api/v1/system 不可用"
  done
  tail -n 40 "$SYSTEM_ERR" >&2 || true
fi

# --- 日志 ------------------------------------------------------------------
check_log_has "5.7" "$HUB_LOG" "hub 日志包含“仅因过期”判定" '仅因过期'
check_log_has "5.8" "$HUB_LOG" "hub 日志包含“自动重签”动作" '自动重签'
check_log_has "5.9" "$HUB_LOG" "hub 日志记录了过期证书的 notAfter" \
  'notAfter=2020-02-01T00:00:00Z'
check_log_absent "5.10" "$HUB_LOG" "hub 日志不包含证书/私钥 PEM 正文" \
  'BEGIN CERTIFICATE|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|PRIVATE KEY-----'
check_log_no_tokens "5.11" "$HUB_LOG" "hub 日志不包含 admin_token / enrollment token"
check_no_panic "5.12" "$HUB_LOG" "hub 启动自愈过程没有 panic"
check_no_panic "5.13" "$AGENT_LOG" "agent 日志没有 panic"

# --- 阶段 6：原 agent 自动重连 ---------------------------------------------
echo
echo "==> 阶段 6/7：原 agent 自动重连与样本续增"
if kill -0 "$A_PID" 2>/dev/null && [[ "$A_PID" == "$A_PID_BEFORE" ]]; then
  pass "6.1" "原 agent 进程未重启（pid=$A_PID）"
else
  fail "6.1" "agent 进程已变化（before=$A_PID_BEFORE now=$A_PID）"
fi

if wait_agent_status online 90; then
  pass "6.2" "原 agent 在 hub 自愈后自动重连为 online（无需重新纳管）"
else
  fail "6.2" "原 agent 未在 90s 内自动重连（last=$LAST_STATUS）"
fi

if AGENT_COUNT=$(agents_len 2>/dev/null); then
  check_eq "6.3" "hub 中仍然只有这一台 agent（无新增纳管记录）" "1" "$AGENT_COUNT"
else
  fail "6.3" "无法读取 /api/v1/agents 统计 agent 数量"
fi

check_eq "6.4" "重连后 agent_id 未变化（未重新 enrollment）" \
  "$AGENT_ID_HASH_BEFORE" "$(file_sha256 "$AGENT_DATA/agent_id")"
check_eq "6.5" "重连后 agent.secret 未变化（未重新 enrollment）" \
  "$AGENT_SECRET_HASH_BEFORE" "$(file_sha256 "$AGENT_DATA/agent.secret")"
check_eq "6.6" "重连后 agent 端 ca.crt 未变化（继续信任原 CA）" \
  "$AGENT_CA_HASH_BEFORE" "$(file_sha256 "$AGENT_DATA/ca.crt")"

if wait_series_min $((COUNT_BEFORE_RESTART + 2)) 60; then
  pass "6.7" "证书自愈+重连后样本数继续增长（基线 $COUNT_BEFORE_RESTART）"
else
  COUNT_NOW=$(series_count 2>/dev/null || echo "unavailable")
  fail "6.7" "样本数未在 60s 内继续增长（基线 $COUNT_BEFORE_RESTART，当前 $COUNT_NOW，last=$LAST_STATUS）"
fi

if http_json "$ADMIN_URL/api/v1/system" > "$SNAPSHOT_DIR/system-final.json" \
    2> "$SYSTEM_ERR"; then
  check_eq "6.8" "重连后 /api/v1/system 仍报告自愈后的新证书" \
    "$NEW_FPR" "$(json_get "$SNAPSHOT_DIR/system-final.json" cert.disk.fingerprint)"
else
  fail "6.8" "重连后 GET /api/v1/system 失败"
  tail -n 40 "$SYSTEM_ERR" >&2 || true
fi

# ---------------------------------------------------------------------------
# 阶段 7：KI-17 管理 API / 面板慢连接（30 条半截 header）
# ---------------------------------------------------------------------------

echo
echo "==> 阶段 7/7：KI-17 hub 管理口 / panel 监听口 30 条半截 header 慢连接"

PANEL_PORT=$(pick_port)
while [[ "$PANEL_PORT" == "$AGENT_PORT" || "$PANEL_PORT" == "$ADMIN_PORT" ]] \
    || [[ "$PANEL_PORT" == "$AGENT_PORT_CFG" || "$PANEL_PORT" == "$ADMIN_PORT_CFG" ]]; do
  PANEL_PORT=$(pick_port)
done
PANEL_URL="http://127.0.0.1:$PANEL_PORT"
PANEL_PASSWORD="v031-panel-$(date +%s%N)-pw"

if ! "$PANEL_BIN" init \
    --config "$PANEL_CFG" \
    --listen "127.0.0.1:$PANEL_PORT" \
    --hub "$ADMIN_URL" \
    --hub-token "$ADMIN_TOKEN" \
    --password "$PANEL_PASSWORD" \
    --force > "$PANEL_INIT_LOG" 2>&1; then
  unset PANEL_PASSWORD
  fail "7.1" "panel init 失败（见 panel-init.log；密码行已脱敏）"
  dump_log "$PANEL_INIT_LOG" 60
  die "panel init 失败，无法继续 KI-17 场景"
fi
unset PANEL_PASSWORD
sed -i -E 's/(面板密码[^:：]*[:：]).*/\1 <redacted>/' "$PANEL_INIT_LOG" 2>/dev/null || true
pass "7.1" "panel init 成功（复用当前 hub 管理地址与 token，不依赖 web/dist）"
check_mode "7.2" "$PANEL_CFG" "600"

PANEL_LISTEN_CFG=$(cfg_str "$PANEL_CFG" listen) \
  || die "无法从 panel 配置解析 listen"
check_eq "7.3" "panel listen 只绑 127.0.0.1:$PANEL_PORT" \
  "127.0.0.1:$PANEL_PORT" "$PANEL_LISTEN_CFG"

RUST_LOG=rustboard_panel=info "$PANEL_BIN" run --config "$PANEL_CFG" \
  >> "$PANEL_LOG" 2>&1 &
PANEL_PID=$!
PIDS+=("$PANEL_PID")
if ! wait_health_url "$PANEL_URL/healthz" 25 "$PANEL_PID"; then
  fail "7.4" "panel /healthz 未在 25s 内返回 200"
  die "panel 未就绪，无法继续 KI-17 场景"
fi
pass "7.4" "panel /healthz 返回 200（未构建前端也可用；页面 503 不影响探针）"

echo "==> KI-17：hub 管理口 $ADMIN_URL（30 条半截 header）"
slow_header_probe "127.0.0.1" "$ADMIN_PORT_CFG" 30 10 \
  > "$SLOW_HUB_JSON" 2> "$SLOW_HUB_ERR" || true
slow_assert_target "hub 管理口" "$SLOW_HUB_JSON" "$SLOW_HUB_ERR" "7" 5 30

echo "==> KI-17：panel 监听口 $PANEL_URL（30 条半截 header）"
slow_header_probe "127.0.0.1" "$PANEL_PORT" 30 10 \
  > "$SLOW_PANEL_JSON" 2> "$SLOW_PANEL_ERR" || true
slow_assert_target "panel 监听口" "$SLOW_PANEL_JSON" "$SLOW_PANEL_ERR" "7" 10 30

# ---------------------------------------------------------------------------
# 收尾与汇总
# ---------------------------------------------------------------------------

echo "==> 停止 panel、agent 与 hub"
if [[ -n "$PANEL_PID" ]]; then
  stop_pid "$PANEL_PID" "panel" 10 || fail "8.1" "panel 未能在 10s 内停止"
  PANEL_PID=""
fi
stop_pid "$A_PID" "agent" 10 || fail "8.2" "agent 未能在 10s 内停止"
A_PID=""
stop_pid "$HUB_PID" "hub" 15 || fail "8.3" "hub 未能在 15s 内停止"
HUB_PID=""

RUN_ELAPSED_MS=$(( $(date +%s%3N) - SCRIPT_STARTED_MS ))
echo
if (( FAILS > 0 )); then
  echo "v031 e2e 结果: PASS $PASSES，FAIL $FAILS（耗时 $((RUN_ELAPSED_MS / 1000))s）" >&2
  exit 1
fi
echo "v031 e2e 结果: 全部 $PASSES 项通过（PASS 数量: $PASSES，耗时 $((RUN_ELAPSED_MS / 1000))s）"
