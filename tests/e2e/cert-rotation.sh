#!/usr/bin/env bash
#
# RustBoard 证书有效期与自动轮换端到端回归。
# 方案：docs/plans/2026-10-23-cert-rotation.md §6（e2e 测试点）
#
# 覆盖 12 个场景：
#   1. hub init（临时 config/data_dir）+ 启动 hub + agent add + 启动 agent：
#      API 显示 online，样本数持续增长，证书/私钥权限符合约定；
#   2. rustboard-agent cert-info：输出证书路径、CN、notAfter、剩余天数，退出 0；
#   3. rustboard-agent renew：agent.crt 内容变化、notAfter 变大、复用原私钥，
#      agent 重启后仍 online 并继续上报；
#   4. 停 hub → rustboard-hub rotate-cert --force（打印新旧指纹且不同）→ 起 hub：
#      agent 保持运行、自动重连、状态 online、数据继续增长，且未重新纳管
#      （证明 CA 信任生效，而不是靠重新 enrollment）；
#   5. GET /api/v1/system 的 cert.fingerprint 与磁盘 server.crt 的 SHA-256 一致。
#   6–12（S1–S7）用独立实例验证证书损坏/恢复与备份：
#      ca.key 与 CA 不匹配、缺 ca.key、垃圾 ca.crt、缺 server.crt、
#      空 server_names、非法 SAN、正常轮换的备份恢复，以及失败路径零新增 bak。
#
# 证书“指纹”沿用 hub ports / 指纹钉扎的既有定义：
#   把 PEM 解码为 DER 后对 DER 做 SHA-256（不是对 PEM 文本做 sha256sum）。
#
# 若同一批次的 M2 已给管理 API 加了 Bearer 鉴权，脚本会从 hub 配置读取
# admin_token 并自动带上 Authorization 头（不回显 token）；证书阶段无此字段时
# 仍按无鉴权方式访问。
#
# 自己构建 hub/agent，在 127.0.0.1 的随机空闲端口和 mktemp 临时目录中运行，
# 结束后清理进程与目录；任一步失败都会打印 hub/agent/CLI 日志尾部。
#
# 依赖：bash 4+、python3（仅标准库）、cargo/rustc、GNU coreutils（timeout/stat/date/find/cp）。
# 用法：bash tests/e2e/cert-rotation.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/cert-rotation.sh   # 保留临时目录与日志
#
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}

# 按任务约定固定使用这套 cargo/rustup 环境。
export PATH="/tmp/cargo/bin:${PATH}"
export CARGO_HOME=/tmp/cargo
export RUSTUP_HOME=/tmp/rustup

PASSES=0
FAILS=0
LAST_STATUS=""

HUB_PID=""
A_PID=""
A_ID=""
ADMIN_URL=""
HUB_BIN=""
AGENT_BIN=""
PIDS=()

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

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-cert-rotation.XXXXXX")
HUB_CFG="$TMP_DIR/hub.toml"
HUB_DATA="$TMP_DIR/hub"
HUB_LOG="$TMP_DIR/hub.log"
AGENT_CFG="$TMP_DIR/agent.toml"
AGENT_DATA="$TMP_DIR/agent"
AGENT_LOG="$TMP_DIR/agent.log"
BUILD_LOG="$TMP_DIR/build.log"
INIT_LOG="$TMP_DIR/init.log"
CERT_INFO_OUT="$TMP_DIR/cert-info.out"
RENEW_OUT="$TMP_DIR/renew.out"
ROTATE_OUT="$TMP_DIR/rotate.out"
SYSTEM_JSON="$TMP_DIR/system.json"
SYSTEM_ERR="$TMP_DIR/system.err"
SNAPSHOT_DIR="$TMP_DIR/snapshots"
FAULT_DIR="$TMP_DIR/fault"
mkdir -p "$SNAPSHOT_DIR"

CASE_HUB_PID=""
CASE_DIR=""
CASE_CFG=""
CASE_DATA=""
CASE_CERT_DIR=""
CASE_CA=""
CASE_AGENT_PORT=""
CASE_ADMIN_URL=""
LAST_RC=0
LAST_TIMED_OUT=0
S1_BAK_BEFORE=0
S1_BAK_AFTER_ROTATE=0
S1_BAK_AFTER_RUN=0

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
    echo "===== cert-rotation e2e 失败现场 =====" >&2
    for log in "$HUB_LOG" "$AGENT_LOG" "$INIT_LOG" "$BUILD_LOG" \
               "$CERT_INFO_OUT" "$RENEW_OUT" "$ROTATE_OUT" "$SYSTEM_ERR"; do
      if [[ -s "$log" ]]; then
        echo "---- $(basename "$log") (tail -n 120) ----" >&2
        tail -n 120 "$log" >&2 || true
      fi
    done
    for log in "$FAULT_DIR"/*/*.log; do
      [[ -e "$log" ]] || continue
      if [[ -s "$log" ]]; then
        echo "---- ${log#"$TMP_DIR"/} (tail -n 120) ----" >&2
        tail -n 120 "$log" >&2 || true
      fi
    done
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

for tool in "$PYTHON" "$CARGO" timeout stat mktemp date tail awk sed grep find sleep; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "找不到命令: $tool（python3 需 3.8+；cargo 请放进 PATH 或设置 CARGO=...）"
done

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

# 可选字符串字段：不存在时输出空串（用于兼容 M2 才引入的 admin_token）。
cfg_str_optional() {
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
if len(values) > 1:
    print(f"配置 {path} 中 {key} 出现 {len(values)} 次（期望 0 或 1 次）", file=sys.stderr)
    raise SystemExit(1)
print(values[0] if values else "")
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

# 证书指纹：PEM -> DER -> SHA-256。与 rustboard-hub ports 的输出一致。
cert_fpr() {
  "$PYTHON" - "$1" <<'PY'
import hashlib
import ssl
import sys

path = sys.argv[1]
try:
    with open(path, encoding="ascii") as handle:
        pem = handle.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
except Exception as exc:
    print(f"解析证书失败 {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)
print(hashlib.sha256(der).hexdigest())
PY
}

# 证书 notAfter（Unix 秒）。
cert_not_after() {
  "$PYTHON" - "$1" <<'PY'
import ssl
import sys

path = sys.argv[1]
try:
    decoded = ssl._ssl._test_decode_cert(path)
    print(int(ssl.cert_time_to_seconds(str(decoded["notAfter"]))))
except Exception as exc:
    print(f"解析证书 notAfter 失败 {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
}

# 输出 {"sha256": ..., "not_after": ...}，用于轮换前后对比。
cert_meta() {
  "$PYTHON" - "$1" <<'PY'
import hashlib
import json
import ssl
import sys

path = sys.argv[1]
try:
    with open(path, encoding="ascii") as handle:
        pem = handle.read()
    der = ssl.PEM_cert_to_DER_cert(pem)
    decoded = ssl._ssl._test_decode_cert(path)
    not_after = int(ssl.cert_time_to_seconds(str(decoded["notAfter"])))
except Exception as exc:
    print(f"解析证书失败 {path}: {exc}", file=sys.stderr)
    raise SystemExit(1)
print(json.dumps({
    "sha256": hashlib.sha256(der).hexdigest(),
    "not_after": not_after,
}))
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

http_json() {
  "$PYTHON" - "$1" <<'PY'
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
  "$PYTHON" - "$ADMIN_URL/healthz" <<'PY' >/dev/null 2>&1
import sys
import urllib.request

try:
    with urllib.request.urlopen(sys.argv[1], timeout=0.5) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
}

agent_status() {
  "$PYTHON" - "$ADMIN_URL/api/v1/agents" "${A_ID:-}" <<'PY'
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
  "$PYTHON" - "$ADMIN_URL" "$A_ID" <<'PY'
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
    sleep 0.2
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
    sleep 0.2
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

# 从命令输出中提取所有 64 位十六进制串（去重、转小写）。
hex64_set() {
  "$PYTHON" - "$1" <<'PY'
import re
import sys

with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
    text = handle.read()
values = sorted({
    match.group(0).lower()
    for match in re.finditer(r'(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])', text)
})
print("\n".join(values))
PY
}

# 解析 cert-info 的输出。优先按 JSON 解析，失败再按文本解析；
# 两种格式都必须能看出 agent.crt 路径、CN、notAfter、剩余天数。
parse_cert_info() {
  "$PYTHON" - "$1" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8", errors="replace") as handle:
    text = handle.read()


def first_line(pattern):
    for line in text.splitlines():
        if re.search(pattern, line, re.I):
            return line
    return ""


def date_fields(value):
    if isinstance(value, bool):
        return None, None
    if isinstance(value, (int, float)):
        return None, int(value)
    if isinstance(value, str):
        match = re.search(r'(\d{4}-\d{2}-\d{2})', value)
        if match:
            return match.group(1), None
        match = re.search(r'\b(1[0-9]{9})\b', value)
        if match:
            return None, int(match.group(1))
    return None, None


cn = None
has_not_after = False
not_after_iso = None
not_after_unix = None
days = None
path_ok = bool(re.search(r'agent\.crt', text))

try:
    payload = json.loads(text)
except Exception:
    payload = None

if isinstance(payload, dict):
    def pick(*keys):
        for key in keys:
            if key in payload and payload[key] is not None:
                return payload[key]
        return None

    cn_value = pick("cn", "CN", "common_name", "commonName")
    if isinstance(cn_value, str):
        cn = cn_value.strip().strip("\"'")

    not_after_value = pick("not_after", "notAfter", "not_after_unix", "notAfterUnix")
    if not_after_value is not None:
        has_not_after = True
        not_after_iso, not_after_unix = date_fields(not_after_value)

    days_value = pick("days_left", "daysLeft", "remaining_days", "remainingDays", "days")
    if isinstance(days_value, bool):
        days = None
    elif isinstance(days_value, (int, float)):
        days = int(days_value)
    elif isinstance(days_value, str) and re.match(r'\s*\d+', days_value):
        days = int(re.match(r'\s*(\d+)', days_value).group(1))

    path_value = pick("path", "cert_path", "certPath")
    if isinstance(path_value, str) and "agent.crt" in path_value:
        path_ok = True

# 文本格式（或 JSON 缺字段时）兜底。
if cn is None:
    match = re.search(r'(?i)\bCN\s*=\s*([^,\s]+)', text)
    if not match:
        match = re.search(r'(?i)\bCN\b\s*[:：]\s*["\']?([^"\'\s,]+)', text)
    if not match:
        match = re.search(r'(?i)\bcommon\s*name\b\s*[:：=]\s*([^,\s]+)', text)
    if match:
        cn = match.group(1).strip("\"'")

if not has_not_after:
    not_after_line = first_line(r'not[_-]?after|到期时间|过期时间')
    has_not_after = bool(not_after_line)
    if not_after_line:
        match = re.search(
            r'(\d{4}-\d{2}-\d{2})(?:[T ]\d{2}:\d{2}:\d{2})?', not_after_line
        )
        if match:
            not_after_iso = match.group(1)
        else:
            match = re.search(r'\b(1[0-9]{9})\b', not_after_line)
            if match:
                not_after_unix = int(match.group(1))

if days is None:
    days_line = first_line(r'剩余|remaining|days[ _-]?left')
    if days_line:
        match = re.search(
            r'(?i)(?:剩余|remaining|days[ _-]?left)[^0-9]{0,32}(\d+)', days_line
        )
        if not match:
            match = re.search(r'(\d+)', days_line)
        if match:
            days = int(match.group(1))

print(json.dumps({
    "path_ok": path_ok,
    "cn": cn,
    "has_not_after": has_not_after,
    "not_after_iso": not_after_iso,
    "not_after_unix": not_after_unix,
    "days": days,
}, ensure_ascii=False))
PY
}

write_agent_config() {
  mkdir -p "$AGENT_DATA"
  chmod 700 "$AGENT_DATA"
  cat > "$AGENT_CFG" <<EOF
hub_url = "wss://127.0.0.1:$AGENT_PORT/agent/ws"
token = "$TOKEN"
server_fingerprint = "$FPR_SERVER"
name = "e2e-rotation"
data_dir = "$AGENT_DATA"
sample_interval_ms = 1000
buffer_max_bytes = 10485760
EOF
  chmod 600 "$AGENT_CFG"
}

start_hub() {
  RUST_LOG=rustboard_hub=info "$HUB_BIN" run --config "$HUB_CFG" >> "$HUB_LOG" 2>&1 &
  HUB_PID=$!
  PIDS+=("$HUB_PID")
  wait_health 25
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
# 证书损坏/恢复场景用的小工具（每个 case 使用独立 config/data_dir/端口）
# ---------------------------------------------------------------------------

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

wait_health_url() {
  local url=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  while :; do
    if health_ok_url "$url"; then
      return 0
    fi
    if [[ -n "$CASE_HUB_PID" ]] && ! kill -0 "$CASE_HUB_PID" 2>/dev/null; then
      return 1
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

init_case_hub() {
  local dir=$1
  local agent_port admin_port

  mkdir -p "$dir"
  CASE_DIR=$dir
  CASE_CFG="$dir/hub.toml"
  CASE_DATA="$dir/data"
  CASE_CERT_DIR="$CASE_DATA/certs"
  CASE_CA="$CASE_CERT_DIR/ca.crt"

  agent_port=$(pick_port)
  admin_port=$(pick_port)
  while [[ "$admin_port" == "$agent_port" ]]; do
    admin_port=$(pick_port)
  done
  CASE_AGENT_PORT=$agent_port
  CASE_ADMIN_URL="http://127.0.0.1:$admin_port"

  "$HUB_BIN" init \
    --config "$CASE_CFG" \
    --data-dir "$CASE_DATA" \
    --agent-listen "127.0.0.1:$agent_port" \
    --admin-listen "127.0.0.1:$admin_port" \
    --force > "$dir/init.log" 2>&1 || return 1

  [[ -f "$CASE_CA" && -f "$CASE_CERT_DIR/server.crt" ]] || return 1
  return 0
}

start_case_hub() {
  local timeout=${1:-25}
  RUST_LOG=rustboard_hub=info "$HUB_BIN" run --config "$CASE_CFG" \
    >> "$CASE_DIR/hub.log" 2>&1 &
  CASE_HUB_PID=$!
  PIDS+=("$CASE_HUB_PID")
  wait_health_url "$CASE_ADMIN_URL/healthz" "$timeout"
}

stop_case_hub() {
  local pid=$CASE_HUB_PID
  CASE_HUB_PID=""
  [[ -n "$pid" ]] || return 0
  stop_pid "$pid" "case-hub" 10
}

case_hub_sanity() {
  local id=$1 label=$2
  if start_case_hub 25; then
    if stop_case_hub; then
      pass "$id" "$label"
    else
      fail "$id" "$label（停止失败）"
    fi
  else
    fail "$id" "$label（启动失败）"
    stop_case_hub || true
  fi
}

# 前台跑 hub run；LAST_RC/LAST_TIMED_OUT 供 check_hub_failure 使用。
# 124/137 表示进程一直运行到 timeout 被 TERM/KILL，属于“未在启动期失败”。
run_hub_expect_failure() {
  local cfg=$1 log=$2 timeout=${3:-12}
  local rc=0
  if RUST_LOG=rustboard_hub=info timeout -k 2 "$timeout" \
      "$HUB_BIN" run --config "$cfg" > "$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  LAST_RC=$rc
  if (( rc == 124 || rc == 137 )); then
    LAST_TIMED_OUT=1
  else
    LAST_TIMED_OUT=0
  fi
  return 0
}

check_hub_failure() {
  local id=$1 desc=$2
  if (( LAST_TIMED_OUT == 1 )); then
    fail "$id" "$desc（超时后仍在运行，rc=$LAST_RC）"
  elif (( LAST_RC == 0 )); then
    fail "$id" "$desc（退出码 0）"
  else
    pass "$id" "$desc（退出码 $LAST_RC）"
  fi
}

check_log_has() {
  local id=$1 log=$2 desc=$3 pattern=$4
  if [[ -s "$log" ]] && grep -Eiq -- "$pattern" "$log"; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（日志未匹配 /$pattern/：$log）"
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

count_bak() {
  local count
  count=$(find "$1" -maxdepth 1 -type f -name '*.bak-*' 2>/dev/null | wc -l) || true
  printf '%s' "${count//[[:space:]]/}"
}

list_bak() {
  find "$1" -maxdepth 1 -type f -name "$2" -printf '%f\n' 2>/dev/null | sort
}

tls_handshake_ok() {
  "$PYTHON" - "$1" "$2" "$3" <<'PY'
import socket
import ssl
import sys

host, port, ca = sys.argv[1], int(sys.argv[2]), sys.argv[3]
try:
    context = ssl.create_default_context(cafile=ca)
    with socket.create_connection((host, port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            if tls.version() is None:
                raise RuntimeError("TLS 版本为空")
except Exception as exc:
    print(f"TLS 握手失败: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
}

set_server_names_empty() {
  "$PYTHON" - "$1" <<'PY'
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    text = handle.read()
replacement, count = re.subn(
    r'(?ms)^server_names\s*=\s*\[.*?\]', 'server_names = []', text, count=1
)
if count != 1:
    print(f"无法在 {path} 找到 server_names 数组", file=sys.stderr)
    raise SystemExit(1)
with open(path, "w", encoding="utf-8") as handle:
    handle.write(replacement)
PY
}

# ---------------------------------------------------------------------------
# 构建与端口
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub / rustboard-agent（cargo build --bin ...）"
# 只构建本测试需要的两个 bin；panel 由其它路线并行开发，不应拖累本回归。
(cd "$ROOT" && "$CARGO" build --bin rustboard-hub --bin rustboard-agent) \
  > "$BUILD_LOG" 2>&1 \
  || die "cargo build --bin rustboard-hub --bin rustboard-agent 失败（日志: $BUILD_LOG）"

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
HUB_BIN="$TARGET_DIR/debug/rustboard-hub"
AGENT_BIN="$TARGET_DIR/debug/rustboard-agent"
[[ -x "$HUB_BIN" ]] || die "找不到可执行文件 $HUB_BIN"
[[ -x "$AGENT_BIN" ]] || die "找不到可执行文件 $AGENT_BIN"

AGENT_PORT=$(pick_port)
ADMIN_PORT=$(pick_port)
while [[ "$ADMIN_PORT" == "$AGENT_PORT" ]]; do
  ADMIN_PORT=$(pick_port)
done

echo
echo "==> 场景 1/12：hub init + 启动 hub + 纳管 agent（online 且样本增长）"

if "$HUB_BIN" init \
    --config "$HUB_CFG" \
    --data-dir "$HUB_DATA" \
    --agent-listen "127.0.0.1:$AGENT_PORT" \
    --admin-listen "127.0.0.1:$ADMIN_PORT" \
    --force > "$INIT_LOG" 2>&1; then
  pass "1.1" "hub init 成功（config=$HUB_CFG data_dir=$HUB_DATA）"
else
  die "hub init 失败（日志: $INIT_LOG）"
fi

[[ -f "$HUB_CFG" ]] || die "hub init 未生成配置: $HUB_CFG"

# 端口/路径一律从生成的 config 读取，而不是沿用脚本变量。
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

# M2 若已合入，管理 API 用 Bearer token；证书阶段没有这个字段则保持无鉴权。
ADMIN_TOKEN=$(cfg_str_optional "$HUB_CFG" admin_token) || die "无法解析可选 admin_token"
export RB_E2E_ADMIN_TOKEN="$ADMIN_TOKEN"
if [[ -n "$ADMIN_TOKEN" ]]; then
  echo "==> 管理 API 使用 admin_token 鉴权（token 不落日志）"
else
  echo "==> 管理 API 未配置 admin_token（当前证书阶段无鉴权）"
fi

# self_monitor 会引入 hub-self，干扰本测试的样本计数；采样间隔降到 1s 加快断言。
sed -i 's/^self_monitor = true$/self_monitor = false/' "$HUB_CFG"
sed -i 's/^sample_interval_ms = 5000$/sample_interval_ms = 1000/' "$HUB_CFG"
grep -q '^self_monitor = false' "$HUB_CFG" || die "无法关闭 hub 的 self_monitor"
grep -q '^sample_interval_ms = 1000' "$HUB_CFG" || die "无法调整 hub 采样间隔"

CA_CRT="$HUB_DATA/certs/ca.crt"
SERVER_CRT="$HUB_DATA/certs/server.crt"
SERVER_KEY="$HUB_DATA/certs/server.key"
[[ -f "$CA_CRT" && -f "$SERVER_CRT" && -f "$SERVER_KEY" ]] \
  || die "hub 证书文件不完整（$HUB_DATA/certs）"

FPR_SERVER=$(cert_fpr "$SERVER_CRT") || die "无法计算 server.crt 指纹"
FPR_PORTS=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p' || true)
check_eq "1.5" "hub ports 打印的指纹与磁盘 server.crt 一致" "$FPR_SERVER" "$FPR_PORTS"

# 先在 hub 未运行时写 DB，避免运维 CLI 与运行中的 hub 并发访问 SQLite。
echo "==> 生成一次性 token 并写 agent 配置"
TOKEN=$("$HUB_BIN" agent add --config "$HUB_CFG" --name "e2e-rotation" \
  | awk '/一次性 token/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print; exit}')
[[ "$TOKEN" =~ ^[0-9a-f]{64}$ ]] || die "无法从 agent add 输出解析 token: $TOKEN"
write_agent_config

echo "==> 启动 hub（agent=127.0.0.1:$AGENT_PORT admin=127.0.0.1:$ADMIN_PORT）"
if ! start_hub; then
  die "hub 未在 25s 内就绪（/healthz）"
fi
pass "1.6" "hub /healthz 就绪"

echo "==> 启动 agent 并等待 enrollment"
start_agent
if ! wait_for_file "$AGENT_DATA/agent_id" 30; then
  die "agent 未在 30s 内完成 enrollment"
fi
if ! wait_for_file "$AGENT_DATA/agent.crt" 10; then
  die "agent 未在 10s 内写入 agent.crt"
fi
if ! wait_for_file "$AGENT_DATA/agent.key" 10; then
  die "agent 未在 10s 内写入 agent.key"
fi
A_ID=$(tr -d '[:space:]' < "$AGENT_DATA/agent_id")
AGENT_SECRET=$(tr -d '[:space:]' < "$AGENT_DATA/agent.secret")
[[ -n "$A_ID" && -n "$AGENT_SECRET" ]] || die "agent_id / agent.secret 为空"

check_mode "1.7" "$AGENT_DATA" "700"
check_mode "1.8" "$AGENT_DATA/agent.key" "600"
check_mode "1.9" "$AGENT_DATA/agent.crt" "644"
if [[ -f "$AGENT_DATA/ca.crt" ]]; then
  pass "1.10" "enrollment 已把 ca.crt 写入 agent 数据目录"
else
  fail "1.10" "enrollment 未写入 ca.crt（CA 信任模式无法工作）：$AGENT_DATA/ca.crt"
fi

if wait_agent_status online 45; then
  pass "1.11" "agent 状态为 online（agent_id=$A_ID）"
else
  fail "1.11" "agent 未在 45s 内 online（最后状态: $LAST_STATUS）"
  die "无法继续：agent 未上线"
fi

if wait_series_min 1 30; then
  pass "1.12" "agent 开始上报样本（已入库 ≥1 行）"
else
  fail "1.12" "agent 未在 30s 内上报任何样本（last=$LAST_STATUS）"
  die "无法继续：没有样本"
fi
COUNT_1=$(series_count 2>/dev/null || echo 0)
if wait_series_min $((COUNT_1 + 2)) 20; then
  pass "1.13" "样本数持续增长（从 $COUNT_1 继续增加）"
else
  fail "1.13" "样本数未继续增长（基线 $COUNT_1，last=$LAST_STATUS）"
fi

# ---------------------------------------------------------------------------
# 场景 2：cert-info
# ---------------------------------------------------------------------------

echo
echo "==> 场景 2/12：rustboard-agent cert-info"

AGENT_CERT="$AGENT_DATA/agent.crt"
AGENT_KEY="$AGENT_DATA/agent.key"
cert_meta "$AGENT_CERT" > "$SNAPSHOT_DIR/agent-cert-before.json" \
  || die "无法解析轮换前的 agent.crt"
NA_BEFORE=$(json_get "$SNAPSHOT_DIR/agent-cert-before.json" not_after)
EXPECT_DAYS=$("$PYTHON" -c \
  'import sys,time; print(max(0, (int(sys.argv[1]) - int(time.time())) // 86400))' \
  "$NA_BEFORE")

if timeout 30 "$AGENT_BIN" cert-info --config "$AGENT_CFG" > "$CERT_INFO_OUT" 2>&1; then
  pass "2.1" "cert-info 退出码为 0"
  if parse_cert_info "$CERT_INFO_OUT" > "$SNAPSHOT_DIR/cert-info.json"; then
    CI_PATH_OK=$(json_get "$SNAPSHOT_DIR/cert-info.json" path_ok)
    CI_CN=$(json_get "$SNAPSHOT_DIR/cert-info.json" cn)
    CI_HAS_NA=$(json_get "$SNAPSHOT_DIR/cert-info.json" has_not_after)
    CI_NA_ISO=$(json_get "$SNAPSHOT_DIR/cert-info.json" not_after_iso)
    CI_NA_UNIX=$(json_get "$SNAPSHOT_DIR/cert-info.json" not_after_unix)
    CI_DAYS=$(json_get "$SNAPSHOT_DIR/cert-info.json" days)

    check_eq "2.2" "cert-info 输出包含 agent.crt 路径" "True" "$CI_PATH_OK"
    check_eq "2.3" "cert-info 输出的 CN 等于 agent_id" "$A_ID" "$CI_CN"
    check_eq "2.4" "cert-info 输出包含 notAfter（标签）" "True" "$CI_HAS_NA"

    if [[ "$CI_NA_ISO" != "None" && "$CI_NA_ISO" != "__MISSING__" ]]; then
      TODAY_UTC=$("$PYTHON" -c \
        'import datetime; print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d"))')
      if [[ "$CI_NA_ISO" > "$TODAY_UTC" || "$CI_NA_ISO" == "$TODAY_UTC" ]]; then
        pass "2.5" "cert-info 的 notAfter 日期合理（$CI_NA_ISO ≥ $TODAY_UTC）"
      else
        fail "2.5" "cert-info 的 notAfter 日期早于今天（$CI_NA_ISO < $TODAY_UTC）"
      fi
    elif [[ "$CI_NA_UNIX" != "None" && "$CI_NA_UNIX" != "__MISSING__" ]]; then
      NA_DELTA=$(( CI_NA_UNIX - NA_BEFORE ))
      if (( NA_DELTA < 0 )); then NA_DELTA=$(( -NA_DELTA )); fi
      if (( NA_DELTA <= 120 )); then
        pass "2.5" "cert-info 的 notAfter 时间戳与证书一致（差 ${NA_DELTA}s）"
      else
        fail "2.5" "cert-info 的 notAfter 时间戳与证书不一致（差 ${NA_DELTA}s，期望 ≤120s）"
      fi
    else
      fail "2.5" "cert-info 的 notAfter 行里找不到日期或 Unix 时间戳：$(printf '%s' "$CERT_INFO_OUT" | grep -i 'not[_-]\?after' | head -n 1)"
    fi

    if [[ "$CI_DAYS" =~ ^[0-9]+$ ]]; then
      DAY_DIFF=$(( CI_DAYS - EXPECT_DAYS ))
      if (( DAY_DIFF < 0 )); then DAY_DIFF=$(( -DAY_DIFF )); fi
      if (( DAY_DIFF <= 1 )); then
        pass "2.6" "cert-info 剩余天数与证书一致（输出 $CI_DAYS，期望约 $EXPECT_DAYS）"
      else
        fail "2.6" "cert-info 剩余天数偏差过大（输出 $CI_DAYS，期望约 $EXPECT_DAYS，允许 ±1）"
      fi
    else
      fail "2.6" "cert-info 未输出可解析的剩余天数（输出: $CI_DAYS）"
    fi
  else
    fail "2.2" "无法解析 cert-info 输出（见 $CERT_INFO_OUT）"
  fi
else
  fail "2.1" "cert-info 退出码非 0"
  tail -n 40 "$CERT_INFO_OUT" >&2 || true
fi

# ---------------------------------------------------------------------------
# 场景 3：renew
# ---------------------------------------------------------------------------

echo
echo "==> 场景 3/12：rustboard-agent renew（换证书、复用私钥、重启后继续上报）"

A_ID_BEFORE=$(tr -d '[:space:]' < "$AGENT_DATA/agent_id")
SECRET_BEFORE=$(file_sha256 "$AGENT_DATA/agent.secret")
CERT_HASH_BEFORE=$(file_sha256 "$AGENT_CERT")
KEY_HASH_BEFORE=$(file_sha256 "$AGENT_KEY")
NA_BEFORE=$(cert_not_after "$AGENT_CERT") || die "无法读取轮换前 notAfter"

if stop_pid "$A_PID" "agent" 5; then
  pass "3.1" "renew 前已停止运行中的 agent（避免并发写证书）"
else
  fail "3.1" "无法停止运行中的 agent"
  die "agent 未停止，无法安全地执行 renew"
fi
A_PID=""

RENEW_OK=0
if timeout 60 "$AGENT_BIN" renew --config "$AGENT_CFG" > "$RENEW_OUT" 2>&1; then
  pass "3.2" "renew 退出码为 0"
  RENEW_OK=1
else
  fail "3.2" "renew 退出码非 0（或 60s 超时）"
  tail -n 40 "$RENEW_OUT" >&2 || true
fi

if (( RENEW_OK == 1 )); then
  CERT_HASH_AFTER=$(file_sha256 "$AGENT_CERT")
  KEY_HASH_AFTER=$(file_sha256 "$AGENT_KEY")
  NA_AFTER=$(cert_not_after "$AGENT_CERT") || die "无法读取轮换后 notAfter"

  if [[ "$CERT_HASH_AFTER" != "$CERT_HASH_BEFORE" ]]; then
    pass "3.3" "renew 后 agent.crt 内容变化（${CERT_HASH_BEFORE:0:12}… → ${CERT_HASH_AFTER:0:12}…）"
  else
    fail "3.3" "renew 后 agent.crt 未变化（sha256=$CERT_HASH_AFTER）"
  fi

  if (( NA_AFTER > NA_BEFORE )); then
    pass "3.4" "renew 后 notAfter 变大（$NA_BEFORE → $NA_AFTER）"
  else
    fail "3.4" "renew 后 notAfter 未变大（期望 > $NA_BEFORE，实际 $NA_AFTER）"
  fi

  if [[ "$KEY_HASH_AFTER" == "$KEY_HASH_BEFORE" ]]; then
    pass "3.5" "renew 复用原私钥（agent.key 未变化）"
  else
    fail "3.5" "renew 改动了 agent.key（应复用原私钥）"
  fi

  check_mode "3.6" "$AGENT_CERT" "644"
  check_mode "3.7" "$AGENT_KEY" "600"
fi

echo "==> 重启 agent 并确认仍在线、继续上报"
start_agent
if wait_agent_status online 45; then
  pass "3.8" "renew 后重启的 agent 仍为 online"
else
  fail "3.8" "renew 后重启的 agent 未在 45s 内 online（last=$LAST_STATUS）"
fi

A_ID_AFTER=$(tr -d '[:space:]' < "$AGENT_DATA/agent_id")
SECRET_AFTER=$(file_sha256 "$AGENT_DATA/agent.secret")
check_eq "3.9" "agent 重启未改变 agent_id" "$A_ID_BEFORE" "$A_ID_AFTER"
check_eq "3.10" "agent 重启未改变 agent.secret" "$SECRET_BEFORE" "$SECRET_AFTER"

if wait_series_min 1 30; then
  COUNT_3=$(series_count 2>/dev/null || echo 0)
  if wait_series_min $((COUNT_3 + 2)) 20; then
    pass "3.11" "renew 后 agent 继续上报（样本数从 $COUNT_3 继续增长）"
  else
    fail "3.11" "renew 后样本数未继续增长（基线 $COUNT_3，last=$LAST_STATUS）"
  fi
else
  fail "3.11" "renew 后 agent 未上报任何样本（last=$LAST_STATUS）"
fi

# ---------------------------------------------------------------------------
# 场景 4：stop hub → rotate-cert --force → start hub
# ---------------------------------------------------------------------------

echo
echo "==> 场景 4/12：停 hub → rotate-cert --force → 起 hub（agent 保持运行自动重连）"

COUNT_BEFORE_ROT=$(series_count 2>/dev/null || echo 0)
OLD_FPR=$(cert_fpr "$SERVER_CRT") || die "无法计算轮换前服务端指纹"
CA_HASH_BEFORE=$(file_sha256 "$CA_CRT")
A_PID_SC4=$A_PID
AGENT_ID_HASH_BEFORE=$(file_sha256 "$AGENT_DATA/agent_id")
AGENT_SECRET_HASH_BEFORE=$(file_sha256 "$AGENT_DATA/agent.secret")
AGENT_CA_HASH_BEFORE=$(file_sha256 "$AGENT_DATA/ca.crt" 2>/dev/null || echo "missing")

if stop_pid "$HUB_PID" "hub" 10; then
  pass "4.1" "hub 已停止（rotate-cert 期间 agent 保持运行）"
  HUB_PID=""
else
  fail "4.1" "hub 未能在 10s 内停止"
  die "hub 未停止，无法继续 rotate 场景"
fi

ROTATE_OK=0
if timeout 60 "$HUB_BIN" rotate-cert --config "$HUB_CFG" --force > "$ROTATE_OUT" 2>&1; then
  pass "4.2" "rotate-cert --force 退出码为 0"
  ROTATE_OK=1
else
  fail "4.2" "rotate-cert --force 退出码非 0（或 60s 超时）"
  tail -n 40 "$ROTATE_OUT" >&2 || true
fi

NEW_FPR=$(cert_fpr "$SERVER_CRT") || die "无法计算轮换后服务端指纹"

if (( ROTATE_OK == 1 )); then
  ROT_FPRS=$(hex64_set "$ROTATE_OUT")
  if grep -Fxq "$OLD_FPR" <<< "$ROT_FPRS" && grep -Fxq "$NEW_FPR" <<< "$ROT_FPRS"; then
    pass "4.3" "rotate-cert 打印了新旧两个指纹"
  else
    fail "4.3" "rotate-cert 未同时打印新旧指纹（旧=$OLD_FPR 新=$NEW_FPR；输出中的指纹: ${ROT_FPRS:-<无>}）"
  fi

  if [[ "$NEW_FPR" != "$OLD_FPR" ]]; then
    pass "4.4" "rotate-cert 后服务端指纹变化（${OLD_FPR:0:12}… → ${NEW_FPR:0:12}…）"
  else
    fail "4.4" "rotate-cert 后服务端指纹未变化（$NEW_FPR）"
  fi

  CA_HASH_AFTER=$(file_sha256 "$CA_CRT")
  check_eq "4.5" "rotate-cert 未更换 CA（ca.crt 内容不变）" \
    "$CA_HASH_BEFORE" "$CA_HASH_AFTER"
  check_mode "4.6" "$SERVER_CRT" "644"
  check_mode "4.7" "$SERVER_KEY" "600"
fi

echo "==> 重新启动 hub"
if ! start_hub; then
  fail "4.8" "hub 重启后未在 25s 内就绪（/healthz）"
  die "hub 重启失败"
fi
pass "4.8" "hub 重启并 /healthz 就绪"

if kill -0 "$A_PID" 2>/dev/null && [[ "$A_PID" == "$A_PID_SC4" ]]; then
  pass "4.9" "agent 进程始终未重启（pid=$A_PID）"
else
  fail "4.9" "agent 进程不是 rotate 前的那个（before=$A_PID_SC4 after=$A_PID）"
fi

if wait_agent_status online 90; then
  pass "4.10" "agent 在服务端证书轮换后自动重连为 online（无需重新纳管）"
else
  fail "4.10" "agent 未在 90s 内自动重连（last=$LAST_STATUS）"
fi

AGENT_ID_HASH_AFTER=$(file_sha256 "$AGENT_DATA/agent_id")
AGENT_SECRET_HASH_AFTER=$(file_sha256 "$AGENT_DATA/agent.secret")
AGENT_CA_HASH_AFTER=$(file_sha256 "$AGENT_DATA/ca.crt" 2>/dev/null || echo "missing")
check_eq "4.11" "重连后 agent_id 未变化（未重新 enrollment）" \
  "$AGENT_ID_HASH_BEFORE" "$AGENT_ID_HASH_AFTER"
check_eq "4.12" "重连后 agent.secret 未变化（未重新 enrollment）" \
  "$AGENT_SECRET_HASH_BEFORE" "$AGENT_SECRET_HASH_AFTER"
check_eq "4.13" "重连后 agent 端 ca.crt 未变化" \
  "$AGENT_CA_HASH_BEFORE" "$AGENT_CA_HASH_AFTER"

if AGENT_COUNT=$(agents_len 2>/dev/null); then
  check_eq "4.14" "hub 中仍然只有这一台 agent（未新增纳管记录）" "1" "$AGENT_COUNT"
else
  fail "4.14" "无法读取 /api/v1/agents 统计 agent 数量"
fi

if wait_series_min $((COUNT_BEFORE_ROT + 2)) 60; then
  pass "4.15" "证书轮换+重连后样本数继续增长（基线 $COUNT_BEFORE_ROT）"
else
  COUNT_NOW=$(series_count 2>/dev/null || echo "unavailable")
  fail "4.15" "样本数未在 60s 内继续增长（基线 $COUNT_BEFORE_ROT，当前 $COUNT_NOW，last=$LAST_STATUS）"
fi

# ---------------------------------------------------------------------------
# 场景 5：/api/v1/system 指纹
# ---------------------------------------------------------------------------

echo
echo "==> 场景 5/12：GET /api/v1/system 的 fingerprint 与磁盘 server.crt 一致"

if http_json "$ADMIN_URL/api/v1/system" > "$SYSTEM_JSON" 2> "$SYSTEM_ERR"; then
  SYS_FPR=$(json_get "$SYSTEM_JSON" "cert.fingerprint")
  DISK_FPR=$(cert_fpr "$SERVER_CRT") || die "无法计算磁盘 server.crt 指纹"
  PORTS_FPR=$("$HUB_BIN" ports --config "$HUB_CFG" | sed -n 's/^证书指纹: //p' || true)

  if [[ "$SYS_FPR" =~ ^[0-9a-f]{64}$ ]]; then
    pass "5.1" "/api/v1/system 返回 64 位十六进制 fingerprint"
  else
    fail "5.1" "/api/v1/system 的 cert.fingerprint 格式不合法：$SYS_FPR"
  fi

  check_eq "5.2" "/api/v1/system 指纹与磁盘 server.crt（DER SHA-256）一致" \
    "$DISK_FPR" "$SYS_FPR"
  check_eq "5.3" "/api/v1/system 指纹与 hub ports 输出一致" \
    "$PORTS_FPR" "$SYS_FPR"
else
  fail "5.1" "GET /api/v1/system 失败"
  tail -n 40 "$SYSTEM_ERR" >&2 || true
fi

# ---------------------------------------------------------------------------
# 阶段 2：证书损坏 / 恢复 / 备份（S1–S7，每个场景独立实例）
# ---------------------------------------------------------------------------

# 主实例收尾：后续场景使用独立的 config/data_dir/端口，互不影响。
if [[ -n "$A_PID" ]]; then
  stop_pid "$A_PID" "agent" 5 || true
  A_PID=""
fi
if [[ -n "$HUB_PID" ]]; then
  stop_pid "$HUB_PID" "hub" 10 || true
  HUB_PID=""
fi

# --- S1: ca.key 与 ca.crt 不匹配 ------------------------------------------
echo
echo "==> 场景 6/12（S1）：ca.key 换成另一套 CA 的私钥"

init_case_hub "$FAULT_DIR/s1-other" || die "S1 另一套 CA 初始化失败"
cp "$CASE_CERT_DIR/ca.key" "$FAULT_DIR/other-ca.key"
chmod 600 "$FAULT_DIR/other-ca.key"

init_case_hub "$FAULT_DIR/s1" || die "S1 实例初始化失败"
S1_DIR=$CASE_DIR
S1_CFG=$CASE_CFG
S1_DATA=$CASE_DATA
S1_CERT_DIR=$CASE_CERT_DIR
S1_CA=$CASE_CA
S1_AGENT_PORT=$CASE_AGENT_PORT
case_hub_sanity "S1.1" "S1 初始 CA/服务端证书可正常启动"

S1_CRT_BEFORE=$(file_sha256 "$S1_CERT_DIR/server.crt")
S1_KEY_BEFORE=$(file_sha256 "$S1_CERT_DIR/server.key")
S1_BAK_BEFORE=$(count_bak "$S1_CERT_DIR")

cp "$FAULT_DIR/other-ca.key" "$S1_CERT_DIR/ca.key"
chmod 600 "$S1_CERT_DIR/ca.key"

if timeout -k 2 30 "$HUB_BIN" rotate-cert --config "$S1_CFG" --force \
    > "$S1_DIR/rotate-fail.log" 2>&1; then
  LAST_RC=0
else
  LAST_RC=$?
fi
if (( LAST_RC == 124 || LAST_RC == 137 )); then LAST_TIMED_OUT=1; else LAST_TIMED_OUT=0; fi
check_hub_failure "S1.2" "ca.key 不匹配时 rotate-cert --force 非零退出"

S1_CRT_AFTER_ROTATE=$(file_sha256 "$S1_CERT_DIR/server.crt" 2>/dev/null || echo missing)
check_eq "S1.3" "rotate-cert 失败后 server.crt 哈希不变" \
  "$S1_CRT_BEFORE" "$S1_CRT_AFTER_ROTATE"
S1_BAK_AFTER_ROTATE=$(count_bak "$S1_CERT_DIR")

run_hub_expect_failure "$S1_CFG" "$S1_DIR/hub-fail.log" 12
check_hub_failure "S1.4" "ca.key 不匹配时 hub run 非零退出且未持续运行"

S1_CRT_AFTER_RUN=$(file_sha256 "$S1_CERT_DIR/server.crt" 2>/dev/null || echo missing)
S1_KEY_AFTER_RUN=$(file_sha256 "$S1_CERT_DIR/server.key" 2>/dev/null || echo missing)
check_eq "S1.5" "hub run 失败后 server.crt 哈希不变" \
  "$S1_CRT_BEFORE" "$S1_CRT_AFTER_RUN"
check_eq "S1.6" "hub run 失败后 server.key 哈希不变" \
  "$S1_KEY_BEFORE" "$S1_KEY_AFTER_RUN"
check_log_has "S1.7" "$S1_DIR/hub-fail.log" \
  "hub 失败信息可操作（提到 CA/证书/修复/init）" \
  'ca\.key|CA[ _-]?(?:key|私钥|证书|cert|material|材料)|CA.*(?:无效|不完整|不一致|invalid)|私钥|不匹配|mismatch|does not match|key\s*pair|修复|init'
check_no_panic "S1.8" "$S1_DIR/hub-fail.log" \
  "hub 失败信息不是 panic"
S1_BAK_AFTER_RUN=$(count_bak "$S1_CERT_DIR")

# --- S2: 删除 ca.key ------------------------------------------------------
echo
echo "==> 场景 7/12（S2）：删除 ca.key（保留 ca.crt）"

init_case_hub "$FAULT_DIR/s2" || die "S2 实例初始化失败"
S2_DIR=$CASE_DIR
S2_CFG=$CASE_CFG
S2_DATA=$CASE_DATA
S2_CERT_DIR=$CASE_CERT_DIR
S2_CA=$CASE_CA
case_hub_sanity "S2.1" "S2 初始材料可正常启动"

S2_CA_HASH=$(file_sha256 "$S2_CERT_DIR/ca.crt")
S2_CRT_BEFORE=$(file_sha256 "$S2_CERT_DIR/server.crt")
S2_KEY_BEFORE=$(file_sha256 "$S2_CERT_DIR/server.key")
rm -f "$S2_CERT_DIR/ca.key"

run_hub_expect_failure "$S2_CFG" "$S2_DIR/hub-fail.log" 12
check_hub_failure "S2.2" "删除 ca.key 后 hub run 非零退出且未持续运行"
S2_CRT_AFTER=$(file_sha256 "$S2_CERT_DIR/server.crt" 2>/dev/null || echo missing)
S2_KEY_AFTER=$(file_sha256 "$S2_CERT_DIR/server.key" 2>/dev/null || echo missing)
check_eq "S2.3" "删除 ca.key 后 hub run 不修改 server.crt" \
  "$S2_CRT_BEFORE" "$S2_CRT_AFTER"
check_eq "S2.4" "删除 ca.key 后 hub run 不修改 server.key" \
  "$S2_KEY_BEFORE" "$S2_KEY_AFTER"

if timeout -k 2 30 "$HUB_BIN" init --config "$S2_CFG" --data-dir "$S2_DATA" --force \
    > "$S2_DIR/init-force.log" 2>&1; then
  S2_INIT_RC=0
else
  S2_INIT_RC=$?
fi
if (( S2_INIT_RC == 124 || S2_INIT_RC == 137 )); then
  fail "S2.5" "init --force 未在 30s 内返回（rc=$S2_INIT_RC）"
else
  pass "S2.5" "init --force 已返回（rc=$S2_INIT_RC；允许明确拒绝）"
fi
S2_CA_AFTER=$(file_sha256 "$S2_CERT_DIR/ca.crt" 2>/dev/null || echo missing)
check_eq "S2.6" "init --force 未静默覆盖 ca.crt" "$S2_CA_HASH" "$S2_CA_AFTER"

# --- S3: ca.crt 是垃圾 ----------------------------------------------------
echo
echo "==> 场景 8/12（S3）：ca.crt 写成垃圾内容"

init_case_hub "$FAULT_DIR/s3" || die "S3 实例初始化失败"
S3_DIR=$CASE_DIR
S3_CFG=$CASE_CFG
S3_DATA=$CASE_DATA
S3_CERT_DIR=$CASE_CERT_DIR
S3_CA=$CASE_CA
case_hub_sanity "S3.1" "S3 初始材料可正常启动"

cp "$S3_CERT_DIR/ca.crt" "$S3_DIR/ca.crt.orig"
chmod 600 "$S3_DIR/ca.crt.orig"
S3_CRT_BEFORE=$(file_sha256 "$S3_CERT_DIR/server.crt")
S3_KEY_BEFORE=$(file_sha256 "$S3_CERT_DIR/server.key")
S3_BAK_BEFORE=$(count_bak "$S3_CERT_DIR")

printf 'this is not a certificate\n' > "$S3_CERT_DIR/ca.crt"
chmod 644 "$S3_CERT_DIR/ca.crt"
S3_GARBAGE_HASH=$(file_sha256 "$S3_CERT_DIR/ca.crt")

run_hub_expect_failure "$S3_CFG" "$S3_DIR/hub-fail1.log" 12
check_hub_failure "S3.2" "垃圾 ca.crt 第 1 次 hub run 非零退出且未持续运行"
S3_CRT_1=$(file_sha256 "$S3_CERT_DIR/server.crt" 2>/dev/null || echo missing)
S3_KEY_1=$(file_sha256 "$S3_CERT_DIR/server.key" 2>/dev/null || echo missing)
check_eq "S3.3" "第 1 次失败后 server.crt 哈希不变" "$S3_CRT_BEFORE" "$S3_CRT_1"
check_eq "S3.4" "第 1 次失败后 server.key 哈希不变" "$S3_KEY_BEFORE" "$S3_KEY_1"

run_hub_expect_failure "$S3_CFG" "$S3_DIR/hub-fail2.log" 12
check_hub_failure "S3.5" "垃圾 ca.crt 第 2 次 hub run 非零退出且未持续运行"
S3_CRT_2=$(file_sha256 "$S3_CERT_DIR/server.crt" 2>/dev/null || echo missing)
S3_KEY_2=$(file_sha256 "$S3_CERT_DIR/server.key" 2>/dev/null || echo missing)
check_eq "S3.6" "第 2 次失败后 server.crt 哈希不变" "$S3_CRT_BEFORE" "$S3_CRT_2"
check_eq "S3.7" "第 2 次失败后 server.key 哈希不变" "$S3_KEY_BEFORE" "$S3_KEY_2"
S3_BAK_AFTER=$(count_bak "$S3_CERT_DIR")
check_eq "S3.8" "两次失败后无新增 *.bak-*" "$S3_BAK_BEFORE" "$S3_BAK_AFTER"
S3_CA_AFTER=$(file_sha256 "$S3_CERT_DIR/ca.crt" 2>/dev/null || echo missing)
check_eq "S3.9" "两次失败后 ca.crt 仍为原垃圾内容" "$S3_GARBAGE_HASH" "$S3_CA_AFTER"

cp "$S3_DIR/ca.crt.orig" "$S3_CERT_DIR/ca.crt"
chmod 644 "$S3_CERT_DIR/ca.crt"
if start_case_hub 25; then
  if stop_case_hub; then
    pass "S3.10" "恢复 ca.crt 后 hub 能启动"
  else
    fail "S3.10" "恢复 ca.crt 后 hub 启动成功但停止失败"
  fi
else
  fail "S3.10" "恢复 ca.crt 后 hub 未能启动"
  stop_case_hub || true
fi

# --- S4: 删除 server.crt --------------------------------------------------
echo
echo "==> 场景 9/12（S4）：删除 server.crt（保留 CA 与 server.key）"

init_case_hub "$FAULT_DIR/s4" || die "S4 实例初始化失败"
S4_DIR=$CASE_DIR
S4_CFG=$CASE_CFG
S4_DATA=$CASE_DATA
S4_CERT_DIR=$CASE_CERT_DIR
S4_CA=$CASE_CA
case_hub_sanity "S4.1" "S4 初始材料可正常启动"

S4_KEY_BEFORE=$(file_sha256 "$S4_CERT_DIR/server.key")
rm -f "$S4_CERT_DIR/server.crt"

if start_case_hub 25; then
  pass "S4.2" "删除 server.crt 后 hub 自动补签并启动"
  S4_WAIT_DEADLINE=$(( $(date +%s%3N) + 10000 ))
  while [[ ! -s "$S4_CERT_DIR/server.crt" ]] \
      && (( $(date +%s%3N) < S4_WAIT_DEADLINE )); do
    sleep 0.1
  done
  while [[ -z "$(list_bak "$S4_CERT_DIR" 'server.key.bak-*')" ]] \
      && (( $(date +%s%3N) < S4_WAIT_DEADLINE )); do
    sleep 0.1
  done
  if [[ -s "$S4_CERT_DIR/server.crt" ]]; then
    pass "S4.3" "自动补签生成了 server.crt"
  else
    fail "S4.3" "hub 启动了但 server.crt 未生成"
  fi

  S4_KEY_BAK_MATCH=0
  while IFS= read -r bak; do
    [[ -n "$bak" ]] || continue
    bak_hash=$(file_sha256 "$S4_CERT_DIR/$bak" 2>/dev/null || true)
    if [[ "$bak_hash" == "$S4_KEY_BEFORE" ]]; then
      S4_KEY_BAK_MATCH=1
    fi
  done < <(list_bak "$S4_CERT_DIR" 'server.key.bak-*')
  check_eq "S4.4" "旧 server.key 有内容匹配的备份" "1" "$S4_KEY_BAK_MATCH"

  S4_CRT_HASH_1=$(file_sha256 "$S4_CERT_DIR/server.crt" 2>/dev/null || echo missing)
  S4_KEY_HASH_1=$(file_sha256 "$S4_CERT_DIR/server.key" 2>/dev/null || echo missing)
  S4_BAK_1=$(count_bak "$S4_CERT_DIR")
  if stop_case_hub; then
    pass "S4.5" "自动补签后的 hub 已停止"
  else
    fail "S4.5" "自动补签后的 hub 停止失败"
  fi

  if start_case_hub 25; then
    if stop_case_hub; then
      pass "S4.6" "第二次启动成功"
    else
      fail "S4.6" "第二次启动成功但停止失败"
    fi
    S4_CRT_HASH_2=$(file_sha256 "$S4_CERT_DIR/server.crt" 2>/dev/null || echo missing)
    S4_KEY_HASH_2=$(file_sha256 "$S4_CERT_DIR/server.key" 2>/dev/null || echo missing)
    S4_BAK_2=$(count_bak "$S4_CERT_DIR")
    check_eq "S4.7" "第二次启动不再重签 server.crt" "$S4_CRT_HASH_1" "$S4_CRT_HASH_2"
    check_eq "S4.8" "第二次启动不再重签 server.key" "$S4_KEY_HASH_1" "$S4_KEY_HASH_2"
    check_eq "S4.9" "第二次启动不再新增备份" "$S4_BAK_1" "$S4_BAK_2"
  else
    fail "S4.6" "第二次启动失败"
    stop_case_hub || true
  fi
else
  fail "S4.2" "删除 server.crt 后 hub 未能自动补签启动"
  stop_case_hub || true
fi

# --- S5: server_names 为空 / init --san 非法 -----------------------------
echo
echo "==> 场景 10/12（S5）：server_names = [] 与 init --san \"bad name\""

init_case_hub "$FAULT_DIR/s5" || die "S5 实例初始化失败"
S5_DIR=$CASE_DIR
S5_CFG=$CASE_CFG
S5_DATA=$CASE_DATA
S5_CERT_DIR=$CASE_CERT_DIR
S5_CA=$CASE_CA
case_hub_sanity "S5.1" "S5 初始材料可正常启动"

set_server_names_empty "$S5_CFG" || die "S5 无法把 server_names 改为空数组"
run_hub_expect_failure "$S5_CFG" "$S5_DIR/hub-empty-names.log" 12
check_hub_failure "S5.2" "server_names = [] 时 hub run 在启动期失败"
check_log_has "S5.3" "$S5_DIR/hub-empty-names.log" \
  "空 server_names 的错误信息提到 server_names/SAN/证书" \
  'server[_ ]?names?|san|证书|域名|dns'
check_no_panic "S5.4" "$S5_DIR/hub-empty-names.log" \
  "空 server_names 失败不是 panic"

S5B_DIR="$FAULT_DIR/s5-bad-san"
S5B_CFG="$S5B_DIR/hub.toml"
S5B_DATA="$S5B_DIR/data"
mkdir -p "$S5B_DIR"
S5B_AGENT_PORT=$(pick_port)
S5B_ADMIN_PORT=$(pick_port)
while [[ "$S5B_ADMIN_PORT" == "$S5B_AGENT_PORT" ]]; do
  S5B_ADMIN_PORT=$(pick_port)
done
if timeout -k 2 20 "$HUB_BIN" init \
    --config "$S5B_CFG" \
    --data-dir "$S5B_DATA" \
    --agent-listen "127.0.0.1:$S5B_AGENT_PORT" \
    --admin-listen "127.0.0.1:$S5B_ADMIN_PORT" \
    --san "bad name" > "$S5B_DIR/init.log" 2>&1; then
  S5B_INIT_RC=0
else
  S5B_INIT_RC=$?
fi
if (( S5B_INIT_RC == 124 || S5B_INIT_RC == 137 )); then
  fail "S5.5" "init --san \"bad name\" 未在 20s 内返回（rc=$S5B_INIT_RC）"
elif (( S5B_INIT_RC == 0 )); then
  fail "S5.5" "init --san \"bad name\" 未拒绝非法 SAN"
else
  pass "S5.5" "init --san \"bad name\" 明确拒绝（rc=$S5B_INIT_RC）"
fi
S5B_CA_COUNT=0
if [[ -d "$S5B_DATA" ]]; then
  S5B_CA_COUNT=$(find "$S5B_DATA" -type f \
    \( -name 'ca.crt' -o -name 'ca.key' \) 2>/dev/null | wc -l) || S5B_CA_COUNT=0
  S5B_CA_COUNT=${S5B_CA_COUNT//[[:space:]]/}
fi
check_eq "S5.6" "非法 SAN 的 init 不留下新 CA" "0" "$S5B_CA_COUNT"
check_log_has "S5.7" "$S5B_DIR/init.log" \
  "非法 SAN 的拒绝信息明确提到 SAN/证书" \
  'san|server[_ ]?names?|证书|dns|bad name'

# --- S6: 正常 rotate-cert 的备份与恢复 -----------------------------------
echo
echo "==> 场景 11/12（S6）：正常 rotate-cert --force 的备份、权限、恢复握手"

init_case_hub "$FAULT_DIR/s6" || die "S6 实例初始化失败"
S6_DIR=$CASE_DIR
S6_CFG=$CASE_CFG
S6_DATA=$CASE_DATA
S6_CERT_DIR=$CASE_CERT_DIR
S6_CA=$CASE_CA
S6_AGENT_PORT=$CASE_AGENT_PORT
case_hub_sanity "S6.1" "S6 初始材料可正常启动"

S6_CRT_BEFORE=$(file_sha256 "$S6_CERT_DIR/server.crt")
S6_KEY_BEFORE=$(file_sha256 "$S6_CERT_DIR/server.key")
if timeout -k 2 30 "$HUB_BIN" rotate-cert --config "$S6_CFG" --force \
    > "$S6_DIR/rotate.log" 2>&1; then
  S6_ROTATE_RC=0
else
  S6_ROTATE_RC=$?
fi
if (( S6_ROTATE_RC == 0 )); then
  pass "S6.2" "正常 rotate-cert --force 退出码为 0"
else
  fail "S6.2" "正常 rotate-cert --force 退出码非 0（rc=$S6_ROTATE_RC）"
fi

S6_CRT_AFTER=$(file_sha256 "$S6_CERT_DIR/server.crt" 2>/dev/null || echo missing)
S6_KEY_AFTER=$(file_sha256 "$S6_CERT_DIR/server.key" 2>/dev/null || echo missing)
if [[ "$S6_CRT_AFTER" != "$S6_CRT_BEFORE" ]]; then
  pass "S6.3" "rotate-cert 后 server.crt 内容变化"
else
  fail "S6.3" "rotate-cert 后 server.crt 未变化"
fi

mapfile -t S6_CRT_BAKS < <(list_bak "$S6_CERT_DIR" 'server.crt.bak-*')
mapfile -t S6_KEY_BAKS < <(list_bak "$S6_CERT_DIR" 'server.key.bak-*')
if (( ${#S6_CRT_BAKS[@]} == 1 && ${#S6_KEY_BAKS[@]} == 1 )); then
  pass "S6.4" "rotate-cert 生成一对备份（crt/key 各 1 个）"

  S6_CRT_SUFFIX=${S6_CRT_BAKS[0]#server.crt.bak-}
  S6_KEY_SUFFIX=${S6_KEY_BAKS[0]#server.key.bak-}
  check_eq "S6.5" "备份 crt/key 的时间戳后缀成对" \
    "$S6_CRT_SUFFIX" "$S6_KEY_SUFFIX"

  S6_CRT_BAK="$S6_CERT_DIR/${S6_CRT_BAKS[0]}"
  S6_KEY_BAK="$S6_CERT_DIR/${S6_KEY_BAKS[0]}"
  check_mode "S6.6" "$S6_CRT_BAK" "644"
  check_mode "S6.7" "$S6_KEY_BAK" "600"
  check_eq "S6.8" "crt 备份内容是轮换前的 server.crt" \
    "$S6_CRT_BEFORE" "$(file_sha256 "$S6_CRT_BAK")"
  check_eq "S6.9" "key 备份内容是轮换前的 server.key" \
    "$S6_KEY_BEFORE" "$(file_sha256 "$S6_KEY_BAK")"

  cp "$S6_CRT_BAK" "$S6_CERT_DIR/server.crt"
  cp "$S6_KEY_BAK" "$S6_CERT_DIR/server.key"
  chmod 644 "$S6_CERT_DIR/server.crt"
  chmod 600 "$S6_CERT_DIR/server.key"
  check_eq "S6.10" "用备份恢复 server.crt 成功" \
    "$S6_CRT_BEFORE" "$(file_sha256 "$S6_CERT_DIR/server.crt")"
  check_eq "S6.11" "用备份恢复 server.key 成功" \
    "$S6_KEY_BEFORE" "$(file_sha256 "$S6_CERT_DIR/server.key")"

  if start_case_hub 25; then
    pass "S6.12" "恢复备份后 hub 能启动"
    if tls_handshake_ok "127.0.0.1" "$S6_AGENT_PORT" "$S6_CA"; then
      pass "S6.13" "恢复备份后 hub 能用恢复的证书完成 TLS 握手"
    else
      fail "S6.13" "恢复备份后 hub TLS 握手失败"
    fi
    stop_case_hub || true
  else
    fail "S6.12" "恢复备份后 hub 未能启动"
    stop_case_hub || true
  fi
else
  fail "S6.4" "rotate-cert 未生成成对备份（crt=${#S6_CRT_BAKS[@]} key=${#S6_KEY_BAKS[@]}）"
fi

# --- S7: S1 校验失败时零新增 bak -----------------------------------------
echo
echo "==> 场景 12/12（S7）：S1 失败路径零新增 *.bak-*"

check_eq "S7.1" "rotate-cert 校验失败后无新增 *.bak-*" \
  "$S1_BAK_BEFORE" "$S1_BAK_AFTER_ROTATE"
check_eq "S7.2" "hub run 校验失败后无新增 *.bak-*" \
  "$S1_BAK_BEFORE" "$S1_BAK_AFTER_RUN"

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

echo
if (( FAILS > 0 )); then
  echo "cert-rotation e2e 结果: PASS $PASSES，FAIL $FAILS" >&2
  exit 1
fi
echo "cert-rotation e2e 结果: 全部 $PASSES 项通过（PASS 数量: $PASSES）"
