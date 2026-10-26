#!/usr/bin/env bash
#
# Phase E S2：hub 级多 agent 压力 / 长稳编排。
#
# 真实启动 rustboard-hub（默认 SQLite），由 tests/load/hub_scale.py 完成
# TLS Enrollment → Hello → Batch/Ack，并输出 metrics.jsonl + summary.json。
#
# 用法：
#   bash tests/e2e/v100-load.sh AGENTS DURATION_SECS [--reconnect-every N] [--backend sqlite]
#
# 例：
#   bash tests/e2e/v100-load.sh 10 60
#   bash tests/e2e/v100-load.sh 200 600
#   bash tests/e2e/v100-load.sh 1000 600
#   bash tests/e2e/v100-load.sh 200 86400
#
# 说明：
# - 1000 agent / 24h 不进 CI，只手工运行；结果、日志、数据库都留在
#   target/load/<UTC 时间>-<N>a/ 下，成功失败都不自动删除。
# - 不打印 token / agent secret / 证书内容；hub init 输出里的 admin token
#   在证据目录内也会被替换为 [REDACTED]。
# - 本脚本只负责编排，不修改生产代码、协议、schema、Docker 或安装器。
#

set -euo pipefail
umask 077
# 复用 tests/e2e/probe.py 时不要改写仓库里已跟踪的 __pycache__/*.pyc。
export PYTHONDONTWRITEBYTECODE=1

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-}
INTERVAL_MS=${INTERVAL_MS:-5000}
WARMUP_SECS=${WARMUP_SECS:-}

HUB_PID=""
HUB_STOPPED=0
RUN_DIR=""

die() {
  echo "FATAL: $*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
用法: bash tests/e2e/v100-load.sh AGENTS DURATION_SECS [--reconnect-every N] [--backend sqlite]

  AGENTS           虚拟 agent 数（1–2048；1000 需要 5 个源 IP，工具自动分配）
  DURATION_SECS    barrier 后统一运行秒数；24h 用 86400
  --reconnect-every N  前 10% agent 每 ACK N 批主动断连重连（默认 0，不主动断）
  --backend sqlite     当前仅实现 SQLite；PG 校验接口待后续阶段

环境变量:
  HUB_BIN          覆盖 target/debug/rustboard-hub（设置后跳过 cargo build）
  CARGO            cargo 路径（默认从 PATH 或 ~/.cargo/bin 查找）
  PYTHON           默认 python3
  INTERVAL_MS      每 agent 发批间隔，默认 5000（需 < hub 空闲超时 45s）
  WARMUP_SECS      资源基线预热；默认 60s；duration >= 3600 时默认 600s
EOF
}

[[ $# -ge 2 ]] || { usage; exit 2; }
AGENTS=$1
DURATION_SECS=$2
shift 2
RECONNECT_EVERY=0
BACKEND=sqlite
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reconnect-every)
      [[ $# -ge 2 ]] || die "--reconnect-every 缺少参数"
      RECONNECT_EVERY=$2
      shift 2
      ;;
    --backend)
      [[ $# -ge 2 ]] || die "--backend 缺少参数"
      BACKEND=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "未知参数: $1"
      ;;
  esac
done

[[ "$AGENTS" =~ ^[0-9]+$ ]] || die "AGENTS 必须是正整数"
[[ "$DURATION_SECS" =~ ^[0-9]+$ ]] || die "DURATION_SECS 必须是正整数"
[[ "$RECONNECT_EVERY" =~ ^[0-9]+$ ]] || die "--reconnect-every 必须是非负整数"
[[ "$INTERVAL_MS" =~ ^[0-9]+$ ]] || die "INTERVAL_MS 必须是正整数"
(( AGENTS >= 1 && AGENTS <= 2048 )) || die "AGENTS 必须在 1–2048 之间"
# hub 的 max_connections 至少 2048；AGENTS 接近上限时留 256 条重连/管理余量。
MAX_CONNECTIONS=2048
if (( AGENTS + 256 > MAX_CONNECTIONS )); then
  MAX_CONNECTIONS=$(( AGENTS + 256 ))
fi
(( DURATION_SECS >= 1 )) || die "DURATION_SECS 必须 ≥1"
(( INTERVAL_MS >= 1000 && INTERVAL_MS <= 40000 )) \
  || die "INTERVAL_MS 必须在 1000–40000（hub 空闲超时 45s）"
[[ "$BACKEND" == "sqlite" ]] \
  || die "当前仅支持 --backend sqlite；PostgreSQL 校验接口见 tests/load/README.md"

if [[ -z "$WARMUP_SECS" ]]; then
  if (( DURATION_SECS >= 3600 )); then
    WARMUP_SECS=600
  else
    WARMUP_SECS=60
  fi
fi
[[ "$WARMUP_SECS" =~ ^[0-9]+$ ]] || die "WARMUP_SECS 必须是非负整数"

command -v "$PYTHON" >/dev/null 2>&1 || die "找不到 Python 解释器: $PYTHON"
command -v curl >/dev/null 2>&1 || die "找不到 curl"
command -v openssl >/dev/null 2>&1 || die "找不到 openssl"
command -v timeout >/dev/null 2>&1 || die "找不到 timeout"

if [[ -z "$CARGO" ]]; then
  if command -v cargo >/dev/null 2>&1; then
    CARGO=cargo
  elif [[ -x "${HOME:-/root}/.cargo/bin/cargo" ]]; then
    CARGO="${HOME:-/root}/.cargo/bin/cargo"
  fi
fi

# ---------------------------------------------------------------------------
# 运行目录 / 构建
# ---------------------------------------------------------------------------

STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR="$ROOT/target/load/${STAMP}-${AGENTS}a"
if [[ -e "$RUN_DIR" ]]; then
  RUN_DIR="${RUN_DIR}-${RANDOM}"
fi
[[ "$RUN_DIR" == "$ROOT/target/load/"* ]] || die "运行目录越界: $RUN_DIR"
mkdir -p -- "$RUN_DIR/config" "$RUN_DIR/data" "$RUN_DIR/out"
chmod 700 -- "$RUN_DIR" "$RUN_DIR/config" "$RUN_DIR/data" "$RUN_DIR/out"

CFG="$RUN_DIR/config/hub.toml"
DATA="$RUN_DIR/data"
OUT="$RUN_DIR/out"
HUB_LOG="$RUN_DIR/hub.log"
INIT_LOG="$RUN_DIR/init.log"
PY_LOG="$RUN_DIR/hub_scale.log"
SUMMARY="$OUT/summary.json"
CA="$DATA/certs/ca.crt"
DB="$DATA/rustboard.db"
# 管理 token 只写到 0600 临时文件，由 Python 读取后立即删除；绝不进入 argv。
ADMIN_TOKEN_FILE="$RUN_DIR/config/admin.token"

cleanup() {
  local code=$?
  trap - EXIT INT TERM
  if [[ -n "${HUB_PID:-}" && "$HUB_STOPPED" -eq 0 ]] \
     && kill -0 "$HUB_PID" 2>/dev/null; then
    kill -TERM "$HUB_PID" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$HUB_PID" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$HUB_PID" 2>/dev/null || true
    wait "$HUB_PID" 2>/dev/null || true
  fi
  # 仅清理本 run 目录内的临时 token 文件，不触碰其它目录；证据目录保留。
  if [[ -n "${RUN_DIR:-}" && -f "$RUN_DIR/config/admin.token" ]]; then
    rm -f -- "$RUN_DIR/config/admin.token"
  fi
  # 证据目录（含 config/data/out、hub.log）在任何情况下都保留，供后续分析；
  # 这里只清理本脚本启动的 hub 进程，绝不删除其它目录。
  echo "证据目录已保留: $RUN_DIR" >&2
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -n "${HUB_BIN:-}" ]]; then
  [[ -x "$HUB_BIN" ]] || die "HUB_BIN 不存在或不可执行: $HUB_BIN"
  echo "==> 使用覆盖的 HUB_BIN: $HUB_BIN（跳过 cargo build）"
else
  [[ -n "$CARGO" ]] || die "找不到 cargo（设置 CARGO=/path/to/cargo）"
  echo "==> 构建 rustboard-hub"
  (cd "$ROOT" && "$CARGO" build --locked -p rustboard-hub) || die "cargo build 失败"
  TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
  if [[ "$TARGET_DIR" != /* ]]; then
    TARGET_DIR="$ROOT/$TARGET_DIR"
  fi
  HUB_BIN="$TARGET_DIR/debug/rustboard-hub"
  [[ -x "$HUB_BIN" ]] || die "找不到构建产物: $HUB_BIN"
fi
echo "==> hub 二进制: $HUB_BIN"

# 证据绑定：提交 + 构建产物。两者都必须在 summary.json 里可复核。
GIT_HEAD=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null) \
  || die "无法读取 git HEAD（证据无法绑定提交）"
[[ "$GIT_HEAD" =~ ^[0-9a-f]{40}$ ]] || die "git HEAD 非法: $GIT_HEAD"
HUB_BIN_SHA256=$("$PYTHON" - "$HUB_BIN" <<'PY'
import hashlib
import sys

digest = hashlib.sha256()
with open(sys.argv[1], "rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
) || die "无法计算 hub 二进制 sha256"
[[ "$HUB_BIN_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "hub 二进制 sha256 非法"
echo "==> 证据绑定: git=${GIT_HEAD:0:12} hub_sha256=${HUB_BIN_SHA256:0:12}"

# ---------------------------------------------------------------------------
# 端口 / 初始化 / 配置
# ---------------------------------------------------------------------------

pick_port() {
  "$PYTHON" - <<'PY'
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

AGENT_PORT=$(pick_port)
ADMIN_PORT=$(pick_port)
while [[ "$ADMIN_PORT" == "$AGENT_PORT" ]]; do
  ADMIN_PORT=$(pick_port)
done
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}"

echo "==> 初始化 hub（agent=${AGENT_PORT} admin=${ADMIN_PORT}）"
"$HUB_BIN" init \
  --config "$CFG" \
  --data-dir "$DATA" \
  --agent-listen "127.0.0.1:${AGENT_PORT}" \
  --admin-listen "127.0.0.1:${ADMIN_PORT}" \
  --san 127.0.0.1 \
  --force > "$INIT_LOG" 2>&1 || {
    echo "---- init.log（tail）----" >&2
    tail -n 40 "$INIT_LOG" >&2 || true
    die "hub init 失败"
  }
# init 会打印管理 token；证据目录里不留明文。
"$PYTHON" - "$INIT_LOG" <<'PY'
import re
import sys

path = sys.argv[1]
text = open(path, encoding="utf-8", errors="replace").read()
text = re.sub(r"(管理 API token:\s*)\S+", r"\1[REDACTED]", text)
with open(path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY

# 替换或新增顶层配置。缺失键必须插到第一个 [section] 之前，绝不能 append 到
# 文件末尾（否则会变成最后一个 [tls] 表的子键，tomllib 校验会失败）。
set_cfg() {
  local key=$1 value=$2
  "$PYTHON" - "$CFG" "$key" "$value" <<'PY'
import re
import sys

path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path, encoding="utf-8").read()
pattern = re.compile(r"^[ \t]*" + re.escape(key) + r"[ \t]*=.*$", re.M)
matches = list(pattern.finditer(text))
if len(matches) > 1:
    raise SystemExit(f"{key} 在配置中出现 {len(matches)} 次")
line = f"{key} = {value}"
if matches:
    text = text[: matches[0].start()] + line + text[matches[0].end() :]
else:
    section = re.search(r"^[ \t]*\[", text, re.M)
    if section:
        text = text[: section.start()] + line + "\n" + text[section.start() :]
    else:
        text = text.rstrip() + "\n" + line + "\n"
open(path, "w", encoding="utf-8").write(text)
PY
}

# 与 docs/plans/2026-10-26-phase-e-hub-scale.md 对齐：自监控关闭、5s 采样、
# 连接上限 max(2048, agents+256) / 单 IP 256，管理 API 读写限速关闭
# （压测脚本要轮询 healthz 与 /api/v1/agents，不能把业务请求打成 429）。
set_cfg self_monitor false
set_cfg sample_interval_ms "$INTERVAL_MS"
set_cfg max_connections "$MAX_CONNECTIONS"
set_cfg max_connections_per_ip 256
set_cfg admin_rate_limit_per_min 0
set_cfg admin_write_rate_limit_per_min 0
chmod 600 "$CFG"

# 用 tomllib 证明这些键确实在顶层，而不是被插进某个 [section]。
"$PYTHON" - "$CFG" "$INTERVAL_MS" "$MAX_CONNECTIONS" <<'PY'
import sys
import tomllib

cfg = tomllib.load(open(sys.argv[1], "rb"))
expected = {
    "self_monitor": False,
    "sample_interval_ms": int(sys.argv[2]),
    "max_connections": int(sys.argv[3]),
    "max_connections_per_ip": 256,
    "admin_rate_limit_per_min": 0,
    "admin_write_rate_limit_per_min": 0,
}
bad = [f"{key}={cfg.get(key)!r} 期望 {value!r}" for key, value in expected.items()
       if cfg.get(key) != value]
if bad:
    raise SystemExit("顶层配置校验失败: " + "; ".join(bad))
PY
[[ -f "$CA" ]] || die "缺少 CA 证书: $CA"

# 从 hub 配置读 admin token 并写入 0600 文件；脚本本身不保存 token 变量。
# Python 压测器启动后读取并 unlink；失败时 trap 也会清掉这个文件。
"$PYTHON" - "$CFG" "$ADMIN_TOKEN_FILE" <<'PY'
import os
import re
import stat
import sys

config_path, token_path = sys.argv[1], sys.argv[2]
pattern = re.compile(r'^\s*admin_token\s*=\s*"([^"]*)"\s*$')
values = []
for line in open(config_path, encoding="utf-8"):
    match = pattern.match(line)
    if match:
        values.append(match.group(1))
if len(values) != 1 or not re.fullmatch(r"[0-9a-f]{64}", values[0]):
    raise SystemExit("无法从 hub 配置解析合法 admin_token")
fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(fd, values[0].encode("ascii") + b"\n")
finally:
    os.close(fd)
os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)
PY
[[ -s "$ADMIN_TOKEN_FILE" ]] || die "无法生成 0600 admin token 文件"
chmod 600 "$ADMIN_TOKEN_FILE"

# ---------------------------------------------------------------------------
# 启动 hub
# ---------------------------------------------------------------------------

echo "==> 启动 hub（日志 $HUB_LOG）"
RUST_LOG=${RUST_LOG:-rustboard_hub=info} "$HUB_BIN" run --config "$CFG" >> "$HUB_LOG" 2>&1 &
HUB_PID=$!

wait_health() {
  local deadline=$(( $(date +%s) + 20 ))
  while (( $(date +%s) < deadline )); do
    if ! kill -0 "$HUB_PID" 2>/dev/null; then
      return 1
    fi
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "${ADMIN_URL}/healthz" || true)" == "200" ]]; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

summary_passed() {
  "$PYTHON" - "$1" <<'PY'
import json
import sys

try:
    summary = json.load(open(sys.argv[1], encoding="utf-8"))
    passed = summary.get("passed")
except Exception:
    raise SystemExit(1)
if not isinstance(passed, bool):
    raise SystemExit(1)
print("true" if passed else "false")
PY
}

if ! wait_health; then
  echo "---- hub.log（tail）----" >&2
  tail -n 80 "$HUB_LOG" >&2 || true
  die "hub 未在 20s 内就绪"
fi
echo "==> hub 就绪（PID $HUB_PID）"

HUB_STARTTIME=$("$PYTHON" - "$HUB_PID" <<'PY'
import sys

pid = sys.argv[1]
raw = open(f"/proc/{pid}/stat", encoding="utf-8").read()
rest = raw.rsplit(")", 1)[1].split()
print(rest[19])
PY
)
[[ "$HUB_STARTTIME" =~ ^[0-9]+$ ]] || die "无法读取 hub starttime"

# ---------------------------------------------------------------------------
# 运行压测器
# ---------------------------------------------------------------------------

echo "==> 运行 hub_scale.py（agents=$AGENTS duration=${DURATION_SECS}s interval=${INTERVAL_MS}ms）"
set +e
PYTHONUNBUFFERED=1 "$PYTHON" "$ROOT/tests/load/hub_scale.py" \
  --agents "$AGENTS" \
  --duration-secs "$DURATION_SECS" \
  --interval-ms "$INTERVAL_MS" \
  --warmup-secs "$WARMUP_SECS" \
  --hub-bin "$HUB_BIN" \
  --git-head "$GIT_HEAD" \
  --hub-bin-sha256 "$HUB_BIN_SHA256" \
  --config "$CFG" \
  --hub-pid "$HUB_PID" \
  --hub-starttime "$HUB_STARTTIME" \
  --ca "$CA" \
  --agent-url "wss://127.0.0.1:${AGENT_PORT}/agent/ws" \
  --admin-url "$ADMIN_URL" \
  --admin-token-file "$ADMIN_TOKEN_FILE" \
  --db "$DB" \
  --backend "$BACKEND" \
  --out-dir "$OUT" \
  --hub-log "$HUB_LOG" \
  --reconnect-every "$RECONNECT_EVERY" 2>&1 | tee "$PY_LOG"
PY_RC=${PIPESTATUS[0]}
set -e
# 正常路径 Python 已 unlink；这里兜底，确保证据目录不留下 token 文件。
rm -f -- "$ADMIN_TOKEN_FILE"

# 先读取 Python 写出的 summary.passed，稍后与 PY_RC / shell 门禁交叉校验；
# 不能只看退出码，否则 wrapper 侧失败或 summary 被截断都可能假通过。
SUMMARY_PARSE_OK=0
PY_PASSED=""
if [[ -f "$SUMMARY" ]]; then
  if PY_PASSED=$(summary_passed "$SUMMARY"); then
    SUMMARY_PARSE_OK=1
  fi
fi

# ---------------------------------------------------------------------------
# 停止 hub / 日志门禁 / summary
# ---------------------------------------------------------------------------

HUB_CRASHED=0
if ! kill -0 "$HUB_PID" 2>/dev/null; then
  HUB_CRASHED=1
  echo "FAIL: 压测结束时 hub 进程已退出" >&2
fi

echo "==> 停止 hub（SIGTERM）"
STOP_OK=1
if (( HUB_CRASHED == 0 )); then
  kill -TERM "$HUB_PID" 2>/dev/null || true
  for _ in $(seq 1 150); do
    kill -0 "$HUB_PID" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$HUB_PID" 2>/dev/null; then
    echo "FAIL: hub 未在 15s 内退出，发送 SIGKILL" >&2
    kill -KILL "$HUB_PID" 2>/dev/null || true
    STOP_OK=0
  fi
fi
wait "$HUB_PID" 2>/dev/null || true
HUB_STOPPED=1

LOG_BAD=0
LOG_MATCHES=0
if [[ -f "$HUB_LOG" ]]; then
  LOG_MATCHES=$(grep -Ec 'panicked|(^|[^A-Za-z_])ERROR([^A-Za-z_]|$)' "$HUB_LOG" || true)
  if (( LOG_MATCHES > 0 )); then
    LOG_BAD=1
    echo "FAIL: hub.log 包含 panicked/ERROR（$LOG_MATCHES 行）" >&2
    grep -E 'panicked|(^|[^A-Za-z_])ERROR([^A-Za-z_]|$)' "$HUB_LOG" | head -n 10 >&2 || true
  fi
fi

SHELL_FAILURES=""
add_shell_failure() {
  if [[ -n "$SHELL_FAILURES" ]]; then
    SHELL_FAILURES+="; $1"
  else
    SHELL_FAILURES=$1
  fi
}

if (( SUMMARY_PARSE_OK == 0 )); then
  add_shell_failure "out/summary.json 不存在或无法解析"
else
  if [[ "$PY_PASSED" == "true" && "$PY_RC" -ne 0 ]]; then
    add_shell_failure "out/summary.json passed=true 与 hub_scale.py 退出码 $PY_RC 不一致"
  elif [[ "$PY_PASSED" == "false" && "$PY_RC" -eq 0 ]]; then
    add_shell_failure "out/summary.json passed=false 与 hub_scale.py 退出码 0 不一致"
  fi
fi
(( HUB_CRASHED == 0 )) || add_shell_failure "压测结束时 hub 进程已退出"
(( STOP_OK == 1 )) || add_shell_failure "hub 未在 15s 内响应 SIGTERM"
(( LOG_BAD == 0 )) || add_shell_failure "hub.log 出现 panicked/ERROR（$LOG_MATCHES 行）"
(( PY_RC == 0 )) || add_shell_failure "hub_scale.py 退出码 $PY_RC"

# 证据泄露扫描：admin token、私钥、无法解释的 64hex。公开的服务端证书指纹
# 与 summary 里的 hub/db sha256 属于公开证据，允许保留。
scan_evidence_secrets() {
  local out
  if out=$("$PYTHON" - "$CFG" "$INIT_LOG" "$HUB_LOG" "$SUMMARY" \
      "$OUT/metrics.jsonl" "$PY_LOG" <<'PY'
import json
import os
import re
import sys

config_path, *files = sys.argv[1:]
summary_path = files[2] if len(files) > 2 else ""
try:
    config_text = open(config_path, encoding="utf-8").read()
except OSError:
    print("config: 无法读取")
    raise SystemExit(1)
match = re.search(r'^admin_token\s*=\s*"([0-9a-f]{64})"', config_text, re.M)
if not match:
    print("config: 缺少合法 admin_token")
    raise SystemExit(1)
admin_token = match.group(1)

texts = {}
for path in files:
    if not path or not os.path.isfile(path):
        continue
    try:
        texts[path] = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        print(f"{os.path.basename(path)}: 读取失败")
        raise SystemExit(1)

allowed = set()
fingerprint_re = re.compile(
    r'(?i)(?:fingerprint\s*=\s*"|证书指纹\s*[:：]\s*)([0-9a-f]{64})'
)
for text in texts.values():
    allowed.update(fingerprint_re.findall(text))

if summary_path and summary_path in texts:
    try:
        data = json.loads(texts[summary_path])
    except Exception:
        data = None

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if (
                    isinstance(item, str)
                    and ("sha256" in key or "fingerprint" in key)
                    and re.fullmatch(r"[0-9a-f]{64}", item)
                ):
                    allowed.add(item)
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    if data is not None:
        walk(data)

violations = []
for path, text in texts.items():
    name = os.path.basename(path)
    if admin_token in text:
        violations.append(f"{name}: admin_token")
    if re.search(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", text):
        violations.append(f"{name}: private_key")
    masked = text
    for digest in allowed:
        masked = masked.replace(digest, "[public]")
    if re.search(r"\b[0-9a-f]{64}\b", masked):
        violations.append(f"{name}: 64hex(可能 secret)")

if violations:
    print("; ".join(violations))
    raise SystemExit(1)
PY
  ); then
    return 0
  fi
  add_shell_failure "证据泄露扫描失败: ${out:-未知原因}"
}
scan_evidence_secrets

if (( SUMMARY_PARSE_OK == 0 )); then
  echo "FAIL: 未生成可解析 summary: $SUMMARY" >&2
  echo "证据目录: $RUN_DIR"
  echo "hub 日志: $HUB_LOG"
  exit 1
fi

if ! "$PYTHON" - "$SUMMARY" "$SHELL_FAILURES" <<'PY'
import json
import os
import sys

path = sys.argv[1]
extra = [item for item in sys.argv[2].split("; ") if item]
summary = json.load(open(path, encoding="utf-8"))
summary["shell_gate_passed"] = not extra
if extra:
    failures = summary.setdefault("failures", [])
    for item in extra:
        if item not in failures:
            failures.append(item)
    summary["passed"] = False
tmp = path + ".tmp"
with open(tmp, "w", encoding="utf-8") as handle:
    json.dump(summary, handle, ensure_ascii=False, indent=2)
    handle.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
then
  add_shell_failure "shell 门禁结果写入 summary 失败"
fi

FINAL_PARSE_OK=0
FINAL_PASSED=""
if FINAL_PASSED=$(summary_passed "$SUMMARY"); then
  FINAL_PARSE_OK=1
fi
if (( FINAL_PARSE_OK == 0 )); then
  echo "FAIL: 最终 summary 无法解析: $SUMMARY" >&2
  echo "证据目录: $RUN_DIR"
  echo "hub 日志: $HUB_LOG"
  exit 1
fi

"$PYTHON" - "$SUMMARY" <<'PY'
import json
import sys

summary = json.load(open(sys.argv[1], encoding="utf-8"))
ack = summary.get("ack_ms", {})
resources = summary.get("resources", {})
rss = resources.get("rss_kb", {})
fd = resources.get("fd", {})
threads = resources.get("threads", {})
db = summary.get("db") or {}
health = resources.get("health", {})
retry_gate = summary.get("retry_gate", {})
print("")
print("========== Phase E S2 结果 ==========")
print(
    "agents={agents} duration={duration}s interval={interval}ms "
    "source_ips={ips} planned={planned} sent={sent} acked={acked} "
    "unacked={unacked} errors={errors} retries={retries} reconnects={reconnects}".format(
        ips=summary.get("source_ips"),
        duration=summary.get("duration_secs"),
        interval=summary.get("interval_ms"),
        **summary,
    )
)
print(
    "ack p50={}ms p95={}ms p99={}ms max={}ms".format(
        ack.get("p50"), ack.get("p95"), ack.get("p99"), ack.get("max")
    )
)
print(
    "throughput batch/s={b} sample/s={s}".format(
        b=summary.get("throughput", {}).get("batches_per_sec"),
        s=summary.get("throughput", {}).get("samples_per_sec"),
    )
)
print(
    "db batches={batches}/{expected} samples={samples}/{samples_expected} "
    "dup={dup_b}/{dup_s} snapshot={snapshot}".format(
        batches=db.get("batches"),
        expected=db.get("batches_expected"),
        samples=db.get("samples"),
        samples_expected=db.get("samples_expected"),
        dup_b=db.get("duplicate_batches"),
        dup_s=db.get("duplicate_samples"),
        snapshot=db.get("snapshot_mode"),
    )
)
print(
    "rss_kb baseline={b} end={e} growth={g}% gate={gate} | fd {fb}->{fe} | "
    "threads {tb}->{te} | cpu_avg={cpu}%".format(
        b=rss.get("baseline"),
        e=rss.get("end"),
        g=rss.get("growth_pct"),
        gate=rss.get("gate_enabled"),
        fb=fd.get("baseline"),
        fe=fd.get("end"),
        tb=threads.get("baseline"),
        te=threads.get("end"),
        cpu=resources.get("cpu", {}).get("avg_pct"),
    )
)
print(
    "health ok={ok}/{samples} fail={failures} | hub restarted={restarted} | "
    "retry_gate enforced={enforced} ok={retry_ok}".format(
        ok=health.get("ok"),
        samples=health.get("samples"),
        failures=health.get("failures"),
        restarted=summary.get("hub", {}).get("restarted"),
        enforced=retry_gate.get("enforced"),
        retry_ok=retry_gate.get("ok"),
    )
)
print(
    "evidence git={git} hub_sha256={hub} db_sha256={dbhash}".format(
        git=summary.get("git_head"),
        hub=summary.get("hub_bin_sha256"),
        dbhash=summary.get("sqlite_db_sha256"),
    )
)
print("result: {}".format("PASS" if summary.get("passed") else "FAIL"))
for failure in summary.get("failures", []):
    print(f"  - {failure}")
print("summary: {}".format(sys.argv[1]))
PY

echo "证据目录: $RUN_DIR"
echo "hub 日志: $HUB_LOG"

FINAL_RC=0
if (( PY_RC != 0 )); then
  FINAL_RC=$PY_RC
fi
if [[ -n "$SHELL_FAILURES" ]]; then
  FINAL_RC=1
fi
if [[ "$FINAL_PASSED" != "true" ]]; then
  FINAL_RC=1
fi
if (( FINAL_RC != 0 )); then
  echo "==> 失败：证据已保留，修复后按 README 要求重跑" >&2
  exit "$FINAL_RC"
fi
echo "==> 通过"
exit 0
