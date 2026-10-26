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

  AGENTS           虚拟 agent 数（1000 需要 5 个源 IP，工具自动分配）
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
(( AGENTS >= 1 && AGENTS <= 5000 )) || die "AGENTS 必须在 1–5000 之间"
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

set_cfg() {
  local key=$1 value=$2
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$CFG"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "$CFG"
  else
    printf '\n%s = %s\n' "$key" "$value" >> "$CFG"
  fi
}

# 与 docs/plans/2026-10-26-phase-e-hub-scale.md 对齐：自监控关闭、5s 采样、
# 连接上限 2048 / 单 IP 256，管理 API 读写限速关闭（压测脚本要轮询 healthz
# 与 /api/v1/agents，不能把业务请求打成 429）。
set_cfg self_monitor false
set_cfg sample_interval_ms "$INTERVAL_MS"
set_cfg max_connections 2048
set_cfg max_connections_per_ip 256
set_cfg admin_rate_limit_per_min 0
set_cfg admin_write_rate_limit_per_min 0
chmod 600 "$CFG"
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
(( HUB_CRASHED == 0 )) || add_shell_failure "压测结束时 hub 进程已退出"
(( STOP_OK == 1 )) || add_shell_failure "hub 未在 15s 内响应 SIGTERM"
(( LOG_BAD == 0 )) || add_shell_failure "hub.log 出现 panicked/ERROR（$LOG_MATCHES 行）"
(( PY_RC == 0 )) || add_shell_failure "hub_scale.py 退出码 $PY_RC"

if [[ -f "$SUMMARY" ]]; then
  "$PYTHON" - "$SUMMARY" "$SHELL_FAILURES" <<'PY'
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
    "ack p50={p50}ms p95={p95}ms p99={p99}ms max={max}ms".format(**ack)
)
print(
    "throughput batch/s={b} sample/s={s}".format(
        b=summary.get("throughput", {}).get("batches_per_sec"),
        s=summary.get("throughput", {}).get("samples_per_sec"),
    )
)
print(
    "db batches={batches}/{expected} samples={samples}/{samples_expected} "
    "dup={dup_b}/{dup_s}".format(
        batches=db.get("batches"),
        expected=db.get("batches_expected"),
        samples=db.get("samples"),
        samples_expected=db.get("samples_expected"),
        dup_b=db.get("duplicate_batches"),
        dup_s=db.get("duplicate_samples"),
    )
)
print(
    "rss_kb baseline={b} end={e} growth={g}% | fd {fb}->{fe} | threads {tb}->{te} | "
    "cpu_avg={cpu}%".format(
        b=rss.get("baseline"),
        e=rss.get("end"),
        g=rss.get("growth_pct"),
        fb=fd.get("baseline"),
        fe=fd.get("end"),
        tb=threads.get("baseline"),
        te=threads.get("end"),
        cpu=resources.get("cpu", {}).get("avg_pct"),
    )
)
print(
    "health ok={ok}/{samples} fail={failures} | hub restarted={restarted}".format(
        ok=health.get("ok"),
        samples=health.get("samples"),
        failures=health.get("failures"),
        restarted=summary.get("hub", {}).get("restarted"),
    )
)
print("result: {}".format("PASS" if summary.get("passed") else "FAIL"))
for failure in summary.get("failures", []):
    print(f"  - {failure}")
print("summary: {}".format(sys.argv[1]))
PY
else
  echo "FAIL: 未生成 summary: $SUMMARY" >&2
  exit 1
fi

echo "证据目录: $RUN_DIR"
echo "hub 日志: $HUB_LOG"

FINAL_RC=0
if (( PY_RC != 0 )); then
  FINAL_RC=$PY_RC
fi
if [[ -n "$SHELL_FAILURES" ]]; then
  FINAL_RC=1
fi
if (( FINAL_RC != 0 )); then
  echo "==> 失败：证据已保留，修复后按 README 要求重跑" >&2
  exit "$FINAL_RC"
fi
echo "==> 通过"
exit 0
