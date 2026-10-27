#!/usr/bin/env bash
#
# RustBoard v0.4.1 已知问题修复的独立 e2e 回归（修复前应失败）：
#
#   KI-29：SQLite 造「最大 rowid 迟到行 → retention 删除 → 新迟到行复用 rowid」，
#          断言 v8 不再依赖 rowid 水位/行存在性；迟到行按身份增量合并，
#          旧聚合 100.0 与新迟到值 5.0 合并为 count=2/avg=52.5，不被残缺 raw 覆盖。
#   KI-31：archive.max_object_bytes 64 MiB 通过校验、64 MiB+1 启动被拒绝；
#          已有 64 MiB+1 对象列表 downloadable=false、下载 413 + archive_too_large
#          + 固定说明（后端地址故意不可达，413 证明未读 body）。
#   KI-28：max_connections_per_ip=2，同一 IP 连续 40 条 TCP 拒绝只有 1 条 WARN、
#          其余 DEBUG；另一个来源 IP 不共享采样窗口（也各有 1 条 WARN）。
#   KI-20：agent add --name 输出对空格、单引号、$()、反引号、分号、换行/Tab
#          做受控子 shell 断言；正常 name 仍可直接粘贴执行。
#
# 依据：docs/plans/2026-10-24-known-issues-fix.md §3.1–§3.4、§4。
# 只写测试，不修改实现；不联网、不碰生产；端口随机；临时目录 0700 并清理。
# 失败的 payload 只有 `printf INJECTED`（无副作用），且只在一次性临时目录的
# stub `rustboard-agent` 下执行，不会运行真实 agent 命令。
#
# 依赖：bash 4.4+、python3 3.8+（仅标准库）、curl、cargo/rustc、timeout。
# 用法：bash tests/e2e/v041.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/v041.sh
#
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
HELPER="$SCRIPT_DIR/v041_helper.py"
PYTHON=${PYTHON:-python3}
CARGO=${CARGO:-cargo}
export PYTHONDONTWRITEBYTECODE=1

# 当前代码构建默认用仓库 target；调用方显式设置 CARGO_TARGET_DIR 时优先。
if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  export CARGO_TARGET_DIR="$ROOT/target"
fi

PASSES=0
FAILS=0
SKIPS=0
SKIP_NOTES=()
STATUS=""
HUB_PID=""
PIDS=()

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-v041.XXXXXX")
chmod 700 "$TMP_DIR"

HUB_CFG="$TMP_DIR/hub.toml"
HUB_CFG_64="$TMP_DIR/hub-64mib.toml"
HUB_CFG_BAD="$TMP_DIR/hub-64mib-plus-one.toml"
HUB_DATA="$TMP_DIR/hub-data"
HUB_LOG="$TMP_DIR/hub.log"
BAD_LOG="$TMP_DIR/bad-run.log"
INIT_LOG="$TMP_DIR/init.log"
BUILD_LOG="$TMP_DIR/build.log"
HTTP_BODY="$TMP_DIR/http-body.json"
CURL_ERR="$TMP_DIR/curl.err"
AGENT_ADD_ERR="$TMP_DIR/agent-add.err"

: > "$HUB_LOG"
: > "$BAD_LOG"
: > "$CURL_ERR"

pass() {
  PASSES=$((PASSES + 1))
  echo "PASS [$1] $2"
}

fail() {
  FAILS=$((FAILS + 1))
  echo "FAIL [$1] $2" >&2
}

skip() {
  SKIPS=$((SKIPS + 1))
  SKIP_NOTES+=("[$1] $2")
  echo "SKIP [$1] $2"
}

die() {
  echo "FATAL: $*" >&2
  exit 1
}

dump_log() {
  local log=$1 lines=${2:-80}
  if [[ -s "$log" ]]; then
    echo "---- $(basename "$log") (tail -n $lines) ----" >&2
    tail -n "$lines" "$log" | sed -E \
      -e 's/(管理 API token:).*/\1 <redacted>/' \
      -e 's/(一次性 token[^:：]*[:：]).*/\1 <redacted>/' \
      -e 's/(Bearer )[^[:space:]]+/\1<redacted>/' >&2 || true
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
    echo "===== v041 e2e 失败现场（日志尾部）=====" >&2
    dump_log "$INIT_LOG" 20
    dump_log "$BUILD_LOG" 40
    dump_log "$BAD_LOG" 20
    dump_log "$HUB_LOG" 80
  fi

  for note in ${SKIP_NOTES[@]+"${SKIP_NOTES[@]}"}; do
    echo "SKIP $note" >&2
  done

  if [[ "${KEEP_E2E_TMP:-0}" == "1" ]]; then
    echo "临时目录已保留: $TMP_DIR" >&2
  elif [[ -n "${TMP_DIR:-}" && "$TMP_DIR" == "${TMPDIR:-/tmp}"/rustboard-v041.* ]]; then
    rm -rf -- "$TMP_DIR"
  else
    echo "警告: 临时目录不符合预期，未删除: ${TMP_DIR:-<unset>}" >&2
  fi
  exit "$code"
}
trap cleanup EXIT

for tool in "$PYTHON" "$CARGO" curl mktemp date tail awk sed grep tr cat timeout; do
  command -v "$tool" >/dev/null 2>&1 \
    || die "找不到命令: $tool（python3 需 3.8+；cargo 请放进 PATH 或设置 CARGO=...）"
done
[[ -f "$HELPER" ]] || die "缺少 Python helper: $HELPER"

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

set_toml() {
  "$PYTHON" "$HELPER" set-toml "$@"
}

get_toml() {
  "$PYTHON" "$HELPER" get-toml "$@"
}

pick_ports() {
  "$PYTHON" "$HELPER" ports "$1"
}

json_get() {
  "$PYTHON" "$HELPER" get "$HTTP_BODY" "$1"
}

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$expected]，实际 [$actual]）"
  fi
}

wait_health() {
  local url=$1 timeout=$2
  local deadline=$(( $(date +%s%3N) + timeout * 1000 ))
  local code
  while :; do
    code=$(curl -sS --noproxy '*' --max-time 3 -o /dev/null -w '%{http_code}' \
      "$url" 2>/dev/null) || code="000"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.15
  done
}

api() {
  local method=$1 path=$2
  STATUS=$(curl -sS --noproxy '*' --max-time 20 \
    -o "$HTTP_BODY" -w '%{http_code}' \
    -X "$method" "${ADMIN_URL}${path}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H 'Accept: application/json' 2>"$CURL_ERR") || STATUS="000"
}

# ---------------------------------------------------------------------------
# 构建、初始化与配置
# ---------------------------------------------------------------------------

echo "==> 构建 rustboard-hub（CARGO_TARGET_DIR=$CARGO_TARGET_DIR）"
if ! (cd "$ROOT" && timeout 1800 "$CARGO" build --locked -p rustboard-hub) \
      > "$BUILD_LOG" 2>&1; then
  dump_log "$BUILD_LOG" 100
  die "cargo build -p rustboard-hub 失败"
fi
TARGET_DIR="$CARGO_TARGET_DIR"
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
HUB_BIN="$TARGET_DIR/debug/rustboard-hub"
[[ -x "$HUB_BIN" ]] || die "找不到 $HUB_BIN"
pass "0.1" "cargo build -p rustboard-hub 成功"

PORT_LINE=$(pick_ports 2) || die "无法挑选空闲端口"
read -r AGENT_PORT ADMIN_PORT <<< "$PORT_LINE"
[[ "$AGENT_PORT" =~ ^[0-9]+$ && "$ADMIN_PORT" =~ ^[0-9]+$ ]] \
  || die "端口解析失败: $PORT_LINE"
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}"

echo "==> 初始化 hub（agent=${AGENT_PORT} admin=${ADMIN_PORT}）"
if ! "$HUB_BIN" init \
    --config "$HUB_CFG" \
    --data-dir "$HUB_DATA" \
    --agent-listen "127.0.0.1:${AGENT_PORT}" \
    --admin-listen "127.0.0.1:${ADMIN_PORT}" \
    --san 127.0.0.1 \
    --force > "$INIT_LOG" 2>&1; then
  dump_log "$INIT_LOG" 80
  die "hub init 失败"
fi
chmod 600 "$HUB_CFG"

# KI-28 需要小上限；KI-29 只需 1 天保留期即可覆盖收窄窗口；关闭自监控避免
# 干扰 raw 行数与 rowid 断言。归档后端给一个不可达的 WebDAV 地址：
# 下载 413 必须在触达后端之前返回（若实现先读 body，会得到 502）。
set_toml "$HUB_CFG" - max_connections_per_ip 2
set_toml "$HUB_CFG" - retention_raw_days 1
set_toml "$HUB_CFG" - self_monitor false
set_toml "$HUB_CFG" archive after_days 1
set_toml "$HUB_CFG" archive.webdav url '"http://127.0.0.1:9/dav"'
set_toml "$HUB_CFG" archive.webdav username '"v041-probe"'
set_toml "$HUB_CFG" archive.webdav password '"v041-not-a-secret"'

MAINT_STATUS_LOG="$TMP_DIR/maintenance-init.json"
if ! "$HUB_BIN" maintenance status --config "$HUB_CFG" > "$MAINT_STATUS_LOG" 2>&1; then
  dump_log "$MAINT_STATUS_LOG" 40
  die "maintenance status 初始化数据库失败"
fi

DB_RAW=$(get_toml "$HUB_CFG" - database)
[[ "$DB_RAW" == sqlite://* ]] || die "database 配置不是 sqlite:// 形式"
DB=${DB_RAW#sqlite://}
[[ -f "$DB" ]] || die "SQLite 数据库不存在: $DB"

ADMIN_TOKEN=$(get_toml "$HUB_CFG" - admin_token)
[[ "$ADMIN_TOKEN" =~ ^[0-9a-f]{64}$ ]] || die "hub admin_token 非法（不打印内容）"
pass "0.2" "hub init、测试配置与 SQLite schema 就绪（token 不打印）"

# ---------------------------------------------------------------------------
# 1. KI-31：配置上限 64 MiB 边界
# ---------------------------------------------------------------------------

echo "==> 1) KI-31 配置边界"

cp "$HUB_CFG" "$HUB_CFG_64"
set_toml "$HUB_CFG_64" archive max_object_bytes 67108864
if "$HUB_BIN" maintenance status --config "$HUB_CFG_64" >/dev/null 2>"$TMP_DIR/64mib.err"; then
  pass "1.1" "archive.max_object_bytes = 64 MiB（67108864）通过配置校验"
else
  fail "1.1" "archive.max_object_bytes = 64 MiB 被错误拒绝（见 64mib.err）"
fi

cp "$HUB_CFG" "$HUB_CFG_BAD"
set_toml "$HUB_CFG_BAD" archive max_object_bytes 67108865
BAD_RC=0
timeout --signal=KILL 15 "$HUB_BIN" run --config "$HUB_CFG_BAD" > "$BAD_LOG" 2>&1 \
  || BAD_RC=$?
if (( BAD_RC == 0 )); then
  fail "1.2" "archive.max_object_bytes = 64 MiB + 1 未被拒绝：run 在 15s 内未退出"
elif (( BAD_RC == 124 || BAD_RC == 137 )); then
  fail "1.2" "archive.max_object_bytes = 64 MiB + 1 仍能启动（timeout 杀死，rc=$BAD_RC）"
elif ! grep -q 'max_object_bytes' "$BAD_LOG"; then
  fail "1.2" "64 MiB + 1 启动失败（rc=$BAD_RC）但错误未点名 archive.max_object_bytes"
else
  pass "1.2" "archive.max_object_bytes = 64 MiB + 1 在启动校验阶段被拒绝（rc=$BAD_RC）"
fi
sleep 0.3

# ---------------------------------------------------------------------------
# 2. KI-29：retention 删除最大 rowid 后，复用 rowid 的迟到行仍触发重算
# ---------------------------------------------------------------------------

echo "==> 2) KI-29 rowid 水位复用"

NOW_MS=$(date +%s%3N)
SEED=$("$PYTHON" "$HELPER" ki29-seed "$DB" "$NOW_MS") \
  || die "ki29-seed 失败"
read -r OLD_TS OLD_BUCKET OLD_HOUR OLD_MAX_ROWID <<< "$SEED"
for value in "$OLD_TS" "$OLD_BUCKET" "$OLD_HOUR" "$OLD_MAX_ROWID"; do
  [[ "$value" =~ ^[0-9]+$ ]] || die "ki29-seed 输出非法: $SEED"
done
if [[ "$OLD_MAX_ROWID" == "2" ]]; then
  pass "2.1" "造数成功：最近行 rowid=1、迟到旧行 rowid=2（迟到行是最大 rowid）"
else
  fail "2.1" "造数前提不成立：MAX(rowid)=$OLD_MAX_ROWID，期望 2"
fi

if ! "$HUB_BIN" maintenance run --config "$HUB_CFG" --task downsample \
      > "$TMP_DIR/downsample-1.json" 2>"$TMP_DIR/downsample-1.err"; then
  fail "2.2" "首次 maintenance run --task downsample 失败（见日志尾部）"
else
  pass "2.2" "首次 downsample 成功（旧 1m/1h 桶已建立，基线值 100.0）"
fi

if ! "$HUB_BIN" maintenance run --config "$HUB_CFG" --task retention \
      > "$TMP_DIR/retention.json" 2>"$TMP_DIR/retention.err"; then
  fail "2.3" "maintenance run --task retention 失败（见日志尾部）"
else
  pass "2.3" "retention 成功执行（预期删除迟到旧 raw 行）"
fi

STATE=$("$PYTHON" "$HELPER" ki29-state "$DB") || die "ki29-state 失败"
read -r WATERMARK NEW_MAX_ROWID RAW_ROWS <<< "$STATE"
if [[ "$NEW_MAX_ROWID" != "1" || "$RAW_ROWS" != "1" ]]; then
  fail "2.4" "retention 后预期只剩 1 行 raw 且 MAX(rowid)=1，实际 MAX=$NEW_MAX_ROWID rows=$RAW_ROWS"
elif [[ "$WATERMARK" == "none" ]]; then
  # v8 用 (agent_id,metric,labels,ts,value) 身份 + aggregated_1m，不再依赖 rowid 水位。
  pass "2.4" "retention 后 raw 非空，v8 无 rowid 水位依赖（WATERMARK=none）；复用 rowid 由 2.5/2.6 覆盖"
elif [[ ! "$WATERMARK" =~ ^[0-9]+$ ]]; then
  fail "2.4" "downsample_1m_last_raw_rowid 不是整数: $WATERMARK"
elif (( WATERMARK > NEW_MAX_ROWID )); then
  fail "2.4" "retention 后 downsample_1m_last_raw_rowid=$WATERMARK 高于新 MAX(rowid)=$NEW_MAX_ROWID；复用 rowid 的迟到行会被误判为已认领"
else
  pass "2.4" "retention 后 raw 非空，rowid 水位 $WATERMARK 为有效整数且不高于新 MAX(rowid)=$NEW_MAX_ROWID"
fi

LATE=$("$PYTHON" "$HELPER" ki29-late "$DB" "$OLD_TS") || die "ki29-late 失败"
read -r LATE_ROWID LATE_MAX <<< "$LATE"
if [[ "$LATE_ROWID" == "2" && "$LATE_MAX" == "2" ]]; then
  pass "2.5" "新迟到行复用了被删除的 rowid=2（ROWID 为 2，MAX 仍为 2）"
else
  fail "2.5" "新迟到行未复用 rowid：ROWID=$LATE_ROWID MAX=$LATE_MAX（期望均为 2）"
fi

if ! "$HUB_BIN" maintenance run --config "$HUB_CFG" --task downsample \
      > "$TMP_DIR/downsample-2.json" 2>"$TMP_DIR/downsample-2.err"; then
  fail "2.6" "迟到行后的 maintenance run --task downsample 失败"
else
  CHECK=$("$PYTHON" "$HELPER" ki29-check "$DB" "$OLD_BUCKET" "$OLD_HOUR") \
    || die "ki29-check 失败"
  read -r M_COUNT M_AVG H_COUNT H_AVG <<< "$CHECK"
  # v8 增量合并：旧 1m/1h 聚合（count=1, avg=100）保留，迟到值 5 追加为第二条，
  # 因此 count=2/avg=52.5；不能按残缺 raw 重算成 5.0（那会丢历史）。
  check_eq "2.6" "复用 rowid 的迟到行按身份增量合并到 1m/1h（count=2, avg=52.5）" \
    "2 52.500000 2 52.500000" "$M_COUNT $M_AVG $H_COUNT $H_AVG"
fi

# ---------------------------------------------------------------------------
# 3. KI-20：agent add --name 的 shell 安全引用
# ---------------------------------------------------------------------------

echo "==> 3) KI-20 安装命令 name 转义"

agent_field() {
  local key=$1 line=$2
  printf '%s\n' "$line" | tr ' ' '\n' | sed -n "s/^${key}=//p"
}

# 数组元素格式：<类别>|<name>。控制字符只允许“拒绝或安全转义”两种结果；
# 其余类别必须生成命令，且命令在受控子 shell 中把完整 name 作为一个 argv 传入。
KI20_CASES=(
  $'normal|web-01'
  $'space|web 01'
  $'single-quote|web\'01'
  $'dollar-paren|web$(printf INJECTED)'
  $'backtick|web`printf INJECTED`'
  $'semicolon|web;printf INJECTED'
  $'newline|web\n01'
  $'tab|web\t01'
)
KI20_INDEX=0
for case_item in "${KI20_CASES[@]}"; do
  KI20_INDEX=$((KI20_INDEX + 1))
  kind=${case_item%%|*}
  name=${case_item#*|}
  case_id="3.${KI20_INDEX}"

  if ! out=$("$PYTHON" "$HELPER" agent-add-safe "$HUB_BIN" "$HUB_CFG" "$name" \
        2>"$AGENT_ADD_ERR"); then
    fail "$case_id" "agent add（$kind）执行失败，无法判断输出安全性"
    continue
  fi

  mode=$(agent_field mode "$out")
  if [[ "$mode" == "rejected" ]]; then
    if [[ "$kind" == "newline" || "$kind" == "tab" ]]; then
      pass "$case_id" "$kind：agent add 明确拒绝含控制字符的 name（安全）"
    else
      fail "$case_id" "$kind：应通过 shell 引用生成可粘贴命令，实际被拒绝（$out）"
    fi
    continue
  fi
  if [[ "$mode" != "executed" ]]; then
    fail "$case_id" "$kind：agent add 未输出可执行安装命令（$out）"
    continue
  fi

  syntax_ok=$(agent_field syntax_ok "$out")
  name_ok=$(agent_field name_ok "$out")
  meta_ok=$(agent_field meta_ok "$out")
  injected=$(agent_field injected "$out")
  stub_called=$(agent_field stub_called "$out")
  if [[ "$syntax_ok" == "1" && "$name_ok" == "1" && "$meta_ok" == "1" \
        && "$injected" == "0" && "$stub_called" == "1" ]]; then
    pass "$case_id" "$kind：bash -n 通过，受控子 shell 中 name 保持单个字面 argv，无注入执行"
  else
    fail "$case_id" "$kind：安装命令不安全（syntax_ok=$syntax_ok name_ok=$name_ok meta_ok=$meta_ok injected=$injected stub_called=$stub_called）"
  fi
done

# ---------------------------------------------------------------------------
# 4. KI-31：已有 >64 MiB 对象的列表标记与下载 413
# ---------------------------------------------------------------------------

echo "==> 4) KI-31 大对象下载"

ARCHIVE_IDS=$("$PYTHON" "$HELPER" archive-seed "$DB" "$NOW_MS") \
  || die "archive-seed 失败"
read -r HUGE_ID SMALL_ID <<< "$ARCHIVE_IDS"
for value in "$HUGE_ID" "$SMALL_ID"; do
  [[ "$value" =~ ^[0-9]+$ ]] || die "archive-seed 输出非法: $ARCHIVE_IDS"
done

echo "==> 启动 hub（RUST_LOG=rustboard_hub=debug，用于 KI-28 采样计数）"
RUST_LOG=rustboard_hub=debug "$HUB_BIN" run --config "$HUB_CFG" >> "$HUB_LOG" 2>&1 &
HUB_PID=$!
PIDS+=("$HUB_PID")
wait_health "${ADMIN_URL}/healthz" 25 \
  || die "hub 未在 25s 内就绪（${ADMIN_URL}/healthz）"
pass "4.1" "hub 管理口 /healthz 返回 200"

api GET "/api/v1/archive/objects"
if [[ "$STATUS" != "200" ]]; then
  fail "4.2" "GET /api/v1/archive/objects（期望 200，实际 $STATUS）"
else
  LIST_FLAGS=$("$PYTHON" "$HELPER" archive-view "$HTTP_BODY" "$HUGE_ID" "$SMALL_ID") \
    || die "archive-view 失败"
  huge_flag=$(agent_field huge "$LIST_FLAGS")
  small_flag=$(agent_field small "$LIST_FLAGS")
  if [[ "$huge_flag" == "false" && "$small_flag" == "true" ]]; then
    pass "4.2" "对象列表：64 MiB+1 对象 downloadable=false，1 KiB 对象 downloadable=true"
  elif [[ "$huge_flag" == "__MISSING__" || "$small_flag" == "__MISSING__" ]]; then
    fail "4.2" "对象列表缺少 downloadable 字段（huge=$huge_flag small=$small_flag），无法标记不可下载对象"
  else
    fail "4.2" "对象列表 downloadable 标记不符（huge=$huge_flag small=$small_flag，期望 false/true）"
  fi
fi

api GET "/api/v1/archive/objects/${HUGE_ID}/download"
if [[ "$STATUS" == "413" ]]; then
  error_code=$(json_get 'd.get("error")')
  message=$(json_get 'd.get("message")')
  if [[ "$error_code" == "archive_too_large" && "$message" == *"64 MiB"* ]]; then
    pass "4.3" "下载 64 MiB+1 对象返回 413 archive_too_large，说明含 64 MiB（后端不可达仍 413，未读 body）"
  else
    fail "4.3" "下载 413 但错误码/文案不符（error=$error_code message=$message）"
  fi
else
  fail "4.3" "下载 64 MiB+1 对象期望 413 archive_too_large，实际 $STATUS"
fi
skip "4.4" "面板 /archive 不渲染可点击下载按钮：需要 panel 登录会话，未在本脚本独立覆盖（API downloadable 与 413 已覆盖）"

# ---------------------------------------------------------------------------
# 5. KI-28：连接拒绝 WARN 采样
# ---------------------------------------------------------------------------

echo "==> 5) KI-28 拒绝日志采样"

LINES_BEFORE=$(wc -l < "$HUB_LOG")
if ! "$PYTHON" "$HELPER" ki28-flood 127.0.0.1 "$AGENT_PORT" > "$TMP_DIR/flood.out" 2>&1; then
  fail "5.1" "连接洪水构造失败（可能无法绑定 127.0.0.2）：$(tail -n 2 "$TMP_DIR/flood.out" | tr '\n' ' ')"
else
  pass "5.1" "已保持 127.0.0.1 / 127.0.0.2 各 2 条连接，并各制造 40 / 5 条超限 TCP 连接"
fi
sleep 1

COUNTS=$("$PYTHON" "$HELPER" ki28-count "$HUB_LOG" "$LINES_BEFORE") \
  || die "ki28-count 失败"
count_field() {
  printf '%s\n' "$COUNTS" | tr ' ' '\n' | sed -n "s/^$1=//p"
}
IP1_WARN=$(count_field ip1_warn)
IP1_DEBUG=$(count_field ip1_debug)
IP1_OTHER=$(count_field ip1_other)
IP2_WARN=$(count_field ip2_warn)
IP2_DEBUG=$(count_field ip2_debug)
IP2_OTHER=$(count_field ip2_other)
for value in "$IP1_WARN" "$IP1_DEBUG" "$IP1_OTHER" "$IP2_WARN" "$IP2_DEBUG" "$IP2_OTHER"; do
  [[ "$value" =~ ^[0-9]+$ ]] || die "ki28-count 输出非法: $COUNTS"
done

if (( IP1_WARN == 1 && IP1_DEBUG == 39 && IP1_OTHER == 0 )); then
  pass "5.2" "来源 127.0.0.1 的 40 次拒绝：WARN=1、DEBUG=39、其它=0（窗口内采样）"
else
  fail "5.2" "来源 127.0.0.1 的 40 次拒绝日志放大：WARN=$IP1_WARN DEBUG=$IP1_DEBUG OTHER=$IP1_OTHER（期望 1/39/0）"
fi

if (( IP2_WARN == 1 && IP2_DEBUG == 4 && IP2_OTHER == 0 )); then
  pass "5.3" "来源 127.0.0.2 的 5 次拒绝独立采样：WARN=1、DEBUG=4、其它=0（不同 IP 不互相抑制）"
else
  fail "5.3" "来源 127.0.0.2 的采样异常：WARN=$IP2_WARN DEBUG=$IP2_DEBUG OTHER=$IP2_OTHER（期望 1/4/0）"
fi

if (( IP1_WARN + IP2_WARN == 2 )); then
  pass "5.4" "两个来源 IP 合计 WARN=2（每 IP 每窗口首条）"
else
  fail "5.4" "两个来源 IP 合计 WARN=$((IP1_WARN + IP2_WARN))，期望 2"
fi

api GET "/healthz"
if [[ "$STATUS" == "200" ]]; then
  pass "5.5" "连接洪水后 hub 仍健康（拒绝行为未受影响，/healthz=200）"
else
  fail "5.5" "连接洪水后 hub /healthz 异常：$STATUS"
fi
skip "5.6" "采样表 4096 IP 上界与过期清理：公开行为难以在不伪造 4096 个来源 IP 的情况下验证，未独立覆盖（需单测）"

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------

echo "===== v041 e2e: PASS=$PASSES FAIL=$FAILS SKIP=$SKIPS ====="
if (( FAILS > 0 )); then
  echo "当前为 v0.4.1 修复前基线：以上失败是 KI-29/31/28/20 的预期失败；修复后重跑应全绿。" >&2
  exit 1
fi
exit 0
