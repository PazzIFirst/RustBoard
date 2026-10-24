#!/usr/bin/env bash
#
# RustBoard M5 Phase A（v1.0.0）安装器独立 e2e。
#
# 依据（只读设计文档，不参考 install 实现细节）：
#   - docs/plans/2026-10-24-m5-phase-a-installer.md
#   - docs/plans/2026-10-24-m5-install-delivery.md §6 Phase A
#   - 现有 v0.4.x CLI 行为（hub init / agent add / ports / run）
#
# 覆盖：
#   1) 构建 hub/panel/agent debug 二进制；root + systemd 不可用时 FATAL；
#   2) --dry-run 全新 prefix：退出 0、prefix 不存在或为空、零 unit/state 写入；
#   3) 失败回滚：python 占住 admin 端口 → install 非零退出、unit/config/binary
#      /state 不残留、服务已停；
#   4) hub install --panel yes：healthz、panel healthz、配置/私钥/数据目录权限、
#      unit verify、ExecStart 指向 prefix 二进制、state 记录；
#   5) 重复 install：退出 0、config/unit sha256 不变、服务仍 healthy、无第二套；
#   6) agent add → agent install：30s enrollment、hub API 出现、15s 后有
#      cpu.usage 点、agent 配置/私钥 0600、token 不在 unit/ExecStart；
#   7) uninstall：agent/panel 先卸，hub 默认保留 config/data，再 --purge 删除；
#   8) 旧手工配置 upgrade：state 出现 hub 记录、config/cert hash 不变、数据未动。
#
# 顺序说明：/run/systemd/system 下 unit 名固定为 rustboard-{hub,panel,agent}.service。
# 为了避免 dry-run/回滚测试覆盖正在运行的同名 unit，第 2、3 组先于真实安装执行；
# 这仍覆盖方案要求的「全新 prefix dry-run」与「失败回滚」。
#
# 静态目录说明：unit 按设计有 ProtectHome=true，而本仓库在 /root 下，panel 服务
# 读不到 /root/.../web/dist。测试把 web/dist 复制到 $TMP_ROOT/panel-web 后再传
# --panel-static-dir；仍然断言 panel / 返回 200 + index.html，unit 加固断言不放宽。
#
# 临时目录说明：unit 按设计有 PrivateTmp=true，/tmp 与 /var/tmp 都会被 unit
# 私有化；因此临时 prefix 放在真实文件系统 /opt/rustboard-v100.*（ProtectSystem=
# strict 下只读可读，数据目录由 ReadWritePaths 放行），不能用 /tmp 或 /var/tmp。
#
# 约束：
#   - 仅写 /opt/rustboard-v100.* 临时 prefix 与 /run/systemd/system 下本测试
#     的三个 unit；不碰 /etc/rustboard、/var/lib/rustboard、/usr/local/bin；
#   - 所有 unit 在 trap 中 disable --now、删文件、daemon-reload；不 reset-failed；
#   - 不联网；端口随机；token/secret/密码不打印，失败 dump 先 redact；
#   - 失败非零退出，逐条 PASS/FAIL。
#
# 依赖：bash 4.4+、python3 3.8+（仅标准库）、curl、cargo/rustc、systemd、
#       systemd-analyze、timeout、sha256sum。
# 用法：bash tests/e2e/v100-install.sh
# 调试：KEEP_E2E_TMP=1 bash tests/e2e/v100-install.sh
#
set -uo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
HELPER="$SCRIPT_DIR/v100_helper.py"
PYTHON=${PYTHON:-python3}

# 本机 cargo/rustc 不在默认 PATH（父 Agent 环境提醒）。优先使用已存在的
# stable 工具链，不安装任何新工具链；调用方显式设置 CARGO 时以调用方为准。
TOOLCHAIN_BIN="/tmp/rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin"
if [[ -d "$TOOLCHAIN_BIN" ]]; then
  export PATH="$TOOLCHAIN_BIN:$PATH"
fi
if [[ -z "${CARGO:-}" ]]; then
  if [[ -x "$TOOLCHAIN_BIN/cargo" ]]; then
    CARGO="$TOOLCHAIN_BIN/cargo"
  else
    CARGO="cargo"
  fi
fi
export PYTHONDONTWRITEBYTECODE=1

if [[ -z "${CARGO_TARGET_DIR:-}" ]]; then
  export CARGO_TARGET_DIR="$ROOT/target"
fi

PASSES=0
FAILS=0
TMP_ROOT=""
LOG_DIR=""
CLEANUP_UNITS=0
HOLD_PID=""
LAST_CODE=""
LP_HOST=""
LP_PORT=""
PARSED_PORT=""
AGENT_ID_API=""
SERIES_POINTS=0
SERIES_ERR=""

UNIT_DIR="/run/systemd/system"
AGENT_NAME="e2e-agent"

# ---------------------------------------------------------------------------
# 输出与 redact
# ---------------------------------------------------------------------------

pass() {
  PASSES=$((PASSES + 1))
  printf 'PASS [%s] %s\n' "$1" "$2"
}

fail() {
  FAILS=$((FAILS + 1))
  printf 'FAIL [%s] %s\n' "$1" "$2" >&2
}

die() {
  printf 'FATAL: %s\n' "$*" >&2
  if (( PASSES + FAILS > 0 )); then
    printf '===== v100-install e2e: PASS=%s FAIL=%s =====\n' "$PASSES" "$FAILS" >&2
  fi
  exit 1
}

redact_stream() {
  sed -E \
    -e '/(密码|password|passwd|admin_token|token|secret)[^:：=]*[:：=].*/I s/.*/<redacted sensitive line>/' \
    -e 's/(--token(-file)?[[:space:]=]+)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/((admin_token|token|secret|password|passwd)[[:space:]]*=[[:space:]]*)"[^"]*"/\1"<redacted>"/Ig' \
    -e 's/((admin_token|token|secret|password|passwd)[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1<redacted>/Ig' \
    -e 's/((初始)?密码[^:：]*[:：][[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/\b[0-9a-fA-F]{64}\b/<redacted-64hex>/g'
}

dump_log() {
  local file=${1:-} lines=${2:-40}
  [[ -n "$file" && -f "$file" && -s "$file" ]] || return 0
  printf -- '---- %s (tail -n %s, redacted) ----\n' "$(basename -- "$file")" "$lines" >&2
  tail -n "$lines" -- "$file" 2>/dev/null | redact_stream >&2 || true
}

dump_journal() {
  local unit=$1
  printf -- '---- journalctl -u %s (tail, redacted) ----\n' "$unit" >&2
  timeout 10 journalctl -u "$unit" -n 60 --no-pager -o cat 2>/dev/null \
    | redact_stream >&2 || true
}

# ---------------------------------------------------------------------------
# 清理
# ---------------------------------------------------------------------------

# rm -rf 前校验：只允许删 mktemp 生成的 /opt/rustboard-v100.* 目录，且必须是
# /opt 下的真实目录（非符号链接、路径本身不含 ..）。
is_safe_tmp_root() {
  local path=${TMP_ROOT:-} real
  [[ -n "$path" && "$path" == /opt/rustboard-v100.* ]] || return 1
  [[ "$path" != *..* && "$path" != "/" && "$path" != "/opt" ]] || return 1
  [[ -d "$path" && ! -L "$path" ]] || return 1
  [[ "${path%/*}" == "/opt" ]] || return 1
  real=$(readlink -f -- "$path" 2>/dev/null || true)
  [[ -n "$real" && "$real" == "$path" ]] || return 1
  return 0
}

cleanup() {
  local code=$?
  local unit state leftovers

  trap - EXIT INT TERM

  if [[ -n "${HOLD_PID:-}" ]]; then
    kill "$HOLD_PID" 2>/dev/null || true
    wait "$HOLD_PID" 2>/dev/null || true
    HOLD_PID=""
  fi

  if (( CLEANUP_UNITS )); then
    for unit in rustboard-panel.service rustboard-agent.service rustboard-hub.service; do
      systemctl disable --now "$unit" >/dev/null 2>&1 || true
    done
    rm -f -- \
      "$UNIT_DIR/rustboard-hub.service" \
      "$UNIT_DIR/rustboard-panel.service" \
      "$UNIT_DIR/rustboard-agent.service" 2>/dev/null || true
    rm -rf -- \
      "$UNIT_DIR/rustboard-hub.service.d" \
      "$UNIT_DIR/rustboard-panel.service.d" \
      "$UNIT_DIR/rustboard-agent.service.d" 2>/dev/null || true
    rm -f -- \
      "$UNIT_DIR/multi-user.target.wants/rustboard-hub.service" \
      "$UNIT_DIR/multi-user.target.wants/rustboard-panel.service" \
      "$UNIT_DIR/multi-user.target.wants/rustboard-agent.service" 2>/dev/null || true
    # preflight 已确认这三个名字原本不存在；若实现错误地写到 /etc，也一并清掉。
    rm -f -- \
      "/etc/systemd/system/rustboard-hub.service" \
      "/etc/systemd/system/rustboard-panel.service" \
      "/etc/systemd/system/rustboard-agent.service" 2>/dev/null || true
    rm -rf -- \
      "/etc/systemd/system/rustboard-hub.service.d" \
      "/etc/systemd/system/rustboard-panel.service.d" \
      "/etc/systemd/system/rustboard-agent.service.d" 2>/dev/null || true
    find "$UNIT_DIR" /etc/systemd/system -maxdepth 2 -type l \
      \( -name 'rustboard-hub.service' -o -name 'rustboard-panel.service' \
         -o -name 'rustboard-agent.service' \) -delete 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    sleep 0.3

    leftovers=$(find "$UNIT_DIR" /etc/systemd/system -maxdepth 2 \
      \( -name 'rustboard-hub.service' -o -name 'rustboard-panel.service' \
         -o -name 'rustboard-agent.service' \) -print 2>/dev/null || true)
    if [[ -n "$leftovers" ]]; then
      printf 'CLEANUP FAIL: 仍有 unit 文件/符号链接:\n%s\n' "$leftovers" >&2
      (( code == 0 )) && code=1
    fi
    for unit in rustboard-panel.service rustboard-agent.service rustboard-hub.service; do
      state=$(systemctl is-active "$unit" 2>/dev/null || true)
      case "$state" in
        active|reloading|activating|deactivating)
          printf 'CLEANUP FAIL: %s 仍为 %s\n' "$unit" "$state" >&2
          (( code == 0 )) && code=1
          ;;
      esac
    done
  fi

  if (( code != 0 || FAILS > 0 )); then
    printf '===== v100-install e2e 失败现场（日志尾部，已 redact）=====\n' >&2
    dump_log "${LOG_DIR:-}/build.log" 30
    dump_log "${LOG_DIR:-}/dry-run.log" 30
    dump_log "${LOG_DIR:-}/rollback.log" 50
    dump_log "${LOG_DIR:-}/hub-install.log" 60
    dump_log "${LOG_DIR:-}/hub-reinstall.log" 40
    dump_log "${LOG_DIR:-}/agent-add.log" 30
    dump_log "${LOG_DIR:-}/agent-install.log" 50
    dump_log "${LOG_DIR:-}/uninstall-agent.log" 30
    dump_log "${LOG_DIR:-}/uninstall-panel.log" 30
    dump_log "${LOG_DIR:-}/uninstall-hub.log" 40
    dump_log "${LOG_DIR:-}/upgrade-dry.log" 30
    dump_log "${LOG_DIR:-}/upgrade.log" 40
    dump_journal rustboard-hub.service
    dump_journal rustboard-panel.service
    dump_journal rustboard-agent.service
  fi

  if [[ "${KEEP_E2E_TMP:-0}" == "1" ]]; then
    printf '临时目录已保留: %s\n' "${TMP_ROOT:-<unset>}" >&2
  elif is_safe_tmp_root; then
    rm -rf -- "$TMP_ROOT"
  else
    printf '警告: 临时目录未通过安全校验，未删除: %s\n' "${TMP_ROOT:-<unset>}" >&2
  fi

  exit "$code"
}

# ---------------------------------------------------------------------------
# 通用断言
# ---------------------------------------------------------------------------

toml_get() {
  "$PYTHON" "$HELPER" toml-get "$@" 2>/dev/null || true
}

sha256_file() {
  if [[ -f "$1" && ! -L "$1" ]]; then
    sha256sum -- "$1" 2>/dev/null | awk '{print $1}'
  else
    printf '__MISSING__\n'
  fi
}

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$expected]，实际 [$actual]）"
  fi
}

check_file_exists() {
  local id=$1 desc=$2 file=$3
  if [[ -f "$file" && ! -L "$file" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（文件不存在或不是普通文件: $file）"
  fi
}

check_executable() {
  local id=$1 desc=$2 file=$3
  if [[ -f "$file" && -x "$file" && ! -L "$file" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（不存在或不可执行: $file）"
  fi
}

check_absent() {
  local id=$1 desc=$2 path=$3
  if [[ ! -e "$path" && ! -L "$path" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（仍存在: $path）"
  fi
}

check_file_mode() {
  local id=$1 desc=$2 file=$3 expected=$4 mode
  if [[ ! -e "$file" ]]; then
    fail "$id" "$desc（文件不存在: $file）"
    return
  fi
  if [[ -L "$file" ]]; then
    fail "$id" "$desc（是符号链接: $file）"
    return
  fi
  if [[ ! -f "$file" ]]; then
    fail "$id" "$desc（不是普通文件: $file）"
    return
  fi
  mode=$(stat -c '%a' -- "$file" 2>/dev/null || true)
  if [[ "$mode" == "$expected" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（权限期望 $expected，实际 ${mode:-?}）"
  fi
}

check_dir_mode() {
  local id=$1 desc=$2 dir=$3 expected=$4 mode
  if [[ ! -d "$dir" || -L "$dir" ]]; then
    fail "$id" "$desc（目录不存在或不是普通目录: $dir）"
    return
  fi
  mode=$(stat -c '%a' -- "$dir" 2>/dev/null || true)
  if [[ "$mode" == "$expected" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（权限期望 $expected，实际 ${mode:-?}）"
  fi
}

check_rc_zero() {
  local id=$1 desc=$2 log=$3 rc=$4
  if (( rc == 0 )); then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（rc=$rc）"
    dump_log "$log" 50
  fi
}

check_rc_nonzero() {
  local id=$1 desc=$2 log=$3 rc=$4
  if (( rc == 0 )); then
    fail "$id" "$desc（期望非零退出，实际 0；服务可能已启动）"
    dump_log "$log" 50
  elif (( rc == 124 || rc == 137 )); then
    fail "$id" "$desc（命令超时被杀死 rc=$rc）"
    dump_log "$log" 50
  else
    pass "$id" "$desc（rc=$rc）"
  fi
}

parse_listen() {
  local value=$1
  LP_HOST=""
  LP_PORT=""
  if [[ "$value" =~ ^([^:[:space:]]+):([0-9]{1,5})$ ]]; then
    LP_HOST=${BASH_REMATCH[1]}
    LP_PORT=$((10#${BASH_REMATCH[2]}))
    if (( LP_PORT >= 1 && LP_PORT <= 65535 )); then
      return 0
    fi
  fi
  return 1
}

check_listen() {
  local id=$1 desc=$2 value=$3 expected_host=$4 min_port=$5 max_port=$6
  PARSED_PORT=""
  if ! parse_listen "$value"; then
    fail "$id" "$desc（无法解析 listen: [$value]）"
    return
  fi
  if [[ "$LP_HOST" != "$expected_host" ]]; then
    fail "$id" "$desc（host 期望 $expected_host，实际 $LP_HOST）"
    return
  fi
  if (( LP_PORT < min_port || LP_PORT > max_port )); then
    fail "$id" "$desc（端口 $LP_PORT 不在 $min_port–$max_port）"
    return
  fi
  PARSED_PORT=$LP_PORT
  pass "$id" "$desc（$LP_HOST:$LP_PORT）"
}

wait_http_200() {
  local url=$1 timeout_secs=$2 body=$3
  local deadline code
  deadline=$(( $(date +%s%3N) + timeout_secs * 1000 ))
  while :; do
    code=$(curl -sS --noproxy '*' --max-time 2 -o "$body" -w '%{http_code}' \
      "$url" 2>/dev/null) || code="000"
    LAST_CODE=$code
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

check_health() {
  local id=$1 desc=$2 url=$3 body=$4
  local payload
  if wait_http_200 "$url" 20 "$body"; then
    payload=$(tr -d '\r\n' < "$body" 2>/dev/null || true)
    if [[ "$payload" == "ok" ]]; then
      pass "$id" "$desc"
    else
      fail "$id" "$desc（HTTP 200 但 body 不是 ok: [$payload]）"
    fi
  else
    fail "$id" "$desc（20s 内未返回 200，最后状态 $LAST_CODE）"
  fi
}

http_get() {
  local url=$1 token=$2 out=$3 code
  code=$(curl -sS --noproxy '*' --max-time 20 -o "$out" -w '%{http_code}' \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/json' \
    "$url" 2>"$TMP_ROOT/curl.err") || code="000"
  printf '%s' "$code"
}

check_agents_api() {
  local id=$1 desc=$2 code count body="$TMP_ROOT/agents.json"
  code=$(http_get "$ADMIN_URL/api/v1/agents" "$ADMIN_TOKEN" "$body")
  if [[ "$code" != "200" ]]; then
    fail "$id" "$desc（GET /api/v1/agents 期望 200，实际 $code）"
    return
  fi
  count=$("$PYTHON" "$HELPER" agents-count "$body" 2>/dev/null || true)
  if [[ "$count" =~ ^[0-9]+$ ]]; then
    pass "$id" "$desc（$count 条 agent 记录）"
  else
    fail "$id" "$desc（200 但响应不是 JSON 数组，count=[$count]）"
  fi
}

check_unit_verify() {
  local id=$1 desc=$2 file=$3 out rc
  if [[ ! -f "$file" ]]; then
    fail "$id" "$desc（unit 文件不存在: $file）"
    return
  fi
  out=$(timeout 30 systemd-analyze verify "$file" 2>&1)
  rc=$?
  if (( rc == 0 )); then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（systemd-analyze verify rc=$rc: $(printf '%s' "$out" | tail -n 3 | tr '\n' ' ' | redact_stream)）"
  fi
}

check_unit_execstart() {
  local id=$1 desc=$2 file=$3 expected_bin=$4 args first
  args=$("$PYTHON" "$HELPER" unit-execstart "$file" 2>/dev/null || true)
  if [[ -z "$args" || "$args" == "__MISSING__" || "$args" == "__MULTI__" ]]; then
    fail "$id" "$desc（无法从 ExecStart 解析出 argv0，值 [$args]）"
    return
  fi
  read -r first _ <<< "$args"
  if [[ "$first" == "$expected_bin" ]]; then
    pass "$id" "$desc（$first）"
  else
    fail "$id" "$desc（ExecStart argv0 期望 $expected_bin，实际 [$first]）"
  fi
}

check_unit_hardening() {
  local id=$1 desc=$2 file=$3 data_dir=$4 out rc
  out=$("$PYTHON" "$HELPER" unit-hardening-check "$file" "$data_dir" 2>&1)
  rc=$?
  if (( rc == 0 )); then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（缺少/不匹配: $(printf '%s' "$out" | tr '\n' '; ')）"
  fi
}

check_unit_active() {
  local id=$1 desc=$2 unit=$3 state
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  if [[ "$state" == "active" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（$unit 状态 [$state]，期望 active）"
  fi
}

check_unit_absent() {
  local id=$1 desc=$2 unit=$3 path="$UNIT_DIR/$unit" state leftover
  if [[ -e "$path" || -L "$path" || -e "/etc/systemd/system/$unit" || -L "/etc/systemd/system/$unit" ]]; then
    fail "$id" "$desc（unit 文件仍存在: $path）"
    return
  fi
  leftover=$(find "$UNIT_DIR" /etc/systemd/system -maxdepth 2 -name "$unit" \
    -print -quit 2>/dev/null || true)
  if [[ -n "$leftover" ]]; then
    fail "$id" "$desc（仍有 unit 文件/符号链接: $leftover）"
    return
  fi
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  case "$state" in
    active|reloading|activating|deactivating)
      fail "$id" "$desc（服务仍为 $state）"
      ;;
    *)
      pass "$id" "$desc（unit 不存在且服务已停，状态 [${state:-unknown}]）"
      ;;
  esac
}

check_hash_unchanged() {
  local id=$1 desc=$2 before=$3 after=$4
  if [[ "$before" == "__MISSING__" ]]; then
    fail "$id" "$desc（变更前文件缺失，无法比较）"
  elif [[ "$before" == "$after" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（sha256 变化: $before -> $after）"
  fi
}

state_role_exists() {
  local role=$1 file=${2:-${STATE:-}}
  if [[ -z "$file" || ! -f "$file" ]]; then
    echo "no"
    return
  fi
  "$PYTHON" "$HELPER" toml-section-exists "$file" "roles.$role" 2>/dev/null || echo "no"
}

check_state_role() {
  local id=$1 desc=$2 role=$3 ecfg=$4 edata=$5 eunit=$6 ebin=$7
  local cfg data unit bin
  if [[ ! -f "$STATE" ]]; then
    fail "$id" "$desc（$STATE 不存在）"
    return
  fi
  cfg=$(toml_get "$STATE" "roles.$role" config)
  data=$(toml_get "$STATE" "roles.$role" data_dir)
  unit=$(toml_get "$STATE" "roles.$role" unit)
  bin=$(toml_get "$STATE" "roles.$role" binary)
  if [[ "$cfg" == "$ecfg" && "$data" == "$edata" && "$unit" == "$eunit" && "$bin" == "$ebin" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（config=[$cfg] data=[$data] unit=[$unit] binary=[$bin]）"
  fi
}

check_no_state_role() {
  local id=$1 desc=$2 role=$3 exists
  exists=$(state_role_exists "$role")
  if [[ "$exists" == "no" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（install-state 仍有 roles.$role）"
  fi
}

wait_files() {
  local timeout_secs=$1
  shift
  local deadline
  deadline=$(( $(date +%s%3N) + timeout_secs * 1000 ))
  while :; do
    local file all=1
    for file in "$@"; do
      if [[ ! -s "$file" ]]; then
        all=0
        break
      fi
    done
    if (( all )); then
      return 0
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.2
  done
}

wait_agent_listed() {
  local timeout_secs=$1 deadline body="$TMP_ROOT/agent-list.json" code aid
  deadline=$(( $(date +%s%3N) + timeout_secs * 1000 ))
  LAST_CODE=""
  AGENT_ID_API=""
  while :; do
    code=$(http_get "$ADMIN_URL/api/v1/agents" "$ADMIN_TOKEN" "$body")
    LAST_CODE=$code
    if [[ "$code" == "200" ]]; then
      aid=$("$PYTHON" "$HELPER" agent-id "$body" "$AGENT_NAME" 2>/dev/null || true)
      if [[ -n "$aid" && "$aid" != "__MISSING__" && "$aid" != "__ERR__" ]]; then
        AGENT_ID_API=$aid
        return 0
      fi
    fi
    if (( $(date +%s%3N) >= deadline )); then
      return 1
    fi
    sleep 0.5
  done
}

check_agent_series() {
  local deadline now from to url body="$TMP_ROOT/agent-series.json"
  local code points
  SERIES_ERR=""
  if [[ ! "$AGENT_ID_API" =~ ^[A-Za-z0-9._:-]+$ ]]; then
    SERIES_ERR="agent_id 不可用于 URL: [$AGENT_ID_API]"
    return 1
  fi
  # 方案要求 enrollment 后等 15s 再确认数据点。
  sleep 15
  deadline=$(( $(date +%s%3N) + 20000 ))
  LAST_CODE=""
  SERIES_POINTS=0
  while :; do
    now=$(date +%s%3N)
    from=$((now - 3600000))
    to=$now
    url="${ADMIN_URL}/api/v1/agents/${AGENT_ID_API}/series?metric=cpu.usage&from=${from}&to=${to}"
    code=$(http_get "$url" "$ADMIN_TOKEN" "$body")
    LAST_CODE=$code
    if [[ "$code" == "200" ]]; then
      points=$("$PYTHON" "$HELPER" series-points "$body" cpu.usage 2>/dev/null || true)
      if [[ "$points" =~ ^[0-9]+$ ]] && (( points > 0 )); then
        SERIES_POINTS=$points
        return 0
      fi
    fi
    if (( $(date +%s%3N) >= deadline )); then
      SERIES_ERR="最后 HTTP $LAST_CODE，points=$SERIES_POINTS"
      return 1
    fi
    sleep 1
  done
}

check_token_not_leaked() {
  local id=$1 desc=$2 unit file show found=0
  if [[ ! -s "$TOKEN_FILE" ]]; then
    fail "$id" "$desc（token 文件缺失，无法验证）"
    return
  fi
  if [[ ! -f "$UNIT_DIR/rustboard-agent.service" ]]; then
    fail "$id" "$desc（agent unit 缺失，无法验证）"
    return
  fi
  for unit in rustboard-hub.service rustboard-panel.service rustboard-agent.service; do
    file="$UNIT_DIR/$unit"
    [[ -f "$file" ]] || continue
    if grep -qF -f "$TOKEN_FILE" "$file" 2>/dev/null; then
      found=1
    fi
  done
  show=$(systemctl show -p ExecStart rustboard-agent.service 2>/dev/null || true)
  if [[ -z "$show" ]]; then
    fail "$id" "$desc（无法读取 systemctl show -p ExecStart）"
    return
  fi
  if printf '%s\n' "$show" | grep -qF -f "$TOKEN_FILE" 2>/dev/null; then
    found=1
  fi
  if (( found )); then
    fail "$id" "$desc（enrollment token 出现在 unit 文件或 ExecStart；内容已隐藏）"
  else
    pass "$id" "$desc"
  fi
}

check_no_live_units() {
  local id=$1 desc=$2 leftovers active_any="" unit state
  leftovers=$(find "$UNIT_DIR" /etc/systemd/system -maxdepth 2 \
    \( -name 'rustboard-hub.service' -o -name 'rustboard-panel.service' \
       -o -name 'rustboard-agent.service' \) -print 2>/dev/null || true)
  for unit in rustboard-hub.service rustboard-panel.service rustboard-agent.service; do
    state=$(systemctl is-active "$unit" 2>/dev/null || true)
    case "$state" in
      active|reloading|activating|deactivating) active_any="$active_any $unit($state)";;
    esac
  done
  if [[ -z "$leftovers" && -z "$active_any" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（文件: [$leftovers]；活动服务: [$active_any]）"
  fi
}

check_no_production_paths() {
  local id=$1 desc=$2 found=""
  local path
  for path in /etc/rustboard /var/lib/rustboard /var/lib/rustboard/install-state.toml; do
    if [[ -e "$path" || -L "$path" ]]; then
      found="$found $path"
    fi
  done
  for path in /usr/local/bin/rustboard-hub /usr/local/bin/rustboard-panel /usr/local/bin/rustboard-agent; do
    if [[ -e "$path" || -L "$path" ]]; then
      found="$found $path"
    fi
  done
  if [[ -z "$found" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（测试写到了生产路径:$found；不会自动删除，请人工检查）"
  fi
}

# 仅用于测试组之间隔离：preflight 已确认三个 unit 名原本都不存在，因此这里
# disable/删除的一定是本测试在上一步（尤其是失败路径）留下的 unit。
reset_test_units() {
  local unit
  (( CLEANUP_UNITS )) || return 0
  for unit in rustboard-panel.service rustboard-agent.service rustboard-hub.service; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
  done
  rm -f -- \
    "$UNIT_DIR/rustboard-hub.service" \
    "$UNIT_DIR/rustboard-panel.service" \
    "$UNIT_DIR/rustboard-agent.service" 2>/dev/null || true
  rm -rf -- \
    "$UNIT_DIR/rustboard-hub.service.d" \
    "$UNIT_DIR/rustboard-panel.service.d" \
    "$UNIT_DIR/rustboard-agent.service.d" 2>/dev/null || true
  rm -f -- \
    "$UNIT_DIR/multi-user.target.wants/rustboard-hub.service" \
    "$UNIT_DIR/multi-user.target.wants/rustboard-panel.service" \
    "$UNIT_DIR/multi-user.target.wants/rustboard-agent.service" 2>/dev/null || true
  rm -f -- \
    "/etc/systemd/system/rustboard-hub.service" \
    "/etc/systemd/system/rustboard-panel.service" \
    "/etc/systemd/system/rustboard-agent.service" 2>/dev/null || true
  rm -rf -- \
    "/etc/systemd/system/rustboard-hub.service.d" \
    "/etc/systemd/system/rustboard-panel.service.d" \
    "/etc/systemd/system/rustboard-agent.service.d" 2>/dev/null || true
  find "$UNIT_DIR" /etc/systemd/system -maxdepth 2 -type l \
    \( -name 'rustboard-hub.service' -o -name 'rustboard-panel.service' \
       -o -name 'rustboard-agent.service' \) -delete 2>/dev/null || true
  systemctl daemon-reload >/dev/null 2>&1 || true
  sleep 0.2
}

# ---------------------------------------------------------------------------
# 初始化临时目录并安装 trap
# ---------------------------------------------------------------------------

TMP_ROOT=$(mktemp -d /opt/rustboard-v100.XXXXXX 2>/dev/null) \
  || { printf 'FATAL: 无法在 /opt 创建临时目录（PrivateTmp 会私有化 /tmp 与 /var/tmp）\n' >&2; exit 1; }
trap cleanup EXIT
trap 'exit 130' INT TERM
chmod 700 "$TMP_ROOT"
LOG_DIR="$TMP_ROOT/log"
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR"

# ---------------------------------------------------------------------------
# 1. 预检与构建
# ---------------------------------------------------------------------------

echo "==> 1/9 预检与构建（临时根目录 $TMP_ROOT）"

[[ -f "$HELPER" ]] || die "缺少 helper: $HELPER"
[[ "$(id -u)" == "0" ]] || die "安装器 e2e 需要 root（当前 euid=$(id -u)）"
[[ -d "$UNIT_DIR" ]] || die "systemd 不可用：$UNIT_DIR 不存在（FATAL）"
[[ "$(cat /proc/1/comm 2>/dev/null || true)" == "systemd" ]] \
  || die "PID 1 不是 systemd（FATAL）"
systemctl show-environment >/dev/null 2>&1 \
  || die "systemctl 不可用（FATAL）"
systemd-analyze --version >/dev/null 2>&1 \
  || die "systemd-analyze 不可用（FATAL）"
[[ -w /opt ]] || die "/opt 不可写（FATAL）"
[[ -w "$UNIT_DIR" ]] || die "$UNIT_DIR 不可写（FATAL）"
[[ -f "$ROOT/web/dist/index.html" ]] \
  || die "缺少 $ROOT/web/dist/index.html（面板静态目录必需）"

for tool in "$PYTHON" "$CARGO" curl systemctl systemd-analyze timeout sha256sum stat find grep sed awk mktemp date readlink; do
  command -v "$tool" >/dev/null 2>&1 || die "找不到命令: $tool"
done

# 不碰生产安装：即使调用方已经装了 RustBoard，也拒绝在同一个命名空间里测试。
for path in /etc/rustboard /var/lib/rustboard; do
  [[ -e "$path" || -L "$path" ]] && die "检测到生产目录 $path，拒绝运行（不碰生产）"
done
for path in /usr/local/bin/rustboard-hub /usr/local/bin/rustboard-panel /usr/local/bin/rustboard-agent; do
  [[ -e "$path" || -L "$path" ]] && die "检测到生产二进制 $path，拒绝运行（不碰生产）"
done

for unit in rustboard-hub.service rustboard-panel.service rustboard-agent.service; do
  existing=$(find "$UNIT_DIR" /etc/systemd/system -maxdepth 2 -name "$unit" \
    -print -quit 2>/dev/null || true)
  [[ -z "$existing" ]] || die "已存在同名 unit 路径 $existing，拒绝运行"
  for path in "$UNIT_DIR/$unit" "/etc/systemd/system/$unit"; do
    [[ -e "$path" || -L "$path" ]] && die "已存在同名 unit 文件 $path，拒绝运行"
  done
  state=$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)
  [[ "$state" == "not-found" ]] \
    || die "已存在同名 unit $unit（LoadState=$state），拒绝运行"
done
CLEANUP_UNITS=1
pass "1.1" "root + systemd + 工具齐全，且测试前无同名 unit/生产安装"

BUILD_LOG="$LOG_DIR/build.log"
TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
if [[ "$TARGET_DIR" != /* ]]; then
  TARGET_DIR="$ROOT/$TARGET_DIR"
fi
BIN_DIR="$TARGET_DIR/debug"
HUB_BIN="$BIN_DIR/rustboard-hub"
AGENT_BIN="$BIN_DIR/rustboard-agent"
PANEL_BIN="$BIN_DIR/rustboard-panel"

echo "==> cargo build --locked -p rustboard-hub -p rustboard-panel -p rustboard-agent"
if ! (cd "$ROOT" && timeout --kill-after=10 2400 "$CARGO" build --locked \
      -p rustboard-hub -p rustboard-panel -p rustboard-agent) > "$BUILD_LOG" 2>&1; then
  fail "1.2" "cargo build 失败"
  dump_log "$BUILD_LOG" 60
  die "三个 debug 二进制构建失败，无法继续"
fi
pass "1.2" "cargo build（locked）成功"

missing_bins=0
for bin in "$HUB_BIN" "$AGENT_BIN" "$PANEL_BIN"; do
  if [[ ! -x "$bin" ]]; then
    fail "1.3" "构建产物不可执行: $bin"
    missing_bins=1
  fi
done
if (( missing_bins == 0 )); then
  pass "1.3" "rustboard-hub / rustboard-panel / rustboard-agent debug 二进制可执行"
else
  die "构建产物缺失，无法继续"
fi

# ---------------------------------------------------------------------------
# 2. --dry-run（先于真实安装，避免同名 unit 冲突）
# ---------------------------------------------------------------------------

echo "==> 2/9 --dry-run 全新 prefix"

DRY_PREFIX="$TMP_ROOT/prefix-dry"
DRY_LOG="$LOG_DIR/dry-run.log"
DRY_ARGS=(
  install --dry-run --yes --prefix "$DRY_PREFIX"
  --systemd --unit-dir "$UNIT_DIR" --panel no
  --san 127.0.0.1 --advertise 127.0.0.1
)
timeout --kill-after=10 120 "$HUB_BIN" "${DRY_ARGS[@]}" > "$DRY_LOG" 2>&1
DRY_RC=$?
check_rc_zero "2.1" "--dry-run hub install 退出码 0" "$DRY_LOG" "$DRY_RC"

if [[ ! -e "$DRY_PREFIX" ]]; then
  pass "2.2" "--dry-run 未创建 prefix（$DRY_PREFIX 不存在）"
elif [[ -d "$DRY_PREFIX" && -z "$(find "$DRY_PREFIX" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  pass "2.2" "--dry-run 只创建了空 prefix 目录"
else
  fail "2.2" "--dry-run 之后 prefix 存在非空内容: $(find "$DRY_PREFIX" -mindepth 1 -maxdepth 2 -print 2>/dev/null | head -n 5 | tr '\n' ' ')"
fi

check_absent "2.3" "--dry-run 未写 install-state.toml" "$DRY_PREFIX/var/lib/rustboard/install-state.toml"
check_unit_absent "2.4" "--dry-run 未创建/启动 hub unit" "rustboard-hub.service"
check_unit_absent "2.5" "--dry-run 未创建/启动 panel unit" "rustboard-panel.service"
# 若 dry-run 有 bug 留下 unit，先清掉再做真实安装，避免同名 unit 互相污染。
reset_test_units

# ---------------------------------------------------------------------------
# 3. 失败回滚（P2；此时还没有真实安装，unit 名无冲突）
# ---------------------------------------------------------------------------

echo "==> 3/9 失败回滚（占用 admin 端口）"

P2="$TMP_ROOT/prefix-rollback"
HOLD_PORT_FILE="$TMP_ROOT/held-port"
HOLD_LOG="$LOG_DIR/held-port.log"
ROLLBACK_LOG="$LOG_DIR/rollback.log"

"$PYTHON" "$HELPER" hold-port "$HOLD_PORT_FILE" > "$HOLD_LOG" 2>&1 &
HOLD_PID=$!
for _ in {1..100}; do
  [[ -s "$HOLD_PORT_FILE" ]] && break
  kill -0 "$HOLD_PID" 2>/dev/null || break
  sleep 0.1
done
if [[ ! -s "$HOLD_PORT_FILE" ]]; then
  die "python 未能占住回环端口（见 $HOLD_LOG）"
fi
OCCUPIED_PORT=$(tr -d '[:space:]' < "$HOLD_PORT_FILE")
[[ "$OCCUPIED_PORT" =~ ^[0-9]+$ ]] || die "占用端口解析失败: [$OCCUPIED_PORT]"
kill -0 "$HOLD_PID" 2>/dev/null || die "占端口进程提前退出"
pass "3.1" "python 已占住 127.0.0.1:$OCCUPIED_PORT（用于 admin 端口冲突）"

timeout --kill-after=10 180 "$HUB_BIN" install --yes --prefix "$P2" \
  --admin-listen "127.0.0.1:${OCCUPIED_PORT}" --panel no \
  --systemd --unit-dir "$UNIT_DIR" > "$ROLLBACK_LOG" 2>&1
ROLLBACK_RC=$?
check_rc_nonzero "3.2" "被占端口导致 hub install 非零退出" "$ROLLBACK_LOG" "$ROLLBACK_RC"
if [[ ! -s "$ROLLBACK_LOG" ]]; then
  fail "3.2a" "安装失败但没有任何输出，无法确认不是 CLI 缺失（避免假阳性）"
elif grep -Eqi 'unrecognized subcommand|invalid subcommand|unexpected argument|Usage: rustboard-hub' \
    "$ROLLBACK_LOG"; then
  fail "3.2a" "回滚失败原因疑似 CLI 不存在/参数错误，而不是端口冲突（避免假阳性）"
elif ! grep -Eqi '健康检查|healthz' "$ROLLBACK_LOG"; then
  # 端口冲突应当表现为启动/健康检查失败；若日志里连这个词都没有，失败可能
  # 发生在更早的无关步骤（例如路径预检），这条用例就失去了注入意义。
  fail "3.2a" "失败日志缺少 健康检查/healthz 证据，无法确认是端口冲突导致启动/健康失败（避免无关早退的假阳性）"
else
  pass "3.2a" "失败输出包含健康检查/healthz，且不是 CLI 缺失/参数错误"
fi

if kill -0 "$HOLD_PID" 2>/dev/null; then
  pass "3.3" "整个安装尝试期间端口保持被占用（回滚断言有效）"
else
  fail "3.3" "占端口进程在 install 结束前退出，回滚断言无效"
fi
kill "$HOLD_PID" 2>/dev/null || true
wait "$HOLD_PID" 2>/dev/null || true
HOLD_PID=""

check_unit_absent "3.4" "失败后 hub unit 不残留、服务已停" "rustboard-hub.service"
rollback_units=$(find "$P2" \( -type f -o -type l \) -name '*.service' -print 2>/dev/null || true)
if [[ -z "$rollback_units" ]]; then
  pass "3.5" "P2 prefix 下没有剩余 unit 文件"
else
  fail "3.5" "P2 prefix 下仍有 unit 文件: $rollback_units"
fi
check_absent "3.6" "失败后 config 已回滚（$P2/etc/rustboard/hub.toml 不存在）" \
  "$P2/etc/rustboard/hub.toml"
check_absent "3.7" "失败后 prefix 内 binary 已回滚" \
  "$P2/usr/local/bin/rustboard-hub"
if [[ ! -f "$P2/var/lib/rustboard/install-state.toml" ]] \
  || [[ "$(state_role_exists hub "$P2/var/lib/rustboard/install-state.toml")" == "no" ]]; then
  pass "3.8" "失败后 install-state 无 hub 记录"
else
  fail "3.8" "失败后 install-state 仍有 hub 记录"
fi
# 本次安装新建的数据目录（含证书/DB）也必须随事务回滚整体删除；
# 这里只断言 P2 这个全新 prefix，不涉及任何预存在数据目录。
check_absent "3.9" "失败后本次新建的 hub 数据目录已整体删除" \
  "$P2/var/lib/rustboard/hub"
reset_test_units

# ---------------------------------------------------------------------------
# 4. hub 安装（--panel yes）
# ---------------------------------------------------------------------------

echo "==> 4/9 hub install --panel yes"

P="$TMP_ROOT/prefix-hub"
HUB_CFG="$P/etc/rustboard/hub.toml"
HUB_DATA="$P/var/lib/rustboard/hub"
HUB_UNIT="$UNIT_DIR/rustboard-hub.service"
HUB_INSTALLED_BIN="$P/usr/local/bin/rustboard-hub"
STATE="$P/var/lib/rustboard/install-state.toml"
PANEL_CFG="$P/etc/rustboard/panel.toml"
PANEL_DATA="$P/var/lib/rustboard/panel"
PANEL_UNIT="$UNIT_DIR/rustboard-panel.service"
PANEL_INSTALLED_BIN="$P/usr/local/bin/rustboard-panel"

HUB_INSTALL_LOG="$LOG_DIR/hub-install.log"

# unit 按设计有 ProtectHome=true，而仓库在 /root 下；panel 服务看不到 /root。
# 为保持静态目录断言与 unit 加固断言都不放宽，把 web/dist 复制到临时目录
# 再传给 --panel-static-dir（生产默认是 /usr/share/rustboard/web）。
PANEL_STATIC="$TMP_ROOT/panel-web"
mkdir -p "$PANEL_STATIC"
if ! cp -a "$ROOT/web/dist/." "$PANEL_STATIC/" 2>"$TMP_ROOT/panel-web-copy.err"; then
  dump_log "$TMP_ROOT/panel-web-copy.err" 10
  die "复制 web/dist 到 $PANEL_STATIC 失败"
fi
chmod -R a+rX "$PANEL_STATIC"
if [[ -f "$PANEL_STATIC/index.html" ]]; then
  pass "4.0" "已将 web/dist 复制到 $PANEL_STATIC（绕过 ProtectHome 对 /root 的遮蔽）"
else
  die "复制后的 panel 静态目录缺少 index.html"
fi

HUB_INSTALL_ARGS=(
  install --yes --prefix "$P" --systemd --unit-dir "$UNIT_DIR"
  --panel yes --panel-static-dir "$PANEL_STATIC"
  --san 127.0.0.1 --advertise 127.0.0.1
)
timeout --kill-after=10 240 "$HUB_BIN" "${HUB_INSTALL_ARGS[@]}" > "$HUB_INSTALL_LOG" 2>&1
HUB_INSTALL_RC=$?
check_rc_zero "4.1" "hub install 退出码 0" "$HUB_INSTALL_LOG" "$HUB_INSTALL_RC"

# 首次安装会由 hub 调起 panel install，面板自动生成的初始密码只打印一次。
# 只计数、不打印内容；redact 只在失败 dump 时处理日志，不影响这里的原始日志计数。
INITIAL_PASSWORD_COUNT=$(grep -o '初始密码' "$HUB_INSTALL_LOG" 2>/dev/null \
  | wc -l | tr -d '[:space:]' || true)
if [[ "$INITIAL_PASSWORD_COUNT" == "1" ]]; then
  pass "4.1a" "hub 安装日志中初始密码只出现 1 次（不打印内容）"
else
  fail "4.1a" "hub 安装日志中初始密码期望出现 1 次，实际 ${INITIAL_PASSWORD_COUNT:-0} 次"
fi

check_file_mode "4.2" "hub 配置存在且 0600" "$HUB_CFG" 600
check_dir_mode "4.3" "hub 数据目录 0700" "$HUB_DATA" 700
check_eq "4.4" "hub 配置 data_dir 指向 prefix 数据目录" "$HUB_DATA" \
  "$(toml_get "$HUB_CFG" - data_dir)"
check_file_mode "4.5" "hub 服务端私钥 0600" "$HUB_DATA/certs/server.key" 600
check_file_mode "4.6" "hub CA 私钥 0600" "$HUB_DATA/certs/ca.key" 600

check_file_exists "4.7" "hub unit 文件存在（--unit-dir 覆盖生效）" "$HUB_UNIT"
check_absent "4.7a" "--unit-dir 覆盖后 prefix 内没有重复 hub unit" \
  "$P/etc/systemd/system/rustboard-hub.service"
check_absent "4.7b" "--unit-dir 覆盖后 /etc 内没有重复 hub unit" \
  "/etc/systemd/system/rustboard-hub.service"
check_unit_verify "4.8" "hub unit 通过 systemd-analyze verify" "$HUB_UNIT"
check_unit_execstart "4.9" "hub ExecStart 指向 prefix 内二进制" "$HUB_UNIT" "$HUB_INSTALLED_BIN"
check_unit_hardening "4.10" "hub unit 关键加固指令齐全且 ReadWritePaths 仅指向数据目录" \
  "$HUB_UNIT" "$HUB_DATA"

ADMIN_LISTEN=$(toml_get "$HUB_CFG" - admin_listen)
check_listen "4.11" "admin_listen 为回环随机端口" "$ADMIN_LISTEN" "127.0.0.1" 20000 64999
ADMIN_PORT=$PARSED_PORT
ADMIN_URL="http://127.0.0.1:${ADMIN_PORT:-0}"
ADMIN_TOKEN=$(toml_get "$HUB_CFG" - admin_token)
if [[ -n "$ADMIN_TOKEN" && "$ADMIN_TOKEN" != "__MISSING__" && "$ADMIN_TOKEN" != "__MULTI__" ]]; then
  pass "4.12" "hub 配置含非空 admin_token（不打印内容，长度 ${#ADMIN_TOKEN}）"
else
  fail "4.12" "hub 配置缺少可用 admin_token"
fi
check_health "4.13" "hub /healthz 20s 内返回 200 且 body=ok" \
  "${ADMIN_URL}/healthz" "$TMP_ROOT/hub-health.body"
check_agents_api "4.14" "Bearer admin_token 访问 /api/v1/agents 返回 200 且为 JSON 数组"

check_file_mode "4.15" "install-state.toml 0600" "$STATE" 600
check_eq "4.16" "install-state schema=1" "1" "$(toml_get "$STATE" - schema)"
check_state_role "4.17" "install-state 有 hub 记录且路径正确" "hub" \
  "$HUB_CFG" "$HUB_DATA" "$HUB_UNIT" "$HUB_INSTALLED_BIN"

AGENT_LISTEN=$(toml_get "$HUB_CFG" - agent_listen)
check_listen "4.18" "agent_listen 默认 0.0.0.0 + 随机端口" "$AGENT_LISTEN" "0.0.0.0" 20000 64999
AGENT_PORT=$PARSED_PORT

check_file_mode "4.19" "panel 配置存在且 0600" "$PANEL_CFG" 600
PANEL_LISTEN=$(toml_get "$PANEL_CFG" - listen)
check_listen "4.20" "panel listen 为回环随机端口" "$PANEL_LISTEN" "127.0.0.1" 20000 64999
PANEL_PORT=$PARSED_PORT
PANEL_URL="http://127.0.0.1:${PANEL_PORT:-0}"
check_file_exists "4.21" "panel unit 文件存在" "$PANEL_UNIT"
check_absent "4.21a" "--unit-dir 覆盖后 prefix 内没有重复 panel unit" \
  "$P/etc/systemd/system/rustboard-panel.service"
check_absent "4.21b" "--unit-dir 覆盖后 /etc 内没有重复 panel unit" \
  "/etc/systemd/system/rustboard-panel.service"
check_unit_verify "4.22" "panel unit 通过 systemd-analyze verify" "$PANEL_UNIT"
check_unit_execstart "4.23" "panel ExecStart 指向 prefix 内二进制" "$PANEL_UNIT" "$PANEL_INSTALLED_BIN"
check_unit_hardening "4.24" "panel unit 关键加固指令齐全" "$PANEL_UNIT" "$PANEL_DATA"
check_health "4.25" "panel /healthz 20s 内返回 200 且 body=ok" \
  "${PANEL_URL}/healthz" "$TMP_ROOT/panel-health.body"

panel_index_code=$(curl -sS --noproxy '*' --max-time 20 -o "$TMP_ROOT/panel-index.html" \
  -w '%{http_code}' "${PANEL_URL}/" 2>/dev/null) || panel_index_code="000"
if [[ "$panel_index_code" == "200" ]] && grep -q 'id="root"' "$TMP_ROOT/panel-index.html"; then
  pass "4.26" "panel 静态目录生效：/ 返回 200 且含 index.html 的 id=\"root\""
else
  fail "4.26" "panel 静态目录异常：/ 返回 $panel_index_code（期望 200 + id=\"root\"）"
fi
check_state_role "4.27" "install-state 有 panel 记录且复用同一 prefix" "panel" \
  "$PANEL_CFG" "$PANEL_DATA" "$PANEL_UNIT" "$PANEL_INSTALLED_BIN"

# ---------------------------------------------------------------------------
# 5. 重复 install 幂等
# ---------------------------------------------------------------------------

echo "==> 5/9 重复 hub install（幂等）"

HUB_CFG_HASH_BEFORE=$(sha256_file "$HUB_CFG")
HUB_UNIT_HASH_BEFORE=$(sha256_file "$HUB_UNIT")
PANEL_CFG_HASH_BEFORE=$(sha256_file "$PANEL_CFG")
PANEL_UNIT_HASH_BEFORE=$(sha256_file "$PANEL_UNIT")

HUB_REINSTALL_LOG="$LOG_DIR/hub-reinstall.log"
timeout --kill-after=10 240 "$HUB_BIN" "${HUB_INSTALL_ARGS[@]}" > "$HUB_REINSTALL_LOG" 2>&1
REINSTALL_RC=$?
check_rc_zero "5.1" "重复执行同一 hub install 退出码 0" "$HUB_REINSTALL_LOG" "$REINSTALL_RC"

check_hash_unchanged "5.2" "hub 配置 sha256 不变" \
  "$HUB_CFG_HASH_BEFORE" "$(sha256_file "$HUB_CFG")"
check_hash_unchanged "5.3" "hub unit sha256 不变" \
  "$HUB_UNIT_HASH_BEFORE" "$(sha256_file "$HUB_UNIT")"
check_hash_unchanged "5.4" "panel 配置 sha256 不变" \
  "$PANEL_CFG_HASH_BEFORE" "$(sha256_file "$PANEL_CFG")"
check_hash_unchanged "5.5" "panel unit sha256 不变" \
  "$PANEL_UNIT_HASH_BEFORE" "$(sha256_file "$PANEL_UNIT")"

hub_cfg_count=$(find "$P/etc/rustboard" -maxdepth 1 -type f -name 'hub.toml' 2>/dev/null | wc -l | tr -d '[:space:]')
hub_unit_count=$(find "$UNIT_DIR" -maxdepth 1 -name 'rustboard-hub.service' 2>/dev/null | wc -l | tr -d '[:space:]')
check_eq "5.6" "没有第二套 hub 配置/unit" "1 1" "$hub_cfg_count $hub_unit_count"
check_health "5.7" "重复安装后 hub 仍 healthy" \
  "${ADMIN_URL}/healthz" "$TMP_ROOT/hub-health-2.body"
check_health "5.8" "重复安装后 panel 仍 healthy" \
  "${PANEL_URL}/healthz" "$TMP_ROOT/panel-health-2.body"
check_unit_active "5.9" "hub service 仍 active" "rustboard-hub.service"
check_unit_active "5.10" "panel service 仍 active" "rustboard-panel.service"

# ---------------------------------------------------------------------------
# 6. agent 纳管
# ---------------------------------------------------------------------------

echo "==> 6/9 agent add → agent install → enrollment → 数据点"

AGENT_CFG="$P/etc/rustboard/agent.toml"
AGENT_DATA="$P/var/lib/rustboard/agent"
AGENT_UNIT="$UNIT_DIR/rustboard-agent.service"
AGENT_INSTALLED_BIN="$P/usr/local/bin/rustboard-agent"
TOKEN_FILE="$TMP_ROOT/enroll-token"
AGENT_ADD_LOG="$LOG_DIR/agent-add.log"
AGENT_INSTALL_LOG="$LOG_DIR/agent-install.log"
PARSE_ERR="$TMP_ROOT/agent-add-parse.err"

timeout --kill-after=10 60 "$HUB_BIN" agent add --config "$HUB_CFG" --name "$AGENT_NAME" \
  > "$AGENT_ADD_LOG" 2>&1
AGENT_ADD_RC=$?
check_rc_zero "6.1" "hub agent add 退出码 0" "$AGENT_ADD_LOG" "$AGENT_ADD_RC"

PARSE_OUT=$("$PYTHON" "$HELPER" agent-add-parse "$AGENT_ADD_LOG" "$TOKEN_FILE" \
  2>"$PARSE_ERR")
PARSE_RC=$?
FPR=$(printf '%s\n' "$PARSE_OUT" | sed -n 's/^fpr=//p')
TOKEN_LEN=$(printf '%s\n' "$PARSE_OUT" | sed -n 's/^token_len=//p')
if (( PARSE_RC == 0 )) && [[ "$FPR" =~ ^[0-9a-f]{64}$ ]] && [[ "$TOKEN_LEN" == "64" ]]; then
  pass "6.2" "从 agent add 输出解析到 64 位 token 与证书指纹（不打印 token）"
else
  fail "6.2" "agent add 输出解析失败（rc=$PARSE_RC，fpr_len=${#FPR}，token_len=${TOKEN_LEN:-?}）"
  dump_log "$PARSE_ERR" 10
fi

check_file_mode "6.3" "enrollment token 文件 0600" "$TOKEN_FILE" 600
if [[ -s "$TOKEN_FILE" ]] \
  && "$PYTHON" "$HELPER" check-64hex-file "$TOKEN_FILE" 2>/dev/null; then
  pass "6.4" "token 文件内容为 64 位十六进制且非符号链接"
else
  fail "6.4" "token 文件内容不是合法 64 位十六进制"
fi

AGENT_INSTALL_ARGS=(
  install --yes --prefix "$P" --systemd --unit-dir "$UNIT_DIR"
  --hub "wss://127.0.0.1:${AGENT_PORT:-0}/agent/ws"
  --token-file "$TOKEN_FILE"
  --fingerprint "$FPR"
  --name "$AGENT_NAME"
)
if [[ "$AGENT_PORT" =~ ^[0-9]+$ && -s "$TOKEN_FILE" && "$FPR" =~ ^[0-9a-f]{64}$ ]]; then
  timeout --kill-after=10 120 "$AGENT_BIN" "${AGENT_INSTALL_ARGS[@]}" \
    > "$AGENT_INSTALL_LOG" 2>&1
  AGENT_INSTALL_RC=$?
  check_rc_zero "6.5" "agent install 退出码 0" "$AGENT_INSTALL_LOG" "$AGENT_INSTALL_RC"
else
  fail "6.5" "agent install 前置失败（端口/ token /指纹不可用），未执行"
  AGENT_INSTALL_RC=999
fi

AGENT_FILES=(
  "$AGENT_DATA/agent.crt"
  "$AGENT_DATA/agent.key"
  "$AGENT_DATA/agent.secret"
  "$AGENT_DATA/agent_id"
)
if wait_files 30 "${AGENT_FILES[@]}"; then
  pass "6.6" "30s 内 agent.crt/agent.key/agent.secret/agent_id 全部出现且非空"
else
  missing_files=""
  for f in "${AGENT_FILES[@]}"; do
    [[ -s "$f" ]] || missing_files="$missing_files $(basename "$f")"
  done
  fail "6.6" "30s 内未完成 enrollment，缺失:$missing_files"
fi

AGENT_ID_FILE=""
if [[ -s "$AGENT_DATA/agent_id" ]]; then
  AGENT_ID_FILE=$(tr -d '[:space:]' < "$AGENT_DATA/agent_id")
fi
if [[ -n "$AGENT_ID_FILE" ]]; then
  pass "6.7" "agent_id 非空（长度 ${#AGENT_ID_FILE}）"
else
  fail "6.7" "agent_id 为空"
fi

check_dir_mode "6.8" "agent 数据目录 0700" "$AGENT_DATA" 700
check_file_mode "6.9" "agent 配置 0600" "$AGENT_CFG" 600
check_file_mode "6.10" "agent 私钥 0600" "$AGENT_DATA/agent.key" 600
check_file_mode "6.11" "agent secret 0600" "$AGENT_DATA/agent.secret" 600
check_file_exists "6.12" "agent unit 文件存在" "$AGENT_UNIT"
check_absent "6.12a" "--unit-dir 覆盖后 prefix 内没有重复 agent unit" \
  "$P/etc/systemd/system/rustboard-agent.service"
check_absent "6.12b" "--unit-dir 覆盖后 /etc 内没有重复 agent unit" \
  "/etc/systemd/system/rustboard-agent.service"
check_unit_verify "6.13" "agent unit 通过 systemd-analyze verify" "$AGENT_UNIT"
check_unit_execstart "6.14" "agent ExecStart 指向 prefix 内二进制" "$AGENT_UNIT" "$AGENT_INSTALLED_BIN"
check_unit_hardening "6.15" "agent unit 关键加固指令齐全" "$AGENT_UNIT" "$AGENT_DATA"
check_unit_active "6.16" "agent service active" "rustboard-agent.service"

if wait_agent_listed 30; then
  pass "6.17" "/api/v1/agents 在 30s 内出现 name=$AGENT_NAME（agent_id=${AGENT_ID_API}）"
else
  fail "6.17" "/api/v1/agents 未在 30s 内出现 name=$AGENT_NAME（最后 HTTP $LAST_CODE）"
fi

if [[ -n "$AGENT_ID_API" ]]; then
  if check_agent_series; then
    pass "6.18" "等 15s 后 /series?metric=cpu.usage 至少 1 个点（共 $SERIES_POINTS 个，agent=$AGENT_ID_API）"
  else
    fail "6.18" "/series?metric=cpu.usage 无数据点（$SERIES_ERR）"
  fi
else
  fail "6.18" "agent 未出现在 API，无法查询 series"
fi

check_token_not_leaked "6.19" "enrollment token 不在 unit 文件与 systemctl show -p ExecStart 中"

# ---------------------------------------------------------------------------
# 7. uninstall：先 agent/panel，再 hub；默认保留 config/data，--purge 删除
# ---------------------------------------------------------------------------

echo "==> 7/9 uninstall（agent → panel → hub）"

UNINSTALL_AGENT_LOG="$LOG_DIR/uninstall-agent.log"
timeout --kill-after=10 90 "$AGENT_BIN" uninstall --prefix "$P" --yes \
  > "$UNINSTALL_AGENT_LOG" 2>&1
UNINSTALL_AGENT_RC=$?
check_rc_zero "7.1" "agent uninstall 退出码 0" "$UNINSTALL_AGENT_LOG" "$UNINSTALL_AGENT_RC"
check_unit_absent "7.2" "agent uninstall 后 unit 不存在且服务已停" "rustboard-agent.service"

UNINSTALL_PANEL_LOG="$LOG_DIR/uninstall-panel.log"
timeout --kill-after=10 90 "$PANEL_BIN" uninstall --prefix "$P" --yes \
  > "$UNINSTALL_PANEL_LOG" 2>&1
UNINSTALL_PANEL_RC=$?
check_rc_zero "7.3" "panel uninstall 退出码 0" "$UNINSTALL_PANEL_LOG" "$UNINSTALL_PANEL_RC"
check_unit_absent "7.4" "panel uninstall 后 unit 不存在且服务已停" "rustboard-panel.service"

UNINSTALL_HUB_LOG="$LOG_DIR/uninstall-hub.log"
timeout --kill-after=10 90 "$HUB_BIN" uninstall --prefix "$P" --yes \
  > "$UNINSTALL_HUB_LOG" 2>&1
UNINSTALL_HUB_RC=$?
check_rc_zero "7.5" "hub uninstall（默认，不 purge）退出码 0" "$UNINSTALL_HUB_LOG" "$UNINSTALL_HUB_RC"
check_unit_absent "7.6" "hub 默认 uninstall 后 unit 不存在且服务已停" "rustboard-hub.service"
check_file_exists "7.7" "默认 uninstall 保留 hub 配置" "$HUB_CFG"
check_file_mode "7.8" "保留的 hub 配置仍为 0600" "$HUB_CFG" 600
check_dir_mode "7.9" "默认 uninstall 保留 hub 数据目录" "$HUB_DATA" 700
check_file_exists "7.10" "默认 uninstall 保留 hub 证书/私钥" "$HUB_DATA/certs/server.key"
check_absent "7.11" "默认 uninstall 删除 prefix 内 hub binary" "$HUB_INSTALLED_BIN"
check_no_state_role "7.12" "默认 uninstall 删除 state 中的 hub 记录" "hub"

timeout --kill-after=10 90 "$HUB_BIN" uninstall --prefix "$P" --purge --yes \
  >> "$UNINSTALL_HUB_LOG" 2>&1
UNINSTALL_PURGE_RC=$?
check_rc_zero "7.13" "hub uninstall --purge --yes 退出码 0" "$UNINSTALL_HUB_LOG" "$UNINSTALL_PURGE_RC"
check_absent "7.14" "--purge 删除 hub 配置" "$HUB_CFG"
check_absent "7.15" "--purge 删除 hub 数据目录" "$HUB_DATA"

# ---------------------------------------------------------------------------
# 8. 旧手工配置 upgrade
# ---------------------------------------------------------------------------

echo "==> 8/9 旧配置 upgrade（P3）"

UP_PREFIX="$TMP_ROOT/prefix-upgrade"
UP_CFG="$UP_PREFIX/etc/rustboard/hub.toml"
UP_DATA="$UP_PREFIX/var/lib/rustboard/hub"
UP_STATE="$UP_PREFIX/var/lib/rustboard/install-state.toml"
UP_UNIT="$UP_PREFIX/etc/systemd/system/rustboard-hub.service"
UP_BIN="$UP_PREFIX/usr/local/bin/rustboard-hub"
UP_INIT_LOG="$LOG_DIR/upgrade-init.log"
UP_DRY_LOG="$LOG_DIR/upgrade-dry.log"
UP_UPGRADE_LOG="$LOG_DIR/upgrade.log"
STATE="$UP_STATE"

UP_PORTS=$("$PYTHON" "$HELPER" ports 2) || die "无法挑选 upgrade 测试端口"
read -r UP_AGENT_PORT UP_ADMIN_PORT <<< "$UP_PORTS"
[[ "$UP_AGENT_PORT" =~ ^[0-9]+$ && "$UP_ADMIN_PORT" =~ ^[0-9]+$ ]] \
  || die "upgrade 端口解析失败: $UP_PORTS"

timeout --kill-after=10 90 "$HUB_BIN" init \
  --config "$UP_CFG" --data-dir "$UP_DATA" \
  --agent-listen "127.0.0.1:${UP_AGENT_PORT}" \
  --admin-listen "127.0.0.1:${UP_ADMIN_PORT}" \
  --san 127.0.0.1 > "$UP_INIT_LOG" 2>&1
UP_INIT_RC=$?
check_rc_zero "8.1" "hub init 生成旧手工配置与证书" "$UP_INIT_LOG" "$UP_INIT_RC"

printf 'v100 upgrade sentinel %s\n' "$$" > "$UP_DATA/upgrade-sentinel.txt"
chmod 600 "$UP_DATA/upgrade-sentinel.txt"

UP_HASH_FILES=(
  "$UP_CFG"
  "$UP_DATA/certs/ca.crt"
  "$UP_DATA/certs/ca.key"
  "$UP_DATA/certs/server.crt"
  "$UP_DATA/certs/server.key"
  "$UP_DATA/upgrade-sentinel.txt"
)
missing_up=""
for f in "${UP_HASH_FILES[@]}"; do
  [[ -f "$f" && ! -L "$f" ]] || missing_up="$missing_up $f"
done
if [[ -z "$missing_up" ]]; then
  pass "8.1a" "旧配置、CA/服务端证书、私钥与 sentinel 已生成"
else
  fail "8.1a" "旧配置/证书/数据文件缺失:$missing_up"
fi

UP_HASH_BEFORE=""
for f in "${UP_HASH_FILES[@]}"; do
  UP_HASH_BEFORE+="$f $(sha256_file "$f")"$'\n'
done
UP_DATA_LIST_BEFORE=$(find "$UP_DATA" -type f -printf '%P %s\n' 2>/dev/null | sort)
UP_TREE_BEFORE=$(find "$UP_PREFIX" -printf '%y %P\n' 2>/dev/null | sort)

timeout --kill-after=10 90 "$HUB_BIN" upgrade --prefix "$UP_PREFIX" --dry-run \
  > "$UP_DRY_LOG" 2>&1
UP_DRY_RC=$?
check_rc_zero "8.2" "hub upgrade --dry-run 退出码 0" "$UP_DRY_LOG" "$UP_DRY_RC"
if [[ ! -e "$UP_STATE" && ! -e "$UP_UNIT" && ! -e "$UP_BIN" ]]; then
  pass "8.3" "upgrade --dry-run 零写入（无 state/unit/binary）"
else
  fail "8.3" "upgrade --dry-run 产生了写入（state=$([[ -e "$UP_STATE" ]] && echo yes || echo no) unit=$([[ -e "$UP_UNIT" ]] && echo yes || echo no) binary=$([[ -e "$UP_BIN" ]] && echo yes || echo no)）"
fi
check_eq "8.3a" "upgrade --dry-run 后 prefix 目录树不变（含空目录）" \
  "$UP_TREE_BEFORE" "$(find "$UP_PREFIX" -printf '%y %P\n' 2>/dev/null | sort)"
UP_HASH_AFTER_DRY=""
for f in "${UP_HASH_FILES[@]}"; do
  UP_HASH_AFTER_DRY+="$f $(sha256_file "$f")"$'\n'
done
check_eq "8.4" "upgrade --dry-run 后 config/cert/数据 hash 不变" \
  "$UP_HASH_BEFORE" "$UP_HASH_AFTER_DRY"
check_eq "8.5" "upgrade --dry-run 后数据目录文件列表不变" \
  "$UP_DATA_LIST_BEFORE" "$(find "$UP_DATA" -type f -printf '%P %s\n' 2>/dev/null | sort)"

timeout --kill-after=10 120 "$HUB_BIN" upgrade --prefix "$UP_PREFIX" \
  > "$UP_UPGRADE_LOG" 2>&1
UP_UPGRADE_RC=$?
check_rc_zero "8.6" "hub upgrade（真实执行）退出码 0" "$UP_UPGRADE_LOG" "$UP_UPGRADE_RC"

check_file_mode "8.7" "upgrade 后 install-state.toml 0600" "$UP_STATE" 600
check_eq "8.8" "upgrade 后 state schema=1" "1" "$(toml_get "$UP_STATE" - schema)"
check_eq "8.9" "upgrade 后 state 出现 roles.hub" "yes" "$(state_role_exists hub)"
check_state_role "8.10" "upgrade 的 hub 记录路径正确" "hub" \
  "$UP_CFG" "$UP_DATA" "$UP_UNIT" "$UP_BIN"
check_eq "8.11" "upgrade 后 hub 配置 hash 不变" \
  "$(printf '%s\n' "$UP_HASH_BEFORE" | sed -n "s#^$UP_CFG ##p")" "$(sha256_file "$UP_CFG")"
check_eq "8.12" "upgrade 后证书 hash 不变" \
  "$(printf '%s\n' "$UP_HASH_BEFORE" | sed -n "s#^$UP_DATA/certs/##p")" \
  "$(for f in "$UP_DATA"/certs/*; do printf '%s %s\n' "$(basename "$f")" "$(sha256_file "$f")"; done)"
check_eq "8.13" "upgrade 后 data 目录文件列表不变（数据未重写）" \
  "$UP_DATA_LIST_BEFORE" "$(find "$UP_DATA" -type f -printf '%P %s\n' 2>/dev/null | sort)"
check_eq "8.14" "upgrade 后 sentinel hash 不变" \
  "$(printf '%s\n' "$UP_HASH_BEFORE" | sed -n "s#^$UP_DATA/upgrade-sentinel.txt ##p")" \
  "$(sha256_file "$UP_DATA/upgrade-sentinel.txt")"

check_file_exists "8.15" "upgrade 补齐 prefix 内 unit" "$UP_UNIT"
check_unit_verify "8.16" "upgrade 生成的 unit 通过 systemd-analyze verify" "$UP_UNIT"
check_unit_execstart "8.17" "upgrade unit 的 ExecStart 指向 prefix 内二进制" "$UP_UNIT" "$UP_BIN"
check_executable "8.18" "upgrade 补齐 prefix 内 hub binary" "$UP_BIN"
UP_ACTIVE=$(systemctl is-active rustboard-hub.service 2>/dev/null || true)
if [[ "$UP_ACTIVE" != "active" && "$UP_ACTIVE" != "reloading" && "$UP_ACTIVE" != "activating" && "$UP_ACTIVE" != "deactivating" ]]; then
  pass "8.19" "upgrade 未擅自启动 systemd 服务（状态 [${UP_ACTIVE:-unknown}]）"
else
  fail "8.19" "upgrade 启动了 rustboard-hub.service（$UP_ACTIVE）"
fi
check_absent "8.20" "upgrade 未在 /run/systemd/system 留下 unit" "$UNIT_DIR/rustboard-hub.service"

# ---------------------------------------------------------------------------
# 9. 收尾确认
# ---------------------------------------------------------------------------

echo "==> 9/9 收尾确认"

check_no_live_units "9.1" "测试结束时无同名 unit/活动服务"
check_no_production_paths "9.2" "测试未写入 /etc/rustboard、/var/lib/rustboard、/usr/local/bin"

echo "===== v100-install e2e: PASS=$PASSES FAIL=$FAILS ====="
if (( FAILS > 0 )); then
  exit 1
fi
exit 0
