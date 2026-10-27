#!/usr/bin/env bash
#
# RustBoard M5 Phase B（v1.0.0）离线包 / 无网 netns 独立 e2e。
#
# 只读依据（不阅读 packaging/install.sh 实现细节）：
#   - docs/plans/2026-10-25-m5-phase-b-delivery.md（B-G1–B-G4、§3.3、§3.6、§6、§8）
#   - docs/plans/2026-10-24-m5-phase-a-installer.md §3
#   - 现有 v0.4.x CLI 的运行时 --help 输出
#
# 覆盖：
#   1) 前置：root、sha256sum/strace/unshare/ip/curl、包顶层布局/权限、
#      包名/版本、SHA256SUMS 逐文件校验、x86_64 静态链接；只有显式
#      PACKAGE/SKIP_BUILD=1 才复用包，默认总是重建；复用前校验 VERSION
#      与 Cargo.toml、install.sh/二进制 hash 与当前源码，并校验外层
#      SHA256SUMS.<arch>；
#   2) unshare -n 内 `ip link set lo up`，确认外网 IP/DNS curl 失败；
#      用 `strace -f -qq -e trace=connect` 包住三角色安装与 hub/panel/agent
#      启动，只允许 AF_UNIX、127.0.0.1、::1；任何非回环 AF_INET/AF_INET6
#      （含 DNS 53）或未知地址族即 FAIL；
#   3) hub：install.sh hub --yes --offline --no-systemd --prefix ...；
#      bin/config/data/state/web 存在，config 0600、data 0700、无 unit；
#      `run --config` 启动，admin /healthz 200；从 hub.toml 读取 admin_token
#      （不打印）写成 0600 临时 token 文件供 panel；
#   4) panel：install.sh panel ... --hub-url/--hub-token-file/--listen；
#      config 0600、web 在 prefix、无 unit；启动后 /healthz 200、/ 返回 200
#      且包含 index 标记；
#   5) agent：先做 dummy token/fingerprint 安装校验（不 enrollment），再用
#      `hub agent add` 真实签发 token/指纹，启动 agent 连 loopback hub 并
#      轮询 agent.crt/agent_id/cert-info；若 CLI 无法在 prefix/no-systemd 下
#      签 token 则 FAIL，不静默 SKIP；token 不落日志；
#   6) 幂等：hub 安装重复执行 config sha 不变、healthz 仍 200；package
#      install.sh 重复执行退出 0；
#   7) 篡改：改二进制 1 字节；修改 web JS/CSS 并删除对应 SHA256SUMS 行；
#      两者 install.sh 都必须非零且不写新 prefix；外层 SHA256SUMS 也校验；
#   8) 明文 argv：--token/--password/--admin-token/--hub-token/--token_file
#      必须非零，且输出不回显 secret；prefix symlink/1777/group-writable
#      必须拒绝；
#   9) 生产路径用递归内容 hash+权限+属主+符号链接快照比对（自检能发现
#      原地改写）；失败时先 redact 再打印日志尾部；SKIP 不计入 PASS；
#      STRICT=1 时任何 SKIP 非零退出。
#
# 约束：
#   - 只写 $HOME/rustboard-v100-offline.* 临时目录；trap 清理前校验路径
#     （仅 $HOME/rustboard-v100-*、非符号链接、readlink -f 等于自身）；
#   - 不碰 /etc/rustboard、/var/lib/rustboard、/usr/local/bin、
#     /usr/share/rustboard、真实 systemd unit；安装只用 prefix + --no-systemd；
#   - 不打印 token/密码/私钥；失败日志先 redact；
#   - 不联网；端口只绑 127.0.0.1。
#
# 依赖：Linux root、bash 4.4+、sha256sum、strace、unshare、ip、curl、tar、
#       awk/sed/stat/find；`file` 缺失时静态检查打印 SKIP（不计 PASS）。
# 用法：bash tests/e2e/v100-offline.sh
# 环境：
#   PACKAGE=<tar.gz>  显式指定离线包；指定时复用并校验来源一致性
#   SKIP_BUILD=1      只用现有 dist 包（复用前同样校验来源一致性）
#   KEEP_E2E_TMP=1    保留临时目录与日志
#   STRICT=1          SKIP 也按失败处理（CI 严格模式）
#   ALLOW_UNVERIFIED=1 仅当 dist/<arch>/bin 或 web/dist 缺源时显式放行：
#                     打印 WARN、不计 PASS；hash 不一致仍 FATAL（默认 fail-closed）
#
set -uo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
SELF="$SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"
BUILD_RELEASE="$ROOT/packaging/build-release.sh"

PASSES=0
FAILS=0
SKIPS=0
# 只有正常走到 finish() 才置 1；cleanup 用它在异常 exit 0 时兜底非零退出。
E2E_COMPLETED=0

TMP_ROOT=""
LOG_DIR=""
EXTRACT_DIR=""
PKG_ROOT=""
PKG_VERSION=""
PACKAGE="${PACKAGE:-}"
SKIP_BUILD="${SKIP_BUILD:-0}"
KEEP_E2E_TMP="${KEEP_E2E_TMP:-0}"
STRICT="${STRICT:-0}"
ALLOW_UNVERIFIED="${ALLOW_UNVERIFIED:-0}"
PACKAGE_MODE=""
ARCH_SUFFIX="x86_64"
DIST_ARCH="amd64"
NETNS_CHILD=0
HOST_NETNS=""

PROD_PATHS=(
  /etc/rustboard
  /var/lib/rustboard
  /usr/local/bin/rustboard-hub
  /usr/local/bin/rustboard-panel
  /usr/local/bin/rustboard-agent
  /usr/share/rustboard/web
  /etc/systemd/system/rustboard-hub.service
  /etc/systemd/system/rustboard-panel.service
  /etc/systemd/system/rustboard-agent.service
)

HUB_PREFIX=""
PANEL_PREFIX=""
AGENT_PREFIX=""
AGENT_RUN_PREFIX=""
HUB_BIN=""
HUB_CFG=""
HUB_DATA=""
HUB_STATE=""
HUB_WEB=""
HUB_TOKEN_FILE=""
ADMIN_TOKEN=""
HUB_PORT=""
HUB_ADMIN_PORT=""
PANEL_PORT=""

HUB_INSTALL_ARGS=()
HUB_RUN_PID=""
HUB_RUN_GROUP=0
PANEL_RUN_PID=""
PANEL_RUN_GROUP=0
AGENT_RUN_PID=""
AGENT_RUN_GROUP=0

STARTED_PID=""
STARTED_GROUP=0
LAST_CODE=""

# ---------------------------------------------------------------------------
# 输出 / redact / 断言
# ---------------------------------------------------------------------------

usage() {
  cat <<'EOF'
用法: bash tests/e2e/v100-offline.sh

M5 Phase B 离线包 e2e：在 unshare -n 中安装并启动 hub/panel/agent，
用 strace 断言安装与启动只 connect 到 Unix socket / 127.0.0.1 / ::1。

环境变量:
  PACKAGE=<tar.gz>  显式指定离线包；指定时复用并校验来源一致性
  SKIP_BUILD=1      只用现有 dist 包（复用前同样校验来源一致性）
  KEEP_E2E_TMP=1    失败/成功后都保留 $HOME/rustboard-v100-offline.* 与日志
  STRICT=1          SKIP 也按失败处理（CI 严格模式）；默认 SKIP 不计 PASS 但不失败
  ALLOW_UNVERIFIED=1 仅当 dist/<arch>/bin 或 web/dist 缺源时显式放行：
                    打印 WARN、不计 PASS；hash 不一致仍 FATAL；默认 fail-closed

默认（既无 PACKAGE 也无 SKIP_BUILD）总是调用 packaging/build-release.sh
重新构建，不复用 dist 里 mtime 最新的旧包。

前置条件（缺失 FATAL，不伪装通过）:
  root、linux、sha256sum、strace、unshare -n、ip、curl、tar、awk/sed/stat/find
  `file` 仅用于静态链接检查，缺失时打印 SKIP（不计 PASS；STRICT=1 失败）。
EOF
}

pass() {
  PASSES=$((PASSES + 1))
  printf 'PASS [%s] %s\n' "$1" "$2"
}

fail() {
  FAILS=$((FAILS + 1))
  printf 'FAIL [%s] %s\n' "$1" "$2" >&2
}

skip() {
  SKIPS=$((SKIPS + 1))
  if [[ "$STRICT" == "1" ]]; then
    printf 'SKIP [%s] %s（关键 SKIP；STRICT=1 将非零退出）\n' "$1" "$2"
  else
    printf 'SKIP [%s] %s（未计入 PASS；STRICT=1 时失败）\n' "$1" "$2"
  fi
}

die() {
  printf 'FATAL: %s\n' "$*" >&2
  if (( PASSES + FAILS + SKIPS > 0 )); then
    printf '===== v100-offline e2e: PASS=%s FAIL=%s SKIP=%s STRICT=%s =====\n' \
      "$PASSES" "$FAILS" "$SKIPS" "$STRICT" >&2
  fi
  exit 1
}

finish() {
  local code=0
  # 显式完成标记：正常跑到汇总才算完成；EXIT 兜底据此区分“提前 exit 0”。
  E2E_COMPLETED=1
  printf '\n===== v100-offline e2e: PASS=%s FAIL=%s SKIP=%s STRICT=%s =====\n' \
    "$PASSES" "$FAILS" "$SKIPS" "$STRICT"
  if (( FAILS > 0 )); then
    code=1
  fi
  if [[ "$STRICT" == "1" ]] && (( SKIPS > 0 )); then
    printf 'STRICT=1: 存在 %s 个 SKIP，按失败处理\n' "$SKIPS" >&2
    code=1
  fi
  exit "$code"
}

abort_tests() {
  printf 'ABORT: %s\n' "${1:-后续断言依赖的前置步骤失败}" >&2
  finish
}

redact_stream() {
  sed -E \
    -e '/(密码|password|passwd|admin_token|admin-token|hub_token|hub-token|token|secret)[^:：=]*[:：=].*/I s/.*/<redacted sensitive line>/' \
    -e 's/(--(token|token_file|token-file|admin-token|hub-token)(-file)?[[:space:]=]+)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/(--password(-file)?[[:space:]=]+)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/((admin_token|token|secret|password|passwd)[[:space:]]*=[[:space:]]*)"[^"]*"/\1"<redacted>"/Ig' \
    -e 's/((admin_token|token|secret|password|passwd)[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1<redacted>/Ig' \
    -e 's/\b[0-9a-fA-F]{64}\b/<redacted-64hex>/g'
}

dump_log() {
  local file=${1:-} lines=${2:-40}
  [[ -n "$file" && -f "$file" && -s "$file" ]] || return 0
  printf -- '---- %s (tail -n %s, redacted) ----\n' "$(basename -- "$file")" "$lines" >&2
  tail -n "$lines" -- "$file" 2>/dev/null | redact_stream >&2 || true
}

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$expected]，实际 [$actual]）"
  fi
}

check_file() {
  local id=$1 desc=$2 file=$3
  if [[ -f "$file" && ! -L "$file" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（不是普通文件或不存在: $file）"
  fi
}

check_executable() {
  local id=$1 desc=$2 file=$3
  if [[ -f "$file" && -x "$file" && ! -L "$file" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（不存在/不是普通文件/不可执行: $file）"
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

check_mode() {
  local id=$1 desc=$2 file=$3 expected=$4 mode
  if [[ ! -e "$file" ]]; then
    fail "$id" "$desc（文件不存在: $file）"
    return
  fi
  if [[ -L "$file" || ! -f "$file" ]]; then
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
    fail "$id" "$desc（不是普通目录或不存在: $dir）"
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
    fail "$id" "$desc（期望非零退出，实际 0）"
    dump_log "$log" 40
  elif (( rc == 124 || rc == 137 )); then
    fail "$id" "$desc（命令超时/被杀 rc=$rc）"
  else
    pass "$id" "$desc（rc=$rc）"
  fi
}

sha256_file() {
  if [[ -f "$1" && ! -L "$1" ]]; then
    sha256sum -- "$1" 2>/dev/null | awk '{print $1}'
  else
    printf '__MISSING__\n'
  fi
}

# web 树的路径+内容 hash（相对路径，权限/属主不参与）；目录内不允许符号链接。
web_tree_digest() {
  local root=$1
  if [[ ! -d "$root" || -L "$root" ]]; then
    return 1
  fi
  if find "$root" -type l -print -quit 2>/dev/null | grep -q .; then
    return 2
  fi
  ( cd "$root" 2>/dev/null || exit 1
    find . -type f -print0 2>/dev/null | LC_ALL=C sort -z | xargs -0 -r sha256sum 2>/dev/null
  ) | sha256sum | awk '{print $1}'
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

# ---------------------------------------------------------------------------
# 临时目录 / 清理
# ---------------------------------------------------------------------------

is_safe_tmp_root() {
  local path=${TMP_ROOT:-} real
  [[ -n "$path" ]] || return 1
  [[ "$path" == $HOME/rustboard-v100-offline.* ]] || return 1
  [[ "$path" != *..* && "$path" != "/" && "$path" != "$HOME" ]] || return 1
  [[ -d "$path" && ! -L "$path" ]] || return 1
  [[ "${path%/*}" == "$HOME" ]] || return 1
  real=$(readlink -f -- "$path" 2>/dev/null || true)
  [[ -n "$real" && "$real" == "$path" ]] || return 1
  return 0
}

ensure_tmp_root() {
  [[ -n "$TMP_ROOT" ]] && return 0
  TMP_ROOT=$(mktemp -d "$HOME/rustboard-v100-offline.XXXXXX" 2>/dev/null) \
    || die "无法在 $HOME 下创建临时目录（需要 root 与可写 HOME）"
  is_safe_tmp_root || die "临时目录未通过安全校验: $TMP_ROOT"
  LOG_DIR="$TMP_ROOT/logs"
  mkdir -p -- "$LOG_DIR" || die "无法创建日志目录: $LOG_DIR"
  install_cleanup_traps
  return 0
}

stop_pid() {
  local pid=${1:-} group=${2:-0} name=${3:-process} i
  [[ -n "$pid" ]] || return 0
  if (( group )); then
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  else
    if command -v pkill >/dev/null 2>&1; then
      pkill -TERM -P "$pid" 2>/dev/null || true
    fi
    kill -TERM "$pid" 2>/dev/null || true
  fi
  for ((i = 0; i < 50; i++)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    if (( group )); then
      kill -KILL -- "-$pid" 2>/dev/null || true
    fi
    if command -v pkill >/dev/null 2>&1; then
      pkill -KILL -P "$pid" 2>/dev/null || true
    fi
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  if command -v pkill >/dev/null 2>&1; then
    pkill -KILL -P "$pid" 2>/dev/null || true
  fi
  printf 'INFO: 已停止 %s（pid=%s）\n' "$name" "$pid" >&2
  return 0
}

stop_servers() {
  stop_pid "${AGENT_RUN_PID:-}" "${AGENT_RUN_GROUP:-0}" "agent"
  AGENT_RUN_PID=""
  AGENT_RUN_GROUP=0
  stop_pid "${PANEL_RUN_PID:-}" "${PANEL_RUN_GROUP:-0}" "panel"
  PANEL_RUN_PID=""
  PANEL_RUN_GROUP=0
  stop_pid "${HUB_RUN_PID:-}" "${HUB_RUN_GROUP:-0}" "hub"
  HUB_RUN_PID=""
  HUB_RUN_GROUP=0
}

dump_failure_logs() {
  [[ -n "$LOG_DIR" ]] || return 0
  printf '===== v100-offline e2e 失败现场（redacted）=====\n' >&2
  dump_log "$LOG_DIR/tar.log" 20
  dump_log "$LOG_DIR/sha256.log" 40
  dump_log "$LOG_DIR/outer-sha256.log" 30
  dump_log "$LOG_DIR/build.log" 40
  dump_log "$LOG_DIR/hub-install.log" 60
  dump_log "$LOG_DIR/hub-reinstall.log" 40
  dump_log "$LOG_DIR/hub-run.log" 60
  dump_log "$LOG_DIR/panel-install.log" 60
  dump_log "$LOG_DIR/panel-run.log" 50
  dump_log "$LOG_DIR/agent-install.log" 40
  dump_log "$LOG_DIR/agent-add.log" 30
  dump_log "$LOG_DIR/agent-enroll-install.log" 50
  dump_log "$LOG_DIR/agent-run.log" 50
  dump_log "$LOG_DIR/tamper.log" 30
  dump_log "$LOG_DIR/tamper-web.log" 30
  printf '（明文 argv 测试日志含 secret，按约定不打印）\n' >&2
}

install_cleanup_traps() {
  trap cleanup EXIT
  trap 'on_signal 130' INT
  trap 'on_signal 143' TERM
}

on_signal() {
  local code=$1
  # 信号路径必须保留 130/143，不能先被 cleanup 当成普通 EXIT 0 吞掉。
  trap - EXIT INT TERM
  cleanup "$code"
}

cleanup() {
  local code=${1:-$?}
  trap - EXIT INT TERM

  stop_servers

  # 已有断言失败时，无论调用方传什么 code 都必须非零退出。
  if (( FAILS > 0 )); then
    code=1
  fi
  # 未到 finish() 的完成标记却以 0 退出，说明流程提前结束，按失败处理。
  if (( E2E_COMPLETED == 0 )) && (( code == 0 )); then
    printf 'FATAL: 未到达完成标记（finish），按失败退出\n' >&2
    code=1
  fi

  if (( code != 0 || FAILS > 0 )); then
    dump_failure_logs
  fi

  if [[ "$KEEP_E2E_TMP" == "1" ]]; then
    printf '临时目录已保留（KEEP_E2E_TMP=1）: %s\n' "${TMP_ROOT:-<unset>}" >&2
  elif is_safe_tmp_root; then
    rm -rf -- "$TMP_ROOT"
  elif [[ -n "$TMP_ROOT" ]]; then
    printf '警告: 临时目录未通过安全校验，未删除: %s\n' "$TMP_ROOT" >&2
  fi

  exit "$code"
}

# ---------------------------------------------------------------------------
# 前置与包解析
# ---------------------------------------------------------------------------

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

preflight() {
  (( EUID == 0 )) || die "需要 root（unshare -n、$HOME prefix、strace 安装 e2e）"
  [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux（unshare -n / strace）"

  local cmd
  for cmd in sha256sum strace unshare ip curl tar awk sed stat find mktemp readlink; do
    require_cmd "$cmd"
  done

  unshare -n true >/dev/null 2>&1 \
    || die "unshare -n 不可用（需要 root + CAP_SYS_ADMIN）"
  unshare -n -- bash -c 'ip link set lo up' >/dev/null 2>&1 \
    || die "unshare -n 内无法 ip link set lo up"

  HOST_NETNS=$(readlink /proc/self/ns/net 2>/dev/null || true)
  [[ -n "$HOST_NETNS" ]] || die "无法读取 /proc/self/ns/net"

  command -v setsid >/dev/null 2>&1 \
    || printf 'WARN: setsid 不可用，使用进程树回退方式清理\n' >&2
  command -v file >/dev/null 2>&1 \
    || printf 'WARN: file 不可用，静态链接检查将 SKIP\n' >&2
  command -v ss >/dev/null 2>&1 \
    || printf 'WARN: ss 不可用，端口占用探测使用 /dev/tcp 回退\n' >&2
}

find_package() {
  local dir="$ROOT/dist" found
  [[ -d "$dir" ]] || return 1
  found=$(find "$dir" -maxdepth 1 -type f -name 'serverdashboard-v*-x86_64.tar.gz' \
    -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -n 1 | cut -d' ' -f2- || true)
  [[ -n "$found" ]] || return 1
  printf '%s\n' "$found"
}

workspace_version() {
  awk '
    /^[[:space:]]*\[workspace\.package\][[:space:]]*$/ { in_section = 1; next }
    /^[[:space:]]*\[/ { in_section = 0 }
    in_section && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0
      sub(/^[^=]*=[[:space:]]*"/, "", line)
      sub(/".*$/, "", line)
      print line
      exit
    }
  ' "$ROOT/Cargo.toml" 2>/dev/null
}

# 包来源策略（评审要求）：
#   - 只有显式 PACKAGE 或 SKIP_BUILD=1 才复用 dist 包；
#   - 默认总是调用 build-release.sh 重新构建，避免复用 mtime 最新的旧包。
resolve_package() {
  local found base
  if [[ -n "$PACKAGE" ]]; then
    PACKAGE_MODE="explicit"
    [[ -f "$PACKAGE" ]] || die "PACKAGE 指向的离线包不存在: $PACKAGE"
    PACKAGE=$(readlink -f -- "$PACKAGE" 2>/dev/null) \
      || die "无法解析 PACKAGE 真实路径"
    [[ -f "$PACKAGE" ]] || die "PACKAGE 不是普通文件: $PACKAGE"
  elif [[ "$SKIP_BUILD" == "1" ]]; then
    PACKAGE_MODE="skip_build"
    found=$(find_package || true)
    [[ -n "$found" ]] \
      || die "SKIP_BUILD=1，但 $ROOT/dist 下没有 serverdashboard-v*-x86_64.tar.gz"
    PACKAGE=$found
  else
    PACKAGE_MODE="built"
    [[ -f "$BUILD_RELEASE" ]] \
      || die "默认需要重新构建，但找不到公开构建入口 $BUILD_RELEASE"
    ensure_tmp_root
    printf 'INFO: 默认重建离线包：packaging/build-release.sh --arch amd64\n'
    if ! bash "$BUILD_RELEASE" --arch amd64 >"$LOG_DIR/build.log" 2>&1; then
      dump_log "$LOG_DIR/build.log" 50
      die "packaging/build-release.sh --arch amd64 失败"
    fi
    found=$(find_package || true)
    [[ -n "$found" ]] \
      || die "构建成功但未找到 dist/serverdashboard-v*-x86_64.tar.gz"
    PACKAGE=$found
  fi

  PACKAGE=$(readlink -f -- "$PACKAGE" 2>/dev/null) || die "无法解析包路径"
  base=$(basename -- "$PACKAGE")
  [[ "$base" == serverdashboard-v*-x86_64.tar.gz ]] \
    || die "本脚本只接受 x86_64 离线包，当前: $base"
  [[ -s "$PACKAGE" ]] || die "离线包为空: $PACKAGE"
  printf 'INFO: 使用离线包 %s（mode=%s）\n' "$PACKAGE" "$PACKAGE_MODE"
}

# 复用/构建产物必须与当前源码一致；缺源默认 FATAL，只有 ALLOW_UNVERIFIED=1
# 显式放行“缺源”（打印 WARN、不计 PASS）；hash 不一致始终 FATAL。
# 逐项处理：所有可得来源先校验，不能因为 web 缺源就跳过 install.sh/二进制的比对。
validate_package_provenance() {
  local cargo_version pkg_hash src_hash bin src pkg_install
  local src_web="$ROOT/web/dist" pkg_web src_dir
  local src_web_digest pkg_web_digest missing="" rc

  cargo_version=$(workspace_version)
  [[ -n "$cargo_version" ]] \
    || die "无法从 $ROOT/Cargo.toml 解析 [workspace.package].version"
  if [[ "$PKG_VERSION" != "$cargo_version" ]]; then
    die "包 VERSION=$PKG_VERSION 与当前 Cargo.toml workspace version=$cargo_version 不一致（mode=$PACKAGE_MODE）；请重建或指定当前包"
  fi

  pkg_install="$PKG_ROOT/install.sh"
  if [[ ! -f "$pkg_install" || -L "$pkg_install" ]]; then
    die "包内缺少普通文件 install.sh，无法校验来源一致性"
  fi

  # install.sh：源可得就必须比对；只有源文件本身不可得才记 missing。
  if [[ -f "$ROOT/packaging/install.sh" && ! -L "$ROOT/packaging/install.sh" ]]; then
    pkg_hash=$(sha256_file "$pkg_install")
    src_hash=$(sha256_file "$ROOT/packaging/install.sh")
    if [[ "$pkg_hash" != "$src_hash" ]]; then
      die "包内 install.sh 与当前 packaging/install.sh 不一致（mode=$PACKAGE_MODE）；请重建或指定当前包"
    fi
  else
    missing+=" packaging/install.sh"
  fi

  # 三个二进制逐项找源并比对；某个二进制缺源不影响其余二进制先校验。
  for bin in rustboard-hub rustboard-panel rustboard-agent; do
    src=""
    for src_dir in "$ROOT/dist/$DIST_ARCH/bin" "$ROOT/dist/$ARCH_SUFFIX/bin"; do
      if [[ -d "$src_dir" && ! -L "$src_dir" \
        && -f "$src_dir/$bin" && ! -L "$src_dir/$bin" ]]; then
        src="$src_dir/$bin"
        break
      fi
    done
    if [[ -n "$src" ]]; then
      pkg_hash=$(sha256_file "$PKG_ROOT/bin/$bin")
      src_hash=$(sha256_file "$src")
      if [[ "$pkg_hash" != "$src_hash" ]]; then
        die "包内 bin/$bin 与当前 $src 不一致（mode=$PACKAGE_MODE）；请重建或指定当前包"
      fi
    else
      missing+=" dist/$DIST_ARCH/bin/$bin"
    fi
  done

  # web 树：源可得就必须比对；不可得才记 missing，且不因 ALLOW_UNVERIFIED
  # 而跳过前面已经发现的 install.sh/二进制不一致。
  if [[ -d "$src_web" && ! -L "$src_web" && -f "$src_web/index.html" ]]; then
    pkg_web="$PKG_ROOT/share/rustboard/web"
    if [[ ! -d "$pkg_web" || -L "$pkg_web" ]]; then
      die "包内 share/rustboard/web 缺失或不是普通目录"
    fi
    src_web_digest=$(web_tree_digest "$src_web")
    rc=$?
    if (( rc != 0 )) || [[ -z "$src_web_digest" ]]; then
      die "无法计算 web/dist 递归 hash（rc=$rc；符号链接/不可读视为不一致）"
    fi
    pkg_web_digest=$(web_tree_digest "$pkg_web")
    rc=$?
    if (( rc != 0 )) || [[ -z "$pkg_web_digest" ]]; then
      die "无法计算包内 share/rustboard/web 递归 hash（rc=$rc；符号链接/不可读视为不一致）"
    fi
    if [[ "$src_web_digest" != "$pkg_web_digest" ]]; then
      die "包内 share/rustboard/web 与当前 web/dist 的路径+sha256 不一致（src=$src_web_digest pkg=$pkg_web_digest）；请重建或指定当前包"
    fi
  else
    missing+=" web/dist"
  fi

  if [[ -n "$missing" ]]; then
    if [[ "$ALLOW_UNVERIFIED" == "1" ]]; then
      printf 'WARN: ALLOW_UNVERIFIED=1：缺少源%s；仅跳过实际不可得的项，已校验项不一致仍会 FATAL（不计 PASS）\n' \
        "$missing" >&2
      return 0
    fi
    die "缺少源$missing；默认 fail-closed，不能验证包来源。请先构建源码，或显式 ALLOW_UNVERIFIED=1（仅在源不可得的逃生场景）"
  fi

  pass "1.14" "包 VERSION、install.sh、三二进制、web 树与当前源码一致（mode=$PACKAGE_MODE）"
}

extract_package() {
  local -a tops=()
  local top_count

  EXTRACT_DIR="$TMP_ROOT/extract"
  mkdir -p -- "$EXTRACT_DIR" || die "无法创建解包目录"
  if ! tar -xzf "$PACKAGE" -C "$EXTRACT_DIR" >"$LOG_DIR/tar.log" 2>&1; then
    fail "1.0" "解包离线包失败"
    dump_log "$LOG_DIR/tar.log" 30
    abort_tests
  fi

  mapfile -t tops < <(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null)
  top_count=${#tops[@]}
  if (( top_count == 1 )) && [[ -d "$EXTRACT_DIR/${tops[0]}" && ! -L "$EXTRACT_DIR/${tops[0]}" ]]; then
    PKG_ROOT="$EXTRACT_DIR/${tops[0]}"
  else
    # 允许 tar 不带顶层版本目录；后续仍按包根逐项校验。
    PKG_ROOT="$EXTRACT_DIR"
  fi
  PKG_ROOT=$(readlink -f -- "$PKG_ROOT" 2>/dev/null) || die "无法解析解包路径"
  [[ "$PKG_ROOT" == "$TMP_ROOT"/* ]] || die "解包路径越出临时目录: $PKG_ROOT"

  if [[ -f "$PKG_ROOT/VERSION" ]]; then
    PKG_VERSION=$(tr -d '[:space:]' < "$PKG_ROOT/VERSION" 2>/dev/null || true)
  fi
  [[ -n "$PKG_VERSION" ]] || PKG_VERSION="unknown"
  printf 'INFO: 包根 %s（VERSION=%s）\n' "$PKG_ROOT" "$PKG_VERSION"
}

# ---------------------------------------------------------------------------
# netns / strace
# ---------------------------------------------------------------------------

start_traced_server() {
  local trace=$1 log=$2
  shift 2
  STARTED_PID=""
  STARTED_GROUP=0
  if command -v setsid >/dev/null 2>&1; then
    setsid strace -f -qq -e trace=connect -o "$trace" "$@" >"$log" 2>&1 &
    STARTED_PID=$!
    STARTED_GROUP=1
  else
    strace -f -qq -e trace=connect -o "$trace" "$@" >"$log" 2>&1 &
    STARTED_PID=$!
    STARTED_GROUP=0
  fi
  sleep 0.2
  if ! kill -0 "$STARTED_PID" 2>/dev/null; then
    STARTED_PID=""
    STARTED_GROUP=0
    return 1
  fi
  return 0
}

# 解析 strace connect 日志：只允许 AF_UNIX、AF_INET 127.0.0.1、AF_INET6 ::1。
# 打印违规行并非零退出；允许时无输出、退出 0。
parse_connect_log() {
  awk '
    /connect\(/ {
      if ($0 ~ /sa_family=AF_UNIX/) next
      if ($0 ~ /sa_family=AF_INET6/) {
        if ($0 ~ /inet_pton\(AF_INET6, "::1"/ || $0 ~ /sin6_addr="::1"/) next
        print "AF_INET6 非回环: " $0
        bad = 1
        next
      }
      if ($0 ~ /sa_family=AF_INET,/) {
        if ($0 ~ /sin_addr=inet_addr\("127\.0\.0\.1"\)/ || $0 ~ /sin_addr="127\.0\.0\.1"/) next
        print "AF_INET 非回环: " $0
        bad = 1
        next
      }
      print "未知地址族: " $0
      bad = 1
    }
    END { exit bad ? 1 : 0 }
  ' "$1"
}

check_connect_log() {
  local id=$1 desc=$2 log=$3 details
  if [[ ! -f "$log" ]]; then
    fail "$id" "$desc（strace 日志不存在: $log）"
    return
  fi
  if details=$(parse_connect_log "$log" 2>/dev/null); then
    pass "$id" "$desc"
  else
    details=$(printf '%s\n' "$details" | head -n 3 | tr '\n' ';' | redact_stream)
    fail "$id" "$desc（${details:-解析失败}）"
  fi
}

# ---------------------------------------------------------------------------
# 端口 / HTTP / 生产路径基线
# ---------------------------------------------------------------------------

port_in_use() {
  local port=$1
  if command -v ss >/dev/null 2>&1; then
    if [[ -n "$(ss -H -ltn "sport = :$port" 2>/dev/null || true)" ]]; then
      return 0
    fi
    if [[ -n "$(ss -H -lun "sport = :$port" 2>/dev/null || true)" ]]; then
      return 0
    fi
    return 1
  fi
  if command -v timeout >/dev/null 2>&1; then
    if timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

pick_port() {
  local p i
  for ((i = 0; i < 100; i++)); do
    if command -v shuf >/dev/null 2>&1; then
      p=$(shuf -i 20000-64999 -n 1)
    else
      p=$((20000 + RANDOM % 45000))
    fi
    if ! port_in_use "$p"; then
      printf '%s\n' "$p"
      return 0
    fi
  done
  return 1
}

pick_port_distinct() {
  local -a avoid=("$@")
  local p i a used
  for ((i = 0; i < 100; i++)); do
    p=$(pick_port || true)
    [[ -n "$p" ]] || continue
    used=0
    for a in "${avoid[@]}"; do
      [[ "$a" == "$p" ]] && used=1
    done
    if (( used == 0 )); then
      printf '%s\n' "$p"
      return 0
    fi
  done
  return 1
}

wait_http_200() {
  local url=$1 timeout_secs=$2 body=$3
  local deadline code
  deadline=$(( $(date +%s) + timeout_secs ))
  while :; do
    code=$(curl -sS --noproxy '*' --max-time 2 -o "$body" -w '%{http_code}' \
      "$url" 2>/dev/null) || code="000"
    LAST_CODE=$code
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    if (( $(date +%s) >= deadline )); then
      return 1
    fi
    sleep 0.3
  done
}

run_limited_cmd() {
  local secs=$1
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  else
    "$@"
  fi
}

# 解析 hub agent add 输出：只写 token 到 0600 文件，stdout 仅返回指纹。
# 不打印 token/原始输出；解析失败返回非零。
parse_agent_add_log() {
  local log=$1 token_out=$2 clean fp token candidates count
  clean="$LOG_DIR/agent-add.clean"
  sed -E 's/\x1b\[[0-9;]*[A-Za-z]//g' "$log" 2>/dev/null | tr -d '\r' >"$clean" || return 1

  fp=$(grep -ioE -- '--fingerprint[[:space:]=]+(sha256:)?[[:space:]]*[0-9a-f]{64}' "$clean" 2>/dev/null \
    | head -n 1 | grep -oE '[0-9a-fA-F]{64}' | head -n 1 | tr 'A-F' 'a-f')
  if [[ -z "$fp" ]]; then
    fp=$(grep -iE 'fingerprint|指纹' "$clean" 2>/dev/null \
      | grep -ioE '(fingerprint|指纹)[^0-9a-fA-F]*(sha256:)?[[:space:]]*[0-9a-f]{64}' \
      | head -n 1 | grep -oE '[0-9a-fA-F]{64}' | head -n 1 | tr 'A-F' 'a-f')
  fi

  token=$(grep -ioE -- '--token[[:space:]=]+[0-9a-f]{64}' "$clean" 2>/dev/null \
    | head -n 1 | grep -oE '[0-9a-fA-F]{64}' | head -n 1 | tr 'A-F' 'a-f')
  if [[ -z "$token" ]]; then
    token=$(grep -iE '(^|[^A-Za-z0-9_-])token[[:space:]]*[=:]' "$clean" 2>/dev/null \
      | grep -ioE 'token[^0-9a-fA-F]*[0-9a-f]{64}' \
      | head -n 1 | grep -oE '[0-9a-fA-F]{64}' | head -n 1 | tr 'A-F' 'a-f')
  fi
  if [[ -z "$token" ]]; then
    token=$(awk -v fp="$fp" '
      tolower($0) ~ /^[[:space:]]*[0-9a-f]{64}[[:space:]]*$/ {
        v = tolower($0); gsub(/[[:space:]]/, "", v)
        if (v != fp) { print v; exit }
      }
    ' "$clean")
  fi
  if [[ -z "$token" ]]; then
    candidates=$(grep -oE '[0-9a-fA-F]{64}' "$clean" 2>/dev/null \
      | tr 'A-F' 'a-f' | sort -u | awk -v fp="$fp" '$0 != fp')
    count=$(printf '%s\n' "$candidates" | grep -c . || true)
    if [[ "$count" == "1" ]]; then
      token=$candidates
    fi
  fi

  if [[ ! "$fp" =~ ^[0-9a-f]{64}$ ]] || [[ ! "$token" =~ ^[0-9a-f]{64}$ ]] \
    || [[ "$fp" == "$token" ]]; then
    return 1
  fi
  if ! ( umask 077; printf '%s\n' "$token" >"$token_out" ); then
    return 1
  fi
  chmod 600 -- "$token_out" 2>/dev/null || true
  rm -f -- "$clean" 2>/dev/null || true
  printf '%s\n' "$fp"
}

extract_admin_token() {
  local file=$1
  awk '
    /^[[:space:]]*admin_token[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "", $0)
      sub(/[[:space:]]+#.*$/, "", $0)
      sub(/[[:space:]]+$/, "", $0)
      if ($0 ~ /^"/) { sub(/^"/, "", $0); sub(/".*$/, "", $0) }
      print
      exit
    }
  ' "$file" 2>/dev/null
}

snapshot_one_path() {
  local path=$1 mode uid gid file
  if [[ -L "$path" ]]; then
    mode=$(stat -c '%a' -- "$path" 2>/dev/null || printf '?')
    uid=$(stat -c '%u' -- "$path" 2>/dev/null || printf '?')
    gid=$(stat -c '%g' -- "$path" 2>/dev/null || printf '?')
    printf 'L\t%s\t%s\t%s\t%s\t%s\n' "$path" "$mode" "$uid" "$gid" \
      "$(readlink -- "$path" 2>/dev/null || true)"
    return
  fi
  if [[ -f "$path" ]]; then
    mode=$(stat -c '%a' -- "$path" 2>/dev/null || printf '?')
    uid=$(stat -c '%u' -- "$path" 2>/dev/null || printf '?')
    gid=$(stat -c '%g' -- "$path" 2>/dev/null || printf '?')
    printf 'F\t%s\t%s\t%s\t%s\n' "$path" "$mode" "$uid" "$gid"
    printf 'H\t%s\t%s\n' "$path" "$(sha256_file "$path")"
    return
  fi
  if [[ -d "$path" ]]; then
    mode=$(stat -c '%a' -- "$path" 2>/dev/null || printf '?')
    uid=$(stat -c '%u' -- "$path" 2>/dev/null || printf '?')
    gid=$(stat -c '%g' -- "$path" 2>/dev/null || printf '?')
    printf 'D\t%s\t%s\t%s\t%s\n' "$path" "$mode" "$uid" "$gid"
    find "$path" -xdev -mindepth 1 -printf '%y\t%p\t%m\t%U\t%G\t%l\n' 2>/dev/null \
      | LC_ALL=C sort
    while IFS= read -r -d '' file; do
      printf 'H\t%s\t%s\n' "$file" "$(sha256_file "$file")"
    done < <(find "$path" -xdev -type f -print0 2>/dev/null | LC_ALL=C sort -z)
    return
  fi
  printf 'A\t%s\n' "$path"
}

snapshot_paths() {
  local path
  for path in "$@"; do
    snapshot_one_path "$path"
  done
}

snapshot_prod_paths() {
  snapshot_paths "${PROD_PATHS[@]}"
}

# 自检：证明 9.1 的递归快照能发现“已有文件被原地改写”，而不只是目录 mtime。
verify_snapshot_detects_rewrite() {
  local dir="$TMP_ROOT/snapshot-selftest"
  local tree="$dir/tree"
  local before="$dir/before.snap"
  local after="$dir/after.snap"
  rm -rf -- "$dir" 2>/dev/null || true
  mkdir -p -- "$tree" || {
    fail "9.0" "无法创建快照自检目录"
    return
  }
  printf 'one\n' >"$tree/file.txt"
  chmod 600 -- "$tree/file.txt"
  snapshot_paths "$tree" >"$before"
  printf 'two\n' >"$tree/file.txt"
  snapshot_paths "$tree" >"$after"
  if cmp -s -- "$before" "$after"; then
    fail "9.0" "递归快照自检失败：原地改写文件后快照未变化"
  else
    pass "9.0" "递归快照能发现已有文件被原地改写（内容 hash 生效）"
  fi
  rm -rf -- "$dir" 2>/dev/null || true
}

check_prod_untouched() {
  local before=$1 after=$2
  if cmp -s -- "$before" "$after"; then
    pass "9.1" "生产路径未被触碰（/etc/rustboard、/var/lib/rustboard、/usr/local/bin、/usr/share/rustboard、真实 systemd unit）"
  else
    fail "9.1" "生产路径被修改（diff 仅打印路径）"
    diff -u -- "$before" "$after" 2>/dev/null | head -n 20 >&2 || true
  fi
}

# ---------------------------------------------------------------------------
# 包内容断言
# ---------------------------------------------------------------------------

check_outer_checksum() {
  local base pkg_dir sums name line_file found_sums=""
  local -a candidates=("SHA256SUMS.$ARCH_SUFFIX" "SHA256SUMS.$DIST_ARCH" "SHA256SUMS")
  base=$(basename -- "$PACKAGE")
  pkg_dir=$(dirname -- "$PACKAGE")
  line_file="$LOG_DIR/outer-$ARCH_SUFFIX.sums"

  for name in "${candidates[@]}"; do
    sums="$pkg_dir/$name"
    [[ -f "$sums" && ! -L "$sums" ]] || continue
    : >"$line_file"
    awk -v b="$base" '
      {
        p = $2
        sub(/^\*/, "", p)
        sub(/^\.\//, "", p)
        if (p == b) { print; found = 1 }
      }
      END { exit found ? 0 : 1 }
    ' "$sums" >"$line_file" || true
    if [[ -s "$line_file" ]]; then
      found_sums="$sums"
      break
    fi
  done

  if [[ -z "$found_sums" ]]; then
    if [[ "$PACKAGE" == "$ROOT/dist/"* ]]; then
      fail "1.15" "dist 包缺少外层 SHA256SUMS.$ARCH_SUFFIX 或其中未列出 $base"
    else
      skip "1.15" "显式 PACKAGE 不在 dist，且未找到列出该包的外层 SHA256SUMS（STRICT=1 失败）"
    fi
    return
  fi

  if ( cd "$pkg_dir" && sha256sum -c --strict "$line_file" ) >"$LOG_DIR/outer-sha256.log" 2>&1; then
    pass "1.15" "外层 $(basename -- "$found_sums") 校验包 tarball 成功"
  else
    fail "1.15" "外层 $(basename -- "$found_sums") 校验包 tarball 失败"
    dump_log "$LOG_DIR/outer-sha256.log" 30
  fi
}

check_package_layout() {
  local bad missing rel
  local -a rels=()

  if [[ -d "$PKG_ROOT" && ! -L "$PKG_ROOT" ]]; then
    pass "1.1" "离线包解出包根目录"
  else
    fail "1.1" "离线包包根不是普通目录: $PKG_ROOT"
    abort_tests
  fi

  if [[ "$PKG_VERSION" != "unknown" ]]; then
    check_eq "1.2" "包名与 VERSION 匹配" \
      "serverdashboard-v${PKG_VERSION#v}-x86_64.tar.gz" "$(basename -- "$PACKAGE")"
  else
    fail "1.2" "包内缺少 VERSION 或内容为空"
  fi

  check_executable "1.3" "bin/rustboard-hub 可执行" "$PKG_ROOT/bin/rustboard-hub"
  check_executable "1.4" "bin/rustboard-panel 可执行" "$PKG_ROOT/bin/rustboard-panel"
  check_executable "1.5" "bin/rustboard-agent 可执行" "$PKG_ROOT/bin/rustboard-agent"
  check_executable "1.6" "install.sh 可执行" "$PKG_ROOT/install.sh"
  check_file "1.7" "share/rustboard/web/index.html 存在" "$PKG_ROOT/share/rustboard/web/index.html"

  for rel in \
    systemd/rustboard-hub.service \
    systemd/rustboard-panel.service \
    systemd/rustboard-agent.service \
    SHA256SUMS \
    VERSION \
    LICENSE \
    README.md; do
    if [[ -f "$PKG_ROOT/$rel" && ! -L "$PKG_ROOT/$rel" ]]; then
      pass "1.8.$rel" "包内 $rel 存在且为普通文件"
    else
      fail "1.8.$rel" "包内 $rel 缺失或不是普通文件"
    fi
  done

  bad=$(find "$PKG_ROOT" -perm -0002 -print 2>/dev/null | head -n 3 || true)
  if [[ -z "$bad" ]]; then
    pass "1.9" "包内无 world-writable 文件/目录"
  else
    fail "1.9" "包内存在 world-writable 项: $(printf '%s' "$bad" | tr '\n' ' ')"
  fi

  bad=$(find "$PKG_ROOT" \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | head -n 3 || true)
  if [[ -z "$bad" ]]; then
    pass "1.10" "包内无 setuid/setgid 文件"
  else
    fail "1.10" "包内存在 setuid/setgid 文件: $(printf '%s' "$bad" | tr '\n' ' ')"
  fi

  if ( cd "$PKG_ROOT" && sha256sum -c --strict SHA256SUMS ) >"$LOG_DIR/sha256.log" 2>&1; then
    pass "1.11" "包内 sha256sum -c --strict SHA256SUMS 成功"
  else
    fail "1.11" "包内 sha256sum -c --strict SHA256SUMS 失败"
    dump_log "$LOG_DIR/sha256.log" 40
  fi

  awk '{print $2}' "$PKG_ROOT/SHA256SUMS" 2>/dev/null \
    | sed -e 's/^\*//' -e 's#^\./##' >"$LOG_DIR/sums.list" || true
  rels=(
    bin/rustboard-hub
    bin/rustboard-panel
    bin/rustboard-agent
    share/rustboard/web/index.html
    systemd/rustboard-hub.service
    systemd/rustboard-panel.service
    systemd/rustboard-agent.service
  )
  missing=""
  for rel in "${rels[@]}"; do
    if ! grep -Fxq -- "$rel" "$LOG_DIR/sums.list" 2>/dev/null; then
      missing+=" $rel"
    fi
  done
  if [[ -z "$missing" ]]; then
    pass "1.12" "SHA256SUMS 覆盖三个二进制、web index 与三个 unit"
  else
    fail "1.12" "SHA256SUMS 缺少条目:$missing"
  fi
}

check_static_binaries() {
  local bin desc
  if ! command -v file >/dev/null 2>&1; then
    skip "1.13" "file 不可用，跳过 x86_64 静态链接检查（SKIP 不计 PASS）"
    return
  fi
  for bin in rustboard-hub rustboard-panel rustboard-agent; do
    desc=$(file -b "$PKG_ROOT/bin/$bin" 2>/dev/null || true)
    if printf '%s' "$desc" | grep -Eqi '(x86-64|x86_64)' \
      && printf '%s' "$desc" | grep -Eqi 'statically linked|static-pie'; then
      pass "1.13.$bin" "bin/$bin 是 x86_64 静态/static-pie ELF"
    else
      fail "1.13.$bin" "bin/$bin 不是静态 x86_64 ELF（file: ${desc:-unknown}）"
    fi
  done
}

# ---------------------------------------------------------------------------
# 安装与启动
# ---------------------------------------------------------------------------

run_strace_logged() {
  local trace=$1 log=$2
  shift 2
  strace -f -qq -e trace=connect -o "$trace" "$@" >"$log" 2>&1
}

test_hub() {
  local rc
  HUB_PREFIX="$TMP_ROOT/prefix-hub"
  HUB_BIN="$HUB_PREFIX/usr/local/bin/rustboard-hub"
  HUB_CFG="$HUB_PREFIX/etc/rustboard/hub.toml"
  HUB_DATA="$HUB_PREFIX/var/lib/rustboard/hub"
  HUB_STATE="$HUB_PREFIX/var/lib/rustboard/install-state.toml"
  HUB_WEB="$HUB_PREFIX/usr/share/rustboard/web"

  HUB_PORT=$(pick_port) || die "无法挑选 hub agent 监听端口"
  HUB_ADMIN_PORT=$(pick_port_distinct "$HUB_PORT") || die "无法挑选 hub admin 监听端口"

  HUB_INSTALL_ARGS=(
    hub
    --yes --offline --no-systemd
    --prefix "$HUB_PREFIX"
    --listen "127.0.0.1:$HUB_PORT"
    --admin-listen "127.0.0.1:$HUB_ADMIN_PORT"
    --panel no
  )
  run_strace_logged "$LOG_DIR/connect-hub-install.log" "$LOG_DIR/hub-install.log" \
    bash "$PKG_ROOT/install.sh" "${HUB_INSTALL_ARGS[@]}"
  rc=$?
  check_rc_zero "3.1" "install.sh hub 安装成功（--offline --no-systemd）" \
    "$LOG_DIR/hub-install.log" "$rc"
  check_connect_log "2.3" "hub 安装期间无外部 connect（strace）" \
    "$LOG_DIR/connect-hub-install.log"
  if (( rc != 0 )); then
    abort_tests "hub 安装失败，后续 panel/agent 断言无法继续"
  fi

  check_executable "3.2" "hub 二进制安装到 prefix" "$HUB_BIN"
  check_file "3.3" "hub 配置文件存在" "$HUB_CFG"
  check_mode "3.4" "hub 配置 0600" "$HUB_CFG" 600
  if [[ -d "$HUB_DATA" && ! -L "$HUB_DATA" ]]; then
    pass "3.5" "hub 数据目录存在"
  else
    fail "3.5" "hub 数据目录不存在或不是普通目录: $HUB_DATA"
  fi
  check_dir_mode "3.6" "hub 数据目录 0700" "$HUB_DATA" 700
  check_file "3.7" "hub install-state 存在" "$HUB_STATE"
  check_mode "3.8" "hub install-state 0600" "$HUB_STATE" 600
  check_absent "3.9" "hub 未写 prefix 内 systemd unit（--no-systemd）" \
    "$HUB_PREFIX/etc/systemd/system/rustboard-hub.service"
  check_absent "3.9b" "hub --panel no 未安装同机 panel 配置" \
    "$HUB_PREFIX/etc/rustboard/panel.toml"
  check_file "3.10" "hub web 安装到 prefix/usr/share/rustboard/web" \
    "$HUB_WEB/index.html"

  ADMIN_TOKEN=$(extract_admin_token "$HUB_CFG")
  if [[ -z "$ADMIN_TOKEN" || "$ADMIN_TOKEN" == *[[:space:]]* ]]; then
    fail "3.11" "无法从 hub.toml 提取合法 admin_token"
    abort_tests "hub admin_token 缺失/格式异常，panel 安装无法继续"
  fi
  HUB_TOKEN_FILE="$TMP_ROOT/panel-hub-token"
  if ! ( umask 077; printf '%s\n' "$ADMIN_TOKEN" >"$HUB_TOKEN_FILE" ); then
    fail "3.11" "无法写入 panel 用的 0600 token 文件"
    abort_tests
  fi
  chmod 600 -- "$HUB_TOKEN_FILE" 2>/dev/null || true
  check_mode "3.11b" "panel 用的 hub token 文件 0600" "$HUB_TOKEN_FILE" 600
  pass "3.11c" "已从 hub.toml 读取 admin_token 并写入 token 文件（不打印）"

  if ! start_traced_server "$LOG_DIR/connect-hub-run.log" "$LOG_DIR/hub-run.log" \
    "$HUB_BIN" run --config "$HUB_CFG"; then
    fail "3.12" "hub run 启动失败（strace 包装）"
    dump_log "$LOG_DIR/hub-run.log" 60
    abort_tests "hub 未启动"
  fi
  HUB_RUN_PID=$STARTED_PID
  HUB_RUN_GROUP=$STARTED_GROUP
  if wait_http_200 "http://127.0.0.1:$HUB_ADMIN_PORT/healthz" 30 "$LOG_DIR/hub-health.body"; then
    pass "3.13" "hub admin /healthz 30s 内返回 200"
  else
    fail "3.13" "hub admin /healthz 未在 30s 内返回 200（最后状态 $LAST_CODE）"
    dump_log "$LOG_DIR/hub-run.log" 60
    abort_tests
  fi
}

test_idempotence() {
  local rc before after
  before=$(sha256_file "$HUB_CFG")

  run_strace_logged "$LOG_DIR/connect-hub-reinstall.log" "$LOG_DIR/hub-reinstall.log" \
    bash "$PKG_ROOT/install.sh" "${HUB_INSTALL_ARGS[@]}"
  rc=$?
  check_rc_zero "6.1" "package install.sh 重复执行退出 0" "$LOG_DIR/hub-reinstall.log" "$rc"
  check_connect_log "2.4" "hub 重复安装期间无外部 connect（strace）" \
    "$LOG_DIR/connect-hub-reinstall.log"

  after=$(sha256_file "$HUB_CFG")
  check_hash_unchanged "6.2" "hub 重复安装后 config sha256 不变" "$before" "$after"

  if wait_http_200 "http://127.0.0.1:$HUB_ADMIN_PORT/healthz" 10 "$LOG_DIR/hub-health2.body"; then
    pass "6.3" "hub 重复安装后 /healthz 仍 200"
  else
    fail "6.3" "hub 重复安装后 /healthz 不再 200（最后状态 $LAST_CODE）"
  fi

  check_absent "6.4" "hub 重复安装后仍未写 prefix 内 unit" \
    "$HUB_PREFIX/etc/systemd/system/rustboard-hub.service"
}

test_panel() {
  local rc code title marker_ok=0
  PANEL_PREFIX="$TMP_ROOT/prefix-panel"
  local panel_bin="$PANEL_PREFIX/usr/local/bin/rustboard-panel"
  local panel_cfg="$PANEL_PREFIX/etc/rustboard/panel.toml"
  local panel_web="$PANEL_PREFIX/usr/share/rustboard/web"
  local panel_unit="$PANEL_PREFIX/etc/systemd/system/rustboard-panel.service"

  PANEL_PORT=$(pick_port_distinct "$HUB_PORT" "$HUB_ADMIN_PORT") \
    || die "无法挑选 panel 监听端口"

  run_strace_logged "$LOG_DIR/connect-panel-install.log" "$LOG_DIR/panel-install.log" \
    bash "$PKG_ROOT/install.sh" panel \
    --yes --offline --no-systemd \
    --prefix "$PANEL_PREFIX" \
    --hub-url "http://127.0.0.1:$HUB_ADMIN_PORT" \
    --hub-token-file "$HUB_TOKEN_FILE" \
    --listen "127.0.0.1:$PANEL_PORT"
  rc=$?
  check_rc_zero "4.1" "install.sh panel 安装成功（--offline --no-systemd）" \
    "$LOG_DIR/panel-install.log" "$rc"
  check_connect_log "4.2" "panel 安装期间无外部 connect（strace）" \
    "$LOG_DIR/connect-panel-install.log"
  if (( rc != 0 )); then
    abort_tests "panel 安装失败"
  fi

  check_executable "4.3" "panel 二进制安装到 prefix" "$panel_bin"
  check_file "4.4" "panel 配置文件存在" "$panel_cfg"
  check_mode "4.5" "panel 配置 0600" "$panel_cfg" 600
  check_file "4.6" "panel web 安装到 prefix/usr/share/rustboard/web" \
    "$panel_web/index.html"
  check_absent "4.7" "panel 未写 prefix 内 systemd unit（--no-systemd）" "$panel_unit"

  if ! start_traced_server "$LOG_DIR/connect-panel-run.log" "$LOG_DIR/panel-run.log" \
    "$panel_bin" run --config "$panel_cfg"; then
    fail "4.8" "panel run 启动失败（strace 包装）"
    dump_log "$LOG_DIR/panel-run.log" 60
    abort_tests "panel 未启动"
  fi
  PANEL_RUN_PID=$STARTED_PID
  PANEL_RUN_GROUP=$STARTED_GROUP

  if wait_http_200 "http://127.0.0.1:$PANEL_PORT/healthz" 30 "$LOG_DIR/panel-health.body"; then
    pass "4.9" "panel /healthz 30s 内返回 200"
  else
    fail "4.9" "panel /healthz 未在 30s 内返回 200（最后状态 $LAST_CODE）"
    dump_log "$LOG_DIR/panel-run.log" 60
    abort_tests
  fi

  code=$(curl -sS --noproxy '*' --max-time 5 -o "$LOG_DIR/panel-index.body" \
    -w '%{http_code}' "http://127.0.0.1:$PANEL_PORT/" 2>/dev/null) || code="000"
  if [[ "$code" == "200" ]]; then
    pass "4.10" "panel / 返回 200"
  else
    fail "4.10" "panel / 期望 200，实际 $code"
  fi

  title=$(sed -n 's:.*<title>\([^<]*\)</title>.*:\1:p' "$panel_web/index.html" 2>/dev/null \
    | head -n 1 || true)
  if [[ -n "$title" ]] && grep -qF -- "<title>${title}</title>" "$LOG_DIR/panel-index.body" 2>/dev/null; then
    marker_ok=1
  elif grep -qF -- 'id="root"' "$LOG_DIR/panel-index.body" 2>/dev/null; then
    marker_ok=1
  fi
  if (( marker_ok )); then
    pass "4.11" "panel / 返回 index 标记（title 或 id=\"root\"）"
  else
    fail "4.11" "panel / 返回内容不含 index 标记"
  fi
}

test_agent() {
  local rc matches file unexpected="" cfg_hit=0
  AGENT_PREFIX="$TMP_ROOT/prefix-agent"
  local agent_bin="$AGENT_PREFIX/usr/local/bin/rustboard-agent"
  local agent_cfg="$AGENT_PREFIX/etc/rustboard/agent.toml"
  local agent_unit="$AGENT_PREFIX/etc/systemd/system/rustboard-agent.service"
  local token_file="$TMP_ROOT/agent-enroll-token"
  local dummy_token="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  local fingerprint="sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

  if ! ( umask 077; printf '%s\n' "$dummy_token" >"$token_file" ); then
    fail "5.0" "无法写入 agent dummy token 文件"
    abort_tests
  fi
  chmod 600 -- "$token_file" 2>/dev/null || true

  run_strace_logged "$LOG_DIR/connect-agent-install.log" "$LOG_DIR/agent-install.log" \
    bash "$PKG_ROOT/install.sh" agent \
    --yes --offline --no-systemd \
    --prefix "$AGENT_PREFIX" \
    --hub "wss://127.0.0.1:$HUB_PORT/agent/ws" \
    --token-file "$token_file" \
    --fingerprint "$fingerprint"
  rc=$?
  check_rc_zero "5.1" "install.sh agent 安装成功（--offline --no-systemd，不做 enrollment）" \
    "$LOG_DIR/agent-install.log" "$rc"
  check_connect_log "5.2" "agent 安装期间无外部 connect（strace）" \
    "$LOG_DIR/connect-agent-install.log"
  if (( rc != 0 )); then
    abort_tests "agent 安装失败"
  fi

  check_executable "5.3" "agent 二进制安装到 prefix" "$agent_bin"
  check_file "5.4" "agent 配置文件存在" "$agent_cfg"
  check_mode "5.5" "agent 配置 0600" "$agent_cfg" 600
  check_absent "5.6" "agent 未写 prefix 内 systemd unit（--no-systemd）" "$agent_unit"

  matches=$(grep -rIlF -- "$dummy_token" "$AGENT_PREFIX" 2>/dev/null || true)
  if [[ -z "$matches" ]]; then
    pass "5.7" "agent dummy token 未写入 prefix 内任何文本文件"
  else
    while IFS= read -r file; do
      [[ -n "$file" ]] || continue
      if [[ "$file" == "$agent_cfg" ]]; then
        cfg_hit=1
      else
        unexpected+=" $file"
      fi
    done <<<"$matches"
    if [[ -n "$unexpected" ]]; then
      fail "5.7" "agent dummy token 出现在非预期文件:$unexpected"
    elif (( cfg_hit )); then
      if [[ "$(stat -c '%a' -- "$agent_cfg" 2>/dev/null || true)" == "600" ]]; then
        pass "5.7" "agent dummy token 仅出现在 0600 config（Phase A 设计允许）"
      else
        fail "5.7" "agent dummy token 出现在非 0600 的 config"
      fi
    fi
  fi

  if grep -qF -- "$dummy_token" "$LOG_DIR/agent-install.log" 2>/dev/null; then
    fail "5.8" "agent 安装输出回显了 token"
  else
    pass "5.8" "agent 安装输出未回显 token"
  fi
}

test_agent_enrollment() {
  # 评审要求：agent 不能只做“不联网安装”，必须用 hub 本地签发的真实
  # enrollment token 启动一次并完成 enrollment；CLI 无法在 prefix/no-systemd
  # 下签 token 时必须 FAIL，不得静默 SKIP。
  local rc fp attempt token_file log enrolled deadline pid group
  local agent_bin agent_cfg agent_data agent_unit
  AGENT_RUN_PREFIX="$TMP_ROOT/prefix-agent-run"
  agent_bin="$AGENT_RUN_PREFIX/usr/local/bin/rustboard-agent"
  agent_cfg="$AGENT_RUN_PREFIX/etc/rustboard/agent.toml"
  agent_data="$AGENT_RUN_PREFIX/var/lib/rustboard/agent"
  agent_unit="$AGENT_RUN_PREFIX/etc/systemd/system/rustboard-agent.service"
  token_file="$TMP_ROOT/agent-run-token"
  log="$LOG_DIR/agent-add.log"

  if run_limited_cmd 10 "$HUB_BIN" agent add --help \
    >"$LOG_DIR/agent-add-help.log" 2>&1 \
    && grep -q -- '--config' "$LOG_DIR/agent-add-help.log" \
    && grep -q -- '--name' "$LOG_DIR/agent-add-help.log"; then
    pass "10.0" "hub agent add --help 暴露 --config/--name（prefix/no-systemd 签名入口）"
  else
    fail "10.0" "hub agent add 不支持 --config/--name，无法在 prefix/no-systemd 下签 token"
    return
  fi

  for attempt in 1 2 3; do
    run_limited_cmd 60 "$HUB_BIN" agent add --config "$HUB_CFG" --name "v100-offline-agent" \
      >"$log" 2>&1
    rc=$?
    (( rc == 0 )) && break
    if (( attempt < 3 )); then
      sleep 1
    fi
  done
  check_rc_zero "10.1" "hub agent add 在 prefix/no-systemd 下签发 enrollment token" \
    "$log" "$rc"
  if (( rc != 0 )); then
    return
  fi

  fp=$(parse_agent_add_log "$log" "$token_file")
  rc=$?
  if (( rc != 0 )) || [[ ! "$fp" =~ ^[0-9a-f]{64}$ ]]; then
    fail "10.2" "无法从 agent add 输出解析唯一 token 与 64hex 指纹（不改用 SKIP）"
    return
  fi
  check_mode "10.3" "agent enrollment token 文件 0600" "$token_file" 600
  pass "10.4" "agent add 输出已解析（token 不回显，指纹 64hex）"

  run_strace_logged "$LOG_DIR/connect-agent-enroll-install.log" \
    "$LOG_DIR/agent-enroll-install.log" \
    bash "$PKG_ROOT/install.sh" agent \
    --yes --offline --no-systemd \
    --prefix "$AGENT_RUN_PREFIX" \
    --hub "wss://127.0.0.1:$HUB_PORT/agent/ws" \
    --token-file "$token_file" \
    --fingerprint "sha256:$fp" \
    --name "v100-offline-agent"
  rc=$?
  check_rc_zero "10.5" "install.sh agent 使用真实 token 安装成功" \
    "$LOG_DIR/agent-enroll-install.log" "$rc"
  check_connect_log "10.6" "agent enrollment 安装期间无外部 connect（strace）" \
    "$LOG_DIR/connect-agent-enroll-install.log"
  if (( rc != 0 )); then
    return
  fi
  check_executable "10.7" "运行用 agent 二进制安装到 prefix" "$agent_bin"
  check_file "10.8" "运行用 agent 配置存在" "$agent_cfg"
  check_mode "10.9" "运行用 agent 配置 0600" "$agent_cfg" 600
  check_absent "10.10" "运行用 agent 未写 prefix 内 systemd unit" "$agent_unit"

  if ! start_traced_server "$LOG_DIR/connect-agent-run.log" "$LOG_DIR/agent-run.log" \
    "$agent_bin" run --config "$agent_cfg"; then
    fail "10.11" "agent run 启动失败（strace 包装）"
    dump_log "$LOG_DIR/agent-run.log" 60
    return
  fi
  AGENT_RUN_PID=$STARTED_PID
  AGENT_RUN_GROUP=$STARTED_GROUP

  enrolled=0
  deadline=$(( $(date +%s) + 45 ))
  while :; do
    if [[ -s "$agent_data/agent.crt" && -s "$agent_data/agent_id" ]]; then
      enrolled=1
      break
    fi
    if ! kill -0 "$AGENT_RUN_PID" 2>/dev/null; then
      break
    fi
    if (( $(date +%s) >= deadline )); then
      break
    fi
    sleep 0.3
  done
  if (( enrolled == 0 )); then
    if run_limited_cmd 10 "$agent_bin" cert-info --config "$agent_cfg" \
      >"$LOG_DIR/agent-cert-info.log" 2>&1; then
      enrolled=2
    fi
  fi
  if (( enrolled == 0 )); then
    fail "10.12" "agent 45s 内未完成 enrollment（agent.crt/agent_id 或 cert-info 均失败）"
    dump_log "$LOG_DIR/agent-run.log" 60
    pid=$AGENT_RUN_PID
    group=$AGENT_RUN_GROUP
    stop_pid "$pid" "$group" "agent"
    AGENT_RUN_PID=""
    AGENT_RUN_GROUP=0
    check_connect_log "10.20" "agent run 期间无外部 connect（strace）" \
      "$LOG_DIR/connect-agent-run.log"
    return
  fi
  pass "10.12" "agent 45s 内完成 enrollment（crt/agent_id 或 cert-info）"
  check_file "10.13" "agent 数据目录生成 agent.crt" "$agent_data/agent.crt"
  check_file "10.14" "agent 数据目录生成 agent_id" "$agent_data/agent_id"

  if kill -0 "$AGENT_RUN_PID" 2>/dev/null; then
    pass "10.15" "enrollment 后 agent 进程仍在运行"
  else
    fail "10.15" "enrollment 后 agent 进程已退出"
  fi
  if run_limited_cmd 10 "$agent_bin" cert-info --config "$agent_cfg" \
    >"$LOG_DIR/agent-cert-info.log" 2>&1; then
    pass "10.16" "agent cert-info 在 enrollment 后退出 0"
  else
    fail "10.16" "agent cert-info 在 enrollment 后非零退出"
    dump_log "$LOG_DIR/agent-cert-info.log" 20
  fi

  if [[ -s "$token_file" ]] \
    && grep -qF -- "$(tr -d '\n' <"$token_file")" "$LOG_DIR/agent-run.log" 2>/dev/null; then
    fail "10.17" "agent run 日志回显了 enrollment token"
  else
    pass "10.17" "agent run 日志未回显 enrollment token"
  fi

  pid=$AGENT_RUN_PID
  group=$AGENT_RUN_GROUP
  stop_pid "$pid" "$group" "agent"
  AGENT_RUN_PID=""
  AGENT_RUN_GROUP=0
  sleep 0.2
  if kill -0 "$pid" 2>/dev/null; then
    fail "10.18" "agent 进程未能清理"
  else
    pass "10.18" "agent 进程已停止"
  fi
  check_connect_log "10.19" "agent run 期间无外部 connect（strace）" \
    "$LOG_DIR/connect-agent-run.log"
}

test_tamper_web() {
  # 评审要求：修改 web 下 JS/CSS 并从包内 SHA256SUMS 删除对应行后，
  # install.sh 仍必须失败，不能只信任可篡改的包内清单。
  local tamper_web="$TMP_ROOT/tamper-web"
  local tamper_prefix="$TMP_ROOT/tamper-web-prefix"
  local js css rel_js rel_css rc
  if ! cp -a -- "$PKG_ROOT" "$tamper_web" 2>/dev/null; then
    fail "7.6" "无法复制包目录用于 web 篡改测试"
    return
  fi
  js=$(find "$tamper_web/share/rustboard/web" -type f -name '*.js' -print -quit 2>/dev/null)
  css=$(find "$tamper_web/share/rustboard/web" -type f -name '*.css' -print -quit 2>/dev/null)
  if [[ -z "$js" || -z "$css" ]]; then
    fail "7.6" "包内 web 缺少 JS/CSS 资源，无法执行清单删除篡改测试"
    return
  fi
  printf 'X' >>"$js"
  printf 'X' >>"$css"
  rel_js=${js#"$tamper_web/"}
  rel_css=${css#"$tamper_web/"}
  awk -v a="$rel_js" -v b="$rel_css" '
    {
      p = $2
      sub(/^\*/, "", p)
      sub(/^\.\//, "", p)
      if (p != a && p != b) print
    }
  ' "$tamper_web/SHA256SUMS" >"$tamper_web/SHA256SUMS.new"
  mv -- "$tamper_web/SHA256SUMS.new" "$tamper_web/SHA256SUMS"

  if [[ ! -s "$tamper_web/SHA256SUMS" ]] \
    || ! grep -Fq -- "bin/rustboard-hub" "$tamper_web/SHA256SUMS"; then
    fail "7.6" "删除 web 校验行后 SHA256SUMS 异常（为空或缺少其他条目）"
    return
  fi
  if ( cd "$tamper_web" && sha256sum -c --strict SHA256SUMS ) >"$LOG_DIR/tamper-web-sha.log" 2>&1; then
    pass "7.6" "测试前提：修改 JS/CSS 并删除对应 SHA256SUMS 行后，包内校验仍通过"
  else
    fail "7.6" "测试前提不成立：删除对应行后包内 sha256sum -c 仍失败"
    return
  fi

  bash "$tamper_web/install.sh" hub \
    --yes --offline --no-systemd \
    --prefix "$tamper_prefix" \
    --panel no >"$LOG_DIR/tamper-web.log" 2>&1
  rc=$?
  check_rc_nonzero "7.7" "删除 web 校验行的篡改包 install.sh 必须非零" \
    "$LOG_DIR/tamper-web.log" "$rc"
  check_absent "7.8" "web 清单篡改测试未创建 config" \
    "$tamper_prefix/etc/rustboard/hub.toml"
  check_absent "7.9" "web 清单篡改测试未创建 bin" \
    "$tamper_prefix/usr/local/bin/rustboard-hub"
  check_absent "7.10" "web 清单篡改测试零写入（prefix 不存在）" "$tamper_prefix"
}

run_hub_install_with_prefix() {
  local prefix=$1 log=$2
  bash "$PKG_ROOT/install.sh" hub \
    --yes --offline --no-systemd \
    --prefix "$prefix" \
    --panel no >"$log" 2>&1
}

test_prefix_negative() {
  local rc target link prefix
  # 1) prefix 是符号链接：拒绝，且不写链接目标。
  target="$TMP_ROOT/prefix-symlink-target"
  link="$TMP_ROOT/prefix-symlink"
  mkdir -p -- "$target" && chmod 700 -- "$target"
  ln -s -- "$target" "$link"
  run_hub_install_with_prefix "$link" "$LOG_DIR/prefix-symlink.log"
  rc=$?
  check_rc_nonzero "11.1" "prefix 为符号链接时 install.sh 必须拒绝" \
    "$LOG_DIR/prefix-symlink.log" "$rc"
  check_absent "11.2" "符号链接 prefix 未写目标 config" "$target/etc/rustboard/hub.toml"
  check_absent "11.3" "符号链接 prefix 未写目标 bin" "$target/usr/local/bin/rustboard-hub"

  # 2) prefix 为 1777（world-writable + sticky）：拒绝。
  prefix="$TMP_ROOT/prefix-1777"
  mkdir -p -- "$prefix"
  chmod 1777 -- "$prefix"
  run_hub_install_with_prefix "$prefix" "$LOG_DIR/prefix-1777.log"
  rc=$?
  check_rc_nonzero "11.4" "prefix 为 1777 时 install.sh 必须拒绝" \
    "$LOG_DIR/prefix-1777.log" "$rc"
  check_absent "11.5" "1777 prefix 未写 config" "$prefix/etc/rustboard/hub.toml"

  # 3) prefix 为 group-writable（0770）：拒绝。
  prefix="$TMP_ROOT/prefix-group-writable"
  mkdir -p -- "$prefix"
  chmod 770 -- "$prefix"
  run_hub_install_with_prefix "$prefix" "$LOG_DIR/prefix-group-writable.log"
  rc=$?
  check_rc_nonzero "11.6" "prefix 为 group-writable（0770）时 install.sh 必须拒绝" \
    "$LOG_DIR/prefix-group-writable.log" "$rc"
  check_absent "11.7" "group-writable prefix 未写 config" \
    "$prefix/etc/rustboard/hub.toml"
}

test_tamper() {
  local rc tamper_root tamper_prefix
  tamper_root="$TMP_ROOT/tamper-pkg"
  tamper_prefix="$TMP_ROOT/tamper-prefix"

  if ! cp -a -- "$PKG_ROOT" "$tamper_root" 2>/dev/null; then
    fail "7.1" "无法复制包目录用于篡改测试"
    return
  fi
  printf 'X' >>"$tamper_root/bin/rustboard-hub" 2>/dev/null || true
  if ( cd "$tamper_root" && sha256sum -c --strict SHA256SUMS ) >"$LOG_DIR/tamper-sha.log" 2>&1; then
    fail "7.1" "篡改 1 字节后 sha256sum -c 仍成功（测试前提未成立）"
    return
  fi
  pass "7.1" "测试前提：篡改 1 字节后包内校验失败"

  bash "$tamper_root/install.sh" hub \
    --yes --offline --no-systemd --dry-run \
    --prefix "$tamper_prefix" \
    --panel no >"$LOG_DIR/tamper.log" 2>&1
  rc=$?
  check_rc_nonzero "7.2" "篡改包 install.sh hub --dry-run 非零退出" \
    "$LOG_DIR/tamper.log" "$rc"
  check_absent "7.3" "篡改包未创建新 prefix 的 config" \
    "$tamper_prefix/etc/rustboard/hub.toml"
  check_absent "7.4" "篡改包未创建新 prefix 的 bin" \
    "$tamper_prefix/usr/local/bin/rustboard-hub"
  check_absent "7.5" "篡改包在写任何文件前退出（新 prefix 不存在）" "$tamper_prefix"
}

test_argv_secrets() {
  local flag name secret prefix log rc
  for flag in --token --password --admin-token --hub-token --token_file; do
    name=${flag#--}
    name=${name//_/-}
    secret="v100-argv-${name}-$RANDOM$RANDOM-$(date +%s)"
    prefix="$TMP_ROOT/argv-prefix-${name}"
    log="$LOG_DIR/argv-${name}.log"
    bash "$PKG_ROOT/install.sh" hub \
      --yes --offline --no-systemd \
      --prefix "$prefix" \
      --panel no "$flag" "$secret" >"$log" 2>&1
    rc=$?
    # 注意：该日志可能包含明文 secret，失败/异常时都不要 dump。
    if (( rc == 0 )); then
      fail "8.1.$name" "明文 argv $flag 未被拒绝（期望非零，实际 0）"
    elif (( rc == 124 || rc == 137 )); then
      fail "8.1.$name" "明文 argv $flag 命令超时/被杀（rc=$rc）"
    else
      pass "8.1.$name" "明文 argv $flag 被拒绝（rc=$rc）"
    fi
    if grep -qF -- "$secret" "$log" 2>/dev/null; then
      fail "8.2.$name" "错误输出回显了明文 secret"
    else
      pass "8.2.$name" "错误输出未回显明文 secret"
    fi
    check_absent "8.3.$name" "明文 argv $flag 失败后未创建 config" \
      "$prefix/etc/rustboard/hub.toml"
    check_absent "8.3b.$name" "明文 argv $flag 失败后未创建 bin" \
      "$prefix/usr/local/bin/rustboard-hub"
  done
}

# ---------------------------------------------------------------------------
# 子进程：netns 内完整测试
# ---------------------------------------------------------------------------

run_inside_netns() {
  local ns before_prod after_prod

  ns=$(readlink /proc/self/ns/net 2>/dev/null || true)
  [[ -n "$ns" && "$ns" != "${HOST_NETNS:-}" ]] \
    || die "未进入独立 network namespace（当前 $ns / host $HOST_NETNS）"

  ip link set lo up >/dev/null 2>&1 || die "netns 内 ip link set lo up 失败"

  if ip route show default 2>/dev/null | grep -q .; then
    die "netns 内存在 IPv4 默认路由，无法保证离线"
  fi
  if ip -6 route show default 2>/dev/null | grep -q .; then
    die "netns 内存在 IPv6 默认路由，无法保证离线"
  fi
  if curl -sS --noproxy '*' --max-time 3 -o /dev/null http://1.1.1.1/ 2>/dev/null; then
    die "netns 仍可访问外网 IP（1.1.1.1），离线测试无效"
  fi
  if curl -sS --noproxy '*' --max-time 3 -o /dev/null http://rb-offline-probe.invalid/ 2>/dev/null; then
    die "netns 仍可解析/访问外部 DNS 名称，离线测试无效"
  fi
  pass "2.1" "netns 隔离：lo up、无默认路由、外网 IP/DNS curl 失败"
  pass "2.2" "在独立 netns 内执行安装与启动"

  verify_snapshot_detects_rewrite
  before_prod="$TMP_ROOT/prod-before.txt"
  after_prod="$TMP_ROOT/prod-after.txt"
  snapshot_prod_paths >"$before_prod"

  check_package_layout
  validate_package_provenance
  check_outer_checksum
  check_static_binaries

  test_hub
  test_idempotence
  test_panel
  test_agent
  test_agent_enrollment
  test_tamper
  test_tamper_web
  test_prefix_negative
  test_argv_secrets

  stop_servers
  sleep 0.5

  check_connect_log "2.5" "hub run 期间无外部 connect（strace）" \
    "$LOG_DIR/connect-hub-run.log"
  check_connect_log "4.12" "panel run 期间无外部 connect（strace）" \
    "$LOG_DIR/connect-panel-run.log"

  snapshot_prod_paths >"$after_prod"
  check_prod_untouched "$before_prod" "$after_prod"

  finish
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

main() {
  case $# in
    0) ;;
    1)
      case "$1" in
        -h | --help)
          usage
          exit 0
          ;;
        --netns-child)
          NETNS_CHILD=1
          ;;
        *)
          printf '未知参数: %s\n' "$1" >&2
          usage >&2
          exit 2
          ;;
      esac
      ;;
    *)
      printf '未知参数: %s\n' "$*" >&2
      usage >&2
      exit 2
      ;;
  esac

  if (( NETNS_CHILD == 1 )); then
    [[ "${RB_OFFLINE_CHILD:-0}" == "1" ]] || die "缺少子进程环境标记"
    TMP_ROOT="${RB_OFFLINE_TMP:-}"
    PKG_ROOT="${RB_OFFLINE_PKG_ROOT:-}"
    PACKAGE="${RB_OFFLINE_PACKAGE:-}"
    PKG_VERSION="${RB_OFFLINE_VERSION:-}"
    PACKAGE_MODE="${RB_OFFLINE_PACKAGE_MODE:-}"
    HOST_NETNS="${RB_OFFLINE_HOST_NETNS:-}"
    KEEP_E2E_TMP="${RB_OFFLINE_KEEP_TMP:-0}"
    LOG_DIR="$TMP_ROOT/logs"
    [[ -n "$HOST_NETNS" ]] || die "子进程缺少 host netns 标记"
    install_cleanup_traps
    is_safe_tmp_root || die "子进程临时目录未通过安全校验: $TMP_ROOT"
    [[ -d "$PKG_ROOT" && "$PKG_ROOT" == "$TMP_ROOT"/* ]] \
      || die "子进程包根不合法: $PKG_ROOT"
    run_inside_netns
    return 0
  fi

  preflight
  resolve_package
  ensure_tmp_root

  if ! strace -f -qq -e trace=connect -o "$TMP_ROOT/strace-probe.log" true \
    >/dev/null 2>&1; then
    die "strace 不可用（ptrace 被拒绝或缺少 -f 支持）"
  fi

  extract_package

  export RB_OFFLINE_CHILD=1
  export RB_OFFLINE_TMP="$TMP_ROOT"
  export RB_OFFLINE_PKG_ROOT="$PKG_ROOT"
  export RB_OFFLINE_PACKAGE="$PACKAGE"
  export RB_OFFLINE_VERSION="$PKG_VERSION"
  export RB_OFFLINE_PACKAGE_MODE="$PACKAGE_MODE"
  export RB_OFFLINE_HOST_NETNS="$HOST_NETNS"
  export RB_OFFLINE_KEEP_TMP="$KEEP_E2E_TMP"

  printf 'INFO: 进入 unshare -n 执行离线安装/启动断言\n'
  shopt -s execfail
  # shellcheck disable=SC2093  # execfail 已开启，失败时继续走 die 分支。
  exec unshare -n -- bash "$SELF" --netns-child
  die "无法进入 network namespace（unshare -n 失败）"
}

# 测试注入点：RB_E2E_TESTING=1 时只加载函数，不执行真实 E2E（供 /tmp 最小
# 子进程测试覆盖 trap/cleanup 退出码）。
if [[ "${RB_E2E_TESTING:-0}" != "1" ]]; then
  main "$@"
fi
