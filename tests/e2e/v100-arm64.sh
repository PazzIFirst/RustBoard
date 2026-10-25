#!/usr/bin/env bash
#
# RustBoard M5 Phase B（v1.0.0）arm64 离线包独立 e2e（qemu-user / 原生）。
#
# 只读依据（不阅读 packaging/install.sh 实现细节）：
#   - docs/plans/2026-10-25-m5-phase-b-delivery.md（B-G1/B-G2/B-G4、§3.3、§3.6、§6、§8）
#   - docs/plans/2026-10-24-m5-phase-a-installer.md §3
#   - 现有 CLI 的运行时 --help 输出
#
# 覆盖：
#   1) 解析 aarch64 离线包：只有显式 PACKAGE/SKIP_BUILD=1 才复用，默认总是
#      调用 build-release.sh 重建；复用前校验 VERSION 与 Cargo.toml、包内
#      install.sh/三个二进制 hash 与当前源码；校验外层 SHA256SUMS.<arch>；
#      包根布局/权限/包名/版本；`file` 断言三个二进制为 aarch64 静态/static-pie；
#      包内 `sha256sum -c --strict SHA256SUMS` 成功且覆盖二进制/web/unit；
#   2) 运行器：`uname -m == aarch64` 直接执行；否则要求 qemu-aarch64(-static)，
#      用 qemu 执行；不依赖 binfmt。注意：package install.sh 会按本机 uname -m
#      校验架构（有意拒绝异架构包），因此非 aarch64 主机即使 binfmt 可透明执行，
#      也不能走 install.sh，只能 qemu 直接执行二进制并把 install.sh 直接执行记
#      SKIP（不放宽产品架构校验）；两者都没有时 FATAL，不以“编译成功”冒充 PASS；
#   3) rustboard-{hub,panel,agent} --version 输出含包内 VERSION；
#   4) hub install --yes --offline --no-systemd --dry-run --prefix ... 退出 0
#      且不写 prefix；实际 install 到随机 127.0.0.1 端口，启动 hub（qemu/原生），
#      轮询 admin /healthz 200；断言 web 目录存在；非原生主机按约定手动复制
#      包内 web（不修改产品），并把“直接执行 install.sh”记 SKIP；
#   5) 全程 --no-systemd，不碰真实 unit/生产路径；生产路径用递归内容 hash/
#      权限/属主/符号链接快照比对；失败日志先 redact；
#   6) 清理所有进程与 $HOME/rustboard-v100-arm64.* 临时目录。
#
# 约束：只写 $HOME/rustboard-v100-arm64.*；trap 清理前校验路径（仅
#       /opt/rustboard-v100-*、非符号链接、readlink -f 等于自身）；
#       不打印 token/密码/私钥；SKIP 不计入 PASS。
#
# 依赖：Linux root、bash 4.4+、sha256sum、file、tar、curl、awk/sed/stat/find；
#       非 aarch64 主机还需要 qemu-aarch64-static 或 qemu-aarch64。
# 用法：bash tests/e2e/v100-arm64.sh
# 环境：
#   PACKAGE=<tar.gz>  显式指定 aarch64 离线包；指定时复用并校验来源一致性
#   SKIP_BUILD=1      只用现有 dist 包（复用前同样校验来源一致性）
#   KEEP_E2E_TMP=1    保留临时目录与日志
#   QEMU=<binary>     显式指定 qemu-aarch64(-static)
#   STRICT=1          SKIP 也按失败处理（CI 严格模式）
#   ALLOW_UNVERIFIED=1 仅当 dist/<arch>/bin 或 web/dist 缺源时显式放行：
#                     打印 WARN、不计 PASS；hash 不一致仍 FATAL（默认 fail-closed）
#
set -uo pipefail
umask 077
export LC_ALL=C

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
BUILD_RELEASE="$ROOT/packaging/build-release.sh"

PASSES=0
FAILS=0
SKIPS=0

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
ARCH_SUFFIX="aarch64"
DIST_ARCH="arm64"
QEMU="${QEMU:-}"
NATIVE=0
QEMU_BIN=""
DIRECT_EXEC=0

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
HUB_BIN=""
HUB_CFG=""
HUB_STATE=""
HUB_WEB=""
HUB_PORT=""
HUB_ADMIN_PORT=""
HUB_PID=""
LAST_CODE=""

# ---------------------------------------------------------------------------
# 输出 / redact / 断言
# ---------------------------------------------------------------------------

usage() {
  cat <<'EOF'
用法: bash tests/e2e/v100-arm64.sh

M5 Phase B arm64 离线包 e2e：用 qemu-aarch64(-static)（或原生 aarch64）运行
rustboard-{hub,panel,agent}，验证 --version、install --dry-run、实际安装与
hub /healthz；不只检查“编译成功”。package install.sh 按本机 uname -m 校验
架构，非 aarch64 主机不直接执行它（用 qemu 跑二进制，install.sh 记 SKIP）。

环境变量:
  PACKAGE=<tar.gz>  显式指定 aarch64 离线包；指定时复用并校验来源一致性
  SKIP_BUILD=1      只用现有 dist 包（复用前同样校验来源一致性）
  KEEP_E2E_TMP=1    保留 $HOME/rustboard-v100-arm64.* 与日志
  QEMU=<binary>     显式指定 qemu-aarch64 或 qemu-aarch64-static
  STRICT=1          SKIP 也按失败处理（CI 严格模式；x86 主机默认会因 SKIP 失败）
  ALLOW_UNVERIFIED=1 仅当 dist/<arch>/bin 或 web/dist 缺源时显式放行：
                    打印 WARN、不计 PASS；hash 不一致仍 FATAL；默认 fail-closed

默认（既无 PACKAGE 也无 SKIP_BUILD）总是调用 packaging/build-release.sh
重新构建，不复用 dist 里 mtime 最新的旧包。

前置条件（缺失 FATAL）:
  root、sha256sum、file、tar、curl、awk/sed/stat/find；
  非 aarch64 主机还要 qemu-aarch64-static（或 qemu-aarch64）。
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
    printf '===== v100-arm64 e2e: PASS=%s FAIL=%s SKIP=%s STRICT=%s =====\n' \
      "$PASSES" "$FAILS" "$SKIPS" "$STRICT" >&2
  fi
  exit 1
}

finish() {
  local code=0
  printf '\n===== v100-arm64 e2e: PASS=%s FAIL=%s SKIP=%s STRICT=%s =====\n' \
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

check_rc_zero() {
  local id=$1 desc=$2 log=$3 rc=$4
  if (( rc == 0 )); then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（rc=$rc）"
    dump_log "$log" 50
  fi
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

# ---------------------------------------------------------------------------
# 临时目录 / 清理
# ---------------------------------------------------------------------------

is_safe_tmp_root() {
  local path=${TMP_ROOT:-} real
  [[ -n "$path" ]] || return 1
  [[ "$path" == $HOME/rustboard-v100-arm64.* ]] || return 1
  [[ "$path" != *..* && "$path" != "/" && "$path" != "$HOME" ]] || return 1
  [[ -d "$path" && ! -L "$path" ]] || return 1
  [[ "${path%/*}" == "$HOME" ]] || return 1
  real=$(readlink -f -- "$path" 2>/dev/null || true)
  [[ -n "$real" && "$real" == "$path" ]] || return 1
  return 0
}

ensure_tmp_root() {
  [[ -n "$TMP_ROOT" ]] && return 0
  TMP_ROOT=$(mktemp -d "$HOME/rustboard-v100-arm64.XXXXXX" 2>/dev/null) \
    || die "无法在 $HOME 下创建临时目录（需要 root 与可写 HOME）"
  is_safe_tmp_root || die "临时目录未通过安全校验: $TMP_ROOT"
  LOG_DIR="$TMP_ROOT/logs"
  mkdir -p -- "$LOG_DIR" || die "无法创建日志目录: $LOG_DIR"
  trap cleanup EXIT INT TERM
  return 0
}

stop_hub() {
  local pid=${1:-$HUB_PID} i
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for ((i = 0; i < 50; i++)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  printf 'INFO: 已停止 hub（pid=%s）\n' "$pid" >&2
  HUB_PID=""
  return 0
}

dump_failure_logs() {
  [[ -n "$LOG_DIR" ]] || return 0
  printf '===== v100-arm64 e2e 失败现场（redacted）=====\n' >&2
  dump_log "$LOG_DIR/build.log" 40
  dump_log "$LOG_DIR/tar.log" 20
  dump_log "$LOG_DIR/sha256.log" 40
  dump_log "$LOG_DIR/outer-sha256.log" 30
  dump_log "$LOG_DIR/dry-run.log" 40
  dump_log "$LOG_DIR/install.log" 60
  dump_log "$LOG_DIR/hub-run.log" 60
}

cleanup() {
  local code=$?
  trap - EXIT INT TERM

  stop_hub "${HUB_PID:-}"

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
# 前置 / 包解析 / 运行器
# ---------------------------------------------------------------------------

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

preflight() {
  (( EUID == 0 )) || die "需要 root（在 $HOME 下创建临时 prefix 并启动 arm64 测试实例）"
  [[ "$(uname -s)" == "Linux" ]] || die "仅支持 Linux"

  local cmd
  for cmd in sha256sum file tar curl awk sed stat find mktemp readlink uname; do
    require_cmd "$cmd"
  done

  if [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; then
    NATIVE=1
    QEMU_BIN=""
    printf 'INFO: 本机为 aarch64，直接执行 arm64 二进制\n'
  else
    NATIVE=0
    if [[ -n "$QEMU" ]]; then
      [[ -f "$QEMU" && -x "$QEMU" ]] || die "QEMU 指定的解释器不可执行: $QEMU"
      QEMU_BIN=$QEMU
    elif command -v qemu-aarch64-static >/dev/null 2>&1; then
      QEMU_BIN=$(command -v qemu-aarch64-static)
    elif command -v qemu-aarch64 >/dev/null 2>&1; then
      QEMU_BIN=$(command -v qemu-aarch64)
    else
      die "非 aarch64 主机且找不到 qemu-aarch64-static/qemu-aarch64；不能只编译通过就 PASS"
    fi
    printf 'INFO: 使用 QEMU 运行 arm64 二进制: %s\n' "$QEMU_BIN"
  fi

  command -v timeout >/dev/null 2>&1 \
    || printf 'WARN: timeout 不可用，外部命令不使用超时包装\n' >&2
  command -v ss >/dev/null 2>&1 \
    || printf 'WARN: ss 不可用，端口占用探测使用 /dev/tcp 回退\n' >&2
}

run_limited() {
  local secs=$1
  shift
  if command -v timeout >/dev/null 2>&1; then
    timeout "$secs" "$@"
  else
    "$@"
  fi
}

run_guest_limited() {
  local secs=$1
  shift
  if (( NATIVE )); then
    run_limited "$secs" "$@"
  else
    run_limited "$secs" "$QEMU_BIN" "$@"
  fi
}

start_hub_bg() {
  local log=$1
  if (( NATIVE )); then
    "$HUB_BIN" run --config "$HUB_CFG" >"$log" 2>&1 &
  else
    "$QEMU_BIN" "$HUB_BIN" run --config "$HUB_CFG" >"$log" 2>&1 &
  fi
  HUB_PID=$!
  sleep 0.3
  if ! kill -0 "$HUB_PID" 2>/dev/null; then
    HUB_PID=""
    return 1
  fi
  return 0
}

find_package() {
  local dir="$ROOT/dist" found
  [[ -d "$dir" ]] || return 1
  found=$(find "$dir" -maxdepth 1 -type f -name 'serverdashboard-v*-aarch64.tar.gz' \
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

# 只有显式 PACKAGE 或 SKIP_BUILD=1 才复用；默认总是重建。
resolve_package() {
  local found base
  if [[ -n "$PACKAGE" ]]; then
    PACKAGE_MODE="explicit"
    [[ -f "$PACKAGE" ]] || die "PACKAGE 指向的离线包不存在: $PACKAGE"
    PACKAGE=$(readlink -f -- "$PACKAGE" 2>/dev/null) || die "无法解析 PACKAGE 真实路径"
    [[ -f "$PACKAGE" ]] || die "PACKAGE 不是普通文件: $PACKAGE"
  elif [[ "$SKIP_BUILD" == "1" ]]; then
    PACKAGE_MODE="skip_build"
    found=$(find_package || true)
    [[ -n "$found" ]] \
      || die "SKIP_BUILD=1，但 $ROOT/dist 下没有 serverdashboard-v*-aarch64.tar.gz"
    PACKAGE=$found
  else
    PACKAGE_MODE="built"
    [[ -f "$BUILD_RELEASE" ]] \
      || die "默认需要重新构建，但找不到公开构建入口 $BUILD_RELEASE"
    ensure_tmp_root
    printf 'INFO: 默认重建 arm64 离线包：packaging/build-release.sh --arch arm64\n'
    if ! bash "$BUILD_RELEASE" --arch arm64 >"$LOG_DIR/build.log" 2>&1; then
      dump_log "$LOG_DIR/build.log" 50
      die "packaging/build-release.sh --arch arm64 失败"
    fi
    found=$(find_package || true)
    [[ -n "$found" ]] \
      || die "构建成功但未找到 dist/serverdashboard-v*-aarch64.tar.gz"
    PACKAGE=$found
  fi

  PACKAGE=$(readlink -f -- "$PACKAGE" 2>/dev/null) || die "无法解析包路径"
  base=$(basename -- "$PACKAGE")
  [[ "$base" == serverdashboard-v*-aarch64.tar.gz ]] \
    || die "本脚本只接受 aarch64 离线包，当前: $base"
  [[ -s "$PACKAGE" ]] || die "离线包为空: $PACKAGE"
  printf 'INFO: 使用 arm64 离线包 %s（mode=%s）\n' "$PACKAGE" "$PACKAGE_MODE"
}

# 缺源默认 FATAL；只有 ALLOW_UNVERIFIED=1 显式放行“缺源”（WARN、不计 PASS）；
# hash 不一致始终 FATAL。
validate_package_provenance() {
  local cargo_version pkg_hash src_hash bin src pkg_install
  local src_bin_dir="" src_web="$ROOT/web/dist" pkg_web src_dir
  local src_web_digest pkg_web_digest missing="" complete rc

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

  for src_dir in "$ROOT/dist/$DIST_ARCH/bin" "$ROOT/dist/$ARCH_SUFFIX/bin"; do
    [[ -d "$src_dir" && ! -L "$src_dir" ]] || continue
    complete=1
    for bin in rustboard-hub rustboard-panel rustboard-agent; do
      if [[ ! -f "$src_dir/$bin" || -L "$src_dir/$bin" ]]; then
        complete=0
      fi
    done
    if (( complete == 1 )); then
      src_bin_dir="$src_dir"
      break
    fi
  done
  if [[ -z "$src_bin_dir" ]]; then
    missing+=" dist/$DIST_ARCH/bin/{rustboard-hub,rustboard-panel,rustboard-agent}"
  fi
  if [[ ! -f "$ROOT/packaging/install.sh" || -L "$ROOT/packaging/install.sh" ]]; then
    missing+=" packaging/install.sh"
  fi
  if [[ ! -d "$src_web" || -L "$src_web" || ! -f "$src_web/index.html" ]]; then
    missing+=" web/dist"
  fi

  if [[ -n "$missing" ]]; then
    if [[ "$ALLOW_UNVERIFIED" == "1" ]]; then
      printf 'WARN: ALLOW_UNVERIFIED=1：缺少源%s；跳过包来源一致性校验（不计 PASS，hash 不一致仍会 FATAL）\n' \
        "$missing" >&2
      return 0
    fi
    die "缺少源$missing；默认 fail-closed，不能验证包来源。请先构建源码，或显式 ALLOW_UNVERIFIED=1（仅在源不可得的逃生场景）"
  fi

  pkg_hash=$(sha256_file "$pkg_install")
  src_hash=$(sha256_file "$ROOT/packaging/install.sh")
  if [[ "$pkg_hash" != "$src_hash" ]]; then
    die "包内 install.sh 与当前 packaging/install.sh 不一致（mode=$PACKAGE_MODE）；请重建或指定当前包"
  fi

  for bin in rustboard-hub rustboard-panel rustboard-agent; do
    src="$src_bin_dir/$bin"
    pkg_hash=$(sha256_file "$PKG_ROOT/bin/$bin")
    src_hash=$(sha256_file "$src")
    if [[ "$pkg_hash" != "$src_hash" ]]; then
      die "包内 bin/$bin 与当前 $src 不一致（mode=$PACKAGE_MODE）；请重建或指定当前包"
    fi
  done

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

  pass "1.14" "包 VERSION、install.sh、三二进制、web 树与当前源码一致（mode=$PACKAGE_MODE）"
}

extract_package() {
  local -a tops=()
  local top_count

  EXTRACT_DIR="$TMP_ROOT/extract"
  mkdir -p -- "$EXTRACT_DIR" || die "无法创建解包目录"
  if ! tar -xzf "$PACKAGE" -C "$EXTRACT_DIR" >"$LOG_DIR/tar.log" 2>&1; then
    fail "1.0" "解包 arm64 离线包失败"
    dump_log "$LOG_DIR/tar.log" 30
    abort_tests
  fi

  mapfile -t tops < <(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null)
  top_count=${#tops[@]}
  if (( top_count == 1 )) && [[ -d "$EXTRACT_DIR/${tops[0]}" && ! -L "$EXTRACT_DIR/${tops[0]}" ]]; then
    PKG_ROOT="$EXTRACT_DIR/${tops[0]}"
  else
    PKG_ROOT="$EXTRACT_DIR"
  fi
  PKG_ROOT=$(readlink -f -- "$PKG_ROOT" 2>/dev/null) || die "无法解析解包路径"
  [[ "$PKG_ROOT" == "$TMP_ROOT"/* ]] || die "解包路径越出临时目录: $PKG_ROOT"

  if [[ -f "$PKG_ROOT/VERSION" ]]; then
    PKG_VERSION=$(tr -d '[:space:]' < "$PKG_ROOT/VERSION" 2>/dev/null || true)
  fi
  if [[ -z "$PKG_VERSION" ]]; then
    # 包损坏时也尽量从文件名派生版本，后续 VERSION 检查会 FAIL。
    PKG_VERSION=$(basename -- "$PACKAGE" | sed -n 's/^serverdashboard-v\(.*\)-aarch64\.tar\.gz$/\1/p')
  fi
  [[ -n "$PKG_VERSION" ]] || PKG_VERSION="unknown"
  printf 'INFO: 包根 %s（VERSION=%s）\n' "$PKG_ROOT" "$PKG_VERSION"
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

verify_snapshot_detects_rewrite() {
  local dir="$TMP_ROOT/snapshot-selftest"
  local tree="$dir/tree"
  local before="$dir/before.snap"
  local after="$dir/after.snap"
  rm -rf -- "$dir" 2>/dev/null || true
  mkdir -p -- "$tree" || {
    fail "6.0" "无法创建快照自检目录"
    return
  }
  printf 'one\n' >"$tree/file.txt"
  chmod 600 -- "$tree/file.txt"
  snapshot_paths "$tree" >"$before"
  printf 'two\n' >"$tree/file.txt"
  snapshot_paths "$tree" >"$after"
  if cmp -s -- "$before" "$after"; then
    fail "6.0" "递归快照自检失败：原地改写文件后快照未变化"
  else
    pass "6.0" "递归快照能发现已有文件被原地改写（内容 hash 生效）"
  fi
  rm -rf -- "$dir" 2>/dev/null || true
}

check_prod_untouched() {
  local before=$1 after=$2
  if cmp -s -- "$before" "$after"; then
    pass "6.1" "生产路径未被触碰（--no-systemd + prefix）"
  else
    fail "6.1" "生产路径被修改（diff 仅打印路径）"
    diff -u -- "$before" "$after" 2>/dev/null | head -n 20 >&2 || true
  fi
}

# ---------------------------------------------------------------------------
# 包内容 / 版本
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
    pass "1.1" "arm64 离线包解出包根目录"
  else
    fail "1.1" "离线包包根不是普通目录: $PKG_ROOT"
    abort_tests
  fi

  check_eq "1.2" "包名与 VERSION 匹配" \
    "serverdashboard-v${PKG_VERSION#v}-aarch64.tar.gz" "$(basename -- "$PACKAGE")"
  if [[ -s "$PKG_ROOT/VERSION" && ! -L "$PKG_ROOT/VERSION" ]]; then
    pass "1.3" "包内 VERSION 存在且非空"
  else
    fail "1.3" "包内 VERSION 缺失/为空/是符号链接"
  fi
  check_executable "1.4" "bin/rustboard-hub 可执行" "$PKG_ROOT/bin/rustboard-hub"
  check_executable "1.5" "bin/rustboard-panel 可执行" "$PKG_ROOT/bin/rustboard-panel"
  check_executable "1.6" "bin/rustboard-agent 可执行" "$PKG_ROOT/bin/rustboard-agent"
  check_executable "1.7" "install.sh 可执行" "$PKG_ROOT/install.sh"
  check_file "1.8" "share/rustboard/web/index.html 存在" "$PKG_ROOT/share/rustboard/web/index.html"

  for rel in \
    systemd/rustboard-hub.service \
    systemd/rustboard-panel.service \
    systemd/rustboard-agent.service \
    SHA256SUMS \
    LICENSE \
    README.md; do
    if [[ -f "$PKG_ROOT/$rel" && ! -L "$PKG_ROOT/$rel" ]]; then
      pass "1.9.$rel" "包内 $rel 存在且为普通文件"
    else
      fail "1.9.$rel" "包内 $rel 缺失或不是普通文件"
    fi
  done

  bad=$(find "$PKG_ROOT" -perm -0002 -print 2>/dev/null | head -n 3 || true)
  if [[ -z "$bad" ]]; then
    pass "1.10" "包内无 world-writable 文件/目录"
  else
    fail "1.10" "包内存在 world-writable 项: $(printf '%s' "$bad" | tr '\n' ' ')"
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
  for bin in rustboard-hub rustboard-panel rustboard-agent; do
    desc=$(file -b "$PKG_ROOT/bin/$bin" 2>/dev/null || true)
    if printf '%s' "$desc" | grep -Eqi 'aarch64' \
      && printf '%s' "$desc" | grep -Eqi 'statically linked|static-pie'; then
      pass "2.1.$bin" "bin/$bin 是 aarch64 静态/static-pie ELF"
    else
      fail "2.1.$bin" "bin/$bin 不是静态 aarch64 ELF（file: ${desc:-unknown}）"
    fi
  done
}

check_versions() {
  local bin out rc
  for bin in rustboard-hub rustboard-panel rustboard-agent; do
    out=$(run_guest_limited 60 "$PKG_ROOT/bin/$bin" --version 2>&1)
    rc=$?
    if (( rc != 0 )); then
      fail "3.1.$bin" "$bin --version 失败（rc=$rc；qemu/原生执行异常）"
      printf '%s\n' "$out" | tail -n 5 | redact_stream >&2 || true
    elif [[ "$out" == *"$PKG_VERSION"* ]]; then
      pass "3.1.$bin" "$bin --version 输出含 VERSION=$PKG_VERSION"
    else
      fail "3.1.$bin" "$bin --version 输出不含 VERSION=$PKG_VERSION"
    fi
  done
}

# ---------------------------------------------------------------------------
# 安装 / 启动
# ---------------------------------------------------------------------------

test_dry_run() {
  local dry_prefix="$TMP_ROOT/dry-run-prefix" rc
  rm -rf -- "$dry_prefix" 2>/dev/null || true
  run_guest_limited 180 "$PKG_ROOT/bin/rustboard-hub" install \
    --yes --offline --no-systemd --dry-run --prefix "$dry_prefix" \
    >"$LOG_DIR/dry-run.log" 2>&1
  rc=$?
  check_rc_zero "4.1" "rustboard-hub install --dry-run 退出 0" \
    "$LOG_DIR/dry-run.log" "$rc"
  check_absent "4.2" "--dry-run 未创建 prefix（零写入）" "$dry_prefix"
}

detect_direct_exec() {
  # package install.sh 会按本机 uname -m 校验包架构（有意拒绝异架构包）。
  # 因此即使 x86_64 主机通过 binfmt 能执行 aarch64 ELF，也不能直接跑
  # package install.sh；非原生主机一律用 qemu 跑二进制，并记 SKIP。
  if (( NATIVE )); then
    DIRECT_EXEC=1
    pass "2.2" "本机为 aarch64，package install.sh 可直接执行"
  else
    DIRECT_EXEC=0
    skip "2.2" "非 aarch64 主机：package install.sh 按设计拒绝异架构包；改用 qemu 直接执行二进制，install.sh 直接执行记 SKIP"
  fi
}

test_install_and_run() {
  local rc web_index
  HUB_PREFIX="$TMP_ROOT/prefix-hub"
  HUB_BIN="$HUB_PREFIX/usr/local/bin/rustboard-hub"
  HUB_CFG="$HUB_PREFIX/etc/rustboard/hub.toml"
  HUB_STATE="$HUB_PREFIX/var/lib/rustboard/install-state.toml"
  HUB_WEB="$HUB_PREFIX/usr/share/rustboard/web"

  HUB_PORT=$(pick_port) || die "无法挑选 hub agent 监听端口"
  HUB_ADMIN_PORT=$(pick_port_distinct "$HUB_PORT") || die "无法挑选 hub admin 监听端口"

  if (( DIRECT_EXEC )); then
    run_limited 300 bash "$PKG_ROOT/install.sh" hub \
      --yes --offline --no-systemd \
      --prefix "$HUB_PREFIX" \
      --listen "127.0.0.1:$HUB_PORT" \
      --admin-listen "127.0.0.1:$HUB_ADMIN_PORT" \
      --panel no >"$LOG_DIR/install.log" 2>&1
    rc=$?
    check_rc_zero "4.3" "package install.sh hub 安装成功（原生 aarch64 直接执行）" \
      "$LOG_DIR/install.log" "$rc"
  else
    run_guest_limited 300 "$PKG_ROOT/bin/rustboard-hub" install \
      --yes --offline --no-systemd \
      --prefix "$HUB_PREFIX" \
      --listen "127.0.0.1:$HUB_PORT" \
      --admin-listen "127.0.0.1:$HUB_ADMIN_PORT" \
      --panel no >"$LOG_DIR/install.log" 2>&1
    rc=$?
    check_rc_zero "4.3" "qemu 执行 rustboard-hub install 成功" \
      "$LOG_DIR/install.log" "$rc"
  fi
  if (( rc != 0 )); then
    abort_tests "arm64 hub 实际安装失败"
  fi

  check_executable "4.4" "hub 二进制安装到 prefix" "$HUB_BIN"
  if [[ -f "$HUB_BIN" ]]; then
    local bin_desc
    bin_desc=$(file -b "$HUB_BIN" 2>/dev/null || true)
    if printf '%s' "$bin_desc" | grep -Eqi 'aarch64'; then
      pass "4.5" "安装后的 hub 二进制仍是 aarch64 ELF"
    else
      fail "4.5" "安装后的 hub 不是 aarch64 ELF（file: ${bin_desc:-unknown}）"
    fi
  fi
  check_file "4.6" "hub 配置存在" "$HUB_CFG"
  check_mode "4.7" "hub 配置 0600" "$HUB_CFG" 600
  check_file "4.8" "hub install-state 存在" "$HUB_STATE"
  check_absent "4.9" "hub 未写 prefix 内 systemd unit（--no-systemd）" \
    "$HUB_PREFIX/etc/systemd/system/rustboard-hub.service"

  web_index="$HUB_WEB/index.html"
  if [[ -f "$web_index" ]]; then
    pass "4.10" "package install.sh 把 web 安装到 prefix/usr/share/rustboard/web"
  elif (( DIRECT_EXEC )); then
    fail "4.10" "package install.sh 未安装 web 目录"
  else
    mkdir -p -- "$(dirname -- "$HUB_WEB")" 2>/dev/null || true
    if cp -a -- "$PKG_ROOT/share/rustboard/web" "$HUB_WEB" 2>/dev/null; then
      skip "4.10" "非原生主机：按测试约定手动复制包内 web（非产品行为，不计 PASS）；直接执行 install.sh 已 SKIP"
    else
      fail "4.10" "手动复制包内 web 到 prefix 失败"
    fi
  fi
  if [[ -f "$web_index" ]]; then
    pass "4.11" "prefix/usr/share/rustboard/web/index.html 存在"
  else
    fail "4.11" "prefix/usr/share/rustboard/web/index.html 不存在"
  fi

  if ! start_hub_bg "$LOG_DIR/hub-run.log"; then
    fail "4.12" "hub 进程启动失败（qemu/原生）"
    dump_log "$LOG_DIR/hub-run.log" 60
    abort_tests "arm64 hub 未启动"
  fi
  if wait_http_200 "http://127.0.0.1:$HUB_ADMIN_PORT/healthz" 45 "$LOG_DIR/hub-health.body"; then
    pass "4.13" "arm64 hub admin /healthz 45s 内返回 200"
  else
    fail "4.13" "arm64 hub admin /healthz 未在 45s 内返回 200（最后状态 $LAST_CODE）"
    dump_log "$LOG_DIR/hub-run.log" 60
    abort_tests
  fi

  local out
  out=$(run_guest_limited 60 "$HUB_BIN" --version 2>&1 || true)
  if [[ "$out" == *"$PKG_VERSION"* ]]; then
    pass "4.14" "安装后的 hub --version 含 VERSION=$PKG_VERSION"
  else
    fail "4.14" "安装后的 hub --version 输出不含 VERSION=$PKG_VERSION"
  fi

  local hub_pid=$HUB_PID
  stop_hub "$hub_pid"
  sleep 0.2
  if kill -0 "$hub_pid" 2>/dev/null; then
    fail "4.15" "hub 进程未能清理"
  else
    pass "4.15" "hub 进程已停止"
  fi
  HUB_PID=""
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

  preflight
  resolve_package
  ensure_tmp_root
  extract_package

  local before_prod="$TMP_ROOT/prod-before.txt"
  local after_prod="$TMP_ROOT/prod-after.txt"
  verify_snapshot_detects_rewrite
  snapshot_prod_paths >"$before_prod"

  check_package_layout
  validate_package_provenance
  check_outer_checksum
  check_static_binaries
  check_versions
  detect_direct_exec
  test_dry_run
  test_install_and_run

  snapshot_prod_paths >"$after_prod"
  check_prod_untouched "$before_prod" "$after_prod"

  finish
}

main "$@"
