#!/usr/bin/env bash
#
# RustBoard M5 Phase B/C（v1.0.0）Docker 交付物独立 e2e。
#
# 依据（只读设计文档与 Docker/Compose 接口，不参考 entrypoint 实现细节）：
#   - docs/plans/2026-10-25-m5-phase-b-delivery.md §3.4、§3.6、§6、§9
#   - docs/plans/2026-10-24-m5-phase-a-installer.md §3
#   - docker/Dockerfile 的 target / build-arg / EXPOSE / HEALTHCHECK 接口
#   - docker/compose.example.yml 的端口、network_mode、profile 接口
#   - tests/e2e/v100-install.sh 的 PASS/FAIL、redact、trap 清理约定
#
# 覆盖：
#   1) 前置：docker/buildx/curl/python3/git；dist/$DOCKER_ARCH/bin 与 web/dist 缺失即
#      FATAL，明确提示先运行 packaging/build-release.sh --arch "$DOCKER_ARCH"；
#   2) 三镜像 buildx --load 构建（linux/$DOCKER_ARCH）与架构断言；
#   3) 镜像隔离：无 /etc/rustboard/<role>.toml、无 /var/lib/rustboard、无 .key/.pem、
#      无运行期 admin token；hub 默认 EXPOSE 8443/80/443（80/443 仅 ACME 元数据，
#      默认 compose 不发布）、panel 8080，8444 不 EXPOSE；
#   4) hub：healthcheck、管理口 8444 /healthz、配置 0600、--no-systemd 无 unit、
#      web 静态目录、主进程 UID 10001、tini 为 root、运行容器只发布 8443；
#   5) 重启幂等：docker restart 后 config/admin_token 的 sha256 不变；
#   6) --user 10001:10001：已初始化 volume 可启动，空 volume 必须非零退出且不写配置；
#   7) panel：共享 hub netns + hub_run volume（token 文件 0600、panel ro 挂载）、
#      8080 healthz 与 /、panel→hub 8444 /healthz、主进程 UID 10001、8444 不发布到宿主；
#   8) agent：无 docker.sock/systemd、--version、空 env fail-fast 且不写 config、
#      未使用 privileged；用 hub 真实 enrollment token + 指纹启动 agent，
#      轮询 cert-info healthy，断言主进程 UID 10001、tini root、无 root agent、
#      control 默认关闭、agent 配置 0600/10001 可读；
#   9) compose：docker compose config 语法、8444 不在 ports、panel network_mode、
#      agent profile 且默认不启动、agent 非 privileged/无 docker.sock；
#  10) arm64 附加检查（仅 DOCKER_ARCH=amd64 且 SKIP_ARM64!=1）：QEMU/binfmt 与
#      dist/arm64 产物均可用时构建并运行 hub；否则 SKIP。DOCKER_ARCH=arm64 时主用例
#      主用例本身即按 arm64 执行全部断言，不再重复该附加检查；多架构 manifest 仍明确标注
#      未在本地验证（由 release workflow 负责）。
#
# 约束：
#   - 只创建 rustboard-test/*:local-$DOCKER_ARCH 本地镜像、临时容器/网络/volume 与
#     mktemp 目录；不 push、不碰宿主 /etc /var/lib /usr/local 与生产路径；
#   - 不打印 token / 密码 / 私钥；失败现场 tail 全部经过 redact；
#   - 所有容器/网络/volume/临时目录在 trap 中清理；失败非零退出；
#   - 不修改 Dockerfile / entrypoint / compose / packaging 实现。
#
# 依赖：bash 4.4+、docker 24+、docker buildx、docker compose（缺失时回退
#       python3 + PyYAML）、curl、python3、git、timeout、sha256sum、tar。
# 用法：DOCKER_ARCH=amd64 bash tests/e2e/v100-docker.sh
#       DOCKER_ARCH=arm64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh   # arm64 原生主机
#       bash tests/e2e/v100-docker.sh --help
# 环境：
#   DOCKER_ARCH=amd64|arm64  运行架构（默认 amd64）。平台 linux/$DOCKER_ARCH、源
#                            dist/$DOCKER_ARCH/bin、包名 x86_64/aarch64、
#                            SHA256SUMS.<pkgarch>；非法值直接 FATAL；
#   SKIP_ARM64=1             跳过可选的 arm64/QEMU 附加检查（避免同一门禁重复；
#                            DOCKER_ARCH=arm64 时也会自动跳过）；
#   HEALTH_TIMEOUT=180       healthcheck 等待秒数；
#   EMPTY_TIMEOUT=30         空 volume/agent 空 env 失败等待秒数；
#   KEEP_E2E_TMP=1           保留临时目录与日志。
# 调试：HEALTH_TIMEOUT=300 / EMPTY_TIMEOUT=60 可放宽等待；KEEP_E2E_TMP=1 保留现场。
#
# cleanup 及其辅助函数由 trap 间接调用；ShellCheck 看不到这条路径，SC2317 为误报。
# shellcheck disable=SC2317,SC2016
set -uo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$ROOT" || {
  printf 'FATAL: 无法进入仓库根目录: %s\n' "$ROOT" >&2
  exit 1
}

PYTHON=${PYTHON:-python3}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-180}
EMPTY_TIMEOUT=${EMPTY_TIMEOUT:-30}
KEEP_E2E_TMP=${KEEP_E2E_TMP:-0}

# 架构参数：平台、dist 源目录、包架构后缀与镜像 tag 全部由 DOCKER_ARCH 派生。
# 非法值必须在任何 preflight/构建之前 FATAL，避免误用错架构产物。
DOCKER_ARCH=${DOCKER_ARCH:-amd64}
SKIP_ARM64=${SKIP_ARM64:-0}
case "$DOCKER_ARCH" in
  amd64) PKG_ARCH=x86_64 ;;
  arm64) PKG_ARCH=aarch64 ;;
  *)
    printf 'FATAL: DOCKER_ARCH 只允许 amd64 或 arm64，实际为 [%s]\n' "$DOCKER_ARCH" >&2
    exit 1
    ;;
esac
case "$SKIP_ARM64" in
  0 | 1) ;;
  *)
    printf 'FATAL: SKIP_ARM64 只允许 0 或 1，实际为 [%s]\n' "$SKIP_ARM64" >&2
    exit 1
    ;;
esac
ARCH_PLATFORM="linux/${DOCKER_ARCH}"
IMAGE_TAG="local-${DOCKER_ARCH}"

PASSES=0
FAILS=0
SKIPS=0
SUMMARY_PRINTED=0
ARM64_VERIFIED=0
ARM64_SKIPPED=0

TMP_ROOT=""
LOG_DIR=""
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
NET_NAME="rb-e2e-${RUN_ID}-net"
HUB_RUN_VOLUME="rb-e2e-${RUN_ID}-run"

HUB_IMAGE="rustboard-test/hub:${IMAGE_TAG}"
PANEL_IMAGE="rustboard-test/panel:${IMAGE_TAG}"
AGENT_IMAGE="rustboard-test/agent:${IMAGE_TAG}"
# 只在 DOCKER_ARCH=amd64 的可选 QEMU 附加检查中使用；tag 同时带主架构与目标架构，
# 与 HUB_IMAGE 始终不同，避免覆盖主镜像。
ARM64_HUB_IMAGE="rustboard-test/hub:local-${DOCKER_ARCH}-qemu-arm64"

HUB_CT="rb-e2e-${RUN_ID}-hub"
PANEL_CT="rb-e2e-${RUN_ID}-panel"
PANEL_USER_CT="rb-e2e-${RUN_ID}-panel-user"
USER_CT="rb-e2e-${RUN_ID}-hub-user"
AGENT_CT="rb-e2e-${RUN_ID}-agent"
EMPTY_CT="rb-e2e-${RUN_ID}-hub-empty"
AGENT_EMPTY_CT="rb-e2e-${RUN_ID}-agent-empty"
PORT_PROBE_PREFIX="rb-e2e-${RUN_ID}-port"

HUB_DATA=""
PANEL_DATA=""
AGENT_DATA=""
AGENT_EMPTY_DATA=""
AGENT_TOKEN_FILE=""
EMPTY_DATA=""
HOST_8443=""
HOST_8080=""
VERSION=""
REVISION=""
HAVE_COMPOSE=0
HAVE_QEMU_AARCH64=0
LAST_STATE="unknown"
LAST_CODE="000"

CONTAINERS=()
NETWORKS=()
VOLUMES=()

# ---------------------------------------------------------------------------
# 输出、redact 与清理
# ---------------------------------------------------------------------------

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
  printf 'SKIP [%s] %s\n' "$1" "$2"
}

info() {
  printf 'INFO %s\n' "$*"
}

die() {
  printf 'FATAL: %s\n' "$*" >&2
  exit 1
}

# 角色 -> 本地镜像 tag（带架构后缀，amd64/arm64 互不覆盖）。
image_for_role() {
  case "$1" in
    hub) printf '%s' "$HUB_IMAGE" ;;
    panel) printf '%s' "$PANEL_IMAGE" ;;
    agent) printf '%s' "$AGENT_IMAGE" ;;
    *) return 1 ;;
  esac
}

usage() {
  cat <<'EOF'
用法: [DOCKER_ARCH=amd64|arm64] [SKIP_ARM64=1] bash tests/e2e/v100-docker.sh [--help]

M5 Docker 交付 e2e：按 DOCKER_ARCH 构建并运行 hub/panel/agent 三镜像
（在对应架构主机上为原生执行），
覆盖镜像隔离、默认端口、非 root 主进程、健康检查、重启幂等、--user、panel
共享 netns、agent 空环境 fail-fast、真实 enrollment 与 compose 结构。
x86_64 主机可在 QEMU 可用且 dist/arm64 存在时附加验证 arm64 hub。

环境变量:
  DOCKER_ARCH=amd64|arm64  运行架构，默认 amd64。平台 linux/$DOCKER_ARCH、
                           源 dist/$DOCKER_ARCH/bin、包名 x86_64/aarch64、
                           校验 dist/SHA256SUMS.<pkgarch>；非法值直接 FATAL
  SKIP_ARM64=1             跳过可选 arm64/QEMU 附加检查；DOCKER_ARCH=arm64 时
                           主用例即按 linux/arm64 执行，该附加检查也自动跳过
  HEALTH_TIMEOUT=180       healthcheck 等待秒数
  EMPTY_TIMEOUT=30         空 volume/agent 空 env 失败退出等待秒数
  KEEP_E2E_TMP=1           保留临时目录与日志

用法示例:
  bash tests/e2e/v100-docker.sh
  DOCKER_ARCH=amd64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh
  DOCKER_ARCH=arm64 SKIP_ARM64=1 bash tests/e2e/v100-docker.sh   # arm64 原生主机
EOF
}

# 日志/容器输出永不原样打印：先遮掉 token、密码、Bearer、私钥与 64hex。
redact_stream() {
  sed -E \
    -e 's/((admin_token|token|secret|password|passwd|fingerprint)[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
    -e 's/((admin|hub)[ _-]?token[^:=]*[:=][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
    -e 's/(--(token|hub-token|password)(-file)?[[:space:]=]+)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1<redacted>/Ig' \
    -e 's/((初始)?密码[^:：]*[:：][[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/\b[0-9a-fA-F]{64}\b/<redacted-64hex>/g' \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----.*/<redacted-private-key>/g' \
    -e 's/.*(admin_token|admin token).*/<redacted admin_token line>/Ig' \
    -e 's/\b[A-Za-z0-9_-]{32,}\b/<redacted-long-value>/g'
}

dump_file() {
  local file=${1:-} lines=${2:-60}
  [[ -n "$file" && -f "$file" && -s "$file" ]] || return 0
  printf -- '---- %s (tail -n %s, redacted) ----\n' "$(basename -- "$file")" "$lines" >&2
  tail -n "$lines" -- "$file" 2>/dev/null | redact_stream >&2 || true
}

dump_container_logs() {
  local ct=${1:-} lines=${2:-80}
  [[ -n "$ct" ]] || return 0
  docker inspect "$ct" >/dev/null 2>&1 || return 0
  printf -- '---- docker logs %s (tail -n %s, redacted) ----\n' "$ct" "$lines" >&2
  docker logs --tail "$lines" "$ct" 2>&1 | redact_stream >&2 || true
}

dump_diagnostics() {
  local i ct file
  printf '===== v100-docker e2e 失败现场（日志尾部，已 redact）=====\n' >&2

  for file in \
    "$LOG_DIR/build-hub.log" \
    "$LOG_DIR/build-panel.log" \
    "$LOG_DIR/build-agent.log" \
    "$LOG_DIR/arm64-build.log" \
    "$LOG_DIR/compose-default.err" \
    "$LOG_DIR/compose-all.err" \
    "$LOG_DIR/compose-fallback.err" \
    "$LOG_DIR/compose-facts.err" \
    "$LOG_DIR/source-outer-sums.log" \
    "$LOG_DIR/source-package-sums.log" \
    "$LOG_DIR/source-extract.log" \
    "$LOG_DIR/source-web.diff" \
    "$LOG_DIR/source-web.err" \
    "$LOG_DIR/source-web-package.err" \
    "$LOG_DIR/image-web-hub.err" \
    "$LOG_DIR/image-web-hub.diff" \
    "$LOG_DIR/image-web-panel.err" \
    "$LOG_DIR/image-web-panel.diff" \
    "$LOG_DIR/empty-hub.log" \
    "$LOG_DIR/agent-empty.log"; do
    dump_file "$file" 80
  done

  for ((i = 0; i < ${#CONTAINERS[@]}; i++)); do
    ct=${CONTAINERS[$i]}
    if docker inspect "$ct" >/dev/null 2>&1; then
      printf -- '---- container %s state ----\n' "$ct" >&2
      docker inspect -f 'status={{.State.Status}} exit={{.State.ExitCode}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}} restarts={{.RestartCount}}' \
        "$ct" >&2 2>/dev/null || true
      docker port "$ct" 2>/dev/null | sed 's/^/port /' >&2 || true
      dump_container_logs "$ct" 80
    fi
  done
}

is_safe_tmp_root() {
  local path=${TMP_ROOT:-} real base=${TMPDIR:-/tmp}
  base=${base%/}
  [[ -n "$path" ]] || return 1
  [[ "$path" == "$base"/rustboard-v100-docker.* ]] || return 1
  [[ "$path" != *..* && "$path" != "/" ]] || return 1
  [[ -d "$path" && ! -L "$path" ]] || return 1
  real=$(readlink -f -- "$path" 2>/dev/null || true)
  [[ -n "$real" && "$real" == "$path" ]] || return 1
  return 0
}

# 容器以 root 首启时会把 /data 等子目录 chown 到 10001；非 root 宿主可能删不掉。
# 先普通 rm；失败且有 hub 镜像时用一次性 root 容器清空临时目录内容。
cleanup_tmp_root() {
  local path=${TMP_ROOT:-}
  [[ -n "$path" && -d "$path" ]] || return 0

  rm -rf -- "$path" 2>/dev/null || true
  if [[ -e "$path" ]] && docker image inspect "$HUB_IMAGE" >/dev/null 2>&1; then
    docker run --rm --user 0:0 -v "$path:/cleanup" --entrypoint /bin/sh \
      "$HUB_IMAGE" -c 'find /cleanup -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +' \
      >/dev/null 2>&1 || true
  fi
  rm -rf -- "$path" 2>/dev/null || true
  [[ ! -e "$path" ]]
}

print_summary() {
  (( SUMMARY_PRINTED == 0 )) || return 0
  SUMMARY_PRINTED=1
  printf '===== v100-docker e2e: PASS=%s FAIL=%s SKIP=%s =====\n' \
    "$PASSES" "$FAILS" "$SKIPS"
  printf 'INFO: 本次 DOCKER_ARCH=%s（%s），包架构 %s；多架构 manifest（linux/amd64 + linux/arm64 合并、latest 标签、GHCR digest）未在本地验证，由 release workflow 的 buildx/imagetools 负责。\n' \
    "$DOCKER_ARCH" "$ARCH_PLATFORM" "$PKG_ARCH"
  if (( ARM64_VERIFIED )); then
    printf 'INFO: arm64 单架构镜像已在本机 QEMU 下构建并运行；合并 manifest 仍需 release workflow 验证。\n'
  elif (( ARM64_SKIPPED )); then
    if [[ "$DOCKER_ARCH" == "arm64" ]]; then
      printf 'INFO: 可选 arm64/QEMU 附加检查已跳过：本门禁按 linux/arm64 执行，主用例已覆盖 arm64（arm64 主机上为原生）。\n'
    elif [[ "$SKIP_ARM64" == "1" ]]; then
      printf 'INFO: 可选 arm64/QEMU 附加检查已跳过（SKIP_ARM64=1）；arm64 原生门禁由 delivery-arm64 覆盖。\n'
    else
      printf 'INFO: 本机未执行 arm64 镜像附加验证（SKIP 原因见上），不视为通过。\n'
    fi
  fi
}

cleanup() {
  local code=$? i name leftovers=0

  trap - EXIT INT TERM

  # 无论 KEEP_E2E_TMP 与否，先移除 enrollment token 临时文件，避免 secret 落盘。
  if [[ -n "${AGENT_TOKEN_FILE:-}" ]]; then
    rm -f -- "$AGENT_TOKEN_FILE" 2>/dev/null || true
  fi
  if [[ -n "${LOG_DIR:-}" ]]; then
    rm -f -- "$LOG_DIR/agent-enroll-add.out" "$LOG_DIR/agent-enroll-add.err" 2>/dev/null || true
  fi

  if (( code != 0 || FAILS > 0 )); then
    dump_diagnostics
  fi

  for ((i = ${#CONTAINERS[@]} - 1; i >= 0; i--)); do
    name=${CONTAINERS[$i]}
    docker rm -f -- "$name" >/dev/null 2>&1 || true
  done
  for ((i = 0; i < ${#CONTAINERS[@]}; i++)); do
    name=${CONTAINERS[$i]}
    if docker inspect "$name" >/dev/null 2>&1; then
      printf 'CLEANUP FAIL: 容器仍存在: %s\n' "$name" >&2
      leftovers=1
    fi
  done

  for ((i = 0; i < ${#VOLUMES[@]}; i++)); do
    name=${VOLUMES[$i]}
    docker volume rm -f -- "$name" >/dev/null 2>&1 || true
    if docker volume inspect "$name" >/dev/null 2>&1; then
      printf 'CLEANUP FAIL: volume 仍存在: %s\n' "$name" >&2
      leftovers=1
    fi
  done

  for ((i = 0; i < ${#NETWORKS[@]}; i++)); do
    name=${NETWORKS[$i]}
    docker network rm -- "$name" >/dev/null 2>&1 || true
    if docker network inspect "$name" >/dev/null 2>&1; then
      printf 'CLEANUP FAIL: network 仍存在: %s\n' "$name" >&2
      leftovers=1
    fi
  done

  if [[ "$KEEP_E2E_TMP" == "1" ]]; then
    printf '临时目录已保留: %s\n' "${TMP_ROOT:-<unset>}" >&2
  elif [[ -z "$TMP_ROOT" ]]; then
    :
  elif is_safe_tmp_root; then
    if ! cleanup_tmp_root; then
      printf 'CLEANUP FAIL: 临时目录未删除: %s\n' "$TMP_ROOT" >&2
      leftovers=1
    fi
  else
    printf 'CLEANUP FAIL: 临时目录路径未通过安全校验，未删除: %s\n' "$TMP_ROOT" >&2
    leftovers=1
  fi

  if (( leftovers )); then
    FAILS=$((FAILS + 1))
    printf 'CLEANUP FAIL: 有测试资源未清理（已计入 FAIL）\n' >&2
  fi

  print_summary
  if (( FAILS > 0 )); then
    code=1
  fi
  exit "$code"
}

# ---------------------------------------------------------------------------
# 通用断言
# ---------------------------------------------------------------------------

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$expected]，实际 [$actual]）"
  fi
}

check_csv_eq() {
  local id=$1 desc=$2 actual=$3 expected=$4 a e
  a=$(printf '%s\n' "$actual" | tr ',' '\n' | sed '/^$/d' | sort -n | paste -sd, -)
  e=$(printf '%s\n' "$expected" | tr ',' '\n' | sed '/^$/d' | sort -n | paste -sd, -)
  if [[ "$a" == "$e" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$e]，实际 [$a]）"
  fi
}

check_container_running() {
  local id=$1 desc=$2 ct=$3
  if [[ "$(docker inspect -f '{{.State.Running}}' "$ct" 2>/dev/null || true)" == "true" ]]; then
    pass "$id" "$desc"
    return 0
  fi
  fail "$id" "$desc（容器未运行: $ct）"
  return 1
}

check_file_in_container() {
  local id=$1 desc=$2 ct=$3 path=$4
  if docker exec "$ct" test -f "$path" >/dev/null 2>&1; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（容器内不存在或不是普通文件: $path）"
  fi
}

check_absent_in_image() {
  local id=$1 desc=$2 image=$3 path=$4
  if docker run --rm --network none --entrypoint /bin/sh "$image" \
    -c 'test ! -e "$1"' sh "$path" >/dev/null 2>&1; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（镜像内仍存在: $path）"
  fi
}

check_mode_in_container() {
  local id=$1 desc=$2 ct=$3 path=$4 expected=$5 mode
  mode=$(docker exec "$ct" stat -c '%a' "$path" 2>/dev/null || true)
  mode=${mode//[[:space:]]/}
  if [[ "$mode" == "$expected" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 $expected，实际 [${mode:-missing}]）"
  fi
}

check_readable_as_10001() {
  local id=$1 desc=$2 ct=$3 path=$4
  if docker exec --user 10001:10001 "$ct" test -r "$path" >/dev/null 2>&1; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（UID 10001 不可读: $path）"
  fi
}

# docker top 用 uid 列（数字），过滤 rustboard-<role> 进程。
check_rustboard_uid_10001() {
  local id=$1 ct=$2 role=$3 out uids bad count
  if ! out=$(docker top "$ct" -o uid,pid,args 2>/dev/null); then
    fail "$id" "无法读取 $ct 的进程列表"
    return
  fi
  uids=$(printf '%s\n' "$out" | awk -v pat="rustboard-$role" 'NR > 1 && index($0, pat) > 0 { print $1 }')
  if [[ -z "$uids" ]]; then
    fail "$id" "未找到 rustboard-$role 进程（无法证明主进程非 root）"
    return
  fi
  count=$(printf '%s\n' "$uids" | wc -l | tr -d '[:space:]')
  bad=$(printf '%s\n' "$uids" | grep -vx '10001' || true)
  if [[ -z "$bad" ]]; then
    pass "$id" "rustboard-$role 主进程 UID=10001（$count 个进程）"
  else
    fail "$id" "rustboard-$role 进程 UID 非 10001（UID: $(printf '%s\n' "$uids" | tr '\n' ' '))"
  fi

  if printf '%s\n' "$uids" | grep -qx '0'; then
    fail "${id}-root" "存在 UID=0 的 rustboard-$role 进程"
  else
    pass "${id}-root" "无 UID=0 的 rustboard-$role 进程"
  fi
}

check_tini_root() {
  local id=$1 ct=$2 out uids bad
  if ! out=$(docker top "$ct" -o uid,pid,args 2>/dev/null); then
    fail "$id" "无法读取 $ct 的进程列表（tini）"
    return
  fi
  uids=$(printf '%s\n' "$out" | awk 'NR > 1 && /(^|[[:space:]\/])tini([[:space:]]|$)/ { print $1 }')
  if [[ -z "$uids" ]]; then
    fail "$id" "未找到 tini（镜像 ENTRYPOINT 应经 tini 转发信号）"
    return
  fi
  bad=$(printf '%s\n' "$uids" | grep -vxE '0|root' || true)
  if [[ -z "$bad" ]]; then
    pass "$id" "tini 以 root 运行（UID: $(printf '%s\n' "$uids" | tr '\n' ' ' | sed 's/[[:space:]]*$//')）"
  else
    fail "$id" "tini UID 非 root（UID: $(printf '%s\n' "$uids" | tr '\n' ' ' | sed 's/[[:space:]]*$//')）"
  fi
}

# ---------------------------------------------------------------------------
# 前置检查
# ---------------------------------------------------------------------------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少依赖命令: $1"
}

source_fail() {
  die "来源校验失败（DOCKER_ARCH=$DOCKER_ARCH，包架构 $PKG_ARCH）: $*；请先运行 packaging/build-release.sh --arch $DOCKER_ARCH"
}

hash_file() {
  local file=$1
  sha256sum -- "$file" 2>/dev/null | awk '{ print $1 }'
}

# 递归记录目录内普通文件的 sha256（相对路径排序）；遇到符号链接直接失败。
write_tree_manifest() {
  local root=$1 out=$2
  "$PYTHON" - "$root" "$out" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
entries = []
for path in sorted(root.rglob("*")):
    if path.is_symlink():
        raise SystemExit("tree contains symlink: %s" % path)
    if not path.is_file():
        continue
    rel = path.relative_to(root).as_posix()
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    entries.append("%s  %s" % (digest.hexdigest(), rel))
if not entries:
    raise SystemExit("tree is empty: %s" % root)
out.write_text("\n".join(entries) + "\n", encoding="utf-8")
PY
}

# 构建前来源校验（全部按 DOCKER_ARCH 派生，避免拿错架构产物构建镜像）：
#   1) dist/$DOCKER_ARCH/bin 三个二进制存在、可执行，且 sha256 与包内/外层校验和一致；
#   2) dist 外层 SHA256SUMS.$PKG_ARCH 覆盖 tarball，包名与 Cargo.toml VERSION 一致；
#   3) dist/serverdashboard-v*-$PKG_ARCH.tar.gz 解包后的 VERSION/SHA256SUMS 全通过；
#   4) web/dist 文件集合的递归 sha256 与包内 share/rustboard/web 一致。
verify_sources() {
  local role pkg pkg_name pkg_root extract sums expected_hash actual_hash
  local dist_bin pkg_bin dist_hash pkg_hash pkg_version web_count
  local expected_pkg_name="serverdashboard-v${VERSION}-${PKG_ARCH}"
  local bin_dir="dist/${DOCKER_ARCH}/bin"
  local -a pkgs=()

  info "校验发布来源（DOCKER_ARCH=$DOCKER_ARCH，bin=$bin_dir，包架构=$PKG_ARCH，VERSION=$VERSION）..."

  [[ -d dist ]] || source_fail "dist 目录不存在"
  [[ -f "dist/SHA256SUMS.${PKG_ARCH}" && ! -L "dist/SHA256SUMS.${PKG_ARCH}" ]] \
    || source_fail "dist/SHA256SUMS.${PKG_ARCH} 不存在或不是普通文件"

  for role in hub panel agent; do
    dist_bin="$bin_dir/rustboard-$role"
    [[ -f "$dist_bin" && ! -L "$dist_bin" && -x "$dist_bin" ]] \
      || source_fail "$dist_bin 不存在、不是普通文件或不可执行"
  done
  [[ -d web/dist && ! -L web/dist ]] || source_fail "web/dist 不存在或不是普通目录"
  [[ -s web/dist/index.html && ! -L web/dist/index.html ]] \
    || source_fail "web/dist/index.html 不存在、为空或不是普通文件"

  mapfile -t pkgs < <(find dist -maxdepth 1 -type f -name "serverdashboard-v*-${PKG_ARCH}.tar.gz" -print 2>/dev/null | sort)
  if (( ${#pkgs[@]} == 0 )); then
    source_fail "缺少 dist/serverdashboard-v*-${PKG_ARCH}.tar.gz"
  elif (( ${#pkgs[@]} > 1 )); then
    source_fail "dist 下存在多个 ${PKG_ARCH} 离线包，无法确定来源: ${pkgs[*]}"
  fi
  pkg=${pkgs[0]}
  pkg_name=$(basename -- "$pkg")
  [[ "$pkg_name" == "$expected_pkg_name.tar.gz" ]] \
    || source_fail "包名 $pkg_name 与 Cargo.toml VERSION=$VERSION 不一致（期望 $expected_pkg_name.tar.gz）"

  sums="dist/SHA256SUMS.${PKG_ARCH}"
  expected_hash=$(awk -v f="$pkg_name" '{ name=$2; sub(/^\*/, "", name); if (name == f) { print $1; exit } }' "$sums")
  if [[ ! "$expected_hash" =~ ^[0-9a-fA-F]{64}$ ]]; then
    source_fail "$sums 未列出 $pkg_name 的 sha256"
  fi
  actual_hash=$(hash_file "$pkg")
  [[ "$actual_hash" == "$expected_hash" ]] \
    || source_fail "$pkg_name sha256 与 $sums 不一致（actual=$actual_hash expected=$expected_hash）"
  if ! ( cd dist && sha256sum -c --strict "SHA256SUMS.${PKG_ARCH}" >"$LOG_DIR/source-outer-sums.log" 2>&1 ); then
    source_fail "$sums sha256sum -c --strict 失败（详见 source-outer-sums.log）"
  fi
  pass "S.1" "$bin_dir 三二进制存在、可执行，且 tarball sha256 与 SHA256SUMS.${PKG_ARCH} 一致"

  extract="$TMP_ROOT/source-check"
  rm -rf -- "$extract"
  mkdir -p "$extract" || source_fail "无法创建解包临时目录"
  if ! tar -tzf "$pkg" >"$LOG_DIR/source-tar-list.log" 2>"$LOG_DIR/source-tar-list.err"; then
    source_fail "无法列出 $pkg 内容"
  fi
  if grep -Eq '(^/|(^|/)\.\.(/|$))' "$LOG_DIR/source-tar-list.log"; then
    source_fail "$pkg 包含绝对路径或 .. 路径"
  fi
  if ! tar -xzf "$pkg" -C "$extract" --no-same-owner >"$LOG_DIR/source-extract.log" 2>&1; then
    source_fail "解包 $pkg 失败"
  fi
  pkg_root="$extract/$expected_pkg_name"
  [[ -d "$pkg_root" && ! -L "$pkg_root" ]] \
    || source_fail "解包后缺少目录 $expected_pkg_name"

  [[ -f "$pkg_root/VERSION" && ! -L "$pkg_root/VERSION" ]] \
    || source_fail "包内缺少 VERSION"
  pkg_version=$(tr -d '\r\n' <"$pkg_root/VERSION")
  [[ "$pkg_version" == "$VERSION" ]] \
    || source_fail "包内 VERSION=[$pkg_version] 与 Cargo.toml VERSION=[$VERSION] 不一致"

  [[ -f "$pkg_root/SHA256SUMS" && ! -L "$pkg_root/SHA256SUMS" ]] \
    || source_fail "包内缺少 SHA256SUMS"
  if ! ( cd "$pkg_root" && sha256sum -c --strict SHA256SUMS >"$LOG_DIR/source-package-sums.log" 2>&1 ); then
    source_fail "包内 SHA256SUMS 校验失败（详见 source-package-sums.log）"
  fi
  pass "S.2" "包内 VERSION=$VERSION 且 SHA256SUMS 全量校验通过（$PKG_ARCH）"

  for role in hub panel agent; do
    dist_bin="$bin_dir/rustboard-$role"
    pkg_bin="$pkg_root/bin/rustboard-$role"
    [[ -f "$pkg_bin" && ! -L "$pkg_bin" && -x "$pkg_bin" ]] \
      || source_fail "包内 $pkg_bin 不存在、不是普通文件或不可执行"
    dist_hash=$(hash_file "$dist_bin")
    pkg_hash=$(hash_file "$pkg_bin")
    if [[ ! "$dist_hash" =~ ^[0-9a-f]{64}$ || ! "$pkg_hash" =~ ^[0-9a-f]{64}$ ]]; then
      source_fail "无法计算 $role 二进制 sha256"
    fi
    [[ "$dist_hash" == "$pkg_hash" ]] \
      || source_fail "$dist_bin 与包内同名二进制 sha256 不一致"
    if ! grep -qE "^${pkg_hash}[[:space:]]+bin/rustboard-${role}$" "$pkg_root/SHA256SUMS"; then
      source_fail "包内 SHA256SUMS 未列出 bin/rustboard-$role 的当前 hash"
    fi
  done
  pass "S.3" "$bin_dir 三二进制 sha256 与包内同名二进制及包内 SHA256SUMS 一致"

  [[ -d "$pkg_root/share/rustboard/web" && ! -L "$pkg_root/share/rustboard/web" ]] \
    || source_fail "包内 share/rustboard/web 不存在或不是普通目录"
  [[ -s "$pkg_root/share/rustboard/web/index.html" && ! -L "$pkg_root/share/rustboard/web/index.html" ]] \
    || source_fail "包内 share/rustboard/web/index.html 不存在、为空或不是普通文件"
  if ! write_tree_manifest "web/dist" "$LOG_DIR/source-web.sha256" >"$LOG_DIR/source-web.err" 2>&1; then
    source_fail "无法递归记录 web/dist 的 sha256（详见 source-web.err）"
  fi
  if ! write_tree_manifest "$pkg_root/share/rustboard/web" "$TMP_ROOT/source-web-package.sha256" >"$LOG_DIR/source-web-package.err" 2>&1; then
    source_fail "无法递归记录包内 web 的 sha256（详见 source-web-package.err）"
  fi
  if ! diff -u "$TMP_ROOT/source-web-package.sha256" "$LOG_DIR/source-web.sha256" >"$LOG_DIR/source-web.diff" 2>&1; then
    source_fail "web/dist 与包内 share/rustboard/web 的文件集合或 sha256 不一致（详见 source-web.diff）"
  fi
  web_count=$(wc -l <"$LOG_DIR/source-web.sha256" | tr -d '[:space:]')
  pass "S.4" "web/dist 递归 sha256 与包内 web 一致（$web_count 个文件）"
  rm -rf -- "$extract"
}

preflight() {
  local version_line driver tmp_base

  need_cmd docker
  need_cmd curl
  need_cmd "$PYTHON"
  need_cmd git
  need_cmd timeout
  need_cmd sha256sum
  need_cmd tar

  docker info >/dev/null 2>&1 || die "docker daemon 不可用（root 可选，但当前用户需能访问 Docker）"
  docker buildx version >/dev/null 2>&1 || die "缺少 docker buildx 插件"
  docker buildx inspect >/dev/null 2>&1 || die "docker buildx 没有可用 builder"
  driver=$(docker buildx inspect 2>/dev/null | awk -F': *' '/^Driver:/ { print $2; exit }' || true)
  info "buildx driver=${driver:-unknown}；当前 UID=$(id -u)（root 可选）"
  info "DOCKER_ARCH=$DOCKER_ARCH platform=$ARCH_PLATFORM pkgarch=$PKG_ARCH image_tag=$IMAGE_TAG SKIP_ARM64=$SKIP_ARM64"

  [[ -f docker/Dockerfile ]] || die "缺少 docker/Dockerfile（Docker 交付接口未就绪）"
  [[ -f docker/compose.example.yml ]] || die "缺少 docker/compose.example.yml（Compose 交付接口未就绪）"

  version_line=$(grep -m1 -E '^version[[:space:]]*=' Cargo.toml 2>/dev/null || true)
  VERSION=$(printf '%s\n' "$version_line" | sed -E 's/^[^=]*=[[:space:]]*"([^"]+)".*/\1/')
  if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
    die "无法从 Cargo.toml 解析 workspace version（得到 [${VERSION:-empty}]）"
  fi
  REVISION=$(git rev-parse HEAD 2>/dev/null || true)
  if [[ ! "$REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    die "无法解析 git HEAD revision（得到 [${REVISION:-empty}]）"
  fi
  info "VERSION=$VERSION REVISION=$REVISION"

  tmp_base=${TMPDIR:-/tmp}
  tmp_base=${tmp_base%/}
  TMP_ROOT=$(mktemp -d "$tmp_base/rustboard-v100-docker.XXXXXX") \
    || die "无法创建临时目录"
  LOG_DIR="$TMP_ROOT/logs"
  mkdir -p "$LOG_DIR" || die "无法创建日志目录"

  verify_sources

  if docker compose version >/dev/null 2>&1; then
    HAVE_COMPOSE=1
    info "docker compose 插件可用"
  else
    HAVE_COMPOSE=0
    if ! "$PYTHON" -c 'import yaml' >/dev/null 2>&1; then
      die "docker compose 插件不可用，且 python3 缺少 PyYAML，无法解析 compose 文件"
    fi
    info "docker compose 插件不可用，compose 用例回退为 python3 + PyYAML 结构解析"
  fi

  if [[ "$DOCKER_ARCH" == "arm64" ]]; then
    HAVE_QEMU_AARCH64=0
    info "DOCKER_ARCH=arm64：主用例按 linux/arm64 构建/运行（arm64 主机上为原生），跳过可选 arm64/QEMU 附加检查"
  elif [[ "$SKIP_ARM64" == "1" ]]; then
    HAVE_QEMU_AARCH64=0
    info "SKIP_ARM64=1：跳过可选 arm64/QEMU 附加检查（arm64 原生门禁由 delivery-arm64 覆盖）"
  elif [[ -f /proc/sys/fs/binfmt_misc/qemu-aarch64 ]] \
    && grep -q '^enabled' /proc/sys/fs/binfmt_misc/qemu-aarch64 2>/dev/null; then
    HAVE_QEMU_AARCH64=1
    info "检测到 qemu-aarch64 binfmt（dist/arm64 产物存在时执行 arm64 镜像附加用例）"
  else
    HAVE_QEMU_AARCH64=0
    info "未检测到 qemu-aarch64 binfmt（可选 arm64 镜像附加用例将 SKIP）"
  fi

  HUB_DATA="$TMP_ROOT/hub-data"
  PANEL_DATA="$TMP_ROOT/panel-data"
  AGENT_DATA="$TMP_ROOT/agent-data"
  AGENT_EMPTY_DATA="$TMP_ROOT/agent-empty"
  AGENT_TOKEN_FILE="$TMP_ROOT/agent-enroll.token"
  mkdir -p "$HUB_DATA" "$PANEL_DATA" "$AGENT_DATA" "$AGENT_EMPTY_DATA" \
    || die "无法创建临时数据目录"
  chmod 0777 "$AGENT_EMPTY_DATA"

  read -r HOST_8443 HOST_8080 < <(
    "$PYTHON" - <<'PY'
import socket

socks = []
try:
    for _ in range(2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        socks.append(s)
    print(socks[0].getsockname()[1], socks[1].getsockname()[1])
finally:
    for s in socks:
        s.close()
PY
  ) || die "无法分配宿主测试端口"
  if [[ ! "$HOST_8443" =~ ^[0-9]+$ || ! "$HOST_8080" =~ ^[0-9]+$ ]]; then
    die "宿主测试端口分配失败（8443=[${HOST_8443:-}]，8080=[${HOST_8080:-}]）"
  fi
  info "宿主测试端口: 8443->$HOST_8443，8080->$HOST_8080"

  if (( HAVE_COMPOSE == 0 )) && ! "$PYTHON" -c 'import yaml' >/dev/null 2>&1; then
    die "compose 回退解析需要 PyYAML"
  fi
}

setup_resources() {
  NETWORKS+=("$NET_NAME")
  if ! docker network create --label "rustboard.e2e=1" "$NET_NAME" \
    >"$LOG_DIR/network-create.log" 2>&1; then
    dump_file "$LOG_DIR/network-create.log" 30
    die "创建测试网络失败: $NET_NAME"
  fi

  VOLUMES+=("$HUB_RUN_VOLUME")
  if ! docker volume create --label "rustboard.e2e=1" "$HUB_RUN_VOLUME" \
    >"$LOG_DIR/volume-create.log" 2>&1; then
    dump_file "$LOG_DIR/volume-create.log" 30
    die "创建 hub_run 测试 volume 失败: $HUB_RUN_VOLUME"
  fi
}

# ---------------------------------------------------------------------------
# Compose 结构检查
# ---------------------------------------------------------------------------

write_compose_facts_py() {
  cat >"$TMP_ROOT/compose_facts.py" <<'PY'
import ipaddress
import json
import sys


def as_int(value):
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    return int(text) if text.isdigit() else None


LOOPBACK_V4 = ipaddress.IPv4Address("127.0.0.1")
LOOPBACK_V6 = ipaddress.IPv6Address("::1")


def normalize_host_ip(host_ip):
    text = "" if host_ip is None else str(host_ip).strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1].strip()
    if not text:
        return ""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text.lower()
    if addr == LOOPBACK_V4 or addr == LOOPBACK_V6:
        return "loopback"
    return str(addr)


def parse_short(value):
    text = str(value).strip()
    if not text:
        return None, None, ""
    if "/" in text:
        text = text.split("/", 1)[0]
    host_ip = ""
    published = None
    target = None
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None, None, ""
        host_ip = text[1:end]
        rest = text[end + 1:]
        if rest.startswith(":"):
            rest = rest[1:]
        parts = rest.split(":") if rest else []
        if len(parts) >= 2:
            published = parts[-2]
            target = parts[-1]
        elif len(parts) == 1:
            target = parts[0]
    else:
        parts = text.split(":")
        if len(parts) >= 3:
            host_ip = parts[0]
            published = parts[-2]
            target = parts[-1]
        elif len(parts) == 2:
            published = parts[0]
            target = parts[1]
        elif len(parts) == 1:
            target = parts[0]
    if published in ("", None):
        published = None
    else:
        published = str(published)
    return as_int(target), published, normalize_host_ip(host_ip)


def normalize_port(port):
    if isinstance(port, dict):
        return (
            as_int(port.get("target")),
            port.get("published"),
            normalize_host_ip(port.get("host_ip")),
        )
    if isinstance(port, int):
        return port, None, ""
    return parse_short(port)


def port_values(services, name):
    targets = set()
    published = set()
    for port in (services.get(name) or {}).get("ports") or []:
        target, pub, _host_ip = normalize_port(port)
        if target is not None:
            targets.add(target)
        if pub is not None:
            published.add(str(pub))
    return targets, published


def pub_contains(published, port):
    expected = str(port)
    for value in published:
        if value == expected:
            return True
        if "-" in value:
            start, end = value.split("-", 1)
            if start.isdigit() and end.isdigit() and int(start) <= port <= int(end):
                return True
    return False


def collect_8080(services):
    entries = 0
    nonloopback = 0
    for service in (services or {}).values():
        for port in (service or {}).get("ports") or []:
            _target, pub, host_ip = normalize_port(port)
            if pub is not None and pub_contains({pub}, 8080):
                entries += 1
                if host_ip != "loopback":
                    nonloopback += 1
    return entries, nonloopback


def socket_mount(service):
    for volume in (service or {}).get("volumes") or []:
        if isinstance(volume, dict):
            text = " ".join(str(volume.get(k) or "") for k in ("type", "source", "target"))
        else:
            text = str(volume)
        if "/var/run/docker.sock" in text or "/run/docker.sock" in text:
            return 1
    return 0


def main():
    path, mode = sys.argv[1], sys.argv[2]
    if mode == "raw":
        import yaml
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    else:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle) or {}

    services = data.get("services") or {}
    if len(sys.argv) > 3 and sys.argv[3] == "default":
        print("agent_present=%d" % (1 if "agent" in services else 0))
        print("services=" + ",".join(sorted(services)))
        return

    hub = services.get("hub") or {}
    panel = services.get("panel") or {}
    agent = services.get("agent") or {}
    hub_targets, hub_published = port_values(services, "hub")
    panel_targets, panel_published = port_values(services, "panel")
    agent_targets, agent_published = port_values(services, "agent")

    all_8444 = 1 if (
        pub_contains(hub_published, 8444)
        or pub_contains(panel_published, 8444)
        or pub_contains(agent_published, 8444)
        or 8444 in hub_targets
        or 8444 in panel_targets
        or 8444 in agent_targets
    ) else 0

    count_8080, nonloopback_8080 = collect_8080(services)
    loopback_8080_ok = 1 if count_8080 > 0 and nonloopback_8080 == 0 else 0

    profiles = agent.get("profiles") or []
    if not isinstance(profiles, list):
        profiles = [str(profiles)]

    print("services=" + ",".join(sorted(services)))
    print("hub_present=%d" % (1 if "hub" in services else 0))
    print("panel_present=%d" % (1 if "panel" in services else 0))
    print("agent_present=%d" % (1 if "agent" in services else 0))
    print("hub_targets=" + ",".join(str(x) for x in sorted(hub_targets)))
    print("hub_published=" + ",".join(sorted(hub_published)))
    print("panel_targets=" + ",".join(str(x) for x in sorted(panel_targets)))
    print("panel_published=" + ",".join(sorted(panel_published)))
    print("agent_targets=" + ",".join(str(x) for x in sorted(agent_targets)))
    print("agent_published=" + ",".join(sorted(agent_published)))
    print("panel_network_mode=" + str(panel.get("network_mode") or ""))
    print("agent_profiles=" + ",".join(str(x) for x in profiles))
    print("agent_privileged=" + ("true" if agent.get("privileged") else "false"))
    print("agent_socket=" + str(socket_mount(agent)))
    print("all_8444=" + str(all_8444))
    print("published_8080_entries=%d" % count_8080)
    print("published_8080_nonloopback=%d" % nonloopback_8080)
    print("published_8080_loopback=%d" % loopback_8080_ok)


if __name__ == "__main__":
    main()
PY
}

compose_fact() {
  local key=$1
  printf '%s\n' "$COMPOSE_FACTS" | sed -n "s/^${key}=//p" | head -n 1
}

compose_checks() {
  local compose_file="docker/compose.example.yml"
  local default_json="$LOG_DIR/compose-default.json"
  local all_json="$LOG_DIR/compose-all.json"
  local facts_source="" facts_mode="json" agent_default=""

  write_compose_facts_py

  if (( HAVE_COMPOSE )); then
    if ! docker compose -f "$compose_file" config --format json \
      >"$default_json" 2>"$LOG_DIR/compose-default.err"; then
      fail "C.1" "docker compose config 语法检查失败"
      dump_file "$LOG_DIR/compose-default.err" 60
      return
    fi
    if ! docker compose --profile '*' -f "$compose_file" config --format json \
      >"$all_json" 2>"$LOG_DIR/compose-all.err"; then
      fail "C.1" "docker compose --profile '*' config 语法检查失败"
      dump_file "$LOG_DIR/compose-all.err" 60
      return
    fi
    pass "C.1" "docker compose config 语法通过（默认 profile 与 --profile '*'）"
    facts_source="$all_json"
  else
    if ! "$PYTHON" -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1], encoding="utf-8"))' \
      "$compose_file" >"$LOG_DIR/compose-fallback.log" 2>"$LOG_DIR/compose-fallback.err"; then
      fail "C.1" "python3 + PyYAML 解析 compose 文件失败"
      dump_file "$LOG_DIR/compose-fallback.err" 60
      return
    fi
    pass "C.1" "python3 + PyYAML compose 语法解析通过（compose 插件不可用的回退）"
    facts_source="$compose_file"
    facts_mode="raw"
  fi

  if ! COMPOSE_FACTS=$("$PYTHON" "$TMP_ROOT/compose_facts.py" "$facts_source" "$facts_mode" 2>"$LOG_DIR/compose-facts.err"); then
    fail "C.1" "compose 结构提取失败"
    dump_file "$LOG_DIR/compose-facts.err" 60
    return
  fi

  check_eq "C.2" "compose 包含 hub/panel/agent 三个 service" "1/1/1" \
    "$(compose_fact hub_present)/$(compose_fact panel_present)/$(compose_fact agent_present)"
  check_csv_eq "C.3a" "hub ports target 仅 8443 与 8080" \
    "$(compose_fact hub_targets)" "8080,8443"
  check_csv_eq "C.3b" "hub ports published 仅 8443 与 8080" \
    "$(compose_fact hub_published)" "8080,8443"
  check_eq "C.3c" "8080 发布项均显式回环 127.0.0.1/::1" "0/1" \
    "$(compose_fact published_8080_nonloopback)/$(compose_fact published_8080_loopback)"
  check_eq "C.4" "8444 不出现在任何 service 的 ports（target/published）" "0" \
    "$(compose_fact all_8444)"
  check_eq "C.5" "panel 使用 network_mode: service:hub" "service:hub" \
    "$(compose_fact panel_network_mode)"
  check_csv_eq "C.6" "panel 没有自己的 ports（targets/published 均为空）" \
    "$(compose_fact panel_targets),$(compose_fact panel_published)" ""

  if [[ -n "$(compose_fact agent_profiles)" && "$(compose_fact agent_profiles)" != *"default"* ]]; then
    pass "C.7" "agent 有 profile [$(compose_fact agent_profiles)]，不属于默认 profile"
  else
    fail "C.7" "agent 必须配置非 default 的 profiles（实际 [$(compose_fact agent_profiles)]）"
  fi

  if (( HAVE_COMPOSE )); then
    agent_default=$("$PYTHON" "$TMP_ROOT/compose_facts.py" "$default_json" json default 2>/dev/null \
      | sed -n 's/^agent_present=//p' | head -n 1)
    check_eq "C.8" "默认 docker compose config 不包含 agent service" "0" "$agent_default"
  else
    info "compose 插件不可用：agent 默认不启动由 profiles 语义断言（C.7）覆盖，未单独渲染默认 profile"
  fi

  check_eq "C.9" "agent 非 privileged 且未挂载 docker socket" "false/0" \
    "$(compose_fact agent_privileged)/$(compose_fact agent_socket)"
}

# ---------------------------------------------------------------------------
# 镜像构建
# ---------------------------------------------------------------------------

build_image() {
  local role=$1 log="$LOG_DIR/build-$1.log" image
  image=$(image_for_role "$role") || {
    fail "B.$2" "未知角色: $role"
    return 1
  }
  if docker buildx build --load --platform "$ARCH_PLATFORM" --progress=plain \
    -f docker/Dockerfile --target "$role" \
    --build-arg "VERSION=$VERSION" \
    --build-arg "REVISION=$REVISION" \
    -t "$image" . >"$log" 2>&1; then
    pass "B.$2" "构建 $image（$ARCH_PLATFORM，VERSION=$VERSION）"
    return 0
  fi
  fail "B.$2" "构建 $image 失败（$ARCH_PLATFORM，日志尾部见下）"
  dump_file "$log" 100
  return 1
}

build_images() {
  local role idx=0 failed=0 platform image
  for role in hub panel agent; do
    idx=$((idx + 1))
    if ! build_image "$role" "$idx"; then
      failed=1
    fi
  done

  for role in hub panel agent; do
    image=$(image_for_role "$role") || continue
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      continue
    fi
    platform=$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$image" 2>/dev/null || true)
    check_eq "B.4-$role" "镜像 $role 架构为 $ARCH_PLATFORM" "$ARCH_PLATFORM" "$platform"
  done

  if (( failed )); then
    return 1
  fi
  return 0
}

# ---------------------------------------------------------------------------
# 镜像 labels（B-G8 可追溯性）
# ---------------------------------------------------------------------------

image_label() {
  local image=$1 key=$2
  docker image inspect -f "{{index .Config.Labels \"$key\"}}" "$image" 2>/dev/null || true
}

label_checks() {
  local role image
  for role in hub panel agent; do
    image=$(image_for_role "$role") || continue
    check_eq "L.$role.source" "镜像 $role label org.opencontainers.image.source" \
      "https://github.com/pazzifirst/rustboard" \
      "$(image_label "$image" org.opencontainers.image.source)"
    check_eq "L.$role.revision" "镜像 $role label org.opencontainers.image.revision" \
      "$REVISION" "$(image_label "$image" org.opencontainers.image.revision)"
    check_eq "L.$role.version" "镜像 $role label org.opencontainers.image.version" \
      "$VERSION" "$(image_label "$image" org.opencontainers.image.version)"
  done
}

# ---------------------------------------------------------------------------
# 镜像内 web 与当前 web/dist 的来源一致性
# ---------------------------------------------------------------------------

image_web_manifest() {
  local image=$1 out=$2 err=$3
  docker run --rm --network none --entrypoint /bin/sh "$image" -c '
    set -e
    cd /usr/share/rustboard/web
    if find . -type l -print -quit | grep -q .; then
      echo "image web contains symlink" >&2
      exit 2
    fi
    find . -type f -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum \
      | sed "s#  \\./#  #"
  ' >"$out" 2>"$err"
}

check_image_web_source() {
  local id=$1 role=$2 image=$3
  local manifest="$LOG_DIR/image-web-$role.sha256"
  local err="$LOG_DIR/image-web-$role.err"
  local source_manifest="$LOG_DIR/source-web.sha256"

  if [[ ! -s "$source_manifest" ]]; then
    fail "$id" "缺少 source-web.sha256，无法比对镜像内 web 与当前 web/dist"
    return
  fi
  if ! image_web_manifest "$image" "$manifest" "$err"; then
    fail "$id" "无法读取镜像 $role 的 /usr/share/rustboard/web（缺目录/符号链接/命令失败）"
    dump_file "$err" 30
    return
  fi
  if diff -u "$source_manifest" "$manifest" >"$LOG_DIR/image-web-$role.diff" 2>&1; then
    pass "$id" "镜像 $role 的 web 路径+sha256 与当前 web/dist 一致"
  else
    fail "$id" "镜像 $role 的 web 与当前 web/dist 文件集合或 sha256 不一致"
    dump_file "$LOG_DIR/image-web-$role.diff" 40
  fi
}

source_image_checks() {
  check_image_web_source "S.5" hub "$HUB_IMAGE"
  check_image_web_source "S.6" panel "$PANEL_IMAGE"
}

# ---------------------------------------------------------------------------
# healthcheck / HTTP 工具
# ---------------------------------------------------------------------------

wait_healthy() {
  local ct=$1 timeout=${2:-$HEALTH_TIMEOUT}
  local deadline status health
  deadline=$((SECONDS + timeout))
  LAST_STATE="unknown"
  while (( SECONDS < deadline )); do
    if ! status=$(docker inspect -f '{{.State.Status}}' "$ct" 2>/dev/null); then
      LAST_STATE="missing"
      return 1
    fi
    health=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$ct" 2>/dev/null || true)
    case "$status" in
      running)
        case "$health" in
          healthy)
            LAST_STATE="healthy"
            return 0
            ;;
          none)
            LAST_STATE="no-healthcheck"
            return 2
            ;;
          unhealthy)
            LAST_STATE="unhealthy"
            return 1
            ;;
          *)
            LAST_STATE="health=$health"
            ;;
        esac
        ;;
      exited|dead)
        LAST_STATE="container-$status"
        return 1
        ;;
      *)
        LAST_STATE="status=$status"
        ;;
    esac
    sleep 1
  done
  LAST_STATE="timeout(${timeout}s)"
  return 1
}

check_health() {
  local id=$1 desc=$2 ct=$3
  if wait_healthy "$ct"; then
    pass "$id" "$desc"
    return 0
  fi
  if [[ "$LAST_STATE" == "no-healthcheck" ]]; then
    fail "$id" "$desc（镜像缺少 HEALTHCHECK）"
  else
    fail "$id" "$desc（状态: $LAST_STATE）"
  fi
  dump_container_logs "$ct" 80
  return 1
}

exec_http_code() {
  local ct=$1 url=$2 code
  code=$(docker exec "$ct" curl -sS --max-time 5 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null) || code="000"
  printf '%s' "${code:-000}"
}

check_exec_http_200() {
  local id=$1 desc=$2 ct=$3 url=$4 code
  code=$(exec_http_code "$ct" "$url")
  if [[ "$code" == "200" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（HTTP $code）"
  fi
}

wait_exec_http_200() {
  local ct=$1 url=$2 timeout=${3:-60} deadline code
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    code=$(exec_http_code "$ct" "$url")
    LAST_CODE=$code
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

host_http_code() {
  local url=$1 code
  code=$(curl -sS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null) || code="000"
  printf '%s' "${code:-000}"
}

wait_host_http_200() {
  local url=$1 timeout=${2:-20} deadline code
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    code=$(host_http_code "$url")
    LAST_CODE=$code
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

# ---------------------------------------------------------------------------
# 镜像隔离与默认端口
# ---------------------------------------------------------------------------

image_clean_checks() {
  local role=$1 image=$2 out user
  check_absent_in_image "I.$role.config" "镜像内无 /etc/rustboard/$role.toml" \
    "$image" "/etc/rustboard/$role.toml"
  check_absent_in_image "I.$role.data" "镜像内无 /var/lib/rustboard" \
    "$image" "/var/lib/rustboard"
  check_absent_in_image "I.$role.token" "镜像内无运行期 admin_token 文件" \
    "$image" "/run/rustboard/admin_token"

  # 只扫描存在的路径；/etc/rustboard 按设计不存在，GNU find 对缺失路径会退出 1。
  if out=$(docker run --rm --network none --entrypoint /bin/sh "$image" -c \
    'for d in /data /etc/rustboard /usr/local/bin; do [ -e "$d" ] || continue; find "$d" \( -name "*.key" -o -name "*.pem" \) -print -quit 2>/dev/null; done' \
    2>/dev/null); then
    if [[ -z "$out" ]]; then
      pass "I.$role.keys" "镜像 /data /etc/rustboard /usr/local/bin 内无 *.key/*.pem"
    else
      fail "I.$role.keys" "镜像内发现密钥/证书文件: $out"
    fi
  else
    fail "I.$role.keys" "镜像内密钥扫描命令失败"
  fi

  user=$(docker image inspect -f '{{.Config.User}}' "$image" 2>/dev/null || true)
  info "镜像 $role Config.User=[${user:-<empty/root>}]（允许 root 用于首启；运行中主进程必须 UID 10001）"
}

start_port_probe() {
  local role=$1 image=$2 ct
  ct="${PORT_PROBE_PREFIX}-${role}"
  if docker run -d --name "$ct" --label "rustboard.e2e=1" --network "$NET_NAME" \
    -P --entrypoint /bin/sh "$image" -c 'sleep 120' >/dev/null 2>"$LOG_DIR/port-$role.err"; then
    CONTAINERS+=("$ct")
    sleep 1
    if [[ "$(docker inspect -f '{{.State.Running}}' "$ct" 2>/dev/null || true)" == "true" ]]; then
      return 0
    fi
  fi
  dump_file "$LOG_DIR/port-$role.err" 30
  return 1
}

probe_ports() {
  local ct=$1
  docker port "$ct" 2>/dev/null || true
}

port_targets_csv() {
  local mappings=$1
  printf '%s\n' "$mappings" | awk -F/ 'NF > 1 { print $1 }' | sed '/^$/d' | sort -n -u | paste -sd, -
}

port_checks() {
  local role image mappings targets union=""
  for role in hub panel agent; do
    image=$(image_for_role "$role") || continue
    if ! start_port_probe "$role" "$image"; then
      fail "O.$role" "无法启动 $role 端口探测容器"
      continue
    fi
    mappings=$(probe_ports "${PORT_PROBE_PREFIX}-${role}")
    targets=$(port_targets_csv "$mappings")
    case "$role" in
      hub) check_csv_eq "O.$role" "hub 默认 EXPOSE 端口为 8443/80/443（80/443 仅 ACME）" "$targets" "80,443,8443" ;;
      panel) check_csv_eq "O.$role" "panel 默认 EXPOSE/发布端口仅 8080" "$targets" "8080" ;;
      agent) check_csv_eq "O.$role" "agent 默认不 EXPOSE 端口" "$targets" "" ;;
    esac
    union="${union:+$union,}$targets"
    docker rm -f "${PORT_PROBE_PREFIX}-${role}" >/dev/null 2>&1 || true
  done

  check_csv_eq "O.union" "三镜像默认端口并集为 80/443/8080/8443（80/443 仅 ACME）" "$union" "80,443,8080,8443"
  if printf '%s\n' "$union" | tr ',' '\n' | grep -qx '8444'; then
    fail "O.8444" "8444 出现在镜像默认端口（不得发布管理口）"
  else
    pass "O.8444" "8444 未出现在任何镜像默认端口"
  fi
}

# ---------------------------------------------------------------------------
# hub
# ---------------------------------------------------------------------------

start_hub_basic() {
  if docker run -d --name "$HUB_CT" --label "rustboard.e2e=1" \
    --network "$NET_NAME" \
    -p "127.0.0.1:${HOST_8443}:8443" \
    -v "$HUB_DATA:/data" \
    "$HUB_IMAGE" >/dev/null 2>"$LOG_DIR/hub-run.err"; then
    CONTAINERS+=("$HUB_CT")
    return 0
  fi
  dump_file "$LOG_DIR/hub-run.err" 50
  return 1
}

hub_checks() {
  local sha_before="" sha_after="" mappings="" out units="" units_any=""

  if ! start_hub_basic; then
    fail "H.1" "hub 容器启动失败"
    return
  fi
  pass "H.1" "hub 容器启动（host 127.0.0.1:$HOST_8443 -> 8443）"

  if ! check_health "H.2" "hub healthcheck 变为 healthy（admin 8444 /healthz）" "$HUB_CT"; then
    return
  fi

  if ! check_container_running "H.3" "hub 容器仍在运行" "$HUB_CT"; then
    return
  fi
  check_exec_http_200 "H.4" "hub 管理口 127.0.0.1:8444/healthz 返回 200" \
    "$HUB_CT" "http://127.0.0.1:8444/healthz"

  if ! docker exec "$HUB_CT" test -f /data/etc/rustboard/hub.toml >/dev/null 2>&1; then
    fail "H.5" "hub 配置 /data/etc/rustboard/hub.toml 不存在"
  else
    pass "H.5" "hub 配置位于 /data/etc/rustboard/hub.toml"
    check_mode_in_container "H.6" "hub 配置权限为 0600" "$HUB_CT" \
      "/data/etc/rustboard/hub.toml" "600"
    check_readable_as_10001 "H.7" "hub 配置对 UID 10001 可读" "$HUB_CT" \
      "/data/etc/rustboard/hub.toml"
  fi

  units=$(docker exec "$HUB_CT" sh -c \
    'find /data/usr/share -name "*.service" -print 2>/dev/null | head -n 5' 2>/dev/null || true)
  if [[ -z "$units" ]]; then
    pass "H.8" "/data/usr/share 下无 systemd unit（--no-systemd）"
  else
    fail "H.8" "/data/usr/share 下发现 unit: $units"
  fi
  units_any=$(docker exec "$HUB_CT" sh -c \
    'find /data -name "rustboard-*.service" -print 2>/dev/null | head -n 5' 2>/dev/null || true)
  if [[ -z "$units_any" ]]; then
    pass "H.9" "/data 下无 rustboard-*.service（未写 unit）"
  else
    fail "H.9" "/data 下发现 rustboard unit: $units_any"
  fi

  check_file_in_container "H.10" "web 静态资源位于 /usr/share/rustboard/web/index.html" \
    "$HUB_CT" "/usr/share/rustboard/web/index.html"
  check_rustboard_uid_10001 "H.11" "$HUB_CT" "hub"
  check_tini_root "H.12" "$HUB_CT"

  if [[ "$(docker inspect -f '{{.State.Running}}' "$HUB_CT" 2>/dev/null || true)" == "true" ]]; then
    mappings=$(docker port "$HUB_CT" 2>/dev/null || true)
    if printf '%s\n' "$mappings" | grep -q "^8443/tcp -> 127\.0\.0\.1:${HOST_8443}$"; then
      pass "H.13" "hub 8443 仅发布到宿主 127.0.0.1:$HOST_8443"
    else
      fail "H.13" "hub 8443 未按 127.0.0.1 发布（docker port: $(printf '%s' "$mappings" | tr '\n' ';')）"
    fi
    if printf '%s\n' "$mappings" | grep -q '^8444/'; then
      fail "H.14" "hub 8444 被发布到宿主（管理口不得发布）"
    else
      pass "H.14" "hub 8444 未发布到宿主"
    fi
  else
    fail "H.13" "hub 未运行，无法检查宿主端口映射"
    fail "H.14" "hub 未运行，无法确认 8444 未发布"
  fi

  sha_before=$(docker exec "$HUB_CT" sha256sum /data/etc/rustboard/hub.toml 2>/dev/null | awk '{ print $1 }' || true)
  if [[ ! "$sha_before" =~ ^[0-9a-f]{64}$ ]]; then
    fail "R.1" "重启前无法读取 hub 配置 sha256"
    return
  fi
  pass "R.1" "重启前已记录 hub 配置 sha256（不打印内容）"

  if ! docker restart "$HUB_CT" >/dev/null 2>"$LOG_DIR/hub-restart.err"; then
    fail "R.1" "docker restart hub 失败"
    dump_file "$LOG_DIR/hub-restart.err" 30
    return
  fi
  if ! check_health "R.2" "hub 重启后 healthcheck 恢复 healthy" "$HUB_CT"; then
    return
  fi
  if ! wait_exec_http_200 "$HUB_CT" "http://127.0.0.1:8444/healthz" 60; then
    fail "R.3" "hub 重启后管理口未恢复 200（最后 HTTP $LAST_CODE）"
  else
    pass "R.3" "hub 重启后管理口 /healthz 恢复 200"
  fi

  sha_after=$(docker exec "$HUB_CT" sha256sum /data/etc/rustboard/hub.toml 2>/dev/null | awk '{ print $1 }' || true)
  check_eq "R.4" "docker restart 不重新生成 hub 配置/admin_token（sha256 不变）" \
    "$sha_before" "$sha_after"
}

# ---------------------------------------------------------------------------
# 已初始化 volume 的 --user 10001 与空 volume 失败
# ---------------------------------------------------------------------------

stop_remove() {
  local ct=$1
  docker stop -t 10 "$ct" >/dev/null 2>&1 || true
  docker rm -f "$ct" >/dev/null 2>&1 || true
}

user_checks() {
  local config="$HUB_DATA/etc/rustboard/hub.toml"

  # 先从容器的 /data 视图确认初始化完成；某些 CI Docker 环境下宿主
  # bind-mount 源路径不保证立即可见，直接查宿主路径会产生假阴性。
  if ! docker exec "$HUB_CT" test -f /data/etc/rustboard/hub.toml; then
    fail "U.1" "已初始化 volume 缺少 /data/etc/rustboard/hub.toml，无法验证 --user 10001:10001"
    stop_remove "$HUB_CT"
    return
  fi
  stop_remove "$HUB_CT"
  if [[ ! -f "$config" ]]; then
    # 容器视图已确认，宿主视图缺失只作为诊断信息；真正启动 --user 用例仍会验证。
    info "U.1 宿主路径 $config 不可见（容器 /data 已确认初始化，继续）"
  fi

  if ! docker run -d --name "$USER_CT" --label "rustboard.e2e=1" \
    --network "$NET_NAME" --user 10001:10001 \
    -v "$HUB_DATA:/data" "$HUB_IMAGE" >/dev/null 2>"$LOG_DIR/hub-user.err"; then
    fail "U.1" "已初始化 volume 以 --user 10001:10001 启动失败"
    dump_file "$LOG_DIR/hub-user.err" 50
    return
  fi
  CONTAINERS+=("$USER_CT")
  pass "U.1" "已初始化 volume 以 --user 10001:10001 启动"

  if ! check_health "U.2" "--user 10001:10001 下 hub healthcheck healthy" "$USER_CT"; then
    stop_remove "$USER_CT"
    return
  fi
  if ! wait_exec_http_200 "$USER_CT" "http://127.0.0.1:8444/healthz" 60; then
    fail "U.3" "--user 10001:10001 下管理口未返回 200（最后 HTTP $LAST_CODE）"
  else
    pass "U.3" "--user 10001:10001 下管理口 /healthz 200"
  fi
  check_readable_as_10001 "U.4" "已初始化 volume 的配置对 10001 可读" "$USER_CT" \
    "/data/etc/rustboard/hub.toml"
  check_rustboard_uid_10001 "U.5" "$USER_CT" "hub"
  stop_remove "$USER_CT"
}

empty_volume_checks() {
  local exit_code="" rc=0 config_count=0
  EMPTY_DATA=$(mktemp -d "$TMP_ROOT/empty-hub.XXXXXX") || {
    fail "V.1" "无法创建空 volume 临时目录"
    return
  }
  chmod 0777 "$EMPTY_DATA"

  if ! docker run -d --name "$EMPTY_CT" --label "rustboard.e2e=1" \
    --network "$NET_NAME" --user 10001:10001 \
    -v "$EMPTY_DATA:/data" "$HUB_IMAGE" >/dev/null 2>"$LOG_DIR/empty-run.err"; then
    fail "V.1" "空 volume 容器启动命令失败（应能启动并快速失败）"
    dump_file "$LOG_DIR/empty-run.err" 50
    return
  fi
  CONTAINERS+=("$EMPTY_CT")

  if timeout "$EMPTY_TIMEOUT" docker wait "$EMPTY_CT" >"$LOG_DIR/empty.exit" 2>"$LOG_DIR/empty.wait.err"; then
    exit_code=$(tr -d '[:space:]' <"$LOG_DIR/empty.exit")
  else
    rc=$?
    if (( rc == 124 || rc == 137 )); then
      fail "V.1" "空 volume + --user 10001 未在 ${EMPTY_TIMEOUT}s 内失败退出（疑似挂起）"
    else
      fail "V.1" "docker wait 空 volume 容器失败（rc=$rc）"
    fi
    docker rm -f "$EMPTY_CT" >/dev/null 2>&1 || true
    return
  fi

  docker logs "$EMPTY_CT" >"$LOG_DIR/empty-hub.log" 2>&1 || true
  if [[ "$exit_code" =~ ^[0-9]+$ ]] && (( exit_code != 0 )); then
    pass "V.1" "空 volume + --user 10001 非零退出（rc=$exit_code）"
  elif [[ "$exit_code" == "0" ]]; then
    fail "V.1" "空 volume + --user 10001 意外以 0 退出（应拒绝启动）"
  else
    fail "V.1" "空 volume 容器退出码异常（[${exit_code:-empty}]）"
  fi

  config_count=$(find "$EMPTY_DATA" -type f \
    \( -name 'hub.toml' -o -name '*.key' -o -name '*.pem' -o -name 'admin_token' \) \
    -print 2>/dev/null | wc -l | tr -d '[:space:]')
  if [[ "$config_count" == "0" ]]; then
    pass "V.2" "空 volume 失败后未写入 config/私钥/token"
  else
    fail "V.2" "空 volume 失败后写入了 $config_count 个配置/密钥/token 文件"
  fi

  if grep -Eqi \
    'BEGIN [A-Z ]*PRIVATE KEY|Bearer [A-Za-z0-9._~+/=-]{8,}|admin_token[[:space:]]*[=:][[:space:]]*[A-Za-z0-9._~+/=-]{8,}' \
    "$LOG_DIR/empty-hub.log" 2>/dev/null; then
    fail "V.3" "空 volume 错误日志疑似包含 secret（内容未打印）"
  else
    pass "V.3" "空 volume 错误日志不含 secret 形态内容"
  fi

  docker rm -f "$EMPTY_CT" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# panel
# ---------------------------------------------------------------------------

panel_checks() {
  local mappings=""

  stop_remove "$PANEL_CT"
  stop_remove "$EMPTY_CT"
  stop_remove "$USER_CT"
  stop_remove "$HUB_CT"

  if ! docker run -d --name "$HUB_CT" --label "rustboard.e2e=1" \
    --network "$NET_NAME" \
    -p "127.0.0.1:${HOST_8443}:8443" \
    -p "127.0.0.1:${HOST_8080}:8080" \
    -e "RUSTBOARD_ADMIN_TOKEN_SHARE=/run/rustboard/admin_token" \
    -v "$HUB_DATA:/data" \
    -v "$HUB_RUN_VOLUME:/run/rustboard" \
    "$HUB_IMAGE" >/dev/null 2>"$LOG_DIR/hub-share-run.err"; then
    fail "P.1" "启用 RUSTBOARD_ADMIN_TOKEN_SHARE 的 hub 启动失败"
    dump_file "$LOG_DIR/hub-share-run.err" 50
    return
  fi
  CONTAINERS+=("$HUB_CT")
  pass "P.1" "hub 以 RUSTBOARD_ADMIN_TOKEN_SHARE=/run/rustboard/admin_token 启动"

  if ! check_health "P.2" "共享 token 的 hub healthcheck healthy" "$HUB_CT"; then
    return
  fi
  if ! wait_exec_http_200 "$HUB_CT" "http://127.0.0.1:8444/healthz" 60; then
    fail "P.3" "共享 token 的 hub 管理口未返回 200（最后 HTTP $LAST_CODE）"
  else
    pass "P.3" "共享 token 的 hub 管理口 /healthz 200"
  fi

  if docker exec "$HUB_CT" test -s /run/rustboard/admin_token >/dev/null 2>&1; then
    pass "P.4" "hub 写出 /run/rustboard/admin_token（非空）"
  else
    fail "P.4" "hub 未写出非空 /run/rustboard/admin_token"
  fi
  check_mode_in_container "P.5a" "admin token 文件权限精确 0600" "$HUB_CT" \
    "/run/rustboard/admin_token" "600"
  if docker exec "$HUB_CT" sh -c 'test ! -L "$1" && test -f "$1"' sh \
    /run/rustboard/admin_token >/dev/null 2>&1; then
    pass "P.5b" "admin token 是非符号链接的普通文件"
  else
    fail "P.5b" "admin token 是符号链接或非普通文件"
  fi
  check_eq "P.5c" "admin token 文件属主为 UID 10001" "10001" \
    "$(docker exec "$HUB_CT" stat -c '%u' /run/rustboard/admin_token 2>/dev/null || true)"

  if [[ "$(docker inspect -f '{{.State.Running}}' "$HUB_CT" 2>/dev/null || true)" == "true" ]]; then
    mappings=$(docker port "$HUB_CT" 2>/dev/null || true)
    if printf '%s\n' "$mappings" | grep -q '^8444/'; then
      fail "P.6" "hub 8444 被发布到宿主（panel 共享 netns 也不得发布管理口）"
    else
      pass "P.6" "hub 8444 仍未发布到宿主"
    fi
  else
    fail "P.6" "hub 未运行，无法确认 8444 未发布"
  fi

  if ! docker run -d --name "$PANEL_CT" --label "rustboard.e2e=1" \
    --network "container:$HUB_CT" \
    -v "$HUB_RUN_VOLUME:/run/rustboard:ro" \
    -v "$PANEL_DATA:/data" \
    -e "HUB_URL=http://127.0.0.1:8444" \
    -e "HUB_TOKEN_FILE=/run/rustboard/admin_token" \
    -e "PANEL_LISTEN=0.0.0.0:8080" \
    -e "PANEL_STATIC_DIR=/usr/share/rustboard/web" \
    "$PANEL_IMAGE" >/dev/null 2>"$LOG_DIR/panel-run.err"; then
    fail "P.7" "panel 容器启动失败"
    dump_file "$LOG_DIR/panel-run.err" 50
    return
  fi
  CONTAINERS+=("$PANEL_CT")
  pass "P.7" "panel 启动（network_mode=container:$HUB_CT，hub_run 只读挂载）"

  if ! check_health "P.8" "panel healthcheck healthy（127.0.0.1:8080/healthz）" "$PANEL_CT"; then
    return
  fi

  if ! wait_exec_http_200 "$PANEL_CT" "http://127.0.0.1:8444/healthz" 30; then
    fail "P.9" "panel 共享 netns 后无法访问 hub 127.0.0.1:8444（最后 HTTP $LAST_CODE）"
  else
    pass "P.9" "panel 共享 netns 后可访问 hub 127.0.0.1:8444/healthz"
  fi

  check_exec_http_200 "P.10" "panel 127.0.0.1:8080/healthz 返回 200" \
    "$PANEL_CT" "http://127.0.0.1:8080/healthz"
  check_exec_http_200 "P.11" "panel 127.0.0.1:8080/ 返回 200" \
    "$PANEL_CT" "http://127.0.0.1:8080/"

  if wait_host_http_200 "http://127.0.0.1:${HOST_8080}/healthz" 20; then
    pass "P.12" "panel 8080 经 hub 发布端口从宿主 127.0.0.1:$HOST_8080 可访问"
  else
    fail "P.12" "panel 8080 未通过 hub 发布端口暴露给宿主（最后 HTTP $LAST_CODE；PANEL_LISTEN 应绑 0.0.0.0:8080）"
  fi

  check_rustboard_uid_10001 "P.13" "$PANEL_CT" "panel"
  check_tini_root "P.14" "$PANEL_CT"
  check_file_in_container "P.15" "panel 配置位于 /data/etc/rustboard/panel.toml" \
    "$PANEL_CT" "/data/etc/rustboard/panel.toml"
  check_mode_in_container "P.16" "panel 配置权限为 0600" "$PANEL_CT" \
    "/data/etc/rustboard/panel.toml" "600"
  check_readable_as_10001 "P.17" "panel 配置对 UID 10001 可读" "$PANEL_CT" \
    "/data/etc/rustboard/panel.toml"

  panel_user_checks
}

# panel 已初始化 volume 的 --user 10001:10001 启动（复用 hub netns 与 token 卷）。
panel_user_checks() {
  stop_remove "$PANEL_CT"

  if ! docker run -d --name "$PANEL_USER_CT" --label "rustboard.e2e=1" \
    --network "container:$HUB_CT" --user 10001:10001 \
    -v "$HUB_RUN_VOLUME:/run/rustboard:ro" \
    -v "$PANEL_DATA:/data" \
    -e "HUB_URL=http://127.0.0.1:8444" \
    -e "HUB_TOKEN_FILE=/run/rustboard/admin_token" \
    -e "PANEL_LISTEN=0.0.0.0:8080" \
    -e "PANEL_STATIC_DIR=/usr/share/rustboard/web" \
    "$PANEL_IMAGE" >/dev/null 2>"$LOG_DIR/panel-user-run.err"; then
    fail "P.18" "已初始化 panel volume 以 --user 10001:10001 启动失败"
    dump_file "$LOG_DIR/panel-user-run.err" 50
    return
  fi
  CONTAINERS+=("$PANEL_USER_CT")
  pass "P.18" "已初始化 panel volume 以 --user 10001:10001 启动"

  if ! check_health "P.19" "--user 10001:10001 下 panel healthcheck healthy" "$PANEL_USER_CT"; then
    stop_remove "$PANEL_USER_CT"
    return
  fi
  check_exec_http_200 "P.20" "--user 10001:10001 下 panel 8080/healthz 返回 200" \
    "$PANEL_USER_CT" "http://127.0.0.1:8080/healthz"

  if wait_host_http_200 "http://127.0.0.1:${HOST_8080}/healthz" 20; then
    pass "P.21" "--user 10001:10001 下 panel 8080 仍可经 hub 从宿主访问"
  else
    fail "P.21" "--user 10001:10001 下 panel 8080 宿主访问失败（最后 HTTP $LAST_CODE）"
  fi

  check_rustboard_uid_10001 "P.22" "$PANEL_USER_CT" "panel"
  check_readable_as_10001 "P.23" "--user 10001:10001 下 panel 配置对 10001 可读" \
    "$PANEL_USER_CT" "/data/etc/rustboard/panel.toml"
  stop_remove "$PANEL_USER_CT"
}

# ---------------------------------------------------------------------------
# agent 真实 enrollment（hub 可用时）
# ---------------------------------------------------------------------------

agent_enrollment_checks() {
  local add_out="$LOG_DIR/agent-enroll-add.out"
  local hub_host="" hub_ip="" token="" fp="" control="" mounts="" privileged=""
  local agent_name="e2e-$RUN_ID"
  local -a hexes=()

  # 复用 panel 阶段仍在运行的 hub；若不可用则单独拉起一个（不挂 token 共享卷）。
  if [[ "$(docker inspect -f '{{.State.Running}}' "$HUB_CT" 2>/dev/null || true)" != "true" ]]; then
    stop_remove "$PANEL_USER_CT"
    stop_remove "$PANEL_CT"
    stop_remove "$HUB_CT"
    if ! docker run -d --name "$HUB_CT" --label "rustboard.e2e=1" \
      --network "$NET_NAME" \
      -p "127.0.0.1:${HOST_8443}:8443" \
      -v "$HUB_DATA:/data" "$HUB_IMAGE" \
      >/dev/null 2>"$LOG_DIR/hub-agent-run.err"; then
      fail "G.1" "agent enrollment 前启动 hub 失败"
      dump_file "$LOG_DIR/hub-agent-run.err" 50
      return
    fi
    CONTAINERS+=("$HUB_CT")
    if ! check_health "G.0" "agent enrollment 前新启动的 hub healthcheck healthy" "$HUB_CT"; then
      return
    fi
  fi

  if ! wait_exec_http_200 "$HUB_CT" "http://127.0.0.1:8444/healthz" 60; then
    fail "G.1" "agent enrollment 用 hub 管理口未返回 200（最后 HTTP $LAST_CODE）"
    return
  fi
  pass "G.1" "hub 可用，管理口 /healthz 200"

  hub_host=$(docker inspect -f '{{.Config.Hostname}}' "$HUB_CT" 2>/dev/null || true)
  hub_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$HUB_CT" 2>/dev/null || true)
  if [[ -z "$hub_host" || -z "$hub_ip" ]]; then
    fail "G.2" "无法解析 hub 容器 hostname/IP（host=[$hub_host] ip=[$hub_ip]）"
    return
  fi

  # 在 hub 容器内生成一次性 token + 指纹；输出只落盘，绝不打印 token。
  if ! docker exec "$HUB_CT" rustboard-hub agent add \
    -c /data/etc/rustboard/hub.toml --name "$agent_name" \
    >"$add_out" 2>"$LOG_DIR/agent-enroll-add.err"; then
    fail "G.2" "hub 生成 enrollment token 失败"
    rm -f "$add_out" "$LOG_DIR/agent-enroll-add.err"
    return
  fi
  mapfile -t hexes < <(grep -Eo '[0-9a-fA-F]{64}' "$add_out" 2>/dev/null || true)
  rm -f "$add_out" "$LOG_DIR/agent-enroll-add.err"
  if (( ${#hexes[@]} < 2 )); then
    fail "G.2" "hub agent add 输出中未解析到 token+fingerprint（输出已删除，不打印内容）"
    return
  fi
  token=${hexes[0]}
  fp=${hexes[${#hexes[@]} - 1]}
  if [[ ! "$token" =~ ^[0-9a-fA-F]{64}$ || ! "$fp" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "G.2" "enrollment token/fingerprint 格式非 64hex"
    return
  fi

  printf '%s\n' "$token" >"$AGENT_TOKEN_FILE" || {
    fail "G.2" "写入临时 enrollment token 文件失败"
    return
  }
  chmod 600 "$AGENT_TOKEN_FILE"
  if [[ ! -f "$AGENT_TOKEN_FILE" || -L "$AGENT_TOKEN_FILE" ]]; then
    fail "G.2" "临时 enrollment token 不是普通文件"
    return
  fi
  pass "G.2" "hub 生成一次性 enrollment token 与证书指纹（内容不打印）"

  if ! docker run -d --name "$AGENT_CT" --label "rustboard.e2e=1" \
    --network "$NET_NAME" \
    --add-host "$hub_host:$hub_ip" \
    -v "$AGENT_DATA:/data" \
    -v "$AGENT_TOKEN_FILE:/run/rustboard/enroll_token:ro" \
    -e "RUSTBOARD_HUB_URL=wss://$hub_host:8443/agent/ws" \
    -e "RUSTBOARD_TOKEN_FILE=/run/rustboard/enroll_token" \
    -e "RUSTBOARD_FINGERPRINT=$fp" \
    -e "RUSTBOARD_NAME=$agent_name" \
    "$AGENT_IMAGE" >/dev/null 2>"$LOG_DIR/agent-enroll-run.err"; then
    fail "G.3" "真实 enrollment agent 容器启动失败"
    dump_file "$LOG_DIR/agent-enroll-run.err" 50
    rm -f "$AGENT_TOKEN_FILE"
    return
  fi
  CONTAINERS+=("$AGENT_CT")
  pass "G.3" "agent 容器以真实 token/指纹启动（未 privileged）"

  if ! check_health "G.4" "agent enrollment 后 healthcheck（cert-info）healthy" "$AGENT_CT"; then
    stop_remove "$AGENT_CT"
    rm -f "$AGENT_TOKEN_FILE"
    return
  fi

  if docker exec "$AGENT_CT" rustboard-agent cert-info \
    --config /data/etc/rustboard/agent.toml >"$LOG_DIR/agent-cert-info.log" 2>&1; then
    pass "G.5" "agent cert-info 成功（证书/CN 不打印）"
  else
    fail "G.5" "agent cert-info 失败（证书未就绪）"
    dump_file "$LOG_DIR/agent-cert-info.log" 30
  fi

  check_rustboard_uid_10001 "G.6" "$AGENT_CT" "agent"
  check_tini_root "G.7" "$AGENT_CT"

  mounts=$(docker inspect -f '{{range .Mounts}}{{.Destination}} {{end}}' "$AGENT_CT" 2>/dev/null || true)
  if [[ "$mounts" == *"docker.sock"* ]]; then
    fail "G.8" "agent 运行期挂载了 docker.sock"
  else
    pass "G.8" "agent 运行期未挂载 docker.sock"
  fi
  privileged=$(docker inspect -f '{{.HostConfig.Privileged}}' "$AGENT_CT" 2>/dev/null || true)
  check_eq "G.9" "agent 运行期未使用 privileged" "false" "$privileged"

  if ! control=$(docker exec "$AGENT_CT" cat /data/etc/rustboard/agent.toml 2>/dev/null | \
    "$PYTHON" -c '
import re
import sys

text = sys.stdin.read()
section = re.search(r"(?ms)^\[control\]\s*$(.*?)(?=^\[|\Z)", text)
body = section.group(1) if section else ""

def value(key):
    hit = re.search(r"(?m)^\s*" + key + r"\s*=\s*(true|false)\s*$", body)
    return hit.group(1) if hit else "false"

print(" ".join(key + "=" + value(key) for key in ("enabled", "systemd", "docker", "process", "logs")))
'); then
    fail "G.10" "无法解析 agent 配置 [control]（配置内容未打印）"
  else
    check_eq "G.10" "agent control 默认全部关闭" \
      "enabled=false systemd=false docker=false process=false logs=false" "$control"
  fi

  check_mode_in_container "G.11" "agent 配置权限为 0600" "$AGENT_CT" \
    "/data/etc/rustboard/agent.toml" "600"
  check_eq "G.12" "agent 配置属主为 UID 10001" "10001" \
    "$(docker exec "$AGENT_CT" stat -c '%u' /data/etc/rustboard/agent.toml 2>/dev/null || true)"

  stop_remove "$AGENT_CT"
  rm -f "$AGENT_TOKEN_FILE"
}

# ---------------------------------------------------------------------------
# agent
# ---------------------------------------------------------------------------

agent_checks() {
  local out="" exit_code="" rc=0 config_count=0 privileged=""

  if docker run --rm --network none --entrypoint /bin/sh "$AGENT_IMAGE" -c \
    'test ! -e /var/run/docker.sock' >/dev/null 2>&1; then
    pass "A.1" "agent 镜像内无 /var/run/docker.sock"
  else
    fail "A.1" "agent 镜像内存在 /var/run/docker.sock"
  fi
  if docker run --rm --network none --entrypoint /bin/sh "$AGENT_IMAGE" -c \
    'test ! -e /run/systemd/system' >/dev/null 2>&1; then
    pass "A.2" "agent 镜像内无 /run/systemd/system（未内置 systemd 运行时）"
  else
    fail "A.2" "agent 镜像内存在 /run/systemd/system"
  fi

  if out=$(docker run --rm --network none --entrypoint /bin/sh "$AGENT_IMAGE" -c \
    'rustboard-agent --version' 2>"$LOG_DIR/agent-version.err"); then
    if printf '%s\n' "$out" | grep -Fq "$VERSION"; then
      pass "A.3" "rustboard-agent --version 成功且包含 $VERSION"
    else
      fail "A.3" "rustboard-agent --version 输出不含版本 $VERSION（输出: $(printf '%s' "$out" | head -n 2 | tr '\n' ' ')）"
    fi
  else
    fail "A.3" "rustboard-agent --version 失败"
    dump_file "$LOG_DIR/agent-version.err" 30
  fi

  if ! docker run -d --name "$AGENT_EMPTY_CT" --label "rustboard.e2e=1" \
    --network none -v "$AGENT_EMPTY_DATA:/data" "$AGENT_IMAGE" \
    >/dev/null 2>"$LOG_DIR/agent-empty-run.err"; then
    fail "A.4" "agent 空环境容器启动命令失败"
    dump_file "$LOG_DIR/agent-empty-run.err" 30
  else
    CONTAINERS+=("$AGENT_EMPTY_CT")
    if timeout "$EMPTY_TIMEOUT" docker wait "$AGENT_EMPTY_CT" \
      >"$LOG_DIR/agent-empty.exit" 2>"$LOG_DIR/agent-empty.wait.err"; then
      exit_code=$(tr -d '[:space:]' <"$LOG_DIR/agent-empty.exit")
      docker logs "$AGENT_EMPTY_CT" >"$LOG_DIR/agent-empty.log" 2>&1 || true
      if [[ "$exit_code" =~ ^[0-9]+$ ]] && (( exit_code != 0 )); then
        pass "A.4" "缺少 RUSTBOARD_HUB_URL/TOKEN_FILE/FINGERPRINT 时 entrypoint 非零退出（rc=$exit_code）"
      elif [[ "$exit_code" == "0" ]]; then
        fail "A.4" "缺少必需 env 时 agent entrypoint 意外以 0 退出"
      else
        fail "A.4" "agent 空环境退出码异常（[${exit_code:-empty}]）"
      fi
    else
      rc=$?
      if (( rc == 124 || rc == 137 )); then
        fail "A.4" "agent 空 env 未在 ${EMPTY_TIMEOUT}s 内 fail-fast（疑似挂起）"
      else
        fail "A.4" "等待 agent 空 env 容器失败（rc=$rc）"
      fi
      docker logs "$AGENT_EMPTY_CT" >"$LOG_DIR/agent-empty.log" 2>&1 || true
    fi

    config_count=$(find "$AGENT_EMPTY_DATA" -type f \
      \( -name 'agent.toml' -o -name 'agent.key' -o -name 'agent.secret' -o -name 'agent_id' \) \
      -print 2>/dev/null | wc -l | tr -d '[:space:]')
    if [[ "$config_count" == "0" ]]; then
      pass "A.5" "agent 空 env 失败后未写 config/私钥/secret"
    else
      fail "A.5" "agent 空 env 失败后写入 $config_count 个配置/密钥文件"
    fi

    if [[ -f "$LOG_DIR/agent-empty.log" ]] && grep -Eqi \
      'BEGIN [A-Z ]*PRIVATE KEY|Bearer [A-Za-z0-9._~+/=-]{8,}|admin_token[[:space:]]*[=:][[:space:]]*[A-Za-z0-9._~+/=-]{8,}' \
      "$LOG_DIR/agent-empty.log" 2>/dev/null; then
      fail "A.6" "agent 空 env 错误日志疑似包含 secret（内容未打印）"
    else
      pass "A.6" "agent 空 env 错误日志不含 secret 形态内容"
    fi

    privileged=$(docker inspect -f '{{.HostConfig.Privileged}}' "$AGENT_EMPTY_CT" 2>/dev/null || true)
    if [[ "$privileged" == "false" ]]; then
      pass "A.7" "agent 运行未使用 --privileged"
    else
      fail "A.7" "agent 运行 privileged=[${privileged:-unknown}]（默认必须 false）"
    fi

    docker rm -f "$AGENT_EMPTY_CT" >/dev/null 2>&1 || true
  fi
}

# ---------------------------------------------------------------------------
# arm64（可选）与 manifest 说明
# ---------------------------------------------------------------------------

arm64_checks() {
  local log="$LOG_DIR/arm64-build.log" out="" arch=""
  if [[ "$DOCKER_ARCH" == "arm64" ]]; then
    skip "M.1" "可选 arm64/QEMU 附加检查已跳过：DOCKER_ARCH=arm64，主用例已按 linux/arm64 执行"
    ARM64_SKIPPED=1
    return
  fi
  if [[ "$SKIP_ARM64" == "1" ]]; then
    skip "M.1" "可选 arm64/QEMU 附加检查已跳过：SKIP_ARM64=1（arm64 原生门禁由 delivery-arm64 覆盖）"
    ARM64_SKIPPED=1
    return
  fi
  if (( HAVE_QEMU_AARCH64 == 0 )); then
    skip "M.1" "arm64 镜像附加检查：本机未注册 qemu-aarch64 binfmt"
    ARM64_SKIPPED=1
    return
  fi
  if [[ ! -x "dist/arm64/bin/rustboard-hub" ]]; then
    skip "M.1" "arm64 镜像附加检查：QEMU 可用但缺少 dist/arm64/bin/rustboard-hub（先运行 packaging/build-release.sh --arch arm64 后重跑）"
    ARM64_SKIPPED=1
    return
  fi

  if docker buildx build --load --platform linux/arm64 --progress=plain \
    -f docker/Dockerfile --target hub \
    --build-arg "VERSION=$VERSION" \
    --build-arg "REVISION=$REVISION" \
    -t "$ARM64_HUB_IMAGE" . >"$log" 2>&1; then
    pass "M.1" "构建 $ARM64_HUB_IMAGE（linux/arm64，QEMU 附加）"
  else
    fail "M.1" "arm64 hub 镜像附加构建失败（QEMU/binfmt 可用）"
    dump_file "$log" 100
    ARM64_SKIPPED=1
    return
  fi

  arch=$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$ARM64_HUB_IMAGE" 2>/dev/null || true)
  check_eq "M.2" "arm64 hub 镜像架构为 linux/arm64" "linux/arm64" "$arch"

  if out=$(docker run --rm --platform linux/arm64 --network none \
    --entrypoint /bin/sh "$ARM64_HUB_IMAGE" -c 'rustboard-hub --version' \
    2>"$LOG_DIR/arm64-version.err"); then
    if printf '%s\n' "$out" | grep -Fq "$VERSION"; then
      pass "M.3" "arm64 hub 在 QEMU 下运行 --version 成功且包含 $VERSION"
      ARM64_VERIFIED=1
    else
      fail "M.3" "arm64 hub --version 输出不含 $VERSION（输出: $(printf '%s' "$out" | head -n 2 | tr '\n' ' ')）"
    fi
  else
    fail "M.3" "arm64 hub 在 QEMU 下运行 --version 失败"
    dump_file "$LOG_DIR/arm64-version.err" 30
  fi
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

parse_args() {
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
}

main() {
  preflight
  setup_resources
  compose_checks

  if ! build_images; then
    info "镜像构建未全部成功；跳过依赖镜像的运行时用例（失败已计入 B 组，不计 PASS）"
    return 0
  fi

  label_checks
  source_image_checks
  image_clean_checks hub "$HUB_IMAGE"
  image_clean_checks panel "$PANEL_IMAGE"
  image_clean_checks agent "$AGENT_IMAGE"
  port_checks
  hub_checks
  user_checks
  empty_volume_checks
  panel_checks
  agent_enrollment_checks
  agent_checks
  arm64_checks
}

# --help 在处理参数时直接退出，不注册 cleanup trap（无需清理任何资源）。
parse_args "$@"

trap cleanup EXIT
trap 'exit 130' INT TERM

main

if (( FAILS > 0 )); then
  exit 1
fi
exit 0
