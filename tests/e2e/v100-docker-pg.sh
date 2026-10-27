#!/usr/bin/env bash
#
# RustBoard M5 Phase E S4：Docker + PostgreSQL overlay 容器内 e2e。
#
# 依据：
#   - docs/plans/2026-10-26-phase-e-docker-pg.md
#   - docker/compose.example.yml 与 docker/compose.postgres.example.yml
#   - docker/Dockerfile / entrypoint-hub.sh / entrypoint-agent.sh 的公开接口
#   - tests/e2e/v100-docker.sh 的 PASS/FAIL/redact/trap 约定
#
# 覆盖：
#   1) 用当前源码 dist/amd64 构建三个本地镜像（tag :local-s4），断言 hub
#      --version = 1.0.0（当前源码），且 hub 镜像内没有 pg_dump/pg_restore；
#   2) 默认 compose 配置无 postgres/5432/8444，实跑 hub+panel 为 SQLite，
#      hub_data volume 内 rustboard.db 有 schema/迁移数据；
#   3) PostgreSQL overlay：postgres:16（本地缺 alpine 时用本地 postgres:16 覆盖
#      image，不联网拉取）+ hub，密码只走 0600 secret，管理 API 可用，
#      hub.toml 是 postgres://...sslmode=disable 且没有 db_sslrootcert；
#   4) 真实 agent enrollment：token 只落 0600 文件、指纹取自 `hub ports`，
#      agent 达到 cert-info healthy/online，PG samples/ingest_batches/agents > 0；
#   5) 停/启 PostgreSQL 与 hub 后健康、计数不减少；
#   6) 已初始化 hub volume 以 --user 10001:10001 启动，健康且无权限错误；
#   7) 外部 postgres:16 client `pg_dump -Fc` → 新库 rustboard_restore
#      `pg_restore`，四张核心表计数一致，原库计数不变；
#   8) 默认 SQLite 与 PG overlay 项目/volume/配置互不串；
#   9) PASS/FAIL 计数；全部检查通过且 cleanup 无残留时输出“全部 N 项通过”，
#      失败/中断/资源残留以非 0 退出。
#
# 安全与清理：
#   - 密码、enrollment token、agent secret 只写 0600 临时文件（/tmp 下独立
#     secret 目录，权限 0700），不打印、不进命令行参数；密码只通过 0600
#     env-file 传给一次性的 postgres client 容器；
#   - 证据目录 target/docker-pg-e2e/<UTC>-<PID>/ 只保留脱敏日志/计数，失败保留；
#   - compose 项目名 rb-s4-<UTC>-<PID>（默认）与 rb-s4-<UTC>-<PID>-pg；trap 只删本项目容器/
#     网络/volume 与临时目录，不执行 docker system prune，不碰其它项目；
#   - 不构建 arm64（S5 独立）；不联网拉取镜像（只用本机已有镜像）。
#
# 前置（主 Agent 运行前确认）：
#   - Linux amd64、Docker 24+、docker compose v2+（优先 buildx）、curl、python3；
#   - dist/amd64/bin/{rustboard-hub,panel,agent} 与 web/dist 已由
#     `packaging/build-release.sh --arch amd64` 生成，Cargo.toml 版本为
#     EXPECTED_VERSION（默认 1.0.0）；
#   - 本机已有 debian:bookworm-slim（Dockerfile 基础镜像）、postgres:16（PG
#     服务端/客户端兜底）；若已有 postgres:16-alpine 则优先用 overlay 默认；
#   - 宿主 8443/8080 空闲。脚本不会自动停止无关容器/服务。
#
# 用法：
#   bash tests/e2e/v100-docker-pg.sh --dist-manifest target/dist-manifest.txt
#   EXPECTED_DIST_SHA256='hub=... panel=... agent=... web=...' \
#     bash tests/e2e/v100-docker-pg.sh
#   bash tests/e2e/v100-docker-pg.sh --help
#
# 环境变量：
#   --dist-manifest FILE          dist 来源绑定清单；与 EXPECTED_DIST_SHA256 二选一，
#                                二者都没有时 FATAL（拒绝未知 dist）
#   EXPECTED_DIST_SHA256=...      hub=<sha> panel=<sha> agent=<sha> web=<sha>
#                                来源绑定；web 指 web/dist/index.html
#   EXPECTED_VERSION=1.0.0  当前源码期望版本（默认值；与 Cargo.toml 不一致
#                                时 fail-fast，防止误用旧镜像）
#   HEALTH_TIMEOUT=240           postgres/hub healthcheck 等待秒数
#   AGENT_TIMEOUT=180            agent enrollment/health 等待秒数
#   DATA_TIMEOUT=120             等待 PG samples/ingest_batches/agents 的秒数
#   PYTHON=python3              Python 解释器
#
# 注意：本脚本会 build/run/remove 本项目资源；CI 不执行（依赖 Docker 与固定
#       宿主端口），由 Phase E 主 Agent 在独立环境运行。
#
# cleanup 及其辅助函数由 trap 间接调用；ShellCheck 看不到这条路径，SC2317 为误报。
# shellcheck disable=SC2317,SC2016
set -euo pipefail
umask 077

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd)
cd "$ROOT" || {
  printf 'FATAL: 无法进入仓库根目录: %s\n' "$ROOT" >&2
  exit 1
}

PYTHON=${PYTHON:-python3}
EXPECTED_VERSION=${EXPECTED_VERSION:-1.0.0}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-240}
AGENT_TIMEOUT=${AGENT_TIMEOUT:-180}
DATA_TIMEOUT=${DATA_TIMEOUT:-120}

DOCKER_ARCH=amd64
PLATFORM="linux/${DOCKER_ARCH}"
DIST_BIN="dist/${DOCKER_ARCH}/bin"
IMAGE_VERSION=local-s4
HUB_IMAGE="ghcr.io/pazzifirst/rustboard-hub:${IMAGE_VERSION}"
PANEL_IMAGE="ghcr.io/pazzifirst/rustboard-panel:${IMAGE_VERSION}"
AGENT_IMAGE="ghcr.io/pazzifirst/rustboard-agent:${IMAGE_VERSION}"

# 与 docker/compose.example.yml 的 ${RUSTBOARD_*} 占位符对齐：只允许本地
# :local-s4 镜像，agent 走宿主机回环 127.0.0.1:8443（自签证书 SAN 覆盖）。
export RUSTBOARD_VERSION="$IMAGE_VERSION"
export RUSTBOARD_HUB_ADVERTISE="127.0.0.1"
export RUSTBOARD_HUB_SAN="127.0.0.1,localhost"

RUN_STAMP=$(date -u +%Y%m%dT%H%M%SZ | tr '[:upper:]' '[:lower:]')
RUN_ID="${RUN_STAMP}-$$"
PROJECT_BASE="rb-s4-${RUN_ID}"
PROJECT_SQLITE="$PROJECT_BASE"
PROJECT_PG="${PROJECT_BASE}-pg"

EVIDENCE_ROOT="$ROOT/target/docker-pg-e2e"
RUN_DIR="$EVIDENCE_ROOT/$RUN_ID"
LOG_DIR="$RUN_DIR/logs"
HELPER="$RUN_DIR/helper.py"
SECRETS=""
PG_PW_FILE=""
PG_ENV_FILE=""
USER_PW_FILE=""
AGENT_TOKEN_FILE=""
DUMP_FILE=""
SQLITE_COPY_DIR=""

SQLITE_HUB_CT=""
SQLITE_PANEL_CT=""
SQLITE_HUB_VOLUME=""
SQLITE_NETWORK=""
SQLITE_VOLUME_NAMES=""
PG_VOLUME_NAMES=""
PG_CT=""
PG_HUB_CT=""
PG_PANEL_CT=""
PG_NETWORK=""
PG_HUB_VOLUME=""
PG_RUN_VOLUME=""
PG_DATA_VOLUME=""
PG_CFG_HASH=""
AGENT_CT="${PROJECT_BASE}-agent"
AGENT_VOLUME="${PROJECT_BASE}-agent-data"
USER_CT="${PROJECT_BASE}-hub-user"
PG_CLIENT_CT="${PROJECT_BASE}-pg-client"
PG_RESTORE_CT="${PROJECT_BASE}-pg-restore"
PG_IMAGE=""
PG_CLIENT_IMAGE=""
PG_COMPOSE_SUBSTITUTED=0
VERSION=""
REVISION=""
HAVE_COMPOSE=0
HAVE_BUILDX=0
LAST_STATE="unknown"
LAST_CODE="000"
LAST_AGENT_SUMMARY=""
S4_AGENT_ID=""
PG_COMPOSE_ARGS=(-f docker/compose.example.yml -f docker/compose.postgres.example.yml)
DIST_MANIFEST=${DIST_MANIFEST:-}
EXPECTED_DIST_SHA256=${EXPECTED_DIST_SHA256:-}
DIST_HUB_SHA=""
DIST_PANEL_SHA=""
DIST_AGENT_SHA=""
DIST_WEB_SHA=""
PROVENANCE_FILE="$RUN_DIR/provenance.txt"

PASSES=0
FAILS=0
SKIPS=0
SUMMARY_PRINTED=0
FINAL_CODE=0
EXTRA_CONTAINERS=()

# ---------------------------------------------------------------------------
# 输出、脱敏与断言
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
  FAILS=$((FAILS + 1))
  printf 'FATAL: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少依赖命令: $1"
}

usage() {
  cat <<'EOF'
用法: bash tests/e2e/v100-docker-pg.sh --dist-manifest FILE
      EXPECTED_DIST_SHA256='hub=<sha> panel=<sha> agent=<sha> web=<sha>' \
        bash tests/e2e/v100-docker-pg.sh
      bash tests/e2e/v100-docker-pg.sh --help

Phase E S4 Docker + PostgreSQL overlay e2e。构建当前 dist 的三个 :local-s4
镜像，验证默认 SQLite compose、PG overlay、真实 agent 上报、重启持久化、
--user 10001、外部 pg_dump/pg_restore，以及默认 SQLite 与 PG 项目隔离。
必须提供 dist 来源绑定（manifest 或 EXPECTED_DIST_SHA256），否则拒绝运行。

参数/环境变量:
  --dist-manifest FILE         来源绑定文件，格式 hub=<64hex> panel=<64hex>
                               agent=<64hex> web=<64hex>（web=index.html）
  EXPECTED_DIST_SHA256=...     同上的环境变量形式（与 --dist-manifest 二选一）
  EXPECTED_VERSION=1.0.0  期望源码版本，默认 1.0.0
  HEALTH_TIMEOUT=240           postgres/hub healthcheck 等待秒数
  AGENT_TIMEOUT=180            agent enrollment/health 等待秒数
  DATA_TIMEOUT=120             等待 PG 样本/agent 计数的秒数
  PYTHON=python3              Python 解释器

前置:
  - 本机已有 debian:bookworm-slim、postgres:16（或 postgres:16-alpine）；
  - dist/amd64/bin 与 web/dist 已由 packaging/build-release.sh --arch amd64 生成；
  - 宿主 8443/8080 空闲。脚本不联网拉取镜像，不构建 arm64（由 S5 覆盖）。

示例:
  bash tests/e2e/v100-docker-pg.sh --dist-manifest target/dist-manifest.txt
  HEALTH_TIMEOUT=300 AGENT_TIMEOUT=240 \
    bash tests/e2e/v100-docker-pg.sh --dist-manifest target/dist-manifest.txt
EOF
}

# 日志/容器输出永不原样打印：先遮掉 DSN userinfo、token、密码、Bearer、
# 64hex 指纹与超长随机值。redact 只用于文本日志，不用于二进制 dump。
redact_stream() {
  sed -E \
    -e 's#(postgres(ql)?://)[^@[:space:]"]*@#\1<redacted>@#Ig' \
    -e 's/((admin_token|token|secret|password|passwd|fingerprint)([[:space:]]*[=:][[:space:]]*))[^[:space:]",]+/\1<redacted>/Ig' \
    -e 's/(--(token|password|fingerprint)(-file)?[[:space:]=]+)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1<redacted>/Ig' \
    -e 's/((初始)?密码[^:：]*[:：][[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/\b[0-9a-fA-F]{64}\b/<redacted-64hex>/g' \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----.*/<redacted-private-key>/g' \
    -e 's/\b[A-Za-z0-9_-]{40,}\b/<redacted-long-value>/g'
}

dump_file() {
  local file=${1:-} lines=${2:-60}
  [[ -n "$file" && -f "$file" && -s "$file" ]] || return 0
  printf -- '---- %s (tail -n %s, redacted) ----\n' "$(basename -- "$file")" "$lines" >&2
  { tail -n "$lines" -- "$file" 2>/dev/null | redact_stream; } >&2 || true
}

dump_container_logs() {
  local ct=${1:-} lines=${2:-80}
  [[ -n "$ct" ]] || return 0
  docker inspect "$ct" >/dev/null 2>&1 || return 0
  printf -- '---- docker logs %s (tail -n %s, redacted) ----\n' "$ct" "$lines" >&2
  { docker logs --tail "$lines" "$ct" 2>&1 | redact_stream; } >&2 || true
}

dump_compose_state() {
  local project=$1
  shift
  (( HAVE_COMPOSE == 1 )) || return 0
  printf -- '---- compose %s ps ----\n' "$project" >&2
  { docker compose -p "$project" "$@" ps 2>&1 | redact_stream; } >&2 || true
}

dump_diagnostics() {
  local ct file
  printf '===== v100-docker-pg e2e 失败现场（已 redact）=====\n' >&2
  for file in \
    "$LOG_DIR/compose-sqlite.err" \
    "$LOG_DIR/compose-pg.err" \
    "$LOG_DIR/compose-sqlite-up.log" \
    "$LOG_DIR/compose-pg-up.log" \
    "$LOG_DIR/sqlite-config-keys.txt" \
    "$LOG_DIR/pg-config-keys.txt" \
    "$LOG_DIR/pg-count.err" \
    "$LOG_DIR/agent-add.err" \
    "$LOG_DIR/agent.log" \
    "$LOG_DIR/user-hub.log" \
    "$LOG_DIR/pg-dump.err" \
    "$LOG_DIR/pg-restore.err"; do
    dump_file "$file" 80
  done
  for ct in "${EXTRA_CONTAINERS[@]}"; do
    dump_container_logs "$ct" 80
  done
  if (( HAVE_COMPOSE == 1 )); then
    dump_compose_state "$PROJECT_SQLITE" -f docker/compose.example.yml
    dump_compose_state "$PROJECT_PG" "${PG_COMPOSE_ARGS[@]}"
  fi
}

# ---------------------------------------------------------------------------
# 临时 secret 与证据目录
# ---------------------------------------------------------------------------

is_safe_secret_dir() {
  local path=${SECRETS:-} base=${TMPDIR:-/tmp} real
  base=${base%/}
  [[ -n "$path" ]] || return 1
  [[ "$path" == "$base"/rustboard-v100-docker-pg.* ]] || return 1
  [[ "$path" != *..* && "$path" != "/" ]] || return 1
  [[ -d "$path" && ! -L "$path" ]] || return 1
  real=$(readlink -f -- "$path" 2>/dev/null || true)
  [[ -n "$real" && "$real" == "$path" ]] || return 1
  return 0
}

sanitize_evidence_logs() {
  local f
  [[ -d "$LOG_DIR" ]] || return 0
  for f in "$LOG_DIR"/*; do
    [[ -f "$f" ]] || continue
    if redact_stream <"$f" >"$f.redacted" 2>/dev/null; then
      mv -f -- "$f.redacted" "$f" || rm -f -- "$f.redacted"
    else
      rm -f -- "$f.redacted"
    fi
  done
  return 0
}

# 证据日志中若仍出现真实密码/token，说明某条输出未被脱敏：失败并把该文件
# 截断为占位符。只输出文件名与标签，不回显 secret。
scan_evidence_logs() {
  local secret=$1 label=$2 f out
  [[ -n "$secret" && -s "$secret" ]] || return 0
  [[ -d "$LOG_DIR" ]] || return 0
  for f in "$LOG_DIR"/*; do
    [[ -f "$f" ]] || continue
    if ! out=$("$PYTHON" "$HELPER" scan-secret "$f" "$secret" 2>/dev/null); then
      fail "SEC.$label" "证据日志 $(basename -- "$f") 出现 $label；已就地截断脱敏"
      printf '[redacted: %s detected in e2e log]\n' "$label" >"$f" || true
    fi
  done
  return 0
}

cleanup_secrets() {
  if [[ -z "${SECRETS:-}" ]]; then
    return 0
  fi
  if ! is_safe_secret_dir; then
    printf 'CLEANUP FAIL: secret 目录未通过安全校验，未删除: %s\n' "$SECRETS" >&2
    FAILS=$((FAILS + 1))
    return 1
  fi
  rm -rf -- "$SECRETS" 2>/dev/null || true
  if [[ -e "$SECRETS" ]]; then
    printf 'CLEANUP FAIL: secret 目录未删除: %s\n' "$SECRETS" >&2
    FAILS=$((FAILS + 1))
  fi
  return 0
}

print_summary() {
  (( SUMMARY_PRINTED == 0 )) || return 0
  SUMMARY_PRINTED=1
  printf '===== v100-docker-pg e2e: PASS=%s FAIL=%s SKIP=%s =====\n' \
    "$PASSES" "$FAILS" "$SKIPS"
  printf '证据目录: %s\n' "$RUN_DIR"
  if (( SKIPS > 0 )); then
    printf 'SKIP: %s 项未计入（arm64 由 S5 独立覆盖）\n' "$SKIPS"
  fi
  if (( FAILS == 0 && FINAL_CODE == 0 )); then
    printf '全部 %s 项通过\n' "$PASSES"
  elif (( FINAL_CODE == 129 || FINAL_CODE == 130 || FINAL_CODE == 143 )); then
    printf '中断：PASS=%s FAIL=%s（exit=%s）\n' "$PASSES" "$FAILS" "$FINAL_CODE"
  else
    printf '未通过：PASS=%s FAIL=%s\n' "$PASSES" "$FAILS"
  fi
}

# ---------------------------------------------------------------------------
# 资源清理（只处理本项目）
# ---------------------------------------------------------------------------

project_container_ids() {
  docker ps -aq --filter "label=com.docker.compose.project=$1" 2>/dev/null || true
}

project_volume_names() {
  docker volume ls -q --filter "label=com.docker.compose.project=$1" 2>/dev/null || true
}

project_network_ids() {
  docker network ls -q --filter "label=com.docker.compose.project=$1" 2>/dev/null || true
}

count_nonempty_lines() {
  awk 'NF { n++ } END { print n + 0 }'
}

remove_project_resources() {
  local project=$1 ids
  ids=$(project_container_ids "$project")
  if [[ -n "$ids" ]]; then
    printf '%s\n' "$ids" | xargs -r docker rm -f >/dev/null 2>&1 || true
  fi
  ids=$(project_volume_names "$project")
  if [[ -n "$ids" ]]; then
    printf '%s\n' "$ids" | xargs -r docker volume rm -f >/dev/null 2>&1 || true
  fi
  ids=$(project_network_ids "$project")
  if [[ -n "$ids" ]]; then
    printf '%s\n' "$ids" | xargs -r docker network rm >/dev/null 2>&1 || true
  fi
}

leftover_count() {
  local project=$1 containers volumes networks
  containers=$(project_container_ids "$project" | count_nonempty_lines)
  volumes=$(project_volume_names "$project" | count_nonempty_lines)
  networks=$(project_network_ids "$project" | count_nonempty_lines)
  printf '%s' "$((containers + volumes + networks))"
}

cleanup_extra_resources() {
  local name ids leftovers=0
  for name in "$AGENT_CT" "$USER_CT" "$PG_CLIENT_CT" "$PG_RESTORE_CT"; do
    docker rm -f -- "$name" >/dev/null 2>&1 || true
  done
  docker volume rm -f -- "$AGENT_VOLUME" >/dev/null 2>&1 || true

  # 按本次 RUN_ID 的 label 再兜底一遍；只匹配本次运行，不碰其它项目。
  ids=$(docker ps -aq --filter "label=rustboard.e2e.run=$RUN_ID" 2>/dev/null || true)
  if [[ -n "$ids" ]]; then
    printf '%s\n' "$ids" | xargs -r docker rm -f >/dev/null 2>&1 || true
  fi
  ids=$(docker volume ls -q --filter "label=rustboard.e2e.run=$RUN_ID" 2>/dev/null || true)
  if [[ -n "$ids" ]]; then
    printf '%s\n' "$ids" | xargs -r docker volume rm -f >/dev/null 2>&1 || true
  fi

  for name in "$AGENT_CT" "$USER_CT" "$PG_CLIENT_CT" "$PG_RESTORE_CT"; do
    if docker inspect "$name" >/dev/null 2>&1; then
      printf 'CLEANUP FAIL: 容器残留: %s\n' "$name" >&2
      leftovers=1
    fi
  done
  if docker volume inspect "$AGENT_VOLUME" >/dev/null 2>&1; then
    printf 'CLEANUP FAIL: volume 残留: %s\n' "$AGENT_VOLUME" >&2
    leftovers=1
  fi
  ids=$(docker ps -aq --filter "label=rustboard.e2e.run=$RUN_ID" 2>/dev/null || true)
  if [[ -n "$ids" ]]; then
    printf 'CLEANUP FAIL: 仍有本次运行 label 的容器残留\n' >&2
    leftovers=1
  fi
  ids=$(docker volume ls -q --filter "label=rustboard.e2e.run=$RUN_ID" 2>/dev/null || true)
  if [[ -n "$ids" ]]; then
    printf 'CLEANUP FAIL: 仍有本次运行 label 的 volume 残留\n' >&2
    leftovers=1
  fi
  if (( leftovers )); then
    FAILS=$((FAILS + 1))
  fi
  return 0
}

cleanup() {
  local code=$? i
  trap - EXIT INT TERM HUP
  FINAL_CODE=$code

  # 先脱敏/截断证据，再做失败现场 dump；secret 目录不进入证据。
  sanitize_evidence_logs || true
  if [[ -s "${PG_PW_FILE:-}" ]]; then
    scan_evidence_logs "$PG_PW_FILE" "postgres 密码" || true
  fi
  if [[ -s "${AGENT_TOKEN_FILE:-}" ]]; then
    scan_evidence_logs "$AGENT_TOKEN_FILE" "enrollment token" || true
  fi

  if (( code != 0 || FAILS > 0 )); then
    dump_diagnostics || true
  fi

  # 先删脚本直接创建的容器/volume，再 down compose（避免 volume 被占用）。
  # dump/restore 是一次性 --rm 容器；中断时按固定名/本次 label 兜底清理。
  cleanup_extra_resources || true

  if (( HAVE_COMPOSE == 1 )); then
    if ! docker compose -p "$PROJECT_SQLITE" -f docker/compose.example.yml \
      down -v --remove-orphans --timeout 20 >"$LOG_DIR/cleanup-sqlite.log" 2>&1; then
      printf 'CLEANUP WARN: 默认 compose 项目 down 失败（详见日志）\n' >&2
    fi
    if ! docker compose -p "$PROJECT_PG" "${PG_COMPOSE_ARGS[@]}" \
      down -v --remove-orphans --timeout 20 >"$LOG_DIR/cleanup-pg.log" 2>&1; then
      printf 'CLEANUP WARN: PG compose 项目 down 失败（详见日志）\n' >&2
    fi
  fi

  remove_project_resources "$PROJECT_SQLITE"
  remove_project_resources "$PROJECT_PG"

  # 注意：只清理带本项目 label 的资源；不执行 docker system prune。
  for i in "$PROJECT_SQLITE" "$PROJECT_PG"; do
    if [[ "$(leftover_count "$i")" != "0" ]]; then
      printf 'CLEANUP FAIL: 项目 %s 仍有容器/volume/network 残留\n' "$i" >&2
      FAILS=$((FAILS + 1))
    fi
  done

  cleanup_secrets || true

  printf 'INFO: 证据目录已保留: %s\n' "$RUN_DIR" >&2

  if (( FAILS > 0 )); then
    code=1
  fi
  FINAL_CODE=$code
  print_summary
  exit "$code"
}

# ---------------------------------------------------------------------------
# 通用判断
# ---------------------------------------------------------------------------

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [[ "$expected" == "$actual" ]]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$expected]，实际 [$actual]）"
  fi
}

check_health() {
  local id=$1 desc=$2 ct=$3 timeout=${4:-$HEALTH_TIMEOUT}
  if wait_healthy "$ct" "$timeout"; then
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

wait_stopped() {
  local ct=$1 timeout=${2:-60}
  local deadline running
  deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    running=$(docker inspect -f '{{.State.Running}}' "$ct" 2>/dev/null || true)
    if [[ "$running" == "false" ]]; then
      return 0
    fi
    sleep 1
  done
  return 1
}

fetch_healthz() {
  local ct=$1 out=$2
  docker exec "$ct" curl -fsS --noproxy '*' --max-time 5 \
    http://127.0.0.1:8444/healthz >"$out" 2>"$LOG_DIR/healthz.err"
}

check_healthz_body() {
  local id=$1 desc=$2 ct=$3 body
  if fetch_healthz "$ct" "$LOG_DIR/healthz.body"; then
    body=$(tr -d '\r\n' <"$LOG_DIR/healthz.body" 2>/dev/null || true)
    if [[ "$body" == "ok" ]]; then
      pass "$id" "$desc"
      return 0
    fi
    fail "$id" "$desc（HTTP 200 但 body 不是 ok）"
    return 1
  fi
  fail "$id" "$desc（管理口 /healthz 非 200）"
  dump_container_logs "$ct" 40
  return 1
}

# 通过容器内 /run/rustboard/admin_token 调用管理 API；token 不进宿主 argv、
# 不打印，响应只落 secret 目录供 Python 提取计数/状态。
exec_http_code() {
  local ct=$1 url=$2 code
  code=$(docker exec "$ct" curl -sS --noproxy '*' --max-time 5 -o /dev/null     -w '%{http_code}' "$url" 2>/dev/null) || code="000"
  printf '%s' "${code:-000}"
}

wait_exec_http_200() {
  local ct=$1 url=$2 timeout=${3:-60} deadline code
  deadline=$((SECONDS + timeout))
  LAST_CODE="000"
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

fetch_agents_api() {
  local ct=$1 out=$2
  docker exec "$ct" sh -c '
    set -e
    token=$(cat /run/rustboard/admin_token)
    exec curl -fsS --noproxy "*" --max-time 15 \
      -H "Authorization: Bearer $token" \
      -H "Accept: application/json" \
      http://127.0.0.1:8444/api/v1/agents
  ' >"$out" 2>"$LOG_DIR/agents-api.err"
}

agents_summary() {
  local file=$1 name=$2
  "$PYTHON" "$HELPER" agents-check "$file" "$name" 2>/dev/null || true
}

# 等待管理 API 出现指定 agent 且 status=online。
wait_agent_online() {
  local ct=$1 name=$2 timeout=${3:-$AGENT_TIMEOUT}
  local deadline summary
  deadline=$((SECONDS + timeout))
  LAST_AGENT_SUMMARY=""
  while (( SECONDS < deadline )); do
    if fetch_agents_api "$ct" "$SECRETS/agents.json" 2>/dev/null; then
      summary=$(agents_summary "$SECRETS/agents.json" "$name")
      LAST_AGENT_SUMMARY="$summary"
      if [[ "$summary" == *"found=1"* && "$summary" == *"status=online"* ]]; then
        return 0
      fi
    fi
    sleep 2
  done
  return 1
}

stat_mode_owner() {
  local ct=$1 path=$2
  docker exec "$ct" stat -c '%a %u' "$path" 2>/dev/null || true
}

mount_name() {
  local ct=$1 dest=$2
  docker inspect -f "{{range .Mounts}}{{if eq .Destination \"$dest\"}}{{.Name}}{{end}}{{end}}" "$ct" 2>/dev/null || true
}

hub_artifacts_hash() {
  local ct=$1
  docker exec "$ct" sh -c \
    'sha256sum /data/etc/rustboard/hub.toml /run/rustboard/admin_token' \
    2>/dev/null | awk '{ print $1 }' | paste -sd, -
}

container_network() {
  local ct=$1
  docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' "$ct" 2>/dev/null \
    | awk 'NF { print; exit }' || true
}

compose_ct() {
  local project=$1 service=$2
  docker compose -p "$project" -f docker/compose.example.yml ps -q "$service" 2>/dev/null || true
}

compose_pg_ct() {
  local service=$1
  docker compose -p "$PROJECT_PG" "${PG_COMPOSE_ARGS[@]}" ps -q "$service" 2>/dev/null || true
}

# 在 hub 容器内临时从 0600 secret 读取 PG 密码并导出为环境变量，再执行
# rustboard-hub CLI。密码不进宿主 argv、不打印。
hub_exec_pg() {
  docker exec "$PG_HUB_CT" sh -c '
    set -e
    if [ -r /run/secrets/rustboard_pg_password ]; then
      RUSTBOARD_DATABASE_PASSWORD=$(cat /run/secrets/rustboard_pg_password)
      export RUSTBOARD_DATABASE_PASSWORD
    fi
    exec "$@"
  ' sh "$@"
}

# PG 计数统一走 postgres 容器内的 psql（local socket trust），不传密码、
# 不需要 hub 镜像包含客户端。
pg_count_db() {
  local db=$1 table=$2
  case "$table" in
    agents|samples|ingest_batches|schema_migrations) ;;
    *)
      printf 'FATAL: 不允许的表名: %s\n' "$table" >&2
      return 2
      ;;
  esac
  docker exec -u postgres "$PG_CT" psql -X -q -A -t -U rustboard -d "$db" \
    -c "SELECT count(*) FROM ${table}" 2>>"$LOG_DIR/pg-count.err"
}

pg_count() {
  pg_count_db rustboard "$1"
}

# 单值 SQL 查询。调用方只能传内部生成、且参数已严格校验的 SQL；这里不接收
# 外部输入，避免把管理 API 的任意字符串拼进 SQL。
pg_scalar() {
  docker exec -u postgres "$PG_CT" psql -X -q -A -t -U rustboard -d rustboard \
    -c "$1" 2>>"$LOG_DIR/pg-count.err"
}

# agent_id 由 hub 用 UUID 生成；断言只接受该格式，既防 SQL 注入又避免把
# 名字/主机名误当成 ID。
is_agent_uuid() {
  [[ "$1" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
}

# 按唯一 agent_id 统计三张核心表；hub-self 的自采样不会计入。
pg_agent_count() {
  local table=$1 agent_id=$2
  case "$table" in
    agents|samples|ingest_batches) ;;
    *)
      printf 'FATAL: 不允许按 agent 统计的表名: %s\n' "$table" >&2
      return 2
      ;;
  esac
  is_agent_uuid "$agent_id" || {
    printf 'FATAL: agent_id 不是 UUID: %s\n' "$agent_id" >&2
    return 2
  }
  pg_scalar "SELECT count(*) FROM ${table} WHERE agent_id = '${agent_id}'"
}

# agent 启动之后新落库的批次（ingest_batches.ts 是 hub 接收时间）。
pg_agent_new_batches_since() {
  local agent_id=$1 since_ms=$2
  is_agent_uuid "$agent_id" || return 2
  [[ "$since_ms" =~ ^[0-9]+$ ]] || return 2
  pg_scalar "SELECT count(*) FROM ingest_batches WHERE agent_id = '${agent_id}' AND ts >= ${since_ms}"
}

# 真实 agent 必须上报这些预期指标；只按 agent_id 计数以排除 hub-self。
pg_agent_expected_metrics() {
  local agent_id=$1
  is_agent_uuid "$agent_id" || return 2
  pg_scalar "SELECT count(DISTINCT metric) FROM samples WHERE agent_id = '${agent_id}' AND metric IN ('cpu.usage','mem.used','sys.uptime')"
}

# ---------------------------------------------------------------------------
# 前置检查与镜像构建
# ---------------------------------------------------------------------------

preflight() {
  local cargo_version base_ref base_tag version_out

  need_cmd docker
  need_cmd curl
  need_cmd "$PYTHON"
  need_cmd git
  need_cmd timeout
  need_cmd stat
  need_cmd install
  need_cmd xargs
  need_cmd awk
  need_cmd sed
  need_cmd sha256sum
  need_cmd paste

  docker info >/dev/null 2>&1 || die "docker daemon 不可用（当前用户需能访问 Docker）"
  if docker compose version >/dev/null 2>&1; then
    HAVE_COMPOSE=1
    info "docker compose 插件可用"
  else
    die "缺少 docker compose 插件（本脚本的默认/PG overlay 用例必须用 compose）"
  fi
  if docker buildx version >/dev/null 2>&1; then
    HAVE_BUILDX=1
    info "docker buildx 可用"
  else
    HAVE_BUILDX=0
    info "docker buildx 不可用，回退 docker build"
  fi

  [[ -f docker/Dockerfile ]] || die "缺少 docker/Dockerfile"
  [[ -f docker/compose.example.yml ]] || die "缺少 docker/compose.example.yml"
  [[ -f docker/compose.postgres.example.yml ]] || die "缺少 docker/compose.postgres.example.yml"

  cargo_version=$(awk -F'"' '/^version[[:space:]]*=/ { print $2; exit }' Cargo.toml 2>/dev/null || true)
  if [[ ! "$cargo_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
    die "无法从 Cargo.toml 解析 workspace version（得到 [${cargo_version:-empty}]）"
  fi
  VERSION="$cargo_version"
  if [[ "$VERSION" != "$EXPECTED_VERSION" ]]; then
    die "当前源码版本 $VERSION 与 EXPECTED_VERSION=$EXPECTED_VERSION 不一致；请确认 dist 已重建，或用 EXPECTED_VERSION 覆盖"
  fi
  REVISION=$(git rev-parse HEAD 2>/dev/null || true)
  if [[ ! "$REVISION" =~ ^[0-9a-f]{40}$ ]]; then
    die "无法解析 git HEAD revision（得到 [${REVISION:-empty}]）"
  fi
  info "VERSION=$VERSION REVISION=$REVISION 平台=$PLATFORM 镜像 tag=$IMAGE_VERSION"

  for role in hub panel agent; do
    [[ -f "$DIST_BIN/rustboard-$role" && ! -L "$DIST_BIN/rustboard-$role" && -x "$DIST_BIN/rustboard-$role" ]] \
      || die "$DIST_BIN/rustboard-$role 不存在、不是普通文件或不可执行；请先运行 packaging/build-release.sh --arch amd64"
  done
  [[ -s web/dist/index.html && ! -L web/dist/index.html ]] \
    || die "web/dist/index.html 不存在、为空或不是普通文件；请先构建前端并运行 packaging/build-release.sh --arch amd64"

  if ! version_out=$("$DIST_BIN/rustboard-hub" --version 2>"$LOG_DIR/source-hub-version.err"); then
    die "dist hub 二进制 --version 执行失败"
  fi
  if ! printf '%s\n' "$version_out" | grep -Fq "$EXPECTED_VERSION"; then
    die "dist hub 二进制 --version 不含 $EXPECTED_VERSION（dist 与当前源码不一致）"
  fi
  pass "S.0" "dist/amd64 三个二进制与 web/dist 存在，hub --version 含 $EXPECTED_VERSION"

  # 来源绑定：版本号 + revision 只能排除“完全不同的版本”，不能排除同名旧
  # rc.2 dist。因此必须把当前 dist 的 sha256 与外部 manifest 强匹配。
  DIST_HUB_SHA=$(sha256sum -- "$DIST_BIN/rustboard-hub" | awk '{ print $1 }')
  DIST_PANEL_SHA=$(sha256sum -- "$DIST_BIN/rustboard-panel" | awk '{ print $1 }')
  DIST_AGENT_SHA=$(sha256sum -- "$DIST_BIN/rustboard-agent" | awk '{ print $1 }')
  DIST_WEB_SHA=$(sha256sum -- web/dist/index.html | awk '{ print $1 }')
  for _sha in "$DIST_HUB_SHA" "$DIST_PANEL_SHA" "$DIST_AGENT_SHA" "$DIST_WEB_SHA"; do
    [[ "$_sha" =~ ^[0-9a-f]{64}$ ]] || die "无法计算 dist sha256（得到 [${_sha:-empty}]）"
  done
  info "dist sha256: hub=$DIST_HUB_SHA panel=$DIST_PANEL_SHA agent=$DIST_AGENT_SHA web=$DIST_WEB_SHA"

  local manifest_source="" expected_hub="" expected_panel="" expected_agent="" expected_web=""
  if [[ -n "$DIST_MANIFEST" ]]; then
    [[ -f "$DIST_MANIFEST" && ! -L "$DIST_MANIFEST" ]] \
      || die "--dist-manifest 不是普通文件或为符号链接: $DIST_MANIFEST"
    if ! "$PYTHON" "$HELPER" dist-manifest "$DIST_MANIFEST" \
      >"$LOG_DIR/dist-manifest.expected" 2>"$LOG_DIR/dist-manifest.err"; then
      die "--dist-manifest 格式非法（需要 hub/panel/agent/web 各一个 64hex）"
    fi
    manifest_source=$DIST_MANIFEST
  else
    if ! printf '%s\n' "$EXPECTED_DIST_SHA256" \
      | "$PYTHON" "$HELPER" dist-manifest - \
        >"$LOG_DIR/dist-manifest.expected" 2>"$LOG_DIR/dist-manifest.err"; then
      die "EXPECTED_DIST_SHA256 格式非法（需要 hub/panel/agent/web 各一个 64hex）"
    fi
    manifest_source="EXPECTED_DIST_SHA256"
  fi
  expected_hub=$(sed -n 's/^hub=//p' "$LOG_DIR/dist-manifest.expected" | head -n 1)
  expected_panel=$(sed -n 's/^panel=//p' "$LOG_DIR/dist-manifest.expected" | head -n 1)
  expected_agent=$(sed -n 's/^agent=//p' "$LOG_DIR/dist-manifest.expected" | head -n 1)
  expected_web=$(sed -n 's/^web=//p' "$LOG_DIR/dist-manifest.expected" | head -n 1)
  if [[ "$expected_hub" != "$DIST_HUB_SHA" || "$expected_panel" != "$DIST_PANEL_SHA" \
    || "$expected_agent" != "$DIST_AGENT_SHA" || "$expected_web" != "$DIST_WEB_SHA" ]]; then
    die "当前 dist 与来源绑定 manifest 不一致，拒绝用旧 dist 构建镜像（expected/actual: hub=$expected_hub/$DIST_HUB_SHA panel=$expected_panel/$DIST_PANEL_SHA agent=$expected_agent/$DIST_AGENT_SHA web=$expected_web/$DIST_WEB_SHA）"
  fi
  {
    printf 'version=%s\n' "$VERSION"
    printf 'revision=%s\n' "$REVISION"
    printf 'dist_manifest_source=%s\n' "$manifest_source"
    printf 'dist_hub_sha256=%s\n' "$DIST_HUB_SHA"
    printf 'dist_panel_sha256=%s\n' "$DIST_PANEL_SHA"
    printf 'dist_agent_sha256=%s\n' "$DIST_AGENT_SHA"
    printf 'dist_web_index_sha256=%s\n' "$DIST_WEB_SHA"
  } >"$PROVENANCE_FILE"
  chmod 0600 "$PROVENANCE_FILE" 2>/dev/null || true
  pass "S.1" "dist sha256 与来源绑定 manifest 强匹配（${manifest_source}，HEAD=$REVISION）"

  base_ref=$(awk '/^FROM[[:space:]]/ { print $2; exit }' docker/Dockerfile)
  base_tag=${base_ref%%@*}
  if ! docker image inspect "$base_ref" >/dev/null 2>&1; then
    if ! docker image inspect "$base_tag" >/dev/null 2>&1; then
      die "本地缺少 Dockerfile 基础镜像 $base_ref（或 $base_tag）；本脚本不联网拉取，请先准备镜像"
    fi
  fi
  info "Dockerfile 基础镜像已在本地: ${base_ref}"

  if docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    PG_IMAGE=postgres:16-alpine
  elif docker image inspect postgres:16 >/dev/null 2>&1; then
    PG_IMAGE=postgres:16
    PG_COMPOSE_SUBSTITUTED=1
  else
    die "本机缺少 postgres:16-alpine 与 postgres:16；PG overlay 用例不联网拉取，明确失败"
  fi
  info "PG overlay 服务端镜像: $PG_IMAGE（不联网拉取）"
  if (( PG_COMPOSE_SUBSTITUTED )); then
    cat >"$SECRETS/compose.postgres.local.yml" <<EOF
services:
  postgres:
    image: ${PG_IMAGE}
EOF
    PG_COMPOSE_ARGS+=(-f "$SECRETS/compose.postgres.local.yml")
    info "本地无 postgres:16-alpine，使用临时 compose override 把 postgres image 固定为本地 postgres:16"
  fi

  if docker image inspect postgres:16 >/dev/null 2>&1; then
    PG_CLIENT_IMAGE=postgres:16
  elif docker image inspect postgres:16-alpine >/dev/null 2>&1; then
    PG_CLIENT_IMAGE=postgres:16-alpine
  else
    die "本地缺少 postgres:16/postgres:16-alpine：PG 备份/恢复必须用 compose 内网 client 容器；不联网拉取"
  fi
  info "PG 备份/恢复 client 容器镜像: $PG_CLIENT_IMAGE（PGPASSWORD 只走 0600 --env-file）"

  if ! "$PYTHON" "$HELPER" ports-free 8443 8080 >"$LOG_DIR/ports.log" 2>"$LOG_DIR/ports.err"; then
    cat "$LOG_DIR/ports.err" >&2 || true
    die "宿主 8443/8080 被占用；本脚本不停止无关容器，请释放后重跑"
  fi
  pass "P.1" "依赖命令、Docker daemon、compose 与本地镜像前置通过"
  pass "P.2" "宿主 8443/8080 空闲"

  # 一次性 secret：PG 密码只写 0600；默认 compose 不使用它。
  printf '%s' "$( "$PYTHON" -c 'import secrets; print(secrets.token_urlsafe(32), end="")' )" >"$PG_PW_FILE"
  chmod 0600 "$PG_PW_FILE"
  if [[ ! -s "$PG_PW_FILE" || "$(stat -c '%a' "$PG_PW_FILE")" != "600" ]]; then
    die "创建 0600 PG 密码文件失败"
  fi
  printf 'PGHOST=postgres\nPGPORT=5432\nPGUSER=rustboard\nPGDATABASE=rustboard\nPGSSLMODE=disable\nPGPASSWORD=%s\n' \
    "$(cat "$PG_PW_FILE")" >"$PG_ENV_FILE"
  chmod 0600 "$PG_ENV_FILE"
  export RUSTBOARD_PG_PASSWORD_FILE="$PG_PW_FILE"
  pass "P.3" "PG 密码只写入 0600 secret/env-file，未进入命令行参数"
}

build_one() {
  local role=$1
  local image=$2
  local log="$LOG_DIR/build-$role.log"
  if (( HAVE_BUILDX == 1 )); then
    docker buildx build --load --platform "$PLATFORM" --progress=plain --pull=false \
      -f docker/Dockerfile --target "$role" \
      --build-arg "VERSION=$VERSION" \
      --build-arg "REVISION=$REVISION" \
      -t "$image" . >"$log" 2>&1
  else
    docker build --platform "$PLATFORM" --pull=false \
      -f docker/Dockerfile --target "$role" \
      --build-arg "TARGETARCH=$DOCKER_ARCH" \
      --build-arg "VERSION=$VERSION" \
      --build-arg "REVISION=$REVISION" \
      -t "$image" . >"$log" 2>&1
  fi
}

build_images() {
  local role image failed=0 arch
  for role in hub panel agent; do
    case "$role" in
      hub) image=$HUB_IMAGE ;;
      panel) image=$PANEL_IMAGE ;;
      agent) image=$AGENT_IMAGE ;;
      *) die "未知角色: $role" ;;
    esac
    if build_one "$role" "$image"; then
      pass "B.$role" "构建 $image（$PLATFORM，VERSION=$VERSION）"
    else
      fail "B.$role" "构建 $image 失败（日志尾部见下）"
      dump_file "$LOG_DIR/build-$role.log" 100
      failed=1
    fi
  done
  if (( failed )); then
    return 1
  fi

  for role in hub panel agent; do
    case "$role" in
      hub) image=$HUB_IMAGE ;;
      panel) image=$PANEL_IMAGE ;;
      agent) image=$AGENT_IMAGE ;;
    esac
    arch=$(docker image inspect -f '{{.Os}}/{{.Architecture}}' "$image" 2>/dev/null || true)
    check_eq "B.$role.arch" "镜像 $role 架构为 $PLATFORM" "$PLATFORM" "$arch"
  done
  return 0
}

record_image_ids() {
  local role image id failed=0
  for role in hub panel agent; do
    case "$role" in
      hub) image=$HUB_IMAGE ;;
      panel) image=$PANEL_IMAGE ;;
      agent) image=$AGENT_IMAGE ;;
    esac
    if ! id=$(docker image inspect -f '{{.Id}}' "$image" 2>/dev/null); then
      fail "B.$role.id" "无法读取镜像 ID: $image"
      failed=1
      continue
    fi
    if [[ ! "$id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      fail "B.$role.id" "镜像 ID 格式异常: $image"
      failed=1
      continue
    fi
    printf 'image_%s_id=%s\n' "$role" "$id" >>"$PROVENANCE_FILE"
    info "image $role id=$id"
  done
  if (( failed )); then
    return 1
  fi
  pass "B.ids" "记录三个本地镜像 ID 到证据 provenance"
  return 0
}

image_checks() {
  local out version_label revision_label
  version_label=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$HUB_IMAGE" 2>/dev/null || true)
  revision_label=$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$HUB_IMAGE" 2>/dev/null || true)
  check_eq "I.1" "hub 镜像 version label 为 $EXPECTED_VERSION" "$EXPECTED_VERSION" "$version_label"
  check_eq "I.2" "hub 镜像 revision label 为当前 HEAD" "$REVISION" "$revision_label"

  if ! out=$(docker run --rm --network none --entrypoint /bin/sh "$HUB_IMAGE" -c \
    'rustboard-hub --version' 2>"$LOG_DIR/hub-version.err"); then
    fail "I.3" "hub 镜像内 rustboard-hub --version 执行失败"
    dump_file "$LOG_DIR/hub-version.err" 30
  elif printf '%s\n' "$out" | grep -Fq "$EXPECTED_VERSION"; then
    pass "I.3" "hub 镜像内 rustboard-hub --version 为 $EXPECTED_VERSION（当前源码）"
  else
    fail "I.3" "hub 镜像内 rustboard-hub --version 不含 $EXPECTED_VERSION（刷新了旧镜像？）"
  fi

  if ! out=$(docker run --rm --network none --entrypoint /bin/sh "$HUB_IMAGE" -c \
    'for c in pg_dump pg_restore psql; do if command -v "$c" >/dev/null 2>&1; then echo "$c"; fi; done' \
    2>"$LOG_DIR/hub-pg-tools.err"); then
    fail "I.4" "无法检查 hub 镜像内 PostgreSQL client"
  elif [[ -z "$out" ]]; then
    pass "I.4" "hub 镜像内没有 pg_dump/pg_restore/psql（备份必须用外部 client）"
  else
    fail "I.4" "hub 镜像内出现 PostgreSQL client: $(printf '%s' "$out" | tr '\n' ' ')"
  fi

  if ! out=$(docker run --rm --network none --entrypoint /bin/sh "$PANEL_IMAGE" -c \
    'rustboard-panel --version' 2>"$LOG_DIR/panel-version.err"); then
    fail "I.5" "panel 镜像内 rustboard-panel --version 执行失败"
  elif printf '%s\n' "$out" | grep -Fq "$EXPECTED_VERSION"; then
    pass "I.5" "panel 镜像内 rustboard-panel --version 为 $EXPECTED_VERSION"
  else
    fail "I.5" "panel 镜像内 rustboard-panel --version 不含 $EXPECTED_VERSION"
  fi

  if ! out=$(docker run --rm --network none --entrypoint /bin/sh "$AGENT_IMAGE" -c \
    'rustboard-agent --version' 2>"$LOG_DIR/agent-version.err"); then
    fail "I.6" "agent 镜像内 rustboard-agent --version 执行失败"
  elif printf '%s\n' "$out" | grep -Fq "$EXPECTED_VERSION"; then
    pass "I.6" "agent 镜像内 rustboard-agent --version 为 $EXPECTED_VERSION"
  else
    fail "I.6" "agent 镜像内 rustboard-agent --version 不含 $EXPECTED_VERSION"
  fi
}

# ---------------------------------------------------------------------------
# 默认 SQLite compose
# ---------------------------------------------------------------------------

compose_sqlite() {
  docker compose -p "$PROJECT_SQLITE" -f docker/compose.example.yml "$@"
}

compose_fact() {
  local file=$1 key=$2
  sed -n "s/^${key}=//p" "$file" | head -n 1
}

write_compose_facts() {
  local json=$1 facts=$2 err=$3
  "$PYTHON" "$HELPER" compose-facts "$json" >"$facts" 2>"$err"
}

copy_sqlite_db() {
  local ct=$1 dest_dir=$2 db_path=/data/var/lib/rustboard/hub/rustboard.db
  local sidecar
  mkdir -p "$dest_dir" || return 1
  chmod 0700 "$dest_dir"
  docker cp "$ct:$db_path" "$dest_dir/rustboard.db" >"$LOG_DIR/sqlite-cp.log" 2>&1 || return 1
  for sidecar in -wal -shm; do
    if docker cp "$ct:$db_path$sidecar" "$dest_dir/rustboard.db$sidecar" \
      >>"$LOG_DIR/sqlite-cp.log" 2>&1; then
      :
    fi
  done
  chmod 0600 "$dest_dir"/rustboard.db* 2>/dev/null || true
  return 0
}

default_sqlite_checks() {
  local down_ok=0
  local cfg="$LOG_DIR/compose-sqlite.json"
  local facts="$LOG_DIR/compose-sqlite.facts"
  local up_log="$LOG_DIR/compose-sqlite-up.log"
  local body_db_out=""

  if ! compose_sqlite config --format json >"$cfg" 2>"$LOG_DIR/compose-sqlite.err"; then
    fail "C.1" "默认 compose config 语法检查失败"
    dump_file "$LOG_DIR/compose-sqlite.err" 60
    return 1
  fi
  if ! write_compose_facts "$cfg" "$facts" "$LOG_DIR/compose-facts-sqlite.err"; then
    fail "C.1" "默认 compose 结构提取失败"
    dump_file "$LOG_DIR/compose-facts-sqlite.err" 60
    return 1
  fi

  check_eq "C.2" "默认 compose 仅 hub/panel（无 postgres service）" "hub,panel" "$(compose_fact "$facts" services)"
  check_eq "C.3" "默认 compose 无 postgres/5432/8444 发布或 target" "0/0/0/0" \
    "$(compose_fact "$facts" postgres_present)/$(compose_fact "$facts" published_5432)/$(compose_fact "$facts" published_8444)/$(compose_fact "$facts" target_5432)"
  check_eq "C.4" "默认 compose 只发布 8443/8080（8080 在 compose 回环）" "8080,8443" \
    "$(compose_fact "$facts" all_published_ports)"
  check_eq "C.4a" "默认 hub 发布 8443 与回环 8080，panel 没有自己的 ports" "8080,8443/" \
    "$(compose_fact "$facts" hub_published)/$(compose_fact "$facts" panel_published)"
  check_eq "C.4b" "默认 compose 的 8080 发布项均显式回环 127.0.0.1/::1" "0/1" \
    "$(compose_fact "$facts" published_8080_nonloopback)/$(compose_fact "$facts" published_8080_loopback)"
  check_eq "C.5" "默认 compose 的 hub 不注入 RUSTBOARD_DATABASE/SSLROOTCERT" "0/0" \
    "$(compose_fact "$facts" hub_database_env)/$(compose_fact "$facts" hub_sslrootcert_env)"
  check_eq "C.6" "默认 compose 使用当前源码镜像 $HUB_IMAGE" "$HUB_IMAGE" \
    "$(compose_fact "$facts" hub_image)"

  if ! compose_sqlite up -d --pull never --wait --wait-timeout "$HEALTH_TIMEOUT" \
    >"$up_log" 2>&1; then
    fail "D.1" "默认 compose 启动/等待 healthcheck 失败"
    dump_file "$up_log" 100
    return 1
  fi
  pass "D.1" "默认 compose hub+panel 启动并全部 healthy"

  SQLITE_HUB_CT=$(compose_ct "$PROJECT_SQLITE" hub)
  SQLITE_PANEL_CT=$(compose_ct "$PROJECT_SQLITE" panel)
  if [[ -z "$SQLITE_HUB_CT" || -z "$SQLITE_PANEL_CT" ]]; then
    fail "D.2" "无法解析默认 compose 的 hub/panel 容器 ID"
    compose_sqlite down -v --remove-orphans --timeout 20 >"$LOG_DIR/sqlite-down.log" 2>&1 || true
    return 1
  fi

  check_health "D.2" "默认 hub healthcheck healthy" "$SQLITE_HUB_CT" || true
  check_health "D.3" "默认 panel healthcheck healthy" "$SQLITE_PANEL_CT" || true
  check_healthz_body "D.4" "默认 hub 管理口 /healthz 返回 ok" "$SQLITE_HUB_CT" || true

  if body=$(curl --noproxy '*' -fsS --max-time 5 http://127.0.0.1:8080/healthz 2>"$LOG_DIR/sqlite-panel-healthz.err"); then
    if [[ "$(printf '%s' "$body" | tr -d '\r\n')" == "ok" ]]; then
      pass "D.5" "默认 panel 宿主回环 8080 /healthz 返回 ok"
    else
      fail "D.5" "默认 panel /healthz HTTP 200 但 body 不是 ok"
    fi
  else
    fail "D.5" "默认 panel 宿主回环 8080 /healthz 非 200"
  fi

  # self_monitor 默认开启时 hub 会注册内置 hub-self；初始列表允许 0 条或
  # 恰好 1 条 hub-self（name 或 agent_id 命中），不能要求空数组。
  if fetch_agents_api "$SQLITE_HUB_CT" "$SECRETS/sqlite-agents.json"; then
    body_db_out=$(agents_summary "$SECRETS/sqlite-agents.json" "hub-self")
    if [[ "$body_db_out" == *"count=0"* ]] \
      || [[ "$body_db_out" == *"count=1"* && "$body_db_out" == *"found=1"* ]]; then
      pass "D.6" "默认 SQLite hub agents 允许为空或仅内置 hub-self（$body_db_out）"
    else
      fail "D.6" "默认 SQLite hub agents 出现 hub-self 之外的记录（$body_db_out）"
    fi
  else
    fail "D.6" "默认 SQLite hub 管理 API /api/v1/agents 调用失败"
  fi

  if ! docker exec "$SQLITE_HUB_CT" sh -c \
    'grep -E "^(database|db_sslrootcert)[[:space:]]*=" /data/etc/rustboard/hub.toml' \
    >"$LOG_DIR/sqlite-config-keys.txt" 2>"$LOG_DIR/sqlite-config.err"; then
    fail "D.7" "无法读取默认 hub 的 database 配置"
    dump_file "$LOG_DIR/sqlite-config.err" 30
  elif grep -qE '^database[[:space:]]*=[[:space:]]*"sqlite:///data/var/lib/rustboard/hub/rustboard\.db"' \
    "$LOG_DIR/sqlite-config-keys.txt" \
    && ! grep -qE '^db_sslrootcert[[:space:]]*=' "$LOG_DIR/sqlite-config-keys.txt" \
    && ! grep -q 'postgres://' "$LOG_DIR/sqlite-config-keys.txt"; then
    pass "D.7" "默认 hub 配置为 sqlite:///data/var/lib/rustboard/hub/rustboard.db，且无 db_sslrootcert"
  else
    fail "D.7" "默认 hub 配置不是预期 SQLite（未打印配置内容）"
  fi

  body_db_out=$(stat_mode_owner "$SQLITE_HUB_CT" /run/rustboard/admin_token)
  check_eq "D.8" "默认 hub 共享 admin_token 为 0600 且属主 10001" "600 10001" "$body_db_out"

  SQLITE_HUB_VOLUME=$(mount_name "$SQLITE_HUB_CT" /data)
  SQLITE_NETWORK=$(container_network "$SQLITE_HUB_CT")
  SQLITE_VOLUME_NAMES=$(project_volume_names "$PROJECT_SQLITE" | sort)
  if [[ -n "$SQLITE_HUB_VOLUME" && -n "$SQLITE_NETWORK" ]]; then
    pass "D.9" "默认 hub 的 /data 来自 volume $SQLITE_HUB_VOLUME，network=$SQLITE_NETWORK"
  else
    fail "D.9" "默认 hub 的 /data volume 或 network 解析失败"
  fi

  # 默认 compose 重启 hub：先停 panel，避免 service:hub 共享 netns 在 hub
  # 重启时悬空；随后断言 hub.toml 与 admin_token 哈希不变。
  local sqlite_hash_before="" sqlite_hash_after=""
  if ! sqlite_hash_before=$(hub_artifacts_hash "$SQLITE_HUB_CT"); then
    fail "D.10" "重启前无法读取默认 hub 配置/admin_token 哈希"
  else
    compose_sqlite stop panel >"$LOG_DIR/sqlite-restart-stop-panel.log" 2>&1 || true
    if ! compose_sqlite restart hub >"$LOG_DIR/sqlite-restart.log" 2>&1; then
      fail "D.10" "默认 compose restart hub 失败"
      dump_file "$LOG_DIR/sqlite-restart.log" 60
    elif ! check_health "D.10" "默认 hub restart 后 healthcheck healthy" "$SQLITE_HUB_CT"; then
      info "D.10 healthcheck 失败已由 check_health 计数"
    elif ! sqlite_hash_after=$(hub_artifacts_hash "$SQLITE_HUB_CT"); then
      fail "D.10" "重启后无法读取默认 hub 配置/admin_token 哈希"
    elif [[ -n "$sqlite_hash_before" && "$sqlite_hash_after" == "$sqlite_hash_before" ]]; then
      pass "D.10" "默认 compose restart hub 后 hub.toml 与 admin_token 哈希不变"
    else
      fail "D.10" "默认 compose restart hub 后配置/admin_token 哈希变化"
    fi
  fi

  # 停 hub/panel 后复制 SQLite 文件，避免运行中复制造成半写状态；之后 down -v。
  if ! compose_sqlite stop panel hub >"$LOG_DIR/sqlite-stop.log" 2>&1; then
    fail "D.11" "默认 compose 停止 hub/panel 失败"
    dump_file "$LOG_DIR/sqlite-stop.log" 40
  elif ! wait_stopped "$SQLITE_HUB_CT" 30; then
    fail "D.11" "默认 hub 未在 30s 内停止"
  else
    pass "D.11" "默认 compose 已干净停止 hub/panel"
  fi

  if copy_sqlite_db "$SQLITE_HUB_CT" "$SQLITE_COPY_DIR"; then
    if body_db_out=$("$PYTHON" "$HELPER" sqlite-check "$SQLITE_COPY_DIR/rustboard.db" 2>"$LOG_DIR/sqlite-check.err"); then
      pass "D.12" "默认 hub_data volume 内 rustboard.db 有 schema/数据（$body_db_out）"
    else
      fail "D.12" "默认 hub_data volume 内 rustboard.db 校验失败"
      dump_file "$LOG_DIR/sqlite-check.err" 40
    fi
  else
    fail "D.12" "无法从默认 hub 容器复制 rustboard.db（检查 volume 内文件）"
    dump_file "$LOG_DIR/sqlite-cp.log" 40
  fi

  if ! compose_sqlite down -v --remove-orphans --timeout 20 >"$LOG_DIR/sqlite-down.log" 2>&1; then
    fail "D.13" "默认 compose down -v 失败"
    dump_file "$LOG_DIR/sqlite-down.log" 60
  elif [[ "$(leftover_count "$PROJECT_SQLITE")" != "0" ]]; then
    fail "D.13" "默认 compose 项目仍有资源残留"
  else
    down_ok=1
    pass "D.13" "默认 compose down -v 只清理本项目，资源无残留"
  fi

  # 个别断言失败不应阻止独立的 PG overlay 用例；只有 down 失败（端口可能
  # 仍被占用）才停止后续。
  if (( down_ok )); then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# PostgreSQL overlay
# ---------------------------------------------------------------------------

compose_pg() {
  docker compose -p "$PROJECT_PG" "${PG_COMPOSE_ARGS[@]}" "$@"
}

pg_overlay_config_checks() {
  local before=$FAILS
  local cfg="$LOG_DIR/compose-pg.json"
  local facts="$LOG_DIR/compose-pg.facts"
  if ! compose_pg config --format json >"$cfg" 2>"$LOG_DIR/compose-pg.err"; then
    fail "C.7" "PG overlay compose config 语法检查失败"
    dump_file "$LOG_DIR/compose-pg.err" 60
    return 1
  fi
  if ! write_compose_facts "$cfg" "$facts" "$LOG_DIR/compose-facts-pg.err"; then
    fail "C.7" "PG overlay 结构提取失败"
    dump_file "$LOG_DIR/compose-facts-pg.err" 60
    return 1
  fi

  check_eq "C.8" "PG overlay 包含 hub/panel/postgres" "hub,panel,postgres" "$(compose_fact "$facts" services)"
  check_eq "C.9" "PG overlay 的 postgres image 为本地已有镜像" "$PG_IMAGE" \
    "$(compose_fact "$facts" postgres_image)"
  check_eq "C.10" "PG overlay 不发布 5432/8444，postgres 无 ports" "0/0/0" \
    "$(compose_fact "$facts" published_5432)/$(compose_fact "$facts" published_8444)/$(compose_fact "$facts" postgres_ports_count)"
  check_eq "C.10a" "PG overlay 仍只发布 8443/回环 8080" "8080,8443" \
    "$(compose_fact "$facts" all_published_ports)"
  check_eq "C.10b" "PG overlay 的 8080 发布项均显式回环 127.0.0.1/::1" "0/1" \
    "$(compose_fact "$facts" published_8080_nonloopback)/$(compose_fact "$facts" published_8080_loopback)"
  check_eq "C.11" "PG overlay 的 hub 使用 postgres:// 且不带密码" "postgres/postgres/5432//rustboard/disable/0" \
    "$(compose_fact "$facts" hub_db_scheme)/$(compose_fact "$facts" hub_db_host)/$(compose_fact "$facts" hub_db_port)/$(compose_fact "$facts" hub_db_path)/$(compose_fact "$facts" hub_db_sslmode)/$(compose_fact "$facts" hub_db_has_password)"
  check_eq "C.12" "PG overlay 通过 PASSWORD_FILE 注入密码，不误配 SSLROOTCERT/直接密码" "1/1/0/0/0" \
    "$(compose_fact "$facts" hub_password_file_env)/$(compose_fact "$facts" postgres_password_file_env)/$(compose_fact "$facts" hub_sslrootcert_env)/$(compose_fact "$facts" hub_database_password_env)/$(compose_fact "$facts" postgres_password_direct_env)"
  check_eq "C.13" "PG overlay 使用当前源码镜像 $HUB_IMAGE" "$HUB_IMAGE" \
    "$(compose_fact "$facts" hub_image)"

  local direct_pg_password=0
  if grep -Eq '"POSTGRES_PASSWORD"[[:space:]]*:' "$cfg"; then
    direct_pg_password=1
  fi
  if (( direct_pg_password )); then
    fail "C.14" "PG overlay 的 compose config 出现 POSTGRES_PASSWORD 直接值（必须用 FILE）"
  elif "$PYTHON" "$HELPER" scan-secret "$cfg" "$PG_PW_FILE" >"$LOG_DIR/compose-pg-secret-scan.txt" 2>&1; then
    pass "C.14" "PG overlay 的 compose config 不含 POSTGRES_PASSWORD 直接值或密码明文"
  else
    fail "C.14" "PG overlay 的 compose config 疑似含数据库密码明文（内容未打印）"
  fi

  if (( FAILS == before )); then
    return 0
  fi
  return 1
}

pg_overlay_runtime_checks() {
  local before=$FAILS
  local up_log="$LOG_DIR/compose-pg-up.log"
  local out="" env_dump=""

  if ! compose_pg up -d --pull never --wait --wait-timeout "$HEALTH_TIMEOUT" \
    >"$up_log" 2>&1; then
    fail "G.1" "PG overlay 启动/等待 healthcheck 失败"
    dump_file "$up_log" 100
    return 1
  fi
  pass "G.1" "PG overlay 的 postgres+hub+panel 启动并全部 healthy"

  PG_CT=$(compose_pg_ct postgres)
  PG_HUB_CT=$(compose_pg_ct hub)
  PG_PANEL_CT=$(compose_pg_ct panel)
  if [[ -z "$PG_CT" || -z "$PG_HUB_CT" ]]; then
    fail "G.2" "无法解析 PG overlay 的 postgres/hub 容器 ID"
    return 1
  fi

  check_health "G.2" "PG overlay postgres healthcheck healthy" "$PG_CT" || true
  check_health "G.3" "PG overlay hub healthcheck healthy" "$PG_HUB_CT" || true
  if [[ -n "$PG_PANEL_CT" ]]; then
    check_health "G.4" "PG overlay panel healthcheck healthy" "$PG_PANEL_CT" || true
  else
    fail "G.4" "PG overlay 未解析到 panel 容器"
  fi

  out=$(docker port "$PG_CT" 2>/dev/null || true)
  if [[ -z "$out" ]]; then
    pass "G.5" "postgres 容器没有发布任何宿主端口（5432 仅 compose 内网）"
  else
    fail "G.5" "postgres 容器发布了宿主端口: $out"
  fi

  check_healthz_body "G.6" "PG hub 管理口 /healthz 返回 ok" "$PG_HUB_CT" || true
  # 同 D.6：允许 0 条或仅内置 hub-self。
  if fetch_agents_api "$PG_HUB_CT" "$SECRETS/pg-agents-initial.json"; then
    out=$(agents_summary "$SECRETS/pg-agents-initial.json" "hub-self")
    if [[ "$out" == *"count=0"* ]] \
      || [[ "$out" == *"count=1"* && "$out" == *"found=1"* ]]; then
      pass "G.7" "PG hub agents 允许为空或仅内置 hub-self（$out）"
    else
      fail "G.7" "PG hub agents 出现 hub-self 之外的记录（$out）"
    fi
  else
    fail "G.7" "PG hub 管理 API /api/v1/agents 调用失败"
  fi

  if ! docker exec "$PG_HUB_CT" sh -c \
    'grep -E "^(database|db_sslrootcert)[[:space:]]*=" /data/etc/rustboard/hub.toml' \
    >"$LOG_DIR/pg-config-keys.txt" 2>"$LOG_DIR/pg-config.err"; then
    fail "G.8" "无法读取 PG hub 的 database 配置"
    dump_file "$LOG_DIR/pg-config.err" 30
  elif grep -qE '^database[[:space:]]*=[[:space:]]*"postgres://rustboard@postgres:5432/rustboard\?sslmode=disable"' \
    "$LOG_DIR/pg-config-keys.txt"; then
    pass "G.8" "PG hub 配置为 postgres://rustboard@postgres:5432/rustboard?sslmode=disable"
  else
    fail "G.8" "PG hub 配置不是预期 PostgreSQL DSN（未打印配置内容）"
  fi

  if grep -qE '^database[[:space:]]*=[[:space:]]*"postgres(ql)?://[^/"]*:[^/"@]*@' \
    "$LOG_DIR/pg-config-keys.txt"; then
    fail "G.8a" "PG hub 配置 DSN 的 userinfo 含密码（禁止进入 argv）"
  else
    pass "G.8a" "PG hub 配置 DSN 不含 userinfo 密码"
  fi

  if ! grep -qE '^db_sslrootcert[[:space:]]*=' "$LOG_DIR/pg-config-keys.txt" \
    && ! grep -q 'sqlite://' "$LOG_DIR/pg-config-keys.txt"; then
    pass "G.9" "PG hub 未误配 db_sslrootcert，且配置中没有 SQLite DSN"
  else
    fail "G.9" "PG hub 出现 db_sslrootcert 或 SQLite DSN（未打印配置内容）"
  fi

  env_dump=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$PG_HUB_CT" 2>/dev/null || true)
  if printf '%s\n' "$env_dump" | grep -q '^RUSTBOARD_DATABASE_SSLROOTCERT='; then
    fail "G.10" "PG hub 容器环境误设 RUSTBOARD_DATABASE_SSLROOTCERT"
  else
    pass "G.10" "PG hub 容器环境未设置 RUSTBOARD_DATABASE_SSLROOTCERT"
  fi
  if printf '%s\n' "$env_dump" | grep -q '^RUSTBOARD_DATABASE_PASSWORD='; then
    fail "G.11" "PG hub 容器环境直接包含数据库密码明文"
  else
    pass "G.11" "PG hub 只使用 RUSTBOARD_DATABASE_PASSWORD_FILE，不在 Config.Env 放密码"
  fi

  out=$(stat_mode_owner "$PG_HUB_CT" /run/rustboard/admin_token)
  check_eq "G.12" "PG hub 共享 admin_token 为 0600 且属主 10001" "600 10001" "$out"
  out=$(stat_mode_owner "$PG_HUB_CT" /data/etc/rustboard/hub.toml)
  check_eq "G.13" "PG hub 配置 hub.toml 为 0600 且属主 10001" "600 10001" "$out"

  if [[ "$(stat -c '%a' "$PG_PW_FILE" 2>/dev/null || true)" == "600" ]]; then
    pass "G.14" "PG 密码 secret 在宿主为 0600"
  else
    fail "G.14" "PG 密码 secret 在宿主不是 0600"
  fi

  if ! docker inspect "$PG_HUB_CT" >"$SECRETS/inspect-pg-hub.json" 2>"$LOG_DIR/inspect-pg-hub.err"; then
    fail "G.15" "docker inspect hub 失败，无法证明容器配置不含密码"
  elif ! docker inspect "$PG_CT" >"$SECRETS/inspect-pg-db.json" 2>"$LOG_DIR/inspect-pg-db.err"; then
    fail "G.15" "docker inspect postgres 失败，无法证明容器配置不含密码"
  elif [[ ! -s "$SECRETS/inspect-pg-hub.json" || ! -s "$SECRETS/inspect-pg-db.json" ]]; then
    fail "G.15" "docker inspect 输出为空，无法证明容器配置不含密码"
  elif "$PYTHON" "$HELPER" scan-secret "$SECRETS/inspect-pg-hub.json" "$PG_PW_FILE" >/dev/null 2>&1 \
    && "$PYTHON" "$HELPER" scan-secret "$SECRETS/inspect-pg-db.json" "$PG_PW_FILE" >/dev/null 2>&1; then
    pass "G.15" "hub/postgres 容器 inspect 不含数据库密码明文"
  else
    fail "G.15" "hub/postgres 容器 inspect 疑似出现数据库密码明文（内容未打印）"
  fi

  out=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$PG_CT" 2>/dev/null || true)
  if printf '%s\n' "$out" | grep -q '^POSTGRES_PASSWORD='; then
    fail "G.15a" "postgres 容器 Config.Env 出现 POSTGRES_PASSWORD 直接值"
  else
    pass "G.15a" "postgres 容器 Config.Env 只使用 POSTGRES_PASSWORD_FILE，不含直接密码"
  fi

  PG_NETWORK=$(container_network "$PG_HUB_CT")
  PG_HUB_VOLUME=$(mount_name "$PG_HUB_CT" /data)
  PG_RUN_VOLUME=$(mount_name "$PG_HUB_CT" /run/rustboard)
  PG_DATA_VOLUME=$(mount_name "$PG_CT" /var/lib/postgresql/data)
  PG_VOLUME_NAMES=$(project_volume_names "$PROJECT_PG" | sort)
  if [[ -n "$PG_NETWORK" && -n "$PG_HUB_VOLUME" && -n "$PG_RUN_VOLUME" && -n "$PG_DATA_VOLUME" ]]; then
    pass "G.16" "PG overlay 网络/数据 volume 解析成功（hub_data、hub_run、postgres_data）"
  else
    fail "G.16" "PG overlay 网络或 volume 解析失败"
  fi

  if out=$(docker exec -u postgres "$PG_CT" psql -X -q -A -t -U rustboard -d rustboard \
    -c 'SHOW server_version' 2>"$LOG_DIR/pg-version.err"); then
    out=$(printf '%s' "$out" | tr -d '[:space:]')
    if [[ "$out" == 16.* ]]; then
      pass "G.17" "PostgreSQL 服务端主版本为 16（$out）"
    else
      fail "G.17" "PostgreSQL 服务端主版本不是 16（$out）"
    fi
  else
    fail "G.17" "查询 PostgreSQL 版本失败"
  fi

  if out=$(pg_count schema_migrations 2>/dev/null); then
    out=$(printf '%s' "$out" | tr -d '[:space:]')
    if [[ "$out" =~ ^[0-9]+$ ]] && (( out > 0 )); then
      pass "G.18" "PG schema 已应用（schema_migrations=$out）"
    else
      fail "G.18" "PG schema_migrations 没有版本行（[$out]）"
    fi
  else
    fail "G.18" "PG schema 查询失败"
  fi

  PG_CFG_HASH=$(docker exec "$PG_HUB_CT" sha256sum /data/etc/rustboard/hub.toml 2>/dev/null | awk '{ print $1 }' || true)
  if [[ "$PG_CFG_HASH" =~ ^[0-9a-f]{64}$ ]]; then
    pass "G.19" "记录 PG hub 配置哈希用于重启/--user 后一致性比较"
  else
    fail "G.19" "无法计算 PG hub 配置哈希"
  fi

  if [[ -z "$PG_HUB_VOLUME" || -z "$PG_DATA_VOLUME" ]]; then
    return 1
  fi
  if (( FAILS == before )); then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 真实 agent enrollment 与 PG 数据
# ---------------------------------------------------------------------------

agent_enrollment_checks() {
  local before=$FAILS
  local add_out="$SECRETS/agent-add.out"
  local ports_out="$SECRETS/agent-ports.out"
  local token_info="" fp="" version_out="" summary="" config_mode=""
  local agent_start_ms=""

  if ! hub_exec_pg rustboard-hub agent add \
    --config /data/etc/rustboard/hub.toml --name s4-agent \
    >"$add_out" 2>"$LOG_DIR/agent-add.err"; then
    fail "A.1" "hub agent add 失败（token 未生成）"
    dump_file "$LOG_DIR/agent-add.err" 40
    rm -f -- "$add_out"
    return 1
  fi
  if ! token_info=$("$PYTHON" "$HELPER" parse-agent-token "$add_out" "$AGENT_TOKEN_FILE" \
    2>"$LOG_DIR/agent-token.err"); then
    fail "A.1" "hub agent add 输出未解析到 64hex token"
    dump_file "$LOG_DIR/agent-token.err" 30
    rm -f -- "$add_out"
    return 1
  fi
  rm -f -- "$add_out"
  chmod 0600 "$AGENT_TOKEN_FILE"
  if [[ "$(stat -c '%a' "$AGENT_TOKEN_FILE")" != "600" ]]; then
    fail "A.1" "enrollment token 文件不是 0600"
    return 1
  fi
  pass "A.1" "hub 生成 enrollment token，仅落 0600 文件、不打印（$token_info）"

  if ! docker exec "$PG_HUB_CT" rustboard-hub ports \
    --config /data/etc/rustboard/hub.toml >"$ports_out" 2>"$LOG_DIR/agent-ports.err"; then
    fail "A.2" "hub ports 读取证书指纹失败"
    dump_file "$LOG_DIR/agent-ports.err" 40
    rm -f -- "$ports_out"
    return 1
  fi
  if ! fp=$("$PYTHON" "$HELPER" parse-fingerprint "$ports_out" 2>"$LOG_DIR/agent-fingerprint.err"); then
    fail "A.2" "无法从 hub ports 输出解析证书指纹"
    dump_file "$LOG_DIR/agent-fingerprint.err" 30
    rm -f -- "$ports_out"
    return 1
  fi
  rm -f -- "$ports_out"
  if [[ ! "$fp" =~ ^[0-9a-fA-F]{64}$ ]]; then
    fail "A.2" "hub ports 输出的证书指纹不是 64hex"
    return 1
  fi
  pass "A.2" "从 hub ports 取得证书指纹（不打印内容）"

  if ! docker volume create --label "rustboard.e2e=1" --label "rustboard.e2e.run=$RUN_ID" \
    "$AGENT_VOLUME" >"$LOG_DIR/agent-volume.log" 2>&1; then
    fail "A.3" "创建 agent 数据 volume 失败"
    dump_file "$LOG_DIR/agent-volume.log" 30
    return 1
  fi

  # --network host：agent 连宿主已发布的 127.0.0.1:8443；证书 SAN 含 127.0.0.1。
  # 记录启动前的时间戳，A.8 要求之后确有新批次落库（不能拿启动前的旧数据充数）。
  agent_start_ms=$(date +%s%3N)
  if ! docker run -d --name "$AGENT_CT" \
    --label "rustboard.e2e=1" --label "rustboard.e2e.run=$RUN_ID" \
    --network host \
    -v "$AGENT_VOLUME:/data" \
    -v "$AGENT_TOKEN_FILE:/run/rustboard/enroll_token:ro" \
    -e "RUSTBOARD_HUB_URL=wss://127.0.0.1:8443/agent/ws" \
    -e "RUSTBOARD_TOKEN_FILE=/run/rustboard/enroll_token" \
    -e "RUSTBOARD_FINGERPRINT=$fp" \
    -e "RUSTBOARD_NAME=s4-agent" \
    "$AGENT_IMAGE" >"$LOG_DIR/agent-run.log" 2>&1; then
    fail "A.3" "真实 agent 容器启动失败"
    dump_file "$LOG_DIR/agent-run.log" 40
    return 1
  fi
  EXTRA_CONTAINERS+=("$AGENT_CT")
  pass "A.3" "agent 以真实 token/指纹和 --network host 启动（未 privileged）"

  if ! check_health "A.4" "agent enrollment 后 cert-info healthcheck healthy" "$AGENT_CT" "$AGENT_TIMEOUT"; then
    return 1
  fi
  if docker exec "$AGENT_CT" rustboard-agent cert-info \
    --config /data/etc/rustboard/agent.toml >"$LOG_DIR/agent-cert-info.log" 2>&1; then
    pass "A.5" "agent cert-info 成功（证书/CN 内容不打印）"
  else
    fail "A.5" "agent cert-info 失败"
    dump_file "$LOG_DIR/agent-cert-info.log" 30
  fi

  config_mode=$(docker exec "$AGENT_CT" stat -c '%a' /data/etc/rustboard/agent.toml 2>/dev/null || true)
  check_eq "A.6" "agent 配置权限为 0600" "600" "$config_mode"

  if wait_agent_online "$PG_HUB_CT" "s4-agent" "$AGENT_TIMEOUT"; then
    S4_AGENT_ID=$(printf '%s\n' "$LAST_AGENT_SUMMARY" \
      | sed -n 's/^agent_id=//p' | head -n 1)
    if [[ "$LAST_AGENT_SUMMARY" == *"matches=1"* ]] && is_agent_uuid "$S4_AGENT_ID"; then
      pass "A.7" "管理 API 显示 s4-agent online 且 agent_id 唯一（agent_id=$S4_AGENT_ID）"
    else
      S4_AGENT_ID=""
      fail "A.7" "s4-agent 的 agent_id 不唯一或非法（${LAST_AGENT_SUMMARY:-无响应}）"
    fi
  else
    fail "A.7" "管理 API 未在 ${AGENT_TIMEOUT}s 内显示 agent s4-agent online（${LAST_AGENT_SUMMARY:-无响应}）"
  fi

  # 等待真实样本落 PG；计数必须按 s4-agent 的唯一 agent_id 过滤，
  # 否则 hub-self 的自采样也能让全表 count>0 通过。还要确认启动后确有
  # 新批次，并出现真实采集器的预期指标。
  local deadline=$((SECONDS + DATA_TIMEOUT))
  local samples=0 batches=0 agents=0 new_batches=0 expected_metrics=0
  if ! is_agent_uuid "$S4_AGENT_ID"; then
    fail "A.8" "无法取得 s4-agent 的唯一 agent_id，不能按 ID 断言 PG 数据（不能退回全表计数）"
  else
    while (( SECONDS < deadline )); do
      samples=$(pg_agent_count samples "$S4_AGENT_ID" 2>/dev/null || true)
      batches=$(pg_agent_count ingest_batches "$S4_AGENT_ID" 2>/dev/null || true)
      agents=$(pg_agent_count agents "$S4_AGENT_ID" 2>/dev/null || true)
      new_batches=$(pg_agent_new_batches_since "$S4_AGENT_ID" "$agent_start_ms" 2>/dev/null || true)
      expected_metrics=$(pg_agent_expected_metrics "$S4_AGENT_ID" 2>/dev/null || true)
      samples=$(printf '%s' "$samples" | tr -d '[:space:]')
      batches=$(printf '%s' "$batches" | tr -d '[:space:]')
      agents=$(printf '%s' "$agents" | tr -d '[:space:]')
      new_batches=$(printf '%s' "$new_batches" | tr -d '[:space:]')
      expected_metrics=$(printf '%s' "$expected_metrics" | tr -d '[:space:]')
      if [[ "$samples" =~ ^[0-9]+$ && "$batches" =~ ^[0-9]+$ && "$agents" =~ ^[0-9]+$ \
        && "$new_batches" =~ ^[0-9]+$ && "$expected_metrics" =~ ^[0-9]+$ ]] \
        && (( samples > 0 && batches > 0 && agents == 1 && new_batches > 0 \
          && expected_metrics == 3 )); then
        break
      fi
      sleep 2
    done
    if [[ "$samples" =~ ^[0-9]+$ && "$batches" =~ ^[0-9]+$ && "$agents" =~ ^[0-9]+$ \
      && "$new_batches" =~ ^[0-9]+$ && "$expected_metrics" =~ ^[0-9]+$ ]] \
      && (( samples > 0 && batches > 0 && agents == 1 && new_batches > 0 \
        && expected_metrics == 3 )); then
      pass "A.8" "PG s4-agent(${S4_AGENT_ID}) samples=$samples ingest_batches=$batches agents=$agents new_batches=$new_batches 预期指标=3/3"
    else
      fail "A.8" "PG 按 s4-agent(${S4_AGENT_ID}) 断言失败（samples=[$samples] ingest_batches=[$batches] agents=[$agents] 启动后新批次=[$new_batches] 预期指标=[$expected_metrics]/3；hub-self 数据不能代替）"
    fi
  fi

  version_out=$(docker exec "$AGENT_CT" rustboard-agent --version 2>/dev/null || true)
  if printf '%s\n' "$version_out" | grep -Fq "$EXPECTED_VERSION"; then
    pass "A.9" "运行中的 agent 版本为 $EXPECTED_VERSION（当前源码）"
  else
    fail "A.9" "运行中的 agent 版本不含 $EXPECTED_VERSION"
  fi

  if (( FAILS == before )); then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 重启持久化
# ---------------------------------------------------------------------------

restart_persistence_checks() {
  local before=$FAILS
  local s0 b0 a0 s1 b1 a1 hash1=""
  local as0="" ab0="" aa0="" as1="" ab1="" aa1=""
  local scoped=1 full_ok=0 scoped_ok=0

  if ! is_agent_uuid "$S4_AGENT_ID"; then
    scoped=0
  fi

  s0=$(pg_count samples 2>/dev/null || true)
  b0=$(pg_count ingest_batches 2>/dev/null || true)
  a0=$(pg_count agents 2>/dev/null || true)
  s0=$(printf '%s' "$s0" | tr -d '[:space:]')
  b0=$(printf '%s' "$b0" | tr -d '[:space:]')
  a0=$(printf '%s' "$a0" | tr -d '[:space:]')
  if [[ ! "$s0" =~ ^[0-9]+$ || ! "$b0" =~ ^[0-9]+$ || ! "$a0" =~ ^[0-9]+$ ]]; then
    fail "R.1" "重启前无法读取 PG 计数"
    return 1
  fi

  # 全表计数只作辅助：hub-self 持续自采样会掩盖 s4-agent 的数据丢失，
  # 因此同时记录按唯一 s4 agent_id 过滤的计数（与 A.8 同口径）。
  if (( scoped == 1 )); then
    as0=$(pg_agent_count samples "$S4_AGENT_ID" 2>/dev/null || true)
    ab0=$(pg_agent_count ingest_batches "$S4_AGENT_ID" 2>/dev/null || true)
    aa0=$(pg_agent_count agents "$S4_AGENT_ID" 2>/dev/null || true)
    as0=$(printf '%s' "$as0" | tr -d '[:space:]')
    ab0=$(printf '%s' "$ab0" | tr -d '[:space:]')
    aa0=$(printf '%s' "$aa0" | tr -d '[:space:]')
    if [[ ! "$as0" =~ ^[0-9]+$ || ! "$ab0" =~ ^[0-9]+$ || ! "$aa0" =~ ^[0-9]+$ ]]; then
      fail "R.7" "重启前无法按 s4-agent(${S4_AGENT_ID}) 读取 PG 计数"
      return 1
    fi
  fi

  # panel 共享 hub network namespace；先停 panel，避免 hub 重启时 netns 悬空。
  compose_pg stop panel >"$LOG_DIR/restart-stop-panel.log" 2>&1 || true
  if ! compose_pg stop hub >"$LOG_DIR/restart-stop-hub.log" 2>&1; then
    fail "R.1" "停止 hub 失败"
    dump_file "$LOG_DIR/restart-stop-hub.log" 40
    return 1
  fi
  if ! wait_stopped "$PG_HUB_CT" 45; then
    fail "R.1" "hub 未在 45s 内停止"
    return 1
  fi
  if ! compose_pg stop postgres >"$LOG_DIR/restart-stop-pg.log" 2>&1; then
    fail "R.2" "停止 postgres 失败"
    dump_file "$LOG_DIR/restart-stop-pg.log" 40
    return 1
  fi
  if ! wait_stopped "$PG_CT" 45; then
    fail "R.2" "postgres 未在 45s 内停止"
    return 1
  fi
  pass "R.1" "按顺序停止 panel、hub、postgres（不删除 volume）"

  if ! compose_pg start postgres >"$LOG_DIR/restart-start-pg.log" 2>&1; then
    fail "R.2" "启动 postgres 失败"
    dump_file "$LOG_DIR/restart-start-pg.log" 40
    return 1
  fi
  if ! check_health "R.2" "postgres 重启后 healthcheck healthy" "$PG_CT" "$HEALTH_TIMEOUT"; then
    return 1
  fi
  if ! compose_pg start hub >"$LOG_DIR/restart-start-hub.log" 2>&1; then
    fail "R.3" "启动 hub 失败"
    dump_file "$LOG_DIR/restart-start-hub.log" 40
    return 1
  fi
  if ! check_health "R.3" "hub 重启后 healthcheck healthy" "$PG_HUB_CT" "$HEALTH_TIMEOUT"; then
    return 1
  fi

  check_healthz_body "R.4" "重启后 hub 管理口 /healthz 返回 ok" "$PG_HUB_CT" || true
  hash1=$(docker exec "$PG_HUB_CT" sha256sum /data/etc/rustboard/hub.toml 2>/dev/null | awk '{ print $1 }' || true)
  if [[ -n "$PG_CFG_HASH" && "$hash1" == "$PG_CFG_HASH" ]]; then
    pass "R.5" "重启后 hub.toml 哈希不变"
  else
    fail "R.5" "重启后 hub.toml 哈希变化（配置被改写？）"
  fi

  if fetch_agents_api "$PG_HUB_CT" "$SECRETS/agents-after-restart.json"; then
    pass "R.6" "重启后管理 API /api/v1/agents 仍返回 200"
  else
    fail "R.6" "重启后管理 API /api/v1/agents 调用失败"
  fi

  s1=$(pg_count samples 2>/dev/null || true)
  b1=$(pg_count ingest_batches 2>/dev/null || true)
  a1=$(pg_count agents 2>/dev/null || true)
  s1=$(printf '%s' "$s1" | tr -d '[:space:]')
  b1=$(printf '%s' "$b1" | tr -d '[:space:]')
  a1=$(printf '%s' "$a1" | tr -d '[:space:]')
  if (( scoped == 1 )); then
    as1=$(pg_agent_count samples "$S4_AGENT_ID" 2>/dev/null || true)
    ab1=$(pg_agent_count ingest_batches "$S4_AGENT_ID" 2>/dev/null || true)
    aa1=$(pg_agent_count agents "$S4_AGENT_ID" 2>/dev/null || true)
    as1=$(printf '%s' "$as1" | tr -d '[:space:]')
    ab1=$(printf '%s' "$ab1" | tr -d '[:space:]')
    aa1=$(printf '%s' "$aa1" | tr -d '[:space:]')
  fi

  if [[ "$s1" =~ ^[0-9]+$ && "$b1" =~ ^[0-9]+$ && "$a1" =~ ^[0-9]+$ ]] \
    && (( s1 >= s0 && b1 >= b0 && a1 >= a0 && a1 > 0 )); then
    full_ok=1
  fi
  if (( scoped == 1 )) \
    && [[ "$as1" =~ ^[0-9]+$ && "$ab1" =~ ^[0-9]+$ && "$aa1" =~ ^[0-9]+$ ]] \
    && (( as1 >= as0 && ab1 >= ab0 && as1 > 0 && ab1 > 0 \
      && aa0 == 1 && aa1 == 1 )); then
    scoped_ok=1
  fi

  if (( full_ok == 1 && scoped_ok == 1 )); then
    pass "R.7" "重启后全表与 s4-agent 数据均不减少（s4-agent=${S4_AGENT_ID} samples ${as0}→${as1}，ingest_batches ${ab0}→${ab1}，agents ${aa0}→${aa1}；全表辅助 samples ${s0}→${s1}，ingest_batches ${b0}→${b1}，agents ${a0}→${a1}）"
  elif (( scoped == 0 )); then
    fail "R.7" "S4_AGENT_ID 不可用，无法排除 hub-self 补偿 s4-agent 丢失（全表 samples ${s0}→${s1}，ingest_batches ${b0}→${b1}，agents ${a0}→${a1}）"
  else
    fail "R.7" "重启后数据减少或 s4-agent 记录丢失（s4-agent=${S4_AGENT_ID} samples ${as0}→${as1}，ingest_batches ${ab0}→${ab1}，agents ${aa0}→${aa1}；全表辅助 samples ${s0}→${s1}，ingest_batches ${b0}→${b1}，agents ${a0}→${a1}）"
  fi

  # agent 在 hub 重启后应能重连；不作为数据断言，但失败会提示。
  if wait_agent_online "$PG_HUB_CT" "s4-agent" 90; then
    pass "R.8" "agent 在 hub 重启后重新 online"
  else
    fail "R.8" "agent 未在 90s 内重新 online（${LAST_AGENT_SUMMARY:-无响应}）"
  fi

  if (( FAILS == before )); then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# --user 10001（已初始化 volume）
# ---------------------------------------------------------------------------

user_10001_checks() {
  local before=$FAILS
  local health_out="" hash_after="" mode_uid="" logs_file="$LOG_DIR/user-hub.log"
  local config_hash_before="$PG_CFG_HASH"

  # 密码文件需对 UID 10001 可读：保留 0600，只把 owner 改成 10001；测试副本
  # 与生产 secret 分离，不改动 root:root 0600 的 $PG_PW_FILE。
  if ! install -m 0600 "$PG_PW_FILE" "$USER_PW_FILE" \
    || ! chown 10001:10001 "$USER_PW_FILE"; then
    fail "U.1" "无法创建 0600 且属主 10001 的 --user 测试密码文件"
    return 1
  fi
  if [[ "$(stat -c '%a %u' "$USER_PW_FILE")" != "600 10001" ]]; then
    fail "U.1" "无法创建 0600 且属主 10001 的 --user 测试密码文件"
    return 1
  fi

  if ! compose_pg stop hub >"$LOG_DIR/user-stop-hub.log" 2>&1; then
    fail "U.1" "--user 前停止 hub 失败"
    dump_file "$LOG_DIR/user-stop-hub.log" 40
    return 1
  fi
  if ! wait_stopped "$PG_HUB_CT" 45; then
    fail "U.1" "--user 前 hub 未在 45s 内停止"
    return 1
  fi

  if ! docker run -d --name "$USER_CT" \
    --label "rustboard.e2e=1" --label "rustboard.e2e.run=$RUN_ID" \
    --user 10001:10001 \
    --network "$PG_NETWORK" \
    -v "$PG_HUB_VOLUME:/data" \
    -v "$PG_RUN_VOLUME:/run/rustboard:ro" \
    -v "$USER_PW_FILE:/run/secrets/rustboard_pg_password:ro" \
    -e "RUSTBOARD_LISTEN=0.0.0.0:8443" \
    -e "RUSTBOARD_ADMIN_LISTEN=127.0.0.1:8444" \
    -e "RUSTBOARD_ADMIN_TOKEN_SHARE=/run/rustboard/admin_token" \
    -e "RUSTBOARD_DATABASE_PASSWORD_FILE=/run/secrets/rustboard_pg_password" \
    -e "RUSTBOARD_TLS_MODE=self-signed" \
    -e "RUSTBOARD_NAME=s4-hub" \
    "$HUB_IMAGE" >"$LOG_DIR/user-run.log" 2>&1; then
    fail "U.1" "--user 10001:10001 启动已初始化 hub volume 失败"
    dump_file "$LOG_DIR/user-run.log" 40
    return 1
  fi
  EXTRA_CONTAINERS+=("$USER_CT")

  if wait_exec_http_200 "$USER_CT" "http://127.0.0.1:8444/healthz" 90; then
    health_out="200"
  else
    health_out="$LAST_CODE"
  fi
  if [[ "$health_out" == "200" ]]; then
    pass "U.1" "--user 10001:10001 在已初始化 volume 上 /healthz 200"
  else
    fail "U.1" "--user 10001:10001 启动后 /healthz 非 200（最后 HTTP $health_out）"
    dump_container_logs "$USER_CT" 60
  fi

  mode_uid=$(docker top "$USER_CT" -o uid,pid,args 2>/dev/null \
    | awk 'NR > 1 && index($0, "rustboard-hub") > 0 { print $1; exit }' || true)
  if [[ "$mode_uid" == "10001" ]]; then
    pass "U.2" "--user 启动的 rustboard-hub 主进程 UID=10001"
  else
    fail "U.2" "--user 启动的 rustboard-hub UID=[${mode_uid:-missing}]"
  fi

  if ! docker stop --time 15 "$USER_CT" >"$LOG_DIR/user-stop.log" 2>&1; then
    fail "U.3" "--user 容器停止失败"
    dump_file "$LOG_DIR/user-stop.log" 30
  else
    pass "U.3" "--user 容器收到 SIGTERM 后正常停止"
  fi
  docker logs "$USER_CT" 2>&1 | redact_stream >"$logs_file" 2>&1 || true
  if grep -Eqi 'permission denied|operation not permitted|eacces|不可读|权限不足' "$logs_file"; then
    fail "U.4" "--user 10001 日志出现权限错误"
    dump_file "$logs_file" 40
  else
    pass "U.4" "--user 10001 日志无权限错误（不打印日志内容）"
  fi

  hash_after=$(docker run --rm --network none --user 10001:10001 \
    -v "$PG_HUB_VOLUME:/data:ro" --entrypoint sha256sum "$HUB_IMAGE" \
    /data/etc/rustboard/hub.toml 2>"$LOG_DIR/user-hash.err" | awk '{ print $1 }' || true)
  if [[ -n "$config_hash_before" && "$hash_after" == "$config_hash_before" ]]; then
    pass "U.5" "--user 10001 运行后 hub.toml 哈希不变且对 10001 可读"
  else
    fail "U.5" "--user 10001 运行后 hub.toml 哈希变化或不可读"
    dump_file "$LOG_DIR/user-hash.err" 30
  fi

  docker rm -f -- "$USER_CT" >/dev/null 2>&1 || true
  if (( FAILS == before )); then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 外部 client pg_dump / pg_restore
# ---------------------------------------------------------------------------

pg_client_dump() {
  docker run --rm --name "$PG_CLIENT_CT" \
    --label "rustboard.e2e=1" --label "rustboard.e2e.run=$RUN_ID" \
    --network "$PG_NETWORK" --env-file "$PG_ENV_FILE" \
    --entrypoint pg_dump "$PG_CLIENT_IMAGE" \
    --format=custom --no-owner --no-privileges --dbname=rustboard
}

pg_client_restore() {
  docker run --rm -i --name "$PG_RESTORE_CT" \
    --label "rustboard.e2e=1" --label "rustboard.e2e.run=$RUN_ID" \
    --network "$PG_NETWORK" --env-file "$PG_ENV_FILE" \
    --entrypoint pg_restore "$PG_CLIENT_IMAGE" \
    --clean --if-exists --exit-on-error --no-owner --no-privileges --dbname=rustboard_restore
}

backup_restore_checks() {
  local before=$FAILS
  local s0 b0 a0 m0 s1 b1 a1 m1 s2 b2 a2 m2
  local dump_mode=""

  # dump 需要停 hub（一致性）；user 用例结束时 hub 已停止，这里再兜底。
  if [[ "$(docker inspect -f '{{.State.Running}}' "$PG_HUB_CT" 2>/dev/null || true)" == "true" ]]; then
    if ! compose_pg stop hub >"$LOG_DIR/backup-stop-hub.log" 2>&1; then
      fail "K.1" "备份前停止 hub 失败"
      dump_file "$LOG_DIR/backup-stop-hub.log" 40
      return 1
    fi
    if ! wait_stopped "$PG_HUB_CT" 45; then
      fail "K.1" "备份前 hub 未停止"
      return 1
    fi
  fi
  pass "K.1" "备份前 hub 已停止（PG 数据处于静态）"

  s0=$(pg_count samples 2>/dev/null || true)
  b0=$(pg_count ingest_batches 2>/dev/null || true)
  a0=$(pg_count agents 2>/dev/null || true)
  m0=$(pg_count schema_migrations 2>/dev/null || true)
  s0=$(printf '%s' "$s0" | tr -d '[:space:]')
  b0=$(printf '%s' "$b0" | tr -d '[:space:]')
  a0=$(printf '%s' "$a0" | tr -d '[:space:]')
  m0=$(printf '%s' "$m0" | tr -d '[:space:]')
  if [[ ! "$s0" =~ ^[0-9]+$ || ! "$b0" =~ ^[0-9]+$ || ! "$a0" =~ ^[0-9]+$ || ! "$m0" =~ ^[0-9]+$ ]]; then
    fail "K.2" "无法读取备份前 PG 计数"
    return 1
  fi

  if ! pg_client_dump >"$DUMP_FILE" 2>"$LOG_DIR/pg-dump.err"; then
    fail "K.2" "外部 pg_dump -Fc 失败（不打印密码/DSN）"
    dump_file "$LOG_DIR/pg-dump.err" 60
    rm -f -- "$DUMP_FILE"
    return 1
  fi
  chmod 0600 "$DUMP_FILE"
  dump_mode=$(stat -c '%a' "$DUMP_FILE" 2>/dev/null || true)
  if [[ -s "$DUMP_FILE" && "$dump_mode" == "600" ]] \
    && "$PYTHON" -c 'import sys; d=open(sys.argv[1], "rb").read(5); raise SystemExit(0 if d == b"PGDMP" else 1)' "$DUMP_FILE" \
      >/dev/null 2>&1; then
    pass "K.2" "外部 pg_dump -Fc 生成非空 custom dump，权限 0600（header=PGDMP）"
  else
    fail "K.2" "pg_dump 输出不是有效 custom dump 或权限不是 0600"
    rm -f -- "$DUMP_FILE"
    return 1
  fi

  # compose 只创建 POSTGRES_USER=rustboard（superuser），容器内没有 postgres
  # 角色；用 rustboard 连默认 postgres 维护库（local socket trust）。
  if ! docker exec -u postgres "$PG_CT" psql -X -q -v ON_ERROR_STOP=1 -U rustboard -d postgres \
    -c 'CREATE DATABASE rustboard_restore OWNER rustboard' >"$LOG_DIR/pg-restore-create.log" 2>&1; then
    fail "K.3" "创建 rustboard_restore 新库失败"
    dump_file "$LOG_DIR/pg-restore-create.log" 40
    return 1
  fi
  pass "K.3" "创建独立新库 rustboard_restore（原库未动）"

  if ! pg_client_restore <"$DUMP_FILE" >"$LOG_DIR/pg-restore.log" 2>"$LOG_DIR/pg-restore.err"; then
    fail "K.4" "外部 pg_restore 到 rustboard_restore 失败"
    dump_file "$LOG_DIR/pg-restore.err" 80
    return 1
  fi
  pass "K.4" "外部 pg_restore 成功（自定义格式、--no-owner --no-privileges）"

  s1=$(pg_count_db rustboard_restore samples 2>/dev/null || true)
  b1=$(pg_count_db rustboard_restore ingest_batches 2>/dev/null || true)
  a1=$(pg_count_db rustboard_restore agents 2>/dev/null || true)
  m1=$(pg_count_db rustboard_restore schema_migrations 2>/dev/null || true)
  s1=$(printf '%s' "$s1" | tr -d '[:space:]')
  b1=$(printf '%s' "$b1" | tr -d '[:space:]')
  a1=$(printf '%s' "$a1" | tr -d '[:space:]')
  m1=$(printf '%s' "$m1" | tr -d '[:space:]')
  if [[ "$s1" == "$s0" && "$b1" == "$b0" && "$a1" == "$a0" && "$m1" == "$m0" ]]; then
    pass "K.5" "恢复库与原库计数一致（samples $s0=$s1，ingest_batches $b0=$b1，agents $a0=$a1，schema_migrations $m0=$m1）"
  else
    fail "K.5" "恢复库计数不一致（原 samples=$s0 batches=$b0 agents=$a0 migrations=$m0；恢复 samples=$s1 batches=$b1 agents=$a1 migrations=$m1）"
  fi

  s2=$(pg_count samples 2>/dev/null || true)
  b2=$(pg_count ingest_batches 2>/dev/null || true)
  a2=$(pg_count agents 2>/dev/null || true)
  m2=$(pg_count schema_migrations 2>/dev/null || true)
  s2=$(printf '%s' "$s2" | tr -d '[:space:]')
  b2=$(printf '%s' "$b2" | tr -d '[:space:]')
  a2=$(printf '%s' "$a2" | tr -d '[:space:]')
  m2=$(printf '%s' "$m2" | tr -d '[:space:]')
  if [[ "$s2" == "$s0" && "$b2" == "$b0" && "$a2" == "$a0" && "$m2" == "$m0" ]]; then
    pass "K.6" "恢复后原库计数完全不变"
  else
    fail "K.6" "恢复后原库计数变化（samples $s0→$s2，batches $b0→$b2，agents $a0→$a2）"
  fi

  if docker exec -u postgres "$PG_CT" psql -X -q -v ON_ERROR_STOP=1 -U rustboard -d postgres \
    -c 'DROP DATABASE rustboard_restore' >"$LOG_DIR/pg-restore-drop.log" 2>&1; then
    pass "K.7" "删除测试恢复库 rustboard_restore，原库继续保留"
  else
    info "恢复库 rustboard_restore 删除失败（项目 volume 会在 cleanup 删除，不影响原库）"
  fi

  rm -f -- "$DUMP_FILE"
  if (( FAILS == before )); then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 默认 SQLite 与 PG 项目隔离
# ---------------------------------------------------------------------------

isolation_checks() {
  local before=$FAILS

  if [[ -f "$LOG_DIR/sqlite-config-keys.txt" ]] \
    && grep -q 'sqlite:///data/var/lib/rustboard/hub/rustboard.db' "$LOG_DIR/sqlite-config-keys.txt" \
    && ! grep -q 'postgres://' "$LOG_DIR/sqlite-config-keys.txt"; then
    pass "X.1" "默认 compose 的 hub_data 配置保持 SQLite，不含 PG DSN"
  else
    fail "X.1" "默认 compose 的 hub_data 配置不是纯 SQLite"
  fi

  if [[ -f "$LOG_DIR/pg-config-keys.txt" ]] \
    && grep -q 'postgres://rustboard@postgres:5432/rustboard?sslmode=disable' "$LOG_DIR/pg-config-keys.txt" \
    && ! grep -q 'sqlite://' "$LOG_DIR/pg-config-keys.txt"; then
    pass "X.2" "PG overlay 的 hub 配置为 PostgreSQL，不含 SQLite DSN"
  else
    fail "X.2" "PG overlay 的 hub 配置不是纯 PostgreSQL"
  fi

  if [[ -n "$SQLITE_HUB_VOLUME" && -n "$PG_HUB_VOLUME" && "$SQLITE_HUB_VOLUME" != "$PG_HUB_VOLUME" ]]; then
    pass "X.3" "默认 SQLite 与 PG overlay 使用不同的 hub_data volume"
  else
    fail "X.3" "默认 SQLite 与 PG overlay 的 hub_data volume 相同或缺失"
  fi

  if [[ "$(leftover_count "$PROJECT_SQLITE")" == "0" ]]; then
    pass "X.4" "默认 compose 项目已清理，不残留 SQLite volume/容器/网络"
  else
    fail "X.4" "默认 compose 项目仍有资源残留"
  fi

  if [[ -n "$PG_DATA_VOLUME" && -n "$PG_HUB_VOLUME" && "$PG_DATA_VOLUME" != "$PG_HUB_VOLUME" ]]; then
    pass "X.5" "PG overlay 的 postgres_data 与 hub_data 是独立 volume"
  else
    fail "X.5" "PG overlay 的 postgres_data/hub_data volume 异常"
  fi

  if [[ -n "$SQLITE_NETWORK" && -n "$PG_NETWORK" && "$SQLITE_NETWORK" != "$PG_NETWORK" ]]; then
    pass "X.7" "默认 SQLite 与 PG overlay 使用不同的 compose network（$SQLITE_NETWORK / $PG_NETWORK）"
  else
    fail "X.7" "默认 SQLite 与 PG overlay 的 compose network 相同或缺失"
  fi

  local overlap=0 vol
  while IFS= read -r vol; do
    [[ -n "$vol" ]] || continue
    if grep -qxF -- "$vol" <<<"$PG_VOLUME_NAMES"; then
      overlap=1
      break
    fi
  done <<<"$SQLITE_VOLUME_NAMES"
  if [[ -n "$SQLITE_VOLUME_NAMES" && -n "$PG_VOLUME_NAMES" && "$overlap" == "0" ]]; then
    pass "X.8" "默认 SQLite 与 PG overlay 的 compose volume 名集合不相交"
  else
    fail "X.8" "默认 SQLite 与 PG overlay 的 compose volume 名集合相交或为空"
  fi

  if [[ "$(stat -c '%a' "$PG_ENV_FILE" 2>/dev/null || true)" == "600" ]]; then
    pass "X.6" "PG client env-file 权限为 0600"
  else
    fail "X.6" "PG client env-file 权限不是 0600"
  fi

  if (( FAILS == before )); then
    return 0
  fi
  return 1
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      -h|--help)
        usage
        exit 0
        ;;
      --dist-manifest)
        (( $# >= 2 )) || {
          printf -- '--dist-manifest 需要 FILE 参数\n' >&2
          exit 2
        }
        DIST_MANIFEST=$2
        shift 2
        ;;
      --dist-manifest=*)
        DIST_MANIFEST=${1#--dist-manifest=}
        shift
        ;;
      *)
        printf '未知参数: %s\n' "$1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done
  if [[ -z "$DIST_MANIFEST" && -z "$EXPECTED_DIST_SHA256" ]]; then
    printf 'FATAL: 必须提供 --dist-manifest FILE 或 EXPECTED_DIST_SHA256（拒绝未知 dist 来源）\n' >&2
    exit 2
  fi
  if [[ -n "$DIST_MANIFEST" && -n "$EXPECTED_DIST_SHA256" ]]; then
    printf 'FATAL: --dist-manifest 与 EXPECTED_DIST_SHA256 只能二选一\n' >&2
    exit 2
  fi
}

init_evidence() {
  mkdir -p "$EVIDENCE_ROOT" "$LOG_DIR" || die "无法创建证据目录: $RUN_DIR"
  chmod 0750 "$EVIDENCE_ROOT" "$RUN_DIR" "$LOG_DIR" 2>/dev/null || true

  SECRETS=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-v100-docker-pg.XXXXXX") \
    || die "无法创建临时 secret 目录"
  chmod 0700 "$SECRETS" || die "无法收紧临时 secret 目录权限"
  PG_PW_FILE="$SECRETS/postgres_password"
  PG_ENV_FILE="$SECRETS/pg-client.env"
  USER_PW_FILE="$SECRETS/user-postgres_password"
  AGENT_TOKEN_FILE="$SECRETS/agent-enroll.token"
  DUMP_FILE="$SECRETS/rustboard.dump"
  SQLITE_COPY_DIR="$SECRETS/sqlite"

  cat >"$HELPER" <<'PY'
#!/usr/bin/env python3
"""v100-docker-pg.sh 的只读解析辅助（仅 Python 标准库）。"""

import json
import ipaddress
import os
import re
import socket
import sqlite3
import sys
import urllib.parse


def die(message, code=2):
    print(message, file=sys.stderr)
    raise SystemExit(code)


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError as exc:
        die("读取文件失败 %s: %s" % (path, exc))


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
    """把 host_ip 规范化为 'loopback' 或可比较的地址文本；空/缺省留空。"""
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


def is_loopback_host(host_ip):
    return normalize_host_ip(host_ip) == "loopback"


def parse_port(port):
    target = None
    published = None
    host_ip = ""
    if isinstance(port, dict):
        target = as_int(port.get("target"))
        published = port.get("published")
        # 缺省 host_ip 必须保留为空，不能被当成回环。
        host_ip = port.get("host_ip")
    else:
        text = str(port).strip()
        if not text:
            return None, None, ""
        if "/" in text:
            text = text.split("/", 1)[0]
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
                target = as_int(parts[-1])
            elif len(parts) == 1:
                target = as_int(parts[0])
        else:
            parts = text.split(":")
            if len(parts) >= 3:
                host_ip = parts[0]
                published = parts[-2]
                target = as_int(parts[-1])
            elif len(parts) == 2:
                published = parts[0]
                target = as_int(parts[1])
            elif len(parts) == 1:
                target = as_int(parts[0])
    if published in ("", None):
        published = None
    else:
        published = str(published)
    return target, published, normalize_host_ip(host_ip)


def published_includes(published, wanted):
    expected = str(wanted)
    if published == expected:
        return True
    if "-" in published:
        start, end = published.split("-", 1)
        if start.isdigit() and end.isdigit() and int(start) <= wanted <= int(end):
            return True
    return False


def env_map(service):
    raw = (service or {}).get("environment") or {}
    result = {}
    if isinstance(raw, dict):
        for key, value in raw.items():
            result[str(key)] = "" if value is None else str(value)
    elif isinstance(raw, list):
        for item in raw:
            text = str(item)
            if "=" in text:
                key, value = text.split("=", 1)
            else:
                key, value = text, ""
            result[key] = value
    return result


def collect_ports(services):
    all_targets = set()
    all_published = set()
    per_service = {}
    count_8080 = 0
    nonloopback_8080 = 0
    for name, service in (services or {}).items():
        targets = set()
        published = set()
        for port in (service or {}).get("ports") or []:
            target, pub, host_ip = parse_port(port)
            if target is not None:
                targets.add(str(target))
                all_targets.add(str(target))
            if pub is not None:
                published.add(pub)
                all_published.add(pub)
                if published_includes(pub, 8080):
                    count_8080 += 1
                    if host_ip != "loopback":
                        nonloopback_8080 += 1
        per_service[name] = (targets, published)
    loopback_ok = 1 if count_8080 > 0 and nonloopback_8080 == 0 else 0
    return (
        all_targets,
        all_published,
        per_service,
        count_8080,
        nonloopback_8080,
        loopback_ok,
    )


def command_compose_facts(args):
    if len(args) != 1:
        die("用法: compose-facts JSON_FILE")
    try:
        with open(args[0], "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        die("读取/解析 compose JSON 失败: %s" % exc)

    services = data.get("services") or {}
    (
        all_targets,
        all_published,
        per_service,
        count_8080,
        nonloopback_8080,
        loopback_8080_ok,
    ) = collect_ports(services)
    hub = services.get("hub") or {}
    postgres = services.get("postgres") or {}
    hub_env = env_map(hub)
    pg_env = env_map(postgres)

    db = hub_env.get("RUSTBOARD_DATABASE", "")
    parsed = urllib.parse.urlsplit(db) if db else urllib.parse.urlsplit("")
    query = urllib.parse.parse_qs(parsed.query)

    secrets = data.get("secrets") or {}
    secret_file = ""
    if isinstance(secrets, dict):
        secret = secrets.get("rustboard_pg_password") or {}
        if isinstance(secret, dict):
            secret_file = str(secret.get("file") or "")

    def has_port(published, wanted):
        expected = str(wanted)
        for value in published:
            if value == expected:
                return 1
            if "-" in value:
                start, end = value.split("-", 1)
                if start.isdigit() and end.isdigit() and int(start) <= wanted <= int(end):
                    return 1
        return 0

    hub_targets, hub_pub = per_service.get("hub", (set(), set()))
    panel_targets, panel_pub = per_service.get("panel", (set(), set()))
    pg_targets, pg_pub = per_service.get("postgres", (set(), set()))

    print("services=" + ",".join(sorted(services)))
    print("postgres_present=%d" % (1 if "postgres" in services else 0))
    print("postgres_image=" + str(postgres.get("image") or ""))
    print("postgres_ports_count=%d" % len(postgres.get("ports") or []))
    print("postgres_published=" + ",".join(sorted(pg_pub)))
    print("hub_image=" + str(hub.get("image") or ""))
    print("panel_image=" + str((services.get("panel") or {}).get("image") or ""))
    print("agent_image=" + str((services.get("agent") or {}).get("image") or ""))
    print("hub_published=" + ",".join(sorted(hub_pub)))
    print("panel_published=" + ",".join(sorted(panel_pub)))
    print("all_published_ports=" + ",".join(sorted(all_published)))
    print("all_target_ports=" + ",".join(sorted(all_targets)))
    print("published_8080_entries=%d" % count_8080)
    print("published_8080_nonloopback=%d" % nonloopback_8080)
    print("published_8080_loopback=%d" % loopback_8080_ok)
    print("published_5432=%d" % has_port(all_published, 5432))
    print("published_8444=%d" % has_port(all_published, 8444))
    print("target_5432=%d" % has_port(all_targets, 5432))
    print("target_8444=%d" % has_port(all_targets, 8444))
    print("hub_database_env=%d" % (1 if "RUSTBOARD_DATABASE" in hub_env else 0))
    print("hub_db_scheme=" + str(parsed.scheme or ""))
    print("hub_db_host=" + str(parsed.hostname or ""))
    print("hub_db_port=" + (str(parsed.port) if parsed.port is not None else ""))
    print("hub_db_path=" + str(parsed.path or ""))
    print("hub_db_sslmode=" + str((query.get("sslmode") or [""])[0]))
    print("hub_db_has_password=%d" % (1 if parsed.password else 0))
    print("hub_password_file_env=%d" % (1 if "RUSTBOARD_DATABASE_PASSWORD_FILE" in hub_env else 0))
    print("hub_database_password_env=%d" % (1 if "RUSTBOARD_DATABASE_PASSWORD" in hub_env else 0))
    print("hub_sslrootcert_env=%d" % (1 if "RUSTBOARD_DATABASE_SSLROOTCERT" in hub_env else 0))
    print("postgres_password_file_env=%d" % (1 if "POSTGRES_PASSWORD_FILE" in pg_env else 0))
    print("postgres_password_direct_env=%d" % (1 if "POSTGRES_PASSWORD" in pg_env else 0))
    print("pg_secret_file=" + secret_file)


def command_dist_manifest(args):
    if len(args) != 1:
        die("用法: dist-manifest FILE|-")
    if args[0] == "-":
        text = sys.stdin.read()
    else:
        text = read_text(args[0])
    values = {}
    for token in text.split():
        if "=" not in token:
            die("dist manifest 含无 '=' 的条目")
        key, value = token.split("=", 1)
        if key not in ("hub", "panel", "agent", "web"):
            die("dist manifest 含未知键: %s" % key)
        if key in values:
            die("dist manifest 重复键: %s" % key)
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            die("dist manifest 的 %s 不是 64hex" % key)
        values[key] = value.lower()
    missing = [key for key in ("hub", "panel", "agent", "web") if key not in values]
    if missing:
        die("dist manifest 缺键: " + ",".join(missing))
    for key in ("hub", "panel", "agent", "web"):
        print("%s=%s" % (key, values[key]))


def command_parse_agent_token(args):
    if len(args) != 2:
        die("用法: parse-agent-token INPUT OUTPUT")
    text = read_text(args[0])
    matches = re.findall(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])", text)
    if not matches:
        die("agent add 输出中没有 64hex token（不打印内容）")
    token = matches[0]
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(args[1], flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (token + "\n").encode("ascii"))
    finally:
        os.close(fd)
    print("token_len=64")


def command_parse_fingerprint(args):
    if len(args) != 1:
        die("用法: parse-fingerprint FILE")
    text = read_text(args[0])
    match = re.search(r"证书指纹\s*[:：]\s*([0-9a-fA-F]{64})", text)
    if not match:
        die("ports 输出中没有证书指纹（不打印内容）")
    print(match.group(1))


def command_agents_check(args):
    if len(args) != 2:
        die("用法: agents-check JSON_FILE NAME")
    try:
        with open(args[0], "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        die("读取/解析 agents JSON 失败: %s" % exc)
    if not isinstance(data, list):
        die("agents 响应不是 JSON 数组")
    matches = [
        candidate
        for candidate in data
        if isinstance(candidate, dict)
        and (candidate.get("name") == args[1] or candidate.get("agent_id") == args[1])
    ]
    item = matches[0] if matches else None
    print("count=%d" % len(data))
    print("matches=%d" % len(matches))
    print("found=%d" % (1 if item else 0))
    print("status=" + (str(item.get("status") or "") if item else ""))
    print("agent_id=" + (str(item.get("agent_id") or "") if item else ""))


def command_sqlite_check(args):
    if len(args) != 1:
        die("用法: sqlite-check FILE")
    path = args[0]
    try:
        conn = sqlite3.connect(path)
    except sqlite3.Error as exc:
        die("无法打开 SQLite 副本: %s" % exc)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()
        if not integrity or integrity[0] != "ok":
            die("SQLite integrity_check 未返回 ok")
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        # SQLite 的 schema 版本在 PRAGMA user_version（当前 v7），没有 PG 的
        # schema_migrations 表；不要把 PG 表名当成 SQLite 的假设。
        required = {"agents", "samples", "ingest_batches"}
        missing = sorted(required - tables)
        if missing:
            die("SQLite 缺少核心表: " + ",".join(missing))
        user_version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        if user_version < 7:
            die("SQLite user_version=%d < 7（schema 未初始化或过旧）" % user_version)
        print(
            "tables=%d required=1 user_version=%d integrity=ok"
            % (len(tables), user_version)
        )
    except sqlite3.Error as exc:
        die("SQLite 校验失败: %s" % exc)
    finally:
        conn.close()


def command_scan_secret(args):
    if len(args) != 2:
        die("用法: scan-secret FILE SECRET_FILE")
    try:
        with open(args[1], "rb") as handle:
            secret = handle.read().strip()
    except OSError as exc:
        die("读取 secret 失败: %s" % exc)
    if not secret:
        die("secret 为空")
    try:
        with open(args[0], "rb") as handle:
            payload = handle.read()
    except OSError as exc:
        die("读取待扫描文件失败: %s" % exc)
    present = secret in payload
    print("secret_present=%d" % (1 if present else 0))
    raise SystemExit(1 if present else 0)


def bind_free(family, address):
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(address)
    finally:
        sock.close()


def command_ports_free(args):
    if not args:
        die("用法: ports-free PORT [PORT ...]")
    busy = []
    for raw in args:
        if not raw.isdigit():
            die("端口必须是整数: %s" % raw)
        port = int(raw)
        try:
            bind_free(socket.AF_INET, ("0.0.0.0", port))
        except OSError:
            busy.append(port)
            continue
        if socket.has_ipv6:
            try:
                bind_free(socket.AF_INET6, ("::", port))
            except OSError as exc:
                if exc.errno not in (97, 99, 101):
                    busy.append(port)
    if busy:
        print("busy_ports=" + ",".join(str(port) for port in sorted(set(busy))), file=sys.stderr)
        raise SystemExit(1)
    print("ports_free=" + ",".join(args))


def main():
    if len(sys.argv) < 2:
        die("缺少子命令")
    command = sys.argv[1]
    args = sys.argv[2:]
    handlers = {
        "compose-facts": command_compose_facts,
        "dist-manifest": command_dist_manifest,
        "parse-agent-token": command_parse_agent_token,
        "parse-fingerprint": command_parse_fingerprint,
        "agents-check": command_agents_check,
        "sqlite-check": command_sqlite_check,
        "scan-secret": command_scan_secret,
        "ports-free": command_ports_free,
    }
    handler = handlers.get(command)
    if handler is None:
        die("未知子命令: %s" % command)
    handler(args)


if __name__ == "__main__":
    main()
PY
  chmod 0755 "$HELPER" || die "无法写入 helper.py"
}

main() {
  preflight
  if ! build_images; then
    info "镜像构建未全部成功，跳过运行时用例（失败已计入 B 组）"
    return 0
  fi
  if ! record_image_ids; then
    info "镜像 ID 未完整记录，停止运行时用例"
    return 0
  fi
  image_checks

  if ! default_sqlite_checks; then
    info "默认 SQLite compose 用例失败，停止后续 PG 用例（避免级联误报）"
    return 0
  fi

  if ! pg_overlay_config_checks; then
    info "PG overlay 配置断言失败，停止后续运行时用例"
    return 0
  fi
  if ! pg_overlay_runtime_checks; then
    info "PG overlay 运行时用例失败，停止后续 agent/备份用例"
    return 0
  fi
  if ! agent_enrollment_checks; then
    info "agent enrollment/PG 数据用例失败，停止后续重启/备份用例"
    return 0
  fi
  if ! restart_persistence_checks; then
    info "重启持久化用例失败，停止后续 --user/备份用例"
    return 0
  fi
  if ! user_10001_checks; then
    info "--user 10001 用例失败，停止后续备份用例"
    return 0
  fi
  if ! backup_restore_checks; then
    info "备份/恢复用例失败，继续执行隔离检查"
  fi
  isolation_checks || true
  skip "S5" "arm64 多架构/原生门禁由 S5 独立覆盖，本脚本只跑 amd64"
}

parse_args "$@"

# --help 在注册 trap 前退出；其余路径的资源都只属于本项目。
trap cleanup EXIT
trap 'exit 130' INT TERM
trap 'exit 129' HUP

init_evidence
main

if (( FAILS > 0 )); then
  exit 1
fi
exit 0
