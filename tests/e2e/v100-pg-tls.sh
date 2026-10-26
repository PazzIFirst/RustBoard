#!/usr/bin/env bash
#
# Phase E：真实 TLS PostgreSQL（verify-full）e2e。
#
# 验证内容：
#   1. 临时 CA + serverAuth/SAN 证书、postgres:16 开启 TLS，psql verify-full 可用；
#   2. hub 用 PostgreSQL DSN + 顶层 db_sslrootcert 启动，/healthz 200；
#   3. 真实 agent enroll / 上报，PG 中 samples / ingest_batches / agents > 0；
#   4. 停 hub 再重启：样本不减少、agent 记录仍在；
#   5. 负向：错误 CA、缺失根证书、根证书是目录、根证书是符号链接、主机名不匹配；
#   6. 密码 / 完整 DSN / token 不进入日志；证据目录只保存脱敏日志与计数。
#
# 前置：Linux + Docker（本地已有 postgres:16 镜像，本脚本不联网拉取）、
#       openssl、psql（建议与 PG 服务端主版本一致）、curl、python3、timeout。
#
# 用法：bash tests/e2e/v100-pg-tls.sh
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"

STAMP=$(date -u +%Y%m%dT%H%M%SZ)-$$
RUN_DIR="$ROOT/target/pg-tls-e2e/$STAMP"
EVIDENCE="$RUN_DIR/evidence"
SECRETS="$RUN_DIR/.secrets"
mkdir -p -- "$EVIDENCE" "$SECRETS"
chmod 0700 -- "$RUN_DIR" "$EVIDENCE" "$SECRETS"

HUB_BIN="$ROOT/target/debug/rustboard-hub"
AGENT_BIN="$ROOT/target/debug/rustboard-agent"
PG_CONTAINER=""
PG_CONTAINER_NAME=""
PG_NAME_WAS_FREE=0
PG_LOG_COLLECTED=0
PG_PORT=""
AGENT_PORT=""
ADMIN_PORT=""
PROXY_PORT=""
HUB_PID=""
AGENT_PID=""
PROXY_PID=""
PG_PASSWORD=""
PG_PASSWORD_ENC=""
PG_DSN=""
HUB_ADMIN_TOKEN=""
ENROLL_TOKEN=""
AGENT_ID=""
FINALIZED=0
RAW_SCAN_DONE=0
RAW_SCANNED_COUNT=0
RAW_SECRET_COUNT=0
CLEANUP_FAILED=0
HEAD_COMMIT=""
HEAD_COMMIT_EPOCH=0
HEAD_DIRTY_ENTRIES=0
HUB_SHA256=""
AGENT_SHA256=""
HUB_MTIME=""
AGENT_MTIME=""
HUB_MTIME_EPOCH=0
AGENT_MTIME_EPOCH=0
HUB_OLDER_THAN_HEAD=0
AGENT_OLDER_THAN_HEAD=0
PG_IMAGE_ID=""
SCRIPT_SHA256=""
PASS=0
FAIL=0

pass_case() {
  PASS=$((PASS + 1))
  printf 'PASS: %s\n' "$1"
  printf 'PASS %s\n' "$1" >>"$EVIDENCE/cases.txt"
}

fail_case() {
  FAIL=$((FAIL + 1))
  printf 'FAIL: %s\n' "$1"
  printf 'FAIL %s\n' "$1" >>"$EVIDENCE/cases.txt"
}

die() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

stop_pid() {
  local pid=${1:-}
  [[ -n "$pid" ]] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 100); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  wait "$pid" 2>/dev/null || true
}

# 清理失败只记录、不覆盖原始退出码；正常路径会在 summary 前把它变成 FAIL。
record_cleanup_failure() {
  local message=$1
  CLEANUP_FAILED=1
  printf 'WARN: %s\n' "$message" >&2
  printf '%s\n' "$message" >>"$EVIDENCE/cleanup-failures.txt" 2>/dev/null || true
}

# 原始文件敏感数据扫描：密码、URL 编码密码、完整 DSN、admin/enrollment token、
# PEM 私钥块。只返回 0/1，绝不打印命中值。缺失文件返回 2。
file_has_sensitive_data() {
  local file=$1
  [[ -f "$file" ]] || return 2
  write_secret_list
  python3 - "$file" "$SECRETS/sanitize-secrets.txt" <<'PY'
import re
import sys

path, secret_file = sys.argv[1], sys.argv[2]
try:
    secrets = [line for line in open(secret_file, encoding="utf-8").read().splitlines() if line]
except FileNotFoundError:
    secrets = []
data = open(path, "rb").read()
text = data.decode("utf-8", "replace")
key_re = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
hit = key_re.search(data) is not None or any(value in text for value in secrets)
raise SystemExit(0 if hit else 1)
PY
}

# docker logs 可能失败；只记录，不把失败当成“没有 secret”。
collect_postgres_log() {
  [[ -n "$PG_CONTAINER" ]] || return 0
  [[ "$PG_LOG_COLLECTED" == 1 ]] && return 0
  if docker logs "$PG_CONTAINER" >"$SECRETS/postgres.log" 2>&1; then
    PG_LOG_COLLECTED=1
    return 0
  fi
  rm -f -- "$SECRETS/postgres.log" 2>/dev/null || true
  record_cleanup_failure "收集 PostgreSQL 容器日志失败: $PG_CONTAINER"
  return 1
}

# 发布脱敏副本之前，扫描所有将要进入证据的原始日志。
# 命中 secret 的文件立即删除，且不发布副本；文件本身不打印值。
scan_raw_logs() {
  [[ "$RAW_SCAN_DONE" == 1 ]] && return 0
  local collected=0 file base
  if collect_postgres_log; then
    collected=1
  fi

  : >"$SECRETS/raw-secret-logs.txt"
  RAW_SCANNED_COUNT=0
  RAW_SECRET_COUNT=0
  for file in \
    "$SECRETS/hub.log" \
    "$SECRETS/hub-restart.log" \
    "$SECRETS/agent.log" \
    "$SECRETS/postgres.log" \
    "$SECRETS/proxy.log" \
    "$SECRETS/hub-init.err" \
    "$SECRETS/agent-add.err" \
    "$SECRETS"/psql*.err \
    "$SECRETS"/negative-*.log; do
    [[ -f "$file" ]] || continue
    RAW_SCANNED_COUNT=$((RAW_SCANNED_COUNT + 1))
    if file_has_sensitive_data "$file"; then
      base=$(basename -- "$file")
      printf '%s\n' "$base" >>"$SECRETS/raw-secret-logs.txt"
      if ! rm -f -- "$file"; then
        record_cleanup_failure "删除含 secret 的原始日志失败: $base"
      fi
      RAW_SECRET_COUNT=$((RAW_SECRET_COUNT + 1))
    fi
  done

  {
    printf 'scanned=%s\n' "$RAW_SCANNED_COUNT"
    printf 'blocked=%s\n' "$RAW_SECRET_COUNT"
    if (( RAW_SECRET_COUNT > 0 )); then
      printf 'blocked_files:\n'
      sed 's/^/  /' "$SECRETS/raw-secret-logs.txt"
      printf 'action=已删除原始 secret 日志，不发布对应脱敏副本\n'
    else
      printf 'action=全部原始日志未命中已知 secret/私钥标记\n'
    fi
  } >"$EVIDENCE/raw-log-scan.txt"

  # PG 日志收集失败时不能宣称扫描完整；finalize 会再试一次。
  if [[ "$collected" == 1 ]]; then
    RAW_SCAN_DONE=1
  else
    RAW_SCAN_DONE=0
  fi

  if (( RAW_SECRET_COUNT > 0 )); then
    printf 'FAIL: 发布前原始日志扫描发现 %s 个含 secret 的日志，已删除（文件名见 raw-log-scan.txt）\n' \
      "$RAW_SECRET_COUNT" >&2
    return 1
  fi
  [[ "$collected" == 1 ]] || return 1
  return 0
}

remove_container() {
  local container=$PG_CONTAINER
  [[ -n "$container" ]] || return 0
  if docker rm -f "$container" >/dev/null 2>&1; then
    PG_CONTAINER=""
    return 0
  fi
  record_cleanup_failure "docker rm -f $container 失败"
  return 1
}

# docker run 成功后到变量赋值之间的窗口若被信号打断，容器名在启动前已确认不存在，
# 因此可以安全地只按这个名字回收；不会碰到其它实例。
cleanup_orphan_container() {
  [[ -z "$PG_CONTAINER" && "$PG_NAME_WAS_FREE" == 1 && -n "$PG_CONTAINER_NAME" ]] || return 0
  if docker container inspect "$PG_CONTAINER_NAME" >/dev/null 2>&1; then
    PG_CONTAINER="$PG_CONTAINER_NAME"
    remove_container || true
  fi
}

remove_secrets_dir() {
  [[ -e "$SECRETS" ]] || return 0
  case "$SECRETS" in
    "$ROOT"/target/pg-tls-e2e/*/.secrets) ;;
    *)
      record_cleanup_failure "拒绝删除非预期临时目录: $SECRETS"
      return 1
      ;;
  esac
  if rm -rf -- "$SECRETS" && [[ ! -e "$SECRETS" ]]; then
    return 0
  fi
  record_cleanup_failure "rm -rf 临时 secret 目录失败: $SECRETS"
  return 1
}

# 把密码/token 等写到 0600 的临时文件，供 Python 脱敏与扫描使用。
# 绝不把 secret 作为 argv 传给外部命令。
write_secret_list() {
  local file="$SECRETS/sanitize-secrets.txt" value
  : >"$file"
  for value in \
    "${PG_PASSWORD:-}" \
    "${PG_PASSWORD_ENC:-}" \
    "${PG_DSN:-}" \
    "${HUB_ADMIN_TOKEN:-}" \
    "${ENROLL_TOKEN:-}"; do
    [[ -n "$value" ]] && printf '%s\n' "$value" >>"$file"
  done
  chmod 0600 -- "$file"
}

# 读取 secret 列表并把 src 中出现的 secret 替换为 ***，另对 PG URL 密码与
# PEM 私钥块做兜底脱敏。输出文件固定 0600。
sanitize_file() {
  local src=$1 dst=$2
  [[ -f "$src" ]] || return 0
  write_secret_list
  mkdir -p -- "$(dirname -- "$dst")"
  python3 - "$src" "$dst" "$SECRETS/sanitize-secrets.txt" <<'PY'
import os
import re
import sys

src, dst, secret_file = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    text = open(src, "rb").read().decode("utf-8", "replace")
except FileNotFoundError:
    sys.exit(0)
try:
    values = [line for line in open(secret_file, encoding="utf-8").read().splitlines() if line]
except FileNotFoundError:
    values = []
for value in sorted(set(values), key=len, reverse=True):
    text = text.replace(value, "***")
text = re.sub(r"(postgres(?:ql)?://[^/\s:@]+:)[^@\s]+(@)", r"\1***\2", text)
text = re.sub(
    r"-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----",
    "[REDACTED KEY]",
    text,
    flags=re.S,
)
with open(dst, "w", encoding="utf-8") as handle:
    handle.write(text)
os.chmod(dst, 0o600)
PY
}

publish_log() {
  local src=$1 name=$2
  [[ -f "$src" ]] || return 0
  # 纵深防御：即使前面的 raw scan 因收集失败漏掉，也绝不把含 secret 的原文写进证据。
  if file_has_sensitive_data "$src"; then
    record_cleanup_failure "拒绝发布含 secret 的原始日志: $(basename -- "$src")"
    rm -f -- "$src" 2>/dev/null || true
    return 1
  fi
  sanitize_file "$src" "$EVIDENCE/$name"
}

publish_all_logs() {
  local file base
  publish_log "$SECRETS/hub.log" "hub.log" || true
  publish_log "$SECRETS/hub-restart.log" "hub-restart.log" || true
  publish_log "$SECRETS/agent.log" "agent.log" || true
  publish_log "$SECRETS/postgres.log" "postgres.log" || true
  publish_log "$SECRETS/proxy.log" "proxy.log" || true
  publish_log "$SECRETS/hub-init.err" "hub-init.err" || true
  publish_log "$SECRETS/agent-add.err" "agent-add.err" || true
  for file in "$SECRETS"/psql*.err; do
    [[ -f "$file" ]] || continue
    base=$(basename -- "$file")
    publish_log "$file" "$base" || true
  done
  for file in "$SECRETS"/negative-*.log; do
    [[ -f "$file" ]] || continue
    base=$(basename -- "$file")
    publish_log "$file" "$base" || true
  done
}

# 运行时资源由脚本自己创建；trap 只清理这些 PID/容器名，绝不按镜像或标签
# 批量删除其它实例（例如手工的 rb-s3-pg）。
finalize_runtime() {
  set +e
  stop_pid "$AGENT_PID"
  AGENT_PID=""
  stop_pid "$HUB_PID"
  HUB_PID=""
  stop_pid "$PROXY_PID"
  PROXY_PID=""
  # 必须在删除容器前收集日志并完成原始 secret 扫描。
  collect_postgres_log
  scan_raw_logs || true
  cleanup_orphan_container
  remove_container || true
  publish_all_logs
  FINALIZED=1
  set -e
}

cleanup() {
  local status=$?
  trap - EXIT HUP INT TERM
  set +e
  if [[ "$FINALIZED" == 0 ]]; then
    finalize_runtime
  fi
  # finalize_runtime 结束时恢复了 set -e；清理阶段必须继续忽略单步失败，
  # 否则会跳过证据路径/secret 清理。
  set +e
  cleanup_orphan_container
  if [[ -n "$PG_CONTAINER" ]]; then
    remove_container
  fi
  remove_secrets_dir || true
  printf '\n证据目录: %s\n' "$EVIDENCE"
  if [[ "$status" -ge 128 ]]; then
    printf 'FAIL: 脚本被信号中断（退出码 %s），未完成全部用例\n' "$status" >&2
  fi
  if [[ "$status" == 0 && "$CLEANUP_FAILED" != 0 ]]; then
    printf 'FAIL: 清理失败，详见 %s/cleanup-failures.txt\n' "$EVIDENCE" >&2
    status=1
  fi
  if [[ "$CLEANUP_FAILED" != 0 && -f "$EVIDENCE/summary.txt" ]]; then
    printf 'cleanup_failed_after_summary=1\n' >>"$EVIDENCE/summary.txt" 2>/dev/null || true
  fi
  if [[ "$status" == 0 && "$FAIL" == 0 && "$FINALIZED" == 1 && "$CLEANUP_FAILED" == 0 ]]; then
    printf '全部 %d 项通过\n' "$PASS"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------- 依赖与二进制 ----------

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少依赖命令: $1"
}
for cmd in docker openssl psql curl python3 timeout git sha256sum stat; do
  need_cmd "$cmd"
done
docker info >/dev/null 2>&1 || die "Docker 不可用（docker info 失败），请确认 daemon 与权限"
docker image inspect postgres:16 >/dev/null 2>&1 \
  || die "本地缺少 postgres:16 镜像；本脚本不联网拉取，请先 docker pull postgres:16"

find_cargo() {
  if command -v cargo >/dev/null 2>&1; then
    command -v cargo
  elif [[ -x "$HOME/.cargo/bin/cargo" ]]; then
    printf '%s\n' "$HOME/.cargo/bin/cargo"
  elif [[ -x /usr/local/cargo/bin/cargo ]]; then
    printf '%s\n' /usr/local/cargo/bin/cargo
  fi
}

build_bins=0
[[ -x "$HUB_BIN" ]] || build_bins=1
[[ -x "$AGENT_BIN" ]] || build_bins=1
if [[ "$build_bins" == 1 ]]; then
  CARGO=$(find_cargo || true)
  [[ -n "$CARGO" ]] || die "缺少 target/debug 二进制且找不到 cargo（PATH 或 ~/.cargo/bin）"
  "$CARGO" build --locked -p rustboard-hub -p rustboard-agent \
    || die "cargo build 失败"
fi
[[ -x "$HUB_BIN" ]] || die "缺少可执行文件: $HUB_BIN"
[[ -x "$AGENT_BIN" ]] || die "缺少可执行文件: $AGENT_BIN"

# 证据绑定：记录本次实际使用的二进制 hash/mtime、git HEAD 与 PG 镜像 ID。
# 不强制重建已有二进制，但所有结果都能追溯到具体构建产物。
HEAD_COMMIT=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null) \
  || die "git rev-parse HEAD 失败（证据绑定需要 git 仓库）"
[[ "$HEAD_COMMIT" =~ ^[0-9a-f]{40,64}$ ]] || die "git HEAD 格式非法"
HEAD_COMMIT_EPOCH=$(git -C "$ROOT" log -1 --format=%ct HEAD 2>/dev/null) \
  || die "读取 git HEAD 时间失败"
[[ "$HEAD_COMMIT_EPOCH" =~ ^[0-9]+$ ]] || die "git HEAD 时间非法"
git -C "$ROOT" status --porcelain >"$EVIDENCE/git-status.txt" 2>/dev/null || true
HEAD_DIRTY_ENTRIES=$(wc -l <"$EVIDENCE/git-status.txt" | tr -d ' ')
[[ "$HEAD_DIRTY_ENTRIES" =~ ^[0-9]+$ ]] || HEAD_DIRTY_ENTRIES=0

HUB_SHA256=$(sha256sum "$HUB_BIN" | awk '{print $1}') \
  || die "计算 hub 二进制 sha256 失败"
AGENT_SHA256=$(sha256sum "$AGENT_BIN" | awk '{print $1}') \
  || die "计算 agent 二进制 sha256 失败"
[[ "$HUB_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "hub 二进制 sha256 格式非法"
[[ "$AGENT_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "agent 二进制 sha256 格式非法"
HUB_MTIME=$(stat -c '%y' "$HUB_BIN") || die "读取 hub 二进制 mtime 失败"
AGENT_MTIME=$(stat -c '%y' "$AGENT_BIN") || die "读取 agent 二进制 mtime 失败"
HUB_MTIME_EPOCH=$(stat -c '%Y' "$HUB_BIN") || die "读取 hub 二进制 mtime epoch 失败"
AGENT_MTIME_EPOCH=$(stat -c '%Y' "$AGENT_BIN") || die "读取 agent 二进制 mtime epoch 失败"
[[ "$HUB_MTIME_EPOCH" =~ ^[0-9]+$ ]] || die "hub mtime epoch 非法"
[[ "$AGENT_MTIME_EPOCH" =~ ^[0-9]+$ ]] || die "agent mtime epoch 非法"
if (( HUB_MTIME_EPOCH < HEAD_COMMIT_EPOCH )); then
  HUB_OLDER_THAN_HEAD=1
  printf 'WARN: hub 二进制 mtime 早于 HEAD 提交，未强制重建；证据记录为 stale\n' >&2
fi
if (( AGENT_MTIME_EPOCH < HEAD_COMMIT_EPOCH )); then
  AGENT_OLDER_THAN_HEAD=1
  printf 'WARN: agent 二进制 mtime 早于 HEAD 提交，未强制重建；证据记录为 stale\n' >&2
fi
PG_IMAGE_ID=$(docker image inspect -f '{{.Id}}' postgres:16 2>/dev/null) \
  || die "读取 postgres:16 镜像 ID 失败"
[[ -n "$PG_IMAGE_ID" ]] || die "postgres:16 镜像 ID 为空"
SCRIPT_SHA256=$(sha256sum "$ROOT/tests/e2e/v100-pg-tls.sh" | awk '{print $1}') \
  || die "计算 e2e 脚本 sha256 失败"
[[ "$SCRIPT_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "e2e 脚本 sha256 格式非法"
HUB_VERSION=$("$HUB_BIN" --version 2>/dev/null | head -1 || true)
AGENT_VERSION=$("$AGENT_BIN" --version 2>/dev/null | head -1 || true)

{
  printf 'git_head=%s\n' "$HEAD_COMMIT"
  printf 'git_head_epoch=%s\n' "$HEAD_COMMIT_EPOCH"
  printf 'git_status_entries=%s\n' "$HEAD_DIRTY_ENTRIES"
  printf 'hub_bin=%s\n' "$HUB_BIN"
  printf 'hub_sha256=%s\n' "$HUB_SHA256"
  printf 'hub_mtime=%s\n' "$HUB_MTIME"
  printf 'hub_older_than_head=%s\n' "$HUB_OLDER_THAN_HEAD"
  printf 'agent_bin=%s\n' "$AGENT_BIN"
  printf 'agent_sha256=%s\n' "$AGENT_SHA256"
  printf 'agent_mtime=%s\n' "$AGENT_MTIME"
  printf 'agent_older_than_head=%s\n' "$AGENT_OLDER_THAN_HEAD"
  printf 'postgres_image_id=%s\n' "$PG_IMAGE_ID"
  printf 'script_sha256=%s\n' "$SCRIPT_SHA256"
  printf 'hub_version=%s\n' "$HUB_VERSION"
  printf 'agent_version=%s\n' "$AGENT_VERSION"
} >"$EVIDENCE/binary-manifest.txt"

# 四个互不相同的回环端口（PG、hub agent、hub admin、Python 代理）。
# 代理必须监听 127.0.0.2，用来验证证书只含 127.0.0.1 时的 hostname 不匹配。
read -r PG_PORT AGENT_PORT ADMIN_PORT PROXY_PORT <<<"$(python3 - <<'PY'
import socket

specs = ["127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.2"]
sockets = []
ports = []
for host in specs:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sockets.append(sock)
    ports.append(sock.getsockname()[1])
print(*ports)
for sock in sockets:
    sock.close()
PY
)"
for port in "$PG_PORT" "$AGENT_PORT" "$ADMIN_PORT" "$PROXY_PORT"; do
  [[ "$port" =~ ^[0-9]+$ ]] || die "生成的端口非法: $port"
done
printf '本次端口: PG=%s hub_agent=%s hub_admin=%s proxy=%s\n' \
  "$PG_PORT" "$AGENT_PORT" "$ADMIN_PORT" "$PROXY_PORT"

# ---------- 临时 PG CA / 服务端证书 ----------

CERT_DIR="$SECRETS/certs"
PG_CERT_DIR="$CERT_DIR/pg"
WRONG_CA_DIR="$CERT_DIR/wrong-ca"
CA_KEY="$CERT_DIR/ca.key"
CA_CERT="$CERT_DIR/ca.crt"
SERVER_KEY="$PG_CERT_DIR/server.key"
SERVER_CSR="$PG_CERT_DIR/server.csr"
SERVER_CERT="$PG_CERT_DIR/server.crt"
SERVER_EXT="$PG_CERT_DIR/server.ext"
WRONG_CA_KEY="$WRONG_CA_DIR/ca.key"
WRONG_CA="$WRONG_CA_DIR/ca.crt"
mkdir -p -- "$PG_CERT_DIR" "$WRONG_CA_DIR"
chmod 0755 -- "$PG_CERT_DIR"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -keyout "$CA_KEY" -out "$CA_CERT" \
  -subj "/CN=RustBoard PG TLS E2E Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1 \
  || die "生成临时 CA 失败"
openssl req -newkey rsa:2048 -sha256 -nodes \
  -keyout "$SERVER_KEY" -out "$SERVER_CSR" \
  -subj "/CN=localhost" >/dev/null 2>&1 \
  || die "生成 PG 服务端 CSR 失败"
cat >"$SERVER_EXT" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -sha256 -days 2 -in "$SERVER_CSR" \
  -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CERT" -extfile "$SERVER_EXT" >/dev/null 2>&1 \
  || die "签发 PG 服务端证书失败"
# 错误 CA：只用来证明 verify-full 会拒绝非信任根。
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -keyout "$WRONG_CA_KEY" -out "$WRONG_CA" \
  -subj "/CN=RustBoard PG TLS E2E Wrong Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1 \
  || die "生成错误 CA 失败"

chmod 0600 -- "$CA_KEY" "$SERVER_KEY" "$WRONG_CA_KEY"
chmod 0644 -- "$CA_CERT" "$SERVER_CERT" "$WRONG_CA"
chmod 0644 -- "$SERVER_CSR" "$SERVER_EXT"

# postgres 镜像以 postgres 用户读 key；0600 必须保持，只改属主。
PG_UID=$(docker run --rm --entrypoint sh postgres:16 -c 'id -u postgres' 2>/dev/null) \
  || die "无法读取 postgres 镜像内的 postgres UID"
[[ "$PG_UID" =~ ^[0-9]+$ ]] || die "postgres UID 非数字: $PG_UID"
chown "$PG_UID:$PG_UID" "$SERVER_KEY" || die "无法把 server.key 交给 postgres 用户"
[[ "$(stat -c '%a' "$SERVER_KEY")" == "600" ]] \
  || die "server.key 权限不是 0600"

if openssl verify -CAfile "$CA_CERT" "$SERVER_CERT" >/dev/null 2>&1 \
  && openssl x509 -in "$SERVER_CERT" -noout -ext subjectAltName 2>/dev/null \
    | grep -q 'DNS:localhost' \
  && openssl x509 -in "$SERVER_CERT" -noout -ext subjectAltName 2>/dev/null \
    | grep -q 'IP Address:127.0.0.1' \
  && openssl x509 -in "$SERVER_CERT" -noout -ext extendedKeyUsage 2>/dev/null \
    | grep -q 'TLS Web Server Authentication' \
  && [[ "$(stat -c '%a' "$SERVER_KEY")" == "600" ]]; then
  pass_case "证书：链校验通过，SAN=DNS:localhost/IP:127.0.0.1，serverAuth，私钥 0600"
else
  fail_case "证书：链/SAN/serverAuth/私钥权限不符合要求"
  die "临时证书不满足测试前置条件"
fi

{
  printf '# PG server certificate\n'
  openssl x509 -in "$SERVER_CERT" -noout -subject -issuer -dates \
    -ext subjectAltName,extendedKeyUsage
  printf '\n# verify result\n'
  openssl verify -CAfile "$CA_CERT" "$SERVER_CERT"
  printf '\n# server.key mode\n'
  stat -c '%a' "$SERVER_KEY"
} >"$EVIDENCE/cert-info.txt" 2>&1

# ---------- 临时 PostgreSQL 16（TLS，不要求客户端证书） ----------

PG_PASSWORD_FILE="$SECRETS/pg-password"
python3 - "$PG_PASSWORD_FILE" <<'PY'
import secrets
import string
import sys
import urllib.parse

alphabet = string.ascii_letters + string.digits + "@:/?#%+._-"
while True:
    password = "".join(secrets.choice(alphabet) for _ in range(32))
    if any(ch in password for ch in "@:/?#%+"):
        break
path = sys.argv[1]
with open(path, "w", encoding="utf-8") as handle:
    handle.write(password + "\n")
with open(path + ".enc", "w", encoding="utf-8") as handle:
    handle.write(urllib.parse.quote(password, safe="") + "\n")
PY
chmod 0600 -- "$PG_PASSWORD_FILE" "$PG_PASSWORD_FILE.enc"
PG_PASSWORD=$(<"$PG_PASSWORD_FILE")
PG_PASSWORD_ENC=$(<"$PG_PASSWORD_FILE.enc")
PG_DSN="postgres://rustboard:${PG_PASSWORD_ENC}@127.0.0.1:${PG_PORT}/rustboard?sslmode=verify-full"
printf '%s' "$PG_DSN" >"$SECRETS/dsn.txt"
chmod 0600 -- "$SECRETS/dsn.txt"

PG_ENV="$SECRETS/pg.env"
printf 'POSTGRES_PASSWORD=%s\n' "$PG_PASSWORD" >"$PG_ENV"
chmod 0600 -- "$PG_ENV"
PG_CONTAINER_NAME="rb-pg-tls-e2e-${STAMP}"

# 启动前先确认这个名字不存在；这样即使 docker run 被中断/半失败，脚本也只可能
# 回收自己刚创建的同名容器，绝不会碰别人的实例。
if docker container inspect "$PG_CONTAINER_NAME" >/dev/null 2>&1; then
  die "容器名已存在，拒绝复用/删除非本脚本创建的容器: $PG_CONTAINER_NAME"
fi
PG_NAME_WAS_FREE=1

# 注意：不设置 ssl_ca_file，否则 PG 会请求客户端证书，而 hub 当前使用
# with_no_client_auth，握手必然失败（文档记录为限制）。
if docker run -d --name "$PG_CONTAINER_NAME" \
  --label "rustboard.e2e=pg-tls" \
  --label "rustboard.e2e.run=${STAMP}" \
  -p "127.0.0.1:${PG_PORT}:5432" \
  -e POSTGRES_USER=rustboard \
  -e POSTGRES_DB=rustboard \
  --env-file "$PG_ENV" \
  -v "$PG_CERT_DIR:/pgcerts:ro" \
  postgres:16 \
  -c ssl=on \
  -c ssl_cert_file=/pgcerts/server.crt \
  -c ssl_key_file=/pgcerts/server.key \
  -c ssl_min_protocol_version=TLSv1.2 >/dev/null; then
  # 成功分支内立即登记，缩小信号打断导致的未登记窗口。
  PG_CONTAINER="$PG_CONTAINER_NAME"
else
  # 名字已确认此前不存在；若 docker run 留下半创建容器，只按该名字回收。
  if docker container inspect "$PG_CONTAINER_NAME" >/dev/null 2>&1; then
    PG_CONTAINER="$PG_CONTAINER_NAME"
    remove_container || true
  fi
  die "启动 postgres:16 容器失败"
fi

# pg_isready 在 docker-entrypoint 的临时 initdb 实例阶段就可能返回 ready；
# 它只能作为早期提示，不能作为“正式实例已可连接”的判据。
for _ in $(seq 1 60); do
  if docker exec "$PG_CONTAINER" pg_isready -U rustboard -d rustboard >/dev/null 2>&1; then
    break
  fi
  running=$(docker inspect -f '{{.State.Running}}' "$PG_CONTAINER" 2>/dev/null || true)
  [[ "$running" == "true" ]] || break
  sleep 1
done

# 权威就绪判断：对正式 TCP 实例执行真实 psql 连接（verify-full）。
# 临时实例会重启、rustboard 库尚不存在或 TLS 尚未就绪，都会在这里重试；
# 另外要求 postmaster 已持续运行 ≥ 2s，避免把 initdb 的临时实例当成正式实例
# （临时实例 shutdown 与正式实例启动之间，单一成功连接仍可能被下一轮重启打断）。
PG_READY_CONN="host=127.0.0.1 port=${PG_PORT} dbname=rustboard user=rustboard sslmode=verify-full"
psql_ready=0
for _ in $(seq 1 120); do
  if PGPASSWORD="$PG_PASSWORD" \
    PGSSLROOTCERT="$CA_CERT" \
    psql "$PG_READY_CONN" -At -c 'select 1' \
    >/dev/null 2>>"$SECRETS/psql-readiness.err"; then
    uptime_flag=$(PGPASSWORD="$PG_PASSWORD" \
      PGSSLROOTCERT="$CA_CERT" \
      psql "$PG_READY_CONN" -At -c \
      "select case when now() - pg_postmaster_start_time() >= interval '2 seconds' then 1 else 0 end" \
      2>>"$SECRETS/psql-readiness.err" || true)
    if [[ "$uptime_flag" == "1" ]]; then
      psql_ready=1
      break
    fi
  fi
  running=$(docker inspect -f '{{.State.Running}}' "$PG_CONTAINER" 2>/dev/null || true)
  [[ "$running" == "true" ]] || break
  sleep 1
done
if [[ "$psql_ready" != 1 ]]; then
  die "PostgreSQL 正式实例未就绪（psql verify-full select 1 超时；容器=$PG_CONTAINER）"
fi

PG_CONN="postgresql://rustboard@127.0.0.1:${PG_PORT}/rustboard?sslmode=verify-full"
psql_query() {
  PGPASSWORD="$PG_PASSWORD" \
    PGSSLMODE=verify-full \
    PGSSLROOTCERT="$CA_CERT" \
    psql "$PG_CONN" -At -v ON_ERROR_STOP=1 -c "$1" 2>>"$SECRETS/psql.err"
}

ssl_on=$(psql_query 'show ssl') || die "psql verify-full 连接 PostgreSQL 失败"
ssl_stat=$(psql_query 'select ssl from pg_stat_ssl where pid = pg_backend_pid()') \
  || die "psql 查询 pg_stat_ssl 失败"
if [[ "$ssl_on" == "on" && ( "$ssl_stat" == "t" || "$ssl_stat" == "true" ) ]]; then
  {
    printf 'show ssl = %s\n' "$ssl_on"
    printf 'pg_stat_ssl.ssl = %s\n' "$ssl_stat"
    printf 'connection = sslmode=verify-full, rootcert=%s\n' "$CA_CERT"
  } >"$EVIDENCE/pg-verify.txt"
  pass_case "PostgreSQL 16 ssl=on；psql sslmode=verify-full 连接成功"
else
  fail_case "PostgreSQL TLS 未生效（show ssl=${ssl_on:-空}, pg_stat_ssl.ssl=${ssl_stat:-空}）"
  die "PostgreSQL TLS 前置验证失败"
fi

# ---------- hub 配置：PG DSN + 顶层 db_sslrootcert ----------

HUB_CONFIG="$SECRETS/hub.toml"
HUB_DATA="$SECRETS/hub-data"
mkdir -p -- "$HUB_DATA"
chmod 0700 -- "$HUB_DATA"

"$HUB_BIN" init \
  --config "$HUB_CONFIG" \
  --data-dir "$HUB_DATA" \
  --agent-listen "127.0.0.1:${AGENT_PORT}" \
  --admin-listen "127.0.0.1:${ADMIN_PORT}" \
  --advertise 127.0.0.1 \
  --san localhost \
  --san 127.0.0.1 \
  --ca-days 2 \
  --server-cert-days 2 \
  --client-cert-days 2 \
  --renew-before-days 1 \
  >"$SECRETS/hub-init.out" 2>"$SECRETS/hub-init.err" \
  || die "rustboard-hub init 失败"
[[ -f "$HUB_CONFIG" ]] || die "hub init 未生成配置: $HUB_CONFIG"
chmod 0600 -- "$HUB_CONFIG"
HUB_ADMIN_TOKEN=$(python3 - "$HUB_CONFIG" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    print(tomllib.load(handle)["admin_token"])
PY
) || die "读取 hub admin_token 失败"
[[ -n "$HUB_ADMIN_TOKEN" ]] || die "hub 配置缺少 admin_token"

# 在第一个 [section] 之前插入顶层 db_sslrootcert；database 改成 PG DSN；
# self_monitor=false、sample_interval_ms=1000。
python3 - "$HUB_CONFIG" "$SECRETS/dsn.txt" "$CA_CERT" <<'PY'
import json
import re
import sys

config_path, dsn_path, ca_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(config_path, encoding="utf-8") as handle:
    text = handle.read()
with open(dsn_path, encoding="utf-8") as handle:
    dsn = handle.read().strip()

lines = text.splitlines()


def set_scalar(lines, key, value):
    pattern = re.compile(rf"^{re.escape(key)}\s*=")
    hits = [idx for idx, line in enumerate(lines) if pattern.match(line)]
    if len(hits) != 1:
        raise SystemExit(f"{key} 期望恰好一行，实际 {len(hits)}")
    lines[hits[0]] = f"{key} = {json.dumps(value)}"


set_scalar(lines, "database", dsn)
set_scalar(lines, "self_monitor", False)
set_scalar(lines, "sample_interval_ms", 1000)

# 无论旧配置把 db_sslrootcert 写在哪里，先全部删掉，再插到第一个 section 之前。
lines = [line for line in lines if not re.match(r"^db_sslrootcert\s*=", line)]
section_index = next(
    (idx for idx, line in enumerate(lines) if line.startswith("[")),
    len(lines),
)
lines.insert(section_index, f"db_sslrootcert = {json.dumps(ca_path)}")
with open(config_path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines) + "\n")
PY

ro_count=$(grep -c '^db_sslrootcert[[:space:]]*=' "$HUB_CONFIG" || true)
ro_line=$(grep -n '^db_sslrootcert[[:space:]]*=' "$HUB_CONFIG" | head -1 | cut -d: -f1 || true)
first_section=$(grep -n '^\[' "$HUB_CONFIG" | head -1 | cut -d: -f1 || true)
if [[ "$ro_count" == "1" && -n "$ro_line" && -n "$first_section" && "$ro_line" -lt "$first_section" ]]; then
  pass_case "hub 配置：db_sslrootcert 位于顶层（第一个 [section] 之前）"
else
  fail_case "hub 配置：db_sslrootcert 不在顶层（count=${ro_count:-0}, line=${ro_line:-无}, section=${first_section:-无}）"
  die "db_sslrootcert 未写入顶层，TLS 根证书会被静默忽略"
fi

if python3 - "$HUB_CONFIG" "$SECRETS/dsn.txt" <<'PY'
import sys
import tomllib

config_path, dsn_path = sys.argv[1], sys.argv[2]
with open(config_path, "rb") as handle:
    config = tomllib.load(handle)
with open(dsn_path, encoding="utf-8") as handle:
    expected_dsn = handle.read().strip()
assert config["database"] == expected_dsn, "database 与 PG DSN 不一致"
assert config["self_monitor"] is False, "self_monitor 未关闭"
assert config["sample_interval_ms"] == 1000, "sample_interval_ms 不是 1000"
assert config.get("db_sslrootcert"), "db_sslrootcert 缺失"
PY
then
  pass_case "hub 配置：PG DSN（密码 URL 编码）、self_monitor=false、sample_interval_ms=1000"
else
  fail_case "hub 配置：DSN / self_monitor / sample_interval_ms 不符合要求"
  die "hub 配置内容不正确"
fi

{
  python3 - "$HUB_CONFIG" <<'PY'
import re
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    config = tomllib.load(handle)
dsn = re.sub(r"(postgres(?:ql)?://[^/\s:@]+:)[^@\s]+(@)", r"\1***\2", config["database"])
print(f"database = {dsn}")
print(f"db_sslrootcert = {config.get('db_sslrootcert')}")
print(f"self_monitor = {config['self_monitor']}")
print(f"sample_interval_ms = {config['sample_interval_ms']}")
print(f"admin_listen = {config['admin_listen']}")
print(f"agent_listen = {config['agent_listen']}")
PY
} >"$EVIDENCE/config-summary.txt"

# ---------- hub + agent ----------

ADMIN_URL="http://127.0.0.1:${ADMIN_PORT}/healthz"
wait_health() {
  local pid=$1
  for _ in $(seq 1 150); do
    if curl -fsS --max-time 1 -o /dev/null "$ADMIN_URL" 2>/dev/null; then
      return 0
    fi
    if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
      return 1
    fi
    sleep 0.2
  done
  return 1
}

"$HUB_BIN" run --config "$HUB_CONFIG" >"$SECRETS/hub.log" 2>&1 &
HUB_PID=$!
if wait_health "$HUB_PID"; then
  pass_case "hub 以 PG DSN + db_sslrootcert 启动，/healthz 200"
else
  fail_case "hub 启动失败或 /healthz 未就绪"
  die "hub 启动失败（证据目录会保留脱敏后的 hub.log）"
fi

# agent add：token 只写临时文件，不进入 argv / 证据。
"$HUB_BIN" agent add --config "$HUB_CONFIG" --name e2e-agent \
  >"$SECRETS/agent-add.out" 2>"$SECRETS/agent-add.err" \
  || die "hub agent add 失败"
python3 - "$SECRETS/agent-add.out" "$SECRETS/enroll-token" "$SECRETS/agent-fingerprint" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
token = re.search(r"^[ \t]+([0-9a-f]{64})$", text, re.MULTILINE)
fingerprint = re.search(r"--fingerprint ([0-9a-f]{64})", text)
if not token or not fingerprint:
    raise SystemExit("agent add 输出中找不到 token 或指纹")
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    handle.write(token.group(1) + "\n")
with open(sys.argv[3], "w", encoding="utf-8") as handle:
    handle.write(fingerprint.group(1) + "\n")
PY
chmod 0600 -- "$SECRETS/enroll-token" "$SECRETS/agent-fingerprint"
ENROLL_TOKEN=$(<"$SECRETS/enroll-token")
AGENT_FP=$(<"$SECRETS/agent-fingerprint")
[[ "$ENROLL_TOKEN" =~ ^[0-9a-f]{64}$ ]] || die "解析 enrollment token 失败"
[[ "$AGENT_FP" =~ ^[0-9a-f]{64}$ ]] || die "解析 server fingerprint 失败"
write_secret_list

AGENT_CONFIG="$SECRETS/agent.toml"
AGENT_DATA="$SECRETS/agent-data"
mkdir -p -- "$AGENT_DATA"
chmod 0700 -- "$AGENT_DATA"
"$AGENT_BIN" init \
  --config "$AGENT_CONFIG" \
  --hub "wss://127.0.0.1:${AGENT_PORT}/agent/ws" \
  --fingerprint "$AGENT_FP" \
  --name e2e-agent \
  --data-dir "$AGENT_DATA" \
  >"$SECRETS/agent-init.out" 2>&1 \
  || die "rustboard-agent init 失败"
# token 通过 0600 文件注入，避免出现在 agent init 的 argv 中。
python3 - "$AGENT_CONFIG" "$SECRETS/enroll-token" <<'PY'
import json
import re
import sys

config_path, token_path = sys.argv[1], sys.argv[2]
with open(config_path, encoding="utf-8") as handle:
    text = handle.read()
with open(token_path, encoding="utf-8") as handle:
    token = handle.read().strip()
text, count = re.subn(r"^token\s*=.*$", f"token = {json.dumps(token)}", text, count=1, flags=re.MULTILINE)
if count != 1:
    raise SystemExit("agent 配置中找不到 token 行")
with open(config_path, "w", encoding="utf-8") as handle:
    handle.write(text)
PY
chmod 0600 -- "$AGENT_CONFIG"
if [[ "$(stat -c '%a' "$AGENT_CONFIG")" == "600" ]] \
  && python3 - "$AGENT_CONFIG" "$SECRETS/enroll-token" <<'PY'
import sys
import tomllib

with open(sys.argv[1], "rb") as handle:
    config = tomllib.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    token = handle.read().strip()
assert config["token"] == token, "agent 配置 token 不一致"
assert config["hub_url"].startswith("wss://127.0.0.1:"), "agent hub_url 不是本机 wss"
PY
then
  pass_case "hub agent add 生成一次性 token；agent 配置以 0600 写入并含 wss 地址"
else
  fail_case "agent 配置写入/token/权限不符合要求"
  die "agent 配置不正确"
fi

"$AGENT_BIN" run --config "$AGENT_CONFIG" >"$SECRETS/agent.log" 2>&1 &
AGENT_PID=$!

agent_online=0
for _ in $(seq 1 120); do
  row=$(psql_query "select agent_id || '|' || status from agents order by created_at desc limit 1" 2>/dev/null || true)
  if [[ "$row" == *"|online" ]]; then
    AGENT_ID=${row%%|*}
    agent_online=1
    break
  fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    break
  fi
  sleep 0.5
done
if [[ "$agent_online" == 1 && -n "$AGENT_ID" ]]; then
  {
    printf 'agent_id = %s\n' "$AGENT_ID"
    printf 'status = online\n'
  } >"$EVIDENCE/agent-online.txt"
  pass_case "真实 agent 完成 enroll 并 online（agent_id 已记录）"
else
  fail_case "真实 agent 未在超时内 online"
  die "agent 未连接（检查 hub.log / agent.log 脱敏副本）"
fi

samples=0
batches=0
agents=0
for _ in $(seq 1 120); do
  samples=$(psql_query 'select count(*) from samples' 2>/dev/null || true)
  batches=$(psql_query 'select count(*) from ingest_batches' 2>/dev/null || true)
  agents=$(psql_query 'select count(*) from agents' 2>/dev/null || true)
  if [[ "$samples" =~ ^[0-9]+$ && "$batches" =~ ^[0-9]+$ && "$agents" =~ ^[0-9]+$ ]]; then
    if (( samples > 0 && batches > 0 && agents > 0 )); then
      break
    fi
  fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    break
  fi
  sleep 0.5
done
if [[ "$samples" =~ ^[0-9]+$ && "$batches" =~ ^[0-9]+$ && "$agents" =~ ^[0-9]+$ ]] \
  && (( samples > 0 && batches > 0 && agents > 0 )); then
  printf '# first run\nsamples=%s\ningest_batches=%s\nagents=%s\n' \
    "$samples" "$batches" "$agents" >"$EVIDENCE/psql-counts.txt"
  pass_case "PG 中已落库至少 1 批样本（samples=${samples}, ingest_batches=${batches}, agents=${agents}）"
else
  printf '# first run\nsamples=%s\ningest_batches=%s\nagents=%s\n' \
    "${samples:-?}" "${batches:-?}" "${agents:-?}" >"$EVIDENCE/psql-counts.txt"
  fail_case "PG 中未观察到 samples/ingest_batches/agents > 0"
  die "未观察到 agent 上报写入 PostgreSQL"
fi

# 正路径日志必须已脱敏；先检查原始日志，再发布脱敏副本。
if python3 - "$SECRETS/hub.log" "$SECRETS/agent.log" "$SECRETS/sanitize-secrets.txt" <<'PY'
import sys

secret_file = sys.argv[3]
secrets = [line for line in open(secret_file, encoding="utf-8").read().splitlines() if line]
for path in sys.argv[1:3]:
    data = open(path, "rb").read().decode("utf-8", "replace")
    for value in secrets:
        if value in data:
            raise SystemExit(1)
PY
then
  pass_case "hub/agent 日志不含 PG 密码、完整 DSN、admin token 或 enrollment token"
else
  fail_case "hub/agent 日志出现 secret（具体值不打印）"
fi
if grep -Fq -- '***' "$SECRETS/hub.log"; then
  pass_case "hub 日志中的 PostgreSQL DSN 已脱敏为 ***"
else
  fail_case "hub 日志未出现 *** 脱敏标记"
fi
# 原始日志的发布统一延迟到 raw scan 之后（见 finalize_runtime），这里不发布副本。

# ---------- 重启持久化 ----------

stop_pid "$AGENT_PID"
AGENT_PID=""
stop_pid "$HUB_PID"
HUB_PID=""

before_samples=$(psql_query 'select count(*) from samples') || die "重启前查询 samples 失败"
before_batches=$(psql_query 'select count(*) from ingest_batches') || die "重启前查询 ingest_batches 失败"
before_agents=$(psql_query 'select count(*) from agents') || die "重启前查询 agents 失败"
printf '# after stop, before restart\nsamples=%s\ningest_batches=%s\n' \
  "$before_samples" "$before_batches" >>"$EVIDENCE/psql-counts.txt"

"$HUB_BIN" run --config "$HUB_CONFIG" >"$SECRETS/hub-restart.log" 2>&1 &
HUB_PID=$!
if wait_health "$HUB_PID"; then
  pass_case "停止后重启 hub（同一 PG），/healthz 200"
else
  fail_case "重启 hub 后 /healthz 未就绪"
  die "重启 hub 失败（证据目录会保留脱敏后的 hub-restart.log）"
fi

after_samples=$(psql_query 'select count(*) from samples') || die "重启后查询 samples 失败"
after_batches=$(psql_query 'select count(*) from ingest_batches') || die "重启后查询 ingest_batches 失败"
after_agents=$(psql_query 'select count(*) from agents') || die "重启后查询 agents 失败"
printf '# after restart\nsamples=%s\ningest_batches=%s\nagents=%s\n' \
  "$after_samples" "$after_batches" "$after_agents" >>"$EVIDENCE/psql-counts.txt"

if [[ "$after_samples" =~ ^[0-9]+$ ]] && (( after_samples >= before_samples )); then
  pass_case "重启后 samples 数量不减少（${before_samples} -> ${after_samples}）"
else
  fail_case "重启后 samples 数量减少（${before_samples} -> ${after_samples}）"
fi
if [[ "$after_batches" =~ ^[0-9]+$ ]] && (( after_batches >= before_batches )); then
  pass_case "重启后 ingest_batches 数量不减少（${before_batches} -> ${after_batches}）"
else
  fail_case "重启后 ingest_batches 数量减少（${before_batches} -> ${after_batches}）"
fi
agent_still=$(psql_query "select count(*) from agents where agent_id = '${AGENT_ID}'" || true)
if [[ "$agent_still" =~ ^[0-9]+$ ]] && (( agent_still == 1 )) && (( after_agents > 0 )); then
  pass_case "重启后 agent 记录仍在（agent_id 可查询，agents=${after_agents}）"
else
  fail_case "重启后 agent 记录丢失（agent_id 查询=${agent_still:-?}, agents=${after_agents:-?}）"
fi

stop_pid "$HUB_PID"
HUB_PID=""

# ---------- 负向：错误 CA / 根证书路径 / 主机名 ----------

NEG_CONF_DIR="$SECRETS/negative-configs"
mkdir -p -- "$NEG_CONF_DIR"
MISSING_CA="$SECRETS/missing-ca.pem"
CA_DIR="$SECRETS/ca-directory"
CA_LINK="$SECRETS/ca-link.pem"
mkdir -p -- "$CA_DIR"
ln -sfn -- "$CA_CERT" "$CA_LINK"

python3 - "$HUB_CONFIG" "$NEG_CONF_DIR" "$WRONG_CA" "$MISSING_CA" "$CA_DIR" "$CA_LINK" <<'PY'
import json
import re
import sys

base_path, out_dir, wrong_ca, missing_ca, ca_dir, ca_link = sys.argv[1:]
with open(base_path, encoding="utf-8") as handle:
    base = handle.read()

variants = {
    "wrong-ca": wrong_ca,
    "missing-ca": missing_ca,
    "dir-ca": ca_dir,
    "symlink-ca": ca_link,
}
for name, path in variants.items():
    lines = base.splitlines()
    hits = [idx for idx, line in enumerate(lines) if re.match(r"^db_sslrootcert\s*=", line)]
    if len(hits) != 1:
        raise SystemExit("base 配置的 db_sslrootcert 行数不为 1")
    lines[hits[0]] = f"db_sslrootcert = {json.dumps(path)}"
    with open(f"{out_dir}/{name}.toml", "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
PY

run_hub_expect_failure() {
  local config=$1 log=$2 rc=0
  if timeout -k 5 20 "$HUB_BIN" run --config "$config" >"$log" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  printf '%s\n' "$rc"
}

# 1) 错误 CA：先用 psql verify-full 证明证书确实不被信任，再验证 hub 拒绝启动。
#    已知限制：tokio-postgres 的 Kind::Tls 只暴露 "error performing TLS handshake"，
#    不携带 rustls 的 UnknownIssuer；因此 hub 日志只能断言通用 TLS 文本，
#    具体“CA 不被信任”由下面的 psql 前置用例独立证明，不伪装成更具体的错误。
wrong_psql_rc=0
if PGPASSWORD="$PG_PASSWORD" \
  PGSSLMODE=verify-full \
  PGSSLROOTCERT="$WRONG_CA" \
  psql "$PG_CONN" -At -c 'select 1' \
  >"$SECRETS/psql-wrong-ca.out" 2>"$SECRETS/psql-wrong-ca.err"; then
  wrong_psql_rc=0
else
  wrong_psql_rc=$?
fi
if [[ "$wrong_psql_rc" -ne 0 ]] \
  && grep -Eqi 'certificate|SSL error|verify' "$SECRETS/psql-wrong-ca.err"; then
  pass_case "错误 CA 前置：psql verify-full 被证书校验拒绝（证书不被信任）"
else
  fail_case "错误 CA 前置：psql verify-full 未按证书校验失败（rc=${wrong_psql_rc}）"
fi

wrong_log="$SECRETS/negative-wrong-ca.log"
wrong_rc=$(run_hub_expect_failure "$NEG_CONF_DIR/wrong-ca.toml" "$wrong_log")
if [[ "$wrong_rc" -ne 0 && "$wrong_rc" -ne 124 ]] \
  && grep -Fq -- 'error performing TLS handshake' "$wrong_log" \
  && ! grep -Eq 'Connection refused|connection refused|os error 111|password authentication failed|database .* does not exist' "$wrong_log"; then
  pass_case "错误 CA：hub 启动非 0（rc=${wrong_rc}）且日志含 TLS handshake 错误"
else
  fail_case "错误 CA：hub 未按预期失败（rc=${wrong_rc}）或日志不像 TLS 失败"
fi
printf 'NOTE: 错误 CA 的 hub 日志仅含 driver 泛化的 "error performing TLS handshake"（tokio-postgres 不暴露 rustls 具体 cause）；CA 不被信任已由 psql verify-full 前置用例证明。\n'
if ! file_has_sensitive_data "$wrong_log" && grep -Fq -- '***' "$wrong_log"; then
  pass_case "错误 CA：日志不含密码/完整 DSN，且 DSN 已脱敏为 ***"
else
  fail_case "错误 CA：日志泄露 secret 或缺少 *** 脱敏"
fi

# 2) 根证书缺失 / 目录 / 符号链接：配置校验阶段必须非 0。
check_roots() {
  local name=$1 expected=$2 config="$NEG_CONF_DIR/$1.toml" log rc
  log="$SECRETS/negative-$name.log"
  rc=$(run_hub_expect_failure "$config" "$log")
  if [[ "$rc" -ne 0 && "$rc" -ne 124 ]] && grep -Fq -- "$expected" "$log"; then
    pass_case "db_sslrootcert ${name}：配置校验非 0 且错误点名（rc=${rc}）"
  else
    fail_case "db_sslrootcert ${name}：未在配置校验阶段拒绝（rc=${rc}）"
  fi
  if file_has_sensitive_data "$log"; then
    fail_case "db_sslrootcert ${name}：错误输出泄露 secret"
  fi
  printf '%s rc=%s expected=%s\n' "$name" "$rc" "$expected" >>"$EVIDENCE/negative-summary.txt"
}

check_roots "missing-ca" "db_sslrootcert 文件不存在"
check_roots "dir-ca" "db_sslrootcert 指向目录"
check_roots "symlink-ca" "db_sslrootcert 指向符号链接"
printf 'psql-wrong-ca rc=%s expected=证书校验错误\n' "$wrong_psql_rc" >>"$EVIDENCE/negative-summary.txt"
printf 'wrong-ca rc=%s expected=error performing TLS handshake（driver 泛化，具体 cause 由 psql 证明）\n' \
  "$wrong_rc" >>"$EVIDENCE/negative-summary.txt"

# 3) 主机名不匹配：Python TCP 代理监听 127.0.0.2，转发到 127.0.0.1:PG。
cat >"$SECRETS/proxy.py" <<'PY'
import socket
import socketserver
import sys
import threading

listen_port = int(sys.argv[1])
target_port = int(sys.argv[2])
print_lock = threading.Lock()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            upstream = socket.create_connection(("127.0.0.1", target_port), timeout=10)
        except OSError:
            return
        # 只记录“已成功连到 PG”，不记录任何载荷；用于证明 hub 不是端口/连接错误。
        with print_lock:
            print("CONNECT", flush=True)

        def pipe(src, dst):
            try:
                while True:
                    chunk = src.recv(65536)
                    if not chunk:
                        break
                    dst.sendall(chunk)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        thread = threading.Thread(target=pipe, args=(self.request, upstream), daemon=True)
        thread.start()
        pipe(upstream, self.request)
        thread.join(timeout=1)
        try:
            upstream.close()
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


server = Server(("127.0.0.2", listen_port), Handler)
print(f"READY {listen_port}", flush=True)
server.serve_forever()
PY

python3 "$SECRETS/proxy.py" "$PROXY_PORT" "$PG_PORT" \
  >"$SECRETS/proxy.log" 2>&1 &
PROXY_PID=$!
proxy_ready=0
for _ in $(seq 1 50); do
  if grep -q '^READY ' "$SECRETS/proxy.log" 2>/dev/null; then
    proxy_ready=1
    break
  fi
  kill -0 "$PROXY_PID" 2>/dev/null || break
  sleep 0.1
done
[[ "$proxy_ready" == 1 ]] || die "Python TCP 代理未在 127.0.0.2:${PROXY_PORT} 就绪"

if PGPASSWORD="$PG_PASSWORD" \
  PGSSLMODE=require \
  PGSSLROOTCERT="$CA_CERT" \
  psql "postgresql://rustboard@127.0.0.2:${PROXY_PORT}/rustboard?sslmode=require" \
  -At -c 'show ssl' 2>"$SECRETS/psql-proxy-require.err" | grep -qx 'on'; then
  pass_case "主机名负向前置：经 127.0.0.2 代理可建立 TLS（sslmode=require, show ssl=on）"
else
  fail_case "主机名负向前置：代理未转发到 PostgreSQL"
  die "代理链路不可用，无法验证 hostname 不匹配"
fi

proxy_verify_rc=0
if PGPASSWORD="$PG_PASSWORD" \
  PGSSLMODE=verify-full \
  PGSSLROOTCERT="$CA_CERT" \
  psql "postgresql://rustboard@127.0.0.2:${PROXY_PORT}/rustboard?sslmode=verify-full" \
  -At -c 'show ssl' \
  >"$SECRETS/psql-proxy-verify.out" 2>"$SECRETS/psql-proxy-verify.err"; then
  proxy_verify_rc=0
else
  proxy_verify_rc=$?
fi
if [[ "$proxy_verify_rc" -ne 0 ]] \
  && grep -Eqi 'does not match host name|hostname|主机名' "$SECRETS/psql-proxy-verify.err"; then
  pass_case "主机名负向前置：psql verify-full 因证书不含 127.0.0.2 被拒"
else
  fail_case "主机名负向前置：psql verify-full 未按 hostname 校验失败（rc=${proxy_verify_rc}）"
fi
# 主机名不匹配配置：DSN 的 host 改成 127.0.0.2，证书仍只有 127.0.0.1。
python3 - "$HUB_CONFIG" "$NEG_CONF_DIR/hostname-mismatch.toml" "$PG_PORT" "$PROXY_PORT" <<'PY'
import re
import sys

base_path, out_path, pg_port, proxy_port = sys.argv[1:]
with open(base_path, encoding="utf-8") as handle:
    text = handle.read()
old = f"127.0.0.1:{pg_port}/"
new = f"127.0.0.2:{proxy_port}/"
if old not in text:
    raise SystemExit("base DSN 中找不到 127.0.0.1:PG_PORT")
if not re.search(r"^db_sslrootcert\s*=", text, re.MULTILINE):
    raise SystemExit("base 配置缺少顶层 db_sslrootcert")
with open(out_path, "w", encoding="utf-8") as handle:
    handle.write(text.replace(old, new, 1))
PY

# psql 前置用例的连接线程可能刚结束；给代理日志一个短暂落盘窗口，避免把
# 前置连接误记为 hub 的连接。
sleep 0.5
proxy_connects_before=$(grep -c '^CONNECT$' "$SECRETS/proxy.log" 2>/dev/null || true)
[[ "$proxy_connects_before" =~ ^[0-9]+$ ]] || proxy_connects_before=0
hostname_log="$SECRETS/negative-hostname-mismatch.log"
hostname_rc=$(run_hub_expect_failure "$NEG_CONF_DIR/hostname-mismatch.toml" "$hostname_log")
proxy_connects_after=$(grep -c '^CONNECT$' "$SECRETS/proxy.log" 2>/dev/null || true)
[[ "$proxy_connects_after" =~ ^[0-9]+$ ]] || proxy_connects_after=0

# 必须同时满足：非 0、走的是 127.0.0.2:代理端口、日志是 TLS 而非连接/认证错误、
# 代理实际收到并转发了连接（CONNECT 数增加）。
if [[ "$hostname_rc" -ne 0 && "$hostname_rc" -ne 124 ]] \
  && grep -Fq -- 'error performing TLS handshake' "$hostname_log" \
  && grep -Fq -- "127.0.0.2:${PROXY_PORT}" "$hostname_log" \
  && ! grep -Eq 'Connection refused|connection refused|os error 111|password authentication failed|database .* does not exist' "$hostname_log" \
  && (( proxy_connects_after > proxy_connects_before )); then
  pass_case "主机名不匹配：hub 非 0（rc=${hostname_rc}）、经代理、日志为 TLS handshake 失败"
else
  fail_case "主机名不匹配：hub 未按预期失败或并非经代理的 TLS 失败（rc=${hostname_rc}, CONNECT ${proxy_connects_before}->${proxy_connects_after}）"
fi
if grep -Eq 'NotValidForName|does not match host name|hostname|certificate' "$hostname_log"; then
  printf 'NOTE: 主机名不匹配 hub 日志包含具体 hostname/certificate 文本。\n'
else
  printf 'NOTE: 主机名不匹配 hub 日志仅含 driver 泛化的 "error performing TLS handshake"（tokio-postgres 不暴露 rustls 具体 cause）；hostname 原因由 psql verify-full 的明确 hostname 报错 + 代理 CONNECT 计数证明。\n'
fi
if (( proxy_connects_after > proxy_connects_before )); then
  pass_case "主机名负向：hub 确实经 127.0.0.2 代理连接到 PostgreSQL（CONNECT ${proxy_connects_before} -> ${proxy_connects_after}）"
else
  fail_case "主机名负向：代理未观察到 hub 连接（CONNECT ${proxy_connects_before} -> ${proxy_connects_after}）"
fi
if ! file_has_sensitive_data "$hostname_log" && grep -Fq -- '***' "$hostname_log"; then
  pass_case "主机名不匹配：日志不含密码/完整 DSN，且 DSN 已脱敏为 ***"
else
  fail_case "主机名不匹配：日志泄露 secret 或缺少 *** 脱敏"
fi
printf 'hostname-mismatch rc=%s connects=%s->%s expected=TLS hostname 校验错误\n' \
  "$hostname_rc" "$proxy_connects_before" "$proxy_connects_after" >>"$EVIDENCE/negative-summary.txt"

stop_pid "$PROXY_PID"
PROXY_PID=""

# ---------- 收尾：raw scan -> 脱敏发布 -> 证据扫描 ----------

# 必须在发布任何脱敏副本之前扫描所有原始日志；命中会删除原始文件并直接 FAIL。
collect_postgres_log || true
scan_raw_logs || true
if [[ "$RAW_SCAN_DONE" == 1 && "$RAW_SECRET_COUNT" == 0 ]] && (( RAW_SCANNED_COUNT > 0 )); then
  pass_case "发布前原始日志扫描：${RAW_SCANNED_COUNT} 个日志无密码/完整 DSN/token/私钥"
else
  fail_case "发布前原始日志扫描未通过（scanned=${RAW_SCANNED_COUNT}, blocked=${RAW_SECRET_COUNT}, complete=${RAW_SCAN_DONE}）"
fi

finalize_runtime

if (( CLEANUP_FAILED != 0 )); then
  fail_case "清理失败（容器/日志/secret 目录），详见 cleanup-failures.txt"
fi

# 用 Python 扫描证据目录；secret 只从 0600 文件读取，不进入 argv。
if python3 - "$EVIDENCE" "$SECRETS/sanitize-secrets.txt" <<'PY'
import os
import re
import sys

evidence, secret_file = sys.argv[1], sys.argv[2]
secrets = [line for line in open(secret_file, encoding="utf-8").read().splitlines() if line]
leaked = []
key_re = re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
for root, _dirs, files in os.walk(evidence):
    for name in files:
        path = os.path.join(root, name)
        try:
            data = open(path, "rb").read()
        except OSError:
            continue
        text = data.decode("utf-8", "replace")
        if key_re.search(data) or any(value in text for value in secrets):
            leaked.append(path)
for path in leaked:
    try:
        os.remove(path)
    except OSError:
        pass
raise SystemExit(1 if leaked else 0)
PY
then
  pass_case "证据目录不含密码、完整 DSN、token 或私钥"
else
  fail_case "证据目录发现 secret，已删除相关文件（具体值不打印）"
fi

# .secrets 已经完成脱敏/扫描用途；在出 summary 前删除并记录失败。
if ! remove_secrets_dir; then
  fail_case "清理临时 secret 目录失败（需手工检查 $SECRETS）"
fi

{
  printf 'run=%s\n' "$STAMP"
  printf 'git_head=%s\n' "$HEAD_COMMIT"
  printf 'git_head_epoch=%s\n' "$HEAD_COMMIT_EPOCH"
  printf 'git_status_entries=%s\n' "$HEAD_DIRTY_ENTRIES"
  printf 'hub_sha256=%s\n' "$HUB_SHA256"
  printf 'hub_mtime=%s\n' "$HUB_MTIME"
  printf 'hub_older_than_head=%s\n' "$HUB_OLDER_THAN_HEAD"
  printf 'agent_sha256=%s\n' "$AGENT_SHA256"
  printf 'agent_mtime=%s\n' "$AGENT_MTIME"
  printf 'agent_older_than_head=%s\n' "$AGENT_OLDER_THAN_HEAD"
  printf 'postgres_image_id=%s\n' "$PG_IMAGE_ID"
  printf 'script_sha256=%s\n' "$SCRIPT_SHA256"
  printf 'hub_version=%s\n' "$HUB_VERSION"
  printf 'agent_version=%s\n' "$AGENT_VERSION"
  printf 'raw_log_scanned=%s\n' "$RAW_SCANNED_COUNT"
  printf 'raw_log_blocked=%s\n' "$RAW_SECRET_COUNT"
  printf 'raw_log_scan_complete=%s\n' "$RAW_SCAN_DONE"
  printf 'samples_before=%s samples_after=%s\n' "$before_samples" "$after_samples"
  printf 'ingest_batches_before=%s ingest_batches_after=%s\n' "$before_batches" "$after_batches"
  printf 'agents_before=%s agents_after=%s\n' "$before_agents" "$after_agents"
  printf 'cleanup_failed=%s\n' "$CLEANUP_FAILED"
  printf 'pass=%s fail=%s\n' "$PASS" "$FAIL"
} >"$EVIDENCE/summary.txt"

printf '\n'
if (( FAIL == 0 )); then
  # “全部 N 项通过”只在 EXIT cleanup 中、确认退出码 0 且清理成功后打印；
  # 这样 TERM/HUP/INT 中断绝不会输出成功结论。
  exit 0
fi
printf 'FAIL: %d 项失败，%d 项通过\n' "$FAIL" "$PASS"
exit 1
