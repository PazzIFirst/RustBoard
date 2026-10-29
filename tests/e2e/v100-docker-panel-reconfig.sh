#!/usr/bin/env bash
#
# P4 #79：Docker 中已初始化 panel_data 的直连 HTTPS 受控重配置 E2E。
#
# 严格按 docs/install/panel-tls.md §9 的顺序，从正常初始化后的 panel_data
# （/data 10001:10001）开始：
#   1) hub + panel 正常首启：panel 用共享 hub netns 的 127.0.0.1:8444 + 共享
#      admin token 首装，/data 归 10001:10001，记录 panel.toml 的 token /
#      admin_password_hash（只记录 sha256，不打印）；
#   2) 停 panel，备份 panel_data（备份留在 0700 临时目录，证据只记 sha256/字节数）；
#   3) docs §9 的 scoped chown：拒绝符号链接/子挂载，只把 /data、/data/etc、
#      /data/etc/rustboard、/data/var、/data/var/lib 与 /data/var/lib/rustboard
#      子树切 root（panel TLS 目录是 0700 私有目录，install 要求祖先
#      /data/etc/rustboard 也由 root 拥有；不是递归 chown /data）；
#   4) 以 root 执行 `rustboard-panel install --yes --force --no-systemd --prefix /data`
#      + TLS 参数（root 才能写 10001 属主 prefix 之外的必要路径），必须 exit 0；
#      失败保留脱敏日志并先恢复 10001；
#   5) 按 docs §9 恢复 10001（同样拒绝符号链接/子挂载 + -xdev + chown -h + 属主断言）；
#   6) 以 `--user 10001:10001` 启动 panel（不注入 HUB token env），等待
#      `https://panel.example.com:18080/healthz` 200（curl --cacert + --resolve，
#      校验 SNI/链/主机名），断言进程 UID、凭据 hash 不变、TLS/config 权限。
#
# 与 docs §9 的对应关系/环境说明：
#   - cert/key 只读挂到 docs 指定的 /run/rustboard-panel-tls/；token 以 0600
#     只读文件挂到 /run/rustboard/admin_token。root install 的一次性容器不挂
#     hub_run:/run/rustboard（compose 示例已说明只读挂载下无法再建 mountpoint）；
#   - `-p 18444:8444` 的宿主发布口无法访问 hub 管理口：hub 默认 admin_listen
#     是容器内 127.0.0.1:8444（管理面只绑回环），Docker DNAT 目标容器 IP，
#     不会走容器回环。脚本仍按设计发布 18443/18444/18080，但 hub 健康等待在
#     容器内用 127.0.0.1:8444（panel 共享 netns 访问的也是同一个回环）。
#
# 约束：
#   - 只创建本脚本的容器/volume/临时目录；不 pull 缺失镜像，不联网；
#   - 不打印 token / 密码 / 私钥；证据目录只写脱敏日志与摘要；
#   - 初始 panel 首装日志可能含一次性初始密码，按约定不采集；
#   - trap 清理容器/volume/临时目录；失败非零退出并保留证据目录。
#
# 依赖：Linux、Docker 24+（当前用户可访问 docker socket）、curl、openssl、tar、sha256sum、awk、find、stat。
# 用法：bash tests/e2e/v100-docker-panel-reconfig.sh
# 调试：HEALTH_TIMEOUT=300 放宽健康等待。
#
# cleanup/collect 仅由 trap 调用；容器内脚本的 $1/$2 是故意不展开的。
# shellcheck disable=SC2317,SC2016
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT" || {
  printf 'FATAL: 无法进入仓库根目录: %s\n' "$ROOT" >&2
  exit 1
}

HUB_IMAGE=${HUB_IMAGE:-ghcr.io/pazzifirst/rustboard-hub:local-s4}
PANEL_IMAGE=${PANEL_IMAGE:-ghcr.io/pazzifirst/rustboard-panel:local-s4}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-120}
HOST_AGENT_PORT=18443
HOST_ADMIN_PORT=18444
HOST_PANEL_PORT=18080

UTC_STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RUN_ID="rb-panel-reconfig-${UTC_STAMP}-$$"
EVIDENCE_DIR="target/docker-panel-reconfig-e2e/${UTC_STAMP}-$$"
SUMMARY="$EVIDENCE_DIR/summary.txt"
TMP=$(mktemp -d "/tmp/rb-panel-reconfig.XXXXXX")

HUB_VOL="${RUN_ID}-hub-data"
RUN_VOL="${RUN_ID}-run"
PANEL_VOL="${RUN_ID}-panel-data"
HUB_CT="${RUN_ID}-hub"
PANEL_CT="${RUN_ID}-panel"
INSTALL_CT="${RUN_ID}-install"

PASSES=0
FAILS=0
CLEANED=0
OWNER_PENDING=0
FINAL_PANEL_STARTED=0
HELPER_SEQ=0
HUB_PROBE=""
CERT="$TMP/panel-tls/cert.pem"
KEY="$TMP/panel-tls/key.pem"
TOKEN_SHA_BEFORE=""
PW_HASH_SHA_BEFORE=""
HUB_TOKEN_SHA=""

mkdir -p "$EVIDENCE_DIR" "$TMP/panel-tls" "$TMP/backup"
chmod 0700 "$TMP" "$TMP/panel-tls" "$TMP/backup"
: >"$SUMMARY"

# ---------------------------------------------------------------------------
# 输出与脱敏
# ---------------------------------------------------------------------------

log() {
  printf '%s\n' "$*"
  printf '%s\n' "$*" >>"$SUMMARY"
}

pass() {
  PASSES=$((PASSES + 1))
  local line="PASS [$1] $2"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >>"$SUMMARY"
}

fail() {
  FAILS=$((FAILS + 1))
  local line="FAIL [$1] $2"
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" >>"$SUMMARY"
}

die() {
  printf 'FATAL: %s\n' "$*" >&2
  printf '\n===== docker-panel-reconfig e2e: PASS=%s FAIL=%s =====\n' \
    "$PASSES" "$FAILS" >&2
  exit 1
}

check_eq() {
  local id=$1 desc=$2 expected=$3 actual=$4
  if [ "$expected" = "$actual" ]; then
    pass "$id" "$desc"
  else
    fail "$id" "$desc（期望 [$expected]，实际 [$actual]）"
  fi
}

# 容器输出/日志写证据前统一脱敏：token/密码/私钥、64 hex、长随机值。
redact_stream() {
  sed -E \
    -e '/(密码|password|passwd|admin_token|admin-token|hub_token|hub-token|token|secret)[^:：=]*[:：=].*/I s/.*/<redacted sensitive line>/' \
    -e 's/(--(token|token_file|token-file|admin-token|hub-token)(-file)?[[:space:]=]+)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/((admin_token|token|secret|password|passwd)[[:space:]]*=[[:space:]]*)"[^"]*"/\1"<redacted>"/Ig' \
    -e 's/((admin_token|token|secret|password|passwd)[[:space:]]*[=:][[:space:]]*)[^[:space:]",]+/\1<redacted>/Ig' \
    -e 's/((初始)?密码[^:：]*[:：][[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' \
    -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._~+\/=-]+/\1<redacted>/Ig' \
    -e 's/-----BEGIN [A-Z ]*PRIVATE KEY-----.*/<redacted-private-key>/g' \
    -e 's/\b[0-9a-fA-F]{64}\b/<redacted-64hex>/g' \
    -e 's/\b[A-Za-z0-9_-]{40,}\b/<redacted-long-value>/g'
}

# 文本哈希：只输出 sha256，不输出原值。
hash_string() {
  printf '%s' "$1" | sha256sum | awk '{print $1}'
}

# 从 panel.toml 只取一个字符串字段；找不到或重复都必须失败（不打印其他字段）。
config_value() {
  local file=$1 key=$2 value lines
  value=$(sed -nE "s/^${key}[[:space:]]*=[[:space:]]*\"([^\"]*)\"$/\\1/p" "$file")
  lines=$(printf '%s\n' "$value" | grep -c . || true)
  if [ "$lines" -ne 1 ]; then
    die "无法从 $(basename -- "$file") 唯一读取字段 $key"
  fi
  printf '%s' "$value"
}

# 宿主端口占用检查：优先 ss，其次 bash /dev/tcp 探连。
port_in_use() {
  local port=$1
  if command -v ss >/dev/null 2>&1; then
    ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN
    return
  fi
  (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
}

# 以 /bin/sh 覆盖 entrypoint 跑一次性 helper（绕过首装/自动 chown 逻辑）。
helper_sh() {
  HELPER_SEQ=$((HELPER_SEQ + 1))
  docker run --rm --name "${RUN_ID}-h${HELPER_SEQ}" --entrypoint /bin/sh "$@"
}

# docs §9 第 3 步：恢复 10001，并在同一容器内断言无残留非 10001 属主。
restore_owner_10001() {
  helper_sh -v "$PANEL_VOL:/data" "$PANEL_IMAGE" -c '
    set -eu
    bad=$(find /data -xdev -type l -print -quit)
    [ -z "$bad" ] || { echo "拒绝：$bad 是符号链接" >&2; exit 1; }
    dev=$(stat -c %d /data)
    bad_mount=$(find /data -xdev -type d -exec stat -c "%d %n" {} + \
      | awk -v dev="$dev" "\$1 != dev { print \$2; exit }")
    [ -z "$bad_mount" ] || { echo "拒绝：$bad_mount 是子挂载" >&2; exit 1; }
    find /data -xdev -exec chown -h 10001:10001 {} +
    bad_owner=$(find /data -xdev \( ! -uid 10001 -o ! -gid 10001 \) -print -quit)
    [ -z "$bad_owner" ] || { echo "属主未恢复: $bad_owner" >&2; exit 1; }
    printf "%s %s %s\n" \
      "$(stat -c %u:%g /data)" \
      "$(stat -c %a /data/etc/rustboard/panel.toml)" \
      "$(stat -c %a /data/etc/rustboard/panel-tls/key.pem)"
  '
}

collect_evidence_logs() {
  # 只采集不含初始密码的日志：hub 全程，panel 只在完成 TLS 重配并重启后采集。
  if docker inspect "$HUB_CT" >/dev/null 2>&1; then
    docker logs "$HUB_CT" 2>&1 | redact_stream >"$EVIDENCE_DIR/hub.log" 2>/dev/null || true
    docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$HUB_CT" \
      >"$EVIDENCE_DIR/hub-state.txt" 2>/dev/null || true
  fi
  if [ "$FINAL_PANEL_STARTED" = "1" ] && docker inspect "$PANEL_CT" >/dev/null 2>&1; then
    docker logs "$PANEL_CT" 2>&1 | redact_stream >"$EVIDENCE_DIR/panel-final.log" 2>/dev/null || true
    docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$PANEL_CT" \
      >"$EVIDENCE_DIR/panel-state.txt" 2>/dev/null || true
  fi
}

cleanup() {
  local rc=$?
  local ids id
  if [ "$CLEANED" = "1" ]; then
    exit "$rc"
  fi
  CLEANED=1
  collect_evidence_logs || true
  ids=$(docker ps -aq --filter "name=${RUN_ID}" 2>/dev/null || true)
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    docker rm -f "$id" >/dev/null 2>&1 || true
  done <<<"$ids"
  if [ "$OWNER_PENDING" = "1" ]; then
    restore_owner_10001 >/dev/null 2>&1 || true
  fi
  docker volume rm "$HUB_VOL" "$RUN_VOL" "$PANEL_VOL" >/dev/null 2>&1 || true
  rm -rf "$TMP"
  if [ "$rc" -ne 0 ]; then
    log "未通过；脱敏证据保留在 $EVIDENCE_DIR"
  else
    log "证据目录: $EVIDENCE_DIR（仅脱敏日志/摘要）"
  fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# 0. 前置检查
# ---------------------------------------------------------------------------

log "P4 #79 Docker panel_data 受控 TLS 重配置 E2E"
log "镜像: $HUB_IMAGE / $PANEL_IMAGE"
log "证据目录: $EVIDENCE_DIR"

# 测试本身只通过 Docker 操作卷；宿主无需 root（GitHub runner 非 root）。
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "缺少依赖命令: $1"
}
for cmd in docker curl openssl sha256sum awk find stat tar timeout tr; do
  need_cmd "$cmd"
done
docker info >/dev/null 2>&1 || die "无法访问 Docker daemon"
DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null) \
  || die "无法读取 Docker 版本"
DOCKER_MAJOR=${DOCKER_VERSION%%.*}
case "$DOCKER_MAJOR" in
  '' | *[!0-9]*) die "无法解析 Docker 版本: $DOCKER_VERSION" ;;
esac
[ "$DOCKER_MAJOR" -ge 24 ] || die "需要 Docker 24+，当前 $DOCKER_VERSION"

missing_images=""
for image in "$HUB_IMAGE" "$PANEL_IMAGE"; do
  docker image inspect "$image" >/dev/null 2>&1 || missing_images="$missing_images $image"
done
if [ -n "$missing_images" ]; then
  die "本地缺少镜像:$missing_images（脚本不联网 pull；请先构建或设置 HUB_IMAGE/PANEL_IMAGE）"
fi

for port in "$HOST_AGENT_PORT" "$HOST_ADMIN_PORT" "$HOST_PANEL_PORT"; do
  if port_in_use "$port"; then
    die "宿主端口 $port 已被占用（不跳过；请先释放后重跑）"
  fi
done
log "Docker $DOCKER_VERSION；宿主端口 $HOST_AGENT_PORT/$HOST_ADMIN_PORT/$HOST_PANEL_PORT 空闲"

HUB_VERSION=$(docker run --rm "$HUB_IMAGE" rustboard-hub --version 2>/dev/null || true)
PANEL_VERSION=$(docker run --rm "$PANEL_IMAGE" rustboard-panel --version 2>/dev/null || true)
log "镜像内版本: hub=[${HUB_VERSION:-unknown}] panel=[${PANEL_VERSION:-unknown}]"

# 自签面板证书：CN/SAN panel.example.com，有效期 2 天，key 0600。
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 2 \
  -keyout "$KEY" -out "$CERT" \
  -subj "/CN=panel.example.com" \
  -addext "subjectAltName=DNS:panel.example.com" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth" \
  >"$TMP/openssl.log" 2>&1 || die "生成面板 TLS 自签证书失败（见 $TMP/openssl.log）"
chmod 0600 "$KEY"
chmod 0644 "$CERT"
openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null \
  | grep -q 'DNS:panel.example.com' || die "自签证书 SAN 未覆盖 panel.example.com"
{
  openssl x509 -in "$CERT" -noout -subject -issuer -dates -ext subjectAltName
  openssl x509 -in "$CERT" -noout -fingerprint -sha256
} >"$EVIDENCE_DIR/tls-cert.txt" 2>&1 || true
CERT_FP=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | sed 's/^[^=]*=//')
log "面板自签证书: CN/SAN panel.example.com，fingerprint sha256=${CERT_FP}"

# ---------------------------------------------------------------------------
# 1. hub + panel 正常首启（真实初始化 panel_data）
# ---------------------------------------------------------------------------

docker volume create "$HUB_VOL" >/dev/null
docker volume create "$RUN_VOL" >/dev/null
docker run -d --name "$HUB_CT" \
  -p "${HOST_AGENT_PORT}:8443" -p "${HOST_ADMIN_PORT}:8444" -p "${HOST_PANEL_PORT}:8080" \
  -v "$HUB_VOL:/data" \
  -v "$RUN_VOL:/run/rustboard" \
  -e RUSTBOARD_ADMIN_TOKEN_SHARE=/run/rustboard/admin_token \
  -e RUSTBOARD_ADVERTISE=localhost \
  "$HUB_IMAGE" >/dev/null || die "hub 容器启动失败"

# 宿主 18444 发布口不转发容器回环（见头部说明）；先做一次快速实测记录，再在容器内等待。
if curl --noproxy '*' -fsS --max-time 2 \
  "http://127.0.0.1:${HOST_ADMIN_PORT}/healthz" >/dev/null 2>&1; then
  HUB_PROBE=host
  log "NOTE: 宿主 127.0.0.1:${HOST_ADMIN_PORT} 可直达 hub 管理口"
else
  HUB_PROBE=container
  log "NOTE: 宿主 18444 不可达（hub 管理口只绑容器回环）；在容器内用 127.0.0.1:8444 探活"
  hub_ok=0
  for ((i = 0; i < HEALTH_TIMEOUT; i++)); do
    if docker exec "$HUB_CT" curl -fsS --max-time 2 \
      http://127.0.0.1:8444/healthz >/dev/null 2>&1; then
      hub_ok=1
      break
    fi
    hub_state=$(docker inspect -f '{{.State.Status}}' "$HUB_CT" 2>/dev/null || echo missing)
    [ "$hub_state" = "running" ] || die "hub 容器状态 $hub_state"
    sleep 1
  done
  [ "$hub_ok" = "1" ] || die "等待 hub /healthz 超时（${HEALTH_TIMEOUT}s）"
fi
[ -n "$HUB_PROBE" ] || die "未能确认 hub /healthz"
pass 1.1 "hub 管理口 /healthz 200（探活位置: $HUB_PROBE）"

TOKEN_FILE_STAT=$(docker exec "$HUB_CT" stat -c '%a %u:%g' \
  /run/rustboard/admin_token 2>/dev/null || true)
check_eq 1.2 "hub 共享 admin token 文件 0600 且属主 10001" \
  "600 10001:10001" "${TOKEN_FILE_STAT:-missing}"

docker volume create "$PANEL_VOL" >/dev/null
docker run -d --name "$PANEL_CT" \
  --network "container:$HUB_CT" \
  -v "$PANEL_VOL:/data" \
  -v "$RUN_VOL:/run/rustboard:ro" \
  -e HUB_URL=http://127.0.0.1:8444 \
  -e HUB_TOKEN_FILE=/run/rustboard/admin_token \
  "$PANEL_IMAGE" >/dev/null || die "panel 首启容器启动失败"

panel_http=0
for ((i = 0; i < HEALTH_TIMEOUT; i++)); do
  code=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 2 \
    "http://127.0.0.1:${HOST_PANEL_PORT}/healthz" 2>/dev/null || true)
  if [ "$code" = "200" ]; then
    panel_http=1
    break
  fi
  panel_state=$(docker inspect -f '{{.State.Status}}' "$PANEL_CT" 2>/dev/null || echo missing)
  [ "$panel_state" = "running" ] \
    || die "panel 首启容器状态 $panel_state（初始安装日志可能含一次性密码，按约定不采集）"
  sleep 1
done
[ "$panel_http" = "1" ] \
  || die "panel 首启 HTTP /healthz 未在 ${HEALTH_TIMEOUT}s 内返回 200（初始日志不采集）"
pass 1.3 "panel 首启 HTTP /healthz 200（18080 → 共享 netns 8080）"

PANEL_DATA_OWNER=$(docker exec "$PANEL_CT" stat -c '%u:%g' /data 2>/dev/null || true)
check_eq 1.4 "首装后 /data 属主 10001:10001" "10001:10001" "${PANEL_DATA_OWNER:-missing}"

PANEL_CONFIG_STAT=$(docker exec "$PANEL_CT" stat -c '%a %u:%g' \
  /data/etc/rustboard/panel.toml 2>/dev/null || true)
check_eq 1.5 "首装后 panel.toml 0600 且属主 10001" \
  "600 10001:10001" "${PANEL_CONFIG_STAT:-missing}"

docker stop "$PANEL_CT" >/dev/null || die "无法停止 panel 容器"
PANEL_STOPPED_STATE=$(docker inspect -f '{{.State.Status}}' "$PANEL_CT" 2>/dev/null || true)
check_eq 1.6 "切换前 panel 已停止" "exited" "${PANEL_STOPPED_STATE:-missing}"

docker run --rm -v "$PANEL_VOL:/data:ro" --entrypoint /bin/cat "$PANEL_IMAGE" \
  /data/etc/rustboard/panel.toml >"$TMP/panel-before.toml" \
  || die "无法从已停止的 panel 卷取回 panel.toml"
chmod 0600 "$TMP/panel-before.toml"

TOKEN_BEFORE=$(config_value "$TMP/panel-before.toml" token)
PW_HASH_BEFORE=$(config_value "$TMP/panel-before.toml" admin_password_hash)
TOKEN_SHA_BEFORE=$(hash_string "$TOKEN_BEFORE")
PW_HASH_SHA_BEFORE=$(hash_string "$PW_HASH_BEFORE")
HUB_TOKEN_SHA=$(docker exec "$HUB_CT" cat /run/rustboard/admin_token \
  | tr -d '\r\n' | sha256sum | awk '{print $1}') \
  || die "读取 hub 共享 admin token 失败"
check_eq 1.7 "panel 配置中的 hub token 与 hub 共享 token 一致" \
  "$HUB_TOKEN_SHA" "$TOKEN_SHA_BEFORE"

case "$PW_HASH_BEFORE" in
  '$argon2id$'*) pass 1.8 "panel 配置含有效 Argon2id admin_password_hash（只记录 sha256）" ;;
  *) fail 1.8 "panel 配置的 admin_password_hash 不是 Argon2id PHC" ;;
esac

# panel_data 备份（含 token/密码哈希，只保存在 0700 临时目录，证据只记摘要）。
# 备份由容器内 root 写入 bind mount；GitHub runner 以非 root 运行，需把文件
# 本身设为 0644（父目录仍是 0700），否则宿主无法校验/计算摘要。
helper_sh -v "$PANEL_VOL:/data" -v "$TMP/backup:/backup" "$PANEL_IMAGE" \
  -c 'set -eu; umask 077; tar -C /data -czf /backup/panel-data-before.tgz .; chmod 0644 /backup/panel-data-before.tgz' \
  || die "panel_data 备份失败"
BACKUP_FILE="$TMP/backup/panel-data-before.tgz"
[ -s "$BACKUP_FILE" ] || die "panel_data 备份为空"
tar -tzf "$BACKUP_FILE" >/dev/null 2>&1 || die "panel_data 备份 tar 不可读"
BACKUP_SHA=$(sha256sum "$BACKUP_FILE" | awk '{print $1}')
BACKUP_BYTES=$(stat -c %s "$BACKUP_FILE")
pass 1.9 "panel_data 已备份（sha256=${BACKUP_SHA} bytes=${BACKUP_BYTES}）"

docker rm -f "$PANEL_CT" >/dev/null || die "无法移除已停止的 panel 容器"

# ---------------------------------------------------------------------------
# 2. docs §9：scoped chown → root install → 恢复 10001
# ---------------------------------------------------------------------------

log "执行 docs §9 scoped chown（拒绝符号链接/子挂载；只切安装必需路径）"
# /data/etc 与 /data/etc/rustboard 必须一起切 root：panel TLS 材料是
# /data/etc/rustboard/panel-tls（0700），install 的私有目录校验要求全部祖先
# 由 root 拥有；只 chown /data、/data/var 会在创建 TLS 目录时被拒绝。
# 这不是递归 chown /data：/data/usr/local/bin 等仍归 10001（见 2.2）。
helper_sh -v "$PANEL_VOL:/data" "$PANEL_IMAGE" -c '
  set -eu
  bad=$(find /data -xdev -type l -print -quit)
  [ -z "$bad" ] || { echo "拒绝：$bad 是符号链接" >&2; exit 1; }
  dev=$(stat -c %d /data)
  bad_mount=$(find /data -xdev -type d -exec stat -c "%d %n" {} + \
    | awk -v dev="$dev" "\$1 != dev { print \$2; exit }")
  [ -z "$bad_mount" ] || { echo "拒绝：$bad_mount 是子挂载" >&2; exit 1; }
  chown -h 0:0 /data /data/etc /data/etc/rustboard /data/var /data/var/lib
  find /data/var/lib/rustboard -xdev -exec chown -h 0:0 {} +
' || die "scoped chown 失败"
OWNER_PENDING=1

SCOPED_OWNERS=$(helper_sh -v "$PANEL_VOL:/data" "$PANEL_IMAGE" -c '
  printf "%s %s %s %s %s\n" \
    "$(stat -c %u:%g /data)" \
    "$(stat -c %u:%g /data/var/lib/rustboard)" \
    "$(stat -c %u:%g /data/etc)" \
    "$(stat -c %u:%g /data/etc/rustboard)" \
    "$(stat -c %u:%g /data/usr/local/bin)"
') || die "无法读取 scoped chown 后的属主"
read -r owner_data owner_rustboard owner_etc owner_etc_rustboard owner_usr_bin \
  <<<"$SCOPED_OWNERS"
check_eq 2.1 "scoped chown 后 /data 属主 0:0" "0:0" "${owner_data:-missing}"
check_eq 2.2 "scoped chown 只切必要路径：rustboard 子树 0:0，/data/usr/local/bin 仍 10001" \
  "0:0 10001:10001" "${owner_rustboard:-missing} ${owner_usr_bin:-missing}"
check_eq 2.3 "panel TLS 祖先 /data/etc 与 /data/etc/rustboard 已切 0:0" \
  "0:0 0:0" "${owner_etc:-missing} ${owner_etc_rustboard:-missing}"

# root install 用的一次性 token 文件：0600，内容与 hub 共享 token 完全一致。
docker exec "$HUB_CT" cat /run/rustboard/admin_token >"$TMP/admin_token" \
  || die "无法导出 hub 共享 admin token"
chmod 0600 "$TMP/admin_token"
[ -s "$TMP/admin_token" ] || die "导出的 hub admin token 为空"
COPY_TOKEN_SHA=$(tr -d '\r\n' <"$TMP/admin_token" | sha256sum | awk '{print $1}')
[ "$COPY_TOKEN_SHA" = "$HUB_TOKEN_SHA" ] || die "导出的 hub admin token 与容器内不一致"

log "以 root 执行 panel install --force（TLS；失败会保留脱敏日志并先恢复 10001）"
install_rc=0
docker run --rm --name "$INSTALL_CT" \
  --network "container:$HUB_CT" \
  -v "$PANEL_VOL:/data" \
  -v "$TMP/admin_token:/run/rustboard/admin_token:ro" \
  -v "$CERT:/run/rustboard-panel-tls/cert.pem:ro" \
  -v "$KEY:/run/rustboard-panel-tls/key.pem:ro" \
  "$PANEL_IMAGE" \
  rustboard-panel install --yes --force --no-systemd --prefix /data \
  --hub-url http://127.0.0.1:8444 \
  --hub-token-file /run/rustboard/admin_token \
  --static-dir /usr/share/rustboard/web \
  --tls-cert /run/rustboard-panel-tls/cert.pem \
  --tls-key /run/rustboard-panel-tls/key.pem \
  --public-origin https://panel.example.com \
  --listen 0.0.0.0:8080 \
  >"$TMP/reconfig-raw.log" 2>&1 || install_rc=$?
redact_stream <"$TMP/reconfig-raw.log" >"$EVIDENCE_DIR/panel-reconfig.log" 2>/dev/null || true
if [ "$install_rc" -ne 0 ]; then
  if restore_owner_10001 >/dev/null 2>&1; then
    OWNER_PENDING=0
  fi
  die "root 受控 install 失败（rc=$install_rc；脱敏日志见 panel-reconfig.log）"
fi
pass 2.4 "root install --force --no-systemd --prefix /data 退出 0"

if grep -q '沿用已有配置中的密码哈希' "$TMP/reconfig-raw.log"; then
  pass 2.5 "install 沿用已有 admin_password_hash（未重新生成密码）"
else
  fail 2.5 "install 未声明沿用已有密码哈希（可能被重新生成）"
fi

TLS_MODES=$(helper_sh -v "$PANEL_VOL:/data" "$PANEL_IMAGE" -c '
  set -eu
  stat -c %a /data/etc/rustboard/panel-tls
  stat -c %a /data/etc/rustboard/panel-tls/cert.pem
  stat -c %a /data/etc/rustboard/panel-tls/key.pem
  stat -c %a /data/etc/rustboard/panel.toml
') || die "安装后无法读取 TLS 材料权限"
mapfile -t tls_mode_lines <<<"$TLS_MODES"
check_eq 2.6 "安装后 panel-tls 目录 0700、cert 0644、key 0600、config 0600" \
  "700 644 600 600" "${tls_mode_lines[*]:-missing}"

helper_sh -v "$PANEL_VOL:/data" "$PANEL_IMAGE" \
  -c 'cat /data/etc/rustboard/panel.toml' >"$TMP/panel-after-install.toml" \
  || die "无法读取安装后的 panel.toml"
chmod 0600 "$TMP/panel-after-install.toml"
TLS_CERT_CFG=$(config_value "$TMP/panel-after-install.toml" tls_cert)
TLS_KEY_CFG=$(config_value "$TMP/panel-after-install.toml" tls_key)
check_eq 2.7 "panel.toml 的 tls_cert/tls_key 指向 /data/etc/rustboard/panel-tls/" \
  "/data/etc/rustboard/panel-tls/cert.pem /data/etc/rustboard/panel-tls/key.pem" \
  "$TLS_CERT_CFG $TLS_KEY_CFG"

log "按 docs §9 恢复 /data 属主 10001:10001（拒绝符号链接/子挂载 + -xdev + 属主断言）"
RESTORE_OUT=$(restore_owner_10001) || {
  OWNER_PENDING=1
  die "恢复 10001 属主失败（cleanup 会再重试）"
}
OWNER_PENDING=0
read -r restored_data_owner restore_cfg_mode restore_key_mode <<<"$RESTORE_OUT"
check_eq 2.8 "恢复 10001 后 /data 属主 10001:10001（脚本内全树断言通过）" \
  "10001:10001" "${restored_data_owner:-missing}"
check_eq 2.9 "恢复后 key.pem / panel.toml 仍为 0600" \
  "600 600" "${restore_cfg_mode:-missing} ${restore_key_mode:-missing}"

# ---------------------------------------------------------------------------
# 3. 以 --user 10001:10001 启动面板，HTTPS 验收
# ---------------------------------------------------------------------------

log "以 --user 10001:10001 启动 panel（不注入 HUB token/HUB_URL env）"
docker run -d --name "$PANEL_CT" \
  --network "container:$HUB_CT" \
  --user 10001:10001 \
  -v "$PANEL_VOL:/data" \
  "$PANEL_IMAGE" >/dev/null || die "panel HTTPS 容器启动失败"
FINAL_PANEL_STARTED=1

PANEL_USER_CFG=$(docker inspect -f '{{.Config.User}}' "$PANEL_CT" 2>/dev/null || true)
PANEL_RUNNING=$(docker inspect -f '{{.State.Running}}' "$PANEL_CT" 2>/dev/null || true)
check_eq 3.1 "panel 以 --user 10001:10001 运行" \
  "10001:10001 true" "${PANEL_USER_CFG:-missing} ${PANEL_RUNNING:-missing}"

https_url="https://panel.example.com:${HOST_PANEL_PORT}/healthz"
https_ok=0
for ((i = 0; i < HEALTH_TIMEOUT; i++)); do
  code=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 2 \
    --cacert "$CERT" --resolve "panel.example.com:${HOST_PANEL_PORT}:127.0.0.1" \
    "$https_url" 2>/dev/null || true)
  if [ "$code" = "200" ]; then
    https_ok=1
    break
  fi
  final_state=$(docker inspect -f '{{.State.Status}}' "$PANEL_CT" 2>/dev/null || echo missing)
  [ "$final_state" = "running" ] || die "panel HTTPS 容器状态 $final_state"
  sleep 1
done
if [ "$https_ok" != "1" ]; then
  collect_evidence_logs || true
  die "HTTPS /healthz 未在 ${HEALTH_TIMEOUT}s 内返回 200（脱敏日志见 panel-final.log）"
fi
HTTPS_BODY=$(curl --noproxy '*' -fsS --max-time 5 \
  --cacert "$CERT" --resolve "panel.example.com:${HOST_PANEL_PORT}:127.0.0.1" \
  "$https_url") || die "HTTPS /healthz 复检失败"
check_eq 3.2 "HTTPS /healthz 200 且 body=ok（SNI panel.example.com + 自签 CA）" \
  "ok" "$HTTPS_BODY"

SERVED_FP=""
SERVED_FP=$(timeout 10 openssl s_client -connect "127.0.0.1:${HOST_PANEL_PORT}" \
  -servername panel.example.com -verify_return_error -CAfile "$CERT" </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
  | sed 's/^[^=]*=//' || true)
if [ -n "$SERVED_FP" ] && [ "$SERVED_FP" = "$CERT_FP" ]; then
  pass 3.3 "服务端证书与本次生成证书一致（sha256 指纹相同，链校验通过）"
else
  fail 3.3 "服务端证书指纹不匹配（期望 ${CERT_FP}，实际 [${SERVED_FP:-empty}]）"
fi

PLAIN_CODE=$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
  "http://127.0.0.1:${HOST_PANEL_PORT}/healthz" 2>/dev/null || true)
if [ "$PLAIN_CODE" = "200" ]; then
  fail 3.4 "18080 仍接受明文 HTTP /healthz 200（未切到 TLS）"
else
  pass 3.4 "18080 不再接受明文 HTTP（code=${PLAIN_CODE:-000}）"
fi

TOP_OUT=$(docker top "$PANEL_CT" -o uid,pid,args 2>/dev/null || true)
PANEL_UIDS=$(printf '%s\n' "$TOP_OUT" \
  | awk 'NR > 1 && index($0, "rustboard-panel") > 0 { print $1 }')
if [ -z "$PANEL_UIDS" ]; then
  fail 3.5 "docker top 未找到 rustboard-panel 进程（无法证明主进程非 root）"
else
  PANEL_UID_COUNT=$(printf '%s\n' "$PANEL_UIDS" | wc -l | tr -d '[:space:]')
  bad_uids=$(printf '%s\n' "$PANEL_UIDS" | grep -vx '10001' || true)
  if [ -z "$bad_uids" ]; then
    pass 3.5 "docker top：rustboard-panel 主进程 UID=10001（${PANEL_UID_COUNT} 个）"
  else
    fail 3.5 "rustboard-panel 进程 UID 非 10001（$(printf '%s' "$PANEL_UIDS" | tr '\n' ' ')）"
  fi
fi

docker exec "$PANEL_CT" cat /data/etc/rustboard/panel.toml >"$TMP/panel-after.toml" \
  || die "无法从运行中的 panel 取回 panel.toml"
chmod 0600 "$TMP/panel-after.toml"
TOKEN_AFTER=$(config_value "$TMP/panel-after.toml" token)
PW_HASH_AFTER=$(config_value "$TMP/panel-after.toml" admin_password_hash)
PW_HASH_SHA_AFTER=$(hash_string "$PW_HASH_AFTER")
TOKEN_SHA_AFTER=$(hash_string "$TOKEN_AFTER")
check_eq 3.6 "admin_password_hash 与切换前一致（sha256 对比）" \
  "$PW_HASH_SHA_BEFORE" "$PW_HASH_SHA_AFTER"
if [ "$TOKEN_SHA_AFTER" = "$TOKEN_SHA_BEFORE" ] && [ "$TOKEN_SHA_AFTER" = "$HUB_TOKEN_SHA" ]; then
  pass 3.7 "hub token 与切换前一致，且仍等于 hub 共享 token（sha256 对比）"
else
  fail 3.7 "hub token 在重配置后变化或与 hub 共享 token 不一致"
fi

CFG_LISTEN=$(config_value "$TMP/panel-after.toml" listen)
CFG_HUB_URL=$(config_value "$TMP/panel-after.toml" hub_url)
CFG_ORIGIN=$(config_value "$TMP/panel-after.toml" public_origin)
CFG_COOKIE=$(config_value "$TMP/panel-after.toml" cookie_secure)
check_eq 3.8 "panel.toml listen/hub_url/public_origin/cookie_secure 正确" \
  "0.0.0.0:8080|http://127.0.0.1:8444|https://panel.example.com|always" \
  "$CFG_LISTEN|$CFG_HUB_URL|$CFG_ORIGIN|$CFG_COOKIE"
CFG_TLS_CERT=$(config_value "$TMP/panel-after.toml" tls_cert)
CFG_TLS_KEY=$(config_value "$TMP/panel-after.toml" tls_key)
check_eq 3.9 "panel.toml 的 TLS 路径为 panel-tls/ 下复制后的绝对路径" \
  "/data/etc/rustboard/panel-tls/cert.pem|/data/etc/rustboard/panel-tls/key.pem" \
  "$CFG_TLS_CERT|$CFG_TLS_KEY"

CONTAINER_STATS=$(docker exec --user 10001:10001 "$PANEL_CT" stat -c '%a %u:%g' \
  /data/etc/rustboard/panel.toml \
  /data/etc/rustboard/panel-tls/cert.pem \
  /data/etc/rustboard/panel-tls/key.pem 2>/dev/null || true)
mapfile -t stat_lines <<<"$CONTAINER_STATS"
check_eq 3.10 "容器内 panel.toml 0600 且属主 10001" \
  "600 10001:10001" "${stat_lines[0]:-missing}"
check_eq 3.11 "容器内 cert.pem 0644 且属主 10001" \
  "644 10001:10001" "${stat_lines[1]:-missing}"
check_eq 3.12 "容器内 key.pem 0600 且属主 10001" \
  "600 10001:10001" "${stat_lines[2]:-missing}"

FINAL_DATA_OWNER=$(docker exec --user 10001:10001 "$PANEL_CT" stat -c '%u:%g' /data \
  2>/dev/null || true)
check_eq 3.13 "运行中 /data 属主 10001:10001（恢复生效）" "10001:10001" \
  "${FINAL_DATA_OWNER:-missing}"

PANEL_ENV=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$PANEL_CT" 2>/dev/null || true)
if printf '%s\n' "$PANEL_ENV" | grep -qE '^(HUB_URL|HUB_TOKEN_FILE|HUB_TOKEN|RUSTBOARD_ADMIN_TOKEN)='; then
  fail 3.14 "panel 容器被注入了 hub token/URL 环境变量（应以 panel.toml 为准）"
else
  pass 3.14 "panel 容器未注入 HUB token/URL 环境变量（凭据来自 panel.toml）"
fi

HUB_HEALTH_FINAL=$(docker exec "$HUB_CT" curl -fsS --max-time 3 \
  http://127.0.0.1:8444/healthz 2>/dev/null || true)
check_eq 3.15 "hub 仍健康（panel 重配置未影响 hub）" "ok" "${HUB_HEALTH_FINAL:-missing}"

# ---------------------------------------------------------------------------
# 4. 证据摘要与退出码
# ---------------------------------------------------------------------------

{
  printf 'run_id=%s\n' "$RUN_ID"
  printf 'script_sha256=%s\n' "$(sha256sum "${BASH_SOURCE[0]}" | awk '{print $1}')"
  printf 'docker_version=%s\n' "$DOCKER_VERSION"
  printf 'hub_image=%s\n' "$HUB_IMAGE"
  printf 'panel_image=%s\n' "$PANEL_IMAGE"
  printf 'hub_version=%s\n' "${HUB_VERSION:-unknown}"
  printf 'panel_version=%s\n' "${PANEL_VERSION:-unknown}"
  printf 'hub_probe=%s\n' "$HUB_PROBE"
  printf 'panel_data_owner_after_first_install=%s\n' "${PANEL_DATA_OWNER:-missing}"
  printf 'panel_config_stat_after_first_install=%s\n' "${PANEL_CONFIG_STAT:-missing}"
  printf 'hub_admin_token_sha256=%s\n' "$HUB_TOKEN_SHA"
  printf 'panel_token_sha256_before=%s\n' "$TOKEN_SHA_BEFORE"
  printf 'panel_token_sha256_after=%s\n' "$TOKEN_SHA_AFTER"
  printf 'admin_password_hash_sha256_before=%s\n' "$PW_HASH_SHA_BEFORE"
  printf 'admin_password_hash_sha256_after=%s\n' "$PW_HASH_SHA_AFTER"
  printf 'panel_data_backup_sha256=%s\n' "$BACKUP_SHA"
  printf 'panel_data_backup_bytes=%s\n' "$BACKUP_BYTES"
  printf 'panel_tls_cert_sha256=%s\n' \
    "$(sha256sum "$CERT" | awk '{print $1}')"
  printf 'panel_tls_cert_fingerprint_sha256=%s\n' "$CERT_FP"
  printf 'served_cert_fingerprint_sha256=%s\n' "${SERVED_FP:-empty}"
  printf 'panel_top_uid_count=%s\n' "${PANEL_UID_COUNT:-0}"
  printf 'final_data_owner=%s\n' "${FINAL_DATA_OWNER:-missing}"
  printf 'final_panel_config_stat=%s\n' "${stat_lines[0]:-missing}"
  printf 'final_cert_stat=%s\n' "${stat_lines[1]:-missing}"
  printf 'final_key_stat=%s\n' "${stat_lines[2]:-missing}"
  printf 'https_health=200\n'
} >"$EVIDENCE_DIR/checks.txt"

log "===== docker-panel-reconfig e2e: PASS=$PASSES FAIL=$FAILS ====="
if [ "$FAILS" -ne 0 ]; then
  exit 1
fi
log "PASS：panel_data 受控 TLS 重配置、属主恢复、HTTPS 健康与凭据保留全部通过"
exit 0
