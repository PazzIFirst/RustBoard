#!/usr/bin/env bash
#
# P4 #56/#79：Docker agent TLS 模式 + 已初始化 volume 受控重配置 E2E。
#
# 覆盖：
#   1. 真实 self-signed hub volume（/data 10001:10001）；
#   2. 按文档做“停服 → scoped chown → install --yes --force → 恢复 10001”；
#   3. 本地 Pebble 真签发，切换 self-signed → ACME；
#   4. 数据/管理员 token 保留、SQLite 完整性、cert/key 配对、服务端/客户端 CA 独立；
#   5. custom-ca 与 system-roots agent 真实 enrollment、连接、重启（不再 enroll）。
#
# 这不是 CI 默认门禁：需要 Docker、curl、openssl、python3，以及本地
# hub/agent 镜像；不会 pull 缺失镜像。默认使用当前本地 local-s4 镜像：
#   HUB_IMAGE=ghcr.io/pazzifirst/rustboard-hub:local-s4
#   AGENT_IMAGE=ghcr.io/pazzifirst/rustboard-agent:local-s4
#
# Pebble：
#   - 默认启动一次性容器（host network，14000/15000、5001/5002 必须空闲）；
#   - 也可复用已运行容器：PEBBLE_REUSE=rb-pebble bash tests/e2e/v100-docker-tls-volume.sh
#
# 证据：target/docker-tls-volume-e2e/<UTC>-<PID>/（脱敏日志/摘要；不含 token/私钥）。
# 失败时保留该目录，成功/失败都会清理测试容器、volume、测试镜像与临时 token。
# shellcheck disable=SC2317  # cleanup/collect_logs 仅由 trap 调用
set -euo pipefail
umask 077

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT" || { echo "FATAL: 无法进入仓库根 $ROOT" >&2; exit 1; }

HUB_IMAGE=${HUB_IMAGE:-ghcr.io/pazzifirst/rustboard-hub:local-s4}
AGENT_IMAGE=${AGENT_IMAGE:-ghcr.io/pazzifirst/rustboard-agent:local-s4}
PEBBLE_IMAGE=${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}
PEBBLE_REUSE=${PEBBLE_REUSE:-}
PEBBLE_NAME=${PEBBLE_NAME:-rb-p4-e2e-pebble-$$}
RUN_ID="rb-p4-e2e-$$-$(date -u +%H%M%S)"
EVIDENCE_DIR=${EVIDENCE_DIR:-"target/docker-tls-volume-e2e/$(date -u +%Y%m%dT%H%M%SZ)-$$"}
TMP=$(mktemp -d "/tmp/rb-p4-e2e.XXXXXX")
SUMMARY="$EVIDENCE_DIR/summary.txt"
HUB_VOL="$RUN_ID-hub-data"
AGENT_CC_VOL="$RUN_ID-agent-cc"
AGENT_SR_VOL="$RUN_ID-agent-sr"
HUB_CT="$RUN_ID-hub"
INSTALL_CT="$RUN_ID-install"
AGENT_CC_CT="$RUN_ID-agent-cc"
AGENT_SR_CT="$RUN_ID-agent-sr"
AGENT_SYSROOTS_IMAGE="$RUN_ID-agent-sysroots"
PEBBLE_STARTED=0
CLEANED=0

mkdir -p "$EVIDENCE_DIR"
: >"$SUMMARY"

log() {
  printf '%s\n' "$*" | tee -a "$SUMMARY"
}

fail() {
  log "FAIL: $*"
  exit 1
}

collect_logs() {
  local name
  for name in "$HUB_CT" "$AGENT_CC_CT" "$AGENT_SR_CT" \
              "$AGENT_CC_CT-restart" "$AGENT_SR_CT-restart"; do
    if docker inspect "$name" >/dev/null 2>&1; then
      docker logs "$name" >"$EVIDENCE_DIR/$name.log" 2>&1 || true
    fi
  done
}

cleanup() {
  local rc=$?
  [ "$CLEANED" = "1" ] && exit "$rc"
  CLEANED=1
  collect_logs || true
  if [ "$rc" -ne 0 ]; then
    log "未通过；证据保留在 $EVIDENCE_DIR（脱敏日志/摘要）"
  fi
  docker rm -f "$INSTALL_CT" "$AGENT_CC_CT" "$AGENT_SR_CT" \
    "$AGENT_CC_CT-restart" "$AGENT_SR_CT-restart" "$HUB_CT" >/dev/null 2>&1 || true
  docker volume rm "$HUB_VOL" "$AGENT_CC_VOL" "$AGENT_SR_VOL" >/dev/null 2>&1 || true
  docker image rm "$AGENT_SYSROOTS_IMAGE" >/dev/null 2>&1 || true
  if [ "$PEBBLE_STARTED" = "1" ]; then
    docker rm -f "$PEBBLE_NAME" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT INT TERM

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "缺少命令: $1"
}

port_free() {
  local port=$1
  command -v ss >/dev/null 2>&1 || return 0
  ! ss -ltn "sport = :$port" 2>/dev/null | grep -q LISTEN
}

require_image() {
  docker image inspect "$1" >/dev/null 2>&1 || fail "本地缺少镜像 $1（脚本不 pull）"
}

wait_health() {
  local name=$1 timeout=${2:-60} status
  for _ in $(seq 1 "$timeout"); do
    status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$name" 2>/dev/null || echo missing)
    [ "$status" = "healthy" ] && return 0
    if [ "$status" = "exited" ] || [ "$status" = "dead" ]; then
      docker logs "$name" >&2 || true
      fail "容器 $name 状态 $status"
    fi
    sleep 1
  done
  docker logs "$name" >&2 || true
  fail "等待 $name healthy 超时（最后状态 ${status:-missing}）"
}

extract_token() {
  local src=$1 dest=$2
  python3 - "$src" "$dest" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
tokens = re.findall(r"[0-9a-fA-F]{64}", text)
if not tokens:
    print("no 64-hex enrollment token", file=sys.stderr)
    sys.exit(1)
open(sys.argv[2], "w", encoding="utf-8").write(tokens[0] + "\n")
PY
  chmod 0600 "$dest"
}

copy_db_with_sidecars() {
  local container=$1 dest_dir=$2
  mkdir -p "$dest_dir"
  docker cp "$container:/data/var/lib/rustboard/hub/rustboard.db" "$dest_dir/rustboard.db"
  docker cp "$container:/data/var/lib/rustboard/hub/rustboard.db-wal" "$dest_dir/rustboard.db-wal" 2>/dev/null || true
  docker cp "$container:/data/var/lib/rustboard/hub/rustboard.db-shm" "$dest_dir/rustboard.db-shm" 2>/dev/null || true
}

db_counts() {
  local db=$1 out=$2
  python3 - "$db" "$out" <<'PY'
import json, sqlite3, sys
con = sqlite3.connect(sys.argv[1])
q = con.execute("PRAGMA quick_check").fetchone()[0]
assert q == "ok", f"quick_check={q}"
counts = {}
for t in ("agents", "samples", "ingest_batches", "alert_rules", "agent_secrets"):
    counts[t] = con.execute(f"SELECT count(*) FROM {t}").fetchone()[0]
con.close()
json.dump(counts, open(sys.argv[2], "w"), sort_keys=True)
print(json.dumps(counts, sort_keys=True))
PY
}

admin_token_hash() {
  local config=$1
  python3 - "$config" <<'PY'
import hashlib, re, sys
text = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r'(?m)^\s*admin_token\s*=\s*"([^"]*)"', text)
if not m:
    print("no admin_token", file=sys.stderr)
    sys.exit(1)
print(hashlib.sha256(m.group(1).encode()).hexdigest())
PY
}

owner_check() {
  local name=$1
  docker exec "$name" sh -c '
    set -eu
    pid=""
    for p in $(pidof rustboard-hub 2>/dev/null || true); do
      cmd=$(tr "\0" " " < "/proc/$p/cmdline" 2>/dev/null || true)
      case "$cmd" in
        *"rustboard-hub run "*)
          [ -z "$pid" ] || { echo "多个 rustboard-hub run PID: $pid $p" >&2; exit 1; }
          pid="$p"
          ;;
      esac
    done
    [ -n "$pid" ] || { echo "未找到 rustboard-hub run" >&2; exit 1; }
    uid=$(awk "/^Uid:/ {print \$2, \$3, \$4, \$5}" "/proc/$pid/status")
    [ "$uid" = "10001 10001 10001 10001" ] || { echo "UID 不是 10001: $uid" >&2; exit 1; }
    echo "$uid"
  '
}

assert_owner_10001() {
  local name=$1
  docker run --rm --entrypoint /bin/sh -v "$HUB_VOL:/data" "$HUB_IMAGE" -c '
    set -eu
    bad=$(find /data -xdev \( ! -uid 10001 -o ! -gid 10001 \) -print -quit)
    [ -z "$bad" ] || { echo "残留非 10001 属主: $bad" >&2; exit 1; }
  ' >/dev/null
}

# ---------------------------------------------------------------------------
log "P4 Docker TLS/volume E2E；镜像: $HUB_IMAGE / $AGENT_IMAGE"
log "证据目录: $EVIDENCE_DIR"
for cmd in docker curl openssl python3; do need_cmd "$cmd"; done
require_image "$HUB_IMAGE"
require_image "$AGENT_IMAGE"
docker image inspect "$PEBBLE_IMAGE" >/dev/null 2>&1 || fail "本地缺少 Pebble 镜像 $PEBBLE_IMAGE（脚本不 pull）"

# 5002 必须由 hub 发布给 Pebble VA；其他端口由 Pebble 自己用。
port_free 5002 || fail "宿主 5002 已被占用（Pebble HTTP-01 测试端口）"

if [ -n "$PEBBLE_REUSE" ]; then
  PEBBLE_NAME=$PEBBLE_REUSE
  docker inspect -f '{{.State.Running}}' "$PEBBLE_NAME" 2>/dev/null | grep -qx true \
    || fail "PEBBLE_REUSE=$PEBBLE_NAME 未运行"
  log "复用 Pebble: $PEBBLE_NAME"
else
  for port in 14000 15000 5001 5002; do
    port_free "$port" || fail "端口 $port 已被占用；可设 PEBBLE_REUSE=<容器名> 复用已有 Pebble"
  done
  docker run -d --name "$PEBBLE_NAME" --network host \
    -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
    "$PEBBLE_IMAGE" >/dev/null
  PEBBLE_STARTED=1
  log "启动一次性 Pebble: $PEBBLE_NAME"
fi

for _ in $(seq 1 60); do
  curl -sk --max-time 1 https://localhost:14000/dir >/dev/null 2>&1 && break
  sleep 0.5
done
curl -sk --max-time 2 https://localhost:14000/dir >/dev/null 2>&1 \
  || fail "Pebble ACME directory 未就绪（14000）"

docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$TMP/pebble-wfe-ca.pem" >/dev/null
chmod 0644 "$TMP/pebble-wfe-ca.pem"
curl -sk --max-time 5 https://localhost:15000/roots/0 -o "$TMP/pebble-issued-root.pem"
chmod 0644 "$TMP/pebble-issued-root.pem"
openssl x509 -in "$TMP/pebble-issued-root.pem" -noout -subject -issuer >"$EVIDENCE_DIR/pebble-root.txt"
log "Pebble 根: $(openssl x509 -in "$TMP/pebble-issued-root.pem" -noout -subject)"

# system-roots 需要一个把测试根装进系统信任库的 agent 镜像；不修改仓库 Dockerfile。
cp docker/entrypoint-agent.sh "$TMP/entrypoint-agent.sh"
cat >"$TMP/Dockerfile.agent-sysroots" <<EOF
FROM $AGENT_IMAGE
COPY entrypoint-agent.sh /usr/local/bin/entrypoint-agent.sh
COPY pebble-issued-root.pem /usr/local/share/ca-certificates/pebble-issued-root.crt
RUN update-ca-certificates
EOF
docker build -q -f "$TMP/Dockerfile.agent-sysroots" -t "$AGENT_SYSROOTS_IMAGE" "$TMP" >/dev/null
log "构建 system-roots 测试 agent 镜像: $AGENT_SYSROOTS_IMAGE"

# ---------------------------------------------------------------------------
# 1) 初始化真实 self-signed volume
# ---------------------------------------------------------------------------
docker volume create "$HUB_VOL" >/dev/null
docker run -d --name "$HUB_CT" \
  -v "$HUB_VOL:/data" \
  -v "$ROOT/docker/entrypoint-hub.sh:/usr/local/bin/entrypoint-hub.sh:ro" \
  -e RUSTBOARD_ADVERTISE=localhost \
  "$HUB_IMAGE" >/dev/null
wait_health "$HUB_CT" 60
log "self-signed hub healthy"

docker exec --user 10001:10001 "$HUB_CT" \
  rustboard-hub tls status --config /data/etc/rustboard/hub.toml \
  >"$EVIDENCE_DIR/tls-before.txt"
grep -q '证书来源: self-signed' "$EVIDENCE_DIR/tls-before.txt" \
  || fail "初始 hub 不是 self-signed"
docker cp "$HUB_CT:/data/etc/rustboard/hub.toml" "$TMP/hub-before.toml"
TOKEN_BEFORE=$(admin_token_hash "$TMP/hub-before.toml")
HASH_BEFORE=$(sha256sum "$TMP/hub-before.toml" | awk '{print $1}')
log "hub.toml before sha256=$HASH_BEFORE admin_token_sha256=$TOKEN_BEFORE"

# 停服后取 DB 快照（带 WAL/SHM）；这是 #79 的数据保留基线。
docker stop "$HUB_CT" >/dev/null
copy_db_with_sidecars "$HUB_CT" "$TMP/db-before"
COUNTS_BEFORE=$(db_counts "$TMP/db-before/rustboard.db" "$TMP/counts-before.json")
log "before DB counts: $COUNTS_BEFORE"
docker rm -f "$HUB_CT" >/dev/null

# ---------------------------------------------------------------------------
# 2) 文档化受控重配置：scoped chown → install → 恢复属主
# ---------------------------------------------------------------------------
docker run --rm --entrypoint /bin/sh -v "$HUB_VOL:/data" "$HUB_IMAGE" -c '
  set -eu
  bad=$(find /data -xdev -type l -print -quit)
  [ -z "$bad" ] || { echo "拒绝：$bad 是符号链接" >&2; exit 1; }
  dev=$(stat -c %d /data)
  bad_mount=$(find /data -xdev -type d -exec stat -c "%d %n" {} + \
    | awk -v dev="$dev" "\$1 != dev { print \$2; exit }")
  [ -z "$bad_mount" ] || { echo "拒绝：$bad_mount 是子挂载" >&2; exit 1; }
  chown -h 0:0 /data /data/var /data/var/lib
  find /data/var/lib/rustboard -xdev -exec chown -h 0:0 {} +
' >/dev/null

docker run --rm --name "$INSTALL_CT" \
  --add-host=pebble:host-gateway \
  -p 5002:5002 \
  -e RUSTBOARD_ACME_HTTP_PORT=5002 \
  -v "$HUB_VOL:/data" \
  -v "$TMP/pebble-wfe-ca.pem:/run/rustboard/pebble-ca.pem:ro" \
  -v "$ROOT/docker/entrypoint-hub.sh:/usr/local/bin/entrypoint-hub.sh:ro" \
  "$HUB_IMAGE" \
  rustboard-hub install --yes --force --no-systemd --prefix /data \
    --listen 0.0.0.0:8443 --admin-listen 127.0.0.1:8444 --panel no \
    --tls acme-domain --advertise localhost \
    --acme-email test@example.invalid --domain localhost \
    --acme-challenge http-01 --acme-directory https://pebble:14000/dir \
    --acme-ca /run/rustboard/pebble-ca.pem >"$EVIDENCE_DIR/hub-reconfig.log" 2>&1 \
  || fail "受控 install --force 失败（见 hub-reconfig.log）"
log "受控 install --force 成功"

docker run --rm --entrypoint /bin/sh -v "$HUB_VOL:/data" "$HUB_IMAGE" -c '
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
' >/dev/null

# 最终 hub 继续挂载 Pebble WFE CA（续期需要），并保留 5002 发布。
docker run -d --name "$HUB_CT" \
  --add-host=pebble:host-gateway \
  -p 5002:5002 \
  -e RUSTBOARD_ACME_HTTP_PORT=5002 \
  -v "$HUB_VOL:/data" \
  -v "$TMP/pebble-wfe-ca.pem:/run/rustboard/pebble-ca.pem:ro" \
  -v "$ROOT/docker/entrypoint-hub.sh:/usr/local/bin/entrypoint-hub.sh:ro" \
  "$HUB_IMAGE" >/dev/null
wait_health "$HUB_CT" 60
assert_owner_10001 "$HUB_CT"
UID_OUT=$(owner_check "$HUB_CT")
log "final hub healthy; run UID=$UID_OUT"

docker exec --user 10001:10001 "$HUB_CT" \
  rustboard-hub tls status --config /data/etc/rustboard/hub.toml \
  >"$EVIDENCE_DIR/tls-after.txt"
grep -q '证书来源: acme-domain' "$EVIDENCE_DIR/tls-after.txt" \
  || fail "切换后证书来源不是 acme-domain"
grep -q '证书名字: localhost' "$EVIDENCE_DIR/tls-after.txt" \
  || fail "ACME 证书名字不是 localhost"
log "tls status after: acme-domain/localhost"

docker cp "$HUB_CT:/data/etc/rustboard/hub.toml" "$TMP/hub-after.toml"
TOKEN_AFTER=$(admin_token_hash "$TMP/hub-after.toml")
HASH_AFTER=$(sha256sum "$TMP/hub-after.toml" | awk '{print $1}')
[ "$TOKEN_BEFORE" = "$TOKEN_AFTER" ] || fail "admin_token 在重配置后变化"
log "hub.toml after sha256=$HASH_AFTER（模式切换后允许变化）；admin_token 保留"

# cert/key 配对 + 服务端/客户端 CA 独立
docker cp "$HUB_CT:/data/var/lib/rustboard/hub/certs/server.crt" "$TMP/server-chain.pem" >/dev/null
docker cp "$HUB_CT:/data/var/lib/rustboard/hub/certs/server.key" "$TMP/server.key" >/dev/null
docker cp "$HUB_CT:/data/var/lib/rustboard/hub/certs/ca.crt" "$TMP/client-ca.pem" >/dev/null
chmod 0600 "$TMP/server.key"
awk '/BEGIN CERT/{n++} n==1{print} /END CERT/{if(n==1)exit}' "$TMP/server-chain.pem" >"$TMP/server-leaf.pem"
openssl verify -CAfile "$TMP/pebble-issued-root.pem" -untrusted "$TMP/server-chain.pem" "$TMP/server-leaf.pem" \
  >"$EVIDENCE_DIR/verify-server.txt" 2>&1 || fail "服务端证书无法用 Pebble 根验证"
CERT_PUB=$(openssl x509 -in "$TMP/server-leaf.pem" -pubkey -noout \
  | openssl pkey -pubin -outform der | sha256sum | awk '{print $1}')
KEY_PUB=$(openssl pkey -in "$TMP/server.key" -pubout -outform der \
  | sha256sum | awk '{print $1}')
[ "$CERT_PUB" = "$KEY_PUB" ] || fail "server.crt/server.key 不配对"
CLIENT_CA_SUBJECT=$(openssl x509 -in "$TMP/client-ca.pem" -noout -subject | sed 's/^subject=//')
SERVER_ISSUER=$(openssl x509 -in "$TMP/server-leaf.pem" -noout -issuer | sed 's/^issuer=//')
[ "$CLIENT_CA_SUBJECT" != "$SERVER_ISSUER" ] \
  || fail "服务端/客户端 CA 看起来相同，未验证独立双 CA"
log "cert/key 配对；client-ca=$CLIENT_CA_SUBJECT；server-issuer=$SERVER_ISSUER"

# ---------------------------------------------------------------------------
# 3) custom-ca agent：enroll → 连接 → 去掉 token/env 重启
# ---------------------------------------------------------------------------
docker exec "$HUB_CT" rustboard-hub agent add \
  -c /data/etc/rustboard/hub.toml --name e2e-custom-ca \
  >"$TMP/add-cc.txt" 2>&1
extract_token "$TMP/add-cc.txt" "$TMP/enroll-cc.token"
docker cp "$HUB_CT:/data/var/lib/rustboard/hub/certs/agent-ca.pem" "$TMP/agent-ca.pem" >/dev/null
chmod 0644 "$TMP/agent-ca.pem"
docker volume create "$AGENT_CC_VOL" >/dev/null
docker run -d --name "$AGENT_CC_CT" \
  --network "container:$HUB_CT" \
  -v "$AGENT_CC_VOL:/data" \
  -v "$TMP/enroll-cc.token:/run/rustboard/enroll_token:ro" \
  -v "$TMP/agent-ca.pem:/run/rustboard/server-ca.pem:ro" \
  -v "$ROOT/docker/entrypoint-agent.sh:/usr/local/bin/entrypoint-agent.sh:ro" \
  -e RUSTBOARD_HUB_URL=wss://localhost:8443/agent/ws \
  -e RUSTBOARD_TOKEN_FILE=/run/rustboard/enroll_token \
  -e RUSTBOARD_TLS_MODE=custom-ca \
  -e RUSTBOARD_SERVER_CA=/run/rustboard/server-ca.pem \
  -e RUSTBOARD_NAME=e2e-custom-ca \
  "$AGENT_IMAGE" >/dev/null
wait_health "$AGENT_CC_CT" 60
docker exec "$AGENT_CC_CT" sh -c '
  set -eu
  grep -q "^tls_mode = \"custom-ca\"$" /data/etc/rustboard/agent.toml
  grep -q "^server_ca = \"/data/var/lib/rustboard/agent/server-ca.pem\"$" /data/etc/rustboard/agent.toml
  test -s /data/var/lib/rustboard/agent/server-ca.pem
  test -s /data/var/lib/rustboard/agent/enrollment.complete
' || fail "custom-ca agent 配置/持久化材料不完整"
docker exec "$AGENT_CC_CT" sh -c \
  'stat -c %Y /data/var/lib/rustboard/agent/enrollment.complete; sha256sum /data/var/lib/rustboard/agent/agent.crt' \
  >"$TMP/cc-before-restart.txt"
log "custom-ca agent enrollment/连接成功"

docker rm -f "$AGENT_CC_CT" >/dev/null
docker run -d --name "$AGENT_CC_CT-restart" \
  --network "container:$HUB_CT" \
  -v "$AGENT_CC_VOL:/data" \
  -v "$ROOT/docker/entrypoint-agent.sh:/usr/local/bin/entrypoint-agent.sh:ro" \
  "$AGENT_IMAGE" >/dev/null
wait_health "$AGENT_CC_CT-restart" 60
docker exec "$AGENT_CC_CT-restart" sh -c \
  'stat -c %Y /data/var/lib/rustboard/agent/enrollment.complete; sha256sum /data/var/lib/rustboard/agent/agent.crt' \
  >"$TMP/cc-after-restart.txt"
diff -u "$TMP/cc-before-restart.txt" "$TMP/cc-after-restart.txt" \
  >/dev/null || fail "custom-ca agent 重启后重新 enrollment/证书变化"
docker logs "$AGENT_CC_CT-restart" 2>&1 | grep -q '已连接 hub' \
  || fail "custom-ca agent 重启后未连接"
log "custom-ca agent 去掉 token/env 重启仍连接；未重新 enrollment"

# ---------------------------------------------------------------------------
# 4) system-roots agent：真实 enrollment + 重启
# ---------------------------------------------------------------------------
docker exec "$HUB_CT" rustboard-hub agent add \
  -c /data/etc/rustboard/hub.toml --name e2e-system-roots \
  >"$TMP/add-sr.txt" 2>&1
extract_token "$TMP/add-sr.txt" "$TMP/enroll-sr.token"
docker volume create "$AGENT_SR_VOL" >/dev/null
docker run -d --name "$AGENT_SR_CT" \
  --network "container:$HUB_CT" \
  -v "$AGENT_SR_VOL:/data" \
  -v "$TMP/enroll-sr.token:/run/rustboard/enroll_token:ro" \
  -e RUSTBOARD_HUB_URL=wss://localhost:8443/agent/ws \
  -e RUSTBOARD_TOKEN_FILE=/run/rustboard/enroll_token \
  -e RUSTBOARD_TLS_MODE=system-roots \
  -e RUSTBOARD_NAME=e2e-system-roots \
  "$AGENT_SYSROOTS_IMAGE" >/dev/null
wait_health "$AGENT_SR_CT" 60
docker exec "$AGENT_SR_CT" sh -c '
  set -eu
  grep -q "^tls_mode = \"system-roots\"$" /data/etc/rustboard/agent.toml
  grep -q "^server_ca = \"\"$" /data/etc/rustboard/agent.toml
  grep -q "^server_fingerprint = \"\"$" /data/etc/rustboard/agent.toml
  test -s /data/var/lib/rustboard/agent/enrollment.complete
' || fail "system-roots agent 配置/持久化材料不完整"
docker exec "$AGENT_SR_CT" sh -c \
  'stat -c %Y /data/var/lib/rustboard/agent/enrollment.complete; sha256sum /data/var/lib/rustboard/agent/agent.crt' \
  >"$TMP/sr-before-restart.txt"
log "system-roots agent enrollment/连接成功"

docker rm -f "$AGENT_SR_CT" >/dev/null
docker run -d --name "$AGENT_SR_CT-restart" \
  --network "container:$HUB_CT" \
  -v "$AGENT_SR_VOL:/data" \
  "$AGENT_SYSROOTS_IMAGE" >/dev/null
wait_health "$AGENT_SR_CT-restart" 60
docker exec "$AGENT_SR_CT-restart" sh -c \
  'stat -c %Y /data/var/lib/rustboard/agent/enrollment.complete; sha256sum /data/var/lib/rustboard/agent/agent.crt' \
  >"$TMP/sr-after-restart.txt"
diff -u "$TMP/sr-before-restart.txt" "$TMP/sr-after-restart.txt" \
  >/dev/null || fail "system-roots agent 重启后重新 enrollment/证书变化"
docker logs "$AGENT_SR_CT-restart" 2>&1 | grep -q '已连接 hub' \
  || fail "system-roots agent 重启后未连接"
log "system-roots agent 去掉 token/env 重启仍连接；未重新 enrollment"

# ---------------------------------------------------------------------------
# 5) 最终数据验收：停服后 DB quick_check/计数不下降
# ---------------------------------------------------------------------------
docker stop "$HUB_CT" >/dev/null
copy_db_with_sidecars "$HUB_CT" "$TMP/db-after"
COUNTS_AFTER=$(db_counts "$TMP/db-after/rustboard.db" "$TMP/counts-after.json")
python3 - "$TMP/counts-before.json" "$TMP/counts-after.json" <<'PY'
import json, sys
before = json.load(open(sys.argv[1]))
after = json.load(open(sys.argv[2]))
for table, n in before.items():
    if after.get(table, 0) < n:
        raise SystemExit(f"数据下降: {table} {n} -> {after.get(table, 0)}")
print("no table count decrease")
PY
log "after DB counts: $COUNTS_AFTER（无下降；quick_check=ok）"

# 客户端证书由 client CA 签发，服务端由 Pebble 签发：双 CA 独立。
docker cp "$AGENT_CC_CT-restart:/data/var/lib/rustboard/agent/agent.crt" "$TMP/agent-cert.pem" >/dev/null
AGENT_ISSUER=$(openssl x509 -in "$TMP/agent-cert.pem" -noout -issuer | sed 's/^issuer=//')
[ "$AGENT_ISSUER" = "$CLIENT_CA_SUBJECT" ] \
  || fail "agent 客户端证书 issuer 与 client CA 不一致: $AGENT_ISSUER"
log "双 CA 独立：server issuer=$SERVER_ISSUER；client cert issuer=$AGENT_ISSUER"

# 证据只写摘要/校验值，不复制 hub.toml / DB / 私钥。
{
  printf 'hub_image=%s\n' "$HUB_IMAGE"
  printf 'agent_image=%s\n' "$AGENT_IMAGE"
  printf 'pebble=%s\n' "$PEBBLE_NAME"
  printf 'hub_toml_before_sha256=%s\n' "$HASH_BEFORE"
  printf 'hub_toml_after_sha256=%s\n' "$HASH_AFTER"
  printf 'admin_token_sha256_before=%s\n' "$TOKEN_BEFORE"
  printf 'admin_token_sha256_after=%s\n' "$TOKEN_AFTER"
  printf 'run_uid=%s\n' "$UID_OUT"
  printf 'client_ca_subject=%s\n' "$CLIENT_CA_SUBJECT"
  printf 'server_issuer=%s\n' "$SERVER_ISSUER"
  printf 'agent_cert_issuer=%s\n' "$AGENT_ISSUER"
  printf 'counts_before=%s\n' "$COUNTS_BEFORE"
  printf 'counts_after=%s\n' "$COUNTS_AFTER"
} >"$EVIDENCE_DIR/checks.txt"
log "PASS：真实 volume 重配置、ACME、custom-ca/system-roots 双 CA 与重连全部通过"
log "证据: $EVIDENCE_DIR"
exit 0
