#!/usr/bin/env bash
# #84 安全回归：不启动真实 hub/agent，只验证 control.sh 的日志脱敏与
# token 解析失败路径不会把一次性 token / admin token / Bearer / 密码写进输出。
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CONTROL="$SCRIPT_DIR/control.sh"
[[ -f "$CONTROL" ]] || {
  echo "FATAL: 找不到 $CONTROL" >&2
  exit 1
}

TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/rustboard-control-redact.XXXXXX")
trap 'rm -rf "$TMP_DIR"' EXIT

# 从真实脚本抽取函数，避免复制一份脱敏规则导致测试与实现漂移。
sed -n '/^redact_stream() {/,/^}/p' "$CONTROL" >"$TMP_DIR/redact.sh"
sed -n '/^dump_log() {/,/^}/p' "$CONTROL" >>"$TMP_DIR/redact.sh"
sed -n '/^add_agent_token() {/,/^}/p' "$CONTROL" >"$TMP_DIR/add-token.sh"
grep -q '^redact_stream()' "$TMP_DIR/redact.sh" \
  || { echo "FATAL: 抽取 redact_stream 失败" >&2; exit 1; }
grep -q '^dump_log()' "$TMP_DIR/redact.sh" \
  || { echo "FATAL: 抽取 dump_log 失败" >&2; exit 1; }
grep -q '^add_agent_token()' "$TMP_DIR/add-token.sh" \
  || { echo "FATAL: 抽取 add_agent_token 失败" >&2; exit 1; }

# shellcheck source=/dev/null
source "$TMP_DIR/redact.sh"

FAILS=0
pass() { echo "PASS $*"; }
fail() { FAILS=$((FAILS + 1)); echo "FAIL $*" >&2; }

ADMIN_TOKEN="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
ENROLL_TOKEN="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
BEARER_TOKEN="bearer.abc-DEF_123.xyz"
PASSWORD="P@ssw0rd!with:colon"

cat >"$TMP_DIR/fake.log" <<EOF
INFO: hub 启动成功
管理 API token: ${ADMIN_TOKEN}
一次性 token（仅显示一次）：
${ENROLL_TOKEN}
Authorization: Bearer ${BEARER_TOKEN}
--password ${PASSWORD}
admin_token = "${ADMIN_TOKEN}"
token=${ENROLL_TOKEN}
EOF

if ! dump_log "$TMP_DIR/fake.log" 50 >"$TMP_DIR/dumped.log" 2>&1; then
  fail "dump_log 执行失败"
else
  pass "dump_log 可执行"
fi

for secret in "$ADMIN_TOKEN" "$ENROLL_TOKEN" "$BEARER_TOKEN" "$PASSWORD"; do
  if grep -Fq -- "$secret" "$TMP_DIR/dumped.log"; then
    fail "脱敏输出仍包含敏感值: ${secret:0:8}…"
  else
    pass "脱敏输出不含敏感值: ${secret:0:8}…"
  fi
done
if grep -Fq '<redacted' "$TMP_DIR/dumped.log"; then
  pass "脱敏输出保留 <redacted> 标记"
else
  fail "脱敏输出没有 <redacted> 标记"
fi
if grep -Fq 'INFO: hub 启动成功' "$TMP_DIR/dumped.log"; then
  pass "非敏感诊断行保留"
else
  fail "非敏感诊断行被误删"
fi

# add_agent_token 的失败分支：fake hub 输出原始一次性 token，但解析失败时
# die 消息不得带回 $out（否则 token 会进入公开日志）。
cat >"$TMP_DIR/fake-hub" <<'EOF'
#!/usr/bin/env bash
printf '一次性 token（仅显示一次）：\n'
printf 'RAW-SECRET-ENROLLMENT-TOKEN-9f8e7d\n'
EOF
chmod 0700 "$TMP_DIR/fake-hub"

cat >"$TMP_DIR/run-add-token.sh" <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
HUB_BIN="$1"
HUB_CFG="$2"
source "$3"
die() {
  printf 'FATAL: %s\n' "$*" >&2
  exit 1
}
add_agent_token "redact-test"
EOF
chmod 0700 "$TMP_DIR/run-add-token.sh"

set +e
"$TMP_DIR/run-add-token.sh" "$TMP_DIR/fake-hub" "$TMP_DIR/hub.toml" \
  "$TMP_DIR/add-token.sh" >"$TMP_DIR/add-token.out" 2>"$TMP_DIR/add-token.err"
ADD_RC=$?
set -e
if (( ADD_RC != 0 )); then
  pass "add_agent_token 解析失败返回非零"
else
  fail "add_agent_token 解析失败却返回 0"
fi
if grep -Fq 'RAW-SECRET-ENROLLMENT-TOKEN-9f8e7d' "$TMP_DIR/add-token.out" \
  "$TMP_DIR/add-token.err"; then
  fail "add_agent_token 失败输出泄露原始 token"
else
  pass "add_agent_token 失败输出不含原始 token"
fi
if grep -Fq '原始输出已隐藏' "$TMP_DIR/add-token.err"; then
  pass "add_agent_token 失败消息说明已隐藏原始输出"
else
  fail "add_agent_token 失败消息缺少隐藏说明"
fi

if (( FAILS > 0 )); then
  echo "FAILURES: $FAILS" >&2
  exit 1
fi
echo "ALL PASS"
