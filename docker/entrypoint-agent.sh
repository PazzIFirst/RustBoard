#!/bin/bash
# RustBoard Agent 容器入口。
#
# 安全约定：
# - 不启用 set -x，不打印 enrollment token、agent secret 或私钥；
# - 首次启动以 root 执行 `rustboard-agent install --no-systemd`，chown 到 10001；
# - 服务端信任模式由 RUSTBOARD_TLS_MODE 控制（fingerprint / system-roots /
#   custom-ca，默认 fingerprint 保持旧部署兼容）：fingerprint 必须提供
#   RUSTBOARD_FINGERPRINT；system-roots 禁止 fingerprint/server CA；
#   custom-ca 必须提供 RUSTBOARD_SERVER_CA（容器内 CA PEM 路径）。未知模式
#   在写盘前失败，绝不静默回退；
# - 安装器把最终信任写入 agent.toml（custom-ca 还会把 CA 复制到 data 目录），
#   重启/重连直接读取配置，不需要重新 enroll；
# - 主进程始终以 UID/GID 10001 运行；agent 控制面默认关闭，不 privileged；
# - 已初始化 volume 支持 `docker run --user 10001:10001`，只校验配置可读；
# - 失败时以非零码退出，不启动服务，也不删除已有 /data 数据。

set -euo pipefail
umask 077

readonly RUSTBOARD_UID=10001
readonly RUSTBOARD_GID=10001
readonly DATA_ROOT=/data
readonly CONFIG_FILE=/data/etc/rustboard/agent.toml
readonly AGENT_DATA_DIR=/data/var/lib/rustboard/agent
readonly AGENT_BIN=/usr/local/bin/rustboard-agent
readonly SETPRIV=/usr/bin/setpriv
# 服务端信任模式：fingerprint（默认）/ system-roots / custom-ca。
readonly AGENT_TLS_MODE="${RUSTBOARD_TLS_MODE:-fingerprint}"
# custom-ca 的服务端 CA（容器内 PEM 路径）；其他模式必须为空。
readonly AGENT_SERVER_CA="${RUSTBOARD_SERVER_CA:-}"

log() {
  printf '[entrypoint-agent] %s\n' "$*" >&2
}

die() {
  log "错误: $*"
  exit 1
}

# 显式参数（例如 `--version` 或排障命令）会跳过初始化，直接 exec。
if [ "$#" -gt 0 ]; then
  case "$1" in
    -*) exec "$AGENT_BIN" "$@" ;;
    *) exec "$@" ;;
  esac
fi

# 拒绝受管路径中的符号链接：root entrypoint 写 /data 时不能被 volume 内的链接
# 诱导到 volume 之外。所有受管组件都必须先是普通目录/文件。
reject_unsafe_symlinks() {
  local path
  for path in \
    "$DATA_ROOT" \
    /data/etc \
    /data/etc/rustboard \
    "$CONFIG_FILE" \
    /data/var \
    /data/var/lib \
    /data/var/lib/rustboard \
    "$AGENT_DATA_DIR" \
    /data/var/lib/rustboard/install-state.toml \
    /data/usr \
    /data/usr/local \
    /data/usr/local/bin; do
    if [ -L "$path" ]; then
      die "$path 是符号链接，拒绝使用"
    fi
  done
}

validate_config_readable() {
  reject_unsafe_symlinks
  if [ -L "$CONFIG_FILE" ]; then
    die "$CONFIG_FILE 是符号链接，拒绝启动"
  fi
  if [ ! -e "$CONFIG_FILE" ]; then
    die "未找到 $CONFIG_FILE：volume 尚未初始化。请先用 root 启动一次完成安装。"
  fi
  if [ ! -f "$CONFIG_FILE" ]; then
    die "$CONFIG_FILE 不是普通文件，拒绝启动"
  fi
  if [ ! -r "$CONFIG_FILE" ]; then
    die "$CONFIG_FILE 不可读：请用 root 启动一次修复 /data 属主，或检查 volume 权限。"
  fi
}

# 首次安装前 /data 必须由 root 拥有（Phase A 安装器对 prefix 的硬约束）。
prepare_first_install_root() {
  if [ -L "$DATA_ROOT" ]; then
    die "$DATA_ROOT 是符号链接，拒绝使用"
  fi
  if [ -e "$DATA_ROOT" ] && [ ! -d "$DATA_ROOT" ]; then
    die "$DATA_ROOT 不是目录，拒绝使用"
  fi
  install -d -m 0750 -o root -g root "$DATA_ROOT"

  local owner
  owner="$(stat -c '%u' "$DATA_ROOT")"
  if [ "$owner" -ne 0 ]; then
    die "$DATA_ROOT 属主必须是 root（当前 uid=$owner）：安装器拒绝非 root 拥有的 prefix。\
请执行 chown 0:0 $DATA_ROOT 后重试；不会自动改动已有数据。"
  fi
}

# 已初始化 volume：只在发现非 10001:10001 属主时递归修复，不删除数据。
ensure_initialized_ownership() {
  local offender
  offender="$(find "$DATA_ROOT" -xdev \
    \( ! -uid "$RUSTBOARD_UID" -o ! -gid "$RUSTBOARD_GID" \) \
    -print -quit 2>/dev/null || true)"
  if [ -n "$offender" ]; then
    log "检测到 /data 存在非 $RUSTBOARD_UID:$RUSTBOARD_GID 属主，修复属主（不删除数据）"
    if ! find "$DATA_ROOT" -xdev \
      -exec chown -h "$RUSTBOARD_UID:$RUSTBOARD_GID" {} +; then
      die "修复 /data 属主失败"
    fi
  fi

  chmod 0600 "$CONFIG_FILE"

  if [ -L "$AGENT_DATA_DIR" ]; then
    die "$AGENT_DATA_DIR 是符号链接，拒绝启动"
  fi
  if [ -d "$AGENT_DATA_DIR" ]; then
    chmod 0700 "$AGENT_DATA_DIR"
  elif [ -e "$AGENT_DATA_DIR" ]; then
    die "$AGENT_DATA_DIR 不是目录，拒绝启动"
  fi
}

# enrollment token 必须是 0600 普通文件；内容从不打印。
validate_token_file() {
  if [ -L "$RUSTBOARD_TOKEN_FILE" ]; then
    die "RUSTBOARD_TOKEN_FILE 是符号链接，拒绝读取"
  fi
  if [ ! -e "$RUSTBOARD_TOKEN_FILE" ]; then
    die "缺少 enrollment token 文件: RUSTBOARD_TOKEN_FILE"
  fi
  if [ ! -f "$RUSTBOARD_TOKEN_FILE" ]; then
    die "RUSTBOARD_TOKEN_FILE 不是普通文件，拒绝读取"
  fi
  if [ ! -r "$RUSTBOARD_TOKEN_FILE" ]; then
    die "RUSTBOARD_TOKEN_FILE 不可读"
  fi

  local mode
  mode="$(stat -c '%a' "$RUSTBOARD_TOKEN_FILE")"
  if [ "$mode" != "600" ]; then
    die "RUSTBOARD_TOKEN_FILE 权限为 $mode，agent 安装要求正好 0600"
  fi
}

# 模式值本身在任何启动路径上都失败关闭：拼错的值不能被当成默认 fingerprint。
# 已初始化 volume 不会被环境变量改写，但非法值仍应显式报错而不是静默忽略。
validate_tls_mode_env() {
  case "$AGENT_TLS_MODE" in
    fingerprint|system-roots|custom-ca) ;;
    *) die "RUSTBOARD_TLS_MODE 只接受 fingerprint / system-roots / custom-ca" ;;
  esac
}

# custom-ca 的 CA 源文件预检；安装器还会校验 PEM/大小/权限，这里先给出明确错误，
# 避免在写 /data 之后才发现路径问题。安装器会把 CA 复制到 data 目录并在
# agent.toml 里写复制后的绝对路径。
validate_server_ca_file() {
  case "$AGENT_SERVER_CA" in
    /*) ;;
    *) die "RUSTBOARD_SERVER_CA 必须是容器内绝对路径（挂载 PEM 的位置）" ;;
  esac
  if [ -L "$AGENT_SERVER_CA" ]; then
    die "RUSTBOARD_SERVER_CA 是符号链接，拒绝读取"
  fi
  if [ ! -e "$AGENT_SERVER_CA" ]; then
    die "缺少 RUSTBOARD_SERVER_CA 文件: $AGENT_SERVER_CA"
  fi
  if [ ! -f "$AGENT_SERVER_CA" ]; then
    die "RUSTBOARD_SERVER_CA 不是普通文件: $AGENT_SERVER_CA"
  fi
  if [ ! -r "$AGENT_SERVER_CA" ]; then
    die "RUSTBOARD_SERVER_CA 不可读: $AGENT_SERVER_CA"
  fi

  local mode size
  mode="$(stat -c '%a' "$AGENT_SERVER_CA")"
  case "$mode" in
    600|644) ;;
    *) die "RUSTBOARD_SERVER_CA 权限为 $mode，安装器只接受 0600 或 0644" ;;
  esac
  size="$(stat -c '%s' "$AGENT_SERVER_CA")"
  if [ "$size" -gt 1048576 ]; then
    die "RUSTBOARD_SERVER_CA 超过 1 MiB 上限: $size 字节"
  fi
}

# 新装时按显式模式检查参数组合；错误信息只提变量名，不打印 token/内容。
validate_first_install_tls() {
  case "$AGENT_TLS_MODE" in
    fingerprint)
      [ -z "$AGENT_SERVER_CA" ] \
        || die "fingerprint 模式不接受 RUSTBOARD_SERVER_CA；私有 CA 请设置 RUSTBOARD_TLS_MODE=custom-ca"
      ;;
    system-roots)
      [ -z "${RUSTBOARD_FINGERPRINT:-}" ] \
        || die "system-roots 模式不接受 RUSTBOARD_FINGERPRINT（公共 ACME 由系统根校验）"
      [ -z "$AGENT_SERVER_CA" ] \
        || die "system-roots 模式不接受 RUSTBOARD_SERVER_CA"
      ;;
    custom-ca)
      [ -n "$AGENT_SERVER_CA" ] \
        || die "custom-ca 模式必须设置 RUSTBOARD_SERVER_CA（容器内 CA PEM 路径）"
      validate_server_ca_file
      ;;
  esac

  # 明文 ws:// 下 CA/主机名校验会被忽略；安装器也会拒绝，这里在写盘前失败。
  if [ "$AGENT_TLS_MODE" != "fingerprint" ]; then
    case "${RUSTBOARD_HUB_URL:-}" in
      wss://*) ;;
      *) die "$AGENT_TLS_MODE 模式必须使用 wss:// Hub URL（明文 ws:// 会忽略 CA/主机名校验）" ;;
    esac
  fi
}

validate_tls_mode_env

if [ "$(id -u)" -ne 0 ]; then
  validate_config_readable
  log "以 uid=$(id -u) 启动：已初始化 volume，跳过 install 与 chown"
  exec "$AGENT_BIN" run --config "$CONFIG_FILE"
fi

if [ ! -e "$CONFIG_FILE" ]; then
  reject_unsafe_symlinks
  missing=()
  [ -n "${RUSTBOARD_HUB_URL:-}" ] || missing+=(RUSTBOARD_HUB_URL)
  [ -n "${RUSTBOARD_TOKEN_FILE:-}" ] || missing+=(RUSTBOARD_TOKEN_FILE)
  case "$AGENT_TLS_MODE" in
    fingerprint)
      [ -n "${RUSTBOARD_FINGERPRINT:-}" ] || missing+=(RUSTBOARD_FINGERPRINT)
      ;;
    custom-ca)
      [ -n "$AGENT_SERVER_CA" ] || missing+=(RUSTBOARD_SERVER_CA)
      ;;
  esac
  if [ "${#missing[@]}" -gt 0 ]; then
    die "首次安装缺少环境变量: ${missing[*]}（token 只接受 0600 文件，不接受环境变量明文）"
  fi

  log "首次初始化：在 $DATA_ROOT 安装 agent（--no-systemd，TLS 模式 $AGENT_TLS_MODE，控制面默认关闭）"
  validate_first_install_tls
  prepare_first_install_root
  validate_token_file

  install_args=(
    --yes
    --offline
    --no-systemd
    --prefix /data
    --hub "$RUSTBOARD_HUB_URL"
    --token-file "$RUSTBOARD_TOKEN_FILE"
    --name "${RUSTBOARD_NAME:-$(hostname)}"
    --tls-mode "$AGENT_TLS_MODE"
  )
  case "$AGENT_TLS_MODE" in
    fingerprint)
      install_args+=(--fingerprint "$RUSTBOARD_FINGERPRINT")
      ;;
    custom-ca)
      install_args+=(--server-ca "$AGENT_SERVER_CA")
      # CLI 允许 custom-ca 同时带指纹（只作附加记录，运行时以 CA 为准）；
      # 显式提供时透传，避免用户以为它被静默忽略。
      [ -z "${RUSTBOARD_FINGERPRINT:-}" ] \
        || install_args+=(--fingerprint "$RUSTBOARD_FINGERPRINT")
      ;;
  esac

  if ! "$AGENT_BIN" install "${install_args[@]}"; then
    die "agent 首次安装失败；/data 未被清空，请检查上方日志后重试"
  fi
  if [ "$AGENT_TLS_MODE" = "custom-ca" ] && [ ! -s "$AGENT_DATA_DIR/server-ca.pem" ]; then
    die "custom-ca 安装后未找到持久化的服务端 CA: $AGENT_DATA_DIR/server-ca.pem"
  fi
else
  log "检测到已有配置，跳过 install（不删除数据）；信任模式以 $CONFIG_FILE 为准"
  if [ -n "${RUSTBOARD_SERVER_CA:-}" ] \
    || { [ -n "${RUSTBOARD_TLS_MODE:-}" ] && [ "${RUSTBOARD_TLS_MODE}" != "fingerprint" ]; }; then
    log "提示: RUSTBOARD_TLS_MODE / RUSTBOARD_SERVER_CA 只在首次初始化时生效；\
已有 agent 的信任模式不会因环境变量改变"
  fi
fi

validate_config_readable
ensure_initialized_ownership

log "配置就绪，降权到 $RUSTBOARD_UID:$RUSTBOARD_GID 启动 agent"
exec "$SETPRIV" \
  --reuid="$RUSTBOARD_UID" \
  --regid="$RUSTBOARD_GID" \
  --clear-groups \
  --no-new-privs \
  --inh-caps=-all \
  --ambient-caps=-all \
  "$AGENT_BIN" run --config "$CONFIG_FILE"
