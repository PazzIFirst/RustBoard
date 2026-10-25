#!/bin/bash
# RustBoard Agent 容器入口。
#
# 安全约定：
# - 不启用 set -x，不打印 enrollment token、agent secret 或私钥；
# - 首次启动以 root 执行 `rustboard-agent install --no-systemd`，chown 到 10001；
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
  [ -n "${RUSTBOARD_FINGERPRINT:-}" ] || missing+=(RUSTBOARD_FINGERPRINT)
  if [ "${#missing[@]}" -gt 0 ]; then
    die "首次安装缺少环境变量: ${missing[*]}（token 只接受 0600 文件，不接受环境变量明文）"
  fi

  log "首次初始化：在 $DATA_ROOT 安装 agent（--no-systemd，控制面默认关闭）"
  prepare_first_install_root
  validate_token_file

  if ! "$AGENT_BIN" install \
    --yes \
    --offline \
    --no-systemd \
    --prefix /data \
    --hub "$RUSTBOARD_HUB_URL" \
    --token-file "$RUSTBOARD_TOKEN_FILE" \
    --fingerprint "$RUSTBOARD_FINGERPRINT" \
    --name "${RUSTBOARD_NAME:-$(hostname)}"; then
    die "agent 首次安装失败；/data 未被清空，请检查上方日志后重试"
  fi
else
  log "检测到已有配置，跳过 install（不删除数据）"
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
