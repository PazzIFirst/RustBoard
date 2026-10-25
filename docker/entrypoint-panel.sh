#!/bin/bash
# RustBoard Panel 容器入口。
#
# 安全约定：
# - 不启用 set -x，不打印 hub admin token / 初始密码 / 配置内容；
# - 首次启动以 root 执行 `rustboard-panel install`、收紧权限并 chown 到 10001；
# - 主进程始终以 UID/GID 10001 运行；
# - 已初始化 volume 支持 `docker run --user 10001:10001`，只校验配置可读；
# - 失败时以非零码退出，不启动服务，也不删除已有 /data 数据。

set -euo pipefail
umask 077

readonly RUSTBOARD_UID=10001
readonly RUSTBOARD_GID=10001
readonly DATA_ROOT=/data
readonly CONFIG_FILE=/data/etc/rustboard/panel.toml
readonly PANEL_DATA_DIR=/data/var/lib/rustboard/panel
readonly PANEL_BIN=/usr/local/bin/rustboard-panel
readonly SETPRIV=/usr/bin/setpriv

# 面板运行在 hub 的 network namespace 中，默认通过回环访问 hub 管理 API。
readonly HUB_URL="${HUB_URL:-http://127.0.0.1:8444}"
readonly HUB_TOKEN_FILE="${HUB_TOKEN_FILE:-/run/rustboard/admin_token}"
readonly PANEL_LISTEN="${PANEL_LISTEN:-0.0.0.0:8080}"
readonly PANEL_STATIC_DIR="${PANEL_STATIC_DIR:-/usr/share/rustboard/web}"

log() {
  printf '[entrypoint-panel] %s\n' "$*" >&2
}

die() {
  log "错误: $*"
  exit 1
}

# 显式参数（例如 `--version` 或排障命令）会跳过初始化，直接 exec。
if [ "$#" -gt 0 ]; then
  case "$1" in
    -*) exec "$PANEL_BIN" "$@" ;;
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
    "$PANEL_DATA_DIR" \
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

  if [ -L "$PANEL_DATA_DIR" ]; then
    die "$PANEL_DATA_DIR 是符号链接，拒绝启动"
  fi
  if [ -d "$PANEL_DATA_DIR" ]; then
    chmod 0700 "$PANEL_DATA_DIR"
  elif [ -e "$PANEL_DATA_DIR" ]; then
    die "$PANEL_DATA_DIR 不是目录，拒绝启动"
  fi
}

# hub 写入的共享 token 必须是 0600 普通文件；内容从不打印。
validate_token_file() {
  if [ -L "$HUB_TOKEN_FILE" ]; then
    die "$HUB_TOKEN_FILE 是符号链接，拒绝读取"
  fi
  if [ ! -e "$HUB_TOKEN_FILE" ]; then
    die "缺少 hub 管理 token：$HUB_TOKEN_FILE。\
请先启动 hub 并配置 RUSTBOARD_ADMIN_TOKEN_SHARE（见 docker/compose.example.yml）。"
  fi
  if [ ! -f "$HUB_TOKEN_FILE" ]; then
    die "$HUB_TOKEN_FILE 不是普通文件，拒绝读取"
  fi
  if [ ! -r "$HUB_TOKEN_FILE" ]; then
    die "$HUB_TOKEN_FILE 不可读：共享 token 必须对 root（首启）和 UID $RUSTBOARD_UID（运行）可读。"
  fi

  local mode
  mode="$(stat -c '%a' "$HUB_TOKEN_FILE")"
  if [ "$mode" != "600" ]; then
    die "$HUB_TOKEN_FILE 权限为 $mode，panel 安装要求正好 0600"
  fi
}

if [ "$(id -u)" -ne 0 ]; then
  validate_config_readable
  log "以 uid=$(id -u) 启动：已初始化 volume，跳过 install 与 chown"
  exec "$PANEL_BIN" run --config "$CONFIG_FILE"
fi

if [ ! -e "$CONFIG_FILE" ]; then
  reject_unsafe_symlinks
  log "首次初始化：在 $DATA_ROOT 安装 panel（--no-systemd）"
  log "注意：面板初始密码只由 install 输出一次，会进入本容器日志；请立即保存并限制日志访问"
  prepare_first_install_root
  validate_token_file

  if [ ! -d "$PANEL_STATIC_DIR" ]; then
    die "静态资源目录不存在: $PANEL_STATIC_DIR（构建镜像前需准备 web/dist）"
  fi
  if [ ! -s "$PANEL_STATIC_DIR/index.html" ]; then
    die "静态资源目录缺少 index.html: $PANEL_STATIC_DIR"
  fi

  if ! "$PANEL_BIN" install \
    --yes \
    --offline \
    --no-systemd \
    --prefix /data \
    --hub-url "$HUB_URL" \
    --hub-token-file "$HUB_TOKEN_FILE" \
    --listen "$PANEL_LISTEN" \
    --static-dir "$PANEL_STATIC_DIR"; then
    die "panel 首次安装失败；/data 未被清空，请检查上方日志后重试"
  fi
else
  log "检测到已有配置，跳过 install（不删除数据）"
fi

validate_config_readable
ensure_initialized_ownership

log "配置就绪，降权到 $RUSTBOARD_UID:$RUSTBOARD_GID 启动 panel"
exec "$SETPRIV" \
  --reuid="$RUSTBOARD_UID" \
  --regid="$RUSTBOARD_GID" \
  --clear-groups \
  --no-new-privs \
  --inh-caps=-all \
  --ambient-caps=-all \
  "$PANEL_BIN" run --config "$CONFIG_FILE"
