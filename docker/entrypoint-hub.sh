#!/bin/bash
# RustBoard Hub 容器入口。
#
# 安全约定：
# - 不启用 set -x，不打印 admin token / 私钥 / 配置内容；
# - 首次启动以 root 执行 `rustboard-hub install`、收紧权限并 chown 到 10001，
#   随后用 setpriv 降权；主进程始终以 UID/GID 10001 运行；
# - 已初始化的 volume 支持 `docker run --user 10001:10001`，此时只校验配置可读，
#   不执行 install / chown；
# - 失败时以非零码退出，不启动服务，也不删除已有 /data 数据。

set -euo pipefail
umask 077

readonly RUSTBOARD_UID=10001
readonly RUSTBOARD_GID=10001
readonly DATA_ROOT=/data
readonly CONFIG_FILE=/data/etc/rustboard/hub.toml
readonly HUB_DATA_DIR=/data/var/lib/rustboard/hub
readonly HUB_BIN=/usr/local/bin/rustboard-hub
readonly SETPRIV=/usr/bin/setpriv

log() {
  printf '[entrypoint-hub] %s\n' "$*" >&2
}

die() {
  log "错误: $*"
  exit 1
}

# 显式参数（例如 `--version` 或排障命令）会跳过初始化，直接 exec。
# 正常生产启动必须不带参数。
if [ "$#" -gt 0 ]; then
  case "$1" in
    -*) exec "$HUB_BIN" "$@" ;;
    *) exec "$@" ;;
  esac
fi

# 拒绝受管路径中的符号链接。root entrypoint 会写 /data；如果 10001 可在 volume
# 内放链接，后续 root 启动可能被诱导写 volume 之外。所有受管组件都必须先是
# 普通目录/文件。
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
    "$HUB_DATA_DIR" \
    /data/var/lib/rustboard/install-state.toml \
    /data/usr \
    /data/usr/local \
    /data/usr/local/bin; do
    if [ -L "$path" ]; then
      die "$path 是符号链接，拒绝使用"
    fi
  done
}

# 校验配置是普通文件、非符号链接且当前用户可读。错误信息只包含路径。
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

# 首次安装前 /data 必须是 root 拥有的普通目录。
# Phase A 的 validate_install_prefix 要求 prefix 现有组件属主等于当前 euid（root）
# 且 group/other 不可写；因此不能先 chown 10001。安装完成后再统一 chown。
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

# 已初始化 volume：只在发现非 10001:10001 属主时递归修复，不删除任何数据。
# chown -h 不跟随符号链接，避免把 volume 内的链接指向宿主路径后误改外部文件。
ensure_initialized_ownership() {
  local offender
  offender="$(find "$DATA_ROOT" -xdev \
    \( ! -uid "$RUSTBOARD_UID" -o ! -gid "$RUSTBOARD_GID" \) \
    -print -quit 2>/dev/null || true)"
  if [ -n "$offender" ]; then
    log "检测到 /data 存在非 $RUSTBOARD_UID:$RUSTBOARD_GID 属主，修复属主（不删除数据）"
    # 用 find -xdev 限制在 /data 所在文件系统内，不跟随符号链接，也不进入
    # volume 内的其它挂载点；避免误改宿主路径。
    if ! find "$DATA_ROOT" -xdev \
      -exec chown -h "$RUSTBOARD_UID:$RUSTBOARD_GID" {} +; then
      die "修复 /data 属主失败"
    fi
  fi

  chmod 0600 "$CONFIG_FILE"

  if [ -L "$HUB_DATA_DIR" ]; then
    die "$HUB_DATA_DIR 是符号链接，拒绝启动"
  fi
  if [ -d "$HUB_DATA_DIR" ]; then
    chmod 0700 "$HUB_DATA_DIR"
  elif [ -e "$HUB_DATA_DIR" ]; then
    die "$HUB_DATA_DIR 不是目录，拒绝启动"
  fi
}

# 只读取 hub.toml 顶层的 admin_token 值。TOML 表格开始后不再匹配，避免误取
# 其它 token；值必须是单行基本字符串。读不到就失败，不猜测、不回显配置。
read_admin_token() {
  local token
  token="$(awk '
    /^[[:space:]]*\[/ { exit 20 }
    /^[[:space:]]*admin_token[[:space:]]*=/ {
      value = $0
      if (!sub(/^[^=]*=[[:space:]]*"/, "", value)) exit 21
      if (!sub(/"[[:space:]]*(#.*)?$/, "", value)) exit 22
      if (value == "") exit 23
      print value
      found = 1
      exit 0
    }
    END { if (!found) exit 24 }
  ' "$CONFIG_FILE")" || return 1
  [ -n "$token" ] || return 1
  printf '%s' "$token"
}

# 可选：把 hub.toml 的 admin_token 原子写入共享文件，供同 network namespace 的
# panel 首次安装读取。文件 0600、10001:10001；内容不打印。
share_admin_token_if_requested() {
  local share="${RUSTBOARD_ADMIN_TOKEN_SHARE:-}"
  [ -z "$share" ] && return 0

  case "$share" in
    /*) ;;
    *) die "RUSTBOARD_ADMIN_TOKEN_SHARE 必须是绝对路径" ;;
  esac
  if [ -d "$share" ]; then
    die "RUSTBOARD_ADMIN_TOKEN_SHARE 指向目录，拒绝写入: $share"
  fi

  local share_dir
  share_dir="$(dirname -- "$share")"
  if [ -L "$share_dir" ]; then
    die "共享 token 父目录是符号链接，拒绝写入: $share_dir"
  fi
  if [ ! -d "$share_dir" ]; then
    install -d -m 0750 -o "$RUSTBOARD_UID" -g "$RUSTBOARD_GID" "$share_dir"
  fi

  local token tmp
  token="$(read_admin_token)" \
    || die "无法从 $CONFIG_FILE 解析顶层 admin_token；未写入共享 token。请检查配置格式。"
  tmp="$(mktemp "$share_dir/.admin-token.XXXXXX")" \
    || die "无法在 $share_dir 创建临时文件，未写入共享 token"

  if ! printf '%s\n' "$token" > "$tmp"; then
    rm -f -- "$tmp"
    die "写入共享 token 临时文件失败: $share"
  fi
  if ! chown "$RUSTBOARD_UID:$RUSTBOARD_GID" "$tmp"; then
    rm -f -- "$tmp"
    die "设置共享 token 属主失败: $share"
  fi
  if ! chmod 0600 "$tmp"; then
    rm -f -- "$tmp"
    die "设置共享 token 权限失败: $share"
  fi
  if ! mv -f -- "$tmp" "$share"; then
    rm -f -- "$tmp"
    die "原子替换共享 token 失败: $share"
  fi

  log "已写入共享 admin token: $share（内容不打印）"
}

# 非 root：只允许已初始化 volume，直接运行，避免尝试 chown / install。
if [ "$(id -u)" -ne 0 ]; then
  validate_config_readable
  if [ -n "${RUSTBOARD_ADMIN_TOKEN_SHARE:-}" ] \
    && [ ! -r "${RUSTBOARD_ADMIN_TOKEN_SHARE}" ]; then
    die "非 root 启动不会生成共享 admin token；请先用 root 启动一次，\
或确认 ${RUSTBOARD_ADMIN_TOKEN_SHARE} 对 UID $RUSTBOARD_UID 可读。"
  fi
  log "以 uid=$(id -u) 启动：已初始化 volume，跳过 install 与 chown"
  exec "$HUB_BIN" run --config "$CONFIG_FILE"
fi

# root：首启安装，或对已初始化 volume 做幂等的属主/权限修复。
reject_unsafe_symlinks
if [ ! -e "$CONFIG_FILE" ]; then
  log "首次初始化：在 $DATA_ROOT 安装 hub（--no-systemd --panel no，不写入镜像）"
  prepare_first_install_root

  install_args=(
    --yes
    --offline
    --no-systemd
    --prefix /data
    --listen "${RUSTBOARD_LISTEN:-0.0.0.0:8443}"
    --admin-listen "${RUSTBOARD_ADMIN_LISTEN:-127.0.0.1:8444}"
    --name "${RUSTBOARD_NAME:-$(hostname)}"
    --panel no
  )

  # 可选：把 agent 实际访问的域名/IP 写进服务端证书 SAN。
  # 容器 hostname 通常不是 agent 使用的地址；不设置时 agent 在 enrollment 后
  # 可能因证书 SAN 不匹配而校验证书失败。RUSTBOARD_SAN 用逗号分隔多个值。
  if [ -n "${RUSTBOARD_ADVERTISE:-}" ]; then
    install_args+=(--advertise "$RUSTBOARD_ADVERTISE")
  fi
  if [ -n "${RUSTBOARD_SAN:-}" ]; then
    IFS=',' read -r -a extra_sans <<< "$RUSTBOARD_SAN"
    for san in "${extra_sans[@]}"; do
      san="${san#"${san%%[![:space:]]*}"}"
      san="${san%"${san##*[![:space:]]}"}"
      [ -n "$san" ] && install_args+=(--san "$san")
    done
  fi

  if ! "$HUB_BIN" install "${install_args[@]}"; then
    die "hub 首次安装失败；/data 未被清空，请检查上方日志后重试"
  fi
else
  log "检测到已有配置，跳过 install（不删除数据）"
fi

validate_config_readable
ensure_initialized_ownership
share_admin_token_if_requested

log "配置就绪，降权到 $RUSTBOARD_UID:$RUSTBOARD_GID 启动 hub"
exec "$SETPRIV" \
  --reuid="$RUSTBOARD_UID" \
  --regid="$RUSTBOARD_GID" \
  --clear-groups \
  --no-new-privs \
  --inh-caps=-all \
  --ambient-caps=-all \
  "$HUB_BIN" run --config "$CONFIG_FILE"
