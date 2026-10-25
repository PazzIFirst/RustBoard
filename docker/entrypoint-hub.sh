#!/bin/bash
# RustBoard Hub 容器入口。
#
# 安全约定：
# - 不启用 set -x，不打印 admin token / 私钥 / ACME 账户 key / 配置内容；
# - 首次启动以 root 执行 `rustboard-hub install`、收紧权限并 chown 到 10001，
#   随后用 setpriv 降权；主进程始终以 UID/GID 10001 运行；
# - 降权时只保留 NET_BIND_SERVICE（inheritable + ambient）：ACME 自动续期在
#   运行期仍需临时绑定 80/443，其余能力不保留、--no-new-privs 继续生效；
# - TLS 模式由 RUSTBOARD_TLS_MODE 控制（默认 self-signed，安装阶段追加 --offline）；
#   ACME 模式读取 RUSTBOARD_ACME_* 并在首次安装时映射为 CLI 参数，绝不追加
#   --offline；缺失/非法参数在写盘前失败；
# - 数据库默认 SQLite。RUSTBOARD_DATABASE（postgres:// / postgresql://）只在
#   首次安装时映射为 `--db`，已有配置不改写；该模式需要联网探测，安装阶段不
#   追加 --offline。RUSTBOARD_DATABASE_SSLROOTCERT 映射 `--db-sslrootcert`；
#   RUSTBOARD_DATABASE_PASSWORD_FILE 读取后导出为 RUSTBOARD_DATABASE_PASSWORD；
#   连接串与密码绝不打印；
# - 已初始化的 volume 支持 `docker run --user 10001:10001`，此时只校验配置可读，
#   不执行 install / chown；非 root 启动不保留绑定低端口的能力，不建议用于 ACME；
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

# 服务端证书来源：self-signed（默认）/ acme-domain / acme-ip。
# ACME 只允许在首次安装时通过环境变量选择；已有配置以 hub.toml 为准。
readonly TLS_MODE="${RUSTBOARD_TLS_MODE:-self-signed}"
# 管理 API：off（默认，仅回环 HTTP）/ required（HTTPS）。
readonly ADMIN_TLS_MODE="${RUSTBOARD_ADMIN_TLS:-}"

# PostgreSQL（可选）：只在首次安装时通过 RUSTBOARD_DATABASE 映射为 --db。
# 已有配置以 hub.toml 为准，环境变量不会改写它。原始 DSN 可能含密码，绝不打印。
DATABASE_URL=""
DATABASE_SSLROOTCERT=""

# ACME 安装参数；只在首次安装且 TLS_MODE 为 acme-* 时填充。
ACME_EMAIL=""
ACME_CHALLENGE=""
ACME_DIRECTORY=""
ACME_PROFILE=""
ACME_CA_FILE=""
ACME_DOMAINS=()

log() {
  printf '[entrypoint-hub] %s\n' "$*" >&2
}

die() {
  log "错误: $*"
  exit 1
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

# 环境变量本身可以提前失败；它们不会写配置，也不包含 secret。
validate_tls_mode_env() {
  case "$TLS_MODE" in
    self-signed|acme-domain|acme-ip) ;;
    *) die "RUSTBOARD_TLS_MODE 只接受 self-signed / acme-domain / acme-ip" ;;
  esac
  case "$ADMIN_TLS_MODE" in
    ""|off|required) ;;
    *) die "RUSTBOARD_ADMIN_TLS 只接受 off / required" ;;
  esac
}

# 校验数据库环境变量。RUSTBOARD_DATABASE 的值可能含密码，绝不打印。
# - 只接受 postgres:// / postgresql://（SQLite 是默认，不需要环境变量）；
# - RUSTBOARD_DATABASE_SSLROOTCERT 仅与 RUSTBOARD_DATABASE 同时使用，必须是
#   容器内绝对路径的普通文件；
# - RUSTBOARD_DATABASE_PASSWORD_FILE 读取后导出为 RUSTBOARD_DATABASE_PASSWORD
#   （hub 只认环境变量），便于使用 Docker secret；与直接设置密码互斥。
#   文件末尾的换行会被命令替换去掉。
validate_database_env() {
  local raw cert pw_file pw authority userinfo

  raw="$(trim "${RUSTBOARD_DATABASE:-}")"
  if [ -n "$raw" ]; then
    case "$raw" in
      postgres://*|postgresql://*) ;;
      *) die "RUSTBOARD_DATABASE 只接受 postgres:// 或 postgresql:// 连接串（值不打印）" ;;
    esac
    case "$raw" in
      *[[:space:][:cntrl:]]*) die "RUSTBOARD_DATABASE 含空白或控制字符（值不打印）" ;;
    esac
    case "$raw" in
      *"#"*) die "RUSTBOARD_DATABASE 不能包含 fragment（#）" ;;
    esac
    # URL 内密码会进入 argv / 容器元数据；只提醒，不回显值。
    authority="${raw#*://}"
    authority="${authority%%[/?#]*}"
    if [[ "$authority" == *@* ]]; then
      userinfo="${authority%@*}"
      if [[ "$userinfo" == *:* ]]; then
        log "警告: RUSTBOARD_DATABASE 的 URL 含密码，可能出现在进程参数与容器元数据中；\
建议改用无密码 DSN + RUSTBOARD_DATABASE_PASSWORD(_FILE)"
      fi
    fi
  fi

  cert="$(trim "${RUSTBOARD_DATABASE_SSLROOTCERT:-}")"
  if [ -n "$cert" ]; then
    [ -n "$raw" ] || die "RUSTBOARD_DATABASE_SSLROOTCERT 只能与 RUSTBOARD_DATABASE 一起使用"
    case "$cert" in
      /*) ;;
      *) die "RUSTBOARD_DATABASE_SSLROOTCERT 必须是容器内绝对路径" ;;
    esac
    [ -f "$cert" ] || die "RUSTBOARD_DATABASE_SSLROOTCERT 不是普通文件（请只读挂载 PEM）"
    [ -r "$cert" ] || die "RUSTBOARD_DATABASE_SSLROOTCERT 不可读"
  fi
  DATABASE_URL="$raw"
  DATABASE_SSLROOTCERT="$cert"

  pw_file="$(trim "${RUSTBOARD_DATABASE_PASSWORD_FILE:-}")"
  if [ -n "$pw_file" ]; then
    [ -z "${RUSTBOARD_DATABASE_PASSWORD:-}" ] \
      || die "RUSTBOARD_DATABASE_PASSWORD 与 RUSTBOARD_DATABASE_PASSWORD_FILE 不能同时设置"
    case "$pw_file" in
      /*) ;;
      *) die "RUSTBOARD_DATABASE_PASSWORD_FILE 必须是容器内绝对路径" ;;
    esac
    [ -f "$pw_file" ] || die "RUSTBOARD_DATABASE_PASSWORD_FILE 不是普通文件"
    [ -r "$pw_file" ] || die "RUSTBOARD_DATABASE_PASSWORD_FILE 不可读"
    pw="$(cat -- "$pw_file")" || die "读取 RUSTBOARD_DATABASE_PASSWORD_FILE 失败"
    [ -n "$pw" ] || die "RUSTBOARD_DATABASE_PASSWORD_FILE 为空"
    export RUSTBOARD_DATABASE_PASSWORD="$pw"
    unset pw
  fi
}

has_acme_env() {
  [ -n "${RUSTBOARD_ACME_EMAIL:-}" ] \
    || [ -n "${RUSTBOARD_ACME_DOMAIN:-}" ] \
    || [ -n "${RUSTBOARD_ACME_CHALLENGE:-}" ] \
    || [ -n "${RUSTBOARD_ACME_PROFILE:-}" ] \
    || [ -n "${RUSTBOARD_ACME_CA_FILE:-}" ] \
    || [ -n "${RUSTBOARD_ACME_DIRECTORY:-}" ]
}

# 当前进程是否仍有 CAP_NET_BIND_SERVICE（bit 10）。只用于非 root 启动提示；
# /proc 不可读时按“没有”处理，提示偏保守。
has_net_bind_service() {
  local cap_eff
  cap_eff="$(awk '$1 == "CapEff:" { print $2; exit }' /proc/self/status 2>/dev/null || true)"
  [ -n "$cap_eff" ] || return 1
  (( (16#$cap_eff & (1 << 10)) != 0 ))
}

# 在写盘 / 调用 install 之前校验 ACME 环境变量。错误信息只说明哪个变量不合法，
# 不回显邮箱、域名或配置内容；证书私钥/账户 key 不会出现在环境变量里。
validate_acme_env() {
  local raw challenge directory profile ca domain adv matched
  local -a parts=()

  raw="$(trim "${RUSTBOARD_ACME_EMAIL:-}")"
  [ -n "$raw" ] || die "ACME 模式需要 RUSTBOARD_ACME_EMAIL（联系方式，不会打印该值）"
  case "$raw" in
    *[[:space:][:cntrl:]]*|*"@"*"@"*)
      die "RUSTBOARD_ACME_EMAIL 格式非法（不能含空白/控制字符或重复 @）" ;;
  esac
  case "$raw" in
    *@*) ;;
    *) die "RUSTBOARD_ACME_EMAIL 格式非法（缺少 @）" ;;
  esac
  ACME_EMAIL="$raw"

  raw="$(trim "${RUSTBOARD_ACME_DOMAIN:-}")"
  [ -n "$raw" ] || die "ACME 模式需要 RUSTBOARD_ACME_DOMAIN（多个用逗号分隔）"
  ACME_DOMAINS=()
  IFS=',' read -r -a parts <<< "$raw"
  for domain in "${parts[@]}"; do
    domain="$(trim "$domain")"
    [ -n "$domain" ] || die "RUSTBOARD_ACME_DOMAIN 含空条目"
    case "$domain" in
      *[[:space:][:cntrl:]]*) die "RUSTBOARD_ACME_DOMAIN 含空白或控制字符" ;;
      *"*"*) die "不支持通配符证书；请逐个列出域名" ;;
    esac
    ACME_DOMAINS+=("$domain")
  done
  [ "${#ACME_DOMAINS[@]}" -gt 0 ] || die "RUSTBOARD_ACME_DOMAIN 不能为空"
  if [ "$TLS_MODE" = "acme-ip" ]; then
    [ "${#ACME_DOMAINS[@]}" -eq 1 ] || die "RUSTBOARD_TLS_MODE=acme-ip 需要恰好一个 IPv4"
    if ! [[ "${ACME_DOMAINS[0]}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      die "RUSTBOARD_TLS_MODE=acme-ip 的 RUSTBOARD_ACME_DOMAIN 不是 IPv4"
    fi
  else
    [ "${#ACME_DOMAINS[@]}" -le 20 ] || die "RUSTBOARD_TLS_MODE=acme-domain 最多 20 个域名"
  fi

  challenge="$(trim "${RUSTBOARD_ACME_CHALLENGE:-http-01}")"
  case "$challenge" in
    http-01|tls-alpn-01) ;;
    *) die "RUSTBOARD_ACME_CHALLENGE 只接受 http-01 / tls-alpn-01" ;;
  esac
  ACME_CHALLENGE="$challenge"

  directory="$(trim "${RUSTBOARD_ACME_DIRECTORY:-}")"
  if [ -n "$directory" ]; then
    case "$directory" in
      https://*) ;;
      *) die "RUSTBOARD_ACME_DIRECTORY 必须以 https:// 开头" ;;
    esac
    case "$directory" in
      *[[:space:][:cntrl:]]*|*"@"*|*"#"*)
        die "RUSTBOARD_ACME_DIRECTORY 含非法字符（空白 / userinfo / fragment）" ;;
    esac
  fi
  ACME_DIRECTORY="$directory"

  profile="$(trim "${RUSTBOARD_ACME_PROFILE:-}")"
  if [ -n "$profile" ] && ! [[ "$profile" =~ ^[A-Za-z0-9_-]{1,64}$ ]]; then
    die "RUSTBOARD_ACME_PROFILE 只允许 1–64 个字母 / 数字 / - / _"
  fi
  ACME_PROFILE="$profile"

  ca="$(trim "${RUSTBOARD_ACME_CA_FILE:-}")"
  if [ -n "$ca" ]; then
    case "$ca" in
      /*) ;;
      *) die "RUSTBOARD_ACME_CA_FILE 必须是容器内绝对路径" ;;
    esac
    [ -f "$ca" ] || die "RUSTBOARD_ACME_CA_FILE 不是普通文件（请只读挂载 PEM）"
    [ -r "$ca" ] || die "RUSTBOARD_ACME_CA_FILE 不可读"
  fi
  ACME_CA_FILE="$ca"

  # ACME 证书只覆盖 RUSTBOARD_ACME_DOMAIN。RUSTBOARD_ADVERTISE 用于生成 agent
  # 安装 URL；若不在证书标识内则忽略，避免写出证书不覆盖的地址。
  adv="$(trim "${RUSTBOARD_ADVERTISE:-}")"
  if [ -n "$adv" ]; then
    matched=0
    for domain in "${ACME_DOMAINS[@]}"; do
      if [ "${domain,,}" = "${adv,,}" ]; then
        matched=1
        break
      fi
    done
    if [ "$matched" -ne 1 ]; then
      log "警告: RUSTBOARD_ADVERTISE 不在 RUSTBOARD_ACME_DOMAIN 中，已忽略（将使用第一个域名）"
      RUSTBOARD_ADVERTISE=""
    fi
  fi
}

# 把已校验的 ACME 参数追加到 install_args。调用前必须已执行 validate_acme_env。
append_acme_install_args() {
  local domain
  install_args+=(
    --tls "$TLS_MODE"
    --acme-email "$ACME_EMAIL"
    --acme-challenge "$ACME_CHALLENGE"
  )
  for domain in "${ACME_DOMAINS[@]}"; do
    install_args+=(--domain "$domain")
  done
  if [ -n "$ACME_PROFILE" ]; then
    install_args+=(--acme-profile "$ACME_PROFILE")
  fi
  if [ -n "$ACME_CA_FILE" ]; then
    install_args+=(--acme-ca "$ACME_CA_FILE")
  fi
  if [ -n "$ACME_DIRECTORY" ]; then
    install_args+=(--acme-directory "$ACME_DIRECTORY")
  fi
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

# 环境变量取值在任何 install / exec 之前校验：非法值不能带进运行阶段。
validate_tls_mode_env
validate_database_env

# 非 root：只允许已初始化 volume，直接运行，避免尝试 chown / install。
if [ "$(id -u)" -ne 0 ]; then
  validate_config_readable
  if [ -n "$DATABASE_URL" ]; then
    log "提示: 已初始化 volume，RUSTBOARD_DATABASE 只在首次初始化时生效；\
数据库连接以 hub.toml 为准（改 DSN 请备份后编辑配置，SQLite→PG 迁移见 docs/install/postgres.md）"
  fi
  if [ -n "${RUSTBOARD_ADMIN_TOKEN_SHARE:-}" ] \
    && [ ! -r "${RUSTBOARD_ADMIN_TOKEN_SHARE}" ]; then
    die "非 root 启动不会生成共享 admin token；请先用 root 启动一次，\
或确认 ${RUSTBOARD_ADMIN_TOKEN_SHARE} 对 UID $RUSTBOARD_UID 可读。"
  fi
  if ! has_net_bind_service; then
    log "提示: 非 root 启动未保留 NET_BIND_SERVICE；ACME 自动续期需要绑定 80/443，\
若当前 volume 使用 ACME，请改用默认 root 入口启动（自签模式不受影响）"
  fi
  log "以 uid=$(id -u) 启动：已初始化 volume，跳过 install 与 chown"
  exec "$HUB_BIN" run --config "$CONFIG_FILE"
fi

# root：首启安装，或对已初始化 volume 做幂等的属主/权限修复。
reject_unsafe_symlinks
if [ ! -e "$CONFIG_FILE" ]; then
  log "首次初始化：在 $DATA_ROOT 安装 hub（--no-systemd --panel no，不写入镜像）"

  # 先校验 ACME 环境变量，再做任何目录/文件写入：缺失或非法时 /data 不产生
  # 本次安装残留。self-signed 若混入 ACME 变量也在这里失败，避免静默忽略。
  if [ "$TLS_MODE" = "self-signed" ]; then
    if has_acme_env; then
      die "检测到 RUSTBOARD_ACME_* 但 RUSTBOARD_TLS_MODE=self-signed；\
请显式设置 RUSTBOARD_TLS_MODE=acme-domain|acme-ip，或移除 ACME 变量"
    fi
  else
    validate_acme_env
  fi

  prepare_first_install_root

  install_args=(
    --yes
    --no-systemd
    --prefix /data
    --listen "${RUSTBOARD_LISTEN:-0.0.0.0:8443}"
    --admin-listen "${RUSTBOARD_ADMIN_LISTEN:-127.0.0.1:8444}"
    --name "${RUSTBOARD_NAME:-$(hostname)}"
    --panel no
  )

  # 可选 PostgreSQL：只在首次安装时传给安装器。安装器会 apply_schema + ping，
  # 不自动建库/建角色；DSN 与密码不打印。实例/角色必须先由 DBA 建好。
  if [ -n "$DATABASE_URL" ]; then
    install_args+=(--db "$DATABASE_URL")
    if [ -n "$DATABASE_SSLROOTCERT" ]; then
      install_args+=(--db-sslrootcert "$DATABASE_SSLROOTCERT")
    fi
    log "数据库: PostgreSQL（连接串与密码不打印；安装阶段执行 apply_schema → ping，不建库/建角色）"
  else
    log "数据库: SQLite（默认；设置 RUSTBOARD_DATABASE 可改用 PostgreSQL）"
  fi

  if [ "$TLS_MODE" = "self-signed" ]; then
    if [ -n "$DATABASE_URL" ]; then
      # PostgreSQL 探测需要联网，不能追加 --offline（安装器会明确拒绝）。
      install_args+=(--tls self-signed)
      log "TLS 模式: self-signed（PostgreSQL 探测需要网络，安装阶段不使用 --offline）"
    else
      # 默认行为与 Phase B 一致：自签 + 安装阶段 --offline。
      install_args+=(--offline --tls self-signed)
      log "TLS 模式: self-signed（安装阶段 --offline）"
    fi
  else
    # ACME 必须访问 ACME 目录并完成 80/443 挑战，绝不能追加 --offline。
    log "TLS 模式: $TLS_MODE（不使用 --offline；安装阶段需要访问 ACME 目录并绑定 80/443）"
    append_acme_install_args
  fi
  if [ -n "$ADMIN_TLS_MODE" ]; then
    install_args+=(--admin-tls "$ADMIN_TLS_MODE")
  fi

  # 可选：把 agent 实际访问的域名/IP 写进服务端证书 SAN。
  # 容器 hostname 通常不是 agent 使用的地址；不设置时 agent 在 enrollment 后
  # 可能因证书 SAN 不匹配而校验证书失败。RUSTBOARD_SAN 用逗号分隔多个值。
  # ACME 模式的证书 SAN 由 ACME 标识决定；RUSTBOARD_SAN 只影响回退自签的证书。
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
  if [ "$TLS_MODE" != "self-signed" ] || [ -n "$ADMIN_TLS_MODE" ]; then
    log "提示: RUSTBOARD_TLS_MODE / RUSTBOARD_ADMIN_TLS 只在首次初始化时生效；\
当前配置保持不变。模式或管理端 TLS 变更请备份后执行 rustboard-hub install --force"
  fi
  if [ -n "$DATABASE_URL" ]; then
    log "提示: RUSTBOARD_DATABASE 只在首次初始化时生效；当前配置保持不变。\
切换/迁移数据库请先备份，再编辑 /data/etc/rustboard/hub.toml 的 database（SQLite→PG 见 docs/install/postgres.md）"
  fi
fi

validate_config_readable
ensure_initialized_ownership
share_admin_token_if_requested

log "配置就绪，降权到 $RUSTBOARD_UID:$RUSTBOARD_GID 启动 hub（保留 NET_BIND_SERVICE）"
exec "$SETPRIV" \
  --reuid="$RUSTBOARD_UID" \
  --regid="$RUSTBOARD_GID" \
  --clear-groups \
  --no-new-privs \
  --inh-caps=+net_bind_service \
  --ambient-caps=+net_bind_service \
  "$HUB_BIN" run --config "$CONFIG_FILE"
