#!/usr/bin/env bash
# RustBoard 离线包内安装引导（M5 Phase B）。
#
# 边界：
# - 本脚本只做包完整性、架构/版本、prefix 安全与 web 静态资源安装；
# - 配置 / 证书 / systemd / 事务回滚全部交给 Phase A 的 `rustboard-<role> install`，
#   本脚本不重复实现，也不直接调用 systemctl；
# - 不接受明文 token / 密码 argv，只允许 0600 文件参数；
# - 校验和、架构、版本、prefix 安全全部通过之后才写 web；`--dry-run` 不写 web。
#
# 顺序由发布方案固定：先 `sha256sum -c --strict`，再执行已校验二进制做
# `--version` / 架构校验，再校验 prefix，最后才写 web 并以子进程运行 install；
# Phase A 失败时恢复旧 web，不丢交付目录。

set -euo pipefail
umask 077

SCRIPT_PATH=${BASH_SOURCE[0]}
PKG_ROOT=$(cd -- "$(dirname -- "$SCRIPT_PATH")" && pwd -P) || {
    printf 'error: 无法定位包根目录\n' >&2
    exit 1
}

ROLE=""
VERSION=""
PREFIX="/"
DRY_RUN=0
ARGS=()
WEB_DEST=""
WEB_SRC=""
WEB_STAGING=""
WEB_BACKUP=""
WEB_INSTALLED=0
WEB_COMMITTED=0
CHILD_PID=""
CHILD_STDERR=""
LOCK_FD=""
LOCK_PATH=/run/rustboard-install.lock

usage() {
    cat <<'EOF'
用法: ./install.sh <hub|panel|agent> [install 参数] [--help]

离线包引导脚本。校验包完整性后，把控制权交给包内对应的 Phase A 安装器：
  bin/rustboard-<role> install [install 参数]

角色:
  hub     汇聚端（默认会尝试安装同机 panel，可用 --panel no 关闭）
  panel   面板
  agent   采集端（需要 --hub 与 --token-file）

常用参数（其余参数原样透传，见二进制 --help）:
  --yes                    非交互执行
  --prefix DIR             安装前缀，默认 /。必须是绝对路径、无 . / .. 组件；
                           且从 / 到 prefix 的已存在组件必须 root 所有、非符号
                           链接、group/other 不可写。测试建议用 /opt 下的新目录，
                           不要用 /tmp（通常 1777）。
  --offline                离线安装。幂等；未显式给出时自动追加。
  --dry-run                只打印计划，不写文件；本脚本也不会写 web。
  --token-file F           agent enrollment token 文件（0600）
  --hub-token-file F       panel 读取的 hub 管理 token 文件（0600）
  --password-file F        panel 初始密码文件（0600）
  --panel-static-dir DIR   hub 传给同机 panel 的静态目录（不覆盖本脚本默认值）
  --static-dir DIR         panel 静态目录（不覆盖本脚本默认值）
  --no-systemd             只写文件，不写 unit、不调用 systemctl（测试用）
  --help, -h               显示本帮助

安全:
  - 禁止 --token / --password / --admin-token / --hub-token 等明文 secret 参数；
    只接受上面列出的 *-file 形式；
  - 包内 SHA256SUMS 校验失败时在写任何文件之前退出；
  - hub/panel 会把包内 share/rustboard/web 原子安装到
    <prefix>/usr/share/rustboard/web（prefix=/ 时即 /usr/share/rustboard/web），
    并自动追加 --panel-static-dir / --static-dir；用户显式传对应参数时不覆盖；
  - 已有 web 目录是符号链接或路径组件不安全时直接拒绝，不会写入链接目标。

离线语义:
  --offline 只表示“不发起外部网络探测”；本地端口 bind、loopback /healthz、
  systemd 操作仍可能发生，这是正常安装行为。

示例:
  sudo ./install.sh hub --yes
  sudo ./install.sh panel --yes --prefix /opt/rustboard-test
  sudo ./install.sh agent --yes --hub wss://<hub-host>:8443/agent/ws \
      --token-file /root/agent.token --fingerprint SHA256:<64-hex>
  ./install.sh hub --prefix /opt/rustboard-test --dry-run

失败时:
  脚本会打印可复现的 --dry-run 命令；服务日志用
  journalctl -u rustboard-<role>，脚本与二进制的错误输出在标准错误。
EOF
}

# 兜底脱敏：任何写到 stderr 的路径/消息都可能来自用户参数（例如把 token 拼进
# prefix 或 hub URL）。失败提示本身还会隐藏所有选项值；这里再对常见 secret 形态
# 做一次替换，避免 URL query / key=value 形式的泄露。
redact_secret_text() {
    sed -E \
        -e 's#([A-Za-z][A-Za-z0-9+.-]*://[^/@[:space:]:]+:)[^/@[:space:]]+@#\1***@#g' \
        -e "s/(invalid value ')[^']*(')/\\1***\\2/Ig" \
        -e 's/(invalid value ")[^"]*(")/\1***\2/Ig' \
        -e "s/(unexpected argument ')([^-][^']*)(')/\\1***\\3/Ig" \
        -e 's/(unexpected argument ")([^-][^"]*)(")/\1***\3/Ig' \
        -e "s/(value ')[^']*(')/\\1***\\2/Ig" \
        -e 's/(value ")[^"]*(")/\1***\2/Ig' \
        -e 's/(authorization[[:space:]]*[=:][[:space:]]*)[^&]+/\1***/Ig' \
        -e 's/(Bearer[[:space:]]+)[^[:space:]]+/\1***/Ig' \
        -e 's/((token|secret|password|key)[A-Za-z0-9_-]*[[:space:]]*[=:][[:space:]]*)[^[:space:]&]+/\1***/Ig' \
        -e 's/\bghp_[A-Za-z0-9_]+/ghp_***/g' \
        -e 's/\bgho_[A-Za-z0-9_]+/gho_***/g' \
        -e 's/\bgithub_pat_[A-Za-z0-9_]+/github_pat_***/g' \
        -e 's/\bsk-[A-Za-z0-9_-]+/sk-***/g' \
        -e 's/\bAKIA[0-9A-Za-z_]+/AKIA***/g'
}

die() {
    local msg
    msg=$(printf '%s' "$*" | redact_secret_text)
    printf 'error: %s\n' "$msg" >&2
    exit 1
}

warn() {
    local msg
    msg=$(printf '%s' "$*" | redact_secret_text)
    printf 'warning: %s\n' "$msg" >&2
}

log() {
    local msg
    msg=$(printf '%s' "$*" | redact_secret_text)
    printf '==> %s\n' "$msg" >&2
}

require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || die "缺少必需命令: $cmd"
    done
}

# 打印失败时的只读复现提示与日志位置。
# 安全约束：不回显任何参数值（URL、路径、token 等一律不打印）；只打印 role、
# 经过筛选的选项名和 <redacted> 占位，避免 `--hub 'wss://...?token=...'` 泄露。
print_failure_help() {
    local -a repro=()
    local arg name safe_root
    local -a rendered=()

    [[ -n ${PKG_ROOT:-} && -n ${ROLE:-} ]] || return 0
    repro=("$PKG_ROOT/install.sh" "$ROLE")
    for arg in "${ARGS[@]}"; do
        case $arg in
            --*) ;;
            *) continue ;; # 位置参数一律省略
        esac
        name=${arg%%=*}
        case $name in
            --dry-run) continue ;;
            --) continue ;;
            --yes | --offline | --force | --systemd | --no-systemd)
                repro+=("$name")
                ;;
            --prefix | --panel | --listen | --admin-listen | --advertise | --san | \
            --name | --retention | --db | --tls | --config | --data-dir | --unit-dir | \
            --hub-url | --hub-token-file | --password-file | --token-file | \
            --fingerprint | --server-ca | --static-dir | --panel-static-dir | --hub)
                # 只打印白名单选项名；值一律 <redacted>。
                repro+=("$name" "<redacted>")
                ;;
            *)
                # 未知选项不回显名称/值，避免把 secret 伪装成选项名带出。
                continue
                ;;
        esac
    done
    repro+=(--dry-run)

    safe_root=$(printf '%s' "$PKG_ROOT" | redact_secret_text)
    printf '\n安装未完成。\n' >&2
    printf '可复现（只读；为防泄露，参数值均已隐藏，请按原命令补齐）：\n  ' >&2
    printf '%q %q' "$safe_root" "$ROLE" >&2
    rendered=("${repro[@]:2}")
    for arg in "${rendered[@]}"; do
        case $arg in
            '<redacted>') printf " '<redacted>'" >&2 ;;
            *) printf ' %q' "$arg" >&2 ;;
        esac
    done
    printf '\n' >&2
    printf '日志: 本脚本与 rustboard-%s 的标准错误；systemd 安装后可用 journalctl -u rustboard-%s 查看服务日志。\n' \
        "${ROLE:-<role>}" "${ROLE:-<role>}" >&2
}

# 子进程 stderr 写入 0600 临时文件，结束后脱敏再输出；stdout 保持透传，
# 因此 panel 的初始密码仍按 Phase A 设计只显示一次。
flush_child_stderr() {
    local file=${CHILD_STDERR:-} filtered
    [[ -n $file && -f $file ]] || return 0

    if filtered=$(redact_secret_text < "$file"); then
        [[ -n $filtered ]] && printf '%s\n' "$filtered" >&2
    else
        warn "子进程 stderr 脱敏失败，已丢弃输出: $file"
    fi
    rm -f -- "$file" || warn "清理子进程 stderr 临时文件失败: $file"
    CHILD_STDERR=""
}

# 只需在 EXIT 时清理：临时 web staging、失败时恢复旧 web。成功退出前会主动
# 移除 trap；Phase A 作为子进程运行，失败时由这里统一回滚 web。
on_exit() {
    local status=$?
    local keep_backup=0
    trap - EXIT

    flush_child_stderr

    if [[ -n ${WEB_STAGING:-} && -d ${WEB_STAGING:-} ]]; then
        rm -rf -- "$WEB_STAGING" || warn "清理临时 web 目录失败: $WEB_STAGING"
    fi

    # 一旦 child 成功并决定保留新 web，收到信号也只清理备份，绝不恢复旧目录。
    if ((WEB_COMMITTED == 0)); then
        if [[ -n ${WEB_BACKUP:-} && -e ${WEB_BACKUP:-}/web ]]; then
            if [[ -z ${WEB_DEST:-} ]]; then
                keep_backup=1
                warn "web 目标为空，备份保留在: $WEB_BACKUP/web"
            else
                if [[ -e $WEB_DEST || -L $WEB_DEST ]]; then
                    if ! rm -rf -- "$WEB_DEST"; then
                        keep_backup=1
                        warn "回滚时删除新 web 目录失败，备份保留在: $WEB_BACKUP/web"
                    fi
                fi
                if ((keep_backup == 0)); then
                    if ! mv -T -- "$WEB_BACKUP/web" "$WEB_DEST"; then
                        keep_backup=1
                        warn "回滚旧 web 目录失败，备份保留在: $WEB_BACKUP/web"
                    fi
                fi
            fi
        elif ((WEB_INSTALLED)) && [[ -n ${WEB_DEST:-} ]]; then
            rm -rf -- "$WEB_DEST" || warn "回滚新 web 目录失败: $WEB_DEST"
        fi
    fi

    if ((keep_backup == 0)) && [[ -n ${WEB_BACKUP:-} && -d ${WEB_BACKUP:-} ]]; then
        rm -rf -- "$WEB_BACKUP" || warn "清理 web 备份目录失败: $WEB_BACKUP"
    fi

    if ((status != 0)) && ((WEB_COMMITTED == 0)); then
        print_failure_help
    fi
    exit "$status"
}

# 拒绝明文 secret 参数。允许且仅允许 --token-file / --hub-token-file /
# --password-file（含 --opt=value 形式）；其余包含 token/password/secret 的
# 选项一律拒绝，错误信息不包含选项值。
scan_secret_args() {
    local arg name lower
    for arg in "${ARGS[@]}"; do
        [[ $arg == --* ]] || continue
        name=${arg%%=*}
        lower=${name,,}
        case $lower in
            --token-file | --hub-token-file | --password-file) continue ;;
        esac
        if [[ $lower =~ ^--([a-z0-9_-]*)(token|password|secret)([a-z0-9_-]*)$ ]]; then
            die "拒绝明文 secret 参数: $name；请使用 --token-file / --hub-token-file / --password-file"
        fi
    done
}

# 解析 --prefix P / --prefix=P（只取最后一次，与 clap 的“后者覆盖”一致）。
parse_prefix() {
    local i=0 arg
    while ((i < ${#ARGS[@]})); do
        arg=${ARGS[i]}
        case $arg in
            --prefix)
                ((i + 1 < ${#ARGS[@]})) || die "--prefix 缺少取值"
                PREFIX=${ARGS[i + 1]}
                i=$((i + 2))
                ;;
            --prefix=*)
                PREFIX=${arg#--prefix=}
                i=$((i + 1))
                ;;
            *)
                i=$((i + 1))
                ;;
        esac
    done
}

# 在写任何文件之前校验 prefix 的路径语法与 Phase A 禁用字符。完整所有权/
# 符号链接校验见 assert_safe_root_path。
validate_prefix_syntax() {
    local prefix=$1 ch
    [[ -n $prefix ]] || die "--prefix 不能为空"
    [[ $prefix == /* ]] || die "--prefix 必须是绝对路径"
    [[ $prefix != *[[:cntrl:]]* ]] || die "--prefix 不能包含控制字符"
    # 镜像 Phase A 的 FORBIDDEN_PREFIX_CHARS：这些字符在 systemd / shell 中有
    # 转义歧义，提前拒绝，避免 web 已写完后才被 Rust 安装器拒绝。
    for ch in '$' '%' '"' "'" '\' '`'; do
        if [[ $prefix == *"$ch"* ]]; then
            die "--prefix 含 Phase A 禁止字符: $ch"
        fi
    done
    # 语法错误只说明原因，不回显 prefix 值（值里可能含 secret）。
    [[ $prefix != *'//'* ]] || die "--prefix 不能包含重复分隔符"
    if [[ $prefix != / && $prefix == */ ]]; then
        die "--prefix 不能以 / 结尾"
    fi
    [[ "/$prefix/" != *"/./"* ]] || die "--prefix 不能包含 . 组件"
    [[ "/$prefix/" != *"/../"* ]] || die "--prefix 不能包含 .. 组件"
}

# 从 / 到目标路径逐组件检查已存在的部分：
# - 拒绝符号链接（避免把 root 写入引到链接目标）；
# - 必须属于 root（uid 0）；
# - group/other 不可写，且不允许 sticky（/tmp 这类共享目录不可作为安装根）；
# - 已存在组件必须是目录。
# 目标不存在时检查到最近一个已存在的祖先即停止。所有已存在组件都 root 所有
# 且不可被非 root 改写，因此后续 root 写入不会被普通用户 TOCTOU 替换。
assert_safe_root_path() {
    local path=$1 label=$2
    local -a parts=()
    local current="" part uid mode

    [[ -n $path && $path == /* ]] || die "$label 必须是绝对路径: ${path:-<空>}"
    IFS='/' read -r -a parts <<< "$path"
    ((${#parts[@]} > 0)) || parts=( "" )

    for part in "${parts[@]}"; do
        if [[ -z $part ]]; then
            current="/"
        else
            current="${current%/}/$part"
        fi

        if [[ -L $current ]]; then
            die "${label}的路径组件是符号链接，拒绝安装: $current"
        fi
        if [[ ! -e $current ]]; then
            break
        fi
        if [[ ! -d $current ]]; then
            die "${label}的路径组件不是目录: $current"
        fi

        uid=$(stat -c '%u' "$current") || die "无法读取${label}路径组件属主: $current"
        [[ $uid == 0 ]] || die "${label}的路径组件不属于 root（uid=$uid）: $current"
        mode=$(stat -c '%a' "$current") || die "无法读取${label}路径组件权限: $current"
        if (( (8#$mode & 8#022) != 0 || (8#$mode & 8#1000) != 0 )); then
            die "${label}的路径组件权限不安全（group/other 可写或 sticky）: $current (mode=$mode)"
        fi
    done
}

# 获取 Phase A 全局锁（/run/rustboard-install.lock）。只有 hub/panel 需要：
# 它们必须先写 web，再运行 Phase A；wrapper 持锁可防止两个包安装器交错
# web 替换与 Phase A 的 config/unit/state 写入。agent 不写 web，由 Phase A
# 自己加锁，wrapper 不干预。dry-run 不获取锁。
acquire_install_lock() {
    local meta uid mode

    require_cmd flock
    [[ -d /run && ! -L /run ]] || die "缺少安全的 /run 目录，拒绝安装"
    if [[ -e $LOCK_PATH || -L $LOCK_PATH ]]; then
        [[ -f $LOCK_PATH && ! -L $LOCK_PATH ]] \
            || die "安装锁不是普通文件，拒绝使用: $LOCK_PATH"
        meta=$(stat -c '%u %a' "$LOCK_PATH") \
            || die "读取安装锁元数据失败: $LOCK_PATH"
        read -r uid mode <<< "$meta"
        [[ $uid == "$EUID" ]] \
            || die "安装锁属主 uid=$uid（当前 euid=$EUID），拒绝使用: $LOCK_PATH"
        [[ $mode == 600 ]] \
            || die "安装锁权限为 $mode，要求 0600，拒绝使用: $LOCK_PATH"
    fi

    if ! exec {LOCK_FD}<>"$LOCK_PATH"; then
        die "打开安装锁失败: $LOCK_PATH"
    fi

    # 打开后重新校验，避免 /run 被替换或文件在检查后被换掉。
    if [[ ! -f $LOCK_PATH || -L $LOCK_PATH ]]; then
        exec {LOCK_FD}>&-
        LOCK_FD=""
        die "安装锁不是普通文件，拒绝使用: $LOCK_PATH"
    fi
    if ! meta=$(stat -c '%u %a' "$LOCK_PATH"); then
        exec {LOCK_FD}>&-
        LOCK_FD=""
        die "读取安装锁元数据失败: $LOCK_PATH"
    fi
    read -r uid mode <<< "$meta"
    if [[ $uid != "$EUID" || $mode != 600 ]]; then
        exec {LOCK_FD}>&-
        LOCK_FD=""
        die "安装锁属主/权限不安全（uid=$uid mode=$mode），拒绝使用: $LOCK_PATH"
    fi

    if ! flock -n "$LOCK_FD"; then
        exec {LOCK_FD}>&-
        LOCK_FD=""
        die "另一个 RustBoard 安装/卸载/升级正在运行（锁 $LOCK_PATH 已被占用）"
    fi

    # hub/panel 的 Phase A 读取该标记后跳过二次加锁；hub 的 Rust 侧继承逻辑
    # 由 Phase A 修复，wrapper 只负责在 child 运行期间一直持有这把锁。
    export RUSTBOARD_INSTALL_LOCK_HELD=1
    log "已获取全局安装锁: $LOCK_PATH"
}

# 与 build-release.sh 相同的包内 SHA256SUMS 覆盖检查。
sums_has() {
    local sums=$1 rel=$2
    awk -v target="$rel" '
        {
            line = $0
            sub(/^[0-9a-fA-F]+[[:space:]]+/, "", line)
            if (line == target) found = 1
        }
        END { exit(found ? 0 : 1) }
    ' "$sums"
}

# 校验清单：路径集合与包内普通文件集合精确相等，并显式覆盖固定契约文件。
validate_sums_manifest() {
    local sums="$PKG_ROOT/SHA256SUMS"
    local rel line path special listed_count=0 actual_count=0
    local -A seen=()

    [[ -f $sums && ! -L $sums ]] || die "包内缺少普通文件 SHA256SUMS"
    [[ -d $PKG_ROOT/bin && ! -L $PKG_ROOT/bin ]] || die "包内缺少普通目录 bin/"
    [[ -d $PKG_ROOT/share/rustboard/web && ! -L $PKG_ROOT/share/rustboard/web ]] \
        || die "包内缺少普通目录 share/rustboard/web/"
    [[ -d $PKG_ROOT/systemd && ! -L $PKG_ROOT/systemd ]] || die "包内缺少普通目录 systemd/"

    # 包内只允许普通文件和目录；symlink/FIFO/device 一律拒绝。
    special=$(find "$PKG_ROOT" ! -type f ! -type d -print -quit) \
        || die "枚举包内文件类型失败"
    [[ -z $special ]] \
        || die "包内只允许普通文件和目录（发现 symlink/FIFO/device）: $special"

    # 解析 SHA256SUMS：只接受标准两空格格式，拒绝空行、绝对路径、..、控制字符
    # 与重复路径；路径集合稍后与包内普通文件集合精确比较。
    while IFS= read -r line; do
        [[ -n $line ]] || die "SHA256SUMS 含空行，拒绝安装"
        if [[ ! $line =~ ^[0-9a-fA-F]{64}\ \ (.+)$ ]]; then
            die "SHA256SUMS 行格式非法（需要 <64-hex> 两空格 <相对路径>）"
        fi
        path=${BASH_REMATCH[1]}
        [[ $path != /* ]] || die "SHA256SUMS 含绝对路径，拒绝安装"
        [[ $path != *[[:cntrl:]]* ]] || die "SHA256SUMS 路径含控制字符，拒绝安装"
        if [[ $path =~ (^|/)\.\.(/|$) ]]; then
            die "SHA256SUMS 含 .. 路径组件，拒绝安装"
        fi
        [[ -z ${seen["$path"]+x} ]] || die "SHA256SUMS 重复路径: $path"
        seen["$path"]=1
        listed_count=$((listed_count + 1))
    done < "$sums"

    # 包内实际普通文件集合（排除 SHA256SUMS 自身）；每个文件必须在清单中。
    while IFS= read -r -d '' rel; do
        [[ $rel == SHA256SUMS ]] && continue
        actual_count=$((actual_count + 1))
        [[ -n ${seen["$rel"]+x} ]] || die "SHA256SUMS 未覆盖包内文件: $rel"
    done < <(find "$PKG_ROOT" -type f -printf '%P\0')
    ((actual_count == listed_count)) \
        || die "SHA256SUMS 与包内普通文件集合不一致（清单 $listed_count 条，实际 $actual_count 个）"

    # 固定契约文件必须被覆盖（同时确保 bin/、systemd/ 非空；web 目录已检查）。
    for rel in \
        VERSION \
        install.sh \
        LICENSE \
        README.md \
        bin/rustboard-hub \
        bin/rustboard-panel \
        bin/rustboard-agent \
        systemd/rustboard-hub.service \
        systemd/rustboard-panel.service \
        systemd/rustboard-agent.service; do
        sums_has "$sums" "$rel" || die "SHA256SUMS 未覆盖 $rel，拒绝安装"
    done
    case $ROLE in
        hub | panel)
            sums_has "$sums" "share/rustboard/web/index.html" \
                || die "SHA256SUMS 未覆盖 share/rustboard/web/index.html，拒绝安装"
            ;;
    esac
}

# 读取并校验 VERSION（必须恰一行，且为 semver 形式）。
read_package_version() {
    local -a lines=()
    [[ -f $PKG_ROOT/VERSION && ! -L $PKG_ROOT/VERSION ]] \
        || die "包内缺少普通文件 VERSION"
    mapfile -t lines < "$PKG_ROOT/VERSION" || die "无法读取 VERSION"
    ((${#lines[@]} == 1)) || die "VERSION 必须只有一行"
    VERSION=${lines[0]}
    [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] \
        || die "VERSION 不是合法版本号: $VERSION"
}

# 运行前先按 ELF e_machine 拒绝架构不符（即使宿主启用了 binfmt，也不允许把
# 另一架构的包当成可安装包）。
assert_binary_architecture() {
    local bin=$1 host_arch bin_arch
    host_arch=$(host_machine_arch || true)
    [[ -n $host_arch ]] || die "不支持的本机架构: $(uname -m)"
    bin_arch=$(elf_machine_arch "$bin" || true)
    [[ $bin_arch == "$host_arch" ]] \
        || die "包内二进制架构为 $bin_arch，本机为 $host_arch；请使用对应架构的离线包"
}

host_machine_arch() {
    case $(uname -m) in
        x86_64 | amd64) printf 'x86_64\n' ;;
        aarch64 | arm64) printf 'aarch64\n' ;;
        *) return 1 ;;
    esac
}

# 读取 ELF e_machine（与 build-release.sh 的 lib 实现一致；本脚本必须能脱离
# packaging/lib.sh 独立运行，因此不 source 外部文件）。
elf_machine_arch() {
    local file=$1 magic data b0 b1 machine
    [[ -f $file ]] || return 1
    magic=$(od -An -tx1 -N4 "$file") || return 1
    magic=${magic//[[:space:]]/}
    [[ $magic == 7f454c46 ]] || {
        printf 'unknown:not-elf\n'
        return 0
    }
    data=$(od -An -tu1 -j5 -N1 "$file") || return 1
    data=${data//[[:space:]]/}
    read -r b0 b1 <<< "$(od -An -tu1 -j18 -N2 "$file")" || return 1
    if [[ $data == 2 ]]; then
        machine=$((b0 * 256 + b1))
    else
        machine=$((b0 + b1 * 256))
    fi
    case $machine in
        62) printf 'x86_64\n' ;;
        183) printf 'aarch64\n' ;;
        *) printf 'unknown:%s\n' "$machine" ;;
    esac
}

validate_web_source() {
    local special
    WEB_SRC="$PKG_ROOT/share/rustboard/web"
    [[ -d $WEB_SRC && ! -L $WEB_SRC ]] || die "包内缺少 web 静态目录: $WEB_SRC"
    [[ -f $WEB_SRC/index.html && ! -L $WEB_SRC/index.html ]] \
        || die "包内 web 静态目录缺少普通文件 index.html"
    special=$(find "$WEB_SRC" ! -type f ! -type d -print -quit) \
        || die "检查 web 文件类型失败"
    [[ -z $special ]] \
        || die "包内 web 静态目录含非普通文件/目录（symlink/FIFO/device），拒绝安装: $special"
}

# 逐级创建 web 父目录：
# - 只对本次新建的目录设 0755，保证非 root 进程可读取静态资源；
# - 已存在的目录保持原 mode（不改用户已有布局）；
# - umask 077 只影响 mkdir 的瞬间，紧接着 chmod 新建目录。
ensure_web_parent() {
    local parent=$1
    local -a parts=()
    local current="" part

    [[ -n $parent && $parent == /* ]] || die "web 父目录必须是绝对路径: ${parent:-<空>}"
    IFS='/' read -r -a parts <<< "$parent"
    ((${#parts[@]} > 0)) || parts=( "" )

    for part in "${parts[@]}"; do
        if [[ -z $part ]]; then
            current="/"
        else
            current="${current%/}/$part"
        fi

        if [[ -L $current ]]; then
            die "web 父路径组件是符号链接，拒绝写入: $current"
        fi
        if [[ -e $current ]]; then
            [[ -d $current ]] || die "web 父路径组件不是目录: $current"
            continue
        fi
        mkdir -- "$current" || die "创建 web 父目录失败: $current"
        chmod 0755 -- "$current" || die "设置 web 父目录权限失败: $current"
    done
}

# 原子安装 web：
# 1. 先在同一父目录内 staging 完整复制；
# 2. 旧目录 rename 到备份容器（若有）；
# 3. staging rename 到目标；
# 4. 失败由 EXIT trap 恢复旧目录；成功后备份保留到 Phase A 成功退出再删除。
install_web() {
    local parent=${WEB_DEST%/*}
    local special

    validate_web_source
    assert_safe_root_path "$WEB_DEST" "web 静态目录"
    if [[ -L $WEB_DEST ]]; then
        die "web 静态目录是符号链接，拒绝替换: $WEB_DEST"
    fi

    ensure_web_parent "$parent"

    WEB_STAGING=$(mktemp -d "$parent/.web-staging.XXXXXX") \
        || die "创建 web staging 目录失败"
    cp -a -- "$WEB_SRC/." "$WEB_STAGING/" || die "复制 web 静态资源失败"
    [[ -f $WEB_STAGING/index.html ]] || die "staging 中缺少 index.html"
    special=$(find "$WEB_STAGING" ! -type f ! -type d -print -quit) \
        || die "检查 staging 文件类型失败"
    [[ -z $special ]] || die "staging 中出现非普通文件/目录，拒绝安装: $special"
    # 包可能被非 root 用户解压：cp -a 会保留来源属主/特殊权限；安装为 root 时
    # 收紧为 root 属主并规范化 web 权限，避免普通用户篡改已安装静态资源。
    find "$WEB_STAGING" -type d -exec chmod 0755 {} + \
        || die "设置 web staging 目录权限失败"
    find "$WEB_STAGING" -type f -exec chmod 0644 {} + \
        || die "设置 web staging 文件权限失败"
    if ((EUID == 0)); then
        chown -R 0:0 "$WEB_STAGING" || die "设置 web staging 属主失败"
    fi
    chmod 0755 -- "$WEB_STAGING" || die "设置 web staging 权限失败"

    if [[ -e $WEB_DEST || -L $WEB_DEST ]]; then
        WEB_BACKUP=$(mktemp -d "$parent/.web-backup.XXXXXX") \
            || die "创建 web 备份目录失败"
        mv -T -- "$WEB_DEST" "$WEB_BACKUP/web" \
            || die "备份旧 web 目录失败: $WEB_DEST"
    fi

    # 替换前目标必须不存在；配合 mv -T，目标意外存在时失败而不是嵌套成
    # web/web 或把 staging 移进旧目录。
    if [[ -e $WEB_DEST || -L $WEB_DEST ]]; then
        die "web 目标在替换前仍存在，拒绝嵌套替换: $WEB_DEST"
    fi
    mv -T -- "$WEB_STAGING" "$WEB_DEST" || die "原子替换 web 目录失败: $WEB_DEST"
    WEB_STAGING=""
    WEB_INSTALLED=1
    log "已安装 web 静态资源: $WEB_DEST"
}

has_arg() {
    local needle=$1 arg
    for arg in "${ARGS[@]}"; do
        [[ $arg == "$needle" ]] && return 0
    done
    return 1
}

has_option() {
    local needle=$1 arg
    for arg in "${ARGS[@]}"; do
        [[ $arg == "$needle" || $arg == "$needle="* ]] && return 0
    done
    return 1
}

# 用户是否显式传了角色对应的静态目录参数。
has_static_option() {
    case $ROLE in
        hub) has_option --panel-static-dir ;;
        panel) has_option --static-dir ;;
        *) return 1 ;;
    esac
}

# ----- 入口校验 ---------------------------------------------------------

if (($# == 0)); then
    usage >&2
    exit 2
fi
for arg in "$@"; do
    if [[ $arg == --help || $arg == -h ]]; then
        usage
        exit 0
    fi
done

ROLE=$1
shift
ARGS=("$@")

case $ROLE in
    hub | panel | agent) ;;
    *)
        printf 'error: 第一个参数只允许 hub / panel / agent\n' >&2
        printf '用法: ./install.sh <hub|panel|agent> [install 参数] [--help]\n' >&2
        exit 2
        ;;
esac

scan_secret_args
# secret 参数扫描通过后再挂 trap：失败提示中的参数已确认不含明文 secret。
trap on_exit EXIT
# Phase A 启动前的信号也走 EXIT trap，确保 web staging/旧目录能恢复。
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
parse_prefix
validate_prefix_syntax "$PREFIX"

require_cmd sha256sum stat od find cp mv mkdir chmod chown mktemp awk sed uname dirname

# checksum 之前只允许只读检查；此处不创建目录/文件，也不执行包内二进制。
[[ -f $PKG_ROOT/SHA256SUMS ]] || die "包根缺少 SHA256SUMS: $PKG_ROOT"
validate_sums_manifest

log "校验包完整性: $PKG_ROOT/SHA256SUMS"
(cd -- "$PKG_ROOT" && sha256sum -c --strict SHA256SUMS) \
    || die "SHA256SUMS 校验失败；未写入任何文件"

read_package_version

BIN="$PKG_ROOT/bin/rustboard-$ROLE"
[[ -f $BIN && ! -L $BIN ]] || die "包内缺少普通文件: $BIN"
[[ -x $BIN ]] || die "包内二进制不可执行: $BIN"
assert_binary_architecture "$BIN"

# 校验和通过后才执行二进制；版本输出必须与包 VERSION 一致。
if version_out=$("$BIN" --version 2>&1); then
    :
else
    status=$?
    die "包内二进制 --version 执行失败（退出码 $status；可能架构/依赖不符）: $version_out"
fi
[[ -n $version_out ]] || die "包内二进制 --version 没有输出"
version_token=${version_out##*[[:space:]]}
[[ $version_token == "$VERSION" ]] \
    || die "包内二进制 --version 最后一个 token 是 $version_token，期望 $VERSION: $version_out"

# prefix 必须能安全承载 root 写入。该检查在 web 安装之前完成；具体安装逻辑的
# 路径校验仍由 Rust 安装器负责（双重校验）。
assert_safe_root_path "$PREFIX" "安装前缀"

case $ROLE in
    hub)
        if [[ $PREFIX == / ]]; then
            WEB_DEST=/usr/share/rustboard/web
        else
            WEB_DEST="$PREFIX/usr/share/rustboard/web"
        fi
        ;;
    panel)
        if [[ $PREFIX == / ]]; then
            WEB_DEST=/usr/share/rustboard/web
        else
            WEB_DEST="$PREFIX/usr/share/rustboard/web"
        fi
        ;;
esac

for arg in "${ARGS[@]}"; do
    case $arg in
        --dry-run | --dry-run=*) DRY_RUN=1 ;;
    esac
done

if [[ $ROLE == hub || $ROLE == panel ]]; then
    validate_web_source
    assert_safe_root_path "$WEB_DEST" "web 静态目录"
    if [[ -L $WEB_DEST ]]; then
        die "web 静态目录是符号链接，拒绝替换: $WEB_DEST"
    fi
fi

# 写 web 之前获取 Phase A 全局锁；失败时还没有任何写操作。dry-run 不加锁。
# agent 不写 web，由 Phase A 自己加锁，也不设置继承标记。
if ((DRY_RUN == 0)); then
    case $ROLE in
        hub | panel) acquire_install_lock ;;
        agent) unset RUSTBOARD_INSTALL_LOCK_HELD ;;
    esac
fi

if [[ $ROLE == hub || $ROLE == panel ]] && ! has_static_option; then
    if ((DRY_RUN)); then
        # dry-run 不写 web；只有目标已存在时才追加静态目录，避免让二进制因
        # “显式传入不存在的 --static-dir”而拒绝一个本应可预览的计划。
        if [[ -f $WEB_DEST/index.html ]]; then
            case $ROLE in
                hub) ARGS+=(--panel-static-dir "$WEB_DEST") ;;
                panel) ARGS+=(--static-dir "$WEB_DEST") ;;
            esac
        else
            log "dry-run 不写 web，且 $WEB_DEST 尚不存在；不追加静态目录参数"
        fi
    else
        install_web
        case $ROLE in
            hub) ARGS+=(--panel-static-dir "$WEB_DEST") ;;
            panel) ARGS+=(--static-dir "$WEB_DEST") ;;
        esac
    fi
fi

if ! has_arg --offline; then
    ARGS+=(--offline)
fi

log "包版本: $VERSION"
log "角色: $ROLE"
log "安装前缀: $PREFIX"
if [[ -n $WEB_DEST ]]; then
    if ((DRY_RUN)); then
        log "静态资源: $WEB_DEST（dry-run，不写入）"
    else
        log "静态资源: $WEB_DEST"
    fi
fi
log "离线语义: 不发起外部网络探测；本地 bind / loopback healthz / systemd 仍可发生"
log "若安装失败，可用本脚本加 --dry-run 复现；systemd 日志: journalctl -u rustboard-$ROLE"

# 收到信号时转发给 Phase A，并让 EXIT trap 有机会恢复旧 web。
forward_signal() {
    local sig=$1 code=$2
    trap - INT TERM HUP
    if [[ -n ${CHILD_PID:-} ]] && kill -0 "$CHILD_PID" 2>/dev/null; then
        kill -s "$sig" "$CHILD_PID" 2>/dev/null || true
        wait "$CHILD_PID" 2>/dev/null || true
    fi
    exit "$code"
}

# Phase A 必须是子进程而不是 exec：它失败时 EXIT trap 仍能回滚 web。
# stdout 透传（panel 初始密码仍可见）；stderr 写入 0600 临时文件，结束后
# 统一脱敏再输出，避免 child 错误里带出 URL query / token 文件路径等 secret。
CHILD_STDERR=$(mktemp "${TMPDIR:-/tmp}/rustboard-install-stderr.XXXXXX") \
    || die "创建子进程 stderr 临时文件失败"
chmod 0600 "$CHILD_STDERR" || die "设置子进程 stderr 临时文件权限失败: $CHILD_STDERR"

trap 'forward_signal INT 130' INT
trap 'forward_signal TERM 143' TERM
trap 'forward_signal HUP 129' HUP
"$BIN" install "${ARGS[@]}" 2>"$CHILD_STDERR" <&0 &
CHILD_PID=$!
if wait "$CHILD_PID"; then
    install_status=0
else
    install_status=$?
fi
CHILD_PID=""

# child 成功即标记已提交，成功窗口收到信号也不能再恢复旧 web。
if ((install_status == 0)); then
    WEB_COMMITTED=1
    WEB_INSTALLED=0
fi
flush_child_stderr

if ((install_status != 0)); then
    # 保留 EXIT trap：on_exit 会恢复旧 web（若有）并打印安全失败提示。
    exit "$install_status"
fi

# Phase A 成功：删除 web 备份、释放脚本锁、解除所有 trap，然后以 0 退出。
if [[ -n ${WEB_BACKUP:-} ]]; then
    rm -rf -- "$WEB_BACKUP" || warn "删除 web 备份失败（不影响安装）: $WEB_BACKUP"
    WEB_BACKUP=""
fi
if [[ -n ${LOCK_FD:-} ]]; then
    exec {LOCK_FD}>&-
    LOCK_FD=""
fi
trap - INT TERM HUP
trap - EXIT
exit 0
