#!/usr/bin/env bash
# RustBoard 发布脚本共用库（M5 Phase B）。
#
# 用法：在 `set -euo pipefail` 的脚本里 source 本文件。本文件只定义函数，
# **不执行任何顶层副作用**（不 cd、不创建文件、不改 umask、不检查命令）。
#
# 约定：
# - 失败统一走 `die`（写 stderr 后退出 1）；调用方负责 trap 清理临时目录；
# - 所有路径都由调用方校验；本库不默认信任外部输入；
# - 不打印 token / 密码 / 私钥；需要展示命令输出时先用 `redact` 过滤。

# 统一日志前缀；只写 stderr，避免污染 stdout 的机器可读输出。
log() {
    printf '==> %s\n' "$*" >&2
}

warn() {
    printf 'warning: %s\n' "$*" >&2
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

# 检查命令是否存在；缺失时给出可操作的错误。
require_cmd() {
    local cmd
    for cmd in "$@"; do
        command -v "$cmd" >/dev/null 2>&1 || die "缺少必需命令: $cmd"
    done
}

# 把疑似 secret 的值替换成 ***。
# 本仓库的脚本从不接收明文 secret；该函数用于兜底外部工具输出。
redact() {
    sed -E 's/((token|password|secret|authorization)[A-Za-z0-9_-]*[[:space:]]*[=:][[:space:]]*)[^[:space:]]+/\1***/Ig'
}

# 仓库根目录：lib.sh 位于 <repo>/packaging/，因此取本文件所在目录的上一级。
# 用子 shell 执行 cd，避免改变调用方的当前目录。
repo_root() {
    local src dir
    src=${BASH_SOURCE[0]}
    dir=$(cd -- "$(dirname -- "$src")" && pwd -P) || return 1
    (cd -- "$dir/.." && pwd -P)
}

# 读取根 Cargo.toml 的 [workspace.package].version。
# 只解析该 section，避免误读 [package] / 依赖里的 version。
workspace_version() {
    local root manifest
    root=$(repo_root) || return 1
    manifest=${1:-"$root/Cargo.toml"}
    [[ -f "$manifest" ]] || return 1
    awk '
        /^[[:space:]]*\[workspace\.package\][[:space:]]*$/ { in_section = 1; next }
        /^[[:space:]]*\[/ { in_section = 0 }
        in_section && /^[[:space:]]*version[[:space:]]*=/ {
            line = $0
            sub(/^[^=]*=[[:space:]]*"/, "", line)
            sub(/".*$/, "", line)
            print line
            exit
        }
    ' "$manifest"
}

# Docker/buildx 使用的目标架构：amd64 / arm64。
# 接受常见的 target 拼写与包架构拼写。
target_arch() {
    case ${1:-} in
        amd64 | x86_64) printf 'amd64\n' ;;
        arm64 | aarch64) printf 'arm64\n' ;;
        *) return 1 ;;
    esac
}

# 离线包 / 二进制发布名使用的包架构：x86_64 / aarch64。
pkg_arch() {
    local target
    target=$(target_arch "${1:-}") || return 1
    case "$target" in
        amd64) printf 'x86_64\n' ;;
        arm64) printf 'aarch64\n' ;;
        *) return 1 ;;
    esac
}

# 本机架构对应的包架构；无法识别时返回 1。
host_pkg_arch() {
    case $(uname -m) in
        x86_64 | amd64) printf 'x86_64\n' ;;
        aarch64 | arm64) printf 'aarch64\n' ;;
        *) return 1 ;;
    esac
}

# 跨架构运行二进制所需的 qemu 用户态程序名；调用方用 command -v 判断存在性。
qemu_for_pkg_arch() {
    case ${1:-} in
        x86_64) printf 'qemu-x86_64-static\n' ;;
        aarch64) printf 'qemu-aarch64-static\n' ;;
        *) return 1 ;;
    esac
}

# 只输出文件的 sha256 十六进制值（不含文件名）。
sha256_file() {
    local file=${1:-} out
    [[ -n "$file" && -f "$file" ]] || return 1
    out=$(sha256sum -- "$file") || return 1
    printf '%s\n' "${out%% *}"
}

# 读取 ELF 头里的 e_machine，返回 x86_64 / aarch64 / unknown:<值>。
# 不依赖 file / readelf，只需要 coreutils 的 od；用于在运行二进制前先拒绝架构不符。
elf_machine_arch() {
    local file=${1:-} magic data b0 b1 machine
    [[ -n "$file" && -f "$file" ]] || return 1

    magic=$(od -An -tx1 -N4 "$file") || return 1
    magic=${magic//[[:space:]]/}
    [[ "$magic" == 7f454c46 ]] || {
        printf 'unknown:not-elf\n'
        return 0
    }

    data=$(od -An -tu1 -j5 -N1 "$file") || return 1
    data=${data//[[:space:]]/}
    # e_machine 在 64 位 ELF 头偏移 18，宽度 2 字节。
    read -r b0 b1 <<< "$(od -An -tu1 -j18 -N2 "$file")" || return 1
    if [[ "$data" == 2 ]]; then
        machine=$((b0 * 256 + b1))
    else
        machine=$((b0 + b1 * 256))
    fi

    case "$machine" in
        62) printf 'x86_64\n' ;;
        183) printf 'aarch64\n' ;;
        *) printf 'unknown:%s\n' "$machine" ;;
    esac
}

# 断言一个二进制是静态（static / static-pie）ELF 且没有程序解释器。
# - file 负责断言 static / static-pie；
# - readelf -l 负责断言不存在 INTERP（不依赖 Alpine 上 ldd 的行为）。
assert_static_elf() {
    local bin=${1:-} label=${2:-${1:-<未命名>}} desc phdr
    [[ -n "$bin" && -f "$bin" ]] || die "$label 不存在或不是普通文件: ${bin:-<空路径>}"

    desc=$(file -b "$bin") || die "file 无法读取 $label: $bin"
    [[ "$desc" == ELF* ]] || die "$label 不是 ELF: $bin（file: $desc）"
    case "$desc" in
        *"static-pie linked"* | *"statically linked"*) ;;
        *) die "$label 不是静态 ELF: $bin（file: $desc）" ;;
    esac

    phdr=$(readelf -lW "$bin") || die "readelf 无法读取 $label: $bin"
    if grep -q 'INTERP' <<< "$phdr"; then
        die "$label 含有 INTERP（动态链接），拒绝发布: $bin"
    fi
}

# 断言二进制来自 Alpine/musl 构建（读取 .comment）。
# 主要用于 --skip-build：防止把 glibc / stale 产物当成发布物打包。
assert_musl_elf() {
    local bin=${1:-} label=${2:-${1:-<未命名>}} comment
    [[ -n "$bin" && -f "$bin" ]] || die "$label 不存在或不是普通文件: ${bin:-<空路径>}"

    # readelf 在 section 不存在时也可能返回 0，因此要同时检查输出是否为空。
    comment=$(readelf -p .comment "$bin" 2>/dev/null) || comment=""
    [[ -n "$comment" ]] || die "$label 缺少 .comment，无法确认 Alpine/musl 构建（--skip-build 可能复用了 glibc/stale 产物）"
    if ! grep -Eqi 'alpine|musl' <<< "$comment"; then
        die "$label 的 .comment 未包含 Alpine/musl，拒绝发布: $bin"
    fi
}
