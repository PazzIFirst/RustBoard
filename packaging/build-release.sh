#!/usr/bin/env bash
# RustBoard 离线发布包构建（M5 Phase B）。
#
# 流程：
#   1. 校验 Cargo.toml / --version / 前端产物 / 输出目录；
#   2. 对每个目标架构用 buildx 构建静态 musl 二进制（或 --skip-build 复用）；
#   3. 校验 ELF 架构、静态链接、--version；
#   4. 按方案 §3.3 组装包、生成包内 SHA256SUMS、确定性 tar.gz；
#   5. 生成只含该架构 tarball 的 dist/SHA256SUMS.<pkgarch>。
#
# 本脚本不提交 git，不写 /etc、/var/lib/rustboard、/usr/local。
# 临时目录用 mktemp 创建，退出时由 trap 清理；不打印 token / secret。

set -euo pipefail
umask 022

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

REPO=$(repo_root) || die "无法定位仓库根目录"
cd -- "$REPO"

ARCH=all
VERSION_INPUT=""
VERSION_SET=0
REVISION_INPUT=""
REVISION_SET=0
WEB_DIR=web/dist
OUT_DIR=dist
SKIP_BUILD=0

usage() {
    cat <<'EOF'
用法: packaging/build-release.sh [选项]

构建 RustBoard 两架构静态 musl 离线发布包。

选项:
  --arch ARCH        amd64 | arm64 | x86_64 | aarch64 | all（默认 all）
  --version V        必须与根 Cargo.toml 的 [workspace.package].version 一致
  --revision REV     构建修订号，默认 git rev-parse --short=12 HEAD
  --web-dir DIR      前端构建产物目录，默认 web/dist，必须包含 index.html
  --out DIR          输出目录，默认 dist；仅允许仓库内、/tmp、/opt
  --skip-build       复用 <out>/<amd64|arm64>/bin，不调用 Docker
  --help, -h         显示本帮助

产物:
  <out>/<amd64|arm64>/bin/rustboard-{hub,panel,agent}
  <out>/serverdashboard-v<version>-<x86_64|aarch64>/
  <out>/serverdashboard-v<version>-<x86_64|aarch64>.tar.gz
  <out>/SHA256SUMS.<x86_64|aarch64>

示例:
  pnpm -C web build
  packaging/build-release.sh --arch amd64
  packaging/build-release.sh --arch arm64 --out dist
  packaging/build-release.sh --arch all --version 0.4.2 --revision $(git rev-parse --short=12 HEAD)

说明:
  - 使用固定 digest 的 rust:1.89-alpine，buildx 在目标平台 native 构建；
  - SOURCE_DATE_EPOCH 默认取 HEAD 提交时间，可用环境变量覆盖；
  - arm64 产物在本机有 qemu-aarch64-static 时执行 --version，否则只做静态校验
    （会明确标注“未执行”，不伪装成运行通过）；
  - 构建时先完成全部架构的二进制校验，再打包，避免只产出半套包。
EOF
}

while (($#)); do
    case $1 in
        --arch)
            (($# >= 2)) || die "--arch 缺少取值"
            ARCH=$2
            shift 2
            ;;
        --arch=*)
            ARCH=${1#--arch=}
            shift
            ;;
        --version)
            (($# >= 2)) || die "--version 缺少取值"
            VERSION_INPUT=$2
            VERSION_SET=1
            shift 2
            ;;
        --version=*)
            VERSION_INPUT=${1#--version=}
            VERSION_SET=1
            shift
            ;;
        --revision)
            (($# >= 2)) || die "--revision 缺少取值"
            REVISION_INPUT=$2
            REVISION_SET=1
            shift 2
            ;;
        --revision=*)
            REVISION_INPUT=${1#--revision=}
            REVISION_SET=1
            shift
            ;;
        --web-dir)
            (($# >= 2)) || die "--web-dir 缺少取值"
            WEB_DIR=$2
            shift 2
            ;;
        --web-dir=*)
            WEB_DIR=${1#--web-dir=}
            shift
            ;;
        --out)
            (($# >= 2)) || die "--out 缺少取值"
            OUT_DIR=$2
            shift 2
            ;;
        --out=*)
            OUT_DIR=${1#--out=}
            shift
            ;;
        --skip-build)
            SKIP_BUILD=1
            shift
            ;;
        --help | -h)
            usage
            exit 0
            ;;
        --)
            shift
            (($# == 0)) || die "不支持位置参数: $*"
            ;;
        -*)
            die "未知参数: $1（--help 查看用法）"
            ;;
        *)
            die "不支持位置参数: $1（--help 查看用法）"
            ;;
    esac
done

# 架构归一化。--arch all 表示本地两架构；CI 应按架构分别调用。
ARCHES=()
if [[ $ARCH == all ]]; then
    ARCHES=(amd64 arm64)
else
    normalized_arch=$(target_arch "$ARCH") || die "--arch 只接受 amd64 / arm64 / x86_64 / aarch64 / all，实际: $ARCH"
    ARCHES=("$normalized_arch")
fi

# 版本必须来自 Cargo.toml；显式 --version 只用于防手误，不允许改版本。
CARGO_VERSION=$(workspace_version) || die "无法从根 Cargo.toml 读取 [workspace.package].version"
[[ -n $CARGO_VERSION ]] || die "根 Cargo.toml 的 [workspace.package].version 为空"
[[ $CARGO_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]+)?$ ]] \
    || die "Cargo.toml workspace version 不是合法版本号: $CARGO_VERSION"
if ((VERSION_SET)); then
    [[ -n $VERSION_INPUT ]] || die "--version 不能为空"
    [[ $VERSION_INPUT == "$CARGO_VERSION" ]] \
        || die "显式 --version ($VERSION_INPUT) 必须与 Cargo.toml workspace version ($CARGO_VERSION) 一致；拒绝打错版本"
fi
VERSION=$CARGO_VERSION

# 修订号只用于构建日志/可追溯，不写入包布局（方案 §3.3 固定文件清单）。
require_cmd git
if ((REVISION_SET)); then
    [[ -n $REVISION_INPUT ]] || die "--revision 不能为空"
    REVISION=$REVISION_INPUT
else
    REVISION=$(git -C "$REPO" rev-parse --short=12 HEAD) \
        || die "无法读取 git revision（请在 git 仓库内运行或显式传 --revision）"
fi
[[ $REVISION =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] \
    || die "--revision 含非法字符（只允许字母、数字、. _ -）: $REVISION"

# 前端产物必须存在且已完成构建；缺 index.html 时在创建任何输出目录之前失败。
WEB_DIR_ABS=$WEB_DIR
if [[ $WEB_DIR_ABS != /* ]]; then
    WEB_DIR_ABS="$REPO/$WEB_DIR_ABS"
fi
[[ -d $WEB_DIR_ABS ]] || die "前端构建产物目录不存在: $WEB_DIR_ABS；请先运行 pnpm -C web build"
[[ -f $WEB_DIR_ABS/index.html && ! -L $WEB_DIR_ABS/index.html ]] \
    || die "前端产物缺少普通文件 index.html: $WEB_DIR_ABS；请先运行 pnpm -C web build"
WEB_DIR_ABS=$(cd -- "$WEB_DIR_ABS" && pwd -P) || die "无法解析前端产物目录: $WEB_DIR"

require_cmd awk sed grep file readelf sha256sum tar gzip find sort install cp mv rm mkdir mktemp od dirname uname realpath

# 输出目录白名单（在 realpath 之后调用）：只允许仓库内（.git 除外）、/tmp、/opt。
assert_allowed_out_dir() {
    local path=$1
    case $path in
        "$REPO/.git" | "$REPO/.git/"*)
            die "拒绝把构建产物写入仓库 .git: $path"
            ;;
        "$REPO" | "$REPO"/* | /tmp | /tmp/* | /opt | /opt/*)
            return 0
            ;;
    esac
    die "--out 只允许仓库、/tmp 或 /opt 下的路径（拒绝系统目录）: $path"
}

OUT_DIR_ABS=$OUT_DIR
[[ -n $OUT_DIR_ABS ]] || die "--out 不能为空"
if [[ $OUT_DIR_ABS != /* ]]; then
    OUT_DIR_ABS="$REPO/$OUT_DIR_ABS"
fi
[[ $OUT_DIR_ABS != *'//'* ]] || die "--out 不能包含重复分隔符: $OUT_DIR_ABS"
[[ $OUT_DIR_ABS != *'/../'* && $OUT_DIR_ABS != *'/..' ]] \
    || die "--out 不能包含 .. 组件: $OUT_DIR_ABS"
OUT_DIR_ABS=${OUT_DIR_ABS%/}
[[ -n $OUT_DIR_ABS && $OUT_DIR_ABS != / ]] || die "--out 不能是根目录"
[[ $OUT_DIR_ABS != *,* ]] || die "--out 不能包含逗号（buildx --output 用逗号分隔选项）"
# 先 realpath（不写文件）再按白名单判断；随后 mkdir 并再次 realpath 校验，
# 防止 `--out /tmp/link-to-usr` 在检查后绕过。
OUT_DIR_ABS=$(realpath -m "$OUT_DIR_ABS") || die "无法解析输出目录: $OUT_DIR"
assert_allowed_out_dir "$OUT_DIR_ABS"

mkdir -p -- "$OUT_DIR_ABS" || die "创建输出目录失败: $OUT_DIR_ABS"
OUT_DIR_ABS=$(realpath -e "$OUT_DIR_ABS") || die "无法解析输出目录: $OUT_DIR"
assert_allowed_out_dir "$OUT_DIR_ABS"

if ((SKIP_BUILD == 0)); then
    require_cmd docker
    docker buildx version >/dev/null 2>&1 \
        || die "docker buildx 不可用；请安装 buildx 或使用 --skip-build"
fi

# 确定性 tar 的时间戳：默认用 HEAD 提交时间，允许发布环境覆盖。
if [[ -z ${SOURCE_DATE_EPOCH:-} ]]; then
    SOURCE_DATE_EPOCH=$(git -C "$REPO" log -1 --format=%ct) \
        || die "无法读取 HEAD 提交时间（可显式设置 SOURCE_DATE_EPOCH）"
fi
[[ $SOURCE_DATE_EPOCH =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH 必须是整数秒: $SOURCE_DATE_EPOCH"
export SOURCE_DATE_EPOCH

WORK=$(mktemp -d "$OUT_DIR_ABS/.build.XXXXXX") || die "无法创建临时目录"
cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n ${WORK:-} && -d ${WORK:-} ]]; then
        rm -rf -- "$WORK"
    fi
    exit "$status"
}
trap cleanup EXIT

log "RustBoard $VERSION（revision $REVISION，SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH）"
log "前端产物: $WEB_DIR_ABS"

# 可执行性验证：本机架构直接运行；跨架构优先 qemu-<arch>-static。
# 无 qemu 时不执行，并在日志与最终摘要中明确标注“未验证”。
declare -A ARCH_VERIFIED=()
declare -a RUNNER=()

run_with_runner() {
    local bin=$1
    shift
    if ((${#RUNNER[@]})); then
        "${RUNNER[@]}" "$bin" "$@"
    else
        "$bin" "$@"
    fi
}

for target in "${ARCHES[@]}"; do
    pkg=$(pkg_arch "$target") || die "无法映射架构: $target"
    bin_dir="$OUT_DIR_ABS/$target/bin"

    if ((SKIP_BUILD)); then
        log "复用已有产物: $bin_dir（$pkg）"
        [[ -d $bin_dir ]] || die "--skip-build 需要已有目录: $bin_dir"
    else
        log "构建 linux/$target（$pkg）..."
        # 清掉旧目录，避免上一次构建的残留文件被一起导出/打包。
        rm -rf -- "${OUT_DIR_ABS:?}/$target"
        docker buildx build \
            --platform "linux/$target" \
            --target export \
            --output "type=local,dest=$OUT_DIR_ABS/$target" \
            -f docker/Dockerfile.build .
    fi

    # 静态 + 架构校验：先证明产物确实是该架构的静态 ELF，再尝试运行。
    for name in rustboard-hub rustboard-panel rustboard-agent; do
        bin="$bin_dir/$name"
        [[ -f $bin && -x $bin ]] || die "缺少可执行产物: $bin"
        assert_static_elf "$bin" "$name（$pkg）"
        # --skip-build 可能复用旧目录里的 glibc/stale 产物；用 .comment 断言
        # 它确实来自 Alpine/musl 构建。Docker 构建路径由固定基础镜像保证。
        if ((SKIP_BUILD)); then
            assert_musl_elf "$bin" "$name（$pkg）"
        fi
        actual_arch=$(elf_machine_arch "$bin") || die "无法读取 ELF 架构: $bin"
        [[ $actual_arch == "$pkg" ]] \
            || die "$bin 的 ELF 架构是 $actual_arch，与目标 $pkg 不符"
    done

    host_arch=$(host_pkg_arch || true)
    RUNNER=()
    runner_label=""
    if [[ -n $host_arch && $host_arch == "$pkg" ]]; then
        runner_label="native"
    else
        qemu_bin=$(command -v "$(qemu_for_pkg_arch "$pkg")" 2>/dev/null || true)
        if [[ -n $qemu_bin ]]; then
            RUNNER=("$qemu_bin")
            runner_label=$qemu_bin
        else
            warn "$pkg 未执行 --version：本机为 ${host_arch:-未知架构}，且找不到 $(qemu_for_pkg_arch "$pkg")"
            warn "$pkg 仅完成静态/架构校验，不能视为运行验证通过"
            ARCH_VERIFIED[$target]=0
            continue
        fi
    fi

    for name in rustboard-hub rustboard-panel rustboard-agent; do
        bin="$bin_dir/$name"
        if version_out=$(run_with_runner "$bin" --version 2>&1); then
            :
        else
            status=$?
            die "$name --version 执行失败（退出码 $status，runner=$runner_label）: $version_out"
        fi
        version_token=${version_out##*[[:space:]]}
        [[ $version_token == "$VERSION" ]] \
            || die "$name --version 最后一个 token 是 $version_token，期望 $VERSION: $version_out"
        log "  $name --version: $version_out（$runner_label）"
    done
    ARCH_VERIFIED[$target]=1
done

# 包内 SHA256SUMS 的覆盖断言。
sums_has() {
    local sums=$1 rel=$2
    awk -v target="$rel" '
        {
            line = $0
            sub(/^[0-9a-fA-F]+[[:space:]]+/, "", line)
            if (line == target) {
                found = 1
            }
        }
        END { exit(found ? 0 : 1) }
    ' "$sums"
}

# 组装单个架构的包，但先留在 WORK；全部架构成功后再移动到 dist。
package_arch() {
    local target=$1 pkg=$2
    local pkgbase="serverdashboard-v${VERSION}-${pkg}"
    local pkgdir="$WORK/$pkgbase"
    local bin_dir="$OUT_DIR_ABS/$target/bin"
    local sums_tmp="$WORK/$pkgbase.SHA256SUMS"
    local tar_file="$WORK/$pkgbase.tar.gz"
    local list_file="$WORK/$pkgbase.tar.list"
    local special line rel hash

    log "打包 $pkgbase..."
    rm -rf -- "$pkgdir"
    mkdir -p -- "$pkgdir/bin" "$pkgdir/share/rustboard/web" "$pkgdir/systemd"

    install -m 0755 "$bin_dir/rustboard-hub" "$pkgdir/bin/rustboard-hub"
    install -m 0755 "$bin_dir/rustboard-panel" "$pkgdir/bin/rustboard-panel"
    install -m 0755 "$bin_dir/rustboard-agent" "$pkgdir/bin/rustboard-agent"

    cp -a -- "$WEB_DIR_ABS/." "$pkgdir/share/rustboard/web/"
    special=$(find "$pkgdir" ! -type f ! -type d -print -quit) \
        || die "检查包内文件类型失败"
    [[ -z $special ]] || die "包内只允许普通文件和目录（发现 symlink/FIFO/device）: $special"
    find "$pkgdir/share/rustboard/web" -type d -exec chmod 0755 {} + \
        || die "规范化 web 目录权限失败"
    find "$pkgdir/share/rustboard/web" -type f -exec chmod 0644 {} + \
        || die "规范化 web 文件权限失败"

    install -m 0644 "$REPO/LICENSE" "$pkgdir/LICENSE"
    install -m 0644 "$SCRIPT_DIR/README.md" "$pkgdir/README.md"
    install -m 0755 "$SCRIPT_DIR/install.sh" "$pkgdir/install.sh"
    install -m 0644 "$REPO/packaging/systemd/"*.service "$pkgdir/systemd/"
    printf '%s\n' "$VERSION" > "$pkgdir/VERSION"
    chmod 0644 "$pkgdir/VERSION"

    # 包内校验和：在包根目录下用相对路径，按路径排序；SHA256SUMS 自身不参与。
    (
        cd -- "$pkgdir"
        find . -type f ! -path './SHA256SUMS' -printf '%P\0' \
            | LC_ALL=C sort -z \
            | while IFS= read -r -d '' rel; do
                sha256sum -- "$rel"
            done
    ) > "$sums_tmp" || die "生成包内 SHA256SUMS 失败: $pkg"
    install -m 0644 "$sums_tmp" "$pkgdir/SHA256SUMS"

    for rel in \
        bin/rustboard-hub \
        bin/rustboard-panel \
        bin/rustboard-agent \
        share/rustboard/web/index.html \
        systemd/rustboard-hub.service \
        systemd/rustboard-panel.service \
        systemd/rustboard-agent.service \
        install.sh VERSION LICENSE README.md; do
        sums_has "$pkgdir/SHA256SUMS" "$rel" || die "SHA256SUMS 未覆盖 $rel（$pkg）"
    done
    if awk '
        {
            line = $0
            sub(/^[0-9a-fA-F]+[[:space:]]+/, "", line)
            if (line ~ /^\// || line ~ /(^|\/)\.\.(\/|$)/) bad = 1
        }
        END { exit(bad ? 1 : 0) }
    ' "$pkgdir/SHA256SUMS"; then
        :
    else
        die "包内 SHA256SUMS 含绝对路径或 .. 路径（$pkg）"
    fi
    (cd -- "$pkgdir" && sha256sum -c --strict SHA256SUMS >/dev/null) \
        || die "包内 SHA256SUMS 自校验失败（$pkg）"

    # 确定性 tar：排序、固定 mtime/owner/group、numeric-owner，gzip -n。
    tar --sort=name \
        --mtime="@$SOURCE_DATE_EPOCH" \
        --owner=0 --group=0 --numeric-owner \
        -C "$WORK" -cf "$WORK/$pkgbase.tar" "$pkgbase" \
        || die "tar 打包失败: $pkgbase"
    gzip -n -9 -c "$WORK/$pkgbase.tar" > "$tar_file" \
        || die "gzip 压缩失败: $pkgbase"
    rm -f -- "$WORK/$pkgbase.tar"

    tar -tzf "$tar_file" > "$list_file" || die "无法读取 tarball: $tar_file"
    while IFS= read -r line; do
        [[ $line == "$pkgbase/"* ]] || die "tarball 含异常路径: $line"
    done < "$list_file"
    for rel in install.sh VERSION SHA256SUMS LICENSE README.md bin/rustboard-hub \
        share/rustboard/web/index.html; do
        grep -Fxq "$pkgbase/$rel" "$list_file" || die "tarball 缺少 $rel（$pkg）"
    done

    hash=$(sha256_file "$tar_file") || die "计算 tarball sha256 失败: $tar_file"
    printf '%s  %s\n' "$hash" "$pkgbase.tar.gz" > "$WORK/SHA256SUMS.$pkg"
    (cd -- "$WORK" && sha256sum -c --strict "SHA256SUMS.$pkg" >/dev/null) \
        || die "外部 SHA256SUMS 自校验失败（$pkg）"
}

for target in "${ARCHES[@]}"; do
    pkg=$(pkg_arch "$target") || die "无法映射架构: $target"
    package_arch "$target" "$pkg"
done

# 全部架构打包成功后再替换 dist 产物，避免构建失败时留下半套发布物。
for target in "${ARCHES[@]}"; do
    pkg=$(pkg_arch "$target") || die "无法映射架构: $target"
    pkgbase="serverdashboard-v${VERSION}-${pkg}"
    rm -rf -- "${OUT_DIR_ABS:?}/$pkgbase"
    rm -f -- "$OUT_DIR_ABS/$pkgbase.tar.gz" "$OUT_DIR_ABS/SHA256SUMS.$pkg"
    mv -- "$WORK/$pkgbase" "$OUT_DIR_ABS/"
    mv -- "$WORK/$pkgbase.tar.gz" "$OUT_DIR_ABS/"
    mv -- "$WORK/SHA256SUMS.$pkg" "$OUT_DIR_ABS/"
done

log "发布物已生成: $OUT_DIR_ABS"
for target in "${ARCHES[@]}"; do
    pkg=$(pkg_arch "$target")
    pkgbase="serverdashboard-v${VERSION}-${pkg}"
    if [[ ${ARCH_VERIFIED[$target]:-0} == 1 ]]; then
        printf '  %s/bin/rustboard-{hub,panel,agent}（已执行 --version）\n' "$OUT_DIR_ABS/$target"
    else
        printf '  %s/bin/rustboard-{hub,panel,agent}（仅静态校验；未执行 --version）\n' "$OUT_DIR_ABS/$target"
    fi
    printf '  %s/%s/\n' "$OUT_DIR_ABS" "$pkgbase"
    printf '  %s/%s.tar.gz\n' "$OUT_DIR_ABS" "$pkgbase"
    printf '  %s/SHA256SUMS.%s\n' "$OUT_DIR_ABS" "$pkg"
done
