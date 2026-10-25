#!/usr/bin/env bash
# 从 CHANGELOG.md 提取指定版本的发布说明，供 release workflow 使用。
#
# 用法: packaging/release-notes.sh <version> <CHANGELOG>
#
# - 版本可带或不带 v 前缀，匹配 `## [v<version>]` 或 `## [<version>]`；
# - 只输出该标题到下一个 `## [` 标题之间的内容（含标题）；
# - 段落缺失或没有实质内容时以非零码退出，绝不生成空 notes；
# - 不修改 CHANGELOG。
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
用法: packaging/release-notes.sh <version> <CHANGELOG>

从 CHANGELOG.md 中提取 `## [v<version>]` 或 `## [<version>]` 段落。
版本可带 v 前缀；[Unreleased] 不是版本。
成功时把段落写到 stdout；缺失或为空时以非零码退出。
EOF
}

if [ "$#" -ne 2 ]; then
  usage
  exit 2
fi

version="$1"
changelog="$2"

# 去掉可选的 v 前缀；空版本与 Unreleased 不是可发布版本。
version="${version#v}"
if [ -z "$version" ]; then
  echo "错误: <version> 不能为空" >&2
  exit 2
fi

case "$version" in
  Unreleased | unreleased | UNRELEASED)
    echo "错误: [Unreleased] 不是发布版本，不能作为 release notes 来源" >&2
    exit 2
    ;;
esac

if [[ ! "$version" =~ ^[0-9]+(\.[0-9]+)*(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "错误: 版本号不合法: ${version}" >&2
  exit 2
fi

if [ ! -f "$changelog" ]; then
  echo "错误: CHANGELOG 不存在或不是普通文件: ${changelog}" >&2
  exit 1
fi
if [ ! -r "$changelog" ]; then
  echo "错误: CHANGELOG 不可读: ${changelog}" >&2
  exit 1
fi

# 用标题解析而不是把版号拼进正则，避免 1.2.3 中的点号被当成通配符。
# 版本标题格式固定为 "## [v1.2.3]"，比较时忽略可选的 v 前缀。
notes="$(
  awk -v want="$version" '
    function heading_version(line, value) {
      if (substr(line, 1, 4) != "## [") {
        return ""
      }
      value = substr(line, 5)
      sub(/\].*$/, "", value)
      if (substr(value, 1, 1) == "v") {
        value = substr(value, 2)
      }
      return value
    }

    /^## \[/ {
      if (inside) {
        exit 0
      }
      if (heading_version($0) == want) {
        inside = 1
        found = 1
      }
    }

    inside {
      print
    }

    END {
      if (!found) {
        exit 42
      }
    }
  ' "$changelog"
)" || {
  status=$?
  if [ "$status" -eq 42 ]; then
    echo "错误: CHANGELOG 中找不到版本 [v${version}] 或 [${version}] 的段落" >&2
  else
    echo "错误: 解析 CHANGELOG 失败（awk 退出码 ${status}）" >&2
  fi
  exit 1
}

# 只有标题、空行或纯空白不算有效发布说明。
if ! printf '%s\n' "$notes" | tail -n +2 | grep -q '[^[:space:]]'; then
  echo "错误: 版本 [v${version}] 的 CHANGELOG 段落为空" >&2
  exit 1
fi

printf '%s\n' "$notes"
