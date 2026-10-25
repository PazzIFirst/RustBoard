#!/usr/bin/env python3
"""从 cargo metadata 生成 RustBoard 的 SPDX 2.3 JSON SBOM。

只依赖 Python 3 标准库。输入来自：

    cargo metadata --locked --format-version 1 [--manifest-path PATH]

输出为确定性的 SPDX 2.3 JSON（排序键、缩进固定），时间戳默认取固定 UTC
（1970-01-01T00:00:00Z），可用 SOURCE_DATE_EPOCH 覆盖，避免每次运行产生
不同的 SBOM。生成失败时以非零码退出，不会写出空文件。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

TOOL_NAME = "rustboard-sbom.py"
SPDX_VERSION = "SPDX-2.3"
DEFAULT_NAMESPACE_BASE = "https://github.com/PazzIFirst/RustBoard/spdx"
MAX_CARGO_STDERR = 4000


class SbomError(Exception):
    """可预期的生成错误；由 main() 转成 stderr + 非零退出码。"""


def fail(message: str) -> None:
    raise SbomError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="从 cargo metadata 生成 SPDX 2.3 JSON SBOM（纯标准库）。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python3 packaging/sbom.py \\\n"
            "    --output dist/sbom-x86_64.spdx.json \\\n"
            "    --version 1.0.0 --revision <git-sha> --arch x86_64\n"
            "\n"
            "确定性: 设置 SOURCE_DATE_EPOCH 可固定 creationInfo.created；\n"
            "未设置时使用固定值 0（1970-01-01T00:00:00Z）。\n"
            "缺少 license 字段的包使用 SPDX 的 NOASSERTION；\n"
            "Cargo 旧式 \"/\" 许可分隔符按 OR 规范化。\n"
        ),
    )
    parser.add_argument("--output", required=True, metavar="PATH", help="输出文件路径（UTF-8 JSON）")
    parser.add_argument("--version", required=True, help="发布版本，例如 1.0.0（可带 v 前缀）")
    parser.add_argument("--revision", required=True, help="源码 revision，通常是 40 位 git commit SHA")
    parser.add_argument("--arch", default=None, help="目标架构，例如 x86_64 / aarch64（可选）")
    parser.add_argument(
        "--namespace",
        default=None,
        help=(
            "SPDX documentNamespace（可选）。默认 "
            "https://github.com/PazzIFirst/RustBoard/spdx/<version>/<revision>[/<arch>]"
        ),
    )
    parser.add_argument(
        "--manifest-path",
        default=None,
        metavar="PATH",
        help="传给 cargo metadata 的 --manifest-path（可选，默认当前目录）",
    )
    return parser


def _clean_text(value: str, field: str) -> str:
    value = value.strip()
    if not value:
        fail(f"{field} 不能为空")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        fail(f"{field} 不能包含控制字符")
    return value


def _created_timestamp() -> str:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None or raw.strip() == "":
        epoch = 0
    else:
        raw = raw.strip()
        if not re.fullmatch(r"[0-9]+", raw):
            fail("SOURCE_DATE_EPOCH 必须是 >= 0 的整数秒")
        epoch = int(raw)
    try:
        created = datetime.fromtimestamp(epoch, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        fail(f"SOURCE_DATE_EPOCH 无法转换为 UTC 时间: {exc}")
    return created.strftime("%Y-%m-%dT%H:%M:%SZ")


def _document_namespace(args: argparse.Namespace, version: str, revision: str, arch: str | None) -> str:
    if args.namespace is not None:
        namespace = args.namespace.strip()
        if not namespace:
            fail("--namespace 不能为空")
        if any(ord(char) < 0x20 or char.isspace() for char in namespace):
            fail("--namespace 不能包含空白或控制字符")
        parsed = urlparse(namespace)
        if not parsed.scheme:
            fail("--namespace 必须是绝对 URI（缺少 scheme）")
        if parsed.scheme in ("http", "https") and not parsed.netloc:
            fail("--namespace 的 http(s) URI 必须包含主机名")
        return namespace

    segments = [
        DEFAULT_NAMESPACE_BASE,
        quote(version, safe=""),
        quote(revision, safe=""),
    ]
    if arch:
        segments.append(quote(arch, safe=""))
    return "/".join(segments)


def _run_cargo_metadata(manifest_path: str | None) -> dict:
    command = ["cargo", "metadata", "--locked", "--format-version", "1"]
    if manifest_path:
        command.extend(["--manifest-path", manifest_path])

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except FileNotFoundError:
        fail("找不到 cargo；请先安装 Rust 工具链")
    except OSError as exc:
        fail(f"无法执行 cargo metadata: {exc}")

    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        if len(stderr) > MAX_CARGO_STDERR:
            stderr = "...(截断)...\n" + stderr[-MAX_CARGO_STDERR:]
        detail = f"\n{stderr}" if stderr else "（cargo 未输出 stderr）"
        fail(f"cargo metadata 失败（退出码 {completed.returncode}）{detail}")

    stdout = completed.stdout or ""
    if not stdout.strip():
        fail("cargo metadata 输出为空")
    try:
        metadata = json.loads(stdout)
    except json.JSONDecodeError as exc:
        fail(f"cargo metadata 输出不是合法 JSON: {exc}")
    if not isinstance(metadata, dict):
        fail("cargo metadata 顶层不是 JSON object")
    return metadata


def _license_declared(package: dict) -> str:
    license_value = package.get("license")
    if not isinstance(license_value, str) or not license_value.strip():
        return "NOASSERTION"
    expression = " ".join(license_value.split())
    # Cargo/crates.io 历史上用 "/" 表示 OR（例如 MIT/Apache-2.0），
    # 但 SPDX 表达式不允许 "/"；按 Cargo 语义规范化为 OR。
    expression = re.sub(r"\s*/\s*", " OR ", expression)
    return expression or "NOASSERTION"


def _download_location(package: dict, name: str, package_version: str) -> str:
    source = package.get("source")
    if not isinstance(source, str) or not source:
        # workspace 成员或本地 vendored path 依赖没有可下载地址。
        return "NOASSERTION"
    if source.startswith("registry+"):
        if "crates.io" in source:
            return (
                "https://crates.io/api/v1/crates/"
                f"{quote(name, safe='')}/{quote(package_version, safe='')}/download"
            )
        return "NOASSERTION"
    if source.startswith("git+"):
        location = source[len("git+") :]
        return location or "NOASSERTION"
    return "NOASSERTION"


def _source_kind(package: dict, workspace_members: set[str]) -> str:
    package_id = package.get("id")
    if isinstance(package_id, str) and package_id in workspace_members:
        return "workspace member"
    source = package.get("source")
    if not isinstance(source, str) or not source:
        return "path/vendored package"
    kind = source.split("+", 1)[0]
    if kind == "registry":
        if "crates.io" in source:
            return "crates.io registry"
        return "cargo registry"
    if kind == "git":
        return "git dependency"
    return f"cargo {kind} source" if kind else "cargo source"


def _external_refs(name: str, package_version: str) -> list[dict]:
    locator = (
        "pkg:cargo/"
        f"{quote(name, safe='.-_~')}@{quote(package_version, safe='.-_~')}"
    )
    return [
        {
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": locator,
        }
    ]


def _spdx_base_id(name: str, package_version: str) -> str:
    raw = f"{name}-{package_version}"
    safe = re.sub(r"[^A-Za-z0-9.-]+", "-", raw).strip("-.")
    if not safe:
        safe = "package"
    return f"SPDXRef-Package-{safe}"


def _package_sort_key(package: dict) -> tuple:
    return (
        str(package.get("name") or ""),
        str(package.get("version") or ""),
        str(package.get("source") or ""),
        str(package.get("id") or ""),
    )


def build_document(args: argparse.Namespace) -> dict:
    version = _clean_text(args.version, "--version")
    if version.startswith("v"):
        version = version[1:]
    if not version:
        fail("--version 去掉 v 前缀后不能为空")
    revision = _clean_text(args.revision, "--revision")
    arch = _clean_text(args.arch, "--arch") if args.arch is not None else None

    namespace = _document_namespace(args, version, revision, arch)
    created = _created_timestamp()
    metadata = _run_cargo_metadata(args.manifest_path)

    packages = metadata.get("packages")
    if not isinstance(packages, list) or not packages:
        fail("cargo metadata 未返回任何 package")

    workspace_members_raw = metadata.get("workspace_members")
    if not isinstance(workspace_members_raw, list) or not workspace_members_raw:
        fail("cargo metadata 未返回 workspace_members")
    workspace_members = set()
    for member in workspace_members_raw:
        if not isinstance(member, str) or not member:
            fail("cargo metadata 的 workspace_members 包含非法值")
        workspace_members.add(member)

    resolve = metadata.get("resolve")
    if not isinstance(resolve, dict):
        fail("cargo metadata 未返回 resolve 依赖图（需要完整的 --format-version 1 输出）")
    nodes = resolve.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        fail("cargo metadata 的 resolve.nodes 为空，无法生成 DEPENDS_ON 关系")

    by_id: dict[str, dict] = {}
    for package in packages:
        if not isinstance(package, dict):
            fail("cargo metadata 的 packages 数组包含非 object 元素")
        package_id = package.get("id")
        if not isinstance(package_id, str) or not package_id:
            fail("cargo metadata 的 package 缺少 id")
        if package_id in by_id:
            fail(f"cargo metadata 包含重复的 package id: {package_id}")
        by_id[package_id] = package

    missing_members = sorted(workspace_members - set(by_id))
    if missing_members:
        fail(f"workspace 成员不在 packages 中: {', '.join(missing_members)}")

    ordered_packages = sorted(packages, key=_package_sort_key)
    used_spdx_ids: set[str] = set()
    id_map: dict[str, str] = {}
    missing_license_count = 0

    spdx_packages: list[dict] = []
    for package in ordered_packages:
        package_id = package["id"]
        name = package.get("name")
        package_version = package.get("version")
        if not isinstance(name, str) or not name.strip():
            fail(f"package {package_id} 缺少 name")
        if not isinstance(package_version, str) or not package_version.strip():
            fail(f"package {package_id} 缺少 version")
        name = name.strip()
        package_version = package_version.strip()

        base_id = _spdx_base_id(name, package_version)
        spdx_id = base_id
        suffix = 2
        while spdx_id in used_spdx_ids:
            spdx_id = f"{base_id}-{suffix}"
            suffix += 1
        used_spdx_ids.add(spdx_id)
        id_map[package_id] = spdx_id

        license_declared = _license_declared(package)
        if license_declared == "NOASSERTION":
            missing_license_count += 1

        source_kind = _source_kind(package, workspace_members)
        spdx_packages.append(
            {
                "SPDXID": spdx_id,
                "name": name,
                "versionInfo": package_version,
                "downloadLocation": _download_location(package, name, package_version),
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": license_declared,
                "copyrightText": "NOASSERTION",
                "sourceInfo": f"Cargo package source: {source_kind}",
                "externalRefs": _external_refs(name, package_version),
            }
        )

    relationships: list[dict] = []
    for member in sorted(workspace_members):
        relationships.append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": id_map[member],
            }
        )

    seen_relationships: set[tuple[str, str, str]] = set()
    for node in nodes:
        if not isinstance(node, dict):
            fail("cargo metadata 的 resolve.nodes 数组包含非 object 元素")
        source_package_id = node.get("id")
        if not isinstance(source_package_id, str) or source_package_id not in id_map:
            fail(f"resolve 节点对应的 package 不存在: {source_package_id}")
        source_spdx_id = id_map[source_package_id]
        deps = node.get("deps")
        if deps is None:
            deps = []
        if not isinstance(deps, list):
            fail(f"resolve 节点 {source_package_id} 的 deps 不是数组")
        for dep in deps:
            if not isinstance(dep, dict):
                fail(f"resolve 节点 {source_package_id} 的 deps 包含非 object 元素")
            target_package_id = dep.get("pkg")
            if not isinstance(target_package_id, str) or target_package_id not in id_map:
                fail(f"resolve 依赖指向不存在的 package: {target_package_id}")
            key = (source_spdx_id, "DEPENDS_ON", id_map[target_package_id])
            if key in seen_relationships:
                continue
            seen_relationships.add(key)
            relationships.append(
                {
                    "spdxElementId": key[0],
                    "relationshipType": key[1],
                    "relatedSpdxElement": key[2],
                }
            )
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )

    if missing_license_count:
        print(
            f"警告: {missing_license_count} 个 package 没有 license 字段，"
            "licenseDeclared 使用 NOASSERTION",
            file=sys.stderr,
        )

    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"RustBoard {version} ({arch or 'source'})",
        "documentNamespace": namespace,
        "comment": (
            "Generated from cargo metadata. The dependency graph includes all "
            "dependency kinds resolved by Cargo (normal, build and dev)."
        ),
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: {TOOL_NAME}"],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }


def write_document(document: dict, output: str) -> None:
    payload = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ) + "\n"
    path = Path(output)
    try:
        parent = path.parent
        if str(parent):
            parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
    except OSError as exc:
        fail(f"无法写入 {output}: {exc}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        document = build_document(args)
        write_document(document, args.output)
    except SbomError as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 1

    print(
        f"已生成 SPDX {SPDX_VERSION} SBOM: {args.output} "
        f"（{len(document['packages'])} 个 package，"
        f"{len(document['relationships'])} 条 relationship）",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
