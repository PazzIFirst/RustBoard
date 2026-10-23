#!/usr/bin/env python3
"""v0.4.0 e2e 的 JSON / TOML 断言辅助（仅 Python 标准库）。

`v040.sh` 用 curl 访问管理 API，本文件只负责脚本里容易写错的三类工作：

- `ports N`：挑选 N 个当前可 bind 的回环端口；
- `set-toml` / `get-toml`：按段读写临时 `hub.toml`（不引入第三方 TOML 库，
  只处理 `hub init` 生成的 `key = literal` 形式）；
- JSON 断言：`get` / `find` / `builtin-summary` / `event-max` / `event-find` /
  `event-page-ok`，把易碎的字段判断集中起来；
- `redact`：失败日志与响应预览脱敏，避免打印 token / secret。

本文件不发起网络请求，不访问真实 token，也不打印任何凭据明文。
"""

from __future__ import annotations

import json
import os
import random
import re
import socket
import sys

HEADER_RE = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
KEY_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=")


def die(message: str) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def load_json(path: str):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"__ERR__ 读取 JSON 失败: {exc}", file=sys.stderr)
        return None


def render(value) -> str:
    """字符串按原文输出，其它值按紧凑 JSON 输出。"""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def json_bool(value) -> str:
    return "true" if value is True else "false"


# ---------------------------------------------------------------------------
# 端口
# ---------------------------------------------------------------------------


def command_ports(args) -> None:
    if len(args) != 1:
        die("用法: ports N")
    count = int(args[0])
    chosen = []
    while len(chosen) < count:
        port = random.randint(20000, 64999)
        if port in chosen:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        chosen.append(port)
    print(" ".join(str(port) for port in chosen))


# ---------------------------------------------------------------------------
# TOML：只读写 hub init 生成的单行标量
# ---------------------------------------------------------------------------


def section_range(lines, section: str):
    """返回 (start, end) 行号区间（end 排他）；段不存在返回 None。

    `section` 为 `-` 表示顶层（第一个 `[section]` 之前）。
    """
    if section == "-":
        for index, line in enumerate(lines):
            if HEADER_RE.match(line):
                return 0, index
        return 0, len(lines)

    header = None
    for index, line in enumerate(lines):
        match = HEADER_RE.match(line)
        if match and match.group(1) == section:
            header = index
            break
    if header is None:
        return None

    end = len(lines)
    for index in range(header + 1, len(lines)):
        if HEADER_RE.match(lines[index]):
            end = index
            break
    return header + 1, end


def toml_literal(raw: str) -> str:
    raw = raw.strip()
    match = re.match(r'^"([^"]*)"', raw)
    if match:
        return match.group(1)
    match = re.match(r"^'([^']*)'", raw)
    if match:
        return match.group(1)
    return raw.split("#", 1)[0].strip()


def command_set_toml(args) -> None:
    if len(args) != 4:
        die("用法: set-toml FILE SECTION KEY RHS（SECTION=- 表示顶层）")
    path, section, key, rhs = args
    if section != "-" and not re.fullmatch(r"[A-Za-z0-9_.-]+", section):
        die(f"非法段名: {section}")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
        die(f"非法键名: {key}")

    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        die(f"读取配置失败: {exc}")

    span = section_range(lines, section)
    if span is None:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"[{section}]")
        lines.append(f"{key} = {rhs}")
    else:
        start, end = span
        indexes = [i for i in range(start, end) if KEY_RE.match(lines[i])
                   and KEY_RE.match(lines[i]).group(1) == key]
        if len(indexes) > 1:
            die(f"配置 {path} 的 [{section}] 中 {key} 出现 {len(indexes)} 次")
        if indexes:
            indent = re.match(r"^(\s*)", lines[indexes[0]]).group(1)
            lines[indexes[0]] = f"{indent}{key} = {rhs}"
        else:
            insert_at = end
            while insert_at > start and not lines[insert_at - 1].strip():
                insert_at -= 1
            lines.insert(insert_at, f"{key} = {rhs}")
            if insert_at == len(lines) - 1 and end < len(lines):
                lines.insert(insert_at + 1, "")

    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)


def command_get_toml(args) -> None:
    if len(args) != 3:
        die("用法: get-toml FILE SECTION KEY（SECTION=- 表示顶层）")
    path, section, key = args
    try:
        with open(path, encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        die(f"读取配置失败: {exc}")
    span = section_range(lines, section)
    if span is None:
        print("__MISSING__")
        return
    start, end = span
    values = []
    for index in range(start, end):
        match = KEY_RE.match(lines[index])
        if match and match.group(1) == key:
            values.append(toml_literal(lines[index].split("=", 1)[1]))
    if len(values) != 1:
        print("__MISSING__")
        return
    print(values[0])


# ---------------------------------------------------------------------------
# JSON 视图
# ---------------------------------------------------------------------------


def command_get(args) -> None:
    if len(args) != 2:
        die("用法: get FILE EXPR")
    data = load_json(args[0])
    if data is None:
        print("__ERR__")
        return
    try:
        value = eval(  # noqa: S307 - 表达式来自本仓库测试脚本，受限内建
            args[1],
            {"__builtins__": {}},
            {
                "d": data,
                "len": len,
                "sorted": sorted,
                "any": any,
                "all": all,
                "int": int,
                "str": str,
                "bool": bool,
                "list": list,
                "dict": dict,
                "isinstance": isinstance,
            },
        )
        print(render(value))
    except Exception:
        print("__ERR__")


def iter_items(data):
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("rules", "channels", "silences", "events", "objects", "items"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return None


def command_find(args) -> None:
    if len(args) != 3:
        die("用法: find FILE ID FIELD")
    data = load_json(args[0])
    if data is None:
        print("__ERR__")
        return
    items = iter_items(data)
    if items is None:
        print("__ERR__")
        return
    target, field = args[1], args[2]
    for item in items:
        if not isinstance(item, dict):
            continue
        # 规则 / 渠道 / 静默 / 归档对象用 `id`，agents 列表用 `agent_id`。
        item_id = item.get("id", item.get("agent_id"))
        if str(item_id) == str(target):
            print(render(item.get(field, "__MISSING__")))
            return
    print("__MISSING__")


def command_builtin_summary(args) -> None:
    if len(args) != 1:
        die("用法: builtin-summary FILE")
    data = load_json(args[0])
    if not isinstance(data, list):
        print("__ERR__")
        return
    builtin = [rule for rule in data if isinstance(rule, dict) and rule.get("is_builtin")]
    enabled = [rule for rule in builtin if rule.get("enabled")]
    print(f"total={len(data)} builtin={len(builtin)} enabled_builtin={len(enabled)}")


def event_list(path: str):
    data = load_json(path)
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        return None
    return data["events"]


def command_event_max(args) -> None:
    if len(args) != 2:
        die("用法: event-max FILE RULE_ID")
    events = event_list(args[0])
    if events is None:
        print("__ERR__")
        return
    ids = [event.get("id", 0) for event in events
           if isinstance(event, dict) and str(event.get("rule_id")) == args[1]]
    print(max(ids) if ids else 0)


def command_event_find(args) -> None:
    if len(args) != 5:
        die("用法: event-find FILE RULE_ID AFTER_ID STATE SILENCED")
    events = event_list(args[0])
    if events is None:
        print("__ERR__")
        raise SystemExit(2)
    rule_id, after_raw, state, silenced_raw = args[1:]
    after = int(after_raw)
    if state not in ("firing", "resolved"):
        die(f"非法事件状态: {state}")
    silenced = silenced_raw.lower() in ("1", "true", "yes")

    for event in events:
        if not isinstance(event, dict):
            continue
        if str(event.get("rule_id")) != rule_id:
            continue
        if event.get("state") != state:
            continue
        if bool(event.get("silenced")) != silenced:
            continue
        if int(event.get("id", 0)) <= after:
            continue
        fields = [
            str(event.get("id", "")),
            str(event.get("state", "")),
            str(event.get("series_key", "")),
            json_bool(event.get("notified")),
            json_bool(event.get("silenced")),
            str(event.get("agent_id", "")),
        ]
        print("\t".join(fields))
        return
    raise SystemExit(1)


def command_event_page_ok(args) -> None:
    if len(args) != 2:
        die("用法: event-page-ok FILE CURSOR")
    events = event_list(args[0])
    if events is None:
        die("events 响应结构非法")
    cursor = int(args[1])
    ids = [int(event.get("id", 0)) for event in events if isinstance(event, dict)]
    if any(event_id >= cursor for event_id in ids):
        die(f"分页返回了 >= before_id 的事件: {ids}")
    if ids != sorted(ids, reverse=True):
        die(f"事件未按 id 倒序: {ids}")
    if len(set(ids)) != len(ids):
        die(f"分页出现重复事件: {ids}")
    print(f"ok={len(ids)}")


# ---------------------------------------------------------------------------
# 脱敏
# ---------------------------------------------------------------------------


def command_redact(_args) -> None:
    secrets = [item for item in os.environ.get("RB_V040_SECRETS", "").split("|") if item]
    text = sys.stdin.buffer.read().decode("utf-8", "replace")
    for secret in secrets:
        text = text.replace(secret, "<redacted>")
    text = re.sub(r"(Bearer )[^\s]+", r"\1<redacted>", text)
    text = re.sub(r"(管理 API token:).*", r"\1 <redacted>", text)
    text = re.sub(r"(一次性 token[^:：]*[:：]).*", r"\1 <redacted>", text)
    sys.stdout.write(text)


COMMANDS = {
    "ports": command_ports,
    "set-toml": command_set_toml,
    "get-toml": command_get_toml,
    "get": command_get,
    "find": command_find,
    "builtin-summary": command_builtin_summary,
    "event-max": command_event_max,
    "event-find": command_event_find,
    "event-page-ok": command_event_page_ok,
    "redact": command_redact,
}


def main(argv) -> int:
    if len(argv) < 2 or argv[1] not in COMMANDS:
        print("用法: v040_helper.py <command> ...", file=sys.stderr)
        print("commands: " + " ".join(sorted(COMMANDS)), file=sys.stderr)
        return 2
    try:
        COMMANDS[argv[1]](argv[2:])
    except SystemExit:
        raise
    except Exception as exc:  # 防止 traceback 输出请求体 / 配置内容
        print(f"helper 执行失败: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
