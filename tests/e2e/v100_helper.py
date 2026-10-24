#!/usr/bin/env python3
"""RustBoard M5 Phase A 安装器 e2e 辅助（仅 Python 标准库）。

对应 `tests/e2e/v100-install.sh`。这里只做「用 bash 写容易出错」的几类解析：

- `ports N`：挑选 N 个当前可 bind 的随机回环端口；
- `hold-port FILE`：占住一个回环端口，直到被 SIGTERM/SIGINT，供失败回滚注入；
- `toml-get` / `toml-section-exists`：按段读安装器生成的 TOML（只处理单行标量）；
- `agent-add-parse`：从 `hub agent add` 输出解析 token 与证书指纹，并把 token
  以 0600 写入文件；**不把 token 打到 stdout**；
- `agents-count` / `agent-id` / `series-points`：核对管理 API JSON；
- `unit-execstart` / `unit-hardening-check`：核对 systemd unit。

安全约定：本 helper 不联网、不打印 token / secret / 私钥；所有错误信息只描述
位置或长度，不回显敏感内容。

Python 3.8+；用法见各 command 的 `die()` 文案。
"""

from __future__ import annotations

import json
import os
import random
import re
import shlex
import signal
import socket
import sys
import time

HEX64_RE = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64})(?![0-9A-Fa-f])")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
# unit 段头允许行尾 # / ; 注释（与键值的行尾注释规则保持一致）。
UNIT_SECTION_RE = re.compile(r"^\s*\[([^\]]+)\]\s*(?:[#;].*)?$")
KEY_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)$")


def die(message: str, code: int = 1) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(code)


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError as exc:
        die(f"读取文件失败 {path}: {exc}")


def load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        die(f"读取/解析 JSON 失败 {path}: {exc}", 2)


# ---------------------------------------------------------------------------
# 端口
# ---------------------------------------------------------------------------


def command_ports(args) -> None:
    if len(args) != 1:
        die("用法: ports N")
    try:
        count = int(args[0])
    except ValueError:
        die("ports 的 N 必须是整数")
    if count < 1 or count > 64:
        die("ports 的 N 必须在 1–64 之间")
    chosen = []
    while len(chosen) < count:
        port = random.randint(20000, 64999)
        if port in chosen:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            sock.close()
        chosen.append(port)
    print(" ".join(str(port) for port in chosen))


def command_hold_port(args) -> None:
    if len(args) != 1:
        die("用法: hold-port PORT_FILE")
    port_file = args[0]
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stop = [False]

    def _stop(_signum, _frame):
        stop[0] = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        port = sock.getsockname()[1]
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(port_file, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, f"{port}\n".encode("ascii"))
        finally:
            os.close(fd)
        while not stop[0]:
            time.sleep(0.1)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# TOML：只读单行标量，足够核对安装器生成的 hub/panel/agent/install-state
# ---------------------------------------------------------------------------


def _parse_toml_value(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith('"'):
        out = []
        i = 1
        while i < len(raw):
            char = raw[i]
            if char == "\\" and i + 1 < len(raw):
                nxt = raw[i + 1]
                escapes = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}
                if nxt in escapes:
                    out.append(escapes[nxt])
                    i += 2
                    continue
                if nxt == "u" and i + 5 < len(raw):
                    try:
                        out.append(chr(int(raw[i + 2 : i + 6], 16)))
                        i += 6
                        continue
                    except ValueError:
                        pass
                out.append(nxt)
                i += 2
                continue
            if char == '"':
                return "".join(out)
            out.append(char)
            i += 1
        return "".join(out)
    if raw.startswith("'"):
        end = raw.find("'", 1)
        return raw[1:end] if end != -1 else raw[1:]
    # 未加引号的标量：去掉行尾注释
    return raw.split("#", 1)[0].strip()


def _iter_entries(lines):
    section = ""
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = SECTION_RE.match(line)
        if match:
            section = match.group(1).strip()
            continue
        match = KEY_RE.match(line)
        if not match:
            continue
        yield section, match.group(1), _parse_toml_value(match.group(2))


def _read_lines(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read().splitlines()
    except FileNotFoundError:
        return None
    except OSError as exc:
        die(f"读取 TOML 失败 {path}: {exc}", 2)


def command_toml_get(args) -> None:
    if len(args) != 3:
        die("用法: toml-get FILE SECTION KEY（SECTION=- 表示顶层）")
    path, section, key = args
    if section == "-":
        section = ""
    lines = _read_lines(path)
    if lines is None:
        print("__MISSING__")
        return
    values = [value for sec, name, value in _iter_entries(lines) if sec == section and name == key]
    if not values:
        print("__MISSING__")
        return
    if len(set(values)) > 1:
        print("__MULTI__")
        raise SystemExit(3)
    print(values[0])


def command_toml_section_exists(args) -> None:
    if len(args) != 2:
        die("用法: toml-section-exists FILE SECTION")
    path, section = args
    lines = _read_lines(path)
    if lines is None:
        print("no")
        return
    for line in lines:
        match = SECTION_RE.match(line)
        if match and match.group(1).strip() == section:
            print("yes")
            return
    print("no")


# ---------------------------------------------------------------------------
# hub agent add 输出解析
# ---------------------------------------------------------------------------


def _extract_fingerprint(text: str, lines):
    found = [
        match.group(1).lower()
        for match in re.finditer(
            r"--fingerprint(?:=|\s+)(?:SHA256:)?\s*([0-9A-Fa-f]{64})", text, re.I
        )
    ]
    if not found:
        for line in lines:
            if "fingerprint" in line.lower():
                found.extend(value.lower() for value in HEX64_RE.findall(line))
    unique = []
    for value in found:
        if value not in unique:
            unique.append(value)
    return unique


def _extract_tokens(text: str, lines, fingerprint: str):
    found = [
        match.group(1).lower()
        for match in re.finditer(r"--token(?:=|\s+)\s*([0-9A-Fa-f]{64})", text, re.I)
    ]
    if not found:
        found = [
            match.group(1).lower()
            for match in re.finditer(
                r"(?<![-A-Za-z0-9_])token\s*[=:]\s*([0-9A-Fa-f]{64})", text, re.I
            )
        ]
    if not found:
        # 现有输出把 token 单独印在一行（前面是中文提示）。
        for line in lines:
            match = re.fullmatch(r"\s*([0-9A-Fa-f]{64})\s*", line)
            if match and match.group(1).lower() != fingerprint:
                found.append(match.group(1).lower())
    if not found:
        candidates = []
        for value in HEX64_RE.findall(text):
            value = value.lower()
            if value != fingerprint and value not in candidates:
                candidates.append(value)
        if len(candidates) == 1:
            found = candidates
    unique = []
    for value in found:
        if value != fingerprint and value not in unique:
            unique.append(value)
    return unique


def command_agent_add_parse(args) -> None:
    if len(args) != 2:
        die("用法: agent-add-parse OUTPUT_FILE TOKEN_OUT")
    output_path, token_path = args
    raw = read_text(output_path)
    text = ANSI_RE.sub("", raw).replace("\r", "")
    lines = text.splitlines()

    fingerprints = _extract_fingerprint(text, lines)
    if not fingerprints:
        die("未从 agent add 输出解析到 --fingerprint（不会回显输出内容）")
    if len(fingerprints) > 1:
        die(f"agent add 输出中的指纹不唯一（{len(fingerprints)} 个）")
    fingerprint = fingerprints[0]

    tokens = _extract_tokens(text, lines, fingerprint)
    if not tokens:
        die("未从 agent add 输出解析到 enrollment token（不会回显输出内容）")
    if len(tokens) > 1:
        die(f"agent add 输出中的 token 候选不唯一（{len(tokens)} 个）")
    token = tokens[0]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", token):
        die("解析到的 token 不是 64 位十六进制")

    directory = os.path.dirname(os.path.abspath(token_path))
    if not os.path.isdir(directory):
        die(f"token 输出目录不存在: {directory}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(token_path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, (token + "\n").encode("ascii"))
        finally:
            os.close(fd)
    except OSError as exc:
        die(f"写入 token 文件失败: {exc}")

    # 只输出公开的指纹和长度；token 内容绝不写 stdout/stderr。
    print(f"fpr={fingerprint}")
    print(f"token_len={len(token)}")


def command_check_64hex_file(args) -> None:
    if len(args) != 1:
        die("用法: check-64hex-file FILE")
    path = args[0]
    if os.path.islink(path):
        die("token 文件是符号链接")
    try:
        with open(path, "rb") as handle:
            data = handle.read(4096)
    except OSError as exc:
        die(f"读取 token 文件失败: {exc}")
    try:
        text = data.decode("ascii").strip()
    except UnicodeDecodeError:
        die("token 文件不是 ASCII")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", text):
        die(f"token 文件内容不是 64 位十六进制（长度 {len(text)}）")


# ---------------------------------------------------------------------------
# 管理 API JSON
# ---------------------------------------------------------------------------


def command_agents_count(args) -> None:
    if len(args) != 1:
        die("用法: agents-count JSON_FILE")
    data = load_json(args[0])
    if not isinstance(data, list):
        die("响应不是 JSON 数组", 2)
    print(len(data))


def command_agent_id(args) -> None:
    if len(args) != 2:
        die("用法: agent-id JSON_FILE NAME")
    path, name = args
    data = load_json(path)
    if not isinstance(data, list):
        die("响应不是 JSON 数组", 2)
    for item in data:
        if not isinstance(item, dict):
            continue
        if item.get("name") == name:
            agent_id = item.get("agent_id")
            if isinstance(agent_id, str) and agent_id:
                print(agent_id)
                return
    print("__MISSING__")


def command_series_points(args) -> None:
    if len(args) != 2:
        die("用法: series-points JSON_FILE METRIC（METRIC=- 表示全部）")
    path, metric = args
    data = load_json(path)
    if not isinstance(data, dict):
        die("series 响应不是 JSON 对象", 2)
    series = data.get("series")
    if not isinstance(series, list):
        die("series 响应缺少 series 数组", 2)
    total = 0
    for entry in series:
        if not isinstance(entry, dict):
            continue
        if metric != "-" and entry.get("metric") != metric:
            continue
        points = entry.get("points")
        if not isinstance(points, list):
            die("series 条目缺少 points 数组", 2)
        total += len(points)
    print(total)


# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------


def _unit_values(path: str):
    """按段读取 unit 键值，键统一为 `Section.Key`。

    `systemd-analyze verify` 对「关键字写错段」并不总是报错（例如把
    `Restart=` 写进 `[Unit]` 仍可能 rc=0），因此必须保留段名供调用方带段
    查找。段名按文件原样保留（systemd 段名区分大小写）。
    """
    values = {}
    section = ""
    for line in read_text(path).splitlines():
        match = UNIT_SECTION_RE.match(line)
        if match:
            section = match.group(1).strip()
            continue
        match = KEY_RE.match(line)
        if not match:
            continue
        value = match.group(2).strip()
        # 去掉 systemd 允许的行尾注释（# 或 ;，前面至少一个空白）。
        value = re.split(r"\s+[#;]", value, maxsplit=1)[0].strip()
        key = f"{section}.{match.group(1)}" if section else match.group(1)
        values.setdefault(key, []).append(value)
    return values


def command_unit_execstart(args) -> None:
    if len(args) != 1:
        die("用法: unit-execstart UNIT_FILE")
    values = _unit_values(args[0])
    # 只认 [Service] 段里的 ExecStart；写在 [Unit]/[Install] 等错误段一律视为缺失。
    execs = [value for value in values.get("Service.ExecStart", []) if value]
    if not execs:
        print("__MISSING__")
        return
    if len(execs) > 1:
        print("__MULTI__")
        raise SystemExit(3)
    value = execs[0]
    if value.startswith("-"):
        value = value[1:]
    try:
        argv = shlex.split(value)
    except ValueError as exc:
        die(f"ExecStart 无法解析: {exc}")
    if not argv:
        print("__MISSING__")
        return
    print("\t".join(argv))


def command_unit_hardening_check(args) -> None:
    if len(args) != 2:
        die("用法: unit-hardening-check UNIT_FILE DATA_DIR")
    path, data_dir = args
    values = _unit_values(path)
    required = [
        ("Unit.After", "network-online.target"),
        ("Unit.Wants", "network-online.target"),
        ("Service.Type", "simple"),
        ("Service.Restart", "on-failure"),
        ("Service.RestartSec", "3"),
        ("Service.NoNewPrivileges", "true"),
        ("Service.PrivateTmp", "true"),
        ("Service.ProtectSystem", "strict"),
        ("Service.ProtectHome", "true"),
        ("Service.ProtectKernelTunables", "true"),
        ("Service.ProtectControlGroups", "true"),
        ("Service.LockPersonality", "true"),
        ("Install.WantedBy", "multi-user.target"),
    ]
    missing = []
    for key, expected in required:
        if expected not in values.get(key, []):
            missing.append(f"{key}={expected}")
    writable = []
    for raw in values.get("Service.ReadWritePaths", []):
        try:
            items = shlex.split(raw)
        except ValueError:
            items = raw.split()
        for item in items:
            if item.startswith("-"):
                item = item[1:]
            if item and item not in writable:
                writable.append(item)
    if writable != [data_dir]:
        missing.append(
            "Service.ReadWritePaths 只允许 " + data_dir + "（实际: " + " ".join(writable) + "）"
        )
    if missing:
        print("\n".join(missing))
        raise SystemExit(1)
    print("OK")


# ---------------------------------------------------------------------------
# 子命令分发
# ---------------------------------------------------------------------------

COMMANDS = {
    "ports": command_ports,
    "hold-port": command_hold_port,
    "toml-get": command_toml_get,
    "toml-section-exists": command_toml_section_exists,
    "agent-add-parse": command_agent_add_parse,
    "check-64hex-file": command_check_64hex_file,
    "agents-count": command_agents_count,
    "agent-id": command_agent_id,
    "series-points": command_series_points,
    "unit-execstart": command_unit_execstart,
    "unit-hardening-check": command_unit_hardening_check,
}


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        die("用法: v100_helper.py <%s> ..." % "|".join(sorted(COMMANDS)))
    command = COMMANDS.get(sys.argv[1])
    if command is None:
        die(f"未知子命令: {sys.argv[1]}")
    command(sys.argv[2:])


if __name__ == "__main__":
    main()
