#!/usr/bin/env python3
"""RustBoard v0.4.1 e2e 辅助（仅 Python 标准库）。

对应 `tests/e2e/v041.sh`，集中处理四类容易写错的断言：

- `ports N`：挑选 N 个当前可 bind 的回环端口；
- `set-toml` / `get-toml`：按段读写临时 `hub.toml`（只处理 `key = literal`）；
- KI-29：通过 SQLite 公开表结构造「最大 rowid 迟到行 → retention 删除 →
  新迟到行复用 rowid」场景，并输出 maintenance_state / 1m / 1h 的核对值；
- KI-31 / KI-20 / KI-28：归档对象列表字段、agent add 输出的受控 shell 执行、
  连接拒绝日志计数。

安全约定：
- 不联网、不打印 enrollment token / admin token；`agent-add-safe` 只输出判定位；
- 注入 payload 只有 `printf INJECTED` 这类无副作用命令，并在一次性临时目录 +
  stub `rustboard-agent` 的受控子 shell 中执行，不触碰真实 agent；
- 所有临时目录用 `tempfile.mkdtemp` 创建，退出前清理。
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

HEADER_RE = re.compile(r"^\s*\[([^\]]+)\]\s*(?:#.*)?$")
KEY_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*=")
MARKER = "在目标服务器上执行:"
RUSTBOARD_AGENT = "rustboard-agent"

# KI-29 造数用的 agent / metric；与其它测试隔离。
KI29_AGENT = "agent-v041-ki29"
KI29_METRIC = "cpu.usage"
MINUTE_MS = 60_000
HOUR_MS = 3_600_000
DAY_MS = 86_400_000

# KI-31 归档对象大小：64 MiB + 1（不可下载）与 1 KiB（可下载）。
ARCHIVE_HUGE_BYTES = 64 * 1024 * 1024 + 1
ARCHIVE_SMALL_BYTES = 1024


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
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


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
        indexes = [
            i
            for i in range(start, end)
            if KEY_RE.match(lines[i]) and KEY_RE.match(lines[i]).group(1) == key
        ]
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
# KI-29：SQLite 造数 / 核对
# ---------------------------------------------------------------------------


def open_db(path: str) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(path, timeout=15)
    except sqlite3.Error as exc:
        die(f"打开 SQLite 失败: {exc}")
    conn.execute("PRAGMA busy_timeout = 15000")
    return conn


def ki29_cleanup(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM samples WHERE agent_id = ?", (KI29_AGENT,))
    conn.execute("DELETE FROM samples_1m WHERE agent_id = ?", (KI29_AGENT,))
    conn.execute("DELETE FROM samples_1h WHERE agent_id = ?", (KI29_AGENT,))
    conn.execute(
        "DELETE FROM maintenance_state WHERE key = 'downsample_1m_last_raw_rowid'"
    )


def command_ki29_seed(args) -> None:
    if len(args) != 2:
        die("用法: ki29-seed DB NOW_MS")
    db, now_raw = args
    now = int(now_raw)
    old_ts = now - DAY_MS - 2 * MINUTE_MS
    conn = open_db(db)
    try:
        ki29_cleanup(conn)
        conn.execute(
            "INSERT INTO samples (agent_id, metric, labels, ts, value) "
            "VALUES (?, ?, '{}', ?, ?)",
            (KI29_AGENT, KI29_METRIC, now - 90_000, 1.0),
        )
        # 旧迟到行最后插入 → 它是“最大 rowid”。
        conn.execute(
            "INSERT INTO samples (agent_id, metric, labels, ts, value) "
            "VALUES (?, ?, '{}', ?, ?)",
            (KI29_AGENT, KI29_METRIC, old_ts, 100.0),
        )
        conn.commit()
        max_rowid = conn.execute("SELECT MAX(rowid) FROM samples").fetchone()[0]
    finally:
        conn.close()
    old_bucket = (old_ts // MINUTE_MS) * MINUTE_MS
    old_hour = (old_ts // HOUR_MS) * HOUR_MS
    print(old_ts, old_bucket, old_hour, max_rowid)


def command_ki29_state(args) -> None:
    if len(args) != 1:
        die("用法: ki29-state DB")
    conn = open_db(args[0])
    try:
        row = conn.execute(
            "SELECT value FROM maintenance_state "
            "WHERE key = 'downsample_1m_last_raw_rowid'"
        ).fetchone()
        max_rowid = conn.execute("SELECT MAX(rowid) FROM samples").fetchone()[0]
        rows = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    finally:
        conn.close()
    watermark = "none" if row is None or row[0] is None or row[0] == "" else str(row[0])
    max_text = "none" if max_rowid is None else str(max_rowid)
    print(watermark, max_text, rows)


def command_ki29_late(args) -> None:
    if len(args) != 2:
        die("用法: ki29-late DB OLD_TS")
    db, old_ts_raw = args
    # 必须先对旧行 ts 取分钟 floor 再加 40s：now 不保证整分钟对齐，
    # 直接 old_ts + 40s 可能跨到下一分钟桶，导致旧桶不再被重算。
    bucket = (int(old_ts_raw) // MINUTE_MS) * MINUTE_MS
    conn = open_db(db)
    try:
        cur = conn.execute(
            "INSERT INTO samples (agent_id, metric, labels, ts, value) "
            "VALUES (?, ?, '{}', ?, ?)",
            (KI29_AGENT, KI29_METRIC, bucket + 40_000, 5.0),
        )
        rowid = cur.lastrowid
        conn.commit()
        max_rowid = conn.execute("SELECT MAX(rowid) FROM samples").fetchone()[0]
    finally:
        conn.close()
    print(rowid, max_rowid)


def command_ki29_check(args) -> None:
    if len(args) != 3:
        die("用法: ki29-check DB OLD_BUCKET OLD_HOUR")
    db, old_bucket, old_hour = args
    conn = open_db(db)
    try:
        minute = conn.execute(
            "SELECT count, avg_value FROM samples_1m "
            "WHERE agent_id = ? AND metric = ? AND bucket_ts = ?",
            (KI29_AGENT, KI29_METRIC, int(old_bucket)),
        ).fetchone()
        hour = conn.execute(
            "SELECT count, avg_value FROM samples_1h "
            "WHERE agent_id = ? AND metric = ? AND bucket_ts = ?",
            (KI29_AGENT, KI29_METRIC, int(old_hour)),
        ).fetchone()
    finally:
        conn.close()

    def pair(row):
        if row is None:
            return "none", "none"
        return str(row[0]), f"{row[1]:.6f}"

    m_count, m_avg = pair(minute)
    h_count, h_avg = pair(hour)
    print(m_count, m_avg, h_count, h_avg)


# ---------------------------------------------------------------------------
# KI-31：归档对象造数 / 列表字段
# ---------------------------------------------------------------------------


def _archive_key(shard: int, now_ms: int) -> str:
    stamp = time.gmtime(now_ms / 1000)
    return (
        f"rustboard/{stamp.tm_year:04d}/{stamp.tm_mon:02d}/{stamp.tm_mday:02d}/"
        f"part-{shard:05d}.csv.gz"
    )


def command_archive_seed(args) -> None:
    if len(args) != 2:
        die("用法: archive-seed DB NOW_MS")
    db, now_raw = args
    now = int(now_raw)
    conn = open_db(db)
    ids = []
    try:
        for shard, size in ((1, ARCHIVE_HUGE_BYTES), (2, ARCHIVE_SMALL_BYTES)):
            key = _archive_key(shard, now)
            manifest = key[: -len(".csv.gz")] + ".manifest.json"
            cur = conn.execute(
                "INSERT INTO archive_objects "
                "(backend, object_key, manifest_key, from_ts, to_ts, rows, bytes, "
                " sha256, status, error, created_at, uploaded_at, deleted_at) "
                "VALUES ('webdav', ?, ?, ?, ?, 1, ?, ?, 'uploaded', '', ?, ?, NULL)",
                (
                    key,
                    manifest,
                    now - DAY_MS,
                    now,
                    size,
                    "0" * 64,
                    now,
                    now,
                ),
            )
            ids.append(cur.lastrowid)
        conn.commit()
    finally:
        conn.close()
    print(ids[0], ids[1])


def command_archive_view(args) -> None:
    if len(args) != 3:
        die("用法: archive-view FILE HUGE_ID SMALL_ID")
    data = load_json(args[0])
    if not isinstance(data, dict) or not isinstance(data.get("objects"), list):
        print("__ERR__")
        return
    wanted = {str(args[1]): "huge", str(args[2]): "small"}
    found = {}
    for item in data["objects"]:
        if not isinstance(item, dict):
            continue
        name = wanted.get(str(item.get("id")))
        if name is None:
            continue
        found[name] = item.get("downloadable", "__MISSING__")
    print(
        f"huge={render(found.get('huge', '__MISSING__'))} "
        f"small={render(found.get('small', '__MISSING__'))}"
    )


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
            {"d": data, "len": len, "str": str, "bool": bool},
        )
        print(render(value))
    except Exception:
        print("__ERR__")


# ---------------------------------------------------------------------------
# KI-20：agent add 输出的受控 shell 执行
# ---------------------------------------------------------------------------


def command_agent_add_safe(args) -> None:
    if len(args) != 3:
        die("用法: agent-add-safe HUB_BIN HUB_CFG NAME")
    hub_bin, hub_cfg, name = args

    proc = subprocess.run(
        [hub_bin, "agent", "add", "--config", hub_cfg, "--name", name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        # 拒绝也是安全结果；由 shell 按字符类别决定是否接受。
        print(f"mode=rejected rc={proc.returncode}")
        return

    index = proc.stdout.find(MARKER)
    if index < 0:
        print("mode=no_command rc=0")
        return
    command = proc.stdout[index + len(MARKER) :].lstrip("\n")
    if not command.strip():
        print("mode=no_command rc=0")
        return

    temp_dir = tempfile.mkdtemp(prefix="rustboard-v041-agent-")
    try:
        stub = os.path.join(temp_dir, RUSTBOARD_AGENT)
        with open(stub, "w", encoding="utf-8") as handle:
            handle.write(
                "#!/bin/sh\n"
                'printf \'%s\\0\' "$@" > "$RB_V041_ARGS_OUT"\n'
                "exit 0\n"
            )
        os.chmod(stub, 0o755)
        args_out = os.path.join(temp_dir, "argv.bin")

        syntax_ok = 0
        syntax = subprocess.run(
            ["bash", "-n", "-c", command],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
        )
        if syntax.returncode == 0:
            syntax_ok = 1

        exec_rc = "skip"
        injected = 0
        name_ok = 0
        meta_ok = 0
        stub_called = 0
        if syntax_ok:
            env = dict(os.environ)
            env["PATH"] = temp_dir + ":" + env.get("PATH", "/usr/bin:/bin")
            env["RB_V041_ARGS_OUT"] = args_out
            result = subprocess.run(
                ["bash", "-c", command],
                cwd=temp_dir,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=20,
            )
            exec_rc = result.returncode
            # 注入 payload 只含 `printf INJECTED`；输出里出现该标记即说明执行了注入。
            injected = int("INJECTED" in (result.stdout + result.stderr))
            if os.path.exists(args_out):
                stub_called = 1
                with open(args_out, "rb") as handle:
                    raw = handle.read()
                argv = [part.decode("utf-8", "surrogateescape") for part in raw.split(b"\0") if part]
                name_positions = [i for i, item in enumerate(argv) if item == "--name"]
                if len(name_positions) == 1 and name_positions[0] + 1 < len(argv):
                    name_ok = int(argv[name_positions[0] + 1] == name)
                meta_ok = int(_agent_meta_ok(argv))

        print(
            f"mode=executed rc={exec_rc} syntax_ok={syntax_ok} "
            f"name_ok={name_ok} meta_ok={meta_ok} injected={injected} "
            f"stub_called={stub_called}"
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def _agent_meta_ok(argv) -> bool:
    def value_after(flag: str):
        positions = [i for i, item in enumerate(argv) if item == flag]
        if len(positions) != 1 or positions[0] + 1 >= len(argv):
            return None
        return argv[positions[0] + 1]

    token = value_after("--token")
    fingerprint = value_after("--fingerprint")
    hub = value_after("--hub")
    if token is None or not re.fullmatch(r"[0-9a-f]{64}", token):
        return False
    if fingerprint is None or not re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        return False
    if hub is None or not (hub.startswith("wss://") and hub.endswith("/agent/ws")):
        return False
    return argv[:1] == ["init"]


# ---------------------------------------------------------------------------
# KI-28：同源 / 异源连接洪水与日志等级计数
# ---------------------------------------------------------------------------


def _connect(host: str, port: int, source: str | None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    try:
        if source is not None:
            sock.bind((source, 0))
        sock.connect((host, port))
    except OSError:
        sock.close()
        raise
    return sock


def command_ki28_flood(args) -> None:
    if len(args) != 2:
        die("用法: ki28-flood HOST PORT")
    host, port_raw = args
    port = int(port_raw)
    try:
        held = [
            _connect(host, port, "127.0.0.1"),
            _connect(host, port, "127.0.0.1"),
            _connect(host, port, "127.0.0.2"),
            _connect(host, port, "127.0.0.2"),
        ]
    except OSError as exc:
        die(f"建立占位连接失败（无法绑定 127.0.0.2 时视为环境限制）: {exc}")
    try:
        # 等待 accept 循环登记 4 条占位连接（每 IP 2 条），再制造超限连接。
        time.sleep(0.6)
        for _ in range(40):
            sock = _connect(host, port, "127.0.0.1")
            sock.close()
        for _ in range(5):
            sock = _connect(host, port, "127.0.0.2")
            sock.close()
        # 给日志与 accept 循环留出处理时间；期间保持占位连接不释放。
        time.sleep(1.2)
    finally:
        for sock in held:
            try:
                sock.close()
            except OSError:
                pass
    print("ip1_rejections=40 ip2_rejections=5")


def command_ki28_count(args) -> None:
    if len(args) != 2:
        die("用法: ki28-count LOG OFFSET")
    path, offset_raw = args
    offset = int(offset_raw)
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            lines = handle.read().splitlines()[offset:]
    except OSError as exc:
        die(f"读取日志失败: {exc}")

    counts = {
        "ip1_warn": 0,
        "ip1_debug": 0,
        "ip1_other": 0,
        "ip2_warn": 0,
        "ip2_debug": 0,
        "ip2_other": 0,
    }
    for line in lines:
        # 只统计“来源 IP 连接拒绝”相关的日志：按字段匹配，不依赖具体措辞。
        if "来源 IP" not in line:
            continue
        if "上限" not in line and "拒绝" not in line and "采样" not in line:
            continue
        if "ip=127.0.0.1" in line:
            prefix = "ip1"
        elif "ip=127.0.0.2" in line:
            prefix = "ip2"
        else:
            continue
        if " WARN " in line:
            counts[prefix + "_warn"] += 1
        elif " DEBUG " in line:
            counts[prefix + "_debug"] += 1
        else:
            counts[prefix + "_other"] += 1

    fields = " ".join(f"{key}={value}" for key, value in counts.items())
    print(fields)


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

COMMANDS = {
    "ports": command_ports,
    "set-toml": command_set_toml,
    "get-toml": command_get_toml,
    "ki29-seed": command_ki29_seed,
    "ki29-state": command_ki29_state,
    "ki29-late": command_ki29_late,
    "ki29-check": command_ki29_check,
    "archive-seed": command_archive_seed,
    "archive-view": command_archive_view,
    "get": command_get,
    "agent-add-safe": command_agent_add_safe,
    "ki28-flood": command_ki28_flood,
    "ki28-count": command_ki28_count,
}


def main(argv) -> int:
    if len(argv) < 2 or argv[1] not in COMMANDS:
        print("用法: v041_helper.py <command> ...", file=sys.stderr)
        print("commands: " + " ".join(sorted(COMMANDS)), file=sys.stderr)
        return 2
    try:
        COMMANDS[argv[1]](argv[2:])
    except SystemExit:
        raise
    except Exception as exc:  # 防止 traceback 回显 token / 请求体
        print(f"helper 执行失败: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
