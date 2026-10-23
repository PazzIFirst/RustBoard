#!/usr/bin/env python3
"""v0.3.4 e2e 用的最小 fake agent（仅 Python 标准库）。

复用同目录 `probe.py` 的 TLS / WebSocket / MessagePack 实现，不重新实现协议。
真实 agent 先完成 enrollment，把 `agent_id` / `agent.secret` / `agent.crt` /
`agent.key` / `ca.crt` 留在数据目录；本脚本用这些材料建立真实 mTLS 会话，
因此 Hub 侧的证书 CN / secret / 协议校验路径全部生效。

两个子命令：

- `hello`：发送一条 Hello，元数据可用 `--metadata-file`（JSON）覆盖，用于
  KI-19 的超长 / 控制字符字段与正常 Hello 回归。非法帧必须收到
  `Problem(code=bad_frame)` 且连接关闭；正常帧必须收到 `Welcome` 并可保持会话。
- `multi`：同一个 agent 的多连接编排（KI-24）。脚本按命令文件依次建立/关闭
  连接、发送晚到的 Hello、应答 `ControlRequest`，并把每一步写入状态文件；
  断言仍由 `v034.sh` 用管理 API 完成，本脚本只负责制造真实的协议时序。

凭据只从 `--secret-file` 读取，不出现在命令行参数里；日志与状态文件不打印
secret / 证书正文 / 私钥。
"""

from __future__ import annotations

import argparse
import json
import select
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import probe  # noqa: E402

PROTOCOL_VERSION = 2
_TIMEOUT = object()


def log(message: str) -> None:
    print(message, flush=True)


def read_trimmed(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def default_metadata() -> dict:
    return {
        "name": "e2e-v034-fake",
        "hostname": "e2e-v034-fake",
        "os": "linux",
        "arch": "x86_64",
        "version": "0.3.4-e2e",
        "boot_id": "e2e-v034-fake-boot",
        "protocol": PROTOCOL_VERSION,
        "epoch": 1,
    }


def load_metadata(path: str) -> dict:
    meta = default_metadata()
    if path:
        with open(path, encoding="utf-8") as handle:
            overrides = json.load(handle)
        if not isinstance(overrides, dict):
            raise ValueError("metadata 必须是 JSON 对象")
        for key, value in overrides.items():
            if key not in meta:
                raise ValueError(f"metadata 含未知字段: {key}")
            meta[key] = value
    return meta


def hello_payload(agent_id: str, secret: str, metadata: dict,
                  capabilities: list[str]) -> bytes:
    return probe.pack({
        "Hello": {
            "agent_id": agent_id,
            "name": metadata["name"],
            "hostname": metadata["hostname"],
            "os": metadata["os"],
            "arch": metadata["arch"],
            "version": metadata["version"],
            "protocol": metadata["protocol"],
            "boot_id": metadata["boot_id"],
            "epoch": metadata["epoch"],
            "secret": secret,
            "capabilities": list(capabilities),
        }
    })


def recv_frame(ws: probe.WebSocket, timeout: float):
    """返回 (name, body)；连接关闭返回 None；读超时返回 _TIMEOUT。"""
    try:
        message = ws.recv_message(timeout)
    except (TimeoutError, socket.timeout):
        return _TIMEOUT
    except probe.ProbeError as exc:
        log(f"EOF {exc}")
        return None
    except OSError as exc:
        log(f"ERR socket {exc}")
        return None
    if message is None:
        return None
    opcode, payload = message
    if opcode != 0x2:
        return _TIMEOUT
    name, body = probe.decode_server_frame(payload)
    return name, body


def frame_code(body) -> str:
    if isinstance(body, dict):
        code = body.get("code")
        return "" if code is None else str(code)
    return ""


# ---------------------------------------------------------------------------
# hello：非法 / 正常 Hello 回归
# ---------------------------------------------------------------------------


def run_hello(args) -> int:
    secret = read_trimmed(args.secret_file)
    if not secret:
        log("ERR agent secret 为空")
        return 2
    metadata = load_metadata(args.metadata_file)
    capabilities = [item for item in args.capabilities.split(",") if item]

    ws = probe.WebSocket(args.url, args.ca, args.cert, args.key, timeout=args.timeout)
    result = {
        "mode": "hello",
        "result": "timeout",
        "code": "",
        "closed": False,
        "held": False,
        "welcome": False,
    }
    try:
        ws.send_binary(hello_payload(args.agent_id, secret, metadata, capabilities))
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            left = max(0.05, min(0.5, deadline - time.monotonic()))
            frame = recv_frame(ws, left)
            if frame is None:
                result["closed"] = True
                break
            if frame is _TIMEOUT:
                continue
            name, body = frame
            if name == "Welcome":
                result["result"] = "welcome"
                result["welcome"] = True
                break
            if name == "Problem":
                result["result"] = "problem"
                result["code"] = frame_code(body)
                # 非法 Hello 必须随后关闭连接；等待 EOF（或对端 close 帧）。
                close_deadline = time.monotonic() + 3.0
                while time.monotonic() < close_deadline:
                    frame = recv_frame(ws, 0.3)
                    if frame is None:
                        result["closed"] = True
                        break
                    if frame is _TIMEOUT:
                        continue
                break
            # Ping/Pong 等与断言无关。
    finally:
        ws.close()

    print(json.dumps(result, ensure_ascii=False), flush=True)
    expected = args.expect
    if expected == "welcome":
        return 0 if result["result"] == "welcome" else 1
    if expected == "problem":
        return 0 if (result["result"] == "problem" and result["closed"]) else 1
    return 0


def run_hold(args) -> int:
    """正常 Hello 后保持会话 N 秒：验证 Welcome、Ping/Pong 与连接不关闭。"""
    secret = read_trimmed(args.secret_file)
    if not secret:
        log("ERR agent secret 为空")
        return 2
    metadata = load_metadata(args.metadata_file)
    capabilities = [item for item in args.capabilities.split(",") if item]

    ws = probe.WebSocket(args.url, args.ca, args.cert, args.key, timeout=args.timeout)
    result = {"mode": "hold", "welcome": False, "held": False, "closed_early": False}
    try:
        ws.send_binary(hello_payload(args.agent_id, secret, metadata, capabilities))
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            frame = recv_frame(ws, max(0.05, min(0.5, deadline - time.monotonic())))
            if frame is None:
                result["closed_early"] = True
                break
            if frame is _TIMEOUT:
                continue
            name, body = frame
            if name == "Welcome":
                result["welcome"] = True
                break
            if name == "Problem":
                result["code"] = frame_code(body)
                print(json.dumps(result, ensure_ascii=False), flush=True)
                return 1

        if result["welcome"]:
            hold_deadline = time.monotonic() + args.hold_seconds
            last_ping = time.monotonic()
            while time.monotonic() < hold_deadline:
                if time.monotonic() - last_ping >= 5.0:
                    ws.send_binary(probe.pack({"Ping": {"ts": int(time.time() * 1000)}}))
                    last_ping = time.monotonic()
                frame = recv_frame(ws, 0.3)
                if frame is None:
                    result["closed_early"] = True
                    break
                if frame is _TIMEOUT:
                    continue
                name, body = frame
                if name == "Problem":
                    result["code"] = frame_code(body)
                    break
            result["held"] = not result["closed_early"]
    finally:
        ws.close()

    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0 if (result["welcome"] and result["held"]) else 1


# ---------------------------------------------------------------------------
# multi：多连接能力 / sender 编排（KI-24）
# ---------------------------------------------------------------------------


class ManagedConn:
    def __init__(self, role: str, ws: probe.WebSocket, status_file: str):
        self.role = role
        self.ws = ws
        self.status_file = status_file
        self.alive = True

    def status(self, message: str) -> None:
        line = f"{self.role} {message}"
        with open(self.status_file, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()

    def close(self) -> None:
        if not self.alive:
            return
        self.alive = False
        self.ws.close()
        self.status("CLOSED")


def control_response_payload(rid: int, role: str) -> bytes:
    # 线协议（common/control.rs 的 ControlResult）是外部标签枚举：
    # {"SystemdUnits": [{unit, load, active, sub, description}, ...]}。
    # 管理 API 的 {"type":"systemd_units", ...} 是 hub 的 JSON 转换结果，
    # 不是线协议形态。unit 名带角色标记，供 e2e 断言“控制请求投递到了
    # 哪一条连接”。
    unit = {
        "unit": f"v034-{role}-conn.service",
        "load": "loaded",
        "active": "active",
        "sub": "running",
        "description": f"v034 e2e {role} connection",
    }
    return probe.pack({
        "ControlResponse": [rid, {"SystemdUnits": [unit]}, None]
    })


def request_id(body) -> int:
    if isinstance(body, (list, tuple)) and body:
        return int(body[0])
    if isinstance(body, dict) and "id" in body:
        return int(body["id"])
    raise probe.ProbeError(f"无法从 ControlRequest 解析 id: {body!r}")


class CommandReader:
    """轮询命令文件的新增行（bash 侧只追加，不需要 FIFO 阻塞）。"""

    def __init__(self, path: str):
        self.path = path
        self.offset = 0
        self.pending = ""

    def read(self) -> list[str]:
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                handle.seek(self.offset)
                chunk = handle.read()
                self.offset = handle.tell()
        except FileNotFoundError:
            return []
        self.pending += chunk
        if "\n" not in self.pending:
            return []
        lines = self.pending.split("\n")
        self.pending = lines.pop()
        return [line.strip() for line in lines if line.strip()]


def run_multi(args) -> int:
    secret = read_trimmed(args.secret_file)
    if not secret:
        log("ERR agent secret 为空")
        return 2
    metadata = load_metadata(args.metadata_file)
    caps_b = [item for item in args.caps_b.split(",") if item]
    caps_a = [item for item in args.caps_a.split(",") if item]
    caps_c = [item for item in args.caps_c.split(",") if item]

    status_file = args.status_file
    Path(status_file).write_text("", encoding="utf-8")
    commands = CommandReader(args.cmd_file)

    def open_conn(role: str) -> ManagedConn:
        ws = probe.WebSocket(args.url, args.ca, args.cert, args.key,
                             timeout=args.timeout)
        return ManagedConn(role, ws, status_file)

    conns: list[ManagedConn] = []

    def connect_and_hello(role: str, caps: list[str]) -> ManagedConn:
        conn = open_conn(role)
        conn.ws.send_binary(hello_payload(args.agent_id, secret, metadata, caps))
        conns.append(conn)
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            frame = recv_frame(conn.ws, max(0.05, min(0.5, deadline - time.monotonic())))
            if frame is None:
                conn.status("CLOSED")
                conn.alive = False
                raise probe.ProbeError(f"{role} 连接在 Welcome 前关闭")
            if frame is _TIMEOUT:
                continue
            name, body = frame
            if name == "Welcome":
                conn.status("WELCOME")
                return conn
            if name == "Problem":
                conn.status(f"PROBLEM {frame_code(body)}")
                raise probe.ProbeError(f"{role} Hello 被拒: {frame_code(body)}")
        raise probe.ProbeError(f"{role} 等待 Welcome 超时")

    # 两条真实连接：old 先完成 Hello（能力 B），new 后完成 Hello（能力 A）。
    # late-hello 命令让 old 在**会话建立之后**再补发一条能力 C 的 Hello，
    # 用于验证“旧连接晚到的 Hello 不覆盖最新连接能力”。连接注册顺序由 Hello
    # 处理顺序决定，不能靠“先建 TLS 但晚发 Hello”来伪造旧连接。
    old = connect_and_hello("old", caps_b)
    new = connect_and_hello("new", caps_a)
    with open(status_file, "a", encoding="utf-8") as handle:
        handle.write("MAIN READY\n")
        handle.flush()

    running = True
    last_ping = time.monotonic()
    while running:
        for command in commands.read():
            try:
                if command == "late-hello":
                    old.ws.send_binary(
                        hello_payload(args.agent_id, secret, metadata, caps_c)
                    )
                    old.status("LATE_SENT")
                elif command == "close-new":
                    new.close()
                elif command == "close-old":
                    old.close()
                elif command == "quit":
                    for conn in conns:
                        conn.close()
                    with open(status_file, "a", encoding="utf-8") as handle:
                        handle.write("MAIN BYE\n")
                        handle.flush()
                    running = False
                else:
                    with open(status_file, "a", encoding="utf-8") as handle:
                        handle.write(f"MAIN UNKNOWN {command}\n")
                        handle.flush()
            except OSError as exc:
                log(f"ERR 执行命令 {command}: {exc}")
                running = False
        if not running:
            break

        if time.monotonic() - last_ping >= 10.0:
            for conn in conns:
                if conn.alive:
                    try:
                        conn.ws.send_binary(
                            probe.pack({"Ping": {"ts": int(time.time() * 1000)}})
                        )
                    except OSError:
                        conn.alive = False
            last_ping = time.monotonic()

        sockets = {conn.ws.sock: conn for conn in conns if conn.alive}
        if not sockets:
            with open(status_file, "a", encoding="utf-8") as handle:
                handle.write("MAIN ALL_CLOSED\n")
                handle.flush()
            break
        try:
            ready, _, _ = select.select(list(sockets), [], [], 0.05)
        except OSError:
            ready = []
        # WebSocket 可能已经把多个帧读进用户态缓冲，select 不会再报可读。
        for conn in conns:
            if conn.alive and len(conn.ws.buf) > 0 and conn.ws.sock not in ready:
                ready = list(ready) + [conn.ws.sock]

        for sock in ready:
            conn = sockets.get(sock)
            if conn is None or not conn.alive:
                continue
            try:
                frame = recv_frame(conn.ws, 2.0)
            except OSError as exc:
                conn.status(f"ERR {exc}")
                conn.alive = False
                continue
            if frame is None:
                conn.alive = False
                conn.status("CLOSED")
                continue
            if frame is _TIMEOUT:
                continue
            name, body = frame
            if name == "ControlRequest":
                try:
                    rid = request_id(body)
                except probe.ProbeError as exc:
                    conn.status(f"BAD_CONTROL {exc}")
                    continue
                try:
                    conn.ws.send_binary(control_response_payload(rid, conn.role))
                except OSError as exc:
                    conn.status(f"ERR send {exc}")
                    conn.alive = False
                    continue
                conn.status(f"CTRL id={rid}")
            elif name == "Problem":
                conn.status(f"PROBLEM {frame_code(body)}")
            elif name == "Welcome":
                conn.status("WELCOME")

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def add_connection_args(parser) -> None:
    parser.add_argument("--url", required=True, help="wss://127.0.0.1:PORT/agent/ws")
    parser.add_argument("--ca", required=True, help="hub CA 证书（ca.crt）")
    parser.add_argument("--cert", required=True, help="enrollment 得到的 agent.crt")
    parser.add_argument("--key", required=True, help="enrollment 得到的 agent.key")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--secret-file", required=True,
                        help="enrollment 得到的 agent.secret（不走命令行值）")
    parser.add_argument("--metadata-file", default="",
                        help="Hello 元数据覆盖（JSON 对象，0600）")
    parser.add_argument("--capabilities", default="",
                        help="Hello 上报的能力，逗号分隔")
    parser.add_argument("--timeout", type=float, default=8.0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="v0.3.4 e2e fake agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    hello = sub.add_parser("hello", help="发送一条 Hello 并检查首帧与关闭")
    add_connection_args(hello)
    hello.add_argument("--expect", choices=("welcome", "problem"), required=True)
    hello.set_defaults(func=run_hello)

    hold = sub.add_parser("hold", help="正常 Hello 后保持会话")
    add_connection_args(hold)
    hold.add_argument("--hold-seconds", type=float, default=3.0)
    hold.set_defaults(func=run_hold)

    multi = sub.add_parser("multi", help="多连接能力 / 控制 sender 编排")
    add_connection_args(multi)
    multi.add_argument("--cmd-file", required=True)
    multi.add_argument("--status-file", required=True)
    multi.add_argument("--caps-b", required=True,
                       help="旧连接（第二条注册）上报的能力")
    multi.add_argument("--caps-a", required=True,
                       help="新连接（第三条注册）上报的能力")
    multi.add_argument("--caps-c", required=True,
                       help="旧连接在会话建立后补发 Hello 的能力（不得覆盖最新连接）")
    multi.set_defaults(func=run_multi)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except (OSError, ValueError, probe.ProbeError, json.JSONDecodeError) as exc:
        log(f"ERR {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
