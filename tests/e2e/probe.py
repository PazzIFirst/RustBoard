#!/usr/bin/env python3
"""RustBoard 端到端安全测试客户端。

只使用 Python 标准库实现 TLS + WebSocket + MessagePack，不引入任何第三方依赖
（也无需联网安装）。`tests/e2e/security.sh` 用它模拟正常 / 恶意 agent 会话。

用法见 `python3 tests/e2e/probe.py <subcommand> --help`。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.parse
import urllib.request

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PROTOCOL_VERSION = 2


class ProbeError(Exception):
    """可预期的测试失败（网络、协议、断言）。"""


# ---------------------------------------------------------------------------
# MessagePack：只需覆盖本项目用到的类型（nil/bool/int/float/str/bin/array/map）
# ---------------------------------------------------------------------------


def _pack_int(value: int) -> bytes:
    if 0 <= value < 0x80:
        return bytes((value,))
    if -32 <= value < 0:
        return bytes((value & 0xFF,))
    if value >= 0:
        if value <= 0xFF:
            return b"\xcc" + struct.pack(">B", value)
        if value <= 0xFFFF:
            return b"\xcd" + struct.pack(">H", value)
        if value <= 0xFFFFFFFF:
            return b"\xce" + struct.pack(">I", value)
        if value <= 0xFFFFFFFFFFFFFFFF:
            return b"\xcf" + struct.pack(">Q", value)
    elif value >= -0x80:
        return b"\xd0" + struct.pack(">b", value)
    elif value >= -0x8000:
        return b"\xd1" + struct.pack(">h", value)
    elif value >= -0x80000000:
        return b"\xd2" + struct.pack(">i", value)
    elif value >= -0x8000000000000000:
        return b"\xd3" + struct.pack(">q", value)
    raise ProbeError(f"整数超出 MessagePack 范围: {value}")


def _pack_str(value: str) -> bytes:
    raw = value.encode("utf-8")
    size = len(raw)
    if size < 32:
        return bytes((0xA0 | size,)) + raw
    if size <= 0xFF:
        return b"\xd9" + struct.pack(">B", size) + raw
    if size <= 0xFFFF:
        return b"\xda" + struct.pack(">H", size) + raw
    return b"\xdb" + struct.pack(">I", size) + raw


def _pack_bytes(value: bytes) -> bytes:
    size = len(value)
    if size <= 0xFF:
        return b"\xc4" + struct.pack(">B", size) + value
    if size <= 0xFFFF:
        return b"\xc5" + struct.pack(">H", size) + value
    return b"\xc6" + struct.pack(">I", size) + value


def pack(value) -> bytes:
    if value is None:
        return b"\xc0"
    if value is True:
        return b"\xc3"
    if value is False:
        return b"\xc2"
    if isinstance(value, int):
        return _pack_int(value)
    if isinstance(value, float):
        return b"\xcb" + struct.pack(">d", value)
    if isinstance(value, str):
        return _pack_str(value)
    if isinstance(value, (bytes, bytearray)):
        return _pack_bytes(bytes(value))
    if isinstance(value, (list, tuple)):
        size = len(value)
        if size < 16:
            head = bytes((0x90 | size,))
        elif size <= 0xFFFF:
            head = b"\xdc" + struct.pack(">H", size)
        else:
            head = b"\xdd" + struct.pack(">I", size)
        return head + b"".join(pack(item) for item in value)
    if isinstance(value, dict):
        size = len(value)
        if size < 16:
            head = bytes((0x80 | size,))
        elif size <= 0xFFFF:
            head = b"\xde" + struct.pack(">H", size)
        else:
            head = b"\xdf" + struct.pack(">I", size)
        return head + b"".join(
            pack(str(key)) + pack(item) for key, item in value.items()
        )
    raise ProbeError(f"无法打包的类型: {type(value).__name__}")


def _need(data: bytes, offset: int, size: int) -> None:
    if offset + size > len(data):
        raise ProbeError("MessagePack 数据被截断")


def unpack(data: bytes, offset: int = 0):
    _need(data, offset, 1)
    marker = data[offset]
    offset += 1

    if marker <= 0x7F:
        return marker, offset
    if marker >= 0xE0:
        return marker - 0x100, offset

    if 0x80 <= marker <= 0x8F:
        return _unpack_map(data, offset, marker & 0x0F)
    if 0x90 <= marker <= 0x9F:
        return _unpack_array(data, offset, marker & 0x0F)
    if 0xA0 <= marker <= 0xBF:
        return _unpack_str(data, offset, marker & 0x1F)

    if marker == 0xC0:
        return None, offset
    if marker == 0xC2:
        return False, offset
    if marker == 0xC3:
        return True, offset
    if marker == 0xC4:
        _need(data, offset, 1)
        size = data[offset]
        return _unpack_bytes(data, offset + 1, size)
    if marker == 0xC5:
        _need(data, offset, 2)
        size = struct.unpack_from(">H", data, offset)[0]
        return _unpack_bytes(data, offset + 2, size)
    if marker == 0xC6:
        _need(data, offset, 4)
        size = struct.unpack_from(">I", data, offset)[0]
        return _unpack_bytes(data, offset + 4, size)
    if marker == 0xCA:
        _need(data, offset, 4)
        return struct.unpack_from(">f", data, offset)[0], offset + 4
    if marker == 0xCB:
        _need(data, offset, 8)
        return struct.unpack_from(">d", data, offset)[0], offset + 8
    if marker == 0xCC:
        _need(data, offset, 1)
        return data[offset], offset + 1
    if marker == 0xCD:
        _need(data, offset, 2)
        return struct.unpack_from(">H", data, offset)[0], offset + 2
    if marker == 0xCE:
        _need(data, offset, 4)
        return struct.unpack_from(">I", data, offset)[0], offset + 4
    if marker == 0xCF:
        _need(data, offset, 8)
        return struct.unpack_from(">Q", data, offset)[0], offset + 8
    if marker == 0xD0:
        _need(data, offset, 1)
        return struct.unpack_from(">b", data, offset)[0], offset + 1
    if marker == 0xD1:
        _need(data, offset, 2)
        return struct.unpack_from(">h", data, offset)[0], offset + 2
    if marker == 0xD2:
        _need(data, offset, 4)
        return struct.unpack_from(">i", data, offset)[0], offset + 4
    if marker == 0xD3:
        _need(data, offset, 8)
        return struct.unpack_from(">q", data, offset)[0], offset + 8
    if marker == 0xD9:
        _need(data, offset, 1)
        size = data[offset]
        return _unpack_str(data, offset + 1, size)
    if marker == 0xDA:
        _need(data, offset, 2)
        size = struct.unpack_from(">H", data, offset)[0]
        return _unpack_str(data, offset + 2, size)
    if marker == 0xDB:
        _need(data, offset, 4)
        size = struct.unpack_from(">I", data, offset)[0]
        return _unpack_str(data, offset + 4, size)
    if marker == 0xDC:
        _need(data, offset, 2)
        size = struct.unpack_from(">H", data, offset)[0]
        return _unpack_array(data, offset + 2, size)
    if marker == 0xDD:
        _need(data, offset, 4)
        size = struct.unpack_from(">I", data, offset)[0]
        return _unpack_array(data, offset + 4, size)
    if marker == 0xDE:
        _need(data, offset, 2)
        size = struct.unpack_from(">H", data, offset)[0]
        return _unpack_map(data, offset + 2, size)
    if marker == 0xDF:
        _need(data, offset, 4)
        size = struct.unpack_from(">I", data, offset)[0]
        return _unpack_map(data, offset + 4, size)

    raise ProbeError(f"不支持的 MessagePack marker: 0x{marker:02x}")


def _unpack_str(data: bytes, offset: int, size: int):
    _need(data, offset, size)
    return data[offset : offset + size].decode("utf-8"), offset + size


def _unpack_bytes(data: bytes, offset: int, size: int):
    _need(data, offset, size)
    return data[offset : offset + size], offset + size


def _unpack_array(data: bytes, offset: int, size: int):
    out = []
    for _ in range(size):
        item, offset = unpack(data, offset)
        out.append(item)
    return out, offset


def _unpack_map(data: bytes, offset: int, size: int):
    out = {}
    for _ in range(size):
        key, offset = unpack(data, offset)
        value, offset = unpack(data, offset)
        out[key] = value
    return out, offset


# ---------------------------------------------------------------------------
# WebSocket over TLS
# ---------------------------------------------------------------------------


class WebSocket:
    """最小 RFC 6455 客户端：二进制帧 + ping/pong/close。"""

    def __init__(self, url: str, ca: str, cert: str | None, key: str | None,
                 timeout: float = 8.0, bind_ip: str | None = None):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "wss":
            raise ProbeError(f"只支持 wss://，收到 {url}")
        host = parts.hostname
        if host is None:
            raise ProbeError(f"URL 缺少主机名: {url}")
        port = parts.port or 443
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query

        context = ssl.create_default_context(cafile=ca)
        # 保留 Python 3.13 默认的 X509_STRICT：服务端证书已带 AKI，
        # 严格模式必须通过，否则说明证书链有缺陷，e2e 应当失败。
        if cert and key:
            context.load_cert_chain(certfile=cert, keyfile=key)
        elif cert or key:
            raise ProbeError("--cert 与 --key 必须同时提供")

        # bind_ip 用于 e2e 模拟不同来源 IP；None 时保持 create_connection 默认行为。
        source_address = (bind_ip, 0) if bind_ip else None
        raw = socket.create_connection(
            (host, port), timeout=timeout, source_address=source_address
        )
        try:
            self.sock = context.wrap_socket(raw, server_hostname=host)
        except Exception:
            raw.close()
            raise
        self.sock.settimeout(timeout)
        self.buf = b""

        ws_key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        header = self._read_until(b"\r\n\r\n").decode("iso-8859-1")
        lines = header.split("\r\n")
        if len(lines) < 1 or " 101 " not in lines[0]:
            raise ProbeError(f"WebSocket 升级失败: {lines[0] if lines else header!r}")
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.strip().lower()] = value.strip()
        expected = base64.b64encode(
            hashlib.sha1((ws_key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        if headers.get("sec-websocket-accept") != expected:
            raise ProbeError("WebSocket Sec-WebSocket-Accept 校验失败")

    # -- 原始 IO ---------------------------------------------------------

    def _read_until(self, marker: bytes) -> bytes:
        while marker not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProbeError("连接在握手完成前被关闭")
            self.buf += chunk
        end = self.buf.index(marker) + len(marker)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out

    def _read_exact(self, size: int) -> bytes:
        while len(self.buf) < size:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ProbeError("连接已关闭")
            self.buf += chunk
        out, self.buf = self.buf[:size], self.buf[size:]
        return out

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray((0x80 | opcode,))
        size = len(payload)
        if size < 126:
            header.append(0x80 | size)
        elif size <= 0xFFFF:
            header.append(0x80 | 126)
            header += struct.pack(">H", size)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", size)
        mask = os.urandom(4)
        header += mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def send_binary(self, payload: bytes) -> None:
        self._send_frame(0x2, payload)

    def close(self) -> None:
        try:
            self._send_frame(0x8, struct.pack(">H", 1000))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass

    # -- 帧读取 -----------------------------------------------------------

    def recv_message(self, timeout: float):
        """返回 (opcode, payload)；连接关闭返回 None。超时抛 socket.timeout。"""
        self.sock.settimeout(max(0.05, timeout))
        while True:
            first, second = self._read_exact(2)
            fin = bool(first & 0x80)
            opcode = first & 0x0F
            masked = bool(second & 0x80)
            size = second & 0x7F
            if size == 126:
                size = struct.unpack(">H", self._read_exact(2))[0]
            elif size == 127:
                size = struct.unpack(">Q", self._read_exact(8))[0]
            mask = self._read_exact(4) if masked else None
            payload = self._read_exact(size) if size else b""
            if mask is not None:
                payload = bytes(
                    byte ^ mask[index % 4] for index, byte in enumerate(payload)
                )

            if opcode == 0x9:  # ping
                self._send_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode == 0x8:
                return None
            if opcode in (0x1, 0x2):
                if not fin:
                    raise ProbeError("暂不支持分片消息")
                return opcode, payload
            raise ProbeError(f"不支持的 WebSocket opcode: {opcode}")


# ---------------------------------------------------------------------------
# 协议帧
# ---------------------------------------------------------------------------

# 服务端用 rmp_serde::to_vec 编码：struct 是数组，外部 tag 是单键 map。
_SERVER_FIELDS = {
    "Welcome": ("agent_id", "server_version", "protocol", "sample_interval_ms",
                "server_time"),
    "Problem": ("code", "message"),
    "Ack": ("epoch", "seq"),
    "Ping": ("ts",),
    "Pong": ("ts",),
    "Enrolled": ("agent_id", "agent_secret", "cert_pem", "ca_pem"),
}


def decode_server_frame(payload: bytes):
    value, offset = unpack(payload)
    if offset != len(payload):
        raise ProbeError("帧尾部有多余数据")
    if not isinstance(value, dict) or len(value) != 1:
        raise ProbeError(f"无法识别的帧: {value!r}")
    name, body = next(iter(value.items()))
    fields = _SERVER_FIELDS.get(name)
    if fields is None:
        return name, body
    if isinstance(body, dict):
        return name, {field: body.get(field) for field in fields}
    if isinstance(body, (list, tuple)):
        if len(body) < len(fields):
            raise ProbeError(f"{name} 字段不足: {body!r}")
        return name, dict(zip(fields, body))
    if body is None:
        return name, {}
    raise ProbeError(f"{name} 字段格式异常: {body!r}")


def hello_frame(
    agent_id: str, secret: str, epoch: int = 1, protocol: int = PROTOCOL_VERSION
) -> bytes:
    return pack({
        "Hello": {
            "agent_id": agent_id,
            "name": "e2e-probe",
            "hostname": "e2e-probe",
            "os": "linux",
            "arch": "x86_64",
            "version": "0.1.0",
            "protocol": protocol,
            "boot_id": "e2e-probe-boot",
            "epoch": epoch,
            "secret": secret,
            "capabilities": [],
        }
    })


def batch_frame(agent_id: str, epoch: int, seq: int) -> bytes:
    now = int(time.time() * 1000)
    return pack({
        "Batch": {
            "agent_id": agent_id,
            "epoch": epoch,
            "seq": seq,
            "boot_id": "e2e-probe-boot",
            "sent_at": now,
            "samples": [{
                "metric": "probe.forged",
                "labels": {},
                "ts": now,
                "value": 1.0,
            }],
        }
    })


def connect(args, with_client_cert: bool = True) -> WebSocket:
    cert = args.cert if with_client_cert else None
    key = args.key if with_client_cert else None
    return WebSocket(args.url, args.ca, cert, key, timeout=args.timeout)


def send_hello(
    ws: WebSocket,
    agent_id: str,
    secret: str,
    protocol: int = PROTOCOL_VERSION,
) -> None:
    ws.send_binary(hello_frame(agent_id, secret, protocol=protocol))


def recv_first_frame(ws: WebSocket, timeout: float):
    message = ws.recv_message(timeout)
    if message is None:
        raise ProbeError("连接在应答前关闭")
    opcode, payload = message
    if opcode != 0x2:
        raise ProbeError(f"期望二进制帧，收到 opcode={opcode}")
    return decode_server_frame(payload)


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------


def cmd_hello(args) -> int:
    ws = connect(args, with_client_cert=bool(args.cert))
    try:
        send_hello(ws, args.agent_id, args.secret, protocol=args.protocol)
        name, fields = recv_first_frame(ws, args.timeout)
    finally:
        ws.close()

    if args.expect == "welcome":
        if name != "Welcome":
            print(f"FAIL hello: 期望 Welcome，收到 {name} {fields}", file=sys.stderr)
            return 1
        print(
            f"RESULT welcome agent={fields['agent_id']} "
            f"interval={fields['sample_interval_ms']}"
        )
        return 0

    if name != "Problem":
        print(f"FAIL hello: 期望 Problem，收到 {name} {fields}", file=sys.stderr)
        return 1
    if args.expect_code and fields.get("code") != args.expect_code:
        print(
            f"FAIL hello: 期望 Problem code={args.expect_code}，"
            f"实际 {fields.get('code')}",
            file=sys.stderr,
        )
        return 1
    print(f"RESULT problem code={fields.get('code')} message={fields.get('message')}")
    return 0


def cmd_batch(args) -> int:
    ws = connect(args)
    try:
        send_hello(ws, args.agent_id, args.secret)
        name, fields = recv_first_frame(ws, args.timeout)
        if name != "Welcome":
            print(
                f"FAIL batch: 合法 Hello 未收到 Welcome，收到 {name} {fields}",
                file=sys.stderr,
            )
            return 1

        ws.send_binary(batch_frame(args.batch_agent, args.batch_epoch, args.batch_seq))
        print(f"SENT batch agent={args.batch_agent} epoch={args.batch_epoch} "
              f"seq={args.batch_seq}", flush=True)

        problem = None
        closed = False
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            left = deadline - time.monotonic()
            try:
                message = ws.recv_message(left)
            except (socket.timeout, TimeoutError):
                break
            if message is None:
                closed = True
                break
            opcode, payload = message
            if opcode != 0x2:
                continue
            frame_name, frame_fields = decode_server_frame(payload)
            if frame_name == "Ack":
                print(
                    f"FAIL batch: 伪造批次被 ACK epoch={frame_fields['epoch']} "
                    f"seq={frame_fields['seq']}",
                    file=sys.stderr,
                )
                return 1
            if frame_name == "Problem":
                problem = frame_fields
                print(
                    f"FRAME problem code={frame_fields.get('code')} "
                    f"message={frame_fields.get('message')}",
                    flush=True,
                )
    finally:
        ws.close()

    if problem is None:
        print("FAIL batch: 未收到 Problem", file=sys.stderr)
        return 1
    if args.expect_code and problem.get("code") != args.expect_code:
        print(
            f"FAIL batch: 期望 Problem code={args.expect_code}，"
            f"实际 {problem.get('code')}",
            file=sys.stderr,
        )
        return 1
    print(f"RESULT rejected code={problem.get('code')} closed={closed}")
    return 0


def cmd_hold(args) -> int:
    ws = connect(args)
    try:
        send_hello(ws, args.agent_id, args.secret)
        name, fields = recv_first_frame(ws, args.timeout)
        if name != "Welcome":
            print(
                f"FAIL hold: Hello 未收到 Welcome，收到 {name} {fields}",
                file=sys.stderr,
            )
            return 1

        if args.ready_file:
            tmp = args.ready_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(fields.get("agent_id", args.agent_id))
            os.replace(tmp, args.ready_file)
        print(f"RESULT welcome agent={fields.get('agent_id')}", flush=True)

        problem_code = None
        deadline = time.monotonic() + args.hold_timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                print("FAIL hold: 等待服务端关闭连接超时", file=sys.stderr)
                return 3
            try:
                message = ws.recv_message(left)
            except (socket.timeout, TimeoutError):
                continue
            if message is None:
                break
            opcode, payload = message
            if opcode != 0x2:
                continue
            frame_name, frame_fields = decode_server_frame(payload)
            if frame_name == "Problem":
                problem_code = frame_fields.get("code")
                print(
                    f"FRAME problem code={problem_code} "
                    f"message={frame_fields.get('message')}",
                    flush=True,
                )
            elif frame_name == "Ping":
                continue
    finally:
        ws.close()

    if args.expect_problem_code and problem_code != args.expect_problem_code:
        print(
            f"FAIL hold: 期望 Problem code={args.expect_problem_code}，"
            f"实际 {problem_code}",
            file=sys.stderr,
        )
        return 1
    print(f"RESULT closed problem={problem_code}", flush=True)
    return 0


def _admin_headers():
    """管理 API 的 Bearer 头；token 由 security.sh 从 hub 配置读取后经环境变量传入。"""
    token = os.environ.get("RB_E2E_ADMIN_TOKEN", "")
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _http_json(url: str, timeout: float = 3.0):
    try:
        request = urllib.request.Request(url, headers=_admin_headers())
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise ProbeError(f"HTTP {response.status}: {url}")
            return json.loads(response.read().decode("utf-8"))
    except ProbeError:
        raise
    except Exception as exc:  # urllib 的异常类型较多，统一转成可读错误
        raise ProbeError(f"请求 {url} 失败: {exc}") from exc


def cmd_status(args) -> int:
    agents = _http_json(args.admin.rstrip("/") + "/api/v1/agents")
    for agent in agents:
        if agent.get("agent_id") == args.agent:
            print(agent.get("status", ""))
            return 0
    print("absent")
    return 0


def cmd_series_count(args) -> int:
    query = urllib.parse.urlencode({
        "agent": args.agent,
        "from": 0,
        "to": 4_102_444_800_000,  # 2100-01-01，覆盖测试期间的所有样本
        "limit": 50_000,
    })
    rows = _http_json(args.admin.rstrip("/") + "/api/v1/series?" + query)
    print(len(rows))
    return 0


def cmd_health(args) -> int:
    with urllib.request.urlopen(
        args.admin.rstrip("/") + "/healthz", timeout=args.timeout
    ) as response:
        if response.status != 200:
            print(f"FAIL health: HTTP {response.status}", file=sys.stderr)
            return 1
    print("ok")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def add_connection_args(parser) -> None:
    parser.add_argument("--url", required=True, help="wss://127.0.0.1:PORT/agent/ws")
    parser.add_argument("--ca", required=True, help="hub CA 证书（ca.crt）")
    parser.add_argument("--cert", help="客户端证书；不传表示无客户端证书")
    parser.add_argument("--key", help="客户端私钥；与 --cert 成对出现")
    parser.add_argument("--timeout", type=float, default=8.0, help="单次 IO 超时秒数")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RustBoard e2e 测试客户端")
    sub = parser.add_subparsers(dest="cmd", required=True)

    hello = sub.add_parser("hello", help="发 Hello 并检查首个应答")
    add_connection_args(hello)
    hello.add_argument("--agent-id", required=True)
    hello.add_argument("--secret", required=True)
    hello.add_argument(
        "--protocol", type=int, default=PROTOCOL_VERSION, help="Hello 里的协议版本"
    )
    hello.add_argument("--expect", choices=("welcome", "problem"), default="welcome")
    hello.add_argument("--expect-code", default=None)
    hello.set_defaults(func=cmd_hello)

    batch = sub.add_parser("batch", help="合法会话里提交伪造 agent_id 的 Batch")
    add_connection_args(batch)
    batch.add_argument("--agent-id", required=True, help="Hello 使用的会话身份")
    batch.add_argument("--secret", required=True)
    batch.add_argument("--batch-agent", required=True, help="伪造批次的 agent_id")
    batch.add_argument("--batch-epoch", type=int, default=424242)
    batch.add_argument("--batch-seq", type=int, default=0)
    batch.add_argument("--expect-code", default=None)
    batch.set_defaults(func=cmd_batch)

    hold = sub.add_parser("hold", help="建立会话后保持，直到服务端关闭")
    add_connection_args(hold)
    hold.add_argument("--agent-id", required=True)
    hold.add_argument("--secret", required=True)
    hold.add_argument("--ready-file", default=None)
    hold.add_argument("--hold-timeout", type=float, default=45.0)
    hold.add_argument("--expect-problem-code", default=None)
    hold.set_defaults(func=cmd_hold)

    status = sub.add_parser("status", help="查询 agent 状态")
    status.add_argument("--admin", required=True, help="http://127.0.0.1:ADMIN_PORT")
    status.add_argument("--agent", required=True)
    status.set_defaults(func=cmd_status)

    count = sub.add_parser("series-count", help="查询 agent 的样本行数")
    count.add_argument("--admin", required=True)
    count.add_argument("--agent", required=True)
    count.set_defaults(func=cmd_series_count)

    health = sub.add_parser("health", help="查询 admin /healthz")
    health.add_argument("--admin", required=True)
    health.add_argument("--timeout", type=float, default=2.0)
    health.set_defaults(func=cmd_health)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except (ProbeError, OSError, ssl.SSLError, socket.timeout) as exc:
        print(f"FAIL {args.cmd}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
