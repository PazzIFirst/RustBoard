#!/usr/bin/env python3
"""v0.3.2 e2e 用的最小 fake agent（仅 Python 标准库）。

复用同目录 `probe.py` 的 TLS / WebSocket / MessagePack 实现，不重新实现协议。
真实 agent 先完成 enrollment，把 `agent_id` / `agent.secret` / `agent.crt` /
`agent.key` / `ca.crt` 留在数据目录；本脚本用这些材料建立同一条 mTLS 会话：

- `ignore` 模式：收到 `ControlRequest` 后**故意不回复**，让 hub 的会话内
  deadline 清理 pending（#18）。脚本只记录 `IGNORE id=N`，不伪造成功。
- `busy` 模式：立即按请求里的 id 回 `ControlResponse`，错误码
  `busy_renewing` + 固定文案，模拟 agent 的证书续签等待窗口（#16）。

模式从 `--mode-file` 每次收到控制请求时读取，测试可在不重连的情况下切换。
凭据只从 `--secret-file` 读取，不出现在命令行参数；日志不打印 secret / 证书正文。
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import probe  # noqa: E402

PROTOCOL_VERSION = 2
BUSY_CODE = "busy_renewing"
BUSY_MESSAGE = "agent 正在续签证书，请稍后重试"

_TIMEOUT = object()


def log(message: str) -> None:
    print(message, flush=True)


def read_trimmed(path: str) -> str:
    return Path(path).read_text(encoding="utf-8").strip()


def current_mode(path: str) -> str:
    if not path:
        return "ignore"
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return "ignore"
    return value or "ignore"


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="v0.3.2 e2e fake agent（mTLS + MessagePack，仅标准库）"
    )
    parser.add_argument("--url", required=True, help="wss://127.0.0.1:<port>/agent/ws")
    parser.add_argument("--ca", required=True, help="hub CA 证书路径")
    parser.add_argument("--cert", required=True, help="enrollment 得到的 agent.crt")
    parser.add_argument("--key", required=True, help="enrollment 得到的 agent.key")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument(
        "--secret-file",
        required=True,
        help="enrollment 得到的 agent.secret（不通过命令行传值）",
    )
    parser.add_argument("--ready-file", required=True, help="收到 Welcome 后写入")
    parser.add_argument(
        "--mode-file",
        default="",
        help="控制请求处理模式文件：ignore（默认）/ busy",
    )
    parser.add_argument(
        "--capability",
        action="append",
        default=[],
        help="Hello 上报的控制能力，可重复",
    )
    return parser.parse_args(argv)


def hello_payload(args, secret: str) -> bytes:
    return probe.pack({
        "Hello": {
            "agent_id": args.agent_id,
            "name": "e2e-v032-fake",
            "hostname": "e2e-v032-fake",
            "os": "linux",
            "arch": "x86_64",
            "version": "0.3.2-e2e",
            "protocol": PROTOCOL_VERSION,
            "boot_id": "e2e-v032-fake-boot",
            "epoch": 1,
            "secret": secret,
            "capabilities": list(args.capability),
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


def request_id(body) -> int:
    if isinstance(body, (list, tuple)) and body:
        return int(body[0])
    if isinstance(body, dict) and "id" in body:
        return int(body["id"])
    raise probe.ProbeError(f"无法从 ControlRequest 解析 id: {body!r}")


def run(args) -> int:
    secret = read_trimmed(args.secret_file)
    if not secret:
        log("ERR agent secret 为空")
        return 2

    ws = probe.WebSocket(args.url, args.ca, args.cert, args.key, timeout=8.0)
    ws.send_binary(hello_payload(args, secret))

    deadline = time.monotonic() + 10.0
    welcome = False
    while time.monotonic() < deadline:
        frame = recv_frame(ws, 0.5)
        if frame is None:
            log("ERR 连接在 Welcome 前关闭")
            return 3
        if frame is _TIMEOUT:
            continue
        name, body = frame
        if name == "Welcome":
            welcome = True
            break
        if name == "Problem":
            code = body.get("code") if isinstance(body, dict) else body
            log(f"ERR Problem {code}")
            return 3

    if not welcome:
        log("ERR 等待 Welcome 超时")
        return 3

    Path(args.ready_file).write_text("ready\n", encoding="utf-8")
    log(f"READY agent={args.agent_id} capabilities={','.join(args.capability)}")

    last_ping = time.monotonic()
    requests = 0
    while True:
        if time.monotonic() - last_ping >= 10.0:
            ws.send_binary(probe.pack({"Ping": {"ts": int(time.time() * 1000)}}))
            last_ping = time.monotonic()

        frame = recv_frame(ws, 1.0)
        if frame is None:
            log("EOF hub 关闭连接")
            return 0
        if frame is _TIMEOUT:
            continue

        name, body = frame
        if name == "ControlRequest":
            requests += 1
            try:
                rid = request_id(body)
            except probe.ProbeError as exc:
                log(f"ERR {exc}")
                return 4
            if current_mode(args.mode_file) == "busy":
                # 数组形态：ControlResponse { id, result, error }，
                # ControlError { code, message }；id 必须来自当前请求。
                response = probe.pack({
                    "ControlResponse": [rid, None, [BUSY_CODE, BUSY_MESSAGE]]
                })
                try:
                    ws.send_binary(response)
                except OSError as exc:
                    log(f"ERR 发送 busy_renewing 失败 {exc}")
                    return 5
                log(f"BUSY id={rid}")
            else:
                # #18：只记录，不回复。hub 必须依靠会话内 deadline 清理 pending。
                log(f"IGNORE id={rid}")
        elif name == "Problem":
            code = body.get("code") if isinstance(body, dict) else body
            log(f"ERR Problem {code}")
            return 3
        # Welcome/Pong/CertRenewed 等帧与本测试无关，忽略。


def main() -> int:
    args = parse_args(sys.argv[1:])
    try:
        return run(args)
    except (OSError, probe.ProbeError) as exc:
        log(f"ERR {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
