#!/usr/bin/env python3
"""RustBoard v0.3.5 e2e helper：per-IP WebSocket 连接上限（KI-27）。

flood 模式：
  1. 从 --primary-ip 连续建立 --primary-count 条 WS，每条发正常 Hello 并等 Welcome；
     全部保持打开。
  2. 从同一源 IP 再尝试第 primary-count+1 条，必须失败（连接/握手层异常才算拒绝；
     “握手成功但没有 Welcome”不算拒绝，会显式记录为 handshake_ok_no_welcome）。
  3. 从 --other-ip 建立 1 条，必须收到 Welcome。
  4. JSON 单行输出到 stdout（不含 secret / 证书正文），随后保持连接
     --hold-seconds 秒再关闭。测试脚本据此在“连接仍打开”期间查询管理 API。

退出码：
  0  流程跑完（即使字段值不符合预期，交给 shell 断言）
  2  源地址无法绑定（EADDRNOTAVAIL 等），直接失败、不跳过
  3  helper 自身无法完成前置连接（例如一条都建不起来）

只使用标准库，复用 tests/e2e/probe.py 的 TLS/mTLS + WebSocket 实现。
"""

import argparse
import json
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
        "name": "e2e-v035-flood",
        "hostname": "e2e-v035-flood",
        "os": "linux",
        "arch": "x86_64",
        "version": "0.3.5-e2e",
        "boot_id": "e2e-v035-flood-boot",
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


def hello_payload(agent_id: str, secret: str, metadata: dict) -> bytes:
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
            "capabilities": [],
        }
    })


def recv_frame(ws: probe.WebSocket, timeout: float):
    """返回 (name, body)；连接关闭返回 None；读超时返回 _TIMEOUT。"""
    try:
        message = ws.recv_message(timeout)
    except (TimeoutError, socket.timeout):
        return _TIMEOUT
    except (probe.ProbeError, OSError):
        return None
    if message is None:
        return None
    opcode, payload = message
    if opcode != 0x2:
        return _TIMEOUT
    return probe.decode_server_frame(payload)


def wait_welcome(ws: probe.WebSocket, timeout: float):
    """等待 Welcome；返回 (状态, 细节)。

    状态：welcome / problem / closed / timeout / bad_frame。
    """
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return "timeout", f"{timeout:g}s 内未收到 Welcome"
        frame = recv_frame(ws, remaining)
        if frame is _TIMEOUT:
            return "timeout", f"{timeout:g}s 内未收到 Welcome"
        if frame is None:
            return "closed", "连接在 Welcome 前关闭"
        name, body = frame
        if name == "Welcome":
            return "welcome", ""
        if name == "Problem":
            code = ""
            if isinstance(body, dict):
                code = str(body.get("code", ""))
            return "problem", code
        return "bad_frame", f"收到非 Welcome 帧: {name}"


def assert_source_bindable(ip: str) -> None:
    """提前验证源地址可绑定，避免把配置/环境错误误判成 hub 拒绝。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((ip, 0))
    finally:
        sock.close()


def connect(args, bind_ip: str) -> probe.WebSocket:
    return probe.WebSocket(
        args.url,
        args.ca,
        args.cert,
        args.key,
        timeout=args.timeout,
        bind_ip=bind_ip,
    )


def emit(result: dict) -> None:
    # 单行 JSON；字段只含状态与异常类型/文本，不含 secret / 证书正文。
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")), flush=True)


def close_all(connections) -> None:
    for ws in reversed(connections):
        try:
            ws.close()
        except OSError:
            pass


def run_flood(args) -> int:
    secret = read_trimmed(args.secret_file)
    if not secret:
        log("ERR agent secret 为空（不打印内容）")
        return 2

    result = {
        "mode": "flood",
        "primary_ip": args.primary_ip,
        "other_ip": args.other_ip,
        "primary_count": args.primary_count,
        "opened": 0,
        "same_ip_rejected": False,
        "same_ip_error_type": "",
        "same_ip_error": "",
        "other_ip_ok": False,
        "other_ip_error_type": "",
        "other_ip_error": "",
        "hold_seconds": args.hold_seconds,
        "error": "",
    }
    connections = []

    # 先验证两个源地址确实可绑定；失败就直接非零退出，不进入“预期拒绝”分支。
    for ip in (args.primary_ip, args.other_ip):
        try:
            assert_source_bindable(ip)
        except OSError as exc:
            result["error"] = (
                f"source_bind_failed:{ip}:{type(exc).__name__}:"
                f"{exc.errno if exc.errno is not None else ''}"
            )
            emit(result)
            log(f"ERR 无法绑定源地址 {ip}: {exc}（不跳过）")
            return 2

    try:
        metadata = load_metadata(args.metadata_file)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result["error"] = f"metadata_invalid:{type(exc).__name__}"
        emit(result)
        log(f"ERR metadata 无效: {exc}")
        return 3
    hello = hello_payload(args.agent_id, secret, metadata)

    # ---- 1) 同一源 IP 的前 primary-count 条必须成功并拿到 Welcome ----
    for index in range(args.primary_count):
        try:
            ws = connect(args, args.primary_ip)
        except Exception as exc:  # noqa: BLE001 - 任何连接层失败都是 helper 前置失败
            result["error"] = (
                f"primary_connect_failed[{index + 1}]:{type(exc).__name__}"
            )
            log(f"ERR 第 {index + 1} 条 primary 连接建立失败: {exc}")
            close_all(connections)
            emit(result)
            return 3
        try:
            ws.send_binary(hello)
        except OSError as exc:
            result["error"] = f"primary_hello_send_failed[{index + 1}]:{type(exc).__name__}"
            ws.close()
            close_all(connections)
            emit(result)
            log(f"ERR 第 {index + 1} 条 primary 连接发送 Hello 失败: {exc}")
            return 3
        state, detail = wait_welcome(ws, args.timeout)
        if state != "welcome":
            result["error"] = (
                f"primary_welcome_{state}[{index + 1}]:{detail}"
            )
            ws.close()
            close_all(connections)
            emit(result)
            log(f"ERR 第 {index + 1} 条 primary 连接未拿到 Welcome: {state} {detail}")
            return 3
        connections.append(ws)
        result["opened"] += 1

    # ---- 2) 第 primary-count+1 条：必须失败；握手成功但无 Welcome 不算拒绝 ----
    try:
        extra = connect(args, args.primary_ip)
    except Exception as exc:  # noqa: BLE001 - 这正是预期的拒绝
        result["same_ip_rejected"] = True
        result["same_ip_error_type"] = type(exc).__name__
        result["same_ip_error"] = str(exc)[:300]
    else:
        state, detail = wait_welcome(extra, args.timeout)
        if state == "welcome":
            result["same_ip_error"] = "handshake_ok_welcome_received"
        else:
            result["same_ip_error"] = f"handshake_ok_no_welcome:{state}:{detail}"
        extra.close()

    # ---- 3) 另一个源 IP 必须能拿到 Welcome ----
    try:
        other = connect(args, args.other_ip)
    except Exception as exc:  # noqa: BLE001 - 记录后由 shell 断言失败
        result["other_ip_error_type"] = type(exc).__name__
        result["other_ip_error"] = str(exc)[:300]
    else:
        try:
            other.send_binary(hello)
        except OSError as exc:
            result["other_ip_error_type"] = type(exc).__name__
            result["other_ip_error"] = f"hello_send_failed:{exc}"
            other.close()
        else:
            state, detail = wait_welcome(other, args.timeout)
            if state == "welcome":
                result["other_ip_ok"] = True
                connections.append(other)
            else:
                result["other_ip_error"] = f"{state}:{detail}"
                other.close()

    # 先输出结果（连接仍保持打开），shell 收到后立即查询管理 API。
    emit(result)

    # ---- 4) 保持连接 hold-seconds 秒后关闭 ----
    deadline = time.monotonic() + max(0.0, args.hold_seconds)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(0.2, remaining))

    close_all(connections)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="v0.3.5 e2e per-IP flood helper")
    sub = parser.add_subparsers(dest="command", required=True)

    flood = sub.add_parser("flood", help="同一源 IP 连接上限 + 另一源 IP 可用")
    flood.add_argument("--url", required=True, help="wss://127.0.0.1:PORT/agent/ws")
    flood.add_argument("--ca", required=True, help="hub CA 证书（ca.crt）")
    flood.add_argument("--cert", required=True, help="enrollment 得到的 agent.crt")
    flood.add_argument("--key", required=True, help="enrollment 得到的 agent.key")
    flood.add_argument("--agent-id", required=True)
    flood.add_argument("--secret-file", required=True,
                       help="enrollment 得到的 agent.secret（只读取，不打印）")
    flood.add_argument("--primary-ip", default="127.0.0.2",
                       help="前 primary-count 条连接以及超限尝试使用的源 IP")
    flood.add_argument("--primary-count", type=int, default=2,
                       help="同一源 IP 期望成功并可保持的 WS 数量")
    flood.add_argument("--other-ip", default="127.0.0.3",
                       help="用于验证另一个源 IP 仍可连接的地址")
    flood.add_argument("--hold-seconds", type=float, default=8.0,
                       help="输出 JSON 后保持全部连接打开的秒数")
    flood.add_argument("--metadata-file", default="",
                       help="可选 JSON，覆盖 Hello 元数据（字段名与默认值一致）")
    flood.add_argument("--timeout", type=float, default=8.0,
                       help="单次连接/等待 Welcome 的超时秒数")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.primary_count < 1:
        parser.error("--primary-count 必须 >= 1")
    if args.command == "flood":
        return run_flood(args)
    parser.error(f"未知子命令: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
