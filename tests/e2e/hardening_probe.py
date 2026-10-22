#!/usr/bin/env python3
"""v0.2.1 硬化回归用的最小探针（仅 Python 标准库）。

子命令：
  http             发送 HTTP 请求，输出 status / headers / body 摘要
  tls-fingerprint  取一次 TLS 握手中服务端证书的 DER SHA-256
  flood            从指定源地址开一批空闲 TCP 连接并保持一段时间

所有输出都是单行 JSON，方便 bash 用 python -c 解析。不访问外网。
"""

import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request


def _parse_headers(values):
    headers = {}
    for raw in values or []:
        name, sep, value = raw.partition(":")
        if not sep or not name.strip():
            raise SystemExit(f"非法 header: {raw!r}")
        headers[name.strip()] = value.strip()
    return headers


def _cookie_header(path):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            line = handle.readline().strip()
    except OSError as exc:
        raise SystemExit(f"读取 Cookie 文件失败: {exc}")
    if not line:
        return None
    return line


def _request(args, data=None):
    headers = _parse_headers(args.header)
    if args.bearer_env:
        token = os.environ.get("RB_E2E_ADMIN_TOKEN", "")
        if not token:
            raise SystemExit("RB_E2E_ADMIN_TOKEN 为空，无法附加 Bearer")
        headers["Authorization"] = f"Bearer {token}"
    cookie = _cookie_header(args.cookie_file)
    if cookie:
        headers["Cookie"] = cookie

    request = urllib.request.Request(
        args.url, data=data, headers=headers, method=args.method.upper()
    )
    # 测试探针必须直连，禁止环境代理影响断言。
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=args.timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    return response


def cmd_http(args):
    data = args.data.encode("utf-8") if args.data is not None else None
    response = _request(args, data=data)
    body = response.read(args.max_body + 1)
    if len(body) > args.max_body:
        raise SystemExit(f"响应体超过 {args.max_body} 字节上限")
    headers = {}
    for name, value in response.headers.items():
        key = name.lower()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value
    info = {
        "status": int(response.status),
        "headers": headers,
        "body_len": len(body),
        "body": body.decode("utf-8", errors="replace")[: args.max_inline],
    }
    print(json.dumps(info, ensure_ascii=False))
    return 0


def cmd_tls_fingerprint(args):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((args.host, args.port), timeout=args.timeout) as raw:
        with context.wrap_socket(raw, server_hostname=args.server_name or args.host) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise SystemExit("TLS 握手没有拿到服务端证书")
    print(hashlib.sha256(der).hexdigest())
    return 0


def cmd_flood(args):
    sockets = []
    try:
        for _ in range(args.count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(args.connect_timeout)
            try:
                if args.source:
                    sock.bind((args.source, 0))
                sock.connect((args.host, args.port))
                sockets.append(sock)
            except OSError:
                sock.close()
        print(json.dumps({"opened": len(sockets)}), flush=True)
        time.sleep(args.hold)
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    http = sub.add_parser("http")
    http.add_argument("--url", required=True)
    http.add_argument("--method", default="GET")
    http.add_argument("--header", action="append", default=[])
    http.add_argument("--data", default=None)
    http.add_argument("--cookie-file", default=None)
    http.add_argument("--bearer-env", action="store_true")
    http.add_argument("--timeout", type=float, default=5.0)
    http.add_argument("--max-body", type=int, default=8 * 1024 * 1024)
    http.add_argument("--max-inline", type=int, default=2000)
    http.set_defaults(func=cmd_http)

    tls = sub.add_parser("tls-fingerprint")
    tls.add_argument("--host", required=True)
    tls.add_argument("--port", type=int, required=True)
    tls.add_argument("--server-name", default=None)
    tls.add_argument("--timeout", type=float, default=5.0)
    tls.set_defaults(func=cmd_tls_fingerprint)

    flood = sub.add_parser("flood")
    flood.add_argument("--host", required=True)
    flood.add_argument("--port", type=int, required=True)
    flood.add_argument("--source", default=None)
    flood.add_argument("--count", type=int, default=32)
    flood.add_argument("--hold", type=float, default=10.0)
    flood.add_argument("--connect-timeout", type=float, default=2.0)
    flood.set_defaults(func=cmd_flood)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
