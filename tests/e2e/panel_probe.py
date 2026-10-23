#!/usr/bin/env python3
"""RustBoard M2 面板端到端测试用 HTTP 客户端（仅 Python 标准库）。

供 `tests/e2e/panel.sh` 驱动，负责：
  * 发送原始 HTTP 请求（可保留 `..` / `%2e%2e` 路径，便于测试静态路径穿越）；
  * 读取状态码、Content-Type、Set-Cookie 与 JSON 响应；
  * 解析 / 校验 overview、series、settings 的契约形状；
  * 保存响应体供 bash 侧做脱敏扫描，但**不打印**会话 Cookie、密码或 token。

不依赖 curl / jq / requests，也不访问外网。

用法见 `python3 tests/e2e/panel_probe.py <subcommand> --help`。
"""

from __future__ import annotations

import argparse
import http.client
import ipaddress
import json
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

# 方案 §3.1 允许的服务端自动降采样档位（毫秒）。
ALLOWED_BUCKETS = {
    1_000,
    5_000,
    10_000,
    30_000,
    60_000,
    300_000,
    900_000,
    3_600_000,
    21_600_000,
    43_200_000,
    86_400_000,
}


class ProbeError(Exception):
    """可预期的测试失败（参数、网络、JSON 形状）。"""


# ---------------------------------------------------------------------------
# HTTP 基础
# ---------------------------------------------------------------------------


def _split_url(url: str):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http":
        raise ProbeError(f"只支持 http://（面板 M2 不提供 HTTPS），收到 {url}")
    host = parts.hostname
    if not host:
        raise ProbeError(f"URL 缺少主机名: {url}")
    port = parts.port or 80
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return host, port, path


def _parse_header_args(raw_headers):
    headers = []
    for item in raw_headers:
        if ":" not in item:
            raise ProbeError(f"--header 需要 'Name: value' 形式，收到 {item!r}")
        name, value = item.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return headers


def _bearer_header():
    token = os.environ.get("RB_E2E_ADMIN_TOKEN", "")
    if not token:
        raise ProbeError("环境变量 RB_E2E_ADMIN_TOKEN 为空")
    return ("Authorization", "Bearer " + token)


def _read_cookie_file(path):
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            cookie = handle.readline().strip()
    except OSError as exc:
        raise ProbeError(f"读取 Cookie 文件失败: {exc}") from exc
    if not cookie:
        raise ProbeError("Cookie 文件为空")
    if not cookie.startswith("rb_session="):
        raise ProbeError("Cookie 文件不是 rb_session=... 格式")
    return cookie


def _write_private_file(path: str, data: bytes) -> None:
    tmp = path + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _source_address(raw):
    """把 --source-ip 转成 http.client 的 source_address 元组；空值保持默认行为。"""
    if not raw:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ProbeError(f"--source-ip 不是合法 IP 地址: {raw!r}") from exc
    if address.version != 4:
        raise ProbeError("--source-ip 目前只支持 IPv4")
    return (str(address), 0)


def _request(url, method, headers, body, timeout, raw_path=None, source_address=None):
    host, port, path = _split_url(url)
    if raw_path is not None:
        if not raw_path.startswith("/"):
            raise ProbeError(f"--raw-path 必须以 / 开头: {raw_path!r}")
        path = raw_path

    connection = http.client.HTTPConnection(
        host, port, timeout=timeout, source_address=source_address
    )
    try:
        connection.putrequest(
            method, path, skip_accept_encoding=True, skip_host=False
        )
        for name, value in headers:
            connection.putheader(name, value)
        if body is not None:
            connection.putheader("Content-Length", str(len(body)))
        connection.putheader("Connection", "close")
        connection.endheaders()
        if body:
            connection.send(body)
        response = connection.getresponse()
        data = response.read()
        return response, data
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise ProbeError(f"请求 {method} {url} 失败: {exc}") from exc
    finally:
        connection.close()


def _content_type_base(value: str) -> str:
    return (value or "").split(";", 1)[0].strip().lower()


def _json_shape(data: bytes):
    text = data.decode("utf-8", errors="replace")
    stripped = text.strip()
    if not stripped:
        return False, "", ""
    try:
        parsed = json.loads(stripped)
    except Exception:
        return False, "", ""
    if isinstance(parsed, list):
        kind = "list"
    elif isinstance(parsed, dict):
        kind = "dict"
    elif isinstance(parsed, bool):
        kind = "bool"
    elif parsed is None:
        kind = "null"
    elif isinstance(parsed, (int, float)):
        kind = "number"
    else:
        kind = "string"
    error = ""
    if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
        error = parsed["error"]
    return True, kind, error


def _response_info(response, data, include_body=False, max_inline=4000):
    content_type = response.getheader("Content-Type") or ""
    json_ok, json_kind, json_error = _json_shape(data)
    info = {
        "status": response.status,
        "reason": response.reason,
        "content_type": content_type,
        "content_type_base": _content_type_base(content_type),
        "cache_control": response.getheader("Cache-Control") or "",
        "csp": response.getheader("Content-Security-Policy") or "",
        "set_cookie_count": len(response.msg.get_all("Set-Cookie") or []),
        "body_len": len(data),
        "json_ok": json_ok,
        "json_type": json_kind,
        "json_error": json_error,
    }
    if include_body:
        text = data.decode("utf-8", errors="replace")
        info["body"] = text[:max_inline]
    return info


def _set_cookies(response):
    cookies = []
    for raw in response.msg.get_all("Set-Cookie") or []:
        parsed = _parse_set_cookie(raw)
        if parsed:
            cookies.append(parsed)
    return cookies


def _parse_set_cookie(raw: str):
    parts = [part.strip() for part in raw.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, value = parts[0].split("=", 1)
    attrs = {}
    for part in parts[1:]:
        if not part:
            continue
        if "=" in part:
            key, attr_value = part.split("=", 1)
            attrs[key.strip().lower()] = attr_value.strip()
        else:
            attrs[part.strip().lower()] = ""
    return {"name": name.strip(), "value": value.strip(), "attrs": attrs}


def _find_session_cookie(cookies):
    for cookie in cookies:
        if cookie["name"] == "rb_session":
            return cookie
    return None


def _expired(attrs) -> bool:
    expires = attrs.get("expires", "")
    if not expires:
        return False
    try:
        moment = parsedate_to_datetime(expires)
    except Exception:
        return "1970" in expires
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment <= datetime.now(timezone.utc)


def _session_cookie_info(cookie):
    if not cookie:
        return {
            "cookie_name": "",
            "cookie_value_len": 0,
            "http_only": False,
            "same_site": "",
            "path": "",
            "secure": False,
            "max_age": "",
            "expires": "",
        }
    attrs = cookie["attrs"]
    return {
        "cookie_name": cookie["name"],
        "cookie_value_len": len(cookie["value"]),
        "http_only": "httponly" in attrs,
        "same_site": attrs.get("samesite", ""),
        "path": attrs.get("path", ""),
        "secure": "secure" in attrs,
        "max_age": attrs.get("max-age", ""),
        "expires": attrs.get("expires", ""),
    }


def _add_common_http_args(parser, body=False, raw_path=False):
    parser.add_argument("--url", required=True, help="完整 HTTP URL")
    parser.add_argument("--method", default="GET", help="HTTP 方法，默认 GET")
    parser.add_argument("--header", action="append", default=[],
                        help="额外请求头，可重复：'Name: value'")
    parser.add_argument("--cookie-file", default=None,
                        help="从文件读取 rb_session Cookie 并发送")
    parser.add_argument("--bearer-env", action="store_true",
                        help="从 RB_E2E_ADMIN_TOKEN 读取 hub Bearer token")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--max-body", type=int, default=8 * 1024 * 1024)
    parser.add_argument("--body-out", default=None,
                        help="把响应体写入该文件（0600）")
    if body:
        parser.add_argument("--data", default=None, help="请求体字符串")
        parser.add_argument("--include-body", action="store_true",
                            help="在 JSON 输出里带上响应体（调试用）")
    if raw_path:
        parser.add_argument("--raw-path", default=None,
                            help="原样发送的路径，用于 .. / %%2e%%2e 穿越测试")


def _request_from_args(args, body=None, extra_headers=None):
    headers = _parse_header_args(getattr(args, "header", []))
    if getattr(args, "bearer_env", False):
        headers.append(_bearer_header())
    cookie = _read_cookie_file(getattr(args, "cookie_file", None))
    if cookie:
        headers.append(("Cookie", cookie))
    if extra_headers:
        headers.extend(extra_headers)
    return _request(
        args.url,
        getattr(args, "method", "GET").upper(),
        headers,
        body,
        args.timeout,
        raw_path=getattr(args, "raw_path", None),
    )


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------


def cmd_http(args) -> int:
    body = None
    if args.data is not None:
        body = args.data.encode("utf-8")
    response, data = _request_from_args(args, body=body)
    if len(data) > args.max_body:
        raise ProbeError(f"响应体过大（{len(data)} > {args.max_body}）")
    if args.body_out:
        _write_private_file(args.body_out, data)
    info = _response_info(response, data, include_body=args.include_body)
    if args.body_out:
        info["body_out"] = args.body_out
    print(json.dumps(info, ensure_ascii=False))
    return 0


def cmd_login(args) -> int:
    password = args.password
    if args.password_env:
        password = os.environ.get(args.password_env, "")
    if password is None:
        raise ProbeError("必须提供 --password 或 --password-env")

    headers = [
        ("Content-Type", "application/json"),
        ("Accept", "application/json"),
    ]
    headers.extend(_parse_header_args(args.header))
    body = json.dumps({"password": password}).encode("utf-8")
    response, data = _request(
        args.url,
        "POST",
        headers,
        body,
        args.timeout,
        source_address=_source_address(args.source_ip),
    )
    if len(data) > args.max_body:
        raise ProbeError(f"响应体过大（{len(data)} > {args.max_body}）")

    cookies = _set_cookies(response)
    session = _find_session_cookie(cookies)
    info = _response_info(response, data, include_body=True, max_inline=1000)
    info.update(_session_cookie_info(session))
    info["set_cookie_count"] = len(cookies)
    info["cookie_saved"] = False

    if session and args.cookie_out:
        _write_private_file(
            args.cookie_out,
            f"{session['name']}={session['value']}\n".encode("utf-8"),
        )
        info["cookie_saved"] = True

    # 永远不回显 Cookie 值本身。
    print(json.dumps(info, ensure_ascii=False))
    return 0


def cmd_logout(args) -> int:
    # 面板把变更类请求约束为 application/json（方案 §3.2）；登出也按此发送空对象。
    response, data = _request_from_args(
        args,
        body=b"{}",
        extra_headers=[("Content-Type", "application/json")],
    )
    if len(data) > args.max_body:
        raise ProbeError(f"响应体过大（{len(data)} > {args.max_body}）")
    cookies = _set_cookies(response)
    session = _find_session_cookie(cookies)
    attrs = session["attrs"] if session else {}
    cleared = bool(
        session
        and (
            session["value"] == ""
            or attrs.get("max-age", "") == "0"
            or _expired(attrs)
        )
    )
    info = _response_info(response, data, include_body=True, max_inline=1000)
    info.update(_session_cookie_info(session))
    info["cleared"] = cleared
    print(json.dumps(info, ensure_ascii=False))
    return 0


def cmd_session(args) -> int:
    response, data = _request_from_args(args, body=None)
    if len(data) > args.max_body:
        raise ProbeError(f"响应体过大（{len(data)} > {args.max_body}）")
    info = _response_info(response, data, include_body=True, max_inline=1000)
    authenticated = None
    if info["json_ok"] and info["json_type"] == "dict":
        try:
            payload = json.loads(data.decode("utf-8"))
        except Exception:
            payload = {}
        value = payload.get("authenticated")
        if isinstance(value, bool):
            authenticated = value
    info["authenticated"] = authenticated
    if args.body_out:
        _write_private_file(args.body_out, data)
        info["body_out"] = args.body_out
    print(json.dumps(info, ensure_ascii=False))
    return 0


def _agent_status(agents, agent_id):
    for agent in agents:
        if isinstance(agent, dict) and agent.get("agent_id") == agent_id:
            return True, agent.get("status", "unknown")
    return False, "absent"


def cmd_overview(args) -> int:
    response, data = _request_from_args(args, body=None)
    if len(data) > args.max_body:
        raise ProbeError(f"响应体过大（{len(data)} > {args.max_body}）")
    if args.body_out:
        _write_private_file(args.body_out, data)

    info = _response_info(response, data)
    info.update({
        "keys": [],
        "has_server_time": False,
        "server_time_number": False,
        "agents_is_list": False,
        "latest_is_list": False,
        "settings_is_list": False,
        "agent_present": False,
        "agent_status": "absent",
        "latest_metrics": [],
        "latest_count": 0,
        "latest_has_cpu": False,
        "latest_has_mem": False,
        "settings_count": 0,
        "settings_map": {},
        "agent_interval": None,
    })

    if not info["json_ok"] or info["json_type"] != "dict":
        print(json.dumps(info, ensure_ascii=False))
        return 0
    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ProbeError(f"解析 overview JSON 失败: {exc}") from exc

    info["keys"] = sorted(payload.keys())
    info["has_server_time"] = "server_time" in payload
    server_time = payload.get("server_time")
    info["server_time_number"] = (
        isinstance(server_time, (int, float)) and not isinstance(server_time, bool)
    )
    agents = payload.get("agents")
    latest = payload.get("latest")
    settings = payload.get("settings")
    info["agents_is_list"] = isinstance(agents, list)
    info["latest_is_list"] = isinstance(latest, list)
    info["settings_is_list"] = isinstance(settings, list)

    if isinstance(agents, list):
        present, status = _agent_status(agents, args.agent or "")
        info["agent_present"] = present
        info["agent_status"] = status

    metrics = set()
    latest_count = 0
    if isinstance(latest, list):
        for row in latest:
            if not isinstance(row, dict):
                continue
            if args.agent and row.get("agent_id") != args.agent:
                continue
            latest_count += 1
            metric = row.get("metric")
            if isinstance(metric, str):
                metrics.add(metric)
    info["latest_metrics"] = sorted(metrics)
    info["latest_count"] = latest_count
    info["latest_has_cpu"] = "cpu.usage" in metrics
    info["latest_has_mem"] = "mem.used" in metrics

    settings_map = {}
    if isinstance(settings, list):
        for row in settings:
            if not isinstance(row, dict):
                continue
            agent_id = row.get("agent_id")
            interval = row.get("sample_interval_ms")
            if isinstance(agent_id, str) and isinstance(interval, int) \
                    and not isinstance(interval, bool):
                settings_map[agent_id] = interval
    info["settings_count"] = len(settings_map)
    info["settings_map"] = settings_map
    if args.agent:
        info["agent_interval"] = settings_map.get(args.agent)

    print(json.dumps(info, ensure_ascii=False))
    return 0


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def cmd_series(args) -> int:
    response, data = _request_from_args(args, body=None)
    if len(data) > args.max_body:
        raise ProbeError(f"响应体过大（{len(data)} > {args.max_body}）")
    if args.body_out:
        _write_private_file(args.body_out, data)

    info = _response_info(response, data)
    info.update({
        "bucket_ms": None,
        "bucket_positive": False,
        "bucket_allowed": False,
        "series_count": 0,
        "metrics": [],
        "curves": [],
        "missing_metrics": list(args.metric),
        "missing_count": len(args.metric),
        "max_points_per_curve": 0,
        "total_points": 0,
        "bad_points": 0,
        "shape_ok": False,
        "ts_monotonic": True,
    })

    if not info["json_ok"] or info["json_type"] != "dict":
        print(json.dumps(info, ensure_ascii=False))
        return 0
    try:
        payload = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise ProbeError(f"解析 series JSON 失败: {exc}") from exc

    bucket = payload.get("bucket_ms")
    info["bucket_ms"] = bucket
    info["bucket_positive"] = _number(bucket) and bucket > 0
    info["bucket_allowed"] = info["bucket_positive"] and int(bucket) in ALLOWED_BUCKETS

    series = payload.get("series")
    shape_ok = isinstance(series, list) and info["bucket_positive"]
    metrics = []
    curves = []
    total_points = 0
    max_points = 0
    bad_points = 0
    ts_monotonic = True

    if isinstance(series, list):
        for entry in series:
            if not isinstance(entry, dict):
                shape_ok = False
                continue
            metric = entry.get("metric")
            labels = entry.get("labels")
            points = entry.get("points")
            if not isinstance(metric, str) or not isinstance(labels, dict) \
                    or not isinstance(points, list):
                shape_ok = False
                continue
            metrics.append(metric)
            last_ts = None
            for point in points:
                if not isinstance(point, (list, tuple)) or len(point) != 2:
                    bad_points += 1
                    shape_ok = False
                    continue
                ts, value = point
                if not _number(ts) or not _number(value):
                    bad_points += 1
                    shape_ok = False
                    continue
                if last_ts is not None and ts < last_ts:
                    ts_monotonic = False
                last_ts = ts
            count = len(points)
            total_points += count
            max_points = max(max_points, count)
            curves.append({
                "metric": metric,
                "labels": labels,
                "points": count,
            })

    expected = list(args.metric)
    missing = [metric for metric in expected if metric not in metrics]
    info.update({
        "series_count": len(series) if isinstance(series, list) else 0,
        "metrics": metrics,
        "curves": curves,
        "missing_metrics": missing,
        "missing_count": len(missing),
        "max_points_per_curve": max_points,
        "total_points": total_points,
        "bad_points": bad_points,
        "shape_ok": bool(shape_ok and bad_points == 0),
        "ts_monotonic": ts_monotonic,
    })
    print(json.dumps(info, ensure_ascii=False))
    return 0


def cmd_agents_status(args) -> int:
    headers = []
    if os.environ.get("RB_E2E_ADMIN_TOKEN"):
        headers.append(_bearer_header())
    response, data = _request(args.url, "GET", headers, None, args.timeout)
    if response.status != 200:
        print(f"http_{response.status}")
        return 1
    try:
        agents = json.loads(data.decode("utf-8"))
    except Exception:
        print("invalid_json")
        return 1
    if not isinstance(agents, list):
        print("invalid_shape")
        return 1
    present, status = _agent_status(agents, args.agent)
    print(status if present else "absent")
    return 0


def cmd_json_get(args) -> int:
    try:
        with open(args.file, encoding="utf-8") as handle:
            value = json.load(handle)
    except Exception as exc:
        print(f"__INVALID__:{exc}")
        return 0
    for part in args.key.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            print("__MISSING__")
            return 0
    if isinstance(value, bool):
        print("true" if value else "false")
    elif value is None:
        print("null")
    elif isinstance(value, (dict, list)):
        print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    else:
        print(value)
    return 0


def cmd_assets(args) -> int:
    try:
        with open(args.html, encoding="utf-8", errors="replace") as handle:
            html = handle.read()
    except OSError as exc:
        raise ProbeError(f"读取 HTML 失败: {exc}") from exc

    base = args.base
    if not base.endswith("/"):
        base += "/"
    base_parts = urllib.parse.urlsplit(base)
    refs = re.findall(
        r"""(?:src|href)\s*=\s*["']([^"']+)["']""", html, flags=re.IGNORECASE
    )
    seen = set()
    for ref in refs:
        lowered = ref.strip().lower()
        if not lowered or lowered.startswith(("#", "data:", "mailto:", "javascript:")):
            continue
        absolute = urllib.parse.urljoin(base, ref.strip())
        parts = urllib.parse.urlsplit(absolute)
        if parts.scheme != base_parts.scheme or parts.netloc != base_parts.netloc:
            continue
        if not parts.path.lower().endswith((".js", ".css")):
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        print(absolute)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="RustBoard 面板 e2e 测试客户端")
    sub = parser.add_subparsers(dest="cmd", required=True)

    http_parser = sub.add_parser("http", help="发送任意 HTTP 请求并输出响应元数据")
    _add_common_http_args(http_parser, body=True, raw_path=True)
    http_parser.set_defaults(func=cmd_http)

    login = sub.add_parser("login", help="POST /api/login 并解析会话 Cookie 属性")
    login.add_argument("--url", required=True)
    password_group = login.add_mutually_exclusive_group(required=True)
    password_group.add_argument("--password", default=None)
    password_group.add_argument("--password-env", default=None)
    login.add_argument("--header", action="append", default=[])
    login.add_argument("--cookie-out", default=None,
                       help="把 rb_session Cookie 写入该文件（0600）")
    login.add_argument("--source-ip", default=None,
                       help="绑定 IPv4 源地址（如 127.0.0.2，用于模拟非可信直连来源）")
    login.add_argument("--timeout", type=float, default=5.0)
    login.add_argument("--max-body", type=int, default=8 * 1024 * 1024)
    login.set_defaults(func=cmd_login)

    logout = sub.add_parser("logout", help="POST /api/logout 并判断是否清除 Cookie")
    logout.add_argument("--url", required=True)
    logout.add_argument("--method", default="POST")
    logout.add_argument("--cookie-file", default=None)
    logout.add_argument("--timeout", type=float, default=5.0)
    logout.add_argument("--max-body", type=int, default=8 * 1024 * 1024)
    logout.set_defaults(func=cmd_logout)

    session = sub.add_parser("session", help="GET /api/session 并读取 authenticated")
    session.add_argument("--url", required=True)
    session.add_argument("--cookie-file", default=None)
    session.add_argument("--timeout", type=float, default=5.0)
    session.add_argument("--max-body", type=int, default=8 * 1024 * 1024)
    session.add_argument("--body-out", default=None)
    session.set_defaults(func=cmd_session)

    overview = sub.add_parser("overview", help="GET overview 并校验键与类型")
    overview.add_argument("--url", required=True)
    overview.add_argument("--cookie-file", default=None)
    overview.add_argument("--bearer-env", action="store_true")
    overview.add_argument("--agent", default=None, help="关注某台 agent_id")
    overview.add_argument("--timeout", type=float, default=5.0)
    overview.add_argument("--max-body", type=int, default=8 * 1024 * 1024)
    overview.add_argument("--body-out", default=None)
    overview.set_defaults(func=cmd_overview)

    series = sub.add_parser("series", help="GET series 并校验 bucket 与 points 形状")
    series.add_argument("--url", required=True)
    series.add_argument("--cookie-file", default=None)
    series.add_argument("--bearer-env", action="store_true")
    series.add_argument("--metric", action="append", default=[],
                        help="期望返回的 metric，可重复")
    series.add_argument("--timeout", type=float, default=5.0)
    series.add_argument("--max-body", type=int, default=8 * 1024 * 1024)
    series.add_argument("--body-out", default=None)
    series.set_defaults(func=cmd_series)

    agents = sub.add_parser("agents-status", help="读取 hub /api/v1/agents 中某 agent 状态")
    agents.add_argument("--url", required=True)
    agents.add_argument("--agent", required=True)
    agents.add_argument("--timeout", type=float, default=3.0)
    agents.set_defaults(func=cmd_agents_status)

    json_get = sub.add_parser("json-get", help="从 JSON 文件读取顶层键（测试用）")
    json_get.add_argument("--file", required=True)
    json_get.add_argument("--key", required=True)
    json_get.set_defaults(func=cmd_json_get)

    assets = sub.add_parser("assets", help="从 HTML 提取同源 JS/CSS 资源 URL")
    assets.add_argument("--html", required=True)
    assets.add_argument("--base", required=True)
    assets.set_defaults(func=cmd_assets)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.func(args)
    except (ProbeError, OSError) as exc:
        print(f"FAIL {args.cmd}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
