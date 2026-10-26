#!/usr/bin/env python3
"""Phase E S2：hub 级多 agent 负载与长稳工具。

用真实 hub（默认 SQLite）+ 真实 TLS Enrollment / Hello / Batch / ACK 驱动
N 个虚拟 agent，采集 ACK 分位数、吞吐、hub 资源与数据库一致性，输出
``metrics.jsonl`` 与 ``summary.json``。

设计约束：

- 只依赖 Python 标准库 + ``openssl`` 命令行；TLS / WebSocket / MessagePack
  编解码复用 ``tests/e2e/probe.py``，不复制协议实现。
- token 只在内存中短暂存在；agent_secret / 证书内容绝不打印。测试私钥与
  agent 证书写在 0700 工作目录、证书 0600，结束后整体删除。
- 任何失败都要写出 summary 并以非零码退出，便于保留证据。

本文件不修改生产代码、协议或数据库 schema。
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import socket
import sqlite3
import ssl
import stat
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# 复用 e2e 的最小 TLS/WebSocket/MessagePack 客户端；按任务约定不复制大段编解码。
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "e2e"))
import probe  # noqa: E402

AGENT_METRICS = ("load.cpu", "load.mem", "load.disk")
EPOCH = 1
PROTOCOL_VERSION = 2
DEFAULT_SOURCE_PER_IP = 200
SOURCE_IP_PREFIX = "127.0.0."
SC_CLK_TCK = os.sysconf("SC_CLK_TCK")
ERROR_SAMPLE_LIMIT = 50
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_PEM_RE = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.S)
_LOG_ERROR_RE = re.compile(r"panicked|(?:^|[^A-Za-z_])ERROR(?:[^A-Za-z_]|$)")


class ScaleError(Exception):
    """可预期的压测失败（连接、协议、配置、校验）。"""


class ConnectionDropped(ScaleError):
    """连接在等待 ACK 期间被关闭。"""


class AckTimeout(ScaleError):
    """等待匹配 ACK 超时。"""


class HubProblem(ScaleError):
    """hub 返回应用层 Problem 帧。"""


def redact(value, limit: int = 300) -> str:
    """把异常/错误串里的 token、私钥、证书等内容去掉，并限制长度。"""
    text = _PEM_RE.sub("[pem]", str(value))
    text = _HEX_RE.sub("[hex]", text)
    text = text.replace("\r", " ").replace("\n", " ")
    return text[:limit]


def exc_text(exc: BaseException) -> str:
    return redact(f"{type(exc).__name__}: {exc}")


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def percentile(values, p: float):
    """线性插值分位数；空列表返回 None。"""
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p / 100.0
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def median_or_none(values):
    return statistics.median(values) if values else None


def percentile_sorted(ordered: list[float], p: float):
    """已排序列表的分位数，避免长稳跑里重复排序。"""
    if not ordered:
        return None
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * p / 100.0
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[low]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


# ---------------------------------------------------------------------------
# 参数与运行上下文
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="RustBoard Phase E S2 hub 级负载 / 长稳工具",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--agents", type=int, required=True, help="虚拟 agent 数")
    parser.add_argument("--duration-secs", type=int, required=True, help="barrier 后统一运行秒数")
    parser.add_argument("--interval-ms", type=int, default=5000, help="每 agent 发批间隔")
    parser.add_argument(
        "--warmup-secs",
        type=int,
        default=60,
        help="资源基线预热秒数（短档 60；24h 建议 600）",
    )
    parser.add_argument("--hub-bin", required=True, help="rustboard-hub 可执行文件")
    parser.add_argument("--config", required=True, help="hub 配置文件（用于 agent add）")
    parser.add_argument("--hub-pid", type=int, required=True, help="已启动 hub 的 PID")
    parser.add_argument(
        "--hub-starttime",
        default="",
        help="/proc/<pid>/stat 的 starttime；用于证明 hub 未重启",
    )
    parser.add_argument("--ca", required=True, help="hub CA 证书路径")
    parser.add_argument("--agent-url", required=True, help="wss://host:port/agent/ws")
    parser.add_argument("--admin-url", required=True, help="管理 API 根地址，如 http://127.0.0.1:9000")
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument(
        "--admin-token-file",
        default="",
        help="0600 文件路径；读取后立即删除，token 不进入 argv",
    )
    token_group.add_argument(
        "--admin-token-env",
        default="",
        help="环境变量名；token 不进入 argv（与 --admin-token-file 二选一）",
    )
    parser.add_argument("--db", default="", help="SQLite 数据库路径（--backend sqlite 必填）")
    parser.add_argument("--backend", choices=("sqlite", "postgres"), default="sqlite")
    parser.add_argument("--out-dir", required=True, help="证据目录（metrics.jsonl / summary.json）")
    parser.add_argument("--hub-log", default="", help="hub.log；结束时扫描 panicked/ERROR")
    parser.add_argument(
        "--reconnect-every",
        type=int,
        default=0,
        help="前 10% agent 每 ACK N 批主动断连重连；0 表示不主动断",
    )
    parser.add_argument(
        "--source-ip-per",
        type=int,
        default=DEFAULT_SOURCE_PER_IP,
        help="每个回环源 IP 最多 agent 数（必须 < hub max_connections_per_ip）",
    )
    parser.add_argument("--thread-stack-kib", type=int, default=512, help="会话线程栈大小")
    parser.add_argument("--barrier-timeout", type=float, default=40.0, help="barrier 超时秒数")
    parser.add_argument("--connect-attempts", type=int, default=5, help="建立会话重试次数")
    parser.add_argument("--batch-attempts", type=int, default=5, help="单批 ACK 失败后的最大尝试次数")
    parser.add_argument("--enroll-attempts", type=int, default=3, help="单 agent enrollment 尝试次数")
    parser.add_argument("--connect-timeout", type=float, default=10.0, help="会话建连/IO 基础超时")
    parser.add_argument("--hello-timeout", type=float, default=15.0, help="Hello→Welcome 超时")
    parser.add_argument("--enroll-timeout", type=float, default=30.0, help="Enrollment 超时")
    parser.add_argument("--health-timeout", type=float, default=3.0, help="healthz 请求超时")
    parser.add_argument("--db-stabilize-secs", type=float, default=10.0, help="等待 SQLite 计数稳定上限")
    return parser


@dataclass
class RunContext:
    args: argparse.Namespace
    out_dir: Path
    work_dir: Path
    metrics_path: Path
    summary_path: Path
    key_path: Path
    source_ips: list[str]
    per_agent_slots: int
    scheduled_batches: int
    hub_starttime: str
    stats: "Stats"
    identities: list["AgentIdentity"] = field(default_factory=list)
    states: list["AgentState"] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    join_timeouts: list[int] = field(default_factory=list)
    run_started: bool = False
    run_start: float = 0.0
    wall_start: str = ""
    prep_started: float = 0.0
    prep_secs: float = 0.0
    barrier_secs: float = 0.0
    start_gate: threading.Event = field(default_factory=threading.Event)
    stop_event: threading.Event = field(default_factory=threading.Event)
    token_sem: threading.Semaphore = field(default_factory=lambda: threading.Semaphore(4))
    reconnect_agents: int = 0
    # 管理 token 只驻留内存；repr=False 避免调试打印上下文时意外泄露。
    admin_token: str = field(default="", repr=False)
    hub_restarted: bool = False
    hub_alive_end: bool = False
    starttime_end: str = ""
    monitor_errors: int = 0
    db_result: dict | None = None
    admin_result: dict | None = None
    hub_log_result: dict | None = None
    finished_at: str = ""


class Stats:
    """跨线程累计计数器；采样线程每秒读一次快照。"""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.sent = 0
        self.acked = 0
        self.retries = 0
        self.reconnects = 0
        self.errors = 0
        self.ack_ms: list[float] = []
        self.error_samples: list[dict] = []

    def add_sent(self) -> None:
        with self.lock:
            self.sent += 1

    def add_acked(self, latency_ms: float) -> None:
        with self.lock:
            self.acked += 1
            self.ack_ms.append(latency_ms)

    def add_retry(self) -> None:
        with self.lock:
            self.retries += 1

    def add_reconnect(self) -> None:
        with self.lock:
            self.reconnects += 1

    def add_error(self, agent_index: int, kind: str, message: str) -> None:
        message = redact(message)
        with self.lock:
            self.errors += 1
            if len(self.error_samples) < ERROR_SAMPLE_LIMIT:
                self.error_samples.append(
                    {"agent": agent_index, "kind": kind, "message": message}
                )

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "sent": self.sent,
                "acked": self.acked,
                "retries": self.retries,
                "reconnects": self.reconnects,
                "errors": self.errors,
                "ack_ms": list(self.ack_ms),
                "error_samples": list(self.error_samples),
            }


@dataclass
class AgentIdentity:
    index: int
    name: str
    agent_id: str
    secret: str
    cert_path: Path
    source_ip: str


class AgentState:
    """单个 agent 的本地状态；连接线程独占写入，join 后由主线程读取。"""

    __slots__ = (
        "identity",
        "sent",
        "acked",
        "retries",
        "reconnects",
        "errors",
        "last_ts",
    )

    def __init__(self, identity: AgentIdentity) -> None:
        self.identity = identity
        self.sent = 0
        self.acked = 0
        self.retries = 0
        self.reconnects = 0
        self.errors = 0
        self.last_ts = 0


# ---------------------------------------------------------------------------
# 通用 IO / 进程工具
# ---------------------------------------------------------------------------


def read_proc_stat(pid: int) -> dict | None:
    """解析 /proc/<pid>/stat 的 utime/stime/starttime/threads。"""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    # comm 可能含空格和右括号，必须从最后一个 ')' 之后切分。
    try:
        rest = raw.rsplit(")", 1)[1].split()
    except IndexError:
        return None
    if len(rest) < 20:
        return None
    # rest[0] 是 field 3（state）；field N 对应 rest[N-3]。
    return {
        "utime_ticks": int(rest[11]),
        "stime_ticks": int(rest[12]),
        "threads": int(rest[17]),
        "starttime": rest[19],
    }


def read_proc_status(pid: int) -> dict:
    values = {"rss_kb": None, "threads": None}
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return values
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    values["rss_kb"] = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith("Threads:"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    values["threads"] = int(parts[1])
                except ValueError:
                    pass
    return values


def count_fds(pid: int) -> int | None:
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except OSError:
        return 0


def http_get(url: str, headers: dict | None = None, timeout: float = 3.0):
    """返回 (status, body, latency_ms, error)；不走环境代理。"""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers=headers or {})
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(8 * 1024 * 1024)
            return response.status, body, (time.monotonic() - started) * 1000.0, None
    except urllib.error.HTTPError as exc:
        return exc.code, b"", (time.monotonic() - started) * 1000.0, None
    except Exception as exc:  # noqa: BLE001 - 网络错误一律转成状态
        return None, b"", (time.monotonic() - started) * 1000.0, exc_text(exc)


# ---------------------------------------------------------------------------
# 身份准备：token / CSR / Enrollment
# ---------------------------------------------------------------------------


def parse_token(output: str) -> str | None:
    """从 `agent add` 输出里取“一次性 token”后的单独一行 64 hex。"""
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if "一次性 token" in line:
            for candidate in lines[index + 1 :]:
                candidate = candidate.strip()
                if re.fullmatch(r"[0-9a-f]{64}", candidate):
                    return candidate
    return None


def add_agent_token(ctx: RunContext, name: str) -> str:
    command = [
        str(ctx.args.hub_bin),
        "agent",
        "add",
        "--config",
        str(ctx.args.config),
        "--name",
        name,
    ]
    with ctx.token_sem:
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ScaleError(f"agent add 执行失败: {type(exc).__name__}") from None
    if proc.returncode != 0:
        # 不打印 stdout/stderr：里面可能含 token 与安装命令。
        raise ScaleError(f"agent add 失败（name={name}, rc={proc.returncode}，输出已隐藏）")
    token = parse_token(proc.stdout)
    if token is None:
        raise ScaleError(f"无法从 agent add 输出解析一次性 token（name={name}，输出已隐藏）")
    return token


def make_csr(ctx: RunContext, index: int) -> str:
    csr_path = ctx.work_dir / "csr" / f"{index}.pem"
    command = [
        "openssl",
        "req",
        "-new",
        "-sha256",
        "-key",
        str(ctx.key_path),
        "-subj",
        f"/CN=load-{index}",
        "-out",
        str(csr_path),
    ]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScaleError(f"openssl req 执行失败: {type(exc).__name__}") from None
    if proc.returncode != 0:
        raise ScaleError(f"openssl req 失败（agent {index}, rc={proc.returncode}）")
    try:
        return csr_path.read_text(encoding="utf-8")
    finally:
        try:
            csr_path.unlink()
        except OSError:
            pass


def recv_frame(ws, timeout: float):
    message = ws.recv_message(max(0.05, timeout))
    if message is None:
        raise ConnectionDropped("连接被对端关闭")
    opcode, payload = message
    if opcode != 0x2:
        raise ScaleError(f"期望二进制帧，收到 opcode={opcode}")
    return probe.decode_server_frame(payload)


def enroll_once(ctx: RunContext, index: int, token: str, csr_pem: str) -> AgentIdentity:
    name = f"load-{index}"
    ws = probe.WebSocket(
        ctx.args.agent_url,
        ctx.args.ca,
        None,
        None,
        timeout=ctx.args.enroll_timeout,
    )
    try:
        ws.send_binary(
            probe.pack(
                {
                    "Enroll": {
                        "token": token,
                        "csr_pem": csr_pem,
                        "requested_name": name,
                        "hostname": name,
                        "protocol": PROTOCOL_VERSION,
                    }
                }
            )
        )
        frame_name, body = recv_frame(ws, ctx.args.enroll_timeout)
    finally:
        try:
            ws.close()
        except Exception:  # noqa: BLE001 - 关闭失败不影响结论
            pass

    if frame_name == "Problem":
        code = redact(body.get("code", "unknown"), 64)
        raise HubProblem(f"enrollment 被拒绝（code={code}）")
    if frame_name != "Enrolled":
        raise ScaleError(f"enrollment 收到非预期帧 {redact(frame_name, 64)}")
    if not isinstance(body, dict):
        raise ScaleError("Enrolled 帧格式异常")
    agent_id = body.get("agent_id")
    secret = body.get("agent_secret")
    cert_pem = body.get("cert_pem")
    if not isinstance(agent_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", agent_id):
        raise ScaleError("Enrolled 未返回合法 agent_id（内容已隐藏）")
    if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-f]{64}", secret):
        raise ScaleError("Enrolled 未返回合法 agent_secret（内容已隐藏）")
    if not isinstance(cert_pem, str) or "-----BEGIN CERTIFICATE-----" not in cert_pem:
        raise ScaleError("Enrolled 未返回合法 cert_pem（内容已隐藏）")

    cert_path = ctx.work_dir / "certs" / f"{index}.pem"
    fd = os.open(cert_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(cert_pem)
    os.chmod(cert_path, 0o600)
    return AgentIdentity(
        index=index,
        name=name,
        agent_id=agent_id,
        secret=secret,
        cert_path=cert_path,
        source_ip="",
    )


def add_agent_token_with_retry(ctx: RunContext, name: str) -> str:
    last_error: BaseException | None = None
    for attempt in range(1, 4):
        try:
            return add_agent_token(ctx, name)
        except ScaleError as exc:
            last_error = exc
            if attempt < 3:
                time.sleep(0.2 * attempt)
    raise ScaleError(f"agent add 重试 3 次仍失败（name={name}）: {exc_text(last_error)}")


def prepare_one(ctx: RunContext, index: int) -> AgentIdentity:
    csr_pem = make_csr(ctx, index)
    last_error: BaseException | None = None
    attempts = max(1, ctx.args.enroll_attempts)
    for attempt in range(1, attempts + 1):
        token = add_agent_token_with_retry(ctx, f"load-{index}")
        try:
            return enroll_once(ctx, index, token, csr_pem)
        except (OSError, socket.timeout, ssl.SSLError, probe.ProbeError, ScaleError) as exc:
            last_error = exc
            if attempt >= attempts:
                break
            time.sleep(min(4.0, 0.25 * (2 ** (attempt - 1))))
    raise ScaleError(
        f"agent {index} enrollment 失败（{attempts} 次）: {exc_text(last_error)}"
    )


def prepare_agents(ctx: RunContext) -> list[AgentIdentity]:
    """串行准备身份。

    身份准备会同时写 SQLite（`agent add` 与 hub 的 Enrollment 都写），并发执行
    会撞上 SQLite 的写锁（实测 200 agent 时出现 `database is locked`，hub 因此
    关闭 Enrollment 连接）。准备阶段不计入 duration，串行换取确定性。
    """
    count = ctx.args.agents
    identities = [prepare_one(ctx, index) for index in range(count)]
    ip_count = len(ctx.source_ips)
    for identity in identities:
        # 轮询分配：既满足每 IP ≤ per_ip，也让“前 10% 重连 agent”分散在多个
        # 源 IP 上，避免主动重连时把单个 IP 的连接数推到 hub 上限。
        identity.source_ip = ctx.source_ips[identity.index % ip_count]
    return identities


def generate_key(ctx: RunContext) -> None:
    command = [
        "openssl",
        "genpkey",
        "-algorithm",
        "EC",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-out",
        str(ctx.key_path),
    ]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScaleError(f"openssl genpkey 执行失败: {type(exc).__name__}") from None
    if proc.returncode != 0 or not ctx.key_path.is_file():
        raise ScaleError(f"openssl genpkey 失败（rc={proc.returncode}）")
    os.chmod(ctx.key_path, 0o600)


# ---------------------------------------------------------------------------
# 会话 / Batch / ACK
# ---------------------------------------------------------------------------


def connect_session(ctx: RunContext, identity: AgentIdentity):
    attempts = max(1, ctx.args.connect_attempts)
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        ws = None
        try:
            ws = probe.WebSocket(
                ctx.args.agent_url,
                ctx.args.ca,
                str(identity.cert_path),
                str(ctx.key_path),
                timeout=ctx.args.connect_timeout,
                bind_ip=identity.source_ip,
            )
            ws.send_binary(probe.hello_frame(identity.agent_id, identity.secret))
            frame_name, body = recv_frame(ws, ctx.args.hello_timeout)
            if frame_name != "Welcome":
                if frame_name == "Problem":
                    code = redact(body.get("code", "unknown"), 64)
                    raise ScaleError(f"Hello 被拒绝（code={code}）")
                raise ScaleError(f"Hello 收到非预期帧 {redact(frame_name, 64)}")
            if not isinstance(body, dict) or body.get("agent_id") != identity.agent_id:
                raise ScaleError("Welcome 的 agent_id 与会话身份不一致")
            if body.get("protocol") != PROTOCOL_VERSION:
                raise ScaleError(f"Welcome 协议版本异常: {body.get('protocol')!r}")
            return ws
        except (OSError, socket.timeout, ssl.SSLError, probe.ProbeError, ScaleError) as exc:
            last_error = exc
            if ws is not None:
                try:
                    ws.close()
                except Exception:  # noqa: BLE001
                    pass
            if attempt < attempts:
                time.sleep(min(4.0, 0.25 * (2 ** (attempt - 1))))
    raise ScaleError(f"agent {identity.index} 建立会话失败（{attempts} 次）: {exc_text(last_error)}")


def reconnect_session(ctx: RunContext, state: AgentState) -> object:
    ws = connect_session(ctx, state.identity)
    state.reconnects += 1
    ctx.stats.add_reconnect()
    return ws


def build_batch(state: AgentState, seq: int) -> tuple[bytes, int, int]:
    identity = state.identity
    now_ms = int(time.time() * 1000)
    # ts 每批唯一；重发时复用同一帧，保证 hub 判重语义可验证。
    ts = max(now_ms, state.last_ts + 1)
    state.last_ts = ts
    sent_at = now_ms
    samples = [
        {
            "metric": metric,
            "labels": {},
            "ts": ts,
            "value": float(10 + (seq + offset) % 90),
        }
        for offset, metric in enumerate(AGENT_METRICS)
    ]
    frame = probe.pack(
        {
            "Batch": {
                "agent_id": identity.agent_id,
                "epoch": EPOCH,
                "seq": seq,
                "boot_id": f"load-boot-{identity.index}",
                "sent_at": sent_at,
                "samples": samples,
            }
        }
    )
    return frame, ts, sent_at


def send_and_wait_ack(
    ctx: RunContext,
    state: AgentState,
    ws,
    seq: int,
    frame: bytes,
    ack_timeout: float,
):
    """串行等待 epoch/seq 匹配的 ACK；异常时重连并重发同一批。"""
    attempts = max(1, ctx.args.batch_attempts)
    last_error: BaseException | None = None
    for attempt in range(1, attempts + 1):
        try:
            sent_mono = time.monotonic()
            ws.send_binary(frame)
            ack_deadline = sent_mono + ack_timeout
            while True:
                remaining = ack_deadline - time.monotonic()
                if remaining <= 0:
                    raise AckTimeout(f"seq={seq} 等待 ACK 超时（{ack_timeout:.1f}s）")
                frame_name, body = recv_frame(ws, remaining)
                if frame_name == "Ack":
                    if body.get("epoch") == EPOCH and body.get("seq") == seq:
                        return ws, (time.monotonic() - sent_mono) * 1000.0
                    raise ScaleError(
                        f"ACK 不匹配（期望 epoch={EPOCH} seq={seq}，"
                        f"收到 epoch={body.get('epoch')!r} seq={body.get('seq')!r}）"
                    )
                if frame_name == "Ping":
                    ws.send_binary(probe.pack({"Pong": {"ts": body.get("ts", 0)}}))
                    continue
                if frame_name == "Pong":
                    continue
                if frame_name == "Problem":
                    code = redact(body.get("code", "unknown"), 64)
                    ctx.stats.add_error(state.identity.index, "problem", f"Problem code={code}")
                    state.errors += 1
                    raise HubProblem(f"hub 返回 Problem（code={code}）")
                message = f"等待 ACK 时收到非预期帧 {redact(frame_name, 64)}"
                ctx.stats.add_error(state.identity.index, "unexpected_frame", message)
                state.errors += 1
                raise ScaleError(message)
        except (OSError, socket.timeout, ssl.SSLError, probe.ProbeError, ScaleError) as exc:
            last_error = exc
            if attempt >= attempts:
                raise ScaleError(
                    f"agent {state.identity.index} seq={seq} 重发 {attempts} 次仍失败: "
                    f"{exc_text(last_error)}"
                ) from None
            state.retries += 1
            ctx.stats.add_retry()
            # ACK 超时不代表旧连接已断；必须先关闭，避免同一 agent 留下两条
            # 会话并占用额外 FD / 单 IP 连接名额。
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
            ws = reconnect_session(ctx, state)
    raise ScaleError(f"agent {state.identity.index} seq={seq} 未取得 ACK")


def run_batches(ctx: RunContext, state: AgentState, ws):
    interval_s = ctx.args.interval_ms / 1000.0
    ack_timeout = max(5.0, 2.0 * interval_s)
    deadline = ctx.run_start + ctx.args.duration_secs
    seq = 0
    next_at = ctx.run_start
    while next_at < deadline:
        wait = next_at - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        if time.monotonic() >= deadline:
            break
        seq += 1
        frame, _ts, _sent_at = build_batch(state, seq)
        state.sent += 1
        ctx.stats.add_sent()
        ws, latency_ms = send_and_wait_ack(ctx, state, ws, seq, frame, ack_timeout)
        state.acked += 1
        ctx.stats.add_acked(latency_ms)
        next_at += interval_s

        # 受控重连：只让前 10% agent 参与，且刚好在已 ACK 第 N 批之后断开。
        if (
            ctx.reconnect_agents > 0
            and state.identity.index < ctx.reconnect_agents
            and state.acked % ctx.args.reconnect_every == 0
            and next_at < deadline
        ):
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass
            ws = reconnect_session(ctx, state)

    # 保持连接直到统一 deadline，避免提前关闭导致资源曲线与健康检查提前结束。
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)
    return ws


def agent_thread(ctx: RunContext, state: AgentState, barrier: threading.Barrier) -> None:
    ws = None
    barrier_passed = False
    try:
        ws = connect_session(ctx, state.identity)
        barrier.wait(ctx.args.barrier_timeout)
        barrier_passed = True
        if not ctx.start_gate.wait(ctx.args.barrier_timeout + 10):
            raise ScaleError("等待统一起跑信号超时")
        ws = run_batches(ctx, state, ws)
    except threading.BrokenBarrierError:
        message = "barrier 超时/中断：并非全部 agent 都在时限内建立会话"
        ctx.stats.add_error(state.identity.index, "barrier", message)
        state.errors += 1
    except Exception as exc:  # noqa: BLE001 - 线程内异常必须转成证据
        ctx.stats.add_error(state.identity.index, "fatal", exc_text(exc))
        state.errors += 1
        # 失败发生在 barrier 之前时必须立刻打断等待，别让其它线程空等 40s。
        if not barrier_passed:
            try:
                barrier.abort()
            except Exception:  # noqa: BLE001
                pass
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# 指标采样
# ---------------------------------------------------------------------------


def db_sizes(db_path: Path) -> tuple[int, int]:
    main = file_size(db_path)
    wal = file_size(Path(str(db_path) + "-wal"))
    return main, wal


def monitor_loop(ctx: RunContext, pid: int) -> None:
    """每秒采样 hub 健康、/proc、DB 大小与累计计数，写 metrics.jsonl。"""
    path = ctx.metrics_path
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)
    previous_ticks = None
    previous_mono = None
    db_path = Path(ctx.args.db) if ctx.args.db else Path("/nonexistent")
    next_tick = time.monotonic()
    with os.fdopen(fd, "w", encoding="utf-8", buffering=1) as handle:
        while not ctx.stop_event.is_set():
            try:
                elapsed = time.monotonic() - ctx.run_start
                status, _body, latency_ms, health_error = http_get(
                    ctx.args.admin_url.rstrip("/") + "/healthz",
                    timeout=ctx.args.health_timeout,
                )
                proc_stat = read_proc_stat(pid)
                status_fields = read_proc_status(pid)
                fds = count_fds(pid)
                main_bytes, wal_bytes = db_sizes(db_path)
                snapshot = ctx.stats.snapshot()
                cpu_pct = None
                if proc_stat is not None:
                    ticks = proc_stat["utime_ticks"] + proc_stat["stime_ticks"]
                    if previous_ticks is not None and previous_mono is not None:
                        delta_s = max(1e-6, time.monotonic() - previous_mono)
                        cpu_pct = (
                            (ticks - previous_ticks) / float(SC_CLK_TCK) / delta_s
                        ) * 100.0
                    previous_ticks = ticks
                    previous_mono = time.monotonic()
                if proc_stat is None:
                    ctx.hub_restarted = True
                elif proc_stat["starttime"] != ctx.hub_starttime:
                    ctx.hub_restarted = True
                record = {
                    "ts": iso_now(),
                    "elapsed": round(elapsed, 3),
                    "health_status": status,
                    "health_ok": status == 200,
                    "health_ms": round(latency_ms, 3),
                    "health_error": health_error,
                    "rss_kb": status_fields["rss_kb"],
                    "threads": status_fields["threads"],
                    "fds": fds,
                    "cpu_pct": None if cpu_pct is None else round(cpu_pct, 3),
                    "cpu_ticks": None
                    if proc_stat is None
                    else proc_stat["utime_ticks"] + proc_stat["stime_ticks"],
                    "db_main_bytes": main_bytes,
                    "db_wal_bytes": wal_bytes,
                    "hub_alive": proc_stat is not None,
                    "sent": snapshot["sent"],
                    "acked": snapshot["acked"],
                    "retries": snapshot["retries"],
                    "reconnects": snapshot["reconnects"],
                    "errors": snapshot["errors"],
                }
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            except Exception as exc:  # noqa: BLE001 - 采样失败要留痕，不能杀掉主流程
                ctx.monitor_errors += 1
                try:
                    handle.write(
                        json.dumps(
                            {
                                "ts": iso_now(),
                                "elapsed": round(time.monotonic() - ctx.run_start, 3),
                                "monitor_error": exc_text(exc),
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
                except Exception:  # noqa: BLE001
                    pass
            next_tick += 1.0
            sleep = next_tick - time.monotonic()
            if sleep > 0:
                ctx.stop_event.wait(sleep)


def read_metrics(path: Path) -> dict[str, list]:
    columns: dict[str, list] = {
        key: []
        for key in (
            "elapsed",
            "health_status",
            "health_ms",
            "rss_kb",
            "threads",
            "fds",
            "cpu_pct",
            "db_main_bytes",
            "db_wal_bytes",
            "sent",
            "acked",
            "hub_alive",
        )
    }
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # monitor_error 行没有部分字段；补 None 保持各列与 elapsed 对齐。
                for key in columns:
                    columns[key].append(record.get(key))
    except OSError:
        pass
    return columns


def baseline_window(
    elapsed: list[float],
    values: list,
    warmup: int,
    duration_secs: int,
    width: int = 30,
) -> tuple[float | None, str, int, int]:
    """返回 (基线中位数, 口径说明, 样本数, 实际使用的 warmup)。

    优先用 [warmup, warmup+width] 窗口。短档（duration <= warmup，例如
    60s 冒烟）不可能有“warmup 之后”的样本；此时把 warmup 夹到 duration/2，
    避免基线与结束值取同一批样本导致 RSS 门禁恒为 0% 增长。无论哪种口径都会
    写进 summary，便于复核。
    """
    pairs = [(e, v) for e, v in zip(elapsed, values) if v is not None]
    effective = max(0, warmup)
    mode_prefix = ""
    if len([1 for e, _v in pairs if e >= effective]) < 3:
        effective = max(5, min(warmup, duration_secs // 2))
        mode_prefix = "clamped-half-duration"
    after = [v for e, v in pairs if e >= effective]
    if len(after) >= 3:
        window = [v for e, v in pairs if effective <= e <= effective + width]
        if len(window) >= 3:
            mode = f"{mode_prefix}+warmup+{width}s" if mode_prefix else f"warmup+{width}s"
            return statistics.median(window), mode, len(window), effective
        mode = f"{mode_prefix}+after-warmup" if mode_prefix else "after-warmup"
        return statistics.median(after), mode, len(after), effective
    tail = [v for _e, v in pairs][-10:]
    if tail:
        return statistics.median(tail), "fallback-last-10", len(tail), effective
    return None, "missing", 0, effective


def tail_median(values: list, count: int = 10) -> float | None:
    present = [v for v in values if v is not None]
    return statistics.median(present[-count:]) if present else None


# ---------------------------------------------------------------------------
# 数据库校验
# ---------------------------------------------------------------------------


def open_sqlite_ro(path: Path):
    import sqlite3

    uri = f"file:{path}?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=10)
    connection.execute("PRAGMA query_only=ON")
    return connection


def sqlite_count_batches(path: Path) -> int:
    connection = open_sqlite_ro(path)
    try:
        row = connection.execute("SELECT COUNT(*) FROM ingest_batches").fetchone()
        return int(row[0]) if row else 0
    finally:
        connection.close()


def check_sqlite(ctx: RunContext) -> dict:
    path = Path(ctx.args.db)
    if not path.is_file():
        raise ScaleError(f"SQLite 数据库不存在: {path}")
    expected = ctx.scheduled_batches
    deadline = time.monotonic() + ctx.args.db_stabilize_secs
    last = -1
    stable = 0
    while time.monotonic() < deadline:
        current = sqlite_count_batches(path)
        if current >= expected:
            break
        if current == last:
            stable += 1
        else:
            stable = 0
            last = current
        if stable >= 3:
            break
        time.sleep(0.25)

    connection = open_sqlite_ro(path)
    try:
        db_batches = int(connection.execute("SELECT COUNT(*) FROM ingest_batches").fetchone()[0])
        db_samples = int(
            connection.execute(
                "SELECT COUNT(*) FROM samples WHERE metric LIKE 'load.%'"
            ).fetchone()[0]
        )
        db_agents = int(connection.execute("SELECT COUNT(*) FROM agents").fetchone()[0])
        duplicate_batches = int(
            connection.execute(
                "SELECT COUNT(*) FROM ("
                "  SELECT 1 FROM ingest_batches"
                "  GROUP BY agent_id, epoch, seq HAVING COUNT(*) > 1)"
            ).fetchone()[0]
        )
        duplicate_samples = int(
            connection.execute(
                "SELECT COUNT(*) FROM ("
                "  SELECT 1 FROM samples WHERE metric LIKE 'load.%'"
                "  GROUP BY agent_id, metric, ts HAVING COUNT(*) > 1)"
            ).fetchone()[0]
        )
        batch_rows = dict(
            connection.execute(
                "SELECT agent_id, COUNT(*) FROM ingest_batches GROUP BY agent_id"
            ).fetchall()
        )
        sample_rows = dict(
            connection.execute(
                "SELECT agent_id, COUNT(*) FROM samples"
                " WHERE metric LIKE 'load.%' GROUP BY agent_id"
            ).fetchall()
        )
    finally:
        connection.close()

    sent_by_id = {
        state.identity.agent_id: state.sent for state in ctx.states if state is not None
    }
    index_by_id = {
        state.identity.agent_id: state.identity.index
        for state in ctx.states
        if state is not None
    }
    batch_mismatch = []
    sample_mismatch = []
    for agent_id, sent in sent_by_id.items():
        index = index_by_id[agent_id]
        if int(batch_rows.get(agent_id, 0)) != sent:
            batch_mismatch.append(
                {
                    "agent": index,
                    "expected": sent,
                    "actual": int(batch_rows.get(agent_id, 0)),
                }
            )
        if int(sample_rows.get(agent_id, 0)) != sent * len(AGENT_METRICS):
            sample_mismatch.append(
                {
                    "agent": index,
                    "expected": sent * len(AGENT_METRICS),
                    "actual": int(sample_rows.get(agent_id, 0)),
                }
            )
    unexpected_batches = sorted(set(batch_rows) - set(sent_by_id))
    lost = max(0, ctx.stats.sent - db_batches)
    missing_sends = max(0, expected - ctx.stats.sent)
    ok = (
        db_batches == expected
        and db_samples == expected * len(AGENT_METRICS)
        and duplicate_batches == 0
        and duplicate_samples == 0
        and not batch_mismatch
        and not sample_mismatch
        and not unexpected_batches
        and db_agents == len(ctx.states)
    )
    return {
        "ok": ok,
        "batches": db_batches,
        "batches_expected": expected,
        "batches_sent": ctx.stats.sent,
        "lost": lost,
        "missing_sends": missing_sends,
        "samples": db_samples,
        "samples_expected": expected * len(AGENT_METRICS),
        "duplicate_batches": duplicate_batches,
        "duplicate_samples": duplicate_samples,
        "agents": db_agents,
        "agents_expected": len(ctx.states),
        "per_agent_batch_mismatches": len(batch_mismatch),
        "per_agent_sample_mismatches": len(sample_mismatch),
        "batch_mismatch_sample": batch_mismatch[:5],
        "sample_mismatch_sample": sample_mismatch[:5],
        "unexpected_agent_batches": len(unexpected_batches),
    }


def check_postgres(ctx: RunContext) -> dict:
    """PG 校验接口预留。

    后续实现要求：用 ``psql -Atc`` + ``PGPASSWORD`` 环境变量连接，密码和完整
    DSN 不得进入 argv、日志或证据。Phase E S2 只交付 SQLite 校验，因此这里
    明确失败而不是静默跳过。
    """
    raise ScaleError(
        "backend=postgres 的数据校验尚未实现（Phase E S2 仅实现 SQLite）；"
        "后续接口：psql -Atc + PGPASSWORD 环境变量，密码不得进入 argv/证据"
    )


# ---------------------------------------------------------------------------
# 管理 API / hub 日志 / 资源汇总
# ---------------------------------------------------------------------------


def check_admin(ctx: RunContext) -> dict:
    expected_ids = {identity.agent_id for identity in ctx.identities}
    url = ctx.args.admin_url.rstrip("/") + "/api/v1/agents"
    status, body, latency_ms, error = http_get(
        url,
        headers={
            "Authorization": f"Bearer {ctx.admin_token}",
            "Accept": "application/json",
        },
        timeout=15.0,
    )
    result = {
        "ok": False,
        "status": status,
        "agents": None,
        "expected": len(expected_ids),
        "missing": None,
        "unexpected": None,
        "latency_ms": round(latency_ms, 3),
        "error": error,
    }
    if status != 200 or error is not None:
        return result
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        result["error"] = "响应不是合法 JSON"
        return result
    if not isinstance(payload, list):
        result["error"] = "响应不是 agent 列表"
        return result
    actual_ids = {
        item.get("agent_id")
        for item in payload
        if isinstance(item, dict) and isinstance(item.get("agent_id"), str)
    }
    missing = expected_ids - actual_ids
    unexpected = actual_ids - expected_ids
    result.update(
        {
            "ok": not missing and not unexpected and len(payload) == len(expected_ids),
            "agents": len(payload),
            "missing": len(missing),
            "unexpected": len(unexpected),
        }
    )
    return result


def scan_hub_log(path: Path) -> dict:
    result = {
        "path": str(path) if path else "",
        "error_lines": 0,
        "panicked": 0,
        "samples": [],
    }
    if not path or not path.is_file():
        return result
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                is_panic = "panicked" in line
                is_error = bool(_LOG_ERROR_RE.search(line))
                if not is_panic and not is_error:
                    continue
                if is_panic:
                    result["panicked"] += 1
                else:
                    result["error_lines"] += 1
                if len(result["samples"]) < 10:
                    result["samples"].append(redact(line, 300))
    except OSError as exc:
        result["samples"].append(f"读取 hub.log 失败: {exc_text(exc)}")
    return result


def resource_summary(ctx: RunContext) -> dict:
    columns = read_metrics(ctx.metrics_path)
    elapsed = columns["elapsed"]
    warmup = ctx.args.warmup_secs
    rss_baseline, rss_mode, rss_count, rss_warmup = baseline_window(
        elapsed, columns["rss_kb"], warmup, ctx.args.duration_secs
    )
    fd_baseline, fd_mode, fd_count, fd_warmup = baseline_window(
        elapsed, columns["fds"], warmup, ctx.args.duration_secs
    )
    thread_baseline, thread_mode, thread_count, thread_warmup = baseline_window(
        elapsed, columns["threads"], warmup, ctx.args.duration_secs
    )
    rss_values = [v for v in columns["rss_kb"] if v is not None]
    fd_values = [v for v in columns["fds"] if v is not None]
    thread_values = [v for v in columns["threads"] if v is not None]
    rss_end = tail_median(rss_values)
    fd_end = tail_median(fd_values)
    threads_end = tail_median(thread_values)
    health_ok = sum(1 for value in columns["health_status"] if value == 200)
    health_total = len(columns["health_status"])
    health_latencies = [
        value
        for status, value in zip(columns["health_status"], columns["health_ms"])
        if status == 200 and value is not None
    ]
    cpu_values = [v for v in columns["cpu_pct"] if v is not None]
    db_main = [v for v in columns["db_main_bytes"] if v is not None]
    db_wal = [v for v in columns["db_wal_bytes"] if v is not None]

    def growth(baseline_value, end_value):
        if not baseline_value or end_value is None:
            return None
        return round((end_value - baseline_value) / float(baseline_value) * 100.0, 3)

    return {
        "metrics_samples": len(elapsed),
        "rss_kb": {
            "start": rss_values[0] if rss_values else None,
            "baseline": rss_baseline,
            "baseline_mode": rss_mode,
            "baseline_warmup_secs": rss_warmup,
            "baseline_samples": rss_count,
            "end": rss_end,
            "max": max(rss_values) if rss_values else None,
            "growth_pct": growth(rss_baseline, rss_end),
        },
        "fd": {
            "baseline": fd_baseline,
            "baseline_mode": fd_mode,
            "baseline_warmup_secs": fd_warmup,
            "baseline_samples": fd_count,
            "end": fd_end,
            "max": max(fd_values) if fd_values else None,
            "delta": None if fd_end is None or fd_baseline is None else fd_end - fd_baseline,
        },
        "threads": {
            "baseline": thread_baseline,
            "baseline_mode": thread_mode,
            "baseline_warmup_secs": thread_warmup,
            "baseline_samples": thread_count,
            "end": threads_end,
            "max": max(thread_values) if thread_values else None,
            "delta": None
            if threads_end is None or thread_baseline is None
            else threads_end - thread_baseline,
        },
        "cpu": {
            "avg_pct": round(sum(cpu_values) / len(cpu_values), 3) if cpu_values else None,
            "peak_pct": round(max(cpu_values), 3) if cpu_values else None,
        },
        "health": {
            "samples": health_total,
            "ok": health_ok,
            "failures": health_total - health_ok,
            "max_ms": round(max(health_latencies), 3) if health_latencies else None,
            "p95_ms": round(percentile(health_latencies, 95), 3)
            if health_latencies
            else None,
        },
        "db_size_bytes": {
            "main_start": db_main[0] if db_main else None,
            "main_end": db_main[-1] if db_main else None,
            "wal_end": db_wal[-1] if db_wal else None,
            "total_start": (db_main[0] + db_wal[0]) if db_main and db_wal else None,
            "total_end": (db_main[-1] + db_wal[-1]) if db_main and db_wal else None,
        },
    }


# ---------------------------------------------------------------------------
# summary
# ---------------------------------------------------------------------------


def fresh_state_counts(ctx: RunContext) -> dict:
    sent = sum(state.sent for state in ctx.states)
    acked = sum(state.acked for state in ctx.states)
    return {
        "sent": sent if ctx.states else ctx.stats.sent,
        "acked": acked if ctx.states else ctx.stats.acked,
    }


def build_summary(ctx: RunContext) -> dict:
    snapshot = ctx.stats.snapshot()
    counts = fresh_state_counts(ctx)
    sent = counts["sent"]
    acked = counts["acked"]
    unacked = max(0, sent - acked)
    planned = ctx.scheduled_batches
    ack_values = sorted(snapshot["ack_ms"])
    duration = float(ctx.args.duration_secs)
    resources = resource_summary(ctx)
    total_retries = sum(state.retries for state in ctx.states)
    total_reconnects = sum(state.reconnects for state in ctx.states)
    errors = sum(state.errors for state in ctx.states)

    failures = list(ctx.failures)
    if not ctx.run_started:
        failures.append("agent 未全部就绪，压测未开始")
    if errors > 0:
        failures.append(f"未处理错误 {errors} 个（详见 error_samples）")
    if unacked > 0:
        failures.append(f"有 {unacked} 个已发送批次未取得 ACK")
    if sent < planned:
        failures.append(f"计划发送 {planned} 批，实际只发出 {sent} 批")
    if acked != sent and sent > 0:
        failures.append(f"sent={sent} 与 acked={acked} 不一致")
    if ctx.join_timeouts:
        failures.append(f"{len(ctx.join_timeouts)} 个 agent 线程未在 join 超时内退出")
    if ctx.monitor_errors:
        failures.append(f"指标采样异常 {ctx.monitor_errors} 次")
    if ctx.hub_restarted:
        failures.append("hub PID/starttime 变化或进程消失（视为重启）")
    if ctx.run_started and not ctx.hub_alive_end:
        failures.append("运行结束时 hub 进程已不存在")
    if resources["health"]["failures"] > 0:
        failures.append(f"healthz 失败 {resources['health']['failures']} 次")
    if resources["rss_kb"]["growth_pct"] is not None and resources["rss_kb"]["growth_pct"] > 10.0:
        failures.append(f"RSS 增长 {resources['rss_kb']['growth_pct']}% 超过 10%")
    if resources["fd"]["delta"] is not None and resources["fd"]["delta"] > 32:
        failures.append(f"FD 结束比基线多 {resources['fd']['delta']}，超过 +32")
    if resources["threads"]["delta"] is not None and resources["threads"]["delta"] > 32:
        failures.append(
            f"线程结束比基线多 {resources['threads']['delta']}，超过 +32"
        )
    if ctx.db_result is None:
        failures.append("数据库校验未执行")
    elif not ctx.db_result.get("ok"):
        failures.append(
            "数据库校验失败："
            f"batches={ctx.db_result.get('batches')}/{planned}, "
            f"samples={ctx.db_result.get('samples')}/{planned * len(AGENT_METRICS)}, "
            f"重复={ctx.db_result.get('duplicate_batches')}/"
            f"{ctx.db_result.get('duplicate_samples')}"
        )
    if ctx.admin_result is None:
        failures.append("管理 API 检查未执行")
    elif not ctx.admin_result.get("ok"):
        failures.append(
            "管理 API 检查失败："
            f"status={ctx.admin_result.get('status')}, "
            f"agents={ctx.admin_result.get('agents')}/"
            f"{ctx.admin_result.get('expected')}, error={ctx.admin_result.get('error')}"
        )
    if ctx.hub_log_result is not None and (
        ctx.hub_log_result.get("panicked", 0) > 0
        or ctx.hub_log_result.get("error_lines", 0) > 0
    ):
        failures.append(
            "hub.log 出现 panicked/ERROR："
            f"panicked={ctx.hub_log_result.get('panicked', 0)}, "
            f"error_lines={ctx.hub_log_result.get('error_lines', 0)}"
        )
    if planned == 0:
        failures.append("计划批次为 0（检查 duration/interval）")

    return {
        "schema": 1,
        "phase": "E-S2",
        "started_at": ctx.wall_start,
        "finished_at": ctx.finished_at,
        "agents": ctx.args.agents,
        "duration_secs": ctx.args.duration_secs,
        "interval_ms": ctx.args.interval_ms,
        "warmup_secs": ctx.args.warmup_secs,
        "source_ips": len(ctx.source_ips),
        "source_ip_list": list(ctx.source_ips),
        "per_agent_slots": ctx.per_agent_slots,
        "backend": ctx.args.backend,
        "db_path": ctx.args.db,
        "planned": planned,
        "sent": sent,
        "acked": acked,
        "unacked": unacked,
        "retries": total_retries if ctx.states else snapshot["retries"],
        "reconnects": total_reconnects if ctx.states else snapshot["reconnects"],
        "errors": errors if ctx.states else snapshot["errors"],
        "prep_secs": round(ctx.prep_secs, 3),
        "barrier_secs": round(ctx.barrier_secs, 3),
        "ack_ms": {
            "count": len(ack_values),
            "p50": None if not ack_values else round(percentile_sorted(ack_values, 50), 3),
            "p95": None if not ack_values else round(percentile_sorted(ack_values, 95), 3),
            "p99": None if not ack_values else round(percentile_sorted(ack_values, 99), 3),
            "min": round(min(ack_values), 3) if ack_values else None,
            "max": round(max(ack_values), 3) if ack_values else None,
            "mean": round(sum(ack_values) / len(ack_values), 3) if ack_values else None,
        },
        "throughput": {
            "batches_per_sec": round(acked / duration, 3) if duration > 0 else None,
            "samples_per_sec": round(acked * len(AGENT_METRICS) / duration, 3)
            if duration > 0
            else None,
            "acked_batches_per_agent_sec": round(acked / duration / ctx.args.agents, 4)
            if duration > 0 and ctx.args.agents
            else None,
        },
        "resources": resources,
        "db": ctx.db_result,
        "hub": {
            "pid": ctx.args.hub_pid,
            "starttime": ctx.hub_starttime,
            "starttime_end": ctx.starttime_end,
            "alive_end": ctx.hub_alive_end,
            "restarted": ctx.hub_restarted,
        },
        "admin_api": ctx.admin_result,
        "hub_log": ctx.hub_log_result,
        "join_timeouts": ctx.join_timeouts,
        "error_samples": snapshot["error_samples"],
        "failures": failures,
        "passed": not failures,
        "notes": ctx.notes,
    }


def write_summary(path: Path, summary: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def print_summary(summary: dict, summary_path: Path) -> None:
    ack = summary.get("ack_ms", {})
    resources = summary.get("resources", {})
    rss = resources.get("rss_kb", {})
    fd = resources.get("fd", {})
    threads = resources.get("threads", {})
    db = summary.get("db") or {}
    print("")
    print("========== Phase E S2 summary ==========")
    print(
        "agents={agents} duration={duration}s interval={interval}ms "
        "source_ips={ips} planned={planned} sent={sent} acked={acked} "
        "unacked={unacked}".format(
            ips=summary["source_ips"],
            duration=summary["duration_secs"],
            interval=summary["interval_ms"],
            **summary,
        )
    )
    print(
        "ack_ms p50={p50} p95={p95} p99={p99} max={max}".format(**ack)
    )
    print(
        "throughput batch/s={b} sample/s={s}".format(
            b=summary.get("throughput", {}).get("batches_per_sec"),
            s=summary.get("throughput", {}).get("samples_per_sec"),
        )
    )
    print(
        "db batches={batches}/{expected} samples={samples}/{samples_expected} "
        "dup={dup_b}/{dup_s} agents={agents}".format(
            batches=db.get("batches"),
            expected=db.get("batches_expected"),
            samples=db.get("samples"),
            samples_expected=db.get("samples_expected"),
            dup_b=db.get("duplicate_batches"),
            dup_s=db.get("duplicate_samples"),
            agents=db.get("agents"),
        )
    )
    print(
        "rss_kb start={start} baseline={baseline} end={end} growth={growth}%".format(
            start=rss.get("start"),
            baseline=rss.get("baseline"),
            end=rss.get("end"),
            growth=rss.get("growth_pct"),
        )
    )
    print(
        "fd baseline={fdb} end={fde} | threads baseline={tb} end={te} | "
        "cpu avg={cpu}%".format(
            fdb=fd.get("baseline"),
            fde=fd.get("end"),
            tb=threads.get("baseline"),
            te=threads.get("end"),
            cpu=resources.get("cpu", {}).get("avg_pct"),
        )
    )
    health = resources.get("health", {})
    print(
        "health ok={ok}/{samples} fail={failures} | hub restarted={restarted} | "
        "errors={errors} retries={retries} reconnects={reconnects}".format(
            ok=health.get("ok"),
            samples=health.get("samples"),
            failures=health.get("failures"),
            restarted=summary["hub"]["restarted"],
            errors=summary["errors"],
            retries=summary["retries"],
            reconnects=summary["reconnects"],
        )
    )
    print("result: {}".format("PASS" if summary.get("passed") else "FAIL"))
    if not summary.get("passed"):
        for failure in summary.get("failures", []):
            print(f"  - {failure}")
    print(f"summary: {summary_path}")


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def load_admin_token(args: argparse.Namespace) -> str:
    """从 0600 文件或环境变量读取管理 token，绝不经 argv。

    文件读取后立即 unlink，避免 token 在运行目录里长期留存；权限必须收紧到
    0600（不允许 group/other 位），也不接受符号链接。
    """
    token = ""
    if args.admin_token_file:
        path = Path(args.admin_token_file)
        try:
            info = os.lstat(path)
        except OSError as exc:
            raise ScaleError(f"无法读取 --admin-token-file: {type(exc).__name__}") from None
        if stat.S_ISLNK(info.st_mode):
            raise ScaleError("--admin-token-file 不得是符号链接")
        if not stat.S_ISREG(info.st_mode):
            raise ScaleError("--admin-token-file 必须是普通文件")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise ScaleError("--admin-token-file 权限必须是 0600（group/other 不可读写）")
        try:
            lines = [
                line.strip()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
        except OSError as exc:
            raise ScaleError(f"读取 --admin-token-file 失败: {type(exc).__name__}") from None
        finally:
            try:
                path.unlink()
            except OSError:
                pass
        if len(lines) != 1:
            raise ScaleError("--admin-token-file 必须恰好包含一行 token")
        token = lines[0]
    elif args.admin_token_env:
        token = os.environ.get(args.admin_token_env, "").strip()
    else:  # argparse 的互斥组已保证不会走到这里
        raise ScaleError("必须指定 --admin-token-file 或 --admin-token-env")
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ScaleError("管理 token 格式非法（内容已隐藏）")
    return token


def validate_inputs(ctx: RunContext) -> None:
    args = ctx.args
    if args.agents < 1 or args.agents > 5000:
        raise ScaleError("--agents 必须在 1–5000 之间")
    if args.duration_secs < 1:
        raise ScaleError("--duration-secs 必须 ≥1")
    if args.interval_ms < 1000 or args.interval_ms > 40000:
        raise ScaleError("--interval-ms 必须在 1000–40000（hub 空闲超时 45s）")
    if args.warmup_secs < 0:
        raise ScaleError("--warmup-secs 不能为负")
    if args.reconnect_every < 0:
        raise ScaleError("--reconnect-every 不能为负")
    if args.source_ip_per < 1 or args.source_ip_per > 256:
        raise ScaleError("--source-ip-per 必须在 1–256（hub max_connections_per_ip 上限）")
    if args.backend == "sqlite" and not args.db:
        raise ScaleError("--backend sqlite 需要 --db")
    if not Path(args.hub_bin).is_file() or not os.access(args.hub_bin, os.X_OK):
        raise ScaleError("--hub-bin 不存在或不可执行")
    for label, path in (
        ("--config", args.config),
        ("--ca", args.ca),
    ):
        if not Path(path).is_file():
            raise ScaleError(f"{label} 文件不存在: {path}")
    if args.hub_pid <= 0:
        raise ScaleError("--hub-pid 非法")
    proc_stat = read_proc_stat(args.hub_pid)
    if proc_stat is None:
        raise ScaleError("hub PID 不存在")
    if not ctx.hub_starttime:
        ctx.hub_starttime = proc_stat["starttime"]
    elif proc_stat["starttime"] != ctx.hub_starttime:
        raise ScaleError("启动时 hub starttime 与 --hub-starttime 不一致")


def initialize_context(args: argparse.Namespace) -> RunContext:
    out_dir = Path(args.out_dir).resolve()
    work_dir = out_dir / "work"
    ip_count = max(1, math.ceil(args.agents / args.source_ip_per))
    if 10 + ip_count > 250:
        raise ScaleError("源 IP 数量超出 127.0.0.0/8 回环段规划")
    source_ips = [f"{SOURCE_IP_PREFIX}{10 + index}" for index in range(ip_count)]
    interval_s = args.interval_ms / 1000.0
    slots = 0
    while slots * interval_s < args.duration_secs:
        slots += 1
    scheduled = slots * args.agents
    hub_starttime = args.hub_starttime
    return RunContext(
        args=args,
        out_dir=out_dir,
        work_dir=work_dir,
        metrics_path=out_dir / "metrics.jsonl",
        summary_path=out_dir / "summary.json",
        key_path=work_dir / "agent-key.pem",
        source_ips=source_ips,
        per_agent_slots=slots,
        scheduled_batches=scheduled,
        hub_starttime=hub_starttime,
        stats=Stats(),
        reconnect_agents=(
            max(1, math.ceil(args.agents / 10)) if args.reconnect_every > 0 else 0
        ),
    )


def prepare_work_dir(ctx: RunContext) -> None:
    ctx.out_dir.mkdir(parents=True, exist_ok=True)
    for directory in (ctx.work_dir, ctx.work_dir / "csr", ctx.work_dir / "certs"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
    generate_key(ctx)


def join_agents(ctx: RunContext, threads: list[threading.Thread]) -> None:
    ack_timeout = max(5.0, 2.0 * ctx.args.interval_ms / 1000.0)
    hard_deadline = (
        ctx.run_start
        + ctx.args.duration_secs
        + ack_timeout * max(1, ctx.args.batch_attempts)
        + 30.0
    )
    for thread in threads:
        remaining = hard_deadline - time.monotonic()
        thread.join(timeout=max(0.05, remaining))
        if thread.is_alive():
            ctx.join_timeouts.append(int(thread.name.rsplit("-", 1)[-1]))
    ctx.stop_event.set()


def collect_evidence(ctx: RunContext) -> None:
    end_stat = read_proc_stat(ctx.args.hub_pid)
    ctx.hub_alive_end = end_stat is not None
    if end_stat is None:
        ctx.hub_restarted = True
    else:
        ctx.starttime_end = end_stat["starttime"]
        if end_stat["starttime"] != ctx.hub_starttime:
            ctx.hub_restarted = True

    try:
        ctx.admin_result = check_admin(ctx)
    except Exception as exc:  # noqa: BLE001
        ctx.admin_result = {"ok": False, "error": exc_text(exc)}

    try:
        if ctx.args.backend == "sqlite":
            ctx.db_result = check_sqlite(ctx)
        else:
            ctx.db_result = check_postgres(ctx)
    except Exception as exc:  # noqa: BLE001
        ctx.db_result = {"ok": False, "error": exc_text(exc)}

    if ctx.args.hub_log:
        try:
            ctx.hub_log_result = scan_hub_log(Path(ctx.args.hub_log))
        except Exception as exc:  # noqa: BLE001
            ctx.hub_log_result = {"ok": False, "error": exc_text(exc)}


def run(ctx: RunContext) -> None:
    validate_inputs(ctx)
    ctx.admin_token = load_admin_token(ctx.args)
    ctx.prep_started = time.monotonic()
    prepare_work_dir(ctx)
    ctx.identities = prepare_agents(ctx)
    ctx.prep_secs = time.monotonic() - ctx.prep_started
    ctx.states = [AgentState(identity) for identity in ctx.identities]

    barrier = threading.Barrier(len(ctx.identities) + 1)
    stack_bytes = max(256, ctx.args.thread_stack_kib) * 1024
    try:
        threading.stack_size(stack_bytes)
    except (ValueError, RuntimeError):
        ctx.notes.append("线程栈大小设置失败，使用解释器默认值")

    threads = [
        threading.Thread(
            target=agent_thread,
            args=(ctx, state, barrier),
            name=f"load-{state.identity.index}",
            daemon=True,
        )
        for state in ctx.states
    ]
    threads_started = time.monotonic()
    for thread in threads:
        thread.start()

    monitor_thread = None
    try:
        barrier.wait(ctx.args.barrier_timeout)
    except threading.BrokenBarrierError:
        ctx.failures.append(
            "barrier 超时或被中断：并非全部 agent 都在时限内完成会话+Hello"
        )
        ctx.stop_event.set()
        for thread in threads:
            thread.join(timeout=2.0)
        return

    ctx.barrier_secs = time.monotonic() - threads_started
    ctx.run_start = time.monotonic()
    ctx.run_started = True
    ctx.wall_start = iso_now()
    monitor_thread = threading.Thread(
        target=monitor_loop,
        args=(ctx, ctx.args.hub_pid),
        name="metrics",
        daemon=True,
    )
    monitor_thread.start()
    ctx.start_gate.set()
    try:
        join_agents(ctx, threads)
    finally:
        ctx.stop_event.set()
        if monitor_thread is not None:
            monitor_thread.join(timeout=5.0)
    collect_evidence(ctx)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ctx = initialize_context(args)
    except ScaleError as exc:
        print(f"FATAL: {exc_text(exc)}", file=sys.stderr)
        # 参数/环境级失败也留一份最小 summary；不包含 token 或证书内容。
        try:
            out_dir = Path(args.out_dir).resolve()
            out_dir.mkdir(parents=True, exist_ok=True)
            write_summary(
                out_dir / "summary.json",
                {
                    "schema": 1,
                    "phase": "E-S2",
                    "started_at": "",
                    "finished_at": iso_now(),
                    "agents": args.agents,
                    "duration_secs": args.duration_secs,
                    "interval_ms": args.interval_ms,
                    "warmup_secs": args.warmup_secs,
                    "backend": args.backend,
                    "passed": False,
                    "failures": [exc_text(exc)],
                },
            )
        except OSError:
            pass
        return 2
    summary: dict | None = None
    try:
        run(ctx)
    except KeyboardInterrupt:
        ctx.failures.append("运行被中断")
    except Exception as exc:  # noqa: BLE001 - 顶层兜底，保证写 summary
        ctx.failures.append(f"运行异常: {exc_text(exc)}")
    finally:
        ctx.stop_event.set()
        ctx.start_gate.set()
        ctx.finished_at = iso_now()
        if ctx.args.backend == "sqlite" and ctx.db_result is None and ctx.run_started:
            try:
                ctx.db_result = check_sqlite(ctx)
            except Exception as exc:  # noqa: BLE001
                ctx.db_result = {"ok": False, "error": exc_text(exc)}
        if ctx.admin_result is None and ctx.run_started:
            try:
                ctx.admin_result = check_admin(ctx)
            except Exception as exc:  # noqa: BLE001
                ctx.admin_result = {"ok": False, "error": exc_text(exc)}
        summary = build_summary(ctx)
        try:
            write_summary(ctx.summary_path, summary)
        except OSError as exc:
            print(f"FATAL: 写入 summary 失败: {exc_text(exc)}", file=sys.stderr)
        shutil.rmtree(ctx.work_dir, ignore_errors=True)
        print_summary(summary, ctx.summary_path)
    return 0 if summary is not None and summary.get("passed") else 1


if __name__ == "__main__":
    sys.exit(main())
