/**
 * M3 控制面与审计页的纯函数。
 *
 * 这里只做数据归一化、错误文案、分页参数与展示格式，不依赖 DOM，
 * 方便 vitest 直接覆盖；网络请求统一放在 `api.ts`。
 */
import { formatDateTime } from "./format";
import type {
  AuditEntry,
  AuditQuery,
  AuditResponse,
  ControlCapability,
  ControlError,
  ControlResponse,
  ControlResult,
  ControlStatus,
  DockerContainer,
  LogSourceInfo,
  ProcessInfo,
  SystemdUnit,
} from "./types";

export const CONTROL_CAPABILITIES: ReadonlyArray<{
  key: ControlCapability;
  label: string;
}> = [
  { key: "systemd", label: "systemd" },
  { key: "docker", label: "Docker" },
  { key: "process", label: "进程" },
  { key: "logs", label: "日志" },
];

export const AUDIT_PAGE_SIZE = 100;

const CAPABILITY_LABELS: Record<string, string> = {
  systemd: "systemd",
  docker: "Docker",
  process: "进程",
  logs: "日志",
};

const ACTION_LABELS: Record<string, string> = {
  start: "启动",
  stop: "停止",
  restart: "重启",
  kill: "结束进程",
  list: "列表",
  tail: "查看日志",
};

/** 能力展示名；未知能力原样返回，避免猜造。 */
export function capabilityLabel(capability: string): string {
  return CAPABILITY_LABELS[capability.trim().toLowerCase()] ?? capability;
}

/** 动作展示名；未知动作原样返回。 */
export function actionLabel(action: string): string {
  return ACTION_LABELS[action.trim().toLowerCase()] ?? action;
}

/**
 * 危险动作需要面板二次确认。
 *
 * 依据 requirements §8.3：停止服务、结束进程属于危险操作；重启包含停止，
 * 同样按危险动作处理。启动服务只读地改变状态，不弹确认框但请求仍带 confirm。
 */
export function isDangerousAction(action: string): boolean {
  switch (action.trim().toLowerCase()) {
    case "stop":
    case "restart":
    case "kill":
      return true;
    default:
      return false;
  }
}

/** 会改变宿主机状态的动作（需要 confirm:true）；list / tail 是只读动作。 */
export function isMutationAction(action: string): boolean {
  const normalized = action.trim().toLowerCase();
  return normalized !== "" && normalized !== "list" && normalized !== "tail";
}

/**
 * 动作输出是否失败。
 *
 * hub 把 `exit_code = null`（进程被信号终止、没有正常退出码）也记为失败，
 * 面板必须保持一致：只有退出码 0 视为成功。
 */
export function isActionFailed(exitCode: number | null): boolean {
  return exitCode !== 0;
}

/** hub 与 agent 都开启的能力才可用；顺序固定为 systemd / Docker / 进程 / 日志。 */
export function enabledCapabilities(
  status: Pick<ControlStatus, "capabilities" | "hub_capabilities">,
): ControlCapability[] {
  const agent = new Set(status.capabilities);
  const hub = new Set(status.hub_capabilities);
  return CONTROL_CAPABILITIES.filter(
    (capability) => agent.has(capability.key) && hub.has(capability.key),
  ).map((capability) => capability.key);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> {
  return isRecord(value) ? value : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function asStringArray(value: unknown): string[] {
  return asArray(value).filter((item): item is string => typeof item === "string");
}

function asFiniteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asNonNegativeInteger(value: unknown): number {
  const number = asFiniteNumber(value);
  return number === null ? 0 : Math.max(0, Math.trunc(number));
}

function asRecords(value: unknown): Record<string, unknown>[] {
  return asArray(value).filter(isRecord);
}

/** 兼容缺失 / 异常字段；只信任显式布尔值。 */
export function normalizeControlStatus(raw: unknown): ControlStatus {
  const value = asRecord(raw);
  return {
    control_enabled: value.control_enabled === true,
    online: value.online === true,
    capabilities: asStringArray(value.capabilities),
    hub_capabilities: asStringArray(value.hub_capabilities),
  };
}

function normalizeSystemdUnit(value: Record<string, unknown>): SystemdUnit {
  return {
    unit: asString(value.unit),
    load: asString(value.load),
    active: asString(value.active),
    sub: asString(value.sub),
    description: asString(value.description),
  };
}

function normalizeDockerContainer(value: Record<string, unknown>): DockerContainer {
  return {
    id: asString(value.id),
    name: asString(value.name),
    image: asString(value.image),
    state: asString(value.state),
    status: asString(value.status),
  };
}

function normalizeProcess(value: Record<string, unknown>): ProcessInfo {
  const rssBytes = asFiniteNumber(value.rss);
  const rssKb = asFiniteNumber(value.rss_kb);
  return {
    pid: asNonNegativeInteger(value.pid),
    name: asString(value.name),
    uid: asNonNegativeInteger(value.uid),
    // 线协议用 rss_kb（KiB）；若 hub API 已换算成字节则读 rss，二者都兼容。
    rss:
      rssBytes !== null
        ? Math.max(0, Math.trunc(rssBytes))
        : rssKb !== null
          ? Math.max(0, Math.trunc(rssKb * 1024))
          : 0,
    cmdline: asString(value.cmdline),
  };
}

function normalizeLogSource(value: Record<string, unknown>): LogSourceInfo {
  const size = asFiniteNumber(value.size) ?? asFiniteNumber(value.size_bytes);
  return {
    id: asString(value.id),
    name: asString(value.name),
    kind: asString(value.kind),
    target: asString(value.target),
    ...(size !== null ? { size: Math.max(0, Math.trunc(size)) } : {}),
  };
}

/** 归一化控制结果；无法识别的 `type` 返回 null，由调用方转成 `invalid_response`。 */
function normalizeControlResult(value: unknown): ControlResult | null {
  const result = asRecord(value);
  const type = asString(result.type);
  switch (type) {
    case "systemd_units": {
      const units = asRecords(result.units)
        .map(normalizeSystemdUnit)
        .filter((unit) => unit.unit !== "");
      return { type, units };
    }
    case "docker_containers": {
      const containers = asRecords(result.containers)
        .map(normalizeDockerContainer)
        .filter((container) => container.name !== "" || container.id !== "");
      return { type, containers };
    }
    case "processes": {
      const processes = asRecords(result.processes)
        .map(normalizeProcess)
        .filter((process) => process.pid > 0);
      return { type, processes };
    }
    case "log_sources": {
      const sources = asRecords(result.sources)
        .map(normalizeLogSource)
        .filter((source) => source.id !== "");
      return { type, sources };
    }
    case "log_lines":
      return {
        type,
        source: asString(result.source),
        lines: asStringArray(result.lines),
        truncated: result.truncated === true,
        size_bytes: asNonNegativeInteger(result.size_bytes),
      };
    case "action_output": {
      const exitCode = asFiniteNumber(result.exit_code);
      return {
        type,
        stdout: asString(result.stdout),
        stderr: asString(result.stderr),
        exit_code: exitCode === null ? null : Math.trunc(exitCode),
      };
    }
    default:
      // 兼容未显式带 type 的动作输出；其余未知结构一律视为响应非法。
      if ("stdout" in result || "stderr" in result || "exit_code" in result) {
        const exitCode = asFiniteNumber(result.exit_code);
        return {
          type: "action_output",
          stdout: asString(result.stdout),
          stderr: asString(result.stderr),
          exit_code: exitCode === null ? null : Math.trunc(exitCode),
        };
      }
      return null;
  }
}

/** 服务端错误体 → 统一错误结构。 */
export function normalizeControlError(value: unknown): ControlError {
  if (typeof value === "string" && value.trim() !== "") {
    return { code: value.trim(), message: "" };
  }
  const record = asRecord(value);
  return {
    code: asString(record.code).trim() || "unknown_error",
    message: asString(record.message).trim(),
  };
}

/**
 * 归一化 POST /control 的响应。
 *
 * `api.control()` 也会用本函数处理 2xx 响应；非 2xx 由 api 层转成同形状的
 * `{ ok:false, error, status }`，页面因此只需处理一种结构。
 */
export function normalizeControlResponse(raw: unknown): ControlResponse {
  const value = asRecord(raw);
  if (value.ok === false) {
    return { ok: false, error: normalizeControlError(value.error) };
  }
  if (value.ok === true) {
    const result = normalizeControlResult(value.result);
    if (result !== null) return { ok: true, result };
    return {
      ok: false,
      error: { code: "invalid_response", message: "服务端返回了无法识别的控制结果" },
    };
  }
  return {
    ok: false,
    error: { code: "invalid_response", message: "服务端返回格式非法" },
  };
}

function withDetail(message: string, detail: string): string {
  return detail ? `${message}（${detail}）` : message;
}

/** 控制面错误码 → 可读中文；未知错误码回退到 HTTP 状态或服务端原始说明。 */
export function describeControlError(error: ControlError, status?: number): string {
  switch (error.code) {
    case "capability_disabled":
      return "该能力未启用：需要在 hub 与 agent 的 [control] 配置中同时开启";
    case "not_whitelisted":
      return withDetail("目标不在白名单，操作被拒绝", error.message);
    case "agent_offline":
      return "agent 不在线，无法执行控制操作";
    case "control_timeout":
      return "控制请求超时：agent 未在限定时间内响应";
    case "control_result_unknown":
      // 面板等待超过 Hub 的最大控制等待：结果未知，动作可能已经执行。
      // 不能引导用户直接重试，否则可能重复执行危险动作。
      return "控制请求结果未知：动作可能已执行，不要直接重试；请先刷新并核对 systemd / 进程 / 容器状态";
    case "too_many_pending":
      return "待处理命令过多，请稍后重试";
    case "rate_limited":
      return "控制操作过于频繁（写操作限 10 次/分钟），请稍后重试";
    case "invalid_request":
      return withDetail("请求参数非法", error.message);
    case "control_failed":
      return withDetail("agent 执行失败", error.message);
    case "invalid_response":
      return error.message || "服务端返回了无法识别的响应";
    case "hub_auth_failed":
      return "面板无法通过 hub 鉴权，请联系管理员检查 token 配置";
    case "hub_unreachable":
      return "面板无法连接 hub 管理 API，请稍后重试";
    case "network_error":
      return error.message || "网络错误：无法连接面板服务";
    default:
      break;
  }
  if (status === 401) return "登录已失效，请重新登录";
  if (status === 403) return withDetail("没有权限执行该操作", error.message);
  if (status === 429) return "请求过于频繁，请稍后重试";
  if (status === 503) return "控制服务暂不可用，请稍后重试";
  if (status === 504) return "控制请求超时，请稍后重试";
  if (error.message) return error.message;
  return error.code === "unknown_error" ? "控制请求失败" : `控制请求失败（${error.code}）`;
}

/**
 * 审计分页 / 过滤参数。
 *
 * 输出顺序固定为 limit → before_id → agent_id → capability，便于测试与日志排查。
 */
export function auditQueryParams(query: AuditQuery = {}): string {
  const params = new URLSearchParams();
  const requestedLimit = query.limit ?? AUDIT_PAGE_SIZE;
  const limit = Number.isFinite(requestedLimit)
    ? Math.min(AUDIT_PAGE_SIZE, Math.max(1, Math.trunc(requestedLimit)))
    : AUDIT_PAGE_SIZE;
  params.set("limit", String(limit));

  if (query.beforeId !== undefined && Number.isFinite(query.beforeId) && query.beforeId > 0) {
    params.set("before_id", String(Math.trunc(query.beforeId)));
  }
  const agentId = query.agentId?.trim() ?? "";
  if (agentId !== "") params.set("agent_id", agentId);
  const capability = query.capability?.trim() ?? "";
  if (capability !== "") params.set("capability", capability);
  return params.toString();
}

/**
 * 计算「加载更早」的 `before_id`。
 *
 * 后端使用排他游标 `id < before_id`：满页时 `next_before_id` 是本页最后一条 id，
 * 因此必须优先使用服务端游标；只有响应缺失该字段时才回退到最后一条 id。
 * 服务端明确返回 null 表示没有更多数据。
 */
export function nextAuditBeforeId(
  entries: AuditEntry[],
  serverNext?: number | null,
): number | undefined {
  if (serverNext === null) return undefined;
  if (serverNext !== undefined && Number.isFinite(serverNext) && serverNext > 0) {
    return Math.trunc(serverNext);
  }
  const last = entries[entries.length - 1];
  if (last && Number.isFinite(last.id) && last.id > 0) return Math.trunc(last.id);
  return undefined;
}

/** 是否还有下一页；优先信任服务端 next_before_id，缺失时才按页大小推断。 */
export function auditHasMore(
  response: AuditResponse,
  pageSize = AUDIT_PAGE_SIZE,
): boolean {
  if (response.next_before_id === null) return false;
  if (response.next_before_id !== undefined) return response.entries.length > 0;
  return response.entries.length >= pageSize;
}

function normalizeAuditEntry(value: unknown): AuditEntry | null {
  if (!isRecord(value)) return null;
  const id = asFiniteNumber(value.id);
  if (id === null || id <= 0) return null;
  return {
    id: Math.trunc(id),
    ts: asFiniteNumber(value.ts) ?? 0,
    actor: asString(value.actor),
    agent_id: asString(value.agent_id),
    capability: asString(value.capability),
    action: asString(value.action),
    target: asString(value.target),
    result: asString(value.result),
    error_code: asString(value.error_code),
    error_message: asString(value.error_message),
    duration_ms: asNonNegativeInteger(value.duration_ms),
  };
}

/**
 * 审计响应归一化：丢弃没有有效 id 的条目，保证分页游标可用。
 *
 * `next_before_id: null` 是服务端明确表示“没有更多”，必须保留，不能当作缺失。
 */
export function normalizeAuditResponse(raw: unknown): AuditResponse {
  const value = asRecord(raw);
  const entries = asArray(value.entries)
    .map(normalizeAuditEntry)
    .filter((entry): entry is AuditEntry => entry !== null);
  if (value.next_before_id === null) {
    return { entries, next_before_id: null };
  }
  const next = asFiniteNumber(value.next_before_id);
  if (next !== null && next >= 0) {
    return { entries, next_before_id: Math.trunc(next) };
  }
  return { entries };
}

/** 秒 / 毫秒时间戳统一成毫秒；非法或非正数返回 null。 */
function timestampMs(value: number): number | null {
  if (!Number.isFinite(value) || value <= 0) return null;
  // 1e11 ms ≈ 1973 年，正常毫秒时间戳远大于该值；小于它按秒处理。
  return value < 100_000_000_000 ? value * 1000 : value;
}

/** 审计时间展示；ts 可能来自秒级或毫秒级字段。 */
export function formatAuditTime(ts: number): string {
  const ms = timestampMs(ts);
  return ms === null ? "—" : formatDateTime(ms);
}

/** 耗时展示：0–999ms 用毫秒，之后用秒/分钟/小时。 */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms) || ms < 0) return "—";
  const rounded = Math.round(ms);
  if (rounded < 1000) return `${rounded} ms`;
  if (rounded < 60_000) {
    const seconds = (rounded / 1000).toFixed(1);
    // 59.95s 以上四舍五入会得到 60.0s，直接归入分钟档，避免出现“60.0 s”。
    return seconds === "60.0" ? "1m 0s" : `${seconds} s`;
  }
  if (rounded < 3_600_000) {
    const minutes = Math.floor(rounded / 60_000);
    const seconds = Math.round((rounded % 60_000) / 1000);
    if (seconds === 60) return `${minutes + 1}m 0s`;
    return `${minutes}m ${seconds}s`;
  }
  return `${(rounded / 3_600_000).toFixed(1)} h`;
}

/** 审计结果 → 样式类；只接受已知结果，未知值不参与颜色推断。 */
export function auditResultClass(result: string): string {
  switch (result.trim().toLowerCase()) {
    case "ok":
      return "result-ok";
    case "denied":
      return "result-denied";
    case "error":
    case "failed":
      return "result-error";
    default:
      return "result-unknown";
  }
}

/** 审计错误列：错误码 + 可读信息。 */
export function auditErrorText(
  entry: Pick<AuditEntry, "error_code" | "error_message">,
): string {
  if (entry.error_code !== "" && entry.error_message !== "") {
    return `${entry.error_code}：${entry.error_message}`;
  }
  return entry.error_code || entry.error_message;
}
