/**
 * 面板同源 API 客户端。
 *
 * 只请求 `/api/*`：hub token 由面板服务端注入，前端 bundle 里没有任何密钥。
 * 401 通过全局回调交给 AuthProvider，避免每个页面各写一套跳转逻辑。
 */
import {
  auditQueryParams,
  normalizeAuditResponse,
  normalizeControlResponse,
  normalizeControlStatus,
} from "./control";
import type {
  AuditQuery,
  AuditResponse,
  OverviewResponse,
  SamplePoint,
  SeriesPoint,
  SeriesResponse,
  AgentSetting,
  ControlRequestPayload,
  ControlResponse,
  ControlStatus,
  SystemInfo,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  /** 服务端返回的可读说明；只在页面需要更具体文案时使用。 */
  readonly serverMessage?: string;

  constructor(status: number, code?: string, serverMessage?: string) {
    super(code ? `API ${status}: ${code}` : `API ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.serverMessage = serverMessage;
  }
}

let unauthorizedHandler: (() => void) | null = null;

/** AuthProvider 挂载时注册；401 时自动回到登录页。 */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  unauthorizedHandler = handler;
}

interface RawSeriesResponse {
  bucket_ms: number;
  series: Array<{
    metric: string;
    labels: Record<string, string>;
    points: Array<[number, number]>;
  }>;
}

interface ApiErrorDetails {
  code?: string;
  message?: string;
}

/** 兼容两种错误体：`{"error":"code","message":"..."}` 与 `{"error":{"code","message"}}`。 */
async function readErrorDetails(response: Response): Promise<ApiErrorDetails> {
  try {
    const body = (await response.json()) as unknown;
    if (typeof body !== "object" || body === null) return {};
    const record = body as Record<string, unknown>;
    const raw = record.error;
    const fallbackMessage = typeof record.message === "string" ? record.message : undefined;
    if (typeof raw === "string") {
      return { code: raw, message: fallbackMessage };
    }
    if (typeof raw === "object" && raw !== null) {
      const nested = raw as Record<string, unknown>;
      return {
        code: typeof nested.code === "string" ? nested.code : undefined,
        message: typeof nested.message === "string" ? nested.message : fallbackMessage,
      };
    }
    return { message: fallbackMessage };
  } catch {
    return {};
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.headers ?? {}),
    },
  });
  if (!response.ok) {
    const details = await readErrorDetails(response);
    if (response.status === 401 && !path.startsWith("/api/login")) {
      unauthorizedHandler?.();
    }
    throw new ApiError(response.status, details.code, details.message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function jsonBody(value: unknown): RequestInit {
  return {
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(value),
  };
}

function normalizeSeries(raw: RawSeriesResponse): SeriesResponse {
  return {
    bucket_ms: raw.bucket_ms,
    series: raw.series.map(
      (row): SeriesPoint => ({
        metric: row.metric,
        labels: row.labels,
        points: row.points.map(
          ([ts, value]): SamplePoint => ({ ts, value }),
        ),
      }),
    ),
  };
}

export interface SeriesQuery {
  metrics: string[];
  from: number;
  to: number;
  bucketMs?: number;
}

export const api = {
  session(): Promise<{ authenticated: boolean }> {
    return request<{ authenticated: boolean }>("/api/session");
  },

  login(password: string): Promise<void> {
    return request<void>("/api/login", {
      method: "POST",
      ...jsonBody({ password }),
    });
  },

  logout(): Promise<void> {
    return request<void>("/api/logout", {
      method: "POST",
      ...jsonBody({}),
    });
  },

  overview(signal?: AbortSignal): Promise<OverviewResponse> {
    return request<OverviewResponse>("/api/overview?window_ms=60000", { signal });
  },

  system(signal?: AbortSignal): Promise<SystemInfo> {
    return request<SystemInfo>("/api/system", { signal });
  },

  async series(agentId: string, query: SeriesQuery, signal?: AbortSignal): Promise<SeriesResponse> {
    const params = new URLSearchParams();
    for (const metric of query.metrics) params.append("metric", metric);
    params.set("from", String(query.from));
    params.set("to", String(query.to));
    if (query.bucketMs !== undefined) params.set("bucket_ms", String(query.bucketMs));
    const raw = await request<RawSeriesResponse>(
      `/api/agents/${encodeURIComponent(agentId)}/series?${params.toString()}`,
      { signal },
    );
    return normalizeSeries(raw);
  },

  settings(agentId: string, signal?: AbortSignal): Promise<AgentSetting> {
    return request<AgentSetting>(
      `/api/agents/${encodeURIComponent(agentId)}/settings`,
      { signal },
    );
  },

  updateSettings(agentId: string, sampleIntervalMs: number): Promise<AgentSetting> {
    return request<AgentSetting>(
      `/api/agents/${encodeURIComponent(agentId)}/settings`,
      {
        method: "PUT",
        ...jsonBody({ sample_interval_ms: sampleIntervalMs }),
      },
    );
  },

  /** 控制台进入时读取能力状态；只读，不写审计。 */
  async controlStatus(agentId: string, signal?: AbortSignal): Promise<ControlStatus> {
    const raw = await request<unknown>(
      `/api/agents/${encodeURIComponent(agentId)}/control`,
      { signal },
    );
    return normalizeControlStatus(raw);
  },

  /**
   * 执行控制动作。
   *
   * 所有非 2xx 都归一化成 `ControlResponse` 的 `ok:false`，页面可统一展示
   * 服务端错误码与 message；401 仍由 request 层触发全局登出。
   */
  async control(
    agentId: string,
    payload: ControlRequestPayload,
    signal?: AbortSignal,
  ): Promise<ControlResponse> {
    try {
      const raw = await request<unknown>(
        `/api/agents/${encodeURIComponent(agentId)}/control`,
        {
          method: "POST",
          ...jsonBody(payload),
          signal,
        },
      );
      return normalizeControlResponse(raw);
    } catch (error) {
      if (error instanceof ApiError) {
        return {
          ok: false,
          status: error.status,
          error: {
            code: error.code ?? `http_${error.status}`,
            message: error.serverMessage ?? "",
          },
        };
      }
      throw error;
    }
  },

  /** 审计列表；分页与过滤参数由 control.ts 统一编码。 */
  async audit(query: AuditQuery = {}, signal?: AbortSignal): Promise<AuditResponse> {
    const raw = await request<unknown>(`/api/audit?${auditQueryParams(query)}`, { signal });
    return normalizeAuditResponse(raw);
  },
};

/** 给页面统一生成可读错误文案，不泄露响应细节之外的信息。 */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "登录已失效，请重新登录";
    if (error.status === 403) {
      return error.code ? `没有权限（${error.code}）` : "没有权限执行该操作";
    }
    if (error.status === 429) return "尝试次数过多，请稍后再试";
    if (error.status === 502) return "无法访问 hub 管理 API";
    if (error.status === 503) return "服务暂不可用，请稍后重试";
    if (error.status === 504) return "请求超时，请稍后重试";
    if (error.code) return `请求失败（${error.status} / ${error.code}）`;
    return `请求失败（${error.status}）`;
  }
  if (error instanceof TypeError) return "网络错误：无法连接面板服务";
  if (error instanceof Error && error.message) return error.message;
  return "请求失败";
}
