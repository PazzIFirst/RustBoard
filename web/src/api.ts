/**
 * 面板同源 API 客户端。
 *
 * 只请求 `/api/*`：hub token 由面板服务端注入，前端 bundle 里没有任何密钥。
 * 401 通过全局回调交给 AuthProvider，避免每个页面各写一套跳转逻辑。
 */
import type {
  OverviewResponse,
  SamplePoint,
  SeriesPoint,
  SeriesResponse,
  AgentSetting,
  SystemInfo,
} from "./types";

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;

  constructor(status: number, code?: string) {
    super(code ? `API ${status}: ${code}` : `API ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
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

async function readErrorCode(response: Response): Promise<string | undefined> {
  try {
    const body = (await response.json()) as { error?: unknown };
    return typeof body.error === "string" ? body.error : undefined;
  } catch {
    return undefined;
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
    const code = await readErrorCode(response);
    if (response.status === 401 && !path.startsWith("/api/login")) {
      unauthorizedHandler?.();
    }
    throw new ApiError(response.status, code);
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
};

/** 给页面统一生成可读错误文案，不泄露响应细节之外的信息。 */
export function describeError(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "登录已失效，请重新登录";
    if (error.status === 429) return "尝试次数过多，请稍后再试";
    if (error.status === 502) return "无法访问 hub 管理 API";
    if (error.code) return `请求失败（${error.status} / ${error.code}）`;
    return `请求失败（${error.status}）`;
  }
  if (error instanceof TypeError) return "网络错误：无法连接面板服务";
  if (error instanceof Error && error.message) return error.message;
  return "请求失败";
}
