import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, setUnauthorizedHandler } from "../api";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  setUnauthorizedHandler(null);
});

function respond(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function mockFetch(status: number, body: unknown): void {
  globalThis.fetch = vi.fn(
    async () => respond(status, body),
  ) as unknown as typeof fetch;
}

async function catchApiError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ApiError);
    return error as ApiError;
  }
  throw new Error("请求应当失败");
}

describe("面板 / hub 401 边界 (#38)", () => {
  it("告警 hub 401 已映射为 502 时，前端不触发全局登出", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    mockFetch(502, { error: "hub_auth_failed" });

    const error = await catchApiError(api.alertRules());
    expect(error.status).toBe(502);
    expect(error.code).toBe("hub_auth_failed");
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("归档 502 hub_auth_failed 同样不触发登出", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    mockFetch(502, { error: "hub_auth_failed" });

    const error = await catchApiError(api.archiveStatus());
    expect(error.status).toBe(502);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });

  it("真正失效的 Panel 会话 401 仍触发全局登出", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    mockFetch(401, { error: "unauthorized" });

    const error = await catchApiError(api.session());
    expect(error.status).toBe(401);
    expect(onUnauthorized).toHaveBeenCalledTimes(1);
  });

  it("登录失败 401 不触发全局登出（不是会话失效）", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);
    mockFetch(401, { error: "unauthorized" });

    const error = await catchApiError(api.login("wrong-password"));
    expect(error.status).toBe(401);
    expect(onUnauthorized).not.toHaveBeenCalled();
  });
});
