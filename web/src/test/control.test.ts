import { describe, expect, it } from "vitest";
import {
  auditErrorText,
  auditHasMore,
  auditQueryParams,
  auditResultClass,
  describeControlError,
  enabledCapabilities,
  formatAuditTime,
  formatDuration,
  isDangerousAction,
  isMutationAction,
  nextAuditBeforeId,
  normalizeAuditResponse,
  normalizeControlResponse,
  normalizeControlStatus,
} from "../control";
import { formatDateTime } from "../format";
import type { AuditEntry } from "../types";

function auditEntry(partial: Partial<AuditEntry>): AuditEntry {
  return {
    id: 1,
    ts: 1_700_000_000_000,
    actor: "admin",
    agent_id: "hub-self",
    capability: "systemd",
    action: "restart",
    target: "nginx.service",
    result: "ok",
    error_code: "",
    error_message: "",
    duration_ms: 83,
    ...partial,
  };
}

describe("危险动作判定", () => {
  it("停止 / 重启 / 结束进程需要二次确认", () => {
    for (const action of ["stop", "restart", "kill", " KILL "]) {
      expect(isDangerousAction(action), action).toBe(true);
    }
  });

  it("启动与只读动作不需要二次确认", () => {
    for (const action of ["start", "list", "tail", ""]) {
      expect(isDangerousAction(action), action).toBe(false);
    }
  });

  it("只有变更动作携带 confirm:true", () => {
    expect(isMutationAction("start")).toBe(true);
    expect(isMutationAction("stop")).toBe(true);
    expect(isMutationAction("kill")).toBe(true);
    expect(isMutationAction("list")).toBe(false);
    expect(isMutationAction("tail")).toBe(false);
    expect(isMutationAction("")).toBe(false);
  });
});

describe("能力状态归一化", () => {
  it("只保留 hub 与 agent 都开启的能力，并保持固定顺序", () => {
    const status = normalizeControlStatus({
      control_enabled: true,
      online: false,
      capabilities: ["logs", "systemd", "unknown", 42],
      hub_capabilities: ["systemd", "docker", "logs"],
    });
    expect(status).toEqual({
      control_enabled: true,
      online: false,
      capabilities: ["logs", "systemd", "unknown"],
      hub_capabilities: ["systemd", "docker", "logs"],
    });
    expect(enabledCapabilities(status)).toEqual(["systemd", "logs"]);
  });

  it("缺失或异常字段按未启用处理", () => {
    expect(normalizeControlStatus(null)).toEqual({
      control_enabled: false,
      online: false,
      capabilities: [],
      hub_capabilities: [],
    });
    expect(
      normalizeControlStatus({ control_enabled: "true", online: 1 }),
    ).toMatchObject({ control_enabled: false, online: false });
  });
});

describe("control 响应 / 错误归一化", () => {
  it("归一化 systemd 列表并丢弃非法条目", () => {
    const response = normalizeControlResponse({
      ok: true,
      result: {
        type: "systemd_units",
        units: [
          {
            unit: "nginx.service",
            load: "loaded",
            active: "active",
            sub: "running",
            description: "Nginx",
          },
          { unit: "" },
          null,
          42,
        ],
      },
    });
    expect(response).toEqual({
      ok: true,
      result: {
        type: "systemd_units",
        units: [
          {
            unit: "nginx.service",
            load: "loaded",
            active: "active",
            sub: "running",
            description: "Nginx",
          },
        ],
      },
    });
  });

  it("归一化进程列表：缺少 PID 的条目不可操作，rss_kb 换算成字节", () => {
    const response = normalizeControlResponse({
      ok: true,
      result: {
        type: "processes",
        processes: [
          { pid: 0, name: "bad" },
          { pid: 7, name: "sleep", uid: 0, rss_kb: 2048, cmdline: "sleep 600" },
          { pid: 8, name: "bytes", uid: 1000, rss: 4096, cmdline: "bytes" },
        ],
      },
    });
    expect(response.ok).toBe(true);
    if (response.ok && response.result.type === "processes") {
      expect(response.result.processes).toEqual([
        {
          pid: 7,
          name: "sleep",
          uid: 0,
          rss: 2048 * 1024,
          cmdline: "sleep 600",
        },
        { pid: 8, name: "bytes", uid: 1000, rss: 4096, cmdline: "bytes" },
      ]);
    }
  });

  it("归一化日志来源：透传 target，size 缺失时保持 undefined", () => {
    const response = normalizeControlResponse({
      ok: true,
      result: {
        type: "log_sources",
        sources: [
          {
            id: "nginx-error",
            name: "Nginx 错误日志",
            kind: "file",
            target: "/var/log/nginx/error.log",
            size_bytes: 1234,
          },
          {
            id: "nginx-journal",
            name: "Nginx journal",
            kind: "journal",
            target: "nginx.service",
          },
        ],
      },
    });
    expect(response).toEqual({
      ok: true,
      result: {
        type: "log_sources",
        sources: [
          {
            id: "nginx-error",
            name: "Nginx 错误日志",
            kind: "file",
            target: "/var/log/nginx/error.log",
            size: 1234,
          },
          {
            id: "nginx-journal",
            name: "Nginx journal",
            kind: "journal",
            target: "nginx.service",
          },
        ],
      },
    });
  });

  it("原样保留动作输出并归一化退出码", () => {
    expect(
      normalizeControlResponse({
        ok: true,
        result: {
          type: "action_output",
          stdout: "done\n",
          stderr: "warn",
          exit_code: 3,
        },
      }),
    ).toEqual({
      ok: true,
      result: {
        type: "action_output",
        stdout: "done\n",
        stderr: "warn",
        exit_code: 3,
      },
    });

    expect(
      normalizeControlResponse({
        ok: true,
        result: { stdout: "ok", stderr: "", exit_code: null },
      }),
    ).toEqual({
      ok: true,
      result: { type: "action_output", stdout: "ok", stderr: "", exit_code: null },
    });
  });

  it("归一化日志行并过滤非字符串行", () => {
    expect(
      normalizeControlResponse({
        ok: true,
        result: {
          type: "log_lines",
          source: "nginx-error",
          lines: ["line-1", "line-2", 7, null],
          truncated: true,
          size_bytes: 4096,
        },
      }),
    ).toEqual({
      ok: true,
      result: {
        type: "log_lines",
        source: "nginx-error",
        lines: ["line-1", "line-2"],
        truncated: true,
        size_bytes: 4096,
      },
    });
  });

  it("把服务端错误体归一化成 ControlError", () => {
    expect(
      normalizeControlResponse({
        ok: false,
        error: { code: "not_whitelisted", message: "unit 不在白名单" },
      }),
    ).toEqual({
      ok: false,
      error: { code: "not_whitelisted", message: "unit 不在白名单" },
    });
  });

  it("未知结果类型与缺失 ok 均视为非法响应", () => {
    expect(
      normalizeControlResponse({ ok: true, result: { type: "bogus" } }),
    ).toMatchObject({
      ok: false,
      error: { code: "invalid_response" },
    });
    expect(normalizeControlResponse({ result: {} })).toMatchObject({
      ok: false,
      error: { code: "invalid_response" },
    });
    expect(normalizeControlResponse(null)).toMatchObject({
      ok: false,
      error: { code: "invalid_response" },
    });
  });
});

describe("控制错误文案", () => {
  it("覆盖 403 / 503 / 504 / 429 常见错误码", () => {
    expect(
      describeControlError({ code: "capability_disabled", message: "" }),
    ).toContain("未启用");
    expect(
      describeControlError({
        code: "not_whitelisted",
        message: "unit 不在白名单",
      }),
    ).toContain("unit 不在白名单");
    expect(
      describeControlError({ code: "agent_offline", message: "" }),
    ).toContain("不在线");
    expect(
      describeControlError({ code: "control_timeout", message: "" }),
    ).toContain("超时");
    expect(
      describeControlError({ code: "too_many_pending", message: "" }),
    ).toContain("待处理命令过多");
    expect(describeControlError({ code: "unknown_error", message: "" }, 504)).toContain(
      "超时",
    );
  });
});

describe("审计过滤参数编码", () => {
  it("默认 limit=100，且按固定顺序拼接", () => {
    expect(auditQueryParams()).toBe("limit=100");
    expect(
      auditQueryParams({
        limit: 100,
        beforeId: 41,
        agentId: "agent 1/测试",
        capability: "systemd",
      }),
    ).toBe(
      "limit=100&before_id=41&agent_id=agent+1%2F%E6%B5%8B%E8%AF%95&capability=systemd",
    );
  });

  it("空过滤值与未提供的 before_id 不写入查询串", () => {
    expect(auditQueryParams({ agentId: "   ", capability: "" })).toBe("limit=100");
    expect(auditQueryParams({ agentId: "hub-self" })).toBe(
      "limit=100&agent_id=hub-self",
    );
    // hub / 面板只接受正整数 before_id。
    expect(auditQueryParams({ beforeId: 0 })).toBe("limit=100");
    expect(auditQueryParams({ beforeId: 41 })).toBe("limit=100&before_id=41");
  });

  it("limit 限制在 1–100", () => {
    expect(auditQueryParams({ limit: 500 })).toBe("limit=100");
    expect(auditQueryParams({ limit: 0 })).toBe("limit=1");
    expect(auditQueryParams({ limit: Number.NaN })).toBe("limit=100");
  });

  it("优先使用服务端排他游标，缺失时回退最后一条 id（不减一）", () => {
    const entries = [auditEntry({ id: 50 }), auditEntry({ id: 42 })];
    expect(nextAuditBeforeId(entries, 42)).toBe(42);
    expect(nextAuditBeforeId(entries, 30)).toBe(30);
    expect(nextAuditBeforeId(entries)).toBe(42);
    expect(nextAuditBeforeId(entries, null)).toBeUndefined();
    expect(nextAuditBeforeId([], 7)).toBe(7);
    expect(nextAuditBeforeId([])).toBeUndefined();
  });

  it("满页的 next_before_id 直接作为下一页 before_id", () => {
    const page = normalizeAuditResponse({
      entries: [auditEntry({ id: 100 }), auditEntry({ id: 99 })],
      next_before_id: 99,
    });
    expect(page.next_before_id).toBe(99);
    expect(nextAuditBeforeId(page.entries, page.next_before_id)).toBe(99);
    expect(auditHasMore(page)).toBe(true);
  });
});

describe("审计响应归一化", () => {
  it("丢弃无效条目并保留 next_before_id", () => {
    const response = normalizeAuditResponse({
      entries: [
        auditEntry({ id: 2, error_code: "", error_message: "" }),
        { id: 0 },
        null,
        { actor: "admin" },
      ],
      next_before_id: 1,
    });
    expect(response.entries).toHaveLength(1);
    expect(response.entries[0].id).toBe(2);
    expect(response.next_before_id).toBe(1);
  });

  it("保留服务端明确返回的 null 游标，区分缺失与没有更多", () => {
    expect(
      normalizeAuditResponse({ entries: [auditEntry({ id: 2 })], next_before_id: null }),
    ).toEqual({
      entries: [auditEntry({ id: 2 })],
      next_before_id: null,
    });
    expect(normalizeAuditResponse({ entries: [] })).toEqual({ entries: [] });

    expect(auditHasMore({ entries: [auditEntry({ id: 2 })], next_before_id: null })).toBe(
      false,
    );
    expect(auditHasMore({ entries: [auditEntry({ id: 2 })], next_before_id: 2 })).toBe(true);
    expect(auditHasMore({ entries: [auditEntry({ id: 2 })] }, 1)).toBe(true);
    expect(auditHasMore({ entries: [] })).toBe(false);
  });

  it("结果与错误列展示", () => {
    expect(auditResultClass("ok")).toBe("result-ok");
    expect(auditResultClass("denied")).toBe("result-denied");
    expect(auditResultClass("error")).toBe("result-error");
    expect(auditResultClass("weird")).toBe("result-unknown");
    expect(
      auditErrorText({ error_code: "not_whitelisted", error_message: "拒绝" }),
    ).toBe("not_whitelisted：拒绝");
    expect(auditErrorText({ error_code: "", error_message: "" })).toBe("");
  });
});

describe("时间与耗时格式化边界", () => {
  it("审计时间兼容秒与毫秒，零值/非法值显示占位", () => {
    expect(formatAuditTime(0)).toBe("—");
    expect(formatAuditTime(-1)).toBe("—");
    expect(formatAuditTime(Number.NaN)).toBe("—");
    expect(formatAuditTime(1_700_000_000)).toBe(
      formatDateTime(1_700_000_000_000),
    );
    expect(formatAuditTime(1_700_000_000_000)).toBe(
      formatDateTime(1_700_000_000_000),
    );
  });

  it("耗时在毫秒 / 秒 / 分钟边界切换", () => {
    expect(formatDuration(0)).toBe("0 ms");
    expect(formatDuration(999)).toBe("999 ms");
    expect(formatDuration(1000)).toBe("1.0 s");
    expect(formatDuration(1500)).toBe("1.5 s");
    expect(formatDuration(59_999)).toBe("1m 0s");
    expect(formatDuration(60_000)).toBe("1m 0s");
    expect(formatDuration(119_600)).toBe("2m 0s");
    expect(formatDuration(3_600_000)).toBe("1.0 h");
    expect(formatDuration(-1)).toBe("—");
    expect(formatDuration(Number.NaN)).toBe("—");
  });
});
