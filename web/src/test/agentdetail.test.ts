import { describe, expect, it } from "vitest";
import { presetRange, refreshRange } from "../pages/AgentDetail";

/** 固定时钟：T0 进入页面，T1 等待新样本后刷新。 */
const T0 = 1_700_000_000_000;
const T1 = T0 + 7 * 60_000;
const HOUR = 3_600_000;

describe("节点详情刷新时间窗口 (#37)", () => {
  it("初始化用 T0；刷新后预设窗口的 to 更新为 T1", () => {
    const initial = presetRange("1h", T0);
    expect(initial).toEqual({ from: T0 - HOUR, to: T0 });

    const refreshed = refreshRange("1h", initial, T1);
    expect(refreshed).toEqual({ from: T1 - HOUR, to: T1 });
    expect(refreshed.to).toBe(T1);
  });

  it("自定义范围刷新后保持用户选择的时间段", () => {
    const custom = { from: T0 - 12_345, to: T0 - 1 };
    const refreshed = refreshRange("custom", custom, T1);
    expect(refreshed).toBe(custom);
    expect(refreshed).toEqual(custom);
  });

  it("加载失败后重试使用新的当前时间，而不是失败请求的旧窗口", () => {
    // 重试按钮与刷新按钮共用 refreshRange：失败发生在 T0 的请求上，
    // 重试时（T1）必须重新计算，而不是沿用失败请求的 to=T0。
    const failedRange = presetRange("24h", T0);
    const retryRange = refreshRange("24h", failedRange, T1);
    expect(retryRange.to).toBe(T1);
    expect(retryRange.from).toBe(T1 - 24 * HOUR);
  });

  it("多次刷新按当前时间重算，不累积偏移", () => {
    let range = presetRange("6h", T0);
    for (const now of [T0 + 60_000, T0 + 120_000, T1]) {
      range = refreshRange("6h", range, now);
      expect(range.to - range.from).toBe(6 * HOUR);
      expect(range.to).toBe(now);
    }
    expect(range).toEqual({ from: T1 - 6 * HOUR, to: T1 });
  });

  it("365 天预设同样按刷新时刻整体平移", () => {
    const old = presetRange("365d", T0);
    const refreshed = refreshRange("365d", old, T1);
    expect(refreshed).toEqual({
      from: T1 - 365 * 24 * HOUR,
      to: T1,
    });
  });
});
