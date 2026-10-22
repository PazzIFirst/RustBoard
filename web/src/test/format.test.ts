import { describe, expect, it } from "vitest";
import {
  formatAxisTime,
  formatBytes,
  formatInterval,
  formatMiB,
  formatPercent,
  formatRate,
  formatRelativeTime,
  parseDateTimeLocal,
  ratioPercent,
  statusClass,
  toDateTimeLocal,
} from "../format";

describe("formatBytes / formatRate", () => {
  it("formats bytes with binary units", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1023 B");
    expect(formatBytes(1024)).toBe("1.0 KiB");
    expect(formatBytes(1536)).toBe("1.5 KiB");
    expect(formatBytes(5 * 1024 ** 3)).toBe("5.0 GiB");
    expect(formatBytes(-2048)).toBe("-2.0 KiB");
    expect(formatBytes(Number.NaN)).toBe("—");
  });

  it("formats rates and MiB labels", () => {
    expect(formatRate(2048)).toBe("2.0 KiB/s");
    expect(formatRate(0)).toBe("0 B/s");
    expect(formatRate(Number.POSITIVE_INFINITY)).toBe("—");
    expect(formatMiB(512)).toBe("512 MiB");
    expect(formatMiB(Number.NaN)).toBe("—");
  });
});

describe("percent / interval", () => {
  it("computes ratios and rejects zero totals", () => {
    expect(ratioPercent(50, 100)).toBe(50);
    expect(ratioPercent(1, 0)).toBeNull();
    expect(ratioPercent(1, -1)).toBeNull();
    expect(ratioPercent(Number.NaN, 1)).toBeNull();
    expect(formatPercent(12.345)).toBe("12.3%");
    expect(formatPercent(null)).toBe("—");
    expect(formatPercent(undefined)).toBe("—");
  });

  it("formats sampling intervals compactly", () => {
    expect(formatInterval(1000)).toBe("1s");
    expect(formatInterval(5000)).toBe("5s");
    expect(formatInterval(60_000)).toBe("1m");
    expect(formatInterval(300_000)).toBe("5m");
    expect(formatInterval(3_600_000)).toBe("1h");
    expect(formatInterval(1500)).toBe("1500ms");
    expect(formatInterval(0)).toBe("—");
  });
});

describe("relative time", () => {
  const now = 1_700_000_000_000;

  it("handles just-now, seconds, minutes, hours and days", () => {
    expect(formatRelativeTime(now, now)).toBe("刚刚");
    expect(formatRelativeTime(now + 5000, now)).toBe("刚刚");
    expect(formatRelativeTime(now - 30_000, now)).toBe("30 秒前");
    expect(formatRelativeTime(now - 90_000, now)).toBe("1 分钟前");
    expect(formatRelativeTime(now - 2 * 3_600_000, now)).toBe("2 小时前");
    expect(formatRelativeTime(now - 3 * 86_400_000, now)).toBe("3 天前");
    expect(formatRelativeTime(Number.NaN, now)).toBe("—");
  });

  it("falls back to an absolute date after 30 days", () => {
    const text = formatRelativeTime(now - 40 * 86_400_000, now);
    expect(text).toMatch(/^\d{4}-\d{2}-\d{2} /);
  });
});

describe("input helpers", () => {
  it("round-trips datetime-local at minute precision", () => {
    const ms = new Date(2026, 0, 2, 3, 4).getTime();
    expect(parseDateTimeLocal(toDateTimeLocal(ms))).toBe(ms);
    expect(parseDateTimeLocal("")).toBeNull();
    expect(parseDateTimeLocal("not-a-date")).toBeNull();
  });

  it("maps statuses to fixed CSS classes", () => {
    expect(statusClass("online")).toBe("status-online");
    expect(statusClass("OFFLINE")).toBe("status-offline");
    expect(statusClass("revoked")).toBe("status-revoked");
    expect(statusClass("weird").length).toBeGreaterThan(0);
    expect(statusClass("<script>")).toBe("status-unknown");
  });

  it("formats axis labels for different spans", () => {
    expect(formatAxisTime(1_700_000_000, 3600)).toMatch(/^\d{2}:\d{2}$/);
    expect(formatAxisTime(1_700_000_000, 7 * 86_400)).toMatch(/^\d{2}-\d{2}$/);
    expect(formatAxisTime(Number.NaN, 3600)).toBe("");
  });
});
