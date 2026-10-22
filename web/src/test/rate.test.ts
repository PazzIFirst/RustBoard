import { describe, expect, it } from "vitest";
import { computeRates, isAbortError, latestValue } from "../rate";

describe("computeRates", () => {
  it("derives bytes-per-second from adjacent counter samples", () => {
    const rates = computeRates([
      { ts: 1000, value: 1000 },
      { ts: 2000, value: 3000 },
      { ts: 4000, value: 9000 },
    ]);
    expect(rates).toEqual([
      { ts: 2000, value: 2000 },
      { ts: 4000, value: 3000 },
    ]);
  });

  it("treats counter resets, duplicate timestamps and bad values as zero", () => {
    const rates = computeRates([
      { ts: 1000, value: 5000 },
      { ts: 2000, value: 1000 },
      { ts: 2000, value: 4000 },
      { ts: 3000, value: Number.NaN },
      { ts: 4000, value: 9000 },
    ]);
    expect(rates[0]).toEqual({ ts: 2000, value: 0 });
    expect(rates[1]).toEqual({ ts: 2000, value: 0 });
    // NaN 样本被过滤，4000ms 的点与 2000ms 的有效点相差 5000
    expect(rates[2]).toEqual({ ts: 4000, value: 2500 });
  });

  it("sorts unsorted input and handles empty/single-point series", () => {
    expect(computeRates([])).toEqual([]);
    expect(computeRates([{ ts: 1, value: 1 }])).toEqual([]);
    const rates = computeRates([
      { ts: 3000, value: 300 },
      { ts: 1000, value: 100 },
      { ts: 2000, value: 200 },
    ]);
    expect(rates).toEqual([
      { ts: 2000, value: 100 },
      { ts: 3000, value: 100 },
    ]);
  });
});

describe("latestValue", () => {
  it("returns the last valid sample", () => {
    expect(latestValue([])).toBeNull();
    expect(latestValue([{ ts: 100, value: 1 }, { ts: 300, value: 3 }, { ts: 200, value: 2 }])).toBe(
      3,
    );
    expect(latestValue([{ ts: 1, value: Number.NaN }])).toBeNull();
  });
});

describe("isAbortError", () => {
  it("recognizes AbortController errors but not ordinary errors", () => {
    expect(isAbortError(new DOMException("aborted", "AbortError"))).toBe(true);
    expect(isAbortError(new Error("AbortError"))).toBe(false);
    expect(isAbortError("AbortError")).toBe(false);
  });
});
