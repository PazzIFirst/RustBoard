import type { SamplePoint } from "./types";

/**
 * 由累计计数器计算速率（单位/秒）。
 *
 * - 相邻点按时间排序后差分；
 * - 计数器回绕/重置（增量为负）、时间戳重复/回退一律按 0 处理；
 * - 首个点没有前一个样本，不产生速率点。
 */
export function computeRates(points: SamplePoint[]): SamplePoint[] {
  const sorted = points
    .filter((point) => Number.isFinite(point.ts) && Number.isFinite(point.value))
    .slice()
    .sort((a, b) => a.ts - b.ts);
  const rates: SamplePoint[] = [];
  for (let index = 1; index < sorted.length; index += 1) {
    const previous = sorted[index - 1];
    const current = sorted[index];
    const deltaMs = current.ts - previous.ts;
    const deltaValue = current.value - previous.value;
    if (deltaMs <= 0 || deltaValue < 0) {
      rates.push({ ts: current.ts, value: 0 });
    } else {
      rates.push({ ts: current.ts, value: (deltaValue * 1000) / deltaMs });
    }
  }
  return rates;
}

/** 最后一个有效样本；空数组或全为非法值返回 null。 */
export function latestValue(points: SamplePoint[]): number | null {
  let latest: SamplePoint | null = null;
  for (const point of points) {
    if (!Number.isFinite(point.ts) || !Number.isFinite(point.value)) continue;
    if (latest === null || point.ts > latest.ts) latest = point;
  }
  return latest ? latest.value : null;
}

/** 判断错误是否来自 AbortController；组件据此静默丢弃过期请求。 */
export function isAbortError(error: unknown): boolean {
  return (
    error instanceof DOMException && error.name === "AbortError"
  ) || (error instanceof Error && error.name === "AbortError");
}
