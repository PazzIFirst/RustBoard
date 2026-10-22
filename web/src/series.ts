import { BYTES_PER_MIB } from "./format";
import { computeRates, latestValue } from "./rate";
import type { SamplePoint, SeriesPoint } from "./types";

export interface NamedSeries {
  label: string;
  points: SamplePoint[];
}

export function seriesByMetric(series: SeriesPoint[], metric: string): SeriesPoint[] {
  return series.filter((row) => row.metric === metric);
}

function convert(series: SeriesPoint, fn: (value: number) => number): NamedSeries[] {
  const points = series.points
    .filter((point) => Number.isFinite(point.ts) && Number.isFinite(point.value))
    .map((point) => ({ ts: point.ts, value: fn(point.value) }));
  return points.length > 0 ? [{ label: series.metric, points }] : [];
}

export function buildCpuSeries(series: SeriesPoint[]): NamedSeries[] {
  return [
    ...seriesByMetric(series, "cpu.usage").flatMap((row) =>
      convert(row, (value) => value),
    ).map((row) => ({ ...row, label: "CPU 使用率" })),
    ...seriesByMetric(series, "cpu.iowait").flatMap((row) =>
      convert(row, (value) => value),
    ).map((row) => ({ ...row, label: "iowait" })),
  ];
}

export function buildMemorySeries(series: SeriesPoint[]): NamedSeries[] {
  const definitions: Array<[string, string]> = [
    ["mem.used", "已用内存"],
    ["mem.total", "总内存"],
    ["swap.used", "Swap 已用"],
  ];
  return definitions.flatMap(([metric, label]) =>
    seriesByMetric(series, metric)
      .flatMap((row) => convert(row, (value) => value / BYTES_PER_MIB))
      .map((row) => ({ ...row, label })),
  );
}

/** 每对 (mount, fs) 一条百分比曲线；used/total 的 label 集合不同，只能按字段关联。 */
export function buildDiskSeries(series: SeriesPoint[]): NamedSeries[] {
  const totals = seriesByMetric(series, "disk.total");
  const result: NamedSeries[] = [];
  for (const used of seriesByMetric(series, "disk.used")) {
    const mount = used.labels.mount ?? "unknown";
    const fs = used.labels.fs;
    const total =
      totals.find(
        (row) =>
          row.labels.mount === used.labels.mount &&
          (row.labels.fs === fs || row.labels.fs === undefined || fs === undefined),
      ) ?? totals.find((row) => row.labels.mount === used.labels.mount);
    if (!total) continue;
    const totalByTs = new Map(total.points.map((point) => [point.ts, point.value]));
    const points = used.points.flatMap((point) => {
      const capacity = totalByTs.get(point.ts);
      if (capacity === undefined || !Number.isFinite(capacity) || capacity <= 0) {
        return [];
      }
      return [{ ts: point.ts, value: (point.value / capacity) * 100 }];
    });
    if (points.length === 0) continue;
    result.push({ label: fs ? `${mount} · ${fs}` : mount, points });
  }
  return result.sort((a, b) => a.label.localeCompare(b.label));
}

export function buildNetworkSeries(series: SeriesPoint[]): NamedSeries[] {
  const rx = seriesByMetric(series, "net.rx_bytes");
  const tx = seriesByMetric(series, "net.tx_bytes");
  const interfaces = new Set<string>();
  for (const row of [...rx, ...tx]) interfaces.add(row.labels.if ?? "unknown");
  const result: NamedSeries[] = [];
  for (const name of [...interfaces].sort()) {
    const rxRow = rx.find((row) => (row.labels.if ?? "unknown") === name);
    const txRow = tx.find((row) => (row.labels.if ?? "unknown") === name);
    if (rxRow) {
      const points = computeRates(rxRow.points);
      if (points.length > 0) result.push({ label: `${name} ↓`, points });
    }
    if (txRow) {
      const points = computeRates(txRow.points);
      if (points.length > 0) result.push({ label: `${name} ↑`, points });
    }
  }
  return result;
}

export interface InterfaceTotals {
  name: string;
  rx: number | null;
  tx: number | null;
}

/** 每块网卡的累计收/发字节（用最新样本，不做差分）。 */
export function latestInterfaceTotals(series: SeriesPoint[]): InterfaceTotals[] {
  const names = new Set<string>();
  for (const row of [...seriesByMetric(series, "net.rx_bytes"), ...seriesByMetric(series, "net.tx_bytes")]) {
    names.add(row.labels.if ?? "unknown");
  }
  return [...names]
    .sort()
    .map((name) => {
      const rx = seriesByMetric(series, "net.rx_bytes").find(
        (row) => (row.labels.if ?? "unknown") === name,
      );
      const tx = seriesByMetric(series, "net.tx_bytes").find(
        (row) => (row.labels.if ?? "unknown") === name,
      );
      return {
        name,
        rx: rx ? latestValue(rx.points) : null,
        tx: tx ? latestValue(tx.points) : null,
      };
    });
}
