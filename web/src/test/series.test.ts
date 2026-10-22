import { describe, expect, it } from "vitest";
import {
  buildCpuSeries,
  buildDiskSeries,
  buildMemorySeries,
  buildNetworkSeries,
  latestInterfaceTotals,
} from "../series";
import type { SeriesPoint } from "../types";

const diskUsed: SeriesPoint = {
  metric: "disk.used",
  labels: { mount: "/", fs: "ext4" },
  points: [{ ts: 1000, value: 50 }],
};
const diskTotal: SeriesPoint = {
  metric: "disk.total",
  labels: { mount: "/", fs: "ext4", dev: "/dev/sda1" },
  points: [{ ts: 1000, value: 200 }],
};

describe("disk series", () => {
  it("joins used/total by mount even when label sets differ", () => {
    const rows = buildDiskSeries([diskUsed, diskTotal]);
    expect(rows).toHaveLength(1);
    expect(rows[0].label).toBe("/ · ext4");
    expect(rows[0].points[0].value).toBe(25);
  });

  it("skips mounts without a matching total or with zero capacity", () => {
    expect(buildDiskSeries([diskUsed])).toEqual([]);
    expect(
      buildDiskSeries([
        diskUsed,
        { ...diskTotal, points: [{ ts: 1000, value: 0 }] },
      ]),
    ).toEqual([]);
    expect(
      buildDiskSeries([
        { ...diskUsed, labels: { mount: "/data" } },
        diskTotal,
      ]),
    ).toEqual([]);
  });
});

describe("memory / cpu series", () => {
  it("converts bytes to MiB and labels the metrics", () => {
    const rows = buildMemorySeries([
      {
        metric: "mem.total",
        labels: {},
        points: [{ ts: 1, value: 8 * 1024 * 1024 * 1024 }],
      },
      { metric: "mem.used", labels: {}, points: [{ ts: 1, value: 2 * 1024 * 1024 * 1024 }] },
      { metric: "swap.used", labels: {}, points: [] },
    ]);
    expect(rows.map((row) => row.label)).toEqual(["已用内存", "总内存"]);
    expect(rows[0].points[0].value).toBe(2048);
    expect(rows[1].points[0].value).toBe(8192);
  });

  it("labels CPU usage and iowait", () => {
    const rows = buildCpuSeries([
      { metric: "cpu.usage", labels: {}, points: [{ ts: 1, value: 12 }] },
      { metric: "cpu.iowait", labels: {}, points: [{ ts: 1, value: 3 }] },
    ]);
    expect(rows.map((row) => row.label)).toEqual(["CPU 使用率", "iowait"]);
  });
});

describe("network series", () => {
  const rx: SeriesPoint = {
    metric: "net.rx_bytes",
    labels: { if: "eth0" },
    points: [
      { ts: 1000, value: 1000 },
      { ts: 2000, value: 3000 },
    ],
  };
  const tx: SeriesPoint = {
    metric: "net.tx_bytes",
    labels: { if: "eth0" },
    points: [
      { ts: 1000, value: 5000 },
      { ts: 2000, value: 4000 },
    ],
  };

  it("computes per-interface rates and zeroes counter resets", () => {
    const rows = buildNetworkSeries([rx, tx]);
    expect(rows.map((row) => row.label)).toEqual(["eth0 ↓", "eth0 ↑"]);
    expect(rows[0].points).toEqual([{ ts: 2000, value: 2000 }]);
    expect(rows[1].points).toEqual([{ ts: 2000, value: 0 }]);
  });

  it("reports latest cumulative bytes per interface", () => {
    expect(latestInterfaceTotals([rx, tx])).toEqual([
      { name: "eth0", rx: 3000, tx: 4000 },
    ]);
    expect(latestInterfaceTotals([])).toEqual([]);
  });
});
