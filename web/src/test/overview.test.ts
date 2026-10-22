import { describe, expect, it } from "vitest";
import { buildAgentCards, highestDiskUsage } from "../pages/Overview";
import type { OverviewResponse } from "../types";

const overview: OverviewResponse = {
  server_time: 1_700_000_000_000,
  agents: [
    {
      agent_id: "agent-1",
      name: "web-1",
      hostname: "web-1.local",
      os: "Linux",
      arch: "x86_64",
      version: "0.1.0",
      boot_id: "boot",
      status: "online",
      last_seen_at: 1_700_000_000_000 - 5000,
      created_at: 1,
    },
  ],
  latest: [
    {
      agent_id: "agent-1",
      metric: "cpu.usage",
      labels: {},
      ts: 1,
      value: 12.5,
    },
    {
      agent_id: "agent-1",
      metric: "mem.used",
      labels: {},
      ts: 1,
      value: 2 * 1024 ** 3,
    },
    {
      agent_id: "agent-1",
      metric: "mem.total",
      labels: {},
      ts: 1,
      value: 8 * 1024 ** 3,
    },
    {
      agent_id: "agent-1",
      metric: "disk.used",
      labels: { mount: "/", fs: "ext4" },
      ts: 1,
      value: 100,
    },
    {
      agent_id: "agent-1",
      metric: "disk.total",
      labels: { mount: "/", fs: "ext4", dev: "/dev/sda" },
      ts: 1,
      value: 200,
    },
    {
      agent_id: "agent-1",
      metric: "disk.used",
      labels: { mount: "/data", fs: "xfs" },
      ts: 1,
      value: 30,
    },
    {
      agent_id: "agent-1",
      metric: "disk.total",
      labels: { mount: "/data", fs: "xfs", dev: "/dev/sdb" },
      ts: 1,
      value: 300,
    },
  ],
  settings: [{ agent_id: "agent-1", sample_interval_ms: 5000 }],
};

describe("overview cards", () => {
  it("computes the highest disk usage across mounts and memory percent", () => {
    expect(highestDiskUsage(overview.latest)).toBe(50);

    const cards = buildAgentCards(overview);
    expect(cards).toHaveLength(1);
    expect(cards[0]).toMatchObject({
      id: "agent-1",
      name: "web-1",
      cpu: 12.5,
      memory: 25,
      disk: 50,
      interval: 5000,
      statusLabel: "在线",
    });
  });

  it("falls back to hostname when name is empty", () => {
    const cards = buildAgentCards({
      ...overview,
      agents: [{ ...overview.agents[0], name: "" }],
    });
    expect(cards[0].name).toBe("web-1.local");
  });
});
