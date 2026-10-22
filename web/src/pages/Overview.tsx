import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, describeError } from "../api";
import {
  formatDateTime,
  formatInterval,
  formatPercent,
  formatRelativeTime,
  ratioPercent,
  statusClass,
} from "../format";
import { isAbortError } from "../rate";
import type { LatestSample, OverviewResponse } from "../types";

interface AgentCardData {
  id: string;
  name: string;
  hostname: string;
  status: string;
  statusLabel: string;
  lastSeen: string;
  cpu: number | null;
  memory: number | null;
  disk: number | null;
  interval: number | null;
}

function labelsFs(labels: Record<string, string>): string {
  return labels.fs ?? "";
}

function findValue(samples: LatestSample[], metric: string): number | null {
  const sample = samples.find((row) => row.metric === metric);
  return sample && Number.isFinite(sample.value) ? sample.value : null;
}

/** 最高磁盘使用率：disk.used 与 disk.total 的 label 集合不同，只能按 mount 关联。 */
export function highestDiskUsage(samples: LatestSample[]): number | null {
  const used = samples.filter((row) => row.metric === "disk.used");
  const total = samples.filter((row) => row.metric === "disk.total");
  let highest: number | null = null;
  for (const usedRow of used) {
    const totalRow =
      total.find(
        (row) =>
          row.labels.mount === usedRow.labels.mount &&
          labelsFs(row.labels) === labelsFs(usedRow.labels),
      ) ?? total.find((row) => row.labels.mount === usedRow.labels.mount);
    if (!totalRow || !Number.isFinite(totalRow.value) || totalRow.value <= 0) continue;
    const percent = ratioPercent(usedRow.value, totalRow.value);
    if (percent !== null && (highest === null || percent > highest)) highest = percent;
  }
  return highest;
}

function statusLabel(status: string): string {
  switch (status.toLowerCase()) {
    case "online":
      return "在线";
    case "offline":
      return "离线";
    case "revoked":
      return "已吊销";
    default:
      return status || "未知";
  }
}

export function buildAgentCards(overview: OverviewResponse): AgentCardData[] {
  const latestByAgent = new Map<string, LatestSample[]>();
  for (const sample of overview.latest) {
    const list = latestByAgent.get(sample.agent_id) ?? [];
    list.push(sample);
    latestByAgent.set(sample.agent_id, list);
  }
  const intervalByAgent = new Map(
    overview.settings.map((setting) => [setting.agent_id, setting.sample_interval_ms]),
  );
  // server_time 按毫秒约定；若上游给了 0 或秒级值，回退到本机时钟。
  const now = overview.server_time > 1_000_000_000_000 ? overview.server_time : Date.now();

  return overview.agents
    .map((agent) => {
      const samples = latestByAgent.get(agent.agent_id) ?? [];
      const memoryUsed = findValue(samples, "mem.used");
      const memoryTotal = findValue(samples, "mem.total");
      return {
        id: agent.agent_id,
        name: agent.name || agent.hostname || agent.agent_id,
        hostname: agent.hostname,
        status: agent.status,
        statusLabel: statusLabel(agent.status),
        lastSeen:
          agent.last_seen_at > 0 ? formatRelativeTime(agent.last_seen_at, now) : "从未上报",
        cpu: findValue(samples, "cpu.usage"),
        memory:
          memoryUsed !== null && memoryTotal !== null
            ? ratioPercent(memoryUsed, memoryTotal)
            : null,
        disk: highestDiskUsage(samples),
        interval: intervalByAgent.get(agent.agent_id) ?? null,
      };
    })
    .sort((a, b) => {
      const aOnline = a.status.toLowerCase() === "online" ? 0 : 1;
      const bOnline = b.status.toLowerCase() === "online" ? 0 : 1;
      return aOnline - bOnline || a.name.localeCompare(b.name);
    });
}

export default function OverviewPage() {
  const [data, setData] = useState<OverviewResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [lastUpdated, setLastUpdated] = useState<number | null>(null);

  useEffect(() => {
    let disposed = false;
    let controller: AbortController | null = null;

    const load = async (initial: boolean) => {
      controller?.abort();
      controller = new AbortController();
      if (initial) setLoading(true);
      try {
        const overview = await api.overview(controller.signal);
        if (disposed) return;
        setData(overview);
        setError(null);
        setLastUpdated(Date.now());
      } catch (loadError) {
        if (disposed || isAbortError(loadError)) return;
        setError(describeError(loadError));
      } finally {
        if (!disposed) setLoading(false);
      }
    };

    void load(true);
    const timer = window.setInterval(() => void load(false), 30_000);
    return () => {
      disposed = true;
      controller?.abort();
      window.clearInterval(timer);
    };
  }, [reloadKey]);

  const cards = useMemo(() => (data ? buildAgentCards(data) : []), [data]);
  const online = cards.filter((card) => card.status.toLowerCase() === "online").length;

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>服务器概览</h1>
          <p className="muted">
            {cards.length} 台机器 · {online} 台在线
            {lastUpdated ? ` · 更新于 ${formatDateTime(lastUpdated)}` : ""}
          </p>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="button"
            onClick={() => setReloadKey((value) => value + 1)}
            disabled={loading}
          >
            {loading ? "刷新中…" : "刷新"}
          </button>
        </div>
      </header>

      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
          <button type="button" className="button small" onClick={() => setReloadKey((k) => k + 1)}>
            重试
          </button>
        </div>
      ) : null}

      {loading && !data ? (
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          正在加载机器列表…
        </div>
      ) : null}

      {!loading && cards.length === 0 ? (
        <div className="empty-state">
          <h2>还没有机器</h2>
          <p className="muted">
            先在 hub 上执行 <code>rustboard-hub agent add</code> 纳管一台服务器，数据会出现在这里。
          </p>
        </div>
      ) : null}

      <section className="agent-grid" aria-live="polite">
        {cards.map((card) => (
          <Link
            key={card.id}
            className="agent-card"
            to={`/agents/${encodeURIComponent(card.id)}`}
          >
            <div className="agent-card-head">
              <span className={`status-dot ${statusClass(card.status)}`} aria-hidden="true" />
              <div className="agent-title">
                <h2>{card.name}</h2>
                <p className="muted mono">
                  {card.hostname || "未知 hostname"} · {card.id}
                </p>
              </div>
              <span className={`status-pill ${statusClass(card.status)}`}>
                {card.statusLabel}
              </span>
            </div>
            <dl className="metric-grid">
              <div>
                <dt>CPU</dt>
                <dd>{formatPercent(card.cpu)}</dd>
              </div>
              <div>
                <dt>内存</dt>
                <dd>{formatPercent(card.memory)}</dd>
              </div>
              <div>
                <dt>最高磁盘</dt>
                <dd>{formatPercent(card.disk)}</dd>
              </div>
              <div>
                <dt>采样间隔</dt>
                <dd>{card.interval === null ? "—" : formatInterval(card.interval)}</dd>
              </div>
            </dl>
            <div className="agent-card-foot">
              <span>最近上报：{card.lastSeen}</span>
              <span>查看详情 →</span>
            </div>
          </Link>
        ))}
      </section>

      <p className="poll-note muted">每 30 秒自动刷新</p>
    </div>
  );
}
