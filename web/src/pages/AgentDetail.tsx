import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { Link, useParams } from "react-router-dom";
import { api, describeError } from "../api";
import Chart, { type ChartSeries } from "../components/Chart";
import {
  formatBytes,
  formatDateTime,
  formatInterval,
  formatMiB,
  formatPercent,
  formatRate,
  parseDateTimeLocal,
  toDateTimeLocal,
} from "../format";
import { isAbortError } from "../rate";
import {
  buildCpuSeries,
  buildDiskSeries,
  buildMemorySeries,
  buildNetworkSeries,
  latestInterfaceTotals,
  type NamedSeries,
} from "../series";
import type { AgentSetting, SeriesResponse } from "../types";

const SERIES_METRICS = [
  "cpu.usage",
  "cpu.iowait",
  "mem.used",
  "mem.total",
  "swap.used",
  "disk.used",
  "disk.total",
  "net.rx_bytes",
  "net.tx_bytes",
];

const PRESET_RANGES = [
  { key: "1h", label: "1 小时", ms: 3_600_000 },
  { key: "6h", label: "6 小时", ms: 6 * 3_600_000 },
  { key: "24h", label: "24 小时", ms: 24 * 3_600_000 },
  { key: "7d", label: "7 天", ms: 7 * 24 * 3_600_000 },
] as const;

type PresetKey = (typeof PRESET_RANGES)[number]["key"];
type RangeKey = PresetKey | "custom";

const MAX_RANGE_MS = 32 * 24 * 3_600_000;

const CPU_COLORS = ["#58a6ff", "#d29922"];
const MEMORY_COLORS = ["#58a6ff", "#8b949e", "#bc8cff"];
const DISK_COLORS = ["#3fb950", "#58a6ff", "#d29922", "#f85149", "#bc8cff", "#39c5cf"];
const NETWORK_COLORS = ["#3fb950", "#58a6ff", "#d29922", "#f85149"];

interface Range {
  from: number;
  to: number;
}

function presetRange(key: PresetKey): Range {
  const preset = PRESET_RANGES.find((row) => row.key === key) ?? PRESET_RANGES[0];
  const to = Date.now();
  return { from: to - preset.ms, to };
}

function colorize(rows: NamedSeries[], palette: readonly string[]): ChartSeries[] {
  return rows.map((row, index) => ({
    ...row,
    color: palette[index % palette.length] ?? "#58a6ff",
  }));
}

export default function AgentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const agentId = id ?? "";

  const initialRange = useMemo(() => presetRange("1h"), []);
  const [rangeKey, setRangeKey] = useState<RangeKey>("1h");
  const lastPresetRef = useRef<PresetKey>("1h");
  const [queryRange, setQueryRange] = useState<Range>(initialRange);
  const [customFrom, setCustomFrom] = useState(() => toDateTimeLocal(initialRange.from));
  const [customTo, setCustomTo] = useState(() => toDateTimeLocal(initialRange.to));
  const [rangeError, setRangeError] = useState<string | null>(null);

  const [data, setData] = useState<SeriesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const [settings, setSettings] = useState<AgentSetting | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [settingsReload, setSettingsReload] = useState(0);
  const [intervalInput, setIntervalInput] = useState("5000");
  const [saving, setSaving] = useState(false);
  const [saveState, setSaveState] = useState<{ kind: "ok" | "error"; text: string } | null>(
    null,
  );

  useEffect(() => {
    if (!agentId) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    setData(null);
    api
      .series(
        agentId,
        { metrics: SERIES_METRICS, from: queryRange.from, to: queryRange.to },
        controller.signal,
      )
      .then((result) => {
        if (!controller.signal.aborted) setData(result);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        setError(describeError(loadError));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [agentId, queryRange, reloadKey]);

  useEffect(() => {
    if (!agentId) return;
    const controller = new AbortController();
    setSettingsError(null);
    api
      .settings(agentId, controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) setSettings(value);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        setSettingsError(describeError(loadError));
      });
    return () => controller.abort();
  }, [agentId, settingsReload]);

  useEffect(() => {
    if (settings) setIntervalInput(String(settings.sample_interval_ms));
  }, [settings]);

  const applyPreset = useCallback((key: PresetKey) => {
    const range = presetRange(key);
    lastPresetRef.current = key;
    setRangeKey(key);
    setQueryRange(range);
    setCustomFrom(toDateTimeLocal(range.from));
    setCustomTo(toDateTimeLocal(range.to));
    setRangeError(null);
  }, []);

  const applyCustom = () => {
    const from = parseDateTimeLocal(customFrom);
    const to = parseDateTimeLocal(customTo);
    if (from === null || to === null) {
      setRangeError("请选择完整的开始与结束时间");
      return;
    }
    if (from >= to) {
      setRangeError("开始时间必须早于结束时间");
      return;
    }
    if (to - from > MAX_RANGE_MS) {
      setRangeError("时间跨度不能超过 32 天");
      return;
    }
    setRangeError(null);
    setRangeKey("custom");
    setQueryRange({ from, to });
  };

  const handleZoom = useCallback((from: number, to: number) => {
    if (!Number.isFinite(from) || !Number.isFinite(to) || to - from < 1000) return;
    const range = { from: Math.round(from), to: Math.round(to) };
    setRangeKey("custom");
    setQueryRange(range);
    setCustomFrom(toDateTimeLocal(range.from));
    setCustomTo(toDateTimeLocal(range.to));
    setRangeError(null);
  }, []);

  const handleReset = useCallback(() => {
    // 缩放后回到缩放前的预设范围；若本来就在自定义范围，则回到最近一次预设。
    const key: PresetKey = rangeKey === "custom" ? lastPresetRef.current : rangeKey;
    applyPreset(key);
  }, [applyPreset, rangeKey]);

  const cpuSeries = useMemo(
    () => colorize(buildCpuSeries(data?.series ?? []), CPU_COLORS),
    [data],
  );
  const memorySeries = useMemo(
    () => colorize(buildMemorySeries(data?.series ?? []), MEMORY_COLORS),
    [data],
  );
  const diskSeries = useMemo(
    () => colorize(buildDiskSeries(data?.series ?? []), DISK_COLORS),
    [data],
  );
  const networkSeries = useMemo(
    () => colorize(buildNetworkSeries(data?.series ?? []), NETWORK_COLORS),
    [data],
  );
  const interfaceTotals = useMemo(
    () => latestInterfaceTotals(data?.series ?? []),
    [data],
  );

  const saveInterval = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!agentId || saving) return;
    const value = Number(intervalInput);
    if (!Number.isInteger(value) || value < 1000 || value > 300_000) {
      setSaveState({ kind: "error", text: "采样间隔必须是 1000–300000 之间的整数（毫秒）" });
      return;
    }
    setSaving(true);
    setSaveState(null);
    try {
      const updated = await api.updateSettings(agentId, value);
      setSettings({
        agent_id: updated?.agent_id ?? agentId,
        sample_interval_ms: updated?.sample_interval_ms ?? value,
      });
      setSaveState({
        kind: "ok",
        text: "已提交。hub 会通知该 agent 重连，最多 60 秒后按新间隔采样。",
      });
    } catch (saveError) {
      setSaveState({ kind: "error", text: describeError(saveError) });
    } finally {
      setSaving(false);
    }
  };

  if (!agentId) {
    return (
      <div className="page">
        <div className="banner error">缺少 agent id</div>
        <Link className="button" to="/">
          返回概览
        </Link>
      </div>
    );
  }

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <Link className="back-link" to="/">
            ← 返回概览
          </Link>
          <h1 className="mono">{agentId}</h1>
          <p className="muted">节点详情 · CPU / 内存 / 磁盘 / 网络</p>
        </div>
        <div className="button-row">
          <button
            type="button"
            className="button"
            onClick={() => setReloadKey((value) => value + 1)}
            disabled={loading}
          >
            {loading ? "加载中…" : "刷新"}
          </button>
        </div>
      </header>

      <section className="panel range-panel">
        <div className="range-row">
          <span className="control-label">时间范围</span>
          <div className="segmented" role="group" aria-label="时间范围">
            {PRESET_RANGES.map((preset) => (
              <button
                key={preset.key}
                type="button"
                className={`segment ${rangeKey === preset.key ? "active" : ""}`}
                onClick={() => applyPreset(preset.key)}
              >
                {preset.label}
              </button>
            ))}
            <span className={`segment static ${rangeKey === "custom" ? "active" : ""}`}>
              自定义
            </span>
          </div>
          <button type="button" className="button small" onClick={handleReset}>
            重置缩放
          </button>
        </div>

        <div className="custom-range">
          <label>
            <span>开始</span>
            <input
              type="datetime-local"
              value={customFrom}
              onChange={(event) => setCustomFrom(event.target.value)}
            />
          </label>
          <label>
            <span>结束</span>
            <input
              type="datetime-local"
              value={customTo}
              max={toDateTimeLocal(Date.now())}
              onChange={(event) => setCustomTo(event.target.value)}
            />
          </label>
          <button type="button" className="button small" onClick={applyCustom}>
            应用
          </button>
        </div>
        {rangeError ? (
          <p className="form-error" role="alert">
            {rangeError}
          </p>
        ) : null}
        <div className="range-meta muted">
          <span>
            {formatDateTime(queryRange.from)} — {formatDateTime(queryRange.to)}
          </span>
          <span>服务端聚合粒度：{data ? formatInterval(data.bucket_ms) : "—"}</span>
          <span>曲线数：{data ? data.series.length : "—"}</span>
          <span>提示：拖拽图表缩放，双击恢复</span>
        </div>
      </section>

      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
          <button type="button" className="button small" onClick={() => setReloadKey((k) => k + 1)}>
            重试
          </button>
        </div>
      ) : null}

      {loading ? (
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          正在加载曲线…
        </div>
      ) : null}

      {!loading && !data && !error ? (
        <div className="empty-state">
          <h2>没有数据</h2>
          <p className="muted">该时间范围内没有查询到采样点，可以调整范围或稍后重试。</p>
        </div>
      ) : null}

      {data ? (
        <>
          {data.series.every((row) => row.points.length === 0) ? (
            <div className="banner info">该时间范围内没有采样点。</div>
          ) : null}
          <section className="charts-grid">
            <Chart
              title="CPU"
              description="cpu.usage / cpu.iowait · %"
              series={cpuSeries}
              yFormat={formatPercent}
              onZoom={handleZoom}
              onReset={handleReset}
            />
            <Chart
              title="内存"
              description="mem.used / mem.total / swap.used · MiB"
              series={memorySeries}
              yFormat={formatMiB}
              onZoom={handleZoom}
              onReset={handleReset}
            />
            <Chart
              title="磁盘使用率"
              description="按 labels.mount 关联 used/total · %"
              series={diskSeries}
              yFormat={formatPercent}
              onZoom={handleZoom}
              onReset={handleReset}
            />
            <Chart
              title="网络吞吐"
              description="累计字节相邻点差分 · 字节/秒"
              series={networkSeries}
              yFormat={formatRate}
              onZoom={handleZoom}
              onReset={handleReset}
            />
          </section>

          <section className="panel">
            <header className="section-head">
              <h2>网卡累计流量</h2>
              <span className="muted">net.rx_bytes / net.tx_bytes 最新样本</span>
            </header>
            {interfaceTotals.length === 0 ? (
              <p className="muted">暂无网卡数据。</p>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>网卡</th>
                    <th>累计接收</th>
                    <th>累计发送</th>
                  </tr>
                </thead>
                <tbody>
                  {interfaceTotals.map((iface) => (
                    <tr key={iface.name}>
                      <td className="mono">{iface.name}</td>
                      <td>{iface.rx === null ? "—" : formatBytes(iface.rx)}</td>
                      <td>{iface.tx === null ? "—" : formatBytes(iface.tx)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        </>
      ) : null}

      <section className="panel settings-panel">
        <div>
          <h2>采样间隔</h2>
          <p className="muted">
            当前：
            {settings ? formatInterval(settings.sample_interval_ms) : "未知"}
            （{settings ? `${settings.sample_interval_ms} ms` : "—"}）
          </p>
          <p className="muted small">
            修改会写入 hub 并通知 agent 重连，通常在 60 秒内生效。
          </p>
          {settingsError ? (
            <p className="form-error">
              {settingsError}{" "}
              <button
                type="button"
                className="link-button"
                onClick={() => setSettingsReload((value) => value + 1)}
              >
                重试
              </button>
            </p>
          ) : null}
        </div>
        <form className="interval-form" onSubmit={saveInterval}>
          <input
            type="number"
            min={1000}
            max={300000}
            step={1000}
            value={intervalInput}
            onChange={(event) => setIntervalInput(event.target.value)}
            aria-label="采样间隔（毫秒）"
            disabled={saving}
          />
          <span className="muted">ms</span>
          <button type="submit" className="button primary" disabled={saving}>
            {saving ? "保存中…" : "保存"}
          </button>
        </form>
        {saveState ? (
          <p className={saveState.kind === "ok" ? "form-success" : "form-error"}>
            {saveState.text}
          </p>
        ) : null}
      </section>
    </div>
  );
}
