import { useEffect, useMemo, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { formatAxisTime } from "../format";
import type { SamplePoint } from "../types";

export interface ChartSeries {
  label: string;
  points: SamplePoint[];
  color: string;
}

interface ChartProps {
  title: string;
  description?: string;
  series: ChartSeries[];
  yFormat: (value: number) => string;
  onZoom?: (fromMs: number, toMs: number) => void;
  onReset?: () => void;
  height?: number;
}

const MAX_ZOOM_DEBOUNCE_MS = 250;

function alignData(series: ChartSeries[]): { data: uPlot.AlignedData; span: number } | null {
  const timestampSet = new Set<number>();
  for (const row of series) {
    for (const point of row.points) {
      if (Number.isFinite(point.ts) && Number.isFinite(point.value)) {
        timestampSet.add(Math.floor(point.ts / 1000));
      }
    }
  }
  const xs = [...timestampSet].sort((a, b) => a - b);
  if (xs.length === 0) return null;
  const indexBySecond = new Map(xs.map((second, index) => [second, index]));
  const columns = series.map((row) => {
    const column: Array<number | null> = new Array(xs.length).fill(null);
    for (const point of row.points) {
      const index = indexBySecond.get(Math.floor(point.ts / 1000));
      if (index !== undefined && Number.isFinite(point.value)) {
        column[index] = point.value;
      }
    }
    return column;
  });
  const span = xs[xs.length - 1] - xs[0];
  return { data: [xs, ...columns] as uPlot.AlignedData, span };
}

export default function Chart({
  title,
  description,
  series,
  yFormat,
  onZoom,
  onReset,
  height = 280,
}: ChartProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const plotRef = useRef<uPlot | null>(null);
  const zoomTimer = useRef<number | null>(null);
  const pendingZoom = useRef<{ min: number; max: number } | null>(null);
  const onZoomRef = useRef(onZoom);
  const onResetRef = useRef(onReset);

  useEffect(() => {
    onZoomRef.current = onZoom;
  }, [onZoom]);
  useEffect(() => {
    onResetRef.current = onReset;
  }, [onReset]);

  const hasData = useMemo(
    () =>
      series.some((row) =>
        row.points.some((point) => Number.isFinite(point.value)),
      ),
    [series],
  );

  useEffect(() => {
    const host = hostRef.current;
    if (plotRef.current) {
      plotRef.current.destroy();
      plotRef.current = null;
    }
    if (!host || !hasData) return;

    const aligned = alignData(series);
    if (!aligned) return;
    const width = Math.max(320, Math.floor(host.clientWidth || 640));

    const options: uPlot.Options = {
      width,
      height,
      padding: [10, 12, 0, 4],
      legend: { show: true },
      cursor: {
        drag: { x: true, y: false, setScale: true },
        points: { show: false },
      },
      scales: { x: { time: true } },
      axes: [
        {
          stroke: "#8b949e",
          grid: { stroke: "#1b2230", width: 1 },
          ticks: { stroke: "#30363d", width: 1 },
          size: 36,
          values: (_self, splits) =>
            splits.map((value) => formatAxisTime(value, aligned.span)),
        },
        {
          stroke: "#8b949e",
          grid: { stroke: "#1b2230", width: 1 },
          ticks: { stroke: "#30363d", width: 1 },
          size: 72,
          values: (_self, splits) => splits.map((value) => yFormat(value)),
        },
      ],
      series: [
        { label: "时间" },
        ...series.map((row) => ({
          label: row.label,
          stroke: row.color,
          width: 1.6,
          points: { show: false },
          spanGaps: false,
          value: (_self: uPlot, value: number | null) =>
            value === null || value === undefined ? "—" : yFormat(value),
        })),
      ],
      hooks: {
        setSelect: [
          (plot) => {
            const selection = plot.select;
            if (selection.width <= 0 || selection.left < 0) return;
            const min = plot.posToVal(selection.left, "x");
            const max = plot.posToVal(selection.left + selection.width, "x");
            if (!Number.isFinite(min) || !Number.isFinite(max) || max <= min) return;
            pendingZoom.current = { min, max };
            if (zoomTimer.current !== null) window.clearTimeout(zoomTimer.current);
            zoomTimer.current = window.setTimeout(() => {
              zoomTimer.current = null;
              const pending = pendingZoom.current;
              if (!pending || !onZoomRef.current) return;
              onZoomRef.current(
                Math.round(pending.min * 1000),
                Math.round(pending.max * 1000),
              );
            }, MAX_ZOOM_DEBOUNCE_MS);
          },
        ],
      },
    };

    const plot = new uPlot(options, aligned.data, host);
    plotRef.current = plot;

    const handleDoubleClick = () => {
      onResetRef.current?.();
    };
    plot.over.addEventListener("dblclick", handleDoubleClick);

    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      const nextWidth = Math.max(320, Math.floor(entry.contentRect.width));
      if (nextWidth !== plot.width) {
        plot.setSize({ width: nextWidth, height });
      }
    });
    observer.observe(host);

    return () => {
      observer.disconnect();
      if (zoomTimer.current !== null) {
        window.clearTimeout(zoomTimer.current);
        zoomTimer.current = null;
      }
      plot.over.removeEventListener("dblclick", handleDoubleClick);
      plot.destroy();
      if (plotRef.current === plot) plotRef.current = null;
    };
  }, [series, hasData, height, yFormat]);

  return (
    <section className="chart-card">
      <header className="chart-head">
        <h3>{title}</h3>
        {description ? <span className="muted">{description}</span> : null}
      </header>
      {hasData ? (
        <>
          <div className="chart-host" ref={hostRef} />
          <p className="chart-hint muted">拖拽选择区域缩放 · 双击图表恢复范围</p>
        </>
      ) : (
        <div className="chart-empty">暂无数据</div>
      )}
    </section>
  );
}
