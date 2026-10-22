/** 展示层的纯函数。所有函数都不依赖 DOM，便于 vitest 直接测试。 */

const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;
export const BYTES_PER_MIB = 1024 * 1024;

function pad2(value: number): string {
  return String(value).padStart(2, "0");
}

/** 人类可读的字节数，默认保留 1 位小数。 */
export function formatBytes(bytes: number, digits = 1): string {
  if (!Number.isFinite(bytes)) return "—";
  const sign = bytes < 0 ? "-" : "";
  let value = Math.abs(bytes);
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  if (unit === 0) return `${sign}${Math.round(value)} B`;
  return `${sign}${value.toFixed(digits)} ${BYTE_UNITS[unit]}`;
}

/** 字节/秒。 */
export function formatRate(bytesPerSecond: number): string {
  if (!Number.isFinite(bytesPerSecond)) return "—";
  return `${formatBytes(bytesPerSecond)}/s`;
}

export function formatPercent(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  return `${value.toFixed(digits)}%`;
}

/** used / total 的百分比；total 非法或为 0 时返回 null。 */
export function ratioPercent(used: number, total: number): number | null {
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return null;
  return (used / total) * 100;
}

/** 采样间隔的紧凑展示：5000 → 5s，60000 → 1m，3600000 → 1h。 */
export function formatInterval(ms: number): string {
  if (!Number.isFinite(ms) || ms <= 0) return "—";
  if (ms % 3_600_000 === 0) return `${ms / 3_600_000}h`;
  if (ms % 60_000 === 0) return `${ms / 60_000}m`;
  if (ms % 1000 === 0) return `${ms / 1000}s`;
  return `${ms}ms`;
}

/** 本地时间 "YYYY-MM-DD HH:mm:ss"。 */
export function formatDateTime(ms: number): string {
  if (!Number.isFinite(ms)) return "—";
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return "—";
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())} ${pad2(
    date.getHours(),
  )}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
}

/** 相对时间；未来时间按“刚刚”处理，超过 30 天回退到绝对时间。 */
export function formatRelativeTime(tsMs: number, nowMs = Date.now()): string {
  if (!Number.isFinite(tsMs) || !Number.isFinite(nowMs)) return "—";
  const seconds = Math.max(0, Math.floor((nowMs - tsMs) / 1000));
  if (seconds < 10) return "刚刚";
  if (seconds < 60) return `${seconds} 秒前`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} 小时前`;
  if (seconds < 30 * 86_400) return `${Math.floor(seconds / 86_400)} 天前`;
  return formatDateTime(tsMs);
}

/** 图表 x 轴标签：跨度越长，标签越偏向日期。 */
export function formatAxisTime(tsSeconds: number, spanSeconds: number): string {
  const date = new Date(tsSeconds * 1000);
  if (Number.isNaN(date.getTime())) return "";
  const day = `${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}`;
  const clock = `${pad2(date.getHours())}:${pad2(date.getMinutes())}`;
  if (spanSeconds > 2 * 86_400) return day;
  if (spanSeconds > 12 * 3600) return `${day} ${clock}`;
  return clock;
}

export function formatMiB(value: number): string {
  if (!Number.isFinite(value)) return "—";
  return `${value.toFixed(0)} MiB`;
}

/** 状态 → CSS 类名。未知状态按 unknown 处理，避免把颜色交给后端字符串。 */
export function statusClass(status: string): string {
  switch (status.toLowerCase()) {
    case "online":
      return "status-online";
    case "offline":
      return "status-offline";
    case "revoked":
      return "status-revoked";
    default:
      return "status-unknown";
  }
}

/** datetime-local 输入框需要的本地时间格式。 */
export function toDateTimeLocal(ms: number): string {
  const date = new Date(ms);
  return `${date.getFullYear()}-${pad2(date.getMonth() + 1)}-${pad2(date.getDate())}T${pad2(
    date.getHours(),
  )}:${pad2(date.getMinutes())}`;
}

export function parseDateTimeLocal(value: string): number | null {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? null : ms;
}
