/**
 * M4 归档数据页的纯函数：状态 / 后端 / 错误码展示、分页游标与下载 URL。
 *
 * 本文件不依赖 React 或 DOM，便于 vitest 直接覆盖；页面只负责把 API 数据
 * 传进来。任何后端 URL、凭据或原始错误报文都不会在这里出现。
 */
import { formatDateTime } from "./format";
import type {
  ArchiveObjectListResponse,
  ArchiveObjectStatus,
} from "./types";

/** 归档对象分页大小（方案 §7.4：limit 1–100，面板固定 50）。 */
export const ARCHIVE_PAGE_SIZE = 50;

const STATUS_LABELS: Record<ArchiveObjectStatus, string> = {
  pending: "待上传",
  uploaded: "已上传",
  local_deleted: "本地已清理",
  failed: "失败",
};

/** 状态展示名；未知状态原样返回，不猜造。 */
export function archiveStatusLabel(status: string): string {
  return STATUS_LABELS[status as ArchiveObjectStatus] ?? (status || "未知");
}

/** 状态对应的既有 status-pill 颜色：只有 uploaded / local_deleted 算可用。 */
export function archiveStatusClass(status: string): string {
  switch (status) {
    case "uploaded":
    case "local_deleted":
      return "status-online";
    case "failed":
      return "status-revoked";
    default:
      return "";
  }
}

/** 只有上传完成（或 raw 已删除但对象仍在）的归档可以下载。 */
export function isArchiveDownloadable(status: string): boolean {
  return status === "uploaded" || status === "local_deleted";
}

const BACKEND_LABELS: Record<string, string> = {
  webdav: "WebDAV",
  s3: "S3 / MinIO",
  sftp: "SFTP",
};

/** 后端类型展示名；只显示类型，不显示 endpoint / bucket / 凭据。 */
export function archiveBackendLabel(backend: string): string {
  const key = backend.trim().toLowerCase();
  return BACKEND_LABELS[key] ?? (backend.trim() || "未知");
}

const ERROR_LABELS: Record<string, string> = {
  invalid_key: "对象 key 非法",
  invalid_manifest: "manifest 非法",
  invalid_status: "对象状态非法",
  encode_failed: "编码失败",
  backend_unavailable: "后端不可用",
  not_found: "对象不存在",
  archive_error: "归档失败",
};

/**
 * `archive_objects.error` 只允许固定错误码；hub 已把未知内容收敛为
 * `archive_error`，这里再做一次白名单映射，页面永远不渲染任意后端报文。
 */
export function formatArchiveError(error: string): string {
  const code = error.trim();
  if (code === "") return "";
  return ERROR_LABELS[code] ?? "归档失败";
}

/** SHA-256 短显示：只接受小写 / 大写 hex，非 hex 一律显示 “—”。 */
export function shortSha256(sha: string, length = 12): string {
  const value = sha.trim().toLowerCase();
  if (value === "" || !/^[0-9a-f]+$/.test(value)) return "—";
  const keep = Math.max(0, Math.trunc(length));
  return value.length <= keep ? value : `${value.slice(0, keep)}…`;
}

/** 对象覆盖的本地时间范围。 */
export function formatArchiveRange(from: number, to: number): string {
  if (!Number.isFinite(from) || !Number.isFinite(to)) return "—";
  return `${formatDateTime(from)} – ${formatDateTime(to)}`;
}

/** 行数展示；负数 / 非数字显示 “—”。 */
export function formatArchiveRows(rows: number): string {
  if (!Number.isFinite(rows) || rows < 0) return "—";
  return Math.trunc(rows).toLocaleString("zh-CN");
}

/** 归档水位：null / 非数字表示尚未归档。 */
export function formatArchiveWatermark(ts: number | null | undefined): string {
  if (ts === null || ts === undefined || !Number.isFinite(ts) || ts <= 0) {
    return "无（尚未归档）";
  }
  return formatDateTime(ts);
}

/**
 * 同源下载 URL；不经过 fetch，也不把对象读进 JS 内存。
 *
 * 非法 id 返回空串，页面据此禁用下载入口。
 */
export function archiveDownloadUrl(id: number): string {
  const value = Math.trunc(id);
  if (!Number.isFinite(value) || value <= 0) return "";
  return `/api/archive/objects/${value}/download`;
}

/**
 * 计算「加载更早」的 `before_id`。
 *
 * 与审计页一致：优先信任服务端排他游标；缺失时才回退到本页最后一条 id。
 * 服务端明确返回 null 表示没有更多数据。
 */
export function nextArchiveBeforeId(
  objects: Array<{ id: number }>,
  serverNext?: number | null,
): number | undefined {
  if (serverNext === null) return undefined;
  if (serverNext !== undefined && Number.isFinite(serverNext) && serverNext > 0) {
    return Math.trunc(serverNext);
  }
  const last = objects[objects.length - 1];
  if (last && Number.isFinite(last.id) && last.id > 0) return Math.trunc(last.id);
  return undefined;
}

/** 是否还有下一页；优先信任服务端 `next_before_id`。 */
export function archiveHasMore(
  response: ArchiveObjectListResponse,
  pageSize = ARCHIVE_PAGE_SIZE,
): boolean {
  if (response.next_before_id === null) return false;
  if (response.next_before_id !== undefined) return response.objects.length > 0;
  return response.objects.length >= pageSize;
}
