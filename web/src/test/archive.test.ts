import { describe, expect, it } from "vitest";
import {
  ARCHIVE_PAGE_SIZE,
  archiveBackendLabel,
  archiveDownloadUrl,
  archiveHasMore,
  archiveStatusClass,
  archiveStatusLabel,
  formatArchiveError,
  formatArchiveRange,
  formatArchiveRows,
  formatArchiveWatermark,
  isArchiveDownloadable,
  isArchiveObjectDownloadable,
  nextArchiveBeforeId,
  shortSha256,
} from "../archive";
import type { ArchiveObject } from "../types";

function archiveObject(id: number, overrides: Partial<ArchiveObject> = {}): ArchiveObject {
  return {
    id,
    object_key: `rustboard/2026/10/24/part-00001.csv.gz`,
    manifest_key: "rustboard/2026/10/24/part-00001.manifest.json",
    from_ts: 1_700_000_000_000,
    to_ts: 1_700_003_600_000,
    rows: 1000,
    bytes: 2048,
    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    status: "uploaded",
    error: "",
    created_at: 1_700_000_000_000,
    uploaded_at: 1_700_000_000_000,
    deleted_at: null,
    ...overrides,
  };
}

describe("archive status helpers", () => {
  it("maps stable statuses to labels and only allows ready objects to download", () => {
    expect(archiveStatusLabel("pending")).toBe("待上传");
    expect(archiveStatusLabel("uploaded")).toBe("已上传");
    expect(archiveStatusLabel("local_deleted")).toBe("本地已清理");
    expect(archiveStatusLabel("failed")).toBe("失败");
    expect(archiveStatusLabel("weird")).toBe("weird");

    expect(archiveStatusClass("uploaded")).toBe("status-online");
    expect(archiveStatusClass("local_deleted")).toBe("status-online");
    expect(archiveStatusClass("failed")).toBe("status-revoked");
    expect(archiveStatusClass("pending")).toBe("");

    expect(isArchiveDownloadable("uploaded")).toBe(true);
    expect(isArchiveDownloadable("local_deleted")).toBe(true);
    for (const status of ["pending", "failed", "", "unknown"]) {
      expect(isArchiveDownloadable(status)).toBe(false);
    }
  });

  it("prefers the server downloadable flag and falls back to status", () => {
    // API 明确 false：即使状态为 uploaded / local_deleted 也必须禁用（>64 MiB）。
    expect(
      isArchiveObjectDownloadable(archiveObject(1, { downloadable: false })),
    ).toBe(false);
    expect(
      isArchiveObjectDownloadable(
        archiveObject(1, { status: "local_deleted", downloadable: false }),
      ),
    ).toBe(false);

    // 旧版响应没有该字段：按既有 status 规则回退。
    expect(isArchiveObjectDownloadable(archiveObject(1))).toBe(true);
    expect(
      isArchiveObjectDownloadable(archiveObject(1, { status: "local_deleted" })),
    ).toBe(true);
    for (const status of ["pending", "failed"] as const) {
      expect(isArchiveObjectDownloadable(archiveObject(1, { status }))).toBe(false);
    }

    // 正常 uploaded / 小对象可下载。
    expect(
      isArchiveObjectDownloadable(
        archiveObject(1, { status: "uploaded", downloadable: true }),
      ),
    ).toBe(true);
    expect(
      isArchiveObjectDownloadable(
        archiveObject(1, { status: "local_deleted", downloadable: true }),
      ),
    ).toBe(true);
  });

  it("labels backends without exposing configuration", () => {
    expect(archiveBackendLabel("webdav")).toBe("WebDAV");
    expect(archiveBackendLabel("S3")).toBe("S3 / MinIO");
    expect(archiveBackendLabel(" sftp ")).toBe("SFTP");
    expect(archiveBackendLabel("future")).toBe("future");
    expect(archiveBackendLabel("")).toBe("未知");
  });

  it("formats only fixed archive error codes", () => {
    expect(formatArchiveError("")).toBe("");
    expect(formatArchiveError("   ")).toBe("");
    expect(formatArchiveError("backend_unavailable")).toBe("后端不可用");
    expect(formatArchiveError("not_found")).toBe("对象不存在");
    expect(formatArchiveError("archive_error")).toBe("归档失败");
    // 人工改库 / 未知内容不能原样展示。
    expect(formatArchiveError("https://minio.internal/secret")).toBe("归档失败");
    expect(formatArchiveError("secret-token")).toBe("归档失败");
  });

  it("shows a short sha256 only for valid hex", () => {
    expect(shortSha256("0123456789abcdef0123456789abcdef")).toBe("0123456789ab…");
    expect(shortSha256("0123456789ab", 12)).toBe("0123456789ab");
    expect(shortSha256("0123456789ABCDEF", 8)).toBe("01234567…");
    expect(shortSha256("")).toBe("—");
    expect(shortSha256("not-hex-value")).toBe("—");
    expect(shortSha256("xyz")).toBe("—");
  });

  it("formats the covered range and row counts", () => {
    const range = formatArchiveRange(1_700_000_000_000, 1_700_003_600_000);
    expect(range).toMatch(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} – \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/,
    );
    expect(formatArchiveRange(Number.NaN, 0)).toBe("—");
    expect(formatArchiveRows(1234567)).toBe((1234567).toLocaleString("zh-CN"));
    expect(formatArchiveRows(-1)).toBe("—");
    expect(formatArchiveRows(Number.NaN)).toBe("—");
  });

  it("formats the watermark and handles missing values", () => {
    expect(formatArchiveWatermark(null)).toBe("无（尚未归档）");
    expect(formatArchiveWatermark(undefined)).toBe("无（尚未归档）");
    expect(formatArchiveWatermark(0)).toBe("无（尚未归档）");
    expect(formatArchiveWatermark(Number.NaN)).toBe("无（尚未归档）");
    expect(formatArchiveWatermark(1_700_000_000_000)).toMatch(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/,
    );
  });

  it("builds only same-origin download URLs with positive integer ids", () => {
    expect(archiveDownloadUrl(42)).toBe("/api/archive/objects/42/download");
    expect(archiveDownloadUrl(1)).toBe("/api/archive/objects/1/download");
    expect(archiveDownloadUrl(0)).toBe("");
    expect(archiveDownloadUrl(-3)).toBe("");
    expect(archiveDownloadUrl(Number.NaN)).toBe("");
    expect(archiveDownloadUrl(Number.POSITIVE_INFINITY)).toBe("");
  });
});

describe("archive pagination", () => {
  it("trusts the server cursor and falls back to the last id", () => {
    const objects = [archiveObject(9), archiveObject(7)];
    expect(nextArchiveBeforeId(objects, 7)).toBe(7);
    expect(nextArchiveBeforeId(objects, undefined)).toBe(7);
    expect(nextArchiveBeforeId([], undefined)).toBeUndefined();
    expect(nextArchiveBeforeId(objects, null)).toBeUndefined();
    expect(nextArchiveBeforeId(objects, 0)).toBe(7);
    expect(nextArchiveBeforeId([archiveObject(0)], undefined)).toBeUndefined();
  });

  it("derives whether another page exists", () => {
    expect(archiveHasMore({ objects: [], next_before_id: null })).toBe(false);
    expect(archiveHasMore({ objects: [], next_before_id: undefined })).toBe(false);
    expect(archiveHasMore({ objects: [archiveObject(2)], next_before_id: 2 })).toBe(true);
    expect(archiveHasMore({ objects: [archiveObject(2)] }, 1)).toBe(true);
    expect(
      archiveHasMore({ objects: Array.from({ length: ARCHIVE_PAGE_SIZE }, (_, i) => archiveObject(i + 1)) }),
    ).toBe(true);
  });
});
