/**
 * M4 归档数据页（`/archive`）。
 *
 * - 状态卡：开关 / 后端类型 / 水位 / 最近运行 / 最近错误 / 对象数；
 * - 对象列表：时间范围、状态、行数、压缩大小、sha256 短显示、下载；
 * - 下载使用同源 `<a href>`，由浏览器直接接收流，不 fetch 进 JS 内存；
 * - 页面只展示后端类型，不展示 endpoint / bucket / 凭据。
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api, describeError } from "../api";
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
  nextArchiveBeforeId,
  shortSha256,
} from "../archive";
import { formatBytes, formatDateTime } from "../format";
import { isAbortError } from "../rate";
import type { ArchiveObject, ArchiveStatus } from "../types";

export default function ArchivePage() {
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>归档</h1>
          <p className="muted">
            冷存储归档对象 · 下载由面板同源流式代理，浏览器不接触 hub token
          </p>
        </div>
      </header>
      <StatusPanel />
      <ObjectsPanel />
    </div>
  );
}

function ErrorBanner({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="banner error" role="alert">
      <span>{message}</span>
      {onRetry ? (
        <button type="button" className="button small" onClick={onRetry}>
          重试
        </button>
      ) : null}
    </div>
  );
}

function Loading({ text }: { text: string }) {
  return (
    <div className="loading-state">
      <span className="spinner" aria-hidden="true" />
      {text}
    </div>
  );
}

function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty-state">
      <h2>{title}</h2>
      {children ? <p className="muted">{children}</p> : null}
    </div>
  );
}

function StatusPanel() {
  const [status, setStatus] = useState<ArchiveStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api
      .archiveStatus(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setStatus(data);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        setError(describeError(loadError));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <div>
          <h2>归档状态</h2>
          <p className="muted">
            只显示后端类型与运行时状态，不显示 endpoint、bucket 或凭据
          </p>
        </div>
        <button
          type="button"
          className="button"
          onClick={() => setReloadKey((value) => value + 1)}
          disabled={loading}
        >
          {loading ? "刷新中…" : "刷新"}
        </button>
      </div>

      {error ? (
        <ErrorBanner
          message={error}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : null}
      {loading && status === null ? <Loading text="正在加载归档状态…" /> : null}

      {status !== null ? (
        <>
          {!status.enabled ? (
            <div className="banner info">
              归档未启用（archive.enabled = false）；启用后由 hub 按每日计划上传冷存储。
            </div>
          ) : null}
          <dl className="archive-status-grid">
            <div className="archive-status-card">
              <dt>开关</dt>
              <dd>
                <span
                  className={`status-pill ${
                    status.enabled ? "status-online" : "status-revoked"
                  }`}
                >
                  {status.enabled ? "已启用" : "未启用"}
                </span>
              </dd>
            </div>
            <div className="archive-status-card">
              <dt>后端</dt>
              <dd>{archiveBackendLabel(status.backend)}</dd>
            </div>
            <div className="archive-status-card">
              <dt>归档水位</dt>
              <dd>{formatArchiveWatermark(status.last_archived_ts)}</dd>
            </div>
            <div className="archive-status-card">
              <dt>最近运行</dt>
              <dd>
                {status.last_run === null
                  ? "从未运行"
                  : formatDateTime(status.last_run)}
              </dd>
            </div>
            <div className="archive-status-card">
              <dt>对象数</dt>
              <dd>{formatArchiveRows(status.objects)}</dd>
            </div>
            <div className="archive-status-card archive-status-error">
              <dt>最近错误</dt>
              <dd title={status.last_error ?? undefined}>
                {status.last_error ? status.last_error : "—"}
              </dd>
            </div>
          </dl>
        </>
      ) : null}
    </section>
  );
}

function ObjectsPanel() {
  const [objects, setObjects] = useState<ArchiveObject[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [moreError, setMoreError] = useState<string | null>(null);
  /** undefined = 服务端未给游标；null = 明确没有更多；number = 排他游标。 */
  const [nextBeforeId, setNextBeforeId] = useState<number | null | undefined>(undefined);
  const [hasMore, setHasMore] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const generationRef = useRef(0);

  useEffect(() => {
    const generation = generationRef.current + 1;
    generationRef.current = generation;
    const controller = new AbortController();
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    setMoreError(null);
    setObjects([]);
    setHasMore(false);
    setNextBeforeId(undefined);
    api
      .archiveObjects({ limit: ARCHIVE_PAGE_SIZE }, controller.signal)
      .then((data) => {
        if (controller.signal.aborted || generation !== generationRef.current) return;
        setObjects(data.objects);
        setNextBeforeId(data.next_before_id);
        setHasMore(archiveHasMore(data));
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        if (generation !== generationRef.current) return;
        setError(describeError(loadError));
      })
      .finally(() => {
        if (controller.signal.aborted || generation !== generationRef.current) return;
        setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  const loadMore = async () => {
    if (loading || loadingMore) return;
    const beforeId = nextArchiveBeforeId(objects, nextBeforeId);
    if (beforeId === undefined) {
      setHasMore(false);
      return;
    }
    const generation = generationRef.current;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const data = await api.archiveObjects({
        limit: ARCHIVE_PAGE_SIZE,
        beforeId,
      });
      if (generation !== generationRef.current) return;
      setObjects((previous) => {
        // 游标是排他的；仍按 id 去重，避免极端重试导致重复行。
        const seen = new Set(previous.map((object) => object.id));
        return [...previous, ...data.objects.filter((object) => !seen.has(object.id))];
      });
      setNextBeforeId(data.next_before_id);
      setHasMore(archiveHasMore(data));
    } catch (loadError) {
      if (isAbortError(loadError)) return;
      if (generation === generationRef.current) {
        setMoreError(describeError(loadError));
      }
    } finally {
      if (generation === generationRef.current) setLoadingMore(false);
    }
  };

  return (
    <section className="panel alert-panel">
      <div className="panel-toolbar">
        <div>
          <h2>归档对象</h2>
          <p className="muted">
            按上传时间倒序 · 每页 {ARCHIVE_PAGE_SIZE} 条 · 仅“已上传 / 本地已清理”可下载
            {objects.length > 0 ? ` · 已加载 ${objects.length} 条` : ""}
          </p>
        </div>
        <button
          type="button"
          className="button"
          onClick={() => setReloadKey((value) => value + 1)}
          disabled={loading}
        >
          {loading ? "刷新中…" : "刷新"}
        </button>
      </div>

      {error ? (
        <ErrorBanner
          message={error}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : null}

      {loading && objects.length === 0 ? (
        <Loading text="正在加载归档对象…" />
      ) : null}

      {!loading && !error && objects.length === 0 ? (
        <EmptyState title="还没有归档对象">
          开启归档并等到首个计划时间（或执行 archive run）后，这里会显示已上传对象。
        </EmptyState>
      ) : null}

      {objects.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table archive-table">
            <thead>
              <tr>
                <th>时间范围（本地）</th>
                <th>状态</th>
                <th>行数</th>
                <th>压缩大小</th>
                <th>SHA-256</th>
                <th>下载</th>
              </tr>
            </thead>
            <tbody>
              {objects.map((object) => {
                const url = archiveDownloadUrl(object.id);
                const downloadable = isArchiveDownloadable(object.status) && url !== "";
                return (
                  <tr key={object.id}>
                    <td>
                      <div className="nowrap" title={object.object_key}>
                        {formatArchiveRange(object.from_ts, object.to_ts)}
                      </div>
                      <span className="muted small mono">{object.object_key}</span>
                    </td>
                    <td>
                      <div className="archive-status-cell">
                        <span
                          className={`status-pill ${archiveStatusClass(object.status)}`}
                        >
                          {archiveStatusLabel(object.status)}
                        </span>
                        {object.error ? (
                          <span className="muted small">
                            {formatArchiveError(object.error)}
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td className="nowrap">{formatArchiveRows(object.rows)}</td>
                    <td className="nowrap">{formatBytes(object.bytes)}</td>
                    <td className="mono nowrap" title={object.sha256}>
                      {shortSha256(object.sha256)}
                    </td>
                    <td>
                      {downloadable ? (
                        <a
                          className="button small"
                          href={url}
                          download
                          aria-label={`下载归档对象 ${object.id}`}
                        >
                          下载
                        </a>
                      ) : (
                        <button
                          type="button"
                          className="button small"
                          disabled
                          title="归档对象尚未上传完成，暂不可下载"
                        >
                          不可下载
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}

      {moreError ? <ErrorBanner message={moreError} /> : null}

      {objects.length > 0 ? (
        <div className="alert-more">
          {hasMore ? (
            <button
              type="button"
              className="button"
              onClick={() => void loadMore()}
              disabled={loadingMore}
            >
              {loadingMore ? "加载中…" : "加载更早"}
            </button>
          ) : (
            <span className="muted">已加载全部 {objects.length} 条</span>
          )}
        </div>
      ) : null}
    </section>
  );
}
