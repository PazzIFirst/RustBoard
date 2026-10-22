import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, describeError } from "../api";
import {
  AUDIT_PAGE_SIZE,
  CONTROL_CAPABILITIES,
  auditErrorText,
  auditResultClass,
  formatAuditTime,
  formatDuration,
  nextAuditBeforeId,
} from "../control";
import { isAbortError } from "../rate";
import type { AuditEntry, AuditQuery } from "../types";

export default function AuditPage() {
  const [agentInput, setAgentInput] = useState("");
  const [capability, setCapability] = useState("");
  const [applied, setApplied] = useState<AuditQuery>({ agentId: "", capability: "" });

  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [moreError, setMoreError] = useState<string | null>(null);
  const [hasMore, setHasMore] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const filterGeneration = useRef(0);

  useEffect(() => {
    const generation = filterGeneration.current + 1;
    filterGeneration.current = generation;
    const controller = new AbortController();
    setLoading(true);
    setLoadingMore(false);
    setError(null);
    setMoreError(null);
    setEntries([]);
    setHasMore(false);
    api
      .audit({ ...applied, limit: AUDIT_PAGE_SIZE }, controller.signal)
      .then((data) => {
        if (controller.signal.aborted || generation !== filterGeneration.current) return;
        setEntries(data.entries);
        setHasMore(data.entries.length >= AUDIT_PAGE_SIZE);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        if (generation !== filterGeneration.current) return;
        setError(describeError(loadError));
      })
      .finally(() => {
        if (controller.signal.aborted || generation !== filterGeneration.current) return;
        setLoading(false);
      });
    return () => controller.abort();
  }, [applied, reloadKey]);

  const applyFilters = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setApplied({ agentId: agentInput.trim(), capability });
  };

  const resetFilters = () => {
    setAgentInput("");
    setCapability("");
    setApplied({ agentId: "", capability: "" });
  };

  const loadMore = async () => {
    if (loading || loadingMore) return;
    const beforeId = nextAuditBeforeId(entries);
    if (beforeId === undefined) {
      setHasMore(false);
      return;
    }
    const generation = filterGeneration.current;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const data = await api.audit({
        ...applied,
        limit: AUDIT_PAGE_SIZE,
        beforeId,
      });
      if (generation !== filterGeneration.current) return;
      setEntries((previous) => {
        const seen = new Set(previous.map((entry) => entry.id));
        return [
          ...previous,
          ...data.entries.filter((entry) => !seen.has(entry.id)),
        ];
      });
      setHasMore(data.entries.length >= AUDIT_PAGE_SIZE);
    } catch (loadError) {
      if (isAbortError(loadError)) return;
      if (generation === filterGeneration.current) setMoreError(describeError(loadError));
    } finally {
      if (generation === filterGeneration.current) setLoadingMore(false);
    }
  };

  const filtered = (applied.agentId ?? "") !== "" || (applied.capability ?? "") !== "";

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>审计日志</h1>
          <p className="muted">
            控制面变更操作记录 · 保留最近 180 天
            {entries.length > 0 ? ` · 已加载 ${entries.length} 条` : ""}
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

      <form className="panel audit-filters" onSubmit={applyFilters}>
        <label className="filter-field">
          <span>Agent ID</span>
          <input
            type="text"
            value={agentInput}
            onChange={(event) => setAgentInput(event.target.value)}
            placeholder="全部 agent"
            autoComplete="off"
            spellCheck={false}
          />
        </label>
        <label className="filter-field">
          <span>能力</span>
          <select
            value={capability}
            onChange={(event) => setCapability(event.target.value)}
          >
            <option value="">全部能力</option>
            {CONTROL_CAPABILITIES.map((item) => (
              <option key={item.key} value={item.key}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <div className="filter-actions">
          <button
            type="submit"
            className="button primary"
            disabled={loading || loadingMore}
          >
            查询
          </button>
          <button
            type="button"
            className="button"
            onClick={resetFilters}
            disabled={loading || loadingMore}
          >
            重置
          </button>
        </div>
      </form>

      {error ? (
        <div className="banner error" role="alert">
          <span>{error}</span>
          <button
            type="button"
            className="button small"
            onClick={() => setReloadKey((value) => value + 1)}
          >
            重试
          </button>
        </div>
      ) : null}

      {loading ? (
        <div className="loading-state">
          <span className="spinner" aria-hidden="true" />
          正在加载审计记录…
        </div>
      ) : null}

      {!loading && !error && entries.length === 0 ? (
        <div className="empty-state">
          <h2>{filtered ? "没有匹配的审计记录" : "还没有审计记录"}</h2>
          <p className="muted">
            {filtered
              ? "可以调整 Agent ID 或能力过滤条件后重试。"
              : "执行一次控制面变更操作后，记录会出现在这里。"}
          </p>
        </div>
      ) : null}

      {entries.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table audit-table">
            <thead>
              <tr>
                <th>时间</th>
                <th>Actor</th>
                <th>Agent</th>
                <th>能力</th>
                <th>动作</th>
                <th>目标</th>
                <th>结果</th>
                <th>错误</th>
                <th>耗时</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => {
                const errorText = auditErrorText(entry);
                return (
                  <tr key={entry.id}>
                    <td className="nowrap">{formatAuditTime(entry.ts)}</td>
                    <td>{entry.actor || "—"}</td>
                    <td className="mono agent-cell" title={entry.agent_id}>
                      {entry.agent_id || "—"}
                    </td>
                    <td className="mono">{entry.capability || "—"}</td>
                    <td className="mono">{entry.action || "—"}</td>
                    <td className="mono wrap-cell">{entry.target || "—"}</td>
                    <td>
                      <span className={`result-pill ${auditResultClass(entry.result)}`}>
                        {entry.result || "unknown"}
                      </span>
                    </td>
                    <td className="wrap-cell error-cell" title={errorText}>
                      {errorText || "—"}
                    </td>
                    <td className="nowrap">{formatDuration(entry.duration_ms)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}

      {moreError ? (
        <div className="banner error" role="alert">
          <span>{moreError}</span>
          <button
            type="button"
            className="button small"
            onClick={() => void loadMore()}
            disabled={loadingMore}
          >
            重试
          </button>
        </div>
      ) : null}

      {entries.length > 0 ? (
        <div className="audit-more">
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
            <span className="muted">已加载全部 {entries.length} 条</span>
          )}
        </div>
      ) : null}
    </div>
  );
}
