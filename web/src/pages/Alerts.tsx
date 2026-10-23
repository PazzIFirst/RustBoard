/**
 * M4 告警管理页。
 *
 * 四个 tab 共用面板同源 API：规则 / 事件 / 渠道 / 静默。
 * 渠道 secret 只写不读：表单用不受控 password 输入，提交后立刻清空，页面
 * state 中只有非敏感字段与“已配置”字段名。
 */
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import {
  ALERT_COMPARATOR_OPTIONS,
  ALERT_EVENT_PAGE_SIZE,
  ALERT_SOURCE_OPTIONS,
  CHANNEL_KIND_OPTIONS,
  MAX_RULE_COOLDOWN_SECS,
  MAX_RULE_DURATION_SECS,
  MAX_RULE_LABELS,
  MAX_SILENCE_SECS,
  MIN_SILENCE_SECS,
  alertSourceLabel,
  buildChannelInput,
  buildRuleCreatePayload,
  buildRuleUpdatePayload,
  buildSilenceInput,
  channelFields,
  channelFormFromView,
  channelKindLabel,
  channelSecretFields,
  channelSecretSummary,
  describeAlertError,
  emptyChannelForm,
  emptyRuleForm,
  emptySilenceForm,
  eventStateClass,
  formatAlertValue,
  formatDurationSecs,
  formatEventAgent,
  formatEventRule,
  formatEventState,
  formatEventTime,
  formatNotifyStatus,
  formatRuleFilter,
  formatRuleTarget,
  formatRuleThreshold,
  formatSilenceScope,
  formatSilenceUntil,
  hasRuleChanges,
  isSecretConfigured,
  ruleFormFromRule,
  sourceRequiresMetric,
  validateChannelForm,
  validateRuleForm,
  validateSilenceForm,
  type ChannelFormState,
  type RuleFormState,
  type SilenceFormState,
} from "../alerts";
import { api } from "../api";
import { formatDateTime } from "../format";
import { isAbortError } from "../rate";
import type {
  AlertEvent,
  AlertRule,
  AlertSilence,
  ChannelKind,
  ChannelView,
} from "../types";

type AlertsTab = "rules" | "events" | "channels" | "silences";

const TABS: Array<{ key: AlertsTab; label: string; hint: string }> = [
  { key: "rules", label: "规则", hint: "阈值与内置规则" },
  { key: "events", label: "事件", hint: "触发 / 恢复记录" },
  { key: "channels", label: "渠道", hint: "通知渠道" },
  { key: "silences", label: "静默", hint: "临时免打扰" },
];

export default function AlertsPage() {
  const [tab, setTab] = useState<AlertsTab>("rules");
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>告警</h1>
          <p className="muted">
            规则、事件、通知渠道与静默 · 通知渠道的 secret 只写不读
          </p>
        </div>
      </header>

      <div className="alert-tabs" role="tablist" aria-label="告警分类">
        {TABS.map((item) => (
          <button
            key={item.key}
            type="button"
            role="tab"
            aria-selected={tab === item.key}
            className={`alert-tab ${tab === item.key ? "active" : ""}`}
            onClick={() => setTab(item.key)}
          >
            <span>{item.label}</span>
            <span className="alert-tab-hint">{item.hint}</span>
          </button>
        ))}
      </div>

      <div role="tabpanel">
        {tab === "rules" ? <RulesPanel /> : null}
        {tab === "events" ? <EventsPanel /> : null}
        {tab === "channels" ? <ChannelsPanel /> : null}
        {tab === "silences" ? <SilencesPanel /> : null}
      </div>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="filter-field">
      <span>{label}</span>
      {children}
      {hint ? <small className="muted">{hint}</small> : null}
    </label>
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

// ===========================================================================
// 规则
// ===========================================================================

function RulesPanel() {
  const [rules, setRules] = useState<AlertRule[] | null>(null);
  const [channels, setChannels] = useState<ChannelView[]>([]);
  const [channelsError, setChannelsError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [editor, setEditor] = useState<
    { mode: "create" } | { mode: "edit"; rule: AlertRule } | null
  >(null);
  const [busyRule, setBusyRule] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api
      .alertRules(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setRules(data);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        setError(describeAlertError(loadError));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  useEffect(() => {
    const controller = new AbortController();
    setChannelsError(null);
    api
      .alertChannels(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setChannels(data);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        setChannelsError(describeAlertError(loadError));
      });
    return () => controller.abort();
  }, [reloadKey]);

  const toggleRule = async (rule: AlertRule) => {
    if (busyRule !== null) return;
    setBusyRule(rule.id);
    setActionError(null);
    setNotice(null);
    try {
      // 启停只发送 enabled，避免把表单里未确认的其它字段一起写入。
      const updated = await api.updateAlertRule(rule.id, { enabled: !rule.enabled });
      setRules((previous) =>
        previous?.map((item) => (item.id === updated.id ? updated : item)) ?? null,
      );
    } catch (toggleError) {
      setActionError(describeAlertError(toggleError));
    } finally {
      setBusyRule(null);
    }
  };

  const deleteRule = async (rule: AlertRule) => {
    if (busyRule !== null) return;
    setBusyRule(rule.id);
    setActionError(null);
    setNotice(null);
    try {
      await api.deleteAlertRule(rule.id);
      setRules((previous) => previous?.filter((item) => item.id !== rule.id) ?? null);
      setPendingDelete(null);
      setNotice(`规则「${rule.name}」已删除`);
    } catch (deleteError) {
      setActionError(describeAlertError(deleteError));
    } finally {
      setBusyRule(null);
    }
  };

  const handleSaved = (rule: AlertRule, message: string) => {
    setRules((previous) => {
      const list = previous ?? [];
      return list.some((item) => item.id === rule.id)
        ? list.map((item) => (item.id === rule.id ? rule : item))
        : [...list, rule];
    });
    setEditor(null);
    setActionError(null);
    setNotice(message);
  };

  return (
    <div className="alert-panel">
      <div className="panel-toolbar">
        <div>
          <h2>告警规则</h2>
          <p className="muted">
            内置规则默认为停用；启用并绑定通知渠道后才会发送通知。内置规则可修改、可停用，不可删除。
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
          <button
            type="button"
            className="button primary"
            onClick={() => {
              setEditor({ mode: "create" });
              setNotice(null);
              setActionError(null);
            }}
          >
            新建规则
          </button>
        </div>
      </div>

      {notice ? <div className="banner info">{notice}</div> : null}
      {actionError ? <ErrorBanner message={actionError} /> : null}
      {error ? (
        <ErrorBanner
          message={error}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : null}

      {editor ? (
        <RuleEditor
          key={editor.mode === "create" ? "create" : editor.rule.id}
          rule={editor.mode === "edit" ? editor.rule : null}
          channels={channels}
          channelsError={channelsError}
          onCancel={() => setEditor(null)}
          onSaved={handleSaved}
        />
      ) : null}

      {loading && rules === null ? <Loading text="正在加载告警规则…" /> : null}

      {!loading && !error && rules !== null && rules.length === 0 ? (
        <EmptyState title="还没有告警规则">点击“新建规则”创建第一条。</EmptyState>
      ) : null}

      {rules !== null && rules.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table alert-table">
            <thead>
              <tr>
                <th>名称</th>
                <th>目标</th>
                <th>阈值</th>
                <th>持续 / 冷却</th>
                <th>筛选</th>
                <th>渠道</th>
                <th>启用</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => {
                const busy = busyRule === rule.id;
                return (
                  <tr key={rule.id}>
                    <td>
                      <div className="alert-name-cell">
                        {rule.is_builtin ? (
                          <span className="builtin-badge">内置</span>
                        ) : null}
                        <span>{rule.name}</span>
                      </div>
                      <span className="muted small mono">{rule.id}</span>
                    </td>
                    <td>
                      <div>{formatRuleTarget(rule)}</div>
                      <span className="muted small">
                        {rule.source === "metric" ? "指标阈值" : alertSourceLabel(rule.source)}
                      </span>
                    </td>
                    <td className="mono nowrap">{formatRuleThreshold(rule)}</td>
                    <td className="nowrap">
                      {formatDurationSecs(rule.duration_secs)} /{" "}
                      {formatDurationSecs(rule.cooldown_secs)}
                    </td>
                    <td className="wrap-cell">{formatRuleFilter(rule)}</td>
                    <td className="nowrap">
                      {rule.channel_ids.length === 0
                        ? "未绑定"
                        : `${rule.channel_ids.length} 个`}
                    </td>
                    <td>
                      <button
                        type="button"
                        role="switch"
                        aria-checked={rule.enabled}
                        aria-label={`${rule.enabled ? "停用" : "启用"}规则 ${rule.name}`}
                        className={`switch ${rule.enabled ? "on" : ""}`}
                        onClick={() => void toggleRule(rule)}
                        disabled={busy}
                      />
                    </td>
                    <td>
                      <div className="row-actions">
                        <button
                          type="button"
                          className="button small"
                          onClick={() => {
                            setEditor({ mode: "edit", rule });
                            setNotice(null);
                            setActionError(null);
                          }}
                        >
                          编辑
                        </button>
                        <button
                          type="button"
                          className="button small danger"
                          title={
                            rule.is_builtin ? "内置规则不可删除，可停用" : "删除规则"
                          }
                          disabled={rule.is_builtin || busy}
                          onClick={() => setPendingDelete(rule.id)}
                        >
                          删除
                        </button>
                        {pendingDelete === rule.id ? (
                          <span className="alert-inline-confirm">
                            <span className="muted small">确认？</span>
                            <button
                              type="button"
                              className="button small danger"
                              disabled={busy}
                              onClick={() => void deleteRule(rule)}
                            >
                              确认删除
                            </button>
                            <button
                              type="button"
                              className="button small"
                              onClick={() => setPendingDelete(null)}
                            >
                              取消
                            </button>
                          </span>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

function RuleEditor({
  rule,
  channels,
  channelsError,
  onCancel,
  onSaved,
}: {
  rule: AlertRule | null;
  channels: ChannelView[];
  channelsError: string | null;
  onCancel: () => void;
  onSaved: (rule: AlertRule, message: string) => void;
}) {
  const [form, setForm] = useState<RuleFormState>(() =>
    rule ? ruleFormFromRule(rule) : emptyRuleForm(),
  );
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const update = <K extends keyof RuleFormState>(
    key: K,
    value: RuleFormState[K],
  ) => {
    setForm((previous) => ({ ...previous, [key]: value }));
  };

  const updateLabel = (index: number, patch: Partial<RuleFormState["labels"][number]>) => {
    setForm((previous) => ({
      ...previous,
      labels: previous.labels.map((row, rowIndex) =>
        rowIndex === index ? { ...row, ...patch } : row,
      ),
    }));
  };

  const toggleChannel = (id: string) => {
    setForm((previous) => ({
      ...previous,
      channelIds: previous.channelIds.includes(id)
        ? previous.channelIds.filter((item) => item !== id)
        : [...previous.channelIds, id],
    }));
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);
    setRequestError(null);
    setNotice(null);
    const validation = validateRuleForm(form);
    if (validation) {
      setFormError(validation);
      return;
    }
    setSubmitting(true);
    try {
      if (rule) {
        const payload = buildRuleUpdatePayload(rule, form);
        if (!hasRuleChanges(payload)) {
          setNotice("没有需要保存的修改");
          return;
        }
        const updated = await api.updateAlertRule(rule.id, payload);
        onSaved(updated, `规则「${updated.name}」已更新`);
      } else {
        const created = await api.createAlertRule(buildRuleCreatePayload(form));
        onSaved(created, `规则「${created.name}」已创建`);
      }
    } catch (submitError) {
      setRequestError(describeAlertError(submitError));
    } finally {
      setSubmitting(false);
    }
  };

  const metricRequired = sourceRequiresMetric(form.source);

  return (
    <form className="panel alert-form" onSubmit={(event) => void handleSubmit(event)}>
      <div className="panel-toolbar">
        <div>
          <h2>{rule ? `编辑规则：${rule.name}` : "新建规则"}</h2>
          <p className="muted">
            {rule?.is_builtin
              ? "内置规则可修改阈值与启停；删除按钮已禁用。"
              : "编辑时只提交发生变化的字段。"}
          </p>
        </div>
      </div>

      {formError ? <div className="form-error">{formError}</div> : null}
      {requestError ? <ErrorBanner message={requestError} /> : null}
      {notice ? <div className="banner info">{notice}</div> : null}

      <div className="alert-form-grid">
        <Field label="名称">
          <input
            type="text"
            value={form.name}
            maxLength={64}
            onChange={(event) => update("name", event.target.value)}
            placeholder="例如 磁盘使用率过高"
            autoComplete="off"
          />
        </Field>

        <Field label="来源">
          <select
            value={form.source}
            onChange={(event) =>
              update("source", event.target.value as RuleFormState["source"])
            }
          >
            {ALERT_SOURCE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </Field>

        {metricRequired ? (
          <Field label="Metric" hint="小写字母、数字与 _ . -">
            <input
              type="text"
              value={form.metric}
              maxLength={64}
              onChange={(event) => update("metric", event.target.value)}
              placeholder="例如 disk.used_percent"
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
        ) : null}

        <Field label="比较符">
          <select
            value={form.comparator}
            onChange={(event) =>
              update("comparator", event.target.value as RuleFormState["comparator"])
            }
          >
            {ALERT_COMPARATOR_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </Field>

        <Field label="阈值">
          <input
            type="number"
            step="any"
            value={form.threshold}
            onChange={(event) => update("threshold", event.target.value)}
            placeholder="例如 90"
          />
        </Field>

        <Field label="持续时间（秒）" hint={`0–${MAX_RULE_DURATION_SECS}`}>
          <input
            type="number"
            min={0}
            max={MAX_RULE_DURATION_SECS}
            step={1}
            value={form.durationSecs}
            onChange={(event) => update("durationSecs", event.target.value)}
          />
        </Field>

        <Field label="冷却时间（秒）" hint={`0–${MAX_RULE_COOLDOWN_SECS}`}>
          <input
            type="number"
            min={0}
            max={MAX_RULE_COOLDOWN_SECS}
            step={1}
            value={form.cooldownSecs}
            onChange={(event) => update("cooldownSecs", event.target.value)}
          />
        </Field>

        <Field label="过滤 agent（可选）" hint="留空 = 全部 agent">
          <input
            type="text"
            value={form.filterAgentId}
            maxLength={64}
            onChange={(event) => update("filterAgentId", event.target.value)}
            placeholder="例如 hub-self"
            autoComplete="off"
          />
        </Field>
      </div>

      <div className="alert-form-section">
        <div className="alert-form-section-head">
          <h3>Labels 过滤</h3>
          <span className="muted small">
            {form.labels.length}/{MAX_RULE_LABELS} 对 · 精确子集匹配
          </span>
        </div>
        <div className="alert-labels">
          {form.labels.map((row, index) => (
            <div className="alert-label-row" key={index}>
              <input
                type="text"
                value={row.key}
                maxLength={64}
                aria-label={`label 键 ${index + 1}`}
                placeholder="key"
                autoComplete="off"
                onChange={(event) => updateLabel(index, { key: event.target.value })}
              />
              <input
                type="text"
                value={row.value}
                maxLength={256}
                aria-label={`label 值 ${index + 1}`}
                placeholder="value"
                autoComplete="off"
                onChange={(event) => updateLabel(index, { value: event.target.value })}
              />
              <button
                type="button"
                className="button small"
                onClick={() =>
                  setForm((previous) => ({
                    ...previous,
                    labels: previous.labels.filter((_, rowIndex) => rowIndex !== index),
                  }))
                }
              >
                删除
              </button>
            </div>
          ))}
          <div>
            <button
              type="button"
              className="button small"
              disabled={form.labels.length >= MAX_RULE_LABELS}
              onClick={() =>
                setForm((previous) => ({
                  ...previous,
                  labels: [...previous.labels, { key: "", value: "" }],
                }))
              }
            >
              添加 label
            </button>
          </div>
        </div>
      </div>

      <div className="alert-form-section">
        <div className="alert-form-section-head">
          <h3>绑定通知渠道</h3>
          <span className="muted small">不绑定也记录事件，但不发送通知</span>
        </div>
        {channelsError ? (
          <p className="form-error">渠道列表加载失败：{channelsError}</p>
        ) : null}
        {channels.length === 0 ? (
          <p className="muted small">暂无通知渠道，可先在“渠道”页创建。</p>
        ) : (
          <div className="alert-checkbox-grid">
            {channels.map((channel) => (
              <label className="checkbox-row" key={channel.id}>
                <input
                  type="checkbox"
                  checked={form.channelIds.includes(channel.id)}
                  onChange={() => toggleChannel(channel.id)}
                />
                <span>{channel.name}</span>
                <span className="muted small">{channelKindLabel(channel.kind)}</span>
              </label>
            ))}
          </div>
        )}
      </div>

      <div className="alert-form-section">
        <div className="checkbox-row-group">
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={form.notifyOnResolve}
              onChange={(event) => update("notifyOnResolve", event.target.checked)}
            />
            恢复时发送通知
          </label>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(event) => update("enabled", event.target.checked)}
            />
            启用规则
          </label>
        </div>
      </div>

      <div className="alert-form-actions">
        <button
          type="button"
          className="button"
          onClick={onCancel}
          disabled={submitting}
        >
          取消
        </button>
        <button type="submit" className="button primary" disabled={submitting}>
          {submitting ? "保存中…" : rule ? "保存修改" : "创建规则"}
        </button>
      </div>
    </form>
  );
}

// ===========================================================================
// 事件
// ===========================================================================

function EventsPanel() {
  const [events, setEvents] = useState<AlertEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [moreError, setMoreError] = useState<string | null>(null);
  const [nextBeforeId, setNextBeforeId] = useState<number | null | undefined>(undefined);
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
    setEvents([]);
    setNextBeforeId(undefined);
    api
      .alertEvents({ limit: ALERT_EVENT_PAGE_SIZE }, controller.signal)
      .then((data) => {
        if (controller.signal.aborted || generation !== generationRef.current) return;
        setEvents(data.events);
        setNextBeforeId(data.next_before_id ?? null);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        if (generation !== generationRef.current) return;
        setError(describeAlertError(loadError));
      })
      .finally(() => {
        if (controller.signal.aborted || generation !== generationRef.current) return;
        setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  const loadMore = async () => {
    if (loading || loadingMore || nextBeforeId === null || nextBeforeId === undefined) {
      return;
    }
    const generation = generationRef.current;
    const cursor = nextBeforeId;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const data = await api.alertEvents({
        limit: ALERT_EVENT_PAGE_SIZE,
        beforeId: cursor,
      });
      if (generation !== generationRef.current) return;
      setEvents((previous) => {
        const seen = new Set(previous.map((event) => event.id));
        return [...previous, ...data.events.filter((event) => !seen.has(event.id))];
      });
      setNextBeforeId(data.next_before_id ?? null);
    } catch (loadError) {
      if (isAbortError(loadError)) return;
      if (generation === generationRef.current) {
        setMoreError(describeAlertError(loadError));
      }
    } finally {
      if (generation === generationRef.current) setLoadingMore(false);
    }
  };

  const hasMore = nextBeforeId !== null && nextBeforeId !== undefined;

  return (
    <div className="alert-panel">
      <div className="panel-toolbar">
        <div>
          <h2>告警事件</h2>
          <p className="muted">
            每页 {ALERT_EVENT_PAGE_SIZE} 条 · 静默期间事件仍记录，但标记为未通知
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
      {loading ? <Loading text="正在加载告警事件…" /> : null}

      {!loading && !error && events.length === 0 ? (
        <EmptyState title="还没有告警事件">
          规则触发或恢复后，事件会出现在这里。
        </EmptyState>
      ) : null}

      {events.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table alert-table alert-event-table">
            <thead>
              <tr>
                <th>时间</th>
                <th>规则</th>
                <th>Agent</th>
                <th>状态</th>
                <th>值</th>
                <th>Message</th>
                <th>静默</th>
                <th>通知状态</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id}>
                  <td className="nowrap">{formatEventTime(event.ts)}</td>
                  <td className="wrap-cell" title={event.rule_id}>
                    {formatEventRule(event)}
                  </td>
                  <td className="mono wrap-cell">{formatEventAgent(event.agent_id)}</td>
                  <td>
                    <span className={`event-pill ${eventStateClass(event.state)}`}>
                      {formatEventState(event.state)}
                    </span>
                  </td>
                  <td className="mono nowrap">{formatAlertValue(event.value)}</td>
                  <td className="wrap-cell" title={event.message}>
                    {event.message || "—"}
                  </td>
                  <td>
                    {event.silenced ? (
                      <span className="silent-badge">静默</span>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td className={event.notify_error ? "error-cell" : "wrap-cell"}>
                    {formatNotifyStatus(event)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {moreError ? <ErrorBanner message={moreError} /> : null}

      {events.length > 0 ? (
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
            <span className="muted">已加载全部 {events.length} 条</span>
          )}
        </div>
      ) : null}
    </div>
  );
}

// ===========================================================================
// 渠道
// ===========================================================================

function ChannelsPanel() {
  const [channels, setChannels] = useState<ChannelView[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [editor, setEditor] = useState<
    { mode: "create" } | { mode: "edit"; channel: ChannelView } | null
  >(null);
  const [testingId, setTestingId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [testFeedback, setTestFeedback] = useState<{
    ok: boolean;
    text: string;
  } | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    api
      .alertChannels(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setChannels(data);
      })
      .catch((loadError: unknown) => {
        if (controller.signal.aborted || isAbortError(loadError)) return;
        setError(describeAlertError(loadError));
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, [reloadKey]);

  const testChannel = async (channel: ChannelView) => {
    if (testingId !== null) return;
    setTestingId(channel.id);
    setTestFeedback(null);
    try {
      await api.testAlertChannel(channel.id);
      setTestFeedback({
        ok: true,
        text: `渠道「${channel.name}」测试消息已发送`,
      });
    } catch (testError) {
      setTestFeedback({
        ok: false,
        text: `渠道「${channel.name}」测试失败：${describeAlertError(testError)}`,
      });
    } finally {
      setTestingId(null);
    }
  };

  const deleteChannel = async (channel: ChannelView) => {
    if (busyId !== null) return;
    setBusyId(channel.id);
    setActionError(null);
    setNotice(null);
    try {
      await api.deleteAlertChannel(channel.id);
      setChannels((previous) =>
        previous?.filter((item) => item.id !== channel.id) ?? null,
      );
      setPendingDelete(null);
      setNotice(`渠道「${channel.name}」已删除`);
    } catch (deleteError) {
      setActionError(describeAlertError(deleteError));
    } finally {
      setBusyId(null);
    }
  };

  const handleSaved = (channel: ChannelView, message: string) => {
    setChannels((previous) => {
      const list = previous ?? [];
      return list.some((item) => item.id === channel.id)
        ? list.map((item) => (item.id === channel.id ? channel : item))
        : [...list, channel];
    });
    setEditor(null);
    setActionError(null);
    setNotice(message);
  };

  return (
    <div className="alert-panel">
      <div className="panel-toolbar">
        <div>
          <h2>通知渠道</h2>
          <p className="muted">
            secret 只写入 hub；列表与编辑表单只显示“已配置”的字段名，永不回显值。
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
          <button
            type="button"
            className="button primary"
            onClick={() => {
              setEditor({ mode: "create" });
              setNotice(null);
              setActionError(null);
            }}
          >
            新建渠道
          </button>
        </div>
      </div>

      {notice ? <div className="banner info">{notice}</div> : null}
      {actionError ? <ErrorBanner message={actionError} /> : null}
      {testFeedback ? (
        <div className={`banner ${testFeedback.ok ? "info" : "error"}`} role="status">
          {testFeedback.text}
        </div>
      ) : null}
      {error ? (
        <ErrorBanner
          message={error}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : null}

      {editor ? (
        <ChannelEditor
          key={editor.mode === "create" ? "create" : editor.channel.id}
          channel={editor.mode === "edit" ? editor.channel : null}
          onCancel={() => setEditor(null)}
          onSaved={handleSaved}
        />
      ) : null}

      {loading && channels === null ? <Loading text="正在加载通知渠道…" /> : null}

      {!loading && !error && channels !== null && channels.length === 0 ? (
        <EmptyState title="还没有通知渠道">
          先创建一个渠道，再在规则中绑定并启用。
        </EmptyState>
      ) : null}

      {channels !== null && channels.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table alert-table alert-channel-table">
            <thead>
              <tr>
                <th>名称</th>
                <th>类型</th>
                <th>启用</th>
                <th>Secret</th>
                <th>更新时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {channels.map((channel) => {
                const busy = busyId === channel.id || testingId === channel.id;
                return (
                  <tr key={channel.id}>
                    <td>
                      <div>{channel.name}</div>
                      <span className="muted small mono">{channel.id}</span>
                    </td>
                    <td>
                      <span className="channel-kind-badge">
                        {channelKindLabel(channel.kind)}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`status-pill ${
                          channel.enabled ? "status-online" : "status-unknown"
                        }`}
                      >
                        {channel.enabled ? "已启用" : "已停用"}
                      </span>
                    </td>
                    <td>
                      <div className="muted small">{channelSecretSummary(channel)}</div>
                      <div className="secret-tags">
                        {channelSecretFields(channel.kind).map((field) => {
                          const configured = isSecretConfigured(channel, field.key);
                          return (
                            <span
                              key={field.key}
                              className={`secret-pill ${configured ? "configured" : ""}`}
                            >
                              {field.label}
                              {configured ? " ✓" : " 未配置"}
                            </span>
                          );
                        })}
                      </div>
                    </td>
                    <td className="nowrap">{formatDateTime(channel.updated_at)}</td>
                    <td>
                      <div className="row-actions">
                        <button
                          type="button"
                          className="button small"
                          onClick={() => void testChannel(channel)}
                          disabled={testingId !== null}
                        >
                          {testingId === channel.id ? "测试中…" : "测试"}
                        </button>
                        <button
                          type="button"
                          className="button small"
                          onClick={() => {
                            setEditor({ mode: "edit", channel });
                            setNotice(null);
                            setActionError(null);
                          }}
                        >
                          编辑
                        </button>
                        <button
                          type="button"
                          className="button small danger"
                          disabled={busy}
                          onClick={() => setPendingDelete(channel.id)}
                        >
                          删除
                        </button>
                        {pendingDelete === channel.id ? (
                          <span className="alert-inline-confirm">
                            <span className="muted small">确认？</span>
                            <button
                              type="button"
                              className="button small danger"
                              disabled={busy}
                              onClick={() => void deleteChannel(channel)}
                            >
                              确认删除
                            </button>
                            <button
                              type="button"
                              className="button small"
                              onClick={() => setPendingDelete(null)}
                            >
                              取消
                            </button>
                          </span>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

function ChannelEditor({
  channel,
  onCancel,
  onSaved,
}: {
  channel: ChannelView | null;
  onCancel: () => void;
  onSaved: (channel: ChannelView, message: string) => void;
}) {
  const isEdit = channel !== null;
  const [form, setForm] = useState<ChannelFormState>(() =>
    channel ? channelFormFromView(channel) : emptyChannelForm(),
  );
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  // secret 只存在 DOM 节点里，不进入 React state，也不参与渲染。
  const secretRefs = useRef<Record<string, HTMLInputElement | null>>({});

  const updateConfig = (key: string, value: string) => {
    setForm((previous) => ({
      ...previous,
      config: { ...previous.config, [key]: value },
    }));
  };

  const changeKind = (kind: ChannelKind) => {
    setForm((previous) => ({ ...previous, kind, config: {} }));
    secretRefs.current = {};
  };

  const collectSecrets = (): Record<string, string> => {
    const secrets: Record<string, string> = {};
    for (const field of channelSecretFields(form.kind)) {
      secrets[field.key] = secretRefs.current[field.key]?.value ?? "";
    }
    return secrets;
  };

  const clearSecrets = () => {
    for (const input of Object.values(secretRefs.current)) {
      if (input) input.value = "";
    }
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);
    setRequestError(null);
    const secrets = collectSecrets();
    const validation = validateChannelForm(form, secrets, isEdit);
    if (validation) {
      setFormError(validation);
      return;
    }
    setSubmitting(true);
    try {
      const input = buildChannelInput(form, secrets);
      const saved = channel
        ? await api.updateAlertChannel(channel.id, input)
        : await api.createAlertChannel(input);
      clearSecrets();
      setForm(emptyChannelForm(form.kind));
      onSaved(saved, `渠道「${saved.name}」已保存`);
    } catch (submitError) {
      setRequestError(describeAlertError(submitError));
    } finally {
      setSubmitting(false);
    }
  };

  const fields = channelFields(form.kind);

  return (
    <form className="panel alert-form" onSubmit={(event) => void handleSubmit(event)}>
      <div className="panel-toolbar">
        <div>
          <h2>{channel ? `编辑渠道：${channel.name}` : "新建渠道"}</h2>
          <p className="muted">
            {isEdit
              ? "secret 留空表示保留已保存的值；不会从 hub 读取或回显。"
              : "新建时必须填写该渠道的全部 secret。"}
          </p>
        </div>
      </div>

      {formError ? <div className="form-error">{formError}</div> : null}
      {requestError ? <ErrorBanner message={requestError} /> : null}

      <div className="alert-form-grid">
        <Field label="名称">
          <input
            type="text"
            value={form.name}
            maxLength={64}
            onChange={(event) =>
              setForm((previous) => ({ ...previous, name: event.target.value }))
            }
            placeholder="例如 运维群"
            autoComplete="off"
          />
        </Field>

        <Field label="类型">
          <select
            value={form.kind}
            disabled={isEdit}
            onChange={(event) => changeKind(event.target.value as ChannelKind)}
          >
            {CHANNEL_KIND_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </Field>

        {fields.nonSecret.map((field) => (
          <Field key={field.key} label={field.label}>
            <input
              type="text"
              value={form.config[field.key] ?? ""}
              onChange={(event) => updateConfig(field.key, event.target.value)}
              placeholder={field.placeholder}
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
        ))}

        {fields.secret.map((field) => {
          const configured = isEdit && channel !== null && isSecretConfigured(channel, field.key);
          return (
            <Field
              key={field.key}
              label={`${field.label}（secret）`}
              hint={isEdit ? "留空表示不修改" : "必填"}
            >
              <input
                key={`${form.kind}:${field.key}`}
                ref={(element) => {
                  secretRefs.current[field.key] = element;
                }}
                type="password"
                placeholder={
                  isEdit
                    ? configured
                      ? "已配置，留空不修改"
                      : "未配置，留空不修改"
                    : field.placeholder
                }
                autoComplete="new-password"
                spellCheck={false}
              />
            </Field>
          );
        })}
      </div>

      <div className="alert-form-section">
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(event) =>
              setForm((previous) => ({ ...previous, enabled: event.target.checked }))
            }
          />
          启用渠道
        </label>
      </div>

      <div className="alert-form-actions">
        <button
          type="button"
          className="button"
          onClick={onCancel}
          disabled={submitting}
        >
          取消
        </button>
        <button type="submit" className="button primary" disabled={submitting}>
          {submitting ? "保存中…" : channel ? "保存修改" : "创建渠道"}
        </button>
      </div>
    </form>
  );
}

// ===========================================================================
// 静默
// ===========================================================================

function SilencesPanel() {
  const [silences, setSilences] = useState<AlertSilence[] | null>(null);
  const [rules, setRules] = useState<AlertRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  const [form, setForm] = useState<SilenceFormState>(emptySilenceForm);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    const controller = new AbortController();
    Promise.all([
      api.alertSilences(controller.signal),
      api.alertRules(controller.signal).catch(() => [] as AlertRule[]),
    ])
      .then(([active, allRules]) => {
        if (cancelled) return;
        setSilences(active);
        setRules(allRules);
      })
      .catch((loadError: unknown) => {
        if (cancelled || isAbortError(loadError)) return;
        setError(describeAlertError(loadError));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [reloadKey]);

  const createSilence = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);
    setActionError(null);
    setNotice(null);
    const validation = validateSilenceForm(form);
    if (validation) {
      setFormError(validation);
      return;
    }
    setSubmitting(true);
    try {
      const created = await api.createAlertSilence(buildSilenceInput(form));
      setSilences((previous) => [created, ...(previous ?? [])]);
      setForm(emptySilenceForm());
      setNotice("静默已创建");
    } catch (submitError) {
      setActionError(describeAlertError(submitError));
    } finally {
      setSubmitting(false);
    }
  };

  const cancelSilence = async (silence: AlertSilence) => {
    if (busyId !== null) return;
    setBusyId(silence.id);
    setActionError(null);
    setNotice(null);
    try {
      await api.deleteAlertSilence(silence.id);
      setSilences((previous) =>
        previous?.filter((item) => item.id !== silence.id) ?? null,
      );
      setPendingDelete(null);
      setNotice("静默已撤销");
    } catch (deleteError) {
      setActionError(describeAlertError(deleteError));
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="alert-panel">
      <div className="panel-toolbar">
        <div>
          <h2>静默</h2>
          <p className="muted">
            静默期间事件仍会记录，但不发送通知；可只匹配某条规则或某个 agent。
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

      <form className="panel alert-form" onSubmit={(event) => void createSilence(event)}>
        <div className="panel-toolbar">
          <div>
            <h2>新建静默</h2>
            <p className="muted">
              时长 {MIN_SILENCE_SECS}–{MAX_SILENCE_SECS} 秒；留空规则 / agent 表示全部。
            </p>
          </div>
        </div>

        {formError ? <div className="form-error">{formError}</div> : null}
        {actionError ? <ErrorBanner message={actionError} /> : null}
        {notice ? <div className="banner info">{notice}</div> : null}

        <div className="alert-form-grid">
          <Field label="规则（可选）">
            <select
              value={form.ruleId}
              onChange={(event) =>
                setForm((previous) => ({ ...previous, ruleId: event.target.value }))
              }
            >
              <option value="">全部规则</option>
              {rules.map((rule) => (
                <option key={rule.id} value={rule.id}>
                  {rule.name}
                </option>
              ))}
            </select>
          </Field>

          <Field label="Agent（可选）" hint="留空 = 全部 agent">
            <input
              type="text"
              value={form.agentId}
              maxLength={64}
              onChange={(event) =>
                setForm((previous) => ({ ...previous, agentId: event.target.value }))
              }
              placeholder="全部 agent"
              autoComplete="off"
            />
          </Field>

          <Field label="时长（秒）" hint={`${MIN_SILENCE_SECS}–${MAX_SILENCE_SECS}`}>
            <input
              type="number"
              min={MIN_SILENCE_SECS}
              max={MAX_SILENCE_SECS}
              step={1}
              value={form.durationSecs}
              onChange={(event) =>
                setForm((previous) => ({
                  ...previous,
                  durationSecs: event.target.value,
                }))
              }
            />
          </Field>
        </div>

        <div className="alert-form-actions">
          <button type="submit" className="button primary" disabled={submitting}>
            {submitting ? "创建中…" : "创建静默"}
          </button>
        </div>
      </form>

      {error ? (
        <ErrorBanner
          message={error}
          onRetry={() => setReloadKey((value) => value + 1)}
        />
      ) : null}
      {loading && silences === null ? <Loading text="正在加载静默…" /> : null}

      {!loading && !error && silences !== null && silences.length === 0 ? (
        <EmptyState title="当前没有生效中的静默">
          创建后会显示在这里，到期自动失效。
        </EmptyState>
      ) : null}

      {silences !== null && silences.length > 0 ? (
        <div className="table-scroll">
          <table className="data-table alert-table alert-silence-table">
            <thead>
              <tr>
                <th>范围</th>
                <th>静默至</th>
                <th>创建者</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {silences.map((silence) => {
                const busy = busyId === silence.id;
                return (
                  <tr key={silence.id}>
                    <td className="wrap-cell">
                      {formatSilenceScope(silence, rules)}
                    </td>
                    <td className="nowrap">{formatSilenceUntil(silence.until_ts)}</td>
                    <td>{silence.created_by || "—"}</td>
                    <td className="nowrap">{formatDateTime(silence.created_at)}</td>
                    <td>
                      <div className="row-actions">
                        <button
                          type="button"
                          className="button small danger"
                          disabled={busy}
                          onClick={() => setPendingDelete(silence.id)}
                        >
                          撤销
                        </button>
                        {pendingDelete === silence.id ? (
                          <span className="alert-inline-confirm">
                            <span className="muted small">确认撤销？</span>
                            <button
                              type="button"
                              className="button small danger"
                              disabled={busy}
                              onClick={() => void cancelSilence(silence)}
                            >
                              确认
                            </button>
                            <button
                              type="button"
                              className="button small"
                              onClick={() => setPendingDelete(null)}
                            >
                              取消
                            </button>
                          </span>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
