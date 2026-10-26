/**
 * 告警页面的纯函数：表单校验、payload 构造、事件 / 渠道展示格式化。
 *
 * 本文件不依赖 React 或 DOM，便于 vitest 直接覆盖；页面只负责把 state 传进来。
 * 所有 secret 只在提交瞬间从表单读取一次，不进入页面展示 state。
 */
import { ApiError, describeError } from "./api";
import { formatDateTime } from "./format";
import type {
  AlertComparator,
  AlertEvent,
  AlertRule,
  AlertRuleInput,
  AlertSilence,
  AlertSilenceInput,
  AlertSource,
  ChannelInput,
  ChannelKind,
  ChannelView,
} from "./types";

/** 事件分页大小（方案 §8.1：limit 1–100，面板固定 50）。 */
export const ALERT_EVENT_PAGE_SIZE = 50;
/** 规则筛选 labels 上限。 */
export const MAX_RULE_LABELS = 16;
/** 规则可绑定渠道数上限。 */
export const MAX_RULE_CHANNELS = 16;
/** `duration_secs` 上限：24 小时。 */
export const MAX_RULE_DURATION_SECS = 86_400;
/** `cooldown_secs` 上限：7 天。 */
export const MAX_RULE_COOLDOWN_SECS = 604_800;
/** 静默时长范围：1 秒–7 天。 */
export const MIN_SILENCE_SECS = 1;
export const MAX_SILENCE_SECS = 604_800;
/** 新建静默时的默认时长：1 小时。 */
export const DEFAULT_SILENCE_SECS = 3_600;

const MAX_NAME_BYTES = 64;
const MAX_METRIC_BYTES = 64;
const MAX_LABEL_KEY_BYTES = 64;
const MAX_LABEL_VALUE_BYTES = 256;
const MAX_CHANNEL_SECRET_BYTES = 128;
const METRIC_PATTERN = /^[a-z0-9_.-]+$/;
const AGENT_ID_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const CHANNEL_ID_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

export interface SelectOption<T extends string> {
  value: T;
  label: string;
}

export const ALERT_SOURCE_OPTIONS: Array<SelectOption<AlertSource> & { requiresMetric: boolean }> = [
  { value: "metric", label: "指标阈值", requiresMetric: true },
  { value: "agent_offline", label: "agent 离线", requiresMetric: false },
  { value: "hub_cert", label: "hub 证书剩余时间", requiresMetric: false },
];

export const ALERT_COMPARATOR_OPTIONS: Array<SelectOption<AlertComparator>> = [
  { value: "gt", label: ">（大于）" },
  { value: "gte", label: "≥（大于等于）" },
  { value: "lt", label: "<（小于）" },
  { value: "lte", label: "≤（小于等于）" },
  { value: "eq", label: "= （等于）" },
  { value: "ne", label: "≠（不等于）" },
];

export function alertSourceLabel(source: string): string {
  return ALERT_SOURCE_OPTIONS.find((item) => item.value === source)?.label ?? source;
}

export function comparatorLabel(comparator: string): string {
  return (
    ALERT_COMPARATOR_OPTIONS.find((item) => item.value === comparator)?.label ?? comparator
  );
}

export function sourceRequiresMetric(source: AlertSource): boolean {
  return ALERT_SOURCE_OPTIONS.find((item) => item.value === source)?.requiresMetric ?? false;
}

/** UTF-8 字节数；与 hub 的字节上限保持一致。 */
export function utf8Bytes(text: string): number {
  return new TextEncoder().encode(text).length;
}

// ---------------------------------------------------------------------------
// 规则表单
// ---------------------------------------------------------------------------

export interface RuleLabelForm {
  key: string;
  value: string;
}

export interface RuleFormState {
  name: string;
  enabled: boolean;
  source: AlertSource;
  metric: string;
  comparator: AlertComparator;
  /** 用字符串保存，避免 number input 的空值被当作 0。 */
  threshold: string;
  durationSecs: string;
  cooldownSecs: string;
  filterAgentId: string;
  labels: RuleLabelForm[];
  channelIds: string[];
  notifyOnResolve: boolean;
}

export function emptyRuleForm(): RuleFormState {
  return {
    name: "",
    enabled: true,
    source: "metric",
    metric: "",
    comparator: "gt",
    threshold: "",
    durationSecs: "0",
    cooldownSecs: "1800",
    filterAgentId: "",
    labels: [],
    channelIds: [],
    notifyOnResolve: true,
  };
}

export function ruleFormFromRule(rule: AlertRule): RuleFormState {
  return {
    name: rule.name,
    enabled: rule.enabled,
    source: rule.source,
    metric: rule.metric,
    comparator: rule.comparator,
    threshold: String(rule.threshold),
    durationSecs: String(rule.duration_secs),
    cooldownSecs: String(rule.cooldown_secs),
    filterAgentId: rule.filter_agent_id ?? "",
    labels: Object.entries(rule.filter_labels).map(([key, value]) => ({ key, value })),
    channelIds: [...rule.channel_ids],
    notifyOnResolve: rule.notify_on_resolve,
  };
}

/** 规则表单的本地校验；返回中文错误，`null` 表示通过。 */
export function validateRuleForm(form: RuleFormState): string | null {
  const name = form.name.trim();
  if (name === "") return "规则名称不能为空";
  if (utf8Bytes(name) > MAX_NAME_BYTES) return `规则名称不能超过 ${MAX_NAME_BYTES} 字节`;

  if (sourceRequiresMetric(form.source)) {
    const metric = form.metric.trim();
    if (metric === "") return "指标规则必须填写 metric";
    if (utf8Bytes(metric) > MAX_METRIC_BYTES || !METRIC_PATTERN.test(metric)) {
      return `metric 必须是 1–${MAX_METRIC_BYTES} 个 [a-z0-9_.-] 字符`;
    }
  }

  if (!isFiniteNumberText(form.threshold)) return "阈值必须是有限数字";

  const duration = integerField(form.durationSecs);
  if (duration === null || duration < 0 || duration > MAX_RULE_DURATION_SECS) {
    return `持续时间必须是 0–${MAX_RULE_DURATION_SECS} 的整数秒`;
  }
  const cooldown = integerField(form.cooldownSecs);
  if (cooldown === null || cooldown < 0 || cooldown > MAX_RULE_COOLDOWN_SECS) {
    return `冷却时间必须是 0–${MAX_RULE_COOLDOWN_SECS} 的整数秒`;
  }

  const agent = form.filterAgentId.trim();
  if (agent !== "" && !AGENT_ID_PATTERN.test(agent)) {
    return "filter_agent_id 必须是 1–64 个 [A-Za-z0-9_.-] 字符";
  }

  const labelError = validateRuleLabels(form.labels);
  if (labelError) return labelError;

  const uniqueChannels = new Set(form.channelIds);
  if (uniqueChannels.size > MAX_RULE_CHANNELS) {
    return `最多绑定 ${MAX_RULE_CHANNELS} 个通知渠道`;
  }
  for (const id of uniqueChannels) {
    if (!CHANNEL_ID_PATTERN.test(id)) return "channel_ids 含非法渠道 id";
  }
  return null;
}

export function validateRuleLabels(labels: RuleLabelForm[]): string | null {
  const seen = new Set<string>();
  let count = 0;
  for (const row of labels) {
    const key = row.key.trim();
    if (key === "" && row.value === "") continue;
    if (key === "") return "labels 的键不能为空";
    if (utf8Bytes(key) > MAX_LABEL_KEY_BYTES || /[\s\p{Cc}]/u.test(key)) {
      return `labels 的键必须是 1–${MAX_LABEL_KEY_BYTES} 字节且不含空白`;
    }
    if (utf8Bytes(row.value) > MAX_LABEL_VALUE_BYTES || /[\p{Cc}]/u.test(row.value)) {
      return `labels 的值不能超过 ${MAX_LABEL_VALUE_BYTES} 字节或包含控制字符`;
    }
    if (seen.has(key)) return `labels 的键重复：${key}`;
    seen.add(key);
    count += 1;
  }
  if (count > MAX_RULE_LABELS) return `labels 最多 ${MAX_RULE_LABELS} 对`;
  return null;
}

/**
 * 把表单的 labels 行转成对象；完全空白的行忽略。
 *
 * 用 `Object.fromEntries` 而不是 `{}` + `out[key] = value`：`__proto__` 是
 * 普通对象上的原型 setter，字符串值会被静默丢弃，导致后端允许的
 * `__proto__` 标签在创建 / 编辑时消失、筛选范围被扩大。#41
 */
export function buildFilterLabels(labels: RuleLabelForm[]): Record<string, string> {
  const entries: Array<[string, string]> = [];
  for (const row of labels) {
    const key = row.key.trim();
    if (key === "") continue;
    entries.push([key, row.value]);
  }
  return Object.fromEntries(entries);
}

/** 创建 / PUT 的完整字段集合；PUT 由 {@link buildRuleUpdatePayload} 做差集。 */
export type AlertRulePayload = Required<AlertRuleInput>;

export function buildRuleCreatePayload(form: RuleFormState): AlertRulePayload {
  return {
    name: form.name.trim(),
    enabled: form.enabled,
    source: form.source,
    metric: sourceRequiresMetric(form.source) ? form.metric.trim() : "",
    comparator: form.comparator,
    threshold: Number(form.threshold.trim()),
    duration_secs: Number(form.durationSecs.trim()),
    cooldown_secs: Number(form.cooldownSecs.trim()),
    filter_agent_id: form.filterAgentId.trim() === "" ? null : form.filterAgentId.trim(),
    filter_labels: buildFilterLabels(form.labels),
    channel_ids: [...new Set(form.channelIds)],
    notify_on_resolve: form.notifyOnResolve,
  };
}

/** 只保留与既有规则不同的字段；启停开关只会得到 `{enabled}`。 */
export function buildRuleUpdatePayload(
  original: AlertRule,
  form: RuleFormState,
): AlertRuleInput {
  const next = buildRuleCreatePayload(form);
  const payload: AlertRuleInput = {};
  if (next.name !== original.name) payload.name = next.name;
  if (next.enabled !== original.enabled) payload.enabled = next.enabled;
  if (next.source !== original.source) payload.source = next.source;
  if (next.metric !== original.metric) payload.metric = next.metric;
  if (next.comparator !== original.comparator) payload.comparator = next.comparator;
  if (next.threshold !== original.threshold) payload.threshold = next.threshold;
  if (next.duration_secs !== original.duration_secs) payload.duration_secs = next.duration_secs;
  if (next.cooldown_secs !== original.cooldown_secs) payload.cooldown_secs = next.cooldown_secs;
  if ((next.filter_agent_id ?? null) !== (original.filter_agent_id ?? null)) {
    payload.filter_agent_id = next.filter_agent_id ?? null;
  }
  if (canonicalLabels(next.filter_labels) !== canonicalLabels(original.filter_labels)) {
    payload.filter_labels = next.filter_labels;
  }
  if (!sameStringSet(next.channel_ids, original.channel_ids)) {
    payload.channel_ids = next.channel_ids;
  }
  if (next.notify_on_resolve !== original.notify_on_resolve) {
    payload.notify_on_resolve = next.notify_on_resolve;
  }
  return payload;
}

export function hasRuleChanges(payload: AlertRuleInput): boolean {
  return Object.keys(payload).length > 0;
}

function canonicalLabels(labels: Record<string, string>): string {
  return JSON.stringify(
    Object.keys(labels)
      .sort()
      .map((key) => [key, labels[key]]),
  );
}

function sameStringSet(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false;
  const rightSet = new Set(right);
  return left.every((value) => rightSet.has(value));
}

function integerField(text: string): number | null {
  const value = text.trim();
  if (!/^\d+$/.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

function isFiniteNumberText(text: string): boolean {
  const value = text.trim();
  if (value === "") return false;
  const parsed = Number(value);
  return Number.isFinite(parsed);
}

// ---------------------------------------------------------------------------
// 规则 / 事件展示
// ---------------------------------------------------------------------------

/** 持续 / 冷却秒数的紧凑展示。 */
export function formatDurationSecs(secs: number): string {
  if (!Number.isFinite(secs) || secs < 0) return "—";
  if (secs === 0) return "0 秒";
  if (secs % 86_400 === 0) return `${secs / 86_400} 天`;
  if (secs % 3_600 === 0) return `${secs / 3_600} 小时`;
  if (secs % 60 === 0) return `${secs / 60} 分钟`;
  return `${secs} 秒`;
}

/** 阈值比较的展示文本，例如 `> 90`。 */
export function formatRuleThreshold(rule: AlertRule): string {
  const symbol =
    ALERT_COMPARATOR_OPTIONS.find((item) => item.value === rule.comparator)?.label.charAt(0) ??
    rule.comparator;
  const threshold = Number.isInteger(rule.threshold)
    ? String(rule.threshold)
    : rule.threshold.toFixed(2);
  return `${symbol} ${threshold}`;
}

/** 规则目标：metric 名称或内置来源的中文名。 */
export function formatRuleTarget(rule: AlertRule): string {
  if (sourceRequiresMetric(rule.source)) {
    return rule.metric === "" ? `${alertSourceLabel(rule.source)}（未填写 metric）` : rule.metric;
  }
  return alertSourceLabel(rule.source);
}

/** 规则筛选条件：agent + labels 数量。 */
export function formatRuleFilter(rule: AlertRule): string {
  const parts: string[] = [];
  if (rule.filter_agent_id) parts.push(`agent=${rule.filter_agent_id}`);
  const labels = Object.keys(rule.filter_labels);
  if (labels.length > 0) parts.push(`${labels.length} 个 label`);
  return parts.length === 0 ? "全部" : parts.join(" · ");
}

/** 事件时间使用本地时间；与审计页一致。 */
export function formatEventTime(ts: number): string {
  return formatDateTime(ts);
}

export function formatEventState(state: string): string {
  switch (state) {
    case "firing":
      return "触发";
    case "resolved":
      return "恢复";
    case "pending":
      return "等待中";
    default:
      return state || "未知";
  }
}

export function eventStateClass(state: string): string {
  if (state === "firing") return "event-firing";
  if (state === "resolved") return "event-resolved";
  return "event-unknown";
}

/** 事件观测值：不是数字时统一显示 `—`，避免出现 NaN / Infinity。 */
export function formatAlertValue(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "—";
  if (Number.isInteger(value)) return String(value);
  return value.toFixed(2);
}

/** 事件是否 / 为何没有发出通知。 */
export function formatNotifyStatus(event: AlertEvent): string {
  if (event.silenced) return "静默中，未通知";
  if (event.notify_error) return `通知失败：${event.notify_error}`;
  if (event.notified) return "已通知";
  return "未通知";
}

export function formatEventAgent(agentId: string): string {
  return agentId === "" ? "全局" : agentId;
}

export function formatEventRule(event: AlertEvent): string {
  return event.rule_name !== "" ? event.rule_name : event.rule_id;
}

// ---------------------------------------------------------------------------
// 通知渠道
// ---------------------------------------------------------------------------

export interface ChannelFieldDef {
  key: string;
  label: string;
  placeholder: string;
}

interface ChannelKindDefinition {
  label: string;
  nonSecret: ChannelFieldDef[];
  secret: ChannelFieldDef[];
}

/**
 * 四种渠道的配置字段（B3 契约）。
 *
 * `secret` 字段只写不读：列表只显示 `secret_fields` 中的字段名，表单留空表示
 * 编辑时保留原值。
 */
export const CHANNEL_KIND_DEFINITIONS: Record<ChannelKind, ChannelKindDefinition> = {
  telegram: {
    label: "Telegram",
    nonSecret: [{ key: "chat_id", label: "chat_id", placeholder: "例如 123456789" }],
    secret: [{ key: "bot_token", label: "bot_token", placeholder: "BotFather 发放的 token" }],
  },
  wecom: {
    label: "企业微信",
    nonSecret: [],
    secret: [{ key: "webhook_key", label: "webhook_key", placeholder: "群机器人 key" }],
  },
  dingtalk: {
    label: "钉钉",
    nonSecret: [],
    secret: [
      { key: "access_token", label: "access_token", placeholder: "机器人 access_token" },
      { key: "secret", label: "secret", placeholder: "加签 secret" },
    ],
  },
  feishu: {
    label: "飞书",
    nonSecret: [],
    secret: [
      { key: "webhook_token", label: "webhook_token", placeholder: "机器人 webhook token" },
      { key: "secret", label: "secret", placeholder: "加签 secret" },
    ],
  },
};

export const CHANNEL_KIND_OPTIONS: Array<SelectOption<ChannelKind>> = (
  Object.keys(CHANNEL_KIND_DEFINITIONS) as ChannelKind[]
).map((kind) => ({ value: kind, label: CHANNEL_KIND_DEFINITIONS[kind].label }));

export function channelKindLabel(kind: ChannelKind | string): string {
  return (
    CHANNEL_KIND_DEFINITIONS[kind as ChannelKind]?.label ?? String(kind)
  );
}

export function channelFields(kind: ChannelKind): ChannelKindDefinition {
  return CHANNEL_KIND_DEFINITIONS[kind];
}

export function channelSecretFields(kind: ChannelKind): ChannelFieldDef[] {
  return CHANNEL_KIND_DEFINITIONS[kind].secret;
}

export interface ChannelFormState {
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  /** 只保存非敏感字段；secret 由不受控输入在提交时读取。 */
  config: Record<string, string>;
}

export function emptyChannelForm(kind: ChannelKind = "telegram"): ChannelFormState {
  return { name: "", kind, enabled: true, config: {} };
}

/**
 * 编辑时只回填非敏感字段；secret 永远不会进入表单 state。
 *
 * B2b 的响应把 Telegram 的 `chat_id` 放在顶层（其他渠道为 null），没有
 * `config` 对象；请求体才使用嵌套的 `config`。
 */
export function channelFormFromView(view: ChannelView): ChannelFormState {
  const config: Record<string, string> = {};
  for (const field of channelFields(view.kind).nonSecret) {
    if (field.key === "chat_id" && view.chat_id !== null) {
      config[field.key] = view.chat_id;
    }
  }
  return { name: view.name, kind: view.kind, enabled: view.enabled, config };
}

export function isSecretConfigured(view: ChannelView, field: string): boolean {
  return view.secret_fields.includes(field);
}

/** 列表用的 secret 汇总，只含字段名与数量，绝不包含值。 */
export function channelSecretSummary(view: ChannelView): string {
  const fields = channelSecretFields(view.kind);
  if (fields.length === 0) return "无 secret";
  const configured = fields.filter((field) => isSecretConfigured(view, field.key)).length;
  return `${configured}/${fields.length} 项 secret 已配置`;
}

/** 校验渠道表单；`secrets` 只在提交时传入，不进入页面 state。 */
export function validateChannelForm(
  form: ChannelFormState,
  secrets: Record<string, string>,
  isEdit: boolean,
): string | null {
  const name = form.name.trim();
  if (name === "") return "渠道名称不能为空";
  if (utf8Bytes(name) > MAX_NAME_BYTES) return `渠道名称不能超过 ${MAX_NAME_BYTES} 字节`;

  const fields = channelFields(form.kind);
  for (const field of fields.nonSecret) {
    const value = (form.config[field.key] ?? "").trim();
    if (value === "") {
      if (form.kind === "telegram" && field.key === "chat_id") {
        return "Telegram 渠道必须填写 chat_id";
      }
      return `${field.label} 不能为空`;
    }
  }
  for (const field of fields.secret) {
    const value = secrets[field.key] ?? "";
    if (value.trim() === "" && !isEdit) {
      return `新建 ${channelKindLabel(form.kind)} 渠道时必须填写 ${field.label}`;
    }
    if (utf8Bytes(value) > MAX_CHANNEL_SECRET_BYTES) {
      return `${field.label} 不能超过 ${MAX_CHANNEL_SECRET_BYTES} 字节`;
    }
  }
  return null;
}

/**
 * 构造渠道请求体。
 *
 * - 非敏感字段总是发送（编辑时允许清空后由 hub 拒绝）；
 * - secret 为空串时**不写入 config**，编辑语义为“保留已保存值”；
 * - 新建时调用方必须先通过 {@link validateChannelForm}。
 */
export function buildChannelInput(
  form: ChannelFormState,
  secrets: Record<string, string>,
): ChannelInput {
  const config: Record<string, string> = {};
  const fields = channelFields(form.kind);
  for (const field of fields.nonSecret) {
    const value = form.config[field.key] ?? "";
    if (value !== "") config[field.key] = value;
  }
  for (const field of fields.secret) {
    const value = secrets[field.key] ?? "";
    // 只发非空 secret；留空表示保留。值本身不 trim，避免破坏合法 token。
    if (value.trim() !== "") config[field.key] = value;
  }
  return {
    name: form.name.trim(),
    kind: form.kind,
    enabled: form.enabled,
    config,
  };
}

// ---------------------------------------------------------------------------
// 静默
// ---------------------------------------------------------------------------

export interface SilenceFormState {
  ruleId: string;
  agentId: string;
  durationSecs: string;
}

export function emptySilenceForm(): SilenceFormState {
  return { ruleId: "", agentId: "", durationSecs: String(DEFAULT_SILENCE_SECS) };
}

export function validateSilenceForm(form: SilenceFormState): string | null {
  const duration = integerField(form.durationSecs);
  if (duration === null || duration < MIN_SILENCE_SECS || duration > MAX_SILENCE_SECS) {
    return `静默时长必须是 ${MIN_SILENCE_SECS}–${MAX_SILENCE_SECS} 的整数秒`;
  }
  const agent = form.agentId.trim();
  if (agent !== "" && !AGENT_ID_PATTERN.test(agent)) {
    return "agent_id 必须是 1–64 个 [A-Za-z0-9_.-] 字符";
  }
  if (form.ruleId !== "" && !CHANNEL_ID_PATTERN.test(form.ruleId)) {
    return "rule_id 非法";
  }
  return null;
}

export function buildSilenceInput(form: SilenceFormState): AlertSilenceInput {
  const agent = form.agentId.trim();
  return {
    rule_id: form.ruleId === "" ? null : form.ruleId,
    agent_id: agent === "" ? null : agent,
    duration_secs: Number(form.durationSecs.trim()),
  };
}

/** 静默目标的展示文本；规则名找不到时回退 id。 */
export function formatSilenceScope(
  silence: AlertSilence,
  rules: AlertRule[],
): string {
  const ruleName =
    silence.rule_id === null
      ? "全部规则"
      : (rules.find((rule) => rule.id === silence.rule_id)?.name ?? silence.rule_id);
  const agent = silence.agent_id === null ? "全部 agent" : silence.agent_id;
  return `${ruleName} · ${agent}`;
}

/** 静默截止时间展示（本地时间）；过期显示“已结束”。 */
export function formatSilenceUntil(untilTs: number, nowMs = Date.now()): string {
  if (!Number.isFinite(untilTs)) return "—";
  if (untilTs <= nowMs) return "已结束";
  return `${formatDateTime(untilTs)} 结束`;
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/** 统一展示 hub / 面板错误：中文说明 + 服务端 code。 */
export function describeAlertError(error: unknown): string {
  if (!(error instanceof ApiError)) return describeError(error);
  const code = error.code ?? `http_${error.status}`;
  const message = error.serverMessage?.trim() || alertStatusMessage(error.status);
  return `${message}（${code}）`;
}

function alertStatusMessage(status: number): string {
  switch (status) {
    case 400:
      return "请求参数有误";
    case 401:
      return "登录已失效，请重新登录";
    case 403:
      return "没有权限执行该操作";
    case 404:
      return "目标不存在或已被删除";
    case 409:
      return "操作冲突，请刷新后重试";
    case 413:
      return "请求体过大";
    case 415:
      return "请求体必须是 JSON";
    case 502:
      return "无法访问 hub 管理 API";
    case 503:
      return "服务暂不可用，请稍后重试";
    case 504:
      return "请求超时，请稍后重试";
    default:
      return `请求失败（${status}）`;
  }
}
