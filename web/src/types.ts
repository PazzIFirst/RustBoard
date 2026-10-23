/** hub 管理 API 的响应形状；前端只依赖这里定义的字段。 */

export interface AgentRecord {
  agent_id: string;
  name: string;
  hostname: string;
  os: string;
  arch: string;
  version: string;
  boot_id: string;
  status: string;
  last_seen_at: number;
  created_at: number;
}

export interface LatestSample {
  agent_id: string;
  metric: string;
  labels: Record<string, string>;
  ts: number;
  value: number;
}

export interface AgentSetting {
  agent_id: string;
  sample_interval_ms: number;
}

export interface OverviewResponse {
  server_time: number;
  agents: AgentRecord[];
  latest: LatestSample[];
  settings: AgentSetting[];
}

export interface SamplePoint {
  ts: number;
  value: number;
}

export interface SeriesPoint {
  metric: string;
  labels: Record<string, string>;
  points: SamplePoint[];
}

export interface SeriesResponse {
  bucket_ms: number;
  series: SeriesPoint[];
}

export type SystemInfo = Record<string, unknown>;

/** M3 控制面：hub / agent 共同开启的能力。 */
export type ControlCapability = "systemd" | "docker" | "process" | "logs";

export interface ControlStatus {
  control_enabled: boolean;
  online: boolean;
  /** agent 实际上报的能力。 */
  capabilities: string[];
  /** hub 配置中开启的能力。 */
  hub_capabilities: string[];
}

export interface SystemdUnit {
  unit: string;
  load: string;
  active: string;
  sub: string;
  description: string;
}

export interface DockerContainer {
  id: string;
  name: string;
  image: string;
  state: string;
  status: string;
}

export interface ProcessInfo {
  pid: number;
  name: string;
  uid: number;
  /** 常驻内存，统一换算成字节。 */
  rss: number;
  /** 线协议原始字段（KiB）；hub 若直接透传 agent 字段会出现。 */
  rss_kb?: number;
  cmdline: string;
}

export interface LogSourceInfo {
  id: string;
  name: string;
  kind: string;
  /** file 为绝对路径，journal 为 unit 名。 */
  target: string;
  /** 可选：hub 能提供大小时展示；当前线协议没有该字段。 */
  size?: number;
}

export interface ControlActionOutput {
  stdout: string;
  stderr: string;
  exit_code: number | null;
}

export interface ControlLogLines {
  source: string;
  lines: string[];
  truncated: boolean;
  size_bytes: number;
}

/** hub 控制 API 的 `result` 判别联合；字段以方案 §3.1 / §3.3 为准。 */
export type ControlResult =
  | { type: "systemd_units"; units: SystemdUnit[] }
  | { type: "docker_containers"; containers: DockerContainer[] }
  | { type: "processes"; processes: ProcessInfo[] }
  | { type: "log_sources"; sources: LogSourceInfo[] }
  | ({ type: "log_lines" } & ControlLogLines)
  | ({ type: "action_output" } & ControlActionOutput);

export interface ControlError {
  code: string;
  message: string;
}

/** `api.control()` 已把 HTTP 错误归一化成 `ok:false`，页面无需再解析响应体。 */
export type ControlResponse =
  | { ok: true; result: ControlResult }
  | { ok: false; error: ControlError; status?: number };

export interface ControlRequestPayload {
  capability: ControlCapability;
  action: string;
  target?: string;
  pid?: number;
  name?: string;
  signal?: "term" | "kill";
  source?: string;
  lines?: number;
  confirm?: boolean;
}

export interface AuditEntry {
  id: number;
  /** 服务端时间戳；兼容秒与毫秒，展示层统一归一化。 */
  ts: number;
  actor: string;
  agent_id: string;
  capability: string;
  action: string;
  target: string;
  result: string;
  error_code: string;
  error_message: string;
  duration_ms: number;
}

export interface AuditResponse {
  entries: AuditEntry[];
  /** 服务端排他游标（id < next_before_id）；null 表示没有更多。 */
  next_before_id?: number | null;
}

export interface AuditQuery {
  limit?: number;
  beforeId?: number;
  agentId?: string;
  capability?: string;
}

/** M4 告警：规则来源与比较符使用 hub 的稳定小写字符串。 */
export type AlertSource = "metric" | "agent_offline" | "hub_cert";
export type AlertComparator = "gt" | "gte" | "lt" | "lte" | "eq" | "ne";
export type AlertEventState = "firing" | "resolved";

export interface AlertRule {
  id: string;
  name: string;
  enabled: boolean;
  source: AlertSource;
  /** `metric` 来源必填；其他来源为空字符串。 */
  metric: string;
  comparator: AlertComparator;
  threshold: number;
  duration_secs: number;
  cooldown_secs: number;
  filter_agent_id: string | null;
  filter_labels: Record<string, string>;
  channel_ids: string[];
  notify_on_resolve: boolean;
  /** 内置规则可改可停，但不可删除。 */
  is_builtin: boolean;
  updated_by: string;
  created_at: number;
  updated_at: number;
}

/** PUT 只包含出现即覆盖的字段；页面只发送实际变更。 */
export interface AlertRuleInput {
  name?: string;
  enabled?: boolean;
  source?: AlertSource;
  metric?: string;
  comparator?: AlertComparator;
  threshold?: number;
  duration_secs?: number;
  cooldown_secs?: number;
  filter_agent_id?: string | null;
  filter_labels?: Record<string, string>;
  channel_ids?: string[];
  notify_on_resolve?: boolean;
}

export interface AlertEvent {
  id: number;
  ts: number;
  rule_id: string;
  /** 事件产生时的规则名快照。 */
  rule_name: string;
  /** 全局事件为空字符串。 */
  agent_id: string;
  state: AlertEventState;
  value: number | null;
  message: string;
  notified: boolean;
  notify_error: string;
  silenced: boolean;
}

export interface AlertEventListResponse {
  events: AlertEvent[];
  /** 本页满时返回最后一条 id；null 表示没有更多。 */
  next_before_id?: number | null;
}

export interface AlertSilence {
  id: number;
  /** `null` = 全部规则。 */
  rule_id: string | null;
  /** `null` = 全部 agent。 */
  agent_id: string | null;
  until_ts: number;
  created_by: string;
  created_at: number;
}

export interface AlertSilenceInput {
  rule_id?: string | null;
  agent_id?: string | null;
  duration_secs: number;
}

export type ChannelKind = "telegram" | "wecom" | "dingtalk" | "feishu";

/**
 * 渠道 API 视图（B2b 实际形状）。
 *
 * Telegram 的非敏感配置 `chat_id` 是扁平字段；`secret_fields` 只列出已配置的
 * secret 字段名。任何 secret 值都不会出现在响应里。
 */
export interface ChannelView {
  id: string;
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  /** Telegram 的 chat_id；其他渠道为 null。 */
  chat_id: string | null;
  secret_fields: string[];
  updated_by: string;
  created_at: number;
  updated_at: number;
}

/** 新建 / 编辑渠道的请求体；secret 留空表示编辑时保留原值。 */
export interface ChannelInput {
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  config: Record<string, string>;
}

// ---------------------------------------------------------------- M4 归档

/** 归档对象状态；与 hub / SQLite 的稳定字符串一致。 */
export type ArchiveObjectStatus =
  | "pending"
  | "uploaded"
  | "local_deleted"
  | "failed";

/**
 * 归档对象视图。
 *
 * 只含对象元数据；后端 URL / 凭据不会出现在响应里。`error` 是固定错误码
 * （未知内容已被 hub 收敛为 `archive_error`），页面不直接渲染任意后端报文。
 */
export interface ArchiveObject {
  id: number;
  object_key: string;
  manifest_key: string;
  from_ts: number;
  to_ts: number;
  rows: number;
  bytes: number;
  sha256: string;
  status: ArchiveObjectStatus;
  error: string;
  created_at: number;
  uploaded_at: number | null;
  deleted_at: number | null;
}

export interface ArchiveObjectListResponse {
  objects: ArchiveObject[];
  /** 本页满时返回最后一条 id；null 表示没有更多。 */
  next_before_id?: number | null;
}

/** `GET /api/archive/status`；`backend` 只是类型名，不含地址或凭据。 */
export interface ArchiveStatus {
  enabled: boolean;
  backend: string;
  last_archived_ts: number | null;
  last_run: number | null;
  last_error: string | null;
  objects: number;
}
