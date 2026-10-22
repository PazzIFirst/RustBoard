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
