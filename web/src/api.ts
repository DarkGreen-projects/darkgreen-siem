export type SiemEvent = {
  id: number;
  timestamp: string;
  source_type: string;
  vendor: string | null;
  device: string | null;
  host: string | null;
  user: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  action: string | null;
  severity: string;
  message: string;
  raw: string;
  labels: Record<string, unknown>;
  ingest_channel: string;
};

export type AlertStatus = "open" | "acked" | "in_progress" | "closed";

export type AlertComment = {
  id: number;
  alert_id: number;
  author: string;
  body: string;
  created_at: string;
};

export type Alert = {
  id: number;
  rule_id: string;
  rule_name: string;
  severity: string;
  title: string;
  description: string;
  status: AlertStatus | string;
  evidence: Record<string, unknown>;
  threat_brief: string | null;
  comments: AlertComment[];
  created_at: string;
  acked_at: string | null;
};

export type AlertSearchHit = Alert & {
  matched_comment: string | null;
};

export type Rule = {
  id: string;
  name: string;
  description: string;
  threat_brief: string | null;
  severity: string;
  type: string;
  enabled: boolean;
  definition: Record<string, unknown>;
};

export type RuleCreatePayload = {
  id: string;
  name: string;
  title?: string;
  description?: string;
  threat_brief?: string;
  type: "match" | "threshold" | string;
  severity: string;
  enabled?: boolean;
  window_minutes?: number;
  cooldown_minutes?: number;
  match: Record<string, string | string[]>;
  threshold?: number;
  group_by?: string;
  overwrite?: boolean;
};

export type Source = {
  channel: string;
  count: number;
  last_event_at: string | null;
};

export type SourceHealth = {
  source_type: string;
  last_event_at: string | null;
  silent_for_seconds: number | null;
  status: "ok" | "stale" | "silent" | string;
};

export type TimelineBucket = {
  bucket: string;
  count: number;
  by_source: Record<string, number>;
};

export type StatsRange = "1h" | "1d" | "7d" | "30d" | "1y";

export type Stats = {
  range: StatsRange | string;
  total_events: number;
  total_alerts: number;
  open_alerts: number;
  eps_approx: number;
  by_source_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_channel: Record<string, number>;
  timeline: TimelineBucket[];
  source_health: SourceHealth[];
  recent_alerts: Alert[];
};

export const SOURCE_COLORS: Record<string, string> = {
  firewall: "#3ddc97",
  windows: "#6ec1ff",
  cloud_auth: "#e6b84d",
  siem_export: "#f38ba8",
};

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

async function ruleMutationError(res: Response): Promise<never> {
  let detail = res.statusText;
  try {
    const body = (await res.json()) as { detail?: string };
    if (body.detail) detail = body.detail;
  } catch {
    /* ignore */
  }
  throw new Error(detail);
}

export const api = {
  stats: (range: StatsRange | string = "1h") =>
    getJson<Stats>(`/api/stats?range=${encodeURIComponent(range)}`),
  sources: () => getJson<Source[]>("/api/sources"),
  rules: () => getJson<Rule[]>("/api/rules"),
  createRule: async (payload: RuleCreatePayload) => {
    const res = await fetch("/api/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) await ruleMutationError(res);
    return res.json() as Promise<Rule>;
  },
  updateRule: async (id: string, payload: RuleCreatePayload) => {
    const res = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, overwrite: true }),
    });
    if (!res.ok) await ruleMutationError(res);
    return res.json() as Promise<Rule>;
  },
  deleteRule: async (id: string) => {
    const res = await fetch(`/api/rules/${encodeURIComponent(id)}`, { method: "DELETE" });
    if (!res.ok) await ruleMutationError(res);
  },
  setRuleEnabled: async (id: string, enabled: boolean) => {
    const res = await fetch(`/api/rules/${encodeURIComponent(id)}/enabled`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) await ruleMutationError(res);
    return res.json() as Promise<Rule>;
  },
  alerts: (status?: string) =>
    getJson<Alert[]>(status ? `/api/alerts?status=${encodeURIComponent(status)}` : "/api/alerts"),
  getAlert: (id: number) => getJson<Alert>(`/api/alerts/${id}`),
  search: (params: {
    q?: string;
    source_type?: string;
    severity?: string;
    since_minutes?: number;
  }) => {
    const sp = new URLSearchParams();
    if (params.q) sp.set("q", params.q);
    if (params.source_type) sp.set("source_type", params.source_type);
    if (params.severity) sp.set("severity", params.severity);
    if (params.since_minutes) sp.set("since_minutes", String(params.since_minutes));
    sp.set("limit", "100");
    return getJson<{ total: number; events: SiemEvent[]; alerts: AlertSearchHit[] }>(
      `/api/events/search?${sp}`
    );
  },
  setAlertStatus: async (id: number, status: AlertStatus | string) => {
    const res = await fetch(`/api/alerts/${id}/status`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error("status update failed");
    return res.json() as Promise<Alert>;
  },
  ackAlert: async (id: number) => {
    const res = await fetch(`/api/alerts/${id}/ack`, { method: "POST" });
    if (!res.ok) throw new Error("ack failed");
    return res.json() as Promise<Alert>;
  },
  addComment: async (id: number, body: string, author = "analyst") => {
    const res = await fetch(`/api/alerts/${id}/comments`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ body, author }),
    });
    if (!res.ok) throw new Error("comment failed");
    return res.json() as Promise<AlertComment>;
  },
  runRules: async () => {
    const res = await fetch("/api/rules/run", { method: "POST" });
    if (!res.ok) throw new Error("run rules failed");
    return res.json() as Promise<Alert[]>;
  },
};

export function formatSilence(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return "never";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return m ? `${h}h ${m}m` : `${h}h`;
  }
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  return h ? `${d}d ${h}h` : `${d}d`;
}
