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

export type Alert = {
  id: number;
  rule_id: string;
  rule_name: string;
  severity: string;
  title: string;
  description: string;
  status: string;
  evidence: Record<string, unknown>;
  created_at: string;
  acked_at: string | null;
};

export type Rule = {
  id: string;
  name: string;
  description: string;
  severity: string;
  type: string;
  enabled: boolean;
  definition: Record<string, unknown>;
};

export type Source = {
  channel: string;
  count: number;
  last_event_at: string | null;
};

export type Stats = {
  total_events: number;
  total_alerts: number;
  open_alerts: number;
  eps_approx: number;
  by_source_type: Record<string, number>;
  by_severity: Record<string, number>;
  by_channel: Record<string, number>;
  timeline: { bucket: string; count: number }[];
  recent_alerts: Alert[];
};

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  stats: () => getJson<Stats>("/api/stats"),
  sources: () => getJson<Source[]>("/api/sources"),
  rules: () => getJson<Rule[]>("/api/rules"),
  alerts: (status?: string) =>
    getJson<Alert[]>(status ? `/api/alerts?status=${encodeURIComponent(status)}` : "/api/alerts"),
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
    return getJson<{ total: number; events: SiemEvent[] }>(`/api/events/search?${sp}`);
  },
  ackAlert: async (id: number) => {
    const res = await fetch(`/api/alerts/${id}/ack`, { method: "POST" });
    if (!res.ok) throw new Error("ack failed");
    return res.json() as Promise<Alert>;
  },
  runRules: async () => {
    const res = await fetch("/api/rules/run", { method: "POST" });
    if (!res.ok) throw new Error("run rules failed");
    return res.json() as Promise<Alert[]>;
  },
};
