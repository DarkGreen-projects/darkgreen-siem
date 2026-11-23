const TOKEN_KEY = "darkgreen-siem.auth-token";
const USER_KEY = "darkgreen-siem.auth-user";
const ROLE_KEY = "darkgreen-siem.auth-role";
const TENANT_KEY = "darkgreen-siem.auth-tenant";
const EXP_KEY = "darkgreen-siem.auth-exp";

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
  event_id?: string | null;
  channel?: string | null;
  provider?: string | null;
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
  mitre?: string | null;
  comments: AlertComment[];
  audit?: AlertAuditEntry[];
  created_at: string;
  acked_at: string | null;
  closed_at?: string | null;
  disposition?: string | null;
  closure_note?: string | null;
  closed_by?: string | null;
  risk_score?: number | null;
  noise_hint?: string | null;
  sla_ack_status?: string | null;
  sla_ack_target_minutes?: number | null;
  sla_ack_due_at?: string | null;
  sla_ack_elapsed_minutes?: number | null;
  sla_ack_remaining_minutes?: number | null;
  sla_close_status?: string | null;
  sla_close_target_minutes?: number | null;
  sla_close_due_at?: string | null;
  sla_close_elapsed_minutes?: number | null;
  sla_close_remaining_minutes?: number | null;
};

export type AlertAuditEntry = {
  id: number;
  alert_id: number;
  actor: string;
  from_status: string;
  to_status: string;
  note?: string | null;
  created_at: string;
};

export type SimilarAlert = {
  id: number;
  rule_id: string;
  title: string;
  severity: string;
  status: string;
  disposition?: string | null;
  created_at: string;
  closed_at?: string | null;
  noise_hint?: string | null;
  risk_score?: number | null;
};

export type AlertDisposition =
  | "true_positive"
  | "false_positive"
  | "benign"
  | "duplicate"
  | "tuning_needed";

export type MemoryCase = {
  alert_id: number;
  rule_id?: string;
  title?: string;
  disposition?: string | null;
  note_excerpt?: string;
  entity_key?: string | null;
  mitre?: string | null;
  score?: number;
  closed_at?: string | null;
};

export type ConnectedAlert = {
  id: number;
  title?: string;
  rule_id?: string | null;
  severity?: string | null;
  status?: string | null;
  disposition?: string | null;
  mitre?: string | null;
  relation: string;
  score?: number;
  direction?: string;
  shared_keys?: string[];
};

export type AlertLinks = {
  alert_id: number;
  connected: ConnectedAlert[];
  count: number;
};

export type TriageBrief = {
  alert_id: number;
  summary: string;
  entities: Record<string, string>;
  pivot_query?: string | null;
  similar_count: number;
  similar_fp: number;
  similar_tp: number;
  sla: Record<string, string | null | undefined>;
  noise_hint?: string | null;
  risk_score?: number | null;
  mitre?: string | null;
  threat_brief?: string | null;
  cases?: MemoryCase[];
  connected?: ConnectedAlert[];
  fingerprint?: Record<string, unknown>;
};

export type CopilotSuggest = {
  available: boolean;
  suggested_disposition?: string | null;
  suggested_note?: string | null;
  rationale?: string | null;
  message?: string | null;
  source?: string | null;
  citations?: number[];
  cases?: MemoryCase[];
  related_alert_ids?: number[];
  relation_hint?: string | null;
  brief?: TriageBrief | null;
};

export type MemoryStats = {
  tenant_id: string;
  total: number;
  by_disposition: Record<string, number>;
  last_closed_at?: string | null;
  rag_enabled: boolean;
  rag_top_k: number;
};

export type VtEnrich = {
  available: boolean;
  cached?: boolean;
  provider?: string;
  ioc_type?: string | null;
  value?: string | null;
  verdict?: string | null;
  malicious_count?: number;
  message?: string | null;
  error?: string | null;
};

export type MultiEnrich = {
  ioc_type: string;
  value: string;
  results: VtEnrich[];
};

export type AlertSearchHit = Alert & {
  matched_comment: string | null;
};

export type Rule = {
  id: string;
  name: string;
  description: string;
  threat_brief: string | null;
  mitre?: string | null;
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
  mitre?: string | string[] | null;
  type: "match" | "threshold" | string;
  severity: string;
  enabled?: boolean;
  window_minutes?: number;
  cooldown_minutes?: number;
  match: Record<string, string | string[]>;
  threshold?: number;
  group_by?: string;
  join_on?: string;
  steps?: { match: Record<string, string | string[]>; min_count?: number }[];
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
  by_alert_status: Record<string, number>;
  timeline: TimelineBucket[];
  source_health: SourceHealth[];
  recent_alerts: Alert[];
};

export type LabSetup = {
  retention_days: number;
  health_stale_minutes: number;
  health_silent_minutes: number;
  silence_alerts_enabled: boolean;
  purge_interval_sec: number;
  last_purge_at: string | null;
  last_purge_deleted: number;
  vt_configured?: boolean;
  vt_api_key_masked?: string | null;
  abuseipdb_configured?: boolean;
  abuseipdb_api_key_masked?: string | null;
  otx_configured?: boolean;
  otx_api_key_masked?: string | null;
  notify_webhook_configured?: boolean;
  notify_webhook_url_masked?: string | null;
  notify_format?: string;
  notify_min_severity?: string;
  sla_ack_minutes?: Record<string, number>;
  sla_close_minutes?: Record<string, number>;
  triage_scoring_enabled?: boolean;
  triage_prior_days?: number;
  rag_enabled?: boolean;
  rag_top_k?: number;
  llm_enabled?: boolean;
  llm_configured?: boolean;
  llm_api_key_masked?: string | null;
  llm_api_url?: string;
  llm_model?: string;
  graph_enabled?: boolean;
  graph_window_minutes?: number;
  graph_min_history?: number;
};

export type DryRunHit = {
  rule_id: string;
  rule_name: string;
  severity: string;
  title: string;
  mitre?: string | null;
  would_create: boolean;
  evidence: Record<string, unknown>;
};

export type DryRunResponse = {
  matched: DryRunHit[];
  events_normalized: number;
};

export type PurgeResult = {
  deleted: number;
  cutoff: string | null;
  skipped: boolean;
};

export const SOURCE_COLORS: Record<string, string> = {
  firewall: "#3ddc97",
  windows: "#6ec1ff",
  cloud_auth: "#e6b84d",
  siem_export: "#f38ba8",
};

export function clearAuthSession() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  localStorage.removeItem(ROLE_KEY);
  localStorage.removeItem(TENANT_KEY);
  localStorage.removeItem(EXP_KEY);
}

export function getStoredExpiresAt(): number | null {
  try {
    const raw = localStorage.getItem(EXP_KEY);
    if (!raw) return null;
    const n = Number(raw);
    return Number.isFinite(n) ? n : null;
  } catch {
    return null;
  }
}

export function isSessionExpired(): boolean {
  const exp = getStoredExpiresAt();
  if (exp == null) return false;
  return Math.floor(Date.now() / 1000) >= exp;
}

export function getStoredToken(): string | null {
  try {
    if (isSessionExpired()) {
      clearAuthSession();
      return null;
    }
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export type AuthMe = {
  username: string;
  kind: string;
  role: string;
  tenant_id: string;
  tenant_name?: string | null;
};

export type LoginResult = {
  token: string;
  expires_at: number;
  username: string;
  role: string;
  tenant_id: string;
};

export function getStoredUsername(): string | null {
  try {
    return localStorage.getItem(USER_KEY);
  } catch {
    return null;
  }
}

export function getStoredRole(): string | null {
  try {
    return localStorage.getItem(ROLE_KEY);
  } catch {
    return null;
  }
}

export function getStoredTenant(): string | null {
  try {
    return localStorage.getItem(TENANT_KEY);
  } catch {
    return null;
  }
}

export function setAuthSession(
  token: string,
  username: string,
  role?: string,
  tenantId?: string,
  expiresAt?: number
) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, username);
  if (role) localStorage.setItem(ROLE_KEY, role);
  if (tenantId) localStorage.setItem(TENANT_KEY, tenantId);
  if (expiresAt != null) localStorage.setItem(EXP_KEY, String(expiresAt));
}

function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...(extra || {}) };
  const token = getStoredToken();
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

export class AuthError extends Error {
  constructor(message = "Authentication required") {
    super(message);
    this.name = "AuthError";
  }
}

async function handleRes<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    clearAuthSession();
    throw new AuthError();
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { detail?: string };
      if (body.detail) detail = typeof body.detail === "string" ? body.detail : detail;
    } catch {
      /* ignore */
    }
    throw new Error(detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url, { headers: authHeaders() });
  return handleRes<T>(res);
}

async function ruleMutationError(res: Response): Promise<never> {
  if (res.status === 401) {
    clearAuthSession();
    throw new AuthError();
  }
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
  login: async (username: string, password: string) => {
    const res = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      let detail = "Login fallito";
      try {
        const body = (await res.json()) as { detail?: string };
        if (body.detail) detail = body.detail;
      } catch {
        /* ignore */
      }
      throw new Error(detail);
    }
    const data = (await res.json()) as LoginResult;
    setAuthSession(
      data.token,
      data.username,
      data.role,
      data.tenant_id,
      data.expires_at
    );
    return data;
  },
  me: () => getJson<AuthMe>("/api/auth/me"),
  stats: (range: StatsRange | string = "1h") =>
    getJson<Stats>(`/api/stats?range=${encodeURIComponent(range)}`),
  sources: () => getJson<Source[]>("/api/sources"),
  rules: () => getJson<Rule[]>("/api/rules"),
  createRule: async (payload: RuleCreatePayload) => {
    const res = await fetch("/api/rules", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload),
    });
    if (!res.ok) await ruleMutationError(res);
    return res.json() as Promise<Rule>;
  },
  updateRule: async (id: string, payload: RuleCreatePayload) => {
    const res = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ ...payload, overwrite: true }),
    });
    if (!res.ok) await ruleMutationError(res);
    return res.json() as Promise<Rule>;
  },
  deleteRule: async (id: string) => {
    const res = await fetch(`/api/rules/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: authHeaders(),
    });
    if (!res.ok) await ruleMutationError(res);
  },
  setRuleEnabled: async (id: string, enabled: boolean) => {
    const res = await fetch(`/api/rules/${encodeURIComponent(id)}/enabled`, {
      method: "PATCH",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) await ruleMutationError(res);
    return res.json() as Promise<Rule>;
  },
  alerts: (opts?: { status?: string; mitre?: string; sla?: string; disposition?: string }) => {
    const sp = new URLSearchParams();
    if (opts?.status) sp.set("status", opts.status);
    if (opts?.mitre) sp.set("mitre", opts.mitre);
    if (opts?.sla) sp.set("sla", opts.sla);
    if (opts?.disposition) sp.set("disposition", opts.disposition);
    const q = sp.toString();
    return getJson<Alert[]>(q ? `/api/alerts?${q}` : "/api/alerts");
  },
  alertQueue: (limit = 50) => getJson<Alert[]>(`/api/alerts/queue?limit=${limit}`),
  getAlert: (id: number) => getJson<Alert>(`/api/alerts/${id}`),
  similarAlerts: (id: number) => getJson<SimilarAlert[]>(`/api/alerts/${id}/similar`),
  alertBrief: (id: number) => getJson<TriageBrief>(`/api/alerts/${id}/brief`),
  alertLinks: (id: number) => getJson<AlertLinks>(`/api/alerts/${id}/links`),
  copilotSuggest: async (id: number) => {
    const res = await fetch(`/api/alerts/${id}/copilot-suggest`, {
      method: "POST",
      headers: authHeaders(),
    });
    return handleRes<CopilotSuggest>(res);
  },
  memoryStats: () => getJson<MemoryStats>("/api/memory/stats"),
  memoryExport: async (limit = 500) => {
    const res = await fetch(`/api/memory/export?limit=${limit}`, {
      headers: authHeaders(),
    });
    return handleRes<{
      version: number;
      tenant_id: string;
      count: number;
      cases: MemoryCase[];
    }>(res);
  },
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
  setAlertStatus: async (
    id: number,
    status: AlertStatus | string,
    opts?: { disposition?: AlertDisposition | string; closure_note?: string }
  ) => {
    const res = await fetch(`/api/alerts/${id}/status`, {
      method: "PATCH",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        status,
        disposition: opts?.disposition,
        closure_note: opts?.closure_note,
      }),
    });
    return handleRes<Alert>(res);
  },
  ackAlert: async (id: number) => {
    const res = await fetch(`/api/alerts/${id}/ack`, { method: "POST", headers: authHeaders() });
    return handleRes<Alert>(res);
  },
  addComment: async (id: number, body: string, author = "analyst") => {
    const res = await fetch(`/api/alerts/${id}/comments`, {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ body, author }),
    });
    return handleRes<AlertComment>(res);
  },
  runRules: async () => {
    const res = await fetch("/api/rules/run", { method: "POST", headers: authHeaders() });
    return handleRes<Alert[]>(res);
  },
  dryRunRules: async (events: unknown[], ruleIds?: string[]) => {
    const res = await fetch("/api/rules/dry-run", {
      method: "POST",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ events, rule_ids: ruleIds ?? null }),
    });
    return handleRes<DryRunResponse>(res);
  },
  setup: () => getJson<LabSetup>("/api/setup"),
  updateSetup: async (payload: {
    retention_days?: number;
    health_stale_minutes?: number;
    health_silent_minutes?: number;
    silence_alerts_enabled?: boolean;
    vt_api_key?: string;
    abuseipdb_api_key?: string;
    otx_api_key?: string;
    notify_webhook_url?: string;
    notify_format?: string;
    notify_min_severity?: string;
    sla_ack_minutes?: Record<string, number>;
    sla_close_minutes?: Record<string, number>;
    triage_scoring_enabled?: boolean;
    triage_prior_days?: number;
    rag_enabled?: boolean;
    rag_top_k?: number;
    llm_enabled?: boolean;
    llm_api_url?: string;
    llm_api_key?: string;
    llm_model?: string;
    graph_enabled?: boolean;
    graph_window_minutes?: number;
    graph_min_history?: number;
  }) => {
    const res = await fetch("/api/setup", {
      method: "PATCH",
      headers: authHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify(payload),
    });
    return handleRes<LabSetup>(res);
  },
  purge: async () => {
    const res = await fetch("/api/admin/purge", { method: "POST", headers: authHeaders() });
    return handleRes<PurgeResult>(res);
  },
  exportAlertsCsv: async (status?: string) => {
    const url = status
      ? `/api/alerts/export.csv?status=${encodeURIComponent(status)}`
      : "/api/alerts/export.csv";
    const res = await fetch(url, { headers: authHeaders() });
    if (res.status === 401) {
      clearAuthSession();
      throw new AuthError();
    }
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    const blob = await res.blob();
    const a = document.createElement("a");
    const href = URL.createObjectURL(blob);
    a.href = href;
    a.download = status ? `darkgreen-alerts-${status}.csv` : "darkgreen-alerts.csv";
    a.click();
    URL.revokeObjectURL(href);
  },
  enrichVt: (type: string, value: string) =>
    getJson<VtEnrich>(
      `/api/enrich/vt?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}`
    ),
  enrich: (type: string, value: string, providers = "vt,abuseipdb,otx") =>
    getJson<MultiEnrich>(
      `/api/enrich?type=${encodeURIComponent(type)}&value=${encodeURIComponent(value)}&providers=${encodeURIComponent(providers)}`
    ),
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
