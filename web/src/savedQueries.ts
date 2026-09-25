export type SavedQuery = {
  id: string;
  name: string;
  q: string;
  source_type: string;
  severity: string;
  created_at: string;
};

export type QuickQuery = {
  id: string;
  label: string;
  q: string;
  source_type: string;
  severity: string;
};

const STORAGE_KEY = "darkgreen-siem.saved-queries";
const MAX_SAVED = 20;

export const QUICK_QUERIES: QuickQuery[] = [
  {
    id: "win-fail",
    label: "Logon falliti",
    q: "action:login_failed",
    source_type: "windows",
    severity: "",
  },
  {
    id: "fw-deny",
    label: "Deny firewall",
    q: "action:deny",
    source_type: "firewall",
    severity: "",
  },
  {
    id: "audit-cleared",
    label: "Audit cleared",
    q: "action:audit_cleared",
    source_type: "windows",
    severity: "",
  },
  {
    id: "malware",
    label: "Malware / EDR",
    q: "malware",
    source_type: "siem_export",
    severity: "",
  },
  {
    id: "cloud-fail",
    label: "Auth cloud fallite",
    q: "action:login_failed",
    source_type: "cloud_auth",
    severity: "",
  },
];

export function loadSavedQueries(): SavedQuery[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (item): item is SavedQuery =>
        !!item &&
        typeof item === "object" &&
        typeof (item as SavedQuery).id === "string" &&
        typeof (item as SavedQuery).name === "string" &&
        typeof (item as SavedQuery).q === "string"
    );
  } catch {
    return [];
  }
}

function persist(queries: SavedQuery[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(queries));
}

export function addSavedQuery(input: {
  name: string;
  q: string;
  source_type: string;
  severity: string;
}): SavedQuery[] {
  const name = input.name.trim();
  if (!name) return loadSavedQueries();
  const next: SavedQuery = {
    id: crypto.randomUUID(),
    name,
    q: input.q,
    source_type: input.source_type,
    severity: input.severity,
    created_at: new Date().toISOString(),
  };
  const list = [next, ...loadSavedQueries().filter((q) => q.name !== name)];
  const capped = list.slice(0, MAX_SAVED);
  persist(capped);
  return capped;
}

export function removeSavedQuery(id: string): SavedQuery[] {
  const capped = loadSavedQueries().filter((q) => q.id !== id);
  persist(capped);
  return capped;
}
