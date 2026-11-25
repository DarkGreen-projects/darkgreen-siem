import { useCallback, useEffect, useState } from "react";
import { api, type Alert, type AlertSearchHit, type SiemEvent } from "../api";
import {
  QUICK_QUERIES,
  addSavedQuery,
  loadSavedQueries,
  removeSavedQuery,
  type QuickQuery,
  type SavedQuery,
} from "../savedQueries";
import AlertCard from "./AlertCard";
import QueryHelpWiki from "./QueryHelpWiki";
import { iocForIp, type IocHit } from "../vtLinks";

function VtIpLink({ ip }: { ip: string | null | undefined }) {
  const ioc: IocHit | null = iocForIp(ip);
  if (!ioc) return null;
  return (
    <a className="vt-link" href={ioc.vtUrl} target="_blank" rel="noopener noreferrer">
      VT
    </a>
  );
}

function csvEscape(value: unknown): string {
  const s = value == null ? "" : String(value);
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function downloadSearchCsv(events: SiemEvent[], alerts: AlertSearchHit[]): void {
  const header = [
    "kind",
    "id",
    "timestamp",
    "source_type",
    "severity",
    "action",
    "user",
    "src_ip",
    "dst_ip",
    "host",
    "status",
    "title",
    "message",
  ];
  const rows: string[][] = [header];
  for (const ev of events) {
    rows.push([
      "event",
      String(ev.id),
      ev.timestamp || "",
      ev.source_type || "",
      ev.severity || "",
      ev.action || "",
      ev.user || "",
      ev.src_ip || "",
      ev.dst_ip || "",
      ev.host || "",
      "",
      "",
      ev.message || "",
    ]);
  }
  for (const a of alerts) {
    rows.push([
      "alert",
      String(a.id),
      a.created_at || "",
      "",
      a.severity || "",
      "",
      "",
      "",
      "",
      "",
      a.status || "",
      a.title || "",
      a.description || "",
    ]);
  }
  const body = rows.map((r) => r.map(csvEscape).join(",")).join("\r\n");
  const blob = new Blob([body], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `darkgreen-search-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export default function SearchPanel({
  initialQuery,
  onPivotConsumed,
  onPivotSearch,
}: {
  initialQuery?: string | null;
  onPivotConsumed?: () => void;
  onPivotSearch?: (query: string) => void;
} = {}) {
  const [q, setQ] = useState("action:deny");
  const [sourceType, setSourceType] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [total, setTotal] = useState(0);
  const [events, setEvents] = useState<SiemEvent[]>([]);
  const [alertHits, setAlertHits] = useState<AlertSearchHit[]>([]);
  const [selected, setSelected] = useState<SiemEvent | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [saved, setSaved] = useState<SavedQuery[]>([]);
  const [saveName, setSaveName] = useState("");
  const [showSaveForm, setShowSaveForm] = useState(false);
  const [showQueryWiki, setShowQueryWiki] = useState(false);
  const [hasSearched, setHasSearched] = useState(false);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    setSaved(loadSavedQueries());
  }, []);

  const runSearch = useCallback(
    async (next?: {
      q?: string;
      source_type?: string;
      severity?: string;
      status?: string;
    }) => {
      const query = next?.q ?? q;
      const st = next?.source_type ?? sourceType;
      const sev = next?.severity ?? severity;
      const stStatus = next?.status ?? status;
      setLoading(true);
      setError(null);
      try {
        const res = await api.search({
          q: query,
          source_type: st || undefined,
          severity: sev || undefined,
          status: stStatus || undefined,
          since_minutes: 1440,
        });
        setTotal(res.total);
        setEvents(res.events);
        setAlertHits(res.alerts || []);
        setHasSearched(true);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [q, sourceType, severity, status]
  );

  const exportResults = () => {
    setExporting(true);
    try {
      downloadSearchCsv(events, alertHits);
    } finally {
      setExporting(false);
    }
  };

  useEffect(() => {
    if (!initialQuery) return;
    setQ(initialQuery);
    setSourceType("");
    setSeverity("");
    setStatus("");
    void runSearch({ q: initialQuery, source_type: "", severity: "", status: "" });
    onPivotConsumed?.();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery]);

  const applyQuick = (item: QuickQuery) => {
    setQ(item.q);
    setSourceType(item.source_type);
    setSeverity(item.severity);
    setStatus("");
    void runSearch({
      q: item.q,
      source_type: item.source_type,
      severity: item.severity,
      status: "",
    });
  };

  const applySaved = (item: SavedQuery) => {
    setQ(item.q);
    setSourceType(item.source_type);
    setSeverity(item.severity);
    setStatus("");
    void runSearch({
      q: item.q,
      source_type: item.source_type,
      severity: item.severity,
      status: "",
    });
  };

  const saveCurrent = () => {
    const name = saveName.trim();
    if (!name) return;
    setSaved(
      addSavedQuery({
        name,
        q,
        source_type: sourceType,
        severity,
      })
    );
    setSaveName("");
    setShowSaveForm(false);
  };

  const deleteSaved = (id: string) => {
    setSaved(removeSavedQuery(id));
  };

  return (
    <>
      <div className="panel">
        <div className="row">
          <div style={{ flex: 2 }}>
            <label htmlFor="q" className="query-label">
              Query{" "}
              <button
                type="button"
                className="query-help-btn"
                aria-label="Apri guida costruzione query"
                title="Guida query"
                onClick={() => setShowQueryWiki(true)}
              >
                ?
              </button>
            </label>
            <input
              id="q"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder='src_ip:203.0.113.45 AND action:deny'
              onKeyDown={(e) => e.key === "Enter" && void runSearch()}
            />
          </div>
          <div>
            <label htmlFor="st">Sorgente</label>
            <select id="st" value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
              <option value="">Qualsiasi</option>
              <option value="firewall">firewall</option>
              <option value="windows">windows</option>
              <option value="cloud_auth">cloud_auth</option>
              <option value="siem_export">siem_export</option>
            </select>
          </div>
          <div>
            <label htmlFor="sev">Severity</label>
            <select id="sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">Qualsiasi</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
          </div>
          <div>
            <label htmlFor="alert-status">Stato</label>
            <select
              id="alert-status"
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              aria-label="Filtro stato alert"
            >
              <option value="">Qualsiasi</option>
              <option value="open">open</option>
              <option value="acked">acked</option>
              <option value="in_progress">in_progress</option>
              <option value="closed">closed</option>
            </select>
          </div>
          <div style={{ flex: "0 0 auto" }}>
            <label>&nbsp;</label>
            <div className="search-actions">
              <button
                className="primary"
                type="button"
                onClick={() => void runSearch()}
                disabled={loading}
              >
                {loading ? "Ricerca…" : "Cerca"}
              </button>
              <button
                className="ghost"
                type="button"
                onClick={() => setShowSaveForm((v) => !v)}
                title="Salva query corrente"
              >
                Salva
              </button>
            </div>
          </div>
        </div>

        {showSaveForm && (
          <div className="save-query-row">
            <input
              value={saveName}
              onChange={(e) => setSaveName(e.target.value)}
              placeholder="Nome per questa query"
              onKeyDown={(e) => e.key === "Enter" && saveCurrent()}
              aria-label="Nome query salvata"
            />
            <button className="primary" type="button" onClick={saveCurrent} disabled={!saveName.trim()}>
              Conferma
            </button>
            <button className="ghost" type="button" onClick={() => setShowSaveForm(false)}>
              Annulla
            </button>
          </div>
        )}

        <div className="query-section">
          <h3 className="muted query-section-title">Ricerche predefinite</h3>
          <div className="query-chips" role="group" aria-label="Ricerche predefinite">
            {QUICK_QUERIES.map((item) => (
              <button
                key={item.id}
                type="button"
                className="query-chip"
                onClick={() => applyQuick(item)}
                title={[item.q, item.source_type && `source=${item.source_type}`, item.severity && `sev=${item.severity}`]
                  .filter(Boolean)
                  .join(" · ")}
              >
                {item.label}
              </button>
            ))}
          </div>
        </div>

        <div className="query-section">
          <h3 className="muted query-section-title">Query salvate</h3>
          {saved.length === 0 ? (
            <p className="muted" style={{ margin: 0 }}>
              Nessuna query salvata
            </p>
          ) : (
            <div className="query-chips" role="list" aria-label="Query salvate">
              {saved.map((item) => (
                <span key={item.id} className="saved-chip" role="listitem">
                  <button
                    type="button"
                    className="query-chip"
                    onClick={() => applySaved(item)}
                    title={item.q || "(solo filtri)"}
                  >
                    {item.name}
                  </button>
                  <button
                    type="button"
                    className="chip-delete"
                    aria-label={`Elimina ${item.name}`}
                    onClick={() => deleteSaved(item.id)}
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {error && <p className="error">{error}</p>}

      {hasSearched && (
        <div className="panel search-results-toolbar">
          <p className="muted" style={{ margin: 0 }}>
            Risultati: {total} evento{total === 1 ? "" : "i"}
            {alertHits.length > 0 ? ` · ${alertHits.length} alert` : ""}
          </p>
          <button
            type="button"
            className="ghost"
            disabled={exporting || (events.length === 0 && alertHits.length === 0)}
            onClick={exportResults}
          >
            {exporting ? "Export…" : "Esporta risultati CSV"}
          </button>
        </div>
      )}

      {alertHits.length > 0 && (
        <div className="panel">
          <h3 className="muted" style={{ marginTop: 0 }}>
            Alert corrispondenti ({alertHits.length})
          </h3>
          <p className="muted">
            Corrispondenze su titolo, descrizione o commenti — clicca per aprire.
          </p>
          <div className="list-block">
            {alertHits.map((hit) => (
              <button
                key={hit.id}
                type="button"
                className="alert-hit-row"
                onClick={() => setSelectedAlert(hit)}
              >
                <div className="row" style={{ marginBottom: "0.25rem" }}>
                  <strong style={{ flex: 1, textAlign: "left" }}>{hit.title}</strong>
                  <span className={`badge status-${hit.status}`}>{hit.status}</span>
                  <span className={`badge ${hit.severity}`}>{hit.severity}</span>
                </div>
                {hit.matched_comment ? (
                  <div className="muted" style={{ textAlign: "left" }}>
                    Commento: {hit.matched_comment}
                  </div>
                ) : (
                  <div className="muted" style={{ textAlign: "left" }}>
                    {hit.description}
                  </div>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="panel">
        <p className="muted">
          {total} evento{total === 1 ? "" : "i"} trovato{total === 1 ? "" : "i"}
        </p>
        <table>
          <thead>
            <tr>
              <th>Ora</th>
              <th>Sorgente</th>
              <th>Severity</th>
              <th>Action</th>
              <th>User / IP</th>
              <th>Messaggio</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id} className="clickable" onClick={() => setSelected(ev)}>
                <td className="mono">{new Date(ev.timestamp).toLocaleString()}</td>
                <td className="mono">{ev.source_type}</td>
                <td>
                  <span className={`badge ${ev.severity}`}>{ev.severity}</span>
                </td>
                <td className="mono">{ev.action}</td>
                <td className="mono">
                  {ev.user || "—"}
                  <br />
                  {ev.src_ip || "—"} → {ev.dst_ip || "—"}
                </td>
                <td>{ev.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="drawer-backdrop" onClick={() => setSelected(null)}>
          <aside className="drawer" onClick={(e) => e.stopPropagation()}>
            <div className="row" style={{ marginBottom: "1rem" }}>
              <h2 style={{ margin: 0, flex: 1 }}>Evento #{selected.id}</h2>
              <button className="ghost" type="button" onClick={() => setSelected(null)}>
                Chiudi
              </button>
            </div>
            <dl className="kv">
              <dt>Timestamp</dt>
              <dd className="mono">{selected.timestamp}</dd>
              <dt>Sorgente</dt>
              <dd className="mono">{selected.source_type}</dd>
              <dt>Canale ingest</dt>
              <dd className="mono">{selected.ingest_channel}</dd>
              {(selected.event_id || selected.channel || selected.provider) && (
                <>
                  <dt>Event ID</dt>
                  <dd className="mono">{selected.event_id || "-"}</dd>
                  <dt>Channel</dt>
                  <dd className="mono">{selected.channel || "-"}</dd>
                  <dt>Provider</dt>
                  <dd className="mono">{selected.provider || "-"}</dd>
                </>
              )}
              <dt>Vendor</dt>
              <dd>{selected.vendor || "-"}</dd>
              <dt>Host</dt>
              <dd>{selected.host || "-"}</dd>
              <dt>User</dt>
              <dd>{selected.user || "-"}</dd>
              <dt>Src IP</dt>
              <dd className="mono ioc-inline">
                {selected.src_ip || "-"}
                <VtIpLink ip={selected.src_ip} />
              </dd>
              <dt>Dst IP</dt>
              <dd className="mono ioc-inline">
                {selected.dst_ip || "-"}
                <VtIpLink ip={selected.dst_ip} />
              </dd>
              <dt>Action</dt>
              <dd className="mono">{selected.action || "-"}</dd>
              <dt>Severity</dt>
              <dd>
                <span className={`badge ${selected.severity}`}>{selected.severity}</span>
              </dd>
              <dt>Messaggio</dt>
              <dd>{selected.message}</dd>
            </dl>
            <h3 className="muted">Raw</h3>
            <pre className="raw">{selected.raw}</pre>
            <h3 className="muted">Labels</h3>
            <pre className="raw">{JSON.stringify(selected.labels, null, 2)}</pre>
          </aside>
        </div>
      )}

      {selectedAlert && (
        <div className="drawer-backdrop" onClick={() => setSelectedAlert(null)}>
          <aside className="drawer" onClick={(e) => e.stopPropagation()}>
            <div className="row" style={{ marginBottom: "1rem" }}>
              <h2 style={{ margin: 0, flex: 1 }}>Alert #{selectedAlert.id}</h2>
              <button className="ghost" type="button" onClick={() => setSelectedAlert(null)}>
                Chiudi
              </button>
            </div>
            <AlertCard
              alert={selectedAlert}
              matchedComment={
                "matched_comment" in selectedAlert
                  ? (selectedAlert as AlertSearchHit).matched_comment
                  : null
              }
              enableHotkeys
              onPivotSearch={onPivotSearch}
              onUpdated={(updated) => {
                setSelectedAlert(updated);
                setAlertHits((prev) =>
                  prev.map((h) =>
                    h.id === updated.id ? { ...h, ...updated, matched_comment: h.matched_comment } : h
                  )
                );
              }}
            />
          </aside>
        </div>
      )}

      <QueryHelpWiki
        open={showQueryWiki}
        onClose={() => setShowQueryWiki(false)}
        onUseExample={(exampleQ) => setQ(exampleQ)}
      />
    </>
  );
}
