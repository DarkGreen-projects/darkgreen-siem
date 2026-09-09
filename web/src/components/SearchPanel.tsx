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

export default function SearchPanel() {
  const [q, setQ] = useState("action:deny");
  const [sourceType, setSourceType] = useState("");
  const [severity, setSeverity] = useState("");
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

  useEffect(() => {
    setSaved(loadSavedQueries());
  }, []);

  const runSearch = useCallback(
    async (next?: { q?: string; source_type?: string; severity?: string }) => {
      const query = next?.q ?? q;
      const st = next?.source_type ?? sourceType;
      const sev = next?.severity ?? severity;
      setLoading(true);
      setError(null);
      try {
        const res = await api.search({
          q: query,
          source_type: st || undefined,
          severity: sev || undefined,
          since_minutes: 1440,
        });
        setTotal(res.total);
        setEvents(res.events);
        setAlertHits(res.alerts || []);
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setLoading(false);
      }
    },
    [q, sourceType, severity]
  );

  const applyQuick = (item: QuickQuery) => {
    setQ(item.q);
    setSourceType(item.source_type);
    setSeverity(item.severity);
    void runSearch({
      q: item.q,
      source_type: item.source_type,
      severity: item.severity,
    });
  };

  const applySaved = (item: SavedQuery) => {
    setQ(item.q);
    setSourceType(item.source_type);
    setSeverity(item.severity);
    void runSearch({
      q: item.q,
      source_type: item.source_type,
      severity: item.severity,
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
            <label htmlFor="q">Query</label>
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
          <div style={{ flex: "0 0 auto" }}>
            <label>&nbsp;</label>
            <div className="row" style={{ gap: "0.4rem", flexWrap: "nowrap" }}>
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
          <h3 className="muted query-section-title">Query rapide</h3>
          <div className="query-chips" role="group" aria-label="Query rapide">
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
              <dt>Canale</dt>
              <dd className="mono">{selected.ingest_channel}</dd>
              <dt>Vendor</dt>
              <dd>{selected.vendor || "—"}</dd>
              <dt>Host</dt>
              <dd>{selected.host || "—"}</dd>
              <dt>User</dt>
              <dd>{selected.user || "—"}</dd>
              <dt>Src IP</dt>
              <dd className="mono ioc-inline">
                {selected.src_ip || "—"}
                <VtIpLink ip={selected.src_ip} />
              </dd>
              <dt>Dst IP</dt>
              <dd className="mono ioc-inline">
                {selected.dst_ip || "—"}
                <VtIpLink ip={selected.dst_ip} />
              </dd>
              <dt>Action</dt>
              <dd className="mono">{selected.action || "—"}</dd>
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
    </>
  );
}
