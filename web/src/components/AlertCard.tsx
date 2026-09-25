import { useEffect, useMemo, useState } from "react";
import { api, type Alert, type AlertStatus, type VtEnrich } from "../api";
import { extractIocsFromAlert, type IocHit } from "../vtLinks";

export const ALERT_STATUS_OPTIONS: { value: AlertStatus; label: string }[] = [
  { value: "open", label: "aperto" },
  { value: "acked", label: "ack" },
  { value: "in_progress", label: "in corso" },
  { value: "closed", label: "chiuso" },
];

type Props = {
  alert: Alert;
  onUpdated: (alert: Alert) => void;
  compact?: boolean;
  matchedComment?: string | null;
};

function IocList({ iocs }: { iocs: IocHit[] }) {
  const [verdicts, setVerdicts] = useState<Record<string, VtEnrich[]>>({});
  const [vtNote, setVtNote] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const run = async () => {
      const next: Record<string, VtEnrich[]> = {};
      let anyConfigured = false;
      for (const ioc of iocs.slice(0, 8)) {
        const key = `${ioc.kind}:${ioc.value}`;
        try {
          const res = await api.enrich(ioc.kind, ioc.value);
          if (!alive) return;
          next[key] = res.results || [];
          if ((res.results || []).some((r) => r.available)) anyConfigured = true;
          const msg = (res.results || []).find((r) => r.message)?.message;
          if (msg && !(res.results || []).some((r) => r.available)) setVtNote(msg);
        } catch {
          /* ignore */
        }
      }
      if (alive) {
        setVerdicts(next);
        if (!anyConfigured && !vtNote) {
          setVtNote("Nessuna API enrichment configurata (Setup). Restano i link GUI.");
        }
      }
    };
    if (iocs.length) void run();
    return () => {
      alive = false;
    };
  }, [iocs]);

  if (iocs.length === 0) return null;
  return (
    <div className="ioc-block">
      <strong>IOC · Enrichment</strong>
      {vtNote && (
        <p className="muted" style={{ margin: "0.25rem 0", fontSize: "0.8rem" }}>
          {vtNote}
        </p>
      )}
      <div className="ioc-row">
        {iocs.map((ioc) => {
          const key = `${ioc.kind}:${ioc.value}`;
          const results = verdicts[key] || [];
          return (
            <span key={key} className="ioc-chip">
              <span className="badge">{ioc.kind}</span>
              <code className="mono">{ioc.value}</code>
              {results
                .filter((r) => r.available && r.verdict)
                .map((r) => (
                  <span
                    key={`${r.provider}-${r.verdict}`}
                    className={`badge vt-verdict vt-${r.verdict}`}
                  >
                    {r.provider}:{r.verdict}
                  </span>
                ))}
              <a
                className="vt-link"
                href={ioc.vtUrl}
                target="_blank"
                rel="noopener noreferrer"
                title="Apri su VirusTotal"
              >
                VT
              </a>
            </span>
          );
        })}
      </div>
    </div>
  );
}

export default function AlertCard({
  alert,
  onUpdated,
  compact = false,
  matchedComment,
}: Props) {
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const iocs = useMemo(
    () =>
      extractIocsFromAlert({
        title: alert.title,
        description: alert.description,
        threat_brief: alert.threat_brief,
        evidence: alert.evidence as Record<string, unknown>,
      }),
    [alert]
  );

  const setStatus = async (status: AlertStatus) => {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.setAlertStatus(alert.id, status);
      onUpdated(updated);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const addComment = async () => {
    const body = comment.trim();
    if (!body) return;
    setBusy(true);
    setError(null);
    try {
      await api.addComment(alert.id, body);
      const refreshed = await api.getAlert(alert.id);
      setComment("");
      onUpdated(refreshed);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const audit = alert.audit || [];

  return (
    <div className={`list-item alert-card ${compact ? "compact" : ""}`}>
      <div className="alert-card-head">
        <strong className="alert-card-title">{alert.title}</strong>
        <span className={`badge ${alert.severity}`}>{alert.severity}</span>
        <span className={`badge status-${alert.status}`}>{alert.status}</span>
      </div>
      <div className="mono muted alert-card-meta">
        {new Date(alert.created_at).toLocaleString()} · {alert.rule_name}
      </div>
      <p className="muted alert-card-desc">{alert.description}</p>
      {alert.threat_brief && (
        <div className="threat-brief">
          <strong>Threat brief</strong>
          <p>{alert.threat_brief}</p>
        </div>
      )}
      <IocList iocs={iocs} />
      {matchedComment && (
        <div className="threat-brief matched-comment">
          <strong>Commento corrispondente</strong>
          <p>{matchedComment}</p>
        </div>
      )}

      <div className="alert-status-row">
        <label htmlFor={`status-${alert.id}`}>Stato</label>
        <select
          id={`status-${alert.id}`}
          value={alert.status}
          disabled={busy}
          onChange={(e) => void setStatus(e.target.value as AlertStatus)}
        >
          {ALERT_STATUS_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>
              {o.label}
            </option>
          ))}
        </select>
      </div>

      <div className="comment-thread">
        <h4 className="muted">Cronologia</h4>
        {audit.length === 0 ? (
          <p className="muted" style={{ margin: "0.25rem 0" }}>
            Nessun cambio stato ancora
          </p>
        ) : (
          <ul className="comment-list audit-list">
            {audit.map((a) => (
              <li key={a.id}>
                <div className="comment-meta mono">
                  {a.actor} · {new Date(a.created_at).toLocaleString()}
                </div>
                <div>
                  {a.from_status || "?"} → <strong>{a.to_status}</strong>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="comment-thread">
        <h4 className="muted">Commenti</h4>
        {(alert.comments || []).length === 0 ? (
          <p className="muted" style={{ margin: "0.25rem 0" }}>
            Nessun commento
          </p>
        ) : (
          <ul className="comment-list">
            {alert.comments.map((c) => (
              <li key={c.id}>
                <div className="comment-meta mono">
                  {c.author} · {new Date(c.created_at).toLocaleString()}
                </div>
                <div>{c.body}</div>
              </li>
            ))}
          </ul>
        )}
        <div className="comment-form">
          <textarea
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            placeholder="Aggiungi un commento (note di indagine)…"
            rows={2}
            maxLength={4000}
            disabled={busy}
          />
          <button
            className="ghost"
            type="button"
            disabled={busy || !comment.trim()}
            onClick={() => void addComment()}
          >
            Aggiungi commento
          </button>
        </div>
      </div>
      {error && <p className="error">{error}</p>}
    </div>
  );
}
