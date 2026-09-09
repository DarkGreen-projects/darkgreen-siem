import { useMemo, useState } from "react";
import { api, type Alert, type AlertStatus } from "../api";
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
  if (iocs.length === 0) return null;
  return (
    <div className="ioc-block">
      <strong>IOC · VirusTotal</strong>
      <div className="ioc-row">
        {iocs.map((ioc) => (
          <span key={`${ioc.kind}:${ioc.value}`} className="ioc-chip">
            <span className="badge">{ioc.kind}</span>
            <code className="mono">{ioc.value}</code>
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
        ))}
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
