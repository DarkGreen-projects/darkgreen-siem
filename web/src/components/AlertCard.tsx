import { useState } from "react";
import { api, type Alert, type AlertStatus } from "../api";

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

export default function AlertCard({
  alert,
  onUpdated,
  compact = false,
  matchedComment,
}: Props) {
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
      <div className="row" style={{ marginBottom: "0.35rem", alignItems: "center" }}>
        <strong style={{ flex: 1 }}>{alert.title}</strong>
        <span className={`badge ${alert.severity}`}>{alert.severity}</span>
        <span className={`badge status-${alert.status}`}>{alert.status}</span>
      </div>
      <div className="mono muted" style={{ fontSize: "0.8rem" }}>
        {new Date(alert.created_at).toLocaleString()} · {alert.rule_name}
      </div>
      <p className="muted" style={{ margin: "0.35rem 0" }}>
        {alert.description}
      </p>
      {alert.threat_brief && (
        <div className="threat-brief">
          <strong>Threat brief</strong>
          <p>{alert.threat_brief}</p>
        </div>
      )}
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
