import { useEffect, useMemo, useState } from "react";
import {
  api,
  type Alert,
  type AlertDisposition,
  type AlertStatus,
  type ConnectedAlert,
  type SimilarAlert,
  type TriageBrief,
  type VtEnrich,
} from "../api";
import { extractIocsFromAlert, type IocHit } from "../vtLinks";
import { useTriageHotkeys } from "../hooks/useTriageHotkeys";

export const ALERT_STATUS_OPTIONS: { value: AlertStatus; label: string }[] = [
  { value: "open", label: "aperto" },
  { value: "acked", label: "ack" },
  { value: "in_progress", label: "in corso" },
  { value: "closed", label: "chiuso" },
];

const DISPOSITION_OPTIONS: { value: AlertDisposition; label: string }[] = [
  { value: "true_positive", label: "True positive" },
  { value: "false_positive", label: "False positive" },
  { value: "benign", label: "Benign / expected" },
  { value: "duplicate", label: "Duplicate" },
  { value: "tuning_needed", label: "Tuning needed" },
];

type Props = {
  alert: Alert;
  onUpdated: (alert: Alert) => void;
  compact?: boolean;
  matchedComment?: string | null;
  enableHotkeys?: boolean;
  onPivotSearch?: (query: string) => void;
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
  enableHotkeys = false,
  onPivotSearch,
}: Props) {
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [closeOpen, setCloseOpen] = useState(false);
  const [disposition, setDisposition] = useState<AlertDisposition>("true_positive");
  const [closureNote, setClosureNote] = useState("");
  const [similar, setSimilar] = useState<SimilarAlert[]>([]);
  const [connected, setConnected] = useState<ConnectedAlert[]>([]);
  const [brief, setBrief] = useState<TriageBrief | null>(null);
  const [briefOpen, setBriefOpen] = useState(false);
  const [copilotMsg, setCopilotMsg] = useState<string | null>(null);

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

  useEffect(() => {
    let alive = true;
    api
      .similarAlerts(alert.id)
      .then((rows) => {
        if (alive) setSimilar(rows);
      })
      .catch(() => {
        if (alive) setSimilar([]);
      });
    return () => {
      alive = false;
    };
  }, [alert.id, alert.status, alert.disposition]);

  useEffect(() => {
    let alive = true;
    api
      .alertLinks(alert.id)
      .then((res) => {
        if (alive) setConnected(res.connected || []);
      })
      .catch(() => {
        if (alive) setConnected([]);
      });
    return () => {
      alive = false;
    };
  }, [alert.id, alert.status]);

  useEffect(() => {
    let alive = true;
    api
      .alertBrief(alert.id)
      .then((b) => {
        if (alive) {
          setBrief(b);
          if ((b.connected || []).length) setConnected(b.connected || []);
        }
      })
      .catch(() => {
        if (alive) setBrief(null);
      });
    return () => {
      alive = false;
    };
  }, [alert.id, alert.status, alert.disposition, alert.noise_hint]);

  const setStatus = async (status: AlertStatus) => {
    if (status === "closed") {
      setCloseOpen(true);
      return;
    }
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

  const pivot = () => {
    let query = brief?.pivot_query || "";
    if (!query) {
      const sample = alert.evidence?.sample as
        | { src_ip?: string; host?: string; user?: string }
        | undefined;
      if (sample?.src_ip) query = `src_ip:${sample.src_ip}`;
      else if (sample?.host) query = `host:${sample.host}`;
      else if (sample?.user) query = `user:${sample.user}`;
    }
    if (query) onPivotSearch?.(query);
  };

  const runCopilot = async () => {
    setBusy(true);
    setCopilotMsg(null);
    try {
      const res = await api.copilotSuggest(alert.id);
      if (res.available && res.suggested_disposition) {
        setDisposition(res.suggested_disposition as AlertDisposition);
        if (res.suggested_note) setClosureNote(res.suggested_note);
        const src = res.source ? `[${res.source}] ` : "";
        setCopilotMsg(`${src}${res.rationale || "Suggerimento applicato"}`);
        if (res.brief) setBrief(res.brief);
        setCloseOpen(true);
      } else {
        setCopilotMsg(res.message || "Copilot non disponibile");
        setCloseOpen(true);
      }
    } catch (e) {
      setCopilotMsg((e as Error).message);
      setCloseOpen(true);
    } finally {
      setBusy(false);
    }
  };

  useTriageHotkeys({
    enabled: enableHotkeys,
    onAck: () => void setStatus("acked"),
    onInProgress: () => void setStatus("in_progress"),
    onClose: () => setCloseOpen(true),
    onPivot: pivot,
  });

  const confirmClose = async () => {
    setBusy(true);
    setError(null);
    try {
      const updated = await api.setAlertStatus(alert.id, "closed", {
        disposition,
        closure_note: closureNote.trim(),
      });
      setCloseOpen(false);
      setClosureNote("");
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
  const fpSimilar = similar.filter(
    (s) => s.disposition === "false_positive" || s.disposition === "benign"
  ).length;

  return (
    <div className={`list-item alert-card ${compact ? "compact" : ""}`}>
      <div className="alert-card-head">
        <strong className="alert-card-title">{alert.title}</strong>
        <span className={`badge ${alert.severity}`}>{alert.severity}</span>
        <span className={`badge status-${alert.status}`}>{alert.status}</span>
        {alert.mitre && <span className="badge mitre">{alert.mitre}</span>}
        {alert.noise_hint && (
          <span className={`badge noise-${alert.noise_hint}`} title="Stima rumore/minaccia">
            {alert.noise_hint.replace("_", " ")}
            {alert.risk_score != null ? ` · ${alert.risk_score}` : ""}
          </span>
        )}
        {alert.disposition && (
          <span className={`badge disposition-${alert.disposition}`}>{alert.disposition}</span>
        )}
        {alert.sla_ack_status && alert.sla_ack_status !== "na" && (
          <span className={`badge sla-${alert.sla_ack_status}`} title="SLA ack">
            ack {alert.sla_ack_status}
            {alert.sla_ack_status === "ok" || alert.sla_ack_status === "at_risk"
              ? alert.sla_ack_remaining_minutes != null
                ? ` ${alert.sla_ack_remaining_minutes}m`
                : ""
              : ""}
          </span>
        )}
        {alert.sla_close_status && alert.sla_close_status !== "na" && (
          <span className={`badge sla-${alert.sla_close_status}`} title="SLA close">
            close {alert.sla_close_status}
            {alert.sla_close_status === "ok" || alert.sla_close_status === "at_risk"
              ? alert.sla_close_remaining_minutes != null
                ? ` ${alert.sla_close_remaining_minutes}m`
                : ""
              : ""}
          </span>
        )}
        {typeof alert.evidence?.occurrences === "number" &&
          (alert.evidence.occurrences as number) > 1 && (
            <span className="badge">×{String(alert.evidence.occurrences)}</span>
          )}
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
      {brief && (
        <div className="threat-brief">
          <button
            type="button"
            className="ghost brief-toggle"
            onClick={() => setBriefOpen((v) => !v)}
          >
            Briefing {briefOpen ? "▾" : "▸"}
          </button>
          {briefOpen && (
            <>
              <pre className="brief-pre">{brief.summary}</pre>
              {(brief.cases || []).length > 0 && (
                <ul className="comment-list" style={{ marginTop: "0.35rem" }}>
                  {(brief.cases || []).slice(0, 5).map((c) => (
                    <li key={c.alert_id}>
                      <span className="mono muted">#{c.alert_id}</span>{" "}
                      {c.disposition && (
                        <span className={`badge disposition-${c.disposition}`}>
                          {c.disposition}
                        </span>
                      )}{" "}
                      <span className="muted">{c.note_excerpt || c.title}</span>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
        </div>
      )}
      {alert.status === "closed" && alert.disposition && (
        <div className="threat-brief triage-outcome">
          <strong>Esito triage</strong>
          <p>
            <span className={`badge disposition-${alert.disposition}`}>{alert.disposition}</span>
            {alert.closed_by ? ` · ${alert.closed_by}` : ""}
            {alert.closed_at ? ` · ${new Date(alert.closed_at).toLocaleString()}` : ""}
          </p>
          {alert.closure_note && <p>{alert.closure_note}</p>}
        </div>
      )}
      <IocList iocs={iocs} />
      {connected.length > 0 && (
        <div className="threat-brief similar-block">
          <strong>Alert collegati</strong>
          <ul className="comment-list" style={{ marginTop: "0.35rem" }}>
            {connected.slice(0, 8).map((c) => (
              <li key={`${c.id}-${c.relation}`}>
                <span className="mono muted">#{c.id}</span> {c.title || ""}{" "}
                <span className="badge">{c.relation}</span>{" "}
                <span className="mono muted">{c.score ?? 0}</span>
                {c.direction ? (
                  <span className="muted"> · {c.direction}</span>
                ) : null}
                {c.disposition && (
                  <>
                    {" "}
                    <span className={`badge disposition-${c.disposition}`}>{c.disposition}</span>
                  </>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
      {similar.length > 0 && (
        <div className="threat-brief similar-block">
          <strong>
            Alert simili
            {fpSimilar > 0 ? ` (${fpSimilar} FP/benign recenti)` : ""}
          </strong>
          <ul className="comment-list" style={{ marginTop: "0.35rem" }}>
            {similar.slice(0, 5).map((s) => (
              <li key={s.id}>
                <span className="mono muted">#{s.id}</span> {s.title}{" "}
                <span className={`badge status-${s.status}`}>{s.status}</span>{" "}
                {s.disposition && (
                  <span className={`badge disposition-${s.disposition}`}>{s.disposition}</span>
                )}
              </li>
            ))}
          </ul>
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

      {closeOpen && (
        <div className="close-dialog">
          <h4 style={{ marginTop: 0 }}>Chiudi alert</h4>
          <p className="muted" style={{ fontSize: "0.85rem" }}>
            Serve disposition e nota di chiusura (min 10 caratteri).
          </p>
          {copilotMsg && (
            <p className="muted" style={{ fontSize: "0.85rem" }}>
              {copilotMsg}
            </p>
          )}
          <label>
            Disposition
            <select
              value={disposition}
              onChange={(e) => setDisposition(e.target.value as AlertDisposition)}
              disabled={busy}
            >
              {DISPOSITION_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Nota di chiusura
            <textarea
              rows={3}
              value={closureNote}
              onChange={(e) => setClosureNote(e.target.value)}
              placeholder="Cosa hai verificato e perché questa classificazione…"
              disabled={busy}
              maxLength={4000}
            />
          </label>
          <div className="row" style={{ gap: "0.5rem", marginTop: "0.5rem", flexWrap: "wrap" }}>
            <button type="button" className="ghost" disabled={busy} onClick={() => void runCopilot()}>
              Suggerisci chiusura
            </button>
            <button type="button" disabled={busy} onClick={() => void confirmClose()}>
              Conferma chiusura
            </button>
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => setCloseOpen(false)}
            >
              Annulla
            </button>
          </div>
        </div>
      )}

      <div className="comment-thread">
        <h4 className="muted">Cronologia triage</h4>
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
                  {a.note ? <span className="muted"> · {a.note}</span> : null}
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
