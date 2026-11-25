import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  type Alert,
  type AlertDisposition,
  type TriageBrief,
} from "../api";
import AlertCard from "./AlertCard";
import { TRIAGE_HOTKEY_HELP, useTriageHotkeys } from "../hooks/useTriageHotkeys";
import { useVisibleInterval } from "../hooks/useVisibleInterval";

const CHECK_KEYS = [
  { id: "ioc", label: "IOC check" },
  { id: "similar", label: "Simili visti" },
  { id: "note", label: "Nota pronta" },
  { id: "disp", label: "Disposition scelta" },
] as const;

function loadChecks(alertId: number): Record<string, boolean> {
  try {
    const raw = sessionStorage.getItem(`dg-triage-check-${alertId}`);
    return raw ? (JSON.parse(raw) as Record<string, boolean>) : {};
  } catch {
    return {};
  }
}

function saveChecks(alertId: number, checks: Record<string, boolean>) {
  sessionStorage.setItem(`dg-triage-check-${alertId}`, JSON.stringify(checks));
}

type Props = {
  onPivotSearch?: (query: string) => void;
};

export default function WorkbenchPanel({ onPivotSearch }: Props) {
  const [queue, setQueue] = useState<Alert[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [brief, setBrief] = useState<TriageBrief | null>(null);
  const [helpOpen, setHelpOpen] = useState(false);
  const [closeOpen, setCloseOpen] = useState(false);
  const [disposition, setDisposition] = useState<AlertDisposition>("true_positive");
  const [closureNote, setClosureNote] = useState("");
  const [checks, setChecks] = useState<Record<string, boolean>>({});
  const [copilotMsg, setCopilotMsg] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const q = await api.alertQueue(50);
    setQueue(q);
    setSelectedId((prev) => {
      if (prev && q.some((a) => a.id === prev)) return prev;
      return q[0]?.id ?? null;
    });
  }, []);

  useEffect(() => {
    let alive = true;
    refresh()
      .catch((e: Error) => alive && setError(e.message))
      .finally(() => undefined);
    return () => {
      alive = false;
    };
  }, [refresh]);

  useVisibleInterval(
    () => {
      refresh().catch(() => undefined);
    },
    12000,
    { deps: [refresh] }
  );

  const selected = useMemo(
    () => queue.find((a) => a.id === selectedId) || null,
    [queue, selectedId]
  );

  useEffect(() => {
    if (!selected) {
      setBrief(null);
      return;
    }
    setChecks(loadChecks(selected.id));
    let alive = true;
    api
      .alertBrief(selected.id)
      .then((b) => alive && setBrief(b))
      .catch(() => alive && setBrief(null));
    return () => {
      alive = false;
    };
  }, [selected?.id]);

  const idx = selected ? queue.findIndex((a) => a.id === selected.id) : -1;

  const goNext = useCallback(() => {
    if (queue.length === 0) return;
    const next = queue[Math.min(queue.length - 1, Math.max(0, idx + 1))];
    if (next) setSelectedId(next.id);
  }, [queue, idx]);

  const goPrev = useCallback(() => {
    if (queue.length === 0) return;
    const prev = queue[Math.max(0, idx - 1)];
    if (prev) setSelectedId(prev.id);
  }, [queue, idx]);

  const setStatus = useCallback(
    async (status: string, opts?: { disposition?: AlertDisposition; closure_note?: string }) => {
      if (!selected) return;
      setBusy(true);
      setError(null);
      try {
        await api.setAlertStatus(selected.id, status, opts);
        setCloseOpen(false);
        await refresh();
      } catch (e) {
        setError((e as Error).message);
      } finally {
        setBusy(false);
      }
    },
    [selected, refresh]
  );

  const pivot = useCallback(() => {
    const q =
      brief?.pivot_query ||
      (selected?.evidence?.sample as { src_ip?: string; host?: string; user?: string } | undefined);
    let query = typeof brief?.pivot_query === "string" ? brief.pivot_query : "";
    if (!query && q && typeof q === "object") {
      if (q.src_ip) query = `src_ip:${q.src_ip}`;
      else if (q.host) query = `host:${q.host}`;
      else if (q.user) query = `user:${q.user}`;
    }
    if (query) onPivotSearch?.(query);
  }, [brief, selected, onPivotSearch]);

  const confirmClose = async () => {
    await setStatus("closed", { disposition, closure_note: closureNote.trim() });
    setClosureNote("");
  };

  const runCopilot = async () => {
    if (!selected) return;
    setBusy(true);
    setCopilotMsg(null);
    try {
      const res = await api.copilotSuggest(selected.id);
      if (res.available && res.suggested_disposition) {
        setDisposition(res.suggested_disposition as AlertDisposition);
        if (res.suggested_note) setClosureNote(res.suggested_note);
        const src = res.source ? `[${res.source}] ` : "";
        setCopilotMsg(`${src}${res.rationale || "Suggerimento applicato"}`);
        if (res.brief?.cases) setBrief(res.brief);
        setCloseOpen(true);
      } else {
        setCopilotMsg(res.message || "Copilot non disponibile");
      }
    } catch (e) {
      setCopilotMsg((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  useTriageHotkeys({
    enabled: true,
    onNext: goNext,
    onPrev: goPrev,
    onAck: () => void setStatus("acked"),
    onInProgress: () => void setStatus("in_progress"),
    onClose: () => setCloseOpen(true),
    onPivot: pivot,
    onHelp: () => setHelpOpen((v) => !v),
  });

  const toggleCheck = (id: string) => {
    if (!selected) return;
    const next = { ...checks, [id]: !checks[id] };
    setChecks(next);
    saveChecks(selected.id, next);
  };

  return (
    <div className="workbench">
      <div className="workbench-queue panel">
        <div className="row" style={{ alignItems: "center", marginBottom: "0.5rem" }}>
          <h3 style={{ margin: 0, flex: 1 }}>Coda turno</h3>
          <button type="button" className="ghost" onClick={() => setHelpOpen((v) => !v)}>
            ?
          </button>
        </div>
        <p className="muted" style={{ fontSize: "0.8rem", marginTop: 0 }}>
          Priorità: SLA → signal → severity. Hotkeys j/k a i c /
        </p>
        {error && <p className="error">{error}</p>}
        <ul className="workbench-list">
          {queue.map((a) => (
            <li key={a.id}>
              <button
                type="button"
                className={`workbench-item${a.id === selectedId ? " active" : ""}`}
                onClick={() => setSelectedId(a.id)}
              >
                <span className={`badge ${a.severity}`}>{a.severity}</span>
                {a.noise_hint && (
                  <span className={`badge noise-${a.noise_hint}`}>
                    {a.noise_hint.replace("_", " ")}
                  </span>
                )}
                {a.sla_ack_status === "breached" || a.sla_close_status === "breached" ? (
                  <span className="badge sla-breached">SLA</span>
                ) : null}
                <strong className="workbench-item-title">{a.title}</strong>
                <span className="mono muted">#{a.id}</span>
              </button>
            </li>
          ))}
          {queue.length === 0 && (
            <li className="muted" style={{ padding: "0.5rem" }}>
              Nessun alert open / in corso
            </li>
          )}
        </ul>
      </div>

      <div className="workbench-detail">
        {helpOpen && (
          <div className="panel close-dialog" style={{ marginBottom: "0.75rem" }}>
            <strong>Scorciatoie</strong>
            <ul className="comment-list">
              {TRIAGE_HOTKEY_HELP.map((h) => (
                <li key={h.key}>
                  <span className="mono">{h.key}</span> - {h.desc}
                </li>
              ))}
            </ul>
          </div>
        )}

        {!selected && <p className="muted">Seleziona un alert dalla coda.</p>}

        {selected && (
          <>
            <div className="panel" style={{ marginBottom: "0.75rem" }}>
              <div className="row" style={{ gap: "0.35rem", flexWrap: "wrap" }}>
                <button type="button" className="ghost" disabled={busy} onClick={() => void setStatus("acked")}>
                  Ack (a)
                </button>
                <button
                  type="button"
                  className="ghost"
                  disabled={busy}
                  onClick={() => void setStatus("in_progress")}
                >
                  In corso (i)
                </button>
                <button type="button" className="ghost" disabled={busy} onClick={() => setCloseOpen(true)}>
                  Chiudi (c)
                </button>
                <button type="button" className="ghost" disabled={busy} onClick={pivot}>
                  Pivot (/)
                </button>
                <button type="button" className="ghost" disabled={busy} onClick={() => void runCopilot()}>
                  Suggerisci chiusura
                </button>
              </div>
              {copilotMsg && <p className="muted" style={{ marginBottom: 0 }}>{copilotMsg}</p>}

              {closeOpen && (
                <div className="close-dialog" style={{ marginTop: "0.75rem" }}>
                  <h4 style={{ marginTop: 0 }}>Chiudi alert</h4>
                  <label>
                    Disposition
                    <select
                      value={disposition}
                      onChange={(e) => setDisposition(e.target.value as AlertDisposition)}
                      disabled={busy}
                    >
                      <option value="true_positive">True positive</option>
                      <option value="false_positive">False positive</option>
                      <option value="benign">Benign</option>
                      <option value="duplicate">Duplicate</option>
                      <option value="tuning_needed">Tuning needed</option>
                    </select>
                  </label>
                  <label>
                    Nota
                    <textarea
                      rows={3}
                      value={closureNote}
                      onChange={(e) => setClosureNote(e.target.value)}
                      disabled={busy}
                    />
                  </label>
                  <div className="row" style={{ gap: "0.5rem", marginTop: "0.5rem" }}>
                    <button type="button" disabled={busy} onClick={() => void confirmClose()}>
                      Conferma
                    </button>
                    <button type="button" className="ghost" onClick={() => setCloseOpen(false)}>
                      Annulla
                    </button>
                  </div>
                </div>
              )}

              {brief && (
                <div className="threat-brief" style={{ marginTop: "0.75rem" }}>
                  <strong>Briefing</strong>
                  <pre className="brief-pre">{brief.summary}</pre>
                  {(brief.connected || []).length > 0 && (
                    <div style={{ marginTop: "0.5rem" }}>
                      <strong className="muted">Alert collegati</strong>
                      <ul className="comment-list" style={{ marginTop: "0.35rem" }}>
                        {(brief.connected || []).slice(0, 8).map((c) => (
                          <li key={`${c.id}-${c.relation}`}>
                            <span className="mono muted">#{c.id}</span> {c.title || ""}{" "}
                            <span className="badge">{c.relation}</span>{" "}
                            <span className="mono muted">{c.score ?? 0}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {(brief.cases || []).length > 0 && (
                    <div style={{ marginTop: "0.5rem" }}>
                      <strong className="muted">Casi memoria</strong>
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
                    </div>
                  )}
                </div>
              )}

              <div style={{ marginTop: "0.75rem" }}>
                <strong className="muted">Checklist turno</strong>
                <div className="chip-multi" style={{ marginTop: "0.35rem" }}>
                  {CHECK_KEYS.map((c) => (
                    <button
                      key={c.id}
                      type="button"
                      className={`chip-option${checks[c.id] ? " selected" : ""}`}
                      onClick={() => toggleCheck(c.id)}
                    >
                      {c.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            <AlertCard
              alert={selected}
              onUpdated={(u) => {
                setQueue((prev) => prev.map((x) => (x.id === u.id ? u : x)));
                if (u.status === "closed") void refresh();
              }}
              enableHotkeys={false}
            />
          </>
        )}
      </div>
    </div>
  );
}
