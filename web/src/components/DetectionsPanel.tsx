import { useEffect, useState } from "react";
import { api, type Alert, type DryRunHit, type Rule } from "../api";
import AlertCard from "./AlertCard";
import RuleEditorForm from "./RuleEditorForm";

type EditorState = { mode: "create" } | { mode: "edit"; rule: Rule } | null;

const DRY_RUN_PLACEHOLDER = `[
  {
    "Product": "Cynet",
    "Activity": "Malware Detected",
    "Severity": "high",
    "Hostname": "win-ws42.lab.local",
    "category": "malware",
    "Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "ProcessName": "invoice.exe"
  }
]`;

function parseDryRunInput(text: string): unknown[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  if (trimmed.startsWith("[")) {
    const parsed = JSON.parse(trimmed) as unknown;
    if (!Array.isArray(parsed)) throw new Error("JSON deve essere un array di eventi");
    return parsed;
  }
  if (trimmed.startsWith("{")) {
    return [JSON.parse(trimmed)];
  }
  return trimmed
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

export default function DetectionsPanel({ readOnly = false }: { readOnly?: boolean }) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [editor, setEditor] = useState<EditorState>(null);
  const [rowBusy, setRowBusy] = useState<string | null>(null);
  const [mitreFilter, setMitreFilter] = useState("");
  const [slaFilter, setSlaFilter] = useState("");
  const [dryRunText, setDryRunText] = useState(DRY_RUN_PLACEHOLDER);
  const [dryHits, setDryHits] = useState<DryRunHit[] | null>(null);
  const [dryNorm, setDryNorm] = useState(0);
  const [dryBusy, setDryBusy] = useState(false);

  const refresh = async () => {
    const opts: { mitre?: string; sla?: string } = {};
    if (mitreFilter.trim()) opts.mitre = mitreFilter.trim();
    if (slaFilter.trim()) opts.sla = slaFilter.trim();
    const [r, a] = await Promise.all([
      api.rules(),
      api.alerts(Object.keys(opts).length ? opts : undefined),
    ]);
    setRules(r);
    setAlerts(a);
  };

  useEffect(() => {
    let alive = true;
    refresh().catch((e: Error) => alive && setError(e.message));
    const id = setInterval(() => {
      refresh().catch(() => undefined);
    }, 8000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [mitreFilter, slaFilter]);

  const runNow = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.runRules();
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const runDryRun = async () => {
    setDryBusy(true);
    setError(null);
    setDryHits(null);
    try {
      const events = parseDryRunInput(dryRunText);
      if (!events.length) throw new Error("Inserisci almeno un evento");
      const res = await api.dryRunRules(events);
      setDryHits(res.matched);
      setDryNorm(res.events_normalized);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDryBusy(false);
    }
  };

  const onAlertUpdated = (updated: Alert) => {
    setAlerts((prev) => prev.map((a) => (a.id === updated.id ? updated : a)));
  };

  const closeEditor = () => setEditor(null);

  const toggleEnabled = async (rule: Rule) => {
    setRowBusy(rule.id);
    setError(null);
    try {
      await api.setRuleEnabled(rule.id, !rule.enabled);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRowBusy(null);
    }
  };

  const deleteRule = async (rule: Rule) => {
    if (!window.confirm(`Eliminare la regola "${rule.id}"? Rimuove il file YAML.`)) return;
    setRowBusy(rule.id);
    setError(null);
    try {
      await api.deleteRule(rule.id);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRowBusy(null);
    }
  };

  return (
    <div className="grid grid-2">
      <div className="panel">
        <div className="row" style={{ marginBottom: "0.75rem", alignItems: "center" }}>
          <h3 style={{ margin: 0, flex: 1 }}>Regole di detection</h3>
          {!readOnly && (
            <>
              <button
                className="ghost"
                type="button"
                onClick={() => setEditor({ mode: "create" })}
                disabled={busy}
              >
                Crea regola
              </button>
              <button className="ghost" type="button" onClick={() => void runNow()} disabled={busy}>
                {busy ? "Esecuzione…" : "Esegui regole ora"}
              </button>
            </>
          )}
        </div>
        <p className="muted" style={{ marginTop: 0 }}>
          Rivaluta le regole YAML sugli eventi recenti (come il loop in background). Stessa
          rule+entity nella finestra di cooldown vengono merge (count/occurrences), non nuovi alert.
        </p>
        {error && <p className="error">{error}</p>}

        <div className="list-block">
          {rules.map((r) => (
            <div className="list-item" key={r.id}>
              <div className="row" style={{ alignItems: "flex-start", gap: "0.5rem" }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <h4 style={{ marginTop: 0 }}>
                    {r.name}{" "}
                    <span className={`badge ${r.severity}`}>{r.severity}</span>{" "}
                    <span className="badge">{r.type}</span>{" "}
                    {r.mitre && <span className="badge mitre">{r.mitre}</span>}{" "}
                    <span className={`badge ${r.enabled ? "health-ok" : "health-silent"}`}>
                      {r.enabled ? "abilitata" : "disabilitata"}
                    </span>
                  </h4>
                  <p className="muted" style={{ margin: "0.25rem 0" }}>
                    {r.description}
                  </p>
                  {r.threat_brief && (
                    <div className="threat-brief">
                      <strong>Threat brief</strong>
                      <p>{r.threat_brief}</p>
                    </div>
                  )}
                  <p className="mono muted" style={{ margin: 0 }}>
                    id={r.id}
                  </p>
                </div>
                {!readOnly && (
                  <div className="rule-row-actions">
                    <button
                      className="ghost"
                      type="button"
                      disabled={rowBusy === r.id}
                      onClick={() => void toggleEnabled(r)}
                    >
                      {r.enabled ? "Disabilita" : "Abilita"}
                    </button>
                    <button
                      className="ghost"
                      type="button"
                      disabled={rowBusy === r.id}
                      onClick={() => setEditor({ mode: "edit", rule: r })}
                    >
                      Modifica
                    </button>
                    <button
                      className="ghost danger"
                      type="button"
                      disabled={rowBusy === r.id}
                      onClick={() => void deleteRule(r)}
                    >
                      Elimina
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {!readOnly && (
          <div className="dry-run-block" style={{ marginTop: "1.25rem" }}>
            <h4 style={{ marginTop: 0 }}>Dry-run</h4>
            <p className="muted" style={{ fontSize: "0.85rem" }}>
              Incolla un JSON array, un singolo oggetto, o linee syslog. Nessun alert scritto sul DB.
            </p>
            <textarea
              rows={8}
              className="mono"
              value={dryRunText}
              onChange={(e) => setDryRunText(e.target.value)}
              style={{ width: "100%", fontSize: "0.8rem" }}
            />
            <button
              type="button"
              className="ghost"
              style={{ marginTop: "0.5rem" }}
              disabled={dryBusy}
              onClick={() => void runDryRun()}
            >
              {dryBusy ? "Valutazione…" : "Valuta regole"}
            </button>
            {dryHits && (
              <div style={{ marginTop: "0.75rem" }}>
                <p className="muted mono" style={{ margin: "0 0 0.5rem" }}>
                  eventi normalizzati: {dryNorm} · match: {dryHits.length}
                </p>
                {dryHits.length === 0 && <p className="muted">Nessuna regola ha matchato.</p>}
                {dryHits.map((h) => (
                  <div className="list-item" key={`${h.rule_id}-${h.title}`}>
                    <strong>{h.title || h.rule_name}</strong>{" "}
                    <span className={`badge ${h.severity}`}>{h.severity}</span>{" "}
                    {h.mitre && <span className="badge mitre">{h.mitre}</span>}
                    <p className="mono muted" style={{ margin: "0.25rem 0 0" }}>
                      {h.rule_id}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="panel">
        <div className="row" style={{ alignItems: "center", marginBottom: "0.75rem" }}>
          <h3 style={{ margin: 0, flex: 1 }}>Alert</h3>
          <label className="muted" style={{ fontSize: "0.85rem" }}>
            MITRE{" "}
            <input
              value={mitreFilter}
              onChange={(e) => setMitreFilter(e.target.value)}
              placeholder="T1059"
              style={{ width: "7rem", marginLeft: "0.25rem" }}
            />
          </label>
          <label className="muted" style={{ fontSize: "0.85rem", marginLeft: "0.5rem" }}>
            SLA{" "}
            <select
              value={slaFilter}
              onChange={(e) => setSlaFilter(e.target.value)}
              style={{ marginLeft: "0.25rem" }}
            >
              <option value="">tutti</option>
              <option value="breached">breached</option>
              <option value="at_risk">at_risk</option>
              <option value="ok">ok</option>
              <option value="met">met</option>
            </select>
          </label>
        </div>
        <div className="list-block">
          {alerts.map((a) => (
            <AlertCard key={a.id} alert={a} onUpdated={onAlertUpdated} />
          ))}
          {alerts.length === 0 && (
            <p className="muted">
              Nessun alert - dati seed oppure clicca "Esegui regole ora".
            </p>
          )}
        </div>
      </div>

      {!readOnly && editor && (
        <div
          className="modal-backdrop"
          role="presentation"
          onClick={(e) => {
            if (e.target === e.currentTarget) closeEditor();
          }}
        >
          <div className="modal-panel" role="dialog" aria-modal="true">
            <div className="modal-header">
              <span className="muted mono">
                {editor.mode === "edit" ? editor.rule.id : "nuova regola"}
              </span>
              <button className="ghost" type="button" aria-label="Chiudi" onClick={closeEditor}>
                ×
              </button>
            </div>
            <RuleEditorForm
              mode={editor.mode}
              initial={editor.mode === "edit" ? editor.rule : undefined}
              onCancel={closeEditor}
              onSaved={() => {
                closeEditor();
                void refresh();
              }}
            />
          </div>
        </div>
      )}
    </div>
  );
}
