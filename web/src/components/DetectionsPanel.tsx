import { useEffect, useState } from "react";
import { api, type Alert, type Rule } from "../api";
import AlertCard from "./AlertCard";
import RuleEditorForm from "./RuleEditorForm";

type EditorState = { mode: "create" } | { mode: "edit"; rule: Rule } | null;

export default function DetectionsPanel() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [editor, setEditor] = useState<EditorState>(null);
  const [rowBusy, setRowBusy] = useState<string | null>(null);

  const refresh = async () => {
    const [r, a] = await Promise.all([api.rules(), api.alerts()]);
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
  }, []);

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
    if (!window.confirm(`Eliminare la regola “${rule.id}”? Rimuove il file YAML.`)) return;
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
        </div>
        <p className="muted" style={{ marginTop: 0 }}>
          Rivaluta le regole YAML sugli eventi recenti (come il loop in background). Crea nuovi
          alert quando match/threshold scattano e il cooldown lo consente.
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
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Alert</h3>
        <div className="list-block">
          {alerts.map((a) => (
            <AlertCard key={a.id} alert={a} onUpdated={onAlertUpdated} />
          ))}
          {alerts.length === 0 && (
            <p className="muted">
              Nessun alert — dati seed oppure clicca “Esegui regole ora”.
            </p>
          )}
        </div>
      </div>

      {editor && (
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
