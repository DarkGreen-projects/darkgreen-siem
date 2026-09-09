import { useEffect, useState } from "react";
import { api, type Alert, type Rule } from "../api";

export default function DetectionsPanel() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = async () => {
    const [r, a] = await Promise.all([api.rules(), api.alerts()]);
    setRules(r);
    setAlerts(a);
  };

  useEffect(() => {
    let alive = true;
    refresh()
      .catch((e: Error) => alive && setError(e.message));
    const id = setInterval(() => {
      refresh().catch(() => undefined);
    }, 8000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  const ack = async (id: number) => {
    await api.ackAlert(id);
    await refresh();
  };

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

  return (
    <div className="grid grid-2">
      <div className="panel">
        <div className="row" style={{ marginBottom: "0.75rem" }}>
          <h3 style={{ margin: 0, flex: 1 }}>Detection rules</h3>
          <button className="ghost" type="button" onClick={() => void runNow()} disabled={busy}>
            {busy ? "Running…" : "Run rules now"}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
        <div className="list-block">
          {rules.map((r) => (
            <div className="list-item" key={r.id}>
              <h4>
                {r.name}{" "}
                <span className={`badge ${r.severity}`}>{r.severity}</span>{" "}
                <span className="badge">{r.type}</span>
              </h4>
              <p className="muted" style={{ margin: "0.25rem 0" }}>
                {r.description}
              </p>
              <p className="mono muted" style={{ margin: 0 }}>
                id={r.id} enabled={String(r.enabled)}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Alerts</h3>
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Alert</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td className="mono">{new Date(a.created_at).toLocaleString()}</td>
                <td>
                  <strong>{a.title}</strong>
                  <div className="muted">{a.description}</div>
                  <span className={`badge ${a.severity}`}>{a.severity}</span>
                </td>
                <td>
                  <span className={`badge ${a.status}`}>{a.status}</span>
                </td>
                <td>
                  {a.status === "open" && (
                    <button className="ghost" type="button" onClick={() => void ack(a.id)}>
                      Ack
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {alerts.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  No alerts — seed data or click “Run rules now”.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
