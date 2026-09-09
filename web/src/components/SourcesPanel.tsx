import { useEffect, useState } from "react";
import { api, type Source } from "../api";
import { AGENT_PLATFORMS, DEMO_ONBOARDING_DEVICES } from "../onboardingDemo";

const CHANNEL_HELP: Record<string, string> = {
  seed: "File sample caricati all’avvio API",
  http: "REST /api/ingest (tool UI + log-generator)",
  syslog: "Collector syslog UDP sulla porta 5140",
};

function statusBadgeClass(status: string): string {
  if (status === "enrolled") return "health-ok";
  if (status === "pending") return "health-stale";
  return "health-silent";
}

const STATUS_LABEL: Record<string, string> = {
  enrolled: "enrolled",
  pending: "pending",
  never: "never",
};

export default function SourcesPanel() {
  const [sources, setSources] = useState<Source[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showStatus, setShowStatus] = useState(false);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .sources()
        .then((s) => alive && setSources(s))
        .catch((e: Error) => alive && setError(e.message));
    load();
    const id = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  return (
    <div className="sources-stack">
      <div className="panel">
        <div className="row" style={{ marginBottom: "0.5rem", alignItems: "center" }}>
          <h3 style={{ margin: 0, flex: 1 }}>Canali di ingest</h3>
          <button
            type="button"
            className="btn-demo-locked"
            disabled
            title="Non incluso in questa demo"
            aria-disabled="true"
          >
            <span className="demo-locked-label">Aggiungi sorgente</span>
            <span className="badge demo-only">Solo demo</span>
          </button>
        </div>
        <p className="muted">
          DarkGreen SIEM accetta syslog firewall, eventi Windows, JSON cloud auth ed export
          SIEM/EDR — normalizzati in uno schema ECS-lite unico.
        </p>
        {error && <p className="error">{error}</p>}
        <table>
          <thead>
            <tr>
              <th>Canale</th>
              <th>Eventi</th>
              <th>Ultimo evento</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => (
              <tr key={s.channel}>
                <td className="mono">{s.channel}</td>
                <td>{s.count}</td>
                <td className="mono">
                  {s.last_event_at ? new Date(s.last_event_at).toLocaleString() : "—"}
                </td>
                <td className="muted">{CHANNEL_HELP[s.channel] || "Custom / altro"}</td>
              </tr>
            ))}
            {sources.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  Nessuna attività di ingest — avvia Compose e attendi seed/log-generator.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Onboarding agent</h3>
        <p className="muted">
          Distribuisci collector leggeri che inviano telemetria host a DarkGreen SIEM. Pacchetti
          agent ed enrollment live non sono inclusi in questa demo di portfolio — l’UI mostra il
          flusso previsto.
        </p>

        <h4 className="sources-subhead">Come fare onboarding</h4>
        <ol className="onboarding-guide">
          <li>
            Scarica l’agent DarkGreen per la piattaforma target (Windows, macOS, Linux, Android o
            iOS).
          </li>
          <li>
            Installa l’agent e punta all’URL API del SIEM (demo:{" "}
            <code className="mono">http://localhost:8000</code>) con il token di enrollment del
            tenant.
          </li>
          <li>
            Verifica che l’agent raggiunga l’endpoint di ingest e che l’outbound HTTPS/HTTP sia
            consentito.
          </li>
          <li>
            Usa <strong>Verifica stato onboarding</strong> qui sotto per controllare che il device
            risulti <span className="badge health-ok">enrolled</span> dopo il primo heartbeat.
          </li>
        </ol>

        <h4 className="sources-subhead">Download agent</h4>
        <div className="agent-download-grid">
          {AGENT_PLATFORMS.map((platform) => (
            <button
              key={platform}
              type="button"
              className="btn-demo-locked agent-download-card"
              disabled
              title="Download agent non incluso in questa demo"
              aria-disabled="true"
            >
              <span className="demo-locked-label">Download {platform}</span>
              <span className="badge demo-only">Solo demo</span>
            </button>
          ))}
        </div>

        <div className="row" style={{ marginTop: "1rem", alignItems: "center", gap: "0.5rem" }}>
          <button type="button" className="ghost" onClick={() => setShowStatus((v) => !v)}>
            {showStatus ? "Nascondi stato onboarding" : "Verifica stato onboarding"}
          </button>
          <span className="muted" style={{ fontSize: "0.85rem" }}>
            Vista enrollment di esempio (dati seed)
          </span>
        </div>

        {showStatus && (
          <div className="onboarding-status" style={{ marginTop: "0.75rem" }}>
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Piattaforma</th>
                  <th>Ultimo visto</th>
                  <th>Stato</th>
                </tr>
              </thead>
              <tbody>
                {DEMO_ONBOARDING_DEVICES.map((d) => (
                  <tr key={d.id}>
                    <td className="mono">{d.name}</td>
                    <td>{d.platform}</td>
                    <td className="mono">
                      {d.last_seen ? new Date(d.last_seen).toLocaleString() : "—"}
                    </td>
                    <td>
                      <span className={`badge ${statusBadgeClass(d.status)}`}>
                        {STATUS_LABEL[d.status] || d.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
