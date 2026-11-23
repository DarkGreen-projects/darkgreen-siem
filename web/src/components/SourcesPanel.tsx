import { useEffect, useState } from "react";
import { api, type Source } from "../api";

const CHANNEL_HELP: Record<string, string> = {
  seed: "File sample caricati all'avvio API",
  http: "REST /api/ingest (tool UI + log-generator)",
  syslog: "Collector syslog UDP sulla porta 5140",
  "connect-wizard": "Heartbeat del wizard di connessione",
  "windows-agent": "Agent Windows (Security Event Log)",
  agent: "Agent generico",
};

function channelStatus(s: Source | undefined): "enrolled" | "stale" | "never" {
  if (!s || !s.last_event_at) return "never";
  const ageMs = Date.now() - new Date(s.last_event_at).getTime();
  if (ageMs < 15 * 60 * 1000) return "enrolled";
  return "stale";
}

function statusBadgeClass(status: string): string {
  if (status === "enrolled") return "health-ok";
  if (status === "stale") return "health-stale";
  return "health-silent";
}

async function downloadTool(path: string, filename: string) {
  const { getStoredToken } = await import("../api");
  const token = getStoredToken();
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(path, { headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  const blob = await res.blob();
  const a = document.createElement("a");
  const href = URL.createObjectURL(blob);
  a.href = href;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(href);
}

export default function SourcesPanel() {
  const [sources, setSources] = useState<Source[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [dlBusy, setDlBusy] = useState<string | null>(null);

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

  const byChannel = Object.fromEntries(sources.map((s) => [s.channel, s]));
  const wizard = byChannel["connect-wizard"];
  const agent = byChannel["windows-agent"];

  const onDownload = async (kind: "wizard" | "agent") => {
    setDlBusy(kind);
    setError(null);
    try {
      if (kind === "wizard") {
        await downloadTool("/api/tools/connect-wizard.zip", "darkgreen-connect-wizard.zip");
      } else {
        await downloadTool("/api/tools/windows-agent.zip", "darkgreen-windows-agent.zip");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setDlBusy(null);
    }
  };

  return (
    <div className="sources-stack">
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Canali di ingest</h3>
        <p className="muted">
          DarkGreen SIEM accetta syslog firewall, eventi Windows, JSON cloud auth ed export
          SIEM/EDR - normalizzati in uno schema ECS-lite unico.
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
                  {s.last_event_at ? new Date(s.last_event_at).toLocaleString() : "-"}
                </td>
                <td className="muted">{CHANNEL_HELP[s.channel] || "Custom / altro"}</td>
              </tr>
            ))}
            {sources.length === 0 && (
              <tr>
                <td colSpan={4} className="muted">
                  Nessuna attivita di ingest - avvia Compose e attendi seed/log-generator.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Connector host</h3>
        <p className="muted">
          Wizard passo-passo per collegare un host al SIEM, poi agent Windows leggero per eventi
          Security. Download reali dal repo <span className="mono">tools/</span>.
        </p>

        <h4 className="sources-subhead">1. Connect wizard</h4>
        <ol className="onboarding-guide">
          <li>Scarica lo zip e apri <span className="mono">Connect-DarkGreen.ps1</span> (o lo script bash).</li>
          <li>Inserisci URL API e token ingest.</li>
          <li>Il wizard testa <span className="mono">/health</span>, invia un heartbeat e genera snippet NXLog/rsyslog.</li>
          <li>
            Stato heartbeat:{" "}
            <span className={`badge ${statusBadgeClass(channelStatus(wizard))}`}>
              {channelStatus(wizard)}
            </span>
            {wizard?.last_event_at
              ? ` · ultimo ${new Date(wizard.last_event_at).toLocaleString()}`
              : " · nessun heartbeat ancora"}
          </li>
        </ol>
        <button
          type="button"
          disabled={dlBusy === "wizard"}
          onClick={() => void onDownload("wizard")}
        >
          {dlBusy === "wizard" ? "Download…" : "Scarica connect-wizard.zip"}
        </button>

        <h4 className="sources-subhead" style={{ marginTop: "1.25rem" }}>
          2. Windows agent
        </h4>
        <ol className="onboarding-guide">
          <li>Scarica lo zip agent e imposta <span className="mono">SIEM_URL</span> / <span className="mono">SIEM_API_TOKEN</span>.</li>
          <li>
            Esegui <span className="mono">DarkGreen-Agent.ps1 -Once</span> (Admin consigliato per Security log).
          </li>
          <li>
            Stato canale:{" "}
            <span className={`badge ${statusBadgeClass(channelStatus(agent))}`}>
              {channelStatus(agent)}
            </span>
            {agent?.last_event_at
              ? ` · ultimo ${new Date(agent.last_event_at).toLocaleString()}`
              : " · nessun evento agent ancora"}
          </li>
        </ol>
        <button
          type="button"
          className="ghost"
          disabled={dlBusy === "agent"}
          onClick={() => void onDownload("agent")}
        >
          {dlBusy === "agent" ? "Download…" : "Scarica windows-agent.zip"}
        </button>
      </div>
    </div>
  );
}
