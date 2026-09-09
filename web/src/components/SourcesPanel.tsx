import { useEffect, useState } from "react";
import { api, type Source } from "../api";

const CHANNEL_HELP: Record<string, string> = {
  seed: "Sample files loaded at API startup",
  http: "REST /api/ingest (UI tooling + log-generator)",
  syslog: "UDP syslog collector on port 5140",
};

export default function SourcesPanel() {
  const [sources, setSources] = useState<Source[]>([]);
  const [error, setError] = useState<string | null>(null);

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
    <div className="panel">
      <h3 style={{ marginTop: 0 }}>Ingest channels</h3>
      <p className="muted">
        DarkGreen SIEM accepts firewall syslog, Windows events, cloud auth JSON, and SIEM/EDR
        exports — normalized into one ECS-lite schema.
      </p>
      {error && <p className="error">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Channel</th>
            <th>Events</th>
            <th>Last event</th>
            <th>Notes</th>
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
              <td className="muted">{CHANNEL_HELP[s.channel] || "Custom / other"}</td>
            </tr>
          ))}
          {sources.length === 0 && (
            <tr>
              <td colSpan={4} className="muted">
                No ingest activity yet — start Compose and wait for seed/log-generator.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
