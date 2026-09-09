import { useState } from "react";
import { api, type SiemEvent } from "../api";

export default function SearchPanel() {
  const [q, setQ] = useState("action:deny");
  const [sourceType, setSourceType] = useState("");
  const [severity, setSeverity] = useState("");
  const [total, setTotal] = useState(0);
  const [events, setEvents] = useState<SiemEvent[]>([]);
  const [selected, setSelected] = useState<SiemEvent | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.search({
        q,
        source_type: sourceType || undefined,
        severity: severity || undefined,
        since_minutes: 1440,
      });
      setTotal(res.total);
      setEvents(res.events);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="panel">
        <div className="row">
          <div style={{ flex: 2 }}>
            <label htmlFor="q">Query</label>
            <input
              id="q"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder='src_ip:203.0.113.45 AND action:deny'
              onKeyDown={(e) => e.key === "Enter" && void run()}
            />
          </div>
          <div>
            <label htmlFor="st">Source</label>
            <select id="st" value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
              <option value="">Any</option>
              <option value="firewall">firewall</option>
              <option value="windows">windows</option>
              <option value="cloud_auth">cloud_auth</option>
              <option value="siem_export">siem_export</option>
            </select>
          </div>
          <div>
            <label htmlFor="sev">Severity</label>
            <select id="sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">Any</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
          </div>
          <div style={{ flex: "0 0 auto" }}>
            <label>&nbsp;</label>
            <button className="primary" type="button" onClick={() => void run()} disabled={loading}>
              {loading ? "Searching…" : "Search"}
            </button>
          </div>
        </div>
        <p className="muted" style={{ marginBottom: 0, marginTop: "0.75rem" }}>
          Examples: <code className="mono">user:j.doe</code>,{" "}
          <code className="mono">source_type:windows AND action:login_failed</code>, free-text{" "}
          <code className="mono">malware</code>
        </p>
      </div>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <p className="muted">
          {total} hit{total === 1 ? "" : "s"}
        </p>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Severity</th>
              <th>Action</th>
              <th>User / IPs</th>
              <th>Message</th>
            </tr>
          </thead>
          <tbody>
            {events.map((ev) => (
              <tr key={ev.id} className="clickable" onClick={() => setSelected(ev)}>
                <td className="mono">{new Date(ev.timestamp).toLocaleString()}</td>
                <td className="mono">{ev.source_type}</td>
                <td>
                  <span className={`badge ${ev.severity}`}>{ev.severity}</span>
                </td>
                <td className="mono">{ev.action}</td>
                <td className="mono">
                  {ev.user || "—"}
                  <br />
                  {ev.src_ip || "—"} → {ev.dst_ip || "—"}
                </td>
                <td>{ev.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="drawer-backdrop" onClick={() => setSelected(null)}>
          <aside className="drawer" onClick={(e) => e.stopPropagation()}>
            <div className="row" style={{ marginBottom: "1rem" }}>
              <h2 style={{ margin: 0, flex: 1 }}>Event #{selected.id}</h2>
              <button className="ghost" type="button" onClick={() => setSelected(null)}>
                Close
              </button>
            </div>
            <dl className="kv">
              <dt>Timestamp</dt>
              <dd className="mono">{selected.timestamp}</dd>
              <dt>Source</dt>
              <dd className="mono">{selected.source_type}</dd>
              <dt>Channel</dt>
              <dd className="mono">{selected.ingest_channel}</dd>
              <dt>Vendor</dt>
              <dd>{selected.vendor || "—"}</dd>
              <dt>Host</dt>
              <dd>{selected.host || "—"}</dd>
              <dt>User</dt>
              <dd>{selected.user || "—"}</dd>
              <dt>Src IP</dt>
              <dd className="mono">{selected.src_ip || "—"}</dd>
              <dt>Dst IP</dt>
              <dd className="mono">{selected.dst_ip || "—"}</dd>
              <dt>Action</dt>
              <dd className="mono">{selected.action || "—"}</dd>
              <dt>Severity</dt>
              <dd>
                <span className={`badge ${selected.severity}`}>{selected.severity}</span>
              </dd>
              <dt>Message</dt>
              <dd>{selected.message}</dd>
            </dl>
            <h3 className="muted">Raw</h3>
            <pre className="raw">{selected.raw}</pre>
            <h3 className="muted">Labels</h3>
            <pre className="raw">{JSON.stringify(selected.labels, null, 2)}</pre>
          </aside>
        </div>
      )}
    </>
  );
}
