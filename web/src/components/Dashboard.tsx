import { useEffect, useState } from "react";
import { api, type Stats } from "../api";

export default function Dashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .stats()
        .then((s) => {
          if (alive) {
            setStats(s);
            setError(null);
          }
        })
        .catch((e: Error) => alive && setError(e.message));
    load();
    const id = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, []);

  if (error) return <p className="error">Failed to load stats: {error}</p>;
  if (!stats) return <p className="muted">Loading dashboard…</p>;

  const maxBucket = Math.max(1, ...stats.timeline.map((t) => t.count));

  return (
    <>
      <div className="grid grid-4">
        <div className="panel stat-card">
          <h3>Events</h3>
          <strong>{stats.total_events}</strong>
        </div>
        <div className="panel stat-card">
          <h3>EPS (approx)</h3>
          <strong>{stats.eps_approx}</strong>
        </div>
        <div className="panel stat-card">
          <h3>Open alerts</h3>
          <strong>{stats.open_alerts}</strong>
        </div>
        <div className="panel stat-card">
          <h3>Total alerts</h3>
          <strong>{stats.total_alerts}</strong>
        </div>
      </div>

      <div className="grid grid-2">
        <div className="panel">
          <h3 className="muted">Event volume (last hour)</h3>
          <div className="bars" aria-label="timeline">
            {stats.timeline.map((t) => (
              <div
                key={t.bucket}
                className="bar"
                title={`${t.bucket}: ${t.count}`}
                style={{ height: `${Math.max(4, (t.count / maxBucket) * 100)}%` }}
              />
            ))}
          </div>
        </div>
        <div className="panel">
          <h3 className="muted">By source type</h3>
          <table>
            <tbody>
              {Object.entries(stats.by_source_type).map(([k, v]) => (
                <tr key={k}>
                  <td className="mono">{k}</td>
                  <td>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3 className="muted" style={{ marginTop: "1rem" }}>
            By severity
          </h3>
          <table>
            <tbody>
              {Object.entries(stats.by_severity).map(([k, v]) => (
                <tr key={k}>
                  <td>
                    <span className={`badge ${k}`}>{k}</span>
                  </td>
                  <td>{v}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="panel">
        <h3 className="muted">Recent alerts</h3>
        {stats.recent_alerts.length === 0 ? (
          <p className="muted">No alerts yet.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Severity</th>
                <th>Title</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {stats.recent_alerts.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{new Date(a.created_at).toLocaleString()}</td>
                  <td>
                    <span className={`badge ${a.severity}`}>{a.severity}</span>
                  </td>
                  <td>{a.title}</td>
                  <td>
                    <span className={`badge ${a.status}`}>{a.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
