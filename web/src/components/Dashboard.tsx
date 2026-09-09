import { useEffect, useMemo, useState } from "react";
import {
  SOURCE_COLORS,
  api,
  formatSilence,
  type Alert,
  type Stats,
  type StatsRange,
} from "../api";
import AlertCard from "./AlertCard";

const RANGES: { id: StatsRange; label: string }[] = [
  { id: "1h", label: "1 ora" },
  { id: "1d", label: "1 giorno" },
  { id: "7d", label: "7 giorni" },
  { id: "30d", label: "30 giorni" },
  { id: "1y", label: "1 anno" },
];

const SOURCE_ORDER = ["firewall", "windows", "cloud_auth", "siem_export"];

export default function Dashboard() {
  const [range, setRange] = useState<StatsRange>("1h");
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      api
        .stats(range)
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
  }, [range]);

  const sourcesInChart = useMemo(() => {
    if (!stats) return SOURCE_ORDER;
    const seen = new Set<string>(SOURCE_ORDER);
    for (const t of stats.timeline) {
      Object.keys(t.by_source || {}).forEach((k) => seen.add(k));
    }
    for (const h of stats.source_health || []) {
      seen.add(h.source_type);
    }
    return Array.from(seen);
  }, [stats]);

  if (error) return <p className="error">Impossibile caricare le statistiche: {error}</p>;
  if (!stats) return <p className="muted">Caricamento dashboard…</p>;

  const maxBucket = Math.max(1, ...stats.timeline.map((t) => t.count));
  const rangeLabel = RANGES.find((r) => r.id === range)?.label ?? range;

  return (
    <>
      <div className="grid grid-4">
        <div className="panel stat-card">
          <h3>Eventi</h3>
          <strong>{stats.total_events}</strong>
        </div>
        <div className="panel stat-card">
          <h3>EPS (approx)</h3>
          <strong>{stats.eps_approx}</strong>
        </div>
        <div className="panel stat-card">
          <h3>Alert aperti</h3>
          <strong>{stats.open_alerts}</strong>
        </div>
        <div className="panel stat-card">
          <h3>Alert totali</h3>
          <strong>{stats.total_alerts}</strong>
        </div>
      </div>

      <div className="grid grid-2">
        <div className="panel">
          <div className="row" style={{ marginBottom: "0.5rem", alignItems: "center" }}>
            <h3 className="muted" style={{ margin: 0, flex: 1 }}>
              Volume eventi per sorgente ({rangeLabel})
            </h3>
            <div className="range-toggle" role="group" aria-label="Intervallo temporale">
              {RANGES.map((r) => (
                <button
                  key={r.id}
                  type="button"
                  className={range === r.id ? "active" : ""}
                  onClick={() => setRange(r.id)}
                >
                  {r.id}
                </button>
              ))}
            </div>
          </div>

          <div className="legend">
            {sourcesInChart.map((src) => (
              <span key={src} className="legend-item">
                <span
                  className="legend-swatch"
                  style={{ background: SOURCE_COLORS[src] || "#9bb8a8" }}
                />
                {src}
              </span>
            ))}
          </div>

          <div className="bars" aria-label="timeline by source">
            {stats.timeline.map((t) => (
              <div
                key={t.bucket}
                className="bar-stack"
                title={`${t.bucket}: ${t.count} totali`}
                style={{ height: `${Math.max(4, (t.count / maxBucket) * 100)}%` }}
              >
                {sourcesInChart.map((src) => {
                  const n = t.by_source?.[src] || 0;
                  if (!n || !t.count) return null;
                  const pct = (n / t.count) * 100;
                  return (
                    <div
                      key={src}
                      className="bar-seg"
                      style={{
                        flexGrow: pct,
                        background: SOURCE_COLORS[src] || "#9bb8a8",
                      }}
                      title={`${src}: ${n}`}
                    />
                  );
                })}
              </div>
            ))}
          </div>

          <h3 className="muted" style={{ marginTop: "1rem" }}>
            Stato sorgenti
          </h3>
          <div className="health-grid">
            {(stats.source_health || []).map((h) => (
              <div key={h.source_type} className={`health-card status-${h.status}`}>
                <div className="health-top">
                  <span
                    className="legend-swatch"
                    style={{ background: SOURCE_COLORS[h.source_type] || "#9bb8a8" }}
                  />
                  <strong className="mono">{h.source_type}</strong>
                  <span className={`badge health-${h.status}`}>{h.status}</span>
                </div>
                <div className="muted mono" style={{ fontSize: "0.8rem" }}>
                  ultimo:{" "}
                  {h.last_event_at ? new Date(h.last_event_at).toLocaleString() : "—"}
                </div>
                <div className="muted" style={{ fontSize: "0.8rem" }}>
                  silenzio da {formatSilence(h.silent_for_seconds)}
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="panel">
          <h3 className="muted">Per source_type</h3>
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
            Per severity
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
        <h3 className="muted">Alert recenti</h3>
        {stats.recent_alerts.length === 0 ? (
          <p className="muted">Nessun alert ancora.</p>
        ) : (
          <div className="list-block">
            {stats.recent_alerts.map((a) => (
              <AlertCard
                key={a.id}
                alert={a}
                onUpdated={(updated: Alert) => {
                  setStats((prev) =>
                    prev
                      ? {
                          ...prev,
                          recent_alerts: prev.recent_alerts.map((x) =>
                            x.id === updated.id ? updated : x
                          ),
                        }
                      : prev
                  );
                }}
              />
            ))}
          </div>
        )}
      </div>
    </>
  );
}
