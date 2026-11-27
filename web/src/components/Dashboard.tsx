import { useEffect, useMemo, useState } from "react";
import {
  SOURCE_COLORS,
  api,
  formatSilence,
  type Alert,
  type AlertStatus,
  type Stats,
  type StatsRange,
} from "../api";
import AlertCard from "./AlertCard";
import { useVisibleInterval } from "../hooks/useVisibleInterval";

const RANGES: { id: StatsRange; label: string }[] = [
  { id: "1h", label: "1 ora" },
  { id: "1d", label: "1 giorno" },
  { id: "7d", label: "7 giorni" },
  { id: "30d", label: "30 giorni" },
  { id: "1y", label: "1 anno" },
];

const SOURCE_ORDER = ["firewall", "windows", "cloud_auth", "siem_export"];

const STATUS_FILTERS: { id: AlertStatus | "all"; label: string }[] = [
  { id: "all", label: "Tutti" },
  { id: "open", label: "Aperti" },
  { id: "acked", label: "Ack" },
  { id: "in_progress", label: "In corso" },
  { id: "closed", label: "Chiusi" },
];

export default function Dashboard({
  onPivotSearch,
}: {
  onPivotSearch?: (query: string) => void;
} = {}) {
  const [range, setRange] = useState<StatsRange>("1h");
  const [stats, setStats] = useState<Stats | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<AlertStatus | "all">("all");
  const [mitreFilter, setMitreFilter] = useState("");
  const [slaFilter, setSlaFilter] = useState("");
  const [hideNoise, setHideNoise] = useState(false);
  const [filteredAlerts, setFilteredAlerts] = useState<Alert[] | null>(null);
  const [pageOffset, setPageOffset] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [focusedAlertId, setFocusedAlertId] = useState<number | null>(null);
  const PAGE_SIZE = 50;

  useEffect(() => {
    let alive = true;
    api
      .stats(range)
      .then((s) => {
        if (alive) {
          setStats(s);
          setError(null);
        }
      })
      .catch((e: Error) => alive && setError(e.message));
    return () => {
      alive = false;
    };
  }, [range]);

  useVisibleInterval(
    () => {
      api
        .stats(range)
        .then((s) => {
          setStats(s);
          setError(null);
        })
        .catch((e: Error) => setError(e.message));
    },
    10000,
    { deps: [range] }
  );

  useEffect(() => {
    setPageOffset(0);
  }, [statusFilter, mitreFilter, slaFilter, hideNoise]);

  useEffect(() => {
    const mitre = mitreFilter.trim();
    const sla = slaFilter.trim();
    if (statusFilter === "all" && !mitre && !sla && !hideNoise) {
      setFilteredAlerts(null);
      setHasMore(false);
      return;
    }
    let alive = true;
    api
      .alerts({
        status: statusFilter === "all" ? undefined : statusFilter,
        mitre: mitre || undefined,
        sla: sla || undefined,
        hide_noise: hideNoise || undefined,
        limit: PAGE_SIZE,
        offset: pageOffset,
      })
      .then((list) => {
        if (!alive) return;
        setFilteredAlerts((prev) =>
          pageOffset === 0 ? list : [...(prev || []), ...list]
        );
        setHasMore(list.length >= PAGE_SIZE);
      })
      .catch(() => {
        if (alive && pageOffset === 0) setFilteredAlerts([]);
      });
    return () => {
      alive = false;
    };
  }, [statusFilter, mitreFilter, slaFilter, hideNoise, pageOffset]);

  useVisibleInterval(
    () => {
      const mitre = mitreFilter.trim();
      const sla = slaFilter.trim();
      if (statusFilter === "all" && !mitre && !sla) return;
      api
        .alerts({
          status: statusFilter === "all" ? undefined : statusFilter,
          mitre: mitre || undefined,
          sla: sla || undefined,
        })
        .then((list) => setFilteredAlerts(list))
        .catch(() => setFilteredAlerts([]));
    },
    10000,
    { deps: [statusFilter, mitreFilter, slaFilter] }
  );

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
  const byStatus = stats.by_alert_status || {};
  const openCount = byStatus.open ?? stats.open_alerts;
  const alertsShown =
    statusFilter === "all" && !mitreFilter.trim() && !slaFilter.trim() && !hideNoise
      ? stats.recent_alerts
      : filteredAlerts ?? [];

  const patchAlert = (updated: Alert) => {
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
    setFilteredAlerts((prev) =>
      prev ? prev.map((x) => (x.id === updated.id ? updated : x)) : prev
    );
  };

  const exportCsv = async () => {
    setExporting(true);
    try {
      const mitre = mitreFilter.trim();
      const sla = slaFilter.trim();
      await api.exportAlertsCsv({
        status: statusFilter === "all" ? undefined : statusFilter,
        mitre: mitre || undefined,
        sla: sla || undefined,
      });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setExporting(false);
    }
  };

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
          <strong>{openCount}</strong>
        </div>
        <div className="panel stat-card">
          <h3>Alert totali</h3>
          <strong>{stats.total_alerts}</strong>
        </div>
      </div>

      <div className="panel">
        <h3 className="muted" style={{ marginTop: 0 }}>
          Stato alert
        </h3>
        <div className="status-filter-row" role="group" aria-label="Filtro stato alert">
          {STATUS_FILTERS.map((f) => {
            const count =
              f.id === "all"
                ? stats.total_alerts
                : byStatus[f.id] ?? 0;
            return (
              <button
                key={f.id}
                type="button"
                className={`status-filter-btn${statusFilter === f.id ? " active" : ""}`}
                onClick={() => setStatusFilter(f.id)}
              >
                {f.label}
                <span className="muted"> {count}</span>
              </button>
            );
          })}
          <label className="status-filter-field">
            MITRE
            <input
              value={mitreFilter}
              onChange={(e) => setMitreFilter(e.target.value)}
              placeholder="T1059"
              aria-label="Filtro MITRE"
            />
          </label>
          <label className="status-filter-field">
            SLA
            <select
              value={slaFilter}
              onChange={(e) => setSlaFilter(e.target.value)}
              aria-label="Filtro SLA"
            >
              <option value="">tutti</option>
              <option value="breached">breached</option>
              <option value="at_risk">at_risk</option>
              <option value="ok">ok</option>
              <option value="met">met</option>
            </select>
          </label>
          <label className="status-filter-field setup-toggle" style={{ marginLeft: "0.5rem" }}>
            <input
              type="checkbox"
              checked={hideNoise}
              onChange={(e) => setHideNoise(e.target.checked)}
              aria-label="Nascondi likely_noise"
            />
            Nascondi likely_noise
          </label>
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
                  <span className={`badge health-${h.status}`}>
                    {h.status === "silent" ? "NESSUN EVENTO" : h.status}
                  </span>
                </div>
                <div className="muted mono" style={{ fontSize: "0.8rem" }}>
                  ultimo:{" "}
                  {h.last_event_at ? new Date(h.last_event_at).toLocaleString() : "-"}
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
        <div className="row" style={{ alignItems: "center", marginBottom: "0.5rem" }}>
          <h3 className="muted" style={{ margin: 0, flex: 1 }}>
            Alert{" "}
            {statusFilter === "all"
              ? "recenti"
              : STATUS_FILTERS.find((f) => f.id === statusFilter)?.label.toLowerCase()}
          </h3>
          <button type="button" className="ghost" disabled={exporting} onClick={exportCsv}>
            {exporting ? "Export…" : "Esporta CSV"}
          </button>
        </div>
        {alertsShown.length === 0 ? (
          <p className="muted">Nessun alert in questo filtro.</p>
        ) : (
          <div className="list-block" style={{ maxHeight: "70vh", overflowY: "auto" }}>
            {alertsShown.map((a) => (
              <div
                key={a.id}
                onFocusCapture={() => setFocusedAlertId(a.id)}
                onClick={() => setFocusedAlertId(a.id)}
              >
                <AlertCard
                  alert={a}
                  onUpdated={patchAlert}
                  enableHotkeys={focusedAlertId === a.id}
                  onPivotSearch={onPivotSearch}
                />
              </div>
            ))}
          </div>
        )}
        {hasMore && filteredAlerts && (
          <button
            type="button"
            className="ghost"
            style={{ marginTop: "0.75rem" }}
            onClick={() => setPageOffset((o) => o + PAGE_SIZE)}
          >
            Carica altri
          </button>
        )}
      </div>
    </>
  );
}
