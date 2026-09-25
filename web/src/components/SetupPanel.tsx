import { useEffect, useState } from "react";
import { api, type LabSetup } from "../api";

const SLA_SEVS = ["critical", "high", "medium", "low"] as const;

const DEFAULT_ACK: Record<string, number> = {
  critical: 15,
  high: 30,
  medium: 240,
  low: 1440,
};
const DEFAULT_CLOSE: Record<string, number> = {
  critical: 120,
  high: 480,
  medium: 1440,
  low: 10080,
};

export default function SetupPanel() {
  const [setup, setSetup] = useState<LabSetup | null>(null);
  const [retention, setRetention] = useState(7);
  const [staleMin, setStaleMin] = useState(5);
  const [silentMin, setSilentMin] = useState(30);
  const [silenceAlerts, setSilenceAlerts] = useState(true);
  const [vtKey, setVtKey] = useState("");
  const [abuseKey, setAbuseKey] = useState("");
  const [otxKey, setOtxKey] = useState("");
  const [notifyUrl, setNotifyUrl] = useState("");
  const [notifyFormat, setNotifyFormat] = useState("slack");
  const [notifyMinSev, setNotifyMinSev] = useState("high");
  const [slaAck, setSlaAck] = useState<Record<string, number>>({ ...DEFAULT_ACK });
  const [slaClose, setSlaClose] = useState<Record<string, number>>({ ...DEFAULT_CLOSE });
  const [error, setError] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () =>
    api
      .setup()
      .then((s) => {
        setSetup(s);
        setRetention(s.retention_days);
        setStaleMin(s.health_stale_minutes);
        setSilentMin(s.health_silent_minutes);
        setSilenceAlerts(s.silence_alerts_enabled);
        setVtKey("");
        setAbuseKey("");
        setOtxKey("");
        setNotifyUrl("");
        setNotifyFormat(s.notify_format || "slack");
        setNotifyMinSev(s.notify_min_severity || "high");
        setSlaAck({ ...DEFAULT_ACK, ...(s.sla_ack_minutes || {}) });
        setSlaClose({ ...DEFAULT_CLOSE, ...(s.sla_close_minutes || {}) });
        setError(null);
      })
      .catch((e: Error) => setError(e.message));

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const payload: Parameters<typeof api.updateSetup>[0] = {
        retention_days: retention,
        health_stale_minutes: staleMin,
        health_silent_minutes: silentMin,
        silence_alerts_enabled: silenceAlerts,
        notify_format: notifyFormat,
        notify_min_severity: notifyMinSev,
        sla_ack_minutes: slaAck,
        sla_close_minutes: slaClose,
      };
      if (vtKey.trim()) payload.vt_api_key = vtKey.trim();
      if (abuseKey.trim()) payload.abuseipdb_api_key = abuseKey.trim();
      if (otxKey.trim()) payload.otx_api_key = otxKey.trim();
      if (notifyUrl.trim()) payload.notify_webhook_url = notifyUrl.trim();
      const s = await api.updateSetup(payload);
      setSetup(s);
      setVtKey("");
      setAbuseKey("");
      setOtxKey("");
      setNotifyUrl("");
      setSlaAck({ ...DEFAULT_ACK, ...(s.sla_ack_minutes || {}) });
      setSlaClose({ ...DEFAULT_CLOSE, ...(s.sla_close_minutes || {}) });
      setMsg("Impostazioni lab salvate (sessione API).");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const clearKey = async (which: "vt" | "abuseipdb" | "otx" | "notify") => {
    setBusy(true);
    setMsg(null);
    try {
      const payload: Parameters<typeof api.updateSetup>[0] = {};
      if (which === "vt") payload.vt_api_key = "CLEAR";
      if (which === "abuseipdb") payload.abuseipdb_api_key = "CLEAR";
      if (which === "otx") payload.otx_api_key = "CLEAR";
      if (which === "notify") payload.notify_webhook_url = "CLEAR";
      const s = await api.updateSetup(payload);
      setSetup(s);
      setMsg(which === "notify" ? "Webhook notifiche rimosso." : `Key ${which} rimossa dalla sessione.`);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const runPurge = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.purge();
      if (r.skipped) {
        setMsg("Purge saltato: retention = 0 (disabilitato).");
      } else {
        setMsg(`Purge completato: ${r.deleted} eventi eliminati (cutoff ${r.cutoff || "-"}).`);
      }
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!setup && !error) return <p className="muted">Caricamento setup…</p>;

  return (
    <div className="setup-stack">
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Setup lab</h3>
        <p className="muted">
          Controlli pensati per disco, lab ripetibile e costi demo: limita la retention degli
          eventi, regola le soglie di silence sulle sorgenti e genera alert ops quando una
          pipeline smette di scrivere.
        </p>
        {error && <p className="error">{error}</p>}
        {msg && <p className="ok-msg">{msg}</p>}

        <div className="setup-grid">
          <label>
            Retention eventi (giorni)
            <input
              type="number"
              min={0}
              max={3650}
              value={retention}
              onChange={(e) => setRetention(Number(e.target.value))}
            />
            <span className="muted setup-hint">0 = non cancellare mai</span>
          </label>
          <label>
            Health stale (minuti)
            <input
              type="number"
              min={1}
              max={10080}
              value={staleMin}
              onChange={(e) => setStaleMin(Number(e.target.value))}
            />
          </label>
          <label>
            Health silent (minuti)
            <input
              type="number"
              min={1}
              max={10080}
              value={silentMin}
              onChange={(e) => setSilentMin(Number(e.target.value))}
            />
          </label>
          <label className="setup-toggle">
            <input
              type="checkbox"
              checked={silenceAlerts}
              onChange={(e) => setSilenceAlerts(e.target.checked)}
            />
            Alert ops su sorgente silenziosa
          </label>
        </div>

        <h3 className="muted" style={{ marginTop: "1.25rem" }}>
          Enrichment API
        </h3>
        <p className="muted" style={{ fontSize: "0.85rem" }}>
          Inserisci le tue API key (non vengono mostrate in chiaro dopo il salvataggio). Lascia
          vuoto per non modificare. Non committare segreti nel repo.
        </p>
        <div className="setup-grid">
          <label>
            VirusTotal{" "}
            <span className="muted mono">
              {setup?.vt_configured ? setup.vt_api_key_masked || "configurata" : "non configurata"}
            </span>
            <input
              type="password"
              autoComplete="off"
              value={vtKey}
              onChange={(e) => setVtKey(e.target.value)}
              placeholder="nuova VT_API_KEY"
            />
            {setup?.vt_configured ? (
              <button type="button" className="ghost" disabled={busy} onClick={() => void clearKey("vt")}>
                Rimuovi
              </button>
            ) : null}
          </label>
          <label>
            AbuseIPDB{" "}
            <span className="muted mono">
              {setup?.abuseipdb_configured
                ? setup.abuseipdb_api_key_masked || "configurata"
                : "non configurata"}
            </span>
            <input
              type="password"
              autoComplete="off"
              value={abuseKey}
              onChange={(e) => setAbuseKey(e.target.value)}
              placeholder="nuova ABUSEIPDB_API_KEY"
            />
            {setup?.abuseipdb_configured ? (
              <button
                type="button"
                className="ghost"
                disabled={busy}
                onClick={() => void clearKey("abuseipdb")}
              >
                Rimuovi
              </button>
            ) : null}
          </label>
          <label>
            AlienVault OTX{" "}
            <span className="muted mono">
              {setup?.otx_configured ? setup.otx_api_key_masked || "configurata" : "non configurata"}
            </span>
            <input
              type="password"
              autoComplete="off"
              value={otxKey}
              onChange={(e) => setOtxKey(e.target.value)}
              placeholder="nuova OTX_API_KEY"
            />
            {setup?.otx_configured ? (
              <button type="button" className="ghost" disabled={busy} onClick={() => void clearKey("otx")}>
                Rimuovi
              </button>
            ) : null}
          </label>
        </div>

        <h3 className="muted" style={{ marginTop: "1.25rem" }}>
          Notifiche (Slack / Teams)
        </h3>
        <p className="muted" style={{ fontSize: "0.85rem" }}>
          Webhook HTTPS inviato quando si apre un alert con severity &gt;= soglia (default high).
          Solo al primo create, non a ogni merge/dedup. Env:{" "}
          <span className="mono">NOTIFY_WEBHOOK_URL</span>, <span className="mono">NOTIFY_FORMAT</span>.
        </p>
        <div className="setup-grid">
          <label style={{ gridColumn: "1 / -1" }}>
            Webhook URL{" "}
            <span className="muted mono">
              {setup?.notify_webhook_configured
                ? setup.notify_webhook_url_masked || "configurato"
                : "non configurato"}
            </span>
            <input
              type="password"
              autoComplete="off"
              value={notifyUrl}
              onChange={(e) => setNotifyUrl(e.target.value)}
              placeholder="https://hooks.slack.com/... oppure Teams webhook"
            />
            {setup?.notify_webhook_configured ? (
              <button
                type="button"
                className="ghost"
                disabled={busy}
                onClick={() => void clearKey("notify")}
              >
                Rimuovi
              </button>
            ) : null}
          </label>
          <label>
            Formato
            <select value={notifyFormat} onChange={(e) => setNotifyFormat(e.target.value)}>
              <option value="slack">Slack Incoming Webhook</option>
              <option value="teams">Teams MessageCard</option>
            </select>
          </label>
          <label>
            Severity minima
            <select value={notifyMinSev} onChange={(e) => setNotifyMinSev(e.target.value)}>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </label>
        </div>

        <h3 className="muted" style={{ marginTop: "1.25rem" }}>
          SLA alert (minuti)
        </h3>
        <p className="muted" style={{ fontSize: "0.85rem" }}>
          Tempo massimo ad ack (uscita da open) e a closed, per severity.{" "}
          <span className="mono">0</span> = disabilitata. At risk oltre l&apos;80% del target.
        </p>
        <div className="sla-grid">
          <div className="sla-grid-head muted mono">severity</div>
          <div className="sla-grid-head muted mono">ack</div>
          <div className="sla-grid-head muted mono">close</div>
          {SLA_SEVS.map((sev) => (
            <div key={sev} className="sla-grid-row">
              <span className={`badge ${sev}`}>{sev}</span>
              <input
                type="number"
                min={0}
                max={40320}
                value={slaAck[sev] ?? 0}
                onChange={(e) =>
                  setSlaAck((prev) => ({ ...prev, [sev]: Number(e.target.value) }))
                }
              />
              <input
                type="number"
                min={0}
                max={40320}
                value={slaClose[sev] ?? 0}
                onChange={(e) =>
                  setSlaClose((prev) => ({ ...prev, [sev]: Number(e.target.value) }))
                }
              />
            </div>
          ))}
        </div>

        <div className="row" style={{ gap: "0.5rem", marginTop: "1rem" }}>
          <button type="button" disabled={busy} onClick={() => void save()}>
            Salva
          </button>
          <button type="button" className="ghost" disabled={busy} onClick={() => void runPurge()}>
            Esegui purge ora
          </button>
        </div>

        <h3 className="muted" style={{ marginTop: "1.25rem" }}>
          Ultimo purge
        </h3>
        <p className="mono muted" style={{ margin: 0 }}>
          {setup?.last_purge_at
            ? `${new Date(setup.last_purge_at).toLocaleString()} - eliminati ${setup.last_purge_deleted}`
            : "Nessun purge ancora"}
        </p>
        <p className="muted" style={{ marginTop: "0.75rem", fontSize: "0.85rem" }}>
          Intervallo automatico: ogni {setup?.purge_interval_sec ?? "-"}s (env{" "}
          <span className="mono">PURGE_INTERVAL_SEC</span>).
        </p>
      </div>
    </div>
  );
}
