import { useEffect, useState } from "react";
import { api, type LabSetup } from "../api";

export default function SetupPanel() {
  const [setup, setSetup] = useState<LabSetup | null>(null);
  const [retention, setRetention] = useState(7);
  const [staleMin, setStaleMin] = useState(5);
  const [silentMin, setSilentMin] = useState(30);
  const [silenceAlerts, setSilenceAlerts] = useState(true);
  const [vtKey, setVtKey] = useState("");
  const [abuseKey, setAbuseKey] = useState("");
  const [otxKey, setOtxKey] = useState("");
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
      };
      if (vtKey.trim()) payload.vt_api_key = vtKey.trim();
      if (abuseKey.trim()) payload.abuseipdb_api_key = abuseKey.trim();
      if (otxKey.trim()) payload.otx_api_key = otxKey.trim();
      const s = await api.updateSetup(payload);
      setSetup(s);
      setVtKey("");
      setAbuseKey("");
      setOtxKey("");
      setMsg("Impostazioni lab salvate (sessione API).");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const clearKey = async (which: "vt" | "abuseipdb" | "otx") => {
    setBusy(true);
    setMsg(null);
    try {
      const payload: Parameters<typeof api.updateSetup>[0] = {};
      if (which === "vt") payload.vt_api_key = "CLEAR";
      if (which === "abuseipdb") payload.abuseipdb_api_key = "CLEAR";
      if (which === "otx") payload.otx_api_key = "CLEAR";
      const s = await api.updateSetup(payload);
      setSetup(s);
      setMsg(`Key ${which} rimossa dalla sessione.`);
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
