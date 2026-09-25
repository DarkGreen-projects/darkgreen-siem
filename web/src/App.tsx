import { useEffect, useState } from "react";
import {
  AuthError,
  api,
  clearAuthSession,
  getStoredRole,
  getStoredTenant,
  getStoredToken,
  getStoredUsername,
  setAuthSession,
} from "./api";
import Dashboard from "./components/Dashboard";
import SearchPanel from "./components/SearchPanel";
import SourcesPanel from "./components/SourcesPanel";
import DetectionsPanel from "./components/DetectionsPanel";
import SetupPanel from "./components/SetupPanel";
import LoginPanel from "./components/LoginPanel";

type Tab = "dashboard" | "search" | "sources" | "detections" | "setup";

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [username, setUsername] = useState<string | null>(getStoredUsername());
  const [role, setRole] = useState<string | null>(getStoredRole());
  const [tenant, setTenant] = useState<string | null>(getStoredTenant());
  const [checking, setChecking] = useState(!!getStoredToken());
  const [silentCount, setSilentCount] = useState(0);

  const canSetup = role === "admin";
  const canWriteRules = role === "admin" || role === "analyst";

  useEffect(() => {
    if (!getStoredToken()) {
      setChecking(false);
      return;
    }
    let alive = true;
    api
      .me()
      .then((me) => {
        if (!alive) return;
        setUsername(me.username);
        setRole(me.role);
        setTenant(me.tenant_name || me.tenant_id);
        const tok = getStoredToken();
        if (tok) setAuthSession(tok, me.username, me.role, me.tenant_id);
      })
      .catch((e) => {
        if (e instanceof AuthError || (e as Error).message) {
          clearAuthSession();
          if (alive) {
            setUsername(null);
            setRole(null);
            setTenant(null);
          }
        }
      })
      .finally(() => alive && setChecking(false));
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    if (!username) return;
    let alive = true;
    const load = () =>
      api
        .stats("1h")
        .then((s) => {
          if (!alive) return;
          const n = (s.source_health || []).filter((h) => h.status === "silent").length;
          setSilentCount(n);
        })
        .catch(() => {
          /* ignore poll errors */
        });
    load();
    const id = setInterval(load, 10000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [username]);

  useEffect(() => {
    if (tab === "setup" && !canSetup) setTab("dashboard");
  }, [tab, canSetup]);

  const logout = () => {
    clearAuthSession();
    setUsername(null);
    setRole(null);
    setTenant(null);
  };

  if (checking) {
    return (
      <div className="app">
        <p className="muted">Verifica sessione…</p>
      </div>
    );
  }

  if (!username) {
    return (
      <div className="app">
        <header className="header">
          <div className="brand">
            <h1>DarkGreen SIEM</h1>
            <p>Demo SIEM multi-fonte - ingest, normalizzazione, ricerca, detection</p>
          </div>
        </header>
        <LoginPanel
          onLoggedIn={(u, r, t) => {
            setUsername(u);
            setRole(r);
            setTenant(t);
          }}
        />
      </div>
    );
  }

  const tabs: { id: Tab; label: string }[] = [
    { id: "dashboard", label: "Dashboard" },
    { id: "search", label: "Ricerca" },
    { id: "sources", label: "Sorgenti" },
    { id: "detections", label: "Detection" },
  ];
  if (canSetup) tabs.push({ id: "setup", label: "Setup" });

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <h1>DarkGreen SIEM</h1>
          <p>Demo SIEM multi-fonte - ingest, normalizzazione, ricerca, detection</p>
        </div>
        <nav className="nav">
          {tabs.map(({ id, label }) => (
            <button
              key={id}
              className={tab === id ? "active" : ""}
              onClick={() => setTab(id)}
              type="button"
            >
              {label}
              {id === "dashboard" && silentCount > 0 ? (
                <span className="nav-silent-badge" title="Sorgenti silenziose">
                  {silentCount}
                </span>
              ) : null}
            </button>
          ))}
          <span className="nav-user mono muted">
            {username}
            {role ? ` · ${role}` : ""}
            {tenant ? ` · ${tenant}` : ""}
          </span>
          <button className="ghost" type="button" onClick={logout}>
            Esci
          </button>
        </nav>
      </header>

      {tab === "dashboard" && <Dashboard />}
      {tab === "search" && <SearchPanel />}
      {tab === "sources" && <SourcesPanel />}
      {tab === "detections" && <DetectionsPanel readOnly={!canWriteRules} />}
      {tab === "setup" && canSetup && <SetupPanel />}
    </div>
  );
}
