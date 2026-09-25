import { useEffect, useState } from "react";
import {
  AuthError,
  api,
  clearAuthSession,
  getStoredToken,
  getStoredUsername,
} from "./api";
import Dashboard from "./components/Dashboard";
import SearchPanel from "./components/SearchPanel";
import SourcesPanel from "./components/SourcesPanel";
import DetectionsPanel from "./components/DetectionsPanel";
import LoginPanel from "./components/LoginPanel";

type Tab = "dashboard" | "search" | "sources" | "detections";

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");
  const [username, setUsername] = useState<string | null>(getStoredUsername());
  const [checking, setChecking] = useState(!!getStoredToken());

  useEffect(() => {
    if (!getStoredToken()) {
      setChecking(false);
      return;
    }
    let alive = true;
    api
      .me()
      .then((me) => {
        if (alive) setUsername(me.username);
      })
      .catch((e) => {
        if (e instanceof AuthError || (e as Error).message) {
          clearAuthSession();
          if (alive) setUsername(null);
        }
      })
      .finally(() => alive && setChecking(false));
    return () => {
      alive = false;
    };
  }, []);

  const logout = () => {
    clearAuthSession();
    setUsername(null);
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
        <LoginPanel onLoggedIn={(u) => setUsername(u)} />
      </div>
    );
  }

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <h1>DarkGreen SIEM</h1>
          <p>Demo SIEM multi-fonte - ingest, normalizzazione, ricerca, detection</p>
        </div>
        <nav className="nav">
          {(
            [
              ["dashboard", "Dashboard"],
              ["search", "Ricerca"],
              ["sources", "Sorgenti"],
              ["detections", "Detection"],
            ] as const
          ).map(([id, label]) => (
            <button
              key={id}
              className={tab === id ? "active" : ""}
              onClick={() => setTab(id)}
              type="button"
            >
              {label}
            </button>
          ))}
          <span className="nav-user mono muted">{username}</span>
          <button className="ghost" type="button" onClick={logout}>
            Esci
          </button>
        </nav>
      </header>

      {tab === "dashboard" && <Dashboard />}
      {tab === "search" && <SearchPanel />}
      {tab === "sources" && <SourcesPanel />}
      {tab === "detections" && <DetectionsPanel />}
    </div>
  );
}
