import { useState } from "react";
import Dashboard from "./components/Dashboard";
import SearchPanel from "./components/SearchPanel";
import SourcesPanel from "./components/SourcesPanel";
import DetectionsPanel from "./components/DetectionsPanel";

type Tab = "dashboard" | "search" | "sources" | "detections";

export default function App() {
  const [tab, setTab] = useState<Tab>("dashboard");

  return (
    <div className="app">
      <header className="header">
        <div className="brand">
          <h1>DarkGreen SIEM</h1>
          <p>Multi-source demo SIEM — ingest, normalize, search, detect</p>
        </div>
        <nav className="nav">
          {(
            [
              ["dashboard", "Dashboard"],
              ["search", "Search"],
              ["sources", "Sources"],
              ["detections", "Detections"],
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
        </nav>
      </header>

      {tab === "dashboard" && <Dashboard />}
      {tab === "search" && <SearchPanel />}
      {tab === "sources" && <SourcesPanel />}
      {tab === "detections" && <DetectionsPanel />}
    </div>
  );
}
