import { useState } from "react";
import { api } from "../api";

type Props = {
  onLoggedIn: (username: string, role: string, tenant: string) => void;
};

export default function LoginPanel({ onLoggedIn }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const res = await api.login(username.trim(), password);
      onLoggedIn(res.username, res.role, res.tenant_id);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="panel login-panel" onSubmit={(e) => void submit(e)}>
        <h2 style={{ marginTop: 0 }}>Accesso lab</h2>
        <p className="muted">
          Usa le credenziali del tenant lab (vedi README / variabili{" "}
          <span className="mono">DEMO_USERNAME</span>).
        </p>
        <label htmlFor="login-user">Username</label>
        <input
          id="login-user"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="username"
          autoComplete="username"
          disabled={busy}
        />
        <label htmlFor="login-pass">Password</label>
        <input
          id="login-pass"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="password"
          autoComplete="current-password"
          disabled={busy}
        />
        {error && <p className="error">{error}</p>}
        <button className="primary" type="submit" disabled={busy} style={{ marginTop: "0.75rem" }}>
          {busy ? "Accesso…" : "Accedi"}
        </button>
      </form>
    </div>
  );
}
