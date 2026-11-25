type Example = {
  label: string;
  q: string;
  note: string;
};

const EXAMPLES: Example[] = [
  {
    label: "Deny firewall",
    q: "action:deny",
    note: "Tutti gli eventi con action esatta deny.",
  },
  {
    label: "IP sorgente",
    q: "src_ip:10.0.0.9",
    note: "Match esatto sul campo src_ip (case-insensitive).",
  },
  {
    label: "Campo + testo",
    q: "action:login_failed AND windows",
    note: "Filtro campo AND testo libero su message/host/user/ip.",
  },
  {
    label: "Frase tra virgolette",
    q: '"failed logon"',
    note: "Cerca la frase intera nel testo evento.",
  },
  {
    label: "Utente + host",
    q: "user:badguy host:LAB-PC",
    note: "Piu campi: AND implicito (AND opzionale).",
  },
];

const FIELDS = [
  "action",
  "src_ip",
  "dst_ip",
  "user",
  "host",
  "severity",
  "source_type",
  "vendor",
  "device",
  "message",
  "event_id",
  "channel",
  "provider",
  "ingest_channel",
];

type Props = {
  open: boolean;
  onClose: () => void;
  onUseExample: (q: string) => void;
};

export default function QueryHelpWiki({ open, onClose, onUseExample }: Props) {
  if (!open) return null;

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="modal-panel query-wiki"
        role="dialog"
        aria-modal="true"
        aria-labelledby="query-wiki-title"
      >
        <div className="modal-header">
          <h2 id="query-wiki-title" style={{ margin: 0, fontSize: "1.1rem" }}>
            Guida query di ricerca
          </h2>
          <button className="ghost" type="button" aria-label="Chiudi guida" onClick={onClose}>
            ×
          </button>
        </div>

        <section className="query-wiki-section">
          <h3>Sintassi</h3>
          <ul>
            <li>
              <span className="mono">campo:valore</span> - filtro esatto su un campo
              normalizzato (tranne <span className="mono">message</span>, che e substring).
            </li>
            <li>
              Testo libero - cerca in message, raw, user, host, src_ip, dst_ip, action.
            </li>
            <li>
              Unisci con <span className="mono">AND</span> (opzionale; anche solo spazi).
            </li>
            <li>
              Valori con spazi: <span className="mono">&quot;failed logon&quot;</span>.
            </li>
          </ul>
        </section>

        <section className="query-wiki-section">
          <h3>Campi disponibili</h3>
          <p className="muted" style={{ marginTop: 0 }}>
            Usa solo questi nomi a sinistra dei due punti:
          </p>
          <div className="query-wiki-fields">
            {FIELDS.map((f) => (
              <code key={f} className="mono">
                {f}
              </code>
            ))}
          </div>
        </section>

        <section className="query-wiki-section">
          <h3>Filtri della riga</h3>
          <ul>
            <li>
              <strong>Sorgente</strong> / <strong>Severity</strong> restringono gli eventi.
            </li>
            <li>
              <strong>Stato</strong> filtra gli alert trovati (open, acked, in_progress, closed).
            </li>
          </ul>
        </section>

        <section className="query-wiki-section">
          <h3>Esempi pronti</h3>
          <p className="muted" style={{ marginTop: 0 }}>
            Clicca un esempio per inserirlo nella Query (poi premi Cerca).
          </p>
          <div className="query-wiki-examples">
            {EXAMPLES.map((ex) => (
              <button
                key={ex.q}
                type="button"
                className="ghost query-wiki-example"
                onClick={() => {
                  onUseExample(ex.q);
                  onClose();
                }}
              >
                <strong>{ex.label}</strong>
                <span className="mono">{ex.q}</span>
                <span className="muted">{ex.note}</span>
              </button>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
