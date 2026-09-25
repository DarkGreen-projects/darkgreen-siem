import { useMemo, useState } from "react";
import { api, type Rule, type RuleCreatePayload } from "../api";
import InfoTip from "./InfoTip";

type Mode = "create" | "edit";

type Props = {
  mode: Mode;
  initial?: Rule;
  onSaved: () => void;
  onCancel: () => void;
};

const SOURCE_OPTIONS = ["firewall", "windows", "cloud_auth", "siem_export"] as const;

const ACTION_OPTIONS: { value: string; tip: string }[] = [
  { value: "deny", tip: "Deny firewall/rete — traffico bloccato da una policy." },
  { value: "accept", tip: "Accept firewall/rete — traffico consentito." },
  { value: "login_failed", tip: "Autenticazione fallita (password errata, lock, ecc.)." },
  { value: "login_success", tip: "Autenticazione / logon riuscito." },
  { value: "malware_detected", tip: "Endpoint o prodotto security ha segnalato malware." },
];

const GROUP_BY_OPTIONS = ["user", "src_ip", "host", "action", "source_type"];

const KNOWN_MATCH_KEYS = new Set(["source_type", "action"]);

function asList(value: unknown): string[] {
  if (value == null || value === "") return [];
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  return [String(value)].filter(Boolean);
}

function packFilter(values: string[]): string | string[] | undefined {
  if (values.length === 0) return undefined;
  if (values.length === 1) return values[0];
  return values;
}

function initialFromRule(rule?: Rule) {
  const def = (rule?.definition || {}) as Record<string, unknown>;
  const match = (def.match || {}) as Record<string, unknown>;
  const sourceTypes = asList(match.source_type);
  const actions = asList(match.action);
  let extraKey = "";
  let extraValue = "";
  for (const [k, v] of Object.entries(match)) {
    if (KNOWN_MATCH_KEYS.has(k)) continue;
    extraKey = k;
    const vals = asList(v);
    extraValue = vals[0] || "";
    break;
  }
  return {
    id: rule?.id || "",
    name: rule?.name || "",
    title: String(def.title || ""),
    description: rule?.description || "",
    threatBrief: rule?.threat_brief || "",
    type: (rule?.type === "threshold"
      ? "threshold"
      : rule?.type === "correlation"
        ? "correlation"
        : "match") as "match" | "threshold" | "correlation",
    severity: rule?.severity || "medium",
    enabled: rule?.enabled ?? true,
    sourceTypes,
    actions,
    extraKey,
    extraValue,
    windowMinutes: Number(def.window_minutes) || 10,
    cooldownMinutes: Number(def.cooldown_minutes) || 15,
    threshold: Number(def.threshold) || 5,
    groupBy: String(def.group_by || "user"),
    joinOn: String(def.join_on || "src_ip"),
    step1Min: Number((Array.isArray(def.steps) && (def.steps[0] as { min_count?: number })?.min_count) || 5),
    step2Kind: (Array.isArray(def.steps) && (def.steps[1] as { enrich?: unknown })?.enrich
      ? "enrich"
      : "match") as "match" | "enrich",
    step2Action: String(
      (Array.isArray(def.steps) &&
        asList((def.steps[1] as { match?: { action?: unknown } })?.match?.action)[0]) ||
        "login_success"
    ),
    step2Min: Number((Array.isArray(def.steps) && (def.steps[1] as { min_count?: number })?.min_count) || 1),
    enrichProviders: (() => {
      const en = Array.isArray(def.steps)
        ? (def.steps[1] as { enrich?: { providers?: string[] } })?.enrich
        : undefined;
      return en?.providers?.length ? en.providers.map(String) : ["vt", "abuseipdb"];
    })(),
  };
}

function toggleValue(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((x) => x !== value) : [...list, value];
}

export default function RuleEditorForm({ mode, initial, onSaved, onCancel }: Props) {
  const seed = useMemo(() => initialFromRule(initial), [initial]);
  const [id, setId] = useState(seed.id);
  const [name, setName] = useState(seed.name);
  const [title, setTitle] = useState(seed.title);
  const [description, setDescription] = useState(seed.description);
  const [threatBrief, setThreatBrief] = useState(seed.threatBrief);
  const [type, setType] = useState<"match" | "threshold" | "correlation">(seed.type);
  const [severity, setSeverity] = useState(seed.severity);
  const [enabled, setEnabled] = useState(seed.enabled);
  const [sourceTypes, setSourceTypes] = useState<string[]>(seed.sourceTypes);
  const [actions, setActions] = useState<string[]>(seed.actions);
  const [extraKey, setExtraKey] = useState(seed.extraKey);
  const [extraValue, setExtraValue] = useState(seed.extraValue);
  const [windowMinutes, setWindowMinutes] = useState(seed.windowMinutes);
  const [cooldownMinutes, setCooldownMinutes] = useState(seed.cooldownMinutes);
  const [threshold, setThreshold] = useState(seed.threshold);
  const [groupBy, setGroupBy] = useState(seed.groupBy);
  const [joinOn, setJoinOn] = useState(seed.joinOn);
  const [step1Min, setStep1Min] = useState(seed.step1Min);
  const [step2Kind, setStep2Kind] = useState<"match" | "enrich">(seed.step2Kind);
  const [step2Action, setStep2Action] = useState(seed.step2Action);
  const [step2Min, setStep2Min] = useState(seed.step2Min);
  const [enrichProviders, setEnrichProviders] = useState<string[]>(seed.enrichProviders);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const idReadOnly = mode === "edit";

  const submit = async () => {
    setBusy(true);
    setError(null);
    const match: Record<string, string | string[]> = {};
    const packedSrc = packFilter(sourceTypes);
    if (packedSrc !== undefined) match.source_type = packedSrc;
    const packedAct = packFilter(actions);
    if (packedAct !== undefined) match.action = packedAct;
    if (extraKey.trim() && extraValue.trim()) {
      match[extraKey.trim()] = extraValue.trim();
    }
    const payload: RuleCreatePayload = {
      id: id.trim().toLowerCase(),
      name: name.trim(),
      title: title.trim() || undefined,
      description: description.trim(),
      threat_brief: threatBrief.trim(),
      type,
      severity,
      enabled,
      window_minutes: windowMinutes,
      cooldown_minutes: cooldownMinutes,
      match,
    };
    if (type === "threshold") {
      payload.threshold = threshold;
      payload.group_by = groupBy;
    }
    if (type === "correlation") {
      const step1Match: Record<string, string | string[]> = { ...match };
      payload.join_on = joinOn;
      const step2 =
        step2Kind === "enrich"
          ? {
              enrich: {
                providers: enrichProviders.length ? enrichProviders : ["vt"],
                verdicts: ["malicious", "suspicious"],
                ioc_type: "ip",
              },
            }
          : {
              match: {
                source_type: packFilter(sourceTypes.length ? sourceTypes : ["windows"]) || "windows",
                action: step2Action,
              },
              min_count: step2Min,
            };
      payload.steps = [{ match: step1Match, min_count: step1Min }, step2];
    }
    try {
      if (mode === "edit") {
        await api.updateRule(payload.id, payload);
      } else {
        await api.createRule(payload);
      }
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rule-form">
      <h3 style={{ marginTop: 0 }}>
        {mode === "edit" ? "Modifica regola di detection" : "Crea regola di detection"}
      </h3>
      <p className="muted">
        Salva una regola YAML in <code className="mono">rules/</code>. Match su singolo evento,
        threshold sul conteggio, correlation per unire due segnali sullo stesso campo.
      </p>

      <div className="rule-form-grid">
        <div>
          <label htmlFor="rule-id">ID (slug)</label>
          <input
            id="rule-id"
            className="mono"
            value={id}
            onChange={(e) => setId(e.target.value)}
            placeholder="my-custom-rule"
            readOnly={idReadOnly}
            disabled={idReadOnly}
          />
        </div>
        <div>
          <label htmlFor="rule-name">Nome</label>
          <input
            id="rule-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="La mia regola"
          />
        </div>
        <div>
          <label htmlFor="rule-title">Titolo</label>
          <input
            id="rule-title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Titolo alert (opzionale)"
          />
        </div>
        <div>
          <label htmlFor="rule-sev">Severity</label>
          <select id="rule-sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
            <option value="info">info</option>
          </select>
        </div>
        <div>
          <label htmlFor="rule-type">
            Tipo{" "}
            <InfoTip
              text={
                type === "threshold"
                  ? "Scatta quando il conteggio di eventi matching per un gruppo raggiunge N nella finestra."
                  : type === "correlation"
                    ? "Unisce due match (es. spray + success) sullo stesso join_on nella finestra."
                    : "Scatta quando un singolo evento recente soddisfa tutti i filtri."
              }
            />
          </label>
          <select
            id="rule-type"
            value={type}
            onChange={(e) => setType(e.target.value as "match" | "threshold" | "correlation")}
          >
            <option value="match">match</option>
            <option value="threshold">threshold</option>
            <option value="correlation">correlation</option>
          </select>
          <p className="muted tip-inline">
            {type === "match"
              ? "Scatta quando un singolo evento recente soddisfa tutti i filtri."
              : type === "threshold"
                ? "Scatta quando il conteggio di eventi matching per un gruppo raggiunge N nella finestra."
                : "Unisce due segnali (step) sullo stesso campo entro la finestra."}
          </p>
        </div>
        <div className="rule-form-check">
          <label htmlFor="rule-enabled">
            <input
              id="rule-enabled"
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />{" "}
            Abilitata
          </label>
        </div>
      </div>

      <div className="rule-form-grid">
        <div style={{ gridColumn: "1 / -1" }}>
          <label htmlFor="rule-desc">Descrizione</label>
          <textarea
            id="rule-desc"
            rows={2}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
        </div>
        <div style={{ gridColumn: "1 / -1" }}>
          <label htmlFor="rule-brief">Threat brief</label>
          <textarea
            id="rule-brief"
            rows={3}
            value={threatBrief}
            onChange={(e) => setThreatBrief(e.target.value)}
            placeholder="Breve spiegazione della minaccia per l’analista…"
          />
        </div>
      </div>

      <h4 className="muted">Filtri match</h4>
      <div className="rule-form-grid">
        <div style={{ gridColumn: "1 / -1" }}>
          <label>
            source_type{" "}
            <InfoTip text="Seleziona una o più sorgenti log. Valori multipli = OR su questo campo." />
          </label>
          <div className="chip-multi">
            {SOURCE_OPTIONS.map((o) => (
              <button
                key={o}
                type="button"
                className={`chip-option${sourceTypes.includes(o) ? " selected" : ""}`}
                onClick={() => setSourceTypes((prev) => toggleValue(prev, o))}
              >
                {o}
              </button>
            ))}
          </div>
        </div>
        <div style={{ gridColumn: "1 / -1" }}>
          <label>
            action <InfoTip text="Seleziona una o più action. Passa il mouse sulle chip per il significato." />
          </label>
          <div className="chip-multi">
            {ACTION_OPTIONS.map((o) => (
              <button
                key={o.value}
                type="button"
                className={`chip-option${actions.includes(o.value) ? " selected" : ""}`}
                title={o.tip}
                onClick={() => setActions((prev) => toggleValue(prev, o.value))}
              >
                {o.value}
                <InfoTip text={o.tip} />
              </button>
            ))}
          </div>
        </div>
        <div>
          <label htmlFor="rule-ek">
            Campo extra{" "}
            <InfoTip text="Filtro opzionale su qualsiasi campo evento normalizzato (es. severity=high, host=win-dc01). Key = nome campo, Value = valore richiesto." />
          </label>
          <input
            id="rule-ek"
            className="mono"
            value={extraKey}
            onChange={(e) => setExtraKey(e.target.value)}
            placeholder="es. severity"
          />
        </div>
        <div>
          <label htmlFor="rule-ev">
            Valore extra{" "}
            <InfoTip text="Filtro opzionale su qualsiasi campo evento normalizzato (es. severity=high, host=win-dc01). Key = nome campo, Value = valore richiesto." />
          </label>
          <input
            id="rule-ev"
            className="mono"
            value={extraValue}
            onChange={(e) => setExtraValue(e.target.value)}
            placeholder="es. high"
          />
        </div>
      </div>

      {type === "threshold" && (
        <>
          <h4 className="muted">Impostazioni threshold</h4>
          <div className="rule-form-grid">
            <div>
              <label htmlFor="rule-win">Finestra (minuti)</label>
              <input
                id="rule-win"
                type="number"
                min={1}
                value={windowMinutes}
                onChange={(e) => setWindowMinutes(Number(e.target.value) || 1)}
              />
            </div>
            <div>
              <label htmlFor="rule-th">Soglia conteggio</label>
              <input
                id="rule-th"
                type="number"
                min={1}
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value) || 1)}
              />
            </div>
            <div>
              <label htmlFor="rule-gb">Group by</label>
              <select id="rule-gb" value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
                {GROUP_BY_OPTIONS.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="rule-cd">Cooldown (minuti)</label>
              <input
                id="rule-cd"
                type="number"
                min={1}
                value={cooldownMinutes}
                onChange={(e) => setCooldownMinutes(Number(e.target.value) || 1)}
              />
            </div>
          </div>
        </>
      )}

      {type === "correlation" && (
        <>
          <h4 className="muted">Impostazioni correlation</h4>
          <div className="rule-form-grid">
            <div>
              <label htmlFor="rule-join">Join on</label>
              <select id="rule-join" value={joinOn} onChange={(e) => setJoinOn(e.target.value)}>
                {GROUP_BY_OPTIONS.map((o) => (
                  <option key={o} value={o}>
                    {o}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="rule-s1min">Step 1 min_count</label>
              <input
                id="rule-s1min"
                type="number"
                min={1}
                value={step1Min}
                onChange={(e) => setStep1Min(Number(e.target.value) || 1)}
              />
            </div>
            <div>
              <label htmlFor="rule-s2kind">Step 2 tipo</label>
              <select
                id="rule-s2kind"
                value={step2Kind}
                onChange={(e) => setStep2Kind(e.target.value as "match" | "enrich")}
              >
                <option value="match">match (action)</option>
                <option value="enrich">enrich (verdict TI)</option>
              </select>
            </div>
            {step2Kind === "match" ? (
              <>
                <div>
                  <label htmlFor="rule-s2act">Step 2 action</label>
                  <select
                    id="rule-s2act"
                    value={step2Action}
                    onChange={(e) => setStep2Action(e.target.value)}
                  >
                    {ACTION_OPTIONS.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.value}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label htmlFor="rule-s2min">Step 2 min_count</label>
                  <input
                    id="rule-s2min"
                    type="number"
                    min={1}
                    value={step2Min}
                    onChange={(e) => setStep2Min(Number(e.target.value) || 1)}
                  />
                </div>
              </>
            ) : (
              <div style={{ gridColumn: "1 / -1" }}>
                <label>Enrich providers</label>
                <div className="chip-multi">
                  {["vt", "abuseipdb", "otx"].map((p) => (
                    <button
                      key={p}
                      type="button"
                      className={`chip-option${enrichProviders.includes(p) ? " selected" : ""}`}
                      onClick={() => setEnrichProviders((prev) => toggleValue(prev, p))}
                    >
                      {p}
                    </button>
                  ))}
                </div>
              </div>
            )}
            <div>
              <label htmlFor="rule-win-c">Finestra (minuti)</label>
              <input
                id="rule-win-c"
                type="number"
                min={1}
                value={windowMinutes}
                onChange={(e) => setWindowMinutes(Number(e.target.value) || 1)}
              />
            </div>
            <div>
              <label htmlFor="rule-cd-c">Cooldown (minuti)</label>
              <input
                id="rule-cd-c"
                type="number"
                min={1}
                value={cooldownMinutes}
                onChange={(e) => setCooldownMinutes(Number(e.target.value) || 1)}
              />
            </div>
          </div>
          <p className="muted">
            Step 1 usa i filtri match sopra. Step 2:{" "}
            {step2Kind === "enrich"
              ? `enrich verdict malicious/suspicious su ${joinOn} (${enrichProviders.join(", ") || "vt"})`
              : `match action ${step2Action} sullo stesso ${joinOn}`}
            .
          </p>
        </>
      )}

      {type === "match" && (
        <div className="rule-form-grid">
          <div>
            <label htmlFor="rule-win-m">Finestra (minuti)</label>
            <input
              id="rule-win-m"
              type="number"
              min={1}
              value={windowMinutes}
              onChange={(e) => setWindowMinutes(Number(e.target.value) || 1)}
            />
          </div>
          <div>
            <label htmlFor="rule-cd-m">Cooldown (minuti)</label>
            <input
              id="rule-cd-m"
              type="number"
              min={1}
              value={cooldownMinutes}
              onChange={(e) => setCooldownMinutes(Number(e.target.value) || 1)}
            />
          </div>
        </div>
      )}

      {error && <p className="error">{error}</p>}

      <div className="row" style={{ marginTop: "0.75rem", gap: "0.5rem" }}>
        <button className="primary" type="button" disabled={busy} onClick={() => void submit()}>
          {busy ? "Salvataggio…" : mode === "edit" ? "Aggiorna regola" : "Salva regola"}
        </button>
        <button className="ghost" type="button" disabled={busy} onClick={onCancel}>
          Annulla
        </button>
      </div>
    </div>
  );
}
