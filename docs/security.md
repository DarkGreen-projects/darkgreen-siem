# Sicurezza lab (hardening)

DarkGreen SIEM resta una **demo di portfolio**, non un prodotto production-hardened. Questa pagina documenta i controlli presenti dopo il push `84cebe9` (issue [#8](https://github.com/DarkGreen-projects/darkgreen-siem/issues/8)–[#24](https://github.com/DarkGreen-projects/darkgreen-siem/issues/24)).

## Checklist avvio

1. Copia `.env.example` → `.env` e **ruota** tutti i secret.
2. Imposta almeno: `AUTH_SECRET`, `SIEM_API_TOKEN`, `DEMO_PASSWORD`, `SYSLOG_SHARED_SECRET`, password in `DATABASE_URL`.
3. Fuori dal lab privato: `STRICT_SECRETS=true` (rifiuta secret deboli / default noti).
4. Lascia `TRUST_X_FORWARDED_FOR=false` se non c’è un reverse proxy fidato davanti all’API.
5. Non pubblicare UDP `5140` su Internet.

## Secret e auth

| Controllo | Comportamento |
|-----------|----------------|
| `STRICT_SECRETS` | Blocca secret troppo corti / default noti (auth, demo password, syslog, DB) |
| `AUTH_ENABLED=false` | Richiede anche `ALLOW_INSECURE_NO_AUTH=true` |
| Session token | HMAC + `EXP_KEY`; username senza pipe; PBKDF2 rafforzato |
| Machine token | Solo ruolo `ingest`; rate limit per IP/machine |
| OpenAPI | `DISABLE_OPENAPI=true` nasconde `/docs` |

Dettaglio env: [../.env.example](../.env.example).

## Syslog UDP

- `SYSLOG_SHARED_SECRET` **obbligatorio**: se vuoto, ogni datagramma viene scartato.
- Prefissi accettati: `SECRET <payload>` oppure `#dg-token=SECRET <payload>` (anche dopo PRI `<nn>`).
- Compare **timing-safe**; size cap; rate limit per host sorgente.
- Ingest async (niente blocco del event loop sul parse).

Vedi anche [collectors-windows-syslog.md](collectors-windows-syslog.md).

## Rate limit e proxy

- Login / ingest / machine: bucket in-process + persistenza Postgres (`rate_buckets`) per HA multi-replica.
- Client IP: socket peer di default. `TRUST_X_FORWARDED_FOR=true` solo dietro nginx/proxy che imposta `X-Real-IP` / `X-Forwarded-For`.
- Overlay HA/TLS: secret non hardcodati su `api-b`; con TLS la porta API grezza non resta esposta.

## Egress (notify / LLM)

- `url_safety`: solo HTTPS, blocco privati / metadata / CGNAT, allowlist opzionale `EGRESS_HOST_ALLOWLIST`.
- Notify e Copilot LLM passano dal client pin egress (niente `httpx` diretto).
- `ALLOW_INSECURE_WEBHOOKS` solo per lab esplicitamente insecure.

## TI keys e storage

- Chiavi VT / AbuseIPDB / OTX in Setup: cifrate Fernet (`enc:`) derivate da `AUTH_SECRET`.
- Maschera in API/UI; rotate-sealed con warning se XFF non fidato.
- `events.raw` compresso zlib sopra ~512 byte.

## Copilot / RAG

- Suggest **solo consiglio** (nessuna chiusura automatica).
- Redazione secret/PII su prompt e output LLM.
- Sanitize chunk RAG in ingresso memoria.
- Audit trail `CopilotAudit`; feedback thumbs influenza boost retrieve.
- `related_alert_ids` filtrati al contesto fingerprint/grafo.

## Installer host

- Token ingest **non** passato in chiaro negli argomenti Scheduled Task (store protetto / env task).
- Download zip richiede sessione auth valida.

## CI e stress

- Workflow [ci.yml](../.github/workflows/ci.yml): `pytest` su push/PR.
- Workflow [stress-lab.yml](../.github/workflows/stress-lab.yml): gate p95 su mix 1k (schedule + manuale).
- Report locale: [lab-reports/latest/stress-report.md](lab-reports/latest/stress-report.md).

## Cosa non copre questo lab

- Postgres HA / backup / DR
- mTLS client verso API
- Hardening OS del host Docker
- Policy retention legale / GDPR operational

Per il flusso componenti: [architecture.md](architecture.md). Per avvio: [setup-guide.md](setup-guide.md).
