# DarkGreen SIEM

[![License: MIT](https://img.shields.io/badge/License-MIT-3ddc97.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](services/api)
[![React](https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=black)](web)

**Demo SIEM multi-fonte** in un comando: ingest, normalizzazione ECS-lite, ricerca da analista, dashboard e detection YAML con workflow alert e link VirusTotal sugli IOC.

Parte del portfolio [DarkGreen Projects](https://github.com/DarkGreen-projects).

![Dashboard lab DarkGreen SIEM](docs/assets/dashboard-lab.png)

## Cosa fa

| Area | Dettaglio |
|------|-----------|
| **Ingest** | HTTP `/api/ingest`, syslog UDP `5140`, seed `samples/`; traffico continuo solo con `--profile demo` |
| **Normalizzazione** | FortiGate syslog KV + windows / cloud_auth / **siem_export Cynet** (process, hash, MITRE labels) |
| **Auth / RBAC** | Soft multi-tenant + ruoli admin/analyst/viewer/ingest |
| **TLS / HA** | Overlay Compose TLS + 2 API dietro nginx |
| **Ricerca** | Query `field:value` + free-text; filtro **Stato** alert; guida `?` + export CSV risultati |
| **Dashboard** | EPS, timeline, health, filtri stato/MITRE/SLA, export CSV (polling lean) |
| **Turno** | Workbench coda, briefing, **alert collegati**, hotkeys, checklist, pivot |
| **Setup lab** | Retention, silence, purge, TI, webhook, **SLA**, **RAG**, **Alert graph**, **Copilot** |
| **Detection** | YAML match / threshold / correlation; dry-run; `labels.*`; fail-soft sotto stress |
| **Alert workflow** | Disposition/note; MITRE; dedup; SLA; triage anti-noise; fingerprint; campaign; bulk-close; Memory RAG; graph; Copilot audit |
| **Sicurezza lab** | Secret strict, syslog secret obbligatorio, rate buckets Postgres, egress SSRF, redazione LLM |
| **Sorgenti / host** | **Installer EXE** + agent lean; [setup](docs/setup-guide.md) · [collectors](docs/collectors-windows-syslog.md) |
| **VirusTotal / TI** | VT, AbuseIPDB, OTX in Setup + verdict in cache |

Documentazione: [docs/README.md](docs/README.md) · Setup: [docs/setup-guide.md](docs/setup-guide.md) · Sicurezza: [docs/security.md](docs/security.md) · Architettura: [docs/architecture.md](docs/architecture.md)

## Avvio rapido

Guida completa: [docs/setup-guide.md](docs/setup-guide.md).

```bash
cp .env.example .env   # ruota i secret
docker compose up --build
```

Default **lean**: niente `log-generator`, limiti memoria/CPU, `RULE_INTERVAL_SEC=30`. Traffico demo:

```bash
docker compose --profile demo up --build
```

Apri **http://localhost:8080** e accedi con le credenziali lab (default `analyst` / `darkgreen`).

| Endpoint | URL |
|----------|-----|
| UI | http://localhost:8080 |
| API docs | http://localhost:8000/docs |
| Syslog UDP | `localhost:5140` |

Stop: `Ctrl+C` oppure `docker compose down`.

### Installer host (EXE)

Da **Sorgenti** scarica `connect-installer.zip` → sul PC `DarkGreen-Setup.cmd` (o `dist/DarkGreen-Setup.exe`). Passi: compatibilità PC, rete, health, heartbeat, agent/NXLog.

### Auth lab (abilitata di default)

In Compose l’API richiede un Bearer token su `/api/*` (eccetto `POST /api/auth/login` e `/health`):

- **UI**: login username/password → token HMAC (TTL ~12h) in `localStorage`
- **Utenti bootstrap**: `analyst` / `darkgreen` (ruolo **admin**), `viewer` / `viewer` (solo lettura)
- **Ruoli**: `admin` (setup/purge), `analyst` (alert/regole/enrich), `viewer` (GET), `ingest` (machine token)
- **Multi-tenant soft**: colonna `tenant_id` (default `lab`); ogni utente vede solo il proprio tenant
- **Ingest / log-generator**: header `Authorization: Bearer <SIEM_API_TOKEN>` (ruolo ingest)
- **Playground aperto**: `AUTH_ENABLED=false` richiede anche `ALLOW_INSECURE_NO_AUTH=true` (anti-misconfig)
- Syslog UDP: `SYSLOG_SHARED_SECRET` obbligatorio (prefisso messaggio), max 64 KiB/datagram, rate limit per host, compare timing-safe
- Rate limit login/ingest con bucket Postgres (HA-friendly); `TRUST_X_FORWARDED_FOR` solo dietro proxy fidato
- Dettaglio hardening: [docs/security.md](docs/security.md)

### Lean ops e performance

- **Compose lean di default**: niente `log-generator` (usa `--profile demo`); `mem_limit` / `cpus` su postgres/api/web/generator; `RULE_INTERVAL_SEC=30`
- **UI**: polling con pausa tab nascosta; niente doppio `/api/stats` sulla dashboard
- **API**: timeline stats a query unica; liste alert senza N+1 commenti/audit
- **`events.raw`**: zlib sopra ~512 byte (`ZLIB1:`); log API rotanti; Docker log `max-size=10m`
- Dettaglio avvio: [docs/setup-guide.md](docs/setup-guide.md) e [`.env.example`](.env.example)

### TLS (lab HTTPS)

```bash
# genera cert self-signed in deploy/certs/
bash scripts/gen-tls.sh
# oppure: powershell -File scripts/gen-tls.ps1

docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
```

UI HTTPS: **https://localhost:8443** (warning browser sul self-signed). L’API non e pubblica su `:8000`. Syslog UDP resta plaintext su `5140`.

### HA lab (2 API)

```bash
docker compose -f docker-compose.yml -f docker-compose.ha.yml up --build
```

Nginx bilancia `api` + `api-b`. Postgres resta single-node (failover DB fuori scope). Override Setup (key TI, retention) sono in tabella `lab_settings` condivisa.

### Setup lab (retention e silence)

Tab **Setup** in UI (o env Compose):

| Env | Default | Ruolo |
|-----|---------|--------|
| `RETENTION_DAYS` | `7` | Cancella eventi più vecchi di N giorni (`0` = off) |
| `HEALTH_STALE_MINUTES` | `5` | Soglia health `stale` |
| `HEALTH_SILENT_MINUTES` | `30` | Soglia health `silent` + cooldown alert ops |
| `SILENCE_ALERTS_ENABLED` | `true` | Alert `source-silent-*` se una sorgente tace |
| `PURGE_INTERVAL_SEC` | `300` | Intervallo job purge/silence |

API: `GET/PATCH /api/setup`, `POST /api/admin/purge`, `GET /api/alerts/export.csv`.

### VirusTotal enrichment

Imposta le API key in **Setup → Enrichment API** (o env Compose). Provider supportati:

| Env / Setup | Provider |
|-------------|----------|
| `VT_API_KEY` | VirusTotal |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |
| `OTX_API_KEY` | AlienVault OTX |
| `VT_CACHE_TTL_HOURS` | TTL cache (default 24) |

Senza key restano i link GUI. Con key: `GET /api/enrich` (multi) e `GET /api/enrich/vt`. Le regole `correlation` possono avere uno step `enrich` (vedi `rules/spray-then-malicious-ip.yml`).

### Notifiche Slack / Teams

Webhook HTTPS su alert **aperti** con severity >= soglia (default `high`). Solo al primo create, non a ogni merge.

| Env / Setup | Default | Ruolo |
|-------------|---------|--------|
| `NOTIFY_WEBHOOK_URL` | (vuoto) | Incoming Webhook URL |
| `NOTIFY_FORMAT` | `slack` | `slack` o `teams` |
| `NOTIFY_MIN_SEVERITY` | `high` | Soglia minima |

Configurabile anche da **Setup → Notifiche**.

### SLA alert (ack + close)

Minuti massimi per severity, configurabili in **Setup → SLA alert** (o env JSON):

| Env | Esempio |
|-----|---------|
| `SLA_ACK_MINUTES` | `{"critical":15,"high":30,"medium":240,"low":1440}` |
| `SLA_CLOSE_MINUTES` | `{"critical":120,"high":480,"medium":1440,"low":10080}` |

- **Ack**: da creazione fino a uscita da `open` (`acked` / `in_progress`)
- **Close**: da creazione fino a `closed`
- Stati computed: `ok`, `at_risk` (>80%), `breached`, `met`, `na` (se minuti = 0)
- Filtro UI/API: `GET /api/alerts?sla=breached`

### Triage disposition e learning suggestivo

Alla chiusura di un alert sono obbligatori:
- **disposition**: `true_positive` | `false_positive` | `benign` | `duplicate` | `tuning_needed`
- **closure_note** (min 10 caratteri)

Lo score `risk_score` / `noise_hint` usa severity, MITRE, occurrences e priors dalle chiusure passate stessa regola+entity. Backfill allo startup/merge per alert legacy; `fingerprint_hash` stabile. Solo suggerimenti (badge + alert simili): **nessun blocco automatico**. Setup: toggle scoring + finestra giorni.

API: `GET /api/alerts/{id}/similar`, filtri `?disposition=` / `?noise_hint=`, bulk `POST /api/alerts/bulk-close`.

### Workbench Turno + Copilot + Alert Memory RAG

Tab **Turno**: coda `open`/`in_progress` ordinata (SLA breached > at_risk > likely_signal > severity > età), `campaign_id` per cluster grafo, lane rumore deprioritizzata, briefing locale, checklist in `sessionStorage`, pivot 1-click verso Ricerca. Dashboard con offset / load more.

Hotkeys (Workbench e card in focus): `j`/`k` navigazione, `a` ack, `i` in corso, `c` close dialog, `/` pivot, `?` aiuto.

**Alert Memory RAG** (portatile): a ogni chiusura l’alert entra in `alert_memory` (testo + FTS Postgres, sanitize). Suggest **local-first** (priors forti → zero LLM), altrimenti mini-LLM con fingerprint redatto. Feedback thumbs → boost retrieve. Export JSON da Setup.

**Alert graph**: a create/merge normalizza `entity_keys` e scrive archi in `alert_links` (dedupe anti-UniqueViolation). Brief e Copilot usano fingerprint + vicini (`related_alert_ids` filtrati). Audit `CopilotAudit`.

| Endpoint | Ruolo |
|----------|--------|
| `GET /api/alerts/queue` | Coda prioritizzata + `campaign_id` |
| `GET /api/alerts/{id}/brief` | Briefing + fingerprint + connected + casi |
| `GET /api/alerts/{id}/links` | Vicini grafo |
| `POST /api/alerts/{id}/copilot-suggest` | Suggest `local_memory` / `llm_rag` (fail soft + audit) |
| `POST /api/alerts/bulk-close` | Chiusura massiva FP / rumore |
| `GET /api/memory/stats` | Contatori memoria tenant |
| `GET /api/memory/export` | Export JSON (admin) |

Setup: toggle RAG + `rag_top_k`; Alert graph (`graph_enabled`, `graph_window_minutes`, `graph_min_history`); Copilot LLM opzionale (`LLM_*`).

### Connector host (installer EXE + agent lean)

Download da UI Sorgenti (o API):
- `GET /api/tools/connect-installer.zip` - WinForms/EXE wizard (compat, rete, health, auth, collezione) + script Linux
- `GET /api/tools/windows-agent.zip` - agent Security Event Log (default 60s) → `/api/ingest`
- `GET /api/tools/connect-wizard.zip` - alias legacy dello stesso pack installer

Canali ingest: `connect-wizard`, `windows-agent`. Build EXE: `tools/connect-installer/build_exe.ps1`.

### Cynet / siem_export, dry-run, MITRE, dedup

- **Cynet**: `normalize_siem_export` mappa process/hash/MITRE in `labels.*`; regole seed `cynet-malware-hash.yml`, `cynet-suspicious-process.yml`. Match YAML supporta `labels.hash`, `labels.process`, ecc.
- **Dry-run**: `POST /api/rules/dry-run` con array JSON o linee syslog; UI Detection → pannello Dry-run (nessuna scrittura alert).
- **MITRE**: campo `mitre` su YAML/regole; colonna `alerts.mitre`; badge e filtro `?mitre=` su Dashboard/Detection.
- **Dedup**: stessa `rule_id` + entity (`src_ip`/`host`/`user` o join_key) entro `cooldown_minutes` → merge (`evidence.occurrences`), non nuovo alert.

### Collectors Windows / syslog

Guida NXLog / rsyslog verso UDP 5140: [docs/collectors-windows-syslog.md](docs/collectors-windows-syslog.md).

## Query di esempio

```
action:deny
user:j.doe
source_type:windows AND action:login_failed
malware
src_ip:203.0.113.45
```

## Architettura

Pipeline demo ispirata a flussi collect → normalize → search → detect (nessuna affiliazione vendor). Dettaglio: [docs/architecture.md](docs/architecture.md).

![Pipeline DarkGreen SIEM](docs/assets/pipeline-overview.svg)

```text
samples / syslog / HTTP  →  FastAPI + normalizers  →  Postgres
                                      ↓
                     YAML rules → alerts → memory + graph links
                                      ↓
        React UI (Dashboard · Turno · Ricerca · Sorgenti · Detection · Setup)
```

### Workbench e alert graph

![Workbench Turno](docs/assets/workbench-turno.svg)

![Alert graph + LLM context](docs/assets/alert-graph-flow.svg)

## Struttura repository

```text
darkgreen-siem/
├── docker-compose.yml
├── .github/workflows/     # ci.yml (pytest) + stress-lab.yml
├── rules/                 # regole detection YAML
├── samples/               # log multi-vendor + lab_assets.json
├── scripts/               # stress populate/measure, TLS helpers
├── services/
│   ├── api/               # FastAPI, syslog, regole, RAG, graph, copilot, triage
│   ├── normalizers/       # parser ECS-lite
│   └── log-generator/     # traffico demo (profile demo)
├── tools/                 # connect-installer (EXE) + windows-agent
├── web/                   # UI React + Vite (+ nginx)
├── docs/                  # setup, security, architettura, collectors, lab-reports
└── tests/                 # pytest + lab_proof
```

## Sviluppo locale

```bash
pip install -r services/api/requirements.txt
pytest -q

cd web && npm install && npm run dev
```

L’API richiede Postgres (`DATABASE_URL`). Il percorso più semplice resta `docker compose up`.

### Lab proof + stress

A ogni upgrade:

```bash
python -m tests.lab_proof
pytest -q
```

Stress live (lab Docker su):

```bash
python scripts/lab_stress_populate.py --events 1000 --profile mix --login --seed-dispositions 10
python scripts/lab_stress_measure.py --login
```

Output in **[docs/lab-reports/latest/](docs/lab-reports/latest/)**: `report.md` / charts (lab_proof) e `stress-report.md` / `stress-metrics.json`.  
Indice: [docs/lab-reports/README.md](docs/lab-reports/README.md). CI: pytest + gate stress.

## Novita lab (2026-11-27)

Hardening security, triage anti-noise, Copilot audit, stress harness 1k/5k GREEN. Report: [docs/lab-reports/latest/stress-report.md](docs/lab-reports/latest/stress-report.md). Commit `84cebe9`.

### Bug e falle corrette in questa versione

Dettaglio completo (sintomo, causa, perche, fix) nelle Issues chiuse con label `fixed` + `lab`:

| Issue | Titolo |
|-------|--------|
| [#1](https://github.com/DarkGreen-projects/darkgreen-siem/issues/1) | `GET /api/sources` 500: `ingest_stats` senza `tenant_id` |
| [#2](https://github.com/DarkGreen-projects/darkgreen-siem/issues/2) | `acked_at` assente dagli ALTER (DB legacy) |
| [#3](https://github.com/DarkGreen-projects/darkgreen-siem/issues/3) | Download tool pack 404 (tools non in immagine API) |
| [#4](https://github.com/DarkGreen-projects/darkgreen-siem/issues/4) | Build web fallita: step `enrich` non tipizzato |
| [#5](https://github.com/DarkGreen-projects/darkgreen-siem/issues/5) | Bottoni UI bianchi (Salva / Conferma / installer) |
| [#6](https://github.com/DarkGreen-projects/darkgreen-siem/issues/6) | Filtri stato: allineamento MITRE/SLA |
| [#7](https://github.com/DarkGreen-projects/darkgreen-siem/issues/7) | Ricerca: Stato, wiki query, export CSV |
| [#8](https://github.com/DarkGreen-projects/darkgreen-siem/issues/8) | Syslog UDP: secret vuoto, ingest sync, compare non timing-safe |
| [#9](https://github.com/DarkGreen-projects/darkgreen-siem/issues/9) | Compose HA/TLS: secret hardcodati e porta API esposta |
| [#10](https://github.com/DarkGreen-projects/darkgreen-siem/issues/10) | Connect installer: token ingest in chiaro in Scheduled Task |
| [#11](https://github.com/DarkGreen-projects/darkgreen-siem/issues/11) | Egress SSRF CGNAT/metadata e rate limit spoofabile via XFF |
| [#12](https://github.com/DarkGreen-projects/darkgreen-siem/issues/12) | Detection: threshold SQL ignorava `labels.*`; YAML non validato |
| [#13](https://github.com/DarkGreen-projects/darkgreen-siem/issues/13) | Auth/session: pipe nello username; PBKDF2 debole; EXP_KEY |
| [#14](https://github.com/DarkGreen-projects/darkgreen-siem/issues/14) | Copilot/notify: `int()` su related ids; httpx bypass pin egress |
| [#15](https://github.com/DarkGreen-projects/darkgreen-siem/issues/15) | UI: logout su errore me(); CSV/Search/purge/download |
| [#16](https://github.com/DarkGreen-projects/darkgreen-siem/issues/16) | API root e mask chiavi TI con coda in chiaro |
| [#17](https://github.com/DarkGreen-projects/darkgreen-siem/issues/17) | Hardening High: secret deboli startup + syslog secret obbligatorio |
| [#18](https://github.com/DarkGreen-projects/darkgreen-siem/issues/18) | Rate limit spoofabile e bucket solo in-memory |
| [#19](https://github.com/DarkGreen-projects/darkgreen-siem/issues/19) | Redazione LLM, sanitize RAG e audit Copilot |
| [#20](https://github.com/DarkGreen-projects/darkgreen-siem/issues/20) | Triage: backfill score/noise_hint + fingerprint hash |
| [#21](https://github.com/DarkGreen-projects/darkgreen-siem/issues/21) | Workbench/Dashboard: campaign_id e paginazione offset |
| [#22](https://github.com/DarkGreen-projects/darkgreen-siem/issues/22) | Detection: correlazione spray-success e asset lab |
| [#23](https://github.com/DarkGreen-projects/darkgreen-siem/issues/23) | Alert graph: UniqueViolation su `alert_links` |
| [#24](https://github.com/DarkGreen-projects/darkgreen-siem/issues/24) | Lab stress harness e gate CI (pytest + stress-lab) |

Lista: [Issues chiuse (bug fixed)](https://github.com/DarkGreen-projects/darkgreen-siem/issues?q=is%3Aissue+label%3Afixed+is%3Aclosed).

## Ecosistema

| Progetto | Ruolo |
|----------|--------|
| [soc-automation-hub](https://github.com/DarkGreen-projects/soc-automation-hub) | Demo web SOC (VT, MITRE, decoder, pivot, bulk IOC) |
| [Decoder_SIEMjoson](https://github.com/DarkGreen-projects/Decoder_SIEMjoson) | CLI/GUI Python: parse SIEM + OSINT |

## Dati e sicurezza

- Sample con IP **RFC5737** e host/utenti fittizi.
- **Auth lab abilitata di default** (login + `SIEM_API_TOKEN`); resta un lab su rete privata, non esporre su Internet.
- Copia [`.env.example`](.env.example), ruota `AUTH_SECRET` / `SIEM_API_TOKEN` / password demo; con `STRICT_SECRETS=true` i default deboli bloccano l’avvio.
- Login rate-limited (429); OpenAPI disattivabile (`DISABLE_OPENAPI=true`); commenti firmati dal principal (no spoof author).
- Syslog UDP: size/rate limit + `SYSLOG_SHARED_SECRET` opzionale (prefisso `SECRET ` o `#dg-token=SECRET `). Non pubblicare `5140/udp` senza secret.
- Egress SSRF: notify/LLM solo `https` (o http se `ALLOW_INSECURE_WEBHOOKS`), blocco host privati/metadata, allowlist `EGRESS_HOST_ALLOWLIST`.
- Segreti Setup (API key, webhook, LLM) cifrati a riposo (Fernet da `AUTH_SECRET`); mask stretta in UI.
- Nginx: CSP + frame deny; API: header sicurezza + `Cache-Control: no-store` su `/api`.
- Connect wizard Linux: token solo da env/prompt (mai argv).

## Licenza

MIT - vedi [LICENSE](LICENSE).
