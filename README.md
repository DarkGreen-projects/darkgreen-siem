# DarkGreen SIEM

[![License: MIT](https://img.shields.io/badge/License-MIT-3ddc97.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](services/api)
[![React](https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=black)](web)

**Demo SIEM multi-fonte** in un comando: ingest, normalizzazione ECS-lite, ricerca da analista, dashboard e detection YAML — con workflow alert e link VirusTotal sugli IOC.

Parte del portfolio [DarkGreen Projects](https://github.com/DarkGreen-projects).

<img width="1364" height="1072" alt="image" src="https://github.com/user-attachments/assets/0ef56274-fa05-4a70-9a94-1c8aaf78e3c6" />

## Cosa fa

| Area | Dettaglio |
|------|-----------|
| **Ingest** | HTTP `/api/ingest`, syslog UDP `5140`, seed da `samples/`, traffico continuo via `log-generator` |
| **Normalizzazione** | FortiGate syslog KV + windows / cloud_auth / **siem_export Cynet** (process, hash, MITRE labels) |
| **Auth / RBAC** | Soft multi-tenant + ruoli admin/analyst/viewer/ingest |
| **TLS / HA** | Overlay Compose TLS + 2 API dietro nginx (vedi README) |
| **Ricerca** | Query `field:value` + free-text; **ricerche predefinite** (login_failed, deny, audit_cleared, malware…) |
| **Dashboard** | EPS, timeline per sorgente, health strip, filtri stato/MITRE, **export CSV** |
| **Setup lab** | Retention, silence, purge, **enrichment keys**, **webhook Slack/Teams** |
| **Detection** | YAML match / threshold / correlation; CRUD UI; **dry-run** bench; match `labels.*` |
| **Alert workflow** | Stati + commenti + audit; **MITRE** su regole/alert; **dedup/merge** rule+entity in cooldown |
| **Sorgenti** | Canali live + onboarding agent; alert ops se silenziose; [guida collectors](docs/collectors-windows-syslog.md) |
| **VirusTotal / TI** | Key in Setup (VT, AbuseIPDB, OTX) + verdict in cache sulle card; correlazione enrich |

## Avvio rapido

```bash
docker compose up --build
```

Apri **http://localhost:8080** e accedi con le credenziali lab (default `analyst` / `darkgreen`).

| Endpoint | URL |
|----------|-----|
| UI | http://localhost:8080 |
| API docs | http://localhost:8000/docs |
| Syslog UDP | `localhost:5140` |

Stop: `Ctrl+C` oppure `docker compose down`.

### Auth lab (abilitata di default)

In Compose l’API richiede un Bearer token su `/api/*` (eccetto `POST /api/auth/login` e `/health`):

- **UI**: login username/password → token HMAC (TTL ~12h) in `localStorage`
- **Utenti bootstrap**: `analyst` / `darkgreen` (ruolo **admin**), `viewer` / `viewer` (solo lettura)
- **Ruoli**: `admin` (setup/purge), `analyst` (alert/regole/enrich), `viewer` (GET), `ingest` (machine token)
- **Multi-tenant soft**: colonna `tenant_id` (default `lab`); ogni utente vede solo il proprio tenant
- **Ingest / log-generator**: header `Authorization: Bearer <SIEM_API_TOKEN>` (ruolo ingest)
- **Playground aperto**: `AUTH_ENABLED=false` richiede anche `ALLOW_INSECURE_NO_AUTH=true` (anti-misconfig)
- Syslog UDP: max 64 KiB/datagram + rate limit per host (200/s)

### Compressione e performance

- **`events.raw`**: zlib automatico sopra ~512 byte (`ZLIB1:` prefix); decompress in API/UI. Linee corte restano plain per ricerca `ILIKE`.
- **Log API**: `logs/api.log` con rotazione 2MB × 5, backup `.gz` (`LOG_DIR`)
- **Docker**: driver `json-file` `max-size=10m` / `max-file=3` su tutti i servizi

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

```text
samples / syslog / HTTP  →  FastAPI + normalizers  →  Postgres
                                      ↓
                              YAML rule engine → alerts
                                      ↓
                    React UI (Dashboard · Ricerca · Sorgenti · Detection)
```

## Struttura repository

```text
darkgreen-siem/
├── docker-compose.yml
├── rules/                 # regole detection YAML
├── samples/               # log multi-vendor fittizi
├── services/
│   ├── api/               # FastAPI, syslog, regole, validazione input
│   ├── normalizers/       # parser ECS-lite
│   └── log-generator/     # traffico demo continuo
├── web/                   # UI React + Vite (+ nginx)
├── docs/                  # architettura + asset
└── tests/                 # pytest
```

## Sviluppo locale

```bash
pip install -r services/api/requirements.txt
pytest -q

cd web && npm install && npm run dev
```

L’API richiede Postgres (`DATABASE_URL`). Il percorso più semplice resta `docker compose up`.

## Ecosistema

| Progetto | Ruolo |
|----------|--------|
| [soc-automation-hub](https://github.com/DarkGreen-projects/soc-automation-hub) | Demo web SOC (VT, MITRE, decoder, pivot, bulk IOC) |
| [Decoder_SIEMjoson](https://github.com/DarkGreen-projects/Decoder_SIEMjoson) | CLI/GUI Python: parse SIEM + OSINT |

## Dati e sicurezza

- Sample con IP **RFC5737** e host/utenti fittizi.
- **Auth lab abilitata di default** (login + `SIEM_API_TOKEN`); resta un lab locale, non esporre su Internet senza hardening.
- Limiti di input, allowlist, escape LIKE, header di sicurezza base su nginx.
- Non collegare stream di produzione senza hardening ulteriore (TLS, retention, RBAC - fuori scope v0.1).

## Licenza

MIT — vedi [LICENSE](LICENSE).
