# DarkGreen SIEM

[![License: MIT](https://img.shields.io/badge/License-MIT-3ddc97.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](services/api)
[![React](https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=black)](web)

**Demo SIEM multi-fonte** in un comando: ingest, normalizzazione ECS-lite, ricerca da analista, dashboard e detection YAML — con workflow alert e link VirusTotal sugli IOC.

Parte del portfolio [DarkGreen Projects](https://github.com/DarkGreen-projects).

![Anteprima dashboard](docs/assets/dashboard-preview.svg)

## Cosa fa

| Area | Dettaglio |
|------|-----------|
| **Ingest** | HTTP `/api/ingest`, syslog UDP `5140`, seed da `samples/`, traffico continuo via `log-generator` |
| **Normalizzazione** | 4 `source_type` (`firewall`, `windows`, `cloud_auth`, `siem_export`) → schema ECS-lite |
| **Ricerca** | Query `field:value` + free-text; hit anche su alert/commenti |
| **Dashboard** | EPS, timeline per sorgente, health strip, alert recenti |
| **Detection** | Regole YAML match/threshold; CRUD da UI (modal); enable/disable |
| **Alert workflow** | Stati open / ack / in corso / chiuso + commenti |
| **Sorgenti** | Canali live + onboarding agent (UI demo, download barrati) |
| **VirusTotal** | Link GUI diretti su IP / URL / domain estratti da evidence e testo alert |

## Avvio rapido

```bash
docker compose up --build
```

Apri **http://localhost:8080**

| Endpoint | URL |
|----------|-----|
| UI | http://localhost:8080 |
| API docs | http://localhost:8000/docs |
| Syslog UDP | `localhost:5140` |

Stop: `Ctrl+C` oppure `docker compose down`.

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
- **Demo senza autenticazione** — non esporre API/UI su Internet; lab locale one-click.
- Limiti di input, allowlist, escape LIKE, header di sicurezza base su nginx.
- Non collegare stream di produzione senza hardening (auth, TLS, retention, RBAC — fuori scope v0.1).

## Licenza

MIT — vedi [LICENSE](LICENSE).
