# DarkGreen SIEM

[![License: MIT](https://img.shields.io/badge/License-MIT-3ddc97.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](services/api)
[![React](https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=black)](web)

**Demo SIEM multi-fonte** — raccoglie log da firewall, Windows, identity cloud ed export EDR/SIEM, li normalizza in uno schema unico, permette ricerca da analista e attiva regole di detection in YAML.

Parte del portfolio [DarkGreen Projects](https://github.com/DarkGreen-projects).

![Anteprima dashboard](docs/assets/dashboard-preview.svg)

## Perché esiste

I SIEM commerciali (pipeline in stile LogPoint: collect → normalize → search → alert) sono difficili da mostrare in un curriculum. Questo repo è un **lab autocontenuto** avviabile con un comando — utile, visuale e trasparente sul fatto di essere una demo (non un SIEM di produzione, non affiliato a LogPoint/Guardsix).

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

Stop con `Ctrl+C` / `docker compose down`.

## Cosa include

1. **Ingest** — HTTP `/api/ingest`, syslog UDP, seed all’avvio da `samples/`
2. **Normalizzazione** — 4 `source_type` → campi ECS-lite (`src_ip`, `user`, `action`, `severity`, …)
3. **Ricerca** — `src_ip:203.0.113.45 AND action:deny` più free-text
4. **Dashboard** — EPS, timeline volumi, breakdown, alert recenti
5. **Detection** — regole YAML (match + threshold) con workflow alert (ack / commenti)
6. **Traffico live** — `log-generator` continua a inviare eventi multi-fonte

## Query di esempio

```
action:deny
user:j.doe
source_type:windows AND action:login_failed
malware
```

## Architettura

Vedi [docs/architecture.md](docs/architecture.md).

```text
samples / syslog / HTTP  →  FastAPI normalizers  →  Postgres
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
│   ├── api/               # FastAPI + syslog + loop regole
│   ├── normalizers/       # parser ECS-lite
│   └── log-generator/     # traffico demo continuo
├── web/                   # UI React + Vite
└── tests/                 # pytest (normalizer + query parser)
```

## Sviluppo locale (senza UI Compose completa)

```bash
# Dipendenze API
pip install -r services/api/requirements.txt
pytest -q

# Web
cd web && npm install && npm run dev
```

L’API richiede Postgres (`DATABASE_URL`). Il percorso più semplice resta `docker compose up`.

## Ecosistema

- [soc-automation-hub](https://github.com/DarkGreen-projects/soc-automation-hub) — demo SOC (VT, MITRE planner, SIEM decoder, pivot)
- [Decoder_SIEMjoson](https://github.com/DarkGreen-projects/Decoder_SIEMjoson) — parse SIEM Python + arricchimento OSINT

## Ispirato a pipeline in stile LogPoint

Tassonomia, normalizzazione multi-fonte e flussi investigate → alert sono familiari a chi ha configurato un SIEM. Questo progetto ripropone una **fetta educativa** di quell’idea sotto il brand DarkGreen — nessun codice vendor, nessuna pretesa di produzione.

## Dati e sicurezza

- I sample usano solo IP di documentazione **RFC5737** e host/utenti fittizi.
- Non collegare questa demo a stream di log di produzione senza hardening (auth, TLS, retention, RBAC — fuori scope per v0.1).

## Roadmap (anteprima v2)

Backend OpenSearch/ClickHouse, correlazione più ricca, mapping MITRE in UI, collector opzionali — contributi benvenuti quando la storia demo è solida.

## Licenza

MIT — vedi [LICENSE](LICENSE).
