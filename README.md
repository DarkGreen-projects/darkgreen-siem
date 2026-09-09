# DarkGreen SIEM

[![License: MIT](https://img.shields.io/badge/License-MIT-3ddc97.svg)](LICENSE)
[![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)](docker-compose.yml)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](services/api)
[![React](https://img.shields.io/badge/React-Vite-61DAFB?logo=react&logoColor=black)](web)

**Multi-source demo SIEM** — collect logs from firewalls, Windows, cloud identity, and EDR/SIEM exports, normalize them into one schema, search like an analyst, and fire YAML detection rules.

Part of the [DarkGreen Projects](https://github.com/DarkGreen-projects) portfolio.

![Dashboard preview](docs/assets/dashboard-preview.svg)

## Why this exists

Commercial SIEMs (LogPoint-style pipelines: collect → normalize → search → alert) are hard to show on a résumé. This repo is a **self-contained lab** you can run in one command — useful, visual, and honest about being a demo (not a production SIEM, not affiliated with LogPoint/Guardsix).

## Quick start

```bash
docker compose up --build
```

Open **http://localhost:8080**

| Endpoint | URL |
|----------|-----|
| UI | http://localhost:8080 |
| API docs | http://localhost:8000/docs |
| Syslog UDP | `localhost:5140` |

Stop with `Ctrl+C` / `docker compose down`.

## What you get

1. **Ingest** — HTTP `/api/ingest`, syslog UDP, startup seed from `samples/`
2. **Normalize** — 4 source types → ECS-lite fields (`src_ip`, `user`, `action`, `severity`, …)
3. **Search** — `src_ip:203.0.113.45 AND action:deny` plus free-text
4. **Dashboard** — EPS, volume timeline, breakdowns, recent alerts
5. **Detections** — YAML rules (match + threshold) with ack-able alerts
6. **Live traffic** — `log-generator` keeps sending multi-source events

## Example queries

```
action:deny
user:j.doe
source_type:windows AND action:login_failed
malware
```

## Architecture

See [docs/architecture.md](docs/architecture.md).

```text
samples / syslog / HTTP  →  FastAPI normalizers  →  Postgres
                                      ↓
                              YAML rule engine → alerts
                                      ↓
                         React UI (Dashboard · Search · Sources · Detections)
```

## Project layout

```text
darkgreen-siem/
├── docker-compose.yml
├── rules/                 # detection YAML
├── samples/               # fictitious multi-vendor logs
├── services/
│   ├── api/               # FastAPI + syslog listener + rule loop
│   ├── normalizers/       # ECS-lite parsers
│   └── log-generator/     # continuous demo traffic
├── web/                   # React + Vite UI
└── tests/                 # pytest (normalizers + query parser)
```

## Local development (without full Compose UI)

```bash
# API deps
pip install -r services/api/requirements.txt
pytest -q

# Web
cd web && npm install && npm run dev
```

API expects Postgres (`DATABASE_URL`). Easiest path remains `docker compose up`.

## Ecosystem

- [soc-automation-hub](https://github.com/DarkGreen-projects/soc-automation-hub) — SOC analyst demos (VT, MITRE planner, SIEM decoder, pivot)
- [Decoder_SIEMjoson](https://github.com/DarkGreen-projects/Decoder_SIEMjoson) — Python SIEM parse + OSINT enrich

## Inspired by LogPoint-style pipelines

Taxonomy thinking, multi-source normalization, and investigate → alert workflows are familiar to anyone who has tuned a SIEM. This project re-implements a **small educational slice** of that idea under the DarkGreen brand — no vendor code, no production claims.

## Security & data

- Samples use **RFC5737** documentation IPs and fictional hosts/users only.
- Do not point this demo at real production log streams without hardening (auth, TLS, retention, RBAC — out of scope for v0.1).

## Roadmap (v2 teaser)

OpenSearch/ClickHouse backend, richer correlation, MITRE mapping UI, optional collectors — contributions welcome once the demo story is solid.

## License

MIT — see [LICENSE](LICENSE).
