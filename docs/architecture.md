# Architettura

## Panoramica

DarkGreen SIEM è una **demo di portfolio** di una pipeline di log di sicurezza multi-fonte, ispirata ai flussi in stile LogPoint collect → normalize → search → detect. Non è affiliata a LogPoint/Guardsix e non è indurita per la produzione.

![Pipeline overview](assets/pipeline-overview.svg)

## Componenti

| Servizio | Ruolo |
|----------|-------|
| `postgres` | Store eventi + alert + `alert_memory` + `alert_links` |
| `api` | FastAPI ingest, search, stats, regole YAML, syslog UDP, RAG, graph, copilot |
| `web` | UI React (Dashboard, Turno, Ricerca, Sorgenti, Detection, Setup) dietro nginx |
| `log-generator` | Traffico demo (Compose **profile `demo`**, off di default) |

```mermaid
flowchart LR
  Gen[log-generator] -->|HTTP ingest| API
  Gen -->|Syslog UDP 5140| API
  Seed[samples/] -->|startup seed| API
  API --> Norm[normalizers]
  Norm --> PG[(Postgres)]
  Rules[rules/*.yml] --> Engine[rule engine]
  Engine --> PG
  Engine --> Graph[alert_links]
  Engine --> Mem[alert_memory]
  UI[web :8080] -->|/api| API
  API --> PG
```

## Schema normalizzato (ECS-lite)

`timestamp`, `source_type`, `vendor`, `device`, `host`, `user`, `src_ip`, `dst_ip`, `action`, `severity`, `message`, `raw`, `labels`, `ingest_channel`

## Tipi di sorgente

1. **firewall** - FortiGate syslog KV (PRI/header strip, traffic + UTM virus/IPS, labels: logid, type/subtype, intf, policy, url, attack, ...)  
2. **windows** - Windows Event JSON  
3. **cloud_auth** - auth in stile Entra/Okta  
4. **siem_export** - export EDR/SIEM JSON (shape Cynet): `Activity`→action, process/hash/MITRE in `labels` (`process`, `hash`, `technique`, …)

## Multi-tenant e RBAC

Soft tenancy: `tenant_id` su eventi/alert/IOC (default `lab`). Tabelle `tenants` / `users`. Ruoli:

- `admin` - Setup, purge, regole
- `analyst` - search, alert write, regole, enrich
- `viewer` - solo GET
- `ingest` - solo ingest (machine token)

Isolamento rigido per riga: nessun cross-tenant.

## TLS e HA lab

- TLS: `docker-compose.tls.yml` + certs in `deploy/certs/`
- HA: `docker-compose.ha.yml` (api + api-b, nginx upstream). Postgres single; `lab_settings` in DB per override condivisi.

## Sicurezza e storage

- Syslog: size cap + rate limit + `SYSLOG_SHARED_SECRET`; purge/silence per tenant; token invalidi se utente cancellato
- `AUTH_ENABLED=false` richiede `ALLOW_INSECURE_NO_AUTH=true`; `STRICT_SECRETS` blocca secret default; `DISABLE_OPENAPI` nasconde docs
- Login/ingest rate limit in-process; bootstrap token senza users DB → ruolo `viewer`
- Egress: `url_safety` su webhook/LLM (https, no privati, allowlist opzionale); IOC path quoted
- `lab_settings` sensibili: Fernet (`enc:`) derivato da `AUTH_SECRET`
- Nginx CSP + HSTS (overlay TLS); middleware header API
- HA: solo `api` esegue rules/maintenance (`RUN_BACKGROUND_JOBS=false` su `api-b`); setup rilegge `lab_settings` da DB
- `events.raw` compresso zlib se >512B; log API rotanti+gzip; Docker log max-size

## Ricerca

Linguaggio query demo: token `field:value` combinati con free-text opzionale (`AND` è ignorato come operatore). Esempio: `src_ip:203.0.113.45 AND action:deny`.

## Detection

Regole YAML sotto `rules/`:

- `type: match` - qualsiasi evento recente che soddisfa i filtri sui campi (anche `labels.<key>` su JSONB)
- `type: threshold` - conteggio >= N raggruppato per un campo in una finestra temporale
- `type: correlation` - due (o piu) step di match uniti su `join_on` (es. spray + login_success)
- `mitre` - stringa o lista technique ID (persistita su alert)
- **Dedup/merge**: stessa rule + entity key entro `cooldown_minutes` aggiorna `evidence.occurrences` invece di creare un nuovo alert
- **Dry-run**: `POST /api/rules/dry-run` valuta in memoria senza scrivere alert
- **Notify**: webhook Slack/Teams su create di alert critical/high (Setup / env)
- **SLA**: minuti ack/close per severity (`lab_settings` + Setup); badge e filtro `?sla=` su alert; `acked_at` al leave-open, `closed_at` a closed
- **Triage**: disposition + nota obbligatorie a close; score/noise_hint suggest-only da priors FP/TP; `GET /api/alerts/{id}/similar`
- **Workbench**: tab Turno + `GET /api/alerts/queue` (priorità SLA/signal/severity); briefing locale `GET /api/alerts/{id}/brief`; hotkeys triage condivise
- **Alert Memory RAG**: tabella `alert_memory` (upsert a close + backfill); retrieve ibrido FTS + boost rule/entity; `GET /api/memory/stats|export`
- **Entity norm**: `entity_norm` allinea `join:` / `src_ip:` / host / user in `evidence.entity_keys` (similar, RAG, grafo)
- **Alert graph**: tabella `alert_links` (relation + score + shared_keys); `link_alert` post-create; mature above `graph_min_history`; `GET /api/alerts/{id}/links`
- **Fingerprint**: `alert_fingerprint` (title, entity, MITRE, IOC, steps, connected top-K, cases) → brief + Copilot payload
- **Copilot**: local-first da memoria/grafo; altrimenti mini-LLM con fingerprint (`related_alert_ids` filtrati); fail soft + fallback majority
- **Connector**: zip wizard e windows-agent sotto `tools/`, download da Sorgenti / `/api/tools/*.zip`

### Flusso alert graph + LLM

![Alert graph flow](assets/alert-graph-flow.svg)

1. A create/merge: `entity_norm` scrive `entity_key` + `entity_keys`
2. `link_alert` cerca peer nella finestra `graph_window_minutes` e upserta archi
3. Sotto `graph_min_history`: solo `same_entity` / `shared_ioc`; sopra anche `temporal_follows` / `mitre_chain`
4. Brief costruisce fingerprint + `connected`; Copilot propone disposition e `related_alert_ids` (solo ID presenti nel contesto)

### Workbench Turno

![Workbench Turno](assets/workbench-turno.svg)

Coda `GET /api/alerts/queue`, briefing `GET /api/alerts/{id}/brief`, link `GET /api/alerts/{id}/links`, suggest `POST /api/alerts/{id}/copilot-suggest`. Hotkeys: `j`/`k` navigazione, `a` ack, `i` in corso, `c` close, `/` pivot, `?` aiuto.

## Collectors

Vedi [collectors-windows-syslog.md](collectors-windows-syslog.md) (NXLog / rsyslog → UDP 5140). JSON Windows su syslog è normalizzato come `source_type=windows`.

## Porte locali

- UI: http://localhost:8080  
- API: http://localhost:8000  
- Syslog UDP: 5140  
