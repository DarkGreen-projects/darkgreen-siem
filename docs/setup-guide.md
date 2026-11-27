# Guida setup rapida (lean)

Obiettivo: SIEM lab su in pochi minuti, senza consumare risorse a vuoto, poi collegare i PC con l'installer. Hardening: [security.md](security.md).

![Setup flow](assets/setup-flow.svg)

## 1. Ambiente

```bash
cp .env.example .env
# Ruota AUTH_SECRET, SIEM_API_TOKEN, DEMO_PASSWORD, SYSLOG_SHARED_SECRET, password DB
```

| Variabile | Note |
|-----------|------|
| `AUTH_SECRET` | Lunga e random; cifra anche `lab_settings` sealed |
| `SIEM_API_TOKEN` | Bearer machine / installer |
| `DEMO_PASSWORD` | Login UI `DEMO_USERNAME` (default `analyst`) |
| `SYSLOG_SHARED_SECRET` | **Obbligatorio** per UDP 5140 (senza secret = drop totale) |
| `STRICT_SECRETS` | `true` fuori dal lab privato |
| `TRUST_X_FORWARDED_FOR` | `true` solo dietro proxy fidato |
| `DISABLE_OPENAPI` | `true` per nascondere `/docs` |

Lista completa: [../.env.example](../.env.example).

## 2. Avvio lean (default)

```bash
docker compose up --build
```

Senza `log-generator` (niente traffico continuo). Limiti soft su postgres/api/web.

UI: http://localhost:8080 - login `analyst` / password da `.env` (default compose: `darkgreen`).

### Traffico demo (opzionale)

```bash
docker compose --profile demo up --build
```

`INTERVAL_SEC` default 8 (vedi `.env.example`).

### Parametri lean utili

| Env | Default | Ruolo |
|-----|---------|--------|
| `RULE_INTERVAL_SEC` | `30` | Cadenza motore regole |
| `PURGE_INTERVAL_SEC` | `300` | Purge + silence |
| `RETENTION_DAYS` | `7` | Retention eventi |
| `INTERVAL_SEC` | `8` | Solo profilo `demo` |
| `HEALTH_STALE_MINUTES` | `5` | Health sorgente stale |
| `HEALTH_SILENT_MINUTES` | `30` | Health sorgente silent |
| `RUN_BACKGROUND_JOBS` | `true` | `false` su `api-b` in HA |

### TLS / HA (opzionale)

```bash
# TLS
bash scripts/gen-tls.sh   # o scripts/gen-tls.ps1
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build

# HA (api + api-b)
docker compose -f docker-compose.yml -f docker-compose.ha.yml up --build
```

UI HTTPS lab: https://localhost:8443. Con overlay TLS l’API grezza non resta pubblica su `:8000`.

## 3. Setup minimo in UI

Tab **Setup**: retention/SLA se serve; TI / webhook / Copilot / RAG / graph opzionali.

Consigli post-hardening:

- Attiva scoring triage e finestra priors
- RAG top-K + graph window solo se usi Turno/Copilot
- Chiavi TI solo in Setup sealed (non in chat/log)
- Webhook HTTPS con host in allowlist se restringi egress

## 4. Collegare un PC (installer)

1. Tab **Sorgenti** → **Scarica connect-installer.zip**
2. Sul PC Windows: `DarkGreen-Setup.cmd` oppure `DarkGreen-Setup.exe` (nello zip / `dist/`)
3. Passi wizard: URL + token → compatibilità PC → rete → health → heartbeat → collezione (heartbeat / agent task / NXLog)
4. Linux: `./connect-darkgreen.sh http://SIEM:8000`

Token = valore di `SIEM_API_TOKEN` (non finisce in chiaro negli argomenti Scheduled Task).

Dettaglio tool: [../tools/connect-installer/README.md](../tools/connect-installer/README.md).  
Collectors syslog (con prefisso secret): [collectors-windows-syslog.md](collectors-windows-syslog.md).

### Build EXE (opzionale)

Serve .NET 8 SDK:

```powershell
cd tools/connect-installer
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
```

## 5. Verifica

1. In **Sorgenti** il canale `connect-wizard` (o `windows-agent`) deve passare a **enrolled** entro ~15 minuti dall’ultimo evento.
2. Apri **Turno**: coda con `campaign_id` / noise lane, briefing, alert collegati, copilot suggest-only.
3. Health API: `GET /health`.
4. (Opzionale) stress locale:

```bash
python scripts/lab_stress_populate.py --events 1000 --profile mix --login --seed-dispositions 10
python scripts/lab_stress_measure.py --login
```

Report: [lab-reports/latest/stress-report.md](lab-reports/latest/stress-report.md).

## 6. Test automatici

```bash
pip install -r services/api/requirements.txt
pytest -q
```

CI GitHub: `.github/workflows/ci.yml` (pytest) e `stress-lab.yml` (gate p95).

## Link

- Architettura: [architecture.md](architecture.md)
- Sicurezza: [security.md](security.md)
- Indice docs: [README.md](README.md)
- README repo: [../README.md](../README.md)
- Issues fixed: [GitHub issues label:fixed](https://github.com/DarkGreen-projects/darkgreen-siem/issues?q=is%3Aissue+label%3Afixed+is%3Aclosed)
