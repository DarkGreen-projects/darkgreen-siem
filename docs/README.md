# Documentazione DarkGreen SIEM

Indice per chi apre il repo su GitHub.

## Percorso consigliato

1. [setup-guide.md](setup-guide.md) - avvio lean in pochi passi + installer host EXE  
2. [security.md](security.md) - secret, syslog, rate limit, egress, Copilot/RAG, CI  
3. [architecture.md](architecture.md) - componenti, detection, triage, graph, RAG  
4. [collectors-windows-syslog.md](collectors-windows-syslog.md) - NXLog / rsyslog → UDP 5140 (+ secret)  
5. [../tools/connect-installer/README.md](../tools/connect-installer/README.md) - wizard EXE / Linux  
6. [../tools/windows-agent/README.md](../tools/windows-agent/README.md) - agent Security lean  
7. [lab-reports/README.md](lab-reports/README.md) - report regole + stress harness  
8. [../tests/lab_proof/README.md](../tests/lab_proof/README.md) - mini-report regole / copertura / lean  

README principale: [../README.md](../README.md) · Env: [../.env.example](../.env.example)

### Lab reports pubblicati

Report versionati (Markdown + HTML + SVG + JSON):

- Indice: [lab-reports/README.md](lab-reports/README.md)
- Ultimo lab_proof: [lab-reports/latest/report.md](lab-reports/latest/report.md)
- Stress mix: [lab-reports/latest/stress-report.md](lab-reports/latest/stress-report.md)

### Issue chiuse (fixed + lab)

Tabella completa nel [README root](../README.md#bug-e-falle-corrette-in-questa-versione) (#1–#24).  
Filtro GitHub: [label:fixed is:closed](https://github.com/DarkGreen-projects/darkgreen-siem/issues?q=is%3Aissue+label%3Afixed+is%3Aclosed).

## Diagrammi (SVG)

| Asset | Cosa mostra |
|-------|-------------|
| [assets/setup-flow.svg](assets/setup-flow.svg) | Setup lean + EXE host |
| [assets/pipeline-overview.svg](assets/pipeline-overview.svg) | Pipeline collect → API → Postgres / UI |
| [assets/alert-graph-flow.svg](assets/alert-graph-flow.svg) | Entity norm → alert_links → fingerprint → copilot |
| [assets/workbench-turno.svg](assets/workbench-turno.svg) | Coda Turno, briefing, collegati, close |
| [assets/dashboard-lab.png](assets/dashboard-lab.png) | Screenshot dashboard lab |

## API utili (lab)

| Endpoint | Ruolo |
|----------|--------|
| `GET /health` | Liveness |
| `GET /api/setup` | Impostazioni lab (admin) |
| `GET /api/alerts` | Lista + filtri `noise_hint` / SLA / MITRE / disposition |
| `GET /api/alerts/queue` | Coda Turno (`campaign_id`, anti-noise) |
| `GET /api/alerts/{id}/brief` | Briefing + fingerprint + connected |
| `GET /api/alerts/{id}/links` | Grafo alert |
| `GET /api/alerts/{id}/similar` | Simili per triage |
| `POST /api/alerts/{id}/copilot-suggest` | Suggest local / LLM (audit) |
| `POST /api/alerts/bulk-close` | Chiusura massiva FP / rumore |
| `GET /api/memory/stats` | Contatori RAG |
| `GET /api/memory/export` | Export JSON memoria (admin) |
| `GET /api/tools/connect-installer.zip` | Pack installer host |
| `GET /api/tools/windows-agent.zip` | Pack agent |

## CI

| Workflow | Quando |
|----------|--------|
| [ci.yml](../.github/workflows/ci.yml) | Pytest su push/PR |
| [stress-lab.yml](../.github/workflows/stress-lab.yml) | Gate p95 stress 1k (cron + manuale) |
