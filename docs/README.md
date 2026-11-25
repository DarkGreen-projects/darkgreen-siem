# Documentazione DarkGreen SIEM

Indice per chi apre il repo su GitHub.

## Percorso consigliato

1. [setup-guide.md](setup-guide.md) - avvio lean in 5 passi + installer host EXE  
2. [architecture.md](architecture.md) - componenti, detection, graph, RAG, sicurezza  
3. [collectors-windows-syslog.md](collectors-windows-syslog.md) - NXLog / rsyslog → UDP 5140  
4. [../tools/connect-installer/README.md](../tools/connect-installer/README.md) - wizard EXE / Linux  
5. [../tools/windows-agent/README.md](../tools/windows-agent/README.md) - agent Security lean  
6. [../tests/lab_proof/README.md](../tests/lab_proof/README.md) - mini-report regole / copertura / lean impact  

README principale: [../README.md](../README.md) · Env: [../.env.example](../.env.example)

### Lab reports pubblicati

Report versionati (Markdown + HTML + SVG + JSON):

- Indice: [lab-reports/README.md](lab-reports/README.md)
- Ultimo: [lab-reports/latest/report.md](lab-reports/latest/report.md)

## Diagrammi (SVG)

| Asset | Cosa mostra |
|-------|-------------|
| [assets/setup-flow.svg](assets/setup-flow.svg) | Setup lean + EXE host |
| [assets/pipeline-overview.svg](assets/pipeline-overview.svg) | Pipeline collect → API → Postgres / UI |
| [assets/alert-graph-flow.svg](assets/alert-graph-flow.svg) | Entity norm → alert_links → fingerprint → copilot |
| [assets/workbench-turno.svg](assets/workbench-turno.svg) | Coda Turno, briefing, collegati, close |
| [assets/dashboard-preview.svg](assets/dashboard-preview.svg) | Preview stile dashboard |

## API utili (lab)

| Endpoint | Ruolo |
|----------|--------|
| `GET /health` | Liveness |
| `GET /api/setup` | Impostazioni lab (admin) |
| `GET /api/alerts/queue` | Coda Turno |
| `GET /api/alerts/{id}/brief` | Briefing + fingerprint + connected |
| `GET /api/alerts/{id}/links` | Grafo alert |
| `POST /api/alerts/{id}/copilot-suggest` | Suggest local / LLM |
| `GET /api/tools/connect-installer.zip` | Pack installer host |
| `GET /api/tools/windows-agent.zip` | Pack agent |
