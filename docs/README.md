# Documentazione DarkGreen SIEM

| Doc | Contenuto |
|-----|-----------|
| [setup-guide.md](setup-guide.md) | Setup lean in 5 passi + installer host |
| [architecture.md](architecture.md) | Componenti, detection, graph, RAG, sicurezza |
| [collectors-windows-syslog.md](collectors-windows-syslog.md) | NXLog / rsyslog → UDP 5140 |

## Diagrammi

| Asset | Cosa mostra |
|-------|-------------|
| [assets/setup-flow.svg](assets/setup-flow.svg) | Setup lean + EXE host |
| [assets/pipeline-overview.svg](assets/pipeline-overview.svg) | Pipeline collect → API → Postgres / UI |
| [assets/alert-graph-flow.svg](assets/alert-graph-flow.svg) | Entity norm → alert_links → fingerprint → copilot |
| [assets/workbench-turno.svg](assets/workbench-turno.svg) | Coda Turno, briefing, collegati, close |
| [assets/dashboard-preview.svg](assets/dashboard-preview.svg) | Preview stile dashboard |

Torna al [README principale](../README.md).
