# DarkGreen Windows Agent (lab, lean)

Legge Security Event Log e POST JSON a `/api/ingest` (`ingest_channel=windows-agent`).

Default intervallo **60s** (lean). Preferisci `-Once` o Scheduled Task dall'installer invece di lasciare una console aperta.

```powershell
$env:SIEM_URL = "http://localhost:8000"
$env:SIEM_API_TOKEN = "dg-lab-token-change-me"

# una passata
powershell -ExecutionPolicy Bypass -File .\DarkGreen-Agent.ps1 -Once

# loop lean
powershell -ExecutionPolicy Bypass -File .\DarkGreen-Agent.ps1 -IntervalSec 60
```

Richiede permesso lettura Event Log Security (spesso Admin).

L'installer `tools/connect-installer` puo creare il task `DarkGreen-Windows-Agent`.
