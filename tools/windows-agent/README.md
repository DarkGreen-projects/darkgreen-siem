# DarkGreen Windows Agent (lab)

Esegue `DarkGreen-Agent.ps1` per leggere Security Event Log e POST JSON a `/api/ingest`
con `ingest_channel=windows-agent`.

```powershell
$env:SIEM_URL = "http://localhost:8000"
$env:SIEM_API_TOKEN = "dg-lab-token-change-me"
powershell -ExecutionPolicy Bypass -File .\DarkGreen-Agent.ps1 -Once
# oppure loop:
powershell -ExecutionPolicy Bypass -File .\DarkGreen-Agent.ps1 -IntervalSec 30
```

Richiede PowerShell con permesso lettura Event Log Security (spesso Admin).
