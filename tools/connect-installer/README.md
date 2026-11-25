# DarkGreen Setup Installer (host)

Wizard a passi per collegare un PC al SIEM lab.

## Windows (consigliato)

1. Scarica lo zip da UI **Sorgenti** (o copia questa cartella).
2. Doppio click su `DarkGreen-Setup.cmd`  
   - se esiste `dist/DarkGreen-Setup.exe` lo avvia  
   - altrimenti lancia `DarkGreen-Setup.ps1` (WinForms)
3. Oppure: `powershell -ExecutionPolicy Bypass -File .\DarkGreen-Setup.ps1`

### Passi del wizard

1. Benvenuto (URL API + token)
2. Compatibilita PC (Windows 10+, PowerShell 5.1+, disco, Admin)
3. Rete (DNS + TCP verso API)
4. Health (`GET /health`)
5. Autenticazione (heartbeat `connect-wizard`)
6. Collezione: solo heartbeat / agent Scheduled Task / snippet NXLog
7. Fine + riepilogo

### Build EXE

Serve [.NET 8 SDK](https://dotnet.microsoft.com/download).

```powershell
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
```

Output: `dist/DarkGreen-Setup.exe` (+ copia in root pack). L'EXE avvia il wizard WinForms `DarkGreen-Setup.ps1`.

Portabile senza runtime installato:

```powershell
$env:DG_SETUP_SELF_CONTAINED = "1"
powershell -ExecutionPolicy Bypass -File .\build_exe.ps1
```

## Linux

```bash
chmod +x ./connect-darkgreen.sh
SIEM_API_TOKEN=... ./connect-darkgreen.sh http://SIEM:8000
```

## Verifica

In UI → Sorgenti: badge `enrolled` sul canale `connect-wizard` (o `windows-agent`) entro ~15 minuti.
