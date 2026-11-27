# Collectors Windows / syslog verso DarkGreen SIEM

Guida lab per allineare Hyper-V / Windows a ciò che vedi in azienda: Security Event Log → collector → UDP `5140` sull’API DarkGreen.

Per il percorso guidato (compatibilità PC, rete, health, heartbeat, agent): usa l’**installer** in [../tools/connect-installer/README.md](../tools/connect-installer/README.md) o la [setup-guide.md](setup-guide.md). Questa pagina resta per NXLog/rsyslog “a mano”.

## Endpoint

| Canale | Destinazione |
|--------|----------------|
| Syslog UDP | `host:5140` (Compose: porta host `5140`) |
| HTTP ingest | `POST /api/ingest` con Bearer `SIEM_API_TOKEN` |

### Shared secret obbligatorio

Ogni datagramma UDP deve iniziare con il secret di `.env` (`SYSLOG_SHARED_SECRET`), altrimenti viene scartato:

- `SECRET <payload>`
- `#dg-token=SECRET <payload>`
- oppure lo stesso prefisso subito dopo un PRI syslog (`<14>SECRET ...`)

Esempio (secret di lab default `dg-lab-syslog`, da ruotare):

```bash
echo 'dg-lab-syslog {"EventID":4625,"Channel":"Security","Computer":"win-dc01","TargetUserName":"j.doe","IpAddress":"203.0.113.45"}' | nc -u -w1 localhost 5140
```

In NXLog/rsyslog anteponi il secret al messaggio (template / exec prefix). Dettagli hardening: [security.md](security.md).

Il listener syslog dell’API:

- se il payload (dopo lo strip del secret) è **JSON** con `EventID` / `Channel` → `source_type=windows`
- altrimenti tratta la linea come **firewall** KV (FortiGate-like)

## NXLog (Windows Event Log → UDP JSON)

Sample: [samples/nxlog-windows.conf](samples/nxlog-windows.conf)

Punti chiave:

1. Modulo `im_mseventlog` su canale **Security**
2. Output JSON con `EventID`, `Channel`, `ProviderName`, `Computer`, `TargetUserName`, `IpAddress`
3. `om_udp` verso `SIEM_HOST:5140`

Su Hyper-V: installa NXLog sull’ospite Windows (o sul VM guest di laboratorio), apri firewall outbound UDP 5140 verso il container API.

## rsyslog (forward generico)

Sample: [samples/rsyslog-forward.conf](samples/rsyslog-forward.conf)

Utile se un agent Linux (o un relay) inoltra già syslog. Per Windows “puro” preferisci NXLog o Winlogbeat → HTTP.

## Verifica

1. `docker compose up --build` (lean) oppure `--profile demo` per traffico
2. Invia un evento JSON di prova **con prefisso secret** (vedi sopra).
3. In Ricerca: `source_type:windows AND action:login_failed`

## Note lab

- Credenziali UI: `analyst` / password da `.env` (default compose `darkgreen`)
- Ingest HTTP richiede `Authorization: Bearer <SIEM_API_TOKEN>`
- `SYSLOG_SHARED_SECRET` vuoto = **nessun** ingest UDP accettato
- Non esporre UDP 5140 su Internet: lab locale only
- Rate limit per host sorgente; compare secret timing-safe
