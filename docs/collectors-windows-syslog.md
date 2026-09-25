# Collectors Windows / syslog verso DarkGreen SIEM

Guida lab per allineare Hyper-V / Windows a ciò che vedi in azienda: Security Event Log → collector → UDP `5140` sull’API DarkGreen.

## Endpoint

| Canale | Destinazione |
|--------|----------------|
| Syslog UDP | `host:5140` (Compose: porta host `5140`) |
| HTTP ingest | `POST /api/ingest` con Bearer `SIEM_API_TOKEN` |

Il listener syslog dell’API:

- se il payload è **JSON** con `EventID` / `Channel` → `source_type=windows`
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

1. `docker compose up --build`
2. Invia un evento JSON di prova:

```bash
echo '{"EventID":4625,"Channel":"Security","Computer":"win-dc01","TargetUserName":"j.doe","IpAddress":"203.0.113.45"}' | nc -u -w1 localhost 5140
```

3. In Ricerca: `source_type:windows AND action:login_failed`

## Note lab

- Credenziali UI: `analyst` / `darkgreen`
- Ingest HTTP richiede `Authorization: Bearer <SIEM_API_TOKEN>`
- Non esporre UDP 5140 su Internet: lab locale only
