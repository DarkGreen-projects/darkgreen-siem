#!/usr/bin/env bash
# DarkGreen SIEM - Connect Wizard (Linux, lean)
# Token: only SIEM_API_TOKEN env or interactive prompt (never argv).
set -euo pipefail

SIEM_URL="${1:-}"
TOKEN="${SIEM_API_TOKEN:-}"

echo ""
echo "=== DarkGreen SIEM Connect Wizard (Linux) ==="
echo "Passi: URL -> compat -> rete -> health -> heartbeat -> rsyslog"
echo ""

if [[ -z "$SIEM_URL" ]]; then
  read -r -p "SIEM API URL (es. http://localhost:8000): " SIEM_URL
fi
SIEM_URL="${SIEM_URL%/}"
if [[ -z "$TOKEN" ]]; then
  read -r -s -p "Bearer token (SIEM_API_TOKEN): " TOKEN
  echo ""
fi

echo "[1/5] Compatibilita ..."
if ! command -v curl >/dev/null 2>&1; then
  echo "  FAIL: serve curl" >&2
  exit 1
fi
echo "  OK: curl presente · host=$(hostname 2>/dev/null || echo lab-host)"

HOST_ONLY="$(python3 - <<PY
from urllib.parse import urlparse
u = urlparse("$SIEM_URL")
print(u.hostname or "api")
print(u.port or (443 if u.scheme == "https" else 80))
PY
)"
HOST_NAME="$(echo "$HOST_ONLY" | head -n1)"
PORT="$(echo "$HOST_ONLY" | tail -n1)"

echo "[2/5] Rete DNS/TCP $HOST_NAME:$PORT ..."
if getent hosts "$HOST_NAME" >/dev/null 2>&1 || host "$HOST_NAME" >/dev/null 2>&1; then
  echo "  OK DNS"
else
  echo "  WARN: DNS non risolto (continuo comunque)"
fi
if command -v nc >/dev/null 2>&1; then
  if nc -z -w 5 "$HOST_NAME" "$PORT" 2>/dev/null; then
    echo "  OK TCP"
  else
    echo "  FAIL TCP verso $HOST_NAME:$PORT" >&2
    exit 1
  fi
else
  echo "  SKIP TCP (nc non disponibile)"
fi

echo "[3/5] Test /health ..."
curl -fsS --max-time 10 "$SIEM_URL/health" | tee /dev/stderr >/dev/null
echo "  OK"

echo "[4/5] Heartbeat POST /api/ingest ..."
HOST_LOCAL="$(hostname 2>/dev/null || echo lab-host)"
PAYLOAD=$(cat <<EOF
{"events":[{"source_type":"siem_export","ingest_channel":"connect-wizard","payload":{"Product":"ConnectInstaller","Activity":"Heartbeat","Severity":"low","Hostname":"$HOST_LOCAL","Description":"DarkGreen connect-installer heartbeat","category":"ops"}}]}
EOF
)
curl -fsS --max-time 15 -X POST "$SIEM_URL/api/ingest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
echo ""
echo "  OK"

echo "[5/5] Snippet rsyslog (UDP 5140) ..."
echo "  # /etc/rsyslog.d/99-darkgreen.conf"
echo "  *.* @${HOST_NAME}:5140"
if [[ -n "${SYSLOG_SHARED_SECRET:-}" ]]; then
  echo "  # Con SYSLOG_SHARED_SECRET sull'API, prefissa i messaggi con SECRET o #dg-token=SECRET"
fi

echo "Done. Verifica in UI Sorgenti → connect-wizard (enrolled)."
