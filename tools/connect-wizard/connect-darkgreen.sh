#!/usr/bin/env bash
# DarkGreen SIEM - Connect Wizard (Linux)
# Token: only SIEM_API_TOKEN env or interactive prompt (never argv).
set -euo pipefail

SIEM_URL="${1:-}"
TOKEN="${SIEM_API_TOKEN:-}"

echo ""
echo "=== DarkGreen SIEM Connect Wizard ==="
echo "Passi: URL -> token -> health -> heartbeat -> snippet rsyslog"
echo ""

if [[ -z "$SIEM_URL" ]]; then
  read -r -p "SIEM API URL (es. http://localhost:8000): " SIEM_URL
fi
SIEM_URL="${SIEM_URL%/}"
if [[ -z "$TOKEN" ]]; then
  read -r -s -p "Bearer token (SIEM_API_TOKEN): " TOKEN
  echo ""
fi

echo "[1/4] Test /health ..."
curl -fsS --max-time 10 "$SIEM_URL/health" | tee /dev/stderr >/dev/null
echo "  OK"

echo "[2/4] Heartbeat POST /api/ingest ..."
HOST_NAME="$(hostname 2>/dev/null || echo lab-host)"
PAYLOAD=$(cat <<EOF
{"events":[{"source_type":"siem_export","ingest_channel":"connect-wizard","payload":{"Product":"ConnectWizard","Activity":"Heartbeat","Severity":"low","Hostname":"$HOST_NAME","Description":"DarkGreen connect-wizard heartbeat","category":"ops"}}]}
EOF
)
curl -fsS --max-time 15 -X POST "$SIEM_URL/api/ingest" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD"
echo ""
echo "  OK"

HOST_ONLY="$(python3 - <<PY
from urllib.parse import urlparse
print(urlparse("$SIEM_URL").hostname or "api")
PY
)"

echo "[3/4] Snippet rsyslog (UDP 5140) ..."
echo "  # /etc/rsyslog.d/99-darkgreen.conf"
echo "  *.* @${HOST_ONLY}:5140"
if [[ -n "${SYSLOG_SHARED_SECRET:-}" ]]; then
  echo "  # Con SYSLOG_SHARED_SECRET impostato sull'API, prefissa i messaggi con:"
  echo "  #   ${SYSLOG_SHARED_SECRET} <messaggio>"
  echo "  # oppure: #dg-token=${SYSLOG_SHARED_SECRET} <messaggio>"
fi

echo "[4/4] Done."
echo "URL=$SIEM_URL host=$HOST_NAME"
