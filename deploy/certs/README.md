# Lab TLS certificates (self-signed). Do not commit private keys.
#
# Generate:
#   bash scripts/gen-tls.sh
#   powershell -File scripts/gen-tls.ps1
#
# Then:
#   docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
#
# UI: https://localhost:8443  (browser will warn on self-signed)
# Syslog UDP remains plaintext on 5140 (TLS syslog out of scope for this lab).

Put server.crt and server.key in this directory.
