#!/usr/bin/env bash
# Generate self-signed TLS certs for lab HTTPS (Compose profile tls).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/deploy/certs"
mkdir -p "$OUT"
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout "$OUT/server.key" \
  -out "$OUT/server.crt" \
  -subj "/CN=localhost/O=DarkGreen Lab/C=IT" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
echo "Wrote $OUT/server.crt and server.key"
