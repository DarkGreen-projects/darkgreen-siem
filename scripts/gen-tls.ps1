# Generate self-signed TLS certs for lab HTTPS (Compose profile tls).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Out = Join-Path $Root "deploy\certs"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$crt = Join-Path $Out "server.crt"
$key = Join-Path $Out "server.key"

if (Get-Command openssl -ErrorAction SilentlyContinue) {
  & openssl req -x509 -nodes -newkey rsa:2048 -days 825 `
    -keyout $key -out $crt `
    -subj "/CN=localhost/O=DarkGreen Lab/C=IT" `
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
} else {
  # Fallback: .NET self-signed
  $cert = New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(2)
  $pwd = ConvertTo-SecureString -String "lab" -Force -AsPlainText
  $pfx = Join-Path $Out "server.pfx"
  Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pwd | Out-Null
  if (-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
    Write-Host "Generated $pfx (install OpenSSL to also emit .crt/.key for nginx)."
    Write-Host "Or run: choco install openssl / use WSL scripts/gen-tls.sh"
    exit 0
  }
}
Write-Host "Wrote $crt and $key"
