# DarkGreen SIEM - Connect Wizard (Windows)
# Passi: URL SIEM -> token -> health -> heartbeat ingest -> genera snippet NXLog

param(
  [string]$SiemUrl = "",
  [string]$Token = "",
  [switch]$SkipHeartbeat
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=== DarkGreen SIEM Connect Wizard ===" -ForegroundColor Cyan
Write-Host "Ti guida verso la connessione host -> SIEM." -ForegroundColor Gray
Write-Host ""

if (-not $SiemUrl) {
  $SiemUrl = Read-Host "SIEM API URL (es. http://localhost:8000)"
}
$SiemUrl = $SiemUrl.TrimEnd("/")
if (-not $Token) {
  $secure = Read-Host "Bearer token (SIEM_API_TOKEN)" -AsSecureString
  $Token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  )
}

Write-Host "[1/4] Test /health ..." -ForegroundColor Yellow
try {
  $health = Invoke-RestMethod -Uri "$SiemUrl/health" -Method GET -TimeoutSec 10
  Write-Host "  OK: $($health | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
  Write-Host "  FAIL: $_" -ForegroundColor Red
  exit 1
}

if (-not $SkipHeartbeat) {
  Write-Host "[2/4] Heartbeat POST /api/ingest ..." -ForegroundColor Yellow
  $body = @{
    events = @(
      @{
        source_type = "siem_export"
        ingest_channel = "connect-wizard"
        payload = @{
          Product = "ConnectWizard"
          Activity = "Heartbeat"
          Severity = "low"
          Hostname = $env:COMPUTERNAME
          Description = "DarkGreen connect-wizard heartbeat from $env:COMPUTERNAME"
          category = "ops"
        }
      }
    )
  } | ConvertTo-Json -Depth 8
  try {
    $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
    $resp = Invoke-RestMethod -Uri "$SiemUrl/api/ingest" -Method POST -Headers $headers -Body $body -TimeoutSec 15
    Write-Host "  OK ingest: $($resp | ConvertTo-Json -Compress)" -ForegroundColor Green
  } catch {
    Write-Host "  FAIL ingest: $_" -ForegroundColor Red
    Write-Host "  Controlla token e AUTH_ENABLED / SIEM_API_TOKEN." -ForegroundColor Gray
    exit 1
  }
} else {
  Write-Host "[2/4] Heartbeat saltato (-SkipHeartbeat)" -ForegroundColor Gray
}

Write-Host "[3/4] Snippet NXLog (UDP 5140) ..." -ForegroundColor Yellow
$nxlog = @"
# Generato da Connect-DarkGreen.ps1 - invia Security JSON a DarkGreen SIEM
<Extension json>
  Module xm_json
</Extension>
<Input eventlog>
  Module im_msvistalog
  Query <QueryList><Query Id='0'><Select Path='Security'>*</Select></Query></QueryList>
</Input>
<Output darkgreen>
  Module om_udp
  Host REPLACE_SIEM_HOST
  Port 5140
  Exec to_json();
</Output>
<Route r>
  Path eventlog => darkgreen
</Route>
"@
$outDir = Join-Path $PSScriptRoot "generated"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$nxPath = Join-Path $outDir "nxlog-darkgreen.conf"
$hostOnly = ([Uri]$SiemUrl).Host
$nxlog = $nxlog.Replace("REPLACE_SIEM_HOST", $hostOnly)
Set-Content -Path $nxPath -Value $nxlog -Encoding UTF8
Write-Host "  Scritto: $nxPath" -ForegroundColor Green

Write-Host "[4/4] Checklist" -ForegroundColor Yellow
Write-Host "  - Firewall outbound UDP 5140 verso $hostOnly"
Write-Host "  - Oppure usa HTTP ingest con token (come lo heartbeat)"
Write-Host "  - In UI Sorgenti verifica canale connect-wizard / windows-agent"
Write-Host ""
Write-Host "Connessione lab pronta." -ForegroundColor Cyan
