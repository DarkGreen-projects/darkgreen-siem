# DarkGreen SIEM - Windows Agent (lab)
# Legge eventi Security recenti e li POST a /api/ingest

param(
  [string]$SiemUrl = $env:SIEM_URL,
  [string]$Token = $env:SIEM_API_TOKEN,
  [string]$ConfigPath = "",
  [int]$IntervalSec = 60,
  [int]$LookbackMinutes = 5,
  [switch]$Once
)

$ErrorActionPreference = "Stop"

function Read-AgentConfig([string]$Path) {
  if (-not $Path -or -not (Test-Path $Path)) { return @{ Url = ""; Token = "" } }
  $url = ""
  $tok = ""
  Get-Content -Path $Path -ErrorAction Stop | ForEach-Object {
    $line = $_.Trim()
    if (-not $line -or $line.StartsWith("#")) { return }
    $idx = $line.IndexOf("=")
    if ($idx -lt 1) { return }
    $key = $line.Substring(0, $idx).Trim()
    $val = $line.Substring($idx + 1).Trim()
    if ($key -eq "SIEM_URL") { $url = $val }
    elseif ($key -eq "SIEM_API_TOKEN") { $tok = $val }
  }
  return @{ Url = $url; Token = $tok }
}

if ($ConfigPath) {
  $cfg = Read-AgentConfig $ConfigPath
  if ($cfg.Url -and -not $SiemUrl) { $SiemUrl = $cfg.Url }
  if ($cfg.Token -and -not $Token) { $Token = $cfg.Token }
}

if (-not $SiemUrl) { $SiemUrl = Read-Host "SIEM API URL" }
if (-not $Token) {
  $secure = Read-Host "Bearer token" -AsSecureString
  $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
  try {
    $Token = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
  } finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
}
$SiemUrl = $SiemUrl.TrimEnd("/")
$stateFile = Join-Path $PSScriptRoot ".agent-last.json"
$lastSeen = (Get-Date).ToUniversalTime().AddMinutes(-$LookbackMinutes)
if (Test-Path $stateFile) {
  try {
    $prev = Get-Content $stateFile -Raw | ConvertFrom-Json
    if ($prev.lastSeen) { $lastSeen = [datetime]::Parse($prev.lastSeen).ToUniversalTime() }
  } catch {}
}

function Send-Event([hashtable]$payload) {
  $body = @{
    events = @(
      @{
        source_type = "windows"
        ingest_channel = "windows-agent"
        payload = $payload
      }
    )
  } | ConvertTo-Json -Depth 8
  $headers = @{ Authorization = "Bearer $Token"; "Content-Type" = "application/json" }
  Invoke-RestMethod -Uri "$SiemUrl/api/ingest" -Method POST -Headers $headers -Body $body -TimeoutSec 20 | Out-Null
}

function Collect-Once {
  param([datetime]$Since)
  Write-Host "$(Get-Date -Format o) Collect since $Since ..." -ForegroundColor Cyan
  $filter = @{ LogName = "Security"; StartTime = $Since.ToLocalTime() }
  $events = @()
  try {
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue | Select-Object -First 40
  } catch {
    Write-Host "  WinEvent non disponibile: $_" -ForegroundColor Yellow
  }
  $maxTs = $Since
  foreach ($ev in $events) {
    $ts = $ev.TimeCreated.ToUniversalTime()
    if ($ts -gt $maxTs) { $maxTs = $ts }
    $payload = @{
      EventID = $ev.Id
      Computer = $ev.MachineName
      Channel = $ev.LogName
      Provider = $ev.ProviderName
      Message = ($ev.Message | Out-String).Substring(0, [Math]::Min(1500, (($ev.Message | Out-String).Length)))
      TimeCreated = $ts.ToString("o")
    }
    try {
      Send-Event $payload
      Write-Host "  sent EventID=$($ev.Id)" -ForegroundColor Green
    } catch {
      Write-Host "  FAIL send: $_" -ForegroundColor Red
    }
  }
  if ($events.Count -eq 0) {
    # heartbeat so Sorgenti shows the channel
    Send-Event @{
      EventID = 0
      Computer = $env:COMPUTERNAME
      Channel = "Security"
      Provider = "DarkGreenAgent"
      Message = "windows-agent heartbeat"
      TimeCreated = (Get-Date).ToUniversalTime().ToString("o")
    }
    Write-Host "  heartbeat inviato (nessun evento Security recente)" -ForegroundColor Gray
  }
  @{ lastSeen = $maxTs.ToString("o") } | ConvertTo-Json | Set-Content $stateFile -Encoding UTF8
  return $maxTs
}

do {
  $lastSeen = Collect-Once -Since $lastSeen
  if ($Once) { break }
  Start-Sleep -Seconds $IntervalSec
} while ($true)
