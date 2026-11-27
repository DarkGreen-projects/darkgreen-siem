# DarkGreen SIEM - Windows Setup Wizard (WinForms)
# Run: powershell -ExecutionPolicy Bypass -File .\DarkGreen-Setup.ps1
# Or build EXE: .\build_exe.ps1

param(
  [string]$SiemUrl = $env:SIEM_URL,
  [string]$Token = $env:SIEM_API_TOKEN
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

$script:State = @{
  Step = 0
  SiemUrl = if ($SiemUrl) { $SiemUrl.TrimEnd("/") } else { "http://localhost:8000" }
  Token = if ($Token) { $Token } else { "" }
  CompatOk = $false
  NetOk = $false
  HealthOk = $false
  AuthOk = $false
  CollectMode = "heartbeat"
  Log = New-Object System.Collections.Generic.List[string]
  Summary = ""
}

function Add-Log([string]$msg, [string]$level = "info") {
  $prefix = switch ($level) {
    "ok" { "[OK] " }
    "fail" { "[FAIL] " }
    "warn" { "[!] " }
    default { "" }
  }
  $script:State.Log.Add("$prefix$msg") | Out-Null
  if ($script:LogBox) {
    $script:LogBox.AppendText("$prefix$msg`r`n")
    $script:LogBox.SelectionStart = $script:LogBox.Text.Length
    $script:LogBox.ScrollToCaret()
  }
}

function Test-IsAdmin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-CompatCheck {
  $script:State.CompatOk = $false
  Add-Log "Controllo compatibilita PC..."
  $os = [Environment]::OSVersion
  $ver = $os.Version
  if ($ver.Major -lt 10) {
    Add-Log "Serve Windows 10 o superiore (trovato $($os.VersionString))" "fail"
    return $false
  }
  Add-Log "OS: $($os.VersionString)" "ok"
  $psVer = $PSVersionTable.PSVersion
  if ($psVer.Major -lt 5) {
    Add-Log "Serve PowerShell 5.1+ (trovato $psVer)" "fail"
    return $false
  }
  Add-Log "PowerShell: $psVer" "ok"
  $drive = (Get-Item $env:SystemDrive).PSDrive
  $freeGb = [math]::Round(($drive.Free / 1GB), 2)
  if ($freeGb -lt 0.2) {
    Add-Log "Spazio disco basso: ${freeGb} GB liberi" "warn"
  } else {
    Add-Log "Spazio disco: ${freeGb} GB liberi" "ok"
  }
  if (Test-IsAdmin) {
    Add-Log "Sessione elevata (Admin)" "ok"
  } else {
    Add-Log "Non Admin: Event Log Security / task schedulato possono fallire" "warn"
  }
  $script:State.CompatOk = $true
  return $true
}

function Invoke-NetworkCheck {
  $script:State.NetOk = $false
  $url = $script:State.SiemUrl.TrimEnd("/")
  if (-not $url) {
    Add-Log "URL SIEM mancante" "fail"
    return $false
  }
  try {
    $uri = [Uri]$url
  } catch {
    Add-Log "URL non valido: $url" "fail"
    return $false
  }
  $hostName = $uri.Host
  $port = if ($uri.IsDefaultPort) { if ($uri.Scheme -eq "https") { 443 } else { 80 } } else { $uri.Port }
  Add-Log "Risoluzione DNS $hostName ..."
  try {
    $null = [System.Net.Dns]::GetHostAddresses($hostName)
    Add-Log "DNS OK" "ok"
  } catch {
    Add-Log "DNS FAIL: $_" "fail"
    return $false
  }
  Add-Log "TCP $hostName`:$port ..."
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $iar = $client.BeginConnect($hostName, $port, $null, $null)
    $ok = $iar.AsyncWaitHandle.WaitOne(5000, $false)
    if (-not $ok) {
      $client.Close()
      Add-Log "TCP timeout verso $hostName`:$port" "fail"
      return $false
    }
    $client.EndConnect($iar)
    $client.Close()
    Add-Log "TCP OK" "ok"
  } catch {
    Add-Log "TCP FAIL: $_" "fail"
    return $false
  }
  $script:State.NetOk = $true
  return $true
}

function Invoke-HealthCheck {
  $script:State.HealthOk = $false
  $url = $script:State.SiemUrl.TrimEnd("/") + "/health"
  Add-Log "GET $url"
  try {
    $resp = Invoke-RestMethod -Uri $url -Method GET -TimeoutSec 10
    Add-Log ("Health OK: " + ($resp | ConvertTo-Json -Compress)) "ok"
    $script:State.HealthOk = $true
    return $true
  } catch {
    Add-Log "Health FAIL: $_" "fail"
    return $false
  }
}

function Invoke-Heartbeat {
  $script:State.AuthOk = $false
  $url = $script:State.SiemUrl.TrimEnd("/") + "/api/ingest"
  $body = @{
    events = @(
      @{
        source_type = "siem_export"
        ingest_channel = "connect-wizard"
        payload = @{
          Product = "ConnectInstaller"
          Activity = "Heartbeat"
          Severity = "low"
          Hostname = $env:COMPUTERNAME
          Description = "DarkGreen setup wizard heartbeat from $env:COMPUTERNAME"
          category = "ops"
        }
      }
    )
  } | ConvertTo-Json -Depth 8
  Add-Log "POST heartbeat /api/ingest"
  try {
    $headers = @{
      Authorization = "Bearer $($script:State.Token)"
      "Content-Type" = "application/json"
    }
    $resp = Invoke-RestMethod -Uri $url -Method POST -Headers $headers -Body $body -TimeoutSec 15
    Add-Log ("Ingest OK: " + ($resp | ConvertTo-Json -Compress)) "ok"
    $script:State.AuthOk = $true
    return $true
  } catch {
    Add-Log "Ingest FAIL: $_" "fail"
    Add-Log "Controlla SIEM_API_TOKEN e AUTH_ENABLED" "warn"
    return $false
  }
}

function Get-NxLogSnippet {
  $hostOnly = ([Uri]$script:State.SiemUrl).Host
  return @"
# Generato da DarkGreen-Setup - UDP 5140
<Extension json>
  Module xm_json
</Extension>
<Input eventlog>
  Module im_msvistalog
  Query <QueryList><Query Id='0'><Select Path='Security'>*</Select></Query></QueryList>
</Input>
<Output darkgreen>
  Module om_udp
  Host $hostOnly
  Port 5140
</Output>
<Route>
  Path eventlog => darkgreen
</Route>
"@
}

function Write-AgentConfigFile {
  param(
    [string]$SiemUrl,
    [string]$Token
  )
  $cfgDir = Join-Path $env:ProgramData "DarkGreen"
  New-Item -ItemType Directory -Force -Path $cfgDir | Out-Null
  $cfgPath = Join-Path $cfgDir "agent.env"
  @"
SIEM_URL=$SiemUrl
SIEM_API_TOKEN=$Token
"@ | Set-Content -Path $cfgPath -Encoding ASCII -Force
  try {
    icacls $cfgPath /inheritance:r /grant:r "SYSTEM:(R)" "Administrators:(F)" "BUILTIN\Administrators:(F)" | Out-Null
  } catch {
    Add-Log "ACL su agent.env non applicate (continua comunque): $_" "warn"
  }
  return $cfgPath
}

function Install-AgentScheduledTask {
  param([int]$IntervalSec = 60)
  $agentDir = Join-Path (Split-Path $PSScriptRoot -Parent) "windows-agent"
  $agentPs1 = Join-Path $agentDir "DarkGreen-Agent.ps1"
  if (-not (Test-Path $agentPs1)) {
    $agentPs1 = Join-Path $PSScriptRoot "..\windows-agent\DarkGreen-Agent.ps1"
  }
  if (-not (Test-Path $agentPs1)) {
    Add-Log "DarkGreen-Agent.ps1 non trovato accanto all'installer" "fail"
    return $false
  }
  if (-not (Test-IsAdmin)) {
    Add-Log "Serve Admin per creare Scheduled Task" "fail"
    return $false
  }
  $cfgPath = Write-AgentConfigFile -SiemUrl $script:State.SiemUrl -Token $script:State.Token
  $taskName = "DarkGreen-Windows-Agent"
  # Token lives in agent.env (ACL-restricted), not in Task Scheduler argv.
  $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$agentPs1`" -ConfigPath `"$cfgPath`" -IntervalSec $IntervalSec"
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arg
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes ([Math]::Max(1, [int]($IntervalSec / 60)))) -RepetitionDuration ([TimeSpan]::MaxValue)
  if ($IntervalSec -lt 60) {
    $trigger = New-ScheduledTaskTrigger -AtStartup
  }
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
  # Also run once now (still no token on cmdline)
  Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$agentPs1`" -ConfigPath `"$cfgPath`" -Once" -WindowStyle Hidden
  Add-Log "Scheduled Task '$taskName' creato + run -Once (config $cfgPath)" "ok"
  return $true
}

function Write-NxLogFile {
  $outDir = Join-Path $PSScriptRoot "generated"
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null
  $path = Join-Path $outDir "nxlog-darkgreen.conf"
  Get-NxLogSnippet | Set-Content -Path $path -Encoding UTF8
  Add-Log "Snippet NXLog: $path" "ok"
  return $path
}

# --- UI ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "DarkGreen SIEM Setup"
$form.Size = New-Object System.Drawing.Size(720, 520)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(18, 40, 32)

$title = New-Object System.Windows.Forms.Label
$title.Text = "DarkGreen SIEM - Installer host"
$title.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$title.ForeColor = [System.Drawing.Color]::FromArgb(61, 220, 151)
$title.Location = New-Object System.Drawing.Point(20, 16)
$title.AutoSize = $true
$form.Controls.Add($title)

$stepLabel = New-Object System.Windows.Forms.Label
$stepLabel.ForeColor = [System.Drawing.Color]::FromArgb(155, 184, 168)
$stepLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$stepLabel.Location = New-Object System.Drawing.Point(20, 48)
$stepLabel.Size = New-Object System.Drawing.Size(660, 20)
$form.Controls.Add($stepLabel)

$panel = New-Object System.Windows.Forms.Panel
$panel.Location = New-Object System.Drawing.Point(20, 76)
$panel.Size = New-Object System.Drawing.Size(660, 220)
$panel.BackColor = [System.Drawing.Color]::FromArgb(26, 51, 40)
$form.Controls.Add($panel)

$script:LogBox = New-Object System.Windows.Forms.TextBox
$script:LogBox.Multiline = $true
$script:LogBox.ScrollBars = "Vertical"
$script:LogBox.ReadOnly = $true
$script:LogBox.Font = New-Object System.Drawing.Font("Consolas", 9)
$script:LogBox.BackColor = [System.Drawing.Color]::FromArgb(11, 31, 23)
$script:LogBox.ForeColor = [System.Drawing.Color]::FromArgb(232, 245, 239)
$script:LogBox.Location = New-Object System.Drawing.Point(20, 310)
$script:LogBox.Size = New-Object System.Drawing.Size(660, 110)
$form.Controls.Add($script:LogBox)

$btnBack = New-Object System.Windows.Forms.Button
$btnBack.Text = "Indietro"
$btnBack.Location = New-Object System.Drawing.Point(320, 435)
$btnBack.Size = New-Object System.Drawing.Size(100, 30)
$form.Controls.Add($btnBack)

$btnNext = New-Object System.Windows.Forms.Button
$btnNext.Text = "Avanti"
$btnNext.Location = New-Object System.Drawing.Point(430, 435)
$btnNext.Size = New-Object System.Drawing.Size(120, 30)
$btnNext.BackColor = [System.Drawing.Color]::FromArgb(61, 220, 151)
$btnNext.FlatStyle = "Flat"
$form.Controls.Add($btnNext)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = "Esci"
$btnCancel.Location = New-Object System.Drawing.Point(560, 435)
$btnCancel.Size = New-Object System.Drawing.Size(100, 30)
$form.Controls.Add($btnCancel)

$steps = @(
  "Benvenuto",
  "Compatibilita PC",
  "Rete",
  "Health SIEM",
  "Autenticazione",
  "Collezione",
  "Fine"
)

function Clear-Panel {
  $panel.Controls.Clear()
}

function Show-Step {
  Clear-Panel
  $i = $script:State.Step
  $stepLabel.Text = "Passo $($i + 1)/$($steps.Count): $($steps[$i])"
  $btnBack.Enabled = ($i -gt 0 -and $i -lt ($steps.Count - 1))
  $btnNext.Text = if ($i -eq ($steps.Count - 1)) { "Chiudi" } else { "Avanti" }

  switch ($i) {
    0 {
      $l = New-Object System.Windows.Forms.Label
      $l.Text = "Collega questo PC al DarkGreen SIEM in pochi passi:`r`ncompatibilità, rete, health, autenticazione, collezione eventi."
      $l.ForeColor = [System.Drawing.Color]::White
      $l.Location = New-Object System.Drawing.Point(16, 16)
      $l.Size = New-Object System.Drawing.Size(620, 50)
      $panel.Controls.Add($l)

      $lu = New-Object System.Windows.Forms.Label
      $lu.Text = "URL API SIEM"
      $lu.ForeColor = [System.Drawing.Color]::FromArgb(155, 184, 168)
      $lu.Location = New-Object System.Drawing.Point(16, 80)
      $lu.AutoSize = $true
      $panel.Controls.Add($lu)
      $script:UrlBox = New-Object System.Windows.Forms.TextBox
      $script:UrlBox.Text = $script:State.SiemUrl
      $script:UrlBox.Location = New-Object System.Drawing.Point(16, 100)
      $script:UrlBox.Size = New-Object System.Drawing.Size(620, 24)
      $panel.Controls.Add($script:UrlBox)

      $lt = New-Object System.Windows.Forms.Label
      $lt.Text = "Token ingest (SIEM_API_TOKEN)"
      $lt.ForeColor = [System.Drawing.Color]::FromArgb(155, 184, 168)
      $lt.Location = New-Object System.Drawing.Point(16, 140)
      $lt.AutoSize = $true
      $panel.Controls.Add($lt)
      $script:TokenBox = New-Object System.Windows.Forms.TextBox
      $script:TokenBox.Text = $script:State.Token
      $script:TokenBox.UseSystemPasswordChar = $true
      $script:TokenBox.Location = New-Object System.Drawing.Point(16, 160)
      $script:TokenBox.Size = New-Object System.Drawing.Size(620, 24)
      $panel.Controls.Add($script:TokenBox)
    }
    1 {
      $l = New-Object System.Windows.Forms.Label
      $l.Text = "Verifica OS, PowerShell, disco e privilegi Admin."
      $l.ForeColor = [System.Drawing.Color]::White
      $l.Location = New-Object System.Drawing.Point(16, 16)
      $l.Size = New-Object System.Drawing.Size(620, 40)
      $panel.Controls.Add($l)
      $b = New-Object System.Windows.Forms.Button
      $b.Text = "Esegui controllo"
      $b.Location = New-Object System.Drawing.Point(16, 70)
      $b.Size = New-Object System.Drawing.Size(160, 30)
      $b.Add_Click({ Invoke-CompatCheck | Out-Null })
      $panel.Controls.Add($b)
    }
    2 {
      $l = New-Object System.Windows.Forms.Label
      $l.Text = "DNS + TCP verso l'API SIEM (porta dall'URL)."
      $l.ForeColor = [System.Drawing.Color]::White
      $l.Location = New-Object System.Drawing.Point(16, 16)
      $l.Size = New-Object System.Drawing.Size(620, 40)
      $panel.Controls.Add($l)
      $b = New-Object System.Windows.Forms.Button
      $b.Text = "Esegui controllo rete"
      $b.Location = New-Object System.Drawing.Point(16, 70)
      $b.Size = New-Object System.Drawing.Size(180, 30)
      $b.Add_Click({ Invoke-NetworkCheck | Out-Null })
      $panel.Controls.Add($b)
    }
    3 {
      $l = New-Object System.Windows.Forms.Label
      $l.Text = "GET /health sull'API."
      $l.ForeColor = [System.Drawing.Color]::White
      $l.Location = New-Object System.Drawing.Point(16, 16)
      $l.Size = New-Object System.Drawing.Size(620, 40)
      $panel.Controls.Add($l)
      $b = New-Object System.Windows.Forms.Button
      $b.Text = "Test health"
      $b.Location = New-Object System.Drawing.Point(16, 70)
      $b.Size = New-Object System.Drawing.Size(140, 30)
      $b.Add_Click({ Invoke-HealthCheck | Out-Null })
      $panel.Controls.Add($b)
    }
    4 {
      $l = New-Object System.Windows.Forms.Label
      $l.Text = "Invia heartbeat autenticato (canale connect-wizard)."
      $l.ForeColor = [System.Drawing.Color]::White
      $l.Location = New-Object System.Drawing.Point(16, 16)
      $l.Size = New-Object System.Drawing.Size(620, 40)
      $panel.Controls.Add($l)
      $b = New-Object System.Windows.Forms.Button
      $b.Text = "Invia heartbeat"
      $b.Location = New-Object System.Drawing.Point(16, 70)
      $b.Size = New-Object System.Drawing.Size(160, 30)
      $b.Add_Click({ Invoke-Heartbeat | Out-Null })
      $panel.Controls.Add($b)
    }
    5 {
      $l = New-Object System.Windows.Forms.Label
      $l.Text = "Come vuoi raccogliere eventi da questo PC?"
      $l.ForeColor = [System.Drawing.Color]::White
      $l.Location = New-Object System.Drawing.Point(16, 16)
      $l.Size = New-Object System.Drawing.Size(620, 30)
      $panel.Controls.Add($l)
      $script:RbHb = New-Object System.Windows.Forms.RadioButton
      $script:RbHb.Text = "Solo heartbeat (gia inviato)"
      $script:RbHb.ForeColor = [System.Drawing.Color]::White
      $script:RbHb.Location = New-Object System.Drawing.Point(16, 55)
      $script:RbHb.AutoSize = $true
      $script:RbHb.Checked = $true
      $panel.Controls.Add($script:RbHb)
      $script:RbAgent = New-Object System.Windows.Forms.RadioButton
      $script:RbAgent.Text = "Agent Security + Scheduled Task (60s, lean)"
      $script:RbAgent.ForeColor = [System.Drawing.Color]::White
      $script:RbAgent.Location = New-Object System.Drawing.Point(16, 90)
      $script:RbAgent.AutoSize = $true
      $panel.Controls.Add($script:RbAgent)
      $script:RbNx = New-Object System.Windows.Forms.RadioButton
      $script:RbNx.Text = "Genera snippet NXLog (UDP 5140)"
      $script:RbNx.ForeColor = [System.Drawing.Color]::White
      $script:RbNx.Location = New-Object System.Drawing.Point(16, 125)
      $script:RbNx.AutoSize = $true
      $panel.Controls.Add($script:RbNx)
    }
    6 {
      $l = New-Object System.Windows.Forms.Label
      $l.Text = $script:State.Summary
      $l.ForeColor = [System.Drawing.Color]::White
      $l.Location = New-Object System.Drawing.Point(16, 16)
      $l.Size = New-Object System.Drawing.Size(620, 180)
      $panel.Controls.Add($l)
    }
  }
}

function Save-WelcomeInputs {
  if ($script:UrlBox) {
    $script:State.SiemUrl = $script:UrlBox.Text.Trim().TrimEnd("/")
  }
  if ($script:TokenBox) {
    $script:State.Token = $script:TokenBox.Text.Trim()
  }
}

$btnCancel.Add_Click({ $form.Close() })
$btnBack.Add_Click({
  if ($script:State.Step -gt 0) {
    $script:State.Step--
    Show-Step
  }
})
$btnNext.Add_Click({
  $i = $script:State.Step
  if ($i -eq ($steps.Count - 1)) {
    $form.Close()
    return
  }
  if ($i -eq 0) {
    Save-WelcomeInputs
    if (-not $script:State.SiemUrl -or -not $script:State.Token) {
      [System.Windows.Forms.MessageBox]::Show("URL e token obbligatori.", "DarkGreen") | Out-Null
      return
    }
  }
  if ($i -eq 1 -and -not $script:State.CompatOk) {
    if (-not (Invoke-CompatCheck)) {
      [System.Windows.Forms.MessageBox]::Show("Compatibilita non OK. Correggi e riprova.", "DarkGreen") | Out-Null
      return
    }
  }
  if ($i -eq 2 -and -not $script:State.NetOk) {
    if (-not (Invoke-NetworkCheck)) {
      [System.Windows.Forms.MessageBox]::Show("Rete non OK.", "DarkGreen") | Out-Null
      return
    }
  }
  if ($i -eq 3 -and -not $script:State.HealthOk) {
    if (-not (Invoke-HealthCheck)) {
      [System.Windows.Forms.MessageBox]::Show("Health non OK.", "DarkGreen") | Out-Null
      return
    }
  }
  if ($i -eq 4 -and -not $script:State.AuthOk) {
    if (-not (Invoke-Heartbeat)) {
      [System.Windows.Forms.MessageBox]::Show("Heartbeat fallito.", "DarkGreen") | Out-Null
      return
    }
  }
  if ($i -eq 5) {
    $mode = "heartbeat"
    if ($script:RbAgent.Checked) { $mode = "agent" }
    elseif ($script:RbNx.Checked) { $mode = "nxlog" }
    $script:State.CollectMode = $mode
    $extra = ""
    if ($mode -eq "agent") {
      if (Install-AgentScheduledTask -IntervalSec 60) {
        $extra = "Agent: Scheduled Task DarkGreen-Windows-Agent (60s)."
      } else {
        $extra = "Agent: task non creato (vedi log)."
      }
    } elseif ($mode -eq "nxlog") {
      $p = Write-NxLogFile
      $extra = "NXLog config: $p`r`nApri UDP 5140 sul SIEM se serve."
    } else {
      $extra = "Solo heartbeat: verifica Sorgenti → connect-wizard."
    }
    $script:State.Summary = @"
Setup completato su $env:COMPUTERNAME

SIEM: $($script:State.SiemUrl)
Compat: $($script:State.CompatOk) · Rete: $($script:State.NetOk)
Health: $($script:State.HealthOk) · Auth: $($script:State.AuthOk)

$extra

In UI: Sorgenti → badge enrolled entro ~15 min.
Guida: docs/setup-guide.md
"@
  }
  $script:State.Step++
  Show-Step
})

Show-Step
Add-Log "Wizard avviato su $env:COMPUTERNAME"
[void]$form.ShowDialog()
