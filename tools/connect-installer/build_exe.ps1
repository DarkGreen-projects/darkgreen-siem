# Build DarkGreen-Setup.exe (dotnet launcher → WinForms PS1 wizard)
#   powershell -ExecutionPolicy Bypass -File .\build_exe.ps1

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$src = Join-Path $here "DarkGreen-Setup.ps1"
$dist = Join-Path $here "dist"
$proj = Join-Path $here "launcher\DarkGreenSetup.csproj"
$out = Join-Path $dist "DarkGreen-Setup.exe"

if (-not (Test-Path $src)) { throw "Missing DarkGreen-Setup.ps1" }
if (-not (Test-Path $proj)) { throw "Missing launcher project" }
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) {
  Write-Host "dotnet SDK non trovato. Usa DarkGreen-Setup.cmd / DarkGreen-Setup.ps1" -ForegroundColor Yellow
  exit 1
}

Write-Host "Compilo launcher → $out ..." -ForegroundColor Cyan
# Framework-dependent (piccolo): richiede .NET 8 Desktop Runtime sul PC target.
# Per portabilita totale: -SelfContained $true (EXE piu grande).
$selfContained = $env:DG_SETUP_SELF_CONTAINED -eq "1"
dotnet publish $proj -c Release -r win-x64 --self-contained:$selfContained -o $dist `
  /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
if (-not (Test-Path $out)) {
  throw "Build fallita: $out assente"
}
# Copy script next to EXE so the launcher finds it when run from dist/
Copy-Item -Force $src (Join-Path $dist "DarkGreen-Setup.ps1")
# Also copy EXE to pack root for zip users
Copy-Item -Force $out (Join-Path $here "DarkGreen-Setup.exe")
Write-Host "OK: $out" -ForegroundColor Green
Write-Host "Copia anche in: $here\DarkGreen-Setup.exe" -ForegroundColor Gray
Write-Host "Oppure: DarkGreen-Setup.cmd" -ForegroundColor Gray
