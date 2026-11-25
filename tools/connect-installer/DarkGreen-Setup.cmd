@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0dist\DarkGreen-Setup.exe" (
  start "" "%~dp0dist\DarkGreen-Setup.exe"
  exit /b 0
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DarkGreen-Setup.ps1" %*
