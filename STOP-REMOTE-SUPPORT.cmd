@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0STOP-REMOTE-SUPPORT.ps1" %*
if errorlevel 1 (echo STOP_REMOTE_FAILED & pause & exit /b 1)
pause
