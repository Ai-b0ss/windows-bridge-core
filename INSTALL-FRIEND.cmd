@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Transport Local %*
if errorlevel 1 (echo INSTALL_FAILED & pause & exit /b 1)
echo INSTALL_COMPLETED. Local bridge should start under current user.
pause
