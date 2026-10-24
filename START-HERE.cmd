@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
if errorlevel 1 (
  echo.
  echo Installation failed. Keep this window and retry START-HERE.cmd after fixing the reported error.
  if "%~1"=="" pause
  exit /b 1
)
echo.
echo DONE - FFBridge setup completed. See the startup status above.
if "%~1"=="" pause
exit /b 0
