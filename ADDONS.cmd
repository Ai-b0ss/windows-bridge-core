@echo off
setlocal
cd /d "%~dp0"
set "CORE=%LOCALAPPDATA%\FF-Windows-Bridge"
set "PYTHON=%CORE%\tools\python-3.13.9-embed\python.exe"
if not exist "%PYTHON%" (
 echo CORE_NOT_INSTALLED: install Full Core first using INSTALL-FRIEND.cmd
 pause
 exit /b 2
)
if "%~1"=="" (
 echo Usage:
 echo   ADDONS.cmd status
 echo   ADDONS.cmd install --name browser --archive "C:\path\browser-runtime.zip"
 echo   ADDONS.cmd install --name visual --archive "C:\path\visual-runtime.zip"
 echo   ADDONS.cmd remove --name browser
 echo   ADDONS.cmd remove --name visual
 pause
 exit /b 0
)
"%PYTHON%" "%~dp0tools\optional_addons.py" %* --install-root "%CORE%"
if errorlevel 1 (
 echo ADDON_OPERATION_FAILED: examine the message above. Existing unknown files are never overwritten.
 pause
 exit /b 2
)
exit /b 0
