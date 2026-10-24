@echo off
setlocal
cd /d "%~dp0"
echo.
echo WINDOWS BRIDGE REMOTE SUPPORT
echo.
echo This pairs your computer via a PRIVATE GitHub transport repository.
echo The named operator can send full Windows Bridge commands under YOUR Windows account.
echo Commands, results and diagnostics can be visible to repository collaborators.
echo Do not proceed unless YOU want remote support and trust the operator.
echo You need your own GitHub account with a collaborator invitation already accepted.
echo Never share your GitHub login, token, password, or a VPN subscription with your operator.
echo.
choice /C YN /M "Allow remote support for this computer"
if errorlevel 2 exit /b 1
if not errorlevel 1 exit /b 1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" -Transport GitHub -Repository Ai-b0ss/windows-bridge-support-20261024 -TrustedOperator Ai-b0ss %*
if errorlevel 1 (echo REMOTE_PAIRING_FAILED & pause & exit /b 1)
echo REMOTE_PAIRING_INSTALL_DONE
pause
