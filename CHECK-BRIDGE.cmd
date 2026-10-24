@echo off
setlocal
powershell.exe -NoLogo -NoProfile -Command "$p=39073;$s=Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue; if($s){Write-Host 'BRIDGE_LISTENING_LOCAL_PORT_39073'} else {Write-Host 'BRIDGE_NOT_LISTENING_CHECK_INSTALL_OR_START_FF'}; Write-Host 'Install root:' $env:LOCALAPPDATA\FF-Windows-Bridge"
pause
