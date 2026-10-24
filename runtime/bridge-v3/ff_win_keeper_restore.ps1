[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
$ProgressPreference='SilentlyContinue'
$bridgeRoot=Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\bridge-v3'
$keeperPath=Join-Path $bridgeRoot 'ff_win_v3_keeper.ps1'
$ownerChromeBootstrapPath=Join-Path $bridgeRoot 'cua_owner_chrome_logon.ps1'
function KeeperProcs { @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue|Where-Object{$_.CommandLine -and $_.CommandLine -match '(?i)ff_win_v3_keeper\.ps1'}|ForEach-Object{[pscustomobject]@{pid=[int]$_.ProcessId;ppid=[int]$_.ParentProcessId}}) }
function RelayProcs { @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue|Where-Object{$_.CommandLine -and $_.CommandLine -match '(?i)(desktop-commander.*remote|wonderwhy-er.*remote)'}|ForEach-Object{[pscustomobject]@{pid=[int]$_.ProcessId;ppid=[int]$_.ParentProcessId;name=$_.Name}}) }
$events=@()
$runtimeDependencyOk=(Test-Path -LiteralPath $keeperPath -PathType Leaf) -and (Test-Path -LiteralPath $ownerChromeBootstrapPath -PathType Leaf)
if($runtimeDependencyOk){
  foreach($script in @($keeperPath,$ownerChromeBootstrapPath)){
    $tokens=$null;$errors=$null
    [void][System.Management.Automation.Language.Parser]::ParseFile($script,[ref]$tokens,[ref]$errors)
    if($errors.Count -ne 0){$runtimeDependencyOk=$false;$events+=('runtime script parse failed: '+[IO.Path]::GetFileName($script))}
  }
}else{$events+='keeper runtime dependency missing'}
$before=[ordered]@{keeper=@(KeeperProcs);relay=@(RelayProcs);keeper_path_exists=(Test-Path -LiteralPath $keeperPath);owner_chrome_bootstrap_exists=(Test-Path -LiteralPath $ownerChromeBootstrapPath);runtime_dependency_ok=$runtimeDependencyOk}
if($runtimeDependencyOk -and @(KeeperProcs).Count -eq 0){
  try{
    $task=Get-ScheduledTask -TaskName 'FF-Windows-Bridge-Interactive' -ErrorAction SilentlyContinue
    if($task){Start-ScheduledTask -TaskName 'FF-Windows-Bridge-Interactive' -ErrorAction Stop;$events+='started scheduled task FF-Windows-Bridge-Interactive'}
  }catch{$events+=('scheduled task start failed: '+$_.Exception.Message)}
  Start-Sleep -Seconds 4
}
if($runtimeDependencyOk -and @(KeeperProcs).Count -eq 0){
  try{
    $ps=(Get-Command powershell.exe -ErrorAction Stop|Select-Object -First 1)
    $psi=New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName=$ps.Source
    $psi.Arguments=('-NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$keeperPath+'"')
    $psi.WorkingDirectory=$bridgeRoot
    $psi.UseShellExecute=$false
    $psi.CreateNoWindow=$true
    $psi.WindowStyle=[System.Diagnostics.ProcessWindowStyle]::Hidden
    @($psi.EnvironmentVariables.Keys)|ForEach-Object{$k=[string]$_;if($k -eq 'RUNNER_TRACKING_ID' -or $k -like 'GITHUB_*' -or $k -like 'ACTIONS_*'){$psi.EnvironmentVariables.Remove($k)}}
    $kp=[System.Diagnostics.Process]::Start($psi)
    $events+=('direct keeper start pid '+$kp.Id)
  }catch{$events+=('direct keeper start failed: '+$_.Exception.Message)}
}
$timeline=@()
for($i=0;$i -lt 12;$i++){
  Start-Sleep -Seconds 3
  $k=@(KeeperProcs);$r=@(RelayProcs)
  $timeline += [pscustomobject]@{after_seconds=(($i+1)*3);keeper_count=$k.Count;relay_count=$r.Count;keeper_pids=@($k|ForEach-Object{$_.pid});relay_pids=@($r|ForEach-Object{$_.pid})}
  if($k.Count -gt 0 -and $r.Count -gt 0){break}
}
$after=[ordered]@{keeper=@(KeeperProcs);relay=@(RelayProcs)}
$ok=($runtimeDependencyOk -and $after.keeper.Count -gt 0 -and $after.relay.Count -gt 0)
$result=[ordered]@{schema='ff3-keeper-restore-v1';ok=$ok;device=$env:COMPUTERNAME;at=(Get-Date).ToString('o');before=$before;events=$events;timeline=$timeline;after=$after}
$result|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $env:FF_KEEPER_RESTORE_RESULT -Encoding UTF8
if($ok){exit 0}else{exit 7}
