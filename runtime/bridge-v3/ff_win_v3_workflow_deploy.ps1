param(
  [ValidateSet('Sync','Bootstrap')][string]$Mode = 'Sync',
  [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path,
  [string]$RuntimeRoot = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\bridge-v3'),
  [Parameter(Mandatory=$true)][string]$ResultPath
)

$ErrorActionPreference='Stop'

function Resolve-FF3Python {
  $portable=Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\tools\python-3.13.9-embed\python.exe'
  if(Test-Path -LiteralPath $portable -PathType Leaf){return $portable}
  $cmd=Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if($cmd){return $cmd.Source}
  throw 'FF3_PYTHON_NOT_FOUND'
}

function Invoke-FF3Verify {
  param([string]$Python,[string]$Deployer,[string]$Root)
  $oldPreference=$ErrorActionPreference
  $ErrorActionPreference='Continue'
  try{
    $raw=@(& $Python $Deployer verify --runtime-root $Root 2>&1)
    $nativeRc=$LASTEXITCODE
  }finally{
    $ErrorActionPreference=$oldPreference
  }
  if($nativeRc -ne 0){throw ('FF3_INSTALLED_MANIFEST_VERIFY_FAILED:' + (($raw|Out-String).Trim()))}
  $obj=(($raw|Out-String).Trim()) | ConvertFrom-Json
  if(-not $obj.ok){throw 'FF3_INSTALLED_MANIFEST_NOT_OK'}
  return $obj
}

New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null
$python=Resolve-FF3Python
$deployer=Join-Path $RepoRoot 'tools\cua_runtime_deploy.py'
if(-not(Test-Path -LiteralPath $deployer -PathType Leaf)){throw 'FF3_DEPLOYER_MISSING'}
$expectedHead=((& git -C $RepoRoot rev-parse HEAD | Out-String).Trim())
if(-not $expectedHead){throw 'FF3_SOURCE_HEAD_MISSING'}

$oldPreference=$ErrorActionPreference
$ErrorActionPreference='Continue'
try{
  $applyRaw=@(& $python $deployer apply --repo $RepoRoot --runtime-root $RuntimeRoot --ref HEAD --strict-external-validation 2>&1)
  $applyRc=$LASTEXITCODE
}finally{
  $ErrorActionPreference=$oldPreference
}
if($applyRc -ne 0){throw ('FF3_TRANSACTIONAL_APPLY_FAILED:' + (($applyRaw|Out-String).Trim()))}
$apply=(($applyRaw|Out-String).Trim()) | ConvertFrom-Json
$verify=Invoke-FF3Verify -Python $python -Deployer $deployer -Root $RuntimeRoot
if([string]$verify.source_head -ne $expectedHead){throw "FF3_SOURCE_HEAD_MISMATCH:$($verify.source_head):$expectedHead"}

$manifestPath=Join-Path $RuntimeRoot 'installed-runtime-manifest.json'
if(-not(Test-Path -LiteralPath $manifestPath -PathType Leaf)){throw 'FF3_INSTALLED_MANIFEST_MISSING'}
$manifest=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if([string]$manifest.release_id -ne [string]$verify.release_id){throw 'FF3_RELEASE_ID_MISMATCH'}

if($Mode -eq 'Sync'){
  @{
    ok=$true
    mode='Sync'
    root=$RuntimeRoot
    source_head=[string]$verify.source_head
    release_id=[string]$verify.release_id
    runtime_file_count=[int]$verify.file_count
    validation=$apply.validation
    manifest_path=$manifestPath
  } | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
  exit 0
}

$preVerify=Invoke-FF3Verify -Python $python -Deployer $deployer -Root $RuntimeRoot
if([string]$preVerify.source_head -ne $expectedHead){throw 'FF3_PRE_RESTART_HEAD_DRIFT'}
if([string]$preVerify.release_id -ne [string]$verify.release_id){throw 'FF3_PRE_RESTART_RELEASE_DRIFT'}

$agent=Join-Path $RuntimeRoot 'ff_win_v3_agent.py'
$keeper=Join-Path $RuntimeRoot 'ff_win_v3_keeper.ps1'
$pythonPathFile=Join-Path $RuntimeRoot 'python-path.txt'
$keeperPidPath=Join-Path $RuntimeRoot 'keeper.pid'
$agentPidPath=Join-Path $RuntimeRoot 'agent.pid'
$secretPath=Join-Path $RuntimeRoot 'secret'
Set-Content -LiteralPath $pythonPathFile -Value $python -Encoding ASCII

$runtimeHashes=@{}
foreach($item in @($manifest.files)){
  $target=Join-Path $RuntimeRoot ([string]$item.target)
  if(-not(Test-Path -LiteralPath $target -PathType Leaf)){throw "FF3_RUNTIME_FILE_MISSING:$($item.target)"}
  $actual=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
  if($actual -ne [string]$item.sha256){throw "FF3_RUNTIME_HASH_DRIFT_BEFORE_RESTART:$($item.target)"}
  $runtimeHashes[[string]$item.target]=$actual
}

$oldKeeperPid=$null
if(Test-Path -LiteralPath $keeperPidPath -PathType Leaf){
  $text=(Get-Content -LiteralPath $keeperPidPath -Raw).Trim()
  if($text -match '^\d+$'){
    $oldKeeperPid=[int]$text
    Stop-Process -Id $oldKeeperPid -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
  }
}

if(Test-Path -LiteralPath $secretPath -PathType Leaf){
  try{
    $secret=(Get-Content -LiteralPath $secretPath -Raw).Trim()
    if($secret){
      $headers=@{'X-FF3-Key'=$secret}
      Invoke-RestMethod -UseBasicParsing -Uri 'http://127.0.0.1:39073/shutdown' -Headers $headers -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 2 | Out-Null
      Start-Sleep -Milliseconds 700
    }
  }catch{}
}
if(Test-Path -LiteralPath $agentPidPath -PathType Leaf){
  $text=(Get-Content -LiteralPath $agentPidPath -Raw).Trim()
  if($text -match '^\d+$'){
    Stop-Process -Id ([int]$text) -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
  }
}

$startupDir=[Environment]::GetFolderPath('Startup')
$startupPath=Join-Path $startupDir 'FF-Windows-Bridge-V3.cmd'
$startupLines=@(
  '@echo off',
  'start "" /min powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $keeper + '"'
)
Set-Content -LiteralPath $startupPath -Value $startupLines -Encoding ASCII

$taskName='FF-Windows-Bridge-V3-Keeper-Start-Once'
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
$quoted='"' + $keeper + '"'
$action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File ' + $quoted)
$trigger=New-ScheduledTaskTrigger -Once -At ((Get-Date).AddMinutes(5))
$principal=New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName

$newKeeperPid=$null
for($i=0;$i-lt30;$i++){
  Start-Sleep -Milliseconds 500
  if(Test-Path -LiteralPath $keeperPidPath -PathType Leaf){
    $candidateText=(Get-Content -LiteralPath $keeperPidPath -Raw).Trim()
    if($candidateText -match '^\d+$'){
      $candidate=[int]$candidateText
      if($candidate -ne $oldKeeperPid -and (Get-Process -Id $candidate -ErrorAction SilentlyContinue)){
        $newKeeperPid=$candidate
        break
      }
    }
  }
}
if(-not $newKeeperPid){throw 'FF3_NEW_KEEPER_NOT_STARTED'}

$health=$null
for($i=0;$i-lt45;$i++){
  Start-Sleep -Seconds 1
  if(Test-Path -LiteralPath $secretPath -PathType Leaf){
    try{
      $secret=(Get-Content -LiteralPath $secretPath -Raw).Trim()
      $headers=@{'X-FF3-Key'=$secret}
      $candidateHealth=Invoke-RestMethod -UseBasicParsing -Uri 'http://127.0.0.1:39073/health' -Headers $headers -Method Get -TimeoutSec 2
      if($candidateHealth.ok){$health=$candidateHealth;break}
    }catch{}
  }
}
if(-not $health -or -not $health.ok){throw 'FF3_AGENT_HEALTH_FAILED'}
if(-not(Get-Process -Id $newKeeperPid -ErrorAction SilentlyContinue)){throw 'FF3_NEW_KEEPER_DIED'}

$expectedAgent=(@($manifest.files)|Where-Object{[string]$_.target -eq 'ff_win_v3_agent.py'}|Select-Object -First 1)
if(-not $expectedAgent){throw 'FF3_AGENT_MANIFEST_RECORD_MISSING'}
if([string]$health.agent_sha256 -ne [string]$expectedAgent.sha256){throw 'FF3_AGENT_SHA_MISMATCH'}

$unauthStatus=$null
try{
  Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:39073/health' -Method Get -TimeoutSec 2 | Out-Null
  $unauthStatus=200
}catch{
  if($_.Exception.Response){$unauthStatus=[int]$_.Exception.Response.StatusCode}
}
if($unauthStatus -ne 403){throw "FF3_AUTH_FAIL_CLOSED_FAILED:$unauthStatus"}

$postVerify=Invoke-FF3Verify -Python $python -Deployer $deployer -Root $RuntimeRoot
if([string]$postVerify.source_head -ne $expectedHead){throw 'FF3_POST_RESTART_HEAD_DRIFT'}
if([string]$postVerify.release_id -ne [string]$verify.release_id){throw 'FF3_POST_RESTART_RELEASE_DRIFT'}
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

@{
  ok=$true
  mode='Bootstrap'
  device=[string]$health.device
  protocol_version=[int]$health.protocol_version
  agent_pid=[int]$health.pid
  keeper_pid=[int]$newKeeperPid
  agent_sha256=[string]$health.agent_sha256
  source_head=[string]$postVerify.source_head
  release_id=[string]$postVerify.release_id
  runtime_file_count=[int]$postVerify.file_count
  runtime_sha256=$runtimeHashes
  validation=$apply.validation
  manifest_path=$manifestPath
  auth_fail_closed=$true
  startup_path=$startupPath
  python=$python
  start_method='scheduled_task_detached'
} | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ResultPath -Encoding UTF8
