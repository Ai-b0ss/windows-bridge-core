param(
    [string]$Repository = 'Ai-b0ss/windows-agent-bridge', [string]$Branch = 'main', [int]$InboxIssue = 0,
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge'), [int]$RpcPort = 39073,
    [string]$Device = '', [string]$ResultsBranch = 'ff-transport-results', [switch]$StageOnly, [switch]$NonInteractive,
    [switch]$RuntimeOnly, [switch]$NoStartup,
    [ValidateSet('Local','GitHub')][string]$Transport = 'Local',
    [string]$TrustedOperator = ''
)
$originalLocalAppData = $env:LOCALAPPDATA
$originalPath = $env:PATH
$originalBridgeRoot = $env:FF_BRIDGE_ROOT
$originalBrowserPath = $env:PLAYWRIGHT_BROWSERS_PATH
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Modules') + ';' + $env:PSModulePath
Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Archive
. (Join-Path $PSScriptRoot 'ff-release-common.ps1')
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$defaultRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge'))
$rootHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($InstallRoot.ToLowerInvariant()))).Replace('-','').Substring(0,10)
if (-not $Device) { $Device = [Environment]::MachineName; if ($InstallRoot -ine $defaultRoot) { $Device += '-' + $rootHash } }
$root = Join-Path $InstallRoot 'github-transport'
$v3Root = Join-Path $InstallRoot 'bridge-v3'
$manifestPath = Join-Path $PSScriptRoot 'release-manifest.json'
if (-not (Test-Path $manifestPath)) { throw 'Use the complete release ZIP and START-HERE.cmd. Source-only install is not supported.' }
$manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json
if ($manifest.schema -ne 'ff-gh-release-v1') { throw 'RELEASE_MANIFEST_INVALID' }
# Check all bytes before authentication or touching running services.
foreach ($entry in $manifest.files.PSObject.Properties) {
    $path = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $entry.Name))
    if (-not $path.StartsWith($PSScriptRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'RELEASE_PATH_ESCAPE' }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw ('RELEASE_FILE_MISSING:' + $entry.Name) }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $entry.Value) { throw ('RELEASE_SHA256_MISMATCH:' + $entry.Name) }
}
function Write-JsonAtomic($Path, $Value) {
    $temp=$Path+'.tmp'
    [IO.File]::WriteAllText($temp, ($Value | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temp -Destination $Path -Force
}
$ownedStage = New-FFOwnedStage $InstallRoot
$stage = $ownedStage.path
$keepStage = $false
$localInstallLease = $null
try {
if (($RuntimeOnly -or $Transport -eq 'Local') -and -not $StageOnly) {
    $localMarker = Join-Path $v3Root 'ff-local-owned-runtime.json'
    if ((Test-Path -LiteralPath $v3Root) -and -not (Test-Path -LiteralPath $localMarker)) { throw 'LOCAL_RUNTIME_FOREIGN_TARGET' }
    if (Test-Path -LiteralPath $localMarker) {
        $previousLocal = Get-Content -LiteralPath $localMarker -Raw | ConvertFrom-Json
        if ($previousLocal.schema -ne 'ff-local-owned-runtime-v1') { throw 'LOCAL_RUNTIME_OWNERSHIP_INVALID' }
        # Ownership alone does not permit replacing a different source build.
        # Version changes use a new shadow root and an explicit controlled cutover.
        if ([string]$previousLocal.source_commit -cne [string]$manifest.source_commit) {
            throw 'LOCAL_RUNTIME_UPGRADE_REQUIRES_CUTOVER'
        }
    }
    # Re-installing into the exact directory used by a running Bridge would
    # replace imported Python modules and the launch script mid-execution.
    # Never infer a safe in-place upgrade from a valid ownership marker or
    # -NoStartup. Explicit controlled cutover and rollback are separate steps.
    $entry = [IO.Path]::GetFullPath((Join-Path $v3Root 'ff_win_v3_main.py'))
    if (Test-Path -LiteralPath $entry -PathType Leaf) {
        try {
            $pythonProcesses = @(Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'pythonw.exe'" -ErrorAction Stop)
        } catch { throw 'LOCAL_RUNTIME_PROCESS_AUDIT_UNAVAILABLE' }
        foreach ($proc in $pythonProcesses) {
            if ($proc.CommandLine -and $proc.CommandLine.IndexOf($entry,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw 'LIVE_RUNTIME_RUNNING_SWITCH_REQUIRED'
            }
        }
    }
    $localInstallLease = [IO.File]::Open((Join-Path $InstallRoot 'local-runtime.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
# Copy only hash-verified runtime entries, never extra files/profiles in a
# caller's extraction directory. Bundled assets are installed separately.
foreach ($entry in $manifest.files.PSObject.Properties) {
    if ($entry.Name.StartsWith('runtime/')) {
        $target = Join-Path $stage $entry.Name
        [void][IO.Directory]::CreateDirectory((Get-FFExtendedPath (Split-Path -Parent $target)))
        [IO.File]::Copy((Get-FFExtendedPath (Join-Path $PSScriptRoot $entry.Name)), (Get-FFExtendedPath $target), $false)
    }
}
$pythonDirectory = Join-Path $stage ('tools\python-' + $manifest.python_version + '-embed')
$python = Join-Path $pythonDirectory 'python.exe'
function Install-VerifiedArchive($Archive, $Destination, $Label) {
    $extract = Join-Path $stage $Label
    Expand-FFSafeArchive $Archive $extract
    Copy-FFPortableTree $extract $Destination
}
Install-VerifiedArchive (Join-Path $PSScriptRoot ('assets\' + $manifest.python_asset)) $pythonDirectory 'python'
$ghDirectory = Join-Path $stage 'tools\github-cli'
Install-VerifiedArchive (Join-Path $PSScriptRoot ('assets\' + $manifest.gh_asset)) $ghDirectory 'github-cli'
$gh = Get-FFPortableExecutable $ghDirectory 'gh.exe'
Install-VerifiedArchive (Join-Path $PSScriptRoot ('assets\' + $manifest.node_asset)) (Join-Path $stage 'tools\node') 'node'
$nodeDirectory = Split-Path -Parent (Get-FFPortableExecutable (Join-Path $stage 'tools\node') 'node.exe')
$env:PATH = $nodeDirectory + ';' + (Split-Path -Parent $gh) + ';' + $env:PATH
$transportStage = Join-Path $stage 'runtime\github-transport'
$v3Stage = Join-Path $stage 'runtime\bridge-v3'
if ($manifest.browser_asset) { Install-VerifiedArchive (Join-Path $PSScriptRoot ('assets\' + $manifest.browser_asset)) $v3Stage 'browser' }
if ($manifest.visual_asset) { Install-VerifiedArchive (Join-Path $PSScriptRoot ('assets\' + $manifest.visual_asset)) $v3Stage 'visual' }
$uiaBuildOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $v3Stage 'build_cua_native_uia3_sidecar.ps1') -OutputPath (Join-Path $v3Stage 'cua_native_uia3_sidecar.exe')
if ($LASTEXITCODE -ne 0) {
    $uiaDiagnostic = ($uiaBuildOutput | Out-String)
    if ($uiaDiagnostic.Length -gt 4000) { $uiaDiagnostic = $uiaDiagnostic.Substring(0,4000) }
    throw ('UIA_BUILD_FAILED:' + $uiaDiagnostic)
}
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $v3Stage 'browsers'
$env:FF_BRIDGE_ROOT = Join-Path $stage 'isolated-smoke-state'
$env:LOCALAPPDATA = Join-Path $stage 'isolated-appdata'
& $python (Join-Path $v3Stage 'ff_win_v3_main.py') --help | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'RELEASE_RUNTIME_IMPORT_FAILED' }
$compileTargets = @(Get-ChildItem $transportStage,$v3Stage -Filter '*.py' -File | Select-Object -ExpandProperty FullName)
& $python -c 'import pathlib,sys; [compile(pathlib.Path(p).read_bytes(),p,''exec'') for p in sys.argv[1:]]' @compileTargets
if ($LASTEXITCODE -ne 0) { throw 'RELEASE_PYTHON_COMPILE_FAILED' }
foreach ($file in Get-ChildItem $transportStage -Filter '*.ps1') { [void][ScriptBlock]::Create((Get-Content $file.FullName -Raw)) }
if ($StageOnly) {
    $keepStage = $true
    [ordered]@{ok=$true;stage=$stage;python=$python;source_commit=$manifest.source_commit;verified_files=@($manifest.files.PSObject.Properties).Count;stage_policy='intentional-diagnostics-7-days-owner-cleanup';installed=$false} | ConvertTo-Json
    return
}
# StageOnly has no dependency writes outside the owned diagnostic stage.
$env:LOCALAPPDATA = $originalLocalAppData
$env:FF_BRIDGE_ROOT = $InstallRoot
$installedTools = Join-Path $InstallRoot 'tools'
New-Item -ItemType Directory -Path $installedTools -Force | Out-Null
Copy-FFPortableTree (Join-Path $stage 'tools') $installedTools
$pythonDirectory = Join-Path $installedTools ('python-' + $manifest.python_version + '-embed')
$python = Join-Path $pythonDirectory 'python.exe'
$gh = Get-FFPortableExecutable (Join-Path $installedTools 'github-cli') 'gh.exe'
$nodeDirectory = Split-Path -Parent (Get-FFPortableExecutable (Join-Path $installedTools 'node') 'node.exe')
$env:PATH = $nodeDirectory + ';' + (Split-Path -Parent $gh) + ';' + $originalPath
if ($RuntimeOnly -or $Transport -eq 'Local') {
    # Full local FF runtime, without provisioning a GitHub inbox or touching
    # ScheduledTasks/authentication. Reinstallation accepts only our marker.
    $localMarker = Join-Path $v3Root 'ff-local-owned-runtime.json'
    if ((Test-Path -LiteralPath $v3Root) -and -not (Test-Path -LiteralPath $localMarker)) { throw 'LOCAL_RUNTIME_FOREIGN_TARGET' }
    if (Test-Path -LiteralPath $localMarker) {
        $previousLocal = Get-Content -LiteralPath $localMarker -Raw | ConvertFrom-Json
        if ($previousLocal.schema -ne 'ff-local-owned-runtime-v1') { throw 'LOCAL_RUNTIME_OWNERSHIP_INVALID' }
        # Ownership alone does not permit replacing a different source build.
        # Version changes use a new shadow root and an explicit controlled cutover.
        if ([string]$previousLocal.source_commit -cne [string]$manifest.source_commit) {
            throw 'LOCAL_RUNTIME_UPGRADE_REQUIRES_CUTOVER'
        }
    }
    New-Item -ItemType Directory -Path $v3Root -Force | Out-Null
    Write-JsonAtomic $localMarker @{schema='ff-local-owned-runtime-v1';source_commit=$manifest.source_commit}
    Copy-FFPortableTree $v3Stage $v3Root
    # Paths resolve on every launch; moving the complete InstallRoot is safe.
    $start = @'
param([int]$Port=39073)
$ErrorActionPreference='Stop'
$env:FF_BRIDGE_ROOT=$PSScriptRoot
$env:PLAYWRIGHT_BROWSERS_PATH=Join-Path $PSScriptRoot 'bridge-v3\browsers'
$nodeRoot=Join-Path $PSScriptRoot 'tools\node'
$node=[IO.Directory]::EnumerateFiles(('\\?\'+$nodeRoot),'node.exe',[IO.SearchOption]::AllDirectories) | Select-Object -First 1
if(-not $node){throw 'BUNDLED_NODE_MISSING'}
$env:PATH=(Split-Path -Parent $node.Substring(4))+';'+$env:PATH
$python=Join-Path $PSScriptRoot 'tools\PYTHON_DIRECTORY\python.exe'
$lease=[IO.File]::Open((Join-Path $PSScriptRoot 'local-runtime.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$exitCode=1
try {
    # Hold the ownership lease across recovery; a second launcher cannot compete.
    $restarts=0
    while ($true) {
        & $python (Join-Path $PSScriptRoot 'bridge-v3\ff_win_v3_main.py') serve --port $Port
        $exitCode=$LASTEXITCODE
        # A clean shutdown is intentional. Persistent errors have a bounded budget.
        if ($exitCode -eq 0 -or $restarts -ge 3) { break }
        $restarts++
        Start-Sleep -Seconds ([int][Math]::Pow(2,$restarts))
    }
} finally { $lease.Dispose() }
exit $exitCode
'@
    $start = $start.Replace('PYTHON_DIRECTORY',('python-'+$manifest.python_version+'-embed'))
    [IO.File]::WriteAllText((Join-Path $InstallRoot 'Start-FF.ps1'),$start,[Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $InstallRoot 'START-FF.cmd'),"@echo off`r`npowershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"%~dp0Start-FF.ps1`" %*`r`n",[Text.ASCIIEncoding]::new())
    $localStartup = 'explicit-START-FF.cmd'
    $localHealth = $null
    if (-not $NoStartup) {
        Import-Module ScheduledTasks
        $fullRootHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($InstallRoot.ToLowerInvariant()))).Replace('-','')
        $localTaskName = 'FF-Local-' + $fullRootHash
        $description = 'FFBridge.Local owned ' + $fullRootHash
        $arguments = '-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + (Join-Path $InstallRoot 'Start-FF.ps1') + '" -Port ' + $RpcPort
        $executable = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $existing = Get-ScheduledTask -TaskName $localTaskName -ErrorAction SilentlyContinue
        if ($existing -and ($existing.Description -cne $description -or @($existing.Actions).Count -ne 1 -or $existing.Actions[0].Execute -ine $executable -or $existing.Actions[0].Arguments -cne $arguments)) { throw 'LOCAL_STARTUP_FOREIGN_TASK' }
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        $action = New-ScheduledTaskAction -Execute $executable -Argument $arguments
        Register-ScheduledTask -TaskName $localTaskName -InputObject (New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $description) -Force | Out-Null
        # The install lease is released before the runtime takes its own lease.
        $localInstallLease.Dispose();$localInstallLease=$null
        # Bootstrap in the installer's existing user token. An Interactive task
        # remains for future logon, but need not run immediately in a credential
        # process that does not own an interactive Windows session.
        $localLauncher = Start-Process -FilePath $executable -ArgumentList $arguments -WindowStyle Hidden -PassThru
        $localHealth = Wait-FFLocalRuntime -Root $InstallRoot -Port $RpcPort
        $localStartup = 'limited-interactive-logon-and-current-user-start'
    }
    [ordered]@{ok=$true;root=$InstallRoot;installed=$true;mode='full-local-runtime';startup=$localStartup;runtime_ready=($null -ne $localHealth);github_provisioned=$false;source_commit=$manifest.source_commit} | ConvertTo-Json
    return
}
Import-Module ScheduledTasks
# The operator is explicitly named and is never guessed from the laptop owner's local GitHub login.
# Never turn a public repo into a remote execution/control channel.
if ($Repository -notmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$') { throw 'REMOTE_REPOSITORY_INVALID' }
$repositoryOwner = ($Repository -split '/')[0]
if (-not $TrustedOperator) { $TrustedOperator = $repositoryOwner }
if ($TrustedOperator -notmatch '^[A-Za-z0-9-]{1,39}$') { throw 'REMOTE_TRUSTED_OPERATOR_INVALID' }
if ($TrustedOperator -ine $repositoryOwner) { throw 'REMOTE_OPERATOR_MUST_BE_REPOSITORY_OWNER' }
$token = $env:GH_TOKEN
if (-not $token) { try { $token = (& $gh auth token 2>$null | Out-String).Trim() } catch { $token = '' } }
if (-not $token) {
    if ($NonInteractive) { throw 'GH_AUTH_TOKEN_UNAVAILABLE' }
    & $gh auth login --hostname github.com --web --git-protocol https
    if ($LASTEXITCODE -ne 0) { throw 'GH_AUTH_FAILED' }
    $token = (& $gh auth token 2>$null | Out-String).Trim()
}
if (-not $token) { throw 'GH_AUTH_TOKEN_UNAVAILABLE' }
$headers = @{Authorization=('Bearer ' + $token);Accept='application/vnd.github+json';'X-GitHub-Api-Version'='2026-03-10'}
function Invoke-Repo($Method, $Suffix, $Body = $null) {
    $params = @{Uri=(('https://api.github.com/repos/' + $Repository + '/' + $Suffix).TrimEnd('/'));Headers=$headers;Method=$Method;UseBasicParsing=$true;TimeoutSec=30}
    if ($null -ne $Body) { $params.ContentType='application/json';$params.Body=($Body | ConvertTo-Json -Depth 20 -Compress) }
    Invoke-RestMethod @params
}
$repoInfo = Invoke-Repo GET ''
if (-not $repoInfo.private) { throw 'REMOTE_GITHUB_REPOSITORY_MUST_BE_PRIVATE' }
if (-not $repoInfo.permissions.push) { throw 'GITHUB_REPOSITORY_WRITE_ACCESS_REQUIRED' }
$userInfo = Invoke-RestMethod -Uri 'https://api.github.com/user' -Headers $headers -UseBasicParsing
$device = $Device
$configPath = Join-Path $root 'github_transport_config.json'
$previous = if (Test-Path $configPath) { Get-Content $configPath -Raw | ConvertFrom-Json } else { $null }
if ($InboxIssue -le 0 -and $previous -and $previous.repository -eq $Repository) { $InboxIssue = [int]$previous.inbox_issue }
if ($InboxIssue -le 0) {
    $matches = @()
    for ($page=1; $page -le 50; $page++) {
        $listing = Invoke-Repo GET ('issues?state=open&per_page=100&page=' + $page)
        $issues = @($listing)
        $matches += @($issues | Where-Object { $_.title -eq ('[FF-GH-INBOX] ' + $device) -or $_.title.StartsWith('[FF-GH-INBOX] ' + $device + ' generation ') })
        if ($issues.Count -lt 100) { break }
    }
    if ($matches.Count) { $InboxIssue = [int](@($matches | Sort-Object { [int]$_.number } -Descending)[0].number) }
    else {
        $metadata = @{device=$device;generation=0} | ConvertTo-Json -Compress
        $created = Invoke-Repo POST 'issues' @{title=('[FF-GH-INBOX] ' + $device);body=('FF_GH_INBOX_V2 ' + $metadata + "`nPersistent GitHub Windows inbox. Do not delete.")}
        $InboxIssue = [int]$created.number
    }
}
for ($n=0; $n -lt 100; $n++) {
    $issue = Invoke-Repo GET ('issues/' + $InboxIssue)
    $first = ([string]$issue.body -split "`n")[0]
    if ($first.StartsWith('FF_GH_INBOX_V2 ')) {
        $metadata = $first.Substring(15) | ConvertFrom-Json
        if ($metadata.PSObject.Properties['redirect']) { $InboxIssue=[int]$metadata.redirect;continue }
    }
    break
}
$defaultRoot = [IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge'))
$rootHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($InstallRoot.ToLowerInvariant()))).Replace('-','').Substring(0,10)
$suffix = if ($InstallRoot -ieq $defaultRoot) { '' } else { '-' + $rootHash }
$taskName = 'FF-Windows-GitHub-Transport' + $suffix
$v3TaskName = 'FF-GitHub-V3' + $suffix
$backup = Join-Path $InstallRoot ('backups\github-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
New-Item -ItemType Directory -Path $backup -Force | Out-Null
if (Test-Path $root) { Get-ChildItem -LiteralPath $root -File | Where-Object { $_.Name -ne 'comment_transport.lock' } | Copy-Item -Destination $backup }
$journal = Join-Path $InstallRoot 'fast-transport\transport_journal.sqlite3'
if (Test-Path $journal) {
    & $python -c 'import sqlite3,sys; source=sqlite3.connect(sys.argv[1]); destination=sqlite3.connect(sys.argv[2]); source.backup(destination); destination.close(); source.close()' $journal (Join-Path $backup 'transport_journal.sqlite3')
    if ($LASTEXITCODE -ne 0) { throw 'JOURNAL_BACKUP_FAILED' }
}
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) { Export-ScheduledTask -TaskName $taskName | Set-Content (Join-Path $backup 'scheduled-task.xml');Stop-ScheduledTask -TaskName $taskName }
$oldLogonTask = Get-ScheduledTask -TaskName ($taskName + '-Logon') -ErrorAction SilentlyContinue
if ($oldLogonTask) { Stop-ScheduledTask -TaskName ($taskName + '-Logon') }
$keeperPath = Join-Path $root 'ff_win_github_transport_keeper.ps1'
$daemonPath = Join-Path $root 'ff_win_github_comment_daemon.py'
Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -and (($_.Name -ieq 'python.exe' -and $_.CommandLine.Contains($daemonPath)) -or
                         ($_.Name -in @('powershell.exe','pwsh.exe') -and $_.CommandLine.Contains($keeperPath)))
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
$freshV3 = -not (Test-Path (Join-Path $v3Root 'ff_win_v3_main.py'))
$v3OwnedMarker = Join-Path $v3Root 'ff-gh-owned-runtime.json'
$managedV3 = $freshV3 -or (Test-Path -LiteralPath $v3OwnedMarker)
New-Item -ItemType Directory -Path $root -Force | Out-Null
foreach ($file in Get-ChildItem -LiteralPath $transportStage -File) { Copy-Item -LiteralPath $file.FullName -Destination $root -Force }
if ($managedV3) {
    New-Item -ItemType Directory -Path $v3Root -Force | Out-Null
    # The marker is committed before copying, so a interrupted first install
    # repairs this owned runtime rather than mistaking it for someone else's V3.
    Write-JsonAtomic $v3OwnedMarker @{schema='ff-gh-owned-v3-v1';source_commit=$manifest.source_commit}
    $oldManaged = Get-ScheduledTask -TaskName $v3TaskName -ErrorAction SilentlyContinue
    if ($oldManaged) { Stop-ScheduledTask -TaskName $v3TaskName }
    $managedMain = Join-Path $v3Root 'ff_win_v3_main.py'
    Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq 'python.exe' -and $_.CommandLine -and $_.CommandLine.Contains($managedMain) } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Copy-FFPortableTree $v3Stage $v3Root
    [IO.File]::WriteAllText((Join-Path $v3Root 'python-path.txt'), $python)
}
$config = [ordered]@{schema='ff-win-github-transport-config-v2';repository=$Repository;branch=$Branch;device=$device;
    inbox_issue=$InboxIssue;results_branch=$ResultsBranch;python_path=$python;gh_path=$gh;
    rpc_url=('http://127.0.0.1:' + $RpcPort + '/rpc');allowed_senders=@([string]$TrustedOperator);
    source_commit=$manifest.source_commit;rotation_comments=1000;installed_at=[DateTimeOffset]::UtcNow.ToString('o')}
if ($previous -and $previous.PSObject.Properties['archived_inboxes']) { $config.archived_inboxes=$previous.archived_inboxes }
Write-JsonAtomic $configPath $config
Copy-Item $manifestPath (Join-Path $root 'release-manifest.json') -Force
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
function Register-Keeper($Name, $Arguments) {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $Arguments
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal
    Register-ScheduledTask -TaskName $Name -InputObject $task -Force | Out-Null
    Start-ScheduledTask -TaskName $Name
}
if ($managedV3) { Register-Keeper $v3TaskName ('-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + (Join-Path $root 'ff_win_github_v3_keeper.ps1') + '" -Root "' + $v3Root + '" -Python "' + $python + '" -Port ' + $RpcPort) }
# S4U uses this same user's existing credential store. No Windows password,
# SYSTEM token copy, or plaintext token file is created.
$probeName = 'FF-GitHub-Prelogin-Probe' + $suffix
$probeOutput = Join-Path $root 'prelogin-capability.json'
Remove-Item -LiteralPath $probeOutput -Force -ErrorAction SilentlyContinue
$prelogin = $false
try {
    $s4uPrincipal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Limited
    $probeArguments = '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + (Join-Path $root 'ff_win_github_prelogin_probe.ps1') + '" -GhPath "' + $gh + '" -Repository "' + $Repository + '" -Output "' + $probeOutput + '"'
    $probeAction = New-ScheduledTaskAction -Execute powershell.exe -Argument $probeArguments
    Register-ScheduledTask -TaskName $probeName -InputObject (New-ScheduledTask -Action $probeAction -Principal $s4uPrincipal -Settings $settings) -Force | Out-Null
    Start-ScheduledTask -TaskName $probeName
    $probeDeadline = (Get-Date).AddSeconds(40)
    while ((Get-Date) -lt $probeDeadline -and -not (Test-Path $probeOutput)) { Start-Sleep -Milliseconds 500 }
    if (Test-Path $probeOutput) {
        $probe = Get-Content $probeOutput -Raw | ConvertFrom-Json
        $prelogin = [bool]($probe.github_read -and $probe.credential_available -and $probe.session_id -eq 0)
    }
} catch { $prelogin = $false }
finally { Unregister-ScheduledTask -TaskName $probeName -Confirm:$false -ErrorAction SilentlyContinue }
if ($prelogin) {
    $principal = $s4uPrincipal
    $trigger = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn -User $user))
    $backgroundTaskName = 'FF-GitHub-Background' + $suffix
    $oldBackground = Get-ScheduledTask -TaskName $backgroundTaskName -ErrorAction SilentlyContinue
    if ($oldBackground) { Stop-ScheduledTask -TaskName $backgroundTaskName }
    $backgroundAgent = Join-Path $root 'ff_win_github_background_agent.py'
    $backgroundKeeper = Join-Path $root 'ff_win_github_background_keeper.ps1'
    Get-CimInstance Win32_Process | Where-Object {
        $_.ProcessId -ne $PID -and $_.CommandLine -and
        (($_.Name -ieq 'python.exe' -and $_.CommandLine.Contains($backgroundAgent)) -or
         ($_.Name -ieq 'powershell.exe' -and $_.CommandLine.Contains($backgroundKeeper)))
    } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    $backgroundPort = $RpcPort + 2
    $config.background_rpc_url = 'http://127.0.0.1:' + $backgroundPort + '/rpc'
    $config.autostart_mode = 'startup-s4u-and-logon'
    Write-JsonAtomic $configPath $config
    Register-Keeper $backgroundTaskName ('-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $backgroundKeeper + '" -Root "' + $root + '" -Python "' + $python + '" -Port ' + $backgroundPort)
} else {
    $config.autostart_mode = 'interactive-logon'
    Write-JsonAtomic $configPath $config
    Write-Host 'This PC requires Windows login for GitHub control. No password or token was copied.'
}
Register-Keeper $taskName ('-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $keeperPath + '" -Root "' + $root + '"')
if ($prelogin) {
    # One active keeper owns the shared mutex. This separate interactive
    # trigger covers a cold boot whose S4U credential access differs from the
    # install-time probe; it is an automatic fallback, never an activation step.
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    Register-Keeper ($taskName + '-Logon') ('-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $keeperPath + '" -Root "' + $root + '"')
} elseif ($oldLogonTask) {
    Disable-ScheduledTask -TaskName ($taskName + '-Logon') | Out-Null
}
$deadline = (Get-Date).AddSeconds(90)
$healthy = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 1
    $raw = & powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'ff_win_github_transport_health.ps1') -Root $root
    try { $health=$raw | ConvertFrom-Json; if ($health.ok) {$healthy=$true;break} } catch {}
}
if (-not $healthy) { throw 'INSTALL_HEALTH_FAILED - rerun START-HERE.cmd; local backup is retained.' }
& powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'ff_win_github_smoke_test.ps1') -Root $root -TimeoutSeconds 90
if ($LASTEXITCODE -ne 0) { throw 'INSTALL_SMOKE_FAILED - installation is not marked DONE.' }
[ordered]@{ok=$true;root=$root;inbox_issue=$InboxIssue;task=$taskName;prelogin=$prelogin;source_commit=$manifest.source_commit;backup=$backup;post_install_smoke='PASS'} | ConvertTo-Json
} finally {
    if ($localInstallLease) { $localInstallLease.Dispose() }
    $env:LOCALAPPDATA = $originalLocalAppData
    $env:PATH = $originalPath
    $env:FF_BRIDGE_ROOT = $originalBridgeRoot
    $env:PLAYWRIGHT_BROWSERS_PATH = $originalBrowserPath
    try { if (-not $keepStage) { Remove-FFOwnedStage $ownedStage } }
    finally { $ownedStage.pin.Dispose() }
}
