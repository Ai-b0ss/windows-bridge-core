param(
    [string]$InstallRoot = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge')
)
$ErrorActionPreference = 'Stop'
$InstallRoot = [IO.Path]::GetFullPath($InstallRoot)
$transportRoot = Join-Path $InstallRoot 'github-transport'
$config = Join-Path $transportRoot 'github_transport_config.json'
if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
    Write-Host 'NO_REMOTE_PAIRING_CONFIG_FOUND'
    exit 0
}
$cfg = Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
if ($cfg.schema -ne 'ff-win-github-transport-config-v2') {
    throw 'REMOTE_CONFIG_UNKNOWN_SCHEMA'
}
if ($cfg.repository -ne 'Ai-b0ss/windows-bridge-support-20261024') {
    throw 'REMOTE_CONFIG_FOREIGN_REPOSITORY'
}
$prefixes = @('FF-Windows-GitHub-Transport','FF-GitHub-V3','FF-GitHub-Background')
$roots = @($transportRoot,(Join-Path $InstallRoot 'bridge-v3'))
$matched = @()
foreach ($task in @(Get-ScheduledTask -ErrorAction Stop)) {
    $allowedName = $false
    foreach ($prefix in $prefixes) {
        if ($task.TaskName -eq $prefix -or $task.TaskName.StartsWith($prefix + '-')) { $allowedName = $true; break }
    }
    if (-not $allowedName) { continue }
    $owned = $false
    foreach ($action in $task.Actions) {
        foreach ($expected in $roots) {
            if ($action.Arguments -and $action.Arguments.IndexOf($expected,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $owned = $true
            }
        }
    }
    if ($owned) { $matched += $task }
}
foreach ($task in $matched) {
    Stop-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
}
# Stop only processes whose command lines identify this precise owned transport runtime.
# A GitHub-managed-only Bridge v3 agent must stop when remote support is disabled.
# If a separately-installed local agent exists, leave it running on loopback.
$ghV3Marker = Join-Path $InstallRoot 'bridge-v3\ff-gh-owned-runtime.json'
$ownedPaths = @(
    (Join-Path $transportRoot 'ff_win_github_comment_daemon.py'),
    (Join-Path $transportRoot 'ff_win_github_transport_keeper.ps1'),
    (Join-Path $transportRoot 'ff_win_github_background_agent.py'),
    (Join-Path $transportRoot 'ff_win_github_background_keeper.ps1'),
    (Join-Path $transportRoot 'ff_win_github_v3_keeper.ps1')
)
if (Test-Path -LiteralPath $ghV3Marker -PathType Leaf) {
    $ownedPaths += (Join-Path $InstallRoot 'bridge-v3\ff_win_v3_main.py')
}
foreach ($proc in @(Get-CimInstance Win32_Process)) {
    if ($proc.ProcessId -eq $PID -or -not $proc.CommandLine) { continue }
    if ($proc.Name -notin @('python.exe','pythonw.exe','powershell.exe','pwsh.exe')) { continue }
    $owned = $false
    foreach ($expected in $ownedPaths) {
        if ($proc.CommandLine.IndexOf($expected,[StringComparison]::OrdinalIgnoreCase) -ge 0) {$owned=$true; break}
    }
    if ($owned) { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue }
}
Write-Host ('REMOTE_SUPPORT_DISABLED tasks=' + $matched.Count)
Write-Host 'Also ask the owner to revoke this GitHub account from the private transport repository.'
