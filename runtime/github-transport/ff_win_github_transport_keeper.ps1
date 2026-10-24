param(
    [string]$Root = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\github-transport')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Path $Root -Force | Out-Null

# A boot S4U context lacking credentials must not own the cross-session mutex
# and prevent a healthy interactive logon fallback from taking control.
try {
    $preflightConfig = Get-Content (Join-Path $Root 'github_transport_config.json') -Raw | ConvertFrom-Json
    $preflightGh = if ($preflightConfig.PSObject.Properties['gh_path']) { [string]$preflightConfig.gh_path } else { 'gh.exe' }
    $preflightToken = (& $preflightGh auth token 2>$null | Out-String).Trim()
    if (-not $preflightToken) { exit 1 }
    $preflightToken = $null
} catch { exit 1 }

$mutex = $null
$owned = $false
$rootHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($Root).ToLowerInvariant()))).Replace('-','').Substring(0,16)
try {
    try { $mutex = [System.Threading.Mutex]::new($false, ('Global\FF-Windows-GitHub-Transport-' + $rootHash)) }
    catch { $mutex = [System.Threading.Mutex]::new($false, ('Local\FF-Windows-GitHub-Transport-' + $rootHash)) }
    try { $owned = $mutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) { exit 0 }

    $configPath = Join-Path $Root 'github_transport_config.json'
    $daemon = Join-Path $Root 'ff_win_github_comment_daemon.py'
    $log = Join-Path $Root 'github-transport-keeper.log'
    while ($true) {
        try {
            if (-not (Test-Path -LiteralPath $daemon -PathType Leaf)) { throw 'DAEMON_MISSING' }
            if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) { throw 'CONFIG_MISSING' }
            $cfg = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json

            $portable = Join-Path (Split-Path -Parent $Root) 'tools\python-3.13.9-embed\python.exe'
            if ($cfg.PSObject.Properties['python_path']) { $portable = [string]$cfg.python_path }
            if (Test-Path -LiteralPath $portable -PathType Leaf) { $python = $portable }
            else {
                $cmd = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
                if (-not $cmd) { throw 'PYTHON_MISSING' }
                $python = $cmd.Source
            }

            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $python
            $psi.Arguments = '"' + $daemon + '"'
            $psi.WorkingDirectory = $Root
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            $psi.EnvironmentVariables['FF_GH_HOME'] = $Root
            $psi.EnvironmentVariables['FF_BRIDGE_ROOT'] = Split-Path -Parent $Root
            if ($cfg.PSObject.Properties['gh_path']) { $psi.EnvironmentVariables['PATH'] = (Split-Path -Parent ([string]$cfg.gh_path)) + ';' + $psi.EnvironmentVariables['PATH'] }
            # The daemon reads current config, including rotated inbox state.
            $psi.EnvironmentVariables.Remove('FF_GH_INBOX_ISSUE')
            if ($cfg.results_branch) { $psi.EnvironmentVariables['FF_GH_RESULTS_BRANCH'] = [string]$cfg.results_branch }
            @('FF_TRANSPORT_TEST_MODE','FF_TRANSPORT_FAULT_DIR','FF_GH_API_HOST') | ForEach-Object { $psi.EnvironmentVariables.Remove($_) }
            @($psi.EnvironmentVariables.Keys) | ForEach-Object {
                $key = [string]$_
                if ($key -eq 'RUNNER_TRACKING_ID' -or $key -like 'ACTIONS_*') { $psi.EnvironmentVariables.Remove($key) }
            }

            $process = [System.Diagnostics.Process]::Start($psi)
            $process.WaitForExit()
            $line = ('{0:o} daemon_exit={1}' -f (Get-Date), $process.ExitCode)
        } catch {
            $line = ('{0:o} keeper_error={1}' -f (Get-Date), [string]$_.Exception.Message)
        }
        try {
            Add-Content -LiteralPath $log -Value $line -Encoding UTF8
            $lines = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue)
            if ($lines.Count -gt 300) { Set-Content -LiteralPath $log -Value ($lines | Select-Object -Last 200) -Encoding UTF8 }
        } catch {}
        Start-Sleep -Seconds 2
    }
} finally {
    if ($owned -and $mutex) { try { $mutex.ReleaseMutex() } catch {} }
    if ($mutex) { try { $mutex.Dispose() } catch {} }
}
