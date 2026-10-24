<#
.SYNOPSIS
    Idempotent, safe stop command for all FF-Windows-Bridge processes.
.DESCRIPTION
    Cleanly and definitively terminates all running Bridge processes (keeper, agent,
    relay, continuation daemon, watchers, and sidecars) without touching user applications
    such as Chrome, Notepad, Word, or VPN/FlClash.
#>
[CmdletBinding()]
param(
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$root = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\bridge-v3'
$continuationsRoot = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\continuations'
$stoppedPids = [System.Collections.Generic.List[int]]::new()
$stoppedDetails = [System.Collections.Generic.List[string]]::new()

function Stop-SafeProcessById([int]$ProcessId, [string]$Reason) {
    if ($ProcessId -le 0 -or $ProcessId -eq $PID) { return }
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($null -eq $proc) { return }
        $procName = $proc.ProcessName.ToLowerInvariant()

        # Strict safety guardrails: NEVER kill user applications or VPN
        if ($procName -in @('chrome', 'msedge', 'firefox', 'flclash', 'clash', 'explorer', 'taskmgr')) {
            return
        }

        # Kill process tree cleanly
        try {
            & taskkill.exe /PID $ProcessId /T /F 2>$null | Out-Null
        } catch {
            $proc.Kill()
        }
        $stoppedPids.Add($ProcessId)
        $stoppedDetails.Add(("{0} (PID {1})" -f $Reason, $ProcessId))
    } catch {}
}

# 1. Stop keeper recorded in keeper.pid
$keeperPidFile = Join-Path $root 'keeper.pid'
if (Test-Path -LiteralPath $keeperPidFile -PathType Leaf) {
    try {
        $kpid = [int]((Get-Content -LiteralPath $keeperPidFile -Raw).Trim())
        Stop-SafeProcessById $kpid 'keeper_pid'
    } catch {}
    Remove-Item -LiteralPath $keeperPidFile -Force -ErrorAction SilentlyContinue
}

# 2. Stop agent recorded in agent.pid
$agentPidFile = Join-Path $root 'agent.pid'
if (Test-Path -LiteralPath $agentPidFile -PathType Leaf) {
    try {
        $apid = [int]((Get-Content -LiteralPath $agentPidFile -Raw).Trim())
        Stop-SafeProcessById $apid 'agent_pid'
    } catch {}
    Remove-Item -LiteralPath $agentPidFile -Force -ErrorAction SilentlyContinue
}

# 3. Stop continuation daemon and watchers
if (Test-Path -LiteralPath $continuationsRoot -PathType Container) {
    # Daemon PID
    $daemonPidFile = Join-Path $continuationsRoot 'continuation_daemon.pid'
    if (Test-Path -LiteralPath $daemonPidFile -PathType Leaf) {
        try {
            $raw = Get-Content -LiteralPath $daemonPidFile -Raw
            $dpid = if ($raw.Trim().StartsWith('{')) { [int]((ConvertFrom-Json $raw).pid) } else { [int]($raw.Trim()) }
            Stop-SafeProcessById $dpid 'continuation_daemon_pid'
        } catch {}
        Remove-Item -LiteralPath $daemonPidFile -Force -ErrorAction SilentlyContinue
    }
    # Watcher PIDs
    Get-ChildItem -LiteralPath $continuationsRoot -Filter "*.watcher.pid" -File -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $raw = Get-Content -LiteralPath $_.FullName -Raw
            $wpid = if ($raw.Trim().StartsWith('{')) { [int]((ConvertFrom-Json $raw).pid) } else { [int]($raw.Trim()) }
            Stop-SafeProcessById $wpid ('watcher_' + $_.BaseName)
        } catch {}
        Remove-Item -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue
    }
}

# 4. Find any remaining Bridge processes by command line / binary path
try {
    $bridgeProcs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $cmd = [string]$_.CommandLine
        $name = [string]$_.Name
        $path = [string]$_.ExecutablePath
        (
            ($cmd -match '(?i)bridge-v3-keeper-launch\.ps1') -or
            ($cmd -match '(?i)ff_win_v3_keeper\.ps1') -or
            ($cmd -match '(?i)ff_win_v3_main\.py') -or
            ($cmd -match '(?i)run_fast_transport\.cmd') -or
            ($cmd -match '(?i)ff_win_fast_transport_daemon_v2\.py') -or
            ($cmd -match '(?i)cua_session_continuation\.py') -or
            ($cmd -match '(?i)desktop-commander.*dist[\\/]index\.js') -or
            ($name -ieq 'cua_native_uia3_sidecar.exe') -or
            ($name -ieq 'cua_browser_companion_host.exe')
        ) -and
        ($name -notin @('chrome.exe', 'msedge.exe', 'flclash.exe', 'clash.exe'))
    })
    foreach ($bp in $bridgeProcs) {
        Stop-SafeProcessById ([int]$bp.ProcessId) ('cim_discovery_' + $bp.Name)
    }
} catch {}

# 5. Clean up stale lock files
$deployLock = Join-Path $root '.cua-runtime-deploy-lock.json'
Remove-Item -LiteralPath $deployLock -Force -ErrorAction SilentlyContinue

# 6. Truthful stop verification. A watchdog/launcher left behind means STOP did not succeed.
Start-Sleep -Seconds 4
$residual = @()
try {
    $residual = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $cmd = [string]$_.CommandLine
        $name = [string]$_.Name
        (
            ($cmd -match '(?i)bridge-v3-keeper-launch\.ps1') -or
            ($cmd -match '(?i)ff_win_v3_keeper\.ps1') -or
            ($cmd -match '(?i)ff_win_v3_main\.py') -or
            ($cmd -match '(?i)run_fast_transport\.cmd') -or
            ($cmd -match '(?i)ff_win_fast_transport_daemon_v2\.py') -or
            ($cmd -match '(?i)cua_session_continuation\.py') -or
            ($cmd -match '(?i)desktop-commander.*dist[\\/]index\.js') -or
            ($name -ieq 'cua_native_uia3_sidecar.exe') -or
            ($name -ieq 'cua_browser_companion_host.exe')
        ) -and
        ($name -notin @('chrome.exe', 'msedge.exe', 'flclash.exe', 'clash.exe', 'explorer.exe'))
    } | ForEach-Object {
        [pscustomobject]@{ pid=[int]$_.ProcessId; name=[string]$_.Name; command_line=[string]$_.CommandLine }
    })
} catch {}

$ok = ($residual.Count -eq 0)
$result = [ordered]@{
    ok = $ok
    status = if ($ok) { 'STOPPED' } else { 'STOP_FAILED' }
    stopped_count = $stoppedPids.Count
    stopped_processes = @($stoppedDetails)
    residual_count = $residual.Count
    residual_processes = @($residual)
    timestamp = [DateTime]::UtcNow.ToString('o')
}

$result | ConvertTo-Json -Depth 6 -Compress
if ($ok) { exit 0 } else { exit 8 }
