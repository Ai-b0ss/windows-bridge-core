param([switch]$ProbeRelayCloud)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

# ProbeRelayCloud is diagnostic-only and must not contend for keeper ownership
# or publish keeper.pid. The long-lived mode below retains the named mutex as
# the atomic ownership boundary for all real keeper instances.
$keeperMutex = $null
$keeperMutexOwned = $false
if (-not $ProbeRelayCloud) {
    try {
        try {
            $keeperMutex = [System.Threading.Mutex]::new($false, 'Global\FF-Windows-Bridge-V3-Keeper')
        } catch {
            $keeperMutex = [System.Threading.Mutex]::new($false, 'Local\FF-Windows-Bridge-V3-Keeper')
        }
        try {
            $keeperMutexOwned = $keeperMutex.WaitOne(0)
        } catch [System.Threading.AbandonedMutexException] {
            $keeperMutexOwned = $true
        }
        if (-not $keeperMutexOwned) {
            try { $keeperMutex.Dispose() } catch {}
            exit 0
        }
    } catch {
        try { if ($keeperMutex) { $keeperMutex.Dispose() } } catch {}
        exit 1
    }
}

$root = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\bridge-v3'
$agent = Join-Path $root 'ff_win_v3_main.py'
$secretPath = Join-Path $root 'secret'
$keeperPidPath = Join-Path $root 'keeper.pid'
$pythonPathFile = Join-Path $root 'python-path.txt'
$relayEgressPath = Join-Path $root 'relay-egress.txt'
$relayWatchdogLog = Join-Path $root 'relay-watchdog.log'
$relayDeviceConfigPath = Join-Path $env:USERPROFILE '.desktop-commander-device\device.json'
$relayPackageJsonPath = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\commander-runtime\node_modules\@wonderwhy-er\desktop-commander\package.json'
$relayRuntimePath = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\commander-runtime\node_modules\@wonderwhy-er\desktop-commander\dist\index.js'
$relayStdoutPath = Join-Path $root 'commander-remote.out.log'
$relayStderrPath = Join-Path $root 'commander-remote.err.log'
$continuationsRoot = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\continuations'
$continuationDaemonPidPath = Join-Path $continuationsRoot 'continuation_daemon.pid'
$continuationDaemon = Join-Path $root 'cua_session_continuation.py'
$ownerChromeBootstrap = Join-Path $root 'cua_owner_chrome_logon.ps1'
$runtimeDeployLock = Join-Path $root '.cua-runtime-deploy-lock.json'
$port = 39073

if (-not $ProbeRelayCloud) {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    Set-Content -LiteralPath $keeperPidPath -Value $PID -Encoding ASCII
}

function Write-FF3RelayWatchdogLog([string]$Message) {
    try {
        $line = ('{0:o} {1}' -f (Get-Date), $Message)
        Add-Content -LiteralPath $relayWatchdogLog -Value $line -Encoding UTF8
        $lines = @(Get-Content -LiteralPath $relayWatchdogLog -ErrorAction SilentlyContinue)
        if ($lines.Count -gt 300) { Set-Content -LiteralPath $relayWatchdogLog -Value ($lines | Select-Object -Last 200) -Encoding UTF8 }
    } catch {}
}

function Get-FF3Python {
    if (Test-Path -LiteralPath $pythonPathFile -PathType Leaf) {
        $candidate = (Get-Content -LiteralPath $pythonPathFile -Raw).Trim()
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $candidate }
    }
    $portable = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\tools\python-3.13.9-embed\python.exe'
    if (Test-Path -LiteralPath $portable -PathType Leaf) { return $portable }
    $cmd = Get-Command python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    return $null
}

function Test-FF3Agent {
    if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) {
        Write-FF3RelayWatchdogLog 'agent_health_failure:secret_missing'
        return $false
    }
    try {
        $secret = (Get-Content -LiteralPath $secretPath -Raw).Trim()
        if (-not $secret) { return $false }
        $headers = @{ 'X-FF3-Key' = $secret }
        $response = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:$port/health" -Headers $headers -Method Get -TimeoutSec 2
        return [bool]$response.ok
    } catch {
        Write-FF3RelayWatchdogLog ('agent_health_failure:' + $_.Exception.GetType().Name)
        return $false
    }
}

function Get-FF3DirectRelayProcesses {
    try {
        $runtimePattern = [regex]::Escape($relayRuntimePath)
        return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -ieq 'node.exe' -and
            $_.CommandLine -and
            ($_.CommandLine -match $runtimePattern) -and
            ($_.CommandLine -match '(?i)\sremote(?:\s|$)')
        })
    } catch { return @() }
}

function Test-FF3DirectRelay {
    return (@(Get-FF3DirectRelayProcesses).Count -eq 1)
}

function Get-FF3RelayRuntimeVersion {
    try {
        if (-not (Test-Path -LiteralPath $relayPackageJsonPath -PathType Leaf)) { return $null }
        $pkg = Get-Content -LiteralPath $relayPackageJsonPath -Raw | ConvertFrom-Json
        return [string]$pkg.version
    } catch { return $null }
}

function Test-FF3RelayRuntimeVersion {
    $versionText = Get-FF3RelayRuntimeVersion
    if (-not $versionText) { return $false }
    try { return ([version]$versionText -ge [version]'0.2.51') } catch { return $false }
}

function Get-FF3ContinuationDaemonProcesses {
    try {
        if (Test-Path -LiteralPath $continuationDaemonPidPath -PathType Leaf) {
            $raw = (Get-Content -LiteralPath $continuationDaemonPidPath -Raw).Trim()
            $dpid = if ($raw.StartsWith('{')) { [int]((ConvertFrom-Json $raw).pid) } else { [int]$raw }
            $proc = Get-Process -Id $dpid -ErrorAction SilentlyContinue
            if ($null -ne $proc -and $proc.ProcessName -ieq 'python') {
                return @($proc)
            }
        }
        $escaped = [regex]::Escape($continuationDaemon)
        return @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
            $_.CommandLine -and ($_.CommandLine -match $escaped) -and ($_.CommandLine -match '(?i)\sdaemon(?:\s|$)')
        })
    } catch { return @() }
}

function Test-FF3ContinuationDaemon {
    return (@(Get-FF3ContinuationDaemonProcesses).Count -gt 0)
}

function Start-FF3ContinuationDaemon {
    $python = Get-FF3Python
    if (-not $python -or -not (Test-Path -LiteralPath $continuationDaemon -PathType Leaf)) { return $false }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $python
    $psi.Arguments = '"' + $continuationDaemon + '" daemon --interval 2'
    $psi.WorkingDirectory = $root
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    try { [System.Diagnostics.Process]::Start($psi) | Out-Null; return $true } catch { return $false }
}

function Stop-FF3DirectRelay {
    $matches = @(Get-FF3DirectRelayProcesses)
    if ($matches.Count -eq 0) { return }
    $ids = @($matches | ForEach-Object { [int]$_.ProcessId } | Sort-Object -Unique)
    foreach ($id in $ids) {
        try { & taskkill.exe /PID $id /T /F 2>$null | Out-Null } catch {}
    }
    Start-Sleep -Milliseconds 800
}

function Start-FF3DirectRelay {
    $node = Get-Command node.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $node -or -not (Test-Path -LiteralPath $relayRuntimePath -PathType Leaf)) { return $false }
    if (-not (Test-FF3RelayRuntimeVersion)) {
        Write-FF3RelayWatchdogLog ('relay_start_blocked_runtime_version:' + [string](Get-FF3RelayRuntimeVersion))
        return $false
    }

    $cmdArgs = '/d /s /c ""' + $node.Source + '" "' + $relayRuntimePath + '" remote --debug 1>>"' + $relayStdoutPath + '" 2>>"' + $relayStderrPath + '""'
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $env:ComSpec
    $psi.Arguments = $cmdArgs
    $psi.WorkingDirectory = $env:USERPROFILE
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    @($psi.EnvironmentVariables.Keys) | ForEach-Object {
        $key = [string]$_
        if ($key -eq 'RUNNER_TRACKING_ID' -or $key -like 'GITHUB_*' -or $key -like 'ACTIONS_*') { $psi.EnvironmentVariables.Remove($key) }
    }
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
        Write-FF3RelayWatchdogLog ('relay_start_requested:runtime=' + [string](Get-FF3RelayRuntimeVersion))
        return $true
    } catch {
        Write-FF3RelayWatchdogLog ('relay_start_failed:' + [string]$_.Exception.Message)
        return $false
    }
}

function Restart-FF3DirectRelay([string]$Reason, [int]$CooldownSeconds = 900) {
    $now = Get-Date
    if ($script:lastRelayRestart -ne [datetime]::MinValue -and ($now - $script:lastRelayRestart).TotalSeconds -lt $CooldownSeconds) {
        Write-FF3RelayWatchdogLog ('relay_restart_suppressed:' + $Reason)
        return $false
    }
    $script:lastRelayRestart = $now
    Write-FF3RelayWatchdogLog ('relay_restart:' + $Reason)
    Stop-FF3DirectRelay
    Start-Sleep -Seconds 1
    Start-FF3DirectRelay | Out-Null
    Start-Sleep -Seconds 4
    return $true
}

function Get-FF3EgressIp {
    try {
        $value = (Invoke-RestMethod -UseBasicParsing -Uri 'https://api.ipify.org' -Method Get -TimeoutSec 4)
        $text = ([string]$value).Trim()
        if ($text -match '^[0-9A-Fa-f:.]{3,64}$') { return $text }
    } catch {}
    return $null
}

function Test-FF3RelayEndpoint {
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri 'https://mcp.desktopcommander.app/api/mcp-info' -Method Get -TimeoutSec 4
        return ([int]$response.StatusCode -ge 200 -and [int]$response.StatusCode -lt 500)
    } catch { return $false }
}

function Test-FF3DirectRelayCloud([ref]$Reason) {
    $Reason.Value = 'unknown'
    if (-not (Test-Path -LiteralPath $relayDeviceConfigPath -PathType Leaf)) {
        $Reason.Value = 'config_missing'
        return $false
    }

    try {
        $config = Get-Content -LiteralPath $relayDeviceConfigPath -Raw | ConvertFrom-Json
        $deviceId = [string]$config.deviceId
        $accessToken = [string]$config.session.access_token
        if (-not $deviceId -or -not $accessToken) {
            $Reason.Value = 'config_incomplete'
            return $false
        }

        $mcpInfo = Invoke-RestMethod -UseBasicParsing -Uri 'https://mcp.desktopcommander.app/api/mcp-info' -Method Get -TimeoutSec 5
        $supabaseUrl = [string]$mcpInfo.supabaseUrl
        $publishableKey = [string]$mcpInfo.supabasePublishableKey
        if (-not $publishableKey) { $publishableKey = [string]$mcpInfo.supabaseAnonKey }
        if (-not $supabaseUrl -or -not $publishableKey) {
            $Reason.Value = 'mcp_info_incomplete'
            return $false
        }

        $headers = @{
            'apikey' = $publishableKey
            'Authorization' = 'Bearer ' + $accessToken
        }
        $encodedId = [uri]::EscapeDataString($deviceId)
        $uri = $supabaseUrl.TrimEnd('/') + '/rest/v1/mcp_devices?id=eq.' + $encodedId + '&select=id,status,last_seen,capabilities'
        $rows = @(Invoke-RestMethod -UseBasicParsing -Uri $uri -Headers $headers -Method Get -TimeoutSec 5)
        if ($rows.Count -ne 1) {
            $Reason.Value = 'device_row_missing'
            return $false
        }

        $row = $rows[0]
        if ([string]$row.status -ne 'online') {
            $Reason.Value = 'status_' + [string]$row.status
            return $false
        }

        $lastSeen = [DateTimeOffset]::Parse([string]$row.last_seen).ToUniversalTime()
        $ageSeconds = ([DateTimeOffset]::UtcNow - $lastSeen).TotalSeconds
        $broadcastCapable = [bool]$row.capabilities.transport_broadcast_v1
        $maxAgeSeconds = if ($broadcastCapable) { 420 } else { 60 }
        if ($ageSeconds -lt -120 -or $ageSeconds -gt $maxAgeSeconds) {
            $Reason.Value = ('last_seen_stale:{0:N0}s' -f $ageSeconds)
            return $false
        }

        $Reason.Value = ('ok:{0:N0}s:broadcast={1}' -f $ageSeconds, $broadcastCapable)
        return $true
    } catch {
        $statusCode = $null
        try {
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }
        } catch {}
        # The relay refreshes and persists its own OAuth session. A stale token
        # in the keeper's read-only probe can briefly return 401 even while the
        # live relay is healthy. Do not kill a healthy relay for that condition.
        if ($statusCode -eq 401 -and (Test-FF3DirectRelay)) {
            $Reason.Value = 'probe_auth_stale_process_alive'
            return $true
        }
        $Reason.Value = 'probe_error:' + [string]$_.Exception.Message
        return $false
    }
}

function Test-FF3OwnerChromeSupervisor {
    if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) { return $false }
    try {
        $secret = (Get-Content -LiteralPath $secretPath -Raw).Trim()
        $headers = @{ 'X-FF3-Key' = $secret }
        $healthBody = @{ op = 'computer_use'; args = @{ command = 'health' } } | ConvertTo-Json -Depth 6 -Compress
        $healthResponse = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:$port/rpc" -Headers $headers -Method Post -ContentType 'application/json' -Body $healthBody -TimeoutSec 4
        $health = $healthResponse.result.browser.extension
        if (-not $healthResponse.ok -or -not $health.running -or [int]$health.protocol_error_count -ne 0) { return $false }
        $attachBody = @{ op = 'computer_use'; args = @{
            command = 'attach'; surface_kind = 'browser'; transport = 'extension'
            force_new_connection = $true
            options = @{ extensionClientName = 'FF Bridge keeper readiness probe' }
        } } | ConvertTo-Json -Depth 8 -Compress
        $attached = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:$port/rpc" -Headers $headers -Method Post -ContentType 'application/json' -Body $attachBody -TimeoutSec 8
        $surfaceId = [string]$attached.result.surface_id
        if (-not $attached.ok -or -not $surfaceId) { return $false }
        $closeBody = @{ op = 'computer_use'; args = @{ command = 'close'; surface_id = $surfaceId } } | ConvertTo-Json -Depth 6 -Compress
        $closed = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:$port/rpc" -Headers $headers -Method Post -ContentType 'application/json' -Body $closeBody -TimeoutSec 8
        return [bool]($closed.ok -and $closed.result.ok)
    } catch { return $false }
}

function Invoke-FF3OwnerChromeBootstrap {
    if (-not (Test-Path -LiteralPath $ownerChromeBootstrap -PathType Leaf)) { return $false }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = '-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + $ownerChromeBootstrap + '"'
    $psi.WorkingDirectory = $root
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    try {
        $process = [System.Diagnostics.Process]::Start($psi)
        if (-not $process.WaitForExit(45000)) {
            try { $process.Kill() } catch {}
            Write-FF3RelayWatchdogLog 'owner_chrome_bootstrap_timeout'
            return $false
        }
        $output = ($process.StandardOutput.ReadToEnd() + ' ' + $process.StandardError.ReadToEnd()).Trim()
        Write-FF3RelayWatchdogLog ('owner_chrome_bootstrap_exit=' + $process.ExitCode + ':' + $output.Substring(0, [Math]::Min(1000, $output.Length)))
        return ($process.ExitCode -eq 0)
    } catch {
        Write-FF3RelayWatchdogLog ('owner_chrome_bootstrap_failed:' + [string]$_.Exception.Message)
        return $false
    }
}

function Get-FF3AgentProcesses {
    try {
        $escaped = [regex]::Escape($agent)
        $invocation = '(?i)^\s*(?:"[^"]+"|[^\s"]+)\s+(?:-B\s+)?(?:"' + $escaped + '"|' + $escaped + ')\s+serve(?:\s|$)'
        $portArgument = '(?i)(?:^|\s)--port\s+' + [regex]::Escape([string]$port) + '(?:\s|$)'
        return @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {
            $_.Name -ieq 'python.exe' -and
            $_.CommandLine -and
            ($_.CommandLine -match $invocation) -and
            ($_.CommandLine -match $portArgument)
        })
    } catch { throw }
}

function Test-FF3AgentStartAllowed {
    # A failed HTTP health probe is not evidence that a live process or its
    # jobs are safe to terminate. Only respawn after verified absence. An
    # unresponsive live agent remains diagnosable; trusted runtime deployment
    # owns its separately verified stop/backup/recovery transaction.
    if (Test-Path -LiteralPath $runtimeDeployLock -PathType Leaf) { return $false }
    try {
        $existing = @(Get-FF3AgentProcesses)
        if ($existing.Count -gt 0) {
            Write-FF3RelayWatchdogLog 'agent_restart_suppressed:live_agent_health_unverified'
            return $false
        }
    } catch {
        Write-FF3RelayWatchdogLog 'agent_restart_suppressed:process_query_unverified'
        return $false
    }
    return $true
}

function Start-FF3Agent {
    if (-not (Test-FF3AgentStartAllowed)) { return $false }
    $python = Get-FF3Python
    if (-not $python) { return $false }
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { return $false }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $python
    $psi.Arguments = '"' + $agent + '" serve --host 127.0.0.1 --port ' + $port
    $psi.WorkingDirectory = $root
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
    @($psi.EnvironmentVariables.Keys) | ForEach-Object {
        $key = [string]$_
        if ($key -eq 'RUNNER_TRACKING_ID' -or $key -like 'GITHUB_*' -or $key -like 'ACTIONS_*') { $psi.EnvironmentVariables.Remove($key) }
    }
    try { [System.Diagnostics.Process]::Start($psi) | Out-Null; return $true } catch { return $false }
}

if ($ProbeRelayCloud) {
    $probeReason = ''
    $probeOk = Test-FF3DirectRelayCloud ([ref]$probeReason)
    @{
        ok = [bool]$probeOk
        reason = [string]$probeReason
        runtime_version = [string](Get-FF3RelayRuntimeVersion)
        relay_process_count = @(Get-FF3DirectRelayProcesses).Count
    } | ConvertTo-Json -Compress
    if ($probeOk) { exit 0 } else { exit 2 }
}

$lastRelayProbe = [datetime]::MinValue
$relayEndpointFailures = 0
$relayCloudFailures = 0
$lastRelayRestart = [datetime]::MinValue
$lastEgress = $null
$enableCommanderRelay = ($env:FF_ENABLE_COMMANDER_RELAY -ne '0')
$enableContinuationDaemon = ($env:FF_ENABLE_CONTINUATION_DAEMON -eq '1')
$enableOwnerChromeProbe = ($env:FF_ENABLE_OWNER_CHROME_PROBE -eq '1')
$lastOwnerChromeProbe = [datetime]::MinValue
$ownerChromeReady = $false
$ownerChromeAttempts = 0
$ownerChromeAttemptLimit = 5
$agentConsecutiveFailures = 0
$agentLastRestart = [datetime]::MinValue

try {
    if (Test-Path -LiteralPath $relayEgressPath -PathType Leaf) {
        $lastEgress = (Get-Content -LiteralPath $relayEgressPath -Raw).Trim()
        if (-not $lastEgress) { $lastEgress = $null }
    }
} catch { $lastEgress = $null }

try {
    while ($true) {
        if (-not (Test-Path -LiteralPath $runtimeDeployLock -PathType Leaf)) {
            $agentHealthy = Test-FF3Agent
            if ($agentHealthy) {
                $agentConsecutiveFailures = 0
            } else {
                $now = Get-Date
                $retryDelaySeconds = if ($agentConsecutiveFailures -ge 10) { 60 } elseif ($agentConsecutiveFailures -ge 5) { 15 } else { 3 }
                if (($now - $agentLastRestart).TotalSeconds -ge $retryDelaySeconds -and (Test-FF3AgentStartAllowed)) {
                    $agentConsecutiveFailures++
                    $agentLastRestart = $now
                    Write-FF3RelayWatchdogLog ("agent_start_after_exit_attempt:$agentConsecutiveFailures")
                    Start-FF3Agent | Out-Null
                    Start-Sleep -Seconds 2
                }
            }
        }
        if ($enableCommanderRelay -and -not (Test-FF3DirectRelay)) {
            Start-FF3DirectRelay | Out-Null
            Start-Sleep -Seconds 3
        }
        # Continuation automation is strictly opt-in and passive by default.
        if ($enableContinuationDaemon -and -not (Test-FF3ContinuationDaemon)) {
            Start-FF3ContinuationDaemon | Out-Null
            Start-Sleep -Milliseconds 500
        }

        $now = Get-Date
        if (-not $ownerChromeReady -and $enableOwnerChromeProbe -and ($now - $lastOwnerChromeProbe).TotalSeconds -ge 30) {
            $lastOwnerChromeProbe = $now
            if (Test-FF3OwnerChromeSupervisor) {
                $ownerChromeReady = $true
            } elseif ($ownerChromeAttempts -lt $ownerChromeAttemptLimit) {
                $ownerChromeAttempts++
                $ownerChromeReady = [bool](Invoke-FF3OwnerChromeBootstrap)
            }
        }
        if ($enableCommanderRelay -and ($now - $lastRelayProbe).TotalSeconds -ge 30) {
            $lastRelayProbe = $now
            $endpointOk = Test-FF3RelayEndpoint
            if ($endpointOk) { $relayEndpointFailures = 0 } else { $relayEndpointFailures++ }

            $cloudReason = ''
            $cloudOk = Test-FF3DirectRelayCloud ([ref]$cloudReason)
            if ($cloudOk) {
                if ($relayCloudFailures -gt 0) { Write-FF3RelayWatchdogLog ('relay_cloud_recovered:' + $cloudReason) }
                $relayCloudFailures = 0
            } else {
                $relayCloudFailures++
                if ($relayCloudFailures -eq 1 -or $relayCloudFailures -eq 3) {
                    Write-FF3RelayWatchdogLog ('relay_cloud_unhealthy:' + $relayCloudFailures + ':' + $cloudReason)
                }
            }

            $egress = Get-FF3EgressIp
            $egressChanged = ($egress -and $lastEgress -and ($egress -ne $lastEgress))
            $hasCredentials = Test-Path -LiteralPath $relayDeviceConfigPath -PathType Leaf

            # Never restart a process that is waiting for the owner to authorize a
            # fresh device code. Repeated restarts would open a new browser tab/code
            # every cycle and reproduce the exact runaway behavior this watchdog
            # exists to prevent.
            if ($hasCredentials -and $egressChanged) {
                Restart-FF3DirectRelay ('egress_changed:' + $lastEgress + '->' + $egress) | Out-Null
            } elseif ($hasCredentials -and $relayEndpointFailures -ge 2) {
                Restart-FF3DirectRelay 'relay_endpoint_unreachable_twice' | Out-Null
                $relayEndpointFailures = 0
            } elseif ($hasCredentials -and $relayCloudFailures -ge 3) {
                Restart-FF3DirectRelay ('relay_cloud_unhealthy:' + $cloudReason) | Out-Null
                $relayCloudFailures = 0
            }

            if ($egress) {
                $lastEgress = $egress
                try { Set-Content -LiteralPath $relayEgressPath -Value $egress -Encoding ASCII } catch {}
            }
        }
        Start-Sleep -Seconds 5
    }
} finally {
    try {
        if (Test-Path -LiteralPath $keeperPidPath -PathType Leaf) {
            $current = (Get-Content -LiteralPath $keeperPidPath -Raw).Trim()
            if ($current -eq [string]$PID) { Remove-Item -LiteralPath $keeperPidPath -Force -ErrorAction SilentlyContinue }
        }
    } catch {}
    if ($keeperMutexOwned -and $keeperMutex) {
        try { $keeperMutex.ReleaseMutex() } catch {}
    }
    if ($keeperMutex) {
        try { $keeperMutex.Dispose() } catch {}
    }
}
