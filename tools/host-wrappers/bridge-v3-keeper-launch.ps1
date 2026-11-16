param([switch]$LoadFunctionsOnly)

$ErrorActionPreference = 'SilentlyContinue'
$env:FF_ENABLE_COMMANDER_RELAY = '1'
$bridgeDir = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\bridge-v3'
$keeper = Join-Path $bridgeDir 'ff_win_v3_keeper.ps1'
$deployLock = Join-Path $bridgeDir '.cua-runtime-deploy-lock.json'
$maintLock = Join-Path $bridgeDir '.cua-cold-maintenance.lock'
$maintMaxTtlSeconds = 300
$log = Join-Path $env:ProgramData 'FF-Windows-Bridge\bridge-v3-keeper-launch.log'

function Test-FF3ColdMaintenanceLockActive {
    param(
        [string]$LockPath = $maintLock,
        [int]$MaxTtlSeconds = $maintMaxTtlSeconds
    )
    if (-not (Test-Path -LiteralPath $LockPath -PathType Leaf)) { return $false }
    try {
        $item = Get-Item -LiteralPath $LockPath -ErrorAction Stop
        $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        $mtimeEpoch = ([DateTimeOffset]$item.LastWriteTimeUtc).ToUnixTimeSeconds()
        if ($mtimeEpoch -gt ($nowEpoch + 60)) { $mtimeEpoch = $nowEpoch }
        $effectiveExpiry = [double]($mtimeEpoch + $MaxTtlSeconds)
        try {
            $raw = Get-Content -LiteralPath $LockPath -Raw -ErrorAction Stop
            if ($raw -and $raw.Trim().StartsWith('{')) {
                $doc = $raw | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $doc.expires_epoch) {
                    $parsedExpiry = [double]$doc.expires_epoch
                    if ($parsedExpiry -lt $effectiveExpiry) {
                        $effectiveExpiry = $parsedExpiry
                    }
                } elseif ($null -ne $doc.created_epoch -and $null -ne $doc.ttl_seconds) {
                    $ttl = [Math]::Min([Math]::Max([double]$doc.ttl_seconds, 1.0), [double]$MaxTtlSeconds)
                    $parsedExpiry = [double]$doc.created_epoch + $ttl
                    if ($parsedExpiry -lt $effectiveExpiry) {
                        $effectiveExpiry = $parsedExpiry
                    }
                }
            }
        } catch {}
        if ([double]$nowEpoch -lt $effectiveExpiry) {
            return $true
        }
        try { Add-Content -LiteralPath $log -Value ((Get-Date -Format o) + ' cold_maint_lock_expired_ignored age_s=' + ($nowEpoch - $mtimeEpoch)) -Encoding UTF8 } catch {}
        return $false
    } catch {
        return $false
    }
}

function Test-KeeperLauncherStartAllowed {
    if (Test-Path -LiteralPath $deployLock -PathType Leaf) { return $false }
    if (Test-FF3ColdMaintenanceLockActive -LockPath $maintLock -MaxTtlSeconds $maintMaxTtlSeconds) { return $false }
    return $true
}

function Get-KeeperProcesses {
    @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {
        $_.Name -in @('powershell.exe', 'pwsh.exe') -and $_.CommandLine -and
        $_.CommandLine -match '(?i)ff_win_v3_keeper\.ps1'
    })
}

if ($LoadFunctionsOnly) { return }

while ($true) {
    if (-not (Test-KeeperLauncherStartAllowed)) {
        Start-Sleep -Seconds 2
        continue
    }
    if ((Get-KeeperProcesses).Count -eq 0 -and (Test-Path -LiteralPath $keeper)) {
        Add-Content -LiteralPath $log -Value ((Get-Date -Format o) + ' start_keeper') -Encoding UTF8
        & powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File $keeper
        Add-Content -LiteralPath $log -Value ((Get-Date -Format o) + ' keeper_exited') -Encoding UTF8
    }
    Start-Sleep -Seconds 5
}
