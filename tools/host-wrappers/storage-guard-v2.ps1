[CmdletBinding()]
param(
    [string]$OwnerProfile = $env:USERPROFILE,
    [string]$BridgeRoot = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge'),
    [string]$DataBridgeRoot = '',
    [string]$DataDrive = '',
    [double]$TriggerFreeC_GiB = 18.0,
    [double]$EmergencyFreeC_GiB = 10.0,
    [double]$TriggerFreeData_GiB = 30.0,
    [double]$EmergencyFreeData_GiB = 18.0,
    [int]$SilentCleanupCooldownHours = 24,
    [string[]]$ProtectedPathTokens = @(
        'ff-windows-bridge\recovery',
        'chrome\user data',
        'chromium\user data',
        'bravesoftware\brave-browser\user data',
        '.ssh',
        '.gnupg',
        'secrets',
        'backup-recovery-keys',
        'preservedbackups'
    ),
    [switch]$IncludeTier1Guarded,
    [switch]$DryRun,
    [switch]$ForceRun,
    [switch]$LoadFunctionsOnly,
    [string]$LogPath = (Join-Path $env:ProgramData 'FF-Windows-Bridge\storage-guard.jsonl'),
    [string]$StatePath = (Join-Path $env:ProgramData 'FF-Windows-Bridge\storage-guard-state.json')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'
$script:Actions = New-Object System.Collections.Generic.List[object]

function Write-GuardEvent([string]$Kind, [hashtable]$Data = @{}) {
    try {
        $dir = Split-Path -Parent $LogPath
        if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $row = [ordered]@{ time = (Get-Date).ToString('o'); version = '2.0'; kind = $Kind }
        foreach ($k in $Data.Keys) { $row[$k] = $Data[$k] }
        Add-Content -LiteralPath $LogPath -Value ($row | ConvertTo-Json -Compress -Depth 6) -Encoding UTF8
        if ((Get-Item -LiteralPath $LogPath -ErrorAction SilentlyContinue).Length -gt 2MB) {
            $tail = @(Get-Content -LiteralPath $LogPath -Tail 1000 -ErrorAction SilentlyContinue)
            Set-Content -LiteralPath $LogPath -Value $tail -Encoding UTF8
        }
    } catch {}
}

function Get-FreeGiB([string]$Drive) {
    if (-not $Drive) { return -1.0 }
    try {
        $d = Get-CimInstance Win32_LogicalDisk -Filter ("DeviceID='" + $Drive + "'")
        if ($d) { return [math]::Round(([double]$d.FreeSpace / 1GB), 3) }
    } catch {}
    return -1.0
}

function Get-RealPhysicalDrive([string]$Path) {
    try {
        $cur = [IO.Path]::GetFullPath($Path)
        while ($cur -and $cur.Length -gt 3) {
            $it = Get-Item -LiteralPath $cur -Force -ErrorAction SilentlyContinue
            if ($it -and ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $it.PSObject.Properties['Target'] -and $it.Target) {
                $t = @($it.Target)[0]
                if ($t -match '^\\\\\?\\(.*)$') { $t = $Matches[1] }
                return ([IO.Path]::GetPathRoot($t)).TrimEnd('\').ToUpperInvariant()
            }
            $cur = Split-Path -Parent $cur
        }
        return ([IO.Path]::GetPathRoot($Path)).TrimEnd('\').ToUpperInvariant()
    } catch {
        return 'UNKNOWN'
    }
}

function Test-HardProtected([string]$Path) {
    $low = $Path.Replace('/', '\').ToLowerInvariant()
    if ($low -match '\.(dpapi|pfx|jks|keystore|kdbx|enc|pem|key)$') { return $true }
    foreach ($tok in $ProtectedPathTokens) {
        if ($tok -and $low.Contains($tok.Replace('/', '\').ToLowerInvariant())) { return $true }
    }
    return $false
}

$script:ProcessHaystack = $null
function Get-ProcessHaystack {
    if ($null -eq $script:ProcessHaystack) {
        $lines = New-Object System.Collections.Generic.List[string]
        try {
            foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
                if ($p.CommandLine) { $lines.Add([string]$p.CommandLine) | Out-Null }
                if ($p.ExecutablePath) { $lines.Add([string]$p.ExecutablePath) | Out-Null }
            }
        } catch {}
        $script:ProcessHaystack = ($lines -join "`n")
    }
    return $script:ProcessHaystack
}

function Test-ProcessReference([string]$Path) {
    try {
        $needle = [IO.Path]::GetFullPath($Path).TrimEnd('\')
        $hay = Get-ProcessHaystack
        if ($hay -and $hay.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    } catch {}
    return $false
}

function Get-NonReparseBytes([string]$Path) {
    $it = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $it) { return [int64]0 }
    if ($it.Attributes -band [IO.FileAttributes]::ReparsePoint) { return [int64]0 }
    if (-not $it.PSIsContainer) { return [int64]$it.Length }
    [int64]$sum = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $Path -Force -File -Recurse -ErrorAction SilentlyContinue)) {
        if (-not ($f.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            $sum += [int64]$f.Length
        }
    }
    return $sum
}

function Remove-SafePath([string]$Path, [string]$Reason) {
    if (Test-HardProtected $Path) {
        Write-GuardEvent 'skip_hard_protected' @{ path = $Path; reason = $Reason }
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if (-not $item) { return $false }
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        Write-GuardEvent 'skip_reparse_point' @{ path = $Path; reason = $Reason }
        return $false
    }
    if (Test-ProcessReference $Path) {
        Write-GuardEvent 'skip_active_process' @{ path = $Path; reason = $Reason }
        return $false
    }
    $drive = Get-RealPhysicalDrive $Path
    $bytes = Get-NonReparseBytes $Path
    if ($DryRun) {
        $script:Actions.Add([pscustomobject]@{ drive = $drive; path = $Path; reason = $Reason; bytes = $bytes; dry_run = $true }) | Out-Null
        Write-GuardEvent 'dry_run_reclaim' @{ drive = $drive; path = $Path; reason = $Reason; bytes = $bytes }
        return $true
    }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        $script:Actions.Add([pscustomobject]@{ drive = $drive; path = $Path; reason = $Reason; bytes = $bytes; dry_run = $false }) | Out-Null
        Write-GuardEvent 'reclaimed' @{ drive = $drive; path = $Path; reason = $Reason; bytes = $bytes }
        return $true
    } catch {
        Write-GuardEvent 'delete_failed' @{ drive = $drive; path = $Path; reason = $Reason; error = $_.Exception.Message }
        return $false
    }
}

function Invoke-BridgeRuntimeCleaners([string]$RootPath) {
    if (-not $RootPath -or -not (Test-Path -LiteralPath $RootPath)) { return }
    $detDir = Join-Path $RootPath 'bridge-v3\state\detached_logs'
    $detJson = Join-Path $RootPath 'bridge-v3\state\detached_sessions.json'
    if (Test-Path -LiteralPath $detDir) {
        $tracked = @{}
        if (Test-Path -LiteralPath $detJson) {
            try {
                $parsed = Get-Content -LiteralPath $detJson -Raw -Encoding UTF8 | ConvertFrom-Json
                foreach ($prop in $parsed.PSObject.Properties) { $tracked[$prop.Name] = $prop.Value }
            } catch {}
        }
        $cutoff1h = (Get-Date).AddHours(-1)
        foreach ($lf in @(Get-ChildItem -LiteralPath $detDir -Filter '*.log' -File -ErrorAction SilentlyContinue)) {
            $sid = [IO.Path]::GetFileNameWithoutExtension($lf.Name)
            if ($sid -notmatch '^[0-9a-f]{16}$') { continue }
            if (-not $tracked.ContainsKey($sid)) {
                if ($lf.LastWriteTime -lt $cutoff1h) {
                    Remove-SafePath $lf.FullName 'orphan_detached_session_log' | Out-Null
                }
            } elseif ($lf.Length -gt 512MB) {
                Write-GuardEvent 'alert_oversized_detached_log' @{
                    session_id = $sid; path = $lf.FullName; bytes = $lf.Length;
                    pid = $tracked[$sid].pid
                }
            }
        }
    }

    $spillDir = Join-Path $RootPath 'state\cf-flight-controller\spillover'
    $cutoff48h = (Get-Date).AddHours(-48)
    if (Test-Path -LiteralPath $spillDir) {
        foreach ($sf in @(Get-ChildItem -LiteralPath $spillDir -Filter '*.log' -File -ErrorAction SilentlyContinue)) {
            if ($sf.LastWriteTime -lt $cutoff48h) {
                Remove-SafePath $sf.FullName 'expired_contextshield_spillover' | Out-Null
            }
        }
    }
}

function Invoke-DriveC-Cleaners([bool]$Emergency) {
    $cutoff3d = (Get-Date).AddDays(-3)
    foreach ($cacheSpec in @(
        @{ path = (Join-Path $OwnerProfile 'AppData\Local\npm-cache\_cacache'); minBytes = 128MB; reason = 'npm_http_cache' },
        @{ path = (Join-Path $OwnerProfile 'AppData\Local\pip\cache');          minBytes = 64MB;  reason = 'pip_wheel_cache' },
        @{ path = (Join-Path $OwnerProfile 'AppData\Local\uv\cache');           minBytes = 64MB;  reason = 'uv_local_cache' },
        @{ path = (Join-Path $OwnerProfile 'AppData\Roaming\uv\cache');         minBytes = 64MB;  reason = 'uv_roaming_cache' }
    )) {
        if ((Test-Path -LiteralPath $cacheSpec.path) -and ((Get-RealPhysicalDrive $cacheSpec.path) -eq 'C:')) {
            if ((Get-NonReparseBytes $cacheSpec.path) -ge $cacheSpec.minBytes) {
                Remove-SafePath $cacheSpec.path $cacheSpec.reason | Out-Null
            }
        }
    }

    $localApp = Join-Path $OwnerProfile 'AppData\Local'
    foreach ($upd in @(Get-ChildItem -LiteralPath $localApp -Directory -Filter '*-updater' -ErrorAction SilentlyContinue)) {
        if ($upd.LastWriteTime -lt $cutoff3d) {
            Remove-SafePath $upd.FullName 'stale_app_updater_cache' | Out-Null
        }
    }

    $tempRoot = Join-Path $localApp 'Temp'
    $cutoff48h = (Get-Date).AddHours(-48)
    if (Test-Path -LiteralPath $tempRoot) {
        foreach ($ti in @(Get-ChildItem -LiteralPath $tempRoot -Force -ErrorAction SilentlyContinue)) {
            if ($ti.LastWriteTime -lt $cutoff48h) {
                Remove-SafePath $ti.FullName 'stale_temp_48h' | Out-Null
            }
        }
    }
}

if ($LoadFunctionsOnly) {
    return
}

$mutex = $null
$owned = $false
try {
    try { $mutex = [Threading.Mutex]::new($false, 'Global\FF-Windows-Bridge-Storage-Guard') }
    catch { $mutex = [Threading.Mutex]::new($false, 'Local\FF-Windows-Bridge-Storage-Guard') }
    try { $owned = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned = $true }
    if (-not $owned) { Write-GuardEvent 'already_running'; exit 0 }

    $prevState = @{}
    if (Test-Path -LiteralPath $StatePath) {
        try {
            $obj = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($p in $obj.PSObject.Properties) { $prevState[$p.Name] = $p.Value }
        } catch {}
    }

    $targetRuntime = if ($DataBridgeRoot) { $DataBridgeRoot } else { $BridgeRoot }
    $resolvedDataDrive = if ($DataDrive) { $DataDrive } elseif ($targetRuntime) { Get-RealPhysicalDrive $targetRuntime } else { '' }

    $cBefore = Get-FreeGiB 'C:'
    $dBefore = if ($resolvedDataDrive -and $resolvedDataDrive -ne 'C:' -and $resolvedDataDrive -ne 'UNKNOWN') { Get-FreeGiB $resolvedDataDrive } else { -1.0 }
    $needC = $ForceRun -or ($cBefore -ge 0 -and $cBefore -lt $TriggerFreeC_GiB)
    $needD = $ForceRun -or ($dBefore -ge 0 -and $dBefore -lt $TriggerFreeData_GiB)

    Write-GuardEvent 'check' @{
        free_c_gib = $cBefore; free_data_gib = $dBefore;
        need_c = $needC; need_data = $needD; dry_run = [bool]$DryRun
    }

    if ($needC) { Invoke-DriveC-Cleaners ($cBefore -lt $EmergencyFreeC_GiB) }
    if ($needC -or $needD) { Invoke-BridgeRuntimeCleaners $targetRuntime }

    $cAfter = Get-FreeGiB 'C:'
    $dAfter = if ($resolvedDataDrive -and $resolvedDataDrive -ne 'C:' -and $resolvedDataDrive -ne 'UNKNOWN') { Get-FreeGiB $resolvedDataDrive } else { -1.0 }

    $lastSilentEpoch = if ($prevState.ContainsKey('last_silent_cleanup_epoch')) { [double]$prevState['last_silent_cleanup_epoch'] } else { 0.0 }
    $nowEpoch = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if (-not $DryRun -and $cAfter -ge 0 -and $cAfter -lt $EmergencyFreeC_GiB -and (($nowEpoch - $lastSilentEpoch) -ge ($SilentCleanupCooldownHours * 3600))) {
        try {
            Start-ScheduledTask -TaskPath '\Microsoft\Windows\DiskCleanup\' -TaskName 'SilentCleanup' -ErrorAction SilentlyContinue
            $lastSilentEpoch = $nowEpoch
            Write-GuardEvent 'requested_windows_silent_cleanup_with_24h_cooldown'
        } catch {}
    }

    $status = if (($cAfter -ge 0 -and $cAfter -lt $EmergencyFreeC_GiB) -or ($dAfter -ge 0 -and $dAfter -lt $EmergencyFreeData_GiB)) {
        'critical_low_space'
    } elseif (($cAfter -ge 0 -and $cAfter -lt $TriggerFreeC_GiB) -or ($dAfter -ge 0 -and $dAfter -lt $TriggerFreeData_GiB)) {
        'low_space'
    } else {
        'ok'
    }

    [int64]$reclaimedBytes = 0
    foreach ($act in $script:Actions) { $reclaimedBytes += [int64]$act.bytes }

    $newState = [ordered]@{
        time = (Get-Date).ToString('o')
        version = '2.0'
        status = $status
        free_c_before_gib = $cBefore
        free_c_after_gib = $cAfter
        free_data_before_gib = $dBefore
        free_data_after_gib = $dAfter
        action_count = $script:Actions.Count
        planned_or_reclaimed_gib = [math]::Round(([double]$reclaimedBytes / 1GB), 3)
        last_silent_cleanup_epoch = $lastSilentEpoch
        dry_run = [bool]$DryRun
    }
    if (-not $DryRun) {
        $dir = Split-Path -Parent $StatePath
        if ($dir) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $tmp = $StatePath + '.tmp'
        $newState | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $tmp -Encoding UTF8
        Move-Item -LiteralPath $tmp -Destination $StatePath -Force
    }
    Write-GuardEvent 'complete' @{
        status = $status; free_c_after_gib = $cAfter; free_data_after_gib = $dAfter;
        actions = $script:Actions.Count; reclaimed_gib = $newState.planned_or_reclaimed_gib
    }
    if ($DryRun) {
        $newState | ConvertTo-Json -Depth 5 | Write-Output
        exit 0
    }
    if ($status -eq 'critical_low_space') { exit 3 }
    exit 0
} finally {
    if ($owned -and $mutex) { try { $mutex.ReleaseMutex() } catch {} }
    if ($mutex) { try { $mutex.Dispose() } catch {} }
}
