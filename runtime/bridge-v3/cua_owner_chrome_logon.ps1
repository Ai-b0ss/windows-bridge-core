[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $BridgeRoot = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\bridge-v3'),
    [ValidateRange(3000, 30000)]
    [int] $UiTimeoutMs = 15000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$extensionId = 'mmlmfjhmonkocbjadbfplnigmagldckm'
$extensionName = 'Playwright Extension'
$secretPath = Join-Path $BridgeRoot 'secret'
$port = 39073

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class OwnerChromeWin32 {
    [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hwnd);
    [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hwnd, IntPtr processId);
    [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool attach);
    [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool GetCursorPos(out POINT point);
}
'@
function Get-OwnerChromeWindows {
    $pids = @{}
    @(Get-Process chrome -ErrorAction SilentlyContinue) | ForEach-Object { $pids[[int]$_.Id] = $true }
    if ($pids.Count -eq 0) { return @() }
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $children = $root.FindAll(
        [System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition
    )
    $windows = @()
    foreach ($element in $children) {
        try {
            $processId = [int]$element.Current.ProcessId
            $hwnd = [int64]$element.Current.NativeWindowHandle
            if ($pids.ContainsKey($processId) -and $hwnd -gt 0 -and
                $element.Current.ClassName -eq 'Chrome_WidgetWin_1' -and
                -not $element.Current.IsOffscreen) {
                $windows += [pscustomobject]@{ Element = $element; Hwnd = $hwnd; ProcessId = $processId }
            }
        } catch {}
    }
    return @($windows)
}

function Invoke-BridgeRpc([hashtable] $Arguments, [string] $StepName) {
    if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) { throw 'FF3_SECRET_MISSING' }
    $secret = (Get-Content -LiteralPath $secretPath -Raw -Encoding ASCII).Trim()
    if (-not $secret) { throw 'FF3_SECRET_EMPTY' }
    $body = @{ op = 'computer_use'; args = $Arguments } | ConvertTo-Json -Depth 12 -Compress
    $stepTimer = [Diagnostics.Stopwatch]::StartNew()
    [Console]::Out.WriteLine("STEP $StepName begin")
    try {
        $response = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:$port/rpc" -Method Post -ContentType 'application/json; charset=utf-8' -Headers @{ 'X-FF3-Key' = $secret } -Body $body -TimeoutSec 30
    } catch {
        $stepTimer.Stop()
        [Console]::Out.WriteLine("STEP $StepName result=failure duration_ms=$($stepTimer.ElapsedMilliseconds) error_type=$($_.Exception.GetType().Name)")
        throw
    }
    $stepTimer.Stop()
    if (-not $response.ok) {
        [Console]::Out.WriteLine("STEP $StepName result=failure duration_ms=$($stepTimer.ElapsedMilliseconds) error_code=$([string]$response.error_code)")
        throw ('FF3_CUA_RPC_FAILED:' + [string]$response.error_code)
    }
    [Console]::Out.WriteLine("STEP $StepName result=success duration_ms=$($stepTimer.ElapsedMilliseconds)")
    return $response.result
}

function Restore-ForegroundWindow([IntPtr] $TargetHwnd) {
    if ($TargetHwnd -eq [IntPtr]::Zero -or -not [OwnerChromeWin32]::IsWindow($TargetHwnd)) { return $false }
    $currentThread = [OwnerChromeWin32]::GetCurrentThreadId()
    $targetThread = [OwnerChromeWin32]::GetWindowThreadProcessId($TargetHwnd, [IntPtr]::Zero)
    $currentForeground = [OwnerChromeWin32]::GetForegroundWindow()
    $foregroundThread = if ($currentForeground -ne [IntPtr]::Zero) { [OwnerChromeWin32]::GetWindowThreadProcessId($currentForeground, [IntPtr]::Zero) } else { 0 }
    $attachedTarget = $false
    $attachedForeground = $false
    try {
        if ($targetThread -ne 0 -and $targetThread -ne $currentThread) { $attachedTarget = [OwnerChromeWin32]::AttachThreadInput($currentThread, $targetThread, $true) }
        if ($foregroundThread -ne 0 -and $foregroundThread -ne $currentThread -and $foregroundThread -ne $targetThread) { $attachedForeground = [OwnerChromeWin32]::AttachThreadInput($currentThread, $foregroundThread, $true) }
        [void][OwnerChromeWin32]::BringWindowToTop($TargetHwnd)
        [void][OwnerChromeWin32]::SetForegroundWindow($TargetHwnd)
    } finally {
        if ($attachedForeground) { [void][OwnerChromeWin32]::AttachThreadInput($currentThread, $foregroundThread, $false) }
        if ($attachedTarget) { [void][OwnerChromeWin32]::AttachThreadInput($currentThread, $targetThread, $false) }
    }
    return ([OwnerChromeWin32]::GetForegroundWindow() -eq $TargetHwnd)
}

function Find-ExactToggle($Window) {
    $condition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        'enableToggle'
    )
    $all = $Window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
    $visible = @()
    foreach ($element in $all) {
        try {
            if ($element.Current.IsEnabled -and -not $element.Current.IsOffscreen) { $visible += $element }
        } catch {}
    }
    if ($visible.Count -gt 1) { throw "OWNER_CHROME_EXTENSION_TOGGLE_AMBIGUOUS:$($visible.Count)" }
    if ($visible.Count -eq 0) { return $null }

    $nameCondition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::NameProperty,
        $extensionName
    )
    $names = $Window.FindAll([System.Windows.Automation.TreeScope]::Descendants, $nameCondition)
    if ($names.Count -lt 1) { return $null }
    return $visible[0]
}

$foregroundBefore = [OwnerChromeWin32]::GetForegroundWindow()
$cursorBefore = New-Object OwnerChromeWin32+POINT
[void][OwnerChromeWin32]::GetCursorPos([ref]$cursorBefore)
$before = @(Get-OwnerChromeWindows)
if ($before.Count -eq 0) { throw 'OWNER_CHROME_WINDOW_UNAVAILABLE' }
$paths = @($before | ForEach-Object {
    (Get-Process -Id $_.ProcessId -ErrorAction Stop).Path
} | Sort-Object -Unique)
if ($paths.Count -ne 1 -or -not $paths[0]) { throw "OWNER_CHROME_BINARY_AMBIGUOUS:$($paths.Count)" }
$beforeHandles = @{}
$before | ForEach-Object { $beforeHandles[[int64]$_.Hwnd] = $true }
$detailsUrl = "chrome://extensions/?id=$extensionId"
$bootstrapWindow = $null
$enabledBefore = $null
$enabledAfter = $null
$toggleInvoked = $false
$surfaceId = $null
$supervisor = $null

$uiStepTimer = [Diagnostics.Stopwatch]::StartNew()
[Console]::Out.WriteLine('STEP extension_ui_enable begin')
try {
    Start-Process -FilePath $paths[0] -ArgumentList '--new-window' | Out-Null
    $deadline = [DateTime]::UtcNow.AddMilliseconds($UiTimeoutMs)
    do {
        Start-Sleep -Milliseconds 200
        $fresh = @(Get-OwnerChromeWindows | Where-Object { -not $beforeHandles.ContainsKey([int64]$_.Hwnd) })
        if ($fresh.Count -gt 1) { throw "OWNER_CHROME_BOOTSTRAP_WINDOW_AMBIGUOUS:$($fresh.Count)" }
        if ($fresh.Count -eq 1) { $bootstrapWindow = $fresh[0]; break }
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $bootstrapWindow) { throw 'OWNER_CHROME_BOOTSTRAP_WINDOW_TIMEOUT' }

    $omniboxCondition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ClassNameProperty,
        'OmniboxViewViews'
    )
    $omniboxes = $bootstrapWindow.Element.FindAll(
        [System.Windows.Automation.TreeScope]::Descendants,
        $omniboxCondition
    )
    $visibleOmniboxes = @($omniboxes | Where-Object { -not $_.Current.IsOffscreen -and $_.Current.IsEnabled })
    if ($visibleOmniboxes.Count -ne 1) { throw "OWNER_CHROME_OMNIBOX_AMBIGUOUS:$($visibleOmniboxes.Count)" }
    $valuePattern = $null
    if (-not $visibleOmniboxes[0].TryGetCurrentPattern(
        [System.Windows.Automation.ValuePattern]::Pattern,
        [ref]$valuePattern
    )) { throw 'OWNER_CHROME_OMNIBOX_VALUE_PATTERN_UNAVAILABLE' }
    $valuePattern.SetValue($detailsUrl)

    $matchCondition = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
        'match-0'
    )
    $match = $null
    do {
        $matches = @($bootstrapWindow.Element.FindAll(
            [System.Windows.Automation.TreeScope]::Descendants,
            $matchCondition
        ) | Where-Object { -not $_.Current.IsOffscreen -and $_.Current.Name.Contains($extensionId) })
        if ($matches.Count -gt 1) { throw "OWNER_CHROME_OMNIBOX_MATCH_AMBIGUOUS:$($matches.Count)" }
        if ($matches.Count -eq 1) { $match = $matches[0]; break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $match) { throw 'OWNER_CHROME_OMNIBOX_MATCH_TIMEOUT' }
    $invokePattern = $null
    if (-not $match.TryGetCurrentPattern(
        [System.Windows.Automation.InvokePattern]::Pattern,
        [ref]$invokePattern
    )) { throw 'OWNER_CHROME_OMNIBOX_MATCH_INVOKE_UNAVAILABLE' }
    $invokePattern.Invoke()

    $toggle = $null
    do {
        $toggle = Find-ExactToggle $bootstrapWindow.Element
        if ($null -ne $toggle) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -eq $toggle) { throw 'OWNER_CHROME_EXTENSION_IDENTITY_NOT_VISIBLE' }
    $pattern = $null
    if (-not $toggle.TryGetCurrentPattern(
        [System.Windows.Automation.TogglePattern]::Pattern,
        [ref]$pattern
    )) { throw 'OWNER_CHROME_EXTENSION_TOGGLE_PATTERN_UNAVAILABLE' }
    $enabledBefore = $pattern.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On
    if (-not $enabledBefore) {
        if ($pattern.Current.ToggleState -ne [System.Windows.Automation.ToggleState]::Off) {
            throw 'OWNER_CHROME_EXTENSION_TOGGLE_INDETERMINATE'
        }
        $pattern.Toggle()
        $toggleInvoked = $true
        $verifyDeadline = [DateTime]::UtcNow.AddMilliseconds(5000)
        do {
            Start-Sleep -Milliseconds 200
            $enabledAfter = $pattern.Current.ToggleState -eq [System.Windows.Automation.ToggleState]::On
        } while (-not $enabledAfter -and [DateTime]::UtcNow -lt $verifyDeadline)
        if (-not $enabledAfter) { throw 'OWNER_CHROME_EXTENSION_ENABLE_UNVERIFIED' }
    } else {
        $enabledAfter = $true
    }
}
catch {
    $uiStepTimer.Stop()
    [Console]::Out.WriteLine("STEP extension_ui_enable result=failure duration_ms=$($uiStepTimer.ElapsedMilliseconds) error_type=$($_.Exception.GetType().Name)")
    throw
}
finally {
    if ($null -ne $bootstrapWindow -and [OwnerChromeWin32]::IsWindow([IntPtr]$bootstrapWindow.Hwnd)) {
        [void][OwnerChromeWin32]::PostMessage([IntPtr]$bootstrapWindow.Hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
    }
    if ($foregroundBefore -ne [IntPtr]::Zero -and [OwnerChromeWin32]::IsWindow($foregroundBefore)) {
        Start-Sleep -Milliseconds 300
        [void](Restore-ForegroundWindow $foregroundBefore)
    }
}
$uiStepTimer.Stop()
[Console]::Out.WriteLine("STEP extension_ui_enable result=success duration_ms=$($uiStepTimer.ElapsedMilliseconds)")

Start-Sleep -Milliseconds 800
try {
    $attached = Invoke-BridgeRpc @{
        command = 'attach'; surface_kind = 'browser'; transport = 'extension'
        options = @{ extensionClientName = 'FF Bridge per-logon readiness' }
    } 'rpc_attach'
    $surfaceId = [string]$attached.surface_id
    if (-not $surfaceId) { throw 'OWNER_CHROME_EXTENSION_ATTACH_NO_SURFACE' }
    $health = Invoke-BridgeRpc @{ command = 'health' } 'rpc_health_after_attach'
    $supervisor = $health.browser.extension
    if ($null -eq $supervisor -or -not $supervisor.running) {
        throw 'OWNER_CHROME_EXTENSION_SUPERVISOR_NOT_RUNNING'
    }
    if ([int]$supervisor.protocol_error_count -ne 0) {
        throw 'OWNER_CHROME_EXTENSION_PROTOCOL_ERROR'
    }
}
finally {
    if ($surfaceId) {
        $closed = Invoke-BridgeRpc @{ command = 'close'; surface_id = $surfaceId } 'rpc_close'
        if (-not $closed.ok) { throw 'OWNER_CHROME_EXTENSION_SURFACE_CLOSE_FAILED' }
    }
}

if ($foregroundBefore -ne [IntPtr]::Zero -and [OwnerChromeWin32]::IsWindow($foregroundBefore)) {
    Start-Sleep -Milliseconds 300
    [void](Restore-ForegroundWindow $foregroundBefore)
}
$cursorAfter = New-Object OwnerChromeWin32+POINT
[void][OwnerChromeWin32]::GetCursorPos([ref]$cursorAfter)
$foregroundAfter = [OwnerChromeWin32]::GetForegroundWindow()
$result = [ordered]@{
    ok = $true
    extension_id = $extensionId
    extension_name = $extensionName
    enabled_before = [bool]$enabledBefore
    enabled_after = [bool]$enabledAfter
    toggle_invoked = [bool]$toggleInvoked
    supervisor_running = [bool]$supervisor.running
    supervisor_pid = [int]$supervisor.pid
    protocol_error_count = [int]$supervisor.protocol_error_count
    foreground_preserved = ([int64]$foregroundBefore -eq [int64]$foregroundAfter)
    cursor_preserved = ($cursorBefore.X -eq $cursorAfter.X -and $cursorBefore.Y -eq $cursorAfter.Y)
    physical_input_used = $false
    wrong_target_actions = 0
}
$result | ConvertTo-Json -Compress
if (-not $result.foreground_preserved -or -not $result.cursor_preserved) { exit 4 }
exit 0