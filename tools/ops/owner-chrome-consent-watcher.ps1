# Windows interactive-session consent watcher for explicitly delegated FF Hub CDP.



# Requires confirmed local owner opt-in. Uses UIA Invoke only (no cursor/focus).



# Autostart is provided by a separate owner-owned Scheduled Task.



[CmdletBinding()]



param(



    [switch]$DryRun,



    [switch]$ValidateOnly,



    [int]$MaxSeconds=0,



    [int]$PollMilliseconds=750,



    [string]$LogPath = "K:\FF-Windows-Bridge\state\chrome-cdp-consent-watcher\watcher.log"



)



$ErrorActionPreference = "Stop"



Add-Type -AssemblyName UIAutomationClient



Add-Type -AssemblyName UIAutomationTypes



if (-not ("FFFastTcp" -as [type])) {

Add-Type -TypeDefinition @"

using System;

using System.Collections.Generic;

using System.Runtime.InteropServices;



public class FFFastTcpRow {

    public int State;

    public string LocalAddress;

    public int LocalPort;

    public string RemoteAddress;

    public int RemotePort;

    public int OwningProcess;

}



public static class FFFastTcp {

    [DllImport("iphlpapi.dll", SetLastError = true)]

    private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwOutBufLen, bool sort, int ipVersion, int tblClass, uint reserved);



    [StructLayout(LayoutKind.Sequential)]

    private struct MIB_TCPROW_OWNER_PID {

        public uint state;

        public uint localAddr;

        public uint localPort;

        public uint remoteAddr;

        public uint remotePort;

        public uint owningPid;

    }



    private static int PortFromNet(uint p) {

        return (int)(((p & 0xFF) << 8) | ((p >> 8) & 0xFF));

    }



    private static string IpFromNet(uint a) {

        return string.Format("{0}.{1}.{2}.{3}", a & 0xFF, (a >> 8) & 0xFF, (a >> 16) & 0xFF, (a >> 24) & 0xFF);

    }



    public static FFFastTcpRow[] GetTcp4() {

        int size = 0;

        GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);

        if (size <= 0) return new FFFastTcpRow[0];

        IntPtr buf = Marshal.AllocHGlobal(size);

        try {

            if (GetExtendedTcpTable(buf, ref size, false, 2, 5, 0) != 0) return new FFFastTcpRow[0];

            int count = Marshal.ReadInt32(buf);

            var list = new List<FFFastTcpRow>(count);

            IntPtr rowPtr = IntPtr.Add(buf, 4);

            int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));

            for (int i = 0; i < count; i++) {

                var r = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(rowPtr, typeof(MIB_TCPROW_OWNER_PID));

                list.Add(new FFFastTcpRow {

                    State = (int)r.state,

                    LocalAddress = IpFromNet(r.localAddr),

                    LocalPort = PortFromNet(r.localPort),

                    RemoteAddress = IpFromNet(r.remoteAddr),

                    RemotePort = PortFromNet(r.remotePort),

                    OwningProcess = (int)r.owningPid

                });

                rowPtr = IntPtr.Add(rowPtr, rowSize);

            }

            return list.ToArray();

        } finally {

            Marshal.FreeHGlobal(buf);

        }

    }

}

"@

}



function Get-FastTcpListen([int]$port) {

    $rows = [FFFastTcp]::GetTcp4()

    @($rows | Where-Object { $_.State -eq 2 -and $_.LocalPort -eq $port -and $_.LocalAddress -eq "127.0.0.1" })

}



function Get-FastTcpEstablished([int]$remotePort, [int]$owningPid) {

    $rows = [FFFastTcp]::GetTcp4()

    @($rows | Where-Object { $_.State -eq 5 -and $_.RemotePort -eq $remotePort -and $_.OwningProcess -eq $owningPid -and $_.LocalAddress -eq "127.0.0.1" -and $_.RemoteAddress -eq "127.0.0.1" })

}









$stateDir = "K:\FF-Windows-Bridge\state\hub"



$endpointFile = Join-Path $stateDir "endpoint.json"



$configFile = Join-Path $stateDir "config.json"



$chromePortFile = Join-Path $env:LOCALAPPDATA "Google\Chrome\User Data\DevToolsActivePort"



$stopFile = "K:\FF-Windows-Bridge\state\chrome-cdp-consent-watcher\stop.flag"



$authorizedAgent = "chatgpt-gpt6-owner-browser"



$policyFile = Join-Path $stateDir "policy.json"



$mustHaveClass = "owner_chrome_hidden_secondary"



$mutex = New-Object System.Threading.Mutex($false, "Local\FFOwnerChromeCDPConsentWatcher")



if (-not $mutex.WaitOne(0)) { exit 0 }



$lastSuccessfulDialog = $null



$lastChromePid = 0



$script:approvedSocketKey = $null







function Write-WatchLog([string]$message) {



    try {



        $p = [System.IO.Path]::GetFullPath($LogPath)



        if ([System.IO.File]::Exists($p) -and (Get-Item $p).Length -gt 524288) {



            Move-Item -LiteralPath $p -Destination ($p + ".old") -Force -ErrorAction SilentlyContinue



        }



        $line = "[" + (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff") + "] " + $message



        [System.IO.File]::AppendAllText($p, $line + [Environment]::NewLine, [System.Text.Encoding]::UTF8)



    } catch { }



}











$script:verifiedHubCacheKey = $null

$script:verifiedHubCacheObj = $null

$script:verifiedHubStateDir = $null



function Resolve-TrustedHub {

    $candidates = @("K:\FF-Windows-Bridge\state\hub", (Join-Path $env:LOCALAPPDATA "FF-Windows-Bridge\state\hub"))

    foreach ($candidate in $candidates) {

        try {

            $epPath = Join-Path $candidate "endpoint.json"

            if (-not (Test-Path -LiteralPath $epPath)) { continue }

            $ep = Get-Content -LiteralPath $epPath -Raw -Encoding UTF8 | ConvertFrom-Json

            $hp = [int]$ep.pid

            if ($hp -le 0) { continue }

            $cacheKey = "$candidate|$hp|$($ep.create_time)|$($ep.port)"

            $birth = (Get-Process -Id $hp -ErrorAction Stop).StartTime.ToUniversalTime().ToFileTimeUtc()

            if ([Math]::Abs([decimal]$birth - [decimal]$ep.create_time) -gt 10000) { continue }

            $listen = @(Get-FastTcpListen ([int]$ep.port) | Where-Object { $_.OwningProcess -eq $hp })

            if ($listen.Count -lt 1) { continue }

            if ($script:verifiedHubCacheKey -eq $cacheKey -and $null -ne $script:verifiedHubCacheObj) {

                $actual = $script:verifiedHubStateDir

                $script:stateDir = $actual

                $script:endpointFile = Join-Path $actual "endpoint.json"

                $script:configFile = Join-Path $actual "config.json"

                $script:policyFile = Join-Path $actual "policy.json"

                return $script:verifiedHubCacheObj

            }

            $p = Get-CimInstance Win32_Process -Filter "ProcessId=$hp" -ErrorAction Stop

            if (-not $p -or $p.Name -notin @("python.exe","pythonw.exe")) { continue }

            $cmd = ([string]$p.CommandLine) -replace '\\+', '\'

            $pkg = ([string]$ep.package) -replace '\\+', '\'

            if ($pkg -notmatch '(?i)^K:\\FF-Windows-Bridge\\runtime-releases\\(?:hub|bridge)-[0-9a-f]{7,40}\\bridge-v3$') { continue }

            $scriptPath = Join-Path $pkg "ff_hub.py"

            if ($cmd -notmatch ([regex]::Escape($scriptPath) + '"?\s+serve(?:\s|$)')) { continue }

            $m = [regex]::Match($cmd, '(?i)(?:^|\s)--state-dir(?:\s+|=)(?:"([^"]+)"|(\S+))')

            if (-not $m.Success) { continue }

            $actual = if ($m.Groups[1].Success) {$m.Groups[1].Value} else {$m.Groups[2].Value}

            $actual = [IO.Path]::GetFullPath($actual).TrimEnd('\')

            $canonical = Get-Content -LiteralPath (Join-Path $actual "endpoint.json") -Raw -Encoding UTF8 | ConvertFrom-Json

            if ([int]$canonical.pid -ne $hp -or [string]$canonical.create_time -ne [string]$ep.create_time -or [int]$canonical.port -ne [int]$ep.port) { continue }

            $script:verifiedHubCacheKey = $cacheKey

            $script:verifiedHubCacheObj = $p

            $script:verifiedHubStateDir = $actual

            $script:stateDir = $actual

            $script:endpointFile = Join-Path $actual "endpoint.json"

            $script:configFile = Join-Path $actual "config.json"

            $script:policyFile = Join-Path $actual "policy.json"

            return $p

        } catch { }

    }

    $script:verifiedHubCacheKey = $null

    $script:verifiedHubCacheObj = $null

    return $null

}







function Get-TrustedPending {



    # No Bridge or ChatGPT RPC needed. Read authoritative local process/socket state.



    # This is intentionally fail-closed whenever attribution is uncertain.



    try {



        if (Test-Path -LiteralPath $stopFile) { $script:blockReason = 1; return $null }



        $trustedHub = Resolve-TrustedHub



        if (-not $trustedHub) { $script:blockReason = 2; return $null }



        if (-not (Test-Path -LiteralPath $chromePortFile)) { $script:blockReason = 3; return $null }



        $config = Get-Content -LiteralPath $configFile -Raw -Encoding UTF8 | ConvertFrom-Json



        if ($config.owner_chrome_profile -ne "Default") { $script:blockReason = 4; return $null }



        $policy = Get-Content -LiteralPath $policyFile -Raw -Encoding UTF8 | ConvertFrom-Json



        $grant = @($policy.grants | Where-Object {



            ($_.agents -contains $authorizedAgent -or $_.agents -contains "*") -and



            ($null -eq $_.expires_at -or [double]$_.expires_at -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -and



            $_.revoked -ne $true -and



            ($_.classes -contains $mustHaveClass) -and



            ($true)



        })



        if ($grant.Count -lt 1) { $script:blockReason = 5; return $null }



        $endpoint = Get-Content -LiteralPath $endpointFile -Raw -Encoding UTF8 | ConvertFrom-Json



        $hubPid = [int]$endpoint.pid



        if ($hubPid -le 0) { $script:blockReason = 6; return $null }



        $proc = $trustedHub



        if ([int]$proc.ProcessId -ne $hubPid) { $script:blockReason = 7; return $null }



        $lines = @(Get-Content -LiteralPath $chromePortFile -TotalCount 2 -Encoding ASCII)



        $port = [int]$lines[0]



        if ($port -le 0 -or $port -gt 65535 -or $lines.Count -lt 2) { $script:blockReason = 8; return $null }



        # Both halves of this TCP flow must match: Hub is initiating the pending



        # loopback connection to Chrome, and Chrome owns the listening CDP port.



        $listeners = @(Get-FastTcpListen $port)



        if ($listeners.Count -ne 1) { $script:blockReason = 9; return $null }



        $chromePid = [int]$listeners[0].OwningProcess



        $chromeProc = Get-Process -Id $chromePid -ErrorAction Stop

        if ($chromeProc.ProcessName -ne "chrome") { $script:blockReason = 10; return $null }

        if (-not $chromeProc.Path -or $chromeProc.Path -notlike "*\Google\Chrome\Application\chrome.exe") { $script:blockReason = 11; return $null }



        $pending = @(Get-FastTcpEstablished $port $hubPid)



        if ($pending.Count -ne 1) {



            if ($pending.Count -gt 1) { Write-WatchLog "HUB_MULTI_SOCKET count=$($pending.Count) hub=$hubPid" }



            $script:blockReason = 12; return $null



        }



        $socketKey = "$hubPid|$chromePid|$($pending[0].LocalPort)"



        # An already approved persistent Hub socket MUST NOT authorize a fresh



        # dialog raised by an unrelated program. Cache the approved connection



        # and never click another dialog while it remains established.



        if ($script:approvedSocketKey -eq $socketKey) { $script:blockReason = 13; return $null }



        # A new browser socket belongs to the verified Hub process. Its



        # pending handshake is never blocked by a nested hub_status query.



        # Already-approved sockets were seeded at watcher startup or marked



        # immediately after this watcher approved their own dialog.



        # Only a CDP connection initiated by Hub *while Hub has no approved



        # connection* is eligible. No auto-consent for external MCP clients.



        return [pscustomobject]@{ HubPid=$hubPid; ChromePid=$chromePid; Port=$port; SocketKey=$socketKey }



    } catch {



        $script:blockReason = 14; return $null



    }



}







function Initialize-ApprovedSocket {



    # One-time startup snapshot. When a previously authorized Hub CDP socket



    # already exists, do not let a foreign client trigger an automatic approval.



    # Do NOT query status while processing an actual CDP dialog: Hub's CDP lock



    # would block the query until the approval opportunity expires.



    try {



        $conn = Get-TrustedPending



        if (-not $conn) { return }



        $endpoint = Get-Content -LiteralPath $endpointFile -Raw -Encoding UTF8 | ConvertFrom-Json



        $pkg = ([string]$endpoint.package) -replace '\\+', '\'



        if ($pkg -notmatch '(?i)[\\/ ]FF-Windows-Bridge[\\/]runtime-releases[\\/](?:hub|bridge)-[0-9a-f]+[\\/]bridge-v3$') { return }



        $pythonCli = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'



        if (-not (Test-Path -LiteralPath $pythonCli)) { return }



        $hubScript = Join-Path $pkg 'ff_hub.py'



        if (-not (Test-Path -LiteralPath $hubScript)) { return }



        $check = New-Object System.Diagnostics.Process



        $check.StartInfo = New-Object System.Diagnostics.ProcessStartInfo



        $check.StartInfo.FileName = $pythonCli



        $check.StartInfo.Arguments = ('"' + $hubScript + '" --state-dir "' + $stateDir + '" status')



        $check.StartInfo.UseShellExecute = $false



        $check.StartInfo.RedirectStandardOutput = $true



        $check.StartInfo.RedirectStandardError = $true



        $check.StartInfo.CreateNoWindow = $true



        try {



            if (-not $check.Start()) { return }



            if (-not $check.WaitForExit(1500)) {



                $check.Kill()



                Write-WatchLog "STARTUP_STATUS_TIMEOUT"



                return



            }



            if ($check.ExitCode -ne 0) { return }



            $status = $check.StandardOutput.ReadToEnd() | ConvertFrom-Json



            if ([int]$status.pid -ne $conn.HubPid) { return }



            if ($status.owner_chrome_secondary.connected -eq $true) {



                $script:approvedSocketKey = $conn.SocketKey



                Write-WatchLog "STARTUP_EXISTING_APPROVED_SOCKET_CACHED"



            } else {



                Write-WatchLog "STARTUP_HUB_SOCKET_NOT_YET_APPROVED"



            }



        } finally {



            $check.Dispose()



        }



    } catch {



        Write-WatchLog "STARTUP_STATUS_ERROR type=$($_.Exception.GetType().Name)"



    }



}







$script:reconnectWorker = $null



$script:lastReconnectCheck = [DateTime]::MinValue



$script:lastReconnectStart = [DateTime]::MinValue



$script:reconnectFailures = 0



$script:reconnectBackoffUntil = [DateTime]::MinValue







function Maybe-StartReconnect {



    # Proactively attach once while idle. This runs independently of ChatGPT



    # and Bridge requests, so a missed Chrome prompt is retried automatically.



    $now = Get-Date



    if (($now - $script:lastReconnectCheck).TotalSeconds -lt 4) { return }



    $script:lastReconnectCheck = $now



    if ($script:reconnectWorker) {



        if (-not $script:reconnectWorker.HasExited) { return }



        $rc = [int]$script:reconnectWorker.ExitCode



        $summary = ""



        try {



            $lines = @(Get-Content -LiteralPath "K:\FF-Windows-Bridge\state\chrome-cdp-consent-watcher\reconnect-worker.log" -Tail 2 -ErrorAction SilentlyContinue)



            $summary = (($lines -join " ") -replace '[\r\n]', ' ')



            if ($summary.Length -gt 160) { $summary = $summary.Substring(0,160) }



        } catch {}



        # Some detached Windows process wrappers return rc=0 even when the



        # structured preflight result says connection=false. Fail closed.



        if ($summary -match '"connected"\s*:\s*false') { $rc = 3 }



        Write-WatchLog "RECONNECT_WORKER_FINISHED rc=$rc detail=$summary"



        if ($rc -eq 0) {



            $script:reconnectFailures = 0



            $script:reconnectBackoffUntil = $now.AddSeconds(30)



        } else {



            $script:reconnectFailures = [Math]::Min(8, $script:reconnectFailures + 1)



            $delay = [Math]::Min(600, 8 * [Math]::Pow(2, $script:reconnectFailures))



            $script:reconnectBackoffUntil = $now.AddSeconds($delay)



            Write-WatchLog "RECONNECT_BACKOFF seconds=$delay failures=$($script:reconnectFailures)"



        }



        $script:reconnectWorker.Dispose()



        $script:reconnectWorker = $null



    }



    if ($now -lt $script:reconnectBackoffUntil) { return }



    if (($now - $script:lastReconnectStart).TotalSeconds -lt 16) { return }



    if (Test-Path -LiteralPath $stopFile) { return }



    if (-not (Resolve-TrustedHub)) { return }



    try {



        $endpoint = Get-Content -LiteralPath $endpointFile -Raw -Encoding UTF8 | ConvertFrom-Json



        $hubPid = [int]$endpoint.pid



        if ($hubPid -le 0) { return }



        # endpoint.json may outlive a replaced Hub. Never spawn workers for dead PIDs.



        $hubProcess = Get-Process -Id $hubPid -ErrorAction SilentlyContinue



        if (-not $hubProcess -or $hubProcess.ProcessName -notin @("python", "pythonw")) { return }



        if (-not (Test-Path -LiteralPath $chromePortFile)) { return }



        $portLines = @(Get-Content -LiteralPath $chromePortFile -TotalCount 1 -Encoding ASCII)



        $cdpPort = [int]$portLines[0]



        if ($cdpPort -le 0 -or $cdpPort -gt 65535) { return }



        $chromeListen = @(Get-FastTcpListen $cdpPort)



        if ($chromeListen.Count -ne 1) { return }



        # Any established Hub-owned CDP socket is either approved or pending.



        # In both cases the existing connection should be handled, not duplicated.



        $already = @(Get-FastTcpEstablished $cdpPort $hubPid)



        if ($already.Count -gt 0) { return }



        # Revoking the existing owner's browser grant also disables proactive



        # reconnection, avoiding unattended permission request spam.



        $policy = Get-Content -LiteralPath $policyFile -Raw -Encoding UTF8 | ConvertFrom-Json



        $grant = @($policy.grants | Where-Object {



            ($_.agents -contains $authorizedAgent -or $_.agents -contains "*") -and



            ($null -eq $_.expires_at -or [double]$_.expires_at -gt [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -and



            $_.revoked -ne $true -and



            ($_.classes -contains $mustHaveClass) -and



            ($true)



        })



        if ($grant.Count -lt 1) { return }



        # A background Chrome has no top-level window to host Chrome 158's



        # native permission dialog. Ask the supervisor to create a bounded



        # temporary window BEFORE initiating the new CDP handshake.



        $chromePid = [int]$chromeListen[0].OwningProcess



        $chromeProcess = Get-Process -Id $chromePid -ErrorAction SilentlyContinue



        if (-not $chromeProcess -or $chromeProcess.ProcessName -ne "chrome") { return }



        if ($chromeProcess.MainWindowHandle -eq [IntPtr]::Zero) {



            $requestFile = "K:\FF-Windows-Bridge\state\chrome-cdp-consent-watcher\support-window-request.json"



            $request = @{



                hub_pid=$hubPid; chrome_pid=$chromePid; cdp_port=$cdpPort



                issued_at=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()



                schema="ff-consent-helper-request-v1"



            }



            $request | ConvertTo-Json -Compress | Set-Content -LiteralPath $requestFile -Encoding UTF8



            return



        }



        $pythonCli = Join-Path $env:LOCALAPPDATA "Programs\Python\Python313\python.exe"



        $worker = "K:\FF-Windows-Bridge\state\chrome-cdp-consent-watcher\reconnect_once.py"



        if (-not (Test-Path -LiteralPath $pythonCli) -or -not (Test-Path -LiteralPath $worker)) { return }



        # Clear any orphaned/expired native CDP consent dialogs before initiating



        # a fresh Hub handshake (safe here because $already.Count -eq 0).



        $staleClosed = Close-StaleNativeDialogs $chromePid



        if ($staleClosed -gt 0) {



            Write-WatchLog "STALE_CDP_DIALOGS_CLOSED count=$staleClosed chrome=$chromePid"



        }



        $script:lastReconnectStart = $now



        $stdoutLog = "K:\FF-Windows-Bridge\state\chrome-cdp-consent-watcher\reconnect-worker.log"



        $stderrLog = "K:\FF-Windows-Bridge\state\chrome-cdp-consent-watcher\reconnect-worker.err.log"



        $script:reconnectWorker = Start-Process -FilePath $pythonCli -ArgumentList ('"' + $worker + '"') -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog



        Write-WatchLog "RECONNECT_WORKER_STARTED pid=$($script:reconnectWorker.Id) hub=$hubPid"



    } catch {



        Write-WatchLog "RECONNECT_WORKER_LAUNCH_FAILED type=$($_.Exception.GetType().Name)"



    }



}







if (-not ("FFNativeDialogWin32" -as [type])) {



    Add-Type -TypeDefinition @"



using System;



using System.Runtime.InteropServices;



public static class FFNativeDialogWin32 {



    [DllImport("user32.dll", SetLastError = true)]



    public static extern bool PostMessageW(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);



}



"@



}







function Close-StaleNativeDialogs([int]$chromePid) {



    $closed = 0



    try {



        $root = [Windows.Automation.AutomationElement]::RootElement



        $chromeWindowCond = New-Object Windows.Automation.PropertyCondition(



            [Windows.Automation.AutomationElement]::ClassNameProperty, "Chrome_WidgetWin_1")



        $windows = $root.FindAll([Windows.Automation.TreeScope]::Children, $chromeWindowCond)



        $names = @("Разрешить удаленную отладку?", "Разрешить удалённую отладку?", "Allow remote debugging?")



        $brvCond = New-Object Windows.Automation.PropertyCondition(

            [Windows.Automation.AutomationElement]::ClassNameProperty, "BrowserRootView")

        foreach ($win in $windows) {

            try {

                if ([int]$win.Current.ProcessId -ne $chromePid) { continue }

                if ($names -contains [string]$win.Current.Name) {

                    $hwnd = [IntPtr]$win.Current.NativeWindowHandle

                    if ($hwnd -ne [IntPtr]::Zero) {

                        [void][FFNativeDialogWin32]::PostMessageW($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)

                        $closed++

                    }

                    continue

                }

                # Also close stale native consent dialogs nested under BrowserRootView (Chrome 158+)

                $brvs = $win.FindAll([Windows.Automation.TreeScope]::Children, $brvCond)

                foreach ($brv in $brvs) {

                    $nested = $brv.FindAll([Windows.Automation.TreeScope]::Children, $chromeWindowCond)

                    foreach ($nd in $nested) {

                        if ($names -notcontains [string]$nd.Current.Name) { continue }

                        $nhwnd = [IntPtr]$nd.Current.NativeWindowHandle

                        if ($nhwnd -ne [IntPtr]::Zero) {

                            [void][FFNativeDialogWin32]::PostMessageW($nhwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)

                            $closed++

                        }

                    }

                }

            } catch { continue }

        }



        if ($closed -gt 0) { Start-Sleep -Milliseconds 150 }



    } catch { }



    return $closed



}







function Find-ExactNativeDialog([int]$chromePid) {



    # Important: do not search by a page's ARIA label and never walk Descendants



    # of the main Chrome browser tab window (scanning a full tab DOM takes ~6s



    # and misses preflight timeouts). Chrome 158 hosts the consent prompt in its



    # own top-level Chrome_WidgetWin_1 window whose Name matches $names.



    $root = [Windows.Automation.AutomationElement]::RootElement



    $chromeWindowCond = New-Object Windows.Automation.PropertyCondition(



        [Windows.Automation.AutomationElement]::ClassNameProperty, "Chrome_WidgetWin_1")



    $windows = $root.FindAll([Windows.Automation.TreeScope]::Children,$chromeWindowCond)



    $windowTypeCond = New-Object Windows.Automation.PropertyCondition(



        [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Window)



    $rootViewCond = New-Object Windows.Automation.PropertyCondition(



        [Windows.Automation.AutomationElement]::ClassNameProperty, "RootView")



    $rootWindow = New-Object Windows.Automation.AndCondition($windowTypeCond,$rootViewCond)



    $btnTypeCond = New-Object Windows.Automation.PropertyCondition(



        [Windows.Automation.AutomationElement]::ControlTypeProperty, [Windows.Automation.ControlType]::Button)



    $mdButtonCond = New-Object Windows.Automation.PropertyCondition(



        [Windows.Automation.AutomationElement]::ClassNameProperty, "MdTextButton")



    $btnNameRU = New-Object Windows.Automation.PropertyCondition(



        [Windows.Automation.AutomationElement]::NameProperty, "Разрешить")



    $btnNameEN = New-Object Windows.Automation.PropertyCondition(



        [Windows.Automation.AutomationElement]::NameProperty, "Allow")



    $btnName = New-Object Windows.Automation.OrCondition($btnNameRU, $btnNameEN)



    $btnQuery = New-Object Windows.Automation.AndCondition(



        (New-Object Windows.Automation.AndCondition($btnTypeCond,$mdButtonCond)), $btnName)



    $names = @("Разрешить удаленную отладку?", "Разрешить удалённую отладку?", "Allow remote debugging?")



    # Fast path: top-level Chrome_WidgetWin_1 dialog windows (Z-order topmost first).



    foreach ($win in $windows) {



        try {



            if ([int]$win.Current.ProcessId -ne $chromePid) { continue }



            $winName = [string]$win.Current.Name



            if ($names -notcontains $winName) { continue }



            if ($win.Current.IsOffscreen) { continue }



            $button = $win.FindFirst([Windows.Automation.TreeScope]::Descendants,$btnQuery)



            if (-not $button) {



                $btnFallback = New-Object Windows.Automation.AndCondition($btnTypeCond,$btnName)



                $button = $win.FindFirst([Windows.Automation.TreeScope]::Descendants,$btnFallback)



            }



            if (-not $button -or $button.Current.IsOffscreen) { continue }



            $rect = $button.Current.BoundingRectangle



            if ($rect.Width -lt 20 -or $rect.Height -lt 15) { continue }



            return [pscustomobject]@{ Button=$button; Dialog=$winName; ButtonName=$button.Current.Name }



        } catch { continue }



    }



    # Chrome 158+ nested path: Chrome_WidgetWin_1 -> BrowserRootView (Children) -> Chrome_WidgetWin_1 (Children, exact Name) -> MdTextButton.

    # Strictly TreeScope::Children down to the tiny native dialog, never scanning tab DOM.

    $brvCond = New-Object Windows.Automation.PropertyCondition(

        [Windows.Automation.AutomationElement]::ClassNameProperty, "BrowserRootView")

    foreach ($win in $windows) {

        try {

            if ([int]$win.Current.ProcessId -ne $chromePid) { continue }

            $brvs = $win.FindAll([Windows.Automation.TreeScope]::Children, $brvCond)

            foreach ($brv in $brvs) {

                $nestedDialogs = $brv.FindAll([Windows.Automation.TreeScope]::Children, $chromeWindowCond)

                for ($ni = $nestedDialogs.Count - 1; $ni -ge 0; $ni--) {

                    $nd = $nestedDialogs[$ni]

                    $ndName = [string]$nd.Current.Name

                    if ($names -notcontains $ndName) { continue }

                    if ($nd.Current.IsOffscreen) { continue }

                    $button = $nd.FindFirst([Windows.Automation.TreeScope]::Descendants, $btnQuery)

                    if (-not $button) {

                        $btnFallback = New-Object Windows.Automation.AndCondition($btnTypeCond, $btnName)

                        $button = $nd.FindFirst([Windows.Automation.TreeScope]::Descendants, $btnFallback)

                    }

                    if (-not $button -or $button.Current.IsOffscreen) { continue }

                    $rect = $button.Current.BoundingRectangle

                    if ($rect.Width -lt 20 -or $rect.Height -lt 15) { continue }

                    return [pscustomobject]@{ Button=$button; Dialog=$ndName; ButtonName=$button.Current.Name }

                }

            }

        } catch { continue }

    }

    # Bounded fallback: direct Window/RootView children only (never Descendants of tab DOM).



    foreach ($win in $windows) {



        try {



            if ([int]$win.Current.ProcessId -ne $chromePid) { continue }



            foreach ($wanted in $names) {



                $dialogName = New-Object Windows.Automation.PropertyCondition(



                    [Windows.Automation.AutomationElement]::NameProperty,$wanted)



                $dialogQuery = New-Object Windows.Automation.AndCondition($rootWindow,$dialogName)



                $dialogs = $win.FindAll([Windows.Automation.TreeScope]::Children,$dialogQuery)



                $dialog = $null



                for ($di=$dialogs.Count-1; $di -ge 0; $di--) {



                    if (-not $dialogs[$di].Current.IsOffscreen) { $dialog=$dialogs[$di]; break }



                }



                if (-not $dialog -or $dialog.Current.IsOffscreen) { continue }



                $button = $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants,$btnQuery)



                if (-not $button) {



                    $btnFallback = New-Object Windows.Automation.AndCondition($btnTypeCond,$btnName)



                    $button = $dialog.FindFirst([Windows.Automation.TreeScope]::Descendants,$btnFallback)



                }



                if (-not $button -or $button.Current.IsOffscreen) { continue }



                $rect = $button.Current.BoundingRectangle



                if ($rect.Width -lt 20 -or $rect.Height -lt 15) { continue }



                return [pscustomobject]@{ Button=$button; Dialog=$wanted; ButtonName=$button.Current.Name }



            }



        } catch { continue }



    }



    return $null



}







if ($ValidateOnly) {



    try {



        $trusted = Resolve-TrustedHub



        @{trusted=[bool]$trusted;pid=if($trusted){$trusted.ProcessId}else{0};state=$stateDir} | ConvertTo-Json -Compress



    } finally { $mutex.ReleaseMutex() | Out-Null; $mutex.Dispose() }



    exit



}







try {



    Write-WatchLog "WATCHER_STARTED mode=$($(if($DryRun){'dry-run'}else{'active'})) pid=$PID"



    Initialize-ApprovedSocket



    $started = Get-Date



    $lastReport = [DateTime]::MinValue



    while ($true) {



        if (Test-Path -LiteralPath $stopFile) {



            Write-WatchLog "WATCHER_STOP_REQUESTED"



            break



        }



        if ($MaxSeconds -gt 0 -and (Get-Date).Subtract($started).TotalSeconds -ge $MaxSeconds) { break }



        try {



        Maybe-StartReconnect



        $conn = Get-TrustedPending



        if ($conn) {



            $match = Find-ExactNativeDialog $conn.ChromePid



            if ($match) {



                $sig = "$($conn.ChromePid):$($conn.HubPid):$($match.Dialog)"



                if ($DryRun) {



                    if ((Get-Date).Subtract($lastReport).TotalSeconds -ge 2) {



                        Write-WatchLog "DRYRUN_MATCH hub=$($conn.HubPid) chrome=$($conn.ChromePid) title=$($match.Dialog)"



                        $lastReport = Get-Date



                    }



                } elseif ($lastSuccessfulDialog -ne $sig) {



                    # This is Chrome's own InvokePattern, not pointer input.



                    # The source socket is rechecked immediately before invoking.



                    $verify = Get-TrustedPending



                    if ($verify -and $verify.HubPid -eq $conn.HubPid -and $verify.ChromePid -eq $conn.ChromePid -and $verify.SocketKey -eq $conn.SocketKey) {



                        try {



                            $pattern = $match.Button.GetCurrentPattern([Windows.Automation.InvokePattern]::Pattern)



                            $pattern.Invoke()



                            Write-WatchLog "CDP_DIALOG_APPROVED hub=$($conn.HubPid) chrome=$($conn.ChromePid) title=$($match.Dialog)"



                            $lastSuccessfulDialog = $sig



                            $script:approvedSocketKey = $conn.SocketKey



                        } catch {



                            # Chrome destroys the native dialog immediately after



                            # accepting. UIA can throw on the now-stale element



                            # even though the click worked. Verify disappearance.



                            $errorType=$_.Exception.GetType().Name



                            $innerType=if ($_.Exception.InnerException) {$_.Exception.InnerException.GetType().Name} else {"none"}



                            Start-Sleep -Milliseconds 160



                            $stillVisible = Find-ExactNativeDialog $conn.ChromePid



                            if (-not $stillVisible) {



                                Write-WatchLog "CDP_DIALOG_DISAPPEARED_AFTER_INVOKE hub=$($conn.HubPid) chrome=$($conn.ChromePid) exception=$errorType/$innerType"



                                $lastSuccessfulDialog = $sig



                                $script:approvedSocketKey = $conn.SocketKey



                            } else {



                                Write-WatchLog "INVOKE_FAILED_DIALOG_STILL_VISIBLE hub=$($conn.HubPid) type=$errorType/$innerType"



                            }



                        }



                    }



                }



            } else {



                $lastSuccessfulDialog = $null



            }



        } else {



            $lastSuccessfulDialog = $null



        }



        } catch { Write-WatchLog "LOOP_ERROR type=$($_.Exception.GetType().Name) message=$($_.Exception.Message)" }



        if ((Get-Date).Subtract($lastReport).TotalSeconds -ge 30) {



            Write-WatchLog "HEARTBEAT hub_state=$stateDir reconnect_failures=$script:reconnectFailures block=$script:blockReason"



            $lastReport = Get-Date



        }



        Start-Sleep -Milliseconds ([Math]::Max(250,$PollMilliseconds))



    }



} finally {



    Write-WatchLog "WATCHER_STOPPED"



    $mutex.ReleaseMutex() | Out-Null



    $mutex.Dispose()



}



