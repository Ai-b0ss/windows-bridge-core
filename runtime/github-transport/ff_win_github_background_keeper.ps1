param([string]$Root, [string]$Python, [int]$Port = 39075)
$env:FF_BRIDGE_ROOT = Split-Path -Parent $Root
$env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + $env:PSModulePath
$ErrorActionPreference = 'Stop'
$rootHash = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($Root).ToLowerInvariant()))).Replace('-','').Substring(0,16)
$mutex = [Threading.Mutex]::new($false, ('Global\FF-GitHub-Background-' + $rootHash))
$owned=$false
try {
    try { $owned=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned=$true }
    if (-not $owned) { exit 0 }
    while ($true) {
        & $Python (Join-Path $Root 'ff_win_github_background_agent.py') --port $Port
        Start-Sleep -Seconds 2
    }
} finally { if ($owned) { $mutex.ReleaseMutex() };$mutex.Dispose() }
