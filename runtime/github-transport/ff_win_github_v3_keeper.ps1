param([string]$Root, [string]$Python, [int]$Port = 39073)
$ErrorActionPreference = 'Stop'
# Minimal keeper for a clean GitHub-only installation. Existing V3 keepers
# and Commander/Cloudflare are neither replaced nor restarted.
$env:FF_BRIDGE_ROOT = Split-Path -Parent $Root
$nodeRoot = [IO.Path]::GetFullPath((Join-Path $env:FF_BRIDGE_ROOT 'tools\node'))
$nodeFile = [IO.Directory]::EnumerateFiles(('\\?\' + $nodeRoot),'node.exe',[IO.SearchOption]::AllDirectories) | Select-Object -First 1
if (-not $nodeFile) { throw 'BUNDLED_NODE_MISSING' }
$nodeDirectory = Split-Path -Parent $nodeFile.Substring(4)
$env:PATH = $nodeDirectory + ';' + $env:PATH
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path $Root 'browsers'
while ($true) {
    & $Python (Join-Path $Root 'ff_win_v3_main.py') serve --port $Port
    Start-Sleep -Seconds 2
}
