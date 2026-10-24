[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string] $BridgeRoot = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\bridge-v3')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$extensionId = 'mmhkecdcdceeibbhalmfhjleeebgdbhk'
$hostName = 'com.ff.browser_companion'
$extensionSource = Join-Path $SourceRoot 'browser_companion'
$extensionRuntime = Join-Path $BridgeRoot 'browser_companion'
$hostSource = Join-Path $SourceRoot 'tools\cua_browser_companion_host.cs'
$hostExe = Join-Path $BridgeRoot 'cua_browser_companion_host.exe'
$hostManifest = Join-Path $BridgeRoot 'cua_browser_companion_native_host.json'

if (-not (Test-Path -LiteralPath $extensionSource -PathType Container)) { throw 'COMPANION_SOURCE_MISSING' }
if (-not (Test-Path -LiteralPath $hostSource -PathType Leaf)) { throw 'COMPANION_HOST_SOURCE_MISSING' }
New-Item -ItemType Directory -Force -Path $BridgeRoot | Out-Null
if (Test-Path -LiteralPath $extensionRuntime) { Remove-Item -LiteralPath $extensionRuntime -Recurse -Force }
Copy-Item -LiteralPath $extensionSource -Destination $extensionRuntime -Recurse -Force
$cscCandidates = @(
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
    (Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe')
)
$csc = $cscCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $csc) { throw 'CSC_NOT_FOUND' }
& $csc /nologo /target:exe /out:$hostExe /r:System.Web.Extensions.dll $hostSource
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $hostExe -PathType Leaf)) { throw 'COMPANION_HOST_BUILD_FAILED' }

$manifestObject = [ordered]@{
    name = $hostName
    description = 'FF Browser Companion native messaging host'
    path = $hostExe
    type = 'stdio'
    allowed_origins = @("chrome-extension://$extensionId/")
}
$manifestJson = $manifestObject | ConvertTo-Json -Depth 4
[IO.File]::WriteAllText($hostManifest, $manifestJson, (New-Object Text.UTF8Encoding($false)))
$regPath = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$hostName"
New-Item -Path $regPath -Force | Out-Null
Set-Item -Path $regPath -Value $hostManifest
$result = [ordered]@{
    ok = $true
    extension_id = $extensionId
    extension_path = $extensionRuntime
    extension_version = (Get-Content -LiteralPath (Join-Path $extensionRuntime 'manifest.json') -Raw | ConvertFrom-Json).version
    host_path = $hostExe
    host_manifest = $hostManifest
    host_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $hostExe).Hash
    manifest_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $extensionRuntime 'manifest.json')).Hash
    service_worker_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $extensionRuntime 'service_worker.js')).Hash
    state_machine_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $extensionRuntime 'download_state.mjs')).Hash
}
$result | ConvertTo-Json -Compress
