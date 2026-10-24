[CmdletBinding(PositionalBinding = $false)]
param(
    [string] $TokenPath = (Join-Path $env:LOCALAPPDATA 'FFWindowsBridge\secrets\playwright-extension-token.dpapi')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) {
    throw "Playwright extension token is not provisioned at $TokenPath"
}

$node = (Get-Command node.exe -ErrorAction Stop).Source
$rpc = Join-Path $PSScriptRoot 'cua_browser_rpc.mjs'
$coreBundle = Join-Path $PSScriptRoot 'node_modules\playwright-core\lib\coreBundle.js'
if (-not (Test-Path -LiteralPath $rpc -PathType Leaf)) {
    throw 'BROWSER_RPC_NOT_INSTALLED'
}
if (-not (Test-Path -LiteralPath $coreBundle -PathType Leaf)) {
    throw 'PINNED_PLAYWRIGHT_RUNTIME_NOT_INSTALLED'
}

Add-Type -AssemblyName System.Security
$sealed = [IO.File]::ReadAllBytes($TokenPath)
$plain = [Security.Cryptography.ProtectedData]::Unprotect(
    $sealed,
    $null,
    [Security.Cryptography.DataProtectionScope]::CurrentUser
)
$token = [Text.Encoding]::UTF8.GetString($plain)
if ($token -notmatch '^[A-Za-z0-9_-]{40,}$') {
    throw 'The protected Playwright extension token is malformed.'
}

$previousToken = [Environment]::GetEnvironmentVariable('PLAYWRIGHT_MCP_EXTENSION_TOKEN', 'Process')
try {
    [Environment]::SetEnvironmentVariable('PLAYWRIGHT_MCP_EXTENSION_TOKEN', $token, 'Process')
    & $node $rpc
    exit $LASTEXITCODE
}
finally {
    [Environment]::SetEnvironmentVariable('PLAYWRIGHT_MCP_EXTENSION_TOKEN', $previousToken, 'Process')
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    $token = $null
    $sealed = $null
}
