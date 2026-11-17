[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string] $Script,
    [string[]] $ScriptArgs = @(),
    [string] $TokenPath = (Join-Path $env:LOCALAPPDATA 'FFWindowsBridge\secrets\playwright-extension-token.dpapi')
)
# Local owner-machine test launcher. Unseals the Playwright extension token with DPAPI into
# this process only and runs a Node or Python test with it. Never prints the token.
$ErrorActionPreference = 'Stop'
# Browser smoke checks upstream background-connect preconditions before reading DPAPI.
if ([IO.Path]::GetFileName($Script) -in @('browser_hub_owner_chrome_smoke.mjs', 'hub_real_smoke.py')) {
    $hub = Join-Path (Split-Path -Parent $PSScriptRoot) '..\runtime\bridge-v3\ff_browser_hub.mjs'
    $preflightSource = @'
import {pathToFileURL} from 'node:url';
try {
  const {backgroundChromePreflight} = await import(pathToFileURL(process.argv[2]).href);
  await backgroundChromePreflight();
} catch (error) {
  process.stdout.write(JSON.stringify({status: 'NOT_RUN', reason: error.code || 'BACKGROUND_PREFLIGHT_UNAVAILABLE'}) + '\n');
  process.exit(3);
}
'@
    & node.exe --input-type=module -e $preflightSource -- ff-background-preflight $hub
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) { throw 'EXTENSION_TOKEN_NOT_PROVISIONED' }
Add-Type -AssemblyName System.Security
$plain = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($TokenPath), $null,
    [Security.Cryptography.DataProtectionScope]::CurrentUser)
try {
    $env:PLAYWRIGHT_MCP_EXTENSION_TOKEN = [Text.Encoding]::UTF8.GetString($plain)
    $runner = if ($Script -match '\.py$') { if ($env:FF_TEST_PYTHON) { $env:FF_TEST_PYTHON } else { 'python.exe' } } else { 'node.exe' }
    & $runner $Script @ScriptArgs
    exit $LASTEXITCODE
}
finally {
    $env:PLAYWRIGHT_MCP_EXTENSION_TOKEN = $null
    [Array]::Clear($plain, 0, $plain.Length)
}
