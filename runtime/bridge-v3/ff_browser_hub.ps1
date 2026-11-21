[CmdletBinding(PositionalBinding = $false)]
param(
    [Parameter(Mandatory = $true)][string] $StateDir,
    [Parameter(Mandatory = $true)][string] $EndpointFile,
    [string] $PlaywrightRoot = $PSScriptRoot,
    [string] $ProfileDirName = '',
    [int] $Port = 0,
    [string] $TokenPath = (Join-Path $env:LOCALAPPDATA 'FFWindowsBridge\secrets\playwright-extension-token.dpapi')
)
# Starts the FF Browser Session Manager with the owner's Playwright extension token.
# The launcher passes the DPAPI-unsealed token to Node through its environment.
# The official Playwright relay supplies it to Chrome through its extension connect URL.

$ErrorActionPreference = 'Stop'
if (-not $env:FF_BROWSER_HUB_KEY) { throw 'FF_BROWSER_HUB_KEY_REQUIRED' }
if (-not (Test-Path -LiteralPath $TokenPath -PathType Leaf)) { throw 'EXTENSION_TOKEN_NOT_PROVISIONED' }
if ($ProfileDirName -and $ProfileDirName -notmatch '^(Default|Profile [0-9]+)$') { throw 'OWNER_CHROME_PROFILE_INVALID' }
$node = (Get-Command node.exe -ErrorAction Stop).Source
$hub = Join-Path $PSScriptRoot 'ff_browser_hub.mjs'
if (-not (Test-Path -LiteralPath $hub -PathType Leaf)) { throw 'BROWSER_HUB_NOT_INSTALLED' }

# Verify pinned Playwright coreBundle.js integrity BEFORE unsealing the DPAPI token.
$integrityScript = Join-Path $PSScriptRoot 'cua_playwright_integrity.py'
$python = Get-Command python.exe -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath $integrityScript -PathType Leaf) -and $null -ne $python) {
    $null = & $python.Source $integrityScript --playwright-root $PlaywrightRoot
    if ($LASTEXITCODE -ne 0) {
        if ($LASTEXITCODE -eq 2) { throw 'PLAYWRIGHT_CORE_BUNDLE_TAMPERED' }
        throw "PLAYWRIGHT_INTEGRITY_CHECK_FAILED_$LASTEXITCODE"
    }
}

# Check before unsealing the token: on older Chrome even a token-authenticated connect
# page can take the foreground. Do not launch Chrome or silently fall back to that path.
$preflightSource = @'
import {pathToFileURL} from 'node:url';
import path from 'node:path';
try {
  const {backgroundChromePreflight, verifyPlaywrightCoreBundle} = await import(pathToFileURL(process.argv[2]).href);
  verifyPlaywrightCoreBundle(process.argv[5]);
  await backgroundChromePreflight({profileBindingFile: path.join(process.argv[3], 'owner-profile-binding.json'),
    profileDirName: process.argv[4] || undefined});
} catch (error) {
  process.stderr.write((error.code || 'BACKGROUND_PREFLIGHT_UNAVAILABLE') + '\n');
  process.exit(3);
}
'@
& $node --input-type=module -e $preflightSource -- ff-background-preflight $hub $StateDir $ProfileDirName $PlaywrightRoot
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Add-Type -AssemblyName System.Security
$plain = [Security.Cryptography.ProtectedData]::Unprotect(
    [IO.File]::ReadAllBytes($TokenPath), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
try {
    $token = [Text.Encoding]::UTF8.GetString($plain)
    if ($token -notmatch '^[A-Za-z0-9_-]{40,}$') { throw 'EXTENSION_TOKEN_MALFORMED' }
    [Environment]::SetEnvironmentVariable('PLAYWRIGHT_MCP_EXTENSION_TOKEN', $token, 'Process')
    $arguments = @($hub, '--state-dir', $StateDir, '--endpoint-file', $EndpointFile,
        '--playwright-root', $PlaywrightRoot, '--port', [string]$Port)
    if ($ProfileDirName) { $arguments += @('--profile', $ProfileDirName) }
    & $node @arguments
    exit $LASTEXITCODE
}
finally {
    [Environment]::SetEnvironmentVariable('PLAYWRIGHT_MCP_EXTENSION_TOKEN', $null, 'Process')
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    $token = $null
}
