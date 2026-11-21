$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$PackageRoot = $PSScriptRoot
$Manifest = Join-Path $PackageRoot 'package.json'
$Lockfile = Join-Path $PackageRoot 'package-lock.json'

if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    throw 'BROWSER_RUNTIME_MANIFEST_MISSING'
}
if (-not (Test-Path -LiteralPath $Lockfile -PathType Leaf)) {
    throw 'BROWSER_RUNTIME_LOCKFILE_MISSING'
}

$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if ($null -eq $npm) {
    throw 'NPM_NOT_INSTALLED'
}

& $npm.Source ci --prefix $PackageRoot --omit=dev --ignore-scripts --no-audit --no-fund
if ($LASTEXITCODE -ne 0) {
    throw "BROWSER_RUNTIME_NPM_CI_FAILED_$LASTEXITCODE"
}

$node = Get-Command node.exe -ErrorAction SilentlyContinue
if ($null -eq $node) {
    throw 'NODE_NOT_INSTALLED'
}

$verify = @'
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const localRequire = createRequire(path.join(process.argv[1], 'package.json'));
const { dependencies } = localRequire('./package.json');
for (const name of ['@playwright/cli', 'playwright', 'playwright-core']) {
  const version = dependencies?.[name];
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version || ''))
    throw new Error(`BROWSER_RUNTIME_VERSION_NOT_PINNED_${name}`);
  const actual = localRequire(name + '/package.json').version;
  if (actual !== version)
    throw new Error(`BROWSER_RUNTIME_VERSION_MISMATCH_${name}_${actual}`);
}
const bundlePath = localRequire.resolve('playwright-core/lib/coreBundle');
const bundleText = fs.readFileSync(bundlePath, 'utf8');
const forbidden = [
  /pw_connect_url/i,
  /ChatGPT_Conversation_Audit/i,
  /(?<![A-Za-z0-9_])[A-Za-z]:[/\\]{1,2}Users[/\\]{1,2}/i,
  /\/Users\/[A-Za-z0-9._-]+\//,
  /require\s*\(\s*['"](?:node:)?fs['"]\s*\)\s*\.\s*(?:writeFileSync|appendFileSync|writeFile|promises\s*\.\s*writeFile)/,
  /(?:writeFileSync|appendFileSync|writeFile)\s*\([^;\n]{0,240}(?:connect|token|relay|pw_|audit|extension|ws:\/\/|chrome-extension:\/\/|\.txt\b)/i,
];
for (const pattern of forbidden) {
  if (pattern.test(bundleText))
    throw new Error('PLAYWRIGHT_CORE_BUNDLE_TAMPERED');
}
localRequire('playwright');
const coreBundle = localRequire('playwright-core/lib/coreBundle');
if (typeof coreBundle.tools?.createBrowserWithInfo !== 'function')
  throw new Error('PLAYWRIGHT_EXTENSION_FACTORY_EXPORT_MISSING');
'@

& $node.Source -e $verify $PackageRoot
if ($LASTEXITCODE -ne 0) {
    throw "BROWSER_RUNTIME_VERIFY_FAILED_$LASTEXITCODE"
}

$integrityScript = Join-Path $PackageRoot 'cua_playwright_integrity.py'
$python = Get-Command python.exe -ErrorAction SilentlyContinue
if ((Test-Path -LiteralPath $integrityScript -PathType Leaf) -and $null -ne $python) {
    $null = & $python.Source $integrityScript --playwright-root $PackageRoot
    if ($LASTEXITCODE -ne 0) {
        if ($LASTEXITCODE -eq 2) { throw 'PLAYWRIGHT_CORE_BUNDLE_TAMPERED' }
        throw "BROWSER_RUNTIME_INTEGRITY_FAILED_$LASTEXITCODE"
    }
}

Write-Output 'BROWSER_RUNTIME_READY'

