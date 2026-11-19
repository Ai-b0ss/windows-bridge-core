<#
.SYNOPSIS
Product canary staging, health verification, and cutover-readiness script for FF Windows Bridge (C1) + GeminiTaskGateway (C2).

.DESCRIPTION
Defaults to SAFE DRY-RUN. Enforces mandatory pinned SHA-256 (empty SHA-256 hard-fails),
protected production port/path boundaries, real separate-codebase C2 staging via immutable
archive + SQLite Online Backup API, 4-factor process leases, and persistent SQLite receipts.
Production services (ports 20128, 21476, 21477, 39073, 39076, 39090) are NEVER automatically
restarted or modified by this script.
#>
[CmdletBinding()]
param(
    [ValidateSet('DryRun', 'ShadowStage', 'ShadowVerify', 'ShadowFull', 'PrepareReadiness')]
    [string]$Mode = 'DryRun',
    [switch]$ConfirmOwnerCutover,
    [string]$FullCoreZipPath = '',
    [string]$FullCoreSha256 = '',
    [string]$C1ExpectedCommit = '',
    [string]$ShadowRoot = '',
    [int]$C1RpcPort = 39173,
    [int]$C1HubPort = 39190,
    [string]$C2RepoPath = '',
    [string]$C2ExpectedCommit = '',
    [string]$C2ZipPath = '',
    [string]$C2ZipSha256 = '',
    [string]$C2SourceDbPath = '',
    [int]$C2GatewayPort = 21587,
    [int]$C2UnifiedPort = 21588,
    [int]$C2OmniPort = 20128,
    [int]$HealthConsecutivePasses = 2,
    [switch]$SkipC2,
    [switch]$StartC1Rpc,
    [switch]$RunFullInstaller,
    [switch]$AllowNonHeadC2Commit,
    [switch]$RequireUpstreamOmniroute,
    [switch]$StopAfterVerify,
    [string]$RequestKey = '',
    [string]$ReadinessOutputPath = '',
    [string]$ReadinessManifestPath = '',
    [string]$OwnerApprovalFile = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$workflowPy = Join-Path $PSScriptRoot 'canary_release_workflow.py'
if (-not (Test-Path -LiteralPath $workflowPy -PathType Leaf)) {
    throw 'CANARY_WORKFLOW_ENGINE_MISSING'
}

# Defense-in-depth validation in PowerShell before invoking the Python engine.
$forbiddenPorts = @(20128, 21476, 21477, 39073, 39076, 39090)

function Assert-PinnedSha256([string]$Value, [string]$Name) {
    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw "PINNED_SHA256_REQUIRED: $Name must be a non-empty 64-hex SHA-256"
    }
    if ($Value -notmatch '^[0-9a-fA-F]{64}$') {
        throw "PINNED_SHA256_INVALID: $Name must be exact 64 hex characters"
    }
}

function Assert-SafeShadowPort([int]$Port, [string]$Name) {
    if ($Port -lt 1024 -or $Port -gt 65535) {
        throw "SHADOW_PORT_INVALID: $Name=$Port"
    }
    if ($forbiddenPorts -contains $Port) {
        throw "SHADOW_PORT_FORBIDDEN_PRODUCTION_PORT: $Name=$Port collides with a protected production port"
    }
}

if ([string]::IsNullOrWhiteSpace($ShadowRoot)) {
    throw 'SHADOW_ROOT_INVALID: -ShadowRoot is mandatory and must point to an isolated non-production directory'
}

Assert-SafeShadowPort $C1RpcPort 'C1RpcPort'
Assert-SafeShadowPort $C1HubPort 'C1HubPort'
if (-not $SkipC2) {
    Assert-SafeShadowPort $C2GatewayPort 'C2GatewayPort'
    Assert-SafeShadowPort $C2UnifiedPort 'C2UnifiedPort'
}

# Explicit owner cutover gate: NEVER auto-restarts production; verifies readiness + approval only.
if ($ConfirmOwnerCutover) {
    Assert-PinnedSha256 $FullCoreSha256 'FullCoreSha256'
    $gateArgs = @('-X', 'utf8', $workflowPy, 'verify-owner-gate', '--c1-zip-sha256', $FullCoreSha256)
    if ($C2ExpectedCommit) { $gateArgs += @('--c2-commit', $C2ExpectedCommit) }
    if ($ReadinessManifestPath) { $gateArgs += @('--readiness', $ReadinessManifestPath) }
    if ($OwnerApprovalFile) { $gateArgs += @('--approval', $OwnerApprovalFile) }
    & python @gateArgs
    exit $LASTEXITCODE
}

function Invoke-Workflow([string[]]$PyArgs) {
    & python -X utf8 $workflowPy @PyArgs
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

if ($Mode -eq 'PrepareReadiness') {
    if ([string]::IsNullOrWhiteSpace($ReadinessOutputPath)) {
        $ReadinessOutputPath = Join-Path $ShadowRoot 'state\cutover-readiness.json'
    }
    Invoke-Workflow @('prepare-readiness', '--shadow-root', $ShadowRoot, '--output', $ReadinessOutputPath)
    exit 0
}

if ($Mode -eq 'ShadowVerify') {
    $healthArgs = @(
        'health', '--shadow-root', $ShadowRoot,
        '--consecutive-passes', ([string]$HealthConsecutivePasses)
    )
    if ($StartC1Rpc) { $healthArgs += '--c1-rpc' }
    if ($SkipC2) { $healthArgs += @('--no-c2-gateway', '--no-c2-unified') }
    if ($RequireUpstreamOmniroute) { $healthArgs += '--require-upstream-omniroute' }
    if ($RequestKey) { $healthArgs += @('--request-key', $RequestKey) }
    Invoke-Workflow $healthArgs
    exit 0
}

# DryRun, ShadowStage, ShadowFull all require mandatory pinned SHA-256 and source paths.
if ([string]::IsNullOrWhiteSpace($FullCoreZipPath)) {
    throw 'ARCHIVE_MISSING: -FullCoreZipPath is mandatory'
}
Assert-PinnedSha256 $FullCoreSha256 'FullCoreSha256'
if (-not $SkipC2) {
    if ($C2RepoPath) {
        if ([string]::IsNullOrWhiteSpace($C2ExpectedCommit) -or $C2ExpectedCommit -notmatch '^[0-9a-fA-F]{40}$') {
            throw 'PINNED_COMMIT_REQUIRED: -C2ExpectedCommit must be a 40-hex Git commit SHA'
        }
    } elseif ($C2ZipPath) {
        Assert-PinnedSha256 $C2ZipSha256 'C2ZipSha256'
    } else {
        throw 'C2_SOURCE_REQUIRED: provide -C2RepoPath + -C2ExpectedCommit or -C2ZipPath + -C2ZipSha256 (or -SkipC2)'
    }
}

$commonArgs = @(
    '--shadow-root', $ShadowRoot,
    '--c1-zip', $FullCoreZipPath,
    '--c1-zip-sha256', $FullCoreSha256,
    '--c1-rpc-port', ([string]$C1RpcPort),
    '--c1-hub-port', ([string]$C1HubPort),
    '--c2-gateway-port', ([string]$C2GatewayPort),
    '--c2-unified-port', ([string]$C2UnifiedPort),
    '--c2-omni-port', ([string]$C2OmniPort)
)
if ($C1ExpectedCommit) { $commonArgs += @('--c1-expected-commit', $C1ExpectedCommit) }
if ($SkipC2) { $commonArgs += '--skip-c2' }
if ($C2RepoPath) { $commonArgs += @('--c2-repo', $C2RepoPath) }
if ($C2ExpectedCommit) { $commonArgs += @('--c2-commit', $C2ExpectedCommit) }
if ($C2ZipPath) { $commonArgs += @('--c2-zip', $C2ZipPath) }
if ($C2ZipSha256) { $commonArgs += @('--c2-zip-sha256', $C2ZipSha256) }

if ($Mode -eq 'DryRun') {
    Invoke-Workflow (@('plan') + $commonArgs)
    exit 0
}

$stageArgs = @('stage') + $commonArgs
if ($C2SourceDbPath) { $stageArgs += @('--c2-source-db', $C2SourceDbPath) }
if ($RunFullInstaller) { $stageArgs += '--run-full-installer' }
if ($AllowNonHeadC2Commit) { $stageArgs += '--allow-non-head-c2-commit' }
if ($RequestKey) { $stageArgs += @('--request-key', $RequestKey) }

if ($Mode -eq 'ShadowStage') {
    Invoke-Workflow $stageArgs
    exit 0
}

# Mode -eq 'ShadowFull': stage -> start shadow services -> verify health -> optional clean idle stop.
$stageOut = & python -X utf8 $workflowPy @stageArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$startArgs = @('start-shadow', '--shadow-root', $ShadowRoot)
if ($StartC1Rpc) { $startArgs += '--c1-rpc' }
if ($SkipC2) { $startArgs += @('--no-c2-gateway', '--no-c2-unified') }
$startOut = & python -X utf8 $workflowPy @startArgs
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

try {
    $healthArgs = @('health', '--shadow-root', $ShadowRoot, '--consecutive-passes', ([string]$HealthConsecutivePasses))
    if ($StartC1Rpc) { $healthArgs += '--c1-rpc' }
    if ($SkipC2) { $healthArgs += @('--no-c2-gateway', '--no-c2-unified') }
    if ($RequireUpstreamOmniroute) { $healthArgs += '--require-upstream-omniroute' }
    $healthOut = & python -X utf8 $workflowPy @healthArgs
    $healthCode = $LASTEXITCODE
    Write-Output ([ordered]@{
        ok = ($healthCode -eq 0)
        mode = 'SHADOW_FULL'
        stage = ($stageOut | ConvertFrom-Json)
        start = ($startOut | ConvertFrom-Json)
        health = ($healthOut | ConvertFrom-Json)
        live_production_mutated = $false
    } | ConvertTo-Json -Depth 10)
    if ($healthCode -ne 0) { exit $healthCode }
} finally {
    if ($StopAfterVerify) {
        & python -X utf8 $workflowPy stop-shadow --shadow-root $ShadowRoot | Out-Null
    }
}
exit 0
