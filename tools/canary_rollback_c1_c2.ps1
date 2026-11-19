<#
.SYNOPSIS
Safe idle-verified, lease-verified, receipt-preserving canary rollback script for C1 + C2.

.DESCRIPTION
Defaults to SAFE DRY-RUN. Never uses substring process matching or blind Stop-Process -Force;
never kills active Hub sessions or active C2 jobs; never runs `git checkout` against live
production. Verifies 4-factor process identity (PID + kernel creation FILETIME + executable &
entrypoint path + owner lease), captures SQLite Online Backup API snapshots, restores immutable
shadow releases, and preserves persistent SQLite receipts (`canary_receipts.sqlite3`,
`entry-grants.sqlite3`, `hub.db`).
#>
[CmdletBinding()]
param(
    [ValidateSet('DryRun', 'ShadowRollback', 'StopIdleShadow', 'VerifyReceipts')]
    [string]$Mode = 'DryRun',
    [switch]$ConfirmShadowRollback,
    [switch]$ConfirmOwnerRollback,
    [string]$ShadowRoot = '',
    [string]$C1TargetReleaseId = '',
    [string]$C1BaselineZipPath = '',
    [string]$C1BaselineZipSha256 = '',
    [string]$C2TargetReleaseId = '',
    [string]$C2RestoreDbBackupPath = '',
    [string]$C2RestoreDbBackupSha256 = '',
    [string]$PrivateRuntimeHome = '',
    [string]$RequestKey = '',
    [int]$ReceiptLimit = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$workflowPy = Join-Path $PSScriptRoot 'canary_release_workflow.py'
if (-not (Test-Path -LiteralPath $workflowPy -PathType Leaf)) {
    throw 'CANARY_WORKFLOW_ENGINE_MISSING'
}

if ([string]::IsNullOrWhiteSpace($ShadowRoot)) {
    throw 'SHADOW_ROOT_INVALID: -ShadowRoot is mandatory'
}

# Production rollback is never executed automatically from the canary helper.
if ($ConfirmOwnerRollback) {
    throw 'LIVE_PRODUCTION_MUTATION_FORBIDDEN: Production rollback requires manual operator execution with verified cold rollback bundle (tools/cua_cold_rollback_bundle.py) and docs/CANARY_MANUAL_CUTOVER_PLAYBOOK_RU.md'
}

if ($C1BaselineZipPath -and ($C1BaselineZipSha256 -notmatch '^[0-9a-fA-F]{64}$')) {
    throw 'PINNED_SHA256_REQUIRED: -C1BaselineZipSha256 must be exact 64 hex characters when -C1BaselineZipPath is supplied'
}
if ($C2RestoreDbBackupPath -and ($C2RestoreDbBackupSha256 -notmatch '^[0-9a-fA-F]{64}$')) {
    throw 'PINNED_SHA256_REQUIRED: -C2RestoreDbBackupSha256 must be exact 64 hex characters when -C2RestoreDbBackupPath is supplied'
}

if ($Mode -eq 'StopIdleShadow') {
    & python -X utf8 $workflowPy stop-shadow --shadow-root $ShadowRoot
    exit $LASTEXITCODE
}

if ($Mode -eq 'VerifyReceipts') {
    & python -X utf8 $workflowPy verify-receipts --shadow-root $ShadowRoot --limit ([string]$ReceiptLimit)
    exit $LASTEXITCODE
}

$rbArgs = @('rollback', '--shadow-root', $ShadowRoot)
if ($Mode -eq 'ShadowRollback') {
    if (-not $ConfirmShadowRollback) {
        throw 'SHADOW_ROLLBACK_CONFIRMATION_REQUIRED: pass -ConfirmShadowRollback explicitly to execute shadow rollback'
    }
    $rbArgs += '--confirm-shadow-rollback'
}
if ($C1TargetReleaseId) { $rbArgs += @('--c1-target-release', $C1TargetReleaseId) }
if ($C1BaselineZipPath) { $rbArgs += @('--c1-baseline-zip', $C1BaselineZipPath, '--c1-baseline-zip-sha256', $C1BaselineZipSha256) }
if ($C2TargetReleaseId) { $rbArgs += @('--c2-target-release', $C2TargetReleaseId) }
if ($C2RestoreDbBackupPath) { $rbArgs += @('--restore-c2-db-backup', $C2RestoreDbBackupPath, '--restore-c2-db-backup-sha256', $C2RestoreDbBackupSha256) }
if ($PrivateRuntimeHome) { $rbArgs += @('--private-runtime-home', $PrivateRuntimeHome) }
if ($RequestKey) { $rbArgs += @('--request-key', $RequestKey) }

& python -X utf8 $workflowPy @rbArgs
exit $LASTEXITCODE
