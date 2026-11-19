<#
.SYNOPSIS
PowerShell regression suite for tools/canary_cutover_c1_c2.ps1 and tools/canary_rollback_c1_c2.ps1.
Runs strictly in disposable temporary directories on non-production ports.
Never touches production installations, production ports, or the visible desktop.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$cutoverScript = Join-Path $repoRoot 'tools\canary_cutover_c1_c2.ps1'
$rollbackScript = Join-Path $repoRoot 'tools\canary_rollback_c1_c2.ps1'

if (-not (Test-Path -LiteralPath $cutoverScript -PathType Leaf)) { throw "MISSING_CUTOVER_SCRIPT: $cutoverScript" }
if (-not (Test-Path -LiteralPath $rollbackScript -PathType Leaf)) { throw "MISSING_ROLLBACK_SCRIPT: $rollbackScript" }

function Format-WinArg([string]$Arg) {
    if ($null -eq $Arg -or $Arg.Length -eq 0) { return '""' }
    if ($Arg -notmatch '[\s"]') { return $Arg }
    return '"' + ($Arg -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-PsScript {
    param([string]$ScriptPath, [string[]]$Arguments)
    $allArgs = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $ScriptPath) + $Arguments
    $argLine = ($allArgs | ForEach-Object { Format-WinArg $_ }) -join ' '
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = $argLine
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    $proc = [System.Diagnostics.Process]::new()
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $proc.WaitForExit()
    $out = $outTask.GetAwaiter().GetResult()
    $err = $errTask.GetAwaiter().GetResult()
    $code = [int]$proc.ExitCode
    $proc.Dispose()
    return [ordered]@{
        exit_code = $code
        stdout    = [string]$out
        stderr    = [string]$err
    }
}

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "ASSERTION_FAILED: $Message" }
}

$tempBase = Join-Path ([IO.Path]::GetTempPath()) ('ff-canary-ps-test-' + [Guid]::NewGuid().ToString('N').Substring(0, 10))
New-Item -ItemType Directory -Path $tempBase -Force | Out-Null

$results = [System.Collections.Generic.List[object]]::new()

try {
    # Prepare isolated fixture ZIP + C2 git repo using Python helper.
    $fixtureHelper = @'
import hashlib, json, subprocess, sys, zipfile
from pathlib import Path
base = Path(sys.argv[1])
repo_root = Path(sys.argv[2])

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def make_c1(path: Path, commit: str, ver: str) -> str:
    files = {}
    bridge = repo_root / "runtime" / "bridge-v3"
    for name in ("ff_hub.py","ff_hub_store.py","ff_hub_permissions.py","ff_hub_secrets.py",
                 "ff_hub_apps.py","ff_agent_entry.py","ff_app_catalog.py","ff_browser_routes.py",
                 "ff_win_process_identity.py","cua_private_browser.py","cua_hidden_chrome.py"):
        p = bridge / name
        if p.is_file():
            files["runtime/bridge-v3/" + name] = p.read_bytes()
    files["runtime/bridge-v3/ff_win_v3_agent.py"] = f"PS_FIXTURE_VER = {ver!r}\n".encode("utf-8")
    files["tools/agent_entry.py"] = (repo_root / "tools" / "agent_entry.py").read_bytes()
    mf = {
        "schema": "ff-gh-release-v1",
        "source_commit": commit,
        "public_source_commit": commit,
        "source_bytes_verified_against_commit": True,
        "files": {k: sha(v) for k, v in sorted(files.items())},
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for k, v in sorted(files.items()):
            zf.writestr(k, v)
        zf.writestr("release-manifest.json", json.dumps(mf, sort_keys=True, indent=2).encode("utf-8"))
    return sha(path.read_bytes())

c1_v1_sha = make_c1(base / "c1-v1.zip", "1" * 40, "v1")
c1_v2_sha = make_c1(base / "c1-v2.zip", "2" * 40, "v2")

c2 = base / "c2-repo"
c2.mkdir()
def git(*args):
    return subprocess.check_output(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "-C", str(c2), *args], text=True).strip()
git("init", "-q")
git("config", "user.name", "PS Test")
git("config", "user.email", "ps-test@example.invalid")
git("config", "core.autocrlf", "false")
(c2 / "idempotency_utils.py").write_text("X = 1\n", encoding="utf-8", newline="\n")
(c2 / "server.py").write_text("VER = 'v1'\n", encoding="utf-8", newline="\n")
(c2 / "unified_api.py").write_text("VER = 'v1'\n", encoding="utf-8", newline="\n")
git("add", ".")
git("commit", "-q", "-m", "v1")
c2_v1 = git("rev-parse", "HEAD")
(c2 / "server.py").write_text("VER = 'v2'\n", encoding="utf-8", newline="\n")
(c2 / "unified_api.py").write_text("VER = 'v2'\n", encoding="utf-8", newline="\n")
git("add", "-A")
git("commit", "-q", "-m", "v2")
c2_v2 = git("rev-parse", "HEAD")

print(json.dumps({
    "c1_v1_zip": str(base / "c1-v1.zip"),
    "c1_v1_sha": c1_v1_sha,
    "c1_v2_zip": str(base / "c1-v2.zip"),
    "c1_v2_sha": c1_v2_sha,
    "c2_repo": str(c2),
    "c2_v1": c2_v1,
    "c2_v2": c2_v2,
}))
'@
    $fixtureScript = Join-Path $tempBase 'make_fixtures.py'
    [IO.File]::WriteAllText($fixtureScript, $fixtureHelper, [Text.UTF8Encoding]::new($false))
    $fixtureJson = & python -X utf8 $fixtureScript $tempBase $repoRoot
    if ($LASTEXITCODE -ne 0) { throw 'FIXTURE_GENERATION_FAILED' }
    $fx = $fixtureJson | ConvertFrom-Json
    $shadowRoot = Join-Path $tempBase 'shadow-root'

    # Test 1: Empty SHA-256 MUST fail closed (no pinning bypass!)
    $r1 = Invoke-PsScript -ScriptPath $cutoverScript -Arguments @(
        '-Mode', 'DryRun',
        '-FullCoreZipPath', $fx.c1_v1_zip,
        '-FullCoreSha256', '',
        '-ShadowRoot', $shadowRoot,
        '-C2RepoPath', $fx.c2_repo,
        '-C2ExpectedCommit', $fx.c2_v2
    )
    Assert-True ($r1.exit_code -ne 0) "Empty SHA256 should fail closed (exit=$($r1.exit_code))"
    Assert-True (($r1.stderr + $r1.stdout) -match 'PINNED_SHA256') "Expected PINNED_SHA256 error"
    $results.Add([ordered]@{ test = 'empty_sha256_fails_closed'; ok = $true })

    # Test 2: Production port MUST fail closed
    $r2 = Invoke-PsScript -ScriptPath $cutoverScript -Arguments @(
        '-Mode', 'DryRun',
        '-FullCoreZipPath', $fx.c1_v1_zip,
        '-FullCoreSha256', $fx.c1_v1_sha,
        '-ShadowRoot', $shadowRoot,
        '-C1RpcPort', '39073',
        '-C2RepoPath', $fx.c2_repo,
        '-C2ExpectedCommit', $fx.c2_v2
    )
    Assert-True ($r2.exit_code -ne 0) "Production port 39073 must fail closed"
    Assert-True (($r2.stderr + $r2.stdout) -match 'PRODUCTION_PORT') "Expected PRODUCTION_PORT error"
    $results.Add([ordered]@{ test = 'production_port_fails_closed'; ok = $true })

    # Test 3: ConfirmOwnerCutover without readiness+approval MUST fail closed
    $r3 = Invoke-PsScript -ScriptPath $cutoverScript -Arguments @(
        '-ConfirmOwnerCutover',
        '-FullCoreZipPath', $fx.c1_v1_zip,
        '-FullCoreSha256', $fx.c1_v1_sha,
        '-ShadowRoot', $shadowRoot,
        '-C2RepoPath', $fx.c2_repo,
        '-C2ExpectedCommit', $fx.c2_v2
    )
    Assert-True ($r3.exit_code -ne 0) "ConfirmOwnerCutover without readiness+approval must fail closed"
    Assert-True (($r3.stderr + $r3.stdout) -match 'OWNER_CUTOVER_READINESS_REQUIRED') "Expected OWNER_CUTOVER_READINESS_REQUIRED"
    $results.Add([ordered]@{ test = 'owner_cutover_gate_fails_closed'; ok = $true })

    # Test 4: Safe DryRun succeeds without creating shadow root
    $r4 = Invoke-PsScript -ScriptPath $cutoverScript -Arguments @(
        '-Mode', 'DryRun',
        '-FullCoreZipPath', $fx.c1_v1_zip,
        '-FullCoreSha256', $fx.c1_v1_sha,
        '-ShadowRoot', $shadowRoot,
        '-C1RpcPort', '48173',
        '-C1HubPort', '48190',
        '-C2GatewayPort', '48587',
        '-C2UnifiedPort', '48588',
        '-C2RepoPath', $fx.c2_repo,
        '-C2ExpectedCommit', $fx.c2_v2
    )
    Assert-True ($r4.exit_code -eq 0) "DryRun should succeed: stderr=$($r4.stderr) stdout=$($r4.stdout)"
    $dryObj = $r4.stdout | ConvertFrom-Json
    Assert-True ($dryObj.mode -eq 'DRY_RUN_ONLY' -and $dryObj.executed -eq $false) "DryRun contract mismatch"
    Assert-True (-not (Test-Path -LiteralPath $shadowRoot)) "DryRun must not create shadow root"
    $results.Add([ordered]@{ test = 'safe_dry_run_no_mutation'; ok = $true })

    # Test 5: ShadowStage v1 then ShadowStage v2 via PowerShell entrypoint
    & git -C $fx.c2_repo checkout -q $fx.c2_v1
    $r5a = Invoke-PsScript -ScriptPath $cutoverScript -Arguments @(
        '-Mode', 'ShadowStage',
        '-FullCoreZipPath', $fx.c1_v1_zip,
        '-FullCoreSha256', $fx.c1_v1_sha,
        '-C1ExpectedCommit', ('1' * 40),
        '-ShadowRoot', $shadowRoot,
        '-C1RpcPort', '48173',
        '-C1HubPort', '48190',
        '-C2GatewayPort', '48587',
        '-C2UnifiedPort', '48588',
        '-C2RepoPath', $fx.c2_repo,
        '-C2ExpectedCommit', $fx.c2_v1,
        '-RequestKey', 'ps-stage-v1'
    )
    Assert-True ($r5a.exit_code -eq 0) "ShadowStage v1 failed: stderr=$($r5a.stderr) stdout=$($r5a.stdout)"
    $s1 = $r5a.stdout | ConvertFrom-Json
    Assert-True ($s1.ok -eq $true) "ShadowStage v1 ok=false"

    & git -C $fx.c2_repo checkout -q $fx.c2_v2
    $r5b = Invoke-PsScript -ScriptPath $cutoverScript -Arguments @(
        '-Mode', 'ShadowStage',
        '-FullCoreZipPath', $fx.c1_v2_zip,
        '-FullCoreSha256', $fx.c1_v2_sha,
        '-C1ExpectedCommit', ('2' * 40),
        '-ShadowRoot', $shadowRoot,
        '-C1RpcPort', '48173',
        '-C1HubPort', '48190',
        '-C2GatewayPort', '48587',
        '-C2UnifiedPort', '48588',
        '-C2RepoPath', $fx.c2_repo,
        '-C2ExpectedCommit', $fx.c2_v2,
        '-RequestKey', 'ps-stage-v2'
    )
    Assert-True ($r5b.exit_code -eq 0) "ShadowStage v2 failed: stderr=$($r5b.stderr) stdout=$($r5b.stdout)"
    $results.Add([ordered]@{ test = 'shadow_stage_v1_and_v2'; ok = $true })

    # Test 6: Rollback DryRun succeeds with zero mutation; ConfirmOwnerRollback without gate fails closed
    $r6a = Invoke-PsScript -ScriptPath $rollbackScript -Arguments @(
        '-Mode', 'DryRun',
        '-ShadowRoot', $shadowRoot
    )
    Assert-True ($r6a.exit_code -eq 0) "Rollback DryRun failed: $($r6a.stderr)"
    $rbDry = $r6a.stdout | ConvertFrom-Json
    Assert-True ($rbDry.mode -eq 'DRY_RUN_ONLY' -and $rbDry.executed -eq $false) "Rollback DryRun contract mismatch"

    $r6b = Invoke-PsScript -ScriptPath $rollbackScript -Arguments @(
        '-ConfirmOwnerRollback',
        '-ShadowRoot', $shadowRoot
    )
    Assert-True ($r6b.exit_code -ne 0) "ConfirmOwnerRollback without approval gate must fail closed"
    $results.Add([ordered]@{ test = 'rollback_dryrun_and_owner_gate'; ok = $true })

    # Test 7: ShadowRollback restores v1 cleanly and preserves SQLite receipts
    $r7 = Invoke-PsScript -ScriptPath $rollbackScript -Arguments @(
        '-Mode', 'ShadowRollback',
        '-ConfirmShadowRollback',
        '-ShadowRoot', $shadowRoot,
        '-RequestKey', 'ps-rollback-v1'
    )
    Assert-True ($r7.exit_code -eq 0) "ShadowRollback failed: stderr=$($r7.stderr) stdout=$($r7.stdout)"
    $rbRes = $r7.stdout | ConvertFrom-Json
    Assert-True ($rbRes.ok -eq $true -and $rbRes.receipt_chain_ok -eq $true) "ShadowRollback result invalid"

    # Test 8: VerifyReceipts reports intact hash chain
    $r8 = Invoke-PsScript -ScriptPath $rollbackScript -Arguments @(
        '-Mode', 'VerifyReceipts',
        '-ShadowRoot', $shadowRoot
    )
    Assert-True ($r8.exit_code -eq 0) "VerifyReceipts failed: $($r8.stderr)"
    $vr = $r8.stdout | ConvertFrom-Json
    Assert-True ($vr.ok -eq $true -and $vr.receipts_verified -ge 3) "VerifyReceipts chain count invalid"
    $results.Add([ordered]@{ test = 'shadow_rollback_and_receipt_verification'; ok = $true })

    # Test 9: Rollback refuses baseline ZIP or DB backup without pinned 64-hex SHA-256
    $r9a = Invoke-PsScript -ScriptPath $rollbackScript -Arguments @(
        '-Mode', 'ShadowRollback',
        '-ConfirmShadowRollback',
        '-ShadowRoot', $shadowRoot,
        '-C1BaselineZipPath', $fx.c1_v1_zip,
        '-C1BaselineZipSha256', ''
    )
    Assert-True ($r9a.exit_code -ne 0) "Rollback baseline ZIP with empty SHA256 must fail closed"
    Assert-True (($r9a.stderr + $r9a.stdout) -match 'PINNED_SHA256') "Expected PINNED_SHA256 on baseline ZIP"

    $r9b = Invoke-PsScript -ScriptPath $rollbackScript -Arguments @(
        '-Mode', 'ShadowRollback',
        '-ConfirmShadowRollback',
        '-ShadowRoot', $shadowRoot,
        '-C2RestoreDbBackupPath', $fx.c1_v1_zip,
        '-C2RestoreDbBackupSha256', ''
    )
    Assert-True ($r9b.exit_code -ne 0) "Rollback DB backup with empty SHA256 must fail closed"
    Assert-True (($r9b.stderr + $r9b.stdout) -match 'PINNED_SHA256') "Expected PINNED_SHA256 on DB backup"
    $results.Add([ordered]@{ test = 'rollback_requires_pinned_baseline_and_backup_sha256'; ok = $true })

    # Test 10: PrepareReadiness produces valid cutover readiness manifest without touching prod
    $readinessPath = Join-Path $shadowRoot 'state\test-readiness.json'
    $r10 = Invoke-PsScript -ScriptPath $cutoverScript -Arguments @(
        '-Mode', 'PrepareReadiness',
        '-ShadowRoot', $shadowRoot,
        '-ReadinessOutputPath', $readinessPath
    )
    Assert-True ($r10.exit_code -eq 0) "PrepareReadiness failed: $($r10.stderr)"
    $rdyObj = Get-Content -LiteralPath $readinessPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-True ($rdyObj.schema -eq 'ff-canary-cutover-readiness-v1' -and $rdyObj.receipt_chain_verified -eq $true -and $rdyObj.live_production_cutover_executed -eq $false) "Readiness manifest contract invalid"
    $results.Add([ordered]@{ test = 'prepare_readiness_manifest'; ok = $true })

    Write-Output ([ordered]@{
        ok = $true
        tests_passed = $results.Count
        results = $results
    } | ConvertTo-Json -Depth 6)
    exit 0
} finally {
    Remove-Item -LiteralPath $tempBase -Recurse -Force -ErrorAction SilentlyContinue
}
