param(
    [string]$Root = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\github-transport'),
    [int]$MaxPollAgeSeconds = 15
)

$ErrorActionPreference = 'SilentlyContinue'
$healthPath = Join-Path $Root 'comment_transport_health.json'
$result = [ordered]@{
    ok = $false
    schema = 'ff-win-github-transport-health-check-v1'
    daemon = $false
    poll_fresh = $false
    github_error = $null
    v3 = $false
    interactive_v3 = $false
    background_v3 = $false
    pid = $null
    poll_age_seconds = $null
    rate_remaining = $null
}

try {
    if (-not (Test-Path -LiteralPath $healthPath -PathType Leaf)) { throw 'HEALTH_FILE_MISSING' }
    $h = Get-Content -LiteralPath $healthPath -Raw | ConvertFrom-Json
    if ([string]$h.schema -ne 'ff-win-github-comment-health-v5') { throw 'HEALTH_SCHEMA_INVALID' }

    $result.pid = [int]$h.pid
    $proc = Get-Process -Id ([int]$h.pid) -ErrorAction SilentlyContinue
    $result.daemon = [bool]($proc -and $proc.ProcessName -ieq 'python')

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $age = [Math]::Max(0.0, ($now - [int64]$h.last_poll_ms) / 1000.0)
    $result.poll_age_seconds = [Math]::Round($age, 3)
    $result.poll_fresh = ($age -le $MaxPollAgeSeconds)
    $result.github_error = $h.last_error
    $result.rate_remaining = $h.rate_remaining

    $cfg = Get-Content (Join-Path $Root 'github_transport_config.json') -Raw | ConvertFrom-Json
    $v3Root = Join-Path (Split-Path -Parent $Root) 'bridge-v3'
    $secretPath = Join-Path $v3Root 'secret'
    if (Test-Path -LiteralPath $secretPath -PathType Leaf) {
        $secret = (Get-Content -LiteralPath $secretPath -Raw).Trim()
        $healthUrl = 'http://127.0.0.1:39073/health'
        if ($cfg.PSObject.Properties['rpc_url']) { $healthUrl = [string]$cfg.rpc_url -replace '/rpc$', '/health' }
        try {
            $response = Invoke-RestMethod -UseBasicParsing -Uri $healthUrl -Headers @{'X-FF3-Key'=$secret} -Method Get -TimeoutSec 3
            $result.interactive_v3 = [bool]$response.ok
        } catch {}
        if ($cfg.PSObject.Properties['background_rpc_url']) {
            try {
                $backgroundUrl = [string]$cfg.background_rpc_url -replace '/rpc$', '/health'
                $backgroundResponse = Invoke-RestMethod -UseBasicParsing -Uri $backgroundUrl -Headers @{'X-FF3-Key'=$secret} -Method Get -TimeoutSec 3
                $result.background_v3 = [bool]$backgroundResponse.ok
            } catch {}
        }
        $result.v3 = [bool]($result.interactive_v3 -or $result.background_v3)
    }
    $result.ok = [bool]($result.daemon -and $result.poll_fresh -and $result.v3 -and -not $result.github_error)
} catch {
    $result.error = [string]$_.Exception.Message
}
$result | ConvertTo-Json -Compress
if ($result.ok) { exit 0 } else { exit 2 }
