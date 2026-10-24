param(
    [int]$TimeoutSeconds = 60,
    [string]$Root = (Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\github-transport')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = $Root
$configPath = Join-Path $root 'github_transport_config.json'
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw 'GITHUB_TRANSPORT_NOT_INSTALLED'
}
$config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json

$gh = (Get-Command gh.exe -ErrorAction SilentlyContinue | Select-Object -First 1)
if (-not $gh) {
    $known = Join-Path $env:ProgramFiles 'GitHub CLI\gh.exe'
    if (Test-Path -LiteralPath $known -PathType Leaf) {
        $ghPath = $known
    } else {
        throw 'GH_CLI_MISSING'
    }
} else {
    $ghPath = $gh.Source
}

$token = (& $ghPath auth token 2>$null | Out-String).Trim()
if (-not $token) { throw 'GH_AUTH_TOKEN_UNAVAILABLE' }

$headers = @{
    Authorization = 'Bearer ' + $token
    Accept = 'application/vnd.github+json'
    'X-GitHub-Api-Version' = '2026-03-10'
    'User-Agent' = 'ff-windows-github-smoke-test'
}

function Invoke-GitHub([string]$Method, [string]$Url, $Body = $null) {
    $params = @{
        Uri = $Url
        Headers = $headers
        Method = $Method
        UseBasicParsing = $true
        TimeoutSec = 20
    }
    if ($null -ne $Body) {
        $params.ContentType = 'application/json'
        $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress)
    }
    Invoke-RestMethod @params
}

$repository = [string]$config.repository
$issue = [int]$config.inbox_issue
$device = [string]$config.device
$taskId = 'manual-smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$task = [ordered]@{
    schema = 'ff-win-github-comment-v5'
    task_id = $taskId
    client_id = 'manual-smoke-test'
    target_device = $device
    op = 'ping'
    args = @{}
    timeout_seconds = 20
}

$base = 'https://api.github.com/repos/' + $repository
$created = Invoke-GitHub 'POST' ($base + '/issues/' + $issue + '/comments') @{
    body = ($task | ConvertTo-Json -Depth 20 -Compress)
}
$commentId = [int64]$created.id
$started = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$deadline = (Get-Date).AddSeconds($TimeoutSeconds)

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    $comment = Invoke-GitHub 'GET' ($base + '/issues/comments/' + $commentId)
    try { $result = ([string]$comment.body) | ConvertFrom-Json } catch { $result = $null }
    if ($result -and [string]$result.schema -eq 'ff-win-github-comment-result-v5') {
        $finished = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        $ok = ([string]$result.outcome -eq 'PASS')
        [ordered]@{
            ok = $ok
            schema = 'ff-win-github-transport-smoke-v1'
            task_id = $taskId
            comment_id = $commentId
            outcome = [string]$result.outcome
            route = $result.route
            elapsed_ms = ($finished - $started)
            worker_elapsed_ms = $result.worker_elapsed_ms
        } | ConvertTo-Json -Depth 8
        if ($ok) { exit 0 } else { exit 2 }
    }
}
throw 'SMOKE_TEST_TIMEOUT'
