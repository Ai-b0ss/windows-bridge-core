param([string]$GhPath, [string]$Repository, [string]$Output)
$env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + $env:PSModulePath
$ErrorActionPreference='Stop'
$result=[ordered]@{session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId;credential_available=$false;github_read=$false}
try {
    $token=(& $GhPath auth token 2>$null | Out-String).Trim()
    $result.credential_available=[bool]$token
    if ($token) {
        $response=Invoke-RestMethod -UseBasicParsing -Uri ('https://api.github.com/repos/' + $Repository) -Headers @{Authorization=('Bearer ' + $token);Accept='application/vnd.github+json'} -TimeoutSec 20
        $result.github_read=[bool]$response.id
    }
} catch { $result.error_type=$_.Exception.GetType().Name }
[IO.File]::WriteAllText($Output, ($result | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
