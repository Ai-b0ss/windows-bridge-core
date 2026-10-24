param(
  [Parameter(Mandatory=$true)][string]$Dotnet,
  [Parameter(Mandatory=$true)][string]$Dll,
  [int]$FrameTimeoutMs = 3000,
  [int64]$Hwnd = 0,
  [int]$SupervisorTimeoutMs = 5000
)

$exitCode = 0
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $Dotnet
$escapedDll = $Dll.Replace('"','\"')
$psi.Arguments = '"' + $escapedDll + '" ' + [string]$FrameTimeoutMs
if ($Hwnd -ne 0) { $psi.Arguments += ' ' + [string]$Hwnd }
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
try {
  [void]$p.Start()
  if (-not $p.WaitForExit($SupervisorTimeoutMs)) {
    try { $p.Kill() } catch {}
    try { [void]$p.WaitForExit(1000) } catch {}
    Write-Output '{"ok":false,"error":"SUPERVISOR_TIMEOUT"}'
    $exitCode = 124
  }
  else {
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $exitCode = [int]$p.ExitCode
    if ($stdout) { Write-Output $stdout.TrimEnd() }
    if ($exitCode -ne 0 -and $stderr) { Write-Error $stderr.TrimEnd() }
  }
}
finally {
  $p.Dispose()
}
exit $exitCode
