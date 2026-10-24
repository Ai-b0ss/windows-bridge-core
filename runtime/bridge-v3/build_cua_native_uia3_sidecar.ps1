param(
    [string]$OutputPath = (Join-Path $env:TEMP 'cua_native_uia3_sidecar.exe')
)
$ErrorActionPreference = 'Stop'
$framework = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319'
$wpf = Join-Path $framework 'WPF'
$csc = Join-Path $framework 'csc.exe'
$source = Join-Path $PSScriptRoot 'cua_native_uia3_sidecar.cs'
$refs = @(
    (Join-Path $wpf 'UIAutomationClient.dll'),
    (Join-Path $wpf 'UIAutomationTypes.dll'),
    (Join-Path $framework 'System.Web.Extensions.dll')
)
foreach ($path in @($csc, $source) + $refs) {
    if (-not (Test-Path $path)) { throw "Required UIA build dependency missing: $path" }
}
& $csc /nologo /optimize+ /target:exe "/out:$OutputPath" "/r:$($refs[0])" "/r:$($refs[1])" "/r:$($refs[2])" $source
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $OutputPath)) { throw "UIA3 sidecar compile failed: $LASTEXITCODE" }
Get-Item $OutputPath | Select-Object FullName, Length, LastWriteTime

