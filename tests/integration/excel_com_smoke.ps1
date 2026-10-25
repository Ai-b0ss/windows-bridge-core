# Verify actual hidden Excel.Application COM on a throwaway workbook only.
# Never touch user workbooks and never connect to a running Excel session.
$ErrorActionPreference = 'Stop'
$startedAt = Get-Date
$type = [type]::GetTypeFromProgID('Excel.Application', $false)
if ($null -eq $type) {
    Write-Output '{"schema":"ff-excel-com-smoke-v1","status":"SKIP","reason":"excel_com_not_installed"}'
    exit 0
}
if (@(Get-CimInstance Win32_Process -Filter "Name='EXCEL.EXE'").Count -ne 0) {
    Write-Output '{"schema":"ff-excel-com-smoke-v1","status":"SKIP","reason":"owner_excel_already_running"}'
    exit 0
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('ff-excel-com-smoke-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root -ErrorAction Stop | Out-Null
$path = Join-Path $root 'owned-smoke.xlsx'
$excel = $null
$book = $null
$sheet = $null
$pidOwned = $null
$closed = $false
$verified = $false
$cleaned = $false
try {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FFExcelSmokeNative {
    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr window, out uint pid);
}
'@
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false
    $excel.EnableEvents = $false
    $excel.AutomationSecurity = 3
    [uint32]$ownedPid = 0
    [void][FFExcelSmokeNative]::GetWindowThreadProcessId([IntPtr]$excel.Hwnd, [ref]$ownedPid)
    if ($ownedPid -lt 4) { throw 'EXCEL_COM_OWNED_PID_NOT_PROVEN' }
    $pidOwned = [int]$ownedPid
    $active = Get-CimInstance Win32_Process -Filter "ProcessId=$pidOwned"
    if (-not $active -or $active.Name -ne 'EXCEL.EXE' -or
        [datetime]$active.CreationDate -lt $startedAt.AddSeconds(-5)) {
        throw 'EXCEL_COM_NEW_PROCESS_OWNERSHIP_NOT_PROVEN'
    }
    $book = $excel.Workbooks.Add()
    $sheet = $book.Worksheets.Item(1)
    $sheet.Range('A1').Value2 = 20
    $sheet.Range('A2').Value2 = 22
    $sheet.Range('A3').Formula = '=SUM(A1:A2)'
    $excel.CalculateFull()
    if ([double]$sheet.Range('A3').Value2 -ne 42) {
        throw 'EXCEL_COM_CALCULATION_FAILED'
    }
    $book.SaveAs($path, 51)
    $book.Close($false)
    $closed = $true
    if (-not (Test-Path -LiteralPath $path)) {throw 'EXCEL_COM_SAVE_FAILED'}
    & python (Join-Path $PSScriptRoot 'excel_com_verify_ooxml.py') $path
    if ($LASTEXITCODE -ne 0) {throw 'EXCEL_COM_INDEPENDENT_VERIFICATION_FAILED'}
    $verified = $true
} finally {
    if ($book -and -not $closed) { try { $book.Close($false) } catch {} }
    if ($excel) { try {$excel.Quit()} catch {} }
    if ($sheet) { try {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($sheet)} catch {} }
    if ($book) { try {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($book)} catch {} }
    if ($excel) { try {[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($excel)} catch {} }
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
    if ($pidOwned) {
        Start-Sleep -Milliseconds 600
        $remaining = Get-CimInstance Win32_Process -Filter "ProcessId=$pidOwned"
        if ($remaining) {
            if ($remaining.Name -ne 'EXCEL.EXE' -or
                [datetime]$remaining.CreationDate -lt $startedAt.AddSeconds(-5)) {
                throw 'EXCEL_COM_PROCESS_OWNERSHIP_CHANGED'
            }
            Stop-Process -Id $pidOwned -Force -ErrorAction Stop
        }
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
    $cleaned = -not (Test-Path -LiteralPath $root)
}
if (-not $verified -or -not $cleaned) {throw 'EXCEL_COM_ACCEPTANCE_INCOMPLETE'}
Write-Output '{"schema":"ff-excel-com-smoke-v1","status":"PASS","excel_hidden":true,"calculated_value":42,"independent_xlsx_readback":true,"owner_process_cleaned":true,"owned_temp_data_cleaned":true}'
