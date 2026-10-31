param(
    [Parameter(Mandatory)][string]$ConfigPath
)
# Owner-visible notice: small, always on top, never takes keyboard focus.
# The Bridge touches HeartbeatPath on every agent action. The notice says
# "finished" after IdleSeconds without a heartbeat and closes itself.
# The Stop button writes StopPath; the Bridge then revokes the desktop grant.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$cfg = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Windows.Forms;
public class FFNoticeForm : Form {
    protected override bool ShowWithoutActivation { get { return true; } }
    protected override CreateParams CreateParams {
        get {
            CreateParams cp = base.CreateParams;
            cp.ExStyle |= 0x08000000 | 0x00000080 | 0x00000008; // NOACTIVATE | TOOLWINDOW | TOPMOST
            return cp;
        }
    }
}
'@ -ReferencedAssemblies System.Windows.Forms

$form = New-Object FFNoticeForm
$form.FormBorderStyle = 'FixedToolWindow'
$form.ControlBox = $false
$form.Text = [string]$cfg.title
$form.StartPosition = 'Manual'
$form.ClientSize = New-Object System.Drawing.Size(360, 104)
$area = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
$form.Location = New-Object System.Drawing.Point(($area.Right - $form.Width - 16), ($area.Bottom - $form.Height - 16))
$form.TopMost = $true
$form.ShowInTaskbar = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(255, 250, 235)

$label = New-Object System.Windows.Forms.Label
$label.Text = [string]$cfg.text
$label.Location = New-Object System.Drawing.Point(12, 10)
$label.Size = New-Object System.Drawing.Size(336, 48)
$form.Controls.Add($label)

$stop = New-Object System.Windows.Forms.Button
$stop.Text = [string]$cfg.stop_label
$stop.Location = New-Object System.Drawing.Point(12, 62)
$stop.Size = New-Object System.Drawing.Size(120, 30)
$stop.Add_Click({
    Set-Content -LiteralPath $cfg.stop_path -Value ([string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) -Encoding ASCII
    $label.Text = [string]$cfg.stopped_text
    $stop.Enabled = $false
    $script:closeAt = [DateTime]::UtcNow.AddSeconds(3)
})
$form.Controls.Add($stop)

$script:closeAt = $null
$script:finished = $false
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 1000
$timer.Add_Tick({
    $now = [DateTime]::UtcNow
    if ($script:closeAt -and $now -ge $script:closeAt) { $form.Close(); return }
    if ($script:closeAt) { return }
    $age = 9999
    if (Test-Path -LiteralPath $cfg.heartbeat_path) {
        $age = ($now - (Get-Item -LiteralPath $cfg.heartbeat_path).LastWriteTimeUtc).TotalSeconds
    }
    if ($age -gt [double]$cfg.idle_seconds) {
        $label.Text = [string]$cfg.done_text
        $stop.Enabled = $false
        $script:closeAt = $now.AddSeconds(4)
    }
})
$timer.Start()
$hardStop = [DateTime]::UtcNow.AddSeconds([double]$cfg.max_seconds)
$guard = New-Object System.Windows.Forms.Timer
$guard.Interval = 5000
$guard.Add_Tick({ if ([DateTime]::UtcNow -ge $hardStop) { $form.Close() } })
$guard.Start()
[void]$form.ShowDialog()
