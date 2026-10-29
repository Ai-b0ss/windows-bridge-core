Set-StrictMode -Version Latest

function Get-FFExtendedPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\?\')) { return $full }
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }
    return '\\?\' + $full
}

function Get-FFSha256([string]$Path) {
    # Hashing must also work in Windows PowerShell started from PowerShell 7,
    # whose inherited module path may not expose Get-FileHash.
    $stream = [IO.File]::OpenRead((Get-FFExtendedPath $Path))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
        $stream.Dispose()
    }
}

function Copy-FFPortableTree([string]$Source, [string]$Destination) {
    $sourcePath = (Get-FFExtendedPath $Source).TrimEnd('\')
    $destPath = (Get-FFExtendedPath $Destination).TrimEnd('\')
    # Used only on verified archives extracted into the current owned stage.
    foreach ($file in [IO.Directory]::EnumerateFiles($sourcePath,'*',[IO.SearchOption]::AllDirectories)) {
        $target = $destPath + '\' + $file.Substring($sourcePath.Length + 1)
        [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
        [IO.File]::Copy($file,$target,$true)
    }
}

function Remove-FFLegacyTransportModules([string]$Root) {
    $transportPath = [IO.Path]::GetFullPath($Root)
    if (-not (Test-Path -LiteralPath $transportPath)) { return }
    $cachePath = Join-Path $transportPath '__pycache__'
    foreach ($directory in @($transportPath, $cachePath)) {
        if ((Test-Path -LiteralPath $directory) -and
            ((Get-Item -LiteralPath $directory -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'LEGACY_TRANSPORT_PATH_LINKED'
        }
    }
    $legacyModules = @(
        'ff_win_v3_security.py', 'ff_win_v3_extras.py', 'ff_win_evidence.py',
        'cua_global_resources.py', 'cua_task_authority.py', 'ff_win_v3_agent.py'
    )
    foreach ($name in $legacyModules) {
        foreach ($file in @($name, [IO.Path]::ChangeExtension($name, '.pyc'))) {
            $target = Join-Path $transportPath $file
            if (Test-Path -LiteralPath $target -PathType Leaf) { Remove-Item -LiteralPath $target -Force }
        }
        if (Test-Path -LiteralPath $cachePath -PathType Container) {
            $prefix = [IO.Path]::GetFileNameWithoutExtension($name) + '.'
            foreach ($cached in Get-ChildItem -LiteralPath $cachePath -File) {
                if ($cached.Name.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and $cached.Extension -ieq '.pyc') {
                    Remove-Item -LiteralPath $cached.FullName -Force
                }
            }
        }
    }
}

function Assert-FFTransportImports([string]$Python, [string]$TransportRoot) {
    Push-Location -LiteralPath $TransportRoot
    try {
        # Run the real entry points: embedded Python (._pth) adds no script folder,
        # so this proves each one bootstraps its own import path.
        foreach ($entry in 'ff_win_github_client.py', 'ff_win_github_background_agent.py') {
            & $Python (Join-Path $TransportRoot $entry) --help | Out-Null
            if ($LASTEXITCODE -ne 0) { throw ('RELEASE_TRANSPORT_IMPORT_FAILED:' + $entry) }
        }
    } finally { Pop-Location }
}

function Get-FFPortableExecutable([string]$Root, [string]$Name) {
    foreach ($file in [IO.Directory]::EnumerateFiles((Get-FFExtendedPath $Root),$Name,[IO.SearchOption]::AllDirectories)) {
        if ($file.StartsWith('\\?\UNC\')) { return '\\' + $file.Substring(8) }
        return $file.Substring(4)
    }
    throw ('BUNDLED_EXECUTABLE_MISSING:' + $Name)
}

function Get-FFVerifiedZip([string]$Uri, [string]$Path, [string]$Sha256, [int]$Attempts = 3) {
    if ($Sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $Attempts -lt 1 -or $Attempts -gt 5) { throw 'DOWNLOAD_CONTRACT_INVALID' }
    if ((Test-Path -LiteralPath $Path) -and (Get-FFSha256 $Path) -ieq $Sha256) { return $Path }
    New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
    $partial = $Path + '.partial'
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $response = $null; $output = $null
        try {
            $offset = if (Test-Path -LiteralPath $partial) { (Get-Item -LiteralPath $partial).Length } else { 0 }
            $request = [Net.HttpWebRequest]::Create($Uri)
            $request.Timeout = 30000; $request.ReadWriteTimeout = 30000
            if ($offset -gt 0) { $request.AddRange([long]$offset) }
            $response = $request.GetResponse()
            $append = $offset -gt 0 -and [int]$response.StatusCode -eq 206
            if ($append -and -not ([string]$response.Headers['Content-Range']).StartsWith(('bytes ' + $offset + '-'))) { throw 'DOWNLOAD_RANGE_INVALID' }
            $fileMode = if ($append) { [IO.FileMode]::Append } else { [IO.FileMode]::Create }
            $output = [IO.File]::Open($partial,$fileMode,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $startingLength = $output.Length
            $response.GetResponseStream().CopyTo($output)
            $received = $output.Length - $startingLength
            $output.Dispose(); $output = $null
            # .NET may return EOF without throwing after a truncated response.
            # Keep the owned partial for the next bounded Range attempt.
            if ($response.ContentLength -ge 0 -and $received -ne $response.ContentLength) { throw 'DOWNLOAD_INTERRUPTED' }
            if ((Get-FFSha256 $partial) -ine $Sha256) {
                Remove-Item -LiteralPath $partial -Force
                throw 'DOWNLOAD_SHA256_MISMATCH_OR_DRIVE_LOGIN_REQUIRED'
            }
            Move-Item -LiteralPath $partial -Destination $Path -Force
            return $Path
        } catch {
            if ($_.Exception -is [Net.WebException] -and $_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 416) {
                if (Test-Path -LiteralPath $partial) { Remove-Item -LiteralPath $partial -Force }
            }
            if ($attempt -eq $Attempts) { throw }
            Start-Sleep -Seconds $attempt
        } finally {
            if ($output) { $output.Dispose() }
            if ($response) { $response.Dispose() }
        }
    }
}

function Expand-FFSafeArchive([string]$Archive, [string]$Destination) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $base = [IO.Path]::GetFullPath($Destination).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
    $cursor = [IO.Path]::GetFullPath($Destination)
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'ZIP_DESTINATION_REPARSE' }
        $cursor = Split-Path -Parent $cursor
    }
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $files = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        [long]$total = 0
        # Validate every entry before extracting even the first byte.
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName.Replace('\','/')
            $parts = $name.Split('/')
            if (-not $name -or $name.StartsWith('/') -or $name.Contains(':') -or $parts -contains '..' -or
                $parts -contains '.' -or $name.Contains([char]0) -or -not $seen.Add($name.TrimEnd('/'))) { throw 'ZIP_PATH_INVALID' }
            foreach ($part in $parts) {
                if ($part -and ($part -match '[<>"|?*\x00-\x1f]' -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)')) { throw 'ZIP_PATH_INVALID' }
            }
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $name))
            if (-not $target.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) { throw 'ZIP_PATH_ESCAPE' }
            if ((($entry.ExternalAttributes -shr 16) -band 0xf000) -eq 0xa000) { throw 'ZIP_SYMLINK_FORBIDDEN' }
            $total += $entry.Length
            if (-not $name.EndsWith('/')) { [void]$files.Add($name) }
            if ($entry.Length -gt 1GB -or $total -gt 4GB -or $zip.Entries.Count -gt 100000) { throw 'ZIP_SIZE_LIMIT' }
        }
        foreach ($name in $seen) {
            $ancestor = $name
            while ($ancestor.Contains('/')) {
                $ancestor = $ancestor.Substring(0,$ancestor.LastIndexOf('/'))
                if ($files.Contains($ancestor)) { throw 'ZIP_FILE_DIRECTORY_CONFLICT' }
            }
        }
        if (Test-Path -LiteralPath $Destination) {
            if (@(Get-ChildItem -LiteralPath $Destination -Force).Count) { throw 'ZIP_DESTINATION_NOT_EMPTY' }
            if ((Get-Item -LiteralPath $Destination).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'ZIP_DESTINATION_REPARSE' }
        } else { [void][IO.Directory]::CreateDirectory((Get-FFExtendedPath $Destination)) }
        foreach ($entry in $zip.Entries) {
            $target = Join-Path $Destination $entry.FullName
            if ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) {
                [void][IO.Directory]::CreateDirectory((Get-FFExtendedPath $target))
            } else {
                [void][IO.Directory]::CreateDirectory((Get-FFExtendedPath (Split-Path -Parent $target)))
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,(Get-FFExtendedPath $target),$false)
            }
        }
    } finally { $zip.Dispose() }
}

function New-FFOwnedStage([string]$Root) {
    if (-not ('FFStagePin' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public sealed class FFStagePin : IDisposable {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern SafeFileHandle CreateFile(string path,uint access,uint share,IntPtr sa,uint mode,uint flags,IntPtr tpl);
  [DllImport("kernel32.dll",SetLastError=true)]
  static extern bool SetFileInformationByHandle(SafeFileHandle h,int cls,ref int value,int size);
  SafeFileHandle handle;
  public FFStagePin(string path) {
    handle=CreateFile(path,0x00010080,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
    if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
  }
  public void DeleteEmpty() {
    int yes=1;
    if(!SetFileInformationByHandle(handle,4,ref yes,4)) throw new Win32Exception(Marshal.GetLastWin32Error());
  }
  public void Dispose() { if(handle!=null)handle.Dispose(); }
}
'@
    }
    $parent = [IO.Path]::GetFullPath($Root)
    # Refuse link ancestors before any extraction or cleanup.
    $cursor = $parent
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'STAGE_ANCESTOR_REPARSE' }
        $cursor = Split-Path -Parent $cursor
    }
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    $nonce = [guid]::NewGuid().ToString('N')
    $path = Join-Path $parent ('.stg-' + $nonce)
    $directory = New-Item -ItemType Directory -Path $path
    $pin = [FFStagePin]::new($path) # no FILE_SHARE_DELETE; keep exact root pinned
    $marker = Join-Path $path 'ff-owned-stage.json'
    [IO.File]::WriteAllText($marker,(@{schema='ff-owned-stage-v1';nonce=$nonce;root=$parent;created_utc=[DateTimeOffset]::UtcNow.ToString('o');diagnostic_retention_days=7} | ConvertTo-Json))
    return @{path=$path;parent=$parent;nonce=$nonce;created=$directory.CreationTimeUtc.Ticks;marker=$marker;pin=$pin}
}

function Remove-FFOwnedStage($Owned) {
    $path = [IO.Path]::GetFullPath($Owned.path)
    $parent = [IO.Path]::GetFullPath($Owned.parent)
    if ((Split-Path -Parent $path) -ine $parent -or (Split-Path -Leaf $path) -cne ('.stg-' + $Owned.nonce)) { throw 'STAGE_OUTSIDE_OWNERSHIP' }
    if (-not (Test-Path -LiteralPath $path)) { return }
    $directory = Get-Item -LiteralPath $path -Force
    if ($directory.CreationTimeUtc.Ticks -ne $Owned.created -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'STAGE_IDENTITY_CHANGED' }
    # The marker is UTF-8 without BOM; PS 5.1 defaults to the ANSI code page.
    $marker = Get-Content -LiteralPath $Owned.marker -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($marker.schema -ne 'ff-owned-stage-v1' -or $marker.nonce -cne $Owned.nonce -or $marker.root -ine $parent) { throw 'STAGE_OWNERSHIP_CHANGED' }
    $directories = [Collections.Generic.List[string]]::new()
    $files = [Collections.Generic.List[string]]::new()
    $pending = [Collections.Generic.Stack[string]]::new()
    $pending.Push((Get-FFExtendedPath $path))
    while ($pending.Count) {
        $current = $pending.Pop()
        foreach ($entry in [IO.Directory]::EnumerateFileSystemEntries($current)) {
            $attributes = [IO.File]::GetAttributes($entry)
            if ($attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'STAGE_REPARSE_PRESERVED' }
            if ($attributes -band [IO.FileAttributes]::Directory) { $directories.Add($entry); $pending.Push($entry) }
            else { $files.Add($entry) }
        }
    }
    # Only the exact stage created in this invocation is eligible. Unknown old
    # .stg directories are never enumerated or adopted for cleanup.
    foreach ($file in $files) { [IO.File]::SetAttributes($file,[IO.FileAttributes]::Normal); [IO.File]::Delete($file) }
    for ($i=$directories.Count-1; $i -ge 0; $i--) { [IO.Directory]::Delete($directories[$i],$false) }
    # Delete the exact held directory handle after emptying it; no path reopen.
    $Owned.pin.DeleteEmpty()
    $Owned.pin.Dispose()
}
function Wait-FFLocalRuntime {
    param([Parameter(Mandatory=$true)][string]$Root, [int]$Port, [int]$TimeoutSeconds = 90)
    if ($Port -lt 1 -or $Port -gt 65535 -or $TimeoutSeconds -lt 1) { throw 'LOCAL_HEALTH_ARGUMENT_INVALID' }
    $expected = Get-FFSha256 (Join-Path $Root 'bridge-v3\ff_win_v3_agent.py')
    $secretPath = Join-Path $Root 'bridge-v3\secret'
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        $response=$null;$reader=$null
        try {
            if (-not [IO.File]::Exists($secretPath)) { throw 'LOCAL_SECRET_NOT_READY' }
            $key=[IO.File]::ReadAllText($secretPath,[Text.Encoding]::ASCII).Trim()
            if ($key.Length -lt 32) { throw 'LOCAL_SECRET_NOT_READY' }
            $request=[Net.HttpWebRequest]::Create('http://127.0.0.1:'+$Port+'/rpc')
            $request.Proxy=$null
            $request.AllowAutoRedirect=$false
            $request.Timeout=[Math]::Max(100,[Math]::Min(2000,[int](($TimeoutSeconds-$watch.Elapsed.TotalSeconds)*1000)))
            $request.ReadWriteTimeout=$request.Timeout
            $request.Method='POST';$request.ContentType='application/json'
            $request.Headers.Add('X-FF3-Key',$key)
            $bytes=[Text.Encoding]::UTF8.GetBytes('{"op":"capabilities","args":{}}')
            $request.ContentLength=$bytes.Length
            $stream=$request.GetRequestStream()
            try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
            $response=$request.GetResponse()
            if ([int]$response.StatusCode -ne 200) { throw 'LOCAL_RESPONSE_NOT_READY' }
            $reader=[IO.StreamReader]::new($response.GetResponseStream(),[Text.Encoding]::UTF8)
            $buffer=New-Object char[] 32769
            $count=$reader.ReadBlock($buffer,0,$buffer.Length)
            if ($count -eq $buffer.Length) { throw 'LOCAL_HEALTH_RESPONSE_TOO_LARGE' }
            $reply=(-join $buffer[0..($count-1)]) | ConvertFrom-Json -ErrorAction Stop
            if ($reply.ok -isnot [bool] -or -not $reply.ok -or $reply.result.agent_sha256 -ine $expected) { throw 'LOCAL_RUNTIME_IDENTITY_NOT_READY' }
            return [ordered]@{ok=$true;rpc_port=$Port;agent_sha256=$expected;elapsed_ms=[int]$watch.Elapsed.TotalMilliseconds}
        } catch {
            # Do not expose the key or HTTP body; only readiness is reported.
        } finally {
            if ($reader) { $reader.Dispose() }
            if ($response) { $response.Dispose() }
        }
        Start-Sleep -Milliseconds 200
    }
    throw 'LOCAL_RUNTIME_HEALTH_FAILED - the installed bridge did not become ready; setup is not marked DONE.'
}
