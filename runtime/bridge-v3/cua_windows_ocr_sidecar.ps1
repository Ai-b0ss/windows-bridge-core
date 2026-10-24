$ErrorActionPreference='Stop'
[Console]::InputEncoding=New-Object System.Text.UTF8Encoding($false)
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
$OutputEncoding=[Console]::OutputEncoding

Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null=[Windows.Storage.Streams.IBuffer,Windows.Storage.Streams,ContentType=WindowsRuntime]
$null=[Windows.Graphics.Imaging.SoftwareBitmap,Windows.Graphics.Imaging,ContentType=WindowsRuntime]
$null=[Windows.Graphics.Imaging.BitmapPixelFormat,Windows.Graphics.Imaging,ContentType=WindowsRuntime]
$null=[Windows.Graphics.Imaging.BitmapAlphaMode,Windows.Graphics.Imaging,ContentType=WindowsRuntime]
$null=[Windows.Media.Ocr.OcrEngine,Windows.Foundation,ContentType=WindowsRuntime]
$null=[Windows.Media.Ocr.OcrResult,Windows.Foundation,ContentType=WindowsRuntime]
$null=[Windows.Globalization.Language,Windows.Foundation,ContentType=WindowsRuntime]

$EngineName='WINDOWS_MEDIA_OCR'
$MaxPixelBytes=12000000
$EngineCache=@{}

function Await-WinRT {
    param($Operation,[Type]$ResultType)
    $method=[System.WindowsRuntimeSystemExtensions].GetMethods() |
        Where-Object {$_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1} |
        Select-Object -First 1
    if($null -eq $method){ throw 'WINDOWS_OCR_AS_TASK_UNAVAILABLE' }
    $task=$method.MakeGenericMethod($ResultType).Invoke($null,@($Operation))
    $task.Wait()
    return $task.Result
}

function Fail-Response {
    param([string]$Id,[string]$Code,[string]$Message)
    return @{
        id=$Id
        ok=$false
        error=@{code=$Code;message=$Message}
    }
}

function Write-Response {
    param($Payload)
    [Console]::Out.WriteLine(($Payload | ConvertTo-Json -Depth 10 -Compress))
    [Console]::Out.Flush()
}

function Get-Engine {
    param([string]$Language)
    if(-not $EngineCache.ContainsKey($Language)){
        $lang=New-Object Windows.Globalization.Language($Language)
        $engine=[Windows.Media.Ocr.OcrEngine]::TryCreateFromLanguage($lang)
        if($null -eq $engine){ throw 'WINDOWS_OCR_LANGUAGE_UNAVAILABLE' }
        $EngineCache[$Language]=$engine
    }
    return $EngineCache[$Language]
}

while(($line=[Console]::In.ReadLine()) -ne $null){
    if([string]::IsNullOrWhiteSpace($line)){ continue }
    $id=$null
    $soft=$null
    try {
        try {
            $req=$line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            Write-Response (Fail-Response $null 'WINDOWS_OCR_REQUEST_INVALID' 'invalid_json')
            continue
        }
        $id=[string]$req.id
        if([string]::IsNullOrWhiteSpace($id)){
            Write-Response (Fail-Response $id 'WINDOWS_OCR_REQUEST_INVALID' 'id_required')
            continue
        }
        $op=[string]$req.op
        if($op -eq 'health'){
            $langs=@([Windows.Media.Ocr.OcrEngine]::AvailableRecognizerLanguages | ForEach-Object {$_.LanguageTag})
            Write-Response @{
                id=$id;ok=$true;result=@{
                    engine=$EngineName
                    available=$true
                    languages=$langs
                    max_image_dimension=[Windows.Media.Ocr.OcrEngine]::MaxImageDimension
                    raw_pixels_persisted=$false
                }
            }
            continue
        }
        if($op -ne 'ocr'){
            Write-Response (Fail-Response $id 'WINDOWS_OCR_OP_UNSUPPORTED' $op)
            continue
        }
        $a=$req.args
        if($null -eq $a){
            Write-Response (Fail-Response $id 'WINDOWS_OCR_INPUT_INVALID' 'args_required')
            continue
        }
        $w=0;$h=0;$maxWords=0
        if(-not [int]::TryParse([string]$a.width,[ref]$w) -or
           -not [int]::TryParse([string]$a.height,[ref]$h) -or
           -not [int]::TryParse([string]$a.max_words,[ref]$maxWords) -or
           $w -le 0 -or $h -le 0 -or $maxWords -lt 1 -or $maxWords -gt 256 -or
           ([long]$w*[long]$h*4) -gt $MaxPixelBytes){
            Write-Response (Fail-Response $id 'WINDOWS_OCR_INPUT_INVALID' 'dimensions_or_limit')
            continue
        }
        $language=[string]$a.language
        if([string]::IsNullOrWhiteSpace($language) -or $language.Length -gt 35 -or
           $language -notmatch '^[A-Za-z0-9-]+$'){
            Write-Response (Fail-Response $id 'WINDOWS_OCR_INPUT_INVALID' 'language')
            continue
        }
        try {
            $raw=[Convert]::FromBase64String([string]$a.pixel_bgra_base64)
        } catch {
            Write-Response (Fail-Response $id 'WINDOWS_OCR_INPUT_INVALID' 'base64')
            continue
        }
        if($raw.Length -ne ([long]$w*[long]$h*4)){
            Write-Response (Fail-Response $id 'WINDOWS_OCR_INPUT_INVALID' 'pixel_length')
            continue
        }
        try {
            $engine=Get-Engine $language
        } catch {
            if($_.Exception.Message -eq 'WINDOWS_OCR_LANGUAGE_UNAVAILABLE'){
                Write-Response (Fail-Response $id 'WINDOWS_OCR_LANGUAGE_UNAVAILABLE' $language)
                continue
            }
            throw
        }
        $buffer=[System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]::AsBuffer($raw)
        $soft=[Windows.Graphics.Imaging.SoftwareBitmap]::CreateCopyFromBuffer(
            $buffer,
            [Windows.Graphics.Imaging.BitmapPixelFormat]::Bgra8,
            $w,$h,
            [Windows.Graphics.Imaging.BitmapAlphaMode]::Premultiplied
        )
        $sw=[Diagnostics.Stopwatch]::StartNew()
        $ocr=Await-WinRT ($engine.RecognizeAsync($soft)) ([Windows.Media.Ocr.OcrResult])
        $sw.Stop()
        $allWords=@()
        $lineRanges=@()
        $wordOffset=0
        foreach($ocrLine in $ocr.Lines){
            $lineStart=$wordOffset
            foreach($word in $ocrLine.Words){
                $r=$word.BoundingRect
                $allWords+=@{
                    text=[string]$word.Text
                    bbox=@([double]$r.X,[double]$r.Y,[double]$r.Width,[double]$r.Height)
                }
                $wordOffset++
            }
            $lineWordCount=$wordOffset-$lineStart
            if($lineWordCount -gt 0){
                $lineRanges+=@{word_start=$lineStart;word_count=$lineWordCount}
            }
        }
        $total=[int]$allWords.Count
        $totalLines=[int]$lineRanges.Count
        $limited=@($allWords | Select-Object -First $maxWords)
        $limitedLines=@()
        $remaining=[int]$limited.Count
        foreach($lineRange in $lineRanges){
            if($remaining -le 0){ break }
            $take=[Math]::Min([int]$lineRange.word_count,$remaining)
            $start=[int]$lineRange.word_start
            $slice=@()
            for($i=0;$i -lt $take;$i++){ $slice+=$allWords[$start+$i] }
            $left=[double]::PositiveInfinity;$top=[double]::PositiveInfinity
            $right=[double]::NegativeInfinity;$bottom=[double]::NegativeInfinity
            foreach($item in $slice){
                $b=$item.bbox
                $left=[Math]::Min($left,[double]$b[0]);$top=[Math]::Min($top,[double]$b[1])
                $right=[Math]::Max($right,[double]$b[0]+[double]$b[2])
                $bottom=[Math]::Max($bottom,[double]$b[1]+[double]$b[3])
            }
            $limitedLines+=@{
                text=(($slice | ForEach-Object {[string]$_.text}) -join ' ')
                bbox=@([double]$left,[double]$top,([double]$right-[double]$left),([double]$bottom-[double]$top))
                word_count=$take
            }
            $remaining-=$take
        }
        Write-Response @{
            id=$id;ok=$true;result=@{
                engine=$EngineName
                language=$language
                words=$limited
                word_count=[int]$limited.Count
                total_word_count=$total
                lines=$limitedLines
                line_count=[int]$limitedLines.Count
                total_line_count=$totalLines
                truncated=($total -gt $maxWords)
                inference_ms=[math]::Round($sw.Elapsed.TotalMilliseconds,3)
                raw_pixels_persisted=$false
            }
        }
    } catch {
        Write-Response (Fail-Response $id 'WINDOWS_OCR_INTERNAL_ERROR' $_.Exception.GetType().Name)
    } finally {
        if($null -ne $soft){ try{$soft.Dispose()}catch{} }
    }
}
