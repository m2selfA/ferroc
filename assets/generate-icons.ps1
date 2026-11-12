param(
    [string]$Source=(Join-Path $PSScriptRoot 'branding/ferroc-agnes-original.png'),
    [ValidateRange(245,255)][int]$WhiteThreshold=245
)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$sourcePath=(Resolve-Path $Source).Path
$original=[Drawing.Image]::FromFile($sourcePath)
try {
    if($original.Width -ne $original.Height -or $original.Width -lt 512){throw 'Expected square high-resolution Agnes source'}
    $bitmap=[Drawing.Bitmap]::new($original.Width,$original.Height,[Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g=[Drawing.Graphics]::FromImage($bitmap)
    try {$g.CompositingMode=[Drawing.Drawing2D.CompositingMode]::SourceCopy;$g.DrawImageUnscaled($original,0,0)}finally{$g.Dispose()}
} finally {$original.Dispose()}
try {
    # Remove only edge-connected near-white matte, never interior ivory/white details.
    $w=$bitmap.Width;$h=$bitmap.Height
    $rect=[Drawing.Rectangle]::new(0,0,$w,$h)
    $bits=$bitmap.LockBits($rect,[Drawing.Imaging.ImageLockMode]::ReadWrite,[Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
        if($bits.Stride -ne $w*4){throw 'Unexpected bitmap stride'}
        $pixels=[byte[]]::new($bits.Stride*$h)
        [Runtime.InteropServices.Marshal]::Copy($bits.Scan0,$pixels,0,$pixels.Length)
        $visited=[bool[]]::new($w*$h);$queue=[Collections.Generic.Queue[int]]::new()
        for($x=0;$x -lt $w;$x++){foreach($p in @($x,(($h-1)*$w+$x))){if(-not $visited[$p]){$visited[$p]=$true;$queue.Enqueue($p)}}}
        for($y=0;$y -lt $h;$y++){foreach($p in @(($y*$w),($y*$w+$w-1))){if(-not $visited[$p]){$visited[$p]=$true;$queue.Enqueue($p)}}}
        $removed=0
        while($queue.Count){
            $p=$queue.Dequeue();$i=$p*4
            if($pixels[$i+3] -ne 0 -and ($pixels[$i] -lt $WhiteThreshold -or $pixels[$i+1] -lt $WhiteThreshold -or $pixels[$i+2] -lt $WhiteThreshold)){continue}
            if($pixels[$i+3] -ne 0){$removed++}
            $pixels[$i]=0;$pixels[$i+1]=0;$pixels[$i+2]=0;$pixels[$i+3]=0
            $x=$p%$w;$y=[int][Math]::Floor($p/$w)
            $neighbors=[Collections.Generic.List[int]]::new()
            if($x -gt 0){$neighbors.Add($p-1)};if($x -lt $w-1){$neighbors.Add($p+1)}
            if($y -gt 0){$neighbors.Add($p-$w)};if($y -lt $h-1){$neighbors.Add($p+$w)}
            foreach($n in $neighbors){if(-not $visited[$n]){$visited[$n]=$true;$queue.Enqueue($n)}}
        }
        [Runtime.InteropServices.Marshal]::Copy($pixels,0,$bits.Scan0,$pixels.Length)
        $visible=0;for($i=3;$i -lt $pixels.Length;$i+=4){if($pixels[$i] -gt 0){$visible++}}
        $visibleFraction=$visible/($w*$h)
        if($visibleFraction -lt .35 -or $visibleFraction -gt .95){throw "Unexpected visible silhouette ratio: $visibleFraction; inspect source before changing threshold"}
    } finally {$bitmap.UnlockBits($bits)}
    foreach($point in @(@(0,0),@(($w-1),0),@(0,($h-1)),@(($w-1),($h-1)))){if($bitmap.GetPixel($point[0],$point[1]).A -ne 0){throw 'Icon corners must be transparent'}}
    New-Item -ItemType Directory -Force (Join-Path $PSScriptRoot 'icons')|Out-Null
    $pngs=@{};$pngSizes=@(16,20,24,32,40,48,64,128,256,512)
    foreach($size in $pngSizes){
        $small=[Drawing.Bitmap]::new($size,$size,[Drawing.Imaging.PixelFormat]::Format32bppArgb)
        $g=[Drawing.Graphics]::FromImage($small)
        $attributes=[Drawing.Imaging.ImageAttributes]::new()
        try {
            $g.CompositingMode=[Drawing.Drawing2D.CompositingMode]::SourceCopy
            $g.CompositingQuality=[Drawing.Drawing2D.CompositingQuality]::HighQuality
            $g.InterpolationMode=[Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
            $g.PixelOffsetMode=[Drawing.Drawing2D.PixelOffsetMode]::HighQuality
            $attributes.SetWrapMode([Drawing.Drawing2D.WrapMode]::TileFlipXY)
            $g.DrawImage($bitmap,[Drawing.Rectangle]::new(0,0,$size,$size),0,0,$w,$h,[Drawing.GraphicsUnit]::Pixel,$attributes)
            $stream=[IO.MemoryStream]::new()
            try {$small.Save($stream,[Drawing.Imaging.ImageFormat]::Png);$pngs[$size]=$stream.ToArray()}finally{$stream.Dispose()}
            [IO.File]::WriteAllBytes((Join-Path $PSScriptRoot "icons/$size.png"),$pngs[$size])
        } finally {$attributes.Dispose();$g.Dispose();$small.Dispose()}
    }
    $bitmap.Save((Join-Path $PSScriptRoot 'ferroc.png'),[Drawing.Imaging.ImageFormat]::Png)
    $icoSizes=@(16,24,32,48,64,128,256)
    $file=[IO.File]::Create((Join-Path $PSScriptRoot 'ferroc.ico'));$writer=[IO.BinaryWriter]::new($file)
    try {
        $writer.Write([uint16]0);$writer.Write([uint16]1);$writer.Write([uint16]$icoSizes.Count)
        $offset=6+16*$icoSizes.Count
        foreach($size in $icoSizes){$dim=if($size -eq 256){0}else{$size};$writer.Write([byte]$dim);$writer.Write([byte]$dim);$writer.Write([byte]0);$writer.Write([byte]0);$writer.Write([uint16]1);$writer.Write([uint16]32);$writer.Write([uint32]$pngs[$size].Length);$writer.Write([uint32]$offset);$offset+=$pngs[$size].Length}
        foreach($size in $icoSizes){$writer.Write([byte[]]$pngs[$size])}
    } finally {$writer.Dispose();$file.Dispose()}
    $paths=@('ferroc.png','ferroc.ico')+@($pngSizes|ForEach-Object{"icons/$_.png"})
    $outputs=@($paths|ForEach-Object{@{path="assets/$_";sha256=(Get-FileHash (Join-Path $PSScriptRoot $_) -Algorithm SHA256).Hash.ToLowerInvariant()}})
    $manifest=@{source=[IO.Path]::GetRelativePath((Split-Path $PSScriptRoot -Parent),$sourcePath).Replace('\','/');sourceSha256=(Get-FileHash $sourcePath).Hash.ToLowerInvariant();sourceDimensions=@($w,$h);operation='edge-connected near-white alpha cleanup then high-quality bicubic resize; no new artwork synthesized';whiteThreshold=$WhiteThreshold;removedMattePixels=$removed;visibleFraction=$visibleFraction;icoSizes=$icoSizes;pngSizes=$pngSizes;masterDimensions=@($w,$h);outputs=$outputs}|ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'branding/icon-manifest.json'),($manifest.Replace("`r`n","`n")+"`n"),[Text.UTF8Encoding]::new($false))
    Write-Output "Generated Agnes-derived ferroc.png ($($w)x$h), seven-size ferroc.ico, ten PNG variants; cleared $removed outside-matte pixels."
} finally {$bitmap.Dispose()}
