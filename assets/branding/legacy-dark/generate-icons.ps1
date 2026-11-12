$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$sizes = @(16, 24, 32, 48, 64, 128, 256)
$images = @()
foreach ($size in $sizes) {
    $bitmap = [System.Drawing.Bitmap]::new($size, $size)
    $g = [System.Drawing.Graphics]::FromImage($bitmap)
    $g.Clear([System.Drawing.Color]::FromArgb(255, 20, 30, 44))
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $brush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(255, 224, 109, 65))
    # Iron-orange F monogram, with a small command cursor.
    $g.FillRectangle($brush, [single]($size*.22), [single]($size*.18), [single]($size*.16), [single]($size*.65))
    $g.FillRectangle($brush, [single]($size*.22), [single]($size*.18), [single]($size*.56), [single]($size*.15))
    $g.FillRectangle($brush, [single]($size*.22), [single]($size*.44), [single]($size*.43), [single]($size*.14))
    $g.FillRectangle($brush, [single]($size*.57), [single]($size*.72), [single]($size*.22), [single]($size*.09))
    $stream = [System.IO.MemoryStream]::new()
    $bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $images += ,$stream.ToArray()
    if ($size -eq 256) { $bitmap.Save((Join-Path $PSScriptRoot 'ferroc.png'), [System.Drawing.Imaging.ImageFormat]::Png) }
    $stream.Dispose(); $brush.Dispose(); $g.Dispose(); $bitmap.Dispose()
}
$file = [System.IO.File]::Create((Join-Path $PSScriptRoot 'ferroc.ico'))
$writer = [System.IO.BinaryWriter]::new($file)
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$sizes.Count)
    $offset = 6 + 16 * $sizes.Count
    for ($i=0; $i -lt $sizes.Count; $i++) {
        $dim = if ($sizes[$i] -eq 256) { 0 } else { $sizes[$i] }
        $writer.Write([byte]$dim); $writer.Write([byte]$dim); $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$images[$i].Length); $writer.Write([uint32]$offset)
        $offset += $images[$i].Length
    }
    foreach ($image in $images) { $writer.Write([byte[]]$image) }
} finally { $writer.Dispose(); $file.Dispose() }
Write-Output 'Generated ferroc.png and seven-size ferroc.ico.'
