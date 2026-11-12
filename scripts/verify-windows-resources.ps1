param(
    [string]$Exe = (Join-Path $PSScriptRoot '../target/debug/ferroc.exe'),
    [string]$Icon = (Join-Path $PSScriptRoot '../assets/ferroc.ico')
)
$ErrorActionPreference = 'Stop'
$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $Exe))
function U16([int]$o) { [BitConverter]::ToUInt16($bytes,$o) }
function U32([int]$o) { [BitConverter]::ToUInt32($bytes,$o) }
$pe = U32 0x3c
if ([Text.Encoding]::ASCII.GetString($bytes,$pe,4) -ne "PE`0`0") { throw 'Not a PE executable' }
$optional = $pe + 24
$dirs = if ((U16 $optional) -eq 0x20b) { $optional + 112 } else { $optional + 96 }
$resourceRva = U32 ($dirs+16)
$sectionCount = U16 ($pe+6)
$sections = $optional + (U16 ($pe+20))
function RvaOffset([uint32]$rva) {
    for ($s=0;$s -lt $sectionCount;$s++) {
        $o=$sections+40*$s; $va=U32 ($o+12); $size=[Math]::Max((U32 ($o+8)),(U32 ($o+16)))
        if ($rva -ge $va -and $rva -lt ($va+$size)) { return [int]((U32 ($o+20))+$rva-$va) }
    }
    throw "Unmapped RVA $rva"
}
$base = RvaOffset $resourceRva
function Entries([int]$relative) {
    $o=$base+$relative; $count=(U16 ($o+12))+(U16 ($o+14))
    for ($i=0;$i -lt $count;$i++) {
        $e=$o+16+8*$i; $name=U32 $e; $target=U32 ($e+4)
        [pscustomobject]@{ Id=$name; IsDirectory=(($target -band 0x80000000L) -ne 0); Offset=[int]($target -band 0x7fffffffL) }
    }
}
function Leaves([int]$relative) {
    foreach ($entry in @(Entries $relative)) {
        if ($entry.IsDirectory) { Leaves $entry.Offset } else {
            $o=$base+$entry.Offset; $rva=U32 $o; $size=U32 ($o+4)
            [pscustomobject]@{ Offset=(RvaOffset $rva); Size=[int]$size }
        }
    }
}
$types = @(Entries 0)
$icons = @($types | Where-Object Id -eq 3 | ForEach-Object { Leaves $_.Offset })
$groups = @($types | Where-Object Id -eq 14 | ForEach-Object { Leaves $_.Offset })
$versions = @($types | Where-Object Id -eq 16 | ForEach-Object { Leaves $_.Offset })
if ($icons.Count -ne 7 -or $groups.Count -ne 1 -or $versions.Count -lt 1) { throw 'Missing icon/group/version resources' }
$ico=[IO.File]::ReadAllBytes((Resolve-Path $Icon))
if ([BitConverter]::ToUInt16($ico,4) -ne 7) { throw 'ICO must contain seven sizes' }
$embedded=@{}
foreach ($entry in $icons) {
    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$bytes[$entry.Offset..($entry.Offset+$entry.Size-1)]))
    $embedded[$hash]=$true
}
$sizes=@()
for ($i=0;$i -lt 7;$i++) {
    $o=6+16*$i; $size=[BitConverter]::ToUInt32($ico,$o+8); $pos=[BitConverter]::ToUInt32($ico,$o+12)
    $hash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$ico[$pos..($pos+$size-1)]))
    if (-not $embedded.ContainsKey($hash)) { throw "Icon payload $i is not embedded byte-for-byte" }
    $sizes += $(if ($ico[$o] -eq 0) { 256 } else { [int]$ico[$o] })
}
# Payload membership alone is insufficient: validate the group references/dimensions too.
$iconType=@($types|Where-Object Id -eq 3)[0];$byId=@{}
foreach($node in @(Entries $iconType.Offset)){
    $leaves=@(Leaves $node.Offset)
    if(-not $node.IsDirectory -or $leaves.Count -ne 1){throw 'Ambiguous icon language/resource mapping'}
    $byId[$node.Id]=$leaves[0]
}
$group=$groups[0].Offset
if((U16 $group) -ne 0 -or (U16 ($group+2)) -ne 1 -or (U16 ($group+4)) -ne 7 -or $groups[0].Size -ne 104){throw 'Invalid seven-entry icon group'}
$ids=@{}
for($i=0;$i -lt 7;$i++){
    $go=$group+6+14*$i;$io=6+16*$i;$id=U16 ($go+12)
    if($ids.ContainsKey($id) -or -not $byId.ContainsKey([uint32]$id)){throw 'Duplicate or missing grouped icon ID'}
    $ids[$id]=$true
    if($bytes[$go] -ne $ico[$io] -or $bytes[$go+1] -ne $ico[$io+1] -or $bytes[$go+2] -ne 0 -or $bytes[$go+3] -ne 0 -or (U16 ($go+4)) -ne 1 -or (U16 ($go+6)) -ne 32){throw "Icon group dimension/format mismatch: $i"}
    $entry=$byId[[uint32]$id];$length=[BitConverter]::ToUInt32($ico,$io+8);$pos=[BitConverter]::ToUInt32($ico,$io+12)
    if((U32 ($go+8)) -ne $length -or $entry.Size -ne $length){throw "Icon group payload size mismatch: $i"}
    $expected=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$ico[$pos..($pos+$length-1)]))
    $actual=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([byte[]]$bytes[$entry.Offset..($entry.Offset+$entry.Size-1)]))
    if($actual -ne $expected){throw "Icon group ID points to wrong payload: $i"}
}
$info=[Diagnostics.FileVersionInfo]::GetVersionInfo((Resolve-Path $Exe))
if ($info.ProductName -ne 'ferroc' -or $info.FileDescription -ne 'ferroc - Ferrum + Commander') { throw 'Product identity mismatch' }
[pscustomobject]@{ Binary=(Resolve-Path $Exe).Path; Product=$info.ProductName; Version=$info.FileVersion; IconSizes=$sizes; IconPayloadsVerified=$icons.Count; GroupMappingsVerified=$sizes.Count; Sha256=(Get-FileHash $Exe -Algorithm SHA256).Hash } | ConvertTo-Json
