param([string]$Exe='target/release/ferroc-gui.exe',[string]$ExpectedSha256='',[string]$BaseRef='HEAD')
$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    New-Item -ItemType Directory -Force artifacts | Out-Null
    if(-not $ExpectedSha256){
        if(-not (Test-Path artifacts/gui-release-screenshot-receipt.json)){throw 'Pass -ExpectedSha256 captured immediately after the GUI build'}
        $ExpectedSha256=(Get-Content artifacts/gui-release-screenshot-receipt.json -Raw|ConvertFrom-Json).GuiBinarySha256
    }
    if($ExpectedSha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'Expected GUI SHA256 must contain64 hex digits'}
    $binaryHash=(Get-FileHash $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    if($binaryHash -ne $ExpectedSha256.ToLowerInvariant()){throw 'GUI binary hash mismatch; wrong or changed executable'}
    $peBytes=[IO.File]::ReadAllBytes((Resolve-Path $Exe))
    $pe=[BitConverter]::ToInt32($peBytes,0x3c)
    if([BitConverter]::ToUInt16($peBytes,$pe+24+68) -ne 2){throw 'Expected Windows GUI subsystem2, not a CLI binary'}
    $tracked=@(& git diff --binary $BaseRef --)
    if($LASTEXITCODE -ne 0){throw 'Tracked diff generation failed'}
    & git diff --check $BaseRef --
    if($LASTEXITCODE -ne 0){throw 'Tracked whitespace audit failed'}
    $patch=[Collections.Generic.List[string]]::new()
    foreach($line in $tracked){$patch.Add($line)}
    $new=@(& git ls-files --others --exclude-standard)
    if($LASTEXITCODE -ne 0){throw 'Untracked enumeration failed'}
    foreach($file in $new){
        $check=@(& git -c core.autocrlf=false diff --no-index --check -- /dev/null $file 2>&1)
        if($LASTEXITCODE -gt 1 -or $check.Count -gt 0){throw "Untracked whitespace/diff audit failed: $file : $check"}
        $lines=@(& git -c core.autocrlf=false diff --no-index --binary -- /dev/null $file)
        if($LASTEXITCODE -gt 1){throw "New-file diff generation failed: $file"}
        foreach($line in $lines){$patch.Add($line)}
    }
    $out=Join-Path (Get-Location) 'artifacts/gui-review.patch'
    $patchText=if($patch.Count){[string]::Join("`n",$patch)+"`n"}else{''}
    [IO.File]::WriteAllText($out,$patchText,[Text.UTF8Encoding]::new($false))
    if($patch.Count){
        & git apply --stat $out
        if($LASTEXITCODE -ne 0){throw 'Combined patch parse failed'}
        & git apply --reverse --check $out
        if($LASTEXITCODE -ne 0){throw 'Combined patch reverse-check failed'}
    } else {
        Write-Output 'No diff against selected base; continuing full source, binary and registry checks.'
    }
    $files=@(& git ls-files --cached --others --exclude-standard)
    if($LASTEXITCODE -ne 0){throw 'Source enumeration failed'}
    $manifest=@($files|Sort-Object -Unique|ForEach-Object {
        if(-not (Test-Path -LiteralPath $_ -PathType Leaf)){throw "Missing source file: $_"}
        [ordered]@{path=$_;sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()}
    })
    $metadataText=(& cargo metadata --locked --features gui --format-version 1 --filter-platform x86_64-pc-windows-msvc | Out-String)
    if($LASTEXITCODE -ne 0){throw 'Locked GUI metadata failed'}
    $metadata=$metadataText|ConvertFrom-Json
    $windui=@($metadata.packages|Where-Object name -eq 'windui')
    if($windui.Count -ne 1 -or $windui[0].version -ne '0.32.0' -or $windui[0].source -ne 'registry+https://github.com/rust-lang/crates.io-index'){throw 'WindUI registry identity mismatch'}
    $w=$windui[0];$dir=Split-Path $w.manifest_path
    $registry=Split-Path (Split-Path (Split-Path $dir))
    $registryName=Split-Path (Split-Path $dir) -Leaf
    $archive=Join-Path $registry ('cache/'+$registryName+'/windui-0.32.0.crate')
    $packageHash=(Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if($packageHash -ne '464c6095750e6d24823007f877d63eaab32594e83dea4fca4d49c6331ca54fe5'){throw 'WindUI package checksum mismatch'}
    # Independently compare the actual compilation cache with the verified crate.
    # Witness extraction lives under ignored artifacts, never in canonical cache.
    $witness=Join-Path (Get-Location) 'artifacts/windui-registry-archive-witness'
    New-Item -ItemType Directory -Force $witness|Out-Null
    & tar.exe -xf $archive -C $witness
    if($LASTEXITCODE -ne 0){throw 'Registry archive witness extraction failed'}
    $published=Join-Path $witness 'windui-0.32.0'
    $verifiedSourceFiles=0
    foreach($file in @(Get-ChildItem $published -Recurse -File -Force)){
        $relative=[IO.Path]::GetRelativePath($published,$file.FullName)
        $cached=Join-Path $dir $relative
        if(-not (Test-Path -LiteralPath $cached -PathType Leaf)){throw "Registry cached file missing: $relative"}
        if((Get-FileHash -LiteralPath $cached).Hash -ne (Get-FileHash -LiteralPath $file.FullName).Hash){throw "Registry source differs from published archive: $relative"}
        $verifiedSourceFiles++
    }
    if($verifiedSourceFiles -eq 0){throw 'Registry source witness was empty'}
    foreach($file in @(Get-ChildItem $dir -Recurse -File -Force)){
        $relative=[IO.Path]::GetRelativePath($dir,$file.FullName)
        if($relative -in @('.cargo-ok','.cargo-checksum.json')){continue}
        if(-not (Test-Path -LiteralPath (Join-Path $published $relative) -PathType Leaf)){throw "Unpublished registry cache file: $relative"}
    }
    $provenance=[ordered]@{
        state='local GUI preview snapshot; no release tag or build-to-commit correspondence asserted'
        baseCommit=(& git rev-parse HEAD);diffBaseRef=$BaseRef;hasDiff=($patch.Count -gt 0);compiler=(& rustc --version);cargo=(& cargo --version)
        binary=$Exe;binarySha256=$binaryHash;expectedBinarySha256=$ExpectedSha256.ToLowerInvariant()
        buildRecipe='cargo build --locked --release --features gui --bin ferroc-gui'
        recipeEvidence='artifacts/gui-release-final-build.log'
        windui=[ordered]@{version=$w.version;source=$w.source;packageSha256=$packageHash;extractedSourceFilesVerified=$verifiedSourceFiles;publishedVcs=(Get-Content (Join-Path $dir '.cargo_vcs_info.json') -Raw|ConvertFrom-Json).git.sha1}
        patchSha256=(Get-FileHash $out -Algorithm SHA256).Hash.ToLowerInvariant()
        sourceFiles=$manifest
        boundaries=@('native test binary is not the GUI release executable','queue consumption is not Shell tooltip readback','Cua pixel/copy path and independent advisor remain live-blocked')
    }
    $provenance|ConvertTo-Json -Depth 7|Set-Content -Encoding utf8 artifacts/gui-build-provenance.json
    Write-Output ('GUI source/registry manifest, untracked whitespace and combined patch reverse-check passed; binary SHA256 '+$provenance.binarySha256)
} finally {Pop-Location}
