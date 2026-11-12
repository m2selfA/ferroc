$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    New-Item -ItemType Directory -Force artifacts | Out-Null
    if ((git rev-list --all --count 2>$null) -ne '0') { throw 'Whole-addition audit is only for an unborn repository. Use normal git diff for a committed baseline.' }
    $files=@(git ls-files --others --exclude-standard)
    $patch=[Collections.Generic.List[string]]::new()
    foreach ($file in $files) {
        $lines=git -c core.autocrlf=false diff --no-index --binary -- /dev/null $file
        if ($LASTEXITCODE -gt 1) { throw "Diff generation failed: $file" }
        foreach ($line in $lines) { $patch.Add($line) }
    }
    # Keep LF: WriteAllLines on Windows corrupts Git binary-patch parsing with CRLF.
    [IO.File]::WriteAllText((Join-Path (Get-Location) 'artifacts/review.patch'),([string]::Join("`n",$patch)+"`n"),[Text.UTF8Encoding]::new($false))
    git apply --stat artifacts/review.patch
    if ($LASTEXITCODE -ne 0) { throw 'Patch stat failed' }
    git apply --reverse --check artifacts/review.patch
    if ($LASTEXITCODE -ne 0) { throw 'Patch reverse-check failed' }
    git diff --check
    if ($LASTEXITCODE -ne 0) { throw 'Whitespace diff check failed' }
    $sourceFiles=@('Cargo.toml','Cargo.lock','build.rs')+@(Get-ChildItem src -File | ForEach-Object { 'src/'+$_.Name })+@(Get-ChildItem assets -Recurse -File | Sort-Object FullName | ForEach-Object { [IO.Path]::GetRelativePath((Get-Location).Path,$_.FullName).Replace('\','/') })
    $manifest=@($sourceFiles | ForEach-Object { @{path=$_;sha256=(Get-FileHash $_ -Algorithm SHA256).Hash.ToLowerInvariant()} })
    $map=@{ compiler=(& rustc --version); cargo=(& cargo --version); binary='target/release/ferroc.exe'; binarySha256=(Get-FileHash target/release/ferroc.exe -Algorithm SHA256).Hash.ToLowerInvariant(); sourceFiles=$manifest; sourceState='uncommitted native Rust agent and relay preview; no commit hash claimed'; upstreamPin='cbe511702dd0147650353c29ac6ab1decd8afda1' }
    $map | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 artifacts/build-provenance.json
    Write-Output 'Whole-addition diff generated and reverse-check passed (unborn repository baseline).'
} finally { Pop-Location }
