param([switch]$Release)
$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    New-Item -ItemType Directory -Force artifacts | Out-Null
    $checks=@(
        @{ Name='fmt'; Args=@('fmt','--check') },
        @{ Name='clippy'; Args=@('clippy','--locked','--all-targets','--all-features','--','-D','warnings') },
        @{ Name='tests'; Args=@('test','--locked','--all-targets','--all-features') }
    )
    if ($Release) { $checks += @{ Name='release'; Args=@('build','--locked','--release') } }
    foreach ($check in $checks) {
        & cargo @($check.Args) 2>&1 | Tee-Object -FilePath "artifacts/$($check.Name).log"
        if ($LASTEXITCODE -ne 0) { throw "$($check.Name) failed with exit $LASTEXITCODE" }
    }
    if ($env:OS -eq 'Windows_NT') {
        $exe=if ($Release) { './target/release/ferroc.exe' } else { './target/debug/ferroc.exe' }
        $resourceReport=if($Release){"artifacts/windows-resources-release.json"}else{"artifacts/windows-resources-debug.json"}
        & "$PSScriptRoot/verify-windows-resources.ps1" -Exe $exe | Tee-Object -FilePath $resourceReport
    }
} finally { Pop-Location }
