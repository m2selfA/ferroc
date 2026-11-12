param([string]$Binary='target/release/ferroc.exe',[string]$UpstreamReceipt='artifacts/upstream-e2e.json',[string]$ProxyReceipt='artifacts/agent-proxy-verification.json')
$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $map=Get-Content artifacts/build-provenance.json -Raw | ConvertFrom-Json
    foreach($s in $map.sourceFiles){
        if((Get-FileHash $s.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $s.sha256){throw "Source hash mismatch: $($s.path)"}
    }
    $actual=(Get-FileHash $Binary -Algorithm SHA256).Hash.ToLowerInvariant()
    foreach($p in @('artifacts/build-provenance.json','artifacts/native-release-roundtrip.json',$UpstreamReceipt,'artifacts/transfer-verification.json')){
        $r=Get-Content $p -Raw | ConvertFrom-Json
        if($r.binarySha256 -ne $actual){throw "Receipt binary mismatch: $p"}
    }
    $up=Get-Content $UpstreamReceipt -Raw | ConvertFrom-Json
    if($up.success -ne $true -or (Get-FileHash $up.harness -Algorithm SHA256).Hash.ToLowerInvariant() -ne $up.harnessSha256){throw 'Upstream harness/result mismatch'}
    $transfer=Get-Content artifacts/transfer-verification.json -Raw | ConvertFrom-Json
    if($transfer.success -ne $true){throw 'Transfer verification did not succeed'}
    foreach($f in $transfer.evidenceFiles){if((Get-FileHash $f.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $f.sha256){throw "Transfer evidence mismatch: $($f.path)"}}
    $r=Get-Content artifacts/windows-resources-release.json -Raw | ConvertFrom-Json
    # Resolve actual paths; do not put Windows backslashes in an embedded JS wildcard (\r/\f).
    if($r.Sha256.ToLowerInvariant() -ne $actual -or (Resolve-Path $r.Binary).Path -ne (Resolve-Path $Binary).Path){throw 'Resource identity mismatch'}
    $r=Get-Content artifacts/native-release-roundtrip.json -Raw | ConvertFrom-Json
    if((Get-FileHash $r.harness -Algorithm SHA256).Hash.ToLowerInvariant() -ne $r.harnessSha256 -or (Get-FileHash $r.log -Algorithm SHA256).Hash.ToLowerInvariant() -ne $r.logSha256){throw 'Harness/log mapping mismatch'}
    $proxy=Get-Content $ProxyReceipt -Raw | ConvertFrom-Json
    if($proxy.binarySha256 -ne $actual -or $proxy.success -ne $true){throw 'Proxy receipt binary/result mismatch'}
    foreach($f in $proxy.evidenceFiles){
        if((Get-FileHash $f.path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $f.sha256){throw "Proxy evidence mismatch: $($f.path)"}
    }
    if($proxy.publicProviderAttempted -ne $false -or $proxy.publicProxyAttempted -ne $false){throw 'Unexpected public-network evidence scope'}
    # Compare production inputs; first full-suite scenarios have a separately retained source snapshot.
    $full=Get-Content artifacts/agent-proxy/full-suite-source.json -Raw | ConvertFrom-Json
    if($full.binarySha256 -ne $actual){throw 'Full-suite binary association mismatch'}
    foreach($s in $map.sourceFiles){
        $record=@($full.files|Where-Object path -eq $s.path)
        if($record.Count -ne 1 -or $record[0].sha256 -ne $s.sha256){throw "Full-suite production source mismatch: $($s.path)"}
    }
    git apply --reverse --check artifacts/review.patch
    if($LASTEXITCODE -ne 0){throw 'Patch no longer matches workspace'}
    if($env:OS -eq 'Windows_NT'){
        $live=@(Get-CimInstance Win32_Process | Where-Object Name -eq 'ferroc.exe')
        if($live.Count){throw 'Residual ferroc process'}
    }
    Write-Output "PASS evidence closure: source map, 4 binary receipts + proxy receipt, release resources, harness/log hashes, whole-addition patch, no test processes. SHA256=$actual"
} finally { Pop-Location }
