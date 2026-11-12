param([string]$Binary='target/release/ferroc.exe',[string]$Dispatcher='docs/upstream/dispatcher.ts')
$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    $blob=git hash-object --no-filters $Dispatcher
    if($LASTEXITCODE -ne 0 -or $blob -ne 'a6c68e503915e1e9f7cf60942f80866c2036e461'){throw 'Dispatcher source identity mismatch'}
    $source=Get-Content $Dispatcher -Raw
    $block=[regex]::Match($source,'(?s)const TOOL_HANDLERS:[^{]*\{(.*?)\r?\n\};')
    if(-not $block.Success){throw 'Cannot locate pinned upstream dispatcher map'}
    $names=@([regex]::Matches($block.Groups[1].Value,'(?m)^\s+([a-z_]+):')|ForEach-Object{$_.Groups[1].Value})
    if($names.Count -ne 27 -or @($names|Sort-Object -Unique).Count -ne 27){throw 'Expected exactly 27 unique upstream handlers'}
    $definitions=& $Binary tools | ConvertFrom-Json
    if($LASTEXITCODE -ne 0){throw 'Native tool registry probe failed'}
    $actual=@($definitions.name)
    $expected=@($names|Where-Object{$_ -notin @('set_config_value','write_pdf')})
    if($actual.Count -ne 25 -or @($actual|Sort-Object -Unique).Count -ne 25 -or @(Compare-Object $expected $actual -CaseSensitive).Count){throw 'Unexpected registry parity drift'}
    $rows=@($names|ForEach-Object{@{name=$_;status=$(if($_ -eq 'set_config_value'){'intentionally_denied'}elseif($_ -eq 'write_pdf'){'not_implemented'}else{'advertised_native_implementation'})}})
    @{binarySha256=(Get-FileHash $Binary -Algorithm SHA256).Hash.ToLowerInvariant();upstreamPin='cbe511702dd0147650353c29ac6ab1decd8afda1';dispatcherBlob=$blob;scope='Static pinned-dispatcher-name mapping + actual binary registry probe; NOT full semantic tests of all 27 handlers';handlers=$rows}|ConvertTo-Json -Depth 5|Set-Content -Encoding utf8 artifacts/handler-parity.json
    Write-Output 'PASS exact 27-name ledger: 25 advertised native handlers, 1 intentional denial, 1 absent PDF handler (no full-equivalence claim).'
} finally {Pop-Location}
