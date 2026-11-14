# Local-stage synthetic scale probe, NOT relay/network/fleet acceptance.
# No installation, daemon, persistent environment change or real user data.
[CmdletBinding()]
param([int]$TimeoutSeconds = 180, [ValidateSet("release","debug")][string]$Profile = "release")
$ErrorActionPreference = 'Stop'
if ($TimeoutSeconds -lt 10 -or $TimeoutSeconds -gt 600) { throw 'TimeoutSeconds must be 10..600' }
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$evidence = Join-Path $repo ('artifacts/fleet-p0/scale-' + $Profile + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss-fff'))
$null = New-Item -ItemType Directory -Path $evidence
Push-Location $repo
try {
    $inputs=@(); $inputPaths=@("Cargo.toml","Cargo.lock","src/lib.rs","src/runtime.rs","scripts/measure-fleet-p0.ps1","tests/fixtures/fleet-p0-vectors.json","tests/fixtures/fleet-p0-control-vectors.json") + @(Get-ChildItem (Join-Path $repo "src/fleet") -File | ForEach-Object {"src/fleet/"+$_.Name})
    foreach($rel in $inputPaths){$inputs+=@{path=$rel;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $repo $rel)).Hash.ToLowerInvariant()}}
    @{profile=$Profile;timeoutSeconds=$TimeoutSeconds;inputs=$inputs} | ConvertTo-Json -Depth 5 | Set-Content -Encoding utf8 (Join-Path $evidence "inputs.json")
    $cargoArgs=@("test","--locked","--features","fleet-core","--lib","--no-run","--message-format=json");if($Profile -eq "release"){$cargoArgs+="--release"}
    $build = & cargo @cargoArgs 2> (Join-Path $evidence 'build.stderr.log')
    if ($LASTEXITCODE -ne 0) { throw 'test binary build failed; inspect build.stderr.log' }
    $build | Set-Content -Encoding utf8 (Join-Path $evidence 'build.jsonl')
    $artifacts = @($build | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'ferroc' -and $_.executable -and $_.profile.test })
    if ($artifacts.Count -ne 1) { throw 'cannot uniquely identify actual test executable' }
    $exe = $artifacts[0].executable
    $binaryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant()
    $rows = @()
    foreach ($bytes in @(134217728,1073741824)) {
        $workspace=Join-Path $evidence ("workspace-"+$bytes);$null=New-Item -ItemType Directory -Path $workspace
        $row=$null
        $p = [Diagnostics.Process]::new()
        $p.StartInfo.FileName = $exe
        $p.StartInfo.Arguments = '--exact fleet::tests::local_stage_streaming_scale_probe --ignored --nocapture'
        $p.StartInfo.WorkingDirectory = $repo
        $p.StartInfo.UseShellExecute = $false
        $p.StartInfo.CreateNoWindow = $true
        $p.StartInfo.RedirectStandardOutput = $true
        $p.StartInfo.RedirectStandardError = $true
        # Child only: never mutate the controller's environment.
        $p.StartInfo.EnvironmentVariables['FERROC_P0_PROBE_BYTES'] = [string]$bytes
        $p.StartInfo.EnvironmentVariables['FERROC_P0_PROBE_PARENT'] = $workspace
        $watch = [Diagnostics.Stopwatch]::StartNew()
        $peak = 0L; $samples = 0; $started = $false; $saved = $false
        try {
            $started = $p.Start()
            if (-not $started) { throw 'probe process failed to start' }
            $stdout = $p.StandardOutput.ReadToEndAsync()
            $stderr = $p.StandardError.ReadToEndAsync()
            do {
                try { $p.Refresh(); $peak = [Math]::Max($peak,$p.PeakWorkingSet64); $samples++ }
                catch { if (-not $p.HasExited) { throw } }
                if ($p.WaitForExit(100)) { break }
                if ($watch.Elapsed.TotalSeconds -ge $TimeoutSeconds) { $p.Kill(); $p.WaitForExit(); throw 'bounded stage probe timeout; process terminated' }
            } while ($true)
            $out = $stdout.GetAwaiter().GetResult()
            $err = $stderr.GetAwaiter().GetResult()
            $out | Set-Content -Encoding utf8 (Join-Path $evidence "$bytes.stdout.log")
            $err | Set-Content -Encoding utf8 (Join-Path $evidence "$bytes.stderr.log")
            $saved = $true
            if ($p.ExitCode -ne 0) { throw "probe exit $($p.ExitCode); inspect $bytes logs" }
            $line = @($out -split '\r?\n' | Where-Object { $_.StartsWith('FLEET_STAGE_PROBE ') })
            if ($line.Count -ne 1 -or $samples -eq 0 -or $peak -le 0) { throw 'missing stage receipt or process memory observations' }
            $receipt = $line[0].Substring('FLEET_STAGE_PROBE '.Length) | ConvertFrom-Json
            if ($receipt.bytes -ne $bytes -or $receipt.scope -ne 'local-stage-only/not-network') { throw 'probe receipt scope or size mismatch' }
            $row = [pscustomobject]@{bytes=$bytes;sampledKernelPeakWorkingSetBytes=$peak;sampleCount=$samples;receipt=$receipt;workspaceCleanAfterExit=$null}
            $rows += $row
        } finally {
            if ($started) {
                if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
                if (-not $saved -and $stdout -and $stderr) {
                    $stdout.GetAwaiter().GetResult() | Set-Content -Encoding utf8 (Join-Path $evidence "$bytes.stdout.log")
                    $stderr.GetAwaiter().GetResult() | Set-Content -Encoding utf8 (Join-Path $evidence "$bytes.stderr.log")
                }
            }
            $p.Dispose()
            $remaining=@(Get-ChildItem -LiteralPath $workspace -Force)
            if($remaining.Count -gt 0){
                Get-ChildItem -LiteralPath $workspace -Force -Recurse | Select-Object FullName,Length | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidence "$bytes.orphans.json")
                $trash=Get-Command trash -ErrorAction Stop; & $trash.Source $workspace
                if($LASTEXITCODE -ne 0 -or (Test-Path -LiteralPath $workspace)){throw "owned probe workspace cleanup not confirmed: $workspace"}
                @{originalAbsent=$true;method="trash-owned-workspace"} | ConvertTo-Json | Set-Content -Encoding utf8 (Join-Path $evidence "$bytes.rollback.json")
            }
            if($row){$row.workspaceCleanAfterExit=$true}
        }
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLowerInvariant() -ne $binaryHash) { throw 'test executable changed during probes' }
    $growth = $rows[1].sampledKernelPeakWorkingSetBytes - $rows[0].sampledKernelPeakWorkingSetBytes
    $result = [ordered]@{scope='local-stage-only/not-network';profile=$Profile;timeoutSeconds=$TimeoutSeconds;binary=$exe.Substring($repo.Length+1).Replace('\','/');binarySha256=$binaryHash;testBinaryOnly=$true;rows=$rows;observedGrowthBytes=$growth;note='Observed kernel high-water marks sampled before exit; not proof of relay queue RSS, physical disk reservation or universal peak bound.'}
    $result | ConvertTo-Json -Depth 8 | Set-Content -Encoding utf8 (Join-Path $evidence 'result.json')
    $result | ConvertTo-Json -Depth 8 | Write-Output
    Write-Output "Evidence: $evidence"
    if ($growth -gt 64MB -or $rows[1].sampledKernelPeakWorkingSetBytes -gt 256MB) { throw 'unexpected memory growth; investigate instead of declaring bounded memory' }
} finally { Pop-Location }
