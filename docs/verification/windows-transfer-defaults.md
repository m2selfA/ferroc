# Windows transfer default-on increment

Historical pre-icon build. The default-on behavior remains current, but the executable hash and receipts below belong to that earlier build. Current executable/icon evidence is in [windows-bright-icon.md](windows-bright-icon.md); old source/binary/evidence are preserved in `artifacts/before-bright-icon/`.

## Requested behavior

Encrypted transfers are now enabled by default for the CLI AND `Policy::new`. `--no-transfers` locally disables all three handlers; the old `--allow-transfers` is accepted as a compatible explicit enable. Supplying both flags is rejected by Clap before dispatch. Shell stays OFF by default. Startup/key preparation do not initiate provider upload; only explicit send/receive calls can contact tmpfiles.org.

The old default-off binary `5f43424ef2820699d8463e20dfb5a8b158e4f117317818150446a6f53cc68b27` has historical receipts/source patch archived in `artifacts/transfers-optin-baseline/`. Do not assign its identity or default-deny behavior to the new source.

## Verification state

Historical pre-icon release SHA-256: `6a4e911229ed64fc4d38d348e4e48b54af3980fed20aa06665a9887cffdfe8fa`. Fmt, all-targets/all-features strict clippy, **40 default tests + 1 separate original-Node oracle**, release build and PE checks passed. Actual release CLI tests passed for default get_config/prepare, legacy enable, --no-transfers config/all-three-handler denial, and flag conflict. Same release native relay+agent: 2 passed (8.15s); unchanged original relay: 7 groups + canonical14 passed. Both agent recipes omit --allow-transfers. Source/binary/receipt/resource hashes and cleanup are checked by verify-provenance.ps1; no public-provider request or full-rewrite completion claim.

The two relay harnesses deliberately omit --allow-transfers, so successful prepare checks verify the new DEFAULT rather than an explicit startup recipe. No actual public-provider upload/download is attempted. Existing BRCX1, 99MB limit, allow-dir restrictions, integrity checks and atomic commit remain unchanged.

## Reproduction

```powershell
.\scripts\verify.ps1 -Release
$env:FERROC_TEST_BINARY = (Resolve-Path .\target\release\ferroc.exe).Path
try { cargo test --locked --all-features --test transfer_defaults --test native_relay -- --nocapture }
finally { Remove-Item Env:FERROC_TEST_BINARY }
# Local manual policy readback, no provider request:
.\target\release\ferroc.exe call get_config
.\target\release\ferroc.exe --no-transfers call get_config
```

Logs: `artifacts/default-on-full-verification.log`, `default-on-original-node.log`, `default-on-release-cli.log`, `native-release-roundtrip.log`, `default-on-upstream.log`. Persistent service installation, real provider, public SaaS, native non-Windows, PDF/rich-document parity and production-load validation remain outside this increment's evidence.
