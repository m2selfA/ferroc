# Windows encrypted-transfer increment (historical opt-in baseline)

This report covers ONLY the default-off binary hash `5f43424e...3cc68b27`. The operator subsequently requested default-on behavior; current source/binary may differ. Historical receipts are archived in `artifacts/transfers-optin-baseline/`. See [windows-transfer-defaults.md](windows-transfer-defaults.md) for the default-on increment.

## Identity and status

Current release `target/release/ferroc.exe` SHA-256: `5f43424ef2820699d8463e20dfb5a8b158e4f117317818150446a6f53cc68b27`. Windows x86_64, Rust/Cargo 1.98.1, uncommitted preview (no commit-to-binary claim). All local gates below passed; full project/security sign-off remains open. Previous native-only baseline: `677aebe5aae57543f4a63c2f4757fea1b64ff4840c7fc9891b4453880745fb6a`, archived receipts/source patch under `artifacts/native-before-transfers/`.

## Executed local gates

- `scripts/verify.ps1 -Release`: fmt, strict clippy all-targets/all-features, **38 passed + 1 intentionally separate/ignored oracle**, release build and seven-size PE resource/identity check.
- Explicit original-Node oracle: **1 passed** (same new source; default suite deliberately does not require Node/upstream checkout). Node transform-mode loader corrected after an initial strip-only failure; original crypto was not modified.
- Actual SAME release native relay + agent subprocesses: **2 passed, 9.07s**. 26 remote tools; 22 existing core handlers successful, transfer prepare successful, send/receive malformed-input negative routes. These negatives are NOT successful external file transfers.
- Same release against unchanged original Node relay: **7 groups + canonical 14 checks passed** after fixing the harness's stale `22` count to exact `25`. Added prepare + invalid-input transfer routing. Initial failing log/receipt retained separately, no failure waived, canonical OAuth script unchanged.
- Resource negative copy `artifacts/transfers-corrupted-icon-negative.exe` (never executed): one changed icon byte rejected with expected payload mismatch. Canonical binary SHA-256 unchanged.
- `scripts/audit-source.ps1`: full-addition patch parsed/reverse-checked against current unborn repository; all source hashes recorded. `scripts/verify-provenance.ps1`: checks four binary-linked receipts, source hashes, successful upstream/transfer records, harness/log hashes, release-resource path/hash, current patch, and no residual ferroc test processes. No commit/staging/reset or service installation.
- Receipts: `artifacts/build-provenance.json`, `native-release-roundtrip.json`, `upstream-e2e.json`, `transfer-verification.json`. The transfer receipt binds oracle source/helper/test/log hashes and explicitly labels mocked vs live scope. Previous receipt set stays under `artifacts/native-before-transfers/`.

## Implemented contract

25 of 27 upstream handlers now have implementations: prior 22 plus `prepare_file_transfer`, `send_file_transfer`, `receive_file_transfer`. `set_config_value` remains intentionally denied; `write_pdf` absent. Rich document semantics, service lifecycle and deeper protocol parity remain open. Native remote list adds `list_devices` (26 advertised tools); advertised does NOT mean enabled without local opt-in.

BRCX1 v1 uses X25519 DER/SPKI (44 bytes), HKDF-SHA256, AES-256-GCM. Exact AAD/info strings and envelope fields follow pinned upstream `cbe511702dd0147650353c29ac6ab1decd8afda1`. Public provider remains tmpfiles.org: no extra persistent service and no new relay wire protocol. Default denies all three handlers until local `--allow-transfers`.

## Evidence tiers

- **Static-confirmed:** pinned transfer source Git blob `d541a49af6a0c3371e1d6726a6b80de84d3e3997`, source SHA-256 `1aa3e0ee075ace1961af9cfda49dbdb6abedae13b0c33db54339cc1d6d8a47c0`. Byte-identical snapshot `docs/upstream/file-transfer.ts`.
- **Locally verified crypto/IO:** original pinned Node functions and actual Rust transfer handlers interoperate in BOTH directions for empty, binary and 1 MiB fixtures; recovered file bytes checked exactly. Rust sends through a local HTTP multipart fixture, Node receives using its original decrypt/write functions; Node sends through its original encrypt/upload functions and Rust receives through HTTP fixture and atomic commit.
- **Oracle provenance:** `scripts/transfer-oracle.mjs` verifies checkout pin and blob, uses Node built-in TypeScript transform, replaces ONLY filesystem-policy import with fixture identity, and mocks provider fetch in memory. Crypto/format/streaming functions remain original source. This is not a full unchanged Node agent or live provider run. Oracle helper/source identity is printed to its separate log; oracle process is stopped and joined.
- **Locally verified scale:** 99,000,000-byte Rust cryptographic roundtrip, the configured plaintext cap. This is NOT a 99 MB HTTP/provider test or cross-language scale proof.
- **Failure cases:** mismatching GCM fields/key/salt/IV/tag, wrong receiver/low-order public key, hash/size mismatch, malformed/expired tokens, bad URL hosts/schemes/ports/credentials/fragment, source policy/oversize refusal, strict argument types, receive-key cap/expiry/shutdown, default deny. HTTP provider Content-Length and chunked overflow, truncated body, 503 and redirect rejection have exact expected error assertions, not generic-error passes.
- **Commit/cancellation:** failures leave destination absent/unchanged and retain receive key; success consumes it. Cancelling a blocking read retains the one-transfer capacity until CPU work finishes. Cancelling an observer before admitted commit does not roll back the commit: target is written and receive key consumed INSIDE blocking commit. Dedicated test proves this boundary.
- **Not attempted / unverified:** real tmpfiles.org HTTPS upload/download, provider HTML/API changes/retention/proxies, 99 MB HTTP transport, public relay/SaaS, native Linux/macOS and production load. No private/user file upload, installed service or persistent infrastructure change.

## Limits and intentional divergences

One active transfer, 128 receive keys, TTL 60..7200s, keys volatile with expiry cleanup, 99 MB data cap. Provider URLs limited to HTTPS tmpfiles.org/www.tmpfiles.org:443, no credentials/fragment, no redirects. Token 16 KiB; page 1 MiB; provider JSON 64 KiB. Bounded full-buffer AEAD instead of upstream disk streaming. Atomic tempfile replacement instead of upstream delete-before-rename. Recheck expiry before persist. No sender identity authentication, metadata-AEAD binding, hard rollback, memory-locking or crash-exactly-once claim. Synchronized clocks required; provider retention is outside local control. See `../../SECURITY.md`.

## Independent review boundary

Advisor final-check returned **Not done yet** for the original FULL rewrite; accepted, and task #4 remains in progress. Raw review: `artifacts/advisor-transfer-final-check.log`. PDF/rich documents, service lifecycle and deeper compatibility are still open, not waived.

Its pending-#5/no-verification/self-wait statements conflict with the completed #5 record, terminal review task and retained successful logs above. Those stale observations are not independent source-code/security findings. Requested complete test matrix already passed after all runtime/Cargo changes; the corrected exact-count harness was rerun separately. A final cached release rebuild and hash check verify no build-input drift. The repository is unborn; no commit provenance is fabricated. This review is NOT independent security approval.

`verify-handler-parity.ps1` produces an exact 27-name static ledger against the actual 25-tool binary registry, classifying the two unregistered names separately. It is NOT a substitute for full behavioral equivalence testing. The first audit prototype incorrectly read the broader schema map; this tooling error was fixed to the real dispatcher snapshot (`a6c68e503915e1e9f7cf60942f80866c2036e461`). Exact 27/25 positive check and rejection of schemas.ts as an incorrect source both pass; no false alarm is left unresolved.

## Reproduction

```powershell
.\scripts\verify.ps1 -Release
$env:FERROC_UPSTREAM = 'E:/inter/Documents/Repos/better-remote-commander'
try { cargo test --locked --all-features --lib original_node_brcx1_interop -- --ignored --nocapture }
finally { Remove-Item Env:FERROC_UPSTREAM }
$env:FERROC_TEST_BINARY = (Resolve-Path .\target\release\ferroc.exe).Path
try { cargo test --locked --all-features --test native_relay -- --nocapture }
finally { Remove-Item Env:FERROC_TEST_BINARY }
node scripts/upstream-e2e.mjs E:/inter/Documents/Repos/better-remote-commander ./target/release/ferroc.exe
.\scripts\audit-source.ps1
.\scripts\verify-provenance.ps1
```

Logs: `artifacts/transfer-full-verification.log`, `transfer-original-node-final.log`, `native-release-roundtrip.log`, `upstream-e2e-transfers-fixed.log`. These commands require the receipts produced by the recorded harness; the provenance script does not fabricate successful test records.
