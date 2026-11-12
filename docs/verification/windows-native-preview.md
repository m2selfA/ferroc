# Windows native relay + agent preview verification (historical pre-transfer baseline)

This report belongs ONLY to hash `677aebe5...0745fb6a`. The executable at the canonical path has since changed. Its receipts/log/source patch are archived in `artifacts/native-before-transfers/`; current increment: [windows-transfer-preview.md](windows-transfer-preview.md). Do not attribute this old hash or full-22-tool success to the new transfer handlers.

## Identity and provenance

- Actual release executable: `target/release/ferroc.exe`, version 0.1.0, Rust/Cargo 1.98.1 x86_64-pc-windows-msvc.
- SHA-256: `677aebe5aae57543f4a63c2f4757fea1b64ff4840c7fc9891b4453880745fb6a`.
- Both native relay and agent are OS processes launched from this same executable in the release roundtrip, not a Node relay or an in-process substitute. The test runner is a debug Rust test executable selected via `FERROC_TEST_BINARY`.
- Current source/binary map: `artifacts/build-provenance.json`; native receipt/log: `artifacts/native-release-roundtrip.json` and `.log`. Source is uncommitted; no commit-to-binary claim.
- The earlier agent-only binary has a DIFFERENT hash and archived receipts under `artifacts/agent-only/`. Do not substitute its identity for this binary.

## Executed verification

- `scripts/verify.ps1 -Release`: fmt, clippy with warnings denied, 31 tests (18 core + 2 native relay/store + 2 process I/O + 8 transports + 1 Windows path), release build and seven-size embedded PE icon/product checks.
- `scripts/audit-source.ps1`: whole-addition patch parsed and reverse-check passed against the unborn repository; no staging/reset/commit.
- Native actual release relay + release agent roundtrip: 8.18 seconds. Discovery, DCR, login/consent, PKCE S256, invalid verifier refusal, one-use code, initialize, remote tools/list, list_devices, **all 22 agent tools through the native relay**, outside-root refusal, process stdin/output/lifecycle, background search, pause/resume/rename/delete, metadata-only audit, access revocation, refresh rotation/replay refusal and client deletion.
- Origin-required login, cross-origin MCP HTTP 403, malformed MCP request IDs/params (-32600), unsafe redirect control-character normalization, and invalid consent-CSRF negative cases passed. Session/browser pages were exercised as HTTP forms, not a visual interactive-browser QA claim.
- SQLite independent test: eight concurrent attempts consume one one-shot row exactly once; reopen persistence works; unique device insertion refuses replacement. Generated access/refresh/code/device token material absent from actual fixture SQLite + WAL bytes.
- Resource negative control: mutate one embedded-icon byte in a **separate non-executed artifact copy**; verifier must reject precisely the changed icon. Canonical release hash remains unchanged.

## Independent original-relay compatibility track

The same release binary was separately rerun against the unchanged pinned BRC Node relay (`cbe511702dd0147650353c29ac6ab1decd8afda1`). Pairing, file edits/read/search, outside-root refusal, all canonical 14 OAuth/MCP checks, and admin device revocation passed. Receipt: `artifacts/upstream-e2e.json`; log: `artifacts/upstream-e2e-native.log`.

These checks remain original-relay compatibility evidence, NOT native OAuth equivalence evidence. Node is only used on this separate reference-test track.

## Hygiene and scope

- Temporary DB, credentials and listeners; no persistent service, existing relay mutation, registry change or Node DB migration.
- Device revoked and agent joined; isolated relay fixture terminated and joined; scratch directories removed. Final process check found no remaining ferroc.exe test process. Canonical release hash unchanged after both tracks.
- Recommended scrypt cost was NOT weakened after an initial 10s debug-test timeout. Crate source confirmed N=2^17/r=8/p=1; only test observation budget became 90s. Default unoptimized double-process E2E takes about 53s.
- Native implementation is a single-admin, JSON HTTP MCP preview. Static multi-device routing is not a live multi-device/reconnect proof. No SSE/session-resumption, native non-Windows execution, public TLS/real SaaS connector, adversarial local race or production-load claim.
- Full rewrite remains in progress: four document/encrypted-transfer handlers and service lifecycle missing; remote policy mutation intentionally denied. See `../PARITY.md` and `../../SECURITY.md`.

## Historical executed recipe (not reproducible with the changed current tree)

Recover the archived source patch before reproducing this historical binary; these commands alone against the current tree do not establish the old identity.

```powershell
.\scripts\verify.ps1 -Release
$env:FERROC_TEST_BINARY = (Resolve-Path .\target\release\ferroc.exe).Path
try { cargo test --locked --test native_relay -- --nocapture }
finally { Remove-Item Env:FERROC_TEST_BINARY }
.\scripts\audit-source.ps1
.\scripts\verify-provenance.ps1
```

## Independent review

Final-check returned **Not done yet**; full rewrite remains in progress, not reduced or declared complete. Raw receipt: `artifacts/advisor-native-final-check.log`. Its scope warning is accepted: four unimplemented handlers plus one intentionally denied handler, service lifecycle and deeper parity remain. Its “no verification result recorded / background unresolved” observations conflict with the retained successful logs and terminal task receipt; they are not a direct repository code audit. The self-referential wait item was satisfied by inspecting the completed task, not starting another review loop. Requested all-targets/all-features fmt/clippy/test and native/resource checks were executed and recorded after the final source changes. Earlier syntax/escaping failures were repaired before rerunning and regenerating the full patch; no failed gate was waived. Local tests and scope review are NOT independent security approval.
