# Windows bright-icon increment (historical binary)

The icon assets below remain canonical. The executable/hash and test counts belong only to this historical increment; current agent proxy build evidence is in [windows-agent-proxy.md](windows-agent-proxy.md). The old executable, source map and receipts are preserved in `artifacts/before-agent-proxy/`.

## Scope and identity

Agnes generated a bright iron-orange **F** with a turquoise command chevron on an ivory rounded tile. The English prompt, unmodified original and source provenance are in `assets/branding/`. Only that original is used for all derivatives; no substitute hand-drawn/vector artwork is presented as the Agnes output.

- Requested API model: `agnes-image-2.1-flash`. The provider returned a task ID and URL, not an independently reported model field.
- Task: `task_46EQiUvcHd2fTkswF1dYl4BgNDosvoB4`.
- Original PNG SHA-256: `34640d50d729f38bb53c9911709ee603cfc96993f7898136c13ed29877d43ac2` (1024×1024).
- Current transparent master: `assets/ferroc.png`, 1024×1024, SHA-256 `65fcb92328afff4ecff602a62f74fd70dd43ef28518b6066c2274a97a21dbe68`.
- Current ICO: `assets/ferroc.ico`, SHA-256 `ed48485a9844375533f0efc0a1caee77f778daf99d4b7f0d865603ad8d0372f3`.
- Historical release executable for this increment: `target/release/ferroc.exe`, SHA-256 **`3e459bbf664344c6fd2bd8fb7c80ae9c381669b1b4c96b520e90b12d7e2e9691`**.

The executable is an uncommitted preview build with a source-file hash map, NOT a commit-addressed published release. Version metadata remains 0.1.0. No remote/branch/credential configuration was changed.

## Integration and evidence tiers

**Static-confirmed:** `build.rs` continues embedding the canonical ICO and product identity. `src/icons.rs` shares ICO/master/32px PNG bytes. Existing relay routes serve `/favicon.ico` and `/icon.png`; the shared browser page head links both. No new crate, asset service, desktop framework or persistent service was introduced.

**Locally verified:**

- Native16/24/32/48/64/128 previews were visually inspected on light and dark backgrounds (`artifacts/bright-icon/contact-sheet.png`). The F is the primary tiny-size identifier; the chevron is secondary detail.
- ICO contains exactly 16/24/32/48/64/128/256px, 32-bit RGBA PNG-backed entries. Ten standalone PNG sizes cover 16–512px, including 20/40px DPI variants. `tests/icon_assets.rs` checks dimensions/channel format, directory layout and exact ICO-to-PNG payload identity.
- Offline conversion reproduced all twelve derived output hashes. Encoding identity on other GDI+ versions is not asserted.
- `verify.ps1 -Release`: fmt, locked strict all-targets/all-features clippy, **42 default tests** (including source-profile local99MB crypto), release build and Windows resource validation passed. The ignored original-Node crypto oracle was run separately: **1 passed**. The oracle retains Node's experimental TypeScript-transform warning; it is not a crypto failure or a claim of a stable Node transform API.
- Same-release native test file: **2 passed, 8.34s** (one actual relay+agent OS-process roundtrip; one linked Rust SQLite test, not a second executable probe). Includes 25-tool scope, OAuth/admin/revocation and new favicon HTTP status/content-type/exact-byte checks plus HTML links. Actual release default/disable/legacy/conflict CLI probes: **2 passed**. `FERROC_TEST_BINARY` selected the recorded release executable, not the default debug binary.
- Same release against unchanged pinned original BRC relay: **7 groups + canonical14 OAuth/MCP checks passed**. The extra icon endpoints do not change the BRC tool registry.
- PE validation confirms **7 embedded payloads byte-for-byte**, all **7 group directory dimension/format/ID-to-payload mappings**, and product identity. This is stronger than finding the same image hashes somewhere in the PE.
- `System.Drawing.Icon.ExtractAssociatedIcon` read a real 32px Windows executable/file icon from a byte-identical uniquely named probe copy; the extracted PNG was visually checked. Probe/executable SHA-256 match. This is **not** a native GUI/window/taskbar/tray lifecycle test.
- Negative controls correctly reject the historical executable with the new ICO, and a wrong expected ICO directory (payloads unchanged, first width altered). Separate fixture files were used; canonical assets/binary were not mutated.
- Existing pinned-dispatcher ledger remains exact27: 25 advertised handlers, intentional remote-policy denial and missing PDF handler. No full semantic-equivalence claim.

**Not implemented / not verified:** native desktop GUI window, window/taskbar identity and tray-menu lifecycle; no such program currently exists. Future GUI code can reuse `ferroc::icons` and the PNG sizes but must explicitly wire and test its framework surfaces. Browser favicon byte-serving/HTML linkage were verified; an actual browser rendering/cache session was not run. Public BRC transfer provider, public TLS/SaaS, production load and native Linux/macOS execution remain outside these results.

## Diagnostics, historical evidence and cleanup

The first alpha-cleanup check at threshold250 failed before writing canonical outputs: the actual top-left pixel measured RGB(247,247,251), not pure white. Threshold245 cleared only edge-connected near-white matte; corners and plausible visible area are checked before writing. The ivory tile and colored emblem remain opaque. All outputs reproduced after the fix.

Git warned about generated JSON CRLF normalization. The generator now writes explicit UTF-8/LF metadata, existing provider provenance was normalized without changing data, and source audit reran cleanly. Historical source reconstruction separately emitted notices about whitespace already present in immutable upstream reference snapshots; their exact original bytes/hashes were preserved rather than editing canonical source evidence. No current code/format/resource gate failure is waived.

The old default-on hash `6a4e911229ed64fc4d38d348e4e48b54af3980fed20aa06665a9887cffdfe8fa` is historical, not this build. Its binary, original source reconstructed from the old patch, native harness and every referenced transfer-evidence file were hash-checked and preserved under `artifacts/before-bright-icon/`. Original receipt paths refer to the historical execution; reconstructed source is under `source/` and copied evidence under `evidence/`. The old hand-drawn dark artwork is retained separately in `assets/branding/legacy-dark/`.

Agnes received only the icon prompt and authorized API request; its generated image was intentionally downloaded. No project source or private file was sent for generation, and no BRC tmpfiles-provider transfer was attempted. No registry/service/user configuration was changed; all test relay/agent processes and temporary test directories are cleaned by their harnesses. A final `verify-provenance.ps1` gates current source/binary/receipts/resource/log hashes and process cleanup.

Custom `-Source` provenance was also checked using a byte-identical local fixture: the manifest records the actually selected path, then a `finally` conversion restores the canonical source. All twelve artwork hashes and the release hash remained unchanged; `source-parameter-probe.json` records this.

Initial advisor was on track; its duplicate-generation warning did not match the task evidence: one job generated the image and a different job ran the advisor. No second image-generation job was submitted. Final advisor returned **Not done yet for the full rewrite**, which is accepted: PDF/services/deep compatibility are still incomplete. Its assertions that no tests were recorded and two verification jobs were still running conflict with terminal tasks `d459d602-95b1-4dcc-ab25-21f6983f9623` and `0ac2036a-9241-4568-a055-5e2fd690f6d8` and the successful named logs/receipts above. The 27-handler versionable matrix already exists at `docs/PARITY.md`. The full rewrite is NOT signed off; this report closes only the icon increment. `artifacts/bright-icon/final-advisor.json` preserves the response; it is not an independent code/security approval.

## Reproduction and receipts

See `assets/README.md` for offline asset conversion. From the repository root:

```powershell
./scripts/verify.ps1 -Release
$env:FERROC_TEST_BINARY=(Resolve-Path ./target/release/ferroc.exe).Path
try { cargo test --locked --all-features --test native_relay --test transfer_defaults -- --nocapture }
finally { Remove-Item Env:FERROC_TEST_BINARY }
node scripts/upstream-e2e.mjs E:/inter/Documents/Repos/better-remote-commander ./target/release/ferroc.exe
./scripts/audit-source.ps1
./scripts/verify-provenance.ps1
```

These are representative build/probe commands, not a self-contained script that refreshes every JSON receipt. Rebuilding produces a new binary identity if build tooling changes; regenerate receipts rather than assigning an earlier hash. Primary local artifacts: `bright-icon/full-verification.log`, `bright-icon/original-node-oracle.log`, `native-release-roundtrip.{log,json}`, `bright-icon/upstream-e2e.log`, `upstream-e2e.json`, `windows-resources-release.json`, `bright-icon/resource-negative-controls.json`, `bright-icon/windows-icon-extraction.json`, `transfer-verification.json`, `build-provenance.json` and the parsed/reverse-checked whole-addition `review.patch`.
