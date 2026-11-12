# Windows agent/core preview verification (historical)

This receipt belongs ONLY to the original agent-only binary below. Current native relay evidence: [windows-native-preview.md](windows-native-preview.md).

This verifies the initial native Rust agent/core vertical slice, NOT completion of the full BRC rewrite.

## Build identity

- Rust/Cargo 1.98.1, x86_64-pc-windows-msvc.
- Binary: `target/release/ferroc.exe`, version 0.1.0.
- SHA-256: `52772fb1a47ad3aac333c41c8a3437f32c602634e8519454498cc525039e138e`.
- Source-file hash map: `artifacts/agent-only/build-provenance.json`; source is uncommitted, no commit-to-binary claim.
- Windows PE resources: product/description/version verified, seven icon payloads (16/24/32/48/64/128/256) compared byte-for-byte by SHA-256 to source ICO.
- Negative control: changed one byte of an icon payload in a SEPARATE artifact copy; resource verifier rejected it. Canonical binary SHA-256 unchanged.

## Executed checks

- `scripts/verify.ps1 -Release`: fmt, clippy with warnings denied, 29 tests (18 core + 2 process I/O + 8 transports + 1 Windows path), release build, PE resource verification.
- `scripts/audit-source.ps1`: complete whole-addition patch for unborn Git baseline; parsed stat + reverse application dry-run. No staging, commits or worktree reset.
- GitHub MCP reference snapshots independently compared to pinned upstream Git blob IDs; all five match exactly. See `docs/UPSTREAM.md`.
- Native binary stdio write/read roundtrip; stdin process interaction; process wait vs kill distinction; pagination no-loss regression; bounded output; invalid optional types fail without side effects.
- WebSocket fixture tests: auth header, hello shape, heartbeat during slow call, duplicate-ID refusal without replay, protocol mismatch/pre-welcome call refusal, 401 fail-closed.
- Pairing fixture tests: approval/private credentials and denial/no saved secret.

## Canonical upstream interoperability

`node scripts/upstream-e2e.mjs E:/inter/Documents/Repos/better-remote-commander ./target/release/ferroc.exe`

Separate upstream checkout: commit `cbe511702dd0147650353c29ac6ab1decd8afda1`, tracked source clean. Shared + relay built with its frozen pnpm 11.24.0 lockfile (dependency lifecycle scripts disabled). Node v24.15.0.

- Real upstream device pairing and token-authenticated Rust WS hello.
- File write/edit/read and content search through unmodified upstream DeviceHub.
- Outside-root remote file access rejected.
- Canonical unmodified 14-check OAuth/MCP suite passed: discovery, DCR, PKCE, browser-session login/consent, code/token exchange, MCP initialization/listing/device routing/start_process, invalid-token refusal and refresh rotation.
- Upstream admin revoke stops Rust agent without silent re-pairing.
- Scratch DB and test pairing credentials removed; test agent and relay stopped. No persistent service added.

`artifacts/agent-only/upstream-e2e.json` binds the observed integration receipt to the same release SHA-256. The Node program is only a test driver/reference relay, not a ferroc runtime dependency.

## Not verified / not implemented

Rust relay/SQLite/OAuth/dashboard, rich documents, encrypted transfer and autostart installer are pending. No public TLS or actual claude.ai/chatgpt.com session was used. Linux/macOS paths have CI configuration but no executed native evidence in this session. File policy is not an adversarial sandbox, and process-tree cleanup is best effort (no Windows Job Object).

## Review state

Advisor returned **Not done yet**: agent compatibility is not the requested full rewrite. The reviewer could not read the external ferroc path due to its current-project boundary (host cwd is the WIP directory), so this is a scope/evidence review, not a direct code audit. Full rewrite remains in progress; no independent security approval is claimed.
