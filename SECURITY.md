# ferroc security model (preview)

## Trust boundary

- Only control computers you own or are authorized to administer.
- CLI `agent` listens on no network port; it connects outbound to a trusted native ferroc or existing BRC relay. The optional Windows GUI explicitly adds an authenticated loopback-only HTTP MCP listener. The optional relay command is a separately selected role of the same binary, not a mandatory additional service.
- HTTPS required except loopback HTTP. Relay URL credentials/query/fragment are rejected. Pairing HTTP does not follow redirects.
- No telemetry, no persistent argument/output logs. History stores tool name/time/error only, bounded to 1000 entries. Process command strings remain in in-memory sessions and can be returned by list_sessions.
- Separate ~/.ferroc credentials: ACL restricted on Windows before writing secrets; Unix mode 0600. Existing credentials never overwritten. Revocation stops the agent; explicit pairing in another --home is required. No silent automatic re-pairing.

## Windows GUI HTTP MCP preview

- Uses published WindUI 0.32.0 and an in-process listener on an explicit loopback address only. Not an additional relay, public OAuth endpoint, or Windows service. CLI stdio remains separate.
- 256-bit random bearer per start, exact Host and optional Origin, duplicate security header rejection, negotiated per-session protocol versions. Credentials appear only on explicit Copy MCP configuration; clipboard is an OS/user trust boundary, not a secret vault. Stop/restart invalidates old tokens and sessions.
- JSON Streamable HTTP, not SSE: GET returns405. Sessions expire after30 minutes, maximum64; maximum4 admitted operations and16 body readers,5-second body deadline,1MiB message limit. Limits are preview controls, not production load qualification.
- Pause/close prevent new admission; already admitted operations can complete and mutate state even after client disconnect or session DELETE. Exit waits for those operations before Runtime shutdown; no rollback/exactly-once/hard cancellation claim.
- Resident host drives status/exit independently of window painting. Closing/minimizing destroys the replaceable UI window, not the controller; global input state persists on reopening. Native fixture verifies queued tooltip effects, not actual Shell tooltip text readback or end-user mouse behavior.

## Agent outbound proxies

- One local policy controls pairing HTTP, ws/wss and transfer provider requests. Agent --proxy overrides FERROC_PROXY; --no-proxy conflicts with --proxy and overrides all environment routing. Explicit routes ignore standard NO_PROXY and do not silently retry direct. Without either explicit option, reqwest standard HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY matching applies. NO_PROXY=* is explicitly corrected for IP targets in the locked connector. Environment status describes configuration, NOT proof that a particular request used a proxy.
- Accepted explicit proxy schemes: http, https, socks5 (local DNS), socks5h (remote DNS). Proxy failure does not disable certificate/hostname checks or trigger automatic re-pairing. Request redirects remain disabled. PAC/WPAD, NTLM/Kerberos and service installation are not implemented.
- Proxy credentials are not persisted in device.json, returned by get_config or included in ferroc connector diagnostics. Status exposes only scheme/host/port and whether authentication is configured. CLI arguments remain OS-visible; prefer a controlled FERROC_PROXY environment injection for credentials. Environment values and SDK memory are not encrypted secrets storage and may be visible to the same OS user/child processes; no credential-memory zeroization guarantee. HTTP and SOCKS5 authentication to the proxy is not encrypted by those protocols; use HTTPS proxy transport on an untrusted proxy hop.
- Native platform and bundled WebPKI roots remain enabled. Optional --ca-cert/FERROC_CA_CERT adds 1..32 PEM roots (max 1 MiB) to the client, for BOTH proxy TLS and relay/provider TLS. It does not modify the OS trust store or bypass hostname validation. Never load an untrusted CA bundle.
- WS proxy/TCP/TLS/HTTP-upgrade budget is 15s total; the 5s connector budget is inside it. There is no 15s lifetime on an upgraded connection. HTTP connect/request budgets and transfer commit semantics remain separate.

## File policy is NOT a sandbox

Absolute paths, component-aware containment, nearest existing ancestor canonicalization, no parent traversal, NTFS ADS/device namespace refusal, no directory symlink traversal in search/list.

These checks do NOT eliminate filesystem TOCTOU, hardlink aliases, mount/reparse races, or an adversarial local user changing the filesystem. Writes/edit/rename are not crash-atomic or rollback transactions. Directory policy is a convenience guard for a trusted operator, not an OS security boundary.

Shell is OFF by default. --allow-shell intentionally gives the authenticated remote caller arbitrary command execution as the OS user. allowedDirectories does NOT constrain shell file/network/process access. Use OS accounts/containers/ACLs for real isolation; do not expose to untrusted clients. Remote policy mutation is disabled.

## Bounded operations and deadline semantics

- UTF-8 text: at most 8 MiB/file, 8 MiB aggregate multi-read, 32 files/call. No URL/document parsers.
- Transport input/output limit: 1 MiB; request smaller pages for larger results. Oversized output reports that side effects may already have completed.
- WS: four concurrent calls, 128-byte IDs, 10000 unique IDs/connection; duplicate IDs disconnect rather than replay side effects. New connections do not promise exactly-once execution.
- Handshake 15s; welcome 15s; heartbeat 45s; sends 5s; reconnect 1..30s. Auth rejection/revocation/fatal errors stop instead of re-pairing.
- timeout_ms in process tools = bounded observation wait (0..30000ms), NOT process lifetime or cancellation. It returns a PID while the process may continue.
- WS timeoutMs = response observation deadline, not transaction cancellation. Admitted filesystem/spawn operations may still have effects after timeout/disconnect; inspect state before retrying. No hard rollback promise.
- Processes: 64 retained sessions, 1 MiB merged output/session with droppedBytes, stdin max 64 KiB with 5s write deadline. Pipes, no PTY/prompt detection. Root process exit and pipe EOF are different; output can arrive after running becomes false. Read again if needed.
- Process cleanup targets live owned roots and their process group/tree (taskkill /T on Windows, killpg on Unix), best effort. Detached children after parent exit are NOT guaranteed contained; Windows Job Objects are not implemented. Graceful shutdown cleans live owned processes; force-kill/crash is not guaranteed tree cleanup.
- Searches: 64 retained sessions, max 10000 matches, at most 512 KiB retained JSON/search with conservative per-file cutoff; line snippets truncate at 1024 characters. done/truncated/errors/skippedFiles are explicit. Hidden filtering is dot-name based, not Windows hidden attribute. Stop is cooperative, not instantaneous. Restart releases retained sessions.

## Encrypted transfer (enabled by default)

- All three BRCX1 tools are enabled by default at the operator request. Local `--no-transfers` disables them; `--allow-transfers` remains a compatible explicit enable and conflicts with disable. Startup and key preparation do not upload data; explicit send/receive calls may contact the third-party provider. Shell remains OFF by default and its opt-in is independent. Keys are scoped to one long-running agent/stdio process, NOT a persistent `ferroc call` session.
- Pinned upstream format: X25519 SPKI, HKDF-SHA256 (`brc-file-transfer-v1`), AES-256-GCM with `BRCX1:file` / `BRCX1:key` AAD. Low-order public keys, malformed lengths, unknown versions/providers and expired tokens fail closed. This does NOT authenticate sender identity. V1 metadata (including URL/expiry) is not itself AEAD-bound; receiver enforces host/expiry/size/hash policy independently. Synchronized clocks required.
- Upload/download only via HTTPS tmpfiles.org/www.tmpfiles.org on 443, no credentials/fragments, no redirect following. Provider learns ciphertext size/timing and retention/deletion is NOT guaranteed. No external provider was contacted in this verification. Test-only origin override is compiled out of normal binaries and cannot be enabled through CLI/env/RPC.
- 99,000,000-byte plaintext/ciphertext cap, one active transfer per runtime (busy fails fast), at most 128 receive keys, TTL 60..7200s, token cap 16 KiB, HTML cap 1 MiB, provider JSON cap 64 KiB. HTTP connect budget 5s, each request budget 30s; these are not end-to-end transaction deadlines. Full-buffer AEAD is bounded but may need a few hundred MB including buffer growth, and large-file CPU work runs off the async executor.
- Keys are in-memory only, zeroized on drop where supported, expired via weak-reference timers, and cleared at shutdown. No memory locking/swap/forensic-erasure guarantee. GCM/size/SHA-256 validation precedes plaintext staging, followed by shared filesystem-gate policy/expiry rechecks and same-directory tempfile persist. Default refuses existing targets; explicit overwrite uses replacement rather than deleting old data first. Local race/hardlink threats remain outside the convenience policy.
- Successful commit consumes the receive key INSIDE blocking commit, even if the observing future was cancelled. Failed validation/IO retains the unexpired key for retry. The transfer permit also survives a cancelled async observer while blocking work continues. No cancellation/rollback or exactly-once-after-process-crash guarantee; a timed-out upload might already exist at the provider without a returned token.
- Native HTTP fixtures, original Node interoperability and 99 MB local cryptographic roundtrip are separate evidence tiers. Loopback HTTP/HTTPS/SOCKS proxy behavior is fixture-verified separately; real provider HTTPS, WAN proxy operation and 99 MB HTTP transfer remain unverified; do not call fixture success production qualification.

## Native relay preview

- Optional `relay` role uses axum + bundled SQLite, one local admin account (`admin`), password from FERROC_ADMIN_PASSWORD (minimum 12 bytes). Recommended scrypt N=2^17/r=8/p=1; verification runs off the async executor and is serialized with an in-memory failure lockout (HTTP 429). No password/session migration or multi-user parity.
- Operate in an ACL-private directory: SQLite/WAL may hold device names, registration metadata and audit records. File ACL provisioning/encryption-at-rest is the operator's responsibility; bearer/code/refresh keys are SHA-256 indexed rather than stored raw. Actual fixture DB+WAL scanned for generated bearer/code material in the native integration test.
- Browser mutations require exact configured Origin plus session CSRF. MCP rejects a present mismatching Origin (HTTP 403) and invalid request IDs/parameter shapes (-32600); browser return paths reject control characters. HttpOnly/SameSite cookies, Secure on HTTPS, no-store, nosniff, frame denial and HTTPS HSTS. Serve externally ONLY behind a trusted existing HTTPS reverse proxy; no built-in TLS/forwarded-header auto-trust.
- Exact redirect registration, PKCE S256, one-use authorization codes, rotating one-use refresh tokens, client/device revocation. One-shot SQLite consumption and unique device insertion are atomic; the whole token-pair issuance/admin flow is not a crash-atomic transaction.
- Body/WS frame cap 1 MiB, pending call cap 256, send budget 5s and call observation budget 120s. Cancelling the HTTP future cleans its pending correlation entry, not admitted agent effects. Audit errors explicitly report that execution may have completed. Audit persists hashes/metadata, not raw tool arguments/output, with bounded retention.
- Pause blocks new calls, not already admitted work. Deletion revokes the stored token and requests live disconnect. No exactly-once semantics or hard transaction cancellation; no claim of complete overload/reconnect/race verification.
- Native MCP is JSON POST only; no SSE/GET streaming, protocol session-resumption or production load qualification. Do not expose this preview to untrusted public users.

## Remaining verification gaps

Native relay/OAuth/dashboard exist and have a Windows release-binary loopback roundtrip. Full BRC behavioral parity remains incomplete. Public TLS, real claude.ai/chatgpt.com sessions, reconnect under WAN faults, adversarial local races and Linux/macOS native behavior are not production-validated. This is a development preview, not a security-audited release.
