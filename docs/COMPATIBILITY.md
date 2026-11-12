# Compatibility at pinned BRC revision

Source: shahidx0x/better-remote-commander @ cbe511702dd0147650353c29ac6ab1decd8afda1 (2.0.2).
README's 24-tool count is stale; dispatcher has 27 handlers. ferroc advertises 25 implemented tools (3 encrypted-transfer handlers are enabled by default; --no-transfers disables them).

| Surface | ferroc status / difference |
|---|---|
| hello/welcome/call/result/ping/pong/error | Native Rust protocol v1; actual upstream relay roundtrip verified on Windows loopback |
| Agent outbound proxy | One local policy for pairing, ws/wss and transfers; --proxy HTTP/HTTPS/SOCKS5/SOCKS5h, FERROC_PROXY, --no-proxy, standard proxy env/NO_PROXY; redacted startup/get_config status; optional extra CA, no PAC/WPAD/NTLM/Kerberos. Local fixture evidence is not public-deployment qualification. |
| Pairing | Native HTTP start/poll + private credential storage; manual browser approval; no browser launch, service installer, logout or automatic re-pair |
| MCP stdio | Native newline JSON-RPC; supports 2024-11-05, 2025-03-26, 2025-06-18; sequential calls, no cancellation/progress/resource/prompt APIs |
| Remote MCP / OAuth | Native Rust preview (axum/SQLite), JSON HTTP POST, DCR + PKCE S256 + code/refresh/revoke. Actual release relay+agent processes tested. Existing Node relay remains compatible; its canonical 14 checks are separate evidence. No SSE/session-resumption support. |
| Files: 8 tools | UTF-8/local text only, exact edits, metadata subset, bounded traversal; no Office/image/PDF/URL reads, no fuzzy matching; outputs are JSON in MCP text, not byte-for-byte BRC formatting |
| Processes: 7 tools | Pipes and owned sessions only; no PTY, prompt detection, node:local, arbitrary OS process enumeration/kill; stdout/stderr merged in arrival order, bounded output |
| Search: 4 tools | Rust regex/globset/walkdir background sessions with cooperative stop; no upstream ripgrep dependency; no automatic 5-min cleanup; conservative truncation explicitly reported |
| get_config | Immutable local policy info, no upstream client history/watcher |
| get_usage_stats, get_recent_tool_calls | Bounded memory metadata only; maxResults/toolName supported; since rejected explicitly, no persistent telemetry |
| set_config_value | Not registered; direct attempts fail; local CLI only to prevent remote privilege escalation |
| write_pdf | NOT implemented/advertised |
| prepare_file_transfer / send_file_transfer / receive_file_transfer | Native BRCX1 (X25519 SPKI, HKDF-SHA256, AES-256-GCM), enabled by default; --no-transfers disables them, --allow-transfers remains compatible. Fixed tmpfiles.org HTTPS; no redirects; one active transfer, 128 receive keys, 99 MB plaintext. Independent original-Node bidirectional fixtures verified; actual public-provider upload/download unverified and not attempted. |
| Rust relay/SQLite/OAuth/PKCE/DCR/dashboard/audit | Implemented preview: single-admin server-rendered UI, manual approval, pause/resume/rename/delete, OAuth client deletion and bounded metadata audit. Native temporary DB roundtrip verified; no Node DB/token migration or multi-user/tenant parity. |
| Packaging | Cargo binary, Windows PE metadata and Agnes bright 7-size icon, shared transparent PNGs and existing browser favicon; no GUI/tray/autostart/Docker/Scoop package/release signing |
| Platforms | Windows locally tested. Unix implementation and three-OS CI configuration exist but Linux/macOS execution unverified |

## Registered tools (25)

get_config, get_usage_stats, get_recent_tool_calls,
read_file, read_multiple_files, write_file, edit_block, create_directory, move_file, list_directory, get_file_info,
start_process, read_process_output, interact_with_process, force_terminate, kill_process, list_sessions, list_processes,
start_search, get_more_search_results, stop_search, list_searches,
prepare_file_transfer, send_file_transfer, receive_file_transfer.

## Evidence tiers

- static-confirmed: pinned upstream protocol/schemas/dispatcher and local Rust definitions; LICENSE/NOTICE attribution; architecture differences recorded.
- locally-verified: 54 default Rust tests + 1 separately invoked original-Node interoperability test; native release relay + agent OS-process roundtrip (22 core successes + transfer prepare success + send/receive negative routes), OAuth/admin/revocation and SQLite persistence/one-shot behavior; binary stdio and loopback fixtures. Separate unmodified upstream Node relay + Rust release agent interoperability and canonical 14-check OAuth/MCP suite.
- locally-verified transfer increment: original pinned Node functions (filesystem/provider mocked) <-> actual Rust handlers, empty/binary/1 MiB fixtures, 99 MB local crypto, exact HTTP failure causes and cancellation/commit boundaries. See verification/windows-transfer-preview.md for historical transfer evidence and verification/windows-agent-proxy.md for the current build/full-suite receipt.
- not verified: real tmpfiles.org service, 99 MB HTTP transfer, public native deployment/real SaaS connector sessions, native multi-device conflict/reconnect behavior, native Linux/macOS execution, hostile local filesystem race defense, production-scale load. Native redirects are deliberately restricted to HTTPS/loopback without query/fragment/credentials; no upstream equivalence claim.

Protocol compatibility is NOT complete behavioral or security equivalence to Desktop Commander/BRC.
