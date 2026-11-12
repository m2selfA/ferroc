# Full BRC -> ferroc parity ledger

Pinned upstream dispatcher has 27 handlers. Status is semantic parity, not name count.

| Upstream handler | Rust implementation | Current tests / gap |
|---|---|---|
| get_config | runtime::dispatch / Policy::describe | core::shell_and_remote_policy_mutation_denied_by_default; subset only |
| set_config_value | explicitly denied, not advertised | core::shell_and_remote_policy_mutation_denied_by_default; intentional security divergence |
| get_usage_stats | runtime::dispatch | memory-only subset; dedicated test pending |
| get_recent_tool_calls | runtime::dispatch | maxResults/toolName only, since rejected; dedicated test pending |
| start_process | Processes::start | core process lifecycle + process_io stdin/output cap + canonical OAuth/MCP integration |
| read_process_output | Processes::read | core::process_pagination_does_not_drop_unread_lines |
| interact_with_process | Processes::interact | process_io::stdin_roundtrip_and_output_cap |
| force_terminate | Processes::kill | core::process_lifecycle_observation_is_not_kill_timeout |
| list_sessions | Processes::list | owned-only subset; dedicated test pending |
| list_processes | Processes::list | owned-only subset, not all OS processes; dedicated test pending |
| kill_process | Processes::kill | arbitrary-PID rejection covered; owned-positive dedicated test pending |
| read_file | files::call | core files/multi/size/policy + native stdio + real original relay |
| read_multiple_files | files::call | core::directory_move_and_multi_read |
| write_file | files::call | core roundtrip + native stdio + original relay |
| write_pdf | absent | pending |
| create_directory | files::call | core::directory_move_and_multi_read |
| list_directory | files::call | core::directory_move_and_multi_read |
| move_file | files::call | core move/overwrite-refusal tests |
| prepare_file_transfer | transfer::Transfers | default-on/local --no-transfers disable, SPKI format, TTL 60..7200s, 128 keys, expiry/shutdown, original Node interop |
| send_file_transfer | transfer::Transfers | actual bounded HTTP multipart fixture + original Node decrypt; source policy/size/low-order-key refusal; actual tmpfiles.org unverified |
| receive_file_transfer | transfer::Transfers | actual Node ciphertext -> HTTP fixture -> verified atomic Rust file commit; tags/hash/size/default-no-overwrite, one-use, failure retention, cancellation/commit; external provider unverified |
| get_file_info | files::call | core::directory_move_and_multi_read; metadata subset |
| edit_block | files::call | exact-match/count/no-mutation/concurrent tests; no rich documents/fuzzy edits |
| start_search | Searches::start | literal/hidden/glob/limit tests + real original relay |
| get_more_search_results | Searches::results | pagination/truncation tests |
| stop_search | Searches::stop | cooperative cancellation test |
| list_searches | Searches::list | dedicated test pending |

| Platform surface | Implementation / evidence |
|---|---|
| Pair start/poll/private credentials | transport::pair; fixture approval/denial + real original relay approval |
| WS auth/hello/call/result/heartbeat | transport::session; loopback fixtures + real original relay |
| Revocation | Both original and native relay admin deletion stop the actual release agent; client deletion invalidates native MCP credentials |
| Reconnect/backoff | code present, dedicated transport reconnection test pending |
| Malformed message/overload/deadline | parser/code present; additional adversarial tests pending |
| MCP stdio | Mcp::handle/serve; actual binary fixture roundtrip |
| Rust relay / SQLite device store | Native axum/rusqlite preview; actual relay+agent process E2E, store persistence + eight-thread one-shot consumption; no Node DB migration |
| Native OAuth DCR / PKCE / code / refresh / revoke / metadata | Native release roundtrip incl. invalid verifier/token, code replay, refresh replay and revocation; external SaaS integration pending |
| Native remote MCP endpoint and multi-device routing | JSON POST endpoint, 25 agent handlers + relay list_devices; 22 core successes, transfer prepare success and send/receive invalid-input routes verified. Positive transfer provider IO is source-profile fixture evidence. Multi-device conflict/reconnect has static implementation, not live-verified |
| Native browser admin / login / pair approval / device pause/rename/delete / audit / client revoke | Implemented server-rendered single-admin UI; HTTP form flow + Origin/CSRF failures tested. No interactive browser visual QA or multi-user parity |
| Shared Agnes bright icon | Windows PE7 payload/group mappings and file-icon extraction verified; existing browser favicon HTTP bytes/HTML links verified; optional Windows GUI uses the same embedded/window/tray assets; native resident minimize/reopen/exit fixture and release PE7 mapping verified. Actual Shell tooltip mouse/copy-path acceptance pending; see [GUI verification](verification/windows-gui-preview.md) |
| Service install/uninstall | pending |
| Linux/macOS native execution | CI configured, not executed locally |

Native E2E now executes every advertised agent handler; earlier “dedicated test pending” entries refer to deeper isolated semantic tests, not absence of a native route invocation. There are now 25 implemented of 27 upstream handlers: 1 intentionally denied remote policy mutation and 1 unimplemented write_pdf handler. Rich read/write/edit semantics, services and deeper relay behavior remain incomplete; handler count is not semantic-equivalence proof. Transfer success is fixture/interop evidence, not a live public-provider claim.

This ledger must remain explicit about intentional restrictions versus unimplemented features. No agent-only preview is a full-rewrite completion claim.
