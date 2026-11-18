# GUI fleet peer — explicit local approvals

The Windows preview can use the existing fleet setup and DATA path on its own
Runtime. It adds no relay service, protocol, grant authority or unprotected key
storage. Default builds remain unchanged.

## Use

```powershell
cargo build --locked --release --features gui,fleet-core --bin ferroc-gui
.\target\release\ferroc-gui.exe --allow-dir E:\work --relay https://relay.example --home E:\ferroc-home --fleet-setup E:\config\approved.json --start
```

The approval file is the same v2 local contract used by the stock agent. Pair the
selected home first and enroll identities/peer fingerprints/endpoints explicitly.
With `transfer.mcp:true`, the GUI's authenticated loopback HTTP MCP exposes
`send_file`, `sync_dir`, `transfer_get`, `transfer_cancel` for preapproved rounds.
Without that flag it follows the existing automatic transfer setting. `sync_dir`
is still a sequential approved-round batch, not remote directory diff/apply.

`FERROC_FLEET_SETUP` is an optional local environment setting. The switch exists
only with `fleet-core`. No relay or `--no-transfers` makes the configured start
fail. A bad approval fails before its relay WS session, without falling back to
an unconfigured agent. Local HTTP MCP can remain available for the other tools.

## Lifetime and display

The GUI resolves the real device credentials, loads the provision once for that
controller start, and shares that same Arc with the local MCP attachment and the
observed relay session. Reconnect uses this same approval; it does not reload the
file, shift authorization time, or obtain authority from relay messages. Changed
settings take effect after stop/start.

The existing resident status pump displays bounded counts from that Runtime's
retained local MCP source tasks: pending, peer-reported completed, interrupted,
failed. Counts are historical task observations, not throughput, remote cleanup,
target automatic-pump progress, or proof of current disk bytes. HTTP pause still
pauses local HTTP requests; it does not cancel already admitted fleet work or
pause relay auto-transfers. Stop/quit closes HTTP admission and signals/drains the
same transport and Runtime. No second task registry or worker service exists.

## Verification

`src/gui_service_tests.rs` checks both start guards before listener/network setup.
`src/fleet/gui_peer_tests.rs` uses two independently DPAPI-protected identities,
real authenticated controller HTTP MCP, relay control WS and DATA sockets in one
test process. It checks all four tools, 131073-byte cross-chunk transmission,
matching source authenticated observation and target SQLite receipt, target file
bytes, Completed/no live stage, late cancellation refusal, task counts, listener
shutdown, token rotation and no stale tools/counts after restart without fleet.
A separate bad-config probe requires no relay connection, no fleet tools/tasks,
no acceptance of send_file and no config-path leakage in the GUI snapshot.

The feature matrix includes gui-only all-target checks and strict clippy; the
fleet config switch/fixture fields are gated accordingly. The default transport
unit placeholder that failed no-fleet strict clippy was corrected as part of
this increment. Exact executed results, inputs and binary hashes belong to the
local GUI increment receipt, not the older 314-input freeze.

## Executed evidence (2026-11-18)

The 317-input source archive in `artifacts/fleet-p1/gui-fleet-regression-20261118-003014`
has a composite verification and an independent postcheck: Windows all-features
873 passed / 0 failed / 37 ignored, default 63/0/2, docs 97/0/0; gui-only tests
2/0/1; strict clippy for both feature combinations, fmt, three Node oracles and
13 CI checks. The existing offscreen resident lifecycle probe also passed. The
first Windows runner is still rejected: its setup oracle invocation omitted the
Rust-export input file. The supplement exports from the archived test binary and
runs the oracle with that input; it does not relabel the rejected invocation.

Linux ran the same 317 inputs: all-features 768/0/24, default 62/0/2 and docs
93/0/0, with system fmt/clippy. Its first formatter-dispatch rejection and second
runner's 900-second SSH/BrokenPipe truncation are retained. Completed test logs
and a separate docs/hash supplement form its composite acceptance. The Linux
evidence archive is `artifacts/fleet-p1/gui-fleet-integration/linux-composite-evidence.tar.gz`.
These are tests of the archived inputs; this later report update is a separate
documentation delta, not a rerun of the entire updated tree.

The archived Windows GUI image is SHA-256
`b8943cc408387b8d68c91ebb31f61f0425857a844cb928bd6f6e42842a536df8`.
Independent GUI-source/CLI-target/relay processes passed 3 B, 131073 B and 8 MiB;
CLI-source/GUI-target/relay processes passed 8 MiB. Each round has separate homes,
identities, database and logs. Original completion events, full receipts, SQL,
file SHA and the actual process image are checked. Source and target receipts
match field for field, SQL is Completed with no live stage, and private parent
creation and file ACLs are checked. Programmatic Win32 mouse messages invoke the
same window's Exit button and the GUI exits normally. See
`artifacts/fleet-p1/gui-process-20261118/independent-postcheck.json`.

Native Copy-MCP-config/HTTP MCP passed in `mcp-131073-03`: programmatic window
button input copies the actual config, initializes authenticated HTTP MCP, checks
all four tools, calls send_file/transfer_get, verifies the complete source/SQL
receipt and file SHA, and confirms late cancel is false. Exit closes the HTTP
listener. The round captures all original clipboard formats and verifies their
bytes after restoring them; no clipboard contents or bearer token enter logs.
Independent audit re-reads the original completion logs and SQLite/file/image
state, with seven mutation controls rejected and original evidence unchanged.

Rejected fixture rounds remain separate. The first OLE Python helper crashed
with 0xc000041d; the pre-crash clipboard restoration cannot be certified. A
replacement Win32 snapshot/restore control passed; a subsequent early-copy round
restored its baseline but copied before HTTP readiness and was rejected. The
passing round waits for the HTTP listener. A later native pause/restart attempt
refused BEFORE clipboard alteration because GetClipboardData could not retrieve
an enumerated Unicode format; native pause/restart remains unverified, despite
the passing controller-level stop/restart tests. Fixture ACL failures are also
retained: explicit DACL setup plus per-object checks were needed. Product ACL
checks were not relaxed.

Manual tray/mouse acceptance, two-host GUI acceptance, durable restart/resume,
QUIC/NAT and production qualification remain open. Programmatic messages are not
human mouse acceptance. No restart/resume or QUIC/NAT capability is added.
