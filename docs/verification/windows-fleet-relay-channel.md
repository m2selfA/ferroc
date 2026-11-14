# Windows P1 same-relay channel candidate

## Result and scope

**Current frozen recheck passed, with an unresolved earlier parallel timing failure.** This increment adds an explicit library-only same-relay channel and real Source/Target IO pump. It is not a production `send_file`/`sync_dir`, deployed agent/registration flow, Linux qualification or two-host acceptance. No Advisor was consulted; no commit/push/tag or new service was made.

Stock router and production CLI/GUI remain unchanged/default-off. Explicit `Relay::router_with_fleet` mounts `/fleet/ws` on the SAME Relay/listener/Store/security middleware. Existing device Bearer plus one-use, exact grant/role-bound header ticket are both required. Local routing approval is not trusted grant issuance, pin import, trusted time or filesystem authority. See the [channel contract](../design/fleet-relay-channel.md).

## Implemented boundaries

- `relay_channel.rs`: exact native headers, current tokenHash/pause/revoke, lifetime spent-digest history,16 active pairs/32 admitted sockets/8-message lanes, positive monotonic TTL at most300s, frame/message/write-buffer caps; opaque E2E records, not peer disk attestation. Checks do not atomically cancel already queued/in-flight effects.
- `relay_io.rs`: existing Network proxy/TLS connector; bounded SourceWindow plus ONE send-copy. Receiving controls never restarts a partially polled send; after8 controls it polls that SAME future first and yields, preserving timer progress. READY/progress ACK is not final completion.
- Windows Target: real HostReceiver→seal→prepare→original-handle rename→observation→v9 settlement→cached final ACK. ACK delivery can fail after local settlement; that error does not undo v9 or delete the target. Disconnect before completion keeps stage/debt. All owners must drop before host.close.
- No reconnect/resume/flow renewal; initial-epoch grant limits remain. Arbitrary long/1GiB transfers are not qualified by this short-grant8MiB experiment.

## Current frozen verification

Evidence: `artifacts/fleet-p1/relay-20261113-205131/` (local, ignored).

| Verification | Observed |
| --- | --- |
| frozen inputs and raw copies |93 unique paths |
| fmt and strict all-target/all-feature clippy | passed |
| original-flags all-feature/all-target recheck |564 passed |
| default all-target |62 passed |
| API/documentation tests |81 passed |
| release fleet components |502 passed |
| exact release channel normal tests |16 passed,2 explicit worker/controller helpers ignored |
| explicit three-process controller |1 passed /4 file sizes |
| Node/OpenSSL deterministic oracles |suite1 and suite2 passed |
| CI validator |13 passed; workflows/ABI scripts unchanged |

The16 channel tests cover default404, wrong device/single-use/reapproval, opaque AEAD contrast, revoke/pause/TTL, actual0/1/cross-chunk/8MiB transfers; exact header rejection, server-side binding/direction/oversize rejection,16/64 caps, real duplex blocked-send deadline with always-ready controls and exactly one send invocation, post-one-ACK disconnect retaining65536B stage plus full131073B/one-slot debt and no target, and real HTTP proxy forward/407-no-direct-fallback/credential-redaction contrasts. Proxy coverage here is HTTP, not a new full TLS/SOCKS matrix. The blocked-send contrast exercises the actual shared selection helper with a real bounded duplex writer; it is NOT an equivalent native TCP/WebSocket congestion experiment. Real WS/TCP queue saturation/slow-peer deadlines remain a next verification increment.

## Actual three OS processes

Each dataset uses separate native Relay, Source and Target TEST processes, distinct PIDs, per-role raw stdout/stderr, actual source and target bytes, Target receipt vs Source observation, and original process exit confirmation before fixture recycling. They use PUBLIC cfg(test) keys and explicit synthetic trusted-time fixtures, not operator provisioning or production credentials.

| Bytes | Controller interval, ms |
| --- | --- |
|0 |662 |
|1 |801 |
|131073 |1309 |
|8388608 |3622 |

These are loopback intervals including readiness/peer startup, not pure network throughput or two-host numbers. Actual frozen TEST SHA256:

`b0bf1e2e8f1cb174ec5cec5116aa03358baf807330aaa8334dee9173ca9890d9`

`three-process-frozen/bytes-*/` preserves per-role logs, receipts and provenance. Initial d9a6 three-process success has its own earlier source/exe snapshot; it is NOT the current frozen b0bf test. Previous427e window-only TEST also remains separately archived. None is a rebuilt production CLI/GUI.

## Unclosed timing finding: do not erase a failure with a recheck

First original-flags parallel `all-features.log` FAILED at `commit_admission_tests.rs:571`: the entire `reserve_commit` call measured **2.9294087s**, exceeding the existing2s negative gate. Earlier assertions had already observed the expected `database is locked` error and restored timeout5000. The measurement includes hashing/file validation/sync and SQL, so it does NOT establish2.929s spent in SQLite busy waiting.

- Frozen failed DEBUG TEST SHA: `a474aa6b64dc1b74d792cd7b572fc75783b0a0376841591253fefc3ae15ddd79`; raw source93, first log and verifier v1 retained.
- Same DEBUG executable, original exact test at idle: passed,0.18s test interval /390ms parent interval.
- Same DEBUG executable with8 exact default-router/KDF processes confirmed CPU-active first: SQL test passed,525ms whole-parent interval; every original load/SQL process exited and was waited. **This does not support attributing the first failure to KDF contention.**
- Exactly ONE same-source/original-flags parallel recheck was run, with separate `all-features-recheck.log`; it and remaining suites passed. No product code, original2s/5s windows or parallel flags were changed.

Root phase is **not established or fixed**; todo66 stays pending, separate from earlier process-output/deadline todo54. Recheck success is current regression evidence, not proof of historical root-cause closure. Do not claim an entirely failure-free run or production readiness.

## Provenance and remaining work

`source-delta.json/.diff` verifies exactly3 modified existing Rust files (`relay.rs`, `network.rs`, `fleet/mod.rs`) plus5 new channel/IO/test modules against the preceding window increment. Actual Runtime, SourceWindow, Host, wire/crypto, lease and journal source bytes remain unchanged. Older schema probes remain historical evidence, not newly executed probes for this no-schema-change increment.

`verification.json` binds current test/log hashes and93 frozen inputs; `post-run-recheck.json` independently checks current/raw inputs, old427e and firstd9a6 archives, current executable, every role log/receipt/PID, source delta, oracles/CI and unchanged production artifacts. The postcheck must pass before final handoff.

Next original P1 work: controlled task entry with operational approved trust/progress/cancel, bounded renewal/failure delivery semantics, then real two-host validation. P2 filesystem scanning/apply and P3 QUIC/NAT remain later phases. Default tool surface, existing BRC `/ws`/BRCX1, old CLI/GUI hashes, protected identity and tag-only CI are preserved.
