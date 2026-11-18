# Native setup /ws routing — verification scope

See [contract](../design/fleet-setup-ws.md). This increment is explicitly optional
via `router_with_setup` / `router_with_fleet`, NOT an operational file-transfer
endpoint. CLI setup-only verification and current limitations are recorded in
[agent verification](windows-fleet-setup-agent.md).

## Tests and provenance

- Eight initial broker cases cover3phase state, exact offer/response digest,
  wrong role/generation, malformed/repeated phase, immutable30s deadline,
  disconnect/queued invalidation, per-device/global/history bounds and reapproval
  of an exact job with new binding. Full counts belong only to actual raw logs.
- Three adapter cases include real TCP/WebSocket forwarding, duplicate/replayed
  binding refusal, connection replacement without delivering to the replacement,
  Store pause, default router, unknown version, query and unnegotiated client
  rejection. Strict outer envelope is separately tested for unknown/duplicate
  fields and wrong phase. A synthetic full queue isolates fail-fast enqueue.
- A fourth adapter case additionally uses random identities/random wrapping keys
  and real3phase signatures across loopbackTCP/WS, followed by LOCAL leasedAEAD
  buffer readback. Both stores are still controlled by one parent process with
  explicit synthetic approved time; DATA does not use the control socket, no
  receiver/stage is allocated, target directory remains empty. It passed1/1
  before strict lint rejected consecutive-if formatting and explicit Drop on a
  non-Drop key type. Binary/log/seven-source snapshot retained separately under
  rejected-lint-4; not a full acceptance. Corrected lexical scope/formatting,
  without disabling lints or changing crypto/deadline semantics.
- Origin/duplicateAuthorization guards are statically inspected, not a live
  malformed-header matrix in this round.
- The other public-routing fixtures use INVALID PUBLIC signatures; no private peer proof,
  stage/receiver, content or final receipt is inferred. There is no new
  three-process/two-machine/scale/file-path acceptance.
- First compilation rejected because a test local `server` JoinHandle shadowed
  the fixture's `server` function. E0277 unsized-str errors were cascading, not
  a Rust/network API defect. Seven affected source files+raw compiler log are
  preserved under `artifacts/fleet-p1/setup-ws/rejected-compile-1/`; no binary
  existed. Renamed the helper, without changing deadlines/assertions/protocol.

- Second targeted run compiled but rejected29pass/2fail BEFORE any socket:
  the fixture passed an `http://` URL to `Network::websocket`, which explicitly
  requires `ws://`/`wss://`. Raw log, actual failed EXE+SHA and seven affected
  source files are separately archived. The fixture now uses the real existing
  `transport::websocket_url`; product URL/TLS policy is unchanged. Observation
  timeout is also made an explicit panic rather than disguised as peer close;
  no negative case may pass just because5s elapsed with no message.

Earlier `setup-handshake-regression-20261115-165355` remains accepted for its
OWN247input freeze:756all(serial)/63default/95docs,Node3/CI13. Independent postcheck
completed BEFORE new source changes; source/archive/raw logs/actual executables
and old production hashes matched. Do not rerun that old current-tree check
against this intentional new delta and misclassify the expected drift.

Current routing acceptance needs its OWN new exact source delta, raw logs,
executable mappings, fmt/clippy/default checks and full regression receipt.

## §4183 — targeted acceptance, full freeze pending

`targeted-5.log`:32passed (19existing crypto,8new broker,4new adapter,1existing
worker fixture),12new NOT32new. Random-identity signed WS exchange +LOCALleased
AEAD passed. Strictclippy/alltargets/allfeatures and defaultcheck passed. Limited
seven-affected-source/actualEXE snapshot is NOT a full linked-source freeze.

New exact7source+6docs audit against prior247inputs; fullfreeze must independently
enumerate768all/37ignored SERIAL,63default/2ignored normal,95docs,Node3/CI13.
No1GiB results borrowed; unchanged pump/oldwire/standardhello does not certify a
new control path. No stockagentbackend/fourtools/independentagent/filedeployment.

Historical parallel settlement2278.5795ms and reserve_commit2929ms remain open.
No Advisor, production service change, commit or push.
