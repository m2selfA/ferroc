# Explicit DATA route admission candidate

## Boundary

This increment wires independent **routing** approval and one-shot tickets, not
agent DATA/file execution. Existing relay/listener/Store/Network/FleetRelay are
reused; no service, MCP tool, pin discovery or trusted-time service is added.
Default startup and setup-only still have no DATA route authority.

- `relay --fleet-setup --fleet-data-config <LOCAL FILE>` is explicit operator
  approval, read before listener/network startup. The trusted local configuration
  parent is not an OS sandbox; no remote frame can construct this authority.
- Strict version 1, 64KiB actual read cap (including post-stat file growth), 1..16
  approvals. Each has `sourceDeviceId`, `targetDeviceId`, `profile: singleOwner`,
  `ttlMs: 1..300000`, and `round`: the SAME source-side round object used in the
  agent config. The shared Rust materializer derives the canonical grant; there
  is no script-reimplemented hash or new signature format. Nil/duplicate id,
  grant or job, wrong device/role/profile/chunk/version/unknown field reject all.
- Agent config v2 `dataRoutes: true` requires its existing separate local clock
  approval. Before network, selected approved peer endpoint must equal the
  connection origin (no hidden fallback/path/relay substitution). Absent flag
  preserves previous hello and setup-only behavior.
- Only an original live `SetupLease` can issue its single route request. Request
  contains round id and exact grant digest, NOT sender identity, paths, grant,
  token, permission or clock. `fleetDataProtocol: 1` and setup protocol 1 must
  both be negotiated. Roles/generations come only from authenticated sockets.
- Both roles must separately present; one role, same-role duplicate, unknown id,
  foreign actor or wrong digest cannot mint tickets. The relay compares its OWN
  locally approved grant. A presentation is an endpoint declaration, NOT proof
  that its private lease/time/path/IO is valid. End-to-end checks remain required.
- First presentation starts a fixed 30s pairing window; both then mint exactly
  one source and one target header ticket via existing `approve_local`. Routing
  TTL is independent of the E2E lease. No retries, rotation scheduling, reconnect
  reconstruction or replay-history eviction; capacity is fixed, including spent.
- Queue and actual write recheck both current generations, negotiated scope,
  token row/device tokenHash, pause/revocation. Unavailable negotiation has public
  code `FLEET_DATA_UNAVAILABLE`; presentation rejection is `FLEET_DATA_REJECTED`,
  without echoing remote payload/secret/path. Fatal presentation closes matching
  routes BEFORE awaiting the bounded error write. Failure/disconnect invalidates this
  route and unused tickets without debt changes. Original approval digest—not a
  potentially renewed current binding—identifies the route to close.
- Agent accepts only its requested id/digest and a single 64hex ticket, rechecking
  current Runtime, peer/pin/endpoint and effect lease. Secret stays in the SAME
  noncloneable owner and is cleared on close/disconnect. No ticket in logs.
  Ordinary JSON/socket buffers can hold transient copies; this is not a universal
  RAM-erasure guarantee. Expired ACK/state observation remains allowed.

The agent does NOT consume this ticket into `FleetLink`/`SourceFile`/`HostReceiver`
yet. It creates no target file, stage, SQLite journal or file grant. Native
routing-only probes can open `/fleet/ws` with received tickets; that is a socket
claim, not DATA/AEAD/IO completion. Four MCP tools, directory apply, restart
resume, QUIC/NAT, production signing/time and two-machine rollout remain open.

## Evidence and failure hygiene

- Local configuration/ledger tests cover two presenters, exact grant, foreign
  role isolation, unknown id, duplicates, fixed expiry, generation disconnect,
  consumed approvals, write-failure invalidation and bounded schema.
- Original-owner tests cover wrong/no request, id/digest/format/replay, expiry,
  peer revocation and close. Real native WS tests use the actual router and
  device-token path; wrong-device tickets and replay reject. A separate unused
  target-ticket test observes A's actual waiting DATA socket close before B's
  first claim, avoiding the false positive of testing an already-spent ticket.
- Routing-only fixtures have explicitly INVALID signatures; they are not E2E
  lease proofs. Real independently signed setup is separate, and the actual CLI
  three-process probe uses distinct encrypted identity stores and only each
  process's own private key. It must report both original owners holding their
  own ticket, empty target and owner release on disconnect.
- First directed run rejected 58/59: new positive config fixture issued at now
  conflicted with its +/-100ms approved interval. Product correctly refused;
  fixture issuance/expiry moved 5s EARLIER (not a widened gate). Raw source/test
  EXE/log retained as `rejected-config-fixture`.
- Review exposed a defect in my new close-by-current-binding helper. Native
  component red test proved a rotated pair remained (1 instead of 0); original
  changed-file snapshots/test EXE/log archived (not a full red frozen source
  tree). Fix binds close to the initial approval digest.
  This is not a claim to fix historical renewal/SQL/final-ACK issues.

Directed/native/CLI/frozen acceptance is pending this source snapshot. Final
receipts under ignored `artifacts/fleet-p1/route-control-*` and the corresponding
freeze, NOT earlier setup/lease or 1GiB results, must bind exact source/binaries.
Existing parallel SQL timing and historical final-ACK delivery gaps remain open.
