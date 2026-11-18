# fleet setup: configured local backend (candidate)

Status: optional CLI setup-control candidate, locally verified with independent
relay/source/target processes. No DATA/MCP tool/file IO. The stock agent stays off.

## What it is

`fleet::setup_agent::SetupBackend` drives ONE locally pre-armed three-phase setup
round over a bounded frame channel. The explicit agent transport must:

1. call `Runtime::open_fleet_setup(device, capacity)` once per authenticated
   connection and keep the returned `SetupOutbox`;
2. arm each round with a LOCAL `LocalSetupApproval` (identity store, exact
   `ValidatedGrant`, exact peer fingerprint/slot/profile, local authority-time
   closure);
3. feed only THIS connection's `fleetSetup` frames to `receive_if_setup`;
4. write each `SetupEmission` after `wire_frame()`, then call
   `report_written()` — or drop it to fail the round.

Nothing in the wire frame supplies a grant, fingerprint, profile or time.

## Bounds

| Bound | Value |
|---|---|
| active rounds | 1..=4 (constructor argument) |
| retained rounds | 64 per backend (spent ids/jobs/bindings) |
| inbound mailbox | 2 |
| outbound writer queue | 8 |
| round budget | 30 s fixed (test-only shorter) |
| write-report budget | 5 s |

A full history refuses new rounds instead of evicting spent identities. Job
digest, binding digest and round id are spent at admission and never reused.

## Failure semantics

- Cancel, shutdown, deadline, foreign/unknown sender rejection and mailbox
  exhaustion never restore a consumed round.
- A dropped emission, missing write report or binding/phase mismatch fails that
  round; no optimistic success.
- `PreparedLocally` means only that this process produced both proofs and a
  local `PreparedSetup`. It is not peer readiness, a lease install, a data
  channel or a publish permit. It does not allocate a stage or touch a target.
- `Runtime::shutdown` stops setup admission in the same cut as host/task
  admission, drains setup rounds before the host, and no new round can start
  afterwards.
- Errors are not exposed with paths/tokens; snapshots carry a closed enum.

## Explicit setup-to-lease opt-in

Config v2 may additionally contain:

```json
"leaseAuthority": { "kind": "singleOwnerSystemClock", "uncertaintyMs": 100 }
```

This is a LOCAL operator's decision to trust the host wall epoch to within the
stated bound (1..=2000 ms), not proof of NTP accuracy or a new time service.
It is permitted only with the independently selected SingleOwner profile.
Absent this field, behavior stays **PreparedLocally only**, with no fallback.
Unknown/peer clock kinds, zero uncertainty or extra time fields are rejected.
The initial interval must fit completely inside the fixed grant. Its sample is
captured once at config load and reused without shifting issuance/expiry on
connect, proof completion or reconnect; processing latency still counts.

On a prepared result, the configured transport consumes it through
`Runtime::authenticate_fleet_setup`. Expected role/grant/profile/pin must match;
local identity, peer approval, endpoint and local-role path are re-read under
registry -> fs_gate both before and after leased authentication. No other
machine's path is locally approved and no network message supplies authority.

`SetupLease` retains the original records privately (no Clone/serde/extraction),
with at most four owners per connection. Every record operation repeats Runtime,
policy/trust and clock checks before returning a frame/plaintext. Trust changes,
clock discontinuity or authenticated semantic faults close it irreversibly.
Unauthenticated corrupt frames do not poison healthy state. Mutation expiry
refuses DATA/effects but still permits the original ACK/status/cancel observation
rules; it neither renews nor resurrects authorization. Explicit close/Drop closes
all record rights. Runtime stop rejects the next idle-owner operation and that
operation closes it; stop does not wait for idle crypto owners or promise instant
erasure of externally held keys. Connection end drops its own owners before
retiring the setup backend. These records are NOT File/DB/publish/route tickets;
there is still no production DATA routing or file transfer.

## Explicit non-claims

- `agent --fleet-setup <FILE>` enables only the configured connection backend;
  `relay --fleet-setup` attaches a broker on the same `/ws` without mounting
  `/fleet/ws` or `/fleet/renew`. Both are absent from default-feature builds.
- Pair first, then create the identity using the assigned deviceId; approve the
  peer fingerprint and endpoint locally before creating either config. No TOFU.
- Config **v2** requires identical explicit authorizationId/keyEpoch/issuedAtMs,
  sessions/job/chunk/lease on both hosts. Loading validates the fixed grant;
  connect/reconnect never randomly reissues it or shifts its time. v1 is rejected.
- Wrapping-key environment values use the CLI's 64-hex encoding of 32 bytes.
- Source starts only after the target is locally armed. Results are observed
  during the live session. They remain historical local proofs, not DATA readiness.
- No operational enrollment, certificate pinning or trusted time service.
- No renewal, no DATA/frames, no stage/quota/receipt side effects.
- The original six backend tests remain same-process component evidence. The
  separate independent-process CLI probe verifies setup only; neither tier is
  a two-machine, production, leased-DATA or file-publication acceptance.
