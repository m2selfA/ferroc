# Windows setup-to-lease candidate verification

## Scope and authority

This increment connects an actual prepared proof to a live, connection-owned
leased record session. It does NOT create a DATA route, File/receiver, stage,
journal record, receipt or four MCP transfer tools. The prior setup-only freeze
(781/63/95,259 inputs, EXE66601534...) is historical, not this increment's pass.

Optional config `leaseAuthority.kind=singleOwnerSystemClock` is an explicit
operator approval to trust this host epoch within `uncertaintyMs` (1..=2000).
It is SingleOwner-only, default absent, never inferred from grant/hello/peer.
No NTP check or synchronization service is implemented or claimed. The local
sample is captured once at load; process/crypto/setup delay counts against the
original grant. It cannot be used to refresh an expired interval on reconnect.

## Ownership and safety checks

- Runtime authentication consumes the original PreparedSetup/ephemeral and
  compares exact expected grant, profile, role, peer pin/endpoint. It re-reads
  encrypted local identity/peer/endpoint and local-role path under real
  registry -> fs_gate before and after crypto. No SQLite lock or payload-file IO is added.
- SetupLease holds private original LeasedRecords, is not Clone/serde, and has
  no raw-record, route, source-file or receiver export. Two compile-fail probes
  enforce no Clone and no raw field access.
- Record encode/decode repeats Runtime/trust/clock checks before return. Stop,
  revoke, endpoint drift, clock fault or authenticated semantic fault cannot be
  repaired by restoring metadata/new grant. Drop/connection end closes it.
- Runtime shutdown blocks new record effects, not idle-owner release. A held
  idle owner closes on its next attempted operation; explicit connection exit
  drops its own owners before retiring its setup backend. No claim of immediate
  erasure of externally held keys, peer cancellation or on-disk cleanup.
- Mutation expiry does not destroy the original read-only ACK/status/cancel
  behavior. A corrupt unauthenticated ciphertext does not poison valid records.

## Directed evidence

Seven owner cases pass: local source DATA encode/target AEAD buffer readback
and reverse ACK; bad ciphertext followed by valid frame; before/after Runtime
stop; peer/endpoint changes at installation and during later use; expected
grant/role/pin/anchor mismatches; effect expiry, clock discontinuity, explicit
close and Runtime drop. Source and target buffers are LOCAL, target remains
empty. Eight config cases pass, including missing authority -> no lease,
explicit policy validation and real three-phase proof consumption.

### Failures preserved

1. New config-to-proof test omitted the TARGET store's own enrolled endpoint.
   Product correctly returned `setup endpoint missing`. Corrected the fixture,
   not the admission rule. Actual rejected test EXE311DF4A5... and tests retained.
2. Initial wrapper incorrectly required mutation admission around every frame,
   rejecting read-only ACK after expiry. A real crypto negative test failed
   before correction; its source/actual test EXE/log are archived separately.
   The wrapper now distinguishes observation admission from effect checks,
   preserving the existing lease contract without widening deadlines.

3. All54 setup directed tests passed; strict clippy then rejected a nested
   conditional introduced by the ACK correction. Rewritten as a single guarded
   conditional, no lint suppression; strict clippy/default build/exact audit
   passed. The rejected source/log remain separate, not a full acceptance.

## Independent processes

The initial `initial-leased` run under
`artifacts/fleet-p1/setup-lease-20261115-215425/` used real relay plus two agents,
independent encrypted stores, fingerprint approval and explicit time policy.
Both remained live through prepared + leased messages. Relay closure then made
both agents exit and release their one retained owner; targets stayed empty.
This EXE predates the ACK-compatibility correction and is NOT final acceptance.

The final-source probe matrix additionally requires unconfigured setup to stay
unleased, invalid clock approval to fail before arming, disabled relay rejection,
and mismatched-grant rejection. Each result owns EXE/script/logs and PID cleanup.
Final full freeze, exact test enumeration and final-binary re-probes are pending;
consult their separate receipts, never substitute the prior setup-only counts.

## Remaining work

Operational DATA route approval/tickets, consuming these records into the real
SourceFile/HostReceiver and pumps, end-to-end file settlement, four MCP tools,
two-machine/TLS/proxy/production scale remain separate. Existing library pumps
and local v9 settlement are not recreated here. Historical parallel SQL timing
and final-ACK-delivery gaps remain open. No commit, push, service or Advisor.
