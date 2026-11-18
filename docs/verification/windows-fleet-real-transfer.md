# Ferroc fleet: real local transfer through the stock agent

## What this increment adds

A local, explicit `transfer` section in the existing fleet setup config (same
file, same strict `deny_unknown_fields`) can let the stock agent drive the
existing source/target pumps after an authenticated DATA ticket arrives. It does
not add a wire message, a second relay process, a new crypto format or a new
file path authority.

```json
"dataRoutes": true,
"leaseAuthority": {"kind":"singleOwnerSystemClock","uncertaintyMs":100},
"transfer": {"windowChunks": 4, "hostDb": "C:\\private\\fleet-host.db"}
```

- `windowChunks` is 1..=8 and is the local source flow window. The target READY
  remains the existing bounded 8-chunk offer.
- `hostDb` is required when any provisioned round has role `target`; it must be
  an absolute existing local database with a single-user parent. The test
  harness creates it with a private ACL; the product does not auto-create or
  relax that requirement.
- `transfer` requires `dataRoutes: true` and an explicit local `leaseAuthority`.
  Neither the relay nor the peer can enable it. Without `transfer`, the agent
  behaves as before and does not drive pumps.

## Ordering and ownership

1. The existing setup backend produces `PreparedSetup`; the local time approval
   makes the original `SetupLease`.
2. The current authenticated socket sends the DATA presentation. The relay
   returns one `fleetRoute` ticket to that same owner.
3. The ticketed owner calls `connect_link`: the ticket is removed **before**
   dialing, the link uses the lease's own approved grant/role/endpoint, and any
   dial failure terminally closes the owner.
4. Only then may the same owner move its records into `SourceWindow` or a
   `HostReceiver` on the same Runtime. Target admission still checks the database
   owner fence, stage binding, private destination parent, policy and live lease.
   Admission creates a private stage and journal row, not the destination file.
5. The existing pumps perform DATA/ACK/FINISH; the target performs v9 local
   settlement and the source records the peer's authenticated receipt statement.
6. The target pump's receiver future is dropped before `host.close()`. The
   session aborts owned transfer tasks before clearing lease owners.

## Evidence

A real three-independent-process run (relay + two agent binaries, loopback
public URL, PUBLIC test keys) transferred a 3-byte and an 8 MiB file with:

- both sides `prepared locally`, `leased locally`, `DATA ticket held locally`;
- target `target settled locally bytes=<size>` and one target file only;
- source `source observed peer completion bytes=<size>`;
- destination size and SHA-256 equal to source.

Raw evidence is under `artifacts/fleet-p1/lease-handoff-*/transferred-*` and the
final freeze directory. This is a local component/process proof, **not** a
claim of two-machine, Linux, scale, deployment or MCP `send_file`/`sync_dir`.

## Known boundaries

- A failed dial consumes the ticket and leaves no reusable routing secret.
- Transfer failure leaves possible local effects and does not claim cleanup or
  debt release. The target stage's journal/obligation remains the existing
  conservative contract.
- The target host database must pre-exist with a single-user ACL; an empty or
  non-private directory yields `ScopeUnavailable` and admission is refused.
- The stock agent still exposes no `send_file`, `sync_dir`, `transfer_get` or
  `transfer_cancel` MCP tools.
