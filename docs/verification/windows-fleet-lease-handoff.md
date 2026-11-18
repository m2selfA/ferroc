# Lease owner handoff to existing fleet IO

## Scope

This increment connects the **already authenticated** `SetupLease` and its
one-shot routing ticket to the existing `FleetLink`, `SourceWindow` and
`HostReceiver`. It does not invent a second link, re-encrypt records, expose raw
`LeasedRecords`, or add a CLI/MCP transfer entry.

## Contract

- `SetupLease::connect_link` requires a live owner and a held ticket. It removes
  the ticket BEFORE dialing, uses the lease's own approved grant, role and bound
  endpoint (never message data), and terminally closes the owner on any dial
  failure. No reusable secret survives a failed connect.
- `into_source_window` requires the SOURCE role, a ticket consumed by THIS owner,
  and current Runtime/identity/peer/endpoint + lease checks. It moves records
  exactly once into the existing `SourceFile`/`SourceWindow`; no path override or
  second window from the same lease.
- `into_receiver` requires the TARGET role, a consumed ticket, and a host on the
  SAME Runtime as the lease (pointer identity, not device strings). The existing
  `HostReceiver::admit_receiver` still revalidates job/policy, owner fence,
  database/stage binding, private parent and live lease. Admission creates a
  private stage and journal row, NOT a published destination file.
- A ticket alone is routing, not file permission. A lease alone (no ticket, or a
  held-but-unconsumed ticket) cannot open source/receiver IO. Wrong role, wrong
  Runtime, closed owner, expired/revoked peer and failed link are rejected.

## Evidence status

Directed tests cover source handoff with a real file/`SourceWindow`, no-ticket and
unconsumed-ticket rejection, wrong-role rejection, closed-owner rejection, target
handoff into a real resumed `FleetHost` with no published destination, and
failed-dial ticket consumption. These are LOCAL component tests. They do NOT
show agent pump execution, DATA over the relay, final receipt parity, two
machines, Linux, scale, deployment or MCP tools.

The stock agent still only holds the ticket. Driving `run_source`/`run_target`
from the transport lifecycle is the separate next step and needs its own
shutdown/drain ordering, because an accepted receiver must be dropped before
`Host::close`/`Runtime::shutdown`.
