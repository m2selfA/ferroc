# Fleet successor grant issuance

Status: **candidate increment**. It adds the missing producer of renewal
successors. It does NOT make ≥1 GiB pass, because the pumps still never ask for
one.

## Why this component exists

Renewal had three of four pieces: the peers can rotate their records
(`SourceWindow::renew`, `HostReceiver::renew`), the relay can route a successor
(`/fleet/renew`), and the route enforces rotation/no-reuse. Nothing produced the
successor grant itself, so a caller had to hand-build a `FileGrant` — which is
exactly the step that is easy to get wrong (changing the job, exceeding the
lease, reusing an epoch).

## `fleet::renewal::successor`

`successor(current, seed, generation, now_ms, lease_ms) -> ValidatedGrant`

- Carries the job over verbatim, so path, size, SHA, permission and the fixed
  job deadline cannot change across a renewal.
- Lease is bounded by `MAX_LEASE_MS` (60 s) and must end at or before
  `job.deadline_ms`.
- `now_ms` is the caller's trusted-time sample; the function reads no clock, so
  a wrong sample is visible at the call site instead of being hidden.
- Identifiers derive from `seed + generation` (SHA-256 → v4-shaped UUID). Same
  inputs reproduce the same binding, so a replayed generation is caught by the
  route's reuse rejection rather than becoming a fresh-looking live binding.
- Refuses: empty seed, generation 0, generation past `MAX_GENERATIONS` (1024),
  lease outside `1..=MAX_LEASE_MS`, an already expired current lease ("renewal
  is not resurrection"), a window that would outlive the job deadline, and any
  result whose identifiers did not actually rotate.

Issuance is still not approval: the caller needs local policy, pins and both
peers' end-to-end authentication before anything is written. This function
signs nothing and touches no network or disk.

## Tests (6, `fleet::relay_channel::tests::renewal_issue_tests`)

Happy path rotation with stable routing identity; replayed generation
reproduces identical identifiers while a different seed does not; every refusal
boundary above; a real signature round-trip on the issued successor for both
roles plus the negative that the old grant cannot authenticate against the new
transcript; the registry accepts the issued successor then refuses its reuse;
a non-rotating grant is refused at offer time.

## What is still missing for ≥1 GiB

The pumps do not call this. Wiring it in needs a coordinated rotation the two
hosts agree on, and that needs one thing that does not exist yet: a way for one
peer to prove to the other that it is at the same drained boundary. A
single-process seam can fake it by holding both identities, which would prove
nothing about two hosts, so it was **not** added.

Next increments, in order: (1) a renewal handshake record so both peers agree on
the boundary and exchange the successor + signatures; (2) pump integration that
presents to the relay and installs on both sides at that agreed boundary;
(3) the MCP tool surface.
