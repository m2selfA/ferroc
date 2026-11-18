# Fleet renewal handshake (RENEW_OFFER / RENEW_ACCEPT / RENEW_COMMIT)

Status: **candidate increment**. This is the piece that was missing before any
pump could rotate safely: a way for two hosts to agree they are at the SAME
drained boundary before either installs a new epoch.

## Why a handshake, and not a timer

Cached DATA belongs to the old epoch and is rejected after rotation, so a
rotation is only safe when nothing is cached and the peer's acknowledged prefix
equals what has been encoded. The source can check its own half; it cannot know
the peer's coverage without asking. A timer-driven rotation would therefore be
a guess that occasionally destroys a live transfer.

## The three frames (all sealed under the CURRENT epoch)

| Kind | Direction | Body | Meaning |
| --- | --- | --- | --- |
| `RenewOffer` (10) | Source→Target | next authorization id + key epoch + generation | "I propose rotating to this successor" |
| `RenewAccept` (11) | Target→Source | same successor + `drained_at` | "I agree, and my contiguous coverage is exactly this" |
| `RenewCommit` (12) | Source→Target | same successor + `drained_at` | "Installing now" — the commit point |

None of them carries a path, size, SHA or permission: a renewal frame cannot
smuggle a different job in. Both hosts already hold their own copy of the
successor (see `fleet::renewal::successor`); the handshake only agrees *which*
successor and *at what boundary*.

## Invariants enforced in code

- **Source**: `begin_renewal` requires `at_renewal_boundary()` — negotiated,
  no cached ciphertext, and peer-acknowledged prefix equal to encoded bytes —
  and refuses a second concurrent handshake. It records `drained_at` and seals
  the offer under the old epoch.
- **Target**: `accept_renewal` requires READY, no DATA in flight, and one
  handshake at a time. It reports its own `contiguous()` as `drained_at`.
- **Source**: `observe_control` accepts a `RenewAccept` only if generation,
  successor identifiers AND `drained_at` all match what it offered. A peer that
  agreed a different offset faults the window instead of installing over bytes
  it never acknowledged.
- **Source**: `commit_renewal` re-checks the boundary has not moved, seals the
  commit under the OLD epoch, and only then calls `renew`. Order matters: after
  `renew` the old sealer is gone, so a commit sealed afterwards could not be
  read by a peer still on the old epoch.
- **Target**: `install_renewal` refuses a commit naming a different successor or
  boundary, refuses a successor it never accepted, re-checks coverage, and
  faults the receiver on any mismatch.
- Counters survive rotation: nothing is re-encoded and nothing is re-acknowledged.

## Tests (2, `fleet::relay_channel::tests::renew_handshake_tests`)

Full handshake on a real file with a real host receiver: offer → accept →
commit, both sides installed, `bytes_encoded`/`peer_contiguous`/`observed_coverage`
all preserved at 2 chunks, transfer continues to 3 chunks under the new epoch.
Negative: a second `accept_renewal` for the same offer is refused; a commit for
a successor the receiver never accepted is refused.

## Route retirement (this increment, kept)

Adoption used to invalidate the superseded binding immediately, which is wrong:
frames sealed under it may still be in the relay's queues, and dropping them
kills a live transfer. `Route` now keeps exactly ONE superseded binding
routable, and retires it on **delivery order** — the moment both roles have been
observed sending a frame under the current binding — never on a timer, never
more than one generation back.

That is a real defect fix with a test
(`renewal_tests::advance_local_requires_stable_identity_rotation_and_no_reuse`
now asserts: superseded frames route, one role switching is not enough, both
roles switching retires them, and two generations back never returns).

## Pump integration: it works now, and what it took

Four earlier attempts were reverted. Each exposed one real ordering constraint;
the fifth works because all four are now satisfied.

1. **Check placement.** The rotation check has to be at the TOP of the source
   loop: once an ACK frees a window slot, `next_record` hands back the next
   chunk immediately, so the drained-and-idle state is invisible anywhere else.
2. **Route retirement.** Adoption used to invalidate the superseded binding
   immediately. `Route` now keeps exactly one superseded binding routable and
   retires it on delivery order — both roles observed on the new binding — not
   on a timer, never more than one generation back.
3. **Adoption cannot be commit-driven.** The relay is opaque: it cannot decode a
   sealed commit, and the commit's header carries the OLD binding by
   construction. So the relay must tell the peers, and it does: the second
   presentation returns `{"advanced":true}`.
4. **A fourth frame.** The target confirms with `RENEW_COMMITTED` (13), sealed
   under the NEW epoch. That is both the source's proof the relay adopted, and
   proof the target can read the rotated session. Without it the source resumed
   DATA into a relay still routing the old binding and the pair was torn down.

The pump sequence, then:

| step | who | frame / call |
| --- | --- | --- |
| 1 | source | offers at the drained boundary (`RENEW_OFFER`, old epoch) |
| 2 | target | parses the offer, answers its OWN coverage (`RENEW_ACCEPT`) |
| 3 | source | seals `RENEW_COMMIT` (old epoch), presents to the relay, sends commit, advances |
| 4 | target | reads commit (old epoch), installs, presents (second → adopted), advances |
| 5 | target | `RENEW_COMMITTED` (new epoch) |
| 6 | source | observes it, resumes DATA under the new epoch |

Both rotation steps are **boxed futures**: this pump is nested inside a driver
future, and the composed state overflowed a default 2 MiB test stack
(`STATUS_STACK_OVERFLOW`) until they were split out and `Box::pin`ed.

Test: `renew_pump_tests::pumps_rotate_through_the_handshake_and_still_settle` —
a real relay, real file, 40 chunks, rotating every 8 chunks; asserts the payload
lands intact, both receipts match, and **both hosts agree on the installed
generation (≥3)**.

Fixture-supplied and NOT proven for two hosts: the signatures (one process holds
both identities) and the offer registration (a real run needs an out-of-band
control plane). A real deployment still needs each host to obtain its own
successor and signatures.

## What is still missing

The pumps do not drive this handshake yet: `run_source` / `run_target` still
never call it, so a real transfer does not rotate on its own. Wiring it in needs
the pumps to carry a "renewal requested" branch through their existing control
loop, which is the next increment. Also still open: presenting to the relay's
`/fleet/renew` as part of that flow, the MCP tool surface, directory apply,
non-loopback TLS, restart-resume, production acceptance.
