# `fleet-release`: explicit local recovery of a stopped owner's absent allocation

`ferroc --allow-dir <root> fleet-release --db <abs> --root <abs>` is the first
**mutating** fleet CLI. It is deliberately narrow: local only, no network, and it
does exactly two things — take metadata ownership over from a STOPPED origin, and
retire an allocation whose stage object is confirmed ABSENT.

## Why the approval is derived in-process

`AbsenceApproval` binds the exact observation **fingerprint**, and that fingerprint
includes the owning fence instance (`fence.owner`). A fingerprint printed by an
earlier process therefore can never match a later one: `owner_recovered` would be
false and the release would be refused. So the flow is a single process:

1. `--recover-owner <uuid>` — metadata takeover from the stopped owner;
2. `--release --digest <hex>` — the tool re-inspects, requires
   `eligibleForAbsenceRelease`, builds `AbsenceApproval` from **its own** fresh
   fingerprint and releases.

`--fingerprint <hex>` remains as an optional extra assertion, but it can only ever
match the fresh observation. The operator's decision is expressed by naming the
exact digest and passing `--release`; eligibility is still proved from scratch
(same DB domain, different original owner, current owner recovered, object absent,
row is an absence candidate).

## Operational prerequisite

The owner fence is exclusive, so both CLIs must be run **while the agent that owns
the database is stopped** — otherwise the database is already held and the command
fails instead of waiting. That is the intended behaviour: no silent queueing and no
second concurrent owner.

## Tests (3, native Windows)

| case | expectation | result |
| --- | --- |
| reservation whose object was never created, stopped owner | released: stage absent, `recordedBytes` 0, `recordedSlots` 0, `complete` true | pass |
| same, but a wrong `--fingerprint` | refused with "does not match this process's fresh observation", obligation still `(4096, 1)` | pass |
| a real file sits at the recorded stage path | refused with "not eligible" (state `PresentBoundIdsMatch`/present), obligation still `(4096, 1)` | pass |

CLI-level checks on the built binary: `--help` prints the local-only description;
a relative `--db` is refused with "database path must be absolute"; a missing
operation reports "nothing to do: pass --recover-owner and/or --release".

## Regression standing for this tree

`fleet::` library suites with both CLIs: Windows **786 passed / 0 failed / 34
ignored** (826.98 s) and Linux **684 / 0 / 22** (800.57 s) — +3 over the previous
783/681, matching the three new release tests. `cargo fmt --all -- --check` and
`cargo clippy --all-features --all-targets -D warnings` clean (one doc-list lint in
the new module was found by clippy and fixed before the run).

## What it still cannot do

- It cannot release **anonymous** stages: those are `AnonymousUnobservable` and
  never eligible, by design (see `fleet-inventory-cli.md`).
- It never deletes or moves any file, never publishes, never contacts a peer, and
  never bypasses the inventory check on the next admission.
- It is local recovery, not resynchronisation: the peer has no idea anything was
  released.

## Boundaries

fleet-core builds only; absent from the default build. Local database + local root
only; test identities irrelevant here because no key material is touched.
