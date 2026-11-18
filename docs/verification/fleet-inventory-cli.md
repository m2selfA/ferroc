# `fleet-inventory`: read-only obligation view (fleet-core builds)

`ferroc --allow-dir <root> fleet-inventory --db <abs> --root <abs> [--root ...]`
opens the SAME host database the agent uses and prints what is already persisted.
It never admits, resumes, publishes, deletes or releases anything, and the output
carries `"authority": false`.

## What it prints

- `complete` / `entriesSeen` and the bounded scan `findings` (kind + path);
- `recordedBytes` / `recordedSlots` — the durable obligation, not a file length;
- one `obligations[]` row per persisted job: digest, phase, owner, revision,
  reserved bytes, whether a receipt exists, and a read-only
  `reconciliation` block (`state`, `databaseMatches`, `originStopped`,
  `eligibleForAbsenceRelease`, fingerprint).

## Real evidence: the crashed round from this session

Run on 3dv0 against the database left by the SIGKILL crash round:

```json
{
  "authority": false,
  "complete": false,
  "entriesSeen": 5,
  "findings": [{"kind": "AnonymousStageUnobservable", "path": ".../.ferroc-fleet-alloc-9f247a88-..."}],
  "obligations": [{
    "phase": "Transferring",
    "reservedBytes": 16777216,
    "hasReceipt": false,
    "reconciliation": {"state": "AnonymousUnobservable", "databaseMatches": true,
                       "originStopped": true, "eligibleForAbsenceRelease": false,
                       "fingerprint": "87bd33a2…d047"}
  }],
  "recordedBytes": 16777216,
  "recordedSlots": 1
}
```

Two things this makes explicit:

1. The obligation is visible even though the crashed process is gone and the
   stage has no path (an `O_TMPFILE` inode).
2. `eligibleForAbsenceRelease` is **false**, and correctly so: an anonymous stage
   cannot be shown to be absent, so the absence-release path must not be used. A
   crashed anonymous obligation is therefore **not releasable through that path** —
   this is a property of the design, not a CLI shortcoming, and operators must not
   expect the quota to come back on its own.

## Operational prerequisite

The owner fence is exclusive: run it while the agent that owns the database is
stopped. A running agent already holds the database, and the command fails instead
of waiting for it.

## Tests

Four unit tests: clean database (no obligation, no authority), a staged obligation
(17 MiB… i.e. reserved bytes and phase reported, no receipt), a disabled-transfer
policy (the view still works — read-only recovery must not depend on `allow_transfers`),
and relative `--db`/`--root` refused before any database access.

## Regression standing for this tree

`fleet::` library suites with the CLI included: Windows **783 passed / 0 failed /
34 ignored** (844.88 s) and Linux **681 / 0 / 22** (786.14 s) — exactly +4 over the
previous 779 / 677, matching the four new tests. `cargo fmt --all -- --check` and
`cargo clippy --all-features --all-targets -D warnings` clean. The subcommand is
absent from the default (no `fleet-core`) build: `ferroc fleet-inventory` there
returns `unrecognized subcommand`, and with `fleet-core` its help reads
"LOCAL read-only fleet obligation view; no admission, release or network".

## Boundaries

- READ ONLY. There is deliberately no `--release` flag: releasing an obligation
  needs the library-level approval path (`inspect_allocation` → operator approval →
  `release_absent_allocation`) with a real fingerprint, and no such command is
  exposed yet.
- It reports the database's own claims plus one bounded scan; it is not a
  filesystem snapshot, not a receipt, and not proof about peer state.
- Windows and Linux builds only (fleet-core feature); default build unchanged.
