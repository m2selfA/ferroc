# `ferroc fleet-dir preflight` — local read-only destination check

## What it does

`ferroc --allow-dir <src> --allow-dir <dst> fleet-dir preflight --source-root <dir> --target-root <dir>`
scans both local roots, builds the add-only plan, and then runs
`Runtime::preflight_fleet_target` against the target. It emits NDJSON: one
`preflightHeader`, one `preflightEntry` per planned file (path, destination,
bytes, parent id), zero or more `plannedDirectory` records, then the final
`complete` record carrying a `preflightDigest` and the plan digest.

It creates nothing, publishes nothing, deletes nothing, takes no SQLite
lock, and issues no grant. `authorization`, `lease`, `snapshot` and
`applySupported` are all `false` in the header on purpose: the stream is an
observation, never an approval.

## Refusals (whole round, no partial stream)

1. Only add-only plans are accepted. An already-present target file that would
   need an overwrite fails with
   `sync plan refused: <path> needs an overwrite the no-clobber engine does not have`.
   Type conflicts and blocked subtrees fail the same way.
2. A destination whose parent is absent, not private, or reached through a
   symlink/reparse anchor is refused; preflight never runs `mkdir`.
3. Names must satisfy the declared narrow ASCII profile, and ASCII-case
   collisions inside one plan are refused.
4. `--allow-planned-directories` is opt-in and only lists the plan's own
   declared-but-absent directories ancestor-first; they are still not created.

## Engineering identity is local

The CLI does not read an authorization; it fills a fixed local
`SyncTemplate` (fixed ids, `localpreflight` prefix, 1 h descriptive deadline)
so the add-only planner can derive per-file job keys. Those values are
observation identity only — not a fleet identity, grant or expiry — and the
header says so.

## Verification

- `fleet::directory_cli` — 3 tests: successful observation of two absent
destinations with nothing created; missing parent refused by default and listed
ancestor-first only with the explicit opt-in; existing target file refuses the
whole round without touching it.
- Real CLI subprocess (`artifacts/fleet-p1/preflight-cli-20261117/smoke2.json`):
success path emits 2 entries / 8 bytes with `exit=0`; the overwrite case returns
`exit=1` with the planner refusal; the target directory afterwards contains only
the file the fixture itself wrote — no `sub/b.bin` was created.
- Native Linux (`probes/preflight-cli-20261117/linux/verification.json`, 298
inputs `e2b5c14e…d1dfc6`): `fmt --check`, strict `clippy -D warnings
--all-features --all-targets`, the 3 CLI tests and the whole
`fleet::target_preflight::` suite passed on one test image.
- Windows full freeze `cli-preflight-regression-20261117-…`: 862 all-features /
63 default / 97 docs plus Node oracles and CI checks, 298 inputs, 15 gates,
independent postcheck.

## Limits

Read-only local observation. It does not apply, copy, reserve or authorise
anything; the target may be created by someone else right after the check. It
adds no remote directory scan, no remote approval, and no Linux overwrite; Linux
replace still fails closed in `owned_publish`. It inherits no glibc 2.17 or
cross-machine qualification.
