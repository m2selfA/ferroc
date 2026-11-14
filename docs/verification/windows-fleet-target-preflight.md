# Windows target preflight verification

Status: native targeted tests, frozen regression and an explicit actual-tree probe
passed. LOCAL component only: not apply, not two-host, not production.

## Scope

`Runtime::preflight_fleet_target` observes, for one ordered add-only plan, that every
destination parent already exists as a private plain directory resolving to the same
object as its original spelling, that the resolved destination stays inside the given
root, and that the destination is absent. It changes nothing on disk.

## Native cases

21 normal tests cover: absent destinations under existing private parents; missing
parent refused and not created; existing destination refusing the whole plan with
content untouched; reserved/unsafe/non-ASCII/`space`/`period`/`?` names refused
rather than folded; ASCII case collision between planned targets; the manifest's own
file/directory clash refusal; junction parent refused even when policy could resolve
it; a junction between root and parent that would relocate the destination outside
the root; a destination outside the given root; plan-digest binding refusing another
plan; cancellation before start and after the first entry; a retained parent handle
denying an ordinary rename only for the observation window (rename succeeds after it
returns); transfer disable and `Runtime::shutdown` blocking new preflights; empty plan
and narrowed file limits; a real 64-component existing chain; and a directory at the
destination path not treated as absent. Four more cover the explicit directory
contract: default mode still refusing a missing grandchild; the explicit mode
listing declared directories without creating them; a declared directory that is
actually a file being refused; and the manifest's own requirement that every
non-root parent is declared, with the preflight then listing them ancestor-first.

## Explicit actual probe

`native_target_preflight_probe` builds a real 73-entry source tree (69 files, one of
them 8 MiB), scans it, diffs against an empty target manifest, plans, and preflights
the real private target root.

## Evidence

- Frozen inputs, raw logs and binary hashes: `artifacts/fleet-p1/preflight-freeze-20261114-074500/`.
- Result of that frozen run: 69 planned files, 8392524 planned bytes, all destinations
  absent, all parent IDs present, 0 target files created,14 ms preflight. An earlier
  ad-hoc probe of the same tree reported21 ms. Directory cache state was not
  controlled, so neither number is a throughput benchmark.

`native_planned_directories_probe` (explicit, ignored by default) scans a real
source tree with three nested new directories plus one 8 MiB file, and checks that
the strict mode refuses, the explicit mode lists `d0, d0/nested, d1, d1/nested,
d2, d2/nested` ancestor-first, 4 files / 8388701 bytes are planned, and no
destination directory or file exists afterwards.

No schema, cryptography, lease, journal, receiver/pump, production executable,
default feature or CI changes. Historical `reserve_commit` 2.929 s remains open.
No commit/push.
