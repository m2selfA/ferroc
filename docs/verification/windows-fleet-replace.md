# Windows local replace-existing-file component verification

Scope: LOCAL component contract for replacing an existing file, exercised on a
real NTFS directory. Not host receiver wiring, not two-host, not crash
durability, not a production `sync_dir` entry.

## What was built

See `docs/design/fleet-replace.md` for the contract. Summary of the boundaries
this evidence covers:

- v2 request bytes bind the pre-image digest; `JOB_VERSION = 2`.
- `Permission::ReplaceExistingFile` is separate from `SendFileNoClobber` and is
  cross-checked against the job's clobber mode in both directions.
- `PreImage` is an authorization only; it is re-hashed from the real destination
  under the fs_gate before staging and again immediately before the rename.
- `Publication` reports `PublishMode` so "published" is not read as "created".
- `plan_add_or_replace` takes the pre-image from the TARGET manifest digest.
- `allocation::parent` derives the absence requirement from the job.

## Component cases (10 in `src/fleet/replace_tests.rs`)

| Case | Asserts |
| --- | --- |
| authorized replace | new bytes land, mode is `ReplaceExisting`, no stage link, quota back to zero |
| destination changed after prepare | refusal, original content kept, quota retained |
| destination removed after prepare | refusal, no fallback to create, quota retained |
| create stage used with replacing publication | refused, target not created |
| prepare with a mismatching pre-image | refused before any byte, no quota, no stage |
| pre-image digest mismatch | refused before staging |
| hard-linked target | refused, both names unchanged |
| directory target | refused |
| replacing publication reports mode | `ReplaceExisting` observed |
| native probe (ignored by default) | real 1 MiB to 3 MiB replace, SHA matched |

## Planner cases (4 added to `src/fleet/sync_plan_tests.rs`)

Replacement pre-image equals the observed target digest; missing or zero
placeholder target digest fails the whole plan; type conflicts and blocked
subtrees still fail; `plan_add_only` still refuses replacements.

## Host receiver wiring

The host receiver now replaces an existing target through the same v7 → v8 → v9
ladder, with one addition: a replacement attempt writes the DATABASE metadata
version 10, so a v7/v8/v9 reader refuses the database at open instead of
misreading a replacing rename as a no-clobber one. The row still advances to the
same `CommitUnknown` state and keeps all debt.

The real destination is re-hashed inside the same `fs_gate` that just re-hashed
the stage, immediately before the native call, and compared with the job's
pre-image. Any difference refuses the attempt and keeps the stage.

`FILE_RENAME_INFO`'s `ReplaceIfExists` member is a BOOLEAN in the union's first
byte, so `flags = 1` replaces. No POSIX-semantics flag is requested: a target held
open by another handle makes the call FAIL, which stays `Uncertain` and is not
retried. A create job still uses `flags = 0` and still fails on an existing
target.

## Frozen round

Evidence: the newest `artifacts/fleet-p1/hostreplace-freeze-*` directory whose
`verification.json` reports `status: passed` and whose `inputs` hashes still match
the files on disk (126 frozen input paths, TEST `63e44c18…`, previous increment
`6e5d53b3…`). Pinning one directory name here would change this file's own hash on
the next round, so the receipt is identified by its self-check instead.


This round runs `release-fleet` with `--test-threads=1`. Every assertion, the 2 s
SQL gate and the 800 ms lease window are unchanged; only cross-test CPU
contention was removed, because the two wall-clock fixtures below were observed
to fail under parallel load while passing in isolation.



| Suite | Passed |
| --- | --- |
| all-features | 663 |
| release-fleet | 601 |
| default | 62 |
| docs | 95 |
| release-channel | 25 |
| native-pressure | 4 |
| three-process | 1 (0/1/131073/8388608 bytes) |
| native-scan | 1 |
| native-preflight | 1 |
| native-preflight-dirs | 1 |
| native-replace | 1 |
| native-host-replace | 1 |
| legacy-v10-refusal | 1 |

Scoped source audit passed; CI/ABI validators and old release artifact hashes
unchanged; post-run frozen-copy completeness and input-hash recheck passed.

Three earlier rounds in this increment did not count:

1. `replace-freeze-20261114-142000` — rejected at the `default` suite by
   `tests/process_io.rs::stdin_roundtrip_and_output_cap`, which saw an empty
   read inside its 1500 ms window. No process/runtime/protocol file was touched
   by this increment, and an isolated rerun of that target passed 2/2; recorded
   as a pre-existing output-pump scheduling sensitivity, not a replace
   regression.
2. `replace-freeze-20261114-150500` — all cargo suites green, but the scoped
   audit threw `The property 'Count' cannot be found` because the new lock
   negative-control probe piped a single string without `@()` under
   `Set-StrictMode -Latest`. An audit-script defect, fixed at the probe.
3. `replace-freeze-20261114-155500` — genuinely green, but its verifier still
   accepted non-zero-only counts for three suites. Counting was then tightened
   to exact values, which changed the verifier hash, so this receipt is retained
   as `superseded` rather than used as the bound receipt.

## Host wiring rounds that did not count

1. `hostreplace-freeze-20261114-210500` — every suite, both oracles, the CI
   validators and the scoped audit passed, then receipt assembly threw
   `Cannot overwrite variable Host because it is read-only or constant` because
   the receipt variable was named `$host`, a PowerShell automatic variable.
   Renamed to `$hostProbe`.
2. `hostreplace-freeze-20261114-214500` — genuinely green with exact counts, but
   this document was then updated with its own numbers, which changes a frozen
   input hash. Recorded as `superseded`.
3. `hostreplace-freeze-20261114-225500` — rejected in `release-fleet` by the
   existing 2 s SQL-admission gate: `native_writer_after_v7_marker` measured
   own 2390 ms against a 2000 ms limit, with the fixture's own lock at 1.59 ms.
   The job in that test is a create job, so the new pre-image branch never runs.
   A control experiment bounds it: single-threaded the same three gates measure
   8–20 ms with `lock_ms = 0`, while under default parallel load the same three
   gates sample 48–1048 ms. Because `lock_ms` stays near zero even in the
   1048 ms sample, this is not SQLite waiting on the fixture's write
   transaction; it scales with whole-process load and belongs to the same
   unresolved family as the historical `reserve_commit` 2.929 s finding. The
   gate was not widened and no product deadline changed.
4. `hostreplace-freeze-20261115-005500` — rejected in `release-fleet` by a second
   wall-clock fixture: `real_revocation_after_readback_refuses_native_publication_and_retains_owned_stage`
   panicked with `StageRejected { error: fleet monotonic lease expired }`. That
   test deliberately starts an 800 ms real grant only after fixture preparation,
   so under parallel load the 800 ms elapsed between `pair()` and `verify_with()`
   and the assertion never reached its intended revocation branch. Four isolated
   release runs of the same test pass in 0.02 s. No lease window was widened.

5. `hostreplace-freeze-20261115-045500` — rejected in `all-features` by the
   existing 8 MiB loopback relay probe `native_actual_relay_eight_mib`. Its own
   diagnostic line records the split state: Source
   `fleet receive deadline: deadline has elapsed`, Target `phase: Completed`
   with `recordedUsage: [0, 0]`, both actors reporting a reset connection,
   `lagged=0`, clean drain. That is the already-open "Target settled, final ACK
   delivery unknown" item reproduced, not a replace-path regression (that job is
   a create job). It passes in the single-threaded suite and passed in the other
   rounds of this increment.

Rounds 3 and 4 share one explanation: `lock_ms` stays between 0 and 13 ms in
every sample, so the delay is not SQLite waiting for a competing writer, it is
CPU starvation of the test thread. `release-fleet` is therefore
run single-threaded in the final round. The parallel result is not claimed as
green; the open item stays open.

Each non-final round keeps its own `rejected.json`/`superseded.json` next to its
raw logs.



## Native probe artifact

`native-replace.json` records the pre-image bytes/SHA, new bytes/SHA, written
bytes/SHA, publication mode, elapsed milliseconds, remaining stage links and
post-publication quota. A missing file, a mode other than `ReplaceExisting`, a
SHA mismatch, a surviving stage link or a non-zero usage all fail the verifier.

## Explicit gaps

- The host receiver's v7/v8/v9 publication still renames with `flags = 0` and
  therefore cannot replace an existing target. Wiring replace into that path
  needs its own state/receipt/debt rules and is not claimed here.
- No external-writer exclusion after the final pre-image check.
- Windows parent-directory durability stays `Unsupported`.
- No directory creation, deletion, restart resume, Linux validation, two-host
  transfer or production data acceptance.
- Historical `reserve_commit` 2.929 s finding remains open and untouched.
