# Windows P2 single-file executor verification

Date: 2026-11-14. Scope: one planned file executed through the existing pumps on
the real native relay, in one process. Not two hosts, not production enrollment.

## Evidence binding

Evidence directory: `artifacts/fleet-p1/syncexec-freeze-20261114-011243/`.

| Item | Value |
| --- | --- |
| Frozen input paths | 112 |
| Release TEST binary SHA-256 | `dff79ea7…61176f7f` |
| Previous increment TEST SHA-256 | `88545b07…0dd77162b` |
| Source delta | 2 modified (`mod.rs`, relay test registration) + 2 new files |

`journal.rs`, `lease.rs`, `crypto.rs`, `protocol.rs`, `host.rs` and the pumps are
unchanged; `delta.json` records the diff hash.

## Suites (original parallel flags)

| Suite | Passed |
| --- | --- |
| fmt / clippy `-D warnings` | pass |
| all-features | 593 |
| default | 62 |
| doc | 89 |
| release fleet components | 531 |
| release relay channel | 21 |
| native pressure (ignored, serial) | 4 |
| three independent OS processes | 1 |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

## Executor under test

| Case | Assertion |
| --- | --- |
| additive plan, two files | plan → grants → route approval → both links → `execute_file`; receipts equal, sizes match, ledger settles in plan order |
| target appears before the next file | `admit_receiver` refuses, the ledger records the failure and blocks the run, the earlier settlement is kept and the planted bytes are unchanged |

Files were 1 B and 128 KiB. The executor itself adds only: both pumps must
succeed and both receipts must be identical; ordering and one-in-flight remain in
`RunLedger`.

## Failure in this increment

The first freeze attempt failed the doc gate: my `compile_fail` example actually
compiled. It was replaced by a missing-argument call and a nonexistent
`Receipt::resend`; the run afterwards passed every suite. The failed directory is
retained and not counted as acceptance.

## Not covered

No signing/clock/pin/policy beyond fixtures, no cross-host transport, no retry or
resume, no delete/overwrite, no scheduling, no progress surface, no persistence
and no production dataset.
