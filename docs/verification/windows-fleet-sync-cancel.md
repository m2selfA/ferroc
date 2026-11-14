# Windows P2 run cancellation and status verification

Date: 2026-11-14. Scope: ledger-level cancellation and an aggregated, local-only
status view. No mid-flight pump abort, no rollback, no persistence.

## Evidence binding

Evidence directory: `artifacts/fleet-p1/synccancel-freeze-20261114-012520/`.

| Item | Value |
| --- | --- |
| Frozen input paths | 112 |
| Release TEST binary SHA-256 | `fc02f590…3d2f2ab0` |
| Previous increment TEST SHA-256 | `dff79ea7…61176f7f` |
| Source delta | 2 modified files (`sync_run.rs`, `sync_run_tests.rs`) |

`journal.rs`, `lease.rs`, `crypto.rs`, `protocol.rs`, `host.rs`, the pumps and the
executor are unchanged.

## Suites (original parallel flags)

| Suite | Passed |
| --- | --- |
| fmt / clippy `-D warnings` | pass |
| all-features | 597 |
| default | 62 |
| doc | 89 |
| release fleet components | 535 |
| release relay channel | 21 |
| native pressure (ignored, serial) | 4 |
| three independent OS processes | 1 |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

## Behaviour under test

| Case | Assertion |
| --- | --- |
| status | Running while files remain, Complete only when all settled |
| cancel without flight | future start/settle/fail refused, reason retained |
| cancel with flight | in-flight file becomes Cancelled, earlier settlement kept, no late settlement |
| double cancel | refused; the first reason is not overwritten |
| cancel after failure | refused; state stays Blocked |
| cancel after completion | refused; state stays Complete |

`status()` aggregates local ledger facts plus accepted receipt sizes only. It is
not remote progress and `Complete` is not a delivery or durability claim.

Cancelling does not abort a running pump: the caller must drop its own window,
links and receiver, and no rollback or debt release is implied.

## Not covered

No mid-flight abort, no pump cooperation, no retry/resume, no persistence, no
progress push, no cross-host operation, no Linux qualification and no production
dataset.
