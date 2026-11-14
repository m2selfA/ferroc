# Windows P2 cancellable execution verification

Date: 2026-11-14. Scope: cooperative cancellation at the executor boundary. Not a
graceful drain, not a rollback and not a remote abort.

## Evidence binding

Evidence directory: `artifacts/fleet-p1/syncabort-freeze-20261114-013824/`.

| Item | Value |
| --- | --- |
| Frozen input paths | 112 |
| Release TEST binary SHA-256 | `90566a97…1ca3fad09` |
| Previous increment TEST SHA-256 | `fc02f590…3d2f2ab0` |
| Source delta | 2 modified files (`sync_exec.rs`, relay exec tests) |

`journal.rs`, `lease.rs`, `crypto.rs`, `protocol.rs`, `host.rs` and both pumps are
unchanged.

## Suites (original parallel flags)

| Suite | Passed |
| --- | --- |
| fmt / clippy `-D warnings` | pass |
| all-features | 598 |
| default | 62 |
| doc | 90 |
| release fleet components | 536 |
| release relay channel | 22 |
| native pressure (ignored, serial) | 4 |
| three independent OS processes | 1 |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

## Behaviour under test

| Case | Assertion |
| --- | --- |
| cancel before any byte | `ExecOutcome::Cancelled`, no target file, admitted stage and full recorded debt retained |
| cancelled file in the ledger | file marked Cancelled, no receipt, earlier settlement untouched |
| normal path | unchanged: the existing ordered-plan case still settles both files |

The cancelled 128 KiB job kept `(131072, 1)` recorded usage, i.e. the whole
reservation with one slot. Nothing was deleted, exempted or credited.

## Limits of this mechanism

Cancellation polls every 5 ms and then drops both pumps. A chunk already inside a
blocking write may still land, the peer is not signalled, and there is no drain,
rollback, resume or retry. Delivery is not proven either way.

## Not covered

No remote cancel, no persistence, no cross-host operation, no Linux qualification,
no production dataset.
