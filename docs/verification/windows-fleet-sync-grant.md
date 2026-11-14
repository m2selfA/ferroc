# Windows P2 plan-to-grant batch verification

Date: 2026-11-14. Scope: structural `ValidatedGrant` batch for one `SyncPlan`.
No signature, trusted clock, pin approval, network, send or persistence.

## Evidence binding

Evidence directory: `artifacts/fleet-p1/syncgrant-freeze-20261114-003756/`.

| Item | Value |
| --- | --- |
| Frozen input paths | 106 |
| Release TEST binary SHA-256 | `a645463f…d96adac4` |
| Previous increment TEST SHA-256 | `a1beb518…21958b5` |
| Source delta | 1 registration line + 2 new files + 3 test-timing separations |

`journal.rs`, `lease.rs`, `crypto.rs`, `protocol.rs` and `host.rs` are unchanged.

## Suites (original parallel flags)

| Suite | Passed |
| --- | --- |
| fmt / clippy `-D warnings` | pass |
| all-features | 584 |
| default | 62 |
| doc | 85 |
| release fleet components | 522 |
| release relay channel | 19 |
| native pressure (ignored, serial) | 4 |
| three independent OS processes | 1 |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

## Grant behaviour under test

| Case | Assertion |
| --- | --- |
| one grant per file | job id/paths preserved, no-clobber, chunk carried |
| identical inputs | identical grant digests and bindings |
| distinct ids | authorization and epoch unique per file, never nil |
| lease bounds | lease positive and inside the fixed job deadline |
| chunk bounds | 0 and 65537 refused |
| session shape | nil or equal sessions refused |
| seeds | zero or equal seeds refused |
| empty plan | empty batch |

## Gate-timing correction found in this increment

Three existing 2 s no-wait gates measured a closure that runs the fixture's own
`BEGIN IMMEDIATE` on a second SQLite connection. That statement can block on the
default 5 s busy timeout, so the gate included the fixture's wait, not the
product's. This explains two previous intermittent failures (2232 ms, 2512 ms);
the failing operations still returned `database is locked`, i.e. they failed fast.

The gates now record the fixture lock wait separately and assert on
`elapsed - lock_wait`, printing both numbers. Assertions on the error text, the
restored 5000 ms timeout and the retained state are unchanged. Measured after the
change: own 12–24 ms with fixture lock 0 ms.

The earlier 2.929 s `reserve_commit` case already took the lock before the timer,
so it is NOT explained by this and stays open as an independent timing question.

## Not covered

No signature, pin or clock verification, no local policy approval, no admission,
no send, no scheduling, no retry, no deletion or overwrite, no two-host run, no
Linux qualification and no production dataset.
