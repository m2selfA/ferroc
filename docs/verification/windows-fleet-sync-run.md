# Windows P2 additive sync run ledger verification

Date: 2026-11-14. Scope: in-memory run ledger for one additive plan. No send,
persistence, retry, concurrency or completion proof.

## Evidence binding

Evidence directory: `artifacts/fleet-p1/syncrun-freeze-20261114-004942/`.

| Item | Value |
| --- | --- |
| Frozen input paths | 109 |
| Release TEST binary SHA-256 | `88545b07…d77162b` |
| Previous increment TEST SHA-256 | `a645463f…d96adac4` |
| Source delta | 1 registration line + 2 new files |

`journal.rs`, `lease.rs`, `crypto.rs`, `protocol.rs` and `host.rs` are unchanged.

## Suites (original parallel flags)

| Suite | Passed |
| --- | --- |
| fmt / clippy `-D warnings` | pass |
| all-features | 591 |
| default | 62 |
| doc | 87 |
| release fleet components | 529 |
| release relay channel | 19 |
| native pressure (ignored, serial) | 4 |
| three independent OS processes | 1 |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

## Ledger behaviour under test

| Case | Assertion |
| --- | --- |
| order | files start strictly in plan order |
| one flight | a second start is refused while a file is in flight |
| settle | exact receipt size required; mismatch changes nothing |
| no flight | settling without a flight is refused |
| duplicate | a settled file cannot be settled twice |
| failure | blocks the whole run, keeps settled history and bytes |
| no revival | a blocked run accepts neither start nor settle |
| reason | failure requires a flight and a non-empty reason |
| empty/zero | empty plan returns None; zero-byte file settles at 0 bytes |
| history | per-file receipts are retained and never rewritten |

`settled_bytes` is the sum of accepted receipt sizes, not traffic, encoded bytes
or durability. A receipt only records a peer statement observed locally.

## Tooling corrections in this increment

My derived post-check still expected the previous increment's four-file delta
(module registration plus three timing separations), so it rejected a correct run.
The expectation was corrected to the actual single registration file; no product
code or assertion changed. The first freeze run itself passed every suite.

## Not covered

No signing, pin, clock, policy, admission, transport, persistence, restart,
resume, delete or overwrite; no `send_file`/`sync_dir` entry point; no two-host
run, Linux qualification or production dataset.
