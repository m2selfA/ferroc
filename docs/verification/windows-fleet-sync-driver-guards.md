# Windows P2 driver boundary verification

Status: full frozen regression and postcheck passed. This is a local candidate,
not two-host, Linux or production acceptance.

## Reproduced defects

The prior TEST `dcc63e59…` and all 112 source inputs remain in
`artifacts/fleet-p1/syncdrive-freeze-20261114-015233/frozen/`.
New negative tests against unchanged product code reproduced six failures and one
passing terminal-state control. Raw log: `artifacts/fleet-p1/driver-boundaries-red.log`.
The original red debug executable was not separately archived before rebuilding;
its SHA-256 is unavailable. These red observations are raw-log evidence, not a
hash-bound binary receipt. The previous product source baseline is retained;
the final successful binary is bound separately by the frozen verification.
`driver-boundaries-red-diagnostics.json` extracts the six expected failures; it
does not retroactively prove the identity of the first red executable. A first
extractor incorrectly assumed a default 50KB read included the summary; the
corrected extractor uses the explicit final failure-list range.

| Boundary | Before | After |
| --- | --- | --- |
| different plan, same length/size | preparation invoked for unrelated job | ordered JobSpec list bound before mutation |
| already settled prefix | callback restarted at index 0 | next pending ledger index used |
| preparation pending | token ignored until prepare returned | biased cancellation drops preparation |
| complete/empty + stop token | attempted illegal cancellation | remains Complete, no preparation |
| externally active file + stop | ledger cancelled despite foreign owner | refused without mutation |
| same size, different SHA receipt | accepted | rejected without changing ledger |
| wrong admitted Target job | could pump another job | blocked before DATA; stage and full debt retained |

Seven new pure/bounded async tests passed after fixes. A real relay counterpart
uses valid grants for two same-size 70000-byte jobs: providing job 2's receiver for
job 1 is rejected; no target file, zero-length stage, full `(70000,1)` debt, no
receipt. Normal two-file counterpart still completes at 140000 accepted bytes.
These use public cfg(test) fixed-key/synthetic-time issuance, not enrollment.

## Cancellation correction

`Cancelled` means no receipt returned to this caller, not proof that Target never
settled. If Target already persisted v9 before Source completion, its historical
receipt and zero stage debt may already exist. Dropping futures does not roll
back those effects. Before settlement, admitted stage/debt are retained. The
pre-cancel probe only establishes that earlier phase; it does not cover a race
after local settlement. Synchronous calls and caller-spawned work are not made
abortable by dropping a preparation future. No hard cancellation latency bound
is claimed for OS blocking or scheduler delay.

## Frozen verification

Evidence directory: `artifacts/fleet-p1/driverguard-freeze-20261114-055531/`.
113 frozen input paths; original default stack and parallel flags.
Release TEST SHA-256:
`4a8ce311b1b75668923884553a197897fe7e5585b668d97eb90c1eebcc08db59`.
Previous TEST SHA-256:
`dcc63e59327a91e1b0c115b2cd20eb7a7b5df77157422261b90e865d19c56fc6`.

| Suite | Passed |
| --- | --- |
| fmt / strict clippy | pass |
| all-features | 608 |
| default | 62 |
| doc | 91 |
| release fleet | 546 |
| release channel | 25 |
| native pressure | 4 |
| three-process harness | 1 (four sizes) |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

Scoped audit: 108 files, 43 local links. Postcheck passed: current/frozen
sources, current/archived TEST, previous TEST, raw suite hashes, all eight new
case names, native pressure observations, three-process receipts and exact delta.
Four modified existing sources (`sync_exec.rs`, `sync_run.rs` and their existing
relay/ledger tests); one new source (`sync_exec_tests.rs`). No timeout, stack
limit, schema, wire, cryptography, host implementation or CI changes.
The actual driver real-relay positive control now uses two 70000-byte files.
Prior report's 4+70000-byte fixture is historical, not this run's dataset.

Historical reserve_commit 2.929s root cause remains open. No cross-host, Linux,
real-directory scan, operational issuance or production acceptance. No commit/push.
