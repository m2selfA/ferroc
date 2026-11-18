# Full freeze receipt for the fleet-CLI tree

Two changes to the fleet surface are in this tree: a read-only obligation view
(`fleet-inventory`) and an explicit local recovery command (`fleet-release`),
plus the Linux replacement receiver and the session-liveness fix from earlier the
same day. The receipt below freezes them together.

## Auditing this increment

The previous tree-specific auditor asserted a **300-file** input set with a 2
source + 7 doc delta. That auditor no longer describes this tree, so the first
attempt at this freeze was **rejected by its own audit gate** and archived as
`cli-preflight-regression-20261117-191613` (with its archived sources, inputs and
`rejected.json`); it is not counted as a pass.

The replacement auditor (`artifacts/fleet-p1/fleet-cli-20261117/audit.py`) asserts
this tree exactly:

- baseline = the 300-input set of `cli-preflight-regression-20261117-085302`;
- current set = **314 files** (14 added, none removed — the last two are this note
  and the refusal-diagnostics note);
- delta = exactly **18 sources + 12 documents**, enumerated by name;
- 11 negative controls: four unexpected paths and seven removed-required paths must
  all be rejected (the auditor refuses to accept a delta it does not expect);
- no trailing whitespace and no stray control characters in any changed file.

## Receipts

`cli-preflight-regression-20261117-192248` (312 inputs), `…-195129` (313 inputs)
and `cli-preflight-regression-20261117-222547`, `…-225949` and `…-232554`
(314 inputs each) all have status `passed`. Each receipt binds its own archived
document bytes; later edits to this report, including the addition of a receipt
name after that run, are not covered by the earlier input hash:

| gate | result |
| --- | --- |
| fmt / strict clippy (`-D warnings`, all features, all targets) | pass |
| all-features, all targets, serial | **869 passed / 0 failed / 37 ignored** |
| default | **63 / 0 / 2** |
| docs | **97 / 0 / 0** |
| Node oracles (p0, control, setup) | pass — setup oracle 5 signatures, 3 canonical messages, 2 unchanged auth vectors |
| CI validator | 13 tests, OK |
| source audit + independent postcheck + production-artifact postcheck | pass |
| inputs | 312 / 313 / 314, hashes re-verified after each run |

The counts are compared against an enumeration taken **before** execution, so a
test that silently disappears or is skipped fails the gate.

## Scope

Windows regression of the code that also produced the Linux two-host and public-TLS
results earlier the same day. It is not a production sign-off, not a Linux run of
this exact tree, and not evidence about QUIC/NAT, resume or operational issuance.
The historical parallel-settlement timing anomaly remains an open item recorded in
the receipt itself.
