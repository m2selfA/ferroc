# Crash leaves a durable obligation and admission fails closed (network level)

Date: 2026-11-17. Topology: relay on 3dv0 loopback, Windows source (cap00),
Linux target (3dv0) — same as the LAN ladder. Binaries: Windows `1efa50f8…c6ce`,
Linux `72576c74…4abd`. Fresh identities, own run root.

## Round 1 — crash in the middle of DATA

The target agent was killed with **SIGKILL** (not a graceful stop) once its stage
held 16 MiB. Result, from the target's own database and directory:

| observation | value |
| --- | --- |
| staged bytes at kill | 16777216 |
| row phase | `transferring` |
| receipt | none |
| recorded stage debt | 16777216 (schema 11) |
| destination file | **absent** |
| completion events | none on either end |
| source error | `fleet receive failed (protocol-reset-without-close); effects may exist` |

So a crash leaves the full obligation and nothing published — no partial target
file and no receipt are invented.

## Round 2 — the SAME database, a NEW job

A second round was started against the same host database and directory with new
job/transfer/file ids, new sessions, a new authorization and a new route approval.
It was **refused**:

```
target host resume: unresolved inventory/debt blocks host admission
```

and the obligation was untouched: debt before `[(16777216, "transferring")]`, debt
after `[(16777216, "transferring")]`, still no destination file, still no events.
That is the fail-closed property: a crashed round cannot be bypassed by simply
starting another job, and the error names the reason.

## What this does NOT show

- **No resume.** This round does not claim interrupted transfer resumption; the
  documented boundary stands that a restart does not continue or publish.
- **No automatic reconciliation.** Clearing the obligation requires an explicit
  operator action in the same lock domain with proof that the previous owner is
  gone; there is no CLI for that yet, so the recovery path is still
  library-level only.
- Single machine pair, test identities and local approvals; not production
  qualification and not a durability guarantee for the parent directory.

## Harness notes

- The target was killed with SIGKILL via the helper, and the crash was timed by
  polling the target database for a live stage of at least 1 MiB, so the kill
  happens after real bytes exist.
- A relay left behind by an aborted earlier run can hold the port while using a
  different database and admin password; the harness now also stops anything bound
  to the port regardless of its run root. Without that, pairing fails with 401.
