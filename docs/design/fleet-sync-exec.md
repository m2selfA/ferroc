# P2 single-file executor

## Boundary

`sync_exec::execute_file` runs the EXISTING source window and target receiver pumps
against caller-built links and returns one receipt only when both sides agree.
It does not create links, approve routes, issue grants, order files, retry,
reconnect, persist or orchestrate two hosts. The caller drives those and the run
ledger.

| Rule | Reason |
| --- | --- |
| both pumps must succeed | one-sided failure is not a transfer |
| receipts must be equal | the source's authenticated observation must match the local target receipt |
| one call per file | ordering and one-in-flight stay with the ledger |
| cancellation drops both pumps | before target settlement, stage/debt remain; existing settlement history is not rolled back |
| `run_plan` drives order | it binds the ledger ordered jobs, uses its next pending index, and starts/prepares/executes/settles one file at a time |
| preparation is cancellable | a pending preparation future is dropped; synchronous or detached side effects are not undone |
| actual target job must match | a wrong admitted owner fails before DATA; its existing stage debt remains |
| receipt size and SHA must match | a rejected receipt blocks the ledger, never rolls back the target |
| per-file futures are boxed | their state holds both pumps; unboxed nesting overflowed a 2 MiB stack |

## What the tests cover

Two additive files (1 B and 128 KiB) are planned, granted, routed, transferred and
settled in plan order through the real native relay in one process. A second case
plants a destination before the next file, so admission refuses before any byte
moves; the ledger records the failure, blocks the run, keeps the earlier
settlement and the planted bytes stay unchanged.

## Not covered

No signing/clock/pin/policy beyond the fixtures, no cross-host operation, no
retry or restart resume, no delete or overwrite, no background scheduling, no live byte-progress surface and no
production enrollment.
