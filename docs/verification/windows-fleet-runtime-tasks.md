# Runtime-owned fleet task lifecycle (local candidate)

## Contract

Runtime starts without a task table. `open_fleet_tasks(capacity)` is an explicit
local Rust API, Policy-gated and rejected after stop. One id space only; a second
open cannot reset history/capacity. `fleet_tasks()` shares the table, including
historical results after stop. This is NOT enrollment, operational signing,
a CLI option or four enabled MCP tools.

Shutdown marks the shared registry stopped and closes host/task admission under
short control locks, without DB/fs_gate/await. Cancellation is requested at this
cut. Owned task futures drop/drain BEFORE host drain. The old DB->fs_gate and
zero-wait publisher rules are unchanged. External DB/fence owners still must
close/Drop. Never await shutdown of the owning Runtime from inside its worker.

Cancelling a shutdown observer cannot reopen admission. An unobserved blocking
drain may still exist; external owners and OS-blocking IO are not fake-drained.

## Red controls and provenance

`artifacts/fleet-p1/runtime-tasks/red/` preserves an executable: one pass/four
failures. Three found Running after Runtime stop. Initial native readiness failed
BEFORE shutdown, not evidence of deadlock. `red-native-diagnostic` found inventory
rejection of the fixture's broad nonprivate temp root. Only Policy scope narrowed
to its private target directory; ACL/inventory were not relaxed.
`red-native-corrected` then reproduced a real idle receiver blocking host drain
for the unchanged 5s observation window. External fallback cancellation dropped
that owner so the failed test could exit. Stage debt remained3bytes/1slot; no
target was created.

`red-factory-drop` independently used a test-only blocking Drop plus another
OS thread: queued cancellation published terminal state while a factory capture
was still alive. Factory and Operation now share an ordered owner, including
never-polled tasks; pre-cancel explicitly drops captures before interruption.
Product snapshot errors remain redacted codes.

## Lifecycle checks

Nine targeted test functions passed: attachment/Policy/default absence, fleet
shutdown and full shutdown, other Runtime/detached-table isolation, native idle
receiver, external fence with aborted stop observer, attach-stop race, queued
capture-drop ordering, and actual never-polled Tokio executor destruction.
Some functions cover multiple assertions. No remote cleanup ACK is inferred.

## Worker integration and acceptance scope

The SingleOwner SOURCE test worker now uses `Runtime::open_fleet_tasks` for the
actual SourceFile/window/network future. Parent Runtime shuts down after wait;
`source-runtime-task.json` records the same id/history and late admission refusal.
The scale verifier checks that record against the polled task, both receipts and
actual disk SHA. Rotating workers retain their direct path. NoRenewal, fixed
job deadlines,300s route/IO and PUBLIC test identity/time fixtures remain.

Formal full-regression/new-binary scale results are separate artifact manifests;
only their exact results count. Prior113A61F8/B94 binaries did NOT have this
Runtime attachment. No MCP/crosshost1GiB/Linux sink/operational authorization,
restart recovery/remote cleanup/parent durability acceptance is claimed.
Historical2048ms/2929ms SQL admission failures remain separately unresolved.
