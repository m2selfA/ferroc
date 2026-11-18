# Ferroc fleet: local MCP task surface

## Scope

`transfer.mcp: true` in the existing local setup file attaches a bounded MCP
task surface to that Runtime. The stock agent/default catalog is unchanged when
the flag or the service is absent.

Tools:

- `send_file({roundId, timeoutMs?})` starts one locally preapproved SOURCE round
  and returns a local task id immediately. It does not accept a path, peer,
  grant, hash or size from the wire.
- `sync_dir({rounds:[roundId...], timeoutMs?})` registers 1..=8 preapproved
  source rounds and starts them **one at a time**, waiting for each terminal task
  before the next. It does **not discover or authorize** a directory diff,
  overwrite or delete. Individual preapproved jobs may explicitly authorize
  replacement with a bound pre-image.
- `transfer_get({taskId})` returns the local `TaskSnapshot`; a peer observation
  is the peer's statement, not proof of its private disk.
- `transfer_cancel` takes exactly one of `taskId`, `roundId` or `rounds` (1..=8
  unique local rounds). It requests local cancellation, not remote cleanup,
  rollback, debt release or resumption. Invalid selectors/batches fail before
  cancellation side effects; already completed tasks cannot be cancelled.

## Lifecycle

The local setup file's source rounds are not started at websocket welcome when
MCP is enabled. `send_file` registers the task, the live session starts the
same `SetupBackend` round from the cached local approval, and the resulting
`SetupLease` consumes its one-shot ticket. The session then delivers that same
owner to the waiting task; the source pump runs exactly as in automatic mode.
A failed setup, dropped session, cancelled task or failed dial ends the waiter;
the owner is closed/dropped and no reusable ticket remains. The MCP table is
the same Runtime task attachment, installed atomically with the service.
Runtime shutdown cancels/drains it before host drain; an existing task
attachment cannot be silently replaced. A cancelled first batch task stops
later setup starts and abandons remaining waiters.

## Evidence status

Local component tests cover: exact four tool names, default catalog unchanged,
explicit Runtime attachment, local stdio `tools/list` + `tools/call` dispatch,
queued task id, unknown round rejection, unknown task id error, batch bound and
local cancellation.

A separate live probe used relay OAuth 2.1 PKCE against `/mcp`, selected the
source device with `deviceId`, called `send_file`, then `transfer_get`. It
completed 3 B and 8 MiB through the real loopback relay and two agent processes:
target `settled locally`, one destination file, matching SHA-256, and
`peerReportedCompleted`. A separate 8 MiB immediate-cancel probe returned
`cancelled: true`, `transfer_get` phase `interrupted`, no destination file and a
retained private stage. A one-round `sync_dir` live probe also reached
`peerReportedCompleted` with matching SHA. A two-round `sync_dir` probe
transferred `a.bin` and `b.bin`, both `peerReportedCompleted`, with two
destination files and matching SHA-256. This proves the sequential preapproved
batch path, not a directory diff/apply. The live probe did **not** exercise a
directory scan/diff/overwrite/delete, a full cancellation race matrix, two
machines, Linux, scale or deployment. Evidence:
`mcp-live-verification.json` under the lease-handoff evidence directory.

The subsequent [target-parent and cancellation increment](windows-fleet-target-directories.md)
adds explicit `transfer.createParentsBelow`, whole-batch prevalidation,
pre-start/queued cancellation and Runtime lifecycle closure. Its final candidate
hash, live matrices and native SQL readbacks are recorded separately; old
085254 evidence is not attributed to the new binary. Directory scan/diff-driven
apply, deletion and empty-directory mirroring are still not MCP capabilities.

The four tools are absent from the stock/default catalog and from builds without
`fleet-core`; the relay cannot mint grants or paths for them.
