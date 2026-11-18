# Fleet relay EOF drain: accepted-tail preservation

## Scope

This increment changes only the relay's per-pair forwarding ownership. It does not add a wire message, retry, reconnect, lease extension, receipt, stage cleanup, debt reduction or callback API. A zero outstanding forwarding count means only that this process has no further accepted frame to attempt on the peer socket; it proves nothing about peer read, authentication, crypto, file write or settlement.

## Static fault chain

`run_target_inner` sent its final local-commit ACK and then dropped `FleetLink`. `Claim::drop` retired the whole pair and set the closed watch. The connection loop used a fixed `read`/`write`/`monitor` selection in which the closed branch preceded the writer, so a read EOF could cancel the other socket's writer with queued frames still pending.

## Native red

`artifacts/fleet-p1/eof-drain-20261116/red2/verification.json` (293 inputs, `af65565f…0d507b`, test image `23590ef9…baf4ab`): real TCP/WebSocket/AEAD, original queue 8, original 5 s write budget, 1 MiB authenticated DATA. Queue full and actual sink `Pending` were both observed; the sender then closed. Only **458752** of **1048576** bytes arrived and both actors exited with connection-reset/route-closed errors. This is a channel result, not a v9 file-settlement test.

## Change

`ForwardGate` keeps a synchronous watch state: a closing flag and, per role, a count of frames admitted for forwarding but not yet finished with their fixed socket writer. Admission and the EOF cut share one state modification, so a frame is either counted before the cut or refused after it. Each `ForwardFrame` owns a non-clone permit dropped when the original `sink.send` future completes, errors or is cancelled.

On a transport EOF or close the role stops admitting new work, keeps its own writer and the peer's previously admitted tail alive, and waits at most the original `IO_BUDGET` plus the original pair deadline. Explicit close, route expiry, pause/revoke, routing/format errors and backpressure faults remain immediate hard failures and never enter the drain path. A frame accepted after a cut is held rather than forwarded.

## Verification

`artifacts/fleet-p1/eof-drain-20261116/green2/verification.json` (294 inputs, `54238782…a5b8cd`, one test image `0c7362d7…f71ec7` for all test gates) on native Linux release:

1. The unchanged red test now delivers all **1048576** bytes with the same queue and 5 s budget, while still observing queue-full and native sink `Pending`.
2. Seven ownership contracts cover empty EOF, per-direction drain, cancelled blocked enqueue, queue drop, dequeue-kept inflight write, aborted task, 16-round concurrent cut, and multiple waiters.
3. The three default-ignored native stress probes (`never-read` deadline, pause/resume SHA/no-loss, revocation before deadline) were explicitly run: 3 passed, 0 failed. The earlier round that predicted 5 passing was rejected before execution and is preserved; the correct default enumeration is 1 passed / 3 ignored.
4. Strict clippy and fmt passed; the whole existing `relay_channel` suite passed.

Windows candidate: `artifacts/fleet-p1/eof-drain-20261116/windows-green2/verification.json` — fmt, strict all-target clippy and the same seven ownership tests passed.

## Limits

This closes only the relay tail-drop mechanism under a real local TCP/WebSocket channel. It is not proof of the historical 1 GiB asymmetric settlement cause, not a two-machine or production acceptance, and it does not inherit glibc 2.17 qualification. The earlier `strace -c` throughput probe remains rejected: Source reset, Target unpublished, full 8 MiB journal debt retained, and its zero received checkpoint is a grouped SQL value rather than a physical byte count.
