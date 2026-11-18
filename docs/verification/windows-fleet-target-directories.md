# Explicit target parent creation and batch/lifecycle corrections

## Scope and entry

`fleet-core` agent configuration can explicitly opt into:

```json
{"transfer":{"windowChunks":4,"hostDb":"C:/private/host.db","createParentsBelow":"C:/private/target"}}
```

The existing root and host DB must already be private. The option defaults to
absent and is accepted only with a local Target round, DATA routes and explicit
local lease authority. Loading configuration creates nothing. Every destination
must be below the approved root and fit the existing narrow ASCII name profile.
The option creates only missing ancestors of that exact, locally preapproved
job destination; not arbitrary peer-supplied paths or empty-directory mirroring.
No additional service, listener, wire message or authorization suite is added.

The original ticket-consuming Target `SetupLease` performs the operation inside
the real Runtime registry -> fs_gate. It rechecks local trust and lease before
and after, and lease admission around each directory syscall. Original root
ancestors and private parent handles stay open through receiver admission and
settlement. Creation uses the existing native private DACL at creation, not a
wide directory later repaired. Existing paths must be plain private directories;
reparse/junction, files, escape, reserved names and concurrent CREATE collisions
are rejected. The final destination is still created only by the original
stage -> hash -> native rename -> v9 receipt path.

On failure/expiry/cancellation, directories already created remain. No deletion,
rollback, debt forgiveness or directory durability is claimed. A successful
CreateDirectory followed by path observation does not prove atomic provenance
of that object against another same-user process between the syscalls. Retained
handles deny ordinary ancestor rename/delete, not external writes/mmap or a
sandbox. The original host performs its own fresh file/parent admission.

## Defects isolated with red tests

1. Unknown later batch round or exhausted capacity could leave earlier tasks
   registered. Entire local set/job/capacity/budget is now checked before
   registration under serialized admission; shutdown races cancel prior ids.
2. A pre-cancelled batch task could still enqueue setup. Enqueue and session
   consumption both check the exact live task; later rounds stop on first
   interruption/failure. Cancellation is marked before withdrawing a waiter,
   avoiding a competing oneshot-failure outcome.
3. `transfer_cancel` accepted ambiguous selectors and partially cancelled an
   invalid list. Exactly one selector and the entire bounded unique round list
   are checked before effects.
4. MCP used a separate `TransferTasks` table invisible to Runtime shutdown.
   Red test observed `Running` after shutdown returned. MCP and Runtime now
   share one atomically installed task table and reject replacement of an
   existing attachment. The original stop/cancel/drain ordering is unchanged.
5. Real two-file replacement exposed new-reader rejection of schema 10 on
   reopening the host. A second native red case showed v9 -> replace retaining
   schema 9. New reader admits 10; replace always raises the metadata gate to
   10 (never preserves 9); settled replace history cannot be read under a
   downgraded gate. Older binaries remain required to refuse 10.

## Evidence and exact provenance

Local evidence directory: `artifacts/fleet-p1/target-sweep-20261116/` (ignored).
Red logs and actual test executables are retained, including invalid test-filter
and host-fixture runs separately from the corrected two-case schema red run.
The red test binaries were archived, but their full source trees were not each
archived before the next edit; do not claim a complete per-red-build source
receipt. Final build/source mapping is independent of that limitation.

- Initial candidate `4B7B456D...4474565`, `cli-receipt.json`, 273 archived inputs:
  real OAuth MCP two-file nested creation passed, with four new directories;
  `nested-two/readback.json` independently compares both complete source/target
  receipts and current endpoint SHA, zero live stage debt, all processes exited.
  Post-completion cancellation returned false and left snapshots unchanged.
- The same candidate's `replace-two` failed on second host open; preserve it as
  failed, not a passing replacement proof. Runtime/schema fixes require the
  final candidate and fresh live probes, not relabelled initial results.
- Final acceptance requires the final candidate receipt, exact incremental
  source audit, full regression `verification.json`, matrix case `result.json`
  and separate native SQLite/endpoint `readback.json` to agree on hashes.
  The machine receipts, not a count copied into this text, are authoritative.
- Native directed coverage: private nested creation, original handle pinning,
  existing contents preserved, true junction, escapes/invalid names, concurrent
  creator, cancellation between mkdir calls and lease failure after a syscall.
  Setup tests additionally enforce source-role/no-ticket/expired/shutdown
  rejection. Cancellation tests use three distinct rounds, not duplicate ids.
- The read-only SQLite auditor has five synthetic positive/negative controls
  (receipt-id divergence, current same-size content mutation, retained stage,
  binary-hash drift). Its initial connection-cleanup failure is retained; the
  corrected auditor closes every connection explicitly with ResourceWarnings
  treated as errors. Synthetic auditor fixtures are not product executables.

## Remaining qualification

`sync_dir` is still a sequential batch of locally preapproved rounds, not
remote manifest scan/diff-driven apply. General deletion, rename planning,
empty directories, resume, stable external-writer exclusion and Windows parent
fsync are not implemented by this increment. Historical SQL scheduling and
final-ACK delivery gaps remain open. Linux candidate compilation is a separate
isolated delta snapshot; installed binaries/systemd are not replaced by these
checks. No two-machine/TLS/scale/deployment claim follows from loopback probes.
