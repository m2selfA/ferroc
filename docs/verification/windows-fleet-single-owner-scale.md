# SingleOwner relay scale and task ownership (Windows candidate)

## Verified baseline: real 1 GiB network stream

`artifacts/fleet-p1/single-owner-scale-20261115-105645/verification.json`
records five completed transfers through three independent LOCAL OS processes
(relay, source, Windows target), over loopback TCP/WebSocket. These are not
in-memory duplex streams, a cross-host acceptance, or product CLI processes.

| Bytes | Controller elapsed ms | Both workers / receipts / disk SHA |
| --- | ---: | --- |
| 0 | 616 | Passed |
| 1 | 626 | Passed |
| 131073 | 609 | Passed |
| 134217728 | 32201 | Passed |
| 1073741824 | 250625 | Passed |

The exact archived release test executable is
`B94B169D3BEACD1221A93E9815096ED3E4E9AE637912B0E78A4CC89F67E44FF4`.
Its 124 build inputs were independently rehashed and copied byte-for-byte into
that artifact's `sources/` after completion. Three relative-path copies initially
used the process cwd instead of the PowerShell cwd and landed outside that
subtree; `archive-path-correction.json` records the correction using an explicit
repo base and revalidates all124 original hashes. Primary transfer receipts and
file hashes were unchanged; the earlier copy-placement claim was incomplete. The task-registry implementation
below was added AFTER this baseline and is not attributed to that binary.
The two actual 1 GiB files independently hash to
`0BFD5DB49C6B8BEAF50A697AA0863D7EAB60DA901DCD5DD3E7568371B7CE63D6`.
The raw target log reports local settlement with slot debt zero. Both receipts
match in id, size, SHA and parent durability (Unsupported).

Both ends explicitly selected SingleOwner, used a one-hour lease, and ran the
unchanged default NoRenewal pumps. Route and IO caps remain 300 seconds. This
removes the earlier 60-second-grant blocker for this explicit local profile;
it does NOT remove deadlines, pause/revoke checks, AEAD or the fixed job term.
All identity seeds and time approval are PUBLIC cfg(test) fixtures, NOT an
operational signer, pin enrollment or a deployable fleet control plane.

Sampled OS high-water marks at 1 GiB: source 15417344 B, target 14532608 B,
relay 141832192 B. Samples can miss the final interval; these are observations,
not universal memory ceilings or proof of an allocator-wide bound.

## Background task component for the future MCP backend

`fleet::transfer_tasks::TransferTasks` is a bounded local library registry, not
four enabled tools. A local Rust Runtime attachment now exists; no product
CLI/GUI/stdio entry invokes it. See [Runtime lifecycle](windows-fleet-runtime-tasks.md). It uses the existing
Tokio runtime; there is no additional service. Admission returns an id without
awaiting execution; registry insertion precedes spawning, but a multithreaded
worker can begin before the caller receives the id. Clones share one id space. Workers own their futures;
dropping/timing out a task observer does not cancel execution.

- Capacity 1..128; retained terminal records count. Reject a retained duplicate
  job or full capacity BEFORE invoking its trusted local factory. Explicit
  forgetting is not journal recovery, quota release or permission to retry.
- Only explicit SingleOwner grants; worker budget positive and <=300 seconds.
  The actual worker still must authenticate, approve paths and admit native IO.
- Completion accepts only a typed authenticated PeerCommitObservation matching
  exact job digest, binding, size and SHA. It remains a peer statement: cloned
  historical observations are not new live capabilities or private-IO proof.
- Unknown encoded/coverage counters are null, not zero. Snapshot errors are
  bounded codes, not raw worker messages/credentials.
- Cancel is a local request; interruption retains unknown remote effects.
  It never reports remote-cleanup confirmation or control::Phase::Cancelled.
  An already accepted terminal receipt cannot be withdrawn by cancellation.
- Shutdown rejects new work and drains owned futures after dropping losing
  workers. This does not drain unrelated externally held host owners and cannot
  preempt OS-blocking IO. Panic and even a never-polled Tokio task drop their
  active-operation guard rather than leave the registry permanently running.

The native background test drives actual SourceFile/window + Windows receiver
through a real relay and checks the polled peer receipt against target settlement,
zero stage liability and 131073 actual output bytes. PUBLIC fixture provisioning
still does not constitute operational enrollment.

## Send boundary found by actual backend integration

The first native task compile was rejected: receive() held &Route across await,
and its RefCell/Cell retirement state was not Sync. Saved compiler/source evidence:
`artifacts/fleet-p1/single-owner-auth-closeout/task-send-red/` (static red test,
no failed executable claimed). A single short-lived mutex now couples the old
binding and observed-role bits. Clone remains a deep independent retirement copy;
no lock spans await, no unsafe Send, and retirement/renewal rules remain intact.

The single-owner SOURCE TEST worker now launches this owned background task,
waits by id, and records source-task.json. New release scale verification must
bind its OWN executable and source manifest; never relabel the B94 baseline as
having used the task registry.

## Verification gaps and rejected attempts

The earlier parallel all-features freeze was REJECTED (633 pass, 1 fail,
35 ignored): native_writer_after_v7_marker measured own2048ms, fixture lock0ms
against its unchanged 2s threshold. The exact archived binary's isolated
controls were27/24/24ms; that is not a root cause or a replacement full pass.
Do not attribute this to SQLite locking or claim this increment fixes it.
A stale archive-parser backslash, new-code large-enum lint, and incorrect test
shutdown return assumption were corrected with raw failures retained, not
silently counted as green.


A later task-layer full suite failed646/1/35 in the NEW native task test, not
that historical2s gate. The diagnostic replay measured33291ms from route
approval to server readiness with a30000ms route TTL, followed by
`fleet authentication rejected` before pumps started. The retained directory
contained a0-byte stage and no final receipt. Evidence and exact replay binary:
`artifacts/fleet-p1/task-regression-20261115-115152/`.
The fixture now approves only AFTER `server()` returns. The30s route and25s task
budget are unchanged; product authorization/IO deadlines and error redaction are
untouched. A test-only task-native JSON records initialization time, both pump
outcomes and the polled/native receipts. Diagnostic failure directories are kept.
This correction does not close the separate2048ms SQL admission historical issue.

Current increment regression/scale manifests are local artifact receipts, each
with exact binary paths and input hashes. Test counts must be bound to frozen
harness enumeration, not merely nonzero or inferred from a passing total.
Remaining: actual Runtime attachment/enrollment and MCP dispatch, large-file
cross-host acceptance, Linux target parity, production signing/packaging,
remote cancellation/cleanup confirmation, directory apply/100k real files,
non-loopback TLS, QUIC/NAT and restart resumption. No commit/push is implied.
