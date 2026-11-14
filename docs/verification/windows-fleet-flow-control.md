# Windows P1 authenticated DATA window — candidate increment

## Implemented

`SourceWindow` now composes actual Runtime SourceFile IO with authenticated READY/ACK and retained original ciphertext. READY chooses a window no larger than8; full windows do not read/encode more source content. Only authenticated monotone contiguous chunk-end coverage releases cache. Retry borrows exact old AEAD bytes. Selective received/STATUS Completed/early final ACK cannot replace final completion. FINISH requires all DATA coverage/drained cache, then AwaitingCommit still requires its separate final ACK.

Live Target HostReceiver exposes cached ready_record/ack_record under current file/parent/DB/revision/lease checks. Even a cached frame is not returned after failed current checks. Controls reuse the existing gate→DB try/no_wait helper, existing_fenced and restored busy_timeout, not journal() or new SQL writes. The helper itself changed ONLY to pub(super) visibility. Active P1 flow does not yet support renewal; refusal preserves the original session. No persistent metadata or wire schema change.

The sole3 new Rust modules are source_window.rs/source_window_tests.rs/flow_control_tests.rs.7 existing source files changed: mod, source, source_file, source_tests, receive, receive_tests, commit_admission. Exact old-a879/new diff was captured and checked; Runtime/wire/crypto/lease/journal implementations were not changed. The previous a879 real executable and original inputs remain archived, not overwritten by the shared target test filename.

## Frozen results

Evidence: `artifacts/fleet-p1/window-20261113-201659/` (ignored local data).

| Verification | Passed |
|---|---:|
| All features/all targets |548|
| Default/all targets |62|
| API contracts |76 (6 positive+70 compile-fail)|
| Release fleet components including P1 |486|
| Exact new source-window filter |17|
| Exact new Target-control filter |8|
| Explicit128MiB window probe |1|
| Node/OpenSSL canonical fixtures |2|
| Unchanged CI validator |13|

Strict fmt/clippy passed.25 new normal tests plus1 explicit ignored scale test were added.486 is a combined component count, NOT independent P0/platform sign-off. Tests include READY gating, smaller peer window, exact retry, selective coverage, invalid/midchunk/beyond-encoded/fresh-regressive ACK, authenticated older sequence, tamper/wrong key, early final receipt, expiry, revoke, Runtime shutdown, changed source, cached Target controls, duplicate DATA, invalid READY, DB-mutex fast failure, successful read-only SQL-writer coexistence, failed EXCLUSIVE SQL reads and5000ms busy_timeout restoration.

Real local SourceFile→window→Target v9→encrypted final ACK:

| File bytes | Maximum pending records | Release elapsed_ms |
|---:|---:|---:|
|0|0|857|
|1|1|131|
|131073|2|168|
|8388608|2|3415|

The small-file test reverses each DATA batch. Target coverage ACK does not free holes; contiguous coverage later drains correctly. These times include local Target IO/settlement and are NOT network throughput.

Real128MiB incremental fixture→SourceWindow→authenticated peer decoding→final peer statement:134217728 bytes,2048 records, maximum8 retained records/526144B ciphertext,4517ms stream loop. Fixture generation excluded. No full-file Vec is built by this scale test; it is NOT128MiB Host settlement,1GiB source or network/production data acceptance.

Separate same-binary memory trial:4563ms stream/5702ms whole process,103 samples, max sampled PrivateMemorySize64=2256896B, max observed kernel PeakWorkingSet64=8036352B. Each sampling iteration waits20ms plus query overhead. This is not an exact private peak, exact20ms cadence or total OS cache footprint. The526144B retained-ciphertext bound excludes controls/replay/metadata, transient encode/plaintext buffers and caller/socket copies.

New actual release TEST SHA256:

`427ea425cfcb7251d49d2884cd23c38154892e7446eb71311d1caffa7ea91bc5`

Previous actual release TEST (archived before this increment):

`a879cbb17a31b6efee4e3468023ad3217ddeca68f32dcafd551c185987bc2996`

80 declared source/config/contract inputs were frozen, copied as original bytes, and checked unchanged after execution. AGENTS.md and docs/design/fleet-transfers.md are NOT in that80 list: two stale P0-only/missing-window sentences were separately corrected with raw-before copies and explicit old/current SHA documentation-amendments.json; no frozen input/test receipt was rewritten. Source remains uncommitted; test artifacts are not a release/commit qualification. Existing production CLI/GUI hashes, CI, dependency versions and canonical fixture bytes remain unchanged. Historical stage1GiB/8 old-reader results were not rerun or relabeled fresh evidence.

## Errors and diagnostics retained

- One read-only grep regex escaped incorrectly; one read offset exceeded the actual222-line file. Both stopped before downstream edits; corrected by bare identifier/actual source range.
- New expiry test initially lacked its cfg(test)-only internal seam; flow-negative.log captures compiler E0599. Added that seam, without any public bare-time API; corrected tests passed.
- Preliminary delta auditor used .NET ReadAllText relative to process cwd rather than PowerShell location. Original helper and explicit tool-result excerpt are retained; Resolve-Path absolute paths fixed it. No code/fixture was changed to satisfy the auditor.
- Documentation supplement initially assumed those2 documents were frozen inputs. Validation refused that false assumption; actual list was inspected, and they are explicitly labeled separate non-frozen docs. Original80 hashes still match.
- Outer Fabric120s completion was only shell spill; actual task980d9f64 exited0 after all steps. No duplicate run or timeout relaxation.

## Capability boundary and next step

No Advisor consulted, no read-root request, new service, global credential/trust changes, remote selection, commit or push. Default-off fleet-core still adds no fleet MCP/CLI/GUI endpoint or `/fleet/ws`; legacy25 tools and BRC `/ws` are unchanged.

This completes the bounded DATA-stage flow increment, NOT machine-to-machine transfer. Next: separate authenticated channel in the EXISTING relay and an IO pump with bounded socket allocations/one send-copy and responsive control input. Initial-epoch-only transfer cannot be promoted to arbitrary long/1GiB operation without actual lease coverage or coordinated renewal. Real relay+A+B processes, two-host/Linux and production data remain unverified.

See [flow contract](../design/fleet-flow-control.md) and [source IO baseline](windows-fleet-source-io.md).
