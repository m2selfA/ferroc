# Windows P1 source-file IO — candidate increment

## Result and execution policy

The user explicitly stopped Advisor consultations and requested implementation. No Advisor was called and no plugin, read-root, credential, global trust or remote service was changed. The canceled Advisor path is not an independent source sign-off. Development now continues on the original P1 path rather than waiting for that activation or adding substitute P0 components.

`Runtime::open_fleet_source` and [SourceFile](../../src/fleet/source_file.rs) connect real approved source files to existing SourceEncoder/LeasedRecords. Real0B/1B/65537B/8MiB sources passed the local Target v9 settlement and encrypted ACK round-trip. Default-off `fleet-core` still exposes no fleet CLI/MCP/GUI/network entry; production CLI/GUI, legacy25 tools, BRCX1, `/ws`, CI/tag rules and dependency versions are unchanged. This is NOT operational machine-to-machine transfer.

## Implemented boundary

- Only Runtime constructs the non-cloneable lifetime-bound owner; only the fresh Source lease's exact job.source_path is used. No path override, imported File/fs_gate/Snapshot or raw writable handle.
- Runtime policy/transfers flag/terminal state, original source File and parent IDs, plain single-link/non-reparse objects and exact size are checked. Ordinary source files are not incorrectly forced to have private database ACLs.
- Existing registry→fs_gate lock order serializes each synchronous operation without taking a DB lock. Shutdown drains an admitted operation but not idle owners; subsequent reads/FINISH reject. Idle handles close on revoke/error/Drop.
- Each call reads at most min(grant chunk,64KiB), zeroizes its plaintext buffer and rechecks lease/object state around IO/encoding. Failure revokes the owner, closes File/parent and cannot reopen/resume it. Returned frames are encoded, not sent/ACKed/durable; caller queues are NOT automatically bounded.
- FINISH requires full cumulative encoded count/SHA. It proves that encoded stream, not a later source snapshot: abc encoded before an external same-size rewrite to xyz may validly finish the approved abc stream. A pre-read change to xyz instead prevents FINISH. No mmap/external-process immutability claim.
- No sender journal, restart-resume or SourceFile renewal API yet. Existing pure SourceEncoder renewal semantics are unchanged. Finite lease expiry fails closed rather than silently extending/restarting.

The original pre-edit fleet files and Runtime were copied before edits. Exact scope audit verifies only mod.rs/source.rs/source_tests.rs changed within the existing fleet set; source_file.rs is the sole new Rust module, with Runtime entrypoint added separately. Wire, crypto, lease, journal, Target settlement and canonical golden fixtures were not edited. Cargo.lock is unchanged by this increment; only the already-existing optional ring edge differs from HEAD.

## Frozen validation

Evidence root: `artifacts/fleet-p1/source-io-20261113-194149/` (local ignored data, not public release assets).

| Surface | Result | Evidence |
|---|---|---|
| All features/all targets |523 passed,23 ignored,14 suites|all-features.log|
| Default/all targets |62 passed,2 ignored,13 suites|default.log|
| API contracts |72 passed:6 positive+66 compile-fail|docs.log|
| Release fleet components |461 passed,20 ignored|release-fleet.log|
| New P1 source IO |19 normal test functions, plus one explicit ignored scale case|source tests within the above suites|
| Real128MiB source+authenticated record stream |134217728B,2048 records,64KiB max plaintext,4006ms stream loop|source-scale.log|
| Independent Node/OpenSSL oracles |suite1 historical and suite2 current fixtures both passed unchanged|node-oracle.json,control-oracle.json|
| Unchanged CI validator |13 positive/negative tests passed|ci-validator.log|
| Scope audit |2 positive permutations+4 rejection controls|increment-scope.json|
| Formatting/lint |cargo fmt check and strict all-features/all-targets clippy passed|fmt.log,clippy.log|

461 is a combined fleet-component count INCLUDING the19 P1 IO tests, not a claim that new P0 platform gates passed. The128MiB test uses incremental fixture writing, source encoding and authenticated decoding, not a128MiB in-memory Vec. It is NOT a128MiB Host journal settlement, relay/network transfer,1GiB source test or production dataset. Source setup/fixture generation is outside the reported4006ms stream loop.

A separate same-binary memory trial passed with4059ms stream loop and5525ms whole process.99 native samples observed maximum PrivateMemorySize64=1642496B and maximum observed kernel PeakWorkingSet64=7561216B. Each iteration waits20ms plus query overhead; it is not an exact20ms period, exact private peak or total OS file-cache footprint. Raw memory stdout/stderr and source-memory.json remain separate from the main scale run.

Frozen verification.json binds75 declared source/config/contract inputs before/after execution. New release TEST executable SHA256:

`a879cbb17a31b6efee4e3468023ad3217ddeca68f32dcafd551c185987bc2996`

Actual previous release TEST executable copied before rebuilding:

`6c458e237fdd382283ac51a18182148084b97a7ffec27badaf3a27b73bc352c6`

The source is uncommitted. These are test binaries mapped to the declared source snapshot, NOT a release/commit qualification claim. Current production release CLI/GUI hashes and CI rules were checked unchanged by the scoped auditor. This increment did not repeat historical stage1GiB or8 old-reader probes: wire/schema/Target code were unchanged, and their old receipts remain historical rather than being relabeled fresh passes.

## Errors caught, not waived

1. Initial test code used nonexistent PeerRecord::Data.plaintext; actual field is bytes, with Zeroizing<Vec<u8>>. Two compile-error logs are preserved. Tests now borrow that slice; product protocol was not changed to accommodate tests.
2. Initial handle-release test renamed only after finish consumed the owner, proving Drop rather than error-time release. It was strengthened BEFORE frozen validation to rename while the failed owner remains alive.
3. A preliminary inline scope auditor compared culture-sorted names to a hardcoded order and falsely rejected the correct three-name set. Its tool-result excerpt is explicitly labeled as an excerpt; the CI command after that throw had not run. An exact Ordinal set checker plus2 positive/4 negative controls fixed the auditor; CI then ran successfully. No code/fixture mutation or assertion relaxation was used to force a pass.
4. tasks.wait rejected an observation timeout above300000ms. The computation was not canceled/restarted; waiting with the documented bound returned the actual terminal exit0. The outer120s Fabric spill was never treated as completion.

The first postcheck receipt was valid, but its recipe would include the previous output in its own file-hash list on repeated execution. Before reuse that self-reference was excluded; the original recipe/receipt were retained and repeated readback is required. The current75 raw inputs and actual a879 TEST were also archived before any next increment, not only the old6c45 baseline.

## Remaining original P1 work

- Authenticated DATA-stage progress ACK/control entry and a bounded ciphertext window. Final ACK observation is currently after FINISH and must not be reused as early completion.
- Relay-only source/target channel in the EXISTING relay process, separate from legacy `/ws`, reusing Network proxy/TLS policy and imposing transport frame/message allocation bounds.
- Actual relay+A+B processes: auth failures, interruptions, cancel, no-clobber, changed hashes, final-ACK loss,0B/1B/cross-chunk/>99MB/1GiB, then two-machine/Linux and real production data progression.

Linux branches were not executed. No arbitrary SSH target was selected, no new service installed and no commit/push performed. Historical independent source sign-off remains absent, but Advisor activation is no longer a development dependency.
