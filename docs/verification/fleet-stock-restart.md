# Explicit stock process restart — Windows single retained lineage

Verified on 2026-11-18: a real stock CLI transfer wrote an actual schema12 checkpoint; old source/target processes exited after forced target termination; fresh stock processes with a new job, authorization, epoch and sessions resumed the original named stage through schema13 migration and completed the file. This is **one Windows host over loopback, one retained lineage**, not a one-process fixture and not two-host, GUI, MCP recovery or production qualification.

## Implemented path

- `FleetHost::recover_retained_job` selects an exact stopped owner/job/revision under the exclusive same-database fence in explicit `RecoveryOnly`. Unrelated rows and ordinary clean-inventory/fresh admission gates remain strict. Historical received counts do not grant verified coverage.
- Local `round.recovery` binds `oldJob`, `checkpoint` and bounded `maxPrefixBytes`; the target must additionally approve `stoppedOwner` and `revision`. A source cannot supply those target selectors. The current prefix budget is at most 1 GiB; this budget is not a stock scale qualification.
- The existing `fleetRoute` dual-role presentation carries bounded optional public resume proofs. The relay correlates the locally preapproved condition and current authenticated socket role; it does not verify the endpoint lease or import authorization. Ordinary frames omit the resume field entirely.
- Each endpoint retains the real `PreparedSetup` private ephemeral until BOTH signatures validate through the Runtime-bound `ResumeSetupLease`. The original owner consumes its one-shot route ticket and transfers the same typed lease into the real source window or target receiver; metadata cannot reconstruct keys or live owners.
- The stock target explicitly enables `transfer.retainedCheckpointBytes` before DATA. Resume separately reopens/rechecks the original retained object, restores only the actually rehashed prefix, and uses the existing schema13 transaction to transfer exactly one full allocation to the new job. Source ACK boundaries use logical offsets while `bytes_encoded` counts only the suffix.
- No new service, default-on behavior, deadline extension, automatic retry or anonymous-to-retained conversion. The original route/link bound of 300 seconds remains unchanged. `transfer.mcp` recovery is explicitly rejected in this increment.

## Exact native verification

Source archive: `5652a9c6146bbad4e595345293716185bb564616110264e1836b4f270eb6eee5` — 353 inputs, 199 Rust/Cargo files; 15 existing Rust files changed and 3 Rust files added relative to qualified350.

| Same archived source | Windows | Linux |
|---|---:|---:|
| Exact unique selected native members | 130 passed / 0 failed | 130 passed / 0 failed |
| Disjoint existing actual TCP/WS pump members | 2 passed / 0 failed | 2 passed / 0 failed |
| Union checked for duplicates | 132 unique | 132 unique |
| Documentation tests | 104 passed | 100 passed |
| Independent native posterior mutations rejected | 10 | 10 |

Both platforms passed fmt, strict all-feature/all-target clippy, build/default-check and four Node/OpenSSL oracle groups. The selected native groups contain 16 new tests: 7 stopped-owner tests, 3 routing tests, 3 local recovery configuration tests and 3 Runtime/pending-proof tests. The supplemental WS functions contain several size/prefix loop cases; those cases are not counted as additional test members.

The Linux WS positive is deliberately **seal/intent then named-publication refusal with full debt**, not a completed Linux retained transfer. Native cryptographic fixtures retain their PUBLIC/synthetic-checkpoint labels; they do not supply the process evidence below.

Images:

- Windows native test: `972a01ad2f117a57424eb143b9d79a09dbfac96ca527a19fb481c569b0a245b4`.
- Windows stock CLI used by every live case: `414cde1074be7f0b4fcd02be8086b36a8e5b1d6129e0bade1633f7138d7144b3`.
- Linux native test ELF: `01a8a6ee7116c078e104b967b4407b571c80b2436249bc1f53c481a6f9a277c2`.
- Original Linux raw evidence archive: `a061ad849a30a45eba25a8f43a7bba906c950ae6d9397fb9d74a98b33f911340`.

The controller downloaded the original Linux ELF/log/source archive, checked its full SHA, reran the byte/member/log/source posterior and proved that each platform's two supplemental WS members are disjoint from the 130 selected members. These are targeted native results, **not a new unfiltered all-target regression or Linux glibc2.17/release qualification**. The older347 Linux full run remains rejected (837 passed / 1 failed / 24 ignored, helper readiness cause open).

## Real stock process cases

Each case has independent random encrypted identities, explicit fingerprint and endpoint approvals, local wall-clock approval, a fresh relay database and target host database, and its own logs/SQL. The supplied wrapping key stays in the process environment, not argv or the report. All nine process-image observations per accepted case match the frozen Windows CLI. Old source/target PIDs are confirmed exited before the new pair starts; a new relay process also opens the same relay store. This is process-crash recovery, not a power-loss durability experiment.

| Case | Observed checkpoint | Result after new processes |
|---|---:|---|
| `live-success-16m-02` | 4,194,304 bytes of a 16,777,216-byte file | Only 12,582,912 new suffix bytes encoded; authenticated source receipt = local target receipt = actual schema13 receipt; target SHA matches; original stage and final target native fileIndex equal; old migration history + new Completed row, zero live bytes/slots |
| `live-wrong-owner-16m-01` | 4,194,304 bytes | Recovery refused; the entire SQL row remains identical; original stage bytes unchanged; no published target or completion event; full 16,777,216 bytes / 1 slot retained |
| `live-bad-prefix-16m-01` | 4,194,304 bytes | After changing one persisted prefix byte, recovery refuses on prefix validation; no target publication/completion; stage stays byte-identical to the intentionally modified pre-attempt stage; full 16,777,216 bytes / 1 slot retained |

For the prefix rejection, metadata takeover **has already committed**: `owner`, `revision` and `phase` change to the new interrupted owner. It is not rollback and does not create schema13 successor/IO rights. The source may have independently revalidated its own prefix before the target refuses; that is not target admission or completion.

Successful receipt: `5f6dca29-07ec-4c34-8102-36925627a482`, size 16,777,216, SHA256 `341aacac661ccb210720bedaa9ead5d668fe5ea41a73532fc147c71e34040df1`, parent durability `unsupported`. The original stage and final target OS fileIndex are both `281474981305402`. The 146,421 ms whole harness includes pairing, identity/configuration and process startup; it is not steady-state bandwidth.

The independent live auditor rereads actual SQLite, original logs, file bytes, prefix SHA, OS object identity and suffix counters. It rejects 13 report mutations for success and 12 for each refusal case. Exact reports and postchecks are under `artifacts/fleet-p1/stock-restart-20261118/v3/`.

## Rejected evidence and tooling corrections

- Native v1's unrelated-row fixture tried to allocate a second stage while unresolved debt existed; the ordinary gate correctly rejected it. The fixture was changed to an unrelated queued metadata row. Original source/image/logs remain separate.
- Native v2's Windows member table included one Linux-only configuration test. Enumeration rejected the round before that group executed. The v3 member tables bind exactly 130 unique tests per platform. Linux v2 was not executed.
- Live `live-success-16m-01` was rejected before checkpoint: Python `mkdir(mode=0o700)` created protected Windows child directories with OW/SY/BA ACEs. Product rejection was `private identity DACL must contain only one user ACE`. Actual ACL comparison showed 3 ACEs in that fixture versus one current-user ACE after inheriting the explicitly private test root. Only the fixture changed; accepted cases use the identical stock image. The original failed case and cleanup receipt remain intact.
- Controller v1 correctly reran the Linux native posterior but then falsely required regenerated JSON reports to have byte-identical line endings across Windows and Linux. Independent comparison proved exact JSON equality and only 29 CRLF differences. Rejected script/log/classification remain. Controller v2 preserves the original report bytes and requires both exact parsed JSON equality and exclusively CRLF/LF differences; source, image, raw-log, count and member checks remain byte-exact. It then reran all checks from a new extraction directory and passed.

## Remaining boundaries

The original single-lineage migration guard remains strict; repeated recovery lineage is rejected. A second crash during resumed transfer is not an automatic third recovery/checkpoint generation. No source persistent journal, remote grant issuance, automatic operator selection, retry/reconnect, two-host restart, GUI/MCP restart, QUIC/NAT or production qualification is provided. Linux retained named publication remains closed; anonymous stage debt is never reclassified, deleted or forgiven. Prefix hashes/receipts are historical observations, not snapshots against external writers, mmap or power loss; parent durability remains unsupported.

The final living documentation is updated after the archived native run. `acceptance.json` and its source/document map distinguish the exact 353-input archive from subsequent documentation-only edits; no test count is inherited by newer Rust/Cargo bytes. No commit, push or production service changes were made.
