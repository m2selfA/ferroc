# Explicit protocol-sized chunks and accurate ciphertext capacity

Local setup and relay DATA approval configuration now accept explicit `chunkBytes` up to the existing protocol `MAX_DATA` (**262144**), using the same ceiling as `FileGrant`. Existing65536 configurations remain valid and byte-identical in canonical grant input; the field remains required. The pure `sync_grant` planner intentionally retains its separate65536 limit. No wire/version/schema/deadline/lease/permission change or additional service is introduced.

Chunk size remains authenticated grant authority: the same JobSpec with a different chunk produces a different grant digest, so the peer must independently approve that exact grant. Unit tests cover65536/65537/262144 acceptance and0/262145 refusal at both configuration load and materialization.

## Capacity bug and native verification

A real source file and authenticated peer test filled8 original256KiB ciphertexts. Actual retained bytes were **2099008**, while the old public capacity report returned **526144**. `SourceFile::flow_chunk_limit` still used `io_chunk_bytes().min(65536)` after actual reads had already been changed to honor the grant. Removing this stale clamp fixes the report; the test retains its original equality, exact-retry, backpressure, plaintext decode and FINISH/final-ACK assertions.

`SourceWindow` still retains at most8 ciphertexts. The bound is `window*(grant_chunk+232)`, excluding metadata, controls/replay, transient plaintext/encoding, caller copies, socket/relay queues and global process memory. A64KiB grant's8-frame bound remains526144B. A256KiB grant's bound is2099008B. This source/peer test does not prove target private IO or global memory use.

Evidence root: `artifacts/fleet-p1/large-chunks-20261116/` (local only).

- Mandatory config red on old guard is retained with its actual test image; replacing only the local configuration guards passes.
- Capacity red2099008≠526144 is separately retained. Windows config12 and flow20 passed/1 original ignored; Linux config13 and flow18 passed/1 original ignored. Linux lacks the two existing Windows-native Host tests; they are not newly ignored. Strict clippy passed on both.
- Two auditor mistakes are preserved and corrected: assuming0 ignored on Windows, then copying Windows enumeration21 to Linux (actual19). Same-image ignored-list and target-specific exact counts establish20+1 vs18+1. Product assertions were not relaxed.
- Final290-input green snapshot4e4ec6a6…6225d produced native Linux candidate **6fe672b22b62725c8e426ff9e5fa791d9d2e054ad2866037e0d050b7896fb5c4**, with actual package rebuild after the separately documented shared-target Fresh issue. It does not inherit glibc2.17 qualification.

## Actual link and scale control

One candidate is used for source/target/relay, fresh encrypted identities and journals per row, real pairing and local approval, original `SingleOwner`/NoRenewal and <=300s route/IO budget. Fixture generation and final independent file hashing use streaming1MiB buffers. Every row requires source authenticated completion, target local completion, SQLite receipt and actual target SHA equality; failure preserves raw role logs and a read-only SQL/file post-state even if Target has already settled.

The sequence is8MiB and128MiB at64/256KiB with4 frames; additional128MiB64KiB×8 and256KiB×2 rows keep the same512KiB plaintext window. Only a successful128MiB256KiB row with conservative budget margin starts a fresh1GiB row. There is no retry of a failed owner and no deadline extension. Source-launch to both completion observations and sampled per-role kernel VmHWM are recorded separately from fixture/identity/auth setup time. These are local real processes, not two-host/TLS/production or a global memory guarantee. All six rows passed full source/target/SQL/actual-file receipt reconciliation and an independent postcheck (with all owned children stopped):

| Bytes | Chunk | Frames | Source launch→both completion observed |
|---|---:|---:|---:|
|8MiB|64KiB|4|4.715s|
|8MiB|256KiB|4|6.593s|
|128MiB|64KiB|4|48.809s|
|128MiB|256KiB|4|50.515s|
|128MiB|64KiB|8|55.880s|
|128MiB|256KiB|2|42.734s|

These are single observations with source startup included. Larger chunks did not resolve throughput; no statistical speedup or1GiB root-cause closure is claimed. Even the fastest observed256KiB128MiB row lacks conservative margin for1GiB under the unchanged300s cap, so the planned1GiB row was **not attempted**. No failed owner was retried. The historical88a…1GiB remains TargetCompleted/Sourcefailed, independently preserved. A subsequent read-only aggregate `strace -c` probe was rejected: Source reported `protocol-reset-without-close`; Target had no published file or receipt and retained its full 8MiB journal reservation in transferring/v4. Its received checkpoint of zero does not prove no DATA bytes were written; anonymous bytes disappear after last FD close while journal debt remains. Both test children stopped. This instrumented failure is not a throughput result or proof of final-ACK loss.

A separate native TCP/AEAD test reproduced the suspected EOF tail loss with the original queue8/write5s budgets: 1MiB was sent, only 458752B arrived, queue-full and actual sink-Pending were both observed, then sender EOF retired the pair. Both actors exited. This is a channel red-light result, not a v9 file-settlement test or closure of the historical1GiB cause. Evidence is `artifacts/fleet-p1/eof-drain-20261116/`; the bounded-drain candidate remains in an isolated source snapshot while its positive and hard-cut controls run.

The combined 292-input source snapshot passed Windows852/63/97 plus Node3/CI13 and native Linux727 passed/24 originally ignored; independent source, log, image and count checks passed. Local raw evidence is exported under `artifacts/fleet-p1/directory-chunks-20261116/linux-export/`. Initial Linux formatter-entry and duplicate-enumeration auditor rejections remain separate. This documentation status addendum changes no Rust/Cargo input and does not certify the isolated EOF candidate or inherit glibc2.17 qualification.
