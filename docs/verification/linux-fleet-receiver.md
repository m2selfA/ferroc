# Linux fleet anonymous receiver candidate

This increment adds an explicitly selected Linux receiver backend. The default
named-stage APIs retain their prior behavior. This is a candidate implementation;
completed tests and process evidence are recorded below without inheriting old
Windows, C primitive, TLS, or scale results.

## Local approval and ownership

A Linux target must set `transfer.linuxAnonymousStage: true`, with the existing
explicit `dataRoutes`, local lease clock approval, and private absolute `hostDb`.
Source-only configurations cannot request this mode. Replacement jobs are rejected
before connection/receiver admission. Target parents must already exist. The
existing authenticated socket, preapproved job, peer pins, original SetupLease,
one-use route ticket, Runtime, host fence and records remain mandatory. No relay
message can select the backend or supply local file permissions.

`SetupLease::into_linux_anonymous_receiver` transfers the same records to the
same Runtime's host. Admission commits a logical StageReference and metadata
schema **11** before creating `O_TMPFILE` with `openat` on the checked parent.
Ordinary database/key/marker file checks still require one link; only the live
anonymous stage accepts link count zero before publication and one after it.

The recorded `.ferroc-fleet-alloc-<uuid>` path is a liability identifier. It is
never created as the anonymous stage and cannot reopen/recover its inode. A
collision at that logical name refuses further IO. Closing the final unlinked FD
lets Linux reclaim those bytes; the journal keeps the entire byte and slot debt.
Inventory reports `AnonymousStageUnobservable`, and absence reconciliation cannot
release this kind of allocation. The record is deliberately not a resume token.

## Publication and receipt boundary

The existing gate-held complete hash, lease/object checks and zero-wait SQL
admission write v7 CommitUnknown before one native link attempt. Linux publication
uses the retained original FD via `/proc/self/fd/<fd>` and `linkat` with
`AT_SYMLINK_FOLLOW`, into the checked parent FD and one filename component. It
requires O_TMPFILE support and procfs; it never retries with pathname rename or
AT_EMPTY_PATH. EEXIST leaves the existing target intact. Other syscall/fsync
errors also retain Unknown and the full reservation, with no automatic cleanup.

After linking, the same live owner goes through the existing independent v8
readback, v9 settlement and once-encoded ACK. Metadata **11** is preserved across
all transitions and reopen; older readers must reject it at entry. Completion
logs distinguish source authenticated peer claims from target local historical
settlement; verification compares both full receipts, SQL and actual file SHA.

A Linux directory FD does not block its directory or ancestors being renamed.
Checks can detect replacement at their observation points; they do not make
pathname publication atomic with ancestry validation against another process.
A move after link can leave the target in the old parent while the operation
returns an error and retains full debt. External writes/mmap can still change
published content. Parent fsync is attempted but final receipt durability stays
**Unsupported**: no power-loss or hostile-local-writer guarantee is asserted.

## Verification record

Evidence root: `artifacts/fleet-p1/linux-target-20261116-173539/`.

- Primitive probes used identical C source on delta and 3dv0. They established
  original-FD linking/EEXIST preservation and rejected source-path rename or
  retained-parent-FD exclusion as equivalent implementations.
- Native receiver: **10 passed**; setup config: **11 passed**. Windows original
  HostReceiver directed regression: **152 passed, 11 ignored**, serial. The
  independent Windows frozen matrix passed **848 all-features / 63 default /
  97 docs**, Node three oracle groups and 13 CI checks; **284 inputs / 15 gates**
  and product hashes were independently recounted. These counts belong to that
  archived snapshot, before the later test-only Creator fixture correction.
- The debug stock CLI
  `9c10d9cccf7ffb75a366a6da7b4728738d4e2e760e62b9b5853759d4eb0ede06`
  completed independent relay/source/target rounds at **3 B / 8 MiB** on both
  delta (WSL Linux/ext4) and 3dv0 (Manjaro Linux/XFS), then actual **3dv0→delta**
  cross-machine 3 B / 8 MiB. Full source/target/SQL receipts and target size/SHA
  match; live debt is zero. The cross-machine route is an owned SSH forward to
  loopback, not a public-TLS claim. All owned children/forwards were stopped.
- Every **151** repository Rust/Cargo source input maps to the compiling tree.
  Native old-reader testing ran a real older executable: schema10 positive
  control opens, schema11 rejects at entry, DB/row/target bytes stay unchanged.
  A unit metadata-downgrade check is not substituted for this executable probe.
- A separate **release** ELF
  `88a063a6b59606d74dc001b12831801f5736ae692eef22399d797d4f0a80ef3b`
  maps to `release-sources.tar` (**284 archived inputs**). Its static maximum
  GLIBC requirement is **2.17** and the same ELF passed initialize, **25** tools
  and write/read in an existing rootless Podman, fixed-digest manylinux2014
  container. Container cleanup is recorded; no new service was installed.
- That release ELF completed a fresh-identity/database **3dv0→delta** staircase
  at **0 / 1 / 131073 / 8388608 / 134217728 bytes**. Per-role `/proc/<pid>/exe`
  hashes identify the actual image. Each level matches complete source/target
  receipts, SQL, target SHA and zero live debt. Independent checks reject
  **30** tampered receipt/role/binary/debt controls without changing originals.
  Source age at observation was **3.690 s** at 8 MiB and **38.470 s** at128 MiB;
  this includes source-process startup, not pure transfer throughput. Observed
  peak RSS at128 MiB: source **14820 KiB**, target **16964 KiB**; relay is recorded
  separately. These forwarded-loopback results do not replace public-TLS tests.

## Rejected 1 GiB and fixture-only correction

The new release's **1073741824-byte** round is **not an end-to-end pass**.
Source logged `fleet receive failed; effects may exist` with no completion
observation. Target logged its full local receipt and SQLite has **Completed**,
no live StageReference, full file size and matching SHA
`468dd8f6369807c1da044f5f8c5ded1893ac65e0c08f2e0dfba8ebf0425c0399`.
This is target settlement with source completion missing, not retained stage
liability and not a source-observed receipt. Read-only diagnostics and both log
archives are separate from the five passing levels. Generic WS error redaction
prevents assigning the underlying cause; neither the 300s ceiling nor the static
2s target grace/relay-close race alone proves this round's root cause. No blind
retry, changed deadline, deletion or manufactured source receipt is used.

The first full Linux matrix was rejected by two Creator test fixtures. Linux
SQLite VACUUM INTO and copying to a new path produced **0644**, so native privacy
validation rejected before the intended object/fence assertion. A single-variable
0600 control demonstrated that entry barrier. Only `src/fleet/creator_tests.rs`
was corrected to set0600 on those private test copies; assertions and product
permission checks remain intact. The Windows Creator group passed **15** after
this correction. The older release runtime is unchanged: its binary is not
represented as containing the later test-only correction.

The first corrected full-Linux runner still invoked rustup's missing clippy
component and was separately rejected before tests ran. The new runner calls
existing `/usr/bin/cargo-clippy` explicitly, without installing components or
changing defaults; strict all-target clippy passed. The unfiltered serial Linux all-features/all-targets run was **rejected**:
after strict clippy and the 15 Creator cases passed, the full runner did not
produce its expected 693/0/24 final summary within the observation budget.
The last sampled cases were existing relay-channel tests; the log advanced
between observations, so the sampled futex wait does not establish deadlock.
PID/start ticks, CPU/wchan, log tail and the original test executable were
archived; verified worker/Cargo/test processes were then terminated. This is
an open full-Linux regression gap, not a pass or a skipped test. Separate
observer 120s and missing-script errors do not substitute for that test result.

Rejected compilation, fixture, image-observer and validation-script rounds stay
in the evidence root or isolated remote candidate directory. The startup image
observer was corrected to tolerate fork/exec transition and still requires the
actual child image SHA; the failed earlier observation is not a transfer pass.
Installed agents/relay/Caddy were not replaced; no commit or push.

This receiver/release increment does not implement Linux replacement, restart
resume, remote directory approval, QUIC/NAT, or production qualification. The
later [explicit Linux parent creation increment](linux-fleet-target-directories.md)
has a separate source snapshot, binary and directed/live acceptance; its results
are not inherited by the earlier release.
The existing 300-second route/IO maximum is unchanged.
