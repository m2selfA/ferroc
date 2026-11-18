# Linux release candidate — 2026-11-17

## Exact candidate and source

- ELF SHA-256: `d8473b635729f53418dc38035b608f90027e9a714f5ed7f6cd36184c3a99ac75` (14,346,488 bytes).
- Source archive: `e5466ac3c8b5dede61d9bccffd26fd45e95ee162474b08e2cf9a86191ecd3abc`, **300 inputs**.
- Build: `cargo zigbuild --locked --offline --release --features fleet-core --target x86_64-unknown-linux-gnu.2.17 --bin ferroc`, on delta, isolated source/target/cache.
- Local evidence: `artifacts/fleet-p1/glibc217-20261117/` (ignored, not published).
- This is an uncommitted candidate, not a release tag or production deployment.

## 1. ABI and actual old-glibc userspace

The repository's unchanged `scripts/verify-linux-compat.py` assertions ran through
an explicit Docker-command-to-rootless-Podman adapter on 3dv0. Verifier SHA-256:
`17399748c2b70edae4ca25962ad25567d45132d41d64611e3b9c613d9bd6cfe8`.

Fixed image:
`quay.io/pypa/manylinux2014_x86_64@sha256:62eeff30ef134a85ec0f97109e008a319b0315ca5e8a6d754ee771556c02622a`.
The exact cached digest was used without network access. Runtime readback returned
`glibc 2.17`; x86_64 ELF, maximum GLIBC requirement 2.17, interpreter, allowed
libraries, absence of DT_RELR, and real MCP initialize/list25/write/read all passed.
The container was removed. `container-proof.json` binds the exact ELF and verifier.

Independent RPC negative controls rejected a missing tool, tool error, wrong file
readback, reordered replies, duplicated reply and truncated stream. Source archive
members and all 300 content hashes were independently checked against the frozen
input manifest (`evidence-audit.json`).

## 2. New directory CLI in the same glibc 2.17 image

The same ELF passed:
- paginated scan with exact-subtree exclusion;
- preflight two files/eight bytes, no target files created;
- overwrite refusal with no partial approval stream;
- missing parent refusal, explicit ancestor-first directory declarations without mkdir;
- FIFO rejection without blocking content reads.

All accepted NDJSON terminal record counts and stream SHA-256 were recomputed.
Truncated, duplicated and mutated streams were rejected. All containers were
removed. This verifies the directory CLI in old-glibc userspace, not fleet DATA
inside that container (`directory-proof.json`).

## 3. Stock CLI relay + two agents on native Linux

The **same ELF**, not a test executable, ran on 3dv0/XFS/loopback. Independent
processes used fresh random encrypted identities, explicit peer pins, setup-v2
local approval, fixed SingleOwner grants, real DATA tickets and existing pumps.
Each pairing/data/agent process image was hashed through `/proc/<pid>/exe` and
matched the candidate. All eight cases were independently re-read after exit.

| size | whole-harness elapsed | outcome |
| --- | --- | --- |
| 3 B | 12.142 s | completed |
| 8 MiB | 12.683 s | completed |
| 128 MiB | 23.193 s | completed |
| 512 MiB | 54.645 s | completed |
| 1 GiB | **98.360 s** | completed |

These are whole-harness timings including setup/pairing, not isolated DATA
throughput measurements. The original 300 s grant/route limit and 240 s completion
observation remained unchanged; no renewal or deadline expansion was introduced.

For every successful case, exactly one source `peerReportedCompleted` event and
one target `targetSettledLocally` event had identical job digests and complete
receipts. Target SQLite schema11 held one Completed row, the same receipt, no live
stage, and an anonymous settlement origin. Source and target file SHA matched;
two created parents were 0700 and target files 0600. All candidate processes exited.

1 GiB receipt ID: `b64e2057-9e88-4923-bd65-8c33b68616ea`.
SHA-256: `468dd8f6369807c1da044f5f8c5ded1893ac65e0c08f2e0dfba8ebf0425c0399`.
`parentDurability` remains `unsupported`.

Three additional 3 B cases passed expected rejection: parent creation disabled,
existing non-private 0755 intermediate directory, symlink intermediate directory.
They produced no completion events or target file and preserved the refusal state.

The old controller's fixture-size cap was extended for the scale lane; fixture
creation and hashing became streaming. Acceptance assertions, window/chunk sizes,
grants and observation limits were not weakened. No product peak-RSS claim is made.
`stock-postcheck.json` binds raw source/target logs, SQL observations and filesystem
postconditions; private identities/config credentials remain remote.

## Provenance and limits

The old cross-machine EOF workers were **297-input test builds**; they are not this
300-input release ELF. The Rust/Cargo delta is directory_cli.rs and its tests.
Unchanged runtime paths do not imply binary identity. The old two-machine 1 GiB
TargetCompleted/SourceFailed evidence is not superseded by this local success.

Windows frozen regression `cli-preflight-regression-20261117-085302` passed
862 all-features / 63 default / 97 docs, Node3, CI13, 300 inputs and independent
postcheck. This report and provenance/wording corrections are a later documentation
addendum: the original receipt is not relabelled to cover changed document hashes.
No Rust/Cargo input changed in this addendum.

Remaining: new-ELF two-host/public-TLS scale, Linux replacement publication,
restart resume, QUIC/NAT, GUI fleet integration and production qualification.
Container evidence uses the host kernel and rootless Podman, not Docker CI or a
legacy kernel. No service binary/configuration was replaced; no commit or push.
