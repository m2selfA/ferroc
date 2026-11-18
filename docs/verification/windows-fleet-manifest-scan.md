# Windows P2 bounded manifest observation verification

Status: frozen Windows regression, actual 273-entry tree probe and postcheck passed.
This is a LOCAL component candidate, not remote scan authority, network sync_dir,
two-host, Linux or production acceptance.

## Scope

`Runtime::scan_fleet_manifest` is a synchronous LOCAL read under existing Policy
and registry-to-fs_gate lifecycle locking; no SQLite locks or extra service.
Windows-only; other platforms explicitly fail rather than silently falling back.
The original root spelling/ordinary ancestor handles are checked, even when
Policy canonicalization could hide an in-policy junction.

Budget: manifest100000 entries/16MiB aggregate logical paths, depth128, default
64MiB hashed bytes, hard1GiB; content reads at most64KiB. Global name count includes
ancestor queues. Errors/cancellation return no partial manifest and never write,
delete, clean up or release transfer debt. The historical no-rules probe below
remains unchanged; explicit exact-subtree rules, bounded metadata pages and local
CLI were added later: [directory entry](windows-fleet-directory-entry.md).

## Native tests

16 normal tests cover nested files/empty directories/zero bytes, actual file SHA,
second scan zero changes, same-size/same-mtime checksum change, exact global entry
budget, path/depth/hash budgets, outside/missing/traversal roots, junction at root
and ancestor/child, multi-hardlinks, non-UTF8/reserved names, cancellation after
one64KiB chunk, truncation, native root-rename denial and release, Runtime shutdown
and transfer-disable, directory mutation, and scanned manifest to add-only plan.
The last test creates no target and does not imply actual directory apply.

## Non-snapshot counterexample

A native writer changed the already-read prefix at65536 bytes and restored the
original mtime. The observation returned the original read-sequence SHA while
subsequent disk bytes had a different SHA. Original bytes/mtime were restored and
rescanned. Result is explicitly ReadSequence+ExactUtf8Unqualified, not a snapshot,
latest-content proof or target naming qualification. No security claim that same
size/mtime checks exclude external processes or mapped writers.

## First failure and tooling

Initial focused run15passed/1failed because cmd mklink/J interpreted `tree/link`
as a switch. Fixed only the fixture's Windows path composition; no product
reparse admission was relaxed. Failed actual TEST0ac967d1 and116source snapshots
are retained under `artifacts/fleet-p1/scan-fixture-failure-20261114-062520/`.
The first inline archive recipe had a regex escaping failure after copying source;
that partial directory was kept. A standalone literal-path archive helper fixed
it and recorded the real failed EXE. Initial test API/import/lint failures and an
unneeded postcheck derivation anchor failure were corrected before execution.

## Complete frozen evidence

Evidence: `artifacts/fleet-p1/scan-freeze-20261114-063337/`.

- 116 unique frozen inputs; current and raw copies SHA-256 match.
- all-features624 / default62 / docs92 / release-fleet562 / channel25.
- Explicit native tree1 / native backpressure4 / three-process1 (four datasets).
- Node/OpenSSL oracles2 and CI validators13 passed; fmt/strict clippy passed.
- Scoped audit112files/45local links; postcheck passed and binds63 evidence files.
- TEST SHA-256: `316a290fe9b34ea1d2039ab4ae2a54daac25b33e77615ee949bf6f7b38e9ce1d`.
- Previous TEST `4a8ce311b1b75668923884553a197897fe7e5585b668d97eb90c1eebcc08db59`
  preserved. These are test executable hashes, NOT Git commits or release binaries.

The explicit probe created a real273-entry/257-file generated Windows tree and
hashed8421632 bytes. Every observed file SHA matched an independent whole-file
read at that observation boundary. First scan125ms; cache state was uncontrolled,
so this is not a disk/network throughput benchmark. The second checksum diff
selected0changes. Same-size `d15/f15` rewrite with restored mtime selected exactly
that1file. The owned workspace was removed and absence asserted. This is not the
older100000-entry metadata-only experiment and not production data validation.

The existing four-data-size relay/Source/Target subprocess regression also passed;
that is separate evidence from the local tree scanner. No scan result was sent
as a remotely authorized manifest or applied to a target tree.

Cancellation checks the atomic flag at chunk/enumeration boundaries. The5ms timer
belongs to the async executor token waiter, not this synchronous scanner. Neither
provides a hard real-time bound or interrupts an OS syscall or mutex wait.

Static-confirmed: no non-Windows fallback; same Policy/Runtime lock ordering and
no new network authority. Locally verified: Windows actual files/guards/errors,
read-sequence counterexample, existing loopback relay probes. Not validated:
Linux implementation/platform qualification, two-host transfer, native target
namespace qualification, operational issuance or production-scale directory sync.
Independent source sign-off was not added; no Advisor consultation was made.

No schema, cryptography, lease, journal, receiver/pump, production executable,
default feature or CI changes. Historical reserve_commit2.929s remains open.
No commit/push.

