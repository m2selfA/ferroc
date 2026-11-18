# LOCAL fleet directory entry: rules, pages and dry-run

## Capability and evidence tiers

`fleet-core` now provides `fleet-dir scan` and `fleet-dir dry-run`. They use the
existing Runtime, Policy and registry -> fs_gate native scanner. No identity
store, network, new service, MCP tool, grant signing, stage, SQL or transfer is
created. The default build does not expose this command; `--no-transfers` rejects
it. Linux now has a separately verified O_PATH/openat/procfs reader; see
[Linux evidence](linux-fleet-manifest-scan.md). The historical Windows records below
remain their original source/binary evidence, not Linux or newer combined freezes.

Locally verified directed tests: the first combined manifest run passed 26 tests
with one existing ignored tree probe; six real CLI subprocess tests passed. Strict
all-features/all-targets clippy passed. Later paging controls and the complete
frozen matrix have their own immutable logs/receipts under
`artifacts/fleet-p2/directory-entry-*` and `directory-regression-*`; do not reuse the
prior 830/63/97 transfer freeze to certify these new inputs. Test count discovery
excludes ignored tests, and execution must match the pinned counts exactly.

## Commands

```powershell
cargo build --locked --features fleet-core
# Explicit absolute LOCAL roots, each within --allow-dir. No relay connection.
ferroc --allow-dir C:/approved fleet-dir scan --root C:/approved/source --exclude-subtree cache --page-entries 256 --page-bytes 262144
ferroc --allow-dir C:/approved fleet-dir dry-run --source-root C:/approved/source --target-root C:/approved/target --exclude-subtree cache
```

Both roots must exist; missing/unreadable target fails the whole observation,
never acts as empty. Hash budget defaults to 64MiB **per root**, hard1GiB; no auto
widening. Checksum is default; explicit `--quick` is size+mtime heuristic and can
miss same-size/same-mtime edits. Both modes still read SHA in this scanner.
Changes, retained target-only names, manifest fingerprints, rules and ordered plan
fingerprint are descriptive. Existing-file changes are not replace approvals.
The roots are read sequentially, NOT jointly atomically. Empty directories can be
described, not mirrored/created. No apply, delete, rename or restart continuation.

## Exact subtree rules

Rules are exact root-relative UTF8 slash paths, excluding that path and all
component descendants. `cache` matches `cache/a` but not `cache2`, `Cache` or
`x/cache`. No globs, negation, gitignore, case folding or Unicode normalization.
Glob-looking `* ? [ ]`, malformed/traversal/reserved paths and duplicate rules
are rejected. Maximum128 rules and16KiB combined rule paths. Sorted length-framed
canonical rules have a domain-separated SHA256 fingerprint; both dry-run roots
use exactly the same rules. Excluded paths are absent on both sides, not deleted.

Visited-directory names still pass name validation, queue/path/depth budgets and
both directory-name stability reads. Only after that does the scanner skip opening,
traversing or hashing an excluded child. This intentionally does NOT inspect an
excluded subtree or prove anything about its descendants. Exclusion cannot bypass
root/ancestor Policy, lifecycle or transfer-disable checks. Errors/cancellation
still return no partial ManifestObservation and release no transfer liabilities.

## Manifest pages and NDJSON completeness

A page includes scanId, rulesDigest, manifestDigest, consistency, namespace,
offset, totalEntries, entries and nextCursor. Limits are checked against actual
serialized page JSON, including its envelope: <=1000 entries and<=1MiB. The CLI
reserves wrapper bytes and checks every actual output record too (LF excluded).
A single entry that cannot fit fails, rather than skipping/truncating it.

The 80-hex cursor contains an offset and HMAC-SHA256 tag. Its binding covers the
random owner ID, canonical rules digest, content digest, page limits and offset;
the secret is random, local and never serialized. Modified or foreign cursors
fail. Re-reading the same valid cursor is permitted for this immutable metadata
owner. Cursors do not survive the invocation, restart or rescan.

Paging retains the bounded whole manifest in memory (100000 entries/16MiB logical
paths). It is **not** a streaming filesystem scanner, unbounded tree index or
global process-memory limit. `ManifestPages::new` labels caller claims separately;
only an actual `ManifestObservation` yields `readSequence`. Neither is a snapshot,
current-byte guarantee, native target-name qualification or publication permit.

CLI output is NDJSON: header, source/target manifestPage records, individual
ordered difference/retained records, then exactly one `complete`. The terminal
record binds the count and SHA256 of all preceding **raw lines including LF**.
An error/broken pipe can leave a partial stdout stream; without the terminal
record and matching count/hash it must be rejected. The hash detects accidental
truncation/corruption; it is not artifact authentication or remote authorization.
No transport protocol accepts these records as grants.

## Tests and remaining work

Tests cover cursor offset/tag/owner/rules/content/limits binding, replay reads,
exact JSON byte caps, oversized-entry failure, empty and100000-metadata paging,
rule grammar/ceilings, native exclude-before-hash, unchanged global name budgets,
Policy/disable/cancel, default feature omission, actual scan SHA and add/replace
**descriptions**, target-only preservation, same-mtime checksum/quick contrast,
read-only files, missing target refusal, and stream truncation/tamper/duplication.
The100000 metadata test is NOT an actual100000-file tree. Any actual filesystem
scale probe has separate dataset/count/timing/CLI-SHA receipts; no network, Linux
sink, QUIC/NAT, restart recovery or deployment qualification follows from it.

Next: bounded remote directory observation approvals and per-file apply proposals;
Linux native receiver; authenticated direct-path/fallback; restart-resume design;
parent durability/external-writer limits; scale and production gates. The failed
128MiB public-TLS round remains failed with full stage debt and300s hard boundary.
