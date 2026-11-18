# P2 bounded local manifest observation

## Scope

Candidate Windows/Linux synchronous library API on the existing Runtime. It reads
an explicitly selected local root under the current Policy and transfer/lifecycle
gates, not a cryptographically authorized remote directory command. No new MCP, network route, service, signing authority, persistent scanner or apply path.
The separate `fleet-dir` CLI exposes these local observations only. Other platforms
return explicit unsupported errors. Linux uses O_PATH/openat and validated regular
FD procfs reads; it does not inherit Windows deny-delete handle semantics. See
[Linux native evidence](../verification/linux-fleet-manifest-scan.md).

## Safety and bounds

- Use the existing registry then filesystem gate lock order, with no SQLite lock.
- Retain native ordinary ancestor/directory handles throughout enumeration. Windows
  denies delete and rejects reparse points; Linux directory FDs do not prevent
  ancestor rename. Check current object IDs before/after content reads.
- Reject symlink/junction/reparse, special objects, non-UTF8 names and multi-link
  files. Use exact names, never lossy conversion, case-fold or Unicode merging.
- Reuse logical manifest path validation; reserved fleet names fail, not skip.
- Bound entries, aggregate logical path bytes, depth and total bytes hashed.
  Defaults: manifest ceilings (100000 entries/16MiB logical path bytes), depth128,
  64MiB hashed bytes. Hash ceiling is1GiB; callers may lower to0 for empty files.
  Queued names in ancestor frames count toward the same global entry budget.
  A second bounded name enumeration detects simple directory additions/removals;
  it still cannot detect every external modification.
  Read content in at most64KiB chunks; cancellation checked at each chunk and
  enumeration boundary. This does not interrupt an OS syscall or bound scheduling.
- On any read/metadata/budget/cancel/error, return no partial observation. Do not
  interpret read failure as an empty directory. No writes or automatic cleanup.

## Evidence meaning

The result describes a sequential read, not an atomic tree/file snapshot. Same
Runtime mutations serialize, but external/mapped writers are not excluded.
Metadata/identity rechecks detect some changes, not all possible concurrent edits.
The returned namespace remains ExactUtf8Unqualified: reading real native names
does not prove they are distinct/valid on a different target or volume.

The original whole-manifest reader remains the default. The explicit filtered
Runtime API now adds exact-subtree rules; `ManifestPages` adds session-MAC-bound
metadata paging and `fleet-dir` exposes local scan/dry-run. These retain the whole
bounded manifest in memory; they are not remote scan authority, update publication,
restart resume, operational sync_dir or production-scale acceptance. See
[the current entry contract](../verification/windows-fleet-directory-entry.md).
