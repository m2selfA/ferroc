# P2 additive sync planning

## Boundary

`sync_plan` turns ONE existing `DiffPlan` into ordered per-file `JobSpec`s. It does
not scan, read, write, delete, overwrite, send or resume. Digests and sizes are
caller claims from the manifest; a plan is not an authorization, a grant or a
promise that the target still looks that way.

## Rules

| Rule | Reason |
| --- | --- |
| checksum comparison only | quick mode may miss a same-size backdated edit |
| `CopyTarget::Absent` only | the current publisher is no-clobber |
| whole plan refused on update/conflict/blocked subtree | skipping them silently would misreport a sync |
| target-only entries are counted, never planned | no delete support exists |
| missing target directories are counted, not planned as files | the receiver must still create parents |
| `JobSpec::validate` decides path legality | one path contract, not two |
| per-file key is `prefix:digest16(path)` | job keys allow only ASCII alnum and `._:-` |

`SyncPlan::directories()` additionally exposes the declared directories as an
ancestor-first relative list, bounded by the same 4096-entry limit. It is still
intent only: nothing here creates a directory, and `directories_ensured()` keeps
reporting the same count.

Limits: 4096 files, 512 GiB selected, each file within the fleet hard ceiling, and
the caller prefix at most 96 bytes.

## What a `PlannedFile` carries

Relative path, size, digest, copy reason, and a complete `JobSpec` with a
deterministically derived `file_id` and idempotency key. Two identical inputs
therefore produce identical job digests, which is what makes replay auditable.

## Not covered

No update/overwrite path, no deletes, no native name equivalence, no live
re-observation per file, no grants, no scheduling, no `send_file`/`sync_dir` entry
point and no execution. P3 direct transport remains later.
