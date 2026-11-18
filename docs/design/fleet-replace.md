# Fleet replace-existing-file contract

Scope: the LOCAL contract that lets a planned job replace a file that already
exists, without turning the create path into an overwrite path. No network
change, no service, no schema version bump, no `sync_dir` execution entry.

## Why a separate mode

v1 `JobSpec` had `overwrite` but rejected it outright, and `Permission` had only
`SendFileNoClobber`. A create grant therefore could not express "replace these
specific bytes", and a replace could not be represented at all. Adding a flag to
the create path would let one permission mean two different destructive powers.

## Job contract (request version 2)

- `JobSpec::pre_image_sha256: Option<[u8; 32]>`.
- `(overwrite, pre_image_sha256)` must be `(false, None)` or `(true, Some(_))`.
  A no-clobber job carrying a pre-image, or a replace job without one, is
  refused by `validate()`.
- A replace whose pre-image equals the new content is refused: it would spend a
  full transfer to write identical bytes.
- The pre-image is hashed inside the same canonical request bytes, so
  re-pointing a replace job at different existing content changes the request,
  job and grant digests together.
- `JOB_VERSION` is now 2. Old implementations reject v2 instead of hashing a v1
  request that lacks the pre-image binding.

## Permission

- `Permission::ReplaceExistingFile` (canonical byte `2`) is distinct from
  `SendFileNoClobber` (`1`).
- `FileGrant::validate_for` requires the permission to match the job's clobber
  mode in BOTH directions, so a create grant can never authorize a replacement
  and a replace grant can never authorize a create.
- `sync_grant` derives the permission from the planned job.

## Pre-image is an authorization, not an observation

`PreImage::new(sha256, bytes)` only records what the caller authorized. It proves
nothing about the file. It is re-checked twice, both times against the real
filesystem:

1. `StageFile::prepare_replacing` hashes the existing destination under the
   fs_gate before any byte is accepted, and refuses on any difference.
2. `VerifiedStage::publish_replacing` re-hashes it under the fs_gate again, after
   the stage itself was re-read and synced, immediately before the rename.

The destination is opened through the plain-object path (`open_object`), not the
identity/stage privacy path: a replace target is an ordinary user file, so
requiring a single-user DACL would refuse legitimate work. Links, reparse
points, special objects and multi-link files are still refused, because
replacing them would rewrite bytes reachable under another name.

## Publication

- `Publication::Published` gains `mode: PublishMode`, either `CreateNoClobber`
  or `ReplaceExisting`. "Published" must not be read as "created".
- Replace uses `tempfile::persist`, i.e. one rename over the target
  (`MoveFileExW` with `REPLACE_EXISTING` on Windows, `rename(2)` elsewhere), so
  no reader observes a half-written destination.
- A missing destination at publish time is a REFUSAL, never a fallback to
  create: the stage carries replace-only permission.
- After the rename is attempted, every outcome is `Published` or `Uncertain`.
  A failed replace is never reported as safe to retry, and the stage and its
  quota are retained until the caller settles journal state.

## Planning

- `plan_add_only` keeps its old behavior and still fails the whole plan on any
  existing-file copy.
- `plan_add_or_replace(source, target, diff, template)` additionally emits
  replace jobs, each bound to the digest OBSERVED in the target manifest.
  Taking the pre-image from the source entry would authorize overwriting
  whatever is actually there now.
- A replacement whose target digest is missing or the all-zero placeholder fails
  the whole plan. Type conflicts and blocked subtrees still fail the whole plan.
- `PlanMode::AddOrReplace` records which planner produced the plan.

## Receiving reservation

`allocation::parent` derives the absence requirement from the job instead of a
caller flag: a create job's destination must be absent, a replace job's must be
an existing plain single-link file. The reserved stage is still a fresh
`CREATE_NEW` temp file in the same directory, so the pre-image is untouched
until the final rename.

## Host receiver wiring (metadata version 10)

The v7/v8/v9 publication path renames with `flags = 0`, which cannot replace.
Wiring replace in cannot reuse row version 7: an old reader opening the same
database would see version 7 and treat a replacing rename as a no-clobber one.

- A replacement attempt writes the DATABASE metadata version **10**
  (`CASE WHEN version IN(9,10) THEN version ELSE 10 END`), so every v7/v8/v9
  reader refuses the database at open, and a v9 settlement can no longer
  downgrade it back to 9.
- The row itself still advances to the same v7 `CommitUnknown` state with all
  debt retained; only the database gate differs.
- Immediately before the native call, and inside the same `fs_gate` that just
  re-hashed the stage, the real destination is re-hashed again and compared with
  the job's pre-image. Any difference refuses the attempt and keeps the stage.
- The rename uses `FILE_RENAME_INFO`'s `ReplaceIfExists` member (`flags = 1`).
  No POSIX-semantics flag is requested, so a target with an open handle makes the
  call FAIL; that stays `Uncertain` rather than being retried.
- A create job is unchanged: `flags = 0`, and an existing target still fails.

## Deliberate limits of this increment

- Replacement is validated only on one Windows machine with real local files.
  No two-host, Linux, restart-resume or production acceptance.
- The external-writer window between the last pre-image check and the rename is
  still not excluded.

- No external-writer exclusion after the final pre-image check: a same-user
  process may change the file between the check and the rename. This is the same
  boundary the rest of the receiver already declares.
- No crash-durability claim on Windows; parent directory sync remains
  `Unsupported`.
- Nothing here creates directories, deletes files, resumes after restart, or
  authorizes network work.
