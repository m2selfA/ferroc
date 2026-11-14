# Target preflight: native name and parent admission before any directory apply

Status: Windows-only LOCAL read-only candidate. It is NOT publication permission,
not a reservation, not a filesystem snapshot and not a network or remote authority.

## Why this exists

After a scan produces a manifest, the diff and the add-only planner can name files
that the current no-clobber publisher cannot actually admit. Two gaps remain:

1. Exact UTF-8 manifest keys do not prove two names are distinct Windows objects.
2. A descriptive plan does not prove the target parent exists, is private, is a
   plain directory, or that the resolved destination stays inside the target root.

`Runtime::preflight_fleet_target` observes those facts for one ordered plan without
changing the target tree.

## Contract

- Entry: `preflight_fleet_target(root, plan, limits, cancel)`. Windows only; other
  platforms fail explicitly instead of falling back.
- Lifecycle: reuses the existing registry to `fs_gate` order. It requires
  `allow_transfers` and is drained by `Runtime::shutdown`, exactly like the scanner.
- Roots: the caller's original spelling is authorized through `Policy`, then the
  original ancestor chain is opened with the existing deny-delete native directory
  handles and pinned by object ID. A junction between root and destination is
  therefore refused rather than silently resolved.
- Parents: by default every destination parent must already exist, be a plain
  private directory (`open_private`: no reparse, single-user DACL) and resolve to
  the same directory object as its original spelling. Preflight never creates a
  directory, so with the default limits a plan needing new parents fails whole
  instead of implying mkdir.
- Declared directories: `PreflightLimits::allow_planned_directories` (default
  false) additionally admits the directories the plan itself declares. Each is
  checked ancestor-first: an existing one must be a private plain directory
  resolving to the same object; a missing one is only admitted when its own parent
  is already existing or declared earlier in the same plan. Admitted-but-missing
  directories are returned as `planned_directories()` for the receiver to create,
  carry the marker `planned-directory` instead of an object id, and are still NOT
  created by preflight. A directory declaration that is actually a file, or a
  planned file that is also a declared directory or directory ancestor, fails the
  whole plan.
- Absence: only `NotFound` counts as absent. Existing files, directories and
  reparse objects fail the entire plan; nothing is overwritten.
- Binding: the result carries a digest over the ordered `(path, bytes, sha, job)`
  list and `matches()` re-checks it. A preflight of one plan cannot be attached to
  another.
- Limits: file count bounded by `MAX_PLAN_FILES`; depth and path bytes reuse the
  manifest ceilings; a caller limit may only narrow them.

## Deliberately narrow name profile

Accepted components: ASCII only, no control characters, no
`< > : " / \ | ? *`, no trailing space or period, at most 255 bytes, not a
reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`,
including with an extension), not the `.ferroc-fleet-` stage namespace, and no
two planned targets that collide ignoring ASCII case.

Everything else is REFUSED, not folded. Microsoft's naming documentation is the
basis for the reserved-device and trailing space/period rules, plus the statement
that case must not be assumed. This module therefore never claims Unicode
case-folding, 8.3 alias equivalence, or support for names outside the profile.

## Explicit non-capabilities

- No directory creation, file creation, rename, overwrite, delete or cleanup.
- No grant, lease, reservation, stage, journal row or database lock.
- No remote read authority: the caller's own policy and local files are the input.
- Not an atomic snapshot; a writer can still create the destination after the check.
- The pinned parent handle denies ordinary rename/delete only while the observation
  runs, and only for the parent itself, not for deeper ancestors.

## Next

A later increment may turn an observation into an apply step only with a per-file
grant, fresh re-observation under the publisher's own gate, and an explicit
parent-creation contract. None of that exists yet.
