# Linux replacement publication (receiver level)

Status: implemented at the Linux receiver/publish layer **and reachable from the
stock agent path**. The setup-config gate that used to refuse every Linux
replacement round now accepts one that carries its authorized pre-image and still
refuses one without it. Nothing here changes restart, recovery or cleanup
semantics.

## Mechanism

`linux_stage::replace` links the same `O_TMPFILE` inode once into the pinned
parent under a **job-digest-derived** reserved name
(`.ferroc-fleet-repl-<16 hex bytes of the job digest>`), then `renameat`s that
name over the destination. The destination is therefore replaced atomically and
never observed partially written. Order and ownership unchanged from the
no-clobber path: the authorized pre-image is re-hashed inside the same `fs_gate`
immediately before the syscalls, the live `File`/lease/parent guard stay held, and
`mark_publication_attempt` already wrote the durable marker first.

Why a derived name instead of a new metadata version: the job row already stores
the job, so the digest reproduces the only name this job may create. A leftover
reserved name is attributable and a retry hits `EEXIST` (fail closed) rather than
silently adopting it. The earlier design note claiming an anonymous stage must
reach link count > 1 was wrong: `O_TMPFILE` starts at 0, the first link yields 1,
and `rename` keeps 1.

## Admission changes

Three refusals were replaced by "replacement requires the authorized pre-image":
`admit_linux_anonymous_receiver`, the allocation gate in `allocation.rs`, and the
journal's anonymous-allocation validation. `owned_publish` now allows an anonymous
owner to publish a replacement. The setup-config check changed the same way: an
anonymous target round may request a replacement only together with
`preImageSha256`. Anonymous rows keep the v11 schema; the replace intent is
carried by the job's `overwrite` flag plus its pre-image binding.

## Network evidence (Windows source -> Linux target)

Same topology as `fleet-twohost-release.md` (stock release binaries, relay on the
Linux loopback, Windows peer joined over `ssh -L`, no renewal, unchanged 300 s
authority):

| scenario | outcome | target state |
| --- | --- | --- |
| replace 131073 B | passed | v11 `completed`, no stage, file SHA = receipt, no reserved name |
| replace 8388608 B | passed | same |
| replace 131073 B with a wrong pre-image | refused as expected | v11 `commitUnknown`, full 131073-byte stage debt, destination bytes unchanged |

Evidence: `artifacts/fleet-p1/twohost-20261117/final-replace.json`,
`final-replace-wrong.json` plus the per-scenario target databases under
`target/<size>-replace-<preimage>/`.


## Native evidence (Linux, 3dv0/XFS)

Primitive cases (`linux_stage::replace_tests`), 5/5 pass:
- replacement swaps the destination, leaves no reserved name, nlink stays 1;
- an existing reserved name is refused, destination and squatter untouched, stage
  still unlinked (nlink 0);
- a directory destination fails at `rename`, destination still a directory and the
  reserved name is deliberately left in place (no silent cleanup);
- the reserved name is derived only from the job digest and is stable;
- empty/`/`/`.`/`..` components are refused before any link.

Host-level cases (`linux_receiver_tests`), 2/2 pass with a real host, journal and
anonymous stage:
- replacement publishes over the authorized pre-image and settles: schema 11,
  `Completed`, no live stage, destination bytes equal the sent bytes, no reserved
  name left, inventory debt back to zero;
- a same-size destination change after admission refuses publication ("no longer
  matches the authorized pre-image"), destination untouched, full 70 000-byte debt
  and one slot retained.

Linux `fleet::` library suite (`--features fleet-core --lib --test-threads=1`):
- first run: 676 passed / **1 failed** / 22 ignored. The single failure was a
  defect in my own new test — one 70 000-byte record exceeded the 65 536-byte
  chunk quota — not a product fault;
- earlier tree: 677 / 0 / 22 (836.47 s) after that fix.

Final tree (Linux replacement + setup-config acceptance + the session-liveness
fix): Windows **779 passed / 0 failed / 34 ignored** (818.43 s) and Linux
**677 passed / 0 failed / 22 ignored** (830.70 s), with `cargo fmt --all --
--check` and `cargo clippy --all-features --all-targets -D warnings` clean. The
102-test difference is platform gating, not skipped defects.

## Boundaries

- Replacement is reachable only for an EXPLICIT `linuxAnonymousStage` target with
  the pre-image in the job; a round without the pre-image is still refused at
  configuration time, so no default path can overwrite anything.
- A failure between link and rename leaves the reserved name behind with the full
  debt and an inventory finding; there is no automatic cleanup, adoption or
  reconciliation, and no receipt is produced.
- No parent-directory durability promise (still `unsupported`), no restart resume,
  no defence against an external writer between the pre-image check and the
  rename, and no protection against an ancestor directory being renamed.
- Windows replacement behaviour is unchanged by this increment.
