# Linux read-only target preflight

## What it is

`Runtime::preflight_fleet_target` now runs on Linux as well as Windows. It is a local, read-only observation of an add-only plan's destinations. It creates nothing, publishes nothing, deletes nothing, takes no SQLite lock and issues no grant. Its result is not a publication permit, a reservation or a snapshot: the receiver must re-observe under its own gate.

## Reused contracts

The Linux branch uses the same implementation as Windows, so the contract is identical:

1. Policy resolution plus the retained original-spelling ancestor chain; every anchor and the private parent are re-observed by object ID at the end.
2. A parent that does not exist refuses the whole plan; preflight never runs `mkdir`.
3. The resolved destination must stay inside the given target root, and the destination must currently be absent (`NotFound` only).
4. Names must satisfy the declared narrow ASCII profile (reserved device names, trailing space/period, reserved characters, non-ASCII and the `.ferroc-fleet-` namespace are refused, not folded), and ASCII-case collisions inside one plan refuse the whole round.
5. `PreflightLimits::allow_planned_directories` stays default-false. When explicitly enabled it only lists the plan's own declared-but-absent directories ancestor-first (each with an existing or earlier-declared parent); it still creates nothing and returns the placeholder `planned-directory` rather than a real object id.
6. The result carries an ordered `(path, bytes, sha, job)` digest and `matches()` refuses another plan.

Linux specifics kept honest: the retained parent and ancestor `File` handles bind objects but do **not** fence against directory rename, so an owner may still move a parent during the observation; the private-parent requirement means mode-restricted single-user directories, not a sandbox; and the observed-absent result can be undone by any concurrent creator after preflight returns.

## Verification

Isolated source snapshot `artifacts/fleet-p1/preflight-linux-20261117/` (296 inputs, archive `fd235b43a8e082331b5b59992c416eabfc9f6952e814a328d7be0454fe569cf4`, production delta exactly `src/fleet/target_preflight.rs` + `src/runtime.rs`, one added test file).

Native Linux release, receipt `probes/preflight-linux-20261117/linux8/verification.json`:

1. fmt `--check` and strict `clippy -D warnings --all-features --all-targets` passed.
2. `fleet::target_preflight::linux_tests` — **14 passed, 0 failed**, one test image `52edc402…e0636` shared with the listing gate.
3. Cases cover: absent destinations under existing private parents (nothing created), missing parent refused, non-private (`0755`) parent refused, existing destination refuses the round without touching bytes, symlinked parent refused rather than followed, declared directories staying declarations in opt-in mode, ancestor-first ordering, only the absent level declared when the base parent exists, ASCII-case collision refused, plan-digest binding, ordered hook observation plus mid-round cancellation, the narrow portable profile, and limit validation before any observation.
4. Every rejection/cancellation case asserts that no directory or file was created.

Preserved rejected rounds (all auditor or fixture defects, product unchanged): `linux` reused a stale cached test image because tar members carried epoch mtimes; `linux3` failed the format gate on a newly added assert; `linux4` used manifest fixtures without their parent directory entries; `linux5`/`linux7` failed only my own pinned assertions (a wrong expected count of 13 for 14 tests, and a test-name prefix that omitted the `fleet::` module); `linux6` failed because the verifier's result-line regex was double-escaped. No product assertion or gate was loosened.

## Limits

This is a local Linux component result. It does not add apply/publication, does not implement Linux replace, does not perform remote directory approval, and does not inherit glibc 2.17 or cross-machine qualification. Windows behaviour is unchanged; the Windows full regression for this increment is recorded separately.
