# Windows P2 additive sync planning verification

Date: 2026-11-14. Scope: pure planning over an existing `DiffPlan`. No scan, IO,
apply, network or scheduling. Windows x86_64.

## Evidence binding

Evidence directory: `artifacts/fleet-p1/syncplan-freeze-20261114-002013/`.

| Item | Value |
| --- | --- |
| Frozen input paths | 103 |
| Release TEST binary SHA-256 | `a1beb518…958b5` |
| Previous increment TEST SHA-256 | `b2035da8…ffd9ad` |
| Source delta | 1 modified file (`src/fleet/mod.rs`) + 2 new files |

`journal.rs`, `lease.rs`, `crypto.rs`, `protocol.rs` and `host.rs` are unchanged.
The diff hash is recorded in `delta.json`.

## Suites (original parallel flags)

| Suite | Passed |
| --- | --- |
| fmt / clippy `-D warnings` | pass |
| all-features | 577 |
| default | 62 |
| doc | 83 |
| release fleet components | 515 |
| release relay channel | 19 |
| native pressure (ignored, serial) | 4 |
| three independent OS processes | 1 |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

## Planned behaviour under test

| Case | Assertion |
| --- | --- |
| add-only plan | missing targets become jobs with rooted paths, no overwrite, planned bytes counted |
| extra target files | counted as retained, never planned or deleted |
| existing-file update | whole plan refused; no partial plan |
| type conflict / blocked subtree | whole plan refused |
| quick comparison | refused before planning |
| missing digest | refused upstream by the manifest diff |
| missing directories | counted only; not turned into file transfers |
| roots and relative paths | trailing-slash, non-rooted and unsafe spellings rejected |
| determinism | two identical inputs give identical job digests and file ids |
| limits | chunk, deadline, idempotency and file-id rules enforced |

## Failures and corrections in this increment

1. The first freeze attempt failed an untouched pre-existing 2 s gate
   (`native_writer_after_v7_marker_never_reinitializes_journal`, 2232 ms). It is
   logged in `syncplan-freeze-20261114-000757/`.
2. A load experiment on the same binary measured idle 23–33 ms and 6-thread
   fsync load 52–70 ms for that path, so plain volume fsync pressure does not
   explain the 2232 ms. Root cause stays open with the earlier 2.929 s case.
3. The second attempt passed every suite but was rejected by my own over-strict
   `docs=81` expectation (actual 83). Doc-test count is now required only to be
   non-zero; suites whose selection matters keep exact counts.
4. The third attempt ran every suite; its receipt was recomputed with
   `-OnlyReport`, which reuses the raw logs of that same run and still executes
   fmt/clippy. This is a re-evaluation of that run, not a fourth execution.

## Not covered

No update/overwrite path, no deletes, no native name equivalence, no per-file
re-observation, no grants, no `send_file`/`sync_dir` execution, no two-host run,
no Linux qualification and no production dataset.
