# Two-host transfer with the 2026-11-17 release builds

Windows source -> Linux target, relay on the Linux host's loopback, Windows agent
reaching it through `ssh -L`. Both peers are stock `ferroc` binaries, not test
workers: Windows `target/release/ferroc.exe` SHA-256
`c0279dbc32f68b140d328a8833f4c57d94df6e377098e61a1ef3b5f5b6428298` (built with
`--features fleet-core` from this worktree) and Linux `d8473b63…9ac75` (the
300-input release ELF already validated against real glibc 2.17).

## Ladder

Whole-harness timings include relay restart, setup/pairing and DATA; they are not
DATA-only throughput measurements. The 300 s grant/route ceiling was not changed
and no renewal was used.

| bytes | outcome | whole harness | target SHA-256 (first 16) |
| --- | --- | --- | --- |
| 0 | passed | 4.98 s | `e3b0c44298fc1c14` |
| 1 | passed | 5.27 s | `bbeebd879e1dff69` |
| 131073 | passed | 5.66 s | `02bea565a35f177f` |
| 8388608 | passed | 5.73 s | `7014ae0f2fc0fee4` |
| 67108864 | passed | 11.39 s | `103f23a15401a701` |
| 268435456 | passed | 24.45 s | `d4e0d5a6082e9536` |
| **1073741824** | passed | **86.62 s** | `518c513144751984` |

For every size: exactly one source `peerReportedCompleted` event and one target
`targetSettledLocally` event with the same job digest and identical complete
receipt (`receiptId`/`size`/`sha256`/`parentDurability: unsupported`); the target
file's size and SHA-256 equal the receipt (and the source payload); the target
SQLite schema is 11 with one `completed` row, the same receipt and no live stage;
created parents are 0700 and the file 0600. Evidence:
`artifacts/fleet-p1/twohost-20261117/` (`ladder-results.json`, `target-sql.json`,
raw `target-*.log`) plus `run/` logs, kept local.

## Replacement (overwrite) rounds over the same network path

With the current binaries (Windows `1efa50f8…c6ce`, Linux `72576c74…4abd`) the
same harness also drives REPLACEMENT rounds:

| scenario | outcome | whole harness | target state |
| --- | --- | --- | --- |
| replace 131073 B | passed | 5.56 s | v11 `completed`, no stage, file SHA = receipt |
| replace 8388608 B | passed | 6.10 s | v11 `completed`, no stage, file SHA = receipt |
| replace 131073 B, wrong pre-image | passed (refused as expected) | 5.38 s | v11 `commitUnknown`, **full 131073-byte stage debt retained**, destination unchanged |

The destination was pre-created with the authorized pre-image bytes; the refusal
case advertises a different pre-image and must therefore fail. No reserved
`.ferroc-fleet-repl-*` name survives a successful replacement.

## Create re-baseline with the current binaries

0 / 1 / 131073 / 8 MiB / 64 MiB / 256 MiB / 1 GiB all passed again with
`1efa50f8…c6ce` + `72576c74…4abd` (1 GiB whole harness 84.72 s), each with both
completion events, identical receipts, schema 11 `completed`, no live stage and
file SHA equal to the receipt.

## Defect found and fixed: the idle window could abort a live transfer

One 1 GiB ladder step (seven sizes in a few minutes) produced a target that had
**already settled** — SQLite `completed`, no live stage, file 1 GiB with the receipt
SHA — while its log showed `Error: relay heartbeat/welcome timeout` and **no**
`fleetTransferCompletion` line, and the harness wait timed out. Cause: the agent
session's 45 s liveness window (`welcome`/`ping` re-arm it) could expire while the
relay was busy carrying DATA; the session then aborted, discarding the completion
line and turning a completed job into a spurious failure.

Fix: the liveness arm is now armed only when no owned transfer task is in flight,
and the window is re-armed once the transfer tasks drain. Idle sessions keep the
original 45 s recycling behaviour, and DATA remains bounded by its own link/lease
budget. After the fix, three consecutive 1 GiB runs produced both completion
events (1/1 each).

## Harness defects found while running this ladder

All three are in the test driver, not the product:

- The per-run pid file only remembers the LAST `ssh -L` forward, so repeated
  invocations leaked four forwards on 127.0.0.1:21100; the sweep now enumerates
  every ssh process still forwarding the port.
- Evidence was first keyed by SIZE, so a later scenario deleted an earlier one's
  directory (and its SQL), and `results.json` was only written after the whole
  ladder, losing partial progress. Both are now keyed per scenario and flushed
  after every size.
- The Windows API used for private directories must be `pwsh` (PowerShell 7):
  Windows PowerShell 5.1 spawned from a non-shell parent here cannot autoload
  `Microsoft.PowerShell.Security`, which silently broke `Set-Acl`. In the end the
  harness stopped pre-creating private ACLs entirely — `fleet init` creates its own
  private store, and a leftover fence marker from a previous run in the SAME
  directory is a ForeignControl finding that correctly blocks admission, which is
  why each scenario needs its own directory.

## What this does and does not show

- Shows the release binaries on two hosts, cross-OS, relay-only route, single-owner
  profile, Linux anonymous-stage receiver, no-clobber create, up to 1 GiB inside
  the unchanged 300 s authority.
- The relay is on the Linux host's loopback and the Windows peer joins through an
  SSH local forward. This is a LAN/SSH topology, not a public TLS deployment, not
  QUIC/NAT, and not operational issuance: test identities, test wrapper keys and
  local approvals only.
- Whole-harness timings are wall clocks of this harness; the 1 GiB figure carries
  no steady-state bandwidth claim and no margin statement for larger sizes.
- Replacement (overwrite) is not part of this ladder; Linux replacement is a
  separate receiver/publish increment and the setup-config path still refuses it.
- Nothing here extends to restart resume, GUI integration or production
  qualification.
