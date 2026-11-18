# Cross-host fleet transfer: Linux source → Windows target

Status: **one candidate increment, two physical hosts, one size ladder**. This is
not production acceptance, not three hosts, and not a direct routable path from
the Linux peer to the relay.

## What ran

- Source: `3dv0`, Manjaro Linux, kernel 7.2.9-1-MANJARO, glibc 2.44,
  `ferroc-linux-test` sha256 `cdc2e2ce…` (release test binary, `fleet-core`).
- Target and relay: `cap00`, Windows, `relay-test.exe` sha256 `59b18e31…`
  (same release test binary, `fleet-core`).
- Sizes: 0, 1, 131073 and 8388608 bytes, each with a fresh job, grant, relay
  database and target directory.

Evidence: `artifacts/fleet-p1/crosshost-20261115-110500`
(`ladder2.json`, `ladder4.out`, and per-size relay/target/source logs,
source observation, target receipt and setup).

## Result

For every size: the Source worker reported success, the Target reported
`TARGET_LOCAL_SETTLED bytes=<size> slot_debt=0`, the persisted target file had
the expected length and SHA-256, and the receipt the Source authenticated was
field-for-field identical to the Target's local receipt (`receiptId`, `size`,
`sha256`, `parentDurability`).

| bytes | receipt matches job | peer receipt equals target | file sha matches |
| --- | --- | --- | --- |
| 0 | yes | yes | yes |
| 1 | yes | yes | yes |
| 131073 | yes | yes | yes |
| 8388608 | yes | yes | yes |

## Topology, stated plainly

The relay listens on `127.0.0.1` on the Windows host. The Linux peer reaches it
through an SSH reverse port-forward (`ssh -R 18877:127.0.0.1:18877`), so the
fleet WebSocket runs over a real cross-machine TCP stream that terminates in
that forward. It is **not** an end-to-end routable path and the relay is not on a
third host.

A direct attempt was made and refused by the product itself: binding the relay
to `0.0.0.0` and advertising `http://10.100.11.1:18878` failed with
`use HTTPS except for loopback development`. Serving non-loopback plaintext is
deliberately disallowed, so a direct LAN path needs TLS with a trusted chain,
which this increment does not add.

## Test-harness changes required to run this at all

- The process worker gained `FERROC_FLEET_TEST_BIND`, `FERROC_FLEET_TEST_URL`,
  `FERROC_FLEET_TEST_ROOT`, `FERROC_FLEET_TEST_RELAY_FOREVER`, a `setup` role
  that mints one job/grant pair without needing a config file, and
  `FERROC_FLEET_TEST_WRITE_INPUT` so the source peer materialises its input.
- `Setup::root` became optional and `grant_for_paths` was split out, so the same
  job can name a Linux source path and a Windows destination path.
- `sync_exec` now gates only the Windows publish sink (`run_target`,
  `execute_file`, `execute_file_cancellable`, `run_plan`, `PreparedFile`) instead
  of the whole module, because `CancelToken`/`ExecOutcome` are platform-neutral
  and are used by the scanner and preflight.
- `replace_host_tests`, `relay_sync_exec_tests` and the three-process controller
  are Windows-gated; the process worker itself now compiles on Linux so it can
  act as a Source peer.

All fixture seeds and approved time windows remain `cfg(test)`-only. No MCP/CLI
tool, no service, no default-on switch and no schema change were added.


## Regression at the time of this increment

Windows (single serial invocation, `win-final.log` copied into the evidence
directory): `fmt`, `clippy -D warnings`, `all-features --all-targets`,
`default`, and `--doc` all exited 0, with 614 `all-features` lib tests and 89
doc tests.

Linux (same source revision, release, `fleet-core`, `3dv0`/`delta`): 454 passed,
6 failed, 22 ignored. The six failures are Windows-primitive tests (handle-based
rename publish, private NTFS DACL, file-id replacement detection). Linux test
parity is not claimed.

Two earlier Windows regression logs in this directory were invalidated: two
`cargo test` invocations ran concurrently against one target directory and one
was killed mid-link, producing `LNK1104` and 467/147 sub-counts. They are kept
only to show the collision; `invalid-regression-logs.json` says so.

## Binary binding

The ladder above was re-run with the binary built from the current source:
Linux `47b4e19d…`, Windows `59b18e31…`. An earlier run used the pre-fix Linux
binary `cdc2e2ce…` and is retained; the fix touched only a test helper.

## Later independent-identity TLS receipt evidence

A later delta→tecs→CAP00 stock-agent run retained full receipt logs and independently
matched source/target/SQL receipts and current target SHA for 3 B and 8 MiB,
without a clock shim. Its new Linux ELF passed real pinned-image glibc2.17
MCP25 write/read. Its 128 MiB run exhausted the unchanged300s DATA budget,
leaving a private partial stage and full debt, and its first new full freeze was
rejected by the older process-pagination test. An independent subsequent full
freeze passed 830/63/97 plus Node3/CI13 with archive/binary postchecks. A raw
TLS16MiB read without fleet/stage/SQL took46.18s; this is not a cloud quota
measurement and does not change the300s budget. See
[completion observations](windows-fleet-completion-observations.md); these
results do not retroactively change this historical worker probe or establish
Linux target parity/production qualification.

## Still open (this historical increment)

- Two hosts only. Three-host and relay-on-a-third-machine are not verified.
- The Linux leg is an SSH forward, not a direct routable path; at the time of
  this increment TLS on a non-loopback origin was unimplemented. A later
  increment tested temporary Caddy HTTPS on 8444 in
  `docs/verification/windows-linux-fleet-tls-crosshost.md`; that is not a
  production deployment and does not change this increment’s Linux-parity
  boundary.
- No crash/restart resume, no directory-level apply (`send_file`/`sync_dir`
  execution entry), no progress UI.
- Linux test parity is **not** established. An earlier attempt to run the
  Linux suite reported 88 failures that I first attributed to Windows-only
  fixtures; that attribution was wrong. The real cause was a stale
  `version: 1` in a test helper while `JOB_VERSION` is 2, and the same defect
  broke 150 Windows receiver tests. After correcting the helper, the Windows
  receiver suite passes 150/150; the Linux suite is re-run separately and its
  result is recorded with the increment.
- The pre-existing open items stand: whole-admission SQL latency measured at
  2.929 s once, the 2 s wall-clock gate sensitivity under parallel load, and the
  8 MiB relay probe that once reported a settled Target with a Source deadline.
