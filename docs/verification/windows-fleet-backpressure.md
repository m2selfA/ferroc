# Windows P1 native pressure verification

Date: 2026-11-13. Scope: native relay TCP/WS failure paths and post-settlement ACK failure. Host: Windows x86_64, loopback only, one test process per case. This report does NOT qualify Linux, two hosts, public registration or production data.

## Evidence binding

Evidence directory: `artifacts/fleet-p1/backpressure-20261113-221343/diagnostic-freeze-20261113-224827/`.

| Item | Value |
| --- | --- |
| Frozen input paths | 96 |
| Release TEST binary SHA-256 | `417f3811…9d74de` |
| Previous relay increment TEST SHA-256 | `b0bf1e2e…9890d9` |
| Frozen verifier SHA-256 | `d11b0241…84f511` |
| `all-features.log` SHA-256 | `2ad00458…aae1834e` |
| `release-channel.log` SHA-256 | `821e07f3…bc35e078` |
| `native-pressure.log` SHA-256 | `7ed49c05…e9c0dc` |

Source delta against the previous increment is exactly three modified files (`src/fleet/relay_channel.rs`, `src/fleet/relay_io.rs`, `src/fleet/relay_channel_tests.rs`) plus one new test file. `SourceWindow`, Host, Runtime, journal, lease, crypto and wire format are unchanged; `delta.json` records the diff hash.

## Suites (original parallel flags)

| Suite | Passed |
| --- | --- |
| fmt | pass |
| clippy `-D warnings` (all features, all targets) | pass |
| all-features | 564 |
| default | 62 |
| doc | 81 |
| release fleet components | 502 |
| release relay channel | 16 |
| native pressure (ignored, serial) | 4 |
| three independent OS processes | 1 |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

Full regression used the original parallel flags. Serial execution applies only to the explicit native pressure probes.

## Native socket contrasts

`Pair.test_events` exists only under `cfg(test)`. Bounded 256-entry broadcast records queue-full, the first Pending poll of the native `sink.send`, and actor exit. The observer polls the same future and preserves its result and 5 s timeout. Non-test builds keep the original path.

| Case | Observed | Result |
| --- | --- | --- |
| Never read | queue full + real sink Pending; last Pending→exit 5014 ms; both actors report the 5 s deadline | pass |
| Resume before deadline | full 8 MiB decoded, contiguous offsets, stream SHA match; 133 ms | pass |
| Pause device while blocked | real Store revocation, both actors report paused/rotated at 1001 ms, before 5 s | pass |

Requested `SO_RCVBUF` 65536; `getsockopt` reported 65536. An OS may clamp or double this value; it is not an exact advertised TCP window.

The resume case drives authenticated DATA without READY/SourceWindow ACK gating to stress the opaque router. It is not a compliant SourceWindow transfer, not filesystem publication and not a v9 throughput number. Actor reset/route-closed messages after deliberate cleanup are expected, not proof of a clean closing handshake.

## Actual v9 then failed native ACK send

Public Windows `run_target` delegates to a private shared implementation with a no-op observer. The test hook runs after real v9 settlement and before the original ACK send while the live final owner is still held.

Observed: Target returned `target settled locally; final ACK delivery unknown`; local `Host.get` shows `Completed` with receipt and settlement origin, no live stage, zero recorded usage, full target bytes and drained owner. Source returned a receive error, never a peer-completed observation, and its bytes are unchanged. Both actors exited; 32 socket permits restored, zero pairs.

This proves one local-settlement/failed-native-send window only. It does not prove ACK delivery on a successful send, does not observe remote private IO, and permits no rollback, retry, resume or reconstruction from history.

## Retained earlier failure

The first freeze attempt in `../backpressure-20261113-221343/` failed `native_actual_relay_eight_mib` (15/16) with a generic Source receive error. The fixture unwrapped the Source result first, so the Target/actor cause was lost. Read-only inspection of the single retained fixture (`immutable=1`, `mode=ro`) found job paths and public 8 MiB source SHA matching the fixture, phase `transferring`, persisted count 3276800, no seal/intent/receipt, no target file, and full 8388608 reservation still held with the stage present.

That directory keeps the original bytes and the original debt. An `ARCHIVE-NOT-LIVE` copy preserves per-file SHA-256 for analysis; it carries no object identity, path binding or recovery permission and must not be opened as a live owner.

The fixture now joins both ends, records actor exits, Target phase/debt/in-flight and lag, then asserts the receipts. The next frozen run passed with the 8 MiB case at 3920 ms. One pass is not a root cause. The closure stage remains unknown and is tracked as an open item.

## Still open

- The earlier SQL whole-admission timing failure (2.929 s against a 2 s gate) remains unattributed. These socket probes do not explain or fix it.
- The 8 MiB channel failure cause is not established; only the diagnostic gap is closed.
- Linux qualification, two-host operation, public credentials, progress/cancel surfaces, window renewal, long transfers and P2/P3 remain unqualified.
- No independent source-visible review was performed; Advisor is no longer consulted by user instruction.
