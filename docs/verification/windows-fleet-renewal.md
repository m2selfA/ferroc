# Windows P1 renewal verification

Date: 2026-11-13. Scope: explicit lease renewal at an acknowledged boundary on the
P1 candidate. Windows x86_64, loopback only. Not two hosts, not operational
issuance, not production data.

## Evidence binding

Evidence directory: `artifacts/fleet-p1/renewal-freeze-20261113-235052/`.

| Item | Value |
| --- | --- |
| Frozen input paths | 100 |
| Release TEST binary SHA-256 | `b2035da8…ffd9ad` |
| Previous increment TEST SHA-256 | `417f3811…9d74de` |
| `release-channel.log` SHA-256 | `dc39f2ef…2f3d2f` |
| Source delta vs previous relay increment | 8 modified, 2 new test files |

The delta covers the relay route, source file/window and receiver flow cache.
`journal.rs`, `lease.rs`, `crypto.rs`, `protocol.rs` and `host.rs` are unchanged and
`delta.json` records the diff hash.

## Suites (original parallel flags)

| Suite | Passed |
| --- | --- |
| fmt / clippy `-D warnings` | pass |
| all-features | 569 |
| default | 62 |
| doc | 81 |
| release fleet components | 507 |
| release relay channel | 19 |
| native pressure (ignored, serial) | 4 |
| three independent OS processes | 1 |
| Node/OpenSSL oracles | 2 |
| CI validators | 13 |

## Renewal cases

| Case | Proves |
| --- | --- |
| `flow_renewal_after_acked_prefix_keeps_coverage_and_rotates_epoch` | received coverage survives rotation, superseded-epoch ACK cannot reopen, later DATA continues |
| `renewal_requires_drained_acked_window_and_preserves_session` | pre-READY and pending-window renewal refused without poisoning; counts and total deadline kept |
| `renewal_rejection_keeps_old_epoch_writable_and_finish_gated` | changed job totals are refused and the old epoch still finishes |
| `advance_local_requires_stable_identity_rotation_and_no_reuse` | route advancement needs stable identity, real rotation, no replay; stale bindings never route |
| `advance_local_after_registry_close_is_refused` | a stopped registry cannot advance |
| `native_relay_renewal_mid_transfer_keeps_coverage_and_settles` | real relay + real file: rotate at 64 KiB, continue, local v9 settles, both receipts equal |

Un-authenticatable frames, including a superseded epoch, are rejected without
poisoning the live session; only authenticated-but-wrong traffic faults. This is
the existing rule and the renewal tests assert it explicitly.

## Native relay numbers (same run)

| Bytes | Elapsed |
| --- | --- |
| 0 | 506 ms |
| 1 | 288 ms |
| 131073 | 304 ms |
| 8388608 | 4428 ms |

The mid-transfer rotation case is part of that suite; its elapsed time is not a
throughput claim.

## Failure found and fixed in this increment

A first discovery run failed 6 existing receiver tests (`receiver faulted or DATA
sealed`): I had added `data_seal().is_none()` to renewal, which forbade what
`SealedReceiver::renew` already guarantees. The guard was reverted to `!faulted`;
DATA closure stays enforced by the flow-control and DATA paths. That failed run is
kept in `renewal-discovery-20261113-233739/` and is not counted as acceptance.

Two further tooling corrections are recorded rather than hidden: the freeze list
initially named the not-yet-written report, and the post-check reused `$channel`
for an `[int]$Channel` parameter.

## Still open

- No automatic renewal scheduling, issuer, trusted-time injection or reconnect.
- No sender persistence, resume, cross-restart continuation or two-host run.
- Linux, production enrollment and datasets remain unqualified.
- The earlier SQL admission timing (2.929 s vs 2 s) and the 8 MiB channel closure
  cause remain open; this increment neither explains nor fixes them.
