# Two-machine confirmation of the relay accepted-tail drain

Date: 2026-11-17. Hosts: `delta` (Linux, source) and `cap00` (Windows,
target). The workers are archived **297-input test builds**, not the later
300-input release ELF. See the provenance correction below.

## Topology

- Relay and Source run on **delta**, both on its loopback (`127.0.0.1:20xxx`).
- The Windows Target reaches that loopback through `ssh -N -L <port>:127.0.0.1:<port> delta`.
- Both peers use `http://127.0.0.1:<port>`; DATA crosses the LAN between the two
  machines. Not a production deployment, not TLS on a public origin, not
  operational issuance.

## Binaries

- Windows: `artifacts/fleet-p1/preflight-regression-20261117-011848/all-features-lib.exe`
  SHA-256 `56ab82cdf914d2bc433a429aa0e01163f6a29fa331e8cf67b1c1c42059694076`.
- Linux: release `fleet-core` test binary from the 297-input snapshot,
  `793a38d64981cf4280f0346bc0825b3fe7397cbc583ec8be4b2531594149ef5d`

Independent archive comparison found two Rust/Cargo differences from 297 to 300:
`src/fleet/directory_cli.rs` and `src/fleet/directory_cli_tests.rs`. The relay/worker
paths are unchanged, but this is **not binary identity** or a transfer acceptance
for the new release ELF. Full mapping: local artifact
`artifacts/fleet-p1/glibc217-20261117/evidence-audit.json`.

## Results

| bytes | target settled | receipts (id/size/sha256/parentDurability) | target file |
| --- | --- | --- | --- |
| 0 | `slot_debt=0` | equal | 0 B |
| 1 | `slot_debt=0` | equal | 1 B |
| 131073 | `slot_debt=0` | equal | 131073 B |
| 8388608 | `slot_debt=0` | equal | 8388608 B |
| **134217728** | `TARGET_LOCAL_SETTLED bytes=134217728 slot_debt=0` | equal | 134217728 B, sha `bca383cf…b43f` |

For 128 MiB the source's authenticated peer observation and the target's local
receipt are identical (`receiptId b456ae61-…`, size 134217728, sha
`bca383cf073bc8e921a977bbd13de1edf19ec00232839086e65610796f71b43f`,
`parentDurability unsupported`), and the file on disk hashes to the same value.
Wall clock: 206.10 s end-to-end (≈0.65 MB/s over this path).

## Two harness bugs found and fixed (neither is a product defect)

1. **`ssh -R` never bound**: PowerShell parses `"$Port:127.0.0.1:$Port"` as the
   *scoped variable* `$Port:` plus literal text, so the forwarding spec was
   malformed and ssh silently created nothing. `${Port}:127.0.0.1:${Port}` fixed
   it. Controls that proved the product was fine: a raw WS handshake from delta
   through the forward returned `101`, the same ticket replayed locally returned
   `401`, and the identical option set worked against a plain listener.
2. **Every transfer ≥64 MiB died at ≈31 s**: this was
   `FERROC_FLEET_TEST_LINK_SECS` defaulting to **30 s** — the fixture's FleetLink
   budget — which my harness never set, so the source's `receive` deadline expired
   mid-transfer and the pair was reset. Diagnostic (temporary, reverted) printed
   `SOURCE_WORK_ERROR fleet receive deadline: deadline has elapsed`; a lower route
   TTL shortens the pump (TTL 20 → 20.01 s) while a higher TTL cannot extend it
   (120/300 → ≈31.7 s), exactly as a 30 s link budget predicts. Setting
   `FERROC_FLEET_TEST_LINK_SECS=300` on **both** peers fixed it; the first retry
   still failed because the variable was only exported on the Windows side.

## Capacity note

The 206.10 s source-worker elapsed time is one observation, not a measured
steady-state bandwidth limit or whole harness wall clock. Linear extrapolation
at that average predicts about 186 MiB in 300 s and about 27.5 min for 1 GiB,
so this run provides **no conservative margin** for a 1 GiB retry within the
unchanged 300 s ceiling. It does not prove a hard 180–200 MiB capacity bound or
that 1 GiB is impossible after performance work. The independent local
single-owner 1 GiB receipt (250.625 s) is not inherited by this topology.

## Regression standing

The workers predate the 300-input CLI increment. The later Windows full freeze
`cli-preflight-regression-20261117-085302` passed 300 inputs, 862/63/97 plus Node
and CI gates and independent postcheck; the native Linux 300-input full matrix
(all-features all-targets **752 passed / 24 ignored / 0 failed**, default **62 / 2 /
0**, fmt and strict clippy clean). This document adds cross-machine results only;
it does not extend qualification to production, public TLS, or glibc 2.17.
