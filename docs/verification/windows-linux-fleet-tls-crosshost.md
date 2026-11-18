# Ferroc fleet: cross-machine DATA over public TLS

## New receipt-capable increment

The historical run below keeps its original provenance and limitations. A
fresh delta-to-CAP00 run through the same temporary TLS topology used independent
locally encrypted identities and **no clock shim**. New Linux ELF f8cfacda...
and the archived Windows CLI 6c5abc75... matched full source/target/SQL receipts
and current target SHA for 3 B and 8 MiB. Its 128 MiB attempt failed at the
unchanged 300s DATA deadline and kept schema4 stage/full debt; not a scale pass.
The first fresh full freeze was rejected by an older core pagination test;
the independent subsequent freeze passed 830/63/97, Node3/CI13 and hash
postchecks. A pureTLS16MiB control took46.18s without fleet/stage/SQL; this
does not prove a cloud bandwidth quota or relax the300s budget. See
[completion observations](windows-fleet-completion-observations.md) for exact
hashes, scope and `receipt-crosshost-20261116/` evidence. Production clock
qualification, Linux target, QUIC/NAT and generic sync remain open.

## Historical run: what was checked

Two independent stock agents exchanged files across machines via an existing
Caddy HTTPS listener instead of loopback or `ssh -R`:

- source: `delta` (WSL2, Linux 6.18.33.1, candidate binary
  `734a185c…20c6d6f`);
- relay: `tecs`, isolated candidate relay on `127.0.0.1:3212`, published as
  `https://brc.tecs.ltd:8444` (temporary Caddy site, TLS 1.3);
- target: `CAP00` (Windows 11 10.0.28000, candidate binary
  `C75B20B4…E18899E`).

The 128 source-file hashes in the Linux manifest match the corresponding
Windows candidate manifest entries byte for byte. This comparison alone does
not establish equality of every build input or equivalence of the two binaries.
The production relay on 3211, its binary and its unit file were not replaced.

## Results

| bytes | round | source statement | target statement | target file |
| --- | --- | --- | --- | --- |
| 3 | `5bc1be00…` | `source observed peer completion bytes=3` | `target settled locally bytes=3` | 3 B, SHA matches |
| 8388608 | `a3d7d3ac…` | `source observed peer completion bytes=8388608` | `target settled locally bytes=8388608` | 8 MiB, SHA matches |

Each target directory holds exactly the destination file and no stage residue.
A later read-only SQLite audit (`target-receipts-audit.json`) confirmed both
historical rows are Completed/schema 9 with `stage=null`, size/SHA matching the
current target files, and `parentDurability=unsupported`. **The original source
logs retained only completion byte counts, not full receipt fields. Cross-host
receipt parity for `receiptId/size/sha256/parentDurability` is therefore NOT
verified by this run.** The TLS-path and target-file observations remain valid;
full cross-host acceptance requires a fresh run retaining both complete receipts.
The Caddy access log records `/ws` (12) and `/fleet/ws` (6) upgrades with
TLS 1.3 (`"version": 772`) and status 101, so the DATA channel really passed
through the public TLS listener rather than a loopback shortcut.

## Non-obvious step: clocks

The product binds a lease to a local clock interval with at most 2000 ms of
uncertainty. The three hosts are not synchronized: measured against the same
Caddy response, CAP00 ran about 55 s behind and delta about 142 s behind.

- CAP00 has no usable time service (`w32time` stopped, no elevation), so the
  target stayed on its own clock.
- The source subprocess was started with a small test-only `LD_PRELOAD` shim
  (`clock_shift.so`, `clock_shift.c` archived) that shifts only
  `CLOCK_REALTIME` for that process by +87 s. No product code, host clock or
  security check was changed, and the 2 s uncertainty stayed untouched.

A first 8 MiB attempt with a static -55 s shim was rejected as
`approved local clock interval outside fixed grant` because the offset moved
between the two hosts during the session. That rejection is preserved, not
retried silently. **Production still requires real host clock synchronization;
the shim is evidence scaffolding, not a deployment recommendation.**

## Cleanup

- Caddy config restored byte-for-byte from the pre-change backup
  (`938c81dd…`); port 8444 closed; no test site remains.
- Test relay on 3212 stopped; production 3211 still reports
  `devices=2, status=ok`.
- Installed agent binaries on tecs/delta unchanged (`c7f0acba…`).
- Test device tokens and identity stores were deleted after the run; evidence
  keeps only public material, logs, configs and output bytes.

## Evidence

- root: `artifacts/fleet-p1/tls-crosshost-20261116/`
- receipt: `acceptance-8m.json`, SHA-256 `7192F1C3…27A8`
- audit: `artifacts/fleet-p1/tls-harness/verify-acceptance.ps1`
  recomputed 31 file hashes, both target files, the Caddy TLS/WS counts and
  the no-token check; result `passed files=31 results=2 caddy_ws=18 tokenHits=0`.

## Boundaries

- Temporary test relay and temporary Caddy site, not a production deployment.
- Two test agents with public test wrapping keys; no operator signing,
  certificate pinning beyond normal CA validation, or client certificates.
- No proxy traversal, IPv6, restart/resume, deletion, directory sync or
  production-scale dataset.
- Caddy sees one shared NAT address, so the access log does not by itself prove
  two hosts; host identity comes from the separately controlled SSH sessions
  and per-host log files.
- Not a release, commit or independent sign-off.
