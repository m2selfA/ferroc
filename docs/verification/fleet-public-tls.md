# Public-TLS two-host transfer (2026-11-17)

First fleet transfer where **both peers reach the relay over the public internet
with a real certificate**, instead of a loopback relay plus an SSH forward.

## Topology

- Relay: `tecs` (public cloud host), temporary instance on `127.0.0.1:3212` with
  its own database, `--fleet-setup` and a per-round `--fleet-data-config`.
- TLS entry point: Caddy site `brc.tecs.ltd:8444` -> `127.0.0.1:3212`, certificate
  `CN=brc.tecs.ltd`, issuer `Let's Encrypt`, valid 2026-11-09 .. 2027-02-07.
- Source: `cap00` (Windows), stock `ferroc.exe` `1efa50f8…c6ce`.
- Target: `3dv0` (Linux), stock `ferroc` `72576c74…4abd` (glibc <= 2.17).
- Both agents used `--no-proxy` and `https://brc.tecs.ltd:8444`; no SSH forward,
  no loopback relay, no renewal, unchanged 300 s authority.

## Results

| bytes | outcome | whole harness | target state |
| --- | --- | --- | --- |
| 8388608 | passed | 30.42 s | v11 `completed`, no stage, file SHA = receipt |
| 67108864 | passed | 199.94 s | v11 `completed`, no stage, file SHA = receipt |

Each size produced exactly one source `peerReportedCompleted` and one target
`targetSettledLocally` event with identical complete receipts; the target file's
size and SHA-256 equal the receipt (`7014ae0f…` and `103f23a1…`).

## What this adds

- The TLS path is exercised end to end by stock binaries: pairing, setup control,
  DATA admission, encrypted DATA, settlement and the final ACK all crossed the
  public internet through a certificate-validating entry point.
- The 64 MiB round ran ~200 s, i.e. far longer than the 45 s session liveness
  window, and completed without a heartbeat abort — the liveness fix from the same
  day is exercised by a real long transfer, not only by the LAN ladder.

## Capacity fact for this path

64 MiB in ~200 s is roughly 0.4 MB/s end to end. With the unchanged 300 s
link/route ceiling, a single transfer over this public relay is bounded to roughly
100 MB. That is a deployment property of this relay/route, not a defect, and it is
not a bandwidth claim for other paths (the LAN ladder did 1 GiB in 84.7 s).

## Teardown verified

Temporary relay stopped, the `:8444` site removed, Caddyfile restored from the
backup taken before the change, `caddy validate` clean and reloaded. Afterwards:
production `https://brc.tecs.ltd:8441/health` = 200, `:8444` closed, no listener on
`127.0.0.1:3212`. The production relay and its database were never touched.

## Boundaries

- Test identities, test wrapper keys and local approvals only; the relay is a
  shared public host but this instance used its own port and database, and it was
  removed afterwards. Not operational issuance, not a production deployment.
- No QUIC/NAT, no restart resume, no GUI integration, no glibc-2.17 container run
  for this round (the ELF's ABI was checked separately).
- Harness defects found here (all in the driver, not the product): a login shell
  appending a line after the helper's JSON broke parsing; the external-approval
  pairing path killed the agent it had just started; a relative `--root` broke the
  identity store's absolute-path requirement; the per-size relay restart still
  used the loopback URL; and the new Linux root needed its own `side.py` copy.
