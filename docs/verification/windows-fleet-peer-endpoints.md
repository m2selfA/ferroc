# Approved-peer endpoints (local candidate)

Two encrypted slots per peer (`primary`, `fallback`) store URLs under the held
private identity directory. URL policy reuses `transport::relay_url`: HTTPS or
loopback-only HTTP, no credentials/query/fragment/control characters, <=512
bytes. Writes use a private temp + sync + rename; this is file-atomic replacement,
not a Windows parent-directory durability guarantee. Only NotFound means a
missing slot; other filesystem errors fail closed.

## v2 correction

The initial v1 implementation validated a fingerprint at WRITE time but stored
only the device name. Two red tests exposed that (1) revoke/re-enrol under a new
key inherited the old URL, and (2) `.ok()` masked damaged records during `set`.
The local signing integration requires both to be fixed. v2 now stores the
approving fingerprint, checks it against the CURRENT roster on every read, and
propagates corruption instead of overwriting it. Copied-device ciphertext fails.

Authenticated v1 records explicitly fail the version gate, with no migration or
plaintext fallback. Clear healthy endpoints before revoking a peer. Stale-key,
corrupt and legacy records need separate explicit offline remediation; `set`
and `clear` do not silently repair them. No new force-clear API was introduced.

## Roster concurrency

Duplicate labels refuse the entire roster. Creating a new peer re-checks the
label and removes only the just-created record on a detected collision. This
is fail-closed admission, not inter-process serializable transactions.

## Evidence

Original endpoint increment: 6 tests plus identity group35 passed, and frozen
endpoint-regression-20261115-150712 + LOCAL task 1GiB252239ms, all for v1 inputs.
Those tests did NOT cover key inheritance or corrupt overwrite; don't reuse the
old freeze as v2 acceptance. Current targeted identity group:38 passed/1 existing
ignored, including 9 endpoint tests. See
[local signing verification](windows-fleet-local-issuance.md) for reproduced red
cases and the current full-regression receipt boundary.

No DNS, connection, TLS certificate pin, health probe, QUIC, remote registration,
operational signing deployment or MCP tools. Local role signing is a separate
explicit Runtime API, not a network service.
