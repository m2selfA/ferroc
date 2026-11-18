# Local fleet setup CLI — candidate, no network transfer

Available ONLY when built with `--features fleet-core`; default builds do not
advertise or accept `fleet`. No new listener/service or MCP tool is activated.
Existing stdio/HTTP/agent tool catalog and relay routing remain unchanged.

## Build and explicit identity scope

```powershell
cargo build --locked --features fleet-core --bin ferroc
$bin = '.\target\debug\ferroc.exe'
$store = "$env:LOCALAPPDATA\ferroc-fleet"
# Use the SAME non-nil fleet UUID on both hosts. Device IDs must be their actual
# existing agent device IDs; these commands do NOT register or invent them.
$fleet = '<same fleet UUID>'
$device = '<this agent device ID>'
& $bin fleet --store $store --fleet-id $fleet --device-id $device init
& $bin fleet --store $store --fleet-id $fleet --device-id $device identity
```

The parent must exist and be trusted. Init creates a private directory and one
protected identity; any existing store refuses init. Identity only reopens; a
missing/corrupt key is never regenerated. Output contains PUBLIC key hex and
fingerprint, never private key or wrapping-key bytes. Independently verify the
fingerprint out of band; copying both key and fingerprint from an unverified
channel is not independent approval and is not TOFU protection by itself.

Windows defaults to CurrentUser DPAPI. On other platforms the default refuses;
explicit `--wrapping-key-env VARIABLE_NAME` selects a 32-byte hex external key
from that environment variable, on every call. Only the VARIABLE NAME appears
in argv. The key must be securely provisioned/recoverable outside this CLI;
there is no plaintext fallback or automatic key generation/storage. Environment
secrets remain subject to the OS process-environment threat model; no absolute
memory secrecy is claimed. Invalid/missing values are omitted from diagnostics.

## Enroll an independently approved peer

Append one of these commands after the same fleet/store/device arguments:

```text
peer enroll --peer-device <peer ID> --label <label> --public-key <64 hex PUBLIC key> --expected-fingerprint <verified 64 hex>
peer list
endpoint set --peer-device <peer ID> --slot primary --url https://relay.example:8441 --expected-fingerprint <verified 64 hex>
endpoint set --peer-device <peer ID> --slot fallback --url https://fallback.example --expected-fingerprint <verified 64 hex>
endpoint list --peer-device <peer ID>
endpoint clear --peer-device <peer ID> --slot primary --expected-fingerprint <verified 64 hex>
peer revoke --peer-device <peer ID> --expected-fingerprint <verified 64 hex>
```

Both slots must be cleared before ordinary CLI peer revocation. Endpoint v2
requires the current approved key. Stale-key/legacy/corrupt records fail closed;
no force-repair or migration command was added. `--no-transfers` blocks the
configuration command before files are created. There is no command to print
private keys, sign for a peer, activate a route, send/sync a file or resume work.
JSON marks `localOnly=true`, `mcpFleetToolsEnabled=false`.

## Locally executed evidence

Seven actual `ferroc` subprocess tests cover init/reopen/overwrite refusal,
mandatory matching fingerprint/no implicit trust, endpoint rotation and ordered
revocation, wrong key/device/corruption retention, secret diagnostic redaction,
no-transfers rejection and the unchanged shared tool catalog. A real Windows
DPAPI CLI identity reopens and refuses the external-key backend without mutation;
on Unix the equivalent default-backend test requires refusal, but Unix execution
was NOT performed here. A separate default-feature test requires `fleet` absent
from help AND rejected by parsing.

New complete regression is explicitly scheduled with `--test-threads=1` for the
all-feature suite, same test assertions and product deadlines. The prior parallel
issuance-regression-20261115-154303 stays REJECTED: settlement own2278.5795ms,
fixture lock16.5541ms exceeded2s. Same archived executable isolated controls were
15/12/13ms; this does NOT close the historical performance root cause. The failed
library had680 passed/1 failed/35 ignored and later suites were not executed.

Full results/actual CLI binary mapping belong to this run's own verification
receipt. No prior 1GiB receipt certifies the CLI or local signing path. No commit,
push, remote deployment, Linux qualification or four-tool capability is claimed.
