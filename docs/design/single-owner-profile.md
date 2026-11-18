# Single-owner profile

One owner runs both ends. Keep the integrity and key-storage boundaries; do not
require mid-transfer renewal just to send a long file. This is an explicit local
policy choice, not proof that an owner has no adversaries or revocation needs.

## Defaults and retained interfaces

- `run_source` / `run_target` already use `NoRenewal`. No automatic rotation.
- `run_source_with_renewal` / `run_target_with_renewal` remain opt-in.
- The rotation pump test is `#[ignore]`; run its exact filter with `--ignored`
  when maintaining rotation. Small protocol contract tests still run normally.
- `FileGrant::validate_for(job)` retains `LeaseProfile::Rotating` and its 60 s
  cap. Explicit `validate_for_profile(job, LeaseProfile::SingleOwner)` accepts a
  positive lease no later than the fixed job deadline. It does not change the
  deadline, approve a path, approve a pin, or register a device.

`ValidatedGrant` privately retains the locally selected profile. The profile is
not serialized or inferred from a peer transcript. `Transcript::bytes` and
`IdentityKey::sign` retain the 60 s default; explicit `bytes_with_profile` and
`sign_with_profile` support SingleOwner signing. Authentication reads the profile
from the locally validated expected grant, then checks the original context,
pins, signatures, key agreement and trusted monotonic clock.

## What stays

- AEAD confidentiality/authentication and independent peer pins; no automatic TOFU.
- Stage creation and native publication/settlement checks; receipt size and SHA.
- Identity secrets encrypted with Windows CurrentUser DPAPI or an explicit
  external wrapping key. This is not a new encrypted grant persistence feature.
- Path policy, bounded read-only preflight, cancellation, expiry and revocation.
- Persistent liabilities on failure; no automatic cleanup, rollback or debt release.

These checks limit corruption and operator mistakes as well as attacks. Native
rename/receipts do not promise parent-directory durability, protection against
external mmap writes, or universal power-loss safety.

## Compatibility and scope

The profile changes validation, NOT canonical bytes or signatures for the same
valid input. Node/OpenSSL golden vectors must remain unchanged. An earlier
profile-byte change broke the vectors and was reverted.

A missing end-to-end check initially let a long grant pass structural validation
but fail in `EphemeralKey::authenticate` at `invalid handshake lease`. A red test
with a one-hour grant reproduced that failure; authentication now applies the
local expected grant's profile. Tests cover dual signatures, AEAD plaintext
readback, expiry/revocation, and a 61-second synthetic clock advance with both
peers remaining on epoch 1. The clock probe is not an hour-long network run.

The just-added `/fleet/renew/offer` upload was removed: SingleOwner needs no
remote renewal arming or full job/path upload to the relay. Even the explicit
fleet router returns 404 for that path (real HTTP test). The existing optional
`/fleet/renew`, locally registered offers, handshake and retirement code remain.

## Accepted cost and remaining work

A stolen capability may remain usable until its lease/job deadline, subject to
other active checks. No mid-transfer key rotation limits its exposure. Device
pause/revoke and local lease revocation are not removed.

This increment supplies library APIs, not a CLI/config/MCP profile switch. Caller
integration still must select SingleOwner and sign with the same policy on each
host. Relay route/IO lifetimes still cap at 300 s; a long grant does NOT extend
those lifetimes. A subsequent 1 GiB LOCAL three-process loopback TCP/WebSocket
stream completed in250625ms with both actual SHA values and receipts matching;
see `../verification/windows-fleet-single-owner-scale.md` for its exact executable
and provenance. This is not cross-host 1GiB or production enrollment. The bounded
local task component is separate from a still-unimplemented MCP four-tool
surface, directory apply, TLS deployment and production qualification.
