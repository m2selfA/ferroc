# Local grant proposal and role approval (candidate implementation)

## Entry points

`issuance::propose(job, ProposalOptions)` constructs one structurally validated
FileGrant with random authorization/epoch IDs. This is not trusted issuance,
durable idempotency or retry permission. Both hosts must approve the SAME
proposal, not generate separate ones.

`Runtime::approve_fleet_grant(store, LocalApprovalRequest, now_ms)` returns
SignedLocalGrant: exact grant/transcript, ONE role signature, locally derived
pins and descriptive selected endpoint. It does not sign for the other host.

## Identity and path semantics

JobSpec devices are `device_digest(device_name)`, NOT public keys. The local
store's fleet/name and explicitly enrolled peer must match the requested role.
Transcript keys come from the encrypted local identity and freshly read roster;
the expected peer fingerprint is mandatory.

Only this host's role path is resolved by this Runtime Policy: source_path for
Source, destination_path for Target. The remote path belongs to the peer's OS
and policy. This corrects the original draft's impossible both-paths-on-one-host
assumption. Policy resolution is not private-file admission, source existence or
SHA proof, no-clobber reservation, a sandbox, or publication permission.

## Signing boundary

Uses existing registry -> real fs_gate; no SQLite or network. Checks admission,
transfers enabled, selected endpoint, fingerprint, local identity, caller time,
then signs only its role on the exact grant and both public ephemeral keys.
Re-reads roster/key/endpoint before returning. `now_ms` is trusted-caller input,
not peer time or a clock service. This does not install TrustedTimeAnchor.
Dual signatures, locally trusted time, leased authentication and the existing
source/host IO gates remain required. Returned approval is a historical event,
not a live capability; external changes after the last check are not prevented.
The endpoint is descriptive local metadata, NOT added to canonical wire or
signature bytes. Peer identity and both ephemeral keys ARE signed.

## Required endpoint correction

Endpoint v1 bound only a device name, not the approving key. Revocation plus
re-enrolment could inherit its URL. Two red tests also exposed `.ok()` masking
corruption during replacement. Endpoint v2 stores the approving fingerprint and
compares it to the current roster. v1/key drift/corruption fail without migration
or silent overwrite. Clear healthy endpoints BEFORE peer revocation; orphaned,
corrupt or legacy files require explicit offline remediation. No force-clear or
migration API was added. This is NOT a SQLite schema change.

## Non-goals

No remote consent/registration, relay ticket/routing approval, TLS connection or
certificate pinning, time service, MCP catalog, resume, apply or rollout. No
fixture signing key on the production path; default fleet feature unchanged.
