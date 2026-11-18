# One-shot fleet setup messages — candidate component

## Local API and trust

`Runtime::begin_fleet_setup` returns a source-only `PendingSource` and public
`SetupOffer`. `Runtime::accept_fleet_setup` takes an **independently locally
selected** expected `ValidatedGrant`, profile, enrolled peer fingerprint and
slot. It never treats decoded offer structure as local approval. Each pending
owner borrows its real Runtime/store and owns ONLY its local fresh ephemeral.
No private identity/ephemeral is serialized, cloned, extracted or reconstructed.

The target verifies the enrolled source identity's offer proof BEFORE generating
its ephemeral or issuing a target transcript signature. It returns a public
`SetupResponse` plus `PendingTarget`. Source `confirm` consumes its pending owner,
verifies target setup AND auth-v2 signatures, performs current local role
approval, and emits `SetupConfirmation`. Target `finish` consumes its owner,
verifies both source signatures, then repeats actual local role approval.
Error consumes a pending owner too; no implicit retry/revival.

`PreparedSetup::authenticate` still requires a separately approved LOCAL
`TrustedTimeAnchor` and consumes the ephemeral into existing `LeasedRecords`.
It does not install trusted time, mint routing tickets, open SourceFile, allocate
receiver/stage/SQLite metadata, or grant publication. Runtime source/host IO
admission, no-clobber/pre-image checks and leases remain mandatory afterward.
Prepared crypto is not a live Runtime IO permit: a stopped Runtime rejects IO.

## New domains, old bytes untouched

Every integer below is big endian. `H` is SHA256. Identity and ephemeral keys
are32bytes. Ed25519 signatures are64bytes. `job_digest`, `grant_digest` use the
existing exact JobSpec/FileGrant canonical encodings. Profile0=Rotating,
1=SingleOwner; the profile MUST match the caller's local choice, never inferred.

- Offer bytes: `ferroc:fleet:setup-offer:v1\0` + u16(version1) + u8(profile)
  + job_digest + grant_digest + source_identity + target_identity + source_ephemeral.
- offer_digest: `H(offer_bytes || source_setup_signature)`.
- Response bytes: `ferroc:fleet:setup-response:v1\0` + u16(version1)
  + offer_digest + target_ephemeral + target_auth_v2_signature.
- response_digest: `H(response_bytes || target_setup_signature)`.
- Confirmation bytes: `ferroc:fleet:setup-confirm:v1\0` + u16(version1)
  + response_digest + source_auth_v2_signature.

Target setup signature covers exact offer/proof and its final role signature.
Source confirmation covers exact response/proof and its final role signature.
The old420byte auth-v2, grant/job/control/AEAD encodings are unchanged. No generic
sign-bytes API is added: the crate-private signer accepts a closed three-variant
setup-message enum and checks its typed signing identity.

JSON messages use version1, unknown/duplicate fields reject, including nested
JobSpec/FileGrant/Binding. `decode` checks raw length<=32768 BEFORE serde. The
future network adapter MUST use this bounded decoder; public serde traits are
not a claim that arbitrary caller deserialization is budgeted. Canonical proofs
are binary, not hashes of JSON ordering. Signatures have exact64byte lengths.
This is a per-message parser bound, not a global memory/inflight registry bound.

## Revalidation and lifecycle

Signing reuses this Runtime's actual registry->fs_gate, no SQL/network. Local
role path, live caller-approved time, encrypted local identity, current enrolled
peer fingerprint and v2 endpoint are checked before and after proof signing.
Each later transition repeats Runtime local approval, compares identities,
ephemerals and selected local endpoint to the original round. Observed endpoint
change, revoke, wrong role/profile/path/time or stopped Runtime fails closed.
Endpoint URLs are local descriptive configuration, NOT canonical signed fields.
Concurrent external change after final check is not prevented. `now_ms` remains
a trusted-caller decision, not peer time or an automatically trusted OS clock.

Each pending owner also records its first LOCAL approval `now_ms` and rejects
any later transition with a smaller local value, even inside the grant window.
This is per-round signing-time monotonicity, not peer time validation or proof
of continuity across a separately caller-approved TrustedTimeAnchor.

Setup owns no transfer IO, so shutdown need not wait for an idle pending setup;
its next transition fails. Existing accepted transfer IO/drain contracts are
unchanged. Prepared source must still wait for target READY through SourceWindow
before reading content; completion of source setup is not proof target received
confirmation or allocated anything.

## Explicit non-goals / next integration

This component mounts no endpoint or tools. The later opt-in
[control adapter](fleet-setup-ws.md) routes public messages over the original
`/ws`; stock agents do not enable that extension. The crypto evidence here
remains same-process component verification, not independent agent processes. Each public message carries cleartext job metadata/paths;
content AEAD does not hide setup metadata from a future relay.

Consuming an owner is NOT a global replay ledger. The same offer can currently
create two independent target candidates. Their response hashes/ephemerals
cannot be cross-finished; source owner confirms only once. A network coordinator
must enforce its own bounded per-device/global inflight/generation/idempotency
admission before using these APIs. Existing relay bearer auth is only routing
identity, not peer consent. No auto grant approval from ordinary RPC arguments.

Next: reuse existing `/ws` authenticated connection-generation checks and bounded
queues, route the public three-phase exchange, then prove three truly separate
processes with independently CLI-provisioned random encrypted identities. Only
then attach shared task/catalog dispatch. No trusted time, persistent resume,
remote rollback/cleanup, operational issuance or production qualification is
claimed here.
