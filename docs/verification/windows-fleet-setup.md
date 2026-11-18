# One-shot setup component — Windows evidence

See [contract](../design/fleet-setup.md).

## Implemented and targeted scope

- Source-offer, target-response, source-confirmation use separate Ed25519 domains.
  Each real encrypted identity store signs ONLY its local role. Final records
  require two auth-v2 signatures plus a separately supplied trusted local anchor.
-19 component tests passed in the final targeted round, including correct
  setup proof with INVALID source auth signature and deterministic export.
  Independent Node/OpenSSL reconstructed191/161/128byte canonical messages
  and matched all5signatures; old420byte auth and legacy signatures matched.
  Final targeted logs are `artifacts/fleet-p1/setup-handshake/targeted-3.log`,
  `node-setup-3.log`, `clippy-3.log`. All19 pass and strict clippy passes;
  full results belong to the new frozen receipt only.
- Tests cover public JSON transport simulation and real leased AEAD DATA readback
  at caller-approved authority time61200ms for a grant issued100ms. This is NOT
  a61s wall-clock wait or a clock-continuity experiment. Coverage also includes
  wrong proposal/recipient/profile/role/path/pin,
  re-signed invalid auth-v2 proof, crossed responses, malformed/oversize/unknown/
  duplicate/nested fields, corrupt signatures, revoke/endpoint drift, expiry and
  actual Runtime shutdown while idle setup owners remain alive.
- Two additional negatives reproduced a real local signing-time regression:
  source/target accepted199ms after their own200ms start. Both failed before
  the fix; `red-clock/` retains six affected sources, raw2-failure log and the
  actual test executable+SHA (not a full linked-source freeze). Each pending
  owner now refuses a lower local transition time; no old wire bytes changed.
- No source content read or target stage/DB allocation is performed by setup.
  Tests assert the target work directory stays empty and source bytes unchanged.
  This does not verify actual disk-full handling or per-file network execution.

`scripts/fleet-setup-oracle.mjs` independently encodes job/grant, old420byte auth
and all three new setup domains. It derives PUBLIC fixture Ed25519 keys through
Node/OpenSSL, compares deterministic signature bytes and domain/reflection
negatives, and compares legacy auth signatures with the untouched existing
control fixture. The Rust export is cfg(test)-only, CREATE_NEW, requires explicit
`FERROC_FLEET_SETUP_ORACLE_OUTPUT`; it never exports operational secrets. This is
an independent canonical/signature oracle, not a network transfer.

## Provenance and acceptance qualification

The15test first pass binary and five affected sources are separately archived
under `artifacts/fleet-p1/setup-handshake/targeted-1/`; not a full source freeze.
Later tests/Node output must use their own binary/log/source correspondence.
Full acceptance uses a NEW frozen source set and exact enumeration pins;
`--test-threads=1` remains the explicit all-feature schedule, default normal.
Previous local-setup-regression-20261115-155445 remains valid for its OLD inputs
and CLI binaries, not certification of this new setup module.

Historical parallel settlement2278.5795ms / reserve_commit2929ms remain open;
no product deadline,2s assertion, SQL lock behavior, pump or routeTTL changed.
Node three oracles andCI13 run anew. No scale outcome is borrowed as setup-path
acceptance. Later [relay-only probes](windows-fleet-setup-ws.md) are a separate
public routing evidence tier, not this signed network path. No remote agent/CLI signing orchestration, TLS pin,
Linux qualification, deployment, production data, four MCP tools or independent
source signoff is claimed. No Advisor, commit or push.
