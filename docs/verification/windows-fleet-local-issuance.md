# Local role approval and signing — Windows candidate

See [contract](../design/fleet-issuance.md). These are explicit library APIs, not
MCP tools or a running operational signing service.

## Locally executed

- `cargo test --locked --offline --all-features --lib issuance::`: **9 passed**.
  Two independently persisted random identities and reciprocal peer approvals
  sign the SAME long SingleOwner proposal. Both leased sessions authenticate;
  AEAD DATA decrypts as `abc`. Using the local signature for both roles fails.
  This is local crypto, not network transfer or a one-hour wall-clock run.
- Negative coverage: time overflow/zero/ceiling/deadline, equal/nil sessions,
  chunk zero, replace pre-image/version, wrong role/fleet/device/fingerprint,
  local path escape, absent/revoked peer/endpoint, zero/reflected ephemeral keys,
  expired/future time, stopped Runtime, transfers disabled. Remote OS paths are
  not falsely checked on this host. Job/ephemeral tampering invalidates signature.
- Endpoint rotation changes returned metadata, not canonical signature bytes.
  A URL-signature binding is NOT claimed.
- `identity::`: **38 passed, 1 pre-existing ignored**. Red negatives reproduced
  key-rotation URL inheritance and silent corrupt-record overwrite (6 pass / 2
  fail before fix). Selected affected sources, raw log and actual red executable
  with SHA are retained in `artifacts/fleet-p1/local-issuance/red-endpoint/`;
  NOT a full source freeze of every linked module. Both pass after fix. An
  additional test seals a real authenticated v1-layout endpoint and proves
  version rejection rather than AEAD failure, with no automatic migration.
- Strict clippy and targeted passes are separate from full frozen regression;
  only that run's verification.json may certify complete regression.

## Evidence boundaries

Prior endpoint-regression-20261115-150712 and runtime-task-scale-20261115-151511
(1GiB 252239ms) certify THOSE frozen binaries, not the new signing entry. The
increment does not change pumps/wire encoding. Full regression/golden oracles
are rerun; no old or redundant 1GiB result is claimed as signing-path acceptance.

No deployment, remote signing exchange, TLS connection, two-machine operational
acceptance, four tools, Linux qualification or production-data claim. No Advisor,
commit or push.
