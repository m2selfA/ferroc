# Windows verification: optional agent setup control

## Evidence tiers

- Original six `setup_agent` tests: two local backends, encrypted stores/DPAPI,
  cancellation/history/foreign sender/write-report/lifecycle failures. Same
  process, with local leased-AEAD buffer readback; not independent machines.
- CLI control probe: three independent relay/source/target OS processes after
  real device-code approval, own encrypted identities and explicit peer pins.
  Both agents report the same round `prepared locally` while still online;
  target directory stays empty. No leased records or DATA are produced here.
- Setup-control repairs were accepted in `setup-agent-regression-20261115-210927`:
  781/63/95,259 inputs,15 gates,Node3/CI13 and independent postcheck. Final EXE
  66601534EF07BE10542202A3A086BBE05C4C40EC4C4453BE879C0FDD9DC9138F matched
  all three final process probes, unlike the earlier initial EXE below.
- The next leased-owner increment is separate; see
  [leased setup verification](windows-fleet-setup-lease.md). These historical
  setup-only numbers do not qualify that new source or DATA/file transfer.

## Diagnosed defects and fixes

1. CLI relay always called default `router()`, which deliberately rejects a
   setup hello. `relay --fleet-setup` now selects `router_with_setup`: only the
   existing `/ws` broker, not `/fleet/ws` or `/fleet/renew`. Default stays off.
   Disabled/invalid setup negotiation returns fatal `FLEET_SETUP_UNAVAILABLE`;
   the configured agent also requires the welcome capability echo.
2. Each host used `propose()` at connect, generating DIFFERENT random grant/epoch
   IDs and issuance times. A saved-config double-materialization test failed
   before the fix (actual test EXE and raw log retained). Config v2 now requires
   the exact locally selected authorizationId/keyEpoch/issuedAtMs and keeps
   sessions/job/chunk/lease fixed. Both hosts must be provisioned with the SAME
   grant material. No remote grant/time import, implicit migration or revival.
3. Result observers were only polled AFTER disconnect. They now participate in
   the live session select; their result and the outbox writer are connection-
   owned tasks that are cancelled/drained on exit, not detached. Raw paths,
   proofs and credentials are not logged.
4. CLI/config wrapping keys had incompatible encodings. Both now use 64 hex
   characters encoding 32 bytes; the environment string is zeroized after use.

## Provisioning order (correction)

Pair without setup first to obtain relay-assigned deviceId. Then create the
identity bound to that ID, exchange/approve fingerprints and bind endpoints,
then write matching v2 setup configs. The earlier claim that identity creation
MUST precede pairing was a harness assumption, not a product constraint.
Unpaired setup startup is now explicitly refused before pairing/network access.
The local CLI identity result includes public deviceDigest for exact job binding.

## Local results

- Six config tests pass, including stable materialization, legacy/future/expired
  rejection and nil/overflow refusal. Four real WS adapter tests pass, retaining
  pause/replay/old-generation/default-off/queue-boundary assertions.
- Initial post-fix success: `artifacts/fleet-p1/setup-three/success-20261115-205716/`
  (consult actual result.json; directory timestamp is not a binary identity).
  Probe EXE SHA-256: D54CEB17C010EA713F7AA6D9A6ECDCC550E042A373091F5E4B0D961793C73DCA.
  Both live local proofs, zero target entries, all five owned processes exited
  after harness cleanup (two pairing processes, relay and two configured agents).
  This binary predates the final input-hygiene/CLI-guard additions: final-binary
  probes are collected separately, never relabelled as this initial run.
- Negative process probes passed: `disabled-20261115-205850` returned the
  explicit fatal code at both ends; `mismatch-20261115-210008` rejected a different
  target keyEpoch. Neither reported prepared, both target directories stayed
  empty and all owned child processes exited. Same initial EXE SHA as above.
  Raw result.json/process logs, not the controller exit code, are the evidence.

## Harness corrections, not protocol relaxations

Old attempts had unchecked native exit codes, wrong JSON result wrapping,
reserved PowerShell variables, relative paths and broad process-name cleanup.
Current harness checks CLI exits, archives its EXE/script, uses absolute paths,
random temporary admin password in the environment (not argv), never prints
credentials, and only stops PIDs it started. Every run has its own logs.
Debug relay scrypt took 23452 ms BEFORE listen: an earlier 20s readiness check
was invalid. Harness startup/login observation allows KDF completion before
arming; the product's 30s setup round and 5s write budgets remain unchanged.
Live log reads use FileShare.ReadWrite; a previous default-share reader conflicted
with the child writer and was rejected as a harness failure.

## Not claimed

No two-machine/TLS/proxy qualification, production identity ceremony or time
service, lease installation, DATA/stage/quota/receipt, file transfer, four MCP
transfer tools, restart recovery or new scale acceptance. Historical SQL timing
anomalies and prior final-ACK delivery gaps remain open. No commit or push.
