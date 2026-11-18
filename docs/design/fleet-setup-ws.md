# Native setup routing over the existing /ws — candidate

## Explicit opt-in, same infrastructure

`Relay::router_with_setup` (CLI `relay --fleet-setup`) attaches only a setup
broker on the SAME Relay/listener/Store. `router_with_fleet` additionally mounts
the candidate DATA/renew routes. Default `router()` does neither. A native client must explicitly add
`fleetSetupProtocol:1` to its original protocol1 hello; welcome echoes it only
when enabled. Native hello rejects Origin, query, duplicate Authorization headers,
unknown versions and a router without the broker. An upgrade may succeed before
the hello is rejected; this is not an HTTP403 guarantee.

The unconfigured agent does NOT advertise or process this extension. Only
`agent --fleet-setup <FILE>` supplies its local backend and checks the welcome
capability echo before arming rounds. Unavailable/invalid negotiation receives
`FLEET_SETUP_UNAVAILABLE` (fatal), never a silent retry/downgrade. No new service,
port, MCP tool, trusted-time installer, route-ticket issuer or publisher is added.

## Public envelope

Client to relay:

```json
{"type":"fleetSetup","request":{"stage":"offer","id":"<non-nil UUID>","peerDevice":"<target device>","payload":"<SetupOffer JSON string>"}}
```

Response/confirmation use the same envelope, stage=`response`/`confirmation`,
`id` and `payload`; `peerDevice` is forbidden on later phases. Unknown/duplicate
fields and wrong variants reject. Raw outer envelope<=2*32768+4096bytes; nested
payload goes through the existing raw<=32768 bounded setup decoders. Legacy
/ws still has its existing1MiB frame/reassembly limit; this does not turn that
limit into32768 or claim a global process-memory bound.

Relay to peer:

```json
{"type":"fleetSetup","id":"<same UUID>","fromDevice":"<relay-authenticated sender>","stage":"offer","payload":"<original exact payload string>"}
```

Sender identity is taken from the authenticated socket. Each pending route
captures BOTH current connection generations and the broker scope; it never
reroutes an old response to a replacement socket. Both current device token rows,
`deviceId`, current tokenHash, not-paused and live scope/generation must hold
before enqueue and again before actual write. Native heartbeat also rechecks its
own credential. Checks are not atomic with external revoke/rotation: an already
admitted write may complete; no rollback or strict instant revocation is claimed.

## Bounded route lifetime

Registry uses16active,4per-device active,64lifetime spent IDs/bindings/exact job
digests. History never evicts to make space; full refuses. It is in-memory and
not persistent idempotency/restart/replay immunity across router reconstruction.
Reapproval with a new binding for the SAME exact job is refused; a different
JobSpec does not become the same job merely because paths happen to match.

A fixed30s monotonic routing TTL starts when the offer is admitted, AFTER server
startup. Response does not extend it. This is an admission/queue-check deadline,
not a TCP flush or hard cancellation deadline: a write admitted before expiry or
revocation/replacement can still complete under the existing5s send budget;
already handed-off bytes cannot be recalled. Cleanup is lazy on activity and
heartbeat; no prompt timer/drain/debt-release guarantee is inferred. Expired,
offline or replaced endpoints cannot advance at the next checked transition. Foreign role/generation errors do not mutate another entry; invalid or
out-of-order phases from the correct participant terminate its route. The actual
socket adapter closes its offending socket on protocol errors, so that socket's
OTHER pending routes can also terminate; no hidden retry is performed.

`offer_digest` and `response_digest` structurally correlate the three existing
signed setup messages; they do NOT authenticate them. Relay accepts an untrusted
declared profile only to hash structural bytes, never as local peer policy.
The target/source MUST independently perform the real setup signature, enrolled
fingerprint, explicit expected proposal/profile, local path and trusted-time
checks before IO. Device bearer alone is not E2E file authorization.

The existing per-connection32message queue is reused. `try_send` fails closed
when full; setup never waits for queue space in the socket reader. Failure
consumes route/spent history, no retry. Before WS write the delivery is checked
again; OS write still uses the original5s budget. Final remains active until
write completes or fails. Successful write means neither remote read nor peer
consent, receiver allocation, file settlement or ACK acceptance.

Disconnect cleans only that generation; unrelated/new generation entries remain.
Late in-flight network effects may still exist, and no stage/debt is deleted by
this routing layer because it owns none. No SQLite gate/fence behavior changes.

## Evidence tiers and next integration

Pure broker tests exercise exact digests, order, timeout/capacity/history and old
connection cleanup. Actual loopback TCP/WS probes exercise3public phase forwards,
exact payload preservation, connection replacement, pause, replay and default-off
negotiation. Their signatures are intentionally INVALID PUBLIC arrays: this
proves opaque routing is NOT peer authorization, not a cryptographic exchange.
A synthetic full mpsc queue separately isolates enqueue failure; not a native
TCP sink-Pending/backpressure measurement.

The earlier real two-store setup19tests + independent Node/OpenSSL oracle remain
a separate crypto component tier. A further same-process probe creates random
identities with random encrypted-store wrapping keys, forwards the REAL signed
Offer/Response/Confirmation through actual loopback TCP/WS and only then performs
LOCAL leased AEAD buffer readback. No DATA travels over the control socket, no
receiver/stage is allocated, and the target working directory stays empty.
The fixture parent still controls both stores/keys and its explicit synthetic
time authority: this is not independent endpoint custody or deployment evidence.
Neither probe proves three independent agents, operational enrollment, TLS/proxy
qualification or file transfer.

Next: a bounded, configured agent setup backend for this existing socket; each
agent supplies its own encrypted identity, expected peer/proposal and local time
authority. Then independently CLI-provisioned random-identity three-process
signed exchange and actual file path. Four MCP tools remain closed.
