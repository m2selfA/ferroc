# P1 renewal at an acknowledged boundary

## What it is

Renewal rotates authorization_id, key_epoch and ephemeral keys while keeping the
approved job, live sessions, chunk ceiling and total deadline. It exists so a long
transfer can continue after the short grant expires, without reconnecting or
re-reading bytes.

This is a local, explicit API. There is no timer, no issuer, no trusted-time
injection and no automatic retry. Tests use PUBLIC cfg(test) fixture issuance.

## Where it is allowed

| Component | Rule |
| --- | --- |
| SourceWindow | READY negotiated, no cached ciphertext, contiguous coverage equals the encoded prefix |
| SourceFile | live owner, object identity/size re-checked under the gate before rotation |
| HostReceiver (flow) | DATA not sealed; negotiated window and received ranges survive |
| FleetRelay route | explicit successor approval for the same pair |

A rejected renewal keeps the previous session usable. SourceWindow clears its
stale-ACK counter because a new epoch restarts the AEAD sequence; comparing
sequence values across two sealers would be meaningless.

## What survives and what changes

| Field | After renewal |
| --- | --- |
| Job digest, paths, size, SHA, deadline | unchanged |
| source/target session ids | unchanged |
| authorization_id, key_epoch, ephemeral keys | must rotate |
| read cursor, encoded count, encoded SHA | unchanged |
| peer-reported contiguous coverage | unchanged |
| target received ranges, READY window | unchanged |
| cached READY/ACK ciphertext | dropped and re-sealed on next control call |

## Relay advancement

`advance_local(current, next)` requires:

1. a live approved pair whose route binding equals `current`;
2. identical stable identity (fleet, both devices, both sessions, transfer, file);
3. identical job digest, unchanged total, chunk ceiling not increased;
4. both authorization and key epoch rotated, never reused, at most 1024 successors;
5. registry not stopped and route not expired.

Afterwards the superseded binding is rejected by `Route::validate`, so a delayed
old-epoch frame cannot re-enter. The opaque relay still cannot verify the renewal
signature, pins or time; both peers must authenticate it end to end.

## Failure semantics

- A frame that cannot authenticate (tampered, foreign or superseded epoch) is
  rejected WITHOUT poisoning the live session; that is the existing rule.
- A frame that authenticates but regresses coverage, changes the window or leaves
  the approved route DOES fault and close the owner.
- Renewal failure never restores a revoked or expired grant, never re-anchors the
  trusted interval and never extends the fixed job deadline.

## Not covered

No automatic renewal scheduling, no persisted sender state, no reconnect or
resume, no target-side journal change, no two-host or production enrollment, and
no reward for the opaque-relay stress path. Linux remains unqualified.
