# P2 additive sync run ledger

## Boundary

`sync_run::RunLedger` tracks one additive run in memory. It does not send, retry,
persist, schedule concurrently or prove that the peer stored anything. A receipt
stored here is the peer's statement, observed locally.

## Rules

| Rule | Reason |
| --- | --- |
| files advance in plan order | no skip-ahead past an unfinished file |
| one file in flight | no overlapping transfers in this ledger |
| settle needs exact receipt size and SHA-256 | same-size wrong-content receipts are rejected without mutation |
| a failure blocks the whole run | no silent continuation, no retry, no revival |
| settled receipts and bytes are kept | history stays auditable after a failure |
| empty plans and zero-byte files | both are representable |
| cancel stops the run | in-flight file becomes Cancelled; nothing is rolled back |
| cancel after failure or completion | refused |
| `status()` | derived from local facts; Complete is not delivery proof |

`settled_bytes` counts accepted receipt sizes only; it is not traffic, encoded
bytes, or durability.

## Not covered

No signing, pin, clock, policy, admission, transport, persistence, restart,
resume, delete or overwrite. The eventual executor must wire this ledger to the
existing host/source/relay pumps and keep the same one-file-at-a-time ordering.
