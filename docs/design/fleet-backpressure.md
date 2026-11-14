# Native TCP/WS pressure and post-settlement failure probes

Extends the [same-relay candidate](fleet-relay-channel.md), without a new production entry/service or changed authentication, grant, schema or five-second IO budget. No Advisor consultation.

## Observation boundary

Pair.test_events is cfg(test)-ONLY, bounded256-entry broadcast: queue-full, first native sink.send Pending per message, actor exit. It polls the SAME future and preserves its result and timeout, not simulated blockage or fault injection. Non-test builds use the original sink.send timeout path. It is not an operational progress API.

Locked Tokio1.54.1 TcpSocket sets SO_RCVBUF before real connection/WS upgrade. The fixture records both requested65536B and actual getsockopt value. OS clamping/doubling is allowed; this is NOT an exact advertised TCP-window/global memory measurement. Native device Bearer and exact role/grant ticket remain mandatory.

## Opaque relay contrasts

Wait for BOTH observed full8-message lane and actual native sink Pending, then:

- Never read: original5s native writer/forward timeout must close the pair. Record last Pending→exit and precise error, not merely external test timeout.
- Resume: authenticate every DATA, contiguous offsets and full8MiB SHA. Pending IO and monitor ticks must not lose/reorder a consumed frame.
- Pause device while saturated: real Store revocation must interrupt before5s; at least one actor must report actual paused/rotated credential error.

Producer intentionally uses authenticated DATA without SourceWindow/READY/ACK flow to stress the opaque router. These are NOT SourceWindow transfers, filesystem publication or final completion. Resume interval is NOT v9 throughput. After deliberate socket cleanup, reset/route-closed actor errors are expected, not proof of a clean WS closing handshake.

All cases join/abort original client tasks, await both relay actor exits, assert32 socket permits/zero pairs, then remove only owned fixtures. Explicit release probes serialize ONLY to isolate these socket experiments; normal full regression keeps original parallel flags.

## True v9 followed by failed native ACK send

Public Windows run_target delegates to one private shared implementation with no-op after-settle observer. No public callback API, File mutation, DB/fence export or metadata restoration is added. The private test seam executes AFTER actual v9 and BEFORE original ACK send while holding the live final owner.

Actual SourceFile/SourceWindow and HostReceiver use native relay IO on owned blocking lanes. After v9, close the real registry and drive Target socket to actual EOF. Original ACK send must fail with `target settled locally; final ACK delivery unknown`. Independent local Host.get/Inventory must observe Completed+receipt+historical origin, no live stage/zero debt, full target bytes and drained owners. Source must return error, never PeerReportedCompleted; source bytes remain unchanged. Both actors/permits close.

This proves one local-settlement/native-send-error window, NOT ACK delivery on successful sink.send or remote private IO. No v9 rollback/delete, reconstruction from history, automatic retry/resume or lease extension is permitted. Public observer remains no-op.

## Evidence and gaps

New frozen source/exe/log/JSON, previousb0bf and earlier first-two-probe receipts stay distinct. Early fixture type/escaped-newline failures are build errors, not runtime passes. Prior SQL whole-admission2.929s timing cause remains todo66; socket evidence is not its fix.

Operational trust/task/progress/cancel, window renewal/long transfer, Linux, two-host and production datasets remain unqualified. P2/P3 remain later phases.
