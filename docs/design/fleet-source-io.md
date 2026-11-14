# Fleet P1 source-file IO candidate

A separate [SourceWindow](fleet-flow-control.md) now adds authenticated READY/cumulative ACK and bounded ciphertext retention over SourceFile. SourceFile alone retains its original unqueued API; neither type is a network channel. The original IO results remain separately archived.

## Execution policy

The user explicitly stopped Advisor consultations and requested implementation. No Advisor call, read-root activation or plugin modification is a development prerequisite. Historical independent source sign-off is still absent, not retroactively passed. This increment starts the originally planned P1 source IO; it does not add more P0 prerequisites. Linux, actual relay+A+B, two-machine and production-data acceptance remain outstanding.

## API and safety contract

`Runtime::open_fleet_source(LeasedRecords) -> SourceFile<'_>` is compiled only under default-off `fleet-core`, never exposed by CLI/MCP/GUI/relay. It accepts only a fresh initial Source-role session. The only path is the signed/approved JobSpec.source_path, resolved by the actual Runtime policy; transfers-disabled and terminal Runtime state reject admission. No caller-supplied file, path override, fs_gate or restored Snapshot.

Source and parent are retained ordinary read-only handles. Source files do not require private DB/identity ACLs; roots/parents are trusted local paths and policy is not an OS sandbox. Symlink final components, reparse objects, special files and multi-link regular files are rejected. Windows reserves deny-delete sharing and reuses existing native file-ID primitives; Unix uses no-follow/nonblocking opens and dev/inode IDs. Native Linux execution is not implied by this source branch.

Every operation uses existing registry→filesystem-gate order, matching host construction, without holding SQLite. Source IO is synchronous and needs a blocking lane in a future async transport. Holding the registry during one operation makes Runtime shutdown wait for that admitted operation, not for idle SourceFile owners. Idle handles remain until failure/revoke/Drop; after terminal shutdown no new read/FINISH may enter. This is not immediate cancellation of a blocking OS call.

`next_record()` reads at most min(granted chunk,64KiB), performs current object/size/path/parent and lease checks around IO, then calls the existing SourceEncoder. Plaintext staging is zeroized. Returned bytes are encoded ciphertext, NOT network delivery, ACK or durable progress. None means the approved count is exhausted, not successful transfer completion. Any read/object/lease/encoding error permanently revokes this owner and closes both source and parent handles; no automatic reopen, retry or resume.

`finish(self)` checks current object/size/lease and consumes the encoder. Its cumulative encoded count/SHA must match the approved job before cached FINISH is exposed. This binds the encoded stream: after abc was read/encoded, an external same-size rewrite to xyz may leave current source xyz while the approved abc stream validly finishes. It is not a coherent or later source snapshot. Conversely, changing bytes before they are encoded causes a mismatch and prevents FINISH. External processes/mmap are not serialized by Runtime's gate.

The first SourceFile candidate has no renewal or sender journal API. It fails closed on expiry rather than implicitly extending/restarting; pure SourceEncoder's existing renewal contract is unchanged. Future transport must coordinate control/revocation/renewal, retain exact ciphertext for retries and enforce a bounded window: callers can otherwise accumulate returned Vecs. No network allocation/memory bound, sender persistence or restart completion is claimed.

## Local validation scope

Real files are used for zero, one, cross-chunk and 8MiB SourceFile→DATA→Target v9 settlement→encrypted ACK tests. Existing pure-record tests remain separate. Negative tests cover policy escape, disabled transfers, wrong role/used session, missing/directory/wrong-size input, hardlink, growth/truncation, changed pre-read SHA, partial coverage, revoke/expiry, terminal Runtime and Windows replacement denial. Handle release is checked while the failed owner still exists, not only after finish/Drop. A small-grant control uses 3/3/3/1-byte chunks; an encoded-stream/later-source control prevents overclaiming current-byte stability.

The explicit ignored release-only128MiB probe writes and hashes with one64KiB fixture buffer, reads the real source and decrypts authenticated records incrementally. It exceeds the old BRCX199MB limit but is NOT a network or128MiB Target-journal settlement test. Exact results, current binary/source hashes and unresolved gaps belong in the verification report, not inferred from this contract.

## Next original P1 work

Add bounded control-priority flow and a real authenticated relay-only source/target channel in the existing relay process, then verify relay+A+B processes with negative auth/interrupt/no-clobber/SHA/cancel/ACK-loss cases. No second service, P2 apply, deletion or QUIC shortcut. Keep production opt-in and platform claims behind actual evidence.
