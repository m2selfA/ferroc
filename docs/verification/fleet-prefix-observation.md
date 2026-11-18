# Live named-stage synced prefix observation

`HostReceiver::observe_synced_prefix` is an explicit local candidate API. It
returns `SyncedPrefixObservation` while retaining the existing live writer. It
adds no listener, tool, service, persistent record, schema version, resume entry
or source seek. Pumps do not call it automatically.

The prefix comes from in-memory contiguous authenticated coverage. A written
out-of-order tail can make file length exceed that prefix; journal received is
also not a coverage proof. The same original File is sync_data'd and then read
in at most 64 KiB blocks under the actual Runtime fs_gate. Each block checks the
current lease, object/parent and journal revision. DB access uses no_wait and
Journal::existing_fenced, restores busy_timeout and never waits for the DB mutex
or a SQLite writer while holding gate. Original parent handles are retained for
the read sequence. Final metadata IO is followed by another lease check.

Success returns descriptive bytes/SHA/job digest/grant digest/revision and object
identities. It does not advance received/revision, seal DATA, publish, settle or
release quota. The live writer can accept subsequent DATA. Failure faults the
writer and preserves stage and full debt. Anonymous stages are explicitly
rejected; existing schema11 anonymous bytes cannot be reopened after FD loss.
The description owns no File, lease or host and cannot reconstruct a receiver.

## Meaning and limits

This is a sync-completion event followed by a read sequence, not a coherent or
immutable snapshot, nor proof that all read bytes were included in the preceding
flush. External/mmap writes remain possible. A native control changes the first
byte after its block was read: the first returned SHA describes the old sequence,
while a fresh observation sees different bytes. This is an intentionally tested
limit, not a stable-content claim. Full prefix validation against a new source
read and stopped-owner re-observation remain required for future resume.

Do not serialize this returned value into the existing journal and call it a
durable checkpoint. A future opt-in retained-stage format needs an old-reader
version gate, atomic checkpoint metadata after sync/read in the SAME gate,
explicit crash-window controls, stopped-owner/fence verification, and a new
peer-approved session/epoch with independently recomputed prefixes. Commit or
publication history must not become a resume writer.

## Executed evidence

`artifacts/fleet-p1/prefix-observation-20261118` contains the independent 319-input
archive, Windows receipt, Linux logs/receipt and independent postcheck. The Rust
change relative to the preceding GUI archive is exactly four files:
receive.rs, receive_tests.rs, prefix_observation.rs and prefix_observation_tests.rs;
Cargo inputs are unchanged. Windows 8/0/0 and Linux 9/0/0 passed, with fmt and
strict all-features/all-targets clippy on both platforms. Test image hashes and
individual log hashes are recorded. Linux additionally tests anonymous rejection.

Controls cover partial prefix with continued writes, out-of-order tail/zero
prefix, cancellation, expiry during hashing, truncation, DB mutex contention,
SQLite writer/read-only observation with busy_timeout restoration, and the
same-size rewrite limitation. Reservations and schema remain unchanged. This is
targeted component validation; it does not inherit the 317-input GUI full-suite
results or claim a new full-tree freeze. This report and later rule updates are
separate documentation deltas from the tested 319 inputs.

Later schema12 checkpoint capture and stopped-owner readback have independent
325-input verification; see [fleet-retained-checkpoints.md](fleet-retained-checkpoints.md).
The observation API here still writes no metadata and grants no resume capability.
