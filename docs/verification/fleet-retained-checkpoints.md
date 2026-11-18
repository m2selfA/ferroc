# Schema12 retained checkpoints — local candidate

Explicit library-only opt-in; no new service, wire message, CLI/MCP or stock-agent
configuration. It persists checkpoint metadata and can freshly verify a stopped
named stage. It does not resume a transfer.

`HostReceiver::enable_retained_checkpoints` requires the live original named File
before DATA, empty file/coverage and current owner/lease/parent. Schema12 and mode
commit atomically. Defaults remain unchanged; Linux anonymous stages refuse this
mode and anonymous debt cannot become a retained file.

`capture_retained_checkpoint` accepts no cached observation. In the same real
Runtime gate it syncs, hashes contiguous in-memory coverage in <=64KiB blocks,
verifies any older checkpoint prefix, syncs again, and CAS-writes bounded metadata.
It rechecks lease/object/revision/length around IO and SQL, uses nonwaiting DB
access and restores busy_timeout. Out-of-order tail bytes are not coverage.

`FencedConnection::inspect_retained_checkpoint` requires explicit metadata recovery
by a DIFFERENT stopped owner under the same native DB/fence. Only Interrupted,
unsealed/uncommitted/uncancelled retained allocations qualify. Read-only reopen
checks exact private single-link file, original parent, policy and current row,
hashes the prefix with a caller budget (hard1GiB), and changes no SQL/debt. It
returns no File, lease, writer, publication or release authority. Tail length is
reported separately and is never verified prefix coverage.

## Executed verification

Second325-input archive: Windows full894/0/38, default63/0/2, docs97/0/0; Linux
full792/0/24, default62/0/2, docs93/0/0. Both fmt/strict all-features/all-targets
clippy, Node3/CI13, raw-log counts, source/image hashes and independent postcheck
passed. Evidence: `artifacts/fleet-p1/checkpoint-persistence-20261118-02/`.
Node setup uses the recorded public Rust export from unchanged auth/setup source;
it is not a new network handshake. Later canonical document changes form a
separate delta from the325 tested inputs.

Windows13/0/1 and Linux15/0/0 checkpoint tests plus original prefix8/9 passed.
Controls cover late opt-in, partial/zero/advancing prefixes, same-size mutation,
object replacement, budget, cancellation/expiry, contention, SQL failure,
POST-COMMIT expiry preserving metadata/debt, malformed metadata and downgraded
schema. A SQLite writer can remain active during stopped-owner read-only check;
the original1357ms busy_timeout is restored. Native Windowsv5→v9 settlement and
Linux anonymous transitions preserve12.

Actual archived schema11 CLI SHA256
`fd2d9c91291c8e61aecd6e8cdc90bdcde9f6725fac24acb179ae3bba97fba70b`
obtained its own fence then refused12, with row/stage/debt unchanged.

Two real regressions remain independently archived. Settlement CASE IN(10,11)
omitted12 and downgraded metadata to9 (11pass/1fail/1ignore); fixed SQL preserves12.
Independent audit executes all11 schema updates from12 and must detect the old
downgrade. Fourteen source allowlist negatives reject. Inline retained state also
expanded Snapshot to2488B and overflowed the original default stack in two-file
run_plan; the archived image reproduces alone. Boxing only retained metadata
reduced Snapshot to1920B. The exact original case and full matrix now pass with
unchanged stack settings; rejected and successful sources/images stay separate.

## Remaining boundary

A checkpoint persists a historical sync/read sequence, not immutable bytes,
assured power-loss recovery, source-prefix proof or IO authority. External/mmap
writes remain possible. SQL can commit before final expiry/error: the call fails
while metadata exists and full debt remains, without automatic retry/rollback or
cleanup. Linux stock agent still uses anonymous staging and gains no retained
writer here. Network restart resume needs a newly approved signed condition,
fresh session/epoch/time anchor, source-prefix rehash and original target File
ownership transition under the actual Runtime gate. Old deadlines, cancelled
tasks and commit/receipt history cannot be revived. QUIC/NAT and production
qualification remain separate.
