# Fleet MCP task lifecycle and explicit provisioning

## Current capability versus planned directory synchronization

Only an explicitly configured `fleet-core` agent with `transfer.mcp:true`
attaches the four tools. Default agent, default build and unconfigured GUI do
not advertise them. The existing Runtime, `/ws`, relay listener and OAuth MCP
surface are reused; no additional service is required. The local configuration
CLI initializes encrypted identities and explicit peer pins/endpoints; it does
not itself start a transfer or trust a wire-provided grant.

`send_file` and `sync_dir` accept only locally preapproved source round ids.
They do not accept paths, hashes, permissions, peer pins or trusted time from
MCP. Each configured round binds the same exact grant at both endpoints, with
independent local-role policy approval and signatures. Three-phase setup is
not DATA permission: separate locally approved route presentations must yield
the one-shot ticket held by the original `SetupLease`. That same owner consumes
the ticket into `FleetLink` and hands its original records to the existing pump.

`sync_dir` currently registers 1..=8 unique preapproved rounds (the setup file
currently supplies at most four), then starts one at a time. It is **not** the
planned checksum manifest/diff/dry-run/apply API. Explicit per-file replace
jobs can carry a bound target pre-image, but the tool does not discover or
mint replace authority. No automatic deletion, rename or empty-directory mirror.

The separate `fleet-dir scan/dry-run` CLI now exposes LOCAL read-only Windows/Linux
observations, exact-subtree rules and bounded manifest pages under the same Runtime
policy. It neither changes this MCP API nor imports observations as transfer
approvals. See [entry contract](../verification/windows-fleet-directory-entry.md).

## One Runtime task table and cancellation

The MCP table is installed as the same `Runtime::fleet_tasks()` attachment,
atomically with MCP service registration. An existing table is not overwritten.
A short registration lock validates the whole batch, job uniqueness, retained
capacity and budget before any launch. Shutdown races after validation cancel
any already registered ids; no remote IO is hidden behind a failed request.

Each call returns a task id promptly: the existing agent RPC observation cap
is 120 seconds while transfer task budgets can be up to 300 seconds. An RPC
observer disconnect is not task cancellation. Retained terminal entries still
occupy capacity and prevent duplicate jobs; no auto-retry/reconnect/resurrection.

`transfer_cancel` takes exactly one of taskId, roundId or a unique bounded
round list. Invalid requests are rejected before cancellation effects. The
local task is marked cancelled before dropping the undelivered owner waiter.
Setup enqueue and session consumption recheck the exact task. If setup already
began, cancellation cannot retract its historical messages or remote effects.
An interrupted/failed batch stops subsequent starts and abandons remaining
waiters. Late cancellation cannot withdraw a completed receipt.

Runtime stop closes task/setup/host admission, requests cancellation, drains
owned futures before host Operations, and preserves readable terminal history.
Workers must not await their own Runtime shutdown. External receiver/DB/fence
owners remain explicitly Drop/close responsibilities. Session termination drops
its own pump/lease owners; no operation deletes a retained stage or forgives debt.

## Target parent preparation

The optional target-only `transfer.createParentsBelow` approves creation of
missing ancestors of each exact local job destination below an existing private
root. It defaults off, supplies no new peer path authority, creates nothing
at config load, and is executed by the original live Target owner under the
real registry -> gate. Native private ACL and pinned original ancestors are
retained through host admission/publication. Partial directories remain after
failure/cancel; file publication and journal settlement stay on the original
path. Linux anonymous targets use checked openat/mkdirat0700; retained Linux
FDs do not exclude ancestor rename. See [Windows boundaries](../verification/windows-fleet-target-directories.md)
and [Linux boundaries and separate evidence](../verification/linux-fleet-target-directories.md).

## Observations are not proof of current remote bytes

`transfer_get` exposes local phase and descriptive peer observation. Planned,
encoded, coverage and committed counters are distinct; unknown is null, not
zero. Source-authenticated receipts are peer statements, target SQL receipts
are historical local native events, and parent durability remains Unsupported.
They do not prevent external writers/mmap or prove current content after return.

`control::Status::Cancelled` requires confirmed cleanup; local pump interruption
retains stage/debt and cannot use that stronger label. A target settlement may
precede source interruption; cancellation cannot undo v9 history or zero debt.
Uncertain final-ACK delivery must not be converted into source success.

## Evidence and open work

[Four-tool evidence](../verification/windows-fleet-mcp-tasks.md) includes real
loopback relay OAuth `/mcp` send_file/get and sequential rounds, not just stdio.
[The current increment](../verification/windows-fleet-target-directories.md)
adds native parent creation, cancellation/admission negatives and lifecycle/schema
repairs. Its final receipts must be evaluated separately from older frozen CLIs.

Remote directory scan/diff-driven apply, general deletion/renames, restart resume,
Linux target primitives, two-machine TLS/production-scale qualification and
operational deployment remain separate work. Default pumps still use NoRenewal;
SingleOwner profile and fixed deadline require explicit local approval. Existing
parallel 2-second SQL scheduling failures and final-ACK gaps are not closed by
an unrelated successful native or scale probe.
