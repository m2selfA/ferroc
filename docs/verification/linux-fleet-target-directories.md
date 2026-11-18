# Linux explicit target parent preparation

This increment extends the existing local `transfer.createParentsBelow` option
to an explicitly approved Linux anonymous no-clobber target. It adds no service,
wire message, remote path authority or journal schema. The existing private root
and host database must already exist; config load is read-only. Source-only
rounds cannot enable the option.

The original `SetupLease` must already have consumed its own one-use route
ticket. Under the real Runtime registry→fs_gate, the owner rechecks local trust,
policy and lease. Missing parents of the exact job destination are created with
`mkdirat(0700)` relative to the retained checked parent FD. Every component is
opened with `O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC`; the original chain object IDs,
private UID/mode and policy are checked before and after each creation. Names
reuse the narrow portable ASCII profile and depth bound. A concurrent EEXIST
is a failure, never an adopted creation, deleted directory or automatic retry.
Existing private directories and their contents are retained without chmod.

Linux FDs do **not** exclude directory/ancestor rename. The rechecks detect
changes at their observation points; a rename after mkdir can leave a private
child under the moved original parent even though this call fails. Retained
handles do not turn the root into a sandbox. Cancellation or failure keeps
partial directories, with no rollback, receipt or parent-durability guarantee.
The receiver performs its own original lease/object/fence/stage and publication
checks after preparation. No file is created by the preparation API itself.

## Verification state

Evidence: `artifacts/fleet-p1/linux-parents-20261116/`.

- Red case verified against the old runtime: the newly Linux-enabled existing
  config test failed once with `target parent creation requires Windows host
  primitives`; archived actual test binary `af8c10798cba…321da` and raw log.
- The new source snapshot is independent of release `88a063a6…80ef3b` and the
  earlier Windows848/63/97 freeze. Old scale/container evidence does not qualify
  this binary. Linux **native10 / config12 / original-owner1**, strict all-target
  clippy and actual debug CLI build passed; candidate SHA
  `9485c8c309859385fe4f3d5f358269d8cbd6d80b6f17de6f658ede3bc529aeb9`.
- Windows original **directory7 / owner1 / config11** passed separately.
- Real independent stock CLI relay/source/target rounds passed for **3 B and\n  8 MiB** into two newly created private parents. Full source/target/SQLite\n  receipts and actual file SHA matched; directories0700 and file0600 were\n  independently reread, with no live stage after settlement.
- Three refusal rounds passed: option absent, existing0755 intermediate, and\n  symlink intermediate. The symlink round stopped at **setup before lease/DATA**;\n  it does not exercise the mkdir NOFOLLOW branch, which native10 covers.\n  Thirty tamper controls reject changed receipts/log events/image/debt/termination\n  state. Independent read-only SQL/file/mode/proc recheck confirmed the actual\n  state and candidate children were gone; installed full C7 SHA was unchanged.
- Evidence: `live-export/independent-postcheck.json` and\n  `actual-state-postcheck.json` under the evidence root. This is local Linux\n  loopback process acceptance, not cross-machine/TLS/scale/deployment approval.
- The subsequent safe-WS-error diagnostic increment passed Windows full freeze\n  `linux-parents-regression-20261116-210644`: **850 passed/37 ignored**, default\n  **63/2**, docs **97**, Node3/CI13, **288 inputs/15 gates**, independently\n  rehashed. This report's terminal-result update occurred after that freeze;\n  it is not represented as having the archived document hash. Full unfiltered\n  Linux release validation independently passed **707/24**, matching **731**
  pre-enumerated tests, strict clippy and CLI build. Archived inputs match
  Windows in all288 paths/bytes. Separate raw-log and actual-file rechecks
  passed; native CLI `fe17f148…b0194` references GLIBC up to **2.39**, so this
  is not the earlier glibc2.17 release qualification. Original incomplete debug
  run stays rejected. See `release-matrix/independent-postcheck.json` and
  `release-matrix/actual-files-postcheck.json`.

General remote directory scan/approval/apply, empty-directory mirroring, Linux
replacement, deletion, restart resume, QUIC/NAT and production qualification
remain separate work. The original 300-second route/IO cap is unchanged.
