# Windows P2 sequential driver verification

Local Windows candidate only. No operational enrollment, two-host, Linux or production acceptance.

## Frozen evidence

Directory: `artifacts/fleet-p1/syncdrive-freeze-20261114-015233/`.
112 frozen input paths. Release test SHA-256:
`dcc63e59327a91e1b0c115b2cd20eb7a7b5df77157422261b90e865d19c56fc6`.
Previous test SHA-256:
`90566a97f15ed523c458c001472703474343539582e8e22595a67ab1ca3fad09`.

| Suite | Passed |
| --- | --- |
| fmt / strict clippy | pass |
| all-features | 600 |
| default | 62 |
| doc | 91 |
| release fleet | 538 |
| release channel | 24 |
| native pressure | 4 |
| three-process harness | 1 (four sizes) |
| Node/OpenSSL | 2 |
| CI validators | 13 |

Source increment: `sync_exec.rs`, `relay_sync_exec_tests.rs`. Host, journal,
lease, crypto, protocol and pumps unchanged.

`run_plan` sequentially starts, calls a caller-supplied prepare closure, executes,
and settles each file. Two real files (4 and 70000 bytes) passed via the local
relay with matching receipts and final bytes. A pre-cancelled token invoked no
preparation. These are fixed-key, synthetic-time test sessions, not enrollment.

The first unboxed debug attempt exited with stack overflow `0xC00000FD`.
A 32 MiB stack control passed. Boxing per-file preparation and execution futures
then passed on the original default test-thread stack. No larger-stack default
was adopted.

## Postcheck disposition

All test suites passed in the original run. Its final postcheck failed because
this report had not been created, not because a test failed. The missing-report
error remains in the task log. After creating this report, rerun the postcheck
against those same raw logs and frozen hashes; that is not another test execution.

## Remaining boundaries

No retry, reconnect, persistence, overwrite, delete, trusted issuance or new
service. The driver is a local candidate; callback correctness and failure/cancel
boundary qualification require further negative tests. Historical reserve_commit
2.929s timing remains unexplained. No commit/push.
