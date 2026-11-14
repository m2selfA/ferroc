# P2 plan-to-grant batch

## What it is

`sync_grant::issue_for_plan` turns one `SyncPlan` into one `ValidatedGrant` per
planned file. Structural only: no signature, no trusted clock, no enrollment, no
local policy approval, no send and no persistence. A consumer must still verify
pins/signatures, check its own policy and get admission before any byte moves.

## Fields

| Input | Rule |
| --- | --- |
| sessions | non-nil, source and target must differ |
| seeds | both non-zero and different |
| chunk | 1..=65536, carried into every grant |
| issued/lease | lease positive; issued+lease <= each job's fixed deadline |
| per-file ids | authorization/epoch derived from seed + index, unique per batch |

Every grant uses `Permission::SendFileNoClobber`, the job digest from the plan, and
the plan's `transfer_id`/`file_id`, so the grant cannot silently switch file,
paths or size.

## Determinism

Same plan plus same template gives identical grant digests and ids in plan order,
which keeps replay auditable. It does not make a batch valid later: expiry and
replay are rejected by the lease/admission layers.

## Not covered

No signing, no pin approval, no clock import, no network, no scheduling, no
retry, no `send_file`/`sync_dir` entry point, no deletion and no overwrite path.
