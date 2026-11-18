# Actionable host-admission refusal when debt exists

When a host database still carries an unresolved obligation, `FleetHost::resume`
refuses admission. The message used to be a single sentence that told an operator
what was wrong but nothing about the size, the shape or the next command. It now
carries bounded, non-identifying diagnostics:

```
target host resume: unresolved inventory/debt blocks host admission: complete=false
reservedBytes=16777216 slots=1 findings=["anonymousStageUnobservable"];
inspect with `ferroc fleet-inventory`
```

Included: whether the scan completed, reserved bytes, occupied slots, and the
finding KINDS. Deliberately excluded: any path, digest, owner id or peer detail —
the message is meant to be safe to paste into an issue or a team channel, and the
full detail stays behind `ferroc fleet-inventory`.

## Evidence

Live, on the crashed database from the SIGKILL round (16 MiB staged, anonymous
stage), by re-running a new job against the same database with the rebuilt Linux
binary (`4ff03469…fbfe`):

- refusal text as quoted above;
- `debtBefore` `[(16777216, "transferring")]` and `debtAfter` identical — the
  refusal changed nothing;
- still no destination file, still no completion events.

## Tests

The existing `target_receipt_tests` case that asserts the refusal now also requires
`reservedBytes=`, `slots=`, `findings=`, the `fleet-inventory` hint, and asserts the
message does NOT contain an allocation filename. 36 tests in that module pass.

## Boundaries

- Diagnostics only: no admission, release, retry or resume behaviour changed.
- The frozen input set for this tree is 314 files (18 sources + 12 documents in the
  increment), audited by `artifacts/fleet-p1/fleet-cli-20261117/audit.py` with 11
  negative controls; the receipt for this exact tree is named in
  `artifacts/fleet-p1/last-cli-preflight-regression.txt`.
- The finding kinds are a closed mapping; unknown kinds render as `other`.
- This is Windows-and-Linux library behaviour; the live run above was on Linux.
