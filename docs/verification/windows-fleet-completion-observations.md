# Stock-agent completion receipt observations

The public-TLS probe retained the source completion byte count but not the full
source receipt. Its TLS and target-file evidence is valid; four-field
cross-host receipt parity remains unverified for that old run. Target SQL
receipts cannot reconstruct a missing source observation.

## Implementation

`src/fleet/transport_driver.rs` now emits one bounded JSON log line after each
successful source or target pump outcome. Both automatic transfers and the MCP
source task pass through this driver. The existing human-readable completion
lines remain unchanged.

The record has exactly `event`, `version`, `evidence`, `jobDigest`, and
`receipt`. `event` is `fleetTransferCompletion`, version is 1, and the receipt
uses its existing serde representation: `receiptId`, `size`, the 32-byte
`sha256` array, and `parentDurability`. Job digests are also 32-byte arrays.

- `peerReportedCompleted`: the source authenticated a peer completion statement.
- `targetSettledLocally`: the target pump succeeded and its host closed.

These are descriptive historical observations. They add no file capability,
lease, route, signature, wire message, persistence or recovery path. No file
paths, tokens, route tickets, wrapping keys or plaintext are in these records.
Matching `jobDigest` and complete receipt values allows an operator to compare
separate logs without importing either log as authorization.

A failed pump emits no success record. That absence does not establish that the
target never settled: SQL completion may precede an ACK-delivery error. A later
cancellation also cannot retract an earlier receipt or observation. The journal
remains the source of historical target state.

## Verification scope

The source increment changes only `src/fleet/transport_driver.rs` relative to
the previous candidate's Rust inputs. Format checking, strict all-feature /
all-target clippy, explicit fleet CLI build and default-build checking passed.
The CLI was immediately archived as
`artifacts/fleet-p1/receipt-observation-20261116/ferroc-receipt.exe`, SHA-256
`6c5abc75e9f052e47dc10bc71faaba5ea15b52437c7a0579519e86d45e266d8e`.
This is an incremental build receipt, not a new full frozen regression.

Three real CLI process cases passed using that exact archived binary:

| Case | Source / target completion records | SQL schema | Independent readback |
| --- | --- | --- | --- |
| automatic 3 B transfer | 1 / 1 | 9 | complete receipt parity and file SHA |
| MCP two-file 3 B replacement | 2 / 2 | 10 | both receipts, MCP snapshots and file SHA |
| cancel after 8 MiB stage admission | 0 / 0 | 4 | no receipt/published target; retained stage and full reservation |

The auditor compared all four receipt fields, not completion byte counts alone.
Two negative controls on disposable copies also passed: changing the source
receipt ID and duplicating a source event both caused rejection, while the
original evidence remained byte-identical. The acceptance-generator repair
separately passed AST parsing, 31-file regeneration, and bad-hash/self-reference
rejection controls.

## Fresh public-TLS receipt validation (separate increment)

Evidence: `artifacts/fleet-p1/receipt-crosshost-20261116/`. The same archived
Windows CLI above and a Linux release ELF
`f8cfacdabe743470ad24817ea3bd0dfc31cfc05ce310a4f252da3bc60bd93369`
ran on CAP00 and delta respectively, through tecs Caddy TLS 1.3 / the isolated
relay. All 130 Rust/Cargo inputs matched. Each endpoint created its own encrypted
identity and explicitly enrolled the other public fingerprint; no shared private
identity, clock shim or system-clock adjustment was used.

- 3 B and 8 MiB: one source and one target completion record each. All four
  receipt fields, job digest, target SQL job/receipt/schema9/stage-null and
  current target SHA matched. Independent audit controls rejected changed IDs,
  duplicate source records, changed approved sizes and nonempty pre-images.
- 128 MiB: both pumps exhausted the existing 300s link budget. Caddy observed
  299.92--299.94s DATA connections. Schema4 remained Transferring, no receipt or
  published target, stage length 105119744 B, checkpoint 104857600 B, and the
  full 134217728 B reservation retained. This is **not a scale pass**; throughput
  attribution is unresolved. The observer's separate 200s timeout is not the
  product timeout. No automatic retry or debt cleanup was attempted.
- New Linux ELF: real pinned-digest manylinux/glibc2.17 rootless-Podman
  initialize/list25/write/read passed; original canonical raw-RPC oracle also
  passed, container removed, installed binaries unchanged. Not Linux sink or
  legacy-kernel qualification.
- Clock brackets found tecs/3dv0 about +56s and delta about -87s relative to
  CAP00. The explicitly approved fixed grant interval contained both local
  wall-clock intervals without importing peer time into lease authentication.
  This tests local approval, not UTC accuracy or production clock discipline.
- The first new full frozen run was rejected: lib773 and proxy7 passed, then
  `process_pagination_does_not_drop_unread_lines` returned no lines after its
  fixed2s wait. The exact archived failing core binary (2096ae5c...) passed the
  isolated test and all18 core tests. Original failure remains rejected;
  neither source nor the2s assertion was changed. No whole-run sign-off.
- Test agents and isolated relay were stopped; Caddy restored to
  `938c81ddf13034c0c45bc20092150cf33e4365c0e3fc6864b2653a944bdede98`,
  3212/8444 closed. Production3211 health and public8441 health200 rechecked;
  installed tecs binary remains c7f0acba.... Existing user-bus ECONNREFUSED was
  not repaired or used as evidence that the relay was down.

## Subsequent complete freeze and raw TLS control

A fresh independent run, `receipt-crosshost-regression-20261116-153904`, passed
all-feature830/37ignored, default63/2ignored, doc97, Node3 oracles and CI13.
The independent postcheck recomputed276 archived inputs,15 gate logs, actual
test/CLI hashes and130 Rust/Cargo mappings to the live Windows6c5abc75...
candidate. All276 current inputs matched before this documentation-only
amendment. Original failure144032 stays rejected; no assertions or deadlines
were relaxed, and no gates were reused. The six documentation changes after
this run are separately hash-bound; the130 Rust/Cargo inputs remain unchanged.

An isolated synthetic16MiB raw HTTPS download through the same Caddy/tecs
and CAP00, with normal CA validation/no proxy/64KiB streaming hash and no
output file, took46180ms (363296B/s, client process CPU1312.5ms). This removed
fleet AEAD, flow control, stage IO and SQLite from the path and still observed
similar low throughput to the partial128MiB transfer. Thus those components
are not necessary for observing this rate. It does **not** establish a cloud
bandwidth quota, maximum capacity or exclusive cause. At this observed rate,
128MiB would take about369s and1GiB about2956s; these are estimates, not
successful transfers. The existing300s hard limit stays unchanged.

The temporary rawTLS route was removed immediately afterwards. Caddy returned
to the same original SHA,8444 closed, and production8441 health returned200.
No relay/agent daemon was started for the raw control; the synthetic public
body remains as a private Caddy-owned file without a serving route.

`frozen-acceptance.json`, `raw-tls-cap00.json` and `raw-tls-rollback.json` are
separate supplements to the immutable55-file `crosshost-acceptance.json`.
These results still do not qualify production clocks, Linux target publishing,
QUIC/NAT, generic directory API, restart/resume or a production-scale dataset.

Old public-TLS binaries, shim and missing full source receipts remain separate;
these fresh runs do not retroactively validate the historical run.

Evidence root: `artifacts/fleet-p1/receipt-observation-20261116/`.
