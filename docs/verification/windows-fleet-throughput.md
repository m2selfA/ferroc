# Fleet large-transfer throughput and lease ceiling

Status: **candidate increment**. Throughput work only; the ≥1 GiB network
requirement is still NOT met, and the reason is structural, not a tuning knob.

## Measured before/after (local three-process relay, 128 MiB, 256 KiB chunks)

| variant | wall | note |
| --- | --- | --- |
| original (64 KiB chunks, fsync + SQL commit per chunk) | 48.4 s | ~2.6 MB/s |
| grouped durability + coarse checkpoints | 40.1 s | still capped at 64 KiB by the source |
| source honours the granted chunk (256 KiB) | 31.7 s | ~4.0 MB/s |

Isolated costs on this machine's E: volume (NTFS, HDD-backed volume):

- one `FlushFileBuffers` per 64 KiB: 11.2 ms/chunk, i.e. 23.0 s for 128 MiB
- same bytes with one flush: 0.97 s
- `Get-Acl` per call: 1.6 ms; open/close: 0.16 ms

So the per-chunk durability point was the dominant cost, and the source's hard
64 KiB cap silently defeated a larger grant.

## What changed

- `HostReceiver::write_record` groups `sync_data` at 4 MiB instead of once per
  chunk. Sealing re-reads and re-hashes the whole stage before any receipt, and
  an unsynced tail can only lose stage bytes: no target file appears and the
  stage debt is preserved. Grouping weakens nothing that a receipt claims.
- Received-byte journal checkpoints are grouped at 4 MiB **only for jobs larger
  than 4 MiB**; small transfers keep the exact per-chunk journal so existing
  observations and tests still hold. It is a checkpoint, never a resume token.
- `SourceFile::read_one` now uses the granted chunk size (bounded by
  `MAX_DATA` = 256 KiB) instead of `min(..., 65536)`.
- `SourceFile` re-opens the pathname and parent every 32 chunks rather than on
  every chunk; `finish()` still re-verifies both before accepting the stream.

## Why ≥1 GiB still does not pass

Two product invariants, not performance:

- `MAX_LEASE_MS = 60_000` — a grant lease may never exceed 60 s.
- `approve_local` routing TTL is capped at 300 s.

At 4 MB/s, 1 GiB needs ~250 s, so it needs mid-transfer renewal, and renewal
today exists only as library calls (`SourceWindow::renew`, `receiver.renew`,
`FleetRelay::advance_local`). There is **no relay-side renewal endpoint** and
the IO pumps never trigger renewal themselves. Until those exist, any transfer
longer than the lease fails with `fleet monotonic lease expired` no matter how
fast the disk is.

## Fixture knobs added (test-only, `cfg(test)` seeds unchanged)

`FERROC_FLEET_TEST_DEADLINE_MS`, `_TTL_SECS` (≤300), `_LEASE_MS` (≤60000),
`_LINK_SECS`, `_CHUNK_BYTES` (≤262144), `_WRITE_INPUT`.

## Regression

Windows: `fmt`, `clippy -D warnings`, `all-features --all-targets`,
`default`, `--doc` all exit 0; 614 `all-features` lib tests and 820 total
passed across the five invocations. Two earlier logs in this session are
invalid: one had `clippy` failing on a lint I then fixed, one failed to remove
`target/debug/ferroc.exe` because a stale process held it.

## Still open

Relay-side renewal endpoint and pump-driven renewal (the actual ≥1 GiB
blocker); `transfer_get`/`transfer_cancel`/`send_file`/`sync_dir` MCP
surface; directory-level apply; non-loopback TLS; restart-resume; production
acceptance.
