# P1 authenticated DATA flow candidate

SourceWindow consumes a not-yet-encoded Runtime SourceFile. It does NOT open a socket, prove remote private IO or expose a final completion state. Default-off fleet-core, no new service or MCP/CLI endpoint; Advisor is not used. Wire/control schemas and persistent metadata version9 are unchanged.

## Bound and transitions

- Constructor accepts1..=8 local chunks and checks actual file/Runtime/lease. Authenticated READY chooses min(local,peer) windows before reading source contents. SourceFile alone remains a lower-level unqueued API; future transport must use the wrapper.
- Full window returns Backpressured without encoding/reading another chunk. Control observation and exact-byte retries remain available. Wait asynchronously for input, do not busy-loop next_record.
- Up to8 Box ciphertexts, max min(grant chunk,64KiB)+216-byte header+16-byte tag each. Largest retained DATA payload is526144B. This excludes queue metadata, one transient plaintext+encoding buffer, incoming controls, replay book, caller copies and socket buffers; it is NOT a global process/network memory bound.
- Only authenticated cumulative contiguous ACK at an encoded chunk end releases cached frames. ACK cannot exceed encoded bytes. Selective received count is descriptive, never credit; STATUS Completed never means completion. A valid older ACK sequence is ignored, exact duplicate is idempotent, fresh regressive/mid-chunk/early-final control faults and closes file/clears retained DATA.
- Corrupt/unrelated-key unauthenticated input does not release capacity or poison a still-valid session. Authenticated semantic faults and lease/Runtime/object failures close it. DATA-stage checks require a live lease BEFORE and AFTER control crypto, even though base protocol ACK permits final settlement after expiry.
- Retry borrows the original AEAD bytes, never re-encrypts, seeks or resumes. A released offset is unavailable. FINISH consumes only after READY/full encoded stream/full peer-contiguous coverage/empty queue. AwaitingCommit still requires a separate authenticated final ACK; a peer can lie about its IO.

## Target control ownership

HostReceiver::ready_record / ack_record check current original stage File/parent/database/revision, unsealed DATA phase and active original lease. READY must precede DATA and cannot change its window. Unchanged READY/coverage counters return exact cached bytes, not new nonces. A post-write ACK describes in-memory coverage after existing write+progress code, not target commit/durability. Failed checks retain stage/debt; no cleanup/auto-retry is issued.

Controls hold the real gate and use the existing commit no_wait helper: try_lock DB, busy_timeout0, existing_fenced reads and restoration of prior timeout on both success/failure. They do NOT call journal(), reset5s or open a new write transaction. DB-mutex/EXCLUSIVE-read conflicts fail quickly; a concurrent reserved SQL writer that permits reads should not falsely fail read-only READY. SourceFile/window have no renewal API yet; Target opts out of renew once READY is emitted. Failed renewal leaves the old active session unchanged.

## Validation scope

Real files and authenticated records exercise empty/one/cross-chunk/8MiB local Targetv9+finalACK, out-of-order DATA and ACK, exact retransmission, full window, zero credit, tamper/wrong key, expiry, Runtime shutdown, source growth/truncation and invalid initial use. Actual DB mutex and SQLite writer controls cover successful read-only access and failed exclusive access, with5000ms timeout restoration. API borrow/clone/import negative compilation gates complement runtime tests.

Release-only128MiB probe writes incrementally, fills an8-frame window, decrypts authenticated records, checks full SHA and exact526144B retained peak, then verifies final peer statement. It is NOT a128MiB Host settlement or network test. Exact frozen counts/hashes/results belong in the verification report.

## Subsequent P1 relay candidate

The [same-relay channel](fleet-relay-channel.md) now composes this flow with an explicit library route/IO pump and actual loopback three-test-process probes. These do not rewrite the earlier isolated window results into two-host/production evidence. The remaining integration obligations below still apply to a production task entry.

## Original P1 next-step constraints

Connect this owner and live Target controls to the SAME relay process, a separate fleet route and reused Network proxy/TLS policy. Bound transport frame/message allocation and copies, keep control input responsive under full DATA window, and test actual relay+A+B processes before claiming send_file. Linux, two-host,1GiB source and production data remain separate evidence gates; no additional service or arbitrary SSH target.
