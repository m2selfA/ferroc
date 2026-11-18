# Local peer roster (candidate component)

## Contract

`IdentityStore::enroll_peer(approval, label, now_ms)` adds exactly one peer key
to the identity directory. Admission still requires a caller-supplied expected
fingerprint through `PeerApproval`; there is no trust-on-first-use, no implicit
rotation, no network lookup and no grant issuance. A second enrolment of the
same device with a different key fails until the caller explicitly revokes the
recorded fingerprint. Revocation itself requires the expected fingerprint; a
drifted value leaves the record intact.

Each record is one create-only encrypted file named from the SHA-256 of the
device name (`peer-<digest>.fpeer`), sealed with the same DPAPI / explicit
external wrapping key used by identity and pins. Records are never replaced in
place. Reading decrypts the record and re-derives the device digest and peer
fingerprint; a stored fingerprint is not trusted as-is. A record copied under
another device digest fails authentication or the binding check and the whole
roster call fails rather than silently skipping the entry.

Bounds: at most 64 peers; labels are 1..=64 ASCII letters, digits, `-`, `_`,
`.` and must start and end alphanumeric; a label may name only one device.
Unknown record versions, truncation, tampering and oversized files are errors.

## What this does NOT provide

No endpoint or URL storage, no TLS validation, no operational signing, no
automatic peer discovery, no MCP tool, no CLI flag and no grant issuance. A
roster entry only means "this local administrator explicitly approved this key
for this device name in this fleet". It is not proof of reachability, presence,
permission or consent by the peer.

## Evidence

`cargo test --lib identity::` -> 29 passed, 1 ignored (pre-existing ignored
case), 0 failed. Seven new peer-book tests cover: idempotent same-key
enrolment with fingerprint recomputation after reopen; explicit-approval
mismatch enrolling nothing; key conflict requiring explicit revoke; self,
foreign-fleet and invalid-label refusal; duplicate label across devices;
corrupt/truncated/copied-record rejection; capacity bound and a four-thread
concurrent enrolment where exactly one caller creates the record.

All keys are PUBLIC test seeds; no production credential is involved.
