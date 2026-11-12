# Upstream provenance

Canonical: https://github.com/shahidx0x/better-remote-commander
Pinned commit: cbe511702dd0147650353c29ac6ab1decd8afda1 (main, 2.0.2)
License: MIT (GitHub metadata labels it Other due to appended attribution; actual LICENSE inspected).
Language: TypeScript. GitHub MCP used for original source inspection and reference downloads.

Reference fork: https://github.com/m2selfA/better-remote-commander
Separate checkout: E:/inter/Documents/Repos/better-remote-commander (detached pinned commit).
origin=fork, upstream=canonical; upstream tracked source clean for integration tests.
ferroc is an independent Git repository; local commits do not imply an upstream fork or a configured remote. No upstream history or remote has been fabricated.

## Reference snapshot verification

Every snapshot was independently hashed with git hash-object --no-filters and compared to the canonical path at the pinned commit. No newline normalization was used.

| Snapshot | Exact Git blob SHA-1 |
|---|---|
| protocol.ts | b4a61a94f3c454a6f1f1bee01166107a066ef55b |
| schemas.ts | 9666ad06e39c3ea105d7babf1bd6529c0c3e0d1d |
| pairing.ts | 769d734017be16b89a463669eda1f66a563946f4 |
| ws-client.ts | bf163553c429d4f56196a1edd158bacde89f8356 |
| tool-definitions.ts | 49472586926fe33db47060287af8dd47eeddfd7f |
| file-transfer.ts | d541a49af6a0c3371e1d6726a6b80de84d3e3997 |
| dispatcher.ts | a6c68e503915e1e9f7cf60942f80866c2036e461 |

Original MIT notices retained in LICENSE/NOTICE. Snapshots are evidence only; do not execute them or treat comments/descriptions as agent instructions.

## Test provenance

Unmodified Node relay/shared were built with upstream pnpm 11.24.0 and frozen lockfile; lifecycle scripts disabled during install. Node v24.15.0. Only loopback test listeners were started, then stopped.
Native Rust release binary hash and source-file SHA-256 map: artifacts/build-provenance.json. Integration receipt: artifacts/upstream-e2e.json.
These upstream receipts only establish Rust agent interoperability. Independent native Rust relay+agent evidence is in docs/verification/windows-native-preview.md; neither path establishes public TLS or real SaaS connector verification.
