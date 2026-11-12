# Tag-only build and preview publication

## Contract

`.github/workflows/ci.yml` runs **only on pushed tags** (`**`, including names with slashes). Branch pushes, pull requests, schedules and manual dispatch do not start it. Deleted tags do not build. Publishing this source repository or pushing `main` does not create a release or a version tag.

| Asset | Contents |
|---|---|
| `ferroc-windows-x86_64.zip` | MSVC CLI `ferroc.exe`, WindUI GUI `ferroc-gui.exe`, licenses, Windows resource receipts and `BUILD-INFO.json` |
| `ferroc-linux-x86_64-glibc2.17.tar.gz` | GNU/glibc CLI `ferroc`, compatibility receipt, licenses and `BUILD-INFO.json`; no Linux GUI |
| `SHA256SUMS` | SHA-256 of the two archives |

There is no macOS, ARM or musl artifact. All automatically created GitHub releases are **prereleases**, not full BRC equivalence or independent security certification. GUI mouse/tray/copy-path acceptance is separate from CI. Runtime does not need Node/Python/Docker; Python and Docker are build/verification tools only.

Both platform jobs must succeed before the publication job runs. Assets first upload to a draft prerelease, which is published only after upload succeeds. Existing releases/assets are not silently overwritten; an incomplete draft requires operator inspection before retrying. Job tokens are read-only except the final publisher's `contents: write`; checkout credentials are not persisted. Actions are pinned to commit SHA.

## Linux glibc gate

- Build host: Ubuntu 24.04; pinned Rust 1.98.0, cargo-zigbuild 0.24.1 and Zig 0.14.1.
- Explicit target: `x86_64-unknown-linux-gnu.2.17`, generic x86-64 CPU. A new Ubuntu runner alone **does not** produce an old-glibc-compatible executable.
- `scripts/verify-linux-compat.py` checks the actual ELF64 x86_64 file, version **requirements** (not definitions), `GLIBC_* <= 2.17`, supported dynamic libraries, interpreter and absence of DT_RELR. Missing/unrecognized/private ABI labels fail closed.
- Then the same binary is mounted read-only in the immutable manylinux2014 x86_64 image. `getconf` must report glibc 2.17. Network is disabled; actual stdio initialize, exact 25 unique tools, write and exact readback must all succeed. Failure cannot leave a previous passing receipt.
- Runtime image: `quay.io/pypa/manylinux2014_x86_64@sha256:62eeff30ef134a85ec0f97109e008a319b0315ca5e8a6d754ee771556c02622a` (Quay tag `2026.11.07-1` when inspected).
- Node-based Actions run on the modern host, **not inside** the old-glibc container. This is native GNU/glibc userspace validation on the CI host kernel, not proof of an old distribution kernel, all optional features or production load.

Sources: [cargo-zigbuild target/caveats](https://github.com/rust-cross/cargo-zigbuild#specify-glibc-version), [Rust GNU platform baseline](https://doc.rust-lang.org/rustc/platform-support.html), [manylinux project](https://github.com/pypa/manylinux), [Quay tag metadata](https://quay.io/api/v1/repository/pypa/manylinux2014_x86_64/tag/?limit=3&onlyActiveTags=true).

## Creating a preview tag

Only when ready to build/publish a version (example, not automatically executed):

```sh
git tag -a v0.1.0-preview.1 -m "ferroc 0.1.0 preview 1"
git push origin v0.1.0-preview.1
```

Align Cargo.toml's version when preparing a new version; tag and actual source commit are both recorded in package metadata. Do not move/reuse a published version tag. Inspect Actions logs and archive SHA256SUMS before distribution. Build provenance and ABI/runtime receipts belong to the actual tag build; historical Windows executable hashes must not be relabeled as new CI assets.

## Verification status at setup

Local parser/RPC/failed-receipt tests and workflow lint are setup checks, **not** Linux build/runtime evidence. The current workstation has no Docker/WSL Linux runtime; the first real tag run must still demonstrate both platform builds and the 2.17 container gate. Do not describe CI as passed before that run. Public repository creation and a clean `main` push are independently verifiable and should produce no workflow run. Independent review of this CI increment was requested with a cwd-readable source packet but timed out after 240 seconds; no independent approval is asserted.
