# ferroc icon assets

Bright iron-orange **F** (Ferrum / forged tool) with a turquoise command chevron (Commander), on a pale ivory tile with transparent exterior. Generated using Agnes; raster artwork, **not** an editable vector.

## Canonical files

- `ferroc.png`: transparent 1024×1024 master, derived from the original generated image.
- `ferroc.ico`: 32-bit PNG-backed Windows ICO, sizes 16/24/32/48/64/128/256. `build.rs` already embeds it as the executable product icon.
- `icons/{16,20,24,32,40,48,64,128,256,512}.png`: shared transparent PNGs, including intermediate Windows DPI sizes.
- `branding/ferroc-agnes-original.png`: unmodified 1024×1024 provider output. Its SHA-256 is `34640d50d729f38bb53c9911709ee603cfc96993f7898136c13ed29877d43ac2`.
- `branding/ferroc-agnes-prompt.txt`, `agnes-provenance.json`: English generation prompt, task ID, source URL without query, and requested model. The provider did not report a model field; do not treat the requested model as an independently reported field.
- `branding/icon-manifest.json`: conversion parameters and SHA-256 for all twelve derived files. No API key is stored.
- `branding/legacy-dark/`: historical hand-drawn orange-on-dark assets and original generator. These are NOT the current product artwork.

## Reproduce without API access

From the repository root, on Windows PowerShell 7 with System.Drawing:

```powershell
./assets/generate-icons.ps1
cargo test --locked --test icon_assets
cargo build --locked --release
./scripts/verify-windows-resources.ps1 -Exe ./target/release/ferroc.exe
```

The converter clears only **edge-connected** near-white pixels (all RGB channels ≥245), preserves the ivory interior, then uses high-quality bicubic resizing. It rejects unexpected source dimensions, an implausible visible silhouette or opaque corners. The source corner actually measured RGB(247,247,251), so a pure-white/250 threshold was rejected rather than silently leaving an opaque matte. Output bytes reproduced exactly in two consecutive local conversions; PNG encoding identity on different GDI+ versions is not asserted.

## Existing and future surfaces

- Windows executable/file icon: canonical ICO, embedded via `build.rs`; inspect the built PE resources, not merely the source file.
- Browser login/admin/pairing pages: `/favicon.ico` and `/icon.png` are served by the existing Rust relay. Both come from these same assets; no separate asset server.
- Future native GUI: `ferroc::icons::{ICO, PNG, PNG_32}` exposes the same artwork bytes. Use ICO for native window/taskbar identity and PNG variants as needed for tray/menu sizes. GUI frameworks may require explicit icon/window/taskbar/tray configuration.
- **No native GUI window, taskbar window identity, or tray menu currently exists. Their runtime behavior is not implemented or verified by this asset increment.** Do not present file-icon verification or a browser favicon as a native tray/taskbar test.

The source URL may expire; the downloaded original and its hash are the reproducible source. Provider timestamps are recorded verbatim, not trusted as the local clock. Old binary receipts remain historical; new executable hashes must be verified separately.
