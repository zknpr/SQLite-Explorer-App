# Release readiness

Status on November 26, 2026, for desktop 0.4.0, before its release. The source
is public under MIT. Release packages are built by the
[release workflow](../.github/workflows/release.yml); the gates below separate
source publication from binary distribution.

## Source and build provenance

Everything a package is built from is in this repository, the prebuilt engine
binaries included. The viewer's sources
are in `viewer/`, imported from the SQLite Explorer extension's desktop port of
its v1.9.0. `npm run build:viewer` builds them into `viewer-dist/`, which is
committed as built for Apple Silicon macOS; CI and the release workflow rebuild
it on every runner and fail unless the bytes match. The native binaries are
pinned by SHA-256: `tjs` to a build of the
[zknpr/txiki.js](https://github.com/zknpr/txiki.js) fork
(`viewer/scripts/refresh-natives.mjs`), and the query-plan library and sql.js
in `viewer/vendor/query-plan-manifest.json`.

When the viewer moved into this repository, a build on macOS reproduced, byte
for byte, the files the extension's desktop port had produced for
`aarch64-macos`, `x86_64-linux-gnu` and `x86_64-windows`. From a Windows checkout
the check first failed: the build matched the page's backend swap against
forward-slash paths, so a Windows build bundled the wrong one. With that fixed,
the check passed from a Windows and a Linux checkout on November 26. CI runs it on every OS.

Other platforms build their own viewer and engine (`npm run build:viewer` on
that OS); `viewer-dist/manifest.json` records the target and every file's hash.
It verifies those bytes; it does not establish that the bundled runtime matches
another target.

`npm run tauri build` signs the macOS app ad-hoc with the hardened runtime
(`src-tauri/tauri.macos.conf.json`), which seals its resources so
`codesign --verify --deep --strict` passes. That does not validate a
downloaded package or close the macOS interaction gates.

## Publication checklist

| Gate | Current state |
| --- | --- |
| README and contributor build instructions | Present in this revision |
| Project license | MIT |
| Viewer source | In this repository (`viewer/`); CI checks that it builds the committed `viewer-dist/` |
| Security policy | [SECURITY.md](../SECURITY.md), private vulnerability reporting |
| Continuous integration | Apple Silicon macOS: `viewer-dist/` manifest and rebuild checks, viewer type check, script and viewer tests, native lane, notices check, shell unit tests, clippy. Linux and Windows: rebuild check, script and viewer tests, shell unit tests, clippy. Not in CI: the `--ignored` live-sidecar tests and installed-app checks. The 0.4.0 workflows have not run yet |
| Navigation pin and CSP `base-uri`/`form-action`/`frame-ancestors` | Verified against a foreign listener on installed packages. macOS: QA build against a pre-change control. Linux 0.3.0 `.deb`: no request left. Windows 0.3.0: the page stayed, but WebView2 still sent every refused navigation's request, so 0.3.0 was never published. Windows 0.3.1 adds the request pin: zero foreign requests for `location.href`/`assign`, link click and meta refresh, and `window.open` sends nothing |
| Release pipeline | Builds macOS, Linux and Windows packages on their own OS, viewer included, with no cache, and drafts a release for a `v*` tag; a prerelease version drafts a prerelease. Each asset gets SHA256SUMS and a build-provenance attestation. Publishing is manual |
| Third-party notices | Bundled inside every package; the release also attaches them with the MPL Cargo sources, which are checksum-verified against Cargo.lock |
| AppImage distribution | Not distributed: its extra bundled Linux system libraries have no notice/source inventory. Linux ships as `.deb` |
| Linux glibc floor | The native engine needs glibc 2.38 and the app built on Ubuntu 24.04 needs 2.39; the `.deb` declares `libc6 (>= 2.39)` and the workflow fails if any packaged binary needs more |
| Final macOS installed-package checks | Open cases and older tested source are recorded in the [September macOS QA](qa/2026-09-macos.md); rerun against the final candidate |
| Linux/Windows installed-package checks | The 0.2.0 packages passed the checks in the [September Linux/Windows QA](qa/2026-09-linux-windows.md), including real shutdown/restart. Candidates: Linux 0.3.0 `.deb` (upgraded in place from 0.2.0) passed the 6 installed-app smoke checks; Windows 0.3.1 NSIS (upgraded from 0.3.0) passed them with the request pin active. Shutdown/restart was not rerun on these candidates. 0.4.0, built on Windows and Linux test machines from the release branch rather than by the workflow ([QA records](qa/README.md)): the Windows NSIS installer and the Linux `.deb` (upgraded in place from 0.3.2) passed the 6 smoke checks and a short real-input regression (Refresh asks, Save, F5 refused, Open, the quit prompt). Shutdown/restart was not rerun. Linux file dialogs are not transient for the window, as before |
| Other Linux desktops, Wayland and physical keyboards | Unverified; limit platform claims to observed coverage |
| Windows distribution | Unsigned. Signing through the SignPath Foundation is planned; its terms require a project already released in the form to be signed, which the published 0.3.1 and 0.3.2 installers meet. Signing will cover the app and installer, not the `tjs.exe` engine or the query-plan library (see the [code signing policy](code-signing-policy.md)). Smart App Control blocks the unsigned installer; whether it blocks `tjs.exe` under a signed app (the app would fall back to WASM) is untested. SmartScreen on a clean machine unverified |
| macOS distribution | The app has an ad-hoc signature with the hardened runtime, built by the workflow; the DMG is unsigned. No Developer ID signing or notarization, by choice. Gatekeeper's Open Anyway flow on a downloaded package unverified |

The source MIT license does not replace third-party licenses. The
[notice inventory](../third-party/inventory.json) records identities, source
URLs and notice hashes. It includes build and platform-specific dependencies
as well as linked code. Codicons font assets are CC BY 4.0; their supporting
code is MIT. Recheck the inventory when dependencies or packaging change.

## Releasing

1. Bump the version in `package.json`, `src-tauri/Cargo.toml` and
   `src-tauri/tauri.conf.json` (`scripts/release/version.mjs` refuses drift),
   then refresh both lockfiles: `npm install --package-lock-only` and
   `cargo update --workspace --manifest-path src-tauri/Cargo.toml`.
2. Merge the bump through a reviewed pull request.
3. A maintainer pushes the `v<version>` tag on that commit. The workflow builds,
   verifies and attaches every asset to a draft release.
4. Run the candidate checks below on the drafted packages, then publish the
   draft.

## Candidate checks

Before publishing a binary release, retain the app revision, native target and
package SHA256 values alongside results from the exact
candidate packages. Verify the contributor build commands from a fresh
checkout. Test the package obtained through the intended download path, with
normal OS trust protections enabled. Keep missing checks visible rather than
treating a successful local install as equivalent evidence.

Changing bundled code, native resources or signing invalidates the corresponding
package hashes. Rebuild and repeat the affected installed-package checks before
reusing the earlier results as release evidence.
