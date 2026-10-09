# Release readiness

Status checked October 8, 2026, for desktop 0.3.1 and the extension 1.8.1
integration. The source is public under MIT. Release packages are built by the
[release workflow](../.github/workflows/release.yml); the gates below separate
source publication from binary distribution.

## Source and build provenance

The viewer source pin is `d503473a7dd6a3ed3d77aad1b506b45379d1da2a` on the
extension repository's public `desktop-v1.8.1-port` branch. On October 8, a
fresh clone of the public extension repository synced all ten viewer/native
files at that pin for `aarch64-macos`, `x86_64-linux-gnu` and `x86_64-windows`,
and each set verified against its manifest. The `aarch64-macos` set is
byte-identical to the committed `viewer-dist/`. The sync copies the generated
artifacts committed at the pin; an earlier rebuild at that revision reproduced
the shipped viewer outputs' hashes (see the
[notice inventory notes](../third-party/README.md)).

The app's committed viewer targets Apple Silicon macOS. Other platforms must
sync native resources from that same upstream commit before building. The
manifest verifies copied bytes; it does not establish that the host's bundled
runtime matches another target.

A fresh local checkout passed the npm checks and produced an optimized Apple
Silicon macOS app from its checked-in viewer. The default linker signature did
not seal the bundle's resources, so the README includes the explicit ad-hoc
signing step needed for local bundle verification. This does not validate a
downloaded package or close the macOS interaction gates.

## Publication checklist

| Gate | Current state |
| --- | --- |
| README and contributor build instructions | Present in this revision |
| Project license | MIT |
| Publicly retrievable viewer source pin | Public; fresh-clone sync verified for three targets as above |
| Security policy | [SECURITY.md](../SECURITY.md), private vulnerability reporting |
| Continuous integration | Apple Silicon macOS: manifest verification, script tests, shell unit tests, clippy. No Linux or Windows lane |
| Navigation pin and CSP `base-uri`/`form-action`/`frame-ancestors` | Live-verified in an Apple Silicon macOS QA build against a pre-change control build. Linux and Windows runtime behaviour unverified |
| Release pipeline | Builds macOS, Linux and Windows packages on their own OS from the viewer pin, with no cache, and drafts a release for a `v*` tag; a prerelease version drafts a prerelease. Each asset gets SHA256SUMS and a build-provenance attestation. Publishing is manual |
| Third-party notices | Bundled inside every package; the release also attaches them with the MPL Cargo sources, which are checksum-verified against Cargo.lock |
| AppImage distribution | Not distributed: its extra bundled Linux system libraries have no notice/source inventory. Linux ships as `.deb` |
| Linux glibc floor | The native engine needs glibc 2.38 and the app built on Ubuntu 24.04 needs 2.39; the `.deb` declares `libc6 (>= 2.39)` and the workflow fails if any packaged binary needs more |
| Final macOS installed-package checks | Open cases and older tested source are recorded in [macOS QA](macos-release-qa.md); rerun against the final candidate |
| Linux/Windows installed-package checks | Passed for the packages and environments in [Linux/Windows QA](linux-windows-release-qa.md), including real shutdown/restart. Those packages predate the navigation pin and CSP change; rerun the affected checks on new packages |
| Other Linux desktops, Wayland and physical keyboards | Unverified; limit platform claims to observed coverage |
| Windows distribution | Unsigned. SignPath Foundation signing requires a prior public release, so the first release ships unsigned, then apply. Signing will cover the app and installer, not the upstream `tjs.exe`. Smart App Control blocks the unsigned installer; whether it blocks `tjs.exe` under a signed app (the app would fall back to WASM) is untested. SmartScreen on a clean machine unverified |
| macOS distribution | The app has an ad-hoc signature with the hardened runtime, built by the workflow; the DMG is unsigned. No Developer ID signing or notarization, by choice. Gatekeeper's Open Anyway flow on a downloaded package unverified |

The source MIT license does not replace third-party licenses. The
[notice inventory](../third-party/inventory.json) records identities, source
URLs and notice hashes. It includes build and platform-specific dependencies
as well as linked code. Codicons font assets are CC BY 4.0; their supporting
code is MIT. Recheck the inventory when dependencies or packaging change.

## Releasing

1. Bump the version in `package.json`, `src-tauri/Cargo.toml` and
   `src-tauri/tauri.conf.json`; `scripts/release/version.mjs` refuses drift.
2. Merge the bump through a reviewed pull request.
3. A maintainer pushes the `v<version>` tag on that commit. The workflow builds,
   verifies and attaches every asset to a draft release.
4. Run the candidate checks below on the drafted packages, then publish the
   draft.

## Candidate checks

Before publishing a binary release, retain the app revision, viewer source pin,
native target and package SHA256 values alongside results from the exact
candidate packages. Verify the contributor build commands from a fresh
checkout. Test the package obtained through the intended download path, with
normal OS trust protections enabled. Keep missing checks visible rather than
treating a successful local install as equivalent evidence.

Changing bundled code, native resources or signing invalidates the corresponding
package hashes. Rebuild and repeat the affected installed-package checks before
reusing the earlier results as release evidence.
