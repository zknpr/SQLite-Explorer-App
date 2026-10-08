# Release readiness

Status checked October 8, 2026, for desktop 0.2.0 and the extension 1.8.1
integration. The source is public under MIT. This repository does not publish
binary releases yet; the gates below separate source publication from binary
distribution.

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
| Third-party notices | Notices and inventory are in this repository; a binary release must ship them with the covered MPL Cargo sources |
| AppImage distribution | Withheld pending notice/source inventory for its additional bundled Linux system libraries |
| Final macOS installed-package checks | Open cases and older tested source are recorded in [macOS QA](macos-release-qa.md); rerun against the final candidate |
| Linux/Windows installed-package checks | Passed for the packages and environments in [Linux/Windows QA](linux-windows-release-qa.md), including real shutdown/restart. Those packages predate the navigation pin and CSP change; rerun the affected checks on new packages |
| Other Linux desktops, Wayland and physical keyboards | Unverified; limit platform claims to observed coverage |
| Windows distribution | Unsigned; no signing setup configured; clean-machine downloaded-package/SmartScreen check unverified |
| macOS distribution | Local ad-hoc signature only; Developer ID signing/notarization and downloaded-package checks unverified |

The source MIT license does not replace third-party licenses. The
[notice inventory](../third-party/inventory.json) records identities, source
URLs and notice hashes. It includes build and platform-specific dependencies
as well as linked code. Codicons font assets are CC BY 4.0; their supporting
code is MIT. Recheck the inventory when dependencies or packaging change.

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
