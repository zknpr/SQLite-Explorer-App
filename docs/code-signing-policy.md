# Code signing policy

Every release package is built by the [release workflow](../.github/workflows/release.yml)
on GitHub-hosted runners from a tagged commit of this repository. The viewer and
native runtime come from the exact
[SQLite Explorer extension](https://github.com/zknpr/SQLite-Explorer) commit
recorded in `viewer-dist/manifest.json`. Releases are drafted automatically and
published by a maintainer.

## Current signing status

| Package | Signature |
| --- | --- |
| macOS `.dmg` | Ad-hoc signature with the hardened runtime. Not signed with an Apple Developer ID and not notarized. |
| Windows installer | Unsigned. Signing through the SignPath Foundation is planned. |
| Linux `.deb` | Unsigned, as is usual for packages installed directly rather than from an apt repository. |

Unsigned and ad-hoc packages are still verifiable. Each release lists
`SHA256SUMS`, and every asset carries a GitHub build-provenance attestation that
ties it to the workflow run and commit that produced it:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify <downloaded file> --repo zknpr/SQLite-Explorer-App
```

### Windows: what signing will and will not cover

Once signing is approved, the application executable and the installer will be
signed. The bundled native database engine (`tjs.exe`, from the
[txiki.js](https://github.com/zknpr/txiki.js) runtime) and its query-plan
library are built by another project and stay unsigned inside the signed
installer, as the SignPath Foundation's terms allow for upstream binaries.

Windows **Smart App Control** blocks unsigned programs and offers no per-app
override. While it is on, the current unsigned installer cannot run. After
signing, the app and installer may run, but Smart App Control may still block
the unsigned native engine. The app then opens databases with its built-in WASM
engine. That engine holds the whole database in memory, so very large databases
may not open.

## Team and roles

| Role | Members |
| --- | --- |
| Authors (commit without further review) | [@zknpr](https://github.com/zknpr) |
| Reviewers (review changes from anyone else) | [@zknpr](https://github.com/zknpr) |
| Approvers (approve each signing request) | [@zknpr](https://github.com/zknpr) |

Changes from contributors outside this list are merged only after review.
Build scripts and workflow files count as source and get the same review.

## Privacy

This program will not transfer any information to other networked systems
unless specifically requested by the user or the person installing or operating
it. It has no telemetry, update checks or crash reporting. The bundled
components (the viewer, the sql.js WASM engine and the txiki.js native engine)
make no network connections in this application. One exception is outside the
app itself: on a Windows system without the Microsoft Edge WebView2 Runtime,
the installer downloads that runtime from Microsoft. Windows 11 includes it.
