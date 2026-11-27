# Code signing policy

Every release package is built by the [release workflow](../.github/workflows/release.yml)
on GitHub-hosted runners from a tagged commit of this repository, the viewer
included: each runner builds it from `viewer/` in that commit. The native
database engine (`tjs`, built by the
[zknpr/txiki.js](https://github.com/zknpr/txiki.js) fork's own workflow) and
the query-plan library are prebuilt binaries under `viewer/natives/`, pinned
by SHA-256. Releases are drafted automatically and published by a maintainer.

## Current signing status

| Package | Signature |
| --- | --- |
| macOS `.dmg` | The disk image is unsigned. The app inside has an ad-hoc signature with the hardened runtime. Neither is signed with an Apple Developer ID, and nothing is notarized. |
| Windows installer | Unsigned. Signing through the SignPath Foundation is planned. |
| Linux `.deb` | Unsigned, as is usual for packages installed directly rather than from an apt repository. |
| In-app updates | Signed with the project's update key (minisign, through Tauri's signer). The private key is kept offline by the maintainer, who signs each release's three update packages before publishing it (`scripts/release/sign-update.mjs`); the app installs an update only when its signature verifies against the public key the app carries, for the announced version. |

Unsigned and ad-hoc packages are still verifiable. Each release lists
`SHA256SUMS`, and every asset carries a GitHub build-provenance attestation that
ties it to the workflow run and commit that produced it:

```sh
shasum -a 256 --check --ignore-missing SHA256SUMS   # macOS
sha256sum --check --ignore-missing SHA256SUMS       # Linux
gh attestation verify <downloaded file> --repo zknpr/SQLite-Explorer-App
```

On Windows, use the PowerShell `Get-FileHash` command from the release notes.

### Windows: what signing will and will not cover

Once signing is approved, the application executable and the installer will be
signed. The bundled native database engine (`tjs.exe`, built by the
[zknpr/txiki.js](https://github.com/zknpr/txiki.js) fork's workflow) stays
unsigned inside the signed installer, as the SignPath Foundation's terms allow
for upstream binaries. The query-plan library (`query-plan.dll`) is built
from this repository's source, but outside the release workflow, so it is not
signed either; whether SignPath accepts it as it is, or the workflow must build
it, is still open.

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
it. It has no telemetry or crash reporting. It checks for updates only when the
user chooses Check for Updates…, or, if the user agreed when the first launch
asked, when the app starts and a day has passed since the last check. A check
requests the release manifest from github.com and, when there is a newer
version, downloads its package (several megabytes) from this project's releases
there before asking to install it; the app downloads from nowhere else. GitHub
receives the request, with the user's IP address and the updater's name and
version, under [GitHub's privacy statement](https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement);
nothing about the user's files or settings is sent. The bundled
components (the viewer, the sql.js WASM engine and the txiki.js native engine)
make no network connections in this application. One exception is outside the
app itself: on a Windows system without the Microsoft Edge WebView2 Runtime,
the installer downloads that runtime from Microsoft. Windows 11 includes it.
