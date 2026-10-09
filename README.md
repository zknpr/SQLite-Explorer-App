# SQLite Explorer

A desktop application for browsing and editing SQLite databases on macOS,
Linux and Windows. It shares its viewer with the
[SQLite Explorer VS Code extension](https://github.com/zknpr/SQLite-Explorer)
and runs in a Tauri desktop shell.

The current desktop version is **0.3.1**, integrating the extension's **1.8.1**
release and desktop-specific fixes. Packages for macOS, Linux and Windows are
attached to each [release](https://github.com/zknpr/SQLite-Explorer-App/releases);
see [Install](#install). See [release readiness](docs/release-readiness.md) for
the remaining distribution gates.

## Working with databases

- Browse tables and views, filter and sort rows, and inspect text and BLOB cells.
- Edit data with Undo/Redo and explicit Save.
- Run SQL in the existing SQL console, bind parameters and inspect query plans.
- Import CSV/JSON data and export tables, databases or cell contents.
- Open multiple databases in tabs and use native file dialogs and menus.

Changes remain pending until Save. Opening the same file in multiple windows of
one app process is refused. Separate app processes are not covered by that
ownership guard. A replaced file or stale in-memory snapshot can cause Save to
refuse; retain pending work with a separate export before reloading.

## Platform status

| Platform tested | Package | Coverage |
| --- | --- | --- |
| macOS, Apple Silicon | `.app` | Native/WASM workflows; remaining OS checks are recorded in [macOS QA](docs/macos-release-qa.md) |
| Ubuntu 24.04, x86-64, Xfce/X11 | Debian package | Installed-app checks, shutdown/restart |
| Windows 11, x86-64 | NSIS installer | Installed-app checks, shutdown/restart and post-boot saves |

See [Linux and Windows QA](docs/linux-windows-release-qa.md) for tested package
hashes and limits. Other Linux desktops and Wayland remain unverified. Linux
session-end cancellation requires a working inherited XSMP session connection.
Forced termination or power loss cannot preserve unsaved edits.

## Install

Download the package for your system from the
[releases page](https://github.com/zknpr/SQLite-Explorer-App/releases). The
packages are not signed with a publisher identity yet; see the
[code signing policy](docs/code-signing-policy.md). Verify a download before
installing it:

Download `SHA256SUMS` next to the package and check it with the tool your
system has:

```sh
shasum -a 256 --check --ignore-missing SHA256SUMS   # macOS
sha256sum --check --ignore-missing SHA256SUMS       # Linux
```

On Windows, the release notes give a PowerShell `Get-FileHash` command that
prints `True` for a matching installer. With the GitHub CLI on any platform,
`gh attestation verify <downloaded file> --repo zknpr/SQLite-Explorer-App`
confirms the file was built by this repository's release workflow.

**macOS (Apple Silicon).** Open the `.dmg` and drag SQLite Explorer to
Applications. The disk image is unsigned; the app inside has an ad-hoc
signature and is not notarized, so macOS
blocks the first launch. Open **System Settings → Privacy & Security** and
choose **Open Anyway** for SQLite Explorer. To uninstall, move the app to the
Trash; settings live in `~/Library/Application Support/xyz.zknpr.sqlite-explorer`.

**Windows (x86-64).** Run the `-setup.exe` installer. It is unsigned, so
SmartScreen shows "Windows protected your PC"; choose **More info → Run
anyway**. If **Smart App Control** is on, Windows blocks unsigned programs and
offers no override, so the installer cannot run there. To uninstall, use
**Settings → Apps → Installed apps → SQLite Explorer → Uninstall**.

**Linux (x86-64, Debian/Ubuntu).** The package needs glibc 2.39 or newer
(Ubuntu 24.04+, Debian 13+):

```sh
sudo apt install ./SQLite-Explorer-<version>-linux-amd64.deb
```

To uninstall, run `sudo apt remove sq-lite-explorer` (the package name Tauri
derives from the product name). AppImage packages are not
provided.

## Build from a checkout

Install Node.js 24 or newer, Rust and the
[Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/).
Linux also needs the libSM and libICE development packages, named `libsm-dev`
and `libice-dev` on Ubuntu.

```sh
npm ci
node scripts/sync-viewer.mjs --verify
```

`viewer-dist/manifest.json` identifies the viewer source commit, native target
and file hashes. The committed native binaries target **Apple Silicon macOS**.
On that target, the checked-in viewer is enough to build the shell. For any
other target, first sync from a checkout containing the exact source commit:

```sh
git clone --branch desktop-v1.8.1-port https://github.com/zknpr/SQLite-Explorer ../SQLite-Explorer
node scripts/sync-viewer.mjs --source ../SQLite-Explorer --ref d503473a7dd6a3ed3d77aad1b506b45379d1da2a
node scripts/sync-viewer.mjs --verify
```

The pin is on the extension repository's `desktop-v1.8.1-port` branch.
Substituting the extension's `v1.8.1` tag omits the desktop fixes validated here.

Build on the destination OS and CPU:

```sh
npm test
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
```

Create the platform's packages:

```sh
npm run tauri build
```

Packages appear under `src-tauri/target/release/bundle/`: `.app` and DMG on
macOS, Debian on Linux and NSIS on Windows. `src-tauri/tauri.macos.conf.json`
signs the macOS app ad-hoc with the hardened runtime, which seals its resources
so `codesign --verify --deep --strict` passes; it is not Developer ID signing or
notarization. Selecting another native target in the sync script stages its
resources; it does not cross-compile the app.

Release packages are built by the [release workflow](.github/workflows/release.yml),
which runs these steps on each OS from the pinned viewer source and drafts a
release for a `v*` tag.

For development, run `npm run tauri dev`. Packaged-app checks are still required
for native dialogs, OS integration and the custom asset protocol.

## Contributing and license

[CONTRIBUTING.md](CONTRIBUTING.md) explains the two-repository source layout,
artifact regeneration and validation. Report reproducible app bugs through
[GitHub issues](https://github.com/zknpr/SQLite-Explorer-App/issues), including the
OS, app version, selected database engine and a small synthetic database when
possible. Avoid attaching private databases. Report security vulnerabilities
privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

The project is licensed under [MIT](LICENSE.md). Bundled dependencies retain
their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.txt) and the
[inventory](third-party/inventory.json). A binary distribution must include
these notices and supply the covered MPL dependency sources.
