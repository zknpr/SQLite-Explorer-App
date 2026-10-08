# SQLite Explorer

A desktop application for browsing and editing SQLite databases on macOS,
Linux and Windows. It shares its viewer with the
[SQLite Explorer VS Code extension](https://github.com/zknpr/SQLite-Explorer)
and runs in a Tauri desktop shell.

The current desktop version is **0.2.0**, integrating the extension's **1.8.1**
release and desktop-specific fixes. This repository does not publish binary
releases yet; build from a checkout as described below. See
[release readiness](docs/release-readiness.md) for the remaining distribution
gates.

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
| Ubuntu 24.04, x86-64, Xfce/X11 | Debian, AppImage | Installed-app checks; shutdown/restart checks used the Debian package |
| Windows 11, x86-64 | NSIS installer | Installed-app checks, shutdown/restart and post-boot saves |

See [Linux and Windows QA](docs/linux-windows-release-qa.md) for tested package
hashes and limits. Other Linux desktops and Wayland remain unverified. Linux
session-end cancellation requires a working inherited XSMP session connection.
Forced termination or power loss cannot preserve unsaved edits.

The Windows build is unsigned. The local macOS build has an ad-hoc signature,
without Developer ID signing or notarization. Downloaded-package trust prompts
have not been signed off.

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

On Linux and Windows, create the platform's packages:

```sh
npm run tauri build
```

On macOS without a configured signing identity, build and seal a local `.app`:

```sh
npm run tauri build -- --bundles app
codesign --force --sign - 'src-tauri/target/release/bundle/macos/SQLite Explorer.app'
codesign --verify --deep --strict 'src-tauri/target/release/bundle/macos/SQLite Explorer.app'
```

The explicit ad-hoc signing step seals the app's resources. The linker's default
signature alone fails strict bundle verification. This local signature does not
provide Developer ID signing or notarization. Distribution packages need their
own [signing and packaging setup](https://v2.tauri.app/distribute/).

Packages appear under `src-tauri/target/release/bundle/`: `.app` for the local
macOS command above, Debian/AppImage on Linux and NSIS on Windows. A configured
macOS distribution build can also produce a DMG. Selecting another native target
in the sync script stages its resources; it does not cross-compile the app.

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
