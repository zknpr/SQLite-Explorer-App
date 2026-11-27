# SQLite Explorer

A desktop application for browsing and editing SQLite databases on macOS,
Linux and Windows: a Tauri shell around a web viewer. The viewer began as the
one in the [SQLite Explorer VS Code extension](https://github.com/zknpr/SQLite-Explorer)
(its v1.9.0) and is developed here, in `viewer/`; this repository builds the
whole app.

The current desktop version is **0.4.0**. Packages for macOS, Linux and Windows
are attached to each [release](https://github.com/zknpr/SQLite-Explorer-App/releases);
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

| Platform tested | Package | Last checked | Coverage |
| --- | --- | --- | --- |
| macOS, Apple Silicon | `.app` | 0.4.0 | Native and WASM engines, SQL console, multiple windows and reload refusal in a QA build; the release bundle's signature |
| Ubuntu 24.04, x86-64, Xfce/X11 | Debian package | 0.4.0 | Installed-app smoke checks and a real-input regression; shutdown/restart last on 0.2.0 |
| Windows 11, x86-64 | NSIS installer | 0.4.0 | Installed-app smoke checks and a real-input regression; shutdown/restart and post-boot saves last on 0.2.0 |

The [QA records](docs/qa/README.md) list what each release was checked for.
Other Linux desktops and Wayland remain unverified. Linux
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

To uninstall, run `sudo apt remove sqlite-explorer`. Releases before 0.4.0
were packaged as `sq-lite-explorer`; installing 0.4.0 replaces that package.
AppImage packages are not provided.

### Updating

From 0.4.0, the app updates itself. At first launch it asks whether to check
for updates automatically: when it starts, if a day has passed since the last
check. **SQLite Explorer → Check for Updates Automatically** changes the answer,
and **Check for Updates…** checks at any time. It asks before installing an update, and asks again if any window has
unsaved changes. It installs only a package signed with the project's update
key, checked against the public key built into the app.

- **macOS:** it replaces the app, so keep it in Applications; a copy run from
  the disk image cannot update itself.
- **Windows:** it runs the new installer.
- **Linux:** it installs the new `.deb` through the system's administrator
  prompt. A copy installed another way, such as from the AUR, is told about the
  new version and updates through its package manager.

A check is one request to github.com, which GitHub answers from its download
server (release-assets.githubusercontent.com). When there is a newer version,
its package (several megabytes) is downloaded from this project's releases the
same way before the app asks to install it; the app requests packages from
nowhere else. GitHub sees your IP address. Nothing about your files or settings
is sent.

## Build from a checkout

Install Node.js 24 or newer, Rust and the
[Tauri platform prerequisites](https://v2.tauri.app/start/prerequisites/).
Linux also needs the libSM and libICE development packages, named `libsm-dev`
and `libice-dev` on Ubuntu.

```sh
npm ci
npm run build:viewer
```

`npm run build:viewer` builds the viewer from `viewer/` into `viewer-dist/`,
with the native engine for the machine it runs on, and checks it against the
shell. `viewer-dist/` is committed as built for **Apple Silicon macOS**, so on
that target the checkout is enough; `npm run check:viewer` confirms the
committed files are what `viewer/` builds. `viewer-dist/manifest.json`
records the native target and every file's hash.

Test on the destination OS and CPU:

```sh
npm test
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
```

Create the platform's packages:

```sh
npm run tauri build
```

Packages appear under `src-tauri/target/release/bundle/`: `.app` and DMG on
macOS, Debian on Linux and NSIS on Windows. A local Linux build keeps the Debian
package name Tauri derives, `sq-lite-explorer`; the release workflow renames it
`sqlite-explorer` (`scripts/release/deb-control.mjs`). `src-tauri/tauri.macos.conf.json`
signs the macOS app ad-hoc with the hardened runtime, which seals its resources
so `codesign --verify --deep --strict` passes; it is not Developer ID signing or
notarization. Building the viewer for another `--target` stages that target's
engine; it does not cross-compile the app.

Release packages are built by the [release workflow](.github/workflows/release.yml),
which runs these steps on each OS and drafts a release for a `v*` tag.

For development, run `npm run tauri dev`. Packaged-app checks are still required
for native dialogs, OS integration and the custom asset protocol.

## Contributing and license

[CONTRIBUTING.md](CONTRIBUTING.md) explains the source layout, how the viewer
is built and checked, and validation. Report reproducible app bugs through
[GitHub issues](https://github.com/zknpr/SQLite-Explorer-App/issues), including the
OS, app version, selected database engine and a small synthetic database when
possible. Avoid attaching private databases. Report security vulnerabilities
privately as described in [SECURITY.md](SECURITY.md), never in a public issue.

The project is licensed under [MIT](LICENSE.md). Bundled dependencies retain
their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.txt) and the
[inventory](third-party/inventory.json). A binary distribution must include
these notices and supply the covered MPL dependency sources.
