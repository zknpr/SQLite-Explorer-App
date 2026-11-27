# QA records

What was checked on installed packages, release by release. The dated reports
describe the runs they record; the app has changed since, so read them for what
was checked then, not as the current state. The [smoke checklist](../../scripts/qa/smoke-checklist.md)
is the macOS pass to repeat for each release.

| Release | Where | What ran | Record |
| --- | --- | --- | --- |
| 0.2.0 (not published) | macOS (local build); Ubuntu 24.04, Xfce/X11 (`.deb`); Windows 11 (NSIS) | Six installed-app smoke groups; native dialogs, file associations, same-file ownership; logout, shutdown and restart with pending edits | [macOS](2026-09-macos.md), [Linux and Windows](2026-09-linux-windows.md), September 21–22, 2026 |
| 0.3.0, 0.3.1 | macOS QA build; Linux 0.3.0 `.deb`; Windows 0.3.1 NSIS | Navigation and request pins, counted on a foreign listener; the six smoke checks on packages upgraded in place | [Release readiness](../release-readiness.md), October 8–9, 2026 |
| 0.3.2 | — | No installed-package record in this repository | — |
| 0.4.0 | macOS (hidden QA bundle, release `.app`); Windows 11 and Ubuntu 24.04 VMs | macOS: native, WASM, console, multi-window and reload sessions, the headless browser suite, the release bundle's signature and embedded files. Windows and Linux: built from a checkout as the release workflow does (viewer rebuild check, tests, clippy, notices, packages), installed over the previous version, the six smoke checks and a short real-input regression | This page, November 26–27, 2026 |

## 0.4.0

- **Build from a checkout.** `build-viewer --check --target aarch64-macos`
  reproduced the committed `viewer-dist/` byte for byte from a Windows and a
  Linux checkout, after a fix: the Windows build had bundled the extension's VS
  Code backend (paths with backslashes defeated the build's swap), and its
  package could not open a database. `build-viewer` now refuses such a page on
  every platform.
- **Tests.** npm test (script and viewer tests), cargo test and clippy passed on
  both. A cargo test that raced on Windows (7 of 40 full runs) was fixed in the
  test and passed 40 of 40.
- **Installed packages.** The NSIS installer (upgraded in place, one Apps entry)
  and the `.deb` reported 0.4.0 and passed the six smoke checks. Windows:
  Refresh asks before discarding edits and Cancel keeps them; Save writes the
  value (checked with sqlite3); F5 with an unsaved edit does nothing; the Open,
  Import and Export dialogs are owned by the window; the unsaved-changes quit
  prompt is owned by it; a clean quit leaves no engine process. Linux: the
  Open, Import and Export file choosers are transient for and modal to the
  window, filter by extension, cancel on Escape, open a typed path, and ask
  before replacing a file.
- **Debian rename.** `apt install` of the release-built `sqlite-explorer`
  package removed an installed `sq-lite-explorer` 0.4.0 build and kept the
  user's settings.
- **Not run:** shutdown and restart, Save As of a new database on Linux, other
  Linux desktops and Wayland, a clean machine's SmartScreen and Gatekeeper
  behaviour on downloaded packages.
