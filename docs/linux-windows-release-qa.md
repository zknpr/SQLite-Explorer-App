# Linux and Windows release QA

September 22, 2026. Tested in x86-64 Proxmox guests: Ubuntu 24.04.4 with
WebKitGTK 4.1, and Windows 11 Pro build 26200 with WebView2 153.0.4234.48.
These checks use the installed Tauri application, real IPC and bundled native
runtime. Node's SQLite independently reads the fixture files to verify saves.

Viewer source: `d503473a7dd6a3ed3d77aad1b506b45379d1da2a` on the extension's
`desktop-v1.8.1-port` branch. Generated viewer manifests record the source commit,
native target and SHA256 of each artifact.

## Installed release results

Both optimized 0.2.0 installers were installed and the final installed apps
passed all six smoke groups. The final Linux AppImage also passed all six groups
when launched directly. Screenshots were inspected after execution. Linux
packages, screenshots, fixture databases and logs are retained under the ignored
`artifacts/cross-platform-2026-09-22/session-gates/` directory. The subsequent
Windows teardown fix, rebuilt installer and its evidence are in `logoff-gates/`.
Actual shutdown/restart checks using those installed packages are in `power-gates/`.
The adjacent `release-gates/` directory retains the earlier dialog, association and ownership
checks; those features did not change in the session/keyboard fixes below.

| Check | Ubuntu Debian package | Windows NSIS package |
| --- | --- | --- |
| Native startup, spaces/Unicode in path, Unicode text and BLOB display | Passed | Passed |
| Exact signed 64-bit integer display | Passed | Passed |
| Filter and sort | Passed | Passed |
| Pending edit leaves disk unchanged; Undo/Redo and Save write expected values | Passed | Passed |
| Existing SQL console, parameters, Explain and draft retention | Passed | Passed |
| WITHOUT ROWID and FTS5 shadow tables | Passed | Passed |
| Native Open, Save As and export dialogs, including cancellation | Passed | Passed |
| File-manager double-click and drag-and-drop | Passed | Passed |
| New window and same-file ownership refusal within one app process | Passed | Passed |
| Unsaved window close and Quit cancellation preserve pending changes | Passed | Passed |
| Clean Quit closes the app and its sidecars | Passed | Passed |
| Normal OS logout with pending edits; Cancel retains changes; subsequent Save verified on disk | Passed (Xfce/X11) | Passed (ExitWindowsEx) |
| Actual OS shutdown and restart: pending-edit cancellation, Save, completed power action and post-boot edit/save | Passed (Xfce/X11) | Passed (Windows desktop power menu) |
| Cancelled and committed shutdown/logoff/Restart Manager messages, visible and hidden event windows | N/A | Passed, 6 cases |
| Command-line logoff closes sidecars without a Rust teardown panic | N/A | Passed; Windows overrides the veto |
| US and Italian zoom in/out/reset with SQL editor focus | Passed (XTest keycodes) | Passed (QEMU keyboard) |
| Rust unit tests | 131 passed | 115 passed |
| Live sidecar/export checks and runtime scheduling measurement | 4 passed | 4 passed |
| Bridge and sync script tests | 14 passed | 14 passed |
| Rust Clippy, warnings denied | Passed | Passed |

The live export checks independently validated database integrity and 10,000
rows in exports larger than the 16 MiB RPC limit. The Windows file-replacement
tests cover native identity and WASM snapshots with unchanged size and mtime.
The normal native transaction probe logs a handled nested-BEGIN refusal; this
is expected and the pending/save assertions still pass.

The native dialog checks independently reopened exported and newly saved Unicode
paths with SQLite and verified integrity and expected data/schema. Cold file-manager
double-click opened the selected database. Opening a different associated file
while the app was running opened another process/window on both guests. The
ownership refusal check covers windows within the same process; it does not
establish ownership exclusion between independent processes.

On Windows, reopening the startup file through the native Open dialog preserved
one native tab and its pending edit; the on-disk value remained unchanged. On the
1280×800 Windows desktop, both the startup window and a new window maximized to
the available work area, keeping the status bar above the taskbar.

The installed Linux executable matches the executable extracted from its Debian
package. Byte comparison of the final installed Windows executable identified
only Tauri's three-byte bundle-type marker (`UNK` to `NSS`) as the difference
from the unbundled build.
Final installed native resource hashes were verified against each platform's
generated manifest.

Actual shutdown and restart were exercised separately on each guest. With an
edit pending, Xfce cancelled the requested power action and displayed the app's
explanation; Windows displayed its blocking screen and offered Cancel. Returning
to the app retained the edit, and Save wrote the expected value, independently
verified with SQLite. Repeating the power action after Save succeeded. For each
shutdown, the hypervisor confirmed the guest was stopped before it was started
again. Boot timestamps on Windows and kernel boot IDs on Linux confirmed the
restart and subsequent boot. Saved values and SQLite integrity survived both
actions; fresh installed-app launches could edit and save again afterward.
The exit logs recorded clean sidecar shutdowns without a Rust panic. Installed
executable hashes remained unchanged. Temporary driver processes, tasks, SSH keys and the
Linux console test account/autologin override were removed afterward.

Final package SHA256 values:

```text
db925e47dffcd7ef17de29d67c3ad96dbe5e66960b137a362aaccf5b9afe8579  SQLite Explorer_0.2.0_amd64.deb
aeab124b0ff9dcbbe55c153aefe8e59308f553af454c1a499251fd34d31ec382  SQLite Explorer_0.2.0_amd64.AppImage
31ec1719d51452fa6e3b447b9ac44931070c70d6f413750bec7e08952e15cbac  SQLite Explorer_0.2.0_x64-setup.exe
```

The shared native lane passed 78 fixtures, 4 errno checks, 15 runtime checks,
20 transport checks, 108 sidecar checks and 122 method checks. The app's 11
browser regressions and macOS Rust checks (133 plus 4 opt-in checks) also passed.
The complete extension unit suite passed 3,215 tests at the final source commit,
including nine new path/ownership regressions. The final shell change passed
133 macOS Rust tests and Clippy with warnings denied. Guest unit/Clippy and all
three package smoke runs were repeated after the session and keyboard fixes.
The opt-in native export/runtime checks were established earlier; their native
runtime and RPC implementation are unchanged by this continuation.

## Fixes found during guest testing

- Native artifact sync now selects the guest OS and CPU. The original sync always
  copied a macOS ARM executable and dylib. Linux and Windows get their respective
  executable and query-plan library, with platform-specific bundle targets.
- Linux compilation no longer includes macOS-only `RunEvent::Opened`.
- Linux and Windows consume startup database paths before the viewer-ready latch.
  Linux file URLs and paths containing spaces and Unicode are supported.
- Windows pins native file identity using the volume and full 128-bit file ID.
  WASM snapshots include that identity and the descriptor's change time, so a
  replacement with the same size and modification time is still stale.
- Windows exports open their staging file with write access before flushing it.
- Windows native launches encode database paths in ASCII and decode UTF-8 in the
  sidecar. The runtime's ANSI argv previously changed non-ASCII names. The fixed
  script basename runs under the shell-selected resource directory, and the
  decoded database path must still match initialization exactly.
- Filtered native grids explicitly alias the synthetic rowid. Without this alias,
  an INTEGER PRIMARY KEY produced duplicate column names and filtering failed
  with a zero-column error. Global, column and zero-result filters are covered.
- The native sidecar uses Windows TEMP/TMP for temporary exports.
- Windows startup paths now display their filename in tabs, status messages and
  export suggestions. Literal backslashes in Unix filenames remain intact.
- Equivalent ordinary and extended Windows path spellings reuse one tab and one
  in-flight open. A native ownership refusal no longer falls back to a second
  editable WASM copy. Verbatim-only Windows names remain distinct.
- Linux desktop entries declare SQLite/GeoPackage MIME types and pass selected
  paths with `%F`. The installed entry passes `desktop-file-validate`, and MIME
  lookup selects SQLite Explorer. Both Debian and AppImage include the template.
- New windows whose outer dimensions exceed the monitor's work area maximize to
  fit it. This prevents the Windows taskbar from covering the status bar.
- Viewer readiness now waits for Tauri's asynchronous event subscriptions.
  A cold Windows launch had consumed its startup path before the listener existed,
  leaving an empty database. Delayed/rejected subscription tests cover the bridge,
  and subsequent installed-app cold launches opened the requested native database.
- Windows registers an unsaved-work shutdown reason on every app window and
  answers session queries from the shared unsaved state. Its shutdown priority
  puts the shell ahead of default-priority WebView/database children. Dirty
  shutdown/logoff queries return a veto; clean and critical queries allow exit.
- Committed Windows session end uses the same bounded cleanup as app exit.
  Tao 0.35.3's hidden event window previously marked its runner destroyed and
  continued dispatching, causing a panic. A direct notification to the visible
  app window did not exit at all. Both failures were reproduced before the fix;
  both now finish sidecar and Tauri cleanup and exit with code 0. This follows
  the lifecycle correction in [Tao's upstream fix](https://github.com/tauri-apps/tao/pull/1157)
  without changing the dependency tree. Cancelled notifications do not clean up
  or exit. The six installed-app message tests also verify no orphaned sidecars
  and unchanged fixture hashes.
- Linux registers an XSMP client on the inherited X11 session connection. Xfce
  4.18 ignores a negative D-Bus EndSessionResponse; the
  [XSMP interaction protocol](https://xorg.freedesktop.org/archive/X11R7.6/doc/libSM/SMlib.html)
  supplies the actual cancellation. A real console logout initially lost pending
  edits. The fixed app cancels logout and explains why; saving then permits a
  clean logout, with the saved value and SQLite integrity independently verified.
- Windows/Linux zoom follows the layout-resolved plus, minus and zero keys when
  native accelerators do not consume them. The bounded command acts only on its
  caller's window. Both guest layouts produced exactly 100%, 110%, 100%, 110%,
  100% through reset/in/out/in/reset, with the SQL editor focused. macOS retains
  its native shortcut handling.

AppImage desktop integration was also checked with fresh XDG config/data/cache
directories, a manually installed desktop entry and MIME association. Opening a
Unicode database through that association launched the AppImage's native engine.
This verifies manual integration, not an automatic desktop-integration installer.

## Repeating the checks

Install the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
and Node 24 or newer. Linux builds also need the libSM and libICE development
packages (`libsm-dev` and `libice-dev` on Ubuntu); the Debian package declares
the corresponding runtime dependencies. Build in each target OS; copying the committed macOS
`viewer-dist/native` files to another OS is insufficient.

```sh
npm ci
node scripts/sync-viewer.mjs --source ../SQLite-Explorer --ref d503473a7dd6a3ed3d77aad1b506b45379d1da2a
node scripts/sync-viewer.mjs --verify
npm test
cargo test --manifest-path src-tauri/Cargo.toml --lib
npm run tauri build
```

The sync defaults to the current OS and CPU. `--target x86_64-linux-gnu` or
`--target x86_64-windows` can stage the viewer for another machine; this does not
cross-compile the Rust application. The default bundles are Debian/AppImage on
Linux, NSIS on Windows, and app/DMG on macOS.

Install the resulting package, then start `tauri-driver` in the guest's logged-in
desktop session. Linux requires WebKitWebDriver; Windows requires the matching
EdgeDriver. See [Tauri's driver setup](https://v2.tauri.app/develop/tests/webdriver/manual-setup/).

```sh
node scripts/qa/native-app-smoke.mjs http://127.0.0.1:4444 /path/to/installed/app /path/to/new/evidence-directory
```

Use a new evidence directory for every run. On Windows the runner requires a
logged-in desktop and permission to create a temporary interactive scheduled
task. It starts the installed application with a loopback-only WebView2 debugging
port, then attaches EdgeDriver. This avoids EdgeDriver 153 rejecting positional
database paths as switches. The task and app process are removed after the run;
the test driver itself must be stopped separately. No test plugin is built into
the application. `SQLITE_QA_DEBUG_PORT` selects a different loopback port if
another test browser already occupies the default 9222.
The runner refuses an occupied port or an existing instance of the test app,
and normalizes Windows executable paths before matching the process for cleanup.
This prevents attachment to a leftover instance. Concurrent WebView2 instances
sharing user data must use matching environment options; changing only a QA
debugging port can make the second instance fail to create its WebView.
See [Microsoft's environment options contract](https://learn.microsoft.com/en-us/microsoft-edge/webview2/reference/win32/webview2-idl).
Two installed app instances with matching options opened separate native fixtures
successfully.

The harness records screenshots, session capabilities, individual checks, failure
diagnostics and the database fixture. It checks native startup, Unicode and BLOB
display, exact 64-bit integers, filtering/sorting, pending edits, Undo/Redo, Save,
SQL parameters and Explain, draft retention, WITHOUT ROWID and FTS5 shadow tables.

The Windows session-message regression runs in the logged-in desktop. It copies
a closed disposable database, starts one installed app, sends query/cancel/commit
messages only to that process, and checks its exit code, sidecars and file hash.
It does not log off the operating system. Use a new evidence directory each time:

```powershell
foreach ($kind in 'shutdown', 'logoff', 'restart-manager') {
    foreach ($target in 'visible', 'event-loop') {
        .\scripts\qa\windows-session-smoke.ps1 -Application $installedApp `
            -Database $closedFixture -Evidence ".\session-$kind-$target" `
            -Kind $kind -Target $target
    }
}
```

## Remaining release coverage

Normal OS logout, shutdown and restart were exercised in Xfce and Windows,
including pending-edit cancellation. Other Linux session managers, Wayland and
physical keyboards remain unverified.
The Linux guard requires a working inherited XSMP session connection; it reports
missing/unavailable protection to stderr. Forced termination and power loss cannot
preserve pending changes through these vetoes.

On this Windows build, `shutdown.exe /l` sends a committed session-end message
despite an application's veto. An independent WinForms control reproduced the
same behavior: ExitWindowsEx offered Cancel, while the command committed logoff
immediately after the control returned zero. The final installed app now cleans
up without the Tao panic on that command path, but its pending edit is lost;
the last explicitly saved value and SQLite integrity remain intact. Once
[WM_ENDSESSION commits](https://learn.microsoft.com/en-us/windows/win32/shutdown/wm-endsession),
the app cannot cancel session end. Normal logoff still offers Cancel, retains the
live native edit, and permits a subsequent independently verified Save.

The Windows package is unsigned, and the maintainer has no signing setup yet.
Signing and clean-machine SmartScreen behavior remain distribution decisions and
unverified checks. No public release was made. See [macOS QA](macos-release-qa.md)
for that platform's remaining gates.
