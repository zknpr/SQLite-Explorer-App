# macOS release QA — September 21–22, 2026

The actual app was exercised through Computer Use, using disposable databases in
`/tmp/sqlite-macos-app-MR9Rk9`. This run includes extension release 1.8.1
(`16a102c98781c803882f4d40736bc65607de7f39`) and the desktop integration at
`5b592ea339fd75f87ab26ebeb8838c90ba62a3d3`, pinned in `viewer-dist/manifest.json`.
The September 21 checks used source `a0061e1`; the continuation below used
`10bea8e` and then the final source above.
Nothing was pushed or published. This is a tested local build, not approval of
every item in the full release checklist.

## Fixes found by running the app

1. **Duplicate SQL entry.** The extension's sidebar SQL Query action carried a
   `hidden` class that its CSS did not honor. It appeared in the app without a
   desktop handler. The shared CSS now honors the class; VS Code explicitly
   removes it. The app retains its existing CodeMirror SQL console.
2. **SQL draft deletion.** With the editor focused, Cmd+Shift+K invoked
   CodeMirror's default Delete Line instead of closing the console. An explicit
   editor binding now closes the existing console and preserves its draft.
   The browser regression failed before the fix and passed after it; both the
   instrumented app and optimized release bundle were checked by keypress.
3. **Native UTF-16 grids failed.** The bundled txiki runtime only supports UTF-8
   TextDecoder, while the new cell validation constructs UTF-16 decoders even
   for ordinary grid reads. A shared strict decoder now handles UTF-16LE/BE,
   retains BOM/NUL data, and refuses malformed surrogate sequences instead of
   changing identity or history bytes. Four real-sidecar grid checks failed
   before the fix; ordinary and WITHOUT ROWID grids pass in both byte orders.
4. **Dirty database tabs would not close.** Cmd+W with two tabs and unsaved
   edits called `window.confirm`, which reached an unavailable Tauri dialog
   command and rejected without presenting a prompt. Tab closing now awaits
   the existing in-page confirmation. Cancel preserves the edit, and an answer
   is ignored if the active database or host changed while the prompt was open.
   Unit and browser regressions failed before the fix and passed afterwards;
   the real WKWebView prompt and Cancel path also passed.
5. **Shell refusals appeared as “undefined”.** Opening a file owned by another
   window correctly refused access, but Rust's string error lost its message
   in a handler expecting an Error object. The status line now preserves both
   forms. A failing regression test pinned the issue; the corrected ownership
   explanation was verified in both QA and optimized release bundles.

## Actual app results

These used WKWebView at `tauri://localhost/viewer.html`, the real Rust bridge and
bundled sidecar, native OS dialogs, and independent sqlite3/file assertions.
The headless browser harness was also run but is not the evidence for this table.

| Flow | Result |
| --- | --- |
| Cold database open, native engine, exact 64-bit integers | Passed |
| Inline edit, Cmd+Z/Cmd+Shift+Z, pending bytes before Cmd+S | Passed |
| Existing SQL console, bound parameters, bounded native Explain, autocomplete | Passed |
| SQL write remains pending; Cmd+S from the editor commits it | Passed |
| Native Save dialog exports the displayed query plan | Passed; CSV contents checked |
| Cmd+Shift+K preserves a focused SQL draft | Passed after fix |
| Three-file cold open retains every tab and selects the last | Passed |
| 407 MiB native database opens and counts 358,400 rows | Passed |
| Cmd+2 selects the second database with editor focus | Passed |
| UTF-16 FTS5 WITHOUT ROWID shadow-table grid | Passed after fix |
| UTF-16 inspector text paging and stored Hex | Passed |
| Complete-cell native download | Passed; all 200,000 bytes match SQLite's BLOB cast |
| CSV import picker, omitted defaults, preview and Save | Passed; two stored rows match defaults |
| Forced WASM fallback in packaged WKWebView | Passed; SQL writes pending until real shell save |
| Error/CSP observation during the final native and WASM sessions | No uncaught errors, rejections, console errors or CSP violations |
| Zoom menu and Cmd+0 | Passed |
| Optimized release bundle without test driver | Opened UTF-16 rows, ran SQL, preserved draft on close/reopen |

The fallback test temporarily removed the QA bundle's native executable and its
debug checkout fallback, then restored both in a `finally` block immediately
after the database opened on WASM. Manifest and bundle signature verification
passed afterwards. Production resources were not removed.

Evidence: `actual-app-checks.json` (22 checks), `native-probe.json`,
`wasm-probe.json`, screenshots, exported files and fixture databases in the
scratch directory above. Automated browser evidence is
`/tmp/sqlite-explorer-port-UuDEYr`. These temporary files are not committed.

## September 22 continuation

These checks ran on disposable fixtures in `/tmp/sqlite-release-sep22-eWR838`,
using macOS 27.0 (26A428), packaged WKWebView and real native dialogs. SQLite
queries, sidecar process counts and exported bytes independently checked the
visible results.

| Flow | Result |
| --- | --- |
| Dirty tab close and Cancel | In-page prompt appears; pending edit and both tabs survive |
| Edits, Undo and Save across two native tabs | Each database retains its own history; only the saved file changes |
| Atomic external replacement during a pending native edit | Save refuses, shows Reload required, invalidates stale history and reaps only that file's sidecar |
| Reload after replacement | Current disk rows load; the other native database remains usable |
| Open the same file in another window | Clear refusal; no second native worker or WASM copy |
| Warm OS file delivery with two windows | Only the focused second window opens the new database |
| Clean second-window close in QA bundle | Only its sidecar exits; the first window still loads rows |
| Native Open dialog Cancel | No database added and existing databases remain open |
| Stale WASM Save | External bytes remain intact and the pending edit stays in memory |
| Recovery export after stale Save | Separate database contains the pending edit and passes SQLite quick_check |
| Export dialog Cancel | Reports Database export cancelled; no output file appears |
| WASM reload and subsequent Save | External edit becomes visible; a fresh edit saves without losing it |
| Native picker after ownership refusal, optimized release | Another file opens successfully in the second window |

For WASM recovery, the single pending inline edit was exported, then undone
before Reload. This verifies clean reload and recovery without claiming to
have tested approval of a dirty-reload confirmation. The native resources were
restored in a `finally` block immediately after forced fallback opened; their
hashes and the QA bundle signature were verified afterwards.

The final native diagnostic session had no uncaught errors, rejections, console
errors or CSP violations. The deliberate external-replacement and stale-save
sessions each logged their expected handled refusal; neither produced uncaught
errors, rejections or CSP violations. These expected errors are retained in
the evidence instead of being removed from the observer.

Evidence includes `checks.json`, `native-final-probe.json`,
`wasm-final-observations.json`, `release-artifacts.json`, screenshots, recovery
exports and fixture databases. The final browser run is
`/tmp/sqlite-explorer-port-8bCEuE`. The optimized release was rebuilt from the
final source; its native resource hashes match the manifest and its deep/strict
ad-hoc signature verifies.

Two automation limitations remain recorded in `limitations.json`. In the QA
bundle, a subsequent Open picker stayed disabled after an ownership refusal;
the same sequence passed in the optimized bundle, and repeated picks passed in
a single QA window. After closing the optimized bundle's second window,
Computer Use timed out inspecting the surviving window. Its sidecar cleanup
was correct and a process sample showed the main thread idle in AppKit's event
loop; this does not establish an app hang. The clean fixture process was stopped
with SIGTERM after collecting evidence. No QA or fixture sidecar processes
remain. A physical multi-window check should resolve these observations.

## Automated verification and build

| Check | Result |
| --- | --- |
| Extension unit suite | 3,203 passed, 259 suites, no failures/skips |
| TypeScript | Passed |
| Native lane | September 21: 78 shared fixtures, 4 errno, 15 fork-only, 20 transport, 108 sidecar and 119 method checks passed; native artifacts unchanged on September 22 |
| Browser GUI | All 11 flows passed, including duplicate SQL action, draft preservation and dirty-tab close regressions |
| App sync tests | 2 passed |
| Rust | 131 passed plus all 4 opt-in checks |
| Clippy | All targets passed with warnings denied |
| Viewer manifest | All 10 files match the pinned source |
| Release bundle | Optimized build; ad-hoc deep/strict signature verified; three bundled native files match the manifest |
| Test-driver exclusion | Normal dependency tree excludes the driver; disabling debug assertions with the QA feature fails compilation; release executable has no QA activation marker |

The local app is `src-tauri/target/release/bundle/macos/SQLite Explorer.app`.
Ad-hoc signing is not Developer ID signing or notarization.

## Repeatable WKWebView diagnostics

The optional `qa-webdriver` feature adds a local WebDriver server only when the
runner explicitly sets a port. It is forbidden in builds without debug
assertions. Its initialization script observes startup errors; it does not
replace the bridge, change CSP, grant capabilities, or fake a database engine.
All 443 existing locked packages retain their versions/checksums; the 26 added
packages belong to the optional QA dependency graph. The QA identity uses a
separate app configuration directory.

```sh
npm run tauri build -- --debug --features qa-webdriver --config src-tauri/tauri.qa.conf.json --bundles app
codesign --force --sign - 'src-tauri/target/debug/bundle/macos/SQLite Explorer QA.app'
open -n -a "$PWD/src-tauri/target/debug/bundle/macos/SQLite Explorer QA.app" --env SQLITE_EXPLORER_QA_WEBDRIVER_PORT=57494 /absolute/path/to/disposable.sqlite
# Exercise the app using Computer Use or manually, then collect read-only diagnostics:
node scripts/qa/macos-probe.mjs 57494 native
# Use "wasm" for an intentionally forced fallback session.
```

The probe checks the actual protocol, engine, SQL entry visibility and collected
errors. It does not automate the interactive checklist or establish CSP attack
resistance. Quit the QA app when finished; the opt-in driver can evaluate page
scripts and should only be used with disposable fixtures.

## Remaining release gates

- **Unsaved OS quit/window-close confirmation:** the menu reaches the prompt path, but
  macOS hosts the unparented alert in UserNotificationCenter. Computer Use
  explicitly blocks that target. Cancel and OS/Dock quit were not verified.
  The same limitation was reproduced with the test driver removed; it is not
  classified as an app defect from this evidence. The separate in-page dirty-tab
  prompt and Cancel path now pass; approval is covered by the browser harness.
- **Zoom accelerators on the Italian keyboard layout:** native menu zoom and
  Cmd+0 work; synthetic Cmd+plus/minus did not change the factor. Distinguish a
  real keyboard-layout issue from the automation mapping with physical keys.
- **Remaining OS/data-loss checklist cases:** Finder double-click, drag/drop,
  physical multi-window interaction, dirty-reload approval and the other
  unexecuted branches still need the full
  [smoke checklist](../scripts/qa/smoke-checklist.md). Automated coverage of
  several of these contracts is not a substitute for their OS checks.
- Distribution signing/notarization and testing the downloaded release package
  remain separate from this local ad-hoc build.
