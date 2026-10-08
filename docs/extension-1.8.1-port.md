# Extension 1.8.1 desktop port

The app keeps the existing Tauri shell and generates its viewer from the extension's
desktop build target. This integration includes release 1.8.1 at
`16a102c98781c803882f4d40736bc65607de7f39`, including the previously requested
development changes.
The final integrated source commit is
`d503473a7dd6a3ed3d77aad1b506b45379d1da2a`.

The app port branch is `port/extension-1.8.1`; native release QA and fixes continue
on `test/macos-release-smoke` and `test/linux-windows-release-smoke`. Its source is the sibling extension's
`desktop-v1.8.1-port` branch in `.claude/worktrees/desktop-target`. Original branches
are preserved. The source commit and per-file SHA256 values are recorded in
`viewer-dist/manifest.json`; generated files must be changed upstream and synced.

## Included changes

- Cross-platform QA fixes: filtered native grids preserve synthetic row identity;
  the native launch protocol preserves Windows Unicode paths and uses the Windows
  temporary directory. Equivalent Windows path spellings reuse one tab, and
  ownership refusals cannot create a second WASM copy. Linux file associations
  pass selected paths, and oversized native windows fit the desktop work area.
  See [Linux and Windows QA](linux-windows-release-qa.md) for installed Debian,
  AppImage and Windows package results.

- Shared 1.8 grid, count, focus, editing, view, cell-content, import, query, and
  runtime changes, preserving the desktop entry point and native menus.
- 1.8.1 FTS5 shadow-table identity, pagination, and count fixes. WITHOUT ROWID
  shadow tables use their declared primary keys instead of a nonexistent rowid.
- Native read-query plans use the pinned query-plan library on the current
  connection, including TEMP objects and pending schema changes. The shell checks
  for the library before offering the native engine. DML Explain retains the
  existing built-in implementation and display limits.
- Full-cell downloads read exact stored bytes in 64 KiB windows and preserve
  UTF-16 and BLOB contents. The host checks every window, closes the snapshot
  before the save dialog, and reports downloads and cancellation correctly.
  The desktop's 512 MiB buffered export limit applies to this path.
- Import previews show omitted defaults and capture a schema token. The worker
  checks that token inside the import savepoint before inserting. The native
  shim's temporary metadata probes do not invalidate an otherwise current preview.
  The shell rejects a CSV/JSON file changed during its descriptor-based read.

## Regression contracts recovered from Claude's sessions

The prior app session was `7900cf19-1058-439f-83bc-48a91730e607`, last active
September 7. Its important contracts remain part of verification:

- Both engines keep edits pending until Save; native export retains its file
  route for databases and tables larger than the 16 MiB RPC frame.
- One editable copy per file across windows, native invalidation after external
  replacement, and stale WASM-save refusal remain shell responsibilities.
- Native availability must fail clearly when runtime artifacts are incomplete.
- Opening a database clears the loading state and imports all required UI helpers.
- CSS must parse through the full stylesheet. Sidebar rows fill their container;
  index names and their table labels have visible spacing and truncate correctly.
- Destructive and large-change confirmations are in-page dialogs. Theme choices,
  keyboard shortcuts, column resizing, and per-database state stay desktop-aware.
- Import files receive read-only grants, never database write grants. The two new
  native methods carry SQL/values or a table name, never filesystem destinations.

## Repeatable checks

In the source worktree:

```sh
node scripts/build.mjs
npx tsc --noEmit -p tsconfig.json
npm test
npm run native-lane
```

In this app:

```sh
npm run sync-viewer -- --ref <source-commit>
node scripts/sync-viewer.mjs --verify
npm test
cargo test --lib --manifest-path src-tauri/Cargo.toml
cargo test --lib --manifest-path src-tauri/Cargo.toml -- --ignored
cargo clippy --all-targets --manifest-path src-tauri/Cargo.toml -- -D warnings
npm run test:gui
npm run tauri build -- --debug --bundles app
codesign --force --sign - 'src-tauri/target/debug/bundle/macos/SQLite Explorer.app'
codesign --verify --deep --strict 'src-tauri/target/debug/bundle/macos/SQLite Explorer.app'
```

The ad-hoc signature seals the local development bundle. The debug build initially
has only the linker's signature on the executable, without a bundle resource seal.
This is not Developer ID signing or notarization.

## Verified on September 21, 2026

| Check | Result |
| --- | --- |
| Extension unit suite | 3,195 passed, 259 suites, no failures or skips |
| TypeScript | Typecheck passed |
| Generated source | Rebuild preserved all six viewer/worker hashes |
| Native lane | 78 shared fixtures, 4 errno checks, 15 fork checks, 20 transport checks, 98 sidecar checks, 119 method checks; all passed |
| New FTS regression | Six failures before the fix; 16 checks passed after it, including offset/keyset reads and unchanged file bytes |
| App sync tests | 2 passed |
| App Rust suite | 131 passed; all 4 opt-in checks also passed, including three live-sidecar tests and the runtime-pool measurement |
| Rust Clippy | All targets passed with warnings denied |
| Final generated viewer GUI | 10 flows passed, no browser errors; all six screenshots inspected |
| Artifact integration | All 10 files match the source commit and manifest; all 38 native methods match the Rust gate |
| macOS debug bundle | Built successfully; ad-hoc signature passes deep, strict verification |
| Bundled native runtime | All three bundled native files match the manifest after signing; initialization, parameterized read, bounded Explain, and clean shutdown passed from the bundle's resource directory |

The development app is
`src-tauri/target/debug/bundle/macos/SQLite Explorer.app`.
Final browser evidence is `/tmp/sqlite-explorer-port-XNeMe3/results.json`, with
screenshots and independently checked database/export files in that directory.
Source and native logs are `/tmp/sqlite-port-1.8.1-tests.log` and
`/tmp/desktop-port-1.8.1-native-lane.log`. Shell integration logs are
`/tmp/sqlite-app-synced-rust.log`, `/tmp/sqlite-app-synced-native-e2e.log`, and
`/tmp/sqlite-app-bundled-native.log`.

## Remaining release verification

The headless GUI script uses the actual generated viewer and WASM worker. It saves
isolated fixture databases and exports, checks them independently with sqlite3,
and writes screenshots plus artifact hashes to `/tmp/sqlite-explorer-port-*`.
Chrome and sqlite3 must be installed; `CHROME_PATH` can select another Chromium
executable. Subsequent testing used the actual bundled WKWebView, native sidecar,
file dialogs, menu shortcuts, and WASM fallback. It fixed an extension-only SQL
action leaking into the desktop, a console shortcut deleting drafts, and native
UTF-16 grid failures. The September 22 continuation also repaired dirty-tab close
confirmation and preservation of Rust refusal messages in the status line, then
checked external replacement, cross-window ownership and stale WASM-save recovery.
See [macOS release QA](macos-release-qa.md) for the current
results and remaining OS checks. The native smoke checklist remains the release
gate; no public release or push was performed.

The Linux/Windows continuation exercised installed Debian, AppImage and NSIS
packages, preserving this same viewer source and the existing desktop SQL console.
It fixed native session-end handling, layout-aware zoom and a startup listener
race. See [Linux/Windows release QA](linux-windows-release-qa.md) for the final
package hashes, native test evidence and remaining OS/distribution limits.
