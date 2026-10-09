# SQLite Explorer — Desktop Shell

Thin Tauri v2 shell around the extension repo's `desktop/` build target. The viewer UI,
worker, and sql.js runtime are **generated upstream** (`../SQLite-Explorer`, `node
scripts/build.mjs`) and synced here — never hand-edit `viewer-dist/`.

## Architecture

- `viewer-dist/` — synced upstream artifacts (`viewer.html`, `worker.js`, `sql-wasm.{js,wasm}`,
  `codicons/`, `dev-harness.html`) + a sha256 `manifest.json`. Produced by
  `scripts/sync-viewer.mjs`, never by hand.
- `src-tauri/` — the shell (Rust, Tauri v2). Owns the window, the native menus (File:
  Open / Open Recent / Save / Export / Import CSV/JSON / Refresh; Edit: native items; View: Theme submenu, Zoom
  ⌘+/⌘−/⌘0, Toggle Developer Tools in debug builds only; Window: predefined items),
  dialog-mediated file access behind a **session allowlist**, atomic saves, the settings
  store, zoom persistence, the recents store, Finder file associations
  (`bundle.fileAssociations` mirrors `DB_EXTENSIONS` — a cargo test holds them in
  lockstep), and a strict CSP. `RunEvent::Opened` delivers association opens; they park in
  `PendingOpen` until the page signals `viewer_ready`, then flush in arrival order through
  `deliver_opens` — a QUEUE bounded by `MAX_PARKED_OPENS`, because a cold-start Finder
  multi-selection admits every path before the page is ready and a single slot kept only
  the last (overflow is refused on stderr, never dropped silently).
  The webview reaches the shell only through the `window.__SQLITE_DESKTOP__` bridge
  injected by `src-tauri/bridge.js` — the viewer bundle never calls Tauri APIs directly.
- Theming: the viewer ships 5 palettes (`data-theme` blocks; `system` resolves to
  dark/light from the OS). Two pickers drive one state: the View>Theme CheckMenuItems
  (shell) and the Configuration modal select (viewer); the shell re-syncs checkmarks
  inside `save_settings` after each successful write. Menu **accelerators are resolved by
  AppKit against the active keyboard layout and fail silently** — verify them by
  keypress, never by menu click (that is why Zoom In ships `CmdOrCtrl+Shift+Equal`,
  which AppKit renders as ⌘+; bare `=` is unreachable on some layouts).
- Engine: native `tjs` sidecar first, with a sql.js WASM worker fallback. Both keep
  edits pending until Save. Native read-query plans load the pinned
  `native/query-plan.dylib` beside `tjs` on the same database connection; the shell
  requires the library, binary, and worker before reporting native availability.

The UI's only backend seam is `core/ui/modules/api.js` upstream; the desktop build swaps in
`desktop-api.js` (esbuild `onResolve`), which calls an in-page `desktop-host.js` that owns
the worker, the `ModificationTracker` undo/redo history, and file I/O via the bridge.

## Commands

- `npm run sync-viewer -- --local` — pull artifacts from the sibling checkout's working tree
- `npm run sync-viewer -- --ref <commit>` — pull from a pinned upstream commit
- `node scripts/sync-viewer.mjs --verify` — check `viewer-dist/` against its manifest
- `npm run tauri dev` — fast iteration, **but serves over localhost with NO CSP**
- `cargo run --features tauri/custom-protocol` (from `src-tauri/`) — the real `tauri://`
  asset protocol with CSP enforced. **Use this to verify any CSP / asset-protocol claim** —
  `tauri dev` cannot.
- `npm test` — sync-script tests; `cd src-tauri && cargo test --lib` — shell unit tests.
  `cargo test --lib -- --ignored` also runs three live-sidecar tests and one runtime-pool measurement.
- `npm run test:gui` — headless Chrome checks against `viewer-dist/` and the real WASM
  worker, with isolated fixtures, saved-byte checks via sqlite3, screenshots and an
  artifact hash report in `/tmp/sqlite-explorer-port-*`. Requires Chrome and sqlite3.
  This does not verify AppKit menus, Finder opens, or Tauri CSP enforcement.
- GUI smoke: `scripts/qa/` (`make-test-db.sh` builds the edge-case fixture, `click.swift` is
  the CGEvent input helper with click/dclick/rclick/move/scroll/drag, `guarded-input.sh`
  refuses any synthetic event while another app is frontmost, `wait-idle.sh` + `winid.swift`
  + `islocked.swift` gate a scripted batch on the human being away and capture the app window
  by CGWindowID only, `smoke-checklist.md` is the macOS pass) — must fully pass
  before a release. Steps 21-22 need a **bundled app**
  (`npm run tauri build -- --debug`): LaunchServices only registers `.app` bundles, never the
  bare `cargo run` binary — and stale registrations from raw dev binaries can intercept
  Finder opens with a "(null)" permission error (`lsregister -f <the .app>` to clean).

## Security invariants

- **No arbitrary-path FS.** The webview renders untrusted DB content; a webview compromise
  must not become an arbitrary file read/write. Reads and in-place writes are restricted to
  session-allowlisted (dialog-picked) paths; `save_file_as` writes only where the user picks.
- **Atomic, symlink-safe writes.** `write_atomically` creates the temp file with
  `File::create_new` (O_EXCL, so a planted symlink at the temp path fails closed), preserves
  the target's mode, and `fsync`s before rename.
- **CSP:** `script-src 'self'` (+ Tauri-injected hashes), no `unsafe-eval`; `base-uri`,
  `form-action` and `frame-ancestors` are `'none'` because `default-src` covers none of them
  (`the_csp_sets_what_default_src_does_not_cover`). Tauri delivers it as a response header,
  so `frame-ancestors` is live. Do not weaken it to debug — use devtools. Verify
  enforcement under `custom-protocol`, not `tauri dev`.
- **Navigation pin:** the `navigation_pin` plugin refuses any top-level navigation off the
  served origin (`tauri://localhost`, `http://tauri.localhost` on Windows, plus `devUrl`
  in `tauri dev` only); `blob:` is judged by its embedded origin. CSP `connect-src` does
  not cover navigation, so without it a compromised page exfiltrates through `location`.
  A plugin hook runs for every webview, so `db-<n>` windows cannot be built without it.
  `window.open` is already refused: no new-window handler is installed.
- **Windows request pin** (`request_pin.rs`): WebView2 SENDS a refused navigation's request.
  `NavigationStarting` is cancelled synchronously and the page stays, but `location.href`,
  `location.assign`, link clicks and meta refresh still delivered their URL to a foreign
  server (measured on WebView2 154; WKWebView and WebKitGTK sent nothing). So the same
  plugin's `on_webview_ready` installs a `*` `WebResourceRequested` filter that answers
  every web request (http/https/ws/wss) off `app_request_origins` with a local 403.
  Only `data:`/`blob:`/`about:` pass; every other scheme is refused, `file:` included,
  because a `file://host/` URI is a UNC/SMB connection that can leak NTLM credentials. wry's custom-protocol handler ignores foreign URIs,
  so the two coexist. `the_request_pin_admits_what_the_csp_connects_to` keeps IPC admitted.
  Verify Windows navigation claims by counting hits on a foreign listener, never by
  checking whether the page moved.
- **Capabilities are the real boundary** (`withGlobalTauri` hands the page the full
  `__TAURI__` surface, so `bridge.js` is hygiene, not a boundary). The set is exactly
  `core:event:allow-listen` + `allow-unlisten` (all the bridge's `listen` needs; every
  other call it makes is an app command, which is not ACL-gated) plus the two
  `core:image:deny-from-*` tripwires. `core:default` and `dialog:default` were REMOVED —
  `core:menu` let a page mint a menu item carrying a shell id (`new-window`, `quit-app`)
  that muda's process-wide dispatch then runs through the shell's own handler, and
  `core:event:allow-emit` defeated the per-window `emit_to` routing. Add nothing back
  without deriving it from a real `bridge.js` call;
  `the_capability_grants_only_what_the_bridge_calls` is the lockstep.
- **Where command bodies run** (`crate::blocking`). A sync `#[tauri::command]` runs on the
  MAIN thread; `#[tauri::command(async)]` on a sync body runs on a WORKER of tauri's shared
  tokio runtime, which is only `available_parallelism()` deep — fewer than the 16 sidecars
  one window may open, so blocking bodies there froze every command in every window. Every
  blocking body is now an `async fn` that hands its body to `crate::blocking` (tokio's
  blocking pool); `native_rpc` alone awaits, because its wait is the unbounded one.
  `no_command_body_blocks_the_main_thread_or_a_shared_runtime_worker` holds this.
- **One editable copy per file, app-wide, on EVERY engine** (`native::OpenFiles`).
  Per-window registries and the page-side host both dedupe within one window only; two
  windows opening one file is silent data loss. One app-global registry, canonical path →
  owning window, fed by two kinds of evidence: the shell OBSERVES the native open/close
  pair, so `native_open` takes a `NativeHold` released by `Drop` on the sidecar handle (no
  teardown path has to remember to unwind it); it sees no such pair for WASM, so each page
  PUSHES its whole open-path set on `set_unsaved_state` and `sync_reported` installs it
  wholesale — a close is simply an absence in the next push. `read_database_bytes` takes a
  TTL-bounded provisional hold to cover the gap before that first push (and to refuse the
  host's WASM fallback, which would otherwise launder a refused native open into the same
  pair). A push can only ever narrow or widen its OWN window's set, never touch another's,
  and never the native flag. Never claim on a read without an expiry: the shell has no
  "the page closed this database" signal, and a hold with no release breaks
  close-then-reopen-elsewhere for the session.
- **Import sources are a READ-ONLY grant on their own list.** CSV/JSON import
  (`pick_import_source` / `read_import_text`, upstream `import-data.js`) keeps picked
  files on `ImportSourceAllowlist`, never `SessionAllowlist` and never the recents: the
  session list is a read-AND-write grant (`save_database` overwrites any path on it),
  and an import source must not become a file a compromised page can rewrite or reopen
  as a database. `read_import_text` reads only paths the import dialog returned, at
  most `IMPORT_MAX_BYTES` (64 MiB, checked from the descriptor before allocating),
  UTF-8-validated, through the same `O_NONBLOCK`+`fstat` gate as the database read.
  The worker method behind it, `importRows`, carries a table name, row objects and
  byte budgets — no path — which is why layer 3 admits it. `an_import_pick_never_
  widens_the_database_allowlist` and `the_import_cap_matches_the_viewer_parser` hold
  this.
- **`settings.json` is the ONLY webview-writable file.** `recents.json` and
  `window-state.json` are shell-written only — never add a command that writes them, and
  never fold their contents into `settings.json`. The reason is an attack path, not
  tidiness: a compromised page that could write a recent entry would only need one
  innocent user click on the Open Recent menu to launder an arbitrary path (`/etc/…`)
  into the read allowlist. Recent/association opens allowlist only OS- or
  native-menu-delivered paths. The only webview-reachable command added for all of this
  is `viewer_ready` — no arguments, its sole effect is flushing a path the OS already
  delivered.
- **External replacement is detected by the shell, keyed on the DbId — never by a
  webview path.** `native_open` pins the bound file's identity (device + inode, from the
  same `stat` that enforces the size bound) into the sidecar's `SidecarCore`; every
  `native_rpc`/export re-`stat`s the bound path BEFORE forwarding and AFTER the answer
  and refuses with `ERR_NATIVE_FILE_CHANGED` on a mismatch, so a sidecar whose
  descriptor points at an orphaned inode (atomic rename over the path, move, delete)
  never executes another statement — least of all a COMMIT the user would see reported
  as saved. The page retires the database on that refusal and offers Reload Database.
  Device + inode ONLY: size and mtime change on every ordinary SQLite write (another
  process's DML, a WAL checkpoint, VACUUM), none of which orphan the handle. The WASM
  lane is the opposite by design: it holds a SNAPSHOT, so `read_database_bytes` records
  the descriptor's full generation (dev, ino, size, mtime, ctime) per window and
  `save_database` refuses (`ERR_FILE_CHANGED`) unless the file is still exactly that
  generation — writing a stale image back would discard another writer's changes. The
  connection is not retired there; Export and Reload are the remedies.
- **maxFileSize is the shell's to enforce, on BOTH engines.** `native_open` (before
  spawning) and `read_database_bytes` (on the open descriptor, before allocating) take
  the page's bound and refuse with one `ERR_FILE_TOO_LARGE` sentence; the host never
  falls back to WASM past it (a user-selected limit that changing engine cannot lift —
  the VS Code host refuses before choosing an engine for the same reason). The desktop's
  default is the setting's ceiling, 4000 MiB, not the extension's 200: the primary engine
  maps the file, so a 400 MiB database is the flagship case (smoke 37). 0 = unlimited.
- Viewer artifacts are sha256-manifested — run `--verify` before building a release.

### Deferred security hardening (fast-follow, tracked)

Not yet closed; all inside the "local attacker already owns the DB's directory" threat model
(F1, the arbitrary-overwrite exploit, IS closed):

- **Symlink-race cluster (F3):** the allowlisted-path read and the save `rename` (final
  component) are exact-match, not `O_NOFOLLOW` / device+inode pinned;
  `write_atomically`'s permission copy is path-based after `drop` (fchmod-before-drop
  would close it). Close these together. (The read's *hang* half IS closed — it opens
  `O_NONBLOCK` and `fstat`s the descriptor, so a FIFO or device swapped in cannot park a
  thread forever; the symlink half is deliberately still open, because a user who picks a
  symlinked database must keep being able to read it.)
- **Ready-latch reload gap:** `viewer_ready` sets a one-way latch; a webview reload
  re-registers listeners but a Finder open landing in that sub-second window emits to a
  torn-down listener and is lost (non-security, user just reopens). Fix needs an
  unload/reload signal.
- **Cross-window duplicate opens depend on the page for the WASM half.** `OpenFiles` is
  authoritative for native (shell-observed) and page-reported for WASM. A COMPROMISED page
  can under-report its own window's set and so let another window open a file it still
  holds — the same self-inflicted loss as a page discarding its own buffer, which it can
  do anyway. A page that dies mid-open strands a file for at most one
  `PROVISIONAL_HOLD_TTL`; a window that dies strands nothing (teardown clears it).

## Repo model

The public repository starts from a single snapshot commit on `main`. The current
viewer pin is on the extension repository's public `desktop-v1.8.1-port` branch; see
`docs/extension-1.8.1-port.md` for that integration's scope and verification.
`docs/superpowers/` and `.superpowers/` are gitignored working files.
