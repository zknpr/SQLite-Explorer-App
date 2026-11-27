# Changelog

## 0.4.0

### One repository

- The viewer, its workers and the native engine's worker are developed and
  built here, in `viewer/`, starting from the SQLite Explorer extension's 1.9.0
  viewer. Building the app no longer needs the extension's repository.
- From that viewer: the WebAssembly engine opens R*Tree tables and has SQLite's
  math functions; the native engine reports SQLite's own error messages; views
  and triggers that quote strings in double quotes work on the native engine;
  edits no longer delete rows silently in tables declared `ON CONFLICT REPLACE`;
  wide tables show fewer rows per page so their values arrive whole; console
  parameters bind as SQLite reads the same number in SQL; a save retries
  briefly while another program reads the database.

### Updates

- The app can update itself: SQLite Explorer → Check for Updates…, and, if
  you agree when the first launch asks, a check once a day. It asks before
  installing, and again when a window has unsaved changes. Updates are signed
  with the project's update key, kept offline; the app installs nothing else.
  macOS replaces the app, Windows runs the new installer, and Linux installs
  the new `.deb` through the administrator prompt.

### Unsaved work

- Refresh From Disk asks before it discards unsaved edits, from the menu, its
  shortcut and the sidebar button; Cancel keeps them.
- A page reload (F5, a context menu's Reload) is refused while the window has
  unsaved edits.
- Export Database with unsaved edits asks to save them first, instead of
  cancelling without a word.
- A Save As or export refuses a destination that is an open database, one of
  its `-wal`, `-shm` or `-journal` files, or a name SQLite would read as one.
- The WebAssembly engine refuses to read, or save over, a database another
  program has open in WAL mode or that has a log holding changes, so an older
  image cannot overwrite them.
- Edits larger than one 16 MiB native message (large deletes, batch updates,
  their undo and redo) go through in pieces on the native engine.
- A minimized window is brought forward before the app asks about unsaved
  changes.

### Windows

- Ctrl+Q, Ctrl+Shift+N, Ctrl+R, Ctrl+Shift+K and Ctrl+M work while the page has
  focus, and the browser's own reload keys do nothing.
- The Open, Import, Save As and Export dialogs belong to their window; they
  could open in the screen's corner, behind the app. Paths in messages no longer
  show the `\\?\` prefix.
- Files on FAT32 and exFAT volumes, paths past `MAX_PATH` and linked files are
  told apart correctly by the same-file and log checks.

### Linux

- Prompts, messages and file choosers belong to their window and are modal to
  it.
- The Debian package is named `sqlite-explorer`. Installing 0.4.0 replaces the
  `sq-lite-explorer` package of earlier releases.

### macOS

- The unsaved-changes prompt is a sheet on its window.

### Packaging

- The app embeds only the viewer's pages; the native engine ships beside them
  once, not twice.
- Tauri 2.12.7.

## 0.3.2 — 2026-10-24

- The viewer from the extension's 1.8.3, on the SQLite 3.54.1 native and
  WebAssembly engines, with native exports limited to the paths the shell
  chooses.

## 0.3.1 — 2026-10-09

- On Windows, the app refuses every web request to a host other than its own
  before it leaves the machine. WebView2 sent a refused navigation's request
  anyway.

## 0.3.0 — not published

- A release workflow builds each package on its own system and drafts a
  release with checksums and build-provenance attestations.

## 0.2.0 — not published

- The first version: native menus, dialogs and file associations, the SQL
  console, the native engine with a WebAssembly fallback, multiple databases
  and windows, and atomic saves.
