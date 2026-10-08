// Injected into the webview before any page script. Adapts the narrow
// __SQLITE_DESKTOP__ bridge contract onto Tauri's global API so the upstream
// viewer bundle never touches Tauri directly.
(function () {
  const invoke = (...args) => window.__TAURI__.core.invoke(...args);
  // Native menu accelerators do not reliably reach a focused Windows WebView,
  // and GTK's Equal accelerator misses layout-resolved plus keys. Handle keys
  // delivered to this page; a native accelerator that consumes a key never
  // delivers this event. AltGr and composition must keep their text semantics.
  if (!/Mac|iPhone|iPad|iPod/.test(navigator.platform)) {
    window.addEventListener('keydown', (event) => {
      if (!event.ctrlKey || event.metaKey || event.altKey || event.isComposing || event.defaultPrevented) return;
      const direction = event.key === '+' || event.key === '=' ? 1
        : event.key === '-' ? -1 : event.key === '0' ? 0 : null;
      if (direction === null) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      invoke('adjust_zoom', { direction }).catch(error => console.error('Could not adjust zoom:', error));
    }, true);
  }
  const encodePathHeader = (value) => encodeURIComponent(value);
  // This window, for event delivery. Menu items and Finder opens are addressed to
  // ONE window by label (several windows share one menu bar), and the shell emits
  // them with `emit_to(<label>)`. A listener registered through the plain
  // `event.listen` is stored with target `Any`, which `emit_to`'s filter does NOT
  // match — only `Window`/`Webview`/`WebviewWindow`/`AnyLabel` with the same label
  // do. `getCurrentWebviewWindow().listen` registers `WebviewWindow { label }`,
  // which matches both a labelled `emit_to` AND a plain app-wide `emit` (the theme
  // broadcast). Keep these two in step with `deliver_open` / the menu passthrough
  // in lib.rs.
  // Acquired LAZILY, never at init-script time. This script is injected BEFORE any
  // page script, which is also before Tauri's own bootstrap has populated
  // `__TAURI_INTERNALS__.metadata` — and `getCurrentWebviewWindow()` reads
  // `metadata.currentWindow.label`. Calling it up here throws, the throw aborts this
  // whole IIFE, and `window.__SQLITE_DESKTOP__` is never assigned, so the viewer
  // renders "Desktop bridge missing" and the app is dead on arrival. (That shipped
  // once: the module and the function both exist by the time the page runs, which is
  // why nothing but a real launch catches it.) Every caller below is a listener
  // registration that runs after page load, by which time the metadata is there.
  let currentWebviewWindow = null;
  const currentWindow = () => {
    if (currentWebviewWindow === null) {
      currentWebviewWindow = window.__TAURI__.webviewWindow.getCurrentWebviewWindow();
    }
    return currentWebviewWindow;
  };
  const subscriptions = [];
  const listenBeforeReady = (name, handler) => {
    // The upstream viewer registers listeners without awaiting them. Retain
    // their completion here so viewerReady cannot flush a startup path into a
    // listener that Tauri has not installed yet. Capture failures immediately;
    // viewerReady propagates them through the viewer's visible error path.
    subscriptions.push(currentWindow().listen(name, handler).then(
      () => ({ ok: true }), error => ({ ok: false, error })
    ));
  };

  window.__SQLITE_DESKTOP__ = {
    pickDatabase: () => invoke('pick_database'),
    // maxBytes is the page's configured maxFileSize in bytes (0 = unlimited). The
    // shell refuses a larger file on the open descriptor BEFORE allocating
    // (ERR_FILE_TOO_LARGE) and records the file's on-disk generation for this
    // window — the stale-image guard saveDatabase checks. A non-numeric bound is
    // not sent (the shell reads absent as unlimited), never coerced to 0.
    async readDatabaseBytes(path, maxBytes) {
      const data = await invoke('read_database_bytes', {
        path,
        ...(Number.isFinite(maxBytes) && maxBytes >= 0 ? { maxBytes: Math.floor(maxBytes) } : {})
      });
      return data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data);
    },
    // In-place save of a WASM image. The shell REFUSES (ERR_FILE_CHANGED) when the
    // file's generation is not the one this window last read or wrote there —
    // writing the image back would discard another writer's changes — and the
    // host surfaces the sentence (Export a copy, or Reload) with the edits kept.
    async saveDatabase(path, bytes) {
      await invoke('save_database', bytes, {
        headers: { 'x-target-path': encodePathHeader(path) }
      });
    },
    saveFileAs(defaultName, bytes) {
      return invoke('save_file_as', bytes, {
        headers: { 'x-default-name': encodePathHeader(defaultName) }
      });
    },
    // Save As, as opposed to the export above: same dialog and same atomic write,
    // plus `x-adopt`, which tells the shell to add the picked path to the session
    // allowlist. That grant is what lets a database with no file yet (the boot
    // `untitled.db`, a dropped file) adopt the chosen path and save in place from
    // then on. Exports deliberately do NOT set it — see save_file_as in lib.rs.
    saveDatabaseAs(defaultName, bytes) {
      return invoke('save_file_as', bytes, {
        headers: { 'x-default-name': encodePathHeader(defaultName), 'x-adopt': '1' }
      });
    },
    // CSV/JSON import (upstream import-data.js). Two calls, both dialog-mediated
    // and both READ-ONLY on the shell side: the pick shows the native open dialog
    // filtered to .csv/.json and puts the chosen path on the shell's IMPORT
    // allowlist — a separate list from the database session allowlist, so an
    // import source never becomes a file this page can save over or reopen as a
    // database — and the read returns that file's UTF-8 text, refusing any other
    // path, non-regular files, non-UTF-8 content and anything over 64 MiB before
    // reading it. The page hands back exactly the path the pick returned.
    pickImportSource: () => invoke('pick_import_source'),
    async readImportText(path) {
      const data = await invoke('read_import_text', { path });
      // The shell already validated the bytes; decoding fatally here means a
      // shell regression surfaces as an error, never as mojibake in the grid.
      return new TextDecoder('utf-8', { fatal: true }).decode(
        data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data)
      );
    },
    loadSettings: () => invoke('load_settings'),
    saveSettings: (settings) => invoke('save_settings', { settings }),
    onMenu(handler) {
      listenBeforeReady('desktop-menu', (event) => handler(event.payload));
    },
    onOpenFile(handler) {
      listenBeforeReady('desktop-open-file', (event) => handler(event.payload.path));
    },
    // The subscription half of drag-and-drop open. Tauri suppresses HTML5 file
    // drops in the webview, so the shell's window-level DragDrop handler is the
    // only place drop paths exist; it filters them (database extensions, regular
    // files) and emits `desktop-drag-drop` to THIS window's label. Without this
    // member the shell emitted to nobody and the feature stayed dead — the two
    // halves shipped in different repos and neither one alone is observable.
    onDragDropPaths(handler) {
      listenBeforeReady('desktop-drag-drop', (event) => handler(event.payload.paths));
    },
    setTitle: (title) => invoke('set_title', { title }),
    async viewerReady() {
      for (const result of await Promise.all(subscriptions)) {
        if (!result.ok) throw result.error;
      }
      return invoke('viewer_ready');
    },
    // Pushed on every registry change (open/close/switch) and on every
    // dirty-state change, so the shell can answer the OS synchronously when
    // this window is asked to close — it cannot await the page from inside
    // that handler. Reports THIS window only; the shell keys it by the
    // webview's own label, so it can neither read nor set another window's
    // state.
    //
    // openPaths is the same push's second job: the set of files this window
    // has open, whichever engine serves them. The shell replaces this
    // window's set wholesale with it and refuses a SECOND window opening any
    // of them — two editable copies of one database silently overwrite each
    // other. Omitted entirely (not sent as []) when the host does not supply
    // it: the shell reads absent as "no report", and an empty array would
    // tell it to release holds it may still need.
    setUnsavedState: (hasUnsaved, count, openPaths) =>
      invoke('set_unsaved_state', {
        hasUnsaved: !!hasUnsaved,
        count: count >>> 0,
        openPaths: Array.isArray(openPaths) ? openPaths.map(String) : null
      }),
    // Native engine (tjs sidecar). N databases may be open at once, each with
    // its own sidecar process; nativeOpen ADDS one and resolves to
    // {dbId, boundPath}:
    //   dbId      — opaque shell-issued routing token. EVERY later native
    //               call must carry the id of the database it means. It is
    //               the shell's only routing input: an unknown, closed, or
    //               malformed id is refused (ERR_NATIVE_UNKNOWN_DB), never
    //               retargeted onto some other open database.
    //   boundPath — the canonical path that sidecar is bound to. The host
    //               MUST carry this exact string in its initializeDatabase
    //               config.path, or the shell's layer-3 gate (and the
    //               sidecar's own argv check) will refuse the envelope. The
    //               gate compares against the bound path of the sidecar the
    //               dbId resolved to, so naming another database's path is a
    //               refusal, not a redirect.
    // nativeRpc takes and returns envelope JSON strings verbatim. nativeClose
    // closes exactly one database and REJECTS an id that is not open (a
    // double close is an error, not a no-op); app exit closes whatever is
    // still open.
    nativeAvailable: () => invoke('native_available'),
    // maxBytes: the same maxFileSize bound as readDatabaseBytes, refused before any
    // sidecar is spawned — so no engine admits a file the other refused. The shell
    // also pins the file's identity (device + inode) at open and refuses every later
    // nativeRpc for this dbId with ERR_NATIVE_FILE_CHANGED once the file at the
    // bound path is a different file (replaced by an atomic rename, moved, deleted);
    // ordinary writes by another process keep the inode and never trigger it.
    nativeOpen: (path, readOnly, maxBytes) => invoke('native_open', {
      path,
      readOnly: !!readOnly,
      ...(Number.isFinite(maxBytes) && maxBytes >= 0 ? { maxBytes: Math.floor(maxBytes) } : {})
    }),
    nativeRpc: (dbId, envelopeJson) => invoke('native_rpc', { dbId, envelope: envelopeJson }),
    nativeClose: (dbId) => invoke('native_close', { dbId }),
    // Out-of-band exports: the shell owns the save dialog, the temp path, and
    // the atomic move — no path arguments exist on this surface. Resolves to
    // {success:false} on dialog cancel or {success:true, savedAs}. argsJson is
    // the worker's positional exportTable argument array as a JSON string.
    nativeExportDatabase: (dbId) => invoke('native_export_database', { dbId }),
    nativeExportTable: (dbId, argsJson) => invoke('native_export_table', { dbId, argsJson })
  };
})();
