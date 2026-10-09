#[cfg(all(feature = "qa-webdriver", not(debug_assertions)))]
compile_error!("qa-webdriver is test-only and must not be enabled in a release build");

use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::menu::{CheckMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::{AppHandle, Emitter, Manager, State, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_dialog::DialogExt;

mod native;
#[cfg(target_os = "linux")]
mod linux_session;
#[cfg(windows)]
mod request_pin;
#[cfg(windows)]
mod windows_file_info;
#[cfg(windows)]
mod windows_session;

/// The other half of quit. The `quit-app` menu item covers ⌘Q; this covers the
/// quits macOS starts itself (Dock ▸ Quit, an `aevt`/`quit` Apple Event,
/// logout), which reach neither the menu nor a preventable tauri event.
#[cfg(target_os = "macos")]
mod terminate;

/// App-global "which window has this file open" registry — see
/// `native::OpenFiles`. Re-exported here because all three of its inputs live
/// in this file's half of the shell: the native route takes a shell-observed
/// hold, the WASM route (`read_database_bytes`) takes a provisional one, and
/// the page's own push (`set_unsaved_state`) installs each window's set.
pub use native::OpenFiles;

/// Paths the user picked via a dialog this session. The webview can only ever
/// read/write these exact paths — DB content is untrusted input, so a
/// compromised webview must not become an arbitrary-path file oracle.
#[derive(Default)]
pub struct SessionAllowlist(Mutex<HashSet<PathBuf>>);

/// Files the user picked in the IMPORT dialog this session (`pick_import_source`).
///
/// A second list, not `SessionAllowlist`, on purpose. The session allowlist is a
/// READ-AND-WRITE grant — `save_database` overwrites any path on it in place —
/// because its entries are databases the user opened for editing. An import source
/// is picked to be read once, as text. Putting it on the database list would let a
/// compromised page rewrite the user's CSV with arbitrary bytes, or hand it to
/// `read_database_bytes`/`native_open` as a database. So: `read_import_text` reads
/// only paths on THIS list, nothing writes to a path on it, and an import pick never
/// touches the recents (a CSV in Open Recent would be reopened as a database).
/// `an_import_pick_never_widens_the_database_allowlist` holds all three.
#[derive(Default)]
pub struct ImportSourceAllowlist(Mutex<HashSet<PathBuf>>);

#[derive(Serialize)]
pub struct PickedFile {
    path: String,
    name: String,
    size: u64,
}

// Mirrored in `tauri.conf.json`'s `bundle.fileAssociations[0].ext` — that list is what
// LaunchServices registers at install/bundle time to route Finder double-click/"Open
// With"/drag-onto-dock at this app, so it has to name the same extensions this constant
// offers in the Open dialog's filter. JSON cannot carry a comment pointing back here, so
// the cross-reference lives on this side; keep the two lists in lockstep by hand.
const DB_EXTENSIONS: [&str; 7] = ["db", "sqlite", "sqlite3", "db3", "sdb", "s3db", "gpkg"];

/// What the import dialog offers. The page decides the parser by the picked name's
/// extension (`.json` is JSON, anything else CSV), so this list is also the only set
/// of formats the viewer's `parseImport` will be handed.
const IMPORT_EXTENSIONS: [&str; 2] = ["csv", "json"];

/// The largest import source the shell will read, in bytes. Mirrors upstream
/// `IMPORT_MAX_BYTES` in `src/core/bulk-import.ts` (64 MiB), whose parser refuses
/// the same size in the page — two identical gates, and this one comes first so a
/// 64 MiB + 1 file is refused from its `fstat` size before a byte of it is
/// allocated here or crosses IPC. `the_import_cap_matches_the_viewer_parser` pins
/// the two together through the synced bundle.
const IMPORT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Request header that turns `save_file_as` from an EXPORT into a SAVE AS — the one
/// difference being that a Save As destination joins the `SessionAllowlist`, so the
/// database can adopt the picked file and write it in place afterwards. Set by
/// `bridge.js`'s `saveDatabaseAs` and by nothing else; held in step with it by
/// `the_save_as_adopt_header_matches_the_bridge`.
const ADOPT_HEADER: &str = "x-adopt";
const ADOPT_HEADER_VALUE: &str = "1";

/// The label of the config-declared window. `tauri.conf.json` gives its single window
/// no explicit label, so it gets Tauri's default — and `capabilities/default.json`
/// scopes the capability set to exactly this label plus `NEW_WINDOW_LABEL_PATTERN`
/// below, so the three must not drift (`capability_covers_every_window_label` holds
/// them together).
const MAIN_WINDOW_LABEL: &str = "main";

/// Labels for windows opened at runtime by File ▸ Open in New Window: `db-<n>`,
/// from a process-monotonic counter that never reuses a number. Never reusing one
/// matters — per-window state is keyed by label, so an adopted label would hand a
/// fresh window the leftovers (a latched-shut sidecar registry, a stale ready
/// latch) of a window that is already gone.
///
/// `capabilities/default.json` must carry `<prefix>*` as a window glob. A label the
/// capability set does not cover gets NO permissions at all: `plugin:`-prefixed
/// commands (the event system this shell delivers menu items and file opens
/// through, and the dialog plugin) are ACL-checked and would be refused outright,
/// and the two `core:image:deny-from-*` entries that close the arbitrary-file-read
/// image oracle would not be attached to it either.
/// `the_capability_covers_every_window_label` is the lockstep.
const NEW_WINDOW_LABEL_PREFIX: &str = "db-";

/// New windows open at the same size the config-declared window does — mirrored
/// from `tauri.conf.json` (`new_window_defaults_mirror_the_configured_window`
/// pins them together; JSON cannot carry the cross-reference comment).
const NEW_WINDOW_URL: &str = "viewer.html";
const NEW_WINDOW_TITLE: &str = "SQLite Explorer";
const NEW_WINDOW_WIDTH: f64 = 1200.0;
const NEW_WINDOW_HEIGHT: f64 = 800.0;
const NEW_WINDOW_MIN_WIDTH: f64 = 800.0;
const NEW_WINDOW_MIN_HEIGHT: f64 = 500.0;

/// The origin Tauri serves `WebviewUrl::App` from outside `tauri dev` — mirrors
/// tauri's `tauri_protocol_url` with `useHttpsScheme` off, which no config file sets
/// (`the_navigation_pin_matches_the_served_origin` holds that).
fn served_origin() -> tauri::Url {
    let origin = if cfg!(any(windows, target_os = "android")) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    };
    tauri::Url::parse(origin).expect("static origin parses")
}

/// SECURITY: whether a top-level navigation stays on the viewer's own origin. A
/// compromised page can otherwise exfiltrate by navigating — `location`, a meta
/// refresh, or a form post put data in a URL, and CSP's `connect-src` covers none of
/// them — and a navigation would also move the page, with its IPC grant, to a
/// remote origin. Same-origin navigations (a reload, a query string) stay allowed.
///
/// `blob:` is judged by the origin it embeds: a blob the page minted itself
/// (`blob:tauri://localhost/<uuid>`, the viewer's web-mode cell download) holds
/// data that is already in the page and sends nothing anywhere. Comparison is
/// exact on scheme, host and port, so `tauri.localhost.evil.example` and a
/// different port on the same host are both refused.
fn is_app_navigation(target: &tauri::Url, allowed: &[tauri::Url]) -> bool {
    if target.scheme() == "blob" {
        return tauri::Url::parse(target.path())
            .is_ok_and(|inner| inner.scheme() != "blob" && is_app_navigation(&inner, allowed));
    }
    allowed.iter().any(|origin| {
        origin.scheme() == target.scheme()
            && origin.host_str() == target.host_str()
            && origin.port_or_known_default() == target.port_or_known_default()
    })
}

/// The origins a webview may send network requests to: the asset origin and,
/// on Windows, the IPC endpoint the bridge fetches (`connect-src` lists it). Only
/// `request_pin` consults this; `the_request_pin_admits_what_the_csp_connects_to`
/// holds it to the CSP.
// Only `request_pin` (Windows) calls these three; the tests run everywhere.
#[cfg_attr(not(windows), allow(dead_code))]
fn app_request_origins() -> Vec<tauri::Url> {
    vec![
        served_origin(),
        tauri::Url::parse("http://ipc.localhost").expect("static origin parses"),
    ]
}

/// SECURITY: whether a webview request may proceed. Web schemes must target an
/// app origin. Only schemes whose bytes come from the page itself (`data:`,
/// `blob:`, `about:`) pass. Every other scheme is refused, because "not a web
/// scheme" does not mean local: on Windows a `file://host/…` URI is a UNC path,
/// an SMB connection to that host that can also hand it the user's NTLM
/// credentials. On Windows the app's own custom protocols arrive as
/// `http://<name>.localhost`, so nothing legitimate is lost. A URI that does not
/// parse is refused.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_app_request(target: &str, allowed: &[tauri::Url]) -> bool {
    let Ok(url) = tauri::Url::parse(target) else {
        return false;
    };
    match url.scheme() {
        "http" | "https" | "ws" | "wss" => is_app_navigation(&url, allowed),
        "data" | "blob" | "about" => true,
        _ => false,
    }
}

/// `scheme://host` of a refused URL for the log. The rest is whatever the page
/// tried to smuggle out, and it does not belong in a log.
#[cfg_attr(not(windows), allow(dead_code))]
fn origin_for_log(target: &str) -> String {
    match tauri::Url::parse(target) {
        Ok(url) => format!("{}://{}", url.scheme(), url.host_str().unwrap_or("")),
        Err(_) => "an unparseable URI".into(),
    }
}

/// Installs `is_app_navigation` on EVERY webview, the config-declared window and
/// the `db-<n>` windows alike: a plugin's navigation hook runs for each webview
/// the app creates, so no window can be built without it. In a `tauri dev` build
/// the page comes from `devUrl` instead (tauri's `get_app_url`), so that origin is
/// admitted there and only there. `window.open` needs no hook — with no new-window
/// handler installed, wry refuses every new-window request on all three platforms.
///
/// On Windows the navigation hook is not enough on its own: WebView2 has already
/// sent a refused navigation's request when the cancel lands, so `request_pin`
/// also refuses foreign requests at the network layer, installed on each webview
/// as it becomes ready.
fn navigation_pin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("navigation-pin")
        .on_webview_ready(|_webview| {
            #[cfg(windows)]
            install_request_pin(&_webview);
        })
        .on_navigation(|webview, url| {
            let mut allowed = vec![served_origin()];
            if tauri::is_dev() {
                allowed.extend(webview.config().build.dev_url.clone());
            }
            let permitted = is_app_navigation(url, &allowed);
            if !permitted {
                // Origin only: the rest of a refused URL is whatever the page
                // tried to smuggle out, and it does not belong in a log.
                eprintln!(
                    "refused a navigation away from the app to {}://{}",
                    url.scheme(),
                    url.host_str().unwrap_or("")
                );
            }
            permitted
        })
        .build()
}

/// A webview without the request pin still has the navigation pin, so a failure
/// here is reported, not fatal: closing the window would leave the app unusable
/// on a WebView2 that lacks an API this needs.
#[cfg(windows)]
fn install_request_pin<R: tauri::Runtime>(webview: &tauri::Webview<R>) {
    let mut allowed = app_request_origins();
    if tauri::is_dev() {
        allowed.extend(webview.config().build.dev_url.clone());
    }
    let label = webview.label().to_string();
    let reached = webview.with_webview(move |platform| {
        if let Err(e) = request_pin::install(platform.controller(), platform.environment(), allowed) {
            eprintln!("could not install the request pin on webview {label}: {e}");
        }
    });
    if let Err(e) = reached {
        eprintln!("could not reach webview {} to install the request pin: {e}", webview.label());
    }
}

/// Source of `db-<n>` labels. Monotonic for the life of the process — see
/// `NEW_WINDOW_LABEL_PREFIX`.
static WINDOW_SEQ: AtomicU64 = AtomicU64::new(0);

fn next_window_label() -> String {
    format!(
        "{NEW_WINDOW_LABEL_PREFIX}{}",
        WINDOW_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

const ZOOM_MIN: f64 = 0.25;
const ZOOM_MAX: f64 = 3.0;
const ZOOM_DEFAULT: f64 = 1.0;
/// Multiplicative step, so a zoom-in followed by a zoom-out lands approximately back
/// where it started — `x * 1.1 / 1.1` is not exactly `x` in binary floating point.
const ZOOM_STEP: f64 = 1.1;

fn settings_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("settings.json"))
}

/// Mirrors `settings_path`, but for state the shell owns exclusively.
///
/// Zoom deliberately does *not* live in `settings.json`: that file is written wholesale
/// by the webview through `save_settings`, so a shell write and a webview write racing
/// on one file would silently drop whichever landed first.
fn window_state_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("window-state.json"))
}

/// Next zoom factor for a step. `direction` is +1 in, -1 out, anything else reset.
fn next_zoom(current: f64, direction: i8) -> f64 {
    let z = match direction {
        1 => current * ZOOM_STEP,
        -1 => current / ZOOM_STEP,
        _ => ZOOM_DEFAULT,
    };
    z.clamp(ZOOM_MIN, ZOOM_MAX)
}

fn change_zoom(app: &AppHandle, label: &str, direction: i8) -> Result<(), String> {
    if !(-1..=1).contains(&direction) {
        return Err("zoom direction must be -1, 0 or 1".into());
    }
    let window = app.get_webview_window(label).ok_or("zoom window no longer exists")?;
    let state = window_state(&app.state::<Windows>(), label);
    let zoom = next_zoom(*state.zoom.lock().unwrap(), direction);
    window.set_zoom(zoom).map_err(|e| e.to_string())?;
    *state.zoom.lock().unwrap() = zoom;
    // The last adjusted window determines the initial zoom for future windows.
    // This small shell-owned preference uses the same path as the native menu.
    save_window_state_to(&window_state_path(app)?, zoom)
}

/// Bounded UI operation, scoped to Tauri's caller identity. The page cannot name
/// another window, create a window, or choose a preference-file destination.
#[tauri::command]
fn adjust_zoom(app: AppHandle, window: tauri::Window, direction: i8) -> Result<(), String> {
    change_zoom(&app, window.label(), direction)
}

/// Infallible like `load_settings`: a corrupt or hostile state file must degrade to the
/// default zoom, never block boot. The clamp is load-bearing — the value reaches
/// `set_zoom`, and this file is as writable by a local attacker as any other.
fn load_window_state_from(path: &Path) -> f64 {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.get("zoomFactor").and_then(|z| z.as_f64()))
        .filter(|z| z.is_finite())
        .map(|z| z.clamp(ZOOM_MIN, ZOOM_MAX))
        .unwrap_or(ZOOM_DEFAULT)
}

/// Unlike loading, a failed save is surfaced: see `save_settings`.
fn save_window_state_to(path: &Path, zoom: f64) -> Result<(), String> {
    let content = serde_json::to_string_pretty(&serde_json::json!({ "zoomFactor": zoom }))
        .map_err(|e| e.to_string())?;
    write_atomically(path, content.as_bytes())
}

// SECURITY (deferred, see task-8 report): the allowlist matches on the exact path
// string captured at pick time and is not re-validated at use time. A local attacker
// who can write the containing directory can swap the file for a symlink between the
// pick and the read, and `fs::read` in `read_database_bytes` will follow it. Closing
// this means an O_NOFOLLOW open, or recording device+inode at pick time and comparing
// on every use. Deferred deliberately: needs a design decision about what to do when
// the user legitimately replaces the file underneath us (the Refresh From Disk flow).
pub(crate) fn assert_allowlisted(allowlist: &SessionAllowlist, path: &Path) -> Result<(), String> {
    let guard = allowlist.0.lock().unwrap();
    if guard.contains(path) {
        Ok(())
    } else {
        Err(format!("path not allowlisted: {}", path.display()))
    }
}

const MIB: f64 = 1024.0 * 1024.0;

/// The configured maxFileSize refusal, shared by BOTH open lanes — `read_database_bytes`
/// (checked on the open descriptor before any allocation) and `native_open`
/// (`native::admit_file`, before any spawn) — so no engine can admit a file the other
/// refused: a user-selected limit that changing engine cannot lift, which is the VS Code
/// host's rule too (its composite bundle refuses before choosing an engine). `None` and
/// `0` mean unlimited. The page transports the setting; sanitizing it is the page host's
/// job (desktop-host.js maxFileSizeBytes), the shell only compares.
pub(crate) fn assert_within_size_limit(len: u64, max_bytes: Option<u64>) -> Result<(), String> {
    match max_bytes {
        Some(max) if max > 0 && len > max => Err(format!(
            "ERR_FILE_TOO_LARGE: File size ({:.2} MB) exceeds the maximum allowed size ({:.2} MB). \
             Configure 'maxFileSize' in settings.json (0 = unlimited) to increase the limit.",
            len as f64 / MIB,
            max as f64 / MIB
        )),
        _ => Ok(()),
    }
}

/// Test-only seam for modules that cannot reach `SessionAllowlist`'s private
/// field: simulates the dialog-pick insertion so gates that reuse the
/// allowlist (native.rs layer 1) can be exercised. Never compiled into a
/// build the webview can reach.
#[cfg(test)]
pub(crate) fn allowlist_insert_for_tests(allowlist: &SessionAllowlist, path: PathBuf) {
    allowlist.0.lock().unwrap().insert(path);
}

/// The import half of `assert_allowlisted`: exact-match against the paths the import
/// dialog returned this session, nothing else — never the database session allowlist,
/// so an opened database cannot be re-read as "text" through this command any more
/// than a CSV can be opened as a database through the other one.
pub(crate) fn assert_import_allowlisted(
    allowlist: &ImportSourceAllowlist,
    path: &Path,
) -> Result<(), String> {
    let guard = allowlist.0.lock().unwrap();
    if guard.contains(path) {
        Ok(())
    } else {
        Err(format!(
            "path is not an import source picked this session: {}",
            path.display()
        ))
    }
}

/// Test-only twin of `allowlist_insert_for_tests` for the import list.
#[cfg(test)]
pub(crate) fn allowlist_import_for_tests(allowlist: &ImportSourceAllowlist, path: PathBuf) {
    allowlist.0.lock().unwrap().insert(path);
}

/// Monotonic counter mixed into temp file names so two saves in one process can
/// never pick the same temp path.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Builds the temp path used for one atomic write.
///
/// The randomness here is *not* the security control — `create_new` in
/// `write_atomically_to` is, and it fails closed no matter what an attacker
/// pre-planted. This exists so an attacker cannot park a file on one predictable
/// name and turn every future save into a permanent failure (a save-DoS on a
/// database the user cannot then persist). A non-crypto source is therefore fine.
fn temp_path_for(target: &Path) -> PathBuf {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("db");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(
        ".{}.tmp-{}-{}-{}",
        name,
        std::process::id(),
        seq,
        nanos
    ))
}

/// Atomic write: exclusive temp file in the same directory, then rename over the target.
pub fn write_atomically(target: &Path, bytes: &[u8]) -> Result<(), String> {
    write_atomically_to(target, &temp_path_for(target), bytes)
}

/// The atomic write itself, with the temp path injected so tests can plant a file
/// at the exact path we are about to use.
fn write_atomically_to(target: &Path, tmp: &Path, bytes: &[u8]) -> Result<(), String> {
    let dir = target.parent().ok_or("target has no parent directory")?;
    // `create_new` is O_CREAT|O_EXCL, which fails with EEXIST if *anything* already
    // exists at `tmp` — including a dangling or redirected symlink. This is what stops
    // an attacker with write access to this directory from planting a symlink and
    // redirecting the write onto an arbitrary file. `fs::write` would have followed it.
    let mut file = File::create_new(tmp)
        .map_err(|e| format!("could not create temp file {}: {e}", tmp.display()))?;
    // Past this point the temp file is ours, so every failure has to remove it.
    let cleanup = |e: String| -> String {
        let _ = fs::remove_file(tmp);
        e
    };
    file.write_all(bytes).map_err(|e| cleanup(e.to_string()))?;
    // Flush before the rename: otherwise a crash can leave the renamed file in place
    // but empty, which looks like a successful save of an empty database.
    file.sync_all().map_err(|e| cleanup(e.to_string()))?;
    drop(file);
    // A fresh temp file gets its mode from the umask, so without this an overwrite
    // would silently widen (or narrow) access to an existing database.
    if let Ok(meta) = fs::metadata(target) {
        let _ = fs::set_permissions(tmp, meta.permissions());
    }
    fs::rename(tmp, target).map_err(|e| cleanup(e.to_string()))?;
    // Best effort: fsync the directory so the rename itself survives a crash. Not
    // every platform or filesystem allows opening a directory for this, and a failure
    // here does not make the save wrong, so it is never fatal.
    if let Ok(dir_handle) = File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

/// Atomic MOVE of an already-written file into place: the file-shaped sibling of
/// `write_atomically`, for content that is already on disk and must not round-trip
/// through shell memory (the native export route stages it in a shell-owned 0700
/// temp directory NEXT TO `dest`, so this rename stays on one filesystem and is
/// atomic). Same guarantees as the byte path: data fsync'd before the rename, an
/// existing dest's mode preserved, a symlink at dest's final component REPLACED —
/// never followed (rename(2) does not follow newpath symlinks) — and a best-effort
/// directory fsync after.
pub(crate) fn move_atomically(source: &Path, dest: &Path) -> Result<(), String> {
    // The source must be the regular file whose write was just reported — refuse
    // symlinks and non-files. Belt-and-braces behind the 0700 temp dir (nothing else
    // can plant there), and what turns "success reply but no file" into a clear
    // error. The check-then-open gap below is attacker-unreachable inside that
    // directory; outside callers inherit the same F3-class TOCTOU residue that
    // `assert_allowlisted` documents.
    let meta = fs::symlink_metadata(source)
        .map_err(|e| format!("no file to move at {}: {e}", source.display()))?;
    if !meta.file_type().is_file() {
        return Err(format!(
            "the file at {} is not a regular file; refusing to move it",
            source.display()
        ));
    }
    // Flush the data before the rename — same rationale as `write_atomically`: a
    // crash right after the rename must not surface a torn file at dest.
    let mut options = fs::OpenOptions::new();
    options.read(true);
    // FlushFileBuffers requires a writable handle on Windows.
    #[cfg(windows)]
    options.write(true);
    let file = options.open(source)
        .map_err(|e| format!("could not open {} to sync it: {e}", source.display()))?;
    file.sync_all()
        .map_err(|e| format!("could not sync {}: {e}", source.display()))?;
    drop(file);
    // Preserve an existing dest's mode, exactly as `write_atomically` does for its
    // temp file (a fresh source otherwise carries its creator's umask-derived mode).
    if let Ok(dest_meta) = fs::metadata(dest) {
        let _ = fs::set_permissions(source, dest_meta.permissions());
    }
    fs::rename(source, dest)
        .map_err(|e| format!("could not move the file into {}: {e}", dest.display()))?;
    if let Some(dir) = dest.parent() {
        if let Ok(dir_handle) = File::open(dir) {
            let _ = dir_handle.sync_all();
        }
    }
    Ok(())
}

/// Runs one command's BLOCKING body on tokio's blocking pool and awaits it.
///
/// Every command in this shell blocks on something — a modal dialog, a
/// multi-gigabyte read or write, a process spawn plus handshake, a reap with a
/// grace period — and there are exactly three places such a body can run:
///
/// - the MAIN thread (a plain sync `#[tauri::command]` under `tauri://`).
///   Freezes every window and the menu bar, and deadlocks outright against a
///   blocking dialog, which is the F8 bug.
/// - a WORKER of tauri's shared multi-thread tokio runtime, which is what
///   `#[tauri::command(async)]` on a sync body actually gives you. The pool is
///   `available_parallelism()` deep — 12 here, fewer than the 16 sidecars ONE
///   window may open — so enough concurrent slow bodies stop every command in
///   every window from being dispatched at all.
/// - tokio's dedicated BLOCKING pool, which exists for precisely this and
///   grows threads on demand instead of competing with the scheduler.
///
/// This is the third. The only body that does not use it is `native_rpc`,
/// whose wait is genuinely unbounded and is therefore awaited rather than run
/// anywhere (see `native::rpc_awaited`).
pub(crate) async fn blocking<T, F>(body: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    match tauri::async_runtime::spawn_blocking(body).await {
        Ok(result) => result,
        // Only reachable if the body panicked or the runtime is shutting down.
        // Surfaced, never swallowed: a command that silently resolved with
        // nothing would look to the page like a successful no-op.
        Err(e) => Err(format!(
            "ERR_SHELL_TASK_FAILED: the command's worker thread did not complete: {e}"
        )),
    }
}

/// Reads an allowlisted database file, refusing anything that is not a
/// REGULAR file.
///
/// Both halves matter and they are one mechanism:
///
/// - `O_NONBLOCK` on the open. Without it, `open(2)` on a FIFO with no writer
///   blocks forever, and so does a device node waiting on carrier. There is
///   no timeout, no signal, and nothing to interrupt it — the thread is gone
///   for the life of the process. With it, the open returns immediately for
///   every file type.
/// - `fstat` on the OPEN DESCRIPTOR, not a `stat` on the path. The type check
///   then describes exactly the object being read, so the F3-class swap
///   (attacker replaces the picked file between the check and the open)
///   cannot turn a checked regular file into a FIFO afterwards.
///
/// `O_NONBLOCK` is deliberately NOT `O_NOFOLLOW`: a user who picked a symlink
/// to a database in the dialog must still be able to read it. Closing the
/// symlink half of F3 is the tracked, separate design decision.
fn regular_read_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // Permit opening directories so the descriptor type check can reject
        // them explicitly, just as it does on Unix. No directory bytes are read.
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS);
    }
    options
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let options = regular_read_options();
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!(
            "{} is not a regular file; refusing to read it",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}

/// The on-disk generation of a database file this window read into the WASM engine:
/// everything `stat` reports that an in-place write changes. The WASM engine holds a
/// SNAPSHOT of the bytes, so — unlike the native lane, whose identity pin deliberately
/// ignores size and mtime — ANY change to the file makes the snapshot stale, and writing
/// the snapshot back would silently discard whatever another writer put there. Recorded
/// by `read_database_bytes` (from the descriptor it read) and by the Save As adoption,
/// compared by `save_database` immediately before the write, re-recorded after it. Same
/// rule as the VS Code host's WASM save guard (atomicDatabaseWrite.ts `FileFingerprint`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct WasmGeneration {
    dev: u64,
    ino: u128,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl WasmGeneration {
    fn of_file(_file: &File, meta: &fs::Metadata) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Ok(Self {
                dev: meta.dev(),
                ino: meta.ino() as u128,
                len: meta.len(),
                mtime: (meta.mtime(), meta.mtime_nsec()),
                ctime: (meta.ctime(), meta.ctime_nsec()),
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            let (dev, ino) = windows_file_info::identity(_file)?;
            let ctime = windows_file_info::change_time(_file)?;
            Ok(Self { dev, ino, len: meta.len(), mtime: (meta.last_write_time() as i64, 0), ctime: (ctime, 0) })
        }
    }

    /// `stat` on the path (following symlinks, like the read that recorded it).
    pub(crate) fn of_path(path: &Path) -> Result<Self, String> {
        let file = regular_read_options().open(path).map_err(|e| e.to_string())?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        Self::of_file(&file, &meta)
    }
}

/// The sentence the page shows (desktop-host.js strips the code): both remedies are
/// named because both are real on the desktop — Export writes the intact in-memory image
/// somewhere else, Reload re-reads the file that moved on.
pub(crate) const FILE_CHANGED_SENTENCE: &str = "The database file changed on disk since it was opened or last saved. \
Your unsaved changes remain available. Use File > Export Database to save them to a different file, \
or Reload Database to open the current file.";

fn file_changed_error() -> String {
    format!("ERR_FILE_CHANGED: {FILE_CHANGED_SENTENCE}")
}

/// Reads an allowlisted DATABASE file for the WASM engine: `read_regular_file`'s open
/// discipline (`O_NONBLOCK`, `fstat` on the descriptor) plus the two things that lane
/// needs and the settings read does not — the configured `max_bytes` bound is checked
/// against the descriptor's size BEFORE the buffer exists (so the cap never means "read
/// it all, then refuse"; a file that grows past it during the read is caught by the
/// bounded read), and the descriptor's generation is returned so the caller can record
/// what the bytes describe.
fn read_regular_file_bounded(
    path: &Path,
    max_bytes: Option<u64>,
) -> Result<(Vec<u8>, WasmGeneration), String> {
    use std::io::Read;
    let options = regular_read_options();
    let file = options.open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err(format!(
            "{} is not a regular file; refusing to read it",
            path.display()
        ));
    }
    assert_within_size_limit(meta.len(), max_bytes)?;
    let generation = WasmGeneration::of_file(&file, &meta)?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    match max_bytes {
        Some(max) if max > 0 => {
            // One byte past the bound is the evidence the file grew under the read.
            file.take(max + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
            assert_within_size_limit(bytes.len() as u64, max_bytes)?;
        }
        _ => {
            (&file).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        }
    }
    Ok((bytes, generation))
}

/// Records what this window just read (or wrote) at `path`. Keyed by the canonical path,
/// like every other per-file registry here; a path that cannot be resolved any more
/// (raced by a delete) records nothing, and the next in-place save then fails closed.
fn record_generation(state: &WindowState, path: &Path, generation: Option<WasmGeneration>) {
    let Ok(canonical) = fs::canonicalize(path) else {
        return;
    };
    let mut generations = state.generations.lock().unwrap();
    match generation {
        Some(generation) => {
            generations.insert(canonical, generation);
        }
        None => {
            generations.remove(&canonical);
        }
    }
}

/// The stale-image guard of an in-place WASM save: refuses unless the file at `path` is
/// exactly the generation this window last read or wrote there. Runs in the same blocking
/// body as the write that follows it, so check and rename share one turn; the remaining
/// race between them is the deferred F3 residue, not something this adds.
fn assert_generation_current(state: &WindowState, path: &Path) -> Result<(), String> {
    let canonical = fs::canonicalize(path).map_err(|_| file_changed_error())?;
    let recorded = state.generations.lock().unwrap().get(&canonical).copied();
    let Some(recorded) = recorded else {
        // No record means this window never read the file (or the record was dropped
        // after an unverifiable write): an in-place save cannot prove it is unchanged.
        return Err(
            "ERR_FILE_CHANGED: This window has no recorded on-disk generation for the database file, \
             so an in-place save cannot prove the file is unchanged. Use Reload Database first, \
             or File > Export Database to save a copy."
                .to_string(),
        );
    };
    let current = WasmGeneration::of_path(&canonical).map_err(|_| file_changed_error())?;
    if current != recorded {
        return Err(file_changed_error());
    }
    Ok(())
}

/// Reads an import source as UTF-8 text, refusing before it allocates anything
/// larger than `cap` bytes.
///
/// Same open discipline as `read_regular_file` (`O_NONBLOCK`, `fstat` on the
/// descriptor — a FIFO or a directory planted at the picked path is refused, never
/// waited on), plus the two checks that make this a TEXT read: the size is taken
/// from the open descriptor and compared BEFORE the buffer exists, and the read is
/// bounded to `cap + 1` so a file that grows between the `fstat` and the read is
/// caught (the extra byte is the evidence) instead of silently truncated. The bytes
/// are validated as UTF-8 here, so the page never receives text the shell has not
/// checked; a CSV in another encoding is a clear refusal, not mojibake.
fn read_text_bounded(path: &Path, cap: u64) -> Result<Vec<u8>, String> {
    let options = regular_read_options();
    let file = options.open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    read_import_snapshot(file, path, meta, cap)
}

fn read_import_snapshot(mut file: File, path: &Path, meta: fs::Metadata, cap: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    if !meta.is_file() {
        return Err(format!(
            "{} is not a regular file; refusing to read it",
            path.display()
        ));
    }
    if meta.len() > cap {
        return Err(format!(
            "{} is {} bytes; the import limit is {} bytes ({} MiB). Split the file into smaller imports.",
            path.display(),
            meta.len(),
            cap,
            cap / (1024 * 1024)
        ));
    }
    let before = WasmGeneration::of_file(&file, &meta)?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    (&mut file).take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > cap {
        return Err(format!(
            "{} grew past the {} byte import limit while it was being read; retry the import",
            path.display(),
            cap
        ));
    }
    // Compare the descriptor we actually read. Reopening the path here could
    // silently follow a different symlink target or replacement file.
    let after = file.metadata().map_err(|e| e.to_string())?;
    if bytes.len() as u64 != meta.len()
        || before != WasmGeneration::of_file(&file, &after)?
    {
        return Err(format!("{} changed while reading; retry the import", path.display()));
    }
    if std::str::from_utf8(&bytes).is_err() {
        return Err(format!(
            "{} is not valid UTF-8; save it as UTF-8 and retry the import",
            path.display()
        ));
    }
    Ok(bytes)
}

// See `blocking` for why every command here is an `async fn` whose body is
// handed straight to the blocking pool.
#[tauri::command]
async fn pick_database(app: AppHandle) -> Result<Option<PickedFile>, String> {
    crate::blocking(move || {
        let picked = app
            .dialog()
            .file()
            .add_filter("SQLite Database", &DB_EXTENSIONS)
            .blocking_pick_file();
        let Some(picked) = picked else {
            return Ok(None);
        };
        let path = picked.into_path().map_err(|e| e.to_string())?;
        let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("database.db")
            .to_string();
        app.state::<SessionAllowlist>()
            .0
            .lock()
            .unwrap()
            .insert(path.clone());
        add_recent(&app, path.clone());
        // set_menu is main-thread-only on macOS, and this body runs on the blocking
        // pool — hop over rather than call it here. `add_recent` itself is just a
        // mutex update and a file write, neither of which needs the main thread, so
        // only the rebuild is deferred.
        let app_for_menu = app.clone();
        if let Err(e) = app.run_on_main_thread(move || rebuild_menu(&app_for_menu)) {
            eprintln!("could not schedule an Open Recent menu rebuild: {e}");
        }
        Ok(Some(PickedFile {
            path: path.to_string_lossy().into_owned(),
            name,
            size: meta.len(),
        }))
    })
    .await
}

/// The IMPORT pick: a native open dialog filtered to CSV/JSON. Mirrors `pick_database`
/// in shape and differs in exactly the three ways `ImportSourceAllowlist` documents —
/// the path joins the IMPORT list (read-only), never the session allowlist, and never
/// the recents. The result carries the picked path back to the page, which hands it
/// to `read_import_text` verbatim; that path is the only thing the page ever names.
#[tauri::command]
async fn pick_import_source(app: AppHandle) -> Result<Option<PickedFile>, String> {
    crate::blocking(move || {
        let picked = app
            .dialog()
            .file()
            .set_title("Choose a CSV or JSON file to import (64 MiB maximum)")
            .add_filter("CSV or JSON", &IMPORT_EXTENSIONS)
            .blocking_pick_file();
        let Some(picked) = picked else {
            return Ok(None);
        };
        let path = picked.into_path().map_err(|e| e.to_string())?;
        let meta = fs::metadata(&path).map_err(|e| e.to_string())?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("import.csv")
            .to_string();
        app.state::<ImportSourceAllowlist>()
            .0
            .lock()
            .unwrap()
            .insert(path.clone());
        Ok(Some(PickedFile {
            path: path.to_string_lossy().into_owned(),
            name,
            size: meta.len(),
        }))
    })
    .await
}

/// Reads an import source the dialog returned this session, as UTF-8 text (raw
/// bytes on the wire, decoded by `bridge.js`), at most `IMPORT_MAX_BYTES`. The
/// path is webview-supplied, so the import allowlist is the whole authority: a path
/// the import dialog never produced — including every database the user has open —
/// is refused before the filesystem is touched. On the blocking pool like every
/// other file read here (see `blocking`).
#[tauri::command]
async fn read_import_text(app: AppHandle, path: String) -> Result<tauri::ipc::Response, String> {
    let bytes = crate::blocking(move || {
        let path = PathBuf::from(path);
        assert_import_allowlisted(&app.state::<ImportSourceAllowlist>(), &path)?;
        read_text_bounded(&path, IMPORT_MAX_BYTES)
    })
    .await?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// The WASM lane's open/refresh read. `max_bytes` is the page's configured maxFileSize
/// (0/absent = unlimited), refused on the open descriptor BEFORE any allocation — the
/// same bound `native_open` applies before spawning. The generation of the descriptor
/// read is recorded for this window so `save_database` can refuse a stale write-back.
#[tauri::command]
async fn read_database_bytes(
    app: AppHandle,
    window: tauri::Window,
    path: String,
    max_bytes: Option<u64>,
) -> Result<tauri::ipc::Response, String> {
    let label = window.label().to_string();
    let state = window_state(&window.state::<Windows>(), &label);
    // Everything here — both gates included — goes to the blocking pool: the
    // cross-window guard resolves the path (`realpath`) and the read itself
    // is unbounded, and neither belongs on the main thread or on one of
    // tauri's shared runtime workers (BUG-1/BUG-2).
    let bytes = crate::blocking(move || {
        let path = PathBuf::from(path);
        assert_allowlisted(&app.state::<SessionAllowlist>(), &path)?;
        // The WASM half of the cross-window guard, and — in a build with no
        // native artifacts at all — the ONLY half. The page-side host falls
        // back to the WASM engine whenever a native open fails, INCLUDING
        // when it failed because another window already has the file, and
        // the WASM engine's save writes the whole image; an unguarded
        // fallback would hand the user exactly the silent-overwrite pair the
        // refusal was for. Same window is fine: that is a refresh, or a
        // re-open the host dedupes.
        native::hold_for_read(&app.state::<OpenFiles>(), &path, &label)?;
        let (bytes, generation) = read_regular_file_bounded(&path, max_bytes)?;
        record_generation(&state, &path, Some(generation));
        Ok(bytes)
    })
    .await?;
    Ok(tauri::ipc::Response::new(bytes))
}

/// The WASM lane's in-place save. Besides the allowlist, the write is refused
/// (`ERR_FILE_CHANGED`) unless the file is still the generation this window last read or
/// wrote there — see `WasmGeneration`. The native lane never comes here: its saves are the
/// sidecar's own COMMIT, guarded by the identity pin in native.rs.
#[tauri::command]
async fn save_database(
    app: AppHandle,
    window: tauri::Window,
    request: tauri::ipc::Request<'_>,
) -> Result<(), String> {
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err("expected raw byte body".into());
    };
    let state = window_state(&window.state::<Windows>(), window.label());
    let path = request
        .headers()
        .get("x-target-path")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing x-target-path header")?;
    let path: String = urlencoding_decode(path)?;
    let path = PathBuf::from(path);
    assert_allowlisted(&app.state::<SessionAllowlist>(), &path)?;
    // The body has to be owned to cross onto the blocking pool, and
    // `ipc::Request` only lends it. One copy of an image the page already
    // holds in full is the price of not writing gigabytes on a shared runtime
    // worker (or, before this, on the main thread with every window frozen).
    let bytes = bytes.clone();
    crate::blocking(move || {
        assert_generation_current(&state, &path)?;
        write_atomically(&path, &bytes)?;
        // The rename made a new inode at the path: what is there NOW is what this
        // window's image describes. An unverifiable post-write stat drops the record, so
        // the next save fails closed rather than trusting a stale one.
        record_generation(&state, &path, WasmGeneration::of_path(&path).ok());
        Ok(())
    })
    .await
}

#[tauri::command]
async fn save_file_as(
    app: AppHandle,
    window: tauri::Window,
    request: tauri::ipc::Request<'_>,
) -> Result<Option<String>, String> {
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err("expected raw byte body".into());
    };
    let state = window_state(&window.state::<Windows>(), window.label());
    let default_name = request
        .headers()
        .get("x-default-name")
        .and_then(|v| v.to_str().ok())
        .map(urlencoding_decode)
        .transpose()?
        .unwrap_or_else(|| "export".to_string());
    // Database and table names reach this header unsanitized, so treat the value as a
    // file name and never as a path: something like "../../.bashrc" must not be able to
    // steer where the save dialog opens or what it pre-fills.
    let default_name = Path::new(&default_name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("export")
        .to_string();
    // SAVE AS vs EXPORT. Both are this one command — same dialog, same atomic write
    // — and they differ only in whether the destination joins the session allowlist.
    //
    // Save As means "this file is now my database": the page has to be able to write
    // it in place on every later ⌘S, which is exactly the grant `pick_database` makes
    // for a file the user opened, on exactly the same basis — the path was chosen by
    // the USER in an OS dialog, never named by the webview. Without it the database
    // would adopt a path the very next save refuses, and a path-less database (the
    // boot `untitled.db`) would still have no way to reach disk.
    //
    // An EXPORT (table CSV, blob, whole-DB copy) does NOT set the header and does not
    // get the grant. Least privilege: a compromised page must not be able to silently
    // rewrite every file the user has ever exported this session.
    let adopt = request
        .headers()
        .get(ADOPT_HEADER)
        .and_then(|v| v.to_str().ok())
        == Some(ADOPT_HEADER_VALUE);
    // Owned for the same reason as `save_database`'s copy.
    let bytes = bytes.clone();
    crate::blocking(move || {
        let picked = app
            .dialog()
            .file()
            .set_file_name(&default_name)
            .blocking_save_file();
        let Some(picked) = picked else {
            return Ok(None);
        };
        let path = picked.into_path().map_err(|e| e.to_string())?;
        write_atomically(&path, &bytes)?;
        if adopt {
            app.state::<SessionAllowlist>()
                .0
                .lock()
                .unwrap()
                .insert(path.clone());
            // The adopted file is now this database's home: every later ⌘S is an in-place
            // `save_database`, whose stale-image guard needs the generation just written.
            record_generation(&state, &path, WasmGeneration::of_path(&path).ok());
        }
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
}

/// Percent-decoding without another dependency (paths travel in an HTTP header).
fn urlencoding_decode(s: &str) -> Result<String, String> {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err("truncated percent escape".into());
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).map_err(|e| e.to_string())?;
            let value = u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
            out.push(value);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|e| e.to_string())
}

/// Settings parsing is total: unreadable, non-UTF-8, malformed, or valid-but-not-an-object
/// content all yield defaults.
///
/// This has to hold because the viewer's `start()` opens with
/// `a = {...defaults, ...await bridge.loadSettings()}` — awaited, unguarded, before
/// anything else. A rejection there aborts boot and leaves a half-rendered UI, and the
/// settings file is not something a user can reasonably be asked to repair by hand.
/// `viewer-dist/` is synced upstream and cannot be patched here, so the guarantee is
/// made entirely on this side: `load_settings` returns a value, not a `Result`, so the
/// IPC promise can only ever resolve.
fn parse_settings(bytes: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(bytes);
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(value) if value.is_object() => value,
        _ => serde_json::json!({}),
    }
}

#[tauri::command]
fn load_settings(app: AppHandle) -> serde_json::Value {
    // Deliberately infallible — see `parse_settings`. Note this does not create the
    // config directory; only saving does.
    let Ok(dir) = app.path().app_config_dir() else {
        return serde_json::json!({});
    };
    // Through the regular-file gate, not a bare `fs::read`: this command IS
    // webview-reachable and it runs on the main thread, so a FIFO planted at
    // settings.json would otherwise park the whole app forever — the same
    // class as the database read, on the only other page-triggered read here.
    match read_regular_file(&dir.join("settings.json")) {
        Ok(bytes) => parse_settings(&bytes),
        Err(_) => serde_json::json!({}),
    }
}

#[tauri::command]
fn save_settings(app: AppHandle, settings: serde_json::Value) -> Result<(), String> {
    let path = settings_path(&app)?;
    let content = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    // Atomic, because a crash partway through a plain write is precisely what produces
    // the corrupt file that `parse_settings` then has to silently discard. Unlike
    // loading, a failed save is surfaced: losing a setting silently is worse than an error.
    write_atomically(&path, content.as_bytes())?;
    // The theme can also be changed from the viewer's settings modal, which never routes
    // through the menu. This write replaces settings.json wholesale, so the theme the
    // menu should now show is exactly the one in the payload we just persisted — including
    // the case where the key is absent and the effective theme falls back to "system".
    sync_theme_checkmarks(&app, theme_id_of(&settings));
    Ok(())
}

#[tauri::command]
fn set_title(window: tauri::Window, title: String) -> Result<(), String> {
    window.set_title(&title).map_err(|e| e.to_string())
}

/// The page's whole-registry push: how many of ITS window's databases have
/// unsaved changes (so the shell can answer `CloseRequested` without asking —
/// see `UnsavedState`), and WHICH files that window currently has open (so the
/// shell can refuse a second window opening one of them — see
/// `native::OpenFiles`).
///
/// One command for both because upstream raises one signal for both:
/// `notifyDatabasesChanged` runs on every registry and dirty-state transition,
/// which is exactly the set of moments either answer can change. Two commands
/// would be two IPC messages that could land out of order and disagree.
///
/// Webview-reachable, and deliberately unable to do anything but (a) change
/// what the shell asks the user before closing that one window and (b) narrow
/// or widen ITS OWN window's open set: it writes no file (the "settings.json
/// is the only webview-writable file" invariant is untouched), touches no
/// other window (`window` is Tauri's own webview identity, not an argument;
/// `sync_reported` skips every entry another window owns), and cannot force a
/// close — only ask for one. Its worst case in a compromised page is
/// under-reporting, and a page that wanted the user's edits gone could discard
/// them directly; it owns them.
///
/// `has_unsaved` and the count are pushed together and reconciled by
/// `normalise_unsaved` rather than trusted separately.
///
/// SYNC on purpose, like `viewer_ready`: `CloseRequested` is answered from the
/// value this wrote, and a sync command over `tauri://` runs on the main
/// thread in IPC order, so the last push before a ⌘W has landed before the
/// close decision is made. The path half is bounded to keep it that way — at
/// most `MAX_REPORTED_OPEN_PATHS` entries, filtered against the session
/// allowlist BEFORE any filesystem call, and `sync_reported` resolves each
/// spelling at most once per window (it caches the previous push's
/// resolutions), so a steady-state push does no I/O at all.
#[tauri::command]
fn set_unsaved_state(
    app: AppHandle,
    window: tauri::Window,
    windows: State<Windows>,
    has_unsaved: bool,
    count: u32,
    open_paths: Option<Vec<String>>,
) {
    *window_state(&windows, window.label()).unsaved.lock().unwrap() =
        normalise_unsaved(has_unsaved, count);
    #[cfg(windows)]
    windows_session::refresh(&app);
    // ABSENT, not empty: a viewer bundle that predates the open-path push
    // leaves this `None`, and treating that as "nothing is open" would
    // release holds the shell took at read time. Leaving the previous set
    // standing degrades to a stale refusal, which is the safe way to be
    // wrong. `the_viewer_bundle_pushes_its_open_paths` is what keeps the
    // shipped bundle from actually being that old.
    let Some(open_paths) = open_paths else { return };
    let reported = allowlisted_open_paths(&app.state::<SessionAllowlist>(), &open_paths);
    if let Err(e) = native::sync_reported(&app.state::<OpenFiles>(), window.label(), &reported) {
        eprintln!("open-file push from {} ignored: {e}", window.label());
    }
}

/// Narrows a page-reported open-path list to paths the user actually picked
/// this session.
///
/// Lossless for an honest page: every route that can open a file — the dialog,
/// an OS/Finder open, Open Recent, a Save As adoption — puts its path on the
/// allowlist first, and both engines refuse a path that is not on it. A
/// path-less database (the boot `untitled.db`, a dropped file) reports `null`
/// and is skipped upstream.
///
/// What it buys: a compromised page can otherwise name ANY path as "open" and
/// so deny every other window the ability to open it. This bounds that to
/// files the user already picked — which the same page could equally have
/// blocked by honestly opening them, so it takes the primitive away entirely.
fn allowlisted_open_paths(allowlist: &SessionAllowlist, reported: &[String]) -> Vec<PathBuf> {
    let guard = allowlist.0.lock().unwrap();
    reported
        .iter()
        .map(PathBuf::from)
        .filter(|path| guard.contains(path))
        .collect()
}

/// Reconciles the two values the page pushes, which can disagree.
///
/// The dangerous disagreement is "unsaved, but zero of them": read naively that
/// means never prompt, which is the silent discard this whole path exists to
/// stop. It fails closed into a prompt about one database instead. The reverse
/// (nothing unsaved, non-zero count) clears, so a stale count cannot nag forever.
fn normalise_unsaved(has_unsaved: bool, count: u32) -> UnsavedState {
    UnsavedState {
        databases: match (has_unsaved, count) {
            (false, _) => 0,
            (true, 0) => 1,
            // Clamped: the count is webview-supplied and is used only to write
            // a sentence for the user. A page reporting 4 294 967 295 is
            // either broken or hostile, and neither should produce an
            // unreadable prompt (or feed an arithmetic edge case downstream —
            // `quit_decision` no longer depends on the sum, but the clamp
            // keeps the number itself plausible).
            (true, count) => count.min(MAX_REPORTED_UNSAVED),
        },
    }
}

/// Ceiling on a page-reported unsaved count. Well above `MAX_NATIVE_SIDECARS`
/// (16 per window) and above any number of WASM tabs a human opens, so it can
/// only ever narrow a nonsense value.
const MAX_REPORTED_UNSAVED: u32 = 1_000;

/// Asks before discarding, then closes on confirm.
///
/// `destroy()` rather than `close()`: `close()` re-emits `CloseRequested`, which
/// would ask again, forever. The dialog is the NON-blocking form — this is called
/// from a main-thread event handler, and a blocking dialog there is the deadlock
/// the `(async)` commands above document. If the dialog never resolves, or the
/// callback never runs, the window simply stays open: the caller has already
/// called `prevent_close`, so every failure mode here keeps the data.
fn confirm_then_close(window: &tauri::Window, databases: u32) {
    let window = window.clone();
    // On its OWN thread, using the BLOCKING form. The non-blocking `show(cb)`
    // called from this main-thread event handler never presented anything: the
    // window stayed open (prevent_close had already run) and no dialog ever
    // appeared, so closing a window with unsaved work was a silent no-op — worse
    // than no prompt, because the user gets no way forward and may force-quit and
    // lose exactly the work this exists to protect. Only a GUI run finds that;
    // the unit tests here assert the DECISION, not that a dialog reached a screen.
    // `pick_database` already had the working shape (blocking dialog, off the main
    // thread); this now matches it. Blocking on the main thread would deadlock,
    // which is what the spawn is for.
    std::thread::spawn(move || {
        let confirmed = window
            .clone()
            .dialog()
            .message(unsaved_prompt(databases))
            .title("Unsaved Changes")
            .kind(tauri_plugin_dialog::MessageDialogKind::Warning)
            .buttons(tauri_plugin_dialog::MessageDialogButtons::OkCancelCustom(
                "Close Anyway".into(),
                "Cancel".into(),
            ))
            .blocking_show();
        if !confirmed {
            return;
        }
        if let Err(e) = window.destroy() {
            eprintln!("could not close the window after confirmation: {e}");
        }
    });
}

/// Whether an unsaved-changes quit prompt is on screen right now.
///
/// App-wide, because the question is: it is asked about EVERY window's unsaved
/// work at once, from two entry points that do not know about each other.
static QUIT_PROMPT: AtomicBool = AtomicBool::new(false);

/// The claim on that one slot. `begin` hands out at most one at a time; `Drop`
/// gives it back, so no answer path has to remember to.
///
/// Not a `Mutex`: the claim is taken on the MAIN thread and given back on the
/// dialog thread, which a lock guard cannot express, and the lock discipline in
/// this shell is that nothing is held across a dialog in the first place.
struct QuitPrompt(&'static AtomicBool);

impl QuitPrompt {
    /// `Some` for the request that gets to ask, `None` while another one is
    /// still asking. Both callers are on the main thread, so this only ever
    /// arbitrates against a claim the DIALOG thread has not released yet — but
    /// it is a compare-exchange rather than a read-then-write anyway, because
    /// "who releases it" is the half that is genuinely concurrent.
    fn begin(in_flight: &'static AtomicBool) -> Option<Self> {
        in_flight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self(in_flight))
    }
}

impl Drop for QuitPrompt {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The quit counterpart. Same discipline: ask, and exit only on confirm.
fn confirm_then_quit(app: &AppHandle, databases: u32) {
    // At most ONE question on screen, app-wide — see `QuitPrompt`. A quit
    // request that arrives while one is up is already answered by the prompt
    // that is showing, including the OS-initiated one: `crate::terminate` has
    // told AppKit to stand down before it gets here, so returning without
    // asking leaves the app alive with the question still on screen, which is
    // the right state. Reported on stderr because "⌘Q appeared to do nothing"
    // is otherwise indistinguishable from a dropped menu event.
    let Some(asking) = QuitPrompt::begin(&QUIT_PROMPT) else {
        eprintln!("quit: the unsaved-changes prompt is already open; not asking twice");
        return;
    };
    let app = app.clone();
    // Same shape, and the same reason, as `confirm_then_close`: the non-blocking
    // form presented nothing from this menu-event handler, so Quit with unsaved
    // work did nothing at all — no prompt, no exit. Verified by driving the real
    // menu: Quit on a CLEAN document exits immediately, Quit on a dirty one used
    // to hang silently; both now prompt.
    std::thread::spawn(move || {
        let confirmed = app
            .clone()
            .dialog()
            .message(unsaved_prompt(databases).replace("Close anyway?", "Quit anyway?"))
            .title("Unsaved Changes")
            .kind(tauri_plugin_dialog::MessageDialogKind::Warning)
            .buttons(tauri_plugin_dialog::MessageDialogButtons::OkCancelCustom(
                "Quit Anyway".into(),
                "Cancel".into(),
            ))
            .blocking_show();
        // The dialog has returned, so the slot is free again — on BOTH buttons,
        // and before the exit. Cancel has to leave a later ⌘Q able to ask, and
        // `app.exit(0)` is the call after which nothing on this thread is
        // guaranteed to run (`Drop` at the end of the closure would be a
        // release the process racing to die may never reach).
        drop(asking);
        if confirmed {
            // Routes through RequestExit → RunEvent::Exit, so every window's
            // sidecars are still closed on the way out.
            app.exit(0);
        }
    });
}

/// The theme ids the viewer understands, in menu order. Kept in lockstep with the
/// upstream viewer's theme list — an id the viewer does not know would render a menu
/// item that silently does nothing.
const THEME_MENU: [(&str, &str); 6] = [
    ("system", "System"),
    ("dark", "Dark"),
    ("light", "Light"),
    ("high-contrast", "High Contrast"),
    ("solarized", "Solarized"),
    ("nord", "Nord"),
];

/// Menu-id namespace shared with the viewer: `theme:<id>`.
const THEME_MENU_PREFIX: &str = "theme:";

/// Narrows any string to a known theme id, defaulting to "system".
///
/// Total by design, and the single gate every theme id passes through: the values come
/// from a user-editable, webview-written settings file and from menu-id suffixes, and
/// this result is compared against the check-item map keys. An unvalidated id would
/// match nothing and so clear *every* checkmark.
fn known_theme_id(requested: &str) -> &'static str {
    THEME_MENU
        .into_iter()
        .find(|(id, _)| *id == requested)
        .map(|(id, _)| id)
        .unwrap_or("system")
}

/// The theme id a settings object selects, defaulting anything unknown to "system".
fn theme_id_of(settings: &serde_json::Value) -> &'static str {
    match settings.get("theme").and_then(|t| t.as_str()) {
        Some(requested) => known_theme_id(requested),
        None => "system",
    }
}

/// The persisted theme, read through the same tolerant path the webview sees.
fn current_theme_from_settings(app: &AppHandle) -> &'static str {
    theme_id_of(&load_settings(app.clone()))
}

/// The View ▸ Theme check items, keyed by theme id.
type ThemeItems = HashMap<String, CheckMenuItem<tauri::Wry>>;

/// Two independent things drive the checkmarks — a click on the menu itself, and the
/// webview persisting a theme it changed from its own settings modal — so the items
/// have to be reachable from both, which means managed state.
#[derive(Default)]
pub struct ThemeMenu(Mutex<ThemeItems>);

/// What the VISIBLE Open Recent submenu shows: menu item id → the path that
/// item was built from.
type RecentItems = HashMap<String, PathBuf>;

/// The snapshot a click resolves against, replaced wholesale by `rebuild_menu`
/// together with the menu it describes.
///
/// The ids used to carry an INDEX into `RecentsStore`, and the handler indexed
/// the live store at click time. Every mutation site rebuilds the menu
/// synchronously on the main thread — except `pick_database`, which runs on the
/// blocking pool: it bumps the MRU there and only then *schedules* the rebuild.
/// In that gap the visible menu's indices were stale, so a click opened a
/// DIFFERENT database than the label named. Resolving against a snapshot taken
/// when the menu was built removes the window entirely: the id names the entry
/// the user actually saw, whatever the store has done since.
///
/// It is not a widening of the path authority either. Nothing but `build_menu`
/// writes this map, and it fills it from `RecentsStore` — so it holds exactly
/// the dialog-picked / OS-delivered paths the index scheme could reach, and an
/// id that is not in the CURRENT map resolves to nothing at all.
#[derive(Default)]
pub struct RecentMenu(Mutex<RecentItems>);

/// Everything ONE window owns exclusively.
///
/// The split is not cosmetic. What lives here is what only makes sense for a single
/// window: its native sidecar registry (a database is open in a window, and a DbId
/// issued there must never resolve anywhere else), its zoom factor, and its
/// pending-open slot plus ready latch (a Finder open is delivered to one webview,
/// and each webview registers its own listener at its own time).
///
/// What deliberately stays APP-GLOBAL is everything a second window must not be
/// able to narrow or widen: `SessionAllowlist` (layer 1 of the path authority — the
/// set of paths the user picked, additive per session; per-window allowlists would
/// not make it stronger, only make a file the user picked in one window unreadable
/// in another), `RecentsStore` (one MRU, shell-written only), `settings.json`, and
/// the theme.
pub(crate) struct WindowState {
    /// This window's sidecar registry — the whole point of Task 5. Every native
    /// command resolves it from the calling window's label, so window 2's opens,
    /// closes and page-load reaps cannot touch window 1's live databases.
    pub(crate) sidecars: native::NativeSidecar,
    /// Current webview zoom factor. Shell-owned; the webview has no command that
    /// touches it.
    zoom: Mutex<f64>,
    /// One parked OS open + the ready latch, per webview — see `PendingOpenState`.
    pending_open: Mutex<PendingOpenState>,
    /// What this window's page last reported about its unsaved work — see
    /// `UnsavedState`.
    unsaved: Mutex<UnsavedState>,
    /// The on-disk generation of every database file this window has read into the
    /// WASM engine (or adopted through Save As), by canonical path — what
    /// `save_database` compares against before writing an image back. Shell-owned:
    /// the page never sees or names a generation, it only reads and saves paths.
    generations: Mutex<HashMap<PathBuf, WasmGeneration>>,
}

/// How many of a window's open databases have unsaved changes, as last pushed by
/// its page.
///
/// PUSHED, not pulled, and that is the whole design. `WindowEvent::CloseRequested`
/// is answered synchronously — the decision to let the window go is made inside
/// that handler, on the main thread — so there is no opportunity to ask the page
/// and await a reply. (Asking would also be the deadlock this file's `(async)`
/// comments exist to prevent: the page's answer arrives over IPC, which the main
/// thread would have to be free to service.) The page therefore keeps this current
/// on every dirty-state and registry change, and the handler reads a value that is
/// already there.
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct UnsavedState {
    databases: u32,
}

/// What to do when something asks a window (or the app) to go away.
#[derive(Debug, PartialEq, Eq)]
enum CloseDecision {
    /// Nothing unsaved — proceed.
    Proceed,
    /// Ask first, naming how many databases would lose changes.
    Confirm { databases: u32 },
}

/// The close decision for one window.
///
/// Fails CLOSED by construction: the only value that yields `Proceed` is a
/// reported zero. A window whose page never pushed anything reads as the
/// `Default` — zero — which is correct, because a page that has not pushed has
/// not edited anything either; the first edit pushes before the user can reach
/// ⌘W.
fn close_decision(unsaved: UnsavedState) -> CloseDecision {
    if unsaved.databases == 0 {
        CloseDecision::Proceed
    } else {
        CloseDecision::Confirm {
            databases: unsaved.databases,
        }
    }
}

/// The same decision for QUIT, over every window: quitting with unsaved work is
/// the same loss as closing one window with it, so it asks the same question with
/// the total.
///
/// The DECISION is `any`, not the sum, and that is the whole point. Every
/// value here was pushed by a webview, so the sum is attacker-steerable: two
/// windows reporting 2^31 each used to add to exactly 2^32, which panicked
/// inside the main-thread menu handler in debug and — in the release profile
/// `tauri build` ships, where overflow checks are off — wrapped to zero and
/// quit the app with NO unsaved-changes prompt at all. Deciding on "does any
/// window report unsaved work" cannot be steered by arithmetic, and the
/// saturating total is then only the number in the sentence.
fn quit_decision(unsaved: &[UnsavedState]) -> CloseDecision {
    if !unsaved.iter().any(|state| state.databases > 0) {
        return CloseDecision::Proceed;
    }
    let databases = unsaved
        .iter()
        .fold(0u32, |total, state| total.saturating_add(state.databases));
    CloseDecision::Confirm { databases }
}

/// `quit_decision` over every live window, read from what each window's page
/// last pushed.
///
/// THE single source of truth for "may the app go away right now", and it has
/// two callers on purpose: the ⌘Q menu item, and — on macOS — the
/// `applicationShouldTerminate:` hook that answers the quits the OS starts
/// itself (`crate::terminate`). They differ only in what they do with the
/// answer (`app.exit(0)` vs. telling AppKit to stand down); a second copy of
/// the DECISION would be a second chance to get the silent-discard case wrong,
/// on the path where getting it wrong is invisible.
fn quit_decision_for(windows: &Windows) -> CloseDecision {
    let unsaved: Vec<UnsavedState> = all_window_states(windows)
        .iter()
        .map(|state| *state.unsaved.lock().unwrap())
        .collect();
    quit_decision(&unsaved)
}

/// The confirm's text. One database is not "1 databases", and the count is the
/// only thing that makes the prompt worth reading.
fn unsaved_prompt(databases: u32) -> String {
    if databases == 1 {
        "1 database has unsaved changes. Close anyway?".to_string()
    } else {
        format!("{databases} databases have unsaved changes. Close anyway?")
    }
}

impl Default for WindowState {
    fn default() -> Self {
        Self {
            sidecars: native::NativeSidecar::default(),
            zoom: Mutex::new(ZOOM_DEFAULT),
            pending_open: Mutex::new(PendingOpenState::default()),
            unsaved: Mutex::new(UnsavedState::default()),
            generations: Mutex::new(HashMap::new()),
        }
    }
}

/// Per-window state for every live window, keyed by window label, plus the two
/// pieces of app-level bookkeeping that only exist because there are several
/// windows: which one has focus, and the detached reapers a window teardown
/// spawned.
#[derive(Default)]
pub struct Windows {
    states: Mutex<HashMap<String, Arc<WindowState>>>,
    /// Label of the window that most recently took focus. Menu items act on ONE
    /// window and this is which — the macOS menu bar is shared by every window, so
    /// without this a ⌘S would be broadcast to all of them.
    focused: Mutex<Option<String>>,
    /// Sidecar reapers detached by a window close or a page reload. Tracked so app
    /// exit can wait them out: the process dying mid-reap would leave the children
    /// to their own orphan paths instead of the shell's bounded grace + force-kill.
    reapers: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

/// The state of one window, created on first use.
///
/// Creating on demand is safe because the only callers are (a) commands, whose
/// label comes from Tauri's own webview identity — a page cannot name another
/// window — and (b) shell-side handlers for a window that exists. A command that
/// somehow began after its window was destroyed would recreate an entry that only
/// app exit reaps; it still cannot reach any OTHER window's sidecars, which is the
/// property that matters here.
pub(crate) fn window_state(windows: &Windows, label: &str) -> Arc<WindowState> {
    let mut states = windows.states.lock().unwrap();
    Arc::clone(states.entry(label.to_string()).or_default())
}

/// Drops a destroyed window's state and hands it back so the caller can close its
/// databases. Callers already holding an `Arc` (an in-flight `native_rpc`, say) keep
/// theirs alive until they are done — their sidecar is latched and fanned out, so
/// they get a structured error rather than a hang.
fn forget_window(windows: &Windows, label: &str) -> Option<Arc<WindowState>> {
    windows.states.lock().unwrap().remove(label)
}

fn all_window_states(windows: &Windows) -> Vec<Arc<WindowState>> {
    windows.states.lock().unwrap().values().cloned().collect()
}

/// Remembers a detached reaper so `join_reapers` can wait it out at exit. Finished
/// handles are dropped on the way in, so the list stays the size of what is actually
/// still running rather than growing once per page load.
fn track_reaper(windows: &Windows, reaper: Option<std::thread::JoinHandle<()>>) {
    let Some(reaper) = reaper else { return };
    let mut reapers = windows.reapers.lock().unwrap();
    reapers.retain(|r| !r.is_finished());
    reapers.push(reaper);
}

/// Waits out every detached reaper. Bounded: each is one `shutdown_all` batch
/// (~one grace period), and they run concurrently with each other.
fn join_reapers(windows: &Windows) {
    let outstanding: Vec<std::thread::JoinHandle<()>> =
        std::mem::take(&mut *windows.reapers.lock().unwrap());
    for reaper in outstanding {
        if let Err(e) = reaper.join() {
            eprintln!("a sidecar reaper thread panicked: {e:?}");
        }
    }
}

/// Drain every window together, then wait for earlier detached reapers. A native
/// session must not outlive the shell and keep a user's database open.
fn finish_app_exit(app: &AppHandle) {
    let windows = app.state::<Windows>();
    let states = all_window_states(&windows);
    let registries: Vec<&native::NativeSidecar> =
        states.iter().map(|state| &state.sidecars).collect();
    native::close_all_registries(
        &registries,
        "ERR_NATIVE_SIDECAR_EXITED: the application is exiting",
    );
    join_reapers(&windows);

    #[cfg(windows)]
    {
        // Tao 0.35 emits Exit from its hidden HWND on WM_ENDSESSION, but then
        // dispatches more events into a destroyed runner. Complete Tauri's usual
        // post-Exit cleanup here and exit before returning to that runner. All
        // app exit requests use code 0; this also covers a committed OS logoff.
        // Revisit when Tauri adopts https://github.com/tauri-apps/tao/pull/1157.
        app.cleanup_before_exit();
        std::process::exit(0);
    }
}

fn note_focus(windows: &Windows, label: &str) {
    *windows.focused.lock().unwrap() = Some(label.to_string());
}

/// Which window a menu action or an OS open belongs to, given the last-focused
/// label and the labels currently alive.
///
/// Pure so it can be tested; the fallbacks are what make it deterministic. The
/// tracked label wins if that window still exists, then the main window, then the
/// lexicographically first live label — never "whatever the HashMap yields first",
/// which would send ⌘S to a different window on different runs.
fn resolve_target(tracked: Option<&str>, live: &[String]) -> Option<String> {
    if let Some(tracked) = tracked {
        if live.iter().any(|label| label == tracked) {
            return Some(tracked.to_string());
        }
    }
    if live.iter().any(|label| label == MAIN_WINDOW_LABEL) {
        return Some(MAIN_WINDOW_LABEL.to_string());
    }
    live.iter().min().cloned()
}

/// `resolve_target` against the live window list. `None` only when no window is
/// open at all, in which case there is nothing to deliver to.
fn target_window(app: &AppHandle) -> Option<String> {
    let windows = app.state::<Windows>();
    let tracked = windows.focused.lock().unwrap().clone();
    let live: Vec<String> = app.webview_windows().into_keys().collect();
    resolve_target(tracked.as_deref(), &live)
}

/// Default dimensions include neither the native frame nor reserved desktop
/// space. On a small or scaled display they can put the status bar below the
/// taskbar. Let the window manager fit those windows to its work area.
fn fit_window_to_work_area(window: &tauri::WebviewWindow) -> tauri::Result<()> {
    let Some(monitor) = window.current_monitor()? else {
        eprintln!("could not fit window {}: no monitor is available", window.label());
        return Ok(());
    };
    let outer = window.outer_size()?;
    let available = monitor.work_area().size;
    if outer.width > available.width || outer.height > available.height {
        window.maximize()?;
    }
    Ok(())
}

/// Opens another window on the same viewer, with its own webview, its own database
/// registry, and its own tabs — the browser model. Shell-driven only: there is no
/// webview-reachable command for this, and the capability set grants the page
/// neither `core:window:allow-create` nor `core:webview:allow-create-webview-window`
/// (see `MAX_NATIVE_SIDECARS`, whose per-window bound rests on that).
fn open_new_window(app: &AppHandle) {
    let label = next_window_label();
    // New windows inherit the persisted zoom as their starting point — the same
    // value the main window restores at boot — rather than starting at 1.0 and
    // ignoring a preference the user already expressed.
    let zoom = match window_state_path(app) {
        Ok(path) => load_window_state_from(&path),
        Err(_) => ZOOM_DEFAULT,
    };
    match WebviewWindowBuilder::new(app, &label, WebviewUrl::App(NEW_WINDOW_URL.into()))
        .title(NEW_WINDOW_TITLE)
        .inner_size(NEW_WINDOW_WIDTH, NEW_WINDOW_HEIGHT)
        .min_inner_size(NEW_WINDOW_MIN_WIDTH, NEW_WINDOW_MIN_HEIGHT)
        .build()
    {
        Ok(webview) => {
            #[cfg(windows)]
            if let Err(e) = windows_session::install(&webview) {
                eprintln!("could not protect the new window from session end: {e}");
                if let Err(e) = webview.destroy() {
                    eprintln!("could not destroy the unprotected window: {e}");
                }
                return;
            }
            if let Err(e) = fit_window_to_work_area(&webview) {
                eprintln!("could not fit the new window to the desktop: {e}");
            }
            *window_state(&app.state::<Windows>(), &label).zoom.lock().unwrap() = zoom;
            if let Err(e) = webview.set_zoom(zoom) {
                eprintln!("could not apply zoom {zoom} to the new window: {e}");
            }
        }
        Err(e) => {
            // No silent failures: a menu click that produced nothing looks like a
            // frozen app. Non-blocking dialog — this runs on the main thread.
            eprintln!("could not open a new window: {e}");
            app.dialog()
                .message(format!("Could not open a new window: {e}"))
                .title("New Window")
                .show(|_| {});
        }
    }
}

/// Points exactly one theme item at `active` and clears the rest.
///
/// muda already toggles the item the user clicked, so this exists mainly to *clear* the
/// previously active one — and to drive the whole group when the change came from the
/// webview instead of the menu.
fn sync_theme_checkmarks(app: &AppHandle, active: &str) {
    // Snapshot under the lock and release it before touching any item: `set_checked` hops
    // to the main thread and blocks until it lands. Holding this lock across that would
    // deadlock the moment the call arrives from a non-main thread while the main thread
    // is already inside a menu event waiting for the same lock. The items are `Arc`s, so
    // cloning them out is cheap.
    let items: Vec<(String, CheckMenuItem<tauri::Wry>)> = {
        let state = app.state::<ThemeMenu>();
        let guard = state.0.lock().unwrap();
        guard
            .iter()
            .map(|(id, item)| (id.clone(), item.clone()))
            .collect()
    };
    for (id, item) in items {
        if let Err(e) = item.set_checked(id == active) {
            eprintln!("could not update the {id} theme checkmark: {e}");
        }
    }
}

/// Applies `zoom` to ONE window's webview. Never fatal: a zoom that cannot be applied
/// is worth a line on stderr, not a dead window.
fn apply_zoom(app: &AppHandle, label: &str, zoom: f64) {
    let Some(webview) = app.get_webview_window(label) else {
        eprintln!("zoom {zoom} not applied: no webview window labelled {label}");
        return;
    };
    if let Err(e) = webview.set_zoom(zoom) {
        eprintln!("could not set zoom to {zoom}: {e}");
    }
}

/// Cap on the Open Recent list — the standard macOS "Open Recent" length, and it keeps
/// the submenu (and the linear `retain`/label-disambiguation scans over it) bounded.
const RECENTS_CAP: usize = 10;

/// Shell-owned MRU list of recently opened database paths, capped at `RECENTS_CAP`.
///
/// There is no webview-reachable command that writes this file or this state: every
/// entry traces back to a dialog pick (`pick_database`) or an OS open request (file
/// associations, Task 8) — both already-trusted paths that reach `SessionAllowlist` on
/// their own. If the webview could write `recents.json` directly, a single user click on
/// a poisoned "recent" entry would launder an arbitrary path into the read allowlist.
#[derive(Default)]
pub struct RecentsStore(Mutex<Vec<PathBuf>>);

fn recents_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("recents.json"))
}

/// Infallible like `load_settings`/`load_window_state_from`: any unusable shape — missing
/// file, corrupt bytes, wrong JSON, a non-array or non-string `files` — degrades to an
/// empty (or partial) list rather than blocking boot. Also truncated defensively on load:
/// this file is as writable by a local attacker as `settings.json` is, so a hand-edited or
/// future-format file with more than the cap must not build an oversized menu.
fn load_recents_from(path: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .and_then(|value| value.get("files").and_then(|f| f.as_array().cloned()))
        .map(|arr| {
            arr.into_iter()
                .filter_map(|v| v.as_str().map(PathBuf::from))
                .collect()
        })
        .unwrap_or_default();
    files.truncate(RECENTS_CAP);
    files
}

/// Unlike loading, a failed save is surfaced by the caller — see `persist_recents`.
fn save_recents_to(path: &Path, recents: &[PathBuf]) -> Result<(), String> {
    let files: Vec<String> = recents
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let content = serde_json::to_string_pretty(&serde_json::json!({ "files": files }))
        .map_err(|e| e.to_string())?;
    write_atomically(path, content.as_bytes())
}

/// Moves `path` to the front, first removing any earlier occurrence so re-opening a
/// database bumps it to MRU position instead of creating a duplicate entry, then caps
/// the list at `RECENTS_CAP`.
fn recents_add(recents: &mut Vec<PathBuf>, path: PathBuf) {
    recents.retain(|p| p != &path);
    recents.insert(0, path);
    recents.truncate(RECENTS_CAP);
}

/// Display label per recent entry: the basename, unless two or more entries share a
/// basename (same file name, different directories) — in which case every one of those
/// falls back to its full path so the menu never shows indistinguishable duplicates.
fn recent_labels(items: &[PathBuf]) -> Vec<String> {
    let basenames: Vec<String> = items
        .iter()
        .map(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string()
        })
        .collect();
    let mut counts: HashMap<&str, usize> = HashMap::new();
    for base in &basenames {
        *counts.entry(base.as_str()).or_insert(0) += 1;
    }
    items
        .iter()
        .zip(basenames.iter())
        .map(|(path, base)| {
            if counts.get(base.as_str()).copied().unwrap_or(0) > 1 {
                path.to_string_lossy().into_owned()
            } else {
                base.clone()
            }
        })
        .collect()
}

/// Best-effort persistence with the same "log, never block" discipline as the zoom
/// handler's `window_state_path` save: a failed recents write must not stop the menu
/// from reflecting the in-memory list, but per the no-silent-failures rule it must not be
/// silent either.
fn persist_recents(app: &AppHandle, recents: &[PathBuf]) {
    match recents_path(app) {
        Ok(path) => {
            if let Err(e) = save_recents_to(&path, recents) {
                eprintln!("recents save failed: {e}");
            }
        }
        Err(e) => eprintln!("recents save failed: {e}"),
    }
}

/// Records `path` as the most recent database and persists it. Deliberately does *not*
/// rebuild the menu — callers do that themselves: `pick_database` runs on the async
/// runtime and has to defer the menu rebuild to the main thread, while this part (a mutex
/// update and a file write, neither UI) can run immediately wherever it is called from.
/// Locks `RecentsStore` only long enough to mutate and clone it back out, so no store
/// lock is ever held across the file write below or across a caller's later `set_menu`.
fn add_recent(app: &AppHandle, path: PathBuf) {
    add_recents(app, &[path]);
}

/// Batch form of `add_recent`, for the callers that open several files at once: a
/// multi-file drag-drop, and the flush of a parked cold-start multi-selection. One
/// store lock and ONE `recents.json` write for the whole batch rather than one of each
/// per file — these run on the main thread, and `persist_recents` fsyncs. Applied in
/// order, so the LAST path of the batch ends up nearest the top of the MRU.
fn add_recents(app: &AppHandle, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    let snapshot: Vec<PathBuf> = {
        let recents = app.state::<RecentsStore>();
        let mut r = recents.0.lock().unwrap();
        for path in paths {
            recents_add(&mut r, path.clone());
        }
        r.clone()
    };
    persist_recents(app, &snapshot);
}

/// Menu-id namespace for the Open Recent entries. Each id is
/// `<prefix><token>`, with the token from `RECENT_SEQ`.
const RECENT_MENU_PREFIX: &str = "recent-";

/// Source of Open Recent menu-item tokens. Monotonic for the life of the
/// process and never reused, so an id minted for one menu generation cannot
/// collide with a different entry in a later one — the property that makes
/// "a stale click resolves to nothing" true structurally rather than by
/// arguing about which thread delivers what.
static RECENT_SEQ: AtomicU64 = AtomicU64::new(0);

fn next_recent_id() -> String {
    format!(
        "{RECENT_MENU_PREFIX}{}",
        RECENT_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// One Open Recent menu generation: `(id, label, path)` per entry, in menu
/// order. Split out of `build_menu` so the id↔path binding is testable — that
/// binding is the whole fix for the click TOCTOU, and `build_menu` itself
/// needs a live `AppHandle`.
fn recent_menu_entries(recents: &[PathBuf]) -> Vec<(String, String, PathBuf)> {
    recents
        .iter()
        .zip(recent_labels(recents))
        .map(|(path, label)| (next_recent_id(), label, path.clone()))
        .collect()
}

fn build_menu(app: &AppHandle) -> tauri::Result<(Menu<tauri::Wry>, ThemeItems, RecentItems)> {
    // `N` is a plain letter key, reachable on every layout — unlike `=`, which AppKit
    // resolved against the active layout and silently dropped (see the zoom-in
    // accelerator note below). Shift+letter is likewise layout-stable.
    let new_window = MenuItem::with_id(
        app,
        "new-window",
        "Open in New Window",
        true,
        Some("CmdOrCtrl+Shift+N"),
    )?;
    let new_window_separator = PredefinedMenuItem::separator(app)?;
    let open = MenuItem::with_id(app, "open-db", "Open Database…", true, Some("CmdOrCtrl+O"))?;

    // Open Recent submenu: one `recent-<token>` item per entry, a separator, then a
    // "Clear Menu" item that stays visible but disabled when the list is empty — the
    // standard macOS "Open Recent" shape.
    //
    // The id is an opaque per-build token, and `recent_map` records which path each
    // one was built from. Neither the id nor the map is derived from the store at
    // CLICK time — see `RecentMenu` for the TOCTOU that cost.
    let recents_snapshot: Vec<PathBuf> = app.state::<RecentsStore>().0.lock().unwrap().clone();
    let generation = recent_menu_entries(&recents_snapshot);
    let mut recent_map = RecentItems::with_capacity(generation.len());
    let mut recent_items: Vec<MenuItem<tauri::Wry>> = Vec::with_capacity(generation.len());
    for (id, label, path) in generation {
        recent_items.push(MenuItem::with_id(app, &id, label, true, None::<&str>)?);
        recent_map.insert(id, path);
    }
    let recents_separator = PredefinedMenuItem::separator(app)?;
    let clear_recents = MenuItem::with_id(
        app,
        "clear-recents",
        "Clear Menu",
        !recents_snapshot.is_empty(),
        None::<&str>,
    )?;
    let mut open_recent_items: Vec<&dyn IsMenuItem<tauri::Wry>> = recent_items
        .iter()
        .map(|item| item as &dyn IsMenuItem<tauri::Wry>)
        .collect();
    open_recent_items.push(&recents_separator);
    open_recent_items.push(&clear_recents);
    let open_recent_menu = Submenu::with_items(app, "Open Recent", true, &open_recent_items)?;

    let save = MenuItem::with_id(app, "save-db", "Save", true, Some("CmdOrCtrl+S"))?;
    // Whole-database "save a copy". Deliberately WITHOUT an accelerator: the viewer
    // owns it (it rides the default `desktop-menu` passthrough below like Open/Save/
    // Refresh), and every accelerator this app ships has to be verified by keypress
    // against the active keyboard layout — an export is not worth one. Until this
    // item existed, `exportDb` — implemented on both engines, including the native
    // out-of-band VACUUM INTO route — had no entry point at all.
    let export = MenuItem::with_id(
        app,
        "export-db",
        "Export Database…",
        true,
        None::<&str>,
    )?;
    // CSV/JSON import into an existing table. Viewer-owned end to end — the page
    // asks the shell for the file (`pick_import_source` / `read_import_text`), then
    // picks the table, maps the columns and runs the import as one undoable edit —
    // so it rides the default `desktop-menu` passthrough like Export, and like
    // Export ships without an accelerator (see the note there).
    let import = MenuItem::with_id(
        app,
        "import-data",
        "Import CSV/JSON…",
        true,
        None::<&str>,
    )?;
    let refresh = MenuItem::with_id(
        app,
        "refresh-db",
        "Refresh From Disk",
        true,
        Some("CmdOrCtrl+R"),
    )?;
    let file_menu = Submenu::with_items(
        app,
        "File",
        true,
        &[
            &new_window,
            &new_window_separator,
            &open,
            &open_recent_menu,
            &save,
            &export,
            &import,
            &PredefinedMenuItem::separator(app)?,
            &refresh,
            // Close Window lives in the Window menu; a second instance here would
            // render ⌘W but never fire (AppKit binds the equivalent to one item).
        ],
    )?;
    // Native Edit menu keeps Cut/Copy/Paste working inside the webview on macOS.
    let edit_menu = Submenu::with_items(
        app,
        "Edit",
        true,
        &[
            &PredefinedMenuItem::undo(app, None)?,
            &PredefinedMenuItem::redo(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, None)?,
            &PredefinedMenuItem::copy(app, None)?,
            &PredefinedMenuItem::paste(app, None)?,
            &PredefinedMenuItem::select_all(app, None)?,
        ],
    )?;
    // Quit is OURS, not `PredefinedMenuItem::quit`. The predefined item sends
    // AppKit's `terminate:`, which arrives in Rust as nothing a handler can
    // refuse: no per-window `CloseRequested`, no preventable
    // `RunEvent::ExitRequested`, just `RunEvent::Exit` once the teardown is
    // already under way. Quitting would discard every window's unsaved databases
    // in silence, which is the same loss ⌘W asks about. A plain menu item routed
    // through `app.exit(0)` gets the prompt AND still reaches `RunEvent::Exit`,
    // so sidecars are reaped as before, and it exits through tao's
    // `[NSApp stop:]` rather than `terminate:` — one prompt, never two.
    // `Q` is a plain letter — layout-reachable, unlike the `=` incident below.
    //
    // This item is only the half a MENU can reach. Dock ▸ Quit, an `aevt`/`quit`
    // Apple Event and logout all send `terminate:` directly; `crate::terminate`
    // adds the `applicationShouldTerminate:` tao leaves unimplemented so those
    // reach the same question.
    let quit = MenuItem::with_id(
        app,
        "quit-app",
        "Quit SQLite Explorer",
        true,
        Some("CmdOrCtrl+Q"),
    )?;
    let app_menu = Submenu::with_items(
        app,
        "SQLite Explorer",
        true,
        &[
            &PredefinedMenuItem::about(app, None, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, None)?,
            &quit,
        ],
    )?;

    // View ▸ Theme. The `theme:` prefix is the shared namespace with the viewer: the
    // shell owns the checkmark, the viewer owns applying and persisting the theme.
    let current = current_theme_from_settings(app);
    let mut theme_items: Vec<(&'static str, CheckMenuItem<tauri::Wry>)> =
        Vec::with_capacity(THEME_MENU.len());
    for (id, label) in THEME_MENU {
        theme_items.push((
            id,
            CheckMenuItem::with_id(
                app,
                format!("{THEME_MENU_PREFIX}{id}"),
                label,
                true,
                id == current,
                None::<&str>,
            )?,
        ));
    }
    let theme_refs: Vec<&dyn IsMenuItem<tauri::Wry>> = theme_items
        .iter()
        .map(|(_, item)| item as &dyn IsMenuItem<tauri::Wry>)
        .collect();
    let theme_menu = Submenu::with_items(app, "Theme", true, &theme_refs)?;

    // `K` is a plain, unmodified-by-layout letter key (unlike `=`, see the zoom-in
    // accelerator note below), so it resolves under every keyboard layout tested.
    let sql_console = MenuItem::with_id(
        app,
        "sql-console",
        "SQL Console",
        true,
        Some("CmdOrCtrl+Shift+K"),
    )?;
    let sql_console_separator = PredefinedMenuItem::separator(app)?;

    // `CmdOrCtrl+Shift+Equal`, not `CmdOrCtrl+=`. Both parse, but muda hands AppKit the
    // *character* of the key equivalent, and AppKit then resolves it against the active
    // keyboard layout. On a layout where "=" is not reachable without a modifier (an
    // Italian layout, for one), asking for "=" with a Command-only mask produced a menu
    // item bound to a character nothing types — verified dead via AXMenuItemCmdChar, and
    // silently so, because `MenuItem::with_id` drops an accelerator it cannot use.
    // Spelling it as Shift+Equal lets AppKit normalise it to the "+" key equivalent that
    // Safari and Chrome also use, which renders as ⌘+ and fires on every layout tested.
    let zoom_in = MenuItem::with_id(
        app,
        "zoom-in",
        "Zoom In",
        true,
        Some("CmdOrCtrl+Shift+Equal"),
    )?;
    let zoom_out = MenuItem::with_id(app, "zoom-out", "Zoom Out", true, Some("CmdOrCtrl+-"))?;
    let zoom_reset =
        MenuItem::with_id(app, "zoom-reset", "Actual Size", true, Some("CmdOrCtrl+0"))?;
    let view_separator = PredefinedMenuItem::separator(app)?;
    // Built as a Vec rather than a literal slice so the debug-only items can be appended
    // without a `#[cfg]` on a slice element, where the separator temporaries do not live
    // long enough. `mut` is genuinely unused in release, hence the targeted allow.
    #[cfg_attr(not(debug_assertions), allow(unused_mut))]
    let mut view_items: Vec<&dyn IsMenuItem<tauri::Wry>> = vec![
        &theme_menu,
        &view_separator,
        &sql_console,
        &sql_console_separator,
        &zoom_in,
        &zoom_out,
        &zoom_reset,
    ];
    // Devtools are compiled out of release builds entirely — the underlying
    // `open_devtools` API is itself `#[cfg(debug_assertions)]`.
    #[cfg(debug_assertions)]
    let devtools_separator = PredefinedMenuItem::separator(app)?;
    #[cfg(debug_assertions)]
    let devtools = MenuItem::with_id(
        app,
        "toggle-devtools",
        "Toggle Developer Tools",
        true,
        Some("CmdOrCtrl+Alt+I"),
    )?;
    #[cfg(debug_assertions)]
    {
        view_items.push(&devtools_separator);
        view_items.push(&devtools);
    }
    let view_menu = Submenu::with_items(app, "View", true, &view_items)?;

    let window_menu = Submenu::with_items(
        app,
        "Window",
        true,
        &[
            &PredefinedMenuItem::minimize(app, None)?,
            &PredefinedMenuItem::maximize(app, None)?,
            &PredefinedMenuItem::fullscreen(app, None)?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::close_window(app, None)?,
        ],
    )?;

    let menu = Menu::with_items(
        app,
        &[&app_menu, &file_menu, &edit_menu, &view_menu, &window_menu],
    )?;
    let theme_map = theme_items
        .into_iter()
        .map(|(id, item)| (id.to_string(), item))
        .collect();
    Ok((menu, theme_map, recent_map))
}

/// Rebuilds the menu bar from scratch and swaps it in. Called whenever the Open Recent
/// list changes so the menu reflects the new or cleared entries immediately.
///
/// Must run on the main thread: `set_menu` mutates the live menu bar, which on macOS is a
/// main-thread-only operation. Every caller here is already on the main thread (menu
/// event handlers, and the `RunEvent` callback Task 8 adds) except `pick_database`, which
/// is `(async)` and hops over explicitly with `run_on_main_thread`.
///
/// Rebuilding recreates every menu item from scratch, including the Theme
/// `CheckMenuItem`s, so the `ThemeMenu` handle map has to be re-registered here too —
/// otherwise `sync_theme_checkmarks` would keep updating handles to menu items no longer
/// attached to the visible menu. `RecentMenu` is swapped for the same reason and with
/// the same timing: it must describe the menu that is actually on screen.
fn rebuild_menu(app: &AppHandle) {
    match build_menu(app) {
        Ok((menu, theme_items, recent_items)) => {
            if let Err(e) = app.set_menu(menu) {
                // The OLD menu is still the visible one, so its id→path
                // snapshot has to stay too — installing the new map here
                // would make every visible entry unresolvable.
                eprintln!("could not rebuild the menu: {e}");
                return;
            }
            *app.state::<ThemeMenu>().0.lock().unwrap() = theme_items;
            *app.state::<RecentMenu>().0.lock().unwrap() = recent_items;
        }
        Err(e) => eprintln!("could not rebuild the menu: {e}"),
    }
}

/// The single path by which an opened database becomes visible to the rest of the app:
/// allowlists it for the webview's read/write commands, records it as the most recent
/// entry, rebuilds the menu, and tells the webview to load it.
///
/// Reused by every source of "open this path" that has already resolved to a real,
/// user-sanctioned file — the Open Recent menu here, and (Task 8) Finder file
/// associations and cold-start argv. `pick_database`'s own dialog-pick path calls
/// `add_recent` plus a main-thread-deferred `rebuild_menu` directly instead of this
/// function: it already does its own allowlist insert and already returns the file to the
/// webview as the command's result, so it does not need the `desktop-open-file` event.
///
/// `target` is a window label and is MANDATORY: an app-global broadcast would open the
/// file in every window at once. The allowlist insert and the recents bump stay
/// app-global on purpose — the user opened this file, and which window they happened to
/// open it from says nothing about where they may read it next.
fn deliver_open(app: &AppHandle, target: &str, path: PathBuf) {
    deliver_opens(app, target, &[path]);
}

/// `deliver_open` for a whole group of files, in the order the user asked for them.
///
/// The page sees exactly what it sees when the same multi-selection arrives while the app
/// is already running: one `desktop-open-file` per path, in order — so the LAST file
/// requested is the last one opened, and the one left active. What is batched is the
/// SHELL-side work: one allowlist lock, one `recents.json` write (which fsyncs) and one
/// `set_menu` for the group rather than one of each per file. That matters because the
/// caller with more than one path is `viewer_ready`, which runs on the main thread.
///
/// No lock is held across `rebuild_menu` or `emit` — `SessionAllowlist`'s guard is scoped
/// to the insert loop, and `add_recents` releases `RecentsStore`'s lock internally before
/// this function ever calls `rebuild_menu`.
fn deliver_opens(app: &AppHandle, target: &str, paths: &[PathBuf]) {
    if paths.is_empty() {
        return;
    }
    {
        let allowlist = app.state::<SessionAllowlist>();
        let mut guard = allowlist.0.lock().unwrap();
        for path in paths {
            guard.insert(path.clone());
        }
    }
    add_recents(app, paths);
    rebuild_menu(app);
    // `to_string_lossy` rather than handing `path` straight to `json!`: serde's `Path`
    // impl serializes via `to_str()` and errors (which `json!` then unwraps) on non-UTF-8
    // paths. Matches the `PickedFile.path` convention below rather than trusting every
    // path on the user's disk to be valid UTF-8.
    //
    // `emit_to` matches a listener registered for this label. bridge.js registers its
    // two listeners through `getCurrentWebviewWindow().listen`, which targets
    // `WebviewWindow { label }`; the plain `event.listen` it used before targeted
    // `Any`, which `emit_to`'s filter does NOT match (tauri 2.11.5,
    // `manager::emit_to::filter_target`). The two have to move together.
    //
    // One failed emit does not abandon the rest of the group: each path is a file the
    // user asked for, and each failure is reported on its own.
    for path in paths {
        if let Err(e) = app.emit_to(
            target,
            "desktop-open-file",
            serde_json::json!({ "path": path.to_string_lossy() }),
        ) {
            eprintln!(
                "could not deliver the open of {} to window {target}: {e}",
                path.display()
            );
        }
    }
}

/// Routes one "open this path" through the target window's ready latch: delivered now
/// if that webview's listener is live, parked for its `viewer_ready` if it is not.
///
/// Everything that opens a file into a window goes through here — the OS/Finder path
/// AND an Open Recent click — because a freshly created window is exactly the case
/// where the listener is not up yet, and an unparked delivery would land on nobody.
fn open_into_window(app: &AppHandle, target: &str, path: PathBuf) {
    let state = window_state(&app.state::<Windows>(), target);
    let admitted = admit_open(&mut state.pending_open.lock().unwrap(), path);
    match admitted {
        OpenAdmission::Deliver(path) => deliver_open(app, target, path),
        OpenAdmission::Parked => {}
        // The one case where a file the user asked for is not going to be opened.
        // Said out loud for the same reason `droppable_paths` names what it skips:
        // silently discarding the tail of a selection is indistinguishable from a
        // broken feature, and is the exact failure this park was widened to fix.
        OpenAdmission::Refused(path) => eprintln!(
            "not opening {}: {MAX_PARKED_OPENS} files are already waiting for window \
             {target}'s page to finish loading",
            path.display()
        ),
    }
}

/// Upper bound on how many files one drop may open. `MAX_NATIVE_SIDECARS` is the
/// smallest per-window database cap any engine imposes, so forwarding more than this
/// could only produce refusals from the page — while still costing an allowlist entry
/// and a `stat` each. Dropping a folder full of databases is a plausible accident;
/// this is what keeps it bounded.
const MAX_DROPPED_PATHS: usize = native::MAX_NATIVE_SIDECARS;

/// Whether a path's extension names a SQLite database, by the same list the Open
/// dialog filters on and `bundle.fileAssociations` registers with LaunchServices.
/// Lowercased first: the drop comes from a case-insensitive filesystem, where
/// `Chinook.SQLite` is the same kind of file as `chinook.sqlite`.
fn has_database_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .is_some_and(|ext| DB_EXTENSIONS.contains(&ext.as_str()))
}

/// Linux desktop files pass URLs; Windows associations pass paths. These are
/// OS launch arguments, never page-provided grants. Resolve them before the
/// ready latch so an early launch cannot lose its file-open request.
#[cfg(any(test, windows, target_os = "linux"))]
fn startup_database_paths(arguments: impl IntoIterator<Item = std::ffi::OsString>) -> Vec<PathBuf> {
    let paths: Vec<PathBuf> = arguments.into_iter().filter_map(|argument| {
        let path = if argument.to_str().is_some_and(|value| value.starts_with("file://")) {
            match tauri::Url::parse(argument.to_str().unwrap())
                .map_err(|error| error.to_string())
                .and_then(|url| url.to_file_path().map_err(|_| "not a local file URL".to_string()))
            {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("could not open launch URL {}: {error}", argument.to_string_lossy());
                    return None;
                }
            }
        } else {
            PathBuf::from(argument)
        };
        match fs::canonicalize(&path) {
            Ok(path) => Some(path),
            Err(error) => {
                eprintln!("could not open launch path {}: {error}", path.display());
                None
            }
        }
    }).collect();
    droppable_paths(&paths)
}

/// The subset of a drop worth opening: plausible databases by extension, regular
/// files only, capped at `MAX_DROPPED_PATHS`.
///
/// This is a USABILITY filter, not the security boundary — a dropped `.sqlite` that
/// is really a FIFO, a device node, or a dangling symlink still has to get past
/// `read_regular_file`'s own `is_file` check (and its `O_NONBLOCK`) before a single
/// byte is read. What it buys is that dropping a folder, a `.txt`, or a screenshot
/// on the window does nothing at all instead of allowlisting a path and handing the
/// page a file it will only fail to parse.
///
/// Every rejection says so on stderr: a drop that silently does nothing is
/// indistinguishable from a broken feature, which is exactly how this feature spent
/// a release being dead code.
fn droppable_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut keep: Vec<PathBuf> = Vec::new();
    for path in paths {
        if !has_database_extension(path) {
            eprintln!(
                "ignoring dropped file (not a database extension): {}",
                path.display()
            );
            continue;
        }
        // Follows symlinks on purpose — a symlink to a database is a database, and
        // Finder's own open does the same. Bounded work on the main thread: at most
        // `paths.len()` stats, in the same handler that already writes recents.json.
        match fs::metadata(path) {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => {
                eprintln!(
                    "ignoring dropped path (not a regular file): {}",
                    path.display()
                );
                continue;
            }
            Err(e) => {
                eprintln!("ignoring dropped path ({e}): {}", path.display());
                continue;
            }
        }
        if keep.len() == MAX_DROPPED_PATHS {
            eprintln!(
                "dropped more than {MAX_DROPPED_PATHS} databases at once; ignoring the rest, \
                 starting at {}",
                path.display()
            );
            break;
        }
        keep.push(path.clone());
    }
    keep
}

/// `deliver_open`'s sibling for a native window drag-drop: the same allowlist grant
/// and the same recents bump, for a whole batch, delivered as ONE array to ONE
/// window's page.
///
/// The path authority is the point. These paths come from the OS's drag-drop
/// handler — the user dragged those exact files onto that exact window — which is
/// the same provenance as a Finder open and gets the same treatment. The webview
/// cannot reach this route at all: there is no command behind it (the only one in
/// this whole flow is `viewer_ready`, which takes no arguments), so the page can
/// only ever RECEIVE paths the shell already observed. Tauri suppresses HTML5 file
/// drops in the webview, so this handler is the only place drop paths exist.
///
/// A separate event from `desktop-open-file` because it carries an ARRAY: the page's
/// `onDragDropPaths` handler opens them in order. If the page never registered it —
/// an older viewer-dist — `emit_to` simply reaches no listener and returns `Ok`; the
/// paths stay allowlisted and nothing else happens.
fn deliver_drop(app: &AppHandle, target: &str, paths: Vec<PathBuf>) {
    if paths.is_empty() {
        return;
    }
    {
        let allowlist = app.state::<SessionAllowlist>();
        let mut guard = allowlist.0.lock().unwrap();
        for path in &paths {
            guard.insert(path.clone());
        }
    }
    add_recents(app, &paths);
    rebuild_menu(app);
    // `to_string_lossy` for the same reason `deliver_open` uses it: serde's `Path`
    // impl panics through `json!` on a non-UTF-8 path.
    let payload: Vec<String> = paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    if let Err(e) = app.emit_to(
        target,
        "desktop-drag-drop",
        serde_json::json!({ "paths": payload }),
    ) {
        eprintln!("could not deliver the drop to window {target}: {e}");
    }
}

/// `open_into_window`'s sibling for a drop: filter first, then route through the
/// TARGET WINDOW'S ready latch.
///
/// `target` is the window the OS reported the drop on, never the focused one — a
/// drop is aimed with the pointer, so the window under it is the answer even if
/// focus is elsewhere.
fn drop_into_window(app: &AppHandle, target: &str, dropped: &[PathBuf]) {
    let paths = droppable_paths(dropped);
    if paths.is_empty() {
        return;
    }
    let state = window_state(&app.state::<Windows>(), target);
    let admitted = admit_drop(&mut state.pending_open.lock().unwrap(), paths);
    if let Some(paths) = admitted {
        deliver_drop(app, target, paths);
    }
}

/// How many OS opens may sit parked at once, across however many `Opened` events they
/// arrived on. The same bound as `MAX_DROPPED_PATHS`, for the same reason — no engine
/// takes more than `MAX_NATIVE_SIDECARS` databases in one window, so a longer queue could
/// only buy refusals from the page — and the same treatment for the overflow: refused
/// out loud, never dropped on the floor.
const MAX_PARKED_OPENS: usize = MAX_DROPPED_PATHS;

/// Cold-start/reopen race this whole module exists to close: macOS can deliver
/// `RunEvent::Opened` (Finder double-click, "Open With", drag-onto-dock/icon) before the
/// webview has finished booting far enough to have registered its `onOpenFile` listener —
/// fire the event at that point and it lands on nobody, silently losing the open. Paths
/// are parked here until `viewer_ready` reports the listener is live.
#[derive(Default)]
struct PendingOpenState {
    ready: bool,
    /// Parked OS opens, oldest first, at most `MAX_PARKED_OPENS` of them.
    ///
    /// A QUEUE, not the single slot this used to be. Finder hands a multi-selection
    /// over as several independent admits (`RunEvent::Opened`'s `urls` is a `Vec`, and
    /// macOS may split one selection across events), and on a COLD START every one of
    /// them lands before the page is ready — so a slot that kept only the newest
    /// opened exactly one of the user's five databases and said nothing about the
    /// other four. Warm, the same selection already opened all five; this is what
    /// makes the cold path agree.
    ///
    /// Bounded rather than replaced — the drop lane's opposite choice below — because
    /// each admit here is a whole separate user request, so "the newest wins" would
    /// still be discarding requested work; a drop is one gesture whose entire batch
    /// arrives in a single event, so a later drop genuinely supersedes it.
    open: Vec<PathBuf>,
    /// The same park, for a drag-drop batch. A SECOND slot rather than sharing
    /// `open`, because the two travel to the page as different events with different
    /// shapes (`desktop-open-file` per path, `desktop-drag-drop` with an array)
    /// — a single slot could not remember which one a parked entry was. They are
    /// independent: an OS open and a drop that both land mid-reload are two distinct
    /// user actions and both are honoured.
    ///
    /// A drop is normally delivered live — the user is dragging onto a window they
    /// can see, so its page is up. The window this exists for is a page RELOAD
    /// (`on_page_load`'s `Started` drops the latch), where the drop would otherwise
    /// be emitted at a torn-down listener and lost.
    dropped: Option<Vec<PathBuf>>,
}

/// What one `viewer_ready` releases. Both slots are drained under the same lock, so
/// a page that signals twice cannot re-flush either.
#[derive(Default, Debug, PartialEq, Eq)]
struct Flushed {
    /// Every parked open, oldest first; empty when there was nothing parked.
    open: Vec<PathBuf>,
    dropped: Option<Vec<PathBuf>>,
}

/// What admitting one open decided. Three outcomes rather than an `Option`, because the
/// third — a park that is already full — is a file the user asked for and will not get,
/// and the caller has to be able to name it.
#[derive(Debug, PartialEq, Eq)]
enum OpenAdmission {
    /// The window's page is live: deliver it now.
    Deliver(PathBuf),
    /// Parked for that window's next `viewer_ready`.
    Parked,
    /// Refused: `MAX_PARKED_OPENS` are already waiting. Hands the path back so the
    /// caller can say which file it is refusing.
    Refused(PathBuf),
}

/// Admits one open request: delivered immediately once ready, otherwise appended to the
/// park. A pure state transition with no I/O of its own, so callers only ever hold
/// `pending_open`'s lock for the span of this one call, never across the `deliver_open`
/// its `Deliver` result gates.
///
/// Arrival ORDER is the contract, both here and in `mark_ready`'s oldest-first drain: the
/// page opens them in the order it receives them, so the last file the user asked for is
/// the last one opened and the one left active — matching what a warm multi-selection
/// already does.
fn admit_open(state: &mut PendingOpenState, path: PathBuf) -> OpenAdmission {
    if state.ready {
        OpenAdmission::Deliver(path)
    } else if state.open.len() >= MAX_PARKED_OPENS {
        OpenAdmission::Refused(path)
    } else {
        state.open.push(path);
        OpenAdmission::Parked
    }
}

/// The same admission for a whole dropped batch, into its own slot. SINGLE-slot, unlike
/// `admit_open`'s queue — a second drop arriving while one is still parked REPLACES it
/// rather than appending, because one drop is one complete gesture: the user let go of
/// those files, then let go of these, and the later batch supersedes the earlier one.
/// That is also what keeps this park bounded no matter how long a reload takes or how
/// many times the user drops during it (`droppable_paths` caps the batch itself).
fn admit_drop(state: &mut PendingOpenState, paths: Vec<PathBuf>) -> Option<Vec<PathBuf>> {
    if state.ready {
        Some(paths)
    } else {
        state.dropped = Some(paths);
        None
    }
}

/// Flips the ready flag and hands back whatever was parked, if anything. Idempotent by
/// construction — `ready` was already `true` and both slots were already emptied by the
/// first call (`mem::take` leaves the queue empty, exactly as `Option::take` leaves the
/// drop slot `None`) — so a second `viewer_ready` invocation (there is no reason for the
/// webview to send one, but nothing here assumes it won't) cannot re-flush a path that
/// already went out.
fn mark_ready(state: &mut PendingOpenState) -> Flushed {
    state.ready = true;
    Flushed {
        open: std::mem::take(&mut state.open),
        dropped: state.dropped.take(),
    }
}

/// Drops the ready latch when a window's page goes away, so the next page has to
/// signal for itself.
///
/// This closes the reload gap the previous task deferred: the latch used to be
/// one-way, so an open arriving in the sub-second window between a reload and the new
/// page's listener registration was emitted at a torn-down listener and lost. The
/// signal it needed is `PageLoadEvent::Started` — wry's `didCommitNavigation`, which
/// fires before the new document's first script, so it can never race ahead of the
/// `viewer_ready` it is resetting.
fn mark_not_ready(state: &mut PendingOpenState) {
    state.ready = false;
}

/// Reports that the webview's `onOpenFile` listener is live, flushing EVERY Finder/
/// cold-start open that arrived before it could have been heard — a multi-selection
/// parks as many paths as it names. Deliberately **not** `(async)` like
/// the dialog commands above: a sync command invoked over the tauri:// protocol already
/// runs on the main thread, which is exactly what the `deliver_opens` call below needs —
/// it reaches `rebuild_menu`'s `set_menu`, main-thread-only on macOS. Marking this `(async)`
/// would move it onto the async runtime and reintroduce the same class of bug the dialog
/// commands' `(async)` comment exists to prevent, just in the opposite direction. Takes no
/// arguments and returns nothing the webview can act on — nothing it sends can steer which
/// path gets delivered, only whether a path already queued by an OS event gets released.
/// Reports readiness for the calling window only — `window` comes from Tauri's own
/// webview identity, so one window cannot flush another's parked open.
#[tauri::command]
fn viewer_ready(app: AppHandle, window: tauri::Window, windows: State<Windows>) {
    let label = window.label().to_string();
    let state = window_state(&windows, &label);
    let flushed = mark_ready(&mut state.pending_open.lock().unwrap());
    // Oldest first, so a cold-start multi-selection reaches the page in the order the
    // user picked it — `deliver_opens` is a no-op when nothing was parked.
    deliver_opens(&app, &label, &flushed.open);
    if let Some(paths) = flushed.dropped {
        deliver_drop(&app, &label, paths);
    }
}

pub fn run() {
    // SECURITY: `navigation_pin` keeps every webview on the viewer's own origin; see
    // `is_app_navigation` for the exfiltration channel it closes.
    //
    // SECURITY NOTE (`dangerousDisableAssetCspModification: ["style-src"]`): Tauri
    // normally rewrites the configured CSP, adding nonces for the HTML's inline
    // styles. Per the CSP spec, the PRESENCE of a hash/nonce in style-src makes
    // browsers ignore 'unsafe-inline' — which silently revoked the very allowance
    // the viewer's CodeMirror console needs for its runtime style injection
    // (autocomplete tooltip, a11y clipping). The opt-out is scoped to style-src
    // only: script-src remains Tauri-managed, hashed, and eval-free. Found live by
    // smoke step 32 (autocomplete dead, aria announcements rendering visibly).
    // SECURITY: the CSP in `tauri.conf.json` sets `base-uri`, `form-action` and
    // `frame-ancestors` to 'none' explicitly, because `default-src` covers none of
    // them — without them a <base> tag could redirect relative URLs and a form post
    // could push data out. `frame-ancestors` takes effect only from a response
    // header, never a <meta> tag. The file is strict JSON and cannot carry this
    // comment; `the_csp_sets_what_default_src_does_not_cover` holds the directives.
    let builder = tauri::Builder::default();
    // The driver can evaluate page scripts, so require BOTH an explicit debug
    // feature and a runner-selected port. Normal builds register no driver and
    // keep the same CSP, capabilities, bridge, and native file authority.
    #[cfg(all(feature = "qa-webdriver", debug_assertions))]
    let builder = match std::env::var("SQLITE_EXPLORER_QA_WEBDRIVER_PORT") {
        Ok(value) => {
            let port = value
                .parse::<std::num::NonZeroU16>()
                .expect("SQLITE_EXPLORER_QA_WEBDRIVER_PORT must be a nonzero u16");
            builder
                .append_invoke_initialization_script(include_str!("../qa-observer.js"))
                .plugin(tauri_plugin_wdio_webdriver::init_with_port(port.get()))
        }
        Err(std::env::VarError::NotPresent) => builder,
        Err(error) => panic!("Invalid QA WebDriver port: {error}"),
    };
    builder
        .plugin(navigation_pin())
        .plugin(tauri_plugin_dialog::init())
        // App-global: paths the user picked (layer 1 of the path authority), the
        // shared menu bar's theme checkmarks, and the one recents MRU. Everything
        // that belongs to a single window — its sidecar registry, its zoom, its
        // parked open — lives in `Windows`, keyed by window label.
        .manage(SessionAllowlist::default())
        .manage(ImportSourceAllowlist::default())
        .manage(ThemeMenu::default())
        .manage(RecentsStore::default())
        .manage(RecentMenu::default())
        .manage(Windows::default())
        // App-global on purpose, and the ONLY native state that is: it is the
        // only place with a view ACROSS windows, which is what "this file is
        // already open somewhere else" needs.
        .manage(OpenFiles::default())
        // Window lifecycle: who has focus, and what a close has to tear down.
        .on_window_event(|window, event| match event {
            // Which window a menu item acts on. The menu bar is shared by every
            // window on macOS, so without this ⌘S would go to all of them.
            tauri::WindowEvent::Focused(true) => {
                note_focus(&window.state::<Windows>(), window.label())
            }
            // Drag-and-drop open. The webview never sees these paths on its own —
            // Tauri installs wry's drag-drop handler and suppresses the HTML5 file
            // drop, so `DataTransfer.files` is empty in the page and the OS-reported
            // paths exist ONLY here. That is why the shell has to forward them, and
            // why forwarding them is not a widening: it is the same OS-delivered user
            // intent a Finder open carries, so it takes the same allowlist grant.
            //
            // `window` is the window the drop landed on, so the routing is exact —
            // `drop_into_window` addresses that label and no other. `Enter`/`Over`/
            // `Leave` are deliberately unhandled: only the completed `Drop` names
            // files the user actually let go of.
            //
            // This rides the WINDOW event rather than `on_webview_event` because the
            // viewer's webview fills its window (`WebviewKind::WindowContent`), which
            // is what tauri-runtime-wry routes to `SynthesizedWindowEvent::DragDrop`.
            // Enabling `tauri/unstable` would make it a `WindowChild` and move the
            // event to `on_webview_event` instead —
            // `drag_drop_rides_the_window_event` is the lockstep.
            tauri::WindowEvent::DragDrop(tauri::DragDropEvent::Drop { paths, .. }) => {
                drop_into_window(window.app_handle(), window.label(), paths)
            }
            // Unsaved work is not discarded without asking. Answered from the
            // value the page already pushed (see `UnsavedState`) — this handler
            // is synchronous and cannot await the webview. The order is
            // load-bearing: prevent FIRST, then ask. Asking first would let the
            // close proceed while the dialog is still up, which is the whole
            // bug. `confirm_then_close` re-closes with `destroy()` on confirm.
            tauri::WindowEvent::CloseRequested { api, .. } => {
                let unsaved = *window_state(&window.state::<Windows>(), window.label())
                    .unsaved
                    .lock()
                    .unwrap();
                if let CloseDecision::Confirm { databases } = close_decision(unsaved) {
                    api.prevent_close();
                    confirm_then_close(window, databases);
                }
            }
            // Closing a window closes ITS databases and nothing else. Destroyed
            // (not CloseRequested) is the point where the webview is definitively
            // gone, so no page can still be holding one of these DbIds.
            tauri::WindowEvent::Destroyed => {
                let windows = window.state::<Windows>();
                // Every file this window had open is free again — including
                // the ones only its page knew about, which is the case a
                // window that dies without a final push would otherwise
                // strand for the rest of the session. Eager rather than
                // waiting on the detached reaper below; `NativeHold::drop`
                // checks the window label, so the reaper's later drop cannot
                // take a hold the next owner has since acquired.
                native::forget_window_holds(&window.state::<OpenFiles>(), window.label());
                if let Some(state) = forget_window(&windows, window.label()) {
                    let reaper = native::close_window_registry(
                        &state.sidecars,
                        "ERR_NATIVE_SIDECAR_EXITED: the window that opened this database was closed",
                    );
                    track_reaper(&windows, reaper);
                }
                #[cfg(windows)]
                windows_session::refresh(window.app_handle());
            }
            _ => {}
        })
        // Reap sidecars orphaned by a page-generation change. Every DbId lives in the
        // page's JS heap, so a reload (⌘R, a devtools reload, a same-origin top-level
        // navigation — `navigation_pin` admits those — or a WKWebView content-process
        // restart) leaves live `tjs` processes holding rw connections to the user's
        // databases that no page can name or close again. `PageLoadEvent::Started` is
        // wry's `didCommitNavigation`, so it fires for real document loads only (a
        // same-document hash/pushState navigation does NOT reach here) and it comes
        // from the webview runtime, never from IPC — the webview cannot forge it. On
        // the first load the registry is empty and this is a no-op. Detached by
        // design: see `reap_orphaned_sidecars` — the drain is synchronous, only the
        // reaping runs off the main thread so a wedged child cannot stall the reload.
        //
        // The registry resolved here is THE RELOADING WINDOW'S OWN, which is what
        // makes a second window safe to exist at all: with the app-global registry
        // this used to reach, window 2's very first page load would have reaped
        // window 1's live sidecars and closed its databases underneath the user.
        // `a_second_windows_page_load_does_not_reap_the_first_windows_sidecars`
        // is the test that holds this.
        //
        // The same event also drops that window's ready latch: the outgoing page's
        // `desktop-open-file` listener dies with it, so the next page has to signal
        // for itself or an open arriving mid-reload would be emitted at nobody.
        .on_page_load(|webview, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Started {
                let windows = webview.state::<Windows>();
                let state = window_state(&windows, webview.window().label());
                mark_not_ready(&mut state.pending_open.lock().unwrap());
                // The outgoing page's database registry died with the
                // document, so nothing it reported as open is true any more.
                // Its sidecars are still live processes at this instant —
                // reaped just below — so their holds stay until those guards
                // drop; only the page half is cleared here.
                native::clear_page_holds(
                    &webview.state::<OpenFiles>(),
                    webview.window().label(),
                );
                let reaper = native::reap_orphaned_sidecars(
                    &state.sidecars,
                    "ERR_NATIVE_SIDECAR_EXITED: the page that opened this database was reloaded",
                );
                track_reaper(&windows, reaper);
            }
        })
        // The leading `;` is load-bearing: tauri's ipc-protocol.js template ends with
        // `})()` and no terminating semicolon, so appending an IIFE directly after it
        // parses as `(...)()(function(){...})()` — a call on `undefined` that throws and
        // aborts the rest of the init script (IPC survives, the bridge never gets defined).
        .append_invoke_initialization_script(format!(";\n{}", include_str!("../bridge.js")))
        .invoke_handler(tauri::generate_handler![
            pick_database,
            read_database_bytes,
            pick_import_source,
            read_import_text,
            save_database,
            save_file_as,
            load_settings,
            save_settings,
            set_title,
            adjust_zoom,
            set_unsaved_state,
            viewer_ready,
            native::native_available,
            native::native_open,
            native::native_rpc,
            native::native_close,
            native::native_export_database,
            native::native_export_table
        ])
        .setup(|app| {
            #[cfg(target_os = "linux")]
            if let Err(e) = linux_session::install(app.handle()) {
                eprintln!("could not install Linux session-end guard: {e}");
            }
            // Recents have to be in managed state before the first `build_menu` call
            // below: it reads `RecentsStore` directly to build the Open Recent submenu,
            // and this is the only point before that call where they can be loaded.
            let recents = match recents_path(app.handle()) {
                Ok(path) => load_recents_from(&path),
                Err(e) => {
                    eprintln!("no recents path, starting Open Recent empty: {e}");
                    Vec::new()
                }
            };
            *app.state::<RecentsStore>().0.lock().unwrap() = recents;

            let (menu, theme_items, recent_items) = build_menu(app.handle())?;
            app.set_menu(menu)?;
            *app.state::<ThemeMenu>().0.lock().unwrap() = theme_items;
            *app.state::<RecentMenu>().0.lock().unwrap() = recent_items;

            // Restore the persisted zoom. Config-declared windows are created before
            // `setup` runs, so the webview is there; if it ever is not, say so rather
            // than dropping the user's zoom without a word.
            let zoom = match window_state_path(app.handle()) {
                Ok(path) => load_window_state_from(&path),
                Err(e) => {
                    eprintln!("no window-state path, using default zoom: {e}");
                    ZOOM_DEFAULT
                }
            };
            *window_state(&app.state::<Windows>(), MAIN_WINDOW_LABEL)
                .zoom
                .lock()
                .unwrap() = zoom;
            apply_zoom(app.handle(), MAIN_WINDOW_LABEL, zoom);
            if let Some(window) = app.get_webview_window(MAIN_WINDOW_LABEL) {
                #[cfg(windows)]
                windows_session::install(&window)?;
                if let Err(e) = fit_window_to_work_area(&window) {
                    eprintln!("could not fit the main window to the desktop: {e}");
                }
            }

            app.on_menu_event(|app, event| {
                // Runs on the main thread, which is where menu mutation has to happen
                // on macOS. Anything not handled here is passed through verbatim — the
                // viewer owns open/save/refresh and theme application.
                // Which window the item acts on. Every arm below that touches a
                // window uses this rather than a hardcoded label — with several
                // windows sharing one menu bar, "the focused one" is the only
                // answer that matches what the user just clicked or typed.
                let id = event.id().0.as_str();
                match id {
                    "new-window" => open_new_window(app),
                    // Quit asks the same question ⌘W does, over every window —
                    // see the `quit` item in `build_menu` for why this is not
                    // `PredefinedMenuItem::quit`.
                    "quit-app" => match quit_decision_for(&app.state::<Windows>()) {
                        CloseDecision::Proceed => app.exit(0),
                        CloseDecision::Confirm { databases } => confirm_then_quit(app, databases),
                    },
                    "zoom-in" | "zoom-out" | "zoom-reset" => {
                        let direction = match id {
                            "zoom-in" => 1,
                            "zoom-out" => -1,
                            _ => 0,
                        };
                        let Some(label) = target_window(app) else {
                            eprintln!("zoom {id} ignored: no window is open");
                            return;
                        };
                        if let Err(e) = change_zoom(app, &label, direction) {
                            eprintln!("zoom {id} failed: {e}");
                        }
                    }
                    #[cfg(debug_assertions)]
                    "toggle-devtools" => {
                        let Some(label) = target_window(app) else { return };
                        if let Some(webview) = app.get_webview_window(&label) {
                            if webview.is_devtools_open() {
                                webview.close_devtools();
                            } else {
                                webview.open_devtools();
                            }
                        }
                    }
                    theme if theme.starts_with(THEME_MENU_PREFIX) => {
                        sync_theme_checkmarks(
                            app,
                            known_theme_id(&theme[THEME_MENU_PREFIX.len()..]),
                        );
                        // The viewer still gets the event: it, not the shell, applies
                        // and persists the theme. THE ONE deliberately app-global
                        // emit in this file (`no_app_global_emit_carries_per_window_
                        // meaning` pins that): the theme lives in the shared
                        // settings.json, so every window must repaint, not just the
                        // focused one.
                        let _ = app.emit("desktop-menu", event.id().0.clone());
                    }
                    // Open Recent and Clear Menu are entirely shell-owned — see
                    // `RecentsStore`'s doc comment — so neither arm forwards a
                    // `desktop-menu` event; the viewer has no role to play here.
                    id if id.starts_with(RECENT_MENU_PREFIX) => {
                        // Resolved against the snapshot taken when THIS menu
                        // was built, never against the live store — see
                        // `RecentMenu`. Statement-scoped guard: `open_into_
                        // window`, the dialog and `rebuild_menu` below must
                        // never run under it.
                        let path = app.state::<RecentMenu>().0.lock().unwrap().get(id).cloned();
                        let Some(path) = path else {
                            // Only reachable for an id from a menu generation
                            // that is no longer on screen (or a forged one).
                            // Doing nothing is right — the entry the user saw
                            // is gone — but it must not be silent.
                            eprintln!(
                                "Open Recent item {id} is not in the current menu; ignoring it"
                            );
                            return;
                        };
                        if path.is_file() {
                            match target_window(app) {
                                // Through the ready latch, not straight to the
                                // emit: a window created moments ago has no
                                // listener yet, and this is the one menu item
                                // that can be clicked that soon after.
                                Some(label) => open_into_window(app, &label, path),
                                None => {
                                    eprintln!("{} not opened: no window is open", path.display())
                                }
                            }
                        } else {
                            // No silent failures: a click that silently does nothing
                            // looks like a bug, not "the file moved." Tell the user,
                            // then self-heal the list so the dead entry does not sit
                            // there forever.
                            app.dialog()
                                .message(format!("{} no longer exists.", path.display()))
                                .title("File Not Found")
                                .show(|_| {});
                            let remaining: Vec<PathBuf> = {
                                let recents = app.state::<RecentsStore>();
                                let mut r = recents.0.lock().unwrap();
                                r.retain(|p| p != &path);
                                r.clone()
                            };
                            persist_recents(app, &remaining);
                            rebuild_menu(app);
                        }
                    }
                    "clear-recents" => {
                        app.state::<RecentsStore>().0.lock().unwrap().clear();
                        persist_recents(app, &[]);
                        rebuild_menu(app);
                    }
                    // Everything the viewer owns — Open, Save, Refresh, SQL Console —
                    // acts on ONE database, so it goes to ONE window. Broadcasting
                    // these would make a single ⌘S save every open window.
                    _ => match target_window(app) {
                        Some(label) => {
                            if let Err(e) =
                                app.emit_to(label.as_str(), "desktop-menu", event.id().0.clone())
                            {
                                eprintln!("could not deliver menu item {id} to {label}: {e}");
                            }
                        }
                        None => eprintln!("menu item {id} ignored: no window is open"),
                    },
                }
            });

            // The `quit-app` arm above is only the half a menu can reach. Quits
            // the OS starts — Dock ▸ Quit, an `aevt`/`quit` Apple Event, Log Out
            // / Restart / Shut Down — send `terminate:` straight past it, and
            // used to take every window's unsaved databases with them without a
            // word. This installs the `applicationShouldTerminate:` that routes
            // them through the same decision. Reported and carried on if it does
            // not install: the failure costs the question, never the quit — see
            // `terminate::install`.
            #[cfg(target_os = "macos")]
            if let Err(e) = terminate::install(app.handle()) {
                eprintln!("OS-initiated quits will not ask about unsaved changes: {e}");
            }
            #[cfg(any(windows, target_os = "linux"))]
            for path in startup_database_paths(std::env::args_os().skip(1)) {
                open_into_window(app.handle(), MAIN_WINDOW_LABEL, path);
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building SQLite Explorer")
        // `RunEvent::Opened` is how macOS delivers Finder file associations: a
        // double-click, "Open With", or drag onto the dock icon — for an already-running
        // app as well as a cold start, in which case this still fires once the event loop
        // is up. Delivered on the main thread, which is exactly what `admit_open`'s
        // `deliver_open` call needs (`rebuild_menu`'s `set_menu` is main-thread-only on
        // macOS, same constraint as everywhere else in this file). `urls` is a `Vec`
        // because Finder can hand over more than one file at once (e.g. "Open With" on a
        // multi-selection); each is admitted independently rather than only the first —
        // and on a cold start, where every one of them arrives before the page can hear
        // anything, `PendingOpenState.open` QUEUES them all instead of keeping only the
        // last (which is what made a cold multi-selection open exactly one file).
        // `to_file_path()` returns `Err(())` for anything that is not a `file://` URL —
        // skipped rather than logged or panicked on, since a non-file URL here is simply
        // not actionable, not a hostile input: every path this handler ever sees came from
        // the OS's own file-open request, never from the webview (see `viewer_ready`'s
        // doc comment — the only webview-reachable command in this flow takes no
        // arguments and cannot steer which path gets delivered).
        .run(|app, event| match event {
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Opened { urls } => {
                for url in urls {
                    if let Ok(path) = url.to_file_path() {
                        // ONE window gets the file — the focused one. Every window
                        // has its own ready latch, so the park-until-`viewer_ready`
                        // race this handler exists to close is closed per window.
                        //
                        // Falling back to the main label rather than dropping the
                        // path keeps the old unconditional park: losing an OS open
                        // silently is the exact failure this whole flow exists to
                        // prevent, and a park costs nothing if that window never
                        // arrives. (In practice it always has: config-declared
                        // windows are built before `run`, so every `Opened` — cold
                        // start included — already has one.)
                        let label = target_window(app)
                            .unwrap_or_else(|| MAIN_WINDOW_LABEL.to_string());
                        open_into_window(app, &label, path);
                    }
                }
            }
            tauri::RunEvent::Exit => finish_app_exit(app),
            _ => {}
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Per-test scratch directory. Tests run in parallel in one process, so sharing a
    /// pid-only name would let them clobber each other.
    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sqx-test-{}-{}-{}",
            std::process::id(),
            tag,
            TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn allowlist_blocks_unpicked_paths() {
        let allowlist = SessionAllowlist::default();
        assert!(assert_allowlisted(&allowlist, Path::new("/etc/passwd")).is_err());
        allowlist
            .0
            .lock()
            .unwrap()
            .insert(PathBuf::from("/tmp/ok.db"));
        assert!(assert_allowlisted(&allowlist, Path::new("/tmp/ok.db")).is_ok());
    }

    /// The drop filter is the whole trust boundary on the paths a drag delivers:
    /// everything downstream (allowlist admission, the emit) trusts that what comes
    /// out of here is a real database file the OS reported. Extension filtering and
    /// the is-a-regular-file check are therefore asserted against the real
    /// filesystem, not a stub.
    #[test]
    fn droppable_paths_keeps_only_real_database_files() {
        let dir = scratch_dir("dropfilter");
        let db = dir.join("real.db");
        let sqlite = dir.join("also.sqlite");
        let text = dir.join("notes.txt");
        let subdir = dir.join("adirectory.db"); // database EXTENSION, but a directory
        let missing = dir.join("gone.db");
        fs::write(&db, b"x").unwrap();
        fs::write(&sqlite, b"x").unwrap();
        fs::write(&text, b"x").unwrap();
        fs::create_dir(&subdir).unwrap();

        let kept = droppable_paths(&[
            db.clone(),
            sqlite.clone(),
            text.clone(),
            subdir.clone(),
            missing.clone(),
        ]);

        assert_eq!(kept, vec![db, sqlite], "only regular files with a database extension survive");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn startup_files_accept_paths_and_file_urls_before_viewer_ready() {
        let dir = scratch_dir("launch-files");
        let first = dir.join("space 東京.sqlite");
        let second = dir.join("second.DB");
        let directory = dir.join("folder.db");
        let text = dir.join("notes.txt");
        fs::write(&first, b"database").unwrap();
        fs::write(&second, b"database").unwrap();
        fs::write(&text, b"text").unwrap();
        fs::create_dir(&directory).unwrap();
        let paths = startup_database_paths([
            first.clone().into_os_string(),
            tauri::Url::from_file_path(&second).unwrap().to_string().into(),
            directory.into_os_string(),
            text.into_os_string(),
            dir.join("missing.db").into_os_string(),
            "file://[invalid".into(),
        ]);
        assert_eq!(paths, vec![fs::canonicalize(first).unwrap(), fs::canonicalize(second).unwrap()]);
        let mut pending = PendingOpenState::default();
        for path in &paths {
            assert_eq!(admit_open(&mut pending, path.clone()), OpenAdmission::Parked);
        }
        assert_eq!(mark_ready(&mut pending).open, paths);
        fs::remove_dir_all(dir).unwrap();
    }

    /// A drop lands on the window under the pointer, so it rides that window's ready
    /// latch exactly as a Finder open does — parked while the page is still booting
    /// (or mid-reload), live once it has signalled. Its own slot: a parked open and a
    /// parked drop must both survive, because they reach the page as different events.
    #[test]
    fn a_drop_parks_on_its_own_slot_and_flushes_with_the_open() {
        let mut s = PendingOpenState::default();
        assert_eq!(
            admit_drop(&mut s, vec![PathBuf::from("/d1")]),
            None,
            "not ready: the drop parks rather than firing at a dead listener"
        );
        assert_eq!(
            admit_open(&mut s, PathBuf::from("/o")),
            OpenAdmission::Parked,
            "so does an open"
        );

        // One ready signal releases BOTH slots, each in its own field.
        assert_eq!(
            mark_ready(&mut s),
            Flushed {
                open: vec![PathBuf::from("/o")],
                dropped: Some(vec![PathBuf::from("/d1")]),
            }
        );
        assert_eq!(
            mark_ready(&mut s),
            Flushed::default(),
            "idempotent: a second ready cannot re-flush what already went out"
        );

        // Ready now, so a later drop is delivered live instead of parked.
        assert_eq!(
            admit_drop(&mut s, vec![PathBuf::from("/d2")]),
            Some(vec![PathBuf::from("/d2")])
        );
    }

    /// A second drop arriving while one is still parked REPLACES it (bounded park),
    /// and a reload re-arms the latch so a drop during it cannot be lost.
    #[test]
    fn a_parked_drop_is_replaced_not_queued_and_survives_a_reload() {
        let mut s = PendingOpenState::default();
        admit_drop(&mut s, vec![PathBuf::from("/first")]);
        admit_drop(&mut s, vec![PathBuf::from("/second")]);
        assert_eq!(
            mark_ready(&mut s).dropped,
            Some(vec![PathBuf::from("/second")]),
            "newest wins; the park stays bounded however long a reload takes"
        );

        mark_not_ready(&mut s); // the page reloads
        assert_eq!(
            admit_drop(&mut s, vec![PathBuf::from("/during")]),
            None,
            "a drop during a reload parks instead of hitting a torn-down listener"
        );
        assert_eq!(mark_ready(&mut s).dropped, Some(vec![PathBuf::from("/during")]));
    }

    /// Each window's latch is its own, so a drop aimed at one window can never be
    /// flushed into another's page — the per-window routing this feature depends on.
    #[test]
    fn a_parked_drop_belongs_to_its_own_window() {
        let windows = Windows::default();
        let main = window_state(&windows, MAIN_WINDOW_LABEL);
        let other = window_state(&windows, "db-0");

        admit_drop(
            &mut main.pending_open.lock().unwrap(),
            vec![PathBuf::from("/aimed-at-main")],
        );

        assert_eq!(
            mark_ready(&mut other.pending_open.lock().unwrap()).dropped,
            None,
            "another window's ready must not flush a drop aimed elsewhere"
        );
        assert_eq!(
            mark_ready(&mut main.pending_open.lock().unwrap()).dropped,
            Some(vec![PathBuf::from("/aimed-at-main")])
        );
    }

    #[test]
    fn atomic_write_replaces_content_and_leaves_no_temp() {
        let dir = scratch_dir("replace");
        let target = dir.join("t.db");
        write_atomically(&target, b"one").unwrap();
        write_atomically(&target, b"two").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"two");
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn percent_decoding_round_trips_spaces_and_unicode() {
        assert_eq!(urlencoding_decode("a%20b").unwrap(), "a b");
        assert_eq!(urlencoding_decode("n%C3%A4me").unwrap(), "näme");
        assert_eq!(urlencoding_decode("plain").unwrap(), "plain");
    }

    /// F1: the write must fail closed when someone has planted a symlink at the exact
    /// temp path we are about to use, and must not touch what that symlink points at.
    #[cfg(unix)]
    #[test]
    fn atomic_write_refuses_to_follow_a_symlink_planted_at_the_temp_path() {
        use std::os::unix::fs::symlink;

        let dir = scratch_dir("symlink");
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"victim contents").unwrap();
        let target = dir.join("db.sqlite");
        fs::write(&target, b"original").unwrap();

        // The exact path the write is about to use, then redirected at the victim.
        let tmp = temp_path_for(&target);
        symlink(&victim, &tmp).unwrap();

        let err = write_atomically_to(&target, &tmp, b"attacker payload").unwrap_err();
        assert!(
            err.contains("could not create temp file"),
            "expected the exclusive create to fail, got: {err}"
        );
        // The whole point: the file the symlink pointed at is untouched.
        assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
        // And the write did not half-apply to the real target either.
        assert_eq!(fs::read(&target).unwrap(), b"original");
        // We must not delete what we did not create — removing the planted symlink here
        // would be us following the attacker's path in a different way.
        assert!(fs::symlink_metadata(&tmp).unwrap().file_type().is_symlink());

        fs::remove_dir_all(&dir).unwrap();
    }

    /// F4: overwriting a 0600 database must not widen it to the umask default.
    #[cfg(unix)]
    #[test]
    fn atomic_write_preserves_target_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("perms");
        let target = dir.join("secret.db");
        fs::write(&target, b"one").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

        write_atomically(&target, b"two").unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"two");
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode was changed to {mode:o}");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// The file-shaped sibling of `write_atomically` (the native export
    /// route's move): same-directory rename, an existing dest's mode
    /// preserved, no source left behind.
    #[cfg(unix)]
    #[test]
    fn atomic_move_replaces_dest_and_preserves_its_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("move-replace");
        let source = dir.join("staged");
        fs::write(&source, b"new contents").unwrap();
        let dest = dir.join("secret.db");
        fs::write(&dest, b"old").unwrap();
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o600)).unwrap();

        move_atomically(&source, &dest).unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"new contents");
        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode was changed to {mode:o}");
        assert!(!source.exists(), "the source must have been moved, not copied");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn atomic_move_creates_a_missing_dest() {
        let dir = scratch_dir("move-create");
        let source = dir.join("staged");
        fs::write(&source, b"fresh").unwrap();
        let dest = dir.join("new-file.csv");
        move_atomically(&source, &dest).unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"fresh");
        assert!(!source.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Symlink discipline, both ends: a symlink SOURCE is refused (the export
    /// must be the regular file the sidecar wrote), and a symlink planted at
    /// DEST is replaced — never followed — matching `write_atomically`'s
    /// final-component semantics (rename(2) replaces newpath symlinks).
    #[cfg(unix)]
    #[test]
    fn atomic_move_never_follows_symlinks_at_either_end() {
        use std::os::unix::fs::symlink;
        let dir = scratch_dir("move-symlink");
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"victim contents").unwrap();

        // Symlink source: refused, victim untouched, nothing at dest.
        let link_source = dir.join("staged-link");
        symlink(&victim, &link_source).unwrap();
        let dest = dir.join("out.db");
        let err = move_atomically(&link_source, &dest).unwrap_err();
        assert!(err.contains("not a regular file"), "{err}");
        assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
        assert!(!dest.exists());

        // Symlink dest: the LINK is replaced; the victim it pointed at is
        // untouched and dest becomes a regular file.
        let source = dir.join("staged");
        fs::write(&source, b"real export").unwrap();
        let link_dest = dir.join("planted.db");
        symlink(&victim, &link_dest).unwrap();
        move_atomically(&source, &link_dest).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
        let meta = fs::symlink_metadata(&link_dest).unwrap();
        assert!(meta.file_type().is_file(), "dest must now be a regular file");
        assert_eq!(fs::read(&link_dest).unwrap(), b"real export");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn percent_decoding_rejects_malformed_escapes() {
        assert!(urlencoding_decode("%").is_err());
        assert!(urlencoding_decode("%4").is_err());
        assert!(urlencoding_decode("%ZZ").is_err());
        assert!(urlencoding_decode("trailing%").is_err());
        assert!(urlencoding_decode("mid%GGdle").is_err());
        // A separator must survive decoding rather than being silently dropped.
        assert_eq!(urlencoding_decode("%2F").unwrap(), "/");
        assert_eq!(urlencoding_decode("a%2Fb").unwrap(), "a/b");
    }

    /// F6: every unusable settings file shape has to come back as defaults.
    #[test]
    fn settings_parsing_falls_back_to_defaults() {
        // Invalid UTF-8 — the case that used to propagate an error to the boot path.
        assert_eq!(parse_settings(&[0xff, 0xfe, 0x00, 0x80]), json_object());
        assert_eq!(parse_settings(b"{not json"), json_object());
        assert_eq!(parse_settings(b""), json_object());
        // Valid JSON that is not an object.
        assert_eq!(parse_settings(b"[1,2,3]"), json_object());
        assert_eq!(parse_settings(b"\"a string\""), json_object());
        assert_eq!(parse_settings(b"null"), json_object());
        // A real object still survives intact.
        assert_eq!(
            parse_settings(br#"{"defaultPageSize":100}"#),
            serde_json::json!({ "defaultPageSize": 100 })
        );
    }

    fn json_object() -> serde_json::Value {
        serde_json::json!({})
    }

    #[test]
    fn zoom_steps_and_clamps() {
        assert!((next_zoom(1.0, 1) - 1.1).abs() < 1e-9);
        assert!((next_zoom(1.0, -1) - 1.0 / 1.1).abs() < 1e-9);
        // Stepping past either end pins to the end instead of running away.
        assert_eq!(next_zoom(3.0, 1), 3.0);
        assert_eq!(next_zoom(0.25, -1), 0.25);
        // Any other direction is "reset", which is what the Actual Size item sends.
        assert_eq!(next_zoom(2.2, 0), 1.0);
    }

    #[test]
    fn window_state_round_trips() {
        let dir = scratch_dir("window-state");
        let path = dir.join("window-state.json");
        save_window_state_to(&path, 1.3).unwrap();
        assert!((load_window_state_from(&path) - 1.3).abs() < 1e-9);
        // A missing file is the first-run case, not an error.
        assert_eq!(load_window_state_from(&dir.join("missing.json")), 1.0);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The state file lives on disk next to settings.json and is as forgeable as any
    /// other local file, so every unusable shape has to degrade to the default zoom
    /// rather than block boot or hand `set_zoom` an absurd factor.
    #[test]
    fn window_state_read_tolerates_garbage() {
        let dir = scratch_dir("window-state-garbage");
        let path = dir.join("window-state.json");

        for content in [
            &b"{not json"[..],
            b"[]",
            b"null",
            b"{}",
            br#"{"zoomFactor":"big"}"#,
            br#"{"zoomFactor":null}"#,
            &[0xff, 0xfe, 0x00, 0x80],
        ] {
            fs::write(&path, content).unwrap();
            assert_eq!(
                load_window_state_from(&path),
                1.0,
                "expected default zoom for {:?}",
                String::from_utf8_lossy(content)
            );
        }

        // Out-of-range values are clamped, not rejected.
        fs::write(&path, br#"{"zoomFactor":1e9}"#).unwrap();
        assert_eq!(load_window_state_from(&path), 3.0);
        fs::write(&path, br#"{"zoomFactor":-4}"#).unwrap();
        assert_eq!(load_window_state_from(&path), 0.25);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn theme_read_tolerates_garbage() {
        assert_eq!(theme_id_of(&serde_json::json!({"theme": "nord"})), "nord");
        assert_eq!(theme_id_of(&serde_json::json!({"theme": 7})), "system");
        assert_eq!(theme_id_of(&serde_json::json!({})), "system");
        // The id is used as a menu-item lookup key, so anything off the known list
        // has to collapse to the default rather than travel any further.
        assert_eq!(
            theme_id_of(&serde_json::json!({"theme": "../evil"})),
            "system"
        );
        assert_eq!(theme_id_of(&serde_json::json!({"theme": ""})), "system");
        assert_eq!(theme_id_of(&serde_json::json!({"theme": null})), "system");
        // Every advertised theme id round-trips.
        for (id, _) in THEME_MENU {
            assert_eq!(theme_id_of(&serde_json::json!({ "theme": id })), id);
        }
    }

    /// The menu-click path validates the raw id suffix through the same gate, so an
    /// unknown `theme:<junk>` id lands on "system" instead of matching no map key and
    /// clearing every checkmark.
    #[test]
    fn unknown_theme_suffix_falls_back_to_system() {
        assert_eq!(known_theme_id("nord"), "nord");
        assert_eq!(known_theme_id("Nord"), "system");
        assert_eq!(known_theme_id(""), "system");
        assert_eq!(known_theme_id("nonesuch"), "system");
        for (id, _) in THEME_MENU {
            assert_eq!(known_theme_id(id), id);
        }
    }

    #[test]
    fn recents_mru_dedupe_cap_clear() {
        let dir = scratch_dir("recents");
        let path = dir.join("recents.json");
        let mut r = load_recents_from(&path);
        for i in 0..12 {
            recents_add(&mut r, PathBuf::from(format!("/tmp/db{i}")));
        }
        assert_eq!(r.len(), 10);
        assert_eq!(r[0], PathBuf::from("/tmp/db11")); // MRU first
        recents_add(&mut r, PathBuf::from("/tmp/db5")); // bump, not duplicate
        assert_eq!(r[0], PathBuf::from("/tmp/db5"));
        assert_eq!(r.len(), 10);
        // The brief's own comment on the line above says "not duplicate" — assert it:
        // len()==10 alone would also hold if the bump had left a second /tmp/db5 in the
        // list and truncated the tail instead of deduping.
        assert_eq!(
            r.iter()
                .filter(|p| p.as_path() == Path::new("/tmp/db5"))
                .count(),
            1
        );
        save_recents_to(&path, &r).unwrap();
        assert_eq!(load_recents_from(&path), r);
        assert_eq!(load_recents_from(&dir.join("nope.json")).len(), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG-5. The Open Recent ids used to be INDICES into `RecentsStore`, and
    /// the click handler indexed the live store. Every mutation site rebuilds
    /// the menu synchronously on the main thread — except `pick_database`,
    /// which runs on the blocking pool: it bumps the MRU there and only then
    /// SCHEDULES the rebuild. In that gap the visible menu's indices were
    /// stale, so a click opened a different database than the label named.
    #[test]
    fn a_recent_click_resolves_to_the_entry_the_user_saw() {
        let shown = vec![
            PathBuf::from("/db/alpha.db"),
            PathBuf::from("/db/beta.db"),
            PathBuf::from("/db/gamma.db"),
        ];
        let generation: RecentItems = recent_menu_entries(&shown)
            .into_iter()
            .map(|(id, _label, path)| (id, path))
            .collect();

        // The user is looking at this menu when `pick_database` bumps a new
        // file to the front off-thread. Under the old scheme every index now
        // names a different file — position 0 was alpha and is now delta.
        let mut store = shown.clone();
        recents_add(&mut store, PathBuf::from("/db/delta.db"));
        assert_eq!(store[0], PathBuf::from("/db/delta.db"), "the MRU shifted");
        assert_ne!(store[0], shown[0]);

        // The click still resolves to what the label promised, because the id
        // carries the entry rather than a position in a list that moved.
        assert_eq!(generation.len(), shown.len());
        let mut resolved: Vec<PathBuf> = generation.values().cloned().collect();
        resolved.sort();
        let mut expected = shown.clone();
        expected.sort();
        assert_eq!(resolved, expected, "every visible item still names its own file");

        // A rebuild mints a WHOLLY new generation: no id is reused, so an id
        // from a menu that is no longer on screen resolves to nothing at all
        // rather than to whatever now sits at that position.
        let rebuilt: RecentItems = recent_menu_entries(&store)
            .into_iter()
            .map(|(id, _label, path)| (id, path))
            .collect();
        for stale in generation.keys() {
            assert!(
                !rebuilt.contains_key(stale),
                "{stale} survived a rebuild; ids must never be reused"
            );
        }
        // …and every id is still in the shell's own namespace, so the
        // handler's prefix match still routes them.
        assert!(rebuilt.keys().all(|id| id.starts_with(RECENT_MENU_PREFIX)));

        // The wiring, on the source: no unit test can dispatch a menu event,
        // and the whole fix is which map the handler reads.
        let source = include_str!("lib.rs");
        let arm = source
            .split("id if id.starts_with(RECENT_MENU_PREFIX) => {")
            .nth(1)
            .expect("the Open Recent arm");
        let arm = &arm[..arm.find("\"clear-recents\"").unwrap_or(arm.len())];
        assert!(
            arm.contains("RecentMenu"),
            "the click must resolve against the menu snapshot"
        );
        assert!(
            !arm.contains("RecentsStore>().0.lock().unwrap().get("),
            "the click must not index the live store — that is BUG-5 itself"
        );
        assert!(
            !arm.contains("parse()"),
            "no index parsing may remain in the Open Recent arm"
        );
    }

    #[test]
    fn recent_labels_disambiguate_shared_basenames() {
        let items = vec![
            PathBuf::from("/a/data.db"),
            PathBuf::from("/b/data.db"),
            PathBuf::from("/c/other.db"),
        ];
        let labels = recent_labels(&items);
        assert_eq!(labels[0], "/a/data.db");
        assert_eq!(labels[1], "/b/data.db");
        assert_eq!(labels[2], "other.db");
    }

    /// Same rationale as `settings_parsing_falls_back_to_defaults` /
    /// `window_state_read_tolerates_garbage`: `recents.json` is exactly as writable by a
    /// local attacker as those two files, so every unusable shape has to degrade to a
    /// safe list rather than block boot or panic building the menu.
    #[test]
    fn recents_read_tolerates_garbage() {
        let dir = scratch_dir("recents-garbage");
        let path = dir.join("recents.json");

        for content in [
            &b"{not json"[..],
            b"[]",
            b"null",
            b"{}",
            br#"{"files":"not-an-array"}"#,
            br#"{"files":[1,2,3]}"#,
            &[0xff, 0xfe, 0x00, 0x80],
        ] {
            fs::write(&path, content).unwrap();
            assert_eq!(
                load_recents_from(&path),
                Vec::<PathBuf>::new(),
                "expected an empty list for {:?}",
                String::from_utf8_lossy(content)
            );
        }

        // A mix of valid and invalid entries keeps only the valid ones.
        fs::write(&path, br#"{"files":["/a/db","/b/db",7,null]}"#).unwrap();
        assert_eq!(
            load_recents_from(&path),
            vec![PathBuf::from("/a/db"), PathBuf::from("/b/db")]
        );

        // Oversized (hand-edited or future-format) lists are truncated, not trusted whole.
        let oversized = serde_json::json!({
            "files": (0..15).map(|i| format!("/tmp/db{i}")).collect::<Vec<_>>()
        });
        fs::write(&path, serde_json::to_vec(&oversized).unwrap()).unwrap();
        assert_eq!(load_recents_from(&path).len(), RECENTS_CAP);

        fs::remove_dir_all(&dir).unwrap();
    }

    /// The race Task 8 exists to close: `RunEvent::Opened` can arrive before the webview's
    /// `onOpenFile` listener is wired up, and losing that open silently would be worse than
    /// any queueing complexity. Parks until `mark_ready` flushes it; `mark_ready` is
    /// idempotent so a duplicate readiness signal cannot re-flush a path that already went
    /// out; once ready, admission is immediate ("live") rather than parked.
    #[test]
    fn open_parks_until_ready_then_flows() {
        let mut s = PendingOpenState::default();
        assert_eq!(admit_open(&mut s, PathBuf::from("/a")), OpenAdmission::Parked);
        assert_eq!(
            mark_ready(&mut s),
            Flushed { open: vec![PathBuf::from("/a")], dropped: None }
        ); // flush on ready
        assert_eq!(mark_ready(&mut s), Flushed::default()); // idempotent
        assert_eq!(
            admit_open(&mut s, PathBuf::from("/c")),
            OpenAdmission::Deliver(PathBuf::from("/c"))
        ); // live
    }

    /// The cold-start multi-selection bug: Finder hands over N files, every one of them
    /// lands before the page is ready, and the park used to keep only the LAST — the
    /// user asked for three databases, got one, and was told nothing. All three park,
    /// and they flush in the order they were asked for so the page opens them in that
    /// order and leaves the last one active.
    #[test]
    fn a_cold_start_multi_selection_parks_every_path_in_order() {
        let mut s = PendingOpenState::default();
        for path in ["/m1", "/m2", "/m3"] {
            assert_eq!(
                admit_open(&mut s, PathBuf::from(path)),
                OpenAdmission::Parked,
                "{path} arrived before the page was ready"
            );
        }

        assert_eq!(
            mark_ready(&mut s),
            Flushed {
                open: vec![PathBuf::from("/m1"), PathBuf::from("/m2"), PathBuf::from("/m3")],
                dropped: None,
            },
            "every path survives, oldest first"
        );
        assert_eq!(
            mark_ready(&mut s),
            Flushed::default(),
            "idempotent: a second ready cannot re-flush the batch"
        );

        // A reload re-arms the latch, and the queue starts empty again — nothing from
        // the flushed batch can come back a second time.
        mark_not_ready(&mut s);
        assert_eq!(admit_open(&mut s, PathBuf::from("/m4")), OpenAdmission::Parked);
        assert_eq!(mark_ready(&mut s).open, vec![PathBuf::from("/m4")]);
    }

    /// The park is bounded, and what it will not take it REFUSES rather than dropping:
    /// `MAX_PARKED_OPENS` is the page's own per-window database cap, so a longer queue
    /// could only buy refusals from the viewer — but the user still has to be told which
    /// files did not make it, which is what the `Refused` arm carries back to
    /// `open_into_window`'s stderr line.
    #[test]
    fn the_open_park_is_bounded_and_hands_back_what_it_refuses() {
        let mut s = PendingOpenState::default();
        for i in 0..MAX_PARKED_OPENS {
            assert_eq!(
                admit_open(&mut s, PathBuf::from(format!("/db{i}"))),
                OpenAdmission::Parked
            );
        }

        let overflow = PathBuf::from("/one-too-many");
        assert_eq!(
            admit_open(&mut s, overflow.clone()),
            OpenAdmission::Refused(overflow),
            "the path comes back so the refusal can name the file"
        );

        let flushed = mark_ready(&mut s);
        assert_eq!(flushed.open.len(), MAX_PARKED_OPENS, "the park stays bounded");
        assert_eq!(
            flushed.open.first(),
            Some(&PathBuf::from("/db0")),
            "the ones that fit are the ones asked for first, in order"
        );
    }

    // -- Separate windows: one database registry each -----------------------

    const BOUND_A: &str = "/Users/u/db/alpha.sqlite";
    const BOUND_B: &str = "/Users/u/db/beta.sqlite";

    /// A path-less envelope — the dangerous class: it names no database, so
    /// routing can only come from the DbId, which is what has to stay
    /// window-scoped.
    fn query_envelope() -> String {
        serde_json::json!({
            "channel": "rpc",
            "content": {
                "kind": "invoke",
                "messageId": "m-1",
                "targetMethod": "runQuery",
                "payload": ["SELECT 1"]
            }
        })
        .to_string()
    }

    /// THE PRECONDITION of this whole task. The page-load reaper closes every
    /// sidecar whose DbId died with the old page — correct within one window,
    /// catastrophic across windows: reaching an app-global registry, window 2's
    /// FIRST page load (i.e. simply opening it) would close every database
    /// window 1 has open, underneath the user, with no page able to notice.
    /// The registry the reaper drains must be the reloading window's own.
    #[test]
    fn a_second_windows_page_load_does_not_reap_the_first_windows_sidecars() {
        let windows = Windows::default();
        let first = window_state(&windows, MAIN_WINDOW_LABEL);
        let second = window_state(&windows, "db-0");
        let (id_1, core_1, rx_1) = native::fake_entry(&first.sidecars, BOUND_A);
        let (_id_2, core_2, _rx_2) = native::fake_entry(&second.sidecars, BOUND_B);

        // Window 2 loads its page (a fresh window, a reload — same event).
        let reaper = native::reap_orphaned_sidecars(&second.sidecars, "window 2 loaded")
            .expect("window 2 had a sidecar of its own to reap");
        reaper.join().expect("reaper thread");

        // Window 1 is untouched: its sidecar is alive, still in its registry,
        // and still answers its own id.
        assert!(!core_1.is_dead(), "window 1's sidecar was reaped by window 2");
        assert_eq!(native::open_ids(&first.sidecars).len(), 1);
        assert!(native::open_ids(&first.sidecars).contains(&id_1));
        let answered = std::thread::spawn({
            let core = Arc::clone(&core_1);
            move || {
                let raw = rx_1.recv().expect("a frame must reach window 1's sidecar");
                let env: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let reply = serde_json::json!({
                    "channel": "rpc",
                    "content": {
                        "kind": "response",
                        "messageId": env.pointer("/content/messageId").unwrap().clone(),
                        "success": true,
                        "data": { "answeredBy": core.bound_path }
                    }
                })
                .to_string();
                native::route_payload(&core, reply.into_bytes());
            }
        });
        let out = native::rpc_inner(&first.sidecars, &id_1, &query_envelope())
            .expect("window 1 still serves its own database");
        answered.join().expect("responder thread");
        assert!(out.contains(BOUND_A), "{out}");

        // …and window 2's own reap did happen, so this is not a no-op passing
        // by accident.
        assert!(core_2.is_dead(), "window 2's own sidecar was not reaped");
        assert!(native::open_ids(&second.sidecars).is_empty());

        native::close_all_inner(&first.sidecars, "test over");
    }

    /// Two windows, two registries: the same label always resolves to the same
    /// state, and a database opened in one is invisible in the other.
    #[test]
    fn each_window_gets_its_own_database_registry() {
        let windows = Windows::default();
        let first = window_state(&windows, MAIN_WINDOW_LABEL);
        let second = window_state(&windows, "db-0");
        assert!(
            !Arc::ptr_eq(&first, &second),
            "two windows must not share one state"
        );
        assert!(
            Arc::ptr_eq(&first, &window_state(&windows, MAIN_WINDOW_LABEL)),
            "the same window must resolve to the same state every time"
        );

        let (id_1, _core_1, _rx_1) = native::fake_entry(&first.sidecars, BOUND_A);
        assert_eq!(native::open_ids(&first.sidecars).len(), 1);
        assert!(
            native::open_ids(&second.sidecars).is_empty(),
            "window 2's registry must not see window 1's database"
        );
        let (id_2, _core_2, _rx_2) = native::fake_entry(&second.sidecars, BOUND_B);
        assert_eq!(native::open_ids(&second.sidecars).len(), 1);
        assert_eq!(native::open_ids(&first.sidecars).len(), 1);
        assert_ne!(id_1, id_2, "ids are process-monotonic, never per-registry");

        native::close_all_inner(&first.sidecars, "test over");
        native::close_all_inner(&second.sidecars, "test over");
    }

    /// The DbId authority has to hold ACROSS windows, not just within one: a
    /// cross-window retarget is the same class as the cross-database one — a
    /// statement executing against a connection its caller never opened. An id
    /// leaked (or guessed) from another window is simply not in this window's
    /// map, so it collapses to the same refusal as any unknown id and reaches
    /// nothing.
    #[test]
    fn a_db_id_from_one_window_never_resolves_in_another() {
        let windows = Windows::default();
        let first = window_state(&windows, MAIN_WINDOW_LABEL);
        let second = window_state(&windows, "db-0");
        let (id_1, core_1, rx_1) = native::fake_entry(&first.sidecars, BOUND_A);
        let (id_2, core_2, rx_2) = native::fake_entry(&second.sidecars, BOUND_B);

        // Window 2 presenting window 1's id: refused, and window 1's sidecar
        // never sees a byte of it. Resolution is asserted FIRST and fails fast —
        // a resolver that retargeted would leave the rpc below blocked on a
        // response nobody is going to send, wedging the suite instead of
        // failing it.
        assert!(!native::resolves(&second.sidecars, &id_1), "cross-window retarget");
        assert!(!native::resolves(&first.sidecars, &id_2), "cross-window retarget");
        let err = native::rpc_inner(&second.sidecars, &id_1, &query_envelope()).unwrap_err();
        assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{err}");
        assert!(
            rx_1.try_recv().is_err(),
            "window 1's sidecar was framed a request from window 2"
        );
        assert!(core_1.has_no_pending());
        assert!(!core_1.is_dead(), "a refusal must not disturb the target");

        // And the mirror image, so neither direction is an ordering accident.
        let err = native::rpc_inner(&first.sidecars, &id_2, &query_envelope()).unwrap_err();
        assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{err}");
        assert!(rx_2.try_recv().is_err());
        assert!(core_2.has_no_pending());

        // A close is a retarget too, and it is refused the same way: window 2
        // cannot shut down window 1's database.
        let err = native::close_inner(&second.sidecars, &id_1, "cross-window close").unwrap_err();
        assert!(err.contains("ERR_NATIVE_UNKNOWN_DB"), "{err}");
        assert!(!core_1.is_dead(), "window 1's database was closed from window 2");
        assert!(native::open_ids(&first.sidecars).contains(&id_1));

        native::close_all_inner(&first.sidecars, "test over");
        native::close_all_inner(&second.sidecars, "test over");
    }

    /// Closing a window closes ITS databases and only its: the same bounded
    /// grace + force-kill per sidecar as before, applied to one registry. The
    /// closed window's registry latches shut, so an open still inside its
    /// handshake cannot land in a window that no longer exists.
    #[test]
    fn closing_one_window_closes_only_its_own_databases() {
        let windows = Windows::default();
        let first = window_state(&windows, MAIN_WINDOW_LABEL);
        let second = window_state(&windows, "db-0");
        let (_id_1, core_1, _rx_1) = native::fake_entry(&first.sidecars, BOUND_A);
        let (id_2, core_2, rx_2) = native::fake_entry(&second.sidecars, BOUND_B);

        let closed = forget_window(&windows, MAIN_WINDOW_LABEL).expect("window 1 was tracked");
        native::close_window_registry(&closed.sidecars, "window closed")
            .expect("window 1 had a database open")
            .join()
            .expect("reaper thread");

        assert!(core_1.is_dead(), "the closed window's database stayed open");
        assert!(native::open_ids(&first.sidecars).is_empty());
        assert!(
            native::try_fake_entry(&first.sidecars, BOUND_A).is_err(),
            "a closed window's registry must be latched shut"
        );

        // Window 2 is untouched and still serving.
        assert!(!core_2.is_dead());
        assert!(native::open_ids(&second.sidecars).contains(&id_2));
        let answered = std::thread::spawn({
            let core = Arc::clone(&core_2);
            move || {
                let raw = rx_2.recv().expect("a frame must reach window 2's sidecar");
                let env: serde_json::Value = serde_json::from_slice(&raw).unwrap();
                let reply = serde_json::json!({
                    "channel": "rpc",
                    "content": {
                        "kind": "response",
                        "messageId": env.pointer("/content/messageId").unwrap().clone(),
                        "success": true,
                        "data": { "answeredBy": core.bound_path }
                    }
                })
                .to_string();
                native::route_payload(&core, reply.into_bytes());
            }
        });
        let out = native::rpc_inner(&second.sidecars, &id_2, &query_envelope())
            .expect("window 2 still serves");
        answered.join().expect("responder thread");
        assert!(out.contains(BOUND_B), "{out}");

        // The state itself is gone from the map, so nothing keeps a closed
        // window's registry alive.
        assert!(forget_window(&windows, MAIN_WINDOW_LABEL).is_none());
        assert_eq!(all_window_states(&windows).len(), 1);

        native::close_all_inner(&second.sidecars, "test over");
    }

    /// App exit still closes EVERY window's sidecars — one parallel batch across
    /// all of them, so the quit cost stays ~one grace period however many
    /// windows are open, and every registry is latched on the way out.
    #[cfg(unix)]
    #[test]
    fn app_exit_closes_every_windows_databases() {
        let windows = Windows::default();
        let states: Vec<Arc<WindowState>> = ["main", "db-0", "db-1"]
            .iter()
            .map(|label| window_state(&windows, label))
            .collect();
        let cores: Vec<_> = states
            .iter()
            .map(|state| native::fake_entry(&state.sidecars, BOUND_A).1)
            .collect();

        let registries: Vec<&native::NativeSidecar> =
            states.iter().map(|state| &state.sidecars).collect();
        native::close_all_registries(&registries, "the application is exiting");

        for (i, core) in cores.iter().enumerate() {
            assert!(core.is_dead(), "window #{i}'s sidecar was not closed at exit");
        }
        for state in &states {
            assert!(native::open_ids(&state.sidecars).is_empty());
            assert!(
                native::try_fake_entry(&state.sidecars, BOUND_A).is_err(),
                "exit must latch every registry shut"
            );
        }
    }

    /// The open cap is PER WINDOW — the ruling, asserted rather than described.
    /// An app-wide cap would refuse window 2's first open while its own page
    /// counts zero open databases, since the host's matching `MAX_OPEN_DATABASES`
    /// is per registry and a registry is per window.
    #[test]
    fn the_native_open_cap_is_per_window() {
        let windows = Windows::default();
        let first = window_state(&windows, MAIN_WINDOW_LABEL);
        let second = window_state(&windows, "db-0");
        for _ in 0..native::MAX_NATIVE_SIDECARS {
            native::fake_entry(&first.sidecars, BOUND_A);
        }
        let err = native::try_fake_entry(&first.sidecars, BOUND_A)
            .err()
            .expect("the 17th open in one window must be refused");
        assert!(err.contains("ERR_NATIVE_TOO_MANY_DATABASES"), "{err}");

        // The second window starts from zero, and can fill its own budget.
        assert!(native::try_fake_entry(&second.sidecars, BOUND_B).is_ok());

        native::close_all_inner(&first.sidecars, "test over");
        native::close_all_inner(&second.sidecars, "test over");
    }

    /// Menu items and OS opens act on exactly one window, so the choice must be
    /// deterministic: the focused window if it is still there, else the main
    /// window, else the lowest live label — never HashMap iteration order.
    #[test]
    fn the_target_window_is_the_focused_one_and_the_fallbacks_are_deterministic() {
        let live = |labels: &[&str]| -> Vec<String> {
            labels.iter().map(|s| s.to_string()).collect()
        };
        assert_eq!(
            resolve_target(Some("db-1"), &live(&["main", "db-0", "db-1"])),
            Some("db-1".into())
        );
        // The tracked window is gone (closed): fall back to main.
        assert_eq!(
            resolve_target(Some("db-9"), &live(&["db-1", "main", "db-0"])),
            Some("main".into())
        );
        // No tracked window yet (nothing focused since boot): main.
        assert_eq!(resolve_target(None, &live(&["db-0", "main"])), Some("main".into()));
        // Main is closed too: the lowest label, stably.
        assert_eq!(
            resolve_target(Some("db-9"), &live(&["db-2", "db-0", "db-1"])),
            Some("db-0".into())
        );
        // Nothing open at all: nothing to deliver to.
        assert_eq!(resolve_target(Some("main"), &[]), None);
    }

    /// The ready latch is per window and no longer one-way: a page load drops
    /// it, so an open arriving during a reload parks for the NEW page instead of
    /// being emitted at the listener the old page took with it.
    #[test]
    fn a_page_load_reopens_the_ready_latch() {
        let windows = Windows::default();
        let state = window_state(&windows, MAIN_WINDOW_LABEL);
        {
            let mut pending = state.pending_open.lock().unwrap();
            assert_eq!(mark_ready(&mut pending), Flushed::default());
            assert_eq!(
                admit_open(&mut pending, PathBuf::from("/a")),
                OpenAdmission::Deliver(PathBuf::from("/a")),
                "a ready window takes an open immediately"
            );
            mark_not_ready(&mut pending); // the page reloads
            assert_eq!(
                admit_open(&mut pending, PathBuf::from("/b")),
                OpenAdmission::Parked,
                "an open during a reload must park, not go out at a dead listener"
            );
            assert_eq!(
                mark_ready(&mut pending),
                Flushed { open: vec![PathBuf::from("/b")], dropped: None }
            );
        }
        // Another window's latch is its own.
        let other = window_state(&windows, "db-0");
        assert_eq!(
            admit_open(&mut other.pending_open.lock().unwrap(), PathBuf::from("/c")),
            OpenAdmission::Parked,
            "a fresh window has not signalled ready"
        );
    }

    /// Every window-scoped delivery must name its window. The theme is the ONE
    /// legitimate app-global broadcast (it lives in the shared settings.json, so
    /// every window repaints); anything else broadcast would mean a single ⌘S or
    /// a single Finder open hitting every window at once. Source-level because
    /// the alternative — a live second window — is not reachable from a test.
    #[test]
    fn no_app_global_emit_carries_per_window_meaning() {
        let source = include_str!("lib.rs");
        // Assembled rather than written out, so this test's own text is not one
        // of the hits it counts.
        let broadcast = format!(".{}(", "emit");
        let hits: Vec<usize> = source.match_indices(&broadcast).map(|(at, _)| at).collect();
        assert_eq!(
            hits.len(),
            1,
            "expected exactly one app-global broadcast (the theme one); a new one \
             must be justified here or addressed to a window with emit_to"
        );
        let preceding = &source[hits[0].saturating_sub(800)..hits[0]];
        assert!(
            preceding.contains("sync_theme_checkmarks"),
            "the one broadcast must be the theme one"
        );
    }

    /// The other half of that contract, in the webview. `emit_to(<label>)` only
    /// reaches listeners registered for that label; the plain `event.listen`
    /// registers target `Any`, which it does NOT match — so if the bridge ever
    /// goes back to it, every menu item and every Finder open silently stops
    /// arriving. That failure is invisible to the Rust tests, hence this gate.
    #[test]
    fn the_bridge_listens_per_window() {
        let bridge = include_str!("../bridge.js");
        assert!(
            bridge.contains("getCurrentWebviewWindow()"),
            "bridge.js must resolve its own window to register labelled listeners"
        );
        assert!(
            bridge.contains("set_unsaved_state"),
            "the page must push its unsaved state or the close prompt never fires"
        );
        // `currentWindow()` is a LAZY accessor, not an eagerly-bound const: resolving
        // the window at init-script time throws (the metadata it reads is not
        // populated yet), and that throw took the whole bridge down — the app booted
        // to "Desktop bridge missing" until a real launch caught it. The parentheses
        // are therefore part of what this gate pins: a future edit that hoists the
        // call back out of the accessor reintroduces a dead app.
        for event in ["desktop-menu", "desktop-open-file", "desktop-drag-drop"] {
            assert!(
                bridge.contains(&format!("listenBeforeReady('{event}'")),
                "{event} must be listened for on this window, not globally"
            );
        }
        assert!(bridge.contains("currentWindow().listen(name, handler)"));
        assert!(
            !bridge.contains("const currentWindow = window.__TAURI__"),
            "the window must be resolved lazily; binding it at init-script time throws \
             and leaves __SQLITE_DESKTOP__ undefined"
        );
        assert!(
            !bridge.contains("event.listen("),
            "no bridge listener may use the app-global event.listen"
        );
    }

    /// A window label the capability set does not cover gets NO permissions at
    /// all: `plugin:`-prefixed commands are ACL-checked (unlike this app's own
    /// commands), so the event system that delivers menu items and file opens
    /// would be refused there — and the two `core:image:deny-from-*` entries
    /// that close the arbitrary-file-read image oracle would not attach to it.
    /// JSON cannot carry the cross-reference comment; this is the lockstep.
    #[test]
    fn the_capability_covers_every_window_label() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json"))
                .expect("capabilities/default.json parses");
        let labels: Vec<&str> = capability["windows"]
            .as_array()
            .expect("windows is an array")
            .iter()
            .map(|v| v.as_str().expect("window entries are strings"))
            .collect();
        assert!(labels.contains(&MAIN_WINDOW_LABEL), "{labels:?}");
        // The glob has to actually match the labels we mint.
        let pattern = format!("{NEW_WINDOW_LABEL_PREFIX}*");
        assert!(labels.contains(&pattern.as_str()), "{labels:?}");
        assert!(next_window_label().starts_with(NEW_WINDOW_LABEL_PREFIX));
        // And the denies must still be there for all of them.
        let permissions = capability["permissions"].to_string();
        assert!(permissions.contains("core:image:deny-from-path"), "{permissions}");
        assert!(permissions.contains("core:image:deny-from-bytes"), "{permissions}");
    }

    /// Least privilege, held by a test because `withGlobalTauri: true` hands
    /// the page the entire `__TAURI__` JS surface — the capability file is the
    /// boundary, `bridge.js` is only hygiene.
    ///
    /// Ground truth for "the bridge calls nothing else": every `__TAURI__`
    /// reference in `bridge.js` and in `viewer-dist/` is either
    /// `__TAURI__.core.invoke` (app commands, which are NOT ACL-gated) or
    /// `__TAURI__.webviewWindow.getCurrentWebviewWindow()` (whose `.listen`
    /// is `plugin:event|listen`, and whose unsubscribe is
    /// `plugin:event|unlisten`). So those two permissions are the whole need.
    ///
    /// The aggregates this replaces were not theoretical: `core:menu` lets a
    /// page mint a menu item carrying one of THIS shell's ids — `new-window`,
    /// `quit-app`, `clear-recents`, `recent-<i>` — and muda dispatches menu
    /// events to the app's global listeners with no check of which menu owns
    /// the item, so one user click runs the shell's own handler.
    /// `core:event:allow-emit`/`-to` let window A synthesise `desktop-menu`
    /// and `desktop-open-file` into window B, defeating the per-window
    /// `emit_to` routing the rest of this file is built around. `dialog:*`
    /// buys the page nothing (every dialog here is opened from Rust, which
    /// bypasses the ACL) and buys an attacker spoofable native alerts plus
    /// asset-scope widening from a picker the PAGE opened.
    #[test]
    fn the_capability_grants_only_what_the_bridge_calls() {
        let capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json"))
                .expect("capabilities/default.json parses");
        let granted: Vec<&str> = capability["permissions"]
            .as_array()
            .expect("permissions is an array")
            .iter()
            .map(|v| v.as_str().expect("permission entries are strings"))
            .collect();
        assert_eq!(
            granted,
            vec![
                "core:event:allow-listen",
                "core:event:allow-unlisten",
                "core:image:deny-from-path",
                "core:image:deny-from-bytes",
            ],
            "the capability set drifted; re-derive it from what bridge.js actually calls"
        );

        // Stated as refusals too, so a re-added aggregate fails here by name
        // rather than only by the equality above.
        for forbidden in [
            "core:default",
            "dialog:",
            "core:menu",
            "core:tray",
            "core:window",
            "core:webview",
            "core:event:allow-emit",
            "core:image:allow",
        ] {
            assert!(
                !granted.iter().any(|p| p.starts_with(forbidden)),
                "{forbidden} is granted again: {granted:?}"
            );
        }

        // The two that ARE granted are exactly the two the bridge uses, and
        // it still uses them the same way.
        let bridge = include_str!("../bridge.js");
        assert!(bridge.contains("getCurrentWebviewWindow()"), "{bridge}");
        assert!(bridge.contains(".listen("), "{bridge}");
    }

    /// New windows are built in Rust while the first one is built from
    /// `tauri.conf.json`; nothing in Tauri keeps the two in step, so a window
    /// opened from the menu could silently get a different size, a different
    /// minimum, or — worse — a different URL from the one the CSP and the asset
    /// protocol were verified against.
    #[test]
    fn new_window_defaults_mirror_the_configured_window() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json"))
            .expect("tauri.conf.json parses");
        let configured = &conf["app"]["windows"][0];
        assert_eq!(configured["url"], NEW_WINDOW_URL);
        assert_eq!(configured["title"], NEW_WINDOW_TITLE);
        assert_eq!(configured["width"], NEW_WINDOW_WIDTH);
        assert_eq!(configured["height"], NEW_WINDOW_HEIGHT);
        assert_eq!(configured["minWidth"], NEW_WINDOW_MIN_WIDTH);
        assert_eq!(configured["minHeight"], NEW_WINDOW_MIN_HEIGHT);
    }

    // -- The page stays on its own origin ------------------------------------

    /// `default-src` is the fallback for fetch directives only. `base-uri`,
    /// `form-action` and `frame-ancestors` never fall back to it, so unless each is
    /// set a <base> tag can retarget the page's relative URLs and a form can post
    /// data out of a page that renders untrusted database content.
    #[test]
    fn the_csp_sets_what_default_src_does_not_cover() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json"))
            .expect("tauri.conf.json parses");
        let csp = &conf["app"]["security"]["csp"];
        for directive in ["base-uri", "form-action", "frame-ancestors"] {
            assert_eq!(csp[directive], "'none'", "{directive}");
        }
        assert_eq!(csp["default-src"], "'none'");
        assert_eq!(csp["script-src"], "'self'", "scripts stay eval-free and inline-free");
    }

    /// The pin admits the served origin — reloads, a query string, the page's own
    /// blobs — and nothing that merely resembles it.
    #[test]
    fn the_navigation_pin_keeps_the_page_on_its_own_origin() {
        let url = |text: &str| tauri::Url::parse(text).expect("test URL parses");
        let macos_linux = [url("tauri://localhost")];
        let windows = [url("http://tauri.localhost")];

        for target in [
            "tauri://localhost/viewer.html",
            "tauri://localhost/viewer.html?reload=1#top",
            "blob:tauri://localhost/2a7c1f80-5d1e-4b7e-9c55-8d1f3b0a6e21",
        ] {
            assert!(is_app_navigation(&url(target), &macos_linux), "{target}");
        }
        for target in [
            "http://tauri.localhost/viewer.html",
            "blob:http://tauri.localhost/2a7c1f80-5d1e-4b7e-9c55-8d1f3b0a6e21",
        ] {
            assert!(is_app_navigation(&url(target), &windows), "{target}");
        }

        for target in [
            "https://attacker.example/?leak=1",
            "http://127.0.0.1:8080/?leak=1",
            "http://localhost/",
            "tauri://attacker/",
            "tauri://localhost.attacker.example/",
            "file:///etc/passwd",
            "data:text/html,leak",
            "about:blank",
            "blob:https://attacker.example/2a7c1f80-5d1e-4b7e-9c55-8d1f3b0a6e21",
            "blob:blob:tauri://localhost/2a7c1f80-5d1e-4b7e-9c55-8d1f3b0a6e21",
            "http://tauri.localhost/viewer.html",
        ] {
            assert!(!is_app_navigation(&url(target), &macos_linux), "{target}");
        }
        for target in [
            "https://tauri.localhost/viewer.html",
            "http://tauri.localhost:8080/viewer.html",
            "http://tauri.localhost.attacker.example/",
            "tauri://localhost/viewer.html",
        ] {
            assert!(!is_app_navigation(&url(target), &windows), "{target}");
        }
    }

    /// `served_origin` hard-codes tauri's `useHttpsScheme: false` choice: a config
    /// that turned it on would serve from `https://tauri.localhost` on Windows and
    /// the pin would refuse the app's own reloads. And the pin is installed on the
    /// builder, so no window — config-declared or `db-<n>` — is built without it.
    #[test]
    fn the_navigation_pin_matches_the_served_origin() {
        for (name, text) in [
            ("tauri.conf.json", include_str!("../tauri.conf.json")),
            ("tauri.windows.conf.json", include_str!("../tauri.windows.conf.json")),
            ("tauri.linux.conf.json", include_str!("../tauri.linux.conf.json")),
            ("tauri.macos.conf.json", include_str!("../tauri.macos.conf.json")),
            ("tauri.qa.conf.json", include_str!("../tauri.qa.conf.json")),
        ] {
            assert!(!text.contains("useHttpsScheme"), "{name} sets useHttpsScheme");
        }
        let viewer = served_origin().join(NEW_WINDOW_URL).expect("viewer URL joins");
        assert!(is_app_navigation(&viewer, &[served_origin()]));

        let source = include_str!("lib.rs");
        let live = &source[..source.find("#[cfg(test)]\nmod tests").expect("tests module")];
        assert!(live.contains(".plugin(navigation_pin())"));
    }

    /// WebView2 sends a refused navigation's request anyway, so on Windows the
    /// request pin must refuse every web request off the app's origins, in any
    /// form a page can issue one, while leaving local schemes alone.
    #[test]
    fn the_request_pin_refuses_web_requests_off_the_app_origins() {
        let url = |text: &str| tauri::Url::parse(text).expect("test URL parses");
        let windows = [url("http://tauri.localhost"), url("http://ipc.localhost")];
        for allowed in [
            "http://tauri.localhost/viewer.html",
            "http://tauri.localhost/viewer.html?nav=control",
            "http://ipc.localhost/plugin%3Aevent%7Clisten",
            "data:image/png;base64,iVBORw0KGgo=",
            "blob:http://tauri.localhost/2a7c1f80-5d1e-4b7e-9c55-8d1f3b0a6e21",
        ] {
            assert!(is_app_request(allowed, &windows), "{allowed}");
        }
        for refused in [
            "http://127.0.0.1:64912/nav-href?leak=1",
            "https://attacker.example/?leak=1",
            "ws://attacker.example/socket",
            "wss://attacker.example/socket",
            "http://tauri.localhost.attacker.example/",
            "http://ipc.localhost:8080/",
            "https://tauri.localhost/viewer.html",
            "not a uri",
            // On Windows a hosted file: URI is a UNC path: an SMB connection to
            // that host, which can also hand it the user's NTLM credentials.
            "file://attacker.example/share/x",
            "file:///C:/Windows/win.ini",
            "ftp://attacker.example/x",
            "chrome-extension://abcdefghijklmnop/x",
        ] {
            assert!(!is_app_request(refused, &windows), "{refused}");
        }
        assert!(is_app_request("about:blank", &windows));
        assert_eq!(origin_for_log("http://127.0.0.1:64912/nav?leak=secret"), "http://127.0.0.1");
        assert!(!origin_for_log("https://attacker.example/?leak=secret").contains("secret"));
    }

    /// The request pin must admit every origin the CSP lets the page connect to,
    /// or the bridge's own IPC fetches would be refused on Windows.
    #[test]
    fn the_request_pin_admits_what_the_csp_connects_to() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json"))
            .expect("tauri.conf.json parses");
        let connect = conf["app"]["security"]["csp"]["connect-src"].as_str().expect("connect-src");
        let origins = app_request_origins();
        for source in connect.split_whitespace().filter(|s| s.starts_with("http")) {
            let origin = tauri::Url::parse(source).expect("connect-src origin parses");
            assert!(origins.contains(&origin), "{source} is in connect-src but not admitted");
        }
        let source = include_str!("lib.rs");
        let live = &source[..source.find("#[cfg(test)]\nmod tests").expect("tests module")];
        assert!(live.contains(".on_webview_ready(") && live.contains("install_request_pin(&_webview)"));
    }

    // -- Unsaved changes are not discarded without asking -------------------

    /// The per-window decision. A window with dirty databases must not close on
    /// its own, a clean one must not nag, and only a reported zero may proceed —
    /// so the failure mode of a missing or garbled push is a prompt, not a
    /// silent discard.
    #[test]
    fn a_window_with_unsaved_databases_is_not_closed_without_asking() {
        assert_eq!(
            close_decision(UnsavedState::default()),
            CloseDecision::Proceed,
            "a clean window must close without a prompt"
        );
        assert_eq!(
            close_decision(UnsavedState { databases: 0 }),
            CloseDecision::Proceed
        );
        assert_eq!(
            close_decision(UnsavedState { databases: 1 }),
            CloseDecision::Confirm { databases: 1 }
        );
        // Several dirty databases in ONE window is the case multi-DB introduced:
        // closing it would discard all of them at once, so the prompt has to say
        // how many.
        assert_eq!(
            close_decision(UnsavedState { databases: 4 }),
            CloseDecision::Confirm { databases: 4 }
        );
        assert_eq!(unsaved_prompt(1), "1 database has unsaved changes. Close anyway?");
        assert_eq!(
            unsaved_prompt(4),
            "4 databases have unsaved changes. Close anyway?"
        );
    }

    /// Quit is the same loss, so it asks the same question — over the TOTAL,
    /// because the windows go away together. Covered here because quit is routed
    /// through our own menu item precisely so that it can be asked at all (see
    /// `build_menu`: `PredefinedMenuItem::quit` sends AppKit's `terminate:`,
    /// which reaches no preventable handler — no per-window `CloseRequested`,
    /// no `ExitRequested`, only `RunEvent::Exit` once the teardown has already
    /// started; `crate::terminate` is what gets in front of that).
    #[test]
    fn quitting_with_unsaved_databases_asks_about_all_of_them() {
        assert_eq!(quit_decision(&[]), CloseDecision::Proceed);
        assert_eq!(
            quit_decision(&[UnsavedState::default(), UnsavedState::default()]),
            CloseDecision::Proceed
        );
        // One dirty window among clean ones still asks.
        assert_eq!(
            quit_decision(&[
                UnsavedState::default(),
                UnsavedState { databases: 2 },
                UnsavedState::default()
            ]),
            CloseDecision::Confirm { databases: 2 }
        );
        // And the total spans windows.
        assert_eq!(
            quit_decision(&[UnsavedState { databases: 2 }, UnsavedState { databases: 3 }]),
            CloseDecision::Confirm { databases: 5 }
        );
    }

    /// …and the collection that feeds it sees EVERY live window, which is the
    /// half the shape above cannot check. Both quit routes — the ⌘Q menu item
    /// and the macOS `applicationShouldTerminate:` hook — read the app's answer
    /// through this one function, so a window whose state it failed to reach
    /// would be a window quietly discarded by both at once.
    #[test]
    fn every_windows_unsaved_work_reaches_the_quit_decision() {
        let windows = Windows::default();
        let first = window_state(&windows, MAIN_WINDOW_LABEL);
        let second = window_state(&windows, "db-0");
        assert_eq!(
            quit_decision_for(&windows),
            CloseDecision::Proceed,
            "nothing pushed yet is nothing to lose"
        );

        // A window that is NOT the focused/main one still has to be seen: the
        // dirty one being the background window is the ordinary case.
        *second.unsaved.lock().unwrap() = UnsavedState { databases: 2 };
        assert_eq!(
            quit_decision_for(&windows),
            CloseDecision::Confirm { databases: 2 }
        );

        *first.unsaved.lock().unwrap() = UnsavedState { databases: 1 };
        assert_eq!(
            quit_decision_for(&windows),
            CloseDecision::Confirm { databases: 3 },
            "the sentence counts both windows"
        );

        // And saving everything really does let the quit through — a prompt
        // that never clears is its own bug.
        *first.unsaved.lock().unwrap() = UnsavedState::default();
        *second.unsaved.lock().unwrap() = UnsavedState::default();
        assert_eq!(quit_decision_for(&windows), CloseDecision::Proceed);

        // A window that has gone away takes its answer with it.
        *second.unsaved.lock().unwrap() = UnsavedState { databases: 9 };
        forget_window(&windows, "db-0");
        assert_eq!(quit_decision_for(&windows), CloseDecision::Proceed);
    }

    /// The OS-initiated quit path, pinned at the source because AppKit is its
    /// only caller: no test in this process can send `terminate:` and live to
    /// assert on the answer.
    ///
    /// Three things make or break it. It must reuse the DECISION rather than
    /// re-derive it (one policy, two entry points). It must answer
    /// `NSTerminateCancel` on the arm that prompts — answering `NSTerminateNow`
    /// and prompting anyway would let AppKit tear the app down with the question
    /// still on screen, which is the exact silent discard this hook exists to
    /// stop. And a failure to install must be REPORTED and survivable: the
    /// method is then simply absent, so the app still quits, and the caller —
    /// not the installer — is what turns the `Err` into the one stderr line.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_os_quit_hook_asks_the_same_question_and_stands_down_while_it_asks() {
        let hook = include_str!("terminate.rs");
        assert!(
            hook.contains("quit_decision_for(&app.state::<Windows>())"),
            "the hook must reuse the shared quit decision, not re-derive one"
        );
        // Comment lines are exempt: the module docs have to NAME `app.exit(0)`
        // to explain why the confirmed quit does not come back through here.
        let exits_itself = hook
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .any(|line| line.contains("app.exit("));
        assert!(
            !exits_itself,
            "the hook answers AppKit; only the confirmed prompt exits"
        );

        let decide = hook.split("fn decide").nth(1).expect("the decision fn");
        let proceed = decide.find("NS_TERMINATE_NOW").expect("a Proceed answer");
        let ask = decide.find("confirm_then_quit(").expect("a prompt");
        let stand_down = decide
            .find("NS_TERMINATE_CANCEL")
            .expect("a Confirm answer");
        assert!(
            proceed < ask && ask < stand_down,
            "Proceed answers NOW; the arm that prompts must answer CANCEL"
        );

        let install = hook
            .split("pub(crate) fn install")
            .nth(1)
            .expect("the installer");
        let install = &install[..install.find("fn should_terminate").unwrap_or(install.len())];
        assert!(
            install.contains("class_getInstanceMethod"),
            "an implementation that is already there must win, not be replaced"
        );
        assert!(
            !install.contains("unwrap()") && !install.contains("expect("),
            "every install failure is an Err the caller reports, never a panic"
        );

        // The caller's half of that contract.
        let source = include_str!("lib.rs");
        let call = source
            .split("terminate::install(")
            .nth(1)
            .expect("setup must install the hook");
        let preceding = &source[..source.find("terminate::install(").unwrap()];
        assert!(
            preceding.ends_with("if let Err(e) = "),
            "an install failure must be reported, not dropped"
        );
        assert!(
            call.contains("eprintln!"),
            "…and reported on stderr, saying what stops working"
        );
    }

    /// The flag is per window: window 1 being dirty must not block window 2's
    /// close, which is exactly the confusion an app-global flag would cause.
    #[test]
    fn the_unsaved_flag_is_per_window() {
        let windows = Windows::default();
        let first = window_state(&windows, MAIN_WINDOW_LABEL);
        let second = window_state(&windows, "db-0");

        *first.unsaved.lock().unwrap() = UnsavedState { databases: 3 };
        assert_eq!(
            close_decision(*first.unsaved.lock().unwrap()),
            CloseDecision::Confirm { databases: 3 }
        );
        assert_eq!(
            close_decision(*second.unsaved.lock().unwrap()),
            CloseDecision::Proceed,
            "a dirty window must not block a clean one's close"
        );
        // Quit, however, sees both.
        assert_eq!(
            quit_decision(&[
                *first.unsaved.lock().unwrap(),
                *second.unsaved.lock().unwrap()
            ]),
            CloseDecision::Confirm { databases: 3 }
        );
    }

    /// The command normalises what the page pushed. `has_unsaved` and the count
    /// are two values that can disagree, and the dangerous disagreement is
    /// "unsaved, but zero of them" — read naively that means never prompt.
    #[test]
    fn a_pushed_unsaved_state_that_disagrees_with_itself_still_prompts() {
        let windows = Windows::default();
        let state = window_state(&windows, MAIN_WINDOW_LABEL);
        // Through the SHIPPING reconciliation, not a copy of it in the test —
        // the command is a one-line wrapper over `normalise_unsaved`, so this is
        // the whole of what a push does.
        let push = |has_unsaved: bool, count: u32| {
            *state.unsaved.lock().unwrap() = normalise_unsaved(has_unsaved, count);
            close_decision(*state.unsaved.lock().unwrap())
        };
        assert_eq!(push(true, 2), CloseDecision::Confirm { databases: 2 });
        assert_eq!(
            push(true, 0),
            CloseDecision::Confirm { databases: 1 },
            "unsaved-but-zero must fail closed into a prompt"
        );
        // Clearing is the page's to do, and it must actually clear.
        assert_eq!(push(false, 0), CloseDecision::Proceed);
        assert_eq!(
            push(false, 9),
            CloseDecision::Proceed,
            "a stale count with nothing unsaved must not nag forever"
        );
    }

    /// Two orderings that are invisible to the unit tests above but decide
    /// whether the prompt actually protects anything, so they are pinned at the
    /// source: the close handler must `prevent_close` BEFORE showing the dialog
    /// (otherwise the window is gone while the question is still on screen), and
    /// the confirm must re-close with `destroy` (a `close` would re-enter
    /// `CloseRequested` and ask forever).
    #[test]
    fn the_close_prompt_prevents_first_and_destroys_on_confirm() {
        let source = include_str!("lib.rs");
        let arm = source
            .split("tauri::WindowEvent::CloseRequested { api, .. }")
            .nth(1)
            .expect("the CloseRequested arm");
        let arm = &arm[..arm.find("tauri::WindowEvent::Destroyed").unwrap_or(arm.len())];
        let prevent = arm.find("api.prevent_close()").expect("must prevent the close");
        let ask = arm.find("confirm_then_close").expect("must ask");
        assert!(prevent < ask, "prevent_close must come before the dialog");

        let confirm = source
            .split("fn confirm_then_close")
            .nth(1)
            .expect("confirm_then_close");
        let confirm = &confirm[..confirm.find("fn confirm_then_quit").unwrap_or(confirm.len())];
        assert!(
            confirm.contains("window.destroy()"),
            "the confirmed close must destroy, not re-enter CloseRequested"
        );
        assert!(
            !confirm.contains("window.close()"),
            "close() would re-emit CloseRequested and ask forever"
        );
        // And quit must not go back to the unpreventable predefined item. The
        // needle is assembled, and shaped like a CALL (trailing paren), so that
        // the prose here and in `build_menu` — which has to name the thing to
        // explain why it is gone — is not itself a hit.
        let predefined_quit = format!("PredefinedMenuItem::{}(", "quit");
        assert!(
            !source.contains(&predefined_quit),
            "predefined quit sends terminate:, which cannot be prevented — see build_menu"
        );
        assert!(source.contains("\"quit-app\""), "quit must route through our own item");
    }

    /// Exactly one unsaved-changes quit prompt, app-wide.
    ///
    /// Two routes reach `confirm_then_quit` — the ⌘Q menu item and the macOS
    /// `applicationShouldTerminate:` hook — and the OS one answers
    /// `NSTerminateCancel` immediately rather than holding the terminate open,
    /// so a second quit request arriving while the first question is still on
    /// screen is the ordinary case, not an exotic one: Dock ▸ Quit twice, ⌘Q
    /// and then a logout, an `osascript … quit` on a machine that is already
    /// asking. With no claim, each request spawns its own blocking dialog and
    /// the ANSWERS then race — Cancel on one and Quit Anyway on the other quits
    /// an app the user just told to stay, and two confirms call `app.exit(0)`
    /// twice. Cancelling must also CLEAR the claim, or the first cancel would
    /// be the last question the app ever asks.
    #[test]
    fn only_one_unsaved_quit_prompt_is_ever_in_flight() {
        // A private flag, not the shipping `QUIT_PROMPT`: the guard is
        // process-wide by design, and a test that claimed the real one would
        // race every other test in this binary.
        static IN_FLIGHT: AtomicBool = AtomicBool::new(false);

        let asking = QuitPrompt::begin(&IN_FLIGHT).expect("the first quit request gets to ask");
        assert!(
            QuitPrompt::begin(&IN_FLIGHT).is_none(),
            "a quit request arriving while the question is up must not open a second dialog"
        );
        assert!(
            QuitPrompt::begin(&IN_FLIGHT).is_none(),
            "…and neither must the third"
        );

        // The dialog returned — whichever button it was.
        drop(asking);
        let asking = QuitPrompt::begin(&IN_FLIGHT)
            .expect("a cancelled quit must leave the app able to ask again");
        assert!(
            QuitPrompt::begin(&IN_FLIGHT).is_none(),
            "…and the fresh claim excludes just as the first one did"
        );
        drop(asking);
        assert!(
            QuitPrompt::begin(&IN_FLIGHT).is_some(),
            "the claim must clear every time, not once"
        );
    }

    /// …and the shipping path has to take that claim in the one order that
    /// makes it a guard.
    ///
    /// BEFORE the spawn: both callers run on the main thread, so claiming
    /// inside the dialog thread would leave exactly the window this exists to
    /// close. AFTER `blocking_show` returns and BEFORE `app.exit(0)`: the
    /// release has to cover BOTH buttons (a release only on the Cancel arm
    /// leaves a confirmed-then-somehow-still-alive app mute), and the exit is
    /// the one call after which nothing here is guaranteed to run again.
    #[test]
    fn the_quit_prompt_is_claimed_before_the_dialog_thread_and_released_when_it_returns() {
        let source = include_str!("lib.rs");
        let body = source
            .split("fn confirm_then_quit")
            .nth(1)
            .expect("confirm_then_quit");
        let body = &body[..body.find("\n}\n").unwrap_or(body.len())];
        // Comment lines are stripped first: the prose here has to be free to
        // NAME `app.exit(0)` while explaining why the release comes before it,
        // and a needle that a comment can satisfy is not pinning anything.
        let body: String = body
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        let body = body.as_str();

        let claim = body
            .find("QuitPrompt::begin(")
            .expect("the quit prompt must claim the single in-flight slot");
        let spawn = body
            .find("thread::spawn")
            .expect("the dialog still runs off the main thread");
        let shown = body
            .find("blocking_show()")
            .expect("the blocking dialog is what the claim covers");
        let released = body
            .find("drop(asking)")
            .expect("the claim must be released when the dialog returns");
        let exit = body.find("app.exit(").expect("a confirm still exits");

        assert!(
            claim < spawn,
            "the claim must be taken before the thread, or two requests both spawn"
        );
        assert!(
            shown < released && released < exit,
            "release when the dialog returns, on both buttons, and before the exit"
        );
    }

    // -- Capstone QA: adversarial probes of the webview-facing surface ------

    /// The allowlist is an exact-path set and the webview supplies the string,
    /// so what counts as "the same path" is `Path`'s COMPONENT-wise equality,
    /// not string equality. That admits every spelling that names the same
    /// file (`//`, `/./`, a trailing separator — `Components` collapses them,
    /// and `Hash for Path` agrees, which is what makes the `HashSet` lookup
    /// sound) and refuses everything that could name a DIFFERENT one: `..` is
    /// never normalised away, and a case variant fails closed even though
    /// macOS's case-insensitive volumes would happily open it.
    #[test]
    fn allowlist_matching_admits_only_spellings_of_the_same_file() {
        let allowlist = SessionAllowlist::default();
        allowlist
            .0
            .lock()
            .unwrap()
            .insert(PathBuf::from("/Users/u/db/app.sqlite"));

        for same in [
            "/Users/u/db/app.sqlite",
            "/Users//u/db/app.sqlite",
            "/Users/u/./db/app.sqlite",
            "/Users/u/db/app.sqlite/",
        ] {
            assert!(
                assert_allowlisted(&allowlist, Path::new(same)).is_ok(),
                "must admit the same file spelled {same:?}"
            );
        }

        for other in [
            "/Users/u/db/../db/app.sqlite",
            "/Users/u/db/../../../etc/passwd",
            "/users/u/db/app.sqlite",
            "/Users/u/db/app.sqlite\u{0}",
            "/Users/u/db/app.sqlite.bak",
            "/Users/u/db",
            "app.sqlite",
            "",
        ] {
            assert!(
                assert_allowlisted(&allowlist, Path::new(other)).is_err(),
                "must refuse {other:?}"
            );
        }
    }

    /// The percent-decoded `x-target-path` header is the webview's only say in
    /// where `save_database` lands. Decoding happens BEFORE the allowlist
    /// check, so an escaped separator or a `%00` cannot smuggle a different
    /// file past it — the decoded value is compared whole.
    #[test]
    fn a_percent_encoded_target_path_cannot_smuggle_a_different_file() {
        let allowlist = SessionAllowlist::default();
        allowlist
            .0
            .lock()
            .unwrap()
            .insert(PathBuf::from("/Users/u/db/app.sqlite"));

        for hostile in [
            "%2Fetc%2Fpasswd",
            "/Users/u/db/app.sqlite%00/../../../etc/passwd",
            "/Users/u/db/app.sqlite%2F..%2Fevil.db",
            "/Users/u/db/app.sqlite%00",
        ] {
            let decoded = urlencoding_decode(hostile).expect("decodes");
            assert!(
                assert_allowlisted(&allowlist, Path::new(&decoded)).is_err(),
                "{hostile} decoded to {decoded:?} and was admitted"
            );
        }

        // The legitimate case still round-trips to the picked path.
        let decoded = urlencoding_decode("/Users/u/db/app%20name.sqlite").unwrap();
        assert_eq!(decoded, "/Users/u/db/app name.sqlite");
    }

    /// Every shell-owned store is written through `write_atomically`, whose
    /// final step is a `rename` — which REPLACES a symlink at the final
    /// component rather than following it. A local attacker who plants a link
    /// at `recents.json` / `window-state.json` therefore cannot turn the
    /// shell's own housekeeping writes into an arbitrary-file overwrite.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_store_file_is_replaced_never_written_through() {
        use std::os::unix::fs::symlink;

        let dir = scratch_dir("store-symlink");
        let victim = dir.join("victim.txt");
        fs::write(&victim, b"victim contents").unwrap();

        let recents = dir.join("recents.json");
        symlink(&victim, &recents).unwrap();
        save_recents_to(&recents, &[PathBuf::from("/tmp/a.db")]).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
        assert!(fs::symlink_metadata(&recents).unwrap().file_type().is_file());
        assert_eq!(load_recents_from(&recents), vec![PathBuf::from("/tmp/a.db")]);

        let state = dir.join("window-state.json");
        symlink(&victim, &state).unwrap();
        save_window_state_to(&state, 1.5).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
        assert!(fs::symlink_metadata(&state).unwrap().file_type().is_file());
        assert!((load_window_state_from(&state) - 1.5).abs() < 1e-9);

        let settings = dir.join("settings.json");
        symlink(&victim, &settings).unwrap();
        write_atomically(&settings, br#"{"theme":"nord"}"#).unwrap();
        assert_eq!(fs::read(&victim).unwrap(), b"victim contents");
        assert_eq!(
            parse_settings(&fs::read(&settings).unwrap()),
            serde_json::json!({"theme": "nord"})
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    /// A store path that cannot be written (here: something else already
    /// occupies it as a DIRECTORY) must fail the save LOUDLY, leave no temp
    /// file behind, and still read back as the safe default — the loaders are
    /// total by contract, the savers are not.
    #[test]
    fn an_unwritable_store_path_fails_the_save_and_still_reads_as_default() {
        let dir = scratch_dir("store-unwritable");

        let recents = dir.join("recents.json");
        fs::create_dir(&recents).unwrap();
        assert!(save_recents_to(&recents, &[PathBuf::from("/tmp/a.db")]).is_err());
        assert!(load_recents_from(&recents).is_empty());

        let state = dir.join("window-state.json");
        fs::create_dir(&state).unwrap();
        assert!(save_window_state_to(&state, 2.0).is_err());
        assert_eq!(load_window_state_from(&state), ZOOM_DEFAULT);

        let settings = dir.join("settings.json");
        fs::create_dir(&settings).unwrap();
        assert!(write_atomically(&settings, b"{}").is_err());

        // The failed writes cleaned up after themselves.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().contains("tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// `parse_settings` runs on the boot path over a file a local attacker can
    /// write, and `load_settings` is deliberately infallible so the viewer's
    /// unguarded `await` can only resolve. Pathological NESTING therefore has
    /// to be refused by the parser (serde_json's recursion limit) rather than
    /// overflowing the stack: a crash here is a boot denial, not a bad setting.
    #[test]
    fn pathological_settings_nesting_degrades_to_defaults_without_overflowing() {
        let deep = format!("{}{}", "[".repeat(200_000), "]".repeat(200_000));
        assert_eq!(parse_settings(deep.as_bytes()), serde_json::json!({}));
        let deep_object = format!(
            "{}{}{}",
            r#"{"a":"#.repeat(200_000),
            "1",
            "}".repeat(200_000)
        );
        assert_eq!(parse_settings(deep_object.as_bytes()), serde_json::json!({}));
    }

    /// Regression for the capstone's BUG-3 (2026-08-18). Was a
    /// characterisation test asserting the bug; it is now the positive
    /// assertion its author asked for.
    ///
    /// `quit_decision` used to add the per-window counts with `+`. Every value
    /// is pushed by a page through `set_unsaved_state`, so two windows
    /// reporting 2^31 each summed to exactly 2^32: in debug that panicked
    /// inside the main-thread menu handler, and in the release profile
    /// `tauri build` ships (overflow checks off) it wrapped to zero, so ⌘Q
    /// quit with NO unsaved-changes prompt — data loss driven entirely from
    /// the webview. The decision is now `any`, never the total, so no
    /// arithmetic a page can steer reaches it.
    #[test]
    fn quit_never_skips_the_prompt_for_hostile_unsaved_counts() {
        let halves = [
            UnsavedState {
                databases: 1 << 31,
            },
            UnsavedState {
                databases: 1 << 31,
            },
        ];
        // Neither a panic (overflow checks on) nor a wrap to Proceed
        // (overflow checks off): the pair that used to be exactly 2^32 asks.
        assert!(matches!(
            quit_decision(&halves),
            CloseDecision::Confirm { .. }
        ));

        // The saturating total is only ever the number in the sentence, and
        // it stays a number a human can read.
        let maxed = [
            UnsavedState { databases: u32::MAX },
            UnsavedState { databases: u32::MAX },
        ];
        assert_eq!(
            quit_decision(&maxed),
            CloseDecision::Confirm {
                databases: u32::MAX
            }
        );

        // One window reporting work is enough, however many report none.
        let mut mixed = vec![UnsavedState::default(); 40];
        mixed.push(UnsavedState { databases: 3 });
        assert_eq!(
            quit_decision(&mixed),
            CloseDecision::Confirm { databases: 3 }
        );

        // And the all-clear still proceeds — the fix must not make ⌘Q always ask.
        assert_eq!(quit_decision(&[UnsavedState::default(); 4]), CloseDecision::Proceed);
        assert_eq!(quit_decision(&[]), CloseDecision::Proceed);

        // The count the page pushes is clamped on the way in, so the prompt
        // can never be built from an absurd number in the first place.
        assert_eq!(
            normalise_unsaved(true, u32::MAX),
            UnsavedState {
                databases: MAX_REPORTED_UNSAVED
            }
        );
        assert_eq!(normalise_unsaved(true, 7), UnsavedState { databases: 7 });
    }

    // -- Capstone fixes: dispatch, non-regular files, cross-window writers ---

    /// BUG-1 / BUG-2, as an invariant rather than one measurement.
    ///
    /// `#[tauri::command(async)]` on a SYNC body is the trap: it reads like
    /// "off the main thread, therefore safe" and in fact means "on a worker of
    /// a shared pool sized by the user's CPU count". Sync commands are the
    /// other trap: they run on the MAIN thread. Every command whose body can
    /// block must therefore hand that body to `crate::blocking` (the blocking
    /// pool) or, for the one unbounded wait, await it.
    ///
    /// Source-level because this is a property of the DISPATCH ANNOTATIONS,
    /// which nothing else can observe from inside the process.
    #[test]
    fn no_command_body_blocks_the_main_thread_or_a_shared_runtime_worker() {
        for (file, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("native.rs", include_str!("native.rs")),
        ] {
            // The needle is assembled, and matched only where an ATTRIBUTE
            // can start: written out literally and searched for anywhere it
            // would match this test — and the doc comments that explain the
            // trap — and so fail forever.
            let trap = format!("#[tauri::command({})]", "async");
            let offender = source.lines().find(|l| l.trim_start().starts_with(&trap));
            assert!(
                offender.is_none(),
                "{file}: (async) on a sync body occupies a shared runtime worker for the \
                 whole body; make it an `async fn` that uses crate::blocking instead"
            );
        }

        // The commands that MAY stay sync: each one is a bounded, non-blocking
        // state update, and `viewer_ready` must stay on the main thread
        // because it reaches `set_menu`. Everything else must be `async fn`.
        let allowed_sync = [
            "fn load_settings",
            "fn save_settings",
            "fn set_title",
            "fn adjust_zoom",
            "fn set_unsaved_state",
            "fn viewer_ready",
        ];
        // Assembled and matched as a whole LINE, for the same reason as the
        // needle above.
        let attribute = format!("#[tauri::{}]", "command");
        let mut seen = 0;
        for (file, source) in [
            ("lib.rs", include_str!("lib.rs")),
            ("native.rs", include_str!("native.rs")),
        ] {
            let lines: Vec<&str> = source.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                if line.trim_start() != attribute {
                    continue;
                }
                seen += 1;
                let signature = lines[i + 1..]
                    .iter()
                    .find(|l| l.contains("fn "))
                    .copied()
                    .expect("a command attribute is followed by its fn");
                if allowed_sync.iter().any(|s| signature.contains(s)) {
                    continue;
                }
                assert!(
                    signature.contains("async fn"),
                    "{file}:{}: {signature} must be an `async fn` (see crate::blocking)",
                    i + 2
                );
            }
        }
        // Every command in `generate_handler!` is accounted for; a new one
        // added without an annotation would drop this count.
        assert_eq!(seen, 18, "the command surface changed size");

        // …and the file-I/O commands: the two the capstone named specifically,
        // plus the import read that joined them.
        let source = include_str!("lib.rs");
        for command in [
            "async fn read_database_bytes",
            "async fn save_database",
            "async fn read_import_text",
        ] {
            let body = source.split(command).nth(1).expect(command);
            let body = &body[..body.len().min(1600)];
            assert!(
                body.contains("crate::blocking("),
                "{command} must not do its file I/O inline"
            );
        }
        // native_rpc awaits instead — it is the only unbounded wait.
        let rpc = include_str!("native.rs")
            .split("pub(crate) async fn native_rpc")
            .nth(1)
            .expect("native_rpc");
        let rpc = &rpc[..rpc.len().min(600)];
        assert!(rpc.contains("rpc_awaited"), "native_rpc must await, not block");
    }

    /// BUG-2. `read_database_bytes` used to be `fs::read` on the MAIN thread.
    /// A FIFO at an allowlisted path (the F3 swap: a local attacker owning the
    /// database's directory replaces the file between the pick and the read)
    /// makes `open(2)` block forever with no timeout and nothing to interrupt
    /// it — the whole app, every window, dead until SIGKILL.
    ///
    /// The read now opens `O_NONBLOCK` and `fstat`s the DESCRIPTOR, so the
    /// open returns immediately for every file type and the type check
    /// describes exactly the object about to be read.
    ///
    /// Driven on a worker thread with a deadline on purpose: if the fix is
    /// reverted, this test must FAIL rather than wedge the whole suite on an
    /// un-interruptible open.
    #[cfg(unix)]
    #[test]
    fn a_fifo_at_an_allowlisted_path_is_refused_instead_of_blocking_forever() {
        let dir = scratch_dir("fifo-read");
        let fifo = dir.join("swapped.db");
        let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // No writer will ever open this FIFO, which is exactly the case where
        // a plain blocking open never returns.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let _ = done_tx.send(read_regular_file(&probe));
        });
        let outcome = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the read must return; a blocking open would never come back");
        let err = outcome.expect_err("a FIFO is not a database");
        assert!(err.contains("not a regular file"), "{err}");

        // A directory and a real file at the same gate, so the refusal is
        // about the file TYPE and not about FIFOs specifically.
        assert!(read_regular_file(&dir).unwrap_err().contains("not a regular file"));
        let real = dir.join("real.db");
        fs::write(&real, b"SQLite format 3\0").unwrap();
        assert_eq!(read_regular_file(&real).unwrap(), b"SQLite format 3\0");

        fs::remove_dir_all(&dir).unwrap();
    }

    /// D4, the WASM half. The page-side host falls back to the WASM engine
    /// whenever a native open fails — including when it failed because
    /// another window already has the file open — and the WASM engine's save
    /// writes the WHOLE image, so an unguarded fallback would produce exactly
    /// the two-editable-copies pair the refusal was for, with the second save
    /// silently discarding the first window's edits. In a build with no
    /// native artifacts at all, this guard is the ONLY one.
    ///
    /// `read_database_bytes` therefore refuses when another window holds the
    /// file, and never when the calling one does (that case is a refresh, or
    /// a re-open the host dedupes in-page).
    #[test]
    fn a_wasm_read_is_refused_only_while_another_window_holds_the_file() {
        let dir = scratch_dir("cross-window-read");
        let db = dir.join("shared.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let canonical = fs::canonicalize(&db).unwrap();
        let files = OpenFiles::default();

        // Unheld: no owner, so nothing to refuse.
        native::hold_for_read(&files, &db, "main").expect("free");

        // The message the OTHER window's user sees names the file and says
        // what to do; it must not leak the path or the other window's label.
        let refusal = native::refuse_second_opener(&canonical, "main", "db-0");
        assert!(refusal.contains("shared.db"), "{refusal}");
        assert!(refusal.contains("another SQLite Explorer window"), "{refusal}");
        assert!(!refusal.contains("db-0"), "{refusal}");

        // …and that is exactly what the second window gets, through a
        // non-canonical spelling too.
        let err = native::hold_for_read(&files, &dir.join(".").join("shared.db"), "db-0")
            .unwrap_err();
        assert_eq!(err, refusal);

        // Same window reads on: refresh must keep working.
        native::hold_for_read(&files, &db, "main").expect("a refresh is not a second opener");

        // The page reporting the file closed releases it for everyone.
        native::sync_reported(&files, "main", &[]).unwrap();
        native::hold_for_read(&files, &db, "db-0").expect("reopenable elsewhere after a close");

        fs::remove_dir_all(&dir).unwrap();

        // The primitives above are only half the guarantee: the guard has to
        // be WIRED INTO the read, and no unit test can invoke a tauri command
        // (it needs a live AppHandle). Pin the wiring on the source, the same
        // way the close-prompt ordering is pinned.
        let source = include_str!("lib.rs");
        let body = source
            .split("async fn read_database_bytes")
            .nth(1)
            .expect("read_database_bytes");
        let body = &body[..body.find("async fn save_database").unwrap_or(body.len())];
        let allowlisted = body
            .find("assert_allowlisted")
            .expect("the allowlist is still layer 1");
        let guard = body
            .find("hold_for_read")
            .expect("the read must take the app-global cross-window hold");
        let read = body
            .find("read_regular_file")
            .expect("the read must go through the regular-file gate");
        assert!(
            allowlisted < guard && guard < read,
            "order: allowlist, then the cross-window guard, then the read"
        );
        assert!(
            body.contains("window.label()"),
            "the guard must be taken for THIS window, or a refresh refuses itself"
        );
        assert!(
            body.contains("crate::blocking("),
            "the read must not run on the main thread or on a shared runtime worker"
        );
    }

    // -- maxFileSize (shell-enforced, both lanes) ---------------------------

    #[test]
    fn the_size_limit_is_unlimited_for_none_and_zero_and_refuses_with_the_configured_sentence() {
        assert_within_size_limit(u64::MAX, None).unwrap();
        assert_within_size_limit(u64::MAX, Some(0)).unwrap();
        assert_within_size_limit(1024 * 1024, Some(1024 * 1024)).unwrap();
        let err = assert_within_size_limit(5 * 1024 * 1024, Some(1024 * 1024)).unwrap_err();
        assert!(err.starts_with("ERR_FILE_TOO_LARGE: "), "{err}");
        assert!(err.contains("File size (5.00 MB) exceeds the maximum allowed size (1.00 MB)"), "{err}");
        assert!(err.contains("Configure 'maxFileSize' in settings.json (0 = unlimited)"), "{err}");
    }

    #[test]
    fn the_bounded_database_read_refuses_before_allocating_and_returns_the_descriptors_generation() {
        let dir = scratch_dir("bounded-read");
        let db = dir.join("big.db");
        fs::write(&db, vec![7u8; 2 * 1024 * 1024]).unwrap(); // 2 MiB
        let err = read_regular_file_bounded(&db, Some(1024 * 1024)).unwrap_err();
        assert!(err.starts_with("ERR_FILE_TOO_LARGE: "), "{err}");
        let (bytes, generation) = read_regular_file_bounded(&db, Some(2 * 1024 * 1024)).unwrap();
        assert_eq!(bytes.len(), 2 * 1024 * 1024);
        assert_eq!(generation, WasmGeneration::of_path(&db).unwrap());
        let (unbounded, _) = read_regular_file_bounded(&db, None).unwrap();
        assert_eq!(unbounded.len(), 2 * 1024 * 1024);
        let (zero_is_unlimited, _) = read_regular_file_bounded(&db, Some(0)).unwrap();
        assert_eq!(zero_is_unlimited.len(), 2 * 1024 * 1024);
        assert!(read_regular_file_bounded(&dir, None).unwrap_err().contains("not a regular file"));
        fs::remove_dir_all(&dir).unwrap();
    }

    // -- WASM stale-image guard ---------------------------------------------

    #[test]
    fn wasm_generation_detects_replacement_even_with_the_same_length_and_mtime() {
        let dir = scratch_dir("wasm-replacement-time");
        let db = dir.join("live.db");
        let replacement = dir.join("replacement.db");
        fs::write(&db, b"original").unwrap();
        let modified = fs::metadata(&db).unwrap().modified().unwrap();
        let original = WasmGeneration::of_path(&db).unwrap();
        fs::write(&replacement, b"replaced").unwrap();
        fs::OpenOptions::new().write(true).open(&replacement).unwrap()
            .set_times(fs::FileTimes::new().set_modified(modified)).unwrap();
        fs::rename(&replacement, &db).unwrap();
        assert_eq!(fs::metadata(&db).unwrap().modified().unwrap(), modified);
        assert_eq!(fs::metadata(&db).unwrap().len(), original.len);
        assert_ne!(WasmGeneration::of_path(&db).unwrap(), original);
        fs::remove_dir_all(dir).unwrap();
    }

    /// Unlike the native identity pin, the WASM generation must move on an
    /// ordinary in-place write too: the engine holds a SNAPSHOT, and writing it
    /// back over a file another writer touched discards that writer's work.
    #[test]
    fn a_wasm_generation_moves_on_any_write_and_is_lost_with_the_file() {
        use std::io::Write;
        let dir = scratch_dir("wasm-generation");
        let db = dir.join("snap.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let read = WasmGeneration::of_path(&db).unwrap();
        assert_eq!(WasmGeneration::of_path(&db).unwrap(), read, "stable while untouched");

        // In place: same inode, different size/mtime — stale for a snapshot.
        let mut file = fs::OpenOptions::new().append(true).open(&db).unwrap();
        file.write_all(b"a page another writer committed").unwrap();
        drop(file);
        assert_ne!(WasmGeneration::of_path(&db).unwrap(), read);

        // Replaced: different inode.
        let after_write = WasmGeneration::of_path(&db).unwrap();
        write_atomically(&db, b"SQLite format 3\0saved").unwrap();
        assert_ne!(WasmGeneration::of_path(&db).unwrap(), after_write);

        // Gone, or not a file: no generation.
        fs::remove_file(&db).unwrap();
        assert!(WasmGeneration::of_path(&db).is_err());
        assert!(WasmGeneration::of_path(&dir).unwrap_err().contains("not a regular file"));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The guard as `save_database` runs it: a save is refused until this window
    /// has read the file, allowed while the file is exactly what it read, refused
    /// after an external in-place write or a replacement, and allowed again once
    /// the post-write record follows the shell's own rename.
    #[test]
    fn an_in_place_save_is_refused_unless_the_file_is_the_generation_this_window_read() {
        use std::io::Write;
        let dir = scratch_dir("stale-save");
        let db = dir.join("edited.db");
        fs::write(&db, b"SQLite format 3\0").unwrap();
        let state = WindowState::default();

        // Never read here: fail closed, naming the remedies.
        let err = assert_generation_current(&state, &db).unwrap_err();
        assert!(err.starts_with("ERR_FILE_CHANGED: "), "{err}");
        assert!(err.contains("no recorded on-disk generation"), "{err}");
        assert!(err.contains("Reload Database") && err.contains("Export Database"), "{err}");

        // Read (what read_database_bytes records): saving is allowed.
        let (_bytes, generation) = read_regular_file_bounded(&db, None).unwrap();
        record_generation(&state, &db, Some(generation));
        assert_generation_current(&state, &db).unwrap();

        // Another writer's in-place change: refused with the sentence.
        let mut file = fs::OpenOptions::new().append(true).open(&db).unwrap();
        file.write_all(b"their rows").unwrap();
        drop(file);
        let err = assert_generation_current(&state, &db).unwrap_err();
        assert_eq!(err, format!("ERR_FILE_CHANGED: {FILE_CHANGED_SENTENCE}"));
        assert!(err.contains("Your unsaved changes remain available"), "{err}");

        // Reload re-records the current generation; the shell's own save then
        // passes, and re-recording after the rename keeps the NEXT save passing.
        let (_bytes, generation) = read_regular_file_bounded(&db, None).unwrap();
        record_generation(&state, &db, Some(generation));
        assert_generation_current(&state, &db).unwrap();
        write_atomically(&db, b"SQLite format 3\0mine").unwrap();
        assert!(
            assert_generation_current(&state, &db).is_err(),
            "the rename made a new inode; without re-recording the next save would refuse"
        );
        record_generation(&state, &db, WasmGeneration::of_path(&db).ok());
        assert_generation_current(&state, &db).unwrap();

        // Replaced outside the app (mv over it): refused; deleted: refused.
        let replacement = dir.join("theirs.db");
        fs::write(&replacement, b"SQLite format 3\0theirs").unwrap();
        fs::rename(&replacement, &db).unwrap();
        assert!(assert_generation_current(&state, &db).unwrap_err().starts_with("ERR_FILE_CHANGED: "));
        fs::remove_file(&db).unwrap();
        assert!(assert_generation_current(&state, &db).unwrap_err().starts_with("ERR_FILE_CHANGED: "));
        // A dropped record (unverifiable post-write stat) fails closed too.
        record_generation(&state, &dir.join("other.db"), None);
        fs::remove_dir_all(&dir).unwrap();

        // Wired in, on the source (no unit test can invoke a command): the save
        // checks the generation AFTER the allowlist and BEFORE the write, then
        // re-records; the read records what it read; Save As records on adopt.
        let source = include_str!("lib.rs");
        let save = source.split("async fn save_database").nth(1).expect("save_database");
        let save = &save[..save.find("async fn save_file_as").expect("save_file_as follows")];
        let allowlisted = save.find("assert_allowlisted").expect("layer 1");
        let guard = save.find("assert_generation_current").expect("the stale-image guard");
        let write = save.find("write_atomically").expect("the write");
        let rerecord = save.find("record_generation").expect("re-record after the rename");
        assert!(allowlisted < guard && guard < write && write < rerecord, "order: allowlist, guard, write, re-record");
        assert!(save.contains("crate::blocking("), "the guard and the write share one blocking body");
        let read = source.split("async fn read_database_bytes").nth(1).expect("read_database_bytes");
        let read = &read[..read.find("async fn save_database").expect("save follows")];
        assert!(read.find("read_regular_file_bounded").unwrap() < read.find("record_generation").unwrap());
        assert!(read.contains("max_bytes"), "the read enforces the page's bound");
        let save_as = source.split("async fn save_file_as").nth(1).expect("save_file_as");
        let save_as = &save_as[..save_as.find("fn urlencoding_decode").expect("decoder follows")];
        let adopt = save_as.find("if adopt {").expect("the adoption branch");
        assert!(save_as[adopt..].contains("record_generation"), "an adopted path must be saveable in place");
    }

    /// The other end of the same mechanism: the push has to actually be
    /// wired into `set_unsaved_state`, and it has to be the ABSENT-vs-empty
    /// shape. No unit test can invoke the command, so this is pinned on the
    /// source next to the primitives' own tests in native.rs.
    #[test]
    fn the_unsaved_push_carries_this_windows_open_files() {
        let source = include_str!("lib.rs");
        let body = source
            .split("fn set_unsaved_state")
            .nth(1)
            .expect("set_unsaved_state's definition");
        let body = &body[..body.find("fn allowlisted_open_paths").unwrap_or(body.len())];
        assert!(
            body.contains("open_paths: Option<Vec<String>>"),
            "absent must be distinguishable from empty, or an old bundle releases every hold"
        );
        let narrowed = body
            .find("allowlisted_open_paths")
            .expect("the reported set must be narrowed to what the user picked");
        let installed = body
            .find("sync_reported")
            .expect("the reported set must reach the app-global registry");
        assert!(narrowed < installed, "narrow before installing, not after");
        assert!(
            body.contains("window.label()"),
            "the set must be keyed by THIS window"
        );

        // The bridge half. `openPaths: null` when the host does not supply
        // an array is the whole absent-vs-empty contract on the JS side.
        let bridge = include_str!("../bridge.js");
        assert!(
            bridge.contains("openPaths: Array.isArray(openPaths) ? openPaths.map(String) : null"),
            "bridge.js must forward the open-path list and send null (not []) when it has none"
        );

        // …and the SHIPPED viewer bundle must actually call it with three
        // arguments. A bundle that predates the open-path push degrades to
        // "this window does not report", which is safe but leaves WASM-only
        // duplicate opens uncovered — exactly the residue this closes — so
        // catch the skew at build time rather than in a smoke pass.
        //
        // Asserted on ARITY, not on parameter names: the bundle is minified,
        // so `openPaths` is renamed to a single letter and only the shape of
        // the call site survives.
        let bundle = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../viewer-dist/viewer.html"),
        )
        .expect("the synced viewer bundle");
        let call = bundle
            .split("setUnsavedState?.(")
            .nth(1)
            .expect("viewer-dist does not push its unsaved state at all");
        let args = &call[..call.find(')').expect("an unterminated call")];
        assert_eq!(
            args.matches(',').count(),
            2,
            "viewer-dist predates the open-path push (call args: {args:?}); \
             re-sync it — npm run sync-viewer"
        );
    }

    /// `bundle.fileAssociations` is the Info.plist side of `DB_EXTENSIONS`; JSON can't
    /// carry the cross-reference comment, so this test is what actually holds the two
    /// lists in lockstep.
    #[test]
    fn file_associations_mirror_db_extensions() {
        let conf: serde_json::Value = serde_json::from_str(include_str!("../tauri.conf.json"))
            .expect("tauri.conf.json parses");
        let exts: Vec<&str> = conf["bundle"]["fileAssociations"][0]["ext"]
            .as_array()
            .expect("fileAssociations[0].ext is an array")
            .iter()
            .map(|v| v.as_str().expect("ext entries are strings"))
            .collect();
        assert_eq!(exts, DB_EXTENSIONS);
    }

    /// `save_file_as` is one command with two meanings, and the whole difference —
    /// whether the destination becomes writable in place for the rest of the session
    /// — hangs on one header. Nothing in Tauri keeps the two ends in step, and a drift
    /// is not harmless in either direction: lose the header and Save As writes the
    /// bytes but leaves the database unable to save over the file the user just
    /// picked; set it on the EXPORT wrapper and every CSV/blob/copy the user exports
    /// becomes silently overwritable by the page.
    #[test]
    fn the_save_as_adopt_header_matches_the_bridge() {
        let bridge = include_str!("../bridge.js");
        let literal = format!("'{ADOPT_HEADER}': '{ADOPT_HEADER_VALUE}'");
        assert!(
            bridge.contains(&literal),
            "bridge.js does not send {literal}: Save As cannot adopt its path"
        );
        assert_eq!(
            bridge.matches(&format!("'{ADOPT_HEADER}'")).count(),
            1,
            "exactly one bridge method may request the allowlist grant (saveDatabaseAs)"
        );
        // …and the shell reads that same constant and actually acts on it. No unit
        // test can invoke the command (it needs a live AppHandle and a dialog), so
        // the wiring is pinned on the source the way the read guard's is.
        let source = include_str!("lib.rs");
        let body = source
            .split("async fn save_file_as")
            .nth(1)
            .expect("save_file_as");
        let body = &body[..body.find("fn urlencoding_decode").unwrap_or(body.len())];
        assert!(body.contains(".get(ADOPT_HEADER)"), "the header is not read");
        assert!(
            body.contains("if adopt {") && body.contains("SessionAllowlist"),
            "the grant is not wired to the flag: Save As could not adopt its path"
        );
    }

    /// The File menu is the ONLY way to reach `exportDb`: the whole-database export is
    /// implemented on both engines and covered by upstream unit tests, but for one
    /// release it had no entry point at all. The viewer half is pinned upstream
    /// (`desktop_capstone_ui.test.ts` greps the built bundle); this is the shell half.
    #[test]
    fn the_file_menu_offers_the_whole_database_export() {
        let source = include_str!("lib.rs");
        // Both needles are BUILT, never written out: `include_str!` pulls this test in
        // too, so a literal would match itself and prove nothing.
        let quoted = format!("{q}export-db{q}", q = '"');
        assert!(source.contains(&quoted), "no export-db menu item");
        // Defined AND in the File submenu's item list — a MenuItem nobody adds to a
        // menu is exactly the unreachable-feature shape this test exists to catch.
        let file_menu = source
            .split(&format!("{q}File{q},", q = '"'))
            .nth(1)
            .expect("the File submenu");
        let file_menu = &file_menu[..file_menu.find(")?;").unwrap_or(file_menu.len())];
        assert!(
            file_menu.contains("&export,"),
            "export-db exists but is not in the File menu"
        );
        // It must ride the default passthrough arm, not be intercepted shell-side:
        // the viewer owns the export (it picks native vs WASM and reports the result).
        assert!(
            !source.contains(&format!("{quoted} =>")),
            "export-db must fall through to the per-window menu emit"
        );
    }

    // -- CSV/JSON import: a read-only grant on its own list --------------------

    #[test]
    fn import_snapshot_refuses_changed_source_bytes_and_metadata() {
        for replacement in [b"id\n2\n".as_slice(), b"id\n2\n3\n".as_slice(), b"id\n".as_slice()] {
            let dir = std::env::temp_dir().join(format!("sqlite-import-generation-{}-{}", std::process::id(), replacement.len()));
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("source.csv");
            fs::write(&path, b"id\n1\n").unwrap();
            let file = File::open(&path).unwrap();
            let before = file.metadata().unwrap();
            fs::write(&path, replacement).unwrap();
            File::options().write(true).open(&path).unwrap().set_times(
                fs::FileTimes::new().set_modified(SystemTime::now() + std::time::Duration::from_secs(2))
            ).unwrap();
            let error = read_import_snapshot(file, &path, before, 64).unwrap_err();
            assert!(error.contains("changed while reading"), "{error}");
            fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// `read_import_text` takes a webview-supplied path, so its allowlist is the
    /// whole authority — and it is the IMPORT list, not the session one: a database
    /// the user has open is refused here exactly like an unpicked path.
    #[test]
    fn an_import_read_accepts_only_paths_the_import_dialog_returned() {
        let dir = scratch_dir("import-read");
        let csv = dir.join("rows.csv");
        fs::write(&csv, "id,name\n1,a\n").unwrap();
        let imports = ImportSourceAllowlist::default();

        let err = assert_import_allowlisted(&imports, &csv).unwrap_err();
        assert!(err.contains("not an import source picked this session"), "{err}");
        assert!(err.contains("rows.csv"), "{err}");

        // A database on the SESSION allowlist buys nothing here.
        let databases = SessionAllowlist::default();
        allowlist_insert_for_tests(&databases, csv.clone());
        assert!(assert_import_allowlisted(&imports, &csv).is_err());

        allowlist_import_for_tests(&imports, csv.clone());
        assert_import_allowlisted(&imports, &csv).expect("picked this session");
        assert_eq!(read_text_bounded(&csv, IMPORT_MAX_BYTES).unwrap(), b"id,name\n1,a\n");
        // Exact match: another spelling of the same file is not the picked path.
        // (`..` is kept as a Path component; a bare `.` would be normalised away.)
        assert!(assert_import_allowlisted(&imports, &dir.join("sub").join("..").join("rows.csv")).is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    /// The cap is enforced from the open descriptor's size BEFORE the buffer
    /// exists, the read is bounded so a file growing underneath it is caught, and
    /// the bytes must be UTF-8 — a Latin-1 CSV is a refusal, not mojibake.
    #[test]
    fn an_import_read_refuses_oversize_grown_and_non_utf8_sources_before_handing_them_over() {
        let dir = scratch_dir("import-bounds");
        let at_cap = dir.join("at-cap.csv");
        fs::write(&at_cap, "a".repeat(16)).unwrap();
        assert_eq!(read_text_bounded(&at_cap, 16).unwrap().len(), 16, "the cap is inclusive");

        let over = dir.join("over.csv");
        fs::write(&over, "a".repeat(17)).unwrap();
        let err = read_text_bounded(&over, 16).unwrap_err();
        assert!(err.contains("17 bytes"), "{err}");
        assert!(err.contains("import limit is 16 bytes"), "{err}");
        assert!(err.contains("Split the file"), "{err}");

        let latin1 = dir.join("latin1.csv");
        fs::write(&latin1, b"name\nJos\xe9\n").unwrap();
        let err = read_text_bounded(&latin1, IMPORT_MAX_BYTES).unwrap_err();
        assert!(err.contains("not valid UTF-8"), "{err}");

        // A BOM'd UTF-8 file is fine here; the page's parser strips the BOM.
        let bom = dir.join("bom.csv");
        fs::write(&bom, "\u{feff}id\n1\n").unwrap();
        assert_eq!(read_text_bounded(&bom, IMPORT_MAX_BYTES).unwrap(), "\u{feff}id\n1\n".as_bytes());

        // Not a regular file: refused by type, like the database read.
        assert!(read_text_bounded(&dir, IMPORT_MAX_BYTES).unwrap_err().contains("not a regular file"));

        // The shipped constant is the upstream parser's 64 MiB, and the message
        // the user sees quotes it.
        assert_eq!(IMPORT_MAX_BYTES, 64 * 1024 * 1024);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Same F3-class swap as the database read: a FIFO planted at the picked path
    /// must be refused, not waited on forever. Driven on a worker thread with a
    /// deadline so a regression fails instead of wedging the suite.
    #[cfg(unix)]
    #[test]
    fn a_fifo_at_an_import_path_is_refused_instead_of_blocking_forever() {
        let dir = scratch_dir("import-fifo");
        let fifo = dir.join("swapped.csv");
        let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let probe = fifo.clone();
        std::thread::spawn(move || {
            let _ = done_tx.send(read_text_bounded(&probe, IMPORT_MAX_BYTES));
        });
        let outcome = done_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the read must return; a blocking open would never come back");
        let err = outcome.expect_err("a FIFO is not an import source");
        assert!(err.contains("not a regular file"), "{err}");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The three properties that make the import grant READ-ONLY, pinned on the
    /// source because no unit test can invoke a command: the pick writes the import
    /// list and neither the session allowlist nor the recents; the read gates on
    /// the import list, on the blocking pool, under the cap; and nothing that
    /// WRITES a file consults the import list.
    #[test]
    fn an_import_pick_never_widens_the_database_allowlist() {
        let source = include_str!("lib.rs");
        let pick = source
            .split("async fn pick_import_source")
            .nth(1)
            .expect("pick_import_source");
        let pick = &pick[..pick.find("async fn read_import_text").expect("read follows pick")];
        assert!(pick.contains("ImportSourceAllowlist"), "the pick must record its path");
        assert!(!pick.contains("SessionAllowlist"), "an import source must never join the database allowlist");
        assert!(!pick.contains("add_recent"), "an import source must never enter Open Recent");
        assert!(pick.contains("IMPORT_EXTENSIONS"), "the dialog must be filtered to the import formats");
        assert!(pick.contains("crate::blocking("), "the dialog must not block the main thread");

        let read = source
            .split("async fn read_import_text")
            .nth(1)
            .expect("read_import_text");
        let read = &read[..read.find("async fn read_database_bytes").expect("database read follows")];
        let gate = read.find("assert_import_allowlisted").expect("the import list is the gate");
        let bounded = read.find("read_text_bounded").expect("the read is the bounded text read");
        assert!(gate < bounded, "order: import allowlist, then the bounded read");
        assert!(read.contains("IMPORT_MAX_BYTES"), "the read must carry the cap");
        assert!(!read.contains("SessionAllowlist"), "the import read must not accept database paths");
        assert!(!read.contains("hold_for_read"), "reading text takes no editing hold");
        assert!(read.contains("crate::blocking("), "the read must not run on the main thread");

        // Nothing that writes a file ever consults the import list.
        for writer in ["async fn save_database", "async fn save_file_as"] {
            let body = source.split(writer).nth(1).expect(writer);
            let body = &body[..body.len().min(4000)];
            assert!(!body.contains("ImportSourceAllowlist"), "{writer} must not write import sources");
        }
        // …and the only two places that read the list are the pick and the read.
        let live = &source[..source.find("#[cfg(test)]\nmod tests").expect("tests module")];
        assert_eq!(
            live.matches("state::<ImportSourceAllowlist>()").count(),
            2,
            "exactly the pick and the read touch the import allowlist"
        );
    }

    /// The shell's 64 MiB is the upstream parser's 64 MiB: the synced desktop
    /// bundle carries the parser's own refusal text for that size, so the two gates
    /// cannot drift apart unnoticed on a re-pin.
    #[test]
    fn the_import_cap_matches_the_viewer_parser() {
        let bundle = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../viewer-dist/viewer.html"
        ))
        .expect("viewer-dist/viewer.html is synced");
        assert!(
            bundle.contains("exceeds the 64 MiB limit"),
            "the synced viewer's parseImport no longer refuses at 64 MiB; re-derive IMPORT_MAX_BYTES"
        );
        assert_eq!(IMPORT_MAX_BYTES / (1024 * 1024), 64);
        // The viewer's import flow is in the bundle at all (a sync to a bundle
        // without it would make File ▸ Import a dead menu item).
        assert!(bundle.contains("importDataModal"), "the synced viewer has no import modal");
    }

    /// File ▸ Import CSV/JSON… exists, sits in the File menu, and rides the default
    /// per-window passthrough — the viewer owns the whole flow.
    #[test]
    fn the_import_menu_item_reaches_the_viewer() {
        let source = include_str!("lib.rs");
        let quoted = format!("{q}import-data{q}", q = '"');
        assert!(source.contains(&quoted), "no import-data menu item");
        let file_menu = source
            .split(&format!("{q}File{q},", q = '"'))
            .nth(1)
            .expect("the File submenu");
        let file_menu = &file_menu[..file_menu.find(")?;").unwrap_or(file_menu.len())];
        assert!(file_menu.contains("&import,"), "import-data exists but is not in the File menu");
        assert!(
            !source.contains(&format!("{quoted} =>")),
            "import-data must fall through to the per-window menu emit"
        );
        // …and the viewer bundle actually listens for it.
        let bundle = fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../viewer-dist/viewer.html"
        ))
        .expect("viewer-dist/viewer.html is synced");
        assert!(bundle.contains("import-data"), "the synced viewer does not handle the import-data menu id");
    }

    /// bridge.js calls exactly the two import commands, by these names, and decodes
    /// the read as UTF-8 text — the shell validated the bytes, the bridge still
    /// decodes fatally so a shell regression cannot produce mojibake silently.
    #[test]
    fn the_bridge_calls_the_import_commands_by_name() {
        let bridge = include_str!("../bridge.js");
        assert!(bridge.contains("invoke('pick_import_source')"), "{bridge}");
        assert!(bridge.contains("invoke('read_import_text', { path })"), "{bridge}");
        assert!(bridge.contains("fatal: true"), "the import text must be decoded fatally");
        // The bridge names no other path-taking read for imports.
        assert_eq!(bridge.matches("read_import_text").count(), 1);
    }
}
