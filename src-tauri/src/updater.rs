//! In-app updates through tauri-plugin-updater, driven by the shell alone.
//!
//! The page has no part in it. No capability grants an updater permission
//! (`the_capability_grants_only_what_the_bridge_calls`), no app command reaches
//! this module, and its one file, `updater.json`, is written only here, so a
//! compromised page can neither start an install nor turn the checks off.
//!
//! An install trusts one thing: the minisign public key in tauri.conf.json
//! (`plugins.updater.pubkey`). The manifest a check reads (`latest.json` on the
//! latest GitHub release) is not signed. The plugin checks the downloaded package
//! against that key and, with `requireSignedVersion`, that the version the signature
//! was made for is the version the manifest announces, so an older signed package
//! cannot be passed off as a newer one; it never installs a lower version. The
//! private key stays offline with the maintainer (`scripts/release/sign-update.mjs`
//! signs a draft release's packages before it is published), so control of the
//! GitHub repository alone cannot ship an update.
//!
//! Each check is one GET of that manifest from github.com, plus the package's
//! download when there is an update. Nothing about the user or their files is sent.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::menu::CheckMenuItem;
use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};
use tauri_plugin_updater::{Update, UpdaterExt};

use crate::{
    answer_on, inform, quit_decision_for, target_window, unsaved_prompt, write_atomically, CloseDecision,
    QuitPrompt, Windows, QUIT_PROMPT,
};

pub(crate) const MENU_CHECK_NOW: &str = "check-for-updates";
pub(crate) const MENU_CHECK_AUTOMATICALLY: &str = "check-for-updates-automatically";

/// At most one automatic check a day.
const AUTO_CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long after launch the automatic check waits, so it never competes with
/// the files the app was opened with.
const AUTO_CHECK_DELAY: Duration = Duration::from_secs(10);

const TITLE: &str = "Software Update";

/// What `updater.json` holds. Shell-written only, like `recents.json`: the page
/// must not be able to turn the checks on or off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(crate) struct UpdaterState {
    /// `None` until the user answers the first-launch question: nothing is
    /// checked automatically before they agree, so the app sends nothing to a
    /// network the user did not ask for (docs/code-signing-policy.md, Privacy).
    pub(crate) check_automatically: Option<bool>,
    /// Seconds since the Unix epoch of the last check that got an answer.
    pub(crate) last_check: u64,
}

/// The first-launch question.
const CONSENT_QUESTION: &str = "Check for updates automatically?\n\n\
SQLite Explorer can check github.com for a new version once a day, and asks before it installs one. \
A check sends GitHub your IP address and the updater's name, nothing about you or your files. \
You can change this later in the SQLite Explorer menu.";

/// The "Check for Updates Automatically" item on screen. Replaced with the
/// menu, after `set_menu` succeeds, for the reason `rebuild_menu` gives for the
/// theme items.
#[derive(Default)]
pub(crate) struct UpdaterMenu(pub(crate) Mutex<Option<CheckMenuItem<tauri::Wry>>>);

/// Serializes every read-modify-write of `updater.json`: the automatic check's
/// thread records `last_check` while the menu may be toggling the setting.
static STATE_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn state_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    Ok(dir.join("updater.json"))
}

/// The saved state, or the defaults (not asked yet) when there is none or it
/// cannot be read; the reason is reported on stderr.
pub(crate) fn load_state_from(path: &Path) -> UpdaterState {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            eprintln!("updater: {} is not valid ({e}); using the defaults", path.display());
            UpdaterState::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => UpdaterState::default(),
        Err(e) => {
            eprintln!("updater: cannot read {} ({e}); using the defaults", path.display());
            UpdaterState::default()
        }
    }
}

fn save_state_to(path: &Path, state: &UpdaterState) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|e| e.to_string())?;
    write_atomically(path, &bytes)
}

/// Applies `change` to the saved state and writes it back; returns the state
/// as saved.
fn update_state(app: &AppHandle, change: impl FnOnce(&mut UpdaterState)) -> Result<UpdaterState, String> {
    let _serialized = STATE_LOCK.lock().unwrap();
    let path = state_path(app)?;
    let mut state = load_state_from(&path);
    change(&mut state);
    save_state_to(&path, &state)?;
    Ok(state)
}

/// Whether the saved state asks for automatic checks (the menu's initial mark).
pub(crate) fn checks_automatically(app: &AppHandle) -> bool {
    let _serialized = STATE_LOCK.lock().unwrap();
    match state_path(app) {
        Ok(path) => load_state_from(&path).check_automatically == Some(true),
        Err(e) => {
            eprintln!("updater: no state path ({e}); no automatic checks");
            false
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())
}

/// Whether an automatic check is due at `now`. A last check in the future (the
/// clock was set back) counts as due rather than postponing checks until then.
pub(crate) fn auto_check_due(state: &UpdaterState, now: u64) -> bool {
    state.check_automatically == Some(true)
        && (state.last_check > now || now - state.last_check >= AUTO_CHECK_INTERVAL.as_secs())
}

/// The setting a click on the menu item asks for: unchecked (off, or not yet
/// asked) becomes on, on becomes off. Choosing it from the menu answers the
/// first-launch question too.
fn toggled(current: Option<bool>) -> Option<bool> {
    Some(current != Some(true))
}

/// The menu's "Check for Updates Automatically": flips the saved setting, then
/// puts the mark where the file says, also when the write failed.
pub(crate) fn toggle_automatic_checks(app: &AppHandle) {
    let saved = update_state(app, |state| state.check_automatically = toggled(state.check_automatically));
    match saved {
        Ok(state) => show_mark(app, state.check_automatically == Some(true)),
        Err(e) => {
            eprintln!("updater: could not save the setting: {e}");
            show_mark(app, checks_automatically(app));
        }
    }
}

fn show_mark(app: &AppHandle, enabled: bool) {
    if let Some(item) = app.state::<UpdaterMenu>().0.lock().unwrap().as_ref() {
        if let Err(e) = item.set_checked(enabled) {
            eprintln!("updater: could not update the menu mark: {e}");
        }
    }
}

/// QA builds only (`--features qa-updater`, never in a release): with
/// `SQLITE_EXPLORER_QA_UPDATE=1` the app runs one Check for Updates… a few
/// seconds after launch and answers every question with its first button, both
/// logged on stderr, so an end-to-end update runs with nobody at the screen.
#[cfg(feature = "qa-updater")]
fn qa_mode() -> bool {
    std::env::var("SQLITE_EXPLORER_QA_UPDATE").as_deref() == Ok("1")
}

#[cfg(not(feature = "qa-updater"))]
fn qa_mode() -> bool {
    false
}

/// One check, download or install at a time, app-wide.
static IN_FLIGHT: AtomicBool = AtomicBool::new(false);

struct InFlight;

impl InFlight {
    fn begin() -> Option<Self> {
        IN_FLIGHT.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).ok().map(|_| Self)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Trigger {
    Automatic,
    Menu,
}

/// A little after launch: the first-launch question while it is unanswered,
/// then the automatic check when the setting is on and the last check is a day
/// old. Never in a development build: those are not installed, and a check
/// there would offer to replace whatever surrounds the binary.
pub(crate) fn schedule_automatic_check(app: &AppHandle) {
    if cfg!(debug_assertions) {
        return;
    }
    let app = app.clone();
    if qa_mode() {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(3));
            run(&app, Trigger::Menu);
        });
        return;
    }
    std::thread::spawn(move || {
        std::thread::sleep(AUTO_CHECK_DELAY);
        let state = {
            let _serialized = STATE_LOCK.lock().unwrap();
            match state_path(&app) {
                Ok(path) => load_state_from(&path),
                Err(e) => {
                    eprintln!("updater: no state path ({e}); not checking");
                    return;
                }
            }
        };
        let state = if state.check_automatically.is_none() {
            let agreed = ask(&app, TITLE, CONSENT_QUESTION, false, ("Check Automatically", "Don't Check"));
            // Unsaved, the answer is asked again at the next launch rather than
            // acted on now.
            match update_state(&app, |state| state.check_automatically = Some(agreed)) {
                Ok(saved) => {
                    show_mark(&app, saved.check_automatically == Some(true));
                    saved
                }
                Err(e) => {
                    eprintln!("updater: could not save the answer: {e}");
                    return;
                }
            }
        } else {
            state
        };
        if auto_check_due(&state, now_secs()) {
            run(&app, Trigger::Automatic);
        }
    });
}

/// The menu's "Check for Updates…". Runs on a thread of its own: the flow waits
/// on the network and on dialogs, and neither may hold the main thread or one
/// of tauri's few runtime workers (see `crate::blocking`).
pub(crate) fn check_now(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || run(&app, Trigger::Menu));
}

fn run(app: &AppHandle, trigger: Trigger) {
    let manual = trigger == Trigger::Menu;
    if cfg!(debug_assertions) {
        if manual {
            say(app, "A development build does not update itself.", MessageDialogKind::Info);
        }
        return;
    }
    let Some(_flight) = InFlight::begin() else {
        if manual {
            say(app, "An update check is already in progress.", MessageDialogKind::Info);
        }
        return;
    };
    let current = app.package_info().version.to_string();
    let found = updater(app).and_then(|updater| {
        tauri::async_runtime::block_on(updater.check()).map_err(|e| match e {
            tauri_plugin_updater::Error::TargetNotFound(_) | tauri_plugin_updater::Error::TargetsNotFound(_) => {
                Unanswered::NoPackageForThisCopy
            }
            other => Unanswered::Failed(other.to_string()),
        })
    });
    if !matches!(found, Err(Unanswered::Failed(_))) {
        if let Err(e) = update_state(app, |state| state.last_check = now_secs()) {
            eprintln!("updater: could not record the check: {e}");
        }
    }
    let update = match found {
        Ok(Some(update)) => update,
        Ok(None) => {
            if manual {
                say(app, &format!("SQLite Explorer {current} is the latest version."), MessageDialogKind::Info);
            }
            return;
        }
        Err(Unanswered::NoPackageForThisCopy) => {
            if manual {
                say(app, ELSEWHERE, MessageDialogKind::Info);
            }
            return;
        }
        Err(Unanswered::Failed(e)) => {
            complain(app, manual, &format!("Could not check for updates: {e}"));
            return;
        }
    };
    let route = match install_route() {
        Ok(route) => route,
        Err(reason) => {
            say(app, &format!("SQLite Explorer {} is available; you have {current}. {reason}", update.version), MessageDialogKind::Info);
            return;
        }
    };
    let bytes = match tauri::async_runtime::block_on(update.download(|_, _| {}, || {})) {
        Ok(bytes) => bytes,
        Err(e) => {
            complain(app, manual, &format!("Could not download SQLite Explorer {}: {e}", update.version));
            return;
        }
    };
    let question = format!(
        "SQLite Explorer {} has been downloaded and verified; you have {current}. Install it now? The app restarts.",
        update.version
    );
    if !ask(app, TITLE, &question, false, ("Install and Restart", "Later")) {
        return;
    }
    if !unsaved_work_may_close(app) {
        return;
    }
    match install(&update, &bytes, route) {
        Ok(()) => app.request_restart(),
        Err(e) => say(
            app,
            &format!("SQLite Explorer {} was not installed: {e}", update.version),
            MessageDialogKind::Warning,
        ),
    }
}

enum Unanswered {
    /// The release has no package for how this copy was installed.
    NoPackageForThisCopy,
    Failed(String),
}

const ELSEWHERE: &str = "This copy of SQLite Explorer does not update itself. Update it the way you installed it.";

/// The plugin's updater, with the Windows hook that stops every engine process
/// before the installer starts: the plugin ends the process right after
/// launching it, with no `RunEvent::Exit`, and a running `tjs.exe` would stop the
/// installer from replacing it.
fn updater(app: &AppHandle) -> Result<tauri_plugin_updater::Updater, Unanswered> {
    let builder = app.updater_builder();
    #[cfg(windows)]
    let builder = {
        let app = app.clone();
        builder.on_before_exit(move || crate::close_all_sidecars(&app))
    };
    builder.build().map_err(|e| Unanswered::Failed(e.to_string()))
}

/// How this copy installs an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// The plugin's own installer: the app bundle on macOS, the NSIS installer on Windows.
    Plugin,
    /// `pkexec dpkg -i`, for a copy the system's dpkg installed from our .deb.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Dpkg,
}

fn install_route() -> Result<Route, &'static str> {
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|_| "Its location could not be determined, so update it by downloading the new version.")?;
    #[cfg(target_os = "macos")]
    return bundle_route(&exe);
    #[cfg(windows)]
    return {
        let _ = exe;
        Ok(Route::Plugin)
    };
    #[cfg(target_os = "linux")]
    return {
        let is_deb = tauri::utils::platform::bundle_type() == Some(tauri::utils::config::BundleType::Deb);
        let list = std::fs::read_to_string(DPKG_LIST).ok();
        dpkg_route(&exe, is_deb, list.as_deref())
    };
}

/// macOS: the plugin replaces the directory three levels above the executable,
/// which is the app only when the executable is in `<name>.app/Contents/MacOS`. A
/// copy on a disk image, or one macOS runs from a temporary read-only place
/// (App Translocation, for an app opened where it was downloaded), cannot be
/// replaced either.
#[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
fn bundle_route(exe: &Path) -> Result<Route, &'static str> {
    let macos_dir = exe.parent();
    let bundle = macos_dir.and_then(Path::parent).and_then(Path::parent);
    let in_bundle = macos_dir.is_some_and(|dir| dir.ends_with("Contents/MacOS"))
        && bundle.is_some_and(|bundle| bundle.extension().is_some_and(|ext| ext == "app"));
    if !in_bundle {
        return Err(ELSEWHERE);
    }
    let text = exe.to_string_lossy();
    if text.starts_with("/Volumes/") || text.contains("/AppTranslocation/") {
        return Err("Move SQLite Explorer to the Applications folder, open it from there, and check again.");
    }
    Ok(Route::Plugin)
}

/// What dpkg records for the package our .deb installs (scripts/release/deb-control.mjs).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const DPKG_LIST: &str = "/var/lib/dpkg/info/sqlite-explorer.list";

/// Linux: only a copy dpkg installed from our .deb installs the next .deb. The
/// AUR package carries the same binary, with the same .deb marker, but pacman
/// installed it, so dpkg must not touch it.
#[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
fn dpkg_route(exe: &Path, is_deb: bool, dpkg_list: Option<&str>) -> Result<Route, &'static str> {
    let owned = dpkg_list.is_some_and(|list| {
        list.lines().map(Path::new).any(|listed| {
            listed == exe
                || (listed.file_name() == exe.file_name()
                    && std::fs::canonicalize(listed).is_ok_and(|resolved| resolved == exe))
        })
    });
    if is_deb && owned {
        Ok(Route::Dpkg)
    } else {
        Err(ELSEWHERE)
    }
}

fn install(update: &Update, bytes: &[u8], route: Route) -> Result<(), String> {
    match route {
        Route::Plugin => update.install(bytes).map_err(|e| e.to_string()),
        #[cfg(target_os = "linux")]
        Route::Dpkg => install_with_dpkg(bytes),
        #[cfg(not(target_os = "linux"))]
        Route::Dpkg => Err("not a dpkg system".into()),
    }
}

/// Installs the verified .deb with `pkexec dpkg -i`, never the plugin's .deb
/// installer: when pkexec fails, or the user cancels its prompt, that one asks
/// for the password in a zenity or kdialog box of its own and pipes it to sudo.
/// The app would then hold the user's password, and Cancel would not cancel.
/// pkexec leaves the password with polkit. The package is written to a private
/// (0700) temporary folder, so only this user can replace it before dpkg reads it.
#[cfg(target_os = "linux")]
fn install_with_dpkg(bytes: &[u8]) -> Result<(), String> {
    let dir = tempfile::Builder::new()
        .prefix("sqlite-explorer-update")
        .tempdir()
        .map_err(|e| format!("could not create a temporary folder: {e}"))?;
    let package = dir.path().join("sqlite-explorer.deb");
    std::fs::write(&package, bytes).map_err(|e| format!("could not write the package: {e}"))?;
    match std::process::Command::new("pkexec").arg("/usr/bin/dpkg").arg("-i").arg(&package).status() {
        Ok(status) if status.success() => Ok(()),
        // pkexec(1): 126 when the authentication dialog was dismissed, 127 when
        // authorization failed or could not be obtained.
        Ok(status) => Err(match status.code() {
            Some(126) => "the administrator authentication was cancelled".to_string(),
            Some(127) => "authorization to install it was not granted".to_string(),
            code => format!("dpkg could not install it (exit status {code:?})"),
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err("pkexec is not installed; download the package from the release page instead".to_string())
        }
        Err(e) => Err(format!("could not run pkexec: {e}")),
    }
}

/// Installing restarts the app, so every window's unsaved work goes: asked as
/// Quit asks, in the same single slot (`QuitPrompt`), so a Quit and an update
/// never put two of these questions on screen.
fn unsaved_work_may_close(app: &AppHandle) -> bool {
    let CloseDecision::Confirm { databases } = quit_decision_for(&app.state::<Windows>()) else {
        return true;
    };
    let Some(_asking) = QuitPrompt::begin(&QUIT_PROMPT) else {
        say(app, "Answer the open question about unsaved changes first.", MessageDialogKind::Info);
        return false;
    };
    let text = unsaved_prompt(databases)
        .replace("Close anyway?", "Installing the update closes them without saving. Install anyway?");
    ask(app, "Unsaved Changes", &text, true, ("Install Anyway", "Cancel"))
}

/// Asks on the focused window and waits; `true` only for the first button.
fn ask(app: &AppHandle, title: &str, text: &str, warning: bool, buttons: (&str, &str)) -> bool {
    if qa_mode() {
        eprintln!("qa-updater: {title}: {text} -> {}", buttons.0);
        return true;
    }
    let parent = target_window(app).and_then(|label| app.get_webview_window(&label));
    let attached = parent.as_ref().map(|window| window.as_ref().window());
    answer_on(attached.as_ref(), title, text, warning, Some(buttons), || {
        let kind = if warning { MessageDialogKind::Warning } else { MessageDialogKind::Info };
        let mut prompt = app
            .dialog()
            .message(text)
            .title(title)
            .kind(kind)
            .buttons(MessageDialogButtons::OkCancelCustom(buttons.0.into(), buttons.1.into()));
        if let Some(window) = &parent {
            prompt = prompt.parent(window);
        }
        prompt.blocking_show()
    })
}

fn say(app: &AppHandle, text: &str, kind: MessageDialogKind) {
    if qa_mode() {
        eprintln!("qa-updater: {text}");
        return;
    }
    inform(app, target_window(app).as_deref(), TITLE, text.to_string(), kind);
}

/// A failure the user asked about is shown; one from an automatic check only
/// goes to stderr, so a laptop offline at launch gets no dialog.
fn complain(app: &AppHandle, manual: bool, text: &str) {
    if manual {
        say(app, text, MessageDialogKind::Warning);
    } else {
        eprintln!("updater: {text}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The updater's tauri.conf.json block, parsed.
    fn updater_config() -> serde_json::Value {
        let conf: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri.conf.json parses");
        conf["plugins"]["updater"].clone()
    }

    #[test]
    fn the_updater_reads_only_the_latest_release_over_https_and_requires_the_signed_version() {
        let config = updater_config();
        assert_eq!(
            config["endpoints"],
            serde_json::json!(["https://github.com/zknpr/SQLite-Explorer-App/releases/latest/download/latest.json"])
        );
        assert_eq!(config["requireSignedVersion"], serde_json::json!(true));
        assert_eq!(config["windows"]["installMode"], serde_json::json!("passive"));
        let keys: Vec<&String> = config.as_object().expect("an object").keys().collect();
        assert!(
            keys.iter().all(|key| !key.starts_with("dangerous") && key.as_str() != "allowDowngrades"),
            "no transport, certificate or downgrade relaxation in a release config: {keys:?}"
        );
    }

    /// The public key every installed copy trusts (minisign key id
    /// C79712E825E62926; its private half is offline with the maintainer). Pinned
    /// here so that changing it takes two edits, and a QA build's key, given
    /// through a --config override, never lands in this file.
    #[test]
    fn the_updater_trusts_the_release_key_not_the_qa_key() {
        let pubkey = updater_config()["pubkey"].as_str().expect("a pubkey").to_string();
        assert_ne!(pubkey, QA_ONLY_PUBKEY, "tauri.conf.json carries the QA-only updater key");
        assert_eq!(pubkey, RELEASE_PUBKEY, "tauri.conf.json's updater key is not the release key");
    }

    const RELEASE_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDI2MjlFNjI1RTgxMjk3QzcKUldUSGx4TG9KZVlwSm5PeE9nSFpnU1RjWllMQWxDUDhwMEUxaUtHUys5MU5VcXJsaEpoYmR3eloK";

    /// scripts/qa/updater: the key the end-to-end QA builds sign with.
    const QA_ONLY_PUBKEY: &str = "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDMxMjNBRjY4ODE5NkI5M0MKUldROHVaYUJhSzhqTVRiaUs4d1ZzUmJwTVBKaWp1cmxTa0I2K29NdTFrTENXU3oxd0xZNGJjKzYK";

    #[test]
    fn no_release_build_enables_the_qa_mode() {
        for workflow in [include_str!("../../.github/workflows/release.yml"), include_str!("../../.github/workflows/ci.yml")] {
            assert!(!workflow.contains("qa-updater"), "a workflow enables the qa-updater feature");
        }
        let manifest = include_str!("../Cargo.toml");
        let default = manifest.lines().find(|line| line.trim_start().starts_with("default")).unwrap_or("");
        assert!(!default.contains("qa-updater"), "qa-updater is a default feature");
    }

    #[test]
    fn nothing_is_checked_until_asked_and_the_state_survives_a_bad_file() {
        let dir = std::env::temp_dir().join(format!("updater-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("updater.json");
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_state_from(&path), UpdaterState::default());
        assert_eq!(UpdaterState::default().check_automatically, None, "not asked yet");
        std::fs::write(&path, b"{not json").unwrap();
        assert_eq!(load_state_from(&path), UpdaterState::default());
        let state = UpdaterState { check_automatically: Some(false), last_check: 42 };
        save_state_to(&path, &state).unwrap();
        assert_eq!(load_state_from(&path), state);
        std::fs::write(&path, br#"{"checkAutomatically":true}"#).unwrap();
        assert_eq!(load_state_from(&path), UpdaterState { check_automatically: Some(true), last_check: 0 });
        std::fs::write(&path, br#"{"checkAutomatically":null,"lastCheck":7}"#).unwrap();
        assert_eq!(load_state_from(&path), UpdaterState { check_automatically: None, last_check: 7 });
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn an_automatic_check_is_due_once_a_day_only_after_the_user_agreed() {
        let day = AUTO_CHECK_INTERVAL.as_secs();
        let on = |last_check| UpdaterState { check_automatically: Some(true), last_check };
        assert!(auto_check_due(&on(0), 10 * day));
        assert!(!auto_check_due(&on(10 * day), 10 * day + day - 1));
        assert!(auto_check_due(&on(10 * day), 11 * day));
        assert!(auto_check_due(&on(12 * day), 11 * day), "a last check in the future");
        for answer in [None, Some(false)] {
            assert!(!auto_check_due(&UpdaterState { check_automatically: answer, last_check: 0 }, 10 * day));
        }
    }

    #[test]
    fn the_menu_item_turns_checks_on_from_unasked_or_off_and_off_from_on() {
        assert_eq!(toggled(None), Some(true));
        assert_eq!(toggled(Some(false)), Some(true));
        assert_eq!(toggled(Some(true)), Some(false));
    }

    #[test]
    fn macos_replaces_only_an_app_bundle_it_can_write() {
        let exe = |p: &str| PathBuf::from(p);
        assert_eq!(
            bundle_route(&exe("/Applications/SQLite Explorer.app/Contents/MacOS/sqlite-explorer-desktop")),
            Ok(Route::Plugin)
        );
        // A bare release binary: three levels up is the checkout, not an app.
        assert!(bundle_route(&exe("/Users/me/dev/app/src-tauri/target/release/sqlite-explorer-desktop")).is_err());
        assert!(bundle_route(&exe("/Volumes/SQLite Explorer/SQLite Explorer.app/Contents/MacOS/x")).is_err());
        assert!(bundle_route(&exe(
            "/private/var/folders/ab/T/AppTranslocation/1234/d/SQLite Explorer.app/Contents/MacOS/x"
        ))
        .is_err());
    }

    #[test]
    fn linux_installs_with_dpkg_only_where_dpkg_installed_this_copy() {
        let exe = Path::new("/usr/bin/sqlite-explorer");
        let list = "/.\n/usr\n/usr/bin\n/usr/bin/sqlite-explorer\n/usr/share/applications/SQLite Explorer.desktop\n";
        assert_eq!(dpkg_route(exe, true, Some(list)), Ok(Route::Dpkg));
        // The AUR package: the .deb marker in the binary, but pacman installed it.
        assert!(dpkg_route(exe, true, None).is_err());
        assert!(dpkg_route(exe, true, Some("/usr/bin/something-else\n")).is_err());
        // Not built as a .deb (an AUR source build, a local build).
        assert!(dpkg_route(exe, false, Some(list)).is_err());
    }
}
