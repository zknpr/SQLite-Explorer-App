//! The menu's shortcuts while a Windows webview has the keyboard.
//!
//! The menu's accelerator table is read by the app's message loop, but while
//! WebView2 has focus its key messages go to the browser process's window, never
//! that loop. So Ctrl+Q and Ctrl+Shift+N did nothing at all (measured on a
//! Windows test machine: no quit prompt, no new window). The viewer's own keydown
//! handler takes Ctrl+O, Ctrl+S, Ctrl+Z/Y, Ctrl+W and the tab keys, and
//! `bridge.js` takes zoom; nothing took Refresh (Ctrl+R), SQL Console
//! (Ctrl+Shift+K) or Minimize (Ctrl+M). Ctrl+R was worse than dead: WebView2's
//! own binding reloaded the page, as F5 did, and a reload discarded every unsaved
//! edit with no prompt. So this takes those keys too, and the browser's reload
//! keys run nothing at all. (The navigation pin refuses a reload of a window with
//! unsaved work whatever starts it; see `navigation_refusal`.)
//!
//! WebView2 raises `AcceleratorKeyPressed` on the host for a Ctrl or Alt key
//! before the page sees it, and only for keyboard input: a page's synthetic key
//! events never reach it. Taking the two keys there gives the page nothing new to
//! call, which is why this is not a bridge command like `adjust_zoom`: a page
//! that could open windows could open them without end.

/// What a shortcut asks the shell to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShellKey {
    Quit,
    NewWindow,
    /// The menu's Refresh From Disk, which the page runs.
    Refresh,
    /// The menu's SQL Console, which the page runs.
    SqlConsole,
    /// The Window menu's Minimize.
    Minimize,
}

/// What the handler does with a key press it takes: the page never sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Taken {
    /// Run the shortcut.
    Run(ShellKey),
    /// Nothing at all.
    Swallow,
}

/// F5 and the keyboard's Refresh key.
const VK_F5: u32 = 0x74;
const VK_BROWSER_REFRESH: u32 = 0xA8;

/// The menu accelerators this hook takes, judged from a Win32 virtual-key code and
/// the modifier state. Alt must be up: AltGr is Ctrl+Alt on Windows, and AltGr+Q
/// types `@` on a German layout, so without it an email address would quit the
/// app. A key held down repeats: a repeat is taken but runs nothing, so a held
/// Ctrl+Shift+N opens one window, and a held Ctrl+R cannot reach WebView2's reload
/// on its second press. The browser's reload keys (F5 with any of Ctrl and Shift,
/// Ctrl+Shift+R, the Refresh key) are taken and run nothing.
/// `the_windows_shortcut_hook_matches_the_menu` holds this in step with `build_menu`.
pub(crate) fn shell_key(
    virtual_key: u32,
    ctrl: bool,
    shift: bool,
    alt: bool,
    repeat: bool,
) -> Option<Taken> {
    if alt {
        return None;
    }
    let browser_reload = virtual_key == VK_F5
        || virtual_key == VK_BROWSER_REFRESH
        || (ctrl && shift && virtual_key == u32::from(b'R'));
    if browser_reload {
        return Some(Taken::Swallow);
    }
    if !ctrl {
        return None;
    }
    let letter = |c: u8| virtual_key == u32::from(c);
    let key = match shift {
        false if letter(b'Q') => ShellKey::Quit,
        true if letter(b'N') => ShellKey::NewWindow,
        false if letter(b'R') => ShellKey::Refresh,
        true if letter(b'K') => ShellKey::SqlConsole,
        false if letter(b'M') => ShellKey::Minimize,
        _ => return None,
    };
    Some(if repeat { Taken::Swallow } else { Taken::Run(key) })
}

/// Installs the handler on every webview as it becomes ready, `db-*` windows too.
#[cfg(windows)]
pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri::plugin::Builder::new("shell-keys")
        .on_webview_ready(|webview| {
            use tauri::Manager;
            let app = webview.app_handle().clone();
            // The window the keys arrive in: the page items and Minimize act on it.
            let label = webview.window().label().to_string();
            let reached = webview.with_webview(move |platform| {
                if let Err(e) = install(platform.controller(), app, label.clone()) {
                    eprintln!("could not install the menu shortcuts on webview {label}: {e}");
                }
            });
            if let Err(e) = reached {
                eprintln!("could not reach webview {} to install the menu shortcuts: {e}", webview.label());
            }
        })
        .build()
}

#[cfg(windows)]
fn install(
    controller: webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Controller,
    app: tauri::AppHandle,
    label: String,
) -> windows::core::Result<()> {
    use webview2_com::AcceleratorKeyPressedEventHandler;
    use webview2_com::Microsoft::Web::WebView2::Win32::{
        COREWEBVIEW2_KEY_EVENT_KIND, COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN,
        COREWEBVIEW2_PHYSICAL_KEY_STATUS,
    };
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        GetKeyState, VK_CONTROL, VK_MENU, VK_SHIFT,
    };
    // SAFETY: WebView2 COM calls on interfaces Tauri handed us, made on the
    // webview's own thread (`with_webview` runs there), as `request_pin` does.
    // The handler runs on that thread too, which is the one whose key state
    // GetKeyState reads: WebView2's window is a child of ours, so the two
    // share their input state.
    unsafe {
        let mut token = 0i64;
        controller.add_AcceleratorKeyPressed(
            &AcceleratorKeyPressedEventHandler::create(Box::new(move |_, args| {
                let Some(args) = args else {
                    return Ok(());
                };
                let mut kind = COREWEBVIEW2_KEY_EVENT_KIND::default();
                args.KeyEventKind(&mut kind)?;
                if kind != COREWEBVIEW2_KEY_EVENT_KIND_KEY_DOWN {
                    return Ok(());
                }
                let mut virtual_key = 0u32;
                args.VirtualKey(&mut virtual_key)?;
                let mut status = COREWEBVIEW2_PHYSICAL_KEY_STATUS::default();
                args.PhysicalKeyStatus(&mut status)?;
                let held = |key: u16| GetKeyState(i32::from(key)) < 0;
                let Some(taken) = shell_key(
                    virtual_key,
                    held(VK_CONTROL),
                    held(VK_SHIFT),
                    status.IsMenuKeyDown.as_bool() || held(VK_MENU),
                    status.WasKeyDown.as_bool(),
                ) else {
                    return Ok(());
                };
                // Taken: neither the page nor WebView2's own bindings see it.
                args.SetHandled(true)?;
                if let Taken::Run(key) = taken {
                    run(&app, &label, key);
                }
                Ok(())
            })),
            &mut token,
        )
    }
}

/// Runs a shortcut the way the event loop runs a menu click. Not from inside the
/// handler: it runs within WebView2's event dispatch on the main thread, where
/// `run_on_main_thread` runs its task inline (tauri-runtime-wry's
/// `send_user_message`), so building a window or exiting would happen inside
/// the callback. From a thread of its own the task goes through the event loop.
#[cfg(windows)]
fn run(app: &tauri::AppHandle, label: &str, key: ShellKey) {
    let app = app.clone();
    let label = label.to_string();
    let spawned = std::thread::Builder::new()
        .name("menu-shortcut".into())
        .spawn(move || {
            let handle = app.clone();
            let queued = app.run_on_main_thread(move || match key {
                ShellKey::Quit => crate::request_quit(&handle),
                ShellKey::NewWindow => crate::open_new_window(&handle),
                ShellKey::Refresh => crate::forward_menu_item(&handle, &label, "refresh-db"),
                ShellKey::SqlConsole => crate::forward_menu_item(&handle, &label, "sql-console"),
                ShellKey::Minimize => {
                    use tauri::Manager;
                    match handle.get_webview_window(&label) {
                        Some(window) => {
                            if let Err(e) = window.minimize() {
                                eprintln!("could not minimize window {label}: {e}");
                            }
                        }
                        None => eprintln!("Minimize ignored: window {label} is gone"),
                    }
                }
            });
            if let Err(e) = queued {
                eprintln!("the {key:?} shortcut did not run: {e}");
            }
        });
    if let Err(e) = spawned {
        eprintln!("the {key:?} shortcut did not run: {e}");
    }
}
