//! Windows session-end requests bypass Tauri's close and menu events. Refuse
//! ordinary shutdown/logoff while any window has pending edits, with a reason
//! Windows can show in its own shutdown UI. Forced shutdown remains OS-owned.

use std::cell::RefCell;
use std::collections::HashSet;
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;

use tauri::{AppHandle, Manager};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy};
use windows_sys::Win32::System::Threading::SetProcessShutdownParameters;
use windows_sys::Win32::UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    ENDSESSION_CRITICAL, WM_ENDSESSION, WM_NCDESTROY, WM_QUERYENDSESSION,
};

use crate::{quit_decision_for, CloseDecision, Windows};

// The process has one Tauri application. Keeping its handle here avoids passing
// Rust allocations through window-procedure pointers or freeing them reentrantly.
static APP: OnceLock<AppHandle> = OnceLock::new();
const SUBCLASS_ID: usize = 0x5351_4c58;
const REASON: &str = "Unsaved database changes. Return to SQLite Explorer to save or discard them.";
thread_local! {
    // Windows returns ERROR_INVALID_PARAMETER when destroying a reason that
    // was never registered. Track successful registrations on the HWND thread.
    static REASONS: RefCell<HashSet<usize>> = RefCell::new(HashSet::new());
}

fn has_unsaved(app: &AppHandle) -> bool {
    matches!(
        quit_decision_for(&app.state::<Windows>()),
        CloseDecision::Confirm { .. }
    )
}

fn set_reason(hwnd: HWND, blocked: bool) {
    if REASONS.with(|reasons| reasons.borrow().contains(&(hwnd as usize))) == blocked {
        return;
    }
    // Both APIs must run on the thread that owns this HWND. Setup, native menu
    // events, synchronous unsaved-state IPC and the subclass all run there.
    let ok = unsafe {
        if blocked {
            let text: Vec<u16> = REASON.encode_utf16().chain(Some(0)).collect();
            ShutdownBlockReasonCreate(hwnd, text.as_ptr())
        } else {
            ShutdownBlockReasonDestroy(hwnd)
        }
    };
    if ok == 0 {
        eprintln!(
            "could not update the Windows shutdown reason: {}",
            io::Error::last_os_error()
        );
    } else {
        REASONS.with(|reasons| {
            if blocked {
                reasons.borrow_mut().insert(hwnd as usize);
            } else {
                reasons.borrow_mut().remove(&(hwnd as usize));
            }
        });
    }
}

/// Called on the window thread whenever the shared unsaved state changes.
pub fn refresh(app: &AppHandle) {
    let blocked = has_unsaved(app);
    for window in app.webview_windows().values() {
        match window.hwnd() {
            Ok(hwnd) => set_reason(hwnd.0 as HWND, blocked),
            Err(e) => eprintln!(
                "could not update the shutdown reason for {}: {e}",
                window.label()
            ),
        }
    }
}

/// Install once per native window, before it can accept user edits.
pub fn install(window: &tauri::WebviewWindow) -> Result<(), Box<dyn std::error::Error>> {
    // Ask the GUI before the default-priority WebView and database children.
    // Ending either child first can destroy pending work before our veto runs.
    // 0x3ff is the documented application range; system priorities are higher.
    if unsafe { SetProcessShutdownParameters(0x3ff, 0) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    APP.get_or_init(|| window.app_handle().clone());
    let hwnd = window.hwnd()?.0 as HWND;
    // Compose with the existing window procedure; ordinary window messages
    // still reach Tao and WebView2.
    if unsafe { SetWindowSubclass(hwnd, Some(session_proc), SUBCLASS_ID, 0) } == 0 {
        return Err(io::Error::other("could not install Windows session-end guard").into());
    }
    set_reason(hwnd, has_unsaved(window.app_handle()));
    Ok(())
}

unsafe extern "system" fn session_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    if message == WM_QUERYENDSESSION {
        if (lparam as u32 & ENDSESSION_CRITICAL) != 0 {
            eprintln!("Windows requested forced session end (flags {:#x})", lparam as u32);
            return 1;
        }
        // Never unwind across the Win32 callback. If state cannot be inspected,
        // preserve pending work; Windows still offers its force-shutdown action.
        let blocked = catch_unwind(AssertUnwindSafe(|| APP.get().map(has_unsaved)))
            .ok()
            .flatten()
            .unwrap_or_else(|| {
                eprintln!("could not inspect unsaved state; refusing Windows session end");
                true
            });
        set_reason(hwnd, blocked);
        eprintln!("Windows session-end query: flags {:#x}, unsaved changes {blocked}", lparam as u32);
        return if blocked { 0 } else { 1 };
    }
    if message == WM_ENDSESSION && wparam != 0 {
        // The OS has committed to ending the session; a veto is no longer valid.
        // Tao handles this only on its hidden event HWND. A direct notification
        // to an app window must also finish, with identical sidecar cleanup.
        eprintln!("Windows session end committed (flags {:#x})", lparam as u32);
        let finished = catch_unwind(AssertUnwindSafe(|| {
            if let Some(app) = APP.get() {
                crate::finish_app_exit(app);
            }
        }));
        // Successful cleanup exits the process. Do not unwind through Win32 or
        // return to the UI after a failed terminal cleanup.
        eprintln!("Windows session cleanup failed (panic: {})", finished.is_err());
        std::process::exit(1);
    }
    if message == WM_NCDESTROY {
        set_reason(hwnd, false);
        // The HWND is going away even if Windows already removed its reason.
        // A reused handle must never inherit this registration bookkeeping.
        REASONS.with(|reasons| reasons.borrow_mut().remove(&(hwnd as usize)));
        if RemoveWindowSubclass(hwnd, Some(session_proc), SUBCLASS_ID) == 0 {
            eprintln!("could not remove the Windows session-end guard");
        }
    }
    DefSubclassProc(hwnd, message, wparam, lparam)
}
