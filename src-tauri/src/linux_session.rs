//! X11 session management. Xfce's D-Bus EndSessionResponse ignores a negative
//! response; XSMP's InteractDone(cancel_shutdown) is its actual logout veto.
//! Keep the connection on one worker so a slow session manager cannot block GTK.

use std::ffi::{c_char, c_int, c_ulong, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tauri::{AppHandle, Manager};
use tauri_plugin_dialog::DialogExt;

use crate::{quit_decision_for, CloseDecision, Windows};

type Connection = *mut c_void;
type Callback = unsafe extern "C" fn(Connection, *mut c_void);

#[repr(C)]
struct Slot<T> {
    callback: T,
    data: *mut c_void,
}

#[repr(C)]
struct Callbacks {
    save: Slot<unsafe extern "C" fn(Connection, *mut c_void, c_int, c_int, c_int, c_int)>,
    die: Slot<Callback>,
    complete: Slot<Callback>,
    cancelled: Slot<Callback>,
}

#[link(name = "SM")]
extern "C" {
    fn SmcOpenConnection(
        network: *mut c_char, context: *mut c_void, major: c_int, minor: c_int,
        mask: c_ulong, callbacks: *mut Callbacks, previous_id: *const c_char,
        client_id: *mut *mut c_char, error_len: c_int, error: *mut c_char,
    ) -> Connection;
    fn SmcCloseConnection(connection: Connection, count: c_int, reasons: *mut *mut c_char) -> c_int;
    fn SmcGetIceConnection(connection: Connection) -> Connection;
    fn SmcSaveYourselfDone(connection: Connection, success: c_int);
    fn SmcInteractRequest(connection: Connection, kind: c_int, callback: Callback, data: *mut c_void) -> c_int;
    fn SmcInteractDone(connection: Connection, cancel: c_int);
}

#[link(name = "ICE")]
extern "C" {
    fn IceConnectionNumber(connection: Connection) -> c_int;
    fn IceProcessMessages(connection: Connection, reply: *mut c_void, ready: *mut c_int) -> c_int;
    fn IceSetIOErrorHandler(handler: Option<unsafe extern "C" fn(Connection)>) -> Option<unsafe extern "C" fn(Connection)>;
}

pub struct SessionGuard(Arc<AtomicBool>);

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

struct Client {
    app: AppHandle,
    waiting_for_interaction: bool,
    finished: bool,
}

#[derive(Debug, PartialEq)]
enum SaveAction { Acknowledge, RequestInteraction }

fn save_action(dirty: bool, shutdown: bool, interact: c_int, fast: bool) -> SaveAction {
    if dirty && shutdown && interact != 0 && !fast {
        SaveAction::RequestInteraction
    } else {
        SaveAction::Acknowledge
    }
}

// All libSM callbacks run synchronously inside this worker's IceProcessMessages.
// Its stack-owned Client outlives SmcCloseConnection; no pointer crosses threads.
unsafe extern "C" fn save(connection: Connection, data: *mut c_void, _kind: c_int, shutdown: c_int, interact: c_int, fast: c_int) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let client = &mut *(data as *mut Client);
        let dirty = matches!(quit_decision_for(&client.app.state::<Windows>()), CloseDecision::Confirm { .. });
        if save_action(dirty, shutdown != 0, interact, fast != 0) == SaveAction::RequestInteraction {
            client.waiting_for_interaction = true;
            // SmDialogError is allowed with both Errors and Any interaction.
            if SmcInteractRequest(connection, 0, interact_granted, data) == 0 {
                client.waiting_for_interaction = false;
                eprintln!("session manager refused the unsaved-changes interaction request");
                SmcSaveYourselfDone(connection, 0);
            }
        } else {
            // Non-shutdown checkpoints and forced logout must not wedge the session.
            SmcSaveYourselfDone(connection, 1);
        }
    }));
    if result.is_err() {
        eprintln!("could not inspect unsaved state during the X11 session-end request");
    }
}

unsafe extern "C" fn interact_granted(connection: Connection, data: *mut c_void) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let client = &mut *(data as *mut Client);
        if !client.waiting_for_interaction { return; }
        client.waiting_for_interaction = false;
        // Cancel first, then explain. No modal dialog or IPC round trip can hold
        // the session manager hostage; saving/discarding remains the user's choice.
        SmcInteractDone(connection, 1);
        SmcSaveYourselfDone(connection, 1);
        client.app.dialog()
            .message("Logout was cancelled because a database has unsaved changes. Save or discard them, then try again.")
            .title("Unsaved changes")
            .show(|_| {});
    }));
    if result.is_err() { eprintln!("could not finish the X11 session-end interaction"); }
}

unsafe extern "C" fn die(_connection: Connection, data: *mut c_void) {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let client = &mut *(data as *mut Client);
        client.finished = true;
        client.app.exit(0);
    }));
    if result.is_err() { eprintln!("could not exit after X11 session end"); }
}

unsafe extern "C" fn complete(_connection: Connection, _data: *mut c_void) {}

unsafe extern "C" fn cancelled(connection: Connection, data: *mut c_void) {
    let client = &mut *(data as *mut Client);
    // Another client may cancel while our interaction is still queued. Complete
    // that pending save exactly once; our own cancellation already acknowledged it.
    if client.waiting_for_interaction {
        client.waiting_for_interaction = false;
        SmcSaveYourselfDone(connection, 1);
    }
}

unsafe extern "C" fn ice_error(_connection: Connection) {
    // libICE's default handler exits the process on a lost session-manager
    // connection. A manager crash must not discard the user's pending edits.
    eprintln!("X11 session-manager connection was lost");
}

pub fn install(app: &AppHandle) -> Result<(), String> {
    let Some(network) = std::env::var_os("SESSION_MANAGER") else {
        eprintln!("no X11 session manager; OS logout protection is unavailable");
        return Ok(());
    };
    use std::os::unix::ffi::OsStrExt;
    let network = CString::new(network.as_bytes()).map_err(|e| e.to_string())?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let app_handle = app.clone();
    std::thread::Builder::new().name("sqlite-session".into()).spawn(move || {
        if let Err(e) = run(app_handle, &network, thread_stop) {
            eprintln!("could not protect unsaved changes during X11 logout: {e}");
        }
    }).map_err(|e| e.to_string())?;
    app.manage(SessionGuard(stop));
    Ok(())
}

fn run(app: AppHandle, network: &CStr, stop: Arc<AtomicBool>) -> Result<(), String> {
    let mut client = Client { app, waiting_for_interaction: false, finished: false };
    let data = &mut client as *mut Client as *mut c_void;
    let mut callbacks = Callbacks {
        save: Slot { callback: save, data }, die: Slot { callback: die, data },
        complete: Slot { callback: complete, data }, cancelled: Slot { callback: cancelled, data },
    };
    let mut id = ptr::null_mut();
    let mut error = [0 as c_char; 256];
    // SAFETY: FFI layout/signatures mirror SMlib.h and ICElib.h. libSM retains
    // callback data only until close. The connection and callbacks stay here.
    unsafe {
        IceSetIOErrorHandler(Some(ice_error));
        let connection = SmcOpenConnection(network.as_ptr() as *mut _, ptr::null_mut(), 1, 0, 15,
            &mut callbacks, ptr::null(), &mut id, error.len() as c_int, error.as_mut_ptr());
        if !id.is_null() { libc::free(id.cast()); }
        if connection.is_null() {
            return Err(CStr::from_ptr(error.as_ptr()).to_string_lossy().into_owned());
        }
        let ice = SmcGetIceConnection(connection);
        let mut fd = libc::pollfd { fd: IceConnectionNumber(ice), events: libc::POLLIN, revents: 0 };
        let result = loop {
            if stop.load(Ordering::Relaxed) || client.finished { break Ok(()); }
            let ready = libc::poll(&mut fd, 1, 250);
            if ready < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted { continue; }
                break Err(e.to_string());
            }
            if ready > 0 && IceProcessMessages(ice, ptr::null_mut(), ptr::null_mut()) != 0 {
                break Err("session-manager connection closed".into());
            }
        };
        SmcCloseConnection(connection, 0, ptr::null_mut());
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_interactive_shutdown_of_dirty_work_requests_a_veto() {
        for interact in [1, 2] {
            assert_eq!(save_action(true, true, interact, false), SaveAction::RequestInteraction);
        }
        for (dirty, shutdown, interact, fast) in [
            (false, true, 2, false), (true, false, 2, false),
            (true, true, 0, false), (true, true, 2, true),
        ] {
            assert_eq!(save_action(dirty, shutdown, interact, fast), SaveAction::Acknowledge);
        }
    }
}
