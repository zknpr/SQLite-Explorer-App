//! macOS: the app's answer to "may I terminate?".
//!
//! ⌘Q is this shell's OWN menu item (see `build_menu`) precisely so that
//! quitting can ask about unsaved databases first. That covers the menu and
//! nothing else. Every OS-INITIATED quit — Dock ▸ Quit, `osascript -e 'tell
//! application "SQLite Explorer" to quit'` (the `aevt`/`quit` Apple Event), and
//! Log Out / Restart / Shut Down — arrives as `-[NSApplication terminate:]`,
//! which never goes near the menu. Measured on a bundled debug build, such a
//! quit fires `RunEvent::Exit` **only**: `RunEvent::ExitRequested` never fires
//! at all, so by the time tauri hears anything AppKit is already tearing the
//! process down and there is nothing left to prevent. A window with an edited
//! cell simply vanished, silently. (Only a BUNDLE shows this: a bare `cargo
//! run` binary is not LaunchServices-registered, so it never receives the
//! event.)
//!
//! The one lever AppKit offers is `applicationShouldTerminate:`, asked BEFORE
//! the teardown and answerable with `NSTerminateCancel`. tao's app delegate
//! implements `applicationWillTerminate:` and not this, so the shell installs
//! it on tao's delegate class at runtime and answers with the same decision the
//! ⌘Q menu item makes — `quit_decision_for` to decide, `confirm_then_quit` to
//! ask. One policy with two entry points; a second copy would be a second
//! chance to get the silent-discard case wrong.
//!
//! Adding it AFTER `setDelegate:` has already run is sound, and that is not an
//! assumption: AppKit is known to cache which delegate methods exist when the
//! delegate is set, so it was probed first, on a runtime-built delegate class of
//! exactly tao's shape (`objc_allocateClassPair`, `setDelegate:`, and only THEN
//! `class_addMethod`). `-[NSApplication terminate:]` called the freshly added
//! IMP and honoured its `NSTerminateCancel` — no cached "does not respond", no
//! need to re-set the delegate to invalidate one.
//!
//! **Cancel-and-ask, not `NSTerminateLater`.** `NSTerminateLater` keeps the
//! terminate pending while the question is on screen, which is the nicer answer
//! during a logout (the logout waits instead of being aborted). It also parks
//! AppKit in a modal run-loop mode until someone calls
//! `replyToApplicationShouldTerminate:` — a reply that has to be marshalled
//! back to the main thread from the dialog thread, and whose absence is an app
//! that is neither alive nor quitting, with a logout wedged behind it.
//! Cancelling is a complete, self-contained answer: the app stays up with the
//! data intact, the question is asked off the main thread exactly as ⌘Q asks
//! it, and a confirm exits through the same `app.exit(0)`. The cost is that a
//! logout is aborted and has to be retried after answering; the cost of the
//! alternative failing is the user's edits or a wedged machine.
//!
//! **`app.exit(0)` does not come back through here**, so a confirmed quit
//! cannot loop and ⌘Q cannot double-prompt. tauri's exit runs
//! `ControlFlow::Exit`, which tao answers with `[NSApp stop:]` plus a dummy
//! event (tao 0.35.3, `platform_impl/macos/app_state.rs::cleared`), never with
//! `terminate:`. `stop:` unwinds `[NSApp run]`, tao then emits `LoopDestroyed`
//! — tauri's `RunEvent::Exit`, which is what reaps the sidecars — and calls
//! `process::exit`. `applicationShouldTerminate:` is sent by `terminate:`
//! alone, so the two routes never cross.

use std::ffi::CString;
use std::panic::{self, AssertUnwindSafe};
use std::sync::OnceLock;

use objc2::runtime::{AnyClass, AnyObject, Imp, Sel};
use objc2::{class, msg_send, sel, Encode, MainThreadMarker};
use tauri::{AppHandle, Manager};

use crate::{confirm_then_quit, quit_decision_for, CloseDecision, Windows};

/// `NSApplicationTerminateReply`, from AppKit's `NSApplication.h`. Spelled out
/// rather than pulled from `objc2-app-kit` so the whole hook costs one crate
/// (`objc2`, already in the tree via tao and wry) instead of the AppKit
/// bindings. `NSTerminateLater` is deliberately absent — see the module docs.
const NS_TERMINATE_CANCEL: usize = 0;
const NS_TERMINATE_NOW: usize = 1;

/// The signature AppKit calls `applicationShouldTerminate:` with:
/// `NSUInteger (id self, SEL _cmd, id sender)`. `NSUInteger` is `usize` on every
/// 64-bit Apple target.
type ShouldTerminateImp = extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject) -> usize;

/// The handle the delegate method decides from. The method is an `extern "C"`
/// function reached from AppKit, so there is no argument to carry it in and no
/// receiver to hang it off (the delegate is tao's, and its ivars are tao's).
/// Written exactly once, by `install`, before the method exists to be called.
static APP: OnceLock<AppHandle> = OnceLock::new();

/// Adds `applicationShouldTerminate:` to the live app delegate's class.
///
/// Errors instead of reporting for itself: the caller in `setup` is what turns
/// a failure into the one stderr line, so "installed" and "not installed, and
/// here is why" cannot drift apart. **Every failure is fail-OPEN** — the method
/// is simply not there, AppKit gets no answer, and a terminate proceeds exactly
/// as it does today. The app stays quittable; what is lost is the question.
pub(crate) fn install(app: &AppHandle) -> Result<(), String> {
    if APP.set(app.clone()).is_err() {
        return Err("the terminate hook is already installed".into());
    }
    // `sharedApplication` is main-thread-only, and it CREATES the singleton if
    // one does not exist yet — which would hand AppKit a plain `NSApplication`
    // in place of tao's subclass and break the event loop. Both preconditions
    // hold by construction (this runs from tauri's `setup`, on the main thread,
    // after the wry runtime has built the event loop, its `NSApplication` and
    // its delegate) and are checked anyway, because being wrong about either is
    // not something a user could diagnose from the outside.
    if MainThreadMarker::new().is_none() {
        return Err("install must run on the main thread".into());
    }
    // SAFETY: main thread, checked above. Both are plain accessors that
    // transfer no ownership; `delegate` is a borrowed reference owned by the
    // `NSApplication` singleton, which outlives everything here.
    let delegate: *mut AnyObject = unsafe {
        let ns_app: *mut AnyObject = msg_send![class!(NSApplication), sharedApplication];
        msg_send![ns_app, delegate]
    };
    // SAFETY: the pointer is either null or a live delegate, and the reference
    // does not outlive this function.
    let Some(delegate) = (unsafe { delegate.as_ref() }) else {
        return Err("NSApplication has no delegate to add the method to".into());
    };

    add_should_terminate(delegate.class())
}

/// Registers `should_terminate` on `class`, refusing to touch a class that
/// already answers the selector.
///
/// Separate from `install` so the whole of the objc-runtime work — the guard,
/// the encoding and the transmute — is reachable from a test on a throwaway
/// class, with no `NSApplication` and no GUI (see this module's tests).
fn add_should_terminate(class: &AnyClass) -> Result<(), String> {
    let selector = sel!(applicationShouldTerminate:);
    // If tao (or anything else) ever implements this itself, ITS implementation
    // wins: replacing one silently would break whatever it was doing, and this
    // shell's reason for wanting the selector — asking before discarding — is
    // exactly the kind of thing a runtime would eventually answer for itself.
    // Reported, not swallowed, because the prompt is then only as good as that
    // other implementation. `class_getInstanceMethod` searches superclasses too,
    // so an inherited implementation counts.
    //
    // SAFETY: `class` is a live, registered class.
    if !unsafe { objc2::ffi::class_getInstanceMethod(class, selector) }.is_null() {
        return Err(format!(
            "{} already implements applicationShouldTerminate:",
            class.name().to_string_lossy()
        ));
    }

    let types = method_type_encoding()?;
    // SAFETY: `should_terminate` has exactly the signature `types` describes and
    // the one AppKit sends this selector with; the transmute only erases that
    // signature to the runtime's opaque `Imp`, which is how every IMP is
    // registered. `class` is live and registered, and was just shown not to
    // implement the selector already, so nothing is being replaced.
    let added = unsafe {
        objc2::ffi::class_addMethod(
            class as *const AnyClass as *mut AnyClass,
            selector,
            std::mem::transmute::<ShouldTerminateImp, Imp>(should_terminate),
            types.as_ptr(),
        )
    };
    if !added.as_bool() {
        return Err(format!(
            "class_addMethod failed on {}",
            class.name().to_string_lossy()
        ));
    }
    Ok(())
}

/// What the runtime is told the IMP looks like: `NSUInteger (id, SEL, id)`.
///
/// Built from the Rust types rather than written out as `"Q@:@"`, so it cannot
/// drift from `ShouldTerminateImp` or from the target's pointer width — the
/// signature and its description are the one pair here that no compiler checks
/// against each other.
fn method_type_encoding() -> Result<CString, String> {
    CString::new(format!(
        "{}{}{}{}",
        usize::ENCODING,
        <*mut AnyObject>::ENCODING,
        Sel::ENCODING,
        <*mut AnyObject>::ENCODING
    ))
    .map_err(|e| format!("could not build the method type encoding: {e}"))
}

/// AppKit's question. Runs on the main thread, inside `-[NSApplication
/// terminate:]`, before any window has been told to go away.
extern "C-unwind" fn should_terminate(
    _this: &AnyObject,
    _cmd: Sel,
    _sender: *mut AnyObject,
) -> usize {
    let Some(app) = APP.get() else {
        // Unreachable: `install` fills `APP` before the method exists to be
        // called at all. Loud rather than silent, and permissive rather than
        // stuck — an app that cannot be quit is its own kind of bug.
        eprintln!("quit: no app handle to check for unsaved changes; allowing the quit");
        return NS_TERMINATE_NOW;
    };
    // `decide` locks the per-window state mutexes and spawns the dialog thread,
    // so a poisoned lock or a failed spawn is the only way it panics. What makes
    // the fallback an easy choice is what it replaces: an unwind out of here
    // goes into AppKit's own frames, which ends the process outright and takes
    // the unsaved work with it either way. Answering NOW at least exits through
    // `applicationWillTerminate:`, so `RunEvent::Exit` still reaps the sidecars
    // — strictly better than the crash, and it keeps the app quittable, which
    // the alternative (refuse forever, on state nothing can read) would not.
    panic::catch_unwind(AssertUnwindSafe(|| decide(app))).unwrap_or_else(|_| {
        eprintln!("quit: the unsaved-changes check panicked; allowing the quit");
        NS_TERMINATE_NOW
    })
}

/// The decision itself, split out so the panic boundary above stays a boundary
/// and nothing else.
fn decide(app: &AppHandle) -> usize {
    match quit_decision_for(&app.state::<Windows>()) {
        CloseDecision::Proceed => NS_TERMINATE_NOW,
        CloseDecision::Confirm { databases } => {
            // The same prompt, the same thread discipline and the same exit as
            // ⌘Q: `confirm_then_quit` shows a BLOCKING dialog on its own thread
            // (blocking on this one — we are on the main thread — deadlocks the
            // app, and the non-blocking form presents nothing from a handler
            // like this) and calls `app.exit(0)` if the user confirms.
            confirm_then_quit(app, databases);
            // Answered before the user has: the quit is refused now, and the
            // confirmed one arrives later as a fresh `app.exit(0)`. Answering
            // NOW here and asking anyway would let AppKit tear the app down
            // with the question still on screen — the bug itself.
            //
            // A quit that arrives while a prompt is ALREADY up is absorbed by
            // `confirm_then_quit` — it asks at most once app-wide — and this
            // arm still answers CANCEL: the refusal is the honest answer for
            // THIS terminate, and the question already on screen is the one
            // that will deliver the real one.
            NS_TERMINATE_CANCEL
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objc2::rc::Retained;
    use objc2::runtime::{ClassBuilder, NSObject};
    use objc2::ClassType;

    /// `NSUInteger (id self, SEL _cmd, id sender)` as the objc runtime spells
    /// it. Written out here — the one place — so that a change to
    /// `ShouldTerminateImp` has to be a deliberate one: AppKit calls this IMP
    /// through the signature in its own headers, and Rust cannot check the two
    /// against each other.
    #[test]
    fn the_registered_signature_is_the_one_appkit_calls() {
        assert_eq!(method_type_encoding().unwrap().as_bytes(), b"Q@:@");
    }

    /// The same registration path, driven end to end on a throwaway class.
    ///
    /// `class_addMethod` plus a transmute to the runtime's opaque `Imp` is the
    /// one piece of this hook that nothing type-checks. Get the signature or the
    /// encoding wrong and the failure is a garbage `NSApplicationTerminateReply`
    /// read inside AppKit's terminate path — on a machine that is, by
    /// definition, already on its way out. Proven here instead: register, send
    /// the selector through `objc_msgSend` exactly as AppKit does, and read the
    /// answer back.
    ///
    /// `APP` is unset in a test process, so the answer under test is the
    /// no-handle one — `NSTerminateNow`, the fail-open value. That is the point
    /// twice over: it exercises the ABI, and it pins that a hook with nothing to
    /// ask about never wedges the quit.
    #[test]
    fn the_added_method_answers_through_the_objc_runtime() {
        let name = CString::new(format!("SqxTerminateProbe{}", std::process::id())).unwrap();
        let probe = ClassBuilder::new(&name, NSObject::class())
            .expect("a class name nothing else has taken")
            .register();

        add_should_terminate(probe).expect("a class without the selector must take it");
        assert!(
            add_should_terminate(probe).is_err(),
            "a class that already answers must be left alone, not overwritten"
        );

        // SAFETY: `probe` is an NSObject subclass, so `new` returns an owned
        // instance of it; sending the selector matches the signature just
        // registered, and `sender` is unused by the implementation.
        let reply: usize = unsafe {
            let obj: Retained<NSObject> = msg_send![probe, new];
            msg_send![&*obj, applicationShouldTerminate: std::ptr::null_mut::<AnyObject>()]
        };
        assert_eq!(
            reply, NS_TERMINATE_NOW,
            "with no app handle the hook must let the quit through"
        );
    }
}
