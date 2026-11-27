//! The shell's messages, unsaved-changes prompts and file choosers on Linux, as
//! GTK dialogs transient for their window.
//!
//! rfd's GTK backend builds every message with a NULL parent, on a GTK thread of
//! its own, so a prompt was a free top-level window: not kept above the window
//! it asks about, not modal to it, and placed wherever the window manager liked
//! (measured on a Linux test machine: no WM_TRANSIENT_FOR). Its portal backend shows
//! messages through zenity, with no parent either. This builds the dialog on the
//! main thread, where tao runs GTK and the window lives, and hands the answer
//! back to the thread that asked.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;

/// Shows `message` on `window` and waits for the answer: `Ok(true)` only for the
/// OK button. `buttons` is `(ok, cancel)` for a question, `None` for a message
/// with one OK button. Return answers OK and Escape cancels, as the macOS sheet
/// does. Blocks, so it is called off the main thread only.
pub(crate) fn ask(
    window: &tauri::Window,
    title: &str,
    message: &str,
    warning: bool,
    buttons: Option<(&str, &str)>,
) -> Result<bool, String> {
    let (answer, answered) = mpsc::channel::<Result<bool, String>>();
    let target = window.clone();
    let title = title.to_string();
    let message = message.to_string();
    let buttons = buttons.map(|(ok, cancel)| (ok.to_string(), cancel.to_string()));
    window
        .run_on_main_thread(move || {
            if let Err(e) = present(&target, &title, &message, warning, buttons, answer.clone()) {
                let _ = answer.send(Err(e));
            }
        })
        .map_err(|e| e.to_string())?;
    answered
        .recv()
        .map_err(|_| "the dialog went away without an answer".to_string())?
}

fn present(
    window: &tauri::Window,
    title: &str,
    message: &str,
    warning: bool,
    buttons: Option<(String, String)>,
    answer: mpsc::Sender<Result<bool, String>>,
) -> Result<(), String> {
    use gtk::prelude::*;
    let parent = window.gtk_window().map_err(|e| e.to_string())?;
    let kind = if warning { gtk::MessageType::Warning } else { gtk::MessageType::Info };
    let dialog = gtk::MessageDialog::new(
        Some(&parent),
        gtk::DialogFlags::MODAL | gtk::DialogFlags::DESTROY_WITH_PARENT,
        kind,
        gtk::ButtonsType::None,
        title,
    );
    dialog.set_title(title);
    dialog.set_secondary_text(Some(message));
    let ok = match &buttons {
        Some((ok, cancel)) => {
            dialog.add_button(cancel, gtk::ResponseType::Cancel);
            dialog.add_button(ok, gtk::ResponseType::Ok)
        }
        None => dialog.add_button("OK", gtk::ResponseType::Ok),
    };
    dialog.set_default_response(gtk::ResponseType::Ok);
    let answer = RefCell::new(Some(answer));
    dialog.connect_response(move |dialog, response| {
        // Taken before the destroy, so a response the destroy itself emits finds
        // nothing to send and no borrow still open.
        let pending = answer.borrow_mut().take();
        if let Some(answer) = pending {
            let _ = answer.send(Ok(response == gtk::ResponseType::Ok));
            // SAFETY: the dialog is this module's own and nothing else holds it.
            unsafe { dialog.destroy() };
        }
    });
    dialog.show_all();
    dialog.present();
    ok.grab_focus();
    Ok(())
}

/// Whether `choose_file` opens an existing file or names one to write.
#[derive(Clone, Copy)]
pub(crate) enum FileAction {
    Open,
    Save,
}

/// Shows a file chooser on `window` and waits for the answer: the chosen path,
/// or `None` for Cancel, Escape or a closed chooser.
///
/// rfd's GTK backend builds its `GtkFileChooserNative` with a NULL parent, on its
/// own GTK thread, so the chooser was a free top-level window, neither kept above
/// the window that asked nor modal to it (measured on a Linux test machine: no
/// WM_TRANSIENT_FOR). This builds the same native chooser on the main thread,
/// transient for and modal to the window, and otherwise as rfd does: one filter
/// of `*.<extension>` patterns, default button labels (GTK translates its own),
/// and a Save chooser that proposes `file_name` and asks before replacing a
/// file. Blocks, so it is called off the main thread only.
pub(crate) fn choose_file(
    window: &tauri::Window,
    action: FileAction,
    title: Option<&str>,
    filter: Option<(&str, &[&str])>,
    file_name: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    let (answer, answered) = mpsc::channel::<Result<Option<PathBuf>, String>>();
    let target = window.clone();
    let title = title.map(str::to_string);
    let filter = filter.map(|(name, extensions)| {
        (name.to_string(), extensions.iter().map(|extension| extension.to_string()).collect::<Vec<_>>())
    });
    let file_name = file_name.map(str::to_string);
    window
        .run_on_main_thread(move || {
            if let Err(e) = present_chooser(&target, action, title, filter, file_name, answer.clone()) {
                let _ = answer.send(Err(e));
            }
        })
        .map_err(|e| e.to_string())?;
    answered
        .recv()
        .map_err(|_| "the file dialog went away without an answer".to_string())?
}

fn present_chooser(
    window: &tauri::Window,
    action: FileAction,
    title: Option<String>,
    filter: Option<(String, Vec<String>)>,
    file_name: Option<String>,
    answer: mpsc::Sender<Result<Option<PathBuf>, String>>,
) -> Result<(), String> {
    use gtk::prelude::*;
    let parent = window.gtk_window().map_err(|e| e.to_string())?;
    let (kind, default_title) = match action {
        FileAction::Open => (gtk::FileChooserAction::Open, "Open File"),
        FileAction::Save => (gtk::FileChooserAction::Save, "Save File"),
    };
    let chooser = gtk::FileChooserNative::new(Some(title.as_deref().unwrap_or(default_title)), Some(&parent), kind, None, None);
    chooser.set_modal(true);
    if let Some((name, extensions)) = filter {
        let patterns = gtk::FileFilter::new();
        patterns.set_name(Some(&name));
        for extension in &extensions {
            patterns.add_pattern(&format!("*.{extension}"));
        }
        chooser.add_filter(patterns);
    }
    if let FileAction::Save = action {
        chooser.set_do_overwrite_confirmation(true);
        if let Some(name) = &file_name {
            chooser.set_current_name(name);
        }
    }
    // GTK does not keep a native dialog alive (it is not a toplevel, unlike a
    // GtkDialog): this reference does, until the response drops it.
    let held = Rc::new(RefCell::new(Some(chooser.clone())));
    let answer = RefCell::new(Some(answer));
    chooser.connect_response(move |chooser, response| {
        // Taken first, so a second response finds nothing to send.
        let pending = answer.borrow_mut().take();
        if let Some(answer) = pending {
            let chosen = if response == gtk::ResponseType::Accept { chooser.filename() } else { None };
            let _ = answer.send(Ok(chosen));
        }
        held.borrow_mut().take();
    });
    chooser.show();
    Ok(())
}
