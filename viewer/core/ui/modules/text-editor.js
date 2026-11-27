const DEFAULT_INDENT = '    ';
const focusEscapeArmed = new WeakSet();

/** Clear the one-shot focus escape when a static textarea starts a new session. */
export function resetTextareaTabFocusEscape(textarea) {
    if (textarea) focusEscapeArmed.delete(textarea);
}

function clampPosition(value, position) {
    return Math.max(0, Math.min(value.length, Number.isFinite(position) ? position : 0));
}

function getSelectedLineStarts(value, selectionStart, selectionEnd) {
    const firstLineStart = value.lastIndexOf('\n', Math.max(0, selectionStart - 1)) + 1;
    // A selection ending immediately after a newline does not include the next
    // line. This matches the indentation behavior users expect from code editors.
    const effectiveEnd = selectionEnd > selectionStart && value[selectionEnd - 1] === '\n'
        ? selectionEnd - 1
        : selectionEnd;
    const starts = [firstLineStart];
    let newline = value.indexOf('\n', firstLineStart);
    while (newline !== -1 && newline + 1 <= effectiveEnd) {
        starts.push(newline + 1);
        newline = value.indexOf('\n', newline + 1);
    }
    return starts;
}

function mapPositionThroughEdits(position, edits) {
    let delta = 0;
    for (const edit of edits) {
        if (position < edit.start) break;
        if (position <= edit.start + edit.deleteCount) {
            return edit.start + delta + edit.text.length;
        }
        delta += edit.text.length - edit.deleteCount;
    }
    return position + delta;
}

function applyEdits(value, edits) {
    let result = '';
    let cursor = 0;
    for (const edit of edits) {
        result += value.slice(cursor, edit.start);
        result += edit.text;
        cursor = edit.start + edit.deleteCount;
    }
    return result + value.slice(cursor);
}

/** Apply code-editor Tab/Shift+Tab behavior to a textarea key event. */
export function handleTextareaTab(event, indent = DEFAULT_INDENT) {
    const textarea = event.target;
    if (!textarea || textarea.readOnly || textarea.disabled || typeof textarea.value !== 'string') {
        return false;
    }

    // A code editor normally consumes Tab, so use the first Escape as a
    // one-shot "Tab moves focus" command. A second Escape retains the modal's
    // normal close behavior, and editing any other key cancels the armed state.
    if (event.key === 'Escape') {
        if (focusEscapeArmed.has(textarea)) {
            focusEscapeArmed.delete(textarea);
            return false;
        }
        focusEscapeArmed.add(textarea);
        event.preventDefault();
        event.stopPropagation();
        return true;
    }
    if (event.key !== 'Tab') {
        // A real Shift+Tab sends a Shift keydown first. It must not consume
        // the one-shot escape before the browser receives the Tab key.
        if (['Shift', 'Control', 'Alt', 'Meta'].includes(event.key)) return false;
        focusEscapeArmed.delete(textarea);
        return false;
    }
    if (focusEscapeArmed.has(textarea)) {
        focusEscapeArmed.delete(textarea);
        return false;
    }

    const value = textarea.value;
    const selectionStart = clampPosition(value, textarea.selectionStart);
    const selectionEnd = clampPosition(value, textarea.selectionEnd);
    let edits;

    if (!event.shiftKey && selectionStart === selectionEnd) {
        edits = [{ start: selectionStart, deleteCount: 0, text: indent }];
    } else {
        const lineStarts = getSelectedLineStarts(value, selectionStart, selectionEnd);
        if (event.shiftKey) {
            edits = lineStarts.map(start => {
                if (value[start] === '\t') {
                    return { start, deleteCount: 1, text: '' };
                }
                const spaces = value.slice(start, start + indent.length).match(/^ +/)?.[0].length ?? 0;
                return { start, deleteCount: spaces, text: '' };
            }).filter(edit => edit.deleteCount > 0);
        } else {
            edits = lineStarts.map(start => ({ start, deleteCount: 0, text: indent }));
        }
    }

    event.preventDefault();
    if (edits.length > 0) {
        textarea.value = applyEdits(value, edits);
        textarea.selectionStart = mapPositionThroughEdits(selectionStart, edits);
        textarea.selectionEnd = mapPositionThroughEdits(selectionEnd, edits);
        if (typeof Event === 'function' && typeof textarea.dispatchEvent === 'function') {
            textarea.dispatchEvent(new Event('input', { bubbles: true }));
        }
    }
    return true;
}

/**
 * keydown for a one-row value <textarea> that stands in for a text <input>
 * (Batch Update, Add Row): plain Enter adds no line break, as in the input it
 * replaced. Shift+Enter still adds one, as in the grid's cell editor, and a
 * pasted value keeps its line breaks.
 */
export function keepEnterSingleLine(event) {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) event.preventDefault();
}

/**
 * paste for the same one-row value fields: the line breaks that end the text
 * are dropped. A spreadsheet copy ends rows with one (LibreOffice ends every
 * row of a multi-cell copy so; Excel, by user reports, a single cell too).
 * The input these fields replaced dropped them all, and a one-row field would
 * store them out of sight. Line breaks inside the text and typed text stay; a
 * paste of line breaks alone inserts nothing, and replaces a selection with
 * nothing, as the input did.
 *
 * Every change goes through the browser's editing commands, so undo and redo
 * stay coherent: a value set from script (setRangeText, value) leaves the
 * native undo history pointing at text that is no longer there.
 */
export function pasteWithoutTrailingLineBreak(event) {
    const text = event.clipboardData?.getData('text/plain');
    if (typeof text !== 'string') return;
    // A scan, not a regex: a backtracking (?:\r\n|\r|\n)+$ is quadratic on a
    // long run of line breaks that does not end the text.
    let end = text.length;
    while (end > 0 && (text[end - 1] === '\n' || text[end - 1] === '\r')) end--;
    if (end === text.length) return;
    const trimmed = text.slice(0, end);
    const field = event.target;
    if (/[\r\n]/.test(trimmed)) {
        // insertText would insert this one line at a time, in time that grows
        // with the square of the line count (41 s for 4,000 lines in
        // WKWebView). The browser's own paste inserts it in one edit; the line
        // breaks it leaves at the end are then deleted as one more edit, which
        // the first undo restores and the second takes the paste back.
        const start = Math.min(field.selectionStart, field.selectionEnd);
        const afterPaste = () => {
            field.removeEventListener('input', afterPaste);
            const caret = field.selectionEnd;
            let from = caret;
            while (from > start && (field.value[from - 1] === '\n' || field.value[from - 1] === '\r')) from--;
            if (from < caret) deleteRange(field, from, caret);
        };
        field.addEventListener('input', afterPaste);
        // The paste's input event arrives in this task; never take a later one.
        setTimeout(() => field.removeEventListener('input', afterPaste), 0);
        return;
    }
    event.preventDefault();
    if (trimmed === '') {
        if (field.selectionStart !== field.selectionEnd) {
            deleteRange(field, field.selectionStart, field.selectionEnd);
        }
        return;
    }
    if (document.execCommand?.('insertText', false, trimmed)) return;
    field.setRangeText(trimmed, field.selectionStart, field.selectionEnd, 'end');
    field.dispatchEvent(new Event('input', { bubbles: true }));
}

/** Delete [from, to) of a field as an undoable edit where the browser has one. */
function deleteRange(field, from, to) {
    field.setSelectionRange(from, to);
    if (document.execCommand?.('delete')) return;
    field.setRangeText('', from, to, 'end');
    field.dispatchEvent(new Event('input', { bubbles: true }));
}
