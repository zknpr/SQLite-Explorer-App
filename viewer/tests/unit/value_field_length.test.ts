import './vscode_mock_setup';

/**
 * Batch Update and Add Row values reach the worker call exactly as entered,
 * whatever their length, on WebKit too.
 *
 * The DOM here models what the system WKWebView measured (WebKit 22625,
 * macOS 27.2.1): an <input type="text"> kept 524,288 characters of a longer
 * value, by assignment and through the insertText editing command alike, and
 * dropped CR and LF; a <textarea> kept 16,777,216 assigned characters whole
 * and read CR LF back as LF; a textarea's type property is read-only. Chromium
 * 146 kept an input's value whole, so only the WebKit model can show a value
 * cut short.
 */
import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert';

(globalThis as any).acquireVsCodeApi = () => ({
    getState: () => undefined,
    setState() {},
    postMessage() {}
});

const stateModulePath = '../../core/ui/modules/state.js';
const apiModulePath = '../../core/ui/modules/api.js';
const sidebarModulePath = '../../core/ui/modules/sidebar.js';
const crudModulePath = '../../core/ui/modules/crud.js';
const modalsModulePath = '../../core/ui/modules/modals.js';
const textEditorModulePath = '../../core/ui/modules/text-editor.js';

const WEBKIT_INPUT_LIMIT = 524288;
const LONG = 1_000_000;

function createClassList(initial: string[] = []) {
    const classes = new Set(initial);
    return {
        add: (...names: string[]) => names.forEach(name => classes.add(name)),
        remove: (...names: string[]) => names.forEach(name => classes.delete(name)),
        contains: (name: string) => classes.has(name)
    };
}

function element(tagName: string, engine: 'webkit' | 'chromium'): any {
    const node: any = {
        tagName: tagName.toUpperCase(),
        id: '', textContent: '', hidden: false, checked: false, disabled: false,
        placeholder: '', title: '', className: '', htmlFor: '', ariaLabel: '',
        dataset: {} as Record<string, string>,
        style: {} as Record<string, string>,
        classList: createClassList(),
        children: [] as any[],
        isFragment: tagName === '#fragment',
        appendChild(child: any) {
            if (child?.isFragment) this.children.push(...child.children);
            else this.children.push(child);
            return child;
        },
        replaceChildren(...children: any[]) { this.children = [...children]; },
        setAttribute(name: string, value: string) { this[name] = value; },
        addEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
        focus() {}
    };
    let value = '';
    if (tagName === 'input') {
        node.type = 'text';
        Object.defineProperty(node, 'value', {
            get: () => value,
            set: (next: unknown) => {
                const text = String(next).replace(/[\r\n]/g, '');
                value = engine === 'webkit' ? text.slice(0, WEBKIT_INPUT_LIMIT) : text;
            }
        });
    } else if (tagName === 'textarea') {
        Object.defineProperty(node, 'type', { get: () => 'textarea' });
        Object.defineProperty(node, 'value', {
            get: () => value,
            set: (next: unknown) => { value = String(next).replace(/\r\n?/g, '\n'); }
        });
    } else {
        node.value = '';
    }
    return node;
}

function findNode(root: any, predicate: (node: any) => boolean): any {
    if (predicate(root)) return root;
    for (const child of root.children ?? []) {
        const match = findNode(child, predicate);
        if (match) return match;
    }
    return undefined;
}

function installDocument(engine: 'webkit' | 'chromium', extra: Record<string, any> = {}) {
    const listeners = new Map<string, (event: any) => void>();
    const elements: Record<string, any> = {
        sidebarPanel: Object.assign(element('div', engine), {
            addEventListener(type: string, listener: (event: any) => void) { listeners.set(type, listener); }
        }),
        batchUpdateSectionTitle: element('button', engine),
        batchUpdateList: element('div', engine),
        batchUpdateCount: element('span', engine),
        batchUpdateFields: element('div', engine),
        btnApplyBatchUpdate: element('button', engine),
        statusText: element('span', engine),
        addRowForm: element('div', engine),
        addRowModal: Object.assign(element('div', engine), { id: 'addRowModal', classList: createClassList(['modal-overlay', 'hidden']) }),
        ...extra
    };
    let queryAll = (_selector: string): any[] => [];
    (globalThis as any).document = {
        activeElement: null,
        getElementById(id: string) { return elements[id] ?? null; },
        querySelector() { return null; },
        querySelectorAll(selector: string) { return queryAll(selector); },
        createElement(tagName: string) { return element(tagName, engine); },
        createTextNode(text: string) { return Object.assign(element('#text', engine), { textContent: text }); },
        createDocumentFragment() { return element('#fragment', engine); }
    };
    return { elements, listeners, setQueryAll(impl: (selector: string) => any[]) { queryAll = impl; } };
}

async function prepareState() {
    const { state } = await import(stateModulePath);
    Object.assign(state, {
        isReadOnly: false, isGridReloading: false, selectedTable: 'items', selectedTableType: 'table',
        selectedTableIdentity: null, tableColumns: [{ name: 'payload', type: 'TEXT', notnull: 0 }],
        gridData: [[7, 'before']], gridExactIntegerTexts: {}, gridOversizedCells: {}, gridReadOnlyRowReasons: {},
        selectedCells: [{ rowIdx: 0, colIdx: 0, rowId: 7, value: 'before' }],
        selectedRowIds: new Set(), selectedColumns: new Set()
    });
    return state;
}

async function captureCall<T>(method: string, run: () => Promise<unknown>): Promise<unknown[] | undefined> {
    const { backendApi } = await import(apiModulePath);
    const original = backendApi[method];
    const originalConsoleError = console.error;
    let captured: unknown[] | undefined;
    // Stop right after the call: what reached it is the whole question here.
    backendApi[method] = async (...args: unknown[]) => { captured = args; throw new Error('captured'); };
    console.error = () => {};
    try {
        await run();
    } finally {
        backendApi[method] = original;
        console.error = originalConsoleError;
    }
    return captured;
}

function keydown(key: string, shiftKey = false) {
    let prevented = false;
    return { event: { key, shiftKey, isComposing: false, preventDefault() { prevented = true; } }, prevented: () => prevented };
}

describe('Batch Update and Add Row values of any length', () => {
    afterEach(async () => {
        const { closeModal } = await import(modalsModulePath);
        closeModal('addRowModal', null, { restoreFocus: false });
        closeModal('addColumnModal', null, { restoreFocus: false });
        closeModal('createTableModal', null, { restoreFocus: false });
        delete (globalThis as any).document;
        const { state } = await import(stateModulePath);
        Object.assign(state, { selectedTable: null, tableColumns: [], gridData: [], selectedCells: [] });
    });

    it('carries a 1,000,000-character Batch Update value to the worker whole', async () => {
        const dom = installDocument('webkit');
        await prepareState();
        const { initSidebar, updateBatchSidebar, applyBatchUpdate } = await import(sidebarModulePath);
        initSidebar();
        updateBatchSidebar();
        const field = findNode(dom.elements.batchUpdateFields, node => node.className === 'batch-input');
        assert.ok(field, 'Batch Update renders a value field');
        dom.setQueryAll(selector => selector === '.batch-input' ? [field] : []);
        field.value = 'v'.repeat(LONG);
        dom.listeners.get('input')!({ target: { ...field, closest: () => field } });

        const call = await captureCall('updateCellBatch', () => applyBatchUpdate());
        assert.ok(call, 'the batch update reached the worker call');
        const [, updates] = call as [string, Array<{ value: string }>];
        assert.strictEqual(updates[0].value.length, LONG);
        assert.strictEqual(field.tagName, 'TEXTAREA');
        assert.strictEqual(field.rows, 1);
    });

    it('carries a 1,000,000-character Add Row value to the worker whole', async () => {
        const dom = installDocument('webkit');
        await prepareState();
        const { openAddRowModal, submitAddRow } = await import(crudModulePath);
        openAddRowModal();
        const field = findNode(dom.elements.addRowForm, node => node.dataset?.column === 'payload');
        assert.ok(field, 'Add Row renders a value field');
        dom.setQueryAll(selector => selector.startsWith('#addRowForm') ? [field] : []);
        field.value = 'w'.repeat(LONG);
        field.oninput?.();

        const call = await captureCall('insertRow', () => submitAddRow());
        assert.ok(call, 'the insert reached the worker call');
        const [, row] = call as [string, Record<string, string>];
        assert.strictEqual(row.payload.length, LONG);
        assert.strictEqual(field.tagName, 'TEXTAREA');
        assert.strictEqual(field.rows, 1);
    });

    it('keeps plain Enter from adding a line break to a one-row value field', async () => {
        const dom = installDocument('webkit');
        await prepareState();
        const { initSidebar, updateBatchSidebar } = await import(sidebarModulePath);
        const { openAddRowModal } = await import(crudModulePath);
        initSidebar();
        updateBatchSidebar();
        openAddRowModal();
        const batchField = findNode(dom.elements.batchUpdateFields, node => node.className === 'batch-input');
        const addRowField = findNode(dom.elements.addRowForm, node => node.dataset?.column === 'payload');
        const onBatchKeydown = dom.listeners.get('keydown');
        assert.ok(onBatchKeydown, 'Batch Update fields need a keydown handler');
        assert.strictEqual(typeof addRowField.onkeydown, 'function', 'Add Row fields need a keydown handler');

        for (const dispatch of [
            (event: any) => onBatchKeydown!({ ...event, target: { closest: (s: string) => s === '.batch-input' ? batchField : null } }),
            (event: any) => addRowField.onkeydown(event)
        ]) {
            const enter = keydown('Enter');
            dispatch(enter.event);
            assert.strictEqual(enter.prevented(), true, 'Enter must not start a second line');
            const shiftEnter = keydown('Enter', true);
            dispatch(shiftEnter.event);
            assert.strictEqual(shiftEnter.prevented(), false, 'Shift+Enter still adds a line break');
        }
    });

    it('refuses an Add Column default that reaches the input limit of an engine that has one', async () => {
        const name = element('input', 'webkit');
        const defaultField = element('input', 'webkit');
        const { elements } = installDocument('webkit', {
            addColumnModal: Object.assign(element('div', 'webkit'), { id: 'addColumnModal', classList: createClassList(['modal-overlay', 'hidden']) }),
            addColumnModalError: Object.assign(element('div', 'webkit'), { hidden: true }),
            newColumnName: name,
            newColumnType: element('select', 'webkit'),
            newColumnDefault: defaultField
        });
        await prepareState();
        const { openAddColumnModal, submitAddColumn } = await import(crudModulePath);
        openAddColumnModal();
        name.value = 'notes';
        defaultField.value = 'd'.repeat(600_000);
        assert.strictEqual(defaultField.value.length, WEBKIT_INPUT_LIMIT);

        const call = await captureCall('addColumn', () => submitAddColumn());
        assert.strictEqual(call, undefined, 'a default that may have been cut must not reach the worker');
        assert.strictEqual(elements.addColumnModalError.hidden, false);
        assert.match(elements.addColumnModalError.textContent, /524,288/);
    });

    it('refuses a Create Table default that reaches the input limit of an engine that has one', async () => {
        const tableName = element('input', 'webkit');
        const dom = installDocument('webkit', {
            createTableModal: Object.assign(element('div', 'webkit'), { id: 'createTableModal', classList: createClassList(['modal-overlay', 'hidden']) }),
            createTableModalError: Object.assign(element('div', 'webkit'), { hidden: true }),
            newTableName: tableName,
            newTableWithoutRowid: element('input', 'webkit'),
            columnDefinitions: element('div', 'webkit')
        });
        await prepareState();
        const { openCreateTableModal, submitCreateTable } = await import(crudModulePath);
        openCreateTableModal();
        tableName.value = 'notes';
        const defaultField = element('input', 'webkit');
        defaultField.value = 'd'.repeat(600_000);
        const row = {
            querySelector(selector: string) {
                if (selector === '.col-name') return { value: 'body' };
                if (selector === '.col-type') return { value: 'TEXT' };
                if (selector === '.col-pk') return { checked: false };
                if (selector === '.col-nn') return { checked: false };
                if (selector === '.col-default') return defaultField;
                return null;
            }
        };
        dom.setQueryAll(selector => selector === '.column-def-row' ? [row] : []);

        const call = await captureCall('createTable', () => submitCreateTable());
        assert.strictEqual(call, undefined, 'a default that may have been cut must not reach the worker');
        assert.strictEqual(dom.elements.createTableModalError.hidden, false);
        assert.match(dom.elements.createTableModalError.textContent, /524,288/);
    });

    it('accepts an Add Column default of that length where inputs keep it whole', async () => {
        const name = element('input', 'chromium');
        const defaultField = element('input', 'chromium');
        installDocument('chromium', {
            addColumnModal: Object.assign(element('div', 'chromium'), { id: 'addColumnModal', classList: createClassList(['modal-overlay', 'hidden']) }),
            newColumnName: name,
            newColumnType: element('select', 'chromium'),
            newColumnDefault: defaultField
        });
        await prepareState();
        const { openAddColumnModal, submitAddColumn } = await import(crudModulePath);
        openAddColumnModal();
        name.value = 'notes';
        defaultField.value = 'd'.repeat(600_000);

        const call = await captureCall('addColumn', () => submitAddColumn());
        assert.ok(call, 'the add reached the worker call');
        assert.strictEqual((call as [string, string, string, string])[3].length, 600_000);
    });
});

describe('pasting into the one-row value fields', () => {
    afterEach(async () => {
        const { closeModal } = await import(modalsModulePath);
        closeModal('addRowModal', null, { restoreFocus: false });
        delete (globalThis as any).document;
        const { state } = await import(stateModulePath);
        Object.assign(state, { selectedTable: null, tableColumns: [], gridData: [], selectedCells: [] });
    });

    /**
     * A paste as the browser runs it: the page's paste handler first; unless
     * it prevented the default, the browser inserts the clipboard text (with
     * CR LF and CR read as LF, as both engines measured) and fires the input
     * event, whose listeners run in the same task. document.execCommand
     * stands in for the editing commands (insertText, delete) a handler can
     * use; setRangeText, setSelectionRange and dispatchEvent for the rest.
     */
    function paste(field: any, text: string, handler: ((event: any) => void) | undefined, onInput: () => void) {
        let prevented = false;
        let inputs = 0;
        const edits: string[] = [];
        const commands: string[] = [];
        field.inputListeners ??= [];
        field.addEventListener = (type: string, listener: () => void) => {
            if (type === 'input') field.inputListeners.push(listener);
        };
        field.removeEventListener = (type: string, listener: () => void) => {
            if (type === 'input') field.inputListeners = field.inputListeners.filter((l: () => void) => l !== listener);
        };
        const announce = () => {
            inputs++;
            onInput();
            for (const listener of [...field.inputListeners]) listener();
        };
        if (typeof field.selectionStart !== 'number') field.selectionStart = field.selectionEnd = field.value.length;
        field.setSelectionRange = (start: number, end: number) => {
            field.selectionStart = start;
            field.selectionEnd = end;
        };
        field.setRangeText = (inserted: string, start: number, end: number, mode: string) => {
            assert.strictEqual(mode, 'end');
            field.value = field.value.slice(0, start) + inserted + field.value.slice(end);
            field.selectionStart = field.selectionEnd = start + inserted.length;
        };
        field.dispatchEvent = (event: { type: string }) => {
            if (event.type === 'input') announce();
            return true;
        };
        (globalThis as any).document.execCommand = (command: string, _ui: boolean, value: string) => {
            commands.push(command);
            if (command === 'insertText') {
                edits.push(value);
                field.setRangeText(value, field.selectionStart, field.selectionEnd, 'end');
            } else {
                assert.strictEqual(command, 'delete');
                assert.notStrictEqual(field.selectionStart, field.selectionEnd, 'delete is only ever given a selection');
                field.setRangeText('', field.selectionStart, field.selectionEnd, 'end');
            }
            announce();
            return true;
        };
        handler?.({
            target: field,
            clipboardData: { getData: (type: string) => (type === 'text/plain' ? text : '') },
            preventDefault() { prevented = true; }
        });
        if (!prevented) {
            field.setRangeText(text.replace(/\r\n?/g, '\n'), field.selectionStart, field.selectionEnd, 'end');
            announce();
        }
        return { edits, commands, inputs, prevented };
    }

    it('stores a Batch Update paste without its trailing CR LF', async () => {
        const dom = installDocument('webkit');
        await prepareState();
        const { initSidebar, updateBatchSidebar, applyBatchUpdate } = await import(sidebarModulePath);
        initSidebar();
        updateBatchSidebar();
        const field = findNode(dom.elements.batchUpdateFields, node => node.className === 'batch-input');
        dom.setQueryAll(selector => selector === '.batch-input' ? [field] : []);
        const onPaste = dom.listeners.get('paste');
        const target = { ...field, closest: () => field };
        paste(field, 'value\r\n', onPaste && (event => onPaste({ ...event, target })),
            () => dom.listeners.get('input')!({ target }));

        const call = await captureCall('updateCellBatch', () => applyBatchUpdate());
        assert.ok(call, 'the batch update reached the worker call');
        assert.strictEqual(JSON.stringify((call as [string, Array<{ value: string }>])[1][0].value), JSON.stringify('value'));
    });

    it('stores an Add Row paste without its trailing line break and keeps the ones inside', async () => {
        for (const [pasted, stored] of [
            ['line one\nline two', 'line one\nline two'],
            ['line one\nline two\r\n', 'line one\nline two'],
            ['tab\tseparated\n', 'tab\tseparated'],
            ['two breaks\r\n\r\n', 'two breaks'],
            ['\nleading and trailing\n\n', '\nleading and trailing']
        ]) {
            const dom = installDocument('webkit');
            await prepareState();
            const { openAddRowModal, submitAddRow } = await import(crudModulePath);
            const { closeModal } = await import(modalsModulePath);
            openAddRowModal();
            const field = findNode(dom.elements.addRowForm, node => node.dataset?.column === 'payload');
            dom.setQueryAll(selector => selector.startsWith('#addRowForm') ? [field] : []);
            paste(field, pasted, field.onpaste, () => field.oninput?.());

            const call = await captureCall('insertRow', () => submitAddRow());
            assert.ok(call, 'the insert reached the worker call');
            assert.strictEqual(JSON.stringify((call as [string, Record<string, string>])[1].payload), JSON.stringify(stored),
                'pasted ' + JSON.stringify(pasted));
            closeModal('addRowModal', null, { restoreFocus: false });
        }
    });

    it('keeps typed text around a pasted value, and a paste of line breaks only inserts nothing', async () => {
        const dom = installDocument('webkit');
        await prepareState();
        const { openAddRowModal, submitAddRow } = await import(crudModulePath);
        openAddRowModal();
        const field = findNode(dom.elements.addRowForm, node => node.dataset?.column === 'payload');
        dom.setQueryAll(selector => selector.startsWith('#addRowForm') ? [field] : []);
        field.value = 'typed hello';
        field.oninput?.();
        // Over a selection it removes the selection, as the input did.
        field.selectionStart = 7;
        field.selectionEnd = 10;
        paste(field, '\r\n', field.onpaste, () => field.oninput?.());
        assert.strictEqual(field.value, 'typed ho');
        field.value = 'typed ';
        field.selectionStart = field.selectionEnd = 6;
        paste(field, '\n\n', field.onpaste, () => field.oninput?.());
        paste(field, 'pasted\n', field.onpaste, () => field.oninput?.());

        const call = await captureCall('insertRow', () => submitAddRow());
        assert.strictEqual(JSON.stringify((call as [string, Record<string, string>])[1].payload), JSON.stringify('typed pasted'));
    });

    it('lets the browser paste a 4,000-line text and deletes its trailing line break as one more edit', async () => {
        const dom = installDocument('webkit');
        await prepareState();
        const { openAddRowModal, submitAddRow } = await import(crudModulePath);
        openAddRowModal();
        const field = findNode(dom.elements.addRowForm, node => node.dataset?.column === 'payload');
        dom.setQueryAll(selector => selector.startsWith('#addRowForm') ? [field] : []);
        field.value = 'typed ';
        field.selectionStart = field.selectionEnd = 6;
        const rows = Array.from({ length: 4000 }, (_, index) => 'row' + index).join('\n');
        const { edits, commands, inputs, prevented } = paste(field, rows + '\r\n', field.onpaste, () => field.oninput?.());

        // insertText inserts a multi-line text line by line, in time that
        // grows with the square of the line count; a value set from script
        // leaves the browser's undo history pointing at text no longer there.
        assert.strictEqual(prevented, false, 'the browser pastes a multi-line text itself');
        assert.deepStrictEqual(edits, []);
        assert.deepStrictEqual(commands, ['delete'], 'the trailing line break goes out through the editing command');
        assert.strictEqual(inputs, 2);
        const call = await captureCall('insertRow', () => submitAddRow());
        assert.strictEqual((call as [string, Record<string, string>])[1].payload, 'typed ' + rows);
    });

    it('leaves a line break typed after a paste the browser did not perform', async () => {
        const { pasteWithoutTrailingLineBreak } = await import(textEditorModulePath);
        const listeners: Array<() => void> = [];
        const field: any = {
            value: 'kept', selectionStart: 4, selectionEnd: 4,
            addEventListener(_type: string, listener: () => void) { listeners.push(listener); },
            removeEventListener(_type: string, listener: () => void) { listeners.splice(listeners.indexOf(listener), 1); }
        };
        (globalThis as any).document = { execCommand: () => { throw new Error('no edit expected'); } };
        pasteWithoutTrailingLineBreak({
            target: field,
            clipboardData: { getData: () => 'a\nb\n' },
            preventDefault() { throw new Error('a multi-line paste is the browser\'s own'); }
        });
        // No input event in the paste's task (a read-only field, say); the
        // next one is typing and must not lose its line break.
        await new Promise(resolve => setTimeout(resolve, 0));
        assert.deepStrictEqual(listeners, []);
    });

    it('splices the trailing line break out where the editing command is unavailable', async () => {
        const { pasteWithoutTrailingLineBreak } = await import(textEditorModulePath);
        const listeners: Array<() => void> = [];
        const fired: string[] = [];
        const field: any = {
            value: '', selectionStart: 0, selectionEnd: 0,
            addEventListener(_type: string, listener: () => void) { listeners.push(listener); },
            removeEventListener(_type: string, listener: () => void) { listeners.splice(listeners.indexOf(listener), 1); },
            setSelectionRange(start: number, end: number) { this.selectionStart = start; this.selectionEnd = end; },
            setRangeText(text: string, start: number, end: number) {
                this.value = this.value.slice(0, start) + text + this.value.slice(end);
                this.selectionStart = this.selectionEnd = start + text.length;
            },
            dispatchEvent(event: { type: string }) { fired.push(event.type); return true; }
        };
        (globalThis as any).document = { execCommand: () => false };
        pasteWithoutTrailingLineBreak({
            target: field,
            clipboardData: { getData: () => 'a\nb\n\n' },
            preventDefault() { throw new Error('a multi-line paste is the browser\'s own'); }
        });
        field.value = 'a\nb\n\n';
        field.selectionStart = field.selectionEnd = 5;
        for (const listener of [...listeners]) listener();
        assert.strictEqual(field.value, 'a\nb');
        assert.deepStrictEqual(fired, ['input']);
    });

    it('splices the pasted value in where the editing command is unavailable', async () => {
        const { pasteWithoutTrailingLineBreak } = await import(textEditorModulePath);
        const fired: string[] = [];
        const field = {
            value: 'ab',
            selectionStart: 1,
            selectionEnd: 1,
            setRangeText(text: string, start: number, end: number, mode: string) {
                assert.strictEqual(mode, 'end');
                this.value = this.value.slice(0, start) + text + this.value.slice(end);
            },
            dispatchEvent(event: { type: string; bubbles: boolean }) {
                fired.push(event.type + (event.bubbles ? ' (bubbles)' : ''));
                return true;
            }
        };
        (globalThis as any).document = { execCommand: () => false };
        let prevented = false;
        pasteWithoutTrailingLineBreak({
            target: field,
            clipboardData: { getData: () => 'X\r\n' },
            preventDefault() { prevented = true; }
        });
        assert.strictEqual(prevented, true);
        assert.strictEqual(field.value, 'aXb');
        assert.deepStrictEqual(fired, ['input (bubbles)']);
    });
});

