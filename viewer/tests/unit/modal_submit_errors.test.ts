import './vscode_mock_setup';

/**
 * A submit modal that stays open after a failed or refused submission shows
 * the reason INSIDE itself (its '<modalId>Error' line, role="alert"), and
 * mirrors it to the status bar. The status bar sits behind every modal
 * overlay and clips to one line, so a reason written only there leaves the
 * dialog open with no visible answer.
 */
import { afterEach, describe, it } from 'node:test';
import assert from 'node:assert';
import { readFileSync } from 'node:fs';
import path from 'node:path';

(globalThis as any).acquireVsCodeApi = () => ({
    getState: () => undefined,
    setState() {},
    postMessage() {}
});

const stateModulePath = '../../core/ui/modules/state.js';
const apiModulePath = '../../core/ui/modules/api.js';
const crudModulePath = '../../core/ui/modules/crud.js';
const exportModulePath = '../../core/ui/modules/export.js';
const editModulePath = '../../core/ui/modules/edit.js';
const settingsModulePath = '../../core/ui/modules/settings.js';
const modalsModulePath = '../../core/ui/modules/modals.js';
const blobInspectorModulePath = '../../core/ui/modules/blob-inspector.js';

const UNDO_REFUSAL = 'Deleting 10 rows from t needs 5242880 bytes of undo memory; the limit is '
    + '1048576 bytes. Delete fewer rows at a time, or raise the undo memory limit. Nothing was deleted.';

function createClassList(initial: string[] = []) {
    const classes = new Set(initial);
    return {
        add: (...names: string[]) => names.forEach(name => classes.add(name)),
        remove: (...names: string[]) => names.forEach(name => classes.delete(name)),
        contains: (name: string) => classes.has(name),
        toggle: (name: string, force?: boolean) => {
            const enabled = force ?? !classes.has(name);
            if (enabled) classes.add(name); else classes.delete(name);
            return enabled;
        }
    };
}

function node(tagName = 'div'): any {
    return {
        tagName: tagName.toUpperCase(),
        id: '',
        textContent: '',
        hidden: false,
        value: '',
        checked: false,
        disabled: false,
        placeholder: '',
        title: '',
        className: '',
        type: '',
        dataset: {} as Record<string, string>,
        style: {} as Record<string, string>,
        classList: createClassList(),
        children: [] as any[],
        appendChild(child: any) { this.children.push(child); return child; },
        append(...children: any[]) { this.children.push(...children); },
        replaceChildren(...children: any[]) { this.children = [...children]; },
        setAttribute(name: string, value: string) { this[name] = value; },
        addEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
        focus() {}
    };
}

/** Each modal starts closed, with its error line; plus the status bar. */
function installModalDocument(modalIds: string[], extra: Record<string, any> = {}) {
    const elements: Record<string, any> = { statusText: node('span'), ...extra };
    for (const modalId of modalIds) {
        elements[modalId] = node();
        elements[modalId].id = modalId;
        elements[modalId].classList = createClassList(['modal-overlay', 'hidden']);
        elements[modalId + 'Error'] = node();
        elements[modalId + 'Error'].id = modalId + 'Error';
        elements[modalId + 'Error'].hidden = true;
    }
    const created: any[] = [];
    let querySelectorAllImpl = (_selector: string): any[] => [];
    (globalThis as any).document = {
        activeElement: null,
        getElementById(id: string) { return elements[id] ?? null; },
        querySelector() { return null; },
        querySelectorAll(selector: string) { return querySelectorAllImpl(selector); },
        createElement(tagName: string) {
            const element = node(tagName);
            created.push(element);
            return element;
        },
        createTextNode(text: string) {
            const element = node('#text');
            element.textContent = text;
            return element;
        },
        createDocumentFragment() { return node('#fragment'); }
    };
    return {
        elements,
        created,
        setQuerySelectorAll(impl: (selector: string) => any[]) { querySelectorAllImpl = impl; }
    };
}

function errorLine(elements: Record<string, any>, modalId: string) {
    const line = elements[modalId + 'Error'];
    return { text: line.textContent, hidden: line.hidden };
}

async function prepareState() {
    const { state } = await import(stateModulePath);
    state.isReadOnly = false;
    state.isGridReloading = false;
    state.isDbConnected = true;
    state.selectedTable = 'items';
    state.selectedTableType = 'table';
    state.selectedTableIdentity = null;
    state.selectedRowIds = new Set([1]);
    state.selectedColumns = new Set();
    state.selectedCells = [];
    state.lastSelectedCell = null;
    state.tableColumns = [{ name: 'value', type: 'TEXT', notnull: 0 }];
    state.gridData = [[1, 'before']];
    state.gridReadOnlyRowReasons = {};
    state.gridOversizedCells = {};
    state.gridExactIntegerTexts = {};
    state.cellPreviewInfo = null;
    return state;
}

async function withRejectingApi<T>(method: string, error: Error, run: () => Promise<T>): Promise<T> {
    const { backendApi } = await import(apiModulePath);
    const original = backendApi[method];
    const originalConsoleError = console.error;
    backendApi[method] = async () => { throw error; };
    console.error = () => {};
    try {
        return await run();
    } finally {
        backendApi[method] = original;
        console.error = originalConsoleError;
    }
}

describe('submit modals keep a refused submission visible inside the dialog', () => {
    afterEach(async () => {
        // Retire the module-level modal sessions through the real close path.
        const { closeModal } = await import(modalsModulePath);
        for (const modalId of ['addRowModal', 'deleteModal', 'createTableModal', 'addColumnModal', 'exportModal']) {
            closeModal(modalId, null, { restoreFocus: false });
        }
        delete (globalThis as any).document;
        const { state } = await import(stateModulePath);
        state.selectedTable = null;
        state.selectedRowIds = new Set();
        state.selectedColumns = new Set();
        state.tableColumns = [];
        state.gridData = [];
        state.cellPreviewInfo = null;
        state.isReadOnly = false;
    });

    it('gives every submit modal in the shared template an error line inside it', () => {
        const template = readFileSync(path.resolve(process.cwd(), 'core/ui/viewer.template.html'), 'utf8');
        for (const modalId of [
            'addRowModal', 'deleteModal', 'createTableModal', 'addColumnModal',
            'exportModal', 'settingsModal', 'cellPreviewModal', 'blob-inspector-modal'
        ]) {
            const start = template.indexOf('id="' + modalId + '"');
            assert.ok(start >= 0, modalId + ' must exist');
            const next = template.slice(start + 1).search(/<div [^>]*\brole="dialog"/);
            const markup = next < 0 ? template.slice(start) : template.slice(start, start + 1 + next);
            const line = markup.match(new RegExp('<[^>]*\\bid="' + modalId + 'Error"[^>]*>'));
            assert.ok(line, modalId + ' must carry its own error line');
            assert.match(line[0], /\brole="alert"/, modalId + ' error line must announce itself');
            assert.match(line[0], /\bhidden\b/, modalId + ' error line must start hidden');
        }
    });

    it('shows an undo-budget refusal of Delete rows inside the open confirmation', async () => {
        const { elements } = installModalDocument(['deleteModal'], { deleteConfirmText: node('p') });
        await prepareState();
        const { openDeleteModal, submitDelete } = await import(crudModulePath);
        openDeleteModal();
        await withRejectingApi('deleteRows', new Error(UNDO_REFUSAL), () => submitDelete());

        assert.strictEqual(elements.deleteModal.classList.contains('hidden'), false);
        assert.deepStrictEqual(errorLine(elements, 'deleteModal'), { text: 'Error: ' + UNDO_REFUSAL, hidden: false });
        assert.strictEqual(elements.statusText.textContent, 'Error: ' + UNDO_REFUSAL);
    });

    it('shows a failed Delete columns inside the open confirmation', async () => {
        const { elements } = installModalDocument(['deleteModal'], { deleteConfirmText: node('p') });
        const state = await prepareState();
        state.selectedRowIds = new Set();
        state.selectedColumns = new Set(['value']);
        const { openDeleteModal, submitDelete } = await import(crudModulePath);
        openDeleteModal();
        await withRejectingApi('deleteColumns', new Error('cannot drop PRIMARY KEY column: "value"'), () => submitDelete());

        assert.strictEqual(elements.deleteModal.classList.contains('hidden'), false);
        assert.deepStrictEqual(errorLine(elements, 'deleteModal'), {
            text: 'Error: cannot drop PRIMARY KEY column: "value"', hidden: false
        });
    });

    it('reports a Delete refused while its confirmation is stale inside the confirmation', async () => {
        const { elements } = installModalDocument(['deleteModal'], { deleteConfirmText: node('p') });
        const state = await prepareState();
        const { openDeleteModal, submitDelete } = await import(crudModulePath);
        openDeleteModal();
        state.contentGeneration++;
        await submitDelete();

        assert.deepStrictEqual(errorLine(elements, 'deleteModal'), {
            text: 'Delete cancelled because the database content changed', hidden: false
        });
    });

    it('leaves a closed confirmation untouched when Delete runs without it', async () => {
        const { elements } = installModalDocument(['deleteModal'], { deleteConfirmText: node('p') });
        await prepareState();
        const { submitDelete } = await import(crudModulePath);
        await withRejectingApi('deleteRows', new Error(UNDO_REFUSAL), () => submitDelete());

        assert.strictEqual(elements.statusText.textContent, 'Error: ' + UNDO_REFUSAL);
        assert.deepStrictEqual(errorLine(elements, 'deleteModal'), { text: '', hidden: true });
    });

    it('clears a previous refusal when the confirmation opens again', async () => {
        const { elements } = installModalDocument(['deleteModal'], { deleteConfirmText: node('p') });
        await prepareState();
        const { openDeleteModal, submitDelete } = await import(crudModulePath);
        const { closeModal } = await import(modalsModulePath);
        openDeleteModal();
        await withRejectingApi('deleteRows', new Error(UNDO_REFUSAL), () => submitDelete());
        assert.strictEqual(errorLine(elements, 'deleteModal').hidden, false);
        closeModal('deleteModal');
        openDeleteModal();

        assert.deepStrictEqual(errorLine(elements, 'deleteModal'), { text: '', hidden: true });
    });

    it('shows a failed and a refused Add Row inside the open form', async () => {
        const harness = installModalDocument(['addRowModal'], { addRowForm: node() });
        const state = await prepareState();
        state.tableColumns = [{ name: 'value', type: 'TEXT', notnull: 1, dflt_value: null }];
        const { openAddRowModal, submitAddRow } = await import(crudModulePath);
        openAddRowModal();
        const field = harness.created.find(element => element.dataset.column === 'value');
        assert.ok(field, 'Add Row renders a field for the column');
        harness.setQuerySelectorAll(selector => selector.startsWith('#addRowForm') ? [field] : []);

        await submitAddRow();
        assert.deepStrictEqual(errorLine(harness.elements, 'addRowModal'), {
            text: 'Required fields missing: value', hidden: false
        });

        field.value = 'duplicate';
        field.dataset.mode = 'value';
        await withRejectingApi('insertRow', new Error('UNIQUE constraint failed: items.value'), () => submitAddRow());
        assert.strictEqual(harness.elements.addRowModal.classList.contains('hidden'), false);
        assert.deepStrictEqual(errorLine(harness.elements, 'addRowModal'), {
            text: 'Error: UNIQUE constraint failed: items.value', hidden: false
        });
    });

    it('shows a failed and a refused Create Table inside the open form', async () => {
        const tableName = node('input');
        const harness = installModalDocument(['createTableModal'], {
            newTableName: tableName,
            newTableWithoutRowid: node('input'),
            columnDefinitions: node()
        });
        await prepareState();
        const { openCreateTableModal, submitCreateTable } = await import(crudModulePath);
        openCreateTableModal();
        const columnRow = {
            querySelector(selector: string) {
                if (selector === '.col-name') return { value: 'id' };
                if (selector === '.col-type') return { value: 'INTEGER' };
                if (selector === '.col-pk') return { checked: true };
                if (selector === '.col-nn') return { checked: false };
                if (selector === '.col-default') return { value: '' };
                return null;
            }
        };
        harness.setQuerySelectorAll(selector => selector === '.column-def-row' ? [columnRow] : []);

        tableName.value = '';
        await submitCreateTable();
        assert.strictEqual(errorLine(harness.elements, 'createTableModal').hidden, false);
        assert.match(errorLine(harness.elements, 'createTableModal').text, /^Error: Table name/);

        tableName.value = 'items';
        await withRejectingApi('createTable', new Error('table "items" already exists'), () => submitCreateTable());
        assert.strictEqual(harness.elements.createTableModal.classList.contains('hidden'), false);
        assert.deepStrictEqual(errorLine(harness.elements, 'createTableModal'), {
            text: 'Error: table "items" already exists', hidden: false
        });
    });

    it('shows a failed and a refused Add Column inside the open form', async () => {
        const name = node('input');
        const { elements } = installModalDocument(['addColumnModal'], {
            newColumnName: name,
            newColumnType: node('select'),
            newColumnDefault: node('input')
        });
        const state = await prepareState();
        const { openAddColumnModal, submitAddColumn } = await import(crudModulePath);
        openAddColumnModal();
        name.value = 'value';

        await withRejectingApi('addColumn', new Error('duplicate column name: value'), () => submitAddColumn());
        assert.strictEqual(elements.addColumnModal.classList.contains('hidden'), false);
        assert.deepStrictEqual(errorLine(elements, 'addColumnModal'), {
            text: 'Error: duplicate column name: value', hidden: false
        });

        state.contentGeneration++;
        await submitAddColumn();
        assert.deepStrictEqual(errorLine(elements, 'addColumnModal'), {
            text: 'Add Column cancelled because the database content changed', hidden: false
        });
    });

    it('shows an Export refused before it starts inside the open dialog', async () => {
        const { elements } = installModalDocument(['exportModal'], {
            exportColumns: node(),
            exportOptions: node(),
            btnSubmitExport: node('button'),
            exportFormat: Object.assign(node('select'), { value: 'csv' }),
            exportHeader: Object.assign(node('input'), { checked: true })
        });
        await prepareState();
        const { openExportModal, submitExport } = await import(exportModulePath);
        openExportModal();
        await submitExport();

        assert.strictEqual(elements.exportModal.classList.contains('hidden'), false);
        assert.deepStrictEqual(errorLine(elements, 'exportModal'), {
            text: 'Error: Select at least one column', hidden: false
        });
    });

    it('shows a failed cell preview Save and a refused JSON format inside the preview', async () => {
        const textarea = Object.assign(node('textarea'), { value: 'after' });
        const { elements } = installModalDocument(['cellPreviewModal'], {
            cellPreviewTextarea: textarea,
            cellPreviewCharCount: node('span')
        });
        elements.cellPreviewModal.classList = createClassList(['cell-preview-modal']);
        const state = await prepareState();
        state.cellPreviewInfo = {
            rowIdx: 0, colIdx: 0, rowId: 1, columnName: 'value', table: 'items', tableType: 'table',
            column: { name: 'value', type: 'TEXT', notnull: 0 }, documentReadOnly: false,
            originalValue: 'before', originalText: 'before', valueMode: 'value', dirty: true
        };
        const { saveCellPreview, formatCellPreviewJson } = await import(editModulePath);

        await withRejectingApi('updateCell', new Error(UNDO_REFUSAL), () => saveCellPreview());
        assert.strictEqual(elements.cellPreviewModal.classList.contains('hidden'), false);
        assert.deepStrictEqual(errorLine(elements, 'cellPreviewModal'), {
            text: 'Save failed: ' + UNDO_REFUSAL, hidden: false
        });

        formatCellPreviewJson();
        assert.deepStrictEqual(errorLine(elements, 'cellPreviewModal'), {
            text: 'Content is not valid JSON', hidden: false
        });
    });

    it('shows a refused PRAGMA change inside the open Configuration dialog', async () => {
        const container = node();
        const { elements } = installModalDocument(['settingsModal'], { pragmaSettingsContainer: container });
        elements.settingsModal.classList.remove('hidden');
        await prepareState();
        const { backendApi } = await import(apiModulePath);
        const originals = { getPragmas: backendApi.getPragmas, getExtensionSettings: backendApi.getExtensionSettings };
        backendApi.getPragmas = async () => { throw new Error('reload probe'); };
        backendApi.getExtensionSettings = async () => ({});
        const { updatePragma } = await import(settingsModulePath);
        try {
            await withRejectingApi('setPragma', new Error('cannot change journal_mode inside a transaction'),
                () => updatePragma('journal_mode', 'WAL'));
        } finally {
            Object.assign(backendApi, originals);
        }

        assert.deepStrictEqual(errorLine(elements, 'settingsModal'), {
            text: 'Error: cannot change journal_mode inside a transaction', hidden: false
        });
    });

    it('shows a failed Replace and a failed Download inside the open inspector', async () => {
        const { elements } = installModalDocument(['blob-inspector-modal']);
        elements['blob-inspector-modal'].classList.remove('hidden');
        const state = await prepareState();
        const { BlobInspector } = await import(blobInspectorModulePath);
        const inspector = Object.create(BlobInspector.prototype);
        Object.assign(inspector, {
            previewGeneration: 0, activeReplacement: null, activeDownload: null, isUploading: false,
            pendingTextSnapshot: false, currentTableType: 'table', currentSnapshotUnavailable: false,
            currentTable: 'items', currentRowId: 1, currentColName: 'value',
            currentCellInfo: { rowIdx: 0, colIdx: 0 }, currentData: Uint8Array.from([1, 2]),
            currentStorageClass: 'blob', currentType: { type: 'binary', ext: 'bin' },
            setUploadState() {}
        });
        state.selectedTable = 'items';

        const operation = inspector.beginReplacementOperation();
        assert.ok(operation);
        const file = { name: 'big.bin', size: 2, arrayBuffer: async () => Uint8Array.from([3, 4]).buffer };
        await withRejectingApi('updateCell', new Error(UNDO_REFUSAL), () => inspector.uploadFile(file, operation));
        assert.deepStrictEqual(errorLine(elements, 'blob-inspector-modal'), {
            text: 'Replace failed: ' + UNDO_REFUSAL, hidden: false
        });

        const { backendApi } = await import(apiModulePath);
        const originalSettings = backendApi.getExtensionSettings;
        backendApi.getExtensionSettings = async () => ({ fileOperations: 'native' });
        try {
            await withRejectingApi('saveFile', new Error('disk full'), () => inspector.download());
        } finally {
            backendApi.getExtensionSettings = originalSettings;
        }
        assert.deepStrictEqual(errorLine(elements, 'blob-inspector-modal'), {
            text: 'Download failed: disk full', hidden: false
        });
    });
});
