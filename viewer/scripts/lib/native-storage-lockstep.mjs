/**
 * Storage-class lockstep between the desktop's two engines.
 *
 * The same worker method layer runs on WebAssembly (viewer-dist/web/worker.js over
 * sql.js) and on the native sidecar (viewer-dist/native/native-worker-desktop.js over
 * tjs:sqlite). A worker call must store the same storage class on both: a
 * value the page sent as 28 is INTEGER 28 on one engine and REAL 28.0 on the
 * other only through a bug, and in a TEXT column the difference is visible
 * ('28' against '28.0').
 *
 * Both engines get the same fixture and the same calls, in order, and their
 * answers and the stored `typeof`/`quote` of every cell are compared. The
 * WebAssembly worker receives JavaScript values directly, as a postMessage
 * from the page delivers them; the sidecar receives them through the JSON
 * frame codec, as the shell delivers them.
 */

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import initSqlJs from '../../vendor/sql.js/sql-wasm.js';
import { startSidecar } from './native-sidecar-lane.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const WASM_WORKER_PATH = path.join(REPO_ROOT, '..', 'viewer-dist', 'web', 'worker.js');
const WASM_BINARY_PATH = path.join(REPO_ROOT, '..', 'viewer-dist', 'web', 'sql-wasm.wasm');

const FIXTURE_SQL = `
    CREATE TABLE cells (id INTEGER PRIMARY KEY, untyped, label TEXT, amount REAL, whole INTEGER);
    INSERT INTO cells (id) VALUES (1), (2), (3), (3000000000);
    CREATE TABLE keyed ("1" INTEGER, b TEXT, "2" TEXT, PRIMARY KEY ("1")) WITHOUT ROWID;
    INSERT INTO keyed VALUES (10, 'x', 'y');
    CREATE TABLE reals (id INTEGER PRIMARY KEY, u);
    INSERT INTO reals VALUES (1, 28.0), (2, 28.0);
`;

/**
 * The desktop's WebAssembly worker, run in a VM context the way a browser
 * worker runs it: `self` is the worker scope, and `initSqlJs` stands in for
 * the glue script `importScripts` would load.
 */
async function startWasmWorker(content) {
    const source = fs.readFileSync(WASM_WORKER_PATH, 'utf8');
    const replies = new Map();
    const scope = {
        initSqlJs: (config) => initSqlJs(config),
        postMessage(message) {
            const id = message?.content?.messageId;
            if (id !== undefined) replies.set(id, message);
        }
    };
    const context = vm.createContext({
        self: scope,
        importScripts() {},
        console: { log() {}, warn() {}, error() {} },
        Uint8Array,
        Int32Array,
        ArrayBuffer,
        SharedArrayBuffer,
        Atomics,
        DataView,
        crypto: webcrypto,
        TextEncoder,
        TextDecoder,
        Date,
        setTimeout,
        clearTimeout
    });
    new vm.Script(source, { filename: 'viewer-dist/web/worker.js' }).runInContext(context);
    let sequence = 0;
    const invoke = async (targetMethod, payload = []) => {
        const messageId = `wasm_${++sequence}`;
        await scope.onmessage({
            data: { channel: 'rpc', content: { kind: 'invoke', messageId, targetMethod, payload } }
        });
        const reply = replies.get(messageId);
        replies.delete(messageId);
        if (!reply) throw new Error(`the WebAssembly worker did not answer ${targetMethod}`);
        return reply;
    };
    const init = await invoke('initializeDatabase', ['lockstep.sqlite', {
        content,
        wasmBinary: new Uint8Array(fs.readFileSync(WASM_BINARY_PATH)),
        queryTimeout: 30000
    }]);
    if (init.content?.success !== true) {
        throw new Error(`the WebAssembly worker refused the fixture: ${init.content?.errorMessage}`);
    }
    return { invoke };
}

/** The columns and values a WITHOUT ROWID identity names, with the value as a number. */
function identityKey(rowId) {
    const payload = JSON.parse(decodeURIComponent(String(rowId).replace(/^pk:/, '')));
    return payload.c.map(([column, [, value]]) => [column, Number(value)]);
}

/** The storage classes a WITHOUT ROWID identity records, one per key column. */
function identityClasses(rowId) {
    const payload = JSON.parse(decodeURIComponent(String(rowId).replace(/^pk:/, '')));
    return payload.c.map(([, [storageClass]]) => storageClass);
}

/** JSON with BigInts and bytes spelled out, so both engines' answers compare as text. */
function comparable(value) {
    return JSON.stringify(value, (_key, entry) => {
        if (typeof entry === 'bigint') {
            return Number.isSafeInteger(Number(entry)) ? Number(entry) : `${entry}n`;
        }
        if (entry instanceof Uint8Array) return { bytes: [...entry] };
        return entry;
    });
}

/** What a reply says, without its correlation id or the timing a console run reports. */
function answerOf(reply) {
    const content = reply?.content ?? {};
    const data = content.data && typeof content.data === 'object' && 'durationMs' in content.data
        ? { ...content.data, durationMs: 0 }
        : content.data;
    return content.success === true
        ? { success: true, data }
        : { success: false, errorMessage: content.errorMessage };
}

const CELL_CLASSES =
    'SELECT id, typeof(untyped), quote(untyped), typeof(label), quote(label), ' +
    'typeof(amount), quote(amount), typeof(whole), quote(whole) FROM cells ORDER BY id';
const KEYED_CLASSES =
    'SELECT "1" AS k, typeof("1") AS k_class, b AS v_b, "2" AS v_2 FROM keyed ORDER BY "1"';

/**
 * Each step is `[label, method, payload]`, or `[label, (engine) => reply]`
 * when the payload depends on that engine's earlier answers.
 */
const STEPS = [
    ['updateCell-untyped-whole', 'updateCell', ['cells', 1, 'untyped', 28]],
    ['updateCell-text-whole', 'updateCell', ['cells', 1, 'label', 28]],
    ['updateCell-untyped-fraction', 'updateCell', ['cells', 2, 'untyped', 2.5]],
    ['updateCell-text-int32-minimum', 'updateCell', ['cells', 2, 'label', -2147483648]],
    ['updateCell-untyped-whole-past-int32', 'updateCell', ['cells', 3, 'untyped', 3000000000]],
    ['updateCellBatch-mixed-on-a-rowid-past-int32', 'updateCellBatch', ['cells', [
        { rowId: 3000000000, column: 'untyped', value: 29 },
        { rowId: 3000000000, column: 'amount', value: 2.5 },
        { rowId: 3000000000, column: 'label', value: 30 }
    ]]],
    ['insertRowWithHistory-mixed', 'insertRowWithHistory', ['cells', {
        id: 4, untyped: 28, label: 1.5, amount: 7, whole: 2147483648
    }]],
    ['importRows-mixed', async (engine) => {
        const target = await engine.invoke('getImportTarget', ['cells']);
        return engine.invoke('importRows', ['cells', [{ id: 5, untyped: 31, label: 32, amount: 2.25 }], {
            expectedSchemaVersion: target.content?.data?.schemaVersion
        }]);
    }],
    ['runQuery-parameters', 'runQuery', [
        'INSERT INTO cells (id, untyped, label) VALUES (?, ?, ?)', [6, 33, 34]
    ]],
    ['runConsole-parameters', 'runConsole', [
        'INSERT INTO cells (id, untyped, label) VALUES (?, ?, ?)', { params: [7, 35, 36] }
    ]],
    ['runQuery-typeof-parameters', 'runQuery', [
        'SELECT typeof(?) AS a, typeof(?) AS b, typeof(?) AS c', [28, 2.5, 3000000000]
    ]],
    ['runConsole-typeof-parameters', 'runConsole', [
        'SELECT typeof(?) AS a, typeof(?) AS b, typeof(?) AS c', { params: [28, 2.5, 3000000000] }
    ]],
    ['cell-edit-undo-and-redo', async (engine) => {
        const edit = await engine.invoke('updateCellBatch', ['cells', [{ rowId: 1, column: 'whole', value: 41 }]]);
        const outcome = edit.content?.data?.[0];
        if (!outcome) return edit;
        const entry = {
            modificationType: 'cell_update',
            targetTable: 'cells',
            affectedCells: [{
                rowId: outcome.rowId,
                newRowId: outcome.newRowId ?? outcome.rowId,
                columnName: outcome.columnName,
                priorValue: outcome.priorValue,
                newValue: outcome.newValue,
                priorState: outcome.priorState,
                postState: outcome.postState,
                operation: outcome.operation
            }]
        };
        const undone = await engine.invoke('undoModification', [entry]);
        const afterUndo = await engine.invoke('runQuery', ['SELECT typeof(whole), quote(whole) FROM cells WHERE id = 1']);
        const redone = await engine.invoke('redoModification', [entry]);
        return { content: { success: true, data: [answerOf(edit), answerOf(undone), answerOf(afterUndo), answerOf(redone)] } };
    }],
    // A whole-valued REAL written back by history must stay REAL on both
    // engines, now that a whole Number binds INTEGER: the history writes by
    // the recorded storage class, not by the JavaScript value.
    ['cell-edit-undo-and-redo-of-a-whole-real', async (engine) => {
        const edit = await engine.invoke('updateCellBatch', ['reals', [{ rowId: 1, column: 'u', value: 5 }]]);
        const outcome = edit.content?.data?.[0];
        if (!outcome) return edit;
        const entry = {
            modificationType: 'cell_update',
            targetTable: 'reals',
            affectedCells: [{
                rowId: outcome.rowId,
                newRowId: outcome.newRowId ?? outcome.rowId,
                columnName: outcome.columnName,
                priorValue: outcome.priorValue,
                newValue: outcome.newValue,
                priorState: outcome.priorState,
                postState: outcome.postState,
                operation: outcome.operation
            }]
        };
        const classOf = () => engine.invoke('runQuery', ['SELECT typeof(u), quote(u) FROM reals WHERE id = 1']);
        const undone = await engine.invoke('undoModification', [entry]);
        const afterUndo = await classOf();
        const redone = await engine.invoke('redoModification', [entry]);
        const afterRedo = await classOf();
        const undoneAgain = await engine.invoke('undoModification', [entry]);
        const final = await classOf();
        return { content: { success: true, data: [undone, afterUndo, redone, afterRedo, undoneAgain, final].map(answerOf) } };
    }],
    ['row-delete-undo-of-a-whole-real', async (engine) => {
        const deleted = await engine.invoke('deleteRows', ['reals', [2]]);
        const restored = await engine.invoke('undoModification', [{
            modificationType: 'row_delete', targetTable: 'reals', deletedRows: deleted.content?.data
        }]);
        const after = await engine.invoke('runQuery', ['SELECT id, typeof(u), quote(u) FROM reals ORDER BY id']);
        return { content: { success: true, data: [answerOf(deleted).success, answerOf(restored), answerOf(after)] } };
    }],
    ['insertRowWithHistory-integer-named-key', async (engine) => {
        const reply = await engine.invoke('insertRowWithHistory', ['keyed', { 1: 11, b: 'bb', 2: 'cc' }]);
        // The identity is compared by the key it names, not by its spelling:
        // see the known divergence checked below.
        const data = reply.content?.data;
        if (!data?.rowId) return reply;
        return { content: { success: true, data: { ...data, rowId: identityKey(data.rowId) } } };
    }],
    // The fork's rows are objects, whose integer-like keys enumerate first:
    // the console showed b's value under "2" and "2"'s under b.
    ['runConsole-integer-like-column-names', 'runConsole', ['SELECT "1", b, "2" FROM keyed ORDER BY "1"']],
    ['runConsole-select-star-integer-like-names', 'runConsole', ['SELECT * FROM keyed ORDER BY "1"']],
    ['runQuery-integer-like-column-names', 'runQuery', ['SELECT b, "2", "1" FROM keyed ORDER BY "1"']],
    ['fetchTableData-integer-like-column-names', 'fetchTableData', ['keyed', { limit: 10, offset: 0 }]],
    ['stored-cell-classes', 'runQuery', [CELL_CLASSES]],
    ['stored-keyed-classes', 'runQuery', [KEYED_CLASSES]]
];

/**
 * @param {{binary: string, scratch: string, note: (ok: boolean, label: string, detail?: string) => void}} context
 * @returns {Promise<number>} checks run
 */
export async function runStorageLockstepCase({ binary, scratch, note }) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };
    const dbPath = path.join(scratch, 'storage-lockstep.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec(FIXTURE_SQL);
    seed.close();

    const wasm = await startWasmWorker(new Uint8Array(fs.readFileSync(dbPath)));
    const native = startSidecar(binary, dbPath, 'rw');
    try {
        const init = await native.invoke('initializeDatabase', [path.basename(dbPath), {
            path: dbPath, readOnlyMode: false, queryTimeout: 30000
        }]);
        check(init.content?.success === true, 'lockstep/native-opens', JSON.stringify(init.content));
        for (const [label, method, payload] of STEPS) {
            const run = (engine) => (typeof method === 'function'
                ? method(engine)
                : engine.invoke(method, payload));
            const expected = comparable(answerOf(await run(wasm)));
            const actual = comparable(answerOf(await run(native)));
            check(actual === expected, `lockstep/${label}`,
                actual === expected ? '' : `WebAssembly ${expected} != native ${actual}`);
        }
        // KNOWN DIVERGENCE, not fixed here. The worker mints a WITHOUT ROWID
        // identity from a RETURNING row read with useBigInt, and
        // encodePrimaryKeyValue (src/core/row-identity.ts) records a BigInt as
        // INTEGER and a Number as REAL. Under useBigInt sql.js gives a BigInt
        // for each INTEGER; the fork hands the shim row objects whose
        // INTEGERs below 2^53 are plain Numbers, indistinguishable from REALs,
        // so the native identity classes the key REAL. Both identities select
        // the same row (SQLite compares 11 and 11.0 equal) and edits, deletes
        // and undo through the native one work; the fix needs the runtime to
        // report storage classes or the projection to carry typeof().
        const nativeKeyed = await native.invoke('insertRowWithHistory', ['keyed', { 1: 12, b: 'b2', 2: 'c2' }]);
        const wasmKeyed = await wasm.invoke('insertRowWithHistory', ['keyed', { 1: 12, b: 'b2', 2: 'c2' }]);
        const nativeClasses = identityClasses(nativeKeyed.content?.data?.rowId);
        const wasmClasses = identityClasses(wasmKeyed.content?.data?.rowId);
        check(JSON.stringify(wasmClasses) === '["integer"]' && JSON.stringify(nativeClasses) === '["real"]',
            'lockstep/known-divergence/without-rowid-insert-identity-records-an-integer-key-as-real',
            `WebAssembly ${JSON.stringify(wasmClasses)}, native ${JSON.stringify(nativeClasses)}`);

        native.endStdin();
        check(await native.untilExit() === 0, 'lockstep/native-clean-shutdown');
    } finally {
        if (native.exitCode === null) native.child.kill('SIGKILL');
        const stderrText = native.stderr.trim();
        if (stderrText) console.log(`[sidecar lockstep stderr]\n${stderrText}\n`);
    }
    return checks;
}
