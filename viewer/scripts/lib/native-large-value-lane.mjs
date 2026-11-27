/**
 * Large values through the desktop's native transport, end to end: the page
 * host (core/ui/modules/desktop-host.js) drives the REAL sidecar
 * (viewer-dist/native/native-worker-desktop.js inside the pinned binary) through a shell
 * stand-in that applies the Rust shell's rules to every envelope: the
 * 16 MiB frame cap in both directions, layer 3's method list, and serde_json's
 * refusal of a string holding a lone surrogate (route_payload drops such a
 * frame; here it fails the call instead of hanging it).
 *
 * Every check reads the database back byte-exact (storage class, length, and
 * the first and last eight bytes of every cell, as the extension's
 * native_batch_edit_frame test does) after the edit, after its undo and after
 * its redo, so a write that landed without its history, or a replay that put
 * back the wrong bytes, fails here.
 *
 * Self-contained on purpose: it imports nothing the 1.9.0 port did not
 * already ship, so the same file runs against an older tree's bundle and
 * host to show what failed there.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { MAX_FRAME_BYTES } from '../../core/native/frame-codec.js';
import { createDesktopHost } from '../../core/ui/modules/desktop-host.js';
import { encodePrimaryKeyRecordId } from '../../src/core/row-identity.ts';
import { BUNDLE_PATH } from './native-sidecar-lane.mjs';

const MiB = 1024 * 1024;
const DEFAULT_UNDO_BUDGET = 52428800;
const RAISED_UNDO_BUDGET = 512 * MiB;
const EDIT_LIMIT = 16 * MiB;
const RPC_TIMEOUT_MS = 180000;

/**
 * Layer 3's method list (src-tauri/src/native.rs KNOWN_METHODS) plus the
 * transport method the shell admits beside it (shell-changes.md).
 */
const SHELL_METHODS = new Set([
    'initializeDatabase', 'runQuery', 'runConsole', 'executeReadQuery', 'getCellMetadata',
    'openCellReadSession', 'readCellChunk', 'closeCellReadSession', 'exportDatabase', 'exportTable',
    'fetchTableData', 'fetchTableCount', 'fetchSchema', 'getTableInfo', 'getImportTarget', 'getPragmas',
    'setPragma', 'updateCell', 'replaceOversizedCell', 'insertRow', 'insertRowWithHistory', 'importRows',
    'deleteRows', 'deleteColumns', 'findDependentIndexes', 'createTable', 'getViewDefinition',
    'validateViewDefinition', 'previewViewDefinition', 'createView', 'editView', 'dropView',
    'undoModification', 'redoModification', 'updateCellBatch', 'addColumn', 'ping', 'refreshFile',
    'nativeTransfer'
]);

/**
 * The shell's `nativeTransfer` gate (src-tauri/src/native.rs
 * check_native_transfer), on the envelope as it crosses: the piece counted in
 * UTF-16 units of the WIRE string, which carries the codec's extra `~` for a
 * piece that starts with one.
 */
const MAX_TRANSFER_UNITS = 256 * 1024 * 1024;
const MAX_TRANSFER_PIECE_UNITS = Math.floor((MAX_FRAME_BYTES - 4096) / 3);
const TRANSFER_ID = /^[A-Za-z0-9_-]{1,64}$/;
function checkNativeTransfer(payload) {
    const count = (value) => (Number.isSafeInteger(value) && value >= 0 ? value : null);
    const ok = Array.isArray(payload) && typeof payload[1] === 'string' && TRANSFER_ID.test(payload[1]) && (() => {
        if (payload[0] === 'push' && payload.length === 6) {
            const [, , index, parts, length, piece] = payload.map((value, at) => (at >= 2 && at <= 4 ? count(value) : value));
            return index !== null && parts !== null && length !== null && typeof piece === 'string'
                && length >= 1 && length <= MAX_TRANSFER_UNITS && parts >= 1 && parts <= length && index < parts
                && piece.length >= 1 && piece.length <= Math.min(MAX_TRANSFER_PIECE_UNITS, length);
        }
        if (payload[0] === 'pull' && payload.length === 3) return count(payload[2]) !== null && payload[2] < MAX_TRANSFER_UNITS;
        return payload[0] === 'commit' && payload.length === 2;
    })();
    if (!ok) {
        const piece = Array.isArray(payload) && typeof payload[5] === 'string' ? ` (piece of ${payload[5].length} units)` : '';
        throw new Error(`ERR_NATIVE_ENVELOPE_MALFORMED: nativeTransfer payload refused by the shell's gate${piece}`);
    }
}

/** serde_json refuses a JSON string that decodes to a lone surrogate. */
function assertWellFormedStrings(value, where) {
    const stack = [value];
    while (stack.length > 0) {
        const current = stack.pop();
        if (typeof current === 'string') {
            if (!current.isWellFormed()) throw new Error(`ERR_LANE_SHELL: ${where} holds a lone surrogate; serde_json would refuse it`);
        } else if (current && typeof current === 'object') {
            for (const key of Object.keys(current)) {
                if (!key.isWellFormed()) throw new Error(`ERR_LANE_SHELL: ${where} has a key with a lone surrogate`);
                stack.push(current[key]);
            }
        }
    }
}

/** One sidecar behind the shell's rules; `rpc` takes and returns envelope JSON verbatim. */
function startShellSidecar(binary, dbPath, mode) {
    const child = spawn(binary, ['run', path.basename(BUNDLE_PATH), `--path-utf8=${encodeURIComponent(dbPath)}`, mode], {
        cwd: path.dirname(BUNDLE_PATH),
        stdio: ['pipe', 'pipe', 'pipe']
    });
    const pending = new Map();
    let stderr = '';
    let exit = null;
    const exitWaiters = [];
    const failAll = (error) => {
        for (const [id, waiter] of pending) {
            pending.delete(id);
            waiter.reject(error);
        }
    };

    // Frames are reassembled with one copy each, when they are complete.
    let chunks = [];
    let buffered = 0;
    const deliver = (payload) => {
        const text = payload.toString('utf8');
        let envelope;
        try {
            envelope = JSON.parse(text);
            assertWellFormedStrings(envelope, 'a sidecar frame');
        } catch (error) {
            failAll(new Error(`ERR_LANE_SHELL: unparseable sidecar frame (${error.message})`));
            return;
        }
        const id = envelope?.content?.messageId;
        const waiter = pending.get(id);
        if (!waiter) {
            stderr += `[lane-shell] sidecar frame for unknown messageId ${JSON.stringify(id)}\n`;
            return;
        }
        pending.delete(id);
        waiter.resolve(text);
    };
    child.stdout.on('data', (chunk) => {
        chunks.push(chunk);
        buffered += chunk.length;
        for (;;) {
            if (buffered < 4) return;
            if (chunks[0].length < 4) chunks = [Buffer.concat(chunks, buffered)];
            const declared = chunks[0].readUInt32BE(0);
            if (declared > MAX_FRAME_BYTES) {
                failAll(new Error(`ERR_LANE_SHELL: the sidecar sent a ${declared}-byte frame, over the ${MAX_FRAME_BYTES}-byte cap`));
                child.kill('SIGKILL');
                return;
            }
            if (buffered < 4 + declared) return;
            const all = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, buffered);
            const payload = all.subarray(4, 4 + declared);
            const rest = all.subarray(4 + declared);
            chunks = rest.length > 0 ? [rest] : [];
            buffered = rest.length;
            deliver(payload);
        }
    });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.stdin.on('error', (error) => { stderr += `[stdin] ${error.code ?? error.message}\n`; });
    child.on('close', (code) => {
        exit = code;
        failAll(new Error(`ERR_NATIVE_SIDECAR_EXITED: exited with code ${code}`));
        for (const waiter of exitWaiters.splice(0)) waiter(code);
    });

    return {
        get stderr() { return stderr; },
        /** native_rpc: the shell's outbound checks, one frame out, the reply's text back. */
        rpc(json) {
            if (exit !== null) return Promise.reject(new Error('ERR_NATIVE_SIDECAR_EXITED: the sidecar is gone'));
            const bytes = Buffer.from(json, 'utf8');
            if (bytes.length > MAX_FRAME_BYTES) {
                return Promise.reject(new Error(
                    `ERR_NATIVE_FRAME_TOO_LARGE: envelope is ${bytes.length} bytes; the frame cap is ${MAX_FRAME_BYTES} bytes (inclusive)`
                ));
            }
            let content;
            try {
                const envelope = JSON.parse(json);
                assertWellFormedStrings(envelope, 'the envelope');
                content = envelope?.channel === 'rpc' ? envelope.content : null;
            } catch (error) {
                return Promise.reject(new Error(`ERR_NATIVE_ENVELOPE_MALFORMED: ${error.message}`));
            }
            if (content?.kind !== 'invoke' || typeof content.messageId !== 'string') {
                return Promise.reject(new Error('ERR_NATIVE_ENVELOPE_MALFORMED: not an rpc invoke with a string messageId'));
            }
            if (!SHELL_METHODS.has(content.targetMethod)) {
                return Promise.reject(new Error(`ERR_NATIVE_METHOD_UNLISTED: method ${JSON.stringify(content.targetMethod)}`));
            }
            if (content.targetMethod === 'nativeTransfer') {
                // `content` is JSON.parse of the frame as sent: wire strings.
                try {
                    checkNativeTransfer(content.payload);
                } catch (error) {
                    return Promise.reject(error);
                }
            }
            if (content.targetMethod === 'initializeDatabase' && content.payload?.[1]?.path !== dbPath) {
                return Promise.reject(new Error('ERR_NATIVE_PATH_MISMATCH: initializeDatabase path is not the bound path'));
            }
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    pending.delete(content.messageId);
                    reject(new Error(`ERR_NATIVE_RPC_TIMEOUT: ${content.targetMethod}`));
                }, RPC_TIMEOUT_MS);
                pending.set(content.messageId, {
                    resolve: (text) => { clearTimeout(timer); resolve(text); },
                    reject: (error) => { clearTimeout(timer); reject(error); }
                });
                const header = Buffer.alloc(4);
                header.writeUInt32BE(bytes.length, 0);
                child.stdin.write(Buffer.concat([header, bytes]));
            });
        },
        close() {
            if (exit !== null) return Promise.resolve(exit);
            const exited = new Promise((resolve) => exitWaiters.push(resolve));
            child.stdin.end();
            const timer = setTimeout(() => child.kill('SIGKILL'), 15000);
            return exited.finally(() => clearTimeout(timer));
        }
    };
}

/** The bridge members the host uses, over real sidecars. `intercept` sees every native_rpc. */
function makeLaneBridge(binary, { maxUndoMemory, intercept }) {
    const sidecars = new Map();
    let sequence = 0;
    return {
        sidecars,
        bridge: {
            nativeAvailable: async () => true,
            nativeOpen: async (dbPath, readOnly) => {
                const dbId = `db_${sequence++}`;
                sidecars.set(dbId, startShellSidecar(binary, dbPath, readOnly ? 'ro' : 'rw'));
                return { dbId, boundPath: dbPath };
            },
            nativeRpc: async (dbId, json) => {
                const sidecar = sidecars.get(dbId);
                if (!sidecar) throw new Error(`ERR_NATIVE_UNKNOWN_DB: ${dbId}`);
                return intercept ? intercept(json, () => sidecar.rpc(json)) : sidecar.rpc(json);
            },
            nativeClose: async (dbId) => {
                const sidecar = sidecars.get(dbId);
                if (!sidecar) throw new Error(`ERR_NATIVE_UNKNOWN_DB: ${dbId}`);
                sidecars.delete(dbId);
                await sidecar.close();
            },
            loadSettings: async () => ({ maxUndoMemory }),
            saveSettings: async () => {},
            setTitle: async () => {},
            setUnsavedState: async () => {},
            onMenu: () => {},
            pickDatabase: async () => null,
            readDatabaseBytes: async () => { throw new Error('lane: the WebAssembly engine is not part of this lane'); },
            saveDatabase: async () => { throw new Error('lane: no WebAssembly saves'); },
            saveFileAs: async () => null
        }
    };
}

/** The boot placeholder's engine: answers its own open and nothing else. */
function scratchWorker() {
    const worker = {
        onmessage: null,
        onerror: null,
        postMessage(message) {
            const { messageId, targetMethod } = message.content;
            queueMicrotask(() => worker.onmessage?.({ data: { channel: 'rpc', content: targetMethod === 'initializeDatabase'
                ? { kind: 'response', messageId, success: true, data: { isReadOnly: false } }
                : { kind: 'response', messageId, success: false, errorMessage: `lane: the placeholder does not serve ${targetMethod}` } } }));
        },
        terminate() {}
    };
    return worker;
}

/** Every cell of `table` as storage class, byte length, and first and last eight bytes. */
async function contents(host, table) {
    const columns = (await host.invoke('runQuery', [`SELECT name FROM pragma_table_info('${table}') ORDER BY cid`]))[0].rows
        .map(row => String(row[0]));
    const key = columns.includes('k') ? 'k' : 'CAST(rowid AS TEXT)';
    const projection = [`${key} AS r`, ...columns.map((column, index) => (
        `typeof("${column}") AS t${index}, length(CAST("${column}" AS BLOB)) AS l${index}, ` +
        `hex(substr(CAST("${column}" AS BLOB), 1, 8)) AS h${index}, hex(substr(CAST("${column}" AS BLOB), -8)) AS e${index}`
    ))];
    const rows = (await host.invoke('runQuery', [`SELECT ${projection.join(', ')} FROM "${table}" ORDER BY 1`]))[0]?.rows ?? [];
    return JSON.stringify(rows, (_key, value) => (typeof value === 'bigint' ? `${value}n` : value));
}

const text = (bytes) => `replace(hex(zeroblob(${bytes / 2})), '0', 'a')`;
const rows = (count, value) =>
    `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ${count}) INSERT INTO t (rowid, v) SELECT i, ${value} FROM n`;
const keyOne = encodePrimaryKeyRecordId([{ identifier: 'k', declaredType: 'INTEGER', position: 1 }], [1n]);
const tenEdits = (value = 'x') => Array.from({ length: 10 }, (_, index) => ({ rowId: index + 1, column: 'v', value }));
/**
 * The budget refusal names what the whole history entry needs against the
 * configured limit (never what is left of it), and what the user can raise.
 */
const budgetRefusal = /^Editing \d+ cells in t needs (\d+) bytes of undo memory; the limit is 52428800 bytes\. Edit fewer cells at a time, or raise 'maxUndoMemory' in settings\.json\. Nothing was changed\.$/;

/**
 * @typedef {{
 *   name: string, setup: string[], undoBudget: number,
 *   edit: (host: any) => Promise<unknown>,
 *   refused?: RegExp,
 *   intercept?: (state: Record<string, any>) => (json: string, forward: () => Promise<string>) => Promise<string>,
 *   abandoned?: boolean
 * }} Scenario
 */

/** @type {Scenario[]} */
const SCENARIOS = [
    {
        name: 'ten-4mib-text-priors-raised-budget',
        setup: ['CREATE TABLE t (v)', rows(10, text(4 * MiB))],
        undoBudget: RAISED_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT])
    },
    {
        name: 'ten-4mib-blob-priors-raised-budget',
        setup: ['CREATE TABLE t (v)', rows(10, 'randomblob(4194304)')],
        undoBudget: RAISED_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT])
    },
    {
        // The tracker charges TEXT at two bytes a character: 80 MiB of priors.
        name: 'ten-4mib-text-priors-default-budget-refused',
        setup: ['CREATE TABLE t (v)', rows(10, text(4 * MiB))],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT]),
        refused: budgetRefusal
    },
    {
        // A BLOB prior is charged byte for byte: ten 4 MiB BLOBs (40 MiB) fit
        // the default 50 MiB budget and are edited, undone and redone ...
        name: 'ten-4mib-blob-priors-default-budget',
        setup: ['CREATE TABLE t (v)', rows(10, 'randomblob(4194304)')],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT])
    },
    {
        // ... and thirteen (52 MiB) do not.
        name: 'thirteen-4mib-blob-priors-default-budget-refused',
        setup: ['CREATE TABLE t (v)', rows(13, 'randomblob(4194304)')],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t',
            Array.from({ length: 13 }, (_, index) => ({ rowId: index + 1, column: 'v', value: 'x' })), 'Edit 13 cells', EDIT_LIMIT]),
        refused: budgetRefusal
    },
    {
        // The new values alone pass the default budget (ten 2 MiB TEXT values,
        // held twice at two bytes a character): nothing is left for the
        // priors, and the refusal still names what the paste needs and the
        // limit, not "the 0-byte memory budget". The request crosses in pieces.
        name: 'paste-whose-new-values-alone-pass-the-default-budget',
        setup: ['CREATE TABLE t (v)', rows(10, "'small'")],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t',
            Array.from({ length: 10 }, (_, index) => ({ rowId: index + 1, column: 'v', value: String.fromCharCode(97 + index).repeat(2 * MiB) })),
            'Paste', EDIT_LIMIT]),
        refused: budgetRefusal,
        needsAtLeast: 80 * MiB
    },
    ...['rowid', 'withoutRowid', 'alias'].map((kind) => ({
        name: `five-6mib-blob-cells-of-one-${kind}-row`,
        setup: [
            kind === 'rowid' ? 'CREATE TABLE t (a, b, c, d, e)'
                : kind === 'alias' ? 'CREATE TABLE t (k INTEGER PRIMARY KEY, a, b, c, d, e)'
                    : 'CREATE TABLE t (k INTEGER PRIMARY KEY, a, b, c, d, e) WITHOUT ROWID',
            kind === 'rowid'
                ? `INSERT INTO t (rowid, a, b, c, d, e) VALUES (1, ${Array(5).fill('randomblob(6291456)').join(', ')})`
                : `INSERT INTO t VALUES (1, ${Array(5).fill('randomblob(6291456)').join(', ')})`
        ],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', [
            // The alias edit moves the row: the path that carries a new rowid forward.
            ...(kind === 'alias' ? [{ rowId: 1, column: 'k', value: 5 }] : []),
            ...['a', 'b', 'c', 'd', 'e'].map(column => ({ rowId: kind === 'withoutRowid' ? keyOne : 1, column, value: 'x' }))
        ], 'Edit one row', EDIT_LIMIT])
    })),
    {
        // One value past a frame on its own, in the answer and in the undo request.
        name: 'one-20mib-cell-edited-to-x',
        setup: ['CREATE TABLE t (v)', 'INSERT INTO t (rowid, v) VALUES (1, randomblob(20971520)), (2, 1)'],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCell', ['t', 1, 'v', 'x', null, 64 * MiB])
    },
    {
        // The request direction: the paste itself is over a frame.
        name: 'paste-of-ten-2mib-values-into-small-cells',
        setup: ['CREATE TABLE t (v)', rows(10, "'small'")],
        undoBudget: RAISED_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t',
            Array.from({ length: 10 }, (_, index) => ({ rowId: index + 1, column: 'v', value: String.fromCharCode(97 + index).repeat(2 * MiB) })),
            'Paste', EDIT_LIMIT])
    },
    {
        name: 'delete-of-two-rows-holding-7mib-blobs',
        setup: ['CREATE TABLE t (v, w)', 'INSERT INTO t (rowid, v, w) VALUES (1, randomblob(7340032), 1), (2, randomblob(7340032), 2), (3, 3, 3)'],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => host.invoke('deleteRows', ['t', [1, 2]])
    },
    {
        // An insert past the frame in both directions: its 13 MiB value and
        // 1 MB key go out in pieces, and its answer (key twice, value) comes
        // back in pieces; its undo and redo carry the row image back.
        name: 'insert-of-a-row-past-the-frame',
        setup: ['CREATE TABLE t (k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID'],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => {
            const value = new Uint8Array(13 * MiB);
            for (let index = 0; index < value.length; index++) value[index] = (index * 31 + 7) & 0xff;
            return host.invoke('insertRow', ['t', { k: 'k'.repeat(1000000), v: value }, EDIT_LIMIT]);
        }
    },
    {
        // settings.json holds the limit as a quoted string: read as the default
        // (with a console notice), and every edit still works.
        name: 'undo-setting-written-as-a-string',
        inOneFrame: true,
        setup: ['CREATE TABLE t (v)', rows(2, "'a'")],
        undoBudget: '52428800',
        edit: (host) => host.invoke('updateCellBatch', ['t', [1, 2].map(rowId => ({ rowId, column: 'v', value: 'b' })), 'Edit 2 cells', EDIT_LIMIT])
    },
    {
        // Small on purpose: the byte-exact read-back of malformed TEXT in one frame.
        name: 'malformed-utf8-text-priors',
        inOneFrame: true,
        setup: ['CREATE TABLE t (v)', "INSERT INTO t (rowid, v) VALUES (1, CAST(X'80FF41' AS TEXT)), (2, 'héllo ✓')"],
        undoBudget: DEFAULT_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', [{ rowId: 1, column: 'v', value: 'x' }, { rowId: 2, column: 'v', value: 'y' }], 'Edit 2 cells', EDIT_LIMIT])
    },
    {
        // The same bytes past a frame: three 6 MiB TEXT cells that are not UTF-8.
        name: 'large-malformed-utf8-text-priors',
        setup: ['CREATE TABLE t (v)', rows(3, "CAST(X'80FF41' || randomblob(6291453) AS TEXT)")],
        undoBudget: RAISED_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t',
            [1, 2, 3].map(rowId => ({ rowId, column: 'v', value: 'x' })), 'Edit 3 cells', EDIT_LIMIT])
    },
    {
        // Pieces that start with '~' at the cut, in both directions: the codec
        // escapes a leading '~' with one more, and the shell's gate counts the
        // piece as sent. The answer is pulled in such pieces, and the undo and
        // redo requests are pushed in them.
        name: 'cells-of-tildes-edited-undone-redone',
        setup: ['CREATE TABLE t (v)', rows(2, "replace(hex(zeroblob(4500000)), '0', '~')")],
        undoBudget: RAISED_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', [1, 2].map(rowId => ({ rowId, column: 'v', value: 'y' })), 'Edit 2 cells', EDIT_LIMIT])
    },
    {
        // The request direction alone: a paste of two 9M-character runs of '~'.
        name: 'paste-of-tildes',
        setup: ['CREATE TABLE t (v)', rows(2, "'small'")],
        undoBudget: RAISED_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', [1, 2].map(rowId => ({ rowId, column: 'v', value: '~'.repeat(9000000) })), 'Paste', EDIT_LIMIT])
    },
    {
        // The commit's answer is lost once: the page asks again, and the
        // sidecar, which did commit, says so (a commit is idempotent by id).
        name: 'commit-answer-lost-once',
        setup: ['CREATE TABLE t (v)', rows(10, text(4 * MiB))],
        undoBudget: RAISED_UNDO_BUDGET,
        edit: (host) => host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT]),
        intercept: (state) => async (json, forward) => {
            const content = JSON.parse(json).content;
            const reply = await forward();
            if (content.targetMethod === 'nativeTransfer' && content.payload?.[0] === 'commit' && !state.lost) {
                state.lost = true;
                throw new Error('lane: injected loss of the answer to the commit');
            }
            return reply;
        }
    },
    {
        // Both answers lost with the sidecar alive: the write's fate is
        // unknown, so the host closes the connection (the session rolls back)
        // and the file keeps its saved bytes.
        name: 'commit-answers-lost-twice',
        setup: ['CREATE TABLE t (v)', rows(10, text(4 * MiB))],
        undoBudget: RAISED_UNDO_BUDGET,
        unconfirmed: true,
        edit: (host) => host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT]),
        intercept: () => async (json, forward) => {
            const content = JSON.parse(json).content;
            const reply = await forward();
            if (content.targetMethod === 'nativeTransfer' && content.payload?.[0] === 'commit') {
                throw new Error('lane: injected loss of the answer to the commit');
            }
            return reply;
        }
    },
    {
        // The request direction abandoned: the shell refuses the paste's second piece.
        name: 'abandoned-request-transfer',
        what: 'the shell refuses request piece 2',
        setup: ['CREATE TABLE t (v)', rows(10, "'small'")],
        undoBudget: RAISED_UNDO_BUDGET,
        abandoned: true,
        edit: (host) => host.invoke('updateCellBatch', ['t',
            Array.from({ length: 10 }, (_, index) => ({ rowId: index + 1, column: 'v', value: String.fromCharCode(97 + index).repeat(2 * MiB) })),
            'Paste', EDIT_LIMIT]),
        intercept: (state) => async (json, forward) => {
            const content = JSON.parse(json).content;
            if (content.targetMethod === 'nativeTransfer' && content.payload?.[0] === 'push' && content.payload?.[2] === 1) {
                state.injected = (state.injected ?? 0) + 1;
                throw new Error('lane: injected refusal of request piece 2');
            }
            return forward();
        }
    },
    // The shell abandons the method's own request after the sidecar ran it
    // (RPC_TIMEOUT, rejected as Tauri rejects a command: with the string).
    // The edit, or the undo, is in the session with no history to say so.
    ...[['edit', 'updateCellBatch'], ['undo', 'undoModification']].map(([step, method]) => ({
        name: `${step}-answer-lost-after-it-ran`,
        what: `the shell abandons ${method} after the sidecar ran it`,
        setup: ['CREATE TABLE t (v)', rows(10, "'small'")],
        undoBudget: DEFAULT_UNDO_BUDGET,
        unknown: step,
        edit: async (host, state) => {
            if (step === 'undo') {
                await host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT]);
                state.edited = await contents(host, 't');
            }
            state.armed = true;
            return step === 'undo'
                ? host.invoke('triggerUndo', [])
                : host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT]);
        },
        intercept: (state) => async (json, forward) => {
            const content = JSON.parse(json).content;
            if (state.armed && content.targetMethod === method) {
                state.armed = false;
                state.injected = (state.injected ?? 0) + 1;
                await forward();
                throw 'ERR_NATIVE_RPC_TIMEOUT: the sidecar did not answer within 600s; the request was abandoned';
            }
            return forward();
        }
    })),
    ...[['refused', 'the shell refuses the pull of piece 2'], ['lost', 'the answer to the pull of piece 2 is lost']].map(([mode, what]) => ({
        name: `abandoned-transfer-${mode}`,
        what,
        setup: ['CREATE TABLE t (v)', rows(10, text(4 * MiB))],
        undoBudget: RAISED_UNDO_BUDGET,
        abandoned: true,
        edit: (host) => host.invoke('updateCellBatch', ['t', tenEdits(), 'Edit 10 cells', EDIT_LIMIT]),
        intercept: (state) => async (json, forward) => {
            const content = JSON.parse(json).content;
            if (content.targetMethod === 'nativeTransfer' && content.payload?.[0] === 'pull' && content.payload?.[2] === 1) {
                state.injected = (state.injected ?? 0) + 1;
                if (mode === 'refused') throw new Error('lane: injected refusal of the pull of piece 2');
                await forward();
                throw new Error('lane: injected loss of the answer to the pull of piece 2');
            }
            return forward();
        }
    }))
];

/**
 * @param {string} binary
 * @param {string} scratch
 * @param {(ok: boolean, label: string, detail?: string) => void} note
 * @param {{ only?: (name: string) => boolean }} [options]
 * @returns {Promise<number>} checks run
 */
export async function runLargeValueCase(binary, scratch, note, options = {}) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const messageOf = (error) => String(error?.message ?? error).slice(0, 400);
    for (const scenario of SCENARIOS) {
        if (options.only && !options.only(scenario.name)) continue;
        const label = (step) => `sidecar/large-values/${scenario.name}/${step}`;
        const dbPath = path.join(scratch, `large-${scenario.name}.sqlite`);
        for (const suffix of ['', '-journal', '-wal', '-shm']) fs.rmSync(dbPath + suffix, { force: true });
        const seed = new DatabaseSync(dbPath);
        for (const sql of scenario.setup) seed.exec(sql);
        seed.close();

        const state = {};
        // What crossed in pieces, per phase: the shell stand-in already holds
        // every frame to the cap, so these say the transfer was what carried it.
        const pieces = { phase: 'open', counts: {} };
        const injected = scenario.intercept?.(state);
        const { bridge, sidecars } = makeLaneBridge(binary, {
            maxUndoMemory: scenario.undoBudget,
            intercept: (json, forward) => {
                const content = JSON.parse(json).content;
                if (content.targetMethod === 'nativeTransfer') {
                    const counts = pieces.counts[pieces.phase] ??= { push: 0, pull: 0, commit: 0 };
                    counts[content.payload?.[0]] = (counts[content.payload?.[0]] ?? 0) + 1;
                }
                return injected ? injected(json, forward) : forward();
            }
        });
        const crossed = (phase, op) => pieces.counts[phase]?.[op] ?? 0;
        const host = createDesktopHost({ bridge, createWorker: scratchWorker });
        try {
            await host.start();
            host.setWebviewMethods({ refreshContent: async () => ({ success: true }) });
            await host.openFromShellPath(dbPath);
            const init = await host.invoke('initialize', []);
            check(init?.engine === 'native', label('opens-native'), JSON.stringify(init));

            const before = await contents(host, 't');
            pieces.phase = 'edit';
            const started = Date.now();
            const outcome = await scenario.edit(host, state).then(
                (value) => ({ ok: true, value }),
                (error) => ({ ok: false, error })
            );
            const elapsed = `${Date.now() - started} ms`;
            if (scenario.refused) {
                const needs = Number(scenario.refused.exec(outcome.ok ? '' : messageOf(outcome.error))?.[1]);
                check(!outcome.ok && needs > DEFAULT_UNDO_BUDGET && needs >= (scenario.needsAtLeast ?? 0),
                    label('refused-by-the-budget'), outcome.ok ? 'the edit was accepted' : messageOf(outcome.error));
                check(await contents(host, 't') === before, label('nothing-written'));
                continue;
            }
            if (scenario.unconfirmed) {
                check(!outcome.ok && /could not be confirmed/.test(messageOf(outcome.error)), label('edit-fails-as-unconfirmed'),
                    outcome.ok ? 'the edit was reported as done' : messageOf(outcome.error));
                for (let waited = 0; sidecars.size > 0 && waited < 10000; waited += 50) await new Promise(resolve => setTimeout(resolve, 50));
                const after = await host.invoke('initialize', []).catch(messageOf);
                check(typeof after?.reloadRequiredReason === 'string' && sidecars.size === 0, label('connection-closed'),
                    JSON.stringify({ after, sidecars: sidecars.size }));
                const disk = new DatabaseSync(dbPath, { readOnly: true });
                const lengths = disk.prepare('SELECT length(CAST(v AS BLOB)) AS l FROM t ORDER BY rowid').all().map(row => row.l);
                disk.close();
                check(lengths.length === 10 && lengths.every(length => length === 4 * MiB), label('file-keeps-its-saved-bytes'),
                    JSON.stringify(lengths));
                continue;
            }
            if (scenario.unknown) {
                // The step ran in the session: the host must record it as a
                // change of unknown outcome, walled off from undo and redo,
                // and Save must keep what the session holds.
                const after = await contents(host, 't');
                check(state.injected === 1 && !outcome.ok && outcome.error?.code === 'ERR_MUTATION_OUTCOME_UNKNOWN',
                    label('fails-as-unknown'), outcome.ok ? 'reported as done' : `${outcome.error?.code}: ${messageOf(outcome.error)}`);
                check(scenario.unknown === 'undo' ? after === before : after !== before, label('the-step-is-in-the-session'));
                const undo = await host.invoke('triggerUndo', []).then((value) => value, messageOf);
                const redo = await host.invoke('triggerRedo', []).then((value) => value, messageOf);
                check(undo?.performed === false && undo?.reason === 'barrier' && redo?.performed === false && redo?.reason === 'empty'
                    && await contents(host, 't') === after, label('history-walled-off'), JSON.stringify({ undo, redo }));
                check(host.hasUnsavedChanges() === true, label('marked-unsaved'));
                const saved = await host.saveToDisk().then((value) => value, messageOf);
                const disk = new DatabaseSync(dbPath, { readOnly: true });
                const values = disk.prepare('SELECT v FROM t ORDER BY rowid').all().map(row => row.v);
                disk.close();
                check(saved?.success !== false && values.length === 10
                    && values.every(value => value === (scenario.unknown === 'undo' ? 'small' : 'x')),
                    label('save-keeps-what-the-session-holds'), JSON.stringify({ saved, first: values[0] }));
                continue;
            }
            if (scenario.abandoned) {
                check(state.injected === 1, label('piece-2-was-attempted'), `${state.injected ?? 0} injected; ${scenario.what}`);
                check(!outcome.ok, label('edit-fails'), outcome.ok ? 'the edit was reported as done' : messageOf(outcome.error));
                check(await contents(host, 't') === before, label('edit-is-not-applied-in-the-session'));
                const next = await host.invoke('updateCell', ['t', 1, 'v', 'next', null, EDIT_LIMIT]).then(() => null, messageOf);
                const afterNext = await contents(host, 't');
                const undone = await host.invoke('triggerUndo', []).then((value) => value, messageOf);
                check(next === null && afterNext !== before && undone?.performed === true && await contents(host, 't') === before,
                    label('the-next-request-works'), JSON.stringify({ next, undone }));
                continue;
            }
            check(outcome.ok, label('edit'), outcome.ok ? elapsed : messageOf(outcome.error));
            if (!outcome.ok) continue;
            pieces.phase = 'check';
            const edited = await contents(host, 't');
            check(edited !== before, label('edit-changed-the-cells'));
            pieces.phase = 'undo';
            const undone = await host.invoke('triggerUndo', []).then((value) => value, messageOf);
            pieces.phase = 'check';
            check(undone?.performed === true && await contents(host, 't') === before, label('undo-restores-every-byte'),
                JSON.stringify(undone));
            pieces.phase = 'redo';
            const redone = await host.invoke('triggerRedo', []).then((value) => value, messageOf);
            pieces.phase = 'check';
            check(redone?.performed === true && await contents(host, 't') === edited, label('redo-reapplies-every-byte'),
                JSON.stringify(redone));
            const summary = JSON.stringify(pieces.counts);
            if (scenario.inOneFrame) {
                check(Object.keys(pieces.counts).every(phase => phase === 'open' || phase === 'check'),
                    label('crossed-in-single-frames'), summary);
            } else {
                // The answer came in pieces and was committed; the undo and
                // redo requests carried the values back in pieces.
                check(crossed('edit', 'pull') > 1 && crossed('edit', 'commit') >= 1
                    && crossed('undo', 'push') > 1 && crossed('redo', 'push') > 1,
                    label('crossed-in-pieces'), summary);
            }
        } catch (error) {
            check(false, label('ran'), messageOf(error));
        } finally {
            for (const [dbId, sidecar] of [...sidecars]) {
                sidecars.delete(dbId);
                await sidecar.close();
            }
        }
    }
    return checks;
}
