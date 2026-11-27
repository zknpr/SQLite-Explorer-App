/**
 * Sidecar half of the native lane: drives the COMMITTED
 * `viewer-dist/native/native-worker-desktop.js` inside the real fork binary over real
 * pipes — the complete shipping path in one piece: RPC envelope in, frame
 * codec, stdio transport, the byte-identical worker method layer, the
 * tjs:sqlite shim, and back.
 *
 * What this proves that the unit suite and the other lane phases cannot:
 * the argv/path binding refuses at the process boundary, real schema/console
 * results come back through real frames, the codec's int64/blob tagging
 * survives REAL RPC responses (not echoes), the wrapped postMessage answers
 * an oversize response in band for the same messageId, the query deadline
 * actually interrupts a runaway statement, and the ppid watchdog kills an
 * orphan whose stdin never closed.
 *
 * RPCs are issued strictly sequentially (send, await the reply, send the
 * next) — the same discipline the desktop host applies. The dispatch layer
 * itself does not serialise concurrent envelopes, exactly like the WASM
 * worker's message queue around initializeDatabase's awaits.
 */

import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
    MAX_FRAME_BYTES,
    NATIVE_FRAME_TOO_LARGE,
    createFrameReader,
    encodeFrame
} from '../../core/native/frame-codec.js';
import { buildDesktopNativeWorkerSource } from '../build.mjs';
import { runLargeValueCase } from './native-large-value-lane.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
// The bundle this app ships: the viewer build's output, committed in viewer-dist/.
export const BUNDLE_PATH = path.join(REPO_ROOT, '..', 'viewer-dist', 'native', 'native-worker-desktop.js');

const FIXTURE_BLOB = [0x00, 0x01, 0x7f, 0x80, 0xff];
const INT64_MAX = 9223372036854775807n;

/** Seed the on-disk fixture the sidecar sessions open. */
function createFixture(dbPath) {
    fs.rmSync(dbPath, { force: true });
    const db = new DatabaseSync(dbPath);
    db.exec(`
        CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, data BLOB, big INTEGER, r REAL);
        INSERT INTO t VALUES
            (1, 'alpha', X'00017f80ff', 9223372036854775807, 1.5),
            (2, 'beta',  NULL,          -9223372036854775808, -2.25),
            (3, 'gamma', X'',           9007199254740993,      0.0);
        CREATE VIEW v AS SELECT id, name FROM t;
    `);
    db.close();
}

/**
 * Spawn one sidecar session and return a sequential RPC client over it.
 * Replies are matched by messageId; stderr is collected for the caller.
 *
 * Exported so the per-method sweep (native-method-sweep.mjs) drives the same
 * real binary through the same real pipes rather than reimplementing — and so
 * a change to the spawn contract cannot silently apply to only one of them.
 */
export function startSidecar(binary, dbPath, mode) {
    const child = spawn(binary, ['run', path.basename(BUNDLE_PATH), `--path-utf8=${encodeURIComponent(dbPath)}`, mode], {
        cwd: path.dirname(BUNDLE_PATH),
        stdio: ['pipe', 'pipe', 'pipe']
    });

    const pending = new Map();
    let stderr = '';
    let exit = null;
    let exitWaiters = [];

    const reader = createFrameReader(
        (message) => {
            const id = message?.content?.messageId;
            const waiter = pending.get(id);
            if (waiter) {
                pending.delete(id);
                waiter.resolve(message);
            }
        },
        (error) => {
            // Lane-side decode failures fail every in-flight RPC loudly rather
            // than timing out.
            for (const [id, waiter] of pending) {
                pending.delete(id);
                waiter.reject(new Error(`frame reader error while awaiting ${id}: ${error.message}`));
            }
        }
    );

    child.stdout.on('data', (chunk) => reader.push(new Uint8Array(chunk)));
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.stdin.on('error', (error) => { stderr += `[stdin] ${error.code ?? error.message}\n`; });
    child.on('close', (code) => {
        exit = code;
        for (const waiter of exitWaiters) waiter(code);
        exitWaiters = [];
        for (const [id, waiter] of pending) {
            pending.delete(id);
            waiter.reject(new Error(`sidecar exited ${code} while awaiting ${id}`));
        }
    });

    let messageId = 0;
    const awaitReply = (id, envelope, label, timeoutMs) => new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            pending.delete(id);
            reject(new Error(`timed out waiting for ${label} (${id})`));
        }, timeoutMs);
        pending.set(id, {
            resolve: (message) => { clearTimeout(timer); resolve(message); },
            reject: (error) => { clearTimeout(timer); reject(error); }
        });
        child.stdin.write(Buffer.from(encodeFrame(envelope)));
    });
    return {
        child,
        get stderr() { return stderr; },
        get exitCode() { return exit; },
        /**
         * Send several invokes in ONE pipe write, as a host that pipelines its
         * requests can, and resolve with their response envelopes and the
         * order (indices into `calls`) in which the replies arrived.
         */
        invokeTogether(calls, timeoutMs = 30000) {
            const ids = calls.map(() => `lane_${++messageId}`);
            const order = [];
            const replies = ids.map((id, index) => new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    pending.delete(id);
                    reject(new Error(`timed out waiting for ${calls[index][0]} (${id})`));
                }, timeoutMs);
                pending.set(id, {
                    resolve: (message) => { clearTimeout(timer); order.push(index); resolve(message); },
                    reject: (error) => { clearTimeout(timer); reject(error); }
                });
            }));
            child.stdin.write(Buffer.concat(calls.map(([targetMethod, payload], index) => Buffer.from(encodeFrame({
                channel: 'rpc',
                content: { kind: 'invoke', messageId: ids[index], targetMethod, payload }
            })))));
            return Promise.all(replies).then((messages) => ({ messages, order }));
        },
        /** Send one invoke and resolve with the FULL response envelope. */
        invoke(targetMethod, payload = [], timeoutMs = 30000) {
            const id = `lane_${++messageId}`;
            return awaitReply(id, {
                channel: 'rpc',
                content: { kind: 'invoke', messageId: id, targetMethod, payload }
            }, targetMethod, timeoutMs);
        },
        /**
         * Send one SHELL-ORIGINATED export-to-path request — the exact message
         * the Rust shell will construct (native-host.js pins the contract) —
         * and resolve with the full `{channel:'shell'}` export-result envelope.
         * `args` is omitted from the content when undefined (exportDatabase
         * takes none; the field is required only for exportTable).
         */
        shellExport(method, tempPath, args = undefined, timeoutMs = 30000) {
            const id = `shell_${++messageId}`;
            const content = { kind: 'export', messageId: id, method, tempPath };
            if (args !== undefined) content.args = args;
            return awaitReply(id, { channel: 'shell', content }, `shell-export ${method}`, timeoutMs);
        },
        /**
         * Write several prepared envelopes (rpc or shell, each carrying its own
         * messageId) in ONE pipe write; resolve with their replies in order.
         */
        sendTogether(envelopes, timeoutMs = 30000) {
            const replies = envelopes.map((envelope) => new Promise((resolve, reject) => {
                const id = envelope.content.messageId;
                const timer = setTimeout(() => {
                    pending.delete(id);
                    reject(new Error(`timed out waiting for ${id}`));
                }, timeoutMs);
                pending.set(id, {
                    resolve: (message) => { clearTimeout(timer); resolve(message); },
                    reject: (error) => { clearTimeout(timer); reject(error); }
                });
            }));
            child.stdin.write(Buffer.concat(envelopes.map((envelope) => Buffer.from(encodeFrame(envelope)))));
            return Promise.all(replies);
        },
        /** Fire-and-forget raw envelope (for messages that must produce NO reply). */
        sendRaw(envelope) {
            child.stdin.write(Buffer.from(encodeFrame(envelope)));
        },
        endStdin() { child.stdin.end(); },
        untilExit(timeoutMs = 15000) {
            if (exit !== null) return Promise.resolve(exit);
            return new Promise((resolve) => {
                const timer = setTimeout(() => resolve('TIMEOUT'), timeoutMs);
                exitWaiters.push((code) => { clearTimeout(timer); resolve(code); });
            });
        }
    };
}

const equalBytes = (a, b) => a.length === b.length && a.every((value, index) => value === b[index]);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** A statement that runs for minutes unless the deadline interrupts it. */
const RUNAWAY_SQL =
    'WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<200000000) ' +
    'SELECT max(x) AS m FROM c';

/**
 * @param {{binary: string, scratch: string, note: (ok: boolean, label: string, detail?: string) => void}} context
 * @returns {Promise<number>} number of checks run
 */
export async function runSidecarLane({ binary, scratch, note }) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };

    // 0. The committed artifact is fresh against the build script's own
    //    bundler config (single source of truth — the import above).
    const committed = fs.readFileSync(BUNDLE_PATH, 'utf8');
    const rebuilt = await buildDesktopNativeWorkerSource();
    check(committed === rebuilt, 'sidecar/committed-bundle-is-fresh',
        committed === rebuilt ? '' : 'viewer-dist/native/native-worker-desktop.js is stale; run npm run build:viewer');

    const dbPath = path.join(scratch, 'sidecar-fixture.sqlite');
    createFixture(dbPath);

    // The executable's directory is the sole native-library authority. An
    // incomplete installation must refuse open rather than weaken plan limits.
    const missingReaderDirectory = path.join(scratch, 'missing-plan-reader');
    fs.mkdirSync(missingReaderDirectory);
    const isolatedBinary = path.join(missingReaderDirectory, path.basename(binary));
    fs.copyFileSync(binary, isolatedBinary);
    const missingReader = startSidecar(isolatedBinary, dbPath, 'rw');
    try {
        const refused = await missingReader.invoke('initializeDatabase', ['sidecar-fixture.sqlite', {
            path: dbPath, readOnlyMode: false
        }]);
        check(refused.content?.success === false
            && /Missing bundled query-plan reader/.test(refused.content?.errorMessage ?? ''),
            'sidecar/missing-bundled-reader-refuses-open', JSON.stringify(refused.content));
        missingReader.endStdin();
        await missingReader.untilExit();
    } finally {
        if (missingReader.exitCode === null) missingReader.child.kill('SIGKILL');
    }

    // ---- writable session -------------------------------------------------
    const rw = startSidecar(binary, dbPath, 'rw');
    try {
        const init = await rw.invoke('initializeDatabase', ['sidecar-fixture.sqlite', {
            path: dbPath,
            readOnlyMode: false,
            queryTimeout: 30000
        }]);
        check(init.content?.success === true
            && init.content?.data?.isReadOnly === false
            && init.content?.data?.storage === 'memory',
            'sidecar/initializeDatabase-opens-bound-path', JSON.stringify(init.content));

        const schema = await rw.invoke('fetchSchema', []);
        const tables = schema.content?.data?.tables?.map((table) => table.identifier) ?? [];
        const views = schema.content?.data?.views?.map((view) => view.identifier) ?? [];
        check(schema.content?.success === true
            && tables.includes('t') && views.includes('v'),
            'sidecar/fetchSchema-returns-real-schema', JSON.stringify({ tables, views }));

        // Real rows through real frames; the blob arrives as a tagged
        // Uint8Array, byte-intact.
        const rows = await rw.invoke('runConsole', ['SELECT id, name, data, r FROM t ORDER BY id']);
        const result = rows.content?.data?.results?.[0];
        const blob = result?.rows?.[0]?.[2];
        check(rows.content?.success === true
            && JSON.stringify(result?.headers) === JSON.stringify(['id', 'name', 'data', 'r'])
            && result?.rows?.length === 3
            && result?.rows?.[0]?.[1] === 'alpha'
            && result?.rows?.[0]?.[3] === 1.5
            && blob instanceof Uint8Array && equalBytes([...blob], FIXTURE_BLOB)
            && result?.rows?.[1]?.[2] === null,
            'sidecar/runConsole-selects-with-blob-tag',
            JSON.stringify(rows.content, (_key, v) => (typeof v === 'bigint' ? `${v}n` : v instanceof Uint8Array ? [...v] : v)));

        // int64 OUTBOUND: updateCellBatch reads prior values with useBigInt, so
        // the response carries a genuine BigInt through the codec's int64 tag.
        const update = await rw.invoke('updateCellBatch', ['t', [{ rowId: 1, column: 'big', value: 5 }]]);
        const priorValue = update.content?.data?.[0]?.priorValue;
        check(update.content?.success === true && priorValue === INT64_MAX,
            'sidecar/int64-survives-outbound-envelope',
            `priorValue=${typeof priorValue === 'bigint' ? `${priorValue}n` : JSON.stringify(priorValue)}`);

        // int64 INBOUND: a BigInt RPC parameter binds losslessly (a lossy
        // Number would make the equality fail).
        const bound = await rw.invoke('runQuery', [
            'SELECT ? = 9223372036854775807 AS eq', [INT64_MAX]
        ]);
        check(bound.content?.success === true && bound.content?.data?.[0]?.rows?.[0]?.[0] === 1,
            'sidecar/int64-survives-inbound-envelope', JSON.stringify(bound.content?.data));

        // A small BigInt reaches the sidecar whenever the page sends one
        // through the codec's int64 tag; it must bind as INTEGER, as a large
        // one already did.
        const small = await rw.invoke('runQuery', ['SELECT ? AS v, typeof(?) AS t', [5n, 5n]]);
        check(small.content?.success === true
            && JSON.stringify(small.content?.data?.[0]?.rows) === JSON.stringify([[5, 'integer']]),
            'sidecar/small-bigint-parameter-is-stored-as-integer', JSON.stringify(small.content));

        const mutation = await rw.invoke('runConsole', [
            "INSERT INTO t VALUES (4, 'delta', NULL, 4, 4.0)"
        ]);
        check(mutation.content?.success === true
            && mutation.content?.data?.mutated === true
            && mutation.content?.data?.changes === 1,
            'sidecar/runConsole-reports-mutation', JSON.stringify(mutation.content?.data));

        // exportDatabase served through the shim's exportAsync at the dispatch
        // layer; the image must reopen and contain the mutation above.
        const exported = await rw.invoke('exportDatabase', []);
        const bytes = exported.content?.data;
        let reopenedCount = null;
        if (bytes instanceof Uint8Array) {
            const copyPath = path.join(scratch, 'sidecar-export.sqlite');
            fs.writeFileSync(copyPath, bytes);
            const reopened = new DatabaseSync(copyPath, { readOnly: true });
            reopenedCount = reopened.prepare('SELECT count(*) AS c FROM t').get().c;
            reopened.close();
        }
        check(exported.content?.success === true
            && bytes instanceof Uint8Array
            && String.fromCharCode(...bytes.subarray(0, 15)) === 'SQLite format 3'
            && reopenedCount === 4,
            'sidecar/exportDatabase-roundtrips', `bytes=${bytes?.length}, rows=${reopenedCount}`);

        // SECURITY: ATTACH/DETACH must not reach files outside the bound path.
        // The reviewer's exact READ and WRITE bypasses, replayed through the
        // real binary via runConsole (an intended webview feature). runConsole
        // resolves failures (failure-is-a-resolution), so the block surfaces in
        // data.error; nothing must run, and the out-of-path files must be
        // untouched. `secret` proves a READ can't reach it; `planted` proves a
        // WRITE can't create it.
        const secretPath = path.join(scratch, 'attack-secret.sqlite');
        const plantedPath = path.join(scratch, 'attack-planted.sqlite');
        fs.rmSync(plantedPath, { force: true });
        {
            const secret = new DatabaseSync(secretPath);
            secret.exec("CREATE TABLE secrets(v); INSERT INTO secrets VALUES('TOPSECRET')");
            secret.close();
        }
        const attachBlocked = (data) => /blocked on the native engine/i.test(data?.error ?? '')
            && (data?.results?.length ?? 0) === 0
            && data?.mutated === false;

        const attachRead = await rw.invoke('runConsole', [
            `ATTACH DATABASE '${secretPath}' AS steal; SELECT v FROM steal.secrets`
        ]);
        check(attachRead.content?.success === true && attachBlocked(attachRead.content?.data),
            'sidecar/ATTACH-read-blocked', JSON.stringify(attachRead.content?.data));

        const attachWrite = await rw.invoke('runConsole', [
            `ATTACH DATABASE '${plantedPath}' AS evil; CREATE TABLE evil.pwn(x); INSERT INTO evil.pwn VALUES(1)`
        ]);
        check(attachWrite.content?.success === true
            && attachBlocked(attachWrite.content?.data)
            && !fs.existsSync(plantedPath),
            'sidecar/ATTACH-write-blocked-and-no-file-created',
            `${JSON.stringify(attachWrite.content?.data)} planted=${fs.existsSync(plantedPath)}`);

        const detach = await rw.invoke('runConsole', ['DETACH DATABASE steal']);
        check(detach.content?.success === true
            && /blocked on the native engine/i.test(detach.content?.data?.error ?? ''),
            'sidecar/DETACH-blocked', JSON.stringify(detach.content?.data?.error));

        // Smuggling: a leading block comment and mixed case must not slip past
        // the leading-token reject.
        const smuggle = await rw.invoke('runConsole', [
            `/*x*/ AtTaCh DATABASE '${secretPath}' AS s3`
        ]);
        check(smuggle.content?.success === true
            && /blocked on the native engine/i.test(smuggle.content?.data?.error ?? ''),
            'sidecar/ATTACH-smuggle-comment-and-case-blocked', JSON.stringify(smuggle.content?.data?.error));

        // Not over-broad: the word `attach` inside a string literal is fine, and
        // normal single-DB SELECT/INSERT keep working right after the blocks.
        const benign = await rw.invoke('runConsole', ["SELECT 'attach me' AS note"]);
        check(benign.content?.success === true
            && benign.content?.data?.results?.[0]?.rows?.[0]?.[0] === 'attach me'
            && benign.content?.data?.error === undefined,
            'sidecar/word-attach-in-literal-not-blocked', JSON.stringify(benign.content?.data));

        const normalInsert = await rw.invoke('runConsole', ["INSERT INTO t VALUES (5, 'epsilon', NULL, 5, 5.0)"]);
        check(normalInsert.content?.success === true && normalInsert.content?.data?.mutated === true,
            'sidecar/normal-sql-unaffected-by-attach-block', JSON.stringify(normalInsert.content?.data));

        // SECURITY: VACUUM ... INTO must not write a database copy outside the
        // bound path. The reviewer's exact probe, replayed through the real
        // binary via runConsole; nothing must run and the out-of-path file must
        // not be created.
        const vacuumTarget = path.join(scratch, 'attack-PWNED.db');
        fs.rmSync(vacuumTarget, { force: true });
        const vacuumInto = await rw.invoke('runConsole', [`VACUUM INTO '${vacuumTarget}'`]);
        check(vacuumInto.content?.success === true
            && /blocked on the native engine/i.test(vacuumInto.content?.data?.error ?? '')
            && (vacuumInto.content?.data?.results?.length ?? 0) === 0
            && !fs.existsSync(vacuumTarget),
            'sidecar/VACUUM-INTO-blocked-and-no-file-created',
            `${JSON.stringify(vacuumInto.content?.data?.error)} created=${fs.existsSync(vacuumTarget)}`);

        // In-place VACUUM (no INTO) must stay legitimate.
        const plainVacuum = await rw.invoke('runConsole', ['VACUUM']);
        check(plainVacuum.content?.success === true && plainVacuum.content?.data?.error === undefined,
            'sidecar/plain-VACUUM-allowed', JSON.stringify(plainVacuum.content?.data));

        // NON-INTERFERENCE: exportDatabase issues the shim's OWN VACUUM INTO via
        // backing.prepare (bypassing compileNext), so the guard must not touch
        // it — prove the whole export path still works after the block lands.
        const exportAfterBlock = await rw.invoke('exportDatabase', []);
        check(exportAfterBlock.content?.success === true
            && exportAfterBlock.content?.data instanceof Uint8Array
            && String.fromCharCode(...exportAfterBlock.content.data.subarray(0, 15)) === 'SQLite format 3',
            'sidecar/export-still-works-after-vacuum-block',
            `bytes=${exportAfterBlock.content?.data?.length}`);

        // Not over-broad: the phrase in a string literal is fine.
        const vacuumLiteral = await rw.invoke('runConsole', ["SELECT 'vacuum into' AS note"]);
        check(vacuumLiteral.content?.success === true
            && vacuumLiteral.content?.data?.results?.[0]?.rows?.[0]?.[0] === 'vacuum into'
            && vacuumLiteral.content?.data?.error === undefined,
            'sidecar/vacuum-into-in-literal-not-blocked', JSON.stringify(vacuumLiteral.content?.data));

        // A table whose name merely starts with "vacuum" is unaffected (leading
        // token `vacuumlog` is not the `vacuum` keyword; no INTO involved).
        const vacuumlog = await rw.invoke('runConsole', [
            'CREATE TABLE vacuumlog(into_count); INSERT INTO vacuumlog VALUES (1); SELECT into_count FROM vacuumlog'
        ]);
        check(vacuumlog.content?.success === true
            && vacuumlog.content?.data?.results?.[0]?.rows?.[0]?.[0] === 1
            && vacuumlog.content?.data?.error === undefined,
            'sidecar/vacuumlog-table-and-into-column-unaffected', JSON.stringify(vacuumlog.content?.data?.error));

        // Tripwires: the other SQL→filesystem vectors are absent/disabled in the
        // pinned fork binary. If a future binary bump enables one, THIS fails —
        // forcing a matching block before it can ship as a hole.
        for (const [label, sql] of [
            ['readfile', "SELECT readfile('/etc/hosts')"],
            ['writefile', "SELECT writefile('/tmp/sqlx-tripwire','x')"],
            ['load_extension', "SELECT load_extension('/tmp/x')"]
        ]) {
            const probe = await rw.invoke('runConsole', [sql]);
            check(probe.content?.success === true && (probe.content?.data?.error ?? '') !== '',
                `sidecar/tripwire-${label}-unavailable`, JSON.stringify(probe.content?.data?.error));
        }

        // ---- engine defects a review found, on the real binary ------------
        // Every one of these was a SILENTLY WRONG answer through this exact
        // path, so each asserts the value or the on-disk state, not a message.

        // E-1: a statement with no trailing `;` used to lose its whole result
        // set to a fabricated leftover-SQL error (sql.js) — the guard is gone
        // on both engines, so this must simply answer.
        const noSemicolon = await rw.invoke('runConsole', ['SELECT 1 AS one']);
        check(noSemicolon.content?.success === true
            && noSemicolon.content?.data?.error === undefined
            && noSemicolon.content?.data?.results?.[0]?.rows?.[0]?.[0] === 1,
            'sidecar/E1-statement-without-trailing-semicolon-returns-rows',
            JSON.stringify(noSemicolon.content?.data));

        // E-1b: NUL in console SQL is refused up front rather than running the
        // prefix and dropping the rest.
        const nulSql = await rw.invoke('runConsole', ['SELECT 1\u0000; SELECT 2']);
        check(nulSql.content?.success === false
            && /NUL/.test(nulSql.content?.errorMessage ?? ''),
            'sidecar/E1-nul-in-console-sql-refused',
            JSON.stringify(nulSql.content?.errorMessage));

        // E-2: every value-returning PRAGMA came back as ZERO ROWS and no
        // error, because the shim cannot name a PRAGMA's columns before it has
        // been stepped and the console read that as "this is DML".
        const pragmaRows = await rw.invoke('runConsole', ['PRAGMA table_info(t)']);
        const pragmaResult = pragmaRows.content?.data?.results?.[0];
        check(pragmaRows.content?.success === true
            && pragmaRows.content?.data?.error === undefined
            && JSON.stringify(pragmaResult?.headers)
                === JSON.stringify(['cid', 'name', 'type', 'notnull', 'dflt_value', 'pk'])
            && JSON.stringify(pragmaResult?.rows?.map((row) => row[1]))
                === JSON.stringify(['id', 'name', 'data', 'big', 'r']),
            'sidecar/E2-value-returning-pragma-returns-rows',
            JSON.stringify(pragmaRows.content?.data));

        const journalMode = await rw.invoke('runConsole', ['PRAGMA journal_mode']);
        check(journalMode.content?.success === true
            && journalMode.content?.data?.results?.[0]?.rows?.length === 1,
            'sidecar/E2-pragma-journal_mode-returns-its-value',
            JSON.stringify(journalMode.content?.data));

        // E-2b: the same root cause as the known RETURNING gap — and the fix
        // closes it. The row comes back AND the insert applies exactly once.
        await rw.invoke('runConsole', ['CREATE TABLE returning_probe(n INTEGER)']);
        const returning = await rw.invoke('runConsole', [
            'INSERT INTO returning_probe VALUES (41) RETURNING n + 1 AS answer'
        ]);
        const applied = await rw.invoke('runConsole', [
            'SELECT count(*) AS c FROM returning_probe'
        ]);
        check(returning.content?.success === true
            && returning.content?.data?.results?.[0]?.rows?.[0]?.[0] === 42
            && applied.content?.data?.results?.[0]?.rows?.[0]?.[0] === 1,
            'sidecar/E2-dml-with-returning-yields-its-row-once',
            JSON.stringify(returning.content?.data));

        // E-4: db.exec() collapsed duplicate result column names and shifted
        // the values left. runQuery is the only caller, and it answered wrong
        // rather than erroring.
        await rw.invoke('runConsole', [
            'CREATE TABLE dup_parent(id INTEGER PRIMARY KEY, label TEXT);'
            + 'CREATE TABLE dup_child(id INTEGER PRIMARY KEY, parent_id INTEGER, note TEXT);'
            + "INSERT INTO dup_parent VALUES (1,'p1'); INSERT INTO dup_child VALUES (7,1,'c1')"
        ]);
        const joined = await rw.invoke('runQuery', [
            'SELECT * FROM dup_parent JOIN dup_child ON dup_child.parent_id = dup_parent.id'
        ]);
        const joinedSet = joined.content?.data?.[0];
        check(joined.content?.success === true
            && joinedSet?.headers?.length === 5
            && JSON.stringify(joinedSet?.rows?.[0]) === JSON.stringify([1, 'p1', 7, 1, 'c1']),
            'sidecar/E4-duplicate-result-columns-keep-every-value',
            JSON.stringify(joinedSet));

        // E-3: updateCell reported success for a row that does not exist and
        // changed nothing; updateCellBatch always refused. They must agree.
        const ghost = await rw.invoke('updateCell', ['t', 999999, 'name', 'ghost']);
        check(ghost.content?.success === false
            && /row 999999 no longer exists/.test(ghost.content?.errorMessage ?? ''),
            'sidecar/E3-updateCell-refuses-a-row-that-does-not-exist',
            JSON.stringify(ghost.content?.errorMessage));

        const liveEdit = await rw.invoke('updateCell', ['t', 1, 'name', 'alpha-edited']);
        const liveRead = await rw.invoke('runConsole', ['SELECT name FROM t WHERE id = 1']);
        check(liveEdit.content?.success === true
            && liveRead.content?.data?.results?.[0]?.rows?.[0]?.[0] === 'alpha-edited',
            'sidecar/E3-updateCell-still-applies-to-a-row-that-exists',
            JSON.stringify(liveRead.content?.data));

        // E-5: TEXT written through the WASM engine lost everything past its
        // first NUL. Both engines now route it through a blob bind + CAST, so
        // the bytes on disk are identical on both.
        await rw.invoke('updateCell', ['t', 1, 'name', 'a\u0000b']);
        const nulBytes = await rw.invoke('runConsole', [
            'SELECT hex(CAST(name AS BLOB)) AS h, typeof(name) AS t FROM t WHERE id = 1'
        ]);
        check(nulBytes.content?.data?.results?.[0]?.rows?.[0]?.[0] === '610062'
            && nulBytes.content?.data?.results?.[0]?.rows?.[0]?.[1] === 'text',
            'sidecar/E5-text-with-an-embedded-nul-round-trips',
            JSON.stringify(nulBytes.content?.data?.results?.[0]?.rows?.[0]));

        // E-15: foreign_keys defaulted to 1 on native and 0 on WASM, so the
        // same delete was refused on one engine and orphaned children on the
        // other. Pinned ON at open on both.
        const pragmas = await rw.invoke('getPragmas', []);
        check(pragmas.content?.success === true && pragmas.content?.data?.foreign_keys === 1,
            'sidecar/E15-foreign-keys-enforced', JSON.stringify(pragmas.content?.data?.foreign_keys));

        await rw.invoke('runConsole', [
            'CREATE TABLE fk_parent(id INTEGER PRIMARY KEY);'
            + 'CREATE TABLE fk_child(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES fk_parent(id));'
            + 'INSERT INTO fk_parent VALUES (1); INSERT INTO fk_child VALUES (1,1)'
        ]);
        const orphan = await rw.invoke('deleteRows', ['fk_parent', [1]]);
        const survivors = await rw.invoke('runConsole', ['SELECT count(*) AS c FROM fk_child']);
        check(orphan.content?.success === false
            && survivors.content?.data?.results?.[0]?.rows?.[0]?.[0] === 1,
            'sidecar/E15-parent-delete-refused-instead-of-orphaning',
            JSON.stringify(orphan.content?.errorMessage));

        // Oversize response: the wrapped postMessage must answer IN BAND for
        // the same messageId instead of stranding the RPC (worker.js's send
        // sites are unguarded by design — byte-identity gate). runQuery, not
        // the console: the console cuts its own answer to fit the frame.
        const oversize = await rw.invoke('runQuery', [
            'SELECT randomblob(17 * 1024 * 1024) AS b'
        ], 60000);
        check(oversize.content?.success === false
            && oversize.content?.error?.code === NATIVE_FRAME_TOO_LARGE
            && typeof oversize.content?.messageId === 'string',
            'sidecar/oversize-response-answers-in-band', JSON.stringify(oversize.content?.error));

        const afterOversize = await rw.invoke('runConsole', ['SELECT 1 AS ok']);
        check(afterOversize.content?.success === true
            && afterOversize.content?.data?.results?.[0]?.rows?.[0]?.[0] === 1,
            'sidecar/session-survives-oversize-response');

        const unknown = await rw.invoke('definitelyNotAMethod', []);
        check(unknown.content?.success === false
            && unknown.content?.errorMessage === 'Unknown method: definitelyNotAMethod',
            'sidecar/unknown-method-reply-passes-wrapped-send', JSON.stringify(unknown.content));

        // Query deadline: re-init with a 250ms budget, then fire a statement
        // that would otherwise run for minutes. runConsole RESOLVES with the
        // timeout recorded (failure-is-a-resolution), fast. The runtime's
        // deadline interrupts the statement, and an interrupt at or after the
        // deadline reads as the same timeout the WebAssembly engine reports.
        const reinit = await rw.invoke('initializeDatabase', ['sidecar-fixture.sqlite', {
            path: dbPath,
            readOnlyMode: false,
            queryTimeout: 250
        }]);
        check(reinit.content?.success === true, 'sidecar/re-initializeDatabase');

        const startedAt = Date.now();
        const runaway = await rw.invoke('runConsole', [RUNAWAY_SQL], 30000);
        const elapsedMs = Date.now() - startedAt;
        check(runaway.content?.success === true
            && /timed out after 250ms/.test(runaway.content?.data?.error ?? '')
            && elapsedMs < 10000,
            'sidecar/query-deadline-interrupts-runaway',
            `${elapsedMs}ms -- ${JSON.stringify(runaway.content?.data?.error)}`);

        const afterDeadline = await rw.invoke('runConsole', ['SELECT 1 AS ok']);
        check(afterDeadline.content?.success === true,
            'sidecar/session-survives-deadline-interrupt');

        // Path binding: layer 2 must refuse any path but the argv one, and the
        // refusal must not create the other file (`create: true` would).
        const elsewhere = path.join(scratch, 'not-the-bound-db.sqlite');
        const refused = await rw.invoke('initializeDatabase', ['x', {
            path: elsewhere, readOnlyMode: false
        }]);
        check(refused.content?.success === false
            && /bound to at spawn/.test(refused.content?.errorMessage ?? '')
            && !fs.existsSync(elsewhere),
            'sidecar/wrong-path-initializeDatabase-refused',
            JSON.stringify(refused.content?.errorMessage));

        // Byte-mode opens have no place in the native engine either.
        const byteMode = await rw.invoke('initializeDatabase', ['x', {
            content: new Uint8Array([1, 2, 3])
        }]);
        check(byteMode.content?.success === false,
            'sidecar/content-mode-initializeDatabase-refused',
            JSON.stringify(byteMode.content?.errorMessage));

        rw.endStdin();
        const code = await rw.untilExit();
        check(code === 0, 'sidecar/stdin-eof-exits-clean', `exit ${code}`);
    } finally {
        if (rw.exitCode === null) rw.child.kill('SIGKILL');
        const stderrText = rw.stderr.trim();
        // Worker-side console.error noise (method errors) is expected for the
        // refusal cases; keep it visible without failing on it.
        if (stderrText) console.log(`[sidecar rw stderr]\n${stderrText}\n`);
    }

    // ---- read-only session ------------------------------------------------
    createFixture(dbPath);
    const ro = startSidecar(binary, dbPath, 'ro');
    try {
        const init = await ro.invoke('initializeDatabase', ['sidecar-fixture.sqlite', {
            path: dbPath, readOnlyMode: true
        }]);
        check(init.content?.success === true && init.content?.data?.isReadOnly === true,
            'sidecar/ro-session-opens-read-only', JSON.stringify(init.content));

        const boundedRead = await ro.invoke('executeReadQuery', ['SELECT 1 AS value']);
        const badRead = await ro.invoke('executeReadQuery', ['SELECT * FROM absent_read_table']);
        const enforced = await ro.invoke('executeReadQuery', ['SELECT query_only FROM pragma_query_only']);
        const noMetadataViews = await ro.invoke('executeReadQuery', [
            "SELECT count(*) FROM sqlite_temp_schema WHERE name LIKE 'query_columns_%'"
        ]);
        check(boundedRead.content?.success === true && boundedRead.content?.data?.rows?.[0]?.[0] === 1
            && badRead.content?.success === false
            && enforced.content?.data?.rows?.[0]?.[0] === 1
            && noMetadataViews.content?.data?.rows?.[0]?.[0] === 0,
            'sidecar/ro-bounded-reads-preserve-enforcement-and-clean-up',
            JSON.stringify({ read: boundedRead.content, guard: enforced.content, views: noMetadataViews.content }));

        // The console refuses the write by name before compiling it, and that
        // refusal resolves as any statement error does (runReadOnlyConsoleCase
        // drives the console's reads and refusals on a read-only file).
        const write = await ro.invoke('runConsole', ["INSERT INTO t VALUES (9, 'x', NULL, 9, 9.0)"]);
        check(write.content?.success === true
            && /^statement 1: INSERT is unavailable because the database is read-only/.test(write.content?.data?.error ?? '')
            && write.content?.data?.mutated === false,
            'sidecar/ro-session-blocks-writes', JSON.stringify(write.content));

        // Reads still flow through the structured methods. Export also works
        // read-only (VACUUM INTO a temp copy, not a write to the database
        // itself).
        const read = await ro.invoke('fetchSchema', []);
        check(read.content?.success === true
            && (read.content?.data?.tables?.map((table) => table.identifier) ?? []).includes('t'),
            'sidecar/ro-session-reads-via-structured-methods');

        const exported = await ro.invoke('exportDatabase', []);
        check(exported.content?.success === true
            && exported.content?.data instanceof Uint8Array
            && String.fromCharCode(...exported.content.data.subarray(0, 15)) === 'SQLite format 3',
            'sidecar/ro-session-exports');

        // Escalation refusal: an `ro` spawn never grants a writable open, no
        // matter what the config asks for.
        const escalate = await ro.invoke('initializeDatabase', ['sidecar-fixture.sqlite', {
            path: dbPath, readOnlyMode: false
        }]);
        check(escalate.content?.success === false
            && /read-only session/.test(escalate.content?.errorMessage ?? ''),
            'sidecar/ro-session-refuses-writable-reopen',
            JSON.stringify(escalate.content?.errorMessage));

        ro.endStdin();
        const code = await ro.untilExit();
        check(code === 0, 'sidecar/ro-session-eof-exits-clean', `exit ${code}`);
    } finally {
        if (ro.exitCode === null) ro.child.kill('SIGKILL');
        const stderrText = ro.stderr.trim();
        if (stderrText) console.log(`[sidecar ro stderr]\n${stderrText}\n`);
    }

    // ---- shell-originated export-to-path (> 16 MiB, bytes never framed) ----
    // The out-of-band export route: the shell hands the sidecar a temp path
    // and the RESULT crosses the pipe as a path-sized reply, never as bytes.
    // Driven on a fixture whose DB image AND CSV export both exceed the
    // 16 MiB frame cap — the framed route provably cannot carry either.
    checks += await runShellExportCase(binary, scratch, note);

    // ---- fatal desync exit mapping ----------------------------------------
    // The frame lane proves this contract for its echo harness; this proves
    // the SHIPPING entry maps a desync to flush + NONZERO exit too.
    const desync = startSidecar(binary, dbPath, 'rw');
    try {
        // 0xffffffff: not a plausible length — the reader stops for good.
        desync.child.stdin.write(Buffer.from([0xff, 0xff, 0xff, 0xff]));
        const code = await desync.untilExit();
        check(code !== 'TIMEOUT' && code !== 0 && code !== null,
            'sidecar/desync-exits-nonzero-without-hanging', `exit ${code}`);
    } finally {
        if (desync.exitCode === null) desync.child.kill('SIGKILL');
        const stderrText = desync.stderr.trim();
        if (stderrText) console.log(`[sidecar desync stderr]\n${stderrText}\n`);
    }

    // ---- usage exit (malformed argv) --------------------------------------
    // A direct child (no reparenting), so its real wait-status IS reap-able.
    // Bad flag + a path that must never be opened: assert exit 2 and that the
    // named file was not created (the entry exits at argv parse, before any
    // open).
    {
        const neverOpened = path.join(scratch, 'must-not-open.sqlite');
        fs.rmSync(neverOpened, { force: true });
        const usage = spawn(binary, ['run', BUNDLE_PATH, neverOpened, 'bogus'], {
            stdio: ['ignore', 'ignore', 'pipe']
        });
        let usageStderr = '';
        usage.stderr.on('data', (chunk) => { usageStderr += chunk; });
        const code = await new Promise((resolve) => usage.on('close', resolve));
        check(code === 2 && !fs.existsSync(neverOpened),
            'sidecar/malformed-argv-exits-2-without-opening',
            `exit ${code}, opened=${fs.existsSync(neverOpened)}, stderr=${JSON.stringify(usageStderr.trim().slice(0, 120))}`);
    }

    // ---- a file the process cannot write -------------------------------
    checks += await runUnwritableFileCase(binary, scratch, note);

    // ---- journal_mode WAL round trip --------------------------------------
    checks += await runJournalModeCase(binary, scratch, note);
    checks += await runWalExitCase(binary, scratch, note);
    checks += await runWalWatchdogCase(binary, scratch, note);

    checks += await runFtsShadowReadCase(binary, scratch, note);
    checks += await runUtf16ReadCase(binary, scratch, note);
    checks += await runReadBoundaryCase(binary, scratch, note);
    checks += await runImportConflictCase(binary, scratch, note);
    checks += await runLockWaitCase(binary, scratch, note);
    checks += await runReplyFrameCase(binary, scratch, note);
    checks += await runTransferCommitCase(binary, scratch, note);
    checks += await runConsoleAndDeadlineCase(binary, scratch, note);
    checks += await runSameChunkOrderCase(binary, scratch, note);
    checks += await runReplyReserveCase(binary, scratch, note);
    checks += await runLargeValueCase(binary, scratch, note);
    checks += await runConsoleDuplicateNamesCase(binary, scratch, note);
    checks += await runConsoleParameterHeadersCase(binary, scratch, note);
    checks += await runConsoleUnknownOutcomeCase(binary, scratch, note);
    checks += await runParameterMarkerCase(binary, scratch, note);
    checks += await runReadOnlyModuleCheckCase(binary, scratch, note);
    checks += await runReadOnlyConsoleCase(binary, scratch, note);
    checks += await runFramePageCase(binary, scratch, note);
    checks += await runFrameRawTextRoomCase(binary, scratch, note);
    checks += await runFrameAnchorCase(binary, scratch, note);
    checks += await runFrameKeyRoomCase(binary, scratch, note);
    checks += await runViewPreviewFrameCase(binary, scratch, note);

    // ---- ppid watchdog ----------------------------------------------------
    checks += await runWatchdogCase(binary, dbPath, note);

    return checks;
}

/**
 * Reads refuse writes on the native engine: worker.js readRefusingWrites,
 * held through the shim so its column probe can still make its TEMP VIEW.
 * The probe view has a row only while the connection accepts writes, so
 * every read entry must find it empty; a statement that is not a read still
 * sees a writable connection, and the session writes normally afterwards.
 */
export async function runReadBoundaryCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const show = (reply) => JSON.stringify(reply?.content, (_key, v) => (typeof v === 'bigint' ? `${v}n` : v));
    const dbPath = path.join(scratch, 'read-boundary.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, label TEXT);
        INSERT INTO notes (label) VALUES ('one'), ('two');
        CREATE VIEW guard_probe AS SELECT 1 AS writable FROM pragma_query_only WHERE query_only = 0;`);
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        const init = await session.invoke('initializeDatabase', [path.basename(dbPath), {
            path: dbPath, readOnlyMode: false, queryTimeout: 30000
        }]);
        check(init.content?.success === true && init.content?.data?.isReadOnly === false,
            'sidecar/read-boundary/opens-writable', show(init));

        // Control: not a read, so the same view sees a writable connection and
        // an empty answer below is the boundary at work.
        const control = await session.invoke('runQuery', ['PRAGMA query_only; SELECT count(*) FROM guard_probe']);
        check(control.content?.success === true && control.content?.data?.at(-1)?.rows?.[0]?.[0] === 1,
            'sidecar/read-boundary/control-sees-a-writable-connection', show(control));

        const rowsOf = (reply) => reply.content?.data?.rows?.length;
        const page = await session.invoke('fetchTableData', ['guard_probe', { limit: 100, offset: 0 }]);
        check(page.content?.success === true && rowsOf(page) === 0, 'sidecar/read-boundary/grid-page', show(page));
        const filtered = await session.invoke('fetchTableData', ['guard_probe', { limit: 100, offset: 0, globalFilter: '1' }]);
        check(filtered.content?.success === true && rowsOf(filtered) === 0,
            'sidecar/read-boundary/filtered-grid-page', show(filtered));
        const count = await session.invoke('fetchTableCount', ['guard_probe', {}]);
        check(count.content?.success === true && count.content?.data?.count === 0,
            'sidecar/read-boundary/count', show(count));
        for (const [label, sql] of [
            ['generic-select', 'SELECT count(*) FROM guard_probe'],
            ['generic-with-select', '/* lead */ WITH probe (writable) AS (SELECT writable FROM guard_probe) SELECT count(*) FROM probe;'],
            ['generic-values', 'VALUES ((SELECT count(*) FROM guard_probe))']
        ]) {
            const read = await session.invoke('runQuery', [sql]);
            check(read.content?.success === true && read.content?.data?.[0]?.rows?.[0]?.[0] === 0,
                `sidecar/read-boundary/${label}`, show(read));
        }
        const exported = await session.invoke('exportTable', [
            { table: 'guard_probe' }, ['writable'], null, null, { format: 'csv', header: false }
        ]);
        check(exported.content?.success === true
            && (exported.content?.data?.contentChunks ?? []).join('').trim() === '',
            'sidecar/read-boundary/table-export', show(exported));

        // A console read holds it too, a read after an empty statement
        // included: that statement's compiled text starts with the `;`.
        const consoleRead = await session.invoke('runConsole', [
            'SELECT count(*) FROM guard_probe;; SELECT count(*) FROM guard_probe', {}
        ]);
        check(consoleRead.content?.success === true && consoleRead.content?.data?.error === undefined
            && JSON.stringify(consoleRead.content?.data?.results?.map((set) => set.rows[0][0])) === '[0,0]',
            'sidecar/read-boundary/console-reads-after-an-empty-statement', show(consoleRead));

        // The flag is down again after every read: a write goes through.
        const after = await session.invoke('runQuery', ['PRAGMA query_only']);
        const write = await session.invoke('runQuery', ["INSERT INTO notes (label) VALUES ('three')"]);
        const total = await session.invoke('fetchTableCount', ['notes', {}]);
        check(after.content?.data?.[0]?.rows?.[0]?.[0] === 0
            && write.content?.success === true
            && total.content?.data?.count === 3,
            'sidecar/read-boundary/connection-writable-afterwards',
            JSON.stringify([show(after), show(write), show(total)]));
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/read-boundary/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * The FTS3/FTS4 engine switch reads through the read workspace because
 * runQuery refuses every statement on a read-only session: on a file the
 * process cannot write, the workspace still reads the catalog and the journal
 * mode, and reports the missing module as SQLite words it.
 */
export async function runReadOnlyModuleCheckCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'read-only-fts4.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec("CREATE VIRTUAL TABLE docs USING fts4(body); INSERT INTO docs VALUES ('hello');");
    seed.close();
    fs.chmodSync(dbPath, 0o444);
    const session = startSidecar(binary, dbPath, 'rw');
    const show = (reply) => JSON.stringify(reply?.content).slice(0, 400);
    try {
        const init = await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 30000 }]);
        check(init.content?.data?.isReadOnly === true, 'sidecar/read-only-module-check/opens-read-only', show(init));
        const refused = await session.invoke('runQuery', ["SELECT name FROM main.sqlite_schema WHERE type = 'table'"]);
        check(refused.content?.success === false, 'sidecar/read-only-module-check/runQuery-refuses', show(refused));
        const consoleRead = await session.invoke('runConsole', ['SELECT 1', {}]);
        check(consoleRead.content?.success === true && consoleRead.content?.data?.results?.[0]?.rows?.[0]?.[0] === 1,
            'sidecar/read-only-module-check/console-answers-a-read', show(consoleRead));
        const catalog = await session.invoke('executeReadQuery', ["SELECT name FROM main.sqlite_schema WHERE type = 'table' AND sql LIKE 'CREATE VIRTUAL TABLE%'", '[]']);
        check(JSON.stringify(catalog.content?.data?.rows) === '[["docs"]]', 'sidecar/read-only-module-check/workspace-reads-the-catalog', show(catalog));
        const compiled = await session.invoke('executeReadQuery', ['SELECT 1 FROM main."docs" LIMIT 0', '[]']);
        check(compiled.content?.success === false && compiled.content?.errorMessage === 'no such module: fts4',
            'sidecar/read-only-module-check/workspace-names-the-missing-module', show(compiled));
        const journal = await session.invoke('executeReadQuery', ['SELECT journal_mode FROM pragma_journal_mode', '[]']);
        check(JSON.stringify(journal.content?.data?.rows) === '[["delete"]]', 'sidecar/read-only-module-check/workspace-reads-the-journal-mode', show(journal));
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/read-only-module-check/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
        fs.chmodSync(dbPath, 0o644);
    }
    return checks;
}

/**
 * The SQL console on a database the process cannot write, in both spawn
 * modes: reads answer, and every statement that is not a read is refused by
 * name before it is compiled. Compiling first would be too late on this
 * engine as on sql.js: preparing `PRAGMA locking_mode = EXCLUSIVE`,
 * `PRAGMA foreign_keys = OFF` or `PRAGMA query_only = 0` sets the flag, none
 * needing a step. locking_mode and foreign_keys (which the worker pins ON) are
 * read back after every refusal and show a pragma that compiled. query_only
 * cannot: the shim lifts and restores it around the column probe of nearly
 * every statement, the read-back's own included, so it reads 1 either way.
 * The 0444 file alone shows nothing either: the OS refuses its writes anyway.
 */
export async function runReadOnlyConsoleCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'read-only-console.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (v) VALUES ('one'), ('two');");
    seed.close();
    fs.chmodSync(dbPath, 0o444);
    const fingerprint = () => ({
        sha256: createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex'),
        mtimeMs: fs.statSync(dbPath).mtimeMs
    });
    const before = fingerprint();
    const show = (value) => JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? `${item}n` : item)).slice(0, 600);
    const refusal = (index, name) => new RegExp(
        `^statement ${index}: ${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} is unavailable because the database is read-only`
    );
    try {
        for (const [mode, readOnlyMode] of [['rw', false], ['ro', true]]) {
            const label = (name) => `sidecar/read-only-console/${mode}/${name}`;
            const session = startSidecar(binary, dbPath, mode);
            try {
                const init = await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode, queryTimeout: 30000 }]);
                check(init.content?.data?.isReadOnly === true, label('opens-read-only'), show(init.content));
                const scalar = async (sql) => (await session.invoke('executeReadQuery', [sql, '[]'])).content?.data?.rows?.[0]?.[0];
                const state = async () => ({
                    queryOnly: await scalar('SELECT query_only FROM pragma_query_only'),
                    lockingMode: await scalar('SELECT locking_mode FROM pragma_locking_mode'),
                    foreignKeys: await scalar('SELECT foreign_keys FROM pragma_foreign_keys'),
                    temp: await scalar('SELECT count(*) FROM sqlite_temp_schema'),
                    rows: await scalar("SELECT group_concat(v, ',') FROM (SELECT v FROM t ORDER BY id)")
                });
                const asFound = show({ queryOnly: 1, lockingMode: 'normal', foreignKeys: 1, temp: 0, rows: 'one,two' });
                const run = async (sql, options = {}) => (await session.invoke('runConsole', [sql, options])).content;

                const read = await run('SELECT id, v FROM t ORDER BY id');
                check(read?.success === true && read.data?.error === undefined && read.data?.mutated === false
                    && show(read.data?.results?.[0]?.rows) === '[[1,"one"],[2,"two"]]',
                    label('answers-a-select'), show(read));
                const script = await run('-- note\nSELECT count(*) FROM t; ; VALUES (2); WITH a (n) AS (SELECT 3) SELECT n FROM a;');
                check(script?.success === true && script.data?.error === undefined
                    && show(script.data?.results?.map((set) => set.rows[0][0])) === '[2,2,3]',
                    label('answers-every-read-of-a-script'), show(script));

                for (const [sql, name, slug] of [
                    ["INSERT INTO t (v) VALUES ('three')", 'INSERT', 'insert'],
                    ["UPDATE t SET v = 'x'", 'UPDATE', 'update'],
                    ['PRAGMA query_only = 0', 'PRAGMA', 'query-only-off'],
                    ['PRAGMA locking_mode = EXCLUSIVE', 'PRAGMA', 'locking-mode'],
                    ['PRAGMA foreign_keys = OFF', 'PRAGMA', 'foreign-keys-off'],
                    ['PRAGMA journal_mode = delete', 'PRAGMA', 'journal-mode'],
                    ['CREATE TEMP TABLE scratch (a)', 'CREATE', 'temp-table'],
                    ["ATTACH DATABASE ':memory:' AS other", 'ATTACH', 'attach'],
                    ['BEGIN', 'BEGIN', 'begin'],
                    ["WITH a AS (SELECT 1) INSERT INTO t (v) SELECT 'w' FROM a", 'A WITH statement that is not a SELECT', 'with-insert']
                ]) {
                    const reply = await run(sql);
                    const after = show(await state());
                    check(reply?.success === true && refusal(1, name).test(reply.data?.error ?? '')
                        && reply.data?.mutated === false && after === asFound,
                        label(`refuses-${slug}-by-name-uncompiled`), show({ reply, after }));
                }
                const mixed = await run("SELECT 1; PRAGMA query_only = 0; INSERT INTO t (v) VALUES ('x')");
                const afterMixed = show(await state());
                check(mixed?.success === true && refusal(2, 'PRAGMA').test(mixed.data?.error ?? '')
                    && mixed.data?.multiStatement === true && mixed.data?.mutated === false && afterMixed === asFound,
                    label('refuses-a-script-at-its-first-non-read'), show({ mixed, afterMixed }));
                // SQLite's Tcl-style `$x(...)` variable: sql.js reads each suffix
                // as part of its variable, so the console refuses the WITH ...
                // INSERT and the pragma by name (web_demo_worker.test.ts); the
                // fork is built without such variables, so here both fail to
                // compile, and nothing after them runs.
                for (const [sql, slug] of [
                    ["WITH a AS (SELECT $x(')) INSERT INTO t (v) VALUES ('x') -- ')) SELECT 1", 'with-insert'],
                    ["SELECT $a(') ; PRAGMA foreign_keys = OFF; SELECT ')", 'script']
                ]) {
                    const misread = await run(sql);
                    const afterMisread = show(await state());
                    check(misread?.success === true && /^statement 1: /.test(misread.data?.error ?? '')
                        && misread.data?.mutated === false && afterMisread === asFound,
                        label(`a-misread-${slug}-changes-nothing`), show({ misread, afterMisread }));
                }
                const plan = await run('SELECT v FROM t WHERE id = 1', { explain: true });
                check(plan?.success === true && plan.data?.error === undefined && plan.data?.explain === true
                    && plan.data?.results?.[0]?.rows?.length > 0 && plan.data?.mutated === false,
                    label('explains-a-select'), show(plan));
                // The fork has no bounded plan reader: a plan is SQLite's own
                // EXPLAIN QUERY PLAN, which refuses a pragma before compiling.
                for (const sql of ['PRAGMA locking_mode = EXCLUSIVE', 'PRAGMA foreign_keys = OFF']) {
                    const pragmaPlan = await run(sql, { explain: true });
                    const afterPlan = show(await state());
                    check(pragmaPlan?.success === true && /PRAGMA statements have no query plan/.test(pragmaPlan.data?.error ?? '')
                        && afterPlan === asFound,
                        label(`explain-refuses-${sql.split(' ')[1]}-uncompiled`), show({ pragmaPlan, afterPlan }));
                }

                session.endStdin();
                check(await session.untilExit() === 0, label('clean-shutdown'));
            } finally {
                if (session.exitCode === null) session.child.kill('SIGKILL');
            }
        }
        const after = fingerprint();
        check(after.sha256 === before.sha256 && after.mtimeMs === before.mtimeMs,
            'sidecar/read-only-console/file-unchanged', show({ before, after }));
    } finally {
        fs.chmodSync(dbPath, 0o644);
    }
    return checks;
}

/**
 * A page answer fits the reply frame whatever its values hold. The page
 * budget used to cost cells as the webview carries them (32 MiB, a string at
 * its UTF-8 bytes), while the sidecar answers in one 16 MiB JSON frame where
 * each char(1) is a six-byte \u0001: 20 rows of 200,000 char(1), small enough
 * to be sent whole, came to 24 MB, and the grid's page after its count (limit
 * 20) was refused by the frame. Now a value the frame cannot carry is an
 * oversized cell, read-only and named as not byte-exact, as one past the page
 * budget always was; no row is dropped and nothing short passes as whole.
 */
export async function runFramePageCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'frame-page.sqlite');
    fs.rmSync(dbPath, { force: true });
    const series = (count, expression) =>
        `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ${count}) SELECT ${expression} FROM n`;
    const control = (bytes) => `replace(hex(zeroblob(${bytes})), '00', char(1))`;
    const columnsNamed = (prefix, count) => Array.from({ length: count }, (_, index) => `${prefix}${index}`);
    const latinColumns = columnsNamed('l', 49);
    const wideColumns = columnsNamed('w', 60);
    const realColumns = columnsNamed('r', 200);
    const hugeName = '\u0001'.repeat(100000);
    const seed = new DatabaseSync(dbPath);
    seed.exec(`
        CREATE TABLE ctrl(v TEXT);
        INSERT INTO ctrl ${series(20, control(200000))};
        CREATE TABLE plain(v TEXT);
        INSERT INTO plain ${series(20, "replace(hex(zeroblob(200000)), '00', 'a')")};
        CREATE TABLE keyed(k INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID;
        INSERT INTO keyed ${series(1000, `i, ${control(4000)}`)};
        CREATE VIEW ctrl_view AS SELECT v FROM keyed;
        CREATE TABLE tight(v TEXT);
        INSERT INTO tight ${series(5000, control(700))};
        CREATE TABLE shadowed(rowid INTEGER, v TEXT);
        INSERT INTO shadowed ${series(1000, `i, ${control(4000)}`)};
        CREATE TABLE text_key(k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID;
        INSERT INTO text_key ${series(1000, `printf('%05d', i) || ${control(2500)}, i`)};
        CREATE TABLE mixed(v TEXT);
        INSERT INTO mixed ${series(20, `replace(hex(zeroblob(52000)), '00', '"' || char(92) || char(10) || char(9) || 'é中😀' || char(8232))`)};
        CREATE VIEW mixed_view AS SELECT v FROM mixed;
        CREATE TABLE blobs(v BLOB);
        INSERT INTO blobs ${series(20, 'zeroblob(838860)')};
        CREATE VIEW blob_view AS SELECT v FROM blobs;
        CREATE TABLE nul(v TEXT);
        INSERT INTO nul ${series(1000, "replace(hex(zeroblob(4000)), '00', char(0))")};
        CREATE TABLE nul_keyed(k INTEGER PRIMARY KEY, v TEXT) WITHOUT ROWID;
        INSERT INTO nul_keyed ${series(1000, "i, replace(hex(zeroblob(4000)), '00', char(0))")};
        CREATE TABLE nul_key(k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID;
        INSERT INTO nul_key ${series(1000, "printf('%05d', i) || replace(hex(zeroblob(2000)), '00', char(0)), i")};
        CREATE TABLE raw_mix(a TEXT, b TEXT);
        INSERT INTO raw_mix ${series(1000, `${control(2700)}, 'x' || char(0)`)};
        CREATE TABLE latin1(${latinColumns.map((column) => `${column} TEXT`).join(', ')});
        INSERT INTO latin1 ${series(5000, latinColumns.map(() => "CAST(X'636166E9' AS TEXT)").join(', '))};
        CREATE TABLE wide(${wideColumns.map((column) => `${column} TEXT`).join(', ')});
        INSERT INTO wide ${series(1000, wideColumns.map(() => "replace(hex(zeroblob(135)), '00', 'ab')").join(', '))};
        CREATE TABLE huge_name("${hugeName}" TEXT);
        INSERT INTO huge_name ${series(1000, control(4000))};
        CREATE TABLE long_key(k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID;
        INSERT INTO long_key ${series(2500, `printf('%05d', i) || ${control(3000)}, i`)};
        CREATE TABLE wide_real(${realColumns.map((column) => `${column} REAL`).join(', ')});
        INSERT INTO wide_real ${series(5000, realColumns.map((_column, index) => `(i + ${index}) / 3.0`).join(', '))};
    `);
    seed.close();
    const ctrlValue = '\u0001'.repeat(200000);
    const keyedValue = '\u0001'.repeat(4000);
    const show = (value) => String(JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? `${item}n` : item))).slice(0, 400);
    // The grid's own request (grid-data.js buildDataQueryOptions; the host adds
    // maxInlineCellBytes): the first page asks for 5,000 rows, and once its
    // short length proved the count, the grid asks again bounded by it.
    const gridPage = (columns, limit, orderBy = null, keyset = { mode: 'first' }) => ({
        columns, globalFilterColumns: columns.filter((column) => column !== 'rowid'),
        orderBy, orderDir: 'ASC', limit, offset: 0, pageSize: 5000, filters: [], globalFilter: '',
        ...(keyset ? { keyset } : {}), maxInlineCellBytes: 1048576
    });
    // Every row present, each value either whole or an oversized cell that
    // names its stored size; at least `minimumWhole` whole; the answer within
    // one frame.
    const assertPage = (reply, label, { rows, column, value, minimumWhole }) => {
        const data = reply.content?.data;
        const frameBytes = reply.content?.success === true ? encodeFrame(reply).length - 4 : 0;
        let whole = 0;
        let wrong = null;
        (data?.rows ?? []).forEach((row, rowIndex) => {
            const cell = row[column];
            const clipped = data.oversizedCells?.[rowIndex]?.[column];
            if (clipped === undefined) {
                if (cell === value) whole++;
                else wrong ??= { rowIndex, length: cell?.length, reason: 'short value with no oversized entry' };
            } else if (clipped.storageClass !== 'text' || clipped.byteLength !== Buffer.byteLength(value, 'utf8')
                || typeof cell !== 'string' || !value.startsWith(cell) || cell.length >= value.length) {
                wrong ??= { rowIndex, clipped, length: cell?.length };
            }
        });
        check(reply.content?.success === true && data.rows.length === rows && wrong === null
            && whole >= minimumWhole && frameBytes <= MAX_FRAME_BYTES,
            label, show({ success: reply.content?.success, error: reply.content?.errorMessage, rows: data?.rows?.length, whole, wrong, frameBytes }));
        return whole;
    };
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 60000 }]);
        const first = await session.invoke('fetchTableData', ['ctrl', gridPage(['rowid', 'v'], 5000)]);
        assertPage(first, 'sidecar/frame-page/first-page-previews', { rows: 20, column: 1, value: ctrlValue, minimumWhole: 0 });
        const counted = await session.invoke('fetchTableData', ['ctrl', gridPage(['rowid', 'v'], 20)]);
        const whole = assertPage(counted, 'sidecar/frame-page/counted-page-fits-the-frame', { rows: 20, column: 1, value: ctrlValue, minimumWhole: 1 });
        check(counted.content?.success === true && whole < 20,
            'sidecar/frame-page/counted-page-cuts-what-the-frame-cannot-carry', `${whole} whole`);
        const sorted = await session.invoke('fetchTableData', ['ctrl', gridPage(['rowid', 'v'], 20, 'v', null)]);
        assertPage(sorted, 'sidecar/frame-page/sorted-page-fits-the-frame', { rows: 20, column: 1, value: ctrlValue, minimumWhole: 1 });
        // Control: the same shape in plain ASCII is a quarter of the frame and
        // arrives whole, so the cut above is the escaping and not the size.
        const plain = await session.invoke('fetchTableData', ['plain', gridPage(['rowid', 'v'], 20)]);
        const plainWhole = assertPage(plain, 'sidecar/frame-page/plain-page-arrives-whole', { rows: 20, column: 1, value: 'a'.repeat(200000), minimumWhole: 20 });
        check(plainWhole === 20 && plain.content?.data?.oversizedCells === undefined,
            'sidecar/frame-page/plain-page-has-no-oversized-cells', show(plain.content?.data?.oversizedCells));
        const keyed = await session.invoke('fetchTableData', ['keyed', gridPage(['rowid', 'k', 'v'], 1000, null, null)]);
        assertPage(keyed, 'sidecar/frame-page/without-rowid-page-fits-the-frame', { rows: 1000, column: 2, value: keyedValue, minimumWhole: 1 });
        const view = await session.invoke('fetchTableData', ['ctrl_view', gridPage(['v'], 1000, null, null)]);
        assertPage(view, 'sidecar/frame-page/view-page-fits-the-frame', { rows: 1000, column: 0, value: keyedValue, minimumWhole: 1 });
        const read = await session.invoke('executeReadQuery', ['SELECT v FROM keyed', '[]']);
        assertPage(read, 'sidecar/frame-page/read-workspace-fits-the-frame', { rows: 1000, column: 0, value: keyedValue, minimumWhole: 1 });
        // Values that fill the frame to the byte, with the identity column the
        // page gains after them: rowids, the read-only tokens of a shadowed
        // rowid, and the record ids of a control-character TEXT key.
        const tight = await session.invoke('fetchTableData', ['tight', gridPage(['rowid', 'v'], 5000)]);
        assertPage(tight, 'sidecar/frame-page/full-rowid-page-fits-the-frame', { rows: 5000, column: 1, value: '\u0001'.repeat(700), minimumWhole: 1 });
        const shadowed = await session.invoke('fetchTableData', ['shadowed', gridPage(['rowid', 'rowid', 'v'], 1000, null, null)]);
        assertPage(shadowed, 'sidecar/frame-page/shadowed-rowid-page-fits-the-frame', { rows: 1000, column: 2, value: keyedValue, minimumWhole: 1 });
        check(Object.keys(shadowed.content?.data?.readOnlyRowReasons ?? {}).length === 1000,
            'sidecar/frame-page/shadowed-rowid-rows-stay-read-only', show(Object.keys(shadowed.content?.data?.readOnlyRowReasons ?? {}).length));
        const textKey = await session.invoke('fetchTableData', ['text_key', gridPage(['rowid', 'k', 'v'], 1000, null, null)]);
        const keyData = textKey.content?.data;
        const reasons = keyData?.readOnlyRowReasons ?? {};
        const identitiesAccounted = (keyData?.rows ?? []).every((row, rowIndex) => (
            typeof row[0] === 'string' && (reasons[rowIndex] === undefined) === row[0].startsWith('pk:')
        ));
        check(textKey.content?.success === true && keyData.rows.length === 1000 && identitiesAccounted
            && encodeFrame(textKey).length - 4 <= MAX_FRAME_BYTES,
            'sidecar/frame-page/text-key-page-fits-with-every-identity-or-its-reason',
            show({ success: textKey.content?.success, error: textKey.content?.errorMessage, rows: keyData?.rows?.length,
                readOnly: Object.keys(reasons).length, sampleReason: reasons[Object.keys(reasons)[0]], identitiesAccounted }));
        // A page that fits the frame as the WebAssembly worker contains it is
        // that page: 16.4 MB of ASCII arrives whole, no cell cut for headroom.
        const wide = await session.invoke('fetchTableData', ['wide', gridPage(['rowid', ...wideColumns], 1000)]);
        const wideValue = 'ab'.repeat(135);
        check(wide.content?.success === true && wide.content.data.rows.length === 1000
            && wide.content.data.oversizedCells === undefined
            && wide.content.data.rows.every((row) => row.slice(1).every((cell) => cell === wideValue)),
            'sidecar/frame-page/page-within-the-frame-arrives-whole',
            show({ success: wide.content?.success, error: wide.content?.errorMessage, rows: wide.content?.data?.rows?.length,
                clippedRows: Object.keys(wide.content?.data?.oversizedCells ?? {}).length }));
        // The column names share the frame: 600 KB of them here.
        const huge = await session.invoke('fetchTableData', ['huge_name', gridPage(['rowid', hugeName], 1000)]);
        assertPage(huge, 'sidecar/frame-page/page-under-a-huge-column-name-fits-the-frame', { rows: 1000, column: 1, value: '\u0001'.repeat(4000), minimumWhole: 1 });
        // Keys of 3,005 bytes, within the inline limit, that the frame has no
        // room for: each read-only row says that, not that its key is too large.
        const longKey = await session.invoke('fetchTableData', ['long_key', { ...gridPage(['rowid', 'k', 'v'], 1000, null, null), pageSize: 1000 }]);
        const longKeyData = longKey.content?.data;
        const longKeyReasons = Object.values(longKeyData?.readOnlyRowReasons ?? {});
        const longKeyAccounted = (longKeyData?.rows ?? []).every((row, rowIndex) => (
            typeof row[0] === 'string' && (longKeyData.readOnlyRowReasons?.[rowIndex] === undefined) === row[0].startsWith('pk:')
        ));
        check(longKey.content?.success === true && longKeyData.rows.length === 1000 && longKeyAccounted && longKeyReasons.length > 0
            && longKeyReasons.every((reason) => /exceeds the page transport budget/.test(reason) && !/inline limit/.test(reason))
            && encodeFrame(longKey).length - 4 <= MAX_FRAME_BYTES,
            'sidecar/frame-page/long-key-rows-say-the-frame-had-no-room',
            show({ success: longKey.content?.success, error: longKey.content?.errorMessage, rows: longKeyData?.rows?.length,
                readOnly: longKeyReasons.length, inlineLimitReasons: longKeyReasons.filter((reason) => /inline limit/.test(reason)).length }));
        // 26 MB of REALs: nothing a preview can shorten. The refusal names the
        // frame's limit, not a budget the containment shrank to, and says no
        // cut can make the page fit rather than that its values were cut.
        const wideReal = await session.invoke('fetchTableData', ['wide_real', gridPage(['rowid', ...realColumns], 5000)]);
        check(wideReal.content?.success === false
            && /16777216-byte reply frame, and cutting its values to previews cannot make it fit/.test(wideReal.content.errorMessage ?? ''),
            'sidecar/frame-page/page-past-the-frame-names-the-frame-limit',
            show({ success: wideReal.content?.success, error: wideReal.content?.errorMessage }));
        // The neighbours that never were page containment: the export route
        // writes the rows to the shell's file and frames none of them, and the
        // console cuts whole rows to fit its answer and marks the set truncated.
        const csvPath = path.join(scratch, 'frame-page-export.csv');
        fs.rmSync(csvPath, { force: true });
        const exported = await session.shellExport('exportTable', csvPath,
            // The host's own export bound (desktop-host.js DESKTOP_EXPORT_MAX_BYTES).
            [{ table: 'ctrl' }, ['v'], null, null, { format: 'csv', header: false, maxExportBytes: 512 * 1024 * 1024 }], 60000);
        const controlBytes = fs.existsSync(csvPath) ? fs.readFileSync(csvPath).filter((byte) => byte === 1).length : 0;
        check(exported.content?.success === true && controlBytes === 20 * 200000,
            'sidecar/frame-page/export-writes-every-value-whole', show({ exported: exported.content, controlBytes }));
        const consoleRun = await session.invoke('runConsole', ['SELECT v FROM ctrl', {}]);
        const consoleSet = consoleRun.content?.data?.results?.[0];
        check(consoleRun.content?.success === true && consoleSet?.truncated === true && consoleSet.rows.length > 0
            && consoleSet.rows.every((row) => row[0] === ctrlValue),
            'sidecar/frame-page/console-keeps-whole-rows-and-marks-the-cut', show({ error: consoleRun.content?.errorMessage, rows: consoleSet?.rows?.length, truncated: consoleSet?.truncated }));
        // Characters the codec spells otherwise: two-byte escapes, multi-byte
        // UTF-8, an astral pair and U+2028 (which JSON leaves unescaped),
        // about 1.3 times the frame in all, so the model must match what the
        // runtime's own JSON.stringify writes.
        const mixedValue = '"\\\n\té中😀\u2028'.repeat(52000);
        const mixed = await session.invoke('fetchTableData', ['mixed_view', gridPage(['v'], 20, null, null)]);
        assertPage(mixed, 'sidecar/frame-page/escaped-and-multibyte-page-fits-the-frame', { rows: 20, column: 0, value: mixedValue, minimumWhole: 1 });
        // The budget half of the mismatch, with nothing to escape: BLOBs the
        // page budget admits whole are a third larger as base64, more than the
        // frame.
        const blobView = await session.invoke('fetchTableData', ['blob_view', gridPage(['v'], 20, null, null)]);
        const blobData = blobView.content?.data;
        let wholeBlobs = 0;
        const blobsAccounted = (blobData?.rows ?? []).every((row, rowIndex) => {
            const clipped = blobData.oversizedCells?.[rowIndex]?.[0];
            if (clipped === undefined) return row[0] instanceof Uint8Array && row[0].length === 838860 && ++wholeBlobs > 0;
            return clipped.storageClass === 'blob' && clipped.byteLength === 838860
                && row[0] instanceof Uint8Array && row[0].length < 838860;
        });
        check(blobView.content?.success === true && blobData.rows.length === 20 && blobsAccounted && wholeBlobs >= 1
            && encodeFrame(blobView).length - 4 <= MAX_FRAME_BYTES,
            'sidecar/frame-page/blob-view-page-fits-the-frame',
            show({ success: blobView.content?.success, error: blobView.content?.errorMessage, rows: blobData?.rows?.length, wholeBlobs, blobsAccounted }));
        // NUL-bearing TEXT arrives as its stored bytes (the grid shows it as
        // bytes): every cell is an oversized TEXT cell naming its size, with
        // a byte prefix where the frame has room for one. A page the frame
        // cannot carry whole keeps the tail cells without a prefix.
        const nulPage = (reply, label, column, stored, minimumPrefixes = 1) => {
            const data = reply.content?.data;
            let prefixes = 0;
            const accounted = (data?.rows ?? []).every((row, rowIndex) => {
                const cell = row[column];
                const clipped = data.oversizedCells?.[rowIndex]?.[column];
                if (clipped?.storageClass !== 'text' || clipped.byteLength !== stored.length) return false;
                if (cell instanceof Uint8Array && cell.length > 0) {
                    prefixes++;
                    return cell.length <= stored.length && Buffer.from(cell).equals(stored.subarray(0, cell.length));
                }
                return cell === '' || (cell instanceof Uint8Array && cell.length === 0);
            });
            check(reply.content?.success === true && data.rows.length === 1000 && accounted && prefixes >= minimumPrefixes
                && encodeFrame(reply).length - 4 <= MAX_FRAME_BYTES,
                label, show({ success: reply.content?.success, error: reply.content?.errorMessage, rows: data?.rows?.length, accounted, prefixes }));
            return data;
        };
        // These fit the frame as the WebAssembly worker contains them, so every
        // cell keeps a prefix, as before the frame was counted.
        nulPage(await session.invoke('fetchTableData', ['nul', gridPage(['rowid', 'v'], 1000)]),
            'sidecar/frame-page/nul-text-page-fits-the-frame', 1, Buffer.alloc(4000), 1000);
        nulPage(await session.invoke('fetchTableData', ['nul_keyed', gridPage(['rowid', 'k', 'v'], 1000, null, null)]),
            'sidecar/frame-page/nul-text-without-rowid-page-fits-the-frame', 2, Buffer.alloc(4000), 1000);
        // A neighbour that fills the frame to within half a megabyte: the
        // NUL-bearing cells still keep their bytes (a frame budget that kept
        // the webview's headroom left them no room and refused the page).
        nulPage(await session.invoke('fetchTableData', ['raw_mix', gridPage(['rowid', 'a', 'b'], 1000)]),
            'sidecar/frame-page/raw-text-beside-a-full-frame-keeps-its-bytes', 2, Buffer.from('x\u0000'), 1000);
        // Every value unrepresentable (Latin-1 bytes), each an oversized entry:
        // the tail's prefixes give way to empty previews so that every row fits.
        const latin = await session.invoke('fetchTableData', ['latin1', gridPage(['rowid', ...latinColumns], 5000)]);
        const latinData = latin.content?.data;
        const latinAccounted = (latinData?.rows ?? []).every((row, rowIndex) => latinColumns.every((_column, index) => {
            const clipped = latinData.oversizedCells?.[rowIndex]?.[index + 1];
            const cell = row[index + 1];
            return clipped?.storageClass === 'text' && clipped.byteLength === 4
                && (cell === '' || (cell instanceof Uint8Array && Buffer.from(cell).equals(Buffer.from([0x63, 0x61, 0x66, 0xe9]))));
        }));
        check(latin.content?.success === true && latinData.rows.length === 5000 && latinAccounted
            && encodeFrame(latin).length - 4 <= MAX_FRAME_BYTES,
            'sidecar/frame-page/unrepresentable-text-page-keeps-every-row',
            show({ success: latin.content?.success, error: latin.content?.errorMessage, rows: latinData?.rows?.length, latinAccounted }));
        // A NUL-bearing key cannot mint an editable identity: every row is
        // read-only and says why, and the page still fits.
        const nulKey = await session.invoke('fetchTableData', ['nul_key', gridPage(['rowid', 'k', 'v'], 1000, null, null)]);
        const nulKeyReasons = nulKey.content?.data?.readOnlyRowReasons ?? {};
        check(nulKey.content?.success === true && nulKey.content.data.rows.length === 1000
            && Object.keys(nulKeyReasons).length === 1000 && encodeFrame(nulKey).length - 4 <= MAX_FRAME_BYTES,
            'sidecar/frame-page/nul-key-rows-read-only-with-their-reason',
            show({ success: nulKey.content?.success, error: nulKey.content?.errorMessage, rows: nulKey.content?.data?.rows?.length,
                readOnly: Object.keys(nulKeyReasons).length, sample: nulKeyReasons[0] }));
        const count = await session.invoke('fetchTableCount', ['ctrl', {}]);
        check(count.content?.data?.count === 20, 'sidecar/frame-page/session-stays-usable', show(count.content));
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/frame-page/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A page the frame has to contain again, with NUL-bearing or invalid UTF-8
 * TEXT beside values that fill it: the grid's page bounded by its count
 * (limit 1000, so each 2,795-character control value arrives whole within
 * the inline limit and the frame overflows). The raw-TEXT pass needs an
 * oversized entry for each such cell, and it was held to the values' budget
 * the decode had just filled: every attempt refused the page. Each case is
 * a rowid table, a WITHOUT ROWID table (whose identities are checked after
 * the pass), one whose key holds a NUL, and a view; and a page whose values
 * fit the first budgets whole, beside more entries than they leave room for.
 */
export async function runFrameRawTextRoomCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'frame-raw-text-room.sqlite');
    fs.rmSync(dbPath, { force: true });
    const series = (count, expression) =>
        `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ${count}) SELECT ${expression} FROM n`;
    const control = (bytes) => `replace(hex(zeroblob(${bytes})), '00', char(1))`;
    const latin = Array.from({ length: 12 }, (_, index) => `e${index}`);
    const seed = new DatabaseSync(dbPath);
    let storedCutInvalid;
    seed.exec(`
        CREATE TABLE nul_text(a TEXT, b TEXT);
        INSERT INTO nul_text ${series(1000, `${control(2795)}, 'x' || char(0)`)};
        CREATE TABLE bad_utf8(a TEXT, b TEXT);
        INSERT INTO bad_utf8 ${series(1000, `${control(3000)}, CAST(X'78FF' AS TEXT)`)};
        CREATE TABLE keyed(k TEXT PRIMARY KEY, a TEXT, b TEXT) WITHOUT ROWID;
        INSERT INTO keyed ${series(1000, `printf('k%06d', i), ${control(2795)}, 'x' || char(0)`)};
        CREATE TABLE nul_key(k TEXT PRIMARY KEY, a TEXT) WITHOUT ROWID;
        INSERT INTO nul_key ${series(1000, `printf('k%06d', i) || char(0), ${control(2795)}`)};
        CREATE VIEW nul_view AS SELECT a, b FROM nul_text;
        CREATE TABLE cut_invalid(s TEXT, t TEXT);
        INSERT INTO cut_invalid ${series(1000, `CASE WHEN i = 1000 THEN CAST(CAST('s' || printf('%06d', i) AS BLOB) || X'FF' || CAST(${control(1000)} AS BLOB) AS TEXT) ELSE 's' || printf('%06d', i) || ${control(1000)} END, ${control(1800)}`)};
        CREATE TABLE gap(c0 TEXT, c1 TEXT, c2 TEXT, ${latin.map((column) => `${column} TEXT`).join(', ')});
        INSERT INTO gap ${series(5000, [control(150), control(150), control(150), ...latin.map(() => "CAST(X'E9' AS TEXT)")].join(', '))};
    `);
    storedCutInvalid = seed.prepare('SELECT length(CAST(s AS BLOB)) AS s, length(CAST(t AS BLOB)) AS t FROM cut_invalid ORDER BY s, rowid').all();
    seed.close();
    const show = (value) => String(JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? `${item}n` : item))).slice(0, 400);
    const gridPage = (columns, keyset) => ({
        columns, globalFilterColumns: columns.filter((column) => column !== 'rowid'),
        orderBy: null, orderDir: 'ASC', limit: 1000, offset: 0, pageSize: 5000, filters: [], globalFilter: '',
        ...(keyset ? { keyset } : {}), maxInlineCellBytes: 1048576
    });
    // Every row; each control value whole or a prefix naming its size; each
    // stored-bytes cell (column `raw`, `stored` its bytes, or a row's) an
    // oversized TEXT cell naming its size, empty or a prefix of its bytes;
    // one frame.
    const assertPage = (reply, label, { controlColumn, controlBytes, raw, stored }) => {
        const data = reply.content?.data;
        let wrong = null;
        (data?.rows ?? []).forEach((row, rowIndex) => {
            const value = row[controlColumn];
            const clipped = data.oversizedCells?.[rowIndex]?.[controlColumn];
            if (clipped === undefined ? value !== '\u0001'.repeat(controlBytes)
                : clipped.byteLength !== controlBytes || typeof value !== 'string' || !'\u0001'.repeat(controlBytes).startsWith(value)) {
                wrong ??= { rowIndex, column: controlColumn, clipped, length: value?.length };
            }
            if (raw === undefined) return;
            const cell = row[raw];
            const bytes = typeof stored === 'function' ? stored(rowIndex) : stored;
            const rawClipped = data.oversizedCells?.[rowIndex]?.[raw];
            const prefixOk = cell === '' || (cell instanceof Uint8Array && cell.length <= bytes.length
                && Buffer.from(cell).equals(bytes.subarray(0, cell.length)));
            if (rawClipped?.storageClass !== 'text' || rawClipped.byteLength !== bytes.length || !prefixOk) {
                wrong ??= { rowIndex, column: raw, rawClipped, cell: show(cell) };
            }
        });
        check(reply.content?.success === true && data.rows.length === 1000 && wrong === null
            && encodeFrame(reply).length - 4 <= MAX_FRAME_BYTES,
            label, show({ success: reply.content?.success, error: reply.content?.errorMessage, rows: data?.rows?.length, wrong }));
        return data;
    };
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 60000 }]);
        const nulStored = Buffer.from('x\u0000');
        assertPage(await session.invoke('fetchTableData', ['nul_text', gridPage(['rowid', 'a', 'b'], { mode: 'first' })]),
            'sidecar/frame-raw-text-room/nul-text-page-fits', { controlColumn: 1, controlBytes: 2795, raw: 2, stored: nulStored });
        assertPage(await session.invoke('fetchTableData', ['bad_utf8', gridPage(['rowid', 'a', 'b'], { mode: 'first' })]),
            'sidecar/frame-raw-text-room/invalid-utf8-page-fits', { controlColumn: 1, controlBytes: 3000, raw: 2, stored: Buffer.from([0x78, 0xff]) });
        const keyed = assertPage(await session.invoke('fetchTableData', ['keyed', gridPage(['rowid', 'k', 'a', 'b'], { mode: 'first' })]),
            'sidecar/frame-raw-text-room/without-rowid-page-fits', { controlColumn: 2, controlBytes: 2795, raw: 3, stored: nulStored });
        const keyedReasons = keyed?.readOnlyRowReasons ?? {};
        check((keyed?.rows ?? []).length === 1000 && keyed.rows.every((row, rowIndex) => (
            typeof row[0] === 'string' && (keyedReasons[rowIndex] === undefined) === row[0].startsWith('pk:'))),
            'sidecar/frame-raw-text-room/without-rowid-rows-keep-an-identity-or-its-reason',
            show({ editable: (keyed?.rows ?? []).filter((row) => String(row[0]).startsWith('pk:')).length, readOnly: Object.keys(keyedReasons).length }));
        const nulKey = assertPage(await session.invoke('fetchTableData', ['nul_key', gridPage(['rowid', 'k', 'a'], { mode: 'first' })]),
            'sidecar/frame-raw-text-room/nul-key-page-fits', { controlColumn: 2, controlBytes: 2795, raw: 1, stored: (rowIndex) => Buffer.from(`k${String(rowIndex + 1).padStart(6, '0')}\u0000`) });
        check(Object.keys(nulKey?.readOnlyRowReasons ?? {}).length === 1000,
            'sidecar/frame-raw-text-room/nul-key-rows-read-only', show(Object.keys(nulKey?.readOnlyRowReasons ?? {}).length));
        assertPage(await session.invoke('fetchTableData', ['nul_view', gridPage(['a', 'b'], null)]),
            'sidecar/frame-raw-text-room/view-page-fits', { controlColumn: 0, controlBytes: 2795, raw: 1, stored: nulStored });
        // The frame cuts the last row's sort value for room, an invalid UTF-8
        // TEXT of 1,008 stored bytes that decodes to 1,010: its entry, like
        // every other on the page, names the stored length.
        const cutInvalid = await session.invoke('fetchTableData', ['cut_invalid', { ...gridPage(['rowid', 's', 't'], { mode: 'first' }), orderBy: 's', pageSize: 1000 }]);
        const cutData = cutInvalid.content?.data;
        let cutWrong = null;
        let lastCut = null;
        Object.entries(cutData?.oversizedCells ?? {}).forEach(([rowIndex, cells]) => {
            Object.entries(cells).forEach(([column, entry]) => {
                const stored = storedCutInvalid[Number(rowIndex)]?.[column === '1' ? 's' : 't'];
                if (entry.byteLength !== stored) cutWrong ??= { rowIndex, column, entry, stored };
                if (rowIndex === '999' && column === '1') lastCut = entry;
            });
        });
        check(cutInvalid.content?.success === true && cutData.rows.length === 1000 && cutWrong === null
            && lastCut?.byteLength === 1008,
            'sidecar/frame-raw-text-room/cut-invalid-text-names-its-stored-length',
            show({ success: cutInvalid.content?.success, error: cutInvalid.content?.errorMessage, rows: cutData?.rows?.length, lastCut, cutWrong }));
        // Values two to four MiB under the frame, and 60,000 entries for
        // invalid UTF-8 cells that take more than that gap: the first two
        // budgets leave the values whole (the decode cuts nothing) and the
        // entries do not fit, the third cuts values and they do.
        const gap = await session.invoke('fetchTableData', ['gap', { ...gridPage(['rowid', 'c0', 'c1', 'c2', ...latin], { mode: 'first' }), limit: 5000 }]);
        const gapData = gap.content?.data;
        let gapWrong = null;
        (gapData?.rows ?? []).forEach((row, rowIndex) => {
            for (let column = 1; column <= 3; column++) {
                const clipped = gapData.oversizedCells?.[rowIndex]?.[column];
                if (clipped === undefined ? row[column] !== '\u0001'.repeat(150)
                    : clipped.byteLength !== 150 || !'\u0001'.repeat(150).startsWith(row[column])) gapWrong ??= { rowIndex, column };
            }
            for (let column = 4; column < 16; column++) {
                const clipped = gapData.oversizedCells?.[rowIndex]?.[column];
                const cell = row[column];
                if (clipped?.storageClass !== 'text' || clipped.byteLength !== 1
                    || !(cell === '' || (cell instanceof Uint8Array && cell.length === 1 && cell[0] === 0xe9))) gapWrong ??= { rowIndex, column, clipped };
            }
        });
        check(gap.content?.success === true && gapData.rows.length === 5000 && gapWrong === null
            && encodeFrame(gap).length - 4 <= MAX_FRAME_BYTES,
            'sidecar/frame-raw-text-room/entries-past-the-values-gap-fit',
            show({ success: gap.content?.success, error: gap.content?.errorMessage, rows: gapData?.rows?.length, gapWrong }));
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/frame-raw-text-room/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A page the frame has to contain again keeps both keyset anchors when the
 * cells it cuts for the reply's room include a boundary row's key: a sort
 * column or a WITHOUT ROWID key of 1,006 control characters, each within the
 * inline limit and whole in its source row, but cut from the reply's tail
 * first. Without its `last` anchor the grid's next page fell back to
 * OFFSET. The next page, sought from that anchor, starts at the row after
 * the page's last one.
 */
export async function runFrameAnchorCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'frame-anchor.sqlite');
    fs.rmSync(dbPath, { force: true });
    const series = (count, expression) =>
        `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ${count}) SELECT ${expression} FROM n`;
    const control = (bytes) => `replace(hex(zeroblob(${bytes})), '00', char(1))`;
    const seed = new DatabaseSync(dbPath);
    seed.exec(`
        CREATE TABLE sorted(a TEXT, k TEXT);
        INSERT INTO sorted ${series(2000, `${control(1800)}, ${control(1000)} || printf('%06d', 2001 - i)`)};
        CREATE TABLE keyed(k TEXT PRIMARY KEY, a TEXT) WITHOUT ROWID;
        INSERT INTO keyed ${series(2000, `printf('%06d', i) || ${control(1000)}, ${control(1800)}`)};
    `);
    const keysInOrder = {
        sorted: seed.prepare('SELECT k FROM sorted ORDER BY k, rowid').all().map((row) => row.k),
        keyed: seed.prepare('SELECT k FROM keyed ORDER BY k').all().map((row) => row.k)
    };
    seed.close();
    const show = (value) => String(JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? `${item}n` : item))).slice(0, 400);
    const gridPage = (columns, orderBy, keyset, offset = 0) => ({
        columns, globalFilterColumns: columns.filter((column) => column !== 'rowid'),
        orderBy, orderDir: 'ASC', limit: 1000, offset, pageSize: 1000, filters: [], globalFilter: '',
        keyset, maxInlineCellBytes: 1048576
    });
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 60000 }]);
        for (const [table, columns, orderBy, keyColumn] of [
            ['sorted', ['rowid', 'a', 'k'], 'k', 2],
            ['keyed', ['rowid', 'k', 'a'], null, 1]
        ]) {
            const first = await session.invoke('fetchTableData', [table, gridPage(columns, orderBy, { mode: 'first' })]);
            const data = first.content?.data;
            const keyCut = Object.keys(data?.oversizedCells?.[999] ?? {}).includes(String(keyColumn));
            check(first.content?.success === true && data.rows.length === 1000 && keyCut
                && typeof data.keysetAnchors?.first === 'string' && typeof data.keysetAnchors?.last === 'string'
                && encodeFrame(first).length - 4 <= MAX_FRAME_BYTES,
                `sidecar/frame-anchor/${table}-page-keeps-both-anchors`,
                show({ success: first.content?.success, error: first.content?.errorMessage, rows: data?.rows?.length, keyCut, anchors: Object.keys(data?.keysetAnchors ?? {}) }));
            if (typeof data?.keysetAnchors?.last !== 'string') continue;
            const next = await session.invoke('fetchTableData', [table, gridPage(columns, orderBy, { mode: 'after', anchor: data.keysetAnchors.last }, 1000)]);
            const nextRows = next.content?.data?.rows ?? [];
            const nextKey = (rowIndex) => {
                const cell = nextRows[rowIndex]?.[keyColumn];
                return next.content.data.oversizedCells?.[rowIndex]?.[keyColumn] ? null : cell;
            };
            check(next.content?.success === true && nextRows.length === 1000
                && nextKey(0) === keysInOrder[table][1000] && (nextKey(999) === null || nextKey(999) === keysInOrder[table][1999]),
                `sidecar/frame-anchor/${table}-next-page-starts-after-the-last-row`,
                show({ success: next.content?.success, error: next.content?.errorMessage, rows: nextRows.length,
                    firstKeyMatches: nextKey(0) === keysInOrder[table][1000] }));
        }
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/frame-anchor/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A WITHOUT ROWID page whose keys are long control-character TEXT keeps as
 * many rows editable as the frame has room for. Each key (3,006 bytes,
 * within the inline limit) costs 18 KB in the frame and its editable
 * identity, which repeats it, 24 KB more: 1,000 of them cannot all be
 * editable. The rows that are not keep their reason, and from the tail they
 * give up their key cells (cut for the reply's room) so the rows before them
 * keep both; 75 of 1,000 stayed editable before, where the frame holds
 * about 390. Every editable identity names its own row's key.
 */
export async function runFrameKeyRoomCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'frame-key-room.sqlite');
    fs.rmSync(dbPath, { force: true });
    const series = (count, expression) =>
        `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ${count}) SELECT ${expression} FROM n`;
    const seed = new DatabaseSync(dbPath);
    seed.exec(`
        CREATE TABLE long_key(k TEXT PRIMARY KEY, v INTEGER) WITHOUT ROWID;
        INSERT INTO long_key ${series(1000, "printf('%06d', i) || replace(hex(zeroblob(3000)), '00', char(1)), i")};
    `);
    const keys = seed.prepare('SELECT k FROM long_key ORDER BY k').all().map((row) => row.k);
    seed.close();
    const show = (value) => String(JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? `${item}n` : item))).slice(0, 400);
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 60000 }]);
        const reply = await session.invoke('fetchTableData', ['long_key', {
            columns: ['rowid', 'k', 'v'], globalFilterColumns: ['k', 'v'], orderBy: null, orderDir: 'ASC',
            limit: 1000, offset: 0, pageSize: 5000, filters: [], globalFilter: '', keyset: { mode: 'first' }, maxInlineCellBytes: 1048576
        }]);
        const data = reply.content?.data;
        const reasons = data?.readOnlyRowReasons ?? {};
        let editable = 0;
        let wrong = null;
        (data?.rows ?? []).forEach((row, rowIndex) => {
            const clipped = data.oversizedCells?.[rowIndex]?.[1];
            const keyShown = clipped === undefined ? row[1] === keys[rowIndex]
                : clipped.storageClass === 'text' && clipped.byteLength === 3006 && row[1] === '';
            if (String(row[0]).startsWith('pk:')) {
                editable++;
                const named = JSON.parse(decodeURIComponent(String(row[0]).slice(3))).c?.[0]?.[1]?.[1];
                if (reasons[rowIndex] !== undefined || clipped !== undefined || named !== keys[rowIndex] || row[2] !== rowIndex + 1) {
                    wrong ??= { rowIndex, editable: true, reason: reasons[rowIndex], clipped, namesItsKey: named === keys[rowIndex] };
                }
            } else if (!/exceeds the page transport budget/.test(reasons[rowIndex] ?? '') || !keyShown || row[2] !== rowIndex + 1) {
                wrong ??= { rowIndex, editable: false, reason: reasons[rowIndex], clipped, keyShown };
            }
        });
        check(reply.content?.success === true && data.rows.length === 1000 && wrong === null && editable >= 350
            && encodeFrame(reply).length - 4 <= MAX_FRAME_BYTES,
            'sidecar/frame-key-room/long-key-page-keeps-the-rows-it-has-room-for-editable',
            show({ success: reply.content?.success, error: reply.content?.errorMessage, rows: data?.rows?.length, editable,
                readOnly: Object.keys(reasons).length, wrong }));
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/frame-key-room/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A view preview (the Edit View modal: up to 100 rows, values of any size)
 * fits the reply frame. 50 values of 200,000 control characters came to 60 MB
 * and the frame refused the preview. Now each long value arrives as a prefix
 * with an oversized entry (views.js marks it), the rows contained as a page
 * is when the prefixes alone still do not fit; a preview that fits is
 * unchanged.
 */
export async function runViewPreviewFrameCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'view-preview-frame.sqlite');
    fs.rmSync(dbPath, { force: true });
    const series = (count, expression) =>
        `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ${count}) SELECT ${expression} FROM n`;
    const control = (bytes) => `replace(hex(zeroblob(${bytes})), '00', char(1))`;
    const wideColumns = Array.from({ length: 300 }, (_, index) => `w${index}`);
    const seed = new DatabaseSync(dbPath);
    seed.exec(`
        CREATE TABLE big(v TEXT, b BLOB);
        INSERT INTO big ${series(100, `${control(200000)}, randomblob(300000)`)};
        CREATE VIEW big_view AS SELECT v FROM big;
        CREATE TABLE wide(${wideColumns.map((column) => `${column} TEXT`).join(', ')});
        INSERT INTO wide ${series(100, wideColumns.map(() => control(600)).join(', '))};
        CREATE TABLE small(v TEXT, n INTEGER);
        INSERT INTO small ${series(100, "'v' || i, 9007199254740993 + i")};
    `);
    const blobs = seed.prepare('SELECT b FROM big ORDER BY rowid LIMIT 50').all().map((row) => Buffer.from(row.b));
    seed.close();
    const show = (value) => String(JSON.stringify(value, (_key, item) => (typeof item === 'bigint' ? `${item}n` : item))).slice(0, 400);
    // Each cell whole, or a prefix of its value with an oversized entry naming its size.
    const accounted = (data, expected) => {
        let wrong = null;
        let prefixes = 0;
        (data?.rows ?? []).forEach((row, rowIndex) => row.forEach((cell, columnIndex) => {
            const want = expected(rowIndex, columnIndex);
            const clipped = data.oversizedCells?.[rowIndex]?.[columnIndex];
            if (clipped === undefined) {
                if (!(typeof want === 'string' ? cell === want : Buffer.isBuffer(want) && cell instanceof Uint8Array && Buffer.from(cell).equals(want))) {
                    wrong ??= { rowIndex, columnIndex, reason: 'short value with no oversized entry' };
                }
                return;
            }
            const prefix = typeof want === 'string'
                ? clipped.storageClass === 'text' && clipped.byteLength === Buffer.byteLength(want) && typeof cell === 'string' && want.startsWith(cell)
                : clipped.storageClass === 'blob' && clipped.byteLength === want.length && cell instanceof Uint8Array && want.subarray(0, cell.length).equals(Buffer.from(cell));
            if (!prefix) wrong ??= { rowIndex, columnIndex, clipped };
            else if (cell.length > 0) prefixes++;
        }));
        return { wrong, prefixes };
    };
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 60000 }]);
        const longValue = '\u0001'.repeat(200000);
        for (const [label, payload] of [
            ['new-view', ['preview_big', 'SELECT v, b FROM big', 50, 'create']],
            ['edited-view', ['big_view', 'SELECT v, b FROM big', 50, 'edit']]
        ]) {
            const reply = await session.invoke('previewViewDefinition', payload);
            const data = reply.content?.data;
            const { wrong, prefixes } = accounted(data, (rowIndex, columnIndex) => (columnIndex === 0 ? longValue : blobs[rowIndex]));
            check(reply.content?.success === true && data.rows.length === 50 && wrong === null && prefixes === 100
                && encodeFrame(reply).length - 4 <= MAX_FRAME_BYTES,
                `sidecar/view-preview-frame/${label}-preview-of-long-values-fits`,
                show({ success: reply.content?.success, error: reply.content?.errorMessage, rows: data?.rows?.length, wrong, prefixes }));
        }
        const wide = await session.invoke('previewViewDefinition', ['preview_wide', 'SELECT * FROM wide', 100, 'create']);
        const wideData = wide.content?.data;
        const wideCheck = accounted(wideData, () => '\u0001'.repeat(600));
        check(wide.content?.success === true && wideData.rows.length === 100 && wideCheck.wrong === null && wideCheck.prefixes > 0
            && encodeFrame(wide).length - 4 <= MAX_FRAME_BYTES,
            'sidecar/view-preview-frame/wide-preview-fits', show({ success: wide.content?.success, error: wide.content?.errorMessage, rows: wideData?.rows?.length, ...wideCheck }));
        // Control: a preview within the frame is the rows as they are.
        const small = await session.invoke('previewViewDefinition', ['preview_small', 'SELECT v, n FROM small', 50, 'create']);
        const smallData = small.content?.data;
        check(small.content?.success === true && smallData.rows.length === 50 && smallData.oversizedCells === undefined
            && smallData.rows.every((row, rowIndex) => row[0] === `v${rowIndex + 1}`)
            && smallData.exactIntegerTexts?.[0]?.[1] === '9007199254740994',
            'sidecar/view-preview-frame/small-preview-is-unchanged', show({ success: small.content?.success, error: small.content?.errorMessage, data: smallData }));
        // The preview's savepoint was rolled back: no view was created.
        const schema = await session.invoke('fetchSchema', []);
        check(!JSON.stringify(schema.content?.data ?? '').includes('preview_big'),
            'sidecar/view-preview-frame/preview-leaves-no-view', show(schema.content?.success));
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/view-preview-frame/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A parameterised console statement whose result names collide keeps every
 * column and its bound values on the native engine (before, the runtime's
 * object rows collapsed the duplicates: a self-join showed only its second
 * table's values).
 */
export async function runConsoleDuplicateNamesCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'console-duplicates.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO t VALUES (1, 'a'), (2, 'b');");
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    const plain = (value) => JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? Number(v) : v));
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 30000 }]);
        for (const [label, sql, params, expected] of [
            ['self-join', 'SELECT a.*, c.* FROM t a JOIN t c ON c.id = a.id + ?', [1n], [[1, 'a', 2, 'b']]],
            ['repeated-name', 'SELECT ?, 7 AS "0", ?', [8n, 9n], [[8, 7, 9]]]
        ]) {
            const reply = await session.invoke('runConsole', [sql, { params }]);
            const result = reply.content?.data?.results?.[0];
            check(plain(result?.rows) === plain(expected) && result?.headers?.length === expected[0].length,
                `sidecar/console-duplicates/${label}`, plain(reply.content?.data));
        }
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/console-duplicates/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A parameterised console statement heads its columns with the names it was
 * written with, before its first step and so with no rows too: `?`, `:x`,
 * `? + 1`, never the NULL of its expansion. A repeated name carries the
 * view's `:1` suffix, as `SELECT 1 AS x, 2 AS x` does, so there is one header
 * per value.
 */
export async function runConsoleParameterHeadersCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'console-parameter-headers.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO t VALUES (1, 'alpha');");
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    const plain = (value) => JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? Number(v) : v));
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 30000 }]);
        for (const [label, sql, params, headers, rows] of [
            ['aliased-and-named', 'SELECT ? AS a, :x', [1n, 2n], ['a', ':x'], [[1, 2]]],
            ['typed-parameters', 'SELECT ? AS a, :x', [1, 2], ['a', ':x'], [[1, 2]]],
            ['zero-rows', 'SELECT id AS alpha, ? FROM t WHERE name = ?', [5n, 'none'], ['alpha', '?'], []],
            ['with-rows', 'SELECT id AS alpha, ? FROM t WHERE name = ?', [5n, 'alpha'], ['alpha', '?'], [[1, 5]]],
            ['expressions-zero-rows', 'SELECT :x, :x + 1, $y FROM t WHERE id = ?3', [1n, 2n, 9n], [':x', ':x + 1', '$y'], []],
            ['repeated-zero-rows', 'SELECT ?, ? FROM t WHERE 0', [8n, 9n], ['?', '?:1'], []],
            ['repeated-with-rows', 'SELECT ?, ? FROM t', [8n, 9n], ['?', '?:1'], [[8, 9]]]
        ]) {
            const reply = await session.invoke('runConsole', [sql, { params }]);
            const result = reply.content?.data?.results?.[0];
            check(plain(result?.headers) === plain(headers) && plain(result?.rows) === plain(rows),
                `sidecar/console-parameter-headers/${label}`, plain(reply.content?.data));
        }
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/console-parameter-headers/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * The column probe's parameter literals carry a marker nobody can predict:
 * a schema name that looks like one keeps its own name, and a statement
 * that holds the marker's prefix followed by a long name is probed in
 * linear time (choosing the marker grew it one character per match, and
 * the query deadline cannot interrupt JavaScript).
 */
export async function runParameterMarkerCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const plain = (value) => JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? Number(v) : v));
    const dbPath = path.join(scratch, 'parameter-marker.sqlite');
    fs.rmSync(dbPath, { force: true });
    const long = `sqlite_explorer_parameter_${'x'.repeat(160000)}`;
    const seed = new DatabaseSync(dbPath);
    seed.exec(`CREATE TABLE h (id INTEGER PRIMARY KEY, "'sqlite_explorer_parameter_0'" TEXT, "x'sqlite_explorer_parameter_1'y" TEXT);
        INSERT INTO h VALUES (1, 'p', 'q');
        CREATE TABLE k (id INTEGER PRIMARY KEY, "${long}" TEXT); INSERT INTO k VALUES (1, 'p');`);
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 30000 }], 120000);
        const names = ['id', "'sqlite_explorer_parameter_0'", "x'sqlite_explorer_parameter_1'y"];
        for (const [label, params, rows] of [['zero-rows', [5n, 6n], []], ['with-rows', [1n, 6n], [[1, 'p', 'q']]]]) {
            const reply = await session.invoke('runConsole', ['SELECT * FROM h WHERE id = ?1 OR id = ?2', { params }]);
            const result = reply.content?.data?.results?.[0];
            check(plain(result?.headers) === plain(names) && plain(result?.rows) === plain(rows),
                `sidecar/parameter-marker/schema-names-kept-${label}`, plain(reply.content?.data ?? reply.content));
        }
        const timed = async (label, method, payload) => {
            const started = Date.now();
            const reply = await session.invoke(method, payload, 600000);
            const elapsed = Date.now() - started;
            check(reply.content?.success === true && elapsed < 3000, `sidecar/parameter-marker/${label}-in-linear-time`,
                `${elapsed} ms: ${String(reply.content?.errorMessage ?? '').slice(0, 200)}`);
        };
        await timed('grid-filter', 'fetchTableData', ['k', { limit: 100, offset: 0, columns: ['rowid', 'id', long], globalFilter: 'p' }]);
        await timed('console', 'runConsole', [`SELECT id, "${long}" FROM k WHERE id = ?`, { params: [1n] }]);
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/parameter-marker/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A console run whose answer cannot cross one frame -- a header over the
 * frame, which fitConsoleAnswer cannot cut -- is answered by the sidecar's
 * in-band frame refusal (code ERR_NATIVE_FRAME_TOO_LARGE) AFTER its
 * statements ran: the write before it is in the session transaction, which
 * the probe the host sends next still finds open. This is the shape
 * desktop-host.js runOutcomeUnknown reads as "may have written".
 */
export async function runConsoleUnknownOutcomeCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const show = (reply) => JSON.stringify(reply?.content, (_key, v) => (typeof v === 'bigint' ? Number(v) : v)).slice(0, 600);
    const dbPath = path.join(scratch, 'console-unknown-outcome.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    // One column name over the 16 MiB frame, from the schema rather than the
    // request, so the request itself still fits.
    seed.exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, x);
        CREATE TABLE wide ("${'h'.repeat(MAX_FRAME_BYTES + 1024)}" INTEGER);`);
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    const count = async () => Number((await session.invoke('runQuery', ['SELECT count(*) FROM notes'])).content?.data?.[0]?.rows?.[0]?.[0]);
    try {
        await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 30000 }]);
        const begin = await session.invoke('runQuery', ['BEGIN']);
        check(begin.content?.success === true, 'sidecar/console-unknown-outcome/session-begins', show(begin));
        const run = await session.invoke('runConsole', ["INSERT INTO notes (x) VALUES ('kept'); SELECT * FROM wide", {}], 120000);
        check(run.content?.success === false && run.content?.error?.code === 'ERR_NATIVE_FRAME_TOO_LARGE'
            && /^Native frame rejected: outgoing payload is \d+ bytes/.test(run.content?.errorMessage ?? ''),
            'sidecar/console-unknown-outcome/answered-by-an-in-band-frame-refusal', show(run));
        const probe = await session.invoke('runQuery', ['BEGIN']);
        check(probe.content?.success === false && /within a transaction|SQL logic error/.test(probe.content?.errorMessage ?? ''),
            'sidecar/console-unknown-outcome/the-probe-finds-the-session-open', show(probe));
        check(await count() === 1, 'sidecar/console-unknown-outcome/the-write-ran');
        await session.invoke('runQuery', ['ROLLBACK']);
        check(await count() === 0, 'sidecar/console-unknown-outcome/nothing-was-committed');
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/console-unknown-outcome/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * The room a write keeps for its undo request is what the host really adds:
 * nothing per row for an import (refusing a 100,000-row import that undoes
 * fine was the earlier, per-row reserve), and a second copy of the key for an
 * insert (an insert whose answer fit could not be undone). A console run whose
 * answer is over the frame answers with fewer rows, and says it wrote.
 */
export async function runReplyReserveCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const short = (reply) => JSON.stringify(reply?.content, (_key, v) => (typeof v === 'bigint' ? `${v}n`
        : typeof v === 'string' && v.length > 120 ? `${v.slice(0, 120)}…` : v)).slice(0, 500);
    const dbPath = path.join(scratch, 'reply-reserve.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec(`CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT, email TEXT, joined TEXT);
        CREATE TABLE keyed (k TEXT PRIMARY KEY, v BLOB) WITHOUT ROWID;
        CREATE TABLE r (b); INSERT INTO r VALUES (1);`);
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    const scalar = async (sql) => (await session.invoke('runQuery', [sql])).content?.data?.[0]?.rows?.[0]?.[0];
    try {
        const init = await session.invoke('initializeDatabase', [path.basename(dbPath), {
            path: dbPath, readOnlyMode: false, queryTimeout: 60000
        }]);
        check(init.content?.success === true, 'sidecar/reply-reserve/opens', short(init));
        await session.invoke('runQuery', ['BEGIN']);

        const rows = Array.from({ length: 100000 }, (_, i) => ({
            name: `Person ${i}`, email: `person${i}@example.com`, joined: '2024-01-15'
        }));
        const imported = await session.invoke('importRows', ['people', rows, {
            maxEditValueBytes: 16 * 1024 * 1024, maxUndoSnapshotBytes: 512 * 1024 * 1024,
            maxSnapshotTransportBytes: 14 * 1024 * 1024
        }], 120000);
        check(imported.content?.success === true && Number(await scalar('SELECT count(*) FROM people')) === 100000,
            'sidecar/reply-reserve/import-whose-undo-fits-is-accepted', short(imported));
        if (imported.content?.success === true) {
            const entry = {
                label: 'Import 100000 rows', description: 'Import 100000 rows into people',
                modificationType: 'row_insert', targetTable: 'people', importedRows: imported.content.data.snapshots
            };
            const undone = await session.invoke('undoModification', [entry], 120000);
            const afterUndo = Number(await scalar('SELECT count(*) FROM people'));
            const redone = await session.invoke('redoModification', [entry], 120000);
            check(undone.content?.success === true && afterUndo === 0 && redone.content?.success === true
                && Number(await scalar('SELECT count(*) FROM people')) === 100000,
                'sidecar/reply-reserve/import-entry-undoes-and-redoes', JSON.stringify([short(undone), afterUndo, short(redone)]));
        }

        // An insert whose answer fits one frame but leaves less than the room
        // the host's undo request adds (its copy of the 1 MB key): refused
        // before transfers, because that request then could not cross. It now
        // can, in pieces (native-large-value-lane drives one end to end), so
        // the insert is accepted and answered in one frame.
        const key = 'k'.repeat(1000000);
        const inserted = await session.invoke('insertRowWithHistory', ['keyed',
            { k: key, v: new Uint8Array(11078301) }, 16 * 1024 * 1024, 512 * 1024 * 1024], 120000);
        check(inserted.content?.kind === 'response' && inserted.content?.success === true
            && Number(await scalar('SELECT count(*) FROM keyed')) === 1,
            'sidecar/reply-reserve/insert-whose-undo-request-passes-the-frame-is-accepted', short(inserted));

        const consoleRun = await session.invoke('runConsole', ['UPDATE r SET b = 2 RETURNING randomblob(17 * 1024 * 1024)'], 120000);
        const result = consoleRun.content?.data?.results?.[0];
        check(consoleRun.content?.success === true && consoleRun.content?.data?.mutated === true
            && result?.truncated === true && result?.rows?.length === 0
            && Number(await scalar('SELECT b FROM r')) === 2,
            'sidecar/reply-reserve/console-answer-over-the-frame-is-cut-and-reports-the-write', short(consoleRun));
        await session.invoke('runQuery', ['ROLLBACK']);
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/reply-reserve/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * Requests that reach the sidecar in one pipe read run in arrival order, each
 * to completion, as they do on the WebAssembly worker. Before, every frame of
 * a chunk started at once and the handlers interleaved at their awaits: a
 * grid read sent after an edit ran first and showed the old rows.
 */
export async function runSameChunkOrderCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'same-chunk.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO t VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma');");
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    const page = ['fetchTableData', ['t', { columns: ['rowid', 'id', 'name'], limit: 50, offset: 0 }]];
    const names = (reply) => (reply.content?.data?.rows ?? []).map(row => row[2]);
    try {
        const init = await session.invoke('initializeDatabase', [path.basename(dbPath), {
            path: dbPath, readOnlyMode: false, queryTimeout: 30000
        }]);
        check(init.content?.success === true, 'sidecar/same-chunk/opens', JSON.stringify(init.content));
        await session.invoke('runQuery', ['BEGIN']);

        const edit = await session.invokeTogether([
            ['updateCellBatch', ['t', [{ rowId: 1, column: 'name', value: 'CHANGED', originalValue: 'alpha' }], null, 16 * 1024 * 1024]],
            page
        ]);
        check(edit.messages[0].content?.success === true && names(edit.messages[1]).join() === 'CHANGED,beta,gamma'
            && edit.order.join() === '0,1',
            'sidecar/same-chunk/read-after-edit-sees-the-edit', JSON.stringify({ saw: names(edit.messages[1]), order: edit.order }));

        const removed = await session.invokeTogether([['deleteRows', ['t', [2]]], page]);
        check(removed.messages[0].content?.success === true && names(removed.messages[1]).join() === 'CHANGED,gamma',
            'sidecar/same-chunk/read-after-delete-sees-the-delete', JSON.stringify({ saw: names(removed.messages[1]), order: removed.order }));

        // Two writes in one chunk: each runs inside its own savepoint, whole.
        const both = await session.invokeTogether([
            ['updateCellBatch', ['t', [{ rowId: 1, column: 'name', value: 'one', originalValue: 'CHANGED' }], null, 16 * 1024 * 1024]],
            ['updateCellBatch', ['t', [{ rowId: 3, column: 'name', value: 'three', originalValue: 'gamma' }], null, 16 * 1024 * 1024]],
            page
        ]);
        check(both.messages.every(reply => reply.content?.success === true) && names(both.messages[2]).join() === 'one,three'
            && both.order.join() === '0,1,2',
            'sidecar/same-chunk/two-writes-then-a-read-in-order', JSON.stringify({ saw: names(both.messages[2]), order: both.order }));

        // A shell export behind a write in the same pipe read: it used to start
        // at once and export the table as it was before the write.
        const csvTemp = path.join(scratch, 'same-chunk-export.csv');
        fs.rmSync(csvTemp, { force: true });
        const [inserted, exported] = await session.sendTogether([
            { channel: 'rpc', content: { kind: 'invoke', messageId: 'lane_mixed_insert', targetMethod: 'runQuery', payload: ["INSERT INTO t VALUES (4, 'four')"] } },
            { channel: 'shell', content: { kind: 'export', messageId: 'shell_mixed_export', method: 'exportTable', tempPath: csvTemp,
                args: [{ table: 't' }, [], null, null, { format: 'csv', header: false, maxExportBytes: 1024 * 1024 }] } }
        ]);
        const csv = fs.existsSync(csvTemp) ? fs.readFileSync(csvTemp, 'utf8') : '';
        check(inserted.content?.success === true && exported.content?.success === true && csv.includes('4,four'),
            'sidecar/same-chunk/shell-export-after-a-write-sees-the-write', JSON.stringify({ csv, exported: exported.content }));
        await session.invoke('runQuery', ['ROLLBACK']);
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/same-chunk/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A write whose answer cannot cross one native frame never stays in the
 * session without that answer. Before 0.3.2 the write landed and the
 * transport then replaced its answer with a frame error: the change stayed
 * with no history entry, and a Save committed it. Such an answer is now
 * parked with its write held in a savepoint and announced as a transfer
 * (core/native/native-transfer.js); a caller that takes no piece of it and
 * sends anything else instead finds the write rolled back. (The page's pull,
 * commit and abandonment are driven end to end in native-large-value-lane.)
 * An edit that fits, with the room the guard keeps, is undone and redone by
 * its own entry.
 */
export async function runReplyFrameCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const show = (reply) => JSON.stringify(reply?.content, (_key, v) => (typeof v === 'bigint' ? `${v}n`
        : typeof v === 'string' && v.length > 200 ? `${v.slice(0, 200)}…` : v)).slice(0, 600);
    const dbPath = path.join(scratch, 'reply-frame.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec(`CREATE TABLE cells (id INTEGER PRIMARY KEY, v TEXT);
        WITH RECURSIVE k(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM k WHERE i < 10)
        INSERT INTO cells SELECT i, printf('%.*c', 1000000, 'x') FROM k;
        CREATE TABLE blobs (id INTEGER PRIMARY KEY, v BLOB);
        INSERT INTO blobs VALUES (1, randomblob(7000000)), (2, randomblob(7000000)), (3, x'00');
        CREATE TABLE defaults (id INTEGER PRIMARY KEY, v BLOB DEFAULT (zeroblob(13000000)));
        CREATE VIEW big_view AS SELECT '${'a'.repeat(9 * 1024 * 1024)}' AS c;`);
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    const scalar = async (sql) => (await session.invoke('runQuery', [sql])).content?.data?.[0]?.rows?.[0]?.[0];
    const refusedByName = (reply) => reply.content?.success === false
        && /bytes to return the values undo restores, over the \d+-byte limit of one native engine reply\. Nothing was changed/
            .test(reply.content?.errorMessage ?? '');
    const parked = (reply) => reply.content?.kind === 'transfer'
        && Number.isSafeInteger(reply.content?.transfer?.parts) && reply.content.transfer.parts > 1;
    try {
        const init = await session.invoke('initializeDatabase', [path.basename(dbPath), {
            path: dbPath, readOnlyMode: false, queryTimeout: 30000
        }]);
        check(init.content?.success === true, 'sidecar/reply-frame/opens', show(init));
        await session.invoke('runQuery', ['BEGIN']);
        const edits = (n) => Array.from({ length: n }, (_, i) => ({ rowId: i + 1, column: 'v', value: 'z' }));

        const tooMany = await session.invoke('updateCellBatch', ['cells', edits(10), null, 16 * 1024 * 1024]);
        check(parked(tooMany) && await scalar("SELECT count(*) FROM cells WHERE v = 'z'") === 0,
            'sidecar/reply-frame/cell-batch-answer-not-taken-is-rolled-back', show(tooMany));

        const blobs = await session.invoke('deleteRows', ['blobs', [1, 2]]);
        check(parked(blobs) && await scalar('SELECT count(*) FROM blobs') === 3,
            'sidecar/reply-frame/blob-delete-answer-not-taken-is-rolled-back', show(blobs));

        const inserted = await session.invoke('insertRowWithHistory', ['defaults', {}, 16 * 1024 * 1024, 64 * 1024 * 1024]);
        check(parked(inserted) && await scalar('SELECT count(*) FROM defaults') === 0,
            'sidecar/reply-frame/insert-answer-not-taken-is-rolled-back', show(inserted));

        // A writer whose answer is not a history entry the host replays in
        // pieces keeps the one-frame limit, refused by name inside its own
        // savepoint: a view edit answering two 9 MiB definitions.
        const viewSql = await scalar("SELECT length(sql) FROM sqlite_schema WHERE name = 'big_view'");
        const viewEdit = await session.invoke('editView', ['big_view', `SELECT '${'b'.repeat(9 * 1024 * 1024)}' AS c`], 120000);
        check(refusedByName(viewEdit)
            && await scalar("SELECT length(sql) FROM sqlite_schema WHERE name = 'big_view'") === viewSql
            && await scalar("SELECT count(*) FROM sqlite_schema WHERE name = 'big_view' AND sql LIKE '%aaaa%'") === 1,
            'sidecar/reply-frame/view-edit-keeps-the-one-frame-refusal', show(viewEdit));

        // A pull for a transfer that was rolled back is refused, not served.
        const stale = await session.invoke('nativeTransfer', ['pull', inserted.content?.transfer?.id ?? 'none', 0]);
        check(stale.content?.success === false && /is not open; the write it carried was rolled back/.test(stale.content?.errorMessage ?? ''),
            'sidecar/reply-frame/pull-after-rollback-is-refused', show(stale));

        // Control: an edit under the limit is written, and the entry the host
        // builds from its answer undoes and redoes it.
        const fits = await session.invoke('updateCellBatch', ['cells', edits(7), null, 16 * 1024 * 1024]);
        check(fits.content?.success === true && await scalar("SELECT count(*) FROM cells WHERE v = 'z'") === 7,
            'sidecar/reply-frame/cell-batch-under-the-limit-is-written', show(fits));
        if (fits.content?.success === true) {
            const label = 'Edit 7 cells';
            const entry = {
                label, description: label, modificationType: 'cell_update', targetTable: 'cells',
                affectedCells: fits.content.data.map(cell => ({
                    rowId: cell.rowId, newRowId: cell.newRowId ?? cell.rowId, columnName: cell.columnName,
                    priorValue: cell.priorValue, newValue: cell.newValue, priorState: cell.priorState,
                    postState: cell.postState, operation: cell.operation
                }))
            };
            const undone = await session.invoke('undoModification', [entry]);
            check(undone.content?.success === true && await scalar("SELECT count(*) FROM cells WHERE v = 'z'") === 0,
                'sidecar/reply-frame/entry-undoes', show(undone));
            const redone = await session.invoke('redoModification', [entry]);
            check(redone.content?.success === true && await scalar("SELECT count(*) FROM cells WHERE v = 'z'") === 7,
                'sidecar/reply-frame/entry-redoes', show(redone));
        }
        check(await scalar('SELECT count(*) FROM cells') === 10, 'sidecar/reply-frame/session-still-usable');
        await session.invoke('runQuery', ['ROLLBACK']);
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/reply-frame/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * What a sidecar says about a transfer's commit is what it knows. A commit
 * retried after other frames (its first answer lost) is told it committed; a
 * transfer it rolled back is reported rolled back; one it no longer knows is
 * reported unknown, never rolled back (the page then closes the connection
 * rather than keep an edit it cannot account for).
 */
export async function runTransferCommitCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const show = (reply) => JSON.stringify(reply?.content, (_key, v) => (typeof v === 'string' && v.length > 200 ? `${v.slice(0, 200)}…` : v)).slice(0, 500);
    const dbPath = path.join(scratch, 'transfer-commit.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec(`CREATE TABLE cells (id INTEGER PRIMARY KEY, v TEXT);
        WITH RECURSIVE k(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM k WHERE i < 10)
        INSERT INTO cells SELECT i, printf('%.*c', 1000000, 'x') FROM k;`);
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    const scalar = async (sql) => (await session.invoke('runQuery', [sql])).content?.data?.[0]?.rows?.[0]?.[0];
    // Every edit writes 1 MB values over 1 MB values: each answer is a transfer.
    const edit = (letter) => session.invoke('updateCellBatch', ['cells',
        Array.from({ length: 10 }, (_, i) => ({ rowId: i + 1, column: 'v', value: letter.repeat(1000000) })), null, 16 * 1024 * 1024]);
    const holding = (letter) => scalar(`SELECT count(*) FROM cells WHERE v = printf('%.*c', 1000000, '${letter}')`);
    const takeAll = async (reply) => {
        for (let index = 0; index < reply.content.transfer.parts; index++) {
            const piece = await session.invoke('nativeTransfer', ['pull', reply.content.transfer.id, index]);
            if (piece.content?.success !== true) return false;
        }
        return true;
    };
    const commit = (reply) => session.invoke('nativeTransfer', ['commit', reply.content.transfer.id]);
    const committed = (reply) => reply.content?.success === true && reply.content?.data?.committed === true;
    const refusedAs = (reply, code) => reply.content?.success === false && reply.content?.error?.code === code;
    try {
        const init = await session.invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false, queryTimeout: 30000 }]);
        check(init.content?.success === true, 'sidecar/transfer-commit/opens', show(init));
        await session.invoke('runQuery', ['BEGIN']);

        const first = await edit('a');
        check(first.content?.kind === 'transfer' && await takeAll(first) && committed(await commit(first)),
            'sidecar/transfer-commit/first-transfer-commits', show(first));
        await scalar('SELECT 1');   // a frame between the commit and its retry
        const retried = await commit(first);
        check(committed(retried) && await holding('a') === 10,
            'sidecar/transfer-commit/retry-after-other-frames-is-told-it-committed', show(retried));

        const second = await edit('b');
        check(second.content?.kind === 'transfer' && await takeAll(second) && committed(await commit(second)),
            'sidecar/transfer-commit/second-transfer-commits', show(second));
        const stale = await commit(first);
        check(refusedAs(stale, 'ERR_NATIVE_TRANSFER_UNKNOWN') && !/was rolled back/.test(stale.content?.errorMessage ?? ''),
            'sidecar/transfer-commit/a-transfer-it-no-longer-knows-is-unknown-not-rolled-back', show(stale));

        const third = await edit('c');
        const untouched = await holding('c');   // ends the transfer: rolls back
        const late = await commit(third);
        check(third.content?.kind === 'transfer' && untouched === 0 && refusedAs(late, 'ERR_NATIVE_TRANSFER_ROLLED_BACK')
            && await holding('b') === 10,
            'sidecar/transfer-commit/a-transfer-it-rolled-back-is-reported-rolled-back', show(late));
        await session.invoke('runQuery', ['ROLLBACK']);
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/transfer-commit/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * The SQL console on the native engine: parameters keep their SQLite type
 * across the 64-bit range, a read runs with writes refused, and a grid page or
 * count past the query deadline fails as a timeout while the session stays
 * usable.
 */
export async function runConsoleAndDeadlineCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const show = (reply) => JSON.stringify(reply?.content, (_key, v) => (typeof v === 'bigint' ? `${v}n` : v)).slice(0, 600);
    const lastRow = (reply) => reply.content?.data?.results?.at(-1)?.rows?.[0];
    const dbPath = path.join(scratch, 'console-deadline.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, x);
        CREATE VIEW guard_probe AS SELECT 1 AS writable FROM pragma_query_only WHERE query_only = 0;
        CREATE VIEW slow_view AS WITH RECURSIVE n(x) AS
            (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 1000000000) SELECT sum(x) AS total FROM n;`);
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        const init = await session.invoke('initializeDatabase', [path.basename(dbPath), {
            path: dbPath, readOnlyMode: false, queryTimeout: 200
        }]);
        check(init.content?.success === true, 'sidecar/console/opens', show(init));

        const typed = await session.invoke('runConsole', [
            'SELECT typeof(?1), typeof(?2), typeof(?3), ?4 = 9223372036854775807, ?2 / 2, ?3 / 2',
            { params: [3000000000n, 1, 5n, 9223372036854775807n] }
        ]);
        const row = lastRow(typed);
        check(Array.isArray(row) && row[0] === 'integer' && row[1] === 'real' && row[2] === 'integer'
            && Number(row[3]) === 1 && row[4] === 0.5 && Number(row[5]) === 2,
            'sidecar/console/parameters-keep-their-type', show(typed));

        const script = await session.invoke('runConsole', [
            'INSERT INTO notes (x) VALUES (?); SELECT typeof(x), x = ? FROM notes', { params: [4000000000n] }
        ]);
        const scriptRow = lastRow(script);
        check(script.content?.data?.mutated === true && scriptRow?.[0] === 'integer' && Number(scriptRow?.[1]) === 1,
            'sidecar/console/every-statement-of-a-script-is-typed', show(script));

        const control = await session.invoke('runConsole', ['PRAGMA query_only']);
        const read = await session.invoke('runConsole', ['SELECT count(*) FROM guard_probe']);
        check(Number(lastRow(control)?.[0]) === 0 && Number(lastRow(read)?.[0]) === 0,
            'sidecar/console/read-runs-with-writes-refused', JSON.stringify([show(control), show(read)]));

        const page = await session.invoke('fetchTableData', ['slow_view', { limit: 10, offset: 0 }]);
        check(page.content?.success === false && /timed out after 200ms/.test(page.content?.errorMessage ?? ''),
            'sidecar/deadline/grid-page-times-out', show(page));
        const count = await session.invoke('fetchTableCount', ['slow_view', {}]);
        check(count.content?.success === false && /timed out after 200ms/.test(count.content?.errorMessage ?? ''),
            'sidecar/deadline/row-count-times-out', show(count));
        const after = await session.invoke('fetchTableCount', ['notes', {}]);
        check(after.content?.success === true && after.content?.data?.count === 1,
            'sidecar/deadline/session-usable-afterwards', show(after));
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/console/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * The desktop import writes with OR ABORT on the native engine too: a row that
 * collides with another row's unique key under a schema ON CONFLICT REPLACE
 * fails the import and leaves the table as it was.
 */
export async function runImportConflictCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const show = (reply) => JSON.stringify(reply?.content, (_key, v) => (typeof v === 'bigint' ? `${v}n` : v));
    const dbPath = path.join(scratch, 'import-conflict.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, k TEXT UNIQUE ON CONFLICT REPLACE, v TEXT);
        INSERT INTO t VALUES (1, 'x', 'keep');`);
    seed.close();
    const session = startSidecar(binary, dbPath, 'rw');
    try {
        const init = await session.invoke('initializeDatabase', [path.basename(dbPath), {
            path: dbPath, readOnlyMode: false, queryTimeout: 30000
        }]);
        check(init.content?.success === true, 'sidecar/import-conflict/opens', show(init));
        const preview = await session.invoke('getImportTarget', ['t']);
        const imported = await session.invoke('importRows', ['t', [
            { id: 2, k: 'new', v: 'a' }, { id: 3, k: 'x', v: 'collides' }
        ], { expectedSchemaVersion: preview.content?.data?.schemaVersion }]);
        const rows = await session.invoke('runQuery', ['SELECT id, k, v FROM t ORDER BY id']);
        check(imported.content?.success === false
            && /UNIQUE constraint failed/.test(imported.content?.errorMessage ?? '')
            && JSON.stringify(rows.content?.data?.[0]?.rows) === JSON.stringify([[1, 'x', 'keep']]),
            'sidecar/import-conflict/refused-and-table-unchanged', JSON.stringify([show(imported), show(rows)]));
        session.endStdin();
        check(await session.untilExit() === 0, 'sidecar/import-conflict/clean-shutdown');
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
    }
    return checks;
}

/** UTF-16 grid reads must work in txiki, whose TextDecoder only supports UTF-8. */
export async function runUtf16ReadCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    for (const encoding of ['UTF-16le', 'UTF-16be']) {
        const dbPath = path.join(scratch, `${encoding}.sqlite`);
        const reference = new DatabaseSync(dbPath);
        reference.exec(`PRAGMA encoding='${encoding}';
            CREATE TABLE ordinary(id INTEGER PRIMARY KEY, value TEXT);
            CREATE TABLE keyed(value TEXT PRIMARY KEY) WITHOUT ROWID;`);
        const value = '東京😀\uFEFF';
        reference.prepare('INSERT INTO ordinary VALUES(1,?)').run(value);
        reference.prepare('INSERT INTO keyed VALUES(?)').run(value);
        reference.close();
        const before = createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex');
        const session = startSidecar(binary, dbPath, 'ro');
        try {
            const init = await session.invoke('initializeDatabase', [path.basename(dbPath), {
                path: dbPath, readOnlyMode: true
            }]);
            check(init.content?.success === true, `sidecar/${encoding}/opens`, JSON.stringify(init.content));
            for (const table of ['ordinary', 'keyed']) {
                const page = await session.invoke('fetchTableData', [table, { limit: 10 }]);
                check(page.content?.success === true
                    && page.content?.data?.rows?.length === 1
                    && page.content.data.rows[0].includes(value),
                    `sidecar/${encoding}/${table}-grid-preserves-text`, JSON.stringify(page.content));
            }
            session.endStdin();
            check(await session.untilExit() === 0, `sidecar/${encoding}/clean-shutdown`);
        } finally {
            if (session.exitCode === null) session.child.kill('SIGKILL');
        }
        check(createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex') === before,
            `sidecar/${encoding}/inspection-keeps-file-byte-identical`);
    }
    return checks;
}

/** Read FTS5's WITHOUT ROWID shadow tables through the shipping desktop worker. */
export async function runFtsShadowReadCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks++; };
    const dbPath = path.join(scratch, 'fts-shadow-read.sqlite');
    const seed = new DatabaseSync(dbPath);
    seed.close();
    const writer = startSidecar(binary, dbPath, 'rw');
    try {
        const init = await writer.invoke('initializeDatabase', ['fts-shadow-read.sqlite', {
            path: dbPath, readOnlyMode: false
        }]);
        if (init.content?.success !== true) throw new Error(init.content?.errorMessage ?? 'FTS fixture open failed');
        const created = await writer.invoke('runQuery', ['CREATE VIRTUAL TABLE desktop_fts USING fts5(body)']);
        if (created.content?.success !== true) throw new Error(created.content?.errorMessage ?? 'FTS fixture create failed');
        // Separate autocommit inserts produce multiple index segments. Only
        // the virtual table is written; shadow tables are inspected read-only.
        for (const text of ['alpha', 'beta', 'gamma']) {
            const inserted = await writer.invoke('runQuery', ['INSERT INTO desktop_fts(body) VALUES (?)', [text]]);
            if (inserted.content?.success !== true) throw new Error(inserted.content?.errorMessage ?? 'FTS fixture insert failed');
        }
        writer.endStdin();
        check(await writer.untilExit() === 0, 'sidecar/fts-shadow/fixture-seeded-through-native-worker');
    } finally {
        if (writer.exitCode === null) writer.child.kill('SIGKILL');
    }

    const digest = () => createHash('sha256').update(fs.readFileSync(dbPath)).digest('hex');
    const before = digest();
    const reader = startSidecar(binary, dbPath, 'ro');
    const reference = new DatabaseSync(dbPath, { readOnly: true });
    const image = rows => JSON.stringify((rows ?? []).map(row => row.map(value =>
        value instanceof Uint8Array ? Array.from(value) : value
    )));
    try {
        const init = await reader.invoke('initializeDatabase', ['fts-shadow-read.sqlite', {
            path: dbPath, readOnlyMode: true
        }]);
        check(init.content?.success === true && init.content?.data?.isReadOnly === true,
            'sidecar/fts-shadow/inspection-opens-read-only', JSON.stringify(init.content));
        const schema = await reader.invoke('fetchSchema', []);
        for (const fixture of [
            { table: 'desktop_fts_idx', columns: ['segid', 'term', 'pgno'], keys: ['segid', 'term'] },
            { table: 'desktop_fts_config', columns: ['k', 'v'], keys: ['k'] }
        ]) {
            const label = `sidecar/fts-shadow/${fixture.table}`;
            const identity = schema.content?.data?.tables?.find(table => table.identifier === fixture.table)?.identity;
            check(schema.content?.success === true && identity?.kind === 'primaryKey'
                && JSON.stringify(identity.columns.map(column => column.identifier)) === JSON.stringify(fixture.keys),
                `${label}/schema-primary-key`, JSON.stringify(identity));
            const expected = reference.prepare(
                `SELECT ${fixture.columns.join(', ')} FROM ${fixture.table} ORDER BY ${fixture.keys.join(', ')}`
            ).all().map(row => fixture.columns.map(column => row[column]));
            check(expected.length >= (fixture.table.endsWith('_idx') ? 2 : 1),
                `${label}/fixture-has-rows-to-page`, `rows=${expected.length}`);
            const count = await reader.invoke('fetchTableCount', [fixture.table, {}]);
            check(count.content?.success === true && count.content?.data?.count === expected.length
                && count.content?.data?.isExact === true,
                `${label}/exact-count`, JSON.stringify(count.content));
            const options = {
                columns: ['rowid', ...fixture.columns], orderBy: 'rowid', orderDir: 'ASC', limit: 1, offset: 0
            };
            const first = await reader.invoke('fetchTableData', [fixture.table, {
                ...options, keyset: { mode: 'first' }
            }]);
            let page = first.content?.data;
            const firstId = page?.rows?.[0]?.[0];
            check(first.content?.success === true && typeof firstId === 'string' && firstId.startsWith('pk:')
                && image(page.rows.map(row => row.slice(1))) === image(expected.slice(0, 1)),
                `${label}/first-page-primary-key`, JSON.stringify(first.content));
            const recordIds = [firstId];
            if (first.content?.success === true) {
                for (let offset = 1; offset < expected.length; offset++) {
                    const next = await reader.invoke('fetchTableData', [fixture.table, {
                        ...options, offset, keyset: { mode: 'after', anchor: page?.keysetAnchors?.last }
                    }]);
                    const current = next.content?.data;
                    const rowId = current?.rows?.[0]?.[0];
                    check(Boolean(page?.keysetAnchors?.last) && next.content?.success === true
                        && typeof rowId === 'string' && rowId.startsWith('pk:')
                        && !recordIds.includes(rowId)
                        && image(current.rows.map(row => row.slice(1))) === image([expected[offset]]),
                        `${label}/keyset-page-${offset + 1}`, JSON.stringify(next.content));
                    recordIds.push(rowId);
                    page = current;
                }
            }
            const offsetPage = await reader.invoke('fetchTableData', [fixture.table, { ...options, limit: 10 }]);
            check(offsetPage.content?.success === true
                && image(offsetPage.content?.data?.rows?.map(row => row.slice(1))) === image(expected)
                && offsetPage.content?.data?.rows?.[0]?.[0] === firstId,
                `${label}/offset-page-matches-reference`, JSON.stringify(offsetPage.content));
        }
        reader.endStdin();
        check(await reader.untilExit() === 0, 'sidecar/fts-shadow/inspection-exits-clean');
    } finally {
        reference.close();
        if (reader.exitCode === null) reader.child.kill('SIGKILL');
    }
    check(digest() === before, 'sidecar/fts-shadow/inspection-keeps-file-byte-identical');
    return checks;
}

/**
 * journal_mode WAL and back through the shipped sidecar.
 *
 * The desktop's Configuration modal drives exactly these RPCs (setPragma,
 * getPragmas, and — for a checkpoint — runQuery), and this is what a WASM
 * image can never do: the mode change lands on the real file. Asserted: the
 * -wal/-shm sidecars appear on the first write and an external reader sees
 * the row through the log; a TRUNCATE checkpoint drains the log (SQLite
 * resets it before reading the counters, hence 0/0/0 and an empty -wal);
 * the switch is refused while a transaction is open — the host's session
 * transaction on a dirty database — and the mode stays put; leaving WAL
 * removes both sidecars; the mode a session leaves is the mode a FRESH
 * session finds, with the rows intact; and a read-only session cannot
 * change it at all.
 *
 * @returns {Promise<number>} checks run
 */
async function runJournalModeCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };

    const dbPath = path.join(scratch, 'journal-fixture.sqlite');
    createFixture(dbPath);
    const sidecarFiles = () => ['-wal', '-shm'].filter((suffix) => fs.existsSync(`${dbPath}${suffix}`));
    const walBytes = () => (fs.existsSync(`${dbPath}-wal`) ? fs.statSync(`${dbPath}-wal`).size : -1);
    const journalMode = async (session) => (await session.invoke('getPragmas', [])).content?.data?.journal_mode;

    let session = startSidecar(binary, dbPath, 'rw');
    try {
        await session.invoke('initializeDatabase', ['journal-fixture.sqlite', {
            path: dbPath, readOnlyMode: false
        }]);
        const before = await journalMode(session);
        const toWal = await session.invoke('setPragma', ['journal_mode', 'WAL']);
        const afterSwitch = await journalMode(session);
        check(before === 'delete' && toWal.content?.success === true && afterSwitch === 'wal',
            'sidecar/journal-mode-switches-to-wal',
            `before=${before}, answer=${JSON.stringify(toWal.content)}, after=${afterSwitch}`);

        const write = await session.invoke('runConsole', ["INSERT INTO t VALUES (4, 'delta', NULL, 4, 4.0)"]);
        const external = new DatabaseSync(dbPath, { readOnly: true });
        let externalMode;
        let externalCount;
        try {
            externalMode = external.prepare('PRAGMA journal_mode').get()?.journal_mode;
            externalCount = external.prepare('SELECT count(*) AS c FROM t').get()?.c;
        } finally {
            external.close();
        }
        check(write.content?.data?.mutated === true
            && JSON.stringify(sidecarFiles()) === JSON.stringify(['-wal', '-shm'])
            && walBytes() > 0
            && externalMode === 'wal' && externalCount === 4,
            'sidecar/wal-write-lands-in-the-log-and-an-external-reader-sees-it',
            `files=${JSON.stringify(sidecarFiles())}, walBytes=${walBytes()}, externalMode=${externalMode}, externalCount=${externalCount}`);

        const checkpoint = await session.invoke('runQuery', ['PRAGMA wal_checkpoint(TRUNCATE)']);
        const counters = checkpoint.content?.data?.[0]?.rows?.[0];
        check(checkpoint.content?.success === true
            && JSON.stringify(counters) === JSON.stringify([0, 0, 0])
            && walBytes() === 0,
            'sidecar/wal-checkpoint-drains-the-log',
            `counters=${JSON.stringify(counters)}, walBytes=${walBytes()}`);

        // The fork answers the in-transaction refusal with its generic
        // "SQL logic error" (message loss, not a different outcome): what
        // matters is that it IS refused and the mode did not move.
        await session.invoke('runQuery', ['BEGIN']);
        await session.invoke('runQuery', ['SELECT count(*) FROM t']);
        const inTransaction = await session.invoke('setPragma', ['journal_mode', 'DELETE']);
        const stillWal = await journalMode(session);
        await session.invoke('runQuery', ['ROLLBACK']);
        check(inTransaction.content?.success === false && stillWal === 'wal',
            'sidecar/journal-mode-change-inside-a-transaction-is-refused-and-keeps-wal',
            `answer=${JSON.stringify(inTransaction.content)}, mode=${stillWal}`);

        const toDelete = await session.invoke('setPragma', ['journal_mode', 'DELETE']);
        const afterDelete = await journalMode(session);
        check(toDelete.content?.success === true && afterDelete === 'delete' && sidecarFiles().length === 0,
            'sidecar/leaving-wal-removes-both-sidecar-files',
            `answer=${JSON.stringify(toDelete.content)}, mode=${afterDelete}, files=${JSON.stringify(sidecarFiles())}`);

        // Lower-case value (the settings modal's select) — left in place so
        // the fresh session below proves the mode outlives the process.
        const lower = await session.invoke('setPragma', ['journal_mode', 'wal']);
        check(lower.content?.success === true && await journalMode(session) === 'wal',
            'sidecar/journal-mode-accepts-a-lower-case-value', JSON.stringify(lower.content));

        session.endStdin();
        const code = await session.untilExit();
        check(code === 0, 'sidecar/journal-session-exits-clean', `exit ${code}`);
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
        const stderrText = session.stderr.trim();
        if (stderrText) console.log(`[sidecar journal stderr]\n${stderrText}\n`);
    }

    session = startSidecar(binary, dbPath, 'rw');
    try {
        await session.invoke('initializeDatabase', ['journal-fixture.sqlite', {
            path: dbPath, readOnlyMode: false
        }]);
        const reopenedMode = await journalMode(session);
        const rows = await session.invoke('runQuery', ['SELECT count(*) AS c FROM t']);
        const back = await session.invoke('setPragma', ['journal_mode', 'DELETE']);
        check(reopenedMode === 'wal'
            && rows.content?.data?.[0]?.rows?.[0]?.[0] === 4
            && back.content?.success === true,
            'sidecar/journal-mode-persists-into-a-fresh-session-with-its-rows',
            `mode=${reopenedMode}, rows=${JSON.stringify(rows.content?.data)}, back=${JSON.stringify(back.content)}`);
        session.endStdin();
        await session.untilExit();
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
        const stderrText = session.stderr.trim();
        if (stderrText) console.log(`[sidecar journal reopen stderr]\n${stderrText}\n`);
    }

    const independent = new DatabaseSync(dbPath, { readOnly: true });
    let finalMode;
    let quickCheck;
    try {
        finalMode = independent.prepare('PRAGMA journal_mode').get()?.journal_mode;
        quickCheck = independent.prepare('PRAGMA quick_check').get()?.quick_check;
    } finally {
        independent.close();
    }
    check(finalMode === 'delete' && quickCheck === 'ok' && sidecarFiles().length === 0,
        'sidecar/leaving-wal-is-durable-and-the-file-is-intact',
        `mode=${finalMode}, quick_check=${quickCheck}, files=${JSON.stringify(sidecarFiles())}`);

    const readOnly = startSidecar(binary, dbPath, 'ro');
    try {
        await readOnly.invoke('initializeDatabase', ['journal-fixture.sqlite', {
            path: dbPath, readOnlyMode: true
        }]);
        const refused = await readOnly.invoke('setPragma', ['journal_mode', 'WAL']);
        check(refused.content?.success === false && /read-only/i.test(refused.content?.errorMessage ?? ''),
            'sidecar/read-only-session-cannot-change-journal-mode', JSON.stringify(refused.content));
        readOnly.endStdin();
        await readOnly.untilExit();
    } finally {
        if (readOnly.exitCode === null) readOnly.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * The folder beside a database after the sidecar exits, for each way a
 * session can leave it. In WAL mode a read creates <db>-wal and <db>-shm, and
 * only the last connection's close deletes them, after copying the -wal into
 * the main file. The sidecar closes at exit only when the -wal is one its own
 * open created and is still empty; a -wal that was already there or that
 * holds committed edits must survive byte for byte, main file included.
 *
 * @returns {Promise<number>} checks run
 */
async function runWalExitCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };
    const directory = path.join(scratch, 'wal-exit');
    fs.mkdirSync(directory, { recursive: true });
    const digest = (file) => (fs.existsSync(file)
        ? createHash('sha256').update(fs.readFileSync(file)).digest('hex')
        : null);
    const listing = (dbPath) => fs.readdirSync(directory)
        .filter((name) => name.startsWith(path.basename(dbPath)))
        .sort()
        .map((name) => `${name}:${fs.statSync(path.join(directory, name)).size}`);
    const seedWal = (dbPath) => {
        const seed = new DatabaseSync(dbPath);
        seed.exec("PRAGMA journal_mode = WAL; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (v) VALUES ('one');");
        seed.close();
    };
    /** Open, run `work`, end stdin, and report what the folder holds afterwards. */
    const session = async (dbPath, mode, work, end = (s) => s.endStdin()) => {
        const s = startSidecar(binary, dbPath, mode);
        try {
            const init = await s.invoke('initializeDatabase', [path.basename(dbPath), {
                path: dbPath, readOnlyMode: mode === 'ro', queryTimeout: 30000
            }]);
            if (init.content?.success !== true) throw new Error(`open refused: ${JSON.stringify(init.content)}`);
            const page = await s.invoke('fetchTableData', ['t', { limit: 10, offset: 0 }]);
            if (page.content?.success !== true) throw new Error(`page refused: ${JSON.stringify(page.content)}`);
            await work?.(s);
            const during = listing(dbPath);
            const started = Date.now();
            end(s);
            const code = await s.untilExit();
            return { code, exitMs: Date.now() - started, during, after: listing(dbPath), stderr: s.stderr.trim() };
        } finally {
            if (s.exitCode === null) s.child.kill('SIGKILL');
        }
    };
    const name = (dbPath) => path.basename(dbPath);

    // Opened and read: the -wal and -shm appear during the session and are
    // gone after it, the exit is quick, and the main file is unchanged.
    {
        const dbPath = path.join(directory, 'read.sqlite');
        seedWal(dbPath);
        const before = digest(dbPath);
        const result = await session(dbPath, 'rw');
        check(result.code === 0 && result.during.includes(`${name(dbPath)}-wal:0`)
            && JSON.stringify(result.after) === JSON.stringify([`${name(dbPath)}:${fs.statSync(dbPath).size}`])
            && digest(dbPath) === before && result.exitMs < 1000,
            'sidecar/wal-exit/read-only-use-leaves-the-folder-as-found', JSON.stringify(result));
    }

    // Same outcome when the sidecar exits on a frame stream it cannot resynchronise.
    {
        const dbPath = path.join(directory, 'fatal.sqlite');
        seedWal(dbPath);
        const result = await session(dbPath, 'rw', undefined, (s) => {
            s.child.stdin.write(Buffer.from([0xff, 0xff, 0xff, 0xff]));
        });
        check(result.code === 1
            && JSON.stringify(result.after) === JSON.stringify([`${name(dbPath)}:${fs.statSync(dbPath).size}`]),
            'sidecar/wal-exit/transport-fatal-exit-cleans-up-too', JSON.stringify(result));
    }

    // A -wal present before the open (here copied in beside the file, with a
    // committed row in it) is kept byte for byte, and so is the main file:
    // closing would have copied the row into it.
    {
        const dbPath = path.join(directory, 'arrived.sqlite');
        seedWal(dbPath);
        const writer = new DatabaseSync(dbPath);
        writer.exec("PRAGMA wal_autocheckpoint = 0; INSERT INTO t (v) VALUES ('pending in the log');");
        fs.copyFileSync(dbPath, `${dbPath}.copy`);
        fs.copyFileSync(`${dbPath}-wal`, `${dbPath}.copy-wal`);
        writer.close();
        fs.renameSync(`${dbPath}.copy`, dbPath);
        fs.renameSync(`${dbPath}.copy-wal`, `${dbPath}-wal`);
        fs.rmSync(`${dbPath}-shm`, { force: true });
        const main = digest(dbPath);
        const log = digest(`${dbPath}-wal`);
        const result = await session(dbPath, 'rw');
        check(result.code === 0 && digest(dbPath) === main && digest(`${dbPath}-wal`) === log,
            'sidecar/wal-exit/pre-existing-wal-is-not-checkpointed', JSON.stringify(result));
    }

    // A committed edit lives in the -wal: the files stay, the main file is
    // unchanged, and a later reader still finds the row.
    {
        const dbPath = path.join(directory, 'edited.sqlite');
        seedWal(dbPath);
        const main = digest(dbPath);
        const result = await session(dbPath, 'rw', async (s) => {
            const write = await s.invoke('runQuery', ["INSERT INTO t (v) VALUES ('two')"]);
            if (write.content?.success !== true) throw new Error(JSON.stringify(write.content));
        });
        const walBytes = fs.existsSync(`${dbPath}-wal`) ? fs.statSync(`${dbPath}-wal`).size : -1;
        const reader = new DatabaseSync(dbPath, { readOnly: true });
        const rows = reader.prepare('SELECT count(*) AS c FROM t').get()?.c;
        reader.close();
        check(result.code === 0 && walBytes > 0 && digest(dbPath) === main && rows === 2,
            'sidecar/wal-exit/committed-edits-stay-in-the-wal', JSON.stringify({ ...result, walBytes, rows }));
    }

    // Rollback-journal mode: a read creates no file, so there is nothing to do.
    {
        const dbPath = path.join(directory, 'journal.sqlite');
        const seed = new DatabaseSync(dbPath);
        seed.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (v) VALUES ('one');");
        seed.close();
        const result = await session(dbPath, 'rw');
        check(result.code === 0
            && JSON.stringify(result.after) === JSON.stringify([`${name(dbPath)}:${fs.statSync(dbPath).size}`]),
            'sidecar/wal-exit/rollback-journal-database-has-no-sidecar-files', JSON.stringify(result));
    }

    // Unsaved edits at exit, as when a database is closed without saving. In
    // WAL mode they never reached the -wal, so the close rolls them back and
    // removes both files: the row is gone and the main file unchanged.
    {
        const dbPath = path.join(directory, 'unsaved.sqlite');
        seedWal(dbPath);
        const main = digest(dbPath);
        const result = await session(dbPath, 'rw', async (s) => {
            await s.invoke('runQuery', ['BEGIN']);
            await s.invoke('runQuery', ["INSERT INTO t (v) VALUES ('unsaved')"]);
        });
        const reader = new DatabaseSync(dbPath, { readOnly: true });
        const rows = reader.prepare('SELECT count(*) AS c FROM t').get()?.c;
        reader.close();
        check(result.code === 0 && digest(dbPath) === main && rows === 1
            && JSON.stringify(result.after) === JSON.stringify([`${name(dbPath)}:${fs.statSync(dbPath).size}`]),
            'sidecar/wal-exit/unsaved-wal-edits-are-discarded-and-the-files-removed', JSON.stringify({ ...result, rows }));
    }

    // KNOWN LIMIT, pinned: unsaved edits in a rollback-journal database leave
    // their -journal behind, because nothing closes that database at exit
    // (as before this change). It is a hot journal, and the next writable
    // open rolls it back; the main file is unchanged.
    {
        const dbPath = path.join(directory, 'unsaved-journal.sqlite');
        const seed = new DatabaseSync(dbPath);
        seed.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (v) VALUES ('one');");
        seed.close();
        const main = digest(dbPath);
        const result = await session(dbPath, 'rw', async (s) => {
            await s.invoke('runQuery', ['BEGIN']);
            await s.invoke('runQuery', ["INSERT INTO t (v) VALUES ('unsaved')"]);
        });
        check(result.code === 0 && digest(dbPath) === main
            && result.after.some((entry) => entry.startsWith(`${name(dbPath)}-journal:`)),
            'sidecar/wal-exit/known-limit/unsaved-rollback-journal-edits-leave-a-hot-journal', JSON.stringify(result));
    }

    // KNOWN LIMIT, pinned: a session opened read-only leaves behind the two
    // files created by its read. SQLite deletes them on close only after
    // taking a write lock on the main file, which a read-only file handle
    // cannot take. The main file is unchanged.
    {
        const dbPath = path.join(directory, 'read-only.sqlite');
        seedWal(dbPath);
        const before = digest(dbPath);
        const result = await session(dbPath, 'ro');
        check(result.code === 0 && digest(dbPath) === before
            && result.after.includes(`${name(dbPath)}-wal:0`) && result.after.some((entry) => entry.startsWith(`${name(dbPath)}-shm:`)),
            'sidecar/wal-exit/known-limit/ro-session-wal-files-remain', JSON.stringify(result));
    }
    return checks;
}

/**
 * The orphan watchdog's exit applies the same close rule as EOF. Set up like
 * runWatchdogCase, but with the sidecar's stdin and stdout on pipes this lane
 * holds, so the database can be opened and read before the parent dies.
 *
 * @returns {Promise<number>} checks run
 */
async function runWalWatchdogCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };
    const directory = path.join(scratch, 'wal-watchdog');
    fs.mkdirSync(directory, { recursive: true });
    const dbPath = path.join(directory, 'orphaned.sqlite');
    const seed = new DatabaseSync(dbPath);
    seed.exec("PRAGMA journal_mode = WAL; CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (v) VALUES ('one');");
    seed.close();
    const listing = () => fs.readdirSync(directory).sort()
        .map((name) => `${name}:${fs.statSync(path.join(directory, name)).size}`);

    const intermediarySource = `
        const { spawn } = require('node:child_process');
        const child = spawn(${JSON.stringify(binary)},
            ['run', ${JSON.stringify(BUNDLE_PATH)}, ${JSON.stringify(`--path-utf8=${encodeURIComponent(dbPath)}`)}, 'rw'],
            { stdio: [3, 4, 'inherit'] });
        console.log(String(child.pid));
        setInterval(() => {}, 1000);
    `;
    const intermediary = spawn(process.execPath, ['-e', intermediarySource], {
        stdio: ['ignore', 'pipe', 'pipe', 'pipe', 'pipe']
    });
    const replies = new Map();
    const reader = createFrameReader(
        (message) => replies.get(message?.content?.messageId)?.(message),
        () => {}
    );
    intermediary.stdio[4].on('data', (chunk) => reader.push(new Uint8Array(chunk)));
    let stderr = '';
    intermediary.stderr.on('data', (chunk) => { stderr += chunk; });
    const alive = (pid) => {
        try { process.kill(pid, 0); return true; } catch { return false; }
    };
    let sidecarPid;
    try {
        sidecarPid = await new Promise((resolve, reject) => {
            const timer = setTimeout(() => reject(new Error('intermediary never reported the sidecar pid')), 10000);
            let stdout = '';
            intermediary.stdout.on('data', (chunk) => {
                stdout += chunk;
                const match = stdout.match(/^(\d+)\n/);
                if (match) { clearTimeout(timer); resolve(Number(match[1])); }
            });
        });
        let sequence = 0;
        const invoke = (targetMethod, payload) => new Promise((resolve, reject) => {
            const messageId = `orphan_${++sequence}`;
            const timer = setTimeout(() => reject(new Error(`timed out waiting for ${targetMethod}`)), 15000);
            replies.set(messageId, (message) => { clearTimeout(timer); replies.delete(messageId); resolve(message); });
            intermediary.stdio[3].write(Buffer.from(encodeFrame({
                channel: 'rpc', content: { kind: 'invoke', messageId, targetMethod, payload }
            })));
        });
        const init = await invoke('initializeDatabase', [path.basename(dbPath), { path: dbPath, readOnlyMode: false }]);
        const page = await invoke('fetchTableData', ['t', { limit: 10, offset: 0 }]);
        const during = listing();
        intermediary.kill('SIGKILL');
        let died = false;
        const deadline = Date.now() + 10000;
        while (Date.now() < deadline) {
            if (!alive(sidecarPid)) { died = true; break; }
            await sleep(100);
        }
        check(init.content?.success === true && page.content?.success === true && died
            && during.includes('orphaned.sqlite-wal:0')
            && JSON.stringify(listing()) === JSON.stringify([`orphaned.sqlite:${fs.statSync(dbPath).size}`]),
            'sidecar/wal-exit/orphan-watchdog-exit-cleans-up-too',
            JSON.stringify({ died, during, after: listing(), stderr: stderr.trim().slice(0, 220) }));
    } finally {
        if (sidecarPid !== undefined && alive(sidecarPid)) process.kill(sidecarPid, 'SIGKILL');
        if (intermediary.exitCode === null) intermediary.kill('SIGKILL');
    }
    return checks;
}

/**
 * The wall time of one 600 ms busy wait (native-host.js LOCK_WAIT_MS) on this
 * machine, measured with node:sqlite against an exclusive lock: the same SQLite
 * busy handler and sleep schedule the sidecar's connection uses. The handler
 * counts the sleeps it asks for, not the time they take, so where the OS
 * oversleeps, one wait lasts well past 600 ms of wall time. The single-wait
 * ceilings in runLockWaitCase scale with this, so they still tell one wait from
 * two on such a machine. Median of three.
 *
 * @returns {number} milliseconds
 */
function measureOneBusyWait(scratch) {
    const file = path.join(scratch, 'busy-wait-control.sqlite');
    fs.rmSync(file, { force: true });
    const holder = new DatabaseSync(file);
    holder.exec('CREATE TABLE t (x)');
    holder.exec('BEGIN EXCLUSIVE');
    const walls = [];
    try {
        for (let i = 0; i < 3; i += 1) {
            const waiter = new DatabaseSync(file, { timeout: 600 });
            const started = Date.now();
            try {
                waiter.prepare('SELECT count(*) FROM t').get();
                throw new Error('busy-wait control: a read under an exclusive lock was not refused');
            } catch (error) {
                if (!/database is locked/.test(error?.message ?? '')) throw error;
            } finally {
                waiter.close();
            }
            walls.push(Date.now() - started);
        }
    } finally {
        holder.exec('ROLLBACK');
        holder.close();
    }
    return walls.sort((a, b) => a - b)[1];
}

/**
 * busy_timeout against a second connection on the same file. In
 * rollback-journal mode a SHARED lock elsewhere blocks this session's COMMIT
 * and an EXCLUSIVE one blocks its reads. The second connection is node:sqlite
 * in this process; a timer releases it while the sidecar's request is still
 * outstanding.
 *
 * @returns {Promise<number>} checks run
 */
async function runLockWaitCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };
    const show = (reply) => JSON.stringify(reply?.content, (_key, v) => (typeof v === 'bigint' ? `${v}n` : v)).slice(0, 300);
    const dbPath = path.join(scratch, 'lock-wait.sqlite');
    fs.rmSync(dbPath, { force: true });
    const seed = new DatabaseSync(dbPath);
    seed.exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT, payload BLOB);
        INSERT INTO t VALUES (1, 'one', X'00010203'), (2, 'two', NULL);`);
    seed.close();
    // At least 1100 ms (well below two waits on an idle machine), more where one
    // wait takes longer here; two waits still exceed it.
    const oneWaitMs = measureOneBusyWait(scratch);
    const singleWaitCeilingMs = Math.max(1100, Math.round(1.5 * oneWaitMs));
    const waitNote = `(one wait here: ${oneWaitMs} ms; ceiling ${singleWaitCeilingMs} ms)`;
    const lockers = [];
    const timedReleases = [];
    /**
     * Open a second connection and take a lock: 'shared' (a read inside an
     * open transaction) or 'exclusive'. Returns its release; with
     * `releaseAfterMs` a timer releases it too.
     */
    const takeLock = (mode, releaseAfterMs) => {
        const locker = new DatabaseSync(dbPath, { timeout: 0 });
        lockers.push(locker);
        locker.exec(mode === 'exclusive' ? 'BEGIN EXCLUSIVE' : 'BEGIN');
        if (mode === 'shared') locker.prepare('SELECT count(*) AS c FROM t').get();
        const release = () => { if (locker.isOpen) { locker.exec('ROLLBACK'); locker.close(); } };
        if (releaseAfterMs !== undefined) {
            timedReleases.push(new Promise((resolve) => setTimeout(() => { release(); resolve(); }, releaseAfterMs)));
        }
        return release;
    };
    // initializeDatabase reads the file as well: an exclusive lock released
    // after 150 ms delays the open instead of failing it.
    {
        takeLock('exclusive', 150);
        const opener = startSidecar(binary, dbPath, 'rw');
        try {
            const started = Date.now();
            const opened = await opener.invoke('initializeDatabase', [path.basename(dbPath), {
                path: dbPath, readOnlyMode: false, queryTimeout: 30000
            }]);
            const ms = Date.now() - started;
            check(opened.content?.success === true && ms >= 100,
                'sidecar/lock-wait/open-succeeds-when-an-exclusive-lock-clears-within-the-wait', `${ms} ms ${show(opened)}`);
            opener.endStdin();
            await opener.untilExit();
        } finally {
            if (opener.exitCode === null) opener.child.kill('SIGKILL');
        }
        await Promise.all(timedReleases);
    }

    const s = startSidecar(binary, dbPath, 'rw');
    const timed = async (method, payload) => {
        const started = Date.now();
        const reply = await s.invoke(method, payload);
        return { reply, ms: Date.now() - started };
    };
    const locked = (reply) => /database is locked/.test(reply?.content?.errorMessage ?? '');
    try {
        const init = await s.invoke('initializeDatabase', [path.basename(dbPath), {
            path: dbPath, readOnlyMode: false, queryTimeout: 30000
        }]);
        check(init.content?.success === true, 'sidecar/lock-wait/session-opens', show(init));

        // The desktop's Save is a COMMIT of the host's session transaction.
        // A shared lock released after 150 ms delays it instead of failing it.
        await s.invoke('runQuery', ['BEGIN']);
        await s.invoke('runQuery', ["INSERT INTO t (v) VALUES ('three')"]);
        takeLock('shared', 150);
        const saved = await timed('runQuery', ['COMMIT']);
        check(saved.reply.content?.success === true && saved.ms >= 100 && saved.ms < 600,
            'sidecar/lock-wait/commit-succeeds-when-a-shared-lock-clears-within-the-wait', `${saved.ms} ms ${show(saved.reply)}`);

        // A shared lock that is never released: the COMMIT is refused once
        // the 600 ms are spent (well above 0, well below two waits). SQLite
        // keeps the transaction and its row, so a COMMIT after the release
        // succeeds.
        await s.invoke('runQuery', ['BEGIN']);
        await s.invoke('runQuery', ["INSERT INTO t (v) VALUES ('four')"]);
        const releaseShared = takeLock('shared');
        const refused = await timed('runQuery', ['COMMIT']);
        check(locked(refused.reply) && refused.ms >= 450 && refused.ms < singleWaitCeilingMs,
            'sidecar/lock-wait/commit-is-refused-after-about-600-ms-under-a-held-shared-lock',
            `${refused.ms} ms ${waitNote} ${show(refused.reply)}`);
        releaseShared();
        const retried = await s.invoke('runQuery', ['COMMIT']);
        check(retried.content?.success === true, 'sidecar/lock-wait/a-refused-commit-can-be-repeated-after-release',
            show(retried));

        // The refusal above turned waiting off for that request only; the
        // next request gets the full wait back.
        await s.invoke('runQuery', ['BEGIN']);
        await s.invoke('runQuery', ["INSERT INTO t (v) VALUES ('five')"]);
        takeLock('shared', 150);
        const next = await timed('runQuery', ['COMMIT']);
        const rows = await s.invoke('runQuery', ['SELECT count(*) FROM t']);
        check(next.reply.content?.success === true && next.ms >= 100
            && rows.content?.data?.[0]?.rows?.[0]?.[0] === 5,
            'sidecar/lock-wait/a-refusal-does-not-carry-over-to-the-next-request', `${next.ms} ms ${show(next.reply)} ${show(rows)}`);

        // Under an exclusive lock that is never released, no request may take
        // longer than one wait, however many statements it runs. Taking that
        // lock needs the file free: a COMMIT refused above (when this lane
        // runs against an engine without the wait) leaves a transaction open,
        // so it is rolled back first; with none open the ROLLBACK just fails.
        await s.invoke('runQuery', ['ROLLBACK']);
        await Promise.all(timedReleases);
        await s.invoke('fetchSchema', []);
        const releaseExclusive = takeLock('exclusive');
        // getPragmas may answer from what the connection already holds, so it
        // is only held to the upper bound.
        const answers = {};
        for (const [label, method, payload, readsTheFile = true] of [
            ['schema', 'fetchSchema', []],
            ['grid-page', 'fetchTableData', ['t', { limit: 10, offset: 0 }]],
            ['count', 'fetchTableCount', ['t', {}]],
            ['table-info', 'getTableInfo', ['t']],
            ['pragmas', 'getPragmas', [], false],
            ['console-script', 'runConsole', ['SELECT * FROM t; SELECT v FROM t; SELECT 1 FROM t']],
            ['table-export', 'exportTable', [{ table: 't' }, ['id', 'v'], null, null, { format: 'csv', header: true }]],
            // After the refused export, several pragmas need the file again;
            // getPragmas runs them one by one and catches each failure, so
            // without the per-request rule it paid one wait per pragma.
            ['pragmas-after-a-refused-export', 'getPragmas', [], false],
            ['edit', 'updateCell', ['t', 1, 'v', 'edited']]
        ]) {
            const answer = await timed(method, payload);
            answers[label] = answer.reply;
            check((!readsTheFile || answer.ms >= 450) && answer.ms < singleWaitCeilingMs,
                `sidecar/lock-wait/bounded-by-a-single-wait/${label}`, `${answer.ms} ms ${waitNote} ${show(answer.reply)}`);
        }
        // The column probe used to swallow the refusal, and the grid then
        // failed on "Cell containment requires a positive column count".
        check(locked(answers['grid-page']), 'sidecar/lock-wait/grid-page-under-an-exclusive-lock-says-database-is-locked',
            show(answers['grid-page']));
        releaseExclusive();

        // With a cell read session open, the worker's own guard refuses every
        // other request before any SQL runs, so no wait applies.
        const session = await s.invoke('openCellReadSession', [{ table: 't', rowId: 1, column: 'payload' }]);
        takeLock('shared', 150);
        const during = await timed('runQuery', ['COMMIT']);
        check(session.content?.success === true && during.ms < 200
            && /cell read snapshot is active/.test(during.reply.content?.errorMessage ?? ''),
            'sidecar/lock-wait/requests-during-a-cell-read-session-are-refused-immediately',
            `${during.ms} ms ${show(during.reply)}`);
        await s.invoke('closeCellReadSession', [session.content?.data?.sessionId]);

        s.endStdin();
        check(await s.untilExit() === 0, 'sidecar/lock-wait/clean-shutdown');
    } finally {
        for (const locker of lockers) if (locker.isOpen) locker.close();
        if (s.exitCode === null) s.child.kill('SIGKILL');
    }
    return checks;
}

/**
 * A 0444 database opened in a WRITABLE session.
 *
 * SQLite opens such a file happily and only refuses at the first write, so
 * initializeDatabase used to answer `isReadOnly: false` and the UI offered
 * edits that could not possibly land. The open-time BEGIN IMMEDIATE probe has
 * to catch it, report it, and leave the session honestly read-only.
 *
 * @returns {Promise<number>} checks run
 */
async function runUnwritableFileCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };

    const dbPath = path.join(scratch, 'unwritable-fixture.sqlite');
    createFixture(dbPath);
    fs.chmodSync(dbPath, 0o444);

    const session = startSidecar(binary, dbPath, 'rw');
    try {
        const init = await session.invoke('initializeDatabase', ['unwritable-fixture.sqlite', {
            path: dbPath, readOnlyMode: false
        }]);
        check(init.content?.success === true
            && init.content?.data?.isReadOnly === true
            && /read-only/i.test(init.content?.data?.readOnlyReason ?? ''),
            'sidecar/E11-unwritable-file-opens-read-only',
            JSON.stringify(init.content?.data));

        // ...and the refusal is the ordinary read-only one, before SQLite is
        // ever asked to do the impossible.
        const write = await session.invoke('insertRow', ['t', { name: 'nope' }]);
        check(write.content?.success === false
            && /read-only/i.test(write.content?.errorMessage ?? ''),
            'sidecar/E11-unwritable-file-refuses-edits-up-front',
            JSON.stringify(write.content?.errorMessage));

        const read = await session.invoke('fetchSchema', []);
        check(read.content?.success === true
            && (read.content?.data?.tables?.map((table) => table.identifier) ?? []).includes('t'),
            'sidecar/E11-unwritable-file-still-reads');

        // …and the GRID reads, which is the half that was broken. Escalating to
        // read-only used to arm `PRAGMA query_only` behind the shim's back, so
        // the shim's column probe could no longer create its TEMP VIEW, the
        // refusal was swallowed into "no columns", and fetchTableData died on
        // "Cell containment requires a positive column count, got 0" — the
        // schema loaded, the table was selectable, and selecting it replaced the
        // grid with an internal invariant message. fetchSchema alone never saw
        // it, because schema reads do not go through the probe.
        const grid = await session.invoke('fetchTableData', ['t', { limit: 100, offset: 0 }]);
        check(grid.content?.success === true
            && Array.isArray(grid.content?.data?.headers)
            && grid.content.data.headers.length > 0
            && (grid.content?.data?.rows?.length ?? 0) > 0,
            'sidecar/E11-unwritable-file-renders-a-grid',
            JSON.stringify(grid.content?.errorMessage ?? grid.content?.data?.headers));

        session.endStdin();
        const code = await session.untilExit();
        check(code === 0, 'sidecar/E11-unwritable-session-exits-clean', `exit ${code}`);
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
        const stderrText = session.stderr.trim();
        if (stderrText) console.log(`[sidecar unwritable stderr]\n${stderrText}\n`);
        fs.chmodSync(dbPath, 0o644);
    }

    // WRITABLE CONTROL. The probe attempts a real write, so it has to be
    // provably invisible: open a writable database, do nothing else, and the
    // file must be byte-identical afterwards with no journal left behind.
    const controlPath = path.join(scratch, 'probe-control.sqlite');
    createFixture(controlPath);
    const before = createHash('sha256').update(fs.readFileSync(controlPath)).digest('hex');
    const control = startSidecar(binary, controlPath, 'rw');
    try {
        const init = await control.invoke('initializeDatabase', ['probe-control.sqlite', {
            path: controlPath, readOnlyMode: false
        }]);
        const sidecars = ['-journal', '-wal', '-shm']
            .filter((suffix) => fs.existsSync(`${controlPath}${suffix}`));
        const after = createHash('sha256').update(fs.readFileSync(controlPath)).digest('hex');
        check(init.content?.data?.isReadOnly === false
            && init.content?.data?.readOnlyReason === undefined
            && after === before
            && sidecars.length === 0,
            'sidecar/E11-write-probe-leaves-a-writable-database-untouched',
            `same=${after === before}, leftovers=${JSON.stringify(sidecars)}`);

        control.endStdin();
        const code = await control.untilExit();
        check(code === 0, 'sidecar/E11-control-session-exits-clean', `exit ${code}`);
    } finally {
        if (control.exitCode === null) control.child.kill('SIGKILL');
        const stderrText = control.stderr.trim();
        if (stderrText) console.log(`[sidecar probe-control stderr]\n${stderrText}\n`);
    }

    // READ-ONLY DIRECTORY: the shape this defect was actually reported in (a
    // read-only mount, a locked-down folder). The FILE stays rw-r--r--; only
    // the directory refuses, so SQLite opens it happily, serves every read, and
    // fails only when it tries to create the journal. Same escalation path as
    // the 0444 case above, different trigger — and the one a user hits without
    // having done anything unusual.
    checks += await runReadOnlyDirectoryCase(binary, scratch, note);
    return checks;
}

/**
 * @returns {Promise<number>} checks run (0 when the platform cannot express it)
 */
async function runReadOnlyDirectoryCase(binary, scratch, note) {
    if (process.platform === 'win32') return 0;
    const directory = path.join(scratch, 'readonly-dir');
    fs.mkdirSync(directory, { recursive: true });
    const dbPath = path.join(directory, 'locked.sqlite');
    createFixture(dbPath);
    fs.chmodSync(directory, 0o555);
    try {
        // Running as root defeats the fixture entirely (root writes read-only
        // directories), so PROVE the trigger before asserting anything about it
        // — a silently-writable directory would turn this into a green test of
        // nothing.
        const witness = path.join(directory, '.write-probe');
        let refuses = false;
        try {
            fs.writeFileSync(witness, 'x');
            fs.rmSync(witness, { force: true });
        } catch {
            refuses = true;
        }
        if (!refuses) {
            note(true, 'sidecar/E11-readonly-directory-SKIPPED', 'the directory is still writable (root?)');
            return 1;
        }

        const session = startSidecar(binary, dbPath, 'rw');
        try {
            const init = await session.invoke('initializeDatabase', ['locked.sqlite', {
                path: dbPath, readOnlyMode: false
            }]);
            const grid = await session.invoke('fetchTableData', ['t', { limit: 100, offset: 0 }]);
            note(init.content?.data?.isReadOnly === true
                && /read-only/i.test(init.content?.data?.readOnlyReason ?? '')
                && grid.content?.success === true
                && (grid.content?.data?.headers?.length ?? 0) > 0
                && (grid.content?.data?.rows?.length ?? 0) > 0,
                'sidecar/E11-readonly-directory-opens-read-only-and-renders',
                JSON.stringify({
                    isReadOnly: init.content?.data?.isReadOnly,
                    grid: grid.content?.errorMessage ?? grid.content?.data?.headers
                }));

            session.endStdin();
            const code = await session.untilExit();
            note(code === 0, 'sidecar/E11-readonly-directory-session-exits-clean', `exit ${code}`);
        } finally {
            if (session.exitCode === null) session.child.kill('SIGKILL');
            const stderrText = session.stderr.trim();
            if (stderrText) console.log(`[sidecar readonly-dir stderr]\n${stderrText}\n`);
        }
        return 2;
    } finally {
        // Always restore, or the scratch directory cannot be removed.
        fs.chmodSync(directory, 0o755);
    }
}

/** Mirrors DESKTOP_EXPORT_MAX_BYTES in desktop-host.js (the host's raised ceiling). */
const DESKTOP_EXPORT_MAX_BYTES = 512 * 1024 * 1024;

/**
 * Drive the SHELL-ORIGINATED export-to-path route through the real binary:
 * `{channel:'shell', content:{kind:'export', ...}}` in, a small
 * `{kind:'export-result'}` reply out, and the actual bytes land at the
 * shell-provided temp path — for BOTH methods, on results larger than the
 * 16 MiB frame cap (which the framed route provably cannot carry). Also the
 * negative space: the webview's rpc surface must NOT reach exportToPath, and
 * an rpc-channel envelope must never be treated as a shell export.
 *
 * @returns {Promise<number>} checks run
 */
async function runShellExportCase(binary, scratch, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };

    // A fixture whose DB image AND CSV export both exceed MAX_FRAME_BYTES:
    // 20,000 rows x 1,016 chars of hex text ≈ 20.3 MiB of payload.
    const bigPath = path.join(scratch, 'shell-export-big.sqlite');
    fs.rmSync(bigPath, { force: true });
    {
        const big = new DatabaseSync(bigPath);
        big.exec(`
            CREATE TABLE big(id INTEGER PRIMARY KEY, payload TEXT NOT NULL);
            INSERT INTO big(payload)
                WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 20000)
                SELECT hex(randomblob(508)) FROM n;
        `);
        big.close();
    }

    const session = startSidecar(binary, bigPath, 'rw');
    try {
        const init = await session.invoke('initializeDatabase', ['shell-export-big.sqlite', {
            path: bigPath, readOnlyMode: false, queryTimeout: 30000
        }]);
        check(init.content?.success === true, 'sidecar/shell-export-session-initializes',
            JSON.stringify(init.content?.errorMessage ?? ''));

        // exportDatabase → VACUUM INTO the shell's temp path. Only the small
        // export-result crosses the pipe; the >16 MiB image never does.
        const dbTemp = path.join(scratch, 'shell-export-db.sqlite');
        fs.rmSync(dbTemp, { force: true });
        let dbReply;
        try {
            dbReply = await session.shellExport('exportDatabase', dbTemp, undefined, 120000);
        } catch (error) {
            dbReply = { laneError: String(error?.message ?? error) };
        }
        const dbSize = fs.existsSync(dbTemp) ? fs.statSync(dbTemp).size : -1;
        let bigCount = null;
        if (dbSize > 0) {
            const reopened = new DatabaseSync(dbTemp, { readOnly: true });
            bigCount = reopened.prepare('SELECT count(*) AS c FROM big').get().c;
            reopened.close();
        }
        check(dbReply?.channel === 'shell'
            && dbReply?.content?.kind === 'export-result'
            && dbReply?.content?.success === true
            && dbReply?.content?.bytesWritten === dbSize
            && dbSize > MAX_FRAME_BYTES
            && bigCount === 20000,
            'sidecar/shell-export-database-lands-over-16MiB',
            `reply=${JSON.stringify(dbReply?.content ?? dbReply)} size=${dbSize} rows=${bigCount}`);

        // exportTable → the worker's own exportTable runs in-process; its
        // chunks are written to the shell's temp path as one CSV file.
        const csvTemp = path.join(scratch, 'shell-export-table.csv');
        fs.rmSync(csvTemp, { force: true });
        let csvReply;
        try {
            csvReply = await session.shellExport('exportTable', csvTemp, [
                { table: 'big' }, [], null, null,
                { format: 'csv', header: true, maxExportBytes: DESKTOP_EXPORT_MAX_BYTES }
            ], 120000);
        } catch (error) {
            csvReply = { laneError: String(error?.message ?? error) };
        }
        const csvSize = fs.existsSync(csvTemp) ? fs.statSync(csvTemp).size : -1;
        let csvShape = null;
        if (csvSize > 0) {
            const lines = fs.readFileSync(csvTemp, 'utf8').split('\n');
            // Row 1 checked against the DB itself: real content, byte-exact.
            const reopened = new DatabaseSync(bigPath, { readOnly: true });
            const row1 = reopened.prepare('SELECT payload FROM big WHERE id = 1').get().payload;
            reopened.close();
            csvShape = {
                header: lines[0],
                lineCount: lines.length,
                row1Matches: lines[1] === `1,${row1}`
            };
        }
        check(csvReply?.channel === 'shell'
            && csvReply?.content?.kind === 'export-result'
            && csvReply?.content?.success === true
            && csvReply?.content?.bytesWritten === csvSize
            && csvSize > MAX_FRAME_BYTES
            && csvShape?.header === 'id,payload'
            && csvShape?.lineCount === 20001
            && csvShape?.row1Matches === true,
            'sidecar/shell-export-table-csv-lands-over-16MiB',
            `reply=${JSON.stringify(csvReply?.content ?? csvReply)} size=${csvSize} ` +
            `shape=${JSON.stringify({ ...csvShape, header: csvShape?.header?.slice(0, 40) })}`);

        // Failure contract, exportDatabase: an existing target fails closed
        // (VACUUM INTO refuses it) with a structured error; file untouched.
        const occupied = path.join(scratch, 'shell-export-occupied');
        fs.writeFileSync(occupied, 'occupied');
        const clash = await session.shellExport('exportDatabase', occupied, undefined, 60000)
            .catch((error) => ({ laneError: String(error?.message ?? error) }));
        check(clash?.content?.kind === 'export-result'
            && clash?.content?.success === false
            && typeof clash?.content?.error?.message === 'string'
            && clash.content.error.message.length > 0
            && fs.readFileSync(occupied, 'utf8') === 'occupied',
            'sidecar/shell-export-existing-target-fails-closed',
            JSON.stringify(clash?.content ?? clash));

        // Failure contract, exportTable: a worker-level failure (unknown
        // table) reports structurally and creates NO file at the temp path.
        const failTemp = path.join(scratch, 'shell-export-fail.csv');
        fs.rmSync(failTemp, { force: true });
        const noTable = await session.shellExport('exportTable', failTemp, [
            { table: 'no_such_table' }, [], null, null,
            { format: 'csv', header: true, maxExportBytes: DESKTOP_EXPORT_MAX_BYTES }
        ], 60000).catch((error) => ({ laneError: String(error?.message ?? error) }));
        check(noTable?.content?.kind === 'export-result'
            && noTable?.content?.success === false
            && typeof noTable?.content?.error?.message === 'string'
            && !fs.existsSync(failTemp),
            'sidecar/shell-export-table-failure-creates-no-file',
            `${JSON.stringify(noTable?.content ?? noTable)} created=${fs.existsSync(failTemp)}`);

        // SECURITY: the webview surface did not widen — exportToPath is not a
        // worker method the rpc channel can reach.
        const viaRpc = await session.invoke('exportToPath', ['/tmp/shell-export-pwn.sqlite']);
        check(viaRpc.content?.success === false
            && viaRpc.content?.errorMessage === 'Unknown method: exportToPath',
            'sidecar/exportToPath-not-a-worker-method', JSON.stringify(viaRpc.content));

        // SECURITY: an rpc-channel envelope carrying the shell-export shape is
        // NEVER treated as a shell export (worker.js ignores it; no file, no
        // reply). The ping is the ordering barrier: by the time it answers,
        // the forged frame has been consumed.
        const forgedTemp = path.join(scratch, 'shell-export-forged');
        fs.rmSync(forgedTemp, { force: true });
        session.sendRaw({
            channel: 'rpc',
            content: { kind: 'export', messageId: 'forged_1', method: 'exportDatabase', tempPath: forgedTemp }
        });
        const barrier = await session.invoke('ping', []);
        check(barrier.content?.success === true && !fs.existsSync(forgedTemp),
            'sidecar/rpc-envelope-never-treated-as-shell-export',
            `created=${fs.existsSync(forgedTemp)}`);

        session.endStdin();
        const code = await session.untilExit();
        check(code === 0, 'sidecar/shell-export-session-eof-exits-clean', `exit ${code}`);
    } finally {
        if (session.exitCode === null) session.child.kill('SIGKILL');
        const stderrText = session.stderr.trim();
        if (stderrText) console.log(`[sidecar shell-export stderr]\n${stderrText}\n`);
    }
    return checks;
}

/**
 * Kill the sidecar's PARENT while a grandparent keeps its stdin pipe open, so
 * EOF never arrives and only the ppid watchdog can notice the orphaning.
 *
 * Topology: this process (L) spawns an intermediary node process (P) with an
 * extra pipe on fd 3; P spawns the sidecar (S) with that fd as S's stdin. The
 * pipe's write end lives in L, so SIGKILLing P closes nothing S reads from —
 * exactly the "write end inherited elsewhere" scenario the watchdog exists
 * for. S's stderr rides P's inherited stderr pipe, which S keeps holding
 * after P dies, so the watchdog's log line still reaches L.
 *
 * @returns {Promise<number>} checks run
 */
async function runWatchdogCase(binary, dbPath, note) {
    let checks = 0;
    const check = (ok, label, detail) => { note(ok, label, detail); checks += 1; };

    const intermediarySource = `
        const { spawn } = require('node:child_process');
        const child = spawn(${JSON.stringify(binary)},
            ['run', ${JSON.stringify(BUNDLE_PATH)}, ${JSON.stringify(dbPath)}, 'rw'],
            { stdio: [3, 'ignore', 'inherit'] });
        console.log(String(child.pid));
        setInterval(() => {}, 1000); // stay alive until killed
    `;
    const intermediary = spawn(process.execPath, ['-e', intermediarySource], {
        stdio: ['ignore', 'pipe', 'pipe', 'pipe']
    });

    let stderr = '';
    intermediary.stderr.on('data', (chunk) => { stderr += chunk; });
    const sidecarPid = await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error('intermediary never reported the sidecar pid')), 10000);
        let stdout = '';
        intermediary.stdout.on('data', (chunk) => {
            stdout += chunk;
            const match = stdout.match(/^(\d+)\n/);
            if (match) { clearTimeout(timer); resolve(Number(match[1])); }
        });
    });

    const alive = (pid) => {
        try { process.kill(pid, 0); return true; } catch { return false; }
    };

    try {
        // No false positive while the parent lives: outlast one watchdog tick.
        await sleep(2000);
        check(alive(sidecarPid), 'sidecar/watchdog-quiet-while-parent-alive', `pid ${sidecarPid}`);

        intermediary.kill('SIGKILL');
        // L still holds the stdin write end, so the ONLY signal S gets is the
        // reparenting the watchdog polls for.
        let died = false;
        const deadline = Date.now() + 10000;
        while (Date.now() < deadline) {
            if (!alive(sidecarPid)) { died = true; break; }
            await sleep(200);
        }
        check(died, 'sidecar/watchdog-exits-orphan-with-open-stdin', `pid ${sidecarPid}`);

        // The abnormal-death breadcrumb reached us over the inherited stderr.
        // The orphan reparents to the OS reaper (launchd/init), so its real
        // wait-status is unreachable here — the watchdog names its numeric exit
        // code in the breadcrumb (EXIT_ORPHANED = 3), and that is what we assert.
        await sleep(200);
        check(/vanished without closing stdin/.test(stderr) && /exiting \(code 3\)/.test(stderr),
            'sidecar/watchdog-logs-abnormal-death-with-code-3', JSON.stringify(stderr.trim().slice(0, 220)));
    } finally {
        if (alive(sidecarPid)) process.kill(sidecarPid, 'SIGKILL');
        if (intermediary.exitCode === null) intermediary.kill('SIGKILL');
    }
    return checks;
}
