/**
 * Differential suite for `core/native/sqljs-shim.js`.
 *
 * The shim's contract is "behave like sql.js", so almost every assertion here
 * runs the SAME operation against the real vendored sql.js `Database` and
 * against the shim, and compares. The shim runs over a node:sqlite stand-in
 * reshaped to the fork's `tjs:sqlite` contract (see
 * `helpers/tjs-backing-standin.ts`); the REAL binary runs the same fixture
 * matrix in `scripts/native-lane.mjs` (`npm run native-lane`, macOS-local).
 *
 * Where the fork genuinely differs from sql.js, the difference is asserted
 * EXPLICITLY in the "documented divergences" block rather than smoothed over,
 * so a future fork refresh that changes one of them fails loudly.
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import { Worker } from 'node:worker_threads';
import initSqlJs from '../../vendor/sql.js/sql-wasm.js';
import {
    createShimDatabase,
    consumedSourceLength,
    NATIVE_SQL_ATTACH_BLOCKED,
    NATIVE_SQL_VACUUM_INTO_BLOCKED
} from '../../core/native/sqljs-shim.js';
import type { ShimDatabase, ShimValueConfig, NativeBindParams } from '../../core/native/sqljs-shim.js';
import { standInSqliteModule } from './helpers/tjs-backing-standin';

/** The slice of sql.js's Database the shim reimplements. */
type SqlJsLike = Pick<
    ShimDatabase,
    'exec' | 'run' | 'prepare' | 'iterateStatements' | 'getRowsModified' | 'close'
>;

const SEED_SQL = `
CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT, data BLOB, amount REAL);
INSERT INTO t VALUES
  (1, 'alpha', x'0102ff', 1.5),
  (2, NULL, NULL, -0.25),
  (9007199254740993, 'big', x'', 0.0);
CREATE TABLE u(a INTEGER UNIQUE, b TEXT NOT NULL);
INSERT INTO u VALUES (1, 'x');
`;

let SQL: { Database: new (data?: Uint8Array) => SqlJsLike };
const scratchDirs: string[] = [];

/** Synchronous filesystem hooks for the shim's export(); the sidecar supplies tjs's async ones. */
const nodeFileSystem = {
    makeTempDir: () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqljs-shim-'));
        scratchDirs.push(dir);
        return dir;
    },
    readFile: (target: string) => new Uint8Array(fs.readFileSync(target)),
    remove: (target: string) => fs.rmSync(target, { recursive: true, force: true })
};

function createShim(config: Record<string, unknown> = {}): ShimDatabase {
    return createShimDatabase(config, { sqlite: standInSqliteModule, fs: nodeFileSystem });
}

before(async () => {
    SQL = await (initSqlJs as unknown as (c?: unknown) => Promise<typeof SQL>)();
});

/**
 * Compare values across engines.
 *
 * BigInt below 2^53 collapses to Number: sql.js's `useBigInt` returns BigInt
 * for EVERY integer, while the fork only crosses to BigInt at 2^53 (probed,
 * exact boundary). Both shapes are identical after the worker's own
 * `normalizeIntegerRowsForTransport`, which converts safe BigInts to Number and
 * only preserves exact text beyond the safe range — so this normalisation is
 * the real equivalence, not a papered-over difference. Unsafe integers are
 * compared as exact decimal text, which is the property that actually matters.
 */
function normalize(value: unknown): unknown {
    if (typeof value === 'bigint') {
        return Number.isSafeInteger(Number(value)) ? Number(value) : `int64:${value}`;
    }
    if (value instanceof Uint8Array) return { blob: Array.from(value) };
    if (Array.isArray(value)) return value.map(normalize);
    if (value !== null && typeof value === 'object') {
        return Object.fromEntries(
            Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, normalize(v)])
        );
    }
    return value;
}

/** sql.js throws bare strings from some paths and Errors from others. */
function errorText(error: unknown): string {
    if (typeof error === 'string') return error;
    return (error as Error)?.message ?? String(error);
}

type Probe = (db: SqlJsLike) => unknown;

function runProbe(db: SqlJsLike, probe: Probe): unknown {
    try {
        return { ok: normalize(probe(db)) };
    } catch (error) {
        return { threw: errorText(error) };
    }
}

/** Run `probe` against both engines on a freshly seeded database and assert equality. */
function differential(name: string, probe: Probe, options: { seed?: string } = {}): void {
    it(name, () => {
        const seed = options.seed ?? SEED_SQL;
        const reference = new SQL.Database();
        const shim = createShim();
        try {
            reference.run(seed);
            shim.run(seed);
            const expected = runProbe(reference, probe);
            const actual = runProbe(shim, probe);
            assert.deepStrictEqual(actual, expected);
        } finally {
            reference.close();
            shim.close();
        }
    });
}

/** Same, but only the two engines' error CLASSIFICATION is comparable (messages differ). */
function differentialThrows(name: string, probe: Probe, expectedErrno: number): void {
    it(name, () => {
        const reference = new SQL.Database();
        const shim = createShim();
        try {
            reference.run(SEED_SQL);
            shim.run(SEED_SQL);
            assert.throws(() => probe(reference), 'sql.js should reject this input');
            let captured: unknown;
            assert.throws(() => probe(shim), (error: unknown) => {
                captured = error;
                return true;
            });
            assert.strictEqual(
                (captured as { errno?: number }).errno,
                expectedErrno,
                'the fork classifies failures on errno; messages are nonspecific'
            );
        } finally {
            reference.close();
            shim.close();
        }
    });
}

// ---------------------------------------------------------------------------

describe('sqljs-shim: exec', () => {
    differential('multi-statement results, one entry per row-producing statement',
        db => db.exec('SELECT 1 AS a; SELECT 2 AS b'));
    differential('statements without rows contribute nothing',
        db => db.exec("INSERT INTO t VALUES(4, 'four', NULL, 1.0)"));
    differential('a zero-row SELECT contributes nothing',
        db => db.exec('SELECT id FROM t WHERE 0'));
    differential('unaliased expressions are named by their source text',
        db => db.exec('SELECT 1'));
    differential('trivia-only SQL yields no results',
        db => db.exec('  -- nothing at all\n'));
    differential('empty SQL yields no results', db => db.exec(''));
    differential('empty statements between real ones are consumed',
        db => db.exec('SELECT 1 AS a;; SELECT 2 AS b'));
    differential('a leading semicolon does not truncate the script',
        db => db.exec('; SELECT 1 AS a'));
    differential('PRAGMA reads return rows', db => db.exec('PRAGMA schema_version'));
    differential('positional parameters bind',
        db => db.exec('SELECT ? AS p, ? AS q', [7, 'seven']));
    differential('named parameters bind (sigil included in the key)',
        db => db.exec('SELECT :x AS p', { ':x': 5 } as unknown as NativeBindParams));
    differential('NULL, BLOB, REAL and int64 values cross intact',
        db => db.exec('SELECT id, name, data, amount FROM t ORDER BY id'));
    differential('useBigInt preserves an int64 beyond 2^53',
        db => db.exec('SELECT id FROM t ORDER BY id', null, { useBigInt: true } as ShimValueConfig));
    differential('without useBigInt an int64 beyond 2^53 is a lossy Number',
        db => db.exec('SELECT id FROM t ORDER BY id'));
    differential('an empty BLOB is a zero-length Uint8Array',
        db => db.exec("SELECT x'' AS empty_blob"));
    differential('semicolons inside string literals are not statement boundaries',
        db => db.exec("SELECT ';' AS semi; SELECT 2 AS after"));
    differential('a statement spanning a comment containing a semicolon',
        db => db.exec('SELECT 1 AS a /* ; not a boundary */ ; SELECT 2 AS b'));
});

describe('sqljs-shim: run and getRowsModified', () => {
    differential('run reports rows modified by the last statement', db => {
        db.run("INSERT INTO t VALUES(10, 'ten', NULL, 0.5)");
        return db.getRowsModified();
    });
    differential('run with parameters', db => {
        db.run('INSERT INTO t VALUES(?, ?, ?, ?)', [11, 'eleven', null, 0.5]);
        return db.getRowsModified();
    });
    differential('a multi-row UPDATE reports every row', db => {
        db.run('UPDATE t SET name = name');
        return db.getRowsModified();
    });
    differential('a SELECT does not reset the change counter', db => {
        db.run('UPDATE t SET name = name');
        db.exec('SELECT 1');
        return db.getRowsModified();
    });
    differential('run without parameters executes every statement in the script', db => {
        db.run("INSERT INTO t VALUES(20,'a',NULL,0); INSERT INTO t VALUES(21,'b',NULL,0)");
        return db.exec('SELECT count(*) AS c FROM t WHERE id >= 20');
    });
    differential('run returns the database for chaining', db => db.run('SELECT 1') === db);
});

describe('sqljs-shim: prepare and statement', () => {
    differential('getSQL reports only the first statement of a multi-statement string', db => {
        const statement = db.prepare('SELECT 1 AS a; SELECT 2 AS b');
        const sql = statement.getSQL();
        statement.free();
        return sql;
    });
    differential('getSQL keeps leading trivia (worker.js boundary guard depends on it)', db => {
        const statement = db.prepare('  -- lead\n  SELECT 1 AS one');
        const sql = statement.getSQL();
        statement.free();
        return sql;
    });
    differential('a trailing boundary comment survives a single-statement prepare', db => {
        const statement = db.prepare('SELECT 1 AS one\n/*boundary*/');
        const sql = statement.getSQL();
        statement.free();
        return sql.trimEnd().endsWith('/*boundary*/');
    });
    differential('a trailing boundary comment is absent after a multi-statement prepare', db => {
        const statement = db.prepare('SELECT 1; SELECT 2\n/*boundary*/');
        const sql = statement.getSQL();
        statement.free();
        return sql.trimEnd().endsWith('/*boundary*/');
    });
    differential('step/get walks every row', db => {
        const statement = db.prepare('SELECT id, name FROM t ORDER BY id');
        const rows = [];
        while (statement.step()) rows.push(statement.get());
        const columns = statement.getColumnNames();
        statement.free();
        return { rows, columns };
    });
    differential('get(null, {useBigInt}) reads the current row', db => {
        const statement = db.prepare('SELECT id FROM t ORDER BY id DESC LIMIT 1');
        statement.step();
        const row = statement.get(null, { useBigInt: true });
        statement.free();
        return row;
    });
    differential('get before any step is empty', db => {
        const statement = db.prepare('SELECT 1 AS a');
        const row = statement.get();
        statement.free();
        return row;
    });
    differential('getColumnNames answers for a zero-row result', db => {
        const statement = db.prepare('SELECT id AS alpha, name AS beta FROM t WHERE 0');
        const columns = statement.getColumnNames();
        statement.free();
        return columns;
    });
    // The regression that motivated the expanded-text probe: worker.js's table
    // fetch is prepare(sql, params) -> getColumnNames() -> headers, and a zero-
    // match filter left headers empty, which surfaces as "Primary-key column
    // missing from table fetch". A view body cannot contain a parameter, so the
    // probe has to run over the statement's parameter-free expansion.
    differential('getColumnNames answers for a parameterised zero-row table query', db => {
        const statement = db.prepare(
            'SELECT id AS alpha, name AS beta FROM t WHERE name LIKE ?',
            ['no-such-name-%']
        );
        const columns = statement.getColumnNames();
        statement.free();
        return columns;
    });
    differential('getColumnNames answers for a parameterised table query with rows', db => {
        const statement = db.prepare(
            'SELECT id AS alpha, name AS beta FROM t WHERE name LIKE ?',
            ['alpha']
        );
        const columns = statement.getColumnNames();
        const rows = [];
        while (statement.step()) rows.push(statement.get());
        statement.free();
        return { columns, rows };
    });
    differential('getColumnNames answers for a parameterised LIMIT/OFFSET page query', db => {
        const statement = db.prepare(
            'SELECT rowid, id AS alpha, name AS beta FROM t WHERE id > ? ORDER BY id LIMIT ? OFFSET ?',
            [0, 2, 0]
        );
        const columns = statement.getColumnNames();
        statement.free();
        return columns;
    });
    differential('getColumnNames answers for a named-parameter table query', db => {
        const statement = db.prepare(
            'SELECT id AS alpha FROM t WHERE name = :wanted AND id > @floor',
            { ':wanted': 'nothing', '@floor': 0 } as unknown as NativeBindParams
        );
        const columns = statement.getColumnNames();
        statement.free();
        return columns;
    });
    // Unaliased placeholders head their columns as written, with or without
    // rows (the console reads the names before its first step).
    for (const [label, where] of [['zero-row', 'AND 0'], ['with rows', 'LIMIT 1']]) {
        for (const [sql, params] of [
            ['SELECT ? AS a, ?, ? + 1, (+CAST(?3 AS REAL)), id = ?2 AS hit FROM t WHERE ?1 = 1', [1, 2, 3]],
            ['SELECT :x, @y + 1, $z AS z FROM t WHERE :x = 1', { ':x': 1, '@y': 2, '$z': 3 }]
        ] as const) {
            differential(`getColumnNames names unaliased placeholders as written (${label}: ${sql})`, db => {
                const statement = db.prepare(`${sql} ${where}`, params as unknown as NativeBindParams);
                const before = statement.getColumnNames();
                const rows = [];
                while (statement.step()) rows.push(statement.get());
                statement.free();
                return { before, rows };
            });
        }
    }
    // A schema name holding what looks like a probe literal keeps its own
    // name: the probe's literals carry a marker nobody can predict.
    const markerSeed = `CREATE TABLE h (id INTEGER PRIMARY KEY, "'sqlite_explorer_parameter_0'" TEXT,
        "x'sqlite_explorer_parameter_1'y" TEXT); INSERT INTO h VALUES (1, 'p', 'q');`;
    for (const [label, params] of [['zero-row', [5, 6]], ['with rows', [1, 6]]] as const) {
        differential(`getColumnNames keeps schema names that look like probe literals (${label})`, db => {
            const statement = db.prepare('SELECT * FROM h WHERE id = ?1 OR id = ?2', [...params] as unknown as NativeBindParams);
            const before = statement.getColumnNames();
            const rows = [];
            while (statement.step()) rows.push(statement.get());
            statement.free();
            return { before, rows };
        }, { seed: markerSeed });
    }
    it('probes a statement that holds the marker prefix many times over in linear time', () => {
        const column = `sqlite_explorer_parameter_${'x'.repeat(160000)}`;
        const shim = createShim();
        try {
            shim.run(`CREATE TABLE k (id INTEGER PRIMARY KEY, "${column}" TEXT)`);
            const started = performance.now();
            const statement = shim.prepare(`SELECT id, "${column}" FROM k WHERE id = ?`, [1] as unknown as NativeBindParams);
            const columns = statement.getColumnNames();
            statement.free();
            const elapsed = performance.now() - started;
            assert.deepStrictEqual(columns, ['id', column]);
            // Choosing the marker used to grow it one character per match:
            // seconds here. Loose enough for a loaded machine.
            assert.ok(elapsed < 1500, `${Math.round(elapsed)} ms`);
        } finally {
            shim.close();
        }
    });
    it('names placeholder columns when the runtime has no working crypto random source', () => {
        const original = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
        const shim = createShim();
        try {
            for (const stand of [
                { getRandomValues() { throw new Error('no entropy source'); } },
                undefined
            ]) {
                Object.defineProperty(globalThis, 'crypto', { value: stand, configurable: true, writable: true });
                const statement = shim.prepare('SELECT ? AS a, ?, ? + 1', [1, 2, 3] as unknown as NativeBindParams);
                assert.deepStrictEqual(statement.getColumnNames(), ['a', '?', '? + 1'], String(stand));
                statement.free();
            }
        } finally {
            if (original) Object.defineProperty(globalThis, 'crypto', original);
            shim.close();
        }
    });
    differential('exec over a parameterised zero-row table query', db =>
        db.exec('SELECT id AS alpha, name AS beta FROM t WHERE name LIKE ?', ['no-match-%']));
    differential('exec over a parameterised table query with rows', db =>
        db.exec('SELECT id AS alpha, name AS beta FROM t WHERE name LIKE ?', ['alpha']));
    differential('getColumnNames answers before the first step', db => {
        const statement = db.prepare('SELECT id, name FROM t');
        const columns = statement.getColumnNames();
        statement.free();
        return columns;
    });
    differential('getColumnNames is empty for a statement with no result columns', db => {
        const statement = db.prepare("INSERT INTO t VALUES(30,'x',NULL,0)");
        const columns = statement.getColumnNames();
        statement.free();
        return columns;
    });
    differential('step past the end restarts the cursor', db => {
        const statement = db.prepare('SELECT 1 AS a');
        const steps = [statement.step(), statement.step(), statement.step()];
        statement.free();
        return steps;
    });
    differential('statement.run executes DML once', db => {
        const statement = db.prepare("INSERT INTO t VALUES(40,'forty',NULL,0)");
        statement.run();
        statement.free();
        return db.exec('SELECT count(*) AS c FROM t WHERE id = 40');
    });
    differential('statement.run binds its argument', db => {
        const statement = db.prepare('INSERT INTO t VALUES(?,?,?,?)');
        statement.run([41, 'forty-one', null, 0]);
        statement.free();
        return db.exec('SELECT name FROM t WHERE id = 41');
    });
    differential('prepare accepts parameters up front', db => {
        const statement = db.prepare('SELECT ? AS bound', [3]);
        statement.step();
        const row = statement.get();
        statement.free();
        return row;
    });
    differential('double free is tolerated', db => {
        const statement = db.prepare('SELECT 1');
        statement.free();
        statement.free();
        return 'survived';
    });
    differential('use after free throws', db => {
        const statement = db.prepare('SELECT 1');
        statement.free();
        return statement.step();
    });
    differential('prepare of trivia-only SQL throws', db => db.prepare('-- nothing'));
    differential('use after close throws', db => {
        db.close();
        return db.exec('SELECT 1');
    });
});

describe('sqljs-shim: metadata never causes side effects', () => {
    /**
     * These assert the SIDE EFFECT, not the return value. An earlier revision
     * passed every return-value assertion while silently executing a prepared
     * INSERT the moment its column names were asked for — sql.js reads
     * sqlite3_column_count off the compiled statement and runs nothing.
     */
    const countRows = (db: SqlJsLike, id: number) =>
        normalize(db.exec('SELECT count(*) AS c FROM t WHERE id = ?', [id]));

    differential('getColumnNames on a prepared INSERT does not run it', db => {
        const statement = db.prepare("INSERT INTO t VALUES(60,'sixty',NULL,0)");
        const columns = statement.getColumnNames();
        statement.free();
        return { columns, rowsAfter: countRows(db, 60) };
    });
    differential('getColumnNames on a prepared UPDATE does not run it', db => {
        const statement = db.prepare("UPDATE t SET name = 'clobbered'");
        const columns = statement.getColumnNames();
        statement.free();
        return { columns, names: normalize(db.exec('SELECT name FROM t ORDER BY id')) };
    });
    differential('getColumnNames on a prepared DELETE does not run it', db => {
        const statement = db.prepare('DELETE FROM t');
        const columns = statement.getColumnNames();
        statement.free();
        return { columns, remaining: normalize(db.exec('SELECT count(*) AS c FROM t')) };
    });
    differential('getColumnNames on a prepared DDL statement does not run it', db => {
        const statement = db.prepare('CREATE TABLE created_by_metadata(a)');
        const columns = statement.getColumnNames();
        statement.free();
        return {
            columns,
            exists: normalize(db.exec(
                "SELECT count(*) AS c FROM sqlite_master WHERE name = 'created_by_metadata'"
            ))
        };
    });
    differential('get() before any step does not run the statement', db => {
        const statement = db.prepare("INSERT INTO t VALUES(61,'sixty-one',NULL,0)");
        const row = statement.get();
        statement.free();
        return { row, rowsAfter: countRows(db, 61) };
    });
    differential('the column probe does not disturb the change counter', db => {
        db.run("INSERT INTO t VALUES(62,'sixty-two',NULL,0)");
        const statement = db.prepare('SELECT id FROM t WHERE 0');
        statement.getColumnNames();
        statement.free();
        return db.getRowsModified();
    });
    differential('the column probe does not disturb schema_version', db => {
        const before = normalize(db.exec('PRAGMA schema_version'));
        const statement = db.prepare('SELECT id AS alpha FROM t WHERE name LIKE ?', ['x%']);
        statement.getColumnNames();
        statement.free();
        return { before, after: normalize(db.exec('PRAGMA schema_version')) };
    });
    differential('a parameterised page query executes exactly once', db => {
        // The names pass used to materialise, so every filtered page ran twice.
        // total_changes is engine-visible proof for the write case; for reads,
        // a one-shot side effect is easier: count executions of a statement that
        // mutates on every run.
        db.run('CREATE TABLE exec_probe(n INTEGER)');
        const statement = db.prepare(
            'INSERT INTO exec_probe VALUES(?) RETURNING n',
            [1]
        );
        statement.getColumnNames();
        while (statement.step()) { /* drain */ }
        statement.free();
        return normalize(db.exec('SELECT count(*) AS runs FROM exec_probe'));
    });
});

describe('sqljs-shim: iterateStatements', () => {
    /** Drive an iterator exactly as worker.js's console does, recording the tail at each step. */
    const walk = (sql: string) => (db: SqlJsLike) => {
        const iterator = db.iterateStatements(sql);
        const steps: unknown[] = [];
        try {
            for (;;) {
                const step = iterator.next();
                if (step.done) {
                    // The tail is deliberately NOT compared here: sql.js reads a
                    // freed pointer once its iterator is done and reports ''
                    // or stray bytes. The tail after each YIELDED statement --
                    // the value worker.js's console actually consumes -- is
                    // compared below, and the post-completion behaviour is
                    // pinned in "documented divergences".
                    steps.push({ done: true });
                    break;
                }
                const statement = step.value;
                steps.push({
                    sql: statement.getSQL(),
                    columns: statement.getColumnNames(),
                    remaining: iterator.getRemainingSQL()
                });
                statement.free();
            }
        } catch (error) {
            steps.push({ threw: errorText(error), remaining: iterator.getRemainingSQL() });
        }
        return steps;
    };

    differential('two statements, tail after each', walk('SELECT 1 AS a; SELECT 2 AS b'));
    differential('trailing semicolon', walk('SELECT 1 AS a; SELECT 2 AS b;'));
    differential('trailing comment trivia', walk('SELECT 1 AS a; -- trailing comment'));
    differential('trailing whitespace', walk('SELECT 1 AS a;   '));
    differential('a leading semicolon belongs to the next statement', walk('; SELECT 1 AS a'));
    differential('an empty statement between two real ones', walk('SELECT 1 AS a;; SELECT 2 AS b'));
    differential('trivia only yields nothing', walk('  -- only a comment'));
    differential('semicolon inside a string literal', walk("SELECT ';' AS semi; SELECT 2 AS b"));
    differential('semicolon inside a quoted identifier',
        walk('SELECT 1 AS "semi;colon"; SELECT 2 AS b'));
    differential('a compile error stops iteration and the tail names the failure',
        walk('SELECT 1 AS a; SELEC bad; SELECT 3 AS c'));
    differential('a trigger body\'s internal semicolons are not boundaries', db => {
        db.run('CREATE TABLE tg(a)');
        return walk(
            'CREATE TRIGGER tr AFTER INSERT ON tg BEGIN UPDATE tg SET a=1; END; SELECT 1 AS after'
        )(db);
    });
    // Parameters make the compiled statement text diverge from its source
    // (`?` renders as NULL), which is exactly the case consumedSourceLength's
    // resynchronising walk exists for.
    differential('placeholders do not shift the statement boundary',
        walk('SELECT ? AS p; SELECT 2 AS q'));
    differential('named placeholders do not shift the statement boundary',
        walk('SELECT :name AS p, @other AS o, $third AS t; SELECT 2 AS q'));
    differential('a placeholder in the final statement',
        walk('SELECT 1 AS a; SELECT ?1 AS first, ?2 AS p'));
    differential('placeholders in a statement that reads a table',
        walk('SELECT id AS a FROM t WHERE name LIKE ?; SELECT 2 AS q'));
});

describe('sqljs-shim: error surfaces', () => {
    differentialThrows('syntax error', db => db.exec('SELEC 1'), 1);
    differentialThrows('no such table', db => db.exec('SELECT * FROM nope'), 1);
    differentialThrows('UNIQUE violation', db => db.run("INSERT INTO u VALUES(1, 'y')"), 19);
    differentialThrows('NOT NULL violation', db => db.run('INSERT INTO u VALUES(2, NULL)'), 19);

    /**
     * The stand-in is node:sqlite, which DOES report `sqlite3_errmsg`, so these
     * assert the honesty gate from the side the fork cannot reach: a specific
     * message must survive untouched. The enrichment itself is proven against
     * the real binary (`npm run native-lane` / the probe recorded in the wave-2
     * report) and unit-tested in tests/unit/sqlite_errors.test.ts.
     */
    it('leaves a binding that reports a real SQLite message alone', () => {
        const shim = createShim();
        try {
            shim.run(SEED_SQL);
            for (const [sql, pattern] of [
                ['SELECT * FROM nope', /no such table: nope/],
                ['SELECT nope FROM t', /no such column: nope/],
                ["INSERT INTO u VALUES(2, NULL)", /NOT NULL constraint failed/]
            ] as [string, RegExp][]) {
                assert.throws(() => shim.exec(sql), (error: unknown) => {
                    const message = (error as Error).message;
                    assert.match(message, pattern);
                    assert.doesNotMatch(message, /SQLITE_/, `enriched a specific message: ${message}`);
                    return true;
                });
            }
        } finally {
            shim.close();
        }
    });

    it('enriches a nonspecific message and keeps its errno', () => {
        // Forces the fork's shape onto the stand-in: canonical errstr text with
        // the primary result code, which is exactly what the real binary hands
        // back for every SQLITE_ERROR.
        type BackingDatabase = {
            prepare(sql: string): unknown;
            exec(sql: string): unknown;
            close(): void;
        };
        const Backing = standInSqliteModule.Database as unknown as
            new (...ctorArgs: unknown[]) => BackingDatabase;
        const forkShaped = {
            Database: class {
                #inner: BackingDatabase;
                constructor(...args: unknown[]) {
                    this.#inner = new Backing(...args);
                }
                prepare(sql: string) {
                    try {
                        return this.#inner.prepare(sql);
                    } catch (error) {
                        const replacement = new Error('SQL logic error');
                        Object.defineProperty(replacement, 'errno', {
                            value: (error as { errno?: number }).errno ?? 1,
                            enumerable: false
                        });
                        throw replacement;
                    }
                }
                exec(sql: string) { return this.#inner.exec(sql); }
                close() { this.#inner.close(); }
            }
        };
        const shim = createShimDatabase({}, { sqlite: forkShaped as never });
        try {
            shim.run(SEED_SQL);
            // Proven missing table: SQLite's own phrasing, recovered.
            assert.throws(() => shim.exec('SELECT * FROM absent_table'), (error: unknown) => {
                assert.equal((error as Error).message, 'no such table: absent_table');
                assert.equal((error as { errno?: number }).errno, 1, 'errno must survive the rewrite');
                return true;
            });
            // Nothing provable: the class, plus why the engine cannot say more.
            assert.throws(() => shim.exec('SELECT nope FROM t'), (error: unknown) => {
                assert.match((error as Error).message, /^SQL logic error \(SQLITE_ERROR: /);
                assert.equal((error as { errno?: number }).errno, 1);
                return true;
            });
            // A name that exists is never accused.
            assert.throws(() => shim.exec('SELECT * FROM t WHERE'), (error: unknown) => {
                assert.doesNotMatch((error as Error).message, /no such table/);
                return true;
            });
            // A view whose base table was dropped is in the catalog, so the
            // view is never accused — the proof walks into its stored body and
            // names the table it lost instead. This is also how the view
            // editor's own failures stay actionable: it validates through the
            // installed view, whose name is all the failing statement carries.
            shim.run('CREATE TABLE gone (v); CREATE VIEW over_gone AS SELECT v FROM gone; DROP TABLE gone');
            assert.throws(() => shim.exec('SELECT * FROM over_gone'), (error: unknown) => {
                assert.equal((error as Error).message, 'no such table: gone');
                assert.equal((error as { errno?: number }).errno, 1);
                return true;
            });
            assert.throws(() => shim.exec('EXPLAIN SELECT * FROM main."over_gone"'), (error: unknown) => {
                assert.equal((error as Error).message, 'no such table: gone');
                return true;
            });
        } finally {
            shim.close();
        }
    });

    it('a statement-level failure carries errno', () => {
        const shim = createShim();
        try {
            shim.run(SEED_SQL);
            const statement = shim.prepare('INSERT INTO u VALUES(1, ?)');
            assert.throws(() => statement.run(['dup']), (error: unknown) => {
                assert.strictEqual((error as { errno?: number }).errno, 19);
                return true;
            });
            statement.free();
        } finally {
            shim.close();
        }
    });
});

describe('sqljs-shim: ATTACH/DETACH is blocked at the compile chokepoint', () => {
    const isBlock = (error: unknown) => {
        const e = error as { code?: string; errno?: number };
        assert.strictEqual(e.code, NATIVE_SQL_ATTACH_BLOCKED);
        // A shim policy, not a SQLite result code: no errno.
        assert.strictEqual(e.errno, undefined);
        return true;
    };

    // Every path into raw SQL must reject, since compileNext is shared by all.
    it('rejects a leading ATTACH through exec/prepare/iterateStatements', () => {
        const shim = createShim();
        try {
            const attach = "ATTACH DATABASE '/tmp/x.sqlite' AS steal";
            assert.throws(() => shim.exec(attach), isBlock);
            assert.throws(() => shim.prepare(attach), isBlock);
            assert.throws(() => shim.iterateStatements(attach).next(), isBlock);
        } finally {
            shim.close();
        }
    });

    it('rejects DETACH', () => {
        const shim = createShim();
        try {
            assert.throws(() => shim.exec('DETACH DATABASE steal'), isBlock);
        } finally {
            shim.close();
        }
    });

    // The no-param run() path hands the whole string to backing.exec, bypassing
    // compileNext — the shim scans it separately. A leading ATTACH in the SECOND
    // statement must still be caught, and nothing before it must persist.
    it('rejects ATTACH in a no-param run() script and applies nothing', () => {
        const shim = createShim();
        try {
            shim.run('CREATE TABLE g(n)');
            assert.throws(
                () => shim.run("INSERT INTO g VALUES(1); ATTACH DATABASE '/tmp/x.sqlite' AS steal"),
                isBlock
            );
            // backing.exec never ran because the scan threw first: the INSERT did
            // not persist.
            assert.deepStrictEqual(shim.exec('SELECT count(*) AS c FROM g')[0].values, [[0]]);
        } finally {
            shim.close();
        }
    });

    it('sees through leading trivia and mixed case', () => {
        const shim = createShim();
        try {
            assert.throws(() => shim.exec("/* c */ AtTaCh DATABASE '/tmp/x.sqlite' AS s"), isBlock);
            assert.throws(() => shim.exec("  \n-- note\n  detach database s"), isBlock);
        } finally {
            shim.close();
        }
    });

    it('does not block the word attach inside a string literal or identifier', () => {
        const shim = createShim();
        try {
            assert.deepStrictEqual(shim.exec("SELECT 'attach me' AS a")[0].values, [['attach me']]);
            shim.run('CREATE TABLE "attachment"(id)');
            shim.run('INSERT INTO "attachment" VALUES (1)');
            assert.deepStrictEqual(shim.exec('SELECT id FROM "attachment"')[0].values, [[1]]);
        } finally {
            shim.close();
        }
    });
});

describe('sqljs-shim: VACUUM INTO is blocked, plain VACUUM is not', () => {
    const isBlock = (error: unknown) => {
        const e = error as { code?: string; errno?: number };
        assert.strictEqual(e.code, NATIVE_SQL_VACUUM_INTO_BLOCKED);
        assert.strictEqual(e.errno, undefined);
        return true;
    };

    // Every INTO form, through every raw-SQL path. The INTO clause is detected
    // in the single statement's own source, after compile / before step.
    it('rejects every VACUUM ... INTO form across exec/prepare/iterateStatements', () => {
        const shim = createShim();
        try {
            for (const sql of [
                "VACUUM INTO '/tmp/x.db'",
                "VACUUM main INTO '/tmp/x.db'",
                'VACUUM INTO ?',
                "VACUUM /* c */ INTO '/tmp/x.db'"  // comment injection cannot hide the INTO token
            ]) {
                assert.throws(() => shim.exec(sql), isBlock, sql);
                assert.throws(() => shim.prepare(sql), isBlock, sql);
                assert.throws(() => shim.iterateStatements(sql).next(), isBlock, sql);
            }
        } finally {
            shim.close();
        }
    });

    it('rejects VACUUM INTO in a no-param run() script and applies nothing', () => {
        const shim = createShim();
        try {
            shim.run('CREATE TABLE g(n)');
            assert.throws(
                () => shim.run("INSERT INTO g VALUES(1); VACUUM INTO '/tmp/x.db'"),
                isBlock
            );
            assert.deepStrictEqual(shim.exec('SELECT count(*) AS c FROM g')[0].values, [[0]]);
        } finally {
            shim.close();
        }
    });

    it('allows plain VACUUM and VACUUM main (in place)', () => {
        const shim = createShim();
        try {
            shim.run('CREATE TABLE t(a); INSERT INTO t VALUES(1),(2)');
            assert.doesNotThrow(() => shim.exec('VACUUM'));
            assert.doesNotThrow(() => shim.exec('VACUUM main'));
            // Data survives the in-place rebuild.
            assert.deepStrictEqual(shim.exec('SELECT count(*) AS c FROM t')[0].values, [[2]]);
        } finally {
            shim.close();
        }
    });

    it('scopes the INTO check to the current statement, not a later one', () => {
        // A plain VACUUM followed by a statement that legitimately contains
        // `into` must not false-trip: each statement is checked on its own.
        const shim = createShim();
        try {
            shim.run('CREATE TABLE t(a)');
            assert.doesNotThrow(() => shim.exec("VACUUM; SELECT 'into' AS x"));
        } finally {
            shim.close();
        }
    });

    it('is not over-broad: the phrase in a literal, and vacuum-prefixed names, are fine', () => {
        const shim = createShim();
        try {
            assert.deepStrictEqual(shim.exec("SELECT 'vacuum into' AS a")[0].values, [['vacuum into']]);
            // A table name starting with "vacuum" is not the VACUUM keyword
            // (no word boundary), and its "into"-containing column is untouched.
            shim.run('CREATE TABLE vacuumlog(into_count)');
            shim.run('INSERT INTO vacuumlog VALUES (1)');
            assert.deepStrictEqual(shim.exec('SELECT into_count FROM vacuumlog')[0].values, [[1]]);
        } finally {
            shim.close();
        }
    });

    it('does not interfere with the shim export path (its own VACUUM INTO)', () => {
        // export() issues VACUUM INTO through backing.prepare directly, NOT
        // through compileNext, so the guard must leave it working.
        const shim = createShim();
        try {
            shim.run('CREATE TABLE t(a); INSERT INTO t VALUES(1),(2),(3)');
            const bytes = shim.export();
            assert.strictEqual(
                String.fromCharCode(...bytes.subarray(0, 15)),
                'SQLite format 3'
            );
        } finally {
            shim.close();
        }
    });
});

describe('sqljs-shim: statement boundary alignment', () => {
    it('returns the compiled length when the source has no parameters', () => {
        assert.strictEqual(consumedSourceLength('SELECT 1; SELECT 2', 'SELECT 1;'), 9);
    });
    it('resynchronises across an unbound positional parameter', () => {
        assert.strictEqual(
            consumedSourceLength('SELECT ? AS v; rest', 'SELECT NULL AS v;'),
            14
        );
    });
    it('resynchronises across numbered and named parameters', () => {
        assert.strictEqual(
            consumedSourceLength('SELECT ?12, :name, @a, $b; rest', 'SELECT NULL, NULL, NULL, NULL;'),
            'SELECT ?12, :name, @a, $b;'.length
        );
    });
    it('does not mistake a question mark inside a literal for a parameter', () => {
        assert.strictEqual(consumedSourceLength("SELECT '?' AS v;", "SELECT '?' AS v;"), 16);
    });
    it('reports failure rather than guessing when the texts cannot be aligned', () => {
        assert.strictEqual(consumedSourceLength('SELECT 1', 'TOTALLY DIFFERENT'), -1);
    });
});

describe('sqljs-shim: native-only behaviour', () => {
    const withFileDatabase = (body: (file: string) => void) => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqljs-shim-db-'));
        try {
            const file = path.join(dir, 'fixture.sqlite');
            const seeded = createShim({ path: file });
            seeded.run(SEED_SQL);
            seeded.close();
            body(file);
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    };

    it('opens a file by path without inhaling its bytes', () => {
        withFileDatabase(file => {
            const db = createShim({ path: file });
            try {
                assert.deepStrictEqual(
                    normalize(db.exec('SELECT count(*) AS c FROM t')),
                    [{ columns: ['c'], values: [[3]] }]
                );
            } finally {
                db.close();
            }
        });
    });

    it('changes journal_mode to WAL and back through the worker-shaped PRAGMA path, durably', () => {
        // The desktop's Configuration modal drives setPragma, which prepares
        // and runs exactly `PRAGMA journal_mode = '<value>'` as one statement
        // (worker.js runSingleStatement); the sidecar-lane case in
        // scripts/lib/native-sidecar-lane.mjs runs the same round trip against
        // the shipped binary. Here the stand-in is real SQLite on a real file,
        // so the -wal/-shm sidecars and the durability across a reopen are the
        // engine's own behaviour, not a mock's.
        const journalMode = (db: ShimDatabase) => db.exec('PRAGMA journal_mode')[0].values[0][0];
        const setJournalMode = (db: ShimDatabase, mode: string) => {
            const statement = db.prepare(`PRAGMA journal_mode = '${mode}'`);
            try {
                statement.run();
            } finally {
                statement.free();
            }
        };
        withFileDatabase(file => {
            const db = createShim({ path: file });
            try {
                assert.strictEqual(journalMode(db), 'delete');
                setJournalMode(db, 'WAL');
                assert.strictEqual(journalMode(db), 'wal');
                db.run("INSERT INTO t VALUES (10, 'wal', NULL, 0.0)");
                assert.ok(fs.existsSync(`${file}-wal`), 'a write in WAL mode must materialise the -wal sidecar');
                assert.ok(fs.statSync(`${file}-wal`).size > 0);
                // TRUNCATE resets the log before the counters are read, so a
                // successful checkpoint reports zero frames and an empty -wal.
                assert.deepStrictEqual(
                    normalize(db.exec('PRAGMA wal_checkpoint(TRUNCATE)')),
                    [{ columns: ['busy', 'log', 'checkpointed'], values: [[0, 0, 0]] }]
                );
                assert.strictEqual(fs.statSync(`${file}-wal`).size, 0);
                // Inside a transaction (the desktop's session transaction on a
                // dirty database) SQLite refuses the switch and the mode stays.
                db.run('BEGIN');
                db.exec('SELECT count(*) FROM t');
                assert.throws(() => setJournalMode(db, 'DELETE'), /within a transaction|SQL logic error/i);
                assert.strictEqual(journalMode(db), 'wal');
                db.run('ROLLBACK');
                setJournalMode(db, 'DELETE');
                assert.strictEqual(journalMode(db), 'delete');
                assert.ok(!fs.existsSync(`${file}-wal`) && !fs.existsSync(`${file}-shm`),
                    'leaving WAL must remove both sidecar files');
            } finally {
                db.close();
            }
            const reopened = createShim({ path: file });
            try {
                assert.strictEqual(journalMode(reopened), 'delete');
                assert.deepStrictEqual(
                    normalize(reopened.exec('SELECT count(*) AS c FROM t')),
                    [{ columns: ['c'], values: [[4]] }]
                );
            } finally {
                reopened.close();
            }
        });
    });

    it('a readOnly open refuses writes with SQLITE_READONLY', () => {
        withFileDatabase(file => {
            const db = createShim({ path: file, readOnly: true });
            try {
                assert.throws(
                    () => db.run("INSERT INTO t VALUES(99,'no',NULL,0)"),
                    (error: unknown) => {
                        assert.strictEqual((error as { errno?: number }).errno, 8);
                        return true;
                    }
                );
                // Enforcement is a connection flag, not a trusted open option:
                // the fork silently ignores a mis-cased `readonly` key, so the
                // shim arms PRAGMA query_only and verifies it.
                assert.deepStrictEqual(
                    normalize(db.exec('PRAGMA query_only')),
                    [{ columns: ['query_only'], values: [[1]] }]
                );
            } finally {
                db.close();
            }
        });
    });

    it('a readOnly connection still answers column names for a zero-row query', () => {
        withFileDatabase(file => {
            const db = createShim({ path: file, readOnly: true });
            try {
                const statement = db.prepare('SELECT id AS alpha, name AS beta FROM t WHERE 0');
                assert.deepStrictEqual(statement.getColumnNames(), ['alpha', 'beta']);
                statement.free();
                // The probe lifts query_only only for its own TEMP VIEW and puts it back.
                assert.deepStrictEqual(
                    normalize(db.exec('PRAGMA query_only')),
                    [{ columns: ['query_only'], values: [[1]] }]
                );
            } finally {
                db.close();
            }
        });
    });

    // -----------------------------------------------------------------------
    // Escalating an OPEN writable session to read-only.
    //
    // Found live: a database in a read-only DIRECTORY (and equally a 0444 file)
    // opens writable, the worker's open-time write probe finds it unwritable,
    // and the worker used to arm `PRAGMA query_only` itself. That left the
    // shim's own readOnly flag false, so its column probe never lifted the
    // pragma, SQLite refused the probe's CREATE TEMP VIEW as a write, the
    // refusal was swallowed into "no columns" — and every grid on such a
    // database rendered "Cell containment requires a positive column count,
    // got 0" instead of rows.
    // -----------------------------------------------------------------------

    it('enforceReadOnly() arms query_only AND keeps the column probe working', () => {
        withFileDatabase(file => {
            const db = createShim({ path: file });
            try {
                assert.strictEqual(db.enforceReadOnly(), true);
                assert.deepStrictEqual(
                    normalize(db.exec('PRAGMA query_only')),
                    [{ columns: ['query_only'], values: [[1]] }]
                );
                assert.throws(() => db.run("INSERT INTO t VALUES(99,'no',NULL,0)"),
                    (error: unknown) => (error as { errno?: number }).errno === 8);

                // The column probe is the half that used to break: it needs its
                // TEMP VIEW, which query_only refuses, so the escalation has to
                // have moved the shim's own read-only flag as well as SQLite's.
                const statement = db.prepare('SELECT id AS alpha, name AS beta FROM t WHERE 0');
                assert.deepStrictEqual(statement.getColumnNames(), ['alpha', 'beta']);
                statement.free();
                // …and the lift was put back.
                assert.deepStrictEqual(
                    normalize(db.exec('PRAGMA query_only')),
                    [{ columns: ['query_only'], values: [[1]] }]
                );

                // Idempotent: a second escalation is a no-op, not an error.
                assert.strictEqual(db.enforceReadOnly(), true);
            } finally {
                db.close();
            }
        });
    });

    it('arming query_only BEHIND the shim is reported, not swallowed into "no columns"', () => {
        withFileDatabase(file => {
            const db = createShim({ path: file });
            try {
                // Exactly what the worker used to do — and what any future
                // caller reaching past enforceReadOnly() would do.
                db.run('PRAGMA query_only = ON');
                const statement = db.prepare('SELECT id AS alpha FROM t WHERE 0');
                assert.throws(
                    () => statement.getColumnNames(),
                    (error: unknown) => {
                        const message = (error as Error).message;
                        // Names the mechanism and the fix, rather than
                        // answering [] and letting the caller's own invariant
                        // check fail three layers away with no cause in it.
                        assert.match(message, /query_only/);
                        assert.match(message, /enforceReadOnly/);
                        assert.strictEqual((error as { errno?: number }).errno, 8);
                        return true;
                    }
                );
                statement.free();
            } finally {
                db.close();
            }
        });
    });

    it('the query_only report does not fire for statements that were never viewable', () => {
        withFileDatabase(file => {
            const db = createShim({ path: file });
            try {
                db.run('PRAGMA query_only = ON');
                // SQLite refuses the probe's CREATE for being a WRITE before it
                // looks at the body, so a PRAGMA takes errno 8 here exactly like
                // a SELECT does. It must still fall through to "[]", which was
                // always the right answer for it — the report is only for
                // statements whose columns a caller would have relied on.
                const pragma = db.prepare('PRAGMA user_version');
                assert.deepStrictEqual(pragma.getColumnNames(), []);
                pragma.free();

                const dml = db.prepare("UPDATE t SET name = 'x' WHERE id = 1");
                assert.deepStrictEqual(dml.getColumnNames(), []);
                dml.free();
            } finally {
                db.close();
            }
        });
    });

    it('a statement that is genuinely not viewable still falls through quietly', () => {
        // The un-swallow above must stay narrow: DML/DDL/PRAGMA cannot be a view
        // body, and "no columns" is the correct answer for them — the ladder's
        // documented rung 4, not a hidden failure.
        const db = createShim();
        try {
            db.run(SEED_SQL);
            const statement = db.prepare("UPDATE t SET name = 'x' WHERE id = 1");
            assert.deepStrictEqual(statement.getColumnNames(), []);
            statement.free();
        } finally {
            db.close();
        }
    });

    it('export() produces a readable image with the same contents', () => {
        const db = createShim();
        try {
            db.run(SEED_SQL);
            const bytes = db.export();
            assert.ok(bytes instanceof Uint8Array);
            assert.strictEqual(
                Buffer.from(bytes.subarray(0, 15)).toString('latin1'),
                'SQLite format 3'
            );
            const reference = new SQL.Database(bytes);
            try {
                assert.deepStrictEqual(
                    normalize(reference.exec('SELECT count(*) AS c FROM t')),
                    [{ columns: ['c'], values: [[3]] }]
                );
            } finally {
                reference.close();
            }
        } finally {
            db.close();
        }
    });

    it('exportAsync() matches export()', async () => {
        const db = createShim();
        try {
            db.run(SEED_SQL);
            const asyncBytes = await db.exportAsync();
            const syncBytes = db.export();
            assert.deepStrictEqual(Array.from(asyncBytes), Array.from(syncBytes));
        } finally {
            db.close();
        }
    });

    it('export() from a readOnly connection works (VACUUM INTO writes only its output)', () => {
        withFileDatabase(file => {
            const db = createShim({ path: file, readOnly: true });
            try {
                const bytes = db.export();
                assert.ok(bytes.length > 0);
            } finally {
                db.close();
            }
        });
    });

    it('exportToPath() lands a valid reopenable image reflecting live mutations', async () => {
        const db = createShim();
        try {
            db.run(SEED_SQL);
            // Mutation AFTER the seed: the exported image must carry it, proving
            // exportToPath snapshots the live database, not stale state.
            db.run("INSERT INTO t VALUES (42, 'mutation-check', NULL, 9.75)");
            const target = path.join(nodeFileSystem.makeTempDir(), 'export-to-path.sqlite');
            await db.exportToPath(target);
            const bytes = new Uint8Array(fs.readFileSync(target));
            assert.strictEqual(
                Buffer.from(bytes.subarray(0, 15)).toString('latin1'),
                'SQLite format 3'
            );
            const reference = new SQL.Database(bytes);
            try {
                assert.deepStrictEqual(
                    normalize(reference.exec('SELECT name FROM t WHERE id = 42')),
                    [{ columns: ['name'], values: [['mutation-check']] }]
                );
                assert.deepStrictEqual(
                    normalize(reference.exec('SELECT count(*) AS c FROM t')),
                    [{ columns: ['c'], values: [[4]] }]
                );
            } finally {
                reference.close();
            }
        } finally {
            db.close();
        }
    });

    it('exportToPath() refuses an existing target (VACUUM INTO fails closed)', async () => {
        const db = createShim();
        try {
            db.run(SEED_SQL);
            const target = path.join(nodeFileSystem.makeTempDir(), 'planted');
            fs.writeFileSync(target, 'planted');
            // The exact message depends on the target's content and the SQLite
            // build ("output file already exists" vs "file is not a database");
            // the invariant is: it throws and the planted file is untouched.
            await assert.rejects(db.exportToPath(target), /already exists|not a database/);
            assert.strictEqual(fs.readFileSync(target, 'utf8'), 'planted', 'planted file untouched');
        } finally {
            db.close();
        }
    });

    it('exportToPath() rejects a non-string target structurally', async () => {
        const db = createShim();
        try {
            db.run(SEED_SQL);
            await assert.rejects(
                db.exportToPath(undefined as unknown as string),
                /non-empty target path/
            );
            await assert.rejects(db.exportToPath(''), /non-empty target path/);
        } finally {
            db.close();
        }
    });

    it('exportToPath() from a readOnly connection works (writes only its output)', async () => {
        // Not withFileDatabase: its callback is synchronous and this body awaits.
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqljs-shim-db-'));
        try {
            const file = path.join(dir, 'fixture.sqlite');
            const seeded = createShim({ path: file });
            seeded.run(SEED_SQL);
            seeded.close();
            const db = createShim({ path: file, readOnly: true });
            try {
                const target = path.join(dir, 'ro-export.sqlite');
                await db.exportToPath(target);
                assert.ok(fs.statSync(target).size > 0);
            } finally {
                db.close();
            }
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('exportToPath() after close rejects', async () => {
        const db = createShim();
        db.run(SEED_SQL);
        db.close();
        await assert.rejects(
            db.exportToPath(path.join(os.tmpdir(), 'never-written.sqlite')),
            /Database closed/
        );
    });

    it('rejects opening from bytes', () => {
        assert.throws(
            () => createShim({ content: new Uint8Array([1, 2, 3]) }),
            /opening from bytes is not supported/
        );
    });

    it('requires a backing sqlite module', () => {
        assert.throws(
            () => createShimDatabase({}, {} as never),
            /requires deps\.sqlite\.Database/
        );
    });

    it('export() without filesystem hooks fails loudly', () => {
        const db = createShimDatabase({}, { sqlite: standInSqliteModule });
        try {
            assert.throws(() => db.export(), /requires deps\.fs/);
        } finally {
            db.close();
        }
    });

    it('inTransaction tracks an explicit transaction', () => {
        const db = createShim();
        try {
            assert.strictEqual(db.inTransaction, false);
            db.run('BEGIN');
            assert.strictEqual(db.inTransaction, true);
            db.run('ROLLBACK');
            assert.strictEqual(db.inTransaction, false);
        } finally {
            db.close();
        }
    });

    it('close is idempotent and frees outstanding statements', () => {
        const db = createShim();
        db.run(SEED_SQL);
        const statement = db.prepare('SELECT 1');
        db.close();
        db.close();
        assert.throws(() => statement.step(), /Statement closed/);
    });

    it('the column probe leaves no temp view behind', () => {
        const db = createShim();
        try {
            db.run(SEED_SQL);
            for (let attempt = 0; attempt < 3; attempt += 1) {
                const statement = db.prepare('SELECT id AS alpha FROM t WHERE id > ?', [0]);
                statement.getColumnNames();
                statement.free();
            }
            assert.deepStrictEqual(
                normalize(db.exec(
                    "SELECT count(*) AS c FROM temp.sqlite_master WHERE name LIKE '_sqlx_shim_cols_%'"
                )),
                [{ columns: ['c'], values: [[0]] }]
            );
        } finally {
            db.close();
        }
    });

    it('a cleanup failure is reported, not swallowed, and does not fail the caller', () => {
        const failures: string[] = [];
        const db = createShimDatabase({}, {
            sqlite: standInSqliteModule,
            fs: {
                makeTempDir: nodeFileSystem.makeTempDir,
                readFile: nodeFileSystem.readFile,
                remove: () => {
                    throw new Error('remove refused');
                }
            },
            onCleanupFailure: (_error, context) => failures.push(context)
        });
        try {
            db.run(SEED_SQL);
            const bytes = db.export();
            assert.ok(bytes.length > 0, 'the export itself still succeeds');
            assert.deepStrictEqual(failures, ['remove export temp directory']);
        } finally {
            db.close();
        }
    });

    it('a lost read-only guarantee quarantines the whole connection', () => {
        // Poison is set when `PRAGMA query_only = 1` cannot be restored after an
        // internal lift. Every route back into the connection must then fail
        // with THAT error -- in particular the column probe, whose blanket catch
        // would otherwise report a lost read-only guarantee as "no columns".
        let armed = false;
        const execLog: string[] = [];
        interface BackingDatabase {
            exec(sql: string): void;
            prepare(sql: string): unknown;
            close(): void;
        }
        const BackingDatabaseCtor = standInSqliteModule.Database as unknown as new (
            path?: string,
            options?: Record<string, unknown>
        ) => BackingDatabase;
        const brittleSqlite = {
            Database: class {
                #inner: BackingDatabase;
                constructor(path?: string, options?: Record<string, unknown>) {
                    this.#inner = new BackingDatabaseCtor(path, options);
                }
                exec(sql: string) {
                    execLog.push(sql);
                    if (armed && sql === 'PRAGMA query_only = 1') {
                        throw new Error('simulated restore failure');
                    }
                    this.#inner.exec(sql);
                }
                prepare(sql: string) {
                    return this.#inner.prepare(sql);
                }
                close() {
                    this.#inner.close();
                }
            }
        };

        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqljs-shim-poison-'));
        try {
            const file = path.join(dir, 'fixture.sqlite');
            const seeded = createShim({ path: file });
            seeded.run(SEED_SQL);
            seeded.close();

            const db = createShimDatabase(
                { path: file, readOnly: true },
                { sqlite: brittleSqlite as never, fs: nodeFileSystem }
            );
            try {
                const statement = db.prepare('SELECT id AS alpha FROM t WHERE 0');
                // Arm the failure only now: the constructor's own arming call
                // must succeed, or there would be no read-only connection to lose.
                armed = true;

                // The probe lifts query_only, fails to restore it, and must
                // surface that rather than degrade to "not viewable".
                const execCountAtPoison = execLog.length;
                assert.throws(() => statement.getColumnNames(), /no longer trustworthy/);

                // Writes are never re-enabled on a connection whose query_only
                // state is already unknown: the failed lift is the last one.
                assert.deepStrictEqual(
                    execLog.slice(execCountAtPoison).filter(sql => sql === 'PRAGMA query_only = 0'),
                    ['PRAGMA query_only = 0'],
                    'exactly the one lift that poisoned the connection, and no re-lift after it'
                );

                // Every other route in is closed too: statement methods...
                assert.throws(() => statement.step(), /no longer trustworthy/);
                assert.throws(() => statement.get(), /no longer trustworthy/);
                statement.free();
                // ...database methods...
                assert.throws(() => db.exec('SELECT 1'), /no longer trustworthy/);
                assert.throws(() => db.prepare('SELECT 1'), /no longer trustworthy/);
                assert.throws(() => db.getRowsModified(), /no longer trustworthy/);
                // ...and a fresh probe cannot re-lift the connection.
                assert.throws(() => db.export(), /no longer trustworthy/);
            } finally {
                armed = false;
                // close() stays available: a quarantined connection must still
                // be releasable.
                db.close();
            }
        } finally {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    it('progress_handler is recorded but inert (the fork has no per-row callback)', () => {
        const db = createShim();
        try {
            const callback = () => false;
            db.progress_handler(1000, callback);
            assert.strictEqual(db.progressHandler?.callback, callback);
            db.progress_handler(null);
            assert.strictEqual(db.progressHandler, null);
        } finally {
            db.close();
        }
    });
});

describe('sqljs-shim: exec preserves duplicate result columns', () => {
    it('keeps every column of a JOIN whose result names collide', () => {
        // `exec` used to step FIRST and ask for columns after, so the TEMP VIEW
        // probe -- the only thing that can tell the shim a statement's TRUE
        // arity -- never ran, and `all()`'s object rows silently collapsed the
        // duplicate key. The result came back one column SHORT with its values
        // shifted left: a wrong answer, with no error. Only reachable through
        // runQuery today, which is exactly why it went unnoticed.
        const reference = new SQL.Database();
        const shim = createShim();
        const setup =
            'CREATE TABLE parent(id INTEGER PRIMARY KEY, label TEXT);' +
            'CREATE TABLE child(id INTEGER PRIMARY KEY, parent_id INTEGER, note TEXT);' +
            "INSERT INTO parent VALUES (1,'p1'); INSERT INTO child VALUES (7,1,'c1');";
        const query = 'SELECT * FROM parent JOIN child ON child.parent_id = parent.id';
        try {
            reference.run(setup);
            shim.run(setup);
            const expected = reference.exec(query);
            const actual = shim.exec(query);
            // The disambiguation suffix is a documented divergence (sql.js reads
            // sqlite3_column_name positionally and reports `id` twice); the
            // ARITY and the VALUES are what has to match.
            assert.deepStrictEqual(
                actual[0].columns.length,
                expected[0].columns.length
            );
            assert.deepStrictEqual(normalize(actual[0].values), normalize(expected[0].values));
            assert.deepStrictEqual(actual[0].columns, ['id', 'label', 'id:1', 'parent_id', 'note']);
        } finally {
            reference.close();
            shim.close();
        }
    });

    it('keeps every value of a parameterised statement whose result names collide', () => {
        // A view body holds no parameters, so the view repair above cannot
        // re-read a parameterised statement. It used to fall back to the
        // collapsed object keys: a self-join showed only its second table's
        // values, under half the columns. The rows are re-read through a CTE
        // whose column list renames every column, with the same parameters.
        const reference = new SQL.Database();
        const shim = createShim();
        const setup = "CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT); INSERT INTO t VALUES (1,'a'),(2,'b');";
        const cases: Array<[string, number[]]> = [
            ['SELECT a.*, c.* FROM t a JOIN t c ON c.id = a.id + ?', [1]],
            ['SELECT ?, 7 AS "0", ? -- trailing note', [8, 9]],
            ['WITH q AS (SELECT name FROM t WHERE id > ?) SELECT name, name FROM q ORDER BY name DESC', [0]]
        ];
        try {
            reference.run(setup);
            shim.run(setup);
            for (const [query, params] of cases) {
                const expected = reference.exec(query, params);
                const viaExec = shim.exec(query, params);
                assert.strictEqual(viaExec[0].columns.length, expected[0].columns.length, query);
                assert.deepStrictEqual(normalize(viaExec[0].values), normalize(expected[0].values), query);
                // The console's route: prepare, bind, step, get.
                const statement = shim.prepare(query);
                statement.bind(params);
                const rows = [];
                while (statement.step()) rows.push(statement.get());
                const columns = statement.getColumnNames();
                statement.free();
                assert.strictEqual(columns.length, expected[0].columns.length, query);
                assert.deepStrictEqual(normalize(rows), normalize(expected[0].values), query);
            }
        } finally {
            reference.close();
            shim.close();
        }
    });

    it('names repeated unaliased placeholders as written, disambiguated, before any step', () => {
        const shim = createShim();
        try {
            shim.run("CREATE TABLE t(id INTEGER PRIMARY KEY); INSERT INTO t VALUES (1);");
            for (const [where, rows] of [['WHERE 0', []], ['WHERE 1', [[8, 9]]]] as const) {
                const statement = shim.prepare(`SELECT ?, ? FROM t ${where}`);
                statement.bind([8, 9]);
                // The same convention as `SELECT 1 AS x, 2 AS x`: one header per value.
                assert.deepStrictEqual(statement.getColumnNames(), ['?', '?:1'], where);
                const values = [];
                while (statement.step()) values.push(statement.get());
                statement.free();
                assert.deepStrictEqual(normalize(values), rows, where);
            }
        } finally {
            shim.close();
        }
    });

    it('keeps both values of two identically aliased expressions', () => {
        const shim = createShim();
        try {
            assert.deepStrictEqual(normalize(shim.exec('SELECT 1 AS x, 2 AS x')), [
                { columns: ['x', 'x:1'], values: [[1, 2]] }
            ]);
        } finally {
            shim.close();
        }
    });

    it('leaves the change counter, the schema version and temp objects alone', () => {
        // The probe now runs on EVERY exec, including the ones worker.js uses to
        // read `changes()`/`total_changes()`/`schema_version` right after a
        // mutation. A probe that disturbed any of those would corrupt the
        // console's mutation detection and every oversized-cell guard.
        const shim = createShim();
        try {
            shim.run(SEED_SQL);
            shim.run("UPDATE t SET name = 'renamed' WHERE id IN (1,2)");
            assert.deepStrictEqual(
                normalize(shim.exec('SELECT changes() AS c')),
                [{ columns: ['c'], values: [[2]] }]
            );
            const before = normalize(shim.exec('PRAGMA schema_version'));
            shim.exec('SELECT id, name FROM t');
            shim.exec('SELECT 1 AS x, 2 AS x');
            assert.deepStrictEqual(normalize(shim.exec('PRAGMA schema_version')), before);
            assert.deepStrictEqual(
                normalize(shim.exec('SELECT count(*) AS c FROM temp.sqlite_master')),
                [{ columns: ['c'], values: [[0]] }]
            );
        } finally {
            shim.close();
        }
    });

    it('answers a value-returning PRAGMA with the same columns sql.js reports', () => {
        // The console's fix for E-2 is "step once, then ask again"; this is the
        // shim half of that contract -- once a row has been produced, rung 1 of
        // the metadata ladder knows the real names.
        const reference = new SQL.Database();
        const shim = createShim();
        const setup = 'CREATE TABLE pragma_probe(id INTEGER PRIMARY KEY, note TEXT)';
        try {
            reference.run(setup);
            shim.run(setup);
            const statement = shim.prepare('PRAGMA table_info(pragma_probe)');
            // Nothing knowable before the first step: a PRAGMA is not a legal
            // view body and is not EXPLAIN-prefixed.
            assert.deepStrictEqual(statement.getColumnNames(), []);
            assert.strictEqual(statement.step(), true);
            const referenceStatement = reference.prepare('PRAGMA table_info(pragma_probe)');
            referenceStatement.step();
            assert.deepStrictEqual(
                statement.getColumnNames(),
                referenceStatement.getColumnNames()
            );
            referenceStatement.free();
            statement.free();
        } finally {
            reference.close();
            shim.close();
        }
    });
});

/**
 * The values a statement hands the backing binder, recorded on top of the
 * node:sqlite stand-in. V8 shows no difference between an int-tagged and a
 * double-tagged Number, and node:sqlite binds every Number as REAL, so the
 * storage class the fork stores is checked against the real binary in the
 * native lane (`bind/json-numbers-*`, `lockstep/*`). These hold what can be
 * seen from here: which values change on the way and which do not.
 */
function createRecordingShim(): { shim: ShimDatabase; bound: unknown[] } {
    const bound: unknown[] = [];
    const Backing = standInSqliteModule.Database;
    class RecordingDatabase extends Backing {
        prepare(sql: string) {
            const statement = super.prepare(sql);
            const all = statement.all.bind(statement);
            statement.all = (params?: unknown) => {
                bound.push(params);
                return all(params);
            };
            return statement;
        }
    }
    const shim = createShimDatabase({}, { sqlite: { Database: RecordingDatabase }, fs: nodeFileSystem });
    return { shim, bound };
}

describe('sqljs-shim: result columns named like integers', () => {
    // The fork returns each row as an object, and JavaScript enumerates the
    // keys "1" and "2" before "b" whatever order they were added in. Values
    // must still come back in the statement's own column order.
    const seed = 'CREATE TABLE w ("1" INTEGER, b TEXT, "2" TEXT, PRIMARY KEY ("1")) WITHOUT ROWID;'
        + "INSERT INTO w VALUES (10, 'x', 'y'), (20, 'p', 'q');";
    differential('exec of aliased constants', db => db.exec(`SELECT 10 AS "1", 'x' AS b, 'y' AS "2"`), { seed });
    differential('exec of a column list', db => db.exec('SELECT "1", b, "2" FROM w ORDER BY "1"'), { seed });
    differential('exec of SELECT *', db => db.exec('SELECT * FROM w ORDER BY 1'), { seed });
    differential('names past the array-index range keep their place', db => db.exec(
        `SELECT 1 AS b, 2 AS "4294967295", 3 AS "4294967294", 4 AS "-1", 5 AS "01", 6 AS "0"`
    ), { seed });
    differential('prepare, step and get', db => {
        const statement = db.prepare('SELECT b, "2", "1" FROM w ORDER BY "1"');
        const rows = [];
        while (statement.step()) rows.push(statement.get());
        const columns = statement.getColumnNames();
        statement.free();
        return { columns, rows };
    }, { seed });
    differential('iterateStatements', db => {
        const rows = [];
        for (const statement of db.iterateStatements('SELECT "2", b FROM w ORDER BY "1"; SELECT "1", b FROM w')) {
            while (statement.step()) rows.push([statement.getColumnNames(), statement.get()]);
        }
        return rows;
    }, { seed });
    differential('a parameterised statement', db => db.exec(
        'SELECT ? AS p, "1", b, "2" FROM w WHERE "1" = ?', JSON.parse('["bound", 10]')
    ), { seed });
    differential('useBigInt', db => db.exec('SELECT b, "1" FROM w ORDER BY "1"', null,
        { useBigInt: true } as ShimValueConfig), { seed });

    it('an unaliased placeholder beside them: values in place, every name as sql.js reports it', () => {
        const reference = new SQL.Database();
        const shim = createShim();
        try {
            reference.run(seed);
            shim.run(seed);
            const query = 'SELECT ?, "1", b, "2" FROM w WHERE "1" = 10';
            const [expected] = reference.exec(query, ['bound']);
            const [actual] = shim.exec(query, ['bound']);
            assert.deepStrictEqual(normalize(actual.values), normalize(expected.values));
            // Names come from the rows once there are rows; the probe of a
            // parameterised statement reads its params-as-NULL expansion and
            // used to name the placeholder NULL.
            assert.deepStrictEqual(actual.columns, expected.columns);
            assert.deepStrictEqual(actual.columns, ['?', '1', 'b', '2']);
        } finally {
            reference.close();
            shim.close();
        }
    });

    it('a duplicate name among them: every value, in place', () => {
        const reference = new SQL.Database();
        const shim = createShim();
        try {
            reference.run(seed);
            shim.run(seed);
            const query = 'SELECT "2", b, "2", "1" FROM w ORDER BY "1"';
            const [expected] = reference.exec(query);
            const [actual] = shim.exec(query);
            assert.deepStrictEqual(normalize(actual.values), normalize(expected.values));
            assert.deepStrictEqual(actual.columns, ['2', 'b', '2:1', '1']);
        } finally {
            reference.close();
            shim.close();
        }
    });
});

describe('sqljs-shim: waiting for another connection\'s lock', () => {
    // A real file and a real second connection: node:sqlite is real SQLite,
    // so the busy handler and its locks are the engine's own.
    const LOCK_WAIT_MS = 1000;
    const seed = 'CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO t (v) VALUES (\'one\');';
    const withLockedFile = (body: (file: string, takeExclusiveLock: () => DatabaseSync) => void | Promise<void>) => async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sqljs-shim-lock-'));
        const holders: DatabaseSync[] = [];
        try {
            const file = path.join(dir, 'locked.sqlite');
            const seeded = new DatabaseSync(file);
            seeded.exec(seed);
            seeded.close();
            await body(file, () => {
                // An exclusive lock in a rollback-journal database refuses
                // every other connection's read until it is let go.
                const holder = new DatabaseSync(file, { timeout: 0 });
                holder.exec('BEGIN EXCLUSIVE');
                holders.push(holder);
                return holder;
            });
        } finally {
            for (const holder of holders) if (holder.isOpen) holder.close();
            fs.rmSync(dir, { recursive: true, force: true });
        }
    };
    const timed = (operation: () => unknown) => {
        const started = Date.now();
        let error: unknown;
        try { operation(); } catch (caught) { error = caught; }
        return { ms: Date.now() - started, errno: (error as { errno?: number } | undefined)?.errno };
    };

    it('after one refusal the connection stops waiting until restoreLockWait', withLockedFile((file, takeExclusiveLock) => {
        const db = createShim({ path: file, lockWaitMs: LOCK_WAIT_MS });
        try {
            db.exec('SELECT count(*) FROM t');
            takeExclusiveLock();
            const first = timed(() => db.exec('SELECT v FROM t'));
            assert.strictEqual(first.errno, 5);
            assert.ok(first.ms >= LOCK_WAIT_MS * 0.8, `the first refusal came after ${first.ms} ms`);
            const second = timed(() => db.exec('SELECT v FROM t'));
            assert.strictEqual(second.errno, 5);
            assert.ok(second.ms < LOCK_WAIT_MS * 0.4, `the second refusal came after ${second.ms} ms`);
            db.restoreLockWait();
            const third = timed(() => db.exec('SELECT v FROM t'));
            assert.strictEqual(third.errno, 5);
            assert.ok(third.ms >= LOCK_WAIT_MS * 0.8, `the refusal after restoreLockWait came after ${third.ms} ms`);
        } finally {
            db.close();
        }
    }));

    it('a lock released during the wait does not fail the statement', withLockedFile(async (file) => {
        const db = createShim({ path: file, lockWaitMs: LOCK_WAIT_MS });
        // The holder runs on its own thread: this one is busy inside SQLite
        // for as long as the statement waits.
        const holder = new Worker(`
            const { DatabaseSync } = require('node:sqlite');
            const { parentPort, workerData } = require('node:worker_threads');
            const db = new DatabaseSync(workerData, { timeout: 0 });
            db.exec('BEGIN EXCLUSIVE');
            parentPort.postMessage('held');
            // Timed from the moment the statement is about to start, so a
            // slow thread start cannot use up the 150 ms.
            parentPort.once('message', () => {
                setTimeout(() => { db.exec('ROLLBACK'); db.close(); }, 150);
            });
        `, { eval: true, workerData: file });
        try {
            db.exec('SELECT count(*) FROM t');
            await once(holder, 'message');
            holder.postMessage('start');
            const started = Date.now();
            const [result] = db.exec("INSERT INTO t (v) VALUES ('two') RETURNING id");
            const ms = Date.now() - started;
            assert.deepStrictEqual(normalize(result.values), [[2]]);
            assert.ok(ms >= 100 && ms < LOCK_WAIT_MS, `the statement went through after ${ms} ms`);
        } finally {
            await holder.terminate();
            db.close();
        }
    }));

    it('reports a lock refusal from the column probe instead of no columns', withLockedFile((file, takeExclusiveLock) => {
        const db = createShim({ path: file });
        try {
            db.exec('SELECT count(*) FROM t');
            takeExclusiveLock();
            const statement = db.prepare('SELECT id, v FROM t');
            try {
                assert.throws(() => statement.getColumnNames(), (error: { errno?: number }) => error?.errno === 5);
            } finally {
                statement.free();
            }
        } finally {
            db.close();
        }
    }));

    it('sets the wait again on every request, over a busy_timeout run as SQL', () => {
        const db = createShim({ lockWaitMs: LOCK_WAIT_MS });
        try {
            const timeout = () => normalize(db.exec('PRAGMA busy_timeout')[0].values[0][0]);
            assert.strictEqual(timeout(), LOCK_WAIT_MS);
            db.exec('PRAGMA busy_timeout = 5000');
            assert.strictEqual(timeout(), 5000);
            db.restoreLockWait();
            assert.strictEqual(timeout(), LOCK_WAIT_MS);
        } finally {
            db.close();
        }
    });

    it('does not wait unless asked to: sql.js\'s busy timeout is 0 too', withLockedFile((file, takeExclusiveLock) => {
        const db = createShim({ path: file });
        try {
            db.exec('SELECT count(*) FROM t');
            takeExclusiveLock();
            const refused = timed(() => db.exec('SELECT v FROM t'));
            assert.strictEqual(refused.errno, 5);
            assert.ok(refused.ms < 400, `refused after ${refused.ms} ms`);
        } finally {
            db.close();
        }
    }));
});

describe('sqljs-shim: bound values', () => {
    it('passes fractions, -0, NaN and integers beyond int32 through unchanged', () => {
        const { shim, bound } = createRecordingShim();
        try {
            const values = JSON.parse('[28, 2.5, -0.0, 2147483648, -2147483649, 1e300]');
            values.push(Number.NaN);
            shim.exec('SELECT ?, ?, ?, ?, ?, ?, ?', values);
            const handed = bound.at(-1) as unknown[];
            assert.strictEqual(handed.length, values.length);
            handed.forEach((value, index) => assert.ok(Object.is(value, values[index]),
                `position ${index + 1}: ${String(value)} != ${String(values[index])}`));
        } finally {
            shim.close();
        }
    });

    it('binds from a copy, so the caller keeps its parameters', () => {
        const { shim } = createRecordingShim();
        try {
            const positional = JSON.parse('[28, 2.5]');
            const named = JSON.parse('{":whole": 28, ":fraction": 2.5}');
            shim.exec('SELECT ? AS a, ? AS b', positional);
            shim.exec('SELECT :whole AS a, :fraction AS b', named);
            assert.deepStrictEqual(positional, [28, 2.5]);
            assert.deepStrictEqual(named, { ':whole': 28, ':fraction': 2.5 });
        } finally {
            shim.close();
        }
    });

    it('hands the binder a BigInt between -2^31 and 2^31 - 1 as a Number, since the fork rejects it as a BigInt', () => {
        // The stand-in refuses such a BigInt as the fork does. That the Number
        // is then stored as INTEGER is the fork's int-tag rule, checked in the
        // native lane (native/bigint-binds-as-integer).
        const { shim, bound } = createRecordingShim();
        try {
            const values = [0n, 5n, -1n, 2147483647n, -2147483648n, 2147483648n, -2147483649n,
                9223372036854775807n, -9223372036854775808n];
            const [result] = shim.exec(
                `SELECT ${values.map((_, index) => `?${index + 1}`).join(', ')}`, values, { useBigInt: true });
            assert.deepStrictEqual(bound.at(-1), [0, 5, -1, 2147483647, -2147483648,
                2147483648n, -2147483649n, 9223372036854775807n, -9223372036854775808n]);
            assert.deepStrictEqual(normalize(result.values[0]), normalize(values));
            shim.exec('SELECT :small AS v', { ':small': 7n });
            assert.deepStrictEqual(bound.at(-1), { ':small': 7 });
        } finally {
            shim.close();
        }
    });

    it('refuses a BigInt outside the 64-bit range instead of storing another number', () => {
        // The fork's binder keeps the low 64 bits, so 2^63 would be stored as -2^63.
        const shim = createShim();
        try {
            assert.throws(() => shim.exec('SELECT ?', [2n ** 63n]), RangeError);
            assert.throws(() => shim.exec('SELECT ?, ?', [1, -(2n ** 63n) - 1n]), /parameter 2 is outside/);
            assert.throws(() => shim.exec('SELECT :big', { ':big': 2n ** 64n }), /parameter :big is outside/);
        } finally {
            shim.close();
        }
    });

    it('keeps every named parameter, whatever its name', () => {
        const { shim, bound } = createRecordingShim();
        try {
            const named = JSON.parse('{":whole": 28, "__proto__": 1}');
            assert.throws(() => shim.exec('SELECT :whole AS a', named));
            const handed = bound.at(-1) as Record<string, unknown>;
            assert.deepStrictEqual(Object.keys(handed), [':whole', '__proto__']);
            assert.strictEqual(Object.getPrototypeOf(handed), Object.prototype);
        } finally {
            shim.close();
        }
    });
});

describe('sqljs-shim: documented divergences from sql.js', () => {
    it('duplicate result names are disambiguated, and both values survive', () => {
        // sql.js reports ['x','x'] because it reads sqlite3_column_name
        // positionally. The fork only exposes rows as objects, so a duplicate
        // name would collapse to a single key AND lose a value; the shim's TEMP
        // VIEW repair recovers both values under SQLite's own disambiguated
        // names. Losing the `:1` suffix would be worse than keeping it: names
        // and values must stay the same length or the grid mis-renders.
        const reference = new SQL.Database();
        const shim = createShim();
        try {
            assert.deepStrictEqual(normalize(reference.exec('SELECT 1 AS x, 2 AS x')), [
                { columns: ['x', 'x'], values: [[1, 2]] }
            ]);
            const statement = shim.prepare('SELECT 1 AS x, 2 AS x');
            const columns = statement.getColumnNames();
            const rows = [];
            while (statement.step()) rows.push(statement.get());
            statement.free();
            assert.deepStrictEqual(columns, ['x', 'x:1']);
            assert.deepStrictEqual(normalize(rows), [[1, 2]]);
        } finally {
            reference.close();
            shim.close();
        }
    });

    it('probes a parameterised statement once whether or not a view can hold it', () => {
        let probes = 0;
        const counting = {
            ...standInSqliteModule,
            Database: class extends (standInSqliteModule.Database as unknown as new (...args: unknown[]) => { prepare(sql: string): unknown }) {
                prepare(sql: string) {
                    if (sql.startsWith('CREATE TEMP VIEW')) probes += 1;
                    return super.prepare(sql);
                }
            }
        };
        const shim = createShimDatabase({}, { sqlite: counting as unknown as typeof standInSqliteModule, fs: nodeFileSystem });
        try {
            shim.run('CREATE TABLE t (id INTEGER PRIMARY KEY)');
            for (const [sql, columns] of [
                ['SELECT ? AS a, ? FROM t', ['a', '?']],
                // No view holds DML: its one failed probe is the documented "no columns yet".
                ['INSERT INTO t (id) VALUES (?) RETURNING id', []]
            ] as const) {
                probes = 0;
                const statement = shim.prepare(sql);
                statement.bind([1, 2].slice(0, sql.startsWith('INSERT') ? 1 : 2));
                assert.deepStrictEqual(statement.getColumnNames(), columns, sql);
                statement.free();
                assert.equal(probes, 1, sql);
            }
        } finally {
            shim.close();
        }
    });

    it('an UNALIASED placeholder column is named as written', () => {
        // A view body may not contain parameters, so the probe spells each one
        // as a string literal and reads the literal back as the parameter: the
        // name is what sql.js reports, not the NULL of the statement's
        // expansion. Still one probe per statement; repeated spellings keep the
        // view's `:1` suffix, as repeated names do.
        const reference = new SQL.Database();
        const shim = createShim();
        try {
            const referenceStatement = reference.prepare('SELECT ? AS named, ?');
            assert.deepStrictEqual(referenceStatement.getColumnNames(), ['named', '?']);
            referenceStatement.free();
            const statement = shim.prepare('SELECT ? AS named, ?');
            assert.deepStrictEqual(statement.getColumnNames(), ['named', '?']);
            statement.free();
        } finally {
            reference.close();
            shim.close();
        }
    });

    it('DML with RETURNING reports no columns until it has been stepped', () => {
        // The probe cannot express DML as a view, and the shim will not run a
        // mutation to answer a metadata question, so getColumnNames() is empty
        // where sql.js names the RETURNING columns. Documented gap, not an
        // accident: executing the INSERT early is the strictly worse trade.
        // runConsole no longer LOSES the rows over it -- it steps once and asks
        // again, which is the rung-1 answer -- but the pre-step reply is still
        // `[]` and callers must not read it as "this statement has no columns".
        const reference = new SQL.Database();
        const shim = createShim();
        try {
            reference.run(SEED_SQL);
            shim.run(SEED_SQL);
            const referenceStatement = reference.prepare(
                "INSERT INTO t VALUES(70,'seventy',NULL,0) RETURNING id, name"
            );
            assert.deepStrictEqual(referenceStatement.getColumnNames(), ['id', 'name']);
            referenceStatement.free();

            const statement = shim.prepare(
                "INSERT INTO t VALUES(70,'seventy',NULL,0) RETURNING id, name"
            );
            assert.deepStrictEqual(statement.getColumnNames(), []);
            // ...and asking did not run it.
            assert.deepStrictEqual(
                normalize(shim.exec('SELECT count(*) AS c FROM t WHERE id = 70')),
                [{ columns: ['c'], values: [[0]] }]
            );
            // Once stepped, the columns are available and the row is there.
            assert.strictEqual(statement.step(), true);
            assert.deepStrictEqual(statement.getColumnNames(), ['id', 'name']);
            statement.free();
            assert.deepStrictEqual(
                normalize(shim.exec('SELECT count(*) AS c FROM t WHERE id = 70')),
                [{ columns: ['c'], values: [[1]] }]
            );
        } finally {
            reference.close();
            shim.close();
        }
    });

    it('EXPLAIN keeps its columns: it cannot be a view, but it cannot mutate either', () => {
        // The one rung where the shim does materialise to answer getColumnNames.
        // Without it the console's EXPLAIN button would see zero headers and
        // discard the plan as side-effect-only output.
        const reference = new SQL.Database();
        const shim = createShim();
        try {
            const referenceStatement = reference.prepare('EXPLAIN QUERY PLAN SELECT 1');
            const expected = referenceStatement.getColumnNames();
            referenceStatement.free();
            const statement = shim.prepare('EXPLAIN QUERY PLAN SELECT 1');
            assert.deepStrictEqual(statement.getColumnNames(), expected);
            statement.free();
        } finally {
            reference.close();
            shim.close();
        }
    });

    it('a parameterised duplicate-name query reports every BOUND value, never the probe expansion', () => {
        // The probe view holds no parameters, so re-reading it would not
        // return the bound values. A
        // parameterised statement is re-read through a column-list CTE over its
        // own text, with the parameters it was bound with, so both columns
        // keep their bound values (before, the shim declined the repair and one
        // column collapsed into the other).
        const shim = createShim();
        try {
            const statement = shim.prepare('SELECT ? AS x, ? AS x', [1, 2]);
            assert.deepStrictEqual(statement.getColumnNames(), ['x', 'x:1']);
            const rows = [];
            while (statement.step()) rows.push(statement.get());
            const columns = statement.getColumnNames();
            statement.free();
            assert.deepStrictEqual(columns, ['x', 'x:1']);
            assert.strictEqual(columns.length, rows[0].length, 'names and values must agree');
            assert.deepStrictEqual(normalize(rows), [[1, 2]], 'the BOUND values, not NULL');
        } finally {
            shim.close();
        }
    });

    it('errors are Error instances, never bare strings', () => {
        // sql.js throws the STRING "Nothing to prepare"/"Statement closed";
        // worker.js already duck-types error messages, so the shim raises real
        // Errors and keeps stack traces.
        const shim = createShim();
        try {
            assert.throws(() => shim.prepare('-- nothing'), (error: unknown) => {
                assert.ok(error instanceof Error);
                assert.strictEqual((error as Error).message, 'Nothing to prepare');
                return true;
            });
        } finally {
            shim.close();
        }
    });

    it('getRemainingSQL after natural completion reports the leftover trivia', () => {
        // sql.js reads a FREED pointer at this point (its next() releases the
        // heap copy of the script before reporting `done`) and returns whatever
        // byte landed there; the shim reports the trailing trivia
        // deterministically. Neither is usable as a "was anything dropped?"
        // test, which is why worker.js no longer consults it after natural
        // completion -- both iterators only report `done` once prepare found no
        // further statement. Pinned here so a future engine swap has to look at
        // this difference on purpose.
        const shim = createShim();
        try {
            const iterator = shim.iterateStatements('SELECT 1; -- tail');
            for (;;) {
                const step = iterator.next();
                if (step.done) break;
                step.value.free();
            }
            assert.strictEqual(iterator.getRemainingSQL().trim(), '-- tail');
        } finally {
            shim.close();
        }
    });

    it('RETURNING with integer-like names keeps each value under its own name, in object order', () => {
        // A DML statement cannot be a view body, so there is no probe to give
        // its column order, and the fork's row objects enumerate "1" and "2"
        // ahead of b. Names and values still pair up; only their order
        // differs from sql.js. Restoring it needs the runtime to return rows
        // as arrays or to report column names.
        const reference = new SQL.Database();
        const shim = createShim();
        const seed = 'CREATE TABLE w ("1" INTEGER, b TEXT, "2" TEXT, PRIMARY KEY ("1")) WITHOUT ROWID';
        const insert = `INSERT INTO w VALUES (30, 'r', 's') RETURNING b, "2", "1"`;
        try {
            reference.run(seed);
            shim.run(seed);
            assert.deepStrictEqual(normalize(reference.exec(insert)), [
                { columns: ['b', '2', '1'], values: [['r', 's', 30]] }
            ]);
            assert.deepStrictEqual(normalize(shim.exec(insert)), [
                { columns: ['1', '2', 'b'], values: [[30, 's', 'r']] }
            ]);
        } finally {
            reference.close();
            shim.close();
        }
    });

    it('over-stepping a DML statement does not re-run its side effects', () => {
        // sqlite3_step implicitly resets after SQLITE_DONE, so sql.js re-executes
        // an INSERT when a caller steps it again. The shim replays rows but never
        // side effects; nothing in the worker layer over-steps.
        const shim = createShim();
        try {
            shim.run(SEED_SQL);
            const statement = shim.prepare("INSERT INTO t VALUES(50,'fifty',NULL,0)");
            statement.step();
            statement.step();
            statement.free();
            assert.deepStrictEqual(
                normalize(shim.exec('SELECT count(*) AS c FROM t WHERE id = 50')),
                [{ columns: ['c'], values: [[1]] }]
            );
        } finally {
            shim.close();
        }
    });
});
