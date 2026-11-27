/**
 * The desktop SQL console on a read-only database, page side: the run goes to
 * the worker, which answers its reads and refuses every other statement by
 * name before it runs, and the console stays up under a notice saying so.
 *
 * runConsoleSql and applyConsoleAvailability live in an entry point that boots
 * a whole viewer on import, so they are evaluated here from the shipped source
 * with their dependencies injected (the technique
 * desktop_history_refresh.test.ts uses for refreshContentOnce).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const viewerSource = readFileSync(path.resolve(process.cwd(), 'core/ui/desktop-viewer.js'), 'utf8');

/** The shipped source from `start` through the first `end` after it. */
function sourceOf(start: string, end: string): string {
    const from = viewerSource.indexOf(start);
    assert.notEqual(from, -1, `desktop-viewer.js no longer has ${start}`);
    const to = viewerSource.indexOf(end, from);
    assert.notEqual(to, -1, `could not find the end of ${start}`);
    return viewerSource.slice(from, to + end.length);
}

function makePage(isReadOnly: boolean) {
    const runs: unknown[] = [];
    const rendered: unknown[] = [];
    const calls: string[] = [];
    const elements: Record<string, Record<string, unknown>> = {
        consoleResults: { replaceChildren: () => { calls.push('clear results'); } },
        consoleNotice: { textContent: '', hidden: true }
    };
    let open = false;
    const answer = { results: [{ headers: ['1'], rows: [[1]], truncated: false }], mutated: false, changes: 0, durationMs: 1 };
    const deps: Record<string, unknown> = {
        state: { isReadOnly },
        document: { getElementById: (id: string) => elements[id] ?? null },
        sqlConsole: {
            isOpen: () => open,
            show: () => { open = true; calls.push('show'); },
            hide: () => { open = false; calls.push('hide'); }
        },
        renderConsoleResults: (_container: unknown, payload: unknown) => { rendered.push(payload); },
        backendApi: {
            runConsole: async (sql: string, options: unknown) => { runs.push([sql, options]); return answer; }
        },
        exportConsoleCsv: async () => {},
        consoleSurface: () => () => {}
    };
    const names = Object.keys(deps);
    const page = new Function(...names, [
        sourceOf('const READ_ONLY_CONSOLE_NOTICE =', ';\n'),
        sourceOf('async function runConsoleSql(', '\n}\n'),
        sourceOf('function applyConsoleAvailability(', '\n}\n'),
        'return { runConsoleSql, applyConsoleAvailability, notice: READ_ONLY_CONSOLE_NOTICE };'
    ].join('\n'))(...names.map(name => deps[name])) as {
        runConsoleSql(sql: string, options: unknown): Promise<void>;
        applyConsoleAvailability(): void;
        notice: string;
    };
    return { ...page, runs, rendered, calls, elements, answer };
}

test('a read-only database sends its console run to the worker, which answers its reads', async () => {
    const page = makePage(true);
    await page.runConsoleSql('SELECT 1', { params: [] });
    assert.deepEqual(page.runs, [['SELECT 1', { params: [] }]]);
    assert.deepEqual(page.rendered, [page.answer]);
});

test('a read-only database keeps the console up under a notice that it runs reads only', () => {
    const page = makePage(true);
    page.applyConsoleAvailability();
    // Shown, and the results pane kept: they can come from this database now.
    assert.deepEqual(page.calls, ['show']);
    assert.equal(page.elements.consoleNotice.hidden, false);
    assert.equal(page.elements.consoleNotice.textContent, page.notice);
    assert.match(page.notice, /read-only/);
    assert.match(page.notice, /SELECT/);

    const writable = makePage(false);
    writable.applyConsoleAvailability();
    assert.deepEqual(writable.calls, ['show']);
    assert.equal(writable.elements.consoleNotice.hidden, true);
});