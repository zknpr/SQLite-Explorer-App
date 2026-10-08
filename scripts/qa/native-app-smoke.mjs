#!/usr/bin/env node
// Run inside a Linux/Windows guest against its installed app and native WebDriver.
// No bridge stubs: independent SQLite reads verify the file behind the UI.
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { execFileSync } from 'node:child_process';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';

const [driver, applicationArg, output] = process.argv.slice(2);
assert.ok(driver && applicationArg && output,
    'Usage: node native-app-smoke.mjs DRIVER_URL INSTALLED_APP EVIDENCE_DIRECTORY (Node 24+)');
// Get-Process.Path uses native separators. Normalize before the cleanup identity
// check so a Windows invocation using forward slashes cannot leave an app alive.
const application = resolve(applicationArg);
const evidence = resolve(output);
await mkdir(evidence, { recursive: true });
const database = join(evidence, 'native space 東京.sqlite');
const fixture = new DatabaseSync(database);
fixture.exec(`
CREATE TABLE people(id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER, payload BLOB);
INSERT INTO people VALUES(1,'Alice',30,X'DEADBEEF'),(2,'Bob',20,X'00FF'),(3,'Chärlie 世界',40,NULL);
CREATE TABLE big_numbers(id INTEGER PRIMARY KEY, value INTEGER);
INSERT INTO big_numbers VALUES(1,9223372036854775807),(2,-9223372036854775808),(3,9007199254740993);
CREATE TABLE keyed(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;
INSERT INTO keyed VALUES('first','Original');
CREATE VIRTUAL TABLE search USING fts5(body);
INSERT INTO search VALUES('SQLite app smoke test');
`);
fixture.close();
const disk = sql => {
    const db = new DatabaseSync(database, { readOnly: true });
    try { return db.prepare(sql).all().map(row => ({ ...row })); }
    finally { db.close(); }
};
let session;
let windowsTask;
const psQuote = value => `'${value.replaceAll("'", "''")}'`;
const encoded = value => Buffer.from(value, 'utf16le').toString('base64');
const powershell = script => execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded("$ProgressPreference='SilentlyContinue'; " + script)], { encoding: 'utf8' });
const results = [];
async function request(method, route, body) {
    const response = await fetch(driver.replace(/\/$/, '') + route, {
        method, headers: { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: AbortSignal.timeout(route === '/session' ? 240_000 : 30_000)
    });
    const result = await response.json();
    if (!response.ok || result.value?.error) throw new Error(JSON.stringify(result));
    return result.value;
}
const command = (method, route, body) => request(method, `/session/${session}${route}`, body);
const evaluate = (fn, ...args) => command('POST', '/execute/sync', { script: `return (${fn.toString()})(...arguments)`, args });
async function until(fn, label, ...args) {
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
        const value = await evaluate(fn, ...args);
        if (value) return value;
        await new Promise(resolveWait => setTimeout(resolveWait, 200));
    }
    throw new Error(`Timed out: ${label}`);
}
const element = selector => command('POST', '/element', { using: 'css selector', value: selector });
const elementId = el => el['element-6066-11e4-a52e-4f735466cecf'];
async function click(selector) {
    const el = await element(selector);
    await command('POST', `/element/${elementId(el)}/click`, {});
}
async function fill(selector, value) {
    const el = await element(selector);
    await command('POST', `/element/${elementId(el)}/clear`, {});
    await command('POST', `/element/${elementId(el)}/value`, { text: value });
}
async function keys(...values) {
    const actions = values.map(value => ({ type: 'keyDown', value }));
    actions.push(...values.toReversed().map(value => ({ type: 'keyUp', value })));
    await command('POST', '/actions', { actions: [{ type: 'key', id: 'keyboard', actions }] });
}
const control = '\uE009', shift = '\uE008', enter = '\uE007';
const textOf = selector => evaluate(sel => document.querySelector(sel)?.textContent, selector);
const cell = (row, column) => `.data-row[data-rowid="${row}"] .data-cell[data-colidx="${column}"]`;
async function table(name) {
    await click(`.list-item[data-type="table"][data-name="${name}"]`);
    await until(name => document.querySelector('#tableNameLabel')?.textContent === name
        && document.querySelectorAll('.data-row').length > 0, `table ${name}`, name);
}
async function edit(selector, value) {
    const el = await element(selector);
    await command('POST', '/actions', { actions: [{ type: 'pointer', id: 'mouse', parameters: { pointerType: 'mouse' }, actions: [
        { type: 'pointerMove', origin: el, x: 0, y: 0 },
        { type: 'pointerDown', button: 0 }, { type: 'pointerUp', button: 0 },
        { type: 'pause', duration: 60 },
        { type: 'pointerDown', button: 0 }, { type: 'pointerUp', button: 0 }
    ] }] });
    await until(() => document.querySelector('.cell-input'), 'inline editor');
    await fill('.cell-input', value);
    await keys(enter);
    await until((selector, value) => document.querySelector(selector)?.textContent === value,
        'edited value', selector, value);
    await click('#statusText');
}
async function screenshot(name) {
    await writeFile(join(evidence, `${name}.png`), Buffer.from(await command('GET', '/screenshot'), 'base64'));
}
async function step(name, action) {
    await action();
    results.push({ name, passed: true });
    console.log(`PASS ${name}`);
}

try {
    let capabilities = { 'tauri:options': { application, args: [database] } };
    if (process.platform === 'win32') {
        const debugPort = Number(process.env.SQLITE_QA_DEBUG_PORT || 9222);
        assert.ok(Number.isInteger(debugPort) && debugPort > 0 && debugPort <= 65535,
            'SQLITE_QA_DEBUG_PORT must be a TCP port');
        powershell(`$ErrorActionPreference='Stop'; `
            + `if (Get-NetTCPConnection -LocalPort ${debugPort} -State Listen -ErrorAction SilentlyContinue) `
            + `{ throw 'The QA debugging port is already occupied; choose SQLITE_QA_DEBUG_PORT' }; `
            // Different debug ports also mean different WebView2 environment
            // options, which cannot share an already running app's user data.
            + `if (Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq ${psQuote(application)} }) `
            + `{ throw 'Close existing instances of the test app before running native QA' }`);
        // EdgeDriver 153 rejects positional file paths as malformed switches.
        // Launch normally in the logged-in desktop, then attach to its WebView2.
        // This also works when the runner itself is in SSH's noninteractive session.
        windowsTask = `SQLiteAppSmoke-${process.pid}`;
        const launch = `$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS='--remote-debugging-port=${debugPort}'; `
            + `$p=Start-Process -FilePath ${psQuote(application)} -ArgumentList ${psQuote('"' + database + '"')} -PassThru `
            + `-RedirectStandardOutput ${psQuote(join(evidence, 'app.stdout.log'))} -RedirectStandardError ${psQuote(join(evidence, 'app.stderr.log'))}; `
            + `[IO.File]::WriteAllText(${psQuote(join(evidence, 'app.pid'))}, [string]$p.Id); Wait-Process -Id $p.Id`;
        powershell(`$ErrorActionPreference='Stop'; `
            + `$a=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ${encoded(launch)}'; `
            + `$p=New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Limited; `
            + `Register-ScheduledTask -TaskName ${psQuote(windowsTask)} -Action $a -Principal $p | Out-Null; `
            + `Start-ScheduledTask -TaskName ${psQuote(windowsTask)}`);
        const deadline = Date.now() + 30_000;
        let ready = false;
        while (Date.now() < deadline) {
            try { ready = (await fetch(`http://127.0.0.1:${debugPort}/json/version`)).ok; }
            catch { /* The app has not created its WebView2 yet. */ }
            if (ready) break;
            await new Promise(resolveWait => setTimeout(resolveWait, 250));
        }
        assert.ok(ready, 'Installed app did not expose its test WebView2');
        capabilities = { browserName: 'webview2', 'ms:edgeOptions': { debuggerAddress: `127.0.0.1:${debugPort}` } };
    }
    const created = await request('POST', '/session', { capabilities: { alwaysMatch: capabilities } });
    session = created.sessionId;
    await writeFile(join(evidence, 'session.json'), JSON.stringify(created, null, 2));
    await step('installed app opens a path containing spaces and Unicode with the native engine', async () => {
        await until(() => document.querySelector('#engineBadge')?.dataset.engine === 'native'
            && document.querySelector('.list-item[data-name="people"]'), 'native database open');
        assert.match(await evaluate(() => location.href), /^(tauri:\/\/localhost|http:\/\/tauri\.localhost)\/viewer.html$/);
        assert.equal(await evaluate(() => getComputedStyle(document.querySelector('#btnOpenQuery')).display), 'none');
        await table('people');
        assert.equal(await textOf(cell(1, 1)), 'Alice');
        assert.equal(await textOf(cell(3, 1)), 'Chärlie 世界');
        assert.match(await textOf(cell(1, 3)), /BLOB|4 bytes/);
        await screenshot('01-native-grid');
    });
    await step('64-bit integers retain every digit', async () => {
        await table('big_numbers');
        assert.equal(await textOf(cell(1, 1)), '9223372036854775807');
        assert.equal(await textOf(cell(2, 1)), '-9223372036854775808');
        assert.equal(await textOf(cell(3, 1)), '9007199254740993');
    });
    await step('filter and sort', async () => {
        await table('people');
        await fill('#filterInput', 'Alice');
        await click('#btnApplyFilter');
        await until(() => document.querySelectorAll('.data-row').length === 1, 'filter');
        assert.equal(await textOf(cell(1, 1)), 'Alice');
        await click('#btnClearFilter');
        await until(() => document.querySelectorAll('.data-row').length === 3, 'clear filter');
        await click('.header-cell[data-column="age"] .header-sort-button');
        await until(() => document.querySelector('.data-row')?.dataset.rowid === '2', 'sort');
    });
    await step('edit stays pending; undo, redo, and Save persist the expected bytes', async () => {
        await edit(cell(1, 1), 'Alice edited');
        assert.deepEqual(disk('SELECT name FROM people WHERE id=1'), [{ name: 'Alice' }]);
        await keys(control, 'z');
        await until(() => document.querySelector('.data-row[data-rowid="1"] .data-cell[data-colidx="1"]')?.textContent === 'Alice', 'undo');
        await keys(control, shift, 'z');
        await until(() => document.querySelector('.data-row[data-rowid="1"] .data-cell[data-colidx="1"]')?.textContent === 'Alice edited', 'redo');
        await keys(control, 's');
        await until(() => !document.title.startsWith('●') && !document.title.startsWith('•')
            && /saved/i.test(document.querySelector('#statusText')?.textContent ?? ''), 'save');
        assert.equal(await textOf('#statusText'), 'Saved native space 東京.sqlite');
        assert.deepEqual(disk('SELECT name FROM people WHERE id=1'), [{ name: 'Alice edited' }]);
        assert.deepEqual(disk('PRAGMA integrity_check'), [{ integrity_check: 'ok' }]);
    });
    await step('existing SQL console runs parameters and Explain and preserves its draft', async () => {
        await click('#btnSqlConsole');
        await click('.cm-content');
        await keys(control, 'a');
        const editor = await element('.cm-content');
        await command('POST', `/element/${elementId(editor)}/value`, { text: 'SELECT name FROM people WHERE age > ? ORDER BY id' });
        await fill('.sql-console-params', '[25]');
        await click('.sql-console-run');
        await until(() => document.querySelector('.sql-console-results-status-text, .sql-console-results-error'), 'SQL result');
        assert.equal(await evaluate(() => document.querySelector('.sql-console-results-error')?.textContent ?? null), null);
        assert.match(await textOf('#consoleResults'), /Alice edited/);
        assert.match(await textOf('#consoleResults'), /Chärlie 世界/);
        await click('.sql-console-explain');
        await until(() => /SCAN|SEARCH/.test(document.querySelector('#consoleResults')?.textContent ?? ''), 'Explain');
        const draft = await textOf('.cm-content');
        await screenshot('02-sql-console');
        await click('.cm-content');
        await keys(control, shift, 'k');
        await until(() => document.querySelector('#consoleContainer')?.hidden, 'console toggle');
        await click('#btnSqlConsole');
        assert.equal(await textOf('.cm-content'), draft);
        await click('#btnSqlConsole');
    });
    await step('WITHOUT ROWID and FTS5 shadow tables load', async () => {
        await table('keyed');
        assert.match(await textOf('#gridContainer'), /Original/);
        await table('search_idx');
        assert.match(await textOf('#tableNameLabel'), /search_idx/);
        await screenshot('03-shadow-table');
    });
    console.log(`PASS ${results.length} native app checks; evidence: ${evidence}`);
} catch (error) {
    results.push({ passed: false, error: error.stack });
    if (session) {
        try {
            await screenshot('failure');
            await writeFile(join(evidence, 'failure-state.json'), JSON.stringify(await evaluate(() => ({
                title: document.title, body: document.body.innerText, url: location.href,
                engine: document.querySelector('#engineBadge')?.dataset.engine,
                engineTitle: document.querySelector('#engineBadge')?.title
            })), null, 2));
        } catch (diagnosticError) { console.error('Diagnostic collection failed:', diagnosticError); }
    }
    throw error;
} finally {
    await writeFile(join(evidence, 'results.json'), JSON.stringify({ platform: process.platform, application, database, results }, null, 2));
    try {
        if (session) await command('DELETE', '');
    } finally {
        if (windowsTask) {
            const pid = Number(await readFile(join(evidence, 'app.pid'), 'utf8'));
            assert.ok(Number.isInteger(pid) && pid > 0);
            powershell(`$ErrorActionPreference='Stop'; $p=Get-Process -Id ${pid} -ErrorAction SilentlyContinue; `
                + `if ($p -and $p.Path -eq ${psQuote(application)}) { Stop-Process -Id ${pid} }; `
                + `Unregister-ScheduledTask -TaskName ${psQuote(windowsTask)} -Confirm:$false`);
        }
    }
}
