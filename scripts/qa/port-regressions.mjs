#!/usr/bin/env node
/** Headless integration coverage for the generated desktop viewer and real WASM worker.
 * Usage: node scripts/qa/port-regressions.mjs [--viewer-dir /path/to/desktop]
 * Chrome can be overridden with CHROME_PATH. Evidence and saved files stay in /tmp.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, writeFile, stat } from 'node:fs/promises';
import { dirname, extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const args = process.argv.slice(2);
if (args.length && (args.length !== 2 || args[0] !== '--viewer-dir')) {
    throw new Error('Usage: port-regressions.mjs [--viewer-dir PATH]');
}
const viewerDir = resolve(args[1] ?? join(appRoot, 'viewer-dist'));
const evidence = await mkdtemp('/tmp/sqlite-explorer-port-');
const primaryDb = join(evidence, 'primary.sqlite');
const secondaryDb = join(evidence, 'secondary.sqlite');
const importCsv = join(evidence, 'import.csv');
await writeFile(importCsv, 'key\nimport-1\nimport-2\nimport-3\n');
const sqlite = (path, sql) => execFileSync('sqlite3', [path], { input: sql, encoding: 'utf8' }).trim();
const longText = '東京😀\n'.repeat(20_000);
sqlite(primaryDb, `
PRAGMA encoding='UTF-16le';
CREATE TABLE people(id INTEGER PRIMARY KEY, name TEXT NOT NULL, age INTEGER, payload BLOB);
INSERT INTO people VALUES(1,'Alice',30,X'DEADBEEF'),(2,'Bob',20,X'00FF'),(3,'Chärlie',40,NULL);
CREATE INDEX idx_people_name_with_a_deliberately_long_identifier_for_sidebar_layout ON people(name);
CREATE TABLE cells(id INTEGER PRIMARY KEY, body TEXT, computed TEXT GENERATED ALWAYS AS ('value ' || id) STORED);
INSERT INTO cells(id,body) VALUES(1,'${longText}');
CREATE TABLE bulk(id INTEGER PRIMARY KEY, value TEXT);
WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1100)
INSERT INTO bulk SELECT x,'row '||x FROM n;
`);
sqlite(secondaryDb, "CREATE TABLE people(id INTEGER PRIMARY KEY,name TEXT); INSERT INTO people VALUES(9,'Second database');");
const allowed = new Set([primaryDb, secondaryDb]);
const artifacts = Object.fromEntries(await Promise.all(['viewer.html', 'worker.js', 'sql-wasm.js', 'sql-wasm.wasm'].map(async name => [name, createHash('sha256').update(await readFile(join(viewerDir, name))).digest('hex')])));
const saves = [];
const errors = [];
let nextPick = primaryDb;
let browser;
let page;
const server = createServer(async (request, response) => {
    try {
        const pathname = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
        if (pathname === '/favicon.ico') { response.writeHead(204).end(); return; }
        const file = resolve(viewerDir, '.' + pathname);
        if (!file.startsWith(viewerDir + sep)) throw new Error('Outside viewer directory');
        const bytes = await readFile(file);
        const mime = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm', '.css': 'text/css', '.ttf': 'font/ttf' }[extname(file)];
        response.writeHead(200, { 'Content-Type': mime ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
        response.end(bytes);
    } catch {
        response.writeHead(404).end();
    }
});
await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
const baseUrl = `http://127.0.0.1:${server.address().port}`;
const noErrors = () => assert.deepEqual(errors, [], 'Browser JavaScript/console errors');
async function step(name, action) {
    await action();
    noErrors();
    console.log(`PASS ${name}`);
}
async function menu(id) { await page.evaluate(id => window.__QA_MENU__(id), id); }
async function table(name) {
    await page.locator(`.list-item[data-name="${name}"][data-type="table"]`).click();
    await page.waitForFunction(name => document.querySelector('#tableNameLabel')?.textContent === name
        && document.querySelectorAll('.data-row').length > 0, name);
}
const cell = (rowId, col) => page.locator(`.data-row[data-rowid="${rowId}"] .data-cell[data-colidx="${col}"]`);
async function sql(statement, params = '') {
    if (!await page.locator('.cm-content').isVisible()) await menu('sql-console');
    await page.locator('.cm-content').fill(statement);
    await page.locator('.sql-console-params').fill(params);
    await page.locator('.sql-console-run').click();
    await page.waitForFunction(() => document.querySelector('.sql-console-results-status-text, .sql-console-results-error'));
    assert.equal(await page.locator('.sql-console-results-error').count(), 0, await page.locator('#consoleResults').innerText());
}
async function saveDb() {
    const before = saves.length;
    await menu('save-db');
    assert.ok(saves.length > before, 'Save must reach the bridge');
    assert.equal(saves.at(-1).kind, 'database');
}

try {
    await stat(join(viewerDir, 'viewer.html'));
    browser = await chromium.launch({
        executablePath: process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
        headless: true
    });
    page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    page.setDefaultTimeout(15_000);
    page.on('pageerror', error => errors.push(error.stack ?? error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(`${message.text()} at ${message.location().url}`); });
    await page.exposeFunction('__qaPick', async () => ({ path: nextPick, name: nextPick.split('/').at(-1), size: (await stat(nextPick)).size }));
    await page.exposeFunction('__qaImportPick', async () => ({ path: importCsv, name: 'import.csv', size: (await stat(importCsv)).size }));
    await page.exposeFunction('__qaImportRead', async path => {
        assert.equal(path, importCsv, 'Only the selected CSV fixture may be read');
        return readFile(path, 'utf8');
    });
    await page.exposeFunction('__qaRead', async path => {
        assert.ok(allowed.has(path), 'Only fixture paths may be read');
        return (await readFile(path)).toString('base64');
    });
    await page.exposeFunction('__qaSave', async (kind, path, name, bytes) => {
        const target = kind === 'database' ? path : join(evidence, `export-${saves.length}-${name.replace(/[^a-zA-Z0-9._-]/g, '_')}`);
        if (kind === 'database') assert.ok(allowed.has(target), 'Only fixture paths may be overwritten');
        await writeFile(target, Buffer.from(bytes));
        saves.push({ kind, path: target, name });
        return target;
    });
    await page.addInitScript(() => {
        let menuHandler;
        let settings = { theme: 'dark', defaultPageSize: 5000, cellEditBehavior: 'inline' };
        window.__SQLITE_DESKTOP__ = {
            pickDatabase: () => window.__qaPick(),
            pickImportSource: () => window.__qaImportPick(),
            readImportText: path => window.__qaImportRead(path),
            readDatabaseBytes: async path => Uint8Array.from(atob(await window.__qaRead(path)), char => char.charCodeAt(0)),
            saveDatabase: (path, bytes) => window.__qaSave('database', path, '', Array.from(bytes)),
            saveFileAs: (name, bytes) => window.__qaSave('export', '', name, Array.from(bytes)),
            saveDatabaseAs: (name, bytes) => window.__qaSave('export', '', name, Array.from(bytes)),
            loadSettings: async () => settings,
            saveSettings: async next => { settings = { ...settings, ...next }; },
            onMenu: handler => { menuHandler = handler; },
            onOpenFile() {},
            setTitle: async title => { document.title = title; },
            viewerReady: async () => { window.__QA_READY__ = true; }
        };
        window.__QA_MENU__ = id => menuHandler(id);
    });
    await step('boot, layout, and first database loading state', async () => {
        await page.goto(`${baseUrl}/viewer.html`);
        await page.waitForFunction(() => window.__QA_READY__);
        assert.equal(await page.locator('#btnOpenQuery').isVisible(), false,
            'Desktop must keep its existing SQL console without an extension-only SQL Query action');
        await menu('open-db');
        await page.locator('.list-item[data-name="people"]').waitFor();
        assert.equal(await page.locator('#loadingView').isVisible(), false, 'First open must clear loading');
        const layout = await page.evaluate(() => {
            const sidebar = document.querySelector('#sidebarPanel').getBoundingClientRect();
            const filter = document.querySelector('#sidebarFilterInput').getBoundingClientRect();
            const panel = document.querySelector('.main-panel').getBoundingClientRect();
            return { sidebar: sidebar.width, filter: filter.width, panel: panel.width, edge: panel.right, width: innerWidth };
        });
        assert.ok(layout.sidebar >= 150 && layout.sidebar <= 400, JSON.stringify(layout));
        assert.ok(layout.filter > layout.sidebar - 40, 'Sidebar filter must fill its container');
        assert.ok(layout.panel > 900 && Math.abs(layout.edge - layout.width) < 3, 'Main panel must fill available width');
        await table('people');
        assert.equal(await page.locator('#engineBadge').getAttribute('data-engine'), 'wasm');
        assert.equal(await page.locator('.data-row').count(), 3);
        assert.equal(await cell(1, 1).innerText(), 'Alice');
        await page.screenshot({ path: join(evidence, '01-grid.png') });
    });
    await step('index names and table labels stay separate inside the sidebar', async () => {
        await page.locator('.section-toggle[data-section="indexes"]').click();
        const index = page.locator('#indexesList .list-item').filter({ hasText: 'idx_people_name_with_a_deliberately_long_identifier_for_sidebar_layout' });
        await index.waitFor({ state: 'visible' });
        const layout = await index.evaluate(row => {
            const name = row.querySelector('.item-name');
            const detail = row.querySelector('.item-detail');
            const sidebar = document.querySelector('#sidebarPanel').getBoundingClientRect();
            const nameBox = name.getBoundingClientRect();
            const detailBox = detail.getBoundingClientRect();
            return {
                contentDisplay: getComputedStyle(row.querySelector('.item-content')).display,
                nameEllipsis: getComputedStyle(name).textOverflow, detailEllipsis: getComputedStyle(detail).textOverflow,
                nameWidth: nameBox.width, nameOverflow: name.scrollWidth > name.clientWidth,
                detail: detail.textContent, detailWidth: detailBox.width, gap: detailBox.left - nameBox.right,
                right: detailBox.right, sidebarRight: sidebar.right, rowRight: row.getBoundingClientRect().right
            };
        });
        assert.equal(layout.contentDisplay, 'flex');
        assert.equal(layout.nameEllipsis, 'ellipsis');
        assert.equal(layout.detailEllipsis, 'ellipsis');
        assert.equal(layout.detail, 'people');
        assert.ok(layout.nameWidth > 0 && layout.detailWidth > 0 && layout.nameOverflow, JSON.stringify(layout));
        assert.ok(layout.gap >= 5, 'Index name and table label need a visible gap');
        assert.ok(layout.right <= layout.sidebarRight && layout.rowRight <= layout.sidebarRight, JSON.stringify(layout));
        await page.screenshot({ path: join(evidence, '01-index-layout.png') });
    });
    await step('filter, sort, edit, undo, redo, and saved database bytes', async () => {
        await page.locator('#filterInput').fill('Alice');
        await page.locator('#btnApplyFilter').click();
        await page.waitForFunction(() => document.querySelectorAll('.data-row').length === 1);
        assert.equal(await cell(1, 1).innerText(), 'Alice');
        await page.locator('#btnClearFilter').click();
        await page.waitForFunction(() => document.querySelectorAll('.data-row').length === 3);
        await page.locator('.header-cell[data-column="age"] .header-sort-button').click();
        await page.waitForFunction(() => document.querySelector('.data-row')?.dataset.rowid === '2');
        await cell(1, 1).dblclick();
        await page.locator('.cell-input').fill('Alice edited');
        await page.locator('.cell-input').press('Enter');
        await page.waitForFunction(() => [...document.querySelectorAll('.data-cell')].some(cell => cell.textContent === 'Alice edited'));
        await page.locator('#statusText').click();
        await page.keyboard.press('Control+z');
        await page.waitForFunction(() => [...document.querySelectorAll('.data-cell')].some(cell => cell.textContent === 'Alice'));
        await page.keyboard.press('Control+Shift+z');
        await page.waitForFunction(() => [...document.querySelectorAll('.data-cell')].some(cell => cell.textContent === 'Alice edited'));
        await saveDb();
        assert.equal(sqlite(primaryDb, 'SELECT name FROM people WHERE id=1;'), 'Alice edited');
        assert.equal(sqlite(primaryDb, 'PRAGMA integrity_check;'), 'ok');
    });
    await step('SQL parameters, Explain, and CSV export', async () => {
        await sql('SELECT name FROM people WHERE age > ? ORDER BY id', '[25]');
        assert.match(await page.locator('#consoleResults').innerText(), /Alice edited/);
        assert.match(await page.locator('#consoleResults').innerText(), /Chärlie/);
        const before = saves.length;
        await page.locator('.sql-console-results-export').click();
        await page.waitForFunction(() => document.querySelector('#statusText')?.textContent.includes('Exported'));
        assert.equal(saves.length, before + 1);
        const csv = await readFile(saves.at(-1).path, 'utf8');
        assert.match(csv, /Alice edited/);
        assert.match(csv, /Chärlie/);
        await page.locator('.sql-console-explain').click();
        await page.waitForFunction(() => /SCAN|SEARCH/.test(document.querySelector('#consoleResults')?.textContent ?? ''));
        await page.screenshot({ path: join(evidence, '02-console.png') });
        const draft = await page.locator('.cm-content').innerText();
        await page.locator('.cm-content').press('ControlOrMeta+Shift+k');
        await page.locator('#consoleContainer').waitFor({ state: 'hidden' });
        await menu('sql-console');
        assert.equal(await page.locator('.cm-content').innerText(), draft,
            'Toggling SQL while editing must preserve the draft, never delete its current line');
        await menu('sql-console');
    });
    await step('create WITHOUT ROWID table with literal default', async () => {
        await page.locator('#btnOpenCreateTable').click();
        await page.locator('#newTableName').fill('created_ui');
        const first = page.locator('.column-def-row').first();
        await first.locator('.col-name').fill('key');
        await first.locator('.col-type').selectOption('TEXT');
        await first.locator('.col-pk').check();
        await page.locator('#btnAddColumnDef').click();
        const second = page.locator('.column-def-row').nth(1);
        await second.locator('.col-name').fill('note');
        await second.locator('.col-type').selectOption('TEXT');
        await second.locator('.col-default').fill('hello');
        await page.locator('#newTableWithoutRowid').check();
        await page.locator('#btnSubmitCreateTable').click();
        await page.locator('#createTableModal').waitFor({ state: 'hidden' });
        await page.locator('.list-item[data-name="created_ui"][data-type="table"]').click();
        await page.locator('.header-cell[data-column="key"]').waitFor();
        await page.locator('#btnAddRow').click();
        await page.locator('#addRowForm input[data-column="key"]').fill('one');
        await page.locator('#btnSubmitAddRow').click();
        await page.locator('#addRowModal').waitFor({ state: 'hidden' });
        await saveDb();
        assert.match(sqlite(primaryDb, "SELECT sql FROM sqlite_master WHERE name='created_ui';"), /WITHOUT ROWID/i);
        assert.equal(sqlite(primaryDb, 'SELECT note FROM created_ui;'), 'hello');
    });
    await step('CSV import preview defaults, stored rows, and undo', async () => {
        await page.locator('#btnImportData').click();
        await page.locator('#importDataModal').waitFor({ state: 'visible' });
        assert.equal(await page.locator('#importTargetTable').inputValue(), 'created_ui');
        await page.waitForFunction(() => document.querySelectorAll('#importPreview tbody tr').length === 3);
        assert.match(await page.locator('#importPreviewLabel').innerText(), /first 3 of 3/);
        const defaults = await page.locator('#importPreview tbody tr td:nth-child(2)').allTextContents();
        assert.deepEqual(defaults, ["DEFAULT 'hello'", "DEFAULT 'hello'", "DEFAULT 'hello'"]);
        await page.screenshot({ path: join(evidence, '03-import-preview.png') });
        await page.locator('#btnSubmitImport').click();
        await page.locator('#importDataModal').waitFor({ state: 'hidden' });
        await page.waitForFunction(() => document.querySelectorAll('.data-row').length === 4);
        await saveDb();
        assert.equal(sqlite(primaryDb, "SELECT key || ':' || note FROM created_ui WHERE key LIKE 'import-%' ORDER BY key;"),
            'import-1:hello\nimport-2:hello\nimport-3:hello');
        await page.locator('#statusText').click();
        await page.keyboard.press('Control+z');
        await page.waitForFunction(() => document.querySelectorAll('.data-row').length === 1);
        await saveDb();
        assert.equal(sqlite(primaryDb, "SELECT key || ':' || note FROM created_ui;"), 'one:hello');
    });
    await step('large TEXT pages, stored UTF-16 Hex, and complete-cell download', async () => {
        await table('cells');
        await cell(1, 1).dblclick();
        await page.locator('#blob-inspector-modal').waitFor({ state: 'visible' });
        await page.waitForFunction(() => document.querySelector('#blob-info')?.textContent.includes('Loaded'));
        assert.ok(await page.locator('#tab-preview pre').evaluate(pre => pre.textContent.length <= 65536));
        await page.locator('#tab-preview').getByRole('button', { name: 'Next', exact: true }).click();
        assert.equal(await page.locator('#tab-preview input[aria-label="Text preview page"]').inputValue(), '2');
        await page.locator('#tab-preview pre').focus();
        await page.keyboard.press('Control+a');
        assert.ok(await page.locator('#tab-preview pre').evaluate(pre => {
            const clipboardData = new DataTransfer();
            pre.dispatchEvent(new ClipboardEvent('copy', { clipboardData, bubbles: true, cancelable: true }));
            return clipboardData.getData('text/plain') === pre.textContent;
        }), 'Select All and Copy must preserve every character on the displayed page');
        await page.locator('.tab-btn[data-tab="hex"]').click();
        assert.match((await page.locator('.hex-dump').innerText()).slice(0, 80), /^00000000\s+71 67 ac 4e 3d d8 00 de\s+0a 00/i);
        await page.locator('#blob-save-full-btn').click();
        await page.waitForFunction(() => document.querySelector('#statusText')?.textContent.includes('Saved full cell content'));
        const exported = await readFile(saves.at(-1).path);
        assert.deepEqual(exported, Buffer.from(longText, 'utf16le'));
        assert.equal(exported.toString('hex').toUpperCase(), sqlite(primaryDb, 'SELECT hex(body) FROM cells WHERE id=1;'));
        await page.screenshot({ path: join(evidence, '03-cell-hex.png') });
        await page.keyboard.press('Escape');
        await page.locator('#blob-inspector-modal').waitFor({ state: 'hidden' });
    });
    await step('BLOB Hex and byte-exact download', async () => {
        await table('people');
        await cell(1, 3).dblclick();
        await page.locator('#blob-inspector-modal').waitFor({ state: 'visible' });
        await page.locator('.tab-btn[data-tab="hex"]').click();
        assert.match(await page.locator('.hex-dump').innerText(), /^00000000\s+de ad be ef/i);
        const before = saves.length;
        await page.locator('#blob-download-btn').click();
        await page.waitForFunction(() => document.querySelector('#statusText')?.textContent.startsWith('Saved '));
        assert.equal(saves.length, before + 1);
        assert.deepEqual(await readFile(saves.at(-1).path), Buffer.from('deadbeef', 'hex'));
        await page.keyboard.press('Escape');
        await page.locator('#blob-inspector-modal').waitFor({ state: 'hidden' });
    });
    await step('cancel a large row deletion', async () => {
        await table('bulk');
        await page.locator('.row-select-all-button').click();
        await page.locator('#btnDeleteRows').click();
        await page.locator('#btnSubmitDelete').click();
        await page.locator('#destructiveConfirmModal').waitFor({ state: 'visible' });
        await page.locator('#destructiveConfirmModal .modal-cancel').click();
        await page.waitForFunction(() => document.querySelector('#statusText')?.textContent === 'Change cancelled');
        await page.locator('#deleteModal .modal-cancel').click();
        await saveDb();
        assert.equal(sqlite(primaryDb, 'SELECT count(*) FROM bulk;'), '1100');
    });
    await step('database switch restores table state and theme layout', async () => {
        await table('people');
        await page.locator('#filterInput').fill('Alice');
        await page.locator('#btnApplyFilter').click();
        await page.waitForFunction(() => document.querySelectorAll('.data-row').length === 1);
        nextPick = secondaryDb;
        await menu('open-db');
        await table('people');
        assert.match(await page.locator('#gridContainer').innerText(), /Second database/);
        await page.locator('.db-tab-select').filter({ hasText: 'primary.sqlite' }).click();
        await page.waitForFunction(() => document.querySelector('#filterInput')?.value === 'Alice'
            && document.querySelector('#gridContainer')?.textContent.includes('Alice edited'));
        assert.match(await page.locator('#gridContainer').innerText(), /Alice edited/);
        await menu('theme:light');
        assert.equal(await page.locator('html').evaluate(el => getComputedStyle(el).colorScheme), 'light');
        await page.screenshot({ path: join(evidence, '04-light-restored.png') });
        await menu('theme:dark');
        assert.equal(await page.locator('html').evaluate(el => getComputedStyle(el).colorScheme), 'dark');
    });
    await step('dirty database close prompts in-page, cancellation preserves edits, confirmation closes only its tab', async () => {
        await page.locator('.db-tab-select').filter({ hasText: 'secondary.sqlite' }).click();
        await table('people');
        await cell(9, 1).dblclick();
        await page.locator('.cell-input').fill('Pending tab close');
        await page.locator('.cell-input').press('Enter');
        await page.waitForFunction(() => document.querySelector('.db-tab-dirty'));
        await page.keyboard.press('ControlOrMeta+w');
        const prompt = page.locator('#destructiveConfirmModal');
        await prompt.waitFor({ state: 'visible' });
        assert.match(await prompt.innerText(), /secondary.sqlite.*unsaved/s);
        await prompt.getByRole('button', { name: 'Cancel', exact: true }).click();
        assert.equal(await cell(9, 1).innerText(), 'Pending tab close');
        assert.equal(await page.locator('.db-tab-select').count(), 2);
        await page.keyboard.press('ControlOrMeta+w');
        await prompt.getByRole('button', { name: 'Close without saving', exact: true }).click();
        await page.waitForFunction(() => document.querySelectorAll('.db-tab-select').length === 1);
        assert.equal(sqlite(secondaryDb, 'SELECT name FROM people WHERE id=9;'), 'Second database');
        assert.equal(sqlite(primaryDb, 'SELECT name FROM people WHERE id=1;'), 'Alice edited');
    });
    await writeFile(join(evidence, 'results.json'), JSON.stringify({ viewerDir, artifacts, saves, errors }, null, 2));
    console.log(`Evidence: ${evidence}`);
} catch (error) {
    await page?.screenshot({ path: join(evidence, 'failure.png') }).catch(() => {});
    await writeFile(join(evidence, 'failure.json'), JSON.stringify({ error: String(error), stack: error.stack, errors, saves }, null, 2));
    console.error(`FAIL. Evidence: ${evidence}`);
    if (errors.length) console.error('Browser errors:', errors);
    throw error;
} finally {
    await browser?.close();
    await new Promise(resolveClose => server.close(resolveClose));
}
