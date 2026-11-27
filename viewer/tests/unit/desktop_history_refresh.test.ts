/**
 * Desktop undo/redo refreshes: the 1.9.0 history-change contract, ported.
 *
 * The VS Code host sends the page, with each refresh a history change caused,
 * the entry's modificationType and the record ids it removed or moved, and no
 * connection object (editorController.ts historyRowIdentityChange; rpc.js
 * refreshContent). The desktop host builds the same change in
 * desktop-history-change.js, and desktop-viewer.js refreshContentOnce applies
 * the same count, pin and refreshed-generation rules as rpc.js.
 *
 * refreshContentOnce lives in an entry point that boots a whole viewer on
 * import, so it is evaluated here from the shipped source with its
 * dependencies injected (the technique desktop_ui_surface.test.ts uses for
 * the shell-open lane).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const historyChangeModulePath = '../../core/ui/modules/desktop-history-change.js';

const viewerSource = () => readFileSync(path.resolve(process.cwd(), 'core/ui/desktop-viewer.js'), 'utf8');

/** `async function refreshContentOnce` from desktop-viewer.js, as runnable source. */
function refreshContentOnceSource(): string {
  const source = viewerSource();
  const start = source.indexOf('async function refreshContentOnce(');
  assert.notEqual(start, -1, 'desktop-viewer.js no longer defines refreshContentOnce');
  const end = source.indexOf('\n}\n', start);
  assert.notEqual(end, -1, 'could not find the end of refreshContentOnce');
  return source.slice(start, end + 2);
}

type Page = ReturnType<typeof makePage>;

/**
 * A page around the shipped refreshContentOnce: a plain state object and
 * recording stubs for every module function it calls.
 */
function makePage(options: { hasTriggers?: boolean } = {}) {
  const calls: Array<[string, ...unknown[]]> = [];
  const record = (name: string) => (...args: unknown[]) => { calls.push([name, ...args]); };
  const state: Record<string, any> = {
    dbId: 'db-1',
    isDbConnected: true,
    isReadOnly: false,
    reloadRequiredReason: null,
    connectionGeneration: 1,
    contentGeneration: 0,
    refreshedContentGeneration: 0,
    isRefreshingContent: false,
    selectedTable: 'items',
    selectedTableType: 'table',
    selectedTableIdentity: null,
    pinnedRowIds: new Set<unknown>(),
    pinnedColumns: new Set<string>(),
    editingCellInfo: null,
    activeCellInput: null,
    schemaCache: {
      tables: [{ name: 'items' }, { name: 'other' }],
      views: [],
      indexes: [],
      ...('hasTriggers' in options ? { hasTriggers: options.hasTriggers } : {})
    }
  };
  // What the next schema load answers; the desktop's engines never report
  // hasTriggers, so neither does this by default.
  let schemaAnswer: Record<string, unknown> = { tables: [{ name: 'items' }, { name: 'other' }], views: [], indexes: [] };
  let loadTableDataResult: Promise<unknown> | unknown = true;
  let loadTableColumnsResult: unknown = true;
  const page = {
    state,
    calls,
    names: () => calls.map(([name]) => name),
    setSchemaAnswer(answer: Record<string, unknown>) { schemaAnswer = answer; },
    setLoadTableData(result: Promise<unknown> | unknown) { loadTableDataResult = result; },
    setLoadTableColumns(result: unknown) { loadTableColumnsResult = result; },
    deps: {
      state,
      invalidateAllCounts: record('invalidateAllCounts'),
      keepTableRowCounts: record('keepTableRowCounts'),
      persistState: record('persistState'),
      updateMutationControlCapabilities: () => {},
      applyConnectionResult: (result: Record<string, unknown>) => {
        calls.push(['applyConnectionResult', result]);
        state.isDbConnected = result.connected === true;
        if (typeof result.connectionGeneration === 'number') state.connectionGeneration = result.connectionGeneration;
        return state.isDbConnected;
      },
      updateEngineBadge: record('updateEngineBadge'),
      reportReadOnlyReason: record('reportReadOnlyReason'),
      closeDatabaseTargetModals: record('closeDatabaseTargetModals'),
      clearSelection: () => {},
      updateToolbarButtons: () => {},
      showErrorState: record('showErrorState'),
      updateStatus: record('updateStatus'),
      clearContentStatus: record('clearContentStatus'),
      showLoading: record('showLoading'),
      showEmptyState: record('showEmptyState'),
      refreshSchema: async () => {
        calls.push(['refreshSchema', state.schemaCache.hasTriggers]);
        state.schemaCache = { ...schemaAnswer };
        return true;
      },
      loadTableColumns: async () => { calls.push(['loadTableColumns']); return loadTableColumnsResult; },
      loadTableData: async (...args: unknown[]) => { calls.push(['loadTableData', ...args]); return loadTableDataResult; },
      refreshConsoleSchema: record('refreshConsoleSchema'),
      isConsoleOpen: () => true,
      applyConsoleAvailability: record('applyConsoleAvailability'),
      document: { getElementById: () => ({ textContent: '', innerHTML: '' }) }
    } as Record<string, unknown>
  };
  const names = Object.keys(page.deps);
  const refreshContentOnce = new Function(...names, `${refreshContentOnceSource()}\nreturn refreshContentOnce;`)(
    ...names.map(name => page.deps[name])
  ) as (filename: string, connectionResult?: unknown, contentChange?: unknown) => Promise<Record<string, unknown>>;
  return { ...page, refreshContentOnce };
}

const CONNECTION = { connected: true, readOnly: false, connectionGeneration: 1, engine: 'wasm' };

test('a cell edit\'s undo/redo keeps table row counts only when the last schema load found no trigger', async () => {
  const counted = async (page: Page, connection: unknown, change: unknown) => {
    page.calls.length = 0;
    await page.refreshContentOnce('qa.db', connection, change);
    return page.calls.filter(([name]) => name === 'keepTableRowCounts' || name === 'invalidateAllCounts');
  };

  const triggerFree = makePage({ hasTriggers: false });
  assert.deepEqual(await counted(triggerFree, undefined, { modificationType: 'cell_update' }),
    [['keepTableRowCounts', ['items', 'other']]]);

  // Every other change, a connection object, or a schema that has a trigger
  // or does not say, drops every count.
  for (const [hasTriggers, connection, change] of [
    [false, undefined, { modificationType: 'row_insert' }],
    [false, undefined, { modificationType: 'row_delete' }],
    [false, undefined, undefined],
    [false, CONNECTION, { modificationType: 'cell_update' }],
    [true, undefined, { modificationType: 'cell_update' }],
    [undefined, undefined, { modificationType: 'cell_update' }]
  ] as const) {
    const page = makePage(hasTriggers === undefined ? {} : { hasTriggers });
    assert.deepEqual(await counted(page, connection, change), [['invalidateAllCounts']],
      JSON.stringify({ hasTriggers, connection: !!connection, change }));
  }
});

test('the trigger answer is cleared until the refresh\'s own schema load replaces it', async () => {
  const page = makePage({ hasTriggers: false });
  page.setSchemaAnswer({ tables: [{ name: 'items' }], views: [], indexes: [], hasTriggers: false });
  await page.refreshContentOnce('qa.db', undefined, { modificationType: 'cell_update' });
  // The schema load ran with no answer standing: an overlapping refresh
  // cannot keep counts on the strength of the schema before this change.
  assert.deepEqual(page.calls.find(([name]) => name === 'refreshSchema'), ['refreshSchema', undefined]);
  assert.equal(page.state.schemaCache.hasTriggers, false, 'the new load supplies the next answer');
});

test('pins stay on the records a history change moved and drop the records it removed', async () => {
  const page = makePage();
  for (const id of [1, 2, 3, 5]) page.state.pinnedRowIds.add(id);
  await page.refreshContentOnce('qa.db', undefined, {
    modificationType: 'cell_update',
    // A batch can shift keys along a chain: every move reads the pins as they were.
    rowIdentity: { table: 'items', removedRowIds: ['5'], movedRowIds: [[2, 3], [3, 4]] }
  });
  assert.deepEqual([...page.state.pinnedRowIds], [1, 3, 4]);
  assert.equal(page.names().filter(name => name === 'persistState').length, 1, 'changed pins are persisted');
});

test('pins are kept for another table\'s change and cleared for any change without record ids', async () => {
  const otherTable = makePage();
  for (const id of [1, 2]) otherTable.state.pinnedRowIds.add(id);
  await otherTable.refreshContentOnce('qa.db', undefined, {
    modificationType: 'row_delete', rowIdentity: { table: 'other', removedRowIds: [1], movedRowIds: [] }
  });
  assert.deepEqual([...otherTable.state.pinnedRowIds], [1, 2]);
  assert.equal(otherTable.names().includes('persistState'), false);

  for (const [connection, change] of [
    [undefined, undefined],
    [undefined, { modificationType: 'cell_update' }],
    [CONNECTION, { modificationType: 'cell_update', rowIdentity: { table: 'items', removedRowIds: [], movedRowIds: [] } }]
  ] as const) {
    const page = makePage();
    page.state.pinnedRowIds.add(1);
    await page.refreshContentOnce('qa.db', connection, change);
    assert.deepEqual([...page.state.pinnedRowIds], [], JSON.stringify({ connection: !!connection, change }));
  }
});

test('a refresh marks its generation refreshed only once its reload has succeeded', async () => {
  const loaded = makePage();
  assert.deepEqual(await loaded.refreshContentOnce('qa.db', undefined, { modificationType: 'cell_update' }), { success: true });
  assert.deepEqual(loaded.calls.find(([name]) => name === 'loadTableData'), ['loadTableData', false]);
  assert.equal(loaded.state.refreshedContentGeneration, loaded.state.contentGeneration);

  // No table to reload: the refresh is complete once the schema is in.
  const empty = makePage();
  empty.state.selectedTable = null;
  assert.deepEqual(await empty.refreshContentOnce('qa.db'), { success: true });
  assert.equal(empty.state.refreshedContentGeneration, empty.state.contentGeneration);
  assert.equal(empty.names().includes('showEmptyState'), true, 'the empty-state fallback still draws');

  // A superseded (undefined) or failed (false) row load, or failed columns,
  // leave the generation unmarked so a post-edit reload still runs. The
  // console's schema refresh happens all the same.
  for (const [columns, data] of [[true, undefined], [true, false], [false, true]] as const) {
    const page = makePage();
    page.setLoadTableColumns(columns);
    page.setLoadTableData(data);
    assert.deepEqual(await page.refreshContentOnce('qa.db', undefined, { modificationType: 'row_insert' }),
      { success: false }, JSON.stringify({ columns, data }));
    assert.equal(page.state.refreshedContentGeneration, 0, JSON.stringify({ columns, data }));
    assert.equal(page.state.isRefreshingContent, false);
    assert.equal(page.names().includes('refreshConsoleSchema'), true);
    assert.equal(page.names().includes('applyConsoleAvailability'), true);
  }
});

test('an older refresh that finishes after a newer one has started does not mark either generation', async () => {
  const page = makePage();
  let release!: (value: unknown) => void;
  page.setLoadTableData(new Promise(resolve => { release = resolve; }));
  const older = page.refreshContentOnce('qa.db', undefined, { modificationType: 'cell_update' });
  // Let the older refresh reach its row load.
  while (!page.names().includes('loadTableData')) await new Promise(resolve => setImmediate(resolve));
  page.state.contentGeneration += 1;      // a newer refresh has begun
  release(true);
  assert.deepEqual(await older, { success: true });
  assert.equal(page.state.refreshedContentGeneration, 0);
  assert.equal(page.state.isRefreshingContent, true, 'the newer refresh still owns the flag');
});

test('the desktop refresh keeps its connection-only behaviour: badge, read-only reason, reload-required state', async () => {
  const page = makePage();
  await page.refreshContentOnce('qa.db', { ...CONNECTION, readOnlyReason: 'read-only mount' });
  assert.deepEqual(page.calls.find(([name]) => name === 'updateEngineBadge'), ['updateEngineBadge', 'wasm']);
  assert.deepEqual(page.calls.find(([name]) => name === 'reportReadOnlyReason'), ['reportReadOnlyReason', 'read-only mount']);

  // A history refresh carries no connection object: none of that is re-applied.
  page.calls.length = 0;
  await page.refreshContentOnce('qa.db', undefined, { modificationType: 'cell_update' });
  for (const name of ['applyConnectionResult', 'updateEngineBadge', 'reportReadOnlyReason']) {
    assert.equal(page.names().includes(name), false, name);
  }

  const retired = makePage();
  retired.state.reloadRequiredReason = 'The file was replaced.';
  assert.deepEqual(await retired.refreshContentOnce('qa.db', undefined, { modificationType: 'cell_update' }),
    { success: false, reloadRequired: true });
  assert.equal(retired.names().includes('refreshSchema'), false);
  assert.equal(retired.state.refreshedContentGeneration, 0);
});

test('a refresh expires a completed action\'s status before its first read, as rpc.js does', async () => {
  // An undo of the row insert whose "Row inserted" status asked to be cleared
  // on the next content refresh (crud.js, updateStatus clearOnRefresh).
  const page = makePage();
  await page.refreshContentOnce('qa.db', undefined, { modificationType: 'row_insert' });
  const names = page.names();
  assert.equal(names.filter(name => name === 'clearContentStatus').length, 1);
  assert.ok(names.indexOf('clearContentStatus') < names.indexOf('refreshSchema'),
    'expired before the schema read, so a newer status set meanwhile survives');

  // A retired connection's refresh, which reads nothing, expires it too.
  const retired = makePage();
  retired.state.reloadRequiredReason = 'The file was replaced.';
  await retired.refreshContentOnce('qa.db', undefined, { modificationType: 'row_insert' });
  assert.ok(retired.names().indexOf('clearContentStatus') !== -1
    && retired.names().indexOf('clearContentStatus') < retired.names().indexOf('updateStatus'));
});

test('webviewMethods.refreshContent forwards the history change to refreshContentOnce', () => {
  const forwarded = /async refreshContent\(filename, connectionResult, contentChange\) \{\n\s*const refresh = refreshContentOnce\(filename, connectionResult, contentChange\);/;
  assert.equal(forwarded.test(viewerSource()), true, 'refreshContent must pass contentChange through');
});

// ---------------------------------------------------------------------------
// desktop-history-change.js: the record ids a history step changed
// ---------------------------------------------------------------------------

test('a cell update reports its identity moves in the direction applied', async () => {
  const { historyRowIdentityChange } = await import(historyChangeModulePath);
  const modification = {
    modificationType: 'cell_update',
    targetTable: 'items',
    // The single-cell form some entries use, ahead of the batch's cells.
    targetRowId: 1,
    newTargetRowId: 2,
    affectedCells: [
      { rowId: 2, newRowId: 3, columnName: 'id' },
      { rowId: 7, newRowId: 7, columnName: 'name' },     // unchanged: not a move
      { rowId: 8, columnName: 'name' }                   // legacy, no newRowId
    ]
  };
  assert.deepEqual(historyRowIdentityChange(modification, 'forward'),
    { table: 'items', removedRowIds: [], movedRowIds: [[1, 2], [2, 3]] });
  assert.deepEqual(historyRowIdentityChange(modification, 'undo'),
    { table: 'items', removedRowIds: [], movedRowIds: [[2, 1], [3, 2]] });
});

test('row deletes and inserts report the rows each direction removes', async () => {
  const { historyRowIdentityChange } = await import(historyChangeModulePath);
  const deleted = { modificationType: 'row_delete', targetTable: 't', deletedRows: [{ rowId: 4 }, { rowId: 5 }] };
  assert.deepEqual(historyRowIdentityChange(deleted, 'forward'), { table: 't', removedRowIds: [4, 5], movedRowIds: [] });
  assert.deepEqual(historyRowIdentityChange(deleted, 'undo'), { table: 't', removedRowIds: [], movedRowIds: [] });
  // affectedRowIds, when an entry has it, names the rows.
  assert.deepEqual(historyRowIdentityChange({ ...deleted, affectedRowIds: [9] }, 'forward').removedRowIds, [9]);

  const inserted = { modificationType: 'row_insert', targetTable: 't', insertedRow: { rowId: 6 }, insertedRows: [{ rowId: 7 }] };
  assert.deepEqual(historyRowIdentityChange(inserted, 'undo'), { table: 't', removedRowIds: [6, 7], movedRowIds: [] });
  assert.deepEqual(historyRowIdentityChange(inserted, 'forward'), { table: 't', removedRowIds: [], movedRowIds: [] });

  const imported = {
    modificationType: 'row_insert', targetTable: 't',
    importedRows: { columns: ['a'], storageClassPatterns: [['text']], rows: [{ rowId: 1, values: ['x'], pattern: 0 }, { rowId: 2, values: ['y'], pattern: 0 }] }
  };
  assert.deepEqual(historyRowIdentityChange(imported, 'undo'), { table: 't', removedRowIds: [1, 2], movedRowIds: [] });
  assert.deepEqual(historyRowIdentityChange(imported, 'forward'), { table: 't', removedRowIds: [], movedRowIds: [] });
  // An import entry whose rows cannot be read names nothing, so the page clears its pins.
  for (const importedRows of [{}, { rows: 'x' }, { rows: [{ values: [] }] }, null]) {
    assert.equal(historyRowIdentityChange({ ...imported, importedRows }, 'undo'), undefined, JSON.stringify(importedRows));
  }

  // View history moves no records.
  assert.deepEqual(historyRowIdentityChange({ modificationType: 'view_drop', targetTable: 'v' }, 'undo'),
    { table: 'v', removedRowIds: [], movedRowIds: [] });
});

test('a change naming more than the size cap of record ids names none', async () => {
  const { historyRowIdentityChange, MAX_ROW_IDENTITY_CHANGE_CHARS } = await import(historyChangeModulePath);
  assert.equal(MAX_ROW_IDENTITY_CHANGE_CHARS, 1024 * 1024);
  // Each id costs its length plus one separator.
  const id = 'k'.repeat(1023);
  const rows = (count: number) => Array.from({ length: count }, () => ({ rowId: id }));
  const at = { modificationType: 'row_delete', targetTable: 't', deletedRows: rows(1024) };
  assert.equal(historyRowIdentityChange(at, 'forward')?.removedRowIds.length, 1024);
  const over = { ...at, deletedRows: [...rows(1024), { rowId: 1 }] };
  assert.equal(historyRowIdentityChange(over, 'forward'), undefined);
});

test('historyContentChange carries the entry type, and the record ids when they are known', async () => {
  const { historyContentChange } = await import(historyChangeModulePath);
  assert.deepEqual(historyContentChange({ modificationType: 'row_delete', targetTable: 't', deletedRows: [{ rowId: 1 }] }, 'forward'),
    { modificationType: 'row_delete', rowIdentity: { table: 't', removedRowIds: [1], movedRowIds: [] } });
  assert.deepEqual(historyContentChange({ modificationType: 'row_insert', targetTable: 't', importedRows: {} }, 'undo'),
    { modificationType: 'row_insert' });
  assert.equal(historyContentChange({ targetTable: 't' }, 'undo'), undefined);
});
