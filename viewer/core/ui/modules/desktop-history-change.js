/**
 * The record identities a desktop undo or redo changed, for the page's
 * refreshContent (desktop-viewer.js refreshContentOnce).
 *
 * Mirrors historyRowIdentityChange in src/editorController.ts, the VS Code
 * host's refresh after a history change: the same rules and the same size
 * cap. Keep the two in step. One addition: a desktop import records its rows
 * as `importedRows` (ImportedRowSnapshots, desktop-host.js buildModification),
 * a shape no VS Code history entry carries, so undoing an import names those
 * rows as removed too. Without it the page would keep pins on rows the undo
 * deleted, and a later insert that reuses a rowid would inherit the pin.
 *
 * Only the entry's own rows are known: rows that triggers or foreign-key
 * actions change are not reported.
 */

// A refresh carries at most this many characters of record ids. A larger
// change names none, and the page then clears its pins as for any change it
// cannot account for.
export const MAX_ROW_IDENTITY_CHANGE_CHARS = 1024 * 1024;

/**
 * The records `modification`, applied forward or undone, removed from its
 * table or moved to another rowid or key; undefined when they cannot be named.
 *
 * @param {Record<string, any>} modification a ModificationEntry
 * @param {'forward' | 'undo'} direction
 * @returns {{ table: string | undefined, removedRowIds: Array<string | number>,
 *   movedRowIds: Array<[string | number, string | number]> } | undefined}
 */
export function historyRowIdentityChange(modification, direction) {
    const undo = direction === 'undo';
    const removedRowIds = [];
    const movedRowIds = [];
    if (modification.modificationType === 'cell_update') {
        const moves = (modification.affectedCells ?? []).map(cell => [cell.rowId, cell.newRowId]);
        if (modification.targetRowId !== undefined) {
            moves.unshift([modification.targetRowId, modification.newTargetRowId]);
        }
        for (const [before, after] of moves) {
            if (after === undefined || after === before) continue;
            movedRowIds.push(undo ? [after, before] : [before, after]);
        }
    } else if (modification.modificationType === 'row_delete' && !undo) {
        for (const id of modification.affectedRowIds ?? modification.deletedRows?.map(row => row.rowId) ?? []) {
            removedRowIds.push(id);
        }
    } else if (modification.modificationType === 'row_insert' && undo) {
        for (const row of [modification.insertedRow, ...(modification.insertedRows ?? [])]) {
            if (row) removedRowIds.push(row.rowId);
        }
        if (modification.importedRows !== undefined) {
            // The worker's replay refuses an unreadable entry before any refresh;
            // should one get here anyway, name nothing rather than guess.
            const rows = modification.importedRows?.rows;
            if (!Array.isArray(rows) || !rows.every(row => row?.rowId !== undefined)) return undefined;
            for (const row of rows) removedRowIds.push(row.rowId);
        }
    }
    let chars = 0;
    for (const id of [removedRowIds, movedRowIds].flat(2)) {
        chars += String(id).length + 1;
        if (chars > MAX_ROW_IDENTITY_CHANGE_CHARS) return undefined;
    }
    return { table: modification.targetTable, removedRowIds, movedRowIds };
}

/**
 * The `contentChange` a refresh after this history step hands the page, as
 * the VS Code host builds it (editorController.ts onDidChangeContent); undefined
 * for an entry with no type, which then gets the full refresh.
 *
 * @param {Record<string, any>} modification a ModificationEntry
 * @param {'forward' | 'undo'} direction
 */
export function historyContentChange(modification, direction) {
    const modificationType = modification.modificationType;
    if (!modificationType) return undefined;
    const rowIdentity = historyRowIdentityChange(modification, direction);
    return { modificationType, ...(rowIdentity ? { rowIdentity } : {}) };
}
