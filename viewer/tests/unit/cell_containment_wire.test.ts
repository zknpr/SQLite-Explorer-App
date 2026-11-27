/**
 * What a cell costs in the desktop native sidecar's reply frame, and what the
 * page containment does with a page that does not fit it.
 *
 * The containment costed every page as the webview carries it (a string at
 * its UTF-8 bytes, within 32 MiB), while the sidecar answers in one 16 MiB
 * JSON frame where each control character is a six-byte \uXXXX: 20 values of
 * 200,000 char(1) went out whole as 24 MB and the frame refused the page.
 * FRAME_CELL_WIRE (core/native/frame-codec.js) is the frame's own cost, checked
 * here against the codec's real output.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { encodeFrameValue, FRAME_CELL_WIRE, MAX_FRAME_BYTES } from '../../core/native/frame-codec.js';
import {
  containUnrepresentableTextCells,
  decodeCellContainment,
  remapPrimaryKeyContainment,
  remapShadowedRowIdContainment,
  VERIFIED_TEXT_BYTES,
  WEBVIEW_CELL_WIRE,
  type RawTextSlot
} from '../../src/core/cell-containment';
import { encodePrimaryKeyRecordId, encodeReadOnlyPrimaryKeyRecordId } from '../../src/core/row-identity';
import type { CellValue } from '../../src/core/types';

const frameBytes = (value: unknown): number => Buffer.byteLength(JSON.stringify(encodeFrameValue(value)), 'utf8');

/** A deterministic generator, so a failing string can be reproduced. */
function* seededStrings(count: number): Generator<string> {
  const pool = [
    ...Array.from({ length: 32 }, (_, code) => String.fromCharCode(code)),
    '"', '\\', '~', 'a', 'Z', '0', ' ', '\u007f', '\u0080', 'é', '\u07ff', '\u0800', '中', '\u2028', '\uffff',
    '\ud83d\ude00', '\ud800', '\udfff', '\udbff', '\udc00'
  ];
  let state = 0x9e3779b9;
  const next = () => {
    state ^= state << 13; state ^= state >>> 17; state ^= state << 5;
    return (state >>> 0) / 0x100000000;
  };
  for (let index = 0; index < count; index++) {
    const length = Math.floor(next() * 40);
    let value = '';
    for (let char = 0; char < length; char++) value += pool[Math.floor(next() * pool.length)];
    yield value;
  }
}

describe('a cell in the native reply frame', () => {
  it('costs a string exactly as the frame codec writes it', () => {
    const fixed = [
      '', 'plain', '"quoted"', 'back\\slash', '\b\t\n\f\r', '\u0000\u0001\u001f', '\u007f',
      '~', '~~marker', '~sqlite-explorer-non-finite:Infinity', 'é中\u2028', '\ud83d\ude00',
      'lone \ud800 high', 'lone \udc00 low', 'trailing \ud83d', '\u0001'.repeat(1000)
    ];
    for (const value of [...fixed, ...seededStrings(2000)]) {
      assert.equal(FRAME_CELL_WIRE.stringBytes!(value), frameBytes(value), JSON.stringify(value));
    }
  });

  it('costs numbers, BigInts and NULL exactly, and non-finite REALs at least as written', () => {
    for (const value of [0, -0, 1, -1, 9, 10, -10, 99, 100, 1234567890, -9007199254740991, 9007199254740991,
      0.1 + 0.2, 1e300, -1.7976931348623157e308, 5e-324, 123456789012345680000, 2 ** 53, 1e21]) {
      assert.equal(FRAME_CELL_WIRE.scalarBytes!(value), frameBytes(value), String(value));
    }
    for (const value of [0n, 9223372036854775807n, -9223372036854775808n]) {
      assert.equal(FRAME_CELL_WIRE.scalarBytes!(value), frameBytes(value), String(value));
    }
    assert.equal(FRAME_CELL_WIRE.scalarBytes!(null), frameBytes(null));
    for (const value of [Infinity, -Infinity, NaN]) {
      assert.ok(FRAME_CELL_WIRE.scalarBytes!(value) >= frameBytes(value), String(value));
    }
  });

  it('is the frame limit itself', () => {
    assert.equal(FRAME_CELL_WIRE.limitBytes, MAX_FRAME_BYTES);
  });
});

/** decodeCellContainment's input: the values, then the packed metadata column. */
const transported = (values: CellValue[]) => values.map(value => [value, '']);

describe('a page contained for the native reply frame', () => {
  const value = '\u0001'.repeat(200000);

  it('cuts the values the frame cannot carry to oversized cells and keeps every row', () => {
    const page = decodeCellContainment(transported(Array(20).fill(value)), 1, undefined, undefined, false, FRAME_CELL_WIRE);
    assert.equal(page.rows.length, 20);
    let whole = 0;
    page.rows.forEach((row, rowIndex) => {
      const clipped = page.oversizedCells?.[rowIndex]?.[0];
      if (clipped === undefined) {
        assert.equal(row[0], value, `row ${rowIndex} is whole or oversized`);
        whole++;
      } else {
        assert.deepEqual(clipped, { storageClass: 'text', byteLength: 200000 });
        assert.equal(row[0], '');
      }
    });
    assert.ok(whole > 0 && whole < 20, `${whole} whole`);
    // The answer fits the frame with the headroom the envelope and headers use.
    assert.ok(frameBytes(page) <= MAX_FRAME_BYTES - 512 * 1024, String(frameBytes(page)));
  });

  it('leaves the same page whole for the webview, and a plain one whole for the frame', () => {
    const webview = decodeCellContainment(transported(Array(20).fill(value)), 1);
    assert.equal(webview.oversizedCells, undefined);
    const plain = decodeCellContainment(transported(Array(20).fill('a'.repeat(200000))), 1, undefined, undefined, false, FRAME_CELL_WIRE);
    assert.equal(plain.oversizedCells, undefined);
    assert.ok(plain.rows.every(row => row[0] === 'a'.repeat(200000)));
  });

  it('measures exactly where the bounded first pass would clip', () => {
    // 100 values of 30,000 bytes: the bound (six bytes a unit) reaches the
    // frame, the exact JSON (plain ASCII, one byte a unit) does not.
    const ascii = 'b'.repeat(30000);
    const page = decodeCellContainment(transported(Array(100).fill(ascii)), 1, undefined, undefined, false, FRAME_CELL_WIRE);
    assert.equal(page.oversizedCells, undefined);
  });
});

describe('what the worker retries', () => {
  // worker.js contains a page again in less when a step refuses it with this
  // message; read from the worker so the two cannot drift apart.
  const workerSource = readFileSync(path.resolve(process.cwd(), 'worker/worker.js'), 'utf8');
  const refusal = new RegExp(/const CONTAINMENT_TRANSPORT_REFUSAL = \/(.+)\/;/.exec(workerSource)![1]);

  it('is what each identity step answers when the values left it no room', () => {
    const filled = Array.from({ length: 20 }, () => [1, '\u0001'.repeat(140000)] as CellValue[]);
    assert.throws(() => remapShadowedRowIdContainment({ rows: filled, wire: FRAME_CELL_WIRE }), refusal);
    assert.throws(() => containUnrepresentableTextCells({
      sourceRows: filled,
      rawTextRows: filled.map(() => [VERIFIED_TEXT_BYTES]),
      rawTextColumnIndices: [1],
      textEncoding: 'utf-8',
      contained: { rows: filled },
      wire: FRAME_CELL_WIRE
    }), refusal);
    // The webview carries the same rows.
    assert.doesNotThrow(() => remapShadowedRowIdContainment({ rows: filled, wire: WEBVIEW_CELL_WIRE }));
  });
});

describe('the containment steps a frame page goes through', () => {
  it('keeps a raw-TEXT cell with no room for a byte prefix as an oversized cell, not a refused page', () => {
    // The decode left no room (the budget is the values' own size): the
    // unrepresentable cell cannot keep any of its bytes. Before, the pass
    // threw and the page was refused.
    const filled = '\u0001'.repeat(2000);
    const sourceRows = [[filled, 'x\u0000']];
    // Room for the value, the oversized entry and an empty preview, short of
    // the BLOB marker a byte prefix takes (12,110 keeps both bytes).
    const wire = { ...FRAME_CELL_WIRE, limitBytes: 512 * 1024 + 12080 };
    const page = containUnrepresentableTextCells({
      sourceRows,
      rawTextRows: [[VERIFIED_TEXT_BYTES, new Uint8Array([0x78, 0x00])]],
      rawTextColumnIndices: [0, 1],
      textEncoding: 'utf-8',
      contained: { rows: sourceRows.map(row => [...row]) },
      wire
    });
    assert.equal(page.rows[0][0], filled);
    assert.equal(page.rows[0][1], '');
    assert.deepEqual(page.oversizedCells?.[0]?.[1], { storageClass: 'text', byteLength: 2 });
  });

  it('gives the tail\'s byte prefixes up to empty previews when the oversized entries leave no room', () => {
    // Each prefix is funded by what the cells after it still cost (5 bytes as
    // text); their entries then cost more. Before, that page was refused.
    const count = 100;
    const sourceRows = Array.from({ length: count }, () => ['ab\u0000']);
    const contain = (extraBytes: number) => containUnrepresentableTextCells({
      sourceRows,
      rawTextRows: sourceRows.map(() => [new Uint8Array([0x61, 0x62, 0x00])]),
      rawTextColumnIndices: [0],
      textEncoding: 'utf-8',
      contained: { rows: sourceRows.map(row => [...row]) },
      wire: { ...WEBVIEW_CELL_WIRE, limitBytes: 512 * 1024 + extraBytes }
    });
    const shape = (page: ReturnType<typeof contain>) => page.rows
      .map(row => row[0] instanceof Uint8Array ? 'P' : row[0] === '' ? 'E' : '?').join('');
    const tight = contain(8000);
    assert.match(shape(tight), /^P+E+$/);
    assert.equal(Object.keys(tight.oversizedCells ?? {}).length, count);
    // With room, every cell keeps its prefix, as before.
    assert.equal(shape(contain(100_000)), 'P'.repeat(count));
  });

  it('keeps the oversized entries it must add within the page when the values filled their own budget', () => {
    // A later frame attempt: the decode filled the values' budget to within
    // a few bytes, and each NUL-bearing cell needs an oversized entry. Within
    // the page's limit (fitWire) there is room for them; within the values'
    // there never is, however far the values give way, and the page was
    // refused at every attempt.
    const count = 200;
    const filled = '\u0001'.repeat(1000);
    const sourceRows = Array.from({ length: count }, () => [filled, 'x\u0000'] as CellValue[]);
    const contained = { rows: sourceRows.map(row => [...row]) };
    // The rows as the frame writes them (cell-containment.ts estimateRowsWireBytes).
    const rowBytes = 3 + FRAME_CELL_WIRE.stringBytes!(filled) + FRAME_CELL_WIRE.stringBytes!('x\u0000');
    const pageBytes = 2 + (count - 1) + count * rowBytes;
    const input = (fitExtraBytes?: number) => ({
      sourceRows,
      rawTextRows: sourceRows.map((): RawTextSlot[] => [VERIFIED_TEXT_BYTES, new Uint8Array([0x78, 0x00])]),
      rawTextColumnIndices: [0, 1],
      textEncoding: 'utf-8' as const,
      contained: { rows: contained.rows.map(row => [...row]) },
      wire: { ...FRAME_CELL_WIRE, limitBytes: 512 * 1024 + pageBytes + 8 },
      ...(fitExtraBytes === undefined ? {} : { fitWire: { ...FRAME_CELL_WIRE, limitBytes: 512 * 1024 + pageBytes + fitExtraBytes } })
    });
    // Control: within the values' budget alone the entries do not fit.
    assert.throws(() => containUnrepresentableTextCells(input()), /Raw TEXT containment cannot fit this page/);
    const page = containUnrepresentableTextCells(input(64 * 1024));
    assert.equal(page.rows.length, count);
    page.rows.forEach((row, rowIndex) => {
      assert.equal(row[0], filled);
      assert.deepEqual(page.oversizedCells?.[rowIndex]?.[1], { storageClass: 'text', byteLength: 2 });
      // No prefix: those are funded by the values' budget, which is full.
      assert.equal(row[1], '');
    });
    // The page's own limit still holds.
    assert.throws(() => containUnrepresentableTextCells(input(100)), /within the \d+-byte transport limit/);
  });

  it('names a cell cut for the page\'s room by its stored length where the stored bytes are known', () => {
    // The decode names a cell it cuts for room by its decoded string's UTF-8
    // length: 's' + 0xFF + 'abc' decodes to 's\uFFFDabc', 7 bytes for 5
    // stored, and UTF-16 TEXT 'ab' to 2 for 4. The grid and inspector showed
    // that number as the cell's size.
    const page = (textEncoding: 'utf-8' | 'utf-16le', decoded: string, stored: Uint8Array, entryBytes: number) => {
      const contained = {
        rows: [[''], ['']] as CellValue[][],
        oversizedCells: {
          0: { 0: { storageClass: 'text' as const, byteLength: entryBytes } },
          // A SQL prefix: no stored bytes here, SQLite's own length kept.
          1: { 0: { storageClass: 'text' as const, byteLength: 9000 } }
        }
      };
      const result = containUnrepresentableTextCells({
        sourceRows: [[decoded], ['x'.repeat(10)]],
        rawTextRows: [[stored], [null]],
        rawTextColumnIndices: [0],
        textEncoding,
        contained,
        decodedWithinBudget: true
      });
      // The input is left as it was.
      assert.equal(contained.oversizedCells[0][0].byteLength, entryBytes);
      return result;
    };
    const invalid = page('utf-8', 's\uFFFDabc', new Uint8Array([0x73, 0xff, 0x61, 0x62, 0x63]), 7);
    assert.deepEqual(invalid.oversizedCells?.[0]?.[0], { storageClass: 'text', byteLength: 5 });
    assert.deepEqual(invalid.oversizedCells?.[1]?.[0], { storageClass: 'text', byteLength: 9000 });
    assert.deepEqual(invalid.rows, [[''], ['']]);
    const utf16 = page('utf-16le', 'ab', new Uint8Array([0x61, 0x00, 0x62, 0x00]), 2);
    assert.deepEqual(utf16.oversizedCells?.[0]?.[0], { storageClass: 'text', byteLength: 4 });
  });

  it('names a key cut for the reply, not for its size, as the reply that had no room', () => {
    const identity = { kind: 'primaryKey' as const, columns: [{ identifier: 'k', declaredType: 'TEXT', position: 1 }] };
    const remapped = remapPrimaryKeyContainment({
      identity,
      sourceColumns: ['k', 'v'],
      visibleColumnCount: 2,
      identityRows: [['key-1', 1], ['key-2', 2]],
      rawTextBytes: [[VERIFIED_TEXT_BYTES], [VERIFIED_TEXT_BYTES]],
      rawTextColumnIndices: [0],
      textEncoding: 'utf-8',
      // Row 0's key was cut by the budget (5 bytes, within the 8,388-byte
      // limit); row 1's was cut for its size.
      rows: [['', 1], ['', 2]],
      oversizedCells: { 0: { 0: { storageClass: 'text', byteLength: 5 } }, 1: { 0: { storageClass: 'text', byteLength: 9000 } } },
      effectiveInlineCellBytes: 8388
    });
    assert.match(remapped.readOnlyRowReasons![0], /exceeds the page transport budget/);
    assert.doesNotMatch(remapped.readOnlyRowReasons![0], /inline limit/);
    assert.match(remapped.readOnlyRowReasons![1], /9000 bytes and exceeds the 8388-byte inline limit/);
  });
});

describe('the rounds native-host.js gives a page answer that does not fit the frame', () => {
  // The worker's own offer (worker.js offerFrameContainment and the two
  // functions it calls), driven as sendGuarded drives it, against a page of
  // coarse cells whose encode comes out over the estimate. Read from the
  // worker so the two cannot drift apart.
  const root = process.cwd();
  const workerSource = readFileSync(path.resolve(root, 'worker/worker.js'), 'utf8');
  const hostSource = readFileSync(path.resolve(root, 'core/native/native-host.js'), 'utf8');
  const functionSource = (source: string, name: string): string => {
    const start = source.indexOf(`function ${name}(`);
    assert.ok(start >= 0, name);
    let depth = 0;
    for (let index = source.indexOf('{', source.indexOf(')', start)); index < source.length; index++) {
      if (source[index] === '{') depth++;
      else if (source[index] === '}' && --depth === 0) return source.slice(start, index + 1);
    }
    throw new Error(`unterminated ${name}`);
  };
  const constant = (source: string, name: string): string => new RegExp(`const ${name} = (.+);`).exec(source)![1];
  const rounds = Number(constant(hostSource, 'MAX_CONTAIN_AGAIN_ROUNDS'));
  /** A simulated answer: how many cells it kept and the frame its encode writes. */
  type Answer = { headers: string[]; cells: number; frameBytes: number; [offer: symbol]: unknown };
  // The worker's source is this repository's own, evaluated as the bundle
  // would run it; nothing outside the checkout reaches it.
  const load = (frameCellWire: typeof FRAME_CELL_WIRE | null) => new Function(
    'frameCellWire', 'WEBVIEW_CELL_WIRE', 'WEBVIEW_GRID_RESPONSE_HEADROOM_BYTES', 'getErrorMessage',
    [
      `const CONTAINMENT_TRANSPORT_REFUSAL = ${constant(workerSource, 'CONTAINMENT_TRANSPORT_REFUSAL')};`,
      `const MAX_CONTAINMENT_ATTEMPTS = ${constant(workerSource, 'MAX_CONTAINMENT_ATTEMPTS')};`,
      `const CONTAIN_AGAIN = ${constant(workerSource, 'CONTAIN_AGAIN')};`,
      `const FRAME_ENVELOPE_BYTES = ${constant(workerSource, 'FRAME_ENVELOPE_BYTES')};`,
      ...['containForEngine', 'offerFrameContainment', 'frameValueLimit', 'containWithinFrame']
        .map(name => functionSource(workerSource, name)),
      'return { containForEngine, offerFrameContainment, CONTAIN_AGAIN };'
    ].join('\n')
  )(frameCellWire, WEBVIEW_CELL_WIRE, 512 * 1024, (error: Error) => error.message) as {
    containForEngine: (
      containPage: (valueWire: unknown, pageWire: unknown, cut?: { values?: number }) => Answer,
      headers: string[]
    ) => Answer;
    offerFrameContainment: (answer: Answer, containPage: unknown, valueLimit: number | null) => Answer;
    CONTAIN_AGAIN: symbol;
  };
  const offer = load(FRAME_CELL_WIRE);

  /** What sendGuarded does: send, and contain again while the frame is over, up to its rounds. */
  const send = (hiddenBytes: number) => {
    const cellBytes = 1_200_002;
    // The values keep whole cells within their budget; the encode writes
    // hiddenBytes more than the containment counted.
    const containPage = (valueWire: { limitBytes: number }): Answer => {
      const cells = Math.min(20, Math.floor((valueWire.limitBytes - 512 * 1024) / cellBytes));
      return { headers: ['v'], cells, frameBytes: cells * cellBytes + hiddenBytes + 200 };
    };
    let answer = offer.offerFrameContainment({ headers: ['v'], cells: 20, frameBytes: 24_000_200 }, containPage, null);
    for (let round = 0; round < rounds && answer.frameBytes > MAX_FRAME_BYTES; round++) {
      answer = (answer[offer.CONTAIN_AGAIN] as (frameBytes: number, limitBytes: number) => Answer)(
        answer.frameBytes, MAX_FRAME_BYTES);
    }
    return answer;
  };

  it('fits in one round when the frame is what the containment counted', () => {
    const sent = send(0);
    assert.ok(sent.frameBytes <= MAX_FRAME_BYTES);
    assert.equal(sent.cells, 13);
  });

  it('gives up whole cells in a later round when the encode came out over the count', () => {
    // A megabyte more than counted: the first round keeps 13 cells and is
    // 23 KB over. Before, each later round took 25 KB off a budget the 13
    // cells did not fill, so it kept the same 13 and the page was refused.
    const sent = send(1_200_000);
    assert.ok(sent.frameBytes <= MAX_FRAME_BYTES, String(sent.frameBytes));
    assert.ok(sent.cells < 13);
  });

  /** containWithinFrame through the offer's first round, with the containment each attempt runs. */
  const firstRound = (containPage: (valueWire: { limitBytes: number }, pageWire: unknown, cut?: { values?: number }) => Answer) => {
    const answer = offer.offerFrameContainment({ headers: ['v'], cells: 1, frameBytes: 24_000_200 }, containPage, null);
    return (answer[offer.CONTAIN_AGAIN] as (frameBytes: number, limitBytes: number) => Answer)(24_000_200, MAX_FRAME_BYTES);
  };
  const refusal = 'Cell containment cannot fit this page within the 17301504-byte transport limit';

  it('refuses after one attempt a page whose values themselves do not fit, without saying values were cut', () => {
    // The values refused: nothing reported cut. A smaller budget cuts the
    // same values and refuses again, so the attempts after the first only
    // cost the page's time (and its database's queue).
    let attempts = 0;
    assert.throws(() => firstRound(() => { attempts++; throw new Error(refusal); }), (error: Error) => {
      assert.match(error.message, /16777216-byte reply frame, and cutting its values to previews cannot make it fit/);
      assert.doesNotMatch(error.message, /even with its values cut/);
      return true;
    });
    assert.equal(attempts, 1);
  });

  it('tries again after a later step refused, though the attempt before cut nothing', () => {
    // A smaller budget cuts values only once it falls below what they cost:
    // here the values fit the first two budgets whole (nothing emptied), a
    // later step refused both, and the third budget cut and fitted.
    const attempts: number[] = [];
    const answer = firstRound((valueWire, _pageWire, cut) => {
      attempts.push(valueWire.limitBytes);
      if (cut) cut.values = attempts.length < 3 ? 0 : 5;
      if (attempts.length < 3) throw new Error(refusal);
      return { headers: ['v'], cells: 1, frameBytes: 100 };
    });
    assert.equal(answer.frameBytes, 100);
    assert.equal(attempts.length, 3);
    assert.ok(attempts.every((limit, index) => index === 0 || limit < attempts[index - 1]));
  });

  it('says values were cut only when the last attempt cut some', () => {
    const refuse = (values: number) => {
      let attempts = 0;
      let message = '';
      try {
        firstRound((_valueWire, _pageWire, cut) => {
          attempts++;
          if (cut) cut.values = values;
          throw new Error(refusal);
        });
      } catch (error) {
        message = (error as Error).message;
      }
      return { attempts, message };
    };
    const none = refuse(0);
    assert.equal(none.attempts, 4);
    assert.equal(none.message, "This page does not fit the native engine's 16777216-byte reply frame");
    const some = refuse(3);
    assert.equal(some.attempts, 4);
    assert.match(some.message, /16777216-byte reply frame, even with its values cut to previews$/);
  });

  it('lets tail rows give up their key cells on a frame round when read-only identities cannot make room', () => {
    // 50 keys of 1,005 control characters: 6 KB each in the frame, and an
    // editable identity repeating each key costs 8 KB more. The values left
    // 250 KB, less than the keys themselves, so read-only identities for every
    // row still left the page too large: it was refused, and the next frame
    // attempt cut the values for a page with fewer editable rows than fit.
    // As above, the worker's own source.
    const remapGivingWayKeys = new Function(
      'remapPrimaryKeyContainment', 'getErrorMessage',
      [
        `const CONTAINMENT_TRANSPORT_REFUSAL = ${constant(workerSource, 'CONTAINMENT_TRANSPORT_REFUSAL')};`,
        ...['remapGivingWayKeys', 'utf8ByteLength'].map(name => functionSource(workerSource, name)),
        'return remapGivingWayKeys;'
      ].join('\n')
    )(remapPrimaryKeyContainment, (error: Error) => error.message) as typeof remapPrimaryKeyContainment;
    const identity = { kind: 'primaryKey' as const, columns: [{ identifier: 'k', declaredType: 'TEXT', position: 1 }] };
    const count = 50;
    const keys = Array.from({ length: count }, (_, index) => `K${String(index).padStart(4, '0')}` + '\u0001'.repeat(1000));
    const input = {
      identity,
      sourceColumns: ['k', 'v'],
      visibleColumnCount: 2,
      identityRows: keys.map((key, index) => [key, index]),
      rawTextBytes: keys.map((): RawTextSlot[] => [VERIFIED_TEXT_BYTES]),
      rawTextColumnIndices: [0],
      textEncoding: 'utf-8' as const,
      rows: keys.map((key, index) => [key, index]),
      effectiveInlineCellBytes: 1048576,
      wire: { ...FRAME_CELL_WIRE, limitBytes: 512 * 1024 + 250_000 }
    };
    // Control: identities alone give way, and cannot fit it.
    assert.throws(() => remapPrimaryKeyContainment(input), /Cell containment cannot fit this page within the \d+-byte transport limit/);
    const page = remapGivingWayKeys(input);
    const editable = page.rows.filter(row => String(row[0]).startsWith('pk:')).length;
    // The earliest rows keep their key and identity, as the decode keeps a
    // page's earliest cells; every later row is read-only, saying the reply
    // had no room, the first of them giving up its identity before its key,
    // the rest their keys too.
    page.rows.forEach((row, rowIndex) => {
      if (rowIndex < editable) {
        assert.equal(row[0], encodePrimaryKeyRecordId(identity.columns, [keys[rowIndex]]));
        assert.equal(row[1], keys[rowIndex]);
        assert.equal(page.readOnlyRowReasons?.[rowIndex], undefined);
        return;
      }
      assert.match(page.readOnlyRowReasons![rowIndex], /exceeds the page transport budget/);
      if (rowIndex === editable && row[1] === keys[rowIndex]) return;
      assert.equal(row[1], '');
      assert.deepEqual(page.oversizedCells?.[rowIndex]?.[1], { storageClass: 'text', byteLength: 1005 });
    });
    // The input is left as it was: a frame attempt may contain it again.
    assert.equal(input.rows[count - 1][0], keys[count - 1]);
    // As many editable rows as fit beside the read-only rest: each costs its
    // key and identity, a read-only row its token, reason and cut entry.
    const editableBytes = FRAME_CELL_WIRE.stringBytes!(keys[0])
      + FRAME_CELL_WIRE.stringBytes!(String(encodePrimaryKeyRecordId(identity.columns, [keys[0]])));
    const readOnlyBytes = 250 + FRAME_CELL_WIRE.stringBytes!(String(encodeReadOnlyPrimaryKeyRecordId(
      'Row is read-only because its encoded WITHOUT ROWID primary-key identity exceeds the page transport budget.', 0)));
    const expected = Math.floor((250_000 - count * readOnlyBytes) / (editableBytes - readOnlyBytes));
    assert.ok(Math.abs(editable - expected) <= 1, `${editable} editable, about ${expected} expected`);
    // A page whose keys cannot be cut keeps its refusal.
    const integerKeys = { ...input, identityRows: keys.map((_key, index) => [index, keys[index]]), rows: keys.map((key, index) => [index, key]),
      sourceColumns: ['k', 'v'], wire: { ...FRAME_CELL_WIRE, limitBytes: 512 * 1024 + 1000 } };
    assert.throws(() => remapGivingWayKeys(integerKeys), /Cell containment cannot fit this page/);
  });

  it('contains a WebAssembly page once, as the webview carries it, and offers nothing', () => {
    // The WebAssembly worker has no frame: one pass with the webview's
    // wires, as before the frame was counted, and a refusal is the answer.
    const wasm = load(null);
    const calls: unknown[][] = [];
    const answer = wasm.containForEngine((valueWire, pageWire) => {
      calls.push([valueWire, pageWire]);
      return { headers: ['v'], cells: 1, frameBytes: 0 };
    }, ['v']);
    assert.deepEqual(calls, [[WEBVIEW_CELL_WIRE, WEBVIEW_CELL_WIRE]]);
    assert.equal(Object.getOwnPropertySymbols(answer).length, 0);
    let refusals = 0;
    assert.throws(() => wasm.containForEngine(() => {
      refusals++;
      throw new Error('Cell containment cannot fit this page within the 33554432-byte transport limit');
    }, ['v']), /33554432-byte transport limit/);
    assert.equal(refusals, 1);
  });
});
