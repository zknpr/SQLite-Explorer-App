import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { MAX_FRAME_BYTES, encodeFrame, encodeFrameValue, decodeFrameValue } from '../../core/native/frame-codec.js';
import {
  MAX_NATIVE_TRANSFER_UNITS,
  NATIVE_TRANSFER_METHOD,
  REPLY_TRANSFER_METHODS,
  REQUEST_TRANSFER_METHODS,
  TRANSFER_PIECE_UNITS,
  encodeTransferText,
  exchangeNativeCall,
  sliceTransferText,
  transferPieceBounds,
  utf8Length,
  wirePieceUnits
} from '../../core/native/native-transfer.js';

const pushFrame = (piece: string, index = 0) => encodeFrame({
  channel: 'rpc',
  content: {
    kind: 'invoke', messageId: `rpc_${'9'.repeat(40)}_push${index}`, targetMethod: NATIVE_TRANSFER_METHOD,
    payload: ['push', 'req_999999999_1764000000000', index, 999999, MAX_NATIVE_TRANSFER_UNITS, piece]
  }
});
const pullFrame = (piece: string) => encodeFrame({
  channel: 'rpc',
  content: { kind: 'response', messageId: `rpc_${'9'.repeat(40)}_pull99999`, success: true, data: { id: 'reply_999999999', index: 99999, piece } }
});

test('a piece never ends between the two halves of a surrogate pair, and the pieces rejoin exactly', () => {
  for (let offset = 0; offset < 6; offset++) {
    const text = 'a'.repeat(offset) + '\u{1F600}'.repeat(40) + 'z';
    for (const maxUnits of [2, 3, 4, 5, 7]) {
      const pieces = sliceTransferText(text, maxUnits);
      assert.equal(pieces.join(''), text);
      for (const piece of pieces) {
        assert.ok(piece.length >= 1 && piece.length <= maxUnits, `piece of ${piece.length} units, max ${maxUnits}`);
        assert.ok(piece.isWellFormed(), `a lone surrogate at offset ${offset}, max ${maxUnits}`);
      }
    }
  }
  assert.deepEqual(transferPieceBounds('', 4), [0, 0]);
  assert.throws(() => transferPieceBounds('abc', 1), RangeError);
});

test('the worst-case piece still fits one frame, at the exact piece size', () => {
  // JSON.stringify output re-escaped inside a frame: three bytes a unit is the
  // most any of it costs (a BMP character past U+07FF), two for " and \.
  const threeByte = encodeTransferText(['\u20ac'.repeat(TRANSFER_PIECE_UNITS)]).slice(2, 2 + TRANSFER_PIECE_UNITS);
  const quotes = '"'.repeat(TRANSFER_PIECE_UNITS);
  const backslashes = '\\'.repeat(TRANSFER_PIECE_UNITS);
  // A piece that starts with '~' is cut one unit shorter: the codec's escape adds it back.
  const tilde = '~' + '\u20ac'.repeat(TRANSFER_PIECE_UNITS - 2);
  for (const [name, piece] of Object.entries({ threeByte, quotes, backslashes, tilde })) {
    assert.equal(wirePieceUnits(piece), TRANSFER_PIECE_UNITS, name);
    assert.ok(pushFrame(piece).length - 4 <= MAX_FRAME_BYTES, `${name} push frame over the cap`);
    assert.ok(pullFrame(piece).length - 4 <= MAX_FRAME_BYTES, `${name} pull frame over the cap`);
  }
  // And a surrogate pair at the cut moves whole into the next piece.
  const pairAtCut = 'x'.repeat(TRANSFER_PIECE_UNITS - 1) + '\u{1F600}';
  const [first, second] = sliceTransferText(pairAtCut);
  assert.equal(first.length, TRANSFER_PIECE_UNITS - 1);
  assert.equal(second, '\u{1F600}');
  assert.equal(utf8Length(pairAtCut), TRANSFER_PIECE_UNITS - 1 + 4);
});

test('every piece fits the shell\'s unit count as it crosses, a leading ~ and its escape included', () => {
  // The shell's gate (check_native_transfer) counts the piece's UTF-16 units
  // in the frame as sent; the codec sends a '~'-leading string with one '~' more.
  const wireUnits = (piece: string) => (JSON.parse(JSON.stringify(encodeFrameValue(piece))) as string).length;
  for (const text of ['~'.repeat(3 * TRANSFER_PIECE_UNITS + 5), `a${'~'.repeat(2 * TRANSFER_PIECE_UNITS)}`, '~a'.repeat(TRANSFER_PIECE_UNITS)]) {
    const pieces = sliceTransferText(text);
    assert.equal(pieces.join(''), text);
    for (const piece of pieces) {
      assert.ok(wireUnits(piece) <= TRANSFER_PIECE_UNITS, `a piece of ${wireUnits(piece)} units on the wire`);
      assert.equal(wireUnits(piece), wirePieceUnits(piece));
    }
    assert.ok(pieces.slice(0, -1).every(piece => wireUnits(piece) === TRANSFER_PIECE_UNITS), 'pieces stay as full as the bound allows');
  }
});

test('the transfer methods are worker methods, and initializeDatabase never takes a payload in pieces', () => {
  const worker = readFileSync(path.resolve(process.cwd(), 'worker/worker.js'), 'utf8');
  const table = worker.match(/const methods = \{([^}]+)\}/);
  assert.ok(table, 'the worker dispatch table');
  const dispatch = new Set(table[1].split(',').map(name => name.trim()).filter(Boolean));
  for (const method of REQUEST_TRANSFER_METHODS) assert.ok(dispatch.has(method), method);
  for (const method of REPLY_TRANSFER_METHODS) assert.ok(REQUEST_TRANSFER_METHODS.has(method), method);
  assert.equal(REQUEST_TRANSFER_METHODS.has('initializeDatabase'), false);
  assert.equal(dispatch.has(NATIVE_TRANSFER_METHOD), false, 'a transport method, not a worker method');
});

/**
 * A sidecar that speaks the transfer protocol (native-host.js), answering
 * `run(method, payload)` and parking any answer over one frame. `fail`
 * can refuse or lose the answer of one frame.
 */
function fakeSidecar(run: (method: string, payload: unknown[]) => unknown) {
  const log: Array<{ method: string; op?: string; bytes: number }> = [];
  let inFlight = 0;
  let request: { id: string; pieces: string[] } | null = null;
  let parked: { id: string; pieces: string[]; next: number } | null = null;
  let committed: string | null = null;
  const hooks: { fail?: (method: string, op: string | undefined, index: unknown) => 'refuse' | 'lose' | undefined } = {};
  const send = async (json: string) => {
    assert.equal(inFlight, 0, 'one frame in flight at a time');
    inFlight++;
    try {
      await new Promise(resolve => setTimeout(resolve, 0));
      const bytes = Buffer.byteLength(json);
      assert.ok(bytes <= MAX_FRAME_BYTES, `a ${bytes}-byte frame crossed`);
      const { content } = decodeFrameValue(JSON.parse(json)) as any;
      const op = content.targetMethod === NATIVE_TRANSFER_METHOD ? content.payload[0] : undefined;
      log.push({ method: content.targetMethod, op, bytes });
      const fate = hooks.fail?.(content.targetMethod, op, content.payload?.[2]);
      if (fate === 'refuse') throw new Error('injected refusal');
      const reply = (body: Record<string, unknown>) => JSON.stringify(encodeFrameValue({ channel: 'rpc', content: { kind: 'response', messageId: content.messageId, ...body } }));
      let answer: string;
      if (op === 'push') {
        const [, id, index, , , piece] = content.payload;
        if (index === 0) request = { id, pieces: [] };
        request!.pieces.push(piece);
        answer = reply({ success: true, data: { id, index } });
      } else if (op === 'pull') {
        const [, id, index] = content.payload;
        assert.equal(parked?.id, id);
        assert.equal(parked!.next, index);
        parked!.next++;
        answer = reply({ success: true, data: { id, index, piece: parked!.pieces[index] } });
      } else if (op === 'commit') {
        const [, id] = content.payload;
        if (parked?.id === id || committed === id) {
          committed = id;
          parked = null;
          answer = reply({ success: true, data: { id, committed: true } });
        } else {
          answer = reply({ success: false, errorMessage: `Native transfer ${id} is not open` });
        }
      } else {
        parked = null;
        const payload = content.payloadTransfer
          ? decodeFrameValue(JSON.parse(request!.pieces.join(''))) as unknown[]
          : content.payload;
        request = null;
        const data = run(content.targetMethod, payload);
        const text = encodeTransferText(data);
        if (Buffer.byteLength(reply({ success: true, data })) <= MAX_FRAME_BYTES) {
          answer = reply({ success: true, data });
        } else {
          parked = { id: 'reply_1', pieces: sliceTransferText(text), next: 0 };
          answer = JSON.stringify({ channel: 'rpc', content: {
            kind: 'transfer', messageId: content.messageId, transfer: { id: 'reply_1', length: text.length, parts: parked.pieces.length }
          } });
        }
      }
      if (fate === 'lose') throw new Error('injected loss of the answer');
      return answer;
    } finally {
      inFlight--;
    }
  };
  return { send, log, hooks, get parked() { return parked; } };
}

const MiB = 1024 * 1024;
const call = (sidecar: ReturnType<typeof fakeSidecar>, method: string, args: unknown[], alive = () => true) => {
  const messageId = 'rpc_1_1764000000000';
  const envelopeJson = JSON.stringify(encodeFrameValue({ channel: 'rpc', content: { kind: 'invoke', messageId, targetMethod: method, payload: args } }));
  return exchangeNativeCall({ method, messageId, args, envelopeJson, send: sidecar.send, alive });
};

test('a request over one frame crosses in pieces, then as the real invoke naming them', async () => {
  const value = 'v'.repeat(20 * MiB) + '\u{1F600}';
  let seen: unknown[] = [];
  const sidecar = fakeSidecar((_method, payload) => { seen = payload; return { ok: true }; });
  const response = await call(sidecar, 'undoModification', [{ affectedCells: [{ priorState: { storageClass: 'text', value } }] }]) as any;
  assert.deepEqual(response.content, { kind: 'response', messageId: 'rpc_1_1764000000000', success: true, data: { ok: true } });
  assert.equal((seen[0] as any).affectedCells[0].priorState.value, value);
  const pushes = sidecar.log.filter(frame => frame.op === 'push');
  assert.ok(pushes.length >= 4, `${pushes.length} pushes`);
  assert.deepEqual(sidecar.log.at(-1), { method: 'undoModification', op: undefined, bytes: sidecar.log.at(-1)!.bytes });
});

test('a request that is not a history-bearing write is sent as one frame, as before', async () => {
  const sidecar = fakeSidecar(() => ({ ok: true }));
  await call(sidecar, 'runQuery', ['SELECT ' + "'x'".repeat(10)]);
  assert.deepEqual(sidecar.log.map(frame => frame.method), ['runQuery']);
});

test('an answer over one frame is pulled piece by piece, decoded, then committed', async () => {
  const prior = new Uint8Array(13 * MiB).map((_, index) => index & 0xff);
  const sidecar = fakeSidecar(() => [{ rowId: 1, priorState: { storageClass: 'blob', value: prior } }]);
  const response = await call(sidecar, 'updateCellBatch', ['t', [{ rowId: 1, column: 'v', value: 'x' }]]) as any;
  assert.deepEqual(response.content.data[0].priorState.value, prior);
  const ops = sidecar.log.map(frame => frame.op ?? frame.method);
  assert.equal(ops[0], 'updateCellBatch');
  assert.ok(ops.slice(1, -1).every(op => op === 'pull') && ops.length > 3);
  assert.equal(ops.at(-1), 'commit');
});

test('a lost or refused pull ends the call without a commit', async () => {
  for (const fate of ['refuse', 'lose'] as const) {
    const sidecar = fakeSidecar(() => ['x'.repeat(20 * MiB)]);
    sidecar.hooks.fail = (_method, op, index) => (op === 'pull' && index === 1 ? fate : undefined);
    await assert.rejects(call(sidecar, 'deleteRows', ['t', [1]]), /injected/);
    assert.equal(sidecar.log.some(frame => frame.op === 'commit'), false, fate);
  }
});

test('a call failed by close or retire stops before its next frame', async () => {
  let alive = true;
  const sidecar = fakeSidecar(() => ['x'.repeat(20 * MiB)]);
  sidecar.hooks.fail = (_method, op) => { if (op === 'pull') alive = false; return undefined; };
  await assert.rejects(call(sidecar, 'deleteRows', ['t', [1]], () => alive), /no longer open/);
  assert.equal(sidecar.log.filter(frame => frame.op === 'pull').length, 1);
  assert.equal(sidecar.log.some(frame => frame.op === 'commit'), false);
});

test('a commit whose answer is lost is asked again; lost twice, the outcome is reported unconfirmed', async () => {
  const once = fakeSidecar(() => ['x'.repeat(20 * MiB)]);
  let lost = 0;
  once.hooks.fail = (_method, op) => (op === 'commit' && lost++ === 0 ? 'lose' : undefined);
  const response = await call(once, 'deleteRows', ['t', [1]]) as any;
  assert.equal(response.content.data[0].length, 20 * MiB);
  assert.equal(once.log.filter(frame => frame.op === 'commit').length, 2);

  const twice = fakeSidecar(() => ['x'.repeat(20 * MiB)]);
  twice.hooks.fail = (_method, op) => (op === 'commit' ? 'lose' : undefined);
  await assert.rejects(call(twice, 'deleteRows', ['t', [1]]), (error: any) => error.code === 'ERR_NATIVE_TRANSFER_UNCONFIRMED');

  // A commit the sidecar refuses as rolled back is a known outcome, not a loss.
  // One it refuses as unknown, or without saying, leaves the write's fate open.
  const commitAnswered = async (error: Record<string, unknown> | undefined) => {
    const sidecar = fakeSidecar(() => ['x'.repeat(20 * MiB)]);
    const send = async (json: string) => {
      const content = JSON.parse(json).content;
      if ((content.payload ?? [])[0] === 'commit') {
        return JSON.stringify({ channel: 'rpc', content: {
          kind: 'response', messageId: content.messageId, success: false, errorMessage: 'Native transfer reply_1 is not open',
          ...(error ? { error } : {})
        } });
      }
      return sidecar.send(json);
    };
    const messageId = 'rpc_1_1764000000000';
    const args = ['t', [1]];
    return exchangeNativeCall({
      method: 'deleteRows', messageId, args,
      envelopeJson: JSON.stringify(encodeFrameValue({ channel: 'rpc', content: { kind: 'invoke', messageId, targetMethod: 'deleteRows', payload: args } })),
      send, alive: () => true
    }).then(() => null, (failure: any) => failure);
  };
  const rolledBack = await commitAnswered({ name: 'Error', message: 'x', code: 'ERR_NATIVE_TRANSFER_ROLLED_BACK' });
  assert.match(rolledBack.message, /is not open/);
  assert.notEqual(rolledBack.code, 'ERR_NATIVE_TRANSFER_UNCONFIRMED');
  for (const error of [{ name: 'Error', message: 'x', code: 'ERR_NATIVE_TRANSFER_UNKNOWN' }, undefined]) {
    assert.equal((await commitAnswered(error))?.code, 'ERR_NATIVE_TRANSFER_UNCONFIRMED', JSON.stringify(error));
  }
});

test('an answer the page cannot decode is not committed', async () => {
  const sidecar = fakeSidecar(() => ['x'.repeat(20 * MiB)]);
  const send = async (json: string) => {
    const reply = await sidecar.send(json);
    const parsed = JSON.parse(reply);
    if (parsed.content?.data?.index === 0) parsed.content.data.piece = '{' + parsed.content.data.piece.slice(1);
    return JSON.stringify(parsed);
  };
  const messageId = 'rpc_1_1764000000000';
  const args = ['t', [1]];
  await assert.rejects(exchangeNativeCall({
    method: 'deleteRows', messageId, args,
    envelopeJson: JSON.stringify(encodeFrameValue({ channel: 'rpc', content: { kind: 'invoke', messageId, targetMethod: 'deleteRows', payload: args } })),
    send, alive: () => true
  }), SyntaxError);
  assert.equal(sidecar.log.some(frame => frame.op === 'commit'), false);
});

test('a commit the shell refuses for a replaced file or a gone sidecar keeps the shell\'s error, unretried', async () => {
  for (const [refusal, after] of [
    ['ERR_NATIVE_FILE_CHANGED: the file at the bound path was replaced', 0],
    ['ERR_NATIVE_FILE_CHANGED: the file at the bound path was replaced', 1],
    ['ERR_NATIVE_SIDECAR_EXITED: exited with code 1', 1],
    ['ERR_NATIVE_UNKNOWN_DB: db_0', 0]
  ] as const) {
    const sidecar = fakeSidecar(() => ['x'.repeat(20 * MiB)]);
    let commits = 0;
    // `after` lost answers first (a commit that may have landed), then the refusal.
    const send = async (json: string) => {
      if ((JSON.parse(json).content.payload ?? [])[0] === 'commit' && commits++ >= after) throw new Error(refusal);
      const reply = await sidecar.send(json);
      if ((JSON.parse(json).content.payload ?? [])[0] === 'commit') throw new Error('injected loss of the answer');
      return reply;
    };
    const messageId = 'rpc_1_1764000000000';
    const args = ['t', [1]];
    const error = await exchangeNativeCall({
      method: 'deleteRows', messageId, args,
      envelopeJson: JSON.stringify(encodeFrameValue({ channel: 'rpc', content: { kind: 'invoke', messageId, targetMethod: 'deleteRows', payload: args } })),
      send, alive: () => true
    }).then(() => null, (failure: any) => failure);
    assert.equal(error?.message, refusal, `${refusal} after ${after} lost answers`);
    assert.notEqual(error?.code, 'ERR_NATIVE_TRANSFER_UNCONFIRMED');
    assert.equal(commits, after + 1, 'no retry after the refusal');
  }
});

test('only a lost answer to the method\'s own request is marked as one whose outcome is unknown', async () => {
  const { answerWasLost } = await import('../../core/native/native-transfer.js');
  const timeout = 'ERR_NATIVE_RPC_TIMEOUT: the sidecar did not answer within 600s; the request was abandoned';
  const small = (method: string, messageId: string) => ({
    method, messageId, args: ['t'], alive: () => true,
    envelopeJson: JSON.stringify(encodeFrameValue({ channel: 'rpc', content: { kind: 'invoke', messageId, targetMethod: method, payload: ['t'] } }))
  });
  // The request itself went to the shell and its answer is lost or unreadable.
  const lost = await exchangeNativeCall({ ...small('updateCellBatch', 'rpc_1'), send: async () => { throw timeout; } })
    .then(() => null, (error: unknown) => error);
  assert.ok(lost instanceof Error && lost.message === timeout && answerWasLost(lost));
  const garbled = await exchangeNativeCall({ ...small('updateCellBatch', 'rpc_2'), send: async () => 'not json' })
    .then(() => null, (error: unknown) => error);
  assert.ok(garbled instanceof Error && answerWasLost(garbled));
  // A request piece lost: the method was never sent.
  const big = ['t', 'x'.repeat(MAX_FRAME_BYTES)];
  const piece = await exchangeNativeCall({
    method: 'updateCellBatch', messageId: 'rpc_3', args: big, alive: () => true,
    envelopeJson: JSON.stringify(encodeFrameValue({ channel: 'rpc', content: { kind: 'invoke', messageId: 'rpc_3', targetMethod: 'updateCellBatch', payload: big } })),
    send: async () => { throw timeout; }
  }).then(() => null, (error: unknown) => error);
  assert.equal(piece, timeout);
  assert.equal(answerWasLost(piece), false);
  // An answer piece lost: the parked write is rolled back at the next frame.
  let sends = 0;
  const pull = await exchangeNativeCall({
    ...small('updateCellBatch', 'rpc_4'),
    send: async () => {
      if (sends++ === 0) return JSON.stringify({ channel: 'rpc', content: { kind: 'transfer', messageId: 'rpc_4', transfer: { id: 'reply_1', length: 10, parts: 1 } } });
      throw timeout;
    }
  }).then(() => null, (error: unknown) => error);
  assert.equal(pull, timeout);
  assert.equal(answerWasLost(pull), false);
});
