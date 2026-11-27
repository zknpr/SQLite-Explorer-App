/**
 * Runtime surface the desktop native sidecar installs BEFORE the worker
 * method layer loads: argv binding, the tjs:sqlite engine factory, the framed
 * stdio transport, the `self` global worker.js expects, the
 * shell-originated export-to-path route (see the CONTRACT block below), and
 * the transfers that carry a value larger than one frame (the transfer
 * CONTRACT block, with native-transfer.js). The lifecycle (importing worker.js, then start/flush/exit) lives in
 * native-entry.js.
 *
 * This split is load-bearing, not cosmetic. worker.js's module body reads
 * `self`, so everything here must initialise first — and the engine seam's
 * injected binding (core/native/native-engine-inject.js) makes worker.js
 * depend on this module. If the factory lived in the entry alongside its
 * top-level awaits, that dependency would put a top-level-await module inside
 * an import cycle, which esbuild can only express by wrapping it lazily —
 * and a lazily-wrapped module cannot legally contain top-level await (the
 * bundle it emits fails to parse). Keeping this module synchronous and
 * cycle-free is what keeps the bundle valid.
 *
 * See native-entry.js for the argv contract and exit codes.
 */

import { Database } from 'tjs:sqlite';
import path from 'tjs:path';
import { createShimDatabase } from './sqljs-shim.js';
import { createStdioTransport } from './stdio-transport.js';
import {
  FRAME_CELL_WIRE,
  MAX_FRAME_BYTES,
  NATIVE_FRAME_TOO_LARGE,
  encodeFrame,
  frameErrorResponse,
  isNativeFrameError,
  toFrameErrorData
} from './frame-codec.js';
import { decodeBoundPathArgument } from './bound-path-argument.js';
import {
  MAX_NATIVE_TRANSFER_UNITS,
  NATIVE_TRANSFER_METHOD,
  NATIVE_TRANSFER_ROLLED_BACK,
  NATIVE_TRANSFER_UNKNOWN,
  REPLY_TRANSFER_METHODS,
  REQUEST_TRANSFER_METHODS,
  TRANSFER_PIECE_UNITS,
  decodeTransferText,
  encodeTransferText,
  isTransferId,
  transferPieceBounds,
  wirePieceUnits
} from './native-transfer.js';

export const EXIT_CLEAN = 0;
export const EXIT_TRANSPORT_FATAL = 1;
export const EXIT_USAGE = 2;
export const EXIT_ORPHANED = 3;

/** Mirrors DEFAULT_QUERY_TIMEOUT_MS in worker.js (which the seam cannot export). */
const DEFAULT_QUERY_TIMEOUT_MS = 30000;
const PPID_WATCHDOG_INTERVAL_MS = 1000;

/**
 * busy_timeout for the sidecar's connection, in milliseconds. With SQLite's
 * default of 0, any lock another process held at the wrong moment failed the
 * request outright: a Save's COMMIT while a reader had the file open, a page
 * read during another writer's commit. 600 ms rides out the short locks such
 * programs normally take. The shim spends it once per request
 * (restoreLockWait, called below as each message arrives), because a
 * sleeping busy handler is not interrupted by the query deadline.
 */
const LOCK_WAIT_MS = 600;

// ---------------------------------------------------------------------------
// argv
// ---------------------------------------------------------------------------

const args = tjs.args.slice(3);
if (args.length !== 2 || args[0] === '' || (args[1] !== 'ro' && args[1] !== 'rw')) {
  console.error(
    `[native-worker] bad argv ${JSON.stringify(args)}; ` +
    'usage: tjs run native-worker-desktop.js <dbPath> ro|rw'
  );
  tjs.exit(EXIT_USAGE);
}
let boundPath;
try {
  boundPath = decodeBoundPathArgument(args[0]);
  if (!boundPath) throw new Error('database path is empty');
} catch (error) {
  console.error(`[native-worker] invalid bound path: ${error.message}`);
  tjs.exit(EXIT_USAGE);
}
const boundReadOnly = args[1] === 'ro';

// ---------------------------------------------------------------------------
// Engine factory (the worker.js seam's `__desktopNativeCreateEngine`)
// ---------------------------------------------------------------------------

// TMPDIR is the user-private temp root on macOS; Windows supplies TEMP/TMP.
// The /tmp fallback is for Unix environments without TMPDIR. makeTempDir guarantees the fresh,
// uniquely named, owner-only directory the shim's export contract requires.
const tempRoot = (tjs.env.TMPDIR ?? tjs.env.TEMP ?? tjs.env.TMP ?? '/tmp').replace(/[\\/]+$/, '');

const shimDeps = {
  sqlite: { Database },
  fs: {
    makeTempDir: () => tjs.makeTempDir(`${tempRoot}/sqlite-explorer-export-XXXXXX`),
    readFile: (path) => tjs.readFile(path),
    remove: (path) => tjs.remove(path, { recursive: true })
  },
  onCleanupFailure: (error, context) => {
    console.error(`[native-worker] cleanup failed (${context}): ${error?.message ?? error}`);
  }
};

/**
 * The engine the factory last produced, or null before the first successful
 * `initializeDatabase` and after a refused one. Only the `exportDatabase`
 * interception below reads it; worker.js owns the engine's lifecycle (it
 * closes the previous instance before every re-initialisation).
 */
let activeDb = null;

/**
 * Whether the active engine's open found no -wal beside the database. Only
 * then can a -wal at exit be one this session created (closeDatabaseForExit).
 */
let activeOpenFoundNoWal = false;

/** The shell installs the pinned reader beside the executable, never at a page-supplied path. */
async function loadQueryPlanReader(db) {
  const directory = path.dirname(tjs.exePath);
  for (const name of ['query-plan.dylib', 'query-plan.so', 'query-plan.dll']) {
    const library = path.join(directory, name);
    try { await tjs.stat(library); }
    catch (error) {
      if (error?.code === 'ENOENT') continue;
      throw error;
    }
    // A present but incompatible library is a broken installation. Never
    // continue with the unbounded native EXPLAIN implementation after failure.
    db.backingDatabase.loadExtension(library, 'sqlite3_sqliteexplorer_init');
    return;
  }
  throw new Error('Missing bundled query-plan reader beside the native runtime.');
}

/**
 * Engine factory called by worker.js's engine seam with the raw
 * `initializeDatabase` config. Returns `{ SQL, db, measureReply, cellWire }`:
 * `db` is the sql.js-shaped shim over `tjs:sqlite`, `SQL` is an inert marker —
 * the only WASM-build code that reaches into `SQL` (the paged-open ladder) is
 * unreachable here because native configs carry a path, never a File handle —
 * `measureReply` is the frame check below, and `cellWire` is what a cell
 * costs in the frame (frame-codec.js FRAME_CELL_WIRE), against which a page
 * whose answer comes out over the frame is contained again (sendGuarded,
 * worker.js offerFrameContainment).
 *
 * PATH BINDING (layer 2 of the desktop's three-layer path authority; layers
 * 1 and 3 live in the Rust shell): the open is refused unless `config.path`
 * strictly equals the argv path, and a session spawned `ro` refuses a
 * writable open. This holds even if the Rust layers are bypassed, because
 * this factory is the only code in the process that opens databases.
 * Refusals throw; worker.js's dispatch catch turns them into a structured
 * `{ success: false, errorMessage }` response for the caller.
 */
export async function createNativeEngine(config) {
  // Whatever happens next, the engine we handed out before this call is gone:
  // worker.js closes it before asking for a new one.
  activeDb = null;
  activeOpenFoundNoWal = false;

  if (config?.path !== boundPath) {
    throw new Error(
      'refusing to open a database other than the one this sidecar was ' +
      `bound to at spawn (got ${JSON.stringify(config?.path ?? null)})`
    );
  }
  // `readOnlyMode` is the same key worker.js consumes for its own read-only
  // state, so worker guards and engine enforcement cannot diverge. A stricter
  // open than the session (ro over an rw spawn) is harmless and allowed; a
  // writable open of an `ro` session would be privilege escalation and is
  // refused rather than silently downgraded.
  const readOnly = config.readOnlyMode === true;
  if (boundReadOnly && !readOnly) {
    throw new Error(
      'refusing a writable open: this sidecar was spawned for a read-only session'
    );
  }

  // Looked at before the open, which creates a -wal beside a WAL database.
  const foundNoWal = await walIsAbsent();
  const db = createShimDatabase({ path: boundPath, readOnly, lockWaitMs: LOCK_WAIT_MS }, shimDeps);
  try { await loadQueryPlanReader(db); }
  catch (error) {
    db.close();
    throw new Error(`Unable to initialize the bounded query-plan reader: ${error?.message ?? error}`, { cause: error });
  }

  // Query-timeout wiring. worker.js arms `db.progress_handler(interval, cb)`
  // immediately before every bounded synchronous operation and disarms it in
  // a `finally`; on the fork the callback is inert (queries run as one
  // synchronous native call, so no JS can observe progress), which would
  // leave the timeout dead. Translate arm/disarm into the fork's native
  // statement deadline instead. The budget mirrors worker.js's own
  // computation (armed-at + queryTimeout); an expiry surfaces as SQLite's
  // "interrupted" (errno 9) rather than the WASM timeout message.
  // Cancellation flags cannot arrive here at all: they require a
  // SharedArrayBuffer, which the JSON frame codec cannot carry.
  const queryTimeoutMs = Number.isFinite(config.queryTimeout) && config.queryTimeout > 0
    ? config.queryTimeout
    : DEFAULT_QUERY_TIMEOUT_MS;
  const recordProgressHandler = db.progress_handler.bind(db);
  db.progress_handler = (interval, callback) => {
    // Keep the shim's own recording (its `progressHandler` inspection hook).
    recordProgressHandler(interval, callback);
    if (interval != null && typeof callback === 'function') {
      db.setQueryDeadline(queryTimeoutMs);
    } else {
      db.clearQueryDeadline();
    }
    return undefined;
  };

  activeDb = db;
  activeOpenFoundNoWal = foundNoWal;
  return {
    SQL: Object.freeze({ engine: 'tjs-native', queryPlanReaderActive: true }),
    db,
    measureReply,
    cellWire: FRAME_CELL_WIRE
  };
}

/**
 * The longest messageId worker.js reflects (256 code units), as the characters
 * JSON spells longest (`\u0000`, six bytes each): a reply measured with it is
 * at least as large as the same reply to any request the worker answers.
 */
const LONGEST_REPLY_MESSAGE_ID = '\u0000'.repeat(256);

/**
 * Set while one of REPLY_TRANSFER_METHODS runs inside runWithReplyTransfer:
 * its answer may cross as a transfer (native-transfer.js), so measureReply
 * holds it to the transfer ceiling instead of the frame, and keeps the text
 * it encoded so the transfer does not encode the answer a second time.
 * @type {null | { measured: null | { data: unknown, text: string } }}
 */
let replyTransfer = null;

/**
 * worker.js's measure of one success reply carrying `data`: null when the
 * frame the transport would write for it fits the cap less `reserveBytes`,
 * else the encoded size and that limit. It encodes exactly as
 * `transport.postMessage` does, so the worker can refuse a write whose answer
 * the frame would refuse while the write's savepoint is still open
 * (worker.js assertWriteAnswerFits). The reserve is room the caller keeps for
 * what the host adds when it sends the answer back as an undo or redo request.
 *
 * For REPLY_TRANSFER_METHODS only (replyTransfer set), the limit is the
 * transfer ceiling in encoded characters: such an answer crosses in pieces,
 * and its undo request can too. Every other caller keeps the frame: its
 * answer is sent in one frame after its write was released, so a limit past
 * the frame would leave the write in place behind a frame error.
 */
function measureReply(data, reserveBytes = 0) {
  if (replyTransfer !== null) {
    const limit = MAX_NATIVE_TRANSFER_UNITS - reserveBytes;
    const text = encodeTransferText(data);
    if (text.length > limit) return { bytes: text.length, limitBytes: Math.max(0, limit), unit: 'characters' };
    replyTransfer.measured = { data, text };
    return null;
  }
  const limitBytes = MAX_FRAME_BYTES - reserveBytes;
  if (!(limitBytes > 0)) return { bytes: reserveBytes, limitBytes: 0 };
  try {
    encodeFrame({
      channel: 'rpc',
      content: { kind: 'response', messageId: LONGEST_REPLY_MESSAGE_ID, success: true, data }
    }, { maxFrameBytes: limitBytes });
    return null;
  } catch (error) {
    if (isNativeFrameError(error) && error.code === NATIVE_FRAME_TOO_LARGE) {
      return { bytes: error.actualBytes, limitBytes };
    }
    throw error;
  }
}

/**
 * True only when the bound database's -wal is known not to exist. Any other
 * answer, a failed stat included, counts as a -wal that may be there, which
 * keeps the database open at exit.
 */
async function walIsAbsent() {
  try {
    await tjs.stat(`${boundPath}-wal`);
    return false;
  } catch (error) {
    return error?.code === 'ENOENT';
  }
}

/**
 * Called before every deliberate exit (stdin EOF, a fatal transport error,
 * the orphan watchdog). It closes the database only when doing so restores
 * the folder this session found.
 *
 * In WAL mode, opening and reading a database creates <db>-wal and <db>-shm,
 * and SQLite deletes them only when the last connection closes, after
 * copying the -wal's committed pages into the main file. If the -wal did not
 * exist before this session opened the file and is still zero bytes, that
 * copy is empty and closing just deletes the two files. In every other case
 * -- a -wal some other program left behind, or one that now holds this
 * session's committed edits -- closing would rewrite the main file, so the
 * connection is left for the process exit to drop and all files stay
 * untouched, which is what every exit did before. A rollback-journal database
 * has no -wal and is never closed here. An empty -wal closes in a millisecond
 * or two, far inside the two seconds the shell waits before it kills the
 * sidecar.
 *
 * Never throws: the exit that follows must happen regardless.
 */
export async function closeDatabaseForExit() {
  const db = activeDb;
  if (db === null || !activeOpenFoundNoWal) return;
  let walBytes;
  try {
    walBytes = (await tjs.stat(`${boundPath}-wal`)).size;
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      console.error(`[native-worker] leaving the database open at exit: ${error?.message ?? error}`);
    }
    return;
  }
  if (walBytes !== 0) return;
  try {
    db.close();
  } catch (error) {
    console.error(`[native-worker] closing the database at exit failed: ${error?.message ?? error}`);
  }
}

// ---------------------------------------------------------------------------
// Transport + the worker's `self` surface
// ---------------------------------------------------------------------------

/** Set by onEof exactly once; consulted after start() resolves to pick the exit code. */
let shutdownReason = { kind: 'eof' };
export const getShutdownReason = () => shutdownReason;

export const transport = createStdioTransport({
  onEof: (reason) => { shutdownReason = reason; },
  onTransportError: (error) => {
    console.error(`[native-worker] transport error: ${error?.message ?? error}`);
  }
});

/** The key of worker.js's offer to contain a page answer again (offerFrameContainment). */
const CONTAIN_AGAIN = Symbol.for('sqlite-explorer.contain-again');
/** Each round measures the last; a page past this still fails with the frame's error. */
const MAX_CONTAIN_AGAIN_ROUNDS = 4;

const messageIdOf = (message) => {
  const id = message?.content?.messageId;
  return typeof id === 'string' || typeof id === 'number' ? id : null;
};

/**
 * The cap-safe send every reply goes through. `transport.postMessage` throws
 * synchronously on an over-cap frame, and two of worker.js's three send sites
 * (the unknown-method reply, which interpolates the caller-supplied method
 * name, and the catch-branch reply) call it unguarded — so the worker layer is
 * handed THIS instead: on a cap error the response is replaced by a bounded
 * error response for the same messageId, and the pending RPC still resolves.
 * The fallback send is itself guarded because this function must never throw
 * back into worker.js.
 */
const sendGuarded = (message) => {
  let reply = message;
  for (let round = 0; ; round++) {
    let failure;
    try {
      transport.postMessage(reply);
      return;
    } catch (error) {
      failure = error;
    }
    // A page is contained as the WebAssembly worker contains it, a string at
    // its UTF-8 bytes, while the frame writes a control character as six, so
    // its answer can come out over the cap. Such an answer carries worker.js's
    // offer to contain it again within what this encode measured
    // (offerFrameContainment); the next encode measures that, and the last
    // failure is the one sent back.
    const containAgain = reply?.content?.data?.[CONTAIN_AGAIN];
    if (round < MAX_CONTAIN_AGAIN_ROUNDS && typeof containAgain === 'function'
      && isNativeFrameError(failure) && failure.code === NATIVE_FRAME_TOO_LARGE) {
      try {
        reply = { ...reply, content: { ...reply.content, data: containAgain(failure.actualBytes, failure.limitBytes) } };
        continue;
      } catch (error) {
        failure = error;
      }
    }
    try {
      transport.postMessage(frameErrorResponse(failure, messageIdOf(message)));
    } catch (secondary) {
      console.error(
        `[native-worker] failed to send bounded error response: ${secondary?.message ?? secondary}`
      );
    }
    return;
  }
};

// worker.js's `self` global: in the tjs runtime `self === globalThis`, so the
// process global IS the worker-scope surface, exactly like a real
// DedicatedWorkerGlobalScope — worker.js's `self.onmessage = ...` lands on
// globalThis, and its `self.postMessage(...)` resolves to the send installed
// here. This is not a stylistic choice: tjs pins `self` behind a fixed
// accessor, so a replacement surface object assigned to `globalThis.self`
// would be silently discarded and the worker would wire itself to nothing.
// The transfer list worker.js passes on export responses is a WASM-side
// memory optimisation with no meaning on a byte-copying pipe; accepted and
// ignored. In-process captures (the shell-export route's way of calling a
// worker method without its result crossing the pipe) are checked FIRST — a
// captured response must never reach the frame codec, where its size could
// exceed the cap the whole route exists to avoid.
globalThis.postMessage = (message, _transferList) => {
  if (deliverToInProcessCapture(message)) return;
  sendGuarded(message);
};

// ---------------------------------------------------------------------------
// In-process worker-method calls (for the shell-originated export route)
// ---------------------------------------------------------------------------

/**
 * In-flight in-process response captures, keyed by internal messageId. Ids
 * carry a random suffix so a webview rpc invoke cannot predict one and race a
 * forged same-id response into a pending capture (worst case would be a
 * structurally rejected export, not a wrong file — but the suffix closes even
 * that).
 */
const inProcessCaptures = new Map();
let inProcessSequence = 0;

/** Divert a worker response to its in-process capture. True when diverted. */
const deliverToInProcessCapture = (message) => {
  if (message?.channel !== 'rpc' || message?.content?.kind !== 'response') return false;
  const capture = inProcessCaptures.get(message.content.messageId);
  if (capture === undefined) return false;
  inProcessCaptures.delete(message.content.messageId);
  capture(message.content);
  return true;
};

/**
 * Run one worker method IN PROCESS, through the worker's own dispatch
 * (`globalThis.onmessage`, i.e. worker.js's `self.onmessage`) — same envelope
 * validation, same cell-read-session guard, same error wrapping — but with
 * the response captured here instead of framed onto the pipe. worker.js posts
 * the response before its onmessage promise resolves, so the capture is
 * always settled once the await returns; a missing capture is a structural
 * failure, not a hang.
 *
 * Resolves with the response's content exactly as the worker posted it,
 * success or failure (its typed `error` data included).
 */
async function captureWorkerResponse(targetMethod, args) {
  const captureId =
    `__in_process_${++inProcessSequence}_${Math.random().toString(36).slice(2)}`;
  let captured = null;
  inProcessCaptures.set(captureId, (content) => { captured = content; });
  try {
    if (typeof globalThis.onmessage !== 'function') {
      throw new Error('worker method layer is not loaded (no onmessage handler)');
    }
    await globalThis.onmessage({
      data: {
        channel: 'rpc',
        content: { kind: 'invoke', messageId: captureId, targetMethod, payload: args }
      }
    });
  } finally {
    inProcessCaptures.delete(captureId);
  }
  if (captured === null) {
    throw new Error(`in-process ${targetMethod} completed without posting a response`);
  }
  return captured;
}

/**
 * captureWorkerResponse, resolving with the method's `data`; rejects with the
 * response's error (message + code/errno restored) when the method failed.
 */
async function invokeWorkerMethodInProcess(targetMethod, args) {
  const captured = await captureWorkerResponse(targetMethod, args);
  if (captured.success !== true) {
    const error = new Error(captured.errorMessage || `${targetMethod} failed`);
    if (typeof captured.error?.code === 'string') error.code = captured.error.code;
    if (Number.isSafeInteger(captured.error?.errno)) error.errno = captured.error.errno;
    throw error;
  }
  return captured.data;
}

/**
 * `exportDatabase`, served at this dispatch layer instead of worker.js's own
 * handler: that handler calls `db.export()`, which requires a synchronous
 * filesystem the fork does not have. The shim's `exportAsync()` (VACUUM INTO
 * a fresh temp file, read, remove) is the native equivalent. A result larger
 * than the frame cap becomes `sendGuarded`'s bounded error response by
 * design — the out-of-band large-export route is a later host decision.
 *
 * Accepted parity gap: the worker-side cell-read-session guard
 * (`assertCellReadSessionAllowsMethod`) is not consulted here; the host
 * closes read sessions before exporting.
 */
async function handleExportDatabase(messageId) {
  try {
    if (!activeDb) throw new Error('No database initialized');
    const bytes = await activeDb.exportAsync();
    sendGuarded({
      channel: 'rpc',
      content: { kind: 'response', messageId, success: true, data: bytes }
    });
  } catch (error) {
    sendGuarded(frameErrorResponse(error, messageId));
  }
}

// ---------------------------------------------------------------------------
// Shell-originated export-to-path (the out-of-band large-export route)
// ---------------------------------------------------------------------------

/**
 * CONTRACT — pinned verbatim; the Tauri shell's Rust (the only legitimate
 * sender) constructs the request and matches the reply EXACTLY as follows.
 *
 * Request (shell → sidecar), one frame:
 *
 *   { "channel": "shell",
 *     "content": {
 *       "kind": "export",
 *       "messageId": <string|number>,
 *       "method": "exportDatabase" | "exportTable",
 *       "tempPath": <string>,             // shell-owned fresh path; must not exist
 *       "args": <array>                   // exportTable's positional worker args;
 *     } }                                 //   omitted/ignored for exportDatabase
 *
 * Reply (sidecar → shell), one small frame — the export BYTES never cross
 * the pipe, only this path-sized result does:
 *
 *   { "channel": "shell",
 *     "content": {
 *       "kind": "export-result",
 *       "messageId": <echoed>,
 *       "success": true,  "bytesWritten": <number> } }        on success
 *   { ... "success": false, "error": {name, message, code?, errno?} }  on failure
 *
 * SECURITY: `channel:'shell'` is the trust boundary marker. The Rust shell
 * refuses to forward a webview-built shell envelope (its L3 gate), and this
 * dispatch never routes a `{channel:'rpc'}` envelope here — so `tempPath` is
 * always a path the SHELL constructed inside its own 0700 temp directory,
 * never a webview-named one. The sidecar writes to exactly that path and
 * nothing else; on failure the partial temp is the shell's to clean up
 * (it removes the whole temp directory). `args`, by contrast, carries the
 * same webview-authored export options the rpc route already accepts —
 * exportTable treats them as untrusted exactly as it always has.
 */
async function handleShellExport(content) {
  const messageId = typeof content?.messageId === 'string' || typeof content?.messageId === 'number'
    ? content.messageId
    : null;
  if (messageId === null) {
    // Nothing to route a reply to; a trusted-sender message without an id is
    // a shell bug, and silence would strand its await.
    console.error('[native-worker] shell export request without a messageId; dropped');
    return;
  }
  try {
    const method = content.method;
    const tempPath = content.tempPath;
    if (method !== 'exportDatabase' && method !== 'exportTable') {
      throw new Error(`unknown shell export method ${JSON.stringify(method ?? null)}`);
    }
    if (typeof tempPath !== 'string' || tempPath.length === 0) {
      throw new Error('shell export request carries no tempPath');
    }

    let bytesWritten;
    if (method === 'exportDatabase') {
      if (!activeDb) throw new Error('No database initialized');
      // VACUUM INTO the shell's temp path: the image streams to disk inside
      // SQLite; no read-back, nothing held in memory, nothing framed.
      await activeDb.exportToPath(tempPath);
      bytesWritten = (await tjs.stat(tempPath)).size;
    } else {
      if (!Array.isArray(content.args)) {
        throw new Error('shell exportTable request carries no args array');
      }
      // The worker's own exportTable, run in process (its result is bounded
      // by args' maxExportBytes, held briefly here, never framed) — then its
      // chunks land at the shell's temp path. Export first, create the file
      // second: a failed export leaves no file behind.
      const result = await invokeWorkerMethodInProcess('exportTable', content.args);
      const chunks = result?.contentChunks;
      if (!Array.isArray(chunks)) {
        throw new Error('exportTable returned no contentChunks array');
      }
      bytesWritten = await writeChunksToPath(tempPath, chunks);
    }
    sendGuarded({
      channel: 'shell',
      content: { kind: 'export-result', messageId, success: true, bytesWritten }
    });
  } catch (error) {
    sendGuarded({
      channel: 'shell',
      content: {
        kind: 'export-result', messageId, success: false, error: toFrameErrorData(error)
      }
    });
  }
}

/**
 * Create `tempPath` and append each export chunk (exportTable emits strings;
 * Uint8Array accepted for future-proofing). Returns total bytes written.
 * `'wx'` = O_EXCL create: a pre-existing file at the shell's fresh temp path
 * is a protocol violation and fails closed rather than being truncated.
 */
async function writeChunksToPath(tempPath, chunks) {
  const handle = await tjs.open(tempPath, 'wx');
  let bytesWritten = 0;
  let failure = null;
  try {
    const encoder = new TextEncoder();
    for (const chunk of chunks) {
      let view;
      if (typeof chunk === 'string') view = encoder.encode(chunk);
      else if (chunk instanceof Uint8Array) view = chunk;
      else throw new Error(`exportTable produced an unwritable chunk (${typeof chunk})`);
      // pos omitted → current file offset; loop on the returned count so a
      // short write can never silently truncate the export.
      while (view.length > 0) {
        const wrote = await handle.write(view);
        if (!Number.isInteger(wrote) || wrote <= 0) {
          throw new Error(`short write to export temp file (wrote ${wrote})`);
        }
        bytesWritten += wrote;
        view = view.subarray(wrote);
      }
    }
    // The success reply asserts the bytes ARE in the file; make that hold
    // across a crash too — the shell renames this file into place next.
    await handle.sync();
    return bytesWritten;
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    try {
      await handle.close();
    } catch (closeError) {
      // Never mask the original failure with a close failure; a close failure
      // after a clean sync IS the caller's error, though.
      if (failure === null) throw closeError;
      console.error(
        `[native-worker] failed to close export temp file: ${closeError?.message ?? closeError}`
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Transfers: values larger than one frame (native-transfer.js)
// ---------------------------------------------------------------------------

/**
 * CONTRACT — the page half is exchangeNativeCall in native-transfer.js.
 *
 *   push    invoke nativeTransfer ['push', id, index, parts, length, piece]
 *           -> response { id, index }        (request pieces, in order)
 *   invoke  { kind:'invoke', messageId, targetMethod, payloadTransfer:{id, length, parts} }
 *           -> the method runs on the assembled payload, for
 *              REQUEST_TRANSFER_METHODS only, or nothing runs
 *   answer  { kind:'transfer', messageId, transfer:{id, length, parts} }
 *           (REPLY_TRANSFER_METHODS: the write is held in a savepoint)
 *   pull    invoke nativeTransfer ['pull', id, index] -> response { id, index, piece }
 *   commit  invoke nativeTransfer ['commit', id] -> response { id, committed:true }
 *           (RELEASE; idempotent for the last committed id). A transfer that
 *           is not open is refused with error.code ERR_NATIVE_TRANSFER_ROLLED_BACK
 *           when this sidecar rolled it back, else ERR_NATIVE_TRANSFER_UNKNOWN
 *
 * At most one transfer is open per connection: a request being assembled or
 * an answer being pulled, never both, and its memory is freed when it
 * completes, when any frame arrives that does not continue it, or with the
 * process. A parked answer that does not complete takes its write back with
 * it (abandonOpenTransfer), so no write stays in the session without the
 * history the page records to undo it. Pieces name no path and carry no SQL:
 * a short id, counts and opaque JSON text, decoded with the frame codec and
 * handed to the very method the real envelope names, which the shell's
 * layer 3 has already admitted.
 */

/** The outer savepoint a reply-transfer write runs inside. */
const REPLY_SAVEPOINT = 'native_host_reply';

/**
 * The open transfer, or null:
 *   { kind: 'request', id, length, parts, pieces: string[], units }
 *   { kind: 'reply', id, text, bounds, nextIndex, startedTxn }
 */
let openTransfer = null;
/**
 * The answer transfers this sidecar last committed and last rolled back.
 * Facts about ids that are never reused (reply_<n>), kept until a later
 * transfer replaces them, whatever frames arrive in between: a commit retried
 * after its first answer was lost is told what happened. For an id it no
 * longer remembers, the sidecar says it does not know, never that it rolled
 * the write back.
 */
let lastCommittedReplyId = null;
let lastAbandonedReplyId = null;
let replySequence = 0;

/** The worker's own correlation-id rule (worker.js onmessage); it drops anything else. */
const isWorkerMessageId = (id) => typeof id === 'string' && id.length > 0 && id.length <= 256;

/** Take back everything since the reply savepoint. Throws when SQLite refuses. */
function rollbackReplySavepoint(startedTxn) {
  // An abort-class failure (SQLITE_FULL, IOERR, the query deadline's
  // INTERRUPT) already rolled the whole transaction back, savepoint included.
  if (!activeDb?.inTransaction) return;
  if (startedTxn) {
    activeDb.run('ROLLBACK');
    return;
  }
  activeDb.run(`ROLLBACK TO ${REPLY_SAVEPOINT}`);
  activeDb.run(`RELEASE ${REPLY_SAVEPOINT}`);
}

/**
 * The write whose answer did not complete must not stay: roll it back, and if
 * SQLite refuses that, the whole session (the page's reconcile probe then
 * finds autocommit and resets its history). If even that fails, nothing in
 * this process can take the write back, so the process ends: an uncommitted
 * transaction never outlives it, and the shell fans the death out.
 */
function discardParkedWrite(startedTxn, why) {
  try {
    rollbackReplySavepoint(startedTxn);
    return;
  } catch (error) {
    console.error(`[native-worker] rolling back ${why} failed: ${error?.message ?? error}`);
  }
  try {
    if (activeDb?.inTransaction) activeDb.run('ROLLBACK');
    return;
  } catch (error) {
    console.error(
      `[native-worker] rolling the session back failed too: ${error?.message ?? error}; ` +
      `exiting (code ${EXIT_TRANSPORT_FATAL}) so the write cannot outlive its history`
    );
  }
  tjs.exit(EXIT_TRANSPORT_FATAL);
}

/** End the open transfer without completing it: free it, and take a parked write back. */
function abandonOpenTransfer() {
  const transfer = openTransfer;
  openTransfer = null;
  if (transfer?.kind !== 'reply') return;
  discardParkedWrite(transfer.startedTxn, 'a write whose answer was not taken');
  lastAbandonedReplyId = transfer.id;
}

/** Whether `content` is the next frame of `transfer`. */
function continuesOpenTransfer(transfer, content) {
  if (content?.kind !== 'invoke') return false;
  if (content.targetMethod === NATIVE_TRANSFER_METHOD) {
    const [op, id, index] = Array.isArray(content.payload) ? content.payload : [];
    if (id !== transfer.id) return false;
    if (transfer.kind === 'request') return op === 'push' && index === transfer.pieces.length && index > 0;
    if (op === 'pull') return index === transfer.nextIndex && index < transfer.bounds.length - 1;
    return op === 'commit' && transfer.nextIndex === transfer.bounds.length - 1;
  }
  return transfer.kind === 'request' && content.payloadTransfer?.id === transfer.id;
}

/** One nativeTransfer frame (dispatchFrame has already ended any transfer it does not continue). */
function handleTransferOp(content) {
  const { messageId, payload } = content;
  const answer = (data) => sendGuarded({ channel: 'rpc', content: { kind: 'response', messageId, success: true, data } });
  const refuse = (message, code) => {
    const error = new Error(message);
    if (code !== undefined) error.code = code;
    sendGuarded(frameErrorResponse(error, messageId));
  };
  // What became of a transfer that is not open, as far as this sidecar knows.
  const notOpen = (id) => (id === lastAbandonedReplyId
    ? refuse(`Native transfer ${id} is not open; the write it carried was rolled back`, NATIVE_TRANSFER_ROLLED_BACK)
    : refuse(
      `Native transfer ${id} is not open, and this sidecar cannot tell whether the write it carried ` +
      'was committed or rolled back', NATIVE_TRANSFER_UNKNOWN));
  if (!Array.isArray(payload)) return refuse('nativeTransfer payload must be an array');
  const [op, id] = payload;
  if (!isTransferId(id)) return refuse('nativeTransfer needs a transfer id');

  if (op === 'push') {
    const [, , index, parts, length, piece] = payload;
    if (!Number.isSafeInteger(length) || length < 1 || length > MAX_NATIVE_TRANSFER_UNITS
      || !Number.isSafeInteger(parts) || parts < 1 || parts > length
      || !Number.isSafeInteger(index) || index < 0 || index >= parts
      // Counted as the shell's gate counts it: the piece as it crossed, its
      // codec escape of a leading `~` included (native-transfer.js).
      || typeof piece !== 'string' || piece.length === 0 || wirePieceUnits(piece) > TRANSFER_PIECE_UNITS) {
      openTransfer = null;
      return refuse(`Native transfer ${id}: malformed request piece; the request was discarded`);
    }
    if (index === 0) openTransfer = { kind: 'request', id, length, parts, pieces: [], units: 0 };
    const transfer = openTransfer;
    if (transfer?.kind !== 'request' || transfer.id !== id || transfer.pieces.length !== index
      || transfer.length !== length || transfer.parts !== parts || transfer.units + piece.length > length) {
      openTransfer = null;
      return refuse(`Native transfer ${id}: request piece ${index + 1} is out of order; the request was discarded`);
    }
    transfer.pieces.push(piece);
    transfer.units += piece.length;
    return answer({ id, index });
  }

  if (op === 'pull') {
    const transfer = openTransfer;
    if (transfer?.kind !== 'reply' || transfer.id !== id) return notOpen(id);
    const index = transfer.nextIndex;
    transfer.nextIndex += 1;
    return answer({ id, index, piece: transfer.text.slice(transfer.bounds[index], transfer.bounds[index + 1]) });
  }

  if (op === 'commit') {
    const transfer = openTransfer;
    if (transfer?.kind === 'reply' && transfer.id === id) {
      openTransfer = null;
      if (!activeDb?.inTransaction) {
        // The engine rolled the whole transaction back underneath it.
        lastAbandonedReplyId = id;
        return notOpen(id);
      }
      try {
        activeDb.run(`RELEASE ${REPLY_SAVEPOINT}`);
      } catch (error) {
        // RELEASE fails only when it is the COMMIT of a transaction this
        // savepoint began (busy): nothing of the write may stay.
        discardParkedWrite(transfer.startedTxn, 'a write whose commit failed');
        lastAbandonedReplyId = id;
        return refuse(
          `Committing native transfer ${id} failed (${error?.message ?? error}); the write was rolled back`,
          NATIVE_TRANSFER_ROLLED_BACK
        );
      }
      lastCommittedReplyId = id;
      return answer({ id, committed: true });
    }
    if (transfer === null && id === lastCommittedReplyId) return answer({ id, committed: true });
    return notOpen(id);
  }

  return refuse(`unknown nativeTransfer operation ${JSON.stringify(op ?? null).slice(0, 64)}`);
}

/** The assembled payload an invoke names in place of `payload`; consumes the open request. */
function takeAssembledPayload(content) {
  const transfer = openTransfer;
  openTransfer = null;
  const reference = content.payloadTransfer;
  if (!REQUEST_TRANSFER_METHODS.has(content.targetMethod)) {
    throw new Error(`${String(content.targetMethod).slice(0, 64)} cannot take its payload in pieces; nothing ran`);
  }
  if (transfer?.kind !== 'request' || reference?.id !== transfer.id || reference.length !== transfer.length
    || reference.parts !== transfer.parts || transfer.pieces.length !== transfer.parts
    || transfer.units !== transfer.length) {
    throw new Error(`The pieces of this ${content.targetMethod} request did not all arrive; nothing ran`);
  }
  const payload = decodeTransferText(transfer.pieces.join(''));
  if (!Array.isArray(payload)) throw new Error(`${content.targetMethod}: an assembled payload must be an array`);
  return payload;
}

/**
 * Run one of REPLY_TRANSFER_METHODS inside an outer savepoint. An answer that
 * fits one frame is released and sent as always. A larger one is parked with
 * the savepoint still open and announced as a transfer; the page's commit
 * releases it, and anything else rolls it back. A failure rolls the outer
 * savepoint back and forwards the worker's response content as it is
 * (errorMessage and the typed refusal data the host rebuilds).
 */
async function runWithReplyTransfer(content) {
  const { messageId, targetMethod } = content;
  const startedTxn = !activeDb.inTransaction;
  activeDb.run(`SAVEPOINT ${REPLY_SAVEPOINT}`);
  replyTransfer = { measured: null };
  let captured;
  let measured;
  try {
    captured = await captureWorkerResponse(targetMethod, content.payload);
  } catch (error) {
    discardParkedWrite(startedTxn, `a ${targetMethod} that posted no answer`);
    throw error;
  } finally {
    measured = replyTransfer?.measured ?? null;
    replyTransfer = null;
  }
  if (captured.success !== true) {
    discardParkedWrite(startedTxn, `a failed ${targetMethod}`);
    sendGuarded({ channel: 'rpc', content: { ...captured, messageId } });
    return;
  }

  const text = measured?.data === captured.data ? measured.text : encodeTransferText(captured.data);
  const response = { channel: 'rpc', content: { kind: 'response', messageId, success: true, data: captured.data } };
  let fits = false;
  // Characters never outnumber bytes, so a longer text cannot fit a frame.
  if (text.length <= MAX_FRAME_BYTES) {
    try {
      encodeFrame(response);
      fits = true;
    } catch (error) {
      if (!(isNativeFrameError(error) && error.code === NATIVE_FRAME_TOO_LARGE)) {
        discardParkedWrite(startedTxn, `a ${targetMethod} whose answer could not be encoded`);
        throw error;
      }
    }
  }
  if (fits) {
    try {
      activeDb.run(`RELEASE ${REPLY_SAVEPOINT}`);
    } catch (error) {
      discardParkedWrite(startedTxn, `a ${targetMethod} whose release failed`);
      throw error;
    }
    sendGuarded(response);
    return;
  }
  if (text.length > MAX_NATIVE_TRANSFER_UNITS) {
    // worker.js refuses this by name first (assertWriteAnswerFits); a backstop.
    discardParkedWrite(startedTxn, `a ${targetMethod} whose answer is over the transfer limit`);
    throw new Error(
      `${targetMethod} needs ${text.length} encoded characters to return the values undo restores, over the ` +
      `${MAX_NATIVE_TRANSFER_UNITS}-character limit of one native engine answer. Nothing was changed.`
    );
  }
  const id = `reply_${++replySequence}`;
  const bounds = transferPieceBounds(text);
  openTransfer = { kind: 'reply', id, text, bounds, nextIndex: 0, startedTxn };
  sendGuarded({
    channel: 'rpc',
    content: { kind: 'transfer', messageId, transfer: { id, length: text.length, parts: bounds.length - 1 } }
  });
}

// Dispatch: shell-originated messages are routed to the shell-export handler
// (and ONLY messages already marked `channel:'shell'` — an rpc envelope can
// never become a shell export, whatever its content claims); exportDatabase
// invokes are intercepted; everything else flows to the unchanged worker
// method layer (its `self.onmessage` assignment — the globalThis read below).
// Async (and try/caught) so no malformed envelope or handler failure can
// throw synchronously into the transport's read loop — a dispatch-level
// failure answers in band instead. worker.js has registered its onmessage by
// the time any frame can arrive: native-entry.js imports it before calling
// transport.start().
async function dispatchFrame(event) {
  const envelope = event?.data;
  try {
    // Each request gets one lock wait, whichever route serves it.
    activeDb?.restoreLockWait();
    let content = envelope?.channel === 'rpc' ? envelope.content : undefined;
    const transferOp = content?.kind === 'invoke' && content.targetMethod === NATIVE_TRANSFER_METHOD
      ? (Array.isArray(content.payload) ? content.payload[0] : undefined)
      : null;
    // An open transfer survives only the frames that continue it. Any other
    // frame, rpc or shell, ends it BEFORE it runs: a parked write goes back.
    if (openTransfer !== null && !continuesOpenTransfer(openTransfer, content)) abandonOpenTransfer();
    if (envelope?.channel === 'shell') {
      if (envelope.content?.kind === 'export') {
        await handleShellExport(envelope.content);
      } else {
        // Trusted sender, unknown kind: version skew. There is no defined
        // reply shape for it, so say so where the shell's logs can see it.
        console.error(
          `[native-worker] unknown shell message kind ${JSON.stringify(envelope.content?.kind ?? null)}; dropped`
        );
      }
      return;
    }
    if (transferOp !== null) {
      if (!isWorkerMessageId(content.messageId)) {
        console.warn('[native-worker] nativeTransfer frame with an invalid correlation ID; dropped');
        return;
      }
      handleTransferOp(content);
      return;
    }
    if (content?.kind === 'invoke' && content.payloadTransfer !== undefined) {
      content = {
        kind: 'invoke',
        messageId: content.messageId,
        targetMethod: content.targetMethod,
        payload: takeAssembledPayload(content)
      };
      event = { data: { channel: 'rpc', content } };
    }
    if (content?.kind === 'invoke' && content.targetMethod === 'exportDatabase') {
      await handleExportDatabase(content.messageId);
      return;
    }
    if (content?.kind === 'invoke' && REPLY_TRANSFER_METHODS.has(content.targetMethod) && activeDb !== null
      && isWorkerMessageId(content.messageId) && Array.isArray(content.payload)) {
      await runWithReplyTransfer(content);
      return;
    }
    await globalThis.onmessage?.(event);
  } catch (error) {
    sendGuarded(frameErrorResponse(error, messageIdOf(envelope)));
  }
}

// Frames run one at a time, in arrival order, each to completion: what the
// WebAssembly worker gives the page for free, since each of its messages is
// its own task and its handlers wait only on microtasks. The frame reader
// calls onmessage synchronously for every frame a pipe read holds, so without
// this chain the handlers of one read's frames would interleave at their
// awaits: a grid read sent after an edit ran first and showed the old rows,
// two writes' savepoints could cross, and a shell export behind a write
// exported the table as it was before it. Shell frames (the export route)
// queue with the rest: an export is bounded by the shell's 120 s export
// timeout, well inside the 600 s an rpc queued behind it may wait.
let frameChain = Promise.resolve();
transport.onmessage = (event) => {
  const run = frameChain.then(() => dispatchFrame(event));
  frameChain = run.then(() => undefined, () => undefined);
  return run;
};

// ---------------------------------------------------------------------------
// Orphan watchdog
// ---------------------------------------------------------------------------

// stdin EOF is the PRIMARY orphan signal (transport.start() resolving in the
// entry). This ppid poll is the backstop for the write end having been
// inherited by some other process, which would keep the pipe open after the
// parent died. Captured at boot: if the parent died even earlier, ppid never
// changes again and the EOF path is the one that fires.
const bootPpid = tjs.ppid;
let orphanExitStarted = false;
setInterval(() => {
  if (tjs.ppid !== bootPpid && !orphanExitStarted) {
    orphanExitStarted = true;
    // The code is named in the breadcrumb because an orphaned process reparents
    // to the OS reaper (launchd/init), so its real wait-status is not reap-able
    // by any surviving relative — the log line is the only channel that carries
    // the numeric exit code out.
    console.error(
      `[native-worker] parent process ${bootPpid} vanished without closing ` +
      `stdin (ppid now ${tjs.ppid}); exiting (code ${EXIT_ORPHANED})`
    );
    closeDatabaseForExit().finally(() => tjs.exit(EXIT_ORPHANED));
  }
}, PPID_WATCHDOG_INTERVAL_MS);
