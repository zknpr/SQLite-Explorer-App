/**
 * Values larger than one native frame, carried in pieces, in both directions.
 *
 * Every frame between the page and the sidecar stays within MAX_FRAME_BYTES:
 * the shell's bounded-memory reasoning (write queue cap x frame cap x
 * sidecars) depends on it. A history-bearing edit can still need more: its
 * answer carries the prior values undo restores, and the undo and redo
 * requests carry them back. Those cross as a TRANSFER: the JSON text of the
 * value, cut into pieces that each fit a frame, sent one at a time over the
 * `nativeTransfer` transport method, which native-host.js serves before the
 * worker's own dispatch. Pieces carry nothing but a short id, counts and
 * opaque text; the real envelope, with its real targetMethod, still crosses
 * the shell's layer 3 as one frame, and its payload is decoded with the same
 * codec as a frame.
 *
 * Answers (sidecar -> page): a writing method's answer too large for one
 * frame is parked by the sidecar with its write still inside a savepoint, and
 * the invoke is answered `{kind: 'transfer', transfer: {id, length, parts}}`.
 * The page pulls every piece, decodes the whole, and only then commits; the
 * sidecar releases the savepoint on that commit, and ANY other frame first
 * rolls the write back. So the write never stays in the session without the
 * history that undoes it.
 *
 * Requests (page -> sidecar): an envelope over the frame is pushed as pieces,
 * then sent as the real invoke with `payloadTransfer` naming them in place of
 * `payload`. Any other frame between them discards the pieces: nothing runs.
 *
 * WHY PIECES ARE CUT BY CODE UNITS. The transferred text is always
 * JSON.stringify output, which since ES2019 holds no raw control character
 * and no lone surrogate (both are escaped). Written again as a JSON string
 * inside a piece frame, one UTF-16 code unit of such text costs at most three
 * UTF-8 bytes: `"` and `\\` become two, other ASCII one, U+0080-U+07FF
 * two, the rest of the BMP three, and a surrogate pair four for two units. A
 * piece of TRANSFER_PIECE_UNITS units therefore fits a frame with
 * PIECE_ENVELOPE_RESERVE_BYTES to spare, with no per-character scan (which
 * costs ~27 ms/MiB in the sidecar's QuickJS). A piece never ends between the
 * two halves of a pair: a lone surrogate is what the shell's serde_json
 * refuses, and the shell drops a frame it cannot parse, which would leave the
 * pull waiting for its timeout.
 *
 * A PIECE IS MEASURED AS IT CROSSES. The frame codec prefixes one more `~` to
 * any string that starts with `~` (escapeJsonSafeNumberString,
 * src/core/json-safe-numbers.ts), so such a piece is one unit longer on the
 * wire than in memory. The shell's gate counts the wire string's UTF-16 units
 * against TRANSFER_PIECE_UNITS (check_native_transfer), and the sidecar
 * applies the same count to what it receives (wirePieceUnits). So a piece is
 * cut to TRANSFER_PIECE_UNITS units AS SENT: one unit shorter when it starts
 * with `~`, in both directions. The frame reserve covers that unit for the
 * pull answers, which the shell does not count.
 */

import { MAX_FRAME_BYTES, decodeFrameValue, encodeFrameValue } from './frame-codec.js';
import { jsonSafeNumberStringExpansionBytes } from '../../src/core/json-safe-numbers.ts';

/** The transport method, served by native-host.js; never a worker method. */
export const NATIVE_TRANSFER_METHOD = 'nativeTransfer';

/** A transfer's write was rolled back: a known outcome. */
export const NATIVE_TRANSFER_ROLLED_BACK = 'ERR_NATIVE_TRANSFER_ROLLED_BACK';
/** The sidecar no longer knows whether a transfer's write was committed. */
export const NATIVE_TRANSFER_UNKNOWN = 'ERR_NATIVE_TRANSFER_UNKNOWN';

/**
 * The most one transfer may hold, in UTF-16 code units of JSON text, in either
 * direction, whatever budget the page asks for (settings.json is
 * webview-writable). One string of this length must be possible on every
 * engine the text meets: V8 (WebView2) stops at 2^29 - 24, QuickJS at 2^30 - 1.
 */
export const MAX_NATIVE_TRANSFER_UNITS = 256 * 1024 * 1024;

/** Room in a piece frame for its envelope: ids, counts, keys, the codec's `~` escape. */
const PIECE_ENVELOPE_RESERVE_BYTES = 4096;

/** The longest piece, in code units (see WHY PIECES ARE CUT BY CODE UNITS). */
export const TRANSFER_PIECE_UNITS = Math.floor((MAX_FRAME_BYTES - PIECE_ENVELOPE_RESERVE_BYTES) / 3);

/**
 * Methods whose ANSWER may be a transfer: the writing methods whose answer is
 * the history that undoes them. Each runs only SAVEPOINT/RELEASE inside, never
 * BEGIN, COMMIT or ROLLBACK, so native-host may wrap it in an outer savepoint
 * of its own. The worker's per-frame answer check is lifted for exactly these
 * (native-host measureReply); every other method still answers in one frame.
 */
export const REPLY_TRANSFER_METHODS = Object.freeze(new Set([
    'updateCellBatch', 'deleteRows', 'insertRowWithHistory', 'importRows'
]));

/**
 * Methods whose REQUEST may be a transfer: the same writes (a paste, an insert
 * or an import carries new values) and the history replays (they carry the
 * prior values back). Never initializeDatabase: the shell checks its path and
 * query timeout on the payload, which must therefore cross in one frame.
 */
export const REQUEST_TRANSFER_METHODS = Object.freeze(new Set([
    ...REPLY_TRANSFER_METHODS, 'undoModification', 'redoModification'
]));

const TRANSFER_ID = /^[A-Za-z0-9_-]{1,64}$/;

export const isTransferId = (id) => typeof id === 'string' && TRANSFER_ID.test(id);

/** The text a value crosses as: exactly what a frame would carry for it. */
export const encodeTransferText = (value) => JSON.stringify(encodeFrameValue(value));

export const decodeTransferText = (text) => decodeFrameValue(JSON.parse(text));

const isHighSurrogate = (code) => code >= 0xd800 && code <= 0xdbff;

/** A piece's length in UTF-16 units as it crosses the wire (see A PIECE IS MEASURED AS IT CROSSES). */
export const wirePieceUnits = (piece) => piece.length + jsonSafeNumberStringExpansionBytes(piece);

/**
 * Where each piece of `text` starts, plus `text.length`: piece i is
 * text.slice(bounds[i], bounds[i + 1]). Never splits a surrogate pair, and
 * every piece's wire form (wirePieceUnits) is at most `maxUnits`.
 *
 * @param {string} text
 * @param {number} [maxUnits]
 * @returns {number[]}
 */
export function transferPieceBounds(text, maxUnits = TRANSFER_PIECE_UNITS) {
    if (!Number.isSafeInteger(maxUnits) || maxUnits < 2) {
        throw new RangeError(`A transfer piece must hold at least 2 code units, got ${maxUnits}`);
    }
    const bounds = [0];
    let start = 0;
    while (start < text.length) {
        // The codec's escape of a leading `~` takes one unit of the piece.
        const room = maxUnits - jsonSafeNumberStringExpansionBytes(text.charAt(start));
        let end = Math.min(start + room, text.length);
        if (end < text.length && isHighSurrogate(text.charCodeAt(end - 1))) end -= 1;
        bounds.push(end);
        start = end;
    }
    if (text.length === 0) bounds.push(0);
    return bounds;
}

/** `text` cut into pieces (transferPieceBounds). */
export function sliceTransferText(text, maxUnits = TRANSFER_PIECE_UNITS) {
    const bounds = transferPieceBounds(text, maxUnits);
    const pieces = [];
    for (let index = 0; index + 1 < bounds.length; index++) pieces.push(text.slice(bounds[index], bounds[index + 1]));
    return pieces;
}

/** UTF-8 byte length of a JS string, as TextEncoder would write it. */
export function utf8Length(text) {
    let bytes = 0;
    for (let index = 0; index < text.length; index++) {
        const code = text.charCodeAt(index);
        if (code < 0x80) bytes += 1;
        else if (code < 0x800) bytes += 2;
        else if (isHighSurrogate(code) && index + 1 < text.length
            && text.charCodeAt(index + 1) >= 0xdc00 && text.charCodeAt(index + 1) <= 0xdfff) {
            bytes += 4;
            index++;
        } else bytes += 3;
    }
    return bytes;
}

/**
 * Both commit attempts for a parked answer failed while the database was still
 * open: the sidecar may or may not have kept the write. The host closes the
 * connection (its session rolls back) rather than keep an edit it cannot
 * account for.
 */
export class NativeTransferUnconfirmedError extends Error {
    constructor(method, cause) {
        super(
            `${method} wrote more than one native frame can answer, and its commit could not be confirmed `
            + `(${cause?.message ?? cause}). The connection was closed without saving so the edit cannot `
            + 'stay without its undo history; reload the database to continue.',
            { cause }
        );
        this.name = 'NativeTransferUnconfirmedError';
        this.code = 'ERR_NATIVE_TRANSFER_UNCONFIRMED';
    }
}

/**
 * Shell refusals after which the session's uncommitted writes cannot persist:
 * the file was replaced (the host retires the database and its sidecar), or
 * the sidecar exited or was closed. A commit refused with one of these is not
 * committed, whatever happened to an earlier attempt, so the shell's error
 * goes to the host as it is — its own handling (retire, for a replaced file)
 * applies — and is neither retried nor reported unconfirmed.
 */
const SESSION_ENDING_REFUSALS = ['ERR_NATIVE_FILE_CHANGED', 'ERR_NATIVE_SIDECAR_EXITED', 'ERR_NATIVE_UNKNOWN_DB'];
export const endsTheSession = (error) => {
    const text = String(error?.message ?? error);
    return SESSION_ENDING_REFUSALS.some(code => text === code || text.startsWith(`${code}:`));
};

/**
 * Failures of a call whose own invoke went to the shell and came back with no
 * readable answer: the method may have run. Every other failure of an
 * exchange has a known outcome -- a request piece fails before the invoke is
 * sent, and a write parked for a reply transfer that is never committed is
 * rolled back by the sidecar at its next frame -- except a commit that got no
 * answer, which is NativeTransferUnconfirmedError. A shell refusal made before
 * queueing the frame also comes back here; the caller tells those apart by
 * their code.
 */
const lostAnswers = new WeakSet();

/** `error` as an Error marked as a lost answer (see lostAnswers). */
export function noteLostAnswer(error) {
    const lost = error instanceof Error ? error : new Error(String(error));
    lostAnswers.add(lost);
    return lost;
}

export const answerWasLost = (error) => typeof error === 'object' && error !== null && lostAnswers.has(error);

let transferSequence = 0;

/**
 * The page half of one native call, whatever its size: one frame when the
 * request and answer fit, pieces otherwise. Every frame goes through `send`
 * (one shell round trip, envelope JSON in and out) strictly one at a time,
 * inside the caller's turn of the database's call chain.
 *
 * @param {object} call
 * @param {string} call.method - the real targetMethod
 * @param {string} call.messageId
 * @param {unknown[]} call.args - re-encoded only when the envelope is over the frame
 * @param {string} call.envelopeJson - the encoded invoke envelope
 * @param {(json: string) => Promise<string>} call.send
 * @param {() => boolean} call.alive - false once the call was failed (database
 *   closed or retired): the exchange stops before its next frame
 * @returns {Promise<object>} the decoded response envelope for `messageId`
 */
export async function exchangeNativeCall({ method, messageId, args, envelopeJson, send, alive }) {
    const roundTrip = async (envelope, what) => {
        if (!alive()) throw new Error(`${method} was abandoned before its ${what}: the database is no longer open`);
        return decodeFrameValue(JSON.parse(await send(JSON.stringify(encodeFrameValue(envelope)))));
    };
    const pieceAnswer = (response, pieceMessageId, what) => {
        const content = response?.channel === 'rpc' ? response.content : undefined;
        if (content?.kind !== 'response' || content.messageId !== pieceMessageId) {
            throw new Error(`${method}: the sidecar answered its ${what} with something else`);
        }
        if (content.success !== true) throw new Error(content.errorMessage || `${method}: the ${what} failed`);
        return content.data;
    };

    let json = envelopeJson;
    if (json.length > TRANSFER_PIECE_UNITS && utf8Length(json) > MAX_FRAME_BYTES) {
        if (REQUEST_TRANSFER_METHODS.has(method)) {
            const text = encodeTransferText(args);
            if (text.length > MAX_NATIVE_TRANSFER_UNITS) {
                throw new Error(
                    `${method} would send ${text.length} encoded characters, over the ${MAX_NATIVE_TRANSFER_UNITS}`
                    + '-character limit of one native engine request. Nothing was sent; change fewer cells or rows at a time.'
                );
            }
            const id = `req_${++transferSequence}_${Date.now()}`;
            const pieces = sliceTransferText(text);
            for (const [index, piece] of pieces.entries()) {
                const pieceId = `${messageId}_push${index}`;
                const data = pieceAnswer(await roundTrip({
                    channel: 'rpc',
                    content: {
                        kind: 'invoke', messageId: pieceId, targetMethod: NATIVE_TRANSFER_METHOD,
                        payload: ['push', id, index, pieces.length, text.length, piece]
                    }
                }, `request piece ${index + 1}`), pieceId, `request piece ${index + 1}`);
                if (data?.id !== id || data?.index !== index) {
                    throw new Error(`${method}: the sidecar acknowledged a different request piece`);
                }
            }
            json = JSON.stringify(encodeFrameValue({
                channel: 'rpc',
                content: {
                    kind: 'invoke', messageId, targetMethod: method,
                    payloadTransfer: { id, length: text.length, parts: pieces.length }
                }
            }));
        }
        // Any other method keeps today's answer: the shell refuses the frame.
    }

    if (!alive()) throw new Error(`${method} was abandoned before it was sent: the database is no longer open`);
    let responseJson;
    try {
        responseJson = await send(json);
    } catch (error) {
        throw noteLostAnswer(error);
    }
    let response;
    try {
        response = decodeFrameValue(JSON.parse(responseJson));
    } catch (error) {
        throw noteLostAnswer(new Error(`Native RPC response for ${method} is undecodable: ${error?.message ?? error}`));
    }
    const content = response?.channel === 'rpc' ? response.content : undefined;
    if (content?.kind !== 'transfer' || content.messageId !== messageId) return response;

    // The write is in, inside the sidecar's savepoint, until the commit below.
    if (!REPLY_TRANSFER_METHODS.has(method)) {
        throw new Error(`${method} answered in pieces, which only a history-bearing write may`);
    }
    const { id, length, parts } = content.transfer ?? {};
    if (!isTransferId(id) || !Number.isSafeInteger(length) || length < 1 || length > MAX_NATIVE_TRANSFER_UNITS
        || !Number.isSafeInteger(parts) || parts < 1 || parts > length) {
        throw new Error(`${method}: the sidecar announced an answer the host cannot accept`);
    }
    const pieces = [];
    let received = 0;
    for (let index = 0; index < parts; index++) {
        const pieceId = `${messageId}_pull${index}`;
        const data = pieceAnswer(await roundTrip({
            channel: 'rpc',
            content: {
                kind: 'invoke', messageId: pieceId, targetMethod: NATIVE_TRANSFER_METHOD,
                payload: ['pull', id, index]
            }
        }, `answer piece ${index + 1} of ${parts}`), pieceId, `answer piece ${index + 1} of ${parts}`);
        if (data?.id !== id || data?.index !== index || typeof data?.piece !== 'string'
            || data.piece.length === 0 || received + data.piece.length > length) {
            throw new Error(`${method}: answer piece ${index + 1} of ${parts} is not the piece that was asked for`);
        }
        pieces.push(data.piece);
        received += data.piece.length;
    }
    if (received !== length) throw new Error(`${method}: the answer arrived incomplete`);
    // Decoded BEFORE the commit: an answer the page cannot read is not
    // committed, and the write goes with it.
    const data = decodeTransferText(pieces.join(''));
    pieces.length = 0;

    // Only a commit that never got an answer leaves the outcome open. An answer
    // either way (committed, or refused because the write was rolled back) is
    // the outcome; a lost one is retried once — a commit is idempotent by id,
    // so the retry tells "the first one landed" from "it never arrived" (and
    // then commits). Two lost answers with the database still open leave the
    // write's fate unknown: NativeTransferUnconfirmedError.
    const commitId = `${messageId}_commit`;
    const commitEnvelope = {
        channel: 'rpc',
        content: { kind: 'invoke', messageId: commitId, targetMethod: NATIVE_TRANSFER_METHOD, payload: ['commit', id] }
    };
    let answer;
    try {
        answer = await roundTrip(commitEnvelope, 'commit');
    } catch (lost) {
        if (!alive() || endsTheSession(lost)) throw lost;
        try {
            answer = await roundTrip(commitEnvelope, 'commit');
        } catch (lostAgain) {
            if (!alive() || endsTheSession(lostAgain)) throw lostAgain;
            throw new NativeTransferUnconfirmedError(method, lostAgain);
        }
    }
    const outcome = answer?.channel === 'rpc' ? answer.content : undefined;
    if (outcome?.kind === 'response' && outcome.messageId === commitId && outcome.success === false
        && outcome.error?.code === NATIVE_TRANSFER_ROLLED_BACK) {
        // The sidecar rolled the write back: the edit failed, nothing stays.
        throw new Error(outcome.errorMessage || `${method}: the write was rolled back`);
    }
    if (outcome?.kind !== 'response' || outcome.messageId !== commitId || outcome.success !== true
        || outcome.data?.id !== id || outcome.data?.committed !== true) {
        // Anything else, a sidecar that cannot say included, leaves the
        // write's fate open.
        throw new NativeTransferUnconfirmedError(method,
            new Error(outcome?.errorMessage || 'the sidecar answered the commit with something else'));
    }
    return { channel: 'rpc', content: { kind: 'response', messageId, success: true, data } };
}
