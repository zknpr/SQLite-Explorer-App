/**
 * Types for native-transfer.js — values larger than one native frame, carried
 * in pieces in both directions. See the module docstring for the protocol.
 */

export const NATIVE_TRANSFER_METHOD: 'nativeTransfer';
export const NATIVE_TRANSFER_ROLLED_BACK: 'ERR_NATIVE_TRANSFER_ROLLED_BACK';
export const NATIVE_TRANSFER_UNKNOWN: 'ERR_NATIVE_TRANSFER_UNKNOWN';
/** The most one transfer may hold, in UTF-16 code units of JSON text. */
export const MAX_NATIVE_TRANSFER_UNITS: number;
/** The longest piece, in UTF-16 code units. */
export const TRANSFER_PIECE_UNITS: number;
/** Methods whose answer may cross as a transfer. */
export const REPLY_TRANSFER_METHODS: ReadonlySet<string>;
/** Methods whose request may cross as a transfer. */
export const REQUEST_TRANSFER_METHODS: ReadonlySet<string>;

export function isTransferId(id: unknown): id is string;
export function encodeTransferText(value: unknown): string;
export function decodeTransferText(text: string): unknown;
/** Piece starts plus `text.length`; never splits a surrogate pair. */
export function transferPieceBounds(text: string, maxUnits?: number): number[];
export function sliceTransferText(text: string, maxUnits?: number): string[];
export function utf8Length(text: string): number;
/** A piece's UTF-16 length as it crosses the wire: one more for a leading '~'. */
export function wirePieceUnits(piece: string): number;

export class NativeTransferUnconfirmedError extends Error {
    readonly name: 'NativeTransferUnconfirmedError';
    readonly code: 'ERR_NATIVE_TRANSFER_UNCONFIRMED';
    constructor(method: string, cause: unknown);
}

/** True for a shell refusal after which the session's uncommitted writes cannot persist. */
export function endsTheSession(error: unknown): boolean;
/** `error` as an Error marked as the lost answer to a call's own request. */
export function noteLostAnswer(error: unknown): Error;
/** True when `error` is a lost answer to a call's own request: the method may have run. */
export function answerWasLost(error: unknown): boolean;
export function exchangeNativeCall(call: {
    method: string;
    messageId: string;
    args: unknown[];
    envelopeJson: string;
    send: (json: string) => Promise<string>;
    alive: () => boolean;
}): Promise<unknown>;
