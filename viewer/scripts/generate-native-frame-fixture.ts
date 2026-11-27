/**
 * Writes the CROSS-LANGUAGE frame fixture consumed by the Rust parent.
 *
 *   npx tsx scripts/generate-native-frame-fixture.ts
 *
 * `tests/fixtures/native-frames.bin` is a concatenation of REAL frames
 * produced by `core/native/frame-codec.js` — never hand-written and never
 * re-derived on the Rust side. The shell's `src-tauri` tests decode those exact
 * bytes and compare against `native-frames.json`, so a change to the codec
 * that would desynchronise the two languages fails first in
 * `tests/unit/native_frame_codec.test.ts`, which regenerates the fixture and
 * byte-compares it against the committed copy.
 *
 * The 16 MiB boundary is pinned as HEADER BYTES rather than as a 16 MiB frame:
 * committing a 16 MiB blob to git to fix four bytes is a bad trade, and the
 * only part of an over-cap frame the decoder ever looks at is its prefix. The
 * real 16 MiB frame is exercised end-to-end through the real binary by
 * `npm run native-lane`.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    FRAME_HEADER_BYTES,
    MAX_DRAIN_BYTES,
    MAX_FRAME_BYTES,
    encodeFrame,
    encodeFrameHeader,
    encodeFrameValue,
    readFrameHeader
} from '../core/native/frame-codec.js';

export const FIXTURE_BASENAME = 'native-frames';

export interface FrameFixtureEntry {
    /** What this frame exists to pin. */
    label: string;
    /** Byte offset of the frame's header inside the .bin. */
    offset: number;
    /** Declared payload length — the value of the big-endian prefix. */
    payloadBytes: number;
    /** The 4 header bytes, so a decoder can be checked before it parses anything. */
    header: number[];
    /** The exact UTF-8 JSON the payload must decode to. */
    payloadUtf8: string;
}

/**
 * A wire form the decoder must ACCEPT but the encoder never emits, so it can
 * have no frame in the .bin without leaving Rust guessing.
 */
export interface DecodeOnlyCase {
    label: string;
    payloadUtf8: string;
    note: string;
}

export interface FrameFixtureManifest {
    /** Bumped when the wire contract changes in a way Rust must follow. */
    version: number;
    format: string;
    limits: {
        maxFrameBytes: number;
        /** Header for a payload of exactly the cap — must be ACCEPTED. */
        maxHeader: number[];
        /** Header for one byte over the cap — REJECTED, then drained, then resync. */
        overMaxHeader: number[];
        /**
         * A header at or below this is drained and the stream resynchronises;
         * above it the stream is treated as desynchronised and reading stops.
         */
        maxDrainBytes: number;
        /** Header for exactly the drain limit — still RECOVERABLE. */
        maxDrainHeader: number[];
        /** Header for one byte past it — FATAL desync, stop reading. */
        overMaxDrainHeader: number[];
        /**
         * 0x80000000. A SIGNED 32-bit read returns -2147483648 here, which
         * slips past every `> limit` check and leaves the decoder waiting on a
         * body that never ends. Read the header as UNSIGNED.
         */
        signedTrapHeader: number[];
        /** 0xffffffff — the largest expressible length; must hit the desync path. */
        maxU32Header: number[];
    };
    frames: FrameFixtureEntry[];
    decodeOnly: DecodeOnlyCase[];
}

/** An error carrying the fork's NON-ENUMERABLE errno, exactly as tjs:sqlite raises it. */
function sqliteError(message: string, errno: number): Error {
    const error = new Error(message);
    Object.defineProperty(error, 'errno', { value: errno, enumerable: false });
    return error;
}

/**
 * Every case here is a byte-level fact the Rust side has to agree with, not a
 * behavioural sample. Keep additions append-only so existing offsets in the
 * manifest stay meaningful across regenerations.
 */
function fixtureMessages(): Array<{ label: string; message: unknown }> {
    return [
        {
            label: 'minimal invoke envelope',
            message: {
                channel: 'rpc',
                content: { kind: 'invoke', messageId: 'm-1', targetMethod: 'ping', payload: [] }
            }
        },
        {
            label: 'int64 edges — number below 2^53, BigInt at and beyond it',
            message: {
                channel: 'rpc',
                content: {
                    kind: 'response',
                    messageId: 'm-2',
                    success: true,
                    data: {
                        columns: ['maxSafe', 'atBoundary', 'pastBoundary', 'int64Max', 'int64Min', 'zero'],
                        values: [[
                            9007199254740991,
                            9007199254740992n,
                            9007199254740993n,
                            9223372036854775807n,
                            -9223372036854775808n,
                            0n
                        ]]
                    }
                }
            }
        },
        {
            label: 'blob cells — empty, high bytes, and a DataView',
            message: {
                channel: 'rpc',
                content: {
                    kind: 'response',
                    messageId: 'm-3',
                    success: true,
                    data: {
                        columns: ['empty', 'bytes', 'view'],
                        values: [[
                            new Uint8Array([]),
                            new Uint8Array([0, 1, 0x7f, 0x80, 0xfe, 0xff]),
                            new DataView(new Uint8Array([0xde, 0xad, 0xbe, 0xef]).buffer)
                        ]]
                    }
                }
            }
        },
        {
            label: 'non-finite REALs and the escaped sentinel namespace',
            message: {
                channel: 'rpc',
                content: {
                    kind: 'response',
                    messageId: 'm-4',
                    success: true,
                    data: {
                        columns: ['pos', 'neg', 'nan', 'literalSentinel', 'tilde', 'empty'],
                        values: [[
                            Number.POSITIVE_INFINITY,
                            Number.NEGATIVE_INFINITY,
                            Number.NaN,
                            '~sqlite-explorer-non-finite:NaN',
                            '~',
                            ''
                        ]]
                    }
                }
            }
        },
        {
            label: 'error response carrying a NON-ENUMERABLE SQLite errno',
            message: {
                channel: 'rpc',
                content: {
                    kind: 'response',
                    messageId: 'm-5',
                    success: false,
                    errorMessage: 'constraint failed',
                    error: { name: 'Error', message: 'constraint failed', errno: 19 }
                }
            }
        },
        {
            label: 'tagged Error value inside a payload (errno survives the marker)',
            message: {
                channel: 'rpc',
                content: {
                    kind: 'response',
                    messageId: 'm-6',
                    success: true,
                    data: { failures: [sqliteError('attempt to write a readonly database', 8)] }
                }
            }
        },
        {
            // The two trailing control characters are written as ESCAPES on
            // purpose: as literal bytes they put a NUL in this source file,
            // which makes git classify it binary and hide its diffs. Same
            // string value, same fixture bytes.
            label: 'non-ASCII text — payload byte length exceeds its code-unit length',
            message: {
                channel: 'rpc',
                content: {
                    kind: 'response',
                    messageId: 'm-7',
                    success: true,
                    data: { columns: ['t'], values: [['héllo 𝕏 日本語 \u0000\u001f']] }
                }
            }
        },
        {
            label: 'endianness discriminator — payload padded to exactly 258 bytes (header 00 00 01 02)',
            message: undefined as unknown // replaced below; needs its own encoded length
        },
        {
            // Larger than a typical 4 KiB read buffer, so a decoder that
            // assumes one read per frame fails here. Deliberately NOT 256 KiB:
            // the fixture pins BYTES, and chunk sizes are a runtime property
            // the lane already proves against the real binary byte-identically.
            label: 'multi-read payload — 8 KiB, spans more than one read buffer',
            message: {
                channel: 'rpc',
                content: {
                    kind: 'response',
                    messageId: 'm-9',
                    success: true,
                    data: { columns: ['big'], values: [['x'.repeat(8 * 1024)]] }
                }
            }
        }
    ];
}

/**
 * Pad a message so its encoded payload is EXACTLY `target` bytes. The padding
 * is ASCII, so one character is one byte and the fit is a subtraction.
 */
function paddedToExactly(target: number): unknown {
    const build = (pad: string) => ({ channel: 'rpc', content: { kind: 'ping', pad } });
    const base = encodeFrame(build('')).length - FRAME_HEADER_BYTES;
    const padding = target - base;
    if (padding < 0) throw new Error(`cannot pad below the ${base}-byte floor`);
    return build('P'.repeat(padding));
}

export function buildFrameFixture(): { bytes: Uint8Array; manifest: FrameFixtureManifest } {
    const entries = fixtureMessages();
    const discriminator = entries.findIndex((entry) => entry.message === undefined);
    entries[discriminator].message = paddedToExactly(258);

    const frames: FrameFixtureEntry[] = [];
    const parts: Uint8Array[] = [];
    let offset = 0;

    for (const { label, message } of entries) {
        const frame = encodeFrame(message);
        const payloadBytes = readFrameHeader(frame);
        frames.push({
            label,
            offset,
            payloadBytes,
            header: Array.from(frame.subarray(0, FRAME_HEADER_BYTES)),
            payloadUtf8: new TextDecoder().decode(frame.subarray(FRAME_HEADER_BYTES))
        });
        parts.push(frame);
        offset += frame.length;
    }

    const bytes = new Uint8Array(offset);
    let cursor = 0;
    for (const part of parts) {
        bytes.set(part, cursor);
        cursor += part.length;
    }

    return {
        bytes,
        manifest: {
            version: 2,
            format: 'u32 big-endian payload length || UTF-8 JSON payload',
            limits: {
                maxFrameBytes: MAX_FRAME_BYTES,
                maxHeader: Array.from(encodeFrameHeader(MAX_FRAME_BYTES)),
                overMaxHeader: Array.from(encodeFrameHeader(MAX_FRAME_BYTES + 1)),
                maxDrainBytes: MAX_DRAIN_BYTES,
                maxDrainHeader: Array.from(encodeFrameHeader(MAX_DRAIN_BYTES)),
                overMaxDrainHeader: Array.from(encodeFrameHeader(MAX_DRAIN_BYTES + 1)),
                signedTrapHeader: Array.from(encodeFrameHeader(0x80000000)),
                maxU32Header: Array.from(encodeFrameHeader(0xffffffff))
            },
            frames,
            decodeOnly: [
                {
                    label: 'legacy array-form Uint8Array marker',
                    payloadUtf8: JSON.stringify({
                        v: { __type: 'Uint8Array', data: [1, 2, 255] }
                    }),
                    note: 'ACCEPTED on decode for wire compatibility with older webview '
                        + 'payloads; the encoder NEVER emits it, which is why it has no frame '
                        + 'in the .bin. A decoder must handle it; it must not produce it. The '
                        + 'canonical emitted form is the base64 marker — see the blob frame.'
                },
                {
                    label: 'canonical blob marker, for contrast',
                    payloadUtf8: JSON.stringify(encodeFrameValue({
                        v: new Uint8Array([1, 2, 255])
                    })),
                    note: 'What the encoder actually emits for the same three bytes.'
                }
            ]
        }
    };
}

export function writeFrameFixture(directory: string): void {
    const { bytes, manifest } = buildFrameFixture();
    fs.mkdirSync(directory, { recursive: true });
    fs.writeFileSync(path.join(directory, `${FIXTURE_BASENAME}.bin`), bytes);
    fs.writeFileSync(
        path.join(directory, `${FIXTURE_BASENAME}.json`),
        `${JSON.stringify(manifest, null, 2)}\n`
    );
    console.log(
        `wrote ${manifest.frames.length} frames (${bytes.length} bytes) to `
        + `${path.join(directory, `${FIXTURE_BASENAME}.bin`)}`
    );
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
    writeFrameFixture(path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        '..',
        'tests',
        'fixtures'
    ));
}
