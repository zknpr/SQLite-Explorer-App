#!/usr/bin/env node
/**
 * Regenerates src-tauri/tests/fixtures/native-transfer/: nativeTransfer push
 * envelopes encoded by the page's own codec (viewer/core/native), for the shell gate's
 * piece-length and tagged-value checks (native.rs check_native_transfer). The
 * pieces are judged at a small TEST bound (TEST_PIECE_UNITS) that the Rust test
 * injects (check_native_transfer_bounded), so the fixtures stay a few KB; the
 * real bound is pinned by a Rust-built test and by transferPieceUnits here.
 *
 *   node scripts/gen-native-transfer-fixtures.mjs [--source <viewer sources>]
 *
 * The codec imports a .ts file, so this needs a runtime that strips
 * TypeScript: Node 24 (run as above) or bun. --source defaults to viewer/ in
 * this repository; the manifest records the sha256 of every codec source read,
 * so a fixture is always traceable to the code that wrote it (a commit id would
 * not survive a history rewrite; the hashes do).
 *
 * Each case's expectation is the sidecar's own rule,
 * which the gate applies too: the piece must decode to a non-empty string whose
 * wire form, the codec's escape of a leading `~` included (wirePieceUnits), is at
 * most the bound in UTF-16 units. The generator refuses to write a case on which
 * the gate's rule and the sidecar's would differ.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const argv = process.argv.slice(2);
const valueOf = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.resolve(valueOf('--source', path.join(repoRoot, 'viewer')));
const outDir = path.join(repoRoot, 'src-tauri', 'tests', 'fixtures', 'native-transfer');
const sources = ['core/native/frame-codec.js', 'core/native/native-transfer.js', 'src/core/json-safe-numbers.ts'];

const codec = await import(pathToFileURL(path.join(source, 'core/native/frame-codec.js')).href);
const transfer = await import(pathToFileURL(path.join(source, 'core/native/native-transfer.js')).href);
/** The bound the Rust test injects for these pieces; the real one is TRANSFER_PIECE_UNITS. */
const TEST_PIECE_UNITS = 64;
const bound = TEST_PIECE_UNITS;

// What the page sends over native_rpc for one push: the envelope encoded by the
// frame codec, as exchangeNativeCall does.
const pushEnvelope = (n, piece) => JSON.stringify(codec.encodeFrameValue({
  channel: 'rpc',
  content: {
    kind: 'invoke',
    messageId: `rpc_fixture_${n}`,
    targetMethod: transfer.NATIVE_TRANSFER_METHOD,
    payload: ['push', 'req_1_fixture', 0, 2, 2 * bound, piece]
  }
}));

// A `~`-led piece travels one unit longer than it decodes (the codec's escape).
const cases = [
  ['tilde-wire-one-short', '~'.repeat(bound - 2)],
  ['tilde-wire-at-bound', '~'.repeat(bound - 1)],
  ['tilde-wire-one-over', '~'.repeat(bound)],
  ['tagged-non-finite', Number.NaN]
];

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(outDir, { recursive: true });
const manifest = {
  generator: 'scripts/gen-native-transfer-fixtures.mjs',
  source: {
    sha256: Object.fromEntries(sources.map((file) => [
      file, createHash('sha256').update(fs.readFileSync(path.join(source, file))).digest('hex')
    ]))
  },
  testPieceUnits: bound,
  transferPieceUnits: transfer.TRANSFER_PIECE_UNITS,
  cases: []
};
for (const [index, [name, piece]] of cases.entries()) {
  const envelope = pushEnvelope(index, piece);
  const wire = JSON.parse(envelope).content.payload[5];
  const decoded = codec.decodeFrameValue(JSON.parse(envelope)).content.payload[5];
  // The gate's rule: text that decodes to a non-empty string, never a single
  // leading `~` (the codec's tag for a non-finite number), at most `bound` on the wire.
  const gateAdmits = typeof wire === 'string' && !(wire.startsWith('~') && !wire.startsWith('~~'))
    && typeof decoded === 'string' && decoded.length > 0 && wire.length <= bound;
  const sidecarAccepts = typeof decoded === 'string' && decoded.length > 0
    && transfer.wirePieceUnits(decoded) <= bound;
  if (gateAdmits !== sidecarAccepts) throw new Error(`${name}: the gate's rule and the sidecar's disagree`);
  fs.writeFileSync(path.join(outDir, `${name}.json`), envelope);
  manifest.cases.push({
    file: `${name}.json`,
    gate: gateAdmits ? 'admit' : 'refuse',
    wireUnits: typeof wire === 'string' ? wire.length : null,
    decodedType: typeof decoded,
    decodedUnits: typeof decoded === 'string' ? decoded.length : null,
    sidecarAccepts: sidecarAccepts
  });
}
fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`native-transfer fixtures: ${cases.length} cases`);
