import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import { UPDATER_PACKAGES } from './assemble.mjs';
import { parseChecksums, parsePublicKey, updateManifest, verifyMinisign } from './sign-update.mjs';

// A payload signed for 0.4.0 with a QA-only key (`tauri signer sign --app-version 0.4.0`).
// Only its public half is here; no release is signed with it.
const fixture = (name) => fs.readFileSync(new URL(`./fixtures/updater/${name}`, import.meta.url));
const qaKey = fixture('qa-only.key.pub').toString('utf8').trim();
const signature = fixture('payload.txt.sig').toString('utf8').trim();
const payload = fixture('payload.txt');

/** The signature with its decoded text edited, re-encoded as Tauri encodes it. */
function editSignature(change) {
  const text = Buffer.from(signature, 'base64').toString('utf8');
  return Buffer.from(change(text), 'utf8').toString('base64');
}

test('a signature is accepted only for its package, its version and its key', () => {
  assert.match(verifyMinisign({ publicKey: qaKey, signature, data: payload, version: '0.4.0' }), /version:0\.4\.0/);
  assert.doesNotThrow(() => verifyMinisign({ publicKey: qaKey, signature, data: payload, version: 'v0.4.0' }));
  const tampered = Buffer.concat([payload, Buffer.from('x')]);
  assert.throws(() => verifyMinisign({ publicKey: qaKey, signature, data: tampered, version: '0.4.0' }),
    /does not match the package/);
  assert.throws(() => verifyMinisign({ publicKey: qaKey, signature, data: payload, version: '0.4.1' }),
    /for version 0\.4\.0, not 0\.4\.1/);
  // An edited trusted comment (a version rewritten after signing) breaks the global signature.
  const rewritten = editSignature((text) => text.replace('version:0.4.0', 'version:0.4.1'));
  assert.throws(() => verifyMinisign({ publicKey: qaKey, signature: rewritten, data: payload, version: '0.4.1' }),
    /trusted comment is not covered/);
  // The same key id with other key bytes: the signature does not verify.
  const pub = Buffer.from(qaKey, 'base64').toString('utf8').split('\n');
  const raw = Buffer.from(pub[1], 'base64');
  raw[raw.length - 1] ^= 1;
  const otherKey = Buffer.from([pub[0], raw.toString('base64'), ''].join('\n')).toString('base64');
  assert.throws(() => verifyMinisign({ publicKey: otherKey, signature, data: payload, version: '0.4.0' }),
    /does not match the package/);
  // Another key id: refused before any arithmetic.
  raw[2] ^= 1;
  const otherId = Buffer.from([pub[0], raw.toString('base64'), ''].join('\n')).toString('base64');
  assert.throws(() => verifyMinisign({ publicKey: otherId, signature, data: payload, version: '0.4.0' }),
    /different key/);
});

test('latest.json lists exactly the three update packages, by their release download URLs', () => {
  const signatures = Object.fromEntries(Object.keys(UPDATER_PACKAGES).map((target) => [target, `sig of ${target}`]));
  const manifest = updateManifest({ version: '0.4.1', tag: 'v0.4.1', pubDate: '2026-12-01T00:00:00.000Z', signatures });
  assert.deepEqual(Object.keys(manifest.platforms).sort(), ['darwin-aarch64-app', 'linux-x86_64-deb', 'windows-x86_64-nsis']);
  assert.equal(manifest.platforms['darwin-aarch64-app'].url,
    'https://github.com/zknpr/SQLite-Explorer-App/releases/download/v0.4.1/SQLite-Explorer-0.4.1-macos-aarch64.app.tar.gz');
  assert.equal(manifest.platforms['linux-x86_64-deb'].url,
    'https://github.com/zknpr/SQLite-Explorer-App/releases/download/v0.4.1/SQLite-Explorer-0.4.1-linux-amd64.deb');
  assert.equal(manifest.platforms['windows-x86_64-nsis'].signature, 'sig of windows-x86_64-nsis');
  assert.equal(manifest.version, '0.4.1');
  // No bare {os}-{arch} key: a copy built some other way finds no package and
  // says it does not update itself (src-tauri/src/updater.rs).
  assert.ok(Object.keys(manifest.platforms).every((key) => key.split('-').length === 3));
  assert.throws(() => updateManifest({ version: '0.4.1', tag: 'v0.4.1', pubDate: 'd',
    signatures: { ...signatures, 'linux-x86_64-deb': '' } }), /no signature for linux-x86_64-deb/);
});

test('the signer runs through node on every platform, never through a .cmd shim', async () => {
  // execFileSync cannot start npm's tauri.cmd on Windows without a shell, so a
  // Windows signing run stopped before uploading anything (Codex review, #9).
  const source = fs.readFileSync(new URL('./sign-update.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /tauri\.cmd/);
  const { signerCommand } = await import('./sign-update.mjs');
  const [node, cli] = signerCommand();
  assert.equal(node, process.execPath);
  assert.match(execFileSync(node, [cli, '--version'], { encoding: 'utf8' }), /^tauri-cli \d/);
});

test('the draft checksums are read in sha256sum format', () => {
  const sums = parseChecksums(`${'a'.repeat(64)}  one.deb\n${'b'.repeat(64)}  two words.exe\nnot a line\n`);
  assert.equal(sums.get('one.deb'), 'a'.repeat(64));
  assert.equal(sums.get('two words.exe'), 'b'.repeat(64));
  assert.equal(sums.size, 2);
});

test('the app trusts a minisign Ed25519 key, and the release job archives the macOS update', () => {
  const conf = JSON.parse(fs.readFileSync(new URL('../../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
  assert.match(parsePublicKey(conf.plugins.updater.pubkey).keyId, /^[0-9a-f]{16}$/);
  const workflow = fs.readFileSync(new URL('../../.github/workflows/release.yml', import.meta.url), 'utf8');
  assert.match(workflow, /asset-name macos-update/);
  assert.match(workflow, /COPYFILE_DISABLE=1 tar -C/);
  const name = execFileSync(process.execPath, [fileURLToPath(new URL('./assemble.mjs', import.meta.url)), 'asset-name', 'macos-update'],
    { encoding: 'utf8' }).trim();
  assert.match(name, /^SQLite-Explorer-\d+\.\d+\.\d+.*-macos-aarch64\.app\.tar\.gz$/);
});
