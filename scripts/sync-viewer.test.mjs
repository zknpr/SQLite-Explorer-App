import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/// The audited method list, read from the same source the sync script's
/// drift pin reads — so the fake bundle below stays in lockstep with
/// native.rs instead of hardcoding a second copy of the 34 names.
function auditedMethods() {
  const rust = fs.readFileSync(path.join(repoRoot, 'src-tauri', 'src', 'native.rs'), 'utf8');
  const block = rust.match(/const KNOWN_METHODS: \[&str; \d+\] = \[([^\]]+)\]/);
  assert.ok(block, 'KNOWN_METHODS present in native.rs');
  return [...block[1].matchAll(/"([A-Za-z0-9_]+)"/g)].map((m) => m[1]);
}

/// Minified-shape dispatch table the drift pin extracts: {name:ident,...}.
function fakeBundle(methods) {
  return `// sidecar bundle\nvar q={${methods.map((m, i) => `${m}:v${i}`).join(',')}};`;
}

function makeFakeUpstream(bundleContent) {
  const fakeUpstream = fs.mkdtempSync(path.join(os.tmpdir(), 'fake-ext-'));
  const desktopDir = path.join(fakeUpstream, 'desktop');
  fs.mkdirSync(path.join(desktopDir, 'codicons'), { recursive: true });
  for (const [file, content] of [
    ['viewer.html', '<html>v</html>'],
    ['worker.js', '// w'],
    ['sql-wasm.js', '// g'],
    ['sql-wasm.wasm', 'WASM'],
    ['dev-harness.html', '<html>h</html>'],
    ['codicons/codicon.css', 'css'],
    ['codicons/codicon.ttf', 'ttf'],
    ['native-worker-desktop.js', bundleContent]
  ]) fs.writeFileSync(path.join(desktopDir, file), content);
  const nativesDir = path.join(fakeUpstream, 'natives', 'aarch64-macos');
  fs.mkdirSync(nativesDir, { recursive: true });
  fs.writeFileSync(path.join(nativesDir, 'tjs'), 'BINARY');
  fs.writeFileSync(path.join(nativesDir, 'query-plan.dylib'), 'QUERY_PLAN');
  for (const [target, binary, library] of [
    ['x86_64-macos', 'tjs', 'query-plan.dylib'],
    ['x86_64-linux-gnu', 'tjs', 'query-plan.so'],
    ['aarch64-linux-gnu', 'tjs', 'query-plan.so'],
    ['x86_64-windows', 'tjs.exe', 'query-plan.dll']
  ]) {
    const dir = path.join(fakeUpstream, 'natives', target);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, binary), `BINARY_${target}`);
    fs.writeFileSync(path.join(dir, library), `READER_${target}`);
  }
  return fakeUpstream;
}

test('sync-viewer --local copies artifacts and writes a verifying manifest', () => {
  const bundle = fakeBundle(auditedMethods());
  const fakeUpstream = makeFakeUpstream(bundle);
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  execFileSync('node', [
    path.join(repoRoot, 'scripts', 'sync-viewer.mjs'),
    '--local', '--target', 'aarch64-macos', '--source', fakeUpstream, '--out', outDir
  ]);

  const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'manifest.json'), 'utf8'));
  assert.equal(manifest.files['viewer.html'].length, 64);
  assert.ok(fs.existsSync(path.join(outDir, 'codicons', 'codicon.ttf')));

  // Native engine artifacts land under native/, sha-manifested like the
  // rest, and the binary carries the executable bit the spawn needs.
  assert.equal(manifest.files['native/tjs'].length, 64);
  assert.equal(manifest.files['native/native-worker-desktop.js'].length, 64);
  assert.equal(manifest.files['native/query-plan.dylib']?.length, 64);
  assert.equal(fs.readFileSync(path.join(outDir, 'native', 'query-plan.dylib'), 'utf8'), 'QUERY_PLAN');
  const binaryMode = fs.statSync(path.join(outDir, 'native', 'tjs')).mode;
  if (process.platform !== 'win32') assert.ok(binaryMode & 0o111, 'native/tjs must be executable');
  assert.equal(
    fs.readFileSync(path.join(outDir, 'native', 'native-worker-desktop.js'), 'utf8'),
    bundle
  );

  // verify mode passes on intact copy, fails on tamper
  execFileSync('node', [path.join(repoRoot, 'scripts', 'sync-viewer.mjs'), '--verify', '--out', outDir]);
  fs.writeFileSync(path.join(outDir, 'worker.js'), '// tampered');
  assert.throws(() => execFileSync('node',
    [path.join(repoRoot, 'scripts', 'sync-viewer.mjs'), '--verify', '--out', outDir]));
});

for (const [target, binary, library] of [
  ['x86_64-macos', 'tjs', 'query-plan.dylib'],
  ['x86_64-linux-gnu', 'tjs', 'query-plan.so'],
  ['aarch64-linux-gnu', 'tjs', 'query-plan.so'],
  ['x86_64-windows', 'tjs.exe', 'query-plan.dll']
]) {
  test(`sync-viewer selects and records ${target} native artifacts`, () => {
    const source = makeFakeUpstream(fakeBundle(auditedMethods()));
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-platform-'));
    execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'sync-viewer.mjs'),
      '--local', '--target', target, '--source', source, '--out', out]);
    const manifest = JSON.parse(fs.readFileSync(path.join(out, 'manifest.json'), 'utf8'));
    assert.equal(manifest.target, target);
    assert.equal(fs.readFileSync(path.join(out, 'native', binary), 'utf8'), `BINARY_${target}`);
    assert.equal(fs.readFileSync(path.join(out, 'native', library), 'utf8'), `READER_${target}`);
    assert.deepEqual(fs.readdirSync(path.join(out, 'native')).sort(),
      [binary, library, 'native-worker-desktop.js'].sort());
    execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'sync-viewer.mjs'),
      '--verify', '--out', out]);
  });
}

test('unsupported native target fails before replacing an existing viewer', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-platform-'));
  fs.writeFileSync(path.join(out, 'keep.txt'), 'previous build');
  assert.throws(() => execFileSync(process.execPath,
    [path.join(repoRoot, 'scripts', 'sync-viewer.mjs'), '--local', '--target', 'unsupported', '--out', out],
    { stdio: 'pipe' }), error => /unsupported native target/.test(String(error.stderr)));
  assert.equal(fs.readFileSync(path.join(out, 'keep.txt'), 'utf8'), 'previous build');
});

test('sync-viewer fails when the bundle method table diverges from KNOWN_METHODS', () => {
  // A method the Rust gate never audited: syncing it must fail loudly, and
  // the failed sync must not leave a valid-looking manifest behind.
  const divergent = fakeBundle([...auditedMethods(), 'openArbitraryFile']);
  const fakeUpstream = makeFakeUpstream(divergent);
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  assert.throws(
    () => execFileSync('node', [
      path.join(repoRoot, 'scripts', 'sync-viewer.mjs'),
      '--local', '--source', fakeUpstream, '--out', outDir
    ], { stdio: 'pipe' }),
    (err) => /diverged[\s\S]*openArbitraryFile/.test(String(err.stderr))
  );
  assert.ok(!fs.existsSync(path.join(outDir, 'manifest.json')), 'no manifest after a failed sync');

  // A bundle whose table cannot be found at all is a refusal too.
  const noTable = makeFakeUpstream('// no dispatch table here');
  const outDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  assert.throws(() => execFileSync('node', [
    path.join(repoRoot, 'scripts', 'sync-viewer.mjs'),
    '--local', '--source', noTable, '--out', outDir2
  ], { stdio: 'pipe' }));
});
