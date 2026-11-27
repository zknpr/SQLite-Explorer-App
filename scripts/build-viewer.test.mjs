import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/// One list from native.rs, read the way the build script's pins read it — so
/// the fake bundle below stays in lockstep with native.rs instead of
/// hardcoding a second copy of the names.
function shellList(name) {
  const rust = fs.readFileSync(path.join(repoRoot, 'src-tauri', 'src', 'native.rs'), 'utf8');
  const block = rust.match(new RegExp(`const ${name}: \\[&str; (\\d+)\\] = \\[([^\\]]+)\\]`));
  assert.ok(block, `${name} present in native.rs`);
  const names = [...block[2].matchAll(/"([A-Za-z0-9_]+)"/g)].map((m) => m[1]);
  assert.equal(names.length, Number(block[1]), `every ${name} entry is read`);
  return names;
}
const auditedMethods = () => shellList('KNOWN_METHODS');

/// Minified-shape sidecar bundle: the dispatch table the drift pin extracts
/// ({name:ident,...}), and the native-host transfer code the transfer pin
/// extracts, in the shapes esbuild emits: the transport method compared with
/// targetMethod through a minified identifier, a frozen reply Set and a
/// request Set that spreads it (identifiers with $ in them), plus decoys the
/// pin must ignore: a spread-only Set of keywords, a typeof check, and a
/// worker-method comparison.
function fakeBundle(methods, {
  transport = shellList('TRANSPORT_METHODS'),
  request = shellList('REQUEST_TRANSFER_METHODS'),
  extra = ''
} = {}) {
  const reply = request.slice(0, Math.max(1, request.length - 2));
  const more = request.slice(reply.length);
  const quote = (names) => names.map((name) => `"${name}"`).join(',');
  const sets = request.length
    ? `F$r=Object.freeze(new Set([${quote(reply)}])),n$s=Object.freeze(new Set([...F$r${more.length ? `,${quote(more)}` : ''}]));`
    : '';
  const assigned = transport.map((name, i) => `T${i}$="${name}"`).join(',');
  const compared = transport.map((_, i) => `if(n?.kind==="invoke"&&n.targetMethod===T${i}$)return ${i};`).join('');
  return [
    '// sidecar bundle',
    `var q={${methods.map((m, i) => `${m}:v${i}`).join(',')}};`,
    'var Be=["SELECT","FROM"],hi=new Set(["WITH"]),Kw=new Set([...Be,...hi]);',
    assigned ? `var ${assigned};` : '',
    sets ? `var ${sets}` : '',
    `function gd(n){if(typeof n.targetMethod!="string")return;${compared}` +
      `if(n.targetMethod==="exportDatabase")return -1;${request.length ? 'if(!n$s.has(n.targetMethod))throw 0;' : ''}}`,
    // The other shapes the real bundle uses targetMethod in: an in-process
    // invoke, a request re-wrapped, messages, and the two destructurings
    // whose locals go to a call, a message, the dispatch table and a
    // worker-method comparison.
    'function Cs(e,t){return globalThis.onmessage({data:{channel:"rpc",content:{kind:"invoke",messageId:"m",targetMethod:e,payload:t}}})}',
    'function vd(e){let{messageId:t,targetMethod:n}=e,r=1;try{return Cs(n,e.payload)}catch(d){throw new Error(`a ${n} that posted no answer (${t})`)}}',
    request.length
      ? 'function kd(e){if(!n$s.has(e.targetMethod))throw new Error(`${String(e.targetMethod).slice(0,64)} cannot take its payload in pieces`);throw new Error(`${e.targetMethod}: an array`)}'
      : '',
    'function Bd(n){return{kind:"invoke",messageId:n.messageId,targetMethod:n.targetMethod,payload:[/x{2}/.test(n)]}}',
    'self.onmessage=async e=>{let t=e.data;let{kind:n,messageId:r,targetMethod:o,payload:i}=t.content;' +
      'let s=typeof o=="string"&&Object.prototype.hasOwnProperty.call(q,o)?q[o]:void 0;' +
      'if(typeof s!="function")return`Unknown method: ${typeof o=="string"?o.slice(0,256):"<invalid>"}`;' +
      'vm(o);if(o==="exportDatabase")return 1;console.error("[Worker] Method error:",o,r)};',
    'function vm(e){if(!["readCellChunk","closeCellReadSession","initializeDatabase"].includes(e))throw 0}',
    extra
  ].join('\n');
}

const NATIVES = {
  'aarch64-macos': ['tjs', 'query-plan.dylib'],
  'x86_64-macos': ['tjs', 'query-plan.dylib'],
  'x86_64-linux-gnu': ['tjs', 'query-plan.so'],
  'aarch64-linux-gnu': ['tjs', 'query-plan.so'],
  'x86_64-windows': ['tjs.exe', 'query-plan.dll']
};

/// A built viewer for one target, laid out like viewer-dist/, to hand the build
/// script with --from: what a test cannot make the real build produce (a bundle
/// the pins must refuse) goes in here.
function makeFakeBuild(bundleContent, target = 'aarch64-macos') {
  const build = fs.mkdtempSync(path.join(os.tmpdir(), 'fake-build-'));
  fs.mkdirSync(path.join(build, 'web', 'codicons'), { recursive: true });
  fs.mkdirSync(path.join(build, 'native'), { recursive: true });
  const [binary, library] = NATIVES[target];
  const own = target === 'aarch64-macos';
  for (const [file, content] of [
    ['web/viewer.html', '<html>v</html>'],
    ['web/worker.js', '// w'],
    ['web/sql-wasm.js', '// g'],
    ['web/sql-wasm.wasm', 'WASM'],
    ['web/codicons/codicon.css', 'css'],
    ['web/codicons/codicon.ttf', 'ttf'],
    ['native/native-worker-desktop.js', bundleContent],
    [`native/${binary}`, own ? 'BINARY' : `BINARY_${target}`],
    [`native/${library}`, own ? 'QUERY_PLAN' : `READER_${target}`]
  ]) fs.writeFileSync(path.join(build, file), content);
  return build;
}

test('build-viewer --from stages a built viewer and writes a verifying manifest', () => {
  const bundle = fakeBundle(auditedMethods());
  const fakeUpstream = makeFakeBuild(bundle);
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  execFileSync('node', [
    path.join(repoRoot, 'scripts', 'build-viewer.mjs'),
    '--from', fakeUpstream, '--target', 'aarch64-macos', '--out', outDir
  ]);

  const manifest = JSON.parse(fs.readFileSync(path.join(outDir, 'manifest.json'), 'utf8'));
  assert.equal(manifest.files['web/viewer.html'].length, 64);
  assert.ok(fs.existsSync(path.join(outDir, 'web', 'codicons', 'codicon.ttf')));

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
  execFileSync('node', [path.join(repoRoot, 'scripts', 'build-viewer.mjs'), '--verify', '--out', outDir]);
  fs.writeFileSync(path.join(outDir, 'web', 'worker.js'), '// tampered');
  assert.throws(() => execFileSync('node',
    [path.join(repoRoot, 'scripts', 'build-viewer.mjs'), '--verify', '--out', outDir]));
});

for (const [target, binary, library] of [
  ['x86_64-macos', 'tjs', 'query-plan.dylib'],
  ['x86_64-linux-gnu', 'tjs', 'query-plan.so'],
  ['aarch64-linux-gnu', 'tjs', 'query-plan.so'],
  ['x86_64-windows', 'tjs.exe', 'query-plan.dll']
]) {
  test(`build-viewer records ${target} native artifacts`, () => {
    const source = makeFakeBuild(fakeBundle(auditedMethods()), target);
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-platform-'));
    execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'build-viewer.mjs'),
      '--from', source, '--target', target, '--out', out]);
    const manifest = JSON.parse(fs.readFileSync(path.join(out, 'manifest.json'), 'utf8'));
    assert.equal(manifest.target, target);
    assert.equal(fs.readFileSync(path.join(out, 'native', binary), 'utf8'), `BINARY_${target}`);
    assert.equal(fs.readFileSync(path.join(out, 'native', library), 'utf8'), `READER_${target}`);
    assert.deepEqual(fs.readdirSync(path.join(out, 'native')).sort(),
      [binary, library, 'native-worker-desktop.js'].sort());
    execFileSync(process.execPath, [path.join(repoRoot, 'scripts', 'build-viewer.mjs'),
      '--verify', '--out', out]);
  });
}

test('unsupported native target fails before replacing an existing viewer', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-platform-'));
  fs.writeFileSync(path.join(out, 'keep.txt'), 'previous build');
  assert.throws(() => execFileSync(process.execPath,
    [path.join(repoRoot, 'scripts', 'build-viewer.mjs'), '--target', 'unsupported', '--out', out],
    { stdio: 'pipe' }), error => /unsupported native target/.test(String(error.stderr)));
  assert.equal(fs.readFileSync(path.join(out, 'keep.txt'), 'utf8'), 'previous build');
});

test('build-viewer fails when the bundle method table diverges from KNOWN_METHODS', () => {
  // A method the Rust gate never audited: building it must fail loudly, and
  // the failed build must not leave a valid-looking manifest behind.
  const divergent = fakeBundle([...auditedMethods(), 'openArbitraryFile']);
  const fakeUpstream = makeFakeBuild(divergent);
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  assert.throws(
    () => execFileSync('node', [
      path.join(repoRoot, 'scripts', 'build-viewer.mjs'),
      '--from', fakeUpstream, '--target', 'aarch64-macos', '--out', outDir
    ], { stdio: 'pipe' }),
    (err) => /diverged[\s\S]*openArbitraryFile/.test(String(err.stderr))
  );
  assert.ok(!fs.existsSync(path.join(outDir, 'manifest.json')), 'no manifest after a failed build');

  // A bundle whose table cannot be found at all is a refusal too.
  const noTable = makeFakeBuild('// no dispatch table here');
  const outDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  assert.throws(() => execFileSync('node', [
    path.join(repoRoot, 'scripts', 'build-viewer.mjs'),
    '--from', noTable, '--target', 'aarch64-macos', '--out', outDir2
  ], { stdio: 'pipe' }), (err) => /cannot find the worker dispatch table/.test(String(err.stderr)));
});

/// Runs a build of `bundle` and returns its stderr; asserts it failed and left
/// no manifest behind.
function refusedBuild(bundle) {
  const source = makeFakeBuild(bundle);
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  let stderr = '';
  assert.throws(() => execFileSync('node', [
    path.join(repoRoot, 'scripts', 'build-viewer.mjs'),
    '--from', source, '--target', 'aarch64-macos', '--out', outDir
  ], { stdio: 'pipe' }), (err) => { stderr = String(err.stderr); return true; });
  assert.ok(!fs.existsSync(path.join(outDir, 'manifest.json')), 'no manifest after a failed build');
  return stderr;
}

test('build-viewer refuses a bundle without native transfers against a shell that admits them', () => {
  // The pinned 1.9.0 bundle's shape: no transport method, no transfer sets.
  const stderr = refusedBuild(fakeBundle(auditedMethods(), { transport: [], request: [] }));
  assert.match(stderr, /native transfer lists diverged/);
  assert.match(stderr, /transport methods: in bundle but not admitted by the shell: \[\]; admitted by the shell but not in bundle: \[nativeTransfer\]/);
  for (const method of shellList('REQUEST_TRANSFER_METHODS')) assert.match(stderr, new RegExp(method));
});

test('build-viewer refuses request-transfer methods the shell and the bundle disagree on, both ways', () => {
  const request = shellList('REQUEST_TRANSFER_METHODS');
  // The bundle takes a payload in pieces on a method the gate refuses it on…
  let stderr = refusedBuild(fakeBundle(auditedMethods(), { request: [...request, 'updateCell'] }));
  assert.match(stderr, /request-transfer methods: in bundle but not admitted by the shell: \[updateCell\]/);
  // …and the gate admits one the bundle would refuse.
  stderr = refusedBuild(fakeBundle(auditedMethods(), { request: request.filter((m) => m !== 'redoModification') }));
  assert.match(stderr, /admitted by the shell but not in bundle: \[redoModification\]/);
});

test('build-viewer refuses transport methods the shell and the bundle disagree on, both ways', () => {
  const transport = shellList('TRANSPORT_METHODS');
  let stderr = refusedBuild(fakeBundle(auditedMethods(), { transport: [...transport, 'nativeStream'] }));
  assert.match(stderr, /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/);
  stderr = refusedBuild(fakeBundle(auditedMethods(), { transport: [] }));
  assert.match(stderr, /admitted by the shell but not in bundle: \[nativeTransfer\]/);
});

test('build-viewer refuses transfer code it cannot classify', () => {
  // A Set mixing worker methods with anything else.
  let stderr = refusedBuild(fakeBundle(auditedMethods(), { extra: 'var Zz=new Set(["deleteRows","bogus"]);' }));
  assert.match(stderr, /mixes worker method names/);
  // A spread that resolves to no set of worker methods.
  stderr = refusedBuild(fakeBundle(auditedMethods(), { extra: 'var Zy=new Set([...Nope,"undoModification"]);' }));
  assert.match(stderr, /cannot resolve the Set spread \.\.\.Nope/);
  // A targetMethod comparison with an identifier that names no one string.
  stderr = refusedBuild(fakeBundle(auditedMethods(), { extra: 'function h(e,t){return e.targetMethod===t}' }));
  assert.match(stderr, /cannot resolve the targetMethod comparison with t/);
});

const buildScript = path.join(repoRoot, 'scripts', 'build-viewer.mjs');

/// Every entry under dir: relative path → mode and sha256 (or "dir" and mode).
function snapshot(dir) {
  const entries = {};
  const walk = (folder, rel) => {
    for (const name of fs.readdirSync(folder).sort()) {
      const full = path.join(folder, name);
      const key = rel ? `${rel}/${name}` : name;
      const stat = fs.lstatSync(full);
      if (stat.isDirectory()) {
        entries[key] = `dir ${stat.mode.toString(8)}`;
        walk(full, key);
      } else {
        entries[key] = `${stat.mode.toString(8)} ${createHash('sha256').update(fs.readFileSync(full)).digest('hex')}`;
      }
    }
  };
  walk(dir, '');
  return entries;
}

/// git reads where its repository is from these before -C (the list is git's own,
/// `git rev-parse --local-env-vars`). The helpers here run git without them, so an
/// exported GIT_DIR cannot send their writes to another repository.
const GIT_REPOSITORY_ENV = new Set(['GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_CONFIG', 'GIT_OBJECT_DIRECTORY',
  'GIT_DIR', 'GIT_WORK_TREE', 'GIT_IMPLICIT_WORK_TREE', 'GIT_GRAFT_FILE', 'GIT_INDEX_FILE', 'GIT_NO_REPLACE_OBJECTS',
  'GIT_REPLACE_REF_BASE', 'GIT_PREFIX', 'GIT_SHALLOW_FILE', 'GIT_COMMON_DIR']);
const gitEnv = Object.fromEntries(Object.entries(process.env).filter(([name]) => !GIT_REPOSITORY_ENV.has(name.toUpperCase())));

/// A viewer-dist from a successful build, in a folder of its own.
function builtViewer() {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-swap-'));
  const out = path.join(parent, 'viewer-dist');
  execFileSync(process.execPath, [buildScript, '--from', makeFakeBuild(fakeBundle(auditedMethods())),
    '--target', 'aarch64-macos', '--out', out], { stdio: 'pipe' });
  return { parent, out };
}

/// Runs a build that must fail, and asserts it left viewer-dist byte for byte as
/// it was and nothing beside it; returns its stderr.
function refusedAndUntouched(args, { parent, out }) {
  const before = snapshot(out);
  const siblings = fs.readdirSync(parent).sort();
  let stderr = '';
  assert.throws(() => execFileSync(process.execPath, [buildScript, ...args, '--target', 'aarch64-macos', '--out', out],
    { stdio: 'pipe' }), (err) => { stderr = String(err.stderr); return true; });
  assert.deepEqual(snapshot(out), before, 'a failed build leaves viewer-dist as it was');
  assert.deepEqual(fs.readdirSync(parent).sort(), siblings, 'a failed build leaves nothing beside viewer-dist');
  return stderr;
}

test('a build from a folder that is not there leaves viewer-dist as it was', () => {
  const viewer = builtViewer();
  const stderr = refusedAndUntouched(['--from', path.join(viewer.parent, 'no-such-build')], viewer);
  assert.match(stderr, /cannot read web\/viewer\.html from .*no-such-build/);
});

test('a build the pins refuse leaves viewer-dist as it was', () => {
  const viewer = builtViewer();
  let stderr = refusedAndUntouched(['--from',
    makeFakeBuild(fakeBundle([...auditedMethods(), 'openArbitraryFile']))], viewer);
  assert.match(stderr, /diverged[\s\S]*openArbitraryFile/);
  stderr = refusedAndUntouched(['--from',
    makeFakeBuild(fakeBundle(auditedMethods(), { transport: [] }))], viewer);
  assert.match(stderr, /native transfer lists diverged/);
});

test('a build replaces viewer-dist whole', () => {
  const build = makeFakeBuild(fakeBundle(auditedMethods()));
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-swap-'));
  const out = path.join(parent, 'viewer-dist');
  const run = () => execFileSync(process.execPath, [buildScript, '--from', build, '--target', 'aarch64-macos',
    '--out', out], { stdio: 'pipe' });
  run();
  const first = JSON.parse(fs.readFileSync(path.join(out, 'manifest.json'), 'utf8'));
  fs.writeFileSync(path.join(out, 'stale.txt'), 'from an older build');
  run();
  const second = JSON.parse(fs.readFileSync(path.join(out, 'manifest.json'), 'utf8'));
  assert.deepEqual(second, first, 'the same input builds the same manifest: no date, no ref');
  assert.ok(!fs.existsSync(path.join(out, 'stale.txt')), 'nothing of the previous viewer-dist is kept');
  assert.deepEqual(fs.readdirSync(parent), ['viewer-dist'], 'no staging or previous copy is left beside it');
  // The folder is made like any other (the umask decides), not private like a temp folder.
  fs.mkdirSync(path.join(parent, 'plain'));
  assert.equal(fs.statSync(out).mode, fs.statSync(path.join(parent, 'plain')).mode);
  execFileSync(process.execPath, [buildScript, '--verify', '--out', out]);
});

test('the committed sidecar bundle passes both pins and stages to the committed manifest', () => {
  // The real bundle through the real pins: a pin that refuses it would fail
  // the release workflow's build on every platform.
  const committed = JSON.parse(fs.readFileSync(path.join(repoRoot, 'viewer-dist', 'manifest.json'), 'utf8'));
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-committed-')), 'viewer-dist');
  execFileSync(process.execPath, [buildScript, '--from', path.join(repoRoot, 'viewer-dist'), '--target', committed.target,
    '--out', out], { stdio: 'pipe' });
  assert.deepEqual(JSON.parse(fs.readFileSync(path.join(out, 'manifest.json'), 'utf8')), committed);
});

test('the committed viewer-dist is what the sources in viewer/ build', () => {
  // A source change committed without its rebuilt output, or an output edited by
  // hand, fails here (and in the release workflow, which runs the same check).
  const copy = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-fresh-')), 'viewer-dist');
  fs.cpSync(path.join(repoRoot, 'viewer-dist'), copy, { recursive: true });
  execFileSync(process.execPath, [buildScript, '--check', '--out', copy], { stdio: 'pipe' });
  fs.appendFileSync(path.join(copy, 'web', 'worker.js'), '\n// edited by hand');
  assert.throws(() => execFileSync(process.execPath, [buildScript, '--check', '--out', copy], { stdio: 'pipe' }),
    (err) => /does not match a fresh build[\s\S]*worker\.js/.test(String(err.stderr)));
});

// Each shape below routes a method name past the comparisons and Set literals
// the transfer pin reads; the pin must refuse it rather than read past it.
for (const [shape, extra, refusal] of [
  ['a switch on targetMethod', 'function zz(n){switch(n.targetMethod){case"nativeStream":return 1}}', /cannot account for/],
  ['a switch on a destructured targetMethod', 'function zy(n){let{targetMethod:m}=n;switch(m){case"nativeStream":return 1}}',
    /cannot account for[\s\S]*through the local m/],
  ['an .includes on an array literal', 'function zx(n){if(["nativeStream"].includes(n.targetMethod))return 1}',
    /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/],
  ['an .includes on a computed member', 'function zx2(n){if(Q$[0].includes(n.targetMethod))return 1}', /cannot account for/],
  ['an .indexOf on an array literal', 'function zw(n){return["nativeStream"].indexOf(n.targetMethod)>=0}', /cannot account for/],
  ['a lookup in an object', 'function zv(n){return{nativeStream:1}[n.targetMethod]}', /cannot account for/],
  ['a copy into a variable', 'function zu(n){let m=n.targetMethod;return m==="nativeStream"}', /cannot account for/],
  ['a destructured parameter', 'function zt({targetMethod:m}){return m==="nativeStream"}', /cannot account for/],
  ['a .has on a Set that is not a literal', 'var Z$=new Set(W$);function zs(n){return Z$.has(n.targetMethod)}', /cannot account for/],
  ['a property read by its name in a string', 'function zr(n){return n["targetMethod"]==="nativeStream"}', /names targetMethod outside code/],
  ['a method added to the request Set', 'n$s.add("updateCell");', /n\$s .*is changed after it is built/],
  ['a method deleted from the request Set', 'n$s.delete("deleteRows");', /n\$s .*is changed after it is built/],
  ['a method Set built with .add', 'var Q$=new Set;Q$.add("updateCell");', /adds the method name updateCell to a Set with \.add/],
  ['a destructured targetMethod compared with a new method', 'function zq(n){let{targetMethod:m}=n;if(m==="nativeStream")return 1}',
    /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/],
  // A local passed to a plain function is followed into it, one level.
  ['a switch in a helper the method name is passed to', 'function zh(n){let{targetMethod:o}=n;Zh(o)}function Zh(m){switch(m){case"nativeStream":return 1}}',
    /cannot account for[\s\S]*through the local m in Zh/],
  ['a new method compared in a helper', 'function zg(n){let{targetMethod:o}=n;return Zg(1,o)}function Zg(a,m){return m==="nativeStream"}',
    /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/],
  ['a helper that passes the method name on', 'function zf(n){let{targetMethod:o}=n;Zf(o)}function Zf(m){Zf2(m)}function Zf2(k){}',
    /passes the method name on from Zf to Zf2/],
  ['a helper written as an arrow', 'var Ze=(m)=>m==="nativeStream";function ze(n){let{targetMethod:o}=n;Ze(o)}',
    /passes the method name to Ze, which the transfer pin cannot follow \(0 declarations/],
  ['a helper declared twice', 'function zd(n){let{targetMethod:o}=n;Zd(o)}function Zd(m){}function Zd(m){}', /cannot follow \(2 declarations/],
  ['a helper with a default parameter', 'function zc(n){let{targetMethod:o}=n;Zc(o)}function Zc(m="x"){}', /not plain names/]
]) {
  test(`build-viewer refuses ${shape} in the sidecar bundle`, () => {
    assert.match(refusedBuild(fakeBundle(auditedMethods(), { extra })), refusal);
  });
}

/// A module preloaded into a build to inject what a test cannot otherwise cause:
/// RENAME_FAIL=2,3 fails those renames (counted from 1), RM_FAIL=1 fails removing
/// the previous copy after a swap, SIGNAL_AT_WRITE=<signal> sends that signal to the
/// sync as it writes its first staged file and then holds it there for a moment.
const INJECT = `
import fs from 'node:fs';
const renameFails = (process.env.RENAME_FAIL || '').split(',').filter(Boolean).map(Number);
let renames = 0;
const rename = fs.renameSync;
fs.renameSync = function (from, to) {
  renames += 1;
  if (renameFails.includes(renames)) throw Object.assign(new Error('injected failure of rename ' + renames), { code: 'EPERM' });
  return rename.call(this, from, to);
};
const rm = fs.rmSync;
fs.rmSync = function (target, options) {
  if (process.env.RM_FAIL === '1' && String(target).endsWith('-previous')) {
    throw Object.assign(new Error('injected failure to remove'), { code: 'EBUSY' });
  }
  return rm.call(this, target, options);
};
const writeFile = fs.writeFileSync;
let signalled = false;
fs.writeFileSync = function (target, ...rest) {
  const written = writeFile.call(this, target, ...rest);
  if (process.env.SIGNAL_AT_WRITE && !signalled && String(target).includes('.build-')) {
    signalled = true;
    process.kill(process.pid, process.env.SIGNAL_AT_WRITE);
    const until = Date.now() + 300;
    while (Date.now() < until) {}
  }
  return written;
};
`;
function injector() {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'build-inject-')), 'inject.mjs');
  fs.writeFileSync(file, INJECT);
  return pathToFileURL(file).href;
}

/// Runs a build of viewer.out with the injector and extra environment; returns
/// { status, stderr }.
function injectedBuild(viewer, args, env) {
  try {
    execFileSync(process.execPath, ['--import', injector(), buildScript, ...args, '--target', 'aarch64-macos',
      '--out', viewer.out], { stdio: 'pipe', env: { ...process.env, ...env } });
    return { status: 0, stderr: '' };
  } catch (err) {
    return { status: err.status, signal: err.signal, stderr: String(err.stderr) };
  }
}

const goodSource = () => ['--from', makeFakeBuild(fakeBundle(auditedMethods()))];
const leftoverNames = (parent) => fs.readdirSync(parent).filter((name) => name.startsWith('.viewer-dist.build-')).sort();

for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  test(`a build stopped by ${signal} leaves viewer-dist as it was`, {
    skip: process.platform === 'win32' && 'process.kill sends no catchable POSIX signal on Windows'
  }, () => {
    const viewer = builtViewer();
    const before = snapshot(viewer.out);
    const run = injectedBuild(viewer, goodSource(), { SIGNAL_AT_WRITE: signal });
    assert.equal(run.status, code, run.stderr || `ended by ${run.signal}`);
    assert.match(run.stderr, new RegExp(`interrupted by ${signal}`));
    assert.deepEqual(snapshot(viewer.out), before, 'viewer-dist is as it was');
    assert.deepEqual(leftoverNames(viewer.parent), [], 'nothing is left beside it');
  });
}

test('a swap that cannot move the new copy in puts the previous viewer-dist back', () => {
  const viewer = builtViewer();
  const before = snapshot(viewer.out);
  const run = injectedBuild(viewer, goodSource(), { RENAME_FAIL: '2' });
  assert.equal(run.status, 1);
  assert.match(run.stderr, /cannot move the built files into .*injected failure of rename 2/);
  assert.deepEqual(snapshot(viewer.out), before);
  assert.deepEqual(leftoverNames(viewer.parent), []);
});

test('a previous copy a failed swap could not put back is restored by the next run', () => {
  const viewer = builtViewer();
  const before = snapshot(viewer.out);
  let run = injectedBuild(viewer, goodSource(), { RENAME_FAIL: '2,3' });
  assert.match(run.stderr, /move it back by hand/);
  assert.ok(!fs.existsSync(viewer.out), 'viewer-dist is missing');
  const [aside] = leftoverNames(viewer.parent);
  assert.match(aside, /-previous$/);
  // --verify only says where it is.
  const verify = injectedBuild(viewer, ['--verify'], {});
  assert.match(verify.stderr, new RegExp(`left the previous copy at .*${aside}`));
  assert.ok(!fs.existsSync(viewer.out) && leftoverNames(viewer.parent).includes(aside), '--verify changes nothing');
  // The next build, even one that then fails, puts it back first.
  run = injectedBuild(viewer, ['--from', path.join(viewer.parent, 'no-such-build')], {});
  assert.match(run.stderr, /restored .*viewer-dist/);
  assert.deepEqual(snapshot(viewer.out), before);
  assert.deepEqual(leftoverNames(viewer.parent), []);
});

test('what an interrupted build left beside viewer-dist is removed by the next run', () => {
  const viewer = builtViewer();
  // A swap whose previous copy could not be removed, then a staging folder a
  // killed build left.
  let run = injectedBuild(viewer, goodSource(), { RM_FAIL: '1' });
  assert.match(run.stderr, /could not be removed/);
  const swapped = snapshot(viewer.out);
  fs.mkdirSync(path.join(viewer.parent, '.viewer-dist.build-0f0e0d0c-0b0a-4908-8706-050403020100', 'native'), { recursive: true });
  fs.mkdirSync(path.join(viewer.parent, '.viewer-dist.build-not-a-uuid'));
  assert.equal(leftoverNames(viewer.parent).length, 3);
  run = injectedBuild(viewer, ['--from', path.join(viewer.parent, 'no-such-build')], {});
  assert.match(run.stderr, /removed \.viewer-dist\.build-/);
  assert.deepEqual(snapshot(viewer.out), swapped, 'viewer-dist itself is not touched');
  assert.deepEqual(leftoverNames(viewer.parent), ['.viewer-dist.build-not-a-uuid'], 'only names of its own form are removed');
});

test('a staging folder left in the checkout is ignored by git', (t) => {
  // A source archive (a release tarball, a distribution's source package) has
  // no git work tree to ask; the .gitignore entry only matters in a checkout.
  try {
    execFileSync('git', ['-C', repoRoot, 'rev-parse', '--is-inside-work-tree'], { stdio: 'pipe', env: gitEnv });
  } catch {
    t.skip('not a git checkout');
    return;
  }
  for (const name of ['.viewer-dist.build-0f0e0d0c-0b0a-4908-8706-050403020100',
    '.viewer-dist.build-0f0e0d0c-0b0a-4908-8706-050403020100-previous']) {
    execFileSync('git', ['-C', repoRoot, 'check-ignore', '-q', '--no-index', `${name}/x`], { stdio: 'pipe', env: gitEnv });
  }
});

test('known false pass: a parameter that shadows a declared function of the same name', () => {
  // The pin resolves a call by its callee's name, so here it follows Zb's
  // declaration, whose body never uses the method name, and not the parameter
  // the call really goes to. Pinned so that a change to that resolution shows.
  const extra = 'function zb(n,Zb){let{targetMethod:o}=n;Zb(o)}function Zb(m){}';
  const source = makeFakeBuild(fakeBundle(auditedMethods(), { extra }));
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  execFileSync(process.execPath, [buildScript, '--from', source, '--target', 'aarch64-macos', '--out', out],
    { stdio: 'pipe' });
  assert.ok(fs.existsSync(path.join(out, 'manifest.json')));
});

// A template literal holding the method name carries it: the template is held to the
// same shapes as the name (a message to console or an Error is fine). A followed
// helper that reads its arguments object cannot be followed.
for (const [shape, extra, refusal] of [
  ["a template literal of targetMethod switched on", "function zz(n){switch(`${n.targetMethod}`){case\"nativeStream\":return 1}}", /cannot account for/],
  ["a template literal of a local compared with a new method", "function zy(n){let{targetMethod:o}=n;if(`${o}`===\"nativeStream\")return 1}", /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/],
  ["a template literal switched on in a helper", "function zx3(n){let{targetMethod:o}=n;Zx(o)}function Zx(m){switch(`${m}`){case\"nativeStream\":return 1}}", /cannot account for[\s\S]*in Zx/],
  ["a template literal passed to a helper that compares it", "function zw3(n){let{targetMethod:o}=n;Zw(`${o}`)}function Zw(m){return m===\"nativeStream\"}", /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/],
  ["a helper reading its arguments object", "function zv3(n){let{targetMethod:o}=n;Zv(o)}function Zv(m){switch(arguments[0]){case\"nativeStream\":return 1}}", /cannot follow \(it reads its arguments object\)/]
]) {
  test(`build-viewer refuses ${shape} in the sidecar bundle`, () => {
    assert.match(refusedBuild(fakeBundle(auditedMethods(), { extra })), refusal);
  });
}

// Only the built-in error constructors only say the method name. A function or class
// of the bundle's own, whatever its name, is followed like any other call, and so is
// one that takes a built-in's name.
for (const [shape, extra, refusal] of [
  ['a helper whose name ends in Error', 'function zq(n){let{targetMethod:o}=n;QError(o)}function QError(m){if(m==="nativeStream")return}',
    /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/],
  ['a class whose name ends in Error', 'function zq2(n){let{targetMethod:o}=n;new QError(o)}class QError extends Error{constructor(m){super(m);if(m==="nativeStream")return}}',
    /passes the method name to QError, which the transfer pin cannot follow \(0 declarations/],
  ['a template literal handed to a helper whose name ends in Error', 'function zq3(n){QError(`${n.targetMethod}`)}function QError(m){if(m==="nativeStream")return}',
    /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/],
  ['a function that takes a built-in error\'s name', 'function zq4(n){let{targetMethod:o}=n;TypeError(o)}function TypeError(m){if(m==="nativeStream")return}',
    /transport methods: in bundle but not admitted by the shell: \[nativeStream\]/],
  ['a class that takes a built-in error\'s name', 'function zq5(n){let{targetMethod:o}=n;new RangeError(o)}class RangeError{constructor(m){if(m==="nativeStream")return}}',
    /passes the method name to RangeError, which the transfer pin cannot follow \(0 declarations/]
]) {
  test(`build-viewer refuses ${shape} in the sidecar bundle`, () => {
    assert.match(refusedBuild(fakeBundle(auditedMethods(), { extra })), refusal);
  });
}

test('a method name handed to a built-in error constructor builds', () => {
  // The control for the shapes above: the bundle's own error constructors.
  for (const ctor of ['Error', 'TypeError', 'RangeError', 'AggregateError']) {
    const extra = `function zp(n){let{targetMethod:o}=n;throw new ${ctor}(o)}`;
    const source = makeFakeBuild(fakeBundle(auditedMethods(), { extra }));
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
    execFileSync(process.execPath, [buildScript, '--from', source, '--target', 'aarch64-macos', '--out', out],
      { stdio: 'pipe' });
    assert.ok(fs.existsSync(path.join(out, 'manifest.json')), ctor);
  }
});

test('the desktop api swap applies whatever separator the importer path uses', async () => {
  // esbuild hands onResolve the importer as a native path, so on Windows it
  // carries backslashes; a forward-slash-only match there bundled the VS Code
  // api.js into the page instead of desktop-api.js.
  const { desktopApiPlugin } = await import('../viewer/scripts/build.mjs');
  const hooks = [];
  desktopApiPlugin.setup({ onResolve: (options, callback) => hooks.push({ options, callback }) });
  assert.equal(hooks.length, 1);
  const [{ options, callback }] = hooks;
  assert.ok(options.filter.test('./api.js'));
  const desktopApi = path.join('core', 'ui', 'modules', 'desktop-api.js');
  for (const importer of [
    '/repo/viewer/core/ui/modules/grid-data.js',
    '/repo/viewer/core/ui/desktop-viewer.js',
    'C:\\repo\\viewer\\core\\ui\\modules\\grid-data.js',
    'C:\\repo\\viewer\\core\\ui\\desktop-viewer.js'
  ]) {
    const result = callback({ path: './api.js', importer });
    assert.ok(result && result.path.endsWith(desktopApi), `${importer} resolved ./api.js to the VS Code seam`);
  }
  assert.equal(callback({ path: './api.js', importer: 'C:\\repo\\viewer\\src\\core\\other.js' }), null);
});

test('build-viewer refuses a page that bundled the VS Code backend instead of desktop-api.js', () => {
  // The page reaches the shell only through desktop-api.js. When the build's
  // swap misses (it did on Windows), the VS Code api.js lands in the page,
  // which then cannot open a database: refuse it on every target, not only
  // where a committed copy exists to compare against.
  const source = makeFakeBuild(fakeBundle(auditedMethods()));
  fs.writeFileSync(path.join(source, 'web', 'viewer.html'), '<html><script>const vscode = acquireVsCodeApi();</script></html>');
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'viewer-dist-'));
  assert.throws(
    () => execFileSync('node', [
      path.join(repoRoot, 'scripts', 'build-viewer.mjs'),
      '--from', source, '--target', 'aarch64-macos', '--out', outDir
    ], { stdio: 'pipe' }),
    (err) => /VS Code backend/.test(String(err.stderr))
  );
  assert.ok(!fs.existsSync(path.join(outDir, 'manifest.json')), 'no manifest after a refused build');
});
