#!/usr/bin/env node
/**
 * Build the desktop viewer into viewer-dist/, from the sources in viewer/.
 *
 *   (no flag)            build for --target, check, and replace viewer-dist/
 *   --verify             verify viewer-dist/ against its manifest and exit
 *   --check              build afresh and fail if viewer-dist/ differs from it
 *   --target <platform>  native engine platform (default: current OS/CPU)
 *   --out <path>         output dir (default viewer-dist/)
 *   --from <dir>         stage an already built viewer (laid out like
 *                        viewer-dist/, for one target) instead of building
 *
 * The manifest records the target and every file's sha256.
 *
 * A build is all or nothing: everything is written into a staging folder
 * beside --out and checked there (the shell's method and transfer pins,
 * the hashes), and only then does the staging folder take --out's place. A
 * failure anywhere leaves --out as it was. SIGINT, SIGTERM and SIGHUP stop it
 * at the next step boundary, never inside the swap; a run that was killed
 * outright is repaired by the next one, which puts a previous copy it finds
 * moved aside back and removes a staging folder it finds. One build at a
 * time: a second one would take the first's staging for a leftover.
 */
import { createHash, randomUUID } from 'node:crypto';
import fs from 'node:fs';
import { constants as osConstants } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildViewerInto } from '../viewer/scripts/build.mjs';

// web/ is embedded as the app's pages; native/ ships beside them as resources.
const FILES = [
  'web/viewer.html', 'web/worker.js', 'web/sql-wasm.js', 'web/sql-wasm.wasm',
  'web/codicons/codicon.css', 'web/codicons/codicon.ttf'
];

const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const valueOf = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const outDir = path.resolve(valueOf('--out', path.join(repoRoot, 'viewer-dist')));

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// The staging folder of a build in progress. Removed on the way out, whether
// fail() or an uncaught error ends the run: process.exit runs no finally block.
let stageDir = null;
process.on('exit', () => {
  if (stageDir) fs.rmSync(stageDir, { recursive: true, force: true });
});

function fail(message) {
  console.error(`build-viewer: ${message}`);
  process.exit(1);
}

// What an interrupted build can leave beside outDir: its staging folder
// (.viewer-dist.build-<uuid>) and the previous copy it moved aside to swap
// (.viewer-dist.build-<uuid>-previous). Only names of exactly that form count.
const parentDir = path.dirname(outDir);
const leftoverPrefix = `.${path.basename(outDir)}.build-`;
function leftovers() {
  let names;
  try {
    names = fs.readdirSync(parentDir);
  } catch (error) {
    if (error.code === 'ENOENT') return { staged: [], previous: [] };
    fail(`cannot list ${parentDir} for what an interrupted build left: ${error.message}`);
  }
  const ours = names.filter((name) => name.startsWith(leftoverPrefix) &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(-previous)?$/.test(name.slice(leftoverPrefix.length)))
    .sort();
  return { staged: ours.filter((name) => !name.endsWith('-previous')), previous: ours.filter((name) => name.endsWith('-previous')) };
}

// Every file the manifest in dir names, hashed against it; returns the manifest.
function verifyManifest(dir) {
  const manifestPath = path.join(dir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) fail('no manifest to verify');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  for (const [file, expected] of Object.entries(manifest.files)) {
    const actual = sha256(fs.readFileSync(path.join(dir, file)));
    if (actual !== expected) fail(`hash mismatch for ${file}`);
  }
  return manifest;
}

if (has('--verify')) {
  // Changes nothing: a previous copy moved aside is only pointed at.
  const { previous } = leftovers();
  if (!fs.existsSync(outDir) && previous.length > 0) {
    fail(`no manifest to verify: ${outDir} is missing, and an interrupted build left the previous copy at ` +
      `${path.join(parentDir, previous[0])}; the next build puts it back, or move it to ${outDir} by hand`);
  }
  const manifest = verifyManifest(outDir);
  console.log(`build-viewer: ${Object.keys(manifest.files).length} files verified (${manifest.target})`);
  process.exit(0);
}

const platforms = {
  'aarch64-macos': ['tjs', 'query-plan.dylib'],
  'x86_64-macos': ['tjs', 'query-plan.dylib'],
  'aarch64-linux-gnu': ['tjs', 'query-plan.so'],
  'x86_64-linux-gnu': ['tjs', 'query-plan.so'],
  'x86_64-windows': ['tjs.exe', 'query-plan.dll']
};
const cpu = { arm64: 'aarch64', x64: 'x86_64' }[process.arch];
const os = { darwin: 'macos', linux: 'linux-gnu', win32: 'windows' }[process.platform];
const target = valueOf('--target', has('--check') && fs.existsSync(path.join(outDir, 'manifest.json'))
  ? JSON.parse(fs.readFileSync(path.join(outDir, 'manifest.json'), 'utf8')).target
  : `${cpu}-${os}`);
if (!Object.hasOwn(platforms, target)) fail(`unsupported native target: ${target}`);
const [binary, library] = platforms[target];
const OUTPUTS = [...FILES, 'native/native-worker-desktop.js', `native/${library}`, `native/${binary}`];

if (has('--check')) {
  // Builds into a scratch folder beside outDir and compares; replaces nothing.
  const scratch = path.join(parentDir, `${leftoverPrefix}${randomUUID()}`);
  stageDir = scratch;
  await buildViewerInto(scratch, target);
  const committed = fs.existsSync(path.join(outDir, 'manifest.json'))
    ? JSON.parse(fs.readFileSync(path.join(outDir, 'manifest.json'), 'utf8')) : { files: {} };
  const stale = [];
  for (const file of OUTPUTS) {
    const fresh = sha256(fs.readFileSync(path.join(scratch, file)));
    const current = fs.existsSync(path.join(outDir, file)) ? sha256(fs.readFileSync(path.join(outDir, file))) : null;
    if (fresh !== current || committed.files[file] !== fresh) stale.push(file);
  }
  const extra = Object.keys(committed.files).filter((file) => !OUTPUTS.includes(file));
  if (stale.length || extra.length || committed.target !== target) {
    fail(`${outDir} does not match a fresh build for ${target}: ${[...stale, ...extra].join(', ') || 'manifest target'}; ` +
      'run npm run build:viewer and commit viewer-dist/');
  }
  console.log(`build-viewer: ${OUTPUTS.length} files match a fresh build (${target})`);
  process.exit(0);
}

const from = valueOf('--from', null);

// Signals. The default action would end the run wherever it stood: with its
// staging folder left beside outDir, or between the swap's two renames with no
// outDir at all. A handler that only records the signal replaces it, and
// checkpoint() acts on it between steps, where stopping leaves outDir as it
// was; the swap has none. (A handler runs only when the event loop does, which
// is what checkpoint() gives it.)
let interrupted = null;
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => {
    interrupted ??= signal;
  });
}
function stop(signal, state) {
  console.error(`build-viewer: interrupted by ${signal}; ${state}`);
  process.exit(128 + (osConstants.signals[signal] ?? 0));
}
async function checkpoint() {
  await new Promise((resolve) => setImmediate(resolve));
  if (interrupted !== null) stop(interrupted, `${outDir} is as it was`);
}

// A run that was killed outright (SIGKILL, a crash) between the swap's renames
// left outDir missing and its previous copy aside: put it back. Anything else
// such a run left is removed.
{
  const { staged, previous } = leftovers();
  try {
    if (!fs.existsSync(outDir) && previous.length > 0) {
      if (previous.length > 1) {
        fail(`${outDir} is missing and interrupted builds left ${previous.length} previous copies beside it ` +
          `(${previous.join(', ')}); move the one to keep to ${outDir} by hand`);
      }
      fs.renameSync(path.join(parentDir, previous[0]), outDir);
      console.error(`build-viewer: restored ${outDir} from ${previous[0]}, which an interrupted build had moved aside`);
      previous.shift();
    }
    for (const name of [...staged, ...previous]) {
      fs.rmSync(path.join(parentDir, name), { recursive: true, force: true });
      console.error(`build-viewer: removed ${name}, which an interrupted build left beside ${outDir}`);
    }
  } catch (error) {
    fail(`cannot repair what an interrupted build left beside ${outDir}: ${error.message}`);
  }
}
await checkpoint();

// Staged beside outDir, on the same volume, so taking its place is a rename.
// mkdirSync rather than mkdtempSync: the folder becomes outDir, so it takes the
// umask's mode as outDir always had, not a temp folder's 0700.
fs.mkdirSync(path.dirname(outDir), { recursive: true });
try {
  const staging = path.join(path.dirname(outDir), `${leftoverPrefix}${randomUUID()}`);
  fs.mkdirSync(staging);
  stageDir = staging;
} catch (error) {
  fail(`cannot create a staging folder beside ${outDir}: ${error.message}`);
}
await checkpoint();

if (from) {
  for (const file of OUTPUTS) {
    const source = path.join(path.resolve(from), file);
    const dest = path.join(stageDir, file);
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    try {
      fs.copyFileSync(source, dest);
    } catch (error) {
      fail(`cannot read ${file} from ${from}: ${error.message}`);
    }
    if (file === `native/${binary}`) fs.chmodSync(dest, 0o755);
  }
} else {
  try {
    await buildViewerInto(stageDir, target);
  } catch (error) {
    fail(`the viewer build failed: ${error.message}`);
  }
}
await checkpoint();
const files = {};
for (const file of OUTPUTS) files[file] = sha256(fs.readFileSync(path.join(stageDir, file)));
const unexpected = [];
(function walk(dir, prefix) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) walk(path.join(dir, entry.name), rel);
    else if (!OUTPUTS.includes(rel)) unexpected.push(rel);
  }
})(stageDir, '');
if (unexpected.length) fail(`the build wrote files the manifest does not cover: ${unexpected.join(', ')}`);

// Drift pin for the shell's layer-3 method audit. The Rust gate forwards
// only methods listed in KNOWN_METHODS (src-tauri/src/native.rs); esbuild
// minification preserves the worker dispatch table's property names, so the
// built bundle's method set is mechanically extractable and compared
// against the Rust list — a divergence fails the build so a method added to
// or removed from the worker must be re-audited in native.rs BEFORE it can
// ship. LIMIT: this is a name-level check. It cannot catch an EXISTING method
// whose payload gains a filesystem path — the real risk — so every worker
// change still requires re-auditing the path-bearing payloads against the
// worker source (see the PATH AUDIT comment on KNOWN_METHODS).
// The page reaches the shell only through desktop-api.js. A build whose swap
// of the backend seam misses bundles the VS Code api.js instead (it did on
// Windows, where esbuild's importer paths carry backslashes), and that page
// cannot open a database. Byte-identity catches it only where a committed copy
// exists to compare against, so refuse it here on every target.
if (fs.readFileSync(path.join(stageDir, 'web', 'viewer.html'), 'utf8').includes('acquireVsCodeApi')) {
  fail('the page bundled the VS Code backend (api.js) instead of desktop-api.js; see desktopApiPlugin in viewer/scripts/build.mjs');
}

const rustPath = path.join(repoRoot, 'src-tauri', 'src', 'native.rs');
const rustSource = fs.readFileSync(rustPath, 'utf8');
const bundle = fs.readFileSync(path.join(stageDir, 'native', 'native-worker-desktop.js'), 'utf8');

// One `const NAME: [&str; N] = [...]` list from native.rs. The count must match N:
// a ] inside the array's comments would cut the list short, and a quoted word
// there would add a name, both silently.
function rustList(name) {
  const block = rustSource.match(new RegExp(`const ${name}: \\[&str; (\\d+)\\] = \\[([^\\]]+)\\]`));
  if (!block) fail(`cannot find ${name} in ${rustPath}`);
  const names = [...block[2].matchAll(/"([A-Za-z0-9_]+)"/g)].map((m) => m[1]);
  if (names.length !== Number(block[1])) {
    fail(`${name} in ${rustPath} declares ${block[1]} entries but ${names.length} were read — update the drift pin`);
  }
  return names;
}

function assertNativeMethodsAudited() {
  const audited = rustList('KNOWN_METHODS');
  // The dispatch table survives minification as {initializeDatabase:X,...}
  // with bare-identifier values (no nested braces); initializeDatabase
  // appears in exactly one such table.
  const table = bundle.match(/\{initializeDatabase:[^{}]*\}/);
  if (!table) fail('cannot find the worker dispatch table in native-worker-desktop.js — update the drift pin');
  const shipped = table[0].slice(1, -1).split(',').map((pair) => pair.split(':')[0].trim());

  const unaudited = shipped.filter((name) => !audited.includes(name));
  const gone = audited.filter((name) => !shipped.includes(name));
  if (unaudited.length || gone.length) {
    fail(
      `native method table diverged from the audited KNOWN_METHODS list — ` +
      `unaudited in bundle: [${unaudited.join(', ')}]; audited but missing: [${gone.join(', ')}]. ` +
      `Re-audit the path-bearing payloads and update src-tauri/src/native.rs before building.`
    );
  }
  console.log(
    `build-viewer: native method table matches the ${audited.length} audited methods ` +
    `(re-audit path-bearing payloads in src-tauri/src/native.rs on every native re-pin)`
  );
  return shipped;
}

// Lockstep for native transfers (values larger than one frame, carried in
// pieces). The shell admits the transport methods in TRANSPORT_METHODS, which
// the sidecar's native-host serves before the dispatch table, and a
// content.payloadTransfer only on REQUEST_TRANSFER_METHODS. Both must be what
// the bundle serves, in both directions: a bundle with no transfers against a
// shell that admits them is refused like any other difference (that shell
// carries traffic no sidecar of this pin would understand, and the next
// re-pin would have nothing to compare against).
// - Transport methods: every value the bundle compares targetMethod with
//   (identifiers resolved to their one string literal) that is not a worker
//   method. An unresolvable or ambiguous comparison fails the build.
// - Request-transfer methods: the union of every Set literal whose string
//   members are worker method names (the reply set and the request set that
//   spreads it), spreads resolved. A set mixing method names with anything
//   else, or a spread that resolves to no such set, fails the build.
// Every use of targetMethod in the bundle's code is accounted for, not only
// its comparisons: each must be a shape classifyTargetMethodUse knows (a
// comparison, an array literal's .includes, which compares each member, a
// typeof, a .has on one of those Set literals, a message, an invoke envelope,
// or a destructuring whose local is held to the same shapes throughout its
// block). Anything else (a switch, an .indexOf, a lookup, a copy into a
// variable) fails the build, and so does a method Set changed after it is built
// or a method name added to any Set. A local passed to a plain function call is
// followed one level, into the function's one declaration in the bundle
// (`function NAME(plain, params)`), where the parameter is held to the same
// shapes; passing it on from there fails the build, as does a callee declared
// more than once, assigned, written as an expression or arrow, or reading its
// arguments object. A template literal the name is interpolated into carries
// it, and is held to the same shapes (a message to console or an Error passes).
// LIMIT: name-level like the drift pin above; the gate's numeric bounds
// (transfer length, piece size, id pattern) are not compared. A call is resolved
// by its callee's name, so a parameter or variable that shadows a declared
// function of the same name is followed into the wrong function.
const IDENT = '[A-Za-z_$][\\w$]*';
const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\$]/g, '\\$&');
const NOT_A_METHOD = new Set(['void', 'null', 'undefined', 'true', 'false']);

function stringAssignedTo(identifier, what) {
  const values = new Set([...bundle.matchAll(
    new RegExp(`(?<![\\w$.])${escapeRegExp(identifier)}="([^"\\\\]*)"`, 'g')
  )].map((m) => m[1]));
  if (values.size !== 1) {
    fail(`cannot resolve ${what} ${identifier} to one string literal in native-worker-desktop.js ` +
      `(found ${values.size}) — update the transfer pin`);
  }
  return [...values][0];
}

// Which characters of the bundle are code (not inside a string, template
// text, comment or regular expression), and the matching bracket of every
// bracket in code. A regular expression is told from a division by what
// precedes the slash. Anything it cannot follow to a balanced end fails the
// build rather than be guessed at.
function scanBundle() {
  const n = bundle.length;
  const code = new Uint8Array(n);
  const match = new Int32Array(n).fill(-1);
  const TEMPLATE = -1; // on the stack: a template's ${, whose } returns to template text
  const stack = [];
  // Every template literal's [opening, closing] backtick, and the ones still open.
  const templates = [];
  const opened = [];
  const cannot = (what, at) =>
    fail(`cannot scan native-worker-desktop.js (${what} at ${at}) — update the transfer pin`);
  let prev = '';
  let i = 0;
  // Template text, up to its end or to a ${ (code from there).
  const templateText = () => {
    for (; i < n; i++) {
      if (bundle[i] === '\\') { i++; continue; }
      if (bundle[i] === '`') { templates.push([opened.pop(), i]); i++; prev = 'a'; return; }
      if (bundle[i] === '$' && bundle[i + 1] === '{') { stack.push(TEMPLATE); i += 2; prev = '{'; return; }
    }
    cannot('an unterminated template literal', n);
  };
  const KEYWORD_BEFORE_REGEXP =
    /(?:^|[^\w$])(?:return|typeof|case|do|else|in|of|new|delete|void|throw|instanceof|await|yield)$/;
  while (i < n) {
    const c = bundle[i];
    if (c === '/' && bundle[i + 1] === '/') {
      const end = bundle.indexOf('\n', i);
      i = end < 0 ? n : end;
      continue;
    }
    if (c === '/' && bundle[i + 1] === '*') {
      const end = bundle.indexOf('*/', i + 2);
      if (end < 0) cannot('an unterminated comment', i);
      i = end + 2;
      continue;
    }
    if (c === '"' || c === "'") {
      const start = i;
      for (i++; i < n && bundle[i] !== c; i++) {
        if (bundle[i] === '\\') i++;
        else if (bundle[i] === '\n') cannot('an unterminated string', start);
      }
      if (i >= n) cannot('an unterminated string', start);
      i++;
      prev = 'a';
      continue;
    }
    if (c === '`') {
      opened.push(i);
      i++;
      templateText();
      continue;
    }
    if (c === '/' && (prev === '' || '(,=:[!&|?{};+-*%<>~^'.includes(prev) ||
        (prev === 'a' && KEYWORD_BEFORE_REGEXP.test(bundle.slice(Math.max(0, i - 12), i).trimEnd())))) {
      const start = i;
      let inClass = false;
      for (i++; i < n; i++) {
        const r = bundle[i];
        if (r === '\\') { i++; continue; }
        if (r === '\n') cannot('an unterminated regular expression', start);
        if (inClass) { if (r === ']') inClass = false; continue; }
        if (r === '[') inClass = true;
        else if (r === '/') break;
      }
      if (i >= n) cannot('an unterminated regular expression', start);
      for (i++; i < n && /[a-z]/.test(bundle[i]); i++);
      prev = 'a';
      continue;
    }
    code[i] = 1;
    if (c === '{' || c === '(' || c === '[') {
      stack.push(i);
    } else if (c === '}' || c === ')' || c === ']') {
      const open = stack.pop();
      if (open === undefined) cannot(`an unmatched ${c}`, i);
      if (open === TEMPLATE) {
        if (c !== '}') cannot(`${c} closing a template's ${'$'}{`, i);
        code[i] = 0;
        i++;
        templateText();
        continue;
      }
      if ({ '}': '{', ')': '(', ']': '[' }[c] !== bundle[open]) cannot(`${c} closing ${bundle[open]} at ${open}`, i);
      match[open] = i;
      match[i] = open;
    }
    if (!/\s/.test(c)) prev = /[\w$]/.test(c) ? 'a' : c;
    i++;
  }
  if (stack.length) cannot('an unclosed bracket', stack.at(-1));
  return { code, match, templates };
}

// The innermost template literal around position at, as [opening, closing], or null.
function enclosingTemplate({ templates }, at) {
  let inner = null;
  for (const template of templates) {
    if (template[0] < at && at < template[1] && (inner === null || template[0] > inner[0])) inner = template;
  }
  return inner;
}

// The innermost bracket in code that encloses position at: its index, or -1.
function enclosingBracket({ code, match }, at) {
  for (let j = at - 1; j >= 0; j--) {
    if (!code[j]) continue;
    const c = bundle[j];
    if (c === '}' || c === ')' || c === ']') j = match[j];
    else if (c === '{' || c === '(' || c === '[') return j;
  }
  return -1;
}

// Whether the object literal opened at brace is an RPC invoke envelope: it has
// kind:"invoke" among its own properties, which no destructuring pattern can
// (a string is not a binding).
function isInvokeEnvelope(scan, brace) {
  if (bundle[brace] !== '{') return false;
  const literal = bundle.slice(brace, scan.match[brace] + 1);
  for (const m of literal.matchAll(/(?<=[{,])kind:"invoke"(?=[,}])/g)) {
    if (enclosingBracket(scan, brace + m.index) === brace) return true;
  }
  return false;
}

// One use of targetMethod, as the property at at, or (context.local) as the
// local of that name at at that a destructuring copied it into. Returns
// { kind: 'compare', operand }, { kind: 'ok' }, or for a destructuring
// { kind: 'alias', local, from, to } (the local's block); fails the build on
// any other shape.
function classifyTargetMethodUse(scan, at, len, context) {
  const before = bundle.slice(Math.max(0, at - 160), at);
  const after = bundle.slice(at + len, at + len + 160);
  const isLocal = context.local !== undefined;
  const unaccounted = () => fail(
    `native-worker-desktop.js uses targetMethod in a way the transfer pin cannot account for: ` +
    `"…${bundle.slice(Math.max(0, at - 40), at + len + 40)}…"` +
    `${isLocal ? ` (through the local ${context.local}${context.within ? ` in ${context.within}` : ''})` : ''} ` +
    `— update the transfer pin in scripts/build-viewer.mjs and re-audit the transfer lists in native.rs`);
  // What reads the value: X.targetMethod (any chain), or the local itself.
  const chain = isLocal ? '' : before.match(/(?:[\w$]+(?:\?\.|\.))+$/)?.[0];
  if (chain === undefined) {
    // targetMethod as a property name: an invoke envelope's, or a destructuring's.
    if (!/[{,]$/.test(before) || !after.startsWith(':')) return unaccounted();
    const brace = enclosingBracket(scan, at);
    if (isInvokeEnvelope(scan, brace)) return { kind: 'ok' };
    const local = after.match(new RegExp(`^:(${IDENT})[,}]`));
    const declared = /(?:^|[^\w$])(?:let|const|var)\s*$/.test(bundle.slice(Math.max(0, brace - 8), brace));
    const assigned = /^=(?![=>])/.test(bundle.slice(scan.match[brace] + 1, scan.match[brace] + 3));
    const block = enclosingBracket(scan, brace);
    if (bundle[brace] !== '{' || !local || !declared || !assigned || bundle[block] !== '{') return unaccounted();
    return { kind: 'alias', local: local[1], from: scan.match[brace] + 1, to: scan.match[block] };
  }
  const lead = before.slice(0, before.length - chain.length);
  if (/(?:^|[^\w$])typeof\s*$/.test(lead)) return { kind: 'ok' };
  const compared = after.match(new RegExp(`^\\s*[!=]==?\\s*(${IDENT}|"[^"\\\\]*")(?![\\w$.(\\[]|\\?\\.)`)) ??
    lead.match(new RegExp(`(?<![\\w$.])(${IDENT}|"[^"\\\\]*")\\s*[!=]==?\\s*$`));
  if (compared) return { kind: 'compare', operands: [compared[1]] };
  // An array literal's .includes: a comparison with each member, each a string or
  // an identifier (resolved like a compared one).
  if (lead.endsWith('].includes(') && after.startsWith(')')) {
    const close = at - chain.length - '.includes('.length - 1;
    const open = scan.match[close];
    const prior = bundle.slice(0, open).trimEnd().at(-1) ?? '';
    const members = bundle.slice(open + 1, close).split(',').map((member) => member.trim());
    const plain = new RegExp(`^(?:${IDENT}|"[^"\\\\]*")$`);
    if (scan.code[close] && open >= 0 && !/[\w$)\]]/.test(prior) && members.every((member) => plain.test(member))) {
      return { kind: 'compare', operands: members };
    }
    return unaccounted();
  }
  const tested = lead.match(new RegExp(`(?<![\\w$.])(${IDENT})\\.has\\($`));
  if (tested && after.startsWith(')')) return context.methodSets.has(tested[1]) ? { kind: 'ok' } : unaccounted();
  // Interpolated into a template literal, as it is or shortened: the template then
  // carries the value and is held to the same shapes (a message handed to console or
  // to an Error passes; compared, switched on, or handed to a helper, it is judged as
  // the name itself would be).
  if ((lead.endsWith('${') && after.startsWith('}')) ||
      (lead.endsWith('${String(') && /^\)\.slice\(\d+,\d+\)\}/.test(after))) {
    const template = enclosingTemplate(scan, at);
    if (template === null) return unaccounted();
    return classifyTargetMethodUse(scan, template[0], template[1] - template[0] + 1,
      { ...context, local: context.local ?? 'targetMethod' });
  }
  // An invoke envelope's targetMethod value: a request re-wrapped.
  if (/[{,]targetMethod:$/.test(lead) && /^[,}]/.test(after) &&
      isInvokeEnvelope(scan, enclosingBracket(scan, at))) return { kind: 'ok' };
  if (!isLocal) return unaccounted();
  if (/^\.slice\(\d+,\d+\)[:}]/.test(after)) return { kind: 'ok' };
  // The dispatch table's own lookup, which the drift pin audits.
  if (lead.endsWith(`Object.prototype.hasOwnProperty.call(${context.table},`) && after.startsWith(')')) {
    return { kind: 'ok' };
  }
  if (lead.endsWith(`${context.table}[`) && after.startsWith(']')) return { kind: 'ok' };
  // An argument of console's (it only prints), or of a plain function call, which
  // the caller follows one level.
  const paren = enclosingBracket(scan, at);
  const callee = bundle.slice(Math.max(0, paren - 40), paren);
  if (bundle[paren] === '(' && /[(,]\s*$/.test(lead) && /^\s*[,)]/.test(after) &&
      !/(?:^|[^\w$])(?:if|while|for|switch|return|typeof|catch|await|function)$/.test(callee)) {
    // console's and a built-in error constructor's: they only say it. A name the
    // bundle binds itself is not the built-in, and is followed like any other call.
    const sink = callee.match(
      /(?:^|[^\w$.])(?:console\.[a-z]+|(?:new\s+)?(Error|EvalError|RangeError|ReferenceError|SyntaxError|TypeError|URIError|AggregateError))$/);
    if (sink && (sink[1] === undefined || !bindsName(scan, sink[1]))) return { kind: 'ok' };
    const name = callee.match(new RegExp(`(?:^|[^\\w$.])(${IDENT})$`))?.[1];
    if (name !== undefined) {
      if (context.depth > 0) {
        fail(`native-worker-desktop.js passes the method name on from ${context.within} to ${name}, ` +
          `which the transfer pin does not follow — update the transfer pin in scripts/build-viewer.mjs and ` +
          `re-audit the transfer lists in native.rs`);
      }
      return { kind: 'call', callee: name, index: argumentIndex(scan, paren, at) };
    }
  }
  return unaccounted();
}

// Which argument of the call whose ( is at paren the expression at at is.
// Anything that would make the count uncertain (a spread, a template literal)
// makes it -1, which no parameter matches.
function argumentIndex(scan, paren, at) {
  const between = bundle.slice(paren + 1, at);
  if (between.includes('...') || between.includes('`')) return -1;
  let index = 0;
  for (let j = paren + 1; j < at; j++) {
    if (!scan.code[j]) continue;
    if ('([{'.includes(bundle[j]) && scan.match[j] > j) j = scan.match[j];
    else if (bundle[j] === ',') index += 1;
  }
  return index;
}

// Whether the bundle binds name itself: declares a function or class of that name,
// or assigns to it. A call of such a name does not reach the global of that name.
function bindsName(scan, name) {
  const n = escapeRegExp(name);
  const binding = new RegExp(`(?<![\\w$.])(?:(?:function\\s*\\*?\\s*|class\\s+)${n}(?![\\w$])|${n}\\s*=(?![=>]))`, 'g');
  return [...bundle.matchAll(binding)].some((m) => scan.code[m.index]);
}

// The parameter a plain call's argument index binds in its callee's one
// declaration (`function NAME(a,b){…}`), and that function's body. A callee
// declared more than once or also assigned, or whose parameters are not plain
// names (a default, a pattern, a rest), fails the build: it cannot be followed.
function calleeParameter(scan, callee, index) {
  const cannot = (why) => fail(`native-worker-desktop.js passes the method name to ${callee}, which the ` +
    `transfer pin cannot follow (${why}) — update the transfer pin in scripts/build-viewer.mjs and re-audit the ` +
    `transfer lists in native.rs`);
  const declarations = [...bundle.matchAll(new RegExp(`(?<![\\w$.])function\\s*${escapeRegExp(callee)}\\s*\\(`, 'g'))]
    .filter((m) => scan.code[m.index]);
  if (declarations.length !== 1) cannot(`${declarations.length} declarations of it`);
  if (new RegExp(`(?<![\\w$.])${escapeRegExp(callee)}\\s*=(?![=>])`).test(bundle)) cannot('it is also assigned');
  const open = declarations[0].index + declarations[0][0].length - 1;
  const close = scan.match[open];
  const params = bundle.slice(open + 1, close).split(',').map((param) => param.trim());
  if (!params.every((param) => new RegExp(`^${IDENT}$`).test(param))) cannot('its parameters are not plain names');
  if (index < 0 || index >= params.length) cannot('the argument does not bind one of its parameters');
  if (bundle[close + 1] !== '{') cannot('no body after its parameters');
  const from = close + 2;
  const to = scan.match[close + 1];
  // Its arguments object holds the name under no parameter's name.
  for (const m of bundle.slice(from, to).matchAll(/(?<![\w$.])arguments(?![\w$])/g)) {
    if (scan.code[from + m.index]) cannot('it reads its arguments object');
  }
  return { param: params[index], from, to };
}

function bundleTransportMethods(workerMethods) {
  const scan = scanBundle();
  // The dispatch table's identifier ({initializeDatabase:X,...}, as the drift pin finds it).
  const table = bundle.match(/([\w$]+)=\{initializeDatabase:[^{}]*\}/)?.[1];
  if (!table) {
    fail('cannot find the worker dispatch table\'s identifier in native-worker-desktop.js — update the transfer pin');
  }
  // The Sets a method may be tested against: the method Set literals, each assigned once and never changed.
  const methodSets = new Set();
  const literalSet = new RegExp(`(?<![\\w$.])(${IDENT})=(?:Object\\.freeze\\()?new Set\\(\\[([^\\]]*)\\]\\)`, 'g');
  for (const m of bundle.matchAll(literalSet)) {
    if (classifyMethodSet(m[2], new Set(), workerMethods).length) methodSets.add(m[1]);
  }
  for (const name of methodSets) {
    const assignments = bundle.match(new RegExp(`(?<![\\w$.])${escapeRegExp(name)}=(?![=>])`, 'g')).length;
    if (assignments !== 1) {
      fail(`the method Set ${name} in native-worker-desktop.js is assigned ${assignments} times ` +
        '— update the transfer pin');
    }
    if (new RegExp(`(?<![\\w$.])${escapeRegExp(name)}\\.(?:add|delete|clear)\\(`).test(bundle)) {
      fail(`the method Set ${name} in native-worker-desktop.js is changed after it is built ` +
        '— update the transfer pin');
    }
  }
  const added = [...bundle.matchAll(/\.add\("([^"\\]*)"\)/g)].map((m) => m[1])
    .find((name) => workerMethods.includes(name) || rustList('TRANSPORT_METHODS').includes(name));
  if (added !== undefined) {
    fail(`native-worker-desktop.js adds the method name ${added} to a Set with .add — update the transfer pin`);
  }
  const context = { methodSets, table, depth: 0 };
  const operands = [];
  // Every use of a local in its block (from..to), held to the same shapes; a plain
  // call it is passed to is followed into its callee, one level.
  const follow = (use, within) => {
    const helper = calleeParameter(scan, use.callee, use.index);
    holdLocal(helper.param, helper.from, helper.to, { ...within, depth: within.depth + 1, within: use.callee });
  };
  const holdLocal = (local, from, to, within) => {
    const uses = new RegExp(`(?<![\\w$.])${escapeRegExp(local)}(?![\\w$])`, 'g');
    for (const l of bundle.slice(from, to).matchAll(uses)) {
      const at = from + l.index;
      // Not code, or a property that only shares the name ({x:…}).
      if (!scan.code[at] || (/[{,]/.test(bundle[at - 1]) && bundle[at + local.length] === ':')) continue;
      const use = classifyTargetMethodUse(scan, at, local.length, { ...within, local });
      if (use.kind === 'compare') operands.push(...use.operands);
      if (use.kind === 'call') follow(use, within);
    }
  };
  for (const m of bundle.matchAll(/(?<![\w$])targetMethod(?![\w$])/g)) {
    if (!scan.code[m.index]) {
      fail(`native-worker-desktop.js names targetMethod outside code (at ${m.index}) — update the transfer pin`);
    }
    const use = classifyTargetMethodUse(scan, m.index, m[0].length, context);
    if (use.kind === 'compare') operands.push(...use.operands);
    if (use.kind === 'alias') holdLocal(use.local, use.from, use.to, context);
    if (use.kind === 'call') follow(use, context);
  }
  const names = operands.filter((operand) => !NOT_A_METHOD.has(operand)).map((operand) => operand.startsWith('"')
    ? operand.slice(1, -1)
    : stringAssignedTo(operand, 'the targetMethod comparison with'));
  return [...new Set(names)].filter((name) => !workerMethods.includes(name));
}

// The members of one Set literal's array (body), spreads resolved: [] when it
// names no worker method.
function classifyMethodSet(body, seen, workerMethods) {
  const literals = [...body.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  const methodLiterals = literals.filter((s) => workerMethods.includes(s));
  if (!methodLiterals.length) return [];
  const rest = body.replace(/"((?:[^"\\]|\\.)*)"/g, '');
  const spreads = [...rest.matchAll(new RegExp(`\\.\\.\\.(${IDENT})`, 'g'))].map((m) => m[1]);
  const leftover = rest.replace(new RegExp(`\\.\\.\\.${IDENT}`, 'g'), '').replace(/[\s,]/g, '');
  if (methodLiterals.length !== literals.length || leftover) {
    fail(`a Set in native-worker-desktop.js mixes worker method names with other members ` +
      `(new Set([${body.slice(0, 120)}])) — update the transfer pin`);
  }
  const resolved = [...literals];
  for (const spread of spreads) {
    if (seen.has(spread)) fail(`the Set spread ${spread} in native-worker-desktop.js is circular`);
    const definitions = [...bundle.matchAll(new RegExp(
      `(?<![\\w$.])${escapeRegExp(spread)}=(?:Object\\.freeze\\()?new Set\\(\\[([^\\]]*)\\]\\)`, 'g'))];
    const inner = definitions.length === 1
      ? classifyMethodSet(definitions[0][1], new Set([...seen, spread]), workerMethods)
      : [];
    if (!inner.length) {
      fail(`cannot resolve the Set spread ...${spread} in native-worker-desktop.js to one set of worker ` +
        `method names (found ${definitions.length} definitions) — update the transfer pin`);
    }
    resolved.push(...inner);
  }
  return resolved;
}

function bundleRequestTransferMethods(workerMethods) {
  const members = new Set();
  for (const set of bundle.matchAll(/new Set\(\[([^\]]*)\]\)/g)) {
    for (const name of classifyMethodSet(set[1], new Set(), workerMethods)) members.add(name);
  }
  return [...members];
}

function assertNativeTransfersAudited(workerMethods) {
  const pairs = [
    ['transport methods', rustList('TRANSPORT_METHODS'), bundleTransportMethods(workerMethods)],
    ['request-transfer methods', rustList('REQUEST_TRANSFER_METHODS'), bundleRequestTransferMethods(workerMethods)]
  ];
  const differences = pairs.flatMap(([what, shell, shipped]) => {
    const unadmitted = shipped.filter((name) => !shell.includes(name));
    const unserved = shell.filter((name) => !shipped.includes(name));
    return unadmitted.length || unserved.length
      ? [`${what}: in bundle but not admitted by the shell: [${unadmitted.join(', ')}]; ` +
         `admitted by the shell but not in bundle: [${unserved.join(', ')}]`]
      : [];
  });
  if (differences.length) {
    fail(
      `native transfer lists diverged between src-tauri/src/native.rs and the bundle — ${differences.join('; ')}. ` +
      `A bundle without native transfers and a shell that admits them disagree too: build a viewer that ` +
      `carries them, or re-audit TRANSPORT_METHODS and REQUEST_TRANSFER_METHODS in native.rs before building.`
    );
  }
  console.log(
    `build-viewer: native transfers match the shell (transport [${pairs[0][1].join(', ')}]; ` +
    `request-transfer [${pairs[1][1].join(', ')}])`
  );
}
assertNativeTransfersAudited(assertNativeMethodsAudited());

fs.writeFileSync(path.join(stageDir, 'manifest.json'), JSON.stringify({
  source: 'viewer/ in this repository (npm run build:viewer)',
  target,
  files
}, null, 2) + '\n');
verifyManifest(stageDir);
await checkpoint();

// The swap. A rename cannot replace a folder that has files in it, so the
// previous outDir moves aside first and is moved back if the staged one
// cannot take its place.
const previous = fs.existsSync(outDir) ? `${stageDir}-previous` : null;
if (previous !== null) {
  try {
    fs.renameSync(outDir, previous);
  } catch (error) {
    fail(`cannot move ${outDir} aside to replace it: ${error.message}`);
  }
}
try {
  fs.renameSync(stageDir, outDir);
} catch (error) {
  if (previous !== null) {
    try {
      fs.renameSync(previous, outDir);
    } catch (restoreError) {
      fail(`cannot move the built files into ${outDir} (${error.message}), nor the previous copy back ` +
        `from ${previous} (${restoreError.message}); move it back by hand`);
    }
  }
  fail(`cannot move the built files into ${outDir}: ${error.message}`);
}
stageDir = null;
if (previous !== null) {
  try {
    fs.rmSync(previous, { recursive: true, force: true });
  } catch (error) {
    fail(`built ${outDir}, but the previous copy at ${previous} could not be removed: ${error.message}`);
  }
}
console.log(`build-viewer: built ${OUTPUTS.length} files for ${target}`);
// A signal that came during the swap: the build had already finished.
await new Promise((resolve) => setImmediate(resolve));
if (interrupted !== null) stop(interrupted, `it came after ${outDir} was replaced, so the build completed`);
