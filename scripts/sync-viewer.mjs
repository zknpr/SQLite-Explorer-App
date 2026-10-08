#!/usr/bin/env node
/**
 * Sync the upstream desktop viewer artifacts into viewer-dist/.
 *
 *   --local              copy from the sibling checkout's working tree
 *   --ref <commit>       copy from a pinned upstream commit (git show)
 *   --verify             verify viewer-dist/ against its manifest and exit
 *   --source <path>      upstream repo path (default ../SQLite-Explorer)
 *   --out <path>         output dir (default viewer-dist/)
 *   --target <platform>  native artifact platform (default current OS/CPU)
 *
 * The manifest records source, ref, and per-file sha256 so a build is always
 * traceable to an exact upstream state (same policy as refresh-natives.mjs).
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const FILES = [
  'viewer.html', 'worker.js', 'sql-wasm.js', 'sql-wasm.wasm', 'dev-harness.html',
  'codicons/codicon.css', 'codicons/codicon.ttf'
];

// Native engine artifacts. The sidecar bundle is a desktop/ build product
// like the viewer files; the tjs binary comes from the extension's committed
// per-platform natives (fork CI builds, sha-pinned upstream by
// refresh-natives.mjs), alongside the pinned query-plan reader. All three land
// under viewer-dist/native/, which
// tauri.conf.json ships as the bundled `native/` resource dir and
// native_available() checks at runtime. `mode` restores the executable bit
// that neither writeFileSync nor `git show` preserves — without it the shell
// cannot spawn the sidecar.
const argv = process.argv.slice(2);
const has = (flag) => argv.includes(flag);
const valueOf = (flag, fallback) => {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.resolve(valueOf('--source', path.join(repoRoot, '..', 'SQLite-Explorer')));
const outDir = path.resolve(valueOf('--out', path.join(repoRoot, 'viewer-dist')));

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

function fail(message) {
  console.error(`sync-viewer: ${message}`);
  process.exit(1);
}

if (has('--verify')) {
  const manifestPath = path.join(outDir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) fail('no manifest to verify');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  for (const [file, expected] of Object.entries(manifest.files)) {
    const actual = sha256(fs.readFileSync(path.join(outDir, file)));
    if (actual !== expected) fail(`hash mismatch for ${file}`);
  }
  console.log(`sync-viewer: ${Object.keys(manifest.files).length} files verified (ref ${manifest.ref})`);
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
const target = valueOf('--target', `${cpu}-${os}`);
if (!Object.hasOwn(platforms, target)) fail(`unsupported native target: ${target}`);
const [binary, library] = platforms[target];
const NATIVE_FILES = [
  { out: 'native/native-worker-desktop.js', src: 'desktop/native-worker-desktop.js' },
  { out: `native/${library}`, src: `natives/${target}/${library}` },
  { out: `native/${binary}`, src: `natives/${target}/${binary}`, mode: 0o755 }
];

const local = has('--local');
const ref = valueOf('--ref', null);
if (!local && !ref) fail('pass --local or --ref <commit> (or --verify)');

fs.rmSync(outDir, { recursive: true, force: true });
fs.mkdirSync(path.join(outDir, 'codicons'), { recursive: true });
fs.mkdirSync(path.join(outDir, 'native'), { recursive: true });

const entries = [
  ...FILES.map((file) => ({ out: file, src: `desktop/${file}` })),
  ...NATIVE_FILES
];
const files = {};
for (const { out, src, mode } of entries) {
  let bytes;
  if (local) {
    bytes = fs.readFileSync(path.join(source, src));
  } else {
    bytes = execFileSync('git', ['-C', source, 'show', `${ref}:${src}`],
      { maxBuffer: 256 * 1024 * 1024 });
  }
  const dest = path.join(outDir, out);
  fs.writeFileSync(dest, bytes);
  if (mode !== undefined) fs.chmodSync(dest, mode);
  files[out] = sha256(bytes);
}

// Drift pin for the shell's layer-3 method audit. The Rust gate forwards
// only methods listed in KNOWN_METHODS (src-tauri/src/native.rs); esbuild
// minification preserves the worker dispatch table's property names, so the
// synced bundle's method set is mechanically extractable and compared
// against the Rust list — a divergence fails the sync so a method added or
// removed upstream must be re-audited in native.rs BEFORE it can ship.
// LIMIT: this is a name-level check. It cannot catch an EXISTING method
// whose payload gains a filesystem path — the real risk — so every native
// re-pin still requires re-auditing the path-bearing payloads against the
// worker source (see the PATH AUDIT comment on KNOWN_METHODS).
function assertNativeMethodsAudited() {
  const rustPath = path.join(repoRoot, 'src-tauri', 'src', 'native.rs');
  const rustSource = fs.readFileSync(rustPath, 'utf8');
  const block = rustSource.match(/const KNOWN_METHODS: \[&str; \d+\] = \[([^\]]+)\]/);
  if (!block) fail(`cannot find KNOWN_METHODS in ${rustPath}`);
  const audited = [...block[1].matchAll(/"([A-Za-z0-9_]+)"/g)].map((m) => m[1]);

  const bundlePath = path.join(outDir, 'native', 'native-worker-desktop.js');
  const bundle = fs.readFileSync(bundlePath, 'utf8');
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
      `Re-audit the path-bearing payloads and update src-tauri/src/native.rs before syncing.`
    );
  }
  console.log(
    `sync-viewer: native method table matches the ${audited.length} audited methods ` +
    `(re-audit path-bearing payloads in src-tauri/src/native.rs on every native re-pin)`
  );
}
assertNativeMethodsAudited();

let resolvedRef;
try {
  resolvedRef = local
    ? `local-worktree@${execFileSync('git', ['-C', source, 'rev-parse', '--short', 'HEAD'],
        { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim()}`
    : execFileSync('git', ['-C', source, 'rev-parse', ref],
        { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
} catch {
  if (!local) fail(`cannot resolve ref ${ref} in ${source}`);
  resolvedRef = 'local-worktree@unknown'; // non-git source (tests use a temp dir)
}

fs.writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify({
  source: 'SQLite-Explorer desktop/ build target',
  ref: resolvedRef,
  target,
  syncedAt: new Date().toISOString(),
  files
}, null, 2) + '\n');
console.log(`sync-viewer: synced ${entries.length} files from ${resolvedRef}`);
