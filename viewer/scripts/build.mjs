#!/usr/bin/env node
/**
 * Builds the desktop viewer from the sources in this folder: the page
 * (core/ui), the WASM worker, the native engine's worker bundle (core/native),
 * sql.js and the codicons, plus the engine binaries for one platform. Every
 * output is deterministic: the same sources give the same bytes.
 *
 *   node scripts/build.mjs [--out <dir>] [--target <platform>]
 *
 * scripts/build-viewer.mjs at the repository root runs this into a staging
 * folder, checks the result and installs it as viewer-dist/.
 */
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const resolve = (...parts) => path.join(root, ...parts);
const require = createRequire(import.meta.url);

/** The desktop build swaps the page's backend seam (api.js) for desktop-api.js. */
export const desktopApiPlugin = {
  name: 'desktop-api-plugin',
  setup(build) {
    build.onResolve({ filter: /\/api\.js$/ }, (args) => {
      // esbuild hands the importer as a native path: backslashes on Windows.
      const importer = args.importer.replaceAll('\\', '/');
      if (importer.includes('core/ui/modules') || importer.includes('core/ui/desktop-viewer')) {
        return { path: resolve('core', 'ui', 'modules', 'desktop-api.js') };
      }
      return null;
    });
  },
};

/** The page's script: the desktop entry. */
const pageScriptOptions = () => ({
  entryPoints: [resolve('core', 'ui', 'desktop-viewer.js')],
  bundle: true,
  write: false,
  minify: true,
  format: 'iife',
  target: 'es2020',
  plugins: [desktopApiPlugin],
  loader: { '.js': 'js', '.ts': 'ts' },
  absWorkingDir: root,
});

/** The WASM worker: the page's sql.js engine, with the native branch folded away. */
const workerOptions = () => ({
  entryPoints: [resolve('worker', 'worker.js')],
  bundle: true,
  platform: 'browser',
  format: 'iife',
  target: 'es2020',
  minify: true,
  write: false,
  define: { 'import.meta.env.DESKTOP_NATIVE_ENGINE': 'false' },
  absWorkingDir: root,
});

/** The native engine's worker bundle, run by tjs. */
const nativeWorkerOptions = () => ({
  entryPoints: [resolve('core', 'native', 'native-entry.js')],
  bundle: true,
  format: 'esm',
  platform: 'neutral',
  target: 'es2022',
  external: ['tjs:*'],
  minify: true,
  write: false,
  define: { 'import.meta.env.DESKTOP_NATIVE_ENGINE': 'true' },
  inject: [resolve('core', 'native', 'native-engine-inject.js')],
  loader: { '.js': 'js', '.ts': 'ts' },
  absWorkingDir: root,
});

/** A bundle with the sha256 of its own text up front, so any change to anything it pulls in changes the marker. */
const marked = (label, source) => `/*! ${label}:${createHash('sha256').update(source).digest('hex')} */\n${source}`;

async function buildWorker() {
  const result = await esbuild.build(workerOptions());
  return marked('sqlite-viewer-bundle-sha256', result.outputFiles[0].text);
}

/** The page: template + CSS + script. */
async function buildViewer() {
  const template = fs.readFileSync(resolve('core', 'ui', 'viewer.template.html'), 'utf-8');
  const css = fs.readFileSync(resolve('core', 'ui', 'viewer.css'), 'utf-8');
  const themesCss = fs.readFileSync(resolve('core', 'ui', 'desktop-themes.css'), 'utf-8');
  const js = await esbuild.build(pageScriptOptions());
  const styles = await esbuild.transform(`${css}\n${themesCss}`, { loader: 'css', minify: true });
  return template
    .replace('<!--HEAD-->', () => '<link rel="stylesheet" href="./codicons/codicon.css">')
    .replace('<!--STYLES-->', () => styles.code)
    .replace('<!--SCRIPTS-->', () => js.outputFiles[0].text)
    .replaceAll('nonce="<!--NONCE-->"', '');
}

/**
 * The native engine's worker bundle, as text. Exported so the native lanes
 * (scripts/lib/native-sidecar-lane.mjs) check the shipped bundle against this
 * exact configuration.
 */
export async function buildDesktopNativeWorkerSource() {
  const result = await esbuild.build(nativeWorkerOptions());
  return marked('sqlite-explorer-native-worker-sha256', result.outputFiles[0].text);
}

/**
 * `name version` of every npm package the viewer ships: what the three bundles
 * pull in, and the codicons the build copies. The third-party notices check
 * (scripts/release/notices.mjs) holds the inventory to exactly this set.
 */
export async function viewerNpmPackages() {
  const packages = new Set();
  const codicons = JSON.parse(fs.readFileSync(require.resolve('@vscode/codicons/package.json'), 'utf8'));
  packages.add(`${codicons.name} ${codicons.version}`);
  for (const options of [pageScriptOptions(), workerOptions(), nativeWorkerOptions()]) {
    const result = await esbuild.build({ ...options, metafile: true });
    for (const input of Object.keys(result.metafile.inputs)) {
      const at = input.lastIndexOf('node_modules/');
      if (at < 0) continue;
      const parts = input.slice(at + 'node_modules/'.length).split('/');
      const name = parts[0].startsWith('@') ? `${parts[0]}/${parts[1]}` : parts[0];
      const manifest = path.join(root, input.slice(0, at), 'node_modules', name, 'package.json');
      packages.add(`${name} ${JSON.parse(fs.readFileSync(manifest, 'utf8')).version}`);
    }
  }
  return packages;
}

/** Builds everything into `out`, with the engine binaries for `target` when one is given. */
export async function buildViewerInto(out, target) {
  const [viewer, worker, nativeWorker] = await Promise.all([buildViewer(), buildWorker(), buildDesktopNativeWorkerSource()]);
  // web/ is what the shell embeds and serves as its pages (frontendDist);
  // native/ is bundled beside it as resources and never served.
  const web = path.join(out, 'web');
  fs.mkdirSync(path.join(web, 'codicons'), { recursive: true });
  fs.mkdirSync(path.join(out, 'native'), { recursive: true });
  fs.writeFileSync(path.join(web, 'viewer.html'), viewer);
  fs.writeFileSync(path.join(web, 'worker.js'), worker);
  fs.writeFileSync(path.join(out, 'native', 'native-worker-desktop.js'), nativeWorker);
  for (const file of ['sql-wasm.js', 'sql-wasm.wasm']) fs.copyFileSync(resolve('vendor', 'sql.js', file), path.join(web, file));
  for (const file of ['codicon.css', 'codicon.ttf']) {
    fs.copyFileSync(require.resolve(`@vscode/codicons/dist/${file}`), path.join(web, 'codicons', file));
  }
  if (target) {
    const natives = resolve('natives', target);
    for (const file of fs.readdirSync(natives)) {
      fs.copyFileSync(path.join(natives, file), path.join(out, 'native', file));
      if (!/\.(dll|dylib|so)$/.test(file)) fs.chmodSync(path.join(out, 'native', file), 0o755);
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const valueOf = (flag, fallback) => {
    const i = argv.indexOf(flag);
    return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
  };
  const out = path.resolve(valueOf('--out', resolve('dist')));
  await buildViewerInto(out, valueOf('--target', null));
  console.log('built the desktop viewer into ' + out);
}
