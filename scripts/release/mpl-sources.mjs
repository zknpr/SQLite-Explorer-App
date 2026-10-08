#!/usr/bin/env node
/**
 * Collect the unmodified sources of every MPL-2.0 crate in the locked Cargo
 * graph, for a binary release to ship beside its installers. MPL 2.0 §3.2
 * requires a binary distribution to make the covered source available.
 *
 *   node scripts/release/mpl-sources.mjs --out <dir>
 *
 * Writes <dir>/mpl-dependency-sources.tar.gz holding each `.crate` exactly as
 * crates.io serves it plus SOURCES.txt. Every archive must match the checksum
 * Cargo.lock pins, so the shipped source is provably the source that was
 * built. The whole lock graph is covered (all targets), which is a superset
 * of what any one platform links.
 */
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const CRATES_IO = 'registry+https://github.com/rust-lang/crates.io-index';

/**
 * Whether a crate's SPDX expression obliges us under MPL. A top-level OR lets
 * the distributor pick any alternative, so `MIT OR MPL-2.0` does not. Anything
 * this simple reader cannot split safely (parentheses) is treated as
 * obligating whenever it mentions MPL: shipping extra source is harmless,
 * omitting required source is not.
 */
export function requiresMpl(expression) {
  if (typeof expression !== 'string' || !/MPL/.test(expression)) return false;
  if (/[()]/.test(expression)) return true;
  return expression.split(/\s+OR\s+|\//).every((alternative) => /MPL/.test(alternative));
}

/** name@version → checksum, from Cargo.lock's [[package]] tables. */
export function parseLockChecksums(lockText) {
  const checksums = new Map();
  // A Windows checkout may carry CRLF; the line anchors below expect LF.
  for (const block of lockText.replace(/\r\n/g, '\n').split(/^\[\[package\]\]$/m).slice(1)) {
    const field = (key) => block.match(new RegExp(`^${key} = "([^"]*)"$`, 'm'))?.[1];
    const name = field('name');
    const version = field('version');
    if (name && version) checksums.set(`${name}@${version}`, { source: field('source'), checksum: field('checksum') });
  }
  return checksums;
}

/** The MPL-obligating packages of `cargo metadata`, each with its pinned checksum. */
export function selectMplPackages(metadata, checksums) {
  const selected = [];
  for (const pkg of metadata.packages) {
    if (!requiresMpl(pkg.license)) continue;
    const lock = checksums.get(`${pkg.name}@${pkg.version}`);
    if (!lock) throw new Error(`${pkg.name} ${pkg.version} is not in Cargo.lock`);
    if (lock.source !== CRATES_IO || !/^[0-9a-f]{64}$/.test(lock.checksum ?? '')) {
      throw new Error(`${pkg.name} ${pkg.version} is not a checksummed crates.io package; collect its source by hand`);
    }
    selected.push({ name: pkg.name, version: pkg.version, license: pkg.license, checksum: lock.checksum });
  }
  return selected.sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));
}

export const crateUrl = ({ name, version }) => `https://static.crates.io/crates/${name}/${name}-${version}.crate`;

/** Download each crate and refuse any byte that differs from Cargo.lock. */
export async function fetchVerified(packages, fetchBytes) {
  const files = [];
  for (const pkg of packages) {
    const bytes = await fetchBytes(crateUrl(pkg));
    const actual = createHash('sha256').update(bytes).digest('hex');
    if (actual !== pkg.checksum) {
      throw new Error(`${pkg.name} ${pkg.version}: downloaded sha256 ${actual} != Cargo.lock ${pkg.checksum}`);
    }
    files.push({ ...pkg, file: `${pkg.name}-${pkg.version}.crate`, bytes });
  }
  return files;
}

export function sourcesListing(files) {
  return [
    'Unmodified sources of the MPL-2.0 Cargo dependencies in this release.',
    'Each archive is byte-identical to crates.io and matches the checksum in Cargo.lock.',
    '',
    ...files.map((f) => `${f.file}  ${f.license}  sha256=${f.checksum}  ${crateUrl(f)}`),
    ''
  ].join('\n');
}

async function main() {
  const argv = process.argv.slice(2);
  const outIndex = argv.indexOf('--out');
  if (outIndex < 0 || !argv[outIndex + 1]) throw new Error('usage: mpl-sources.mjs --out <dir>');
  const outDir = path.resolve(argv[outIndex + 1]);
  const manifest = path.join(repoRoot, 'src-tauri', 'Cargo.toml');
  const metadata = JSON.parse(execFileSync('cargo', ['metadata', '--locked', '--format-version', '1', '--manifest-path', manifest], {
    encoding: 'utf8', maxBuffer: 256 * 1024 * 1024
  }));
  const checksums = parseLockChecksums(fs.readFileSync(path.join(repoRoot, 'src-tauri', 'Cargo.lock'), 'utf8'));
  const packages = selectMplPackages(metadata, checksums);
  if (packages.length === 0) throw new Error('no MPL-2.0 crates found; check the selection before shipping without sources');
  const files = await fetchVerified(packages, async (url) => {
    const response = await fetch(url, { signal: AbortSignal.timeout(60_000) });
    if (!response.ok) throw new Error(`${url}: HTTP ${response.status}`);
    return Buffer.from(await response.arrayBuffer());
  });
  const staging = fs.mkdtempSync(path.join(outDir, '.mpl-'));
  try {
    const dir = path.join(staging, 'mpl-dependency-sources');
    fs.mkdirSync(dir);
    for (const f of files) fs.writeFileSync(path.join(dir, f.file), f.bytes);
    fs.writeFileSync(path.join(dir, 'SOURCES.txt'), sourcesListing(files));
    execFileSync('tar', ['-czf', path.join(outDir, 'mpl-dependency-sources.tar.gz'), '-C', staging, 'mpl-dependency-sources']);
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }
  for (const f of files) console.log(`mpl-sources: ${f.file} verified`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(`mpl-sources: ${error.message}`);
    process.exit(1);
  });
}
